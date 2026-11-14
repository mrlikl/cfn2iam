// Install a built cfn2iam wheel in Pyodide the way the web version does, and run the core.
//
//   npm install --no-save --prefix <dir> pyodide@<version>
//   node tests/pyodide/smoke.mjs <dir>/node_modules/pyodide dist/cfn2iam-<version>-py3-none-any.whl
//
// Like the page: PyYAML comes from Pyodide, micropip installs the wheel with deps=False
// (typer and boto3 are CLI-only), and schemas are fetched asynchronously. Here the
// fetch is an in-memory fake, so the only network use is Pyodide's own packages.
import { readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [pyodideDir, wheel] = process.argv.slice(2);
if (!pyodideDir || !wheel) {
  console.error("usage: node smoke.mjs <pyodide package dir> <wheel>");
  process.exit(2);
}

const { loadPyodide } = await import(pathToFileURL(join(resolve(pyodideDir), "pyodide.mjs")).href);
const pyodide = await loadPyodide();
await pyodide.loadPackage(["micropip", "pyyaml"], { messageCallback: () => {} });
console.log(`Pyodide ${pyodide.version}, Python ${pyodide.runPython("import sys; sys.version.split()[0]")}`);

const wheelPath = `/tmp/${basename(wheel)}`;
pyodide.FS.writeFile(wheelPath, readFileSync(wheel));
pyodide.globals.set("wheel_url", `emfs:${wheelPath}`);
pyodide.globals.set("wheel_name", basename(wheel));

const CHECK = `
import json
import sys
from importlib.metadata import version

import micropip

await micropip.install(wheel_url, deps=False)

from cfn2iam import core

expected = wheel_name.split("-")[1]
assert version("cfn2iam") == expected, (version("cfn2iam"), expected)

BACKEND = {
    "schemas/index.json": {"schemas": [{"typeName": "AWS::S3::Bucket", "filename": "AWS_S3_Bucket.json"}]},
    "schemas/AWS_S3_Bucket.json": {
        "handlers": {
            "create": {"permissions": ["s3:CreateBucket"]},
            "delete": {"permissions": ["s3:DeleteBucket"]},
        }
    },
    "schemas/AWS_Lambda_Function.json": {"handlers": {"create": {"permissions": ["lambda:CreateFunction"]}}},
    "schemas/AWS_IAM_Role.json": {"handlers": {"create": {"permissions": ["iam:CreateRole"]}}},
    "sam_rules/AWS_Serverless_Function.json": {
        "base_resources": ["AWS::Lambda::Function"],
        "conditional_resources": [
            {"condition": {"path": "properties.Role", "op": "is_null"}, "resources": ["AWS::IAM::Role"]}
        ],
    },
}

async def fetch_json(path):  # async, like the page's pyfetch
    if path not in BACKEND:
        raise core.NotFound(path)
    return BACKEND[path]

TEMPLATE = """
Transform: AWS::Serverless-2016-10-31
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "\${AWS::StackName}-bucket"
  Function:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
"""

analysis = await core.analyze_template(TEMPLATE, fetch_json)
assert not analysis.failures, analysis.unresolved
assert analysis.resource_types == ["AWS::IAM::Role", "AWS::Lambda::Function", "AWS::S3::Bucket"], analysis.resource_types
assert analysis.policy["Statement"] == [
    {"Effect": "Allow", "Action": ["iam:CreateRole", "lambda:CreateFunction", "s3:CreateBucket"], "Resource": "*"},
    # CloudFormation runs the SAM transform as the deploy role.
    {"Effect": "Allow", "Action": ["cloudformation:CreateChangeSet"], "Resource": "arn:*:cloudformation:*:aws:transform/Serverless-2016-10-31"},
    {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
], analysis.policy
assert [t["name"] for t in analysis.to_dict()["transforms"]] == ["AWS::Serverless-2016-10-31"], analysis.transforms
json.dumps(analysis.to_dict())

lookup = await core.analyze_resource_type("AWS::Serverless::Function", fetch_json)
assert lookup.resource_types == ["AWS::IAM::Role", "AWS::Lambda::Function"], lookup.resource_types

# Resource scoping, as the page runs it when an account is entered.
BACKEND.update({
    "servicereference/index.json": {"services": {p: {"filename": f"{p}.json"} for p in ("s3", "iam", "lambda")}},
    "servicereference/s3.json": {
        "actions": {
            "createbucket": {"name": "CreateBucket", "resources": ["bucket"]},
            "deletebucket": {"name": "DeleteBucket", "resources": ["bucket"]},
        },
        "resources": {"bucket": {"arnFormats": ["arn:\${Partition}:s3:::\${BucketName}"]}},
    },
    "servicereference/iam.json": {
        "actions": {"createrole": {"name": "CreateRole", "resources": ["role"]}},
        "resources": {"role": {"arnFormats": ["arn:\${Partition}:iam::\${Account}:role/\${RoleNameWithPath}"]}},
    },
    "servicereference/lambda.json": {
        "actions": {"createfunction": {"name": "CreateFunction", "resources": ["function"]}},
        "resources": {"function": {"arnFormats": ["arn:\${Partition}:lambda:\${Region}:\${Account}:function:\${FunctionName}"]}},
    },
})
scoped = await core.analyze_template(TEMPLATE, fetch_json, account="123456789012", region="eu-west-1")
assert scoped.policy["Statement"] == [
    {"Effect": "Allow", "Action": ["cloudformation:CreateChangeSet"], "Resource": "arn:aws:cloudformation:eu-west-1:aws:transform/Serverless-2016-10-31"},
    {"Effect": "Allow", "Action": ["iam:CreateRole"], "Resource": "arn:aws:iam::123456789012:role/*"},
    {"Effect": "Allow", "Action": ["lambda:CreateFunction"], "Resource": "arn:aws:lambda:eu-west-1:123456789012:function:*"},
    {"Effect": "Allow", "Action": ["s3:CreateBucket"], "Resource": "arn:aws:s3:::*"},
    {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
], scoped.policy
assert scoped.to_dict()["scoping"]["scoped_count"] == 4, scoped.scoping
json.dumps(scoped.to_dict())

cli_only = sorted(m for m in ("typer", "click", "boto3", "cfn2iam.app") if m in sys.modules)
assert not cli_only, cli_only
print(f"cfn2iam {version('cfn2iam')} core OK under Pyodide")
`;

try {
  await pyodide.runPythonAsync(CHECK);
} catch (err) {
  // A PythonError's message is the Python traceback; Node's default report adds Pyodide's minified source.
  console.error(err.message ?? err);
  process.exit(1);
}
