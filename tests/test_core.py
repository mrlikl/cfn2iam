"""Tests for cfn2iam.core, the logic shared by the CLI and the web version."""

import ast
import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from cfn2iam import core

BUCKET = {
    "handlers": {
        "create": {"permissions": ["s3:CreateBucket", "s3:PutBucketTagging"]},
        "read": {"permissions": ["s3:GetBucketTagging"]},
        "delete": {"permissions": ["s3:DeleteBucket", "s3:GetBucketTagging"]},
    }
}
FUNCTION = {
    "handlers": {
        "create": {"permissions": ["lambda:CreateFunction", "iam:PassRole"]},
        "delete": {"permissions": ["lambda:DeleteFunction"]},
    }
}
ROLE = {"handlers": {"create": {"permissions": ["iam:CreateRole"]}, "delete": {"permissions": ["iam:DeleteRole"]}}}
URL = {"handlers": {"create": {"permissions": ["lambda:CreateFunctionUrlConfig"]}}}
SAM_FUNCTION = {
    "base_resources": ["AWS::Lambda::Function"],
    "conditional_resources": [
        {"condition": {"path": "properties.Role", "op": "is_null"}, "resources": ["AWS::IAM::Role"]},
        {"condition": {"path": "properties.FunctionUrlConfig", "op": "truthy"}, "resources": ["AWS::Lambda::Url"]},
    ],
}

BACKEND = {
    "schemas/index.json": {"schemas": [{"typeName": "AWS::S3::Bucket", "filename": "AWS_S3_Bucket.json"}]},
    "schemas/AWS_S3_Bucket.json": BUCKET,
    "schemas/AWS_Lambda_Function.json": FUNCTION,
    "schemas/AWS_IAM_Role.json": ROLE,
    "schemas/AWS_Lambda_Url.json": URL,
    "sam_rules/AWS_Serverless_Function.json": SAM_FUNCTION,
}


def backend(files=None, fail=()):
    """A sync fetch_json over a dict of paths; paths in ``fail`` raise a network-style error."""
    files = BACKEND if files is None else files
    fetched = []

    def fetch(path):
        fetched.append(path)
        if path in fail:
            raise OSError("connection refused")
        if path not in files:
            raise core.NotFound(path)
        return json.loads(json.dumps(files[path]))  # a fresh copy, like a real fetch

    fetch.fetched = fetched
    return fetch


def analyze(template, fetch=None, **kwargs):
    text = template if isinstance(template, str) else json.dumps(template)
    return asyncio.run(core.analyze_template(text, fetch or backend(), **kwargs))


def lookup(resource_type, fetch=None, **kwargs):
    return asyncio.run(core.analyze_resource_type(resource_type, fetch or backend(), **kwargs))


# --- Parsing ------------------------------------------------------------------


def test_yaml_short_form_intrinsics_in_every_node_kind():
    text = """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-data"
      Tags: !If [HasTags, [{Key: a, Value: b}], !Ref AWS::NoValue]
      Other: !Transform {Name: X}
"""
    template = core.parse_template(text)
    props = template["Resources"]["Bucket"]["Properties"]
    assert props["BucketName"] == "${AWS::StackName}-data"
    assert props["Tags"][0] == "HasTags"
    assert props["Other"] == {"Name": "X"}


def test_short_form_tags_do_not_leak_into_the_global_safe_loader():
    import yaml

    with pytest.raises(yaml.YAMLError):
        yaml.safe_load("a: !Ref B")


def test_format_detection_and_errors():
    assert core.parse_template('{"Resources": {}}') == {"Resources": {}}
    assert core.parse_template("Resources: {}") == {"Resources": {}}
    with pytest.raises(core.TemplateError):
        core.parse_template("Resources: [unclosed")
    with pytest.raises(core.TemplateError):
        core.parse_template("Resources: {}", template_format="json")


def test_ignored_and_malformed_resources():
    result = analyze(
        {
            "Resources": {
                "C": {"Type": "Custom::Thing"},
                "M": {"Type": "AWS::CDK::Metadata"},
                "R": {"Type": "AWS::CloudFormation::CustomResource"},
                "NoType": {"Properties": {}},
            }
        }
    )
    assert result.resource_types == []
    assert result.policy == {"Version": "2012-10-17", "Statement": []}


def test_template_without_resources_fetches_nothing():
    fetch = backend()
    result = analyze({"Parameters": {}}, fetch)
    assert result.resource_types == [] and fetch.fetched == []


def test_template_that_is_not_a_mapping_is_an_error():
    with pytest.raises(core.TemplateError):
        analyze("[1, 2]")


# --- Permissions and the policy ----------------------------------------------


def test_policy_allows_handlers_and_denies_delete_only_actions():
    result = analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}})
    assert result.policy["Statement"] == [
        {
            "Effect": "Allow",
            "Action": ["s3:CreateBucket", "s3:GetBucketTagging", "s3:PutBucketTagging"],
            "Resource": "*",
        },
        {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
    ]
    assert result.by_type["AWS::S3::Bucket"] == {
        "allow": ["s3:CreateBucket", "s3:GetBucketTagging", "s3:PutBucketTagging"],
        "delete": ["s3:DeleteBucket"],
    }
    assert result.failures == {}


def test_allow_delete_flips_the_delete_statement():
    result = analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}, allow_delete=True)
    assert [s["Effect"] for s in result.policy["Statement"]] == ["Allow", "Allow"]


def test_action_needed_by_another_type_is_never_denied():
    files = dict(BACKEND)
    files["schemas/AWS_SNS_Topic.json"] = {"handlers": {"update": {"permissions": ["sns:Unsubscribe"]}}}
    files["schemas/AWS_SNS_Subscription.json"] = {"handlers": {"delete": {"permissions": ["sns:Unsubscribe"]}}}
    result = analyze(
        {"Resources": {"T": {"Type": "AWS::SNS::Topic"}, "S": {"Type": "AWS::SNS::Subscription"}}}, backend(files)
    )
    assert result.delete == []
    assert result.by_type["AWS::SNS::Subscription"]["delete"] == ["sns:Unsubscribe"]  # per type, it is delete-only


def test_index_failure_warns_and_uses_conventional_filenames():
    result = analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}, backend(fail={"schemas/index.json"}))
    assert result.failures == {}
    assert result.warnings and "schema index" in result.warnings[0]


def test_index_maps_type_names_to_filenames():
    files = {
        "schemas/index.json": {"schemas": [{"typeName": "AWS::S3::Bucket", "filename": "renamed.json"}]},
        "schemas/renamed.json": BUCKET,
    }
    assert analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}, backend(files)).failures == {}


def test_async_fetch_is_awaited():
    async def fetch(path):
        await asyncio.sleep(0)
        if path not in BACKEND:
            raise core.NotFound(path)
        return BACKEND[path]

    result = analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}, fetch)
    assert result.allow == ["s3:CreateBucket", "s3:GetBucketTagging", "s3:PutBucketTagging"]


# --- Unresolved types ---------------------------------------------------------


def test_unknown_type_is_reported_and_the_rest_still_resolves():
    result = analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}, "X": {"Type": "MyOrg::Private::Thing"}}})
    assert isinstance(result.failures["MyOrg::Private::Thing"], core.UnknownResourceType)
    assert result.unresolved == {"MyOrg::Private::Thing": "no published schema"}
    assert result.resource_types == ["AWS::S3::Bucket", "MyOrg::Private::Thing"]
    assert "s3:CreateBucket" in result.allow


def test_fetch_failure_is_a_schema_error_not_an_unknown_type():
    result = analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}, backend(fail={"schemas/AWS_S3_Bucket.json"}))
    error = result.failures["AWS::S3::Bucket"]
    assert type(error) is core.SchemaError and "could not fetch schema" in str(error)


def test_schema_fallback_is_used_for_missing_schemas_only():
    asked = []

    def fallback(rtype):
        asked.append(rtype)
        return {"handlers": {"create": {"permissions": ["myorg:Create"]}}}

    result = analyze(
        {"Resources": {"B": {"Type": "AWS::S3::Bucket"}, "X": {"Type": "MyOrg::Private::Thing"}}},
        schema_fallback=fallback,
    )
    assert asked == ["MyOrg::Private::Thing"]
    assert "myorg:Create" in result.allow and result.failures == {}


def test_without_published_schemas_every_type_uses_the_fallback():
    fetch = backend()
    result = analyze(
        {"Resources": {"B": {"Type": "AWS::S3::Bucket"}}},
        fetch,
        schema_fallback=lambda rtype: BUCKET,
        published_schemas=False,
    )
    assert fetch.fetched == [] and result.failures == {}


# --- SAM ------------------------------------------------------------------------


def test_sam_conditions_follow_each_resources_properties():
    result = analyze(
        {
            "Resources": {
                "A": {"Type": "AWS::Serverless::Function", "Properties": {"Role": "arn:aws:iam::1:role/x"}},
                "B": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {"Role": "arn:aws:iam::1:role/y", "FunctionUrlConfig": {"AuthType": "AWS_IAM"}},
                },
            }
        }
    )
    assert result.resource_types == ["AWS::Lambda::Function", "AWS::Lambda::Url"]  # no role: both pass one
    assert result.sam_resources == [
        {"logical_id": "A", "type": "AWS::Serverless::Function", "expands_to": ["AWS::Lambda::Function"]},
        {
            "logical_id": "B",
            "type": "AWS::Serverless::Function",
            "expands_to": ["AWS::Lambda::Function", "AWS::Lambda::Url"],
        },
    ]


def test_sam_function_without_role_gets_one():
    result = analyze("Resources:\n  F:\n    Type: AWS::Serverless::Function\n")
    assert result.resource_types == ["AWS::IAM::Role", "AWS::Lambda::Function"]
    assert "iam:CreateRole" in result.allow


def test_sam_type_without_a_rule_is_unresolved():
    result = analyze({"Resources": {"G": {"Type": "AWS::Serverless::Unheard"}}})
    assert result.resource_types == ["AWS::Serverless::Unheard"]
    assert isinstance(result.failures["AWS::Serverless::Unheard"], core.UnknownResourceType)


def test_sam_rule_fetch_failure_is_unresolved_not_skippable():
    fetch = backend(fail={"sam_rules/AWS_Serverless_Function.json"})
    result = analyze(
        {"Resources": {"F": {"Type": "AWS::Serverless::Function"}, "B": {"Type": "AWS::S3::Bucket"}}}, fetch
    )
    error = result.failures["AWS::Serverless::Function"]
    assert type(error) is core.SchemaError and "SAM rule" in str(error)
    assert "schemas/AWS_Serverless_Function.json" not in fetch.fetched
    assert "s3:CreateBucket" in result.allow


def test_unsupported_sam_condition_raises():
    files = dict(BACKEND)
    files["sam_rules/AWS_Serverless_Function.json"] = {
        "base_resources": [],
        "conditional_resources": [{"condition": {"path": "x", "op": "nope"}, "resources": []}],
    }
    with pytest.raises(ValueError, match="unsupported op"):
        analyze({"Resources": {"F": {"Type": "AWS::Serverless::Function"}}}, backend(files))


@pytest.mark.parametrize(
    "op,value,props,expected",
    [
        ("exists", None, {"A": None}, True),
        ("exists", None, {}, False),
        ("truthy", None, {"A": []}, False),
        ("truthy", None, {"A": [1]}, True),
        ("any_eq", "Api", {"E": {"x": {"Type": "Sqs"}, "y": {"Type": "Api"}}}, True),
        ("all_eq", "Api", {"E": {"x": {"Type": "Sqs"}, "y": {"Type": "Api"}}}, False),
        ("is_null", None, {}, True),
        ("is_null", None, {"A": "x"}, False),
    ],
)
def test_condition_ops(op, value, props, expected):
    path = "properties.E.*.Type" if "E" in props else "properties.A"
    assert core.compile_condition_callable(path, op, value)(props) is expected


# --- Single resource type lookup -----------------------------------------------


def test_lookup_of_a_sam_type_includes_everything_it_can_create():
    result = lookup("AWS::Serverless::Function")
    assert result.resource_types == ["AWS::IAM::Role", "AWS::Lambda::Function", "AWS::Lambda::Url"]
    assert result.sam["base_resources"] == ["AWS::Lambda::Function"]
    assert len(result.sam["conditional_resources"]) == 2


def test_lookup_of_a_plain_type():
    result = lookup(" AWS::S3::Bucket ")
    assert result.resource_types == ["AWS::S3::Bucket"] and result.sam is None
    assert result.policy == analyze({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}).policy


def test_lookup_of_an_unknown_type():
    assert lookup("AWS::Nope::Nope").unresolved == {"AWS::Nope::Nope": "no published schema"}


# --- What the web page relies on ------------------------------------------------


def test_to_dict_is_json_ready():
    result = analyze(
        {"Resources": {"F": {"Type": "AWS::Serverless::Function"}, "X": {"Type": "MyOrg::Private::Thing"}}}
    )
    data = json.loads(json.dumps(result.to_dict()))
    assert set(data) == {
        "policy",
        "resource_types",
        "allow",
        "delete",
        "by_type",
        "unresolved",
        "sam_resources",
        "sam",
        "warnings",
    }
    assert data["by_type"]["MyOrg::Private::Thing"] == {
        "allow": [],
        "delete": [],
        "error": "no published schema",
        "unknown": True,
    }
    assert data["by_type"]["AWS::Lambda::Function"]["error"] is None


CORE_PATH = Path(core.__file__)
ALLOWED_IMPORTS = {"asyncio", "inspect", "json", "re", "dataclasses", "functools", "typing", "yaml"}


def test_core_imports_only_what_pyodide_has():
    tree = ast.parse(CORE_PATH.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= ALLOWED_IMPORTS, imported - ALLOWED_IMPORTS


def test_importing_core_does_not_pull_in_the_cli():
    code = "import sys, cfn2iam.core; print(sorted(m for m in ('typer', 'click', 'boto3', 'urllib.request', 'cfn2iam.app') if m in sys.modules))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "[]"
