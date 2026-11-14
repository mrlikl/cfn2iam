# cfn2iam

Generate the IAM policy a CloudFormation stack needs, from its template, before you deploy it.

Deploy roles are usually far broader than the stack needs, often `AdministratorAccess`, because working out the minimum by hand means reading the docs for every resource type in the template. IAM Access Analyzer can generate a policy, but it works from CloudTrail, so you have to deploy with broad permissions first and narrow them afterwards. cfn2iam reads the template instead.

[Web version](https://mrlikl.github.io/cfn2iam/) · [PyPI](https://pypi.org/project/cfn2iam/) · [![Test](https://github.com/mrlikl/cfn2iam/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/mrlikl/cfn2iam/actions/workflows/test.yml)

## Install

```bash
pip install cfn2iam            # or: uv tool install cfn2iam
pip install "cfn2iam[iam]"     # adds boto3, for --create-role and registry lookups of private types
```

Requires Python 3.11+ and network access to the schema host (see [How it works](#how-it-works)).

## Usage

```bash
cfn2iam template.yaml
```

This writes `policy-<random>.json` to the current directory:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:CreateBucket", "s3:GetBucketTagging", "..."], "Resource": "*" },
    { "Effect": "Deny",  "Action": ["s3:DeleteBucket", "..."], "Resource": "*" }
  ]
}
```

| Option | Effect |
|---|---|
| `-d`, `--allow-delete` | Allow the delete-only actions instead of denying them |
| `-c`, `--create-role` | Also create an IAM role CloudFormation can assume, with this policy inline (needs `cfn2iam[iam]` and AWS credentials) |
| `-r`, `--role-name NAME` | Role name for `--create-role` (default `cfn2iam-<random>`) |
| `-p`, `--permissions-boundary ARN` | Permissions boundary for the created role |
| `--ignore-unknown` | Skip resource types found in neither the public schemas nor the CloudFormation registry, instead of failing |
| `--registry` | Look up every resource type with CloudFormation `DescribeType` in your account instead of the published schemas (needs `cfn2iam[iam]` and AWS credentials) |
| `--region REGION` | Region for CloudFormation registry lookups (default: your AWS config) |
| `--version` | Print the version |

Examples:

```bash
cfn2iam template.yaml -d                       # allow deletes, e.g. for stacks you tear down
cfn2iam template.yaml -c -r MyDeployRole       # create the role as well
cfn2iam template.yaml -c -p arn:aws:iam::123456789012:policy/boundary
```

## How it works

1. Reads the template (JSON or YAML, including short-form intrinsics like `!Ref`) and collects the resource types.
2. Expands SAM resources (`AWS::Serverless::*`) into the resources SAM creates, using rules that check the resource's properties (for example, a function with an SQS event also needs the event source mapping).
3. Fetches each type's CloudFormation resource schema from [mrlikl.github.io/cfn2iam/backend/schemas](https://mrlikl.github.io/cfn2iam/backend/schemas/). These are AWS's published schemas, refreshed weekly by a GitHub workflow. The SAM expansion rules live next to them, in `backend/sam_rules`.
4. For a type with no public schema (a private type, or a third-party type activated in your account), it calls CloudFormation `DescribeType` in your account and region. This needs `cfn2iam[iam]`, AWS credentials and `cloudformation:DescribeType`. With `--registry`, every type is looked up this way; SAM rules still come from the published rules.
5. Takes the permissions each schema lists for its `create`, `read`, `update` and `list` handlers as **Allow**, and the permissions only its `delete` handler needs as **Deny** (or Allow with `-d`).

If any resource type can't be resolved, cfn2iam lists them, writes no policy, and exits with status 1. A partial policy would fail mid-deploy at best. Network failures (including a SAM rule that can't be fetched) can't be skipped; types found nowhere can, with `--ignore-unknown`.

### One implementation, two front ends

The logic lives in `cfn2iam.core`: template parsing, SAM expansion, permissions from the schema handlers, and the policy document. It does no I/O of its own; it reads schemas and SAM rules through a fetch function its caller passes in, and needs only PyYAML. The CLI (`cfn2iam.app`) wraps it with HTTPS fetching, registry lookups, `--create-role` and file output. The [web version](https://mrlikl.github.io/cfn2iam/) installs this same package in the browser with [Pyodide](https://pyodide.org/), so both produce the same policy.

```python
import asyncio
from cfn2iam import core


def fetch_json(path):  # e.g. "schemas/AWS_S3_Bucket.json"; may also be async
    ...  # return the parsed JSON, or raise core.NotFound if there is no such file


analysis = asyncio.run(core.analyze_template(open("template.yaml").read(), fetch_json))
analysis.policy  # the policy document
analysis.failures  # resource types that couldn't be resolved, and why
```

## Limitations

- **Actions, not resources.** Every statement uses `"Resource": "*"`. Resource ARNs mostly don't exist until the stack does, so the policy is least-privilege on actions only.
- **The delete statement is an explicit Deny.** An explicit Deny overrides an Allow from any other policy attached to the same role. Use `-d` if the role also has to delete these resources.
- **Custom resources are skipped** (`Custom::*`, `AWS::CloudFormation::CustomResource`, `AWS::CDK::Metadata`). Anything they need, such as permission to invoke their Lambda function, isn't included.
- **The policy is only as complete as AWS's schemas.** The handler permission lists are maintained by AWS and can be incomplete for some resource types or configurations. Test the policy on a non-production stack first.

## Development

The project uses [uv](https://docs.astral.sh/uv/). These are the main checks CI runs on every pull request:

```bash
uv sync                                   # add --extra iam to include boto3 and its tests
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv lock --check                           # uv.lock matches pyproject.toml
uv build && uvx twine check --strict dist/*
```

CI also runs the tests on every Python from 3.11 to 3.15 on Linux (and the oldest and newest on macOS and Windows), installs the built wheel into a clean environment and runs the CLI on `samples/`, and installs the wheel in [Pyodide](https://pyodide.org/) to check that `cfn2iam.core` still runs in the browser (`tests/pyodide/smoke.mjs`).

### Releasing

Merge everything for the release into `main` through pull requests, then tag the merge commit and push the tag:

```bash
git switch main && git pull
git tag v0.3.1 && git push origin v0.3.1
```

The tag starts `.github/workflows/publish.yml`, which:

1. checks that the tag is a full `vX.Y.Z` version and that its commit is on `main`;
2. runs the whole test workflow above, including the build;
3. uploads that build's wheel and sdist to [PyPI](https://pypi.org/project/cfn2iam/) with trusted publishing (the `pypi` environment);
4. once the upload has succeeded, checks the files against what PyPI serves and creates the [GitHub Release](https://github.com/mrlikl/cfn2iam/releases) for the tag, with the same wheel and sdist attached.

The version comes from the tag (hatch-vcs), so there is nothing to bump in the code. If any step fails, nothing after it runs: no upload without a green test run, and no Release without a successful upload. A moving tag such as `v1` never publishes or creates a Release. After fixing the cause of a failed Release step, use **Re-run failed jobs** on the run; the release job skips what already exists.

The release notes are GitHub's generated notes: install instructions for the version, then the pull requests merged since the previous `vX.Y.Z` tag, grouped by label as set in `.github/release.yml` (`breaking`, `enhancement`, `bug` and `documentation`; unlabelled pull requests under "Changes"; Dependabot's under "Dependency updates"). So the changelog is the pull request titles: give them titles that make sense to a user. There is no `CHANGELOG.md` to update. Notes can be edited on GitHub after the Release is created, and a re-run leaves them alone.

## License

MIT. See [LICENSE](LICENSE).
