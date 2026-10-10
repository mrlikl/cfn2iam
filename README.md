# cfn2iam

Generate the IAM policy a CloudFormation stack needs, from its template, before you deploy it.

Deploy roles are usually far broader than the stack needs, often `AdministratorAccess`, because working out the minimum by hand means reading the docs for every resource type in the template. IAM Access Analyzer can generate a policy, but it works from CloudTrail, so you have to deploy with broad permissions first and narrow them afterwards. cfn2iam reads the template instead.

[Web version](https://mrlikl.github.io/cfn2iam/) · [PyPI](https://pypi.org/project/cfn2iam/)

## Install

```bash
pip install cfn2iam            # or: uv tool install cfn2iam
pip install "cfn2iam[iam]"     # adds boto3, for --create-role and registry lookups of private types
```

Requires Python 3.9+ and network access to the schema host (see [How it works](#how-it-works)).

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

If any resource type can't be resolved, cfn2iam lists them, writes no policy, and exits with status 1. A partial policy would fail mid-deploy at best. Network failures can't be skipped; types found nowhere can, with `--ignore-unknown`.
## Limitations

- **Actions, not resources.** Every statement uses `"Resource": "*"`. Resource ARNs mostly don't exist until the stack does, so the policy is least-privilege on actions only.
- **The delete statement is an explicit Deny.** An explicit Deny overrides an Allow from any other policy attached to the same role. Use `-d` if the role also has to delete these resources.
- **Custom resources are skipped** (`Custom::*`, `AWS::CloudFormation::CustomResource`, `AWS::CDK::Metadata`). Anything they need, such as permission to invoke their Lambda function, isn't included.
- **The policy is only as complete as AWS's schemas.** The handler permission lists are maintained by AWS and can be incomplete for some resource types or configurations. Test the policy on a non-production stack first.

## License

MIT. See [LICENSE](LICENSE).
