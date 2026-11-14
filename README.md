# cfn2iam

Generate the IAM policy a CloudFormation stack needs, from its template, before you deploy it.

Deploy roles are usually far broader than the stack needs, often `AdministratorAccess`, because working out the minimum by hand means reading the docs for every resource type in the template. IAM Access Analyzer can generate a policy, but it works from CloudTrail, so you have to deploy with broad permissions first and narrow them afterwards. cfn2iam reads the template instead.

[Web version](https://mrlikl.github.io/cfn2iam/) · [PyPI](https://pypi.org/project/cfn2iam/) · [![Test](https://github.com/mrlikl/cfn2iam/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/mrlikl/cfn2iam/actions/workflows/test.yml)

## Install

```bash
pip install cfn2iam            # or: uv tool install cfn2iam
pip install "cfn2iam[iam]"     # adds boto3, for --create-role and registry lookups of private types
```

If you sign in with `aws login`, boto3 also needs `botocore[crt]` to read those credentials: `pip install "cfn2iam[iam]" "botocore[crt]"` (or `uv tool install "cfn2iam[iam]" --with "botocore[crt]"`). cfn2iam says so, before writing anything, when it is missing.

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
| `-c`, `--create-role` | Also create an IAM role CloudFormation can assume, with this policy inline (needs `cfn2iam[iam]` and AWS credentials). If IAM refuses the policy, the role this run created is deleted again; an existing role is never changed |
| `-r`, `--role-name NAME` | Role name for `--create-role` (default `cfn2iam-<random>`) |
| `-p`, `--permissions-boundary ARN` | Permissions boundary for the created role |
| `--format policy\|json` | `policy` (default): the policy document. `json`: the policy plus the resource types, the actions each one needs, the SAM expansion and any skipped types, written to stdout unless `-o` is given; stdout then carries nothing else |
| `-o`, `--output PATH` | Write to `PATH` instead of `policy-<random>.json` (missing directories are created); `-` for stdout |
| `--ignore-unknown` | Skip resource types found in neither the public schemas nor the CloudFormation registry, instead of failing |
| `--registry` | Look up every resource type with CloudFormation `DescribeType` in your account instead of the published schemas (needs `cfn2iam[iam]` and AWS credentials) |
| `--region REGION` | Region for CloudFormation registry lookups (default: your AWS config). With `--account`, also the region resources are scoped to (default: any region) |
| `--account ID` | New in 0.4: scope resources to this 12-digit account ID: ARNs in the account (and `--region`) instead of `"*"`, wherever IAM supports it. See [Resource scoping](#resource-scoping) |
| `--partition NAME` | Partition for `--account`: `aws` (default), `aws-cn`, `aws-us-gov`, `aws-iso`, `aws-iso-b`, `aws-iso-e`, `aws-iso-f` or `aws-eusc` |
| `--version` | Print the version |

Examples:

```bash
cfn2iam template.yaml -d                       # allow deletes, e.g. for stacks you tear down
cfn2iam template.yaml -c -r MyDeployRole       # create the role as well
cfn2iam template.yaml -c -p arn:aws:iam::123456789012:policy/boundary
cfn2iam template.yaml --account 123456789012 --region eu-west-1   # scope resources to one account and region
```

### What the default policy does on delete

By default the actions that only deleting a resource needs are **denied**, so a role with the default policy can create and update the stack but not tear it down. In practice a stack deletion with that role fails part way: resources whose delete action is also needed by another resource type in the template are deleted (in testing: API Gateway methods, deployments and stages, SNS subscriptions, and queue and topic policies), the rest are refused, and the stack ends in `DELETE_FAILED`. So the Deny protects some resources; it does not leave the stack intact.

Use `-d` (`allow-delete: true` in the Action) for a role that must be able to delete the stack or replace resources: stacks you tear down, preview or test environments, and any update that makes CloudFormation replace a resource (replacing deletes the old one). Keep the default for a long-lived stack whose deletion should go through someone with more access.

## Use it in CI

A policy generated once drifts as soon as the template changes. The check below runs on every pull request: the repository keeps a **baseline**, the policy the deploy role has (or the cfn2iam output it was built from), and each pull request regenerates the policy from the changed templates and compares the two. The pull request gets a comment saying which actions were added or are no longer needed, and the check fails when the templates now need actions the baseline doesn't grant, before a deploy fails on them.

### GitHub Actions

```yaml
# .github/workflows/iam.yml
name: IAM permissions

on:
  pull_request:  # every pull request: see below before adding a paths filter

permissions:
  contents: read        # check out the templates
  pull-requests: write  # the comment; without it, the report is in the job summary only

jobs:
  cfn2iam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: mrlikl/cfn2iam@v0
        with:
          templates: templates/*.yaml
          baseline: iam/deploy-policy.json
```

The first run finds no baseline, lists what the templates need, and prints the commands that create it (it doesn't fail unless `require-baseline: true`). Commit that file and give the deploy role the same policy, or one that grants at least as much. The baseline is the deploy role's policy, with the same options: a role given the default policy can't delete the stack (see [What the default policy does on delete](#what-the-default-policy-does-on-delete)), so if it has to, set `allow-delete: true` on the action and generate the baseline with `-d`.

**Don't filter on paths if the check is required.** With `paths:` (say, `["templates/**", "iam/deploy-policy.json"]`), a pull request that changes neither never runs the check, and a required check that never runs stays pending, so the pull request can't merge. The check takes well under a minute, so run it on every pull request. To skip it anyway, leave it out of the required checks, or keep the workflow unfiltered and skip inside it (for example with a step that compares the changed files and exits early) so the check still reports.

The action installs cfn2iam from its own files, not from PyPI, so the ref you pin is exactly the code that runs, with the dependency versions in its `uv.lock`. It sets up [uv](https://docs.astral.sh/uv/), which uses an installed Python 3.11+ or downloads one, so the job needs no `setup-python`. It needs network access to PyPI and to the schema host. It runs on Linux, macOS and Windows runners.

Pin a release tag (`mrlikl/cfn2iam@v0.4.1`) or a commit SHA for a fixed version, or `@v0` to follow the 0.x releases. Dependabot updates both a tag and a SHA pin. Whatever the pin, the report's footer shows the cfn2iam version that ran, and the commands it prints install that version.

| Input | Default | |
|---|---|---|
| `templates` | (required) | Template files, one per line: paths or globs (`**` for any depth), relative to the workspace. Their permissions are combined, as for one role that deploys every template |
| `baseline` | none | Baseline policy file; several (one per line) combine, as for a role with several policies. Without one, the action lists what the templates need |
| `fail-on-drift` | `true` | Fail when the templates need actions the baseline doesn't grant |
| `comment` | `always` | `always`, `on-change` (comment only when something differs; an existing comment is still updated) or `never`. One comment per pull request, updated on each push |
| `conditional` | `missing` | How to count actions the baseline grants only under a `Condition` or for specific resources: `missing` or `granted` (see [How the baseline is read](#how-the-baseline-is-read)) |
| `allow-delete` | `false` | `-d`: allow the delete-only actions instead of denying them |
| `ignore-unknown` | `false` | `--ignore-unknown`: skip resource types with no schema |
| `require-baseline` | `false` | Fail when the baseline file doesn't exist yet |
| `update-baseline` | `false` | Write the generated policy to the baseline file instead of failing on drift (needs one `baseline` file). The outputs then describe the new baseline (`drift` is `false`), and the report says what changed |
| `name` | none | Names the check. Give every invocation in a workflow its own `name`: invocations with the same name (or none) share one pull request comment and replace each other's report (within one job the action warns when that happens) |
| `account` | none | `--account`: scope resources to this 12-digit account ID (new in 0.4; see [Resource scoping](#resource-scoping)) |
| `region` | none | `--region`: the region resources are scoped to with `account`, and the region for registry lookups |
| `partition` | none | `--partition`, for `account` (default `aws`); without `account` it is an error |
| `registry-fallback` | `false` | Install `cfn2iam[iam]`, so types with no public schema (private or third-party) are looked up with CloudFormation `DescribeType`. Needs AWS credentials in the job |
| `python-version` | uv's choice | Python for cfn2iam, 3.11 or later |
| `github-token` | `github.token` | Token for the comment |

| Output | |
|---|---|
| `drift` | `true` when the templates need actions the baseline doesn't grant |
| `added-count` | Actions needed and not granted (0 without a baseline) |
| `removed-count` | Baseline `Allow` entries that no needed action matches |
| `conditional-count` | Needed actions the baseline grants only under a condition or for some resources |
| `baseline-status` | `found`, `missing` (not created yet) or `none` (no `baseline` input) |
| `baseline-updated` | `true` when `update-baseline` wrote the baseline file |
| `policy-path` | The generated policy, all templates combined |
| `report-path` | The report in Markdown, as in the job summary |
| `commented`, `comment-url` | Whether the pull request comment was written, and its URL |
| `error` | `true` when the check couldn't run (an invalid input, cfn2iam failed to install, a template missing or unresolvable, an invalid baseline) |

Use the outputs in a later step by giving the action an `id`. Pass them through `env:` rather than writing `${{ }}` into the script: that is safe for any value, and on Windows runners the paths have backslashes, which bash would otherwise mangle.

```yaml
      - id: iam
        uses: mrlikl/cfn2iam@v0
        with:
          templates: templates/*.yaml
          baseline: iam/deploy-policy.json
          fail-on-drift: false
      - if: steps.iam.outputs.drift == 'true'
        shell: bash
        env:
          ADDED: ${{ steps.iam.outputs.added-count }}
          POLICY: ${{ steps.iam.outputs.policy-path }}
        run: |
          echo "The templates need $ADDED more actions; the policy they need is:"
          cat "$POLICY"
```

Every run writes the report to the job summary. On a pull request it also comments, like this:

> #### cfn2iam permission check
>
> **Permission drift: the templates need 102 actions the baseline does not grant.**
>
> Templates: `samples/cfn.json` · Baseline: `tests/fixtures/action/drift-baseline.json`
>
> | | Actions | Counts as drift |
> |---|--:|:-:|
> | Needed, not granted by the baseline | 52 | yes |
> | Granted only under a condition or for some resources | 50 | yes |
> | Allowed by the baseline, no longer needed | 1 | no |
> | Delete-only, newly denied | 5 | no |
> | Denied by the baseline, no longer denied | 1 | no |
>
> **Needed, not granted by the baseline (52)**
>
> <details><summary><code>kms</code> (7)</summary>
>
> - `kms:CreateGrant` (AWS::DynamoDB::Table, AWS::Lambda::Function)
> - `kms:Decrypt` (AWS::DynamoDB::Table, AWS::Lambda::Function)
> - ...
>
> </details>
> <details><summary><code>lambda</code> (23)</summary>
>
> - `lambda:CreateFunction` (AWS::Lambda::Function)
> - ...
>
> </details>
>
> **Granted only under a condition or for some resources (50)**
>
> <details><summary>31 actions: allowed by tests/fixtures/action/drift-baseline.json, statement 2 (Sid "TablesInOneRegion"), which has a Condition</summary>
>
> | Service | Actions |
> |---|---|
> | `dynamodb` | `CreateTable`, `DescribeTable`, `UpdateTable`, ... |
>
> </details>
>
> **Allowed by the baseline, no longer needed (1)** · **Delete-only actions** · How to accept this change · The generated policy (each collapsed)

That is the self-test in this repository's CI (trimmed), with a hand-written baseline. Each section is grouped by service and collapsed when long. If the comment has to be cut to fit GitHub's size limit, it says what was left out (the resource types behind each action, the generated policy) and links to the job summary, which has the full report. Warnings, such as a policy over IAM's size limits or custom resources the policy has nothing for, are in both. When nothing changed it says **No permission changes: the baseline grants exactly what the templates need.**

**Accepting a change.** When a pull request needs new permissions on purpose, grant them to the deploy role and regenerate the baseline in the same pull request, so the change is reviewed with the template. The comment prints the exact commands; for one template:

```bash
cfn2iam templates/app.yaml -o iam/deploy-policy.json
```

For several, generate each and combine them:

```bash
cfn2iam templates/a.yaml -o /tmp/a.json
cfn2iam templates/b.yaml -o /tmp/b.json
cfn2iam diff /tmp/a.json /tmp/b.json -w iam/deploy-policy.json
```

`cfn2iam -o` and `cfn2iam diff -w` create the baseline's directory if it doesn't exist yet. If the baseline is a hand-written policy (with wildcards or conditions), edit it instead: regenerating replaces it (the comment says so when the baseline looks hand-written).

To regenerate it in CI instead, run the action with `update-baseline: true` and commit the file in a later step, for example from a `workflow_dispatch` workflow with `contents: write`, run on the pull request's branch. GitHub lists and runs a `workflow_dispatch` workflow only once the workflow file is on the default branch, so merge it first. A push made with the workflow's `GITHUB_TOKEN` doesn't start the usual runs on that commit: depending on the repository's settings it starts none, or runs that wait for someone to approve them. Either way the required check doesn't pass on its own until something else is pushed or the runs are approved; check out with a GitHub App or personal access token if the checks must run by themselves.

**Forks and Dependabot.** Pull requests from forks, and Dependabot's, get a read-only token on `pull_request`, so the action can't comment there. It says so in a notice and the job summary, and the check itself still passes or fails as usual. (A token GitHub rejects outright, HTTP 401, is reported as a bad `github-token` instead.) Don't switch to `pull_request_target` to get a write token unless no step runs code from the pull request.

**Other events.** On `push` (or any event without a pull request) the check runs and writes the job summary, without a comment.

**Several stacks.** The templates in one run are combined, for one deploy role (the action warns if the combined policy is over IAM's size limits). When each stack has its own role and policy, run the action once per stack, each with its own `name`, also when the invocations are in different jobs or workflows; without distinct names they would share, and overwrite, one comment:

```yaml
      - uses: mrlikl/cfn2iam@v0
        with: { name: network, templates: stacks/network.yaml, baseline: iam/network.json }
      - uses: mrlikl/cfn2iam@v0
        with: { name: app, templates: stacks/app/*.yaml, baseline: iam/app.json }
```

### Other CI systems

The comparison is part of the CLI, so the same check runs anywhere:

```bash
pip install cfn2iam
cfn2iam templates/app.yaml --format json -o /tmp/app.json
cfn2iam diff /tmp/app.json --baseline iam/deploy-policy.json   # --format markdown for a merge request note
```

`cfn2iam diff GENERATED... [-b BASELINE]...` reads files that cfn2iam wrote (`--format json` output also says which resource types need each action) and combines several. `--format text|json|markdown` and `-o` set the report, `-w FILE` also writes the combined policy (to create or refresh a baseline), and `--conditional granted` counts conditional grants as granted. Its exit status: `0` when the baseline grants everything the templates need, `3` when it doesn't (permission drift), `1` on an error such as an unreadable file, `2` on a usage error. Generating the policy keeps exiting `1` when a resource type can't be resolved.

### How the baseline is read

The baseline can be a policy document (one statement or several), the output of `aws iam get-role-policy` or `aws iam get-policy-version`, or cfn2iam output. Each action the templates need is evaluated the way IAM would, for the resources the generated policy gives it:

- Action names match case-insensitively, with `*` and `?` wildcards: `s3:*` and `ec2:Describe*` grant what they cover, and `"Action": "*"` grants everything.
- An explicit `Deny` that covers an action makes it not granted, whatever allows it.
- `NotAction` and `NotResource` are evaluated exactly: an `Allow` with `NotAction: iam:*` grants every action except IAM's.
- A `Condition`, or a `Resource` narrower than what the generated policy needs (including policy variables), can't be checked from a template: whether a condition holds, or which resources CloudFormation creates, is only known at deploy time. Such an action is reported as **conditional**, with the statement that made it so. By default it counts as not granted, so the check fails closed; set `conditional: granted` (`--conditional granted`) if your conditions hold for deploys. A conditional `Deny` makes an action conditional too.
- Resources: each action is checked on every resource the generated policy gives it. A baseline statement on `"*"` covers any ARN, so a baseline made without `--account` still covers a scoped policy. A baseline statement limited to ARNs covers a scoped ARN pattern only if it includes it (`arn:aws:sqs:*:123456789012:*` includes `arn:aws:sqs:us-east-1:123456789012:*`), and covers `"*"` only conditionally. Keep the baseline and the check on the same scoping options, or the comparison reports conditional grants.
- "No longer needed" lists the baseline's `Allow` entries that no needed action matches, wildcards included. Delete-only changes (actions the generated policy denies) are listed separately and never count as drift.

## How it works

1. Reads the template (JSON or YAML, including short-form intrinsics like `!Ref`) and collects the resource types.
2. Expands SAM resources (`AWS::Serverless::*`) into the resources SAM creates, using rules that check the resource's properties (for example, a function with an SQS event also needs the event source mapping). Resources in `Fn::ForEach` loops (`AWS::LanguageExtensions`) count too.
3. Fetches each type's CloudFormation resource schema from [mrlikl.github.io/cfn2iam/backend/schemas](https://mrlikl.github.io/cfn2iam/backend/schemas/). These are AWS's published schemas, refreshed weekly by a GitHub workflow. The SAM expansion rules live next to them, in `backend/sam_rules`.
4. For a type with no public schema (a private type, or a third-party type activated in your account), it calls CloudFormation `DescribeType` in your account and region. This needs `cfn2iam[iam]`, AWS credentials and `cloudformation:DescribeType`. With `--registry`, every type is looked up this way; SAM rules still come from the published rules.
5. Takes the permissions each schema lists for its `create`, `read`, `update` and `list` handlers as **Allow**, and the permissions only its `delete` handler needs as **Deny** (or Allow with `-d`).
6. For each transform the template uses (`Transform`, or `Fn::Transform` anywhere), allows `cloudformation:CreateChangeSet` on that transform, such as `arn:aws:cloudformation:<region>:aws:transform/Serverless-2016-10-31` for SAM. When a stack is deployed with a service role, CloudFormation runs the transform as that role and checks this permission first; without it every SAM deploy fails at once. The same holds for `AWS::LanguageExtensions` and `AWS::Include` (account `aws`) and for macros (your account), as tested in a real account. `AWS::Include` also needs `s3:GetObject` on each snippet, which cfn2iam can't read, so it warns instead.
7. With `--account`, scopes the Allow statements to that account, region and partition, using AWS's [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html), also republished weekly under `backend/servicereference`. See [Resource scoping](#resource-scoping).

If any resource type can't be resolved, cfn2iam lists them, writes no policy, and exits with status 1. A partial policy would fail mid-deploy at best. Network failures (including a SAM rule that can't be fetched) can't be skipped; types found nowhere can, with `--ignore-unknown`. With `--account`, the same goes for the Service Authorization Reference: if it can't be fetched, no policy is written, rather than an unscoped one.

If the policy is over IAM's size limits, cfn2iam warns on stderr and still writes it. The limits count every character but whitespace: 6,144 for one customer managed policy, and 10,240 for all of a role's inline policies together. Between the two, attach it inline (as `--create-role` does) or split it into several managed policies; over 10,240, only splitting works, and `--create-role` refuses before creating anything.

### Resource scoping

Scoping is new in 0.4 and off unless you pass `--account`. It has been deployed against real AWS for a handful of templates (S3, Lambda, IAM, DynamoDB, SQS, SNS, Step Functions, EventBridge, CloudWatch, SSM, API Gateway and SAM), with a role holding only the scoped policy, and the fixes in 0.4.1 came from those tests. AWS services don't always authorize a call against the resource the Service Authorization Reference lists, so other resource types may still be denied: if a scoped policy is denied something the unscoped one allows, please [open an issue](https://github.com/mrlikl/cfn2iam/issues) with the error message.

`--region` alone keeps its old meaning (registry lookups only) and scopes nothing. With `--account`:

1. Each action is looked up in the Service Authorization Reference, which lists the resource types it can be scoped to and their ARN formats, such as `arn:${Partition}:sqs:${Region}:${Account}:${QueueName}`.
2. `${Partition}`, `${Region}` and `${Account}` (or `${AccountId}`) are filled in, each only in its own ARN segment, and every other placeholder becomes `*`: `arn:aws:sqs:eu-west-1:123456789012:*`. Without `--region`, the region segment is `*`. Segments AWS writes literally are kept: S3 bucket and object ARNs have no account or region (`arn:aws:s3:::*`), IAM ARNs no region (`arn:aws:iam::123456789012:role/*`), AMIs no account.
3. An action is allowed on every resource type the reference lists for it (`ec2:RunInstances` lists 18), because the reference doesn't say which are required.
4. The Allow statements are grouped by service: one statement holds a service's scoped actions and all their ARN patterns. IAM checks an action only against ARNs of the resource types it acts on, so this grants nothing outside the account and region, and it keeps the policy close to its unscoped size. Patterns another pattern covers are dropped (`arn:aws:s3:::*` covers `arn:aws:s3:::*/*`), and more than four patterns of one service, region and account become `arn:aws:<service>:<region>:<account>:*`, except where IAM would read that pattern as another resource type: an S3 resource without a type prefix is a bucket, which has no region or account, so IAM rejects `arn:aws:s3:<region>:<account>:*`, and S3's patterns are always listed one by one. Every such pattern the reference can produce was checked against IAM; only S3's were refused.
5. Whatever can't be scoped with confidence stays in one Allow statement on `"Resource": "*"`, so no action is dropped. That includes the few actions AWS authorizes against `"*"` in some calls although the reference lists resource types for them, such as `lambda:GetEventSourceMapping` and `lambda:DeleteEventSourceMapping` once the mapping is gone (`core.ACTIONS_ON_STAR` lists them, with the evidence for each). cfn2iam prints a one-line summary on stderr of how many actions were scoped, and how many stayed on `"*"` and why.

```json
{ "Effect": "Allow", "Action": ["iam:CreateRole", "iam:PassRole", "..."], "Resource": "arn:aws:iam::123456789012:role/*" },
{ "Effect": "Allow", "Action": ["sqs:CreateQueue", "..."], "Resource": "arn:aws:sqs:eu-west-1:123456789012:*" },
{ "Effect": "Deny",  "Action": ["s3:DeleteBucket", "..."], "Resource": "*" }
```

In the core, `analyze_template(...)` and `analyze_resource_type(...)` take `account`, `region` and `partition` keyword arguments with the same rule: scoping is on exactly when `account` is given, and `region` or `partition` without it raises `core.ScopeError`. `Analysis.scoping` (also in `to_dict()`) has the counts, the actions left on `"*"` by reason, and the scoped actions left open to other regions or accounts on purpose.

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

- **Scoping is to the account and region, not to resource names.** By default every statement uses `"Resource": "*"`. With `--account` the Allow statements name ARNs in that account and region, with `*` for every name, ID and path: most names don't exist until the stack does, and CloudFormation generates many of them.
- **Some actions always stay on `"*"`.** Actions with no resource-level permissions (such as most `Describe` and `List` actions), actions the Service Authorization Reference doesn't have (often mistakes in AWS's schemas, such as `s3:HeadObject`), unknown service prefixes, wildcard actions such as `ec2:Describe*`, and the few resource types whose ARN format can't be filled in (an AWS Backup recovery point's service segment is a placeholder, and IAM allows no wildcard there). `efs:`, `emr:` and `stepfunctions:` in a schema are not IAM service prefixes. They are reported with a warning, and not mapped to `elasticfilesystem:`, `elasticmapreduce:` and `states:`, because IAM ignores the action whatever its `Resource` says.
- **Scoping assumes the stack's resources are in that account and region.** A template that refers to resources elsewhere is denied them: a KMS key, SNS topic or container image in another account, or an existing resource in another region referred to by its ARN. A few cases are handled: Lambda layer versions are allowed in any account (AWS and vendors publish layers from their own accounts), and the actions of `AWS::DynamoDB::GlobalTable`, `AWS::KMS::ReplicaKey`, `AWS::RDS::GlobalCluster`, `AWS::SecretsManager::Secret` and the VPC and transit gateway peering types are allowed in any region (and, for peering, any account). Leave out `--region` to allow every region.
- **The delete statement is an explicit Deny, and is never scoped.** An explicit Deny overrides an Allow from any other policy attached to the same role. Limiting it to the account's ARNs would deny less, so it stays on `"Resource": "*"` with `--account` too. Use `-d` if the role also has to delete these resources; the delete actions are then scoped like the other Allow actions.
- **Custom resources are skipped** (`Custom::*`, `AWS::CloudFormation::CustomResource`; `AWS::CDK::Metadata` needs nothing). cfn2iam warns about each one it skips, in the CLI, the Action's report and `to_dict()["skipped_resources"]`. Anything they need, such as `lambda:InvokeFunction` on their ServiceToken function when CloudFormation deploys with a service role, isn't included.
- **Delete-only read actions are denied too.** The Deny lists every action only a delete handler needs, including read actions such as `ec2:DescribeNetworkInterfaces` (Lambda's delete handler). An explicit Deny on `"*"` also applies to everything else attached to the same role, so don't attach the deploy policy to a role that needs those actions for other work, or use `-d`.
- **The policy is only as complete as AWS's schemas.** The handler permission lists are maintained by AWS and can be incomplete for some resource types or configurations. Test the policy on a non-production stack first.

## How it compares

| | cfn2iam | IAM Access Analyzer policy generation | Writing the policy by hand |
|---|---|---|---|
| When it runs | Before the first deploy | After the role has been used: it reviews up to 90 days of the role's past activity | Any time |
| What it reads | The template, AWS's CloudFormation resource schemas (the permissions each handler needs) and, for scoping, the Service Authorization Reference | Your CloudTrail trail (it must exist and log the account) and IAM's last-accessed information | The documentation for every resource type and service in the template |
| Needs a broad deploy first | No | Yes: the role has to deploy the stack with broader permissions, so the actions show up in CloudTrail | No, but usually several failed deploys while you find what's missing |
| Actions it can miss | Whatever AWS's schemas leave out | `iam:PassRole` (CloudTrail doesn't record it), action-level detail for data events such as S3 object access, and anything the role didn't do in the period (such as updates or deletes) | Whatever you miss |
| Resource scoping | Optional, to the account and region (`--account`, `--region`); names stay `*` | A policy template with placeholder ARNs for actions that support resource-level permissions, for you to fill in | As narrow as you write it |

Sources: [IAM Access Analyzer policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html).

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
