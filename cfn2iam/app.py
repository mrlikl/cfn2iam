#!/usr/bin/env python3
"""The cfn2iam command line: fetching, registry lookups, role creation and file output.

The logic itself lives in :mod:`cfn2iam.core`, which the web version also runs.
"""

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from enum import StrEnum
from importlib.metadata import version
from typing import Dict, Optional

import typer

from . import core
from .core import NotFound, SchemaError, UnknownResourceType, generate_policy_document  # noqa: F401  (re-exported)

SCHEMA_BASE_URL = "https://mrlikl.github.io/cfn2iam/backend"
MAX_WORKERS = 8


class OutputFormat(StrEnum):
    policy = "policy"
    json = "json"


def version_callback(value: bool):
    if value:
        try:
            pkg_version = version("cfn2iam")
        except Exception:
            pkg_version = "unknown"
        print(f"cfn2iam {pkg_version}")
        raise typer.Exit()


def _fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "cfn2iam/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise NotFound(url) from e
        raise


def _has_boto3() -> bool:
    try:
        import boto3  # noqa: F401
    except ImportError:
        return False
    return True


def get_registry_schema(resourcetype: str, region: Optional[str]) -> Dict:
    """Look the type up with CloudFormation DescribeType in the caller's account and region."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        # A session per call: the default session isn't safe to share across worker threads.
        client = boto3.session.Session().client("cloudformation", region_name=region)
        response = client.describe_type(Type="RESOURCE", TypeName=resourcetype)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "TypeNotFoundException":
            raise UnknownResourceType(f"not in the CloudFormation registry in {client.meta.region_name}") from e
        raise SchemaError(f"registry lookup failed: {e}") from e
    except BotoCoreError as e:
        raise SchemaError(f"registry lookup failed: {e}") from e
    return json.loads(response["Schema"])


async def analyze_template_file(
    template_path: str,
    region: Optional[str] = None,
    use_registry: bool = False,
    allow_delete: bool = False,
    account: Optional[str] = None,
    partition: str = "aws",
) -> core.Analysis:
    """Run the core on a template file, fetching schemas and registry lookups on a thread pool.

    With ``account``, the policy is scoped to it, ``partition`` and ``region`` (which then
    does both jobs: registry lookups and scoping). Without it, ``region`` is only for the registry.
    """
    # Read before any fetch starts, so blocking the event loop here costs nothing.
    with open(template_path) as f:  # noqa: ASYNC230
        text = f.read()
    template_format = "json" if template_path.endswith(".json") else "yaml"
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:

        async def fetch(path):
            return await loop.run_in_executor(pool, _fetch_json, f"{SCHEMA_BASE_URL}/{path}")

        async def registry(resourcetype):
            return await loop.run_in_executor(pool, get_registry_schema, resourcetype, region)

        async def registry_fallback(resourcetype):
            # No public schema: likely a private or activated third-party type, so try the registry.
            if not _has_boto3():
                raise UnknownResourceType(
                    'no public schema; install "cfn2iam[iam]" to look it up in the CloudFormation registry'
                )
            try:
                schema = await registry(resourcetype)
            except SchemaError as e:
                raise UnknownResourceType(f"no public schema, and {e}") from e
            print(f"Resolved {resourcetype} from the CloudFormation registry", file=sys.stderr)
            return schema

        return await core.analyze_template(
            text,
            fetch,
            template_format=template_format,
            allow_delete=allow_delete,
            schema_fallback=registry if use_registry else registry_fallback,
            published_schemas=not use_registry,
            account=account,
            region=region if account else None,
            partition=partition,
        )


def scoping_summary(scoping: Dict) -> str:
    """One line on what scoping did, from Analysis.scoping."""
    total = scoping["scoped_count"] + scoping["unscoped_count"]
    where = f"account {scoping['account']}, " + (f"region {scoping['region']}" if scoping["region"] else "any region")
    line = f"Scoped {scoping['scoped_count']} of {total} actions to {where} (partition {scoping['partition']})"
    if scoping["unscoped"]:
        reasons = "; ".join(
            f"{len(actions)} {core.UNSCOPED_REASONS.get(reason, reason)}"
            for reason, actions in scoping["unscoped"].items()
        )
        line += f'. On "Resource": "*": {reasons}'
    return line + "."


def generate_random_hash():
    return uuid.uuid4().hex[:8]


def aws_credentials_problem() -> Optional[str]:
    """Why boto3 can't sign requests with the caller's AWS credentials, or None when it can.

    Checked before anything is written, so --create-role fails before the policy file appears.
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, MissingDependencyException
    except ImportError:
        return 'boto3 is required for IAM role creation. Install with: pip install "cfn2iam[iam]"'
    try:
        credentials = boto3.session.Session().get_credentials()
    except MissingDependencyException:
        return (
            'your AWS credentials come from "aws login", which boto3 can read only with botocore[crt]. Install it '
            'next to cfn2iam: pip install "cfn2iam[iam]" "botocore[crt]" (with uv: uv tool install "cfn2iam[iam]" '
            '--with "botocore[crt]"), or use other credentials, such as AWS_PROFILE for an SSO or access key profile'
        )
    except BotoCoreError as e:
        return f"could not load your AWS credentials: {e}"
    if credentials is None:
        return (
            "no AWS credentials found (see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)"
        )
    return None


def create_iam_role(policy_document, role_name, permissions_boundary=None):
    """Create the role with the policy inline. Returns its ARN, or None after printing why not.

    The size is checked before anything is created. If attaching the policy fails, the role
    this call created is deleted again; a role that already existed is never touched, because
    CreateRole fails for it first.
    """
    size = core.policy_size(policy_document)
    if size > core.INLINE_POLICY_LIMIT:
        print(
            f"Error: the policy is {size:,} characters (not counting whitespace), over the {core.INLINE_POLICY_LIMIT:,} "
            f"IAM allows inline on a role, so the role {role_name} was not created. Split its statements into several "
            "customer managed policies and attach those instead.",
            file=sys.stderr,
        )
        return None
    try:
        import boto3
    except ImportError:
        print(
            'Error: boto3 is required for IAM role creation. Install with: pip install "cfn2iam[iam]"', file=sys.stderr
        )
        return None
    iam_client = boto3.client("iam")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    params = {
        "RoleName": role_name,
        "AssumeRolePolicyDocument": json.dumps(trust_policy),
        "Description": "Role generated using cfn2iam",
    }
    if permissions_boundary:
        params["PermissionsBoundary"] = permissions_boundary
    try:
        response = iam_client.create_role(**params)
    except Exception as e:
        print(f"Error: failed to create IAM role {role_name}: {e}", file=sys.stderr)
        return None
    role_arn = response["Role"]["Arn"]
    try:
        iam_client.put_role_policy(
            RoleName=role_name, PolicyName=f"{role_name}-Policy", PolicyDocument=json.dumps(policy_document)
        )
    except Exception as e:
        print(f"Error: failed to attach the policy to the new IAM role {role_name}: {e}", file=sys.stderr)
        try:
            iam_client.delete_role(RoleName=role_name)
        except Exception as delete_error:
            print(
                f"Error: could not delete the role {role_name} that this run created ({delete_error}). "
                "It has no policy; delete it yourself.",
                file=sys.stderr,
            )
        else:
            print(
                f"Deleted the role {role_name} that this run created, so no role without the policy is left.",
                file=sys.stderr,
            )
        return None
    return role_arn


app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.command(epilog="Compare policies with a baseline: cfn2iam diff --help")
def main(
    template_path: str = typer.Argument(help="Path to the CloudFormation template file"),
    allow_delete: bool = typer.Option(
        False, "-d", "--allow-delete", help="Allow delete permissions instead of denying them"
    ),
    create_role: bool = typer.Option(
        False, "-c", "--create-role", help="Create an IAM role with the generated permissions"
    ),
    role_name: str = typer.Option(
        None, "-r", "--role-name", help="Name for the IAM role (if not specified, uses 'cfn2iam-<random_hash>')"
    ),
    permissions_boundary: str = typer.Option(
        None, "-p", "--permissions-boundary", help="ARN of the permissions boundary to attach to the role"
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.policy,
        "--format",
        help="What to write: the policy document, or json: the policy with the resource types and the actions each needs",
    ),
    output: Optional[str] = typer.Option(
        None,
        "-o",
        "--output",
        help="File to write, or - for stdout (default: policy-<random>.json for --format policy, stdout for json)",
    ),
    ignore_unknown: bool = typer.Option(
        False,
        "--ignore-unknown",
        help="Skip resource types found in neither the public schemas nor the CloudFormation registry, instead of failing",
    ),
    registry: bool = typer.Option(
        False,
        "--registry",
        help="Look up every resource type with CloudFormation DescribeType in your account instead of the published schemas (needs cfn2iam\\[iam] and AWS credentials)",
    ),
    region: str = typer.Option(
        None,
        "--region",
        help="AWS region for CloudFormation registry lookups (default: your AWS config), and with --account the region to scope resources to (default: any region)",
    ),
    account: str = typer.Option(
        None,
        "--account",
        help='Scope resources to this 12-digit AWS account ID: ARNs in the account (and --region) instead of "*" where IAM supports it',
    ),
    partition: str = typer.Option(
        "aws", "--partition", help="AWS partition for --account scoping: aws, aws-cn, aws-us-gov, ..."
    ),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, help="Show version and exit"),
):
    to_stdout = output == "-" or (output is None and output_format == OutputFormat.json)
    # Keep stdout for the document when it goes there, and always for --format json.
    messages = sys.stderr if to_stdout or output_format == OutputFormat.json else sys.stdout

    def say(text: str, file=messages) -> None:
        # Flushed, so stdout and stderr keep their order when both are piped to one place.
        print(text, file=file, flush=True)

    try:
        if registry and not _has_boto3():
            print('Error: --registry needs boto3. Install with: pip install "cfn2iam[iam]"', file=sys.stderr)
            sys.exit(1)
        if create_role:
            problem = aws_credentials_problem()
            if problem:
                print(f"Error: --create-role can't run: {problem}. No policy was written.", file=sys.stderr)
                sys.exit(1)
        account = (account or "").strip() or None
        try:
            # --region alone is for registry lookups, so only --partition needs --account here.
            core.make_scope(account, region if account else None, partition)
        except core.ScopeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        try:
            analysis = asyncio.run(
                analyze_template_file(template_path, region, registry, allow_delete, account, partition)
            )
        except core.ServiceReferenceError as e:
            print(f"Error: {e}", file=sys.stderr)
            print("No policy was written, because it couldn't be scoped as asked.", file=sys.stderr)
            sys.exit(1)
        general_size_warning = core.size_warning(analysis.policy_size)
        for warning in analysis.warnings:
            if create_role and warning == general_size_warning:
                continue  # --create-role attaches the policy inline, where other limits apply; checked below
            say(f"Warning: {warning}", sys.stderr)
        resource_types = analysis.resource_types
        if not resource_types:
            say("No resource types found in the template.")
            sys.exit(1)
        failures = analysis.failures
        skipped = {t: e for t, e in failures.items() if ignore_unknown and isinstance(e, UnknownResourceType)}
        unresolved = {t: e for t, e in failures.items() if t not in skipped}
        for t in sorted(skipped):
            print(f"Warning: skipped {t}: {skipped[t]}", file=sys.stderr)
        if unresolved:
            print(
                f"Error: could not resolve permissions for {len(unresolved)} of {len(resource_types)} resource type(s):",
                file=sys.stderr,
            )
            for t in sorted(unresolved):
                print(f"  {t}: {unresolved[t]}", file=sys.stderr)
            if any(isinstance(e, UnknownResourceType) for e in unresolved.values()):
                print("Use --ignore-unknown to skip resource types that can't be found.", file=sys.stderr)
            print("No policy was written, because it would be missing permissions.", file=sys.stderr)
            sys.exit(1)
        if analysis.scoping is not None:
            say(scoping_summary(analysis.scoping), sys.stderr)
        policy_document = analysis.policy
        if output_format == OutputFormat.json:
            document = {"template": template_path, "allow_delete": allow_delete, **analysis.to_dict()}
        else:
            document = policy_document
        if to_stdout:
            json.dump(document, sys.stdout, indent=2)
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            file_path = output or f"policy-{generate_random_hash()}.json"
            parent = os.path.dirname(file_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(file_path, "w") as f:
                json.dump(document, f, indent=2)
            say(f"Generated IAM Policy Document to {file_path}")
        if create_role:
            role_name = role_name or f"cfn2iam-{generate_random_hash()}"
            role_arn = create_iam_role(policy_document, role_name, permissions_boundary)
            if not role_arn:
                sys.exit(1)
            say(f"Successfully created IAM role: {role_arn}")
    except Exception as e:
        say(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    typer.run(main)
