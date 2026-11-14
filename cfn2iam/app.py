#!/usr/bin/env python3
"""The cfn2iam command line: fetching, registry lookups, role creation and file output.

The logic itself lives in :mod:`cfn2iam.core`, which the web version also runs.
"""

import asyncio
import json
import sys
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version
from typing import Dict, Optional

import typer

from . import core
from .core import NotFound, SchemaError, UnknownResourceType, generate_policy_document  # noqa: F401  (re-exported)

SCHEMA_BASE_URL = "https://mrlikl.github.io/cfn2iam/backend"
MAX_WORKERS = 8


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


def create_iam_role(policy_document, role_name, permissions_boundary=None):
    try:
        import boto3
    except ImportError:
        print("Error: boto3 is required for IAM role creation. Install with: pip install boto3", file=sys.stderr)
        return None
    iam_client = boto3.client("iam")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    try:
        params = {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": json.dumps(trust_policy),
            "Description": "Role generated using cfn2iam",
        }
        if permissions_boundary:
            params["PermissionsBoundary"] = permissions_boundary
        response = iam_client.create_role(**params)
        role_arn = response["Role"]["Arn"]
        policy_name = f"{role_name}-Policy"
        iam_client.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )
        return role_arn
    except Exception as e:
        print(f"Error: failed to create IAM role {role_name}: {e}", file=sys.stderr)
        return None


app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.command()
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
    try:
        if registry and not _has_boto3():
            print('Error: --registry needs boto3. Install with: pip install "cfn2iam[iam]"', file=sys.stderr)
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
        for warning in analysis.warnings:
            print(f"Warning: {warning}", file=sys.stderr)
        resource_types = analysis.resource_types
        if not resource_types:
            print("No resource types found in the template.")
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
            print(scoping_summary(analysis.scoping), file=sys.stderr)
        policy_document = analysis.policy
        file_path = f"policy-{generate_random_hash()}.json"
        with open(file_path, "w") as f:
            json.dump(policy_document, f, indent=2)
        print(f"Generated IAM Policy Document to {file_path}")
        if create_role:
            role_name = role_name or f"cfn2iam-{generate_random_hash()}"
            role_arn = create_iam_role(policy_document, role_name, permissions_boundary)
            if not role_arn:
                sys.exit(1)
            print(f"Successfully created IAM role: {role_arn}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    typer.run(main)
