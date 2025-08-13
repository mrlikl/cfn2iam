#!/usr/bin/env python3
import boto3
import typer
import json
import yaml
import sys
import re
import uuid
from typing import Optional
from importlib.metadata import version


def version_callback(value: bool):
    if value:
        try:
            pkg_version = version("cfn2iam")
        except Exception:
            pkg_version = "unknown"
        print(f"cfn2iam {pkg_version}")
        raise typer.Exit()

# Simple constructor that ignores CloudFormation intrinsic functions


def ignore_unknown_tags(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


# Add multi constructor to handle all CloudFormation tags
yaml.SafeLoader.add_multi_constructor('!', ignore_unknown_tags)


def parse_cloudformation_template(file_path):
    with open(file_path, 'r') as file:
        if file_path.endswith('.json'):
            template = json.load(file)
        elif file_path.endswith(('.yaml', '.yml')):
            template = yaml.safe_load(file)
        else:
            raise ValueError(
                "Unsupported file format. Please provide a JSON or YAML file.")

    if 'Resources' not in template:
        print("No Resources section found in the template.")
        return set()

    ignore_patterns = [
        r"^Custom::.*",
        r"^AWS::CDK::Metadata",
        r"^AWS::CloudFormation::CustomResource"
    ]

    resource_types = set()
    for resource in template['Resources'].values():
        if 'Type' in resource:
            resource_type = resource['Type']
            if not any(re.match(pattern, resource_type) for pattern in ignore_patterns):
                resource_types.add(resource_type)
    return resource_types


def get_permissions(resourcetype):
    cfn_client = boto3.client('cloudformation')
    response = cfn_client.describe_type(Type='RESOURCE', TypeName=resourcetype)
    data = json.loads(response['Schema'])

    iam_update = set()
    iam_delete = set()

    if 'handlers' in data:
        handlers = data['handlers']
        # Collect all non-delete permissions
        for action in ['create', 'update', 'read', 'list']:
            if action in handlers:
                iam_update.update(handlers[action]['permissions'])

        # Collect delete-only permissions
        if 'delete' in handlers:
            delete_perms = set(handlers['delete']['permissions'])
            iam_delete = delete_perms - iam_update

    return iam_update, iam_delete


def generate_random_hash():
    """Generate a short random hash for role name uniqueness"""
    return uuid.uuid4().hex[:8]


def generate_policy_document(all_update_permissions, all_delete_permissions, allow_delete=False):
    """
    Generate an IAM policy document with the specified permissions.

    Args:
        all_update_permissions (set): Set of permissions to allow
        all_delete_permissions (set): Set of permissions to deny or allow based on allow_delete flag
        allow_delete (bool): If True, include delete permissions as Allow, otherwise as Deny

    Returns:
        dict: Policy document
    """
    statements = []
    if all_update_permissions:
        statements.append({
            "Effect": "Allow",
            "Action": list(sorted(all_update_permissions)),
            "Resource": "*"
        })
    if all_delete_permissions:
        statements.append({
            "Effect": "Allow" if allow_delete else "Deny",
            "Action": list(sorted(all_delete_permissions)),
            "Resource": "*"
        })

    policy_document = {
        "Version": "2012-10-17",
        "Statement": statements
    }

    return policy_document


def create_iam_role(policy_document, role_name, permissions_boundary=None):
    iam_client = boto3.client('iam')
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudformation.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        create_role_params = {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": json.dumps(trust_policy),
            "Description": "Role generated using cfn2iam"
        }
        if permissions_boundary:
            create_role_params["PermissionsBoundary"] = permissions_boundary

        response = iam_client.create_role(**create_role_params)
        role_arn = response['Role']['Arn']
        policy_name = f"{role_name}-Policy"
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        return role_arn

    except Exception as e:
        print(f"Error creating IAM role: {e}")
        return None


app = typer.Typer(no_args_is_help=True)


@app.command()
def main(
    template_path: str = typer.Argument(
        help="Path to the CloudFormation template file"),
    allow_delete: bool = typer.Option(
        False, "-d", "--allow-delete", help="Allow delete permissions instead of denying them"),
    create_role: bool = typer.Option(
        False, "-c", "--create-role", help="Create an IAM role with the generated permissions"),
    role_name: str = typer.Option(
        None, "-r", "--role-name", help="Name for the IAM role (if not specified, uses 'cfn2iam-<random_hash>')"),
    permissions_boundary: str = typer.Option(
        None, "-p", "--permissions-boundary", help="ARN of the permissions boundary to attach to the role"),
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, help="Show version and exit")
):
    """Generate IAM permissions for CloudFormation resources."""
    try:
        print(f"Parsing CloudFormation template: {template_path}")
        resource_types = parse_cloudformation_template(template_path)

        if not resource_types:
            print("No resource types found in the template.")
            sys.exit(1)

        all_update_permissions = set()
        all_delete_permissions = set()

        for resource in resource_types:
            update_permissions, delete_permissions = get_permissions(resource)
            all_update_permissions.update(update_permissions)
            all_delete_permissions.update(delete_permissions)

        policy_document = generate_policy_document(
            all_update_permissions, all_delete_permissions, allow_delete)
        file_path = f"policy-{generate_random_hash()}.json"
        with open(file_path, 'w') as json_file:
            json.dump(policy_document, json_file, indent=2)
        print(f"\nGenerated IAM Policy Document to {file_path}")

        if create_role:
            role_name = role_name or f"cfn2iam-{generate_random_hash()}"

            role_arn = create_iam_role(
                policy_document,
                role_name,
                permissions_boundary
            )
            if role_arn:
                print(f"\nSuccessfully created IAM role: {role_arn}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    typer.run(main)
