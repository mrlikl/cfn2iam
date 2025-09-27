#!/usr/bin/env python3
import typer
import json
import yaml
import sys
import re
import uuid
import urllib.request
import urllib.error
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


import os
from pathlib import Path

def load_sam_rules():
    """Load SAM transformation rules from rules directory"""
    rules = {}
    rules_dir = Path(__file__).parent.parent / "rules"
    
    if not rules_dir.exists():
        return rules
        
    for rule_file in rules_dir.glob("AWS_Serverless_*.json"):
        try:
            with open(rule_file, 'r') as f:
                rule = json.load(f)
                resource_type = rule['resource_type']
                rules[resource_type] = rule
        except Exception as e:
            print(f"Warning: Failed to load rule {rule_file}: {e}")
    
    return rules

def evaluate_condition(condition, resource_properties):
    """Enhanced condition evaluator for SAM rules"""
    if condition == "always":
        return True
    elif condition == "properties.Role == null":
        return resource_properties.get('Role') is None
    elif condition == "properties.StageName == null":
        return resource_properties.get('StageName') is None
    elif "properties.DeploymentPreference.Role == null" in condition:
        dp = resource_properties.get('DeploymentPreference', {})
        return dp.get('Role') is None if dp else False
    elif "properties.Events.*.Type" in condition:
        events = resource_properties.get('Events', {})
        if not events:
            return False
        
        # Extract the condition type/value
        if "== 'Api'" in condition:
            return any(event.get('Type') == 'Api' for event in events.values())
        elif "== 'HttpApi'" in condition:
            return any(event.get('Type') == 'HttpApi' for event in events.values())
        elif "== 'IoTRule'" in condition:
            return any(event.get('Type') == 'IoTRule' for event in events.values())
        elif "in ['DynamoDB', 'Kinesis', 'MQ', 'MSK', 'SQS']" in condition:
            streaming_types = ['DynamoDB', 'Kinesis', 'MQ', 'MSK', 'SQS']
            return any(event.get('Type') in streaming_types for event in events.values())
        elif "in ['EventBridgeRule', 'Schedule', 'CloudWatchEvents']" in condition:
            event_types = ['EventBridgeRule', 'Schedule', 'CloudWatchEvents']
            return any(event.get('Type') in event_types for event in events.values())
    elif "EventInvokeConfig" in condition:
        eic = resource_properties.get('EventInvokeConfig', {})
        dc = eic.get('DestinationConfig', {}) if eic else {}
        
        if "OnSuccess.Type == 'SNS'" in condition:
            on_success = dc.get('OnSuccess', {})
            return on_success.get('Type') == 'SNS' and on_success.get('Destination') is None
        elif "OnFailure.Type == 'SNS'" in condition:
            on_failure = dc.get('OnFailure', {})
            return on_failure.get('Type') == 'SNS' and on_failure.get('Destination') is None
        elif "OnSuccess.Type == 'SQS'" in condition:
            on_success = dc.get('OnSuccess', {})
            return on_success.get('Type') == 'SQS' and on_success.get('Destination') is None
        elif "OnFailure.Type == 'SQS'" in condition:
            on_failure = dc.get('OnFailure', {})
            return on_failure.get('Type') == 'SQS' and on_failure.get('Destination') is None
    elif condition.startswith("properties."):
        # Simple property existence check
        prop_path = condition.replace("properties.", "").split(".")
        current = resource_properties
        for prop in prop_path:
            if prop in current:
                current = current[prop]
            else:
                return False
        return current is not None
    
    return False

def apply_sam_rules(resource_types, template):
    """Apply SAM transformation rules to convert SAM resources to CloudFormation"""
    sam_rules = load_sam_rules()
    mapped_resources = set()
    
    for resource_type in resource_types:
        if resource_type in sam_rules:
            rule = sam_rules[resource_type]
            
            # Add base resources
            mapped_resources.update(rule['base_resources'])
            print(f"SAM {resource_type} → {rule['base_resources']}")
            
            # Find matching resources in template to check conditions
            matching_resources = []
            if 'Resources' in template:
                for res_name, res_def in template['Resources'].items():
                    if res_def.get('Type') == resource_type:
                        matching_resources.append(res_def.get('Properties', {}))
            
            # Apply conditional resources
            for condition_rule in rule['conditional_resources']:
                condition = condition_rule['condition']
                resources = condition_rule['resources']
                
                # Check condition against any matching resource
                for props in matching_resources:
                    if evaluate_condition(condition, props):
                        mapped_resources.update(resources)
                        print(f"SAM {resource_type} + condition '{condition}' → {resources}")
                        break
        else:
            mapped_resources.add(resource_type)
    
    return mapped_resources

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
    
    # Apply SAM transformation rules
    return apply_sam_rules(resource_types, template)


def get_permissions(resourcetype):
    # Convert resource type to filename format (AWS::S3::Bucket -> AWS_S3_Bucket.json)
    filename = resourcetype.replace('::', '_') + '.json'
    url = f'https://mrlikl.github.io/cfn2iam/backend/schemas/{filename}'
    
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"Warning: Schema not found for {resourcetype}")
            return set(), set()
        raise Exception(f"Failed to fetch schema for {resourcetype}: {e}")
    except Exception as e:
        raise Exception(f"Error processing schema for {resourcetype}: {e}")

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
    try:
        import boto3
    except ImportError:
        print("Error: boto3 is required for IAM role creation. Install with: pip install boto3")
        return None
        
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


app = typer.Typer(no_args_is_help=True, add_completion=False)


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
    """A tool to automatically generate minimal IAM policy to deploy a CloudFormation stack from its template."""
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
