#!/usr/bin/env python3
import typer
import json
import yaml
import sys
import re
import uuid
import urllib.request
import urllib.error
from typing import Optional, Any, Callable, Dict, List, Tuple
from importlib.metadata import version
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

def version_callback(value: bool):
    if value:
        try:
            pkg_version = version("cfn2iam")
        except Exception:
            pkg_version = "unknown"
        print(f"cfn2iam {pkg_version}")
        raise typer.Exit()

def ignore_unknown_tags(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None

yaml.SafeLoader.add_multi_constructor('!', ignore_unknown_tags)

SAM_RULES_DIR = Path(__file__).parent / "sam_rules"

def load_sam_rules():
    rules = {}
    if not SAM_RULES_DIR.exists():
        return rules
    for rule_file in sorted(SAM_RULES_DIR.glob("*.json")):
        try:
            with open(rule_file, "r") as f:
                rule = json.load(f)
                resource_type = rule.get("resource_type") or rule.get("resourceType")
                if resource_type:
                    rules[resource_type] = rule
        except Exception:
            continue
    return rules

def _is_truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (str, list, dict)):
        return len(v) > 0
    return True

def _get_values_by_path(props: Dict, path_parts: Tuple[str, ...]) -> List:
    cur = [props]
    for part in path_parts:
        if not cur:
            return []
        next_level = []
        if part == "*":
            for node in cur:
                if isinstance(node, dict):
                    next_level.extend(node.values())
                elif isinstance(node, list):
                    next_level.extend(node)
        else:
            for node in cur:
                if isinstance(node, dict) and part in node:
                    next_level.append(node[part])
        cur = next_level
    return cur

@lru_cache(maxsize=8192)
def compile_condition_callable(path: str, op: str, value: Any = None) -> Callable[[Dict], bool]:
    if path.startswith("properties."):
        path = path[11:]
    path_parts = tuple(path.split("."))
    if op == "exists":
        return lambda props: len(_get_values_by_path(props, path_parts)) > 0
    if op == "truthy":
        return lambda props: any(_is_truthy(v) for v in _get_values_by_path(props, path_parts))
    if op == "any_eq":
        return lambda props: any(v == value for v in _get_values_by_path(props, path_parts))
    if op == "all_eq":
        def fn(props):
            vals = _get_values_by_path(props, path_parts)
            return bool(vals) and all(v == value for v in vals)
        return fn
    if op == "is_null":
        return lambda props: (not (vals := _get_values_by_path(props, path_parts))) or all(v is None for v in vals)
    raise ValueError(f"unsupported op: {op}")

def evaluate_condition(condition: Any, resource_properties: Dict) -> bool:
    if isinstance(condition, dict):
        path = condition.get("path")
        op = condition.get("op")
        value = condition.get("value")
        if not path or not op:
            return False
        try:
            fn = compile_condition_callable(path, op, value)
        except Exception:
            return False
        return fn(resource_properties)
    return False

_COMPILED_SAM_RULES = {}
for rtype, rule in load_sam_rules().items():
    base = tuple(rule.get("base_resources") or [])
    conds = []
    for cr in rule.get("conditional_resources", []):
        cond = cr.get("condition")
        if isinstance(cond, dict):
            try:
                fn = compile_condition_callable(cond["path"], cond["op"], cond.get("value"))
                conds.append((fn, tuple(cr.get("resources", []))))
            except Exception:
                continue
    _COMPILED_SAM_RULES[rtype] = {"base": base, "conds": conds}

def apply_sam_rules(resource_types, template):
    mapped_resources = set()
    props_by_type: Dict[str, List[Dict]] = {}
    for res_def in template.get("Resources", {}).values():
        rtype = res_def.get("Type")
        if rtype:
            props_by_type.setdefault(rtype, []).append(res_def.get("Properties", {}) or {})
    for rtype in resource_types:
        if rtype in _COMPILED_SAM_RULES:
            rule = _COMPILED_SAM_RULES[rtype]
            mapped_resources.update(rule["base"])
            for cond_fn, resources in rule["conds"]:
                for props in props_by_type.get(rtype, []):
                    if cond_fn(props):
                        mapped_resources.update(resources)
                        break
        else:
            mapped_resources.add(rtype)
    return mapped_resources

def parse_cloudformation_template(file_path):
    with open(file_path, "r") as file:
        template = json.load(file) if file_path.endswith(".json") else yaml.safe_load(file)
    if "Resources" not in template:
        return set()
    ignore_patterns = [
        r"^Custom::.*",
        r"^AWS::CDK::Metadata",
        r"^AWS::CloudFormation::CustomResource",
    ]
    resource_types = {
        res["Type"]
        for res in template["Resources"].values()
        if "Type" in res and not any(re.match(p, res["Type"]) for p in ignore_patterns)
    }
    return apply_sam_rules(resource_types, template)

@lru_cache(maxsize=1024)
def get_permissions_cached(resourcetype: str):
    filename = resourcetype.replace("::", "_") + ".json"
    url = f"https://mrlikl.github.io/cfn2iam/backend/schemas/{filename}"
    req = urllib.request.Request(url, headers={"User-Agent": "cfn2iam/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception:
        return None

def get_permissions(resourcetype):
    data = get_permissions_cached(resourcetype)
    if not data:
        return set(), set()
    handlers = data.get("handlers", {})
    iam_update = set()
    iam_delete = set()
    for action in ("create", "update", "read", "list"):
        if action in handlers:
            iam_update.update(handlers[action].get("permissions", []))
    if "delete" in handlers:
        delete_perms = set(handlers["delete"].get("permissions", []))
        iam_delete = delete_perms - iam_update
    return iam_update, iam_delete

def aggregate_permissions(resource_types: List[str]) -> Tuple[set, set]:
    all_update, all_delete = set(), set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(get_permissions, r): r for r in resource_types}
        for fut in as_completed(futures):
            try:
                u, d = fut.result()
                all_update.update(u)
                all_delete.update(d)
            except Exception:
                pass
    return all_update, all_delete

def generate_random_hash():
    return uuid.uuid4().hex[:8]

def generate_policy_document(all_update_permissions, all_delete_permissions, allow_delete=False):
    statements = []
    if all_update_permissions:
        statements.append({"Effect": "Allow", "Action": sorted(all_update_permissions), "Resource": "*"})
    if all_delete_permissions:
        statements.append({
            "Effect": "Allow" if allow_delete else "Deny",
            "Action": sorted(all_delete_permissions),
            "Resource": "*",
        })
    return {"Version": "2012-10-17", "Statement": statements}

def create_iam_role(policy_document, role_name, permissions_boundary=None):
    try:
        import boto3
    except ImportError:
        print("Error: boto3 is required for IAM role creation. Install with: pip install boto3")
        return None
    iam_client = boto3.client("iam")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}],
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
        iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
        return role_arn
    except Exception:
        return None

app = typer.Typer(no_args_is_help=True, add_completion=False)

@app.command()
def main(
    template_path: str = typer.Argument(help="Path to the CloudFormation template file"),
    allow_delete: bool = typer.Option(False, "-d", "--allow-delete", help="Allow delete permissions instead of denying them"),
    create_role: bool = typer.Option(False, "-c", "--create-role", help="Create an IAM role with the generated permissions"),
    role_name: str = typer.Option(None, "-r", "--role-name", help="Name for the IAM role (if not specified, uses 'cfn2iam-<random_hash>')"),
    permissions_boundary: str = typer.Option(None, "-p", "--permissions-boundary", help="ARN of the permissions boundary to attach to the role"),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, help="Show version and exit"),
):
    try:
        resource_types = parse_cloudformation_template(template_path)
        if not resource_types:
            print("No resource types found in the template.")
            sys.exit(1)
        all_update, all_delete = aggregate_permissions(list(resource_types))
        policy_document = generate_policy_document(all_update, all_delete, allow_delete)
        file_path = f"policy-{generate_random_hash()}.json"
        with open(file_path, "w") as f:
            json.dump(policy_document, f, indent=2)
        print(f"Generated IAM Policy Document to {file_path}")
        if create_role:
            role_name = role_name or f"cfn2iam-{generate_random_hash()}"
            role_arn = create_iam_role(policy_document, role_name, permissions_boundary)
            if role_arn:
                print(f"Successfully created IAM role: {role_arn}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    typer.run(main)
