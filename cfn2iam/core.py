"""The cfn2iam logic: template text in, IAM policy out.

This module does no I/O of its own. Every CloudFormation resource schema and SAM
rule is read through the ``fetch_json`` callable the caller passes in, so the same
code runs in the CLI (which fetches over HTTPS) and in a browser under Pyodide
(which fetches with the page's ``fetch``). Keep it that way: no typer, urllib,
threads, boto3 or filesystem access here, and nothing but PyYAML beyond the
standard library.

``fetch_json(path)`` receives a path relative to the backend root, such as
``"schemas/index.json"``, ``"schemas/AWS_S3_Bucket.json"``,
``"sam_rules/AWS_Serverless_Function.json"`` or, with resource scoping,
``"servicereference/index.json"`` and ``"servicereference/s3.json"``. It returns the
parsed JSON, or an awaitable of it, and raises :class:`NotFound` when the backend has
no such file. Any other exception means the file could not be fetched.

Resource scoping is opt-in: it is on exactly when ``account`` is given. ``region`` and
``partition`` only refine it, and passing either without ``account`` is a
:class:`ScopeError`, so no caller can believe it scoped a policy that it did not.
"""

import asyncio
import inspect
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple, Union

import yaml

__all__ = [
    "Analysis",
    "NotFound",
    "PARTITIONS",
    "POLICY_SIZE_LIMITS",
    "SchemaError",
    "Scope",
    "ScopeError",
    "ServiceReferenceError",
    "TemplateError",
    "UNSCOPED_REASONS",
    "UnknownResourceType",
    "analyze_resource_type",
    "analyze_template",
    "fill_arn",
    "generate_policy_document",
    "make_scope",
    "parse_template",
    "permissions_from_schema",
    "policy_size",
]

JsonFetcher = Callable[[str], Union[Any, Awaitable[Any]]]
SchemaLoader = Callable[[str], Union[Dict, Awaitable[Dict]]]

IGNORED_TYPE_PATTERNS = (
    r"^Custom::.*",
    r"^AWS::CDK::Metadata",
    r"^AWS::CloudFormation::CustomResource",
)
SAM_PREFIX = "AWS::Serverless::"


class SchemaError(Exception):
    """A schema or SAM rule could not be fetched, so the policy would be incomplete."""


class UnknownResourceType(SchemaError):
    """No schema source knows the resource type."""


class NotFound(Exception):
    """The backend has no file at this path. Raised by ``fetch_json``."""


class TemplateError(ValueError):
    """The template could not be read."""


class ScopeError(ValueError):
    """The account, region or partition for resource scoping is not valid."""


class ServiceReferenceError(Exception):
    """Scoping was asked for, but the Service Authorization Reference could not be fetched."""


# --- Template parsing -------------------------------------------------------


def _construct_tagged(loader, tag_suffix, node):
    # Short-form intrinsics (!Ref, !GetAtt, ...) are read as their plain value.
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


class _TemplateLoader(yaml.SafeLoader):
    """SafeLoader that accepts CloudFormation's short-form intrinsic tags."""


_TemplateLoader.add_multi_constructor("!", _construct_tagged)


def parse_template(text: str, template_format: Optional[str] = None) -> Any:
    """Parse template text. ``template_format`` is "json", "yaml", or None to try JSON then YAML."""
    if template_format == "json":
        try:
            return json.loads(text)
        except ValueError as e:
            raise TemplateError(f"invalid JSON template: {e}") from e
    if template_format == "yaml":
        try:
            return yaml.load(text, Loader=_TemplateLoader)
        except yaml.YAMLError as e:
            raise TemplateError(f"invalid YAML template: {e}") from e
    if template_format is not None:
        raise ValueError(f"unsupported template format: {template_format}")
    try:
        return json.loads(text)
    except ValueError as json_error:
        try:
            return yaml.load(text, Loader=_TemplateLoader)
        except yaml.YAMLError as yaml_error:
            raise TemplateError(
                f"the template is neither valid JSON ({json_error}) nor valid YAML ({yaml_error})"
            ) from yaml_error


def _template_resources(template: Any) -> List[Tuple[str, str, Dict]]:
    """(logical id, type, properties) for every resource that needs permissions."""
    if template is None:
        return []
    if not isinstance(template, dict):
        raise TemplateError("the template is not a mapping")
    resources = template.get("Resources")
    if resources is None:
        return []
    if not isinstance(resources, dict):
        raise TemplateError("the template's Resources section is not a mapping")
    found = []
    for logical_id, res in resources.items():
        if not isinstance(res, dict):
            continue
        rtype = res.get("Type")
        if not isinstance(rtype, str) or any(re.match(p, rtype) for p in IGNORED_TYPE_PATTERNS):
            continue
        found.append((str(logical_id), rtype, res.get("Properties", {}) or {}))
    return found


# --- SAM expansion ----------------------------------------------------------


def _is_truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (str, list, dict)):
        return len(v) > 0
    return True


def _get_values_by_path(props: Any, path_parts: Tuple[str, ...]) -> List:
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


@dataclass
class SamRule:
    resource_type: str
    base_resources: Tuple[str, ...]
    conditional: List[Tuple[Callable[[Dict], bool], Tuple[str, ...]]]
    raw: Dict

    def expand(self, properties: Dict) -> List[str]:
        """The resource types SAM creates for one resource with these properties."""
        out = list(self.base_resources)
        for cond_fn, resources in self.conditional:
            if cond_fn(properties):
                out.extend(resources)
        return _dedupe(out)

    def all_resources(self) -> List[str]:
        """Every resource type the rule can produce, whatever the properties."""
        out = list(self.base_resources)
        for _, resources in self.conditional:
            out.extend(resources)
        return _dedupe(out)


def compile_sam_rule(resource_type: str, rule: Dict) -> SamRule:
    conds = []
    for cr in rule.get("conditional_resources", []) or []:
        cond = cr.get("condition")
        if isinstance(cond, dict):
            # An unsupported op raises: silently dropping the condition would drop its permissions.
            fn = compile_condition_callable(cond["path"], cond["op"], cond.get("value"))
            conds.append((fn, tuple(cr.get("resources", []) or [])))
    return SamRule(resource_type, tuple(rule.get("base_resources") or []), conds, rule)


def _dedupe(items) -> List[str]:
    return list(dict.fromkeys(items))


# --- Permissions and the policy --------------------------------------------


def permissions_from_schema(schema: Optional[Dict]) -> Tuple[Set[str], Set[str]]:
    """(allow, delete-only) actions from a resource schema's handlers."""
    handlers = (schema or {}).get("handlers", {}) or {}
    allow: Set[str] = set()
    for action in ("create", "update", "read", "list"):
        if action in handlers:
            allow.update(handlers[action].get("permissions", []) or [])
    delete: Set[str] = set()
    if "delete" in handlers:
        delete = set(handlers["delete"].get("permissions", []) or []) - allow
    return allow, delete


def generate_policy_document(all_update_permissions, all_delete_permissions, allow_delete: bool = False) -> Dict:
    statements = []
    if all_update_permissions:
        statements.append({"Effect": "Allow", "Action": sorted(all_update_permissions), "Resource": "*"})
    if all_delete_permissions:
        statements.append(
            {
                "Effect": "Allow" if allow_delete else "Deny",
                "Action": sorted(all_delete_permissions),
                "Resource": "*",
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


# IAM's size limits, which count every character except whitespace.
POLICY_SIZE_LIMITS = (("customer managed policy", 6144), ("role's inline policies", 10240))


def policy_size(policy: Dict) -> int:
    """The policy's size as IAM counts it against its limits: characters other than whitespace."""
    return len(re.sub(r"\s", "", json.dumps(policy, separators=(",", ":"))))


def _size_warnings(policy: Dict) -> List[str]:
    size = policy_size(policy)
    over = [f"{limit:,} for a {name}" for name, limit in POLICY_SIZE_LIMITS if size > limit]
    if not over:
        return []
    return [
        f"The policy is {size:,} characters (not counting whitespace), over IAM's limit of "
        + " and ".join(over)
        + ". Split its statements into several managed policies to use it."
    ]


# --- Resource scoping -------------------------------------------------------
#
# Scoping fills each action's ARN formats from the Service Authorization Reference
# (servicereference/ on the backend) with the partition, account and region, and
# wildcards every other placeholder. It never makes a policy narrower than is correct:
# whatever can't be resolved with confidence stays on "Resource": "*".

# Partition -> the shape of its region names, from the AWS SDKs' partition table
# (botocore/data/partitions.json). The Service Authorization Reference writes every
# partition as ${Partition}, so it doesn't list them itself.
PARTITIONS = {
    "aws": r"^(us|eu|ap|sa|ca|me|af|il|mx)-\w+-\d+$",
    "aws-cn": r"^cn-\w+-\d+$",
    "aws-us-gov": r"^us-gov-\w+-\d+$",
    "aws-iso": r"^us-iso-\w+-\d+$",
    "aws-iso-b": r"^us-isob-\w+-\d+$",
    "aws-iso-e": r"^eu-isoe-\w+-\d+$",
    "aws-iso-f": r"^us-isof-\w+-\d+$",
    "aws-eusc": r"^eusc-de-\w+-\d+$",
}
_REGION_SHAPE = r"^[a-z]+(-[a-z]+)+-\d+$"

# Why an action stays on "Resource": "*". Keys of Analysis.scoping["unscoped"].
NO_RESOURCE_TYPES = "no_resource_types"  # the action has no resource-level permissions
UNKNOWN_ACTION = "unknown_action"  # the service is known, the action is not
UNKNOWN_SERVICE = "unknown_service"  # the prefix is not an IAM service prefix
WILDCARD = "wildcard"  # s3:*, ec2:Describe*
INVALID_ACTION = "invalid_action"  # not service:action
UNSCOPABLE_ARN = "unscopable_arn"  # an ARN format that can't be filled with confidence
DENY = "deny"  # delete-only actions, denied on every resource on purpose

# Each reason in words that read after a count ("3 with no resource-level permissions").
UNSCOPED_REASONS = {
    NO_RESOURCE_TYPES: "with no resource-level permissions",
    UNKNOWN_ACTION: "not in the Service Authorization Reference",
    UNKNOWN_SERVICE: "with a service prefix IAM doesn't know",
    WILDCARD: "written with wildcards",
    INVALID_ACTION: "not of the form service:action",
    UNSCOPABLE_ARN: "with an ARN format that can't be filled in",
    DENY: "delete-only, denied on every resource",
}

# Prefixes that appear in AWS's schemas but are not IAM service prefixes. They are
# reported, not aliased: IAM matches no action under such a prefix, so the statement
# grants nothing whatever its Resource says, and scoping it would only hide that.
MISTAKEN_PREFIXES = {"efs": "elasticfilesystem", "emr": "elasticmapreduce", "stepfunctions": "states"}

# Resource types whose ARNs routinely belong to another account, so that segment is "*":
# Lambda layers published by AWS (Lambda Insights, the Parameters and Secrets extension)
# and by vendors live in the publisher's account.
_ANY_ACCOUNT_RESOURCES = {("lambda", "layerVersion")}

# CloudFormation types whose own handlers act on resources in other regions or accounts
# by design (replicas, peers). Every action such a type needs keeps that segment as "*".
_CROSS_REGION_TYPES = {
    "AWS::DynamoDB::GlobalTable",  # replicas in each listed region
    "AWS::EC2::TransitGatewayPeeringAttachment",  # the peer transit gateway
    "AWS::EC2::VPCPeeringConnection",  # the peer VPC
    "AWS::KMS::ReplicaKey",  # the primary key
    "AWS::RDS::GlobalCluster",  # members in other regions
    "AWS::SecretsManager::Secret",  # ReplicaRegions
}
_CROSS_ACCOUNT_TYPES = {
    "AWS::EC2::TransitGatewayPeeringAttachment",  # PeerAccountId
    "AWS::EC2::VPCPeeringConnection",  # PeerOwnerId
}

# An action whose resources include more than this many ARNs of one service, region and
# account gets arn:<partition>:<service>:<region>:<account>:* for them instead.
COLLAPSE_AT = 4

_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")


@dataclass(frozen=True)
class Scope:
    """Where the stack is deployed. ``region`` None means any region."""

    account: str
    region: Optional[str] = None
    partition: str = "aws"


def _blank_to_none(value: Any) -> Optional[str]:
    value = None if value is None else str(value).strip()
    return value or None


def make_scope(account: Optional[str] = None, region: Optional[str] = None, partition: str = "aws") -> Optional[Scope]:
    """Validate the scoping arguments. None (no scoping) unless ``account`` is given.

    Blank strings, as a web form sends them, count as not given; ``partition`` then means "aws".
    """
    account, region = _blank_to_none(account), _blank_to_none(region)
    partition = _blank_to_none(partition) or "aws"
    if account is None:
        given = [name for name, value in (("region", region), ("partition", partition)) if value not in (None, "aws")]
        if given:
            verb = "applies" if len(given) == 1 else "apply"
            raise ScopeError(f"{' and '.join(given)} only {verb} to resource scoping, which needs an account")
        return None
    if not re.fullmatch(r"\d{12}", account):
        raise ScopeError(f"the account must be a 12-digit AWS account ID, not {account!r}")
    if partition not in PARTITIONS:
        raise ScopeError(f"unknown partition {partition!r}; expected one of {', '.join(PARTITIONS)}")
    if region is not None:
        if not re.fullmatch(_REGION_SHAPE, region):
            raise ScopeError(f"{region!r} is not an AWS region name such as us-east-1")
        if not re.match(PARTITIONS[partition], region):
            # Unknown shapes pass, so a new region works before this table learns of it.
            others = [p for p, pattern in PARTITIONS.items() if re.match(pattern, region)]
            if others:
                raise ScopeError(f"region {region} is in partition {others[0]}, not {partition}")
    return Scope(account, region, partition)


def _fill_segment(segment: str, values: Dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), "*"), segment)


def fill_arn(arn_format: str, scope: Scope, any_region: bool = False, any_account: bool = False) -> Optional[str]:
    """Fill one ARN format from the reference, or None if it can't be filled with confidence.

    ``${Partition}``, ``${Region}`` and ``${Account}`` or ``${AccountId}`` are filled only in
    their own segment. Every other placeholder becomes ``*``: ``${ManagementAccountId}`` or
    ``${VpcOwnerAccount}`` need not be the deploying account. Literal segments (an empty
    account or region, ``aws``, ``*``, a fixed region) are kept as they are.
    """
    parts = arn_format.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return None
    _, partition, service, region, account, resource = parts
    if not service or "$" in service or "*" in service or "?" in service:
        return None  # IAM allows no wildcard in the service segment
    partition = _fill_segment(partition, {"Partition": scope.partition})
    region = _fill_segment(region, {"Region": "*" if any_region or not scope.region else scope.region})
    own = "*" if any_account else scope.account
    account = _fill_segment(account, {"Account": own, "AccountId": own})
    resource = _fill_segment(resource, {})
    if not resource or "$" in resource:
        return None
    arn = ":".join(("arn", partition, service, region, account, resource))
    return re.sub(r"\*{2,}", "*", arn)


def _covers(a: str, b: str) -> bool:
    """True if ARN pattern ``a`` matches everything ``b`` does (conservatively: False if unsure).

    The partition, service, region and account segments must be equal, or ``*`` in ``a``
    against a non-empty segment of ``b``. In the resource part, only a trailing ``*`` with
    no other wildcard before it counts; IAM documents that a trailing ``*`` expands beyond
    colons. So ``arn:aws:s3:::*`` covers ``arn:aws:s3:::*/*``, and ``...:log-group:*`` covers
    ``...:log-group:*:log-stream:*``.
    """
    if a == b:
        return True
    pa, pb = a.split(":", 5), b.split(":", 5)
    for sa, sb in zip(pa[1:5], pb[1:5], strict=True):
        if sa != sb and not (sa == "*" and sb):
            return False
    ra, rb = pa[5], pb[5]
    if ra == rb:
        return True
    stem = ra[:-1]
    return ra.endswith("*") and "*" not in stem and "?" not in stem and rb.startswith(stem)


def _reduce_arns(arns: Set[str]) -> List[str]:
    """Collapse long runs within one service, then drop ARNs another one covers.

    Both steps only ever widen: arn:<partition>:<service>:<region>:<account>:* replaces
    more than COLLAPSE_AT ARNs that share those segments.
    """
    by_base: Dict[str, Set[str]] = {}
    for arn in arns:
        by_base.setdefault(":".join(arn.split(":", 5)[:5]), set()).add(arn)
    out: Set[str] = set()
    for base, group in by_base.items():
        out.update({base + ":*"} if len(group) > COLLAPSE_AT else group)
    kept = []
    for arn in sorted(out):
        # Of two patterns that cover each other (they are then equal), the sort keeps the first.
        if not any(other != arn and _covers(other, arn) for other in out):
            kept.append(arn)
    return kept


def _split_action(action: Any) -> Tuple[Optional[Tuple[str, str]], Optional[str]]:
    """((prefix, name), None), lowercased, or (None, reason)."""
    if not isinstance(action, str) or action.count(":") != 1:
        return None, INVALID_ACTION
    prefix, name = (part.strip().lower() for part in action.split(":"))
    if not prefix or not name:
        return None, INVALID_ACTION
    if "*" in action or "?" in action:
        return None, WILDCARD
    return (prefix, name), None


class _ServiceReference:
    """The parts of the Service Authorization Reference one analysis needs, each fetched once."""

    def __init__(self, fetch_json: JsonFetcher):
        self.fetch_json = fetch_json
        self.index: Dict[str, str] = {}  # prefix -> filename
        self.services: Dict[str, Dict] = {}

    async def _get(self, path: str) -> Any:
        try:
            return await _call(self.fetch_json, path)
        except NotFound as e:
            raise ServiceReferenceError(f"the backend has no {path}, so the policy can't be scoped") from e
        except Exception as e:
            raise ServiceReferenceError(f"could not fetch {path}, so the policy can't be scoped: {e}") from e

    async def load_index(self) -> None:
        data = await self._get("servicereference/index.json")
        try:
            self.index = {prefix.lower(): s["filename"] for prefix, s in data["services"].items()}
        except (AttributeError, KeyError, TypeError) as e:
            raise ServiceReferenceError(f"servicereference/index.json is malformed: {e!r}") from e

    async def load_services(self, actions) -> None:
        prefixes = set()
        for action in actions:
            parsed, _ = _split_action(action)
            if parsed and parsed[0] in self.index and parsed[0] not in self.services:
                prefixes.add(parsed[0])
        ordered = sorted(prefixes)
        files = await asyncio.gather(*(self._get(f"servicereference/{self.index[p]}") for p in ordered))
        for prefix, data in zip(ordered, files, strict=True):
            if not isinstance(data, dict) or not isinstance(data.get("actions"), dict):
                raise ServiceReferenceError(f"servicereference/{self.index[prefix]} is malformed")
            self.services[prefix] = data

    def resources(self, action: str, scope: Scope, any_region: bool, any_account: bool) -> Tuple[Any, ...]:
        """(ARNs, widened, None) for an action that can be scoped, or (None, False, the reason it stays on "*").

        ``widened`` is true when a segment the scope would fill was left as "*" on purpose
        (``any_region``, ``any_account``, or a resource type in _ANY_ACCOUNT_RESOURCES).
        """
        parsed, reason = _split_action(action)
        if parsed is None:
            return None, False, reason
        prefix, name = parsed
        service = self.services.get(prefix)
        if service is None:
            return None, False, UNKNOWN_SERVICE
        entry = service["actions"].get(name)
        if not isinstance(entry, dict):
            return None, False, UNKNOWN_ACTION
        types = entry.get("resources") or []
        if not types:
            return None, False, NO_RESOURCE_TYPES
        arns: Set[str] = set()
        widened = any_account or bool(any_region and scope.region)
        for rtype in types:
            formats = ((service.get("resources") or {}).get(rtype) or {}).get("arnFormats") or []
            if not formats:
                return None, False, UNSCOPABLE_ARN
            other_account = any_account or (prefix, rtype) in _ANY_ACCOUNT_RESOURCES
            widened = widened or other_account
            for arn_format in formats:
                arn = fill_arn(arn_format, scope, any_region, other_account) if isinstance(arn_format, str) else None
                if arn is None:
                    return None, False, UNSCOPABLE_ARN
                arns.add(arn)
        return _reduce_arns(arns), widened, None


def _scoped_policy(
    allow: Set[str],
    delete: Set[str],
    allow_delete: bool,
    scope: Scope,
    reference: _ServiceReference,
    by_type: Dict[str, Dict[str, List[str]]],
) -> Tuple[Dict, Dict, List[str]]:
    """(policy, the scoping report, warnings).

    One Allow statement for the actions that stay on "*", then one per service: IAM checks
    each action only against ARNs of the resource types it acts on, so listing all of a
    service's ARN patterns together grants nothing outside the account and region. Actions
    with a deliberately widened segment are grouped only with actions that have exactly
    the same resources, so the widening never spreads. The Deny on delete-only actions
    stays on "*": a Deny limited to some ARNs would deny less.
    """
    cross_region: Set[str] = set()
    cross_account: Set[str] = set()
    for rtype, perms in by_type.items():
        actions = set(perms.get("allow", [])) | set(perms.get("delete", []))
        if rtype in _CROSS_REGION_TYPES:
            cross_region |= actions
        if rtype in _CROSS_ACCOUNT_TYPES:
            cross_account |= actions

    pool = set(allow) | (set(delete) if allow_delete else set())
    unscoped: Dict[str, List[str]] = {}
    on_star: List[str] = []
    groups: Dict[Tuple, Tuple[Set[str], List[str]]] = {}
    widened_actions: Set[str] = set()
    for action in sorted(pool):
        arns, widened, reason = reference.resources(action, scope, action in cross_region, action in cross_account)
        if arns is None:
            unscoped.setdefault(reason, []).append(action)
            on_star.append(action)
            continue
        if widened:
            widened_actions.add(action)
            key: Tuple = ("exact", *arns)
        else:
            key = ("service", action.split(":", 1)[0].strip().lower())
        group = groups.setdefault(key, (set(), []))
        group[0].update(arns)
        group[1].append(action)

    # Groups that end up with the same resources share a statement.
    merged: Dict[Tuple[str, ...], List[str]] = {}
    for arns, actions in groups.values():
        merged.setdefault(tuple(_reduce_arns(arns)), []).extend(actions)

    statements = []
    if on_star:
        statements.append({"Effect": "Allow", "Action": on_star, "Resource": "*"})
    for arns, actions in sorted(merged.items(), key=lambda g: min(g[1])):
        resource = arns[0] if len(arns) == 1 else list(arns)
        statements.append({"Effect": "Allow", "Action": sorted(actions), "Resource": resource})
    if delete and not allow_delete:
        statements.append({"Effect": "Deny", "Action": sorted(delete), "Resource": "*"})
        unscoped[DENY] = sorted(delete)

    warnings = []
    for action in unscoped.get(UNKNOWN_SERVICE, []):
        prefix, name = action.split(":", 1)
        if prefix.strip().lower() in MISTAKEN_PREFIXES:
            warnings.append(
                f"{action} is not an IAM action, so IAM ignores it; the schema probably means "
                f"{MISTAKEN_PREFIXES[prefix.strip().lower()]}:{name}"
            )
    scoped = {action for _, actions in groups.values() for action in actions}
    report = {
        "account": scope.account,
        "region": scope.region,
        "partition": scope.partition,
        "scoped_count": len(scoped),
        "unscoped_count": sum(len(v) for v in unscoped.values()),
        "unscoped": {reason: unscoped[reason] for reason in sorted(unscoped)},
        # Scoped actions with a segment left as "*" on purpose: in another account or region.
        "widened": sorted(widened_actions),
    }
    return {"Version": "2012-10-17", "Statement": statements}, report, warnings


# --- Resolution -------------------------------------------------------------


@dataclass
class Analysis:
    """Everything one run works out. ``to_dict()`` gives a JSON-ready form for the web page."""

    policy: Dict
    resource_types: List[str]  # after SAM expansion, sorted
    allow: List[str]  # sorted
    delete: List[str]  # delete-only across the whole stack, sorted
    by_type: Dict[str, Dict[str, List[str]]]  # type -> {"allow": [...], "delete": [...]}
    failures: Dict[str, SchemaError]  # types whose permissions are missing
    sam_resources: List[Dict] = field(default_factory=list)  # template mode: SAM resources in the template
    sam: Optional[Dict] = None  # lookup mode: the SAM rule behind a SAM type
    warnings: List[str] = field(default_factory=list)
    # With scoping: account, region, partition, scoped_count, unscoped_count, and
    # unscoped ({reason: [actions]}, every action left on "*"). None without scoping.
    scoping: Optional[Dict] = None

    @property
    def policy_size(self) -> int:
        """Characters IAM counts against its policy size limits (whitespace excluded)."""
        return policy_size(self.policy)

    @property
    def unresolved(self) -> Dict[str, str]:
        return {t: str(e) for t, e in sorted(self.failures.items())}

    def to_dict(self) -> Dict:
        by_type = {}
        for t in self.resource_types:
            entry = dict(self.by_type.get(t, {"allow": [], "delete": []}))
            entry["error"] = str(self.failures[t]) if t in self.failures else None
            entry["unknown"] = isinstance(self.failures.get(t), UnknownResourceType)
            by_type[t] = entry
        return {
            "policy": self.policy,
            "resource_types": self.resource_types,
            "allow": self.allow,
            "delete": self.delete,
            "by_type": by_type,
            "unresolved": self.unresolved,
            "sam_resources": self.sam_resources,
            "sam": self.sam,
            "warnings": self.warnings,
            "scoping": self.scoping,
            "policy_size": self.policy_size,
        }


async def _call(fn: Callable, *args):
    result = fn(*args)
    if inspect.isawaitable(result):
        result = await result
    return result


class _Resolver:
    def __init__(self, fetch_json: JsonFetcher, schema_fallback: Optional[SchemaLoader], published_schemas: bool):
        self.fetch_json = fetch_json
        self.schema_fallback = schema_fallback
        self.published_schemas = published_schemas
        self.index: Dict[str, str] = {}
        self.warnings: List[str] = []

    async def load_index(self) -> None:
        if not self.published_schemas:
            return
        # The index only maps type names to filenames; on failure we fall back to the
        # conventional filename, and a missing schema is still caught per type.
        try:
            data = await _call(self.fetch_json, "schemas/index.json")
            self.index = {s["typeName"]: s["filename"] for s in data.get("schemas", [])}
        except Exception as e:
            self.warnings.append(f"Failed to fetch schema index: {e}")
            self.index = {}

    async def sam_rule(self, resource_type: str) -> Optional[SamRule]:
        """The compiled rule, or None when the backend has none for this type."""
        filename = resource_type.replace("::", "_") + ".json"
        try:
            rule = await _call(self.fetch_json, f"sam_rules/{filename}")
        except NotFound:
            return None
        except Exception as e:
            raise SchemaError(f"could not fetch SAM rule: {e}") from e
        return compile_sam_rule(resource_type, rule)

    async def schema(self, resource_type: str) -> Dict:
        if not self.published_schemas:
            if self.schema_fallback is None:
                raise UnknownResourceType("no schema source")
            return await _call(self.schema_fallback, resource_type)
        filename = self.index.get(resource_type) or resource_type.replace("::", "_").replace("/", "_") + ".json"
        try:
            return await _call(self.fetch_json, f"schemas/{filename}")
        except NotFound:
            pass
        except Exception as e:
            raise SchemaError(f"could not fetch schema: {e}") from e
        if self.schema_fallback is None:
            raise UnknownResourceType("no published schema")
        return await _call(self.schema_fallback, resource_type)

    async def permissions(self, resource_types: List[str], failures: Dict[str, SchemaError]):
        async def one(rtype):
            try:
                return rtype, permissions_from_schema(await self.schema(rtype)), None
            except SchemaError as e:
                return rtype, None, e

        all_allow: Set[str] = set()
        all_delete: Set[str] = set()
        by_type: Dict[str, Dict[str, List[str]]] = {}
        todo = [t for t in resource_types if t not in failures]
        for rtype, perms, error in await asyncio.gather(*(one(t) for t in todo)):
            if error is not None:
                failures[rtype] = error
                by_type[rtype] = {"allow": [], "delete": []}
                continue
            allow, delete = perms
            by_type[rtype] = {"allow": sorted(allow), "delete": sorted(delete)}
            all_allow.update(allow)
            all_delete.update(delete)
        for rtype in resource_types:
            by_type.setdefault(rtype, {"allow": [], "delete": []})
        # An action can be delete-only for one type but needed to create or update another.
        # Keep it allowed: an explicit Deny would override the Allow and break the deploy.
        return all_allow, all_delete - all_allow, by_type


async def _gather_rules(resolver: _Resolver, sam_types: List[str]):
    async def one(rtype):
        try:
            return rtype, await resolver.sam_rule(rtype), None
        except SchemaError as e:
            return rtype, None, e

    results = await asyncio.gather(resolver.load_index(), *(one(t) for t in sam_types))
    return results[1:]


async def _permissions(resolver: _Resolver, resource_types, failures, scope: Optional[Scope]):
    """resolver.permissions, plus the Service Authorization Reference when scoping.

    The reference index is fetched alongside the schemas; then only the service files
    the actions need, once each.
    """
    if scope is None:
        return (*await resolver.permissions(resource_types, failures), None)
    reference = _ServiceReference(resolver.fetch_json)
    perms, index = await asyncio.gather(
        resolver.permissions(resource_types, failures), reference.load_index(), return_exceptions=True
    )
    if isinstance(perms, BaseException):
        raise perms
    allow, delete, by_type = perms
    if allow or delete:
        if isinstance(index, BaseException):
            raise index
        await reference.load_services(allow | delete)
    return allow, delete, by_type, reference


def _finish(
    resolver, resource_types, failures, allow, delete, by_type, allow_delete, scope=None, reference=None, **extra
) -> Analysis:
    warnings = resolver.warnings
    scoping = None
    if scope is None:
        policy = generate_policy_document(allow, delete, allow_delete)
    else:
        policy, scoping, scope_warnings = _scoped_policy(allow, delete, allow_delete, scope, reference, by_type)
        warnings = warnings + scope_warnings
    return Analysis(
        policy=policy,
        resource_types=sorted(resource_types),
        allow=sorted(allow),
        delete=sorted(delete),
        by_type=by_type,
        failures=failures,
        warnings=warnings + _size_warnings(policy),
        scoping=scoping,
        **extra,
    )


async def analyze_template(
    template_text: str,
    fetch_json: JsonFetcher,
    *,
    template_format: Optional[str] = None,
    allow_delete: bool = False,
    schema_fallback: Optional[SchemaLoader] = None,
    published_schemas: bool = True,
    account: Optional[str] = None,
    region: Optional[str] = None,
    partition: str = "aws",
) -> Analysis:
    """Work out the policy a template needs.

    ``schema_fallback(type_name)`` is called for a type with no published schema
    (or for every type, with ``published_schemas=False``). It returns the schema or
    raises :class:`SchemaError`. Types that can't be resolved are reported in
    ``Analysis.failures``; the policy covers the rest.

    Giving ``account`` (a 12-digit account ID) turns on resource scoping: the Allow
    statements name ARNs in that account, in ``region`` (any region when None) and
    ``partition``, wherever the Service Authorization Reference allows it, and
    ``Analysis.scoping`` reports what was scoped. ``region`` or ``partition`` without
    ``account`` raises :class:`ScopeError`. Without ``account`` the policy is exactly the
    unscoped one and nothing more is fetched. If the reference can't be fetched,
    :class:`ServiceReferenceError` is raised rather than falling back to ``"*"``.
    """
    scope = make_scope(account, region, partition)
    resources = _template_resources(parse_template(template_text, template_format))
    resolver = _Resolver(fetch_json, schema_fallback, published_schemas)
    failures: Dict[str, SchemaError] = {}
    if not resources:
        reference = _ServiceReference(fetch_json)  # nothing to scope, so nothing to fetch
        return _finish(resolver, [], failures, set(), set(), {}, allow_delete, scope, reference)

    sam_types = sorted({rtype for _, rtype, _ in resources if rtype.startswith(SAM_PREFIX)})
    rules: Dict[str, Optional[SamRule]] = {}
    for rtype, rule, error in await _gather_rules(resolver, sam_types):
        if error is not None:
            failures[rtype] = error
        rules[rtype] = rule

    resource_types: Set[str] = set()
    sam_resources = []
    for logical_id, rtype, props in resources:
        if rtype in rules:
            rule = rules[rtype]
            # No rule (or none we could fetch): keep the SAM type so it shows up as unresolved.
            expands_to = rule.expand(props) if rule else [rtype]
            sam_resources.append({"logical_id": logical_id, "type": rtype, "expands_to": expands_to})
            resource_types.update(expands_to)
        else:
            resource_types.add(rtype)

    allow, delete, by_type, reference = await _permissions(resolver, sorted(resource_types), failures, scope)
    return _finish(
        resolver,
        resource_types,
        failures,
        allow,
        delete,
        by_type,
        allow_delete,
        scope,
        reference,
        sam_resources=sam_resources,
    )


async def analyze_resource_type(
    resource_type: str,
    fetch_json: JsonFetcher,
    *,
    allow_delete: bool = False,
    schema_fallback: Optional[SchemaLoader] = None,
    published_schemas: bool = True,
    account: Optional[str] = None,
    region: Optional[str] = None,
    partition: str = "aws",
) -> Analysis:
    """Work out the policy for one resource type. A SAM type includes everything it can create.

    ``account``, ``region`` and ``partition`` scope the policy as for :func:`analyze_template`.
    """
    scope = make_scope(account, region, partition)
    resource_type = resource_type.strip()
    resolver = _Resolver(fetch_json, schema_fallback, published_schemas)
    failures: Dict[str, SchemaError] = {}
    sam = None
    resource_types = [resource_type]
    if resource_type.startswith(SAM_PREFIX):
        [(_, rule, error)] = await _gather_rules(resolver, [resource_type])
        if error is not None:
            failures[resource_type] = error
        elif rule is not None:
            resource_types = rule.all_resources()
            sam = {
                "base_resources": list(rule.base_resources),
                "conditional_resources": rule.raw.get("conditional_resources", []) or [],
                "logical_id_templates": rule.raw.get("logical_id_templates", []) or [],
            }
    else:
        await resolver.load_index()
    allow, delete, by_type, reference = await _permissions(resolver, sorted(resource_types), failures, scope)
    return _finish(resolver, resource_types, failures, allow, delete, by_type, allow_delete, scope, reference, sam=sam)
