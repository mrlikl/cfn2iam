"""The cfn2iam logic: template text in, IAM policy out.

This module does no I/O of its own. Every CloudFormation resource schema and SAM
rule is read through the ``fetch_json`` callable the caller passes in, so the same
code runs in the CLI (which fetches over HTTPS) and in a browser under Pyodide
(which fetches with the page's ``fetch``). Keep it that way: no typer, urllib,
threads, boto3 or filesystem access here, and nothing but PyYAML beyond the
standard library.

``fetch_json(path)`` receives a path relative to the backend root, such as
``"schemas/index.json"``, ``"schemas/AWS_S3_Bucket.json"`` or
``"sam_rules/AWS_Serverless_Function.json"``. It returns the parsed JSON, or an
awaitable of it, and raises :class:`NotFound` when the backend has no such file.
Any other exception means the file could not be fetched.
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
    "SchemaError",
    "TemplateError",
    "UnknownResourceType",
    "analyze_resource_type",
    "analyze_template",
    "generate_policy_document",
    "parse_template",
    "permissions_from_schema",
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


def _finish(resolver, resource_types, failures, allow, delete, by_type, allow_delete, **extra) -> Analysis:
    return Analysis(
        policy=generate_policy_document(allow, delete, allow_delete),
        resource_types=sorted(resource_types),
        allow=sorted(allow),
        delete=sorted(delete),
        by_type=by_type,
        failures=failures,
        warnings=resolver.warnings,
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
) -> Analysis:
    """Work out the policy a template needs.

    ``schema_fallback(type_name)`` is called for a type with no published schema
    (or for every type, with ``published_schemas=False``). It returns the schema or
    raises :class:`SchemaError`. Types that can't be resolved are reported in
    ``Analysis.failures``; the policy covers the rest.
    """
    resources = _template_resources(parse_template(template_text, template_format))
    resolver = _Resolver(fetch_json, schema_fallback, published_schemas)
    failures: Dict[str, SchemaError] = {}
    if not resources:
        return _finish(resolver, [], failures, set(), set(), {}, allow_delete)

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

    allow, delete, by_type = await resolver.permissions(sorted(resource_types), failures)
    return _finish(
        resolver, resource_types, failures, allow, delete, by_type, allow_delete, sam_resources=sam_resources
    )


async def analyze_resource_type(
    resource_type: str,
    fetch_json: JsonFetcher,
    *,
    allow_delete: bool = False,
    schema_fallback: Optional[SchemaLoader] = None,
    published_schemas: bool = True,
) -> Analysis:
    """Work out the policy for one resource type. A SAM type includes everything it can create."""
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
    allow, delete, by_type = await resolver.permissions(sorted(resource_types), failures)
    return _finish(resolver, resource_types, failures, allow, delete, by_type, allow_delete, sam=sam)
