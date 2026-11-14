"""Compare the policy cfn2iam generates with a baseline policy: the permission check.

The baseline is the policy a deploy role has, or the cfn2iam output it was built
from. This module answers three questions about it:

- which actions the templates need that the baseline does not grant (permission
  drift: the deploy would fail);
- which actions the baseline allows that the templates no longer need;
- how the delete-only actions the generated policy denies differ from the baseline's.

Like :mod:`cfn2iam.core` it is pure: standard library only, no I/O. The CLI
(``cfn2iam diff``) and the GitHub Action read the files and call it.

How a baseline is read
----------------------

IAM evaluates a request as: denied if any applicable Deny matches, else allowed if
any applicable Allow matches. Here a request is one action the templates need, on
the resources the generated policy gives it (``"*"`` today). Action names match
case-insensitively with ``*`` and ``?`` wildcards; resource ARNs match
case-sensitively, the same way. ``NotAction`` and ``NotResource`` are exact on the
action and resource dimensions ("every action except these"), so they are
evaluated, not guessed.

What can't be evaluated from a template is whether a ``Condition`` holds at deploy
time, or whether CloudFormation will only touch resources a narrower ``Resource``
covers (it names resources at deploy time). A statement with either one makes the
action *conditional*: an Allow of that kind may not grant it, and a Deny of that
kind may deny it. Conditional actions are listed separately, with the statements
that caused them, and by default count as not granted (``conditional="missing"``),
so the check fails closed; ``conditional="granted"`` counts them as granted.
"""

import re
from dataclasses import dataclass, field
from functools import cache, lru_cache
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    "Baseline",
    "Generated",
    "PolicyError",
    "Report",
    "Statement",
    "combined_policy",
    "compare",
    "load_baseline",
    "load_generated",
    "matches",
    "overlaps",
    "render_markdown",
    "render_text",
]

CONDITIONAL_MODES = ("missing", "granted")

# Status of one needed action against the baseline, worst first.
DENIED, MISSING, CONDITIONAL, GRANTED = "denied", "missing", "conditional", "granted"
_RANK = {DENIED: 0, MISSING: 1, CONDITIONAL: 2, GRANTED: 3}

FULL, PARTIAL, NONE = 2, 1, 0


class PolicyError(ValueError):
    """A policy file is not something this module can read."""


# --- Wildcard matching ------------------------------------------------------


def _norm(text: str, ignore_case: bool) -> str:
    return text.lower() if ignore_case else text


@lru_cache(maxsize=65536)
def _covers(pattern: str, target: str) -> bool:
    """Every string ``target`` can stand for also matches ``pattern``.

    Both may hold IAM wildcards (``*`` any run of characters, ``?`` one character).
    A literal character in ``pattern`` only matches the same literal in ``target``;
    ``?`` matches one literal or ``?``; ``*`` matches anything, wildcards included.
    That is exact for literal targets and sound (never claims coverage wrongly) for
    wildcard ones.
    """
    n, m = len(pattern), len(target)
    # reach[j]: pattern[:i] can consume target[:j]
    reach = [True] + [False] * m
    for i in range(n):
        p = pattern[i]
        nxt = [False] * (m + 1)
        if p == "*":
            seen = False
            for j in range(m + 1):
                seen = seen or reach[j]
                nxt[j] = seen
        else:
            for j in range(m):
                if reach[j]:
                    t = target[j]
                    if (p == "?" and t != "*") or (p not in "*?" and t == p):
                        nxt[j + 1] = True
        reach = nxt
    return reach[m]


@lru_cache(maxsize=65536)
def _overlaps(a: str, b: str) -> bool:
    """Some string matches both wildcard patterns."""

    @cache
    def go(i: int, j: int) -> bool:
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] == "*" and (go(i + 1, j) or (j < len(b) and go(i, j + 1))):
            return True
        if j < len(b) and b[j] == "*" and (go(i, j + 1) or (i < len(a) and go(i + 1, j))):
            return True
        if i < len(a) and j < len(b) and a[i] != "*" and b[j] != "*":
            if a[i] == "?" or b[j] == "?" or a[i] == b[j]:
                return go(i + 1, j + 1)
        return False

    return go(0, 0)


def matches(pattern: str, target: str, ignore_case: bool = True) -> bool:
    """``pattern`` (with IAM wildcards) covers ``target``. Actions ignore case, ARNs don't."""
    return _covers(_norm(pattern, ignore_case), _norm(target, ignore_case))


def overlaps(a: str, b: str, ignore_case: bool = True) -> bool:
    """The two wildcard patterns have a match in common."""
    return _overlaps(_norm(a, ignore_case), _norm(b, ignore_case))


def _has_variable(pattern: str) -> bool:
    return "${" in pattern


def _match(patterns: Optional[Sequence[str]], not_patterns: Optional[Sequence[str]], target: str, ignore_case: bool):
    """How a statement's Action/NotAction (or Resource/NotResource) applies to one target."""
    if patterns is not None:
        if any(not _has_variable(p) and matches(p, target, ignore_case) for p in patterns):
            return FULL
        if any(_has_variable(p) or overlaps(p, target, ignore_case) for p in patterns):
            return PARTIAL
        return NONE
    if any(not _has_variable(p) and matches(p, target, ignore_case) for p in not_patterns or ()):
        return NONE  # everything the target stands for is excluded
    if any(_has_variable(p) or overlaps(p, target, ignore_case) for p in not_patterns or ()):
        return PARTIAL
    return FULL


# --- Reading policies -------------------------------------------------------


def _as_list(value: Any, what: str, where: str) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise PolicyError(f"{where}: {what} must be a string or a list of strings")


@dataclass
class Statement:
    """One baseline statement, normalised."""

    effect: str  # "Allow" or "Deny"
    actions: Optional[List[str]]  # None when the statement uses NotAction
    not_actions: Optional[List[str]]
    resources: Optional[List[str]]  # None when the statement uses NotResource
    not_resources: Optional[List[str]]
    has_condition: bool
    label: str  # where it came from, for messages: 'baseline.json, statement 2 (Sid "X")'

    def applies(self, action: str, resource: str) -> int:
        on_action = _match(self.actions, self.not_actions, action, ignore_case=True)
        if on_action == NONE:
            return NONE
        on_resource = _match(self.resources, self.not_resources, resource, ignore_case=False)
        if on_resource == NONE:
            return NONE
        level = min(on_action, on_resource)
        return PARTIAL if self.has_condition else level

    def why_partial(self, action: str, resource: str) -> str:
        reasons = []
        if self.has_condition:
            reasons.append("has a Condition")
        if _match(self.actions, self.not_actions, action, True) == PARTIAL:
            reasons.append("covers only some of the actions this name stands for")
        on_resource = _match(self.resources, self.not_resources, resource, False)
        if on_resource == PARTIAL:
            reasons.append("uses NotResource" if self.resources is None else "is limited to specific resources")
        return " and ".join(reasons) or "applies only in part"


def _policy_document(data: Any, where: str) -> Dict:
    """The policy document inside the forms a baseline or generated file can take."""
    if not isinstance(data, dict):
        raise PolicyError(f"{where}: not a JSON object")
    if "Statement" in data:
        return data
    if isinstance(data.get("policy"), dict):  # cfn2iam --format json
        return data["policy"]
    if isinstance(data.get("PolicyDocument"), dict):  # aws iam get-role-policy
        return data["PolicyDocument"]
    version = data.get("PolicyVersion")
    if isinstance(version, dict) and isinstance(version.get("Document"), dict):  # aws iam get-policy-version
        return version["Document"]
    raise PolicyError(f"{where}: no policy found (expected a policy document with a Statement)")


def _statements(document: Dict, where: str) -> List[Dict]:
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(isinstance(s, dict) for s in statements):
        raise PolicyError(f"{where}: Statement must be an object or a list of objects")
    return statements


def _parse_statement(raw: Dict, where: str) -> Statement:
    effect = raw.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise PolicyError(f'{where}: Effect must be "Allow" or "Deny", not {effect!r}')
    if ("Action" in raw) == ("NotAction" in raw):
        raise PolicyError(f"{where}: needs exactly one of Action and NotAction")
    actions = _as_list(raw["Action"], "Action", where) if "Action" in raw else None
    not_actions = _as_list(raw["NotAction"], "NotAction", where) if "NotAction" in raw else None
    if "Resource" in raw and "NotResource" in raw:
        raise PolicyError(f"{where}: has both Resource and NotResource")
    if "NotResource" in raw:
        resources, not_resources = None, _as_list(raw["NotResource"], "NotResource", where)
    else:
        # Identity policies need one of the two; without either, assume nothing about resources.
        resources = _as_list(raw["Resource"], "Resource", where) if "Resource" in raw else ["${unknown}"]
        not_resources = None
    sid = raw.get("Sid")
    label = f'{where} (Sid "{sid}")' if sid else where
    return Statement(effect, actions, not_actions, resources, not_resources, bool(raw.get("Condition")), label)


@dataclass
class Baseline:
    sources: List[str]
    statements: List[Statement]


def load_baseline(documents: Iterable[Tuple[str, Any]]) -> Baseline:
    """Read baseline files, given as (name, parsed JSON). Several files combine, like the policies of one role."""
    sources, statements = [], []
    for name, data in documents:
        sources.append(name)
        document = _policy_document(data, name)
        for i, raw in enumerate(_statements(document, name), start=1):
            statements.append(_parse_statement(raw, f"{name}, statement {i}"))
    return Baseline(sources, statements)


@dataclass
class Generated:
    """What one or more cfn2iam outputs need, combined as if one role deploys every template."""

    sources: List[str]
    required: Dict[str, Set[str]]  # action -> resources, from Allow statements
    denied: Dict[str, Set[str]]  # delete-only actions the policy denies -> resources
    delete_only: Set[str]  # actions known to be delete-only (needed only to delete), allowed or denied
    needed_by: Dict[str, Set[Tuple[str, str]]]  # action -> {(source, resource type)}
    warnings: List[str] = field(default_factory=list)
    unresolved: Dict[str, Dict[str, str]] = field(default_factory=dict)  # source -> {type: reason}
    policies: List[Dict] = field(default_factory=list)


def load_generated(documents: Iterable[Tuple[str, Any]]) -> Generated:
    """Read cfn2iam outputs, given as (name, parsed JSON): a policy file, or ``--format json`` output.

    ``--format json`` output also says which resource types need each action.
    """
    gen = Generated([], {}, {}, set(), {})
    create_needed: Set[str] = set()  # actions some template needs for more than deleting
    for name, data in documents:
        gen.sources.append(name)
        document = _policy_document(data, name)
        gen.policies.append(document)
        detailed = isinstance(data, dict) and "policy" in data  # --format json output
        label = (data.get("template") or name) if detailed else name
        for i, raw in enumerate(_statements(document, name), start=1):
            where = f"{name}, statement {i}"
            for key in ("NotAction", "NotResource", "Condition"):
                if key in raw:
                    raise PolicyError(f"{where}: {key} is not supported in a generated policy")
            stmt = _parse_statement({"Resource": "*", **raw}, where)
            target = gen.required if stmt.effect == "Allow" else gen.denied
            for action in stmt.actions or []:
                target.setdefault(action, set()).update(stmt.resources or ["*"])
                if stmt.effect == "Allow" and not detailed:
                    create_needed.add(action)
        if detailed:
            gen.delete_only.update(data.get("delete") or [])
            create_needed.update(data.get("allow") or [])
            for rtype, entry in (data.get("by_type") or {}).items():
                for action in (entry.get("allow") or []) + (entry.get("delete") or []):
                    gen.needed_by.setdefault(action, set()).add((label, rtype))
            gen.warnings.extend(f"{label}: {w}" for w in data.get("warnings") or [])
            if data.get("unresolved"):
                gen.unresolved[label] = dict(data["unresolved"])
    # An action one template needs to create or update is never denied for another:
    # the explicit Deny would override the Allow and break that template's deploy.
    for action in list(gen.denied):
        if action in gen.required:
            del gen.denied[action]
    gen.delete_only -= create_needed
    return gen


def _resource_value(resources: Sequence[str]):
    return resources[0] if len(resources) == 1 else list(resources)


def combined_policy(gen: Generated) -> Dict:
    """The policy for every template together: what a new baseline would be.

    One input is returned unchanged. Several are merged: an action any template needs
    is allowed, and an action denied only for deletion stays denied unless another
    template needs it.
    """
    if len(gen.policies) == 1:
        return gen.policies[0]
    groups: Dict[Tuple[int, str, Tuple[str, ...]], List[str]] = {}
    for action, resources in gen.required.items():
        order = 1 if action in gen.delete_only else 0  # allow-delete output keeps deletes apart
        groups.setdefault((order, "Allow", tuple(sorted(resources))), []).append(action)
    for action, resources in gen.denied.items():
        groups.setdefault((2, "Deny", tuple(sorted(resources))), []).append(action)
    statements = []
    for (_, effect, resources), actions in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][2] != ("*",), kv[0])):
        statements.append({"Effect": effect, "Action": sorted(actions), "Resource": _resource_value(resources)})
    return {"Version": "2012-10-17", "Statement": statements}


# --- The comparison ---------------------------------------------------------


@dataclass
class Finding:
    action: str  # an action, or a baseline Action entry (for "not needed" findings)
    status: str = ""
    reasons: List[str] = field(default_factory=list)
    needed_by: List[Tuple[str, str]] = field(default_factory=list)  # (template, resource type)

    def to_dict(self) -> Dict:
        out: Dict[str, Any] = {"action": self.action}
        if self.status:
            out["status"] = self.status
        if self.reasons:
            out["reasons"] = self.reasons
        if self.needed_by:
            out["needed_by"] = [{"template": t, "type": r} for t, r in self.needed_by]
        return out


@dataclass
class Report:
    generated: Generated
    baseline: Optional[Baseline]
    conditional_mode: str
    not_granted: List[Finding]  # missing or denied: drift
    conditional: List[Finding]  # granted or denied only under a Condition or for some resources
    not_needed: List[Finding]  # baseline Allow entries that match no needed action
    newly_denied: List[Finding]  # delete-only actions the generated policy denies and the baseline doesn't
    no_longer_denied: List[Finding]  # baseline Deny entries that match nothing the generated policy denies
    required_count: int

    @property
    def has_baseline(self) -> bool:
        return self.baseline is not None

    @property
    def added(self) -> List[Finding]:
        """The actions that count as permission drift."""
        if self.conditional_mode == "missing":
            return sorted(self.not_granted + self.conditional, key=lambda f: f.action.lower())
        return self.not_granted

    @property
    def drift(self) -> bool:
        return bool(self.added)

    @property
    def changed(self) -> bool:
        return bool(
            self.not_granted or self.conditional or self.not_needed or self.newly_denied or self.no_longer_denied
        )

    def counts(self) -> Dict[str, int]:
        return {
            "required": self.required_count,
            "added": len(self.added),
            "conditional": len(self.conditional),
            "removed": len(self.not_needed),
            "newly_denied": len(self.newly_denied),
            "no_longer_denied": len(self.no_longer_denied),
        }

    def to_dict(self) -> Dict:
        return {
            "drift": self.drift,
            "baseline": self.baseline.sources if self.baseline else None,
            "generated": self.generated.sources,
            "conditional_mode": self.conditional_mode,
            "counts": self.counts(),
            "added": [f.to_dict() for f in self.added],
            "conditional": [f.to_dict() for f in self.conditional],
            "removed": [f.to_dict() for f in self.not_needed],
            "newly_denied": [f.to_dict() for f in self.newly_denied],
            "no_longer_denied": [f.to_dict() for f in self.no_longer_denied],
            "warnings": self.generated.warnings,
        }


def _status(statements: List[Statement], action: str, resources: Set[str]) -> Tuple[str, List[str]]:
    worst, reasons = GRANTED, []
    for resource in sorted(resources):
        allow_full = allow_partial = deny_full = False
        notes = []
        for s in statements:
            level = s.applies(action, resource)
            if level == NONE:
                continue
            if s.effect == "Deny":
                if level == FULL:
                    deny_full = True
                    notes.append(f"denied by {s.label}")
                else:
                    notes.append(f"may be denied by {s.label}, which {s.why_partial(action, resource)}")
            elif level == FULL:
                allow_full = True
            else:
                allow_partial = True
                notes.append(f"allowed by {s.label}, which {s.why_partial(action, resource)}")
        if deny_full:
            status = DENIED
            notes = [n for n in notes if n.startswith("denied by")]
        elif allow_full and not any(n.startswith("may be denied") for n in notes):
            status, notes = GRANTED, []
        elif allow_full or allow_partial:
            status = CONDITIONAL
            if allow_full:
                notes = [n for n in notes if n.startswith("may be denied")]
        else:
            status = MISSING
            notes = [n for n in notes if n.startswith("may be denied")]
        if _RANK[status] < _RANK[worst]:
            worst = status
        for n in notes:
            if n not in reasons:
                reasons.append(n)
    return worst, reasons


def _needed_by(gen: Generated, action: str) -> List[Tuple[str, str]]:
    return sorted(gen.needed_by.get(action, ()))


def compare(gen: Generated, baseline: Optional[Baseline], conditional: str = "missing") -> Report:
    """Compare what the templates need with the baseline. Without a baseline, nothing is compared."""
    if conditional not in CONDITIONAL_MODES:
        raise ValueError(f"conditional must be one of {CONDITIONAL_MODES}, not {conditional!r}")
    report = Report(gen, baseline, conditional, [], [], [], [], [], len(gen.required))
    if baseline is None:
        return report
    statements = baseline.statements
    for action in sorted(gen.required, key=str.lower):
        status, reasons = _status(statements, action, gen.required[action])
        if status == GRANTED:
            continue
        finding = Finding(action, status, reasons, _needed_by(gen, action))
        (report.conditional if status == CONDITIONAL else report.not_granted).append(finding)

    needed = list(gen.required)
    denied = list(gen.denied)
    seen: Set[Tuple[str, str]] = set()
    for s in statements:
        if s.has_condition or s.actions is None:
            continue  # NotAction can't be listed; a conditional entry isn't a plain grant or deny
        pool = needed if s.effect == "Allow" else denied
        for entry in s.actions:
            key = (s.effect, entry.lower())
            if key in seen:
                continue
            seen.add(key)
            if not any(overlaps(entry, a) for a in pool):
                target = report.not_needed if s.effect == "Allow" else report.no_longer_denied
                target.append(Finding(entry, reasons=[s.label]))
    for action in sorted(denied, key=str.lower):
        hard_deny = [
            s
            for s in statements
            if s.effect == "Deny" and all(s.applies(action, r) == FULL for r in gen.denied[action])
        ]
        if not hard_deny:
            report.newly_denied.append(Finding(action, needed_by=_needed_by(gen, action)))
    report.not_needed.sort(key=lambda f: f.action.lower())
    report.no_longer_denied.sort(key=lambda f: f.action.lower())
    return report


# --- Rendering --------------------------------------------------------------


def _service(action: str) -> str:
    return action.split(":", 1)[0].lower() if ":" in action else "*"


def _by_service(findings: Sequence[Finding]) -> List[Tuple[str, List[Finding]]]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(_service(f.action), []).append(f)
    return sorted(groups.items())


def _by_reasons(findings: Sequence[Finding]) -> List[Tuple[Tuple[str, ...], List[Finding]]]:
    groups: Dict[Tuple[str, ...], List[Finding]] = {}
    for f in findings:
        groups.setdefault(tuple(f.reasons), []).append(f)
    return list(groups.items())


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _types(f: Finding, multi: bool) -> str:
    if not f.needed_by:
        return ""
    if multi:
        parts = [f"{rtype} in {template}" for template, rtype in f.needed_by]
    else:
        parts = list(dict.fromkeys(rtype for _, rtype in f.needed_by))
    return ", ".join(parts)


def headline(report: Report) -> str:
    """One line saying what the check found."""
    if not report.has_baseline:
        return f"No baseline to compare with. The templates need {_plural(report.required_count, 'action')}."
    added = report.added
    if added:
        return f"Permission drift: the templates need {_plural(len(added), 'action')} the baseline does not grant."
    if report.changed:
        return "No new permissions needed: the baseline grants every action the templates need."
    return "No permission changes: the baseline grants exactly what the templates need."


def render_text(report: Report) -> str:
    """A plain-text report for a terminal or a CI log."""
    multi = len(report.generated.sources) > 1
    lines = [headline(report)]

    def section(title: str, findings: Sequence[Finding], detail: bool = True):
        if not findings:
            return
        lines.append("")
        lines.append(f"{title} ({len(findings)}):")
        for f in findings:
            extra = _types(f, multi) if detail else ""
            lines.append(f"  {f.action}" + (f"  ({extra})" if extra else ""))
            for r in f.reasons:
                lines.append(f"      {r}")

    if not report.has_baseline:
        return "\n".join(lines) + "\n"
    section("Needed, not granted by the baseline", report.not_granted)
    counted = "counted as not granted" if report.conditional_mode == "missing" else "counted as granted"
    if report.conditional:
        lines.append("")
        lines.append(f"Granted only under a condition or for some resources, {counted} ({len(report.conditional)}):")
        for reasons, group in _by_reasons(report.conditional):
            lines.append(f"  {'; '.join(reasons)}:")
            lines.extend(f"      {f.action}" for f in group)
    section("Allowed by the baseline, not needed by the templates", report.not_needed)
    section("Delete-only, denied by the generated policy but not by the baseline", report.newly_denied)
    section("Denied by the baseline, not by the generated policy", report.no_longer_denied)
    return "\n".join(lines) + "\n"


def _md_code(text: str) -> str:
    return f"`{text}`" if "`" not in text else f"``{text}``"


def _md_escape(text: str) -> str:
    return re.sub(r"([\\`*_{}\[\]<>|])", r"\\\1", text)


def _md_findings(
    findings: Sequence[Finding], multi: bool, open_: bool, limit: Optional[int], detail: bool
) -> List[str]:
    out = []
    shown = 0
    hidden = 0
    for service, group in _by_service(findings):
        if limit is not None and shown >= limit:
            hidden += len(group)
            continue
        out.append(f"<details{' open' if open_ else ''}><summary><code>{service}</code>: {len(group)}</summary>")
        out.append("")
        for f in group:
            if limit is not None and shown >= limit:
                hidden += 1
                continue
            shown += 1
            line = f"- {_md_code(f.action)}"
            if detail:
                extra = _types(f, multi)
                if extra:
                    line += f" ({_md_escape(extra)})"
                if f.reasons:
                    line += ": " + "; ".join(_md_escape(r) for r in f.reasons)
            out.append(line)
        out.append("")
        out.append("</details>")
    if hidden:
        out.append("")
        out.append(f"...and {_plural(hidden, 'more action')}, left out for length.")
    return out


def _md_compact(findings: Sequence[Finding], limit: Optional[int]) -> List[str]:
    """A table, one row per service, for the lists a reviewer rarely needs in full."""
    out = ["| Service | Actions |", "|---|---|"]
    shown = 0
    for service, group in _by_service(findings):
        names = [f.action.split(":", 1)[-1] for f in group]
        if limit is not None:
            names = names[: max(0, limit - shown)]
        shown += len(names)
        more = len(group) - len(names)
        cell = ", ".join(_md_code(n) for n in names) + (f" and {more} more" if more else "")
        out.append(f"| `{service}` | {cell} |")
    return out


def render_markdown(
    report: Report,
    *,
    title: str = "cfn2iam permission check",
    marker: str = "",
    context: Sequence[str] = (),
    notes: Sequence[str] = (),
    footer: Sequence[str] = (),
    max_length: Optional[int] = None,
) -> str:
    """A Markdown report for a pull request comment or a job summary.

    ``context`` lines go under the headline (what was checked), ``notes`` after the
    findings, ``footer`` at the end. With ``max_length``, lists are shortened until the
    text fits (a GitHub comment holds 65,536 characters).
    """
    for limit, detail in ((None, True), (None, False), (200, False), (50, False), (10, False), (0, False)):
        text = _render_markdown(report, title, marker, context, notes, footer, limit, detail)
        if max_length is None or len(text) <= max_length:
            return text
    return text[: max_length - 40] + "\n\n...cut short for length.\n"


def _render_markdown(report, title, marker, context, notes, footer, limit, detail) -> str:
    multi = len(report.generated.sources) > 1
    out = []
    if marker:
        out.append(marker)
    out.append(f"### {title}")
    out.append("")
    if not report.has_baseline:
        out.append(f"**{headline(report)}**")
    elif report.drift:
        out.append(f"> [!CAUTION]\n> **{headline(report)}**")
    else:
        out.append(f"> [!NOTE]\n> **{headline(report)}**")
    out.extend(["", *context] if context else [])

    if report.has_baseline:
        counts = report.counts()
        counted = "yes" if report.conditional_mode == "missing" else "no"
        rows = [
            ("Needed, not granted by the baseline", len(report.not_granted), "yes"),
            ("Granted only under a condition or for some resources", counts["conditional"], counted),
            ("Allowed by the baseline, no longer needed", counts["removed"], "no"),
            ("Delete-only, newly denied", counts["newly_denied"], "no"),
            ("Denied by the baseline, no longer denied", counts["no_longer_denied"], "no"),
        ]
        out.extend(["", "| | Actions | Counts as drift |", "|---|--:|:-:|"])
        out.extend(f"| {name} | {n} | {drift if n else ''} |" for name, n, drift in rows)

        if report.not_granted:
            out.extend(["", f"#### Needed, not granted by the baseline ({len(report.not_granted)})", ""])
            out.extend(_md_findings(report.not_granted, multi, len(report.not_granted) <= 30, limit, detail))
        if report.conditional:
            counted_text = (
                "They count as not granted. If the conditions hold when the stack deploys, set `conditional: granted` (CLI: `--conditional granted`)."
                if report.conditional_mode == "missing"
                else "They count as granted (`conditional: granted`)."
            )
            out.extend(
                [
                    "",
                    f"#### Granted only under a condition or for some resources ({len(report.conditional)})",
                    "",
                    "cfn2iam can't tell from the template whether a `Condition` holds at deploy time, or whether the "
                    f"resources the stack creates fall within a statement's `Resource`. {counted_text}",
                    "",
                ]
            )
            for reasons, group in _by_reasons(report.conditional):
                summary = _md_escape("; ".join(reasons)) or "conditional"
                out.extend(["", f"<details><summary>{_plural(len(group), 'action')}: {summary}</summary>", ""])
                out.extend(_md_compact(group, limit))
                out.extend(["", "</details>"])
        if report.not_needed:
            out.extend(["", f"#### Allowed by the baseline, no longer needed ({len(report.not_needed)})", ""])
            out.append("<details><summary>Baseline entries that match no action the templates need</summary>")
            out.append("")
            out.extend(_md_compact(report.not_needed, limit))
            out.extend(["", "</details>"])
        if report.newly_denied or report.no_longer_denied:
            out.extend(["", "#### Delete-only actions", ""])
            out.append(
                "The generated policy denies the actions only deleting resources needs (unless `allow-delete` is on)."
            )
            if report.newly_denied:
                out.extend(["", f"<details><summary>Newly denied: {len(report.newly_denied)}</summary>", ""])
                out.extend(_md_compact(report.newly_denied, limit))
                out.extend(["", "</details>"])
            if report.no_longer_denied:
                out.extend(
                    [
                        "",
                        f"<details><summary>Denied by the baseline, no longer denied: {len(report.no_longer_denied)}</summary>",
                        "",
                    ]
                )
                out.extend(_md_compact(report.no_longer_denied, limit))
                out.extend(["", "</details>"])
    else:
        needed = [
            Finding(a, needed_by=_needed_by(report.generated, a))
            for a in sorted(report.generated.required, key=str.lower)
        ]
        if needed:
            out.extend(["", "<details><summary>Actions the templates need, by service</summary>", ""])
            out.extend(_md_compact(needed, limit))
            out.extend(["", "</details>"])

    warnings = report.generated.warnings
    skipped = {
        f"{src}: {t}": reason for src, types in report.generated.unresolved.items() for t, reason in types.items()
    }
    if warnings or skipped:
        out.extend(["", "#### Warnings", ""])
        out.extend(f"- {_md_escape(w)}" for w in warnings)
        out.extend(
            f"- Skipped {_md_escape(t)} ({_md_escape(r)}): its permissions are not in the policy"
            for t, r in skipped.items()
        )
    if notes:
        out.extend(["", *notes])
    if footer:
        out.extend(["", *footer])
    return "\n".join(out).rstrip() + "\n"
