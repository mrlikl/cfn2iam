"""The GitHub Action's work, run by action.yml with the Python cfn2iam is installed in.

For each template it runs the ``cfn2iam`` CLI (``--format json``), combines the
results, compares them with the baseline (:mod:`cfn2iam.compare`), writes the job
summary and the step outputs, and comments on the pull request. Inputs arrive as
``INPUT_*`` environment variables set by action.yml.

This file is not part of the cfn2iam package: the action runs it from its own
checkout. Everything GitHub-specific lives here, and only here.
"""

import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from typing import Dict, List, Mapping, Optional, Tuple

from cfn2iam import compare, core

DOCS = "https://github.com/mrlikl/cfn2iam#use-it-in-ci"
COMMENT_LIMIT = 65536  # characters GitHub allows in a comment body
SUMMARY_LIMIT = 1024 * 1024  # bytes per step summary
COMMENT_MODES = {"always": "always", "true": "always", "on-change": "on-change", "never": "never", "false": "never"}
PR_EVENTS = ("pull_request", "pull_request_target")


class InputError(Exception):
    pass


def _bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    value = env.get(f"INPUT_{name.upper().replace('-', '_')}", "").strip().lower()
    if not value:
        return default
    if value in ("true", "yes", "1"):
        return True
    if value in ("false", "no", "0"):
        return False
    raise InputError(f"{name} must be true or false, not {value!r}")


def _str(env: Mapping[str, str], name: str) -> str:
    return env.get(f"INPUT_{name.upper().replace('-', '_')}", "").strip()


def _lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


@dataclass
class Inputs:
    templates: List[str]
    baseline: List[str]
    allow_delete: bool
    ignore_unknown: bool
    conditional: str
    fail_on_drift: bool
    require_baseline: bool
    update_baseline: bool
    comment: str
    name: str
    region: str
    account: str
    partition: str
    token: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Inputs":
        conditional = _str(env, "conditional") or "missing"
        if conditional not in compare.CONDITIONAL_MODES:
            raise InputError(f"conditional must be missing or granted, not {conditional!r}")
        comment = _str(env, "comment").lower() or "always"
        if comment not in COMMENT_MODES:
            raise InputError(f"comment must be always, on-change or never, not {comment!r}")
        templates = _lines(_str(env, "templates"))
        if not templates:
            raise InputError("templates is empty: give at least one template path or glob pattern")
        return cls(
            templates=templates,
            baseline=_lines(_str(env, "baseline")),
            allow_delete=_bool(env, "allow-delete"),
            ignore_unknown=_bool(env, "ignore-unknown"),
            conditional=conditional,
            fail_on_drift=_bool(env, "fail-on-drift", True),
            require_baseline=_bool(env, "require-baseline"),
            update_baseline=_bool(env, "update-baseline"),
            comment=COMMENT_MODES[comment],
            name=_str(env, "name"),
            region=_str(env, "region"),
            account=_str(env, "account"),
            partition=_str(env, "partition"),
            token=env.get("INPUT_GITHUB_TOKEN", ""),
        )

    def cli_options(self) -> List[str]:
        args = []
        if self.allow_delete:
            args.append("-d")
        if self.ignore_unknown:
            args.append("--ignore-unknown")
        for flag, value in (("--region", self.region), ("--account", self.account), ("--partition", self.partition)):
            if value:
                args += [flag, value]
        return args


# --- Workflow commands ------------------------------------------------------


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def annotate(level: str, message: str, file: Optional[str] = None, title: Optional[str] = None) -> None:
    props = []
    if file:
        props.append(f"file={_escape_property(file)}")
    if title:
        props.append(f"title={_escape_property(title)}")
    print(f"::{level}{' ' + ','.join(props) if props else ''}::{_escape_data(message)}", flush=True)


def set_outputs(env: Mapping[str, str], outputs: Dict[str, str]) -> None:
    path = env.get("GITHUB_OUTPUT")
    lines = [f"{k}={v}" for k, v in outputs.items()]
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def write_summary(env: Mapping[str, str], text: str) -> None:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        print(text)
        return
    data = text.encode("utf-8")
    if len(data) > SUMMARY_LIMIT:
        text = (
            data[: SUMMARY_LIMIT - 200].decode("utf-8", "ignore")
            + "\n\n...cut short: the job summary limit is 1 MiB.\n"
        )
    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")


# --- Templates and generation -----------------------------------------------


def expand_templates(patterns: List[str], cwd: str) -> Tuple[List[str], List[str]]:
    """The template files the patterns name, and an error for each pattern that names none."""
    found: List[str] = []
    errors: List[str] = []
    for pattern in patterns:
        if any(c in pattern for c in "*?["):
            matched = sorted(
                p for p in glob.glob(pattern, root_dir=cwd, recursive=True) if os.path.isfile(os.path.join(cwd, p))
            )
            if not matched:
                errors.append(f"No template matches `{pattern}`.")
            found.extend(matched)
        elif os.path.isfile(os.path.join(cwd, pattern)):
            found.append(pattern)
        elif os.path.isdir(os.path.join(cwd, pattern)):
            errors.append(f"`{pattern}` is a directory: give template files, or a glob such as `{pattern}/*.yaml`.")
        else:
            errors.append(f"Template `{pattern}` does not exist.")
    return list(dict.fromkeys(p.replace(os.sep, "/") for p in found)), errors


@dataclass
class Generation:
    template: str
    output: Optional[str] = None  # the --format json file, when cfn2iam succeeded
    error: Optional[str] = None
    log: str = ""  # cfn2iam's stderr (warnings) when it succeeded
    hint: str = ""  # what to change in the action's inputs, for an error


def generate(template: str, out_path: str, options: List[str], cwd: str) -> Generation:
    cmd = [sys.executable, "-I", "-m", "cfn2iam", template, "--format", "json", "-o", out_path, *options]
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return Generation(template, error="cfn2iam took longer than 15 minutes")
    log = "\n".join(line for line in proc.stderr.splitlines() if not line.startswith("Generated IAM Policy Document"))
    if proc.returncode != 0:
        message = "\n".join(part for part in (proc.stderr.strip(), proc.stdout.strip()) if part)
        hint = ""
        if 'install "cfn2iam[iam]"' in message:
            hint = (
                "In the action, set `registry-fallback: true` (and configure AWS credentials) to look such types "
                "up in the CloudFormation registry, or `ignore-unknown: true` to skip them."
            )
        return Generation(template, error=message or f"cfn2iam exited with status {proc.returncode}", hint=hint)
    return Generation(template, output=out_path, log=log.strip())


# --- Pull request comments --------------------------------------------------


class GitHub:
    def __init__(self, api_url: str, repo: str, token: str):
        self.api_url = api_url.rstrip("/")
        self.repo = repo
        self.token = token

    def request(self, method: str, path: str, body: Optional[Dict] = None):
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "cfn2iam-action")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            return json.loads(payload) if payload else None, resp.headers.get("Link", "")

    def find_comment(self, number: int, marker: str) -> Optional[Dict]:
        path: Optional[str] = f"/repos/{self.repo}/issues/{number}/comments?per_page=100"
        while path:
            comments, link = self.request("GET", path)
            for c in comments or []:
                if (c.get("body") or "").startswith(marker):
                    return c
            m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
            path = m.group(1) if m else None
        return None

    def upsert_comment(self, number: int, marker: str, body: str, create: bool) -> Optional[str]:
        """Update the comment that starts with ``marker``, or create one. Returns its URL, or None if none was made."""
        existing = self.find_comment(number, marker)
        if existing:
            updated, _ = self.request("PATCH", f"/repos/{self.repo}/issues/comments/{existing['id']}", {"body": body})
            return (updated or existing).get("html_url")
        if not create:
            return None
        created, _ = self.request("POST", f"/repos/{self.repo}/issues/{number}/comments", {"body": body})
        return (created or {}).get("html_url")


def _http_reason(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        try:
            message = json.loads(e.read() or b"{}").get("message", "")
        except ValueError:
            message = ""
        return f"HTTP {e.code}{': ' + message if message else ''}"
    return str(e)


def pull_request(env: Mapping[str, str]) -> Optional[Dict]:
    if env.get("GITHUB_EVENT_NAME") not in PR_EVENTS or not env.get("GITHUB_EVENT_PATH"):
        return None
    try:
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
            return json.load(f).get("pull_request")
    except (OSError, ValueError):
        return None


# --- The run ----------------------------------------------------------------


def comment_marker(name: str) -> str:
    """The hidden first line that identifies this check's comment, for any ``name``.

    An HTML comment ends at ``-->`` or ``--!>``, so ``>`` is percent-encoded, along with ``<``,
    ``&``, ``%`` (so encoded names stay distinct) and line breaks and other control characters.
    Other names are kept as they are, so the markers of comments earlier versions wrote still match.
    """
    if not name:
        return "<!-- cfn2iam-action -->"
    safe = re.sub(r"[<>&%\x00-\x1f\x7f\u2028\u2029]", lambda m: "".join(f"%{b:02X}" for b in m.group().encode()), name)
    return f"<!-- cfn2iam-action:{safe} -->"


def _summary_url(env: Mapping[str, str]) -> str:
    server, repo, run_id = (env.get(k, "") for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    if not (server and repo and run_id):
        return ""
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    return f"{server}/{repo}/actions/runs/{run_id}" + (f"/attempts/{attempt}" if attempt else "")


def _code_list(items: List[str]) -> str:
    return ", ".join(f"`{i}`" for i in items)


def _cfn2iam_version() -> str:
    try:
        return version("cfn2iam")
    except PackageNotFoundError:
        return "unknown"


def accept_commands(inputs: Inputs, templates: List[str], baseline: str, pkg_version: str) -> str:
    release = re.fullmatch(r"\d+\.\d+\.\d+", pkg_version)
    install = f'pip install "cfn2iam=={pkg_version}"' if release else "pip install cfn2iam"
    options = " ".join(_shell_quote(o) for o in inputs.cli_options())
    options = f" {options}" if options else ""
    lines = [install]
    if len(templates) == 1:
        lines.append(f"cfn2iam {_shell_quote(templates[0])}{options} -o {_shell_quote(baseline)}")
    else:
        outs = []
        for i, t in enumerate(templates, start=1):
            out = f"/tmp/cfn2iam-{i}.json"
            outs.append(out)
            lines.append(f"cfn2iam {_shell_quote(t)}{options} -o {out}")
        lines.append(f"cfn2iam diff {' '.join(outs)} -w {_shell_quote(baseline)}")
    return "\n".join(lines)


def _shell_quote(text: str) -> str:
    return text if re.fullmatch(r"[A-Za-z0-9_./:=@+-]+", text) else "'" + text.replace("'", "'\\''") + "'"


@dataclass
class Result:
    markdown_comment: str
    markdown_summary: str
    outputs: Dict[str, str]
    exit_code: int
    notices: List[Tuple[str, str]] = field(default_factory=list)  # (level, message)
    changed: bool = False


def run(env: Mapping[str, str], cwd: str, workdir: str) -> Result:
    """Everything except posting the comment and writing to GitHub's files."""
    # CFN2IAM_ACTION_COMMENT_LIMIT is for this repository's CI, to exercise shortening without a huge template.
    comment_limit = min(COMMENT_LIMIT, int(env.get("CFN2IAM_ACTION_COMMENT_LIMIT") or COMMENT_LIMIT))
    pkg_version = _cfn2iam_version()
    inputs = Inputs.from_env(env)
    title = "cfn2iam permission check" + (f": {compare._md_escape(inputs.name)}" if inputs.name else "")
    marker = comment_marker(inputs.name)
    footer = [f'<sub>cfn2iam {pkg_version} · <a href="{DOCS}">how this check works</a></sub>']
    notices: List[Tuple[str, str]] = []
    errors: List[str] = []

    templates, missing = expand_templates(inputs.templates, cwd)
    errors.extend(missing)
    for m in missing:
        notices.append(("error", m.replace("`", "")))
    generations = []
    options = inputs.cli_options()
    for i, template in enumerate(templates, start=1):
        g = generate(template, os.path.join(workdir, f"generated-{i}.json"), options, cwd)
        generations.append(g)
        if g.error:
            hint = f"\n\n  {g.hint}" if g.hint else ""
            errors.append(
                f"cfn2iam could not generate the policy for `{template}`:\n\n  ```\n  {g.error.replace(chr(10), chr(10) + '  ')}\n  ```{hint}"
            )
            first = next((line for line in g.error.splitlines() if line.strip()), g.error)
            notices.append(("error", f"{template}: {first}"))
        for line in g.log.splitlines():
            if line.startswith("Warning: "):
                notices.append(("warning", f"{template}: {line.removeprefix('Warning: ')}"))
            elif line.strip():
                print(f"{template}: {line}")  # e.g. the scoping summary

    baseline_status = "none"
    baseline_path = inputs.baseline[0] if inputs.baseline else ""
    existing = [b for b in inputs.baseline if os.path.isfile(os.path.join(cwd, b))]
    if inputs.baseline:
        if len(existing) == len(inputs.baseline):
            baseline_status = "found"
        elif not existing:
            baseline_status = "missing"
        else:
            absent = [b for b in inputs.baseline if b not in existing]
            errors.append(f"Baseline file {_code_list(absent)} does not exist (the others do).")
    if inputs.update_baseline and len(inputs.baseline) != 1:
        errors.append("`update-baseline` needs exactly one `baseline` file to write.")
    if baseline_status == "missing" and inputs.require_baseline and not inputs.update_baseline:
        errors.append(f"Baseline {_code_list(inputs.baseline)} does not exist, and `require-baseline` is on.")

    report = None
    policy_path = ""
    generated_data: List[Dict] = []
    hand_written = ""
    if not any(g.error for g in generations) and templates:
        try:
            generated_data = [_read_json(g.output) for g in generations]
            gen = compare.load_generated([(g.template, d) for g, d in zip(generations, generated_data, strict=True)])
            if len(generations) > 1:
                # Each template's own size warning is in gen.warnings; the combined policy can be over
                # the limits when none of them is.
                combined_warning = core.size_warning(core.policy_size(compare.combined_policy(gen)))
                if combined_warning:
                    gen.warnings.append(f"All templates combined: {combined_warning}")
                    notices.append(("warning", f"All templates combined: {combined_warning}"))
            base = None
            if baseline_status == "found":
                base = compare.load_baseline([(b, _read_json(os.path.join(cwd, b))) for b in inputs.baseline])
            report = compare.compare(gen, base, inputs.conditional)
            if baseline_status == "found":
                hand_written = _hand_written([_read_json(os.path.join(cwd, b)) for b in inputs.baseline])
            policy_path = os.path.join(workdir, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump(compare.combined_policy(gen), f, indent=2)
                f.write("\n")
        except (compare.PolicyError, OSError) as e:
            errors.append(f"Could not compare the policies: {e}")
            notices.append(("error", str(e)))
            report = None

    context = [f"Templates: {_code_list(templates) or '(none)'}"]
    if inputs.baseline:
        state = {"found": "", "missing": " (does not exist yet)", "none": ""}[baseline_status]
        context.append(f"Baseline: {_code_list(inputs.baseline)}{state}")
    pr = pull_request(env)
    sha = ((pr or {}).get("head") or {}).get("sha") or env.get("GITHUB_SHA", "")
    if sha:
        context[-1] += f" · Commit {sha[:7]}"
    context = [" · ".join(context)] if len(" · ".join(context)) < 300 else context
    scopes = sorted({_scope_text(d.get("scoping")) for d in generated_data if d.get("scoping")})
    if scopes:
        context.append(
            f'Resources scoped to {"; ".join(scopes)}: a baseline statement on `"*"` covers them, a narrower one is '
            "checked ARN by ARN."
        )

    notes: List[str] = []
    wrote_baseline = False
    if report is not None and inputs.update_baseline and not errors:
        target = os.path.join(cwd, baseline_path)
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(policy_path, encoding="utf-8") as src, open(target, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        wrote_baseline = True
        notes.append(
            f"> [!NOTE]\n> `update-baseline` is on: wrote the generated policy to `{baseline_path}`. "
            "Commit that file to accept these permissions."
        )
    if report is not None and not wrote_baseline:
        commands = accept_commands(inputs, templates, baseline_path or "iam/deploy-policy.json", pkg_version)
        if baseline_status != "found":
            where = f"`{baseline_path}`" if baseline_path else "a file, and set the `baseline` input to it,"
            notes.append(
                f"**Start checking:** commit the policy the templates need as {where} "
                "and give your deploy role that policy (or one that grants at least as much). "
                f"Later runs will report what changes.\n\n```bash\n{commands}\n```"
            )
        elif report.changed and hand_written:
            what = (
                "grant the actions listed above to the deploy role and to the baseline"
                if report.added
                else "nothing new needs granting; to drop what is no longer needed, remove it from the deploy role "
                "and the baseline"
            )
            notes.append(
                "<details><summary>How to accept this change</summary>\n\n"
                f"{_code_list(inputs.baseline)} looks hand-written ({hand_written}), so edit it: {what} in this "
                "pull request. Regenerating it with cfn2iam would replace it with the generated policy.\n\n</details>"
            )
        elif report.changed:
            first = (
                "Grant the new actions to the deploy role, then regenerate the baseline"
                if report.added
                else "Nothing new needs granting. To record the change, regenerate the baseline (and remove the "
                "actions no longer needed from the deploy role, if you like)"
            )
            notes.append(
                "<details><summary>How to accept this change</summary>\n\n"
                f"{first} and commit it in this pull request:\n\n```bash\n{commands}\n```\n\n</details>"
            )
    if errors:
        notes.insert(0, "> [!CAUTION]\n> **The check could not run.**\n\n" + "\n\n".join(f"- {e}" for e in errors))

    policy_block = ""
    if report is not None and (report.drift or baseline_status != "found" or wrote_baseline):
        with open(policy_path, encoding="utf-8") as f:
            policy_block = (
                f"<details><summary>The generated policy</summary>\n\n```json\n{f.read().rstrip()}\n```\n\n</details>"
            )

    summary_url = _summary_url(env)
    summary_link = f"[the job summary]({summary_url})" if summary_url else "the job summary"
    if report is None:
        body = "\n".join([marker, f"### {title}", "", *context, "", *notes, "", *footer]).rstrip() + "\n"
        comment_md = summary_md = body
    else:
        summary_md = compare.render_markdown(
            report, title=title, context=context, notes=[*notes, policy_block] if policy_block else notes, footer=footer
        )
        with_policy = None
        if policy_block:
            with_policy = compare.render_markdown(
                report, title=title, marker=marker, context=context, notes=[*notes, policy_block], footer=footer
            )
        if with_policy is not None and len(with_policy) <= comment_limit:
            comment_md = with_policy
        else:
            comment_notes = list(notes)
            if policy_block:
                comment_notes.append(
                    f"The generated policy is left out of this comment for length: see {summary_link}."
                )
            comment_md = compare.render_markdown(
                report,
                title=title,
                marker=marker,
                context=context,
                notes=comment_notes,
                footer=footer,
                max_length=comment_limit,
                shortened_note=(
                    "> [!NOTE]\n> This comment is shortened to fit GitHub's size limit: some details (such as the "
                    f"resource types that need each action) are left out. The full report is in {summary_link}."
                ),
            )

    counts = report.counts() if report else {}
    # After update-baseline wrote the file, the baseline grants exactly what the templates need:
    # the outputs describe that, and the report describes what the write changed.
    has_baseline = report is not None and report.has_baseline and not wrote_baseline
    drift = bool(report and report.drift) and not wrote_baseline
    outputs = {
        "policy-path": policy_path,
        "added-count": str(counts.get("added", 0) if has_baseline else 0),
        "removed-count": str(counts.get("removed", 0) if has_baseline else 0),
        "conditional-count": str(counts.get("conditional", 0) if has_baseline else 0),
        "drift": "true" if drift else "false",
        "baseline-status": "found" if wrote_baseline else baseline_status,
        "baseline-updated": "true" if wrote_baseline else "false",
        "error": "true" if errors else "false",
    }
    exit_code = 0
    if errors:
        exit_code = 1
    elif wrote_baseline:
        changed_text = f" ({compare.headline(report)})" if report.has_baseline and report.changed else ""
        notices.append(
            ("notice", f"Wrote the generated policy to {baseline_path}; commit it to accept it.{changed_text}")
        )
    elif drift and inputs.fail_on_drift:
        exit_code = 1
        notices.append(("error", compare.headline(report)))
    elif drift:
        notices.append(("warning", compare.headline(report)))
    elif baseline_status == "missing":
        notices.append(("notice", f"Baseline {', '.join(inputs.baseline)} does not exist yet; see the job summary."))
    changed = bool(errors) or report is None or report.changed or baseline_status != "found"
    return Result(comment_md, summary_md, outputs, exit_code, notices, changed)


def _hand_written(documents: List) -> str:
    """Why a baseline isn't plain cfn2iam output, or "" when it could be."""
    reasons = []
    for data in documents:
        try:
            statements = compare._statements(compare._policy_document(data, ""), "")
        except compare.PolicyError:
            continue
        for st in statements:
            if "Condition" in st:
                reasons.append("conditions")
            if "NotAction" in st or "NotResource" in st:
                reasons.append("NotAction or NotResource")
            actions = st.get("Action", [])
            if any(c in a for a in ([actions] if isinstance(actions, str) else actions) for c in "*?"):
                reasons.append("wildcard actions")
            if "Sid" in st:
                reasons.append("statement IDs")
    return ", ".join(dict.fromkeys(reasons))


def _scope_text(scoping: Dict) -> str:
    parts = [f"account `{scoping.get('account')}`"]
    if scoping.get("region"):
        parts.append(f"region `{scoping['region']}`")
    if scoping.get("partition") and scoping["partition"] != "aws":
        parts.append(f"partition `{scoping['partition']}`")
    return ", ".join(parts)


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except ValueError as e:
        raise compare.PolicyError(f"{path}: not valid JSON: {e}") from e


def comment(env: Mapping[str, str], inputs_comment: str, token: str, result: Result) -> Tuple[str, str, Optional[str]]:
    """Post or update the pull request comment. Returns (commented, comment-url, a notice for the summary)."""
    if inputs_comment == "never":
        return "false", "", None
    pr = pull_request(env)
    if pr is None:
        print(
            f"Not a pull request event ({env.get('GITHUB_EVENT_NAME', 'none')}): the report is in the job summary only."
        )
        return "false", "", None
    marker = result.markdown_comment.split("\n", 1)[0]
    gh = GitHub(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GITHUB_REPOSITORY", ""), token)
    try:
        url = gh.upsert_comment(
            int(pr["number"]), marker, result.markdown_comment, create=(inputs_comment == "always" or result.changed)
        )
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = _http_reason(e)
        head = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
        status = e.code if isinstance(e, urllib.error.HTTPError) else None
        if status == 401:
            why = "GitHub rejected the token: check the `github-token` input (it is expired, revoked or not a token)."
        elif status not in (403, 404):
            why = "GitHub could not be reached or failed; a later run will update the comment."
        elif head and head != env.get("GITHUB_REPOSITORY"):
            why = "This pull request comes from a fork, so its token is read-only."
        else:
            why = (
                "Pull requests from forks and from Dependabot get a read-only token; otherwise, give the job "
                "`pull-requests: write`."
            )
        message = f"Could not comment on the pull request ({reason}). {why} The report is in the job summary."
        annotate("notice", message, title="cfn2iam")
        return "false", "", f"> [!NOTE]\n> {message}"
    if url:
        print(f"Pull request comment: {url}")
        return "true", url, None
    return "false", "", None


def _check_marker_reuse(env: Mapping[str, str], inputs: "Inputs", marker: str) -> None:
    """Warn when an earlier step of this job wrote the comment this step is about to overwrite.

    Steps of one job share RUNNER_TEMP, so each records its marker there. Other jobs can't be
    seen: there, only distinct names keep the comments apart.
    """
    if inputs.comment == "never" or pull_request(env) is None or not env.get("RUNNER_TEMP"):
        return
    registry = os.path.join(env["RUNNER_TEMP"], "cfn2iam-action-comments.txt")
    try:
        with open(registry, encoding="utf-8") as f:
            earlier = {line.rstrip("\n") for line in f}
    except OSError:
        earlier = set()
    if marker in earlier:
        which = f"`name: {inputs.name}`" if inputs.name else "no `name`"
        annotate(
            "warning",
            f"An earlier cfn2iam step in this job wrote the same pull request comment ({which}); this step replaces "
            "its report. Give each invocation its own `name` to keep separate comments.",
            title="cfn2iam",
        )
        return
    try:
        with open(registry, "a", encoding="utf-8") as f:
            f.write(marker + "\n")
    except OSError:
        pass


def main() -> int:
    env = dict(os.environ)
    cwd = os.getcwd()
    try:
        inputs = Inputs.from_env(env)
    except InputError as e:
        annotate("error", str(e), title="cfn2iam")
        write_summary(env, f"### cfn2iam permission check\n\n> [!CAUTION]\n> **The check could not run:** {e}\n")
        set_outputs(env, {"error": "true", "drift": "false"})
        return 1
    workdir = tempfile.mkdtemp(prefix="cfn2iam-", dir=env.get("RUNNER_TEMP") or None)
    result = run(env, cwd, workdir)
    report_path = os.path.join(workdir, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(result.markdown_summary)
    # The comment as it would be posted, next to the report (this repository's CI reads it).
    with open(os.path.join(workdir, "comment.md"), "w", encoding="utf-8") as f:
        f.write(result.markdown_comment)
    _check_marker_reuse(env, inputs, result.markdown_comment.split("\n", 1)[0])
    commented, url, comment_notice = comment(env, inputs.comment, inputs.token, result)
    summary = result.markdown_summary
    if comment_notice:
        summary = summary.rstrip() + "\n\n" + comment_notice + "\n"
    write_summary(env, summary)
    for level, message in result.notices:
        annotate(level, message, title="cfn2iam")
    set_outputs(env, {**result.outputs, "report-path": report_path, "commented": commented, "comment-url": url})
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
