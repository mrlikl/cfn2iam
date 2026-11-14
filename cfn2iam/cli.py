"""The ``cfn2iam`` command: ``cfn2iam TEMPLATE`` generates a policy, ``cfn2iam diff`` compares policies.

``cfn2iam TEMPLATE`` is :data:`cfn2iam.app.app`, unchanged. A first argument of
exactly ``diff`` runs the comparison instead (a template file named ``diff`` can be
given as ``./diff``). Dispatching here, rather than turning the app into a command
group, keeps ``cfn2iam template.yaml`` and its help exactly as they were.
"""

import json
import os
import sys
from enum import StrEnum
from typing import List, Optional

import typer

from . import compare
from .app import app

# Exit codes of cfn2iam diff. 2 is a usage error, as for every typer command.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DRIFT = 3


class ReportFormat(StrEnum):
    text = "text"
    json = "json"
    markdown = "markdown"


class ConditionalMode(StrEnum):
    missing = "missing"
    granted = "granted"


diff_app = typer.Typer(add_completion=False)


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise compare.PolicyError(f"{path}: no such file") from None
    except (OSError, ValueError) as e:
        raise compare.PolicyError(f"{path}: {e}") from e


def _write(path: Optional[str], text: str) -> None:
    if path in (None, "-"):
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


@diff_app.command(
    help=(
        "Compare policies cfn2iam generated with a baseline policy.\n\n"
        "GENERATED are policy files written by cfn2iam (plain, or --format json, which also says which resource "
        "types need each action). Several are combined, as for one role that deploys every template. The baseline "
        "is a policy document (or several, for a role with several policies); wildcards, Deny, NotAction and "
        "NotResource are evaluated, and statements with a Condition or specific resources count as conditional.\n\n"
        "Exit status: 0 when the baseline grants everything the templates need, 3 when it does not (permission "
        "drift), 1 on an error, 2 on a usage error."
    ),
    epilog="Example: cfn2iam template.yaml --format json -o new.json && cfn2iam diff new.json -b baseline.json",
)
def diff(
    generated: List[str] = typer.Argument(..., help="Policy files cfn2iam wrote", metavar="GENERATED..."),
    baseline: Optional[List[str]] = typer.Option(
        None, "-b", "--baseline", help="Baseline policy file; repeat for several. Without one, nothing is compared"
    ),
    conditional: ConditionalMode = typer.Option(
        ConditionalMode.missing,
        "--conditional",
        help="How to count actions the baseline grants only under a Condition or for specific resources",
    ),
    report_format: ReportFormat = typer.Option(ReportFormat.text, "--format", help="Report format"),
    output: Optional[str] = typer.Option(
        None, "-o", "--output", help="Write the report to this file (default: stdout)"
    ),
    write_policy: Optional[str] = typer.Option(
        None,
        "-w",
        "--write-policy",
        help="Also write the combined generated policy to this file, e.g. to create or refresh the baseline",
    ),
):
    try:
        gen = compare.load_generated([(p, _read_json(p)) for p in generated])
        base = compare.load_baseline([(p, _read_json(p)) for p in baseline]) if baseline else None
        report = compare.compare(gen, base, conditional.value)
        if report_format == ReportFormat.json:
            text = json.dumps(report.to_dict(), indent=2) + "\n"
        elif report_format == ReportFormat.markdown:
            text = compare.render_markdown(report)
        else:
            text = compare.render_text(report)
        _write(output, text)
        if write_policy:
            _write(write_policy, json.dumps(compare.combined_policy(gen), indent=2) + "\n")
            print(f"Wrote the combined policy to {write_policy}", file=sys.stderr)
    except (compare.PolicyError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        raise typer.Exit(EXIT_ERROR) from None
    raise typer.Exit(EXIT_DRIFT if report.drift else EXIT_OK)


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point of the ``cfn2iam`` script."""
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] == ["diff"]:
        diff_app(args=args[1:], prog_name="cfn2iam diff")
    elif argv is None:
        app()
    else:
        app(args=args)
