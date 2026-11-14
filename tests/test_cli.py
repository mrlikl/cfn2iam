"""The CLI's output options (--format, -o) and the cfn2iam diff command."""

import json
import os
import re
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from cfn2iam import app as cli
from cfn2iam import cli as entry

BUCKET = {
    "handlers": {
        "create": {"permissions": ["s3:CreateBucket"]},
        "read": {"permissions": ["s3:GetBucketTagging"]},
        "delete": {"permissions": ["s3:DeleteBucket"]},
    }
}


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has_boto3", lambda: False)

    def fetch(url):
        if url.endswith("schemas/AWS_S3_Bucket.json"):
            return BUCKET
        raise cli.NotFound(url)

    monkeypatch.setattr(cli, "_fetch_json", fetch)


def template(tmp_path, resources=None):
    path = tmp_path / "template.yaml"
    path.write_text(json.dumps({"Resources": resources or {"B": {"Type": "AWS::S3::Bucket"}}}))
    return str(path)


def run(args):
    return CliRunner().invoke(cli.app, args)


def diff(args):
    return CliRunner().invoke(entry.diff_app, args)


EXPECTED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:CreateBucket", "s3:GetBucketTagging"], "Resource": "*"},
        {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
    ],
}


def test_default_still_writes_a_random_file(tmp_path):
    result = run([template(tmp_path)])
    assert result.exit_code == 0, result.output
    [written] = tmp_path.glob("policy-*.json")
    assert json.loads(written.read_text()) == EXPECTED_POLICY
    assert result.stdout == f"Generated IAM Policy Document to {written.name}\n"


def test_output_path(tmp_path):
    result = run([template(tmp_path), "-o", "iam.json"])
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / "iam.json").read_text()) == EXPECTED_POLICY
    assert list(tmp_path.glob("policy-*.json")) == []
    assert "iam.json" in result.stdout


def test_policy_to_stdout(tmp_path):
    result = run([template(tmp_path), "-o", "-"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == EXPECTED_POLICY
    assert list(tmp_path.glob("*.json")) == []


def test_json_format_to_stdout(tmp_path):
    path = template(tmp_path)
    result = run([path, "--format", "json", "-d"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)  # nothing else on stdout
    assert data["template"] == path
    assert data["allow_delete"] is True
    assert data["policy"]["Statement"][1] == {"Effect": "Allow", "Action": ["s3:DeleteBucket"], "Resource": "*"}
    assert data["allow"] == ["s3:CreateBucket", "s3:GetBucketTagging"]
    assert data["delete"] == ["s3:DeleteBucket"]
    assert data["by_type"]["AWS::S3::Bucket"]["allow"] == ["s3:CreateBucket", "s3:GetBucketTagging"]
    assert data["unresolved"] == {}
    assert list(tmp_path.glob("*.json")) == []


def test_json_format_to_a_file_keeps_stdout_empty(tmp_path):
    result = run([template(tmp_path), "--format", "json", "-o", "out.json"])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert "out.json" in result.stderr
    assert json.loads((tmp_path / "out.json").read_text())["policy"] == EXPECTED_POLICY


def test_json_format_failure_writes_nothing_to_stdout(tmp_path):
    result = run([template(tmp_path, {"T": {"Type": "MyOrg::Private::Thing"}}), "--format", "json"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "MyOrg::Private::Thing" in result.stderr


def test_json_format_lists_skipped_types(tmp_path):
    resources = {"B": {"Type": "AWS::S3::Bucket"}, "T": {"Type": "MyOrg::Private::Thing"}}
    result = run([template(tmp_path, resources), "--format", "json", "--ignore-unknown"])
    assert result.exit_code == 0, result.output
    assert list(json.loads(result.stdout)["unresolved"]) == ["MyOrg::Private::Thing"]


def test_empty_template_message_goes_to_stderr_in_json_mode(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("Resources: {}")
    assert run([str(path)]).stdout == "No resource types found in the template.\n"  # unchanged
    result = run([str(path), "--format", "json"])
    assert result.exit_code == 1 and result.stdout == ""


# --- cfn2iam diff ------------------------------------------------------------------


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def test_diff_no_drift(tmp_path):
    gen = write(tmp_path, "gen.json", EXPECTED_POLICY)
    result = diff([gen, "-b", gen])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("No permission changes")


def test_diff_drift_exit_code(tmp_path):
    gen = write(tmp_path, "gen.json", EXPECTED_POLICY)
    base = write(
        tmp_path, "base.json", {"Statement": [{"Effect": "Allow", "Action": "s3:CreateBucket", "Resource": "*"}]}
    )
    result = diff([gen, "--baseline", base])
    assert result.exit_code == entry.EXIT_DRIFT == 3
    assert "s3:GetBucketTagging" in result.stdout


def test_diff_conditional_option(tmp_path):
    gen = write(tmp_path, "gen.json", EXPECTED_POLICY)
    stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": {"Bool": {"aws:ViaAWSService": "true"}}}
    base = write(tmp_path, "base.json", {"Statement": [stmt]})
    assert diff([gen, "-b", base]).exit_code == 3
    assert diff([gen, "-b", base, "--conditional", "granted"]).exit_code == 0


def test_diff_json_and_markdown(tmp_path):
    gen = write(tmp_path, "gen.json", EXPECTED_POLICY)
    base = write(tmp_path, "base.json", {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    data = json.loads(diff([gen, "-b", base, "--format", "json"]).stdout)
    assert data["drift"] is False
    assert data["counts"]["required"] == 2
    assert data["newly_denied"] == [{"action": "s3:DeleteBucket"}]
    result = diff([gen, "-b", base, "--format", "markdown", "-o", "report.md"])
    assert result.exit_code == 0 and result.stdout == ""
    assert (tmp_path / "report.md").read_text().startswith("### cfn2iam permission check")


def test_diff_without_baseline_writes_the_combined_policy(tmp_path):
    a = write(tmp_path, "a.json", EXPECTED_POLICY)
    b = write(tmp_path, "b.json", {"Statement": [{"Effect": "Allow", "Action": ["sqs:CreateQueue"], "Resource": "*"}]})
    result = diff([a, b, "-w", "baseline.json"])
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / "baseline.json").read_text())["Statement"] == [
        {"Effect": "Allow", "Action": ["s3:CreateBucket", "s3:GetBucketTagging", "sqs:CreateQueue"], "Resource": "*"},
        {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
    ]


@pytest.mark.parametrize("problem", ["missing", "invalid json", "not a policy"])
def test_diff_errors_exit_1(tmp_path, problem):
    gen = write(tmp_path, "gen.json", EXPECTED_POLICY)
    base = str(tmp_path / "base.json")
    if problem == "invalid json":
        (tmp_path / "base.json").write_text("{")
    elif problem == "not a policy":
        write(tmp_path, "base.json", {"hello": 1})
    result = diff([gen, "-b", base])
    assert result.exit_code == entry.EXIT_ERROR == 1
    assert result.stderr.startswith("Error: ")


def test_diff_usage_error_exit_2():
    assert diff([]).exit_code == 2


def test_entry_point_dispatch(tmp_path, monkeypatch):
    gen = write(tmp_path, "gen.json", EXPECTED_POLICY)
    with pytest.raises(SystemExit) as raised:
        entry.main(["diff", gen, "-b", gen])
    assert raised.value.code == 0
    with pytest.raises(SystemExit) as raised:
        entry.main([template(tmp_path), "-o", "p.json"])
    assert raised.value.code == 0
    assert json.loads((tmp_path / "p.json").read_text()) == EXPECTED_POLICY


def test_python_dash_m(tmp_path):
    out = subprocess.run([sys.executable, "-m", "cfn2iam", "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.startswith("cfn2iam ")
    # In CI, rich colours the help (GITHUB_ACTIONS forces it), so drop the escape codes.
    env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"}
    env.pop("FORCE_COLOR", None)
    out = subprocess.run([sys.executable, "-m", "cfn2iam", "diff", "--help"], capture_output=True, text=True, env=env)
    assert out.returncode == 0
    assert "--baseline" in re.sub(r"\x1b\[[0-9;]*m", "", out.stdout)
