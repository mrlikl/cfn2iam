"""The CLI's --account, --region and --partition options, with the backend faked."""

import json
import urllib.error

import pytest
from scoping_data import BACKEND
from typer.testing import CliRunner

from cfn2iam import app as cli

ACCOUNT = "123456789012"
TEMPLATE = {"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}, "Queue": {"Type": "AWS::SQS::Queue"}}}


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_has_boto3", lambda: True)

    def no_registry(resourcetype, region=None):
        raise cli.UnknownResourceType("not in the CloudFormation registry")

    monkeypatch.setattr(cli, "get_registry_schema", no_registry)


@pytest.fixture
def fetched(monkeypatch):
    """Serve scoping_data.BACKEND; returns the list of backend paths fetched."""
    paths = []

    def fetch(url):
        path = url.removeprefix(cli.SCHEMA_BASE_URL + "/")
        paths.append(path)
        if path not in BACKEND:
            raise cli.NotFound(url)
        return json.loads(json.dumps(BACKEND[path]))

    monkeypatch.setattr(cli, "_fetch_json", fetch)
    return paths


def run(tmp_path, *args):
    path = tmp_path / "template.json"
    path.write_text(json.dumps(TEMPLATE))
    return CliRunner().invoke(cli.app, [str(path), *args])


def written_policy(tmp_path):
    [policy_file] = list(tmp_path.glob("policy-*.json"))
    return json.loads(policy_file.read_text())


def test_account_and_region_scope_the_policy(tmp_path, fetched):
    result = run(tmp_path, "--account", ACCOUNT, "--region", "us-west-2")

    assert result.exit_code == 0, result.output
    statements = written_policy(tmp_path)["Statement"]
    assert {"Effect": "Allow", "Action": ["sqs:CreateQueue"], "Resource": f"arn:aws:sqs:us-west-2:{ACCOUNT}:*"} in (
        statements
    )
    assert statements[-1] == {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"}
    # The summary goes to stderr, like the other notes; stdout keeps its one line.
    assert result.stdout.startswith("Generated IAM Policy Document to policy-")
    assert f"Scoped 3 of 6 actions to account {ACCOUNT}, region us-west-2 (partition aws)" in result.stderr
    assert "2 with no resource-level permissions" in result.stderr
    assert "1 delete-only, denied on every resource" in result.stderr


def test_account_without_region_is_any_region(tmp_path, fetched):
    result = run(tmp_path, "--account", ACCOUNT)

    assert result.exit_code == 0, result.output
    assert "any region" in result.stderr
    resources = [s["Resource"] for s in written_policy(tmp_path)["Statement"]]
    assert f"arn:aws:sqs:*:{ACCOUNT}:*" in resources


def test_region_alone_does_not_scope(tmp_path, fetched):
    result = run(tmp_path, "--region", "eu-west-1")

    assert result.exit_code == 0, result.output
    assert all(s["Resource"] == "*" for s in written_policy(tmp_path)["Statement"])
    assert not any(p.startswith("servicereference/") for p in fetched)
    assert "Scoped" not in result.output


def test_partition(tmp_path, fetched):
    result = run(tmp_path, "--account", ACCOUNT, "--region", "cn-north-1", "--partition", "aws-cn")

    assert result.exit_code == 0, result.output
    resources = [s["Resource"] for s in written_policy(tmp_path)["Statement"]]
    assert f"arn:aws-cn:sqs:cn-north-1:{ACCOUNT}:*" in resources


@pytest.mark.parametrize(
    "args,message",
    [
        (["--account", "1234"], "12-digit"),
        (["--account", ACCOUNT, "--partition", "aws-moon"], "unknown partition"),
        (["--account", ACCOUNT, "--region", "cn-north-1"], "partition aws-cn"),
        (["--partition", "aws-cn"], "needs an account"),
    ],
)
def test_invalid_options_fail_before_fetching(tmp_path, fetched, args, message):
    result = run(tmp_path, *args)

    assert result.exit_code == 1
    assert message in result.stderr
    assert fetched == []
    assert list(tmp_path.glob("policy-*.json")) == []


def test_unreachable_reference_writes_no_policy(tmp_path, monkeypatch):
    def fetch(url):
        path = url.removeprefix(cli.SCHEMA_BASE_URL + "/")
        if path.startswith("servicereference/"):
            raise urllib.error.URLError("connection refused")
        if path not in BACKEND:
            raise cli.NotFound(url)
        return BACKEND[path]

    monkeypatch.setattr(cli, "_fetch_json", fetch)
    result = run(tmp_path, "--account", ACCOUNT)

    assert result.exit_code == 1
    assert "could not fetch servicereference/" in result.stderr
    assert "No policy was written" in result.stderr
    assert list(tmp_path.glob("policy-*.json")) == []


def test_create_role_uses_the_scoped_policy(tmp_path, fetched, monkeypatch):
    created = {}

    def create_iam_role(policy_document, role_name, permissions_boundary=None):
        created.update(policy=policy_document, name=role_name)
        return f"arn:aws:iam::{ACCOUNT}:role/{role_name}"

    monkeypatch.setattr(cli, "create_iam_role", create_iam_role)
    monkeypatch.setattr(cli, "aws_credentials_problem", lambda: None)
    result = run(tmp_path, "--account", ACCOUNT, "--region", "us-east-1", "-c", "-r", "deploy")

    assert result.exit_code == 0, result.output
    assert created["name"] == "deploy"
    assert created["policy"] == written_policy(tmp_path)
    assert any(
        isinstance(s["Resource"], str) and s["Resource"].startswith("arn:") for s in created["policy"]["Statement"]
    )
    assert f"Successfully created IAM role: arn:aws:iam::{ACCOUNT}:role/deploy" in result.stdout
