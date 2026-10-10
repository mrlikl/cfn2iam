import json
import urllib.error

import pytest
from typer.testing import CliRunner

from cfn2iam import app as cli

SCHEMA = {
    "handlers": {
        "create": {"permissions": ["s3:CreateBucket", "s3:PutBucketTagging"]},
        "read": {"permissions": ["s3:GetBucketTagging"]},
        "delete": {"permissions": ["s3:DeleteBucket"]},
    }
}

TEMPLATE = {
    "Resources": {
        "Bucket": {"Type": "AWS::S3::Bucket"},
        "Thing": {"Type": "MyOrg::Private::Thing"},
    }
}


def registry_without(resourcetype, region=None):
    raise cli.UnknownResourceType("not in the CloudFormation registry")


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Never reach a real AWS account from tests.
    monkeypatch.setattr(cli, "_has_boto3", lambda: True)
    monkeypatch.setattr(cli, "get_registry_schema", registry_without)
    cli.get_schema_index.cache_clear()
    cli.get_permissions_cached.cache_clear()
    yield
    cli.get_schema_index.cache_clear()
    cli.get_permissions_cached.cache_clear()


def write_template(tmp_path, template):
    path = tmp_path / "template.json"
    path.write_text(json.dumps(template))
    return str(path)


def fake_fetch(responses):
    """responses maps a URL suffix to a dict (returned) or an exception (raised)."""
    def fetch(url):
        for suffix, value in responses.items():
            if url.endswith(suffix):
                if isinstance(value, Exception):
                    raise value
                return value
        raise cli.NotFound(url)
    return fetch


def run(args):
    return CliRunner().invoke(cli.app, args)


def policy_files(tmp_path):
    return list(tmp_path.glob("policy-*.json"))


def test_network_failure_writes_no_policy(tmp_path, monkeypatch):
    def offline(url):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(cli, "_fetch_json", offline)
    result = run([write_template(tmp_path, {"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})])

    assert result.exit_code == 1
    assert "could not resolve permissions" in result.output
    assert "No policy was written" in result.output
    assert policy_files(tmp_path) == []


def test_network_failure_is_not_skippable(tmp_path, monkeypatch):
    def offline(url):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(cli, "_fetch_json", offline)
    result = run([write_template(tmp_path, {"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}), "--ignore-unknown"])

    assert result.exit_code == 1
    assert policy_files(tmp_path) == []


def test_unknown_type_fails_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_fetch_json", fake_fetch({"AWS_S3_Bucket.json": SCHEMA}))
    result = run([write_template(tmp_path, TEMPLATE)])

    assert result.exit_code == 1
    assert "MyOrg::Private::Thing" in result.output
    assert "--ignore-unknown" in result.output
    assert policy_files(tmp_path) == []


def test_unknown_type_can_be_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_fetch_json", fake_fetch({"AWS_S3_Bucket.json": SCHEMA}))
    result = run([write_template(tmp_path, TEMPLATE), "--ignore-unknown"])

    assert result.exit_code == 0
    assert "skipped MyOrg::Private::Thing" in result.output
    [policy_file] = policy_files(tmp_path)
    policy = json.loads(policy_file.read_text())
    assert policy["Statement"] == [
        {"Effect": "Allow", "Action": ["s3:CreateBucket", "s3:GetBucketTagging", "s3:PutBucketTagging"], "Resource": "*"},
        {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"},
    ]


def test_private_type_resolves_from_registry(tmp_path, monkeypatch):
    private = {"handlers": {"create": {"permissions": ["myorg:CreateThing"]}, "delete": {"permissions": ["myorg:DeleteThing"]}}}
    looked_up = []

    def registry(resourcetype, region):
        looked_up.append((resourcetype, region))
        return private

    monkeypatch.setattr(cli, "_fetch_json", fake_fetch({"AWS_S3_Bucket.json": SCHEMA}))
    monkeypatch.setattr(cli, "get_registry_schema", registry)
    result = run([write_template(tmp_path, TEMPLATE), "--region", "eu-west-1"])

    assert result.exit_code == 0
    assert looked_up == [("MyOrg::Private::Thing", "eu-west-1")]  # public types never hit the registry
    [policy_file] = policy_files(tmp_path)
    actions = {a for s in json.loads(policy_file.read_text())["Statement"] for a in s["Action"]}
    assert {"myorg:CreateThing", "myorg:DeleteThing", "s3:CreateBucket"} <= actions


def test_registry_flag_skips_published_schemas(tmp_path, monkeypatch):
    def fetch(url):
        if "/schemas/" in url:
            raise AssertionError(f"published schema fetched in --registry mode: {url}")
        raise cli.NotFound(url)

    monkeypatch.setattr(cli, "_fetch_json", fetch)
    monkeypatch.setattr(cli, "get_registry_schema", lambda resourcetype, region: SCHEMA)
    result = run([write_template(tmp_path, TEMPLATE), "--registry"])

    assert result.exit_code == 0, result.output
    assert len(policy_files(tmp_path)) == 1


def test_sam_rule_fetch_failure_is_reported(tmp_path, monkeypatch):
    def fetch(url):
        if "/sam_rules/" in url:
            raise urllib.error.URLError("connection refused")
        raise cli.NotFound(url)

    monkeypatch.setattr(cli, "_fetch_json", fetch)
    result = run([write_template(tmp_path, {"Resources": {"Fn": {"Type": "AWS::Serverless::Function"}}})])

    assert result.exit_code == 1
    assert "AWS::Serverless::Function" in result.output
    assert policy_files(tmp_path) == []


def test_unsupported_sam_condition_is_an_error(tmp_path, monkeypatch):
    rule = {
        "base_resources": ["AWS::Lambda::Function"],
        "conditional_resources": [
            {"condition": {"path": "properties.Events", "op": "no_such_op"}, "resources": ["AWS::SQS::Queue"]}
        ],
    }
    monkeypatch.setattr(cli, "_fetch_json", fake_fetch({"AWS_Serverless_Function.json": rule}))
    result = run([write_template(tmp_path, {"Resources": {"Fn": {"Type": "AWS::Serverless::Function"}}})])

    assert result.exit_code == 1
    assert "unsupported op" in result.output
    assert policy_files(tmp_path) == []
