"""The cfn2iam[iam] code paths, with boto3 stubbed so no AWS account is reached.

Skipped unless boto3 is installed (`uv sync --extra iam`); CI runs them in the iam job.
"""

import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import ANY, Stubber  # noqa: E402

from cfn2iam import app as cli  # noqa: E402

SCHEMA = {"handlers": {"create": {"permissions": ["myorg:CreateThing"]}}}


@pytest.fixture(autouse=True)
def no_aws_config(tmp_path, monkeypatch):
    for var in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-credentials"))


def stubbed(monkeypatch, service):
    client = boto3.session.Session().client(
        service, region_name="eu-west-1", aws_access_key_id="testing", aws_secret_access_key="testing"
    )
    monkeypatch.setattr(boto3.session.Session, "client", lambda self, *a, **kw: client)
    monkeypatch.setattr(boto3, "client", lambda *a, **kw: client)
    stubber = Stubber(client)
    stubber.activate()
    return stubber


def test_boto3_is_detected():
    assert cli._has_boto3()


def test_registry_schema(monkeypatch):
    stubber = stubbed(monkeypatch, "cloudformation")
    stubber.add_response(
        "describe_type",
        {"Schema": json.dumps(SCHEMA)},
        {"Type": "RESOURCE", "TypeName": "MyOrg::Private::Thing"},
    )
    assert cli.get_registry_schema("MyOrg::Private::Thing", "eu-west-1") == SCHEMA
    stubber.assert_no_pending_responses()


def test_registry_type_not_found_is_unknown(monkeypatch):
    stubber = stubbed(monkeypatch, "cloudformation")
    stubber.add_client_error("describe_type", service_error_code="TypeNotFoundException")
    with pytest.raises(cli.UnknownResourceType, match="eu-west-1"):
        cli.get_registry_schema("MyOrg::Private::Thing", "eu-west-1")


def test_registry_other_error_is_not_skippable(monkeypatch):
    stubber = stubbed(monkeypatch, "cloudformation")
    stubber.add_client_error("describe_type", service_error_code="AccessDeniedException")
    with pytest.raises(cli.SchemaError) as e:
        cli.get_registry_schema("MyOrg::Private::Thing", "eu-west-1")
    assert not isinstance(e.value, cli.UnknownResourceType)


def test_create_iam_role(monkeypatch):
    stubber = stubbed(monkeypatch, "iam")
    policy = {"Version": "2012-10-17", "Statement": []}
    arn = "arn:aws:iam::123456789012:role/deploy"
    stubber.add_response(
        "create_role",
        {
            "Role": {
                "Path": "/",
                "RoleName": "deploy",
                "RoleId": "AROAEXAMPLEEXAMPLE123",
                "Arn": arn,
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        },
        {
            "RoleName": "deploy",
            "AssumeRolePolicyDocument": ANY,
            "Description": "Role generated using cfn2iam",
            "PermissionsBoundary": "arn:aws:iam::123456789012:policy/boundary",
        },
    )
    stubber.add_response(
        "put_role_policy",
        {},
        {"RoleName": "deploy", "PolicyName": "deploy-Policy", "PolicyDocument": json.dumps(policy)},
    )
    assert cli.create_iam_role(policy, "deploy", "arn:aws:iam::123456789012:policy/boundary") == arn
    stubber.assert_no_pending_responses()
