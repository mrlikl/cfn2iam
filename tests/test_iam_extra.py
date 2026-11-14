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


ROLE = {
    "Role": {
        "Path": "/",
        "RoleName": "deploy",
        "RoleId": "AROAEXAMPLEEXAMPLE123",
        "Arn": "arn:aws:iam::123456789012:role/deploy",
        "CreateDate": "2026-01-01T00:00:00Z",
    }
}


def test_a_role_whose_policy_is_refused_is_deleted_again(monkeypatch, capsys):
    # repro-s3-collapse: PutRolePolicy refused the policy and left an empty role behind.
    stubber = stubbed(monkeypatch, "iam")
    stubber.add_response("create_role", ROLE)
    stubber.add_client_error(
        "put_role_policy", service_error_code="MalformedPolicyDocument", service_message="can not contain region"
    )
    stubber.add_response("delete_role", {}, {"RoleName": "deploy"})
    assert cli.create_iam_role({"Version": "2012-10-17", "Statement": []}, "deploy") is None
    stubber.assert_no_pending_responses()
    err = capsys.readouterr().err
    assert "failed to attach the policy to the new IAM role deploy" in err and "can not contain region" in err
    assert "Deleted the role deploy that this run created" in err


def test_a_role_that_could_not_be_deleted_is_named(monkeypatch, capsys):
    stubber = stubbed(monkeypatch, "iam")
    stubber.add_response("create_role", ROLE)
    stubber.add_client_error("put_role_policy", service_error_code="LimitExceeded")
    stubber.add_client_error("delete_role", service_error_code="AccessDenied")
    assert cli.create_iam_role({"Version": "2012-10-17", "Statement": []}, "deploy") is None
    assert "could not delete the role deploy that this run created" in capsys.readouterr().err


def test_an_existing_role_is_never_deleted(monkeypatch, capsys):
    stubber = stubbed(monkeypatch, "iam")
    stubber.add_client_error("create_role", service_error_code="EntityAlreadyExists")
    assert cli.create_iam_role({"Version": "2012-10-17", "Statement": []}, "deploy") is None
    stubber.assert_no_pending_responses()  # no PutRolePolicy, no DeleteRole
    assert "failed to create IAM role deploy" in capsys.readouterr().err


def test_a_policy_too_large_to_attach_inline_creates_no_role(monkeypatch, capsys):
    stubber = stubbed(monkeypatch, "iam")  # no responses queued: any call would fail the test
    big = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": [f"s3:A{i:05}" for i in range(1200)], "Resource": "*"}],
    }
    assert cli.create_iam_role(big, "deploy") is None
    stubber.assert_no_pending_responses()
    assert "over the 10,240 IAM allows inline on a role, so the role deploy was not created" in capsys.readouterr().err


def test_aws_login_credentials_without_crt_are_explained(tmp_path, monkeypatch):
    from botocore import compat

    if getattr(compat, "HAS_CRT", False):
        pytest.skip("awscrt is installed, so the login provider works")
    config = tmp_path / "login-config"
    config.write_text("[default]\nlogin_session = arn:aws:iam::123456789012:user/someone\nregion = eu-west-1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    problem = cli.aws_credentials_problem()
    assert '"aws login"' in problem and 'pip install "cfn2iam[iam]" "botocore[crt]"' in problem


def test_missing_credentials_are_explained():
    assert cli.aws_credentials_problem().startswith("no AWS credentials found")
