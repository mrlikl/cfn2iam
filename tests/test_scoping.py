"""Resource scoping in cfn2iam.core, against the small reference in scoping_data."""

import asyncio
import json

import pytest
from scoping_data import BACKEND, LAMBDA, SQS, action, backend, schema, service, template

from cfn2iam import core

ACCOUNT = "123456789012"


def scope(region="us-east-1", partition="aws", account=ACCOUNT):
    return core.make_scope(account, region, partition)


def analyze(text, fetch=None, **kwargs):
    return asyncio.run(core.analyze_template(text, fetch or backend(), **kwargs))


def statements(analysis):
    return analysis.policy["Statement"]


def statement_for(analysis, action):
    [found] = [s for s in statements(analysis) if action in s["Action"]]
    return found


def resources(statement):
    r = statement["Resource"]
    return [r] if isinstance(r, str) else r


# --- Filling ARN formats ---------------------------------------------------------


@pytest.mark.parametrize(
    "arn_format,expected",
    [
        # S3 buckets and objects have no region or account: nothing to fill but the partition.
        ("arn:${Partition}:s3:::${BucketName}", "arn:aws:s3:::*"),
        ("arn:${Partition}:s3:::${BucketName}/${ObjectName}", "arn:aws:s3:::*/*"),
        # IAM is global: the account only.
        ("arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}", f"arn:aws:iam::{ACCOUNT}:role/*"),
        ("arn:${Partition}:sqs:${Region}:${Account}:${QueueName}", f"arn:aws:sqs:us-east-1:{ACCOUNT}:*"),
        (
            "arn:${Partition}:chime:${Region}:${AccountId}:meeting/${MeetingId}",
            f"arn:aws:chime:us-east-1:{ACCOUNT}:meeting/*",
        ),
        # Accounts that need not be the deploying one become "*".
        (
            "arn:${Partition}:account::${ManagementAccountId}:account/o-${OrganizationId}/${MemberAccountId}",
            "arn:aws:account::*:account/o-*/*",
        ),
        (
            "arn:${Partition}:kafka:${Region}:${VpcOwnerAccount}:vpc-connection/${ClusterOwnerAccount}/${ClusterName}/${Uuid}",
            "arn:aws:kafka:us-east-1:*:vpc-connection/*/*/*",
        ),
        # ${AccountId} in the resource part is someone else's account.
        (
            "arn:${Partition}:organizations::${Account}:account/o-${OrganizationId}/${AccountId}",
            f"arn:aws:organizations::{ACCOUNT}:account/o-*/*",
        ),
        # Literal segments are left alone.
        ("arn:${Partition}:iam::aws:role-template/${A}/${B}:${C}", "arn:aws:iam::aws:role-template/*/*:*"),
        (
            "arn:${Partition}:s3:us-west-2:${Account}:async-request/mrap/${Op}/${T}",
            f"arn:aws:s3:us-west-2:{ACCOUNT}:async-request/mrap/*/*",
        ),
        ("arn:${Partition}:braket:*:*:device/${DeviceType}/${Provider}/${DeviceId}", "arn:aws:braket:*:*:device/*/*/*"),
        ("arn:${Partition}:health:*::event/${Service}/${EventTypeCode}/*", "arn:aws:health:*::event/*/*/*"),
        # Adjacent placeholders make one wildcard.
        ("arn:${Partition}:x:${Region}:${Account}:a/${B}${C}", f"arn:aws:x:us-east-1:{ACCOUNT}:a/*"),
    ],
)
def test_fill_arn(arn_format, expected):
    assert core.fill_arn(arn_format, scope()) == expected


@pytest.mark.parametrize(
    "arn_format",
    [
        "arn:${Partition}:${Vendor}:${Region}:*:${ResourceType}:${RecoveryPointId}",  # no wildcard service in IAM
        "arn:${Partition}:s3:::",  # no resource
        "arn:${Partition}:s3",  # not six parts
        "not-an-arn:${Partition}:s3:::${BucketName}",
    ],
)
def test_unfillable_arn_formats(arn_format):
    assert core.fill_arn(arn_format, scope()) is None


def test_no_region_means_any_region():
    assert core.fill_arn("arn:${Partition}:sqs:${Region}:${Account}:${QueueName}", scope(region=None)) == (
        f"arn:aws:sqs:*:{ACCOUNT}:*"
    )


def test_other_partition():
    s = scope("cn-north-1", "aws-cn")
    assert core.fill_arn("arn:${Partition}:sqs:${Region}:${Account}:${QueueName}", s) == (
        f"arn:aws-cn:sqs:cn-north-1:{ACCOUNT}:*"
    )
    assert core.fill_arn("arn:${Partition}:s3:::${BucketName}", s) == "arn:aws-cn:s3:::*"


def test_widened_segments():
    f = "arn:${Partition}:lambda:${Region}:${Account}:layer:${LayerName}:${LayerVersion}"
    assert core.fill_arn(f, scope(), any_account=True) == "arn:aws:lambda:us-east-1:*:layer:*:*"
    assert core.fill_arn(f, scope(), any_region=True) == f"arn:aws:lambda:*:{ACCOUNT}:layer:*:*"


# --- Reducing resource lists ---------------------------------------------------------


@pytest.mark.parametrize(
    "a,b,covers",
    [
        ("arn:aws:s3:::*", "arn:aws:s3:::*/*", True),
        ("arn:aws:logs:r:1:log-group:*", "arn:aws:logs:r:1:log-group:*:log-stream:*", True),
        ("arn:aws:lambda:*:1:*", "arn:aws:lambda:us-east-1:1:function:*", True),
        ("arn:aws:lambda:r:1:*", "arn:aws:lambda:r:*:layer:*:*", False),  # one account doesn't cover any
        ("arn:aws:ec2:r:1:*", "arn:aws:ec2:r::image/*", False),  # an empty segment isn't assumed matched
        ("arn:aws:x:r:1:a*b", "arn:aws:x:r:1:a:c:b", False),  # only a trailing * counts
        ("arn:aws:s3:::*/*", "arn:aws:s3:::*", False),
        ("arn:aws:sqs:r:1:*", "arn:aws:sns:r:1:*", False),
    ],
)
def test_covers(a, b, covers):
    assert core._covers(a, b) is covers


def always(base):
    return True


def test_reduce_drops_covered_and_collapses_long_runs():
    assert core._reduce_arns({"arn:aws:s3:::*", "arn:aws:s3:::*/*"}, always) == ["arn:aws:s3:::*"]
    many = {f"arn:aws:ec2:r:1:t{i}/*" for i in range(core.COLLAPSE_AT + 1)} | {"arn:aws:ec2:r::image/*"}
    assert core._reduce_arns(many, always) == ["arn:aws:ec2:r:1:*", "arn:aws:ec2:r::image/*"]
    assert core._reduce_arns(many, lambda base: False) == sorted(many)
    few = {f"arn:aws:ec2:r:1:t{i}/*" for i in range(core.COLLAPSE_AT)}
    assert core._reduce_arns(few, always) == sorted(few)


# repro-s3-collapse: s3:TagResource and s3:ListTagsForResource act on five regional S3 resource types besides
# buckets. 0.4.0 collapsed them to arn:aws:s3:<region>:<account>:*, which IAM rejects ("Resource
# arn:aws:s3:ap-south-1:123456789012:* can not contain region information"): an S3 resource with no type
# prefix is a bucket, and bucket ARNs have no region or account. The ARN formats are the published ones.
S3_TAGGING = service(
    "s3",
    [
        action("CreateBucket", "bucket"),
        action("DeleteBucket", "bucket"),
        action(
            "TagResource",
            "accessgrant",
            "accessgrantsinstance",
            "accessgrantslocation",
            "accesspoint",
            "bucket",
            "storagelensgroup",
        ),
    ],
    {
        "bucket": ["arn:${Partition}:s3:::${BucketName}"],
        "accessgrant": ["arn:${Partition}:s3:${Region}:${Account}:access-grants/default/grant/${Token}"],
        "accessgrantsinstance": ["arn:${Partition}:s3:${Region}:${Account}:access-grants/default"],
        "accessgrantslocation": ["arn:${Partition}:s3:${Region}:${Account}:access-grants/default/location/${Token}"],
        "accesspoint": ["arn:${Partition}:s3:${Region}:${Account}:accesspoint/${AccessPointName}"],
        "storagelensgroup": ["arn:${Partition}:s3:${Region}:${Account}:storage-lens-group/${Name}"],
    },
)
S3_REGIONAL = [
    "access-grants/default",
    "access-grants/default/grant/*",
    "access-grants/default/location/*",
    "accesspoint/*",
    "storage-lens-group/*",
]


@pytest.mark.parametrize("region", ["ap-south-1", None])
def test_s3_resources_are_never_collapsed_to_a_bucket_arn_with_a_region(region):
    files = dict(BACKEND)
    files["servicereference/s3.json"] = S3_TAGGING
    files["schemas/AWS_S3_Bucket.json"] = schema(["s3:CreateBucket", "s3:TagResource"], ["s3:DeleteBucket"])
    result = analyze(template("AWS::S3::Bucket"), backend(files), account=ACCOUNT, region=region)
    tag = statement_for(result, "s3:TagResource")
    where = f"{region or '*'}:{ACCOUNT}"
    assert resources(tag) == sorted(["arn:aws:s3:::*"] + [f"arn:aws:s3:{where}:{r}" for r in S3_REGIONAL])
    arns = [a for s in statements(result) for a in resources(s)]
    assert f"arn:aws:s3:{where}:*" not in arns
    assert not any(a.startswith("arn:aws:s3:") and a.split(":", 5)[5] == "*" and a.split(":")[3] for a in arns)


def test_lambda_types_are_still_collapsed():
    # Lambda has no resource type without a prefix, so its many types collapse; IAM accepted that pattern.
    files = dict(BACKEND)
    many = {f"t{i}": [f"arn:${{Partition}}:lambda:${{Region}}:${{Account}}:t{i}:${{Name}}"] for i in range(7)}
    files["servicereference/lambda.json"] = service("lambda", [action("TagResource", *many)], many)
    files["schemas/AWS_Lambda_Function.json"] = schema(["lambda:TagResource"])
    result = analyze(template("AWS::Lambda::Function"), backend(files), account=ACCOUNT, region="us-east-1")
    assert statement_for(result, "lambda:TagResource")["Resource"] == f"arn:aws:lambda:us-east-1:{ACCOUNT}:*"


def test_collapsible_reads_the_prefixless_resource_type():
    reference = core._ServiceReference(None)
    reference.services = {"s3": S3_TAGGING, "sqs": SQS, "lambda": LAMBDA}
    assert not reference.collapsible(f"arn:aws:s3:us-east-1:{ACCOUNT}")
    assert not reference.collapsible(f"arn:aws:s3:*:{ACCOUNT}")
    assert not reference.collapsible(f"arn:aws:s3::{ACCOUNT}")
    assert reference.collapsible("arn:aws:s3::")  # the bucket's own shape: arn:aws:s3:::* is a valid pattern
    assert reference.collapsible(f"arn:aws:sqs:us-east-1:{ACCOUNT}")  # a queue name has region and account
    assert reference.collapsible(f"arn:aws:lambda:us-east-1:{ACCOUNT}")  # no prefix-less type
    assert not reference.collapsible(f"arn:aws:license-manager:us-east-1:{ACCOUNT}")  # its formats aren't loaded


# --- Actions that stay on "*" despite the reference ------------------------------------------


def test_event_source_mapping_lookups_stay_on_every_resource():
    # repro-esm-delete: a scoped -d policy could not delete an AWS::Lambda::EventSourceMapping: "not authorized to
    # perform: lambda:GetEventSourceMapping on resource: *", then lambda:DeleteEventSourceMapping on "*".
    files = dict(BACKEND)
    esm = "eventSourceMapping"
    files["servicereference/lambda.json"] = service(
        "lambda",
        [
            action("CreateEventSourceMapping"),
            action("GetEventSourceMapping", esm),
            action("DeleteEventSourceMapping", esm),
            action("UpdateEventSourceMapping", esm),
        ],
        {esm: ["arn:${Partition}:lambda:${Region}:${Account}:event-source-mapping:${UUID}"]},
    )
    files["schemas/AWS_Lambda_EventSourceMapping.json"] = schema(
        ["lambda:CreateEventSourceMapping", "lambda:GetEventSourceMapping", "lambda:UpdateEventSourceMapping"],
        ["lambda:DeleteEventSourceMapping"],
    )
    result = analyze(
        template("AWS::Lambda::EventSourceMapping"),
        backend(files),
        account=ACCOUNT,
        region="ap-south-1",
        allow_delete=True,
    )
    assert statements(result)[0] == {
        "Effect": "Allow",
        "Action": [
            "lambda:CreateEventSourceMapping",
            "lambda:DeleteEventSourceMapping",
            "lambda:GetEventSourceMapping",
        ],
        "Resource": "*",
    }
    assert statement_for(result, "lambda:UpdateEventSourceMapping")["Resource"] == (
        f"arn:aws:lambda:ap-south-1:{ACCOUNT}:event-source-mapping:*"
    )
    assert result.scoping["unscoped"] == {
        "authorized_on_star": ["lambda:DeleteEventSourceMapping", "lambda:GetEventSourceMapping"],
        "no_resource_types": ["lambda:CreateEventSourceMapping"],
    }
    assert "authorized_on_star" in core.UNSCOPED_REASONS


def test_actions_on_star_are_documented():
    for action_name, reason in core.ACTIONS_ON_STAR.items():
        assert action_name == action_name.lower() and action_name.count(":") == 1
        assert "*" in reason and len(reason) > 40


# --- Transforms ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "region, partition, expected",
    [
        ("ap-south-1", "aws", "arn:aws:cloudformation:ap-south-1:aws:transform/Serverless-2016-10-31"),
        (None, "aws", "arn:aws:cloudformation:*:aws:transform/Serverless-2016-10-31"),
        ("cn-north-1", "aws-cn", "arn:aws-cn:cloudformation:cn-north-1:aws:transform/Serverless-2016-10-31"),
    ],
)
def test_scoped_transform_keeps_the_aws_account(region, partition, expected):
    text = json.dumps({"Transform": "AWS::Serverless-2016-10-31", "Resources": {"Q": {"Type": "AWS::SQS::Queue"}}})
    result = analyze(text, account=ACCOUNT, region=region, partition=partition)
    assert statement_for(result, "cloudformation:CreateChangeSet") == {
        "Effect": "Allow",
        "Action": ["cloudformation:CreateChangeSet"],
        "Resource": expected,
    }
    assert result.transforms[0]["resources"] == [expected]
    assert result.scoping["scoped_count"] == 2


def test_scoped_macro_is_in_the_account():
    text = json.dumps({"Transform": "MyMacro", "Resources": {"Q": {"Type": "AWS::SQS::Queue"}}})
    result = analyze(text, account=ACCOUNT, region="us-east-1")
    assert statement_for(result, "cloudformation:CreateChangeSet")["Resource"] == (
        f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:transform/MyMacro"
    )


# --- Validating the scope ---------------------------------------------------------


def test_scoping_is_off_without_an_account():
    assert core.make_scope() is None
    assert core.make_scope(None, None, "aws") is None
    # What a web form sends when the fields are left empty.
    assert core.make_scope("", " ", "") is None
    assert core.make_scope(ACCOUNT, "", None) == core.Scope(ACCOUNT, None, "aws")


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"account": "12345678901"}, "12-digit"),
        ({"account": "12345678901a"}, "12-digit"),
        ({"account": "1234-5678-9012"}, "12-digit"),
        ({"account": ACCOUNT, "partition": "aws-moon"}, "unknown partition"),
        ({"account": ACCOUNT, "region": "us_east_1"}, "not an AWS region"),
        ({"account": ACCOUNT, "region": "cn-north-1"}, "partition aws-cn"),
        ({"account": ACCOUNT, "region": "us-east-1", "partition": "aws-us-gov"}, "partition aws, not aws-us-gov"),
        ({"region": "us-east-1"}, "needs an account"),
        ({"partition": "aws-cn"}, "needs an account"),
    ],
)
def test_invalid_scope(kwargs, message):
    with pytest.raises(core.ScopeError, match=message):
        core.make_scope(**kwargs)


def test_valid_scopes():
    assert core.make_scope(f" {ACCOUNT} ", "us-gov-west-1", "aws-us-gov") == core.Scope(
        ACCOUNT, "us-gov-west-1", "aws-us-gov"
    )
    assert core.make_scope(ACCOUNT, "eusc-de-east-1", "aws-eusc").partition == "aws-eusc"
    # A region of a shape no partition knows yet is let through, for new regions.
    assert core.make_scope(ACCOUNT, "zz-newplace-1").region == "zz-newplace-1"


def test_analyze_validates_before_fetching_anything():
    fetch = backend()
    with pytest.raises(core.ScopeError):
        analyze(template("AWS::S3::Bucket"), fetch, account="123")
    with pytest.raises(core.ScopeError):
        analyze(template("AWS::S3::Bucket"), fetch, region="us-east-1")
    assert fetch.fetched == []


# --- Unscoped output is unchanged ------------------------------------------------------


UNSCOPED_BUCKET_AND_ROLE = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:CreateRole", "iam:ListRoles",'
    ' "iam:PassRole", "s3:CreateBucket", "s3:GetObject", "s3:ListAllMyBuckets"], "Resource": "*"},'
    ' {"Effect": "Deny", "Action": ["iam:DeleteRole", "s3:DeleteBucket"], "Resource": "*"}]}'
)


@pytest.mark.parametrize("kwargs", [{}, {"account": None}, {"account": None, "partition": "aws"}])
def test_without_an_account_the_policy_is_byte_for_byte_unscoped(kwargs):
    fetch = backend()
    result = analyze(template("AWS::S3::Bucket", "AWS::IAM::Role"), fetch, **kwargs)
    assert json.dumps(result.policy) == UNSCOPED_BUCKET_AND_ROLE
    assert json.dumps(result.policy, indent=2) == json.dumps(json.loads(UNSCOPED_BUCKET_AND_ROLE), indent=2)
    assert result.policy == core.generate_policy_document(result.allow, result.delete)
    assert not any(p.startswith("servicereference/") for p in fetch.fetched)
    assert result.scoping is None and result.to_dict()["scoping"] is None


# --- Scoped policies --------------------------------------------------------------------


def test_scoped_policy():
    result = analyze(
        template("AWS::S3::Bucket", "AWS::IAM::Role", "AWS::SQS::Queue", "AWS::Lambda::Function"),
        account=ACCOUNT,
        region="us-east-1",
    )
    assert statements(result) == [
        {
            "Effect": "Allow",
            "Action": ["iam:ListRoles", "s3:ListAllMyBuckets", "sqs:ListQueues"],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": ["iam:CreateRole", "iam:PassRole"], "Resource": f"arn:aws:iam::{ACCOUNT}:role/*"},
        {
            "Effect": "Allow",
            "Action": ["lambda:CreateFunction", "lambda:TagResource"],
            "Resource": [
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:code-signing-config:*",
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:event-source-mapping:*",
                f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:*",
            ],
        },
        # Layers are often published from other accounts, so this one is kept apart.
        {"Effect": "Allow", "Action": ["lambda:GetLayerVersion"], "Resource": "arn:aws:lambda:us-east-1:*:layer:*:*"},
        {
            "Effect": "Allow",
            "Action": ["s3:CreateBucket", "s3:GetObject"],
            "Resource": ["arn:aws:s3:::*", f"arn:aws:s3:us-east-1:{ACCOUNT}:accesspoint/*/object/*"],
        },
        {"Effect": "Allow", "Action": ["sqs:CreateQueue"], "Resource": f"arn:aws:sqs:us-east-1:{ACCOUNT}:*"},
        {
            "Effect": "Deny",
            "Action": ["iam:DeleteRole", "lambda:DeleteFunction", "s3:DeleteBucket"],
            "Resource": "*",
        },
    ]
    assert result.scoping == {
        "account": ACCOUNT,
        "region": "us-east-1",
        "partition": "aws",
        "scoped_count": 8,
        "unscoped_count": 6,
        "unscoped": {
            "deny": ["iam:DeleteRole", "lambda:DeleteFunction", "s3:DeleteBucket"],
            "no_resource_types": ["iam:ListRoles", "s3:ListAllMyBuckets", "sqs:ListQueues"],
        },
        "widened": ["lambda:GetLayerVersion"],
    }
    # Analysis.allow and .delete are the same as unscoped: scoping changes only Resource.
    unscoped = analyze(template("AWS::S3::Bucket", "AWS::IAM::Role", "AWS::SQS::Queue", "AWS::Lambda::Function"))
    assert (result.allow, result.delete) == (unscoped.allow, unscoped.delete)


def test_the_deny_stays_on_every_resource_and_allow_delete_scopes_it():
    denied = analyze(template("AWS::S3::Bucket"), account=ACCOUNT)
    assert statements(denied)[-1] == {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"}
    allowed = analyze(template("AWS::S3::Bucket"), account=ACCOUNT, allow_delete=True)
    assert all(s["Effect"] == "Allow" for s in statements(allowed))
    assert statement_for(allowed, "s3:DeleteBucket")["Resource"] == [
        f"arn:aws:s3:*:{ACCOUNT}:accesspoint/*/object/*",
        "arn:aws:s3:::*",
    ]
    assert "deny" not in allowed.scoping["unscoped"]


def test_iam_and_s3_have_no_region_even_when_one_is_given():
    result = analyze(template("AWS::S3::Bucket", "AWS::IAM::Role"), account=ACCOUNT, region="eu-west-1")
    assert statement_for(result, "iam:PassRole")["Resource"] == f"arn:aws:iam::{ACCOUNT}:role/*"
    assert "arn:aws:s3:::*" in resources(statement_for(result, "s3:CreateBucket"))


def test_no_region_given():
    result = analyze(template("AWS::SQS::Queue", "AWS::Logs::LogGroup"), account=ACCOUNT)
    assert statement_for(result, "sqs:CreateQueue")["Resource"] == f"arn:aws:sqs:*:{ACCOUNT}:*"
    # The log-group pattern covers the log-stream one, so one statement for logs.
    logs = statement_for(result, "logs:PutLogEvents")
    assert logs == {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:*:{ACCOUNT}:log-group:*",
    }
    assert result.scoping["region"] is None


def test_non_default_partition():
    result = analyze(
        template("AWS::S3::Bucket", "AWS::IAM::Role"), account=ACCOUNT, region="cn-northwest-1", partition="aws-cn"
    )
    arns = [a for s in statements(result) if s["Resource"] != "*" for a in resources(s)]
    assert arns and all(a.startswith("arn:aws-cn:") for a in arns)
    assert f"arn:aws-cn:iam::{ACCOUNT}:role/*" in arns


def test_an_action_with_many_resource_types_is_allowed_on_all_of_them():
    result = analyze(template("AWS::EC2::Instance"), account=ACCOUNT, region="us-east-1")
    run = statement_for(result, "ec2:RunInstances")
    assert run["Resource"] == [
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:*",  # six ec2 types collapsed
        "arn:aws:ec2:us-east-1::image/*",  # AMIs: no account, so public and shared images work
        f"arn:aws:license-manager:us-east-1:{ACCOUNT}:license-configuration:*",
    ]
    assert "ec2:DescribeInstances" in statement_for(result, "ec2:DescribeInstances")["Action"]
    assert statement_for(result, "ec2:DescribeInstances")["Resource"] == "*"


def test_what_stays_on_every_resource_and_why():
    fetch = backend()
    result = analyze(template("AWS::Odd::Thing", "AWS::SageMaker::Domain"), fetch, account=ACCOUNT)
    assert result.scoping["unscoped"] == {
        "invalid_action": [""],
        "unknown_action": ["s3:HeadObject"],
        "unknown_service": ["efs:CreateFileSystem", "sagemaker:CreateDomain"],
        "unscopable_arn": ["backup:TagResource"],  # one of its types has ${Vendor} as the service
        "wildcard": ["ec2:Describe*", "s3:*"],
    }
    assert result.scoping["scoped_count"] == 0
    [statement] = statements(result)
    assert statement["Resource"] == "*" and len(statement["Action"]) == 7  # no action is dropped
    # Known schema mistakes are not aliased (IAM would ignore the action anyway) but reported.
    assert any("efs:CreateFileSystem" in w and "elasticfilesystem:CreateFileSystem" in w for w in result.warnings)
    assert "servicereference/elasticfilesystem.json" not in fetch.fetched


def test_mixed_case_actions_are_looked_up_case_insensitively():
    files = dict(BACKEND)
    files["schemas/AWS_SQS_Queue.json"] = {"handlers": {"create": {"permissions": ["SQS:createQUEUE"]}}}
    result = analyze(template("AWS::SQS::Queue"), backend(files), account=ACCOUNT)
    assert statements(result) == [
        {"Effect": "Allow", "Action": ["SQS:createQUEUE"], "Resource": f"arn:aws:sqs:*:{ACCOUNT}:*"}
    ]


def test_cross_region_types_keep_any_region_and_are_kept_apart():
    result = analyze(
        template("AWS::DynamoDB::GlobalTable", "AWS::DynamoDB::Table"), account=ACCOUNT, region="us-east-1"
    )
    # CreateTable is needed by both types; the global table's replicas are in other regions.
    replica = statement_for(result, "dynamodb:CreateTableReplica")
    assert replica["Resource"] == f"arn:aws:dynamodb:*:{ACCOUNT}:table/*"
    assert "dynamodb:CreateTable" in replica["Action"]
    stream = statement_for(result, "dynamodb:DescribeStream")
    assert stream["Resource"] == f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/*/stream/*"
    assert result.scoping["widened"] == ["dynamodb:CreateTable", "dynamodb:CreateTableReplica"]


def test_lookup_of_one_type_can_be_scoped():
    result = asyncio.run(core.analyze_resource_type("AWS::SQS::Queue", backend(), account=ACCOUNT, region="eu-west-1"))
    assert statement_for(result, "sqs:CreateQueue")["Resource"] == f"arn:aws:sqs:eu-west-1:{ACCOUNT}:*"


# --- Fetching ----------------------------------------------------------------------------


def test_only_the_services_needed_are_fetched_once_each():
    fetch = backend()
    analyze(template("AWS::S3::Bucket", "AWS::IAM::Role", "AWS::Lambda::Function"), fetch, account=ACCOUNT)
    reference = [p for p in fetch.fetched if p.startswith("servicereference/")]
    assert sorted(reference) == [
        "servicereference/iam.json",
        "servicereference/index.json",
        "servicereference/lambda.json",
        "servicereference/s3.json",
    ]


def test_async_fetch():
    async def fetch(path):
        await asyncio.sleep(0)
        if path not in BACKEND:
            raise core.NotFound(path)
        return BACKEND[path]

    result = analyze(template("AWS::SQS::Queue"), fetch, account=ACCOUNT)
    assert result.scoping["scoped_count"] == 1


def test_a_template_without_resources_fetches_nothing():
    fetch = backend()
    result = analyze('{"Resources": {}}', fetch, account=ACCOUNT)
    assert fetch.fetched == [] and statements(result) == [] and result.scoping["scoped_count"] == 0


@pytest.mark.parametrize("path", ["servicereference/index.json", "servicereference/s3.json"])
def test_unreachable_reference_is_an_error_not_a_silent_star(path):
    with pytest.raises(core.ServiceReferenceError, match="could not fetch"):
        analyze(template("AWS::S3::Bucket"), backend(fail={path}), account=ACCOUNT)


def test_missing_reference_is_an_error():
    files = {k: v for k, v in BACKEND.items() if not k.startswith("servicereference/")}
    with pytest.raises(core.ServiceReferenceError, match="has no servicereference/index.json"):
        analyze(template("AWS::S3::Bucket"), backend(files), account=ACCOUNT)


def test_a_service_missing_from_the_index_is_an_unknown_prefix_not_an_error():
    files = dict(BACKEND)
    files["servicereference/index.json"] = {"services": {"iam": {"filename": "iam.json"}}}
    result = analyze(template("AWS::S3::Bucket", "AWS::IAM::Role"), backend(files), account=ACCOUNT)
    assert result.scoping["unscoped"]["unknown_service"] == ["s3:CreateBucket", "s3:GetObject", "s3:ListAllMyBuckets"]
    assert statement_for(result, "iam:PassRole")["Resource"] == f"arn:aws:iam::{ACCOUNT}:role/*"


def test_unreachable_schema_is_still_a_per_type_failure_with_scoping():
    result = analyze(
        template("AWS::S3::Bucket", "AWS::SQS::Queue"), backend(fail={"schemas/AWS_S3_Bucket.json"}), account=ACCOUNT
    )
    assert type(result.failures["AWS::S3::Bucket"]) is core.SchemaError
    assert result.scoping["scoped_count"] == 1


# --- Size -----------------------------------------------------------------------------------


def test_policy_size_ignores_whitespace():
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["a:B"], "Resource": "*"}]}
    assert core.policy_size(policy) == len(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["a:B"],"Resource":"*"}]}'
    )


@pytest.mark.parametrize("kwargs", [{}, {"account": ACCOUNT}])
def test_size_warning(kwargs):
    files = dict(BACKEND)
    files["schemas/AWS_SQS_Queue.json"] = {
        "handlers": {"create": {"permissions": [f"sqs:SomeRatherLongActionName{i:04}" for i in range(250)]}}
    }
    result = analyze(template("AWS::SQS::Queue"), backend(files), **kwargs)
    assert 6144 < result.policy_size <= 10240
    [warning] = [w for w in result.warnings if "characters" in w]
    assert "over IAM's limit of 6,144 for a customer managed policy" in warning
    assert "inline policy, which can hold up to 10,240" in warning and "split" in warning
    assert core.size_warning(result.policy_size, inline=True) is None  # --create-role attaches it inline
    assert result.to_dict()["policy_size"] == result.policy_size

    files["schemas/AWS_SQS_Queue.json"]["handlers"]["create"]["permissions"] *= 2
    files["schemas/AWS_SQS_Queue.json"]["handlers"]["create"]["permissions"] = [
        f"sqs:SomeRatherLongActionName{i:04}" for i in range(500)
    ]
    bigger = analyze(template("AWS::SQS::Queue"), backend(files), **kwargs)
    [warning] = [w for w in bigger.warnings if "characters" in w]
    assert "limits of 6,144 for a customer managed policy and 10,240 for all of a role's inline policies" in warning
    assert core.size_warning(bigger.policy_size, inline=True) == warning


def test_small_policy_has_no_size_warning():
    assert analyze(template("AWS::S3::Bucket"), account=ACCOUNT).warnings == []


def test_to_dict_carries_the_scoping_report():
    data = json.loads(json.dumps(analyze(template("AWS::S3::Bucket"), account=ACCOUNT).to_dict()))
    assert data["scoping"]["scoped_count"] == 2
    assert data["scoping"]["unscoped"] == {"deny": ["s3:DeleteBucket"], "no_resource_types": ["s3:ListAllMyBuckets"]}
    assert set(core.UNSCOPED_REASONS) >= set(data["scoping"]["unscoped"])
