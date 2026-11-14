"""Tests for cfn2iam.compare: reading a baseline, and the permission check."""

import ast
from pathlib import Path

import pytest

from cfn2iam import compare


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(actions, resource="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


def deny(actions, resource="*", **extra):
    return {"Effect": "Deny", "Action": actions, "Resource": resource, **extra}


def detailed(template, allow_actions, delete_actions=(), by_type=None, allow_delete=False, warnings=()):
    """What cfn2iam --format json writes."""
    statements = [allow(sorted(allow_actions))]
    if delete_actions:
        statements.append(
            {"Effect": "Allow" if allow_delete else "Deny", "Action": sorted(delete_actions), "Resource": "*"}
        )
    return {
        "template": template,
        "allow_delete": allow_delete,
        "policy": policy(*statements),
        "allow": sorted(allow_actions),
        "delete": sorted(delete_actions),
        "by_type": by_type or {},
        "unresolved": {},
        "warnings": list(warnings),
    }


def check(generated, *baselines, conditional="missing"):
    gens = generated if isinstance(generated, list) else [("generated.json", generated)]
    gen = compare.load_generated(gens)
    base = compare.load_baseline([(f"baseline{i}.json", b) for i, b in enumerate(baselines)]) if baselines else None
    return compare.compare(gen, base, conditional)


def actions(findings):
    return [f.action for f in findings]


# --- Matching -----------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern, target, expected",
    [
        ("s3:GetObject", "s3:GetObject", True),
        ("S3:getobject", "s3:GetObject", True),  # actions ignore case
        ("s3:*", "s3:GetObject", True),
        ("*", "kms:Decrypt", True),
        ("s3:Get*", "s3:PutObject", False),
        ("ec2:Describe*", "ec2:DescribeVpcs", True),
        ("s3:Get?bject", "s3:GetObject", True),
        ("s3:Get?bject", "s3:GetOObject", False),
        ("s3:*Object", "s3:GetObjectAcl", False),
        ("s3:*", "s3tables:CreateTable", False),  # the colon is a literal
        # A wildcard target is covered only when everything it stands for is.
        ("s3:*", "s3:Get*", True),
        ("s3:Get*", "s3:*", False),
        ("s3:Get?", "s3:Get*", False),
        ("s3:Get*", "s3:Get?", True),
    ],
)
def test_action_matching(pattern, target, expected):
    assert compare.matches(pattern, target) is expected


def test_resources_match_case_sensitively():
    assert compare.matches("arn:aws:s3:::App-*", "arn:aws:s3:::App-logs", ignore_case=False)
    assert not compare.matches("arn:aws:s3:::app-*", "arn:aws:s3:::App-logs", ignore_case=False)


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("s3:Get*", "s3:*Object", True),
        ("s3:Get*", "s3:Put*", False),
        ("ec2:*", "s3:*", False),
        ("*", "anything", True),
        ("a?c", "ab*", True),
    ],
)
def test_overlaps(a, b, expected):
    assert compare.overlaps(a, b) is expected


# --- A previous cfn2iam output as the baseline ----------------------------------


PREVIOUS = policy(allow(["s3:CreateBucket", "s3:GetBucketTagging"]), deny(["s3:DeleteBucket"]))


def test_same_policy_is_no_change():
    report = check(PREVIOUS, PREVIOUS)
    assert not report.drift and not report.changed
    assert report.counts() == {
        "required": 2,
        "added": 0,
        "conditional": 0,
        "removed": 0,
        "newly_denied": 0,
        "no_longer_denied": 0,
    }
    assert compare.headline(report).startswith("No permission changes")


def test_new_action_is_drift_and_dropped_action_is_not_needed():
    new = policy(allow(["s3:CreateBucket", "s3:PutBucketPolicy"]), deny(["s3:DeleteBucket"]))
    report = check(new, PREVIOUS)
    assert report.drift
    assert actions(report.added) == ["s3:PutBucketPolicy"]
    assert report.added[0].status == "missing"
    assert actions(report.not_needed) == ["s3:GetBucketTagging"]
    assert report.counts()["removed"] == 1


def test_delete_only_changes():
    new = policy(allow(["s3:CreateBucket", "s3:GetBucketTagging"]), deny(["sqs:DeleteQueue"]))
    report = check(new, PREVIOUS)
    assert not report.drift
    assert report.changed
    assert actions(report.newly_denied) == ["sqs:DeleteQueue"]
    assert actions(report.no_longer_denied) == ["s3:DeleteBucket"]
    assert compare.headline(report).startswith("No new permissions needed")


def test_action_the_baseline_denies_is_not_granted():
    # The template now needs, to create something, an action the old policy denied.
    new = policy(allow(["s3:CreateBucket", "s3:DeleteBucket"]))
    report = check(new, PREVIOUS)
    [finding] = report.added
    assert (finding.action, finding.status) == ("s3:DeleteBucket", "denied")
    assert finding.reasons == ["denied by baseline0.json, statement 2"]


def test_allow_delete_output_needs_the_delete_actions():
    new = policy(allow(["s3:CreateBucket"]), allow(["s3:DeleteBucket"]))
    report = check(new, policy(allow(["s3:CreateBucket"])))
    assert actions(report.added) == ["s3:DeleteBucket"]


def test_no_baseline_compares_nothing():
    report = check(PREVIOUS)
    assert not report.has_baseline and not report.drift
    assert report.required_count == 2
    assert compare.headline(report) == "No baseline to compare with. The templates need 2 actions."


# --- A hand-written deploy role policy -------------------------------------------


NEEDED = policy(allow(["s3:CreateBucket", "s3:PutBucketTagging", "ec2:DescribeVpcs", "iam:PassRole"]))


def test_wildcards_grant():
    report = check(NEEDED, policy(allow(["S3:*", "ec2:Describe*", "iam:Pass?ole"])))
    assert not report.drift and not report.changed


def test_admin_policy_grants_everything():
    report = check(NEEDED, policy({"Effect": "Allow", "Action": "*", "Resource": "*"}))
    assert not report.drift and not report.not_needed


def test_unused_wildcard_is_not_needed():
    report = check(NEEDED, policy(allow(["s3:*", "ec2:*", "iam:*", "sqs:*", "kms:Decrypt"])))
    assert not report.drift
    assert actions(report.not_needed) == ["kms:Decrypt", "sqs:*"]


def test_explicit_deny_wins_over_a_wildcard_allow():
    report = check(NEEDED, policy(allow("*"), deny(["iam:*"])))
    [finding] = report.added
    assert (finding.action, finding.status) == ("iam:PassRole", "denied")


def test_statements_across_files_combine():
    report = check(NEEDED, policy(allow(["s3:*"])), policy(allow(["ec2:*", "iam:PassRole"])))
    assert not report.drift


def test_not_action_allow_grants_everything_else():
    baseline = policy({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"})
    report = check(NEEDED, baseline)
    assert actions(report.added) == ["iam:PassRole"]
    assert report.added[0].status == "missing"


def test_not_action_deny_denies_everything_else():
    baseline = policy(allow("*"), {"Effect": "Deny", "NotAction": ["s3:*", "ec2:*"], "Resource": "*"})
    report = check(NEEDED, baseline)
    assert [(f.action, f.status) for f in report.added] == [("iam:PassRole", "denied")]


def test_condition_makes_a_grant_conditional():
    region_only = {"Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}}
    baseline = policy(allow(["s3:*", "ec2:*"]), allow("iam:*", Sid="Iam", **region_only))
    report = check(NEEDED, baseline)
    assert report.drift  # fails closed by default
    assert actions(report.added) == ["iam:PassRole"]
    [finding] = report.conditional
    assert finding.status == "conditional"
    assert finding.reasons == ['allowed by baseline0.json, statement 2 (Sid "Iam"), which has a Condition']

    lenient = check(NEEDED, baseline, conditional="granted")
    assert not lenient.drift
    assert actions(lenient.conditional) == ["iam:PassRole"]


def test_specific_resources_make_a_grant_conditional():
    baseline = policy(allow(["s3:*", "ec2:*"]), allow("iam:PassRole", "arn:aws:iam::123456789012:role/app-*"))
    report = check(NEEDED, baseline)
    [finding] = report.conditional
    assert "limited to specific resources" in finding.reasons[0]


def test_conditional_deny_makes_a_grant_conditional():
    baseline = policy(allow("*"), deny("s3:*", Condition={"Bool": {"aws:SecureTransport": "false"}}))
    report = check(NEEDED, baseline)
    assert sorted(actions(report.conditional)) == ["s3:CreateBucket", "s3:PutBucketTagging"]
    assert report.conditional[0].reasons[0].startswith("may be denied by baseline0.json, statement 2")


def test_not_resource():
    baseline = policy(allow("*"), {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::keep-*"})
    report = check(NEEDED, baseline)
    assert {f.status for f in report.conditional} == {"conditional"}
    assert "uses NotResource" in report.conditional[0].reasons[0]


def test_deny_without_allow_is_missing_not_conditional():
    report = check(NEEDED, policy(deny("iam:*", Condition={"Bool": {"x": "y"}})))
    assert {f.status for f in report.added} == {"missing"}
    assert not report.conditional


def test_policy_variables_count_as_conditional():
    baseline = policy(allow(["s3:*", "ec2:*"]), allow("iam:PassRole", "arn:aws:iam::*:role/${aws:username}"))
    assert actions(check(NEEDED, baseline).conditional) == ["iam:PassRole"]


def test_scoped_generated_resources():
    # Once cfn2iam scopes resources, the generated policy names ARN patterns.
    generated = policy(allow(["sqs:CreateQueue"], ["arn:aws:sqs:eu-west-1:123456789012:*"]))
    assert not check(generated, policy(allow("sqs:*", "arn:aws:sqs:*:123456789012:*"))).drift
    # A statement for other resources doesn't grant it. (Another account's ARNs could still
    # overlap string-wise, since * also matches colons, so use another service's.)
    elsewhere = check(generated, policy(allow("*", "arn:aws:sns:*:123456789012:*")))
    assert elsewhere.added[0].status == "missing"
    narrower = check(generated, policy(allow("sqs:*", "arn:aws:sqs:eu-west-1:123456789012:app-*")))
    assert narrower.conditional[0].status == "conditional"


def test_wildcard_in_the_generated_policy():
    # Some schemas list wildcards; a narrower baseline grant doesn't cover them.
    generated = policy(allow(["ec2:Describe*"]))
    assert not check(generated, policy(allow("ec2:*"))).drift
    assert actions(check(generated, policy(allow("ec2:DescribeVpcs"))).added) == ["ec2:Describe*"]


# --- Reading files -------------------------------------------------------------


@pytest.mark.parametrize(
    "wrapper",
    [
        lambda p: p,
        lambda p: {"PolicyDocument": p},  # aws iam get-role-policy
        lambda p: {"PolicyVersion": {"Document": p, "VersionId": "v3"}},  # aws iam get-policy-version
        lambda p: {"policy": p},  # cfn2iam --format json
    ],
)
def test_baseline_forms(wrapper):
    baseline = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
    report = check(policy(allow(["s3:CreateBucket"])), wrapper(baseline))
    assert not report.drift


@pytest.mark.parametrize(
    "baseline, message",
    [
        ([], "not a JSON object"),
        ({"Statement": "x"}, "Statement must be"),
        ({"Version": "2012-10-17"}, "no policy found"),
        (policy({"Effect": "allow", "Action": "s3:*", "Resource": "*"}), "Effect must be"),
        (policy({"Effect": "Allow", "Resource": "*"}), "exactly one of Action and NotAction"),
        (policy({"Effect": "Allow", "Action": [1], "Resource": "*"}), "Action must be a string"),
        (policy({"Effect": "Allow", "Action": "s3:*", "Resource": "*", "NotResource": "*"}), "both Resource"),
    ],
)
def test_invalid_baseline(baseline, message):
    with pytest.raises(compare.PolicyError, match=message):
        compare.load_baseline([("b.json", baseline)])


def test_generated_policy_rejects_conditions():
    with pytest.raises(compare.PolicyError, match="Condition is not supported"):
        compare.load_generated([("g.json", policy(allow("s3:*", Condition={"x": {}})))])


def test_statement_without_resource_is_conditional():
    report = check(policy(allow(["s3:CreateBucket"])), policy({"Effect": "Allow", "Action": "s3:*"}))
    assert actions(report.conditional) == ["s3:CreateBucket"]


# --- Several templates -----------------------------------------------------------


def test_templates_combine_and_say_who_needs_what():
    a = detailed(
        "stacks/a.yaml",
        ["s3:CreateBucket"],
        ["s3:DeleteBucket", "sns:Unsubscribe"],
        by_type={"AWS::S3::Bucket": {"allow": ["s3:CreateBucket"], "delete": ["s3:DeleteBucket", "sns:Unsubscribe"]}},
    )
    b = detailed(
        "stacks/b.yaml",
        ["sns:Subscribe", "sns:Unsubscribe"],
        by_type={"AWS::SNS::Topic": {"allow": ["sns:Subscribe", "sns:Unsubscribe"], "delete": []}},
    )
    gen = compare.load_generated([("1.json", a), ("2.json", b)])
    # Needed to update b's topic, so never denied for a's deletes.
    assert sorted(gen.required) == ["s3:CreateBucket", "sns:Subscribe", "sns:Unsubscribe"]
    assert sorted(gen.denied) == ["s3:DeleteBucket"]
    assert compare.combined_policy(gen) == policy(
        allow(["s3:CreateBucket", "sns:Subscribe", "sns:Unsubscribe"]), deny(["s3:DeleteBucket"])
    )
    report = compare.compare(gen, compare.load_baseline([("b.json", policy(allow("s3:*")))]))
    assert actions(report.added) == ["sns:Subscribe", "sns:Unsubscribe"]
    assert report.added[1].needed_by == [("stacks/a.yaml", "AWS::S3::Bucket"), ("stacks/b.yaml", "AWS::SNS::Topic")]


def test_combined_allow_delete_keeps_deletes_apart():
    a = detailed("a.yaml", ["s3:CreateBucket"], ["s3:DeleteBucket"], allow_delete=True)
    b = detailed("b.yaml", ["sqs:CreateQueue"], ["sqs:DeleteQueue"], allow_delete=True)
    combined = compare.combined_policy(compare.load_generated([("1", a), ("2", b)]))
    assert combined["Statement"] == [
        allow(["s3:CreateBucket", "sqs:CreateQueue"]),
        allow(["s3:DeleteBucket", "sqs:DeleteQueue"]),
    ]


def test_one_template_policy_is_unchanged():
    a = detailed("a.yaml", ["s3:CreateBucket"], ["s3:DeleteBucket"])
    assert compare.combined_policy(compare.load_generated([("1", a)])) is a["policy"]


# --- Rendering -------------------------------------------------------------------


def test_markdown_no_change():
    text = compare.render_markdown(check(PREVIOUS, PREVIOUS), marker="<!-- m -->")
    assert text.startswith("<!-- m -->\n### cfn2iam permission check\n")
    assert "No permission changes" in text


def test_markdown_groups_by_service_and_collapses():
    needed = [f"svc{i % 7}:Action{i}" for i in range(80)]
    text = compare.render_markdown(check(policy(allow(needed)), policy(allow("svc0:*"))))
    assert "Permission drift: the templates need 68 actions" in text
    assert "<details><summary><code>svc1</code>: 12</summary>" in text  # long: collapsed
    assert "- `svc1:Action1`" in text


def test_markdown_fits_the_limit():
    needed = [f"svc{i % 30}:A{'x' * 60}{i}" for i in range(3000)]
    report = check(policy(allow(needed)), policy(allow("nothing:*")))
    full = compare.render_markdown(report)
    short = compare.render_markdown(report, max_length=20000)
    assert len(full) > 20000 >= len(short)
    assert "left out for length" in short


def test_text_report():
    region_only = {"Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}}
    report = check(NEEDED, policy(allow(["s3:*", "sqs:*"]), allow("iam:*", **region_only)))
    text = compare.render_text(report)
    assert "Needed, not granted by the baseline (1):\n  ec2:DescribeVpcs" in text
    assert "counted as not granted (1)" in text
    assert "Allowed by the baseline, not needed by the templates (1):\n  sqs:*" in text


def test_compare_uses_only_the_standard_library():
    # Like core, compare must run anywhere (the web version may use it): no third-party imports.
    tree = ast.parse(Path(compare.__file__).read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [ast.alias(node.module or "")])
    }
    assert imported <= {"re", "dataclasses", "functools", "typing"}


def test_scoped_policy_with_several_statements():
    # cfn2iam --account: an Allow statement per ARN pattern, the rest on "*", deletes denied on "*".
    scoped = policy(
        allow(["sqs:CreateQueue", "sqs:GetQueueAttributes"], "arn:aws:sqs:eu-west-1:123456789012:*"),
        allow(["s3:CreateBucket"], ["arn:aws:s3:::*"]),
        allow(["sqs:ListQueues"]),
        deny(["sqs:DeleteQueue"]),
    )
    unscoped = policy(
        allow(["s3:CreateBucket", "sqs:CreateQueue", "sqs:GetQueueAttributes", "sqs:ListQueues"]),
        deny(["sqs:DeleteQueue"]),
    )
    assert not check(scoped, scoped).changed
    assert not check(scoped, unscoped).changed  # "*" covers every ARN
    narrower = check(unscoped, scoped)  # the baseline grants only some resources
    assert sorted(actions(narrower.conditional)) == ["s3:CreateBucket", "sqs:CreateQueue", "sqs:GetQueueAttributes"]
    assert not narrower.not_granted
