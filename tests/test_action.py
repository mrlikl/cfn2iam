"""The GitHub Action's script (action/cfn2iam_action.py), with cfn2iam and the GitHub API faked."""

import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "action" / "cfn2iam_action.py"
spec = importlib.util.spec_from_file_location("cfn2iam_action", SCRIPT)
action = importlib.util.module_from_spec(spec)
spec.loader.exec_module(action)

POLICIES = {
    "a.yaml": {"allow": ["s3:CreateBucket", "s3:GetBucketTagging"], "delete": ["s3:DeleteBucket"]},
    "b.yaml": {"allow": ["sqs:CreateQueue"], "delete": ["sqs:DeleteQueue"]},
}


def fake_generate(template, out_path, options, cwd):
    name = Path(template).name
    if name == "broken.yaml":
        return action.Generation(
            template,
            error="Error: could not resolve permissions for 1 of 1 resource type(s):\n  MyOrg::X::Y: no published schema",
        )
    p = POLICIES[name]
    data = {
        "template": template,
        "allow_delete": "-d" in options,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": p["allow"], "Resource": "*"},
                {"Effect": "Allow" if "-d" in options else "Deny", "Action": p["delete"], "Resource": "*"},
            ],
        },
        "allow": p["allow"],
        "delete": p["delete"],
        "by_type": {"AWS::S3::Bucket": {"allow": p["allow"], "delete": p["delete"]}},
        "unresolved": {},
        "warnings": [],
    }
    log = "Warning: something to know" if name == "b.yaml" else ""
    if "--account" in options:
        account = options[options.index("--account") + 1]
        data["scoping"] = {"account": account, "region": "eu-west-1", "partition": "aws"}
        arn = "arn:aws:s3:::*"
        data["policy"]["Statement"][0]["Resource"] = arn
        log = f"Scoped 2 of 3 actions to account {account}."
    Path(out_path).write_text(json.dumps(data))
    return action.Generation(template, output=out_path, log=log)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(action, "generate", fake_generate)
    for name in ("a.yaml", "b.yaml", "broken.yaml"):
        (tmp_path / "stacks").mkdir(exist_ok=True)
        (tmp_path / "stacks" / name).write_text("Resources: {}")
    (tmp_path / "work").mkdir()
    return tmp_path


def env(**inputs):
    out = {f"INPUT_{k.upper()}": v for k, v in inputs.items()}
    out.setdefault("INPUT_TEMPLATES", "stacks/a.yaml")
    return out


def run(repo, **inputs):
    return action.run(env(**inputs), str(repo), str(repo / "work"))


def baseline(repo, actions, deny=()):
    statements = [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}]
    if deny:
        statements.append({"Effect": "Deny", "Action": list(deny), "Resource": "*"})
    (repo / "iam").mkdir(exist_ok=True)
    (repo / "iam" / "baseline.json").write_text(json.dumps({"Version": "2012-10-17", "Statement": statements}))
    return "iam/baseline.json"


def test_no_drift(repo):
    result = run(repo, baseline=baseline(repo, ["s3:CreateBucket", "s3:GetBucketTagging"], ["s3:DeleteBucket"]))
    assert result.exit_code == 0
    assert result.outputs["drift"] == "false"
    assert result.outputs["added-count"] == "0"
    assert result.outputs["baseline-status"] == "found"
    assert not result.changed
    assert "No permission changes" in result.markdown_comment
    assert result.markdown_comment.startswith("<!-- cfn2iam-action -->\n")
    assert not result.markdown_summary.startswith("<!--")
    policy = json.loads(Path(result.outputs["policy-path"]).read_text())
    assert policy["Statement"][0]["Action"] == ["s3:CreateBucket", "s3:GetBucketTagging"]


def test_drift_fails_by_default(repo):
    result = run(repo, baseline=baseline(repo, ["s3:CreateBucket", "kms:Decrypt"]))
    assert result.exit_code == 1
    assert result.outputs["drift"] == "true"
    assert result.outputs["added-count"] == "1"
    assert result.outputs["removed-count"] == "1"
    assert ("error", "Permission drift: the templates need 1 action the baseline does not grant.") in result.notices
    assert "`s3:GetBucketTagging` (AWS::S3::Bucket)" in result.markdown_comment
    assert "How to accept this change" in result.markdown_comment
    assert "cfn2iam stacks/a.yaml -o iam/baseline.json" in result.markdown_comment
    assert "The generated policy" in result.markdown_summary


def test_drift_reported_without_failing(repo):
    result = run(repo, baseline=baseline(repo, ["s3:CreateBucket"]), fail_on_drift="false")
    assert result.exit_code == 0
    assert result.outputs["drift"] == "true"
    assert result.notices[-1][0] == "warning"


def test_options_reach_the_cli(repo, monkeypatch):
    seen = []

    def spy(template, out_path, options, cwd):
        seen.append(options)
        return fake_generate(template, out_path, options, cwd)

    monkeypatch.setattr(action, "generate", spy)
    run(repo, allow_delete="true", ignore_unknown="true", region="eu-west-1", account="123456789012", partition="aws")
    assert seen == [
        ["-d", "--ignore-unknown", "--region", "eu-west-1", "--account", "123456789012", "--partition", "aws"]
    ]


def test_missing_baseline_explains_how_to_start(repo):
    result = run(repo, baseline="iam/baseline.json")
    assert result.exit_code == 0
    assert result.outputs["baseline-status"] == "missing"
    assert result.outputs["drift"] == "false"
    assert "does not exist yet" in result.markdown_comment
    assert "**Start checking:**" in result.markdown_comment
    assert "cfn2iam stacks/a.yaml -o iam/baseline.json" in result.markdown_comment
    assert result.notices[-1][0] == "notice"


def test_missing_baseline_can_be_required(repo):
    result = run(repo, baseline="iam/baseline.json", require_baseline="true")
    assert result.exit_code == 1
    assert result.outputs["error"] == "true"


def test_no_baseline_input(repo):
    result = run(repo)
    assert result.exit_code == 0
    assert result.outputs["baseline-status"] == "none"
    assert "No baseline to compare with. The templates need 2 actions." in result.markdown_comment


def test_several_templates_and_globs(repo):
    result = run(
        repo,
        templates="stacks/a.yaml\nstacks/[ab].yaml\n# a comment\n",
        baseline=baseline(repo, ["s3:CreateBucket", "s3:GetBucketTagging"]),
    )
    assert "Templates: `stacks/a.yaml`, `stacks/b.yaml`" in result.markdown_comment
    assert result.outputs["added-count"] == "1"  # sqs:CreateQueue
    assert "AWS::S3::Bucket in stacks/b.yaml" in result.markdown_comment
    assert ("warning", "stacks/b.yaml: something to know") in result.notices
    assert "cfn2iam diff /tmp/cfn2iam-1.json /tmp/cfn2iam-2.json -w iam/baseline.json" in result.markdown_comment


def test_template_that_does_not_exist(repo):
    result = run(repo, templates="stacks/nope.yaml\nstacks/*.json")
    assert result.exit_code == 1
    assert result.outputs["error"] == "true"
    assert "Template `stacks/nope.yaml` does not exist." in result.markdown_summary
    assert "No template matches `stacks/*.json`." in result.markdown_summary


def test_unresolved_type_surfaces_the_cli_message(repo):
    result = run(repo, templates="stacks/broken.yaml")
    assert result.exit_code == 1
    assert "MyOrg::X::Y: no published schema" in result.markdown_comment
    assert (
        "error",
        "stacks/broken.yaml: Error: could not resolve permissions for 1 of 1 resource type(s):",
    ) in result.notices


def test_invalid_baseline_is_an_error(repo):
    (repo / "bad.json").write_text("{")
    result = run(repo, baseline="bad.json")
    assert result.exit_code == 1
    assert "not valid JSON" in result.markdown_summary


def test_update_baseline_writes_the_policy(repo):
    result = run(repo, baseline="iam/new/baseline.json", update_baseline="true")
    assert result.exit_code == 0
    written = json.loads((repo / "iam" / "new" / "baseline.json").read_text())
    assert written == json.loads(Path(result.outputs["policy-path"]).read_text())
    assert "wrote the generated policy to `iam/new/baseline.json`" in result.markdown_comment
    assert result.notices == [
        ("notice", "Wrote the generated policy to iam/new/baseline.json; commit it to accept it.")
    ]
    again = run(repo, baseline="iam/new/baseline.json")
    assert again.exit_code == 0 and not again.changed


def test_update_baseline_needs_one_file(repo):
    assert run(repo, update_baseline="true").exit_code == 1


@pytest.mark.parametrize(
    "inputs, message",
    [
        ({"INPUT_TEMPLATES": " "}, "templates is empty"),
        ({"INPUT_TEMPLATES": "x", "INPUT_FAIL_ON_DRIFT": "maybe"}, "fail-on-drift must be true or false"),
        ({"INPUT_TEMPLATES": "x", "INPUT_COMMENT": "sometimes"}, "comment must be"),
        ({"INPUT_TEMPLATES": "x", "INPUT_CONDITIONAL": "maybe"}, "conditional must be"),
    ],
)
def test_input_validation(inputs, message):
    with pytest.raises(action.InputError, match=message):
        action.Inputs.from_env(inputs)


def test_annotation_escaping(capsys):
    action.annotate("error", "50% done\nnext", file="a,b:c.yaml", title="cfn2iam")
    assert capsys.readouterr().out == "::error file=a%2Cb%3Ac.yaml,title=cfn2iam::50%25 done%0Anext\n"


# --- The pull request comment ---------------------------------------------------


class FakeAPI:
    def __init__(self, comments=(), fail=None):
        self.comments = list(comments)
        self.calls = []
        self.fail = fail

    def __call__(self, gh, method, path, body=None):
        self.calls.append((method, path))
        if self.fail and method in ("POST", "PATCH"):
            raise urllib.error.HTTPError(
                path, self.fail, "Forbidden", {}, io.BytesIO(b'{"message": "Resource not accessible by integration"}')
            )
        if method == "GET":
            return self.comments, ""
        if method == "PATCH":
            return {"html_url": "https://github.com/o/r/pull/7#issuecomment-1"}, ""
        return {"html_url": "https://github.com/o/r/pull/7#issuecomment-2"}, ""


def patch_api(monkeypatch, api):
    monkeypatch.setattr(action.GitHub, "request", lambda self, *args, **kwargs: api(self, *args, **kwargs))


def pr_env(tmp_path, event="pull_request", head_repo="o/r"):
    path = tmp_path / "event.json"
    path.write_text(
        json.dumps({"pull_request": {"number": 7, "head": {"sha": "abcdef0123", "repo": {"full_name": head_repo}}}})
    )
    return {"GITHUB_EVENT_NAME": event, "GITHUB_EVENT_PATH": str(path), "GITHUB_REPOSITORY": "o/r"}


def result(changed=True, marker="<!-- cfn2iam-action -->"):
    return action.Result(f"{marker}\n### report", "### report", {}, 0, [], changed)


def test_comment_is_created(tmp_path, monkeypatch):
    api = FakeAPI([{"id": 1, "body": "unrelated"}, {"id": 2, "body": "<!-- cfn2iam-action:other -->\n..."}])
    patch_api(monkeypatch, api)
    commented, url, notice = action.comment(pr_env(tmp_path), "always", "t", result())
    assert (commented, notice) == ("true", None)
    assert api.calls[-1] == ("POST", "/repos/o/r/issues/7/comments")


def test_comment_is_updated_in_place(tmp_path, monkeypatch):
    api = FakeAPI([{"id": 41, "body": "<!-- cfn2iam-action -->\nold"}])
    patch_api(monkeypatch, api)
    commented, url, _ = action.comment(pr_env(tmp_path), "always", "t", result(changed=False))
    assert commented == "true"
    assert api.calls[-1] == ("PATCH", "/repos/o/r/issues/comments/41")


def test_on_change_skips_a_new_comment_when_nothing_changed(tmp_path, monkeypatch):
    api = FakeAPI()
    patch_api(monkeypatch, api)
    assert action.comment(pr_env(tmp_path), "on-change", "t", result(changed=False))[0] == "false"
    assert [m for m, _ in api.calls] == ["GET"]


@pytest.mark.parametrize("head_repo, why", [("fork/r", "comes from a fork"), ("o/r", "Dependabot")])
def test_read_only_token_degrades_to_the_summary(tmp_path, monkeypatch, capsys, head_repo, why):
    patch_api(monkeypatch, FakeAPI(fail=403))
    commented, url, notice = action.comment(pr_env(tmp_path, head_repo=head_repo), "always", "t", result())
    assert commented == "false"
    assert "HTTP 403: Resource not accessible by integration" in notice and why in notice
    assert capsys.readouterr().out.startswith("::notice title=cfn2iam::Could not comment")


def test_no_comment_outside_pull_requests(tmp_path, monkeypatch):
    patch_api(monkeypatch, FakeAPI(fail=500))
    assert action.comment({"GITHUB_EVENT_NAME": "push"}, "always", "t", result())[0] == "false"
    assert action.comment(pr_env(tmp_path), "never", "t", result())[0] == "false"


def test_pagination(monkeypatch):
    pages = {
        "/repos/o/r/issues/7/comments?per_page=100": ([{"id": 1, "body": "x"}], '<https://api/next>; rel="next"'),
        "https://api/next": ([{"id": 9, "body": "<!-- m -->\n"}], ""),
    }
    monkeypatch.setattr(action.GitHub, "request", lambda self, method, path, body=None: pages[path])
    assert action.GitHub("https://api", "o/r", "t").find_comment(7, "<!-- m -->")["id"] == 9


def test_main_writes_summary_and_outputs(repo, monkeypatch, tmp_path):
    out, summary = tmp_path / "out", tmp_path / "summary"
    monkeypatch.chdir(repo)
    for k, v in {
        **env(baseline=baseline(repo, ["s3:*"])),
        "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(summary),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_EVENT_NAME": "push",
    }.items():
        monkeypatch.setenv(k, v)
    assert action.main() == 0
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert outputs["drift"] == "false" and outputs["commented"] == "false"
    assert Path(outputs["report-path"]).read_text() in summary.read_text()


def test_scoped_run(repo, capsys):
    result = run(repo, account="123456789012", region="eu-west-1", baseline=baseline(repo, ["s3:*"]))
    assert result.exit_code == 0, result.markdown_summary
    assert "Resources scoped to account `123456789012`, region `eu-west-1`" in result.markdown_comment
    assert not any("Scoped" in message for _, message in result.notices)  # the summary line is not a warning
    assert "stacks/a.yaml: Scoped 2 of 3 actions" in capsys.readouterr().out
    assert "cfn2iam stacks/a.yaml --region eu-west-1 --account 123456789012 -o iam/other.json" in (
        run(repo, account="123456789012", region="eu-west-1", baseline="iam/other.json").markdown_comment
    )


def test_hand_written_baseline_is_edited_not_regenerated(repo):
    (repo / "role.json").write_text(
        json.dumps({"Statement": [{"Sid": "S3", "Effect": "Allow", "Action": "s3:Create*", "Resource": "*"}]})
    )
    result = run(repo, baseline="role.json", fail_on_drift="false")
    assert "looks hand-written (wildcard actions, statement IDs), so edit it" in result.markdown_comment
    assert "-o role.json" not in result.markdown_comment


def test_registry_hint_is_outside_the_error_block(repo, monkeypatch):
    def needs_registry(template, out_path, options, cwd):
        return action.Generation(
            template, error='  X::Y: no public schema; install "cfn2iam[iam]" to ...', hint="Set it."
        )

    monkeypatch.setattr(action, "generate", needs_registry)
    text = run(repo).markdown_summary
    assert "  ```\n    X::Y: no public schema" in text
    assert "  ```\n\n  Set it." in text
