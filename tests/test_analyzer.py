import json
from pathlib import Path

import pytest

from abr.analyzer import analyze, least_privilege_policy
from abr.cli import main
from abr.iam import parse_policy
from abr.manifest import parse_manifest

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "support-bot"


def ids(result):
    return [f.id for f in result.findings]


def make(tools, *statements):
    return parse_manifest({"agent": "test", "tools": tools}), parse_policy({"Statement": list(statements)})


def test_clean_agent_has_no_findings():
    manifest, st = make(
        [{"name": "kb", "aws_actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::kb/*"]}],
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::kb/*"},
    )
    result = analyze(manifest, st)
    assert result.findings == []
    assert result.score == 0


def test_lethal_trifecta_detected():
    manifest, st = make(
        [{"name": "browse", "reads_untrusted_input": True, "external_comms": True},
         {"name": "db", "aws_actions": ["dynamodb:GetItem"], "touches_private_data": True}],
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"},
    )
    result = analyze(manifest, st)
    assert "ABR-001" in ids(result)
    assert result.findings[0].severity == "CRITICAL"


def test_no_trifecta_without_untrusted_input():
    manifest, st = make(
        [{"name": "notify", "external_comms": True},
         {"name": "db", "aws_actions": ["dynamodb:GetItem"], "touches_private_data": True}],
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"},
    )
    assert "ABR-001" not in ids(analyze(manifest, st))


def test_escalation_path_needs_every_action():
    tools = [{"name": "noop"}]
    _, partial = make(tools, {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction"], "Resource": "*"})
    manifest, full = make(tools, {"Effect": "Allow",
                                  "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                                  "Resource": "*"})
    titles_partial = [f.title for f in analyze(manifest, partial).findings]
    titles_full = [f.title for f in analyze(manifest, full).findings]
    assert not any("Lambda with a privileged role" in t for t in titles_partial)
    assert any("Lambda with a privileged role" in t for t in titles_full)


def test_untrusted_input_raises_severity():
    statement = {"Effect": "Allow", "Action": "cloudtrail:StopLogging", "Resource": "*"}
    calm, st = make([{"name": "noop"}], statement)
    exposed, _ = make([{"name": "reader", "reads_untrusted_input": True}], statement)
    sev = lambda m: next(f.severity for f in analyze(m, st).findings if "turn off logging" in f.title)
    assert sev(calm) == "HIGH"
    assert sev(exposed) == "CRITICAL"


def test_missing_permission_reported():
    manifest, st = make([{"name": "kb", "aws_actions": ["s3:GetObject"]}],
                        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"})
    assert "ABR-401" in ids(analyze(manifest, st))


def test_least_privilege_policy_only_has_tool_actions():
    manifest, _ = make(
        [{"name": "lookup order", "aws_actions": ["dynamodb:Query", "dynamodb:GetItem"],
          "resources": ["arn:aws:dynamodb:us-east-1:1:table/orders"]},
         {"name": "browse", "reads_untrusted_input": True}],
    )
    doc = least_privilege_policy(manifest)
    assert doc["Statement"] == [{
        "Sid": "LookupOrder", "Effect": "Allow",
        "Action": ["dynamodb:GetItem", "dynamodb:Query"],
        "Resource": ["arn:aws:dynamodb:us-east-1:1:table/orders"],
    }]


def test_manifest_rejects_wildcard_actions():
    with pytest.raises(ValueError):
        parse_manifest({"tools": [{"name": "bad", "aws_actions": ["s3:*"]}]})


def test_example_end_to_end(tmp_path, capsys):
    out_policy = tmp_path / "lp.json"
    code = main(["scan", "-m", str(EXAMPLE / "manifest.json"), "-p", str(EXAMPLE / "policy.json"),
                 "-f", "json", "--write-policy", str(out_policy), "--fail-on", "critical"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["counts"]["critical"] >= 1
    assert "iam:PassRole" in report["unused_risky_actions"]

    # Re-scanning with the generated policy removes every finding except the trifecta,
    # which is a design problem that permissions alone cannot fix.
    code = main(["scan", "-m", str(EXAMPLE / "manifest.json"), "-p", str(out_policy), "-f", "json"])
    fixed = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [f["id"] for f in fixed["findings"]] == ["ABR-001"]
    assert fixed["unused_risky_actions"] == []
