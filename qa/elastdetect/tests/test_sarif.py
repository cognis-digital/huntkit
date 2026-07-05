"""Tests for SARIF 2.1.0 export (sarif.py + `validate --sarif`)."""

import json
import os

from elastdetect.cli import main
from elastdetect.sarif import reports_to_sarif, SARIF_VERSION
from elastdetect.validate import validate_rule

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(HERE, "demos")


def _report(rule):
    return [validate_rule(rule, source="x.json")]


def test_sarif_clean_rule_has_no_results(valid_query_rule):
    log = reports_to_sarif(_report(valid_query_rule))
    assert log["version"] == SARIF_VERSION
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "elastdetect"
    assert log["runs"][0]["results"] == []


def test_sarif_envelope_shape(make_rule):
    rule = make_rule(severity="nope")
    log = reports_to_sarif(_report(rule))
    assert "$schema" in log
    run = log["runs"][0]
    assert set(run) >= {"tool", "results"}
    assert "rules" in run["tool"]["driver"]
    # The descriptor for the failing check is registered.
    rule_ids = {d["id"] for d in run["tool"]["driver"]["rules"]}
    assert "elastdetect/severity" in rule_ids


def test_sarif_result_for_each_error(make_rule):
    rule = make_rule(severity="nope", risk_score=999)
    log = reports_to_sarif(_report(rule))
    results = log["runs"][0]["results"]
    fields = {r["properties"]["field"] for r in results}
    assert {"severity", "risk_score"} <= fields
    for r in results:
        assert r["level"] == "error"
        assert r["ruleId"].startswith("elastdetect/")
        loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert loc  # non-empty artifact uri


def test_sarif_excludes_warnings_when_disabled(make_rule, DELETE):
    # A rule with no errors but lint-style gaps still has zero validation issues,
    # so include_warnings=False yields no results either way; assert the flag is
    # honoured by feeding a hand-built warning-level report.
    from elastdetect.validate import Issue, RuleReport

    rep = RuleReport(rule_id="w1", source="x.json")
    rep.issues.append(Issue("w1", "tags", "missing", level="warning"))
    rep.issues.append(Issue("w1", "severity", "bad", level="error"))

    with_warn = reports_to_sarif([rep], include_warnings=True)
    without_warn = reports_to_sarif([rep], include_warnings=False)
    assert len(with_warn["runs"][0]["results"]) == 2
    assert len(without_warn["runs"][0]["results"]) == 1
    assert without_warn["runs"][0]["results"][0]["level"] == "error"


def test_cli_validate_sarif_clean_exit_zero(capsys):
    rc = main(["validate", "--sarif", os.path.join(DEMOS, "01-ci-gate-clean", "rules.json")])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []


def test_cli_validate_sarif_findings_exit_one(capsys):
    rc = main(["validate", "--sarif", os.path.join(DEMOS, "06-sarif-code-scanning", "rules.json")])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert len(payload["runs"][0]["results"]) >= 2
    # stdout must be valid SARIF JSON only (machine-ingestible).
    assert payload["$schema"].endswith("sarif-2.1.0.json")
