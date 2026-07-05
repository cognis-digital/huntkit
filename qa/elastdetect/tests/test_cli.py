"""CLI tests: exit codes (the CI gate), diff output, deploy dry-run.

No network is used: deploy is only ever exercised without --live.
"""

import json
import os

from elastdetect.cli import main

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(HERE, "examples")


def _write(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def test_validate_examples_exit_zero(capsys):
    rc = main(["validate", os.path.join(EXAMPLES, "rules")])
    assert rc == 0


def test_validate_bad_rule_exit_one(tmp_path, capsys):
    _write(tmp_path / "bad.json", {"rule_id": "x", "type": "query", "severity": "nope"})
    rc = main(["validate", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "severity" in err


def test_validate_missing_path_exit_two(capsys):
    rc = main(["validate", os.path.join("no", "such", "dir.json")])
    assert rc == 2


def test_lint_default_exit_zero_with_warnings(tmp_path, capsys):
    # Valid but undocumented rule: warnings, but lint without --strict is exit 0.
    _write(
        tmp_path / "r.json",
        {
            "rule_id": "lint-1",
            "name": "A Valid But Undocumented Rule",
            "type": "query",
            "query": "x : y",
            "risk_score": 10,
            "severity": "low",
        },
    )
    rc = main(["lint", str(tmp_path)])
    assert rc == 0
    assert "warning" in capsys.readouterr().out


def test_lint_strict_exit_one(tmp_path, capsys):
    _write(
        tmp_path / "r.json",
        {
            "rule_id": "lint-2",
            "name": "Another Undocumented Rule Here",
            "type": "query",
            "query": "x : y",
            "risk_score": 10,
            "severity": "low",
        },
    )
    rc = main(["lint", "--strict", str(tmp_path)])
    assert rc == 1


def test_diff_table(capsys):
    rc = main(
        [
            "diff",
            os.path.join(EXAMPLES, "diff", "ruleset_old.json"),
            os.path.join(EXAMPLES, "diff", "ruleset_new.json"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "ADDED" in out
    assert "REMOVED" in out
    assert "MODIFIED" in out


def test_diff_json(capsys):
    rc = main(
        [
            "diff",
            "--json",
            os.path.join(EXAMPLES, "diff", "ruleset_old.json"),
            os.path.join(EXAMPLES, "diff", "ruleset_new.json"),
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    added = [r["rule_id"] for r in payload["added"]]
    removed = [r["rule_id"] for r in payload["removed"]]
    modified = [r["rule_id"] for r in payload["modified"]]
    assert "cognis-0010-rare-dns-tunnel" in added
    assert "cognis-0009-deprecated-rule" in removed
    assert "cognis-0001-encoded-powershell" in modified


def test_deploy_dry_run_no_network(capsys):
    """deploy without --live must be a dry run and never POST."""
    rc = main(["deploy", os.path.join(EXAMPLES, "rules")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run" in out


def test_deploy_live_requires_credentials(tmp_path, capsys):
    _write(
        tmp_path / "r.json",
        {
            "rule_id": "dep-1",
            "name": "Deployable Valid Rule Here",
            "type": "query",
            "query": "x : y",
            "risk_score": 10,
            "severity": "low",
        },
    )
    # --live without url/api-key is a usage error (exit 2), still no network.
    rc = main(["deploy", "--live", str(tmp_path)])
    assert rc == 2


def test_deploy_skips_invalid_rules(tmp_path, capsys):
    _write(tmp_path / "bad.json", {"rule_id": "bad", "type": "query"})
    rc = main(["deploy", str(tmp_path)])
    out = capsys.readouterr().out
    assert "skipped-invalid" in out
