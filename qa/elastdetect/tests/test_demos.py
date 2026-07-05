"""Smoke tests that each shipped demo loads and behaves as its SCENARIO says.

These guard against the demos silently bit-rotting (a demo that no longer fires
the documented outcome is worse than no demo). All offline.
"""

import os

import pytest

from elastdetect.cli import main

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(HERE, "demos")


def _p(*parts):
    return os.path.join(DEMOS, *parts)


def test_all_demos_have_scenario():
    for name in sorted(os.listdir(DEMOS)):
        d = os.path.join(DEMOS, name)
        if os.path.isdir(d):
            assert os.path.isfile(os.path.join(d, "SCENARIO.md")), name


# (demo path args, expected exit code)
VALIDATE_CASES = [
    ([_p("01-ci-gate-clean", "rules.json")], 0),
    ([_p("02-ci-gate-broken", "rules.json")], 1),
    ([_p("07-threshold-bruteforce", "rules.json")], 0),
    ([_p("08-new-terms-rare-process", "rules.json")], 0),
    ([_p("09-machine-learning-job", "rules.json")], 1),
    ([_p("10-mixed-batch-triage", "rules")], 1),
]


@pytest.mark.parametrize("args,expected", VALIDATE_CASES)
def test_demo_validate_exit_codes(args, expected, capsys):
    rc = main(["validate", *args])
    capsys.readouterr()
    assert rc == expected


def test_demo_lint_strict_flags_hygiene(capsys):
    rc = main(["lint", "--strict", _p("03-lint-authoring-hygiene", "rules.json")])
    assert rc == 1
    assert "warning" in capsys.readouterr().out


def test_demo_diff_change_set(capsys):
    rc = main(["diff", "--json", _p("04-rule-tuning-diff", "before.json"),
               _p("04-rule-tuning-diff", "after.json")])
    assert rc == 0
    import json
    d = json.loads(capsys.readouterr().out)
    assert len(d["added"]) == 1
    assert len(d["removed"]) == 1
    assert len(d["modified"]) == 2


def test_demo_deploy_dry_run_skips_invalid(capsys):
    rc = main(["deploy", _p("05-deploy-dry-run", "rules.json")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "dry-run" in out
    assert "skipped-invalid" in out


def test_demo_sarif_export(capsys):
    rc = main(["validate", "--sarif", _p("06-sarif-code-scanning", "rules.json")])
    import json
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"][0]["results"]) >= 2
