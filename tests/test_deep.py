"""Deep tests for sentrylog's bundled Sigma-style rule pack + matcher."""

import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sentrylog import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    load_rules,
    load_events,
    rule_matches,
    scan,
    summarize_findings,
)
from sentrylog import cli  # noqa: E402
from sentrylog.core import evaluate_condition  # noqa: E402

DEMO = os.path.join(ROOT, "demos", "02-deep")


# --------------------------------------------------------------------------- #
# Bundled rule pack
# --------------------------------------------------------------------------- #
def test_bundled_pack_size_and_shape():
    rules = load_rules()
    assert len(rules) >= 25, f"expected >=25 bundled rules, got {len(rules)}"
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for r in rules:
        assert r.id and r.title and r.condition
        assert r.mitre.startswith("T"), f"rule {r.id} missing MITRE technique"
        assert r.detection, f"rule {r.id} has no detection selections"


def test_levels_present():
    levels = {r.level for r in load_rules()}
    assert {"critical", "high", "medium"}.issubset(levels)


# --------------------------------------------------------------------------- #
# Modifier / condition semantics
# --------------------------------------------------------------------------- #
def test_contains_all_modifier():
    rules = {r.id: r for r in load_rules()}
    cradle = rules["win-ps-download-cradle"]
    # "all" requires every term -> only one term present should NOT fire `sel`
    fired, _ = rule_matches(cradle, {"Image": "x\\powershell.exe", "CommandLine": "DownloadString only"})
    assert not fired
    fired, matched = rule_matches(cradle, {"Image": "x\\powershell.exe",
                                           "CommandLine": "IEX (DownloadString(...))"})
    assert fired and "sel" in matched


def test_endswith_and_startswith():
    rules = {r.id: r for r in load_rules()}
    enc = rules["win-ps-encoded"]
    fired, _ = rule_matches(enc, {"Image": "C:\\X\\powershell.exe", "CommandLine": "-enc ABCDEF"})
    assert fired
    fired, _ = rule_matches(enc, {"Image": "C:\\X\\notepad.exe", "CommandLine": "-enc ABCDEF"})
    assert not fired


def test_dotted_field_resolution():
    rules = {r.id: r for r in load_rules()}
    root = rules["cloud-aws-root"]
    fired, _ = rule_matches(root, {"userIdentity": {"type": "Root"}, "eventName": "ListBuckets"})
    assert fired
    # console login is excluded by the `not notconsole` condition
    fired, _ = rule_matches(root, {"userIdentity": {"type": "Root"}, "eventName": "ConsoleLogin"})
    assert not fired


def test_condition_and_not_quantifier():
    sels = {"sel": True, "notconsole": False}
    assert evaluate_condition("sel and not notconsole", sels) is True
    assert evaluate_condition("sel and not notconsole", {"sel": True, "notconsole": True}) is False
    assert evaluate_condition("1 of them", {"a": False, "b": True}) is True
    assert evaluate_condition("all of them", {"a": True, "b": False}) is False
    assert evaluate_condition("1 of sel*", {"sel1": False, "sel2": True, "other": False}) is True


def test_office_child_shell_needs_both():
    rules = {r.id: r for r in load_rules()}
    r = rules["exec-office-child-shell"]
    fired, _ = rule_matches(r, {"ParentImage": "x\\winword.exe", "Image": "x\\cmd.exe"})
    assert fired
    fired, _ = rule_matches(r, {"ParentImage": "x\\winword.exe", "Image": "x\\update.exe"})
    assert not fired


# --------------------------------------------------------------------------- #
# Event loading: JSON / JSON-lines / CSV
# --------------------------------------------------------------------------- #
def test_load_events_formats():
    arr = load_events('[{"a": 1}, {"a": 2}]')
    assert len(arr) == 2
    lines = load_events('{"a": 1}\n{"a": 2}\n')
    assert len(lines) == 2 and lines[1]["a"] == 2
    csv_events = load_events("Image,CommandLine\nx\\net.exe,net localgroup\n")
    assert csv_events[0]["Image"] == "x\\net.exe"


def test_csv_netflow_suspicious_port():
    with open(os.path.join(DEMO, "network.csv"), encoding="utf-8") as fh:
        events = load_events(fh.read())
    findings = scan(events, load_rules())
    ports = {f.rule_id for f in findings}
    assert "net-suspicious-port" in ports
    # 4444, 9001 should hit; 443 / 53 should not
    hit_ports = {str(f.event.get("dst_port")) for f in findings if f.rule_id == "net-suspicious-port"}
    assert "4444" in hit_ports and "9001" in hit_ports
    assert "443" not in hit_ports and "53" not in hit_ports


# --------------------------------------------------------------------------- #
# End-to-end against the demo kill-chain
# --------------------------------------------------------------------------- #
def test_demo_killchain_findings():
    with open(os.path.join(DEMO, "events.jsonl"), encoding="utf-8") as fh:
        events = load_events(fh.read())
    assert len(events) == 20
    findings = scan(events, load_rules())
    fired_rules = {f.rule_id for f in findings}
    expected = {
        "win-ps-encoded", "exec-office-child-shell", "ingress-certutil",
        "cred-lsass-dump", "cred-mimikatz", "persist-run-key",
        "persist-schtasks", "persist-net-localadmin", "impact-vss-delete",
        "def-clear-eventlog", "linux-reverse-shell", "linux-sensitive-read",
        "linux-ssh-bruteforce", "cloud-aws-stoptrail", "cloud-aws-open-sg",
        "cloud-aws-root", "web-sqli", "web-path-traversal",
    }
    missing = expected - fired_rules
    assert not missing, f"expected detections missing: {sorted(missing)}"

    techniques = {f.mitre for f in findings}
    assert "T1003.001" in techniques and "T1490" in techniques


def test_benign_events_do_not_alert():
    with open(os.path.join(DEMO, "events.jsonl"), encoding="utf-8") as fh:
        events = load_events(fh.read())
    findings = scan(events, load_rules())
    flagged_idx = {f.event_index for f in findings}
    # notepad event (index 10) and healthz probe (index 13) are benign
    assert 10 not in flagged_idx, "notepad.exe should not alert"
    assert 13 not in flagged_idx, "/healthz probe should not alert"


def test_summary_rollup():
    with open(os.path.join(DEMO, "events.jsonl"), encoding="utf-8") as fh:
        events = load_events(fh.read())
    summary = summarize_findings(scan(events, load_rules()))
    assert summary["total_findings"] > 0
    assert summary["max_severity"] == "critical"
    assert summary["by_technique"]


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #
def _run_cli(argv, capsys=None):
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        rc = cli.main(argv)
    finally:
        sys.stdout = old
    return rc, out.getvalue()


def test_cli_version_and_constants():
    assert TOOL_NAME == "sentrylog"
    assert TOOL_VERSION.count(".") == 2


def test_cli_scan_json_exit_nonzero():
    rc, text = _run_cli(["--format", "json", "scan", os.path.join(DEMO, "events.jsonl")])
    assert rc == 1, "findings present -> non-zero exit"
    payload = json.loads(text)
    assert payload["tool"] == "sentrylog"
    assert payload["events_scanned"] == 20
    assert payload["summary"]["total_findings"] > 0
    assert all("mitre" in f for f in payload["findings"])


def test_cli_scan_clean_exit_zero(tmp_path):
    clean = tmp_path / "clean.jsonl"
    clean.write_text('{"Image": "x\\\\notepad.exe", "CommandLine": "notepad readme.txt"}\n',
                     encoding="utf-8")
    rc, _ = _run_cli(["scan", str(clean)])
    assert rc == 0


def test_cli_rules_and_rule():
    rc, text = _run_cli(["--format", "json", "rules"])
    assert rc == 0
    listed = json.loads(text)
    assert len(listed) >= 25
    rc, text = _run_cli(["--format", "json", "rule", "cred-mimikatz"])
    assert rc == 0
    assert json.loads(text)["mitre"] == "T1003.001"


def test_cli_level_filter():
    rc, text = _run_cli(["--format", "json", "scan",
                         os.path.join(DEMO, "events.jsonl"), "--level", "critical"])
    payload = json.loads(text)
    assert payload["rules_evaluated"] < 25  # filtered down to critical-only
    assert all(f["level"] == "critical" for f in payload["findings"])


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            import inspect
            params = inspect.signature(fn).parameters
            if "tmp_path" in params:
                import tempfile, pathlib
                with tempfile.TemporaryDirectory() as d:
                    fn(pathlib.Path(d))
            else:
                fn()
            print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    sys.exit(1 if failed else 0)
