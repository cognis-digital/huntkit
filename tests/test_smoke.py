"""Smoke tests for SENTRYLOG. No network. Standard library only."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentrylog import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    BUNDLED_RULES,
    load_events,
    scan,
    load_rules,
)
from sentrylog.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "mixed.log",
)

# Structured JSON-lines events - use json.dumps to ensure valid JSON encoding.
SSHD_FAIL = json.dumps({
    "program": "sshd",
    "message": "Failed password for invalid user admin from 203.0.113.44 port 41122 ssh2",
    "host": "web01",
})
SQLI = json.dumps({
    "request": "GET /products?id=1' UNION SELECT username,password FROM users HTTP/1.1",
    "status": "200",
    "src_ip": "203.0.113.44",
    "agent": "sqlmap/1.7",
})
# Use json.dumps to produce correctly escaped backslash sequences in the JSON.
POWERSHELL_ENC = json.dumps({
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "CommandLine": "powershell.exe -enc SQBFAFgAIAAo...",
    "User": r"CORP\jdoe",
    "Computer": "WIN-FIN-07",
})
CMD_BENIGN = json.dumps({
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": "cmd.exe /c dir",
    "User": r"CORP\jdoe",
})

# Minimal YAML rule pack (load_rules uses parse_yaml_documents, not a JSON parser).
_CUSTOM_RULE_YAML = """\
id: t1
title: Test SSH Failed Login
level: low
detection:
  s:
    program: sshd
    message|contains: Failed password
  condition: s
"""


class TestMeta(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "sentrylog")
        self.assertTrue(TOOL_VERSION)
        self.assertTrue(len(BUNDLED_RULES) >= 5)

    def test_load_rules_default_returns_many(self):
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 5)

    def test_load_rules_custom_yaml(self):
        rules = load_rules(_CUSTOM_RULE_YAML)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].id, "t1")


class TestLoadEvents(unittest.TestCase):
    def test_json_object_parsed(self):
        events = load_events(POWERSHELL_ENC)
        self.assertEqual(len(events), 1)
        self.assertIn("-enc", events[0]["CommandLine"])

    def test_sshd_json_fields_present(self):
        events = load_events(SSHD_FAIL)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["program"], "sshd")
        self.assertIn("Failed password", events[0]["message"])

    def test_sqli_json_fields_present(self):
        events = load_events(SQLI)
        self.assertEqual(len(events), 1)
        self.assertIn("UNION SELECT", events[0]["request"])

    def test_json_lines_multi_event(self):
        text = "\n".join([SSHD_FAIL, SQLI, POWERSHELL_ENC])
        events = load_events(text)
        self.assertEqual(len(events), 3)

    def test_json_array_parsed(self):
        arr = json.dumps([json.loads(SSHD_FAIL), json.loads(SQLI)])
        events = load_events(arr)
        self.assertEqual(len(events), 2)

    def test_blank_lines_skipped(self):
        text = "\n".join(["", SSHD_FAIL, "", SQLI, ""])
        events = load_events(text)
        self.assertEqual(len(events), 2)


class TestDetect(unittest.TestCase):
    def test_builtin_detects_multiple(self):
        with open(DEMO, encoding="utf-8") as fh:
            events = load_events(fh.read())
        rules = load_rules()
        matches = scan(events, rules)
        fired = {m.rule_id for m in matches}
        self.assertIn("linux-ssh-bruteforce", fired)
        self.assertIn("web-sqli", fired)
        self.assertIn("win-ps-encoded", fired)

    def test_clean_log_no_match(self):
        events = load_events(json.dumps({"program": "cron", "message": "clean run"}))
        rules = load_rules()
        self.assertEqual(scan(events, rules), [])

    def test_powershell_needs_both_selections(self):
        # cmd.exe with benign args must NOT fire the powershell rule
        events = load_events(CMD_BENIGN)
        rules = load_rules()
        fired = {m.rule_id for m in scan(events, rules)}
        self.assertNotIn("win-ps-encoded", fired)

    def test_custom_rule_pack_loads(self):
        rules = load_rules(_CUSTOM_RULE_YAML)
        self.assertEqual(len(rules), 1)
        events = load_events(SSHD_FAIL)
        self.assertEqual(len(scan(events, rules)), 1)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            code = main(argv)
        finally:
            sys.stdout = old
        return code, out.getvalue()

    def test_scan_json_exit_nonzero_on_match(self):
        code, out = self._run(["--format", "json", "scan", DEMO])
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertGreaterEqual(data["summary"]["total_findings"], 3)
        self.assertEqual(data["tool"], "sentrylog")

    def test_scan_level_filter(self):
        code, out = self._run(["--format", "json", "scan", DEMO, "--level", "high"])
        data = json.loads(out)
        self.assertTrue(all(m["level"] in ("high", "critical")
                            for m in data["findings"]))

    def test_rules_listing(self):
        code, out = self._run(["--format", "json", "rules"])
        self.assertEqual(code, 0)
        self.assertTrue(len(json.loads(out)) >= 5)

    def test_clean_exit_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(json.dumps({"program": "cron", "message": "clean run"}) + "\n")
            path = fh.name
        try:
            code, _ = self._run(["--format", "json", "scan", path])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
