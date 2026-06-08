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
    BUILTIN_RULES,
    ingest_text,
    detect,
    load_rules_text,
)
from sentrylog.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "mixed.log",
)

SYSLOG = ("Jun  8 09:14:55 web01 sshd[2231]: "
          "Failed password for invalid user admin from 203.0.113.44 port 41122 ssh2")
APACHE = ('203.0.113.44 - - [08/Jun/2026:09:15:33 +0000] '
          '"GET /x?id=1+union+select+a HTTP/1.1" 200 10 "-" "sqlmap/1.7"')
WINJSON = ('{"Image": "C:\\\\powershell.exe", '
           '"CommandLine": "powershell.exe -enc ABCD"}')


class TestMeta(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "sentrylog")
        self.assertTrue(TOOL_VERSION)
        self.assertTrue(len(BUILTIN_RULES) >= 5)


class TestIngest(unittest.TestCase):
    def test_syslog_parsed(self):
        ev = ingest_text(SYSLOG)[0]
        self.assertEqual(ev.fields["program"], "sshd")
        self.assertIn("Failed password", ev.fields["message"])

    def test_apache_parsed(self):
        ev = ingest_text(APACHE)[0]
        self.assertEqual(ev.fields["method"], "GET")
        self.assertEqual(ev.fields["status"], "200")
        self.assertIn("union+select", ev.fields["url"])

    def test_json_flattened(self):
        ev = ingest_text(WINJSON)[0]
        self.assertIn("-enc", ev.fields["CommandLine"])

    def test_blank_lines_skipped(self):
        self.assertEqual(ingest_text("\n\n  \n"), [])


class TestDetect(unittest.TestCase):
    def test_builtin_detects_multiple(self):
        with open(DEMO, encoding="utf-8") as fh:
            events = ingest_text(fh.read())
        matches = detect(events, BUILTIN_RULES)
        fired = {m.rule_id for m in matches}
        self.assertIn("ssh_bruteforce_failed", fired)
        self.assertIn("sudo_su_root", fired)
        self.assertIn("web_sqli_attempt", fired)
        self.assertIn("win_suspicious_powershell", fired)

    def test_clean_log_no_match(self):
        events = ingest_text("Jun  8 09:00:00 host cron[1]: clean run")
        self.assertEqual(detect(events, BUILTIN_RULES), [])

    def test_powershell_needs_both_selections(self):
        # cmd.exe with benign args must NOT fire the powershell rule
        ev = ingest_text('{"Image": "C:\\\\cmd.exe", "CommandLine": "dir"}')
        fired = {m.rule_id for m in detect(ev, BUILTIN_RULES)}
        self.assertNotIn("win_suspicious_powershell", fired)

    def test_custom_rule_pack_loads(self):
        rules = load_rules_text(json.dumps([{
            "id": "t1", "title": "test", "level": "low",
            "detection": {"s": {"program": "sshd"}, "condition": "s"},
        }]))
        self.assertEqual(len(rules), 1)
        ev = ingest_text(SYSLOG)
        self.assertEqual(len(detect(ev, rules)), 1)


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
        self.assertGreaterEqual(data["match_count"], 4)
        self.assertEqual(data["tool"], "sentrylog")

    def test_scan_level_filter(self):
        code, out = self._run(["--format", "json", "scan", DEMO, "--level", "high"])
        data = json.loads(out)
        self.assertTrue(all(m["level"] in ("high", "critical")
                            for m in data["matches"]))

    def test_rules_listing(self):
        code, out = self._run(["--format", "json", "rules"])
        self.assertEqual(code, 0)
        self.assertTrue(len(json.loads(out)) >= 5)

    def test_clean_exit_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                         encoding="utf-8") as fh:
            fh.write("Jun  8 09:00:00 host cron[1]: clean run\n")
            path = fh.name
        try:
            code, _ = self._run(["--format", "json", "scan", path])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
