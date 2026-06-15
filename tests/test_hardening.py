"""Tests covering hardened error and edge-case paths introduced in production hardening."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sentrylog.core import load_events  # noqa: E402
from sentrylog.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_cli(argv):
    """Run main() capturing stdout; return (exit_code, stdout_text)."""
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        rc = main(argv)
    except SystemExit as exc:
        rc = int(exc.code) if exc.code is not None else 0
    finally:
        sys.stdout = old_stdout
    return rc, buf.getvalue()


def _tmp_file(content: str, suffix: str = ".jsonl") -> str:
    """Write content to a named temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ---------------------------------------------------------------------------
# core.load_events — edge cases and error paths
# ---------------------------------------------------------------------------

class TestLoadEventsEdgeCases(unittest.TestCase):
    def test_empty_string_returns_empty_list(self):
        self.assertEqual(load_events(""), [])

    def test_whitespace_only_returns_empty_list(self):
        self.assertEqual(load_events("   \n\t  "), [])

    def test_malformed_json_array_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            load_events("[{bad json}")
        self.assertIn("malformed", str(ctx.exception).lower())

    def test_json_array_of_non_dicts_skipped(self):
        # Arrays of scalars or nested arrays are filtered out silently.
        events = load_events(json.dumps([1, "string", None, {"key": "val"}]))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["key"], "val")

    def test_malformed_jsonlines_raises_value_error(self):
        # A payload starting with '{' that is neither valid JSONL nor a valid
        # single JSON object should raise ValueError.
        bad = '{"a": 1}\n{broken}'
        with self.assertRaises(ValueError):
            load_events(bad)

    def test_csv_no_rows_returns_empty_list(self):
        # A CSV with only a header and no data rows.
        events = load_events("Image,CommandLine\n")
        self.assertEqual(events, [])

    def test_single_json_object_is_wrapped_in_list(self):
        events = load_events(json.dumps({"program": "cron", "message": "ok"}))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["program"], "cron")


# ---------------------------------------------------------------------------
# CLI — missing / empty / malformed input files
# ---------------------------------------------------------------------------

class TestCliInputErrors(unittest.TestCase):
    def test_missing_events_file_exits_2(self):
        rc, _ = _run_cli(["scan", "/nonexistent/path/events.jsonl"])
        self.assertEqual(rc, 2)

    def test_missing_rules_file_exits_2(self):
        path = _tmp_file(json.dumps({"Image": "notepad.exe"}) + "\n")
        try:
            rc, _ = _run_cli(["scan", path, "--rules", "/no/such/rules.yaml"])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_empty_events_file_exits_2(self):
        path = _tmp_file("")
        try:
            rc, stderr_captured = _run_cli(["scan", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_malformed_json_events_exits_2(self):
        path = _tmp_file("[{bad json}")
        try:
            rc, _ = _run_cli(["scan", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_empty_rules_file_exits_2(self):
        events_path = _tmp_file(json.dumps({"program": "cron"}) + "\n")
        rules_path = _tmp_file("", suffix=".yaml")
        try:
            rc, _ = _run_cli(["scan", events_path, "--rules", rules_path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(events_path)
            os.unlink(rules_path)

    def test_summary_missing_file_exits_2(self):
        rc, _ = _run_cli(["summary", "/no/such/file.jsonl"])
        self.assertEqual(rc, 2)

    def test_rule_command_unknown_id_exits_2(self):
        rc, _ = _run_cli(["rule", "no-such-rule-id"])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# CLI — valid empty-result paths still exit 0
# ---------------------------------------------------------------------------

class TestCliCleanPaths(unittest.TestCase):
    def test_scan_no_findings_exits_0(self):
        path = _tmp_file(json.dumps({"program": "cron", "message": "ok"}) + "\n")
        try:
            rc, _ = _run_cli(["scan", path])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_scan_json_array_empty_no_findings_exits_0(self):
        # An array with one benign event — no rule should fire.
        path = _tmp_file(json.dumps([{"program": "cron", "message": "ok"}]))
        try:
            rc, _ = _run_cli(["scan", path])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
