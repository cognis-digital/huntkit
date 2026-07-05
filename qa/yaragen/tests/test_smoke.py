"""Smoke tests for YARAGEN. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yaragen import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, extract_strings, score_string,
    analyze_sample, generate_rule,
)
from yaragen.cli import main, _render_html  # noqa: E402

SAMPLE = (
    b"MZ\x90\x00This program cannot be run in DOS mode.\n"
    b"kernel32.dll\nVirtualAllocEx\nWriteProcessMemory\n"
    b"http://malware-c2.example.net/gate/check.php\n"
    b"C:\\Users\\Public\\AppData\\Local\\Temp\\svc_update.exe\n"
    b"powershell -enc JABjAD0A\n"
    b"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
    b"zzzzzzzzzzzz\n2024\n"
    # a wide (UTF-16LE) string:
    b"W\x00i\x00d\x00e\x00S\x00e\x00c\x00r\x00e\x00t\x00\n\x00"
)


def _write_sample(tmpdir, name="sample.bin", data=SAMPLE):
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


class TestMeta(unittest.TestCase):
    def test_version(self):
        self.assertEqual(TOOL_NAME, "yaragen")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestScoring(unittest.TestCase):
    def test_suspicious_beats_goodware(self):
        s_score, s_cat = score_string("http://evil.example.com/gate.php")
        g_score, g_cat = score_string("This program cannot be run in DOS mode")
        self.assertTrue(s_cat.startswith("suspicious"))
        self.assertEqual(g_cat, "goodware")
        self.assertGreater(s_score, g_score)

    def test_winapi_detected(self):
        _, cat = score_string("CreateRemoteThread")
        self.assertEqual(cat, "suspicious:winapi")

    def test_noise_downweighted(self):
        noise, _ = score_string("zzzzzzzzzzzz")
        normal, _ = score_string("ConfigLoader")
        self.assertLess(noise, normal)


class TestExtraction(unittest.TestCase):
    def test_finds_ascii_and_wide(self):
        finds = extract_strings(SAMPLE)
        values = {f.value for f in finds}
        self.assertIn("VirtualAllocEx", values)
        self.assertIn("WideSecret", values)
        encs = {f.encoding for f in finds}
        self.assertIn("ascii", encs)
        self.assertIn("wide", encs)

    def test_severity_levels(self):
        finds = extract_strings(SAMPLE)
        sevs = {f.severity for f in finds}
        self.assertIn("high", sevs)


class TestRuleGeneration(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()

    def test_rule_structure(self):
        path = _write_sample(self.tmp)
        rep = analyze_sample(path)
        self.assertTrue(rep.rule_name.startswith("YARAGEN_"))
        self.assertIn("rule ", rep.rule_text)
        self.assertIn("strings:", rep.rule_text)
        self.assertIn("condition:", rep.rule_text)
        self.assertIn(rep.sha256, rep.rule_text)
        # suspicious anchors present
        self.assertIn("VirtualAllocEx", rep.rule_text)

    def test_quotes_escaped(self):
        path = _write_sample(self.tmp, "q.bin", b'value with "quotes" inside here\n')
        rep = analyze_sample(path)
        self.assertNotIn('"quotes"', rep.rule_text.replace('\\"', ""))
        self.assertIn('\\"quotes\\"', rep.rule_text)

    def test_empty_sample_safe(self):
        path = _write_sample(self.tmp, "empty.bin", b"")
        rep = analyze_sample(path)
        self.assertIn("condition:", rep.rule_text)


class TestCLI(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.path = _write_sample(self.tmp)

    def test_json_output_and_exit(self):
        out_path = os.path.join(self.tmp, "r.json")
        rc = main(["generate", self.path, "--format", "json", "-o", out_path])
        # high-severity present -> non-zero
        self.assertEqual(rc, 1)
        with open(out_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["tool"], "yaragen")
        self.assertEqual(len(data["samples"]), 1)
        self.assertIn("rule", data["samples"][0])

    def test_html_output(self):
        rep = analyze_sample(self.path)
        html = _render_html([rep])
        self.assertIn("<!doctype html>", html)
        self.assertIn("YARAGEN", html)
        self.assertIn("severity", html)

    def test_no_args_returns_2(self):
        self.assertEqual(main([]), 2)

    def test_missing_file_returns_2(self):
        rc = main(["generate", os.path.join(self.tmp, "nope.bin")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
