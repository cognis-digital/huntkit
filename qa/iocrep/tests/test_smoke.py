"""Smoke tests for IOCREP — offline, no network."""
import json
import os
import tempfile
import unittest

from iocrep import (
    TOOL_NAME,
    TOOL_VERSION,
    ReputationDB,
    classify_indicator,
    score_indicator,
    score_batch,
)
from iocrep.cli import main, render_html, render_json, render_table
from iocrep.core import refang


class TestClassify(unittest.TestCase):
    def test_kinds(self):
        cases = {
            "8.8.8.8": "ip",
            "2001:4860:4860::8888": "ipv6",
            "evil.example.com": "domain",
            "http://evil.example/x": "url",
            "bad@phish.test": "email",
            "44d88612fea8a8f36de82e1278abb02f": "md5",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "sha256",
            "not a real ioc!!": "unknown",
        }
        for raw, kind in cases.items():
            self.assertEqual(classify_indicator(raw)[0], kind, raw)

    def test_refang(self):
        self.assertEqual(refang("hxxps://bad[.]tk/x"), "https://bad.tk/x")
        self.assertEqual(refang("1.2.3.4")[0:7], "1.2.3.4")


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.db = ReputationDB(
            blocklist={
                "evil-c2.example": {"category": "c2", "weight": 95},
                "1.2.3.4": {"category": "scanner", "weight": 50},
            },
            allowlist={"trusted.example", "8.8.8.8"},
        )

    def test_blocklist_hit_is_high(self):
        v = score_indicator("http://evil-c2.example/beacon.exe", self.db)
        self.assertGreaterEqual(v.score, 80)
        self.assertIn(v.severity, ("high", "critical"))
        self.assertTrue(any(r.signal == "blocklist_hit" for r in v.reasons))

    def test_parent_domain_blocklist_match(self):
        v = score_indicator("a.b.evil-c2.example", self.db)
        self.assertTrue(any(r.signal == "blocklist_hit" for r in v.reasons))

    def test_allowlist_forces_clean(self):
        v = score_indicator("8.8.8.8", self.db)
        self.assertTrue(v.allowlisted)
        self.assertEqual(v.score, 0)
        self.assertEqual(v.severity, "allow")

    def test_heuristics_without_db(self):
        v = score_indicator("secure-login.verify.xn--abc.tk", ReputationDB())
        sigs = {r.signal for r in v.reasons}
        self.assertIn("suspicious_tld", sigs)
        self.assertIn("punycode", sigs)
        self.assertGreater(v.score, 0)

    def test_private_ip_credit(self):
        v = score_indicator("10.0.0.5", ReputationDB())
        self.assertTrue(any(r.signal == "private_ip" for r in v.reasons))
        self.assertEqual(v.severity, "clean")

    def test_clean_unknown_hash(self):
        v = score_indicator(
            "a1b9f3c7d2e4081624537890abcdef1234567890abcdef1234567890abcdef12",
            ReputationDB(),
        )
        self.assertEqual(v.severity, "clean")

    def test_batch_and_to_dict(self):
        verdicts = score_batch(["8.8.8.8", "http://evil-c2.example/x.exe"], self.db)
        self.assertEqual(len(verdicts), 2)
        d = verdicts[0].to_dict()
        self.assertIn("reasons", d)
        self.assertIn("severity", d)


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.verdicts = score_batch(
            ["http://evil[.]tk/x.exe", "8.8.8.8"],
            ReputationDB(allowlist={"8.8.8.8"}),
        )

    def test_table(self):
        out = render_table(self.verdicts)
        self.assertIn("SEVERITY", out)
        self.assertIn("Scored 2", out)

    def test_json_valid(self):
        payload = json.loads(render_json(self.verdicts))
        self.assertEqual(payload["tool"], TOOL_NAME)
        self.assertEqual(payload["count"], 2)

    def test_html_self_contained(self):
        html = render_html(self.verdicts)
        self.assertIn("<!doctype html>", html)
        self.assertIn("<style>", html)


class TestCli(unittest.TestCase):
    def test_version_constant(self):
        self.assertTrue(TOOL_VERSION)

    def test_no_args_returns_2(self):
        self.assertEqual(main([]), 2)

    def test_no_indicators_returns_2(self):
        self.assertEqual(main(["score"]), 2)

    def test_clean_exit_zero(self):
        rc = main(["score", "completely-benign-string-zzz", "--fail-on", "high"])
        self.assertEqual(rc, 0)

    def test_findings_exit_one(self):
        with tempfile.TemporaryDirectory() as d:
            dbp = os.path.join(d, "db.json")
            with open(dbp, "w", encoding="utf-8") as fh:
                json.dump({"blocklist": {"bad.example": "c2"}}, fh)
            out = os.path.join(d, "r.html")
            rc = main(["score", "http://bad.example/x", "--db", dbp,
                       "--format", "html", "-o", out])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as fh:
                self.assertIn("IOCREP", fh.read().upper())


if __name__ == "__main__":
    unittest.main()
