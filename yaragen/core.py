"""Core engine for YARAGEN.

Pure standard-library logic that turns sample bytes into candidate YARA
rules. Designed for DEFENSIVE use: triage / detection-engineering on
artifacts you own. No network, no execution of samples.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
MIN_STR_LEN = 6
MAX_STR_LEN = 128
DEFAULT_TOP = 20

# Substrings that are common/boilerplate -> low value as a detection anchor.
_GOODWARE_HINTS = (
    "microsoft", "windows", "kernel32", "advapi32", "user32", "msvcrt",
    "kernel.dll", "this program cannot be run", "<!doctype", "<html",
    "http://schemas", "copyright", "gcc:", "/usr/lib", "libc.so",
    "assembly", "manifestversion", "mscoree.dll",
)

# Patterns that are HIGH value -> suspicious / distinctive indicators.
_SUSPICIOUS_PATTERNS = (
    (re.compile(rb"https?://[\w./?=&%:\-]+", re.I), "url"),
    (re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "ipv4"),
    (re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"), "base64_blob"),
    (re.compile(rb"(?:cmd\.exe|powershell|/bin/sh|/bin/bash|wscript|rundll32)", re.I), "lolbin"),
    (re.compile(rb"(?:CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|"
                rb"LoadLibrary|GetProcAddress|WinExec|ShellExecute)", re.I), "winapi"),
    (re.compile(rb"\\(?:Temp|AppData|ProgramData|Startup)\\", re.I), "fs_path"),
    (re.compile(rb"(?:HKEY_|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)", re.I), "registry"),
    (re.compile(rb"-----BEGIN [A-Z ]+-----"), "pem_key"),
)

_PRINTABLE = set(bytes(string.printable, "ascii")) - set(b"\t\n\r\x0b\x0c")


@dataclass
class Finding:
    """One candidate string indicator extracted from a sample."""
    value: str
    encoding: str          # "ascii" | "wide"
    offset: int
    score: float
    category: str          # "suspicious:<kind>" | "generic" | "goodware"
    entropy: float

    @property
    def severity(self) -> str:
        if self.category.startswith("suspicious"):
            return "high"
        if self.category == "goodware":
            return "low"
        return "medium"

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "encoding": self.encoding,
            "offset": self.offset,
            "score": round(self.score, 3),
            "category": self.category,
            "severity": self.severity,
            "entropy": round(self.entropy, 3),
        }


@dataclass
class SampleReport:
    path: str
    size: int
    md5: str
    sha256: str
    findings: list[Finding] = field(default_factory=list)
    rule_name: str = ""
    rule_text: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "md5": self.md5,
            "sha256": self.sha256,
            "rule_name": self.rule_name,
            "findings": [f.to_dict() for f in self.findings],
            "rule": self.rule_text,
        }


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _ascii_strings(data: bytes):
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            if not cur:
                start = i
            cur.append(b)
        else:
            if MIN_STR_LEN <= len(cur) <= MAX_STR_LEN:
                yield cur.decode("ascii"), "ascii", start
            cur = bytearray()
    if MIN_STR_LEN <= len(cur) <= MAX_STR_LEN:
        yield cur.decode("ascii"), "ascii", start


def _wide_strings(data: bytes):
    """UTF-16LE-style strings: printable byte followed by 0x00."""
    cur = bytearray()
    start = 0
    i = 0
    n = len(data)
    while i + 1 < n:
        b, nxt = data[i], data[i + 1]
        if b in _PRINTABLE and nxt == 0:
            if not cur:
                start = i
            cur.append(b)
            i += 2
        else:
            if MIN_STR_LEN <= len(cur) <= MAX_STR_LEN:
                yield cur.decode("ascii"), "wide", start
            cur = bytearray()
            i += 1
    if MIN_STR_LEN <= len(cur) <= MAX_STR_LEN:
        yield cur.decode("ascii"), "wide", start


def extract_strings(data: bytes) -> list[Finding]:
    """Extract candidate ascii + wide strings and score each."""
    seen: dict[tuple, Finding] = {}
    for value, enc, off in list(_ascii_strings(data)) + list(_wide_strings(data)):
        key = (value, enc)
        if key in seen:
            continue
        score, category = score_string(value)
        ent = shannon_entropy(value.encode("ascii", "ignore"))
        seen[key] = Finding(
            value=value, encoding=enc, offset=off,
            score=score, category=category, entropy=ent,
        )
    return list(seen.values())


def score_string(value: str) -> tuple[float, str]:
    """Heuristic value of a string as a detection anchor.

    Returns (score, category). Higher score == more distinctive.
    """
    raw = value.encode("ascii", "ignore")
    low = value.lower()

    # Goodware / boilerplate -> demote.
    for hint in _GOODWARE_HINTS:
        if hint in low:
            return 0.5, "goodware"

    # Suspicious indicators -> promote.
    for rx, kind in _SUSPICIOUS_PATTERNS:
        if rx.search(raw):
            base = 8.0
            base += min(len(value) / 32.0, 2.0)
            return round(base, 3), f"suspicious:{kind}"

    # Generic scoring: length + entropy + character diversity.
    score = 1.0
    score += min(len(value) / 16.0, 3.0)
    ent = shannon_entropy(raw)
    score += min(ent / 2.0, 2.0)
    diversity = len(set(value)) / max(len(value), 1)
    score += diversity * 2.0
    # Penalize pure-repeat / pure-numeric noise.
    if len(set(value)) <= 2:
        score *= 0.3
    if value.isdigit():
        score *= 0.5
    return round(score, 3), "generic"


# ---------------------------------------------------------------------------
# Analysis + rule generation
# ---------------------------------------------------------------------------
def _hashes(data: bytes) -> tuple[str, str]:
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


def _safe_rule_name(path: str) -> str:
    base = os.path.basename(path) or "sample"
    stem = os.path.splitext(base)[0]
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", stem).strip("_")
    if not cleaned or cleaned[0].isdigit():
        cleaned = "gen_" + cleaned
    return "YARAGEN_" + cleaned


def analyze_sample(path: str, top: int = DEFAULT_TOP) -> SampleReport:
    with open(path, "rb") as fh:
        data = fh.read()
    md5, sha256 = _hashes(data)
    findings = extract_strings(data)
    # Best findings first; suspicious always beats generic via score.
    findings.sort(key=lambda f: f.score, reverse=True)
    findings = findings[:top]
    rep = SampleReport(
        path=path, size=len(data), md5=md5, sha256=sha256, findings=findings,
    )
    rep.rule_name = _safe_rule_name(path)
    rep.rule_text = generate_rule(rep)
    return rep


def _yara_escape(value: str) -> str:
    out = value.replace("\\", "\\\\").replace('"', '\\"')
    return out


def generate_rule(report: SampleReport) -> str:
    """Emit a candidate YARA rule from a report's findings."""
    name = report.rule_name
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    susp = [f for f in report.findings if f.category.startswith("suspicious")]
    others = [f for f in report.findings if not f.category.startswith("suspicious")
              and f.category != "goodware"]

    str_lines = []
    cond_susp = []
    cond_other = []
    idx = 0
    for f in susp:
        mod = " wide" if f.encoding == "wide" else " ascii"
        kind = f.category.split(":", 1)[1]
        str_lines.append(f'        $s{idx} = "{_yara_escape(f.value)}"{mod}  // {kind}')
        cond_susp.append(f"$s{idx}")
        idx += 1
    for f in others:
        mod = " wide" if f.encoding == "wide" else " ascii"
        str_lines.append(f'        $g{idx} = "{_yara_escape(f.value)}"{mod}')
        cond_other.append(f"$g{idx}")
        idx += 1

    if not str_lines:
        str_lines.append('        $h = { 00 }  // no distinctive strings found; review manually')
        cond_susp = ["$h"]

    # Condition: hash anchor OR a meaningful combination of indicators.
    cond_parts = []
    if cond_susp:
        # Any suspicious indicator is a strong signal.
        cond_parts.append("any of (" + ", ".join(cond_susp) + ")" if len(cond_susp) > 1 else cond_susp[0])
    if cond_other:
        need = max(2, math.ceil(len(cond_other) * 0.6))
        cond_parts.append(f"{need} of ({', '.join(cond_other)})")
    condition = " or ".join(cond_parts) if cond_parts else "any of them"

    strings_block = "\n".join(str_lines)
    rule = f"""rule {name}
{{
    meta:
        author = "yaragen"
        description = "Auto-generated candidate rule (REVIEW BEFORE USE)"
        date = "{now}"
        source_file = "{os.path.basename(report.path)}"
        md5 = "{report.md5}"
        sha256 = "{report.sha256}"
        file_size = {report.size}
        yaragen_note = "Heuristic draft for defensive triage; tune to reduce FPs."

    strings:
{strings_block}

    condition:
        {condition}
}}
"""
    return rule
