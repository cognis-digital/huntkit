"""Core IOCREP engine: classify, score, and explain indicators of compromise.

Standard library only. Offline by design — every signal is derived from the
indicator string itself or from local reputation/allow lists supplied by the
operator. No DNS, no WHOIS, no remote lookups.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Severity scale
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = ["allow", "clean", "low", "medium", "high", "critical"]

# Score thresholds (0-100) mapped to a severity verdict.
def _severity_for_score(score: int, allowlisted: bool) -> str:
    if allowlisted:
        return "allow"
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "clean"


# --------------------------------------------------------------------------- #
# Indicator classification
# --------------------------------------------------------------------------- #
_HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.IGNORECASE)

# Defanged notation commonly found in threat reports: hxxp, [.], (.), [at]
_DEFANG_SUBS = [
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("[dot]", "."),
    (" dot ", "."),
]

# Suspicious TLDs frequently abused for malware / phishing infrastructure.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "click", "country", "kim", "work", "party", "review", "su",
}

# Keywords commonly seen in phishing / credential-harvest hostnames.
PHISHING_KEYWORDS = [
    "login", "secure", "account", "verify", "update", "signin",
    "webscr", "banking", "confirm", "wallet", "support", "recover",
]


def refang(value: str) -> str:
    """Convert defanged IOC notation back to its canonical form."""
    out = value.strip()
    low = out.lower()
    for fanged, real in _DEFANG_SUBS:
        if fanged in low:
            # case-insensitive replace preserving structure for [.] style tokens
            out = re.sub(re.escape(fanged), real, out, flags=re.IGNORECASE)
            low = out.lower()
    return out


def classify_indicator(raw: str) -> Tuple[str, str]:
    """Return (kind, normalized_value) for an indicator string.

    kind is one of: ip, ipv6, domain, url, email, md5, sha1, sha256, unknown.
    """
    value = refang(raw)
    # hashes first (most specific)
    for name, rx in _HASH_RE.items():
        if rx.match(value):
            return name, value.lower()
    if _EMAIL_RE.match(value):
        return "email", value.lower()
    if _URL_RE.match(value):
        return "url", value
    # IP addresses
    try:
        ip = ipaddress.ip_address(value)
        return ("ipv6" if ip.version == 6 else "ip"), str(ip)
    except ValueError:
        pass
    if _DOMAIN_RE.match(value):
        return "domain", value.lower()
    return "unknown", value


def _host_of(value: str, kind: str) -> str:
    """Extract the hostname/registrable portion for domain/url/email indicators."""
    if kind == "email":
        return value.split("@", 1)[1]
    if kind == "url":
        m = re.match(r"^[a-zA-Z][\w+.\-]*://([^/?#]+)", value)
        host = m.group(1) if m else value
        # strip credentials and port
        host = host.split("@")[-1].split(":")[0]
        return host.lower()
    return value


def _tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- #
# Reputation database (offline feeds)
# --------------------------------------------------------------------------- #
@dataclass
class ReputationDB:
    """Offline reputation store loaded from local JSON.

    JSON shape (all keys optional)::

        {
          "blocklist": {"1.2.3.4": {"category": "c2", "weight": 90,
                                     "source": "internal", "note": "..."}},
          "allowlist": ["microsoft.com", "8.8.8.8"]
        }

    Blocklist entries may also be a bare string (treated as a category).
    """

    blocklist: Dict[str, dict] = field(default_factory=dict)
    allowlist: set = field(default_factory=set)

    @classmethod
    def load(cls, path: Optional[str]) -> "ReputationDB":
        if not path:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        block_raw = data.get("blocklist", {}) or {}
        block: Dict[str, dict] = {}
        for key, val in block_raw.items():
            if isinstance(val, str):
                val = {"category": val, "weight": 80}
            val.setdefault("category", "malicious")
            val.setdefault("weight", 80)
            block[key.lower()] = val
        allow = {str(a).lower() for a in (data.get("allowlist", []) or [])}
        return cls(blocklist=block, allowlist=allow)

    def lookup(self, candidates: List[str]) -> Optional[Tuple[str, dict]]:
        for cand in candidates:
            hit = self.blocklist.get(cand.lower())
            if hit:
                return cand, hit
        return None

    def is_allowed(self, candidates: List[str]) -> Optional[str]:
        for cand in candidates:
            if cand.lower() in self.allowlist:
                return cand
        return None


# --------------------------------------------------------------------------- #
# Verdict & Indicator data structures
# --------------------------------------------------------------------------- #
@dataclass
class Reason:
    signal: str
    detail: str
    points: int


@dataclass
class Indicator:
    raw: str
    kind: str
    value: str


@dataclass
class Verdict:
    indicator: Indicator
    score: int
    severity: str
    allowlisted: bool
    reasons: List[Reason]

    def to_dict(self) -> dict:
        return {
            "raw": self.indicator.raw,
            "kind": self.indicator.kind,
            "value": self.indicator.value,
            "score": self.score,
            "severity": self.severity,
            "allowlisted": self.allowlisted,
            "reasons": [
                {"signal": r.signal, "detail": r.detail, "points": r.points}
                for r in self.reasons
            ],
        }


# --------------------------------------------------------------------------- #
# Scoring engine
# --------------------------------------------------------------------------- #
def _ip_signals(value: str, kind: str) -> List[Reason]:
    reasons: List[Reason] = []
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return reasons
    if ip.is_private:
        reasons.append(Reason("private_ip", "RFC1918/local-scope address", -20))
    if ip.is_loopback:
        reasons.append(Reason("loopback", "loopback address", -30))
    if ip.is_multicast:
        reasons.append(Reason("multicast", "multicast address", 5))
    if getattr(ip, "is_reserved", False):
        reasons.append(Reason("reserved", "reserved address space", 10))
    return reasons


def _host_signals(host: str) -> List[Reason]:
    reasons: List[Reason] = []
    if not host:
        return reasons
    tld = _tld_of(host)
    if tld in SUSPICIOUS_TLDS:
        reasons.append(Reason("suspicious_tld",
                              f".{tld} is a frequently abused TLD", 25))
    labels = host.split(".")
    if len(labels) >= 5:
        reasons.append(Reason("deep_subdomain",
                              f"{len(labels)} labels — deep subdomain nesting", 15))
    low = host.lower()
    for kw in PHISHING_KEYWORDS:
        if kw in low:
            reasons.append(Reason("phishing_keyword",
                                  f"hostname contains '{kw}'", 18))
            break
    if "xn--" in low:
        reasons.append(Reason("punycode",
                              "IDN/punycode label — possible homograph", 20))
    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", host) or \
       re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        reasons.append(Reason("ip_literal_host",
                              "IP-literal embedded in hostname", 12))
    longest = max(labels, key=len)
    ent = _shannon_entropy(longest)
    if len(longest) >= 12 and ent >= 3.6:
        reasons.append(Reason("high_entropy",
                              f"label '{longest[:16]}…' entropy={ent:.2f} (DGA-like)",
                              22))
    return reasons


def _url_signals(value: str) -> List[Reason]:
    reasons: List[Reason] = []
    low = value.lower()
    if low.startswith("http://"):
        reasons.append(Reason("cleartext_http", "unencrypted http:// scheme", 8))
    if "@" in value.split("://", 1)[-1].split("/")[0]:
        reasons.append(Reason("url_credentials",
                              "credentials/@ in URL authority (obfuscation)", 20))
    if re.search(r"%[0-9a-fA-F]{2}", value):
        reasons.append(Reason("url_encoding",
                              "percent-encoding present in URL", 6))
    suspicious_ext = re.search(
        r"\.(exe|scr|js|vbs|ps1|hta|jar|bat|cmd|dll|lnk)(\?|$)", low)
    if suspicious_ext:
        reasons.append(Reason("executable_payload",
                              f"URL ends in risky .{suspicious_ext.group(1)} payload",
                              28))
    return reasons


def score_indicator(raw: str, db: Optional[ReputationDB] = None) -> Verdict:
    """Score a single indicator and return an explainable Verdict."""
    db = db or ReputationDB()
    kind, value = classify_indicator(raw)
    indicator = Indicator(raw=raw, kind=kind, value=value)
    reasons: List[Reason] = []

    # Candidate keys used for both block- and allow-list matching.
    host = _host_of(value, kind) if kind in ("url", "email", "domain") else ""
    candidates = [value]
    if host and host != value:
        candidates.append(host)
    # add parent domains for hostname matches (e.g. a.b.evil.com -> evil.com)
    if host:
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            candidates.append(".".join(parts[i:]))

    allowed_by = db.is_allowed(candidates)
    allowlisted = allowed_by is not None
    if allowlisted:
        reasons.append(Reason("allowlist",
                              f"matches allowlist entry '{allowed_by}'", -100))

    hit = db.lookup(candidates)
    if hit:
        matched, meta = hit
        weight = int(meta.get("weight", 80))
        cat = meta.get("category", "malicious")
        src = meta.get("source", "local-feed")
        note = meta.get("note")
        detail = f"'{matched}' on blocklist [{cat}] via {src}"
        if note:
            detail += f" — {note}"
        reasons.append(Reason("blocklist_hit", detail, weight))

    # Heuristic signals (apply regardless; allowlist still wins at the end).
    if kind in ("ip", "ipv6"):
        reasons.extend(_ip_signals(value, kind))
    if kind in ("domain", "url", "email"):
        reasons.extend(_host_signals(host))
    if kind == "url":
        reasons.extend(_url_signals(value))
    if kind == "unknown":
        reasons.append(Reason("unparseable",
                              "could not classify as a known IOC type", 5))

    # Aggregate. Allowlist forces a clean verdict.
    raw_score = sum(r.points for r in reasons)
    score = max(0, min(100, raw_score))
    if allowlisted:
        score = 0
    severity = _severity_for_score(score, allowlisted)

    return Verdict(
        indicator=indicator,
        score=score,
        severity=severity,
        allowlisted=allowlisted,
        reasons=reasons,
    )


def score_batch(values: List[str], db: Optional[ReputationDB] = None) -> List[Verdict]:
    db = db or ReputationDB()
    return [score_indicator(v, db) for v in values if v.strip()]
