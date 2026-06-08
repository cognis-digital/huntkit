"""Core engine: ingest normalization + Sigma-style detection.

No third-party deps. A compact, faithful subset of Sigma detection logic:
maps of field->value with modifiers (contains, startswith, endswith, re),
lists (OR within a field), and a `condition` over named selections using
and/or/not + `1 of them` / `all of them`.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Event:
    """A normalized log event: a flat dict of string->value fields."""
    fields: Dict[str, Any]
    raw: str = ""
    source: str = ""
    lineno: int = 0

    def get(self, key: str) -> Any:
        return self.fields.get(key)


@dataclass
class Rule:
    id: str
    title: str
    level: str
    detection: Dict[str, Any]
    condition: str
    logsource: Dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class Match:
    rule_id: str
    title: str
    level: str
    source: str
    lineno: int
    event: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "source": self.source,
            "lineno": self.lineno,
            "event": self.event,
        }


# --------------------------------------------------------------------------
# Field matching with Sigma-style modifiers
# --------------------------------------------------------------------------
def _match_value(actual: Any, expected: Any, modifier: str) -> bool:
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier == "contains":
        return e.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    if modifier == "re":
        return re.search(e, a) is not None
    if modifier == "gt":
        try:
            return float(a) > float(e)
        except ValueError:
            return False
    if modifier == "lt":
        try:
            return float(a) < float(e)
        except ValueError:
            return False
    # default: case-insensitive exact
    return a.lower() == e.lower()


def _match_field(event: Event, key: str, expected: Any) -> bool:
    # key may carry a modifier: "CommandLine|contains"
    if "|" in key:
        name, modifier = key.split("|", 1)
    else:
        name, modifier = key, "eq"
    actual = event.get(name)
    if isinstance(expected, list):
        # list => OR across candidate values
        return any(_match_value(actual, v, modifier) for v in expected)
    return _match_value(actual, expected, modifier)


def _match_selection(event: Event, selection: Any) -> bool:
    # A selection is a dict (AND across keys) or a list of dicts (OR).
    if isinstance(selection, list):
        return any(_match_selection(event, s) for s in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    return False


# --------------------------------------------------------------------------
# Condition evaluation
# --------------------------------------------------------------------------
_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+")


def _eval_condition(condition: str, sel_results: Dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string against precomputed selection bools.

    Supports: and / or / not / parentheses, selection names,
    `1 of them`, `all of them`, `1 of selection*`, `all of selection*`.
    """
    cond = condition.strip()

    # Expand quantifiers into boolean literals before tokenizing.
    def _quant(match: re.Match) -> str:
        qty, pattern = match.group(1), match.group(2)
        if pattern == "them":
            names = list(sel_results)
        else:
            prefix = pattern.rstrip("*")
            names = [n for n in sel_results if n.startswith(prefix)]
        vals = [sel_results.get(n, False) for n in names]
        if qty == "all":
            ok = all(vals) if vals else False
        else:  # "1" / any
            ok = any(vals)
        return "__TRUE__" if ok else "__FALSE__"

    cond = re.sub(r"\b(all|1)\s+of\s+([A-Za-z0-9_]+\*?|them)", _quant, cond)

    tokens = _TOKEN_RE.findall(cond)
    py: List[str] = []
    for tok in tokens:
        low = tok.lower()
        if low in ("and", "or", "not"):
            py.append(low)
        elif tok in ("(", ")"):
            py.append(tok)
        elif tok == "__TRUE__":
            py.append("True")
        elif tok == "__FALSE__":
            py.append("False")
        else:
            py.append("True" if sel_results.get(tok, False) else "False")
    expr = " ".join(py) or "False"
    # Only booleans/operators/parens remain -- safe to eval.
    if not re.fullmatch(r"[\sTrueFalsandotp()]*", expr.replace("or", "")):
        # extremely defensive; should never trigger given the tokenizer
        raise ValueError(f"unsafe condition: {condition!r}")
    return bool(eval(expr, {"__builtins__": {}}, {}))


def _rule_matches(rule: Rule, event: Event) -> bool:
    sel_results: Dict[str, bool] = {}
    for name, sel in rule.detection.items():
        if name == "condition":
            continue
        sel_results[name] = _match_selection(event, sel)
    return _eval_condition(rule.condition, sel_results)


# --------------------------------------------------------------------------
# Rule parsing (minimal YAML-ish loader for our subset, or JSON)
# --------------------------------------------------------------------------
def load_rules_text(text: str) -> List[Rule]:
    """Load rules from JSON (a list of rule objects) text."""
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    return parse_rules(data)


def parse_rules(objs: Iterable[Dict[str, Any]]) -> List[Rule]:
    rules: List[Rule] = []
    for o in objs:
        det = dict(o.get("detection", {}))
        cond = det.pop("condition", o.get("condition", ""))
        if not cond:
            # default: all named selections AND'd
            cond = " and ".join(det.keys()) or "False"
        rules.append(
            Rule(
                id=str(o.get("id", o.get("title", "unknown"))),
                title=str(o.get("title", "untitled")),
                level=str(o.get("level", "medium")),
                detection=det,
                condition=cond,
                logsource=o.get("logsource", {}) or {},
                description=str(o.get("description", "")),
            )
        )
    return rules


# --------------------------------------------------------------------------
# Ingest / normalization
# --------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+"
    r"(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_APACHE_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def _normalize_line(line: str) -> Dict[str, Any]:
    s = line.strip()
    if not s:
        return {}
    # 1) JSON line (incl. Windows EVTX export / structured logs)
    if s[0] in "{[":
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return _flatten(obj)
        except json.JSONDecodeError:
            pass
    # 2) Apache/Nginx combined access log
    m = _APACHE_RE.match(s)
    if m:
        d = {k: v for k, v in m.groupdict().items() if v is not None}
        d["_logtype"] = "web"
        return d
    # 3) Syslog
    m = _SYSLOG_RE.match(s)
    if m:
        d = m.groupdict()
        d = {k: v for k, v in d.items() if v is not None}
        d["_logtype"] = "syslog"
        return d
    # 4) Fallback: opaque message
    return {"message": s, "_logtype": "raw"}


def _flatten(obj: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, prefix=f"{key}."))
        else:
            out[key] = v
            if prefix:  # also expose leaf name unqualified for convenience
                out.setdefault(k, v)
    return out


def ingest_lines(lines: Iterable[str], source: str = "") -> List[Event]:
    events: List[Event] = []
    for i, line in enumerate(lines, start=1):
        fields = _normalize_line(line)
        if not fields:
            continue
        events.append(Event(fields=fields, raw=line.rstrip("\n"),
                            source=source, lineno=i))
    return events


def ingest_text(text: str, source: str = "") -> List[Event]:
    return ingest_lines(text.splitlines(), source=source)


# --------------------------------------------------------------------------
# Detection driver
# --------------------------------------------------------------------------
def detect(events: Iterable[Event], rules: Iterable[Rule]) -> List[Match]:
    rules = list(rules)
    matches: List[Match] = []
    for ev in events:
        for rule in rules:
            if _rule_matches(rule, ev):
                matches.append(
                    Match(
                        rule_id=rule.id,
                        title=rule.title,
                        level=rule.level,
                        source=ev.source,
                        lineno=ev.lineno,
                        event=ev.fields,
                    )
                )
    return matches


# --------------------------------------------------------------------------
# Built-in starter rule pack
# --------------------------------------------------------------------------
BUILTIN_RULES: List[Rule] = parse_rules([
    {
        "id": "ssh_bruteforce_failed",
        "title": "SSH failed password (possible brute force)",
        "level": "medium",
        "detection": {
            "sel": {"program": "sshd", "message|contains": "Failed password"},
            "condition": "sel",
        },
    },
    {
        "id": "sudo_su_root",
        "title": "Privilege escalation to root via su",
        "level": "high",
        "detection": {
            "sel": {"message|contains": "session opened for user root"},
            "condition": "sel",
        },
    },
    {
        "id": "web_sqli_attempt",
        "title": "Web SQL injection attempt in URL",
        "level": "high",
        "detection": {
            "sel": {"url|contains": ["union+select", "' or '1'='1", "%27", "information_schema"]},
            "condition": "sel",
        },
    },
    {
        "id": "web_path_traversal",
        "title": "Web path traversal attempt",
        "level": "high",
        "detection": {
            "sel": {"url|contains": ["../", "..%2f", "/etc/passwd"]},
            "condition": "sel",
        },
    },
    {
        "id": "win_suspicious_powershell",
        "title": "Suspicious PowerShell command line",
        "level": "high",
        "detection": {
            "img": {"Image|endswith": "powershell.exe"},
            "flags": {"CommandLine|contains": ["-enc", "-EncodedCommand", "DownloadString", "FromBase64String", "-w hidden"]},
            "condition": "img and flags",
        },
    },
    {
        "id": "web_5xx_burst",
        "title": "Server error response (5xx)",
        "level": "low",
        "detection": {
            "sel": {"status|startswith": "5"},
            "condition": "sel",
        },
    },
])
