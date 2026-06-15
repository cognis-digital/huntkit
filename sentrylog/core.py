"""SENTRYLOG core — Sigma-style detection engine over JSON/CSV log events.

This module bundles ~25 real Sigma-style detection rules (in a compact
embedded YAML dialect) and a working matcher that evaluates them against
structured log events loaded from JSON, JSON-lines or CSV. Each rule carries
a MITRE ATT&CK technique mapping so findings are immediately actionable.

In the spirit of SigmaHQ/sigma, the engine implements the core of the Sigma
detection model:

    * ``detection`` blocks made of named *selections* (maps of
      ``field|modifier: value``) plus a ``condition`` expression.
    * field value modifiers: ``contains``, ``startswith``, ``endswith``,
      ``re`` (regex), ``all`` (every value must match), ``cidr``, ``gt/gte/lt/lte``.
    * a boolean ``condition`` mini-language: ``and`` / ``or`` / ``not``,
      parentheses, ``1 of selection*`` / ``all of selection*`` quantifiers and
      ``them``.

Standard library only, zero install.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "sentrylog"
TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Bundled rules — a compact Sigma-style YAML dialect.
#
# Each document is separated by a line containing only "---". The dialect
# supports nested maps (2-space indent), lists ("- item"), and scalar values.
# This is deliberately a real, useful pack covering Windows, Linux, cloud and
# web telemetry, each mapped to a MITRE ATT&CK technique.
# --------------------------------------------------------------------------- #
BUNDLED_RULES = r"""
title: Suspicious PowerShell Encoded Command
id: win-ps-encoded
level: high
logsource: windows/process_creation
mitre: T1059.001
description: PowerShell launched with an encoded command, a common obfuscation.
detection:
  sel:
    Image|endswith: \powershell.exe
    CommandLine|contains:
      - -enc
      - -EncodedCommand
      - -e JAB
  condition: sel
---
title: PowerShell Download Cradle
id: win-ps-download-cradle
level: high
logsource: windows/process_creation
mitre: T1059.001
description: In-memory download and execute via .NET WebClient or IEX.
detection:
  sel:
    Image|endswith: \powershell.exe
    CommandLine|contains|all:
      - DownloadString
      - IEX
  net:
    CommandLine|contains:
      - Net.WebClient
      - Invoke-WebRequest
      - iwr
  condition: sel or net
---
title: Mimikatz Credential Dumping Keywords
id: cred-mimikatz
level: critical
logsource: windows/process_creation
mitre: T1003.001
description: Command line contains classic Mimikatz module syntax.
detection:
  sel:
    CommandLine|contains:
      - sekurlsa::logonpasswords
      - lsadump::sam
      - privilege::debug
      - mimikatz
  condition: sel
---
title: LSASS Process Access Dump
id: cred-lsass-dump
level: critical
logsource: windows/process_creation
mitre: T1003.001
description: Dumping LSASS memory via comsvcs or procdump.
detection:
  comsvcs:
    CommandLine|contains|all:
      - comsvcs.dll
      - MiniDump
  procdump:
    Image|endswith: \procdump.exe
    CommandLine|contains: lsass
  condition: comsvcs or procdump
---
title: Disable Windows Defender via Registry or PowerShell
id: def-disable-defender
level: high
logsource: windows/process_creation
mitre: T1562.001
description: Tampering with Defender real-time protection.
detection:
  reg:
    CommandLine|contains|all:
      - DisableRealtimeMonitoring
      - $true
  pref:
    CommandLine|contains: Set-MpPreference
  condition: reg or pref
---
title: Clear Windows Event Logs
id: def-clear-eventlog
level: high
logsource: windows/process_creation
mitre: T1070.001
description: Attacker wiping event logs to cover tracks.
detection:
  wevtutil:
    Image|endswith: \wevtutil.exe
    CommandLine|contains: cl
  ps:
    CommandLine|contains: Clear-EventLog
  condition: wevtutil or ps
---
title: Scheduled Task Creation for Persistence
id: persist-schtasks
level: medium
logsource: windows/process_creation
mitre: T1053.005
description: schtasks used to create a new task.
detection:
  sel:
    Image|endswith: \schtasks.exe
    CommandLine|contains: /create
  condition: sel
---
title: New Service Installed via sc.exe
id: persist-new-service
level: medium
logsource: windows/process_creation
mitre: T1543.003
description: Service creation, often used for persistence or lateral movement.
detection:
  sel:
    Image|endswith: \sc.exe
    CommandLine|contains: create
  condition: sel
---
title: Run Key Persistence via reg.exe
id: persist-run-key
level: medium
logsource: windows/process_creation
mitre: T1547.001
description: Writing to a Run/RunOnce autostart key.
detection:
  sel:
    Image|endswith: \reg.exe
    CommandLine|contains|all:
      - ADD
      - CurrentVersion\Run
  condition: sel
---
title: BITSAdmin Download
id: ingress-bitsadmin
level: medium
logsource: windows/process_creation
mitre: T1197
description: bitsadmin used to transfer a remote file.
detection:
  sel:
    Image|endswith: \bitsadmin.exe
    CommandLine|contains:
      - /transfer
      - /addfile
  condition: sel
---
title: Certutil Download or Decode
id: ingress-certutil
level: high
logsource: windows/process_creation
mitre: T1140
description: certutil abused to download or decode payloads.
detection:
  sel:
    Image|endswith: \certutil.exe
    CommandLine|contains:
      - -urlcache
      - -decode
      - -decodehex
  condition: sel
---
title: Rundll32 Suspicious Execution
id: exec-rundll32-js
level: high
logsource: windows/process_creation
mitre: T1218.011
description: rundll32 used as a proxy to run script protocols.
detection:
  sel:
    Image|endswith: \rundll32.exe
    CommandLine|contains:
      - javascript:
      - vbscript:
      - mshtml
  condition: sel
---
title: Regsvr32 Squiblydoo
id: exec-regsvr32-sct
level: high
logsource: windows/process_creation
mitre: T1218.010
description: regsvr32 loading a remote .sct scriptlet (Squiblydoo).
detection:
  sel:
    Image|endswith: \regsvr32.exe
    CommandLine|contains:
      - scrobj.dll
      - /i:http
  condition: sel
---
title: WMI Process Creation Lateral Movement
id: lateral-wmic-process
level: medium
logsource: windows/process_creation
mitre: T1047
description: wmic spawning a remote process.
detection:
  sel:
    Image|endswith: \wmic.exe
    CommandLine|contains|all:
      - process
      - call
      - create
  condition: sel
---
title: PsExec Service Execution
id: lateral-psexec
level: medium
logsource: windows/process_creation
mitre: T1569.002
description: PsExec/PSEXESVC indicates remote execution.
detection:
  img:
    Image|endswith:
      - \psexec.exe
      - \psexesvc.exe
  cmd:
    CommandLine|contains: -accepteula
  condition: img or cmd
---
title: Office Application Spawning Shell
id: exec-office-child-shell
level: high
logsource: windows/process_creation
mitre: T1059.003
description: Word/Excel/Outlook spawning a command interpreter (macro abuse).
detection:
  parent:
    ParentImage|endswith:
      - \winword.exe
      - \excel.exe
      - \outlook.exe
      - \powerpnt.exe
  child:
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
      - \wscript.exe
      - \cscript.exe
  condition: parent and child
---
title: User Added to Local Administrators Group
id: persist-net-localadmin
level: high
logsource: windows/process_creation
mitre: T1136.001
description: net.exe adding an account to Administrators.
detection:
  sel:
    Image|endswith: \net.exe
    CommandLine|contains|all:
      - localgroup
      - administrators
      - /add
  condition: sel
---
title: Shadow Copy Deletion (Ransomware Precursor)
id: impact-vss-delete
level: critical
logsource: windows/process_creation
mitre: T1490
description: Deleting volume shadow copies to inhibit recovery.
detection:
  vssadmin:
    CommandLine|contains|all:
      - vssadmin
      - delete
      - shadows
  wmic:
    CommandLine|contains|all:
      - wmic
      - shadowcopy
      - delete
  condition: vssadmin or wmic
---
title: Linux Reverse Shell One-Liner
id: linux-reverse-shell
level: high
logsource: linux/process_creation
mitre: T1059.004
description: Common bash/python/nc reverse-shell patterns.
detection:
  bash:
    CommandLine|contains:
      - bash -i >& /dev/tcp/
      - sh -i >& /dev/tcp/
  nc:
    CommandLine|re:
      - '\bnc(\.traditional)?\b.*\s-e\b'
      - '\bncat\b.*\s-e\b'
  py:
    CommandLine|contains|all:
      - python
      - socket
      - subprocess
  condition: bash or nc or py
---
title: Linux Persistence via Cron
id: linux-cron-persist
level: medium
logsource: linux/process_creation
mitre: T1053.003
description: Writing to crontab or cron.d for persistence.
detection:
  sel:
    CommandLine|contains:
      - crontab -
      - /etc/cron.d/
      - /var/spool/cron/
  condition: sel
---
title: Linux Sensitive File Read
id: linux-sensitive-read
level: medium
logsource: linux/process_creation
mitre: T1003.008
description: Reading shadow/passwd, possible credential access.
detection:
  sel:
    CommandLine|contains:
      - /etc/shadow
      - /etc/passwd
  reads:
    CommandLine|contains:
      - cat
      - less
      - cp
  condition: sel and reads
---
title: SSH Brute Force Failed Logins
id: linux-ssh-bruteforce
level: medium
logsource: linux/auth
mitre: T1110.001
description: Repeated failed SSH password authentications from one source.
detection:
  sel:
    program: sshd
    message|contains: Failed password
  condition: sel
---
title: AWS Root Account Usage
id: cloud-aws-root
level: high
logsource: cloud/aws/cloudtrail
mitre: T1078.004
description: Activity performed by the AWS account root user.
detection:
  sel:
    userIdentity.type: Root
  notconsole:
    eventName: ConsoleLogin
  condition: sel and not notconsole
---
title: AWS CloudTrail Logging Stopped
id: cloud-aws-stoptrail
level: critical
logsource: cloud/aws/cloudtrail
mitre: T1562.008
description: Disabling/deleting CloudTrail to evade detection.
detection:
  sel:
    eventSource: cloudtrail.amazonaws.com
    eventName:
      - StopLogging
      - DeleteTrail
  condition: sel
---
title: AWS Security Group Opened to World
id: cloud-aws-open-sg
level: high
logsource: cloud/aws/cloudtrail
mitre: T1562.007
description: Ingress rule authorized for 0.0.0.0/0.
detection:
  sel:
    eventName: AuthorizeSecurityGroupIngress
    requestParameters|contains: 0.0.0.0/0
  condition: sel
---
title: Web Path Traversal Attempt
id: web-path-traversal
level: medium
logsource: web/access
mitre: T1190
description: Directory traversal sequences in the request URI.
detection:
  sel:
    request|contains:
      - ../../
      - ..%2f
      - %2e%2e%2f
      - /etc/passwd
  condition: sel
---
title: Web SQL Injection Probe
id: web-sqli
level: high
logsource: web/access
mitre: T1190
description: SQL injection signatures in query string.
detection:
  sel:
    request|contains:
      - ' UNION SELECT
      - ' OR '1'='1
      - sleep(
      - information_schema
  condition: sel
---
title: Outbound Connection to Suspicious Port
id: net-suspicious-port
level: low
logsource: network/connection
mitre: T1571
description: Egress to ports commonly used by C2 or tunneling.
detection:
  sel:
    dst_port:
      - 4444
      - 1337
      - 8443
      - 9001
  condition: sel
"""


# --------------------------------------------------------------------------- #
# Minimal YAML parser (subset used by the bundled rules / user rules).
# --------------------------------------------------------------------------- #
def _coerce_scalar(text: str) -> Any:
    s = text.strip()
    if s == "":
        return ""
    if (s[0] == s[-1]) and s[0] in ("'", '"') and len(s) >= 2:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    try:
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        if re.fullmatch(r"-?\d+\.\d+", s):
            return float(s)
    except ValueError:
        pass
    return s


def _parse_block(lines: List[Tuple[int, str]], idx: int, indent: int) -> Tuple[Any, int]:
    """Parse a YAML block (map or list) starting at indentation ``indent``."""
    # Decide list vs map by first significant line at this indent.
    while idx < len(lines) and lines[idx][1].strip() == "":
        idx += 1
    if idx >= len(lines):
        return {}, idx
    ind, raw = lines[idx]
    if ind < indent:
        return {}, idx
    if raw.lstrip().startswith("- "):
        return _parse_list(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_list(lines, idx, indent):
    out: List[Any] = []
    while idx < len(lines):
        ind, raw = lines[idx]
        if raw.strip() == "":
            idx += 1
            continue
        if ind < indent or not raw.lstrip().startswith("- "):
            break
        item = raw.lstrip()[2:]
        out.append(_coerce_scalar(item))
        idx += 1
    return out, idx


def _parse_map(lines, idx, indent):
    out: Dict[str, Any] = {}
    while idx < len(lines):
        ind, raw = lines[idx]
        if raw.strip() == "":
            idx += 1
            continue
        if ind < indent:
            break
        if raw.lstrip().startswith("- "):
            break
        line = raw.strip()
        if ":" not in line:
            idx += 1
            continue
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest != "":
            out[key] = _coerce_scalar(rest)
            idx += 1
        else:
            child, idx = _parse_block(lines, idx + 1, ind + 1)
            out[key] = child
    return out, idx


def parse_yaml_documents(text: str) -> List[Dict[str, Any]]:
    """Parse one or more '---'-separated documents in the supported subset."""
    docs: List[Dict[str, Any]] = []
    for chunk in re.split(r"(?m)^---\s*$", text):
        raw_lines = chunk.split("\n")
        lines: List[Tuple[int, str]] = []
        for ln in raw_lines:
            if ln.strip() == "" or ln.lstrip().startswith("#"):
                continue
            indent = len(ln) - len(ln.lstrip(" "))
            lines.append((indent, ln))
        if not lines:
            continue
        doc, _ = _parse_map(lines, 0, lines[0][0])
        if doc:
            docs.append(doc)
    return docs


# --------------------------------------------------------------------------- #
# Rule model
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    level: str
    logsource: str
    mitre: str
    description: str
    detection: Dict[str, Any]
    condition: str

    @classmethod
    def from_doc(cls, doc: Dict[str, Any]) -> "Rule":
        det = doc.get("detection", {}) or {}
        cond = str(det.get("condition", "")).strip()
        sels = {k: v for k, v in det.items() if k != "condition"}
        return cls(
            id=str(doc.get("id", doc.get("title", "rule"))),
            title=str(doc.get("title", "untitled")),
            level=str(doc.get("level", "medium")).lower(),
            logsource=str(doc.get("logsource", "")),
            mitre=str(doc.get("mitre", "")),
            description=str(doc.get("description", "")),
            detection=sels,
            condition=cond,
        )


def load_rules(text: Optional[str] = None) -> List[Rule]:
    """Load rules from YAML text (defaults to the bundled pack)."""
    docs = parse_yaml_documents(text if text is not None else BUNDLED_RULES)
    return [Rule.from_doc(d) for d in docs]


# --------------------------------------------------------------------------- #
# Event loading
# --------------------------------------------------------------------------- #
def load_events(text: str) -> List[Dict[str, Any]]:
    """Load events from a JSON array, JSON-lines, or CSV document.

    Raises ValueError with a descriptive message on malformed JSON input.
    Returns an empty list for valid but structurally empty input.
    """
    if not text or not text.strip():
        return []
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed JSON array: {exc}") from exc
        if not isinstance(data, list):
            raise ValueError(
                f"expected a JSON array, got {type(data).__name__}"
            )
        return [d for d in data if isinstance(d, dict)]
    if stripped.startswith("{"):
        # Could be JSON-lines or a single object.
        events: List[Dict[str, Any]] = []
        ok = True
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                ok = False
                break
            if isinstance(obj, dict):
                events.append(obj)
        if ok and events:
            return events
        # Fall back to treating the whole text as a single JSON object.
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed JSON: {exc}") from exc
        return [obj] if isinstance(obj, dict) else []
    # CSV fallback — DictReader is tolerant; just handle no-header edge case.
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return []
    return [dict(row) for row in reader]


# --------------------------------------------------------------------------- #
# Field resolution + value matching
# --------------------------------------------------------------------------- #
def _resolve_field(event: Dict[str, Any], field_name: str) -> Any:
    """Resolve dotted field paths, falling back to a flat key lookup."""
    if field_name in event:
        return event[field_name]
    cur: Any = event
    for part in field_name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _match_one(value: Any, modifier: str, target: Any) -> bool:
    if modifier in ("gt", "gte", "lt", "lte"):
        try:
            lv, rv = float(value), float(target)
        except (TypeError, ValueError):
            return False
        return {"gt": lv > rv, "gte": lv >= rv, "lt": lv < rv, "lte": lv <= rv}[modifier]
    if modifier == "cidr":
        try:
            return ipaddress.ip_address(str(value)) in ipaddress.ip_network(str(target), strict=False)
        except ValueError:
            return False

    sval = _as_str(value).lower()
    starget = _as_str(target).lower()
    if modifier == "contains":
        return starget in sval
    if modifier == "startswith":
        return sval.startswith(starget)
    if modifier == "endswith":
        return sval.endswith(starget)
    if modifier == "re":
        try:
            return re.search(str(target), _as_str(value)) is not None
        except re.error:
            return False
    # exact (case-insensitive) match
    return sval == starget


def _match_field(event: Dict[str, Any], spec_key: str, spec_val: Any) -> bool:
    parts = spec_key.split("|")
    field_name = parts[0]
    modifiers = parts[1:]
    require_all = "all" in modifiers
    op = next((m for m in modifiers if m in (
        "contains", "startswith", "endswith", "re", "cidr",
        "gt", "gte", "lt", "lte")), "equals")
    value = _resolve_field(event, field_name)
    targets = spec_val if isinstance(spec_val, list) else [spec_val]
    results = [_match_one(value, op, t) for t in targets]
    return all(results) if require_all else any(results)


def _match_selection(event: Dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, list):
        # list of maps -> any map fully matches (Sigma list-of-maps semantics)
        return any(_match_selection(event, item) for item in selection)
    if not isinstance(selection, dict):
        return False
    return all(_match_field(event, k, v) for k, v in selection.items())


# --------------------------------------------------------------------------- #
# Condition expression evaluation
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not|of|them|all|1)\b|[A-Za-z_][\w*]*")


def _expand_quantifiers(condition: str, sel_names: List[str]) -> str:
    """Expand 'N of selection*' / 'all of them' into boolean sub-expressions."""
    def expand(match: "re.Match[str]") -> str:
        quant, pattern = match.group(1), match.group(2)
        if pattern == "them":
            names = list(sel_names)
        elif pattern.endswith("*"):
            prefix = pattern[:-1]
            names = [n for n in sel_names if n.startswith(prefix)]
        else:
            names = [pattern] if pattern in sel_names else []
        if not names:
            return "False"
        joiner = " and " if quant == "all" else " or "
        return "( " + joiner.join(names) + " )"

    pat = re.compile(r"\b(all|1)\s+of\s+([A-Za-z_][\w]*\*?|them)")
    prev = None
    out = condition
    while prev != out:
        prev = out
        out = pat.sub(expand, out)
    return out


def evaluate_condition(condition: str, sel_results: Dict[str, bool]) -> bool:
    sel_names = list(sel_results.keys())
    expr = _expand_quantifiers(condition or "", sel_names)
    if not expr.strip():
        # No condition: default to "any selection matched"
        return any(sel_results.values())

    tokens = _TOKEN_RE.findall(expr)
    safe: List[str] = []
    for tok in tokens:
        if tok in ("(", ")"):
            safe.append(tok)
        elif tok in ("and", "or", "not"):
            safe.append(tok)
        elif tok in ("True", "False"):
            safe.append(tok)
        elif tok in sel_results:
            safe.append("True" if sel_results[tok] else "False")
        else:
            safe.append("False")
    py_expr = " ".join(safe) if safe else "False"
    try:
        return bool(eval(py_expr, {"__builtins__": {}}, {}))  # noqa: S307 - sanitized token stream
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Matching engine
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule_id: str
    title: str
    level: str
    mitre: str
    event_index: int
    event: Dict[str, Any]
    matched_selections: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "mitre": self.mitre,
            "event_index": self.event_index,
            "matched_selections": self.matched_selections,
            "event": self.event,
        }


def rule_matches(rule: Rule, event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    sel_results = {name: _match_selection(event, sel) for name, sel in rule.detection.items()}
    fired = evaluate_condition(rule.condition, sel_results)
    matched = [n for n, r in sel_results.items() if r]
    return fired, matched


def scan(events: Iterable[Dict[str, Any]], rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for i, ev in enumerate(events):
        for rule in rules:
            fired, matched = rule_matches(rule, ev)
            if fired:
                findings.append(Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    level=rule.level,
                    mitre=rule.mitre,
                    event_index=i,
                    event=ev,
                    matched_selections=matched,
                ))
    return findings


_LEVEL_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def severity_rank(level: str) -> int:
    return _LEVEL_ORDER.get(level.lower(), 0)


def summarize_findings(findings: List[Finding]) -> Dict[str, Any]:
    by_level: Dict[str, int] = {}
    by_technique: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    for f in findings:
        by_level[f.level] = by_level.get(f.level, 0) + 1
        if f.mitre:
            by_technique[f.mitre] = by_technique.get(f.mitre, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    max_rank = max((severity_rank(f.level) for f in findings), default=0)
    return {
        "total_findings": len(findings),
        "by_level": dict(sorted(by_level.items(), key=lambda kv: -severity_rank(kv[0]))),
        "by_technique": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "max_severity": next((k for k, v in _LEVEL_ORDER.items() if v == max_rank), "informational"),
    }


__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "BUNDLED_RULES",
    "Rule",
    "Finding",
    "parse_yaml_documents",
    "load_rules",
    "load_events",
    "rule_matches",
    "scan",
    "summarize_findings",
    "severity_rank",
    "evaluate_condition",
]
