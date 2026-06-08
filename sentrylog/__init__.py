"""SENTRYLOG -- single-file SIEM for small teams.

Sigma-style detection rules over multi-source log ingest (syslog, JSON
lines, Apache/Nginx combined access logs, Windows EVTX-export JSON).
Standard library only, zero install.
"""
from .core import (
    Rule,
    Event,
    Match,
    parse_rules,
    load_rules_text,
    ingest_text,
    ingest_lines,
    detect,
    BUILTIN_RULES,
)

TOOL_NAME = "sentrylog"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Rule",
    "Event",
    "Match",
    "parse_rules",
    "load_rules_text",
    "ingest_text",
    "ingest_lines",
    "detect",
    "BUILTIN_RULES",
    "TOOL_NAME",
    "TOOL_VERSION",
]
