"""SENTRYLOG — Sigma-style detection engine over JSON/CSV logs (MITRE ATT&CK mapped).

Bundles ~25 real Sigma-style detection rules and a working matcher that
evaluates them against structured log events (JSON / JSON-lines / CSV). Each
finding carries the rule's MITRE ATT&CK technique so it is immediately
actionable for triage.

Standard library only, zero install. In the spirit of SigmaHQ/sigma.
"""

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    BUNDLED_RULES,
    Rule,
    Finding,
    parse_yaml_documents,
    load_rules,
    load_events,
    rule_matches,
    scan,
    summarize_findings,
    severity_rank,
    evaluate_condition,
)

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
