"""Style linting for Elastic detection rules.

Lint warnings are non-fatal recommendations (distinct from hard validation
errors). They flag rules that are technically valid but miss authoring best
practices:

  - missing or empty ``description``
  - missing or empty ``tags`` (or empty list)
  - missing or empty ``references``
  - very short ``name`` (< 8 chars)
  - missing ``severity_mapping``/``false_positives`` guidance (soft hint)

No network access.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .validate import Issue, RuleReport, _is_nonempty_str


def _is_nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def lint_rule(rule: Dict[str, Any], source: str = "") -> RuleReport:
    rid = str(rule.get("rule_id", "")).strip()
    report = RuleReport(rule_id=rid, source=source)

    if not _is_nonempty_str(rule.get("description")):
        report.issues.append(
            Issue(rid, "description", "missing or empty", level="warning")
        )

    if not _is_nonempty_list(rule.get("tags")):
        report.issues.append(
            Issue(rid, "tags", "missing or empty; add MITRE/category tags", level="warning")
        )

    if not _is_nonempty_list(rule.get("references")):
        report.issues.append(
            Issue(rid, "references", "missing or empty; cite sources", level="warning")
        )

    name = rule.get("name")
    if _is_nonempty_str(name) and len(name.strip()) < 8:
        report.issues.append(
            Issue(rid, "name", "very short; use a descriptive name", level="warning")
        )

    if not _is_nonempty_list(rule.get("false_positives")):
        report.issues.append(
            Issue(
                rid,
                "false_positives",
                "no false-positive guidance documented",
                level="warning",
            )
        )

    return report


def lint_rules(loaded) -> List[RuleReport]:
    return [lint_rule(lr.rule, source=lr.source) for lr in loaded]
