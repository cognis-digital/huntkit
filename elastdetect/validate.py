"""Validation of Elastic detection rules.

Schema checks implemented from the elastdetect spec (clean-room, original):

Required fields per rule:
  - rule_id      : non-empty string
  - name         : non-empty string
  - risk_score   : integer 0-100 inclusive
  - severity     : one of low / medium / high / critical
  - type         : one of the supported rule types
  - query        : non-empty string (KQL/Lucene/EQL source)

Type-specific:
  - threshold rules require a ``threshold`` object with a numeric ``value``
  - eql rules must declare a query (EQL source) like other query types

Validation never touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

SUPPORTED_TYPES = {
    "query",
    "eql",
    "threshold",
    "threat_match",
    "machine_learning",
    "new_terms",
}

SEVERITIES = {"low", "medium", "high", "critical"}

# Rule types that carry a query/language source.
QUERY_TYPES = {"query", "eql", "threshold", "threat_match", "new_terms"}


@dataclass
class Issue:
    rule_id: str
    field: str
    message: str
    level: str = "error"  # "error" or "warning"

    def format(self, source: str = "") -> str:
        loc = self.rule_id or "<no rule_id>"
        prefix = f"{source}: " if source else ""
        return f"{prefix}[{self.level}] rule '{loc}': {self.field}: {self.message}"


@dataclass
class RuleReport:
    rule_id: str
    source: str
    issues: List[Issue] = field(default_factory=list)

    @property
    def errors(self) -> List[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> List[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate_rule(rule: Dict[str, Any], source: str = "") -> RuleReport:
    """Validate one rule dict and return a report of errors/warnings."""
    rid = str(rule.get("rule_id", "")).strip()
    report = RuleReport(rule_id=rid, source=source)

    # rule_id
    if not _is_nonempty_str(rule.get("rule_id")):
        report.issues.append(Issue(rid, "rule_id", "missing or empty"))

    # name
    if not _is_nonempty_str(rule.get("name")):
        report.issues.append(Issue(rid, "name", "missing or empty"))

    # risk_score
    rs = rule.get("risk_score")
    if rs is None:
        report.issues.append(Issue(rid, "risk_score", "missing"))
    elif isinstance(rs, bool) or not isinstance(rs, int):
        report.issues.append(
            Issue(rid, "risk_score", "must be an integer 0-100")
        )
    elif not (0 <= rs <= 100):
        report.issues.append(
            Issue(rid, "risk_score", f"out of range 0-100 (got {rs})")
        )

    # severity
    sev = rule.get("severity")
    if sev is None:
        report.issues.append(Issue(rid, "severity", "missing"))
    elif sev not in SEVERITIES:
        report.issues.append(
            Issue(
                rid,
                "severity",
                f"invalid '{sev}', expected one of {sorted(SEVERITIES)}",
            )
        )

    # type
    rtype = rule.get("type")
    if rtype is None:
        report.issues.append(Issue(rid, "type", "missing"))
    elif rtype not in SUPPORTED_TYPES:
        report.issues.append(
            Issue(
                rid,
                "type",
                f"unsupported '{rtype}', expected one of {sorted(SUPPORTED_TYPES)}",
            )
        )

    # query (required for query-bearing types; ML rules use a job id instead)
    if rtype in QUERY_TYPES:
        if not _is_nonempty_str(rule.get("query")):
            report.issues.append(
                Issue(rid, "query", "missing or empty (KQL/Lucene/EQL required)")
            )
    elif rtype == "machine_learning":
        if not _is_nonempty_str(rule.get("machine_learning_job_id")) and not _is_nonempty_str(
            rule.get("anomaly_threshold")
        ):
            report.issues.append(
                Issue(
                    rid,
                    "machine_learning_job_id",
                    "machine_learning rule requires a job id",
                )
            )

    # threshold-specific
    if rtype == "threshold":
        thr = rule.get("threshold")
        if not isinstance(thr, dict):
            report.issues.append(
                Issue(rid, "threshold", "threshold rule requires a threshold object")
            )
        else:
            val = thr.get("value")
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                report.issues.append(
                    Issue(rid, "threshold.value", "must be a number")
                )
            elif val <= 0:
                report.issues.append(
                    Issue(rid, "threshold.value", "must be greater than 0")
                )

    return report


def validate_rules(loaded) -> List[RuleReport]:
    """Validate a list of LoadedRule objects (from rules.load_path)."""
    reports: List[RuleReport] = []
    for lr in loaded:
        reports.append(validate_rule(lr.rule, source=lr.source))
    return reports
