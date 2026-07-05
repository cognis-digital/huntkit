"""SARIF 2.1.0 export for elastdetect validation findings.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard that
GitHub code scanning, Azure DevOps, and most CI security dashboards ingest. By
emitting validation (and, optionally, lint) findings as SARIF, an elastdetect
CI gate can publish per-rule problems directly into a pull request's "Files
changed" view instead of only failing the build with a console message.

This module is pure/offline: it transforms ``RuleReport`` objects (from
``validate.py`` / ``lint.py``) into a SARIF log dict. Serialisation is left to
the caller (``json.dumps``).

Reference: SARIF v2.1.0 OASIS Standard
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from . import __version__
from .validate import RuleReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://json.schemastore.org/sarif-2.1.0.json"
)

# Map elastdetect issue levels to SARIF result levels.
_LEVEL_MAP = {"error": "error", "warning": "warning"}


def _rule_descriptor(field: str) -> Dict[str, Any]:
    """A SARIF reportingDescriptor (a "rule" in SARIF terms) per checked field.

    elastdetect's "rules" are the *checks* it runs (e.g. ``severity`` must be a
    known value), which SARIF models as ``tool.driver.rules``. We use the
    checked field name as the stable rule id so dashboards can group findings.
    """
    return {
        "id": f"elastdetect/{field}",
        "name": f"detection-rule-{field}",
        "shortDescription": {
            "text": f"Detection rule field check: {field}"
        },
    }


def _uri_for(source: str) -> str:
    """Normalise a filesystem path into a forward-slash relative URI.

    SARIF artifact URIs are expected to be relative and use '/'; this keeps
    output stable across Windows/POSIX and across absolute working dirs.
    """
    if not source:
        return "<unknown>"
    s = source.replace("\\", "/")
    # Strip a leading absolute drive/root so URIs stay repository-relative.
    cwd = os.getcwd().replace("\\", "/")
    if s.startswith(cwd + "/"):
        s = s[len(cwd) + 1:]
    return s


def reports_to_sarif(
    reports: List[RuleReport],
    *,
    include_warnings: bool = True,
) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log from a list of RuleReports.

    Parameters
    ----------
    reports:
        RuleReport objects from ``validate_rules`` (or ``lint_rules``).
    include_warnings:
        If False, only ``error``-level issues are emitted (useful when SARIF is
        produced from validation alone). Defaults to True.
    """
    descriptors: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for rep in reports:
        for issue in rep.issues:
            if issue.level == "warning" and not include_warnings:
                continue

            descriptors.setdefault(issue.field, _rule_descriptor(issue.field))

            rid = issue.rule_id or "<no rule_id>"
            results.append(
                {
                    "ruleId": f"elastdetect/{issue.field}",
                    "level": _LEVEL_MAP.get(issue.level, "note"),
                    "message": {
                        "text": f"rule '{rid}': {issue.field}: {issue.message}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": _uri_for(rep.source)
                                }
                            }
                        }
                    ],
                    "properties": {
                        "detectionRuleId": rid,
                        "field": issue.field,
                    },
                }
            )

    driver = {
        "name": "elastdetect",
        "informationUri": "https://github.com/cognis-digital/elastdetect",
        "version": __version__,
        "rules": [descriptors[k] for k in sorted(descriptors)],
    }

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
            }
        ],
    }
