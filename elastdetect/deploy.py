"""Deployment of detection rules to an Elastic cluster.

THIS IS THE ONLY MODULE THAT PERFORMS NETWORK I/O. It is imported lazily by the
CLI and is never exercised by the test suite. The actual HTTP call is gated
behind an explicit ``live=True`` flag at the call site; without it the function
performs a dry run only.

Uses the Kibana Detection Engine API:
    POST {url}/api/detection_engine/rules
with an ApiKey authorization header. Standard library only (urllib).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .validate import validate_rule


@dataclass
class DeployOutcome:
    rule_id: str
    name: str
    status: str  # "created", "dry-run", "skipped-invalid", "error"
    detail: str = ""


@dataclass
class DeployResult:
    outcomes: List[DeployOutcome] = field(default_factory=list)

    @property
    def errors(self) -> List[DeployOutcome]:
        return [o for o in self.outcomes if o.status == "error"]


def _post_rule(
    base_url: str, api_key: str, rule: Dict[str, Any], timeout: float = 30.0
) -> str:
    """POST a single rule to the Kibana Detection Engine. Returns detail text.

    Raises urllib.error.URLError / HTTPError on failure. NETWORK CALL.
    """
    endpoint = base_url.rstrip("/") + "/api/detection_engine/rules"
    payload = json.dumps(rule).encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("kbn-xsrf", "elastdetect")
    req.add_header("Authorization", f"ApiKey {api_key}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = resp.read().decode("utf-8", errors="replace")
        return f"HTTP {resp.status}: {body[:200]}"


def deploy_rules(
    loaded,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    live: bool = False,
    timeout: float = 30.0,
) -> DeployResult:
    """Deploy loaded rules.

    When ``live`` is False (default) this is a dry run: every valid rule is
    reported as "dry-run" and NO network call is made. When ``live`` is True a
    ``url`` and ``api_key`` are required and each valid rule is POSTed.

    Invalid rules are never deployed regardless of the ``live`` flag.
    """
    result = DeployResult()

    if live and (not url or not api_key):
        raise ValueError("live deploy requires both --url and --api-key")

    for lr in loaded:
        rule = lr.rule
        rid = str(rule.get("rule_id", "")).strip()
        name = str(rule.get("name", ""))

        report = validate_rule(rule, source=lr.source)
        if not report.ok:
            result.outcomes.append(
                DeployOutcome(
                    rid,
                    name,
                    "skipped-invalid",
                    f"{len(report.errors)} validation error(s)",
                )
            )
            continue

        if not live:
            result.outcomes.append(
                DeployOutcome(rid, name, "dry-run", "would POST to detection engine")
            )
            continue

        try:
            detail = _post_rule(url, api_key, rule, timeout=timeout)
            result.outcomes.append(DeployOutcome(rid, name, "created", detail))
        except urllib.error.HTTPError as exc:  # pragma: no cover - network
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            result.outcomes.append(
                DeployOutcome(rid, name, "error", f"HTTP {exc.code}: {body[:200]}")
            )
        except urllib.error.URLError as exc:  # pragma: no cover - network
            result.outcomes.append(
                DeployOutcome(rid, name, "error", f"connection failed: {exc.reason}")
            )

    return result
