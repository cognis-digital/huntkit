"""Diff two Elastic detection-rule sets, keyed by rule_id.

Produces a structured RuleSetDiff:
  - added    : rule_ids present only in the new set
  - removed  : rule_ids present only in the old set
  - modified : rule_ids in both whose fields differ, with per-field changes

The diff is purely structural (no network) and stable/sorted for testing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

# Sentinel marking the absence of a field on one side of a change.
_MISSING = "<absent>"


def _index_by_id(rules: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index rules by rule_id. Later duplicates overwrite earlier ones."""
    index: Dict[str, Dict[str, Any]] = {}
    for r in rules:
        rid = str(r.get("rule_id", "")).strip()
        if rid:
            index[rid] = r
    return index


@dataclass
class FieldChange:
    field: str
    old: Any
    new: Any


@dataclass
class ModifiedRule:
    rule_id: str
    name: str
    changes: List[FieldChange] = field(default_factory=list)


@dataclass
class RuleSetDiff:
    added: List[Dict[str, Any]] = field(default_factory=list)
    removed: List[Dict[str, Any]] = field(default_factory=list)
    modified: List[ModifiedRule] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added": [
                {"rule_id": str(r.get("rule_id", "")), "name": r.get("name", "")}
                for r in self.added
            ],
            "removed": [
                {"rule_id": str(r.get("rule_id", "")), "name": r.get("name", "")}
                for r in self.removed
            ],
            "modified": [
                {
                    "rule_id": m.rule_id,
                    "name": m.name,
                    "changes": [
                        {"field": c.field, "old": c.old, "new": c.new}
                        for c in m.changes
                    ],
                }
                for m in self.modified
            ],
        }


def _normalize(value: Any) -> Any:
    """Order-insensitive comparison for lists, deep for dicts."""
    if isinstance(value, list):
        try:
            return sorted(_normalize(v) for v in value)
        except TypeError:
            # Unsortable (mixed types / nested dicts): compare as JSON strings.
            return sorted(
                json.dumps(_normalize(v), sort_keys=True) for v in value
            )
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in sorted(value.items())}
    return value


def _equal(a: Any, b: Any) -> bool:
    return _normalize(a) == _normalize(b)


def _diff_fields(old: Dict[str, Any], new: Dict[str, Any]) -> List[FieldChange]:
    changes: List[FieldChange] = []
    all_keys = sorted(set(old.keys()) | set(new.keys()))
    for key in all_keys:
        in_old = key in old
        in_new = key in new
        if in_old and in_new:
            if not _equal(old[key], new[key]):
                changes.append(FieldChange(key, old[key], new[key]))
        elif in_old and not in_new:
            changes.append(FieldChange(key, old[key], _MISSING))
        elif in_new and not in_old:
            changes.append(FieldChange(key, _MISSING, new[key]))
    return changes


def diff_rule_sets(
    old_rules: List[Dict[str, Any]], new_rules: List[Dict[str, Any]]
) -> RuleSetDiff:
    old_index = _index_by_id(old_rules)
    new_index = _index_by_id(new_rules)

    old_ids = set(old_index)
    new_ids = set(new_index)

    result = RuleSetDiff()

    for rid in sorted(new_ids - old_ids):
        result.added.append(new_index[rid])

    for rid in sorted(old_ids - new_ids):
        result.removed.append(old_index[rid])

    for rid in sorted(old_ids & new_ids):
        changes = _diff_fields(old_index[rid], new_index[rid])
        if changes:
            name = str(new_index[rid].get("name", old_index[rid].get("name", "")))
            result.modified.append(ModifiedRule(rule_id=rid, name=name, changes=changes))

    return result


def _short(value: Any, width: int = 40) -> str:
    if value is _MISSING:
        return "(absent)"
    s = json.dumps(value) if not isinstance(value, str) else value
    s = s.replace("\n", " ")
    return s if len(s) <= width else s[: width - 1] + "…"


def render_table(d: RuleSetDiff) -> str:
    """Render a human-readable diff table."""
    lines: List[str] = []

    lines.append("=" * 60)
    lines.append(
        f"Rule diff: {len(d.added)} added, {len(d.removed)} removed, "
        f"{len(d.modified)} modified"
    )
    lines.append("=" * 60)

    if d.added:
        lines.append("")
        lines.append("ADDED:")
        for r in d.added:
            lines.append(f"  + {r.get('rule_id', '')}  {r.get('name', '')}")

    if d.removed:
        lines.append("")
        lines.append("REMOVED:")
        for r in d.removed:
            lines.append(f"  - {r.get('rule_id', '')}  {r.get('name', '')}")

    if d.modified:
        lines.append("")
        lines.append("MODIFIED:")
        for m in d.modified:
            lines.append(f"  ~ {m.rule_id}  {m.name}")
            for c in m.changes:
                lines.append(
                    f"      {c.field}: {_short(c.old)} -> {_short(c.new)}"
                )

    if not d.has_changes:
        lines.append("")
        lines.append("No differences.")

    return "\n".join(lines)
