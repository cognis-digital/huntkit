"""Rule loading helpers.

Loads Elastic detection rules from a single JSON file or a directory tree of
JSON files. A file may contain either a single rule object or a JSON array of
rule objects. Everything here is filesystem-only; no network access.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Tuple


@dataclass
class LoadedRule:
    """A single rule along with the file it came from."""

    rule: Dict[str, Any]
    source: str  # path to the file the rule was read from

    @property
    def rule_id(self) -> str:
        return str(self.rule.get("rule_id", ""))


@dataclass
class LoadError:
    """A problem encountered while reading/parsing a file."""

    source: str
    message: str


@dataclass
class LoadResult:
    rules: List[LoadedRule] = field(default_factory=list)
    errors: List[LoadError] = field(default_factory=list)


def iter_json_files(path: str) -> Iterator[str]:
    """Yield JSON file paths from a file or directory (recursive, sorted)."""
    if os.path.isfile(path):
        yield path
        return
    if os.path.isdir(path):
        collected: List[str] = []
        for root, _dirs, files in os.walk(path):
            for name in files:
                if name.lower().endswith(".json"):
                    collected.append(os.path.join(root, name))
        for p in sorted(collected):
            yield p
        return
    # Neither file nor dir: nothing to iterate; caller reports via load_path.


def _coerce_rules(obj: Any) -> Tuple[List[Dict[str, Any]], str]:
    """Normalize a parsed JSON document into a list of rule dicts.

    Returns (rules, error_message). error_message is empty on success.
    """
    if isinstance(obj, dict):
        # A wrapper like {"rules": [...]} is also accepted.
        if "rules" in obj and isinstance(obj["rules"], list):
            rules = [r for r in obj["rules"] if isinstance(r, dict)]
            if len(rules) != len(obj["rules"]):
                return [], "rules array contains non-object entries"
            return rules, ""
        return [obj], ""
    if isinstance(obj, list):
        rules = [r for r in obj if isinstance(r, dict)]
        if len(rules) != len(obj):
            return [], "JSON array contains non-object entries"
        return rules, ""
    return [], "top-level JSON must be an object or array of rule objects"


def load_path(path: str) -> LoadResult:
    """Load all rules reachable from ``path``.

    ``path`` may be a single .json file or a directory tree.
    """
    result = LoadResult()

    if not os.path.exists(path):
        result.errors.append(LoadError(path, "path does not exist"))
        return result

    if os.path.isfile(path) and not path.lower().endswith(".json"):
        result.errors.append(LoadError(path, "not a .json file"))
        return result

    any_file = False
    for fpath in iter_json_files(path):
        any_file = True
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            result.errors.append(LoadError(fpath, f"invalid JSON: {exc}"))
            continue
        except OSError as exc:
            result.errors.append(LoadError(fpath, f"cannot read file: {exc}"))
            continue

        rules, err = _coerce_rules(data)
        if err:
            result.errors.append(LoadError(fpath, err))
            continue
        for rule in rules:
            result.rules.append(LoadedRule(rule=rule, source=fpath))

    if not any_file and os.path.isdir(path):
        result.errors.append(LoadError(path, "directory contains no .json files"))

    return result
