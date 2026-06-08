"""Command-line interface for SENTRYLOG.

Subcommands:
  scan    Ingest log files and run detection rules, emit matches.
  rules   List the active rule pack.
  ingest  Normalize logs and emit parsed events (debug/triage).

Global: --version, --format {table,json}
Exit codes: 0 = clean (no matches), 1 = matches found / error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    BUILTIN_RULES,
    detect,
    ingest_lines,
    load_rules_text,
)


def _read_inputs(paths: List[str]):
    events = []
    if not paths or paths == ["-"]:
        events.extend(ingest_lines(sys.stdin.read().splitlines(), source="<stdin>"))
        return events
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            events.extend(ingest_lines(fh, source=p))
    return events


def _print(obj, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, default=str))


def _cmd_scan(args) -> int:
    rules = list(BUILTIN_RULES)
    if args.rules:
        with open(args.rules, "r", encoding="utf-8") as fh:
            rules = load_rules_text(fh.read())
    events = _read_inputs(args.files)
    matches = detect(events, rules)
    if args.level:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        floor = order.get(args.level, 0)
        matches = [m for m in matches if order.get(m.level, 0) >= floor]

    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "events_scanned": len(events),
        "rules_loaded": len(rules),
        "match_count": len(matches),
        "matches": [m.to_dict() for m in matches],
    }
    if args.format == "json":
        _print(payload, "json")
    else:
        print(f"{TOOL_NAME} {TOOL_VERSION}  events={len(events)}  "
              f"rules={len(rules)}  matches={len(matches)}")
        if matches:
            print(f"{'LEVEL':<9} {'RULE':<28} {'SRC':<16} LINE  TITLE")
            for m in matches:
                src = (m.source[-15:]) if m.source else "-"
                print(f"{m.level:<9} {m.rule_id:<28} {src:<16} "
                      f"{m.lineno:<5} {m.title}")
        else:
            print("no detections")
    return 1 if matches else 0


def _cmd_rules(args) -> int:
    rules = list(BUILTIN_RULES)
    if args.format == "json":
        _print(
            [
                {"id": r.id, "title": r.title, "level": r.level,
                 "condition": r.condition}
                for r in rules
            ],
            "json",
        )
    else:
        print(f"{'LEVEL':<9} {'ID':<28} TITLE")
        for r in rules:
            print(f"{r.level:<9} {r.id:<28} {r.title}")
    return 0


def _cmd_ingest(args) -> int:
    events = _read_inputs(args.files)
    if args.format == "json":
        _print(
            [
                {"source": e.source, "lineno": e.lineno, "fields": e.fields}
                for e in events
            ],
            "json",
        )
    else:
        for e in events:
            lt = e.fields.get("_logtype", "?")
            print(f"{e.lineno:<5} [{lt}] {e.fields}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Single-file SIEM: Sigma-style rules + multi-source ingest.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="run detection rules over logs")
    sp.add_argument("files", nargs="*", help="log files ('-' or none = stdin)")
    sp.add_argument("--rules", help="path to a JSON rule pack (overrides built-ins)")
    sp.add_argument("--level", choices=["low", "medium", "high", "critical"],
                    help="minimum severity to report")
    sp.set_defaults(func=_cmd_scan)

    rp = sub.add_parser("rules", help="list the active rule pack")
    rp.set_defaults(func=_cmd_rules)

    ip = sub.add_parser("ingest", help="normalize logs and emit parsed events")
    ip.add_argument("files", nargs="*", help="log files ('-' or none = stdin)")
    ip.set_defaults(func=_cmd_ingest)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # propagate top-level --format if subparser didn't set its own
    if not hasattr(args, "format") or args.format is None:
        args.format = "table"
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
