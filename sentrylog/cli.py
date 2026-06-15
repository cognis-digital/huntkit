"""SENTRYLOG command-line interface.

Subcommands:
    scan <events>     run the rule pack against a log file (exit 1 on findings)
    rules             list the bundled detection rules
    rule <id>         show one rule in detail
    summary <events>  per-trace rollup of findings

Global: --version, --format {table,json}

Event files may be JSON arrays, JSON-lines, or CSV. Use '-' to read stdin.
Custom rule packs (same Sigma-style YAML dialect) may be supplied via --rules.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Finding,
    Rule,
    load_events,
    load_rules,
    scan,
    severity_rank,
    summarize_findings,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        print(f"error: file not found: {path}", file=sys.stderr)
        raise SystemExit(2)
    except PermissionError:
        print(f"error: permission denied: {path}", file=sys.stderr)
        raise SystemExit(2)
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _emit_json(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


_LEVEL_FLOOR = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


def _get_rules(args) -> List[Rule]:
    rules_text: Optional[str] = None
    if getattr(args, "rules", None):
        rules_text = _read(args.rules)
        if not rules_text.strip():
            print(
                f"error: rules file is empty: {args.rules}", file=sys.stderr
            )
            raise SystemExit(2)
    rules = load_rules(rules_text)
    if not rules:
        print("error: no rules loaded — rule pack produced zero valid rules",
              file=sys.stderr)
        raise SystemExit(2)
    if getattr(args, "level", None):
        floor = _LEVEL_FLOOR.get(args.level, 0)
        rules = [r for r in rules if severity_rank(r.level) >= floor]
    return rules


# --------------------------------------------------------------------------- #
# Table renderers
# --------------------------------------------------------------------------- #
def _print_rules_table(rules: List[Rule]) -> None:
    print(f"{len(rules)} rules loaded")
    width = max((len(r.id) for r in rules), default=4)
    for r in sorted(rules, key=lambda x: (-severity_rank(x.level), x.id)):
        print(f"  [{r.level:<8}] {r.id:<{width}}  {r.mitre:<11}  {r.title}")


def _print_rule_detail(rule: Rule) -> None:
    print(f"id:          {rule.id}")
    print(f"title:       {rule.title}")
    print(f"level:       {rule.level}")
    print(f"logsource:   {rule.logsource}")
    print(f"mitre:       {rule.mitre}")
    print(f"description: {rule.description}")
    print(f"condition:   {rule.condition}")
    print("detection:")
    for name, sel in rule.detection.items():
        print(f"  {name}: {json.dumps(sel)}")


def _print_findings_table(findings: List[Finding]) -> None:
    if not findings:
        print("no findings")
        return
    findings = sorted(findings, key=lambda f: (-severity_rank(f.level), f.event_index))
    print(f"{len(findings)} findings")
    for f in findings:
        marker = {"critical": "!!", "high": "! ", "medium": "* ", "low": ". "}.get(f.level, "  ")
        ev = f.event
        ctx = ev.get("CommandLine") or ev.get("request") or ev.get("message") \
            or ev.get("eventName") or ev.get("Image")
        if not ctx and ev.get("dst_ip"):
            ctx = f"{ev.get('src_ip', '?')} -> {ev.get('dst_ip')}:{ev.get('dst_port', '?')}/{ev.get('proto', '')}"
        ctx = str(ctx or json.dumps(ev))
        if len(ctx) > 88:
            ctx = ctx[:85] + "..."
        print(f"  {marker}[{f.level:<8}] {f.mitre:<11} {f.title}")
        print(f"       event #{f.event_index}: {ctx}")


def _print_summary_table(summary: dict) -> None:
    print(f"total findings: {summary['total_findings']}")
    print(f"max severity:   {summary['max_severity']}")
    if summary["by_level"]:
        print("by level:")
        for k, v in summary["by_level"].items():
            print(f"  {k:<12} {v}")
    if summary["by_technique"]:
        print("by MITRE technique:")
        for k, v in summary["by_technique"].items():
            print(f"  {k:<12} {v}")
    if summary["by_rule"]:
        print("by rule:")
        for k, v in summary["by_rule"].items():
            print(f"  {k:<28} {v}")


# --------------------------------------------------------------------------- #
# Subcommand handlers
# --------------------------------------------------------------------------- #
def _cmd_rules(args) -> int:
    rules = _get_rules(args)
    if args.format == "json":
        _emit_json([{
            "id": r.id, "title": r.title, "level": r.level,
            "logsource": r.logsource, "mitre": r.mitre,
            "description": r.description,
        } for r in rules])
    else:
        _print_rules_table(rules)
    return 0


def _cmd_rule(args) -> int:
    rules = _get_rules(args)
    match = next((r for r in rules if r.id == args.id), None)
    if match is None:
        print(f"no rule with id '{args.id}'", file=sys.stderr)
        return 2
    if args.format == "json":
        _emit_json({
            "id": match.id, "title": match.title, "level": match.level,
            "logsource": match.logsource, "mitre": match.mitre,
            "description": match.description, "condition": match.condition,
            "detection": match.detection,
        })
    else:
        _print_rule_detail(match)
    return 0


def _cmd_scan(args) -> int:
    raw = _read(args.events)
    if not raw.strip():
        print("error: events file is empty", file=sys.stderr)
        return 2
    try:
        events = load_events(raw)
    except ValueError as exc:
        print(f"error: could not parse events: {exc}", file=sys.stderr)
        return 2
    if not events:
        print("warning: no events found in input — nothing to scan", file=sys.stderr)
    rules = _get_rules(args)
    findings = scan(events, rules)
    if args.format == "json":
        _emit_json({
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "events_scanned": len(events),
            "rules_evaluated": len(rules),
            "summary": summarize_findings(findings),
            "findings": [f.to_dict() for f in findings],
        })
    else:
        print(f"scanned {len(events)} events against {len(rules)} rules")
        _print_findings_table(findings)
    return 1 if findings else 0


def _cmd_summary(args) -> int:
    raw = _read(args.events)
    if not raw.strip():
        print("error: events file is empty", file=sys.stderr)
        return 2
    try:
        events = load_events(raw)
    except ValueError as exc:
        print(f"error: could not parse events: {exc}", file=sys.stderr)
        return 2
    if not events:
        print("warning: no events found in input — nothing to scan", file=sys.stderr)
    rules = _get_rules(args)
    findings = scan(events, rules)
    summary = summarize_findings(findings)
    if args.format == "json":
        _emit_json({
            "events_scanned": len(events),
            "rules_evaluated": len(rules),
            **summary,
        })
    else:
        print(f"scanned {len(events)} events against {len(rules)} rules")
        _print_summary_table(summary)
    return 1 if findings else 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Sigma-style detection engine over JSON/CSV logs (MITRE ATT&CK mapped).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")
    sub = p.add_subparsers(dest="command", required=True)

    def add_rule_opts(sp):
        sp.add_argument("--rules", help="path to a custom Sigma-style rule pack (YAML)")
        sp.add_argument("--level", choices=["critical", "high", "medium", "low", "informational"],
                        help="only use rules at this severity or higher")

    sp_scan = sub.add_parser("scan", help="run rules against a log file")
    sp_scan.add_argument("events", help="JSON/JSON-lines/CSV log file ('-' for stdin)")
    add_rule_opts(sp_scan)
    sp_scan.set_defaults(func=_cmd_scan)

    sp_sum = sub.add_parser("summary", help="rollup of findings by technique/level")
    sp_sum.add_argument("events", help="JSON/JSON-lines/CSV log file ('-' for stdin)")
    add_rule_opts(sp_sum)
    sp_sum.set_defaults(func=_cmd_summary)

    sp_rules = sub.add_parser("rules", help="list bundled detection rules")
    add_rule_opts(sp_rules)
    sp_rules.set_defaults(func=_cmd_rules)

    sp_rule = sub.add_parser("rule", help="show one rule in detail")
    sp_rule.add_argument("id", help="rule id")
    add_rule_opts(sp_rule)
    sp_rule.set_defaults(func=_cmd_rule)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
