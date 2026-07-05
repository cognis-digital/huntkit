"""Command-line interface for elastdetect.

Subcommands:
  validate <path>            validate rules; exit non-zero on any error (CI gate)
  diff <old.json> <new.json> structural diff of two rule sets (table or --json)
  lint <path>                style warnings (non-fatal by default)
  deploy <path> --live ...   deploy rules to an Elastic cluster (network)

Only ``deploy --live`` touches the network. All other commands are offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from . import rules as rules_mod
from .diff import diff_rule_sets, render_table
from .lint import lint_rules
from .validate import validate_rules

EXIT_OK = 0
EXIT_FINDINGS = 1  # validation errors / lint failures under --strict
EXIT_USAGE = 2  # bad input / load errors


def _print_load_errors(result, stream) -> None:
    for err in result.errors:
        print(f"{err.source}: load error: {err.message}", file=stream)


def cmd_validate(args) -> int:
    result = rules_mod.load_path(args.path)
    if result.errors:
        _print_load_errors(result, sys.stderr)
        if not result.rules:
            return EXIT_USAGE

    reports = validate_rules(result.rules)
    total_errors = 0
    total_warnings = 0

    if getattr(args, "sarif", False):
        # SARIF mode: emit a machine-readable log on stdout for CI ingestion.
        # Findings are still counted so the exit code keeps gating the build.
        from .sarif import reports_to_sarif

        for rep in reports:
            for issue in rep.issues:
                total_errors += 1 if issue.level == "error" else 0
                total_warnings += 1 if issue.level == "warning" else 0
        log = reports_to_sarif(reports, include_warnings=False)
        print(json.dumps(log, indent=2, sort_keys=True))
        if total_errors or result.errors:
            return EXIT_FINDINGS
        return EXIT_OK

    for rep in reports:
        for issue in rep.issues:
            total_errors += 1 if issue.level == "error" else 0
            total_warnings += 1 if issue.level == "warning" else 0
            print(issue.format(rep.source), file=sys.stderr)

    n_rules = len(reports)
    n_bad = sum(1 for r in reports if not r.ok)
    print(
        f"Validated {n_rules} rule(s): {n_rules - n_bad} ok, {n_bad} with errors "
        f"({total_errors} error(s))."
    )

    if total_errors or result.errors:
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_lint(args) -> int:
    result = rules_mod.load_path(args.path)
    if result.errors:
        _print_load_errors(result, sys.stderr)
        if not result.rules:
            return EXIT_USAGE

    reports = lint_rules(result.rules)
    total_warnings = 0
    for rep in reports:
        for issue in rep.warnings:
            total_warnings += 1
            print(issue.format(rep.source))

    n_rules = len(reports)
    n_flagged = sum(1 for r in reports if r.warnings)
    print(
        f"Linted {n_rules} rule(s): {n_flagged} with warnings "
        f"({total_warnings} warning(s))."
    )

    if args.strict and total_warnings:
        return EXIT_FINDINGS
    return EXIT_OK


def _load_single_file(path: str):
    result = rules_mod.load_path(path)
    if result.errors and not result.rules:
        for err in result.errors:
            print(f"{err.source}: {err.message}", file=sys.stderr)
        return None
    return [lr.rule for lr in result.rules]


def cmd_diff(args) -> int:
    old = _load_single_file(args.old)
    new = _load_single_file(args.new)
    if old is None or new is None:
        return EXIT_USAGE

    d = diff_rule_sets(old, new)

    if args.json:
        print(json.dumps(d.to_dict(), indent=2, sort_keys=True))
    else:
        print(render_table(d))

    return EXIT_OK


def cmd_deploy(args) -> int:
    result = rules_mod.load_path(args.path)
    if result.errors:
        _print_load_errors(result, sys.stderr)
        if not result.rules:
            return EXIT_USAGE

    # Import lazily so the networked module is never loaded unless deploy runs.
    from .deploy import deploy_rules

    try:
        dep = deploy_rules(
            result.rules,
            url=args.url,
            api_key=args.api_key,
            live=args.live,
        )
    except ValueError as exc:
        print(f"deploy error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    for out in dep.outcomes:
        print(f"[{out.status}] {out.rule_id}  {out.name}  {out.detail}")

    if not args.live:
        print(
            "\nDRY RUN: no rules were deployed. Pass --live with --url and "
            "--api-key to deploy.",
            file=sys.stderr,
        )

    if dep.errors:
        return EXIT_FINDINGS
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elastdetect",
        description="Elastic detection-rule management CLI "
        "(validate / diff / lint / deploy).",
    )
    parser.add_argument(
        "--version", action="version", version=f"elastdetect {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="validate rules (CI gate)")
    p_val.add_argument("path", help="rules directory or JSON file")
    p_val.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 to stdout (for GitHub/CI code scanning)",
    )
    p_val.set_defaults(func=cmd_validate)

    p_diff = sub.add_parser("diff", help="diff two rule sets by rule_id")
    p_diff.add_argument("old", help="old rules JSON file")
    p_diff.add_argument("new", help="new rules JSON file")
    p_diff.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_diff.set_defaults(func=cmd_diff)

    p_lint = sub.add_parser("lint", help="style warnings (description/tags/references)")
    p_lint.add_argument("path", help="rules directory or JSON file")
    p_lint.add_argument(
        "--strict", action="store_true", help="exit non-zero if any warnings"
    )
    p_lint.set_defaults(func=cmd_lint)

    p_dep = sub.add_parser("deploy", help="deploy rules to an Elastic cluster")
    p_dep.add_argument("path", help="rules directory or JSON file")
    p_dep.add_argument(
        "--live",
        action="store_true",
        help="actually POST to the cluster (otherwise dry run)",
    )
    p_dep.add_argument("--url", help="Kibana base URL, e.g. https://kibana:5601")
    p_dep.add_argument("--api-key", dest="api_key", help="Elastic API key")
    p_dep.set_defaults(func=cmd_deploy)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
