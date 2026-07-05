"""huntkit rules — the bundled detection-rule library.

Explicit, ATT&CK-mapped detection rules for execution/defense-evasion, persistence/priv-esc,
and credential-access/discovery/exfiltration, applied to command lines, process telemetry, and
logs. Plain-JSON rules under huntkit/rules/ — extend with a text editor.

    huntkit rules list                 list every rule (id, category, severity, ATT&CK)
    huntkit rules stats                counts by category
    huntkit rules scan PATH|-          scan a file/dir/stdin against the rule library
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

RULE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


@dataclass
class Rule:
    id: str
    name: str
    category: str
    severity: str
    attack: str
    rx: re.Pattern


def load_rules(extra_dir: Optional[str] = None) -> List[Rule]:
    rules: List[Rule] = []
    for d in [RULE_DIR] + ([extra_dir] if extra_dir else []):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".json"):
                continue
            try:
                doc = json.load(open(os.path.join(d, fn), encoding="utf-8"))
            except Exception:
                continue
            cat = doc.get("category", os.path.splitext(fn)[0])
            for s in doc.get("signatures", []):
                try:
                    rules.append(Rule(s["id"], s["name"], cat, s.get("severity", "medium"),
                                      s.get("attack", ""), re.compile(s["pattern"])))
                except (re.error, KeyError):
                    continue
    return rules


def _scan_text(rules, text):
    hits = []
    for r in rules:
        m = r.rx.search(text)
        if m:
            line = text[:m.start()].count("\n") + 1
            hits.append((r, line, text[max(0, m.start() - 15): m.start() + 55].replace("\n", " ").strip()))
    hits.sort(key=lambda h: SEV_ORDER.index(h[0].severity) if h[0].severity in SEV_ORDER else 9)
    return hits


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="huntkit rules", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("stats")
    pl = sub.add_parser("list"); pl.add_argument("--category", "-c", default=None)
    ps = sub.add_parser("scan"); ps.add_argument("path"); ps.add_argument("--format", "-f", default="text", choices=["text", "json"])
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    rules = load_rules()
    cmd = args.cmd or "stats"

    if cmd == "stats":
        by = {}
        for r in rules:
            by[r.category] = by.get(r.category, 0) + 1
        print(f"huntkit rule library: {len(rules)} rules")
        for c, n in sorted(by.items()):
            print(f"  {n:>3}  {c}")
        return 0

    if cmd == "list":
        for r in rules:
            if args.category and r.category != args.category:
                continue
            print(f"  {_TAG.get(r.severity,'')} {r.id:<7} {r.category:<28} {r.attack:<10} {r.name}")
        return 0

    # scan
    if args.path == "-":
        results = {"<stdin>": _scan_text(rules, sys.stdin.read())}
    elif os.path.isfile(args.path):
        results = {args.path: _scan_text(rules, open(args.path, encoding="utf-8", errors="replace").read())}
    else:
        results = {}
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.endswith((".log", ".txt", ".json", ".jsonl", ".csv", ".ps1", ".sh", ".md")):
                    fp = os.path.join(root, f)
                    h = _scan_text(rules, open(fp, encoding="utf-8", errors="replace").read())
                    if h:
                        results[fp] = h
    total = sum(len(v) for v in results.values())
    if args.format == "json":
        print(json.dumps({f: [{"id": r.id, "name": r.name, "category": r.category, "severity": r.severity,
                               "attack": r.attack, "line": ln} for r, ln, _ in hs]
                          for f, hs in results.items() if hs}, indent=2))
    else:
        for f, hs in results.items():
            if not hs:
                continue
            print(f"\n{f}")
            for r, ln, ex in hs:
                print(f"  {_TAG.get(r.severity,'')} L{ln:<4} {r.id:<7} {r.attack:<10} {r.name}")
                print(f"           > {ex}")
        print(f"\n{total} detection(s).")
    worst = [r.severity for hs in results.values() for r, _, _ in hs]
    return 1 if any(w in ("critical", "high") for w in worst) else 0


if __name__ == "__main__":
    raise SystemExit(main())
