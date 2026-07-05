"""IOCREP command-line interface.

Subcommands:
    score   Score one or more indicators (positional or --infile) against an
            offline reputation DB; emit table / json / html.

Exit codes:
    0  no findings (all clean / allowlisted)
    1  at least one finding at or above the --fail-on severity
    2  usage / runtime error
"""
from __future__ import annotations

import argparse
import html as _html
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ReputationDB,
    Verdict,
    score_batch,
    SEVERITY_ORDER,
)

_SEV_COLORS = {
    "allow": "#2e7d32",
    "clean": "#388e3c",
    "low": "#9e9d24",
    "medium": "#f9a825",
    "high": "#ef6c00",
    "critical": "#c62828",
}


def _read_indicators(args: argparse.Namespace) -> List[str]:
    items: List[str] = list(args.indicators or [])
    if args.infile:
        with open(args.infile, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    return items


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def render_table(verdicts: List[Verdict]) -> str:
    rows = [("SEVERITY", "SCORE", "KIND", "INDICATOR", "TOP REASON")]
    for v in verdicts:
        top = max(v.reasons, key=lambda r: abs(r.points)) if v.reasons else None
        rows.append((
            v.severity.upper(),
            str(v.score),
            v.indicator.kind,
            v.indicator.value[:48],
            top.signal if top else "-",
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for idx, r in enumerate(rows):
        line = "  ".join(c.ljust(widths[i]) for i, c in enumerate(r))
        out.append(line)
        if idx == 0:
            out.append("  ".join("-" * widths[i] for i in range(len(r))))
    # summary
    counts = {}
    for v in verdicts:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    summary = ", ".join(f"{k}={counts[k]}" for k in SEVERITY_ORDER if k in counts)
    out.append("")
    out.append(f"Scored {len(verdicts)} indicator(s): {summary or 'none'}")
    return "\n".join(out)


def render_json(verdicts: List[Verdict]) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "count": len(verdicts),
        "results": [v.to_dict() for v in verdicts],
    }
    return json.dumps(payload, indent=2)


def render_html(verdicts: List[Verdict]) -> str:
    e = _html.escape
    counts = {}
    for v in verdicts:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLORS.get(k, "#555")}">'
        f'{e(k)}: {counts[k]}</span>'
        for k in SEVERITY_ORDER if k in counts
    )

    rows = []
    for v in sorted(verdicts, key=lambda x: -x.score):
        color = _SEV_COLORS.get(v.severity, "#555")
        reason_items = "".join(
            f'<li><b>{e(r.signal)}</b> '
            f'<span class="pts">({r.points:+d})</span><br>'
            f'<span class="rd">{e(r.detail)}</span></li>'
            for r in v.reasons
        ) or "<li>no signals</li>"
        rows.append(f"""
        <tr>
          <td><span class="sev" style="background:{color}">{e(v.severity.upper())}</span></td>
          <td class="score">{v.score}</td>
          <td>{e(v.indicator.kind)}</td>
          <td class="ioc">{e(v.indicator.value)}</td>
          <td><ul class="reasons">{reason_items}</ul></td>
        </tr>""")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(TOOL_NAME)} report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; padding: 24px; background:#0f1117; color:#e6e6e6; }}
  h1 {{ margin:0 0 4px; font-size:22px; }}
  .meta {{ color:#9aa0aa; font-size:13px; margin-bottom:16px; }}
  .chips {{ margin:12px 0 20px; }}
  .chip {{ display:inline-block; color:#fff; padding:4px 10px; border-radius:14px;
          font-size:12px; margin-right:6px; font-weight:600; }}
  table {{ border-collapse:collapse; width:100%; background:#161922;
          border-radius:8px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 12px; vertical-align:top;
           border-bottom:1px solid #232838; font-size:14px; }}
  th {{ background:#1c2030; color:#aab; text-transform:uppercase;
       font-size:11px; letter-spacing:.05em; }}
  .sev {{ color:#fff; padding:3px 9px; border-radius:5px; font-weight:700;
         font-size:12px; }}
  .score {{ font-variant-numeric: tabular-nums; font-weight:700; }}
  .ioc {{ font-family: ui-monospace, Consolas, monospace; word-break:break-all;
         max-width:320px; }}
  ul.reasons {{ margin:0; padding-left:16px; }}
  ul.reasons li {{ margin-bottom:6px; }}
  .pts {{ color:#9aa0aa; }}
  .rd {{ color:#c2c7d0; font-size:12px; }}
  footer {{ margin-top:18px; color:#6b7280; font-size:12px; }}
</style></head>
<body>
  <h1>IOCREP — Indicator Reputation Report</h1>
  <div class="meta">{e(TOOL_NAME)} v{e(TOOL_VERSION)} · {len(verdicts)} indicator(s) scored · offline analysis</div>
  <div class="chips">{chips or '<span class="chip">no results</span>'}</div>
  <table>
    <thead><tr><th>Severity</th><th>Score</th><th>Kind</th><th>Indicator</th><th>Reasoning</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <footer>Verdicts derived from offline reputation/allow lists and local heuristics only. No network lookups performed.</footer>
</body></html>"""


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Score IOCs against offline reputation/allow lists "
                    "with explainable verdicts (defensive triage).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    sc = sub.add_parser("score", help="score indicators of compromise")
    sc.add_argument("indicators", nargs="*",
                    help="IOC values (IP, domain, url, hash, email); "
                         "defanged forms accepted")
    sc.add_argument("--infile", help="file with one indicator per line "
                                     "(# comments allowed)")
    sc.add_argument("--db", help="path to offline reputation JSON "
                                 "(blocklist/allowlist)")
    sc.add_argument("--format", choices=["table", "json", "html"],
                    default="table", help="output format")
    sc.add_argument("--output", "-o", help="write report to file instead of stdout")
    sc.add_argument("--fail-on", choices=SEVERITY_ORDER, default="medium",
                    help="minimum severity that triggers a non-zero exit "
                         "(default: medium)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "score":
        parser.print_help()
        return 2

    try:
        indicators = _read_indicators(args)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2
    if not indicators:
        print("error: no indicators supplied (pass values or --infile)",
              file=sys.stderr)
        return 2

    try:
        db = ReputationDB.load(args.db)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: cannot load reputation DB: {exc}", file=sys.stderr)
        return 2

    verdicts = score_batch(indicators, db)

    if args.format == "json":
        report = render_json(verdicts)
    elif args.format == "html":
        report = render_html(verdicts)
    else:
        report = render_table(verdicts)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 2
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    threshold = _sev_rank(args.fail_on)
    findings = [v for v in verdicts
                if not v.allowlisted and _sev_rank(v.severity) >= threshold]
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
