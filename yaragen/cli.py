"""Command-line interface for YARAGEN."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze_sample, SampleReport

_SEV_COLOR = {"high": "#c0392b", "medium": "#d68910", "low": "#7f8c8d"}


def _gather_files(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    out.append(os.path.join(root, fn))
        elif os.path.isfile(p):
            out.append(p)
        else:
            print(f"yaragen: warning: not found: {p}", file=sys.stderr)
    return out


def _render_table(reports: list[SampleReport]) -> str:
    lines = []
    for rep in reports:
        lines.append(f"== {rep.path}  ({rep.size} bytes)  sha256={rep.sha256[:16]}..")
        lines.append(f"   rule: {rep.rule_name}   indicators: {len(rep.findings)}")
        lines.append(f"   {'SEV':<7}{'SCORE':>7}  {'ENC':<5} CATEGORY            VALUE")
        for f in rep.findings:
            val = f.value if len(f.value) <= 50 else f.value[:47] + "..."
            lines.append(f"   {f.severity:<7}{f.score:>7.2f}  {f.encoding:<5} "
                         f"{f.category:<19} {val}")
        lines.append("")
        lines.append(rep.rule_text)
        lines.append("")
    return "\n".join(lines)


def _render_html(reports: list[SampleReport]) -> str:
    total_findings = sum(len(r.findings) for r in reports)
    high = sum(1 for r in reports for f in r.findings if f.severity == "high")
    med = sum(1 for r in reports for f in r.findings if f.severity == "medium")
    low = sum(1 for r in reports for f in r.findings if f.severity == "low")

    def esc(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    parts = [f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>YARAGEN report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}}
 header{{background:#1b2733;padding:20px 28px;border-bottom:3px solid #3498db}}
 h1{{margin:0;font-size:20px}} .sub{{color:#8aa0b3;font-size:13px;margin-top:4px}}
 .wrap{{padding:24px 28px;max-width:1100px}}
 .cards{{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}}
 .card{{background:#1b2733;border-radius:8px;padding:14px 18px;min-width:120px}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:12px;color:#8aa0b3}}
 .sample{{background:#1b2733;border-radius:8px;padding:18px;margin-bottom:22px}}
 .sample h2{{font-size:15px;margin:0 0 4px}} .meta{{font-size:12px;color:#8aa0b3;word-break:break-all}}
 table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
 th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #2c3e50}}
 th{{color:#8aa0b3;font-weight:600}} td.val{{font-family:Consolas,monospace;word-break:break-all}}
 .pill{{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600}}
 pre{{background:#0f1419;border:1px solid #2c3e50;border-radius:6px;padding:12px;overflow:auto;font-size:12px;color:#bfe3c0}}
 .note{{color:#d68910;font-size:12px;margin-top:8px}}
</style></head><body>
<header><h1>YARAGEN &mdash; candidate rule report</h1>
<div class="sub">{TOOL_NAME} v{TOOL_VERSION} &middot; defensive detection-engineering draft &middot; review before deployment</div></header>
<div class="wrap">
<div class="cards">
 <div class="card"><div class="n">{len(reports)}</div><div class="l">samples</div></div>
 <div class="card"><div class="n">{total_findings}</div><div class="l">indicators</div></div>
 <div class="card"><div class="n" style="color:{_SEV_COLOR['high']}">{high}</div><div class="l">high</div></div>
 <div class="card"><div class="n" style="color:{_SEV_COLOR['medium']}">{med}</div><div class="l">medium</div></div>
 <div class="card"><div class="n" style="color:{_SEV_COLOR['low']}">{low}</div><div class="l">low</div></div>
</div>"""]

    for rep in reports:
        rows = []
        for f in rep.findings:
            color = _SEV_COLOR[f.severity]
            rows.append(
                f'<tr><td><span class="pill" style="background:{color}">{f.severity}</span></td>'
                f'<td>{f.score:.2f}</td><td>{f.encoding}</td>'
                f'<td>{esc(f.category)}</td><td class="val">{esc(f.value)}</td></tr>'
            )
        parts.append(f"""<div class="sample">
<h2>{esc(os.path.basename(rep.path))}</h2>
<div class="meta">{esc(rep.path)} &middot; {rep.size} bytes<br>md5 {rep.md5} &middot; sha256 {rep.sha256}</div>
<table><thead><tr><th>severity</th><th>score</th><th>enc</th><th>category</th><th>value</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class="note">Candidate YARA rule (tune to reduce false positives):</div>
<pre>{esc(rep.rule_text)}</pre>
</div>""")

    parts.append("</div></body></html>")
    return "\n".join(parts)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate candidate YARA rules from owned sample files (defensive).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    g = sub.add_parser("generate", help="Analyze samples and emit candidate YARA rules.")
    g.add_argument("paths", nargs="+", help="Sample files or directories (artifacts you own).")
    g.add_argument("--format", choices=["table", "json", "html"], default="table")
    g.add_argument("--top", type=int, default=20, help="Max indicators per sample.")
    g.add_argument("-o", "--output", help="Write report to this file instead of stdout.")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "generate":
        parser.print_help()
        return 2

    files = _gather_files(args.paths)
    if not files:
        print("yaragen: error: no input files found", file=sys.stderr)
        return 2

    reports = [analyze_sample(f, top=args.top) for f in files]

    if args.format == "json":
        out = json.dumps({"tool": TOOL_NAME, "version": TOOL_VERSION,
                          "samples": [r.to_dict() for r in reports]}, indent=2)
    elif args.format == "html":
        out = _render_html(reports)
    else:
        out = _render_table(reports)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"yaragen: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(out)

    # Non-zero exit when high-severity indicators are found (pipeline signal).
    has_high = any(f.severity == "high" for r in reports for f in r.findings)
    return 1 if has_high else 0


if __name__ == "__main__":
    raise SystemExit(main())
