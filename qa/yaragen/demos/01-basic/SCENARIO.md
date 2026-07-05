# Demo 01 — Basic: generate a candidate rule from a captured dropper

## Situation
During incident triage you recover a suspicious binary
(`suspicious_dropper.bin`) from a host you administer. You want a
**candidate YARA rule** to hunt for sibling samples across your fleet —
without hand-writing strings from scratch.

> Defensive use only: run YARAGEN on artifacts you own / are authorized to
> analyze. Generated rules are *drafts* and must be reviewed/tuned before
> deployment to reduce false positives.

## Run it

Human-readable table + rule to stdout:

```
python -m yaragen generate demos/01-basic/suspicious_dropper.bin
```

Machine-readable for a pipeline:

```
python -m yaragen generate demos/01-basic/suspicious_dropper.bin --format json
```

Shareable self-contained HTML report (the tool's UI):

```
python -m yaragen generate demos/01-basic/suspicious_dropper.bin --format html -o report.html
```

## What to expect
YARAGEN extracts ASCII + wide strings, scores each as an anchor, and
promotes suspicious indicators:

- `winapi`  — `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
- `lolbin`  — `powershell`
- `url`     — the C2 callback URL
- `registry`— the `CurrentVersion\Run` persistence key
- `fs_path` — the `\Temp\` drop path
- `base64_blob` — the long encoded payload string

Boilerplate (`This program cannot be run...`, the Microsoft copyright) is
demoted to `goodware`, and noise (`zzzz...`, `2024`) is down-weighted, so
they do not anchor the rule.

The emitted rule fires on `any of` the suspicious strings, with file
hashes recorded in `meta`. Because high-severity indicators are present,
the process exits non-zero (1) — a convenient signal for CI / triage
pipelines.
