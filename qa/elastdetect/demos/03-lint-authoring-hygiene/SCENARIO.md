# Demo 03 — Authoring-hygiene lint before promotion

**Situation.** Rules are structurally valid (they would pass `validate`) but a
detection lead wants them well-documented before they ship, so an analyst on
call can triage the alerts they raise. The team runs `lint` in `--strict` mode as
a *promotion* gate (separate from the hard `validate` CI gate).

**Where the data came from.** Two valid rules:

- `cognis-demo-03-undocumented` — a working rule that lacks a `description`,
  `tags`, `references`, and `false_positives`.
- `cognis-demo-03-shortname` — fully documented, but its `name` is only 3
  characters ("Bad"), which is useless in an alert queue.

**Run it (advisory).**

```bash
elastdetect lint demos/03-lint-authoring-hygiene/rules.json
```

Warnings print, but the exit code is `0` — lint is non-fatal by default.

**Run it (promotion gate).**

```bash
elastdetect lint --strict demos/03-lint-authoring-hygiene/rules.json
```

**What to expect.** Several `[warning]` lines (missing description/tags/
references/false-positives on the first rule; "very short name" on the second)
and, under `--strict`, a non-zero exit (`1`).

**How to act.** Add the missing documentation fields and give the second rule a
descriptive name (e.g. "Certutil Remote File Download"). Re-run `--strict` until
it exits `0`.
