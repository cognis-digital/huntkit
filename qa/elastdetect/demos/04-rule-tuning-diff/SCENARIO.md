# Demo 04 — Reviewing a tuning change set with `diff`

**Situation.** After a quarterly detection review, an engineer retunes a few
rules and submits a pull request. The reviewer wants a precise, field-level
summary of what changed before approving — not a raw JSON blob.

**Where the data came from.** `before.json` is the currently deployed rule set;
`after.json` is the proposed version. The intended change set is:

- **Modified** `cognis-demo-04-failed-logon-burst` — threshold lowered
  `25 → 15`, risk `47 → 60`, severity `medium → high` (analysts felt it was
  firing too late).
- **Modified** `cognis-demo-04-encoded-powershell` — query broadened to also
  match `-EncodedCommand`, risk `65 → 73`, severity `medium → high`.
- **Removed** `cognis-demo-04-legacy-heuristic` — retired noisy legacy rule.
- **Added** `cognis-demo-04-impossible-travel` — new `new_terms` rule.

**Run it (table).**

```bash
elastdetect diff demos/04-rule-tuning-diff/before.json demos/04-rule-tuning-diff/after.json
```

**Run it (machine-readable, for a bot comment).**

```bash
elastdetect diff --json demos/04-rule-tuning-diff/before.json demos/04-rule-tuning-diff/after.json
```

**What to expect.** A summary header reading `1 added, 1 removed, 2 modified`,
followed by ADDED / REMOVED / MODIFIED sections. Each modified rule lists its
per-field `old -> new` changes. List fields are compared order-insensitively, so
reordering tags alone would not show up.

**How to act.** Confirm each change matches the PR description. The threshold
drop and severity bumps are intentional sensitivity increases; verify the
removed rule is truly retired and the new `new_terms` rule passes `validate`.
