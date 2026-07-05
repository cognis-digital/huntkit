# Demo 07 — Validating a threshold (brute-force) rule

**Situation.** A SOC is rolling out an RDP brute-force detection. Threshold rules
have an extra structural requirement on top of the common fields — they must
carry a `threshold` object with a numeric `value > 0` — so the team validates the
single rule file before committing it.

**Where the data came from.** A single-object rule file (elastdetect accepts both
a single rule object and an array). It groups by both `source.ip` and
`user.name`, fires at 20 failures, and is scoped to Windows logon type 10 (RDP).

**Run it.**

```bash
elastdetect validate demos/07-threshold-bruteforce/rules.json
elastdetect lint demos/07-threshold-bruteforce/rules.json
```

**What to expect.** `validate` exits `0` (`Validated 1 rule(s): 1 ok ...`) because
the `threshold` object and its positive `value` are present and well-formed.
`lint` reports no warnings — the rule is fully documented.

**How to act.** Tune the `threshold.value` to your environment: 20 is a sensible
starting point for an exposed host, but raise it if jump hosts or scanners create
noise (see the rule's documented false positives). Then promote with Demo 05's
deploy dry run.
