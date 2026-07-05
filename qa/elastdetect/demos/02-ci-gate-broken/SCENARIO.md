# Demo 02 — CI gate catching four real authoring mistakes

**Situation.** A contributor copy-pasted rules from several sources and hand-edited
fields. Each of the four rules carries a different, realistic structural defect.
The CI gate must stop these from reaching the cluster.

**Where the data came from.** Synthetic but representative rules in the Elastic
rule JSON shape. The defects mirror the most common mistakes seen in
detection-as-code reviews:

1. `cognis-demo-02-bad-severity` — `severity: "sev1"` (Elastic only accepts
   `low`/`medium`/`high`/`critical`).
2. `cognis-demo-02-risk-out-of-range` — `risk_score: 250` (must be `0`–`100`).
3. `cognis-demo-02-missing-query` — a `query`-type rule with **no** `query`.
4. `cognis-demo-02-threshold-no-object` — a `threshold` rule missing its
   required `threshold` object.

**Run it.**

```bash
elastdetect validate demos/02-ci-gate-broken/rules.json
```

**What to expect.** Four errors on stderr and a non-zero exit (`1`), which fails
the build:

```
[error] rule 'cognis-demo-02-bad-severity': severity: invalid 'sev1', ...
[error] rule 'cognis-demo-02-risk-out-of-range': risk_score: out of range 0-100 (got 250)
[error] rule 'cognis-demo-02-missing-query': query: missing or empty (KQL/Lucene/EQL required)
[error] rule 'cognis-demo-02-threshold-no-object': threshold: threshold rule requires a threshold object
Validated 4 rule(s): 0 ok, 4 with errors (4 error(s)).
```

**How to act.** Fix each field in place — set a valid severity, clamp the risk
score, supply the missing query, and add a `threshold` object with a positive
`value`. Re-run until the command exits `0`.
