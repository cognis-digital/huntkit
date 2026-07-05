# Demo 05 — Safe deploy preview (dry run, no network)

**Situation.** Before pushing rules to a production Kibana cluster, an operator
wants to confirm *exactly* which rules would be sent and which would be held
back. `deploy` defaults to a **dry run** that makes no network call, so it is
safe to run anywhere — including CI.

**Where the data came from.** Two rules: one fully valid and deployable, one with
an invalid `severity` ("informational" is not an accepted Elastic severity) that
must be withheld.

**Run it (always offline by default).**

```bash
elastdetect deploy demos/05-deploy-dry-run/rules.json
```

**What to expect.** One `[dry-run]` line for the valid rule and one
`[skipped-invalid]` line for the broken one, followed by a notice that nothing
was deployed:

```
[dry-run] cognis-demo-05-valid-deployable  ...  would POST to detection engine
[skipped-invalid] cognis-demo-05-invalid-skipped  ...  1 validation error(s)
DRY RUN: no rules were deployed. Pass --live with --url and --api-key to deploy.
```

**How to act.** Fix the skipped rule's severity, re-run the dry run until every
line reads `[dry-run]`, then (only against an authorized cluster) add
`--live --url https://kibana:5601 --api-key "$ELASTIC_API_KEY"`. Invalid rules
are *never* deployed even with `--live`. Keep API keys in a secret manager.
