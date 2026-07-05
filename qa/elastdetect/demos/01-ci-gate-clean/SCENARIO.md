# Demo 01 — CI gate on a clean rule set

**Situation.** A detection engineer has authored two new rules (ransomware
shadow-copy deletion, and a scheduled-task persistence rule) and opened a pull
request. The CI pipeline runs `elastdetect validate` as a required check before
the rules can be merged into the detection-as-code repository.

**Where the data came from.** `rules.json` is a small batch of authored rules in
the same JSON shape Elastic's Detection Engine accepts (the same shape exported
by the Kibana "export rules" action). Both rules are structurally complete.

**Run it.**

```bash
elastdetect validate demos/01-ci-gate-clean/rules.json
```

**What to expect.** Every rule passes. The command prints a summary line and
exits `0`, so the CI gate goes green and the PR is mergeable:

```
Validated 2 rule(s): 2 ok, 0 with errors (0 error(s)).
```

**How to act.** Nothing to fix — this is the happy path. Use it as the baseline
"green build" in your pipeline and compare against Demo 02, which fails the gate.
