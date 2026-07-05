# Demo 10 — Triaging a whole rule repository (directory tree)

**Situation.** A SOC keeps its detection content as a directory tree organised by
domain (`endpoint/`, `identity/`, ...), with multiple JSON files — some holding a
single rule, some holding arrays. The detection lead wants one command to walk
the entire tree and report the health of the full set.

**Where the data came from.** A miniature rule repo:

```
rules/
  endpoint/credential_dumping.json   (1 rule, valid)
  identity/oauth_consent.json        (2 rules: 1 valid, 1 broken)
```

`elastdetect` recursively discovers every `.json` file under the path, in any
nesting, and flattens single-object and array files together. The broken rule
(`cognis-demo-10-bad-mfa-rule`) has `threshold.value: 0`, which is invalid (the
value must be greater than 0).

**Run it (validate the whole tree).**

```bash
elastdetect validate demos/10-mixed-batch-triage/rules
```

**What to expect.** Three rules discovered across two folders; one error on the
MFA rule and a non-zero exit (`1`):

```
[error] rule 'cognis-demo-10-bad-mfa-rule': threshold.value: must be greater than 0
Validated 3 rule(s): 2 ok, 1 with errors (1 error(s)).
```

**Also useful.** Lint the whole tree for documentation gaps, or export SARIF for
the repo in one shot:

```bash
elastdetect lint demos/10-mixed-batch-triage/rules
elastdetect validate --sarif demos/10-mixed-batch-triage/rules > tree.sarif
```

**How to act.** Set the MFA threshold to a realistic positive value (e.g. 5
failed challenges per user) and re-run. This is the pattern to wire into CI for a
real detection-as-code repository: point `validate` at the rules root and let it
walk everything.
