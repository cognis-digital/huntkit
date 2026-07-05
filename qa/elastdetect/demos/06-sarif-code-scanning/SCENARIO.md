# Demo 06 — SARIF export for GitHub / CI code scanning

**Situation.** A team wants validation failures to show up as annotations in the
pull-request "Files changed" tab (GitHub code scanning) and in their security
dashboard, not just as a red build log. `elastdetect validate --sarif` emits a
**SARIF 2.1.0** log that GitHub's `upload-sarif` action (and Azure DevOps, and
most SAST dashboards) ingest directly.

**Where the data came from.** Three rules: one valid, plus two with realistic
defects — an unsupported `type` ("correlation" is not in elastdetect's supported
set) and a negative `risk_score`.

**Run it.**

```bash
elastdetect validate --sarif demos/06-sarif-code-scanning/rules.json
```

**What to expect.** A SARIF JSON document on **stdout** with:

- `"version": "2.1.0"` and the SARIF JSON `$schema`.
- `runs[0].tool.driver.name == "elastdetect"` and the elastdetect version.
- One `results[]` entry per validation error, each with a `ruleId` like
  `elastdetect/type`, a `level` of `error`, a human-readable `message`, and an
  `artifactLocation.uri` pointing at the offending file.

The exit code is still `1` when there are errors, so the gate keeps working.
Only `error`-level findings are exported in this mode (lint warnings are not).

**How to act in CI.** Redirect to a file and upload it:

```yaml
- run: elastdetect validate --sarif rules/ > elastdetect.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: elastdetect.sarif
```

The `|| true` lets the upload step run even when validation fails, so the
annotations appear on the PR. Use a separate required `validate` step (without
`--sarif`) if you also want the job itself to fail.
