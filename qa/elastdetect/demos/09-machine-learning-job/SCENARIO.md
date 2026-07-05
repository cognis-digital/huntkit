# Demo 09 — Machine-learning rules need a job id, not a query

**Situation.** A team adds an ML-based detection on top of an Elastic prebuilt
anomaly job. Unlike query rules, `machine_learning` rules have **no `query`** —
they reference a job id instead. This demo shows elastdetect enforcing exactly
that distinction.

**Where the data came from.** Two ML rules:

- `cognis-demo-09-ml-rare-process` — correctly references a prebuilt job id
  (`v3_rare_process_by_host_windows_ecs`, a real Elastic prebuilt host-anomaly
  job name) and sets an `anomaly_threshold`.
- `cognis-demo-09-ml-missing-job` — omits the job id and should fail.

**Run it.**

```bash
elastdetect validate demos/09-machine-learning-job/rules.json
```

**What to expect.** One error and a non-zero exit (`1`):

```
[error] rule 'cognis-demo-09-ml-missing-job': machine_learning_job_id: machine_learning rule requires a job id
Validated 2 rule(s): 1 ok, 1 with errors (1 error(s)).
```

Note the first rule passes even though it has **no `query`** — elastdetect does
not require a query for ML rules, only a job id.

**How to act.** Add the missing `machine_learning_job_id` to the second rule
(matching a job that actually exists / is installed on your cluster) and re-run
until clean.
