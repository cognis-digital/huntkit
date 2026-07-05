# Demo 08 — Validating a `new_terms` "first seen" rule

**Situation.** A threat-hunting team wants to know the first time any remote
admin / RMM tool appears on a host, because attackers frequently bring their own
remote-access tooling. The Elastic `new_terms` rule type is built for this: it
alerts on field-value combinations not seen in the history window.

**Where the data came from.** A single `new_terms` rule keyed on
`host.name` + `process.name`, with a 14-day history window. The process names in
the query are well-known commercial RMM/remote-access executables (AnyDesk,
TeamViewer, PsExec, Atera, ScreenConnect) — no fabricated hashes or identifiers.

**Run it.**

```bash
elastdetect validate demos/08-new-terms-rare-process/rules.json
```

**What to expect.** Exit `0`. `new_terms` is a query-bearing type, so elastdetect
checks that the common fields are valid and that a non-empty `query` is present —
both hold here. (`new_terms_fields` and `history_window_start` are Elastic
runtime fields that elastdetect carries through unchanged.)

**How to act.** Maintain the executable list as your environment's sanctioned vs.
unsanctioned tooling changes. During a planned RMM rollout, expect a burst of
first-seen alerts (documented as a false positive) and consider temporarily
disabling the rule or excluding the deployment window.
