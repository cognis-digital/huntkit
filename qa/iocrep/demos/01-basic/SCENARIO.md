# Demo 01 — Basic IOC triage

You are triaging a queue of indicators pulled from an alert. Some are known-bad
(on your offline reputation feed), some are trusted infrastructure (allowlisted),
and some are unknown values that must be judged purely on heuristics.

## Inputs

- `iocs.txt` — one indicator per line. Includes a defanged C2 URL, a malicious IP,
  a quarantined file hash, a DGA/phishing-style hostname (with punycode), a couple
  of trusted hosts, an internal RFC1918 URL, an unknown SHA-256, and a phishing domain.
- `reputation_db.json` — offline block/allow lists. No network is ever contacted.

## Run it

Table view (human triage):

```
python -m iocrep score --infile demos/01-basic/iocs.txt --db demos/01-basic/reputation_db.json
```

JSON for a pipeline:

```
python -m iocrep score --infile demos/01-basic/iocs.txt --db demos/01-basic/reputation_db.json --format json
```

Self-contained HTML report (the shareable "UI"):

```
python -m iocrep score --infile demos/01-basic/iocs.txt --db demos/01-basic/reputation_db.json --format html -o report.html
```

## What to expect

- `evil-c2.example` URL → **critical** (blocklist C2 hit + executable payload).
- `185.220.101.45` → **medium** (tor-exit blocklist weight).
- `44d8…02f` → **critical** (malware blocklist hit).
- The punycode/phishing hostname → flagged for suspicious TLD, deep subdomain,
  phishing keyword, and punycode homograph — even without a blocklist entry.
- `8.8.8.8` and `github.com` → **allow** (allowlisted, score forced to 0).
- The internal `10.0.0.5` URL → low (private IP credit offsets cleartext http).

Exit code is non-zero because findings at/above `medium` are present — useful in CI.
Every verdict ships its full reasoning so an analyst can see *why*.
