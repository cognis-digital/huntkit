# Contributing to huntkit

The highest-value contributions are **new detection rules** and **new blocklist sources**.

## Add a detection rule
Add a JSON object to the right file under `huntkit/rules/` (or a new category file):
```json
{ "id": "EXE011", "severity": "high", "attack": "T1059.001",
  "name": "Short description", "pattern": "(?i)your-bounded-regex" }
```
Use a real [MITRE ATT&CK](https://attack.mitre.org) technique ID, bound your quantifiers, and add a
test in `tests/` proving it fires on a malicious sample and stays quiet on benign command lines
(the suite enforces the benign check).

## Add a blocklist feed
Add a free, keyless, redistributable feed to `FEEDS` in `huntkit/block_cli.py`.

## Ground rules
- Real, named techniques only — no filler. Every rule maps to ATT&CK.
- Low false-positive: benign admin commands must not trip rules.
- Deterministic + stdlib. No runtime deps, no network except `block update`.

```bash
pip install -e ".[dev]"
pytest -q
huntkit rules stats && huntkit block stats
```

New TTPs / feeds: [Discussions](https://github.com/cognis-digital/huntkit/discussions).
