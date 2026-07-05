# Demo 01 -- basic detection sweep

A small team mixes three log sources into one file `mixed.log`:

- Linux **syslog** (auth) lines
- An **Apache/Nginx combined** access log line
- A **Windows Sysmon / EVTX-export** JSON event line

SENTRYLOG auto-detects each line format, normalizes it to flat fields, and
runs the built-in Sigma-style rule pack against every event.

## Run it

```sh
# Human-readable table
python -m sentrylog scan demos/01-basic/mixed.log

# Machine-readable JSON (for piping into alerting/ticketing)
python -m sentrylog --format json scan demos/01-basic/mixed.log

# Only high-severity and above
python -m sentrylog scan demos/01-basic/mixed.log --level high

# Inspect how each line was normalized
python -m sentrylog --format json ingest demos/01-basic/mixed.log

# See the active rule pack
python -m sentrylog rules
```

## What you should see

Four detections fire against `mixed.log`:

| Rule | Source line |
|------|-------------|
| `ssh_bruteforce_failed` (medium) | the repeated `Failed password` sshd line |
| `sudo_su_root` (high) | `session opened for user root` |
| `web_sqli_attempt` (high) | the access-log request containing `union+select` |
| `win_suspicious_powershell` (high) | the Sysmon JSON event with `powershell.exe -enc ...` |

The process **exits non-zero (1) when any detection fires**, so you can wire
`scan` straight into a cron job or CI gate:

```sh
python -m sentrylog scan /var/log/auth.log || notify-security-team
```

Clean logs exit `0`.
