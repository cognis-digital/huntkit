# sentrylog deep demo — full intrusion kill-chain across mixed telemetry

This scenario stitches together a realistic intrusion that spans Windows
process telemetry, a Linux host, a web edge, AWS CloudTrail, and netflow —
exactly the heterogeneous log soup a SOC analyst triages. `sentrylog` applies
its bundled ~25 Sigma-style detection rules and maps every hit to a MITRE
ATT&CK technique.

## The story

1. A finance user opens a malicious Word doc; Office spawns an `-enc`
   PowerShell (T1059.001) and `cmd.exe` (T1059.003).
2. `certutil` pulls a second-stage payload from a C2 IP (T1140).
3. `procdump` + Mimikatz dump and parse LSASS credentials (T1003.001).
4. Persistence is planted: a Run key (T1547.001) and a scheduled task
   (T1053.005); the attacker adds themselves to local admins (T1136.001).
5. Anti-recovery / anti-forensics: shadow copies deleted (T1490) and the
   Security event log cleared (T1070.001).
6. On a Linux app server a reverse shell fires (T1059.004), `/etc/shadow`
   is read (T1003.008), and SSH brute force is logged (T1110.001).
7. In AWS, CloudTrail logging is stopped (T1562.008), a security group is
   opened to `0.0.0.0/0` (T1562.007), and the root account is used (T1078.004).
8. Netflow shows beacons to the C2 on suspicious ports (T1571).

`notepad.exe` and the `/healthz` probe are benign noise that must NOT alert.

## Run it

```bash
# JSON-lines host/cloud/web events — exits 1 because findings exist
python -m sentrylog scan demos/02-deep/events.jsonl

# CSV netflow — catches the C2 beacon ports
python -m sentrylog scan demos/02-deep/network.csv

# rollup by MITRE technique / severity
python -m sentrylog --format json summary demos/02-deep/events.jsonl

# only the worst hits
python -m sentrylog scan demos/02-deep/events.jsonl --level critical

# list / inspect the bundled pack
python -m sentrylog rules
python -m sentrylog rule cred-mimikatz
```

Expected: the `events.jsonl` scan reports findings at `critical` severity
(Mimikatz, LSASS dump, shadow-copy delete, CloudTrail stop) and exits non-zero,
while the two benign events produce no findings.
