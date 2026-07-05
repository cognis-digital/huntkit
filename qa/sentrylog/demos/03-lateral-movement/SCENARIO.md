# Scenario: Active Directory brute-force + recon

Encoded PowerShell on workstation + sustained auth-fail burst against domain controller.

## Expected findings

- SL-T1059-001
- SL-T1078-001 (450 fails on backup-admin@DC-01)

## Why this matters

Classic lateral-movement pattern. SENTRYLOG correlates across host fields.
