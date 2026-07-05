# Scenario: Ransomware incident timeline

Encoded PowerShell → brute-force admin → shadow-copy deletion → file encryption.

## Expected findings

- SL-T1059-001 (encoded PowerShell)
- SL-T1078-001 (auth fail burst)
- SL-T1486-001 × 2 (ransomware extensions)

## Why this matters

Run SENTRYLOG against your last 60 minutes of logs once a minute. This catches active ransomware.
