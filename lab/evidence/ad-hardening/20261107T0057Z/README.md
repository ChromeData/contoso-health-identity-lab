# AD hardening on DC01, 2026-11-07 (RAN on the lab's DC01)

Code: `lab/scripts/dc/hardening/`. Every run went through `run-on-dc.py` as the lab operator.
Secrets were protected run-command parameters from the Mac Keychain, and the helper scrubs them from output.
No password appears in these logs.

| File | What |
|---|---|
| 00-before.txt | discovery, PingCastle before (58), Cloud Sync before |
| 01 to 03 | Set-AdTiering: dry run, first apply (stopped at the GPO step: a wildcard bug, fixed), the full apply |
| 04 to 06 | Enable-WindowsLaps: dry run, first apply (stopped at the read-back: schema cache, fixed), the full apply + one DSRM rotation |
| 07 | Test-AdHardening -SignIn yes: 35 PASS, 0 FAIL |
| 08 | PingCastle after (50) |
| 09 | Cloud Sync after |

`SHA256SUMS` covers every file in this folder except itself.
