# contosoadmin (AD build admin) password rotation, 2026-11-08 (RAN · tenant)

Why: the password was typed into a temporary Tier 2 VM in the PR #239 proof
(the VM is deleted). A password typed on a lower-tier machine counts as known
to it. The owner approved the rotation on 2026-11-08.

Who: the lab operator (certificate, `lab/scripts/operator/op`), no person, no RDP.

| File | What it shows |
|---|---|
| `rotate-contosoadmin.log` | `rotate-build-admin.py`: Keychain and Key Vault copies matched before; no service or task on DC01 runs as contosoadmin; pwdLastSet moved; Kerberos ticket with the new password; old password refused by the KDC; Key Vault new version read back |
| `cloudsync-after.txt` | Both Cloud Sync jobs Active and Succeeded after the rotation (the password hash job's pause started while DC01 was off, before the rotation) |
| `preflight-after.txt` | `preflight.sh --check` READY after the rotation |

No password is in any file here. DC01 was started by preflight.sh and deallocated afterwards.

## Limit of this run (found in review, PR #262)

This run used the first version of `Reset-BuildAdminPassword.ps1`. In that version,
`KERBEROS-OLD: REFUSED` meant "the ticket request with the old password failed" for
ANY error. It did not check that the error was the KDC's bad-password answer
(SEC_E_LOGON_DENIED). One second earlier, the same KDC issued a ticket for the new
password, so an outage is unlikely. But this run does not prove the reason. The
script now prints REFUSED only for SEC_E_LOGON_DENIED and fails on any other error.
The new-password result (ticket issued) is not affected.
