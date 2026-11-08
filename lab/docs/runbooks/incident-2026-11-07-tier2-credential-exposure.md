# Incident record: two Tier-0 passwords typed on a Tier 2 machine (2026-11-07)

Status: **closed**. Reviewed 2026-11-08 (hostile review round 2, R6).
Evidence: capture log `E142r`, `lab/evidence/tier2-exposure-review/20261108T2105Z/`.

## What happened

The Tier GPO proof (PR #239, capture log E142) built a temporary Tier 2
member server, `vm-t2dev-01` (10.43.0.4, no public IP, a peered VNet). Its
first version passed two Tier-0 passwords to scripts that ran **on that
machine**:
- `contosoadmin`, the built-in Domain Admin, to join the machine to the domain.
- `t0-adm-01`, to show that a Tier 0 logon is refused on Tier 2.

Both were protected Run Command parameters, so they were decrypted on the
VM. Error 1385 ("logon type not granted") comes only after the password is
accepted, so the Tier 2 machine saw a valid Domain Admin password. A Tier 0
credential must never touch a lower tier. The test broke that rule.

**Cause:** a design flaw in the test. It used the real Tier-0 accounts
instead of a delegated join account and a no-rights test account.

## Scope and window

- The machine existed for about 8 minutes and was deleted with its
  resource group and peering (E142).
- DC01 saw traffic from 10.43.0.4 only between **01:54:56Z and 01:56:32Z**
  on 2026-11-07.

## Log review (DC01 Security log in Sentinel, read-only, 2026-11-08)

Window searched: 2026-11-07 01:00Z to 2026-11-08 18:15Z (the `contosoadmin`
rotation).

| Check | Result |
|---|---|
| Logons and tickets from 10.43.0.0/24 | Only the expected ones, all 01:54:56Z-01:56:32Z: `contosoadmin` 6 network logons and 2 TGTs (the domain join, NTLM and Kerberos), one password reset by `contosoadmin` on `T2DEV01$` (the join), `t2dev01$` machine logons, `t0-adm-01` 2 TGTs and `t2-adm-01` 2 TGTs (the proof). **Nothing from 10.43.* after 01:56:32Z** |
| `contosoadmin` from anywhere else | DC01 itself (Run Command and services: `::1`, `-`), and one RDP logon from 10.42.250.5 at 02:13Z: the Azure Bastion subnet, the recorded session E133 |
| `t0-adm-01` from anywhere else | DC01 itself only (`::1`), up to the rotation at 03:58Z |
| DCSync (4662 with the replication rights) | Only `DC01$`, the DC's own account (12 events). No other principal |
| Group membership additions (4728, 4732, 4756) | None after 01:50Z. Removals (4729, 4733, 4757) are not collected, so they cannot be ruled out |
| Password resets and account changes | The planned ones only: the `t0-adm-01` rotation (03:58Z, E156), the `svc-pam-discovery` retirement (03:55Z, E157), the `contosoadmin` rotation (2026-11-08 18:09Z, E178), and the HR provisioning gMSA on test workers |

**Not checked (limits):** the VM's own logs (the VM was deleted). DC01's
data collection rule collects only 4624, 4625, 4648, 4662, 4672, 4720,
4722, 4724, 4725, 4728, 4732, 4738, 4756, 4768 and 4769. So these are NOT
covered, and an empty result says nothing about them: 5136 (GPO and
AdminSDHolder edits), group removals (4729, 4733, 4757), self password
changes (4723), Kerberos pre-auth failures (4771) and NTLM validation
(4776). The conclusions above are limited to collected events.

## Containment and fixes

1. `t0-adm-01` rotated about 2 hours later (E156, PR #251, open).
2. `contosoadmin` rotated about 40 hours later, on the owner's decision
   (E178, PR #262, merged).
3. The test is to use a delegated join account and a no-rights test
   account (PR #239 follow-up). Owner task.
4. Since PR #273 (merged; live once the owner applies envs/operator), the operator can no longer read the Domain
   Admin password from Key Vault outside a write session.

## The ready answer

"Design flaw in the test, and I own it. I treated both credentials as
compromised and rotated them. The VM lived 8 minutes with no public IP. I
reviewed the DC logs for the whole window: only the expected join and test
logons, all inside 96 seconds, nothing from that subnet afterwards, no
DCSync by anyone but the DC, no group additions. Changing the test to use a
delegated join account and a no-rights test account is still an owner task."
