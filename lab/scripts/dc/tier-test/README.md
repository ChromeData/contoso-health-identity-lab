# Tier GPO proof: a temporary Tier 2 computer

**Status: RAN · tenant (2026-11-07, capture log E142).** Built, tested, deleted.

The GPO "Tier0 - Deny logon to Tier1 and Tier2" (`../hardening/Set-AdTiering.ps1`)
is linked to `OU=Devices,OU=Tier2` and `OU=Servers,OU=Tier1`. Those OUs hold no
computers, so on its own the GPO denies nothing. These scripts make one small
computer, put it in Tier2\Devices, prove the GPO works there, and remove it.

## Why this machine and not another

| Option | Result |
|---|---|
| Domain-join the Intune VM (vm-win11-01) | **No.** It is Entra joined (Intune and the EPM pilot). Windows cannot be AD joined and Entra joined at once. Hybrid join needs device sync, which Entra Cloud Sync does not do. |
| A VM in eastus2 | **No room.** Free Trial: 4 vCPUs per region, DC01 + vm-win11-01 use 4. Deallocated VMs still count (`az vm list-usage` read 4/4 with vm-win11-01 deallocated; Learn "vCPU quotas" says the same). |
| A VM in eastus | **Chosen.** 0/4 vCPUs used there. No B-series is offered to this subscription; the smallest Windows size is Standard_F1als_v7 (1 vCPU, 2 GiB), $0.107/hour. Global VNet peering to DC01's VNet. |
| AWS EC2 free tier (account 182002546409) | Not chosen. The instance is free, but reaching DC01 needs a site-to-site VPN: an AWS VPN connection (about $0.05/hour) plus an Azure VPN gateway (often 30-45 minutes to create, billed hourly). More parts and more time for the same proof. |

## Credentials: what reaches the Tier 2 machine

The test device is a Tier 2 machine. A Tier 2 admin on it could read any
password that the proof sends to it. Protected run-command parameters hide a
password on the way, not on the machine that gets it.

**What the 2026-11-07 run (E142) did.** It sent two higher-tier passwords to
vm-t2dev-01: the real Tier 0 admin `t0-adm-01` (a Domain Admins member), for
the LogonUser test, and the build admin `contosoadmin`, for the domain join.
The VM had no public IP, only the lab operator could run commands on it, and
it existed about 8 minutes before it was deleted. Even so, it was a design
weakness (Greptile, PR #239). This change does not rotate those two passwords.
Rotating them is the clean close; that is an owner decision (the
`contosoadmin` password is used by other DC01 scripts).

That run's `gpoApplied: true` came from a text search of `gpresult /r`, which
also names filtered-out GPOs. The same run's independent proof still stands:
the secedit export showed the five Deny rights holding the Tier0-Admins SID,
and Windows answered 1385 for the Tier 0 admin. The script now reads
`gpresult /x` (see below).

**What the scripts do now (BUILT, mocked tests; not yet RAN):**

- `New-TierTestAccounts.ps1` (on DC01) makes three DISPOSABLE accounts that
  expire after 3 hours:
  - `t0-tiertest`: member of Tier0-Admins and Protected Users only.
    Tier0-Admins is the SID the deny GPO names, and it gives no AD rights by
    itself. The account is denied like a Tier 0 admin, but its password
    controls nothing.
  - `t2-tiertest`: member of Tier2-Admins only.
  - `tiertest-join`: delegated join rights on `OU=Devices,OU=Tier2` only. It
    replaces `contosoadmin` for the join.
- `Join-Tier2Device.ps1` refuses `contosoadmin` and `Administrator`.
- `Test-TierLogon.ps1` refuses a Tier 0 test account that is a direct
  member of Domain, Enterprise or Schema Admins or Administrators. This check
  runs after the password reached the device, so it stops a wrong proof; it
  does not undo the exposure. Step 4 below is what keeps real admins out.
- `Remove-TierTestAccounts.ps1` (on DC01) deletes the join delegation and
  the three accounts after the proof.

**Not built:** an offline domain join (`djoin /provision` on DC01,
`djoin /requestodj` on the device). It would keep every domain password off
the device. The join blob is itself a secret, and `run-on-dc.py` prints
run-command output, so the blob has no safe path from DC01 to the device
yet. That needs a no-print transfer path first.

## Run (STE)

1. Start DC01: `lab/scripts/demo/preflight.sh`.
2. Make the test passwords (Keychain only): `python3 lab/scripts/dc/tier-test/tier2-device.py test-passwords`.
3. Build: `lab/scripts/operator/op python3 lab/scripts/dc/tier-test/tier2-device.py build`. It refuses if vm-t2dev-01 exists: run step 9 first.
4. Make the disposable accounts on DC01: `lab/scripts/operator/op python3 lab/scripts/dc/run-on-dc.py lab/scripts/dc/tier-test/New-TierTestAccounts.ps1 --secret T0Password=keychain:contoso-lab-tiertest-t0 --secret T2Password=keychain:contoso-lab-tiertest-t2 --secret JoinPassword=keychain:contoso-lab-tiertest-join`. Do not use the real admins (`t0-adm-01`, `t2-adm-01`, `contosoadmin`) in any step that runs on the device.
5. Join: `... run-on-dc.py --rg rg-identity-lab-tiertest --vm vm-t2dev-01 lab/scripts/dc/tier-test/Join-Tier2Device.ps1 --secret JoinPassword=keychain:contoso-lab-tiertest-join`. Wait 2 minutes (restart).
6. Test on the device: `... run-on-dc.py --rg rg-identity-lab-tiertest --vm vm-t2dev-01 lab/scripts/dc/tier-test/Test-TierLogon.ps1 --secret T0Password=keychain:contoso-lab-tiertest-t0 --secret T2Password=keychain:contoso-lab-tiertest-t2`. It must print `VERDICT: PASS`.
7. Test over the network from DC01: `... run-on-dc.py lab/scripts/dc/tier-test/Test-TierNetworkLogon.ps1 --secret T0Password=keychain:contoso-lab-tiertest-t0 --secret T2Password=keychain:contoso-lab-tiertest-t2`. It must print `VERDICT: PASS`.
8. Remove the disposable accounts: `... run-on-dc.py lab/scripts/dc/tier-test/Remove-TierTestAccounts.ps1`.
9. Delete: `lab/scripts/operator/op python3 lab/scripts/dc/tier-test/tier2-device.py delete`.
10. Remove the computer object: `... run-on-dc.py lab/scripts/dc/tier-test/Remove-Tier2DeviceObject.ps1`.
11. Remove the Keychain items: `security delete-generic-password -s <name>` for `contoso-lab-tiertest-admin`, `-t0`, `-t2` and `-join`.

`tier2-device.py build` writes the device's local admin password to the
Keychain only after Azure accepts the VM request.

Tests (offline): `python3 -I -m unittest discover -s lab/scripts/dc/tier-test/tests -v`
and `lab/scripts/powershell/tests/TierTest.Tests.ps1` (in the lab Pester suite).

## How "GPO applied" is read

`Test-TierLogon.ps1` reads `gpresult /x` (XML). The GPO counts as applied
only when its own entry says Enabled, IsValid and FilterAllowed true,
AccessDenied false, and an enabled link has AppliedOrder above 0. A missing
field counts as "not applied". These element names come from gpresult output;
Microsoft Learn does not document the schema, so the next run must compare
`gpoState` with the "Applied Group Policy Objects" list of `gpresult /r`.
The verdict also needs the computer's own secedit export to show the
Tier0-Admins SID in the interactive and network deny rights.

## What the proof shows, in plain words

Names below are the 2026-11-07 run. A new run uses `t0-tiertest` and
`t2-tiertest` (see "Credentials").

- **Tier 0 admin (t0-adm-01):** the password is right, but Windows answers
  "this account may not log on this way here" (error 1385), at the keyboard
  (interactive) and over the network (file share). That is the deny right.
- **Tier 2 admin (t2-adm-01):** signs in both ways.

Not tested: Remote Desktop, and the batch and service deny rights.
