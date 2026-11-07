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

## Run (STE)

1. Start DC01: `lab/scripts/demo/preflight.sh`.
2. Build: `lab/scripts/operator/op python3 lab/scripts/dc/tier-test/tier2-device.py build`.
3. Join: `lab/scripts/operator/op python3 lab/scripts/dc/run-on-dc.py --rg rg-identity-lab-tiertest --vm vm-t2dev-01 lab/scripts/dc/tier-test/Join-Tier2Device.ps1 --secret DomainAdminPassword=keychain:contoso-lab-dc01-admin`. Wait 2 minutes (restart).
4. Test on the device: `... run-on-dc.py --rg rg-identity-lab-tiertest --vm vm-t2dev-01 lab/scripts/dc/tier-test/Test-TierLogon.ps1 --secret T0Password=keychain:contoso-lab-ad-t0-adm-01 --secret T2Password=keychain:contoso-lab-ad-t2-adm-01`. It must print `VERDICT: PASS`.
5. Test over the network from DC01: `... run-on-dc.py lab/scripts/dc/tier-test/Test-TierNetworkLogon.ps1 --secret T0Password=keychain:contoso-lab-ad-t0-adm-01 --secret T2Password=keychain:contoso-lab-ad-t2-adm-01`. It must print `VERDICT: PASS`.
6. Delete: `lab/scripts/operator/op python3 lab/scripts/dc/tier-test/tier2-device.py delete`.
7. Remove the computer object: `... run-on-dc.py lab/scripts/dc/tier-test/Remove-Tier2DeviceObject.ps1`.
8. Remove the Keychain item: `security delete-generic-password -s contoso-lab-tiertest-admin`.

## What the proof shows, in plain words

- **Tier 0 admin (t0-adm-01):** the password is right, but Windows answers
  "this account may not log on this way here" (error 1385), at the keyboard
  (interactive) and over the network (file share). That is the deny right.
- **Tier 2 admin (t2-adm-01):** signs in both ways.

Not tested: Remote Desktop, and the batch and service deny rights.
