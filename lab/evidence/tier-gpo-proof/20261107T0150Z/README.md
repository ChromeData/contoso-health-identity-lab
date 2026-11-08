# Tier GPO proof on a real Tier 2 computer (2026-11-07)

Capture log **E142**. The GPO "Tier0 - Deny logon to Tier1 and Tier2" (PR #225,
`Set-AdTiering.ps1`) was live on DC01 but linked only to empty OUs, so it denied
nothing. This run put one real computer in `OU=Devices,OU=Tier2`, tested it, and
deleted it.

| File | What it shows |
|---|---|
| `01-build.log` | `tier2-device.py build`: vm-t2dev-01, Standard_F1als_v7, eastus, no public IP, VNet 10.43.0.0/24 peered to the lab VNet, DNS = DC01 |
| `02-join-tier2-devices.log` | Joined to corp.contosohealthlab.com straight into OU=Devices,OU=Tier2 |
| `03-logon-on-device.log` | On the device: GPO applied (gpresult); the five Deny rights hold Tier0-Admins + Domain/Enterprise/Schema Admins (secedit); LogonUser: t0-adm-01 interactive and network **1385 (logon type not granted)**, t2-adm-01 interactive and network **signed in**. VERDICT PASS |
| `04-smb-from-dc01.log` | A real SMB connection from DC01 to `\\T2DEV01...\TierTest`: t0-adm-01 **refused** ("the user has not been granted the requested logon type at this computer"), t2-adm-01 **connected**. VERDICT PASS |
| `05-delete.log` | The peering on the lab VNet, then the whole resource group deleted |
| `06-ad-object-removed.log` | The T2DEV01 computer object removed; Tier2 holds 0 computers again |

What was NOT tested: Remote Desktop sign-in (no RDP client in the run), and the
batch/service deny rights (no job or service was set up). The device was a
Windows Server standing in for a workstation.

Cost: the VM existed about 8 minutes (01:52Z to about 02:00Z) at $0.107/hour
(eastus retail, Windows), plus a 30 GB Standard HDD and peering traffic for the
same minutes: under $0.05 in total, charged to the Free Trial credit.
