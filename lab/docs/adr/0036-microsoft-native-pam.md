# ADR 0036: Microsoft-native PAM

- **Status:** Accepted (2026-11-06). **Supersedes [ADR 0007](0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) and [ADR 0019](0019-pam-vault-high-availability-and-dr.md).** This PR removes CyberArk and Conjur from the lab. Each Microsoft piece has its own status in the table below. On 2026-11-07 two pieces ran in the tenant: the Key Vault leak proof (PR #235) and Bastion session recording (PR #247). EPM and LAPS on the Intune PC are BUILT and wait for a person (they need an Intune write permission the operator does not hold).
- **Date:** 2026-11-06
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-06, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

PAM means privileged access management: the tools that control admin
access. Four jobs matter here:

1. **Keep secrets.** A secret is a password, key or token. It lives in a
   locked store, and only named callers can read it.
2. **Record admin sessions.** When an admin connects to a server, the
   session is recorded so that someone can play it back later.
3. **Rotate passwords.** Rotation means changing a password on a schedule
   or after use, so that a stolen copy stops working.
4. **Give admin rights only for a task.** A standard user gets admin rights
   for one approved app, for a short time.

ADR 0007 used local, open-source stand-ins for CyberArk products. HashiCorp
Vault kept secrets and rotated AD passwords. Apache Guacamole recorded
sessions. CyberArk Conjur OSS served secrets to programs. ADR 0019 added a
three-node Vault cluster for high availability (HA) and disaster recovery
(DR). PR #213 started a port of a psPAS script. psPAS is a PowerShell
module for CyberArk's API. The script reconciled CyberArk "safes" (folders
of credentials).

On 2026-11-06 the owner decided to drop CyberArk completely. That includes
Conjur and psPAS. Where Microsoft offers a product for a job, the lab uses
it. The owner's reasons:

- The lab is about Microsoft identity. A CyberArk stand-in teaches a
  product the lab does not run.
- The Microsoft products work in the real tenant. They are not laptop
  containers, so the demo can show a real result.
- Most of them are already licensed. The lab's Microsoft 365 E5 trial
  includes Entra ID P2 (PIM) and Intune (including the `Intune-EPM`
  service plan).

## Options considered

1. **Keep the ADR 0007 stand-ins** (Vault, Guacamole, Conjur). They have
   already run on the laptop harness. But they only stand in for a product
   the lab will not use, and they never ran against DC01. Rejected.
2. **Buy a PAM vendor** (CyberArk, BeyondTrust or Delinea). This was the
   desk review in [`vendor-evaluation.md`](../vendor-evaluation.md). It
   costs money, the lab has no licence, and the rules forbid purchases.
   Rejected.
3. **Use Microsoft products for each job, and keep PIM as the
   just-in-time core.** Chosen.

## Decision

Each job goes to one Microsoft product:

| Job | Was (ADR 0007 / 0019) | Now | Licence | Status (2026-11-07) |
|---|---|---|---|---|
| Keep secrets for people and programs | HashiCorp Vault, Conjur OSS | **Azure Key Vault**, RBAC mode. Azure RBAC role assignments control access, and people get them as PIM-eligible roles | Azure subscription; pay per use | The lab vault `kv-idlab-20f1` exists (RBAC mode). PIM-eligible Key Vault Secrets Officer for people: BUILT, flag off (PR #232). Kubernetes workload secrets from Key Vault through the CSI driver and Workload ID: RAN · tenant (PR #232) |
| Give Terraform a secret without keeping it | Conjur `conjur_secret` ephemeral resource | Key Vault through Terraform's **ephemeral resource**. The usual **data source** read leaves the secret in the state file. The ephemeral read leaves it nowhere | none extra | **RAN · tenant** 2026-11-07 (PR #235, capture log E132), against a throwaway vault deleted afterwards: data source 1 copy in state, 1 in the backup, 2 in the saved plan; ephemeral 0 / 0 / 0. The Conjur run of 2026-11-06 stays as a historical record in `lab/evidence/conjur-state-leak/` |
| Record admin sessions | Apache Guacamole | **Azure Bastion session recording.** It needs the **Premium SKU** and a storage account container. It records browser (portal) sessions only, not the native client. It cannot be used together with Entra ID sign-in for RDP in the portal | Azure; Premium is billed per hour | **RAN · tenant** 2026-11-07 (PR #247, capture log E133): adm-ava.lin was refused DC01 (403), activated PIM-eligible Reader on rg-identity-lab for 1 hour, connected to DC01 through Bastion, and the session was recorded; the reviewer adm-mei.tanaka played it back in the portal. Bastion existed about 58 minutes (about $0.45), then was deleted. **Demonstrated, not always on** in the lab (Premium costs about $10.80 a day) |
| Rotate **local** admin passwords | Vault LDAP secrets engine (CPM-style rotation) | **Windows LAPS**, with the password backed up to Entra ID or AD | Included in Windows; Entra backup needs Entra ID P1 or P2 | DC01 (DSRM password, backed up to AD): RAN · tenant (PR #225, another helper). CH-WIN11-01 (the Intune PC): BUILT, `lab/scripts/intune/New-IntuneEpmAndLaps.ps1` (PR #247). The Intune policy needs `DeviceManagementConfiguration.ReadWrite.All`, which the lab operator does not hold, so a person creates it |
| Domain privileged and service accounts | Vault LDAP rotation of AD accounts (CPM-style) | **Microsoft has no CPM equivalent.** Windows LAPS covers local accounts only. Instead: **gMSA / dMSA** for services (AD rotates the password; nobody knows it); **named Tier-0 admin accounts** per person with no shared password, ideally smart card or Windows Hello for Business with *Smart card required for interactive logon* (AD rolls the hidden password); **krbtgt** rotation twice a year (owner task); **AD tiering** so Tier-0 accounts log on only to Tier-0 systems | Windows Server AD; included | AD tiering: RAN · tenant (PR #225). gMSA, smart-card-required accounts and krbtgt rotation: DESIGNED. The lab still has a shared built-in `contosoadmin`; its password is in the Mac's Keychain and was used for the Bastion capture |
| Admin rights for one app, for a short time | none (CyberArk EPM was out of scope) | **Intune Endpoint Privilege Management (EPM)**, with a *support approved* elevation rule: the user asks, an admin approves, and the app runs elevated | Licensed: the tenant's `SPE_E5` trial SKU lists the `Intune-EPM` service plan, provisioning status `Success` (read from Graph `subscribedSkus` on 2026-11-07). The trial ends 2026-11-26 | BUILT (`New-IntuneEpmAndLaps.ps1`, PR #247), not run. The operator cannot create Intune policies (same missing permission as above), so a person creates them. An approval lasts **24 hours**, fixed by Microsoft (no shorter period, no cancellation) |
| Just-in-time admin roles | PIM (unchanged) | **PIM** for Entra roles, groups and Azure resources | Entra ID P2 | RAN · tenant (ADR 0020, ADR 0025) |
| Vault HA and DR | Three-node Vault Raft cluster, timed DR drill (ADR 0019) | Not needed. Key Vault is a managed service. Microsoft replicates its contents in the region and to a paired region | none | ADR 0019 superseded |
| Safe reconcile (psPAS, PR #213) | psPAS safe and account reconcile | Not needed. Microsoft has no "safe". The nearest thing is "who can read which Key Vault secret", and that is Azure RBAC, managed as code and shown in every Terraform plan. **Not covered today:** the nightly drift check ([ADR 0021](0021-configuration-drift-detection.md)) reads Entra settings through Graph; it does not read Azure RBAC, so a hand-made Key Vault role assignment is not caught. Adding an Azure RBAC read to it is future work | none | PR #213 closed unmerged on 2026-11-06, with the reason in a comment |

The local Vault and Guacamole harness in `lab/pam/` stays for now as an
earlier build of the same ideas, with CyberArk and Conjur removed. A
later PR retires it once Bastion recording and LAPS are proven in the
tenant.

## Costs

Retail prices from the Azure Retail Prices API, region eastus2 (the lab's
region), read 2026-11-07. verify: prices change.

| Item | Price | How the lab limits it |
|---|---|---|
| Azure Bastion Premium | $0.45 per hour, billed from deployment until deletion | It runs only for a capture, then it is deleted or scaled down |
| Azure Bastion Standard | $0.29 per hour | not used |
| Azure Bastion Basic | $0.19 per hour (no session recording) | not used |
| Azure Bastion data out | first 5 GB a month free | a recording session is far below this |
| Azure Key Vault Standard | $0.03 per 10,000 operations | the lab makes a few hundred operations a day |
| Intune EPM | included in the lab's E5 trial SKU | no purchase |
| Windows LAPS | included in Windows | no purchase |

The program's cost rule is: anything over about $5 a day is stopped or
deleted when it is not in use. A Premium Bastion left running costs about
$10.80 a day, so it must never be left running. In the lab, recording is
**demonstrated, not always on**: `lab/bastion/capture.sh` creates it for a
capture and deletes it afterwards. The 2026-11-07 capture: Bastion existed
from 01:59Z to 02:57Z (about 58 minutes), about $0.45.

**Production cost.** Recording must be always on in production, or an
unrecorded window exists. One Premium host (two instances) costs
$0.45 x 730 h = about **$330 a month**; each extra instance adds $0.22 an
hour (about $160 a month). Add the storage for recordings (a 1 min 26 s
session was 1.3 MB) and the outbound data after the first 5 GB.

## Consequences

- **The demo shows real products in the real tenant.** A recorded Bastion
  session to DC01 replaces a Guacamole session to a Linux container that
  stood in for DC01.
- **Fewer moving parts.** There is no vault to unseal, no Raft cluster and
  no Conjur database. Key Vault availability is Microsoft's job.
- **Lost: exclusive check-out.** A Vault library lets one person hold an
  account at a time. Microsoft has no direct equal. PIM gives time-bound,
  approved, audited role access instead. Combined with LAPS rotation and a
  named admin account per person, nobody shares a password.
- **Lost: brokered credential injection.** Guacamole typed the password
  for the admin. Bastion does not. The admin signs in with their own named
  account, after a PIM activation.
- **Bastion recording limits.** It records portal (browser) sessions only.
  It cannot record native-client sessions, so the capture's Bastion has
  tunnelling (the native client) off. It records every session through that
  Bastion host.
- **Open trade-off: recording vs Entra ID sign-in to the VM.** Learn says
  Entra ID RDP in the portal "can't be used concurrently with graphical
  session recording". So a recorded session means the admin types an AD
  password. That keeps AD passwords for Tier-0 accounts alive, which is
  exactly what smart-card-required accounts try to remove. The lab chooses
  recording, with named per-admin accounts as the target (see the domain
  accounts row). Revisit when Microsoft lifts the limit.
- **Playback needs the storage account key (seen live, not in Learn).**
  Learn says a viewer needs Storage Blob Data Reader. On 2026-11-07 the
  portal's player called `listKeys` (403 without it) and built an
  account-key SAS, which also needs shared-key access on. The capture
  turns shared-key access on and gives the reviewer the key role for one
  hour, then turns it off. For that hour the reviewer could delete
  recordings. Production: copy recordings to a WORM container the
  reviewer cannot change (the recording container itself must have no
  immutability policy, per Learn).
- **Intune writes need a person.** The lab operator holds
  `DeviceManagementConfiguration.Read.All` only. Granting itself write
  access would be a self-escalation, so EPM and LAPS policies on the Intune
  PC are created by a person, from the steps in their PR.
- **The Vault anomaly rule is not live, so its rename changes nothing in
  the tenant.** Its output column `CyberArkAnalogue` is renamed `PamTerm`
  (neutral values) in the KQL, the SPL twin, the Terraform custom details
  and the test cases. The rule `vault_privileged_access_anomaly` is in
  `itdr_exclude_rules` (`lab/terraform/envs/dev/lab.tfvars`) and is not in
  the live Sentinel rule list (read as the operator, 2026-11-07).
- **The DC-logon rule leaves Sentinel.** `tier0-logon-without-checkout`
  builds its windows from Vault check-out events (`VaultCheckout_CL`). Key
  Vault and LAPS do not emit those events, so once Vault is retired the
  rule has no source. This PR adds it to `itdr_exclude_rules`, so the next
  apply **deletes** that one live Sentinel rule (the plan says 1 to
  destroy). The KQL stays for the local harness. Its Microsoft replacement
  is DESIGNED, not built: (a) any remote-interactive logon (type 10) on
  DC01 whose source is not `AzureBastionSubnet` (10.42.250.0/26) is an
  alert, because Bastion is the only way in; (b) a Bastion logon by a
  Tier-0 account with no Azure PIM activation on `rg-identity-lab` by the
  paired admin in the hour before is an alert (PIM audit events in
  `AuditLogs`, plus a table that pairs each AD admin account with its Entra
  admin).

## How it is measured

| Measure | Source | Target |
|---|---|---|
| Secret copies in Terraform files, data source vs ephemeral read, against a real Key Vault | `lab/secrets/state-leak/run.sh` (PR #235) | data source ≥ 1 in state; ephemeral 0 in state, backup and plan. **2026-11-07: 1 / 1 / 2 vs 0 / 0 / 0, 239 s** |
| An admin reaches DC01 through Bastion only after a PIM activation, and the session plays back | `lab/bastion/` capture record (PR #247) | **2026-11-07:** 403 before PIM; activation 1 h (02:11:31Z to 03:11:28Z, read back from ARM); DC01 page opened 12 s after the portal showed it active; session 73 s; recording 1.3 MB, listed and played back |
| Hours Bastion Premium existed | `capture.sh` log and the Azure activity log | each capture under 2 hours. **2026-11-07: about 58 minutes** (create sent 01:59:00Z, gone by 02:57:26Z) |
| EPM request and approval shown | Intune EPM reports | DESIGNED: fill after a person creates the policy |
| CyberArk, Conjur or psPAS named outside history | `grep -rliE 'cyberark\|conjur\|pspas'` excluding `lab/evidence/**`, superseded ADRs and the vendor desk review | none in code, CI or the tour |

## Revisit trigger

- Microsoft changes the Bastion recording SKU or limits.
- EPM leaves the E5 SKU, or the trial ends (2026-11-26) before the EPM
  proof runs.
- A real employer requires a PAM vendor product.

## Evidence

- Licence read: Graph `GET /v1.0/subscribedSkus` as the lab operator,
  2026-11-07. `SPE_E5` (trial, `nextLifecycleDateTime` 2026-11-26) includes
  `Intune-EPM` (`bb73f429-78ef-4ff2-83c8-722b04c3e7d1`), status `Success`.
- Intune PC: Graph `managedDevices` lists `CH-WIN11-01` (Windows, MDM,
  compliant, last sync 2026-10-29). The VM `vm-win11-01` was deallocated
  on 2026-11-07.
- Operator permissions: the operator's Graph token roles, read
  2026-11-07, include `DeviceManagementConfiguration.Read.All` and not
  `.ReadWrite.All`.
- PR #213: closed unmerged with a decision comment, 2026-11-06.
- Key Vault leak proof: PR #235, capture log E132.
- Bastion recording: PR #247, capture log E133.

## Sources (checked 2026-11-07)

1. Azure Key Vault overview: https://learn.microsoft.com/en-us/azure/key-vault/general/overview
2. Record Bastion sessions (Premium SKU required; no native client; not with Entra ID RDP in the portal; Storage Blob Data Reader to view): https://learn.microsoft.com/en-us/azure/bastion/session-recording
3. Azure Bastion pricing (billed hourly from deployment until deletion): https://azure.microsoft.com/en-us/pricing/details/azure-bastion/ ; numbers from https://prices.azure.com/api/retail/prices
4. Endpoint Privilege Management overview (support approved elevation): https://learn.microsoft.com/en-us/intune/epm/overview
5. Intune advanced capabilities (licensing through Intune Plan 2, the Intune Suite and select Microsoft 365 bundles): https://learn.microsoft.com/en-us/intune/fundamentals/advanced-capabilities
6. EPM support approvals (approval valid 24 hours, no custom period): https://learn.microsoft.com/en-us/intune/epm/manage-support-approvals
