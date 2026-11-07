# ADR 0027: Microsoft-native PAM

- **Status:** Accepted (2026-11-06). **Supersedes [ADR 0007](0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) and [ADR 0019](0019-pam-vault-high-availability-and-dr.md).** This PR removes CyberArk and Conjur from the lab. Each Microsoft piece has its own status in the table below. At the time of writing, none of them has run in the tenant.
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
| Keep secrets for people and programs | HashiCorp Vault, Conjur OSS | **Azure Key Vault**, RBAC mode. Azure RBAC role assignments control access, and people get them as PIM-eligible roles | Azure subscription; pay per use | The lab vault `kv-idlab-20f1` exists (RBAC mode). The leak proof below: see its PR |
| Give Terraform a secret without keeping it | Conjur `conjur_secret` ephemeral resource | Key Vault through Terraform's **ephemeral resource**. The usual **data source** read leaves the secret in the state file. The ephemeral read leaves it nowhere | none extra | Redone against Key Vault in `lab/secrets/state-leak/` (separate PR, which reports its own measured result). The Conjur run of 2026-11-06 stays as a historical record in `lab/evidence/conjur-state-leak/` |
| Record admin sessions | Apache Guacamole | **Azure Bastion session recording.** It needs the **Premium SKU** and a storage account container. It records browser (portal) sessions only, not the native client. It cannot be used together with Entra ID sign-in for RDP in the portal | Azure; Premium is billed per hour | Pending (see its PR). Bastion runs only while recording, then it is deleted or scaled down |
| Rotate passwords | Vault LDAP secrets engine (CPM-style rotation) | **Windows LAPS**, with the password backed up to Entra ID or AD | Included in Windows; Entra backup needs Entra ID P1 or P2 | DC01: another helper's slice. CH-WIN11-01 (the Intune PC): DESIGNED. The Intune policy needs `DeviceManagementConfiguration.ReadWrite.All`, which the lab operator does not hold, so a person creates it |
| Admin rights for one app, for a short time | none (CyberArk EPM was out of scope) | **Intune Endpoint Privilege Management (EPM)**, with a *support approved* elevation rule: the user asks, an admin approves, and the app runs elevated | Licensed: the tenant's `SPE_E5` trial SKU lists the `Intune-EPM` service plan, provisioning status `Success` (read from Graph `subscribedSkus` on 2026-11-07). The trial ends 2026-11-26 | DESIGNED. The operator cannot create Intune policies (same missing permission as above), so a person creates them |
| Just-in-time admin roles | PIM (unchanged) | **PIM** for Entra roles, groups and Azure resources | Entra ID P2 | RAN · tenant (ADR 0020, ADR 0025) |
| Vault HA and DR | Three-node Vault Raft cluster, timed DR drill (ADR 0019) | Not needed. Key Vault is a managed service. Microsoft replicates its contents in the region and to a paired region | none | ADR 0019 superseded |
| Safe reconcile (psPAS, PR #213) | psPAS safe and account reconcile | Not needed. Microsoft has no "safe". The nearest thing is "who can read which Key Vault secret", and that is Azure RBAC, managed as code. The nightly drift check ([ADR 0021](0021-configuration-drift-detection.md)) reconciles it | none | PR #213 closed unmerged on 2026-11-06, with the reason in a comment |

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
$10.80 a day, so it must never be left running.

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
  It cannot record native-client sessions, and it cannot be combined with
  Entra ID sign-in for RDP in the portal. It records every session through
  that Bastion host.
- **Intune writes need a person.** The lab operator holds
  `DeviceManagementConfiguration.Read.All` only. Granting itself write
  access would be a self-escalation, so EPM and LAPS policies on the Intune
  PC are created by a person, from the steps in their PR.
- **A live Sentinel rule changes on apply.** The Vault anomaly rule's
  output column `CyberArkAnalogue` is renamed `PamTerm` (neutral values),
  in the KQL, the SPL twin, the Terraform custom details and the KQL test
  cases. The rule is on (`enable_itdr_detections_v2 = true`), so the next
  apply updates it in place.

## How it is measured

| Measure | Source | Target |
|---|---|---|
| Secret copies in Terraform files, data source vs ephemeral read, against a real Key Vault | `lab/secrets/state-leak/run.sh` (separate PR) | data source ≥ 1 in state; ephemeral 0 in state, backup and plan. Fill after running |
| An admin reaches DC01 through Bastion only after a PIM activation, and the session plays back | Bastion PR capture record | activation time, connect time, recording present. Fill after running |
| Hours Bastion Premium existed | Azure activity log (create and delete times) | each capture under 2 hours. Fill after running |
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
- Key Vault leak proof and Bastion recording: see their PRs. This ADR
  claims no result for them.

## Sources (checked 2026-11-07)

1. Azure Key Vault overview: https://learn.microsoft.com/en-us/azure/key-vault/general/overview
2. Record Bastion sessions (Premium SKU required; no native client; not with Entra ID RDP in the portal; Storage Blob Data Reader to view): https://learn.microsoft.com/en-us/azure/bastion/session-recording
3. Azure Bastion pricing (billed hourly from deployment until deletion): https://azure.microsoft.com/en-us/pricing/details/azure-bastion/ ; numbers from https://prices.azure.com/api/retail/prices
4. Endpoint Privilege Management overview (support approved elevation): https://learn.microsoft.com/en-us/intune/epm/overview
5. Intune advanced capabilities (licensing through Intune Plan 2, the Intune Suite and select Microsoft 365 bundles): https://learn.microsoft.com/en-us/intune/fundamentals/advanced-capabilities
