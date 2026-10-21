# Mock HR → Entra ID inbound provisioning

This folder is the **HR system of record** for the Contoso Health identity lab.
It exists so the whole joiner/mover/leaver story can run end-to-end without a
paid HR SaaS sandbox.

> **On camera:** this stand-in is row 1 of
> [`STAND-INS.md`](../../docs/STAND-INS.md), and its line is said in §2 (Joiner)
> of the walkthrough video (its script is kept outside this repository).
> STAND-INS.md holds the authoritative wording, so it isn't copied here.

## What stands in for what

| In this lab | In production | Why substituted |
|---|---|---|
| `hr_feed.csv` + `Invoke-InboundProvisioning.ps1` | Workday / SuccessFactors native provisioning connector | No free HR SaaS sandbox for an individual |
| Flat CSV worker export | HRIS worker API / scheduled extract | An extract pushed through API-driven provisioning keeps this SCIM shape and endpoint; the native connectors read the HRIS API instead (below) |

**The substitution is only the *source*.** The target — Entra ID API-driven
inbound provisioning — is the real Microsoft product and the real endpoint:

```
POST /servicePrincipals/{servicePrincipalId}/synchronization/jobs/{jobId}/bulkUpload
Content-Type: application/scim+json
```

Entra's native Workday and SuccessFactors connectors don't call this endpoint.
They work the other way round: the Entra provisioning service reads the HRIS on
a schedule ([cloud HR provisioning plan](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/plan-cloud-hr-provision)).
This push endpoint is Microsoft's route for any other system of record: an HR
ISV's integration, or a CSV/SQL extract like this one
([API-driven inbound provisioning](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/inbound-provisioning-api-concepts)).
Both routes feed the same Entra provisioning service and produce the same
worker account. Swapping the mock for a real HRIS changes *how worker data
reaches Entra* (and the source side of the attribute mappings), not what runs
once the account exists: Lifecycle Workflows, access packages, CA and PIM.

## Files

| File | Role |
|---|---|
| `hr_feed.csv` | Sample roster: Dana Okafor (protagonist) + joiners, actives, a mover, and a leaver, plus the IT personas: Joan Ferris (IT Director), Ava Lin (IAM Engineer), Raj Patel (Service Desk Analyst) and Mei Tanaka (Access Governance Lead). Their workforce accounts get no admin role; their separate `adm-` accounts come from `lab/iga/admin-accounts.json` (`New-AdminAccounts.ps1`). Column contract is documented in the file header. |
| `.gitignore` | Keeps `.state/` (the mass-change guard's last-pushed roster) out of git. |
| `Invoke-InboundProvisioning.ps1` | Reads the CSV, maps each row to a SCIM Enterprise User, chunks into ≤50-record batches, and POSTs SCIM `bulkUpload` payloads to the provisioning job. |
| `README.md` | This file. |

## Key constraints (baked into the script)

- **Mass-change guard (risk register R10).** A run that would DISABLE more
  than `-MaxChanges` accounts (default 10 `leaver` rows) stops before sending
  anything, `-WhatIf` included: a broken HR extract that marks a ward as
  leavers must not disable it mid-shift. It applies the same limit to
  access-changing records: `active`/`joiner` rows whose department or job
  title differ from the last roster pushed (`-StatePath`, default
  `.state/last-pushed-roster.json`, gitignored), because birthright clinical
  access now follows those attributes. `-Force` pushes a reviewed bulk
  change. Pester: `lab/scripts/powershell/tests/Invoke-InboundProvisioning.Tests.ps1`.
- **Hire date.** `startDate` travels as `hireDate` in the custom SCIM
  extension `urn:ietf:params:scim:schemas:extension:contoso:1.0:User`: every
  birthright rule requires `employeeHireDate` on or before today. A
  non-leaver row with no valid `startDate` is refused. The two mappings that
  carry it into Entra (provisioning `FormatDateTime` →
  `msDS-cloudExtensionAttribute1`, then Cloud Sync →
  `employeeHireDate`) are tenant-time steps (verify: on the first job
  setup).

- **License:** API-driven inbound provisioning requires **Entra ID P1 or P2**.
  (The Lifecycle Workflows used in `02-Joiner.ps1` additionally require **Entra
  ID Governance** — hence that script ships a Logic App *alternative* that runs
  on P1/P2 alone.)
- **Permission** (from the [bulkUpload permissions table](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationjob-post-bulkupload?view=graph-rest-1.0#permissions)),
  by how the caller signs in:
  - **App-only (the production pattern):** the Graph **application**
    permission **`SynchronizationData-User.Upload`**, with admin consent. It is
    what Microsoft's grant-access tutorial assigns, and it reaches every
    API-driven provisioning job in the tenant. Microsoft lists the narrower
    **`SynchronizationData-User.Upload.OwnedBy`** as least privileged: it only
    uploads to the provisioning app the caller owns, which is the HR-ISV pattern
    where the caller creates that app itself (with `Application.ReadWrite.OwnedBy`).
    *verify:* whether adding the caller as an owner of an admin-created
    provisioning app is enough for `.OwnedBy`. The docs only describe the case
    where the caller creates it.
  - **Delegated (this README's interactive `Connect-MgGraph`):** the scope
    `SynchronizationData-User.Upload`, **and** the signed-in user must hold the
    **User Administrator** role. Without the role the POST returns 403.
- **Batch limit:** **50 records per `bulkUpload` call.** The script chunks
  automatically; a single request with >50 operations returns HTTP 400.
- **Async:** the endpoint returns **202 Accepted** and queues the records. Landing
  is confirmed via the **Provisioning logs** blade or
  `GET /auditLogs/provisioning`, not from the POST response. That read needs
  `AuditLog.Read.All` + `Directory.Read.All` per its Graph API page; Microsoft's
  grant-access tutorial pairs the upload permission with `ProvisioningLog.Read.All`
  instead (*verify:* whether that one alone is accepted).
- **Idempotent:** records match on `externalId == employeeId` and upsert, so
  re-running the feed is safe; `leaver` rows carry `active:false`.

## One-time setup (before the script can run against a tenant)

1. In the Entra admin center, create an app from **"API-driven provisioning to
   Microsoft Entra ID"** (cloud-only) or **"…to on-premises Active Directory"**
   (hybrid, which is what the diagram shows: HR → AD OU → Cloud Sync → Entra).
2. Configure attribute mappings so SCIM `externalId`/`employeeNumber`,
   `department`, `title`, and `manager.value` map to your target attributes,
   and the extension's `hireDate` reaches `employeeHireDate` (on the AD path:
   `FormatDateTime` into `msDS-cloudExtensionAttribute1`, then a Cloud Sync
   mapping to `employeeHireDate`).
3. Grab the provisioning app's **service principal object id** and its
   **synchronization job id**:
   ```powershell
   $sp  = Get-MgServicePrincipal -Filter "displayName eq '<your provisioning app>'"
   $job = Get-MgServicePrincipalSynchronizationJob -ServicePrincipalId $sp.Id
   ```
4. App-only: grant the calling app registration `SynchronizationData-User.Upload`
   (or `.OwnedBy`, see *Permission* above) and admin-consent it. Interactive:
   consent the delegated `SynchronizationData-User.Upload` scope and sign in as a
   user who holds **User Administrator**.

## Run it

```powershell
# Safe dry run — builds and prints the exact SCIM payloads, sends nothing:
./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -WhatIf

# Segment-2 demo — push just the new hires (incl. Dana Okafor):
Connect-MgGraph -Scopes 'SynchronizationData-User.Upload'   # signed-in user must hold User Administrator
# Managers first, so manager references resolve:
./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your-domain> -StatusFilter active
./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your-domain> -StatusFilter joiner

# Full roster sync — what a scheduled HR extract job would push:
./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId>
```

Then continue the lifecycle with `../powershell/02-Joiner.ps1` (day-1 access).

## A note on "mover"

The `status` column is deliberately only `joiner | active | leaver`. A **mover**
is an `active` row whose `dept`/`jobTitle` differs from what Entra currently
holds — i.e. movers are detected by **diffing this feed against the directory**,
not by a status flag. Marcus Bello ships in `Nursing`; the mover demo edits
Marcus's row to `ICU`, re-runs this script with `-StatusFilter active` (HR -> AD
-> Cloud Sync carries the new department). The automatic assignment
policies then swap Marcus's birthright packages (the old one goes after the
72 h grace period), and `../powershell/03-Mover.ps1` verifies that, acting
itself only on requestable (T2) packages.

## A note on hybrid ownership

Because workers are provisioned **into AD** and synced up, AD (fed by HR) owns
their core attributes and `accountEnabled`. Entra rejects cloud edits to those
on synced users, so mover/leaver changes always start **here, in the feed** -
the PowerShell lifecycle scripts only handle the cloud-side follow-through
(access packages, sessions, app deprovisioning).
