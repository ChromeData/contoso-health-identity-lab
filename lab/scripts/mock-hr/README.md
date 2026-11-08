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
| `.gitignore` | Keeps `.state/` (the mass-change guard's last-pushed roster and quarantine files) out of git. |
| `approved-bulk-changes.json` | Reviewed bulk HR events (change ticket, kind, maximum count, expiry) that may pass the mass-change guard. Changed only through a reviewed pull request. Ships empty. |
| `Invoke-InboundProvisioning.ps1` | Reads the CSV, maps each row to a SCIM Enterprise User, chunks into ≤50-record batches, and POSTs SCIM `bulkUpload` payloads to the provisioning job. `-EmployeeId`, `-UseAzureCliToken`, `-ResultPath` and `-HidePayload` are the pipeline path (below). |
| `Get-HrFeedChange.ps1` | Compares the CSV with an earlier version: who was hired, left, moved, came back, was updated or deleted. The first step of `hr-feed.yml`. |
| `Write-HrFeedSummary.ps1` | Waits (bounded) for the provisioning log and writes the plain-English run summary. The last step of `hr-feed.yml`. |
| `README.md` | This file. |

## Key constraints (baked into the script)

- **Mass-change guard (risk register R10), scaled to the hospital.** Two
  counts per run: accounts it would DISABLE (`leaver` rows), and
  access-changing records (`active`/`joiner` rows whose department or job
  title differ from the last roster pushed, `-StatePath`, default
  `.state/last-pushed-roster.json`, gitignored), because birthright clinical
  access follows those attributes. The threshold is the largest of: a floor
  (`-MaxChanges`, default 10), a share of the population
  (`-MaxChangePercent`, default 1 percent of the joiner and active rows in
  the whole file: 200 people at 20,000), and, when a history file is kept
  (`-ChangeHistoryPath`, at least 7 distinct earlier dates in the last 30),
  the mean plus 3 standard deviations of the daily totals. The file keeps
  one entry per date: several sends on one day add to that day, so they
  never count as more days. WHY: a fixed 10 trips on every normal
  Monday at 20,000 staff (about 15 leavers a day), and people then learn to
  override it (hostile review, finding C2).
  - **Over the threshold, the rows of that kind are held back, not the whole
    run.** They go to a quarantine file (`-QuarantinePath`, ids, status and
    kind only), every other row is still sent, and the run ends with an error
    so the step fails visibly. All rows of that kind are held, not "the
    first N", because in a bad export nobody knows which N are real. This is
    what Entra's own "accidental deletions" threshold does for provisioning.
  - **A planned bulk event passes with its change ticket.**
    `-BulkChangeTicket CHG0040021` passes only if that ticket is listed in
    `approved-bulk-changes.json` (kind, maximum count, expiry date). That
    file changes only through a reviewed pull request, so the review is the
    approval. It ships empty. `-Force` stays as the console override for an
    administrator in an emergency.
  - Pester: `lab/scripts/powershell/tests/Invoke-InboundProvisioning.Tests.ps1`.
- **UPNs: issued once, never re-derived (review finding C3).** If the file has
  a `upn` column, a row's value is used as it is (the HR system issued it at
  hire; it is validated, and no two rows may share one). Otherwise the UPN is
  derived once from the whole file: `given.surname`, ASCII only (an accent is
  dropped, `O'Brien` becomes `obrien`, a space is removed), and a suffix digit
  for a collision (`john.smith2`). The worker with the lower employee id keeps
  the plain name, so the same file always gives the same answer, and a
  collision with a worker who is not in this push is still seen. Every UPN
  sent is recorded in the `-StatePath` file (employee id -> UPN) after a
  send with no failed batch. A recorded UPN stays with its worker and stays
  reserved, also after a name change or after the worker leaves the file, so
  `john.smith2` is never handed to someone else. The GitHub runner starts each run
  with no `-StatePath` file, so it used to forget every derived UPN between
  runs (Greptile, PR #229). Now `hr-feed.yml` passes
  `-IssuedFromGitHistory`: the sender replays every committed version of
  `hr_feed.csv`, oldest first, and a worker keeps the first UPN issued to
  them. A later UPN for the same worker (an HR `upn` value that replaced the
  derived name) stays reserved for that worker too. A feed with staged or
  unstaged edits is refused: commit the HR change first. The committed, protected history of the file (no force push, no
  deletion: the `hr-feed` ruleset) is the lasting register. A shallow
  checkout or an uncommitted file stops the run before anything is sent. A
  version the sender refused issued nothing and is skipped. A version that
  was committed but never sent can reserve a name nobody holds: that only
  adds a suffix digit, it never causes a clash. Accounts made outside the HR
  feed (admin and test accounts) are not in this register. A name that
  leaves no usable ASCII is refused. Two settings in the provisioning app
  keep a name change from renaming anyone (tenant-time steps, verify on the
  app): the matching attribute is `externalId` (the employee id), and the
  `userPrincipalName` and `sAMAccountName` mappings use **Apply this mapping:
  Only during object creation**. Downstream, AWS IAM Identity Center and
  ServiceNow match on `userName`/`user_name` today (E57). The production
  target is to match on the employee id or the Entra object id, so a UPN is
  never a join key. That part is DESIGNED. The HR form (`lab/hr-app`) should
  issue the UPN at hire and store it in the `upn` column, the same way it
  issues the employee number.
- **Rehire.** A rehire is the same AD account (matched on the employee id),
  switched back on. The `parentDistinguishedName` expression
  (`02-Configure-Domain.ps1`, applied Always) moves an active account out of
  `OU=Disabled` into the new department's OU. Birthright follows the new
  department and title. `lab/scripts/dc/Clear-LeaverAdGroups.ps1` removes
  every on-premises group from disabled leavers in `OU=Disabled`, so a rehire
  comes back with no old groups. It is BUILT, with offline tests, and not yet
  run on DC01.
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

Steps 1 and 3 are scripted: `New-InboundProvisioningApp.ps1` instantiates the
gallery template, creates the synchronization job, and prints the
`ServicePrincipalId` and `JobId` this script takes. It is idempotent and
`-WhatIf` only reads:

```powershell
Connect-MgGraph -TenantId <tenant> -Scopes Application.ReadWrite.All,Synchronization.ReadWrite.All
./New-InboundProvisioningApp.ps1 -Target AD -WhatIf   # dry run
./New-InboundProvisioningApp.ps1 -Target AD           # -> ServicePrincipalId, JobId
```

Step 2 stays manual for now: on the AD path it needs the registered Cloud Sync
agent (`lab/scripts/dc/04-Install-CloudSyncAgent.ps1`) assigned to the job, and
the forest-specific mappings.

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

## How HR makes a change: the Contoso HR form

HR does not edit `hr_feed.csv`. HR uses the **Contoso HR** form in
[`lab/hr-app/`](../../hr-app/README.md) (ADR 0027): hire, change job or
department, or make a worker a leaver. The form issues the employee number
and writes the roster on the `hr-feed` branch as one commit per save. The
workflow below then sends that change. The CSV stays the HR app's data store
and the format the sender reads; editing it by hand still works for tests
and retakes, but it is not the HR path any more.

## HR changes through GitHub Actions

[`.github/workflows/hr-feed.yml`](../../../.github/workflows/hr-feed.yml) is
the same push without a laptop sign-in: the `hr-feed` branch plays the HR
system. Edit `hr_feed.csv` on that branch, commit, push, and GitHub Actions
sends **only the rows that commit changed** to the provisioning job, signed in
as **HR-SYNC** over GitHub OIDC (no password or secret anywhere).

**Hire someone** (by hand, for tests; HR uses the form): on `hr-feed`, add a row and push. The form issues the next number in the range itself:

```
400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,
```

**They leave:** change `joiner` to `leaver` (and set `endDate`), push again.
A department or job-title edit is a mover. Deleting a row sends nothing:
HR marks leavers, it never deletes them.

**What the run shows.** The step names read as the story (read the change,
sign in, send, wait for Microsoft), and the job summary is one line per
person, with the technical details folded underneath:

> **HR change sent to Microsoft**
> - **Hired:** Sam Rivera, Cloud Engineer (Information Technology) — account created in Active Directory
>
> **Next:** Cloud Sync copies the change from Active Directory to Entra ID on its next run (about every 20 minutes); AWS follows by SCIM after that.

**What gets sent.** Each push sends the rows that changed since the last
push Microsoft accepted, so a failed run's rows go out with the next one,
never skipped. Before the first successful run the comparison starts at
`HR_FEED_BASE_SHA` if set, otherwise where `hr-feed` left `main`. If the
run history can't be read, the run stops rather than guess.

The run waits up to 3 minutes (`HR_FEED_WAIT_SECONDS`) for the provisioning
log. Microsoft's log can lag several minutes, so "not logged yet" is a note,
not a failure; a failure Microsoft logged turns the run red. The summary
prints first and last name, job title and department only (never the
employee id, UPN, manager, dates or a token), and the log prints no SCIM
payload. The mass-change guard counts this push's rows: more people switched off, or
more department/title changes against the previous version of the file,
than the larger of 10 and 1 percent of the staff in the file. Those rows are
held back (quarantined) and the run turns red. The other rows still go.

**Preview without sending:** *Actions → hr-feed → Run workflow*, keep
*dry run* ticked (any branch, no sign-in). With dry run off it sends the
employee ids you list, on `hr-feed` only.

**Retakes:** `lab/scripts/demo/reset-demo-hire.sh 400104` (dry run;
`--apply` does it) removes the row on `hr-feed` and deletes the AD account on
DC01; Cloud Sync and SCIM clean up downstream. Record again once the Entra
user is gone (about 20 minutes).

### One-time setup (an admin, after this is merged)

1. **Create and protect the branch.** `git push origin origin/main:refs/heads/hr-feed`.
   Then *Settings → Rules → Rulesets → New branch ruleset* on `hr-feed`:
   restrict updates (bypass: repository admin), block force pushes and
   deletion. Whoever can push to `hr-feed` can create and disable workforce
   accounts through HR-SYNC.
2. **Bootstrap apply** (local, as the tenant admin; this also adds the PLAN
   `ref:refs/heads/main` credential the nightly config-drift run needs). In
   `lab/terraform/envs/bootstrap/terraform.tfvars`:
   ```hcl
   enable_hr_sync                = true
   hr_provisioning_app_client_id = "<last segment of HR_PROV_JOB_ID: API2AD.<tenant>.<client id>>"
   ```
   ```bash
   az login --tenant <tenant id>
   cd lab/terraform/envs/bootstrap
   terraform init -backend-config="storage_account_name=<state account>"
   terraform plan -out hr-sync.tfplan    # expect: HR-SYNC app + SP + federated credential,
                                         # 2 app role assignments, 1 application owner,
                                         # PLAN github-main-drift (if not applied before)
   terraform apply hr-sync.tfplan
   ```
3. **Owner of the provisioning service principal** (the `.OwnedBy` upload
   permission only reaches apps HR-SYNC owns; Terraform can own the app
   registration but not the service principal): read, then run, the command
   the apply printed:
   ```bash
   terraform output -raw hr_sync_service_principal_owner_command
   eval "$(terraform output -raw hr_sync_service_principal_owner_command)"
   ```
4. **Consent check:** *Enterprise applications → HR-SYNC → Permissions* shows
   `SynchronizationData-User.Upload.OwnedBy` and `AuditLog.Read.All` as
   *Granted* (Terraform's app role assignments are the admin consent).
5. **Repository variables** (identifiers, not secrets; `AZURE_TENANT_ID`
   exists already):
   ```bash
   gh variable set HR_SYNC_CLIENT_ID --body "$(terraform output -raw github_oidc_hr_sync_client_id)"
   gh variable set HR_PROV_SP_ID  --body "<HR_PROV_SP_ID>"     # lab/setup/handback.env
   gh variable set HR_PROV_JOB_ID --body "<HR_PROV_JOB_ID>"    # lab/setup/handback.env
   gh variable set HR_UPN_DOMAIN  --body "<your verified domain>"
   ```
6. **Smoke test:** a dry run from *Actions → hr-feed → Run workflow*, then the
   real push.

*verify (first real run):* whether owning the app registration plus the
service principal is enough for `SynchronizationData-User.Upload.OwnedBy`
(Microsoft documents only the case where the caller created the app). A 403
in the summary means it is not: set `hr_sync_upload_scope = "tenant"`
(`SynchronizationData-User.Upload`) and apply again. The provisioning-log
read uses `AuditLog.Read.All` alone; its Graph page also lists
`Directory.Read.All`, so a "log not readable" line means set
`hr_sync_log_read_graph_roles = ["AuditLog.Read.All", "Directory.Read.All"]`
and apply again (the narrower `ProvisioningLog.Read.All` is the candidate to
try instead, once proven).

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

## Three gaps from the first HR-form run (2026-11-07, E121, E122, E121b)

1. **The manager had no mail, so the TAP email task failed.** For synced
   users Entra's `mail` comes from AD, and the HR job wrote AD mail only on
   create, with the AD domain. Fix: `lab/scripts/dc/configure-sync.py hrapp
   --mail-domain <verified domain>`, then re-send the manager's row (any HR
   save of that worker). `New-LifecycleWorkflows.ps1 -RunJoinerFor` now warns
   when the joiner's manager has no mail. The address has no mailbox in the
   lab, so nobody receives that email. Never say on camera that the manager
   gets it.
2. **A leaver kept the access package until IT acted.** HR's leaver disables
   the account everywhere, but the package stayed until `04-Leaver.ps1` ran.
   The automatic assignment policy removes it by itself only after its 3-day
   grace period (ADR 0012, on purpose: it protects clinicians from a wrong HR
   record). Fix: a second leaver workflow that runs by itself, triggered when
   the user drops out of the dynamic group All-Workforce (enabled, synced
   members). It has the same six tasks as the on-demand leaver. Turn it on:
   `enable_lcw_leaver_trigger = true` (envs/dev, a reviewed PR), then
   `post-apply/New-LifecycleWorkflows.ps1 -IncludeScheduledLeaver -EnableJoinerSchedule`.
   It runs at the next scheduled evaluation, every 3 hours by default (the
   tenant's setting read 2026-11-07: 3). The on-demand leaver stays for
   "terminate now".
3. **Which mechanism really gives the nurse package on day one.** Measured:
   the user joined the policy's dynamic group at +4:36, but the automatic
   assignment policy had created no assignment by +25 min. The joiner
   workflow's "Request user access package assignment" task did it
   (audit: "Administrator directly assigns user to access package", initiated
   by Lifecycle Workflows, 01:11:01Z), and it was delivered at +30:11. So in
   this lab the **joiner workflow is the day-one mechanism**. Its timing
   depends on the 3-hour schedule: E121's run came 25 minutes after the hire
   only because a scheduled evaluation fell then; the worst case is about 3
   hours. The automatic assignment policy is the **steady-state** mechanism:
   it keeps the package in line with HR attributes (movers, and the 3-day
   removal), with no measured day-one time. Microsoft documents only that its
   evaluation "can take several minutes". Do not say on camera that the
   package arrives by itself in minutes. All of this is for Nursing only:
   the standard install creates one joiner (department Nursing, package
   Nurse - Clinical Apps) and no ICU joiner. An ICU hire relies on the
   automatic assignment policy alone, unless a second joiner is installed.

