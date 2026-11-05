# Demo re-take tool — `Reset-DemoState.ps1`

> **Stand-in note:** the "HR system" this tool edits is the lab's mock HR feed
> (`../mock-hr/hr_feed.csv` + `Invoke-InboundProvisioning.ps1`), which replaces
> **Workday / SAP SuccessFactors**. Everything downstream of it (the Entra
> API-driven inbound provisioning endpoint, AD, Cloud Sync, access packages)
> is the real product.

The video is recorded in segments, and every take changes real tenant state:
Dana gets disabled, packages get removed, Marcus moves to ICU. This script puts
the lab back to the moment **before** a segment so you can film it again, in
one command, with `-WhatIf`.

It is a recording aid. It isn't part of the identity design, and no other
script depends on it.

## What "before the segment" means

| Segment | Dana Okafor (100492) | Marcus Bello (100310) |
|---|---|---|
| `Joiner` | HR `status=joiner`, Nursing, **no** packages | `active`, Nursing, *Nurse - Clinical Apps* |
| `Mover` | `active`, Nursing, *Nurse - Clinical Apps* | `active`, Nursing, *Nurse - Clinical Apps* (no ICU), so 03-Mover has old access to remove |
| `Leaver` | `active`, Nursing, `endDate` cleared, *Nurse - Clinical Apps*; account re-enabled **through HR → AD** | `active`, **ICU**, *ICU - Critical Care Apps* (post-mover) |

The packages in this table are the state the HR attributes lead to, not
something the script writes. Only the three lab packages (Nurse, ICU,
Pharmacy) are considered, by their assignment model in
`lab/iga/access-catalog.json` (ADR 0012):

- **Nurse and ICU (T3 birthright, automatic):** never added or removed here.
  The script resets the HR attributes (department, job title, enabled, hire
  date) and the automatic assignment policy acts: it adds a package while
  its rule matches and removes it after the 72-hour grace period once the
  rule stops matching. So a Joiner re-take inside that grace period can
  still show Dana's *Nurse - Clinical Apps*. The readiness table lists these
  as HR-driven, not as a reset target.
- **Pharmacy (T2, requestable):** still reconciled directly. An assignment
  that shouldn't be there is removed (`adminRemove`), and a missing one is
  added (`adminAdd`) through the request policy.

Other packages are never touched.

## What it does, in order

1. **Edits `hr_feed.csv`.** It changes `status`, `dept`, `jobTitle` and
   `endDate` on Dana's and Marcus's rows only. Every other line (the comments
   and all other workers) stays byte-for-byte the same, and `startDate` is
   kept. The diff is printed.
2. **Re-pushes those two rows** through `../mock-hr/Invoke-InboundProvisioning.ps1`
   (HR → AD), using a temporary two-row copy of the feed. Other workers are not
   re-sent, and the temp file is deleted afterwards, including on `-WhatIf`.
3. **Removes** requestable (T2) packages that shouldn't be there. This is
   safe to do immediately. Birthright packages are left to their automatic
   policy.
4. **Waits** if you pass `-WaitForSyncSeconds`, until Entra shows the HR-owned
   values (department, enabled), then **adds** any missing requestable
   package.
5. **Re-assigns a license** if you pass `-LicenseSkuPartNumber`. The Lifecycle
   Workflow leaver removes licenses.
6. **Prints a readiness table**: expected vs actual department, `accountEnabled`
   and packages for both people. `READY` means you can roll the camera.

### The hybrid rule (same as 03-Mover / 04-Leaver)

Department, title and enabled/disabled belong to **HR → AD**, and Cloud Sync
carries them up. Entra rejects cloud writes to them on synced users. The script
**never** writes `accountEnabled` or `department` in Entra: "re-enable Dana"
means setting Dana's HR row back to `active`. Packages and licenses are
cloud-side, so those are set directly with Graph.

## Usage

```powershell
# Dry run. No tenant needed: prints the CSV diff, the exact SCIM payload, and
# the package changes it would make.
./Reset-DemoState.ps1 -Segment Leaver -WhatIf

# Real run. ConfirmImpact is High, so every step prompts; -Confirm:$false
# skips the prompts once you trust the -WhatIf output.
Connect-MgGraph -Scopes 'EntitlementManagement.ReadWrite.All','User.Read.All','SynchronizationData-User.Upload'
./Reset-DemoState.ps1 -Segment Mover -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain>

# Leaver re-take: wait for Cloud Sync and give Dana's license back.
./Reset-DemoState.ps1 -Segment Leaver -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain> `
    -LicenseSkuPartNumber SPE_E5 -WaitForSyncSeconds 1500 -Confirm:$false

# CSV only (for example while the tenant is down):
./Reset-DemoState.ps1 -Segment Joiner -SkipProvisioning -SkipCloud
```

`<spId>` and `<jobId>` are the same two ids `Invoke-InboundProvisioning.ps1`
takes (see `../mock-hr/README.md`). Re-running is safe: a converged lab gives
`already-correct` / `already-assigned` and `READY`. The only write it still
makes is the re-push of the two HR rows, which is an idempotent upsert keyed on
`employeeId` (add `-SkipProvisioning` to skip it). A package removal that is
still processing from the previous run is reported as `already-pending`, not
as a failure.

The script connects to Graph **once, before it changes anything**, with every
scope the run needs. If you connected yourself with fewer scopes, it warns;
run `Disconnect-MgGraph` and re-run. (Left alone, the provisioning script
would connect with only `SynchronizationData-User.Upload`, and the package
steps would then fail with 403.)

To put the committed feed back afterwards:

```bash
git diff -- lab/scripts/mock-hr/hr_feed.csv      # see what the take changed
git checkout -- lab/scripts/mock-hr/hr_feed.csv  # restore the shipped roster
```

## Timing caveats (why "READY" can take a while)

| Hop | Typical latency | Shortcut on camera day |
|---|---|---|
| HR push (`bulkUpload`, 202 Accepted) | Processed near real time. The **provisioning logs** lag 5–10 min behind (Microsoft: *Troubleshoot inbound provisioning API issues*). | None needed. Don't film the log until it shows up. |
| AD → Entra (**Cloud Sync**) | Users are provisioned roughly **every 10–20 min** (Microsoft: *Cloud Sync FAQ*; the 2–5 min figure is password hash sync, not users). | **Cloud sync → Provision on demand** with the user's DN. After a leaver take, Dana's DN is in `OU=Disabled`. |
| Dynamic groups (All-Nurses / All-ICU) | Minutes after department / `accountEnabled` land. | Wait. Group processing can't be forced. |
| Access-package `adminAdd` / `adminRemove` | Asynchronous: *delivering* → *delivered* within minutes, and the app-group membership follows. | Re-run the script; the readiness table shows the state. |
| ServiceNow / AWS (SCIM) | Next incremental cycle, about every 40 min. | **Provision on demand** in each enterprise app (or 04-Leaver's `-ProvisionOnDemandApps`). |
| Lifecycle Workflows | On-demand runs start within minutes. Scheduled runs follow the tenant schedule (default every 3 h). | `New-LifecycleWorkflows.ps1 -RunJoinerFor / -RunLeaverFor`. |

Without Provision on demand, `-WaitForSyncSeconds 1500` (25 min) is a realistic
wait for one Cloud Sync cycle plus delivery.

## Re-take caveats per segment

**Joiner**
- Dana still exists in AD, so the provisioning log shows **Update**, not
  **Create**. The script never deletes users. For a genuine *Create* shot,
  either film a worker who has never been provisioned, or remove Dana from AD
  by hand. If you do that, know that Cloud Sync then soft-deletes Dana in Entra
  (30 days in *Deleted users*), and the next push creates a **new** Entra object
  with a new object id. Old assignments and history do not carry over.
- The Lifecycle Workflow **TAP task** works only for a user with no
  authentication methods, no sign-ins and no role assignments. After Dana has
  signed in once, that task fails on every re-take. The workflow continues
  (`continueOnError`), but for a clean TAP shot use a fresh joiner such as
  Sofia Reyes (100488).

**Mover**
- The reset gives Marcus the Nurse package back on purpose, so 03-Mover has old
  access to remove on camera. Without it, the "old access removed" step has
  nothing to show.

**Leaver**
- Dana is re-enabled only through HR → AD → Cloud Sync. Until the next Cloud
  Sync cycle (or Provision on demand) Dana is still disabled in Entra, so the
  readiness table says `NOT READY` and a package `adminAdd` may be refused. Use
  `-WaitForSyncSeconds`, or re-run after the sync.
- **OU:** the leaver moved Dana to `OU=Disabled`. Whether re-activation moves
  the account back depends on your provisioning job's OU expression (some
  apply on create only). Check `Get-ADUser dana.okafor` on the DC and use
  `Move-ADObject` if needed. *verify: depends on the `parentDistinguishedName`
  mapping you configured (`lab/scripts/dc/README.md`, step 5).*
- **`OU=Disabled` must be in Cloud Sync scope** (`lab/scripts/dc/README.md`,
  step 6). If it isn't,
  the leaver soft-deletes Dana in Entra, and a re-take creates a new object.
- If the Lifecycle Workflow leaver ran, it also removed licenses. Pass
  `-LicenseSkuPartNumber`.

## What it does not reset

- AD object deletion or recreation (see *Joiner* above).
- History: provisioning logs, sign-in logs, audit logs, Lifecycle Workflow
  history, access-package request history. These are append-only, which is the
  point of an audit trail.
- Revoked sessions (harmless: Dana gets new tokens at the next sign-in).
- Direct (non-package) cloud group memberships and app-role assignments that
  `04-Leaver.ps1` or the Lifecycle Workflow leaver removed. Only the three lab
  packages (and, with `-LicenseSkuPartNumber`, one license) are put back. In
  the default build every app group comes from a package, so nothing else is
  missing; if you added Dana to a group by hand, add that membership again.
- SCIM state in ServiceNow / AWS. It follows the packages on the next cycle.
- Okta JIT users, Vault / Guacamole state, PIM activations.

## Permissions

| Scope (delegated) | Why |
|---|---|
| `EntitlementManagement.ReadWrite.All` | read assignments; `adminAdd` / `adminRemove` |
| `User.Read.All` | read Dana and Marcus |
| `User.ReadWrite.All`, `Organization.Read.All` | only with `-LicenseSkuPartNumber` |
| `SynchronizationData-User.Upload` | only when provisioning runs (the `bulkUpload` permission, `lab/scripts/mock-hr/README.md`) |

License: Entra ID Governance for the access-package part (same as 02/03/04).

## Admin and break-glass passkeys: `signin/passkey.mjs`

```bash
node lab/scripts/demo/signin/passkey.mjs status   adm-ava.lin@contosohealthlab.onmicrosoft.com
node lab/scripts/demo/signin/passkey.mjs register adm-ava.lin@contosohealthlab.onmicrosoft.com
node lab/scripts/demo/signin/passkey.mjs prove    adm-ava.lin@contosohealthlab.onmicrosoft.com
node lab/scripts/demo/signin/passkey.mjs prove    bg-admin-01@ContosoHealthLab.onmicrosoft.com --break-glass
```

Gives a lab admin or break-glass account a phishing-resistant sign-in, so
CA002 and CA021 can be switched on without locking anyone out, and so the
break-glass drill has a key to sign in with. Runs as the lab operator.

- **register**, lab admins (`adm-*`): a one-time Temporary Access Pass,
  then headless Chromium signs in at Security info and adds a passkey with
  Chromium's virtual WebAuthn authenticator, as the user would with a
  security key. **Break-glass** accounts get no TAP (the TAP policy excludes
  them, ADR 0016): the operator provisions the passkey through Graph
  (`fido2Methods/creationOptions` + `POST fido2Methods`, beta), the key
  still made by the virtual authenticator.
- The credential (id, private key, user handle, counter) goes to the login
  Keychain, written over stdin, never printed: first as
  `contoso-lab-passkey-<local-part>-pending`, and as
  `contoso-lab-passkey-<local-part>` once Graph lists the new method.
- `--replace` registers the new key next to the old one, signs in with it,
  and only then swaps the Keychain item and deletes the old method: an
  account is never left without a working key (break-glass has one).
- **prove**: a fresh browser loads the key from the Keychain and signs in
  to My Account with the passkey only. It fails unless the key's counter
  rose, the browser went through Entra's sign-in, and My Account shows the
  account. Screenshot to `$PASSKEY_SHOTS_DIR`.
  Every break-glass `prove` is a real break-glass sign-in: the Sentinel rule
  raises a High incident, on purpose (run it as part of the drill,
  `lab/docs/runbooks/break-glass-drill.md`).
- `PASSKEY_DEBUG=1` adds a screenshot (inputs blurred) and the on-screen
  labels for every step, for when Microsoft changes the wizard.

**Lab deviation.** Production: two attested FIDO2 hardware keys per admin
and break-glass account, in separate safes. Lab: one software passkey per
account in this Mac's Keychain, `notAttested`. Entra accepts it because the
all-users passkey target carries the unattested Default profile, and any one
profile in scope is enough (Learn, passkey profiles). The Keychain item is
the key: for `bg-admin-NN` it is a Global Administrator credential.

## Before every recording or rehearsal: `preflight.sh`

```bash
lab/scripts/demo/preflight.sh            # fixes what breaks overnight, checks the rest
lab/scripts/demo/preflight.sh --check    # look only
lab/scripts/demo/preflight.sh --intune   # also start the Intune pilot device
```

Runs as the lab operator. DC01 shuts down every evening, which takes the
Cloud Sync agent offline and makes Microsoft pause ("quarantine") the
Active Directory to Entra sync. Preflight starts DC01, waits for its agent,
clears the pause, then checks the HR, Cloud Sync and AWS sync jobs, that no
demo hire is left over, the evidence runner, Splunk, the trial end dates and
the time left before the evening shutdown. It ends with READY or NOT READY.

## One demo hire through GitHub Actions: `reset-demo-hire.sh`

The "add a hire row on the `hr-feed` branch, push, watch Actions" demo
(`lab/scripts/mock-hr/README.md`, *HR changes through GitHub Actions*) uses a
new worker, not Dana. To film it again:

```bash
lab/scripts/demo/reset-demo-hire.sh 400104          # dry run: prints each step
lab/scripts/demo/reset-demo-hire.sh 400104 --apply  # removes the row on hr-feed (push), deletes the AD account on DC01
```

The push that removes the row sends nothing (the run says so). Cloud Sync
then deletes the Entra user on its next cycle and SCIM removes the AWS user;
record again once the Entra user is gone (about 20 minutes), or the new AD
account collides with the old Entra user's UPN. `--purge-entra` (after that
cycle) empties it from *Deleted users* too. The script refuses an employeeId
from main's shipped roster (use `Reset-DemoState.ps1` for Dana and Marcus),
and refuses every employeeId when it cannot read that roster (offline, or a
checkout without `origin/main`) rather than treat it as empty.
Needs `az login` as an admin and DC01 running for the AD step.

## A real staff sign-in, no phone: `signin/`

`signin/enroll.mjs <upn>` gives a lab user an authenticator-app sign-in
(one-time Temporary Access Pass, then the code computed from a Keychain
seed); `signin/signin.mjs <upn> <start-url>` signs that user in through Entra,
headless, on any app that sends people to Entra (AWS access portal, Okta, My
Apps), and is also a module (`signIn(upn, url, {headless})`) for scripts that
need a staff session. Details, secrets and undo: [`signin/README.md`](signin/README.md).

## Before recording: close the build noise, `close-build-noise.sh`

Building and testing the lab raised Sentinel incidents (and ServiceNow
tickets) that are not part of the story. Right before recording, the lead
closes them, as the lab operator:

```bash
lab/scripts/demo/close-build-noise.sh --numbers 32-51 --since 2026-11-05T09:00Z --until 2026-11-05T13:30Z           # dry run
lab/scripts/demo/close-build-noise.sh --numbers 32-51 --since 2026-11-05T09:00Z --until 2026-11-05T13:30Z --apply   # acts
```

- An open incident is **closed** when every Account entity on it is a lab
  test or admin account (`test-user-*`, `itdr-drill-*`, `adm-*`,
  `bg-admin-NN`, `svc-*`), or when it was created inside `--since`/`--until`.
- An incident about the **owner's account**, a real (non-lab) account, or an
  account whose name cannot be read is **NEEDS-LEAD**: listed, never closed,
  until its number is passed in `--lead-ok 28,27`.
- Each closed incident gets a one-line reason (comment, BenignPositive). Its
  open ServiceNow tickets (matched by `correlation_id`) are resolved as
  `svc.sentinel` (itil), and so are open tickets whose Sentinel incident was
  already closed.
- Default is a dry run. `--numbers` narrows the set first.

Offline test: `tests/close-build-noise.test.sh`.

## Rewind and replay the whole lab: `rewind-lab.sh`

`Reset-DemoState.ps1` re-takes one people segment. `rewind-lab.sh` moves the
whole build to any **stage**, back or forward, through a normal PR, so someone
else can build it again step by step. It finds the stage main is at by
comparing flags (`rewind-lab.sh --where`). The performer's run sheets and the
`turn.sh` short commands that wrap it are in
[`lab/docs/your-turn/`](../../docs/your-turn/README.md):

```bash
lab/scripts/demo/rewind-lab.sh day1            # dry run: flag changes, CI test, cleanup list
lab/scripts/demo/rewind-lab.sh day1 --open-pr  # opens the rewind PR (never merges it)
```

Stages: `p2`, `day1`, `day2`, `day3`, `sentinel`, `dc`. Each restores
`lab.tfvars` and the stage-pinning mocked test from that stage's merge commit.
Merging the rewind PR runs the usual reviewer-gated apply, which **destroys**
what later stages created. The script then lists what Terraform does not own
(Cloud Sync, the HR provisioning app, HR users, Lifecycle Workflows, CA021 and
auth context `c1`, `adm-` accounts). Replay = re-open the stage PRs in order;
their descriptions on GitHub are the script.

- **Floor is `p2`.** The WORM evidence store is immutable by design. Every run's
  evidence stays, so a replay adds its own capture-log rows next to the first.
- **Tenant-wide settings stay as set** (authentication methods, consent, app
  management, Global Administrator PIM policy). Replaying the post-apply steps
  re-applies them idempotently. For a true blank slate, use a fresh tenant.
- The dry run proves the rewind PR passes CI for every stage. A real rewind
  apply has runtime ordering risks the mocked plan cannot show (for example an
  access package that still has assignments); re-run the apply after cleanup.

### What a replay costs

| Item | Within the 30-day trial window | After the trials end |
|---|---|---|
| Microsoft 365 E5 + Entra ID Governance | Free: rewind and replay in the same tenant | Trials are once per tenant. Sign up a **fresh tenant** with `lab/setup/SIGNUP-KIT.md` (new trials; Microsoft can decline a repeat trial, verify at sign-up) |
| Custom domain | Keep it | Keep it: remove it from the old tenant, then add and verify it in the new one. Renews yearly |
| Azure subscription | Free credit | Upgrade to pay-as-you-go (pay for use only: the DC VM shuts down nightly), or move the subscription to the new tenant (*Change directory*) |
| Okta Integrator, AWS Free plan, ServiceNow PDI, GitHub repo | Reused | Reused: `lab/setup/after-signup.sh` re-points the ids and variables |
| Sentinel | Trial runs 31 days from onboarding | Pay per GB, or `enable_la_alerts` (Log Analytics alerts) instead |

A fresh tenant is capped at 600 directory objects for its first 48 hours
(`lab/setup/SIGNUP-KIT.md`): sign up two days before the DC stage.
