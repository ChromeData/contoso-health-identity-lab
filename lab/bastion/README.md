# Recorded admin sessions: Azure Bastion Premium, only while capturing

**Status: RAN · tenant** (2026-11-07, capture log E133). An admin could not
open DC01. She activated a PIM-eligible role for one hour, then connected to
DC01 through Azure Bastion. Bastion recorded the session. A second admin, the
reviewer, played the recording back in the Azure portal. Bastion was deleted
straight after. Record:
[`lab/evidence/bastion-session-recording/20261107T021051Z/`](../evidence/bastion-session-recording/20261107T021051Z/).

This replaces the Apache Guacamole recorded sessions (ADR 0036).

## Since ADR 0030 (2026-11-08): who does what

The run below happened under the old model, when the operator held subscription
Owner and made the admin's PIM eligibility itself. Since ADR 0030 the operator
is read-only between owner-opened write sessions and can write no PIM request
or role assignment outside the sandbox. So the capture now works like this.
It is **BUILT, not yet run**; it needs `envs/operator` (PR #249) applied and a
write session open.

| Who | What | How |
|---|---|---|
| Owner, **once** | Make the reviewer adm-mei.tanaka **eligible** on `rg-lab-sandbox` for Reader, Storage Blob Data Reader and Storage Account Key Operator Service Role | `capture.sh owner-steps` prints the exact commands (or the PIM blade). The operator cannot do this (ADR 0030). |
| Owner, per capture | Open a write session (`envs/operator` `operator_write_session`) | Gives the operator the session role on the subscription and Contributor plus constrained RBAC Administrator on `rg-lab-sandbox` |
| Operator | `capture.sh up` / `playback-on` / `down` | The subnet goes in the lab VNet (session role). The Bastion, its public IP, the identity and the storage account go in `rg-lab-sandbox`. The identity's Storage Blob Data Contributor is a data role the sandbox grant may assign. Preflight stops if the session is not open. |
| Admin | **adm-presenter** activates its **existing** PIM-Demo-Readers eligibility (Reader on the subscription), 1 hour, with a reason, then connects to DC01 | `prove.mjs` (identity.mjs `activatePim`, RAN · tenant for this group). No new eligibility is made. |
| Reviewer | adm-mei.tanaka activates her three eligible roles on the sandbox, 1 hour each, with a reason, then plays the recording back | `prove.mjs`, the Azure-resources activation path that ran live on 2026-11-07 |

**verify: next run.** Reader now arrives through a group activation, not a
direct assignment. The portal may need a fresh token before DC01's Bastion
page opens. `prove.mjs` reloads for up to about 13 minutes.

## Words used here

- **Azure Bastion:** a Microsoft service that opens RDP or SSH to a VM
  inside the browser. The VM needs no public port.
- **Session recording:** Bastion saves the whole graphical session to a
  storage account. It needs the **Premium** SKU (pricing tier).
- **PIM (Privileged Identity Management):** a person is *eligible* for a
  role, and *activates* it for a short time, with a reason, when needed.
- **Reader:** the Azure role that can see a resource. Bastion needs only
  Reader on the VM, its network card and the Bastion host to connect. The
  real lock on the server is still its own sign-in.

## What ran (2026-11-07, real times)

| Step | Who | Result | Time |
|---|---|---|---|
| `capture.sh up` | lab operator | subnet + public IP 36 s; storage + identity 41 s; **Bastion Premium create 674 s (11 min 14 s)**; access grants 22 s | 12 min 55 s |
| 1. Before | adm-ava.lin (passkey) | DC01 in the portal: **"You don't have access", error 403** | 2 s |
| 2. Activate | adm-ava.lin | PIM, My roles > Azure resources > Reader on rg-identity-lab > Activate, **1 hour**, with a reason. Azure read-back: active 02:11:31Z to 03:11:28Z, assignment type *Activated* | Azure started it 4 s after the click; the portal showed it under Active assignments after 91 s |
| 3. Connect | adm-ava.lin | DC01's Bastion page opened (12 s after "active"); connected with DC01's admin account; a Windows Server desktop (Server Manager: AD DS, AD CS, AD FS, DNS) | desktop on screen within 46 s of Connect (the script waits a fixed 45 s, so logon may be faster); session 73 s in all |
| 4. Recording | Bastion | one recording, `vm-dc01-contosoadmin-06babc7d...`, 1.3 MB, listed as 1 min 26 s | in storage when the session ended |
| 5. Play back | adm-mei.tanaka (reviewer) | Bastion > Settings > Session recordings > View recording: the player opened in a new tab and played DC01's desktop, 1:23 long | listed within 24 s of opening the page |
| `capture.sh down` | lab operator | Bastion deleted (started 02:49:22Z, gone by 02:57:26Z); public IP, subnet, identity, PIM eligibility and reviewer access removed; read back: all absent | 9 min 6 s |

Bastion existed for about **58 minutes** (create sent 01:59:00Z, deleted by
02:57:26Z). At $0.45 an hour that is about **$0.45** (eastus2 retail price,
2026-11-07).

### What did NOT work, and what was changed

- **`whoami & hostname` did not run.** The script pressed the Windows key + R
  in the session. From a headless browser the Windows key does not reach the
  session: Server Manager's Help menu opened instead. The recording shows
  the desktop, not a command prompt. `prove.mjs` now clicks the taskbar
  search box instead (not yet run).
- **The Session recordings blade has no deep link.** `/sessionRecordings`
  falls back to Overview. `prove.mjs` opens Settings > Session recordings.
- **The reviewer needs Reader on the storage account too.** Without it the
  blade says "Storage account not found" and lists 0 recordings.
- **Playback needs the storage account key (not in Learn).** Learn says a
  viewer needs Storage Blob Data Reader. The portal's player instead calls
  `storageAccounts/listKeys` (403 without it: "Unable to get blob SAS URL")
  and builds an account-key SAS, which also needs shared-key access on. For
  the run, shared-key access was turned on and the reviewer got *Storage
  Account Key Operator Service Role* for 1 hour. Both were turned off and
  removed straight after (read back: `allowSharedKeyAccess false`).
  `capture.sh playback-on` now does this, and `down` undoes it. The cost:
  for that hour the reviewer could also delete recordings.

## Run it

```bash
lab/scripts/operator/op bash lab/bastion/capture.sh owner-steps   # once: prints the owner's eligibility step
lab/scripts/operator/op bash lab/bastion/capture.sh up            # ~13 min; billing starts (needs a write session)
node lab/bastion/prove.mjs --out ~/contoso-demo/captures/bastion/$(date +%F)
lab/scripts/operator/op bash lab/bastion/capture.sh playback-on   # before step 4 of prove.mjs
lab/scripts/operator/op bash lab/bastion/capture.sh down          # ~9 min; ALWAYS run it
lab/scripts/operator/op bash lab/bastion/capture.sh status
```

`prove.mjs --step before|activate|connect|playback` runs one step. Every
browser context records a video for the script writers. Screenshots blur
inputs. The DC01 password goes from the Keychain straight into the browser's
password box. It is never printed, logged or put on a command line.

## Design choices

- **A script, not Terraform.** Premium costs $0.45 an hour (about $330 a
  month if left up). The lab runs it only for a capture. A Terraform flag
  would need two reviewed applies per capture. The script owns only objects
  tagged `purpose=bastion-capture`.
- **No SAS token.** Bastion writes recordings with a user-assigned managed
  identity that holds Storage Blob Data Contributor on the one container
  (API 2026-03-01 `sessionRecordingConfiguration`).
- **Native client off.** Learn: "Session recording isn't available via
  native client". With tunnelling off, every way in is recorded.
- **Password, not Entra ID sign-in, to the VM.** Learn: Entra ID RDP in the
  portal "can't be used concurrently with graphical session recording". This
  is an open trade-off (ADR 0036).
- **The reviewer is not the admin.** adm-ava.lin cannot read recordings.
  adm-mei.tanaka can, for 4 hours, and cannot connect to DC01.
- **PIM policy used as it is.** Reader on rg-identity-lab uses Azure's
  default policy: up to 8 hours, a reason, no approval, no MFA on
  activation (read 2026-11-07). The admin signed in with a passkey. A
  Tier-0 policy (1 hour cap, approval by PIM-Approvers-Tier0) is DESIGNED,
  not built.
- **DC01 is started through `preflight.sh` only if it is off, and never
  deallocated by this script** (program 2026-11-08: the leaver helper owns
  DC01's start and stop). `up` and `down` log "DC01 needed by" and "done" in
  the shared progress log.

## Sources (checked 2026-11-07)

- Record Bastion sessions: https://learn.microsoft.com/en-us/azure/bastion/session-recording
- Bastion REST API 2026-03-01 (`sessionRecordingConfiguration`): azure-rest-api-specs, `Microsoft.Network/stable/2026-03-01/virtualNetwork.json`
- Prices: https://prices.azure.com/api/retail/prices (Azure Bastion, eastus2)
