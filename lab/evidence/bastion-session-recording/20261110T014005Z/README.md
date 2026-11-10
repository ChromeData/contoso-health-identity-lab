# Bastion session recording, re-run under ADR 0030, 2026-11-10 (capture log E186)

First run of the post-ADR 0030 model (`lab/bastion/README.md`, "Since ADR
0030"): the operator built Bastion in `rg-lab-sandbox` inside an owner-opened
write session (2026-11-10T00:56Z to 05:01Z); the admin was **adm-presenter**
through its existing PIM-Demo-Readers eligibility; the reviewer
**adm-mei.tanaka** activated her owner-made eligibilities on the sandbox.

| File | What it shows |
|---|---|
| `capture-up.log` | `capture.sh up` as the lab operator: Bastion Premium create 637 s (sent 01:11:30Z, Succeeded 01:22:06Z), read back sku Premium, recording true, tunnelling false; reviewer has 3 eligible roles on the sandbox |
| `01-before-pim-no-access.png` | 01:23:49Z adm-presenter opens DC01's Bastion page before PIM: "You don't have access" |
| `04-pim-active.png` | 01:24:18Z PIM-Demo-Readers active for 1 hour (until 02:24:18Z), with a reason |
| `prove-run-1.log`, `proof-1-before-activate.json` | run 1: before + activate passed; the connect form did NOT appear within prove.mjs's ~13 min of reloads (failed about 01:37:47Z) |
| `05-bastion-form.png` | run 2, 01:40:04Z: DC01's Bastion form opens 12 s into the run, about 16 min after activation (inputs blurred) |
| `06-session-desktop.png`, `07-session-whoami.png` | 01:40:51Z session open (46 s after Connect); `whoami & hostname` in an elevated prompt printed `corp\contosoadmin` and `DC01` (the taskbar-search path worked, unlike 2026-11-07) |
| `prove-run-2-connect.log`, `proof-2-connect.json` | session start 01:40:05Z, tab closed 01:41:24Z (79 s) |
| `playback-on.log` | 01:23:32Z shared-key access on for the recordings account (the portal player needs it) |
| `07r-pim-*.png` | the reviewer's three activations on rg-lab-sandbox, 1 hour each: Reader 01:44:10Z, Storage Blob Data Reader 01:45:57Z, Storage Account Key Operator 01:47:42Z (about 92 s each in the portal) |
| `08-recordings-list.png` | 01:48:07Z Session recordings as adm-mei.tanaka: one recording, `vm-dc01-rdp-contosoadmin-a60762c3...`, 00:01:32, created 01:40:07Z (after this session began) |
| `09-playback-start.png`, `10-playback-whoami.png`, `11-playback-end.png` | 01:48:44Z the player (new tab on the Bastion host) plays; the clock moved 0 s -> 15 s; at 1:11 of 1:28 it shows the `whoami & hostname` output |
| `prove-run-3-playback.log`, `proof-3-playback.json` | step 4 with UTC times |
| `recording-blobs.json` | operator read of the container: one blob, `.guac`, 1,331,893 bytes, created 01:40:07Z |

Not in the repo, on the lab Mac: Playwright videos of both browsers
(`~/contoso-demo/captures/bastion/2026-11-10/video-admin/`, `video-reviewer/`).
The recording stays in `stbstrec184a7387/recordings` until
`capture.sh purge-recordings`.

Not done by this run: `capture.sh down`. Bastion was left up for the Intune EPM
proof on CH-WIN11-01 (it needs Bastion to reach the PC); that proof's agent runs
`down` and records its read-back.
