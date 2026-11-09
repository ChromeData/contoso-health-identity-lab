# Bastion session recording, 2026-11-07 (capture log E133)

| File | What it shows |
|---|---|
| `capture-up.log` | `capture.sh up` as the lab operator: Bastion Premium created in 674 s, recording on, tunnelling off, access granted |
| `01-before-pim-no-access.png` | adm-ava.lin opens DC01 before PIM: "You don't have access", 403 |
| `03-pim-request.png` | the activation blade: Reader on rg-identity-lab, reason filled |
| `04-pim-active.png` | the role under Active assignments |
| `05-bastion-form.png` | DC01's Bastion page, open after activation (taken before the form was filled; inputs blurred) |
| `proof-admin.json` | steps 1 to 3 with UTC times |
| `08-recordings-list.png` | the reviewer's Session recordings: one DC01 recording, 00:01:26 |
| `10-playback-whoami.png` | the recording playing in the portal player at 1:07 of 1:23: DC01's Server Manager (AD DS, AD CS, AD FS, DNS), session clock 2:14 AM 11/7/2026 |
| `proof-playback.json` | step 4 with UTC times (the third playback run; the first two failed, see `lab/bastion/README.md`) |
| `capture-down.log` | the reviewer's storage roles revoked, then `capture.sh down`: Bastion, public IP, subnet, identity and eligibility removed, read back absent |

Not in the repo, on the lab Mac: the recording itself
(`~/contoso-demo/captures/bastion/2026-11-07/vm-dc01-contosoadmin-06babc7d.recording`,
1.3 MB, Guacamole protocol text) and the Playwright videos of both browsers
(`proof-admin/`, `proof-playback/`, 65 MB in all).

Azure read-back of the activation (roleAssignmentScheduleInstances, as the
operator): adm-ava.lin, Reader, rg-identity-lab, `Activated`, Direct,
2026-11-07T02:11:31Z to 03:11:28Z.
