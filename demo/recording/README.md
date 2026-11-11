# Recording cockpit

You talk. You press one key. The cockpit does the clicking, the typing, the
waiting and the recording.

It walks the run sheet's 10 pieces (Sam Rivera, hire to leave) as 45 short
steps (two of them optional). Each step shows the line to say, in big type, on your phone, your iPad
or a second screen. When you press NEXT, the cockpit does that step on the
recorded screen: it opens VS Code at the right lines, types, commits and
pushes, opens GitHub, Entra or AWS at the right page, and draws a soft orange
box around the thing you are talking about. While Microsoft or GitHub is busy,
it pauses OBS. When the next screen is ready, the light turns green and OBS
starts recording again.

## Start it: `npm run record` (2026-11-10 #2)

```bash
cd ~/contoso-demo/cockpit && npm run record                        # LIVE, every v2 part
cd ~/contoso-demo/cockpit && npm run record -- --part 5,6          # LIVE, those parts
cd ~/contoso-demo/cockpit && npm run watch -- --part 16,17 --out <dir>   # hands-free dry demo, recorded
```

`record` runs the lab preflight, opens OBS if needed, sets the stage, checks
the sign-ins, opens the map tab and the first page in a background tab, then
lights **READY** on the presenter card. The terminal prints only what you must
do (`--quiet`); everything else is in `.state/cockpit-<date>.log`.

While the lab preflight runs, `record` also runs `tools/tour-extra-checks.sh`
(read only: the RBAC linter here, today's CI scanner job, and list / describe
reads as the lab operator), so N16's "a read-only check just before recording
shows none is on" is true: `tour/out/*.txt` is from this start. If it fails
(something is on, or `.tour-main` is not at origin/main), it is one of the
NOT READY lines.

**The maps on camera** are served by the cockpit itself, read only and without
the pairing key: `http://localhost:4747/map` (the lab map, `map/lab-map.html`)
and `http://localhost:4747/map/v24?video` (the presenter map). The address bar
never shows a `/Users/...` path. Only those two pages are served, and only to
this Mac.

**The presenter card** (`tools/script-overlay.swift`, `lib/presenter.mjs`) sits
at the top centre of the screen, right under the camera, always the same size
(520 x 210 pt; compact 520 x 112: a long line shrinks a step or two, then
scrolls to the point being said with a soft fade, the box never resizes), in every mode (live,
rehearse, dry, watch). OBS never sees it (macOS `sharingType .none`). It shows
the line point by point (a soft ✓ when speech tracking hears a point's
meaning; ↺ and a dotted underline on a point you went past), a faint
preview of the next line, the part's progress, the take's elapsed time and a
light: **green** talk, **amber** the cockpit is busy (loading, waiting on
GitHub or Microsoft), **red** it needs you (failed step, your hand, paused),
with a 2-3 word reason. `--no-card` turns it off; `--compact` starts it on
one line. The phone teleprompter keeps working as before (**P** = pause).

**Keys that work from anywhere** (no window needs focus; Carbon hot keys, no
macOS permission needed):

| Key | What |
|---|---|
| ⌃⌥→ or ⌃⌥Space | NEXT |
| ⌃⌥← | BACK |
| ⌃⌥R | redo this step |
| ⌃⌥P | pause / go on (OBS, auto-advance and the autopilot hold) |
| ⌃⌥C | compact card on / off |
| ⌃⌥H | hide / show the card |
| PageDown / PageUp | NEXT / BACK, with `--clicker` (on in `npm run record`): a presentation clicker paired with the Mac |

**No typing on screen.** No address is typed and Cmd+L/Cmd+T are never used:
a page the cockpit needs is opened in a BACKGROUND tab (Chrome's own
`Target.createTarget`, `background: true`: the tab in front does not change),
and on its step the hand clicks that tab. The map's links are used when the
map is the page in front. VS Code is driven through the bridge (no typed
commands). Typing that stays because it IS the demo: the commit message in
N01 (`n01-commit`, live only) and Raj's reason in PIM (`n05-activate`, live
only). OrangeHRM (N02, N08) is still a hand step.

**Less dead time.** While a line is said, the next step's pages load in
background tabs. A step's line starts with its first quick on-screen action
(a tab click, a highlight, a file in VS Code), so the hand moves as you start
talking; the 2nd, 3rd... highlight of a step waits for the 2nd, 3rd... point
(your words live; the narration clip's clock in `--watch`). Fixed settles
(2.5-5 s) are now "until the page is quiet", capped at 1.5 s. In a live take
OBS also pauses while a page that is not already loaded has to load (amber
light). The hand is brisker (`COCKPIT_HAND_SPEED`, default 1.3) and
auto-advance fires after 0.6 s of quiet (`COCKPIT_ADVANCE_QUIET`). Off
switches: `COCKPIT_PREFETCH=0`, `COCKPIT_LINE_EARLY=0`, `COCKPIT_LIVE_CUTS=0`,
`COCKPIT_SETTLE=full`. A step can say `lineAfter: true` (its line waits for
all its actions) or give an action `atPoint: n` (it waits for point n).

**Measure a take:** `node tools/gaps.mjs <dir>/N16-*.mp4 <dir>/watch-lines.json`
lists every stretch of still picture of 1.5 s or more with no line being said.

## Start it (the old way)

```bash
cd ~/contoso-demo/cockpit && node cockpit.mjs
```

That is LIVE mode: everything happens for real, and OBS records one file per
piece. The other modes:

| Command | What it does |
|---|---|
| `node cockpit.mjs --dry` | Dry run. It does every step against the lab as it is now, but changes nothing: no typing into files, no commits, pushes, pull requests, merges, sign-ins or workflow runs. For each of those it says what it *would* do. It records nothing. You get a report in `shots/dry-run-report.json` and one picture per step in `shots/`. |
| `node cockpit.mjs --preview` | The whole demo on autopilot, recorded and narrated, then the lab is put back (see "Preview video" below). `--preview --dry` runs the same flow as a dry run. |
| `node cockpit.mjs --rehearse` | Piece 1 for real, on a throwaway branch. The cockpit makes a separate copy of the blueprints folder (`rehearsal/blueprints`), commits, pushes, opens the pull request, waits for GitHub's plan and shows it. Then it closes the pull request without merging and deletes the branch. It never approves and never merges. Your real "1 · The blueprints" folder is not touched. |
| `--record` / `--no-record` | Turns recording on or off (by default it is on only in LIVE). |
| `--display "DELL"` | Records a display other than the main one (any part of its name). |
| `--port 4747`, `--no-open` | The teleprompter port. `--no-open` stops the cockpit opening it on the Mac. |
| `node cockpit.mjs --watch --v2 --part 16,17 --out <dir>` | Hands-free show: a dry autopilot (changes nothing) that records with OBS, plays each line aloud and shows the script in a card OBS cannot see. The camera follows the preview rules: paused while pages load and while a long check runs (n17-check), started and resumed only when the stage window is in front, and a watchdog pauses it the moment anything else comes forward. At the start it lists other apps' visible windows by name (it never touches them: close them yourself) and minimizes every VS Code window that is not a demo window, taking a full-screen one out of full screen first (2026-11-10: the lead's full-screen window was on camera); that window goes back to full screen when the run ends. `--watch --no-record` is the same run with OBS left alone (proves the pointer path). |
| Tabs (2026-11-10) | With the real pointer, the recording browser changes site as a person does: the lab map (`map/lab-map.html`, served at `http://localhost:4747/map`) stays open in a tab; a step that opens a site the map links to goes map tab → the stop's bubble → the card's link (new tab). Otherwise an open tab is clicked in the tab strip, or Cmd+T / Cmd+L and the address is typed. Local pages (the map, files) are never typed. Unattended, the camera rolls through it. `COCKPIT_TABS=0` turns it off. App switches (Chrome and VS Code) stay cuts with the camera paused: a Cmd-Tab or Dock move would show every app on this Mac. |
| `--ring` | The yellow cursor ring (off by default since 2026-11-10; **C** toggles it). |

The cockpit prints two links: one for this Mac and one for your phone. Its
start screen runs `lab/scripts/demo/preflight.sh --check` and shows **READY**
or **NOT READY**, with one line per check. Fix anything red before you start.

## Preview video (autopilot): see the whole take before you record it

```bash
cd ~/contoso-demo/cockpit && node cockpit.mjs --preview
```

The cockpit plays the **whole demo by itself, for real**, and OBS records it
with the microphone muted. Afterwards it lays a stand-in narration over the
picture and gives you `~/contoso-demo/recordings/preview/<date>/preview-full.mp4`,
plus one narrated file per piece (`NN-piece.narrated.mp4`). The narration is
every teleprompter line in the lab's narrator voice (Kokoro am_michael,
`tools/narrate.py`, cached in `narration/`).

- **Pacing.** Each step is held for as long as its narration clip lasts (or
  longer, if its action takes longer). WAIT steps work as they do in a real take:
  OBS pauses until the light is green. The cockpit notes where each step starts
  in the *recorded* time, which leaves out the pauses, in `timeline.json`. That
  is where its clip is mixed in (ffmpeg; the video is copied, never re-encoded).
- **Your hand steps, done for you and labelled on screen** ("PREVIEW · …"):
  - It never approves (rule of 2026-11-07). It stops at the apply gate,
    shows it for the line, and skips the merge's apply; only the owner
    approves.
  - It presses **Contain** on the drill card, only after
    `containment-drill.sh arm` and only when the waiting card is for an
    `itdr-drill-` account.
  - It answers Sam's second-check prompt, if Microsoft asks for one.
- **Works on a copy.** The blueprints change runs from
  `preview/blueprints` on a `preview/cockpit-<time>` branch. Your
  `~/contoso-demo/blueprints` folder and its two uncommitted files are never
  touched. The HR folder is the real one: the reset puts it back.
- **Then it puts the lab back**, so your real take starts from today's state:
  1. It opens a **revert pull request** for the AWS change and labels it
     `ready-for-merge`. The owner approves the PR and its apply; the merge captain
     (the bot) merges it. The cockpit never does either.
  2. It runs `reset-demo-hire.sh 400104 --apply`. When Cloud Sync has removed
     Sam from Entra (about 20 minutes), it runs `--apply --purge-entra
     --skip-git --skip-ad`.
  3. It runs `containment-drill.sh disarm`.
  4. It runs `close-build-noise.sh` as a **dry run**, which only lists what is
     open.
  5. It puts the HR folder back to `origin/hr-feed` and removes the preview copy.

  If a preview stops half-way, `node cockpit.mjs --preview-reset` runs only
  this part, from `.state/preview-last.json`. Add `--dry` to see what it would
  do. The scripts run from a detached worktree of `origin/main` at `.lab-main`,
  so they are always the merged versions.
- **It won't start until you're ready.** `--preview` first checks the
  recording browser's sign-ins (GitHub, Entra, Azure, Defender, AWS, Teams,
  ServiceNow and Splunk; the ServiceNow sign-in is done for you) and that OBS
  can see the screen. If anything is missing, it lists it and stops.
- `node cockpit.mjs --preview --dry` runs the same flow as a **dry run**:
  nothing changes and nothing is recorded. It mixes the narration onto a plain
  test picture, as long as each piece took, to prove the timing and the mix:
  `recordings/preview/<date>-dry/`.

## What the camera sees, and in what order (after preview review 1)

- **One window on stage.** The cockpit never activates a whole app. It brings
  forward exactly one window: the demo VS Code window (found by its title),
  or one of its own Chrome windows (by process). It hides the rest of VS Code
  (including your own VS Code window), and OBS.
- **Before recording,** `Sign in / check sign-ins` also tidies up:
  - it closes the cockpit's old rehearsal and preview VS Code windows;
  - if the demo window is on another Space, it reopens it on this one, and
    sizes it;
  - it minimizes every other VS Code window;
  - it leaves each cockpit browser window with exactly one tab.
- **Screen first, then the line.** A step's actions run first; its line (and
  in `--preview` its narration clip) starts when its page is up. If a WAIT
  follows, OBS pauses only once the line has been said. Live reads such as
  the readiness checks happen off camera.
- **Teams is web Teams only,** as test-user-a in the Contoso tenant. It opens
  through the web app's own channel route
  (`teams.cloud.microsoft/_#/l/channel/...`), not a `/l/` link, so Teams'
  launcher page and Chrome's "Open Microsoft Teams?" prompt never appear. The
  desktop app is quit before each Teams step. The window must show Contoso
  SOC › Identity-SecOps, or the step stops. Microsoft Teams links are blocked in
  the cockpit's Chrome profiles too.
- **ServiceNow:**
  - The admin view is the recovery account's user list. The cockpit checks the
    session before it opens any ServiceNow page.
  - Sam's own view goes through My Apps: the ServiceNow tile, then his
    ServiceNow profile page (`/sp?id=user_profile`), which shows his name.
- **AWS admin view (pieces 4 and 9):** before recording, adm-labops borrows
  LabAdministrator. The cockpit waits until AWS Identity Center lists him in
  the group, and until a real sign-in lands on the Users page. Sam's own AWS
  view opens straight into the patient-portal bucket through the access
  portal's shortcut link.
- **Piece 5** opens Sam's sign-in log only once Graph has his sign-in.
- **Piece 6** is Raj (adm-raj.patel, passkey) activating PIM-Tier1-Helpdesk:
  self-service, MFA plus a reason. The cockpit refreshes until his row shows
  under Active assignments. His role is given back at the end, because PIM
  refuses a deactivation in the first five minutes.
- **Piece 7:**
  - It waits for the alarm on Raj's activation (the rule runs on a timer;
    about 15 minutes) and opens that incident directly. The incident list is
    filtered and can look empty.
  - Entra's user page is shown at 100% zoom, so its Properties column (Account
    enabled, On-premises sync) fits on screen.

**After preview review 2 (unattended takes: `--preview` and `--proof`):**
- **The cockpit's VS Code copy opens on this screen.** A new VS Code window
  opens on the Space of VS Code's active window, and a full-screen window
  has a Space of its own. So the cockpit brings the demo window forward first.
  Then it opens its copy here. If the copy sits on another Space, it closes
  the copy and opens it again here. The preview refuses to start until the
  copy's window is on this screen. Preview 2's piece 1 showed the demo
  window's `pim-activation.kql` instead of the copy's diff.
- **Silent footage is 10 s or less.** A piece starts paused and the camera
  rolls once the first page is up, so it never opens on an empty window. A
  wait pauses as soon as the line ends: unattended there is nobody acting on
  camera, so "hold" does not apply. The camera rolls again only when the next
  page (the result) is up. Any step whose actions (page loads, sign-ins) run
  past 6 s pauses until its page is up. Typing (HR rows, commit messages) is
  never cut.

**After preview review 2, pieces 4 to 8:**
- **A failed step is never left on camera.** In `--preview`, a step that logs
  FAILED stops its line at once. The piece is then retaken in the same lab
  state (automatically, once, for the view-only pieces 3, 4, 5 and 8).
  Otherwise the autopilot stops with a BLOCKED line in progress.log before
  anything changes the lab. `--skip <step-id>` leaves a blocked step out of
  a run.
- **Fresh sessions before every piece,** with the camera off. Each site the
  piece opens is checked and signed in again through the sign-in toolkit
  if it shows a login page: Entra, ServiceNow (recovery account), the staff
  window, and Splunk (its session ends after about an hour).
- **AWS:** provisioning a user on demand doesn't carry their groups. The
  cockpit therefore also provisions the GROUP on demand with that one
  member: App-AWS-IdentityCenter-Users for Sam, PIM-AWS-Lab-Admins for
  adm-labops. It waits until Identity Center lists the membership. A
  LabAdministrator activation that ends within 50 minutes is given back and
  borrowed again. AWS's console tour ("Service menu ... Next") is stepped
  through before any highlight.
- **ServiceNow, Sam's own view:** the cockpit waits for the sign-on hand-off
  to finish before it opens his profile. It closes My Apps' feedback survey
  and answers "Stay signed in?" after the one-time pass. It stops on any
  Entra prompt. This needs the ServiceNow identity provider to NOT request
  an AuthnContextClass (createrequestedauthncontext = false, set by the lead
  on 2026-11-06). Otherwise a passwordless hire gets AADSTS75011.
- **Piece 5** opens Sam's one-time-pass sign-in by its own date and time
  (taken from Graph). It checks that Authentication Details shows "Temporary
  Access Pass", then shows CA001 Require MFA: Success.
- **Piece 7:** the Contain button is found inside the card for this
  incident, tagged, scrolled into view (Teams at 80% if it still doesn't
  fit) and clicked. Then the cockpit waits for the card to say "Decision
  recorded". 7-contained speaks only after Graph shows the drill account is
  off and the card shows the decision.
- **Personal mailboxes are blurred** on every cockpit page (gmail, outlook
  and so on), like ids and IPs: the AWS access portal shows the account's
  root email.
- **The reset** also deletes Sam's ServiceNow record, because Entra's
  leaver only switches it off. It does this as the ServiceNow admin
  (Keychain `contoso-lab-servicenow-admin`, account `admin`), because the
  recovery account can't see inactive users. It matches the exact user_name
  `sam.rivera@contosohealthlab.com`, deletes only records created by
  `svc-entra-provisioning`, and reads back afterwards. The next take then
  shows a clean create.

## Recording day: what changed after preview 2 (read before you record)

These fixes are in the cockpit. Unless noted, they apply to the live take
too, not only to `--preview`:

1. **Only the stage is on screen.**
   - VS Code is never activated as an app. The demo window is raised by its
     title, then VS Code is activated without "all windows", so your own VS
     Code windows (with their chat) stay behind.
   - Every other VS Code window is minimized again before each piece.
   - VS Code's toasts are cleared each time it comes on stage.
   - Unattended takes also check the front window before the camera rolls,
     and every 0.4 s while a line plays. Anything else in front pauses the
     camera until the stage is back. A piece's recording starts only when
     its first page is up.
2. **Sessions are checked before every piece, off camera.** Entra
   (adm-presenter), ServiceNow (recovery account), the staff window, Teams
   (test-user-a in Contoso) and Splunk (its session ends after about an
   hour) are each re-signed by the toolkit if needed.
3. **Personal mailboxes are blurred** on every cockpit page. The AWS access
   portal shows the account's root email.
4. **Piece 4:**
   - AWS needs the GROUP provisioned with Sam, not only Sam (see the
     fallback on the teleprompter).
   - ServiceNow single sign-on needs the identity provider's "Create an
     AuthnContextClass request" turned OFF (done 2026-11-06). Otherwise a
     passwordless hire gets AADSTS75011.
   - Sam's leftover ServiceNow record from an earlier take is deleted by
     the reset as the ServiceNow admin (exact user_name, read back), so
     piece 4 shows a clean create.
5. **Piece 5** opens Sam's one-time-pass sign-in by its date and time, then
   checks Authentication Details before the line.
6. **Pieces 6, 7 and 8 go back to back.**
   - Raj's alarm lands about 10-15 minutes after his activation (AuditLogs
     ingestion about 8 minutes, then a rule that runs every 5 minutes).
     7-incident takes only an incident whose entities include adm-raj.patel,
     and shows Raj in its Assets > Users list.
   - Splunk's rule looks back one hour, so piece 8 must run within the
     hour of Raj's activation. 8-run fails unless the count is above 0 and
     a row shows adm-raj.patel.
   - The cockpit's own AWS-admin activation (adm-labops) also raises PIM
     alarms. They are never shown as Raj's.
7. **Piece 7's card:**
   - The Contain button is in view and highlighted while "nothing happens
     until an approver says yes" plays.
   - Press it on camera. 7-contained then checks Graph (drill account off)
     and the card ("Decision recorded").
   - It tags the NEWEST decided card: the one just pressed, marked before
     the press, or else the last one in the channel. It never tags an older
     card.
8. **Piece 10:**
   - The lines say "write-once store ... the lock stays in its trial
     setting; production locks it for good". The evidence container's
     immutability policy is unlocked in the lab.
   - 10-summary waits until the run's summary says "Evidence pack filed".

9. **Piece 11, the tour** (eight read-only stops, about 2.5 minutes):
   - **Stops 1-2 (vault, recorded sessions)** run on the local PAM harness,
     not the tenant: HashiCorp Vault and Apache Guacamole, named as themselves
     on camera. Start it camera off, on the Splunk Colima VM
     (the default VM holds an older stopped `contoso-pam` stack; leave it):
     a worktree of the lab at origin/main in `cockpit/.pam-tour`, then
     `lab/pam/pam-up.sh` and `test/e2e.sh --skip-ha` (about 5 min; it
     proves check-in rotates the password), then one dual-approved
     check-out: `itsm-ticket.sh add <next> --operator ops-alice --approver
     ops-carol --approver ops-dana` and `psm-session.sh checkout`. The lease
     lasts one hour. The cockpit signs in to Vault (token) and Guacamole
     (guacadmin) itself, typing into masked fields. Afterwards: `checkin`,
     `test/e2e.sh --cleanup`, `docker compose down -v`, and remove the
     worktree.
   - **Stops 3-7** are Entra pages as adm-presenter: PIM-Demo-Readers must
     be active (it lasts 8 hours; the 2026-11-06 run found it expired).
   - **Stop 8, Okta:** test-user-b signs in through Okta's Entra identity
     provider route (`/sso/idps/<id>`; Okta's page itself shows only a
     username box). The window bypasses Okta's CSP so the cockpit's tag
     renders. Every highlight now checks that the overlay really rendered,
     and fails the step otherwise.

   - **Stops 9-12 (added 2026-11-06, about 75 s):** the merged PRs #209,
     #210, #211, #212, #214 and #215 (not #213), read only, in their own
     "Contoso Demo" window (`tour/contoso-demo-tour.code-workspace`): the lab
     at origin/main in the detached worktree `.tour-main`, plus the live
     read-only checks that `tools/tour-extra-checks.sh` writes to `tour/out`
     (RBAC linter run, today's CI scanner self-test, operator reads of Azure
     Policy, CloudTrail, Access Analyzer and Sentinel rules; it refuses if
     anything said to be off is on). Run the script, then
     `node cockpit.mjs --tour-extra`: it records only these four
     stops as `11-tour-extra-raw` and narrates `11-tour-extra.narrated.mp4`.
   - The recorder now restarts OBS's display capture before each session:
     on 2026-11-06 a take recorded a frozen 12:50 AM frame of another window.

10. **VS Code view (owner's request, 2026-11-06):**
    - The demo workspace runs at `window.zoomLevel` 0 and font size 15, with no
      activity bar, status bar, minimap, side bar or panel, and no current-line
      box. The window title stays visible.
    - Piece 1 shows the FINISHED files, not a red/green diff. The bridge
      action `changes` (bridge 0.1.8) reads `git diff -U0 HEAD` and softly
      tints only the changed lines, part by part as each line is spoken
      (`code.changes` with `from`/`to`).
    - New step 1-files opens the pull request's "Files changed" tab on
      GitHub for the clean before and after.
    - Every other VS Code step (pieces 2, 7, 8, 9) gets the same view, and
      their highlights use the same soft tint.
11. **Cursor ring:** `tools/cursor-ring.swift` (built by the cockpit on first
    use) draws a yellow, half-transparent 40 px ring around the pointer.
    - It is click-through, above every window, on every Space, and OBS
      display capture sees it.
    - It follows the real pointer, so it works when you move the mouse
      yourself. Playwright's page clicks don't move the system pointer, and
      those keep their own in-page cursor.
    - **Off by default since 2026-11-10** (owner: no yellow ring in
      recordings). `--ring` starts it with the cockpit, **C** on the
      teleprompter toggles it, and it stops when the cockpit stops.
    - **If OBS shows an old picture without the ring or the orange box**
      (2026-11-10): macOS had stopped OBS's screen capture (display slept,
      error -3805) and OBS never restarts it by itself. The ring and the
      overlays are captured fine while the stream runs. The recorder now
      watches OBS's log and restarts the capture as soon as it stops, pausing
      a take in progress meanwhile. A dry run or rehearsal also refreshes OBS
      when OBS is open, so its preview stays live.
    - Two pointers: OBS records the system pointer (with the ring around it)
      and the in-page pointer separately. `Recorder({ cursor: false })` or
      `obs.setCursor(false)` leaves the system pointer out of the capture.

12. **VS Code profile "Contoso Demo"** (the owner's, 2026-11-06):
    - The cockpit opens the demo workspace and its preview/rehearsal copies
      only with `--profile "Contoso Demo"` (`COCKPIT_VSCODE_PROFILE` to
      change it). A demo window it finds in another profile is closed and
      reopened in this one.
    - The bridge is installed into that profile by `vscode-ext/build-vsix.sh`.
      VS Code adds " — Contoso Demo" to the window title, and the cockpit
      matches on that.
    - Profile settings: GitHub Dark Default, Material icons, Error Lens on,
      zoom 0, font 15, no minimap, and no Copilot or AI chat UI
      (`chat.disableAIFeatures`). The demo workspace file says the same,
      because workspace settings win.
    - The activity bar and status bar stay VISIBLE for the owner. Bridge
      0.1.10+ (`chrome` op) hides both in the window's workspace file when the
      cockpit puts VS Code on stage (`recordingLook` in lib/engine.mjs), and
      `close()` removes them again. A cockpit killed mid-run leaves them
      hidden: the next cockpit run's close() puts them back, or delete the
      two lines from the workspace file.
    - On camera, hr_feed.csv in piece 2 shows in Rainbow CSV's column
      colours.
    - The GitHub Actions side panel is NOT used: VS Code has no GitHub
      sign-in, and the cockpit never signs an extension in with the owner's
      accounts. The run, the PR and the approval gate stay on GitHub's web
      pages. Entra, AWS and ServiceNow stay in the browser.
**Proof clip of piece 1's VS Code part:** `node cockpit.mjs --proof 1`. It
plays diff, nurse, cloud, rule, then types the commit message, on a
throwaway copy, and stops there: nothing is committed, pushed or opened on
GitHub. It is recorded silently and narrated into the preview's folder as
`01-vscode-proof.mp4`. Then the copy's window, worktree and branch are
removed. It needs bridge 0.1.7 (`vscode-ext/build-vsix.sh`).

**Single-piece dry runs:** `node cockpit.mjs --dry --auto --piece 7` runs just
that piece (the Teams step was proven this way, as were piece 4's ServiceNow
steps, with read-only stand-ins).

**Preview retakes:** `node cockpit.mjs --preview --resume-from 7 --only 7
--no-teardown` retakes one piece. It joins `preview-full.mp4` again, and it
disarms any drill it armed.

**Before a preview's revert PR** (the merge captain's spec, in
`lib/teardown.mjs` `clearAutoAssignment`; `npm test` runs its tests):
1. Check that only the preview's automatic policy and its test hire are on
   *IT - Cloud Engineering Apps*. A deleted assignee is identified through the
   audit log; the owner, or anyone unknown, stops it.
2. Switch the policy off (read back to check).
3. Remove the assignments.
4. Wait for 0 assignments on two reads in a row.
5. Delete the policy.

Only then does the revert PR open.

## v2: the 18 parts (N00 to N17), 2026-11-07

`node cockpit.mjs --v2` walks the v2 scripts (`segments/V2-RUNNING-ORDER.md`,
each part's `script-v2.md`) instead of the 11 pieces. The steps are
`stepsV2` and `PIECES_V2` in `steps.mjs`; `node tools/check-steps.mjs --v2`
checks them.

| Command | What it does |
|---|---|
| `node cockpit.mjs --v2` | LIVE, every built part. |
| `node cockpit.mjs --v2 --part 2,3,4,8` | Only those parts (numbers or `N02`). |
| `node cockpit.mjs --v2 --preview --part 0 --out ~/contoso-demo/recordings/preview/2026-11-07` | Preview of a part, recorded into that folder, narrated per part (`N00-intro.narrated.mp4`). |
| `node cockpit.mjs --v2 --dry --auto --piece 4 --no-preflight` | Dry run of one part (`--no-preflight` skips the 4-minute lab check). |
| `node cockpit.mjs --v2 --preview-reset` | Removes a v2 preview's test hire (`.state/v2-hire.json`) if a preview stopped half-way. |
| `--include-pending` | Also loads the PENDING BUILD parts and steps; they stop on their TODO. |
| `--raj-ticket INC00xxxxx` | N05, live: the real ServiceNow incident in Raj's reason (Karen A4). Without it, N05's activation step stops with a red light. |

**What stays the same:** the frontmost-window guard (one stage window;
Claude windows are hidden and never count as the stage), a session check
before each part, FAILED means retake (view-only parts retake once by
themselves), the VS Code bridge with the activity bar and status bar
hidden while recording, and each line starting when its screen is up.

**The cockpit never approves.** It never types an approval, in any mode.
Only the owner approves an apply. A preview stops at the approval screen,
holds it for the line, and skips the apply.

**What a v2 preview changes in the lab: only the HR test hire.** Every step
marked `cloud` (commit, push, pull request, merge, approval, apply, PIM
activation, drill, evidence run, the AWS admin role) is not done; its
`standIn` runs instead: a read-only screen of an earlier real run, labelled
"PREVIEW · ..." on screen (part one: PR #204, its gate and its apply run).
N02 to N08 hire a test nurse ("Test Preview") through the HR form and make
her a leaver. At the end the cockpit removes her the way
`readiness/hr-flow.md` says (reset-demo-hire.sh, Entra purge, ServiceNow
record deleted as the admin, AWS gone after its SCIM cycle) and reads every
place back (`teardown.json`). DC01 is started for the hire if it is off and
deallocated again at the end.

**New screens:**
- `ui/card.html`: title cards, the setup and lab maps (tiles from the lab
  guide's `stops.json`), strips, count and framework cards, the 24-rule
  table. The card is in the URL's hash; nothing is fetched.
- VS Code parts open their lab guide stop with the bridge's `openStop`, so
  VS Code shows that stop's tabs (N01 stop 2, N06 and N07 stop 12).
- N12 and N14 use `v2/contoso-demo-v2.code-workspace`: read-only checkouts
  of PR #225 and PR #222 in `.v2/` (made by `v2Worktrees`).
- The HR form (PR #224) is started from `.v2/hr` (or `COCKPIT_HR_FORM_DIR`)
  when nothing answers on 127.0.0.1:8484. For Sam as Cloud Engineer, run it
  from a checkout whose rules list that job.
- N17's terminal check: bridge 0.1.16 `runCheck` (only
  `lab/scripts/demo/preflight.sh --check`, read only).

**N11, N13 and N15 (2026-11-07)** are built from the real evidence in
read-only copies of their PR branches (`.v2/pam`, `k8skv`, `kvleak`,
`bastion`, `adfs`, `azlp`, and main as `.v2/ssm`) and the Bastion capture in
`captures/bastion/2026-11-07/` (cards can show a picture or a video:
`img`, `video`). EPM is said as built and waiting (24 h per approval); AD FS's
readiness report as not registered; N15 says its gaps. N14's cut-over and
rollback are said as built, not run (no Entra-side result exists).

**Tightening a preview:** `python3 -I tools/tighten.py <part>.narrated.mp4`
cuts every silence over 1.6 s down to 1.6 s (picture and sound together;
the original is kept as `*.untightened.mp4`). N00 uses `--keep-before 16`
so the owner's own opening lines keep their hold. N12's DC01 console screens (Users and Computers, Group
Policy Management) have no cockpit driver: the run's own evidence logs are
shown instead. N14's Okta admin console has no cockpit sign-in: the
Terraform that built those screens is shown instead.

### HR is OrangeHRM (2026-11-07, PR #255, ADR 0028)

The HR form is retired. HR works in **OrangeHRM** (open-source edition 5.9, http://127.0.0.1:8585). Read `readiness/hr-flow.md` for the clicks, the true lines and the measured timings.

- **Before any Sam Rivera take: "Cloud Engineer" must be an OrangeHRM job** (Admin > Job > Job Titles > + Add). Done on this Mac on 2026-11-07 for the screen recapture; check it is still listed (a `hris.sh destroy` loses it). IT's rules must also know the title (the demo branch's rules file), or Sam gets no access package.
- Sam's employee number is **400104** (the next IT number). Manager: Joan Ferris. Nothing leaves OrangeHRM until the Job tab and the Report-to supervisor are both saved.
- Start before recording: `lab/hris/orangehrm/hris.sh up`, then `node lab/hris/connector/sync.mjs --watch 60`. DC01 must be running. Sign in to OrangeHRM as Admin before recording (never on camera) and zoom to 110%.
- Say "within about two minutes the account is in Active Directory; Entra picks it up on its next sync cycle". Never "about four minutes", never "instantly". Leaver: "within a minute of HR's save, the account is switched off in Active Directory".
- N02 and N08 in the cockpit: HR's clicks are **hand steps** (the presenter clicks in OrangeHRM). `--v2 --preview` hires nobody: it shows the captured OrangeHRM run (`captures/E170-E173-orangehrm/`), the connector log, the real hr-feed GitHub run and the watch logs. The old form actions (`hr.open`, `hr.fill`, `hr.hire`, `hr.leave`) and the form's test-hire preview are no longer used by N02/N08.
- Retake reset, in this order: OrangeHRM Terminate Employment, then Maintenance > Purge Records; `lab/hris/orangehrm/hris.sh free-id <number>`; then `lab/scripts/demo/reset-demo-hire.sh <number> --apply` as the operator; then delete the inactive ServiceNow record as admin. Not yet automated in the cockpit for OrangeHRM.

## Once, before your first recording

1. **The VS Code bridge.** Run `vscode-ext/build-vsix.sh`. It packages and
   installs a small extension, "Contoso cockpit bridge". The extension only
   switches on in a window whose workspace file is under `~/contoso-demo` (the
   demo window and the rehearsal window), and it only listens on this Mac.
   The cockpit uses it to open files, show the diff, type, commit and push.
   If you rebuild it while the demo window is open, the cockpit reloads that
   window once so it picks up the new version.
   **The cockpit sizes the VS Code demo window itself**, to the same size as
   the recording browser, through macOS System Events. The first time, macOS
   may ask to let Terminal (or whatever app runs the cockpit) control your
   computer: allow it in System Settings → Privacy & Security →
   Accessibility. If it can't, the log says "could not size it" and the start
   screen tells you the window is too small. On camera, the cockpit hides the
   side bar so the code gets the whole window, and it closes leftover tabs
   at the start of each piece.
2. **OBS.** OBS is installed (`brew install --cask obs`) and has both
   permissions. The cockpit picks the display by its CoreGraphics UUID, read
   with `tools/displays.swift` and cached in `.state/config.json`. It never asks
   OBS for its display list, because OBS 33.0.1 crashes on that request. If OBS
   comes back after a crash in its Safe-Mode prompt, the cockpit clicks "Run in
   Normal Mode". `--display "DELL"` picks another display by name. Run
   `tools/obs-setup.sh` once while OBS is closed. It turns on OBS's remote
   control (port 4455). The password for it is kept in your Keychain as
   `contoso-lab-obs-ws`. The script also skips OBS's first-run wizard. Then,
   in **System Settings → Privacy & Security**:
   - **Screen & System Audio Recording**: turn on **OBS**.
   - **Microphone**: turn on **OBS**.

   Quit OBS and reopen it. The cockpit starts OBS by itself, builds the
   "Contoso demo" scene (your main display plus your microphone) and records
   with Apple's hardware encoder. Until macOS has given OBS permission, the
   start screen says that OBS "cannot see the screen yet".
3. **Sign-ins: the cockpit does them, except GitHub.** Press **Sign in /
   check sign-ins** on the start screen. The cockpit uses the lab's sign-in tool
   (`lab/scripts/demo/signin/identity.mjs`, PR #196) to sign in every lab
   account itself. Secrets stay in your Keychain; the tool reads them there.
   - The **recording window** (`.recording-profile`) is signed in as
     **adm-presenter** (read-only presenter account, passkey) for Entra, Azure,
     Defender and Sentinel. The cockpit activates its PIM group
     **PIM-Demo-Readers** for 8 hours and keeps it signed in. The same window
     also holds **acr.breakglass** for ServiceNow and **splunk-admin** for
     Splunk.
   - The **staff window** (`.staff-profile`) is signed in as **test-user-a**
     for My Apps and Teams. She is a listed containment approver.
   - **Raj's admin badge** (adm-raj.patel, passkey) gets a fresh window of its
     own in piece 6. He activates **PIM-Tier1-Helpdesk**, which is
     self-service: MFA plus a reason, with no approver. Ava's groups are Tier 0
     and would wait for an approver. Between piece 6 and piece 7, off camera,
     the cockpit gives the help-desk power back. **Sam** gets one-time passes
     in his own window.
   - The **AWS admin view** (pieces 4 and 9) is in **adm-labops**'s own window.
     When a live take or a preview starts, he borrows **LabAdministrator** for
     two hours through PIM-AWS-Lab-Admins (ADR 0025). He is provisioned into
     AWS on demand, and gives the role back at the end of a preview.
   - **GitHub is your only sign-in.** It is already signed in as ChromeData in
     the recording window. If it ever isn't, the start screen says "Sign in to
     GitHub once".

   Each window holds exactly one Entra account (the tool refuses to mix them).
   Your own Microsoft account is never used. Page zoom is 125%, and there is no
   bookmarks bar and no automation banner.
4. **Connect your phone or iPad.** It has to be on the same Wi-Fi as the Mac.
   Open the "phone / iPad" link that the cockpit printed (it looks like
   `http://192.168.x.x:4747/?k=…`) and add it to your home screen. The `k=`
   part is the pairing key. Without it, the page doesn't open.
   The key is saved in `.state/ui-key`, so the same link works every time.
   The phone stays awake while the page is open.

## The keys

| Key | What it does |
|---|---|
| **Space**, **→**, **PageDown**, **Enter**, or the big **NEXT** button | Does the next step and shows its line. If the light is still yellow (the screen isn't ready yet), the first press only warns you. Press it again within 6 seconds to go anyway. |
| **←**, **PageUp**, or **BACK** | Goes back one step and shows that screen again. Steps that changed something (commit, push and so on) are not done a second time. |
| **R** | Redo this step (for example, if a page loaded slowly). If the step changes something, press R twice. |
| **T** | **Retake this piece.** Press T twice. The cockpit stops OBS and throws away this piece's file, runs the piece's reset (see below), and goes back to the piece's first step. Press NEXT when you're ready. |
| **L** | Listening on or off (the speech-aware teleprompter, below). |
| **A** | Auto-advance on or off. |
| **M** | The pointer: human, then guide, then dom (the button shows which). |

A presentation clicker sends PageDown and PageUp. **Pair it with the phone or
iPad that shows the teleprompter, not with the Mac.** The cockpit brings
VS Code and Chrome to the front for the camera. On the Mac, a key only reaches
the teleprompter while the teleprompter's window has focus.

**Light:**
- grey: nothing to wait for.
- blue: the cockpit is working.
- yellow: waiting on GitHub or Microsoft. OBS is paused.
- green: the next screen is ready. OBS is recording again.
- red: the cockpit needs your hand. The reason and the fallback appear under
  your line.

**"You:"** lines in orange are the things you do with your own hands. Typing
`approve` on the approval issue is always yours. The cockpit opens the issue
and puts the cursor in the comment box.

## The speech-aware teleprompter: say it your way, it ticks it off

The lines are an outline. Say each one in your own words: the cockpit listens
on this Mac and checks a line off when its **meaning** was said, not its exact
words. "Microsoft Azure is the server hub" is ticked by "Microsoft Azure is
where we hold local cloud servers".

- **On the teleprompter:** each point (one sentence of the lines) has a faint
  ring at its left. It turns into a small green check once you have said it.
  A point you went past (you said a later one, not this one) gets a faint
  amber ring and a dotted underline: say it, or re-record. A small line under
  the light says what it heard and "2 of 3 said". When you leave a step with a
  point not said, the next card shows it in small amber text.
- **Auto-advance (on by default, A turns it off):** once every point of the
  step is said and you pause for about a second, the cockpit presses NEXT for
  you (the same NEXT as the key). It waits while a step is still working or
  the light is yellow, red or blue, and never finishes the last step by itself.
  The NEXT key keeps working as always.
- **The report:** `takes/latest.md` lists every step with points not said
  (its latest take), so you know what to re-record. Each run also writes
  `takes/<date>/<time>-<mode>.json` (every visit: points, what was heard,
  the transcript) and `.md`.
- **Off-topic talk is ignored** ("let me wait for this to load"): it checks
  nothing and does not stop the tracking.
- **How:** ffmpeg reads the microphone; a small voice detector cuts what you
  say at each pause; whisper.cpp (`whisper-server`, model `base.en`, Metal)
  writes it down on this Mac in about 0.1 to 0.3 s; a sentence-meaning model
  (all-mpnet-base-v2 through transformers.js, on this Mac) compares it with
  each point of the step. A sentence counts only for the point it is closest
  to, so saying one point never ticks its neighbour. Nothing leaves the Mac.
- **Settings:** `.state/speech.json` (`listen`, `autoAdvance`, `mic`, the
  ffmpeg avfoundation device: `default`, a name or an index; `model`:
  `base.en` or `small.en`). `--no-listen` turns it off for one run; it is
  always off for `--preview`, `--storyboard` and `--auto`.
- **Microphone permission:** the app that runs the cockpit (VS Code's terminal
  today, which already has it) needs **System Settings > Privacy &
  Security > Microphone**. Without it macOS sends silence; the small line
  says so.
- **Once (already done on this Mac):** the models are in `models/` (not in
  git): `ggml-base.en.bin` and `ggml-small.en.bin` from
  `huggingface.co/ggerganov/whisper.cpp`; the meaning model downloads itself
  into `models/hf/` on first use. `npm install` for `@huggingface/transformers`.
- **After editing lines in `steps.mjs`:** `npm run points` writes each step's
  points into `steps.points.json` (a changed step is derived on the fly anyway).
- **Accuracy:** `node tools/points-eval.mjs` (typed) or `npm run test:speech`
  (each sentence spoken by macOS voices and written down by whisper first) on
  `tests/points-testset.json`: 120 paraphrases of real lines (each also a
  negative for the step's other points) and 34 off-topic sentences (negatives
  for every point of every step). `--tune` re-tunes on split A and reports the
  held-out split B.

## The pointer: a person's hand, or a guide for yours

By default the cockpit moves the **real** macOS pointer (the one OBS records),
not a drawn one, and it moves it the way a hand does (`lib/human.mjs`,
`tools/human-input.swift`, built on first use):

- **Moving:** a slightly curved path (never a straight line or a jump), fast
  in the middle and slow on landing, longer for far or small targets (Fitts'
  law). Far moves overshoot a little and come back; some fall short and correct.
  A faint tremor while moving.
- **Clicking:** a short settle on the target, then press and release about a
  tenth of a second apart. The target is measured again on arrival, so a page
  that moved is followed. The orange box and the click ripple stay.
- **Scrolling:** trackpad flicks that glide to a stop, a beat between flicks,
  not a jump.
- **Typing:** a person's rhythm: uneven keys, a pause between words, longer
  after a comma or before a capital, now and then a short hesitation. No typos.
  Sign-in pages and passwords are never typed with real keys.
- **Changing window:** the hand leaves the page (up toward the tab strip), a
  beat, the window is there, a beat. Opening a page in the same window: the
  hand goes up to the address bar first. No Dock and no Cmd-Tab (both would show
  every app on this Mac); the stage's one-window rule is unchanged.

Safety: a real click happens only if the window under the pointer is the
cockpit's window for that step, and real keys only while that window is in
front. Otherwise that one click or text goes in the old way (Playwright), which
can only reach that page.

| Option | What it does |
|---|---|
| `--mouse human` (default) | The cockpit drives the real pointer and keyboard. |
| `--guide` (= `--mouse guide`) | **You** drive. For each click the cockpit shows where: a pulsing blue ring on the target, a ghost arrow gliding there from your pointer, and a short hint ("Click “Assignments”"). It waits until you click inside it (a click elsewhere is ignored). For typing it says "Click, then type …" and waits until the text is in the box (after 60 s it fills it in). For a scroll it says "Scroll down ↓" (after 20 s it scrolls). The ring, arrow and hint are left out of screen capture, so OBS does not record them. |
| `--old-mouse` (= `--mouse dom`) | The old way: a drawn pointer in the page and Playwright clicks. OBS then hides the system pointer so a take never shows two. Also used by itself when the helper cannot run. |

Live, while the cockpit runs: `POST /api/guide?k=<key>` turns guide mode on and
off; `POST /api/mouse?k=<key>&mode=human|guide|dom` sets the mode. The state
(`mouse: { mode, want, real }`) is in every teleprompter update.

**Needs (once):** System Settings > Privacy & Security > **Accessibility**: the
app you start `node cockpit.mjs` from (Terminal, iTerm or Visual Studio Code),
the same access the stage already uses. Without it the cockpit says so in the
log and uses `--old-mouse`.

## Recordings

The cockpit saves one file per piece in `~/contoso-demo/recordings/<date>/`:
`01-the-blueprints.mkv`, `02-hired.mkv`, and so on. When a piece ends, the
file is converted to `.mp4` (by remuxing, which takes seconds). The `.mkv` is
kept too. A retake replaces that piece's file. Takes from rehearsal or dry runs (when
recorded with `--record`) go to `~/contoso-demo/recordings/practice/<date>/`
instead, so they are never mixed up with the real ones.

**If OBS can't be controlled** (it isn't installed, or its remote control is
off), the cockpit falls back to macOS's built-in `screencapture` (main
display plus the default microphone, saved as `.mov`, then `.mp4`).
`screencapture` **cannot pause**, so the waits stay in the file and you have to
cut them out yourself. The top bar says "screencapture, no pause" when this
happens.

## What each retake (T) resets

| Piece | Reset |
|---|---|
| 1 The blueprints | It closes the pull request, deletes the branch on GitHub, and undoes the commit, so the change is back to uncommitted in your folder. **Once the pull request is merged, piece 1 can't be retaken.** It is live, and undoing it takes a revert. Record from piece 2 onwards, or revert it by hand first. In a rehearsal it starts a fresh throwaway branch. |
| 2 Hired | It runs `reset-demo-hire.sh 400104 --apply`: Sam leaves HR's list and his on-site account is deleted. It brings the HR folder back in line with GitHub. Then it waits (yellow light) until Cloud Sync has removed the old Sam from Entra, which takes about 20 minutes. Only then can he be hired again. |
| 3, 5, 7, 8, 10 | Nothing to undo. These pieces only show things. |
| 4 First-day doors | It closes Sam's sign-in window. |
| 6 The master key | It closes Ava's window. Ava's admin role stays on until it ends by itself (or deactivate it in My roles). |
| 9 Leaving | Leaving can't be undone by itself. It does the same reset as piece 2 and goes back to piece 2. |

## Good to know

- **The start screen checks that the blueprints branch still merges into
  main.** If it doesn't, GitHub runs no checks at all on the pull request
  (a rehearsal on 2026-11-05 found exactly this). Rebase the branch first,
  keeping the two uncommitted on-camera files, then rehearse again.
- **Sam's start date is the recording day.** The cockpit reads the Mac's
  local date when it starts and types it into Sam's row (the run sheet's
  Copy button does the same). The automatic access rules only match people
  whose hire date is today or earlier, so a future start date would mean no
  package in piece 4.
- **Waits:** the GitHub plan takes about 3 minutes and the apply about 4.
  The HR feed takes about 1 minute. Cloud Sync runs about every 20 minutes;
  on its fallback line, the cockpit tells you how to use Provision on demand.
  AWS takes up to 40 minutes (or seconds with Provision on demand). Defender
  alarms can take up to an hour, so record piece 7 last.
- **Piece 4's ServiceNow steps** first check three things live: that
  ServiceNow sign-in through Entra is on (SAML), that the ServiceNow
  provisioning job is on, and that Sam has arrived in its log. If any of them
  isn't true yet, the light turns red and shows the reason (for example "ServiceNow
  provisioning is Paused"). Press NEXT to go past it, or use Provision on
  demand. There are two views:
  - **Admin view.** The recording browser shows ServiceNow's user list, filtered to
    the accounts Entra provisioning created, with Sam's row highlighted. Only
    the account-recovery user `acr.breakglass` can still sign in to ServiceNow
    locally, so the cockpit signs it in **itself, as a setup step** (Check
    sign-ins on the start screen). It reads the password and authenticator
    seed from your Keychain (`contoso-lab-servicenow-acr`,
    `contoso-lab-servicenow-acr-totp`) inside its own process. It computes the
    code, fills both boxes directly (the code box is masked) and forgets them.
    Neither one is ever shown or logged. Before it opens any ServiceNow page, the
    cockpit checks whose ServiceNow session the browser has, and refuses
    anyone but `acr.breakglass`. Opening ServiceNow without that session
    would start single sign-on with your own Entra session, so the cockpit
    never does that. Your account is never used for ServiceNow. If the session
    has expired by the time you reach this step, the cockpit pauses OBS, signs
    in again and then resumes recording.
  - **Staff view.** In a separate clean window, slice 1's staff sign-in toolkit
    (`lab/scripts/demo/signin`) signs `test-user-a` in through My Apps, with a
    real Entra sign-in (password and authenticator code from the Keychain).
    The cockpit highlights the ServiceNow tile, clicks it, and shows Test User A
    landing in ServiceNow.
- **Piece 7's optional Teams step (containment approval)** runs only against
  slice 5's throwaway drill account. First arm the drill (a throwaway
  `itdr-drill-…` user plus a drill incident, the way slice 5 does it). The
  cockpit then checks that the only approval card waiting is for an
  `itdr-drill-` cloud-only account. If a card is waiting for anyone real,
  the light goes red and the cockpit doesn't open Teams. It opens the
  Contoso SOC › Identity-SecOps channel and highlights the card. **You**
  press "Contain (revoke + disable)". OBS keeps recording while it waits for
  your press. The light turns green once the drill account is off. Sign in to
  Teams once in the recording browser (it is in the sign-in check).
- **Sign-ins as Sam and Ava** happen in a separate clean Chrome window. The
  cockpit has the lab operator issue a one-time pass (Temporary Access Pass),
  keeps it in memory, types it into Microsoft's box and forgets it. It is
  never shown, logged or put on a command line. The cockpit allows this only
  for Sam (found by employee ID 400104) and for `adm-ava.lin`.
- **Merging** (piece 1) happens only in LIVE mode, and only for the open
  pull request from the blueprints branch.
- **Logs:** `.state/cockpit-<date>.log`. Rehearsal and dry-run pictures are
  saved in `shots/`. The dry-run report marks each step DONE, WOULD (a change
  it didn't make), SIGN-IN (the recording browser needs your one-time
  sign-in), NOT YET (a live condition, such as Sam not hired), or FAILED.
- **Stopping:** Ctrl-C in the terminal. The cockpit stops OBS, so a piece
  being recorded is saved.

## Files

| Path | What |
|---|---|
| `cockpit.mjs` | The server and the command line |
| `steps.mjs` | Every on-camera step: the line, the actions, the wait, the fallback |
| `lib/engine.mjs` | Moving through the steps, the modes, the waits, retakes and resets |
| `lib/browser.mjs` | The recording Chrome window and the on-screen highlight |
| `lib/human.mjs`, `tools/human-input.swift` | The real pointer and keyboard, moved like a person; guide mode |
| `lib/vscode.mjs`, `vscode-ext/` | The VS Code bridge (client and extension) |
| `lib/obs.mjs`, `lib/recorder.mjs` | OBS remote control and the `screencapture` fallback |
| `lib/live.mjs` | Read-only lookups: `gh`, plus Graph and AWS through the lab operator |
| `lib/rehearsal.mjs` | The throwaway copy and branch used by rehearse mode (and the preview copy) |
| `lib/narration.mjs`, `tools/narrate.py` | Stand-in narration clips for the preview (Kokoro am_michael) |
| `lib/mix.mjs` | Lays each clip over its step's start; produces one file per piece and `preview-full.mp4` |
| `lib/teardown.mjs` | Puts the lab back after a preview: revert PR, Sam reset and purge, drill disarm, noise list |
| `lib/snow.mjs` | ServiceNow: the recovery-account setup sign-in and the provisioned-users list |
| `ui/index.html` | The teleprompter |
| `lib/speech.mjs`, `lib/listen.mjs`, `lib/points.mjs` | The speech-aware teleprompter: tracking and auto-advance, microphone to text, meaning matcher |
| `steps.points.json`, `tools/build-points.mjs` | Each step's key points (precomputed) |
| `tests/points-testset.json`, `tools/points-eval.mjs`, `tests/speech.test.mjs` | The matcher's test set, its precision / recall, and the end-to-end speech test |
| `tools/obs-setup.sh` | The one-time OBS setup |
| `tools/check-steps.mjs` | A quick check to run after editing `steps.mjs`: known actions, waits, files and line numbers |
