# Demo: the lab, part by part

The demo video walks through this identity lab working in its live Microsoft
Entra ID tenant. Entra ID is Microsoft's cloud login service. The video starts
with an intro in which Michael presents the lab map on camera. After that
come 16 short silent clips, one per part of the lab. Each clip has captions
that say what is on screen and why it matters.

## Watch

**Intro: the lab map, presented by Michael (recording coming).**
The script he reads is in [`intro-script.md`](intro-script.md).

The silent captioned clips, in order:

| Part | Title | What it shows | Length | Video |
|---|---|---|---|---|
| N01 | The blueprints | A Terraform change to the nurse and cloud-engineer access packages, from commit to pull request and plan. | TBD | [`N01-the-blueprints.mp4`](videos/N01-the-blueprints.mp4) |
| N02 | Hired | HR hires Sam Rivera in OrangeHRM. There is no password field, and the hire goes out once it is complete. | TBD | [`N02-hired.mp4`](videos/N02-hired.mp4) |
| N04 | First-day doors and the guard | Access by job on day one: the access package, AWS sign-in through Entra, and read-only access to the patient portal stand-in. | TBD | [`N04-first-day-doors.mp4`](videos/N04-first-day-doors.mp4) |
| N04b | The service desk: what staff ask IT for | A nurse asks for ICU apps in ServiceNow, her manager approves, and Entra grants the access. | TBD | [`N04b-the-service-desk.mp4`](videos/N04b-the-service-desk.mp4) |
| N06 | The cameras (Sentinel) | An alarm rule written as code catches an admin power-up and opens an incident in Microsoft Sentinel. | TBD | [`N06-the-cameras.mp4`](videos/N06-the-cameras.mp4) |
| N07 | The second camera (Splunk) | The same rules in Splunk's language, running on the same tenant logs. | TBD | [`N07-the-second-camera.mp4`](videos/N07-the-second-camera.mp4) |
| N08 | Leaving | HR ends Sam's job, and Active Directory, Entra, ServiceNow and AWS each turn the account off with no ticket. | TBD | [`N08-leaving.mp4`](videos/N08-leaving.mp4) |
| N09 | The logbook | One click files seven evidence records, each with a fingerprint, into a write-once store. | TBD | [`N09-the-logbook.mp4`](videos/N09-the-logbook.mp4) |
| N10 | The Microsoft features showcase | Access reviews, requested extras that expire, blocked combinations and other Entra features, each set up as code. | TBD | [`N10-microsoft-features.mp4`](videos/N10-microsoft-features.mp4) |
| N11 | Admin passwords and recorded sessions, the Microsoft way | Key Vault secrets, a Terraform read that leaves no password behind, and a recorded admin session. | TBD | [`N11-admin-passwords-and-sessions.mp4`](videos/N11-admin-passwords-and-sessions.mp4) |
| N12 | Hardening Active Directory | Admin tiers on the domain controller, the policy that keeps top admins off lower-tier computers, and a before and after scan. | TBD | [`N12-hardening-ad.mp4`](videos/N12-hardening-ad.mp4) |
| N13 | Moving an app off AD FS | One app moved from AD FS, an older sign-in server, to Entra: built and tested, cut-over not run yet. | TBD | [`N13-adfs-to-entra.mp4`](videos/N13-adfs-to-entra.mp4) |
| N14 | Okta: the clinic the hospital bought | The clinic's three Okta apps, a tracker built from live reads, and the move to Entra. | TBD | [`N14-okta.mp4`](videos/N14-okta.mp4) |
| N15 | Server access in AWS, and least privilege in Azure | Server shells through AWS Session Manager only during a borrowed admin window, and a narrow operator role in Azure. The gaps are named. | TBD | [`N15-aws-server-access-and-azure-least-privilege.mp4`](videos/N15-aws-server-access-and-azure-least-privilege.mp4) |
| N16 | Checks that prove the code is safe | A Kubernetes permission checker, and scanners that must fail on a deliberately unsafe file. | TBD | [`N16-code-checks.mp4`](videos/N16-code-checks.mp4) |
| N17 | Close: the whole lab from VS Code and GitHub | The code in VS Code, a read-only live check, GitHub Actions runs and the apply approval gate. | TBD | [`N17-close-vscode-github.mp4`](videos/N17-close-vscode-github.mp4) |

Two parts are not in the clip set: N03 (one account, two directories) and N05
(the master key). Both need a real person to sign in live: Sam's account
after his hire, and Raj's admin sign-in to switch on his help-desk power.
A dry run cannot fake those, so they are shown in the live recording, not as
clips. The intro covers both on the map.

## How it was made

- **The map leads.** Every part starts from a stop on the lab map. The tool
  zooms the map to that stop, then opens the real page behind it.
- **A real pointer.** The tool moves the actual mouse pointer and types with
  real key presses in the browser and in VS Code, so what you see is what a
  person would do. It never types a password; sign-ins are done by hand,
  off camera, before recording.
- **Read-only dry runs.** The clips were recorded against the live tenant in
  a dry mode that only reads. Where a step would change something (a hire, an
  approval, an apply), it shows a stand-in instead: a captured screen from an
  earlier real run, labelled as such.
- **OBS pauses while pages load.** OBS is the screen recorder. The tool
  controls it through its websocket and pauses it while a page loads or a
  long check runs, so the clips do not show waiting.
- **Captions come from the checked lines.** Each step's line lives in
  [`recording/steps.mjs`](recording/steps.mjs). A checker
  (`tools/check-steps.mjs`) makes sure every step has a line, a known action
  and real files to point at. The same lines are burned into the clips
  afterwards by [`recording/tools/caption.py`](recording/tools/caption.py),
  in a band under the picture so they never cover the screen.
- **Built with an AI coding assistant.** As the main README says, the
  assistant wrote most of this tool. Michael set the goals, made the design
  calls and reviewed the result.

## Run it yourself

The tool is in [`recording/`](recording/). Its own
[`README.md`](recording/README.md) has the full detail. It was built for one
Mac and one lab, so expect to adapt paths and sign-ins: it looks for the lab
at `~/contoso-health-identity-lab` and its working files at `~/contoso-demo`.

Prerequisites:

- macOS (the pointer, window and display helpers are Swift and AppleScript)
- OBS Studio with the websocket server turned on (`npm run obs-setup` sets it up)
- Node.js
- ffmpeg
- Python 3 with Pillow (for the captions)

Commands, run inside `recording/` after `npm install`:

| Command | What it does |
|---|---|
| `npm start` | Start the cockpit: the teleprompter and driver |
| `npm run dry` | Dry run: steps through the show and changes nothing |
| `npm run rehearse` | Rehearsal on a throwaway copy |
| `npm run record` | Live recording with OBS |
| `npm run watch` | Hands-free dry run, recorded with OBS |
| `npm run clips` | Hands-free dry run, recorded as silent clips |
| `npm run captions -- <dir>` | Burn captions into the clips in `<dir>` |
| `npm run obs-setup` | Turn on the OBS websocket and store its password in the Keychain |
| `npm run bridge` | Build the small VS Code extension the tool drives VS Code through |
| `npm run overlay` | Build the script overlay that OBS cannot see |
| `npm run points` | Build the speech-matching points from the lines |
| `npm test` | Unit tests and the step checker |
| `npm run test:speech` | Check the speech matcher against a test set |

## What is not in this folder

`recording/` is a copy of the tool's tracked files, with these left out:

- `vscode-ext/*.vsix`: built copies of the VS Code extension. `npm run bridge`
  builds one from `vscode-ext/extension.js`.
- `.state/`: run logs, local settings and the teleprompter's access key.
- `tools/github-from-brave.mjs`: a one-time helper that copied the owner's
  own GitHub sign-in from his browser into the recording browser. It is not
  needed to run the tool.
- Untracked files: `node_modules`, speech models, narration audio, takes,
  recordings and captures.

The videos go in [`videos/`](videos/).
