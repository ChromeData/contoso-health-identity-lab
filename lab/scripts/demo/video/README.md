# Demo video: record the live lab

Records a narrated tour of the running tenant, written for non-technical
viewers: title, how the lab was built, lab map, pipeline, HR joiner, AD +
Cloud Sync, access packages, Conditional Access, PIM (with a live activation),
Sentinel, leaver, WORM evidence. On-screen "What that means" cards define each
term as it comes up; the same terms are in `lab/docs/glossary.md`. Output lands in
`lab/evidence/out/video/` (gitignored).

## Needs

- Chrome running with remote debugging on port 9222 and signed in to the
  Entra admin center as a lab admin. `record` copies that session into
  `out/video/state/admin.json` (chmod 600, gitignored); `clean` deletes it.
- `az` signed in to the lab tenant; `pwsh` with Microsoft.Graph (for the TAP).
- `ffmpeg`, Node with Playwright (`lab/setup/signup-assist`), Python 3.
- The Azure OpenAI TTS deployment `narration-tts` (voice `onyx`), reached with
  an Entra token. No API keys.
- The Whisperglass lab map (`LAB_MAP_HTML`, default
  `~/whisperglass/labs/contoso-health/map.html`).

## Run

```bash
cd lab/scripts/demo/video
node director.mjs ids        # object ids for deep links (cached, chmod 600)
node director.mjs map        # map with the tiles now running in the tenant
node director.mjs tts        # narration per beat (cached by text)
node director.mjs record     # all scenes; or: record 08 10 --dry for 2 s beats + stills
python3 assemble.py          # -> out/video/contoso-health-lab-demo.mp4 + .srt
node director.mjs clean      # delete the copied admin session
```

The live PIM scene (11) really activates `adm-raj.patel` into PIM-Tier1-Helpdesk
for one hour. To record it again inside that hour, remove the activation first
(PIM refuses removal in the first five minutes), or wait for it to expire.

Re-record one scene by naming it (`record 11`), then run `assemble.py` again.

## How it stays safe

- No secret reaches a command line, a log, or the video file system. The live
  PIM scene issues a one-time Temporary Access Pass with `issue-tap.ps1`,
  which writes it only to stdout for the recorder to hold in memory.
- Every page blurs GUIDs, the subscription and tenant ids, and public IPv4 and
  IPv6 addresses as it renders.
- Terminal scenes replay real command output captured into `out/video/term/`
  (the commands shown are the ones that produced it).

## How it works

`scenes.mjs` lists the scenes. Each narration beat has a `prep` (navigate,
wait, close pop-ups: cut from the final video) and a `run` (what the viewer
sees while that beat is spoken). `rec.mjs` records each scene as one page,
marks every beat's window, and pins wall-clock time to video time with a
magenta calibration frame. `assemble.py` cuts the windows, lays the narration
on them, crossfades scenes, and builds the subtitle track.
