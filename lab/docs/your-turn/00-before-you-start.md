# 00 · Before you start

Do this once, about fifteen minutes before you record. Nothing here changes the
lab.

## Have these with you

- [ ] Your phone, for the Microsoft sign-in prompt.
- [ ] Headphones or a quiet room: Whisperglass follows your voice.

## Open these windows

| Window | Where | Signed in as |
|---|---|---|
| Browser, tab 1 | `turn open prs` (GitHub pull requests) | your GitHub account |
| Browser, tab 2 | `turn open ca` (Entra admin center) | the lab admin, with MFA on your phone |
| Browser, tab 3 | `turn open sentinel` (Defender portal) | the lab admin |
| Terminal | the repo folder, `~/contoso-health-identity-lab` | |
| VS Code | the repo folder | |
| Whisperglass | `Whisperglass.app` | |

A layout that films well: browser on the left two thirds, terminal on the
right third, Whisperglass's teleprompter at the top edge of the screen near the
camera.

## Check every command works

Run these in the terminal. Each one is safe: it reads, it never changes.

| Command | You should see |
|---|---|
| `turn where` | a stage name, for example `p2` or `dc` |
| `turn outputs` | `saved (... bytes)` |
| `turn post day3` | a table of steps, every one marked `whatif`, `in-place` or `unchanged` |
| `turn au-rule` | the help-desk rule and `DRY RUN: nothing changed` |

If `turn` is not found, use the full path: `lab/scripts/demo/turn.sh`.

If a command asks you to sign in, do it in the browser window that opens, and
approve the prompt on your phone.

## Put the lab where you want to start

`turn where` tells you the stage the lab is at. To start your run from the
beginning, go back to `p2` (the floor: the evidence store stays):

```bash
lab/scripts/demo/rewind-lab.sh p2              # what it would remove
lab/scripts/demo/rewind-lab.sh p2 --open-pr    # do it (then merge that PR)
```

After the rewind's apply finishes, do the cleanup list it printed. Then
`turn where` says `p2`, and you start at run sheet 01.

## Whisperglass

- [ ] Microphone, Screen Recording and Accessibility are allowed for
      Whisperglass (System Settings > Privacy & Security). Without Screen
      Recording the ring cannot find things on screen.
- [ ] Open the section for the stage you are about to do (the run sheet names
      it). Read the first paragraph once as a sound check.
- [ ] Recording? Press `Cmd Shift R` so the teleprompter stays off the video.
