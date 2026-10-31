# Your turn: building the lab yourself

These pages are the script for running the lab with your own hands, on camera
or not. Each stage has a **run sheet**: what to type, where to look, what you
should see, and what to do if it goes wrong. Whisperglass gives you the words
to say and puts a ring on the thing to click. You move the mouse.

## The loop you repeat for every stage

Every stage is the same seven beats. Once you have done one, you have done them
all.

| # | Beat | You do | Takes |
|---|---|---|---|
| 1 | **Say it** | Start the stage's Whisperglass section and read the "Map" part. | 1 min |
| 2 | **Open the change** | `turn pr <stage>`. Read the preview out loud, press Enter. The pull request opens in your browser. | 2 min |
| 3 | **Let the robots check it** | Wait for the checks at the bottom of the PR to go green. Open the **Terraform plan** comment and point at what changes. | 3 to 5 min |
| 4 | **Merge** | Click **Merge pull request**, then **Confirm merge**. | 10 s |
| 5 | **Approve, then watch it build** | `turn approve` opens the waiting approval issue: read it and comment **approve** (you are the second pair of eyes). Then `turn watch` follows the apply until it finishes. | 3 to 10 min |
| 6 | **Finish what Terraform can't** | `turn outputs`, then `turn post <stage>` (dry run), then `turn post <stage> go`. | 2 to 5 min |
| 7 | **Show it** | `turn open <page>` and point at the result. Read the "Proof" part. | 1 to 2 min |

Two bot comments land on every PR. The **Terraform plan** comment is the one
you show. The **AI security review** is advisory: it sometimes says "request
changes", it never blocks the merge, and you can say so on camera.

## Commands

All of them say in plain words what they are about to do, and nothing changes
until a command says **FOR REAL** or you press Enter at its prompt.

```text
turn where                 which stage the lab is at now
turn pr <stage>            preview, then open the PR for <stage>
turn approve [go]          the apply waits for you: open its approval
                           issue ('go' approves from the terminal)
turn deny [go]             the same, to cancel it
turn graduate <CA> [go]    one Conditional Access policy report-only -> On
turn watch                 follow the apply until it finishes
turn outputs               save what the next step needs (private folder)
turn post <stage>          the stage's finishing steps, dry run
turn post <stage> go       the same, for real
turn au-rule [go]          day 2 only: the help-desk admin unit rule
turn open <page>           ca, ca-insights, pim-groups, pim-roles,
                           access-packages, auth-methods, consent,
                           sentinel, actions, prs
```

`turn` is `lab/scripts/demo/turn.sh`. Stages: `p2`, `day1`, `day2`, `day3`,
`sentinel`, `dc`, with more added as the build goes on.

## Whisperglass

| Key | What it does |
|---|---|
| `Ctrl 1` | Show or hide the teleprompter |
| `Cmd Shift R` | Recording mode: the teleprompter disappears from the recording, the ring and the map stay |
| `Cmd Shift M` | Show or hide the lab map |
| `Cmd →` / `Cmd ←` | Jump to the next or previous part (Map, Build, Proof) |
| `Esc` | Pause |

The teleprompter follows your voice, so you never scroll. When the text
mentions something on screen, the **ring** lands on it: that is where your eyes
and the mouse go next. If the ring lands in the wrong place, ignore it and
click what the run sheet says.

## Order

| Run sheet | Stage | Whisperglass section | What gets built |
|---|---|---|---|
| [00 Before you start](00-before-you-start.md) | | | Windows, sign-ins, a dry run of every command |
| [01 Sign-in rules](01-day1-sign-in-rules.md) | `day1` | Contoso 05 · Sign-in rules, Contoso 10 · Delivery | Eleven Conditional Access policies (CA021 arrives in 02); nine enforced, CA002 and CA021 report-only |
| [02 Privileged access](02-day2-privileged-access.md) | `day2` | Contoso 06 · Privileged access | Sixteen PIM tier groups, the Global Administrator policy, the help-desk admin unit |
| [03 Governance](03-day3-governance.md) | `day3` | Contoso 03 · Joiner & mover | Four access packages, separation of duties, consent rules |
| [04 Detection](04-sentinel-detection.md) | `sentinel` | Contoso 07 · Detect & respond | Sentinel with seventeen lab rules plus Fusion |
| [05 Directory](05-dc-directory.md) * | `dc` | Contoso 02 · Directory | DC01, the AD forest, the Cloud Sync agent, the HR provisioning app |
| [06 Joiner](06-joiner-dana.md) * | | Contoso 01 · Source of truth, Contoso 03 · Joiner & mover | Dana's first day: HR row to AD to Entra to her apps |
| [07 Apps](07-apps-sso.md) * | `apps` | Contoso 04 · Apps | Single sign-on and provisioning to AWS |
| [08 Sign-in, live](08-sign-in-live.md) * | | Contoso 05 · Sign-in rules | Risk simulations, then each policy switched on (`turn graduate`) |
| [09 Privileged, live](09-privileged-live.md) * | | Contoso 06 · Privileged access | A real PIM activation, the break-glass drill, a vault check-out |
| [10 Detection, live](10-detect-live.md) * | | Contoso 07 · Detect & respond | The held-back rules, the containment playbook, each rule fired once |
| [11 Mover and leaver](11-leaver.md) * | | Contoso 08 · Leaver + non-human identities | Marcus moves to ICU; Dana leaves and loses everything |
| [12 Proof](12-proof.md) * | | Contoso 09 · Proof, Contoso 11 · Drift, Okta, reporting | Before/after numbers, sealed in the evidence store |

\* Draft: written before that stage first ran in the lab tenant. Each one is
checked, and its "(verify)" items replaced with what actually appears, when the
stage is built for the first time.

## Doing a stage again

`lab/scripts/demo/rewind-lab.sh <stage>` shows what going back would remove;
add `--open-pr` to do it. Then run the stage again from beat 2. Details:
[`lab/scripts/demo/README.md`](../../scripts/demo/README.md).
