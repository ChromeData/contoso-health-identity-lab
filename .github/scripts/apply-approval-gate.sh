#!/usr/bin/env bash
# =============================================================================
# apply-approval-gate.sh - the human "four eyes" step before terraform apply,
# for a PRIVATE repository.
#
# GitHub's own gate (Environment "required reviewers") is free only on public
# repositories; on private ones it needs GitHub Enterprise. Until this repo is
# public, this script is the gate. It runs INSIDE the apply job, AFTER the
# saved plan (tfplan) exists and BEFORE `terraform apply tfplan`:
#
#   plan -> this gate shows that exact plan -> the owner approves it
#        -> the job re-checks the plan file's sha256 -> apply that file
#
# So the approver approves the plan that gets applied, not a run whose plan
# does not exist yet (karen-review A2; the old order is described in ADR 0005
# history). The approval names the plan: the approver comments
# `approve <code>`, where <code> is the first 8 characters of the saved
# plan's sha256, shown in the issue. A bare `approve`, or a code from another
# run, is not accepted.
#
# Who approves: the owner, by hand, from his own GitHub session (repo Variable
# APPLY_APPROVERS, default the repo owner). An AI coding assistant never
# approves. The gate refuses, and cancels the apply on, an approver comment
# that mentions "Claude" or "delegated" (karen-review A1). That check is
# cosmetic on its own - the real control is that nobody but the owner types
# the approval - but it stops the old "reviewed by Claude for ..." pattern.
#
# Change-set check (karen-review A2): the PR plan comment (terraform-plan.yml)
# carries a fingerprint of its change set (`<!-- plan-changeset-sha256: ... -->`,
# from plan-changeset.sh). When the merged commit's PR has that fingerprint and
# the saved plan's change set differs, the gate REFUSES: something besides the
# reviewed PR would be applied (another merge, a portal edit, a repository
# variable). Recovery: re-run from a fresh PR, or a manual workflow_dispatch
# run, whose issue then shows the full saved plan for the owner to read (a
# dispatch skips the PR comparison, even when the commit has a PR, and the
# issue says so).
#
# Honest difference from the Environment reviewer: this gate lives in the
# workflow file, so removing it takes a merged (reviewed) pull request, while
# an Environment reviewer cannot be removed by code at all.
#
# GATE_MODE=check (used by terraform-apply.yml since the repo is public): do
# every check above (author / merger / bot separation, PR change-set compare)
# and write the plan the owner must read to the job summary, then exit
# 0 (checks passed) or 1 (refused). No issue is opened and nothing waits: the
# approval itself is GitHub's Environment "prod" on the apply job (required
# reviewer ChromeData, "Prevent self-review" on), the "Review deployments"
# button.
# GATE_MODE unset = the issue gate below (the private-repo fallback).
#
# Env: GH_TOKEN, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_SHA,
#      GITHUB_SERVER_URL, GITHUB_REPOSITORY_OWNER, GITHUB_EVENT_NAME (Actions)
#      PLAN_SHA256                sha256 of the saved tfplan (required)
#      PLAN_CHANGESET_FILE        plan-changeset.sh output (required; may be empty = no changes)
#      PLAN_SUMMARY_FILE          plain-plan.py output (optional; a missing summary is said)
#      APPLY_APPROVERS            comma-separated logins (default: repo owner)
#      APPLY_TWO_PERSON           "true" = the change author may NOT approve
#      APPLY_BOT_LOGIN            the GitHub App / bot login AI agents push and
#                                 merge as (set 2026-11-08 to
#                                 contoso-health-lab-bot[bot]). Set = real
#                                 two-identity separation: the gate refuses
#                                 unless the PR author AND merger are that bot
#                                 and the approver is in APPLY_APPROVERS and is
#                                 neither of them. Unset = the gate still works
#                                 and says, in the issue and the run summary,
#                                 that separation is by procedure only.
#      APPLY_RANGE_BASE           dispatch runs only: head sha of the last
#                                 successful apply; every PR since then is
#                                 listed with author and merger (R3)
#      APPLY_RANGE_STRICT         true = refuse a dispatch whose range holds a
#                                 change the bot did not author and merge
#      APPROVAL_TIMEOUT_MINUTES   default 30
#      APPROVAL_POLL_SECONDS      default 15
# Exit: 0 approved | 1 denied, refused, timed out, or could not check
# =============================================================================
set -euo pipefail

: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_SHA:?}"
: "${PLAN_SHA256:?PLAN_SHA256 is required: the gate shows and binds the saved plan}"
: "${PLAN_CHANGESET_FILE:?PLAN_CHANGESET_FILE is required}"
[ -f "$PLAN_CHANGESET_FILE" ] || { echo "Refused: change-set file $PLAN_CHANGESET_FILE is missing"; exit 1; }
printf '%s' "$PLAN_SHA256" | grep -Eq '^[0-9a-f]{64}$' || { echo "Refused: PLAN_SHA256 is not a sha256"; exit 1; }

SERVER="${GITHUB_SERVER_URL:-https://github.com}"
APPROVERS="${APPLY_APPROVERS:-${GITHUB_REPOSITORY_OWNER:?}}"
TWO_PERSON="${APPLY_TWO_PERSON:-false}"
TIMEOUT_MIN="${APPROVAL_TIMEOUT_MINUTES:-30}"
POLL="${APPROVAL_POLL_SECONDS:-15}"
REPO="$GITHUB_REPOSITORY"
CODE="${PLAN_SHA256:0:8}"
# shellcheck disable=SC2016  # literal backticks, not a command
MARKER='## Terraform plan — `lab/terraform/envs/dev`'

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }
cap() { head -c "$1" "$2"; [ "$(wc -c < "$2")" -le "$1" ] || printf '\n... [truncated: the full list is in the run log]\n'; }

run_url="$SERVER/$REPO/actions/runs/$GITHUB_RUN_ID"
short="${GITHUB_SHA:0:7}"
changeset_sha=$(sha256_of "$PLAN_CHANGESET_FILE")
n_changes=$(grep -c . "$PLAN_CHANGESET_FILE" || true)

# ---- The merged commit's PR (fail closed: "couldn't read" is not "none") ----
pulls_json=$(gh api "repos/$REPO/commits/$GITHUB_SHA/pulls") || { echo "Refused: could not read the PR for $GITHUB_SHA"; exit 1; }
pr_number=$(printf '%s' "$pulls_json" | jq -r '.[0].number // empty')
pr=$(printf '%s' "$pulls_json" | jq -r '.[0] | select(.) | "#\(.number) \(.title)"')
author=$(printf '%s' "$pulls_json" | jq -r '.[0].user.login // empty')
if [ -z "$author" ]; then
  author=$(gh api "repos/$REPO/commits/$GITHUB_SHA" --jq '.author.login // empty') || { echo "Refused: could not read the commit author"; exit 1; }
fi
author_lc=$(printf '%s' "$author" | tr '[:upper:]' '[:lower:]')
who=$(printf '%s' "$APPROVERS" | sed 's/[^,][^,]*/@&/g; s/,/, /g')

# ---- Who merged it, and the bot / owner separation (APPLY_BOT_LOGIN) --------
# The list endpoint above has no merged_by; the single-PR read does.
merger=""
if [ -n "$pr_number" ]; then
  merger=$(gh api "repos/$REPO/pulls/$pr_number" --jq '.merged_by.login // empty') \
    || { echo "Refused: could not read who merged PR #$pr_number"; exit 1; }
fi
merger_lc=$(printf '%s' "$merger" | tr '[:upper:]' '[:lower:]')
BOT="${APPLY_BOT_LOGIN:-}"
bot_lc=$(printf '%s' "$BOT" | tr '[:upper:]' '[:lower:]')
if [ -n "$BOT" ]; then
  if [ -z "$pr_number" ]; then
    echo "Refused: APPLY_BOT_LOGIN is set, and this run has no pull request whose author and merger can be checked"
    exit 1
  fi
  if [ "$author_lc" != "$bot_lc" ] || [ "$merger_lc" != "$bot_lc" ]; then
    echo "Refused: APPLY_BOT_LOGIN=$BOT, but PR #$pr_number was authored by @${author:-unknown} and merged by @${merger:-unknown}"
    exit 1
  fi
  separation_line="Separation: the change was authored and merged by the bot @$BOT; the approver must be a different account in APPLY_APPROVERS."
else
  separation_line="**Author and approver are the same GitHub account (${GITHUB_REPOSITORY_OWNER:-the owner}); separation is by procedure only.** APPLY_BOT_LOGIN is not set, so AI agents push and open PRs with the owner's login, and only the owner types the approval."
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n\n' "$separation_line" >> "$GITHUB_STEP_SUMMARY"
  fi
fi

# ---- Compare the saved plan's change set with the PR plan comment -----------
compare_line=""
mismatch=false
if [ "${GITHUB_EVENT_NAME:-}" = "workflow_dispatch" ] || [ "${GITHUB_EVENT_NAME:-}" = "repository_dispatch" ]; then
  # The manual recovery path: a workflow_dispatch (the owner), or a
  # repository_dispatch "apply-main" (the bot's recovery run; it needs only
  # Contents: write, lab/pipelines/README.md section 3). A dispatch on a
  # merged main commit still finds that commit's PR, but it was started by
  # hand to apply what is there now, so the PR comparison is skipped (it
  # would refuse again). The summary says so and shows the full saved plan,
  # which is what the reviewer approves.
  from_pr=""
  [ -z "$pr_number" ] || from_pr=" (the commit came from PR #$pr_number; its plan comment is not compared)"
  compare_line="**Not compared:** this is a manual ${GITHUB_EVENT_NAME} run$from_pr. Read the saved plan below; it is what will be applied."
  # karen-review round 2, R3: a dispatch applies EVERYTHING merged since the
  # last successful apply, not just the head commit's PR, so the bot check on
  # the head PR alone proves nothing about the rest. List every PR in the
  # range (APPLY_RANGE_BASE = head sha of the last successful apply, found by
  # the workflow), with author and merger, and flag each one the bot did not
  # both author and merge. APPLY_RANGE_STRICT=true refuses the run instead.
  # Fail closed: a range or PR lookup that cannot be read stops the gate.
  range_base="${APPLY_RANGE_BASE:-}"
  if [ -n "$range_base" ]; then
    printf '%s' "$range_base" | grep -Eq '^[0-9a-f]{7,40}$' || { echo "Refused: APPLY_RANGE_BASE is not a commit sha"; exit 1; }
    # One compare page holds at most 250 commits (Greptile on #274): read
    # every page, then refuse unless the count equals total_commits.
    range_shas=$(gh api "repos/$REPO/compare/$range_base...$GITHUB_SHA?per_page=100" --paginate --jq '.commits[].sha') \
      || { echo "Refused: could not read the commits between $range_base and $GITHUB_SHA"; exit 1; }
    range_total=$(gh api "repos/$REPO/compare/$range_base...$GITHUB_SHA?per_page=1" --jq '.total_commits') \
      || { echo "Refused: could not read the commit count between $range_base and $GITHUB_SHA"; exit 1; }
    range_read=$(printf '%s\n' "$range_shas" | grep -c . || true)
    if [ "$range_read" != "$range_total" ]; then
      echo "Refused: read $range_read of $range_total commits between ${range_base:0:7} and $short; the PR list would be incomplete"
      exit 1
    fi
    range_rows=""; range_flagged=0; seen=" "
    for c in $range_shas; do
      cpulls=$(gh api "repos/$REPO/commits/$c/pulls") || { echo "Refused: could not read the PR for commit $c"; exit 1; }
      n=$(printf '%s' "$cpulls" | jq -r '.[0].number // empty')
      if [ -z "$n" ]; then
        range_rows="$range_rows"$'\n'"| ${c:0:7} | (no PR: a direct commit) | - | - | **check** |"
        range_flagged=$((range_flagged + 1)); continue
      fi
      case "$seen" in *" $n "*) continue ;; esac
      seen="$seen$n "
      a=$(printf '%s' "$cpulls" | jq -r '.[0].user.login // empty')
      m=$(gh api "repos/$REPO/pulls/$n" --jq '.merged_by.login // empty') || { echo "Refused: could not read who merged PR #$n"; exit 1; }
      flag="ok"
      if [ -n "$BOT" ]; then
        a_lc=$(printf '%s' "$a" | tr '[:upper:]' '[:lower:]'); m_lc=$(printf '%s' "$m" | tr '[:upper:]' '[:lower:]')
        if [ "$a_lc" != "$bot_lc" ] || [ "$m_lc" != "$bot_lc" ]; then flag="**not bot**"; range_flagged=$((range_flagged + 1)); fi
      fi
      range_rows="$range_rows"$'\n'"| ${c:0:7} | #$n | @${a:-unknown} | @${m:-unknown} | $flag |"
    done
    compare_line="$compare_line"$'\n\n'"**Every PR this run applies** (merged since the last successful apply, \`${range_base:0:7}\`):"$'\n\n'"| Commit | PR | Author | Merger | Check |"$'\n'"|---|---|---|---|---|$range_rows"
    if [ "$range_flagged" -gt 0 ]; then
      compare_line="$compare_line"$'\n\n'"**$range_flagged change(s) in this range were not authored and merged by the bot.** Read each one's diff before you approve."
      if [ "${APPLY_RANGE_STRICT:-false}" = "true" ]; then
        echo "Refused: APPLY_RANGE_STRICT=true and $range_flagged change(s) between ${range_base:0:7} and $short were not authored and merged by the bot"
        exit 1
      fi
    fi
  else
    compare_line="$compare_line"$'\n\n'"**Range unknown:** no successful apply on record (APPLY_RANGE_BASE unset), so the PRs this run carries are not listed."
    if [ "${APPLY_RANGE_STRICT:-false}" = "true" ]; then
      echo "Refused: APPLY_RANGE_STRICT=true and the range of this dispatch is unknown (APPLY_RANGE_BASE unset)"
      exit 1
    fi
  fi
elif [ -n "$pr_number" ]; then
  comments_json=$(gh api "repos/$REPO/issues/$pr_number/comments" --paginate | jq -s 'add // []') \
    || { echo "Refused: could not read the comments of PR #$pr_number"; exit 1; }
  pr_fp=$(printf '%s' "$comments_json" | jq -r --arg m "$MARKER" '
      [ .[] | select(.user.type == "Bot" and .user.login == "github-actions[bot]")
            | select(.body | startswith($m)) ] | last | select(.)
      | .body | capture("<!-- plan-changeset-sha256: (?<h>[0-9a-f]{64}) -->") | .h' 2>/dev/null || true)
  has_comment=$(printf '%s' "$comments_json" | jq -r --arg m "$MARKER" '
      any(.[]; .user.type == "Bot" and .user.login == "github-actions[bot]" and (.body | startswith($m)))')
  if [ -n "$pr_fp" ] && [ "$pr_fp" = "$changeset_sha" ]; then
    compare_line="**Matches the PR plan.** The saved plan changes the same resources as the plan comment on PR #$pr_number (change-set fingerprint \`${changeset_sha:0:12}\`)."
  elif [ -n "$pr_fp" ]; then
    mismatch=true
    compare_line="**Does NOT match the PR plan.** PR #$pr_number's plan comment has change-set fingerprint \`${pr_fp:0:12}\`; this saved plan has \`${changeset_sha:0:12}\`. Something besides the reviewed PR would be applied (another merge, a portal edit, or a repository variable)."
  elif [ "$has_comment" = "true" ]; then
    compare_line="**Not compared:** PR #$pr_number's plan comment has no change-set fingerprint (it was posted before this check existed). Compare the list below with that comment by hand."
  else
    compare_line="**Not compared:** PR #$pr_number has no Terraform plan comment. Read the saved plan below; it is what will be applied."
  fi
else
  compare_line="**Not compared:** this run has no pull request (${GITHUB_EVENT_NAME:-direct run}). Read the saved plan below; it is what will be applied."
fi

summary_file="${PLAN_SUMMARY_FILE:-}"
if [ -n "$summary_file" ] && [ -s "$summary_file" ]; then
  summary=$(cap 30000 "$summary_file")
else
  summary="_No plain-English summary this time (its step failed). The change set below is complete._"
fi
if [ "$n_changes" -eq 0 ]; then
  changes_block="_No resource changes (the saved plan is \"No changes\")._"
else
  # shellcheck disable=SC2016
  changes_block=$(printf '```text\n%s\n```' "$(cap 20000 "$PLAN_CHANGESET_FILE")")
fi

if [ "${GATE_MODE:-}" = "check" ] && [ "$mismatch" != "true" ]; then
  decision_text=$(cat <<EOF
This is the plan the owner approves. After approval the apply job plans again, and applies only if the full fingerprint of that plan (resources, actions and values) equals this one.

To approve: open the run page, click **Review deployments**, read this summary, tick **prod**, click **Approve and deploy**. Only the required reviewer can approve. "Prevent self-review" is on, so the account that started this run cannot approve it.
EOF
)
elif [ "$mismatch" = "true" ]; then
  decision_text="**The apply is refused** because the saved plan differs from the reviewed PR plan. Nothing was applied."
else
  decision_text=$(cat <<EOF
This is the **exact saved plan** this run will apply. Read it, then comment here:

- \`approve $CODE\` to apply this plan (the code is the first 8 characters of its sha256)
- \`deny\` to cancel it

Only $who can decide, typed by hand from their own GitHub session. A comment that mentions an AI assistant or a delegation is refused. With no decision in $TIMEOUT_MIN minutes the apply is cancelled.
$( [ "$TWO_PERSON" = "true" ] && printf 'Two-person rule is ON: the change author (@%s) cannot approve their own change.' "${author:-unknown}" || printf 'Two-person rule is OFF (single-collaborator lab): an approval by the author (@%s) is accepted and recorded as self-approved.' "${author:-unknown}" )
EOF
)
fi

body=$(cat <<EOF
The **terraform apply** of \`$short\` to **prod** is waiting for a human decision.

- Change: ${pr:-no pull request (${GITHUB_EVENT_NAME:-direct run})}
- Change author: ${author:-unknown}$( [ -n "$pr_number" ] && printf ' (merged by %s)' "${merger:-unknown}" )
- Approver must be: $who
- $separation_line
- Run: $run_url
- ${PLAN_LABEL:-Saved plan sha256}: \`$PLAN_SHA256\`
- Resources changed: $n_changes

$compare_line

### What this plan does

$summary

### Change set (actions and addresses only)

$changes_block

$decision_text
EOF
)

if [ "${GATE_MODE:-}" = "check" ]; then
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '## Plan for owner review\n\n%s\n' "$body" >> "$GITHUB_STEP_SUMMARY"
  else
    printf '%s\n' "$body"
  fi
  if [ "$mismatch" = "true" ]; then
    echo "Refused: the saved plan's change set differs from PR #$pr_number's plan comment"
    exit 1
  fi
  echo "::notice title=Review deployments::Read the summary of job 'plan for review', then Review deployments, tick prod, Approve and deploy"
  exit 0
fi

issue_url=$(gh issue create -R "$REPO" --title "Approve: apply $short to prod" --body "$body")
issue="${issue_url##*/}"
echo "Approval needed: $issue_url"

close() {   # $1 = completed | not_planned, $2 = closing comment
  gh issue comment "$issue" -R "$REPO" --body "$2" >/dev/null || true
  gh api -X PATCH "repos/$REPO/issues/$issue" -f state=closed -f state_reason="$1" >/dev/null || true
}

if [ "$mismatch" = "true" ]; then
  echo "Refused: the saved plan's change set differs from PR #$pr_number's plan comment"
  close not_planned "Refused: the saved plan differs from the reviewed PR plan (see above). Nothing was applied. Open a fresh PR, or run the workflow by hand and approve the plan its issue shows."
  exit 1
fi
echo "::notice title=Approval needed::Comment 'approve $CODE' or 'deny' on $issue_url"

hinted=""
# APPROVAL_TIMEOUT_SECONDS: test hook only (tests/test_apply_gate.py); unset in the workflow.
deadline=$(( $(date +%s) + ${APPROVAL_TIMEOUT_SECONDS:-$(( TIMEOUT_MIN * 60 ))} ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  # The latest approve/deny comment by an approver (bots and others ignored).
  latest=$(gh api "repos/$REPO/issues/$issue/comments" --paginate | jq -s 'add // []' \
    | jq -c --arg ok "$APPROVERS" '
        ($ok | split(",") | map(ascii_downcase | gsub("^\\s+|\\s+$"; ""))) as $approvers
        | [ .[]
            | select(.user.type == "User")
            | select((.user.login | ascii_downcase) as $u | $approvers | index($u))
            | (.body | ascii_downcase) as $b
            | ([$b | splits("\\s+")] | map(select(length > 0))) as $w
            | { id: .id, who: .user.login,
                word: (($w[0] // "") | gsub("[^a-z]"; "")),
                code: (($w[1] // "") | gsub("[^0-9a-f]"; "")),
                ai: ($b | test("claude|delegat")) }
            | select(.word == "approve" or .word == "approved" or .word == "deny" or .word == "denied" or .word == "reject") ]
        | last // empty') || { echo "Refused: could not read the approval issue's comments"; close not_planned "The gate could not read this issue's comments, so it cannot confirm a decision. The apply is cancelled."; exit 1; }
  if [ -n "$latest" ]; then
    who_decided=$(printf '%s' "$latest" | jq -r .who)
    word=$(printf '%s' "$latest" | jq -r .word)
    given=$(printf '%s' "$latest" | jq -r .code)
    cid=$(printf '%s' "$latest" | jq -r .id)
    case "$word" in
      approve|approved)
        if [ "$(printf '%s' "$latest" | jq -r .ai)" = "true" ]; then
          echo "Refused: the approval by @$who_decided mentions an AI assistant or a delegation"
          close not_planned "Refused: this approval mentions an AI assistant or a delegation. Applies are approved by the owner, typed by hand. The apply is cancelled."
          exit 1
        fi
        if [ "$given" != "$CODE" ]; then
          if [ "$hinted" != "$cid" ]; then
            gh issue comment "$issue" -R "$REPO" --body "Not accepted: an approval must name this plan, as \`approve $CODE\`. Still waiting." >/dev/null || true
            hinted="$cid"
          fi
          sleep "$POLL"; continue
        fi
        decider_lc=$(printf '%s' "$who_decided" | tr '[:upper:]' '[:lower:]')
        if [ -n "$BOT" ] && { [ "$decider_lc" = "$author_lc" ] || [ "$decider_lc" = "$merger_lc" ] || [ "$decider_lc" = "$bot_lc" ]; }; then
          echo "Refused: @$who_decided is the change author or merger (APPLY_BOT_LOGIN=$BOT)"
          close not_planned "Refused: @$who_decided authored or merged this change. With APPLY_BOT_LOGIN set, the approver must be a different account. The apply is cancelled."
          exit 1
        fi
        if [ "$TWO_PERSON" = "true" ] && [ -z "$author_lc" ]; then
          echo "Refused: the two-person rule is ON but the change author could not be identified (APPLY_TWO_PERSON=true)"
          close not_planned "Refused: the two-person rule is ON but the change author could not be identified, so this approval cannot be accepted (self-approval cannot be ruled out). The apply is cancelled."
          exit 1
        fi
        if [ "$(printf '%s' "$who_decided" | tr '[:upper:]' '[:lower:]')" = "$author_lc" ] && [ -n "$author_lc" ]; then
          if [ "$TWO_PERSON" = "true" ]; then
            echo "Refused: @$who_decided authored this change and cannot approve it (APPLY_TWO_PERSON=true)"
            close not_planned "Refused: @$who_decided authored this change. A different approver must comment approve. The apply is cancelled."
            exit 1
          fi
          echo "Approved by @$who_decided for plan $CODE (SELF-APPROVAL: two-person rule is off)"
          close completed "Approved by @$who_decided for saved plan \`$CODE\`. **Self-approval**: the change author approved their own change (two-person rule off in this single-collaborator lab). Applying: $run_url"
          exit 0
        fi
        echo "Approved by @$who_decided for plan $CODE (author: @${author:-unknown})"
        close completed "Approved by @$who_decided for saved plan \`$CODE\` (change by @${author:-unknown}). Applying: $run_url"
        exit 0 ;;
      *)
        echo "Denied by @$who_decided"
        close not_planned "Denied by @$who_decided. The apply is cancelled."
        exit 1 ;;
    esac
  fi
  sleep "$POLL"
done

echo "No decision within $TIMEOUT_MIN minutes"
close not_planned "No decision within $TIMEOUT_MIN minutes. The apply is cancelled; re-run the workflow to ask again."
exit 1
