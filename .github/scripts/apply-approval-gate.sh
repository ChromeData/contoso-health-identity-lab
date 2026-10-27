#!/usr/bin/env bash
# =============================================================================
# apply-approval-gate.sh - the human "four eyes" step before terraform apply,
# for a PRIVATE repository.
#
# GitHub's own gate (Environment "required reviewers") is free only on public
# repositories; on private ones it needs GitHub Enterprise. Until this repo is
# public, this script is the gate: it opens an issue for the run, waits for an
# approver to comment "approve" or "deny", then closes the issue. The apply job
# `needs:` this job, so nothing reaches the APPLY identity without a decision.
#
# Honest difference from the Environment reviewer: this gate lives in the
# workflow file, so removing it takes a merged (reviewed) pull request, while
# an Environment reviewer cannot be removed by code at all. The prod
# Environment's deployment-branch policy (main only) still applies either way.
# When the repo goes public, switch back to required reviewers
# (lab/pipelines/README.md section 5E) and delete this job.
#
# Env: GH_TOKEN, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_SHA,
#      GITHUB_SERVER_URL, GITHUB_REPOSITORY_OWNER (all set by Actions)
#      APPLY_APPROVERS            comma-separated logins (default: repo owner)
#      APPROVAL_TIMEOUT_MINUTES   default 30
#      APPROVAL_POLL_SECONDS      default 15
# Exit: 0 approved | 1 denied or timed out
# =============================================================================
set -euo pipefail

: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_SHA:?}"
SERVER="${GITHUB_SERVER_URL:-https://github.com}"
APPROVERS="${APPLY_APPROVERS:-${GITHUB_REPOSITORY_OWNER:?}}"
TIMEOUT_MIN="${APPROVAL_TIMEOUT_MINUTES:-30}"
POLL="${APPROVAL_POLL_SECONDS:-15}"
REPO="$GITHUB_REPOSITORY"

run_url="$SERVER/$REPO/actions/runs/$GITHUB_RUN_ID"
short="${GITHUB_SHA:0:7}"
pr=$(gh api "repos/$REPO/commits/$GITHUB_SHA/pulls" --jq '.[0] | select(.) | "#\(.number) \(.title)"' 2>/dev/null || true)
who=$(printf '%s' "$APPROVERS" | sed 's/[^,][^,]*/@&/g; s/,/, /g')

body=$(cat <<EOF
The **terraform apply** of \`$short\` to **prod** is waiting for a human decision.

- Change: ${pr:-direct push to main}
- Run: $run_url

Read the Terraform plan comment on the pull request, then comment here:

- \`approve\` to apply it
- \`deny\` to cancel it

Only $who can decide. With no decision in $TIMEOUT_MIN minutes the apply is cancelled.
EOF
)

issue_url=$(gh issue create -R "$REPO" --title "Approve: apply $short to prod" --body "$body")
issue="${issue_url##*/}"
echo "Approval needed: $issue_url"
echo "::notice title=Approval needed::Comment 'approve' or 'deny' on $issue_url"

close() {   # $1 = completed | not_planned, $2 = closing comment
  gh issue comment "$issue" -R "$REPO" --body "$2" >/dev/null || true
  gh api -X PATCH "repos/$REPO/issues/$issue" -f state=closed -f state_reason="$1" >/dev/null || true
}

deadline=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  # The latest approve/deny comment by an approver (bots and others ignored).
  decision=$(gh api "repos/$REPO/issues/$issue/comments" --paginate \
    | jq -r --arg ok "$APPROVERS" '
        ($ok | split(",") | map(ascii_downcase | gsub("^\\s+|\\s+$"; ""))) as $approvers
        | [ .[]
            | select(.user.type == "User")
            | select((.user.login | ascii_downcase) as $u | $approvers | index($u))
            | { who: .user.login, word: (.body | ascii_downcase | gsub("^\\s+"; "") | split(" ")[0] | gsub("[^a-z]"; "")) }
            | select(.word == "approve" or .word == "approved" or .word == "deny" or .word == "denied" or .word == "reject") ]
        | last // empty | "\(.who) \(.word)"')
  if [ -n "$decision" ]; then
    who_decided="${decision%% *}"; word="${decision##* }"
    case "$word" in
      approve|approved)
        echo "Approved by @$who_decided"
        close completed "Approved by @$who_decided. Applying: $run_url"
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
