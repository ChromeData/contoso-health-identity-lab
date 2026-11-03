#!/usr/bin/env bash
# =============================================================================
# reset-demo-hire.sh - put ONE demo hire back to "not hired", so the
# "add a hire row, push, watch Actions" demo can be recorded again.
#
#   lab/scripts/demo/reset-demo-hire.sh 400104              # dry run: prints every step, changes nothing
#   lab/scripts/demo/reset-demo-hire.sh 400104 --apply      # does it
#   lab/scripts/demo/reset-demo-hire.sh 400104 --apply --purge-entra   # later: also empty Entra's Deleted users
#
# "Not hired" means, piece by piece:
#   1. HR file: the person's row is removed from hr_feed.csv on the hr-feed
#      branch (a commit pushed to origin/hr-feed, made in a temporary
#      worktree: your checkout is not touched). hr-feed.yml runs and reports
#      "Removed from the HR file: nothing sent" - deleting a row never
#      switches anyone off, so this push changes nothing in the tenant.
#   2. Active Directory: the account HR provisioning created is deleted on
#      DC01, found by employeeID (run-on-dc.py + lab/scripts/dc/Remove-DemoHire.ps1:
#      a managed run command, no RDP, no password anywhere). That script
#      refuses anything outside OU=Workforce / OU=Disabled, protected
#      (adminCount=1) accounts, and more than one match.
#   3. Downstream, by itself: Cloud Sync deletes the Entra user on its next
#      cycle (about every 20 minutes; Entra keeps it 30 days in Deleted users)
#      and the AWS SCIM job removes the AWS user after that.
#      --purge-entra (after that cycle) permanently deletes the soft-deleted
#      Entra user, for a completely clean slate.
#
# Re-record only after step 3 has happened (the old Entra user is gone):
# a new AD account synced while the old Entra user still exists collides on
# its UPN. Check: Entra admin center -> Users -> search the name (or
# --purge-entra, which says whether Cloud Sync has run yet).
#
# Guard rails: refuses an employeeId that is in main's hr_feed.csv (the
# shipped roster: Dana, Marcus, the IT personas...) unless --force; never
# force-pushes; every step is idempotent (re-run after a failure).
# Needs: git with push access to origin; for steps 2 and --purge-entra,
# `az login` as an admin and DC01 running (az vm start -g rg-identity-lab -n vm-dc01).
# =============================================================================
set -euo pipefail

CSV="lab/scripts/mock-hr/hr_feed.csv"
BRANCH="${HR_FEED_BRANCH:-hr-feed}"
REMOTE="${HR_FEED_REMOTE:-origin}"

usage() { sed -n '3,8p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ID=""; APPLY=0; FORCE=0; SKIP_GIT=0; SKIP_AD=0; PURGE=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --force) FORCE=1 ;;
    --skip-git) SKIP_GIT=1 ;;
    --skip-ad) SKIP_AD=1 ;;
    --purge-entra) PURGE=1 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $arg" >&2; usage 2 ;;
    *) [ -z "$ID" ] || { echo "one employeeId only" >&2; exit 2; }; ID="$arg" ;;
  esac
done
[[ "$ID" =~ ^[0-9]+$ ]] || { echo "usage: $0 <employeeId> [--apply] [--purge-entra] [--force] [--skip-git] [--skip-ad]" >&2; exit 2; }

ROOT="$(git rev-parse --show-toplevel)"
say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
plan() { if [ "$APPLY" -eq 1 ]; then printf '   doing: %s\n' "$*"; else printf '   would: %s\n' "$*"; fi; }

# The row on a ref, or nothing. Exact employeeId match on the first column.
row_on() { git -C "$ROOT" show "$1:$CSV" 2>/dev/null | awk -F, -v id="$ID" '$1 == id' || true; }

git -C "$ROOT" fetch -q "$REMOTE" "$BRANCH" main 2>/dev/null || git -C "$ROOT" fetch -q "$REMOTE" main 2>/dev/null ||
  say "note: could not fetch $REMOTE; using the refs fetched last time"
HR_REF="$REMOTE/$BRANCH"
git -C "$ROOT" rev-parse -q --verify "$HR_REF" >/dev/null || HR_REF=""

if [ -n "$(row_on "$REMOTE/main")" ] && [ "$FORCE" -eq 0 ]; then
  say "REFUSED: employeeId $ID is in main's hr_feed.csv, the shipped roster - not a demo hire."
  say "         (Re-takes of the shipped people: lab/scripts/demo/Reset-DemoState.ps1. Override with --force.)"
  exit 1
fi

ROW=""
if [ -n "$HR_REF" ]; then ROW="$(row_on "$HR_REF")"; fi
GIVEN=""; SURNAME=""
if [ -n "$ROW" ]; then
  IFS=, read -r _ GIVEN SURNAME DEPT TITLE _ STATUS _ <<<"$ROW"
  WHO="$GIVEN $SURNAME, $TITLE ($DEPT), status $STATUS"
else
  WHO="employeeId $ID (no row on ${HR_REF:-$REMOTE/$BRANCH})"
fi
say "Reset demo hire: $WHO"
[ "$APPLY" -eq 1 ] || say "(dry run: nothing changes; add --apply)"

# --- 1. HR file ---------------------------------------------------------------
step "1. HR file: remove the row on $REMOTE/$BRANCH"
if [ "$SKIP_GIT" -eq 1 ]; then
  say "   skipped (--skip-git)"
elif [ -z "$ROW" ]; then
  say "   already done: no row for $ID on ${HR_REF:-$REMOTE/$BRANCH}"
else
  plan "commit 'HR: remove demo hire ${GIVEN} ${SURNAME} (retake reset)' on $BRANCH and push it to $REMOTE"
  plan "hr-feed.yml then reports 'Removed from the HR file: nothing sent' (no change in the tenant)"
  if [ "$APPLY" -eq 1 ]; then
    tmp="$(mktemp -d)"
    trap 'git -C "$ROOT" worktree remove --force "$tmp/wt" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
    git -C "$ROOT" worktree add -q --detach "$tmp/wt" "$HR_REF"
    awk -F, -v id="$ID" '$1 != id' "$tmp/wt/$CSV" > "$tmp/hr_feed.csv"
    cat "$tmp/hr_feed.csv" > "$tmp/wt/$CSV"
    git -C "$tmp/wt" add "$CSV"
    git -C "$tmp/wt" commit -q -m "HR: remove demo hire ${GIVEN} ${SURNAME} (retake reset)"
    git -C "$tmp/wt" push -q "$REMOTE" "HEAD:refs/heads/$BRANCH"
    say "   pushed: $(git -C "$tmp/wt" rev-parse --short HEAD)"
    if [ "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)" = "$BRANCH" ]; then
      if [ -z "$(git -C "$ROOT" status --porcelain -- "$CSV")" ]; then
        git -C "$ROOT" pull -q --ff-only "$REMOTE" "$BRANCH" && say "   your $BRANCH checkout is up to date"
      else
        say "   NOTE: your $BRANCH checkout has local edits to hr_feed.csv: commit or discard them, then git pull"
      fi
    else
      say "   before the next take: git switch $BRANCH && git pull"
    fi
  fi
fi

# --- 2. Active Directory --------------------------------------------------------
step "2. Active Directory (DC01): delete the account with employeeID $ID"
DC_CMD=("$ROOT/lab/scripts/dc/run-on-dc.py" "$ROOT/lab/scripts/dc/Remove-DemoHire.ps1" --param "EmployeeId=$ID" --param "Apply=yes")
if [ "$SKIP_AD" -eq 1 ]; then
  say "   skipped (--skip-ad)"
else
  plan "lab/scripts/dc/run-on-dc.py lab/scripts/dc/Remove-DemoHire.ps1 --param EmployeeId=$ID --param Apply=yes"
  plan "(refuses outside OU=Workforce / OU=Disabled, adminCount=1, or more than one match; 'nothing to delete' if already gone)"
  if [ "$APPLY" -eq 1 ]; then
    (cd "$ROOT" && "${DC_CMD[@]}")
  fi
fi

# --- 3. Downstream ----------------------------------------------------------------
step "3. Entra ID and AWS: automatic"
say "   Cloud Sync deletes the Entra user on its next cycle (about every 20 minutes);"
say "   the AWS SCIM job removes the AWS user after that. Re-record once the Entra user is gone."
if [ "$PURGE" -eq 1 ]; then
  GRAPH="https://graph.microsoft.com/v1.0"
  plan "if the user is in Entra's Deleted users: permanently delete it (az rest DELETE $GRAPH/directory/deletedItems/<id>)"
  if [ "$APPLY" -eq 1 ]; then
    live="$(az rest --method GET --url "$GRAPH/users?\$filter=employeeId%20eq%20'$ID'&\$select=id" --query 'value[].id' -o tsv)"
    if [ -n "$live" ]; then
      say "   still an active Entra user: Cloud Sync has not run yet. Re-run with --purge-entra after its next cycle"
      say "   (or Entra admin center -> Entra Connect -> Cloud sync -> Provision on demand)."
    else
      gone="$(az rest --method GET --url "$GRAPH/directory/deletedItems/microsoft.graph.user?\$select=id,employeeId&\$top=999" --query "value[?employeeId=='$ID'].id" -o tsv)"
      if [ -z "$gone" ]; then
        say "   nothing in Deleted users for $ID: already clean"
      else
        for oid in $gone; do
          az rest --method DELETE --url "$GRAPH/directory/deletedItems/$oid" >/dev/null
          say "   permanently deleted the soft-deleted Entra user ($oid)"
        done
      fi
    fi
  fi
else
  say "   (optional, after that cycle: re-run with --apply --purge-entra --skip-git --skip-ad)"
fi

if [ "$APPLY" -eq 1 ]; then say $'\nDone.'; else say $'\nDry run only. Re-run with --apply to do it.'; fi
