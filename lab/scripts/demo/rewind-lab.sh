#!/usr/bin/env bash
# =============================================================================
# rewind-lab.sh - put the lab back to an earlier stage so it can be built again
#
# Every stage of the lab was one PR that changed lab/terraform/envs/dev/lab.tfvars
# (and the mocked test that pins the stage). Rewinding = restoring those two
# files from the stage's merge commit, through a normal PR. Merging that PR runs
# the usual reviewer-gated apply, which destroys everything the later stages
# created. Replaying = re-opening the stage PRs in order (their descriptions on
# GitHub are the script).
#
# Usage:
#   lab/scripts/demo/rewind-lab.sh <stage>            # dry run (default)
#   lab/scripts/demo/rewind-lab.sh <stage> --open-pr  # commit, push, open the PR
#
# Stages, oldest first (stage -> merge commit whose two files are restored):
#   p2        evidence store + ITDR telemetry. FLOOR: the WORM evidence store is
#             immutable by design, so nothing rewinds below it.
#   day1      premium licence features + Conditional Access, report-only
#   day2      PIM tiers, Global Admin PIM policy, help-desk AU, CA021
#   day3      governance (access packages, SoD) + NHI governance
#   sentinel  Sentinel + ITDR analytics rules
#   dc        DC01 (AD forest host)
#
# The dry run restores the files in a throwaway git worktree, runs the mocked
# test exactly as CI does (no local terraform.tfvars), and prints the flag
# changes plus the cleanup Terraform cannot do. It never merges anything.
# =============================================================================
set -euo pipefail

REPO_SLUG="ChromeData/contoso-health-identity-lab"
DEV_DIR="lab/terraform/envs/dev"
FILES=("$DEV_DIR/lab.tfvars" "$DEV_DIR/tests/mock_plan.tftest.hcl")
TF="${TERRAFORM:-$(command -v terraform || echo "$HOME/.local/bin/terraform")}"

stage_commit() {
  case "$1" in
    p2)       echo 7a868c2 ;;
    day1)     echo 0b2ec81 ;;
    day2)     echo 694cfe5 ;;
    day3)     echo c208235 ;;
    sentinel) echo 9325872 ;;
    dc)       echo 8fc86a4 ;;
    *)        return 1 ;;
  esac
}
STAGES=(p2 day1 day2 day3 sentinel dc)

# Cleanup Terraform cannot do: objects created by post-apply scripts or by
# provisioning, listed for every stage boundary the rewind crosses.
cleanup_after() {
  case "$1" in
    dc)
      echo "  - Cloud Sync: delete the configuration, then uninstall/unregister the agent (Entra Connect > Cloud sync)."
      echo "  - Delete the 'Contoso HR Inbound Provisioning' enterprise app (New-InboundProvisioningApp.ps1)."
      echo "  - HR-provisioned users (Dana Okafor and the roster): delete them, or keep them for a people-only re-take with Reset-DemoState.ps1." ;;
    sentinel)
      echo "  - Nothing extra: the analytics rules and Sentinel onboarding are Terraform-owned. The Sentinel trial clock keeps running." ;;
    day3)
      echo "  - Lifecycle Workflows (joiner/leaver) created by post-apply: delete in Identity Governance > Lifecycle workflows."
      echo "  - Tenant-wide settings STAY as set (user consent policy, admin consent workflow, app management policy). Re-running post-apply on replay is idempotent." ;;
    day2)
      echo "  - CA021 and authentication context c1 (created by post-apply Set-AuthContextPolicies.ps1): delete CA021, then c1."
      echo "  - adm- admin accounts (New-AdminAccounts.ps1), if created: delete."
      echo "  - Tenant-wide settings STAY as set (authentication methods policy, Global Administrator PIM policy). Replay re-applies them idempotently." ;;
    day1)
      echo "  - Nothing extra: Conditional Access policies and named locations are Terraform-owned." ;;
  esac
}

die() { echo "rewind-lab: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: $0 <p2|day1|day2|day3|sentinel|dc> [--open-pr]"
TARGET="$1"; OPEN_PR=false
[ "${2:-}" = "--open-pr" ] && OPEN_PR=true
COMMIT=$(stage_commit "$TARGET") || die "unknown stage '$TARGET' (use: ${STAGES[*]})"

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
git fetch -q origin main
CURRENT=$(git show origin/main:"$DEV_DIR/lab.tfvars")
WANTED=$(git show "$COMMIT:$DEV_DIR/lab.tfvars")
[ "$CURRENT" != "$WANTED" ] || die "origin/main is already at stage '$TARGET'."

BRANCH="rewind/${TARGET}-$(date -u +%Y%m%dT%H%M%SZ)"
WT=$(mktemp -d "${TMPDIR:-/tmp}/rewind-lab.XXXXXX")
cleanup() { git worktree remove --force "$WT" >/dev/null 2>&1 || true; $OPEN_PR || git branch -D "$BRANCH" >/dev/null 2>&1 || true; }
trap cleanup EXIT

git worktree add -q -b "$BRANCH" "$WT" origin/main
( cd "$WT" && git checkout -q "$COMMIT" -- "${FILES[@]}" )

echo "== Rewind to '$TARGET' (files from $COMMIT) =="
echo "-- flag changes (lab.tfvars): flag  now -> after --"
flags() { grep -E '^[a-z_]+ *= *(true|false)' | sed -E 's/ *= */=/' | sort -t= -k1,1; }
join -t= -a1 -a2 -e absent -o 0,1.2,2.2 <(flags <<<"$CURRENT") <(flags <<<"$WANTED") \
  | awk -F= '$2 != $3 { printf "  %-38s %s -> %s\n", $1, $2, $3 }'

echo "-- mocked test, as CI runs it --"
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
TEST_LOG="$WT/.rewind-test.log"
rc=0
( cd "$WT/$DEV_DIR" && "$TF" init -backend=false -input=false >/dev/null && "$TF" test -var-file=lab.tfvars -no-color ) >"$TEST_LOG" 2>&1 || rc=$?
grep -E "\.\.\. (pass|fail)|Success!|Failure!|Error:" "$TEST_LOG" | tail -25 || true
if [ "$rc" -ne 0 ]; then
  KEPT="${TMPDIR:-/tmp}/rewind-test-$TARGET.log"; cp "$TEST_LOG" "$KEPT"
  die "the mocked test fails for stage '$TARGET' (exit $rc); not opening a PR. Full log: $KEPT"
fi

echo "-- cleanup Terraform cannot do (do it after the rewind apply) --"
crossing=false
for ((i=${#STAGES[@]}-1; i>=0; i--)); do
  s=${STAGES[$i]}
  [ "$s" = "$TARGET" ] && break
  # Only stages that are live on main are crossed.
  if git merge-base --is-ancestor "$(stage_commit "$s")" origin/main; then cleanup_after "$s"; crossing=true; fi
done
$crossing || echo "  - none"

if ! $OPEN_PR; then
  echo "== Dry run only. Re-run with --open-pr to open the rewind PR. =="
  exit 0
fi

(
  cd "$WT"
  git add "${FILES[@]}"
  git commit -q -m "rewind: lab to stage '$TARGET' ($COMMIT)

Restores lab.tfvars and the stage-pinning mocked test from $COMMIT. Merging
this destroys what later stages created (reviewer-gated apply).

Generated by lab/scripts/demo/rewind-lab.sh"
  git push -q -u origin "$BRANCH"
  gh pr create -R "$REPO_SLUG" --base main --head "$BRANCH" \
    --title "rewind: lab to stage '$TARGET'" \
    --body "Restores \`lab.tfvars\` and the mocked test from \`$COMMIT\` (stage **$TARGET**). Merging runs the reviewer-gated apply, which **destroys** everything the later stages created. After the apply, do the cleanup the script printed (objects Terraform does not own).

Generated by \`lab/scripts/demo/rewind-lab.sh\`."
)
