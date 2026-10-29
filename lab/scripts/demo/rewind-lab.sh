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
    itdr)     echo 73a4897 ;;
    apps)     echo cd2da6e ;;
    servicenow) echo b2cd930 ;;
    okta)     echo d6f9952 ;;
    reviews)  echo 1710d9b ;;
    *)        return 1 ;;
  esac
}
STAGES=(p2 day1 day2 day3 sentinel dc itdr apps servicenow okta reviews)

# Cleanup Terraform cannot do: objects created by post-apply scripts or by
# provisioning, listed for every stage boundary the rewind crosses.
cleanup_after() {
  case "$1" in
    reviews)
      echo "  - Access review definitions created by post-apply (New-AccessReviewDefinitions.ps1): stop/delete them in Identity Governance > Access reviews." ;;
    okta)
      echo "  - Okta root: terraform apply with enable_entra_federation = false (removes the IdP + routing rule); delete the okta-clinic-idp client secret and its app-management exception policy."
      echo "  - Admin consent on okta-clinic-idp goes with the app (Terraform-owned)." ;;
    servicenow)
      echo "  - ServiceNow: delete the Identity Provider record and its certificate (Multi-Provider SSO); clear TF_SERVICENOW_SSO_SYS_ID / servicenow_sso_sys_id." ;;
    apps)
      echo "  - AWS: Settings > Identity source back to the Identity Center directory; disable automatic provisioning (SCIM) and delete its tokens; Key Vault aws-scim-* secrets; lab/terraform/aws destroy."
      echo "  - The imported gallery redirect-URI set and the Clinical Portal app are Terraform-owned (removed with the flag)." ;;
    itdr)
      echo "  - Nothing extra: the four SecurityEvent rules are Terraform-owned (they return to itdr_exclude_rules)." ;;
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

# Moving FORWARD: the steps after each stage's apply that Terraform does not do
# (lab/scripts/powershell/post-apply/Invoke-PostApply.ps1 and friends).
post_apply_for() {
  case "$1" in
    day1)
      echo "  - day1: Invoke-PostApply.ps1 -Execute -Only baseline (break-glass excluded from every CA policy: the gate)." ;;
    day2)
      echo "  - day2: Invoke-PostApply.ps1 -Execute -Only auth-methods,auth-context,directory-role-pim; then the AU-Workforce-Standard membership rule (step helpdesk-au)." ;;
    day3)
      echo "  - day3: Invoke-PostApply.ps1 -Execute -Only sod,app-governance,consent (auto-assignment and lifecycle-workflows once HR people exist)." ;;
    sentinel)
      echo "  - sentinel: nothing to run; check the analytics rules show Enabled." ;;
    dc)
      echo "  - dc: lab/scripts/dc: 01 forest, reboot, 02 configure, 04 Cloud Sync agent; then mock-hr/New-InboundProvisioningApp.ps1." ;;
    itdr)
      echo "  - itdr: nothing to run; DC01 must already send SecurityEvent rows (Sentinel Logs)." ;;
    apps)
      echo "  - apps: run sheet 07 steps 8-19 (certificate activation, AWS identity source, SCIM token to Key Vault, template id, local seeding apply, provision Dana, lab/terraform/aws)." ;;
    servicenow)
      echo "  - servicenow: activate the signing certificate (output servicenow_saml_signing_cert_activation_command), create the IdP from servicenow_federation_metadata_url (plugin com.snc.integration.sso.multi.installer), then TF_SERVICENOW_SSO_SYS_ID + an apply." ;;
    okta)
      echo "  - okta: admin consent on okta-clinic-idp, output okta_idp_client_secret_command (needs the app's secret-exception policy), then lab/terraform/okta apply with enable_entra_federation = true." ;;
    reviews)
      echo "  - reviews: Invoke-PostApply.ps1 -Execute -Only access-reviews (Graph session needs AccessReview.ReadWrite.All)." ;;
  esac
}

die() { echo "rewind-lab: $*" >&2; exit 1; }
flags() { grep -E '^[a-z_]+ *= *(true|false)' | sed -E 's/ *= */=/' | sort -t= -k1,1; }

# --where: print the stage origin/main is at (or "none") and exit.
if [ "${1:-}" = "--where" ]; then
  cd "$(git rev-parse --show-toplevel)"; git fetch -q origin main
  now=$(git show origin/main:"$DEV_DIR/lab.tfvars" | flags); at=none
  for s in "${STAGES[@]}"; do [ "$(git show "$(stage_commit "$s"):$DEV_DIR/lab.tfvars" | flags)" = "$now" ] && at="$s"; done
  echo "$at"; exit 0
fi

[ $# -ge 1 ] || die "usage: $0 <p2|day1|day2|day3|sentinel|dc> [--open-pr]"
TARGET="$1"; OPEN_PR=false
[ "${2:-}" = "--open-pr" ] && OPEN_PR=true
COMMIT=$(stage_commit "$TARGET") || die "unknown stage '$TARGET' (use: ${STAGES[*]})"

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
git fetch -q origin main
# BASE_REF: what "now" is (default origin/main). Override only to test, e.g. BASE_REF=7a868c2.
BASE_REF="${BASE_REF:-origin/main}"
CURRENT=$(git show "$BASE_REF":"$DEV_DIR/lab.tfvars")
WANTED=$(git show "$COMMIT:$DEV_DIR/lab.tfvars")
[ "$CURRENT" != "$WANTED" ] || die "$BASE_REF is already at stage '$TARGET'."

BRANCH="rewind/${TARGET}-$(date -u +%Y%m%dT%H%M%SZ)"
WT=$(mktemp -d "${TMPDIR:-/tmp}/rewind-lab.XXXXXX")
cleanup() { git worktree remove --force "$WT" >/dev/null 2>&1 || true; $OPEN_PR || git branch -D "$BRANCH" >/dev/null 2>&1 || true; }
trap cleanup EXIT

git worktree add -q -b "$BRANCH" "$WT" "$BASE_REF"
( cd "$WT" && git checkout -q "$COMMIT" -- "${FILES[@]}" )

echo "== Move the lab to stage '$TARGET' (files from $COMMIT) =="
echo "-- flag changes (lab.tfvars): flag  now -> after --"
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

# Where is main now? The stage whose flag set equals main's flag set. Git
# ancestry cannot answer this: after one rewind every stage commit is still an
# ancestor of main while its flags are off.
index_of() { local k; for k in "${!STAGES[@]}"; do [ "${STAGES[$k]}" = "$1" ] && { echo "$k"; return; }; done; echo -1; }
CUR_FLAGS=$(flags <<<"$CURRENT")
CUR_STAGE=""
for s in "${STAGES[@]}"; do
  [ "$(git show "$(stage_commit "$s"):$DEV_DIR/lab.tfvars" | flags)" = "$CUR_FLAGS" ] && CUR_STAGE="$s"
done
TI=$(index_of "$TARGET")
if [ -n "$CUR_STAGE" ]; then CI=$(index_of "$CUR_STAGE"); echo "-- main is at stage '$CUR_STAGE' --"
else CI=$((${#STAGES[@]}-1)); echo "-- main matches no stage exactly (flags edited since); treating it as the newest stage --"; fi

if [ "$TI" -lt "$CI" ]; then
  DIRECTION=rewind
  echo "-- cleanup Terraform cannot do (do it after the rewind apply) --"
  for ((i=CI; i>TI; i--)); do cleanup_after "${STAGES[$i]}"; done
else
  DIRECTION=advance
  echo "-- after the apply, run the steps Terraform does not do --"
  for ((i=CI+1; i<=TI; i++)); do post_apply_for "${STAGES[$i]}"; done
fi

if ! $OPEN_PR; then
  echo "== Dry run only. Re-run with --open-pr to open the $DIRECTION PR. =="
  exit 0
fi

(
  cd "$WT"
  git add "${FILES[@]}"
  git commit -q -m "$DIRECTION: lab to stage '$TARGET' ($COMMIT)

Restores lab.tfvars and the stage-pinning mocked test from $COMMIT. Merging
this applies the stage through the normal pipeline (a rewind destroys what
later stages created).

Generated by lab/scripts/demo/rewind-lab.sh"
  git push -q -u origin "$BRANCH"
  gh pr create -R "$REPO_SLUG" --base main --head "$BRANCH" \
    --title "$DIRECTION: lab to stage '$TARGET'" \
    --body "Restores \`lab.tfvars\` and the mocked test from \`$COMMIT\` (stage **$TARGET**, a **$DIRECTION** from \`${CUR_STAGE:-unknown}\`). Merging runs the apply. A rewind **destroys** what later stages created; an advance builds the stage. After the apply, do the steps the script printed (what Terraform does not own).

Generated by \`lab/scripts/demo/rewind-lab.sh\`."
)
