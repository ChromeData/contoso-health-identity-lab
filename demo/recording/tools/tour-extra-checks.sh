#!/usr/bin/env bash
# Piece 11, the four extra tour stops (2026-11-06): the live, READ-ONLY checks
# whose output the stops show in VS Code (cockpit/tour/out/*.txt).
#   bash tools/tour-extra-checks.sh
# Needs the worktree cockpit/.tour-main (the lab at origin/main, detached):
#   git -C ~/contoso-health-identity-lab worktree add --detach ~/contoso-demo/cockpit/.tour-main origin/main
# Every cloud call is a read (list / describe / GET) through the lab operator
# (lab/scripts/operator/op). No secret is read, printed or passed in argv.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$here/.tour-main"; OUT="$here/tour/out"; mkdir -p "$OUT"
REPO=ChromeData/contoso-health-identity-lab
cd "$LAB"
git fetch -q origin main && [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "tour-main is not at origin/main: git -C $LAB checkout --detach origin/main" >&2; exit 1; }
SHA=$(git rev-parse --short HEAD); NOW=$(date '+%Y-%m-%d %H:%M %Z')
OP="$LAB/lab/scripts/operator/op"

# ---- 1 · RBAC linter (PR #209), run here and now --------------------------------
L=lab/k8s/rbac-lint
bad=$(python3 -I $L/rbac_lint.py $L/fixtures/risky-rbac.yaml 2>&1) && be=0 || be=$?
good=$(python3 -I $L/rbac_lint.py $L/fixtures/clean-rbac.yaml 2>&1) && ge=0 || ge=$?
tests=$(python3 -I -m unittest discover -s $L/tests 2>&1 | tail -3 | tr '\n' ' ')
nbad=$(grep -oE '^[0-9]+ risky RBAC rule' <<<"$bad" | grep -oE '^[0-9]+' || echo 0)
[ "$be" = 1 ] && [ "$ge" = 0 ] || { echo "rbac-lint: unexpected exits $be/$ge" >&2; exit 1; }
{
  echo "RBAC linter: who could give themselves more power?"
  echo "Run on this Mac, $NOW (lab main $SHA)"
  echo
  echo "RESULT"
  echo "  planted bad file : $nbad risky rules found   (exit $be)"
  echo "  clean file       : none found              (exit $ge)"
  echo "  unit tests       : $(grep -oE 'Ran [0-9]+ tests' <<<"$tests"), $(grep -oE 'OK|FAILED[^ ]*' <<<"$tests" | tail -1)"
  echo
  echo "\$ python3 $L/rbac_lint.py fixtures/risky-rbac.yaml"
  echo "$bad"
  echo
  echo "\$ python3 $L/rbac_lint.py fixtures/clean-rbac.yaml"
  echo "$good"
} > "$OUT/1-rbac-lint.txt"

# ---- 2 · scanner positive control (PR #215): today's CI run on main -------------
run=$(gh run list -R $REPO --workflow lab-tests.yml --branch main --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId,createdAt -q '.[0] | "\(.databaseId) \(.createdAt)"')
rid=${run%% *}; rat=${run#* }
job=$(gh run view "$rid" -R $REPO --json jobs -q '.jobs[] | select(.name|startswith("scanner positive control")) | "\(.databaseId) \(.conclusion)"')
jid=${job%% *}; jc=${job#* }
[ "$jc" = success ] || { echo "scanner job: $jc" >&2; exit 1; }
# gh 2.10x refuses to print a body with terminal escape codes (job logs have
# colour codes): allowed, then stripped, so the file shown on camera is plain.
log=$(gh api --allow-escape-sequences repos/$REPO/actions/jobs/$jid/logs | perl -pe 's/\e\[[0-9;?]*[A-Za-z]//g; s/\e//g' | sed -E 's/^[0-9T:.-]+Z //' | sed -n '/^scanner self-test/,/^RESULT/p' | grep -v -E 'PRIVATE|BEGIN|END ' )
{
  echo "GitHub Actions: lab-tests, job \"scanner positive control\""
  echo "Run $rid on main ($SHA), started $rat: $jc"
  echo "https://github.com/$REPO/actions/runs/$rid"
  echo
  echo "\$ bash lab/pipelines/scanner-selftest/selftest.sh"
  echo "$log"
} > "$OUT/2-scanner-selftest-ci.txt"

# ---- 4 · built and tested, not switched on yet: live read-only checks ----------
acct=$("$OP" aws sts get-caller-identity --query Account --output text 2>/dev/null)
[ "$acct" = 182002546409 ] || { echo "AWS: operator is in $acct, not the lab account: stopping" >&2; exit 1; }
trails=$("$OP" aws cloudtrail describe-trails --region us-east-1 --query 'length(trailList)' --output text 2>/dev/null)
analyzers=$("$OP" aws accessanalyzer list-analyzers --region us-east-1 --query 'length(analyzers)' --output text 2>/dev/null)
pa=$("$OP" az policy assignment list --query "[].name" -o tsv 2>/dev/null)
npa=$(grep -c . <<<"$pa" || true); ng=$(grep -c -E '^lab-(no-standing-owner|keyvault-deletion-protection)$' <<<"$pa" || true)
ws=$("$OP" az monitor log-analytics workspace list --query "[?name=='loga-idlab'].id" -o tsv 2>/dev/null)
rules=$("$OP" az rest --method get --url "https://management.azure.com${ws}/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01" --query "value[].properties.displayName" -o tsv 2>/dev/null)
nr=$(grep -c . <<<"$rules" || true)
dorm=$(grep -c 'Dormant privileged account' <<<"$rules" || true); bulk=$(grep -c 'Bulk secret reads from Key Vault' <<<"$rules" || true)
flag() { grep -E "^[[:space:]]*$1[[:space:]]*=" "$2" | head -1 | sed -E 's/[[:space:]]+/ /g; s/^ //'; }
dflt() { awk -v v="variable \"$1\"" 'index($0,v){f=1} f&&/^[[:space:]]*default[[:space:]]*=/{gsub(/"/,"",$3); print $3; exit}' "$2"; }
yn() { [ "$1" = 0 ] && echo "not there" || echo "PRESENT"; }
{
  on=$([ "$ng" = 0 ] && [ "$trails" = 0 ] && [ "$analyzers" = 0 ] && [ "$dorm" = 0 ] && [ "$bulk" = 0 ] && echo no || echo yes)
  echo "Built and tested, not switched on yet"
  echo "Read-only check as the lab operator, $NOW (lab main $SHA)"
  echo
  if [ "$on" = no ]; then echo "RESULT: none of the three is switched on."; else echo "RESULT: SOMETHING IS ON: the narration would be wrong."; fi
  echo "  Azure Policy guardrails : off   $ng of the $npa policy assignments are ours"
  echo "  AWS audit trail         : off   $trails trails, $analyzers analyzers"
  echo "  Two new alarms          : off   neither is among the $nr Sentinel rules"
  echo
  echo "DETAILS"
  echo "Azure Policy guardrails (PR #212): no new permanent Owner; key vaults keep delete protection"
  echo "  switch : enable_azure_guardrails = $(dflt enable_azure_guardrails lab/terraform/envs/bootstrap/variables.tf) (default), effect $(dflt standing_owner_effect lab/terraform/envs/bootstrap/variables.tf) (report only)"
  echo "  live   : $npa policy assignment(s) on the subscription, $ng of them ours"
  echo
  echo "AWS audit trail (PR #211): CloudTrail + Access Analyzer"
  echo "  switch : enable_audit_baseline = $(dflt enable_audit_baseline lab/terraform/aws/variables.tf) (default)"
  echo "  live   : lab account $acct, us-east-1: $trails trail(s), $analyzers analyzer(s)"
  echo
  echo "Two new alarms (PR #214): dormant admin signs in again; Key Vault bulk secret reads"
  echo "  switch : $(flag enable_itdr_detections_v3 lab/terraform/envs/dev/lab.tfvars)  (lab.tfvars)"
  echo "  live   : $nr Sentinel rules deployed; dormant admin: $(yn "$dorm"); bulk reads: $(yn "$bulk")"
} > "$OUT/4-not-yet-on.txt"
grep -q '^RESULT: none' "$OUT/4-not-yet-on.txt" || { cat "$OUT/4-not-yet-on.txt" >&2; exit 1; }
echo "tour-extra checks written to $OUT ($NOW, main $SHA)"
