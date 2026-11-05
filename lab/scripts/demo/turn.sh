#!/usr/bin/env bash
# =============================================================================
# turn.sh - short commands for building the lab yourself, on camera or not.
# Every command says in plain words what it is about to do, then does it.
# Nothing here holds a tenant id: ids come from the repo's GitHub variables.
#
#   turn.sh where              which stage the lab is at right now
#   turn.sh pr <stage>         preview, then open the PR that moves the lab to
#                              <stage>; the PR opens in your browser
#   turn.sh approve [go]       the apply waits for you: open the approval
#                              issue (or approve from here with 'go')
#   turn.sh deny [go]          the same, to cancel the apply
#   turn.sh watch              follow the apply run on main until it finishes
#   turn.sh outputs            save the Terraform outputs the post-apply step
#                              reads (private, gitignored folder)
#   turn.sh post <stage>       the stage's post-apply steps, DRY RUN
#   turn.sh post <stage> go    the same, for real (stages: day1, day2, day3,
#                              people, eligibility)
#   turn.sh graduate <CA> [go] one Conditional Access policy report-only -> On:
#                              preview + CI test, 'go' opens its PR
#   turn.sh au-rule [go]       day 2: the help-desk admin unit's membership
#                              rule (dry run unless 'go')
#   turn.sh open <page>        open a portal page in your browser:
#                              ca, ca-insights, pim-groups, pim-roles,
#                              access-packages, auth-methods, consent,
#                              sentinel, actions, prs
#
# Stages: p2, day1, day2, day3, sentinel, dc (lab/scripts/demo/rewind-lab.sh).
# =============================================================================
set -euo pipefail

REPO_SLUG="ChromeData/contoso-health-identity-lab"
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
DEV_DIR="lab/terraform/envs/dev"
OUTPUTS="lab/evidence/out/tf-out.json"   # gitignored
TF="${TERRAFORM:-$(command -v terraform || echo "$HOME/.local/bin/terraform")}"

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ghvar() { gh variable get "$1" -R "$REPO_SLUG"; }
die()  { echo "turn: $*" >&2; exit 1; }

# Graph permissions the post-apply steps need (privileged access + governance).
GRAPH_SCOPES="AdministrativeUnit.ReadWrite.All,Application.Read.All,AuditLog.Read.All,EntitlementManagement.ReadWrite.All,Group.Read.All,GroupMember.Read.All,GroupMember.ReadWrite.All,LifecycleWorkflows.ReadWrite.All,Policy.Read.All,Policy.ReadWrite.ApplicationConfiguration,Policy.ReadWrite.AuthenticationMethod,Policy.ReadWrite.Authorization,Policy.ReadWrite.ConditionalAccess,Policy.ReadWrite.ConsentRequest,Policy.ReadWrite.PermissionGrant,PrivilegedAssignmentSchedule.Read.AzureADGroup,PrivilegedEligibilitySchedule.Read.AzureADGroup,PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup,RoleAssignmentSchedule.ReadWrite.Directory,RoleEligibilitySchedule.Read.Directory,RoleEligibilitySchedule.ReadWrite.Directory,RoleManagement.Read.Directory,RoleManagement.ReadWrite.Directory,RoleManagementPolicy.ReadWrite.Directory,User.Read.All,User.ReadWrite.All,User-LifeCycleInfo.Read.All,UserAuthenticationMethod.Read.All"

# Post-apply steps per stage (names from Invoke-PostApply.ps1 -ListOnly).
post_steps() {
  case "$1" in
    day1) echo "baseline" ;;
    day2) echo "baseline,auth-methods,auth-context,directory-role-pim" ;;
    day3) echo "baseline,sod,app-governance,consent" ;;
    # After the HR feed has created staff (run sheet 06): admin accounts for
    # the IT staff, birthright packages, joiner/leaver workflows.
    people) echo "baseline,admin-accounts,auto-assignment,lifecycle-workflows" ;;
    reviews) echo "access-reviews" ;;
    *)    return 1 ;;
  esac
}

page_url() {
  local tid; tid=$(ghvar AZURE_TENANT_ID)
  case "$1" in
    ca)              echo "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" ;;
    ca-insights)     echo "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/InsightsAndReporting" ;;
    pim-groups)      echo "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/aadgroup" ;;
    pim-roles)       echo "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/quickstart/resourceId//resourceType/tenant/provider/aadroles" ;;
    access-packages) echo "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement" ;;
    auth-methods)    echo "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods" ;;
    consent)         echo "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings" ;;
    sentinel)        echo "https://security.microsoft.com/sentinel/analytics?tid=$tid" ;;
    actions)         echo "https://github.com/$REPO_SLUG/actions" ;;
    prs)             echo "https://github.com/$REPO_SLUG/pulls" ;;
    *)               return 1 ;;
  esac
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  where)
    say "Which stage is the lab at?"
    lab/scripts/demo/rewind-lab.sh --where ;;

  pr)
    stage="${1:?usage: turn.sh pr <stage>}"
    say "Preview: what moving the lab to '$stage' changes (nothing is changed yet)"
    lab/scripts/demo/rewind-lab.sh "$stage"
    read -r -p $'\nPress Enter to open the pull request, or Ctrl+C to stop. '
    say "Opening the pull request"
    url=$(lab/scripts/demo/rewind-lab.sh "$stage" --open-pr | grep -oE "https://github.com/[^ ]+/pull/[0-9]+" | tail -1)
    [ -n "$url" ] || die "no PR URL came back"
    echo "$url"; open "$url" ;;

  watch)
    say "Following the apply on main until it finishes"
    id=$(gh run list -R "$REPO_SLUG" -w terraform-apply.yml -b main -L 1 --json databaseId -q '.[0].databaseId')
    [ -n "$id" ] || die "no apply run found"
    gh run watch "$id" -R "$REPO_SLUG" --exit-status ;;

  outputs)
    say "Reading the Terraform outputs from the state (read only) into $OUTPUTS"
    mkdir -p "$(dirname "$OUTPUTS")"
    ( cd "$DEV_DIR" && "$TF" init -reconfigure -input=false \
        -backend-config="resource_group_name=$(ghvar TFSTATE_RG)" \
        -backend-config="storage_account_name=$(ghvar TFSTATE_STORAGE_ACCOUNT)" >/dev/null \
      && "$TF" output -json ) > "$OUTPUTS.tmp"
    # Drop outputs that are credentials (the post-apply steps never read them)
    # and keep the file readable by you only.
    umask 077
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); [d.pop(k,None) for k in ('dc_admin_password',)]; json.dump(d,open(sys.argv[2],'w'))" "$OUTPUTS.tmp" "$OUTPUTS"
    rm -f "$OUTPUTS.tmp"; chmod 600 "$OUTPUTS"
    echo "saved ($(wc -c <"$OUTPUTS" | tr -d ' ') bytes, credentials removed, readable by you only)" ;;

  post)
    stage="${1:?usage: turn.sh post <stage> [go]}"; mode="${2:-}"
    extra=""
    if [ "$stage" = "eligibility" ]; then
      # PIM-for-Groups eligibility for the adm- accounts, built from the
      # register lab/iga/admin-accounts.json (adminAccount -> eligibleFor;
      # a sponsored row such as adm-presenter has no "owner" to derive it from).
      dom=$(ghvar TF_ONMICROSOFT_DOMAIN | tr '[:upper:]' '[:lower:]')
      map=$(python3 - "$dom" <<'PY'
import json, sys
dom = sys.argv[1]
m = {}
for a in json.load(open("lab/iga/admin-accounts.json")).get("accounts", []):
    upn = f"{a['adminAccount']}@{dom}"
    for g in a.get("eligibleFor", []):
        m.setdefault(g, []).append(upn)
print("@{ " + "; ".join(f"'{g}' = @(" + ",".join(f"'{u}'" for u in us) + ")" for g, us in m.items()) + " }")
PY
)
      steps="pim-eligibility"; extra="-PimEligibility $map"
    else
      steps=$(post_steps "$stage") || die "no post-apply steps for '$stage' (stages: day1, day2, day3, people, eligibility, reviews)"
    fi
    [ -s "$OUTPUTS" ] || die "run 'turn.sh outputs' first"
    tid=$(ghvar AZURE_TENANT_ID)
    if [ "$mode" = "go" ]; then say "Post-apply for '$stage', FOR REAL: $steps"; flag="-Execute"
    else say "Post-apply for '$stage', DRY RUN (changes nothing): $steps"; flag=""; fi
    pwsh -NoProfile -NonInteractive -Command "
      \$global:ConfirmPreference = 'None'
      Connect-MgGraph -TenantId '$tid' -Scopes ('$GRAPH_SCOPES' -split ',') -NoWelcome
      & ./lab/scripts/powershell/post-apply/Invoke-PostApply.ps1 -OutputsPath '$OUTPUTS' -Only $steps $extra $flag" ;;

  approve|deny)
    # The apply waits on an "Approve: apply <sha> to prod" issue
    # (.github/scripts/apply-approval-gate.sh).
    mode="${1:-}"
    n=$(gh issue list -R "$REPO_SLUG" --state open --search 'in:title "Approve: apply"' --json number -q '.[0].number')
    [ -n "$n" ] || die "no apply is waiting for a decision (has the merge's apply run started? try 'turn watch')"
    title=$(gh issue view "$n" -R "$REPO_SLUG" --json title -q .title)
    if [ "$mode" = "go" ]; then
      say "Commenting '$cmd' on: $title"
      gh issue comment "$n" -R "$REPO_SLUG" --body "$cmd" >/dev/null || die "could not comment"
      if [ "$cmd" = "approve" ]; then echo "  approved: the apply starts within 15 seconds ('turn.sh watch' to follow it)"
      else echo "  denied: the apply is cancelled within 15 seconds"; fi
    else
      say "Opening the waiting approval: $title"
      echo "  Read it, then comment '$cmd' (or run 'turn.sh $cmd go')."
      open "https://github.com/$REPO_SLUG/issues/$n"
    fi ;;

  graduate)
    # One Conditional Access policy from report-only to On, as its own PR:
    # the lab.tfvars line, plus the mocked test's list of graduated policies
    # (run plan_lab_tfvars pins every other policy to report-only).
    ca="${1:?usage: turn.sh graduate <CA001..CA060> [go]}"; mode="${2:-}"
    printf '%s' "$ca" | grep -Eq '^CA[0-9]{3}$' || die "policy keys look like CA003"
    [ "$ca" != "CA021" ] || die "CA021 graduates in its own four-PR sequence: run sheet 08"
    git fetch -q origin main
    branch="graduate/$(printf '%s' "$ca" | tr '[:upper:]' '[:lower:]')-$(date -u +%Y%m%dT%H%M%SZ)"
    wt=$(mktemp -d "${TMPDIR:-/tmp}/turn-graduate.XXXXXX")
    git worktree add -q -b "$branch" "$wt" origin/main
    cleanup_wt() { git worktree remove --force "$wt" >/dev/null 2>&1 || true; [ "$mode" = "go" ] || git branch -D "$branch" >/dev/null 2>&1 || true; }
    trap cleanup_wt EXIT
    say "Graduating $ca: report-only -> On"
    python3 - "$wt/$DEV_DIR/lab.tfvars" "$wt/$DEV_DIR/tests/mock_plan.tftest.hcl" "$ca" <<'PY' || die "edit failed"
import re, sys
tfvars, test, ca = sys.argv[1:4]
s = open(tfvars).read()
s2, n = re.subn(r'^(\s*' + ca + r'\s*=\s*)"enabledForReportingButNotEnforced"', r'\1"enabled"', s, count=1, flags=re.M)
if n != 1:
    sys.exit(f"{ca} is not report-only in lab.tfvars (already On, or not a key)")
open(tfvars, 'w').write(s2)
t = open(test).read()
first = 'condition     = alltrue([for k, v in var.ca_policy_states : v == "enabledForReportingButNotEnforced"])'
if first in t:
    t = t.replace(first, f'condition     = alltrue([for k, v in var.ca_policy_states : v == (contains(["{ca}"], k) ? "enabled" : "enabledForReportingButNotEnforced")])', 1)
    t = t.replace('error_message = "Day 1: every CA policy in lab.tfvars is report-only; graduation is a later PR with its checklist"',
                  'error_message = "every CA policy in lab.tfvars is report-only except the graduated list; one graduation per PR, with its checklist"', 1)
else:
    m = re.search(r'contains\(\[([^\]]*)\], k\) \? "enabled"', t)
    if not m:
        sys.exit("could not find the graduated list in run plan_lab_tfvars")
    keys = [k.strip() for k in m.group(1).split(',') if k.strip()]
    keys.append(f'"{ca}"')
    t = t[:m.start(1)] + ', '.join(keys) + t[m.end(1):]
open(test, 'w').write(t)
print(f"  lab.tfvars: {ca} -> \"enabled\"; test: {ca} added to the graduated list")
PY
    # The shorter "enabled" value shifts the trailing comment column, and CI
    # runs terraform fmt -check: format the two edited files as CI would see them.
    ( cd "$wt/$DEV_DIR" && "$TF" fmt lab.tfvars tests/mock_plan.tftest.hcl >/dev/null )
    ( cd "$wt" && git --no-pager diff --stat )
    say "Mocked test, as CI runs it"
    rc=0; ( cd "$wt/$DEV_DIR" && "$TF" init -backend=false -input=false >/dev/null && "$TF" test -var-file=lab.tfvars -no-color ) > "$wt/.test.log" 2>&1 || rc=$?
    grep -E "Success!|Failure!|Error:" "$wt/.test.log" | tail -5 || true
    [ "$rc" -eq 0 ] || { cp "$wt/.test.log" "${TMPDIR:-/tmp}/turn-graduate-$ca.log"; die "test failed; log: ${TMPDIR:-/tmp}/turn-graduate-$ca.log"; }
    if [ "$mode" != "go" ]; then echo "  PREVIEW only. 'turn.sh graduate $ca go' opens the PR."; exit 0; fi
    ( cd "$wt" && git add "$DEV_DIR/lab.tfvars" "$DEV_DIR/tests/mock_plan.tftest.hcl" \
      && git commit -q -m "ca: graduate $ca (report-only -> enabled)" && git push -q -u origin "$branch" )
    url=$(gh pr create -R "$REPO_SLUG" --base main --head "$branch" --title "$ca: report-only to enabled" --body "Graduates **$ca** from report-only to enabled (one policy per PR).

Before merging, fill in from the report-only data (totals only, no names): days in report-only, sign-ins it would have blocked, each one's disposition, and the rollback (a revert PR). Checklist: \`lab/docs/runbooks/ca-change-review-checklist.md\`.

The plan comment must show exactly one change: $ca's \`state\`." | grep -oE "https://github.com/[^ ]+/pull/[0-9]+" | tail -1)
    [ -n "$url" ] || die "no PR URL came back"
    echo "$url"; open "$url" ;;

  au-rule)
    # Day 2's one manual step: the help-desk admin unit's dynamic membership
    # rule, rendered by Terraform (output pim_workforce_au_membership_body).
    mode="${1:-}"
    [ -s "$OUTPUTS" ] || die "run 'turn.sh outputs' first"
    au=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pim_workforce_au_object_id']['value'] or '')" "$OUTPUTS")
    body=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pim_workforce_au_membership_body']['value'] or '')" "$OUTPUTS")
    [ -n "$au" ] && [ -n "$body" ] || die "no admin unit in the outputs (is day2 applied?)"
    say "Help-desk admin unit membership rule"
    python3 -c "import json,sys; b=json.loads(sys.argv[1]); print('  rule:', b.get('membershipRule')); print('  type:', b.get('membershipType'), '| processing:', b.get('membershipRuleProcessingState'))" "$body"
    if [ "$mode" = "go" ]; then
      az rest --method PATCH --url "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$au" \
        --headers Content-Type=application/json --body "$body" -o none && echo "  applied"
    else echo "  DRY RUN: nothing changed. Run 'turn.sh au-rule go' to apply."; fi ;;

  open)
    page="${1:?usage: turn.sh open <page>}"
    url=$(page_url "$page") || die "unknown page '$page'"
    say "Opening $page"; open "$url" ;;

  help|*)
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
