#!/usr/bin/env bash
# =============================================================================
# turn.sh - short commands for building the lab yourself, on camera or not.
# Every command says in plain words what it is about to do, then does it.
# Nothing here holds a tenant id: ids come from the repo's GitHub variables.
#
#   turn.sh where              which stage the lab is at right now
#   turn.sh pr <stage>         preview, then open the PR that moves the lab to
#                              <stage>; the PR opens in your browser
#   turn.sh watch              follow the apply run on main until it finishes
#   turn.sh outputs            save the Terraform outputs the post-apply step
#                              reads (private, gitignored folder)
#   turn.sh post <stage>       the stage's post-apply steps, DRY RUN
#   turn.sh post <stage> go    the same, for real
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
GRAPH_SCOPES="AdministrativeUnit.ReadWrite.All,Application.Read.All,AuditLog.Read.All,EntitlementManagement.ReadWrite.All,Group.Read.All,GroupMember.Read.All,GroupMember.ReadWrite.All,LifecycleWorkflows.ReadWrite.All,Policy.Read.All,Policy.ReadWrite.ApplicationConfiguration,Policy.ReadWrite.AuthenticationMethod,Policy.ReadWrite.Authorization,Policy.ReadWrite.ConditionalAccess,Policy.ReadWrite.ConsentRequest,Policy.ReadWrite.PermissionGrant,PrivilegedAssignmentSchedule.Read.AzureADGroup,PrivilegedEligibilitySchedule.Read.AzureADGroup,PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup,RoleAssignmentSchedule.ReadWrite.Directory,RoleEligibilitySchedule.Read.Directory,RoleEligibilitySchedule.ReadWrite.Directory,RoleManagement.Read.Directory,RoleManagement.ReadWrite.Directory,RoleManagementPolicy.ReadWrite.Directory,User.Read.All,User.ReadWrite.All,UserAuthenticationMethod.Read.All"

# Post-apply steps per stage (names from Invoke-PostApply.ps1 -ListOnly).
post_steps() {
  case "$1" in
    day1) echo "baseline" ;;
    day2) echo "baseline,auth-methods,auth-context,directory-role-pim" ;;
    day3) echo "baseline,sod,app-governance,consent" ;;
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
      && "$TF" output -json ) > "$OUTPUTS"
    echo "saved ($(wc -c <"$OUTPUTS" | tr -d ' ') bytes)" ;;

  post)
    stage="${1:?usage: turn.sh post <stage> [go]}"; mode="${2:-}"
    steps=$(post_steps "$stage") || die "no post-apply steps for '$stage' (stages: day1, day2, day3)"
    [ -s "$OUTPUTS" ] || die "run 'turn.sh outputs' first"
    tid=$(ghvar AZURE_TENANT_ID)
    if [ "$mode" = "go" ]; then say "Post-apply for '$stage', FOR REAL: $steps"; flag="-Execute"
    else say "Post-apply for '$stage', DRY RUN (changes nothing): $steps"; flag=""; fi
    pwsh -NoProfile -NonInteractive -Command "
      \$global:ConfirmPreference = 'None'
      Connect-MgGraph -TenantId '$tid' -Scopes ('$GRAPH_SCOPES' -split ',') -NoWelcome
      & ./lab/scripts/powershell/post-apply/Invoke-PostApply.ps1 -OutputsPath '$OUTPUTS' -Only $steps $flag" ;;

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
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
