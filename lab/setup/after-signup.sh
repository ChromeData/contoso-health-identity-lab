#!/usr/bin/env bash
# =============================================================================
# after-signup.sh — everything after the six sign-ups, from one file.
# -----------------------------------------------------------------------------
# Reads lab/setup/handback.env and does, in order, the human steps that
# lab/terraform/README.md and lab/pipelines/README.md §5 describe:
#
#   A  Azure sign-in (device code: you approve once in a browser), resource
#      providers, the versioned state account, both state containers
#   B  envs/bootstrap: CI identities (PLAN / APPLY), their Graph roles and RBAC;
#      admin consent for both apps; seed the envs/dev state; lock the account
#   C  GitHub: repository variables, the two privacy secrets (+ Dependabot
#      mirror), the `prod` environment with you as required reviewer and
#      `main` as the only deployment branch
#   D  Local tfvars for envs/dev, okta/, aws/ written from handback.env
#   E  Okta root (if OKTA_API_TOKEN is exported): Clinic-Staff, the legacy app
#   F  AWS: `aws sso login` and the Identity Center root, only once SCIM has
#      created the group (printed as a next step otherwise)
#
# Dry run by default: prints every command and changes nothing. --yes applies.
# Idempotent: safe to re-run; each step checks before it creates.
# Nothing here reads or stores a password, token or key.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ENV_FILE="$HERE/handback.env"
YES=0; ONLY=""
for a in "$@"; do
  case "$a" in
    --yes) YES=1 ;;
    --only=*) ONLY="${a#--only=}" ;;
    -h|--help) sed -n 2,22p "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

# ---- helpers ------------------------------------------------------------------
say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
run()  { if [ "$YES" = 1 ]; then printf '   $ %s\n' "$*"; "$@"; else printf '   (dry) %s\n' "$*"; fi; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }
step_on() { [ -z "$ONLY" ] || [[ ",$ONLY," == *",$1,"* ]]; }

[ -f "$ENV_FILE" ] || { echo "No $ENV_FILE. cp handback.env.example handback.env and fill it in." >&2; exit 1; }
set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a
for v in ONMICROSOFT_DOMAIN ADMIN_UPN LAB_SUFFIX AZURE_SUBSCRIPTION_ID AZURE_LOCATION GITHUB_OWNER GITHUB_REPO OPERATOR_IP ALERT_EMAIL; do
  [ -n "${!v:-}" ] || { echo "handback.env: $v is empty" >&2; exit 1; }
done
[[ "$LAB_SUFFIX" =~ ^[a-z0-9]{3,6}$ ]] || { echo "LAB_SUFFIX must be 3-6 lowercase letters/digits" >&2; exit 1; }

need az "brew install azure-cli"; need gh "brew install gh"; need jq "brew install jq"
TF="${TERRAFORM_BIN:-$(command -v terraform || true)}"
[ -n "$TF" ] || [ ! -x "$HOME/.local/bin/terraform" ] || TF="$HOME/.local/bin/terraform"
# macOS: the Okta API token lives in the Keychain (item contoso-lab-okta-token) when not exported.
if [ -z "${OKTA_API_TOKEN:-}" ] && command -v security >/dev/null 2>&1; then
  OKTA_API_TOKEN="$(security find-generic-password -s contoso-lab-okta-token -w 2>/dev/null || true)"; export OKTA_API_TOKEN
fi
[ -n "$TF" ] || { echo "terraform 1.16.5 not found: brew install hashicorp/tap/terraform, or set TERRAFORM_BIN" >&2; exit 1; }

STATE_RG="rg-identity-lab-tfstate"
STATE_SA="stidlabtfstate${LAB_SUFFIX}"
KV_NAME="kv-idlab-${LAB_SUFFIX}"
EVIDENCE_SA="stidlabevidence${LAB_SUFFIX}"
[ "$YES" = 1 ] || say "DRY RUN: nothing below is executed. Re-run with --yes to apply."

# =============================================================================
if step_on A; then
say "A. Azure sign-in and the state account"
if ! az account show --query tenantId -o tsv >/dev/null 2>&1; then
  note "A browser window will ask you to approve this sign-in as $ADMIN_UPN."
  run az login --use-device-code --tenant "${ONMICROSOFT_DOMAIN}" --allow-no-subscriptions -o none
fi
if [ "$YES" = 1 ]; then
  az account set --subscription "$AZURE_SUBSCRIPTION_ID"
  TENANT_ID="$(az account show --query tenantId -o tsv)"
  ADMIN_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv)"
  note "tenant $TENANT_ID · admin object id $ADMIN_OBJECT_ID"
else
  TENANT_ID="<tenant id, read after login>"; ADMIN_OBJECT_ID="<admin object id, read after login>"
fi

note "Resource providers (once; the read-only PLAN identity cannot register them)"
for rp in Microsoft.KeyVault Microsoft.Network Microsoft.Compute Microsoft.ManagedIdentity \
          Microsoft.OperationalInsights Microsoft.OperationsManagement Microsoft.SecurityInsights \
          Microsoft.Insights Microsoft.DevTestLab Microsoft.Logic Microsoft.Web \
          Microsoft.CognitiveServices Microsoft.Storage; do
  run az provider register -n "$rp" -o none
done

note "Versioned state storage account (lab/terraform/README.md, Remote-state bootstrap)"
if [ "$YES" = 1 ] && az group show -n "$STATE_RG" >/dev/null 2>&1; then note "resource group exists"; else run az group create -n "$STATE_RG" -l "$AZURE_LOCATION" -o none; fi
if [ "$YES" = 1 ] && az storage account show -n "$STATE_SA" -g "$STATE_RG" >/dev/null 2>&1; then note "storage account exists"; else
  run az storage account create -n "$STATE_SA" -g "$STATE_RG" -l "$AZURE_LOCATION" \
    --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 \
    --allow-blob-public-access false --allow-shared-key-access false -o none
  run az storage account blob-service-properties update --account-name "$STATE_SA" -g "$STATE_RG" \
    --enable-versioning true --enable-delete-retention true --delete-retention-days 30 \
    --enable-container-delete-retention true --container-delete-retention-days 30 --enable-change-feed true -o none
fi
if [ "$YES" = 1 ]; then
  SA_ID="$(az storage account show -n "$STATE_SA" -g "$STATE_RG" --query id -o tsv)"
  run az role assignment create --role "Storage Blob Data Contributor" --assignee-object-id "$ADMIN_OBJECT_ID" \
    --assignee-principal-type User --scope "$SA_ID" -o none || true
  note "waiting 90 s for the data-plane role to propagate"; sleep 90
else
  note "(dry) az role assignment create --role 'Storage Blob Data Contributor' --assignee-object-id <you> --scope <state account>"
fi
for c in tfstate tfstate-bootstrap; do
  run az storage container create --account-name "$STATE_SA" -n "$c" --auth-mode login -o none
done
fi

# =============================================================================
# When A or B is skipped (--only), later steps still need these; A and B overwrite them.
TENANT_ID="<tenant id, read after login>"; ADMIN_OBJECT_ID="<admin object id, read after login>"
if [ "$YES" = 1 ] && az account show >/dev/null 2>&1; then
  TENANT_ID="$(az account show --query tenantId -o tsv)"; ADMIN_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv)"
fi
BOOT="$ROOT/lab/terraform/envs/bootstrap"
PLAN_CLIENT_ID="<plan client id>"; APPLY_CLIENT_ID="<apply client id>"; IAC_IDS='[]'
if [ "$YES" = 1 ] && "$TF" -chdir="$BOOT" output -raw github_oidc_plan_client_id >/dev/null 2>&1; then
  PLAN_CLIENT_ID="$("$TF" -chdir="$BOOT" output -raw github_oidc_plan_client_id 2>/dev/null || echo "$PLAN_CLIENT_ID")"
  APPLY_CLIENT_ID="$("$TF" -chdir="$BOOT" output -raw github_oidc_apply_client_id 2>/dev/null || echo "$APPLY_CLIENT_ID")"
  IAC_IDS="$("$TF" -chdir="$BOOT" output -json iac_principal_ids 2>/dev/null || echo "$IAC_IDS")"
fi
if step_on B; then
say "B. envs/bootstrap: the pipeline's identities, consent, state seed, lock"
need gh "brew install gh"
if [ "$YES" = 1 ]; then
  read -r OWNER_ID REPO_ID < <(gh api "repos/$GITHUB_OWNER/$GITHUB_REPO" --jq '[.owner.id, .id] | @tsv')
else OWNER_ID="<owner id>"; REPO_ID="<repo id>"; fi
BOOT="$ROOT/lab/terraform/envs/bootstrap"
# Knobs a re-run must NOT reset: an empty log_analytics_workspace_id DELETES the
# tenant's Entra log export (evidence row E07), and the two flags are deliberate
# widenings. Order: env var, then the existing file, then a lookup / off.
prev_knob() {
  [ -f "$BOOT/terraform.tfvars" ] || return 0
  sed -nE -e "s/^$1 *= *\"([^\"]*)\".*/\1/p" -e "s/^$1 *= *([a-z0-9]+).*/\1/p" "$BOOT/terraform.tfvars" | head -1
}
LAW_ID="${LOG_ANALYTICS_WORKSPACE_ID:-$(prev_knob log_analytics_workspace_id)}"
if [ -z "$LAW_ID" ] && [ "$YES" = 1 ]; then
  LAW_ID=$(az monitor log-analytics workspace show -g rg-identity-lab -n loga-idlab --query id -o tsv 2>/dev/null || true)
fi
APP_ROLES="${ENABLE_APP_MANAGEMENT_ROLES:-$(prev_knob enable_app_management_roles)}"; APP_ROLES="${APP_ROLES:-false}"
IDP_LOGS="${ENABLE_IDENTITY_PROTECTION_LOGS:-$(prev_knob enable_identity_protection_logs)}"; IDP_LOGS="${IDP_LOGS:-false}"
note "workspace for the Entra log export: ${LAW_ID:-<none yet: first run, envs/dev not applied>}; app-management roles: $APP_ROLES; Identity Protection logs: $IDP_LOGS"
note "writing $BOOT/terraform.tfvars (gitignored)"
if [ "$YES" = 1 ]; then cat > "$BOOT/terraform.tfvars" <<EOF
subscription_id              = "$AZURE_SUBSCRIPTION_ID"
tenant_id                    = "$TENANT_ID"
github_owner                 = "$GITHUB_OWNER"
github_repo                  = "$GITHUB_REPO"
github_owner_id              = "$OWNER_ID"
github_repo_id               = "$REPO_ID"
prod_environment_name        = "prod"
tfstate_resource_group_name  = "$STATE_RG"
tfstate_storage_account_name = "$STATE_SA"
tfstate_container_name       = "tfstate"
azure_openai_resource_id     = "${AZURE_OPENAI_RESOURCE_ID:-}"
log_analytics_workspace_id   = "$LAW_ID"
enable_app_management_roles     = $APP_ROLES
enable_identity_protection_logs = $IDP_LOGS
enable_pipeline_config_vault    = true
pipeline_config_vault_name      = "${PIPELINE_CONFIG_VAULT:-kv-idlab-cicd-${STATE_SA: -4}}"
EOF
fi
# The lock blocks the role assignments bootstrap creates: lift it around the apply.
run az lock delete -n lock-tfstate-readonly -g "$STATE_RG" --resource "$STATE_SA" --resource-type Microsoft.Storage/storageAccounts -o none || true
run "$TF" -chdir="$BOOT" init -input=false -backend-config="storage_account_name=$STATE_SA" -backend-config="resource_group_name=$STATE_RG"
run "$TF" -chdir="$BOOT" apply -input=false -auto-approve
if [ "$YES" = 1 ]; then
  PLAN_CLIENT_ID="$("$TF" -chdir="$BOOT" output -raw github_oidc_plan_client_id)"
  APPLY_CLIENT_ID="$("$TF" -chdir="$BOOT" output -raw github_oidc_apply_client_id)"
  IAC_IDS="$("$TF" -chdir="$BOOT" output -json iac_principal_ids)"
else PLAN_CLIENT_ID="<plan client id>"; APPLY_CLIENT_ID="<apply client id>"; IAC_IDS='[]'; fi
note "Admin consent for both apps (the portal click, done from the CLI)"
for app in "$PLAN_CLIENT_ID" "$APPLY_CLIENT_ID"; do run az ad app permission admin-consent --id "$app" -o none; done
note "Seeding the envs/dev state blob as you (the PLAN identity cannot create it)"
run "$TF" -chdir="$ROOT/lab/terraform/envs/dev" init -input=false -backend-config="resource_group_name=$STATE_RG" -backend-config="storage_account_name=$STATE_SA"
note "ReadOnly lock on the state account (README: why)"
run az lock create -n lock-tfstate-readonly --lock-type ReadOnly -g "$STATE_RG" --resource "$STATE_SA" --resource-type Microsoft.Storage/storageAccounts -o none
fi

# =============================================================================
if step_on C; then
say "C. GitHub: variables, the prod environment; privacy values to Key Vault"
R="$GITHUB_OWNER/$GITHUB_REPO"
setvar() { run gh variable set "$1" --repo "$R" --body "$2"; }
# The five privacy values go to the pipeline config vault (envs/bootstrap
# pipeline-config.tf), not to GitHub secrets: the workflows read them over
# OIDC (.github/scripts/pipeline-config.sh). The value travels on stdin to
# `az --file`, never in argv; a dry run prints the name only.
CFG_VAULT="$("$TF" -chdir="$ROOT/lab/terraform/envs/bootstrap" output -raw pipeline_config_vault_name 2>/dev/null || echo "<pipeline_config_vault_name>")"
setcfg() {
  if [ "$YES" = 1 ]; then
    printf '%s' "$2" | az keyvault secret set --vault-name "$CFG_VAULT" --name "$1" --file /dev/stdin -o none
    printf '   $ (Key Vault %s) %s = <value>\n' "$CFG_VAULT" "$1"
  else printf '   (dry) Key Vault %s: %s = <value>\n' "$CFG_VAULT" "$1"; fi
}
setvar TF_PIPELINE_CONFIG_VAULT "$CFG_VAULT"
setvar AZURE_TENANT_ID "$TENANT_ID"
setvar AZURE_SUBSCRIPTION_ID "$AZURE_SUBSCRIPTION_ID"
setvar TFSTATE_RG "$STATE_RG"; setvar TFSTATE_STORAGE_ACCOUNT "$STATE_SA"
setvar AZURE_PLAN_CLIENT_ID "$PLAN_CLIENT_ID"
setvar AZURE_APPLY_CLIENT_ID "$APPLY_CLIENT_ID"
setvar TF_ONMICROSOFT_DOMAIN "$ONMICROSOFT_DOMAIN"
setvar TF_KEY_VAULT_NAME "$KV_NAME"
setvar TF_EVIDENCE_STORAGE_ACCOUNT_NAME "$EVIDENCE_SA"
setvar TF_PIM_APPROVER_OBJECT_IDS "[\"$ADMIN_OBJECT_ID\"]"
setvar TF_KV_SECRETS_OFFICER_IDS "[\"$ADMIN_OBJECT_ID\"]"
setvar TF_INTUNE_VM_ADMIN_LOGIN_OBJECT_IDS "[\"$ADMIN_OBJECT_ID\"]"
setvar TF_IAC_PRINCIPAL_IDS "$IAC_IDS"
[ -n "${SERVICENOW_INSTANCE_URL:-}" ] && setvar TF_SERVICENOW_INSTANCE_URL "$SERVICENOW_INSTANCE_URL"
[ -n "${OKTA_ORG_NAME:-}" ] && setvar TF_OKTA_ORG_DOMAIN "${OKTA_ORG_NAME}.${OKTA_BASE_URL:-okta.com}"
if [ -n "${AZURE_OPENAI_ENDPOINT:-}" ]; then
  setvar AZURE_OPENAI_ENDPOINT "$AZURE_OPENAI_ENDPOINT"; setvar AZURE_OPENAI_DEPLOYMENT "${AZURE_OPENAI_DEPLOYMENT:-gpt-5-mini}"
  setvar AZURE_OPENAI_MAX_COMPLETION_TOKENS "${AZURE_OPENAI_MAX_COMPLETION_TOKENS:-12000}"; setvar AZURE_OPENAI_REASONING_EFFORT "${AZURE_OPENAI_REASONING_EFFORT:-low}"
fi
setcfg tf-operator-ip-ranges "[\"${OPERATOR_IP}/32\"]"
setcfg tf-alert-email "$ALERT_EMAIL"
setcfg tf-saml-cert-notification-emails "[\"$ALERT_EMAIL\"]"
setcfg tf-pim-alert-mailbox "${PIM_ALERT_MAILBOX:-security@$ONMICROSOFT_DOMAIN}"   # an alias on the admin mailbox (Exchange admin > mailbox > Manage email address types)
setcfg tf-app-owner-object-ids "[\"$ADMIN_OBJECT_ID\"]"
note "prod environment: you as required reviewer, main as the only deployment branch"
if [ "$YES" = 1 ]; then
  ME_ID="$(gh api user --jq .id)"
  gh api -X PUT "repos/$R/environments/prod" --input - >/dev/null <<EOF
{"reviewers":[{"type":"User","id":$ME_ID}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
EOF
  gh api -X POST "repos/$R/environments/prod/deployment-branch-policies" -f name=main -f type=branch >/dev/null 2>&1 || true
  note "prod environment configured"
else
  note "(dry) gh api -X PUT repos/$R/environments/prod  (reviewer = you; custom branch policy = main)"
fi
fi

# =============================================================================
if step_on D; then
say "D. Local tfvars (gitignored) for envs/dev, okta/, aws/"
DEV="$ROOT/lab/terraform/envs/dev"
# These files collect hand-added values over the lab's life (e.g. the AWS SAML
# metadata). Regenerating them from the .example would silently drop those, so
# an existing file is kept unless REWRITE_TFVARS=1.
if [ "$YES" = 1 ] && [ -f "$DEV/terraform.tfvars" ] && [ "${REWRITE_TFVARS:-0}" != 1 ]; then
  note "kept the existing envs/dev, okta/ and aws/ terraform.tfvars (REWRITE_TFVARS=1 regenerates them from the .example files)"
elif [ "$YES" = 1 ]; then
  sed -e "s|^subscription_id = .*|subscription_id = \"$AZURE_SUBSCRIPTION_ID\"|" \
      -e "s|^tenant_id       = .*|tenant_id       = \"$TENANT_ID\"|" \
      -e "s|^location        = .*|location        = \"$AZURE_LOCATION\"|" \
      -e "s|^key_vault_name = .*|key_vault_name = \"$KV_NAME\"|" \
      -e "s|^operator_ip_ranges = .*|operator_ip_ranges = [\"${OPERATOR_IP}/32\"]|" \
      -e "s|^key_vault_secrets_officer_ids = .*|key_vault_secrets_officer_ids = [\"$ADMIN_OBJECT_ID\"]|" \
      -e "s|^alert_email = .*|alert_email = \"$ALERT_EMAIL\"|" \
      -e "s|^onmicrosoft_domain = .*|onmicrosoft_domain = \"$ONMICROSOFT_DOMAIN\"|" \
      -e "s|^pim_approver_object_ids = .*|pim_approver_object_ids = [\"$ADMIN_OBJECT_ID\"]|" \
      -e "s|^app_owner_object_ids = .*|app_owner_object_ids = [\"$ADMIN_OBJECT_ID\"]|" \
      -e "s|^servicenow_instance_url = .*|servicenow_instance_url = \"${SERVICENOW_INSTANCE_URL:-}\"|" \
      -e "s|^okta_org_domain = .*|okta_org_domain = \"${OKTA_ORG_NAME:+${OKTA_ORG_NAME}.${OKTA_BASE_URL:-okta.com}}\"|" \
      -e "s|^iac_principal_ids = .*|iac_principal_ids = $IAC_IDS|" \
      -e "s|^evidence_storage_account_name = .*|evidence_storage_account_name = \"$EVIDENCE_SA\"|" \
      -e "s|^intune_vm_admin_login_object_ids = .*|intune_vm_admin_login_object_ids = [\"$ADMIN_OBJECT_ID\"]|" \
      "$DEV/terraform.tfvars.example" > "$DEV/terraform.tfvars"
  note "wrote $DEV/terraform.tfvars"
  if [ -n "${OKTA_ORG_NAME:-}" ]; then
    sed -e "s|^okta_org_name = .*|okta_org_name = \"$OKTA_ORG_NAME\"|" \
        -e "s|^okta_base_url = .*|okta_base_url = \"${OKTA_BASE_URL:-okta.com}\"|" \
        -e "s|^clinic_login_domain = .*|clinic_login_domain = \"${CLINIC_LOGIN_DOMAIN:-clinic.contoso.example}\"|" \
        -e "s|^entra_tenant_id         = .*|entra_tenant_id         = \"$TENANT_ID\"|" \
        "$ROOT/lab/terraform/okta/terraform.tfvars.example" > "$ROOT/lab/terraform/okta/terraform.tfvars"
    note "wrote lab/terraform/okta/terraform.tfvars"
  fi
  if [ -n "${AWS_ACCOUNT_ID:-}" ]; then
    sed -e "s|^aws_profile = .*|aws_profile = \"${AWS_PROFILE:-idlab-admin}\"|" \
        -e "s|^aws_region = .*|aws_region = \"${AWS_REGION:-us-east-1}\"|" \
        -e "s|^allowed_account_ids = .*|allowed_account_ids = [\"$AWS_ACCOUNT_ID\"]|" \
        "$ROOT/lab/terraform/aws/terraform.tfvars.example" > "$ROOT/lab/terraform/aws/terraform.tfvars"
    note "wrote lab/terraform/aws/terraform.tfvars"
  fi
else
  note "(dry) envs/dev/terraform.tfvars, okta/terraform.tfvars, aws/terraform.tfvars from the .example files"
fi
fi

# =============================================================================
if step_on E; then
say "E. Okta root (Clinic-Staff, the legacy app; federation stays off until the Entra app exists)"
if [ -n "${OKTA_API_TOKEN:-}" ] && [ -n "${OKTA_ORG_NAME:-}" ]; then
  run "$TF" -chdir="$ROOT/lab/terraform/okta" init -input=false
  run "$TF" -chdir="$ROOT/lab/terraform/okta" apply -input=false -auto-approve
else
  note "skipped: export OKTA_API_TOKEN (Okta admin → Security → API → Tokens) and set OKTA_ORG_NAME"
fi
fi

# =============================================================================
if step_on F; then
say "F. AWS"
if [ -n "${AWS_ACCOUNT_ID:-}" ] && command -v aws >/dev/null 2>&1; then
  note "aws/ is applied AFTER SCIM has created App-AWS-IdentityCenter-Users in Identity Center (lab/terraform/aws/README.md)."
  note "When you reach that step:  aws sso login --profile ${AWS_PROFILE:-idlab-admin} && terraform -chdir=lab/terraform/aws init && terraform -chdir=lab/terraform/aws apply"
else
  note "skipped: AWS_ACCOUNT_ID not set, or the aws CLI is missing (brew install awscli)"
fi
fi

# =============================================================================
say "Next (the pipeline takes it from here)"
cat <<EOF
   1. Entra ID Governance trial: https://admin.microsoft.com → Billing → Purchase services →
      "Step-Up for Microsoft Entra ID P2" → Start free trial  (a click Microsoft does not expose to the CLI)
   2. Open the first pull request (any change under lab/terraform) → the plan comment and Checkov run
      with the PLAN identity. Merge → approve the prod deployment → the first apply (free tier, no trial clock).
   3. Then follow lab/docs/evidence-capture-plan.md day by day: E01 onwards.
   Dry run: re-run with --yes to apply. Partial: --only=A,B,C  (steps A–F).
EOF
