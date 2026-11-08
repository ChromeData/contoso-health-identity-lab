#!/usr/bin/env bash
# =============================================================================
# pipeline-config.sh - read the pipeline's privacy values from Key Vault
# -----------------------------------------------------------------------------
# Used by terraform-plan.yml and terraform-apply.yml AFTER azure/login (GitHub
# OIDC, PLAN or APPLY app). Reads the five values from the pipeline config
# vault (envs/bootstrap pipeline-config.tf) and exports them to the later
# steps as TF_VAR_* through $GITHUB_ENV. Nothing is stored in GitHub.
#
#   PIPELINE_CONFIG_VAULT=kv-idlab-cicd-20f1 .github/scripts/pipeline-config.sh
#
# WHY each rule:
#   * FAIL CLOSED. A value that cannot be read stops the job. The old secrets
#     fell back to '[]' or '' when unset, so a missing value planned the
#     removal of a firewall rule, an app owner or a mailbox; a plan built on a
#     missing value is never what the reviewer meant.
#   * MASK FIRST. Each value is masked before it is written anywhere, and so
#     is each element of a JSON list: GitHub masks only whole strings, so a
#     list secret used to leave each email / id visible when printed alone.
#   * NO VALUE IN ARGV OR LOGS. Values travel in shell variables and files
#     only; errors name the secret, never its value. No `set -x`.
#   * $GITHUB_ENV with a random heredoc delimiter, so a value cannot inject a
#     second variable (GitHub docs, "Workflow commands", multiline strings).
# =============================================================================
set -euo pipefail

vault="${PIPELINE_CONFIG_VAULT:-}"
if [[ ! "$vault" =~ ^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$ ]]; then
  echo "::error::PIPELINE_CONFIG_VAULT is not a Key Vault name: set vars.TF_PIPELINE_CONFIG_VAULT (envs/bootstrap output pipeline_config_vault_name)."
  exit 1
fi
: "${GITHUB_ENV:?GITHUB_ENV is not set (run inside GitHub Actions or set it for a test)}"

# secret name | TF_VAR name | kind (list = JSON list of strings, string = one non-empty value)
config=(
  "tf-operator-ip-ranges|TF_VAR_operator_ip_ranges|list"
  "tf-alert-email|TF_VAR_alert_email|string"
  "tf-app-owner-object-ids|TF_VAR_app_owner_object_ids|list"
  "tf-saml-cert-notification-emails|TF_VAR_saml_cert_notification_emails|list"
  "tf-pim-alert-mailbox|TF_VAR_pim_alert_mailbox|string"
)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"

for row in "${config[@]}"; do
  IFS='|' read -r name tfvar kind <<<"$row"
  # stdout to a private file, stderr kept apart: az never prints the value on
  # an error, but a failed read must not be mistaken for an empty value.
  if ! az keyvault secret show --vault-name "$vault" --name "$name" --query value -o tsv >"$tmp/value" 2>"$tmp/err"; then
    reason="$(grep -oE '(SecretNotFound|Forbidden|ForbiddenByRbac|ForbiddenByFirewall|Unauthorized|NotFound)' "$tmp/err" | head -1 || true)"
    echo "::error::cannot read secret '$name' from vault '$vault' (${reason:-see az error}): stopping, no plan is made on a missing value."
    exit 1
  fi
  value="$(cat "$tmp/value")"
  if [ -z "$value" ]; then
    echo "::error::secret '$name' in vault '$vault' is empty: stopping."
    exit 1
  fi
  # One line only: none of the five is multi-line, and a newline is how a
  # value would try to smuggle a second variable into $GITHUB_ENV.
  if [ "$(printf '%s' "$value" | wc -l | tr -d ' ')" != 0 ]; then
    echo "::error::secret '$name' in vault '$vault' has more than one line: stopping."
    exit 1
  fi
  # "[]" (an empty list) is not private, and masking it would blank every
  # pair of brackets in the log.
  [ "$value" != "[]" ] && echo "::add-mask::$value"
  if [ "$kind" = "list" ]; then
    # Must be a JSON list of strings; mask each element on its own.
    if ! elements="$(printf '%s' "$value" | python3 -I -c 'import json,sys
v=json.load(sys.stdin)
assert isinstance(v,list) and all(isinstance(x,str) and x for x in v)
print("\n".join(v))' 2>/dev/null)"; then
      echo "::error::secret '$name' is not a JSON list of non-empty strings: stopping."
      exit 1
    fi
    while IFS= read -r el; do
      [ -n "$el" ] && echo "::add-mask::$el"
    done <<<"$elements"
  fi
  delim="EOF_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  {
    echo "${tfvar}<<${delim}"
    printf '%s\n' "$value"
    echo "$delim"
  } >>"$GITHUB_ENV"
  echo "read $name -> $tfvar"
done
