#!/usr/bin/env bash
# =============================================================================
# lab-signin.sh - sign the lab operator in to Azure and AWS, no human needed
# -----------------------------------------------------------------------------
#   1. writes the private key from the Keychain into ~/.contoso-operator/session
#      (mode 600) next to the public certificate
#   2. `az login --service-principal` with that certificate, in the operator's
#      own az profile (AZURE_CONFIG_DIR=~/.contoso-operator/azure)
#   3. points the AWS CLI profile "idlab-operator" at aws-credentials.sh, which
#      trades an Entra token for a one-hour session in the lab AWS account
#   4. proves both: the Azure caller is the operator service principal in the
#      lab tenant, the AWS caller is the operator role in account 182002546409
# Safe to run any time; it is what `op` runs when the session has lapsed.
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"
op_load_config

[ -f "$OP_HOME/operator.crt" ] || op_die "no $OP_HOME/operator.crt - run new-operator-cert.sh"
left=$(( ($(date -j -f '%b %e %T %Y %Z' "$(openssl x509 -in "$OP_HOME/operator.crt" -noout -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))
[ "$left" -gt 0 ] || op_die "the operator certificate has expired - run new-operator-cert.sh and re-apply envs/operator"
[ "$left" -gt 14 ] || echo "operator: WARNING the certificate expires in $left days - rotate it (new-operator-cert.sh + envs/operator apply)" >&2

umask 077
mkdir -p "$OP_HOME/session" "$AZURE_CONFIG_DIR"
key_b64="$(security find-generic-password -s "$OP_KEYCHAIN_SERVICE" -w)" || op_die "Keychain item $OP_KEYCHAIN_SERVICE not found"
{ printf '%s' "$key_b64" | base64 -d; cat "$OP_HOME/operator.crt"; } > "$OP_PEM"
unset key_b64

az login --service-principal --username "$OP_CLIENT_ID" --certificate "$OP_PEM" \
  --tenant "$OP_TENANT_ID" --output none --only-show-errors
az account set --subscription "$OP_SUBSCRIPTION_ID"
who="$(az account show --query '[tenantId, user.type, user.name]' -o tsv | tr '\t' ' ')"
[ "$who" = "$OP_TENANT_ID servicePrincipal $OP_CLIENT_ID" ] || op_die "unexpected Azure caller: $who"
echo "Azure: signed in as the lab operator (app $OP_CLIENT_ID) in tenant $OP_TENANT_ID"

if [ -n "${OP_AWS_ROLE_ARN:-}" ]; then
  aws configure set credential_process "$here/aws-credentials.sh" --profile "$OP_AWS_PROFILE"
  aws configure set region us-east-1 --profile "$OP_AWS_PROFILE"
  acct="$(aws sts get-caller-identity --profile "$OP_AWS_PROFILE" --query Account --output text)"
  [ "$acct" = "$OP_LAB_AWS_ACCOUNT" ] || op_die "AWS account is $acct, not the lab account $OP_LAB_AWS_ACCOUNT"
  echo "AWS:   signed in as $(basename "$OP_AWS_ROLE_ARN") in the lab account $acct (profile $OP_AWS_PROFILE)"
else
  echo "AWS:   not set up yet (no OP_AWS_ROLE_ARN in $OP_HOME/config)"
fi
