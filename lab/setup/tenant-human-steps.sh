#!/usr/bin/env bash
# Tenant-time steps a HUMAN runs (the pipeline must not hold these rights).
# Idempotent: safe to re-run. Each step prints what it did.
#   E05  Storage Blob Data Contributor on the evidence container, with the
#        no-delete ABAC condition (modules/evidence-store header).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEV="$ROOT/lab/terraform/envs/dev"
TF="${TERRAFORM_BIN:-$(command -v terraform || true)}"; [ -n "$TF" ] || TF="$HOME/.local/bin/terraform"
# shellcheck disable=SC1091
. "$ROOT/lab/setup/handback.env"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

say "E05. Operator write access on the evidence container (no-delete ABAC)"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
ME="$(az ad signed-in-user show --query id -o tsv)"
# terraform test / plan must not see the local terraform.tfvars; outputs do not need it.
SCOPE="$("$TF" -chdir="$DEV" output -raw evidence_container_id)"
COND="$("$TF" -chdir="$DEV" output -raw evidence_writer_abac_condition)"
if az role assignment list --assignee "$ME" --scope "$SCOPE" --query "[?roleDefinitionName=='Storage Blob Data Contributor'] | length(@)" -o tsv | grep -qv '^0$'; then
  echo "   already granted"
else
  az role assignment create --assignee-object-id "$ME" --assignee-principal-type User \
    --role "Storage Blob Data Contributor" --scope "$SCOPE" \
    --condition-version 2.0 --condition "$COND" -o none
  echo "   granted to $ME on $SCOPE (condition: delete denied in 'evidence')"
fi
echo; echo "Done."
