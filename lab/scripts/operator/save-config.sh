#!/usr/bin/env bash
# =============================================================================
# save-config.sh - record the operator's ids in ~/.contoso-operator/config
# -----------------------------------------------------------------------------
# Reads the outputs of lab/terraform/envs/operator (and, once applied, the
# role ARN from lab/terraform/aws). Ids only - nothing secret.
#   save-config.sh <envs/operator dir> [<aws root dir>]
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"

az_dir="${1:?usage: save-config.sh <envs/operator dir> [<aws root dir>]}"
aws_dir="${2:-}"
tf="$(command -v tofu || command -v terraform)"

# Outputs are read with the caller's own az/aws sign-in (the state backends
# need it), never the operator's profile.
out() { env -u AZURE_CONFIG_DIR "$tf" -chdir="$1" output -raw "$2"; }
tenant_id="$(out "$az_dir" tenant_id)"
subscription_id="$(out "$az_dir" subscription_id)"
client_id="$(out "$az_dir" operator_client_id)"
object_id="$(out "$az_dir" operator_object_id)"
role_arn=""
if [ -n "$aws_dir" ]; then role_arn="$(out "$aws_dir" entra_operator_role_arn 2>/dev/null || true)"; fi

umask 077
mkdir -p "$OP_HOME"
cat > "$OP_HOME/config" <<CFG
# Written by lab/scripts/operator/save-config.sh - ids only, nothing secret.
OP_TENANT_ID=$tenant_id
OP_SUBSCRIPTION_ID=$subscription_id
OP_CLIENT_ID=$client_id
OP_OBJECT_ID=$object_id
OP_AWS_ROLE_ARN=$role_arn
CFG
echo "Saved $OP_HOME/config"
cat "$OP_HOME/config"
