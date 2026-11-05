#!/usr/bin/env bash
# =============================================================================
# kill-switch.sh - turn the lab operator OFF in Azure AND AWS, one command
# -----------------------------------------------------------------------------
# Run as the HUMAN admin (your own `az login`, not `op`). Disables the
# operator's service principal: Entra stops issuing it tokens, so it can no
# longer sign in to Azure, and - because AWS only trusts Entra tokens for this
# subject - it can no longer start AWS sessions either. Tokens already issued
# expire within about an hour.
#   kill-switch.sh          disable
#   kill-switch.sh --undo   enable again
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"
op_load_config
unset AZURE_CONFIG_DIR   # the admin's own az profile, never the operator's

enabled=false
[ "${1:-}" = "--undo" ] && enabled=true
az ad sp update --id "$OP_OBJECT_ID" --set accountEnabled="$enabled" --only-show-errors
echo "Lab operator service principal $OP_OBJECT_ID: accountEnabled=$(az ad sp show --id "$OP_OBJECT_ID" --query accountEnabled -o tsv)"
