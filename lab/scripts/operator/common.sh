# shellcheck shell=bash disable=SC2034
# =============================================================================
# lab/scripts/operator/common.sh - shared settings for the lab operator scripts
# -----------------------------------------------------------------------------
# Everything the operator needs lives in ~/.contoso-operator (mode 700):
#   config            ids only (written by save-config.sh from Terraform outputs)
#   operator.crt      the PUBLIC certificate (uploaded to Entra by envs/operator)
#   azure/            a separate az CLI profile, so the operator's session
#                     never mixes with the admin's own `az login` in ~/.azure
#   session/          the private key, written from the Keychain for the length
#                     of a session (sign-out removes it)
# The private key's only lasting copy is the login Keychain item below.
# =============================================================================

OP_HOME="${CONTOSO_OPERATOR_HOME:-$HOME/.contoso-operator}"
OP_KEYCHAIN_SERVICE="contoso-lab-operator-key"
OP_PEM="$OP_HOME/session/operator.pem"
OP_AWS_PROFILE="idlab-operator"
OP_LAB_AWS_ACCOUNT="182002546409"
export AZURE_CONFIG_DIR="$OP_HOME/azure"

op_die() { echo "operator: $*" >&2; exit 1; }

op_load_config() {
  [ -f "$OP_HOME/config" ] || op_die "no $OP_HOME/config yet - run save-config.sh after the envs/operator apply"
  # shellcheck disable=SC1091
  . "$OP_HOME/config"
  for v in OP_TENANT_ID OP_SUBSCRIPTION_ID OP_CLIENT_ID OP_OBJECT_ID; do
    [ -n "${!v:-}" ] || op_die "$v missing from $OP_HOME/config"
  done
}
