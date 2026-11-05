#!/usr/bin/env bash
# =============================================================================
# aws-credentials.sh - AWS CLI credential_process for profile idlab-operator
# -----------------------------------------------------------------------------
# Asks Entra (as the signed-in operator) for a token to the operator itself,
# trades it with STS (AssumeRoleWithWebIdentity, an unsigned call) for a
# one-hour session on the operator role, and prints the credential_process
# JSON. The token reaches STS through a mode-600 file, never in argv.
# The AWS CLI calls this again on its own when the hour is up.
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"
op_load_config
[ -n "${OP_AWS_ROLE_ARN:-}" ] || op_die "no OP_AWS_ROLE_ARN in $OP_HOME/config"

token="$(az account get-access-token --scope "api://$OP_CLIENT_ID/.default" --query accessToken -o tsv 2>/dev/null)" \
  || op_die "no Entra token - run lab-signin.sh"

# The token goes to STS from a mode-600 file (file:// parameter), never in
# argv, and is deleted right after. No profile, no config: this call must
# never recurse into this script.
umask 077
tok_file="$(mktemp "$OP_HOME/session/token.XXXXXX")"
trap 'rm -f "$tok_file"' EXIT
printf '%s' "$token" > "$tok_file"
unset token

env -u AWS_PROFILE AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  aws sts assume-role-with-web-identity --region us-east-1 \
    --role-arn "$OP_AWS_ROLE_ARN" --role-session-name "lab-operator-$(date +%Y%m%dT%H%M%S)" \
    --duration-seconds 3600 --web-identity-token "file://$tok_file" --output json |
  python3 -I -c 'import json,sys; c=json.load(sys.stdin)["Credentials"]; print(json.dumps({"Version":1,"AccessKeyId":c["AccessKeyId"],"SecretAccessKey":c["SecretAccessKey"],"SessionToken":c["SessionToken"],"Expiration":c["Expiration"]}))'
