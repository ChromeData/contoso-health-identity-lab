#!/usr/bin/env bash
# =============================================================================
# aws-credentials.sh - AWS CLI credential_process for profile idlab-operator
# -----------------------------------------------------------------------------
# Asks Entra (as the signed-in operator) for a token to the operator itself,
# trades it with STS (AssumeRoleWithWebIdentity, an unsigned call) for a
# one-hour session on the operator role, and prints the credential_process
# JSON. The token reaches STS on stdin (--cli-input-json), never in argv.
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

# No profile, no config: this call must never recurse into this script.
printf '{"RoleArn":"%s","RoleSessionName":"lab-operator-%s","WebIdentityToken":"%s","DurationSeconds":3600}' \
  "$OP_AWS_ROLE_ARN" "$(date +%Y%m%dT%H%M%S)" "$token" |
  env -u AWS_PROFILE AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    aws sts assume-role-with-web-identity --region us-east-1 --cli-input-json file:///dev/stdin --output json |
  python3 -I -c 'import json,sys; c=json.load(sys.stdin)["Credentials"]; print(json.dumps({"Version":1,"AccessKeyId":c["AccessKeyId"],"SecretAccessKey":c["SecretAccessKey"],"SessionToken":c["SessionToken"],"Expiration":c["Expiration"]}))'
