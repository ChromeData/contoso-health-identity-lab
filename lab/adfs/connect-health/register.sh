#!/usr/bin/env bash
# =============================================================================
# lab/adfs/connect-health/register.sh - register the Connect Health agent on
# DC01 with no person at the server (ADR 0031). README step 5.
#
#   lab/adfs/connect-health/register.sh enroll     # once per window: passkey for the account
#   lab/adfs/connect-health/register.sh register   # token -> DC01 -> registered
#   lab/adfs/connect-health/register.sh close      # right after: disable the account, revoke sessions
#
# Needs: the PR that sets enable_connect_health_registration = true merged and
# applied (adm-connecthealth-reg exists and holds Hybrid Identity
# Administrator); DC01 running; the agent installed (step 5a,
# 12-Install-ConnectHealthAgent.ps1). Then open the PR that sets the flag back
# to false: its apply deletes the account and the role.
#
# Secrets: the passkey lives in the Keychain (contoso-lab-passkey-adm-connecthealth-reg);
# the access token goes Keychain -> protected run-command parameter and the
# Keychain item is deleted in a trap, whatever happens. Nothing is printed
# but non-secret claims.
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
OP="$repo/lab/scripts/operator/op"
UPN="adm-connecthealth-reg@contosohealthlab.onmicrosoft.com"
TOKEN_ITEM=contoso-lab-connecthealth-token

case "${1:-}" in
  enroll)
    # Operator issues a one-time TAP; the passkey is registered with it and
    # the pass deleted (passkey.mjs register: CA009's TAP door, as for adm-*).
    node "$here/../../scripts/demo/signin/passkey.mjs" register "$UPN"
    ;;
  register)
    trap 'security delete-generic-password -s "$TOKEN_ITEM" >/dev/null 2>&1 || true' EXIT
    node "$here/get-agent-token.mjs" "$UPN"
    "$OP" python3 "$repo/lab/scripts/dc/run-on-dc.py" "$repo/lab/adfs/scripts/12b-Register-ConnectHealthAgent.ps1" \
      --secret "AgentToken=keychain:$TOKEN_ITEM"
    ;;
  close)
    # Close the window at once, before the flag-off PR merges: no sign-in
    # possible, every refresh token revoked. (User.ReadWrite.All, operator.)
    id="$("$OP" az rest --method GET --url "https://graph.microsoft.com/v1.0/users/$UPN?\$select=id" --query id -o tsv)"
    [ -n "$id" ] || { echo "cannot read $UPN" >&2; exit 1; }
    printf '{"accountEnabled": false}' | "$OP" az rest --method PATCH --url "https://graph.microsoft.com/v1.0/users/$id" \
      --headers Content-Type=application/json --body @/dev/stdin >/dev/null
    "$OP" az rest --method POST --url "https://graph.microsoft.com/v1.0/users/$id/revokeSignInSessions" >/dev/null
    en="$("$OP" az rest --method GET --url "https://graph.microsoft.com/v1.0/users/$id?\$select=accountEnabled" --query accountEnabled -o tsv)"
    [ "$en" = false ] || { echo "read-back: $UPN is still enabled" >&2; exit 1; }
    echo "$UPN disabled and its sessions revoked. Now open the PR: enable_connect_health_registration = false."
    ;;
  *) echo "usage: register.sh enroll|register|close" >&2; exit 2 ;;
esac
