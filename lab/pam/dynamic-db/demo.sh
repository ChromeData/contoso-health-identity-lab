#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031  # tokens are exported only inside ( ... ) subshells, on purpose
# =============================================================================
# dynamic-db/demo.sh - one person, one short-lived database login, end to end
# (after dynamic-db/setup.sh). Narration for camera; nothing secret printed.
#
#   1. OPERATOR asks Vault for clinical-readonly access -> a brand-new Postgres
#      login that did not exist a second ago (name carries the operator)
#   2. uses it: reads schema `clinical`; billing and writes are refused
#   3. shows the lease (TTL <= 1h, max 4h) and Postgres's own VALID UNTIL
#   4. security on-call revokes the lease (responder policy; a requester
#      cannot revoke single leases - they end their whole session)
#   5. the same username + password no longer log in; the role is gone
#   On exit the operator's Vault token is revoked, which revokes every lease
#   issued under it (the second credential used in step 5 included).
#
# Usage: dynamic-db/demo.sh [--operator NAME]   (default ops-alice)
# =============================================================================
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "$0")/lib.sh"   # cd's to lab/pam
need docker; need jq; need curl

OPERATOR=ops-alice
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator) OPERATOR="${2:?--operator NAME}"; shift 2 ;;
    -h|--help) awk 'NR > 2 && (!/^#/ || /^# shellcheck/) { exit } NR > 2' "$DYNDB_DIR/${0##*/}"; exit 0 ;;
    *) echo "usage: $0 [--operator NAME]" >&2; exit 2 ;;
  esac
done
[[ "$OPERATOR" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "--operator: lowercase letters, digits and dashes only"

[[ "$("${DC[@]}" ps vault --format '{{.State}}' 2>/dev/null)" == running ]] \
  || die "the $DYNDB_PROJECT stack is not running - run dynamic-db/setup.sh first"
dyndb_vault_unseal
( export VAULT_TOKEN; VAULT_TOKEN=$(root_token); dv read "database/roles/$DB_ROLE" >/dev/null 2>&1 ) \
  || die "database/roles/$DB_ROLE is missing - run dynamic-db/setup.sh first"

indent() { sed 's/^/      /'; }
first_error() { grep -m1 -E 'ERROR|FATAL' | sed -E 's/^.*(ERROR|FATAL): +/\1: /'; }

REQ_TOKEN=$(mint_requester_token "$OPERATOR")
[[ -n "$REQ_TOKEN" && "$REQ_TOKEN" != null ]] || die "could not mint the requester token"
RESP_TOKEN=""
end_session() {
  with_token REQ_TOKEN dv token revoke -self >/dev/null 2>&1 || true
  [[ -n "$RESP_TOKEN" ]] && { with_token RESP_TOKEN dv token revoke -self >/dev/null 2>&1 || true; }
}
trap end_session EXIT

log "0. $OPERATOR signs in to Vault (lab: token minted for them; tenant time: OIDC with Entra ID)"
printf '      policy: %s only, token TTL 1h\n' "$REQ_POLICY"

log "1. $OPERATOR requests clinical-readonly access"
CREDS=$(with_token REQ_TOKEN dv read -format=json "database/creds/$DB_ROLE")
U=$(printf '%s' "$CREDS" | jq -r '.data.username')
P=$(printf '%s' "$CREDS" | jq -j '.data.password')
LEASE=$(printf '%s' "$CREDS" | jq -r '.lease_id')
TTL=$(printf '%s' "$CREDS" | jq -r '.lease_duration')
CREDS=""
printf '      username: %s   (created just now by Vault)\n' "$U"
printf '      password: (not shown - held in this shell only)\n'
printf '      lease:    %s\n      ttl:      %ss\n' "$LEASE" "$TTL"

log "2. Use it from clinical-app (network login, SCRAM)"
printf '%s' "$P" | db_as "$U" \
  "SELECT 'logged in as ' || current_user || ', ' || count(*) || ' encounters readable' FROM clinical.encounters" | indent
out=$(printf '%s' "$P" | db_as "$U" 'SELECT count(*) FROM billing.claims' 2>&1) || true
printf '      other schema (billing): %s\n' "$(printf '%s\n' "$out" | first_error)"
out=$(printf '%s' "$P" | db_as "$U" "INSERT INTO clinical.patients VALUES ('CH-999999', 'x', 2000, 'x')" 2>&1) || true
printf '      write (INSERT):         %s\n' "$(printf '%s\n' "$out" | first_error)"

log "3. The lease, as Vault and as Postgres see it"
with_token REQ_TOKEN dv lease lookup -format=json "$LEASE" \
  | jq -r '.data | "issued:  \(.issue_time)\nexpires: \(.expire_time)\nttl:     \(.ttl)s (role max 4h)"' | indent
printf '%s' "$P" | db_as "$U" \
  "SELECT 'Postgres VALID UNTIL: ' || rolvaliduntil || ' (backstop if Vault were down)' FROM pg_roles WHERE rolname = current_user" | indent

log "4. Security on-call revokes the lease (incident response; policy $RESP_POLICY)"
printf '      (%s cannot revoke a single lease: Vault cannot limit that right to\n' "$OPERATOR"
printf '       their own leases. They end their whole session instead - step 6.)\n'
RESP_TOKEN=$(mint_responder_token sec-oncall)
[[ -n "$RESP_TOKEN" && "$RESP_TOKEN" != null ]] || die "could not mint the responder token"
with_token RESP_TOKEN dv lease revoke -sync "$LEASE" | indent

log "5. The same username and password again"
if out=$(printf '%s' "$P" | db_as "$U" 'SELECT 1' 2>&1); then
  P=""
  die "the revoked credential still logs in"
fi
P=""
printf '      login: %s\n' "$(printf '%s\n' "$out" | first_error)"
# A second, separate credential checks the catalogue (pg_roles is readable by
# any login); it dies with the operator's token when this script exits.
CREDS2=$(with_token REQ_TOKEN dv read -format=json "database/creds/$DB_ROLE")
U2=$(printf '%s' "$CREDS2" | jq -r '.data.username')
gone=$(printf '%s' "$CREDS2" | jq -j '.data.password' \
  | db_as "$U2" "SELECT count(*) FROM pg_roles WHERE rolname = '$U'")
CREDS2=""
printf '      role %s in pg_roles: %s\n' "$U" "$( [[ "$gone" == 0 ]] && echo 'gone' || echo "STILL THERE ($gone)")"
[[ "$gone" == 0 ]] || die "revoked role still exists"

log "6. Done. Ending $OPERATOR's Vault session revokes every lease it still holds ($U2 included)."
