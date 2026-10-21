#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2030,SC2031  # constants are used by the sourcing scripts; tokens are scoped to subshells on purpose
# Shared helpers for dynamic-db/setup.sh, dynamic-db/demo.sh and
# test/e2e-dynamic-db.sh. Sourced, never executed.
#
# Secrets rule (same as ../lib.sh): a password or token is only ever held in a
# shell variable, piped on stdin, or forwarded to `docker compose exec` with
# `-e NAME` (no `=value`, so it never appears in an argument list). Nothing
# here prints one.
set -euo pipefail

DYNDB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAM_DIR="$(cd "$DYNDB_DIR/.." && pwd)"
cd "$PAM_DIR"
umask 077

DYNDB_PROJECT=contoso-dyndb
DYNDB_COMPOSE=docker-compose.dynamic-db.yml
DYNDB_SECRETS=dynamic-db/.secrets
DYNDB_VAULT_ADDR=http://127.0.0.1:8220
DB_CONN=clinical-db                 # database/config/<name>
DB_ROLE=clinical-readonly           # database/roles/<name>
REQ_POLICY=clinical-readonly-requester
RESP_POLICY=clinical-db-responder   # incident response: revoke / renew any lease of the role
PW_POLICY=clinical-db
# One compose invocation for every call: explicit project + file, so nothing
# here can ever address the shared contoso-pam stack.
DC=(docker compose -p "$DYNDB_PROJECT" -f "$DYNDB_COMPOSE")

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# Vault CLI inside this project's Vault container; VAULT_TOKEN is forwarded
# from the caller's environment (export it first), never passed as a value.
dv() { "${DC[@]}" exec -T -e VAULT_TOKEN vault vault "$@"; }

root_token() { jq -r '.root_token' "$DYNDB_SECRETS/vault-init.json"; }

seal_status() { curl -fsS "$DYNDB_VAULT_ADDR/v1/sys/seal-status" 2>/dev/null; }

dyndb_vault_wait() { # until the API answers (sealed or not)
  local _
  for _ in $(seq 1 45); do
    seal_status >/dev/null && return 0
    sleep 2
  done
  die "Vault (contoso-dyndb) did not answer on $DYNDB_VAULT_ADDR (docker compose -p $DYNDB_PROJECT logs vault)"
}

dyndb_vault_unseal() {
  dyndb_vault_wait
  [[ "$(seal_status | jq -r .sealed)" == true ]] || return 0
  [[ -s "$DYNDB_SECRETS/vault-init.json" ]] || die "Vault is sealed and $DYNDB_SECRETS/vault-init.json is missing (setup.sh --teardown, then setup.sh)"
  log "Unsealing Vault (contoso-dyndb)"
  # Key piped as the request body: never in an argument list.
  jq -c '{key: .unseal_keys_b64[0]}' "$DYNDB_SECRETS/vault-init.json" \
    | curl -fsS -X PUT --data @- "$DYNDB_VAULT_ADDR/v1/sys/unseal" \
    | jq -e '.sealed == false' >/dev/null || die "Vault unseal failed"
}

db_wait() {
  local _
  for _ in $(seq 1 60); do
    [[ "$("${DC[@]}" ps clinical-db --format '{{.Health}}' 2>/dev/null)" == healthy ]] && return 0
    sleep 2
  done
  die "clinical-db did not become healthy (docker compose -p $DYNDB_PROJECT logs clinical-db)"
}

# printf '%s' PASSWORD | db_as USER SQL   -> psql output (unaligned, tuples only)
# Runs in clinical-app, i.e. a real network login to clinical-db with SCRAM.
# The exit status is psql's: 0 ok, 1/3 SQL error, 2 connection/auth failure.
db_as() {
  local u="$1" sql="$2" pw
  pw=$(cat)
  [[ -n "$pw" ]] || return 9   # never attempt an empty password: proves nothing
  PGUSER="$u" PGPASSWORD="$pw" "${DC[@]}" exec -T -e PGUSER -e PGPASSWORD clinical-app \
    psql -X -q -At -v ON_ERROR_STOP=1 -c "$sql" </dev/null
}

# db_script_as USER < script.sql   - the SQL script is stdin, so the password
# comes from $DB_SCRIPT_PW instead (export it in a subshell). VAULT_ADMIN_PW,
# if exported, is forwarded too, for psql's \getenv. One-time bootstrap only.
db_script_as() {
  local u="$1"
  [[ -n "${DB_SCRIPT_PW:-}" ]] || return 9
  PGUSER="$u" PGPASSWORD="$DB_SCRIPT_PW" "${DC[@]}" exec -T -e PGUSER -e PGPASSWORD \
    -e VAULT_ADMIN_PW clinical-app psql -X -q -At -v ON_ERROR_STOP=1 -f -
}

gen_password() { # 40 random alphanumerics on stdout - for a FILE, never a terminal
  local p=""
  while [[ ${#p} -lt 40 ]]; do
    p="$p$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${p:0:40}"
}

# Mint the requester's Vault token (policy clinical-readonly-requester only,
# WITHOUT Vault's built-in "default" policy: that one lets any token renew and
# look up ANY lease - sys/leases/renew - which would undo the requester
# policy's "no renew of another person's lease". The self-service paths it
# would have given (lookup-self, revoke-self) are in our policies instead.
# Tenant time: the OIDC role sets token_no_default_policy=true.)
# LAB STAND-IN: here the root token mints it. At tenant time the person signs
# in to Vault with OIDC (Microsoft Entra ID), and the Entra group
# GRP-PAM-ClinicalDB-Readers (PIM-eligible) maps to the same policy.
# mint_requester_token OPERATOR -> token on stdout (capture it; never print it)
mint_requester_token() {
  ( export VAULT_TOKEN; VAULT_TOKEN=$(root_token)
    dv token create -format=json -policy="$REQ_POLICY" -no-default-policy -display-name="$1" \
      -ttl=1h -explicit-max-ttl=4h | jq -r '.auth.client_token' )
}

# Mint the security on-call (responder) token: policy clinical-db-responder
# only - look up, renew and revoke ANY clinical-readonly lease, issue none.
# Tenant time: an Entra group such as GRP-SecOps-OnCall (PIM-eligible).
# mint_responder_token NAME -> token on stdout (capture it; never print it)
mint_responder_token() {
  ( export VAULT_TOKEN; VAULT_TOKEN=$(root_token)
    dv token create -format=json -policy="$RESP_POLICY" -no-default-policy -display-name="$1" \
      -ttl=1h -explicit-max-ttl=1h | jq -r '.auth.client_token' )
}

# with_token TOKEN-VAR-NAME CMD... : run CMD with VAULT_TOKEN set from the
# named variable, in a subshell (the caller's VAULT_TOKEN is untouched).
with_token() {
  local var="$1"; shift
  ( export VAULT_TOKEN="${!var}"; "$@" )
}
