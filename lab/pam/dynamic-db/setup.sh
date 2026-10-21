#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031  # secrets are exported only inside ( ... ) subshells, on purpose
# =============================================================================
# dynamic-db/setup.sh - Vault dynamic database credentials for clinical-db
# (zero standing privilege on infrastructure). LOCAL ONLY; its own compose
# project (contoso-dyndb), never the shared contoso-pam stack.
#
#   1. start vault + clinical-db + clinical-app (docker-compose.dynamic-db.yml)
#   2. init/unseal this Vault (1 key share: lab), file audit device on
#   3. database/ secrets engine, mount TTLs 1h default / 4h max
#   4. password policy clinical-db (32 alphanumerics) for every generated
#      password, root rotation included
#   5. FIRST RUN ONLY: vault_admin on clinical-db (CREATEROLE, admin of
#      clinical_reader but unable to read PHI itself) with a bootstrap
#      password, handed to Vault on stdin, then IMMEDIATELY rotate-root:
#      from here on only Vault knows vault_admin's password
#   6. dynamic role clinical-readonly: a new login per request, member of
#      clinical_reader (SELECT on schema `clinical` only), VALID UNTIL the
#      lease end, TTL 1h / max 4h; revocation disables the login, kills its
#      live sessions and drops it
#   7. policy clinical-readonly-requester: read that role's creds and look up
#      that role's leases - NO renew, NO revoke (a Vault ACL cannot limit a
#      lease to the token that created it, so per-lease renew/revoke would
#      let one analyst cut off - or extend - another's access). Tokens are
#      minted WITHOUT Vault's built-in "default" policy, which would grant
#      sys/leases/renew on any lease. A requester ends their own access with
#      `vault token revoke -self` (granted in the policy), which revokes every
#      lease issued under their token.
#      policy clinical-db-responder (security on-call): look up, renew and
#      revoke ANY lease of that role; cannot issue credentials
#   8. self-test (issue -> log in -> revoke), then FIRST RUN ONLY: remove the
#      bootstrap superuser's password (PASSWORD NULL). No standing password to
#      clinical-db is left anywhere outside Vault.
#
# Re-running is idempotent: Vault keeps the vault_admin password only it
# knows, and the role/policy are rewritten in place.
#
# Usage: dynamic-db/setup.sh              set up / repair (idempotent)
#        dynamic-db/setup.sh --teardown   remove the project's containers,
#                                         network, volumes and generated secrets
#
# Secrets: generated into dynamic-db/.secrets/ (0700 dir, 0600 files,
# gitignored). The two *-bootstrap files are DEAD once setup finishes (the
# e2e test proves it); vault-init.json holds this Vault's unseal key and root
# token (lab only - production: split custody / auto-unseal, root revoked).
# Nothing is printed: passwords travel by stdin or `-e NAME` only.
# =============================================================================
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "$0")/lib.sh"   # cd's to lab/pam
need docker; need jq; need curl; need openssl

BOOT_SU="$DYNDB_SECRETS/clinical-db-bootstrap"   # postgres superuser: initdb only
BOOT_VA="$DYNDB_SECRETS/vault-admin-bootstrap"   # vault_admin: dead after rotate-root
# Each dynamic login names the person who asked (token display name), so the
# database's own connection log is attributable without joining to Vault.
USERNAME_TEMPLATE='{{ printf "v-%s-%s-%s" (.DisplayName | replace "token-" "" | truncate 16) (random 12) (unix_time) | truncate 63 | lowercase }}'

teardown() {
  log "Removing project $DYNDB_PROJECT (containers, network, volumes) and $DYNDB_SECRETS/"
  # compose resolves the file secret even on `down`: give it a placeholder.
  mkdir -p "$DYNDB_SECRETS" && chmod 700 "$DYNDB_SECRETS"
  [[ -e "$BOOT_SU" ]] || : > "$BOOT_SU"
  "${DC[@]}" down -v --remove-orphans 2>&1 | { grep -v -e '^ Container' -e '^ Volume' -e '^ Network' || true; }
  rm -f "$BOOT_SU" "$BOOT_VA" "$DYNDB_SECRETS/vault-init.json" "$DYNDB_SECRETS/vault-init.json.tmp"
  rmdir "$DYNDB_SECRETS" 2>/dev/null || true
}

case "${1:-}" in
  "") ;;
  --teardown) teardown; exit 0 ;;
  -h|--help) awk 'NR > 2 && (!/^#/ || /^# shellcheck/) { exit } NR > 2' "$DYNDB_DIR/${0##*/}"; exit 0 ;;
  *) echo "usage: $0 [--teardown]" >&2; exit 2 ;;
esac

# --------------------------------------------------------------- 1. start ---
mkdir -p "$DYNDB_SECRETS" && chmod 700 "$DYNDB_SECRETS"
if [[ ! -s "$BOOT_SU" ]]; then
  gen_password > "$BOOT_SU"
fi
# The postgres entrypoint reads the secret as uid 999 inside the container; on
# a Linux host the bind mount keeps this file's owner, so 0644 inside the
# 0700 directory (other host users cannot reach it). Dead after step 8.
chmod 644 "$BOOT_SU"

log "Starting $DYNDB_PROJECT (vault, clinical-db, clinical-app)"
"${DC[@]}" up -d 2>&1 | { grep -v -e '^ Container' -e '^ Network' -e '^ Volume' || true; }
db_wait
dyndb_vault_wait

# ------------------------------------------------------- 2. init / unseal ---
if [[ "$(seal_status | jq -r .initialized)" == false ]]; then
  log "Initialising Vault (1 key share - lab only; production: Shamir 3-of-5 or auto-unseal)"
  # Stored in the CLI's shape (unseal_keys_b64), like ../.secrets/vault-init.json.
  curl -fsS -X PUT --data '{"secret_shares":1,"secret_threshold":1}' "$DYNDB_VAULT_ADDR/v1/sys/init" \
    | jq '{unseal_keys_b64: .keys_base64, root_token: .root_token}' > "$DYNDB_SECRETS/vault-init.json.tmp"
  jq -e '(.root_token | length > 0) and (.unseal_keys_b64[0] | length > 0)' \
    "$DYNDB_SECRETS/vault-init.json.tmp" >/dev/null || die "Vault init returned no key/token"
  mv "$DYNDB_SECRETS/vault-init.json.tmp" "$DYNDB_SECRETS/vault-init.json"
fi
[[ -s "$DYNDB_SECRETS/vault-init.json" ]] \
  || die "Vault is initialised but $DYNDB_SECRETS/vault-init.json is gone - run $0 --teardown, then $0"
dyndb_vault_unseal
export VAULT_TOKEN
VAULT_TOKEN=$(root_token)

if ! dv audit list -format=json 2>/dev/null | jq -e 'has("file/")' >/dev/null; then
  log "Audit device: file -> /vault/logs/audit.log (secrets HMAC'd)"
  dv audit enable file file_path=/vault/logs/audit.log >/dev/null
fi

# ----------------------------------------------- 3-4. engine + pw policy ---
if ! dv secrets list -format=json | jq -e 'has("database/")' >/dev/null; then
  log "Enabling the database secrets engine at database/"
  dv secrets enable -path=database database >/dev/null
fi
dv secrets tune -default-lease-ttl=1h -max-lease-ttl=4h database/ >/dev/null

dv write "sys/policies/password/$PW_POLICY" policy=- >/dev/null <<'HCL'
length = 32
rule "charset" {
  charset   = "abcdefghijklmnopqrstuvwxyz"
  min-chars = 1
}
rule "charset" {
  charset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  min-chars = 1
}
rule "charset" {
  charset   = "0123456789"
  min-chars = 1
}
HCL

# ---------------------------------------- 5. vault_admin + rotate-root ---
FIRST_RUN=0
if dv read "database/config/$DB_CONN" >/dev/null 2>&1; then
  log "Connection $DB_CONN already configured - Vault keeps the vault_admin password only it knows"
else
  FIRST_RUN=1
  log "Creating vault_admin on clinical-db (as the bootstrap superuser, network login with SCRAM)"
  gen_password > "$BOOT_VA"
  rc=0
  ( export DB_SCRIPT_PW VAULT_ADMIN_PW
    DB_SCRIPT_PW=$(cat "$BOOT_SU")
    VAULT_ADMIN_PW=$(cat "$BOOT_VA")
    db_script_as postgres <<'SQL'
\getenv vault_admin_pw VAULT_ADMIN_PW
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_admin') AS need_create \gset
\if :need_create
CREATE ROLE vault_admin WITH LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS;
\endif
ALTER ROLE vault_admin WITH PASSWORD :'vault_admin_pw';
GRANT CONNECT ON DATABASE clinical TO vault_admin;
-- Can GRANT clinical_reader to the logins it creates, cannot use it itself.
GRANT clinical_reader TO vault_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
-- Lets revocation terminate a revoked login's live sessions (never a superuser's).
GRANT pg_signal_backend TO vault_admin;
-- clinical has log_statement = all (initdb, statement audit of PHI reads);
-- Vault's own account is exempt: its statements carry password verifiers.
ALTER ROLE vault_admin SET log_statement = 'none';
SQL
  ) || rc=$?
  if [[ $rc -eq 2 ]]; then
    die "the bootstrap superuser cannot log in to clinical-db. It was most likely set up by an earlier Vault (its volume is gone, so is the only copy of vault_admin's password). This lab has no data worth keeping: $0 --teardown, then $0"
  fi
  [[ $rc -eq 0 ]] || die "creating vault_admin failed (psql exit $rc)"

  log "Vault connection $DB_CONN -> clinical-db (admin vault_admin; password via stdin, SCRAM-hashed by Vault)"
  # password_authentication=scram-sha-256: Vault sends Postgres a SCRAM
  # verifier, never the plaintext, so no generated password can reach a
  # Postgres log. sslmode=disable: internal-only lab network (production:
  # verify-full with the DB's CA in tls_ca).
  dv write "database/config/$DB_CONN" password=- \
    plugin_name=postgresql-database-plugin \
    connection_url='postgresql://{{username}}:{{password}}@clinical-db:5432/clinical?sslmode=disable' \
    username=vault_admin \
    allowed_roles="$DB_ROLE" \
    password_authentication=scram-sha-256 \
    password_policy="$PW_POLICY" \
    username_template="$USERNAME_TEMPLATE" \
    verify_connection=true < "$BOOT_VA" >/dev/null

  log "rotate-root: Vault replaces vault_admin's bootstrap password with one only it knows"
  dv write -f "database/rotate-root/$DB_CONN" >/dev/null
  if db_as vault_admin 'SELECT 1' < "$BOOT_VA" >/dev/null 2>&1; then
    die "vault_admin still accepts its bootstrap password after rotate-root"
  fi
  log "  bootstrap password for vault_admin: rejected (rotated)"
fi

# --------------------------------------------------- 6. dynamic role ---
log "Dynamic role $DB_ROLE (TTL 1h, max 4h; SELECT on schema clinical via clinical_reader)"
jq -n --arg db "$DB_CONN" '{
  db_name: $db,
  default_ttl: "1h",
  max_ttl: "4h",
  creation_statements: [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''{{expiration}}'\'' INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5;",
    "GRANT clinical_reader TO \"{{name}}\";"
  ],
  renew_statements: [
    "ALTER ROLE \"{{name}}\" VALID UNTIL '\''{{expiration}}'\'';"
  ],
  revocation_statements: [
    "ALTER ROLE \"{{name}}\" NOLOGIN;",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '\''{{name}}'\'';",
    "DROP ROLE IF EXISTS \"{{name}}\";"
  ]
}' | dv write "database/roles/$DB_ROLE" - >/dev/null

# --------------------------------------------------- 7. requester policy ---
log "Policy $REQ_POLICY (request $DB_ROLE creds; look up those leases; no renew / revoke)"
dv policy write "$REQ_POLICY" - >/dev/null <<HCL
# A person (lab: a token minted per run; tenant time: Vault OIDC sign-in with
# Microsoft Entra ID, group -> this policy) gets a clinical-readonly login on
# request. No renew and no revoke: Vault ACLs cannot limit a lease to the
# token that created it, so either right would reach OTHER requesters' leases
# (revoke also kills their live sessions). The person ends their own access
# with 'vault token revoke -self' (default policy): every lease under the
# token goes with it. Lookup stays: read-only lease metadata (TTL, expiry);
# accepted that it also answers for another requester's lease ID.
# Tokens carrying this policy are minted WITHOUT Vault's "default" policy
# (lib.sh mint_*; tenant time: OIDC role token_no_default_policy=true),
# because "default" allows sys/leases/renew on ANY lease. The two self paths
# a person needs come from here instead.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/revoke-self" {
  capabilities = ["update"]
}
path "database/creds/$DB_ROLE" {
  capabilities = ["read"]
}
path "sys/leases/lookup" {
  capabilities       = ["update"]
  allowed_parameters = { "lease_id" = ["database/creds/$DB_ROLE/*"] }
}
HCL

log "Policy $RESP_POLICY (security on-call: look up / renew / revoke ANY $DB_ROLE lease; issues none)"
dv policy write "$RESP_POLICY" - >/dev/null <<HCL
# Incident response (tenant time: a PIM-eligible on-call Entra group mapped to
# this policy). Can end - or extend, up to the role's 4h max - any analyst's
# clinical-readonly lease; cannot issue a credential or touch the connection.
# Also minted without the "default" policy.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/revoke-self" {
  capabilities = ["update"]
}
path "sys/leases/lookup" {
  capabilities       = ["update"]
  allowed_parameters = { "lease_id" = ["database/creds/$DB_ROLE/*"] }
}
path "sys/leases/renew" {
  capabilities       = ["update"]
  allowed_parameters = { "lease_id" = ["database/creds/$DB_ROLE/*"], "increment" = [] }
}
# The CLI revokes with the lease ID in the URL (PUT sys/leases/revoke/<id>);
# the API also takes it in the body. Both are scoped to this role's leases.
path "sys/leases/revoke/database/creds/$DB_ROLE/*" {
  capabilities = ["update"]
}
path "sys/leases/revoke" {
  capabilities       = ["update"]
  allowed_parameters = { "lease_id" = ["database/creds/$DB_ROLE/*"], "sync" = [] }
}
HCL

# ------------------------------------------------------- 8. self-test ---
log "Self-test: issue a credential, log in with it, revoke it"
creds=$(dv read -format=json "database/creds/$DB_ROLE")
u=$(printf '%s' "$creds" | jq -r '.data.username')
lease=$(printf '%s' "$creds" | jq -r '.lease_id')
who=$(printf '%s' "$creds" | jq -j '.data.password' | db_as "$u" 'SELECT current_user') \
  || die "a freshly issued $DB_ROLE credential could not log in"
creds=""
[[ "$who" == "$u" ]] || die "self-test logged in as '$who', expected '$u'"
dv lease revoke -sync "$lease" >/dev/null
log "  issued $u, logged in, lease revoked"

if [[ $FIRST_RUN -eq 1 ]]; then
  log "Removing the bootstrap superuser's password (PASSWORD NULL): no standing login to clinical-db is left"
  ( export DB_SCRIPT_PW
    DB_SCRIPT_PW=$(cat "$BOOT_SU")
    printf 'ALTER ROLE postgres WITH PASSWORD NULL;\n' | db_script_as postgres ) \
    || die "could not clear the bootstrap superuser's password"
fi

dv read -format=json "database/roles/$DB_ROLE" \
  | jq -r --arg r "$DB_ROLE" '.data | "Ready. \($r): default_ttl=\(.default_ttl)s max_ttl=\(.max_ttl)s"'
log "Next: dynamic-db/demo.sh   (tests: test/e2e-dynamic-db.sh)"
