#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031  # tokens/passwords are exported only inside ( ... ) subshells, on purpose
# =============================================================================
# test/e2e-dynamic-db.sh - Vault dynamic database credentials, end to end,
# against a real Vault 2.1.1 and a real PostgreSQL 16 (compose project
# contoso-dyndb; the shared contoso-pam stack is never touched).
#
#   a. fresh start: dynamic-db/setup.sh --teardown, then setup.sh - exits 0,
#      and its output contains neither bootstrap password
#   b. setup.sh again: idempotent, keeps Vault's admin password
#   c. root credential: vault_admin's bootstrap password is REJECTED by
#      Postgres (rotate-root ran); the bootstrap superuser's too (PASSWORD
#      NULL); Vault never returns its admin password on a config read
#   d. requester token (policy clinical-readonly-requester only, no Vault
#      "default" policy - it would allow renewing ANY lease): creds work
#      - a real network login as the new role, which reads schema clinical
#   e. least privilege: billing schema, INSERT, CREATE are refused; the login
#      is no superuser; vault_admin itself cannot read clinical data; the
#      login cannot even connect to the `postgres` or template1 databases
#   f. unique per request: a second request -> different username AND
#      different password (compared, never printed)
#   g. lease TTL <= 1h (Vault, and Postgres VALID UNTIL is set); the
#      responder renewing for 8h is capped at the role's 4h max
#   h. policy scope: the requester cannot read the connection config, another
#      role's creds, another path's lease; cannot renew or revoke ANY lease
#      (a second requester cannot cut off the first); the responder cannot
#      issue credentials
#   i. the RESPONDER revokes: a LIVE session of the revoked login is terminated, and the same
#      username + password are then rejected; the role is gone from pg_roles;
#      the other credential still works (revocation is per lease)
#   j. revoking the requester's token revokes the leases issued under it
#   k. audit: Vault's audit log names the requester for each issue;
#      Postgres logs the dynamic login's SELECT under its v-<person>-* name
#      (statement audit) but never vault_admin's statements; neither a
#      generated nor a bootstrap password appears in Vault's audit log or
#      Postgres's log in clear
#   l. dynamic-db/demo.sh runs end to end and prints no password-shaped string
#
# "Rejected" always means Postgres answered "password authentication failed"
# (psql exit 2): an unreachable database or an empty password FAILS the
# check, so a negative check cannot pass by accident.
#
# Prints PASS/FAIL per assertion; exit 1 if anything failed. Passwords are
# only held in variables and piped - never printed, never on a command line.
#
# RUN RECORD: every run writes run.log (steps + PASS/FAIL lines), results.json
# (each check's name and status; no password, no token) and SHA256SUMS to
# --evidence-dir (default lab/pam/out/dynamic-db/<UTC>/, gitignored), after a
# scan for bootstrap passwords, password-shaped strings and local paths. A run
# with any FAIL is still recorded, marked failed. --verify DIR re-checks a
# record (hashes, every check PASS, nothing secret-shaped).
# The harness OWNS the contoso-dyndb project: it tears it down and rebuilds
# it on every run, and leaves it running for dynamic-db/demo.sh afterwards.
#
# Usage: test/e2e-dynamic-db.sh [--evidence-dir DIR]   run
#        test/e2e-dynamic-db.sh --verify DIR            check a run record
#        test/e2e-dynamic-db.sh --cleanup               tear the project down
# =============================================================================
# Helpers below are called through check(), which ShellCheck cannot see.
# shellcheck disable=SC2329
# shellcheck source-path=SCRIPTDIR source=../dynamic-db/lib.sh
source "$(dirname "$0")/../dynamic-db/lib.sh"   # cd's to lab/pam
need jq

if [[ "${1:-}" == --cleanup ]]; then
  ./dynamic-db/setup.sh --teardown
  exit 0
fi
EVIDENCE_DIR=""
VERIFY_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-dir) EVIDENCE_DIR="${2:?--evidence-dir DIR}"; shift 2 ;;
    --verify) VERIFY_DIR="${2:?--verify DIR}"; shift 2 ;;
    *) echo "usage: $0 [--evidence-dir DIR] | --verify DIR | --cleanup" >&2; exit 2 ;;
  esac
done

# Anything that looks like a generated password (32+ alphanumerics), an
# absolute local path, or a Vault token must never be in a run record.
record_unsafe() { # record_unsafe DIR -> 0 if something unsafe is found
  # SHA256SUMS is excluded: its hex digests are 64 characters by design.
  grep -rEq --exclude=SHA256SUMS '(^|[^A-Za-z0-9])[A-Za-z0-9]{32,}([^A-Za-z0-9]|$)' "$1" && return 0
  grep -rEq --exclude=SHA256SUMS '(/Users/|/home/|hvs\.[A-Za-z0-9])' "$1" && return 0
  return 1
}
verify_record() { # verify_record DIR
  local d="$1" bad=0 n
  [[ -s "$d/SHA256SUMS" && -s "$d/results.json" && -s "$d/run.log" ]] || { echo "FAIL  record incomplete: $d"; return 1; }
  if (cd "$d" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then echo "PASS  SHA256SUMS verifies"; else echo "FAIL  SHA256SUMS"; bad=1; fi
  n=$(jq '[.checks[] | select(.status == "PASS")] | length' "$d/results.json")
  if jq -e '.result == "PASS" and .fail == 0 and (.checks | length) == .pass and .pass > 0' "$d/results.json" >/dev/null; then
    echo "PASS  results.json: $n checks, all PASS"
  else echo "FAIL  results.json is not an all-PASS run"; bad=1; fi
  if record_unsafe "$d"; then echo "FAIL  secret-shaped string or local path in the record"; bad=1; else echo "PASS  no password-shaped string, token or local path"; fi
  return $bad
}
if [[ -n "$VERIFY_DIR" ]]; then
  need shasum
  verify_record "$VERIFY_DIR" && { log "E2E-DYNAMIC-DB VERIFY PASSED ($(basename "$VERIFY_DIR"))"; exit 0; }
  echo "E2E-DYNAMIC-DB VERIFY FAILED"; exit 1
fi
need docker; need curl; need openssl; need shasum   # (--verify needs only jq + shasum)
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
[[ -n "$EVIDENCE_DIR" ]] || EVIDENCE_DIR="$PAM_DIR/out/dynamic-db/$RUN_UTC"

BOOT_SU="$DYNDB_SECRETS/clinical-db-bootstrap"
BOOT_VA="$DYNDB_SECRETS/vault-admin-bootstrap"
OPERATOR=e2e-ops-bob

FAILS=0
LAST_OUT=""
# Every PASS/FAIL and step line also goes to the run record ($WORK).
pass()  { printf 'PASS  %s\n' "$*"; printf 'PASS\t%s\n' "$*" >> "$WORK/results.tsv"; printf 'PASS  %s\n' "$*" >> "$WORK/run.log"; }
fail()  { printf 'FAIL  %s\n' "$*"; printf 'FAIL\t%s\n' "$*" >> "$WORK/results.tsv"; printf 'FAIL  %s\n' "$*" >> "$WORK/run.log"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
abort() { fail "$*"; printf '\nE2E ABORTED (%d failure(s))\n' "$FAILS"; exit 1; }
step()  { printf '\n'; log "== $*"; printf '\n[%s] == %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$WORK/run.log"; }
indent() { sed 's/^/      /'; }

must() { # must DESC CMD... : must succeed (later steps depend on it)
  local d="$1" rc=0; shift
  LAST_OUT=$("$@" 2>&1) || rc=$?
  printf '%s\n' "$LAST_OUT" | indent
  [[ $rc -eq 0 ]] || abort "$d (exit $rc)"
  pass "$d"
}
said() { grep -q -- "$1" <<<"$LAST_OUT"; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/e2e-dyndb.XXXXXX")
chmod 700 "$WORK"
: > "$WORK/results.tsv"; : > "$WORK/run.log"
REQ_TOKEN=""; REQ2_TOKEN=""; RESP_TOKEN=""
cleanup_run() {
  [[ -n "$REQ_TOKEN" ]] && { with_token REQ_TOKEN dv token revoke -self >/dev/null 2>&1 || true; }
  [[ -n "$REQ2_TOKEN" ]] && { with_token REQ2_TOKEN dv token revoke -self >/dev/null 2>&1 || true; }
  [[ -n "$RESP_TOKEN" ]] && { with_token RESP_TOKEN dv token revoke -self >/dev/null 2>&1 || true; }
  rm -rf "$WORK"
}
trap cleanup_run EXIT

# printf PW | login_rejected USER -> 0 only if Postgres refused the password
login_rejected() {
  local out rc=0
  out=$(db_as "$1" 'SELECT 1' 2>&1) || rc=$?
  [[ $rc -eq 2 ]] && grep -q 'password authentication failed' <<<"$out"
}
# printf PW | sql_denied USER SQL PATTERN -> 0 only if the SQL failed with PATTERN
sql_denied() {
  local out rc=0
  out=$(db_as "$1" "$2" 2>&1) || rc=$?
  [[ $rc -ne 0 && $rc -ne 2 ]] && grep -q -- "$3" <<<"$out"
}
# no_secret_in FILE PW... -> 0 if none of the given strings occurs in FILE.
# The patterns go to grep through a pipe-backed fd, never as arguments.
no_secret_in() {
  local f="$1"; shift
  local s
  for s in "$@"; do [[ -n "$s" ]] || return 1; done
  ! grep -F -q -f <(printf '%s\n' "$@") "$f"
}
# printf PW | connect_denied USER DB -> 0 only if Postgres refused CONNECT on DB
connect_denied() {
  local pw out rc=0
  pw=$(cat); [[ -n "$pw" ]] || return 9
  out=$(PGUSER="$1" PGPASSWORD="$pw" "${DC[@]}" exec -T -e PGUSER -e PGPASSWORD clinical-app \
    psql -X -q -At -d "$2" -c 'SELECT 1' </dev/null 2>&1) || rc=$?
  [[ $rc -eq 2 ]] && grep -q "permission denied for database \"$2\"" <<<"$out"
}
# no_admin_statements PGLOG -> 0 if no vault_admin statement and no role DDL was statement-logged
no_admin_statements() { ! grep -Eq 'user=vault_admin .*statement:' "$1" && ! grep -Eq 'statement: (CREATE|ALTER) ROLE' "$1"; }
lt_eq() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 && $1 <= $2 )); }
positive_int() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 )); }
starts_with() { [[ -n "$1" && "$1" == "$2"* ]]; }
differ() { [[ -n "$1" && -n "$2" && "$1" != "$2" ]]; }
differ_vars() { [[ -n "${!1}" && -n "${!2}" && "${!1}" != "${!2}" ]]; }   # by NAME: values never passed
pw_shape_ok() { local v="${!1}"; [[ ${#v} -eq 32 && "$v" =~ ^[A-Za-z0-9]+$ ]]; }
has_word() { [[ " $1 " == *" $2 "* ]]; }
said_both() { said "$1" && said "$2"; }
# with_pw VARNAME CMD... : pipe the password held in VARNAME into CMD
with_pw() { local v="$1"; shift; printf '%s' "${!v}" | "$@"; }
# A request with the requester's token; JSON on stdout.
request_creds() { with_token REQ_TOKEN dv read -format=json "database/creds/$DB_ROLE"; }
j() { printf '%s' "$1" | jq -r "$2"; }   # j JSON FILTER (non-secret fields only)
pw_of() { printf '%s' "$1" | jq -j '.data.password'; }   # pipe it onward; never echo it

# ------------------------------------------------------------- a. fresh ---
step "a. fresh start (teardown + setup)"
must "setup.sh --teardown" ./dynamic-db/setup.sh --teardown
must "setup.sh (first run)" ./dynamic-db/setup.sh
printf '%s\n' "$LAST_OUT" > "$WORK/setup.out"
check "setup said rotate-root ran and the superuser password was removed" \
  said_both "rotate-root" "PASSWORD NULL"
check "setup output contains neither bootstrap password" \
  no_secret_in "$WORK/setup.out" "$(cat "$BOOT_SU")" "$(cat "$BOOT_VA")"

step "b. idempotent re-run"
must "setup.sh (second run)" ./dynamic-db/setup.sh
check "second run keeps Vault's admin password (no re-bootstrap)" said "already configured"

export VAULT_TOKEN
VAULT_TOKEN=$(root_token)

# ------------------------------------------------------- c. root cred ---
step "c. the root database credential is no longer the bootstrap one"
check "vault_admin + bootstrap password: rejected by Postgres (rotate-root)" \
  login_rejected vault_admin < "$BOOT_VA"
check "postgres superuser + bootstrap password: rejected (PASSWORD NULL)" \
  login_rejected postgres < "$BOOT_SU"
cfg=$(dv read -format=json "database/config/$DB_CONN")
cfg_user=$(j "$cfg" '.data.connection_details.username')
cfg_haspw=$(j "$cfg" '.data.connection_details | has("password")')
cfg_auth=$(j "$cfg" '.data.password_authentication // .data.connection_details.password_authentication')
check "config read shows the admin user ($cfg_user) but no password (has password: $cfg_haspw)" \
  [ "$cfg_user,$cfg_haspw" == "vault_admin,false" ]
check "password_authentication = scram-sha-256 ($cfg_auth): Vault sends Postgres verifiers, not plaintext" \
  [ "$cfg_auth" == scram-sha-256 ]
role=$(dv read -format=json "database/roles/$DB_ROLE")
ttls=$(j "$role" '"\(.data.default_ttl),\(.data.max_ttl)"')
check "role TTLs: default 3600s, max 14400s ($ttls)" [ "$ttls" == "3600,14400" ]

# ------------------------------------------------------------ d. creds ---
step "d. a requester gets working credentials"
REQ_TOKEN=$(mint_requester_token "$OPERATOR")
[[ -n "$REQ_TOKEN" && "$REQ_TOKEN" != null ]] || abort "mint requester token"
pols=$(with_token REQ_TOKEN dv token lookup -format=json | jq -r '.data.policies | sort | join(",")')
check "requester token carries only $REQ_POLICY - no 'default' (it would allow renewing any lease) ($pols)" [ "$pols" == "$REQ_POLICY" ]
RESP_TOKEN=$(mint_responder_token e2e-sec-oncall)
[[ -n "$RESP_TOKEN" && "$RESP_TOKEN" != null ]] || abort "mint responder token"
rpols=$(with_token RESP_TOKEN dv token lookup -format=json | jq -r '.data.policies | sort | join(",")')
check "responder token carries only $RESP_POLICY, no 'default' ($rpols)" [ "$rpols" == "$RESP_POLICY" ]

C1=$(request_creds) || abort "request creds #1"
U1=$(j "$C1" .data.username); L1=$(j "$C1" .lease_id); T1=$(j "$C1" .lease_duration)
P1=$(pw_of "$C1"); C1=""
printf '      #1 %s  lease %s  ttl %ss\n' "$U1" "$L1" "$T1"
check "username names the requester (v-$OPERATOR-...)" starts_with "$U1" "v-$OPERATOR-"
who=$(printf '%s' "$P1" | db_as "$U1" 'SELECT current_user') || who=""
check "creds #1 log in over the network (current_user = $U1)" [ "$who" == "$U1" ]
n=$(printf '%s' "$P1" | db_as "$U1" 'SELECT count(*) FROM clinical.encounters') || n=""
check "creds #1 read schema clinical ($n encounters)" positive_int "$n"

# ------------------------------------------------------ e. least priv ---
step "e. least privilege"
check "billing schema: permission denied" \
  with_pw P1 sql_denied "$U1" 'SELECT count(*) FROM billing.claims' 'permission denied for schema billing'
check "INSERT into clinical: permission denied" \
  with_pw P1 sql_denied "$U1" "INSERT INTO clinical.patients VALUES ('CH-X', 'x', 2000, 'x')" 'permission denied for table patients'
check "CREATE TABLE in clinical: permission denied" \
  with_pw P1 sql_denied "$U1" 'CREATE TABLE clinical.x (i int)' 'permission denied for schema clinical'
attrs=$(printf '%s' "$P1" | db_as "$U1" \
  "SELECT rolsuper::text || ',' || rolcreaterole::text || ',' || rolcreatedb::text || ',' || (rolvaliduntil IS NOT NULL AND rolvaliduntil < 'infinity')::text FROM pg_roles WHERE rolname = current_user") || attrs=""
check "login: not superuser / createrole / createdb, VALID UNTIL set ($attrs)" [ "$attrs" == "false,false,false,true" ]
va=$(printf '%s' "$P1" | db_as "$U1" \
  "SELECT has_table_privilege('vault_admin', 'clinical.encounters', 'SELECT')::text || ',' || pg_has_role('vault_admin', 'clinical_reader', 'USAGE')::text || ',' || pg_has_role('vault_admin', 'clinical_reader', 'SET')::text") || va=""
check "vault_admin cannot read clinical data nor assume clinical_reader ($va)" [ "$va" == "false,false,false" ]
check "the login cannot connect to the postgres maintenance database (CONNECT revoked from PUBLIC)" \
  with_pw P1 connect_denied "$U1" postgres
check "the login cannot connect to template1" with_pw P1 connect_denied "$U1" template1

# --------------------------------------------------------- f. unique ---
step "f. unique per request"
C2=$(request_creds) || abort "request creds #2"
U2=$(j "$C2" .data.username); L2=$(j "$C2" .lease_id)
P2=$(pw_of "$C2"); C2=""
printf '      #2 %s  lease %s\n' "$U2" "$L2"
check "different username" differ "$U1" "$U2"
check "different password (compared in memory)" differ_vars P1 P2
check "different lease" differ "$L1" "$L2"
check "password matches the clinical-db policy (32 alphanumerics)" pw_shape_ok P2

# ------------------------------------------------------------ g. TTL ---
step "g. lease TTL"
check "lease_duration at issue <= 3600s ($T1)" lt_eq "$T1" 3600
lt=$(with_token REQ_TOKEN dv lease lookup -format=json "$L1" | jq -r '.data.ttl') || lt=""
check "lease lookup by the requester: ttl <= 3600s ($lt)" lt_eq "$lt" 3600
rn=$(with_token RESP_TOKEN dv lease renew -format=json -increment=8h "$L2" 2>/dev/null | jq -r '.lease_duration') || rn=""
check "renew (responder) asking for 8h is capped at the 4h max ($rn s)" lt_eq "$rn" 14400

# ---------------------------------------------------------- h. scope ---
step "h. requester policy scope"
denied_as() { local tv="$1" out rc=0; shift; out=$(with_token "$tv" "$@" 2>&1) || rc=$?; [[ $rc -ne 0 ]] && grep -q 'permission denied' <<<"$out"; }
denied() { denied_as REQ_TOKEN "$@"; }
check "cannot read database/config/$DB_CONN" denied dv read "database/config/$DB_CONN"
check "cannot request another role's creds" denied dv read database/creds/clinical-admin
check "cannot look up a lease outside database/creds/$DB_ROLE/" denied dv lease lookup "database/creds/clinical-admin/xyz"
check "cannot revoke a lease outside database/creds/$DB_ROLE/" denied dv lease revoke "database/creds/clinical-admin/xyz"
check "cannot renew a lease, even its own" denied dv lease renew -increment=1h "$L2"
check "cannot revoke a single lease, even its own (ends its session with token revoke -self)" denied dv lease revoke "$L2"
REQ2_TOKEN=$(mint_requester_token e2e-ops-dave)
[[ -n "$REQ2_TOKEN" && "$REQ2_TOKEN" != null ]] || abort "mint second requester token"
check "a second requester cannot revoke the first one's lease" denied_as REQ2_TOKEN dv lease revoke "$L1"
check "a second requester cannot renew the first one's lease" denied_as REQ2_TOKEN dv lease renew -increment=1h "$L1"
with_token REQ2_TOKEN dv token revoke -self >/dev/null 2>&1 || true
REQ2_TOKEN=""
check "the responder cannot issue credentials" denied_as RESP_TOKEN dv read "database/creds/$DB_ROLE"
check "the responder cannot read database/config/$DB_CONN" denied_as RESP_TOKEN dv read "database/config/$DB_CONN"

# --------------------------------------------------------- i. revoke ---
step "i. the responder revokes lease #1 with a live session open"
( export PGUSER="$U1" PGPASSWORD="$P1"
  "${DC[@]}" exec -T -e PGUSER -e PGPASSWORD clinical-app \
    psql -X -q -At -c 'SELECT pg_sleep(60)' </dev/null ) > "$WORK/live.out" 2>&1 &
LIVE_PID=$!
live=0
for _ in $(seq 1 20); do
  live=$(printf '%s' "$P2" | db_as "$U2" "SELECT count(*) FROM pg_stat_activity WHERE usename = '$U1'" 2>/dev/null) || live=0
  [[ "$live" -ge 1 ]] && break
  sleep 0.5
done
check "a live session of $U1 is open before the revoke" [ "$live" -ge 1 ]
must "responder (security on-call) revokes lease #1" with_token RESP_TOKEN dv lease revoke -sync "$L1"
for _ in $(seq 1 20); do kill -0 "$LIVE_PID" 2>/dev/null || break; sleep 0.5; done
live_rc=0; wait "$LIVE_PID" || live_rc=$?
indent < "$WORK/live.out"
check "the live session was terminated by the revoke (psql exit $live_rc)" \
  grep -q "terminating connection due to administrator command" "$WORK/live.out"
check "revoked creds #1 are rejected (same username + password)" with_pw P1 login_rejected "$U1"
gone=$(printf '%s' "$P2" | db_as "$U2" "SELECT count(*) FROM pg_roles WHERE rolname = '$U1'") || gone=""
check "role $U1 no longer exists" [ "$gone" == 0 ]
who=$(printf '%s' "$P2" | db_as "$U2" 'SELECT current_user') || who=""
check "creds #2 still work (revocation is per lease)" [ "$who" == "$U2" ]

# ---------------------------------------------------------- j. token ---
step "j. ending the requester's Vault session revokes its leases"
must "requester token revoke-self" with_token REQ_TOKEN dv token revoke -self
rejected2=1
for _ in $(seq 1 20); do
  if printf '%s' "$P2" | login_rejected "$U2"; then rejected2=0; break; fi
  sleep 0.5
done
check "creds #2 rejected after the token was revoked" [ "$rejected2" -eq 0 ]
REQ_TOKEN=""

# ---------------------------------------------------------- k. audit ---
step "k. audit trail, and no plaintext password in either log"
"${DC[@]}" exec -T vault cat /vault/logs/audit.log </dev/null > "$WORK/audit.log"
"${DC[@]}" logs --no-color clinical-db > "$WORK/pg.log" 2>&1
issued_by=$(jq -r --arg p "database/creds/$DB_ROLE" \
  'select(.type == "response" and .request.path == $p) | .auth.display_name' "$WORK/audit.log" | sort -u | tr '\n' ' ')
check "Vault audit: creds issues attributed to token-$OPERATOR ($issued_by)" \
  has_word "$issued_by" "token-$OPERATOR"
check "Postgres log: connection authorized for $U1 (the DB-side record names the person)" \
  grep -q "connection authorized: user=$U1 " "$WORK/pg.log"
check "Postgres statement audit: $U1's SELECT on clinical.encounters is logged under its name" \
  grep -Eq "user=$U1 db=clinical LOG: +statement: SELECT count\(\*\) FROM clinical\.encounters" "$WORK/pg.log"
check "Postgres statement audit: vault_admin's statements (CREATE / ALTER ROLE ... PASSWORD) are not logged" \
  no_admin_statements "$WORK/pg.log"
check "Vault audit log: neither generated password in clear" no_secret_in "$WORK/audit.log" "$P1" "$P2"
check "Vault audit log: neither bootstrap password in clear" \
  no_secret_in "$WORK/audit.log" "$(cat "$BOOT_SU")" "$(cat "$BOOT_VA")"
check "Postgres log: neither generated password in clear" no_secret_in "$WORK/pg.log" "$P1" "$P2"
check "Postgres log: neither bootstrap password in clear" \
  no_secret_in "$WORK/pg.log" "$(cat "$BOOT_SU")" "$(cat "$BOOT_VA")"
P1=""; P2=""

# ----------------------------------------------------------- l. demo ---
step "l. dynamic-db/demo.sh"
unset VAULT_TOKEN
must "demo.sh --operator e2e-ops-carol" ./dynamic-db/demo.sh --operator e2e-ops-carol
check "demo: the post-revoke login was refused" said "password authentication failed"
check "demo: the revoked role is gone" said "in pg_roles: gone"
no_pw_shaped() { ! grep -E -q '(^|[^A-Za-z0-9])[A-Za-z0-9]{32}([^A-Za-z0-9]|$)' <<<"$LAST_OUT"; }
check "demo output has no 32-character password-shaped string" no_pw_shaped

# ----------------------------------------------------------- record ---
write_record() {
  local stage="$WORK/record" vault_v pg_img
  mkdir -p "$stage"
  cp "$WORK/run.log" "$stage/run.log"
  vault_v=$(sed -n 's/^ *image: *\(hashicorp\/vault[^@ ]*\).*/\1/p' "$DYNDB_COMPOSE" | head -1)
  pg_img=$(sed -n 's/^ *image: *\(postgres[^@ ]*\).*/\1/p' "$DYNDB_COMPOSE" | head -1)
  jq -R -s --arg ts "$RUN_UTC" --arg op "$OPERATOR" --arg v "$vault_v" --arg pg "$pg_img" '
    [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], name: .[1]}] as $c
    | {schema: "contoso-pam/e2e-dynamic-db/v1", run_utc: $ts,
       tenant: "none: local Docker only (compose project contoso-dyndb, synthetic data)",
       images: {vault: $v, postgres: $pg}, requester: ("token-" + $op),
       result: (if ([$c[] | select(.status != "PASS")] | length) == 0 then "PASS" else "FAIL" end),
       pass: ([$c[] | select(.status == "PASS")] | length), fail: ([$c[] | select(.status != "PASS")] | length),
       checks: $c}' "$WORK/results.tsv" > "$stage/results.json"
  if record_unsafe "$stage" || ! no_secret_in "$stage/run.log" "$(cat "$BOOT_SU")" "$(cat "$BOOT_VA")" \
     || ! no_secret_in "$stage/results.json" "$(cat "$BOOT_SU")" "$(cat "$BOOT_VA")"; then
    printf 'RECORD REFUSED: a secret-shaped string or local path is in the run record; nothing written\n'
    return 1
  fi
  (cd "$stage" && shasum -a 256 run.log results.json > SHA256SUMS)
  (umask 022; mkdir -p "$EVIDENCE_DIR")
  cp "$stage/run.log" "$stage/results.json" "$stage/SHA256SUMS" "$EVIDENCE_DIR/"
  chmod 644 "$EVIDENCE_DIR"/*
  log "run record: ${EVIDENCE_DIR#"$PAM_DIR"/} (run.log, results.json, SHA256SUMS)"
}

printf '\n'
write_record || FAILS=$((FAILS + 1))
if [[ $FAILS -eq 0 ]]; then
  log "E2E PASSED (contoso-dyndb left running: dynamic-db/demo.sh; test/e2e-dynamic-db.sh --cleanup to remove)"
else
  printf 'E2E FAILED (%d failure(s))\n' "$FAILS"
  exit 1
fi
