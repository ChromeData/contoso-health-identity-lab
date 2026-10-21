#!/usr/bin/env bash
# =============================================================================
# test/e2e-vault-anomaly.sh - the vault-privileged-access-anomaly feed, end
# to end, from REAL Vault audit events: a real Vault 2.1.1 with a file audit
# device, its LDAP secrets engine on a real Samba AD DC (LDAPS), real
# tokens, real failures. Then lab/scripts/monitoring/ingest-vault-audit.sh
# --signals all turns that audit log into VaultCheckout_CL-shaped rows, and
# the harness asserts on the rows.
#
# Own compose project (contoso-vaultanom, test/docker-compose.vault-anomaly.yml):
# the shared contoso-pam stack is never touched.
#
#   a. fresh start: Samba DC healthy (LDAPS, lab CA), Vault initialised,
#      unsealed, file audit device on
#   b. LDAP engine (schema ad, ldaps + the DC's CA, bound as svc-vault-rotator),
#      static role tier0/svc-legacy-da (a Kerberoastable Tier-0 service
#      account), library tier0-admins, least-privilege policies, userpass
#   c. the scenario, each step answered by Vault for real:
#        ops-alice   ticketed tier0 check-out, then a ticketed tier0 read
#        ops-mallory reads the tier0 static credential: no ticket, no check-out
#        ops-bob     tier0 check-out with ticket "none", then a read it covers
#        ops-carol   tier1-only token asks for the tier0 credential: 403
#        6 failed logins from one address across two login names, plus one
#        call with an invalid token
#   d. rotation failure: the DC is stopped, rotate-role and ops-alice's
#      check-in fail (the error text is Vault's own); DC started again,
#      the check-in succeeds and the library is whole
#   e. ingest-vault-audit.sh --signals all --dry-run over the copied audit
#      log (HMACs resolved through sys/audit-hash/file, as the script does
#      against the shared stack): exit 0, 14 columns on every row
#   f. rows: one assertion per Operation and field the detection reads
#      (Operator, Ticket, Library, Account, ErrorText, LoginName source)
#   g. the KQL rule's per-row Signal predicates, RE-STATED in jq over the
#      rows (the KQL/SPL themselves do not run here): exactly the expected
#      rows light up for each of the six signals, and the ticketed / covered
#      ones do not
#   h. no secret in the audit log or the rows: the bind password, the
#      checked-out and read passwords (compared in memory), no token
#   i. the default (checkout) mode is unchanged: 11 columns, no anomaly rows
#   j. SPL: run only when a local Splunk is up (lab/splunk); otherwise SKIP
#
# Prints PASS/FAIL per assertion; exits 1 if anything failed. Passwords and
# tokens are only held in shell variables and piped (header file on a pipe,
# JSON bodies on stdin) - never printed, never in an argument list.
#
# RUN RECORD: rows.json (the VaultCheckout_CL rows), run.log, results.json and
# SHA256SUMS go to --record-dir (default lab/pam/out/vault-anomaly/<UTC>/,
# gitignored: Vault request ids are UUIDs and the rows name lab operators).
#
# Usage: test/e2e-vault-anomaly.sh [--keep] [--record-dir DIR]
#          --keep       leave the project running afterwards (default: removed)
#        test/e2e-vault-anomaly.sh --cleanup   remove the project + its secrets
# =============================================================================
# Helpers below are called through check(), which ShellCheck cannot see
# (SC2329); token variables are read by name through ${!var} in va_req, which
# it cannot see either (SC2034); single-quoted strings are jq programs (SC2016).
# shellcheck disable=SC2329,SC2034,SC2016
CALLER_PWD="$PWD"
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"   # cd's to lab/pam; set -euo pipefail; umask 077
need docker; need jq; need curl; need openssl

VA_PROJECT=contoso-vaultanom
VA_COMPOSE=test/docker-compose.vault-anomaly.yml
VA_SECRETS=.secrets/vault-anomaly
VA_ADDR=http://127.0.0.1:8230
VA=(docker compose -p "$VA_PROJECT" --project-directory "$PAM_DIR" -f "$VA_COMPOSE")
INGEST="$PAM_DIR/../scripts/monitoring/ingest-vault-audit.sh"
BASE_DN="DC=corp,DC=test,DC=local"
FQDN=dc01.corp.test.local
T0_ROLE=tier0/svc-legacy-da
T0_CRED="ldap/static-cred/$T0_ROLE"
LIB=tier0-admins
TICKET_A=CHG0031001
TICKET_C=CHG0031002
SAMBA_SECRETS=(samba-admin-password svc-vault-rotator-password svc-backup-password svc-pam-discovery-password)

teardown() {
  # compose resolves the file secrets even on `down`: give it placeholders.
  mkdir -p "$VA_SECRETS" && chmod 700 "$VA_SECRETS"
  local f
  for f in "${SAMBA_SECRETS[@]}"; do [[ -e "$VA_SECRETS/$f" ]] || : > "$VA_SECRETS/$f"; done
  "${VA[@]}" down -v --remove-orphans 2>&1 | { grep -v -e '^ Container' -e '^ Volume' -e '^ Network' || true; }
  rm -rf "$VA_SECRETS"
}

KEEP=0
RECORD_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cleanup) teardown; log "contoso-vaultanom removed (containers, network, volumes, $VA_SECRETS)"; exit 0 ;;
    --keep) KEEP=1; shift ;;
    --record-dir) RECORD_DIR="${2:?--record-dir DIR}"; shift 2 ;;
    -h|--help) sed -n '/^# ====/,/^# ====/p' "$PAM_DIR/test/e2e-vault-anomaly.sh" | sed '1d;$d'; exit 0 ;;
    *) die "usage: $0 [--keep] [--record-dir DIR] | --cleanup" ;;
  esac
done
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
[[ -n "$RECORD_DIR" ]] || RECORD_DIR="$PAM_DIR/out/vault-anomaly/$RUN_UTC"
[[ "$RECORD_DIR" == /* ]] || RECORD_DIR="$CALLER_PWD/$RECORD_DIR"
[[ ! -e "$RECORD_DIR" ]] || die "record folder already exists: $RECORD_DIR (never overwritten)"
[[ -x "$INGEST" ]] || die "ingest script not found or not executable: $INGEST"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/e2e-vaultanom.XXXXXX")
chmod 700 "$WORK"
: > "$WORK/results.tsv"; : > "$WORK/run.log"

FAILS=0
pass()  { printf 'PASS  %s\n' "$*"; printf 'PASS\t%s\n' "$*" >> "$WORK/results.tsv"; printf 'PASS  %s\n' "$*" >> "$WORK/run.log"; }
fail()  { printf 'FAIL  %s\n' "$*"; printf 'FAIL\t%s\n' "$*" >> "$WORK/results.tsv"; printf 'FAIL  %s\n' "$*" >> "$WORK/run.log"; FAILS=$((FAILS + 1)); }
skip()  { printf 'SKIP  %s\n' "$*"; printf 'SKIP  %s\n' "$*" >> "$WORK/run.log"; }
# No redirections on a `check` line: they would apply to check itself.
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
step()  { printf '\n'; log "== $*"; printf '\n[%s] == %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$WORK/run.log"; }
indent() { sed 's/^/      /'; }
jqt() { jq -e "$@" >/dev/null; }   # jqt FILTER FILE: the filter's last output is true

# Secrets held for the run (variables only; cleared on exit).
ROOT="" ALICE="" BOB="" MALLORY="" CAROL="" ROTATOR="" PW_ALICE="" PW_MALLORY=""
on_exit() {
  local rc=$?
  ROOT="" ALICE="" BOB="" MALLORY="" CAROL="" ROTATOR="" PW_ALICE="" PW_MALLORY=""
  rm -rf "$WORK"
  if [[ $KEEP -eq 0 ]]; then teardown >/dev/null 2>&1 || true; fi
  exit "$rc"
}
trap on_exit EXIT
abort() {
  fail "$*"
  printf '\nE2E-VAULT-ANOMALY ABORTED (%d failure(s))\n' "$FAILS"
  exit 1
}

# va_req METHOD PATH [TOKEN_VARIABLE_NAME] [< JSON body]: sets RESP and CODE,
# prints nothing. The token goes to curl as a header FILE on a pipe, so it is
# never in curl's argv; responses can carry passwords, so they stay in RESP.
RESP="" CODE=""
va_req() {
  local method="$1" path="$2" tokvar="${3:-}" tok="" out
  [[ -z "$tokvar" ]] || tok="${!tokvar}"
  local c=(curl -sS --max-time 120 -w '\n%{http_code}' -X "$method")
  if [[ "$method" == GET || "$method" == DELETE || "$method" == LIST ]]; then
    if [[ -n "$tok" ]]; then
      out=$("${c[@]}" -H @<(printf 'X-Vault-Token: %s\n' "$tok") "$VA_ADDR/v1/$path" </dev/null 2>/dev/null) || out=$'\n000'
    else
      out=$("${c[@]}" "$VA_ADDR/v1/$path" </dev/null 2>/dev/null) || out=$'\n000'
    fi
  else
    if [[ -n "$tok" ]]; then
      out=$("${c[@]}" -H @<(printf 'X-Vault-Token: %s\n' "$tok") -H 'Content-Type: application/json' \
              --data-binary @- "$VA_ADDR/v1/$path" 2>/dev/null) || out=$'\n000'
    else
      out=$("${c[@]}" -H 'Content-Type: application/json' --data-binary @- "$VA_ADDR/v1/$path" 2>/dev/null) || out=$'\n000'
    fi
  fi
  CODE="${out##*$'\n'}"
  RESP="${out%$'\n'*}"
}
ok2xx() { [[ "$CODE" =~ ^2[0-9][0-9]$ ]]; }
verr() { printf '%s' "$RESP" | jq -r '(.errors // []) | join("; ")' 2>/dev/null | tr '\n\t' '  ' | cut -c1-200; }
must_api() { # must_api DESC METHOD PATH [TOKVAR] [< body]: 2xx or abort (Vault's error shown)
  local d="$1"; shift
  va_req "$@"
  ok2xx || abort "$d (HTTP $CODE: $(verr))"
  pass "$d"
}
api_quiet() { # api_quiet METHOD PATH [TOKVAR] [< body]: 2xx or abort, no PASS line (setup plumbing)
  va_req "$@"
  ok2xx || abort "vault $1 $2 (HTTP $CODE: $(verr))"
}

samba_health() { docker inspect -f '{{.State.Health.Status}}' "$("${VA[@]}" ps -q samba-dc)" 2>/dev/null || true; }
wait_samba_healthy() {
  local h=""
  for _ in $(seq 1 100); do
    h=$(samba_health); [[ "$h" == healthy ]] && return 0
    sleep 3
  done
  "${VA[@]}" logs --tail 30 samba-dc 2>&1 | indent
  return 1
}
wait_vault_api() {
  for _ in $(seq 1 45); do
    curl -fsS "$VA_ADDR/v1/sys/seal-status" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
# Mint a token the way psm-session.sh does (no default policy, metadata).
mint() { # mint VAR DISPLAY OPERATOR TICKET POLICY[,POLICY]
  local var="$1" disp="$2" op="$3" tk="$4" pols="$5" t
  api_quiet POST auth/token/create ROOT < <(jq -n --arg d "$disp" --arg o "$op" --arg t "$tk" --arg p "$pols" \
    '{policies: ($p | split(",")), no_default_policy: true, ttl: "4h", renewable: false,
      display_name: $d, meta: {operator: $o, ticket: $t, library: "tier0-admins"}}')
  t=$(printf '%s' "$RESP" | jq -r '.auth.client_token // empty')
  [[ -n "$t" ]] || abort "token for $op not minted"
  printf -v "$var" '%s' "$t"
  t=""
}
no_secret_in() { # no_secret_in FILE SECRET... -> 0 if none of the (non-empty) secrets occurs in FILE
  local f="$1" s; shift
  for s in "$@"; do
    [[ -n "$s" ]] || return 1          # an empty secret proves nothing: fail the check
    if grep -qF -f <(printf '%s\n' "$s") "$f"; then return 1; fi
  done
  return 0
}

# --- (a) fresh start ------------------------------------------------------------
step "(a) fresh start: Samba AD DC + Vault (project $VA_PROJECT, Vault on 127.0.0.1:8230)"
teardown >/dev/null 2>&1 || true
mkdir -p "$VA_SECRETS" && chmod 700 "$VA_SECRETS"
for f in "${SAMBA_SECRETS[@]}"; do
  # Upper, lower, digit, symbol: satisfies AD complexity. Never printed.
  printf 'Va-%s-4K' "$(openssl rand -hex 16)" > "$VA_SECRETS/$f"
done
chmod 600 "$VA_SECRETS"/*
if ! docker image inspect contoso-pam/samba-ad-test:local >/dev/null 2>&1; then
  build_out=$("${VA[@]}" build samba-dc 2>&1) || { printf '%s\n' "$build_out" | tail -20 | indent; abort "samba-dc image builds"; }
fi
"${VA[@]}" up -d 2>&1 | { grep -v -e '^ Container' -e '^ Network' -e '^ Volume' || true; } | indent
wait_samba_healthy || abort "samba-dc healthy (LDAPS up, certificate valid for $FQDN)"
pass "samba-dc healthy (LDAPS up, certificate valid for $FQDN)"
wait_vault_api || abort "Vault API answers on $VA_ADDR"
va_req PUT sys/init < <(printf '{"secret_shares":1,"secret_threshold":1}')
ok2xx || abort "vault init (HTTP $CODE: $(verr))"
# Init material straight from the response to a 0600 file; nothing printed.
printf '%s' "$RESP" | jq '{root_token, unseal_keys_b64: .keys_base64}' > "$VA_SECRETS/vault-init.json"
RESP=""
chmod 600 "$VA_SECRETS/vault-init.json"
jq -e '.root_token and (.unseal_keys_b64 | length) == 1' "$VA_SECRETS/vault-init.json" >/dev/null || abort "vault init returned a root token and one key share"
pass "Vault initialised (lab: 1 key share; init material in $VA_SECRETS/, 0600)"
va_req PUT sys/unseal < <(jq -c '{key: .unseal_keys_b64[0]}' "$VA_SECRETS/vault-init.json")
check "Vault unsealed" [ "$(printf '%s' "$RESP" | jq -r .sealed)" == false ]
ROOT=$(jq -r .root_token "$VA_SECRETS/vault-init.json")
must_api "file audit device enabled (sys/audit/file)" PUT sys/audit/file ROOT \
  < <(printf '{"type":"file","options":{"file_path":"/vault/logs/audit.log"}}')

# --- (b) LDAP engine + roles + policies -------------------------------------------------
step "(b) LDAP secrets engine on the Samba DC, static role $T0_ROLE, library $LIB, policies"
"${VA[@]}" exec -T samba-dc cat /var/lib/samba/private/tls/ca.pem </dev/null > "$WORK/ca.pem"
grep -q 'BEGIN CERTIFICATE' "$WORK/ca.pem" || abort "Samba lab CA read"
api_quiet POST sys/mounts/ldap ROOT < <(printf '{"type":"ldap"}')
# Bind password: jq reads the secret file; it travels on a pipe, never argv.
must_api "ldap/config: schema ad, ldaps://$FQDN verified against the DC's CA, bound as svc-vault-rotator" POST ldap/config ROOT \
  < <(jq -n --rawfile ca "$WORK/ca.pem" --rawfile pw "$VA_SECRETS/svc-vault-rotator-password" --arg b "$BASE_DN" --arg h "$FQDN" \
      '{binddn: ("CN=svc-vault-rotator,OU=ServiceAccounts," + $b), bindpass: ($pw | rtrimstr("\n")),
        url: ("ldaps://" + $h), certificate: $ca, schema: "ad", userdn: $b, userattr: "sAMAccountName"}')
must_api "static role $T0_ROLE created (Vault rotated svc-legacy-da on the DC)" POST "ldap/static-role/$T0_ROLE" ROOT \
  < <(jq -n --arg dn "CN=svc-legacy-da,OU=ServiceAccounts,$BASE_DN" '{dn: $dn, username: "svc-legacy-da", rotation_period: "24h"}')
va_req GET "ldap/static-role/$T0_ROLE" ROOT
check "... last_vault_rotation set (the rotation really happened)" \
  [ -n "$(printf '%s' "$RESP" | jq -r '.data.last_vault_rotation // empty')" ]
must_api "library $LIB (tier0-admin-01/02, exclusive check-out, rotate on check-in)" POST "ldap/library/$LIB" ROOT \
  < <(printf '{"service_account_names":["tier0-admin-01","tier0-admin-02"],"ttl":"1h","max_ttl":"4h","disable_check_in_enforcement":false}')
policy() { # policy NAME < HCL
  api_quiet PUT "sys/policies/acl/$1" ROOT < <(jq -Rs '{policy: .}')
}
policy tier0-checkout <<'HCL'
path "ldap/library/tier0-admins/check-out" { capabilities = ["update"] }
path "ldap/library/tier0-admins/check-in"  { capabilities = ["update"] }
path "ldap/library/tier0-admins/status"    { capabilities = ["read"] }
HCL
policy tier0-cred-reader <<'HCL'
path "ldap/static-cred/tier0/*" { capabilities = ["read"] }
HCL
policy tier1-cred-reader <<'HCL'
path "ldap/static-cred/tier1/*" { capabilities = ["read"] }
HCL
policy pam-rotate <<'HCL'
path "ldap/rotate-role/*" { capabilities = ["update"] }
HCL
pass "policies tier0-checkout, tier0-cred-reader, tier1-cred-reader, pam-rotate written"
api_quiet POST sys/auth/userpass ROOT < <(printf '{"type":"userpass"}')
# ops-dave exists (password generated, never stored); ops-erin does not.
api_quiet POST auth/userpass/users/ops-dave ROOT \
  < <(openssl rand -hex 16 | jq -R '{password: ("Up-" + . + "-7Q"), token_policies: ["tier1-cred-reader"]}')
pass "userpass auth method + user ops-dave (password generated, not kept)"
mint ALICE   psm-ops-alice   ops-alice   "$TICKET_A" tier0-checkout,tier0-cred-reader
mint BOB     psm-ops-bob     ops-bob     none        tier0-checkout,tier0-cred-reader
mint MALLORY ops-mallory     ops-mallory none        tier0-cred-reader
mint CAROL   psm-ops-carol   ops-carol   "$TICKET_C" tier1-cred-reader
mint ROTATOR rotate-sh       ops-alice   "$TICKET_A" pam-rotate
pass "operator tokens minted as psm-session.sh does (no default policy; metadata operator + ticket)"

# --- (c) the scenario ---------------------------------------------------------------------
step "(c) scenario: check-outs, reads, a denied read, failed logins, an invalid token"
must_api "ops-alice ($TICKET_A) checks out a Tier-0 admin" POST "ldap/library/$LIB/check-out" ALICE < <(printf '{"ttl":"1h"}')
ALICE_ACCT=$(printf '%s' "$RESP" | jq -r '.data.service_account_name')
PW_ALICE=$(printf '%s' "$RESP" | jq -r '.data.password // empty')
check "... Vault handed out $ALICE_ACCT with a password (kept in memory only)" [ -n "$PW_ALICE" ]
must_api "ops-alice ($TICKET_A) reads $T0_CRED" GET "$T0_CRED" ALICE
must_api "ops-mallory (no ticket, no check-out) reads $T0_CRED" GET "$T0_CRED" MALLORY
PW_MALLORY=$(printf '%s' "$RESP" | jq -r '.data.password // empty')
check "... and got the live password (kept in memory only)" [ -n "$PW_MALLORY" ]
must_api "ops-bob (ticket 'none') checks out a Tier-0 admin" POST "ldap/library/$LIB/check-out" BOB < <(printf '{"ttl":"1h"}')
BOB_ACCT=$(printf '%s' "$RESP" | jq -r '.data.service_account_name')
must_api "ops-bob reads $T0_CRED after his check-out" GET "$T0_CRED" BOB
RESP=""
va_req GET "$T0_CRED" CAROL
check "ops-carol's tier1-only token is refused the Tier-0 credential (HTTP 403: $(verr))" [ "$CODE" == 403 ]
# All 7 failures must land in one 10-minute clock bin (the rule's burst
# window; a burst straddling a bin edge splits - a documented KQL gap).
s=$(( $(date -u +%s) % 600 ))
if (( s > 540 )); then log "waiting $(( 601 - s ))s for a fresh 10-minute bin"; sleep $(( 601 - s )); fi
refused=0 codes=""
for u in ops-dave ops-erin ops-dave ops-erin ops-dave ops-erin; do
  va_req POST "auth/userpass/login/$u" < <(openssl rand -hex 6 | jq -R '{password: ("wrong-" + .)}')
  codes="$codes $CODE"
  [[ "$CODE" =~ ^4 ]] && refused=$((refused + 1))
done
check "6 failed userpass logins (ops-dave x3, ops-erin x3 - ops-erin does not exist) refused by Vault (HTTP$codes)" [ "$refused" -eq 6 ]
BOGUS="hvs.$(openssl rand -hex 12)"
va_req GET "ldap/library/$LIB/status" BOGUS
check "a call with an invalid token is refused (HTTP 403: $(verr))" [ "$CODE" == 403 ]
BOGUS=""

# --- (d) rotation failure -----------------------------------------------------------------
step "(d) rotation failure: DC stopped, rotate-role and check-in fail; DC back, check-in succeeds"
"${VA[@]}" stop samba-dc 2>&1 | { grep -v '^ Container' || true; } | indent
va_req POST "ldap/rotate-role/$T0_ROLE" ROTATOR </dev/null
ERR_ROTATE=$(verr)
check "rotate-role $T0_ROLE fails with the DC down (HTTP $CODE: $ERR_ROTATE)" [ "${CODE:0:1}" == 5 -o "${CODE:0:1}" == 4 ]
va_req POST "ldap/library/$LIB/check-in" ALICE < <(jq -n --arg a "$ALICE_ACCT" '{service_account_names: [$a]}')
ERR_CHECKIN=$(verr)
check "ops-alice's check-in of $ALICE_ACCT fails with the DC down: the password cannot rotate (HTTP $CODE: $ERR_CHECKIN)" \
  [ "${CODE:0:1}" == 5 -o "${CODE:0:1}" == 4 ]
va_req GET "ldap/library/$LIB/status" ROOT
check "... and $ALICE_ACCT is still checked out (available=false)" \
  [ "$(printf '%s' "$RESP" | jq -r --arg a "$ALICE_ACCT" '.data[$a].available')" == false ]
"${VA[@]}" start samba-dc 2>&1 | { grep -v '^ Container' || true; } | indent
wait_samba_healthy || abort "samba-dc healthy again"
pass "samba-dc started again and healthy"
must_api "ops-alice's check-in now succeeds (password rotated)" POST "ldap/library/$LIB/check-in" ALICE \
  < <(jq -n --arg a "$ALICE_ACCT" '{service_account_names: [$a]}')
must_api "ops-bob checks his account in" POST "ldap/library/$LIB/check-in" BOB \
  < <(jq -n --arg a "$BOB_ACCT" '{service_account_names: [$a]}')
va_req GET "ldap/library/$LIB/status" ROOT
check "library $LIB whole again (both available)" \
  [ "$(printf '%s' "$RESP" | jq -r '[.data[].available] | all')" == true ]

# --- (e) ingest -----------------------------------------------------------------------------
step "(e) ingest-vault-audit.sh --signals all over the real audit log"
# HMAC map exactly as the script builds it against the shared stack (root
# token, sys/audit-hash/file) - so the copied log also holds those calls.
map='{}'
for a in tier0-admin-01 tier0-admin-02; do
  api_quiet POST sys/audit-hash/file ROOT < <(jq -n --arg i "$a" '{input: $i}')
  map=$(jq -c --arg h "$(printf '%s' "$RESP" | jq -r '.data.hash // .hash')" --arg a "$a" '. + {($h): $a}' <<<"$map")
done
printf '%s\n' "$map" > "$WORK/map.json"
check "HMAC map from sys/audit-hash/file covers both library accounts" jqt 'length == 2 and all(.[]; startswith("tier0-admin-"))' "$WORK/map.json"
"${VA[@]}" exec -T vault cat /vault/logs/audit.log </dev/null > "$WORK/audit.log"
check "audit log copied ($(wc -l < "$WORK/audit.log" | tr -d ' ') records)" [ -s "$WORK/audit.log" ]
rc=0
"$INGEST" --audit-file "$WORK/audit.log" --hash-map "$WORK/map.json" --state-dir "$WORK/state" \
  --signals all --dry-run > "$WORK/rows.json" 2> "$WORK/ingest.err" || rc=$?
indent < "$WORK/ingest.err"
check "ingest-vault-audit.sh --signals all --dry-run exits 0" [ "$rc" -eq 0 ]
check "every row has the 11 VaultCheckout_CL columns + Ticket, Operator, ErrorText (14)" \
  jqt 'length > 0 and all(.[]; (keys | sort) == (["Account","AccountResolved","ErrorText","Library","Operation","Operator","RemoteAddress","RequestId","SourceHost","Ticket","TimeGenerated","TokenPolicies","VaultActor","VaultPath"]))' "$WORK/rows.json"
check "every Operation is one the detections know" \
  jqt 'all(.[]; .Operation | IN("check-out","check-in","heartbeat","cred-read","rotation-failed","root-token","auth-failed","access-denied"))' "$WORK/rows.json"
jq -r 'group_by(.Operation) | map("\(.[0].Operation)=\(length)") | join("  ")' "$WORK/rows.json" | indent

# --- (f) rows -------------------------------------------------------------------------------
step "(f) VaultCheckout_CL rows carry what the detection reads"
R="$WORK/rows.json"
rows_has() { jq -e "$1" "$R" >/dev/null; }   # rows_has JQ_PREDICATE_OVER_THE_ARRAY
check "check-out by ops-alice: Ticket $TICKET_A, Library $LIB, Account $ALICE_ACCT resolved from its HMAC" rows_has \
  "any(.[]; .Operation == \"check-out\" and .Operator == \"ops-alice\" and .Ticket == \"$TICKET_A\" and .Library == \"$LIB\" and .Account == \"$ALICE_ACCT\" and .AccountResolved and .VaultActor == \"token-psm-ops-alice\")"
check "check-out by ops-bob carries Ticket 'none'" rows_has \
  "any(.[]; .Operation == \"check-out\" and .Operator == \"ops-bob\" and .Ticket == \"none\" and .Account == \"$BOB_ACCT\")"
check "cred-read rows: alice, mallory, bob on $T0_CRED, Account svc-legacy-da" rows_has \
  "[.[] | select(.Operation == \"cred-read\" and .VaultPath == \"$T0_CRED\" and .Account == \"svc-legacy-da\") | .Operator] | sort == [\"ops-alice\",\"ops-bob\",\"ops-mallory\"]"
check "access-denied row: ops-carol on $T0_CRED, Vault's 'permission denied' in ErrorText" rows_has \
  "any(.[]; .Operation == \"access-denied\" and .Operator == \"ops-carol\" and .VaultPath == \"$T0_CRED\" and (.ErrorText | test(\"permission denied\")))"
check "auth-failed: 6 login rows on auth/userpass/login/{ops-dave,ops-erin} from ONE address" rows_has \
  '[.[] | select(.Operation == "auth-failed" and (.VaultPath | startswith("auth/userpass/login/")))] as $l
   | ($l | length) == 6 and ([$l[].RemoteAddress] | unique | length) == 1
     and ([$l[].VaultPath | split("/") | last] | unique) == ["ops-dave","ops-erin"]'
check "auth-failed: ops-erin (unknown user, no top-level error in Vault's record) still counted via response.data.error" rows_has \
  '[.[] | select(.Operation == "auth-failed" and .VaultPath == "auth/userpass/login/ops-erin")] | length == 3 and all(.[]; .ErrorText | test("response.data.error"))'
check "auth-failed: the invalid-token call is a row too (no login name; ErrorText says invalid token)" rows_has \
  "any(.[]; .Operation == \"auth-failed\" and .VaultPath == \"ldap/library/$LIB/status\" and (.ErrorText | test(\"invalid token\")))"
check "rotation-failed: rotate-role on $T0_ROLE, Account svc-legacy-da, Vault's error kept" rows_has \
  "any(.[]; .Operation == \"rotation-failed\" and .VaultPath == \"ldap/rotate-role/$T0_ROLE\" and .Account == \"svc-legacy-da\" and .ErrorText != \"\" and .Operator == \"ops-alice\")"
check "rotation-failed: ops-alice's check-in of $ALICE_ACCT (Library $LIB, account resolved from the request HMAC)" rows_has \
  "any(.[]; .Operation == \"rotation-failed\" and .VaultPath == \"ldap/library/$LIB/check-in\" and .Library == \"$LIB\" and .Account == \"$ALICE_ACCT\" and .AccountResolved and .ErrorText != \"\")"
check "the successful check-ins after the DC came back are check-in rows (alice, bob)" rows_has \
  "[.[] | select(.Operation == \"check-in\") | .Operator] | sort == [\"ops-alice\",\"ops-bob\"]"
check "a failed check-in is NOT a check-in row (the session did not end)" rows_has \
  "[.[] | select(.Operation == \"check-in\" and .Account == \"$ALICE_ACCT\")] | length == 1"
check "root-token rows: setup calls (sys/mounts/ldap, ldap/config, sys/policies/acl/*) and the HMAC lookups (sys/audit-hash/file)" rows_has \
  '[.[] | select(.Operation == "root-token") | .VaultPath] as $p
   | ($p | index("sys/mounts/ldap")) != null and ($p | index("ldap/config")) != null
     and any($p[]; startswith("sys/policies/acl/")) and ($p | index("sys/audit-hash/file")) != null'
check "root-token rows name the root policy and nobody's ticket" rows_has \
  'all(.[] | select(.Operation == "root-token"); .TokenPolicies == "root" and .Ticket == "")'
check "exactly one heartbeat" rows_has '[.[] | select(.Operation == "heartbeat")] | length == 1'

# --- (g) the KQL predicates, re-stated ----------------------------------------------------
step "(g) the rule's per-row Signal predicates, RE-STATED in jq (the KQL/SPL do not run here)"
# Mirrors lab/kql/vault-privileged-access-anomaly.kql: TicketValid =
# ^CHG[0-9]{7}$; a Tier-0 read is covered only by a tier0-admins check-out of
# the same (non-empty) Operator in [read - 4h, read + 5m]; AuthFailureBurst =
# >= 5 auth-failed rows from one address in one 10-minute clock bin.
jq '
  def ep: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
  ([.[] | select(.Operation == "check-out" and .Library == "tier0-admins" and .Operator != "")
        | {Operator, t: (.TimeGenerated | ep)}]) as $outs
  | [.[] | select(.Operation != "heartbeat")
     | (.TimeGenerated | ep) as $t
     | (.Ticket | test("^CHG[0-9]{7}$")) as $tv
     | . as $r
     | (.Operation == "cred-read"
        and any($outs[]; .Operator == $r.Operator and .t >= $t - 14400 and .t <= $t + 300)) as $cov
     | . + {Bin: (($t / 600 | floor) * 600), Signal: (
         if .Operation == "cred-read" and (.VaultPath | startswith("ldap/static-cred/tier0/")) and ($tv | not) and ($cov | not) then "Tier0CredReadUncovered"
         elif .Operation == "check-out" and .Library == "tier0-admins" and ($tv | not) then "Tier0CheckoutWithoutTicket"
         elif .Operation == "rotation-failed" then "RotationFailed"
         elif .Operation == "root-token" then "RootTokenUse"
         elif .Operation == "auth-failed" then "AuthFailureBurst"
         elif .Operation == "access-denied" and (.VaultPath | test("(^|[^A-Za-z0-9])tier0($|[^A-Za-z0-9])")) then "Tier0AccessDenied"
         else "" end)}
     | select(.Signal != "")]' "$R" > "$WORK/signals.json"
S="$WORK/signals.json"
sig_has() { jq -e "$1" "$S" >/dev/null; }
check "Tier0CredReadUncovered: exactly ops-mallory's read" sig_has \
  '[.[] | select(.Signal == "Tier0CredReadUncovered") | .Operator] == ["ops-mallory"]'
check "... ops-alice's ticketed read and ops-bob's check-out-covered read do NOT fire" sig_has \
  '[.[] | select(.Signal == "Tier0CredReadUncovered" and (.Operator == "ops-alice" or .Operator == "ops-bob"))] | length == 0'
check "Tier0CheckoutWithoutTicket: exactly ops-bob's check-out (ops-alice's ticketed one does not fire)" sig_has \
  '[.[] | select(.Signal == "Tier0CheckoutWithoutTicket") | .Operator] == ["ops-bob"]'
check "RotationFailed: the rotate-role and the check-in (2 rows; Tier-0 path / library -> High in the rule)" sig_has \
  '[.[] | select(.Signal == "RotationFailed")] | length == 2 and all(.[]; (.VaultPath | test("tier0")) or .Library == "tier0-admins")'
check "RootTokenUse: present, including paths outside the lab-automation list (-> High in the rule)" sig_has \
  '[.[] | select(.Signal == "RootTokenUse") | .VaultPath] | any(.[]; IN("auth/token/create","auth/token/revoke","sys/audit-hash/file") | not)'
check "AuthFailureBurst: one address+bin group with >= 5 rows (7) and login names ops-dave, ops-erin (-> High)" sig_has \
  '[.[] | select(.Signal == "AuthFailureBurst")] | group_by([.RemoteAddress, .Bin])
   | map({n: length, logins: ([.[].VaultPath | capture("^auth/[^/]+/login/(?<n>[^/?]+)").n] | unique)})
   | any(.[]; .n >= 5 and .n == 7 and .logins == ["ops-dave","ops-erin"])'
check "Tier0AccessDenied: exactly ops-carol's denied read" sig_has \
  '[.[] | select(.Signal == "Tier0AccessDenied") | .Operator] == ["ops-carol"]'
check "all six signals present" sig_has \
  '[.[].Signal] | unique == ["AuthFailureBurst","RootTokenUse","RotationFailed","Tier0AccessDenied","Tier0CheckoutWithoutTicket","Tier0CredReadUncovered"]'

# --- (h) no secrets -----------------------------------------------------------------------
step "(h) no secret in the audit log or the rows"
BIND_PW=$(tr -d '\r\n' < "$VA_SECRETS/svc-vault-rotator-password")
ADMIN_PW=$(tr -d '\r\n' < "$VA_SECRETS/samba-admin-password")
check "audit log: neither the checked-out nor the read password in clear (compared in memory)" no_secret_in "$WORK/audit.log" "$PW_ALICE" "$PW_MALLORY"
check "audit log: the bind and DC admin passwords not in clear" no_secret_in "$WORK/audit.log" "$BIND_PW" "$ADMIN_PW"
check "rows: none of those four passwords" no_secret_in "$R" "$PW_ALICE" "$PW_MALLORY" "$BIND_PW" "$ADMIN_PW"
no_token_in() { ! grep -Eq 'hvs\.[A-Za-z0-9]{8,}' "$1"; }
no_local_path() { ! grep -Eq '/Users/|/home/|/private/tmp|/var/folders' "$1"; }
check "rows: no Vault token" no_token_in "$R"
check "rows: no absolute local path" no_local_path "$R"
BIND_PW="" ADMIN_PW="" PW_ALICE="" PW_MALLORY=""

# --- (i) default mode unchanged ------------------------------------------------------------
step "(i) the default (checkout) mode is unchanged"
rc=0
"$INGEST" --audit-file "$WORK/audit.log" --hash-map "$WORK/map.json" --state-dir "$WORK/state2" \
  --dry-run > "$WORK/rows-default.json" 2>/dev/null || rc=$?
check "default mode exits 0" [ "$rc" -eq 0 ]
check "default mode: only check-out / check-in / heartbeat, 11 columns (the DCR's schema today)" \
  jqt 'all(.[]; (.Operation | IN("check-out","check-in","heartbeat")) and (keys | length) == 11)' "$WORK/rows-default.json"
same_checkout_rows() { # check-out / check-in rows identical in both modes, the 3 new columns aside
  local a b
  a=$(jq -cS '[.[] | select(.Operation == "check-out" or .Operation == "check-in") | del(.Ticket, .Operator, .ErrorText)]
              | sort_by(.RequestId, .Operation, .Account)' "$WORK/rows.json")
  b=$(jq -cS '[.[] | select(.Operation == "check-out" or .Operation == "check-in")] | sort_by(.RequestId, .Operation, .Account)' "$WORK/rows-default.json")
  [[ "$a" != "[]" && "$a" == "$b" ]]
}
check "default mode: same check-out / check-in rows as --signals all (minus the 3 new columns)" same_checkout_rows

# --- (j) SPL ---------------------------------------------------------------------------------
step "(j) SPL twin (lab/splunk/detections/vault-privileged-access-anomaly.spl)"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^contoso-splunk-'; then
  skip "a local Splunk is running, but replaying these rows into it is not automated here (follow-up); the SPL did not run"
else
  skip "no local Splunk running (lab/splunk/splunk-up.sh, a licence-accepting trial); the SPL did not run - rows asserted instead"
fi

# --- record ------------------------------------------------------------------------------------
write_record() {
  local stage="$WORK/record"
  mkdir -p "$stage"
  cp "$WORK/run.log" "$stage/run.log"
  cp "$R" "$stage/rows.json"
  jq -R -s --arg ts "$RUN_UTC" '
    [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], name: .[1]}] as $c
    | {schema: "contoso-pam/e2e-vault-anomaly/v1", run_utc: $ts,
       tenant: "none: local Docker only (compose project contoso-vaultanom, Samba test DC, synthetic accounts)",
       images: {vault: "hashicorp/vault:2.1.1", dc: "contoso-pam/samba-ad-test:local (test/samba-ad)"},
       spl_ran: false, kql_ran: false,
       result: (if ([$c[] | select(.status != "PASS")] | length) == 0 then "PASS" else "FAIL" end),
       pass: ([$c[] | select(.status == "PASS")] | length), fail: ([$c[] | select(.status != "PASS")] | length),
       checks: $c}' "$WORK/results.tsv" > "$stage/results.json"
  if grep -rEq '(/Users/|/home/|/private/tmp|/var/folders|hvs\.[A-Za-z0-9]{8,})' "$stage"; then
    printf 'RECORD REFUSED: a local path or token-shaped string is in the run record; nothing written\n'
    return 1
  fi
  (cd "$stage" && sha256_of run.log rows.json results.json > SHA256SUMS)
  (umask 022; mkdir -p "$RECORD_DIR")
  cp "$stage/run.log" "$stage/rows.json" "$stage/results.json" "$stage/SHA256SUMS" "$RECORD_DIR/"
  chmod 644 "$RECORD_DIR"/*
  log "run record: ${RECORD_DIR#"$PAM_DIR"/} (run.log, rows.json, results.json, SHA256SUMS)"
}
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

printf '\n'
write_record || FAILS=$((FAILS + 1))
if [[ $FAILS -eq 0 ]]; then
  if [[ $KEEP -eq 1 ]]; then
    log "E2E-VAULT-ANOMALY PASSED ($VA_PROJECT left running: --cleanup removes it)"
  else
    log "E2E-VAULT-ANOMALY PASSED ($VA_PROJECT removed)"
  fi
  exit 0
fi
log "E2E-VAULT-ANOMALY FAILED: $FAILS assertion(s)"
exit 1
