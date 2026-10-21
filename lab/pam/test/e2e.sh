#!/usr/bin/env bash
# =============================================================================
# test/e2e.sh - rehearse the AD-dependent PAM flow WITHOUT Azure, against a
# real Samba Active Directory DC, using the real scripts (vault-onboard-ad.sh,
# psm-session.sh, conjur-demo.sh, discover.sh, onboard.sh, rotate.sh,
# reconcile.sh, psm-ssh.sh, vault-ha.sh, dr-drill.sh - only the `az` CLI is
# stubbed), not copies.
#
#   a. build + start samba-dc (dc01.corp.test.local) next to the running stack
#      (DC01 layout + a discovery population: SPN, stale, nested, orphaned)
#   b. ./vault-onboard-ad.sh, first run: root CA (CRLF, as from Windows) ->
#      .secrets/vault-ca, DC_FQDN/DC_PUBLIC_IP -> .env + Vault recreate (the
#      name resolves ONLY through that extra_hosts mapping), Key Vault bind
#      password on stdin, LDAP engine, static role, library, policy
#   c. svc-backup rotated on onboarding: pwdLastSet moved, the old password is
#      rejected (LDAP 49), the Vault-held one binds
#   d. guardrails: a second directory is refused; a failed Key Vault read
#      stops before an empty bind password reaches Vault
#   e. --rotate-root on a re-run, then a plain re-run: Vault keeps (and can
#      still use) the bind password only it knows
#  f0. check-out gates: no operator / unknown operator / operator outside the
#      Safe / no ticket / unapproved / expired / someone else's / unknown /
#      malformed ticket are all refused before anything is checked out; a
#      pam-policy.json with the require_ticket key missing, or unparsable,
#      stops the check-out (fail closed); the shared t0-operator no longer
#      exists. DUAL CONTROL (Tier 0): a self-approved change, a single
#      approver, an approver without the Safe right and a policy without
#      approvals_required are each refused; (f) succeeds only with two
#      distinct approvers, neither the requester, and the approvers reach
#      Vault's audit log (token metadata) and the PAM audit line
#   f. ./psm-session.sh checkout --operator --ticket x3: injected password
#      binds as the account, ONLY that operator sees (READ) the connection and
#      gets 403 on its parameters, Vault's audit log names the operator and
#      ticket, the 2nd check-out gets the other account, the 3rd is refused
#      because Vault says the pool is exhausted
#   g. ./psm-session.sh checkin: password rotated (old one rejected), the
#      connection password wiped, the operator no longer sees the connection,
#      the per-check-out token revoked, the account back in the library
#  g3. OIDC mode (PAM_OIDC=1, the tenant-time Entra sign-in): an operator's
#      local Guacamole password stops working at /api/tokens, its file is
#      deleted, its attributes survive, and a person who never signed in
#      through Entra gets no local user at all
#  g2. recordings volume: guacd can write a recording, the web app can read it
#  g4. RDP without DC01: rdp-target (rdp-target/, a LINUX xrdp STAND-IN for an
#      RDP session to DC01) authenticates the AD account by Kerberos against
#      samba-dc. A dual-approved ./psm-session.sh checkout --target
#      rdp-target injects the Vault password; a REAL RDP session runs through
#      Guacamole as the operator (HTTP tunnel, xrdp autologon, keys typed);
#      the typed command ran as the AD account on rdp-target; the recording
#      is written, passes the guacamole-recording format check
#      (test/guac_recording.py: plays back) and is the same file the web
#      app's History serves to its player; check-in rotates the password and
#      the KDC refuses the old one
#   h. ./conjur-demo.sh succeeds (allowed + 403)
#   i. midPoint REST login (and a wrong password is refused) + connector
#      inventory (is MS Graph bundled?)
#   j. ./discover.sh: every planted finding classified (nested membership,
#      primary group, SPN, stale, never used, orphaned adminCount, exclusions)
#   k. ./onboard.sh: bulk onboarding through the Vault API with a Safe per
#      tier; the service account with unresolved dependencies is HELD, and so
#      is a human (library) admin used as a run-as identity; Safe isolation
#      proven with each tier's token; idempotent re-run
#   l. ./rotate.sh: dependency gate (resolved -> rotates; unresolved or
#      unknown -> refused, password untouched)
#   m. ./reconcile.sh --verify --strict: GAP 0; a password changed outside
#      Vault fails "verify" and rotate.sh repairs it; a forced onboarding is
#      recorded in the exception register; an account deleted in AD shows as
#      ORPHAN
#   n. ./psm-ssh.sh: Vault SSH CA, unsigned / expired / wrong-principal
#      access refused, a REAL recorded SSH session through Guacamole as the
#      operator (typescript + recording + history), sshd's log names the
#      operator via the certificate key ID. Tier 1 needs ONE approver: one
#      authorised approver accepted, none / self-approval refused
#   o. ./vault-ha.sh + ./dr-drill.sh: 3-node Raft, leader crash failover,
#      timed snapshot/restore drill (RTO/RPO), rolling-upgrade rehearsal
#      (skip with --skip-ha)
#
# "Rejected" always means the DC answered invalidCredentials (49): an
# unreachable DC, a failed docker exec or an empty password FAIL it, so a
# negative check can never pass by accident.
#
# Prints PASS/FAIL per assertion and exits 1 if anything failed. Passwords are
# only ever piped (to ldapwhoami, compared via binds) - never printed, never
# on a command line. Test credentials live in .secrets/test/ (0600). Reports
# from the scripts under test go to out/e2e/ (PAM_OUT), never mixed with real
# evidence in out/.
#
# The harness OWNS Vault's ldap/ mount while it runs: it refuses to start if
# Vault or .env point at another DC (a real onboarding) unless --force.
#
# RUN RECORD (--evidence-dir DIR, relative DIR taken from lab/pam, e.g.
# ../evidence/pam/<UTC>): results.json (every check's name + PASS/FAIL, the
# tallies, the HA flag, and the code fingerprint: SHA-256 of every lab/pam
# file the run used, taken at the start: lib.sh code_sums -> code.sha256sums),
# run.log (step and PASS/FAIL lines only - never the commands' output),
# reconcile.csv / reconcile.md (the last reconcile report: account names and
# states, no password), rdp-recording.json (step g4: the RDP session's
# operator, account, Guacamole history id (not its UUID) and the recording's size, sha256, frames,
# duration and image counts - never the recording itself) and SHA256SUMS,
# written only after a secret-shape /
# local-path check. A failed run is recorded as failed: an assertion FAIL, and
# also a run that ABORTS part-way (results.json then carries "aborted").
# --dr-evidence-dir DIR passes the same to dr-drill.sh (its RTO/RPO record).
# --verify DIR re-checks a record (hashes, all-PASS, nothing secret-shaped,
# code fingerprint consistent) with only jq + shasum: no Docker needed.
#
# Usage: test/e2e.sh [--force] [--skip-ha] [--evidence-dir DIR] [--dr-evidence-dir DIR]
#        test/e2e.sh --verify DIR
#        test/e2e.sh --cleanup     remove samba-dc + its volume, reset DC_* in
#                                  .env, drop the test-only Vault/PSM/Guacamole
#                                  state, the harness's tickets, rdp-target and
#                                  its connections, and the SSH target / HA
#                                  cluster if the harness made them
# =============================================================================
# Helpers below are called through check/must/must_fail, which ShellCheck
# cannot see (SC2329 "never invoked").
# shellcheck disable=SC2329
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"   # cd's to lab/pam
# The run's dependencies are checked after the arguments: --verify needs only
# jq + shasum, so a reviewer can re-check a published record without the
# container toolchain.

TEST_DOMAIN=corp.test.local
TEST_FQDN=dc01.$TEST_DOMAIN
BASE_DN="DC=corp,DC=test,DC=local"
NETBIOS=CORP
TEST_SECRETS=.secrets/test
SAMBA_VOLUME=contoso-pam_samba-dc
STATE=.secrets/psm-checkout.json
RECORDINGS=/var/lib/guacamole/recordings
DEPS_E2E=test/accounts-dependencies.e2e.json
SSH_CONN="LINUX - ssh-target (recorded)"
# samba-dc lives only in the override file; silence compose's orphan warning
# when the scripts under test run plain `docker compose`.
export COMPOSE_IGNORE_ORPHANS=true
# The scripts under test write their reports here, not into real evidence.
export PAM_OUT=out/e2e
OUT=$PAM_OUT

samba() { docker compose -f docker-compose.yml -f test/docker-compose.samba.yml "$@"; }

FAILS=0
LAST_OUT=""
# Every PASS/FAIL and step line also goes to the run record (REC: a private
# temp folder; copied to --evidence-dir only at the end, after the checks).
REC=$(mktemp -d); chmod 700 "$REC"; : > "$REC/results.tsv"; : > "$REC/run.log"
trap 'rm -rf "$REC"' EXIT
pass()  { printf 'PASS  %s\n' "$*"; printf 'PASS\t%s\n' "$*" >> "$REC/results.tsv"; printf 'PASS  %s\n' "$*" >> "$REC/run.log"; }
fail()  { printf 'FAIL  %s\n' "$*"; printf 'FAIL\t%s\n' "$*" >> "$REC/results.tsv"; printf 'FAIL  %s\n' "$*" >> "$REC/run.log"; FAILS=$((FAILS + 1)); }
# No redirections on a `check` line: they would apply to check itself and
# swallow its PASS/FAIL line. Put them inside a helper function instead.
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
# An abort still leaves a run record (marked failed, with the reason) when
# --evidence-dir is set: the evidence folder holds failed runs too.
ABORTED=""
abort() {
  fail "$*"
  ABORTED="$*"
  if [[ -n "${EVIDENCE_DIR:-}" && -z "${RECORD_WRITTEN:-}" ]]; then write_record || true; fi
  printf '\nE2E ABORTED (%d failure(s))\n' "$FAILS"; exit 1
}
step()  { printf '\n'; log "== $*"; printf '\n[%s] == %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$REC/run.log"; }
indent() { sed 's/^/      /'; }

must() { # must DESC CMD... : must succeed - later steps depend on it, so ABORT otherwise
  local d="$1" rc=0; shift
  LAST_OUT=$("$@" 2>&1) || rc=$?
  printf '%s\n' "$LAST_OUT" | { grep -v -e '^ Container' -e '^ *[a-z0-9-]* Cop' || true; } | indent
  [[ $rc -eq 0 ]] || abort "$d (exit $rc)"
  pass "$d"
}

must_fail() { # must_fail DESC PATTERN CMD... : must exit non-zero AND say PATTERN (the specific reason)
  local d="$1" pat="$2" rc=0; shift 2
  LAST_OUT=$("$@" 2>&1) || rc=$?
  printf '%s\n' "$LAST_OUT" | { grep -v '^ Container' || true; } | indent
  if [[ $rc -ne 0 ]] && grep -q -- "$pat" <<<"$LAST_OUT"; then pass "$d"; else fail "$d (exit $rc)"; fi
}

said() { grep -q -- "$1" <<<"$LAST_OUT"; }   # said PATTERN: the last must/must_fail printed it

dn_of() { # dn_of SAM -> DN in the DC01 layout (+ the discovery population)
  case "$1" in
    tier0-*|t0-*|t1-*|former-*) echo "CN=$1,OU=PrivilegedAccounts,$BASE_DN" ;;
    *)                          echo "CN=$1,OU=ServiceAccounts,$BASE_DN" ;;
  esac
}

ldap_whoami() { # printf '%s' PW | ldap_whoami SAM -> the DC's "u:DOMAIN\sam"; exit = ldapwhoami's (49 = invalidCredentials)
  local pw
  pw=$(cat)
  [[ -n "$pw" ]] || return 2   # empty = anonymous bind: proves nothing either way
  printf '%s' "$pw" | samba exec -T -e LDAPTLS_CACERT=/var/lib/samba/private/tls/ca.pem samba-dc \
    ldapwhoami -x -H "ldaps://$TEST_FQDN" -D "$(dn_of "$1")" -y /dev/stdin 2>/dev/null
}

binds() { # printf '%s' PW | binds SAM -> 0 only if the DC accepts it AND reports the identity as SAM
  local who
  who=$(ldap_whoami "$1") || return 1
  [[ "$who" == "u:${NETBIOS}\\$1" ]]
}

rejected() { # printf '%s' PW | rejected SAM -> 0 only if the DC answers invalidCredentials (49)
  local rc=0
  ldap_whoami "$1" >/dev/null || rc=$?
  [[ $rc -eq 49 ]]
}

pwd_last_set() { # pwd_last_set SAM -> pwdLastSet (100ns ticks), read from sam.ldb
  samba exec -T samba-dc ldbsearch -H /var/lib/samba/private/sam.ldb -b "$BASE_DN" \
    "(sAMAccountName=$1)" pwdLastSet </dev/null 2>/dev/null | sed -n 's/^pwdLastSet: //p'
}

guac_conn_param() { # guac_conn_param ACCOUNT PARAM -> value (pipe it; never echo a password)
  guac_conn_param_by_name "$(conn_name "$1")" "$2"
}

guac_conn_param_by_name() { # guac_conn_param_by_name CONNECTION-NAME PARAM -> value
  local tok id
  tok=$(guac_admin_token)
  id=$(guac_conn_id "$tok" "$1")
  [[ -n "$id" ]] || return 1
  curl -fsS -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections/$id/parameters" \
    | jq -j --arg p "$2" '.[$p] // ""'
}

changed() { [[ -n "$1" && -n "$2" && "$1" != "$2" ]]; }   # changed OLD NEW: both known, and different
same()    { [[ -n "$1" && "$1" == "$2" ]]; }              # same OLD NEW: known, and unchanged

vault_unsealed() { [[ "$(curl -fsS http://127.0.0.1:8200/v1/sys/seal-status | jq -r .sealed)" == false ]]; }

env_points_at() { grep -qx "DC_FQDN=$1" .env && grep -qx "DC_PUBLIC_IP=$2" .env; }

dc_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(samba ps -q samba-dc)"; }

vault_resolves_dc() { # Vault's /etc/hosts (extra_hosts from .env) maps TEST_FQDN -> $1
  [[ "$(docker compose exec -T vault getent hosts "$TEST_FQDN" </dev/null | awk '{print $1}')" == "$1" ]]
}

guacd_cannot_resolve_dc() { # control: without the mapping the name does NOT resolve (getent: 2 = not found)
  local rc=0
  docker compose exec -T guacd getent hosts "$TEST_FQDN" </dev/null >/dev/null 2>&1 || rc=$?
  [[ $rc -eq 2 ]]
}

ca_installed_ok() { # parses, no CR left from the Windows-style output, same certificate as the DC's
  local f=.secrets/vault-ca/ad-root-ca.pem mine theirs
  [[ -s "$f" ]] && ! grep -q $'\r' "$f" || return 1
  mine=$(openssl x509 -noout -fingerprint -sha256 -in "$f" 2>/dev/null) || return 1
  theirs=$(samba exec -T samba-dc cat /var/lib/samba/private/tls/ca.pem </dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || return 1
  [[ -n "$mine" && "$mine" == "$theirs" ]]
}

ldap_config_ok() { # what vault-onboard-ad.sh must have configured
  vault_cli read -format=json ldap/config | jq -e \
    --arg u "ldaps://$TEST_FQDN" --arg b "CN=svc-vault-rotator,OU=ServiceAccounts,$BASE_DN" '.data
      | .schema == "ad" and .userattr == "sAMAccountName" and .url == $u and .binddn == $b
        and .insecure_tls == false and (.certificate | startswith("-----BEGIN CERTIFICATE-----"))' >/dev/null
}

rotate_backup_ok() { # Vault can still bind: an on-demand rotation of svc-backup succeeds
  local b a
  b=$(vault_cli read -field=last_vault_rotation ldap/static-cred/svc-backup)
  vault_cli write -f ldap/rotate-role/svc-backup >/dev/null 2>&1 || return 1
  a=$(vault_cli read -field=last_vault_rotation ldap/static-cred/svc-backup)
  changed "$b" "$a"
}

onboard() { # the REAL vault-onboard-ad.sh, with only the Azure CLI stubbed (test/stub-az)
  PAM_E2E_STUB_AZ=1 PATH="$PAM_DIR/test/stub-az:$PATH" ./vault-onboard-ad.sh -k kv-e2e-stub "$@"
}
onboard_kv_denied() { PAM_E2E_STUB_KV_DENIED=1 onboard "$@"; }

static_pw_binds() { vault_cli read -field=password ldap/static-cred/svc-backup | binds svc-backup; }
static_cred_binds() { vault_cli read -field=password "ldap/static-cred/$1" | binds "$2"; }   # ROLE SAM

conn_exists() { [[ -n "$(guac_conn_id "$(guac_admin_token)" "$(conn_name "$1")")" ]]; }

conn_targets() { # conn_targets ACCOUNT IP
  [[ "$(guac_conn_param "$1" username)|$(guac_conn_param "$1" hostname)" == "$1|$2" ]]
}

conn_wiped() { local p; p=$(guac_conn_param "$1" password) || return 1; [[ -z "$p" ]]; }

injected_binds() { guac_conn_param "$1" password | binds "$1"; }

# Per-person Guacamole users (created by psm-session.sh / psm-ssh.sh).
op_tok() { guac_token "$1" < "$(operator_pw_file "$1")"; }   # op_tok OPERATOR

conn_id_by_name() { guac_conn_id "$(guac_admin_token)" "$1"; }

op_params_denied() { # op_params_denied CONNECTION-NAME OPERATOR: HTTP 403 on the connection's parameters
  local id tok code
  id=$(conn_id_by_name "$1") && [[ -n "$id" ]] || return 1
  tok=$(op_tok "$2") && [[ -n "$tok" && "$tok" != null ]] || return 1
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Guacamole-Token: $tok" \
    "$GUAC_URL/api/session/data/postgresql/connections/$id/parameters")
  [[ "$code" == 403 ]]
}

op_lists_conn() { # op_lists_conn CONNECTION-NAME OPERATOR true|false -> its GET /connections does (not) list it
  local id tok
  id=$(conn_id_by_name "$1") && [[ -n "$id" ]] || return 1
  tok=$(op_tok "$2") && [[ -n "$tok" && "$tok" != null ]] || return 1
  curl -fsS -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections" \
    | jq -e --arg id "$id" --argjson want "$3" 'has($id) == $want' >/dev/null
}

guac_user_absent() { # guac_user_absent NAME -> Guacamole answers 404
  [[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Guacamole-Token: $(guac_admin_token)" \
    "$GUAC_URL/api/session/data/postgresql/users/$1")" == 404 ]]
}

guac_login_code() { # printf '%s' PW | guac_login_code USER -> HTTP status of a LOCAL /api/tokens login
  curl -s -o /dev/null -w '%{http_code}' -X POST "$GUAC_URL/api/tokens" \
    --data-urlencode "username=$1" --data-urlencode "password@-"
}
local_login_ok()      { [[ "$(guac_login_code "$1")" == 200 ]]; }
local_login_refused() { local c; c=$(guac_login_code "$1"); [[ "$c" == 401 || "$c" == 403 ]]; }

guac_attr() { # guac_attr USER KEY -> the attribute's value ('' if unset)
  guac_user_record "$(guac_admin_token)" "$1" | jq -r --arg k "$2" '.attributes[$k] // ""'
}
set_guac_attr() { # set_guac_attr USER KEY VALUE: keeps the user's current (lab) password, from its file
  local tok rec
  tok=$(guac_admin_token)
  rec=$(guac_user_record "$tok" "$1") || return 1
  jq -Rs --argjson rec "$rec" --arg k "$2" --arg v "$3" \
      '{username: $rec.username, password: ., attributes: (($rec.attributes // {}) + {($k): (if $v == "" then null else $v end)})}' \
      < "$(operator_pw_file "$1")" \
    | curl -fsS -X PUT -H "Guacamole-Token: $tok" -H 'Content-Type: application/json' \
        "$GUAC_URL/api/session/data/postgresql/users/$1" -d @- >/dev/null
}
oidc_ensure() { ( PAM_OIDC=1 ensure_guac_operator "$1" ); }                 # the tenant-time path
lab_ensure()  { ( PAM_OIDC=0; OIDC_CLIENT_ID=""; ensure_guac_operator "$1" ); }

conjur_ok() { grep -qE 'fetched secret \([1-9][0-9]* chars' <<<"$1" && grep -q 'denied (403' <<<"$1"; }

open_accounts() { [[ -s "$STATE" ]] && jq -r 'if has("account") then .account else keys[] end' "$STATE" || true; }

library_available() { # library_available SAM [SET] -> true|false (Vault's view)
  vault_cli read -format=json "ldap/library/${2:-tier0-admins}/status" | jq -r --arg a "$1" '.data[$a].available'
}
is_available()   { [[ "$(library_available "$@")" == true ]]; }
is_checked_out() { [[ "$(library_available "$@")" == false ]]; }
both_checked_out() { is_checked_out tier0-admin-01 && is_checked_out tier0-admin-02; }
both_available()   { is_available tier0-admin-01 && is_available tier0-admin-02; }

recordings_ok() { # guacd creates a recording dir + file (its own 0750/0640), the web app reads it back
  local probe="$RECORDINGS/.e2e-probe" got
  docker compose exec -T guacd sh -c "rm -rf '$probe'; umask 027 && mkdir '$probe' && printf rec > '$probe/recording'" \
    </dev/null || return 1
  got=$(docker compose exec -T guacamole cat "$probe/recording" </dev/null 2>/dev/null || true)
  docker compose exec -T guacd rm -rf "$probe" </dev/null >/dev/null 2>&1 || log "could not remove $probe"
  [[ "$got" == rec ]]
}

recordings_mode() { docker compose exec -T guacd stat -c '%u:%g %a' "$RECORDINGS" </dev/null; }

ldap_mount_url() { vault_cli read -field=url ldap/config 2>/dev/null || true; }

# --- tickets in the ITSM mock (all marked, so --cleanup removes only ours) -------
E2E_TICKET_TAG="e2e harness"
new_ticket() { # new_ticket OPERATOR [itsm-ticket.sh options] -> the new CHG number
  local n op="$1"; shift
  n=$(./itsm-ticket.sh next)
  ./itsm-ticket.sh add "$n" --operator "$op" --short "$E2E_TICKET_TAG" "$@" >/dev/null
  echo "$n"
}

vault_audit_names() { # vault_audit_names PATH DISPLAY_NAME TICKET -> Vault's audit log has that request by that token
  docker compose exec -T vault sh -c 'tail -n 4000 /vault/logs/audit.log' </dev/null 2>/dev/null \
    | grep -F "\"$1\"" \
    | jq -e -s --arg p "$1" --arg d "$2" --arg t "$3" \
        'any(.[]; .type == "request" and .request.path == $p and .auth.display_name == $d and .auth.metadata.ticket == $t)' >/dev/null
}

vault_audit_meta() { # vault_audit_meta PATH DISPLAY_NAME KEY VALUE -> that request's token metadata has KEY=VALUE
  docker compose exec -T vault sh -c 'tail -n 4000 /vault/logs/audit.log' </dev/null 2>/dev/null \
    | grep -F "\"$1\"" \
    | jq -e -s --arg p "$1" --arg d "$2" --arg k "$3" --arg v "$4" \
        'any(.[]; .type == "request" and .request.path == $p and .auth.display_name == $d and .auth.metadata[$k] == $v)' >/dev/null
}

pam_audit_has() { # pam_audit_has EVENT key=value... -> a line in $OUT/pam-audit.jsonl matches all pairs
  local ev="$1" filter kv; shift
  filter=".event == \"$ev\""
  for kv in "$@"; do filter="$filter and .\"${kv%%=*}\" == \"${kv#*=}\""; done
  [[ -s "$OUT/pam-audit.jsonl" ]] && jq -e -s "any(.[]; $filter)" "$OUT/pam-audit.jsonl" >/dev/null
}

token_dead() { # token_dead TOKEN -> Vault no longer accepts it (lookup-self fails)
  ! VAULT_TOKEN="$1" vault_cli token lookup >/dev/null 2>&1
}

no_pending_tokens() { ! ls .secrets/psm-tokens/pending.* >/dev/null 2>&1; }

# --- discovery / onboarding / reconcile helpers ----------------------------------
discovery_pw() { cat "$TEST_SECRETS/svc-pam-discovery-password"; }
run_discover() { discovery_pw | ./discover.sh; }
run_discover_wrong() { printf 'wrong-%s' "$(openssl rand -hex 4)" | ./discover.sh; }

proposed() { # proposed SAM -> "action target" from the latest discovery
  jq -r --arg s "$1" '.accounts[] | select(.sam == $s) | "\(.proposed_action) \(.proposed_target // "-")"' "$OUT/discovery-latest.json"
}
proposed_is() { [[ "$(proposed "$1")" == "$2" ]]; }
reason_has() { jq -e --arg s "$1" --arg r "$2" '.accounts[] | select(.sam == $s) | .reason | contains($r)' "$OUT/discovery-latest.json" >/dev/null; }
in_groups() { jq -e --arg s "$1" --arg g "$2" '.accounts[] | select(.sam == $s) | .privileged_groups | index($g) != null' "$OUT/discovery-latest.json" >/dev/null; }
not_discovered() { ! jq -e --arg s "$1" 'any(.accounts[]; .sam == $s)' "$OUT/discovery-latest.json" >/dev/null; }
csv_rows_match() { [[ $(($(wc -l < "$OUT/discovery-latest.csv") - 1)) -eq $(jq '.accounts | length' "$OUT/discovery-latest.json") ]]; }

static_role_exists() { vault_cli read "ldap/static-role/$1" >/dev/null 2>&1; }
static_role_absent() { ! static_role_exists "$1"; }
library_has() { vault_cli read -format=json "ldap/library/$1" | jq -e --arg a "$2" '.data.service_account_names | index($a) != null' >/dev/null; }
policy_exists() { vault_cli policy read "$1" >/dev/null 2>&1; }

with_policy_token() { # with_policy_token POLICY CMD... : run CMD with a short-lived token holding only POLICY
  local t
  t=$(vault_cli token create -policy="$1" -no-default-policy -ttl=5m -field=token) || return 1
  VAULT_TOKEN="$t" "${@:2}"
}
safe_reads() { with_policy_token "$1" vault_cli read "ldap/static-cred/$2" >/dev/null 2>&1; }      # POLICY ROLE
safe_denied() { ! safe_reads "$@"; }
checkout_as_policy() { # checkout_as_policy POLICY SET -> 0 if that token may check out of SET (then checks it back in)
  local t acct
  t=$(vault_cli token create -policy="$1" -no-default-policy -ttl=5m -field=token) || return 1
  acct=$(VAULT_TOKEN="$t" vault_cli write -format=json "ldap/library/$2/check-out" ttl=5m 2>/dev/null | jq -r '.data.service_account_name // empty') || return 1
  [[ -n "$acct" ]] || return 1
  VAULT_TOKEN="$t" vault_cli write "ldap/library/$2/check-in" service_account_names="$acct" >/dev/null
}
checkout_denied() { ! checkout_as_policy "$@"; }

deps_with() { # deps_with JQ-EXPR -> path of a copy of the e2e dependency map, edited
  local f="$TEST_SECRETS/deps-edited.json"
  jq "$1" "$DEPS_E2E" > "$f" && echo "$f"
}

reconcile_row() { # reconcile_row ACCOUNT -> its CSV row from the latest reconcile report
  grep -F "\"$1\"," "$OUT/reconcile-latest.csv" | head -1
}
row_has() { reconcile_row "$1" | grep -qF -- "$2"; }   # row_has ACCOUNT TEXT

set_ad_password_out_of_band() { # someone resets SAM in AD directly (not through Vault); password from stdin
  samba exec -T samba-dc python3 -c '
import sys
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB
lp = LoadParm(); lp.load_default()
SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp).setpassword("(sAMAccountName=%s)" % sys.argv[1], sys.stdin.read())
' "$1"
}

exception_recorded() { # exception_recorded SAM TEXT -> pam-meta/exceptions/SAM's justification contains TEXT
  vault_cli kv get -format=json "pam-meta/exceptions/$1" 2>/dev/null | jq -e --arg t "$2" '.data.data.justification | contains($t)' >/dev/null
}

# --- RDP stand-in helpers (step g4: rdp-target, Linux xrdp + Kerberos to samba-dc) ------
RDP_REALM=CORP.TEST.LOCAL
rdpc() { docker compose --profile rdp "$@"; }
rdp_target_up() { # (re)build + recreate rdp-target (its DC mapping must be THIS run's samba-dc IP), wait healthy
  local h="" _
  rdpc up -d --build --force-recreate rdp-target >/dev/null 2>&1 || return 1
  for _ in $(seq 1 45); do
    h=$(docker inspect -f '{{.State.Health.Status}}' "$(rdpc ps -q rdp-target)" 2>/dev/null || true)
    [[ "$h" == healthy ]] && return 0
    sleep 2
  done
  return 1
}
rdp_resolves_dc() { [[ "$(rdpc exec -T rdp-target getent hosts "$TEST_FQDN" </dev/null 2>/dev/null | awk '{print $1}')" == "$1" ]]; }
rdp_logon_is_domain_only() { # SAM: no usable local password, and the RDP PAM stack authenticates with pam_krb5 alone
  [[ "$(rdpc exec -T rdp-target getent shadow "$1" </dev/null 2>/dev/null | cut -d: -f2)" == '*' ]] || return 1
  [[ "$(rdpc exec -T rdp-target sh -c 'grep -E "^auth" /etc/pam.d/xrdp-sesman' </dev/null 2>/dev/null | tr -s ' ')" \
     == "auth required pam_krb5.so minimum_uid=1000 no_ccache" ]]
}
rdp_kinit() { rdpc exec -T rdp-target kinit -c MEMORY: "$1@$RDP_REALM" 2>&1; }   # printf PW | rdp_kinit SAM
kdc_accepts() { rdp_kinit "$1" >/dev/null; }
# Refused means the KDC said "Password incorrect" (pre-authentication failed):
# an unreachable KDC or an unknown principal fails this check, so a negative
# check cannot pass by accident (as with LDAP 49 above).
kdc_refuses() { local out; if out=$(rdp_kinit "$1"); then return 1; fi; grep -q 'Password incorrect' <<<"$out"; }
rdp_conn_ok() { # CONNECTION-NAME SAM: rdp-target:3389, that account, TLS, no domain, recorded where History looks
  [[ "$(guac_conn_param_by_name "$1" hostname)|$(guac_conn_param_by_name "$1" port)|$(guac_conn_param_by_name "$1" username)" == "rdp-target|3389|$2" ]] \
    && [[ "$(guac_conn_param_by_name "$1" security)|$(guac_conn_param_by_name "$1" domain)" == "tls|" ]] \
    && [[ "$(guac_conn_param_by_name "$1" recording-path)" == "\${HISTORY_PATH}/\${HISTORY_UUID}" ]]
}
rdp_proof_has() { rdpc exec -T rdp-target cat "/home/$1/rdp-proof" </dev/null 2>/dev/null | grep -qF -- "$2"; }   # SAM TEXT
sesman_logged() { rdpc exec -T rdp-target cat /var/log/xrdp-sesman.log </dev/null 2>/dev/null | grep -qF -- "$1"; }
history_last() { # history_last CONNECTION-NAME -> its newest history entry (JSON)
  local tok id
  tok=$(guac_admin_token); id=$(guac_conn_id "$tok" "$1")
  [[ -n "$id" ]] || return 1
  curl -fsS -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections/$id/history" | jq -c 'sort_by(.startDate) | last'
}
history_recording_code() { # HISTORY_ID LOG_NAME TOKEN -> HTTP status of the History player's recording fetch
  curl -sS -o /dev/null -w '%{http_code}' -H "Guacamole-Token: $3" "$GUAC_URL/api/session/data/postgresql/history/connections/$1/logs/$2"
}
same_recording_via_history() { # HISTORY_ID LOG_NAME SHA256: the web app serves exactly the file guacd wrote
  local got
  got=$(curl -fsS -H "Guacamole-Token: $(guac_admin_token)" "$GUAC_URL/api/session/data/postgresql/history/connections/$1/logs/$2" \
        | shasum -a 256 | cut -d' ' -f1) || return 1
  [[ -n "$3" && "$got" == "$3" ]]
}
operator_cannot_fetch_recording() { local c; c=$(history_recording_code "$2" "$3" "$(op_tok "$1")"); [[ "$c" == 403 || "$c" == 404 ]]; }
recording_bigger() { [[ "$(docker compose exec -T guacamole sh -c "wc -c < '$RECORDINGS/$1/recording'" </dev/null 2>/dev/null | tr -d ' \r')" -gt "$2" ]]; }
recording_file_plays_back() { recording_file "$1" recording | python3 test/guac_recording.py --expect-size 1024x768 >/dev/null; }   # UUID
recording_plays_back() { # UUID -> the guacamole-recording format check passes; summary in $REC/rdp-recording-check.json
  recording_file "$1" recording | python3 test/guac_recording.py --expect-size 1024x768 --min-duration-ms 3000 \
    > "$REC/rdp-recording-check.json" 2> "$REC/rdp-recording-check.err"
}

# --- SSH helpers ------------------------------------------------------------------------
ssh_from_tools() { # tar of key + cert on stdin -> ssh from the pam-tools container as labadmin
  docker compose run --rm -T --no-deps --entrypoint sh pam-tools -c '
    mkdir -p /tmp/k && tar -C /tmp/k -xf - 2>/dev/null && chmod 600 /tmp/k/key
    [ -n "$1" ] && sleep "$1"
    ssh -i /tmp/k/key ${2:+-o CertificateFile=/tmp/k/key-cert.pub} -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 labadmin@ssh-target whoami' sh "$@" 2>&1
}

ssh_key_pair() { # ssh_key_pair DIR -> fresh key in DIR (0700)
  rm -rf "$1" && mkdir -p "$1" && chmod 700 "$1" && ssh-keygen -q -t ed25519 -N '' -C e2e -f "$1/key"
}

sign_key() { # sign_key DIR TTL PRINCIPAL -> DIR/key-cert.pub signed by Vault (root token: test only)
  jq -n --rawfile k "$1/key.pub" --arg t "$2" --arg p "$3" '{public_key: $k, valid_principals: $p, cert_type: "user", ttl: $t}' \
    | vault_api POST ssh-client-signer/sign/linux-admin | jq -j '.data.signed_key' > "$1/key-cert.pub"
  [[ -s "$1/key-cert.pub" ]]
}

sign_refused() { ! sign_key "$1" 5m "$2" 2>/dev/null; }   # DIR PRINCIPAL
# COPYFILE_DISABLE: macOS tar would add AppleDouble (._*) entries and xattr
# headers that GNU tar in the container warns about on stderr.
key_tar() { local d="$1"; shift; COPYFILE_DISABLE=1 tar -C "$d" -cf - "$@"; }
ssh_cert_works()   { local out; out=$(key_tar "$1" key key-cert.pub | ssh_from_tools "" cert); [[ "$(tail -n 1 <<<"$out")" == labadmin ]]; }
ssh_plain_denied() { local out; out=$(key_tar "$1" key | ssh_from_tools "" ""); grep -q 'Permission denied' <<<"$out"; }
ssh_expired_denied() { local out; out=$(key_tar "$1" key key-cert.pub | ssh_from_tools 8 cert); grep -q 'Permission denied' <<<"$out"; }

target_trusts_vault_ca() {
  local theirs ours
  ours=$(vault_api GET ssh-client-signer/config/ca | jq -r '.data.public_key' | awk '{print $2}')
  theirs=$(docker compose --profile ssh exec -T ssh-target cat /etc/ssh/trusted-user-ca-keys.pem </dev/null | awk '{print $2}')
  [[ -n "$ours" && "$ours" == "$theirs" ]]
}

ssh_history_uuid() { # newest history entry of the SSH connection: "username uuid"
  local tok id
  tok=$(guac_admin_token); id=$(guac_conn_id "$tok" "$SSH_CONN")
  curl -fsS -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections/$id/history" \
    | jq -r 'sort_by(.startDate) | last | "\(.username) \(.uuid)"'
}

recording_file() { docker compose exec -T guacamole cat "$RECORDINGS/$1/$2" </dev/null 2>/dev/null; }   # UUID FILE
typescript_has() { recording_file "$1" typescript | tr -d '\r' | grep -qF -- "$2"; }
recording_nonempty() { [[ "$(docker compose exec -T guacamole sh -c "wc -c < '$RECORDINGS/$1/recording'" </dev/null 2>/dev/null | tr -d ' \r')" -gt 1000 ]]; }

sshd_logged() { docker compose --profile ssh logs --no-log-prefix ssh-target 2>/dev/null | grep -F 'Accepted publickey for labadmin' | grep -qF -- "$1"; }

drop_test_vault_state() {
  # The harness's static role / library must not survive into a real
  # onboarding: re-writing an EXISTING static role or library set does not
  # rotate, so vault-onboard-ad.sh would silently keep test passwords.
  if vault_cli secrets list -format=json | jq -e 'has("ldap/")' >/dev/null; then
    # -force: drop check-out leases WITHOUT the check-in rotation, which
    # would otherwise hang on a DC that is already gone.
    vault_cli lease revoke -force -prefix ldap/ >/dev/null 2>&1 || log "ldap/ lease revoke reported an error (continuing: the mount is disabled next)"
    vault_cli secrets disable ldap >/dev/null
    log "Vault ldap/ mount (test DC config, roles, library) removed"
  fi
  # The exception register only ever held test-DC accounts if the harness made it.
  if [[ -f "$TEST_SECRETS/created-pam-meta" ]] && vault_cli secrets list -format=json | jq -e 'has("pam-meta/")' >/dev/null; then
    vault_cli secrets disable pam-meta >/dev/null && log "Vault pam-meta/ (test exception register) removed"
  fi
  rm -f "$STATE"
  rm -rf .secrets/psm-tokens .secrets/psm-ssh .secrets/psm-ssh.json
}

# --- arguments ----------------------------------------------------------------
MODE=run FORCE=0 SKIP_HA=0 EVIDENCE_DIR="" DR_EVIDENCE_DIR="" VERIFY_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cleanup) MODE=cleanup; shift ;;
    --force)   FORCE=1; shift ;;
    --skip-ha) SKIP_HA=1; shift ;;
    --evidence-dir) EVIDENCE_DIR="${2:?--evidence-dir DIR}"; shift 2 ;;
    --dr-evidence-dir) DR_EVIDENCE_DIR="${2:?--dr-evidence-dir DIR}"; shift 2 ;;
    --verify) VERIFY_DIR="${2:?--verify DIR}"; shift 2 ;;
    *) die "usage: $0 [--force] [--skip-ha] [--evidence-dir DIR] [--dr-evidence-dir DIR] | --verify DIR | --cleanup" ;;
  esac
done
if [[ -n "$VERIFY_DIR" ]]; then
  need jq; need shasum
  run_record_verify "$VERIFY_DIR" results.json '.result == "PASS" and .fail == 0 and (.checks | length) == .pass and .pass > 0' \
    && { log "E2E VERIFY PASSED ($(basename "$VERIFY_DIR"))"; exit 0; }
  echo "E2E VERIFY FAILED"; exit 1
fi
need docker; need jq; need curl; need openssl; need python3; need ssh-keygen
[[ -n "$EVIDENCE_DIR$DR_EVIDENCE_DIR" ]] && { need shasum; need git; }
[[ -n "$DR_EVIDENCE_DIR" && $SKIP_HA -eq 1 ]] && die "--dr-evidence-dir needs the HA/DR segment (drop --skip-ha)"
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
# The code this run uses, fingerprinted BEFORE it starts (lib.sh code_sums).
if [[ -n "$EVIDENCE_DIR" ]]; then code_sums > "$REC/code.sha256sums" || die "could not fingerprint lab/pam (needs a git checkout) - no run record without it"; fi

# --- run record (--evidence-dir) -------------------------------------------------
# Defined before the run so abort() can write a failed record.
write_record() {
  local stage
  stage=$(mktemp -d); chmod 700 "$stage"
  cp "$REC/run.log" "$stage/run.log"
  jq -R -s --arg ts "$RUN_UTC" --argjson ha "$([[ $SKIP_HA -eq 1 ]] && echo false || echo true)" \
    --arg aborted "$ABORTED" --argjson code "$(code_meta "$REC/code.sha256sums")" '
    [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], name: .[1]}] as $c
    | {schema: "contoso-pam/e2e/v2", run_utc: $ts,
       tenant: "none: local Docker only (contoso-pam stack + Samba AD DC corp.test.local, synthetic accounts)",
       ha_dr_segment: $ha,
       result: (if ([$c[] | select(.status != "PASS")] | length) == 0 and $aborted == "" then "PASS" else "FAIL" end),
       aborted: (if $aborted == "" then null else $aborted end),
       pass: ([$c[] | select(.status == "PASS")] | length), fail: ([$c[] | select(.status != "PASS")] | length),
       code: $code,
       checks: $c}' "$REC/results.tsv" > "$stage/results.json"
  cp "$REC/code.sha256sums" "$stage/code.sha256sums"
  local files=(run.log results.json code.sha256sums)
  if [[ -s "$OUT/reconcile-latest.csv" ]]; then cp "$OUT/reconcile-latest.csv" "$stage/reconcile.csv"; files+=(reconcile.csv); fi
  if [[ -s "$OUT/reconcile-latest.md" ]]; then cp "$OUT/reconcile-latest.md" "$stage/reconcile.md"; files+=(reconcile.md); fi
  if [[ -s "$REC/rdp-recording.json" ]]; then cp "$REC/rdp-recording.json" "$stage/rdp-recording.json"; files+=(rdp-recording.json); fi
  local rc=0
  RECORD_WRITTEN=1   # once, even if sealing is refused (an abort must not retry it)
  run_record_seal "$stage" "$EVIDENCE_DIR" "${files[@]}" || rc=1
  [[ $rc -eq 0 ]] && log "run record: $EVIDENCE_DIR (${files[*]}, SHA256SUMS)"
  rm -rf "$stage"
  return $rc
}

[[ -s .secrets/vault-init.json && -s .secrets/guacadmin-password ]] || die "run ./pam-up.sh first"
load_env
# The harness signs operators in with LAB passwords; under the OIDC overlay
# those must not exist (lib.sh ensure_guac_operator), so the run is refused.
! pam_oidc_mode || die "OIDC mode is on (PAM_OIDC=1 or OIDC_CLIENT_ID in .env): the harness needs lab mode - unset it for the run"
vault_unseal
export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"

# Refuse to clobber a REAL onboarding: Vault would lose the passwords only it knows.
url=$(ldap_mount_url)
if [[ $FORCE -eq 0 ]] && { [[ -n "${DC_FQDN:-}" && "$DC_FQDN" != "$TEST_FQDN" ]] || [[ -n "$url" && "$url" != "ldaps://$TEST_FQDN" ]]; }; then
  die "Vault/.env point at ${DC_FQDN:-$url} - a real DC is onboarded. Re-run with --force to replace it (its vaulted passwords would be lost)."
fi

# --- cleanup ------------------------------------------------------------------
if [[ $MODE == cleanup ]]; then
  drop_test_vault_state
  # SSH segment and HA cluster: only if the harness created them.
  if [[ -f "$TEST_SECRETS/created-ssh-ca" ]]; then
    tok=$(guac_admin_token); id=$(guac_conn_id "$tok" "$SSH_CONN")
    [[ -z "$id" ]] || curl -fsS -X DELETE -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections/$id" >/dev/null
    docker compose --profile ssh rm -sf ssh-target >/dev/null 2>&1 || true
    vault_cli secrets disable ssh-client-signer >/dev/null 2>&1 || true
    log "SSH segment removed (ssh-target, Vault ssh-client-signer/, Guacamole connection)"
  fi
  if [[ -f "$TEST_SECRETS/created-ha" && -d .secrets/ha ]]; then
    ./vault-ha.sh down --volumes >/dev/null 2>&1 || true
    log "HA cluster removed (containers, volumes, .secrets/ha)"
  fi
  # Tickets the harness raised in the ITSM mock.
  if [[ -s itsm/data/tickets.json ]]; then
    jq --arg t "$E2E_TICKET_TAG" 'map(select(.short_description != $t))' itsm/data/tickets.json > itsm/data/tickets.json.tmp \
      && chmod 644 itsm/data/tickets.json.tmp && mv itsm/data/tickets.json.tmp itsm/data/tickets.json
    log "Removed the harness's tickets from the ITSM mock"
  fi
  log "Removing samba-dc and its volume"
  samba rm -sf samba-dc >/dev/null 2>&1 || log "samba-dc container not present"
  docker volume rm -f "$SAMBA_VOLUME" >/dev/null
  rm -rf "$TEST_SECRETS" "$OUT"
  # The Guacamole connections the harness pointed at the Samba DC's IP, and
  # the RDP stand-in's (rdp-target exists only in the harness).
  tok=$(guac_admin_token)
  for a in tier0-admin-01 tier0-admin-02; do
    id=$(guac_conn_id "$tok" "$(conn_name "$a")")
    if [[ -n "$id" && -n "${DC_PUBLIC_IP:-}" && "$(guac_conn_param "$a" hostname)" == "$DC_PUBLIC_IP" ]]; then
      curl -fsS -X DELETE -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections/$id" >/dev/null
      log "Removed Guacamole connection '$(conn_name "$a")' (pointed at the test DC)"
    fi
    id=$(guac_conn_id "$tok" "$(rdp_conn_name rdp-target "$a")")
    if [[ -n "$id" ]]; then
      curl -fsS -X DELETE -H "Guacamole-Token: $tok" "$GUAC_URL/api/session/data/postgresql/connections/$id" >/dev/null
      log "Removed Guacamole connection '$(rdp_conn_name rdp-target "$a")' (the RDP stand-in)"
    fi
  done
  if docker compose --profile rdp rm -sf rdp-target >/dev/null 2>&1; then log "rdp-target (the Linux xrdp stand-in) removed"; fi
  rm -f .secrets/vault-ca/ad-root-ca.pem   # the test CA; real onboarding fetches DC01's
  # Empty values -> compose falls back to the dc01.invalid placeholder mapping.
  vault_point_at_dc "" ""
  log "Cleanup done: DC_FQDN/DC_PUBLIC_IP empty again; the rest of the stack is untouched."
  exit 0
fi

# --- (a) Samba AD DC ------------------------------------------------------------
step "(a) Samba AD DC $TEST_FQDN - fresh build + provision"
drop_test_vault_state   # clean slate, so onboarding below takes the first-run path
rm -rf "$OUT"           # this run's reports only
mkdir -p "$TEST_SECRETS"
for f in samba-admin-password svc-vault-rotator-password svc-backup-password svc-pam-discovery-password; do
  # Upper, lower, digit, symbol: satisfies AD complexity. Never printed.
  [[ -s "$TEST_SECRETS/$f" ]] || printf 'Te-%s-4K' "$(openssl rand -hex 16)" > "$TEST_SECRETS/$f"
done
if ! vault_cli secrets list -format=json | jq -e 'has("pam-meta/")' >/dev/null; then touch "$TEST_SECRETS/created-pam-meta"; fi
samba rm -sf samba-dc >/dev/null 2>&1 || true   # first run: nothing to remove
docker volume rm -f "$SAMBA_VOLUME" >/dev/null
build_out=$(samba build samba-dc 2>&1) || { printf '%s\n' "$build_out" | tail -20 | indent; abort "samba-dc image builds"; }
samba up -d samba-dc 2>&1 | indent
health=""
for _ in $(seq 1 100); do
  health=$(docker inspect -f '{{.State.Health.Status}}' "$(samba ps -q samba-dc)" 2>/dev/null || true)
  [[ "$health" == healthy ]] && break
  sleep 3
done
[[ "$health" == healthy ]] || { samba logs --tail 30 samba-dc | indent; abort "samba-dc healthy (LDAPS up, cert valid for $TEST_FQDN)"; }
pass "samba-dc healthy (LDAPS up, cert valid for $TEST_FQDN)"
samba logs --no-log-prefix samba-dc 2>&1 | { grep -E '^\[samba-ad|^  [+=]' || true; } | indent
DC_IP=$(dc_ip)
[[ -n "$DC_IP" ]] || abort "samba-dc has an IP"
check "control: guacd (no extra_hosts mapping) cannot resolve $TEST_FQDN - no DNS alias helps Vault" guacd_cannot_resolve_dc

# --- (b) first onboarding -----------------------------------------------------------
step "(b) ./vault-onboard-ad.sh (az stubbed) - first onboarding"
p0=$(pwd_last_set svc-backup)
check "pre-onboarding: svc-backup's test password binds" binds svc-backup < "$TEST_SECRETS/svc-backup-password"
must "vault-onboard-ad.sh first run" onboard -d "$TEST_DOMAIN"
check "first run read the bind password from Key Vault (stub), piped" said "Reading svc-vault-rotator's password from Key Vault"
check "AD root CA installed: parses, CRLF stripped, same certificate as the DC's" ca_installed_ok
check ".env: DC_FQDN=$TEST_FQDN DC_PUBLIC_IP=$DC_IP" env_points_at "$TEST_FQDN" "$DC_IP"
# vault-onboard-ad.sh wrote DC_FQDN / DC_PUBLIC_IP to .env in its OWN process.
# This shell still exports what .env held when load_env ran at the start, which
# is empty on a fresh stack or after --cleanup, and docker compose prefers an
# exported variable over .env. Re-read .env so every later compose call here
# (rdp-target in g4) maps the test DC, not dc01.invalid with no DC_FQDN.
load_env
check "Vault resolves $TEST_FQDN -> $DC_IP through extra_hosts" vault_resolves_dc "$DC_IP"
check "Vault unsealed after recreate" vault_unsealed
check "ldap/config: schema=ad, userattr=sAMAccountName, binddn=svc-vault-rotator, url=ldaps://$TEST_FQDN, TLS verified" ldap_config_ok

# --- (c) static role + library --------------------------------------------------------
step "(c) Onboarding rotated svc-backup (CPM moment); library ready"
p1=$(pwd_last_set svc-backup)
check "svc-backup pwdLastSet changed on onboarding ($p0 -> $p1)" changed "$p0" "$p1"
check "svc-backup's pre-onboarding password is rejected (LDAP 49)" rejected svc-backup < "$TEST_SECRETS/svc-backup-password"
check "svc-backup binds with the Vault-held password (ldap/static-cred)" static_pw_binds
for a in tier0-admin-01 tier0-admin-02; do
  check "library tier0-admins: $a available" is_available "$a"
done

# --- (d) guardrails -------------------------------------------------------------------
step "(d) vault-onboard-ad.sh guardrails"
must_fail "a second directory (-d other.test.local) is refused while ldap/ manages $TEST_FQDN" \
  "already manages" onboard -d other.test.local
check "... before touching anything (.env and ldap/config unchanged)" env_points_at "$TEST_FQDN" "$DC_IP"
check "... ldap/config still points at ldaps://$TEST_FQDN" ldap_config_ok
must_fail "--reset-bindpass with a FAILED Key Vault read stops (no empty bind password)" \
  "empty bind password" onboard_kv_denied -d "$TEST_DOMAIN" --reset-bindpass
check "Vault still binds after the refused runs (on-demand rotation of svc-backup)" rotate_backup_ok

# --- (e) --rotate-root ------------------------------------------------------------------
step "(e) ./vault-onboard-ad.sh --rotate-root (re-run), then a plain re-run"
must "vault-onboard-ad.sh --rotate-root (re-run)" onboard -d "$TEST_DOMAIN" --rotate-root
check "the re-run kept Vault's bind password (Key Vault not read)" said 'Vault keeps its bind password'
check "Key Vault's svc-vault-rotator password is rejected now (LDAP 49) - only Vault knows it" \
  rejected svc-vault-rotator < "$TEST_SECRETS/svc-vault-rotator-password"
check "Vault binds with its self-rotated password (on-demand rotation of svc-backup)" rotate_backup_ok
must "vault-onboard-ad.sh re-run after --rotate-root" onboard -d "$TEST_DOMAIN"
check "the re-run did not write the stale Key Vault password back" said 'Vault keeps its bind password'
check "Vault still binds after the re-run (on-demand rotation of svc-backup)" rotate_backup_ok
check "svc-backup binds with the newly rotated Vault password" static_pw_binds

# --- (f0) check-out gates -------------------------------------------------------------
step "(f0) Check-out gates: a named operator in the Safe + an approved, current ticket assigned to them"
check "ITSM mock (ServiceNow Table API v2 stand-in) answers" curl -fsS -o /dev/null http://127.0.0.1:8084/health
check "the shared t0-operator Guacamole user no longer exists (retired by pam-up.sh)" guac_user_absent t0-operator
# Tier 0 is under DUAL CONTROL: two distinct approvers, neither the
# requester, each allowed to approve for tier0-admins (operators.json).
T_A1=$(new_ticket ops-alice --approver ops-carol --approver ops-dana)
T_A2=$(new_ticket ops-alice --approver ops-carol --approver ops-dana)
T_C1=$(new_ticket ops-carol --approver ops-alice --approver ops-dana)
T_REQ=$(new_ticket ops-alice --approval requested)
T_OLD=$(new_ticket ops-alice --start-in-hours -10 --hours 2)
T_SCHED=$(new_ticket ops-alice --state scheduled)
T_SELF=$(new_ticket ops-alice --approver ops-alice --approver ops-carol)
T_ONE=$(new_ticket ops-alice --approver ops-carol)
T_UNAUTH=$(new_ticket ops-alice --approver ops-carol --approver ops-bob)
log "tickets: alice $T_A1 $T_A2, carol $T_C1, requested $T_REQ, expired $T_OLD, scheduled $T_SCHED, self-approved $T_SELF, one approver $T_ONE, unauthorised approver $T_UNAUTH"
must_fail "no --operator: refused (every session belongs to one person)" "needs --operator" ./psm-session.sh checkout --ticket "$T_A1"
must_fail "an operator not in operators.json: refused" "not in operators.json" ./psm-session.sh checkout --operator ops-mallory --ticket "$T_A1"
must_fail "ops-bob (Safe tier1-admins only) asking for Tier 0: refused" "not a member of tier0-admins" ./psm-session.sh checkout --operator ops-bob --ticket "$T_A1"
must_fail "no --ticket: refused (pam-policy.json tier0 require_ticket)" "needs --ticket" ./psm-session.sh checkout --operator ops-alice
must_fail "a ticket awaiting approval: refused" "not approved" ./psm-session.sh checkout --operator ops-alice --ticket "$T_REQ"
must_fail "an expired ticket (window ended 8 h ago): refused" "outside its window" ./psm-session.sh checkout --operator ops-alice --ticket "$T_OLD"
must_fail "an approved change still in Scheduled (not Implement): refused" "not in Implement" ./psm-session.sh checkout --operator ops-alice --ticket "$T_SCHED"
must_fail "someone else's ticket (alice's, used by carol): refused" "assigned to 'ops-alice', not ops-carol" ./psm-session.sh checkout --operator ops-carol --ticket "$T_A1"
must_fail "a ticket ITSM does not know: refused" "not found in ITSM" ./psm-session.sh checkout --operator ops-alice --ticket CHG0999999
must_fail "not a change number: refused" "not a change number" ./psm-session.sh checkout --operator ops-alice --ticket INC0010001
must_fail "dual control: a SELF-APPROVED Tier-0 change (alice approves her own, + carol) is refused" \
  "ops-alice (self-approval: the operator asking)" ./psm-session.sh checkout --operator ops-alice --ticket "$T_SELF"
check "... because only one approval counts (1 of 2 required)" said "has 1 of 2 required approvals"
must_fail "dual control: a SINGLE approver on a Tier-0 change is refused (1 of 2)" \
  "has 1 of 2 required approvals (tier0 dual control: 2 distinct approvers, none of them the requester)" \
  ./psm-session.sh checkout --operator ops-alice --ticket "$T_ONE"
must_fail "dual control: an approver without the Safe right (ops-bob, tier1 only) does not count" \
  "ops-bob (not an authorized approver for tier0-admins)" ./psm-session.sh checkout --operator ops-alice --ticket "$T_UNAUTH"
jq 'del(.tiers.tier0.require_ticket)' pam-policy.json > "$TEST_SECRETS/policy-no-ticket-key.json"
printf '{"tiers": ' > "$TEST_SECRETS/policy-broken.json"
must_fail "pam-policy.json WITHOUT tier0.require_ticket: refused, not 'no ticket needed' (fail closed)" "must be true or false" \
  env PAM_POLICY_FILE="$TEST_SECRETS/policy-no-ticket-key.json" ./psm-session.sh checkout --operator ops-alice
must_fail "an unparsable pam-policy.json: refused (fail closed)" "must be true or false" \
  env PAM_POLICY_FILE="$TEST_SECRETS/policy-broken.json" ./psm-session.sh checkout --operator ops-alice
jq 'del(.tiers.tier0.approvals_required)' pam-policy.json > "$TEST_SECRETS/policy-no-approvals.json"
must_fail "pam-policy.json WITHOUT tier0.approvals_required: a dual-approved ticket is still refused (fail closed)" \
  "approvals_required must be a whole number >= 1" \
  env PAM_POLICY_FILE="$TEST_SECRETS/policy-no-approvals.json" ./psm-session.sh checkout --operator ops-alice --ticket "$T_A1"
check "... and none of the refused attempts checked anything out (both Tier-0 accounts available)" both_available

# --- (f) PSM check-out ------------------------------------------------------------------
step "(f) ./psm-session.sh checkout --operator --ticket - inject into Guacamole, exclusive, per person"
declare -a ACCTS=() OPS=(ops-alice ops-carol) TICKETS=("$T_A1" "$T_C1") APPROVED=("ops-carol + ops-dana" "ops-alice + ops-dana") TOKS=()
for n in 0 1; do
  op="${OPS[$n]}" t="${TICKETS[$n]}" ap="${APPROVED[$n]}"
  before=$(open_accounts)
  must "psm-session.sh checkout #$((n + 1)) --operator $op --ticket $t (dual control: approved by $ap)" ./psm-session.sh checkout --operator "$op" --ticket "$t"
  check "dual control: two distinct approvers, neither the requester, accepted ($ap, 2 of 2)" \
    said "approved by $ap (2 of 2 required: dual control"
  acct=$(comm -13 <(sort <<<"$before") <(open_accounts | sort) | head -1)
  ACCTS+=("$acct")
  check "checkout #$((n + 1)) recorded a newly checked-out account (${acct:-none}) for $op" [ -n "$acct" ]
  check "Vault: $acct is checked out (available=false)" is_checked_out "$acct"
  check "Guacamole connection '$(conn_name "$acct")' exists" conn_exists "$acct"
  check "connection targets $acct@$DC_IP (username/hostname)" conn_targets "$acct" "$DC_IP"
  check "injected password (read back from Guacamole) binds as $acct over LDAPS" injected_binds "$acct"
  check "$op lists '$(conn_name "$acct")' (READ granted)" op_lists_conn "$(conn_name "$acct")" "$op" true
  check "$op gets 403 on that connection's parameters (cannot read the password)" op_params_denied "$(conn_name "$acct")" "$op"
  check "Vault's audit log: check-out by token display name token-psm-$op with ticket $t" \
    vault_audit_names ldap/library/tier0-admins/check-out "token-psm-$op" "$t"
  check "PAM audit line: checkout operator=$op account=$acct ticket=$t approvers=${ap// + /,}" \
    pam_audit_has checkout operator="$op" account="$acct" ticket="$t" approvers="${ap// + /,}"
  check "Vault's audit log: the check-out token carries the approvers (${ap// + /,}) in its metadata" \
    vault_audit_meta ldap/library/tier0-admins/check-out "token-psm-$op" approvers "${ap// + /,}"
  check "a per-check-out Vault token is held for the check-in (.secrets/psm-tokens/$acct)" [ -s ".secrets/psm-tokens/$acct" ]
  TOKS+=("$(cat ".secrets/psm-tokens/$acct" 2>/dev/null || true)")
done
check "2nd check-out got the other account (${ACCTS[0]} vs ${ACCTS[1]})" changed "${ACCTS[0]}" "${ACCTS[1]}"
check "isolation: ops-carol does NOT see ops-alice's connection (${ACCTS[0]})" op_lists_conn "$(conn_name "${ACCTS[0]}")" ops-carol false
check "isolation: ops-alice does NOT see ops-carol's connection (${ACCTS[1]})" op_lists_conn "$(conn_name "${ACCTS[1]}")" ops-alice false
state_before=$(open_accounts | sort | paste -sd, -)
must_fail "3rd check-out (valid ticket) refused because Vault reports the pool exhausted" \
  "no Tier-0 account available" ./psm-session.sh checkout --operator ops-alice --ticket "$T_A2"
check "... both accounts still checked out in Vault" both_checked_out
check "... the broker's check-out state unchanged ($state_before)" [ "$(open_accounts | sort | paste -sd, -)" == "$state_before" ]
check "... the refused attempt's token was revoked and not left behind" no_pending_tokens
check "... and audited as checkout-refused (pool exhausted)" pam_audit_has checkout-refused operator=ops-alice ticket="$T_A2"

# --- (g) PSM check-in -------------------------------------------------------------------
step "(g) ./psm-session.sh checkin - rotate on check-in, wipe the connection, revoke access"
must_fail "bare 'checkin' with two open check-outs asks which account" "name one" ./psm-session.sh checkin
check "... and checked nothing in (both still out in Vault)" both_checked_out
must_fail "checkin of ops-alice's account claimed by ops-carol: refused" "checked out by ops-alice, not ops-carol" \
  ./psm-session.sh checkin "${ACCTS[0]}" --operator ops-carol
check "... still checked out" is_checked_out "${ACCTS[0]}"
for i in 0 1; do
  acct="${ACCTS[$i]}" op="${OPS[$i]}"
  old=$(guac_conn_param "$acct" password || true)
  check "$acct: injected password read back before check-in" [ -n "$old" ]
  before=$(pwd_last_set "$acct")
  # First by name + operator, the last one with the bare command (single open check-out).
  if [[ $i -eq 0 ]]; then args=(checkin "$acct" --operator "$op"); else args=(checkin); fi
  if LAST_OUT=$(./psm-session.sh "${args[@]}" 2>&1); then
    printf '%s\n' "$LAST_OUT" | indent
    pass "psm-session.sh ${args[*]} ($acct)"
  else
    printf '%s\n' "$LAST_OUT" | indent
    fail "psm-session.sh ${args[*]} ($acct)"; old=""; continue
  fi
  check "$acct: the checked-out password is rejected now (LDAP 49 - rotated on check-in)" \
    rejected "$acct" < <(printf '%s' "$old")
  old=""
  after=$(pwd_last_set "$acct")
  check "$acct: pwdLastSet changed on check-in" changed "$before" "$after"
  check "$acct: Guacamole connection password wiped" conn_wiped "$acct"
  check "$acct: $op no longer lists the connection (READ removed)" op_lists_conn "$(conn_name "$acct")" "$op" false
  check "$acct: back in the library (available=true)" is_available "$acct"
  check "$acct: the check-out token is revoked (Vault rejects it)" token_dead "${TOKS[$i]}"
  check "$acct: PAM audit line checkin operator=$op" pam_audit_has checkin operator="$op" account="$acct"
done
TOKS=()
check "no check-outs left in $STATE" [ -z "$(open_accounts)" ]

# --- (g3) OIDC mode ----------------------------------------------------------------------
step "(g3) OIDC mode (PAM_OIDC=1): no operator keeps a working local Guacamole password"
# ops-carol has a lab password from (f). In OIDC mode that password would be a
# way around Entra MFA / Conditional Access, because /api/tokens takes local
# credentials whatever the login page shows.
cp "$(operator_pw_file ops-carol)" "$TEST_SECRETS/carol-lab-password"
check "control: ops-carol's lab password gets a token from /api/tokens (HTTP 200)" local_login_ok ops-carol < "$TEST_SECRETS/carol-lab-password"
check "an admin-set attribute on ops-carol (guac-organization=e2e-oidc-marker)" set_guac_attr ops-carol guac-organization e2e-oidc-marker
must "OIDC mode: ensure_guac_operator ops-carol (record exists)" oidc_ensure ops-carol
check "... the old local password is refused by /api/tokens now (HTTP 401/403)" local_login_refused ops-carol < "$TEST_SECRETS/carol-lab-password"
check "... the lab password file is deleted (nothing on the broker host)" [ ! -e "$(operator_pw_file ops-carol)" ]
check "... the user record still exists (grants can attach to it)" guac_user_exists "$(guac_admin_token)" ops-carol
check "... the admin-set attribute survived the password overwrite" [ "$(guac_attr ops-carol guac-organization)" == e2e-oidc-marker ]
must_fail "OIDC mode: someone who never signed in through Entra gets NO local user" "sign in through Entra first" oidc_ensure ops-oidc-never
check "... Guacamole has no ops-oidc-never user" guac_user_absent ops-oidc-never
check "... and no password file was written" [ ! -e "$(operator_pw_file ops-oidc-never)" ]
must "back to lab mode: ops-carol gets a fresh local password (PUT keeps attributes)" lab_ensure ops-carol
check "... the attribute survived the lab-mode reset too" [ "$(guac_attr ops-carol guac-organization)" == e2e-oidc-marker ]
check "... the new lab password works and the old one still does not" local_login_ok ops-carol < "$(operator_pw_file ops-carol)"
check "... (old one: refused)" local_login_refused ops-carol < "$TEST_SECRETS/carol-lab-password"
set_guac_attr ops-carol guac-organization "" || log "could not clear the e2e marker attribute on ops-carol"
rm -f "$TEST_SECRETS/carol-lab-password"

# --- (g2) recordings ----------------------------------------------------------------------
step "(g2) Guacamole recordings volume"
check "recordings dir is guacd:guacamole 2750 ($(recordings_mode 2>/dev/null || echo '?'))" [ "$(recordings_mode)" == "1000:1001 2750" ]
check "guacd can write a recording there and the web app can read it back" recordings_ok

# --- (g4) RDP without DC01 ----------------------------------------------------------------
# rdp-target is a LINUX xrdp STAND-IN for an RDP session to DC01 (Samba has no
# RDP): not Windows, but the same broker path - dual-approved ticket, Vault
# check-out, password injected into a recorded Guacamole RDP connection the
# operator can use but not read, a real RDP logon with that AD password
# (Kerberos to samba-dc), rotate on check-in.
step "(g4) RDP without DC01: brokered, recorded RDP session to rdp-target (Linux xrdp stand-in for DC01)"
must "rdp-target builds and starts (Debian xrdp + xorgxrdp; AD logon by Kerberos to $TEST_FQDN)" rdp_target_up
check "rdp-target resolves $TEST_FQDN -> $DC_IP only through the .env mapping (as Vault does)" rdp_resolves_dc "$DC_IP"
check "rdp-target: no local password opens a session (shadow '*', PAM auth = pam_krb5 only)" rdp_logon_is_domain_only tier0-admin-01
check "control: the KDC refuses a wrong password for tier0-admin-01 ('Password incorrect', not unreachable)" \
  kdc_refuses tier0-admin-01 < <(printf 'Wrong-%s-1' "$(openssl rand -hex 6)")
T_R1=$(new_ticket ops-alice --approver ops-carol --approver ops-dana)
before=$(open_accounts)
must "psm-session.sh checkout --operator ops-alice --ticket $T_R1 --target rdp-target (dual control: ops-carol + ops-dana)" \
  ./psm-session.sh checkout --operator ops-alice --ticket "$T_R1" --target rdp-target
RACCT=$(comm -13 <(sort <<<"$before") <(open_accounts | sort) | head -1)
RCONN=$(rdp_conn_name rdp-target "${RACCT:-none}")
[[ -n "$RACCT" ]] || abort "the rdp-target check-out recorded an account"
pass "checked out $RACCT for ops-alice -> '$RCONN'"
check "the connection targets rdp-target:3389 as $RACCT over TLS (xrdp has no NLA), no domain, recorded where History looks" \
  rdp_conn_ok "$RCONN" "$RACCT"
check "ops-alice lists '$RCONN' (READ)" op_lists_conn "$RCONN" ops-alice true
check "ops-alice gets 403 on its parameters (never sees the password)" op_params_denied "$RCONN" ops-alice
check "ops-carol does not see it" op_lists_conn "$RCONN" ops-carol false
check "PAM audit line: checkout target=rdp-target account=$RACCT approvers=ops-carol,ops-dana" \
  pam_audit_has checkout operator=ops-alice account="$RACCT" target=rdp-target approvers=ops-carol,ops-dana ticket="$T_R1"
RPW_FILE="$TEST_SECRETS/rdp-injected-password"
guac_conn_param_by_name "$RCONN" password > "$RPW_FILE" || true
check "the injected Vault password gets a Kerberos TGT for $RACCT from the DC (kinit on rdp-target)" kdc_accepts "$RACCT" < "$RPW_FILE"
rdpc exec -T rdp-target rm -f "/home/$RACCT/rdp-proof" </dev/null >/dev/null 2>&1 || true
sess=$(op_tok ops-alice)
if LAST_OUT=$(printf '%s' "$sess" | python3 test/guac_tunnel.py --base "$GUAC_URL" --connection-id "$(conn_id_by_name "$RCONN")" \
     --mouse 512,384 --settle 12 --type "id > rdp-proof; hostname >> rdp-proof; exit" --timeout 120 2>&1); then
  printf '%s\n' "$LAST_OUT" | indent
  pass "a real RDP session through Guacamole as ops-alice (HTTP tunnel, xrdp autologon with the injected credential, keys typed)"
else
  printf '%s\n' "$LAST_OUT" | indent; fail "a real RDP session through Guacamole as ops-alice"
fi
sess=""
check "... and the server ended it when the typed 'exit' closed the session" said "the server ended it"
RH=$(history_last "$RCONN" || echo '{}')
RUSER=$(jq -r '.username // ""' <<<"$RH"); RUUID=$(jq -r '.uuid // ""' <<<"$RH"); RHID=$(jq -r '.identifier // ""' <<<"$RH")
RLOG=$(jq -r '(.logs // {}) | keys[0] // ""' <<<"$RH")
check "Guacamole history: the session belongs to ops-alice ($RUSER)" [ "$RUSER" == ops-alice ]
check "inside the session the typed 'id' ran AS THE AD ACCOUNT ($RACCT) on rdp-target" rdp_proof_has "$RACCT" "($RACCT) gid="
check "... and 'hostname' printed rdp-target" rdp_proof_has "$RACCT" rdp-target
check "xrdp-sesman: the Kerberos logon was accepted for $RACCT" sesman_logged "Received sys login status for $RACCT : logged in"
check "xrdp-sesman: the session ended when its window manager (the xterm) exited" sesman_logged "finished normally"
check "graphical recording written for the session (> 10 KB)" recording_bigger "$RUUID" 10000
if recording_plays_back "$RUUID"; then
  pass "the recording PLAYS BACK: guacamole-recording format check (framing, 1024x768 screen, decodable images, timed frames, screen painted)"
  jq -c '{bytes, frames, duration_ms, images, screen_painted_pct}' "$REC/rdp-recording-check.json" | indent
else
  fail "the recording plays back (guacamole-recording format check)"; indent < "$REC/rdp-recording-check.err"
fi
RSHA=$(jq -r '.sha256 // ""' "$REC/rdp-recording-check.json" 2>/dev/null || true)
check "the web app's History lists it for the session (type GUACAMOLE_SESSION_RECORDING)" \
  [ "$(jq -r --arg l "$RLOG" '.logs[$l].type // ""' <<<"$RH")" == GUACAMOLE_SESSION_RECORDING ]
check "... and serves its player the SAME bytes guacd wrote (History API, sha256 ${RSHA:0:16}...)" same_recording_via_history "$RHID" "$RLOG" "$RSHA"
check "... while ops-alice cannot fetch the recording of her own session (403/404: playback is for reviewers)" \
  operator_cannot_fetch_recording ops-alice "$RHID" "$RLOG"
must "psm-session.sh checkin $RACCT --operator ops-alice (rotate on check-in)" ./psm-session.sh checkin "$RACCT" --operator ops-alice
check "after check-in the KDC refuses the password used in the session ('Password incorrect': rotated)" kdc_refuses "$RACCT" < "$RPW_FILE"
rm -f "$RPW_FILE"
check "'$RCONN' password wiped" [ -z "$(guac_conn_param_by_name "$RCONN" password)" ]
check "ops-alice no longer lists it (READ removed)" op_lists_conn "$RCONN" ops-alice false
check "$RACCT back in the library (available=true)" is_available "$RACCT"
check "PAM audit line: checkin target=rdp-target account=$RACCT" pam_audit_has checkin operator=ops-alice account="$RACCT" target=rdp-target
# For the run record: what was recorded and checked - never the recording itself.
# The history UUID stays out: GUID-shaped values fail the public release
# gate's GUID allowlist; the integer history id names the session.
jq -n --slurpfile r "$REC/rdp-recording-check.json" --arg c "$RCONN" --arg a "$RACCT" --arg t "$T_R1" --arg h "$RHID" '
  {schema: "contoso-pam/e2e-rdp-recording/v1",
   target: "rdp-target: a LINUX xrdp stand-in for an RDP session to DC01 (Samba AD has no RDP); not Windows",
   connection: $c, operator: "ops-alice", account: $a, ticket: $t, approvers: ["ops-carol", "ops-dana"],
   logon: "the Vault-injected AD password, verified by Kerberos against the Samba AD DC",
   guacamole_history_id: $h,
   recording: ($r[0] // null),
   played_back_by: ["test/guac_recording.py (guacamole-recording format check)",
                    "Guacamole History API served the same bytes (sha256) to its player"],
   not_done: "no video encode: guacenc is not in the guacamole/guacd:1.6.0 image and Debian trixie does not package it"}' \
  > "$REC/rdp-recording.json" 2>/dev/null || rm -f "$REC/rdp-recording.json"

# --- (h) Conjur ---------------------------------------------------------------------
step "(h) ./conjur-demo.sh"
if LAST_OUT=$(./conjur-demo.sh 2>&1); then
  printf '%s\n' "$LAST_OUT" | indent
  check "conjur-demo.sh: nightly-report fetched, unapproved-job denied (403)" conjur_ok "$LAST_OUT"
else
  printf '%s\n' "$LAST_OUT" | indent
  fail "conjur-demo.sh exited non-zero"
fi

# --- (i) midPoint -------------------------------------------------------------------
step "(i) midPoint REST (administrator / MIDPOINT_ADMIN_PASSWORD)"
mp_curl() { # MP_PW=... mp_curl PATH [curl args] - credentials via curl config on stdin, not argv
  local pw="${MP_PW//\\/\\\\}"; pw="${pw//\"/\\\"}"
  printf 'user = "administrator:%s"\n' "$pw" \
    | curl -sS -K - -H 'Accept: application/json' "http://127.0.0.1:8082/midpoint/ws/rest/$1" "${@:2}"
}
mp_status() { MP_PW="$1" mp_curl self -o /dev/null -w '%{http_code}' 2>/dev/null || true; }
# A fresh midPoint takes a few minutes to boot after ./pam-up.sh.
status=""
for _ in $(seq 1 80); do
  status=$(mp_status "$MIDPOINT_ADMIN_PASSWORD")
  [[ "$status" == 200 || "$status" == 401 ]] && break
  sleep 3
done
check "GET /midpoint/ws/rest/self as administrator -> 200 (got $status)" [ "$status" == 200 ]
check "... and with a wrong password -> 401 (auth really enforced)" [ "$(mp_status "wrong-$(openssl rand -hex 4)")" == 401 ]
connectors=$(MP_PW="$MIDPOINT_ADMIN_PASSWORD" mp_curl connectors -f | jq -r '[.. | objects | select(has("connectorType"))]
  | map("\(.connectorType)  bundle=\(.connectorBundle)  version=\(.connectorVersion)") | .[]' || true)
if [[ -n "$connectors" ]]; then
  pass "GET /midpoint/ws/rest/connectors lists $(wc -l <<<"$connectors" | tr -d ' ') connectors"
  printf '%s\n' "$connectors" | indent
  if grep -qi 'msgraph' <<<"$connectors"; then
    log "INFO  Microsoft Graph connector IS bundled: $(grep -i msgraph <<<"$connectors" | head -1)"
  else
    log "INFO  Microsoft Graph connector is NOT bundled in this image - deploy com.evolveum.polygon:connector-msgraph (README, midPoint section)"
  fi
else
  fail "GET /midpoint/ws/rest/connectors lists connectors"
fi

# --- (j) discovery -------------------------------------------------------------------
step "(j) ./discover.sh - privileged-account discovery (read-only bind as svc-pam-discovery)"
must_fail "a wrong discovery password is refused by the DC (invalidCredentials), no report written" \
  "invalidCredentials" run_discover_wrong
check "... and no discovery report exists yet" [ ! -s "$OUT/discovery-latest.json" ]
must "discover.sh (bind password on stdin)" run_discover
check "report written: $OUT/discovery-latest.{json,csv}, one CSV row per account" csv_rows_match
check "svc-iis-app (SPN HTTP/...) -> static role svc/svc-iis-app" proposed_is svc-iis-app "static svc/svc-iis-app"
check "svc-sql01 (SPN MSSQLSvc/...) -> static role svc/svc-sql01" proposed_is svc-sql01 "static svc/svc-sql01"
check "svc-backup (service OU) -> static role svc/svc-backup" proposed_is svc-backup "static svc/svc-backup"
check "t1-srvadmin-01 (Tier1-Server-Admins) -> library tier1-admins" proposed_is t1-srvadmin-01 "library tier1-admins"
check "t1-srvadmin-02 (Tier1-Server-Admins) -> library tier1-admins" proposed_is t1-srvadmin-02 "library tier1-admins"
check "tier0-admin-01 (Domain Admins) -> library tier0-admins" proposed_is tier0-admin-01 "library tier0-admins"
check "svc-legacy-da (SPN + Domain Admins) -> exception: Kerberoastable Tier 0" reason_has svc-legacy-da "Kerberoastable"
check "t0-stale-admin -> exception: stale privileged (last logon 400 days ago)" reason_has t0-stale-admin "last logon 400d ago"
check "t0-never-admin -> exception: never logged on, created 200 days ago" reason_has t0-never-admin "never logged on, created 200d ago"
check "t0-never-admin found through NESTED membership (Tier0-Nested-Ops -> Administrators)" in_groups t0-never-admin Administrators
check "former-admin-01 -> exception: orphaned adminCount" reason_has former-admin-01 "orphaned adminCount"
check "Administrator found via primaryGroupID/membership and excluded by policy (break-glass)" reason_has Administrator "policy exclusion"
check "krbtgt excluded by policy (KDC account)" reason_has krbtgt "policy exclusion"
check "svc-vault-rotator excluded by policy (Vault's own bind account)" reason_has svc-vault-rotator "policy exclusion"
check "svc-pam-discovery excluded by policy (the discovery account itself)" reason_has svc-pam-discovery "policy exclusion"
check "Guest (not privileged, no SPN, not in a PAM OU) is not a candidate" not_discovered Guest

# --- (k) onboarding -------------------------------------------------------------------
step "(k) ./onboard.sh - bulk onboarding via the Vault API, a Safe (policy) per tier"
pk_iis=$(pwd_last_set svc-iis-app); pk_sql=$(pwd_last_set svc-sql01)
pk_t1a=$(pwd_last_set t1-srvadmin-01); pk_t1b=$(pwd_last_set t1-srvadmin-02); pk_stale=$(pwd_last_set t0-stale-admin)
must "onboard.sh --dry-run" ./onboard.sh --dry-run --deps "$DEPS_E2E"
check "dry run: svc-sql01 shown as HELD (unresolved dependencies)" said "HELD - windows-service MSSQLSERVER"
deps_t1=$(deps_with '.accounts["t1-srvadmin-01"] = [{"type": "scheduled-task", "host": "app01.corp.test.local", "name": "\\Contoso\\RunAsAdmin", "owner": "app-team", "resolved": false}]')
must "onboard.sh --dry-run with a scheduled task running as t1-srvadmin-01" ./onboard.sh --dry-run --deps "$deps_t1"
check "dry run: library candidate t1-srvadmin-01 HELD too (tier1 dependency_check)" said "HELD - scheduled-task"
deps_t1=$(deps_with 'del(.accounts["t1-srvadmin-02"])')
must "onboard.sh --dry-run with NO dependency record for t1-srvadmin-02" ./onboard.sh --dry-run --deps "$deps_t1"
check "dry run: t1-srvadmin-02 HELD (unknown is not 'none')" said "HELD - no dependency record for t1-srvadmin-02"
check "dry run changed nothing (no static role svc/svc-iis-app)" static_role_absent svc/svc-iis-app
must_fail "--force without --only is refused (one account per override)" "needs --only" ./onboard.sh --force --justification "CHG0012345 blanket override attempt"
must_fail "--force without a justification is refused" "needs --justification" ./onboard.sh --only svc-sql01 --force --deps "$DEPS_E2E"
must_fail "a justification without a change number is refused" "must reference a change number" \
  ./onboard.sh --only svc-sql01 --force --justification "because the DBA said it is fine" --deps "$DEPS_E2E"
must "onboard.sh (bulk)" ./onboard.sh --deps "$DEPS_E2E"
check "static role svc/svc-iis-app created" static_role_exists svc/svc-iis-app
check "svc-iis-app rotated on onboarding (pwdLastSet changed)" changed "$pk_iis" "$(pwd_last_set svc-iis-app)"
check "svc-iis-app binds with the Vault-held password" static_cred_binds svc/svc-iis-app svc-iis-app
check "svc-sql01 HELD: no static role" static_role_absent svc/svc-sql01
check "svc-sql01 HELD: password untouched (pwdLastSet unchanged)" same "$pk_sql" "$(pwd_last_set svc-sql01)"
check "library tier1-admins holds t1-srvadmin-01" library_has tier1-admins t1-srvadmin-01
check "library tier1-admins holds t1-srvadmin-02" library_has tier1-admins t1-srvadmin-02
check "t1-srvadmin-01 got a new password on onboarding" changed "$pk_t1a" "$(pwd_last_set t1-srvadmin-01)"
check "t1-srvadmin-02 got a new password on onboarding" changed "$pk_t1b" "$(pwd_last_set t1-srvadmin-02)"
check "exception t0-stale-admin untouched (pwdLastSet unchanged)" same "$pk_stale" "$(pwd_last_set t0-stale-admin)"
check "existing svc-backup (flat static role) recognised as already vaulted" said "already a static role"
for p in tier0-checkout tier1-checkout tier0-static-read tier1-static-read svc-static-read pam-reconcile; do
  check "Safe policy $p exists" policy_exists "$p"
done
check "Safe svc: a svc-static-read token reads svc/svc-iis-app" safe_reads svc-static-read svc/svc-iis-app
check "Safe svc: the same token cannot read svc-backup (outside svc/*)" safe_denied svc-static-read svc-backup
check "Safe tier1: a tier1-checkout token can check out of tier1-admins (and back in)" checkout_as_policy tier1-checkout tier1-admins
check "Safe tier1: the same token cannot check out of tier0-admins" checkout_denied tier1-checkout tier0-admins
must "onboard.sh re-run (idempotent)" ./onboard.sh --deps "$DEPS_E2E"
check "re-run: svc-iis-app and the tier1 library reported as already vaulted" said "already in the library"
pk_iis=$(pwd_last_set svc-iis-app)

# --- (l) rotation dependency gate -----------------------------------------------------
step "(l) ./rotate.sh - rotation gated on dependencies"
must "rotate.sh svc-iis-app (its one consumer reads from Vault)" ./rotate.sh svc-iis-app --deps "$DEPS_E2E"
check "svc-iis-app rotated (pwdLastSet changed)" changed "$pk_iis" "$(pwd_last_set svc-iis-app)"
check "svc-iis-app binds with the new Vault password" static_cred_binds svc/svc-iis-app svc-iis-app
pk_iis=$(pwd_last_set svc-iis-app)
deps_unres=$(deps_with '.accounts["svc-iis-app"] += [{"type": "scheduled-task", "host": "app01.corp.test.local", "name": "\\Contoso\\ExportJob", "owner": "app-team", "resolved": false}]')
must_fail "a new UNRESOLVED consumer (scheduled task) -> rotation refused" "REFUSED" ./rotate.sh svc-iis-app --deps "$deps_unres"
check "... and the refusal names it" said "scheduled-task \\\\Contoso\\\\ExportJob on app01"
check "... password untouched (pwdLastSet unchanged)" same "$pk_iis" "$(pwd_last_set svc-iis-app)"
check "... audited as rotate-refused" pam_audit_has rotate-refused account=svc-iis-app
deps_none=$(deps_with 'del(.accounts["svc-iis-app"])')
must_fail "NO dependency record (unknown is not 'none') -> rotation refused" "no dependency record" ./rotate.sh svc-iis-app --deps "$deps_none"
must_fail "a library (check-out) account is not rotated here" "not managed by a static role" ./rotate.sh t1-srvadmin-01 --deps "$DEPS_E2E"
# The Windows side of dependency discovery (services / tasks / app pools)
# needs a Windows server; its matching and output contract run here offline.
if command -v pwsh >/dev/null 2>&1; then
  pester_ok() {
    # shellcheck disable=SC2016 # $c / $r are PowerShell variables, expanded by pwsh
    pwsh -NoProfile -Command '$c = New-PesterConfiguration; $c.Run.Path = "test/Get-AccountDependencies.Tests.ps1";
      $c.Run.PassThru = $true; $c.Output.Verbosity = "None"; $r = Invoke-Pester -Configuration $c;
      if ($r.FailedCount -gt 0 -or $r.PassedCount -eq 0) { exit 1 }' >/dev/null 2>&1
  }
  check "dependency-scan/Get-AccountDependencies.ps1: Pester (run-as matching, map contract) passes" pester_ok
else
  log "INFO  pwsh not installed - skipping the Pester test of the Windows dependency scan"
fi

# --- (m) reconciliation -------------------------------------------------------------------
step "(m) ./reconcile.sh - discovered vs vaulted vs rotated vs exception (+ CPM verify)"
must "reconcile.sh --verify --strict (GAP 0, ORPHAN 0, all rotated in policy, all verified)" ./reconcile.sh --verify --strict --deps "$DEPS_E2E"
check "report KPIs: GAP 0" grep -qF '| **GAP** (not vaulted, no exception) | **0** |' "$OUT/reconcile-latest.md"
check "svc-iis-app: VAULTED, rotated within policy, verified" row_has svc-iis-app '"VAULTED","static:svc/svc-iis-app"'
check "... verified=yes (its vaulted password binds)" row_has svc-iis-app '"yes","yes"'
check "svc-sql01: HELD with its unresolved dependencies" row_has svc-sql01 '"HELD"'
check "t1-srvadmin-01: VAULTED in library tier1-admins" row_has t1-srvadmin-01 '"VAULTED","library:tier1-admins"'
check "t0-stale-admin: EXCEPTION (documented reason)" row_has t0-stale-admin '"EXCEPTION"'
printf 'Ob-%s-9Z' "$(openssl rand -hex 16)" | set_ad_password_out_of_band svc-iis-app
must_fail "after an out-of-band reset of svc-iis-app in AD, --verify --strict fails (CPM verify)" "failed-verify=1" \
  ./reconcile.sh --verify --strict --deps "$DEPS_E2E"
check "... svc-iis-app verified=no" row_has svc-iis-app '"yes","no"'
must "rotate.sh svc-iis-app repairs it (Vault resets it with the reconcile account)" ./rotate.sh svc-iis-app --deps "$DEPS_E2E"
must "reconcile.sh --verify --strict passes again" ./reconcile.sh --verify --strict --deps "$DEPS_E2E"
pk_sql=$(pwd_last_set svc-sql01)
must "onboard.sh --only svc-sql01 --force with a change-referenced justification" \
  ./onboard.sh --only svc-sql01 --force --justification "CHG0031337: DBA updates the MSSQLSERVER logon in the window" --operator ops-alice --deps "$DEPS_E2E"
check "svc-sql01 now a static role, rotated (pwdLastSet changed)" changed "$pk_sql" "$(pwd_last_set svc-sql01)"
check "the override is in Vault's exception register (pam-meta/exceptions/svc-sql01)" exception_recorded svc-sql01 CHG0031337
check "... and audited as override by ops-alice" pam_audit_has override account=svc-sql01 by=ops-alice
must "reconcile.sh after the override" ./reconcile.sh --deps "$DEPS_E2E"
check "svc-sql01: VAULTED, the forced override shown on the row" row_has svc-sql01 'onboard-forced by ops-alice'
samba exec -T samba-dc samba-tool user delete svc-iis-app </dev/null >/dev/null 2>&1
must "discover.sh after svc-iis-app was deleted in AD" run_discover
must_fail "reconcile --strict: the deleted account is an ORPHAN in Vault" "ORPHAN=1" ./reconcile.sh --strict --deps "$DEPS_E2E"
check "svc-iis-app row: ORPHAN, static:svc/svc-iis-app" row_has svc-iis-app '"ORPHAN","static:svc/svc-iis-app"'
vault_cli delete ldap/static-role/svc/svc-iis-app >/dev/null
must "reconcile --strict after removing the orphaned static role" ./reconcile.sh --strict --deps "$DEPS_E2E"

# --- (n) SSH CA + recorded SSH session ---------------------------------------------------
step "(n) ./psm-ssh.sh - Vault SSH CA, ephemeral certificate, recorded SSH through Guacamole"
if ! vault_cli secrets list -format=json | jq -e 'has("ssh-client-signer/")' >/dev/null; then touch "$TEST_SECRETS/created-ssh-ca"; fi
must "psm-ssh.sh setup" ./psm-ssh.sh setup
check "ssh-target trusts exactly Vault's SSH CA public key" target_trusts_vault_ca
SSHK="$TEST_SECRETS/ssh"
ssh_key_pair "$SSHK"
check "a plain key without a certificate is refused by sshd" ssh_plain_denied "$SSHK"
check "Vault refuses to sign principal root (allowed_users = linux-admin)" sign_refused "$SSHK" root
check "Vault signs a 5-minute certificate for principal linux-admin" sign_key "$SSHK" 5m linux-admin
check "... and it logs in to ssh-target as labadmin (plain OpenSSH client, no Guacamole)" ssh_cert_works "$SSHK"
check "Vault signs a 3-second certificate" sign_key "$SSHK" 3s linux-admin
check "... which sshd refuses once expired (used after 8 s)" ssh_expired_denied "$SSHK"
rm -rf "$SSHK"
# Tier 1 keeps ONE approver: authorised for linux-admin, not the requester.
T_S1=$(new_ticket ops-alice --approver ops-bob)
T_S_NONE=$(new_ticket ops-alice)
T_S_SELF=$(new_ticket ops-bob --approver ops-bob)
must_fail "ops-carol (no SSH role in operators.json) is refused" "not a member of linux-admin" ./psm-ssh.sh checkout --operator ops-carol --ticket "$T_S1"
must_fail "Tier 1: a change with NO approver is refused (0 of 1)" "has 0 of 1 required approvals" \
  ./psm-ssh.sh checkout --operator ops-alice --ticket "$T_S_NONE"
must_fail "Tier 1: a SELF-APPROVED change (bob approves his own) is refused" "ops-bob (self-approval: the operator asking)" \
  ./psm-ssh.sh checkout --operator ops-bob --ticket "$T_S_SELF"
must_fail "no ticket is refused (tier1 require_ticket)" "needs --ticket" ./psm-ssh.sh checkout --operator ops-alice
must_fail "an expired ticket is refused for SSH too (validation failure stops the check-out)" "outside its window" \
  ./psm-ssh.sh checkout --operator ops-alice --ticket "$T_OLD"
check "... and nothing was checked out (no SSH state file)" [ ! -s .secrets/psm-ssh.json ]
must "psm-ssh.sh checkout --operator ops-alice --ticket $T_S1 (Tier 1: one approver, ops-bob)" ./psm-ssh.sh checkout --operator ops-alice --ticket "$T_S1"
check "Tier 1: a single authorised approver is accepted (ops-bob, 1 of 1)" said "approved by ops-bob (1 of 1 required: 1 approver, not the requester)"
SERIAL=$(jq -r .serial .secrets/psm-ssh.json); KEYID=$(jq -r .key_id .secrets/psm-ssh.json)
check "certificate key ID carries the operator (token-psm-ops-alice-linux-admin)" [ "$KEYID" == token-psm-ops-alice-linux-admin ]
check "ops-alice lists '$SSH_CONN' (READ)" op_lists_conn "$SSH_CONN" ops-alice true
check "ops-alice gets 403 on its parameters (cannot read key or certificate)" op_params_denied "$SSH_CONN" ops-alice
check "ops-carol does not see the SSH connection" op_lists_conn "$SSH_CONN" ops-carol false
sess=$(op_tok ops-alice)
if LAST_OUT=$(printf '%s' "$sess" | python3 test/guac_tunnel.py --base "$GUAC_URL" \
     --connection-id "$(conn_id_by_name "$SSH_CONN")" --type "id; hostname; exit" --timeout 60 2>&1); then
  printf '%s\n' "$LAST_OUT" | indent; pass "a real SSH session through Guacamole as ops-alice (HTTP tunnel, keys typed, session ended)"
else
  printf '%s\n' "$LAST_OUT" | indent; fail "a real SSH session through Guacamole as ops-alice"
fi
sess=""
read -r HUSER HUUID <<<"$(ssh_history_uuid)"
check "Guacamole history: the session belongs to ops-alice ($HUSER)" [ "$HUSER" == ops-alice ]
check "typescript (text recording) shows the command output: uid=1000(labadmin)" typescript_has "$HUUID" "uid=1000(labadmin)"
check "typescript shows the target's hostname (ssh-target)" typescript_has "$HUUID" "ssh-target"
check "graphical recording written for the same session (> 1 KB)" recording_nonempty "$HUUID"
check "... and it plays back (guacamole-recording format check: framing, 1024x768 screen, decodable images, timed frames, screen painted)" \
  recording_file_plays_back "$HUUID"
check "sshd on the target logged the login with ID $KEYID (serial $SERIAL)" sshd_logged "ID $KEYID (serial $SERIAL)"
check "PAM audit line: ssh-checkout operator=ops-alice approvers=ops-bob cert_serial=$SERIAL" pam_audit_has ssh-checkout operator=ops-alice approvers=ops-bob cert_serial="$SERIAL"
must "psm-ssh.sh checkin --operator ops-alice" ./psm-ssh.sh checkin --operator ops-alice
check "connection private key wiped" [ -z "$(guac_conn_param_by_name "$SSH_CONN" private-key)" ]
check "connection certificate wiped" [ -z "$(guac_conn_param_by_name "$SSH_CONN" public-key)" ]
check "ops-alice no longer sees the SSH connection" op_lists_conn "$SSH_CONN" ops-alice false

# --- (o) HA / DR -----------------------------------------------------------------------------
if [[ $SKIP_HA -eq 1 ]]; then
  step "(o) Vault HA / DR - SKIPPED (--skip-ha)"
else
  step "(o) ./vault-ha.sh + ./dr-drill.sh - 3-node Raft, failover, timed DR drill, rolling upgrade"
  [[ -s .secrets/ha/init.json ]] || touch "$TEST_SECRETS/created-ha"
  must "vault-ha.sh up" ./vault-ha.sh up
  check "3 voters, autopilot healthy, failure tolerance 1" said "autopilot healthy=true failure_tolerance=1"
  must "vault-ha.sh failover (SIGKILL the leader)" ./vault-ha.sh failover
  check "a new leader accepted a write" said "FAILOVER: new leader"
  check "the killed node auto-unsealed and rejoined as a healthy voter" said "REJOIN:"
  check "new leader differs from the killed one" jq -e '.old_leader != .new_leader' .secrets/ha/last-failover.json
  if [[ -n "$DR_EVIDENCE_DIR" ]]; then
    must "dr-drill.sh (snapshot -> destroy all nodes + disks -> restore), run record -> $DR_EVIDENCE_DIR" ./dr-drill.sh --evidence-dir "$DR_EVIDENCE_DIR"
  else
    must "dr-drill.sh (snapshot -> destroy all nodes + disks -> restore)" ./dr-drill.sh
  fi
  check "DR: marker restored, policy restored, post-snapshot write lost (RPO shown), RTO within target" \
    said "marker PASS, policy PASS, post-snapshot write lost PASS, RTO PASS"
  check "DR report written with a numeric RTO ($(jq -r .rto_seconds "$OUT/dr-drill-latest.json" 2>/dev/null)s)" \
    jq -e '.rto_seconds | type == "number"' "$OUT/dr-drill-latest.json"
  must "vault-ha.sh upgrade (rolling rehearsal: followers, then step-down + leader)" ./vault-ha.sh upgrade
  check "cluster healthy after the rolling upgrade" said "autopilot healthy=true failure_tolerance=1"
  if [[ -f "$TEST_SECRETS/created-ha" ]]; then
    must "vault-ha.sh down --volumes (the harness made it)" ./vault-ha.sh down --volumes
  fi
fi

if [[ -n "$EVIDENCE_DIR" ]]; then write_record || FAILS=$((FAILS + 1)); fi

# --- summary ------------------------------------------------------------------------
printf '\n'
if [[ $FAILS -eq 0 ]]; then
  log "E2E PASSED - samba-dc stays up for poking around; test/e2e.sh --cleanup removes it"
  exit 0
fi
log "E2E FAILED: $FAILS assertion(s)"
exit 1
