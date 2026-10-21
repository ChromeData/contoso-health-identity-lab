#!/usr/bin/env bash
# =============================================================================
# test/e2e-scale.sh - "500 privileged accounts: how did you onboard them?",
# answered with a real, timed run of the PAM pipeline against a real Samba
# Active Directory DC and a real Vault, with a synthetic but realistic estate.
#
# Own compose project (contoso-pamscale, test/docker-compose.pam-scale.yml):
# Vault 2.1.1 + the Samba AD DC image + the pam-tools image. The shared
# contoso-pam stack is never touched. The REAL pipeline runs: lib.sh's
# vault_configure_ad (as vault-onboard-ad.sh), discover.sh, onboard.sh,
# rotate.sh, reconcile.sh and lib.sh's dep_gate - pointed at this project by
# COMPOSE_PROJECT_NAME / COMPOSE_FILE and lib.sh's PAM_ENV_FILE /
# PAM_VAULT_ADDR / PAM_VAULT_INIT / PAM_CA_FILE / PAM_OUT. Only the
# assertions and the timing live here.
#
#   a. fresh project: DC healthy (LDAPS, lab CA), Vault initialised,
#      unsealed, file audit device on; LDAP engine configured by
#      vault_configure_ad (bound as svc-vault-rotator, CA-verified LDAPS)
#   stages, each TIMED (per-stage seconds and accounts/second go to the
#   run record):
#   seed        seed-accounts.py --bulk N --noise M inside the DC: N
#               PAM-relevant accounts in a fixed realistic mix (SPN service
#               accounts, run-as batch accounts, tier-1/tier-0 admins incl.
#               nested groups and admins outside the PAM OUs, stale, never
#               used, orphaned adminCount, disabled, Kerberoastable Tier 0)
#               + M ordinary staff users, + an accounts-dependencies-style
#               record per eligible account (clear / unresolved / none)
#   discovery   ./discover.sh: read-only bind, paged LDAPS, classification
#   onboarding  ./onboard.sh --deps <generated map>: a Safe (Vault policy)
#               per tier, static roles for service accounts, library sets
#               for humans; unresolved or unknown dependencies -> HELD
#   rerun       ./onboard.sh again: idempotent, nothing new vaulted
#   dependency check  lib.sh dep_gate over every eligible account against a
#               RE-SCAN of the map (new consumers found after onboarding)
#   rotation    ./rotate.sh on a sample of vaulted service accounts (rotates)
#               and on every account the re-scan blocked (REFUSED)
#   reconcile   ./reconcile.sh --strict: VAULTED / EXCEPTION / HELD / GAP / ORPHAN
#
# Assertions (one PASS/FAIL line each):
#   * all discovered: every bulk account, with the action / Vault target /
#     reason its category calls for; no staff account; nothing beyond the
#     base layout
#   * all in-scope onboarded: every eligible account with clear dependencies
#     is in the right static role or library set; no held or exception
#     account is in Vault; Vault set a new password for every onboarded one
#     (pwdLastSet moved) and touched no held or exception account
#   * reconcile categories sum to the rows and to the discovered accounts,
#     every bulk row has its expected status, GAP 0, ORPHAN 0, every VAULTED
#     row rotated within policy
#   * rotation within policy: each sampled account's last_vault_rotation
#     moved and is inside its tier's rotation_period; the new Vault password
#     binds, the previous one is rejected (LDAP 49)
#   * dependency-blocked accounts not rotated: rotate.sh refused each one
#     the re-scan blocked (password and last_vault_rotation unchanged,
#     rotate-refused audited), and no held account's password ever changed
#
# "Rejected" means the DC answered invalidCredentials (49). Passwords are
# only held in shell variables and piped (to ldapwhoami) - never printed,
# never in an argument list. Reports from the scripts under test go to
# out/pam-scale/ (gitignored); stage logs to out/pam-scale/logs/.
#
# RUN RECORD (--evidence-dir DIR, relative DIR taken from lab/pam, e.g.
# ../evidence/pam-scale/<UTC>): scale.json (population, counts, per-stage
# seconds and accounts/second, host shape), results.json (every check, and
# the code fingerprint: SHA-256 of every lab/pam file the run used, taken at
# the start - lib.sh code_sums -> code.sha256sums), run.log (step, stage and PASS/FAIL
# lines only), reconcile.md + reconcile.csv (synthetic account names and
# states, no secret) and SHA256SUMS - sealed by lib.sh run_record_seal
# (refuses secret-shaped strings and local paths). A failed run is recorded
# as failed: an assertion FAIL, and also a run that ABORTS part-way (image
# build, DC health, Vault init, LDAP engine, seeding, a pipeline script
# exiting non-zero) - that record is run.log + results.json with "aborted"
# + code.sha256sums (no scale.json: the stages it would describe did not all
# run).
# --verify DIR re-checks a record (hashes, all-PASS, nothing secret-shaped,
# code fingerprint consistent, reconcile categories add up) with only jq +
# shasum: no Docker needed.
#
# Usage: test/e2e-scale.sh [--accounts N] [--noise M] [--sample K] [--keep] [--evidence-dir DIR]
#        test/e2e-scale.sh --verify DIR
#        test/e2e-scale.sh --cleanup     remove the project, its volumes, secrets and reports
#   defaults: N=500 bulk accounts, M=250 staff users, K=25 rotated
#   --keep: leave the project running afterwards (default: removed)
# Slow (minutes): test/run-all.sh runs it only with --scale.
# =============================================================================
# Helpers below are called through check()/timed(), which ShellCheck cannot
# see (SC2329); single-quoted strings are jq / Python programs (SC2016).
# shellcheck disable=SC2329,SC2016
SC_PROJECT=contoso-pamscale
SC_SECRETS=.secrets/pam-scale
# Point every script (and lib.sh) at THIS project. Set before lib.sh is
# sourced: it reads them once.
export COMPOSE_PROJECT_NAME="$SC_PROJECT"
export COMPOSE_FILE=test/docker-compose.pam-scale.yml
export PAM_ENV_FILE="$SC_SECRETS/env"
export PAM_VAULT_ADDR=http://127.0.0.1:8240
export PAM_VAULT_INIT="$SC_SECRETS/vault-init.json"
export PAM_CA_FILE="$SC_SECRETS/vault-ca/ad-root-ca.pem"
export PAM_OUT=out/pam-scale
unset PAM_POLICY_FILE PAM_OIDC OIDC_CLIENT_ID VAULT_TOKEN
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"   # cd's to lab/pam; set -euo pipefail; umask 077
# Dependencies are checked after the arguments: --verify / --help need no Docker.

export LC_ALL=C   # one collation for sort / comm / join below
TAB=$'\t'
FQDN=dc01.corp.test.local
BASE_DN="DC=corp,DC=test,DC=local"
NETBIOS=CORP
SEED_SCRIPT=/usr/local/lib/samba-ad/seed-accounts.py
SAMBA_SECRETS=(samba-admin-password svc-vault-rotator-password svc-backup-password svc-pam-discovery-password)
# The base layout seed-accounts.py gives every test DC (and discovery finds).
BASE_ACCOUNTS="Administrator krbtgt svc-vault-rotator svc-backup svc-pam-discovery svc-sql01 svc-iis-app
svc-legacy-da t1-srvadmin-01 t1-srvadmin-02 tier0-admin-01 tier0-admin-02 t0-stale-admin t0-never-admin former-admin-01"
DEPS_BASE=test/accounts-dependencies.e2e.json   # the base layout's dependency records
DEPS_ONBOARD="$OUT/deps-onboard.json"            # + the bulk records (relative: the reports quote it)
DEPS_RESCAN="$OUT/deps-rescan.json"              # + consumers a re-scan found after onboarding
DISC="$OUT/discovery-latest.json"
base_accounts() { tr ' ' '\n' <<<"$BASE_ACCOUNTS" | grep .; }
latest_onboarding() { printf '%s\n' "$OUT"/onboarding-*.json | sort | tail -n 1; }   # names carry a sortable UTC stamp

teardown() {
  # compose resolves the file secrets even on `down`: give it placeholders.
  mkdir -p "$SC_SECRETS/vault-ca" && chmod 700 "$SC_SECRETS"
  local f
  for f in "${SAMBA_SECRETS[@]}"; do [[ -e "$SC_SECRETS/$f" ]] || : > "$SC_SECRETS/$f"; done
  docker compose --profile tools down -v --remove-orphans 2>&1 | { grep -v -e '^ Container' -e '^ Volume' -e '^ Network' || true; }
  rm -rf "$SC_SECRETS"
}

N=500 M=250 K=25 KEEP=0 EVIDENCE_DIR="" VERIFY_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --accounts) N="${2:?--accounts N}"; shift 2 ;;
    --noise) M="${2:?--noise M}"; shift 2 ;;
    --sample) K="${2:?--sample K}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --evidence-dir) EVIDENCE_DIR="${2:?--evidence-dir DIR}"; shift 2 ;;
    --verify) VERIFY_DIR="${2:?--verify DIR}"; shift 2 ;;
    --cleanup) need docker; teardown; rm -rf "$OUT"; log "$SC_PROJECT removed (containers, network, volumes, $SC_SECRETS, $OUT)"; exit 0 ;;
    -h|--help) sed -n '/^# ====/,/^# ====/p' "$PAM_DIR/test/e2e-scale.sh" | sed '1d;$d'; exit 0 ;;
    *) die "usage: $0 [--accounts N] [--noise M] [--sample K] [--keep] [--evidence-dir DIR] | --verify DIR | --cleanup" ;;
  esac
done
[[ "$N" =~ ^[0-9]+$ && "$M" =~ ^[0-9]+$ && "$K" =~ ^[0-9]+$ ]] || die "--accounts, --noise and --sample take whole numbers"
[[ $N -ge 50 && $N -le 5000 ]] || die "--accounts must be 50-5000 (every category of the mix needs at least one account)"
[[ $K -ge 1 ]] || die "--sample must be at least 1"

if [[ -n "$VERIFY_DIR" ]]; then
  need jq; need shasum
  bad=0
  run_record_verify "$VERIFY_DIR" results.json '.result == "PASS" and .fail == 0 and (.checks | length) == .pass and .pass > 0' || bad=1
  if jq -e '.result == "PASS" and (.stages | length) == 7 and all(.stages[]; .seconds > 0 and .accounts > 0)
            and .reconcile.gap == 0 and .reconcile.orphan == 0
            and .reconcile.rows == ([.reconcile.by_status[]] | add) and .reconcile.rows == .discovery.discovered' \
       "$VERIFY_DIR/scale.json" >/dev/null 2>&1; then
    echo "PASS  scale.json: PASS, 7 timed stages, reconcile categories add up to the discovered accounts, GAP 0, ORPHAN 0"
  else
    echo "FAIL  scale.json missing or inconsistent"; bad=1
  fi
  # v2 records: scale.json names the same code as results.json.
  if jq -e '.schema == "contoso-pam/scale/v2"' "$VERIFY_DIR/scale.json" >/dev/null 2>&1; then
    if [[ "$(jq -r '.code_sha256 // ""' "$VERIFY_DIR/scale.json")" == "$(jq -r '.code.sha256 // "none"' "$VERIFY_DIR/results.json")" ]]; then
      echo "PASS  scale.json and results.json name the same code fingerprint"
    else echo "FAIL  scale.json and results.json name different code"; bad=1; fi
  fi
  [[ $bad -eq 0 ]] && { log "SCALE VERIFY PASSED ($(basename "$VERIFY_DIR"))"; exit 0; }
  echo "SCALE VERIFY FAILED"; exit 1
fi
need docker; need jq; need curl; need openssl; need python3; need shasum
if [[ -n "$EVIDENCE_DIR" ]]; then
  need git
  [[ ! -e "$EVIDENCE_DIR" ]] || die "record folder already exists: $EVIDENCE_DIR (never overwritten)"
fi
RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/e2e-scale.XXXXXX")
chmod 700 "$WORK"
: > "$WORK/results.tsv"; : > "$WORK/run.log"; : > "$WORK/stages.tsv"
# The code this run uses, fingerprinted BEFORE it starts (lib.sh code_sums).
if [[ -n "$EVIDENCE_DIR" ]]; then
  code_sums > "$WORK/code.sha256sums" || { rm -rf "$WORK"; die "could not fingerprint lab/pam (needs a git checkout) - no run record without it"; }
fi

FAILS=0
pass()  { printf 'PASS  %s\n' "$*"; printf 'PASS\t%s\n' "$*" >> "$WORK/results.tsv"; printf 'PASS  %s\n' "$*" >> "$WORK/run.log"; }
fail()  { printf 'FAIL  %s\n' "$*"; printf 'FAIL\t%s\n' "$*" >> "$WORK/results.tsv"; printf 'FAIL  %s\n' "$*" >> "$WORK/run.log"; FAILS=$((FAILS + 1)); }
# No redirections on a `check` line: they would apply to check itself.
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
step()  { printf '\n'; log "== $*"; printf '\n[%s] == %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$WORK/run.log"; }
indent() { sed 's/^/      /'; }
eq() { [[ "$1" == "$2" ]]; }   # eq GOT WANT

# Secrets held for the run: variables only, cleared on exit.
OLD_PW=()
on_exit() {
  local rc=$?
  OLD_PW=(); VAULT_TOKEN=""
  rm -rf "$WORK"
  if [[ $KEEP -eq 0 ]]; then teardown >/dev/null 2>&1 || true; fi
  exit "$rc"
}
trap on_exit EXIT
# An abort still leaves a run record when --evidence-dir is set: run.log +
# results.json marked FAIL with the reason (write_results_json), sealed by the
# same run_record_seal. No scale.json: its stage variables may not exist yet.
ABORTED="" RECORD_WRITTEN=""
abort() {
  fail "$*"
  ABORTED="$*"
  if [[ -n "$EVIDENCE_DIR" && -z "$RECORD_WRITTEN" ]]; then
    RECORD_WRITTEN=1
    local stage
    stage=$(mktemp -d "$WORK/record.XXXXXX")
    cp "$WORK/run.log" "$stage/run.log"; cp "$WORK/code.sha256sums" "$stage/code.sha256sums"
    if write_results_json > "$stage/results.json" && run_record_seal "$stage" "$EVIDENCE_DIR" run.log results.json code.sha256sums; then
      log "run record (aborted run): $EVIDENCE_DIR (run.log, results.json, code.sha256sums, SHA256SUMS)"
    else log "could not write the aborted run's record to $EVIDENCE_DIR"; fi
  fi
  printf '\nE2E-SCALE ABORTED (%d failure(s))\n' "$FAILS"; exit 1
}
write_results_json() { # every check so far + the code fingerprint -> stdout
  jq -R -s --arg ts "$RUN_UTC" --arg aborted "$ABORTED" --argjson code "$(code_meta "$WORK/code.sha256sums")" '
    [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], name: .[1]}] as $c
    | {schema: "contoso-pam/e2e-scale/v2", run_utc: $ts,
       tenant: "none: local Docker only (Vault + Samba AD DC corp.test.local, synthetic accounts)",
       result: (if ([$c[] | select(.status != "PASS")] | length) == 0 and $aborted == "" then "PASS" else "FAIL" end),
       aborted: (if $aborted == "" then null else $aborted end),
       pass: ([$c[] | select(.status == "PASS")] | length), fail: ([$c[] | select(.status != "PASS")] | length),
       code: $code,
       checks: $c}' "$WORK/results.tsv"
}

# --- timing -------------------------------------------------------------------------------
now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
LAST_MS=0 LAST_RC=0
timed() { # timed STAGE CMD... : output -> $OUT/logs/STAGE.log (tail shown); sets LAST_MS / LAST_RC
  local t0 rc=0
  t0=$(now_ms)
  "${@:2}" < /dev/null > "$OUT/logs/$1.log" 2>&1 || rc=$?
  LAST_MS=$(( $(now_ms) - t0 )); LAST_RC=$rc
  tail -n 3 "$OUT/logs/$1.log" | indent
}
stage() { # stage NAME ACCOUNTS NOTE : record the last timed() run as a stage
  printf '%s\t%s\t%s\t%s\n' "$1" "$LAST_MS" "$2" "$3" >> "$WORK/stages.tsv"
  local line
  line=$(awk -v n="$1" -v ms="$LAST_MS" -v a="$2" 'BEGIN { printf "stage %-16s %6.1f s  %5d accounts  %7.1f accounts/s", n, ms / 1000, a, (ms > 0 ? a * 1000 / ms : 0) }')
  log "   $line"
  printf '[%s]    %s  (%s)\n' "$(date -u +%H:%M:%SZ)" "$line" "$3" >> "$WORK/run.log"
}

# --- DC / Vault helpers ---------------------------------------------------------------------
samba_health() { docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q samba-dc)" 2>/dev/null || true; }
wait_samba_healthy() {
  local h=""
  for _ in $(seq 1 100); do
    h=$(samba_health); [[ "$h" == healthy ]] && return 0
    sleep 3
  done
  docker compose logs --tail 30 samba-dc 2>&1 | indent
  return 1
}
build_images() {
  docker compose build samba-dc || return 1
  docker image inspect contoso-pam/pam-tools:local >/dev/null 2>&1 || docker compose --profile tools build pam-tools
}
vault_init() { # -> $PAM_VAULT_INIT (0600), only if it is valid JSON with a root token
  local tmp
  vault_wait
  tmp=$(mktemp "$SC_SECRETS/vault-init.XXXXXX")
  vault_cli operator init -key-shares=1 -key-threshold=1 -format=json > "$tmp" || { rm -f "$tmp"; return 1; }
  jq -e '.root_token and (.unseal_keys_b64 | length > 0)' "$tmp" >/dev/null || { rm -f "$tmp"; return 1; }
  chmod 600 "$tmp" && mv "$tmp" "$PAM_VAULT_INIT"
}
install_dc_ca() { docker compose exec -T samba-dc cat /var/lib/samba/private/tls/ca.pem </dev/null | vault_install_ca; }
configure_ldap() { vault_configure_ad "$BASE_DN" "$FQDN" < "$SC_SECRETS/svc-vault-rotator-password"; }
ldap_config_ok() {
  vault_api GET ldap/config | jq -e --arg u "ldaps://$FQDN" --arg b "CN=svc-vault-rotator,OU=ServiceAccounts,$BASE_DN" \
    '.data | .schema == "ad" and .url == $u and .binddn == $b and .insecure_tls == false
     and (.certificate | startswith("-----BEGIN CERTIFICATE-----"))' >/dev/null
}
seed_bulk() { # the bulk population; stdout (the manifest) -> $OUT/manifest.json
  docker compose exec -T samba-dc python3 "$SEED_SCRIPT" --bulk "$N" --noise "$M" </dev/null > "$OUT/manifest.json"
}
pls_snapshot() { # every user's pwdLastSet from sam.ldb: "sam<TAB>pwdLastSet" lines -> FILE
  docker compose exec -T samba-dc ldbsearch -H /var/lib/samba/private/sam.ldb -b "$BASE_DN" \
      '(&(objectCategory=person)(objectClass=user))' sAMAccountName pwdLastSet </dev/null 2>/dev/null \
    | awk '/^sAMAccountName: /{s=$2} /^pwdLastSet: /{p=$2} /^(# record|dn:)/{ if (s != "") print s "\t" p; s=""; p="" }
           END { if (s != "") print s "\t" p }' | sort -u > "$1"
  [[ -s "$1" ]]
}
pls_changed() { # pls_changed BEFORE AFTER SAMS_FILE -> how many of SAMS changed (missing = changed)
  awk -F'\t' 'FILENAME == ARGV[1] { b[$1] = $2; next } FILENAME == ARGV[2] { a[$1] = $2; next }
              { if (!($1 in b) || !($1 in a) || b[$1] != a[$1]) n++ } END { print n + 0 }' "$1" "$2" "$3"
}
ldapwhoami_dc() { # printf '%s' PW | ldapwhoami_dc DN -> the DC's answer; exit = ldapwhoami's (49 = invalidCredentials)
  local pw
  pw=$(cat)
  [[ -n "$pw" ]] || return 2      # empty = anonymous bind: proves nothing either way
  printf '%s' "$pw" | docker compose exec -T -e LDAPTLS_CACERT=/var/lib/samba/private/tls/ca.pem samba-dc \
    ldapwhoami -x -H "ldaps://$FQDN" -D "$1" -y /dev/stdin 2>/dev/null
}
binds_as() { local who; who=$(ldapwhoami_dc "$1") || return 1; [[ "$who" == "u:${NETBIOS}\\$2" ]]; }   # DN SAM
rejected() { local rc=0; ldapwhoami_dc "$1" >/dev/null || rc=$?; [[ $rc -eq 49 ]]; }                  # DN
vault_pw() { vault_api GET "ldap/static-cred/$1" | jq -j '.data.password // ""'; }                     # ROLE
policy_exists() { vault_api GET "sys/policies/acl/$1" >/dev/null 2>&1; }
role_field() { vault_api GET "ldap/static-role/$1" | jq -r --arg f "$2" '.data[$f]'; }                  # ROLE FIELD
csv_json() { python3 -c 'import csv, json, sys; json.dump(list(csv.DictReader(open(sys.argv[1], newline=""))), sys.stdout)' "$1"; }
jcount() { jq -r "$1" "${@:2}"; }   # jcount FILTER FILE... -> the filter's (number) output
lines() { if [[ -s "$1" ]]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

# =============================================================================
step "(a) fresh project $SC_PROJECT: Vault 2.1.1 + Samba AD DC + pam-tools (shared stack untouched)"
teardown >/dev/null 2>&1 || true
rm -rf "$OUT"; mkdir -p "$OUT/logs" "$SC_SECRETS/vault-ca"; chmod 700 "$OUT" "$SC_SECRETS"
for f in "${SAMBA_SECRETS[@]}"; do
  # Upper, lower, digit, symbol: satisfies AD complexity. Never printed.
  printf 'Te-%s-4K' "$(openssl rand -hex 16)" > "$SC_SECRETS/$f"
done
printf 'DC_FQDN=%s\nDC_PUBLIC_IP=\n' "$FQDN" > "$PAM_ENV_FILE"
timed build build_images
[[ $LAST_RC -eq 0 ]] || abort "images build (samba-ad-test with the bulk seed, pam-tools)"
pass "images built (samba-ad-test with the bulk seed, pam-tools)"
docker compose up -d vault samba-dc 2>&1 | { grep -v -e '^ Container' -e '^ Network' -e '^ Volume' || true; } | indent
wait_samba_healthy || abort "samba-dc healthy (LDAPS up, certificate valid for $FQDN)"
pass "samba-dc healthy (LDAPS up, certificate valid for $FQDN)"
vault_init || abort "Vault initialised (lab: 1 key share)"
vault_unseal
export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"
check "Vault initialised and unsealed (API on 127.0.0.1:8240)" eq "$(curl -fsS "$PAM_VAULT_ADDR/v1/sys/seal-status" | jq -r '.initialized and (.sealed | not)')" true
vault_cli audit enable file file_path=/vault/logs/audit.log >/dev/null || abort "Vault file audit device enabled"
pass "Vault file audit device on (throughput below includes audit logging)"
install_dc_ca > "$OUT/logs/ca.log" 2>&1 || abort "the DC's root CA installed for Vault and pam-tools (vault_install_ca)"
pass "the DC's root CA installed for Vault and pam-tools (vault_install_ca)"
timed ldap-engine configure_ldap
[[ $LAST_RC -eq 0 ]] || abort "LDAP secrets engine configured by vault_configure_ad (the vault-onboard-ad.sh code)"
pass "LDAP secrets engine configured by vault_configure_ad (the vault-onboard-ad.sh code)"
check "ldap/config: schema=ad, ldaps://$FQDN, bound as svc-vault-rotator, CA-verified (no insecure_tls)" ldap_config_ok

# =============================================================================
step "(b) stage seed: seed-accounts.py --bulk $N --noise $M inside the DC"
timed seed seed_bulk
[[ $LAST_RC -eq 0 ]] || abort "seed-accounts.py --bulk $N --noise $M"
stage seed $((N + M)) "$N PAM-relevant accounts + $M staff users written to the running DC's directory (sam.ldb: user + group adds, attribute writes)"
check "manifest: $N bulk accounts, $M staff users" eq "$(jq -r '[(.accounts | length), (.noise_accounts | length)] | join(" ")' "$OUT/manifest.json")" "$N $M"
MIX=$(jq -r '.mix | to_entries | map("\(.key)=\(.value)") | join(" ")' "$OUT/manifest.json")
check "mix adds up to $N: $MIX" eq "$(jq '[.mix[]] | add' "$OUT/manifest.json")" "$N"
check "every category of the mix is present (>= 1 account each)" eq "$(jq '[.mix[] | select(. < 1)] | length' "$OUT/manifest.json")" 0
pls_snapshot "$WORK/pls-seed.tsv" || abort "pwdLastSet snapshot after seeding"
check "pwdLastSet snapshot: every bulk and staff account is in AD" \
  eq "$(jq -r '.accounts[].sam, .noise_accounts[]' "$OUT/manifest.json" | sort | comm -23 - <(cut -f1 "$WORK/pls-seed.tsv") | wc -l | tr -d ' ')" 0

# Expected outcome per bulk account, from the manifest and pam-policy.json: the
# Vault target the policy names, and VAULTED / HELD / EXCEPTION by the same
# gate as onboard.sh (static: always dependency-gated; library: when the
# tier's dependency_check is true).
jq -n --slurpfile m "$OUT/manifest.json" --slurpfile p pam-policy.json '
  $p[0].tiers as $t
  | [$m[0].accounts[] | . as $a | $a.expect.action as $act
     | (if $act == "static" then true elif $act == "library" then ($t[$a.expect.tier].dependency_check == true) else false end) as $gated
     | {sam: $a.sam, dn: $a.dn, category: $a.category, action: $act, tier: $a.expect.tier, reason: $a.expect.reason,
        target: (if $act == "static" then "\($t[$a.expect.tier].static_prefix)/\($a.sam)"
                 elif $act == "library" then $t[$a.expect.tier].library else null end),
        deps: ($a.deps_status // "n/a"), drift: ($a.drift != null),
        status: (if $act == "exception" then "EXCEPTION"
                 elif ($gated | not) or $a.deps_status == "clear" then "VAULTED" else "HELD" end),
        rotation_period: (if $act == "static" then $t[$a.expect.tier].rotation_period else null end)}]' > "$WORK/expected.json"
E_VAULTED=$(jcount '[.[] | select(.status == "VAULTED")] | length' "$WORK/expected.json")
E_HELD=$(jcount '[.[] | select(.status == "HELD")] | length' "$WORK/expected.json")
E_EXC=$(jcount '[.[] | select(.status == "EXCEPTION")] | length' "$WORK/expected.json")
E_ELIG=$((E_VAULTED + E_HELD))
log "expected for the bulk population: $E_ELIG eligible -> $E_VAULTED in scope (dependencies clear) + $E_HELD held; $E_EXC exceptions"

# The dependency map onboarding reads: the base layout's records + one per bulk
# account that has one (accounts with NO record are left out on purpose).
jq -n --slurpfile m "$OUT/manifest.json" --slurpfile b "$DEPS_BASE" '{
  _comment: ["Generated by test/e2e-scale.sh from the seed manifest: accounts-dependencies.json shape.",
             "Accounts with no record are left out on purpose (unknown is not none: onboarding holds them)."],
  accounts: ($b[0].accounts + ([$m[0].accounts[] | select(.dependencies != null) | {key: .sam, value: .dependencies}] | from_entries))}' > "$DEPS_ONBOARD"
# The re-scan after onboarding: the same, plus each drifted account's new, unresolved consumer.
jq --slurpfile m "$OUT/manifest.json" '
  reduce ($m[0].accounts[] | select(.drift != null)) as $a (.; .accounts[$a.sam] += [$a.drift])
  | ._comment += ["Re-scan after onboarding: new unresolved consumers on some vaulted accounts (drift)."]' "$DEPS_ONBOARD" > "$DEPS_RESCAN"
check "dependency map: a record for every bulk account except the 'no record' ones" \
  eq "$(jq -n --slurpfile m "$OUT/manifest.json" '[$m[0].accounts[] | select(.dependencies != null)] | length')" \
     "$(jq --slurpfile b "$DEPS_BASE" '(.accounts | length) - ($b[0].accounts | length)' "$DEPS_ONBOARD")"

# =============================================================================
step "(c) stage discovery: ./discover.sh (read-only bind as svc-pam-discovery, paged LDAPS)"
run_discover() { ./discover.sh < "$SC_SECRETS/svc-pam-discovery-password"; }
timed discovery run_discover
[[ $LAST_RC -eq 0 && -s "$DISC" ]] || abort "discover.sh wrote $DISC"
D_TOTAL=$(jcount '.accounts | length' "$DISC")
D_BULK=$(jq -n --slurpfile m "$OUT/manifest.json" --slurpfile d "$DISC" '[$d[0].accounts[].sam] - ([$d[0].accounts[].sam] - [$m[0].accounts[].sam]) | length')
D_STAFF=$(jq -n --slurpfile m "$OUT/manifest.json" --slurpfile d "$DISC" '[$d[0].accounts[].sam] - ([$d[0].accounts[].sam] - $m[0].noise_accounts) | length')
stage discovery "$D_TOTAL" "candidates classified (privileged-group members incl. nested, SPN, adminCount, PAM OUs)"
NBASE=$(base_accounts | grep -c .)
check "all discovered: $D_TOTAL candidates = $N bulk + $NBASE base layout" eq "$D_TOTAL" "$((N + NBASE))"
check "every bulk account discovered ($D_BULK of $N)" eq "$D_BULK" "$N"
check "no staff (non-privileged) account discovered ($D_STAFF of $M)" eq "$D_STAFF" 0
check "nothing else discovered: the non-bulk candidates are exactly the base layout" \
  eq "$(jq -rn --slurpfile m "$OUT/manifest.json" --slurpfile d "$DISC" '([$d[0].accounts[].sam] - [$m[0].accounts[].sam]) | sort | join(" ")')" \
     "$(base_accounts | sort | paste -sd ' ' -)"
# Per account: the proposed action, tier and Vault target (or exception reason) the category calls for.
jq -n --slurpfile e "$WORK/expected.json" --slurpfile d "$DISC" '
  ($d[0].accounts | map({key: .sam, value: .}) | from_entries) as $got
  | [$e[0][] | . as $x | $got[$x.sam] as $g
     | select($g == null or $g.proposed_action != $x.action or $g.tier != $x.tier
              or ($x.action != "exception" and $g.proposed_target != $x.target)
              or ($x.action == "exception" and (($g.reason // "") | contains($x.reason) | not)))
     | "\($x.sam): want \($x.action) \($x.target // $x.reason) (\($x.tier)), got \($g.proposed_action // "-") \($g.proposed_target // $g.reason // "-") (\($g.tier // "-"))"]' \
  > "$WORK/disc-mismatch.json"
check "every bulk account classified as its category calls for (action, tier, Vault target / reason): mismatches 0" \
  eq "$(jq length "$WORK/disc-mismatch.json")" 0
jq -r '.[:5][]' "$WORK/disc-mismatch.json" | indent
for c in $(jq -r '.mix | keys_unsorted[]' "$OUT/manifest.json"); do
  want=$(jq -r --arg c "$c" '.mix[$c]' "$OUT/manifest.json")
  what=$(jq -r --arg c "$c" '[.[] | select(.category == $c)][0] | if .action == "exception" then "exception: \(.reason)" elif .action == "static" then "static role \(.target | sub("/.*"; "/<sam>"))" else "library \(.target)" end' "$WORK/expected.json")
  got=$(jq -n --slurpfile e "$WORK/expected.json" --slurpfile d "$DISC" --arg c "$c" '
    ($d[0].accounts | map({key: .sam, value: .}) | from_entries) as $g
    | [$e[0][] | select(.category == $c) | select($g[.sam].proposed_action == .action and $g[.sam].tier == .tier)] | length')
  check "  $c: $got/$want -> $what" eq "$got" "$want"
done
check "nested groups resolved: every staff account admin through Tier1-App-Admins is in Tier1-Server-Admins' chain" \
  eq "$(jq -n --slurpfile e "$WORK/expected.json" --slurpfile d "$DISC" '
        ($d[0].accounts | map({key: .sam, value: .}) | from_entries) as $g
        | [$e[0][] | select(.category == "t1_nested") | select(($g[.sam].privileged_groups | index("Tier1-Server-Admins")) == null)] | length')" 0
check "discovery report: one CSV row per candidate" eq "$(($(lines "$OUT/discovery-latest.csv") - 1))" "$D_TOTAL"

# =============================================================================
step "(d) stage onboarding: ./onboard.sh --deps $DEPS_ONBOARD (a Safe per tier, dependency-gated)"
timed onboarding ./onboard.sh --deps "$DEPS_ONBOARD"
[[ $LAST_RC -eq 0 ]] || abort "onboard.sh (bulk) exits 0"
ONB1=$(latest_onboarding)
bulk_results() { # bulk_results REPORT RESULT -> how many bulk accounts the onboarding report gives RESULT
  jq -r --slurpfile e "$WORK/expected.json" --arg r "$2" '($e[0] | map({key: .sam, value: 1}) | from_entries) as $bulk
    | [.results[] | select($bulk[.account] and .result == $r)] | length' "$1"
}
O_VAULTED=$(bulk_results "$ONB1" vaulted) O_HELD=$(bulk_results "$ONB1" held) O_EXC=$(bulk_results "$ONB1" exception)
stage onboarding "$D_TOTAL" "every candidate planned; $O_VAULTED bulk accounts vaulted (static role created + rotated, or added to a library set + new password), $O_HELD held on dependencies, $O_EXC exceptions skipped"
pass "onboard.sh (bulk) exits 0"
cp "$ONB1" "$WORK/onboarding-1.json"
static_roles | sort > "$WORK/static-roles.txt"
{ for s in $(library_sets); do library_members "$s" | sed "s|^|$s\t|"; done; } | sort > "$WORK/library-members.tsv"
# Vault's view of each bulk account: "static <path>" / "library <set>" / absent.
jq -r '.[] | select(.status == "VAULTED") | "\(.action)\t\(.target)\t\(.sam)"' "$WORK/expected.json" | sort > "$WORK/want-vaulted.tsv"
{ grep -F / "$WORK/static-roles.txt" | awk -F/ '{ print "static\t" $0 "\t" $NF }'
  awk -F'\t' '{ print "library\t" $1 "\t" $2 }' "$WORK/library-members.tsv"; } | sort > "$WORK/have-vaulted.tsv"
check "all in-scope onboarded: $E_VAULTED of $E_VAULTED bulk accounts with clear dependencies in their Vault object (static role / library set)" \
  eq "$(comm -23 "$WORK/want-vaulted.tsv" "$WORK/have-vaulted.tsv" | wc -l | tr -d ' ')" 0
jq -r '.[] | select(.status != "VAULTED") | .sam' "$WORK/expected.json" | sort > "$WORK/not-vaulted.txt"
check "no held or exception account in Vault (0 of $((E_HELD + E_EXC)))" \
  eq "$(cut -f3 "$WORK/have-vaulted.tsv" | sort -u | comm -12 - "$WORK/not-vaulted.txt" | wc -l | tr -d ' ')" 0
check "Vault holds nothing unexpected: static roles + library members = bulk in-scope + the base layout's" \
  eq "$(comm -13 "$WORK/want-vaulted.tsv" "$WORK/have-vaulted.tsv" | cut -f3 | sort | paste -sd ' ' -)" \
     "$(printf '%s\n' svc-iis-app t1-srvadmin-01 t1-srvadmin-02 tier0-admin-01 tier0-admin-02 | sort | paste -sd ' ' -)"
# Observed: bulk accounts Vault now holds, by kind (have-vaulted minus the base layout's).
jq -r '.[].sam' "$WORK/expected.json" | sort > "$WORK/sams-bulk.txt"
N_STATIC=$(awk -F'\t' '$1 == "static" { print $3 }' "$WORK/have-vaulted.tsv" | sort | comm -12 - "$WORK/sams-bulk.txt" | wc -l | tr -d ' ')
N_LIB=$(awk -F'\t' '$1 == "library" { print $3 }' "$WORK/have-vaulted.tsv" | sort | comm -12 - "$WORK/sams-bulk.txt" | wc -l | tr -d ' ')
for t in svc tier1; do
  n=$(grep -c "^static${TAB}$t/" "$WORK/want-vaulted.tsv" || true)
  check "  static roles $t/*: $n bulk$([[ $t == svc ]] && echo ' + 1 base') (rotation_period $(policy_tier "$t" rotation_period), Safe $t-static-read)" \
    eq "$(grep -c "^$t/" "$WORK/static-roles.txt" | tr -d ' ')" "$((n + $([[ $t == svc ]] && echo 1 || echo 0)))"
done
for s in tier0-admins tier1-admins; do
  n=$(grep -c "^library${TAB}$s${TAB}" "$WORK/want-vaulted.tsv" || true)
  check "  library $s: $n bulk + 2 base members" eq "$(grep -c "^$s${TAB}" "$WORK/library-members.tsv" | tr -d ' ')" "$((n + 2))"
done
for p in tier0-checkout tier1-checkout tier0-static-read tier1-static-read svc-static-read pam-reconcile; do
  check "  Safe policy $p written" policy_exists "$p"
done
check "onboarding report: $O_VAULTED bulk vaulted, $O_HELD held, $O_EXC exceptions (expected $E_VAULTED / $E_HELD / $E_EXC)" \
  eq "$O_VAULTED $O_HELD $O_EXC" "$E_VAULTED $E_HELD $E_EXC"
first_static=$(jq -r '[.[] | select(.status == "VAULTED" and .action == "static")][0] | "\(.target)\t\(.sam)\t\(.dn)\t\(.rotation_period)"' "$WORK/expected.json")
IFS=$'\t' read -r fs_role fs_sam fs_dn fs_period <<<"$first_static"
check "  static role $fs_role: username, DN and rotation_period as discovered / policy" \
  eq "$(vault_api GET "ldap/static-role/$fs_role" | jq -r '.data | "\(.username)|\(.dn)|\(.rotation_period)"')" \
     "$fs_sam|$fs_dn|$(( ${fs_period%h} * 3600 ))"
pls_snapshot "$WORK/pls-onboarded.tsv" || abort "pwdLastSet snapshot after onboarding"
jq -r '.[] | select(.status == "VAULTED") | .sam' "$WORK/expected.json" > "$WORK/sams-vaulted.txt"
jq -r '.[] | select(.status == "HELD") | .sam' "$WORK/expected.json" > "$WORK/sams-held.txt"
jq -r '.[] | select(.status == "EXCEPTION") | .sam' "$WORK/expected.json" > "$WORK/sams-exception.txt"
check "Vault set a new password for every onboarded account: pwdLastSet moved on $E_VAULTED of $E_VAULTED" \
  eq "$(pls_changed "$WORK/pls-seed.tsv" "$WORK/pls-onboarded.tsv" "$WORK/sams-vaulted.txt")" "$E_VAULTED"
check "dependency-blocked accounts untouched: pwdLastSet unchanged on all $E_HELD held" \
  eq "$(pls_changed "$WORK/pls-seed.tsv" "$WORK/pls-onboarded.tsv" "$WORK/sams-held.txt")" 0
check "exceptions untouched: pwdLastSet unchanged on all $E_EXC" \
  eq "$(pls_changed "$WORK/pls-seed.tsv" "$WORK/pls-onboarded.tsv" "$WORK/sams-exception.txt")" 0

# =============================================================================
step "(e) stage rerun: ./onboard.sh again (idempotent - the nightly run after discovery)"
timed rerun ./onboard.sh --deps "$DEPS_ONBOARD"
[[ $LAST_RC -eq 0 ]] || abort "onboard.sh re-run exits 0"
stage rerun "$D_TOTAL" "every candidate re-planned against Vault; nothing new to vault"
pass "onboard.sh re-run exits 0"
ONB2=$(latest_onboarding)
check "re-run vaulted nothing new (0 'vaulted' results)" eq "$(jq '[.results[] | select(.result == "vaulted")] | length' "$ONB2")" 0
check "re-run recognised every vaulted account as already vaulted ($((E_VAULTED + 6)) incl. the base layout's 6)" \
  eq "$(jq '[.results[] | select(.result == "already")] | length' "$ONB2")" "$((E_VAULTED + 6))"
check "Vault unchanged by the re-run (same static roles)" eq "$(static_roles | sort | shasum | cut -c1-16)" "$(shasum < "$WORK/static-roles.txt" | cut -c1-16)"

# =============================================================================
step "(f) stage dependency check: lib.sh dep_gate over every eligible account, against the re-scan"
dep_sweep() { # sam<TAB>clear|blocked|unknown for every eligible candidate (dep_gate: 0 / 1 / 2)
  local sam rc
  while IFS= read -r sam; do
    rc=0; dep_gate "$sam" "$DEPS_RESCAN" >/dev/null || rc=$?
    case "$rc" in 0) printf '%s\tclear\n' "$sam" ;; 1) printf '%s\tblocked\n' "$sam" ;; *) printf '%s\tunknown\n' "$sam" ;; esac
  done < <(jq -r '.accounts[] | select(.proposed_action == "static" or .proposed_action == "library") | .sam' "$DISC") > "$OUT/dependency-check.tsv"
}
timed dependency-check dep_sweep
[[ $LAST_RC -eq 0 ]] || abort "dependency sweep ran"
DEP_N=$(lines "$OUT/dependency-check.tsv")
stage "dependency check" "$DEP_N" "every eligible candidate through dep_gate against the re-scanned map"
DEP_CLEAR=$(grep -c $'\tclear$' "$OUT/dependency-check.tsv" || true)
DEP_BLOCKED=$(grep -c $'\tblocked$' "$OUT/dependency-check.tsv" || true)
DEP_UNKNOWN=$(grep -c $'\tunknown$' "$OUT/dependency-check.tsv" || true)
N_DRIFT=$(jcount '[.[] | select(.drift)] | length' "$WORK/expected.json")
# Expected per bulk account: drift -> blocked; held: unresolved -> blocked, no record -> unknown.
jq -r '.[] | select(.action != "exception")
       | "\(.sam)\t\(if .drift or .deps == "unresolved" then "blocked" elif .deps == "unknown" then "unknown" else "clear" end)"' \
  "$WORK/expected.json" | sort > "$WORK/dep-want.tsv"
check "dependency check: $DEP_N eligible = $DEP_CLEAR clear + $DEP_BLOCKED blocked + $DEP_UNKNOWN unknown (no record)" \
  eq "$((DEP_CLEAR + DEP_BLOCKED + DEP_UNKNOWN))" "$DEP_N"
check "every bulk account's gate result as recorded in the map (incl. $N_DRIFT vaulted accounts the re-scan blocked): mismatches 0" \
  eq "$(sort "$OUT/dependency-check.tsv" | comm -13 - "$WORK/dep-want.tsv" | wc -l | tr -d ' ')" 0

# =============================================================================
step "(g) stage rotation: ./rotate.sh on $K vaulted service accounts + the $N_DRIFT the re-scan blocked"
# Sample: K accounts spread evenly over the sorted clear (not drifted) static roles.
jq -r --argjson k "$K" '[.[] | select(.status == "VAULTED" and .action == "static" and (.drift | not))] | sort_by(.sam)
       | . as $c | ($c | length) as $n | ([$k, $n] | min) as $m
       | [range(0; $m) | $c[(. * $n / $m) | floor]] | .[] | "\(.sam)\t\(.target)\t\(.dn)\t\(.tier)"' \
  "$WORK/expected.json" > "$WORK/sample.tsv"
jq -r '.[] | select(.drift) | "\(.sam)\t\(.target)\t\(.dn)\t\(.tier)"' "$WORK/expected.json" > "$WORK/drift.tsv"
N_SAMPLE=$(lines "$WORK/sample.tsv")
check "rotation sample: $N_SAMPLE accounts across $(cut -f4 "$WORK/sample.tsv" | sort -u | paste -sd '+' -) tiers" eq "$N_SAMPLE" "$K"
# Before: last_vault_rotation, pwdLastSet, and the current Vault-held password (memory only).
i=0
while IFS=$'\t' read -r sam role _ _; do
  printf '%s\t%s\n' "$sam" "$(role_field "$role" last_vault_rotation)" >> "$WORK/lvr-before.tsv"
  OLD_PW[i]=$(vault_pw "$role"); i=$((i + 1))
done < "$WORK/sample.tsv"
while IFS=$'\t' read -r sam role _ _; do
  printf '%s\t%s\n' "$sam" "$(role_field "$role" last_vault_rotation)" >> "$WORK/drift-lvr-before.tsv"
done < "$WORK/drift.tsv"
pls_snapshot "$WORK/pls-prerotate.tsv" || abort "pwdLastSet snapshot before rotation"
ROT_OK=0 ROT_REFUSED=0
rotate_campaign() { # rotate.sh per account, as an operator would: clear ones rotate, blocked ones are refused
  local sam out rc
  while IFS=$'\t' read -r sam _ _ _; do
    rc=0; out=$(./rotate.sh "$sam" --deps "$DEPS_RESCAN" 2>&1 </dev/null) || rc=$?
    printf '%s\n' "$out"
    if [[ $rc -eq 0 ]]; then ROT_OK=$((ROT_OK + 1)); else echo "UNEXPECTED: rotate.sh $sam failed (exit $rc)"; fi
  done < "$WORK/sample.tsv"
  while IFS=$'\t' read -r sam _ _ _; do
    rc=0; out=$(./rotate.sh "$sam" --deps "$DEPS_RESCAN" 2>&1 </dev/null) || rc=$?
    printf '%s\n' "$out"
    if [[ $rc -ne 0 ]] && grep -q 'REFUSED' <<<"$out"; then ROT_REFUSED=$((ROT_REFUSED + 1)); else echo "UNEXPECTED: rotate.sh $sam was not refused"; fi
  done < "$WORK/drift.tsv"
}
timed rotation rotate_campaign
stage rotation "$((N_SAMPLE + N_DRIFT))" "$ROT_OK of $N_SAMPLE rotated through rotate.sh (gate + Vault rotate-role + LDAPS password reset); $ROT_REFUSED of $N_DRIFT refused by the dependency gate"
check "rotate.sh rotated $N_SAMPLE of $N_SAMPLE sampled accounts" eq "$ROT_OK" "$N_SAMPLE"
check "rotate.sh REFUSED $N_DRIFT of $N_DRIFT accounts the re-scan blocked (unresolved new consumer)" eq "$ROT_REFUSED" "$N_DRIFT"
# After: per sampled account - moved, within its tier's rotation_period, new binds, old rejected.
now=$(date -u +%s)
moved=0 within=0 newbinds=0 oldrejected=0 i=0
while IFS=$'\t' read -r sam role dn _; do
  before=$(awk -F'\t' -v s="$sam" '$1 == s { print $2 }' "$WORK/lvr-before.tsv")
  r=$(vault_api GET "ldap/static-role/$role" | jq -c '.data | {l: .last_vault_rotation, p: .rotation_period}')
  after=$(jq -r .l <<<"$r"); period=$(jq -r .p <<<"$r")
  [[ -n "$after" && "$after" != null && "$after" != "$before" ]] && moved=$((moved + 1))
  age=$(( now - $(jq -rn --arg t "$after" '$t | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601') ))
  # -300: the Docker VM's clock vs the host's
  [[ $age -ge -300 && $age -le $period ]] && within=$((within + 1))
  vault_pw "$role" | binds_as "$dn" "$sam" && newbinds=$((newbinds + 1))
  printf '%s' "${OLD_PW[i]}" | rejected "$dn" && oldrejected=$((oldrejected + 1))
  OLD_PW[i]=""; i=$((i + 1))
done < "$WORK/sample.tsv"
OLD_PW=()
check "rotation: last_vault_rotation moved on $N_SAMPLE of $N_SAMPLE" eq "$moved" "$N_SAMPLE"
check "rotation within policy: every rotated account's last rotation is inside its tier's rotation_period" eq "$within" "$N_SAMPLE"
check "the new Vault-held password binds as the account (LDAPS) on $N_SAMPLE of $N_SAMPLE" eq "$newbinds" "$N_SAMPLE"
check "the previous password is rejected (LDAP 49) on $N_SAMPLE of $N_SAMPLE" eq "$oldrejected" "$N_SAMPLE"
pls_snapshot "$WORK/pls-rotated.tsv" || abort "pwdLastSet snapshot after rotation"
cut -f1 "$WORK/drift.tsv" > "$WORK/sams-drift.txt"
check "refused accounts NOT rotated: pwdLastSet unchanged on $N_DRIFT of $N_DRIFT" \
  eq "$(pls_changed "$WORK/pls-prerotate.tsv" "$WORK/pls-rotated.tsv" "$WORK/sams-drift.txt")" 0
drift_same=0
while IFS=$'\t' read -r sam role _ _; do
  [[ "$(role_field "$role" last_vault_rotation)" == "$(awk -F'\t' -v s="$sam" '$1 == s { print $2 }' "$WORK/drift-lvr-before.tsv")" ]] && drift_same=$((drift_same + 1))
done < "$WORK/drift.tsv"
check "... and last_vault_rotation unchanged on $N_DRIFT of $N_DRIFT" eq "$drift_same" "$N_DRIFT"
check "... and each refusal audited (rotate-refused in pam-audit.jsonl)" \
  eq "$(jq -r 'select(.event == "rotate-refused") | .account' "$OUT/pam-audit.jsonl" | sort -u | comm -12 - <(sort "$WORK/sams-drift.txt") | wc -l | tr -d ' ')" "$N_DRIFT"
cut -f1 "$WORK/sample.tsv" | sort > "$WORK/sams-sample.txt"
check "only the sample rotated: no other account's pwdLastSet changed during the stage" \
  eq "$(jq -r '.[].sam' "$WORK/expected.json" | sort | comm -23 - "$WORK/sams-sample.txt" > "$WORK/sams-notsample.txt"; pls_changed "$WORK/pls-prerotate.tsv" "$WORK/pls-rotated.tsv" "$WORK/sams-notsample.txt")" 0

# =============================================================================
step "(h) stage reconcile: ./reconcile.sh --strict (discovered vs vaulted vs rotated vs exception)"
timed reconcile ./reconcile.sh --strict --deps "$DEPS_RESCAN"
stage reconcile "$D_TOTAL" "every discovered account joined with Vault's inventory and the dependency map"
check "reconcile.sh --strict exits 0 (GAP 0, ORPHAN 0, nothing rotated out of policy)" eq "$LAST_RC" 0
csv_json "$OUT/reconcile-latest.csv" > "$WORK/reconcile.json"
R_ROWS=$(jcount 'length' "$WORK/reconcile.json")
rc_count() { jq -r --arg s "$1" '[.[] | select(.status == $s)] | length' "$WORK/reconcile.json"; }
R_V=$(rc_count VAULTED) R_E=$(rc_count EXCEPTION) R_H=$(rc_count HELD) R_G=$(rc_count GAP) R_O=$(rc_count ORPHAN)
check "reconcile categories sum: $R_V VAULTED + $R_E EXCEPTION + $R_H HELD + $R_G GAP + $R_O ORPHAN = $R_ROWS rows" \
  eq "$((R_V + R_E + R_H + R_G + R_O))" "$R_ROWS"
check "... = the $D_TOTAL discovered accounts (one row each)" eq "$R_ROWS" "$D_TOTAL"
check "GAP 0 (nothing eligible left unvaulted without a reason)" eq "$R_G" 0
check "ORPHAN 0 (nothing in Vault that AD does not have)" eq "$R_O" 0
check "every bulk account's reconcile status as expected (VAULTED / HELD / EXCEPTION): mismatches 0" \
  eq "$(jq -n --slurpfile e "$WORK/expected.json" --slurpfile r "$WORK/reconcile.json" '
        ($r[0] | map({key: .account, value: .status}) | from_entries) as $s
        | [$e[0][] | select($s[.sam] != .status)] | length')" 0
check "every VAULTED row rotated within policy ($R_V of $R_V)" \
  eq "$(jq '[.[] | select(.status == "VAULTED" and .rotated_within_policy == "yes")] | length' "$WORK/reconcile.json")" "$R_V"
check "HELD rows carry their unresolved dependencies (or 'no dependency record')" \
  eq "$(jq '[.[] | select(.status == "HELD" and (.exception | startswith("unresolved dependencies: ") | not))] | length' "$WORK/reconcile.json")" 0
check "report KPI line: GAP 0" grep -qF '| **GAP** (not vaulted, no exception) | **0** |' "$OUT/reconcile-latest.md"

# =============================================================================
step "(i) end state: no held or exception account's password changed during the whole run"
pls_snapshot "$WORK/pls-end.tsv" || abort "pwdLastSet snapshot at the end"
check "dependency-blocked accounts never rotated: pwdLastSet unchanged since seeding on all $E_HELD held" \
  eq "$(pls_changed "$WORK/pls-seed.tsv" "$WORK/pls-end.tsv" "$WORK/sams-held.txt")" 0
check "exceptions never touched: pwdLastSet unchanged since seeding on all $E_EXC" \
  eq "$(pls_changed "$WORK/pls-seed.tsv" "$WORK/pls-end.tsv" "$WORK/sams-exception.txt")" 0
check "staff accounts never touched: pwdLastSet unchanged on all $M" \
  eq "$(jq -r '.noise_accounts[]' "$OUT/manifest.json" | pls_changed "$WORK/pls-seed.tsv" "$WORK/pls-end.tsv" /dev/stdin)" 0

# --- run record ---------------------------------------------------------------------------
write_scale_json() { # -> FILE: population, counts, stages, host shape
  local host vault_v samba_v
  host=$(docker info --format '{{json .}}' 2>/dev/null | jq -c '{ncpu: .NCPU, mem_gib: ((.MemTotal / 1073741824 * 10 | floor) / 10), os: "\(.OSType)/\(.Architecture)", docker: .ServerVersion}' 2>/dev/null || echo '{}')
  vault_v=$(curl -fsS "$PAM_VAULT_ADDR/v1/sys/seal-status" | jq -r '.version // "unknown"')
  samba_v=$(docker compose exec -T samba-dc samba --version </dev/null 2>/dev/null | tr -d '\r' | head -1 || echo unknown)
  jq -n --rawfile st "$WORK/stages.tsv" --rawfile res "$WORK/results.tsv" --slurpfile m "$OUT/manifest.json" \
    --arg ts "$RUN_UTC" --argjson host "$host" --arg vault "$vault_v" --arg samba "$samba_v" \
    --argjson n "$N" --argjson noise "$M" --argjson nbase "$NBASE" --argjson disc "$D_TOTAL" --argjson dbulk "$D_BULK" --argjson dstaff "$D_STAFF" \
    --argjson ev "$E_VAULTED" --argjson eh "$E_HELD" --argjson ee "$E_EXC" --argjson nstatic "$N_STATIC" --argjson nlib "$N_LIB" \
    --argjson ov "$O_VAULTED" --argjson oh "$O_HELD" --argjson oe "$O_EXC" \
    --argjson dn "$DEP_N" --argjson dc "$DEP_CLEAR" --argjson db "$DEP_BLOCKED" --argjson du "$DEP_UNKNOWN" \
    --argjson ks "$N_SAMPLE" --argjson rok "$ROT_OK" --argjson kd "$N_DRIFT" --argjson rref "$ROT_REFUSED" \
    --argjson rr "$R_ROWS" --argjson rv "$R_V" --argjson re "$R_E" --argjson rh "$R_H" --argjson rg "$R_G" --argjson ro "$R_O" \
    --arg code "$(shasum -a 256 < "$WORK/code.sha256sums" | cut -d' ' -f1)" '
    ($st | split("\n") | map(select(length > 0) | split("\t")
       | {stage: .[0], seconds: ((.[1] | tonumber) / 1000), accounts: (.[2] | tonumber), what: .[3]}
       | . + {accounts_per_second: (if .seconds > 0 then ((.accounts / .seconds * 10 | round) / 10) else null end)})) as $stages
    | ($res | split("\n") | map(select(length > 0) | split("\t") | .[0])) as $r
    | {schema: "contoso-pam/scale/v2", run_utc: $ts, code_sha256: $code,
       tenant: "none: local Docker only (Vault + Samba AD DC corp.test.local, synthetic accounts)",
       result: (if ($r | map(select(. != "PASS")) | length) == 0 and ($r | length) > 0 then "PASS" else "FAIL" end),
       checks: {pass: ($r | map(select(. == "PASS")) | length), fail: ($r | map(select(. != "PASS")) | length)},
       software: {vault: $vault, samba: $samba, pipeline: "lab/pam discover.sh, onboard.sh, rotate.sh, reconcile.sh, lib.sh"},
       host: $host,
       population: {bulk_accounts: $n, staff_accounts_not_privileged: $noise, base_layout_accounts: $nbase,
                    seed: $m[0].seed, mix: $m[0].mix,
                    dependency_records: ($m[0].accounts | map(.deps_status // "n/a") | group_by(.) | map({key: .[0], value: length}) | from_entries)},
       discovery: {discovered: $disc, bulk_discovered: $dbulk, staff_discovered: $dstaff},
       onboarding: {bulk_vaulted: $ov, bulk_vaulted_static_roles: $nstatic, bulk_vaulted_library_members: $nlib,
                    bulk_held_dependencies: $oh, bulk_exceptions_skipped: $oe,
                    expected_from_seed: {in_scope: $ev, held: $eh, exceptions: $ee}},
       dependency_check: {eligible_checked: $dn, clear: $dc, blocked: $db, unknown_no_record: $du, vaulted_blocked_by_rescan: $kd},
       rotation: {sampled: $ks, rotated: $rok, blocked_attempted: $kd, refused: $rref},
       reconcile: {rows: $rr, by_status: {VAULTED: $rv, EXCEPTION: $re, HELD: $rh, GAP: $rg, ORPHAN: $ro}, gap: $rg, orphan: $ro},
       stages: $stages,
       pipeline_seconds: ([$stages[] | select(.stage != "seed" and .stage != "rerun") | .seconds] | add),
       note: "seconds are wall-clock on the host above; the pipeline is one process per step (bash + jq + curl), no parallelism. pipeline_seconds = discovery + onboarding + dependency check + rotation + reconcile (it excludes seeding and the idempotency re-run)"}'
}
write_record() {
  local stage
  RECORD_WRITTEN=1
  stage=$(mktemp -d "$WORK/record.XXXXXX")
  cp "$WORK/run.log" "$stage/run.log"
  write_results_json > "$stage/results.json" || return 1
  write_scale_json > "$stage/scale.json" || return 1
  cp "$OUT/reconcile-latest.csv" "$stage/reconcile.csv"
  cp "$OUT/reconcile-latest.md" "$stage/reconcile.md"
  cp "$WORK/code.sha256sums" "$stage/code.sha256sums"
  run_record_seal "$stage" "$EVIDENCE_DIR" run.log results.json scale.json reconcile.csv reconcile.md code.sha256sums || return 1
  log "run record: $EVIDENCE_DIR (run.log, results.json, scale.json, reconcile.csv, reconcile.md, code.sha256sums, SHA256SUMS)"
}

printf '\n'
log "STAGES (wall clock, this host):"
awk -F'\t' '{ printf "  %-17s %7.1f s  %5d accounts  %7.1f accounts/s\n", $1, $2 / 1000, $3, ($2 > 0 ? $3 * 1000 / $2 : 0) }' "$WORK/stages.tsv"
if [[ -n "$EVIDENCE_DIR" ]]; then write_record || FAILS=$((FAILS + 1)); fi
if [[ $FAILS -eq 0 ]]; then
  log "E2E-SCALE PASSED ($N accounts; project $SC_PROJECT $([[ $KEEP -eq 1 ]] && echo 'kept: test/e2e-scale.sh --cleanup removes it' || echo 'removed'))"
  exit 0
fi
log "E2E-SCALE FAILED: $FAILS assertion(s)"
exit 1
