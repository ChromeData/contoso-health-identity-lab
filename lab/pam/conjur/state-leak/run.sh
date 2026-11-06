#!/usr/bin/env bash
# =============================================================================
# run.sh - does Terraform write a Conjur secret into its state file?
#
# The question: the obvious way to give Terraform a secret from Conjur is the
# provider's conjur_secret DATA SOURCE. Terraform keeps every data source
# result in terraform.tfstate, so the secret ends up there in plaintext.
# Marking things `sensitive` only hides them on screen. The fix is the
# provider's conjur_secret EPHEMERAL resource (Terraform 1.10+), which is
# never written to state.
#
# What it does (about 30 s on the lab Mac once the images are pulled; $0,
# no cloud, no tenant):
#   1. Starts a throwaway Conjur OSS 1.27.0 (own compose project, loopback).
#   2. Loads policy.yml; stores a RANDOM 40-character value (never a real
#      credential); checks the runner identity can fetch it.
#   3. datasource/: apply, apply again (a change, so a backup is written),
#      then a saved plan; counts the value in
#      terraform.tfstate, its backup, the saved plan and Terraform's output.
#   4. ephemeral/: first a plan that expects the wrong length, which must
#      fail on the precondition (so the check can fail); then the same steps
#      as 3. Its precondition proves the value really was read.
#   5. Deletes Conjur, its volume and the work folder (KEEP=1 keeps them).
#
# Exit: 0 = the result the README states (data source leaks into state,
# backup and saved plan; ephemeral does not and did read the value);
# 1 = a different result (read the table); 2 = could not run (including an
# existing contoso-stateleak stack or a busy port, which it leaves alone). Nothing secret is printed: counts and lengths only.
#
# Secrets handling: the Conjur admin key, host key, auth tokens and the value
# live in shell variables and 0600 files in a mktemp folder; they reach curl
# on stdin or through a header FILE (-H @file), never on a command line, and
# reach Terraform as CONJUR_* environment variables (provider docs).
#
# Needs: docker (compose v2), curl, openssl, python3, and HashiCorp Terraform
# >= 1.10 as `terraform` (or TF_BIN=/path/to/terraform). OpenTofu is refused:
# the finding is about Terraform, and the lab's CI runs Terraform.
#
# Ported from the author's earlier Conjur-Terraform-AWS lab, which ran the
# data-source half by hand; this script makes it one command and adds the
# ephemeral half. Its AWS/VPC/bastion/IAM-user parts are not ported.
# =============================================================================
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_BIN="${TF_BIN:-terraform}"
PORT="${STATE_LEAK_PORT:-8093}"
ACCOUNT=stateleak
URL="http://127.0.0.1:$PORT"
HOST_ID="state-leak/terraform-runner"
VAR_ID="state-leak/db-password"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { echo "COULD NOT RUN: $*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
for t in docker curl openssl python3 "$TF_BIN"; do need "$t"; done
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

tf_version="$("$TF_BIN" version 2>/dev/null | head -1)"
[[ "$tf_version" =~ ^Terraform\ v([0-9]+)\.([0-9]+) ]] \
  || die "$TF_BIN is not HashiCorp Terraform (got: ${tf_version:-nothing})"
(( BASH_REMATCH[1] > 1 || BASH_REMATCH[2] >= 10 )) \
  || die "Terraform >= 1.10 is needed for ephemeral resources (got $tf_version)"

# The compose project is pinned HERE, for every docker compose call below. An
# inherited COMPOSE_PROJECT_NAME (or COMPOSE_FILE) would otherwise point
# them, and the cleanup's `down -v`, at someone else's stack.
PROJECT=contoso-stateleak
export COMPOSE_PROJECT_NAME="$PROJECT" COMPOSE_FILE="$HERE/docker-compose.yml" STATE_LEAK_PORT="$PORT"
STATE_LEAK_DB_PASSWORD="$(openssl rand -hex 24)"
STATE_LEAK_DATA_KEY="$(openssl rand -base64 32)"
export STATE_LEAK_DB_PASSWORD STATE_LEAK_DATA_KEY

# Refuse BEFORE taking ownership: if an earlier run (or a KEEP=1 stack) is
# still there, or the port is taken, stop without touching it. The cleanup
# trap is installed only after these checks, so a refusal deletes nothing.
existing="$(docker compose ps -a -q 2>/dev/null)" || die "cannot ask docker compose about project $PROJECT"
[[ -z "$existing" ]] || die "compose project $PROJECT already exists (an earlier KEEP=1 run?); remove it with: docker compose -p $PROJECT -f $COMPOSE_FILE down -v"
if curl -fsS -o /dev/null "$URL/" 2>/dev/null; then
  die "something already answers on $URL; set STATE_LEAK_PORT to a free port"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/conjur-state-leak.XXXXXX")"
cleanup() {
  if [[ "${KEEP:-0}" == 1 ]]; then
    log "KEEP=1: left Conjur (project $PROJECT) and $WORK"
    return
  fi
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- 1. Conjur ---------------------------------------------------------------
log "Starting a throwaway Conjur OSS 1.27.0 on $URL"
docker compose up -d >/dev/null 2>&1 || die "docker compose up failed (docker compose -f $COMPOSE_FILE logs)"
# Root answers 200 unauthenticated once Conjur is up (the earlier lab found
# /health and /info need a token). amd64 under emulation can take a minute.
for _ in $(seq 1 60); do curl -fsS -o /dev/null "$URL/" 2>/dev/null && break; sleep 3; done
curl -fsS -o /dev/null "$URL/" 2>/dev/null || die "Conjur did not come up on $URL"

admin_key="$(docker compose exec -T conjur conjurctl account create "$ACCOUNT" 2>/dev/null \
  | sed -n 's/.*API key for admin: *//p' | tr -d '\r\n')"
[[ -n "$admin_key" ]] || die "conjurctl account create returned no admin API key"

# token_for LOGIN <<< API_KEY  -> writes a 0600 curl header file, prints its path.
# POST /authn/{account}/{login}/authenticate with the API key as the body;
# Accept-Encoding: base64 returns the token ready for the Authorization header
# (same REST calls as terraform-provider-conjur's bin/test, v0.9.15).
token_for() {
  local login_enc hdr tok
  login_enc="$(python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1")"
  tok="$(curl -fsS -H 'Accept-Encoding: base64' --data-binary @- \
    "$URL/authn/$ACCOUNT/$login_enc/authenticate")" || return 1
  [[ -n "$tok" ]] || return 1
  hdr="$(mktemp "$WORK/hdr.XXXXXX")"
  printf 'Authorization: Token token="%s"\n' "$tok" > "$hdr"
  echo "$hdr"
}

admin_hdr="$(printf '%s' "$admin_key" | token_for admin)" || die "admin could not authenticate"

# --- 2. Policy, value, runner check -----------------------------------------
log "Loading policy.yml (one variable, one runner host)"
load_out="$(curl -fsS -H "@$admin_hdr" --data-binary "@$HERE/policy.yml" \
  "$URL/policies/$ACCOUNT/policy/root")" || die "policy load failed"
host_key="$(printf '%s' "$load_out" | python3 -I -c '
import json, sys
roles = json.load(sys.stdin).get("created_roles", {})
print(next((v.get("api_key", "") for k, v in roles.items() if k.endswith(":host:'"$HOST_ID"'")), ""))')"
[[ -n "$host_key" ]] || die "the policy load returned no API key for host/$HOST_ID"

secret="$(openssl rand -base64 30 | tr -d '\n')"     # 40 characters, random
[[ ${#secret} -eq 40 ]] || die "could not generate the test value"
var_enc="$(python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$VAR_ID")"
printf '%s' "$secret" | curl -fsS -o /dev/null -H "@$admin_hdr" --data-binary @- \
  "$URL/secrets/$ACCOUNT/variable/$var_enc" || die "could not store the test value"
log "Stored a random ${#secret}-character value in $VAR_ID (never printed)"

host_hdr="$(printf '%s' "$host_key" | token_for "host/$HOST_ID")" || die "host/$HOST_ID could not authenticate"
fetched="$(curl -fsS -H "@$host_hdr" "$URL/secrets/$ACCOUNT/variable/$var_enc")" \
  || die "host/$HOST_ID could not fetch $VAR_ID (policy?)"
[[ "$fetched" == "$secret" ]] || die "host/$HOST_ID fetched a different value"
unset fetched
log "host/$HOST_ID can fetch the value (policy works)"

# --- 3/4. Terraform, both ways ------------------------------------------------
export CONJUR_APPLIANCE_URL="$URL" CONJUR_ACCOUNT="$ACCOUNT"
export CONJUR_AUTHN_LOGIN="host/$HOST_ID" CONJUR_AUTHN_API_KEY="$host_key"
export TF_PLUGIN_CACHE_DIR="$WORK/plugin-cache" TF_IN_AUTOMATION=1 TF_INPUT=0
mkdir -p "$TF_PLUGIN_CACHE_DIR"
export STATE_LEAK_SECRET="$secret"   # read by count_secret.py from its environment

# Results as R_<path>_<file> variables (printf -v / ${!name}): macOS ships
# bash 3.2, which has no associative arrays.
res() { local n="R_$1_$2"; echo "${!n}"; }
run_path() {  # run_path NAME [extra terraform args...]
  local name="$1"; shift
  local dir="$WORK/$name" logf="$WORK/$name.log"
  cp -R "$HERE/$name" "$dir"
  log "[$name] terraform init / apply / apply again / plan -out"
  {
    "$TF_BIN" -chdir="$dir" init -lockfile=readonly -no-color \
    && "$TF_BIN" -chdir="$dir" apply -auto-approve -no-color -var run_id=1 "$@" \
    && "$TF_BIN" -chdir="$dir" apply -auto-approve -no-color -var run_id=2 "$@" \
    && "$TF_BIN" -chdir="$dir" plan -out=saved.tfplan -no-color -var run_id=3 "$@"
  } > "$logf" 2>&1 || { tail -20 "$logf" | sed 's/^/    /' >&2; die "[$name] terraform failed (log above)"; }
  # The second apply changes run_id, so Terraform writes
  # terraform.tfstate.backup: the earlier lab's open question was whether the
  # backup keeps the value too. "absent" in the table means no backup was
  # written; the verdict counts that as a failure on either path.
  local counts
  counts="$(python3 -I "$HERE/count_secret.py" "$dir/terraform.tfstate" \
    "$dir/terraform.tfstate.backup" "$dir/saved.tfplan" "$logf")" || die "[$name] the scan could not run"
  printf -v "R_${name}_state" %s "$(sed -n 1p <<<"$counts" | cut -f1)"
  printf -v "R_${name}_backup" %s "$(sed -n 2p <<<"$counts" | cut -f1)"
  printf -v "R_${name}_plan" %s "$(sed -n 3p <<<"$counts" | cut -f1)"
  printf -v "R_${name}_log" %s "$(sed -n 4p <<<"$counts" | cut -f1)"
}

run_path datasource

# The precondition must be able to fail, or "the ephemeral path read the value"
# proves nothing. A plan told to expect the wrong length must stop on it.
log "[ephemeral] negative control: a plan expecting the wrong length must fail"
neg="$WORK/ephemeral-negative"
cp -R "$HERE/ephemeral" "$neg"
"$TF_BIN" -chdir="$neg" init -lockfile=readonly -no-color > "$neg.log" 2>&1 || die "[ephemeral] init failed"
if "$TF_BIN" -chdir="$neg" plan -no-color -var "expected_secret_length=$(( ${#secret} - 1 ))" >> "$neg.log" 2>&1; then
  die "[ephemeral] the precondition did not fail on a wrong length; it would not prove the value was read"
fi
grep -q "did not return the value run.sh stored" "$neg.log" \
  || { tail -20 "$neg.log" | sed 's/^/    /' >&2; die "[ephemeral] the negative plan failed, but not on the precondition"; }
log "[ephemeral] negative control failed on the precondition, as it must"

run_path ephemeral -var "expected_secret_length=${#secret}"
log "Terraform: $tf_version; provider cyberark/conjur 0.9.15 (lock file)"

# --- Verdict -----------------------------------------------------------------
echo
printf '%-12s %-18s %-26s %-12s %s\n' "path" "terraform.tfstate" "terraform.tfstate.backup" "saved plan" "terraform output"
for p in datasource ephemeral; do
  printf '%-12s %-18s %-26s %-12s %s\n' "$p" "$(res $p state)" "$(res $p backup)" "$(res $p plan)" "$(res $p log)"
done
echo "(times the ${#secret}-character value appears in each file)"
echo

# The verdict is count_secret.py's (unit-tested): every published number must
# hold, including the data source's backup and saved plan.
python3 -I "$HERE/count_secret.py" --verdict \
  "$(res datasource state)" "$(res datasource backup)" "$(res datasource plan)" "$(res datasource log)" \
  "$(res ephemeral state)" "$(res ephemeral backup)" "$(res ephemeral plan)" "$(res ephemeral log)"
