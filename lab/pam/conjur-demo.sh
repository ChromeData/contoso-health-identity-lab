#!/usr/bin/env bash
# =============================================================================
# conjur-demo.sh - workload (non-human) secrets with Conjur OSS.
#
#   1. Create the Conjur account (admin API key -> .secrets, 0600)
#   2. Load lab/pam/conjur/policy.yml (policy as code; additive, every run)
#   3. Seed a DEMO value into apps/servicenow-api-key (random, not a real key)
#   4. host/apps/nightly-report reads it      -> allowed
#   5. host/apps/unapproved-job tries to read -> 403, by policy
#
# API keys reach the CLI as CONJUR_AUTHN_LOGIN / CONJUR_AUTHN_API_KEY in the
# environment (`-e NAME` forwards the value without putting it in argv), and
# the demo value goes in on stdin - nothing secret on a command line, nothing
# cached in the CLI container's .netrc. Host API keys are rotated by admin on
# every run and kept only in shell variables, never on disk.
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need openssl; need curl

ACCOUNT=contoso
export CONJUR_AUTHN_LOGIN="" CONJUR_AUTHN_API_KEY=""

as() { # as IDENTITY < api-key   -> later `cli` calls authenticate as IDENTITY
  CONJUR_AUTHN_LOGIN="$1"
  CONJUR_AUTHN_API_KEY="$(tr -d '\r\n')"
  [[ -n "$CONJUR_AUTHN_API_KEY" && "$CONJUR_AUTHN_API_KEY" != null ]] || die "no API key for $1"
}
# stdin closed: the CLI must never sit waiting on an interactive prompt.
cli() { docker compose exec -T -e CONJUR_AUTHN_LOGIN -e CONJUR_AUTHN_API_KEY conjur-cli conjur "$@" </dev/null; }
cli_stdin() { docker compose exec -T -e CONJUR_AUTHN_LOGIN -e CONJUR_AUTHN_API_KEY conjur-cli conjur "$@"; }

# Conjur (amd64 under emulation on Apple Silicon) can take a minute after
# ./pam-up.sh before it answers.
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8083/ >/dev/null 2>&1 && break; sleep 3; done
curl -fsS http://127.0.0.1:8083/ >/dev/null 2>&1 || die "Conjur is not answering on 127.0.0.1:8083 (docker compose logs conjur)"

# Valid, not just present: the key must still authenticate (sent as the request
# body from the file, token discarded). Otherwise an interrupted first run or a
# re-created conjur-db volume leaves a key file that fails every later run.
admin_ok() {
  [[ -s "$1" ]] && curl -fsS -o /dev/null --data-binary "@$1" \
    "http://127.0.0.1:8083/authn/$ACCOUNT/admin/authenticate" 2>/dev/null
}
if ! admin_ok .secrets/conjur-admin-api-key; then
  log "Creating Conjur account '$ACCOUNT'"
  # Temp file + mv: a failed run must not leave an empty or wrong key behind.
  tmp=$(mktemp .secrets/conjur-admin.XXXXXX)
  docker compose exec -T conjur conjurctl account create "$ACCOUNT" \
    | sed -n 's/.*API key for admin: *//p' | tr -d '\r\n' > "$tmp" || true
  if [[ ! -s "$tmp" ]]; then
    # conjurctl exits 0 with no key when the account already exists (left by an
    # earlier run): read its admin key instead of re-creating the account.
    log "Account '$ACCOUNT' already exists - retrieving its admin API key"
    docker compose exec -T conjur conjurctl role retrieve-key "$ACCOUNT:user:admin" | tr -d '\r\n' > "$tmp" || true
  fi
  admin_ok "$tmp" || { rm -f "$tmp"; die "could not get a working Conjur admin API key (docker compose logs conjur)"; }
  mv "$tmp" .secrets/conjur-admin-api-key
fi

# CLI 9.x (rebranded "Idira Secrets Manager") needs the environment subcommand;
# --insecure = plain HTTP, acceptable only because Conjur is loopback-only here.
init_out=$(cli init self-hosted --url http://conjur --account "$ACCOUNT" --insecure --force 2>&1) \
  || die "conjur init failed: $init_out"
cli logout >/dev/null 2>&1 || true   # drop any login an older version cached
as admin < .secrets/conjur-admin-api-key

# Every run: `policy load` only adds what is missing, so re-applying is safe.
log "Loading policy (hosts + variable + permit)"
cli policy load --branch root --file /policy/policy.yml >/dev/null || die "conjur policy load failed"
printf 'demo-%s' "$(openssl rand -hex 16)" | cli_stdin variable set --id apps/servicenow-api-key --file /dev/stdin >/dev/null
log "Seeded apps/servicenow-api-key with a random DEMO value"

# policy load returns a host's API key only when it creates the host, so a saved
# copy is lost for good if a run dies. Rotate both (as admin) on every run.
rm -f .secrets/conjur-hosts.json   # earlier versions saved host keys here
log "Rotating the API keys of both hosts (as admin)"
nr_key=$(cli host rotate-api-key --id apps/nightly-report) || die "could not rotate the API key of host/apps/nightly-report"
uj_key=$(cli host rotate-api-key --id apps/unapproved-job) || die "could not rotate the API key of host/apps/unapproved-job"

log "As host/apps/nightly-report (permitted):"
as host/apps/nightly-report < <(printf '%s' "$nr_key"); nr_key=""
val=$(cli variable get --id apps/servicenow-api-key)
echo "  fetched secret (${#val} chars, value hidden)"
val=""

log "As host/apps/unapproved-job (no grant):"
as host/apps/unapproved-job < <(printf '%s' "$uj_key"); uj_key=""
if denied=$(cli variable get --id apps/servicenow-api-key 2>&1); then
  die "unapproved-job could read the secret - policy is wrong"
elif grep -q '403 Forbidden' <<<"$denied"; then
  echo "  denied (403 Forbidden) - least privilege enforced by policy"
else
  # Any other failure (Conjur down, 401 bad key) is NOT proof of least privilege.
  die "unexpected error instead of 403: $(tr -s ' \n' ' ' <<<"$denied")"
fi
