#!/usr/bin/env bash
# =============================================================================
# ingest-vault-audit.sh - forward PAM check-out evidence from the lab Vault's
# audit log to Log Analytics (custom table VaultCheckout_CL).
# -----------------------------------------------------------------------------
# WHY: lab/kql/tier0-logon-without-checkout.kql alerts on a Tier-0 logon on
# DC01 that no vault check-out covers. That join needs the check-outs in the
# same workspace as the DC's SecurityEvent rows. This script is the feed.
#
# STAND-IN: the lab's vault is HashiCorp Vault in Docker on the operator's
# laptop (lab/pam), so there is no VM for the Azure Monitor Agent to sit on.
# Production equivalent (ADR 0027): Azure Key Vault diagnostic logs
# (AuditEvent) -> Log Analytics -> Sentinel, or for a self-run Vault its
# socket/syslog audit device -> AMA on the vault host. Same evidence, delivered by an agent instead of a
# script.
#
# PIPELINE (per run)
#   1. Read the NEW part of /vault/logs/audit.log (file audit device enabled by
#      lab/pam/pam-up.sh) - from the byte offset saved in .state/, complete
#      lines only, so a line Vault is still writing is read next time.
#   2. Keep successful responses to ldap/library/<set>/check-out and
#      .../check-in (and the manage/ force check-in): one row per account.
#   3. Resolve account names. Vault HMACs every string in an audit record by
#      default (service_account_name becomes "hmac-sha256:..."), so the script
#      asks Vault for the HMAC of each library account (sys/audit-hash/file)
#      and maps them back. Production alternative: tune the mount once -
#      `vault secrets tune -audit-non-hmac-response-keys=service_account_name
#      -audit-non-hmac-response-keys=check_ins ldap/` - then names arrive in
#      clear and this step is a no-op. Unresolvable values ship with
#      AccountResolved=false and an empty Account: the detection then treats
#      the logon as uncovered (fail-safe), and this script warns.
#   3b. --signals all ONLY (feeds lab/kql/vault-privileged-access-anomaly.kql,
#      the PTA-style rule): every response record can ALSO yield one row per
#      matching anomaly Operation, from any path and any token:
#        cred-read        successful read of ldap/static-cred/<role>
#                         (Account = the role's last path segment)
#        rotation-failed  ldap/rotate-role/*, ldap/rotate-root or a library
#                         check-in that returned an error other than
#                         "permission denied" (the old password may still work)
#        root-token       any request made with a token holding the root policy
#        auth-failed      a failed auth/<method>/login/* (top-level error, or
#                         only response.data.error: Vault 2.1.1 logs an
#                         unknown userpass user that way), or any call with
#                         an invalid token
#        access-denied    "permission denied" for a valid token
#      Every row then carries three more columns: Ticket and Operator (the
#      calling token's metadata - psm-session.sh / psm-ssh.sh set both;
#      Vault logs token metadata in clear) and ErrorText (the audit record's
#      error on one line, first 512 characters). One record can give several rows (a
#      root check-in is a check-in AND a root-token row; same RequestId).
#      Check-out / check-in rows stay limited to --library; anomaly rows are
#      vault-wide. Not visible in the audit log at all: Vault's OWN periodic
#      static-role rotations (no request), so a failed automatic rotation
#      never becomes a rotation-failed row - reconcile.sh --verify covers it.
#   4. Add ONE heartbeat row (Operation=heartbeat) so the detection can tell
#      "no check-out happened" from "the feed is down" (VaultFeedHealthy).
#   5. POST JSON arrays to the Logs Ingestion API (DCE + DCR from Terraform
#      modules/monitoring output vault_ingestion) with an Entra token from
#      your `az login` - no shared key, no client secret. HTTP 204 = accepted.
#      The offset advances only after every batch is accepted.
#
# PREREQUISITES (human, once)
#   * envs/dev applied with enable_itdr_detections = true (table, DCE, DCR).
#   * Your identity holds "Monitoring Metrics Publisher" on the DCR. CI cannot
#     grant it (not on the apply identity's delegable list), so:
#       az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" \
#         --role "Monitoring Metrics Publisher" --scope <vault_ingestion.dcr_id>
#     (a 403 from this script prints the same command).
#   * lab/pam stack up (./pam-up.sh) with the tier0 library onboarded.
#
# USAGE
#   ./ingest-vault-audit.sh [options]
#     --endpoint URL      DCE logs ingestion endpoint ($VAULT_INGEST_ENDPOINT)
#     --dcr-id ID         DCR immutable id, dcr-<32 hex> ($VAULT_INGEST_DCR_ID)
#     --stream NAME       DCR stream (default Custom-VaultCheckout)
#     --library NAME      Vault LDAP library set (default tier0-admins)
#     --signals SET       checkout (default): check-out / check-in / heartbeat
#                         rows in the 11 VaultCheckout_CL columns the DCR
#                         declares today. all: + the anomaly Operations of
#                         step 3b and the Ticket / Operator / ErrorText
#                         columns ($VAULT_INGEST_SIGNALS). Send `all` only
#                         once modules/monitoring declares those three
#                         columns in the table AND the DCR stream (a schema
#                         change goes in the table, the stream and this
#                         script together). verify: whether the Logs
#                         Ingestion API drops or rejects undeclared columns.
#     --audit-file FILE   read this file instead of the Vault container's log
#                         (offline tests, or a copied log)
#     --hash-map FILE     JSON {"hmac-sha256:...": "account"} instead of asking
#                         Vault (offline tests)
#     --state-dir DIR     where the byte offset lives (default ./.state)
#     --from-start        ignore the saved offset (re-sends rows - duplicates
#                         are harmless to the detection, but they are rows)
#     --dry-run           print the rows as one JSON array on stdout, send
#                         nothing, keep the offset
#     --follow SECONDS    repeat every SECONDS until Ctrl-C (use 60 while
#                         recording: the detection allows 15 min of delay)
#     -h, --help
#
# Written for macOS bash 3.2 (no associative arrays / mapfile). Requires jq,
# curl; az for sending; docker for the live Vault source.
# =============================================================================
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAM_DIR="$(cd "$SCRIPT_DIR/../../pam" && pwd)"
API_VERSION="2023-01-01"
BATCH_ROWS=500     # far below the 1 MB per-call limit at ~400 bytes a row

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
warn() { printf '[%s] WARN: %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vault-ingest.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------- options ---
ENDPOINT="${VAULT_INGEST_ENDPOINT:-}"
DCR_ID="${VAULT_INGEST_DCR_ID:-}"
STREAM="Custom-VaultCheckout"
LIBRARY="tier0-admins"
SIGNALS="${VAULT_INGEST_SIGNALS:-checkout}"
AUDIT_FILE=""
HASH_MAP=""
STATE_DIR="$SCRIPT_DIR/.state"
FROM_START=0
DRY=0
FOLLOW=0

while (( $# > 0 )); do
  case "$1" in
    --endpoint)   ENDPOINT="${2:?missing value for $1}"; shift 2 ;;
    --dcr-id)     DCR_ID="${2:?missing value for $1}"; shift 2 ;;
    --stream)     STREAM="${2:?missing value for $1}"; shift 2 ;;
    --library)    LIBRARY="${2:?missing value for $1}"; shift 2 ;;
    --signals)    SIGNALS="${2:?missing value for $1}"; shift 2 ;;
    --audit-file)AUDIT_FILE="${2:?missing value for $1}"; shift 2 ;;
    --hash-map)   HASH_MAP="${2:?missing value for $1}"; shift 2 ;;
    --state-dir)  STATE_DIR="${2:?missing value for $1}"; shift 2 ;;
    --from-start) FROM_START=1; shift ;;
    --dry-run)    DRY=1; shift ;;
    --follow)     FOLLOW="${2:?missing value for $1}"; shift 2 ;;
    -h|--help)    awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

need jq; need curl
[[ "$LIBRARY" =~ ^[A-Za-z0-9_-]+$ ]] || die "--library must be a plain set name"
[[ "$SIGNALS" == checkout || "$SIGNALS" == all ]] || die "--signals must be 'checkout' or 'all'"
[[ "$STREAM" =~ ^Custom-[A-Za-z0-9_]+$ ]] || die "--stream must look like Custom-<Name>"
[[ "$FOLLOW" == "0" || "$FOLLOW" =~ ^[1-9][0-9]*$ ]] || die "--follow takes a number of seconds"
if (( DRY == 0 )); then
  [[ "$ENDPOINT" =~ ^https://[A-Za-z0-9.-]+\.ingest\.monitor\.azure\.com/?$ ]] \
    || die "--endpoint must be the DCE logs ingestion endpoint (https://<name>.<region>-1.ingest.monitor.azure.com); terraform output vault_ingestion"
  ENDPOINT="${ENDPOINT%/}"
  [[ "$DCR_ID" =~ ^dcr-[0-9a-f]{32}$ ]] || die "--dcr-id must be the DCR immutable id (dcr-<32 hex>); terraform output vault_ingestion"
  need az
fi
if [[ -n "$AUDIT_FILE" ]]; then
  [[ -f "$AUDIT_FILE" ]] || die "--audit-file not found: $AUDIT_FILE"
else
  need docker
fi
if [[ -n "$HASH_MAP" ]]; then
  jq -e 'type == "object"' "$HASH_MAP" >/dev/null 2>&1 || die "--hash-map must be a JSON object {hmac: account}"
fi
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
OFFSET_FILE="$STATE_DIR/vault-audit.offset"
SOURCE_HOST="$(hostname -s 2>/dev/null || hostname)"

# ------------------------------------------------------- Vault (lab/pam) ---
pam_compose() { docker compose -f "$PAM_DIR/docker-compose.yml" --project-directory "$PAM_DIR" "$@"; }

# vault_cli ARGS... - the CLI inside the container, root token forwarded via
# the environment (`-e VAULT_TOKEN` without a value), never via argv.
vault_cli() {
  local init="$PAM_DIR/.secrets/vault-init.json"
  [[ -f "$init" ]] || die "lab/pam/.secrets/vault-init.json missing - is the PAM stack initialised (./pam-up.sh)?"
  VAULT_TOKEN="$(jq -r '.root_token' "$init")" pam_compose exec -T -e VAULT_TOKEN vault vault "$@"
}

audit_size() {
  if [[ -n "$AUDIT_FILE" ]]; then wc -c < "$AUDIT_FILE" | tr -d ' '
  else pam_compose exec -T vault sh -c 'wc -c < /vault/logs/audit.log' | tr -d ' \r'
  fi
}

audit_tail_from() { # audit_tail_from BYTE_OFFSET (validated integer) -> stdout
  local start=$(( $1 + 1 ))
  if [[ -n "$AUDIT_FILE" ]]; then tail -c +"$start" "$AUDIT_FILE"
  else pam_compose exec -T vault sh -c "tail -c +$start /vault/logs/audit.log"
  fi
}

build_hash_map() { # -> JSON object {hmac: account} on stdout
  if [[ -n "$HASH_MAP" ]]; then cat "$HASH_MAP"; return; fi
  local names acct hash map='{}'
  names="$(vault_cli read -format=json "ldap/library/$LIBRARY" | jq -r '.data.service_account_names | if type == "array" then .[] else split(",")[] end')" \
    || die "could not read library '$LIBRARY' from Vault (stack up? onboarded? see lab/pam/README.md)"
  for acct in $names; do
    [[ "$acct" =~ ^[A-Za-z0-9._@-]+$ ]] || die "unexpected account name in library: $acct"
    # sys/audit-hash/file: the HMAC the 'file' audit device writes for this
    # input. Same salt, so it matches the audit log exactly.
    hash="$(vault_cli write -format=json sys/audit-hash/file input="$acct" | jq -r '.data.hash // .hash')" \
      || die "sys/audit-hash/file failed (audit device path 'file' - see pam-up.sh)"
    map="$(jq -c --arg h "$hash" --arg a "$acct" '. + {($h): $a}' <<<"$map")"
  done
  printf '%s\n' "$map"
}

# One audit RESPONSE record -> zero or more VaultCheckout_CL rows (JSONL).
# frac6: Vault writes nanoseconds; Log Analytics datetimes keep 7 digits at
# most, so trim to microseconds.
# shellcheck disable=SC2016  # a jq program: $map/$lib/$host are jq variables
JQ_ROWS='
  def frac6:
    capture("^(?<s>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?<f>\\.[0-9]+)?(?<z>Z|[+-][0-9]{2}:[0-9]{2})$")
    | .s + (((.f // ".0") + "000000") | .[0:7]) + .z;
  def resolve($m):
    if type == "string" and startswith("hmac-sha256:") then ($m[.] // null) else . end;
  fromjson?
  | select(.type == "response")
  | select((.request.operation // "") == "update")
  | select((.request.path // "") | test("^ldap/library/(manage/)?[^/]+/check-(out|in)$"))
  | select((.error // "") == "")
  | (.request.path | capture("^ldap/library/(manage/)?(?<lib>[^/]+)/check-(?<op>out|in)$")) as $p
  | select($p.lib == $lib)
  | . as $e
  | (if $p.op == "out" then [($e.response.data.service_account_name // empty)]
     else ($e.response.data.check_ins // []) end)[]
  | resolve($map) as $acct
  | { TimeGenerated:   ($e.time | frac6),
      Operation:       ("check-" + $p.op),
      Account:         (($acct // "") | ascii_downcase),
      AccountResolved: ($acct != null),
      Library:         $p.lib,
      VaultPath:       $e.request.path,
      RequestId:       ($e.request.id // ""),
      RemoteAddress:   ($e.request.remote_address // ""),
      VaultActor:      ($e.auth.display_name // ""),
      TokenPolicies:   (($e.auth.policies // []) | join(",")),
      SourceHost:      $host }
'

# --signals all: the same check-out / check-in rows, plus the anomaly rows of
# step 3b, every row with Ticket / Operator / ErrorText. Each branch of the
# comma list below is independent: a record that matches none yields nothing.
# shellcheck disable=SC2016  # a jq program: $map/$lib/$host are jq variables
JQ_ROWS_ALL='
  def frac6:
    capture("^(?<s>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?<f>\\.[0-9]+)?(?<z>Z|[+-][0-9]{2}:[0-9]{2})$")
    | .s + (((.f // ".0") + "000000") | .[0:7]) + .z;
  def resolve($m):
    if type == "string" and startswith("hmac-sha256:") then ($m[.] // null) else . end;
  def str: if . == null then "" elif type == "string" then . else tojson end;
  def lastseg: split("/") | last;
  def row($e; $op; $acct; $resolved; $library):
    { TimeGenerated:   ($e.time | frac6),
      Operation:       $op,
      Account:         (($acct // "") | ascii_downcase),
      AccountResolved: $resolved,
      Library:         $library,
      VaultPath:       ($e.request.path // ""),
      RequestId:       ($e.request.id // ""),
      RemoteAddress:   ($e.request.remote_address // ""),
      VaultActor:      ($e.auth.display_name // ""),
      TokenPolicies:   (($e.auth.policies // []) | join(",")),
      SourceHost:      $host,
      Ticket:          ($e.auth.metadata.ticket | str),
      Operator:        ($e.auth.metadata.operator | str),
      # Vault formats multi-errors over several lines ("2 errors occurred:\n\t* ...");
      # one line per row reads better in Sentinel / Splunk.
      ErrorText:       ($e.error | str | gsub("\\s+"; " ") | sub("^ "; "") | sub(" $"; "") | .[0:512]) };
  fromjson?
  | select(type == "object" and .type == "response")
  | . as $e
  | ($e.request.path // "") as $path
  | ($e.request.operation // "") as $verb
  | ($e.error | str) as $err
  | ([$path | capture("^ldap/library/(manage/)?(?<lib>[^/]+)/check-(?<op>out|in)$")?] | .[0]) as $lp
  | (if $lp == null then "" else $lp.lib end) as $plib
  | ($path | test("^auth/[^/]+/login(/|$)")) as $login
  | (
      # check-out / check-in that succeeded, chosen library only (as checkout mode)
      ( select($lp != null and $verb == "update" and $err == "" and $lp.lib == $lib)
        | (if $lp.op == "out" then [($e.response.data.service_account_name // empty)]
           else ($e.response.data.check_ins // []) end)[]
        | resolve($map) as $acct
        | row($e; "check-" + $lp.op; $acct; $acct != null; $lp.lib) ),
      # static credential read (username in clear only on a tuned mount)
      ( select($verb == "read" and $err == "" and ($path | test("^ldap/static-cred/.+")))
        | ($e.response.data.username // null) as $u
        | row($e; "cred-read";
              (if ($u | type) == "string" and ($u | startswith("hmac-sha256:") | not) then $u
               else ($path | lastseg) end); true; "") ),
      # a rotation that returned an error: the old password may still be valid
      ( select($err != "" and ($err | test("permission denied") | not)
               and ($path | test("^ldap/(rotate-role/.+|rotate-root|library/(manage/)?[^/]+/check-in)$")))
        | (if ($path | startswith("ldap/rotate-role/")) then [($path | lastseg)]
           elif $lp != null then
             ([$e.request.data.service_account_names // empty
               | if type == "array" then .[] else (str | split(",")[]) end]
              | if length == 0 then [null] else . end)
           else [null] end)[]
        | . as $raw
        | resolve($map) as $acct
        | row($e; "rotation-failed"; $acct; ($raw == null or $acct != null); $plib) ),
      # any request with a root-policy token
      ( select(any(($e.auth.policies // [])[]; . == "root"))
        | row($e; "root-token"; null; true; $plib) ),
      # failed login, or a call with an invalid token. Vault 2.1.1 (seen on a
      # real run, test/e2e-vault-anomaly.sh): a wrong password for a KNOWN
      # userpass user carries error "invalid credentials"; for an UNKNOWN
      # user the record has NO top-level error, only response.data.error
      # (HMAC-ed) - both are failures.
      ( select(($login and ($err != "" or $e.response.data.error != null)) or ($err | test("invalid token")))
        | row($e; "auth-failed"; null; true; "")
        | if .ErrorText == "" then .ErrorText = "login refused (response.data.error only; HMAC-ed in the audit log)" else . end ),
      # a VALID token refused by policy
      ( select(($err | test("permission denied")) and ($err | test("invalid token") | not) and ($login | not))
        | row($e; "access-denied"; null; true; $plib) )
    )
'

# ---------------------------------------------------------- Logs Ingestion --
# Entra access tokens live 60-90 minutes, and --follow runs for hours: the
# header file is re-fetched when it is older than TOKEN_MAX_AGE_MIN (well
# inside the lifetime), and post_batch drops it and retries once on a 401.
TOKEN_MAX_AGE_MIN=45
token_header() { # writes "Authorization: Bearer ..." to a 0600 file; refreshes it when stale
  local f="$TMP_DIR/auth.hdr" tok
  if [[ -s "$f" && -n "$(find "$f" -mmin +"$TOKEN_MAX_AGE_MIN" 2>/dev/null)" ]]; then rm -f "$f"; fi
  if [[ ! -s "$f" ]]; then
    tok="$(az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv --only-show-errors)" \
      || die "no Azure Monitor token - run 'az login' (your operator login; no new secret)"
    printf 'Authorization: Bearer %s\n' "$tok" > "$f"
    tok=""
  fi
  printf '%s\n' "$f"
}

post_batch() { # post_batch JSON_ARRAY_FILE
  local url="$ENDPOINT/dataCollectionRules/$DCR_ID/streams/$STREAM?api-version=$API_VERSION"
  local resp="$TMP_DIR/resp.json" code hdr attempt refreshed=0
  for attempt in 1 2 3; do
    hdr="$(token_header)"
    code="$(curl -sS --max-time 60 -o "$resp" -w '%{http_code}' -H @"$hdr" \
              -H 'Content-Type: application/json' --data-binary @"$1" "$url")" || code="000"
    case "$code" in
      204) return 0 ;;
      401)
        # Expired / revoked token: fetch a new one and retry ONCE.
        if (( refreshed == 0 )); then
          warn "HTTP 401 - access token expired or revoked; fetching a new one and retrying"
          rm -f "$hdr"; refreshed=1; continue
        fi ;;
      403) die "HTTP 403 from the Logs Ingestion API - your identity lacks 'Monitoring Metrics Publisher' on the DCR. Grant it (human step):
  az role assignment create --assignee \"\$(az ad signed-in-user show --query id -o tsv)\" --role \"Monitoring Metrics Publisher\" --scope <terraform output vault_ingestion.dcr_id>
(role assignments take a few minutes to apply)" ;;
      429|500|502|503|000)
        if (( attempt < 3 )); then warn "HTTP $code (attempt $attempt/3) - retrying in $((attempt * 5))s"; sleep $((attempt * 5)); continue; fi ;;
    esac
    die "Logs Ingestion API rejected the batch: HTTP $code $(head -c 400 "$resp" 2>/dev/null)"
  done
}

# --------------------------------------------------------------- one run ---
run_once() {
  local offset=0 size chunk rows map n=0 batches=0 unresolved b arr consumed
  if (( FROM_START == 0 )) && [[ -s "$OFFSET_FILE" ]]; then
    offset="$(tr -d '[:space:]' < "$OFFSET_FILE")"
    [[ "$offset" =~ ^[0-9]+$ ]] || die "$OFFSET_FILE is corrupt - delete it or use --from-start"
  fi
  size="$(audit_size)"
  [[ "$size" =~ ^[0-9]+$ ]] || die "could not read the audit log size (Vault container up? audit device enabled?)"
  if (( size < offset )); then
    warn "audit log is smaller than the saved offset ($size < $offset): it was recreated - reading from the start"
    offset=0
  fi

  chunk="$TMP_DIR/chunk.log"
  audit_tail_from "$offset" > "$chunk"
  # Complete lines only: a record Vault is still writing is read next run.
  if [[ -s "$chunk" && "$(tail -c 1 "$chunk" | od -An -c | tr -d ' ')" != '\n' ]]; then
    sed '$d' "$chunk" > "$chunk.full" && mv "$chunk.full" "$chunk"
  fi
  consumed="$(wc -c < "$chunk" | tr -d ' ')"

  # Lines that are not JSON objects are skipped by the transform - count them
  # so a damaged log is never silently half-read.
  local invalid
  invalid="$(jq -R -r '(try (fromjson | type) catch "bad") as $t | if $t == "object" then empty else "x" end' "$chunk" | grep -c x || true)"
  (( invalid == 0 )) || warn "$invalid audit line(s) were not JSON objects and were skipped (truncated or damaged log?)"

  map="$TMP_DIR/map.json"
  # Only check-out / check-in records need names. Matching the bare
  # 'ldap/library/' prefix would also match this script's OWN root read of
  # ldap/library/<set> (build_hash_map), so every --follow cycle would trigger
  # the next one - and, with --signals all, emit root-token rows forever.
  if [[ -s "$chunk" ]] && grep -Eq 'ldap/library/(manage/)?[^/"]+/check-(out|in)' "$chunk"; then
    build_hash_map > "$map"
  else
    printf '{}\n' > "$map"
  fi

  rows="$TMP_DIR/rows.jsonl"
  local program="$JQ_ROWS" noun="check-out/in"
  if [[ "$SIGNALS" == all ]]; then program="$JQ_ROWS_ALL"; noun="check-out/in + anomaly"; fi
  jq -c -R --argjson map "$(cat "$map")" --arg host "$SOURCE_HOST" --arg lib "$LIBRARY" "$program" "$chunk" > "$rows" \
    || die "could not convert audit records (see jq error above)"
  # Heartbeat: proves the feed ran even when nobody checked anything out.
  jq -nc --arg t "$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)" --arg host "$SOURCE_HOST" --arg lib "$LIBRARY" \
    --arg signals "$SIGNALS" \
    '{TimeGenerated: $t, Operation: "heartbeat", Account: "", AccountResolved: true, Library: $lib,
      VaultPath: "", RequestId: "", RemoteAddress: "", VaultActor: "ingest-vault-audit.sh",
      TokenPolicies: "", SourceHost: $host}
     + (if $signals == "all" then {Ticket: "", Operator: "", ErrorText: ""} else {} end)' >> "$rows"

  n=$(( $(wc -l < "$rows" | tr -d ' ') - 1 ))
  unresolved="$(jq -s '[.[] | select(.AccountResolved == false)] | length' "$rows")"
  (( unresolved == 0 )) || warn "$unresolved check-out/in row(s) could not be mapped to an account (HMAC not in the library?) - sent with AccountResolved=false; their logons will alert"

  if (( DRY == 1 )); then
    jq -s '.' "$rows"
    log "DRY RUN: $n $noun row(s) + 1 heartbeat built from $consumed new byte(s); nothing sent, offset kept at $offset"
    return 0
  fi

  split -a 4 -l "$BATCH_ROWS" "$rows" "$TMP_DIR/batch."
  for b in "$TMP_DIR/batch."*; do
    arr="$b.json"
    jq -s '.' "$b" > "$arr"
    post_batch "$arr"
    batches=$((batches + 1))
  done
  rm -f "$TMP_DIR/batch."*

  printf '%s\n' $(( offset + consumed )) > "$OFFSET_FILE"
  log "sent $n $noun row(s) + heartbeat in $batches batch(es) to $STREAM; offset $offset -> $(( offset + consumed ))"
}

if (( FOLLOW > 0 )); then
  log "follow mode: every ${FOLLOW}s until Ctrl-C"
  # Each run in a subshell: a failed batch (die) ends THAT run - the offset
  # was not advanced, so nothing is lost - and the feed tries again next
  # cycle instead of stopping mid-recording (a dead feed makes every Tier-0
  # logon alert "Vault feed stale" after 30 minutes).
  while :; do
    ( run_once ) || warn "this run failed (offset kept) - retrying in ${FOLLOW}s"
    sleep "$FOLLOW"
  done
else
  run_once
fi
