#!/usr/bin/env bash
# =============================================================================
# ingest-from-loganalytics.sh - REPLAY Entra ID logs from Log Analytics
# (loga-idlab) into the local Splunk over HEC.
# -----------------------------------------------------------------------------
# STAND-IN - say it on camera: this script REPLAYS logs that Entra already
# streamed to Log Analytics. It stands in for the production data path, the
# Splunk Add-on for Microsoft Azure (Graph sign-in/audit inputs) or Entra
# diagnostic settings -> Azure Event Hub -> Splunk streaming. Same Entra events,
# delivered in batches on demand instead of continuously.
#
# WHY THIS PATH: zero new secrets. It rides your existing `az login` (no
# app registration, no client secret, no Event Hub, no Splunkbase account) and
# reads the workspace with the Log Analytics query API. Cost: $0 (querying
# Analytics-tier tables is not billed per query; Splunk is a local trial).
#
# WHAT IT DOES, per table (SigninLogs, AADNonInteractiveUserSignInLogs,
# AuditLogs by default; the ITDR rules also read AADUserRiskEvents,
# AADRiskyUsers, SecurityEvent and VaultCheckout_CL - name them with -T once
# those tables have data, see --help):
#   1. `az monitor log-analytics query` (log-analytics CLI extension) over
#      --timespan, returning each row as ONE JSON string built with
#      tostring(pack_all(true)). That sidesteps the extension's habit of
#      str()-ing every cell (numbers/booleans become strings, nulls the text
#      "None") and keeps dynamic columns as real nested JSON.
#   2. Columns that hold JSON as TEXT (AADNonInteractiveUserSignInLogs stores
#      LocationDetails, ConditionalAccessPolicies, DeviceDetail... as string)
#      are parsed, so SPL sees the same nested paths for both sign-in tables.
#   3. Each row becomes an HEC envelope: index=entra, sourcetype per table,
#      host=<workspace>, and "time" = TimeGenerated (so Splunk _time IS the
#      KQL TimeGenerated). Detection-critical columns are written first so
#      search-time JSON extraction always reaches them.
#   4. POSTs in batches to https://127.0.0.1:8088/services/collector/event
#      (-k: Splunk's self-signed cert, loopback only). Every batch must return
#      HTTP 200 + {"code":0}, otherwise the script stops non-zero.
#   5. Remembers a per-table high-water mark of ingestion_time() in
#      .state/<Table>.hwm (gitignored), so a re-run sends only rows that
#      reached Log Analytics since the last successful run - replays do not
#      double-count failed sign-ins in the spike rule. --full ignores it.
#      ingestion_time(), not TimeGenerated, because late-arriving rows (5-15
#      min Entra->Log Analytics lag) would otherwise be skipped.
#
# SCHEDULED-ALERT CAVEAT: the Splunk alerts look back 1 h (legacy auth 24 h)
# from NOW by _time, exactly like the Sentinel rules. Replay soon after
# generating signal (or use --follow) - an event replayed 3 hours late lands
# with its true 3-hour-old _time and only shows in ad-hoc searches.
#
# PREREQUISITES (human): `az login` as a user with Log Analytics Reader (or
# better) on loga-idlab; the CLI extension: `az extension add --name
# log-analytics`; Entra diagnostic settings streaming to loga-idlab
# (lab/terraform/envs/bootstrap); ./splunk-up.sh completed.
#
# USAGE
#   ./ingest-from-loganalytics.sh [options]
#     -t, --timespan ISO8601     look-back window on TimeGenerated (default PT24H)
#     -T, --tables LIST          comma list (default: the three Entra tables).
#                                ITDR tables (enable_itdr_detections; P2 risk
#                                categories / DC01 AMA / ingest-vault-audit.sh):
#                                AADUserRiskEvents,AADRiskyUsers,SecurityEvent,VaultCheckout_CL
#                                A table that has never received data fails the
#                                query - add each one only once it has rows.
#     -g, --resource-group RG    default $LA_RESOURCE_GROUP or rg-identity-lab
#     -n, --workspace-name NAME  default $LA_WORKSPACE_NAME or loga-idlab
#     -w, --workspace-id GUID    workspace customer id; skips the lookup
#     -b, --batch-size N         events per HEC POST (default 200)
#         --full                 ignore the high-water mark (re-sends rows!)
#         --dry-run              build payloads in .state/dry-run/, send nothing
#         --follow SECONDS       repeat every SECONDS until Ctrl-C (demo mode)
#         --input-json FILE      offline/test: use a saved az query output for
#                                the single table given with -T (no az call)
#     -h, --help
# =============================================================================
source "$(dirname "$0")/lib.sh"
need jq; need curl; need split

# ---------------------------------------------------------------- options ---
[[ -f .env ]] && load_env    # optional LA_* overrides + HEC token
TIMESPAN="PT24H"
TABLES="SigninLogs,AADNonInteractiveUserSignInLogs,AuditLogs"
RG="${LA_RESOURCE_GROUP:-rg-identity-lab}"
WS_NAME="${LA_WORKSPACE_NAME:-loga-idlab}"
WS_ID="${LA_WORKSPACE_ID:-}"
BATCH=200
FULL=0
DRY=0
FOLLOW=0
INPUT_JSON=""

while (( $# > 0 )); do
  case "$1" in
    -t|--timespan)        TIMESPAN="${2:?missing value for $1}"; shift 2 ;;
    -T|--tables)          TABLES="${2:?missing value for $1}"; shift 2 ;;
    -g|--resource-group)  RG="${2:?missing value for $1}"; shift 2 ;;
    -n|--workspace-name)  WS_NAME="${2:?missing value for $1}"; shift 2 ;;
    -w|--workspace-id)    WS_ID="${2:?missing value for $1}"; shift 2 ;;
    -b|--batch-size)      BATCH="${2:?missing value for $1}"; shift 2 ;;
    --full)               FULL=1; shift ;;
    --dry-run)            DRY=1; shift ;;
    --follow)             FOLLOW="${2:?missing value for $1}"; shift 2 ;;
    --input-json)         INPUT_JSON="${2:?missing value for $1}"; shift 2 ;;
    -h|--help)            awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

re_duration='^P([0-9]+D)?(T([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$'
re_guid='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
re_hwm='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
re_uint='^[1-9][0-9]*$'

[[ "$TIMESPAN" =~ $re_duration && "$TIMESPAN" != "P" && "$TIMESPAN" != *T ]] \
  || die "--timespan must be an ISO 8601 duration such as PT1H, PT24H or P2D (got '$TIMESPAN')"
{ [[ "$BATCH" =~ $re_uint ]] && (( BATCH <= 5000 )); } || die "--batch-size must be 1..5000"
[[ "$FOLLOW" == "0" || "$FOLLOW" =~ $re_uint ]] || die "--follow takes a number of seconds"
(( FOLLOW == 0 || FULL == 0 )) || die "--full with --follow would re-send the whole window on every loop"
[[ -z "$WS_ID" || "$WS_ID" =~ $re_guid ]] || die "--workspace-id must be the workspace customer id (a GUID)"

# Table -> sourcetype. Fixed allow-list: table names are interpolated into KQL,
# so nothing outside this list is ever accepted.
sourcetype_for() {
  case "$1" in
    SigninLogs)                      echo "azure:loganalytics:signinlogs" ;;
    AADNonInteractiveUserSignInLogs) echo "azure:loganalytics:aadnoninteractiveusersigninlogs" ;;
    AuditLogs)                       echo "azure:loganalytics:auditlogs" ;;
    # ITDR twins (lab/splunk/detections/identity-risk.spl,
    # tier0-logon-without-checkout.spl); sourcetypes as in props.conf.
    AADUserRiskEvents)               echo "azure:loganalytics:aaduserriskevents" ;;
    AADRiskyUsers)                   echo "azure:loganalytics:aadriskyusers" ;;
    SecurityEvent)                   echo "azure:loganalytics:securityevent" ;;
    VaultCheckout_CL)                echo "azure:loganalytics:vaultcheckout_cl" ;;
    *) return 1 ;;
  esac
}
IFS=',' read -r -a TABLE_LIST <<< "$TABLES"
(( ${#TABLE_LIST[@]} > 0 )) || die "--tables is empty"
for t in "${TABLE_LIST[@]}"; do
  sourcetype_for "$t" >/dev/null || die "unsupported table '$t' (allowed: SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, AADUserRiskEvents, AADRiskyUsers, SecurityEvent, VaultCheckout_CL)"
done
if [[ -n "$INPUT_JSON" ]]; then
  # lib.sh has already cd'ed into lab/splunk; resolve a relative path against
  # the directory the operator ran the script from.
  [[ "$INPUT_JSON" == /* ]] || INPUT_JSON="$CALLER_PWD/$INPUT_JSON"
  [[ -f "$INPUT_JSON" ]] || die "--input-json file not found: $INPUT_JSON"
  (( ${#TABLE_LIST[@]} == 1 )) || die "--input-json needs exactly one table in -T"
  (( FOLLOW == 0 )) || die "--input-json cannot be combined with --follow"
fi

# Detection-critical columns go first in every event (search-time JSON
# extraction reads events front to back - see app/contoso_identity/default/limits.conf).
PRIORITY_JSON='["TimeGenerated","Type","UserPrincipalName","UserDisplayName","IPAddress","ResultType","ResultDescription","AppDisplayName","ClientAppUsed","ConditionalAccessStatus","Location","RiskLevelDuringSignIn","CorrelationId","LoggedByService","Category","ActivityDisplayName","Result","OperationName","LaIngestionTime","LocationDetails","ConditionalAccessPolicies","InitiatedBy","TargetResources","AdditionalDetails","EventID","Computer","TargetUserName","LogonType","RiskLevel","RiskState","RiskEventType","RiskDetail","Operation","Account","AccountResolved"]'

# One az output row -> one HEC envelope line. Fails (non-zero) on any row it
# cannot convert instead of dropping it.
# dyn: a string that IS JSON text gets parsed; a string that only STARTS with
# [ or { (a display name like "[EXT] Dana") is kept verbatim. Note `catch $s`,
# not `catch .`: inside a jq catch handler `.` is the ERROR MESSAGE, so
# `catch .` would silently overwrite the column with "Invalid literal at ...".
# shellcheck disable=SC2016  # jq program: every $name below is a jq variable, never the shell's
JQ_TRANSFORM='
  def dyn:
    if type == "string" and test("^\\s*[\\[{]") then (. as $s | try fromjson catch $s) else . end;
  def epoch:
    if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$") then
      capture("^(?<s>[^.Z]+)(?<f>\\.[0-9]+)?Z$") as $m
      | ((($m.s + "Z" | fromdateiso8601) + (("0" + ($m.f // ".0")) | tonumber)) * 1000 | floor) / 1000
    else error("TimeGenerated missing or not ISO-8601 UTC: \(tojson)") end;
  def ordered($prio):
    to_entries | sort_by(.key as $k | [(($prio | index($k)) // 999), $k]) | from_entries;
  .[]
  | (.Row // error("row has no Row column - the KQL projection changed?"))
  | (if type == "string" then fromjson else . end)
  | with_entries(.value |= dyn)
  | { time: (.TimeGenerated | epoch), host: $host, source: $source,
      sourcetype: $st, index: $idx, event: ordered($prio) }
'

# Newest ingestion_time() across all rows, compared EXACTLY: [epoch seconds,
# fraction padded to 9 digits] - string order breaks when fraction lengths
# differ, and doubles lose the 100 ns digits. Errors if any row lacks it.
# shellcheck disable=SC2016  # jq program: $m is a jq variable, never the shell's
JQ_MAX_INGESTION='
  def tkey:
    capture("^(?<s>[^.Z]+)(?<f>\\.[0-9]+)?Z$") as $m
    | [($m.s + "Z" | fromdateiso8601), ((($m.f // ".") | .[1:]) + "000000000" | .[0:9])];
  [ .[] | .Row | (if type == "string" then fromjson else . end) | .LaIngestionTime
    | if type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?Z$")
      then . else error("row without a valid LaIngestionTime: \(tojson)") end ]
  | max_by(tkey)
'

mkdir -p .state
chmod 700 .state

# ------------------------------------------------------------- az helpers ---
az_preflight() {
  need az
  az account show --only-show-errors -o none 2>/dev/null \
    || die "not signed in to Azure CLI - run 'az login' (your existing operator login; no new secret)"
  az extension show --name log-analytics --only-show-errors -o none 2>/dev/null \
    || die "Azure CLI extension 'log-analytics' is missing - human step: az extension add --name log-analytics"
  if [[ -z "$WS_ID" ]]; then
    WS_ID="$(az monitor log-analytics workspace show --resource-group "$RG" --workspace-name "$WS_NAME" \
               --query customerId -o tsv --only-show-errors 2>"$TMP_DIR/az-ws.err")" \
      || { cat "$TMP_DIR/az-ws.err" >&2; die "could not read workspace '$WS_NAME' in '$RG' (Reader on the workspace needed)"; }
    WS_ID="$(printf '%s' "$WS_ID" | tr -d '[:space:]')"
    [[ "$WS_ID" =~ $re_guid ]] || die "workspace lookup did not return a customer id GUID (got '$WS_ID')"
  fi
  log "Workspace ${WS_NAME} (customer id ${WS_ID}) - window ${TIMESPAN}"
}

kql_for() { # kql_for TABLE [HWM]
  local q="$1
| extend LaIngestionTime = ingestion_time()"
  if [[ -n "${2:-}" ]]; then
    q="$q
| where LaIngestionTime > datetime($2)"
  fi
  printf '%s\n' "$q
| order by LaIngestionTime asc
| project Row = tostring(pack_all(true))"
}

# ------------------------------------------------------------ one table ----
TOTAL_SENT=0
ingest_table() { # ingest_table TABLE
  local table="$1" st hwm_file hwm="" raw jsonl rows lines batches=0 sent=0 new_hwm b
  st="$(sourcetype_for "$table")"
  hwm_file=".state/${table}.hwm"
  raw="$TMP_DIR/${table}.az.json"
  jsonl="$TMP_DIR/${table}.hec.jsonl"

  if [[ -n "$INPUT_JSON" ]]; then
    cp "$INPUT_JSON" "$raw"
    log "$table: reading $INPUT_JSON (offline input, high-water mark untouched)"
  else
    if (( FULL == 0 )) && [[ -s "$hwm_file" ]]; then
      hwm="$(tr -d '[:space:]' < "$hwm_file")"
      [[ "$hwm" =~ $re_hwm ]] || die "$hwm_file is corrupt ('$hwm') - delete it or use --full"
      log "$table: incremental, rows ingested into Log Analytics after $hwm"
    else
      (( FULL == 1 )) && warn "$table: --full ignores the high-water mark - rows already in Splunk will be sent AGAIN"
    fi
    if ! az monitor log-analytics query --workspace "$WS_ID" --timespan "$TIMESPAN" \
           --analytics-query "$(kql_for "$table" "$hwm")" \
           --only-show-errors -o json > "$raw" 2> "$TMP_DIR/${table}.az.err"; then
      cat "$TMP_DIR/${table}.az.err" >&2
      die "$table: Log Analytics query failed (table missing because no data has ever arrived? permissions?)"
    fi
  fi

  jq -e 'type == "array"' "$raw" >/dev/null 2>&1 || die "$table: query output is not a JSON array"
  rows="$(jq 'length' "$raw")"
  if [[ "$rows" == "0" ]]; then
    log "$table: 0 new rows in the window - nothing to send"
    return 0
  fi

  jq -c --arg st "$st" --arg idx "$SPLUNK_INDEX" --arg host "$WS_NAME" \
        --arg source "loganalytics:${WS_NAME}:${table}" --argjson prio "$PRIORITY_JSON" \
        "$JQ_TRANSFORM" "$raw" > "$jsonl" \
    || die "$table: could not convert rows to HEC events (see jq error above)"
  lines="$(wc -l < "$jsonl" | tr -d ' ')"
  [[ "$lines" == "$rows" ]] || die "$table: $rows rows in, $lines events out - refusing to send a partial replay"

  if (( DRY == 1 )); then
    mkdir -p .state/dry-run
    cp "$jsonl" ".state/dry-run/${table}.jsonl"
    log "$table: DRY RUN - $rows events written to .state/dry-run/${table}.jsonl, nothing sent"
    return 0
  fi

  # -a 5: split's default 2-letter suffix caps it at 676 files (it then aborts),
  # ~135k events at the default batch size; 5 letters covers the query API's
  # 500k-row ceiling at any --batch-size.
  split -a 5 -l "$BATCH" "$jsonl" "$TMP_DIR/${table}.batch."
  for b in "$TMP_DIR/${table}.batch."*; do
    batches=$((batches + 1))
    hec_post "$b" || die "$table: HEC rejected batch $batches after $sent events were accepted (re-run resumes from the last committed high-water mark; accepted events may then repeat)"
    sent=$((sent + $(wc -l < "$b" | tr -d ' ')))
  done
  rm -f "$TMP_DIR/${table}.batch."*
  TOTAL_SENT=$((TOTAL_SENT + sent))
  log "$table: sent $sent events in $batches batch(es) as sourcetype=$st index=$SPLUNK_INDEX"

  # Commit the high-water mark only after every batch landed.
  if [[ -z "$INPUT_JSON" ]]; then
    new_hwm="$(jq -r "$JQ_MAX_INGESTION" "$raw")" \
      || die "$table: events sent, but not every row carried a valid LaIngestionTime - high-water mark NOT advanced (next run repeats this window; use a fresh index or accept duplicates)"
    [[ "$new_hwm" =~ $re_hwm ]] || die "$table: events sent, but the computed high-water mark '$new_hwm' is invalid - NOT advanced"
    printf '%s\n' "$new_hwm" > "$hwm_file"
    log "$table: high-water mark -> $new_hwm"
  fi
}

run_once() {
  local t
  TOTAL_SENT=0
  for t in "${TABLE_LIST[@]}"; do
    ingest_table "$t"
  done
  if (( DRY == 1 )); then
    log "done (dry run): payloads are in .state/dry-run/ - nothing was sent"
  elif (( TOTAL_SENT == 0 )); then
    warn "nothing was sent. If you expected events: Entra diagnostic setting -> loga-idlab enabled (envs/bootstrap)? P1/P2 licence for sign-in logs? Entra->Log Analytics lag is 5-15 min. Window ${TIMESPAN} long enough? High-water mark already past them (see .state/, or --full)?"
  else
    log "done: ${TOTAL_SENT} events sent this run"
  fi
}

# ------------------------------------------------------------------- main ---
if (( DRY == 0 )); then
  [[ -n "${SPLUNK_HEC_TOKEN:-}" ]] || die "SPLUNK_HEC_TOKEN not set - run ./splunk-up.sh first"
  hec_healthy || die "Splunk HEC is not answering on ${SPLUNK_HEC_URL} - run ./splunk-up.sh"
fi
[[ -n "$INPUT_JSON" ]] || az_preflight

if (( FOLLOW > 0 )); then
  log "Follow mode: replaying every ${FOLLOW}s until Ctrl-C (incremental via high-water marks)"
  while :; do
    run_once
    sleep "$FOLLOW"
  done
else
  run_once
fi
