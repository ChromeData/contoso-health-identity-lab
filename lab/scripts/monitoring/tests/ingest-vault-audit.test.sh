#!/usr/bin/env bash
# =============================================================================
# tests/ingest-vault-audit.test.sh - offline test of ../ingest-vault-audit.sh
# -----------------------------------------------------------------------------
# No Vault, no Azure, no network: the audit log is fixtures/vault-audit.sample.log
# (synthetic records shaped like lab/pam's check-out / check-in traffic), HMACs
# resolve through fixtures/hash-map.json, and `az` / `curl` are the stubs in
# stubs/ (they refuse to run outside this test). Proves:
#   * only successful check-out / check-in responses of the chosen library
#     become rows; requests, errors, other paths and other sets do not;
#   * HMAC'd names resolve; unknown ones ship AccountResolved=false (fail-safe);
#   * timestamps are trimmed to microseconds; one heartbeat per run;
#   * the byte offset advances only after HTTP 204, never past a half-written
#     line, and a 403 stops the run with the role-grant hint and no advance;
#   * an expired token (401) is refreshed and retried once; a second 401
#     stops the run without advancing the offset.
# Prints PASS/FAIL per assertion; exits 1 if anything failed.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../ingest-vault-audit.sh"
FIX="$HERE/fixtures"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/vault-ingest-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { # check DESC JQ_FILTER FILE : the filter must print true
  if [[ "$(jq -r "$2" "$3" 2>/dev/null)" == "true" ]]; then pass "$1"; else fail "$1 (jq: $2)"; fi
}

ENDPOINT="https://dce-test-abcd.eastus2-1.ingest.monitor.azure.com"
DCR="dcr-0123456789abcdef0123456789abcdef"
export VAULT_INGEST_TEST_STUBS=1 STUB_CAPTURE_DIR="$WORK/capture"
mkdir -p "$STUB_CAPTURE_DIR"
STUB_PATH="$HERE/stubs:$PATH"

# --- 1. dry run: the transform ------------------------------------------------
"$SCRIPT" --audit-file "$FIX/vault-audit.sample.log" --hash-map "$FIX/hash-map.json" \
  --state-dir "$WORK/state-dry" --dry-run > "$WORK/dry.json" 2> "$WORK/dry.err"
check "dry run: 5 check-out/in rows + 1 heartbeat" 'length == 6' "$WORK/dry.json"
check "check-out of tier0-admin-01 resolved from its HMAC" \
  'any(.[]; .Operation == "check-out" and .Account == "tier0-admin-01" and .AccountResolved and .RequestId == "r-out-1")' "$WORK/dry.json"
check "timestamp trimmed to microseconds" \
  'any(.[]; .RequestId == "r-out-1" and .TimeGenerated == "2026-10-20T07:30:01.223456Z")' "$WORK/dry.json"
check "check-in row from check_ins list" \
  'any(.[]; .Operation == "check-in" and .Account == "tier0-admin-01" and .RequestId == "r-in-1")' "$WORK/dry.json"
check "manage/ force check-in kept, actor recorded" \
  'any(.[]; .RequestId == "r-in-2" and .Account == "tier0-admin-02" and .VaultActor == "root")' "$WORK/dry.json"
check "unknown HMAC -> AccountResolved=false, empty Account" \
  'any(.[]; .RequestId == "r-out-x" and .AccountResolved == false and .Account == "")' "$WORK/dry.json"
check "clear-text name (tuned mount) used as-is, lower-cased" \
  'any(.[]; .RequestId == "r-out-plain" and .Account == "tier0-admin-02" and .AccountResolved)' "$WORK/dry.json"
check "request lines, errors, other paths and other library sets ignored" \
  '[.[] | select(.RequestId == "r-out-fail" or .RequestId == "r-static" or .RequestId == "r-other")] | length == 0' "$WORK/dry.json"
check "exactly one heartbeat" '[.[] | select(.Operation == "heartbeat")] | length == 1' "$WORK/dry.json"
check "every row has exactly the VaultCheckout_CL columns" \
  'all(.[]; (keys | sort) == (["Account","AccountResolved","Library","Operation","RemoteAddress","RequestId","SourceHost","TimeGenerated","TokenPolicies","VaultActor","VaultPath"]))' "$WORK/dry.json"
if grep -q "not JSON objects" "$WORK/dry.err"; then pass "damaged line reported, not silently dropped"; else fail "damaged line was not reported"; fi
if grep -q "AccountResolved=false" "$WORK/dry.err"; then pass "unresolved HMAC reported"; else fail "unresolved HMAC was not reported"; fi
if [[ ! -e "$WORK/state-dry/vault-audit.offset" ]]; then pass "dry run keeps no offset"; else fail "dry run wrote an offset"; fi

# --- 2. send mode with stub az/curl -------------------------------------------
cp "$FIX/vault-audit.sample.log" "$WORK/audit.log"
# A half-written record at the end must wait for the next run.
printf '{"time":"2026-10-20T09:00:00Z","type":"response","auth":{"display_name":"token-psm-broker"},"request":{"id":"r-late","operation":"update","path":"ldap/library/tier0-admins/check-out"},"response":{"data":{"service_account_name":"tier0-admin-01"' >> "$WORK/audit.log"
complete_bytes="$(sed '$d' "$WORK/audit.log" | wc -c | tr -d ' ')"

if PATH="$STUB_PATH" "$SCRIPT" --audit-file "$WORK/audit.log" --hash-map "$FIX/hash-map.json" \
     --state-dir "$WORK/state" --endpoint "$ENDPOINT" --dcr-id "$DCR" 2> "$WORK/send1.err"; then
  pass "send run 1 exits 0 on HTTP 204"
else
  fail "send run 1 failed: $(tail -3 "$WORK/send1.err")"
fi
check "run 1 posted 6 rows as one JSON array" 'type == "array" and length == 6' "$STUB_CAPTURE_DIR/post-1.json"
if grep -q "/dataCollectionRules/$DCR/streams/Custom-VaultCheckout?api-version=2023-01-01" "$STUB_CAPTURE_DIR/post-1.url"; then
  pass "posted to the DCR stream with api-version 2023-01-01"; else fail "wrong ingestion URL: $(cat "$STUB_CAPTURE_DIR/post-1.url")"; fi
if grep -q '^Authorization: Bearer stub-token-not-a-secret$' "$STUB_CAPTURE_DIR/post-1.auth"; then
  pass "bearer token travels in a header file, not argv"; else fail "auth header missing"; fi
offset="$(cat "$WORK/state/vault-audit.offset")"
if [[ "$offset" == "$complete_bytes" ]]; then pass "offset stops before the half-written line ($offset bytes)"; else fail "offset $offset != complete bytes $complete_bytes"; fi

PATH="$STUB_PATH" "$SCRIPT" --audit-file "$WORK/audit.log" --hash-map "$FIX/hash-map.json" \
  --state-dir "$WORK/state" --endpoint "$ENDPOINT" --dcr-id "$DCR" 2> "$WORK/send2.err" || fail "send run 2 failed"
check "run 2 (nothing new) sends only the heartbeat" 'length == 1 and .[0].Operation == "heartbeat"' "$STUB_CAPTURE_DIR/post-2.json"

printf '}}}\n' >> "$WORK/audit.log"   # the record is finished
PATH="$STUB_PATH" "$SCRIPT" --audit-file "$WORK/audit.log" --hash-map "$FIX/hash-map.json" \
  --state-dir "$WORK/state" --endpoint "$ENDPOINT" --dcr-id "$DCR" 2> "$WORK/send3.err" || fail "send run 3 failed"
check "run 3 picks up the completed record once" \
  '([.[] | select(.RequestId == "r-late")] | length == 1) and length == 2' "$STUB_CAPTURE_DIR/post-3.json"

# --- 3. 403: stop, explain, do not advance ------------------------------------
printf '%s\n' '{"time":"2026-10-20T09:30:00Z","type":"response","auth":{},"request":{"id":"r-403","operation":"update","path":"ldap/library/tier0-admins/check-in"},"response":{"data":{"check_ins":["tier0-admin-01"]}}}' >> "$WORK/audit.log"
before="$(cat "$WORK/state/vault-audit.offset")"
if STUB_CURL_CODE=403 PATH="$STUB_PATH" "$SCRIPT" --audit-file "$WORK/audit.log" --hash-map "$FIX/hash-map.json" \
     --state-dir "$WORK/state" --endpoint "$ENDPOINT" --dcr-id "$DCR" 2> "$WORK/send403.err"; then
  fail "HTTP 403 must exit non-zero"
else
  pass "HTTP 403 exits non-zero"
fi
if grep -q "Monitoring Metrics Publisher" "$WORK/send403.err"; then pass "403 explains the missing DCR role"; else fail "403 message lacks the role hint"; fi
if [[ "$(cat "$WORK/state/vault-audit.offset")" == "$before" ]]; then pass "offset unchanged after a rejected batch"; else fail "offset advanced after 403"; fi

# --- 3b. expired token: 401 -> refresh once -> 204 --------------------------
rm -rf "$STUB_CAPTURE_DIR"; mkdir -p "$STUB_CAPTURE_DIR"
before="$(cat "$WORK/state/vault-audit.offset")"
if STUB_CURL_CODES="401,204" PATH="$STUB_PATH" "$SCRIPT" --audit-file "$WORK/audit.log" --hash-map "$FIX/hash-map.json" \
     --state-dir "$WORK/state" --endpoint "$ENDPOINT" --dcr-id "$DCR" 2> "$WORK/send401.err"; then
  pass "HTTP 401 (expired token) is retried and the run succeeds"
else
  fail "HTTP 401 stopped the run: $(tail -3 "$WORK/send401.err")"
fi
if [[ "$(wc -l < "$STUB_CAPTURE_DIR/token-fetches" | tr -d ' ')" == 2 ]]; then pass "a fresh token was fetched after the 401"; else fail "token not refreshed after 401"; fi
rm -rf "$STUB_CAPTURE_DIR"; mkdir -p "$STUB_CAPTURE_DIR"
before="$(cat "$WORK/state/vault-audit.offset")"
if STUB_CURL_CODES="401,401" PATH="$STUB_PATH" "$SCRIPT" --audit-file "$WORK/audit.log" --hash-map "$FIX/hash-map.json" \
     --state-dir "$WORK/state" --endpoint "$ENDPOINT" --dcr-id "$DCR" 2> "$WORK/send401b.err"; then
  fail "a second 401 must stop the run (no endless refresh)"
else
  pass "a second 401 after a refresh stops the run"
fi
if [[ "$(cat "$WORK/state/vault-audit.offset")" == "$before" ]]; then pass "offset unchanged after the failed 401 run"; else fail "offset advanced after 401"; fi
# shellcheck disable=SC2016  # literal source text, not an expansion
if grep -qF 'mmin +"$TOKEN_MAX_AGE_MIN"' "$SCRIPT" && grep -qF '( run_once ) || warn' "$SCRIPT"; then
  pass "follow mode refreshes a token older than TOKEN_MAX_AGE_MIN and survives a failed run"
else
  fail "token age refresh / resilient follow loop missing"
fi

# --- 4. input validation -------------------------------------------------------
if "$SCRIPT" --audit-file "$WORK/audit.log" --endpoint "https://evil.example.com" --dcr-id "$DCR" >/dev/null 2>&1; then
  fail "a non-Azure-Monitor endpoint was accepted"; else pass "refuses an endpoint that is not *.ingest.monitor.azure.com"; fi
if "$SCRIPT" --audit-file "$WORK/audit.log" --endpoint "$ENDPOINT" --dcr-id "not-a-dcr" >/dev/null 2>&1; then
  fail "a malformed DCR id was accepted"; else pass "refuses a malformed DCR immutable id"; fi

echo
if (( FAILS == 0 )); then echo "ingest-vault-audit: ALL PASSED"; exit 0; fi
echo "ingest-vault-audit: $FAILS FAILED"; exit 1
