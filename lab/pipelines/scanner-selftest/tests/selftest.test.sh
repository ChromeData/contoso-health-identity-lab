#!/usr/bin/env bash
# =============================================================================
# selftest.test.sh - offline test of selftest.sh with stub scanners.
# -----------------------------------------------------------------------------
# The positive control must itself be seen to fail (ADR 0026). Each case
# below swaps in a stub Checkov / TruffleHog that misbehaves in one of the
# ways real scanners have (finds nothing, crashes, scans nothing with a clean
# exit, flags clean code) and asserts selftest.sh reports it and exits 1.
# The "all well" case asserts exit 0. No docker, no network, no real scanner.
# Run: bash lab/pipelines/scanner-selftest/tests/selftest.test.sh
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SELFTEST="$HERE/../selftest.sh"
FIXTURES="$HERE/../fixtures"
STUBS="$(mktemp -d "${TMPDIR:-/tmp}/selftest-stubs.XXXXXX")"
trap 'rm -rf "$STUBS"' EXIT

# Stub Checkov: STUB_CHECKOV = ok | zero | crash | empty | parseerr | flags-good
cat > "$STUBS/checkov" <<'STUB'
#!/usr/bin/env bash
dir=""; while (( $# )); do [[ "$1" == "-d" ]] && dir="$2"; shift; done
bad=0; [[ "$(basename "$dir")" == "bad" ]] && bad=1
mode="${STUB_CHECKOV:-ok}"
case "$mode" in
  crash) echo "Traceback: boom" >&2; exit 2 ;;
  empty) printf '{"passed":0,"failed":0,"skipped":0,"parsing_errors":0,"resource_count":0}\n'; exit 0 ;;
  parseerr) printf '{"check_type":"terraform","results":{"failed_checks":[]},"summary":{"passed":0,"failed":0,"parsing_errors":1,"resource_count":1}}\n'; exit 0 ;;
esac
n=0
if (( bad )) && [[ "$mode" != "zero" ]]; then n=2; fi
if (( ! bad )) && [[ "$mode" == "flags-good" ]]; then n=1; fi
fc=""; for ((i=0;i<n;i++)); do fc="$fc${fc:+,}{\"check_id\":\"CKV_AZURE_9\"}"; done
printf '{"check_type":"terraform","results":{"failed_checks":[%s]},"summary":{"passed":2,"failed":%d,"parsing_errors":0,"resource_count":1}}\n' "$fc" "$n"
(( n > 0 )) && exit 1 || exit 0
STUB

# Stub TruffleHog: STUB_TH = ok | zero | crash | nochunks
# It reports a finding only when the planted key is really there, so a
# selftest.sh that forgot to plant it fails the "ok" case.
cat > "$STUBS/trufflehog" <<'STUB'
#!/usr/bin/env bash
dir="$2"; mode="${STUB_TH:-ok}"
case "$mode" in
  crash) echo '{"level":"error","msg":"boom"}' >&2; exit 1 ;;
  nochunks) echo '{"level":"info-0","msg":"finished scanning","chunks":0}' >&2; exit 0 ;;
esac
if [[ "$mode" == "ok" ]] && grep -qs "BEGIN PRIVATE KEY" "$dir/planted-key.pem"; then
  echo '{"DetectorName":"PrivateKey","Verified":false,"Raw":"REDACTED-IN-STUB"}'
fi
echo '{"level":"info-0","msg":"finished scanning","chunks":1}' >&2
exit 0
STUB
chmod +x "$STUBS/checkov" "$STUBS/trufflehog"

pass=0; failn=0
check() { # check NAME WANT_EXIT WANT_TEXT [ENV=VAL...]
  local name="$1" want="$2" text="$3"; shift 3
  local out rc
  out="$(env "$@" SELFTEST_CHECKOV_BIN="$STUBS/checkov" SELFTEST_TRUFFLEHOG_BIN="$STUBS/trufflehog" bash "$SELFTEST" --local 2>&1)"; rc=$?
  if [[ "$rc" == "$want" ]] && grep -qF -- "$text" <<<"$out" && ! grep -q "BEGIN PRIVATE KEY" <<<"$out"; then
    pass=$((pass + 1)); echo "ok   $name"
  else
    failn=$((failn + 1)); echo "FAIL $name (exit $rc, wanted $want and '$text')"; printf '%s\n' "$out"
  fi
}

check "both scanners work: pass"              0 "RESULT PASS"
check "checkov finds nothing on bad"          1 "checkov   : 0 findings - the gate would NOT catch" STUB_CHECKOV=zero
check "checkov crashes (exit 2)"              1 "checkov   : ERROR" STUB_CHECKOV=crash
check "checkov scans nothing, exits 0"        1 "checkov   : ERROR" STUB_CHECKOV=empty
check "checkov parsing error"                 1 "checkov   : ERROR" STUB_CHECKOV=parseerr
check "checkov flags the clean fixture"       1 "the gate would block the clean fixture" STUB_CHECKOV=flags-good
check "trufflehog finds nothing on bad"       1 "trufflehog: 0 findings - the gate would NOT catch" STUB_TH=zero
check "trufflehog scans 0 chunks, exits 0"    1 "trufflehog: ERROR" STUB_TH=nochunks
check "trufflehog crashes"                    1 "trufflehog: ERROR" STUB_TH=crash
# A typo in the mode is refused (exit 2), never run as some default.
out="$(bash "$SELFTEST" --locl 2>&1)"; rc=$?
if [[ "$rc" == 2 ]] && grep -qF "unknown argument" <<<"$out"; then
  pass=$((pass + 1)); echo "ok   unknown argument refused"
else
  failn=$((failn + 1)); echo "FAIL unknown argument refused (exit $rc)"
fi

# The generated key must never land in the committed fixtures.
if find "$FIXTURES" -name '*.pem' | grep -q .; then
  failn=$((failn + 1)); echo "FAIL a .pem file exists under fixtures/"
else
  pass=$((pass + 1)); echo "ok   no key file left in fixtures/"
fi

echo "selftest.test.sh: $pass passed, $failn failed"
(( failn == 0 ))
