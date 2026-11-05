#!/usr/bin/env bash
# =============================================================================
# test/run-all.sh - every PAM test suite from ONE entry point, with totals.
#
#   suite          what                                         needs
#   dependency-scan  Pester: test/Get-AccountDependencies.Tests.ps1  pwsh + Pester 5 (offline)
#   ingest         ../scripts/monitoring/tests/ingest-vault-audit.test.sh
#                  (the Vault audit feed, offline: fixtures + stubs)  jq
#   itsm-dual-control  test/itsm-dual-control.test.sh: ticket validation
#                  + dual control (lib.sh itsm_validate against the
#                  ServiceNow mock run locally, every approval rule)  python3, jq, curl
#   recording-format   test/guac_recording.test.py: the recording
#                  format check passes a good recording and fails
#                  every broken one (so e2e's "plays back" means it)  python3
#   tunnel-client  test/guac_tunnel.test.py: the scripted-session
#                  client's verdicts (server ended it / error / never
#                  ended / not ready) against a fake Guacamole HTTP
#                  tunnel, so e2e's session checks mean what they say  python3
#   log-scrub      test/scrub_logs.test.py: the scrubber that takes
#                  every generated credential out of the logs the
#                  workflow uploads on failure (fail closed)          python3
#   e2e            test/e2e.sh: the AD-dependent PAM flow against a
#                  Samba AD DC (onboarding, check-out + dual control,
#                  RDP to the Linux xrdp stand-in, discovery,
#                  rotation, reconcile, SSH CA, HA/DR)              shared stack
#   midpoint       test/e2e-midpoint.sh: two certification campaigns
#                  + evidence and live-state assertions             shared stack (midPoint)
#   dynamic-db     test/e2e-dynamic-db.sh: Vault dynamic database
#                  credentials (own project contoso-dyndb)           Docker
#   vault-anomaly  test/e2e-vault-anomaly.sh: real Vault audit events
#                  -> VaultCheckout_CL rows -> anomaly assertions
#                  (own project contoso-vaultanom)                   Docker
#   scale          test/e2e-scale.sh: 500 synthetic accounts through
#                  discovery -> onboarding -> dependency check ->
#                  rotation sample -> reconcile, every stage timed
#                  (own project contoso-pamscale)                    Docker
#                  OPTIONAL and OFF by default (several minutes): runs
#                  only with --scale, or when named in --only
#
# Runs them in that order (e2e before midpoint: e2e.sh empties out/e2e/,
# where e2e-midpoint.sh writes). Starts the shared stack with ./pam-up.sh
# first when e2e or midpoint is selected (idempotent; --no-up skips it).
# A suite PASSES when it exits 0 AND printed no FAIL line; its PASS / FAIL
# lines (one per assertion) are counted from its log. SKIP lines (a suite
# saying it did not run something) are counted separately, never as PASS.
#
# Logs: out/test-runs/<UTC>/<suite>.log and summary.json (gitignored: they
# name lab accounts and operators). Test runs never write to lab/evidence/
# unless --publish: then e2e.sh writes its sealed run record to
# lab/evidence/pam/<UTC>/ and dr-drill.sh its RTO/RPO record to
# lab/evidence/pam-dr/<UTC>/, and the scale suite (when it runs) its timed
# record to lab/evidence/pam-scale/<UTC>/. Each published record is then
# re-checked with --verify in its OWN row (record-verify-e2e,
# record-verify-scale): those PASS/FAIL lines are record checks, not test
# assertions, so they are reported apart (totals.record_checks) and the
# assertion totals are the same with or without --publish. A record that does
# not verify fails the run.
#
# Usage: test/run-all.sh [--only s1,s2] [--skip s1,s2] [--skip-ha] [--no-up] [--cleanup] [--publish] [--scale]
#          --scale     also run the optional scale suite (slow; off by default)
#          --skip-ha   pass --skip-ha to e2e.sh (no 3-node Raft / DR drill)
#          --cleanup   afterwards: e2e.sh --cleanup and e2e-dynamic-db.sh
#                      --cleanup (e2e-vault-anomaly.sh and e2e-scale.sh remove
#                      their own projects)
# Exit: 0 only if every selected suite passed.
# =============================================================================
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"   # cd's to lab/pam
need jq

ALL_SUITES="dependency-scan ingest itsm-dual-control recording-format tunnel-client log-scrub e2e midpoint dynamic-db vault-anomaly scale"
OPTIONAL_SUITES="scale"   # never part of a default run: --scale, or named in --only
ONLY="" SKIP="" SKIP_HA=0 UP=1 CLEANUP=0 PUBLISH=0 SCALE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="${2:?--only needs a comma-separated suite list}"; shift 2 ;;
    --skip) SKIP="${2:?--skip needs a comma-separated suite list}"; shift 2 ;;
    --skip-ha) SKIP_HA=1; shift ;;
    --no-up) UP=0; shift ;;
    --cleanup) CLEANUP=1; shift ;;
    --publish) PUBLISH=1; shift ;;
    --scale) SCALE=1; shift ;;
    -h|--help) sed -n '/^# ====/,/^# ====/p' "$PAM_DIR/test/run-all.sh" | sed '1d;$d'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done
for s in ${ONLY//,/ } ${SKIP//,/ }; do
  case " $ALL_SUITES " in *" $s "*) ;; *) die "unknown suite: $s (suites: $ALL_SUITES)" ;; esac
done
selected() { # selected SUITE -> 0 if it runs
  if [[ -n "$ONLY" ]]; then case ",$ONLY," in *",$1,"*) ;; *) return 1 ;; esac; fi
  case ",$SKIP," in *",$1,"*) return 1 ;; esac
  # An optional suite runs only when asked for: --scale, or by name in --only.
  case " $OPTIONAL_SUITES " in *" $1 "*) [[ $SCALE -eq 1 || -n "$ONLY" ]] || return 1 ;; esac
  return 0
}

RUN_UTC=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="out/test-runs/$RUN_UTC"
mkdir -p "$RUN_DIR" && chmod 700 out "$RUN_DIR" 2>/dev/null || true
: > "$RUN_DIR/results.tsv"

# run_suite NAME CMD... : log to RUN_DIR/NAME.log, count PASS/FAIL/SKIP lines
run_suite() {
  local name="$1" rc=0 t0 secs p f k verdict; shift
  t0=$SECONDS
  log "== $name: $*"
  "$@" > "$RUN_DIR/$name.log" 2>&1 || rc=$?
  secs=$((SECONDS - t0))
  p=$(grep -c '^PASS' "$RUN_DIR/$name.log" || true)
  f=$(grep -c '^FAIL' "$RUN_DIR/$name.log" || true)
  k=$(grep -c '^SKIP' "$RUN_DIR/$name.log" || true)
  if [[ $rc -eq 0 && $f -eq 0 && $p -gt 0 ]]; then verdict=PASS; else verdict=FAIL; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$verdict" "$p" "$f" "$k" "$rc" "$secs" >> "$RUN_DIR/results.tsv"
  log "   $verdict  $name: $p passed, $f failed, $k skipped (exit $rc, ${secs}s) - log: $RUN_DIR/$name.log"
  if [[ $verdict == FAIL ]]; then
    # Real failures first: the e2e suite prints ~20 EXPECTED "ERROR:" lines
    # (refusal tests), which used to fill this window and hide the FAIL names.
    # Every grep here may legitimately match nothing (a failure with no ERROR
    # line): under lib.sh's `set -euo pipefail` that used to end run-all right
    # here, so every suite after the failing one silently never ran.
    { grep -E '^FAIL|ABORTED' "$RUN_DIR/$name.log" || true
      grep -E 'ERROR' "$RUN_DIR/$name.log" | grep -vE '^FAIL|ABORTED' || true; } | head -n 20 | sed 's/^/      /' || true
    grep -qE '^FAIL|ABORTED|ERROR' "$RUN_DIR/$name.log" || tail -n 15 "$RUN_DIR/$name.log" | sed 's/^/      /' || true
  fi
  return 0
}
not_run() { printf '%s\tNOT-RUN\t0\t0\t0\t-\t0\t%s\n' "$1" "$2" >> "$RUN_DIR/results.tsv"; log "   NOT RUN  $1: $2"; }

# Called through run_suite (SC2329); the single-quoted block is PowerShell (SC2016).
# shellcheck disable=SC2329,SC2016
pester_suite() { # Pester 5 over the dependency-scan tests; prints PASS/FAIL per test
  pwsh -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    Import-Module Pester -MinimumVersion 5.0
    $c = New-PesterConfiguration
    $c.Run.Path = "./test/Get-AccountDependencies.Tests.ps1"
    $c.Run.PassThru = $true
    $c.Output.Verbosity = "None"
    $r = Invoke-Pester -Configuration $c
    foreach ($t in $r.Tests) {
      $n = ($t.Path -join " > ")
      if ($t.Result -eq "Passed") { "PASS  $n" } elseif ($t.Result -eq "Failed") { "FAIL  $n" } else { "SKIP  $n ($($t.Result))" }
    }
    "Pester: $($r.PassedCount) passed, $($r.FailedCount) failed, $($r.SkippedCount) skipped"
    exit $r.FailedCount'
}

log "PAM test run $RUN_UTC (logs: $RUN_DIR/)"
if [[ $UP -eq 1 ]] && { selected e2e || selected midpoint; }; then
  log "== shared stack: ./pam-up.sh"
  ./pam-up.sh > "$RUN_DIR/pam-up.log" 2>&1 || die "./pam-up.sh failed - see $RUN_DIR/pam-up.log"
fi

if selected dependency-scan; then
  if command -v pwsh >/dev/null 2>&1; then run_suite dependency-scan pester_suite
  else not_run dependency-scan "pwsh not installed"; fi
fi
selected ingest && run_suite ingest bash ../scripts/monitoring/tests/ingest-vault-audit.test.sh
selected itsm-dual-control && run_suite itsm-dual-control ./test/itsm-dual-control.test.sh
selected recording-format && run_suite recording-format python3 -I test/guac_recording.test.py
selected tunnel-client && run_suite tunnel-client python3 -I test/guac_tunnel.test.py
selected log-scrub && run_suite log-scrub python3 -I test/scrub_logs.test.py
# e2e (with --publish: writing its sealed run records). Called through
# run_suite (SC2329).
# shellcheck disable=SC2329
e2e_suite() {
  local args=()
  [[ $SKIP_HA -eq 1 ]] && args+=(--skip-ha)
  if [[ $PUBLISH -eq 1 ]]; then
    args+=(--evidence-dir "../evidence/pam/$RUN_UTC")
    [[ $SKIP_HA -eq 1 ]] || args+=(--dr-evidence-dir "../evidence/pam-dr/$RUN_UTC")
  fi
  # ${args[@]+...}: bash 3.2 with set -u treats an empty "${args[@]}" as unbound.
  ./test/e2e.sh ${args[@]+"${args[@]}"}
}
# The records e2e just published, re-checked from disk (hashes, all-PASS,
# nothing secret-shaped, code fingerprint). Called through run_suite (SC2329).
# shellcheck disable=SC2329
e2e_record_verify() {
  local rc=0
  ./test/e2e.sh --verify "../evidence/pam/$RUN_UTC" || rc=1
  if [[ $SKIP_HA -eq 0 ]]; then ./dr-drill.sh --verify "../evidence/pam-dr/$RUN_UTC" || rc=1; fi
  return "$rc"
}
suite_verdict() { awk -F'\t' -v s="$1" '$1 == s { v = $2 } END { print v }' "$RUN_DIR/results.tsv"; }
if selected e2e; then
  run_suite e2e e2e_suite
  if [[ $PUBLISH -eq 1 ]]; then
    if [[ "$(suite_verdict e2e)" == PASS ]]; then run_suite record-verify-e2e e2e_record_verify
    else not_run record-verify-e2e "e2e failed: its record (if written) is a FAIL record"; fi
  fi
fi
selected midpoint && run_suite midpoint ./test/e2e-midpoint.sh
selected dynamic-db && run_suite dynamic-db ./test/e2e-dynamic-db.sh
selected vault-anomaly && run_suite vault-anomaly ./test/e2e-vault-anomaly.sh
# scale (with --publish: writing its sealed, timed run record), then that
# record re-checked in its own row. Called through run_suite (SC2329).
# shellcheck disable=SC2329
scale_suite() {
  local args=()
  [[ $PUBLISH -eq 0 ]] || args+=(--evidence-dir "../evidence/pam-scale/$RUN_UTC")
  ./test/e2e-scale.sh ${args[@]+"${args[@]}"}
}
# shellcheck disable=SC2329
scale_record_verify() { ./test/e2e-scale.sh --verify "../evidence/pam-scale/$RUN_UTC"; }
if selected scale; then
  run_suite scale scale_suite
  if [[ $PUBLISH -eq 1 ]]; then
    if [[ "$(suite_verdict scale)" == PASS ]]; then run_suite record-verify-scale scale_record_verify
    else not_run record-verify-scale "scale failed: its record (if written) is a FAIL record"; fi
  fi
elif [[ -z "$ONLY" && ",$SKIP," != *",scale,"* ]]; then
  not_run scale "optional, slow: add --scale"
fi

if [[ $CLEANUP -eq 1 ]]; then
  log "== cleanup"
  if selected e2e; then ./test/e2e.sh --cleanup > "$RUN_DIR/cleanup-e2e.log" 2>&1 || log "e2e.sh --cleanup failed (see $RUN_DIR/cleanup-e2e.log)"; fi
  if selected dynamic-db; then ./test/e2e-dynamic-db.sh --cleanup > "$RUN_DIR/cleanup-dynamic-db.log" 2>&1 || log "e2e-dynamic-db.sh --cleanup failed"; fi
fi

# Totals count test ASSERTIONS only; the record-verify-* rows (checks of the
# published records, --publish only) are totalled apart as record_checks.
jq -R -s --arg ts "$RUN_UTC" '
  [split("\n")[] | select(length > 0) | split("\t")
   | {suite: .[0], verdict: .[1], passed: (.[2] | tonumber), failed: (.[3] | tonumber), skipped: (.[4] | tonumber),
      exit: .[5], seconds: (.[6] | tonumber), note: (.[7] // null)}] as $all
  | [$all[] | select(.suite | startswith("record-verify-") | not)] as $s
  | [$all[] | select(.suite | startswith("record-verify-"))] as $r
  | {run_utc: $ts, suites: $all,
     totals: {passed: ([$s[].passed] | add // 0), failed: ([$s[].failed] | add // 0), skipped: ([$s[].skipped] | add // 0),
              suites_passed: ([$s[] | select(.verdict == "PASS")] | length),
              suites_failed: ([$s[] | select(.verdict == "FAIL")] | length),
              suites_not_run: ([$s[] | select(.verdict == "NOT-RUN")] | length),
              record_checks: {passed: ([$r[].passed] | add // 0), failed: ([$r[].failed] | add // 0),
                              records_verified: ([$r[] | select(.verdict == "PASS")] | length),
                              records_failed: ([$r[] | select(.verdict == "FAIL")] | length)}},
     result: (if ([$all[] | select(.verdict == "FAIL")] | length) == 0 and ([$s[] | select(.verdict == "PASS")] | length) > 0
              then "PASS" else "FAIL" end)}' "$RUN_DIR/results.tsv" > "$RUN_DIR/summary.json"

printf '\n%-20s %-8s %7s %7s %7s %6s %7s\n' SUITE VERDICT PASSED FAILED SKIPPED EXIT SECONDS
jq -r '.suites[] | [.suite, .verdict, .passed, .failed, .skipped, .exit, .seconds] | @tsv' "$RUN_DIR/summary.json" \
  | while IFS=$'\t' read -r s v p f k e t; do printf '%-20s %-8s %7s %7s %7s %6s %7s\n' "$s" "$v" "$p" "$f" "$k" "$e" "$t"; done
jq -r '.totals | "TOTAL (assertions)   \(.passed) passed, \(.failed) failed, \(.skipped) skipped; suites: \(.suites_passed) passed, \(.suites_failed) failed, \(.suites_not_run) not run"' "$RUN_DIR/summary.json"
jq -r '.totals.record_checks | select(.records_verified + .records_failed > 0)
  | "RECORD CHECKS        \(.passed) passed, \(.failed) failed (published run records re-verified: \(.records_verified) ok, \(.records_failed) failed)"' "$RUN_DIR/summary.json"
printf '\n'
if [[ "$(jq -r .result "$RUN_DIR/summary.json")" == PASS ]]; then
  log "PAM TESTS PASSED (summary: $RUN_DIR/summary.json)"
  exit 0
fi
log "PAM TESTS FAILED (summary: $RUN_DIR/summary.json)"
exit 1
