#!/usr/bin/env bash
# =============================================================================
# azure-config.test.sh  -  tests for azure-config.sh (the skip-or-run gate in
# front of every job that signs in to Azure). Run by lab-tests.yml; locally:
#   bash .github/scripts/azure-config.test.sh
# Needs bash (3.2+) and git. No network, no credentials.
# =============================================================================
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SUT="$HERE/azure-config.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

VARS=(T_CLIENT_ID T_TENANT_ID T_SUB_ID)
# A value that must never show up in any output.
CANARY="canary-value-0b1c"

# run_sut <mode> [ENV=VALUE ...] -- runs the script with a clean env (only the
# given variables plus PATH/HOME), $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY
# pointing into $TMP; sets $rc, $out (stdout+stderr), $gh_out, $gh_sum.
run_sut() {
  local mode=$1
  shift
  : > "$TMP/output"
  : > "$TMP/summary"
  out=$(env -i PATH="$PATH" HOME="$HOME" GITHUB_OUTPUT="$TMP/output" GITHUB_STEP_SUMMARY="$TMP/summary" \
    "$@" bash "$SUT" "$mode" plan "${VARS[@]}" 2>&1)
  rc=$?
  gh_out=$(cat "$TMP/output")
  gh_sum=$(cat "$TMP/summary")
}

# --- gate ---------------------------------------------------------------------
run_sut gate
if [ "$rc" -eq 0 ] && [ "$gh_out" = "run=false" ]; then ok "gate: nothing set -> run=false"; else bad "gate: nothing set -> run=false (rc=$rc out=$gh_out)"; fi
case $out in *"::notice title=plan skipped"*T_CLIENT_ID*T_TENANT_ID*T_SUB_ID*) ok "gate: skip prints a notice naming every variable" ;; *) bad "gate: skip notice ($out)" ;; esac
case $gh_sum in *"skipped (no Azure tenant wired)"*) ok "gate: skip writes the job summary" ;; *) bad "gate: skip summary ($gh_sum)" ;; esac

run_sut gate T_TENANT_ID="$CANARY"
if [ "$rc" -eq 0 ] && [ "$gh_out" = "run=true" ]; then ok "gate: one variable set -> run=true"; else bad "gate: one set (rc=$rc out=$gh_out)"; fi
case $out in *"$CANARY"*) bad "gate: printed a variable value" ;; *) ok "gate: prints names, never values" ;; esac

run_sut gate AZURE_GATE_FORCE_RUN="fork PR"
if [ "$gh_out" = "run=true" ]; then ok "gate: force (fork PR) -> run=true with nothing set"; else bad "gate: force (out=$gh_out)"; fi

# Marker on the base commit: a throwaway repo with one commit without the
# marker and one with it.
repo="$TMP/repo"
mkdir -p "$repo/.github"
(
  cd "$repo" || exit 1
  git init -q
  git config user.name test
  git config user.email test@example.invalid
  echo x > README
  git add README
  git commit -q -m without
  git rev-parse HEAD > "$TMP/sha_without"
  : > .github/azure-lane.enabled
  git add .github/azure-lane.enabled
  git commit -q -m with
  git rev-parse HEAD > "$TMP/sha_with"
) || { bad "test setup: git repo"; }
sha_without=$(cat "$TMP/sha_without" 2>/dev/null || true)
sha_with=$(cat "$TMP/sha_with" 2>/dev/null || true)

run_in_repo() { (cd "$repo" && run_sut "$@" && printf '%s\n%s\n' "$rc" "$gh_out"); }

res=$(run_in_repo gate AZURE_GATE_MARKER_REF="$sha_with")
if [ "$(printf '%s\n' "$res" | tail -n 1)" = "run=true" ]; then ok "gate: marker on base commit -> run=true with nothing set"; else bad "gate: marker present ($res)"; fi

res=$(run_in_repo gate AZURE_GATE_MARKER_REF="$sha_without")
if [ "$(printf '%s\n' "$res" | tail -n 1)" = "run=false" ]; then ok "gate: base commit without marker -> run=false"; else bad "gate: marker absent ($res)"; fi

res=$(run_in_repo gate AZURE_GATE_MARKER_REF=0123456789abcdef0123456789abcdef01234567)
if [ "$(printf '%s\n' "$res" | tail -n 1)" = "run=true" ]; then ok "gate: unknown base commit -> run=true (fail closed)"; else bad "gate: unknown base ($res)"; fi

# --- require ------------------------------------------------------------------
run_sut require T_CLIENT_ID="$CANARY" T_TENANT_ID="$CANARY" T_SUB_ID="$CANARY"
if [ "$rc" -eq 0 ]; then ok "require: all set -> exit 0"; else bad "require: all set (rc=$rc out=$out)"; fi

run_sut require T_CLIENT_ID="$CANARY"
if [ "$rc" -eq 1 ]; then ok "require: partial -> exit 1"; else bad "require: partial (rc=$rc)"; fi
case $out in *"::error title=plan: Azure configuration incomplete::"*"T_TENANT_ID T_SUB_ID"*) ok "require: error names the missing variables" ;; *) bad "require: error text ($out)" ;; esac
case $out in *"$CANARY"*) bad "require: printed a variable value" ;; *) ok "require: never prints a value" ;; esac

run_sut require
if [ "$rc" -eq 1 ]; then ok "require: nothing set -> exit 1"; else bad "require: nothing set (rc=$rc)"; fi

# --- argument checks ------------------------------------------------------------
out=$(bash "$SUT" gate plan 'BAD-NAME' 2>&1); rc=$?
if [ "$rc" -eq 2 ]; then ok "rejects a malformed variable name"; else bad "bad name (rc=$rc out=$out)"; fi
out=$(bash "$SUT" deploy plan T_CLIENT_ID 2>&1); rc=$?
if [ "$rc" -eq 2 ]; then ok "rejects an unknown mode"; else bad "unknown mode (rc=$rc)"; fi

echo
echo "azure-config tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
