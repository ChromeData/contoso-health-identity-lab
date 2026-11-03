#!/usr/bin/env bash
# =============================================================================
# tests/reset-demo-hire.test.sh - offline test of ../reset-demo-hire.sh
# -----------------------------------------------------------------------------
# No Azure, no DC, no network: a throwaway git repo with a local bare
# "origin" that has main (the shipped roster) and hr-feed (plus one demo
# hire, 400104). The DC step is skipped (--skip-ad) or only printed (dry
# run); `az` and run-on-dc.py are never reached. Proves:
#   * the dry run changes nothing (origin/hr-feed keeps the row);
#   * an employeeId in main's shipped roster is refused without --force;
#   * --apply removes exactly that row on origin/hr-feed and keeps every
#     other line byte-for-byte, with a plain commit message;
#   * a second --apply is idempotent ("already done").
# Prints PASS/FAIL per assertion; exits 1 if anything failed.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../reset-demo-hire.sh"
SRC_CSV="$HERE/../../mock-hr/hr_feed.csv"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/reset-hire-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
CSV="lab/scripts/mock-hr/hr_feed.csv"
HIRE='400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,'
G=(git -c user.email=test@example.invalid -c user.name=test -c init.defaultBranch=main -c commit.gpgsign=false)

# --- fixture: origin with main + hr-feed --------------------------------------
"${G[@]}" init -q --bare "$WORK/origin.git"
"${G[@]}" init -q "$WORK/seed"
mkdir -p "$WORK/seed/lab/scripts/mock-hr"
cp "$SRC_CSV" "$WORK/seed/$CSV"
"${G[@]}" -C "$WORK/seed" add -A && "${G[@]}" -C "$WORK/seed" commit -qm "roster"
"${G[@]}" -C "$WORK/seed" remote add origin "$WORK/origin.git"
"${G[@]}" -C "$WORK/seed" push -q origin HEAD:refs/heads/main
"${G[@]}" -C "$WORK/seed" switch -qc hr-feed
printf '%s\n' "$HIRE" >> "$WORK/seed/$CSV"
"${G[@]}" -C "$WORK/seed" commit -qam "Hire Sam Rivera"
"${G[@]}" -C "$WORK/seed" push -q origin HEAD:refs/heads/hr-feed
"${G[@]}" clone -q "$WORK/origin.git" "$WORK/me"
"${G[@]}" -C "$WORK/me" config user.email test@example.invalid
"${G[@]}" -C "$WORK/me" config user.name test
"${G[@]}" -C "$WORK/me" config commit.gpgsign false
before="$(git -C "$WORK/origin.git" rev-parse hr-feed)"

# --- 1. dry run changes nothing -----------------------------------------------
out="$(cd "$WORK/me" && "$SCRIPT" 400104 2>&1)" || true
if grep -q 'Reset demo hire: Sam Rivera, Cloud Engineer (Information Technology), status joiner' <<<"$out"; then pass "dry run names the hire"; else fail "dry run names the hire: $out"; fi
if grep -q "would: commit 'HR: remove demo hire Sam Rivera (retake reset)'" <<<"$out" && grep -q 'would: lab/scripts/dc/run-on-dc.py lab/scripts/dc/Remove-DemoHire.ps1 --param EmployeeId=400104 --param Apply=yes' <<<"$out"; then pass "dry run prints the git and DC steps"; else fail "dry run steps: $out"; fi
if [ "$(git -C "$WORK/origin.git" rev-parse hr-feed)" = "$before" ]; then pass "dry run pushed nothing"; else fail "dry run moved origin/hr-feed"; fi

# --- 2. shipped roster is refused ---------------------------------------------
if (cd "$WORK/me" && "$SCRIPT" 100492 --apply --skip-ad >/dev/null 2>&1); then fail "shipped employeeId 100492 must be refused"; else pass "shipped employeeId (Dana, 100492) refused without --force"; fi
if [ "$(git -C "$WORK/origin.git" rev-parse hr-feed)" = "$before" ]; then pass "refusal pushed nothing"; else fail "refusal moved origin/hr-feed"; fi

# --- 3. --apply removes exactly the row -----------------------------------------
(cd "$WORK/me" && "$SCRIPT" 400104 --apply --skip-ad >/dev/null)
after_csv="$(git -C "$WORK/origin.git" show "hr-feed:$CSV")"
if ! grep -q '^400104,' <<<"$after_csv"; then pass "--apply removed 400104 on origin/hr-feed"; else fail "row still on origin/hr-feed"; fi
if [ "$after_csv" = "$(cat "$SRC_CSV")" ]; then pass "every other line unchanged (file equals the shipped roster again)"; else fail "other lines changed"; fi
msg="$(git -C "$WORK/origin.git" log -1 --format=%s hr-feed)"
if [ "$msg" = "HR: remove demo hire Sam Rivera (retake reset)" ]; then pass "commit message: $msg"; else fail "commit message: $msg"; fi
if [ "$(git -C "$WORK/origin.git" rev-parse hr-feed^)" = "$before" ]; then pass "a fast-forward commit, no force-push"; else fail "history rewritten"; fi

# --- 4. idempotent -------------------------------------------------------------
out="$(cd "$WORK/me" && "$SCRIPT" 400104 --apply --skip-ad 2>&1)"
if grep -q 'already done: no row for 400104' <<<"$out"; then pass "second --apply: already done"; else fail "second run: $out"; fi

[ "$FAILS" -eq 0 ] || { echo "$FAILS assertion(s) failed"; exit 1; }
echo "all passed"
