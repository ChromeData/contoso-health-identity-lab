#!/usr/bin/env bash
# =============================================================================
# tests/reset-demo-hire.test.sh - offline test of ../reset-demo-hire.sh
# -----------------------------------------------------------------------------
# No Azure, no DC, no network: a throwaway git repo with a local bare
# "origin" that has main (the shipped roster) and hr-feed (plus one demo
# hire, 400104). The DC step is skipped (--skip-ad), only printed (dry
# run), or reaches a stub run-on-dc.py that just records the call; `az`
# and the real DC are never reached. Proves:
#   * the dry run changes nothing (origin/hr-feed keeps the row);
#   * an employeeId in main's shipped roster is refused without --force;
#   * --apply removes exactly that row on origin/hr-feed and keeps every
#     other line byte-for-byte, with a plain commit message;
#   * a second --apply is idempotent ("already done");
#   * the shipped-roster guard also holds the AD delete (--skip-git): an
#     employee absent from a readable roster goes ahead, a present one is
#     refused unless --force;
#   * an UNREADABLE roster (single-branch checkout offline, no
#     origin/main; main without the file; an empty file) refuses every
#     employeeId and never reaches the DC step; --force alone overrides;
#   * a single-branch checkout online gets origin/main by itself, so the
#     guard works there instead of refusing;
#   * an unreadable hr-feed is "NOT checked", never "already done".
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

# --- guard helpers ----------------------------------------------------------------
# stub_dc <clone> <log>: the clone's run-on-dc.py records its arguments and
# does nothing else, so a guard that lets a deletion through shows up as a
# line in <log> (the script runs $ROOT/lab/scripts/dc/run-on-dc.py).
stub_dc() {
  mkdir -p "$1/lab/scripts/dc"
  cat > "$1/lab/scripts/dc/run-on-dc.py" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$2"
STUB
  chmod +x "$1/lab/scripts/dc/run-on-dc.py"
}
# run <clone> <args...>: sets OUT and RC (never stops the test on a refusal).
run() { local dir="$1"; shift; RC=0; OUT="$(cd "$dir" && "$SCRIPT" "$@" 2>&1)" || RC=$?; }
called() { [ -f "$1" ] && grep -q "EmployeeId=$2 --param Apply=yes" "$1"; }
UNREADABLE="REFUSED: could not read main's hr_feed.csv"

# --- 5. readable roster: the guard decides the AD delete too (--skip-git) ---------
stub_dc "$WORK/me" "$WORK/dc-me.log"
run "$WORK/me" 400104 --apply --skip-git
if [ "$RC" -eq 0 ] && called "$WORK/dc-me.log" 400104; then pass "absent from a readable roster: the AD delete goes ahead"; else fail "absent employee should proceed (rc $RC): $OUT"; fi
run "$WORK/me" 100492 --apply --skip-git
if [ "$RC" -ne 0 ] && grep -q "REFUSED: employeeId 100492 is in main's hr_feed.csv" <<<"$OUT" && ! called "$WORK/dc-me.log" 100492; then pass "present on the roster, --skip-git: refused, DC never called"; else fail "shipped employee with --skip-git (rc $RC): $OUT"; fi
run "$WORK/me" 100492 --apply --skip-git --force
if [ "$RC" -eq 0 ] && grep -q 'note: --force: employeeId 100492 IS in main' <<<"$OUT" && called "$WORK/dc-me.log" 100492; then pass "--force still overrides the shipped-roster refusal (and says so)"; else fail "--force on a shipped employee (rc $RC): $OUT"; fi

# --- 6. unreadable roster: refused, whatever the employeeId ------------------------
# 6a. single-branch checkout of hr-feed, offline: no origin/main at all.
"${G[@]}" clone -q --single-branch --branch hr-feed "$WORK/origin.git" "$WORK/single"
"${G[@]}" -C "$WORK/single" remote set-url origin "$WORK/offline.git"   # does not exist: every fetch fails
stub_dc "$WORK/single" "$WORK/dc-single.log"
if ! git -C "$WORK/single" rev-parse -q --verify origin/main >/dev/null; then pass "fixture: single-branch checkout has no origin/main"; else fail "fixture: origin/main exists"; fi
for id in 100492 400104; do
  run "$WORK/single" "$id" --apply --skip-git
  if [ "$RC" -ne 0 ] && grep -q "$UNREADABLE" <<<"$OUT" && ! called "$WORK/dc-single.log" "$id"; then pass "no origin/main: $id --apply --skip-git refused, DC never called"; else fail "no origin/main, $id (rc $RC): $OUT"; fi
done
run "$WORK/single" 100492
if [ "$RC" -ne 0 ] && grep -q "$UNREADABLE" <<<"$OUT"; then pass "no origin/main: the dry run says it would be refused"; else fail "dry run with no origin/main (rc $RC): $OUT"; fi
run "$WORK/single" 100492 --apply --skip-git --force
if [ "$RC" -eq 0 ] && grep -q "note: --force: main's hr_feed.csv could not be read" <<<"$OUT" && called "$WORK/dc-single.log" 100492; then pass "unreadable roster: --force alone goes ahead (and says so)"; else fail "--force with no origin/main (rc $RC): $OUT"; fi

# 6b. origin/main present but without the roster, or with an empty one (offline,
#     so the next fetch cannot put the real main back).
"${G[@]}" clone -q "$WORK/origin.git" "$WORK/bent"
"${G[@]}" -C "$WORK/bent" remote set-url origin "$WORK/offline.git"
stub_dc "$WORK/bent" "$WORK/dc-bent.log"
for how in missing empty; do
  "${G[@]}" -C "$WORK/bent" switch -q --no-track -C "bent-$how" origin/main
  if [ "$how" = missing ]; then "${G[@]}" -C "$WORK/bent" rm -q "$CSV"; else : > "$WORK/bent/$CSV"; "${G[@]}" -C "$WORK/bent" add "$CSV"; fi
  "${G[@]}" -C "$WORK/bent" commit -qm "roster $how"
  "${G[@]}" -C "$WORK/bent" update-ref refs/remotes/origin/main HEAD
  run "$WORK/bent" 100492 --apply --skip-git
  if [ "$RC" -ne 0 ] && grep -q "$UNREADABLE" <<<"$OUT" && ! called "$WORK/dc-bent.log" 100492; then pass "roster $how on origin/main: refused, DC never called"; else fail "roster $how (rc $RC): $OUT"; fi
  "${G[@]}" -C "$WORK/bent" update-ref refs/remotes/origin/main "$(git -C "$WORK/origin.git" rev-parse main)"
done

# --- 7. single-branch checkout ONLINE: the fetch brings origin/main itself ---------
"${G[@]}" clone -q --single-branch --branch hr-feed "$WORK/origin.git" "$WORK/single-online"
stub_dc "$WORK/single-online" "$WORK/dc-online.log"
run "$WORK/single-online" 100492 --apply --skip-git
if [ "$RC" -ne 0 ] && grep -q "REFUSED: employeeId 100492 is in main's hr_feed.csv" <<<"$OUT" && git -C "$WORK/single-online" rev-parse -q --verify origin/main >/dev/null; then pass "single-branch checkout online: origin/main fetched, shipped employee refused as shipped"; else fail "single-branch online (rc $RC): $OUT"; fi

# --- 8. an unreadable hr-feed is "NOT checked", never "already done" ---------------
"${G[@]}" -C "$WORK/bent" update-ref -d refs/remotes/origin/hr-feed
run "$WORK/bent" 400104 --apply --skip-ad
if [ "$RC" -ne 0 ] && grep -q 'NOT checked: hr_feed.csv on origin/hr-feed could not be read' <<<"$OUT" && ! grep -q 'already done' <<<"$OUT" && grep -q 'Not done: step 1' <<<"$OUT"; then pass "no origin/hr-feed: step 1 NOT checked, run exits non-zero"; else fail "unreadable hr-feed (rc $RC): $OUT"; fi

[ "$FAILS" -eq 0 ] || { echo "$FAILS assertion(s) failed"; exit 1; }
echo "all passed"
