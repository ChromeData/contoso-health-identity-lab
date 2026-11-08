#!/usr/bin/env bash
# =============================================================================
# tests/rotate-password.test.sh - offline test of ../rotate-password.sh
# -----------------------------------------------------------------------------
# No Azure, no Keychain, no network. The script runs from a copy in a
# throwaway tree, with a stub `az` (fake Graph) and a stub `security` (a
# folder of files) first on PATH. The real Keychain and tenant are never
# reached. Proves:
#   * --apply completes under set -euo pipefail (the password generator no
#     longer dies on SIGPIPE), and the stored value is 40 letters/digits;
#   * the value sent to Graph is the value promoted in the Keychain, and the
#     -pending item is gone after success;
#   * a failed reset call KEEPS the -pending item and says the outcome is
#     unknown (it never says "delete it");
#   * a second --apply refuses to overwrite that -pending item;
#   * --resume sends the SAME pending value and then promotes it;
#   * the evidence record and capture-log row do not contain the login;
#   * a second run while the per-account lock is held changes nothing, and
#     a finished run releases the lock.
# Prints PASS/FAIL per assertion; exits 1 if anything failed.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/bg-rotate-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

LOGIN='owner.person@example.invalid'
mkdir -p "$WORK/repo/lab/scripts/break-glass" "$WORK/bin" "$WORK/kc" "$WORK/graph"
cp "$HERE/../rotate-password.sh" "$WORK/repo/lab/scripts/break-glass/"
SCRIPT="$WORK/repo/lab/scripts/break-glass/rotate-password.sh"

# --- stub az: a fake Graph. PATCH writes the password to graph/password, or
# fails when graph/fail-patch exists (after or before applying it). ---------
cat > "$WORK/bin/az" <<STUB
#!/usr/bin/env bash
G="$WORK/graph"
args="\$*"
case "\$args" in
  "account show --query user.type -o tsv") echo user ;;
  "account show --query user.name -o tsv") echo "$LOGIN" ;;
  *"/v1.0/domains"*) echo contoso.example ;;
  *"--method patch"*)
    body="\${args##*--body @}"; body="\${body%% *}"
    if [[ -f "\$G/fail-patch-before" ]]; then exit 1; fi
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["passwordProfile"]["password"], end="")' "\$body" > "\$G/password"
    n=\$(( \$(cat "\$G/changes" 2>/dev/null || echo 0) + 1 )); echo "\$n" > "\$G/changes"
    if [[ -f "\$G/fail-patch-after" ]]; then exit 1; fi
    ;;
  *"select=lastPasswordChangeDateTime"*) echo "2026-11-07T0\$(cat "\$G/changes" 2>/dev/null || echo 0):00:00Z" ;;
  *"/v1.0/users/"*) printf '{"id":"00000000-0000-0000-0000-000000000001","lastPasswordChangeDateTime":"2026-01-01T00:00:00Z","createdDateTime":"2026-01-01T00:00:00Z"}' ;;
  *) echo "stub az: unexpected: \$args" >&2; exit 9 ;;
esac
STUB

# --- stub security: one file per service in kc/. -i reads one command line.
cat > "$WORK/bin/security" <<STUB
#!/usr/bin/env bash
K="$WORK/kc"
get() { local want="\$1"; shift; while [[ \$# -gt 0 ]]; do [[ "\$1" == "\$want" ]] && { echo "\$2"; return; }; shift; done; }
case "\$1" in
  -i)
    read -r line
    eval "set -- \$line"
    [[ "\$1" == add-generic-password ]] || exit 9
    shift; s="\$(get -s "\$@")"; w="\$(get -w "\$@")"; upd=no
    for a in "\$@"; do [[ "\$a" == -U ]] && upd=yes; done
    if [[ -f "\$K/\$s" && "\$upd" == no ]]; then echo "already exists" >&2; exit 45; fi
    printf '%s' "\$w" > "\$K/\$s" ;;
  find-generic-password)
    shift; s="\$(get -s "\$@")"
    [[ -f "\$K/\$s" ]] || exit 44
    for a in "\$@"; do [[ "\$a" == -w ]] && { cat "\$K/\$s"; echo; exit 0; }; done
    echo "attributes only" ;;
  delete-generic-password)
    shift; s="\$(get -s "\$@")"; [[ -f "\$K/\$s" ]] || exit 44; rm -f "\$K/\$s" ;;
  *) exit 9 ;;
esac
STUB
chmod +x "$WORK/bin/az" "$WORK/bin/security"
export PATH="$WORK/bin:$PATH"
export BG_ROTATE_LOCK_DIR="$WORK"
LOCK="$WORK/contoso-bg-rotate-bg-admin-01.lock"
SVC=contoso-breakglass-bg-admin-01-password
PEND="$SVC-pending"

# --- 1. --apply completes, value matches, pending removed --------------------
if out="$("$SCRIPT" bg-admin-01 --apply 2>&1)"; then pass "--apply completes under pipefail"; else fail "--apply completes under pipefail: $out"; fi
stored="$(cat "$WORK/kc/$SVC" 2>/dev/null || true)"
if [[ "$stored" =~ ^[A-Za-z0-9]{40}$ ]]; then pass "stored value is 40 letters/digits"; else fail "stored value is 40 letters/digits (got ${#stored} chars)"; fi
if [[ -n "$stored" && "$stored" == "$(cat "$WORK/graph/password")" ]]; then pass "Keychain value == value sent to Graph"; else fail "Keychain value == value sent to Graph"; fi
if [[ ! -e "$WORK/kc/$PEND" ]]; then pass "-pending removed after success"; else fail "-pending removed after success"; fi
if grep -q -- "$stored" <<<"$out"; then fail "password not printed"; else pass "password not printed"; fi
rec="$(ls "$WORK/repo/lab/evidence/break-glass/"*.json 2>/dev/null | head -1)"
if [[ -n "$rec" ]] && ! grep -q "$LOGIN" "$rec"; then pass "record has no login"; else fail "record has no login"; fi
row="$(grep '^E__,' <<<"$out" || true)"
if [[ -n "$row" ]] && ! grep -q "$LOGIN" <<<"$row"; then pass "capture-log row has no login"; else fail "capture-log row has no login: $row"; fi

# --- 2. reset applied but the call failed: pending KEPT -----------------------
rm -f "$WORK/kc/$SVC"; touch "$WORK/graph/fail-patch-after"
if out="$("$SCRIPT" bg-admin-01 --apply 2>&1)"; then fail "failed call exits non-zero"; else pass "failed call exits non-zero"; fi
if [[ -s "$WORK/kc/$PEND" ]]; then pass "-pending kept when the outcome is unknown"; else fail "-pending kept when the outcome is unknown"; fi
if grep -qi 'delete it)' <<<"$out" || ! grep -q 'UNKNOWN' <<<"$out"; then fail "message says unknown, not delete: $out"; else pass "message says unknown, not delete"; fi
if [[ "$(cat "$WORK/kc/$PEND")" == "$(cat "$WORK/graph/password")" ]]; then pass "pending holds the value Entra now uses"; else fail "pending holds the value Entra now uses"; fi
live="$(cat "$WORK/graph/password")"

# --- 3. a new --apply refuses to overwrite it ---------------------------------
rm -f "$WORK/graph/fail-patch-after"
if out="$("$SCRIPT" bg-admin-01 --apply 2>&1)"; then fail "--apply refuses with -pending present"; else pass "--apply refuses with -pending present"; fi
if [[ "$(cat "$WORK/kc/$PEND")" == "$live" && "$(cat "$WORK/graph/password")" == "$live" ]]; then pass "pending and Entra unchanged by the refusal"; else fail "pending and Entra unchanged by the refusal"; fi

# --- 4. --resume sends the same value and promotes it ------------------------
if out="$("$SCRIPT" bg-admin-01 --resume 2>&1)"; then pass "--resume completes"; else fail "--resume completes: $out"; fi
if [[ "$(cat "$WORK/kc/$SVC" 2>/dev/null)" == "$live" && "$(cat "$WORK/graph/password")" == "$live" ]]; then pass "--resume promotes the same value"; else fail "--resume promotes the same value"; fi
if [[ ! -e "$WORK/kc/$PEND" ]]; then pass "-pending removed after resume"; else fail "-pending removed after resume"; fi
if out="$("$SCRIPT" bg-admin-01 --resume 2>&1)"; then fail "--resume with nothing pending refuses"; else pass "--resume with nothing pending refuses"; fi

# --- 5. Entra refused before applying: pending still kept ---------------------
rm -f "$WORK/kc/$SVC"; touch "$WORK/graph/fail-patch-before"
"$SCRIPT" bg-admin-01 --apply >/dev/null 2>&1 || true
if [[ -s "$WORK/kc/$PEND" && "$(cat "$WORK/graph/password")" == "$live" ]]; then pass "refused reset: old password live, pending kept"; else fail "refused reset: old password live, pending kept"; fi

# --- 6. the lock: a held lock refuses and changes nothing --------------------
rm -f "$WORK/graph/fail-patch-before"
if [[ ! -e "$LOCK" ]]; then pass "lock released after every run"; else fail "lock released after every run"; fi
mkdir "$LOCK"; before_pw="$(cat "$WORK/graph/password")"
if out="$("$SCRIPT" bg-admin-01 --resume 2>&1)"; then fail "--resume refuses while locked"; else pass "--resume refuses while locked"; fi
if [[ -s "$WORK/kc/$PEND" && "$(cat "$WORK/graph/password")" == "$before_pw" && -d "$LOCK" ]]; then pass "locked run changed nothing and left the other run's lock"; else fail "locked run changed nothing and left the other run's lock"; fi
if "$SCRIPT" bg-admin-01 >/dev/null 2>&1; then pass "dry run works while locked"; else fail "dry run works while locked"; fi
rmdir "$LOCK"

echo
if [[ "$FAILS" -eq 0 ]]; then echo "rotate-password: all passed"; else echo "rotate-password: $FAILS failed"; exit 1; fi
