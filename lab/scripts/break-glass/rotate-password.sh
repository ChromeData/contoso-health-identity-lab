#!/usr/bin/env bash
# =============================================================================
# lab/scripts/break-glass/rotate-password.sh
# -----------------------------------------------------------------------------
# Rotate the seeded password of ONE break-glass account (bg-admin-NN) and keep
# the new value only in the macOS login Keychain.
#
# WHO RUNS IT: the lab OWNER, signed in to `az` as a human Global
# Administrator or Privileged Authentication Administrator. Never the lab
# operator: resetting a Global Administrator's password needs one of those two
# roles (Microsoft Learn, "Privileged administrator roles that can reset
# passwords"), and the operator must not hold them. The script refuses a
# service-principal sign-in.
#
# WHY: modules/groups seeds the password with random_password, so the value
# sits in Terraform state, which the PLAN identity can read (ADR 0003). A
# read on 2026-11-07 showed lastPasswordChangeDateTime == createdDateTime for
# both accounts: the seeded value was never rotated (capture log E11f). After
# rotation the value in state is stale and useless. The resource already has
# lifecycle { ignore_changes = [password] }, so no later plan sets it back.
#
# SECRET HANDLING (repo rule: Keychain only, never argv, never printed):
#   * The password is made in a shell variable from /dev/urandom.
#   * It reaches Keychain through `security -i` on STDIN (printf is a bash
#     builtin, so the value is never in any process's argv).
#   * It reaches Graph in a mode-600 body file in a private temp dir
#     (`az rest --body @file`); the file is deleted on exit.
#   * It is written to Keychain under a "-pending" name and read back BEFORE
#     the reset, so a failed reset never leaves the account with a password
#     nobody stored. Only after Graph accepts it is it promoted to the real
#     name.
#   * Nothing here ever prints it. Never use `security -g`.
#
# USAGE
#   rotate-password.sh bg-admin-01            # dry run: checks only, changes nothing
#   rotate-password.sh bg-admin-01 --apply    # rotate
# Then commit the record it writes under lab/evidence/break-glass/ and add the
# capture-log row it prints.
# =============================================================================
set -euo pipefail
umask 077

acct="${1:-}"
mode="${2:---dry-run}"
if [[ ! "$acct" =~ ^bg-admin-[0-9]{2}$ ]]; then
  echo "usage: $0 bg-admin-NN [--apply]" >&2; exit 2
fi
case "$mode" in --apply|--dry-run) ;; *) echo "unknown option: $mode" >&2; exit 2;; esac

command -v security >/dev/null || { echo "macOS 'security' not found: this must run on the owner's Mac." >&2; exit 1; }
command -v az >/dev/null || { echo "az CLI not found." >&2; exit 1; }

repo="$(cd "$(dirname "$0")/../../.." && pwd)"
svc="contoso-breakglass-${acct}-password"
pending="${svc}-pending"

# --- 1. A human must be signed in (fail closed: unreadable = stop) ----------
if ! who_type="$(az account show --query user.type -o tsv 2>/dev/null)"; then
  echo "az is not signed in. Run: az login (as the owner, interactively)." >&2; exit 1
fi
if [[ "$who_type" != "user" ]]; then
  echo "Refusing: az is signed in as '$who_type'. A human admin must run this, not the lab operator." >&2; exit 1
fi
who="$(az account show --query user.name -o tsv)"

# --- 2. Find the account (fail closed: not found != could not read) --------
if ! domain="$(az rest --method get --url 'https://graph.microsoft.com/v1.0/domains' \
      --query "value[?isInitial].id | [0]" -o tsv)"; then
  echo "Could not read the tenant's domains." >&2; exit 1
fi
upn="${acct}@${domain}"
if ! user_json="$(az rest --method get \
      --url "https://graph.microsoft.com/v1.0/users/${upn}?\$select=id,userPrincipalName,accountEnabled,lastPasswordChangeDateTime,createdDateTime")"; then
  echo "Could not read ${upn} (not found, or no permission). Nothing changed." >&2; exit 1
fi
uid="$(printf '%s' "$user_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
before="$(printf '%s' "$user_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lastPasswordChangeDateTime"])')"
created="$(printf '%s' "$user_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["createdDateTime"])')"
echo "Account:        ${upn} (${uid})"
echo "Created:        ${created}"
echo "Password set:   ${before}$( [[ "$before" == "$created" ]] && echo '  <- never rotated since creation')"
echo "Signed in as:   ${who}"
echo "Keychain item:  ${svc}"

if [[ "$mode" == "--dry-run" ]]; then
  echo "Dry run: nothing changed. Re-run with --apply to rotate."
  exit 0
fi

# --- 3. New password, into Keychain (pending) and read back ----------------
# Letters and digits only, 40 characters (about 238 bits). No quotes, spaces
# or backslashes, so neither `security -i` parsing nor JSON can mangle it.
# Entra needs 3 of 4 character classes: loop until upper, lower and digit
# are all present.
pw=""
until [[ "$pw" =~ [A-Z] && "$pw" =~ [a-z] && "$pw" =~ [0-9] ]]; do
  pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)"
done

printf 'add-generic-password -U -s %s -a %s -l "Break-glass %s password (rotation pending)" -w %s\n' \
  "$pending" "$upn" "$acct" "$pw" | security -i >/dev/null
readback="$(security find-generic-password -s "$pending" -a "$upn" -w)"
if [[ "$readback" != "$pw" ]]; then
  unset pw readback
  echo "Keychain read-back did not match. Nothing sent to Entra." >&2; exit 1
fi
unset readback

# --- 4. Reset in Entra through a private body file -------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '{"passwordProfile":{"forceChangePasswordNextSignIn":false,"password":"%s"}}' "$pw" > "$tmp/body.json"
if ! az rest --method patch --url "https://graph.microsoft.com/v1.0/users/${uid}" \
      --headers 'Content-Type=application/json' --body "@$tmp/body.json" >/dev/null; then
  rm -f "$tmp/body.json"; unset pw
  echo "Entra refused the reset. The old password still works; the -pending Keychain item holds an UNUSED value (delete it)." >&2
  exit 1
fi
rm -f "$tmp/body.json"

# --- 5. Promote the Keychain item -----------------------------------------
printf 'add-generic-password -U -s %s -a %s -l "Break-glass %s password" -w %s\n' \
  "$svc" "$upn" "$acct" "$pw" | security -i >/dev/null
unset pw
security delete-generic-password -s "$pending" -a "$upn" >/dev/null

# --- 6. Read back and write the record (no secret in it) -------------------
after="$(az rest --method get --url "https://graph.microsoft.com/v1.0/users/${uid}?\$select=lastPasswordChangeDateTime" \
  --query lastPasswordChangeDateTime -o tsv)"
if [[ "$after" == "$before" ]]; then
  echo "WARNING: lastPasswordChangeDateTime did not move yet (${after}). Re-read in a minute before recording." >&2
fi
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
stamp="$(date -u +%Y%m%dT%H%MZ)"
mkdir -p "$repo/lab/evidence/break-glass"
rec="lab/evidence/break-glass/${stamp}-${acct}-password-rotation.json"
python3 - "$repo/$rec" "$upn" "$uid" "$before" "$after" "$who" "$svc" "$now" <<'PY'
import json, sys
path, upn, uid, before, after, who, svc, now = sys.argv[1:]
json.dump({
  "account": upn, "objectId": uid,
  "lastPasswordChangeBefore": before, "lastPasswordChangeAfter": after,
  "rotatedBy": who, "rotatedAtUtc": now,
  "storedIn": "macOS login Keychain, service " + svc + " (value never printed or logged)",
  "terraformState": "random_password.break_glass still holds the SEEDED value; it no longer works (ignore_changes = [password])",
}, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
sha="$(shasum -a 256 "$repo/$rec" | cut -d' ' -f1)"
echo
echo "Rotated. Read back: lastPasswordChangeDateTime ${after}."
echo "Record: ${rec}"
echo "Capture-log row to append (lab/evidence/capture-log.csv), set the id:"
echo "E__,${now},\"Break-glass password rotated (RAN · tenant): ${acct}, by ${who} (human, not the operator), new value in the owner's Keychain only (${svc}), never printed. lastPasswordChangeDateTime ${before} -> ${after}. The seeded value in Terraform state no longer works (runbook break-glass-password-rotation.md)\",${sha},${rec},yes,owner"
