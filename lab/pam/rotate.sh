#!/usr/bin/env bash
# =============================================================================
# rotate.sh - on-demand rotation of a vaulted service account, GATED on its
# dependencies (a password change on an account whose usages are known).
#
# Refuses when accounts-dependencies.json lists an unresolved consumer of the
# password (a Windows service, scheduled task, app pool, connection string
# that holds a copy) or has NO record for the account - unknown is not
# "none". Override for one account with a justification naming a change:
#
#   ./rotate.sh svc-sql01 --force --justification "CHG0031337: DBA updates the SQL service logon in the window"
#
# Overrides go to the exception register (Vault KV v2 pam-meta/exceptions/,
# versioned and in Vault's audit log) and to out/pam-audit.jsonl.
#
# Scope: static roles only. Library (check-out) accounts rotate on every
# check-in (./psm-session.sh checkin). Vault's own scheduled rotation of a
# static role does not consult this gate - which is why onboard.sh only
# creates static roles whose dependencies are resolved.
#
# Usage: ./rotate.sh SAM [--deps FILE] [--force --justification TEXT [--operator NAME]]
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq; need curl
load_env

SAM="" DEPS=accounts-dependencies.json FORCE=0 JUST="" OPERATOR=local-admin
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deps) DEPS="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --justification) JUST="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    -*) die "unknown option $1" ;;
    *) [[ -z "$SAM" ]] || die "one account per run"; SAM="$1"; shift ;;
  esac
done
[[ -n "$SAM" ]] || die "usage: $0 SAM [--deps FILE] [--force --justification TEXT [--operator NAME]]"
[[ $FORCE -eq 0 || -n "$JUST" ]] || die "--force needs --justification \"...CHG#######...\""
[[ -z "$JUST" ]] || check_justification "$JUST"

vault_unseal
export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"

role=$(static_role_of "$SAM")
[[ -n "$role" ]] || die "$SAM is not managed by a static role (library accounts rotate on check-in: ./psm-session.sh checkin)"

rc=0; deps=$(dep_gate "$SAM" "$DEPS") || rc=$?
if [[ $rc -ne 0 ]]; then
  if [[ $FORCE -eq 0 ]]; then
    printf '%s\n' "$deps" | sed 's/^/  - /' >&2
    audit_line rotate-refused account="$SAM" role="$role" reason="$(printf '%s' "$deps" | paste -sd ';' -)"
    die "REFUSED: $SAM has unresolved dependencies (above). Resolve them in $DEPS, or --force with a justification."
  fi
  record_override "$SAM" rotate-forced "$JUST" "$OPERATOR" "$deps"
  audit_line override account="$SAM" action=rotate-forced justification="$JUST" by="$OPERATOR"
  log "Dependency gate overridden for $SAM (recorded in pam-meta/exceptions/$SAM)"
fi

before=$(vault_api GET "ldap/static-role/$role" | jq -r '.data.last_vault_rotation')
printf '{}' | vault_api POST "ldap/rotate-role/$role" >/dev/null || die "Vault could not rotate $role"
after=$(vault_api GET "ldap/static-role/$role" | jq -r '.data.last_vault_rotation')
[[ "$after" != "$before" ]] || die "last_vault_rotation did not move ($before) - check Vault's log"
audit_line rotate account="$SAM" role="$role" rotated="$after" by="$OPERATOR"
log "Rotated $SAM ($role): last_vault_rotation $before -> $after"
