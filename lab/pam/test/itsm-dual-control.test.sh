#!/usr/bin/env bash
# =============================================================================
# test/itsm-dual-control.test.sh - ticket validation + DUAL CONTROL, offline.
#
# Runs the REAL broker code (lib.sh itsm_validate, the function psm-session.sh
# and psm-ssh.sh call) against the REAL ServiceNow mock
# (tools/mock_servicenow.py, started here on 127.0.0.1 with python3) and the
# committed pam-policy.json / operators.json, with tickets raised by the real
# itsm-ticket.sh. No Docker, no Vault, no Guacamole: what this proves is the
# approval rule itself, every branch of it. test/e2e.sh proves the same rule
# end to end through psm-session.sh / psm-ssh.sh (step f0, f, n).
#
#   Tier 0 (tier0-admins, approvals_required 2): two distinct authorised
#   approvers, neither the requester -> accepted; self-approval, a single
#   approver, the same approver twice, an approver without the Safe right,
#   the change's requester approving, a pending approval, any rejection ->
#   refused, each with its own reason. A policy without approvals_required,
#   or with 0 / "2" / 1.5, and an approvals table ITSM cannot serve -> refused
#   (fail closed).
#   Tier 1 (linux-admin, approvals_required 1): one authorised approver ->
#   accepted; none, self-approval, an unauthorised approver -> refused.
#   The older gates still hold (not approved, not Implement, outside the
#   window, someone else's change, unknown, malformed).
#   The mock: sysapproval_approver rows in ServiceNow's shape, no inline
#   "approvals" field on change_request, v1/v2 no-match behaviour, 401.
#
# Prints PASS/FAIL per check (run-all.sh counts them); exit 1 on any FAIL.
# The throwaway ITSM password lives in a private temp dir (0700) for the run
# and is never printed. Usage: test/itsm-dual-control.test.sh
# =============================================================================
# Helpers are called through check, which ShellCheck cannot see (SC2329);
# the single-quoted grep patterns are literal code on purpose (SC2016).
# shellcheck disable=SC2329,SC2016
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"   # cd's to lab/pam
need jq; need curl; need python3; need openssl; need shasum

FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

TMP=$(mktemp -d); chmod 700 "$TMP"
PIDS=()
cleanup() { local p; for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

# --- a private mock: own tickets file, own throwaway credential ------------------
export PAM_ITSM_TICKETS="$TMP/tickets.json"
echo '[]' > "$PAM_ITSM_TICKETS"
printf 'Ix-%s' "$(openssl rand -hex 16)" > "$TMP/itsm-password"
ITSM_PASSWORD_FILE="$TMP/itsm-password"       # lib.sh reads it from here
export ITSM_USER=svc-pam-itsm-test
AUTH_SHA=$(printf '%s:%s' "$ITSM_USER" "$(cat "$TMP/itsm-password")" | shasum -a 256 | cut -d' ' -f1)
free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'; }
start_mock() { # start_mock PORT [FAIL_TABLES]
  env ITSM_TICKETS_FILE="$PAM_ITSM_TICKETS" ITSM_AUTH_SHA256="$AUTH_SHA" ITSM_FAIL_TABLES="${2:-}" \
      BIND=127.0.0.1 PORT="$1" python3 -I tools/mock_servicenow.py 2>"$TMP/mock-$1.log" &
  PIDS+=("$!"); disown "$!"   # no "Terminated" job notice when the trap kills it
  local _
  for _ in $(seq 1 50); do curl -fsS -o /dev/null "http://127.0.0.1:$1/health" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}
PORT=$(free_port); start_mock "$PORT" || die "mock_servicenow.py did not start on 127.0.0.1:$PORT"
FPORT=$(free_port); start_mock "$FPORT" sysapproval_approver || die "fault-injected mock did not start on 127.0.0.1:$FPORT"
export ITSM_URL="http://127.0.0.1:$PORT"

# --- helpers ------------------------------------------------------------------------
ticket() { # ticket OPERATOR [itsm-ticket.sh add options] -> a fresh CHG number (runs in $(...): no counters here)
  local num; num=$(./itsm-ticket.sh next) || return 1
  ./itsm-ticket.sh add "$num" --operator "$@" --short "itsm-dual-control test" >/dev/null || return 1
  printf '%s' "$num"
}
OUT=""
validate() { local rc=0; OUT=$(itsm_validate "$@" 2>&1) || rc=$?; return "$rc"; }   # TICKET OP TIER SAFE
accepted() { # accepted PATTERN TICKET OP TIER SAFE : exit 0 and the summary says PATTERN
  local pat="$1"; shift
  validate "$@" || { printf '      %s\n' "$OUT"; return 1; }
  grep -qF -- "$pat" <<<"$OUT" || { printf '      %s\n' "$OUT"; return 1; }
}
refused() { # refused PATTERN TICKET OP TIER SAFE : exit non-zero AND the reason says PATTERN
  local pat="$1"; shift
  if validate "$@"; then printf '      accepted: %s\n' "$OUT"; return 1; fi
  grep -qF -- "$pat" <<<"$OUT" || { printf '      %s\n' "$OUT"; return 1; }
}
said() { grep -qF -- "$1" <<<"$OUT"; }   # said PATTERN: the last validate printed it
approvers_line() { [[ "$(printf '%s\n' "$OUT" | sed -n 2p)" == "$1" ]]; }   # the 2nd line callers put in the audit trail
api() { # api PORT PATH-AND-QUERY -> "HTTP-CODE BODY" (credentials via curl config on stdin)
  local pw; pw=$(cat "$TMP/itsm-password")
  printf 'user = "%s:%s"\n' "$ITSM_USER" "$pw" | curl -sS -K - -w ' %{http_code}' "http://127.0.0.1:$1$2"
}
api_code() { local r; r=$(api "$1" "$2"); [[ "${r##* }" == "$3" ]]; }
api_json() { local r; r=$(api "$1" "$2"); [[ "${r##* }" == 200 ]] && printf '%s' "${r% *}" | jq -e "$3" >/dev/null; }
noauth_401() { [[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/api/now/v2/table/change_request")" == 401 ]]; }
policy_with() { jq "$1" pam-policy.json > "$TMP/policy.json" && printf '%s' "$TMP/policy.json"; }
static_has() { grep -qF -- "$2" "$1"; }
policy_counts_ok() { jq -e '.tiers.tier0.approvals_required == 2 and .tiers.tier1.approvals_required == 1' pam-policy.json >/dev/null; }
tickets_distinct() { [[ "$(jq '[.[].number] | length' "$PAM_ITSM_TICKETS")" == "$(jq '[.[].number] | unique | length' "$PAM_ITSM_TICKETS")" ]]; }

# --- the mock speaks ServiceNow's shape ------------------------------------------------
T_SHAPE=$(ticket ops-alice --approver ops-carol --approver ops-dana:requested)
check "mock: /health answers without credentials" curl -fsS -o /dev/null "http://127.0.0.1:$PORT/health"
check "mock: the Table API without credentials -> 401" noauth_401
check "mock: change_request returns requested_by.user_name (dot-walked, as a PDI does)" \
  api_json "$PORT" "/api/now/v2/table/change_request?sysparm_query=number%3D$T_SHAPE&sysparm_fields=number,requested_by.user_name" \
  '.result == [{"number": "'"$T_SHAPE"'", "requested_by.user_name": "ops-alice"}]'
check "mock: change_request has NO inline approvals field (ServiceNow keeps them in sysapproval_approver)" \
  api_json "$PORT" "/api/now/v2/table/change_request?sysparm_query=number%3D$T_SHAPE" '.result | length == 1 and (.[0] | has("approvals") | not)'
check "mock: sysapproval_approver serves one row per approver, ServiceNow's dot-walked fields and stored states" \
  api_json "$PORT" "/api/now/v2/table/sysapproval_approver?sysparm_query=sysapproval.number%3D$T_SHAPE&sysparm_fields=approver.user_name,state" \
  '.result == [{"approver.user_name": "ops-carol", "state": "approved"}, {"approver.user_name": "ops-dana", "state": "requested"}]'
check "mock: Table API v2 with no match -> 200 and an empty result" \
  api_json "$PORT" "/api/now/v2/table/sysapproval_approver?sysparm_query=sysapproval.number%3DCHG0999999" '.result == []'
check "mock: Table API v1 with no match -> 404 (why the broker pins v2)" \
  api_code "$PORT" "/api/now/v1/table/change_request?sysparm_query=number%3DCHG0999999" 404
check "mock: ITSM_FAIL_TABLES makes the approvals table answer 500 (fault injection for the fail-closed check)" \
  api_code "$FPORT" "/api/now/v2/table/sysapproval_approver?sysparm_query=sysapproval.number%3D$T_SHAPE" 500

# --- Tier 0: dual control ------------------------------------------------------------------
T=$(ticket ops-alice --approver ops-carol --approver ops-dana)
check "tier0: two distinct authorised approvers (carol + dana), neither the requester -> accepted" \
  accepted "approved by ops-carol + ops-dana (2 of 2 required: dual control" "$T" ops-alice tier0 tier0-admins
check "... and the approvers handed to the audit line / token metadata are exactly ops-carol,ops-dana" approvers_line ops-carol,ops-dana
T=$(ticket ops-alice --approver ops-alice --approver ops-carol)
check "tier0: SELF-APPROVAL (alice approves her own change) does not count -> refused" \
  refused "ops-alice (self-approval: the operator asking)" "$T" ops-alice tier0 tier0-admins
check "... and says so: 1 of 2 required approvals" said "has 1 of 2 required approvals"
T=$(ticket ops-alice --approver ops-carol)
check "tier0: a SINGLE approver -> refused (1 of 2, dual control)" \
  refused "has 1 of 2 required approvals (tier0 dual control: 2 distinct approvers, none of them the requester)" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --approver ops-carol --approver ops-carol)
check "tier0: the SAME approver twice counts once -> refused (1 of 2)" \
  refused "has 1 of 2 required approvals" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --approver ops-carol --approver ops-bob)
check "tier0: an approver without the Safe right (ops-bob approves tier1/linux only) -> refused" \
  refused "ops-bob (not an authorized approver for tier0-admins)" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --requested-by ops-dana --approver ops-dana --approver ops-carol)
check "tier0: the change's REQUESTER (requested_by ops-dana) approving it does not count -> refused" \
  refused "ops-dana (self-approval: the change's requester)" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --approver ops-carol --approver ops-dana:requested)
check "tier0: one approved + one still pending -> refused (1 of 2)" \
  refused "has 1 of 2 required approvals" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --approver ops-carol --approver ops-dana --approver ops-bob:rejected)
check "tier0: two approvals but one REJECTION on the change -> refused (a rejection stops it)" \
  refused "was rejected by ops-bob" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --approver ops-alice --approver ops-carol --approver ops-dana)
check "tier0: a self-approval next to two valid ones neither counts nor blocks -> accepted (2 of 2)" \
  accepted "approved by ops-carol + ops-dana (2 of 2" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice)
check "tier0: no approver records at all (the change's approval field alone is not enough) -> refused (0 of 2)" \
  refused "has 0 of 2 required approvals" "$T" ops-alice tier0 tier0-admins
T_OK=$(ticket ops-alice --approver ops-carol --approver ops-dana)
T_SELF_C=$(ticket ops-carol --approver ops-carol --approver ops-dana)
check "tier0: carol requesting with her own approval + dana -> refused (self-approval, 1 of 2)" \
  refused "ops-carol (self-approval: the operator asking)" "$T_SELF_C" ops-carol tier0 tier0-admins
T=$(ticket ops-carol --approver ops-alice --approver ops-dana)
check "tier0: carol's change approved by alice + dana -> accepted (peers approve each other, never themselves)" \
  accepted "approved by ops-alice + ops-dana (2 of 2" "$T" ops-carol tier0 tier0-admins

# --- fail closed --------------------------------------------------------------------------
pf() { local f; f=$(policy_with "$1"); POLICY_FILE="$f"; }
pf 'del(.tiers.tier0.approvals_required)'
check "policy WITHOUT tier0.approvals_required -> refused, not 'no approvals needed' (fail closed)" \
  refused "approvals_required must be a whole number >= 1" "$T_OK" ops-alice tier0 tier0-admins
pf '.tiers.tier0.approvals_required = 0'
check "approvals_required = 0 -> refused (fail closed)" refused "must be a whole number >= 1" "$T_OK" ops-alice tier0 tier0-admins
pf '.tiers.tier0.approvals_required = "2"'
check "approvals_required = \"2\" (a string) -> refused (fail closed)" refused "must be a whole number >= 1" "$T_OK" ops-alice tier0 tier0-admins
pf '.tiers.tier0.approvals_required = 1.5'
check "approvals_required = 1.5 -> refused (fail closed)" refused "must be a whole number >= 1" "$T_OK" ops-alice tier0 tier0-admins
POLICY_FILE=pam-policy.json
check "itsm_validate without TIER/SAFE (an old two-argument call) -> refused" \
  refused "needs TICKET OPERATOR TIER SAFE" "$T_OK" ops-alice
ITSM_URL="http://127.0.0.1:$FPORT"
check "the approvals table answers HTTP 500 -> refused (no check-out without the approval records)" \
  refused "its approval records could not be read" "$T_OK" ops-alice tier0 tier0-admins
ITSM_URL="http://127.0.0.1:$PORT"
check "control: the same ticket on the healthy mock -> accepted" accepted "2 of 2" "$T_OK" ops-alice tier0 tier0-admins

# --- Tier 1: one approver ----------------------------------------------------------------
T=$(ticket ops-alice --approver ops-bob)
check "tier1: ONE authorised approver (bob, linux-admin) -> accepted (1 of 1)" \
  accepted "approved by ops-bob (1 of 1 required: 1 approver, not the requester)" "$T" ops-alice tier1 linux-admin
T=$(ticket ops-alice)
check "tier1: no approver -> refused (0 of 1)" refused "has 0 of 1 required approvals" "$T" ops-alice tier1 linux-admin
T=$(ticket ops-bob --approver ops-bob)
check "tier1: SELF-APPROVAL (bob approves his own SSH change) -> refused" \
  refused "ops-bob (self-approval: the operator asking)" "$T" ops-bob tier1 linux-admin
T=$(ticket ops-alice --approver ops-carol)
check "tier1: an approver without the linux-admin approve right (carol) -> refused" \
  refused "ops-carol (not an authorized approver for linux-admin)" "$T" ops-alice tier1 linux-admin
T=$(ticket ops-bob --approver ops-dana --approver ops-alice)
check "tier1: dana approves and alice (no linux-admin right) too -> accepted on dana's approval alone (1 of 1)" \
  accepted "approved by ops-dana (1 of 1" "$T" ops-bob tier1 linux-admin

# --- the older gates still hold, before any approval is looked at ---------------------------
T=$(ticket ops-alice --approval requested --approver ops-carol --approver ops-dana)
check "a change awaiting approval -> refused (not approved), whatever its approver rows say" refused "is not approved" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --state scheduled --approver ops-carol --approver ops-dana)
check "an approved change still in Scheduled -> refused (not in Implement)" refused "is not in Implement" "$T" ops-alice tier0 tier0-admins
T=$(ticket ops-alice --start-in-hours -10 --hours 2 --approver ops-carol --approver ops-dana)
check "an expired window -> refused" refused "is outside its window" "$T" ops-alice tier0 tier0-admins
check "someone else's dual-approved change (alice's, used by carol) -> refused" \
  refused "is assigned to 'ops-alice', not ops-carol" "$T_OK" ops-carol tier0 tier0-admins
check "a change ITSM does not know -> refused" refused "not found in ITSM" CHG0999999 ops-alice tier0 tier0-admins
check "not a change number -> refused" refused "is not a change number" INC0010001 ops-alice tier0 tier0-admins

# --- wiring: the brokers ask with their own tier and Safe -----------------------------------
check "psm-session.sh validates as tier0 / tier0-admins (dual control)" \
  static_has psm-session.sh 'itsm_validate "$TICKET" "$OPERATOR" "$TIER" "$LIBRARY"'
check "psm-ssh.sh validates as tier1 / linux-admin" static_has psm-ssh.sh 'itsm_validate "$TICKET" "$OPERATOR" "$TIER" "$ROLE"'
check "pam-policy.json: tier0 approvals_required = 2, tier1 = 1" policy_counts_ok
check "every ticket this run raised is a distinct change ($(jq length "$PAM_ITSM_TICKETS") in the mock)" tickets_distinct
check "itsm-ticket.sh refuses an invalid approver name" bash -c '! ./itsm-ticket.sh add CHG4999999 --operator ops-alice --approver "Bad Name" >/dev/null 2>&1'

printf '\n'
if [[ $FAILS -eq 0 ]]; then log "ITSM DUAL-CONTROL TESTS PASSED"; exit 0; fi
log "ITSM DUAL-CONTROL TESTS FAILED: $FAILS"
exit 1
