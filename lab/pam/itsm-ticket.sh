#!/usr/bin/env bash
# =============================================================================
# itsm-ticket.sh - raise change tickets in the LOCAL ServiceNow mock
# (itsm-mock service), so ticket-gated check-out can be demonstrated and
# tested without a ServiceNow instance. STAND-IN: at tenant time the change
# is raised and approved in the ServiceNow PDI and this script is not used.
#
#   add CHG####### --operator NAME [--requested-by NAME]
#                  [--approver NAME[:STATE]]...   (repeatable; STATE approved
#                                                  (default), requested, rejected)
#                  [--approval approved|requested|rejected]
#                  [--state implement|scheduled|authorize|review|closed|canceled]
#                  [--hours N] [--start-in-hours N] [--short "text"]
#       defaults: requested by the operator, no approver records, change
#       approval approved, state implement, window now-5min .. now+4h
#   approve CHG####### --by NAME [--state approved|requested|rejected]
#       one approver acts on an existing change (replaces that person's record)
#   list | remove CHG####### | next
#
# DUAL CONTROL: the broker counts approver records (ServiceNow table
# sysapproval_approver), not the change's approval field alone. A Tier-0
# check-out needs two distinct approvers, neither of them the requester, both
# allowed to approve for the Safe in operators.json (`approves`); Tier 1 needs
# one (pam-policy.json approvals_required; lib.sh itsm_validate). Example:
#   ./itsm-ticket.sh add CHG0040001 --operator ops-alice --approver ops-carol --approver ops-dana
#
# Records use ServiceNow's stored values (state -1 = Implement, dates in UTC
# "YYYY-MM-DD HH:MM:SS"), the same fields psm-session.sh asks the Table API
# for. Writes itsm/data/tickets.json atomically (PAM_ITSM_TICKETS overrides
# the path: test/itsm-dual-control.test.sh only); the mock re-reads it on
# every request.
# =============================================================================
source "$(dirname "$0")/lib.sh"
need jq
DATA="${PAM_ITSM_TICKETS:-itsm/data/tickets.json}"
if [[ -z "${PAM_ITSM_TICKETS:-}" ]]; then mkdir -p itsm/data && chmod 755 itsm itsm/data; fi
[[ -f "$DATA" ]] || { echo '[]' > "$DATA"; chmod 644 "$DATA"; }

save() { # save < JSON : atomic replace, world-readable for the mock's uid (public lab data)
  local tmp
  tmp=$(mktemp "$(dirname "$DATA")/tickets.XXXXXX")
  cat > "$tmp" && chmod 644 "$tmp" && mv "$tmp" "$DATA"
}

valid_name() { # the same rule as operators.json keys (lib.sh operator_allowed)
  [[ "$1" =~ ^[a-z][a-z0-9._@-]{1,63}$ ]] || die "'$1' is not a valid user name (lowercase, 2-64 chars: a-z 0-9 . _ @ -)"
}

approval_state() {
  case "$1" in approved|requested|rejected) printf '%s' "$1" ;; *) die "unknown approval state '$1' (approved|requested|rejected)" ;; esac
}

state_code() {
  case "$1" in
    implement) echo -1 ;; scheduled) echo -2 ;; authorize) echo -3 ;; assess) echo -4 ;;
    new) echo -5 ;; review) echo 0 ;; closed) echo 3 ;; canceled) echo 4 ;;
    *) die "unknown state '$1'" ;;
  esac
}

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
case "$cmd" in
  add)
    num="${1:-}"; [[ $# -gt 0 ]] && shift
    [[ "$num" =~ ^CHG[0-9]{7}$ ]] || die "usage: $0 add CHG####### --operator NAME [...]"
    op="" reqby="" approval=approved st=implement hours=4 startin=0 short="Privileged access window"
    approvers='[]'
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --operator) op="$2"; shift 2 ;;
        --requested-by) reqby="$2"; shift 2 ;;
        --approver)
          a="${2%%:*}"; as=approved; [[ "$2" == *:* ]] && as="${2#*:}"
          valid_name "$a"; as=$(approval_state "$as")
          approvers=$(printf '%s' "$approvers" | jq -c --arg u "$a" --arg s "$as" '. + [{user_name: $u, state: $s}]')
          shift 2 ;;
        --approval) approval="$2"; shift 2 ;;
        --state) st="$2"; shift 2 ;;
        --hours) hours="$2"; shift 2 ;;
        --start-in-hours) startin="$2"; shift 2 ;;
        --short) short="$2"; shift 2 ;;
        *) die "unknown option $1" ;;
      esac
    done
    [[ -n "$op" ]] || die "--operator NAME is required (the change is assigned to one person)"
    valid_name "$op"; reqby="${reqby:-$op}"; valid_name "$reqby"
    code=$(state_code "$st")
    now=$(date -u +%s)
    # The window opens 5 minutes before "now + start-in" so a ticket made for
    # "now" is valid immediately despite clock skew between host and mock.
    jq --arg n "$num" --arg o "$op" --arg r "$reqby" --arg a "$approval" --arg s "$code" --arg d "$short" \
       --argjson now "$now" --argjson h "$hours" --argjson startin "$startin" --argjson ap "$approvers" '
      ($now + $startin * 3600 - 300) as $start | ($start + 300 + $h * 3600) as $end
      | map(select(.number != $n)) + [{
          table: "change_request", number: $n, state: $s, approval: $a,
          start_date: ($start | strftime("%Y-%m-%d %H:%M:%S")),
          end_date: ($end | strftime("%Y-%m-%d %H:%M:%S")),
          "assigned_to.user_name": $o, "requested_by.user_name": $r, short_description: $d,
          approvals: [$ap[] | . + {at: ($now | strftime("%Y-%m-%d %H:%M:%S"))}] }]' "$DATA" | save
    jq -r --arg n "$num" '.[] | select(.number == $n) | "\(.number) \(.approval) state=\(.state) \(.start_date) -> \(.end_date) UTC, assigned to \(."assigned_to.user_name"), requested by \(."requested_by.user_name"), approvers: \([(.approvals // [])[] | "\(.user_name)=\(.state)"] | if length == 0 then "none" else join(" ") end)"' "$DATA"
    ;;
  approve)
    num="${1:-}"; [[ $# -gt 0 ]] && shift
    [[ "$num" =~ ^CHG[0-9]{7}$ ]] || die "usage: $0 approve CHG####### --by NAME [--state approved|requested|rejected]"
    by="" as=approved
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --by) by="$2"; shift 2 ;;
        --state) as="$2"; shift 2 ;;
        *) die "unknown option $1" ;;
      esac
    done
    [[ -n "$by" ]] || die "approve needs --by NAME (the approver)"
    valid_name "$by"; as=$(approval_state "$as")
    jq -e --arg n "$num" 'any(.[]; .number == $n)' "$DATA" >/dev/null || die "no change $num in $DATA"
    jq --arg n "$num" --arg u "$by" --arg s "$as" --arg t "$(date -u '+%Y-%m-%d %H:%M:%S')" '
      map(if .number == $n
          then .approvals = ([(.approvals // [])[] | select(.user_name != $u)] + [{user_name: $u, state: $s, at: $t}])
          else . end)' "$DATA" | save
    log "$num: $by -> $as"
    ;;
  list)
    jq -r '.[] | "\(.number)  \(.approval)  state=\(.state)  \(.start_date) -> \(.end_date)  \(."assigned_to.user_name")  approvers: \([(.approvals // [])[] | "\(.user_name)=\(.state)"] | if length == 0 then "none" else join(",") end)  \(.short_description)"' "$DATA"
    ;;
  remove)
    [[ -n "${1:-}" ]] || die "usage: $0 remove CHG#######"
    jq --arg n "$1" 'map(select(.number != $n))' "$DATA" | save
    ;;
  next)
    jq -r '[.[].number | ltrimstr("CHG") | tonumber] | (max // 40000) + 1 | "CHG\(. | tostring | ("0000000" + .)[-7:])"' "$DATA"
    ;;
  *) die "usage: $0 add CHG####### --operator NAME [--approver NAME]... [...] | approve CHG####### --by NAME | list | remove CHG####### | next" ;;
esac
