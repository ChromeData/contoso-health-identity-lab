#!/usr/bin/env bash
# =============================================================================
# psm-session.sh - the brokered, recorded session pattern with Vault + Guacamole,
# ticket-gated and attributed to ONE named person per session.
#
#   checkout --operator NAME --ticket CHG####### [--target dc01|rdp-target]
#     1. NAME must be in operators.json with tier0-admins among its libraries
#        (who may check out what).
#     2. The ticket must be an APPROVED change, in Implement, inside its window
#        and ASSIGNED TO NAME (ServiceNow Table API v2; the itsm-mock service
#        locally, a ServiceNow PDI at tenant time: README, "Ticket validation"),
#        and Tier 0 is under DUAL CONTROL: two distinct approvers on the change
#        (ServiceNow approval records), neither of them NAME nor the change's
#        requester, each allowed to approve for tier0-admins in operators.json
#        (pam-policy.json tier0 approvals_required = 2; lib.sh itsm_validate).
#     3. NAME gets their own Guacamole user (lab: created on first use, local
#        password in .secrets/operators/NAME-password; OIDC mode - PAM_OIDC=1
#        or OIDC_CLIENT_ID in .env - the record must come from NAME's first
#        Entra sign-in and any local password on it is destroyed, README
#        "Per-person sign-in"). The shared t0-operator is gone.
#     4. A per-check-out Vault token (policy tier0-checkout, display name
#        psm-NAME, metadata operator + ticket) checks out the next free Tier-0
#        admin, so Vault's OWN audit log names the person and the ticket.
#     5. The password goes straight into that account's recorded RDP
#        connection ("DC01 - <account> (recorded)"); NAME gets READ on that one
#        connection: enough to connect, not to read its parameters.
#        --target rdp-target (harness only) points the connection at the
#        Linux xrdp STAND-IN instead of DC01 ("RDP-TARGET (Linux xrdp stand-in
#        for DC01) - <account> (recorded)"): the same AD account, checked by
#        Kerberos against the Samba AD DC, so the brokered + recorded RDP path
#        runs without a tenant (lib.sh rdp_conn_name; rdp-target/).
#   checkin [ACCOUNT] [--operator NAME]
#     Same token checks the account back in (Vault enforces that only the
#     check-out's token may), Vault ROTATES the password, the connection is
#     wiped, NAME's READ is revoked and the token revoked. Recording stays in
#     Guacamole -> Settings -> History (as guacadmin).
#   status
#
# Every step writes one JSON line to out/pam-audit.jsonl (who, which account,
# which ticket, which connection) - and prints it.
#
# Lab limit: guacadmin (this script's API identity, History playback) can still
# read the stored password, which sits in guac-db until check-in. Production
# PSM fetches it from the vault when the session starts.
#
# Usage: ./psm-session.sh checkout --operator NAME --ticket CHG####### [--target dc01|rdp-target]
#        ./psm-session.sh checkin [ACCOUNT] [--operator NAME]
#        ./psm-session.sh status
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq; need curl; need openssl
load_env
[[ -n "${DC_PUBLIC_IP:-}" ]] || die "run ./vault-onboard-ad.sh first"
vault_unseal

STATE=.secrets/psm-checkout.json   # { "<account>": { checked_out_at, operator, ticket, approvers, target } }
TOKENS=.secrets/psm-tokens         # per-check-out Vault token, one file per account (0600)
LIBRARY=tier0-admins
TIER=tier0
NETBIOS="${NETBIOS:-CORP}"

state() { # current check-outs as a JSON object (upgrades the old single-account file)
  if [[ -s "$STATE" ]]; then
    jq 'if has("account") then {(.account): {checked_out_at}} else . end' "$STATE"
  else
    echo '{}'
  fi
}

save_state() { # save_state < JSON
  cat > "$STATE.tmp"
  if [[ "$(jq length "$STATE.tmp")" -eq 0 ]]; then rm -f "$STATE" "$STATE.tmp"; else mv "$STATE.tmp" "$STATE"; fi
}

# upsert_connection ACCOUNT [TARGET]: printf '%s' PASSWORD | ... (empty stdin wipes it)
# TARGET dc01 (default): DC01 over NLA with the NetBIOS domain. TARGET
# rdp-target: the Linux xrdp stand-in on the compose network, TLS (xrdp has no
# NLA), no domain (Kerberos realm is the target's own config). Both recorded
# the same way: ${HISTORY_PATH}/${HISTORY_UUID}/recording, which is where the
# History page's player looks.
upsert_connection() {
  local name tok id target="${2:-dc01}" host sec dom
  name=$(rdp_conn_name "$target" "$1")
  case "$target" in
    dc01)       host="$DC_PUBLIC_IP"; sec=nla; dom="$NETBIOS" ;;
    rdp-target) host=rdp-target; sec=tls; dom="" ;;
  esac
  tok=$(guac_admin_token)
  id=$(guac_conn_id "$tok" "$name")
  # Password: stdin -> jq (-Rs) -> curl body on stdin (-d @-). Never in argv.
  jq -Rs --arg i "$id" --arg n "$name" --arg h "$host" --arg u "$1" --arg d "$dom" --arg sec "$sec" '
    (if $i == "" then {} else {identifier: $i} end) + {
    parentIdentifier: "ROOT", name: $n, protocol: "rdp", attributes: {},
    parameters: ({
      hostname: $h, port: "3389", username: $u, password: .,
      security: $sec, "ignore-cert": "true",
      "recording-path": "${HISTORY_PATH}/${HISTORY_UUID}",
      "create-recording-path": "true"
    } + (if $d == "" then {} else {domain: $d} end))}' \
  | if [[ -n "$id" ]]; then
      curl -fsS -X PUT -H "Guacamole-Token: $tok" -H 'Content-Type: application/json' \
        "$GUAC_URL/api/session/data/postgresql/connections/$id" -d @- >/dev/null
    else
      curl -fsS -X POST -H "Guacamole-Token: $tok" -H 'Content-Type: application/json' \
        "$GUAC_URL/api/session/data/postgresql/connections" -d @- >/dev/null
    fi
}

conn_id_of() { guac_conn_id "$(guac_admin_token)" "$(rdp_conn_name "${2:-dc01}" "$1")"; }   # ACCOUNT [TARGET]

revoke_token_file() { # revoke_token_file FILE : revoke the token held in FILE (sent in the body), delete FILE
  [[ -s "$1" ]] || { rm -f "$1"; return 0; }
  jq -Rs '{token: (. | rtrimstr("\n"))}' < "$1" \
    | VAULT_TOKEN="$(root_token)" vault_api POST auth/token/revoke >/dev/null 2>&1 \
    || log "could not revoke the check-out token in $1 (it expires on its own TTL)"
  rm -f "$1"
}

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
OPERATOR="" TICKET="" ACCT="" TARGET=dc01
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator) OPERATOR="$2"; shift 2 ;;
    --ticket) TICKET="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    -*) die "unknown option $1" ;;
    *) ACCT="$1"; shift ;;
  esac
done

case "$cmd" in
  checkout)
    [[ -n "$OPERATOR" ]] || die "checkout needs --operator NAME: every session belongs to one person (operators.json)"
    operator_allowed "$OPERATOR" libraries "$LIBRARY"
    # Fail closed: only an explicit `false` in pam-policy.json skips the
    # ticket (policy_flag dies on a missing / mistyped key or a broken file).
    rdp_target_ok "$TARGET" || die "unknown --target '$TARGET' (dc01 | rdp-target)"
    require_ticket=$(policy_flag "$TIER" require_ticket) || exit 1
    APPROVERS=none
    if [[ "$require_ticket" != false ]]; then
      [[ -n "$TICKET" ]] || die "checkout needs --ticket CHG####### (pam-policy.json: $TIER require_ticket=true)"
      # Ticket + dual control (two distinct approvers, neither the requester).
      verdict=$(itsm_validate "$TICKET" "$OPERATOR" "$TIER" "$LIBRARY")
      log "Ticket OK: $(printf '%s\n' "$verdict" | sed -n 1p)"
      APPROVERS=$(printf '%s\n' "$verdict" | sed -n 2p)
      [[ -n "$APPROVERS" ]] || die "ticket validation returned no approvers"
    fi
    ensure_guac_operator "$OPERATOR"   # before Vault: a Guacamole problem must not strand an account

    # Per-check-out token: Vault's audit log records display_name psm-<op> and
    # the metadata on the check-out itself. TTL = the library's max_ttl, so
    # the same token can always check the account back in.
    mkdir -p "$TOKENS" && chmod 700 "$TOKENS"
    tokfile=$(mktemp "$TOKENS/pending.XXXXXX")
    jq -n --arg o "$OPERATOR" --arg t "${TICKET:-none}" --arg a "$APPROVERS" \
      '{policies: ["tier0-checkout"], no_default_policy: true, ttl: "4h", renewable: false,
        display_name: ("psm-" + $o), meta: {operator: $o, ticket: $t, approvers: $a, library: "tier0-admins"}}' \
      | VAULT_TOKEN="$(root_token)" vault_api POST auth/token/create | jq -j '.auth.client_token' > "$tokfile" \
      || { rm -f "$tokfile"; die "could not mint the check-out token"; }

    # stdout carries the password (JSON), so Vault's error goes to a file:
    # only "pool exhausted" is reported as such, anything else as itself.
    err=$(mktemp .secrets/psm-err.XXXXXX)
    if ! out=$(VAULT_TOKEN="$(cat "$tokfile")" vault_cli write -format=json "ldap/library/$LIBRARY/check-out" ttl=1h 2>"$err"); then
      revoke_token_file "$tokfile"
      if grep -q 'No service accounts available' "$err"; then
        rm -f "$err"
        audit_line checkout-refused operator="$OPERATOR" ticket="${TICKET:-none}" approvers="$APPROVERS" reason="pool exhausted"
        die "no Tier-0 account available - both are checked out ($0 status)"
      fi
      cat "$err" >&2; rm -f "$err"; die "Vault check-out failed (see above)"
    fi
    rm -f "$err"
    # printf | jq, not <<<: bash 3.2 backs here-strings with a temp file.
    acct=$(printf '%s' "$out" | jq -r '.data.service_account_name // empty')
    [[ -n "$acct" ]] || { revoke_token_file "$tokfile"; die "Vault check-out returned no service_account_name"; }
    mv "$tokfile" "$TOKENS/$acct"
    # Record first: if the Guacamole step fails, `checkin` can still return it.
    state | jq --arg a "$acct" --arg t "$(date -u +%FT%TZ)" --arg o "$OPERATOR" --arg k "${TICKET:-none}" \
      --arg ap "$APPROVERS" --arg tg "$TARGET" \
      '. + {($a): {checked_out_at: $t, operator: $o, ticket: $k, approvers: $ap, target: $tg}}' | save_state
    printf '%s' "$out" | jq -j '.data.password' | upsert_connection "$acct" "$TARGET"
    out=""
    cname=$(rdp_conn_name "$TARGET" "$acct")
    id=$(conn_id_of "$acct" "$TARGET")
    [[ -n "$id" ]] || die "no Guacamole connection '$cname' after injection"
    guac_grant "$OPERATOR" "$id" add
    audit_line checkout operator="$OPERATOR" ticket="${TICKET:-none}" approvers="$APPROVERS" account="$acct" library="$LIBRARY" \
      target="$TARGET" connection="$cname" vault_display_name="token-psm-$OPERATOR"
    log "Checked out $acct for $OPERATOR (exclusive, 1h). Password injected into Guacamole - not displayed."
    [[ "$TARGET" == dc01 ]] || log "Target: $TARGET - the Linux xrdp STAND-IN for an RDP session to DC01 (harness only)."
    log "$(operator_signin_hint "$OPERATOR") -> '$cname'. The session is recorded."
    ;;
  checkin)
    open=$(state | jq -r 'keys[]')
    acct="$ACCT"
    if [[ -z "$acct" ]]; then
      [[ -n "$open" ]] || die "nothing checked out"
      [[ $(wc -l <<<"$open") -eq 1 ]] || die "several accounts checked out ($(paste -sd, - <<<"$open")) - name one: $0 checkin <account>"
      acct="$open"
    fi
    grep -qx -- "$acct" <<<"$open" || die "$acct is not checked out by this broker (open: ${open:-none})"
    owner=$(state | jq -r --arg a "$acct" '.[$a].operator // ""')
    ticket=$(state | jq -r --arg a "$acct" '.[$a].ticket // "none"')
    target=$(state | jq -r --arg a "$acct" '.[$a].target // "dc01"')
    rdp_target_ok "$target" || die "$STATE names an unknown target '$target' for $acct"
    if [[ -n "$OPERATOR" && -n "$owner" && "$OPERATOR" != "$owner" ]]; then
      die "$acct is checked out by $owner, not $OPERATOR"
    fi
    if [[ -s "$TOKENS/$acct" ]]; then
      VAULT_TOKEN="$(cat "$TOKENS/$acct")" vault_cli write "ldap/library/$LIBRARY/check-in" service_account_names="$acct" >/dev/null
    else
      # Check-outs made before per-person tokens (or a lost token file): the
      # privileged manage endpoint returns it, as an administrator would.
      log "No check-out token for $acct - using ldap/library/manage (administrative check-in)"
      VAULT_TOKEN="$(root_token)" vault_cli write "ldap/library/manage/$LIBRARY/check-in" service_account_names="$acct" >/dev/null
    fi
    upsert_connection "$acct" "$target" </dev/null
    id=$(conn_id_of "$acct" "$target")
    if [[ -n "$owner" && -n "$id" ]]; then guac_grant "$owner" "$id" remove; fi
    revoke_token_file "$TOKENS/$acct"
    state | jq --arg a "$acct" 'del(.[$a])' | save_state
    audit_line checkin operator="${owner:-unknown}" by="${OPERATOR:-${owner:-unknown}}" ticket="$ticket" account="$acct" \
      library="$LIBRARY" target="$target" rotated=on-check-in
    log "Checked in $acct - Vault rotated its password; ${owner:-the operator}'s access revoked. Recording: Guacamole (guacadmin) -> Settings -> History."
    ;;
  status)
    VAULT_TOKEN="$(root_token)" vault_cli read -format=json "ldap/library/$LIBRARY/status" \
      | jq -r '.data | to_entries[] | "\(.key): available=\(.value.available)"'
    state | jq -r 'to_entries[] | "  \(.key): checked out by \(.value.operator // "?") at \(.value.checked_out_at) (ticket \(.value.ticket // "-"), approved by \(.value.approvers // "-"), target \(.value.target // "dc01"))"'
    ;;
  *) die "usage: $0 checkout --operator NAME --ticket CHG####### [--target dc01|rdp-target] | checkin [account] [--operator NAME] | status" ;;
esac
