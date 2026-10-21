#!/usr/bin/env bash
# =============================================================================
# psm-ssh.sh - brokered, recorded SSH with an EPHEMERAL Vault-signed
# certificate (CyberArk: PSM for SSH / PSMP + SSH Key Manager; the pattern
# behind "zero standing access" to Linux).
#
#   setup     Vault SSH secrets engine as a user CA (ssh-client-signer), role
#             linux-admin (principal linux-admin, 10 min certificates, pty
#             only, key ID = the requesting token's display name), Vault
#             policy ssh-linux-admin, then the ssh-target container (trusts
#             only that CA) and the Guacamole connection
#             "LINUX - ssh-target (recorded)": graphical recording + text
#             typescript, host key pinned.
#   checkout --operator NAME --ticket CHG#######
#             NAME must hold ssh_roles linux-admin in operators.json; the
#             ticket is validated like psm-session.sh (tier1 policy: ONE
#             approver on the change, not the requester, allowed to approve
#             for linux-admin in operators.json; Tier 0 needs two). A fresh
#             key pair is generated, Vault signs it with a per-session token
#             (display name psm-NAME), and key + certificate go straight into
#             the Guacamole connection - the operator never holds either.
#             NAME gets READ on that one connection. The certificate dies in
#             10 minutes whatever happens next.
#   checkin [--operator NAME]
#             Wipes key + certificate from the connection, revokes READ and
#             the token. Typescript + recording stay in the guac-recordings
#             volume (Settings -> History as guacadmin).
#   status
#
# sshd on the target logs every login with the certificate's key ID and
# serial, so the target's own log names the person (verify: OpenSSH log
# format "Accepted publickey ... ID <key id> (serial N) CA ...").
#
# Usage: ./psm-ssh.sh setup | checkout --operator NAME --ticket CHG####### | checkin [--operator NAME] | status
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq; need curl; need ssh-keygen
load_env
vault_unseal

MOUNT=ssh-client-signer
ROLE=linux-admin
TIER=tier1
CONN="LINUX - ssh-target (recorded)"
STATE=.secrets/psm-ssh.json
WORK=.secrets/psm-ssh

conn_id() { guac_conn_id "$(guac_admin_token)" "$CONN"; }

upsert_ssh_connection() { # upsert_ssh_connection [PRIVATE_KEY_FILE CERT_FILE]  (no args: wipe credentials)
  local tok id hostkey
  tok=$(guac_admin_token)
  id=$(guac_conn_id "$tok" "$CONN")
  # Pin the target's host key (a known_hosts line): guacd refuses a server
  # that presents anything else, instead of trusting on first use.
  hostkey=$(docker compose --profile ssh exec -T ssh-target cat /etc/ssh/ssh_host_ed25519_key.pub </dev/null | awk '{print "ssh-target " $1 " " $2}')
  [[ -n "$hostkey" ]] || die "could not read ssh-target's host key (./psm-ssh.sh setup)"
  # Private key and certificate: files -> jq --rawfile -> curl body on stdin.
  jq -n --arg i "$id" --arg n "$CONN" --arg hk "$hostkey" \
     --rawfile pk "${1:-/dev/null}" --rawfile cert "${2:-/dev/null}" '
    (if $i == "" then {} else {identifier: $i} end) + {
    parentIdentifier: "ROOT", name: $n, protocol: "ssh", attributes: {},
    parameters: {
      hostname: "ssh-target", port: "22", username: "labadmin",
      "host-key": $hk,
      "private-key": $pk, "public-key": ($cert | rtrimstr("\n")),
      "recording-path": "${HISTORY_PATH}/${HISTORY_UUID}", "create-recording-path": "true",
      "typescript-path": "${HISTORY_PATH}/${HISTORY_UUID}", "create-typescript-path": "true",
      "typescript-name": "typescript"
    }}' \
  | if [[ -n "$id" ]]; then
      curl -fsS -X PUT -H "Guacamole-Token: $tok" -H 'Content-Type: application/json' \
        "$GUAC_URL/api/session/data/postgresql/connections/$id" -d @- >/dev/null
    else
      curl -fsS -X POST -H "Guacamole-Token: $tok" -H 'Content-Type: application/json' \
        "$GUAC_URL/api/session/data/postgresql/connections" -d @- >/dev/null
    fi
}

revoke_token() { # revoke_token TOKEN (in the request body, never argv)
  [[ -n "$1" ]] || return 0
  jq -n --arg t "$1" '{token: $t}' | VAULT_TOKEN="$(root_token)" vault_api POST auth/token/revoke >/dev/null 2>&1 \
    || log "could not revoke the session token (it expires on its TTL)"
}

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
OPERATOR="" TICKET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator) OPERATOR="$2"; shift 2 ;;
    --ticket) TICKET="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done

case "$cmd" in
  setup)
    export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"
    if ! vault_api GET sys/mounts | jq -e --arg m "$MOUNT/" 'has($m)' >/dev/null; then
      log "Enabling the Vault SSH secrets engine at $MOUNT/ (user certificate authority)"
      jq -n '{type: "ssh", description: "SSH user CA - PSM for SSH stand-in"}' | vault_api POST "sys/mounts/$MOUNT" >/dev/null
    fi
    if ! vault_api GET "$MOUNT/config/ca" >/dev/null 2>&1; then
      # Ed25519 CA key generated INSIDE Vault: the private half never leaves it.
      jq -n '{generate_signing_key: true, key_type: "ed25519"}' | vault_api POST "$MOUNT/config/ca" >/dev/null
      log "Generated the SSH CA signing key (ed25519, inside Vault)"
    fi
    # Short-lived, one principal, pty only (no port/agent/X11 forwarding),
    # key ID = token display name + role: the operator's name ends up in the
    # certificate and therefore in sshd's log on the target.
    jq -n '{key_type: "ca", allow_user_certificates: true, allowed_users: "linux-admin",
            default_user: "linux-admin", ttl: "10m", max_ttl: "30m",
            allowed_extensions: "permit-pty", default_extensions: {"permit-pty": ""},
            key_id_format: "{{token_display_name}}-{{role_name}}"}' \
      | vault_api POST "$MOUNT/roles/$ROLE" >/dev/null
    jq -Rs '{policy: .}' <<'HCL' | vault_api PUT sys/policies/acl/ssh-linux-admin >/dev/null
# Sign one public key with role linux-admin - nothing else.
path "ssh-client-signer/sign/linux-admin" { capabilities = ["update"] }
HCL
    log "Role $ROLE (10 min certs, principal linux-admin) + policy ssh-linux-admin written"
    log "Starting ssh-target (trusts only this CA)"
    docker compose --profile ssh up -d --build ssh-target >/dev/null 2>&1 || docker compose --profile ssh up -d --build ssh-target
    # The target reads the CA key at start: restart it if it predates the CA.
    if ! docker compose --profile ssh exec -T ssh-target cat /etc/ssh/trusted-user-ca-keys.pem </dev/null 2>/dev/null \
         | grep -qF "$(vault_api GET "$MOUNT/config/ca" | jq -r '.data.public_key' | awk '{print $2}')"; then
      docker compose --profile ssh restart ssh-target >/dev/null
    fi
    for _ in $(seq 1 30); do
      docker compose --profile ssh exec -T ssh-target test -s /etc/ssh/trusted-user-ca-keys.pem </dev/null 2>/dev/null && break
      sleep 1
    done
    upsert_ssh_connection
    log "Guacamole connection '$CONN' ready (recorded, typescript on, host key pinned, no credentials stored)"
    ;;
  checkout)
    [[ -n "$OPERATOR" ]] || die "checkout needs --operator NAME"
    operator_allowed "$OPERATOR" ssh_roles "$ROLE"
    # Fail closed (see psm-session.sh): only an explicit `false` skips it.
    require_ticket=$(policy_flag "$TIER" require_ticket) || exit 1
    APPROVERS=none
    if [[ "$require_ticket" != false ]]; then
      [[ -n "$TICKET" ]] || die "checkout needs --ticket CHG####### (pam-policy.json: $TIER require_ticket=true)"
      verdict=$(itsm_validate "$TICKET" "$OPERATOR" "$TIER" "$ROLE")
      log "Ticket OK: $(printf '%s\n' "$verdict" | sed -n 1p)"
      APPROVERS=$(printf '%s\n' "$verdict" | sed -n 2p)
      [[ -n "$APPROVERS" ]] || die "ticket validation returned no approvers"
    fi
    [[ ! -s "$STATE" ]] || die "the SSH connection is already checked out by $(jq -r .operator "$STATE") - check it in first"
    id=$(conn_id); [[ -n "$id" ]] || die "no Guacamole connection '$CONN' - run $0 setup"
    ensure_guac_operator "$OPERATOR"

    mkdir -p "$WORK" && chmod 700 "$WORK"
    rm -f "$WORK/key" "$WORK/key.pub" "$WORK/key-cert.pub"
    # Fresh key pair per session; only lives in $WORK (0700) until injected.
    ssh-keygen -q -t ed25519 -N '' -C "psm-$OPERATOR" -f "$WORK/key"
    tok=$(jq -n --arg o "$OPERATOR" --arg t "${TICKET:-none}" --arg a "$APPROVERS" \
      '{policies: ["ssh-linux-admin"], no_default_policy: true, ttl: "15m", renewable: false,
        display_name: ("psm-" + $o), meta: {operator: $o, ticket: $t, approvers: $a, role: "linux-admin"}}' \
      | VAULT_TOKEN="$(root_token)" vault_api POST auth/token/create | jq -r '.auth.client_token')
    [[ -n "$tok" && "$tok" != null ]] || die "could not mint the signing token"
    signed=$(jq -n --rawfile k "$WORK/key.pub" '{public_key: $k, valid_principals: "linux-admin", cert_type: "user", ttl: "10m"}' \
      | VAULT_TOKEN="$tok" vault_api POST "$MOUNT/sign/$ROLE") || { revoke_token "$tok"; die "Vault refused to sign"; }
    printf '%s' "$signed" | jq -j '.data.signed_key | rtrimstr("\n")' > "$WORK/key-cert.pub"
    printf '\n' >> "$WORK/key-cert.pub"
    # Serial in DECIMAL, as sshd logs it ("ID ... (serial N)"), so the audit
    # line and the target's log can be joined; validity in UTC.
    certinfo=$(TZ=UTC ssh-keygen -L -f "$WORK/key-cert.pub")
    serial=$(printf '%s\n' "$certinfo" | sed -n 's/^ *Serial: //p')
    keyid=$(printf '%s\n' "$certinfo" | sed -n 's/^ *Key ID: "\(.*\)"$/\1/p')
    valid=$(printf '%s\n' "$certinfo" | sed -n 's/^ *Valid: //p')
    [[ -n "$serial" && -n "$keyid" ]] || { revoke_token "$tok"; die "Vault returned a certificate ssh-keygen cannot read"; }
    upsert_ssh_connection "$WORK/key" "$WORK/key-cert.pub"
    rm -f "$WORK/key" "$WORK/key.pub" "$WORK/key-cert.pub"
    revoke_token "$tok"   # signing done; the certificate carries its own expiry
    guac_grant "$OPERATOR" "$id" add
    jq -n --arg o "$OPERATOR" --arg t "${TICKET:-none}" --arg a "$APPROVERS" --arg s "$serial" --arg k "$keyid" --arg v "$valid" --arg at "$(date -u +%FT%TZ)" \
      '{operator: $o, ticket: $t, approvers: $a, serial: $s, key_id: $k, valid: $v, checked_out_at: $at}' > "$STATE"
    audit_line ssh-checkout operator="$OPERATOR" ticket="${TICKET:-none}" approvers="$APPROVERS" connection="$CONN" cert_key_id="$keyid" cert_serial="$serial" valid="$valid"
    log "$OPERATOR may now open '$CONN' in Guacamole; certificate $keyid (serial $serial) valid $valid"
    ;;
  checkin)
    [[ -s "$STATE" ]] || die "nothing checked out"
    owner=$(jq -r .operator "$STATE")
    [[ -z "$OPERATOR" || "$OPERATOR" == "$owner" ]] || die "checked out by $owner, not $OPERATOR"
    upsert_ssh_connection
    id=$(conn_id)
    [[ -z "$id" ]] || guac_grant "$owner" "$id" remove
    audit_line ssh-checkin operator="$owner" by="${OPERATOR:-$owner}" ticket="$(jq -r .ticket "$STATE")" connection="$CONN" cert_serial="$(jq -r .serial "$STATE")"
    rm -f "$STATE"
    log "Checked in: key + certificate wiped from '$CONN', $owner's READ revoked"
    ;;
  status)
    if [[ -s "$STATE" ]]; then jq -r '"checked out by \(.operator) (ticket \(.ticket)), cert \(.key_id) serial \(.serial), valid \(.valid)"' "$STATE"; else echo "not checked out"; fi
    ;;
  *) die "usage: $0 setup | checkout --operator NAME --ticket CHG####### | checkin [--operator NAME] | status" ;;
esac
