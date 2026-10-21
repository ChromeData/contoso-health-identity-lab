#!/usr/bin/env bash
# =============================================================================
# vault-onboard-ad.sh - onboard DC01's privileged accounts into Vault
# (the CyberArk "onboard account to the vault + CPM takes over" moment).
#
#   * LDAP secrets engine -> ldaps://dc01.corp.<domain>, verified against the
#     lab root CA (no insecure_tls), bound as svc-vault-rotator whose password
#     is read from Key Vault and piped via stdin (never on a command line).
#   * STATIC role  svc-backup          -> rotated now, then every 24h   (CPM)
#   * LIBRARY set  tier0-admin-01/02   -> exclusive check-out, 1h TTL,
#                                         password rotated on every check-in
#   * Policy tier0-checkout             -> least-privilege token for psm-session.sh
#   * --rotate-root                     -> Vault rotates its OWN bind password;
#                                         afterwards only Vault knows it.
#
# Re-running (e.g. DC01 got a new public IP) is safe: against the same DC the
# bind password Vault already holds is KEPT - after --rotate-root the Key
# Vault copy is stale and writing it back would lock Vault out of AD. Use
# --reset-bindpass only after resetting svc-vault-rotator in AD + Key Vault.
#
# Steps 3-7 live in lib.sh (vault_configure_ad, vault_rotate_root) so the
# Samba AD harness (test/e2e.sh) exercises the same code without Azure.
#
# Usage: ./vault-onboard-ad.sh -k <key-vault-name> -d <corp-domain-fqdn> [-g rg] [-n vm]
#                              [--rotate-root] [--reset-bindpass]
#   e.g. ./vault-onboard-ad.sh -k kv-idlab-7f3a -d corp.contosohealthlab.com
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq; need openssl; need az

RG=rg-identity-lab VM=vm-dc01 KV="" CORP="" ROTATE_ROOT=0 RESET_BINDPASS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -k) KV="$2"; shift 2 ;;
    -d) CORP="$2"; shift 2 ;;
    -g) RG="$2"; shift 2 ;;
    -n) VM="$2"; shift 2 ;;
    --rotate-root) ROTATE_ROOT=1; shift ;;
    --reset-bindpass) RESET_BINDPASS=1; shift ;;
    *) die "unknown argument $1" ;;
  esac
done
[[ -n "$KV" && -n "$CORP" ]] || die "usage: $0 -k <key-vault> -d <corp-domain-fqdn>"

CORP=$(echo "$CORP" | tr '[:upper:]' '[:lower:]')
BASE_DN=$(echo "$CORP" | sed 's/^/DC=/; s/\./,DC=/g')
DC_FQDN="dc01.${CORP}"

# 0. Is Vault's LDAP engine already managing a DIFFERENT directory? -----------
vault_unseal
export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"
CURRENT_URL=$(vault_cli read -field=url ldap/config 2>/dev/null || true)
if [[ -n "$CURRENT_URL" && "$CURRENT_URL" != "ldaps://${DC_FQDN}" ]]; then
  # Its static role / library would be re-written WITHOUT the onboarding
  # rotation, so Vault would hand out passwords from the other directory.
  die "Vault's ldap/ engine already manages $CURRENT_URL. Remove that first (Samba harness: test/e2e.sh --cleanup)."
fi

# 1. Where is DC01, and what CA signed its LDAPS certificate? -----------------
log "Resolving DC01 public IP"
DC_IP=$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)
[[ -n "$DC_IP" ]] || die "no public IP for $VM (is it running? az vm start -g $RG -n $VM)"

log "Fetching the lab root CA certificate from DC01"
az vm run-command invoke -g "$RG" -n "$VM" --command-id RunPowerShellScript \
  --scripts @../scripts/dc/03-Get-LdapsCaCert.ps1 --query 'value[0].message' -o tsv \
  | vault_install_ca

# 2. Recreate Vault with the DC host mapping + CA, then unseal -----------------
vault_point_at_dc "$DC_FQDN" "$DC_IP"

# 3-6. LDAP engine, static role, library, policy, proof (lib.sh - the same code
#      test/e2e.sh runs against the Samba AD harness). Bind password: Key Vault
#      -> stdin, never on a command line.
if [[ -n "$CURRENT_URL" && $RESET_BINDPASS -eq 0 ]]; then
  log "Re-run against $DC_FQDN: Key Vault not read, Vault keeps its bind password"
  vault_configure_ad "$BASE_DN" "$DC_FQDN" --keep-bindpass
else
  log "Reading svc-vault-rotator's password from Key Vault (piped, not displayed)"
  az keyvault secret show --vault-name "$KV" -n svc-vault-rotator --query value -o tsv \
    | vault_configure_ad "$BASE_DN" "$DC_FQDN"
fi

# 7. Optional: Vault takes its own reconcile password ----------------------------
if [[ $ROTATE_ROOT -eq 1 ]]; then
  vault_rotate_root
  log "NOTE: the Key Vault copy of svc-vault-rotator is now STALE; delete or overwrite it."
fi
log "Onboarding complete. Next: ./psm-session.sh checkout"
