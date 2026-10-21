#!/usr/bin/env bash
# =============================================================================
# discover.sh - step 1 of the PAM onboarding pipeline: find every privileged
# account in AD before deciding what to vault (CyberArk "Accounts Discovery").
#
#   discover.sh -> onboard.sh -> rotate.sh (dependency-gated) -> reconcile.sh
#
# Runs tools/discover.py inside the pam-tools container (same DC host mapping
# and AD root CA as Vault, so it needs ./vault-onboard-ad.sh to have run).
# Candidates: privileged-group members (nested + primary group), SPN
# accounts, adminCount=1, anything in the PAM OUs. Each gets a tier and a
# proposed action from pam-policy.json: library (humans), static role
# (service accounts) or exception (with the reason). Read-only: nothing in
# AD or Vault changes.
#
# Binds as a READ-ONLY account (default svc-pam-discovery, a plain Domain
# User), never the Tier-0 rotator. Its password comes on stdin:
#   az keyvault secret show --vault-name <kv> -n svc-pam-discovery --query value -o tsv \
#     | ./discover.sh
# (Samba harness: test/e2e.sh pipes its own test password.)
#
# Output (gitignored, 0600): out/discovery-<UTC stamp>.{json,csv} and
# out/discovery-latest.{json,csv}, which onboard.sh / reconcile.sh read.
#
# Usage: ./discover.sh [-d corp-domain-fqdn] [--bind-dn DN] [--stale-days N]
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq
load_env

DOMAIN="" BIND_DN="" STALE=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2 ;;
    --bind-dn) BIND_DN="$2"; shift 2 ;;
    --stale-days) STALE=(--stale-days "$2"); shift 2 ;;
    *) die "usage: $0 [-d corp-domain-fqdn] [--bind-dn DN] [--stale-days N]  (bind password on stdin)" ;;
  esac
done

[[ -n "${DC_FQDN:-}" ]] || die "DC_FQDN is empty - run ./vault-onboard-ad.sh first (it maps the DC and installs its CA)"
[[ -s "$CA_FILE" ]] || die "no AD root CA at $CA_FILE - run ./vault-onboard-ad.sh first"
[[ -t 0 ]] && die "pipe the discovery account's password on stdin (see the header)"
DOMAIN=$(printf '%s' "${DOMAIN:-${DC_FQDN#*.}}" | tr '[:upper:]' '[:lower:]')
BASE_DN=$(printf '%s' "$DOMAIN" | sed 's/^/DC=/; s/\./,DC=/g')
BIND_DN="${BIND_DN:-CN=svc-pam-discovery,OU=ServiceAccounts,$BASE_DN}"

log "Discovering privileged accounts in $DOMAIN via ldaps://$DC_FQDN (bind: ${BIND_DN%%,*}, read-only)"
# stdin (the password) flows straight into the container; stdout is the JSON.
json=$(docker compose run --rm -T --no-deps pam-tools /pam/tools/discover.py \
  --uri "ldaps://$DC_FQDN" --base-dn "$BASE_DN" --bind-dn "$BIND_DN" "${STALE[@]+"${STALE[@]}"}") \
  || die "discovery failed (see above)"
printf '%s' "$json" | jq -e '.accounts | type == "array"' >/dev/null || die "discovery returned no account list"

out_dir
ts=$(stamp)
printf '%s\n' "$json" > "$OUT/discovery-$ts.json"
printf '%s' "$json" | jq -r '
  ["sam","tier","type","enabled","privileged_groups","spn_count","admin_count","last_logon","pwd_last_set","when_created","stale","proposed_action","proposed_target","reason"],
  (.accounts[] | [.sam, (.tier // ""), .type, .enabled, (.privileged_groups | join(";")), .spn_count, .admin_count,
                  .last_logon, (.pwd_last_set // ""), (.when_created // ""), .stale, .proposed_action, (.proposed_target // ""), .reason])
  | @csv' > "$OUT/discovery-$ts.csv"
cp "$OUT/discovery-$ts.json" "$OUT/discovery-latest.json"
cp "$OUT/discovery-$ts.csv" "$OUT/discovery-latest.csv"

printf '%s' "$json" | jq -r '.accounts[] | "  \(.sam)\t\(.tier // "-")\t\(.proposed_action)\t\(.proposed_target // .reason)"' \
  | awk -F'\t' '{ printf "%-22s %-6s %-10s %s\n", $1, $2, $3, $4 }'
log "$(printf '%s' "$json" | jq -r '.accounts | "\(length) candidates: \([.[] | select(.proposed_action=="library")] | length) library, \([.[] | select(.proposed_action=="static")] | length) static role, \([.[] | select(.proposed_action=="exception")] | length) exception"')"
log "Report: $OUT/discovery-$ts.csv (+ .json); next: ./onboard.sh --dry-run"
