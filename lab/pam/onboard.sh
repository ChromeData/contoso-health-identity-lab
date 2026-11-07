#!/usr/bin/env bash
# =============================================================================
# onboard.sh - step 2: bulk-onboard discovered accounts into Vault through the
# Vault HTTP API, one Safe (policy) per tier (the "add accounts from
# Pending Accounts" + CPM takes over).
#
#   * humans  -> their tier's LIBRARY set (exclusive check-out, rotated on
#                every check-in). Creating or extending a set makes Vault set
#                a new password for each added account right away (verified
#                on Vault 2.1.1 against Samba AD) - so where the tier says
#                dependency_check (pam-policy.json; fail closed: only an
#                explicit false skips it), a human admin used as a run-as
#                identity is HELD by the same gate as a service account.
#   * service -> STATIC ROLE <tier prefix>/<sam> (hierarchical name, so one
#                policy path glob covers a whole tier). Creating it rotates
#                the password immediately, then every rotation_period - so a
#                service account is created ONLY if every consumer of its
#                password is resolved (dependency gate, accounts-dependencies.json).
#                Held accounts stay "not vaulted" in the reconcile report.
#   * exception -> never touched; the reason comes from discovery.
#   * Vault policies per tier ("Safes"), named after pam-policy.json:
#       <tier>-checkout     check-out / check-in / status on the tier's library
#       <tier>-static-read  read ldap/static-cred/<prefix>/*  (the CCP /
#                           Credential Provider equivalent for applications)
#       pam-reconcile       read-only view reconcile.sh runs with
#
# Idempotent: accounts already in a library or a static role are skipped
# (re-writing an existing static role would not rotate anyway).
#
# Override for ONE held account, recorded in the exception register (Vault
# KV v2 pam-meta/exceptions/<sam>, versioned + audited) and out/pam-audit.jsonl:
#   ./onboard.sh --only svc-sql01 --force --justification "CHG0031337: SQL svc password change window, DBA on bridge"
#
# Usage: ./onboard.sh [--dry-run] [--only SAM] [--discovery FILE] [--deps FILE]
#                     [--force --justification TEXT [--operator NAME]]
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq; need curl
load_env

DRY=0 ONLY="" DISCOVERY="$OUT/discovery-latest.json" DEPS=accounts-dependencies.json FORCE=0 JUST="" OPERATOR=local-admin
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --only) ONLY="$2"; shift 2 ;;
    --discovery) DISCOVERY="$2"; shift 2 ;;
    --deps) DEPS="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --justification) JUST="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    *) die "usage: $0 [--dry-run] [--only SAM] [--discovery FILE] [--deps FILE] [--force --justification TEXT [--operator NAME]]" ;;
  esac
done
[[ -s "$DISCOVERY" ]] || die "no discovery report at $DISCOVERY - run ./discover.sh first"
if [[ $FORCE -eq 1 ]]; then
  # One account at a time: a blanket --force would wave through every held
  # service account in the directory on one justification.
  [[ -n "$ONLY" ]] || die "--force needs --only SAM (one account per override)"
  [[ -n "$JUST" ]] || die "--force needs --justification \"...CHG#######...\""
  check_justification "$JUST"
fi

vault_unseal
export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"
vault_api GET ldap/config >/dev/null 2>&1 || die "Vault's ldap/ engine is not configured - run ./vault-onboard-ad.sh first"

# --- Safes: one policy set per tier -------------------------------------------
write_policy() { # write_policy NAME < HCL
  jq -Rs '{policy: .}' | vault_api PUT "sys/policies/acl/$1" >/dev/null
}

ensure_policies() {
  local tier lib prefix
  for tier in $(jq -r '.tiers | keys[]' "$POLICY_FILE"); do
    lib=$(policy_tier "$tier" library)
    prefix=$(policy_tier "$tier" static_prefix)
    if [[ -n "$lib" ]]; then
      write_policy "$tier-checkout" <<HCL
# Safe "$lib" (tier $tier): check out / check in / status - nothing else.
path "ldap/library/$lib/check-out" { capabilities = ["update"] }
path "ldap/library/$lib/check-in"  { capabilities = ["update"] }
path "ldap/library/$lib/status"    { capabilities = ["read"] }
HCL
    fi
    if [[ -n "$prefix" ]]; then
      write_policy "$tier-static-read" <<HCL
# Safe "$prefix/*" (tier $tier): applications read their current password at
# run time instead of storing it - what makes a static role safe to rotate.
path "ldap/static-cred/$prefix/*" { capabilities = ["read"] }
HCL
    fi
  done
  write_policy pam-reconcile <<'HCL'
# reconcile.sh: inventory + CPM-style verify. Reads static-cred to test that
# the vaulted password still binds; cannot write, rotate, check out or in.
path "ldap/static-role"            { capabilities = ["list"] }
path "ldap/static-role/*"          { capabilities = ["read", "list"] }
path "ldap/static-cred/*"          { capabilities = ["read"] }
path "ldap/library"                { capabilities = ["list"] }
path "ldap/library/*"              { capabilities = ["read", "list"] }
path "pam-meta/data/exceptions/*"  { capabilities = ["read"] }
path "pam-meta/metadata/exceptions/*" { capabilities = ["read", "list"] }
path "pam-meta/metadata/exceptions"   { capabilities = ["list"] }
HCL
}

# --- plan -------------------------------------------------------------------------
PLAN=()   # "action|sam|target|detail"

lib_has() { library_members "$1" | tr '[:upper:]' '[:lower:]' | grep -qx "$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"; }

accounts=$(jq -c --arg o "$ONLY" '.accounts[] | select($o == "" or (.sam | ascii_downcase) == ($o | ascii_downcase))' "$DISCOVERY")

# Vault's static roles, indexed ONCE (one GET per role) and looked up locally
# per account: asking Vault per account (static_role_of) is O(accounts x
# roles) - the 500-account re-run in test/e2e-scale.sh spent minutes there.
STATIC_INDEX=$(static_role_index)
indexed_role_of() { # indexed_role_of SAM -> its static role path ('' if none)
  [[ -n "$STATIC_INDEX" ]] || return 0
  awk -F'\t' -v u="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" '$1 == u { print $2; exit }' <<<"$STATIC_INDEX"
}
[[ -n "$accounts" ]] || die "no matching account in $DISCOVERY${ONLY:+ (--only $ONLY)}"

while IFS= read -r a; do
  sam=$(printf '%s' "$a" | jq -r .sam)
  act=$(printf '%s' "$a" | jq -r .proposed_action)
  tgt=$(printf '%s' "$a" | jq -r '.proposed_target // ""')
  case "$act" in
    exception)
      PLAN+=("skip|$sam|-|exception: $(printf '%s' "$a" | jq -r .reason)") ;;
    library)
      if lib_has "$tgt" "$sam"; then
        PLAN+=("vaulted|$sam|library:$tgt|already in the library")
        continue
      fi
      # Adding a human admin to a library set resets its password at once,
      # exactly like creating a static role. An admin account that is also a
      # scheduled-task / service run-as identity (a common finding, and what
      # Get-AccountDependencies.ps1 scans for) would break on the spot, so
      # the same dependency gate applies when the tier asks for it.
      dc=$(policy_flag "$(printf '%s' "$a" | jq -r '.tier // ""')" dependency_check) || exit 1
      if [[ "$dc" == false ]]; then
        PLAN+=("library|$sam|$tgt|add to library $tgt (Vault sets a new password now; dependency_check=false for this tier)")
        continue
      fi
      rc=0; deps=$(dep_gate "$sam" "$DEPS") || rc=$?
      if [[ $rc -eq 0 ]]; then
        PLAN+=("library|$sam|$tgt|add to library $tgt (Vault sets a new password now)")
      elif [[ $FORCE -eq 1 ]]; then
        PLAN+=("forcelib|$sam|$tgt|FORCED past: $(printf '%s' "$deps" | paste -sd ';' -)")
      else
        PLAN+=("hold|$sam|$tgt|HELD - $(printf '%s' "$deps" | paste -sd ';' -)")
      fi ;;
    static)
      existing=$(indexed_role_of "$sam")
      if [[ -n "$existing" ]]; then
        PLAN+=("vaulted|$sam|static:$existing|already a static role")
        continue
      fi
      rc=0; deps=$(dep_gate "$sam" "$DEPS") || rc=$?
      if [[ $rc -eq 0 ]]; then
        PLAN+=("static|$sam|$tgt|create static role $tgt (rotates now, then every $(policy_tier "$(printf '%s' "$a" | jq -r .tier)" rotation_period))")
      elif [[ $FORCE -eq 1 ]]; then
        PLAN+=("force|$sam|$tgt|FORCED past: $(printf '%s' "$deps" | paste -sd ';' -)")
      else
        PLAN+=("hold|$sam|$tgt|HELD - $(printf '%s' "$deps" | paste -sd ';' -)")
      fi ;;
    *) PLAN+=("skip|$sam|-|unknown proposed_action '$act'") ;;
  esac
done <<<"$accounts"

log "Onboarding plan from $DISCOVERY${ONLY:+ (only $ONLY)}:"
for p in "${PLAN[@]}"; do
  IFS='|' read -r act sam tgt detail <<<"$p"
  printf '  %-8s %-22s %s\n' "$act" "$sam" "$detail"
done
if [[ $DRY -eq 1 ]]; then log "--dry-run: nothing changed"; exit 0; fi

# --- apply ------------------------------------------------------------------------
ensure_policies
out_dir
ts=$(stamp)
results=()
for p in "${PLAN[@]}"; do
  IFS='|' read -r act sam tgt detail <<<"$p"
  dn=$(jq -r --arg s "$sam" '.accounts[] | select(.sam == $s) | .dn' "$DISCOVERY")
  tier=$(jq -r --arg s "$sam" '.accounts[] | select(.sam == $s) | .tier // ""' "$DISCOVERY")
  case "$act" in
    library|forcelib)
      if [[ "$act" == forcelib ]]; then
        deps=$(dep_gate "$sam" "$DEPS" || true)
        record_override "$sam" onboard-forced "$JUST" "$OPERATOR" "$deps"
        audit_line override account="$sam" action=onboard-forced justification="$JUST" by="$OPERATOR"
      fi
      # Union with the current members: never drop an account someone added
      # by hand (that is reconcile's call to flag, not onboarding's to undo).
      names=$( { library_members "$tgt"; printf '%s\n' "$sam"; } | awk 'NF && !seen[tolower($0)]++' | paste -sd, -)
      jq -n --arg n "$names" --arg ttl "$(policy_tier "$tier" checkout_ttl)" \
        '{service_account_names: ($n | split(",")), ttl: (if $ttl == "" then "1h" else $ttl end), max_ttl: "4h", disable_check_in_enforcement: false}' \
        | vault_api POST "ldap/library/$tgt" >/dev/null || die "could not add $sam to library $tgt"
      audit_line onboard account="$sam" tier="$tier" target="library:$tgt" by="$OPERATOR"
      results+=("$sam|vaulted|library:$tgt") ;;
    static|force)
      if [[ "$act" == force ]]; then
        deps=$(dep_gate "$sam" "$DEPS" || true)
        record_override "$sam" onboard-forced "$JUST" "$OPERATOR" "$deps"
        audit_line override account="$sam" action=onboard-forced justification="$JUST" by="$OPERATOR"
      fi
      jq -n --arg dn "$dn" --arg u "$sam" --arg r "$(policy_tier "$tier" rotation_period)" \
        '{dn: $dn, username: $u, rotation_period: $r}' \
        | vault_api POST "ldap/static-role/$tgt" >/dev/null || die "could not create static role $tgt"
      last=$(vault_api GET "ldap/static-role/$tgt" | jq -r '.data.last_vault_rotation')
      audit_line onboard account="$sam" tier="$tier" target="static:$tgt" rotated="$last" by="$OPERATOR"
      results+=("$sam|vaulted|static:$tgt") ;;
    hold)    results+=("$sam|held|$detail") ;;
    vaulted) results+=("$sam|already|$tgt") ;;
    skip)    results+=("$sam|exception|$detail") ;;
  esac
done

printf '%s\n' "${results[@]}" | jq -R 'split("|") | {account: .[0], result: .[1], detail: .[2]}' | jq -s \
  --arg t "$(date -u +%FT%TZ)" --arg d "$DISCOVERY" '{generated_at: $t, discovery: $d, results: .}' > "$OUT/onboarding-$ts.json"
log "$(printf '%s\n' "${results[@]}" | awk -F'|' '{c[$2]++} END {for (k in c) printf "%s=%d ", k, c[k]}')- details: $OUT/onboarding-$ts.json"
log "Next: ./reconcile.sh   (held accounts: resolve their dependencies, or --force one with a justification)"
