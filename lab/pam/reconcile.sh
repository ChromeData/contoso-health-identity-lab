#!/usr/bin/env bash
# =============================================================================
# reconcile.sh - step 4: the reconciliation report an auditor asks for
# (discovery results vs vault contents, plus a verify bind).
#
# Joins three views and says, per account, which of these is true:
#   VAULTED    in a library set or a static role (+ rotated within policy?
#              + with --verify, does the vaulted password still bind? - the
#              CPM "Verify" operation: an LDAPS bind as the account, password
#              piped from Vault into the pam-tools container, never printed)
#   EXCEPTION  documented: policy exclusion or a discovery finding (stale,
#              orphaned adminCount, Kerberoastable Tier-0, disabled...)
#   HELD       eligible account onboard.sh keeps out because a dependency is
#              unresolved or has no record (accounts-dependencies.json): a
#              service account always, a human (library) admin when its
#              tier sets dependency_check - the same gate as onboard.sh
#   GAP        discovered, eligible, not vaulted, no exception - the number
#              that must be zero
#   ORPHAN     in Vault but not found by discovery (deleted, renamed or out
#              of scope in AD) - Vault would keep "rotating" nothing
#
# "Rotated within policy":
#   static role  last_vault_rotation is younger than its rotation_period
#                (+5 min grace for the scheduler)
#   library      checked out now (rotates at check-in), or AD pwdLastSet from
#                the discovery report is younger than the tier's
#                max_password_age_days (an idle library account keeps one
#                password nobody knows; past the limit, check it out and in)
#   Forced overrides from the exception register are shown on the row.
#
# Runs with a short-lived token holding only the pam-reconcile policy
# (written by onboard.sh): read/list, no write, no rotate, no check-out.
#
# Output (gitignored): out/reconcile-<stamp>.{csv,md} + reconcile-latest.*
# KPIs at the top of the markdown: % vaulted, % rotated within policy,
# % verified, GAP and ORPHAN counts.
#
# Usage: ./reconcile.sh [--verify] [--strict] [--discovery FILE] [--deps FILE]
#   --strict  exit 3 if any GAP, ORPHAN, out-of-policy rotation or failed verify
# =============================================================================
source "$(dirname "$0")/lib.sh"
need docker; need jq; need curl
load_env

VERIFY=0 STRICT=0 DISCOVERY="$OUT/discovery-latest.json" DEPS=accounts-dependencies.json
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) VERIFY=1; shift ;;
    --strict) STRICT=1; shift ;;
    --discovery) DISCOVERY="$2"; shift 2 ;;
    --deps) DEPS="$2"; shift 2 ;;
    *) die "usage: $0 [--verify] [--strict] [--discovery FILE] [--deps FILE]" ;;
  esac
done
[[ -s "$DISCOVERY" ]] || die "no discovery report at $DISCOVERY - run ./discover.sh first"

vault_unseal
export VAULT_TOKEN; VAULT_TOKEN="$(root_token)"
vault_api GET sys/policies/acl/pam-reconcile >/dev/null 2>&1 || die "policy pam-reconcile missing - run ./onboard.sh first"
# Least privilege from here on: a 15-minute token with pam-reconcile only.
VAULT_TOKEN=$(jq -n '{policies: ["pam-reconcile"], ttl: "15m", no_default_policy: true, display_name: "pam-reconcile", meta: {purpose: "reconcile.sh"}}' \
  | vault_api POST auth/token/create | jq -r '.auth.client_token')
[[ -n "$VAULT_TOKEN" && "$VAULT_TOKEN" != null ]] || die "could not mint the pam-reconcile token"

now_epoch=$(date -u +%s)
iso_epoch() { # ISO-8601 (Vault: 2026-10-20T07:13:36.837248883Z, AD report: ...Z) -> epoch seconds
  jq -rn --arg t "$1" '$t | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601'
}

# --- Vault's inventory: one JSON object per vaulted account ----------------------
vault_inv='[]'
while IFS= read -r r; do
  [[ -n "$r" ]] || continue
  row=$(vault_api GET "ldap/static-role/$r" | jq -c --arg p "$r" '.data | {kind: "static", path: $p, username, last_vault_rotation, rotation_period}')
  vault_inv=$(printf '%s' "$vault_inv" | jq -c --argjson r "$row" '. + [$r]')
done < <(static_roles)
for set in $(library_sets); do
  status=$(vault_api GET "ldap/library/$set/status" | jq -c '.data')
  for m in $(library_members "$set"); do
    row=$(printf '%s' "$status" | jq -c --arg s "$set" --arg m "$m" '{kind: "library", path: $s, username: $m, available: (.[$m].available // null)}')
    vault_inv=$(printf '%s' "$vault_inv" | jq -c --argjson r "$row" '. + [$r]')
  done
done

exception_of() { # forced-override record for SAM from the register ('' if none)
  { vault_api GET "pam-meta/data/exceptions/$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" 2>/dev/null || true; } \
    | jq -r '.data.data | select(.) | "\(.action) by \(.operator) at \(.at): \(.justification)"' 2>/dev/null || true
}

verify_bind() { # verify_bind PATH DN -> yes|no : the vaulted password binds as DN over LDAPS
  local who
  who=$(vault_api GET "ldap/static-cred/$1" | jq -j '.data.password // ""' \
    | docker compose run --rm -T --no-deps --entrypoint ldapwhoami pam-tools \
        -x -H "ldaps://$DC_FQDN" -D "$2" -y /dev/stdin 2>/dev/null) || { echo no; return 0; }
  [[ "$who" == u:* ]] && echo yes || echo no
}

# held_by_deps ACTION TIER SAM -> 0 when onboard.sh HOLDS this account: a
# static candidate always goes through the dependency gate; a library
# candidate does when its tier's dependency_check is on (fail closed: a
# missing or mistyped flag stops the report, as it stops onboard.sh).
held_by_deps() {
  local dc
  case "$1" in
    static) ;;
    library) dc=$(policy_flag "$2" dependency_check) || exit 1
             [[ "$dc" == true ]] || return 1 ;;
    *) return 1 ;;
  esac
  ! dep_gate "$3" "$DEPS" >/dev/null
}

# --- join ---------------------------------------------------------------------------
rows=()   # TSV: sam tier type status vault_object last_rotation policy within verified exception next_action
add_row() { local IFS=$'\t'; rows+=("$*"); }

while IFS= read -r a; do
  sam=$(printf '%s' "$a" | jq -r .sam)
  lsam=$(printf '%s' "$sam" | tr '[:upper:]' '[:lower:]')
  tier=$(printf '%s' "$a" | jq -r '.tier // "-"')
  typ=$(printf '%s' "$a" | jq -r .type)
  act=$(printf '%s' "$a" | jq -r .proposed_action)
  dn=$(printf '%s' "$a" | jq -r .dn)
  v=$(printf '%s' "$vault_inv" | jq -c --arg u "$lsam" '[.[] | select((.username | ascii_downcase) == $u)][0] // empty')
  forced=$(exception_of "$sam")
  if [[ -n "$v" ]]; then
    kind=$(printf '%s' "$v" | jq -r .kind)
    path=$(printf '%s' "$v" | jq -r .path)
    verified=skipped
    if [[ "$kind" == static ]]; then
      last=$(printf '%s' "$v" | jq -r .last_vault_rotation)
      period=$(printf '%s' "$v" | jq -r .rotation_period)
      age=$(( now_epoch - $(iso_epoch "$last") ))
      if [[ $age -le $(( period + 300 )) ]]; then within=yes; else within=no; fi
      pol="every $((period / 3600))h"
      [[ $VERIFY -eq 0 ]] || verified=$(verify_bind "$path" "$dn")
      nxt=$([[ $within == yes ]] && echo "-" || echo "rotation overdue: ./rotate.sh $sam")
    else
      last=$(printf '%s' "$a" | jq -r '.pwd_last_set // ""')
      maxd=$(policy_tier "$tier" max_password_age_days); maxd=${maxd:-30}
      pol="on check-in; idle <= ${maxd}d"
      idle_days=999999
      [[ -z "$last" ]] || idle_days=$(( (now_epoch - $(iso_epoch "$last")) / 86400 ))
      if [[ "$(printf '%s' "$v" | jq -r .available)" == false ]]; then
        within=yes; last="${last} (checked out)"; nxt="-"
      elif [[ $idle_days -le $maxd ]]; then
        within=yes; nxt="-"
      else
        within=no; nxt="idle past ${maxd}d: check out + in to rotate"
      fi
      last="AD pwdLastSet $last"
    fi
    add_row "$sam" "$tier" "$typ" VAULTED "$kind:$path" "$last" "$pol" "$within" "$verified" "${forced:--}" "$nxt"
  elif [[ "$act" == exception ]]; then
    add_row "$sam" "$tier" "$typ" EXCEPTION "-" "-" "-" "n/a" "n/a" "$(printf '%s' "$a" | jq -r .reason)" "owner review (see exception)"
  elif held_by_deps "$act" "$tier" "$sam"; then
    add_row "$sam" "$tier" "$typ" HELD "-" "-" "-" "n/a" "n/a" "unresolved dependencies: $(dep_gate "$sam" "$DEPS" | paste -sd ';' -)" "resolve dependencies, then ./onboard.sh --only $sam"
  else
    add_row "$sam" "$tier" "$typ" GAP "-" "-" "-" "no" "n/a" "-" "./onboard.sh --only $sam"
  fi
done < <(jq -c '.accounts[]' "$DISCOVERY")

# Vault objects whose account discovery did not find.
discovered=$(jq -r '.accounts[].sam | ascii_downcase' "$DISCOVERY")
while IFS= read -r v; do
  [[ -n "$v" ]] || continue
  u=$(printf '%s' "$v" | jq -r '.username | ascii_downcase')
  grep -qx -- "$u" <<<"$discovered" && continue
  add_row "$u" "-" "-" ORPHAN "$(printf '%s' "$v" | jq -r '"\(.kind):\(.path)"')" "-" "-" "n/a" "n/a" \
    "in Vault but not found by discovery" "confirm in AD; remove the Vault object or fix discovery scope"
done < <(printf '%s' "$vault_inv" | jq -c '.[]')

# --- report -----------------------------------------------------------------------------
out_dir
ts=$(stamp)
csv="$OUT/reconcile-$ts.csv" md="$OUT/reconcile-$ts.md"
header=$'account\ttier\ttype\tstatus\tvault_object\tlast_rotation\trotation_policy\trotated_within_policy\tverified\texception\tnext_action'
printf '%s\n' "$header" "${rows[@]}" | jq -Rr 'split("\t") | @csv' > "$csv"

count() { printf '%s\n' "${rows[@]}" | awk -F'\t' -v s="$1" '$4 == s' | wc -l | tr -d ' '; }
pct() { if [[ "$2" -eq 0 ]]; then echo "n/a"; else echo "$(( 100 * $1 / $2 ))%"; fi; }
n_v=$(count VAULTED) n_e=$(count EXCEPTION) n_h=$(count HELD) n_g=$(count GAP) n_o=$(count ORPHAN)
n_in=$(printf '%s\n' "${rows[@]}" | awk -F'\t' '$4 == "VAULTED" && $8 == "yes"' | wc -l | tr -d ' ')
n_ver=$(printf '%s\n' "${rows[@]}" | awk -F'\t' '$4 == "VAULTED" && $9 == "yes"' | wc -l | tr -d ' ')
n_vtry=$(printf '%s\n' "${rows[@]}" | awk -F'\t' '$4 == "VAULTED" && $9 != "skipped"' | wc -l | tr -d ' ')
eligible=$(( n_v + n_h + n_g ))
{
  printf '# PAM reconciliation report\n\n'
  # shellcheck disable=SC2016 # backticks are markdown code spans, not command substitution
  printf 'Generated %s from `%s` (discovery %s) and Vault. Lab evidence: account names only, no secrets.\n\n' \
    "$(date -u +%FT%TZ)" "$DISCOVERY" "$(jq -r .generated_at "$DISCOVERY")"
  printf '| KPI | Value |\n|---|---|\n'
  printf '| Privileged accounts discovered | %s |\n' "$(jq '.accounts | length' "$DISCOVERY")"
  printf '| Eligible for vaulting (excl. documented exceptions) | %s |\n' "$eligible"
  printf '| Vaulted | %s (%s of eligible) |\n' "$n_v" "$(pct "$n_v" "$eligible")"
  printf '| Rotated within policy | %s (%s of vaulted) |\n' "$n_in" "$(pct "$n_in" "$n_v")"
  printf '| Verified (vaulted password binds) | %s |\n' "$([[ $VERIFY -eq 1 ]] && echo "$n_ver of $n_vtry static roles" || echo "not run (--verify)")"
  printf '| Documented exceptions | %s |\n' "$n_e"
  printf '| Held (unresolved dependencies) | %s |\n' "$n_h"
  printf '| **GAP** (not vaulted, no exception) | **%s** |\n' "$n_g"
  printf '| ORPHAN (in Vault, not in AD) | %s |\n\n' "$n_o"
  printf '| Account | Tier | Status | Vault object | Last rotation | Policy | Within | Verified | Exception / note | Next action |\n'
  printf '|---|---|---|---|---|---|---|---|---|---|\n'
  printf '%s\n' "${rows[@]}" | awk -F'\t' '{ gsub(/\|/, "/", $10); printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $4, $5, $6, $7, $8, $9, $10, $11 }'
} > "$md"
cp "$csv" "$OUT/reconcile-latest.csv"
cp "$md" "$OUT/reconcile-latest.md"

printf '%s\n' "${rows[@]}" | awk -F'\t' '{ printf "  %-22s %-9s %-26s within=%-3s verified=%s\n", $1, $4, $5, $8, $9 }'
log "Vaulted $n_v/$eligible eligible, rotated within policy $n_in/$n_v, exceptions $n_e, held $n_h, GAP $n_g, ORPHAN $n_o"
log "Report: $md (+ .csv)"

if [[ $STRICT -eq 1 ]]; then
  bad_rot=$(( n_v - n_in ))
  bad_ver=$(( VERIFY == 1 ? n_vtry - n_ver : 0 ))
  if [[ $n_g -gt 0 || $n_o -gt 0 || $bad_rot -gt 0 || $bad_ver -gt 0 ]]; then
    log "--strict: GAP=$n_g ORPHAN=$n_o out-of-policy=$bad_rot failed-verify=$bad_ver"
    exit 3
  fi
fi
