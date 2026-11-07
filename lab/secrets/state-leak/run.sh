#!/usr/bin/env bash
# =============================================================================
# run.sh - does Terraform write an Azure Key Vault secret into its state file?
#
# The question: the usual way to give Terraform a Key Vault secret is the
# azurerm provider's azurerm_key_vault_secret DATA SOURCE. Terraform keeps
# every data source result in terraform.tfstate, so the secret ends up there
# in plaintext. Marking things `sensitive` only hides them on screen. The fix
# is the provider's azurerm_key_vault_secret EPHEMERAL resource (Terraform
# 1.10+), which is never written to state.
#
# Run it as the lab operator (it creates and deletes real Azure objects):
#   lab/scripts/operator/op bash lab/secrets/state-leak/run.sh
#
# What it does (about 4-6 min, almost all of it Azure create/delete time;
# cost well under $0.01: Key Vault Standard bills $0.03 per 10,000 operations):
#   1. Creates a throwaway resource group and a Key Vault in the lab
#      subscription. The vault uses Azure RBAC (no access policies), purge
#      protection OFF so it can be purged at the end.
#   2. Grants the operator "Key Vault Secrets Officer" on THAT vault only,
#      waits for RBAC to take effect, and stores a RANDOM 40-character value
#      (never a real credential).
#   3. datasource/: apply, apply again (a change, so a backup is written),
#      then a saved plan; counts the value in terraform.tfstate, its backup,
#      the saved plan and Terraform's output.
#   4. ephemeral/: first a plan that expects the wrong length, which must
#      fail on the precondition (so the check can fail); then the same steps
#      as 3. Its precondition proves the value really was read.
#   5. Deletes the resource group, PURGES the vault (soft delete would keep
#      it for 7 days), and reads back that both are gone. KEEP=1 skips this.
#
# Exit: 0 = the result the README states; 1 = a different result (read the
# table); 2 = could not run (wrong subscription, missing tool, Azure error).
# Nothing secret is printed: counts, lengths and timings only.
#
# Secrets handling: the value lives in a shell variable and a 0600 file in a
# mktemp folder. It reaches az on --file (never on a command line) and is
# read back only by Terraform. Every az call that could echo the secret runs
# with -o none.
#
# Needs: az (run under `op`), openssl, python3, and HashiCorp Terraform
# >= 1.10 as `terraform` (or TF_BIN=/path/to/terraform). OpenTofu is
# refused: the finding is about Terraform, and the lab's CI runs Terraform.
#
# Replaces the Conjur version (lab/pam/conjur/state-leak, PR #210): the lab
# dropped CyberArk on 2026-11-06 (ADR 0027). Same counter, same verdict.
# =============================================================================
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_BIN="${TF_BIN:-terraform}"
LAB_SUB="de0b2a93-1c62-47b3-aaaf-1bdd1939a274"
LAB_TENANT="86a2e327-4951-4348-a3c4-6f4b79ffd8f2"
LOCATION="${STATE_LEAK_LOCATION:-eastus2}"
SECRET_NAME="state-leak-db-password"
SUFFIX="$(openssl rand -hex 4)"
RG="rg-stateleak-$SUFFIX"
KV="kv-stateleak-$SUFFIX"

T0=$(date +%s)
log() { printf '[%s +%3ss] %s\n' "$(date -u +%H:%M:%SZ)" "$(( $(date +%s) - T0 ))" "$*"; }
die() { echo "COULD NOT RUN: $*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
for t in az openssl python3 "$TF_BIN"; do need "$t"; done

tf_version="$("$TF_BIN" version 2>/dev/null | sed -n 1p)"
[[ "$tf_version" =~ ^Terraform\ v([0-9]+)\.([0-9]+) ]] \
  || die "$TF_BIN is not HashiCorp Terraform (got: ${tf_version:-nothing})"
(( BASH_REMATCH[1] > 1 || BASH_REMATCH[2] >= 10 )) \
  || die "Terraform >= 1.10 is needed for ephemeral resources (got $tf_version)"

# Refuse anywhere but the lab subscription and tenant: this creates objects.
acct="$(az account show --query '[id, tenantId, user.name]' -o tsv 2>/dev/null | tr '\n' ' ')" \
  || die "az is not signed in (run under lab/scripts/operator/op)"
read -r sub tenant caller <<<"$acct"
[[ "$sub" == "$LAB_SUB" && "$tenant" == "$LAB_TENANT" ]] \
  || die "not the lab subscription/tenant (got $sub / $tenant)"
caller_oid="$(az ad sp show --id "$caller" --query id -o tsv 2>/dev/null)" \
  || die "cannot resolve the caller's object id (run as the lab operator)"
export ARM_SUBSCRIPTION_ID="$LAB_SUB"
# az 2.91 on Python 3.14 prints a SyntaxWarning from one of its own modules; it is noise.
export PYTHONWARNINGS=ignore

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kv-state-leak.XXXXXX")"
created=0
cleanup() {
  local rc=$?
  if [[ "${KEEP:-0}" == 1 ]]; then
    log "KEEP=1: left $RG / $KV and $WORK (delete the group and purge the vault yourself)"
    return
  fi
  rm -rf "$WORK"
  if [[ $created == 1 ]]; then
    local c0; c0=$(date +%s)
    log "Cleanup: deleting $RG, then purging $KV"
    az group delete -n "$RG" --yes -o none 2>/dev/null || echo "WARNING: group delete failed: delete $RG by hand" >&2
    az keyvault purge -n "$KV" --location "$LOCATION" -o none 2>/dev/null || echo "WARNING: purge failed: purge $KV by hand" >&2
    # Read back: the group is gone and the vault is not in the deleted list.
    if [[ "$(az group exists -n "$RG" 2>/dev/null)" == "false" ]] \
       && ! az keyvault show-deleted -n "$KV" -o none 2>/dev/null; then
      log "Cleanup read back: $RG gone, $KV purged ($(( $(date +%s) - c0 )) s)"
    else
      echo "WARNING: read back failed: check $RG and the deleted vault $KV by hand" >&2
      rc=2
    fi
  fi
  exit $rc
}
trap cleanup EXIT

# --- 1. Throwaway vault ------------------------------------------------------
s=$(date +%s)
log "Creating $RG and $KV in $LOCATION (RBAC, purge protection off)"
az group create -n "$RG" -l "$LOCATION" -o none \
  --tags purpose=state-leak-experiment owner=lab-operator delete-after=this-run \
  || die "could not create $RG"
created=1
az keyvault create -n "$KV" -g "$RG" -l "$LOCATION" --sku standard \
  --enable-rbac-authorization true --retention-days 7 -o none \
  || die "could not create $KV"
kv_id="$(az keyvault show -n "$KV" --query id -o tsv)"
log "Vault created ($(( $(date +%s) - s )) s)"

# --- 2. RBAC, then the value ---------------------------------------------------
s=$(date +%s)
az role assignment create --assignee-object-id "$caller_oid" --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets Officer" --scope "$kv_id" -o none \
  || die "could not grant Key Vault Secrets Officer on $KV"
secret="$(openssl rand -base64 30 | tr -d '\n')"     # 40 characters, random
[[ ${#secret} -eq 40 ]] || die "could not generate the test value"
printf '%s' "$secret" > "$WORK/value"
# RBAC takes effect within minutes, not at once: retry the write until it works.
stored=0
for _ in $(seq 1 40); do
  if az keyvault secret set --vault-name "$KV" -n "$SECRET_NAME" --file "$WORK/value" \
       --encoding utf-8 -o none 2>/dev/null; then stored=1; break; fi
  sleep 6
done
rm -f "$WORK/value"
[[ $stored == 1 ]] || die "could not store the value (RBAC never took effect?)"
log "RBAC took effect and a random ${#secret}-character value is stored ($(( $(date +%s) - s )) s; value never printed)"

# --- 3/4. Terraform, both ways ------------------------------------------------
export TF_PLUGIN_CACHE_DIR="$WORK/plugin-cache" TF_IN_AUTOMATION=1 TF_INPUT=0
mkdir -p "$TF_PLUGIN_CACHE_DIR"
export STATE_LEAK_SECRET="$secret"   # read by count_secret.py from its environment
KVARG=(-var "key_vault_id=$kv_id")

# Results as R_<path>_<file> variables (printf -v / ${!name}): macOS ships
# bash 3.2, which has no associative arrays.
res() { local n="R_$1_$2"; echo "${!n}"; }
run_path() {  # run_path NAME [extra terraform args...]
  local name="$1"; shift
  local dir="$WORK/$name" logf="$WORK/$name.log" p0; p0=$(date +%s)
  cp -R "$HERE/$name" "$dir"
  log "[$name] terraform init / apply / apply again / plan -out"
  {
    "$TF_BIN" -chdir="$dir" init -lockfile=readonly -no-color \
    && "$TF_BIN" -chdir="$dir" apply -auto-approve -no-color -var run_id=1 "${KVARG[@]}" "$@" \
    && "$TF_BIN" -chdir="$dir" apply -auto-approve -no-color -var run_id=2 "${KVARG[@]}" "$@" \
    && "$TF_BIN" -chdir="$dir" plan -out=saved.tfplan -no-color -var run_id=3 "${KVARG[@]}" "$@"
  } > "$logf" 2>&1 || { tail -20 "$logf" | sed 's/^/    /' >&2; die "[$name] terraform failed (log above)"; }
  local counts
  counts="$(python3 -I "$HERE/count_secret.py" "$dir/terraform.tfstate" \
    "$dir/terraform.tfstate.backup" "$dir/saved.tfplan" "$logf")" || die "[$name] the scan could not run"
  printf -v "R_${name}_state" %s "$(sed -n 1p <<<"$counts" | cut -f1)"
  printf -v "R_${name}_backup" %s "$(sed -n 2p <<<"$counts" | cut -f1)"
  printf -v "R_${name}_plan" %s "$(sed -n 3p <<<"$counts" | cut -f1)"
  printf -v "R_${name}_log" %s "$(sed -n 4p <<<"$counts" | cut -f1)"
  log "[$name] done ($(( $(date +%s) - p0 )) s)"
}

run_path datasource

log "[ephemeral] negative control: a plan expecting the wrong length must fail"
neg="$WORK/ephemeral-negative"
cp -R "$HERE/ephemeral" "$neg"
"$TF_BIN" -chdir="$neg" init -lockfile=readonly -no-color > "$neg.log" 2>&1 || die "[ephemeral] init failed"
if "$TF_BIN" -chdir="$neg" plan -no-color "${KVARG[@]}" -var "expected_secret_length=$(( ${#secret} - 1 ))" >> "$neg.log" 2>&1; then
  die "[ephemeral] the precondition did not fail on a wrong length; it would not prove the value was read"
fi
grep -q "Resource precondition failed" "$neg.log" \
  || { tail -20 "$neg.log" | sed 's/^/    /' >&2; die "[ephemeral] the negative plan failed, but not on the precondition"; }
log "[ephemeral] negative control failed on the precondition, as it must"

run_path ephemeral -var "expected_secret_length=${#secret}"
log "Terraform: $tf_version; provider hashicorp/azurerm 4.81.0 (lock file)"

# --- Verdict -----------------------------------------------------------------
echo
printf '%-12s %-18s %-26s %-12s %s\n' "path" "terraform.tfstate" "terraform.tfstate.backup" "saved plan" "terraform output"
for p in datasource ephemeral; do
  printf '%-12s %-18s %-26s %-12s %s\n' "$p" "$(res $p state)" "$(res $p backup)" "$(res $p plan)" "$(res $p log)"
done
echo "(times the ${#secret}-character value appears in each file)"
echo

python3 -I "$HERE/count_secret.py" --verdict \
  "$(res datasource state)" "$(res datasource backup)" "$(res datasource plan)" "$(res datasource log)" \
  "$(res ephemeral state)" "$(res ephemeral backup)" "$(res ephemeral plan)" "$(res ephemeral log)"
