#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables below are read by pipeline.sh, which sources this file
# =============================================================================
# lab/k8s/ci/azure.sh - the throwaway Azure side of one pipeline run.
# Sourced by ci/pipeline.sh (after lib.sh), never executed.
#
# Per run, in the lab subscription, as the lab operator (the pipeline must be
# started through lab/scripts/operator/op; preflight refuses anything else):
#   rg-k8skv-test-<run id>   one resource group, tagged, deleted at teardown
#     stk8skv<run id>        storage account; its STATIC WEBSITE is the
#                            cluster's public service-account issuer (the
#                            discovery document + JWKS, nothing else)
#     kv-k8s-<run id>        Key Vault, Azure RBAC, Standard, no purge
#                            protection (so teardown can purge it), soft
#                            delete 7 days. Holds clinical-db (the workload's
#                            secret) and clinical-other (a decoy it must not
#                            read).
#   ../keyvault-trust        app registration + federated credential + Key
#                            Vault Secrets User on clinical-db (Terraform)
#
# COST: the storage account and the vault cost cents per run (Key Vault
# Standard: $0.03 per 10,000 operations; a run makes a few hundred). Both
# are deleted, and the vault purged, at teardown, and read back as gone.
#
# SECRETS: a secret value exists in a shell variable only for the moment it
# is sent. It reaches az through a 0600 file (--file), never argv, and the
# file is removed at once. Reads (stage 12 only) go into a subshell's
# environment, to be COUNTED, never printed.
#
# WHY A PUBLIC STATIC WEBSITE (and why that is safe): Entra must fetch the
# issuer's discovery document and JWKS over the internet. Those two files
# hold PUBLIC keys only (what any verifier needs). The storage account keeps
# anonymous blob access off; only the $web container is served, read-only.
# =============================================================================

az_q() { az "$@" --only-show-errors; }   # az, minus its upgrade/preview chatter

# --- preflight ------------------------------------------------------------------
AZ_OPERATOR_OID=""
az_preflight() {
  need az "Azure CLI"
  # The operator wrapper exports both. Without them az would run as whoever
  # last signed in on this Mac - possibly the owner's account, which this
  # script must never use.
  [[ "${AZURE_CONFIG_DIR:-}" == */.contoso-operator/azure ]] \
    || die "run through the lab operator: lab/scripts/operator/op lab/k8s/ci/pipeline.sh (AZURE_CONFIG_DIR is not the operator's profile)"
  [[ -n "${ARM_SUBSCRIPTION_ID:-}" ]] || die "ARM_SUBSCRIPTION_ID is not set (lab/scripts/operator/op sets it)"
  local acct type
  acct=$(az_q account show -o json) || die "az is not signed in (lab/scripts/operator/op signs in the operator)"
  type=$(jq -r '.user.type' <<<"$acct")
  [[ "$type" == servicePrincipal ]] || die "az is signed in as a $type, not the operator service principal"
  [[ "$(jq -r '.id' <<<"$acct")" == "$ARM_SUBSCRIPTION_ID" ]] || die "az's subscription is not ARM_SUBSCRIPTION_ID"
  AZ_TENANT_ID=$(jq -r '.tenantId' <<<"$acct")
  AZ_OPERATOR_OID=$(az_q ad sp show --id "$(jq -r '.user.name' <<<"$acct")" --query id -o tsv) \
    || die "could not read the operator's own service principal"
  log "az       $(az version --query '"azure-cli"' -o tsv 2>/dev/null) as the operator (service principal ${AZ_OPERATOR_OID:0:8}...), subscription ${ARM_SUBSCRIPTION_ID:0:8}..."
}

# --- run state --------------------------------------------------------------------
write_run_env() { # identifiers only (lib.sh load_run_env reads them back)
  mkdir -p "$STATE_DIR"
  {
    printf 'RUN_ID=%q\nAZ_RG=%q\nAZ_STORAGE=%q\nKV_NAME=%q\n' "$RUN_ID" "$AZ_RG" "$AZ_STORAGE" "$KV_NAME"
    printf 'KV_ID=%q\nSA_ISSUER=%q\nAZ_TENANT_ID=%q\nWORKLOAD_CLIENT_ID=%q\n' \
      "${KV_ID:-}" "${SA_ISSUER:-}" "${AZ_TENANT_ID:-}" "${WORKLOAD_CLIENT_ID:-}"
  } > "$RUN_ENV"
}

trust_vars() { # the TF_VAR_* the keyvault-trust root needs (apply and destroy)
  export TF_VAR_run_id="$RUN_ID" TF_VAR_issuer_url="$SA_ISSUER" TF_VAR_key_vault_id="$KV_ID" TF_VAR_secret_name="$SECRET_NAME"
}

identity_vars() { # the TF_VAR_* ../identity needs (Terraform asks for them on destroy too)
  export TF_VAR_tenant_id="$AZ_TENANT_ID" TF_VAR_workload_client_id="$WORKLOAD_CLIENT_ID" \
    TF_VAR_key_vault_name="$KV_NAME" TF_VAR_secret_name="$SECRET_NAME"
}

# --- Key Vault writes -------------------------------------------------------------
kv_put() { # kv_put NAME < VALUE : a new version of secret NAME, value from stdin (never argv)
  local f rc=0
  f=$(mktemp "$WORK/kv.XXXXXX")
  cat > "$f"
  az_q keyvault secret set --vault-name "$KV_NAME" --name "$1" --file "$f" --encoding utf-8 \
    --query id -o tsv > "$WORK/kv-put.out" 2>"$WORK/kv-put.err" || rc=$?
  rm -f "$f"
  return "$rc"
}

kv_put_retry() { # kv_put_retry NAME VALUE_VAR : retry while the operator's new data-plane role propagates
  local i
  for i in $(seq 1 30); do
    if printf '%s' "${!2}" | kv_put "$1"; then return 0; fi
    grep -q 'Forbidden' "$WORK/kv-put.err" 2>/dev/null || { sed 's/^/      /' "$WORK/kv-put.err" >&2; return 1; }
    [[ $i -eq 1 ]] && log "waiting for the operator's Key Vault Secrets Officer role to take effect (Azure RBAC propagation)"
    sleep 10
  done
  return 1
}

# --- stage 4: throwaway Azure objects + the trust ---------------------------------
azure_up() {
  RUN_ID=$(openssl rand -hex 4)
  AZ_RG="rg-k8skv-test-$RUN_ID"
  AZ_STORAGE="stk8skv$RUN_ID"
  KV_NAME="kv-k8s-$RUN_ID"
  KV_ID="" SA_ISSUER="" WORKLOAD_CLIENT_ID=""
  write_run_env        # first, so teardown can find a half-built run
  AZURE_TOUCHED=1

  local expires
  expires=$(date -u -v+1d +%Y-%m-%dT%H:%MZ 2>/dev/null || date -u -d '+1 day' +%Y-%m-%dT%H:%MZ)
  log "resource group $AZ_RG ($AZ_LOCATION), tagged delete-after=$expires"
  az_q group create -n "$AZ_RG" -l "$AZ_LOCATION" -o none --tags \
    purpose=k8s-keyvault-e2e created-by=lab/k8s/ci/pipeline.sh run-id="$RUN_ID" delete-after="$expires"

  log "storage account $AZ_STORAGE: static website = the cluster's public issuer"
  az_q storage account create -n "$AZ_STORAGE" -g "$AZ_RG" -l "$AZ_LOCATION" -o none \
    --sku Standard_LRS --kind StorageV2 --https-only true --min-tls-version TLS1_2 \
    --allow-blob-public-access false
  # Static website is a blob SERVICE property. az fetches the account key
  # itself over ARM (the operator is Owner); the key is never on a command line.
  az_q storage blob service-properties update --account-name "$AZ_STORAGE" --auth-mode key \
    --static-website --index-document index.html -o none
  SA_ISSUER=$(az_q storage account show -n "$AZ_STORAGE" -g "$AZ_RG" --query primaryEndpoints.web -o tsv)
  SA_ISSUER="${SA_ISSUER%/}"
  [[ "$SA_ISSUER" =~ ^https://$AZ_STORAGE\.z[0-9]+\.web\.core\.windows\.net$ ]] \
    || die "unexpected static website endpoint: $SA_ISSUER"

  log "Key Vault $KV_NAME (Azure RBAC, Standard, no purge protection: purged at teardown)"
  KV_ID=$(az_q keyvault create -n "$KV_NAME" -g "$AZ_RG" -l "$AZ_LOCATION" --sku standard \
    --enable-rbac-authorization true --retention-days 7 --public-network-access Enabled \
    --query id -o tsv)
  write_run_env
  # The operator stores the two values. Its own grant, on this vault only.
  az_q role assignment create --assignee-object-id "$AZ_OPERATOR_OID" --assignee-principal-type ServicePrincipal \
    --role "Key Vault Secrets Officer" --scope "$KV_ID" -o none

  write_db_value seeded
  local decoy
  decoy=$(new_secret_hex 16)
  kv_put_retry "$DECOY_SECRET" decoy || die "could not store $DECOY_SECRET"
  decoy=""
  log "stored $DECOY_SECRET (the decoy the workload must be refused; value not printed)"

  log "terraform apply ${TF_KEYVAULT_TRUST#"$REPO_ROOT"/} (app registration, federated credential, Key Vault Secrets User on $SECRET_NAME)"
  trust_vars
  tf "$TF_KEYVAULT_TRUST" init -input=false -lockfile=readonly -no-color | indent
  tf "$TF_KEYVAULT_TRUST" apply -input=false -auto-approve -no-color 2>&1 | tee "$WORK/trust-apply.log" | indent
  WORKLOAD_CLIENT_ID=$(tf "$TF_KEYVAULT_TRUST" output -raw client_id)
  write_run_env
  identity_vars
  STAGE_NOTE[4]="run $RUN_ID: vault + issuer site + app ${WORKLOAD_CLIENT_ID:0:8}..."
}

# --- stage 5 (after kind create): publish the issuer --------------------------------
publish_issuer() {
  # The API server serves its own discovery document and JWKS (service-
  # account issuer discovery, GA since 1.21). Copy exactly those, so the
  # keys Entra trusts are the keys this API server signs with.
  local disc="$WORK/openid-configuration" jwks="$WORK/jwks" f url got want
  k get --raw /.well-known/openid-configuration > "$disc"
  k get --raw /openid/v1/jwks > "$jwks"
  [[ "$(jq -r '.issuer' "$disc")" == "$SA_ISSUER" ]] || die "the API server's issuer is $(jq -r '.issuer' "$disc"), not $SA_ISSUER"
  [[ "$(jq -r '.jwks_uri' "$disc")" == "$SA_ISSUER/openid/v1/jwks" ]] || die "the API server's jwks_uri is $(jq -r '.jwks_uri' "$disc")"
  jq -e '.keys | length >= 1 and all(.[]; .kty == "RSA" and (has("d") | not))' "$jwks" >/dev/null \
    || die "the JWKS must hold public RSA keys only"
  # shellcheck disable=SC2016  # $web is the container's literal name
  az_q storage blob upload --account-name "$AZ_STORAGE" --auth-mode login -c '$web' --overwrite -o none \
    -n .well-known/openid-configuration -f "$disc" --content-type application/json
  # shellcheck disable=SC2016  # $web is the container's literal name
  az_q storage blob upload --account-name "$AZ_STORAGE" --auth-mode login -c '$web' --overwrite -o none \
    -n openid/v1/jwks -f "$jwks" --content-type application/json
  # Read back over the public internet, anonymously, as Entra will.
  for f in "$disc|.well-known/openid-configuration" "$jwks|openid/v1/jwks"; do
    url="$SA_ISSUER/${f#*|}"
    want=$(sha256_file "${f%%|*}")
    got=""
    for _ in $(seq 1 12); do
      got=$(curl -fsS --max-time 20 "$url" 2>/dev/null | sha256_stdin) || got=""
      [[ "$got" == "$want" ]] && break
      sleep 5
    done
    [[ "$got" == "$want" ]] || die "$url does not serve the API server's document (sha256 ${got:0:12}... vs ${want:0:12}...)"
    log "public: $url (sha256 ${want:0:12}..., same bytes as the API server's)"
  done
}

# --- stage 12: every stored version, for counting ---------------------------------
kv_secret_versions() { # kv_secret_versions NAME -> one secret id per line (identifiers)
  az_q keyvault secret list-versions --vault-name "$KV_NAME" --name "$1" --query '[].id' -o tsv
}

kv_secret_value() { # kv_secret_value SECRET_ID -> the value on stdout (CAPTURE it; never print it)
  az_q keyvault secret show --id "$1" --query value -o tsv
}

# --- teardown -------------------------------------------------------------------------
# kv_deleted_state: "present" (soft-deleted, purgeable), "gone" (Azure said
# so: "No deleted Vault or HSM was found"), or "unknown" (the lookup itself
# failed: outage, token, throttling). Only "gone" counts as absent.
kv_deleted_state() {
  local out
  if out=$(az_q keyvault show-deleted -n "$KV_NAME" -o none 2>&1); then echo present; return; fi
  if grep -qiE 'No deleted Vault|DeletedVaultNotFound|was not found' <<<"$out"; then echo gone; else echo unknown; fi
}

azure_down() { # -> 0 when everything this run created is gone (read back)
  load_run_env || { log "no $RUN_ENV: no Azure objects to delete"; return 0; }
  local ok=0 n
  if tf_has_state "$TF_KEYVAULT_TRUST"; then
    trust_vars
    log "terraform destroy ${TF_KEYVAULT_TRUST#"$REPO_ROOT"/}"
    { tf "$TF_KEYVAULT_TRUST" init -input=false -lockfile=readonly -no-color >/dev/null &&
      tf "$TF_KEYVAULT_TRUST" destroy -input=false -auto-approve -no-color 2>&1 | indent; } || ok=1
  fi
  # Belt and braces: an app registration of this run that Terraform no
  # longer tracks (state lost mid-apply) is found by its display name.
  for n in $(az_q ad app list --display-name "k8s-nightly-report-$RUN_ID" --query '[].id' -o tsv 2>/dev/null); do
    log "deleting leftover app registration k8s-nightly-report-$RUN_ID ($n)"
    az_q ad app delete --id "$n" || ok=1
  done
  if [[ "$(az_q group exists -n "$AZ_RG" 2>/dev/null)" == true ]]; then
    log "az group delete $AZ_RG (storage account + Key Vault)"
    az_q group delete -n "$AZ_RG" --yes || ok=1
  fi
  case "$(kv_deleted_state)" in
    present)
      log "az keyvault purge $KV_NAME (soft-deleted vault, no purge protection)"
      az_q keyvault purge -n "$KV_NAME" -l "$AZ_LOCATION" || ok=1 ;;
    gone) ;;
    *) log "could not tell whether $KV_NAME is soft-deleted (lookup failed): keeping the run record"; ok=1 ;;
  esac
  # Read back: nothing of this run is left.
  local rg app kv
  rg=$(az_q group exists -n "$AZ_RG" 2>/dev/null || echo unknown)
  app=$(az_q ad app list --display-name "k8s-nightly-report-$RUN_ID" --query 'length(@)' -o tsv 2>/dev/null || echo unknown)
  kv=$(kv_deleted_state)   # present | gone | unknown; only "gone" passes
  log "read back: resource group exists=$rg; app registrations=$app; vault $KV_NAME: $kv"
  [[ "$rg" == false && "$app" == 0 && "$kv" == gone ]] || ok=1   # unknown keeps RUN_ENV for a retry
  if [[ $ok -eq 0 ]]; then
    rm -f "$TF_KEYVAULT_TRUST/terraform.tfstate" "$TF_KEYVAULT_TRUST/terraform.tfstate.backup"
    rm -f "$RUN_ENV"
  fi
  return "$ok"
}
