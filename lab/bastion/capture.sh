#!/usr/bin/env bash
# =============================================================================
# capture.sh - Azure Bastion Premium with session recording, ONLY while
# capturing.
#
#   lab/scripts/operator/op bash lab/bastion/capture.sh up      # ~10-15 min
#   node lab/bastion/prove.mjs                                  # the proof (as the admins)
#   lab/scripts/operator/op bash lab/bastion/capture.sh down    # ~5-10 min
#   lab/scripts/operator/op bash lab/bastion/capture.sh playback-on  # just before the reviewer plays it
#   lab/scripts/operator/op bash lab/bastion/capture.sh status
#   lab/scripts/operator/op bash lab/bastion/capture.sh owner-steps  # prints the one-time owner step
#
# WHY a script and not Terraform: Bastion Premium costs $0.45 an hour (Azure
# retail price list, eastus2, 2026-11-07), about $324 a month if it is left
# up. The lab runs it only for a capture and deletes it straight after
# (program 2026-11-06: anything over ~$5/day is stopped when not in use).
# A Terraform flag would need two reviewed applies per capture. The script
# makes "up" and "down" one command each, as the operator. It owns ONLY the
# objects it creates, which carry the tag  purpose=bastion-capture.
#
# ACCESS MODEL SINCE ADR 0030 (2026-11-08). The operator is read-only
# between owner-opened write sessions and can write no role assignment or
# PIM request outside the sandbox. So:
#   * the operator runs `up`/`down` during a write session: the session role
#     (subscription) covers the subnet in the lab VNet and starting DC01; the
#     sandbox grants (envs/operator sandbox.tf) cover everything else, which
#     lives in rg-lab-sandbox;
#   * the ADMIN is adm-presenter through its EXISTING PIM-Demo-Readers
#     eligibility (PIM for Groups; the group holds Reader on the subscription,
#     which is all a Bastion connection needs). No new eligibility is made;
#   * the REVIEWER (adm-mei.tanaka) is made ELIGIBLE once, by the OWNER, for
#     Reader, Storage Blob Data Reader and Storage Account Key Operator
#     Service Role on rg-lab-sandbox (`capture.sh owner-steps` prints the
#     exact commands). She activates them herself, with a reason, per capture.
#
# What "up" creates:
#   * subnet AzureBastionSubnet 10.42.250.0/26 in vnet-identity-lab (rg-
#     identity-lab: Bastion requires that exact name and at least a /26).
#     Terraform's VNet has no inline subnets, so an extra subnet is not drift.
#   * in rg-lab-sandbox, all tagged purpose=bastion-capture:
#     - public IP pip-bastion-capture (Standard, static): Bastion's front door;
#     - storage account stbstrec<random> + container "recordings": no public
#       blobs, no shared keys, no versioning, no immutability policy (Learn:
#       recording fails with versioning or immutability on). CORS allows GET
#       from the Bastion's own bst-*.bastion.azure.com name only;
#     - user-assigned identity id-bastion-recording with Storage Blob Data
#       Contributor on THAT container only (a data role the sandbox grant may
#       assign): Bastion writes recordings with it, no SAS token exists;
#     - bastion-capture: SKU Premium, enableSessionRecording, recordings to
#       the container through the identity (API 2026-03-01
#       sessionRecordingConfiguration). Native-client tunnelling stays OFF:
#       Learn says recording covers browser sessions only.
#   * DC01 is started through preflight.sh if it is off; nothing here ever
#     deallocates it (the leaver helper owns DC01's start/stop, program
#     2026-11-08).
#
# What "down" removes: the Bastion, its public IP, the subnet, the identity
# and its role assignment; shared-key access back off. The storage account
# and its recordings stay (pennies a month) until `capture.sh
# purge-recordings`. The reviewer's eligibilities stay (owner-managed).
#
# PLAYBACK NEEDS THE ACCOUNT KEY (seen live 2026-11-07, not what Learn says):
# Learn says viewers need Storage Blob Data Reader. The portal's player
# instead calls storageAccounts/listKeys (403 without it) and builds an
# account-key SAS, which also needs shared-key access ON. So `playback-on`
# turns shared-key access on; the reviewer activates her eligible "Storage
# Account Key Operator Service Role" for the playback; `down` turns shared-key
# access off again. The cost: while that role is active the reviewer could
# also delete recordings. Production
# answer: keep recordings in a separate account with an immutable copy
# (blob inventory or object replication to a WORM container), because the
# recording container itself must have no immutability policy (Learn).
#
# Nothing here is secret: no passwords, keys or SAS tokens are created.
# =============================================================================
set -euo pipefail
export PYTHONWARNINGS=ignore   # az 2.91 on Python 3.14 prints a SyntaxWarning; noise

SUB="de0b2a93-1c62-47b3-aaaf-1bdd1939a274"
TENANT="86a2e327-4951-4348-a3c4-6f4b79ffd8f2"
RG="rg-identity-lab"                 # DC01 and the VNet (the subnet goes here)
SANDBOX="${BASTION_SANDBOX_RG:-rg-lab-sandbox}"   # everything else (envs/operator sandbox.tf)
LOC="eastus2"
VNET="vnet-identity-lab"
SUBNET_PREFIX="10.42.250.0/26"
BASTION="bastion-capture"
PIP="pip-bastion-capture"
UAMI="id-bastion-recording"
CONTAINER="recordings"
VM="vm-dc01"
# The admin is adm-presenter through its existing PIM-Demo-Readers
# eligibility; prove.mjs signs in as it. This script grants it nothing.
REVIEWER_UPN="adm-mei.tanaka@contosohealthlab.onmicrosoft.com"
STATE="${BASTION_CAPTURE_STATE:-$HOME/.contoso-operator/session/bastion-capture.json}"
API_BASTION="2026-03-01"
BLOB_CONTRIB="ba92f5b4-2d11-453d-a403-e96b0029c9fe"
TAGS=(purpose=bastion-capture owner=lab-operator delete-after=capture)
ARM="https://management.azure.com"
SCOPE_SB="/subscriptions/$SUB/resourceGroups/$SANDBOX"


T0=$(date +%s)
log() { printf '[%s +%4ss] %s\n' "$(date -u +%H:%M:%SZ)" "$(( $(date +%s) - T0 ))" "$*"; }
die() { echo "STOPPED: $*" >&2; exit 2; }
state_get() { python3 -I -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2],""))
except FileNotFoundError: print("")' "$STATE" "$1"; }
state_set() { python3 -I -c 'import json,sys,os
p=sys.argv[1]
try: d=json.load(open(p))
except FileNotFoundError: d={}
d[sys.argv[2]]=sys.argv[3]
os.makedirs(os.path.dirname(p),exist_ok=True)
json.dump(d,open(p,"w"),indent=1)' "$STATE" "$1" "$2"; }

acct="$(az account show --query '[id, tenantId]' -o tsv | tr '\n' ' ')"
read -r sub tenant <<<"$acct"
[[ "$sub" == "$SUB" && "$tenant" == "$TENANT" ]] || die "not the lab subscription/tenant (run under lab/scripts/operator/op)"

# One line per milestone in the shared progress log (program rule).
progress() {
  local f="${CONTOSO_PROGRESS_LOG:-$HOME/contoso-demo/readiness/progress.log}"
  [[ -f "$f" ]] && printf '%s | bastion-capture | %s\n' "$(date -u +%FT%TZ)" "$*" >> "$f" || true
}

oid_of() { az ad user show --id "$1" --query id -o tsv; }
guid() { python3 -I -c 'import uuid; print(uuid.uuid4())'; }

# Preflight (ADR 0030): the write session must be open. The session role on
# the subscription (subnet, DC01 start) and both sandbox grants must be active.
need_session() {
  local op_oid sb roles sub_roles
  op_oid="$(az ad sp show --id "$(az account show --query user.name -o tsv)" --query id -o tsv)" \
    || die "cannot resolve the operator's object id"
  sb="$(az group show -n "$SANDBOX" --query id -o tsv 2>/dev/null)" \
    || die "sandbox resource group $SANDBOX not found: the owner applies envs/operator (sandbox.tf, ADR 0030)"
  roles="$(az role assignment list --assignee "$op_oid" --scope "$sb" --query '[].roleDefinitionName' -o tsv | sort -u | tr '\n' ',')"
  sub_roles="$(az role assignment list --assignee "$op_oid" --scope "/subscriptions/$SUB" --query '[].roleDefinitionName' -o tsv | sort -u | tr '\n' ',')"
  [[ "$roles" == *"Contributor,"* && "$roles" == *"Role Based Access Control Administrator,"* && "$sub_roles" == *"Contoso Lab Operator Session,"* ]] \
    || die "no operator write session (sandbox roles: ${roles:-none}; subscription roles: ${sub_roles:-none}): the owner opens one (envs/operator operator_write_session, ADR 0030)"
  log "Write session: session role on the subscription, Contributor + constrained RBAC Administrator on $SANDBOX"
}

# Ownership: the script only adopts or deletes objects tagged purpose=bastion-capture.
tag_of() { az resource show --ids "$1" --query 'tags.purpose' -o tsv 2>/dev/null || true; }

bastion_state() { az rest --url "$ARM$SCOPE_SB/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" \
  --query 'properties.provisioningState' -o tsv 2>/dev/null || echo absent; }

cmd_status() {
  log "Bastion: $(bastion_state)"
  log "DC01: $(az vm get-instance-view -g "$RG" -n "$VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].displayStatus | [0]" -o tsv)"
  log "Storage: $(state_get storage)   state file: $STATE"
}

cmd_up() {
  need_session
  local s
  # --- DC01 --------------------------------------------------------------------
  # DC01 (program 2026-11-08): the leaver helper OWNS DC01's start and
  # deallocate. Others may start it only through preflight.sh, and NEVER
  # deallocate it. So this script starts it that way if it is off, logs
  # "DC01 needed by" / "done" in progress.log, and 'down' never stops it.
  local power; power="$(az vm get-instance-view -g "$RG" -n "$VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code | [0]" -o tsv)"
  progress "DC01 needed by bastion-capture (lab/bastion/capture.sh up)"
  if [[ "$power" != "PowerState/running" ]]; then
    s=$(date +%s); log "DC01 is $power: starting it through preflight.sh (it will NOT be deallocated by this script)"
    bash "$(cd "$(dirname "${BASH_SOURCE[0]}")/../scripts/demo" && pwd)/preflight.sh" >/dev/null 2>&1 || true
    power="$(az vm get-instance-view -g "$RG" -n "$VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code | [0]" -o tsv)"
    [[ "$power" == "PowerState/running" ]] || die "DC01 is still $power after preflight.sh"
    log "DC01 running ($(( $(date +%s) - s )) s)"
  else
    log "DC01 already running"
  fi

  # --- Network -----------------------------------------------------------------
  s=$(date +%s)
  # A subnet has no tags, so ownership is tracked in the state file: adopt an
  # existing AzureBastionSubnet only if an earlier 'up' of this script made it.
  if az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet -o none 2>/dev/null; then
    [[ "$(state_get subnet_created_by_capture)" == yes ]] \
      || die "AzureBastionSubnet already exists and this script did not create it: not adopting it (a Bastion someone else runs?)"
  else
    az network vnet subnet create -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet --address-prefixes "$SUBNET_PREFIX" -o none
    state_set subnet_created_by_capture yes
  fi
  local pip_id="$SCOPE_SB/providers/Microsoft.Network/publicIPAddresses/$PIP"
  if az network public-ip show -g "$SANDBOX" -n "$PIP" -o none 2>/dev/null; then
    [[ "$(tag_of "$pip_id")" == bastion-capture ]] || die "$PIP exists without tag purpose=bastion-capture: not adopting it"
  else
    az network public-ip create -g "$SANDBOX" -n "$PIP" -l "$LOC" --sku Standard --allocation-method Static --tags "${TAGS[@]}" -o none
  fi
  if [[ "$(bastion_state)" != absent ]]; then
    [[ "$(tag_of "$SCOPE_SB/providers/Microsoft.Network/bastionHosts/$BASTION")" == bastion-capture ]] \
      || die "$BASTION exists without tag purpose=bastion-capture: not adopting it"
  fi
  log "Subnet $SUBNET_PREFIX and public IP ready ($(( $(date +%s) - s )) s)"

  # --- Storage + identity --------------------------------------------------------
  s=$(date +%s)
  local st; st="$(state_get storage)"
  if [[ -z "$st" ]]; then st="stbstrec$(openssl rand -hex 4)"; state_set storage "$st"; fi
  az storage account show -g "$SANDBOX" -n "$st" -o none 2>/dev/null \
    || az storage account create -g "$SANDBOX" -n "$st" -l "$LOC" --sku Standard_LRS --kind StorageV2 \
         --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false \
         --https-only true --tags "${TAGS[@]}" -o none
  local st_id; st_id="$(az storage account show -g "$SANDBOX" -n "$st" --query id -o tsv)"
  az rest --method PUT --url "$ARM$st_id/blobServices/default/containers/$CONTAINER?api-version=2023-05-01" \
    --body '{"properties":{"publicAccess":"None"}}' -o none
  az identity show -g "$SANDBOX" -n "$UAMI" -o none 2>/dev/null \
    || az identity create -g "$SANDBOX" -n "$UAMI" -l "$LOC" --tags "${TAGS[@]}" -o none
  local uami_id uami_pid
  uami_id="$(az identity show -g "$SANDBOX" -n "$UAMI" --query id -o tsv)"
  uami_pid="$(az identity show -g "$SANDBOX" -n "$UAMI" --query principalId -o tsv)"
  local ct_scope="$st_id/blobServices/default/containers/$CONTAINER"
  # Filter on principalId, not --assignee: a brand-new identity is not yet in
  # Graph, and --assignee looks it up there (seen live: "Cannot find user or
  # service principal in graph database").
  [[ -n "$(az role assignment list --scope "$ct_scope" --role "$BLOB_CONTRIB" --query "[?principalId=='$uami_pid'].id | [0]" -o tsv)" ]] \
    || az role assignment create --assignee-object-id "$uami_pid" --assignee-principal-type ServicePrincipal \
         --role "$BLOB_CONTRIB" --scope "$ct_scope" -o none
  log "Storage $st/$CONTAINER and identity $UAMI ready ($(( $(date +%s) - s )) s)"

  # --- Bastion Premium -------------------------------------------------------------
  s=$(date +%s)
  local body
  body="$(python3 -I -c 'import json,sys
sub,rg,vnet,pip,uami,st,ct,loc,sb=sys.argv[1:10]
print(json.dumps({"location":loc,
 "tags":{"purpose":"bastion-capture","owner":"lab-operator","delete-after":"capture"},
 "sku":{"name":"Premium"},
 "identity":{"type":"UserAssigned","userAssignedIdentities":{uami:{}}},
 "properties":{
   "enableSessionRecording":True,
   "sessionRecordingConfiguration":{"identity":{"type":"UserAssigned","userAssignedIdentityId":uami},
                                    "blobContainerUri":f"https://{st}.blob.core.windows.net/{ct}"},
   "enableTunneling":False, "enableShareableLink":False, "enableIpConnect":False, "enableFileCopy":False,
   "ipConfigurations":[{"name":"ipconfig1","properties":{
      "subnet":{"id":f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/AzureBastionSubnet"},
      "publicIPAddress":{"id":f"/subscriptions/{sub}/resourceGroups/{sb}/providers/Microsoft.Network/publicIPAddresses/{pip}"}}}]}}))' \
    "$SUB" "$RG" "$VNET" "$PIP" "$uami_id" "$st" "$CONTAINER" "$LOC" "$SANDBOX")"
  if [[ "$(bastion_state)" != Succeeded ]]; then
    log "Creating $BASTION (Premium, session recording on); Learn says about 10 minutes"
    az rest --method PUT --url "$ARM$SCOPE_SB/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" \
      --body "$body" -o none
    local st_b
    for _ in $(seq 1 120); do
      st_b="$(bastion_state)"
      [[ "$st_b" == Succeeded || "$st_b" == Failed ]] && break
      sleep 15
    done
    [[ "$st_b" == Succeeded ]] || die "Bastion provisioningState is $st_b"
  fi
  local dns; dns="$(az rest --url "$ARM$SCOPE_SB/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" --query 'properties.dnsName' -o tsv)"
  state_set bastion_dns "$dns"
  log "Bastion $BASTION Succeeded, $dns ($(( $(date +%s) - s )) s); billing at \$0.45/h starts now"
  # Read back what Learn requires: Premium, recording on, the container.
  az rest --url "$ARM$SCOPE_SB/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" \
    --query '{sku:sku.name, recording:properties.enableSessionRecording, container:properties.sessionRecordingConfiguration.blobContainerUri, tunneling:properties.enableTunneling}' -o json

  # CORS: the portal's player reads blobs from the browser, origin = the Bastion.
  az rest --method PUT --url "$ARM$st_id/blobServices/default?api-version=2023-05-01" --body "$(python3 -I -c 'import json,sys
print(json.dumps({"properties":{"isVersioningEnabled":False,"cors":{"corsRules":[{"allowedOrigins":["https://"+sys.argv[1]],
 "allowedMethods":["GET"],"allowedHeaders":["*"],"exposedHeaders":["*"],"maxAgeInSeconds":86400}]}}}))' "$dns")" -o none
  log "CORS: GET from https://$dns only"

  # --- Access -------------------------------------------------------------------------
  # No grants here (ADR 0030): the admin uses adm-presenter's existing
  # PIM-Demo-Readers eligibility; the reviewer's eligibilities are an owner
  # step (capture.sh owner-steps). Check the reviewer is eligible, so the
  # playback does not fail at the end of a paid capture.
  local reviewer_oid n
  reviewer_oid="$(oid_of "$REVIEWER_UPN")"
  n="$(az rest --url "$ARM$SCOPE_SB/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&\$filter=principalId eq '$reviewer_oid'" --query 'length(value)' -o tsv 2>/dev/null || echo 0)"
  if [[ "${n:-0}" -ge 3 ]]; then log "Reviewer $REVIEWER_UPN: $n eligible roles on $SANDBOX (owner step done)"
  else echo "WARNING: reviewer $REVIEWER_UPN has ${n:-0} eligible roles on $SANDBOX, 3 expected: run 'capture.sh owner-steps' and have the owner do them before the playback" >&2; fi
  state_set up_at "$(date -u +%FT%TZ)"
  log "UP. Next: node lab/bastion/prove.mjs; then capture.sh down"
}

cmd_down() {
  need_session
  local s0; s0=$(date +%s)
  local st st_id ct_scope bastion_id
  st="$(state_get storage)"
  bastion_id="$SCOPE_SB/providers/Microsoft.Network/bastionHosts/$BASTION"
  # Bastion first: it is the one that costs money.
  if [[ "$(bastion_state)" != absent ]]; then
    [[ "$(tag_of "$bastion_id")" == bastion-capture ]] || die "$BASTION has no tag purpose=bastion-capture: not deleting someone else's Bastion"
    log "Deleting $BASTION"
    az rest --method DELETE --url "$ARM$bastion_id?api-version=$API_BASTION" -o none
    for _ in $(seq 1 80); do [[ "$(bastion_state)" == absent ]] && break; sleep 15; done
    [[ "$(bastion_state)" == absent ]] || die "Bastion still present: delete it by hand NOW (it bills \$0.45/h)"
  fi
  log "Bastion gone ($(( $(date +%s) - s0 )) s since 'down' started)"
  local pip_id="$SCOPE_SB/providers/Microsoft.Network/publicIPAddresses/$PIP"
  if az network public-ip show -g "$SANDBOX" -n "$PIP" -o none 2>/dev/null; then
    if [[ "$(tag_of "$pip_id")" == bastion-capture ]]; then az network public-ip delete -g "$SANDBOX" -n "$PIP" -o none
    else echo "WARNING: $PIP has no capture tag: left alone" >&2; fi
  fi
  if [[ "$(state_get subnet_created_by_capture)" == yes ]]; then
    az network vnet subnet delete -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet -o none 2>/dev/null || true
    az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet -o none 2>/dev/null || state_set subnet_created_by_capture no
  else
    log "AzureBastionSubnet was not created by this script: left alone"
  fi
  if [[ -n "$st" ]]; then
    st_id="$(az storage account show -g "$SANDBOX" -n "$st" --query id -o tsv 2>/dev/null || true)"
    ct_scope="$st_id/blobServices/default/containers/$CONTAINER"
  fi
  local uami_pid; uami_pid="$(az identity show -g "$SANDBOX" -n "$UAMI" --query principalId -o tsv 2>/dev/null || true)"
  if [[ -n "$uami_pid" && -n "${ct_scope:-}" ]]; then
    # shellcheck disable=SC2046  # one id per word, on purpose
    az role assignment delete --ids $(az role assignment list --scope "$ct_scope" --query "[?principalId=='$uami_pid'].id" -o tsv) -o none 2>/dev/null || true
  fi
  az identity delete -g "$SANDBOX" -n "$UAMI" -o none 2>/dev/null || true
  [[ -n "${st_id:-}" ]] && az storage account update --ids "$st_id" --allow-shared-key-access false -o none
  log "Public IP, subnet, identity and its grant removed; shared-key access off"
  # Never deallocate DC01 (the leaver helper owns it): only say we are done.
  progress "done with DC01: bastion-capture (lab/bastion/capture.sh down); DC01 left running for its owner"
  # Read back.
  log "Read back: bastion=$(bastion_state) pip=$(az network public-ip show -g "$SANDBOX" -n "$PIP" --query name -o tsv 2>/dev/null || echo absent) subnet=$(az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet --query name -o tsv 2>/dev/null || echo absent) identity=$(az identity show -g "$SANDBOX" -n "$UAMI" --query name -o tsv 2>/dev/null || echo absent)"
  if [[ -n "${st_id:-}" ]]; then
    local sk
    sk="$(az storage account show --ids "$st_id" --query allowSharedKeyAccess -o tsv)"
    [[ "$sk" == false ]] || die "teardown incomplete on $st: allowSharedKeyAccess=$sk (turn it off by hand)"
    log "Read back: $st allowSharedKeyAccess=false"
  fi
  log "DOWN ($(( $(date +%s) - s0 )) s). Recordings kept in ${st:-?}/$CONTAINER (capture.sh purge-recordings deletes them)"
}

cmd_playback_on() {
  need_session
  local st st_id; st="$(state_get storage)"
  [[ -n "$st" ]] || die "no storage account in $STATE"
  st_id="$(az storage account show -g "$SANDBOX" -n "$st" --query id -o tsv)"
  az storage account update --ids "$st_id" --allow-shared-key-access true -o none
  log "Shared-key access ON for $st (the portal player builds an account-key SAS). The reviewer now activates her eligible Storage Account Key Operator Service Role (prove.mjs does it); 'down' turns shared-key access off."
}

cmd_owner_steps() {
  # Printed, never run: the OWNER does these once, as themselves (Cloud Shell
  # or the PIM blade). The operator cannot: since ADR 0030 it has no
  # Microsoft.Authorization write outside the sandbox's data-role delegation.
  local reviewer_oid; reviewer_oid="$(oid_of "$REVIEWER_UPN")"
  cat <<STEPS
OWNER STEP (once): make the reviewer $REVIEWER_UPN ELIGIBLE (not active) on $SANDBOX
for the three roles the playback needs. In the Azure portal: PIM > Azure resources >
$SANDBOX > Assignments > Add assignments > Eligible, or with az as the owner:

  for role in "Reader" "Storage Blob Data Reader" "Storage Account Key Operator Service Role"; do
    rid=\$(az role definition list --name "\$role" --query '[0].name' -o tsv)
    az rest --method PUT \\
      --url "https://management.azure.com$SCOPE_SB/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/\$(uuidgen)?api-version=2020-10-01" \\
      --body "{\"properties\":{\"principalId\":\"$reviewer_oid\",\"roleDefinitionId\":\"/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/\$rid\",\"requestType\":\"AdminAssign\",\"justification\":\"Bastion recording reviewer (lab/bastion, ADR 0036)\",\"scheduleInfo\":{\"expiration\":{\"type\":\"AfterDuration\",\"duration\":\"P90D\"}}}}"
  done

Why each: Reader (the Bastion's Session recordings blade, and the storage
account it reads), Storage Blob Data Reader (list the recordings), Storage
Account Key Operator Service Role (the portal player calls listKeys).
The ADMIN needs no owner step: adm-presenter's PIM-Demo-Readers eligibility
already exists (Reader on the subscription).
STEPS
}

cmd_purge_recordings() {
  local st; st="$(state_get storage)"
  [[ -n "$st" ]] || die "no storage account in $STATE"
  [[ "$(bastion_state)" == absent ]] || die "run 'down' first"
  need_session
  az storage account delete -g "$SANDBOX" -n "$st" --yes -o none
  state_set storage ""
  log "Deleted $st and its recordings"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  playback-on) cmd_playback_on ;;
  owner-steps) cmd_owner_steps ;;
  purge-recordings) cmd_purge_recordings ;;
  *) echo "usage: capture.sh up|playback-on|down|status|owner-steps|purge-recordings" >&2; exit 2 ;;
esac
