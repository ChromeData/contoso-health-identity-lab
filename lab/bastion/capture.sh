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
#
# WHY a script and not Terraform: Bastion Premium costs $0.45 an hour (Azure
# retail price list, eastus2, 2026-11-07), about $324 a month if it is left
# up. The lab runs it only for a capture and deletes it straight after
# (program 2026-11-06: anything over ~$5/day is stopped when not in use).
# A Terraform flag would need two reviewed applies per capture. The script
# makes "up" and "down" one command each, as the operator. It owns ONLY the
# objects it creates, which carry the tag  purpose=bastion-capture.
#
# What "up" creates (in rg-identity-lab, next to DC01):
#   * subnet AzureBastionSubnet 10.42.250.0/26 in vnet-identity-lab (Bastion
#     requires that exact name and at least a /26). Terraform's VNet has no
#     inline subnets, so an extra subnet is not drift.
#   * public IP pip-bastion-capture (Standard, static): Bastion's front door.
#   * storage account stbstrec<random> + container "recordings": no public
#     blobs, no shared keys, no versioning, no immutability policy (Learn:
#     recording fails with versioning or immutability on). CORS allows GET
#     from the Bastion's own bst-*.bastion.azure.com name only, so the
#     portal's player can read the recordings.
#   * user-assigned identity id-bastion-recording with Storage Blob Data
#     Contributor on THAT container only: Bastion writes recordings with it,
#     no SAS token exists.
#   * bastion-capture: SKU Premium, enableSessionRecording, recordings to the
#     container through the identity (API 2026-03-01
#     sessionRecordingConfiguration). Native-client tunnelling stays OFF:
#     Learn says recording covers browser sessions only, so the native
#     client would be an unrecorded side door.
#   * PIM for Azure resources: adm-ava.lin becomes ELIGIBLE (not active) for
#     Reader on rg-identity-lab for 4 hours. Reader on the VM, its NIC and
#     the Bastion is all a Bastion connection needs (Learn, "Bastion
#     connection permissions"). She holds no Azure role before this.
#   * the reviewer adm-mei.tanaka gets Storage Blob Data Reader on the
#     container, Reader on the storage account and on the Bastion, ACTIVE for
#     4 hours (time-bound),
#     to play the recording back. The admin who was recorded cannot read or
#     delete her own recording.
#   * DC01 is started if it was deallocated; "down" deallocates it again
#     only in that case.
#
# What "down" removes: the Bastion, its public IP, the subnet, the identity
# and its role assignment, the PIM eligibility and the reviewer's
# assignments. The storage account and its recordings stay (pennies a month)
# until the owner deletes them: `capture.sh purge-recordings`.
#
# PLAYBACK NEEDS THE ACCOUNT KEY (seen live 2026-11-07, not what Learn says):
# Learn says viewers need Storage Blob Data Reader. The portal's player
# instead calls storageAccounts/listKeys (403 without it) and builds an
# account-key SAS, which also needs shared-key access ON. So `playback-on`
# turns shared-key access on and gives the reviewer "Storage Account Key
# Operator Service Role" for 1 hour; `down` turns shared-key access off again.
# The cost: for that hour the reviewer could also delete recordings. Production
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
RG="rg-identity-lab"
LOC="eastus2"
VNET="vnet-identity-lab"
SUBNET_PREFIX="10.42.250.0/26"
BASTION="bastion-capture"
PIP="pip-bastion-capture"
UAMI="id-bastion-recording"
CONTAINER="recordings"
VM="vm-dc01"
ADMIN_UPN="adm-ava.lin@contosohealthlab.onmicrosoft.com"
REVIEWER_UPN="adm-mei.tanaka@contosohealthlab.onmicrosoft.com"
STATE="${BASTION_CAPTURE_STATE:-$HOME/.contoso-operator/session/bastion-capture.json}"
API_BASTION="2026-03-01"
READER="acdd72a7-3385-48ef-bd42-f606fba81ae7"
BLOB_READER="2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
BLOB_CONTRIB="ba92f5b4-2d11-453d-a403-e96b0029c9fe"
TAGS=(purpose=bastion-capture owner=lab-operator delete-after=capture)
ARM="https://management.azure.com"
SCOPE_RG="/subscriptions/$SUB/resourceGroups/$RG"

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

oid_of() { az ad user show --id "$1" --query id -o tsv; }
guid() { python3 -I -c 'import uuid; print(uuid.uuid4())'; }

# PIM for Azure resources, through ARM roleEligibilityScheduleRequests /
# roleAssignmentScheduleRequests (api 2020-10-01). The operator is Owner on
# the subscription, which allows these admin requests.
pim_request() {  # pim_request <kind: Eligibility|Assignment> <scope> <roleGuid> <principalId> <AdminAssign|AdminRemove> <justification>
  local kind="$1" scope="$2" role="$3" pid="$4" type="$5" why="$6" path
  [[ "$kind" == Eligibility ]] && path=roleEligibilityScheduleRequests || path=roleAssignmentScheduleRequests
  local body
  body="$(python3 -I -c 'import json,sys,datetime
sub,scope,role,pid,typ,why=sys.argv[1:7]
p={"principalId":pid,"roleDefinitionId":f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{role}",
   "requestType":typ,"justification":why}
if typ=="AdminAssign":
  p["scheduleInfo"]={"startDateTime":datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "expiration":{"type":"AfterDuration","duration":"PT"+sys.argv[7]+"H"}}
print(json.dumps({"properties":p}))' "$SUB" "$scope" "$role" "$pid" "$type" "$why" "${KEY_HOURS:-4}")"
  az rest --method PUT --url "$ARM$scope/providers/Microsoft.Authorization/$path/$(guid)?api-version=2020-10-01" \
    --body "$body" --query 'properties.status' -o tsv
}

# grant <label> <pim_request args...>: run one PIM request, log it, and stop
# the run unless Azure accepted it. (A grant inside $(...) in a log line would
# hide a refusal: log would still succeed.)
grant() {
  local label="$1"; shift
  local st
  st="$(pim_request "$@" 2>&1 | tail -1)" || die "$label: Azure refused the request (${st:0:200})"
  case "$st" in
    Provisioned|Granted|PendingProvisioning|PendingAdminDecision|ScheduleCreated) log "$label: $st" ;;
    *) die "$label: unexpected status '${st:0:200}'" ;;
  esac
}
# revoke <label> <pim_request args...>: AdminRemove; "already gone" is fine,
# anything else is reported (the read-back below then decides success).
revoke() {
  local label="$1"; shift
  local out
  if out="$(pim_request "$@" 2>&1)"; then log "$label: removed ($out)"
  elif grep -qiE 'RoleAssignmentDoesNotExist|RoleEligibilityScheduleNotFound|does not exist|NotFound' <<<"$out"; then log "$label: already gone"
  else echo "WARNING: $label: ${out:0:200}" >&2; fi
}
# Ownership: the script only adopts or deletes objects tagged purpose=bastion-capture.
tag_of() { az resource show --ids "$1" --query 'tags.purpose' -o tsv 2>/dev/null || true; }

bastion_state() { az rest --url "$ARM$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" \
  --query 'properties.provisioningState' -o tsv 2>/dev/null || echo absent; }

cmd_status() {
  log "Bastion: $(bastion_state)"
  log "DC01: $(az vm get-instance-view -g "$RG" -n "$VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].displayStatus | [0]" -o tsv)"
  log "Storage: $(state_get storage)   state file: $STATE"
}

cmd_up() {
  local s
  # --- DC01 --------------------------------------------------------------------
  local power; power="$(az vm get-instance-view -g "$RG" -n "$VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code | [0]" -o tsv)"
  if [[ "$power" != "PowerState/running" ]]; then
    state_set dc01_started_by_capture yes
    s=$(date +%s); log "DC01 is $power: starting it (deallocated again by 'down')"
    az vm start -g "$RG" -n "$VM" -o none
    log "DC01 running ($(( $(date +%s) - s )) s)"
  else
    [[ -n "$(state_get dc01_started_by_capture)" ]] || state_set dc01_started_by_capture no
    log "DC01 already running: 'down' will leave it running"
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
  local pip_id="$SCOPE_RG/providers/Microsoft.Network/publicIPAddresses/$PIP"
  if az network public-ip show -g "$RG" -n "$PIP" -o none 2>/dev/null; then
    [[ "$(tag_of "$pip_id")" == bastion-capture ]] || die "$PIP exists without tag purpose=bastion-capture: not adopting it"
  else
    az network public-ip create -g "$RG" -n "$PIP" -l "$LOC" --sku Standard --allocation-method Static --tags "${TAGS[@]}" -o none
  fi
  if [[ "$(bastion_state)" != absent ]]; then
    [[ "$(tag_of "$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION")" == bastion-capture ]] \
      || die "$BASTION exists without tag purpose=bastion-capture: not adopting it"
  fi
  log "Subnet $SUBNET_PREFIX and public IP ready ($(( $(date +%s) - s )) s)"

  # --- Storage + identity --------------------------------------------------------
  s=$(date +%s)
  local st; st="$(state_get storage)"
  if [[ -z "$st" ]]; then st="stbstrec$(openssl rand -hex 4)"; state_set storage "$st"; fi
  az storage account show -g "$RG" -n "$st" -o none 2>/dev/null \
    || az storage account create -g "$RG" -n "$st" -l "$LOC" --sku Standard_LRS --kind StorageV2 \
         --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false \
         --https-only true --tags "${TAGS[@]}" -o none
  local st_id; st_id="$(az storage account show -g "$RG" -n "$st" --query id -o tsv)"
  az rest --method PUT --url "$ARM$st_id/blobServices/default/containers/$CONTAINER?api-version=2023-05-01" \
    --body '{"properties":{"publicAccess":"None"}}' -o none
  az identity show -g "$RG" -n "$UAMI" -o none 2>/dev/null \
    || az identity create -g "$RG" -n "$UAMI" -l "$LOC" --tags "${TAGS[@]}" -o none
  local uami_id uami_pid
  uami_id="$(az identity show -g "$RG" -n "$UAMI" --query id -o tsv)"
  uami_pid="$(az identity show -g "$RG" -n "$UAMI" --query principalId -o tsv)"
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
sub,rg,vnet,pip,uami,st,ct,loc=sys.argv[1:9]
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
      "publicIPAddress":{"id":f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/publicIPAddresses/{pip}"}}}]}}))' \
    "$SUB" "$RG" "$VNET" "$PIP" "$uami_id" "$st" "$CONTAINER" "$LOC")"
  if [[ "$(bastion_state)" != Succeeded ]]; then
    log "Creating $BASTION (Premium, session recording on); Learn says about 10 minutes"
    az rest --method PUT --url "$ARM$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" \
      --body "$body" -o none
    local st_b
    for _ in $(seq 1 120); do
      st_b="$(bastion_state)"
      [[ "$st_b" == Succeeded || "$st_b" == Failed ]] && break
      sleep 15
    done
    [[ "$st_b" == Succeeded ]] || die "Bastion provisioningState is $st_b"
  fi
  local dns; dns="$(az rest --url "$ARM$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" --query 'properties.dnsName' -o tsv)"
  state_set bastion_dns "$dns"
  log "Bastion $BASTION Succeeded, $dns ($(( $(date +%s) - s )) s); billing at \$0.45/h starts now"
  # Read back what Learn requires: Premium, recording on, the container.
  az rest --url "$ARM$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION?api-version=$API_BASTION" \
    --query '{sku:sku.name, recording:properties.enableSessionRecording, container:properties.sessionRecordingConfiguration.blobContainerUri, tunneling:properties.enableTunneling}' -o json

  # CORS: the portal's player reads blobs from the browser, origin = the Bastion.
  az rest --method PUT --url "$ARM$st_id/blobServices/default?api-version=2023-05-01" --body "$(python3 -I -c 'import json,sys
print(json.dumps({"properties":{"isVersioningEnabled":False,"cors":{"corsRules":[{"allowedOrigins":["https://"+sys.argv[1]],
 "allowedMethods":["GET"],"allowedHeaders":["*"],"exposedHeaders":["*"],"maxAgeInSeconds":86400}]}}}))' "$dns")" -o none
  log "CORS: GET from https://$dns only"

  # --- Access: PIM-eligible admin, time-bound reviewer ---------------------------------
  local admin_oid reviewer_oid bastion_id
  admin_oid="$(oid_of "$ADMIN_UPN")"; reviewer_oid="$(oid_of "$REVIEWER_UPN")"
  bastion_id="$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION"
  grant "PIM: $ADMIN_UPN eligible for Reader on $RG (4 h)" Eligibility "$SCOPE_RG" "$READER" "$admin_oid" AdminAssign 'Bastion capture: Tier-0 DC01 session through PIM (lab/bastion)'
  grant "Reviewer: $REVIEWER_UPN active Storage Blob Data Reader on the container (4 h)" Assignment "$ct_scope" "$BLOB_READER" "$reviewer_oid" AdminAssign 'Bastion capture: play back the recording (lab/bastion)'
  # The portal's Session recordings blade also reads the storage account itself
  # (management plane): without Reader there it shows "Storage account not
  # found" and 0 recordings (seen live 2026-11-07).
  grant "Reviewer: $REVIEWER_UPN active Reader on $st (4 h)" Assignment "$st_id" "$READER" "$reviewer_oid" AdminAssign 'Bastion capture: Session recordings reads the storage account (lab/bastion)'
  grant "Reviewer: $REVIEWER_UPN active Reader on $BASTION (4 h)" Assignment "$bastion_id" "$READER" "$reviewer_oid" AdminAssign 'Bastion capture: open Session recordings (lab/bastion)'
  state_set up_at "$(date -u +%FT%TZ)"
  log "UP. Next: node lab/bastion/prove.mjs; then capture.sh down"
}

cmd_down() {
  local s0; s0=$(date +%s)
  local admin_oid reviewer_oid st st_id ct_scope bastion_id
  admin_oid="$(oid_of "$ADMIN_UPN")"; reviewer_oid="$(oid_of "$REVIEWER_UPN")"
  st="$(state_get storage)"
  bastion_id="$SCOPE_RG/providers/Microsoft.Network/bastionHosts/$BASTION"
  # Bastion first: it is the one that costs money.
  if [[ "$(bastion_state)" != absent ]]; then
    [[ "$(tag_of "$bastion_id")" == bastion-capture ]] || die "$BASTION has no tag purpose=bastion-capture: not deleting someone else's Bastion"
    log "Deleting $BASTION"
    az rest --method DELETE --url "$ARM$bastion_id?api-version=$API_BASTION" -o none
    for _ in $(seq 1 80); do [[ "$(bastion_state)" == absent ]] && break; sleep 15; done
    [[ "$(bastion_state)" == absent ]] || die "Bastion still present: delete it by hand NOW (it bills \$0.45/h)"
  fi
  log "Bastion gone ($(( $(date +%s) - s0 )) s since 'down' started)"
  local pip_id="$SCOPE_RG/providers/Microsoft.Network/publicIPAddresses/$PIP"
  if az network public-ip show -g "$RG" -n "$PIP" -o none 2>/dev/null; then
    if [[ "$(tag_of "$pip_id")" == bastion-capture ]]; then az network public-ip delete -g "$RG" -n "$PIP" -o none
    else echo "WARNING: $PIP has no capture tag: left alone" >&2; fi
  fi
  if [[ "$(state_get subnet_created_by_capture)" == yes ]]; then
    az network vnet subnet delete -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet -o none 2>/dev/null || true
    az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet -o none 2>/dev/null || state_set subnet_created_by_capture no
  else
    log "AzureBastionSubnet was not created by this script: left alone"
  fi
  if [[ -n "$st" ]]; then
    st_id="$(az storage account show -g "$RG" -n "$st" --query id -o tsv 2>/dev/null || true)"
    ct_scope="$st_id/blobServices/default/containers/$CONTAINER"
  fi
  local uami_pid; uami_pid="$(az identity show -g "$RG" -n "$UAMI" --query principalId -o tsv 2>/dev/null || true)"
  if [[ -n "$uami_pid" && -n "${ct_scope:-}" ]]; then
    # shellcheck disable=SC2046  # one id per word, on purpose
    az role assignment delete --ids $(az role assignment list --scope "$ct_scope" --query "[?principalId=='$uami_pid'].id" -o tsv) -o none 2>/dev/null || true
  fi
  az identity delete -g "$RG" -n "$UAMI" -o none 2>/dev/null || true
  # Access: remove before the 4 h expiry. AdminRemove fails harmlessly if already gone.
  revoke "Admin eligibility" Eligibility "$SCOPE_RG" "$READER" "$admin_oid" AdminRemove 'Bastion capture over'
  if [[ -n "${ct_scope:-}" ]]; then
    revoke "Reviewer blob reader" Assignment "$ct_scope" "$BLOB_READER" "$reviewer_oid" AdminRemove 'Bastion capture over'
    revoke "Reviewer storage Reader" Assignment "$st_id" "$READER" "$reviewer_oid" AdminRemove 'Bastion capture over'
    revoke "Reviewer key operator" Assignment "$st_id" 81a9662b-bebf-436f-a333-f67b29880f12 "$reviewer_oid" AdminRemove 'Bastion capture over'
    [[ -n "$st_id" ]] && az storage account update --ids "$st_id" --allow-shared-key-access false -o none
  fi
  log "Public IP, subnet, identity, PIM eligibility and reviewer access removed"
  if [[ "$(state_get dc01_started_by_capture)" == yes ]]; then
    log "DC01 was started by 'up': deallocating it"
    az vm deallocate -g "$RG" -n "$VM" -o none
    state_set dc01_started_by_capture no
  fi
  # Read back.
  log "Read back: bastion=$(bastion_state) pip=$(az network public-ip show -g "$RG" -n "$PIP" --query name -o tsv 2>/dev/null || echo absent) subnet=$(az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n AzureBastionSubnet --query name -o tsv 2>/dev/null || echo absent) admin-eligibility=$(az rest --url "$ARM$SCOPE_RG/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&\$filter=principalId eq '$admin_oid'" --query 'length(value)' -o tsv)"
  # Read back the access the recording account could still give: fail unless
  # shared-key access is off and the reviewer holds nothing on it.
  if [[ -n "${st_id:-}" ]]; then
    local sk left
    sk="$(az storage account show --ids "$st_id" --query allowSharedKeyAccess -o tsv)"
    left="$(az role assignment list --scope "$st_id" --query "[?principalId=='$reviewer_oid'] | length(@)" -o tsv)"
    [[ "$sk" == false && "$left" == 0 ]] \
      || die "teardown incomplete on $st: allowSharedKeyAccess=$sk, reviewer role assignments left=$left (remove them by hand)"
    log "Read back: $st allowSharedKeyAccess=false, reviewer role assignments on it: 0"
  fi
  log "DOWN ($(( $(date +%s) - s0 )) s). Recordings kept in ${st:-?}/$CONTAINER (capture.sh purge-recordings deletes them)"
}

cmd_playback_on() {
  local st st_id reviewer_oid; st="$(state_get storage)"
  [[ -n "$st" ]] || die "no storage account in $STATE"
  st_id="$(az storage account show -g "$RG" -n "$st" --query id -o tsv)"
  reviewer_oid="$(oid_of "$REVIEWER_UPN")"
  az storage account update --ids "$st_id" --allow-shared-key-access true -o none
  log "Shared-key access ON for $st (the portal player builds an account-key SAS)"
  KEY_HOURS=1 grant "Reviewer: Storage Account Key Operator Service Role on $st (1 h)" Assignment "$st_id" 81a9662b-bebf-436f-a333-f67b29880f12 "$reviewer_oid" AdminAssign 'Bastion capture: the portal player calls listKeys (lab/bastion)'
}

cmd_purge_recordings() {
  local st; st="$(state_get storage)"
  [[ -n "$st" ]] || die "no storage account in $STATE"
  [[ "$(bastion_state)" == absent ]] || die "run 'down' first"
  az storage account delete -g "$RG" -n "$st" --yes -o none
  state_set storage ""
  log "Deleted $st and its recordings"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  playback-on) cmd_playback_on ;;
  purge-recordings) cmd_purge_recordings ;;
  *) echo "usage: capture.sh up|playback-on|down|status|purge-recordings" >&2; exit 2 ;;
esac
