#!/usr/bin/env bash
# =============================================================================
# close-build-noise.sh - close the Sentinel incidents (and their ServiceNow
# tickets) that building and testing the lab raised, right before recording,
# so the incident queue on camera shows the demo and nothing else.
#
#   lab/scripts/demo/close-build-noise.sh                         # DRY RUN: lists, changes nothing
#   lab/scripts/demo/close-build-noise.sh --numbers 32-50 --since 2026-11-05T00:00Z --until 2026-11-05T13:00Z
#   lab/scripts/demo/close-build-noise.sh ... --lead-ok 28,27 --apply
#
# Runs as the lab operator (lab/scripts/operator/op): Owner on rg-identity-lab
# covers Sentinel incidents; Graph Directory.Read.All resolves an entity's
# object id to its UPN. ServiceNow tickets are resolved as the integration
# user svc.sentinel (itil: checked live 2026-11-05 - it resolved a throwaway
# ticket, INC0010011), password from the operator Keychain.
#
# WHICH INCIDENTS (open ones only; --numbers narrows the set first)
#   An incident is CLOSED when either selector holds:
#     entities - it has Account entities and EVERY one is a lab test or lab
#                admin account (test-user-*, itdr-drill-*, adm-*, bg-admin-NN,
#                svc-* in the lab's two domains);
#     window   - it was created inside --since / --until (UTC, ISO 8601).
#   It is held as NEEDS LEAD, and never closed unless its number is in
#   --lead-ok, when any Account entity is the OWNER's account or an account
#   that is not a lab test/admin account (a real person): the lead looks at
#   it first. An incident no selector picks is left alone (SKIP).
#   An Account entity whose name cannot be read is "unknown" = NEEDS LEAD
#   (fail closed): never auto-closed.
#
# WHAT --apply DOES, per incident it closes
#   1. a one-line comment with the reason, then status Closed,
#      BenignPositive / SuspiciousButExpected;
#   2. every open ServiceNow ticket whose correlation_id is the incident's
#      name (the notify and containment playbooks set it) is resolved:
#      state 6 (Resolved), close_code "Resolved - Fixed Without Action" (a
#      PDI choice, read live), close notes = the same reason.
#   3. reads both back; any miss is reported and the exit code is 1.
#   If ServiceNow refuses the update (401/403), the run stops and says which
#   role svc.sentinel needs (itil).
#
# Env overrides (tests): CONTOSO_OP, NOISE_CURL, NOISE_SECURITY,
# NOISE_SN_INSTANCE, NOISE_NOW (ISO, for --until default).
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OP="${CONTOSO_OP:-$REPO/lab/scripts/operator/op}"
CURL="${NOISE_CURL:-curl}"
SECURITY="${NOISE_SECURITY:-security}"
SN_INSTANCE="${NOISE_SN_INSTANCE:-dev459905}"
SN_USER="svc.sentinel"
SN_KEYCHAIN="contoso-lab-servicenow-sentinel"
RG="rg-identity-lab"
WS_NAME="loga-idlab"
API="api-version=2024-09-01"
ARM="https://management.azure.com"
GRAPH="https://graph.microsoft.com/v1.0"
LAB_RE='^(test-user-[a-z0-9]+|itdr-drill-[0-9a-z-]+|adm-[a-z0-9.-]+|bg-admin-[0-9]{2}|svc-[a-z0-9.-]+)@(contosohealthlab\.com|contosohealthlab\.onmicrosoft\.com)$'
OWNER_RE='^michaelwilliams@contosohealthlab\.onmicrosoft\.com$'
# ServiceNow close code: a PDI choice (sys_choice incident.close_code, read
# 2026-11-05). The value carries an en dash; JSON writes it as – so this
# file stays ASCII.
CLOSE_CODE_JSON='"Resolved – Fixed Without Action"'

usage() { sed -n '6,9p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die() { printf 'close-build-noise: %s\n' "$1" >&2; exit "${2:-1}"; }
say() { printf '%s\n' "$*"; }

NUMBERS=""; SINCE=""; UNTIL=""; LEAD_OK=""; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --numbers) NUMBERS="${2:-}"; shift 2 ;;
    --since) SINCE="${2:-}"; shift 2 ;;
    --until) UNTIL="${2:-}"; shift 2 ;;
    --lead-ok) LEAD_OK="${2:-}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1" 2 ;;
  esac
done
[ -z "$NUMBERS" ] || [[ "$NUMBERS" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || die "--numbers takes 32-50,52 style lists" 2
[ -z "$LEAD_OK" ] || [[ "$LEAD_OK" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "--lead-ok takes 28,27 style lists" 2
for t in "$SINCE" "$UNTIL"; do
  [ -z "$t" ] || [[ "$t" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?Z$ ]] || die "--since / --until take UTC times like 2026-11-05T09:00Z" 2
done
[ -n "$SINCE" ] || [ -z "$UNTIL" ] || die "--until needs --since" 2

ERR="$(mktemp "${TMPDIR:-/tmp}/noise-err.XXXXXX")"
PAGES="$(mktemp -d "${TMPDIR:-/tmp}/noise-pages.XXXXXX")"
trap 'rm -rf "$ERR" "$PAGES"' EXIT

# rest METHOD URL [--stdin]: exit 0 ok, 4 not found, 1 anything else.
rest() {
  local method="$1" url="$2"; shift 2
  local args=(az rest --method "$method" --url "$url" --only-show-errors -o json)
  if [ "${1:-}" = "--stdin" ]; then args+=(--headers Content-Type=application/json --body @/dev/stdin); fi
  if "$OP" "${args[@]}" 2>"$ERR"; then return 0; fi
  if grep -Eq 'Not ?Found|ResourceNotFound|Request_ResourceNotFound' "$ERR"; then return 4; fi
  sed 's/^/  az: /' "$ERR" >&2
  return 1
}
py() { python3 -c "import json,sys
_t='' if sys.stdin.isatty() else sys.stdin.read()
d=json.loads(_t) if _t.strip() else None
$1"; }
# Every page of an ARM list (nextLink), as {"value": [...]}.
rest_all() {
  local url="$1" n=0 page
  rm -f "$PAGES"/*
  while [ -n "$url" ]; do
    n=$((n + 1)); [ $n -le 200 ] || return 1
    page="$(rest GET "$url")" || return $?
    printf '%s' "$page" >"$PAGES/$(printf '%05d' $n).json"
    url="$(printf '%s' "$page" | py 'print((d or {}).get("nextLink") or "")')"
  done
  python3 -c 'import glob,json,sys
v=[]
for f in sorted(glob.glob(sys.argv[1]+"/*.json")): v+=json.load(open(f)).get("value") or []
print(json.dumps({"value":v}))' "$PAGES"
}
in_list() {  # in_list N "32-50,52"
  NUM="$1" SPEC="$2" python3 -c 'import os,sys
n=int(os.environ["NUM"])
for part in os.environ["SPEC"].split(","):
    a,_,b=part.partition("-")
    if int(a) <= n <= int(b or a): sys.exit(0)
sys.exit(1)'
}

SUB_ID="$("$OP" az account show --query id -o tsv --only-show-errors)"
SI="$ARM/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS_NAME/providers/Microsoft.SecurityInsights"
NOW="${NOISE_NOW:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
[ -z "$SINCE" ] || [ -n "$UNTIL" ] || UNTIL="$NOW"

# ---- ServiceNow, as svc.sentinel ------------------------------------------------
# The password goes to curl in a config on a file descriptor, never in argv.
SN_PW=""
sn() {
  [ -n "$SN_PW" ] || SN_PW="$("$SECURITY" find-generic-password -s "$SN_KEYCHAIN" -w 2>/dev/null)" || die "no ServiceNow password in Keychain item $SN_KEYCHAIN"
  "$CURL" -sS -m 60 -K <(printf 'user = "%s:%s"\n' "$SN_USER" "$SN_PW") -H 'Accept: application/json' -H 'Content-Type: application/json' -w '\n%{http_code}' "$@"
}
SN="https://$SN_INSTANCE.service-now.com/api/now/table/incident"
# Open tickets for an incident name: "<sys_id> <number>" lines; exit 1 on any
# ServiceNow error (never read as "no ticket").
tickets_for() {
  local out code
  out="$(sn "$SN?sysparm_query=correlation_id=$1^stateIN1,2,3&sysparm_fields=sys_id,number")" || return 1
  code="${out##*$'\n'}"; out="${out%$'\n'*}"
  [ "$code" = 200 ] || { printf 'close-build-noise: ServiceNow answered %s reading tickets for %s\n' "$code" "$1" >&2; return 1; }
  printf '%s' "$out" | py 'for r in d.get("result",[]): print(r["sys_id"], r["number"])'
}

# ---- 1. classify ----------------------------------------------------------------
say "== close-build-noise: $([ $APPLY -eq 1 ] && echo APPLY || echo 'DRY RUN (nothing changes; --apply to act)')"
[ -z "$NUMBERS" ] || say "scope: incident numbers $NUMBERS"
[ -z "$SINCE" ] || say "window: created $SINCE .. $UNTIL (UTC)"
[ -z "$LEAD_OK" ] || say "lead-confirmed: $LEAD_OK"
incs="$(rest_all "$SI/incidents?$API&\$filter=properties/status ne 'Closed'&\$orderby=properties/createdTimeUtc asc")" || die "could not list the incidents"
rows="$(printf '%s' "$incs" | py '
for i in d.get("value",[]):
    p=i["properties"]
    print(i["name"], p["incidentNumber"], p["createdTimeUtc"], p["severity"], p["title"].replace(" ","_"))')"
PLAN=()
while read -r name num created sev title; do
  [ -z "$name" ] && continue
  if [ -n "$NUMBERS" ] && ! in_list "$num" "$NUMBERS"; then continue; fi
  ents="$(rest POST "$SI/incidents/$name/entities?$API")" || die "could not read the entities of incident #$num"
  accts=""
  while read -r upn oid; do
    [ -z "$upn" ] && continue
    if [ "$upn" = "-" ] && [[ "$oid" =~ ^[0-9a-fA-F-]{36}$ ]]; then
      upn="$(rest GET "$GRAPH/users/$oid?\$select=userPrincipalName" 2>/dev/null | py 'print(d.get("userPrincipalName") or "-")' || echo -)"
    fi
    accts="$accts $upn"
  done <<<"$(printf '%s' "$ents" | py '
for e in (d or {}).get("entities",[]):
    if e.get("kind")!="Account": continue
    p=e.get("properties") or {}
    n=p.get("friendlyName") or ""
    if "@" not in n and p.get("accountName") and p.get("upnSuffix"): n=p["accountName"]+"@"+p["upnSuffix"]
    print(n if "@" in n else "-", p.get("aadUserId") or "-")')"
  accts="${accts# }"
  lab=0; lead=""
  if [ -n "$accts" ]; then
    lab=1
    for a in $accts; do
      la="$(printf '%s' "$a" | tr '[:upper:]' '[:lower:]')"
      if [[ "$la" =~ $OWNER_RE ]]; then lead="${lead:+$lead, }the owner's account"; lab=0
      elif [ "$a" = "-" ]; then lead="${lead:+$lead, }an account whose name cannot be read"; lab=0
      elif ! [[ "$la" =~ $LAB_RE ]]; then lead="${lead:+$lead, }$a (not a lab test/admin account)"; lab=0
      fi
    done
  fi
  inwin=0
  if [ -n "$SINCE" ]; then
    if C="$created" A="$SINCE" B="$UNTIL" python3 -c 'import os,re,sys
from datetime import datetime, timezone
def f(s):
    t=datetime.fromisoformat(re.sub(r"\.\d+","",s).replace("Z","+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
sys.exit(0 if f(os.environ["A"]) <= f(os.environ["C"]) <= f(os.environ["B"]) else 1)'; then inwin=1; fi
  fi
  why=""
  if [ $lab -eq 1 ]; then why="entities are lab test/admin accounts ($accts)"; fi
  if [ $inwin -eq 1 ]; then why="${why:+$why; }created inside the build window"; fi
  if [ -n "$lead" ]; then
    if [ -n "$LEAD_OK" ] && in_list "$num" "$LEAD_OK"; then
      decision="CLOSE"; why="lead confirmed (names $lead)${why:+; $why}"
    else
      decision="NEEDS-LEAD"; why="names $lead"
    fi
  elif [ -n "$why" ]; then decision="CLOSE"
  else decision="SKIP"; why="no selector matched${accts:+ (accounts: $accts)}${accts:- (no account entity)}"
  fi
  printf '%-10s #%-4s %s %-6s %s\n           %s\n' "$decision" "$num" "${created:0:16}" "$sev" "${title//_/ }" "$why"
  if [ "$decision" = CLOSE ]; then PLAN+=("$name|$num|$why"); fi
done <<<"$rows"

say ""
say "${#PLAN[@]} incident(s) to close."

# ---- 2. tickets -------------------------------------------------------------------
TICKETS=()
for item in ${PLAN[@]+"${PLAN[@]}"}; do
  IFS='|' read -r name num why <<<"$item"
  t="$(tickets_for "$name")" || die "could not read ServiceNow tickets for incident #$num"
  while read -r sid tnum; do
    [ -z "$sid" ] && continue
    say "  #$num -> ServiceNow $tnum (open)"
    TICKETS+=("$sid|$tnum|$num|$why")
  done <<<"$t"
done
# Tickets whose Sentinel incident is ALREADY closed (someone decided; the
# ticket was left open): resolved too, to mirror it (in --numbers scope).
out="$(sn "$SN?sysparm_query=correlation_display=Microsoft%20Sentinel^stateIN1,2,3&sysparm_fields=sys_id,number,correlation_id")" || die "could not list ServiceNow tickets"
code="${out##*$'\n'}"; out="${out%$'\n'*}"
[ "$code" = 200 ] || die "ServiceNow answered $code listing tickets"
planned=" $(for item in ${PLAN[@]+"${PLAN[@]}"}; do printf '%s ' "${item%%|*}"; done)"
while read -r sid tnum corr; do
  [ -z "$sid" ] && continue
  case "$planned" in *" $corr "*) continue ;; esac
  rc=0; inc="$(rest GET "$SI/incidents/$corr?$API")" || rc=$?
  [ $rc -eq 4 ] && { say "  $tnum: no Sentinel incident $corr (left alone)"; continue; }
  [ $rc -eq 0 ] || die "could not read Sentinel incident $corr for $tnum"
  read -r num st <<<"$(printf '%s' "$inc" | py 'p=d["properties"]; print(p["incidentNumber"], p["status"])')"
  if [ -n "$NUMBERS" ] && ! in_list "$num" "$NUMBERS"; then continue; fi
  if [ "$st" = Closed ]; then
    say "  #$num (already closed) -> ServiceNow $tnum (open)"
    TICKETS+=("$sid|$tnum|$num|the Sentinel incident was already closed")
  fi
done <<<"$(printf '%s' "$out" | py 'for r in d.get("result",[]): print(r["sys_id"], r["number"], r["correlation_id"] or "-")')"
say "${#TICKETS[@]} open ServiceNow ticket(s) to resolve."
if [ $APPLY -eq 0 ]; then say "DRY RUN: nothing changed. Re-run with --apply (and --lead-ok <numbers> for NEEDS-LEAD ones the lead has cleared)."; exit 0; fi

# ---- 3. apply -----------------------------------------------------------------------
bad=0
for item in ${PLAN[@]+"${PLAN[@]}"}; do
  IFS='|' read -r name num why <<<"$item"
  reason="Build/test noise before recording: $why. Closed by lab/scripts/demo/close-build-noise.sh."
  R="$reason" py 'import os
print(json.dumps({"properties":{"message":os.environ["R"]}}))' </dev/null |
    rest PUT "$SI/incidents/$name/comments/$(python3 -c 'import uuid; print(uuid.uuid4())')?$API" --stdin >/dev/null || die "could not comment on incident #$num"
  cur="$(rest GET "$SI/incidents/$name?$API")" || die "could not read incident #$num"
  printf '%s' "$cur" | R="$reason" py 'import os
p=d["properties"]
print(json.dumps({"etag":d.get("etag"),"properties":{"title":p["title"],"severity":p["severity"],"status":"Closed","classification":"BenignPositive","classificationReason":"SuspiciousButExpected","classificationComment":os.environ["R"][:1000]}}))' |
    rest PUT "$SI/incidents/$name?$API" --stdin >/dev/null || die "could not close incident #$num"
  st="$(rest GET "$SI/incidents/$name?$API" | py 'print(d["properties"]["status"])')" || st="?"
  if [ "$st" = Closed ]; then say "closed #$num"; else say "NOT CLOSED: #$num reads $st"; bad=1; fi
done
for item in ${TICKETS[@]+"${TICKETS[@]}"}; do
  IFS='|' read -r sid tnum num why <<<"$item"
  body="$(R="Sentinel incident #$num closed before recording: $why. Resolved by lab/scripts/demo/close-build-noise.sh." CC="$CLOSE_CODE_JSON" py 'import os
print(json.dumps({"state":"6","close_code":json.loads(os.environ["CC"]),"close_notes":os.environ["R"][:4000]}))' </dev/null)"
  out="$(printf '%s' "$body" | sn -X PATCH "$SN/$sid?sysparm_fields=number,state" --data-binary @-)" || die "ServiceNow call failed for $tnum"
  code="${out##*$'\n'}"
  case "$code" in
    200) ;;
    401|403) die "ServiceNow refused to resolve $tnum (HTTP $code): svc.sentinel needs the itil role (write on incident state/close_code/close_notes)" ;;
    *) say "NOT RESOLVED: $tnum (HTTP $code)"; bad=1; continue ;;
  esac
  out="$(sn "$SN/$sid?sysparm_fields=state")" || die "ServiceNow read-back failed for $tnum"
  st="$(printf '%s' "${out%$'\n'*}" | py 'print(d["result"]["state"])')"
  if [ "$st" = 6 ]; then say "resolved $tnum"; else say "NOT RESOLVED: $tnum reads state $st"; bad=1; fi
done
SN_PW=""
[ $bad -eq 0 ] || die "some items did not read back closed/resolved (see above)"
say "done: ${#PLAN[@]} incident(s) closed, ${#TICKETS[@]} ticket(s) resolved"
