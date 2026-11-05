#!/usr/bin/env bash
# =============================================================================
# containment-drill.sh - arm and clean up the on-camera containment drill
# (ADR 0017, capture-log E41): ONE High Sentinel incident about ONE throwaway
# cloud-only account, with the approval card waiting in Contoso SOC /
# Identity-SecOps for an approver to press Contain.
#
#   lab/scripts/demo/containment-drill.sh arm      # prints DRILL_INCIDENT=<n> last
#   lab/scripts/demo/containment-drill.sh disarm
#   lab/scripts/demo/containment-drill.sh status
#
# Runs as the lab operator (lab/scripts/operator/op): Graph User.ReadWrite.All
# + User.DeleteRestore.All for the throwaway user, Owner on rg-identity-lab for
# the temporary analytics rule, the incident and the playbook run.
#
# arm (idempotent: a second arm reports the same incident and changes nothing)
#   0. REFUSES while any containment run - card waiting or not posted yet -
#      is about an account that is not a lab test or drill account (a card
#      about a real person - the owner's admin account after a portal change,
#      say - must never sit next to the drill card on camera), and checks
#      again just before it reports ready. It names those incidents and how
#      to clear them. A run whose subject cannot be read counts as real.
#   1. Creates itdr-drill-<UTC date>@<domain>: cloud-only, no licence, a random
#      password nobody keeps (it never signs in). An existing account of that
#      name is reused ONLY if it carries this script's job-title marker and is
#      cloud-only; a disabled one (an earlier take was contained) means
#      "disarm first".
#   2. Raises ONE incident through a temporary Sentinel analytics rule whose
#      query is a single `print` of that user's object id (so the incident's
#      only Account entity is the drill user), High, alert grouping on, then
#      DISABLES the rule as soon as the incident exists. Why a rule and not a
#      hand-made incident: the containment playbook reads the incident's
#      Account entities, and only an alert can carry entities.
#   3. Starts pb-identity-contain on that incident (Sentinel runPlaybook, the
#      same as "Run playbook" in the portal: the ITDR automation rule only
#      matches the lab's own detections) and waits until its card is waiting.
#      --with-notify also starts pb-identity-notify (alert card + ServiceNow
#      ticket) first, for the whole alert-to-approval story.
#
# disarm (idempotent: nothing left = nothing to do)
#   1. Cancels every containment run still running on a drill incident,
#      whether its card is waiting or not posted yet: no approval stays
#      pending. (Teams keeps showing a posted card; a click on it after the
#      cancel reaches nothing.)
#   2. Deletes and PURGES every itdr-drill-* user that carries the marker.
#   3. Deletes the temporary rule.
#   4. Closes each drill incident as BenignPositive / SuspiciousButExpected,
#      with a comment that lists every containment outcome on it.
#   5. Reads everything back and fails unless: no card pending for a drill
#      incident, no drill user (live or deleted), no rule, every drill
#      incident Closed.
#
# status: what arm/disarm would find, changes nothing.
#
# WHY these calls (all read live 2026-11-05 in the E41 drill):
#   * Microsoft.SecurityInsights 2024-09-01 alertRules / incidents / comments /
#     entities, and incidents/{id}/runPlaybook on 2024-04-01-preview (the
#     version that answered; it is how the portal's "Run playbook" works).
#   * Logic Apps runs (2019-05-01): $filter=status eq 'Running', the action
#     repetitions of Post_approval_card_and_wait (status Waiting while a card
#     is open), the run trigger's outputs (the incident and its entities),
#     runs/{id}/cancel. A waiting card's subject is the trigger's Account
#     entity, resolved in Graph by object id.
#   * Run history outputs are behind short-lived SAS links: they go to curl in
#     a config on stdin (-K -), never on a command line.
#
# Env overrides (tests): CONTOSO_OP, DRILL_CURL, DRILL_DATE (YYYYMMDD),
# DRILL_DOMAIN, DRILL_POLL_SECONDS, DRILL_WAIT_SECONDS.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OP="${CONTOSO_OP:-$REPO/lab/scripts/operator/op}"
CURL="${DRILL_CURL:-curl}"
RG="rg-identity-lab"
WS_NAME="loga-idlab"
DOMAIN="${DRILL_DOMAIN:-ContosoHealthLab.onmicrosoft.com}"
DATE="${DRILL_DATE:-$(date -u +%Y%m%d)}"
POLL="${DRILL_POLL_SECONDS:-10}"
WAIT="${DRILL_WAIT_SECONDS:-600}"
# The temporary rule is found by this exact name (one drill at a time). Its
# id is new for every arm: Sentinel refuses to re-create a rule id for a
# while after it was deleted ("The rule with id ... was recently deleted",
# seen live 2026-11-05), so a fixed id would break disarm-then-arm re-takes.
RULE_NAME="Contoso DRILL - containment approval drill (temporary, containment-drill.sh)"
MARKER="Throwaway containment drill target (containment-drill.sh) - delete after the drill"
# Accounts a containment card may be about while a drill is armed: lab test
# users and drill users only (same pattern as answer-teams-card.mjs).
SUBJECT_RE='^(test-user-[a-z0-9]+|itdr-drill-[0-9a-z-]+)@(contosohealthlab\.com|contosohealthlab\.onmicrosoft\.com)$'
SENTINEL_API="api-version=2024-09-01"
LOGIC_API="api-version=2019-05-01"
GRAPH="https://graph.microsoft.com/v1.0"
ARM="https://management.azure.com"

usage() { sed -n '8,10p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
say() { printf '%s\n' "$*"; }
die() { printf 'containment-drill: %s\n' "$1" >&2; exit "${2:-1}"; }

[[ "$DATE" =~ ^[0-9]{8}$ ]] || die "DRILL_DATE must be YYYYMMDD" 2
UPN="itdr-drill-$DATE@$DOMAIN"
[[ "$(printf '%s' "$UPN" | tr '[:upper:]' '[:lower:]')" =~ $SUBJECT_RE ]] || die "drill UPN $UPN would not pass the drill-subject pattern" 2

# ---- az as the lab operator ---------------------------------------------------
ERR="$(mktemp "${TMPDIR:-/tmp}/drill-err.XXXXXX")"
PAGES="$(mktemp -d "${TMPDIR:-/tmp}/drill-pages.XXXXXX")"
# The temporary rule this run switched ON, until it is switched off again: a
# failure or Ctrl-C in between must not leave a `print` rule raising a High
# alert every five minutes. cleanup() makes one best-effort attempt.
RULE_ON=""; RULE_OID=""
cleanup() {
  if [ -n "$RULE_ON" ]; then
    local rid="$RULE_ON"; RULE_ON=""
    if rule_body false "$RULE_OID" | rest PUT "$SI/alertRules/$rid?$SENTINEL_API" --stdin >/dev/null 2>&1; then
      printf 'containment-drill: stopped early - the temporary rule %s was switched off\n' "$rid" >&2
    else
      printf 'containment-drill: stopped early - could NOT switch off the temporary rule %s: run disarm now\n' "$rid" >&2
    fi
  fi
  rm -rf "$ERR" "$PAGES"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
# rest METHOD URL [body-on-stdin]: JSON on stdout. Exit 0 ok, 4 not found,
# 1 anything else (never read as "not there").
rest() {
  local method="$1" url="$2"; shift 2
  local args=(az rest --method "$method" --url "$url" --only-show-errors -o json)
  if [ "${1:-}" = "--stdin" ]; then args+=(--headers Content-Type=application/json --body @/dev/stdin); fi
  if "$OP" "${args[@]}" 2>"$ERR"; then return 0; fi
  if grep -Eq 'Not ?Found|ResourceNotFound|Request_ResourceNotFound' "$ERR"; then return 4; fi
  sed 's/^/  az: /' "$ERR" >&2
  return 1
}
# JSON helper: py '<python code over d>' (d = the JSON on stdin, or None).
py() { python3 -c "import json,sys
_t='' if sys.stdin.isatty() else sys.stdin.read()
d=json.loads(_t) if _t.strip() else None
$1"; }
# A run-history SAS link: URL to curl through a config on stdin.
sas_get() { printf 'url = "%s"\n' "$1" | "$CURL" -sS -m 60 -K -; }
# rest_all URL: GET every page (ARM nextLink / Graph @odata.nextLink) and
# print {"value": [...all pages...]}. A list that stops after the first page
# would let an older drill incident or run escape disarm.
rest_all() {
  local url="$1" n=0 page
  rm -f "$PAGES"/*
  while [ -n "$url" ]; do
    n=$((n + 1)); [ $n -le 200 ] || { printf 'containment-drill: more than 200 pages at %s\n' "$1" >&2; return 1; }
    page="$(rest GET "$url")" || return $?
    printf '%s' "$page" >"$PAGES/$(printf '%05d' $n).json"
    url="$(printf '%s' "$page" | py 'print((d or {}).get("nextLink") or (d or {}).get("@odata.nextLink") or "")')"
  done
  python3 -c 'import glob,json,sys
v=[]
for f in sorted(glob.glob(sys.argv[1]+"/*.json")):
    v+=json.load(open(f)).get("value") or []
print(json.dumps({"value":v}))' "$PAGES"
}

SUB="$("$OP" az account show --query '{s:id,t:tenantId}' -o json --only-show-errors)"
SUB_ID="$(printf '%s' "$SUB" | py 'print(d["s"])')"
TENANT_ID="$(printf '%s' "$SUB" | py 'print(d["t"])')"
WS="/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS_NAME"
SI="$ARM$WS/providers/Microsoft.SecurityInsights"
WF="$ARM/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Logic/workflows"
CONTAIN_ID="/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Logic/workflows/pb-identity-contain"
NOTIFY_ID="/subscriptions/$SUB_ID/resourceGroups/$RG/providers/Microsoft.Logic/workflows/pb-identity-notify"

# ---- what is running --------------------------------------------------------------
# One line per Running containment run and Account entity of its incident:
#   "<run> <incident number or ?> <waiting 1|0> <subject UPN or ?>"
# waiting = its card is open in Teams (Post_approval_card_and_wait Waiting).
# The incident and subject come from the run's TRIGGER (the incident and its
# relatedEntities, an aadUserId), the UPN from Graph by that id - not from
# the nested Get_user output, whose SAS link answers WorkflowRunActionNotFound
# while the run is still waiting (seen live 2026-11-05). Anything unreadable
# prints "?", which every caller treats as "not provably a drill" (fail closed).
running_runs() {
  local runs r reps rc waiting link trig inc oids oid upn
  runs="$(rest_all "$WF/pb-identity-contain/runs?$LOGIC_API&\$filter=status eq 'Running'")" || return 1
  for r in $(printf '%s' "$runs" | py 'print("\n".join(x["name"] for x in d.get("value",[])))'); do
    waiting=0
    rc=0; reps="$(rest GET "$WF/pb-identity-contain/runs/$r/actions/Post_approval_card_and_wait/repetitions?$LOGIC_API")" || rc=$?
    if [ $rc -eq 0 ]; then
      printf '%s' "$reps" | py 'import sys
sys.exit(0 if any(x["properties"].get("status")=="Waiting" for x in d.get("value",[])) else 1)' && waiting=1
    elif [ $rc -ne 4 ]; then return 1; fi
    link="$(rest GET "$WF/pb-identity-contain/runs/$r?$LOGIC_API" | py 'print(((d["properties"].get("trigger") or {}).get("outputsLink") or {}).get("uri",""))')" || return 1
    trig=""; [ -n "$link" ] && trig="$(sas_get "$link" 2>/dev/null || true)"
    inc="$(printf '%s' "$trig" | py 'print(d["body"]["object"]["properties"]["incidentNumber"])' 2>/dev/null || echo '?')"
    oids="$(printf '%s' "$trig" | py '
ents=[e for e in d["body"]["object"]["properties"].get("relatedEntities") or [] if e.get("kind")=="Account"]
print("\n".join((e.get("properties") or {}).get("aadUserId") or "none" for e in ents) if ents else "none")' 2>/dev/null || echo none)"
    for oid in $oids; do
      upn="?"
      if [[ "$oid" =~ ^[0-9a-fA-F-]{36}$ ]]; then
        upn="$(rest GET "$GRAPH/users/$oid?\$select=userPrincipalName" 2>/dev/null | py 'print(d.get("userPrincipalName") or "?")' 2>/dev/null || echo '?')"
      fi
      printf '%s %s %s %s\n' "$r" "$inc" "$waiting" "$upn"
    done
  done
}
# Open cards only: "<run> <incident number or ?> <subject UPN or ?>".
waiting_cards() {
  local all
  all="$(running_runs)" || return 1
  printf '%s\n' "$all" | awk 'NF && $3 == 1 { print $1, $2, $4 }'
}
is_drill_subject() { [[ "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" =~ $SUBJECT_RE ]]; }

# Drill incidents: "<name> <number> <status>", newest first. A scheduled
# rule's incident takes the rule's display name as its title (read live on
# the E41 drill), and that name is this script's own.
drill_incidents() {
  rest_all "$SI/incidents?$SENTINEL_API&\$filter=properties/title eq '$RULE_NAME'&\$orderby=properties/createdTimeUtc desc" | NAME="$RULE_NAME" py '
import os
for i in d.get("value",[]):
    p=i["properties"]
    if p.get("title")==os.environ["NAME"]:
        print(i["name"], p["incidentNumber"], p["status"])'
}
# Ids of the temporary rule(s), by name.
drill_rule_ids() {
  rest_all "$SI/alertRules?$SENTINEL_API" | NAME="$RULE_NAME" py '
import os
for r in d.get("value",[]):
    if (r.get("properties") or {}).get("displayName")==os.environ["NAME"]: print(r["name"])'
}

# Object ids of an incident's Account entities, one per line.
incident_oids() {
  rest POST "$SI/incidents/$1/entities?$SENTINEL_API" | py '
for e in (d or {}).get("entities",[]):
    if e.get("kind")=="Account": print(e["properties"].get("aadUserId") or "none")'
}

# Live itdr-drill-* users (any date), "<id> <upn>" lines, marker or not.
live_drill_users() {
  rest_all "$GRAPH/users?\$filter=startswith(userPrincipalName,'itdr-drill-')&\$select=id,userPrincipalName" | py '
for u in d.get("value",[]): print(u["id"], u["userPrincipalName"])'
}
# Soft-deleted users this script made (marker kept on the deleted object).
deleted_drill_users() {
  rest_all "$GRAPH/directory/deletedItems/microsoft.graph.user?\$select=id,userPrincipalName,jobTitle" | M="$MARKER" py '
import os
for u in d.get("value",[]):
    if u.get("jobTitle")==os.environ["M"] and "itdr-drill-" in (u.get("userPrincipalName") or ""): print(u["id"])'
}

drill_user() {  # prints the user JSON; exit 4 when there is none
  rest GET "$GRAPH/users/$UPN?\$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,jobTitle"
}

rule_body() {  # $1 = enabled (true/false), $2 = user object id
  OID="$2" EN="$1" NAME="$RULE_NAME" U="$UPN" py '
import os
q=("print AadUserId = \"%s\", AccountUpn = \"%s\"\n| extend AccountName = tostring(split(AccountUpn, \"@\")[0]), UPNSuffix = tostring(split(AccountUpn, \"@\")[1])" % (os.environ["OID"], os.environ["U"]))
print(json.dumps({"kind":"Scheduled","properties":{
 "displayName":os.environ["NAME"],
 "description":"Temporary rule of lab/scripts/demo/containment-drill.sh: raises ONE High incident naming only the throwaway drill user, so pb-identity-contain can be run from it. Not one of the lab detections; containment-drill.sh disarm deletes it.",
 "severity":"High","enabled":os.environ["EN"]=="true","query":q,
 "queryFrequency":"PT5M","queryPeriod":"PT5M","triggerOperator":"GreaterThan","triggerThreshold":0,
 "suppressionDuration":"PT5H","suppressionEnabled":False,"tactics":["InitialAccess"],
 "entityMappings":[{"entityType":"Account","fieldMappings":[{"identifier":"AadUserId","columnName":"AadUserId"},{"identifier":"Name","columnName":"AccountName"},{"identifier":"UPNSuffix","columnName":"UPNSuffix"}]}],
 "incidentConfiguration":{"createIncident":True,"groupingConfiguration":{"enabled":True,"reopenClosedIncident":False,"lookbackDuration":"PT5H","matchingMethod":"AllEntities","groupByEntities":[],"groupByAlertDetails":[],"groupByCustomDetails":[]}},
 "eventGroupingSettings":{"aggregationKind":"SingleAlert"}}}))' </dev/null
}

run_playbook() {  # $1 incident name, $2 playbook resource id
  printf '{"logicAppsResourceId":"%s","tenantId":"%s"}' "$2" "$TENANT_ID" |
    rest POST "$SI/incidents/$1/runPlaybook?api-version=2024-04-01-preview" --stdin >/dev/null
}

# Refuse while ANY running containment run (card posted or still on its way)
# is about an account that is not a test or drill account; print the open
# drill-safe cards ("<run> <incident> <upn>") otherwise. $1 = what to say.
refuse_real_cards() {
  local runs real
  runs="$(running_runs)" || die "could not read the running containment runs: refusing (fail closed)"
  real=""
  while read -r run inc waiting upn; do
    [ -z "$run" ] && continue
    is_drill_subject "$upn" || real="$real$run incident #$inc about $upn$([ "$waiting" = 1 ] && echo ' (card waiting)' || echo ' (card not posted yet)')"$'\n'
  done <<<"$runs"
  if [ -n "$real" ]; then
    printf 'containment-drill: refused%s - a containment run is going about an account that is not a test or drill account:\n%s' "${1:+ $1}" "$real" >&2
    printf 'Clear each first: an approver answers Reject on that card, or cancel the run:\n  %s az rest --method POST --url "%s/pb-identity-contain/runs/<run>/cancel?%s"\n' "$OP" "$WF" "$LOGIC_API" >&2
    exit 3
  fi
  printf '%s\n' "$runs" | awk 'NF && $3 == 1 { print $1, $2, $4 }'
}

# =============================================================================
cmd_arm() {
  local with_notify="$1" cards user oid enabled sync title inc waited rid name="" num="" status=""
  say "== containment drill: arm ($UPN)"
  cards="$(refuse_real_cards)" || exit $?

  # Already armed? An open drill incident with a card waiting about the drill user.
  inc="$(drill_incidents | awk '$3 != "Closed"' | head -1)" || die "could not read the incidents"
  if [ -n "$inc" ]; then
    read -r name num status <<<"$inc"
    if printf '%s\n' "$cards" | awk -v n="$num" '$2 == n' | grep -q .; then
      say "already armed: incident #$num, approval card waiting in Contoso SOC / Identity-SecOps"
      say "DRILL_INCIDENT=$num"; return 0
    fi
  fi

  # 1. the throwaway user
  local rc=0; user="$(drill_user)" || rc=$?
  if [ $rc -eq 4 ]; then
    # The password is made inside python and goes straight to az on stdin:
    # never in argv, the environment or a file, and nobody keeps it.
    user="$(U="$UPN" M="$MARKER" D="$DATE" py 'import os,secrets
print(json.dumps({"accountEnabled":True,"displayName":"ITDR Drill %s (throwaway)" % os.environ["D"],
 "mailNickname":os.environ["U"].split("@")[0],"userPrincipalName":os.environ["U"],
 "department":"Lab Test","jobTitle":os.environ["M"],
 "passwordProfile":{"forceChangePasswordNextSignIn":True,"password":secrets.token_urlsafe(24)+"Kx4%"}}))' </dev/null |
      rest POST "$GRAPH/users" --stdin)" || die "could not create $UPN"
    # The create answer omits accountEnabled / onPremisesSyncEnabled: read the
    # user back with the same $select as an existing one.
    # A new user can answer 404 for a few seconds (directory replication):
    # retry that, and only that.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      rc=0; user="$(drill_user)" || rc=$?
      [ $rc -eq 4 ] || break
      sleep "$POLL"
    done
    [ $rc -eq 0 ] || die "created $UPN but cannot read it back"
    say "created $UPN (cloud-only, no licence, password discarded)"
  elif [ $rc -ne 0 ]; then
    die "could not read $UPN: refusing (fail closed)"
  fi
  oid="$(printf '%s' "$user" | py 'print(d["id"])')"
  title="$(printf '%s' "$user" | py 'print(d.get("jobTitle") or "")')"
  sync="$(printf '%s' "$user" | py 'print(d.get("onPremisesSyncEnabled") is True)')"
  enabled="$(printf '%s' "$user" | py 'print(d.get("accountEnabled") is True)')"
  [ "$title" = "$MARKER" ] && [ "$sync" = "False" ] || die "$UPN exists but is not this script's throwaway user (job title / sync state differ): refused" 3
  [ "$enabled" = "True" ] || die "$UPN is disabled (an earlier take was contained): run disarm, then arm" 4

  # An open drill incident must be about THIS user (not an earlier date's).
  # No Account entity YET is the normal few-second delay after creation (the
  # wait below handles it), not proof of another user: only an incident that
  # names someone else is refused.
  if [ -n "$inc" ]; then
    read -r name num status <<<"$inc"
    local seen
    seen="$(incident_oids "$name" | sort -u | tr -d '\n')" || die "could not read the entities of incident #$num"
    [ -z "$seen" ] || [ "$seen" = "$oid" ] || die "open drill incident #$num is not about $UPN: run disarm, then arm" 4
  fi

  # 2. one incident through the temporary rule
  if [ -z "$inc" ]; then
    rid="$(drill_rule_ids | head -1)" || die "could not list the analytics rules"
    [ -n "$rid" ] || rid="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    RULE_ON="$rid"; RULE_OID="$oid"
    rule_body true "$oid" | rest PUT "$SI/alertRules/$rid?$SENTINEL_API" --stdin >/dev/null || die "could not create the temporary rule"
    say "temporary rule enabled; waiting for the incident"
    waited=0; inc=""
    while [ -z "$inc" ] && [ $waited -le "$WAIT" ]; do
      inc="$(drill_incidents | awk '$3 != "Closed"' | head -1)" || die "could not read the incidents"
      [ -n "$inc" ] || { sleep "$POLL"; waited=$((waited + POLL)); [ "$POLL" -gt 0 ] || waited=$((waited + 1)); }
    done
    # The rule has done its job either way: switch it off (disarm deletes it).
    rule_body false "$oid" | rest PUT "$SI/alertRules/$rid?$SENTINEL_API" --stdin >/dev/null || die "could not disable the temporary rule"
    RULE_ON=""
    [ -n "$inc" ] || die "no incident from the temporary rule within ${WAIT}s (rule now disabled; re-run arm)"
    read -r name num status <<<"$inc"
    say "incident #$num raised; temporary rule disabled"
  fi

  # 3. the playbook(s) on it. The incident exists a few seconds before its
  # alert's Account entity is attached (seen 2026-11-05: a run started 17 s
  # after creation found "No account entities"), so wait for the entity:
  # the playbook reads relatedEntities once, when it starts.
  waited=0
  until [ "$(incident_oids "$name" | sort -u | tr -d '\n')" = "$oid" ]; do
    [ $waited -le "$WAIT" ] || die "incident #$num never showed $UPN as its Account entity"
    sleep "$POLL"; waited=$((waited + POLL)); [ "$POLL" -gt 0 ] || waited=$((waited + 1))
  done
  # A run already going for this incident (an earlier arm was interrupted
  # before its card appeared) is reused, never doubled. A running run that
  # cannot be tied to an incident stops arm: it might be this one.
  local running mine
  running="$(running_runs)" || die "could not read the running containment runs"
  if printf '%s\n' "$running" | awk 'NF && $2 == "?"' | grep -q .; then
    die "a running containment run cannot be tied to an incident (trigger unreadable): check it by hand before arming" 3
  fi
  mine="$(printf '%s\n' "$running" | awk -v n="$num" 'NF && $2 == n { print $1 }' | sort -u | head -1)"
  if [ -n "$mine" ]; then
    say "pb-identity-contain run $mine is already working on incident #$num: waiting for its card"
  else
    if [ "$with_notify" = 1 ]; then run_playbook "$name" "$NOTIFY_ID" || die "could not start pb-identity-notify"; say "pb-identity-notify started (alert card + ServiceNow ticket)"; fi
    run_playbook "$name" "$CONTAIN_ID" || die "could not start pb-identity-contain"
    say "pb-identity-contain started; waiting for its approval card"
  fi
  waited=0
  while [ $waited -le "$WAIT" ]; do
    cards="$(waiting_cards)" || die "could not read the waiting cards"
    if printf '%s\n' "$cards" | awk -v n="$num" -v u="$(printf '%s' "$UPN" | tr '[:upper:]' '[:lower:]')" '$2 == n && tolower($3) == u' | grep -q .; then
      # A real person's run could have started while we waited: the same
      # refusal as at the start, before reporting the drill ready.
      refuse_real_cards "(the drill card for incident #$num is posted, but it is not safe to record)" >/dev/null || exit $?
      say "approval card waiting in Contoso SOC / Identity-SecOps for incident #$num (about $UPN)"
      say "DRILL_INCIDENT=$num"; return 0
    fi
    sleep "$POLL"; waited=$((waited + POLL)); [ "$POLL" -gt 0 ] || waited=$((waited + 1))
  done
  die "pb-identity-contain did not post a card within ${WAIT}s: check its run history (Teams connection authorized?)"
}

cmd_disarm() {
  local incs runs ids name num status run inc upn uid rid rc ok=1 summary cur
  say "== containment drill: disarm"
  incs="$(drill_incidents)" || die "could not read the incidents"
  runs="$(running_runs | awk 'NF { print $1, $2 }' | sort -u)" || die "could not read the running containment runs"

  # 1. no containment run left on a drill incident - waiting on a card OR
  # still on its way to one (an interrupted arm): a run that has read the
  # user can still post its card after the user is gone. A running run whose
  # incident cannot be read is left alone (it might be a real approval) and
  # makes the read-back below fail: never reported clean.
  while read -r run inc; do
    [ -z "$run" ] && continue
    if [ "$inc" = "?" ]; then say "cannot tell which incident running run $run belongs to: left alone"; continue; fi
    if printf '%s\n' "$incs" | awk -v n="$inc" '$2 == n' | grep -q .; then
      rest POST "$WF/pb-identity-contain/runs/$run/cancel?$LOGIC_API" >/dev/null || die "could not cancel run $run"
      say "cancelled the containment run $run (incident #$inc)"
    fi
  done <<<"$runs"

  # 2. drill users: delete and purge (marker required)
  ids="$(rest_all "$GRAPH/users?\$filter=startswith(userPrincipalName,'itdr-drill-')&\$select=id,userPrincipalName,jobTitle,onPremisesSyncEnabled" | M="$MARKER" py '
import os,re
for u in d.get("value",[]):
    if re.match(r"^itdr-drill-[0-9]{8}@", u["userPrincipalName"], re.I) and u.get("jobTitle")==os.environ["M"] and not u.get("onPremisesSyncEnabled"):
        print(u["id"], u["userPrincipalName"])
    else:
        print("SKIP", u["userPrincipalName"])')" || die "could not list the drill users"
  while read -r uid upn; do
    [ -z "$uid" ] && continue
    if [ "$uid" = "SKIP" ]; then say "left alone (no drill marker): $upn"; continue; fi
    rc=0; rest DELETE "$GRAPH/users/$uid" >/dev/null || rc=$?
    [ $rc -eq 0 ] || [ $rc -eq 4 ] || die "could not delete $upn"
    say "deleted $upn"
    # A just-deleted user can take a few seconds to show in Deleted users:
    # retry the purge on 404 before giving up on it.
    for _ in 1 2 3 4 5 6; do
      rc=0; rest DELETE "$GRAPH/directory/deletedItems/$uid" >/dev/null || rc=$?
      [ $rc -eq 4 ] || break
      sleep "$POLL"
    done
    [ $rc -eq 0 ] || die "could not purge deleted user $upn ($uid)"
    say "purged $upn"
  done <<<"$ids"
  # Sweep: anything this script soft-deleted earlier (marker kept on the
  # deleted object; its UPN is prefixed with the object id once deleted).
  ids="$(deleted_drill_users)" || die "could not list Deleted users"
  for uid in $ids; do
    rc=0; rest DELETE "$GRAPH/directory/deletedItems/$uid" >/dev/null || rc=$?
    [ $rc -eq 0 ] || [ $rc -eq 4 ] || die "could not purge deleted user $uid"
    if [ $rc -eq 0 ]; then say "purged deleted user $uid"; fi
  done

  # 3. the temporary rule(s)
  ids="$(drill_rule_ids)" || die "could not list the analytics rules"
  for rid in $ids; do
    rc=0; rest DELETE "$SI/alertRules/$rid?$SENTINEL_API" >/dev/null || rc=$?
    [ $rc -eq 0 ] || [ $rc -eq 4 ] || die "could not delete the temporary rule $rid"
    say "temporary rule $rid deleted"
  done

  # 4. close the drill incidents, with every containment outcome on them
  while read -r name num status; do
    [ -z "$name" ] && continue
    [ "$status" = "Closed" ] && continue
    summary="$(rest GET "$SI/incidents/$name/comments?$SENTINEL_API" | py '
import re
out=[]
for c in sorted(d.get("value",[]), key=lambda c: c["properties"]["createdTimeUtc"]):
    t=re.sub(r"\s+"," ",re.sub("<[^>]+>"," ",c["properties"]["message"])).strip()
    if "ITDR containment" in t: out.append(t[:400])
print(" || ".join(out) if out else "no containment outcome recorded")')" || die "could not read the comments of incident #$num"
    S="$summary" N="$num" py 'import os
print(json.dumps({"properties":{"message":"Drill closed by lab/scripts/demo/containment-drill.sh disarm: the throwaway drill user is deleted and purged, the temporary rule is deleted, no approval is left pending. Outcomes on this incident: "+os.environ["S"]}}))' </dev/null |
      rest PUT "$SI/incidents/$name/comments/$(python3 -c 'import uuid; print(uuid.uuid4())')?$SENTINEL_API" --stdin >/dev/null || die "could not comment on incident #$num"
    # Read, then write: never two az calls in one pipeline (they would share
    # the error file, and a 404 on one could be read as the other's).
    cur="$(rest GET "$SI/incidents/$name?$SENTINEL_API")" || die "could not read incident #$num"
    printf '%s' "$cur" | py '
p=d["properties"]
print(json.dumps({"etag":d.get("etag"),"properties":{"title":p["title"],"severity":p["severity"],"status":"Closed","classification":"BenignPositive","classificationReason":"SuspiciousButExpected","classificationComment":"Planned containment drill (lab/scripts/demo/containment-drill.sh) on a throwaway test account."}}))' |
      rest PUT "$SI/incidents/$name?$SENTINEL_API" --stdin >/dev/null || die "could not close incident #$num"
    say "closed incident #$num (BenignPositive) with the drill summary"
  done <<<"$incs"

  # 5. read everything back
  runs="$(running_runs | awk 'NF { print $1, $2 }' | sort -u)" || die "could not re-read the running containment runs"
  incs="$(drill_incidents)" || die "could not re-read the incidents"
  while read -r run inc; do
    [ -z "$run" ] && continue
    if [ "$inc" = "?" ]; then say "NOT CLEAN: running run $run cannot be tied to an incident (trigger unreadable): check it by hand"; ok=0; continue; fi
    if printf '%s\n' "$incs" | awk -v n="$inc" '$2 == n' | grep -q .; then say "NOT CLEAN: containment run $run still running for drill incident #$inc"; ok=0; fi
  done <<<"$runs"
  if printf '%s\n' "$incs" | awk 'NF && $3 != "Closed"' | grep -q .; then say "NOT CLEAN: a drill incident is still open"; ok=0; fi
  ids="$(live_drill_users)" || { say "NOT CLEAN: could not list the drill users"; ok=0; ids=""; }
  [ -z "$ids" ] || { say "NOT CLEAN: drill user(s) still exist: $ids"; ok=0; }
  ids="$(deleted_drill_users)" || { say "NOT CLEAN: could not list Deleted users"; ok=0; ids=""; }
  [ -z "$ids" ] || { say "NOT CLEAN: drill user(s) still in Deleted users: $ids"; ok=0; }
  ids="$(drill_rule_ids)" || { say "NOT CLEAN: could not list the analytics rules"; ok=0; ids=""; }
  [ -z "$ids" ] || { say "NOT CLEAN: temporary rule(s) still exist: $ids"; ok=0; }
  [ $ok -eq 1 ] || die "disarm did not finish clean (see above)"
  say "disarmed: no drill user, no temporary rule, every drill incident closed, no card pending for it"
}

cmd_status() {
  local rc=0
  say "== containment drill: status ($UPN)"
  drill_user >/dev/null || rc=$?
  case $rc in 0) say "drill user: exists" ;; 4) say "drill user: none" ;; *) die "could not read $UPN" ;; esac
  say "temporary rule(s): $(drill_rule_ids | tr '\n' ' ')"
  say "drill incidents (name number status):"; drill_incidents | sed 's/^/  /'
  say "waiting containment cards (run incident subject):"; waiting_cards | sed 's/^/  /'
}

[ $# -ge 1 ] || usage 2
sub="$1"; shift
WITH_NOTIFY=0
for a in "$@"; do
  case "$a" in
    --with-notify) WITH_NOTIFY=1 ;;
    -h|--help) usage 0 ;;
    *) die "unknown option: $a" 2 ;;
  esac
done
case "$sub" in
  arm) cmd_arm "$WITH_NOTIFY" ;;
  disarm) cmd_disarm ;;
  status) cmd_status ;;
  -h|--help) usage 0 ;;
  *) usage 2 ;;
esac
