#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# =============================================================================
# midpoint/run-campaign.sh - run one access-certification campaign end to end
# in the local midPoint 4.10 stand-in (SailPoint / Saviynt), headless, over
# midPoint's REST API, and export the result as hashed evidence.
#
#   1. Baseline: PUT objects/*.xml (create or replace, fixed OIDs): 3 orgs,
#      4 business roles, 8 users built from the mock HR personas. The users
#      are reset to this baseline on every run, so every run reviews the same
#      access. The baseline includes one SoD conflict (marcus.bello: Nurse +
#      Pharmacist), one stale grant (daniel.osei: AP Clerk), one leaver
#      (priya.nair, disabled) and one fallback-reviewer case (helen.carter).
#   2. Detective SoD: midPoint must have marked both conflicting assignments
#      with "Exclusion violation" before anyone reviews them (record-only
#      rule on the Pharmacist role).
#   3. Definition: PUT objects/40-certdef-*.xml, keeping lastCampaignIdUsed so
#      campaign names never collide across runs.
#   4. Create the campaign and open stage 1: task tasks/1-create-campaign.xml
#      (handler-based) -> state inReviewStage, cases and work items exist.
#   5. Probes, then decisions: POST rpc/executeScript runs
#      record-decisions.groovy. Every decision is recorded through
#      AccessCertificationService.recordDecision in the ASSIGNED reviewer's
#      security context (performerRef = reviewer, never the administrator).
#      The probes must be refused by midPoint.
#   6. Close stage 1: task tasks/2-close-stage.xml -> reviewStageDone.
#   7. Remediation: task tasks/3-remediation.xml -> revoked and unanswered
#      assignments removed, campaign closed.
#   8. Evidence -> lab/evidence/midpoint/<UTC timestamp>/ (files: README.md),
#      with SHA256SUMS. The run is staged in out/midpoint/<ts>/ (gitignored)
#      and copied to the evidence folder only if every step passed.
#
# Usage (from anywhere; midPoint must be up: ./pam-up.sh):
#   midpoint/run-campaign.sh                       # evidence -> lab/evidence/midpoint/<ts>/
#   midpoint/run-campaign.sh --evidence-dir DIR    # test runs, e.g. out/e2e/midpoint/x (relative to your cwd)
#   midpoint/run-campaign.sh --no-probes           # skip the authorization probes
#
# Idempotent: re-running resets the dataset to its baseline and runs a NEW
# campaign ("<definition name> N+1"). Earlier campaigns stay in midPoint as
# history. An earlier campaign of this definition that is still open (an
# interrupted run) is reported, never touched.
#
# Secrets: the administrator password is read from .env and passed to curl as
# a config file on stdin (lib-midpoint.sh). It is never echoed, never on a
# command line, and the run checks that it does not appear in the evidence.
# Lab shortcut: the driver authenticates as administrator. Production would
# use a dedicated service account with only the authorizations it needs.
# =============================================================================
CALLER_PWD="$PWD"
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"          # cd's to lab/pam, set -euo pipefail
# shellcheck source=lib-midpoint.sh
source "$PAM_DIR/midpoint/lib-midpoint.sh"
need curl; need jq; need perl; need base64

EVIDENCE_DIR=""
PROBES=true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-dir) EVIDENCE_DIR="${2:?--evidence-dir needs a directory}"; shift 2 ;;
    --no-probes) PROBES=false; shift ;;
    -h|--help) sed -n '/^# ====/,/^# ====/p' "$MP_DIR/run-campaign.sh" | sed '1d;$d'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$EVIDENCE_DIR" ]] || EVIDENCE_DIR="$PAM_DIR/../evidence/midpoint/$TS"
[[ "$EVIDENCE_DIR" == /* ]] || EVIDENCE_DIR="$CALLER_PWD/$EVIDENCE_DIR"   # relative to the caller
[[ ! -e "$EVIDENCE_DIR" ]] || die "evidence folder already exists: $EVIDENCE_DIR (never overwritten)"
STAGE="$PAM_DIR/out/midpoint/$TS"
mkdir -p "$STAGE/raw"
# Paths as printed (and logged into the evidence) are relative to lab/, never
# absolute, so the evidence carries no local path. (A custom --evidence-dir
# outside lab/ is printed as given.)
rel() {
  case "$1" in
    "$PAM_DIR"/../*) printf '%s' "${1#"$PAM_DIR"/../}" ;;
    "$PAM_DIR"/*)    printf 'pam/%s' "${1#"$PAM_DIR"/}" ;;
    *)               printf '%s' "$1" ;;
  esac
}

# Everything below is also logged to the staged run.log: tee reads a FIFO in
# the background (bash 3.2 cannot wait for a process substitution), so the log
# is complete before it is copied and hashed at the end.
# The FIFO lives outside $STAGE: a recursive grep of $STAGE must never open it.
LOG_FIFO_DIR="$(mktemp -d)"
mkfifo "$LOG_FIFO_DIR/log"
tee -a "$STAGE/run.log" < "$LOG_FIFO_DIR/log" &
TEE_PID=$!
exec 3>&1 4>&2 > "$LOG_FIFO_DIR/log" 2>&1

fail_run() { log "RUN FAILED: $*"; log "partial output kept in $(rel "$STAGE") (not copied to the evidence folder)"; exit 1; }
trap 'rc=$?; [[ $rc -eq 0 ]] || log "RUN FAILED (exit $rc). Partial output kept in $(rel "$STAGE")"' EXIT

log "midPoint certification campaign run $TS"
mp_load_password
mp_wait_up
MP_VERSION="$(mp_get nodes | jq -r '[.. | objects | select(has("build")) | .build.version] | first // "unknown"')"
log "midPoint $MP_VERSION answering at $MP_URL (REST, as administrator)"

# Report (never touch) open campaigns left by an interrupted earlier run.
STALE_OPEN=()
while IFS= read -r c; do
  [[ -n "$c" ]] || continue
  st="$(mp_campaign_state "$c")"
  [[ "$st" == closed ]] || STALE_OPEN+=("$c:$st")
done < <(mp_campaign_oids)
[[ ${#STALE_OPEN[@]} -eq 0 ]] || log "WARN  earlier campaign(s) of this definition still open: ${STALE_OPEN[*]} (left as is)"
BEFORE_CAMPAIGNS="$(mp_campaign_oids | sort)"

# --- 1. baseline ---------------------------------------------------------------
log "1. Baseline: importing the Contoso dataset (PUT, fixed OIDs)"
for f in "$MP_DIR"/objects/[123]*.xml; do
  code="$(mp_put "$f")"
  log "   $(basename "$f") -> HTTP $code"
done

user_oids() { for f in "$MP_DIR"/objects/3*.xml; do mp_file_oid "$f"; done; }
export_users() { # export_users FILE: every dataset user, as midPoint returns it
  local tmp; tmp="$(mktemp -d)"
  for oid in $(user_oids); do mp_get "users/$oid" > "$tmp/$oid.json"; done
  jq -s '[.[].user]' "$tmp"/*.json > "$1"
  rm -rf "$tmp"
}
export_users "$STAGE/users-before.json"

# --- 2. detective SoD ------------------------------------------------------------
log "2. Detective SoD: exclusion-violation marks on marcus.bello before the review"
SOD_MARK="00000000-0000-0000-0000-000000000811"
NURSE="c0471e00-0000-4000-8000-000000000201"; PHARM="c0471e00-0000-4000-8000-000000000203"
marked="$(jq -r --arg m "$SOD_MARK" '.[] | select(.name == "marcus.bello") | .assignment[]
  | select(([.effectiveMarkRef] | flatten | map(.oid?) | index($m)) != null) | .targetRef.oid' "$STAGE/users-before.json" | sort | tr '\n' ' ')"
[[ "$marked" == "$NURSE $PHARM " ]] || fail_run "expected the Nurse and Pharmacist assignments of marcus.bello to carry the exclusion-violation mark, got: '${marked}'"
others="$(jq -r --arg m "$SOD_MARK" '[.[] | select(.name != "marcus.bello") | .assignment[]
  | select(([.effectiveMarkRef] | flatten | map(.oid?) | index($m)) != null)] | length' "$STAGE/users-before.json")"
[[ "$others" == 0 ]] || fail_run "$others assignment(s) of other users are marked as SoD violations (expected none)"
log "   marked: Nurse + Pharmacist on marcus.bello; no other user marked"

# --- 3. definition ---------------------------------------------------------------
log "3. Certification definition (PUT, keeping lastCampaignIdUsed)"
last_id="$(mp_curl "accessCertificationDefinitions/$MP_DEF_OID" | jq -r '.accessCertificationDefinition.lastCampaignIdUsed // 0' 2>/dev/null || echo 0)"
[[ "$last_id" =~ ^[0-9]+$ ]] || last_id=0
mp_put "$MP_DIR/objects/40-certdef-requestable-roles.xml" >/dev/null
if [[ "$last_id" -gt 0 ]]; then
  # Body from a file: curl's stdin already carries the credentials (-K -).
  patch="$(mktemp)"
  jq -n --argjson n "$last_id" '{objectModification: {itemDelta: {modificationType: "replace", path: "lastCampaignIdUsed", value: $n}}}' > "$patch"
  mp_curl "accessCertificationDefinitions/$MP_DEF_OID" -f -X PATCH -H 'Content-Type: application/json' --data-binary @"$patch" >/dev/null \
    || { rm -f "$patch"; fail_run "could not restore lastCampaignIdUsed=$last_id on the definition"; }
  rm -f "$patch"
fi
DEF_NAME="$(mp_get "accessCertificationDefinitions/$MP_DEF_OID" | jq -r '.accessCertificationDefinition.name')"
log "   '$DEF_NAME' (campaigns created so far: $last_id)"

# --- 4. create + open stage 1 --------------------------------------------------------
log "4. Create the campaign and open stage 1 (task: campaign-creation handler)"
mp_run_task "$MP_DIR/tasks/1-create-campaign.xml"
NEW="$(comm -13 <(printf '%s\n' "$BEFORE_CAMPAIGNS") <(mp_campaign_oids | sort))"
[[ "$(printf '%s\n' "$NEW" | grep -c .)" == 1 ]] || fail_run "expected exactly one new campaign, found: '$NEW'"
CAMPAIGN="$NEW"
mp_get "accessCertificationCampaigns/$CAMPAIGN" > "$STAGE/raw/campaign-created.json"
CNAME="$(jq -r '.accessCertificationCampaign.name' "$STAGE/raw/campaign-created.json")"
CSTATE="$(jq -r '.accessCertificationCampaign.state' "$STAGE/raw/campaign-created.json")"
CSTAGE="$(jq -r '.accessCertificationCampaign.stageNumber' "$STAGE/raw/campaign-created.json")"
[[ "$CSTATE" == inReviewStage && "$CSTAGE" == 1 ]] || fail_run "campaign is '$CSTATE' stage '$CSTAGE', expected inReviewStage stage 1"
mp_get "accessCertificationCampaigns/$CAMPAIGN?include=case" > "$STAGE/raw/campaign-stage1-open.json"
NCASES="$(jq '[.accessCertificationCampaign.case[]?] | length' "$STAGE/raw/campaign-stage1-open.json")"
log "   '$CNAME' $CAMPAIGN: state $CSTATE, stage $CSTAGE, $NCASES case(s)"

# --- 5. probes + decisions -------------------------------------------------------------
log "5. Reviewer decisions (rpc/executeScript -> record-decisions.groovy)"
input="$(jq --arg c "$CAMPAIGN" --argjson probes "$PROBES" \
  '{campaignOid: $c, decisions: .decisions, probes: (if $probes then .probes else [] end)}' "$MP_DIR/decisions.json")"
b64="$(printf '%s' "$input" | base64 | tr -d '\n')"
[[ "$b64" =~ ^[A-Za-z0-9+/=]+$ ]] || fail_run "unexpected base64 output"
req="$(mktemp)"
{
  printf '%s\n' '<s:executeScript xmlns:s="http://midpoint.evolveum.com/xml/ns/public/model/scripting-3"' \
    '                 xmlns:c="http://midpoint.evolveum.com/xml/ns/public/common/common-3">' \
    '  <s:execute>' '    <s:script>' '      <c:code><![CDATA['
  sed "s|__INPUT_B64__|$b64|" "$MP_DIR/record-decisions.groovy"
  printf '%s\n' ']]></c:code>' '    </s:script>' '    <s:forWholeInput>true</s:forWholeInput>' '  </s:execute>' '</s:executeScript>'
} > "$req"
code="$(mp_curl rpc/executeScript -X POST -H 'Content-Type: application/xml' --data-binary @"$req" \
          -o "$STAGE/raw/executeScript-response.json" -w '%{http_code}' || true)"
rm -f "$req"
[[ "$code" == 200 ]] || fail_run "rpc/executeScript returned HTTP $code: $(jq -r '.. | .message? // empty' "$STAGE/raw/executeScript-response.json" 2>/dev/null | head -n 1)"
jq -r '.object.output.dataOutput.item[0].value["@value"]' "$STAGE/raw/executeScript-response.json" \
  | jq '.' > "$STAGE/decisions-run.json" || fail_run "no data output from record-decisions.groovy"
jq -r '.probes[] | "   probe: \(.actor) deciding \(.user) / \(.role) (assigned to \(.assignedReviewer // "?")): \(.status)"' "$STAGE/decisions-run.json"
jq -r '.decisions[] | "   \(.user) / \(.role) -> reviewer \(.reviewer // "?"): \(.response) [\(.status)]\(if .error then " " + .error else "" end)"' "$STAGE/decisions-run.json"
bad="$(jq '[.decisions[] | select(.status != "recorded" and .status != "left-unanswered")] | length' "$STAGE/decisions-run.json")"
[[ "$bad" == 0 ]] || fail_run "$bad decision(s) could not be recorded"
allowed="$(jq '[.probes[] | select(.status != "refused")] | length' "$STAGE/decisions-run.json")"
[[ "$allowed" == 0 ]] || fail_run "$allowed probe(s) were ALLOWED: a user who is not the assigned reviewer recorded a decision"
expected="$(jq '.decisions | length' "$MP_DIR/decisions.json")"
[[ "$NCASES" == "$expected" ]] || fail_run "campaign has $NCASES cases, decisions.json covers $expected"

# --- 6. close stage --------------------------------------------------------------------
log "6. Close review stage 1 (task: certificationCloseCurrentStage)"
mp_run_task "$MP_DIR/tasks/2-close-stage.xml" "$CAMPAIGN"
st="$(mp_campaign_state "$CAMPAIGN")"; [[ "$st" == reviewStageDone ]] || fail_run "after closing the stage the campaign is '$st'"
log "   state $st"

# --- 7. remediation ----------------------------------------------------------------------
log "7. Remediation (task: certificationRemediation, automated)"
mp_run_task "$MP_DIR/tasks/3-remediation.xml" "$CAMPAIGN"
st="$(mp_campaign_state "$CAMPAIGN")"; [[ "$st" == closed ]] || fail_run "after remediation the campaign is '$st'"
log "   state $st"

# --- 8. evidence -------------------------------------------------------------------------
log "8. Exporting the result"
mp_get "accessCertificationCampaigns/$CAMPAIGN?include=case" > "$STAGE/campaign.json"
mp_get "accessCertificationDefinitions/$MP_DEF_OID" > "$STAGE/definition.json"
export_users "$STAGE/users-after.json"
for f in "$MP_DIR"/objects/2*.xml; do mp_get "roles/$(mp_file_oid "$f")"; done | jq -s '[.[].role]' > "$STAGE/raw/roles.json"
for oid in "$MP_TASK_CREATE" "$MP_TASK_CLOSE_STAGE" "$MP_TASK_REMEDIATION"; do
  mp_get "tasks/$oid" > "$STAGE/raw/task-$oid.json"
done
# Task summary: a projection (named fields) of GET /tasks/{oid}; full objects in raw/.
jq -s '[.[].task | {oid, name, archetypes: ([.archetypeRef] | flatten | map(.oid?) | map(select(. != null))), handlerUri: (.handlerUri // null),
        work: ((.activity.work // {}) | keys), executionState, resultStatus,
        lastRunStartTimestamp, lastRunFinishTimestamp, completionTimestamp}]' \
  "$STAGE"/raw/task-*.json > "$STAGE/tasks.json"

# Name lookup for the flat CSV (users and roles of the dataset).
names="$(jq -s '[.[0][], .[1][]] | map({key: .oid, value: .name}) | from_entries' "$STAGE/users-after.json" "$STAGE/raw/roles.json")"
jq -r --argjson n "$names" '
  def nm($o): ($n[$o] // $o);
  def short(u): (u // "" | split("#") | last);
  ["case_id","user","role","reviewer_assigned","decided_by","response","comment","decided_at_utc","case_outcome","remediated_at_utc"],
  (.accessCertificationCampaign.case[] as $c
   | ([$c.workItem] | flatten | map(select(. != null))) as $wis
   | $wis[] as $w
   | [$c["@id"], nm($c.objectRef.oid), nm($c.targetRef.oid),
      ([$w.assigneeRef] | flatten | map(nm(.oid)) | join(";")),
      (if $w.performerRef then nm($w.performerRef.oid) else "" end),
      (if $w.output.outcome then short($w.output.outcome) else "(no response)" end),
      ($w.output.comment // ""), ($w.outputChangeTimestamp // ""),
      short($c.outcome), ($c.remediedTimestamp // "")])
  | @csv' "$STAGE/campaign.json" > "$STAGE/decisions.csv"

# Summary: counts straight from the exported campaign, plus the review KPIs as
# ADR 0012 ("How it is measured") defines them, applied to this campaign.
# Rubber-stamp thresholds come from the SAME file 10-Review-KPIs.ps1 reads
# (lab/iga/access-catalog.json reviewTiers.rubberStamp), so the two
# implementations cannot disagree: only reviewers with >= minItems items are
# eligible, and the minimum applies to BOTH clauses (approved all / median gap).
RUBBER_STAMP="$(jq -c '.reviewTiers.rubberStamp | {minItems, medianGapSeconds, targetReviewerPct}' "$PAM_DIR/../iga/access-catalog.json")" \
  || fail_run "cannot read reviewTiers.rubberStamp from lab/iga/access-catalog.json"
jq -e '(.minItems | type == "number") and (.medianGapSeconds | type == "number")' <<<"$RUBBER_STAMP" >/dev/null \
  || fail_run "lab/iga/access-catalog.json reviewTiers.rubberStamp lacks minItems / medianGapSeconds"
jq -n --arg ts "$TS" --arg v "$MP_VERSION" --arg c "$CAMPAIGN" --argjson rs "$RUBBER_STAMP" \
   --slurpfile camp "$STAGE/campaign.json" --slurpfile run "$STAGE/decisions-run.json" --argjson names "$names" '
  def secs: (sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) + ((capture("\\.(?<f>[0-9]+)Z$").f // "0") | ("0." + .) | tonumber);
  def median: sort | if length == 0 then null elif length % 2 == 1 then .[length / 2 | floor] else (.[length / 2 - 1] + .[length / 2]) / 2 end;
  def pct($a; $b): if $b == 0 then null else ($a * 1000 / $b | round / 10) end;
  ($camp[0].accessCertificationCampaign) as $k
  | ([$k.case[]]) as $cases
  | ([$cases[] | [.workItem] | flatten | .[] | select(. != null)]) as $wis
  | {
      run_utc: $ts,
      tool: ("Evolveum midPoint " + $v + " (local Docker stand-in for SailPoint / Saviynt; lab/pam/docker-compose.yml)"),
      driven_by: "lab/pam/midpoint/run-campaign.sh over the midPoint REST API",
      tenant: "none: local lab data only (fictional personas from lab/scripts/mock-hr/hr_feed.csv)",
      campaign: {oid: $c, name: $k.name, definition: $k.definitionRef.oid, state: $k.state,
                 start_utc: $k.startTimestamp, end_utc: $k.endTimestamp,
                 stage: [$k.stage] | flatten | map({number, name, startTimestamp, deadline, endTimestamp})},
      cases: ($cases | length),
      work_items: ($wis | length),
      decisions_recorded: ([$wis[] | select(.output.outcome != null)] | length),
      decided_by_assigned_reviewer: ([$wis[] | select(.output.outcome != null and .performerRef.oid == ([.assigneeRef] | flatten | .[0].oid))] | length),
      left_unanswered: ([$wis[] | select(.output.outcome == null)] | length),
      case_outcomes: ($cases | map(.outcome | split("#") | last) | group_by(.) | map({key: .[0], value: length}) | from_entries),
      remediated_cases: ([$cases[] | select(.remediedTimestamp != null)] | map({user: $names[.objectRef.oid], role: $names[.targetRef.oid], outcome: (.outcome | split("#") | last), remediedTimestamp})),
      reviewers: ([$wis[] | [.assigneeRef] | flatten | .[].oid] | map($names[.] // .) | group_by(.) | map({key: .[0], value: length}) | from_entries),
      authorization_probes: [$run[0].probes[] | {actor, item: (.user + " / " + .role), assignedReviewer, status}],
      kpis: (
        ([$wis[] | select(.output.outcome != null)]) as $dec
        | ([$dec[] | select(.output.outcome | endswith("#revoke"))]) as $rev
        | ($wis | group_by([.assigneeRef] | flatten | .[0].oid) | map(
            ([.[] | select(.output.outcome != null)]) as $d
            | {reviewer: ($names[[.[0].assigneeRef] | flatten | .[0].oid] // "?"),
               items: length, decided: ($d | length),
               revoked: ([$d[] | select(.output.outcome | endswith("#revoke"))] | length),
               median_seconds_between_decisions: ([$d[] | .outputChangeTimestamp | secs] | sort
                 | [range(1; length) as $i | .[$i] - .[$i - 1]] | median | if . == null then null else (. * 1000 | round / 1000) end)}
            | .eligible = (.items >= $rs.minItems)
            | .rubber_stamp = (.eligible and ((.revoked == 0 and .decided == .items)
                                 or (.median_seconds_between_decisions != null and .median_seconds_between_decisions < $rs.medianGapSeconds))))) as $per
        | ([$per[] | select(.eligible)]) as $elig
        | ([$elig[] | select(.rubber_stamp)]) as $flag
        | {
            definitions: "lab/docs/adr/0012-access-review-no-response-and-clinical-lockout.md, How it is measured (written for Entra reviews; applied here to the midPoint campaign)",
            completion_pct: pct($dec | length; $wis | length),
            completion_target_t2_pct: 95,
            revocation_rate_pct: pct($rev | length; $dec | length),
            per_reviewer: $per,
            rubber_stamp: {
              definition: ("reviewers with >= " + ($rs.minItems | tostring) + " items (the minimum applies to both clauses) who approved all of them, or whose median gap between decisions is < " + ($rs.medianGapSeconds | tostring) + " s; same thresholds as 10-Review-KPIs.ps1 (lab/iga/access-catalog.json reviewTiers.rubberStamp)"),
              min_items: $rs.minItems, median_gap_seconds: $rs.medianGapSeconds, target_reviewer_pct: $rs.targetReviewerPct,
              rate: (if ($elig | length) == 0
                     then {status: "not-measured", value: null, unit: "% of reviewers", numerator: 0, denominator: 0}
                     else {status: "measured", value: pct($flag | length; $elig | length), unit: "% of reviewers",
                           numerator: ($flag | length), denominator: ($elig | length)} end),
              flagged: [$flag[] | .reviewer]
            },
            approve_against_recommendation: "n/a: no recommendation engine configured in this lab",
            note: ((if ($elig | length) == 0
                    then "The rubber-stamp rate is not measurable on this campaign: no reviewer has the minimum number of items, so a median of a few gaps would mean nothing."
                    else "The rubber-stamp rate covers the eligible reviewers only." end)
                   + " The decisions are scripted (milliseconds apart), so their timing says nothing about a human reviewer. Completion is below the T2 target because one item was left unanswered on purpose.")
          })
    }' > "$STAGE/summary.json"

# No secret may land in the evidence (checked without printing it).
# grep reads the pattern from a pipe (-f), so the password is not in its argv.
if grep -rqF -f <(printf '%s\n' "$MP_PW") "$STAGE"; then fail_run "the administrator password appears in the exported files"; fi
if grep -rq -- "$PAM_DIR" "$STAGE"; then fail_run "an absolute local path appears in the exported files"; fi

# Every GUID-shaped id in the evidence, and what it is (none is a tenant id).
describe_guid() {
  local g="$1" f
  case "$g" in
    "$CAMPAIGN") echo "midPoint certification campaign '$CNAME' (OID generated by midPoint in this run)" ;;
    00000000-0000-0000-0000-000000000002) echo "midPoint built-in user 'administrator'" ;;
    00000000-0000-0000-0000-00000000000b) echo "midPoint built-in role 'Reviewer'" ;;
    00000000-0000-0000-0000-000000000321) echo "midPoint built-in archetype 'Business role'" ;;
    00000000-0000-0000-0000-000000000520) echo "midPoint built-in archetype 'Certification-related task'" ;;
    00000000-0000-0000-0000-000000000535) echo "midPoint built-in archetype 'Certification-remediation-related task'" ;;
    00000000-0000-0000-0000-000000000537) echo "midPoint built-in archetype 'Certification-campaign-close-current-stage task'" ;;
    00000000-0000-0000-0000-000000000811) echo "midPoint built-in mark 'Exclusion violation'" ;;
    c0471e00-0000-4000-8000-*)
      for f in "$MP_DIR"/objects/*.xml "$MP_DIR"/tasks/*.xml; do
        if [[ "$(mp_file_oid "$f")" == "$g" ]]; then echo "lab fixed OID, lab/pam/midpoint/${f#"$MP_DIR"/}"; return 0; fi
      done
      echo "UNKNOWN (lab namespace, no object file)" ;;
    *) echo "UNKNOWN" ;;
  esac
}
CURATED=(summary.json campaign.json decisions.csv decisions-run.json definition.json users-before.json users-after.json tasks.json)
{
  echo "# Every GUID-shaped id in this evidence set and what it is: lab-namespace OIDs"
  echo "# (fixed in the object files), midPoint built-in OIDs, and OIDs midPoint generated"
  echo "# during this run. All come from a local lab midPoint; none is a tenant id."
  (cd "$STAGE" && cat "${CURATED[@]}") | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
    | tr 'A-F' 'a-f' | sort -u | while IFS= read -r g; do printf '%s  # %s\n' "$g" "$(describe_guid "$g")"; done
} > "$STAGE/guids.txt"
unknown="$(grep -c 'UNKNOWN' "$STAGE/guids.txt" || true)"
[[ "$unknown" == 0 ]] || log "WARN  $unknown unexplained GUID(s) in the evidence: see guids.txt"

# Publish: copy the curated files (not raw/) and hash them.
(umask 022; mkdir -p "$EVIDENCE_DIR")   # public data: 755 folders
for f in "${CURATED[@]}" guids.txt run.log; do
  cp "$STAGE/$f" "$EVIDENCE_DIR/$f"
done
log "   files: ${CURATED[*]} guids.txt run.log SHA256SUMS"
log "DONE  campaign '$CNAME' closed: $(jq -r '"\(.cases) cases, \(.decisions_recorded) decisions by the assigned reviewer (\(.decided_by_assigned_reviewer)), \(.left_unanswered) unanswered, outcomes \(.case_outcomes | tostring), \(.remediated_cases | length) remediated"' "$STAGE/summary.json")"
log "evidence: $(rel "$EVIDENCE_DIR")/ (SHA256SUMS written last; full raw API responses in $(rel "$STAGE")/raw/, gitignored)"
# run.log must be final before hashing: detach from tee, let it drain, copy.
exec 1>&3 2>&4 3>&- 4>&-
wait "$TEE_PID" 2>/dev/null || true
rm -rf "$LOG_FIFO_DIR"
cp "$STAGE/run.log" "$EVIDENCE_DIR/run.log"
( cd "$EVIDENCE_DIR" && chmod 644 ./* && sha256_file "${CURATED[@]}" guids.txt run.log > SHA256SUMS && chmod 644 SHA256SUMS )
chmod 755 "$EVIDENCE_DIR"
