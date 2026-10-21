#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# =============================================================================
# test/e2e-midpoint.sh - prove the midPoint certification campaign really ran:
# run midpoint/run-campaign.sh (twice, for idempotency) against the local
# midPoint 4.10 stand-in and assert on its exported evidence AND on midPoint's
# live state over REST. Prints PASS/FAIL per assertion; exits 1 on any FAIL.
#
#   a. midPoint REST: administrator gets 200, a wrong password gets 401
#   b. run-campaign.sh, run 1: exits 0, evidence written (SHA256SUMS valid)
#   c. evidence: campaign closed; 7 cases; scope excludes the leaver, the
#      birthright role and midPoint's system roles; 6 decisions, each recorded
#      by the reviewer midPoint assigned (never the administrator); 1 item left
#      unanswered; reviewer routing (manager, manager's manager, fallback);
#      outcomes 4 accept / 2 revoke / 1 noResponse; exactly the 2 revoked and
#      the 1 unanswered assignments remediated; SoD marks present before, gone
#      after; both authorization probes refused; every GUID explained; no
#      secret, no local path
#   d. live state: the campaign is closed in midPoint; revoked and unanswered
#      assignments are really gone from the users; accepted, birthright and
#      out-of-scope assignments are untouched
#   e. run-campaign.sh, run 2: exits 0, a NEW campaign (number + 1), the
#      dataset reset to its baseline and reviewed again with the same result
#
# Test runs write evidence to out/e2e/midpoint/ (gitignored), never to
# lab/evidence/. To check a committed evidence folder offline (hashes and
# content only, nothing is run), use --verify:
#
# Usage: test/e2e-midpoint.sh                 # after ./pam-up.sh (midPoint up)
#        test/e2e-midpoint.sh --verify DIR    # e.g. ../evidence/midpoint/<ts>
# =============================================================================
# Predicates are called through check(), which ShellCheck cannot see.
# shellcheck disable=SC2329
CALLER_PWD="$PWD"
# shellcheck source-path=SCRIPTDIR source=../lib.sh
source "$(dirname "$0")/../lib.sh"   # cd's to lab/pam
# shellcheck source=../midpoint/lib-midpoint.sh
source "$PAM_DIR/midpoint/lib-midpoint.sh"
need curl; need jq; need perl; need openssl

FAILS=0
pass()  { printf 'PASS  %s\n' "$*"; }
fail()  { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
# No redirections on a `check` line: they would apply to check itself.
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
abort() { fail "$*"; printf '\nE2E-MIDPOINT ABORTED (%d failure(s))\n' "$FAILS"; exit 1; }
step()  { printf '\n'; log "== $*"; }
indent() { sed 's/^/      /'; }

VERIFY_DIR=""
case "${1:-}" in
  --verify) VERIFY_DIR="${2:?--verify needs an evidence directory}"
            [[ "$VERIFY_DIR" == /* ]] || VERIFY_DIR="$CALLER_PWD/$VERIFY_DIR" ;;
  "") ;;
  *) die "usage: test/e2e-midpoint.sh [--verify EVIDENCE_DIR]" ;;
esac

oid() { mp_file_oid "$MP_DIR/objects/$1"; }
U_HELEN="$(oid 30-user-helen-carter.xml)";   U_GRACE="$(oid 31-user-grace-mwangi.xml)"
U_DANIEL="$(oid 32-user-daniel-osei.xml)";   U_MARCUS="$(oid 33-user-marcus-bello.xml)"
U_DANA="$(oid 34-user-dana-okafor.xml)";     U_SOFIA="$(oid 35-user-sofia-reyes.xml)"
U_PRIYA="$(oid 36-user-priya-nair.xml)";     U_LEAD="$(oid 37-user-access-governance-lead.xml)"
R_NURSE="$(oid 20-role-nurse.xml)";          R_ICU="$(oid 21-role-icu-nurse.xml)"
R_PHARM="$(oid 22-role-pharmacist.xml)";     R_APC="$(oid 23-role-ap-clerk.xml)"
R_REVIEWER="00000000-0000-0000-0000-00000000000b"
ADMIN="00000000-0000-0000-0000-000000000002"
SOD_MARK="00000000-0000-0000-0000-000000000811"
OUTCOME="http://midpoint.evolveum.com/xml/ns/public/model/certification/outcome"

# --- predicates over an evidence folder ($EV) -------------------------------------
cases() { jq -c '[.accessCertificationCampaign.case[]]' "$EV/campaign.json"; }
case_of() { cases | jq -c --arg u "$1" --arg r "$2" '[.[] | select(.objectRef.oid == $u and .targetRef.oid == $r)]'; }
n_cases_of() { case_of "$1" "$2" | jq 'length'; }
is() { [[ "$1" == "$2" ]]; }

hashes_ok() {
  ( cd "$EV" && sha256_file -c SHA256SUMS >/dev/null 2>&1 ) || return 1
  # every file is hashed (nothing added afterwards)
  local listed present
  listed="$(awk '{print $2}' "$EV/SHA256SUMS" | sed 's/^\*//' | sort | tr '\n' ' ')"
  present="$(for f in "$EV"/*; do b="${f##*/}"; [[ "$b" == SHA256SUMS ]] || printf '%s\n' "$b"; done | sort | tr '\n' ' ')"
  [[ "$listed" == "$present" ]]
}
campaign_closed() {
  jq -e '.accessCertificationCampaign | .state == "closed" and (.endTimestamp | type == "string")' "$EV/campaign.json" >/dev/null
}
reviewer_of() { case_of "$1" "$2" | jq -r '.[0].workItem | [.] | flatten | .[0].assigneeRef | [.] | flatten | map(.oid) | join(",")'; }
outcome_of() { case_of "$1" "$2" | jq -r '.[0].outcome'; }
decided_by_assignee_count() {
  cases | jq '[.[].workItem | [.] | flatten | .[] | select(.output.outcome != null)
             | select(.performerRef.oid == ([.assigneeRef] | flatten | .[0].oid))] | length'
}
decided_count() { cases | jq '[.[].workItem | [.] | flatten | .[] | select(.output.outcome != null)] | length'; }
admin_performed() { cases | jq --arg a "$ADMIN" '[.[].workItem | [.] | flatten | .[] | select(.performerRef.oid? == $a)] | length'; }
outcome_count() { cases | jq --arg o "$OUTCOME#$1" '[.[] | select(.outcome == $o)] | length'; }
remediated_set() {
  cases | jq -r '[.[] | select(.remediedTimestamp != null) | "\(.objectRef.oid)/\(.targetRef.oid)"] | sort | join(" ")'
}
has_assignment() { # has_assignment FILE USER ROLE -> exit 0 if the user (in FILE) holds ROLE
  jq -e --arg u "$2" --arg r "$3" '.[] | select(.oid == $u) | [.assignment[]? | .targetRef.oid] | index($r) != null' "$1" >/dev/null
}
lacks_assignment() { ! has_assignment "$@"; }
all_hold() { # all_hold FILE ROLE USER... -> every USER holds ROLE
  local f="$1" r="$2" u; shift 2
  for u in "$@"; do has_assignment "$f" "$u" "$r" || return 1; done
}
marked_targets() { # marked_targets FILE USER -> role OIDs of the user's assignments carrying the SoD mark
  jq -r --arg u "$2" --arg m "$SOD_MARK" '.[] | select(.oid == $u) | .assignment[]?
    | select(([.effectiveMarkRef] | flatten | map(.oid?) | index($m)) != null) | .targetRef.oid' "$1" | sort | tr '\n' ' '
}
any_marked() { jq --arg m "$SOD_MARK" '[.[] | .assignment[]? | select(([.effectiveMarkRef] | flatten | map(.oid?) | index($m)) != null)] | length' "$1"; }
probes_refused() {
  jq -e '(.probes | length) == 2 and all(.probes[]; .status == "refused" and (.error | test("not authorized")))' "$EV/decisions-run.json" >/dev/null
}
no_unknown_guid() { ! grep -q UNKNOWN "$EV/guids.txt"; }
no_local_path() { ! grep -rqE '/Users/|/home/|/private/tmp|/var/folders' "$EV"; }
no_password() { # admin password from .env must not appear (pattern read from a pipe, never argv)
  [[ -f .env ]] || return 0
  mp_load_password
  ! grep -rqF -f <(printf '%s\n' "$MP_PW") "$EV"
}
csv_rows() { tail -n +2 "$EV/decisions.csv" | grep -c .; }

verify_evidence() { # verify_evidence DIR
  EV="$1"
  step "(c) evidence in $(basename "$EV")"
  check "SHA256SUMS verifies and covers every file" hashes_ok
  check "campaign state closed, end timestamp set" campaign_closed
  check "7 cases (requestable roles of enabled users)" is "$(cases | jq length)" 7
  check "leaver priya.nair (disabled) not in scope" is "$(cases | jq --arg u "$U_PRIYA" '[.[] | select(.objectRef.oid == $u)] | length')" 0
  check "birthright role Nurse (T3) not in scope" is "$(cases | jq --arg r "$R_NURSE" '[.[] | select(.targetRef.oid == $r)] | length')" 0
  check "midPoint system role Reviewer not in scope" is "$(cases | jq --arg r "$R_REVIEWER" '[.[] | select(.targetRef.oid == $r)] | length')" 0
  check "6 decisions recorded" is "$(decided_count)" 6
  check "... every one by the reviewer midPoint assigned (performerRef = assigneeRef)" is "$(decided_by_assignee_count)" 6
  check "... none by the administrator" is "$(admin_performed)" 0
  check "dana.okafor / ICU Nurse left unanswered -> outcome noResponse" is "$(outcome_of "$U_DANA" "$R_ICU")" "$OUTCOME#noResponse"
  check "routing: marcus.bello's items -> grace.mwangi (manager)" is "$(reviewer_of "$U_MARCUS" "$R_PHARM"),$(reviewer_of "$U_MARCUS" "$R_ICU")" "$U_GRACE,$U_GRACE"
  check "routing: dana.okafor, sofia.reyes -> grace.mwangi" is "$(reviewer_of "$U_DANA" "$R_ICU"),$(reviewer_of "$U_SOFIA" "$R_ICU")" "$U_GRACE,$U_GRACE"
  check "routing: grace.mwangi and daniel.osei (managers) -> helen.carter, never themselves" is "$(reviewer_of "$U_GRACE" "$R_ICU"),$(reviewer_of "$U_DANIEL" "$R_APC")" "$U_HELEN,$U_HELEN"
  check "routing: helen.carter (no manager) -> fallback access-governance-lead" is "$(reviewer_of "$U_HELEN" "$R_ICU")" "$U_LEAD"
  check "outcomes: 4 accept" is "$(outcome_count accept)" 4
  check "outcomes: 2 revoke (SoD conflict + stale grant)" is "$(outcome_count revoke),$(outcome_of "$U_MARCUS" "$R_PHARM"),$(outcome_of "$U_DANIEL" "$R_APC")" "2,$OUTCOME#revoke,$OUTCOME#revoke"
  check "outcomes: 1 noResponse" is "$(outcome_count noResponse)" 1
  check "remediated: exactly the 2 revoked + the 1 unanswered assignment" \
    is "$(remediated_set)" "$(printf '%s\n' "$U_DANIEL/$R_APC" "$U_MARCUS/$R_PHARM" "$U_DANA/$R_ICU" | sort | tr '\n' ' ' | sed 's/ $//')"
  check "before: SoD marks on marcus.bello's Nurse + Pharmacist only" is "$(marked_targets "$EV/users-before.json" "$U_MARCUS")|$(any_marked "$EV/users-before.json")" "$R_NURSE $R_PHARM |2"
  check "after: no assignment carries the SoD mark (conflict removed)" is "$(any_marked "$EV/users-after.json")" 0
  check "after (export): marcus.bello lost Pharmacist" lacks_assignment "$EV/users-after.json" "$U_MARCUS" "$R_PHARM"
  check "after (export): daniel.osei lost AP Clerk (stale)" lacks_assignment "$EV/users-after.json" "$U_DANIEL" "$R_APC"
  check "after (export): dana.okafor lost ICU Nurse (unanswered, T2 rule)" lacks_assignment "$EV/users-after.json" "$U_DANA" "$R_ICU"
  check "after (export): accepted ICU Nurse kept (marcus, sofia, grace, helen)" \
    all_hold "$EV/users-after.json" "$R_ICU" "$U_MARCUS" "$U_SOFIA" "$U_GRACE" "$U_HELEN"
  check "after (export): birthright Nurse kept (marcus, dana, sofia, grace)" \
    all_hold "$EV/users-after.json" "$R_NURSE" "$U_MARCUS" "$U_DANA" "$U_SOFIA" "$U_GRACE"
  check "after (export): priya.nair's AP Clerk untouched (out of scope; leaver path owns it)" has_assignment "$EV/users-after.json" "$U_PRIYA" "$R_APC"
  check "both authorization probes refused by midPoint ('not authorized')" probes_refused
  check "decisions.csv has one row per work item (7)" is "$(csv_rows)" 7
  check "ADR 0012 KPIs: completion 85.7% (6/7), revocation rate 33.3% (2/6)" \
    is "$(jq -r '"\(.kpis.completion_pct)/\(.kpis.revocation_rate_pct)"' "$EV/summary.json")" "85.7/33.3"
  if jq -e '.kpis | has("rubber_stamp")' "$EV/summary.json" >/dev/null; then
    # Current definition (same thresholds as 10-Review-KPIs.ps1, read from
    # lab/iga/access-catalog.json): no reviewer here has >= 10 items, so the
    # rate is not measured and nobody is flagged.
    check "ADR 0012 rubber-stamp: thresholds match access-catalog.json reviewTiers.rubberStamp" \
      is "$(jq -r '"\(.kpis.rubber_stamp.min_items)/\(.kpis.rubber_stamp.median_gap_seconds)"' "$EV/summary.json")" \
         "$(jq -r '.reviewTiers.rubberStamp | "\(.minItems)/\(.medianGapSeconds)"' "$PAM_DIR/../iga/access-catalog.json")"
    check "ADR 0012 rubber-stamp: not measured (0 eligible reviewers), nobody flagged" \
      is "$(jq -r '.kpis.rubber_stamp | "\(.rate.status)/\(.rate.denominator)/\(.flagged | length)"' "$EV/summary.json")" "not-measured/0/0"
  else
    # Evidence written before the KPI was aligned with 10-Review-KPIs.ps1
    # (2026-10-20 first run): its list used the median rule with no item
    # minimum. Kept as the genuine output of that run; see midpoint/README.md.
    check "ADR 0012 KPIs (pre-alignment evidence): rubber_stamp_flagged as that run computed it" \
      is "$(jq -r '.kpis.rubber_stamp_flagged | sort | join(",")' "$EV/summary.json")" "grace.mwangi,helen.carter"
  fi
  check "every GUID in the evidence is explained (guids.txt, no UNKNOWN)" no_unknown_guid
  check "no absolute local path in the evidence" no_local_path
  check "the midPoint administrator password is not in the evidence" no_password
}

verify_live() { # verify_live CAMPAIGN_OID
  local c="$1" live
  step "(d) live midPoint state after the run"
  check "campaign $c is closed in midPoint" is "$(mp_campaign_state "$c")" closed
  live="$(mktemp)"
  for u in "$U_HELEN" "$U_GRACE" "$U_DANIEL" "$U_MARCUS" "$U_DANA" "$U_SOFIA" "$U_PRIYA" "$U_LEAD"; do
    mp_get "users/$u"
  done | jq -s '[.[].user]' > "$live"
  check "live: marcus.bello has no Pharmacist assignment" lacks_assignment "$live" "$U_MARCUS" "$R_PHARM"
  check "live: daniel.osei has no AP Clerk assignment" lacks_assignment "$live" "$U_DANIEL" "$R_APC"
  check "live: dana.okafor has no ICU Nurse assignment" lacks_assignment "$live" "$U_DANA" "$R_ICU"
  check "live: accepted ICU Nurse kept (marcus, sofia, grace, helen)" \
    all_hold "$live" "$R_ICU" "$U_MARCUS" "$U_SOFIA" "$U_GRACE" "$U_HELEN"
  check "live: birthright Nurse kept (marcus, dana, sofia, grace)" \
    all_hold "$live" "$R_NURSE" "$U_MARCUS" "$U_DANA" "$U_SOFIA" "$U_GRACE"
  check "live: priya.nair (leaver, out of scope) still holds AP Clerk" has_assignment "$live" "$U_PRIYA" "$R_APC"
  check "live: no assignment carries the SoD mark any more" is "$(any_marked "$live")" 0
  rm -f "$live"
}

# --- verify-only mode ----------------------------------------------------------------
if [[ -n "$VERIFY_DIR" ]]; then
  [[ -d "$VERIFY_DIR" ]] || die "no such folder: $VERIFY_DIR"
  verify_evidence "$VERIFY_DIR"
  printf '\n'
  if [[ $FAILS -eq 0 ]]; then log "E2E-MIDPOINT VERIFY PASSED ($(basename "$VERIFY_DIR"))"; exit 0; fi
  log "E2E-MIDPOINT VERIFY FAILED: $FAILS assertion(s)"; exit 1
fi

# --- (a) REST + auth ----------------------------------------------------------------
step "(a) midPoint REST at $MP_URL"
mp_load_password
mp_wait_up
check "GET /ws/rest/self as administrator -> 200" is "$(mp_code self)" 200
check "... and with a wrong password -> 401 (auth really enforced)" is "$(MP_PW="wrong-$(openssl rand -hex 4)" mp_code self)" 401

run_campaign() { # run_campaign N -> sets EVN (evidence dir) and CAMP (campaign OID)
  EVN="$PAM_DIR/out/e2e/midpoint/$(date -u +%Y%m%dT%H%M%SZ)-run$1"
  local rc=0 outp
  outp="$("$PAM_DIR/midpoint/run-campaign.sh" --evidence-dir "$EVN" 2>&1)" || rc=$?
  printf '%s\n' "$outp" | grep -E 'DONE|FAILED|WARN|probe:|->  ?reviewer|state ' | indent || true
  [[ $rc -eq 0 ]] || { printf '%s\n' "$outp" | tail -n 15 | indent; abort "run-campaign.sh run $1 exited $rc"; }
  pass "run-campaign.sh run $1 exited 0"
  CAMP="$(jq -r '.campaign.oid' "$EVN/summary.json")"
}

# --- (b)-(d) run 1 ------------------------------------------------------------------
step "(b) run 1"
run_campaign 1
EV1="$EVN"; CAMP1="$CAMP"; NAME1="$(jq -r '.campaign.name' "$EV1/summary.json")"
verify_evidence "$EV1"
verify_live "$CAMP1"

# --- (e) run 2: idempotent re-run ----------------------------------------------------
step "(e) run 2 (idempotency: same dataset, new campaign)"
run_campaign 2
EV2="$EVN"; CAMP2="$CAMP"; NAME2="$(jq -r '.campaign.name' "$EV2/summary.json")"
n1="${NAME1##* }"; n2="${NAME2##* }"
new_campaign() { [[ "$CAMP2" != "$CAMP1" && "$n2" == "$((n1 + 1))" ]]; }
check "run 2 created a NEW campaign ($NAME2 after $NAME1)" new_campaign
check "run 1's campaign is still closed (history kept, not modified)" is "$(mp_campaign_state "$CAMP1")" closed
check "run 2 reviewed the same reset baseline (same outcomes)" \
  is "$(jq -c '.case_outcomes' "$EV2/summary.json")" "$(jq -c '.case_outcomes' "$EV1/summary.json")"
verify_evidence "$EV2"
verify_live "$CAMP2"

printf '\n'
if [[ $FAILS -eq 0 ]]; then
  log "E2E-MIDPOINT PASSED - evidence of both runs in out/e2e/midpoint/ (gitignored)"
  exit 0
fi
log "E2E-MIDPOINT FAILED: $FAILS assertion(s)"
exit 1
