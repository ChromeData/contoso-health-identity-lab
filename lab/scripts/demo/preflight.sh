#!/usr/bin/env bash
# ok/no/warn only print (always succeed), so "test && ok || no" is safe here;
# the single-quoted $select is an OData query, not a shell variable.
# shellcheck disable=SC2015,SC2016
# =============================================================================
# lab/scripts/demo/preflight.sh - is the lab ready to record? (one command)
# -----------------------------------------------------------------------------
# Runs as the lab operator (lab/scripts/operator/op), never as you. It FIXES
# the two things that break between sessions and CHECKS the rest:
#   fixes   DC01 started (it shuts down every evening); Cloud Sync's pause
#           cleared (Microsoft pauses it while DC01 is off - "quarantine")
#   checks  the sync agent on DC01, HR -> AD, AD -> Entra and Entra -> AWS jobs,
#           the evidence runner on this Mac, Splunk and its live feed (newest
#           feed event in Splunk under 15 minutes old), trial end dates, time
#           left before DC01's evening shutdown, and that no demo hire is left over
# Prints one line per check and ends with READY or NOT READY.
#   preflight.sh            fix + check
#   preflight.sh --check    check only (starts nothing, clears nothing)
#   preflight.sh --intune   also start the Intune pilot device (vm-win11-01)
# =============================================================================
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
OP="$here/../operator/op"
RG=rg-identity-lab
CLOUDSYNC_SP=4c0d0455-9356-4954-b8ef-48edc1713efe
HR_SP=876b6339-1332-422c-8c56-3783ad828d50
REPO=ChromeData/contoso-health-identity-lab
DEMO_HIRE=400104
fix=1; intune=0
for a in "$@"; do case "$a" in --check) fix=0 ;; --intune) intune=1 ;; *) echo "unknown option $a" >&2; exit 2 ;; esac; done

bad=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
no()   { printf '  \033[31m✗\033[0m %s\n' "$*"; bad=$((bad + 1)); }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
g()    { "$OP" az rest --method GET --url "https://graph.microsoft.com/v1.0/$1" --query "$2" -o tsv 2>/dev/null; }
power() { "$OP" az vm get-instance-view -g "$RG" -n "$1" --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus | [0]" -o tsv 2>/dev/null; }

echo "Lab preflight $(date '+%a %b %e %H:%M %Z')"

# ---- sign-in ----------------------------------------------------------------
if "$OP" az account show >/dev/null 2>&1; then ok "Operator signed in (no password, certificate)"; else no "Operator sign-in failed: run lab/scripts/operator/lab-signin.sh"; echo "NOT READY"; exit 1; fi

# ---- DC01 -------------------------------------------------------------------
st="$(power vm-dc01)"
if [ "$st" != "VM running" ] && [ $fix = 1 ]; then
  echo "  … starting DC01 (about 3 minutes)"; "$OP" az vm start -g "$RG" -n vm-dc01 >/dev/null 2>&1; st="$(power vm-dc01)"
fi
[ "$st" = "VM running" ] && ok "DC01 (the on-site directory server) is running" || no "DC01 is '$st'"

# ---- sync agent on DC01 -----------------------------------------------------
agent=""; for _ in $(seq 1 20); do
  # The provisioning-agent list exists only on the beta endpoint.
  agent="$("$OP" az rest --method GET --url 'https://graph.microsoft.com/beta/onPremisesPublishingProfiles/provisioning/agents' --query "value[?contains(machineName,'DC01')].status | [0]" -o tsv 2>/dev/null)"
  [ "$agent" = active ] && break; [ $fix = 1 ] || break; sleep 30
done
[ "$agent" = active ] && ok "Sync agent on DC01 is connected" || no "Sync agent on DC01 is '${agent:-unknown}' (DC01 may still be booting)"

# ---- Cloud Sync (AD -> Entra) -----------------------------------------------
job="$(g "servicePrincipals/$CLOUDSYNC_SP/synchronization/jobs" "value[?templateId=='AD2AADProvisioning'].id | [0]")"
code="$(g "servicePrincipals/$CLOUDSYNC_SP/synchronization/jobs/$job" 'status.code')"
if [ "$code" = Quarantine ] && [ $fix = 1 ] && [ "$agent" = active ]; then
  "$OP" az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$CLOUDSYNC_SP/synchronization/jobs/$job/restart" \
    --headers Content-Type=application/json --body '{"criteria":{"resetScope":"QuarantineState"}}' >/dev/null 2>&1
  code="$(g "servicePrincipals/$CLOUDSYNC_SP/synchronization/jobs/$job" 'status.code')"; echo "  … cleared Cloud Sync's pause (it was quarantined while DC01 was off)"
fi
case "$code" in Active|NotRun) ok "Cloud Sync (Active Directory → Entra) is running ($code)" ;; *) no "Cloud Sync is '$code'" ;; esac

# ---- HR -> AD and Entra -> AWS ----------------------------------------------
hr="$(g "servicePrincipals/$HR_SP/synchronization/jobs" 'value[0].status.code')"
[ "$hr" = Active ] && ok "HR front door (HR → Active Directory) is on" || no "HR front door is '$hr'"
aws_sp="$(g "servicePrincipals?\$filter=displayName eq 'AWS IAM Identity Center'&\$select=id" 'value[0].id')"
aws="$(g "servicePrincipals/$aws_sp/synchronization/jobs" 'value[0].status.code')"
aws_last="$(g "servicePrincipals/$aws_sp/synchronization/jobs" 'value[0].status.lastExecution.state')"
[ "$aws" = Active ] && [ "$aws_last" != Failed ] && ok "AWS sync (Entra → AWS) is on, last cycle ${aws_last:-?}" || no "AWS sync is '$aws' (last cycle ${aws_last:-?})"

# ---- leftovers --------------------------------------------------------------
left="$(g "users?\$filter=employeeId eq '$DEMO_HIRE'&\$select=id" 'length(value)')"
[ "${left:-1}" = 0 ] && ok "No leftover demo hire (Sam Rivera) in Entra" || no "Sam Rivera ($DEMO_HIRE) still exists in Entra: run reset-demo-hire.sh $DEMO_HIRE --apply"
if git -C "$here/../../.." fetch -q origin hr-feed 2>/dev/null && git -C "$here/../../.." show origin/hr-feed:lab/scripts/mock-hr/hr_feed.csv | grep -q "^$DEMO_HIRE,"; then
  no "Sam Rivera is still in the HR file on hr-feed"
else ok "HR file is clean (no Sam Rivera yet)"; fi

# ---- Intune pilot device (optional) -----------------------------------------
if [ $intune = 1 ]; then
  st2="$(power vm-win11-01)"
  if [ "$st2" != "VM running" ] && [ $fix = 1 ]; then "$OP" az vm start -g "$RG" -n vm-win11-01 >/dev/null 2>&1; st2="$(power vm-win11-01)"; fi
  [ "$st2" = "VM running" ] && ok "Intune pilot device is running" || no "Intune pilot device is '$st2'"
fi

# ---- GitHub, Splunk ---------------------------------------------------------
rn="$(gh api "repos/$REPO/actions/runners" -q '[.runners[]|select(.name=="contoso-mac-evidence")|.status][0]' 2>/dev/null)"
[ "$rn" = online ] && ok "Evidence runner on this Mac is online" || no "Evidence runner is '${rn:-missing}' (cd ~/actions-runner-contoso && ./svc.sh start)"
open_gates="$(gh issue list -R "$REPO" --search 'Approve: apply in:title is:open' --json number -q 'length' 2>/dev/null)"
[ "${open_gates:-0}" = 0 ] && ok "No change is waiting for approval" || warn "$open_gates change(s) waiting for an 'approve' comment"
docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^contoso-splunk' && ok "Splunk is running (http://127.0.0.1:8000, set time to All time)" || warn "Splunk is not running (only needed for piece 8)"
# The Splunk live feed (lab/scripts/monitoring/feed-splunk-live.py, LaunchAgent every
# 5 min): its newest event in Splunk must be under 15 minutes old, or "Splunk watches
# the live lab too" is not true right now. `check` searches as a search-only Splunk
# user (password in Keychain), never the admin, and prints one line either way.
feed_out="$(/usr/bin/python3 -I "$here/../monitoring/feed-splunk-live.py" check --max-age-minutes 15 2>&1)"; feed_rc=$?
feed_line="$(printf '%s\n' "$feed_out" | tail -1)"
if [ "$feed_rc" = 0 ]; then ok "$feed_line"
else no "${feed_line:-Splunk live feed: check gave no answer} (lab/scripts/monitoring/README.md, The Splunk live feed)"; fi

# ---- sign-ins (signin-doctor) -----------------------------------------------
# Every identity the recording browser signs in as (lab/scripts/demo/signin/
# identities.json): a fresh headless sign-in with its own method (passkey,
# password + authenticator code, ServiceNow/Splunk local), no human. Pass-based
# identities are skipped (they would issue a credential). ~2 minutes.
# The table: node lab/scripts/demo/signin/doctor.mjs
doc_out="$(node "$here/signin/doctor.mjs" --summary 2>/dev/null)"; doc_rc=$?
doc_line="$(printf '%s\n' "$doc_out" | tail -1)"
if [ "$doc_rc" = 0 ]; then ok "Sign-ins: $doc_line"
else no "Sign-ins: ${doc_line:-signin-doctor gave no answer} (node lab/scripts/demo/signin/doctor.mjs for the table)"; fi

# ---- time limits ------------------------------------------------------------
end="$(g 'directory/subscriptions?$select=nextLifecycleDateTime,isTrial' "sort(value[?isTrial].nextLifecycleDateTime) | [0]")"
if [ -n "$end" ]; then
  days=$(( ($(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$end" +%s) - $(date +%s)) / 86400 ))
  [ $days -ge 3 ] && ok "Microsoft trials end ${end%%T*} ($days days left)" || no "Microsoft trials end ${end%%T*}: $days days left"
fi
et_h=$(TZ=America/New_York date +%H)
[ "$et_h" -lt 17 ] && ok "More than 2 hours before DC01's 7 pm (New York) shutdown" || warn "DC01 shuts down at 7 pm New York time: less than 2 hours left"

echo
if [ $bad = 0 ]; then echo "READY"; else echo "NOT READY ($bad to fix)"; exit 1; fi
