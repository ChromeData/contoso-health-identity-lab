#!/usr/bin/env bash
# =============================================================================
# tests/containment-drill.test.sh - offline test of ../containment-drill.sh
# -----------------------------------------------------------------------------
# No Azure, no Graph, no network: CONTOSO_OP points at a stub "op" (python)
# that answers the exact az calls the script makes from a JSON state file
# (users, Deleted users, the temporary rule, incidents and their entities and
# comments, containment runs and their card), and DRILL_CURL at a stub curl
# that serves the run-history "SAS links" from the same state. Proves:
#   * arm on a clean tenant: creates the drill user (password only on stdin),
#     enables the temporary rule, waits for the incident AND its Account
#     entity, disables the rule, starts pb-identity-contain, waits for the
#     card, prints DRILL_INCIDENT=<n> last;
#   * a second arm is idempotent: same incident, no new user, rule or run;
#   * arm REFUSES (exit 3, nothing created) while a card waits about a real
#     account (subject = the run's incident Account entity, UPN from Graph by
#     object id), and when a waiting card's subject cannot be read (an
#     AD-only entity with no Entra id);
#   * arm refuses an existing itdr-drill user without the script's marker
#     (exit 3) and a disabled one (exit 4: disarm first);
#   * a Graph read error is never read as "no user": arm stops, creates nothing;
#   * disarm cancels the waiting drill run, deletes AND purges the user,
#     deletes the rule, closes the incident (BenignPositive) with a comment
#     that carries the containment outcome, and reads it all back;
#   * a second disarm is idempotent, and arm right after it (a re-take) uses
#     a fresh rule id (Sentinel refuses a recently deleted one);
#   * --with-notify starts pb-identity-notify before the containment playbook;
#   * every list is followed across pages, and drill incidents are filtered
#     by title on the server: an older drill behind 60 newer incidents is
#     still found and closed;
#   * an interrupted arm's run (card not posted yet) is reused, not doubled;
#   * disarm cancels a drill run that has not posted its card yet;
#   * a running run whose trigger cannot be read is left alone, fails the
#     disarm read-back (NOT CLEAN) and makes arm refuse;
#   * an arm that fails after switching the rule on switches it off again;
#   * disarm never touches an itdr-drill user without the marker, and then
#     reports NOT CLEAN instead of success.
# Prints PASS/FAIL per assertion; exits 1 if anything failed.
# =============================================================================
# pass/fail always return 0, so `cond && pass ... || fail ...` cannot run both.
# shellcheck disable=SC2015
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../containment-drill.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/drill-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

# --- stub op (az) ---------------------------------------------------------------
cat >"$WORK/op" <<'PY'
#!/usr/bin/env python3
import json, os, re, sys, uuid
S = os.environ["STUB_STATE"]
st = json.load(open(S))
argv = sys.argv[1:]
st["calls"].append(" ".join(argv[:6]))
def save(): json.dump(st, open(S, "w"))
def paged(items, key="nextLink"):
    # Two items per page, like a real API that pages: callers must follow the link.
    m_ = re.search(r"[?&]skip=(\d+)", u); off = int(m_.group(1)) if m_ else 0
    o = {"value": items[off:off + 2]}
    if off + 2 < len(items): o[key] = re.sub(r"([?&])skip=\d+", "", u) + "&skip=%d" % (off + 2)
    return o
def out(o): save(); print(json.dumps(o)); sys.exit(0)
def notfound(): save(); sys.stderr.write('ERROR: Not Found({"error":{"code":"Request_ResourceNotFound"}})\n'); sys.exit(1)
if argv[:3] == ["az", "account", "show"]:
    out({"s": "sub-1", "t": "tenant-1"})
assert argv[:2] == ["az", "rest"], argv
m = argv[argv.index("--method") + 1]; u = argv[argv.index("--url") + 1]
body = json.loads(sys.stdin.read()) if "--body" in argv else None
if body is not None: st["bodies"].append(body)
# ---- Graph
if "graph.microsoft.com" in u:
    path = u.split("/v1.0/", 1)[1]
    if st.get("graph_fail"):
        save(); sys.stderr.write("ERROR: Forbidden({\"error\":{\"code\":\"Authorization_RequestDenied\"}})\n"); sys.exit(1)
    if m == "GET" and path.startswith("users/"):
        key = path[6:].split("?")[0].lower()
        user = st["users"].get(key) or next((x for x in st["users"].values() if x["id"] == key), None)
        if not user: notfound()
        out(user)
    if m == "POST" and path == "users":
        assert "password" in body["passwordProfile"] and len(body["passwordProfile"]["password"]) >= 20
        uid = str(uuid.uuid4())
        user = {"id": uid, "userPrincipalName": body["userPrincipalName"], "accountEnabled": True, "onPremisesSyncEnabled": None, "jobTitle": body["jobTitle"]}
        st["users"][body["userPrincipalName"].lower()] = user
        out({"id": uid, "userPrincipalName": body["userPrincipalName"], "jobTitle": body["jobTitle"]})
    if m == "GET" and path.startswith("users?"):
        out(paged([{"id": x["id"], "userPrincipalName": x["userPrincipalName"], "jobTitle": x.get("jobTitle"), "onPremisesSyncEnabled": x.get("onPremisesSyncEnabled")} for k, x in st["users"].items() if k.startswith("itdr-drill-")], "@odata.nextLink"))
    if m == "DELETE" and path.startswith("users/"):
        uid = path[6:]
        for k, x in list(st["users"].items()):
            if x["id"] == uid:
                d = dict(x); d["userPrincipalName"] = uid.replace("-", "") + x["userPrincipalName"]
                st["deleted"][uid] = d; del st["users"][k]; out({})
        notfound()
    if m == "GET" and path.startswith("directory/deletedItems/microsoft.graph.user"):
        out(paged(list(st["deleted"].values()), "@odata.nextLink"))
    if m == "DELETE" and path.startswith("directory/deletedItems/"):
        uid = path.split("/")[-1]
        if uid not in st["deleted"]: notfound()
        del st["deleted"][uid]; out({})
    raise SystemExit("stub: unhandled graph %s %s" % (m, u))
# ---- ARM: Sentinel
def inc_by_name(n):
    for i in st["incidents"]:
        if i["name"] == n: return i
if "/alertRules" in u:
    tail = u.split("/alertRules", 1)[1]
    if tail.startswith("?"):
        out(paged([{"name": "contoso-%d" % k, "properties": {"displayName": "Contoso rule %d" % k}} for k in range(5)] + [{"name": k, "properties": v} for k, v in st["rules"].items()]))
    rid = tail.lstrip("/").split("?")[0]
    if m == "PUT":
        if rid in st["rule_deleted"]:
            save(); sys.stderr.write("ERROR: Conflict({\"error\":{\"code\":\"Conflict\",\"message\":\"The rule with id was recently deleted\"}})\n"); sys.exit(1)
        st["rules"][rid] = body["properties"]
        if body["properties"]["enabled"] and st.get("fail_incidents_after_rule_on"): st["incidents_broken"] = True
        if body["properties"]["enabled"] and not any(i["status"] != "Closed" and i["rule"] == rid for i in st["incidents"]):
            oid = re.search(r'AadUserId = "([^"]+)"', body["properties"]["query"]).group(1)
            st["n"] += 1
            st["incidents"].insert(0, {"name": "inc-%d" % st["n"], "number": st["n"], "status": "New", "title": body["properties"]["displayName"], "rule": rid, "oids": [oid], "comments": [], "entity_delay": st.get("entity_delay", 0)})
        out({"name": rid})
    if m == "DELETE":
        if rid not in st["rules"]: notfound()
        del st["rules"][rid]; st["rule_deleted"].append(rid); out({})
if "/incidents" in u and "Microsoft.SecurityInsights" in u:
    tail = u.split("/incidents", 1)[1]
    if tail.startswith("?"):
        if st.get("incidents_broken"):
            save(); sys.stderr.write("ERROR: (InternalServerError) boom\n"); sys.exit(1)
        f = re.search(r"properties/title eq '([^']*)'", u)
        rows = [i for i in st["incidents"] if not f or i["title"] == f.group(1)]
        out(paged([{"name": i["name"], "properties": {"incidentNumber": i["number"], "status": i["status"], "title": i["title"]}} for i in rows]))
    name = tail.lstrip("/").split("/")[0].split("?")[0]
    i = inc_by_name(name)
    if i is None: notfound()
    if "/entities" in tail:
        if i.get("entity_delay", 0) > 0:
            i["entity_delay"] -= 1; out({"entities": []})
        out({"entities": [{"kind": "Account", "properties": {"aadUserId": o}} for o in i["oids"]]})
    if "/runPlaybook" in tail:
        if body["logicAppsResourceId"].endswith("/pb-identity-contain"):
            assert i.get("entity_delay", 0) == 0, "playbook started before the Account entity was attached"
            st["runs"].append({"name": "run-%d" % (len(st["runs"]) + 1), "status": "Running", "card": "Waiting", "incident": i["number"]})
        out({})
    if "/comments/" in tail and m == "PUT":
        i["comments"].append(body["properties"]["message"]); out({})
    if tail.endswith("/comments?api-version=2024-09-01") or "/comments?" in tail:
        out({"value": [{"properties": {"createdTimeUtc": "2026-11-05T00:00:%02dZ" % k, "message": c}} for k, c in enumerate(i["comments"])]})
    if m == "GET":
        out({"etag": "e1", "properties": {"title": i["title"], "severity": "High", "status": i["status"]}})
    if m == "PUT":
        i["status"] = body["properties"]["status"]; i["classification"] = body["properties"]["classification"]; out({})
# ---- ARM: Logic Apps runs
if "/workflows/pb-identity-contain/runs" in u:
    tail = u.split("/runs", 1)[1]
    if tail.startswith("?"):
        out(paged([{"name": r["name"]} for r in st["runs"] if r["status"] == "Running"]))
    rn = tail.lstrip("/").split("/")[0].split("?")[0]
    r = next(x for x in st["runs"] if x["name"] == rn)
    if tail.endswith("/cancel?api-version=2019-05-01"):
        r["status"] = "Cancelled"; r["card"] = "Cancelled"
        inc_by_name("inc-%d" % r["incident"])["comments"].append("<p><b>ITDR containment - playbook pb-identity-contain run %s</b></p><p>NO DECISION (cancelled)</p>" % rn)
        out({})
    if "/actions/Post_approval_card_and_wait/repetitions" in tail:
        if r["card"] == "none":              # the run has not reached the card yet
            r["card_after"] = r.get("card_after", 0) - 1
            if r["card_after"] <= 0: r["card"] = "Waiting"
            notfound()
        out({"value": [{"name": "000000", "properties": {"status": r["card"]}}]})
    out({"properties": {"trigger": {"outputsLink": {"uri": "https://stub/trigger/" + rn}}}})
raise SystemExit("stub: unhandled %s %s" % (m, u))
PY
cat >"$WORK/curl" <<'PY'
#!/usr/bin/env python3
import json, os, re, sys
st = json.load(open(os.environ["STUB_STATE"]))
cfg = sys.stdin.read()
assert "-K" in sys.argv and "-" in sys.argv, "the SAS link must come on stdin, not argv"
url = re.search(r'url = "([^"]+)"', cfg).group(1)
kind, rn = url.split("/")[-2:]
r = next(x for x in st["runs"] if x["name"] == rn)
if r.get("trigger") == "bad": print("<html>expired</html>"); sys.exit(0)
i = next(x for x in st["incidents"] if x["number"] == r["incident"])
ents = [{"kind": "Account", "properties": ({"aadUserId": o} if o != "none" else {"accountName": "ad-only"})} for o in i["oids"]]
print(json.dumps({"body": {"object": {"properties": {"incidentNumber": r["incident"], "relatedEntities": ents}}}}))
PY
chmod +x "$WORK/op" "$WORK/curl"

export CONTOSO_OP="$WORK/op" DRILL_CURL="$WORK/curl" STUB_STATE="$WORK/state.json"
export DRILL_DATE=20261105 DRILL_POLL_SECONDS=0 DRILL_WAIT_SECONDS=5
UPN="itdr-drill-20261105@ContosoHealthLab.onmicrosoft.com"
MARK="Throwaway containment drill target (containment-drill.sh) - delete after the drill"
fresh() { printf '{"users":{},"deleted":{},"rules":{},"rule_deleted":[],"incidents":[],"runs":[],"calls":[],"bodies":[],"n":100,"entity_delay":%s}' "${1:-0}" >"$STUB_STATE"; }
q() { python3 -c "import json,os; d=json.load(open(os.environ['STUB_STATE'])); print($1)"; }
run() { rc=0; out="$("$SCRIPT" "$@" 2>&1)" || rc=$?; }

# --- 1. arm on a clean tenant (the entity arrives two polls late) ------------
fresh 2; run arm
[ $rc -eq 0 ] && pass "arm exits 0" || fail "arm exits 0: rc=$rc $out"
[ "$(printf '%s\n' "$out" | tail -1)" = "DRILL_INCIDENT=101" ] && pass "arm prints DRILL_INCIDENT=101 last" || fail "last line: $out"
[ "$(q 'len(d["users"])')" = 1 ] && pass "one drill user created" || fail "users: $(q 'd["users"]')"
[ "$(q "list(d['users'].values())[0]['jobTitle']")" = "$MARK" ] && pass "the user carries the marker" || fail "marker"
[ "$(q 'len(d["rules"])')" = 1 ] && [ "$(q 'list(d["rules"].values())[0]["enabled"]')" = False ] && pass "one temporary rule, left disabled" || fail "rules after arm: $(q 'd["rules"]')"
[ "$(q 'sum(1 for c in d["calls"] if "runPlaybook" in c)')" = 1 ] && pass "pb-identity-contain started once, after the entity" || fail "runPlaybook calls: $(q 'd["calls"]')"
grep -q "Kx4%" <<<"$(q 'd["calls"]')" && fail "a password reached argv" || pass "no password in any az argv"

# --- 2. arm again: idempotent ---------------------------------------------------
writes() { q 'sum(1 for c in d["calls"] if ("--method PUT" in c or "--method DELETE" in c or "runPlaybook" in c or "/cancel" in c or c.endswith("v1.0/users --only-show-errors")))'; }
before="$(writes)"; run arm
[ $rc -eq 0 ] && grep -q "already armed: incident #101" <<<"$out" && [ "$(printf '%s\n' "$out" | tail -1)" = "DRILL_INCIDENT=101" ] && pass "second arm reports the same incident" || fail "second arm: $out"
[ "$(writes)" = "$before" ] && pass "second arm wrote nothing (no user, rule, run or cancel)" || fail "second arm wrote: before=$before after=$(writes)"
[ "$(q 'len(d["runs"])')" = 1 ] && pass "still one containment run" || fail "runs: $(q 'd["runs"]')"

# --- 3. disarm --------------------------------------------------------------------
run disarm
[ $rc -eq 0 ] && grep -q "^disarmed:" <<<"$out" && pass "disarm exits 0 and says disarmed" || fail "disarm: rc=$rc $out"
[ "$(q 'd["runs"][0]["status"]')" = Cancelled ] && pass "the waiting drill run was cancelled" || fail "run not cancelled"
[ "$(q 'len(d["users"]) + len(d["deleted"])')" = 0 ] && pass "drill user deleted AND purged" || fail "users left: $(q 'd["users"], d["deleted"]')"
[ "$(q 'len(d["rules"])')" = 0 ] && pass "temporary rule deleted" || fail "rule left"
[ "$(q 'd["incidents"][0]["status"] + "/" + d["incidents"][0]["classification"]')" = "Closed/BenignPositive" ] && pass "incident closed BenignPositive" || fail "incident: $(q 'd["incidents"][0]')"
grep -q "NO DECISION (cancelled)" <<<"$(q 'd["incidents"][0]["comments"][-1]')" && pass "closing comment carries the containment outcome" || fail "closing comment: $(q 'd["incidents"][0]["comments"]')"

# --- 4. disarm again: idempotent --------------------------------------------------
run disarm
[ $rc -eq 0 ] && pass "second disarm exits 0" || fail "second disarm: $out"

# --- 4b. re-take: arm right after disarm uses a NEW rule id (Sentinel refuses a
#     recently deleted one; the stub does too) and raises a new incident -----------
run arm
[ $rc -eq 0 ] && [ "$(printf '%s\n' "$out" | tail -1)" = "DRILL_INCIDENT=102" ] && pass "re-take: arm after disarm raises incident 102" || fail "re-take: rc=$rc $out"
[ "$(q 'len(set(d["rule_deleted"]) & set(d["rules"]))')" = 0 ] && pass "re-take used a fresh rule id" || fail "reused a deleted rule id"
run disarm
[ $rc -eq 0 ] && pass "re-take disarm exits 0" || fail "re-take disarm: $out"

# --- 4c. --with-notify starts pb-identity-notify first, then the containment -------
fresh; run arm --with-notify
pb="$(q '",".join(b["logicAppsResourceId"].split("/")[-1] for b in d["bodies"] if "logicAppsResourceId" in b)')"
[ $rc -eq 0 ] && [ "$pb" = "pb-identity-notify,pb-identity-contain" ] && pass "--with-notify runs notify, then contain" || fail "--with-notify: rc=$rc playbooks=$pb $out"
run disarm

# --- 4d. an older drill incident behind many newer ones is still found, and an
#     interrupted arm's run (card not posted yet) is reused, not doubled --------
fresh; run arm
python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p))
for k in range(60):
    d["incidents"].insert(0,{"name":"noise-%d"%k,"number":200+k,"status":"New","title":"Contoso - PIM activation (just-in-time elevation)","rule":"contoso-pim-activation","oids":[],"comments":[]})
d["runs"][0]["card"]="none"; d["runs"][0]["card_after"]=3   # the card is posted a few polls later
json.dump(d,open(p,"w"))
PY
run arm
[ $rc -eq 0 ] && grep -q "already working on incident #101" <<<"$out" && pass "arm reuses a running run whose card is not posted yet" || fail "running run reuse: rc=$rc $out"
[ "$(q 'sum(1 for c in d["calls"] if "runPlaybook" in c)')" = 1 ] && pass "...and starts no second containment run" || fail "second runPlaybook: $(q 'sum(1 for c in d["calls"] if "runPlaybook" in c)')"
run disarm
[ $rc -eq 0 ] && [ "$(q '[i["status"] for i in d["incidents"] if i["number"]==101][0]')" = Closed ] && pass "disarm finds the drill incident behind 60 newer ones (paged, filtered by title)" || fail "older drill incident: rc=$rc $out"

# --- 4d2. disarm also cancels a run that has not posted its card yet ---------------
fresh; run arm
python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p)); d["runs"][0]["card"]="none"; d["runs"][0]["card_after"]=99; json.dump(d,open(p,"w"))
PY
run disarm
[ $rc -eq 0 ] && [ "$(q 'd["runs"][0]["status"]')" = Cancelled ] && pass "disarm cancels a drill run whose card is not posted yet" || fail "pre-card run: rc=$rc status=$(q 'd["runs"][0]["status"]') $out"

# --- 4e. a waiting run whose trigger cannot be read is never "clean" -----------------
fresh; run arm
python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p)); d["runs"][0]["trigger"]="bad"; json.dump(d,open(p,"w"))
PY
run disarm
[ $rc -ne 0 ] && grep -q "NOT CLEAN: running run run-1 cannot be tied" <<<"$out" && pass "disarm fails NOT CLEAN on an unidentifiable waiting run" || fail "unreadable run: rc=$rc $out"
[ "$(q 'd["runs"][0]["status"]')" = Running ] && pass "...and leaves that run alone" || fail "cancelled an unidentified run"
run arm
[ $rc -eq 3 ] && pass "arm refuses while a waiting card's trigger is unreadable" || fail "arm with unreadable run: rc=$rc $out"

# --- 4f. a failure after the rule is switched on switches it off again ---------------
fresh; python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p)); d["fail_incidents_after_rule_on"]=True; json.dump(d,open(p,"w"))
PY
run arm
[ $rc -ne 0 ] && grep -q "temporary rule .* was switched off" <<<"$out" && pass "arm failing mid-way reports the rule switched off" || fail "trap: rc=$rc $out"
[ "$(q 'list(d["rules"].values())[0]["enabled"]')" = False ] && pass "...and the rule really is disabled" || fail "rule still enabled after a failed arm"

# --- 5. refuse while a card waits about a real account ----------------------------
fresh; python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p))
oid="11111111-1111-4111-8111-111111111111"
d["users"]["michaelwilliams@contosohealthlab.onmicrosoft.com"]={"id":oid,"userPrincipalName":"MichaelWilliams@ContosoHealthLab.onmicrosoft.com","accountEnabled":True,"onPremisesSyncEnabled":None,"jobTitle":"Owner"}
d["incidents"].append({"name":"inc-7","number":7,"status":"New","title":"Contoso ITDR - Directory role assigned outside PIM","rule":"contoso-role-assigned-outside-pim","oids":[oid],"comments":[]})
d["runs"].append({"name":"run-real","status":"Running","card":"Waiting","incident":7})
json.dump(d,open(p,"w"))
PY
run arm
[ $rc -eq 3 ] && grep -q "incident #7 about MichaelWilliams@" <<<"$out" && pass "arm refuses (exit 3) and names the real card" || fail "real card: rc=$rc $out"
[ "$(q 'len(d["users"])')" = 1 ] && [ "$(q 'len(d["rules"])')" = 0 ] && pass "nothing created while refused" || fail "created while refused"

python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p)); d["incidents"][0]["oids"]=["none"]; json.dump(d,open(p,"w"))
PY
run arm
[ $rc -eq 3 ] && pass "a waiting card with an unreadable subject also refuses" || fail "unreadable subject: rc=$rc $out"

# --- 6. an itdr-drill user that is not ours / disabled ------------------------------
fresh; python3 - <<PY
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p))
d["users"]["${UPN}".lower()]={"id":"u-1","userPrincipalName":"${UPN}","accountEnabled":True,"onPremisesSyncEnabled":None,"jobTitle":"Someone real"}
json.dump(d,open(p,"w"))
PY
run arm
[ $rc -eq 3 ] && grep -q "not this script's throwaway user" <<<"$out" && pass "arm refuses a same-named user without the marker" || fail "foreign user: rc=$rc $out"
run disarm
[ "$(q 'len(d["users"])')" = 1 ] && pass "disarm leaves the unmarked user alone" || fail "disarm deleted an unmarked user"
[ $rc -ne 0 ] && grep -q "NOT CLEAN" <<<"$out" && pass "...and reports NOT CLEAN instead of success" || fail "disarm with a foreign user: rc=$rc $out"

python3 - <<PY
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p))
u=d["users"]["${UPN}".lower()]; u["jobTitle"]="${MARK}"; u["accountEnabled"]=False
json.dump(d,open(p,"w"))
PY
run arm
[ $rc -eq 4 ] && grep -q "is disabled" <<<"$out" && pass "arm refuses a contained (disabled) drill user: disarm first" || fail "disabled user: rc=$rc $out"

# --- 7. a Graph read error is not "no user" -----------------------------------------
fresh; python3 - <<'PY'
import json,os
p=os.environ["STUB_STATE"]; d=json.load(open(p)); d["graph_fail"]=True; json.dump(d,open(p,"w"))
PY
run arm
[ $rc -ne 0 ] && grep -q "fail closed" <<<"$out" && pass "Graph error stops arm (fail closed)" || fail "graph error: rc=$rc $out"
[ "$(q 'sum(1 for c in d["calls"] if "--method POST" in c)')" = 0 ] && pass "...and nothing was created" || fail "created after a Graph error"

printf '\n%s\n' "$([ $FAILS -eq 0 ] && echo 'ALL PASS' || echo "$FAILS FAILED")"
[ $FAILS -eq 0 ]
