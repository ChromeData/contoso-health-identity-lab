#!/usr/bin/env bash
# =============================================================================
# tests/close-build-noise.test.sh - offline test of ../close-build-noise.sh
# -----------------------------------------------------------------------------
# No Azure, no ServiceNow: CONTOSO_OP points at a stub "op" (python) that
# answers the Sentinel / Graph calls from a JSON state file, NOISE_CURL at a
# stub ServiceNow Table API on the same state, NOISE_SECURITY at a stub
# Keychain. Proves:
#   * the default is a dry run: decisions listed, nothing written anywhere;
#   * entities selector: an incident whose accounts are all lab test/admin
#     accounts is closed; one with no account entity is left alone unless
#     the window picks it;
#   * an incident naming the OWNER, a real (non-lab) account, or an account
#     whose name cannot be read is NEEDS-LEAD and is never closed - even
#     inside the window - until --lead-ok names it;
#   * --apply closes with a one-line reason (comment + BenignPositive),
#     resolves the incident's open ServiceNow tickets (state 6, the PDI close
#     code) and mirrors tickets whose Sentinel incident was already closed;
#   * --numbers narrows the set; bad arguments exit 2;
#   * an entities read error stops the run before anything is closed;
#   * ServiceNow answering 403 stops the run and names the role (itil);
#   * the ServiceNow password reaches curl only through -K (never argv).
# Prints PASS/FAIL per assertion; exits 1 if anything failed.
# =============================================================================
# pass/fail always return 0, so `cond && pass ... || fail ...` cannot run both.
# shellcheck disable=SC2015
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../close-build-noise.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/noise-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

cat >"$WORK/op" <<'PY'
#!/usr/bin/env python3
import json, os, re, sys
S = os.environ["STUB_STATE"]; st = json.load(open(S)); argv = sys.argv[1:]
st["calls"].append(" ".join(argv[:6]))
def save(): json.dump(st, open(S, "w"))
def out(o): save(); print(json.dumps(o) if not isinstance(o, str) else o); sys.exit(0)
def notfound(): save(); sys.stderr.write('ERROR: Not Found({"error":{"code":"NotFound"}})\n'); sys.exit(1)
if argv[:3] == ["az", "account", "show"]: out("sub-1")
m = argv[argv.index("--method") + 1]; u = argv[argv.index("--url") + 1]
body = json.loads(sys.stdin.read()) if "--body" in argv else None
if "graph.microsoft.com" in u:
    oid = u.split("/users/")[1].split("?")[0]
    if oid in st["users"]: out({"userPrincipalName": st["users"][oid]})
    notfound()
inc = {i["name"]: i for i in st["incidents"]}
tail = u.split("/incidents", 1)[1]
if tail.startswith("?"):
    rows = [i for i in st["incidents"] if i["status"] != "Closed"] if "status ne 'Closed'" in u else st["incidents"]
    mo = re.search(r"[?&]skip=(\d+)", u); off = int(mo.group(1)) if mo else 0
    o = {"value": [{"name": i["name"], "properties": {"incidentNumber": i["number"], "createdTimeUtc": i["created"], "severity": i["sev"], "title": i["title"], "status": i["status"]}} for i in rows[off:off + 2]]}
    if off + 2 < len(rows): o["nextLink"] = re.sub(r"[?&]skip=\d+", "", u) + "&skip=%d" % (off + 2)
    out(o)
name = tail.lstrip("/").split("/")[0].split("?")[0]
if name not in inc: notfound()
i = inc[name]
if "/entities" in tail:
    if st.get("entities_fail"): save(); sys.stderr.write("ERROR: (InternalServerError) boom\n"); sys.exit(1)
    out({"entities": [{"kind": "Account", "properties": a} for a in i["accounts"]] + [{"kind": "Ip", "properties": {"address": "198.51.100.7"}}]})
if "/comments/" in tail and m == "PUT": i["comments"].append(body["properties"]["message"]); out({})
if m == "GET": out({"etag": "e", "properties": {"incidentNumber": i["number"], "title": i["title"], "severity": i["sev"], "status": i["status"]}})
if m == "PUT": i["status"] = body["properties"]["status"]; i["classification"] = body["properties"]["classification"]; out({})
raise SystemExit("stub op: unhandled %s %s" % (m, u))
PY
cat >"$WORK/curl" <<'PY'
#!/usr/bin/env python3
import json, os, re, sys, urllib.parse
S = os.environ["STUB_STATE"]; st = json.load(open(S)); a = sys.argv[1:]
assert "-K" in a, "credentials must come through -K"
assert not any("sn-secret" in x for x in a), "the ServiceNow password reached argv"
cfg = open(a[a.index("-K") + 1]).read(); assert "svc.sentinel:sn-secret" in cfg
m = a[a.index("-X") + 1] if "-X" in a else "GET"
url = [x for x in a if x.startswith("https://")][0]
body = json.loads(sys.stdin.read()) if "--data-binary" in a else None
st["sn_calls"].append(m + " " + url)
def out(o, code=200): json.dump(st, open(S, "w")); print(json.dumps(o)); print(code, end="")
path, _, q = url.partition("?")
sid = path.rsplit("/incident", 1)[1].lstrip("/")
if m == "PATCH":
    if st.get("sn_forbidden"): out({"error": {"message": "Insufficient rights"}}, 403); sys.exit(0)
    t = next(t for t in st["tickets"] if t["sys_id"] == sid)
    t.update(state=body["state"], close_code=body["close_code"], close_notes=body["close_notes"]); out({"result": {"number": t["number"], "state": t["state"]}}); sys.exit(0)
if sid:
    t = next(t for t in st["tickets"] if t["sys_id"] == sid); out({"result": {"state": t["state"]}}); sys.exit(0)
qs = urllib.parse.unquote(urllib.parse.parse_qs(q)["sysparm_query"][0]) if "sysparm_query" in q else ""
open_ = [t for t in st["tickets"] if t["state"] in ("1", "2", "3")]
mc = re.search(r"correlation_id=([^\^]+)", qs)
rows = [t for t in open_ if t["corr"] == mc.group(1)] if mc else open_
out({"result": [{"sys_id": t["sys_id"], "number": t["number"], "correlation_id": t["corr"]} for t in rows]})
PY
cat >"$WORK/security" <<'SH'
#!/usr/bin/env bash
[ "$1 $2 $3" = "find-generic-password -s contoso-lab-servicenow-sentinel" ] && printf 'sn-secret\n' || exit 44
SH
chmod +x "$WORK/op" "$WORK/curl" "$WORK/security"
export CONTOSO_OP="$WORK/op" NOISE_CURL="$WORK/curl" NOISE_SECURITY="$WORK/security" STUB_STATE="$WORK/state.json" NOISE_NOW=2026-11-05T14:00:00Z

fresh() {
  python3 - <<'PY'
import json, os
A = lambda upn, oid=None: {"friendlyName": upn, **({"aadUserId": oid} if oid else {})}
inc = lambda n, created, accts, title="Contoso ITDR - Permission granted to an application", status="New": {"name": "inc-%d" % n, "number": n, "created": created, "sev": "Medium", "title": title, "status": status, "accounts": accts, "comments": []}
d = {"calls": [], "sn_calls": [],
     "users": {"aaaaaaaa-0000-4000-8000-000000000001": "test-user-b@contosohealthlab.com"},
     "incidents": [
        inc(28, "2026-11-05T02:08:00.1234567Z", [A("MichaelWilliams@ContosoHealthLab.onmicrosoft.com", "85244c30-468f-477a-8dd5-92948d9466b0")]),
        inc(31, "2026-11-05T02:58:00Z", []),
        inc(40, "2026-11-05T10:40:00Z", [A("adm-raj.patel@contosohealthlab.onmicrosoft.com")]),
        inc(43, "2026-11-04T11:08:00Z", [A("adm-labops@ContosoHealthLab.onmicrosoft.com")]),
        inc(44, "2026-11-05T11:22:00Z", []),
        inc(45, "2026-11-05T11:32:00Z", [A("dana.whitfield@contosohealthlab.com")]),
        inc(46, "2026-11-05T11:40:00Z", [{"accountName": "x"}]),
        inc(47, "2026-11-05T11:41:00Z", [{"aadUserId": "aaaaaaaa-0000-4000-8000-000000000001"}]),
        inc(35, "2026-11-05T10:19:00Z", [], title="Contoso TEST - containment drill", status="Closed")],
     "tickets": [
        {"sys_id": "s43", "number": "INC0010002", "corr": "inc-43", "state": "1"},
        {"sys_id": "s44", "number": "INC0010003", "corr": "inc-44", "state": "1"},
        {"sys_id": "s28", "number": "INC0009999", "corr": "inc-28", "state": "1"},
        {"sys_id": "s35", "number": "INC0010001", "corr": "inc-35", "state": "1"},
        {"sys_id": "sx", "number": "INC0000060", "corr": "", "state": "1"}]}
json.dump(d, open(os.environ["STUB_STATE"], "w"))
PY
}
q() { python3 -c "import json,os; d=json.load(open(os.environ['STUB_STATE'])); I={i['number']:i for i in d['incidents']}; T={t['number']:t for t in d['tickets']}; print($1)"; }
run() { rc=0; out="$("$SCRIPT" "$@" 2>&1)" || rc=$?; }
line() { grep -E "^$1 +#$2 " <<<"$out" | head -1; }

# --- 1. dry run --------------------------------------------------------------------
fresh; run --since 2026-11-05T09:00Z --until 2026-11-05T13:30Z
[ $rc -eq 0 ] && grep -q "DRY RUN: nothing changed" <<<"$out" && pass "default is a dry run" || fail "dry run: rc=$rc $out"
[ "$(q 'sum(1 for c in d["calls"] if "--method PUT" in c)')" = 0 ] && [ "$(q 'sum(1 for c in d["sn_calls"] if c.startswith("PATCH"))')" = 0 ] && pass "dry run writes nothing (Sentinel or ServiceNow)" || fail "dry run wrote"
[ -n "$(line CLOSE 40)" ] && pass "#40 (adm- account, in window) -> CLOSE" || fail "#40: $out"
[ -n "$(line CLOSE 43)" ] && pass "#43 (adm- account, outside the window) -> CLOSE by the entities selector" || fail "#43: $out"
[ -n "$(line CLOSE 44)" ] && pass "#44 (no account entity, in window) -> CLOSE by the window" || fail "#44: $out"
[ -n "$(line SKIP 31)" ] && pass "#31 (no account entity, outside the window) -> SKIP" || fail "#31: $out"
[ -n "$(line NEEDS-LEAD 28)" ] && pass "#28 (the owner) -> NEEDS-LEAD" || fail "#28: $out"
[ -n "$(line NEEDS-LEAD 45)" ] && pass "#45 (a real, non-lab account, in window) -> NEEDS-LEAD" || fail "#45: $out"
[ -n "$(line NEEDS-LEAD 46)" ] && pass "#46 (an account name that cannot be read) -> NEEDS-LEAD" || fail "#46: $out"
[ -n "$(line CLOSE 47)" ] && pass "#47 (object id resolved through Graph to a test user) -> CLOSE" || fail "#47: $out"
grep -q "#35 (already closed) -> ServiceNow INC0010001" <<<"$out" && pass "an already-closed incident's open ticket is listed to mirror" || fail "mirror: $out"
grep -q "INC0000060: no Sentinel incident" <<<"$out" && ! grep -q "ServiceNow INC0000060 (open)" <<<"$out" && pass "a ticket with no Sentinel incident is left alone" || fail "INC0000060 picked: $out"

# --- 2. apply ------------------------------------------------------------------------
run --since 2026-11-05T09:00Z --until 2026-11-05T13:30Z --apply
[ $rc -eq 0 ] && pass "--apply exits 0" || fail "apply: rc=$rc $out"
[ "$(q '",".join(str(n) for n in sorted(I) if I[n]["status"]=="Closed")')" = "35,40,43,44,47" ] && pass "closed exactly #40 #43 #44 #47 (35 was closed already)" || fail "closed set: $(q '[(n,I[n]["status"]) for n in sorted(I)]')"
[ "$(q 'I[40]["classification"]')" = BenignPositive ] && grep -q "Build/test noise before recording: entities are lab test/admin accounts" <<<"$(q 'I[40]["comments"][-1]')" && pass "BenignPositive with a one-line reason comment" || fail "reason: $(q 'I[40]')"
[ "$(q 'I[28]["status"]')" = New ] && [ "$(q 'I[45]["status"]')" = New ] && pass "owner and real-account incidents untouched without --lead-ok" || fail "NEEDS-LEAD closed"
[ "$(q 'T["INC0010002"]["state"]+T["INC0010003"]["state"]+T["INC0010001"]["state"]')" = 666 ] && pass "tickets of #43, #44 and the already-closed #35 resolved (state 6)" || fail "tickets: $(q 'd["tickets"]')"
[ "$(q 'T["INC0010002"]["close_code"]')" = "$(printf 'Resolved \xe2\x80\x93 Fixed Without Action')" ] && pass "close code is the PDI choice (en dash)" || fail "close code: $(q 'T["INC0010002"]["close_code"]')"
[ "$(q 'T["INC0009999"]["state"]')" = 1 ] && pass "the owner incident's ticket stays open" || fail "owner ticket resolved"

# --- 3. --lead-ok ----------------------------------------------------------------------
run --numbers 28 --lead-ok 28 --apply
[ $rc -eq 0 ] && [ "$(q 'I[28]["status"]')" = Closed ] && [ "$(q 'T["INC0009999"]["state"]')" = 6 ] && pass "--lead-ok closes the owner incident and its ticket" || fail "lead-ok: rc=$rc $out"

# --- 4. --numbers narrows; bad args ---------------------------------------------------
fresh; run --numbers 40-41 --apply
[ "$(q '",".join(str(n) for n in sorted(I) if I[n]["status"]=="Closed")')" = "35,40" ] && pass "--numbers 40-41 closes only #40" || fail "numbers: $(q '[(n,I[n]["status"]) for n in sorted(I)]')"
run --numbers 40-x; [ $rc -eq 2 ] && pass "bad --numbers exits 2" || fail "bad numbers rc=$rc"
run --until 2026-11-05T10:00Z; [ $rc -eq 2 ] && pass "--until without --since exits 2" || fail "until alone rc=$rc"
run --since yesterday; [ $rc -eq 2 ] && pass "a non-UTC-ISO time exits 2" || fail "bad time rc=$rc"

# --- 5. failures stop the run -----------------------------------------------------------
fresh; python3 -c "import json,os; p=os.environ['STUB_STATE']; d=json.load(open(p)); d['entities_fail']=True; json.dump(d,open(p,'w'))"
run --since 2026-11-05T09:00Z --apply
[ $rc -ne 0 ] && [ "$(q 'sum(1 for n in I if I[n]["status"]=="Closed")')" = 1 ] && pass "an entities read error stops before anything is closed" || fail "entities error: rc=$rc $out"
fresh; python3 -c "import json,os; p=os.environ['STUB_STATE']; d=json.load(open(p)); d['sn_forbidden']=True; json.dump(d,open(p,'w'))"
run --numbers 43 --apply
[ $rc -ne 0 ] && grep -q "needs the itil role" <<<"$out" && pass "ServiceNow 403 stops and names the role" || fail "403: rc=$rc $out"

printf '\n%s\n' "$([ $FAILS -eq 0 ] && echo 'ALL PASS' || echo "$FAILS FAILED")"
[ $FAILS -eq 0 ]
