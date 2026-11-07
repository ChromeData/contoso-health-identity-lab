#!/usr/bin/python3 -I
"""Prove the three ServiceNow use cases live, write evidence, clean up.

  /usr/bin/python3 -I lab/servicenow/demo/prove.py [--keep] [--only uc1,uc1b,leaver,mfa,report]

  uc1     Sofia Reyes (Registered Nurse) asks for ICU float cover in the
          portal; Grace Mwangi (her manager in Entra) approves in the portal;
          ServiceNow asks Entra ID Governance (adminAdd, RITM number in the
          justification); the ticket closes itself when Entra says Delivered;
          Sofia is then in App-ICU-CriticalCare-Users.
  uc1b    Marcus Bello (ICU nurse) asks for Pharmacy dispensing; Grace
          approves; Entra refuses (separation of duties: Pharmacy is
          incompatible with ICU - Critical Care Apps) and the ticket goes to
          the IAM Operations queue with Entra's reason. Nothing is granted.
  leaver  A leaver ticket for test-user-a (holding ICU float, granted for the
          test) creates an IAM task; Ava Lin (IAM Engineer) opens it and
          clicks "Remove access in Entra"; Entra removes it (adminRemove,
          SCTASK number in the justification); the task closes itself.
  mfa     A sign-in/MFA ticket for Marcus is assigned to Raj Patel; Raj's
          admin account activates PIM-Tier1-Helpdesk with the INC number as
          the justification (lab/scripts/demo/signin activatePim). The
          activation is read back from the Entra audit log.
  report  Screenshots of the IAM queue and the access-request list (grouped
          by status, with Duration = time to fulfil), signed in as Ava.

Evidence: lab/evidence/servicenow/<UTC>/ (readback.json, screenshots,
SHA256SUMS). Screens show persona names and ticket numbers only; no pass,
password or patient data is ever on screen or in a file.

Cleanup (unless --keep): every assignment a step granted is removed again
(adminRemove, justification names the proof; compared with what the people
held before the run, and after any in-flight add settles, also when a step
failed half-way), every test ticket is deleted, the PIM
activation is left to expire (1 hour). The ServiceNow build itself stays.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import snlib  # noqa: E402
import cleanup  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OP = os.path.join(REPO, "lab", "scripts", "operator", "op")
G = "https://graph.microsoft.com/v1.0"
EM = G + "/identityGovernance/entitlementManagement"
UPN = {
    "sofia": "sofia.reyes@contosohealthlab.com", "grace": "grace.mwangi@contosohealthlab.com",
    "marcus": "marcus.bello@contosohealthlab.com", "testa": "test-user-a@contosohealthlab.com",
    "ava": "ava.lin@contosohealthlab.com", "raj": "raj.patel@contosohealthlab.com",
}


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def graph(method, url, body=None):
    args = [OP, "az", "rest", "--method", method, "--url", url, "-o", "json"]
    if body is not None:
        args += ["--headers", "Content-Type=application/json", "--body", "@/dev/stdin"]
    r = subprocess.run(args, input=json.dumps(body) if body is not None else None, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"Graph {method} {url} failed: {r.stderr.strip()[:400]}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def node(*args):
    r = subprocess.run(["node", os.path.join(HERE, "portal.mjs"), *args], capture_output=True, text=True, cwd=HERE,
                       env=dict(os.environ, SN_ITEM_SYS_ID=ITEM_ID))
    out = [l for l in r.stdout.splitlines() if l.startswith("{")]
    if r.returncode != 0 or not out:
        raise SystemExit(f"portal.mjs {args[0]} failed: {(r.stderr or r.stdout).strip()[-600:]}")
    return json.loads(out[-1])


def wait(desc, fn, timeout=420, every=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise SystemExit(f"timed out waiting for {desc}")


def ritm_of(sn, req):
    r = sn.query("sc_req_item", f"request.number={req}^cat_item.nameINRequest app access,Report a leaver: remove app access",
                 ["sys_id", "number", "state", "approval", "stage", "correlation_id", "correlation_display",
                  "assignment_group", "opened_at", "closed_at", "calendar_duration"])
    if len(r) != 1:
        raise SystemExit(f"{req}: expected one lab request item, found {len(r)}")
    return r[0]


def notes(sn, sys_id):
    return [j["value"] for j in sn.request("GET", "/api/now/table/sys_journal_field", params={
        "sysparm_query": f"element_id={sys_id}^element=work_notes^ORDERBYsys_created_on", "sysparm_fields": "value"})["result"]]


def pkg(sn, key):
    return json.loads(sn.one("sys_properties", "name=contoso.entra.fulfilment.packages", ["value"])["value"])[key]


def user_id(upn):
    return graph("get", f"{G}/users/{upn}?$select=id")["id"]


def request_and_approve(sn, ev, who, app_text, reason, start, end, shots):
    t0 = now()
    req = node("request", who, app_text, reason, start, end, shots)["request"]
    ritm = ritm_of(sn, req)
    appr = sn.query("sysapproval_approver", f"sysapproval={ritm['sys_id']}", ["sys_id", "state", "approver"])
    ev["submitted"] = t0
    ev["request"], ev["ritm"] = req, ritm["number"]
    ev["after_submit"] = {"approval": ritm["approval"], "stage": ritm["stage"], "approvals": len(appr)}
    if ritm["approval"] != "requested" or len(appr) != 1:
        raise SystemExit(f"{ritm['number']}: expected one pending manager approval, got {ev['after_submit']}")
    approver = sn.one("sys_user", f"sys_id={appr[0]['approver']}", ["user_name"])["user_name"]
    ev["approver"] = approver
    node("approve", "grace.mwangi", ritm["number"], shots)
    ev["approved"] = now()
    return ritm


def uc1(sn, ev, shots):
    today = dt.date.today()
    ritm = request_and_approve(sn, ev, "sofia.reyes", "ICU float cover",
                               "Covering ICU night shifts from the float pool while two ICU nurses are on leave.",
                               today.isoformat(), (today + dt.timedelta(days=14)).isoformat(), shots)
    done = wait("RITM closed", lambda: (lambda r: r if r["state"] in ("3", "4") or "needs IAM" in r["correlation_display"] else None)(ritm_of(sn, ev["request"])))
    ev["closed"] = now()
    ev["final"] = {k: done[k] for k in ("state", "approval", "correlation_display", "opened_at", "closed_at", "calendar_duration")}
    ev["work_notes"] = notes(sn, ritm["sys_id"])
    if done["state"] != "3":
        raise SystemExit(f"{ritm['number']} did not close complete: {ev['final']} {ev['work_notes'][-1:]}")
    p, rid = done["correlation_id"].split("/")
    r = graph("get", f"{EM}/assignmentRequests?$filter=accessPackage/id eq '{p}' and id eq '{rid}'&$expand=requestor")["value"][0]
    ev["entra_request"] = {k: r.get(k) for k in ("id", "requestType", "state", "status", "justification", "createdDateTime", "completedDateTime", "schedule")}
    ev["entra_request"]["requestor"] = (r.get("requestor") or {}).get("displayName")
    sofia = user_id(UPN["sofia"])
    grp = graph("get", f"{G}/groups?$filter=displayName eq 'App-ICU-CriticalCare-Users'&$select=id")["value"][0]["id"]
    ev["member_of_App-ICU-CriticalCare-Users"] = grp in graph("post", f"{G}/users/{sofia}/checkMemberGroups", {"groupIds": [grp]})["value"]
    if not ev["member_of_App-ICU-CriticalCare-Users"]:
        raise SystemExit("Entra says delivered but Sofia is not in App-ICU-CriticalCare-Users")


def uc1b(sn, ev, shots):
    today = dt.date.today()
    ritm = request_and_approve(sn, ev, "marcus.bello", "Pharmacy",
                               "Helping the pharmacy with the evening medication round this month.",
                               today.isoformat(), (today + dt.timedelta(days=30)).isoformat(), shots)
    done = wait("RITM sent to IAM", lambda: (lambda r: r if "needs IAM" in r["correlation_display"] or r["state"] in ("3", "4") or
                                                     any("stopped" in n for n in notes(sn, ritm["sys_id"])) else None)(ritm_of(sn, ev["request"])))
    ev["final"] = {k: done[k] for k in ("state", "approval", "correlation_display", "assignment_group")}
    ev["work_notes"] = notes(sn, ritm["sys_id"])
    marcus = user_id(UPN["marcus"])
    ph = pkg(sn, "pharmacy")["accessPackageId"]
    ev["marcus_pharmacy_assignments"] = len(graph("get", f"{EM}/assignments?$filter=accessPackage/id eq '{ph}' and target/objectId eq '{marcus}' and state eq 'delivered'")["value"])
    if done["state"] == "3" or ev["marcus_pharmacy_assignments"]:
        raise SystemExit("SoD case: access was granted - that is a finding, stop")


def leaver(sn, ev, shots):
    icu = pkg(sn, "icu_float")
    testa = user_id(UPN["testa"])
    r = graph("post", f"{EM}/assignmentRequests", {
        "requestType": "adminAdd", "justification": "Lab proof setup (ServiceNow leaver task test): give test-user-a ICU float so the leaver task has something to remove",
        "assignment": {"targetId": testa, "assignmentPolicyId": icu["assignmentPolicyId"], "accessPackageId": icu["accessPackageId"]}})
    ev["setup_request"] = r["id"]
    wait("test-user-a ICU float delivered", lambda: graph("get", f"{EM}/assignments?$filter=accessPackage/id eq '{icu['accessPackageId']}' and target/objectId eq '{testa}' and state eq 'delivered'")["value"])
    item = sn.one("sc_cat_item", "name=Report a leaver: remove app access", ["sys_id"])
    person = sn.one("sys_user", f"user_name={UPN['testa']}", ["sys_id", "u_entra_object_id"])
    if person["u_entra_object_id"] != testa:
        raise SystemExit("test-user-a has no (or a wrong) Entra object id in ServiceNow: run provision on demand first")
    order = sn.request("POST", f"/api/sn_sc/servicecatalog/items/{item['sys_id']}/order_now", body={
        "sysparm_quantity": "1", "variables": {"leaving_person": person["sys_id"], "last_day": dt.date.today().isoformat()}})["result"]
    ev["request"] = order["number"]
    ritm = ritm_of(sn, order["number"])
    ev["ritm"] = ritm["number"]
    task = wait("leaver task", lambda: sn.query("sc_task", f"request_item={ritm['sys_id']}", ["sys_id", "number", "assignment_group", "short_description"]))[0]
    ev["task"] = task["number"]
    ev["task_short_description"] = task["short_description"]
    t0 = now()
    node("task", "ava.lin", task["sys_id"], shots)
    ev["clicked"] = t0
    done = wait("leaver task closed", lambda: (lambda t: t if t["state"] in ("3", "4") or "needs IAM" in t["correlation_display"] else None)(
        sn.one("sc_task", f"sys_id={task['sys_id']}", ["state", "correlation_id", "correlation_display", "opened_at", "closed_at", "calendar_duration"])))
    ev["closed"] = now()
    ev["final"] = done
    ev["work_notes"] = notes(sn, task["sys_id"])
    if done["state"] != "3":
        raise SystemExit(f"leaver task did not close: {done}")
    p, rid = done["correlation_id"].split(",")[0].split("/")
    r = graph("get", f"{EM}/assignmentRequests?$filter=accessPackage/id eq '{p}' and id eq '{rid}'")["value"][0]
    ev["entra_request"] = {k: r.get(k) for k in ("id", "requestType", "state", "status", "justification", "completedDateTime")}
    ev["testa_icu_float_left"] = len(graph("get", f"{EM}/assignments?$filter=accessPackage/id eq '{icu['accessPackageId']}' and target/objectId eq '{testa}' and state eq 'delivered'")["value"])


def mfa(sn, ev, shots):
    marcus = sn.one("sys_user", f"user_name={UPN['marcus']}", ["sys_id"])
    raj = sn.one("sys_user", f"user_name={UPN['raj']}", ["sys_id"])
    grp = sn.one("sys_user_group", "name=IAM Operations", ["sys_id"])
    inc = sn.insert("incident", {
        "caller_id": marcus["sys_id"], "short_description": "Lost phone: cannot pass the sign-in check (MFA) at the ICU workstation",
        "description": "Marcus replaced his phone and the authenticator app is gone. He can't sign in to the clinical apps. Identity to be verified by call-back to the ICU charge nurse.",
        "category": "inquiry", "contact_type": "phone", "urgency": "2", "impact": "3",
        "assignment_group": grp["sys_id"], "assigned_to": raj["sys_id"]})
    ev["incident"] = inc["number"]
    reason = f"{inc['number']}: Marcus Bello lost phone, identity verified by call-back; issue a one-time pass to re-register MFA"
    t0 = now()
    r = subprocess.run(["node", os.path.join(HERE, "pim.mjs"), "adm-raj.patel", "PIM-Tier1-Helpdesk", "1", reason],
                       capture_output=True, text=True, cwd=HERE)
    if r.returncode != 0:
        raise SystemExit(f"PIM activation failed: {r.stderr.strip()[-500:]}")
    ev["pim_activated"] = t0
    ev["justification"] = reason

    def audit():
        rows = graph("get", f"{G}/auditLogs/directoryAudits?$filter=activityDateTime ge {t0} and loggedByService eq 'PIM'&$top=50")["value"]
        hit = [a for a in rows if inc["number"] in json.dumps(a)]
        return hit
    hit = wait("PIM audit row with the INC number", audit, timeout=600, every=20)
    ev["pim_audit"] = [{"activity": a["activityDisplayName"], "at": a["activityDateTime"], "by": ((a.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName"),
                        "result": a["result"], "reason": a.get("resultReason")} for a in hit]
    sn.update("incident", inc["sys_id"], {"work_notes": f"PIM-Tier1-Helpdesk activated by adm-raj.patel with justification '{reason}' (Entra audit {hit[0]['activityDateTime']})."})


def report(sn, ev, shots):
    grp = sn.one("sys_user_group", "name=IAM Operations", ["sys_id"])
    node("shot", "ava.lin", f"task_list.do?sysparm_query=assignment_group={grp['sys_id']}^active=true^ORDERBYDESCsys_updated_on",
         os.path.join(shots, "20-iam-queue.png"))
    node("shot", "ava.lin", "sc_req_item_list.do?sysparm_view=contoso_access_requests&sysparm_query="
         + "cat_item.name=Request app access^GROUPBYstate^ORDERBYDESCopened_at", os.path.join(shots, "21-access-requests-by-status.png"))
    ev["shots"] = sorted(os.listdir(shots))


# (person, package key) pairs a step may grant. Their delivered assignments
# are read BEFORE the run; afterwards every assignment that was not there
# before is removed, whatever step failed and wherever (Greptile #254:
# "track grants as soon as they are submitted and undo them on failure").
GRANT_PAIRS = [("sofia", "icu_float"), ("testa", "icu_float"), ("marcus", "pharmacy")]


def delivered(sn, who, key):
    p = pkg(sn, key)["accessPackageId"]
    return {a["id"] for a in graph("get", f"{EM}/assignments?$filter=accessPackage/id eq '{p}' and target/objectId eq '{user_id(UPN[who])}' and state eq 'delivered'")["value"]}


def pending(sn, who, key):
    p = pkg(sn, key)["accessPackageId"]
    oid = user_id(UPN[who])
    reqs = graph("get", f"{EM}/assignmentRequests?$filter=accessPackage/id eq '{p}'&$expand=assignment&$top=50")["value"]
    return [r for r in reqs if r.get("requestType") == "adminAdd" and r.get("state") in ("submitted", "accepted", "pendingApproval", "delivering", "scheduled")
            and ((r.get("assignment") or {}).get("targetId") == oid)]


def undo_grants(sn, before, stamp, out):
    for who, key in GRANT_PAIRS:
        # An add still in flight would become access after cleanup: wait for it.
        try:
            wait(f"{who} {key} requests to settle", lambda: not pending(sn, who, key), timeout=480, every=20)
        except SystemExit as e:
            out.append(f"WARNING {who} {key}: {e} - check by hand")
        for asg in delivered(sn, who, key) - before.get((who, key), set()):
            graph("post", f"{EM}/assignmentRequests", {"requestType": "adminRemove", "assignment": {"id": asg},
                                                        "justification": f"Lab proof cleanup ({stamp}): access granted by the ServiceNow proof run"})
            out.append(f"adminRemove {key} for {who} ({asg})")


ITEM_ID = ""


def main():
    global ITEM_ID
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--only", default="uc1,uc1b,leaver,mfa,report")
    a = ap.parse_args()
    sn = snlib.Client()
    ITEM_ID = sn.one("sc_cat_item", "name=Request app access", ["sys_id"])["sys_id"]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(REPO, "lab", "evidence", "servicenow", stamp)
    os.makedirs(out, exist_ok=True)
    ev = {"run": stamp, "instance": snlib.INSTANCE, "steps": {}}
    tickets = []
    before = {(w, k): delivered(sn, w, k) for w, k in GRANT_PAIRS}
    ev["held_before"] = {f"{w}/{k}": len(v) for (w, k), v in before.items()}
    try:
        for name in a.only.split(","):
            step = {}
            ev["steps"][name] = step
            {"uc1": uc1, "uc1b": uc1b, "leaver": leaver, "mfa": mfa, "report": report}[name](sn, step, out)
            print(f"{name}: OK")
    finally:
        # Every ticket a step got as far as creating, also when it failed
        # half-way (a RITM left waiting for approval was seen 2026-11-07).
        for step in ev["steps"].values():
            tickets += [step[k] for k in ("ritm", "incident") if step.get(k)]
        with open(os.path.join(out, "readback.json"), "w") as f:
            json.dump(ev, f, indent=1, sort_keys=True)
        if not a.keep:
            ev["cleanup"] = cleanup.clean(sn, tickets)
            undo_grants(sn, before, stamp, ev["cleanup"])
            with open(os.path.join(out, "readback.json"), "w") as f:
                json.dump(ev, f, indent=1, sort_keys=True)
        with open(os.path.join(out, "SHA256SUMS"), "w") as f:
            for n in sorted(os.listdir(out)):
                if n != "SHA256SUMS":
                    f.write(hashlib.sha256(open(os.path.join(out, n), "rb").read()).hexdigest() + "  " + n + "\n")
        print(f"evidence: {os.path.relpath(out, REPO)}")


if __name__ == "__main__":
    main()
