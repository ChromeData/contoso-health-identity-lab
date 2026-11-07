#!/usr/bin/python3 -I
"""Build the ServiceNow side of the three IAM use cases, as code.

  1. Staff self-service: catalog item "Request app access" -> the manager
     approves -> ServiceNow asks Entra ID Governance to assign the access
     package (adminAdd, ticket number in the justification) -> closed when
     Entra says Delivered.
  2. The IAM queue: group "IAM Operations" receives everything a person must
     finish (no manager, "another app", an Entra refusal), plus the leaver
     access-removal task with its "Remove access in Entra" button.
  3. Reporting: one list of access requests, grouped by status, with the
     time each took to fulfil (Duration).

Idempotent: every record is found by name and created or updated, so a
re-run changes only what differs. Server code lives in lab/servicenow/server/
(one file per record), so reviewers read real JavaScript, not JSON strings.

WHY TABLE API AND NOT AN UPDATE SET: an update set is an XML export of what
someone clicked; it cannot be reviewed line by line, and it cannot resolve
the Entra ids (access packages, client id) that differ per tenant. This
script is the reviewable source; ServiceNow still records every change it
makes in the instance's own update history (sys_update_xml).

Usage (operator Mac):
  /usr/bin/python3 -I lab/servicenow/apply.py --plan            # read only: what would change
  /usr/bin/python3 -I lab/servicenow/apply.py                    # apply
  /usr/bin/python3 -I lab/servicenow/apply.py --client-id <id>   # client id not from Graph lookup
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import snlib  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OP = os.path.join(REPO, "lab", "scripts", "operator", "op")
EM = "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement"


def server(name):
    with open(os.path.join(HERE, "server", name)) as f:
        return f.read()


def graph_get(url, runner=subprocess.run):
    """Graph GET as the lab operator. Fails closed: a failed call stops the run."""
    r = runner([OP, "az", "rest", "--method", "get", "--url", url, "-o", "json"], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"Graph read failed ({url}): {r.stderr.strip()[:300]}")
    return json.loads(r.stdout)


def resolve_packages(cfg, get=graph_get):
    """Choice value -> {accessPackageId, assignmentPolicyId, label}, read live.

    Exactly one package per name, and exactly one assignment policy that can
    take an admin assignment (a request policy with an expiry). Birthright
    (automatic) policies are refused: they follow HR attributes, and an admin
    assignment on them would be undone by the next evaluation.
    """
    out = {}
    for app in cfg["requestItem"]["apps"]:
        name = app["accessPackage"]
        if not name:
            continue
        found = get(f"{EM}/accessPackages?$filter=displayName eq '{name}'&$expand=assignmentPolicies")["value"]
        if len(found) != 1:
            raise SystemExit(f"access package '{name}': expected exactly 1, Graph returned {len(found)}")
        pols = [p for p in found[0].get("assignmentPolicies", [])
                if (p.get("expiration") or {}).get("type") not in (None, "noExpiration")]
        if len(pols) != 1:
            raise SystemExit(f"access package '{name}': expected exactly 1 request policy with an expiry, found {len(pols)}")
        out[app["value"]] = {"accessPackageId": found[0]["id"], "assignmentPolicyId": pols[0]["id"], "label": name}
    return out


def resolve_client_id(cfg, get=graph_get):
    apps = get("https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '"
               + cfg["fulfilmentAppDisplayName"] + "'&$select=appId")["value"]
    if len(apps) != 1:
        raise SystemExit(f"app '{cfg['fulfilmentAppDisplayName']}': expected exactly 1, found {len(apps)} "
                         "(is modules/apps servicenow_fulfilment applied? or pass --client-id)")
    return apps[0]["appId"]


class Plan:
    """Collects (table, key, values) and either prints or applies them."""

    def __init__(self, sn, dry):
        self.sn, self.dry, self.log, self.missing = sn, dry, [], False

    def put(self, table, key_query, values):
        if self.dry:
            row = self.sn.one(table, key_query, ["sys_id"] + list(values.keys()))
            if row is None:
                how = "create"
            else:
                diff = [k for k, v in values.items() if str(row.get(k, "")) != str(v)]
                how = "update " + ",".join(diff) if diff else "same"
            self.log.append(f"{how:30.30} {table} [{key_query}]")
            return row or {"sys_id": f"<new {table}>"}
        row, how = self.sn.upsert(table, key_query, values)
        self.log.append(f"{how:30.30} {table} [{key_query}]")
        return row


# ServiceNow cuts sys_script / script action names at 40 characters (seen
# 2026-11-07: a longer name was stored cut, so the next run's lookup missed it
# and created a duplicate). Every name used as a lookup key stays <= 40.
NAME_MAX = 40

# One person, one request: no quantity, cart, draft, wish list or attachment
# box, and no "Delivery time" (the real answer is "minutes after approval").
# The *_v2 fields are what Service Portal / Employee Center read.
PORTAL_OPTIONS = {k: "true" for k in (
    "no_quantity", "no_quantity_v2", "no_cart", "no_cart_v2", "no_save_as_draft",
    "no_wishlist_v2", "no_attachment_v2", "no_delivery_time_v2")}

ACCESS_LIST_QUERY = "cat_item.name=Request app access^GROUPBYstate^ORDERBYDESCopened_at"
# No delivery plan, no workflow, no flow: ServiceNow then neither creates its
# DEFAULT plan's tasks ("Assess or Scope Task", "Provide requested service")
# nor copies the request's automatic approval down to the item
# (CatalogRequestUtil.cascadeRequestApprovalDeliveryPlan returns early when
# cat_item.delivery_plan is empty). The business rules below own the approval.
# Seen 2026-11-07: with the DEFAULT plan the item showed "Approved" before the
# manager had seen it.
PORTAL_OPTIONS["delivery_plan"] = ""


def build(cfg, sn, packages, client_id, dry=False):
    p = Plan(sn, dry)

    # ---- custom field: the Entra object id (join key for Graph calls) -------
    p.put("sys_dictionary", "name=sys_user^element=u_entra_object_id", {
        "name": "sys_user", "element": "u_entra_object_id", "internal_type": "string",
        "max_length": "40", "column_label": "Entra object ID",
    })

    # ---- properties -----------------------------------------------------------
    props = {
        "contoso.entra.tenant_id": (cfg["tenantId"], "Entra tenant the fulfilment app signs in to."),
        "contoso.entra.fulfilment.client_id": (client_id, "Client id of the Entra app 'ServiceNow - Access Fulfilment' (Terraform modules/apps/servicenow_fulfilment.tf). Not a secret."),
        "contoso.entra.fulfilment.jwt_provider": (cfg["jwtProvider"], "JWT provider whose key signs the client assertion (lab/servicenow/fulfilment-cert.py)."),
        "contoso.entra.fulfilment.packages": (json.dumps(packages, sort_keys=True), "Catalog choice -> Entra access package + policy. Written by lab/servicenow/apply.py from a live Graph read; edit config.json, not this."),
        "contoso.entra.iam_queue": (cfg["iamQueue"]["name"], "Assignment group that finishes anything automation cannot."),
    }
    for name, (value, desc) in props.items():
        p.put("sys_properties", f"name={name}", {"name": name, "value": value, "type": "string", "description": desc})

    # ---- script include -------------------------------------------------------------
    p.put("sys_script_include", "name=ContosoEntraAccess", {
        "name": "ContosoEntraAccess", "api_name": "global.ContosoEntraAccess", "client_callable": "false",
        "active": "true", "access": "package_private", "script": server("ContosoEntraAccess.js"),
        "description": "ServiceNow -> Entra ID Governance (assignment requests). Source: lab/servicenow/server/ContosoEntraAccess.js",
    })

    # ---- IAM queue --------------------------------------------------------------------
    q = cfg["iamQueue"]
    grp = p.put("sys_user_group", f"name={q['name']}", {"name": q["name"], "description": q["description"], "active": "true"})
    for role in q["roles"]:
        r = sn.one("sys_user_role", f"name={role}", ["sys_id"])
        if r is None:
            raise SystemExit(f"role {role} not found")
        if not dry:
            p.put("sys_group_has_role", f"group={grp['sys_id']}^role={r['sys_id']}", {"group": grp["sys_id"], "role": r["sys_id"]})

    for upn in q.get("members", []):
        u = sn.one("sys_user", f"user_name={upn}", ["sys_id"])
        if u is None:
            # Not a silent skip: the run says so, and exits non-zero at the end.
            p.log.append(f"{'MISSING':30.30} sys_user [{upn}] not provisioned yet (App-ServiceNow-Users?)")
            p.missing = True
            continue
        if not dry:
            p.put("sys_user_grmember", f"group={grp['sys_id']}^user={u['sys_id']}", {"group": grp["sys_id"], "user": u["sys_id"]})

    # ---- category + catalog items + variables ------------------------------------------
    catalog = sn.one("sc_catalog", f"title={cfg['catalog']}", ["sys_id"])
    if catalog is None:
        raise SystemExit(f"catalog {cfg['catalog']} not found")
    cat = p.put("sc_category", f"title={cfg['category']['title']}^sc_catalog={catalog['sys_id']}", {
        "title": cfg["category"]["title"], "description": cfg["category"]["description"],
        "sc_catalog": catalog["sys_id"], "active": "true",
    })

    ri = cfg["requestItem"]
    item = p.put("sc_cat_item", f"name={ri['name']}", {
        "name": ri["name"], "short_description": ri["short_description"], "description": ri["description"],
        "sc_catalogs": catalog["sys_id"], "category": cat["sys_id"], "active": "true",
        "workflow": "", "flow_designer_flow": "", **PORTAL_OPTIONS,
    })
    variables = [
        ("app_access", "Which app do you need?", "5", True, 100, None),
        ("business_reason", "Why do you need it? (no patient details)", "2", True, 200, None),
        ("start_date", "Start date", "9", True, 300, None),
        ("end_date", "End date (180 days at most)", "9", True, 400, None),
    ]
    vids = {}
    for name, text, typ, mand, order, ref in variables:
        v = p.put("item_option_new", f"cat_item={item['sys_id']}^name={name}", {
            "cat_item": item["sys_id"], "name": name, "question_text": text, "type": typ,
            "mandatory": "true" if mand else "false", "order": str(order), "active": "true",
        })
        vids[name] = v["sys_id"]
    for i, app in enumerate(ri["apps"]):
        p.put("question_choice", f"question={vids['app_access']}^value={app['value']}", {
            "question": vids["app_access"], "value": app["value"], "text": app["text"], "order": str((i + 1) * 100),
        })

    li = cfg["leaverItem"]
    litem = p.put("sc_cat_item", f"name={li['name']}", {
        "name": li["name"], "short_description": li["short_description"], "sc_catalogs": catalog["sys_id"],
        "category": cat["sys_id"], "active": "true", "workflow": "", "flow_designer_flow": "", **PORTAL_OPTIONS,
    })
    for name, text, typ, order, extra in [
        ("leaving_person", "Who is leaving?", "8", 100, {"reference": "sys_user"}),
        ("last_day", "Last working day", "9", 200, {}),
    ]:
        p.put("item_option_new", f"cat_item={litem['sys_id']}^name={name}", dict({
            "cat_item": litem["sys_id"], "name": name, "question_text": text, "type": typ,
            "mandatory": "true", "order": str(order), "active": "true"}, **extra))

    # ---- business rules ---------------------------------------------------------------------
    rq = f"current.cat_item.name == '{ri['name']}'"
    rules = [
        ("Contoso - access: route to manager", "sc_req_item", "before", True, False, rq, "br_request_ask_manager_before.js", 100),
        ("Contoso - access: create approval", "sc_req_item", "after", True, False,
         rq + " && current.approval == 'requested'", "br_request_ask_manager_after.js", 100),
        ("Contoso - access: manager decided", "sysapproval_approver", "after", False, True,
         "current.state.changes() && (current.state == 'approved' || current.state == 'rejected') && current.source_table == 'sc_req_item'",
         "br_approval_decided.js", 100),
        ("Contoso - time to fulfil (request item)", "sc_req_item", "before", False, True,
         "(current.state.changesTo(3) || current.state.changesTo(4)) && current.opened_at.hasValue()", "br_time_to_fulfil.js", 900),
        ("Contoso - time to fulfil (catalog task)", "sc_task", "before", False, True,
         "(current.state.changesTo(3) || current.state.changesTo(4)) && current.opened_at.hasValue()", "br_time_to_fulfil.js", 900),
        ("Contoso - leaver: create the IAM task", "sc_req_item", "after", True, False,
         f"current.cat_item.name == '{li['name']}'", "br_leaver_task.js", 100),
    ]
    for name, table, when, ins, upd, cond, src, order in rules:
        assert len(name) <= NAME_MAX, name
        p.put("sys_script", f"name={name}^collection={table}", {
            "name": name, "collection": table, "when": when, "action_insert": str(ins).lower(),
            "action_update": str(upd).lower(), "condition": cond, "script": server(src), "active": "true",
            "order": str(order), "advanced": "true",
        })

    # ---- event + script action + poller + UI action ---------------------------------------
    p.put("sysevent_register", "event_name=contoso.entra.fulfil", {
        "event_name": "contoso.entra.fulfil", "table": "sc_req_item",
        "description": "A manager approved an app access request: send it to Entra ID Governance.",
    })
    p.put("sysevent_script_action", "name=Contoso - send access request to Entra", {
        "name": "Contoso - send access request to Entra", "event_name": "contoso.entra.fulfil",
        "script": server("sa_fulfil.js"), "active": "true",
    })
    p.put("sysauto_script", "name=Contoso - check Entra access requests", {
        "name": "Contoso - check Entra access requests", "script": server("job_check_in_flight.js"),
        "run_type": "periodically", "run_period": "1970-01-01 00:01:00", "active": "true",
    })
    p.put("sys_ui_action", "name=Remove access in Entra^table=sc_task", {
        "name": "Remove access in Entra", "table": "sc_task", "action_name": "contoso_remove_in_entra",
        "form_button": "true", "active": "true", "order": "100",
        "condition": f"current.active && gs.hasRole('itil') && current.request_item.cat_item.name == '{li['name']}'",
        "script": server("ui_remove_in_entra.js"),
        "hint": "Ask Entra ID Governance to remove the requested access packages; the task number goes into the request.",
    })

    # ---- reporting: one list view, grouped by state --------------------------------------
    # A list view (sys_ui_view + sys_ui_list + elements) instead of sys_report
    # charts: the chart was refused to the IAM engineer by report_view field
    # ACLs (2026-11-07); the list follows the read ACLs the queue already uses.
    lv = cfg["accessRequestList"]
    view = p.put("sys_ui_view", f"name={lv['view']}", {"name": lv["view"], "title": lv["title"]})
    lst = p.put("sys_ui_list", f"name=sc_req_item^view={view['sys_id']}^elementISEMPTY^parentISEMPTY^sys_userISEMPTY", {
        "name": "sc_req_item", "view": view["sys_id"]})
    for i, col in enumerate(lv["columns"]):
        p.put("sys_ui_list_element", f"list_id={lst['sys_id']}^element={col}", {
            "list_id": lst["sys_id"], "element": col, "position": str(i)})
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true", help="read only: print what would change")
    ap.add_argument("--client-id", help="the fulfilment app's client id (default: look it up in Graph by display name; \"\" = not applied yet)")
    a = ap.parse_args()
    with open(os.path.join(HERE, "config.json")) as f:
        cfg = json.load(f)
    packages = resolve_packages(cfg)
    # --client-id "" is allowed on purpose: before the Terraform app exists the
    # property stays EMPTY and ServiceNow fails closed with "not configured".
    client_id = a.client_id if a.client_id is not None else resolve_client_id(cfg)
    plan = build(cfg, snlib.Client(), packages, client_id, dry=a.plan)
    print("\n".join(plan.log))
    if plan.missing:
        raise SystemExit("some queue members are not in ServiceNow yet (see MISSING above)")


if __name__ == "__main__":
    main()
