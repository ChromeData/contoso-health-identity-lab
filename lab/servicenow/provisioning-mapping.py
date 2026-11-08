#!/usr/bin/python3 -I
"""Add two attribute mappings to the Entra -> ServiceNow provisioning job.

  manager   <- [manager]   so ServiceNow routes approvals to the real manager
                           (Entra, fed by HR, is the only org chart)
  u_entra_object_id <- [objectId]
                           so ServiceNow can name the person to Graph by the
                           immutable id. The fulfilment app has no directory
                           read permission, so it cannot look a UPN up.

WHY A SCRIPT, NOT TERRAFORM: azuread 3.10 has no resource for a
synchronization schema (modules/apps/servicenow_provisioning.tf header). The
schema is a TENANT-TIME step, like the other post-apply scripts: read it,
change only these two mappings, PUT it back, read it back.

VERIFIED LIVE before writing this (2026-11-07, GET .../schema as the
operator): the ServiceNow directory's sys_user object lists `manager` as a
Reference to sys_user (the connector resolves it to the manager's ServiceNow
record), and the default mapping does not use it. `u_entra_object_id` is a
custom column created by lab/servicenow/apply.py, so it is ADDED to the target
object's attribute list here (Learn: "Customize user provisioning attribute
mappings", editing the supported attribute list). The manager reference only
resolves when the manager is in scope too (assigned through
App-ServiceNow-Users), else it stays empty and the request goes to IAM.

Usage: /usr/bin/python3 -I lab/servicenow/provisioning-mapping.py [--plan]
Needs: the lab operator (Synchronization.ReadWrite.All).
"""
import argparse
import copy
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OP = os.path.join(REPO, "lab", "scripts", "operator", "op")
G = "https://graph.microsoft.com/v1.0"
SP_NAME = "ServiceNow - Provisioning"
NEW = [("manager", "manager"), ("objectId", "u_entra_object_id")]


def op(method, url, body=None, runner=subprocess.run):
    args = [OP, "az", "rest", "--method", method, "--url", url, "-o", "json"]
    if body is not None:
        args += ["--headers", "Content-Type=application/json", "--body", "@/dev/stdin"]
    r = runner(args, input=json.dumps(body) if body is not None else None, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"Graph {method} {url} failed: {r.stderr.strip()[:400]}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def change(schema):
    """Return (new_schema, list of what changed). Pure: tested without a tenant."""
    s = copy.deepcopy(schema)
    changed = []
    sn_dir = next(d for d in s["directories"] if d["name"] == "ServiceNow")
    user_obj = next(o for o in sn_dir["objects"] if o["name"] == "sys_user")
    names = {a["name"] for a in user_obj["attributes"]}
    if "manager" not in names:
        raise SystemExit("ServiceNow sys_user has no 'manager' attribute: the connector changed; stop and re-read Learn")
    if "u_entra_object_id" not in names:
        template = next(a for a in user_obj["attributes"] if a["name"] == "title")
        attr = copy.deepcopy(template)
        attr.update({"name": "u_entra_object_id", "required": False, "anchor": False, "referencedObjects": []})
        user_obj["attributes"].append(attr)
        changed.append("target attribute u_entra_object_id added")

    rule = next(r for r in s["synchronizationRules"] if any(m["targetObjectName"] == "sys_user" for m in r["objectMappings"]))
    om = next(m for m in rule["objectMappings"] if m["targetObjectName"] == "sys_user")
    targets = {m["targetAttributeName"] for m in om["attributeMappings"]}
    template = next(m for m in om["attributeMappings"] if m["targetAttributeName"] == "title")
    for src, tgt in NEW:
        if tgt in targets:
            continue
        m = copy.deepcopy(template)
        m["targetAttributeName"] = tgt
        m["source"] = {"expression": f"[{src}]", "name": src, "type": "Attribute", "parameters": []}
        m["matchingPriority"] = 0
        om["attributeMappings"].append(m)
        changed.append(f"mapping {tgt} <- [{src}]")
    return s, changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true")
    a = ap.parse_args()
    sps = op("get", f"{G}/servicePrincipals?$filter=displayName eq '{SP_NAME}'&$select=id")["value"]
    if len(sps) != 1:
        raise SystemExit(f"'{SP_NAME}': expected 1 service principal, found {len(sps)}")
    sp = sps[0]["id"]
    jobs = op("get", f"{G}/servicePrincipals/{sp}/synchronization/jobs")["value"]
    if len(jobs) != 1:
        raise SystemExit(f"expected 1 synchronization job, found {len(jobs)}")
    url = f"{G}/servicePrincipals/{sp}/synchronization/jobs/{jobs[0]['id']}/schema"
    new, changed = change(op("get", url))
    print("\n".join(changed) or "no change")
    if a.plan or not changed:
        return
    op("put", url, new)
    _, still = change(op("get", url))
    if still:
        raise SystemExit(f"read-back still missing: {still}")
    print("read back: both mappings present")


if __name__ == "__main__":
    main()
