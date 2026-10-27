#!/usr/bin/env python3
"""
configure-sync.py - the two Graph-only configurations that sit between DC01
and Entra, scripted (they are portal clicks in the docs). Idempotent: every
run reads the current state and only adds what is missing.

  cloudsync   AD -> Entra (Cloud Sync, "AD2AAD"):
              tenant flag onPremisesSyncEnabled; the AD2AAD app from Microsoft's
              template (one per domain); jobs AD2AADProvisioning +
              AD2AADPasswordHash; Domain + AppKey secrets; SCOPED to the OUs
              given (containerFilter: Tier-0 and service accounts must never
              sync); password-hash CredentialData mappings; hire date
              msDS-cloudExtensionAttribute1 -> EmployeeHireDate; start.

  hrapp       HR -> AD (API-driven inbound provisioning, "API2AD", created by
              lab/scripts/mock-hr/New-InboundProvisioningApp.ps1):
              connectivityParameters (agent compatibility key = the AD domain,
              default OU for new users); parentDistinguishedName expression
              (printed by 02-Configure-Domain.ps1); userPrincipalName straight
              from the HR userName (the verified suffix, not the AD domain);
              the custom SCIM hireDate formatted into msDS-cloudExtensionAttribute1;
              start.

Usage (repo root, after az login as an admin):
  lab/scripts/dc/configure-sync.py cloudsync --domain corp.example.com \\
      --ou "OU=Workforce,DC=corp,DC=example,DC=com" --ou "OU=Disabled,DC=corp,DC=example,DC=com"
  lab/scripts/dc/configure-sync.py hrapp --domain corp.example.com --sp <spId> --job <jobId> \\
      --default-ou "OU=Workforce,DC=corp,DC=example,DC=com" --parent-dn-file parentDN.txt

Facts this encodes (checked against the live tenant, 2026-10-27):
  * the API2AD job has no schema/parseExpression; the TEMPLATE endpoint
    (synchronization/templates/API2AD/schema/parseExpression) parses for it;
  * the portal's Connectivity "Save & activate" is one call:
    PATCH .../synchronization/connectivityParameters with
    syncAgentCompatibilityKey = <AD domain>, syncAgentADContainer = <default OU>;
  * Cloud Sync's user cycle is PT20M; a provisioning push to a just-promoted
    DC can fail with LDAP "Busy" (51): re-send the HR feed (it upserts).
"""
import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile
import time

GB = "https://graph.microsoft.com/beta"
AD2AAD_TEMPLATE = "1a4721b3-e57f-4451-ae87-ef078703ec94"
HIRE = "urn:ietf:params:scim:schemas:extension:contoso:1.0:User:hireDate"
EXT = "msDS-cloudExtensionAttribute1"


def az(method, url, body=None, ok_missing=False):
    cmd = ["az", "rest", "--method", method, "--url", url, "-o", "json"]
    tmp = None
    if body is not None:
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
        json.dump(body, tmp)
        tmp.close()
        cmd += ["--headers", "Content-Type=application/json", "--body", "@" + tmp.name]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if tmp:
        os.unlink(tmp.name)
    if r.returncode != 0:
        if ok_missing:
            return None
        raise SystemExit(f"{method} {url.replace(GB, '')[:100]} failed: {r.stderr.strip()[-600:]}")
    return json.loads(r.stdout) if r.stdout.strip() else {}


def add_attr(obj, name, like):
    """Declare a String attribute on a schema object, shaped like `like`."""
    if any(a["name"].lower() == name.lower() for a in obj["attributes"]):
        return False
    tmpl = next(a for a in obj["attributes"] if a["name"].lower() == like.lower() or a["name"].lower().endswith(":" + like.lower()))
    a = copy.deepcopy(tmpl)
    a.update(name=name, anchor=False, required=False, multivalued=False)
    for k in ("apiExpressions", "metadata", "referencedObjects"):
        if k in a:
            a[k] = []
    obj["attributes"].append(a)
    return True


def mapping(target, source):
    return {"defaultValue": None, "exportMissingReferences": False, "flowBehavior": "FlowWhenChanged",
            "flowType": "Always", "matchingPriority": 0, "targetAttributeName": target, "source": source}


def set_mapping(attr_mappings, target, source):
    attr_mappings[:] = [m for m in attr_mappings if m["targetAttributeName"] != target]
    attr_mappings.append(mapping(target, source))


def cloudsync(a):
    org = az("GET", f"{GB}/organization?$select=id,onPremisesSyncEnabled")["value"][0]
    if not org.get("onPremisesSyncEnabled"):
        az("PATCH", f"{GB}/organization/{org['id']}", {"onPremisesSyncEnabled": True})
        print("tenant: directory synchronization enabled")
    sps = az("GET", f"{GB}/servicePrincipals?$filter=displayName eq '{a.domain}'&$select=id")["value"]
    if len(sps) > 1:
        raise SystemExit(f"more than one service principal named {a.domain}: resolve by hand")
    if not sps:
        az("POST", f"{GB}/applicationTemplates/{AD2AAD_TEMPLATE}/instantiate", {"displayName": a.domain})
        for _ in range(18):
            time.sleep(10)
            sps = az("GET", f"{GB}/servicePrincipals?$filter=displayName eq '{a.domain}'&$select=id")["value"]
            if sps:
                break
        print("created the AD2AAD sync app")
    sp = sps[0]["id"]
    base = f"{GB}/servicePrincipals/{sp}/synchronization"
    for _ in range(12):
        if az("GET", base + "/templates", ok_missing=True) is not None:
            break
        time.sleep(10)
    jobs = {j["templateId"]: j["id"] for j in az("GET", base + "/jobs").get("value", [])}
    for t in ("AD2AADProvisioning", "AD2AADPasswordHash"):
        if t not in jobs:
            jobs[t] = az("POST", base + "/jobs", {"templateId": t})["id"]
            print("created job", t)
    az("PUT", base + "/secrets", {"value": [
        {"key": "Domain", "value": json.dumps({"domain": a.domain})},
        {"key": "AppKey", "value": json.dumps({"appKeyScenario": "AD2AADPasswordHash"})}]})
    sch_url = base + f"/jobs/{jobs['AD2AADProvisioning']}/schema"
    sch = az("GET", sch_url)
    rule = sch["synchronizationRules"][0]
    rule["containerFilter"] = {"includedContainers": a.ou}
    addir = next(d for d in sch["directories"] if d["name"] == "Active Directory")
    for o in addir["objects"]:
        if o["name"] in ("user", "inetOrgPerson"):
            add_attr(o, EXT, "department")
    cred = {"expression": "[PasswordHash]", "name": "PasswordHash", "type": "Attribute", "parameters": []}
    hire = {"expression": f"[{EXT}]", "name": EXT, "type": "Attribute", "parameters": []}
    for om in rule["objectMappings"]:
        if om.get("name") in ("Provision Active Directory users", "Provision Active Directory inetOrgPersons"):
            set_mapping(om["attributeMappings"], "CredentialData", cred)
            set_mapping(om["attributeMappings"], "EmployeeHireDate", hire)
    az("PUT", sch_url, sch)
    back = az("GET", sch_url)["synchronizationRules"][0].get("containerFilter")
    print("scope (containerFilter):", back)
    for t, j in jobs.items():
        st = az("GET", base + f"/jobs/{j}")
        if st["schedule"]["state"] != "Active":
            az("POST", base + f"/jobs/{j}/start")
        print(f"job {t}: started (interval {st['schedule'].get('interval')})")


def hrapp(a):
    base = f"{GB}/servicePrincipals/{a.sp}/synchronization"
    az("PATCH", base + "/connectivityParameters", {"value": [
        {"key": "syncAgentCompatibilityKey", "value": a.domain},
        {"key": "syncAgentADContainer", "value": a.default_ou}]})
    print("connectivity: domain + default OU set")

    def parse(expr):
        p = az("POST", base + "/templates/API2AD/schema/parseExpression",
               {"expression": expr, "targetAttributeDefinition": None, "testInputObject": None})
        if not p.get("parsingSucceeded"):
            raise SystemExit(f"expression did not parse: {expr[:80]}")
        return p["parsedExpression"]

    sch_url = base + f"/jobs/{a.job}/schema"
    sch = az("GET", sch_url)
    api = next(d for d in sch["directories"] if d["name"] == "API")
    ad = next(d for d in sch["directories"] if d["name"] != "API")
    add_attr(next(o for o in api["objects"] if o["name"].endswith("enterprise:2.0:User")), HIRE, "department")
    add_attr(ad["objects"][0], EXT, "department")
    maps = sch["synchronizationRules"][0]["objectMappings"][0]["attributeMappings"]
    if a.parent_dn_file:
        set_mapping(maps, "parentDistinguishedName", parse(open(a.parent_dn_file, encoding="utf-8").read().strip()))
    for m in maps:
        if m["targetAttributeName"] == "userPrincipalName":
            m["source"] = {"expression": "[userName]", "name": "userName", "type": "Attribute", "parameters": []}
    set_mapping(maps, EXT, parse(f'FormatDateTime([{HIRE}], , "yyyy-MM-ddTHH:mm:ssZ", "yyyyMMddHHmmss.fZ")'))
    az("PUT", sch_url, sch)
    print("mappings: parentDistinguishedName, userPrincipalName <- userName, hireDate -> " + EXT)
    st = az("GET", base + f"/jobs/{a.job}")
    if st["schedule"]["state"] != "Active":
        az("POST", base + f"/jobs/{a.job}/start")
    print("HR job: started")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cloudsync")
    c.add_argument("--domain", required=True)
    c.add_argument("--ou", action="append", required=True, help="an OU to sync (repeat); never Tier-0 or service OUs")
    h = sub.add_parser("hrapp")
    h.add_argument("--domain", required=True)
    h.add_argument("--sp", required=True)
    h.add_argument("--job", required=True)
    h.add_argument("--default-ou", required=True)
    h.add_argument("--parent-dn-file", help="file holding the parentDistinguishedName expression from 02-Configure-Domain.ps1")
    a = ap.parse_args()
    (cloudsync if a.cmd == "cloudsync" else hrapp)(a)


if __name__ == "__main__":
    sys.exit(main())
