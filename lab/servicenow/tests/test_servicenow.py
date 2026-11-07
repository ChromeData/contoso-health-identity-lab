"""Offline tests for lab/servicenow (no instance, no tenant, no Keychain).

  python3 -I -m unittest discover -s lab/servicenow/tests -v
"""
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


apply = load("apply_mod", os.path.join(ROOT, "apply.py"))
mapping = load("mapping_mod", os.path.join(ROOT, "provisioning-mapping.py"))
cleanup = load("cleanup_mod", os.path.join(ROOT, "demo", "cleanup.py"))
prove = load("prove_mod", os.path.join(ROOT, "demo", "prove.py"))
CFG = json.load(open(os.path.join(ROOT, "config.json")))


class FakeSn:
    """Table API stand-in: rows per table, records every write."""

    def __init__(self, rows=None):
        self.rows = rows or {}
        self.writes = []

    def query(self, table, q, fields=None, limit=100):
        return [dict(r) for r in self.rows.get(table, []) if r.get("_q") in (None, q)]

    def one(self, table, q, fields=None):
        r = self.query(table, q)
        if len(r) > 1:
            raise RuntimeError("ambiguous")
        return r[0] if r else None

    def upsert(self, table, q, values):
        self.writes.append((table, q, values))
        return dict(values, sys_id=f"id-{len(self.writes)}"), "created"

    def delete(self, table, sys_id):
        self.writes.append(("DELETE", table, sys_id))


def policy(pid, exp):
    return {"id": pid, "expiration": {"type": exp}}


class ResolvePackages(unittest.TestCase):
    def test_one_package_one_request_policy(self):
        def get(url):
            name = url.split("eq '")[1].split("'")[0]
            return {"value": [{"id": "pkg-" + name, "assignmentPolicies": [
                policy("auto", "noExpiration"), policy("req-" + name, "afterDuration")]}]}
        out = apply.resolve_packages(CFG, get=get)
        self.assertEqual(out["icu_float"], {"accessPackageId": "pkg-ICU - Float Access",
                                            "assignmentPolicyId": "req-ICU - Float Access", "label": "ICU - Float Access"})
        self.assertNotIn("other", out, "the manual choice maps to no package: it goes to the IAM queue")

    def test_refuses_zero_or_two_packages(self):
        for n in (0, 2):
            with self.assertRaises(SystemExit):
                apply.resolve_packages(CFG, get=lambda url, n=n: {"value": [{"id": "x", "assignmentPolicies": []}] * n})

    def test_refuses_birthright_only_package(self):
        get = lambda url: {"value": [{"id": "p", "assignmentPolicies": [policy("auto", "noExpiration")]}]}
        with self.assertRaises(SystemExit):
            apply.resolve_packages(CFG, get=get)


class Build(unittest.TestCase):
    def sn(self):
        return FakeSn({"sc_catalog": [{"sys_id": "cat"}], "sys_user_role": [{"sys_id": "itil"}],
                       "sys_user": [{"sys_id": "u1"}]})

    def test_writes_every_rule_with_short_names_and_no_plan(self):
        sn = self.sn()
        apply.build(CFG, sn, {"icu_float": {}}, "client")
        tables = [w[0] for w in sn.writes]
        for t in ("sys_script_include", "sc_cat_item", "sys_script", "sysauto_script", "sys_ui_action", "sys_ui_list_element", "sys_properties"):
            self.assertIn(t, tables)
        for table, q, v in sn.writes:
            if table in ("sys_script", "sysevent_script_action", "sysauto_script"):
                self.assertLessEqual(len(v["name"]), apply.NAME_MAX, v["name"])
            if table == "sc_cat_item":
                self.assertEqual(v["delivery_plan"], "", "a delivery plan would auto-approve the item before the manager sees it")
                self.assertEqual(v["workflow"], "")

    def test_client_id_and_packages_reach_properties(self):
        sn = self.sn()
        apply.build(CFG, sn, {"icu_float": {"accessPackageId": "p"}}, "the-client")
        props = {v["name"]: v["value"] for t, q, v in sn.writes if t == "sys_properties"}
        self.assertEqual(props["contoso.entra.fulfilment.client_id"], "the-client")
        self.assertEqual(json.loads(props["contoso.entra.fulfilment.packages"]), {"icu_float": {"accessPackageId": "p"}})

    def test_missing_queue_member_is_reported_not_skipped(self):
        sn = FakeSn({"sc_catalog": [{"sys_id": "cat"}], "sys_user_role": [{"sys_id": "itil"}]})
        p = apply.build(CFG, sn, {}, "c")
        self.assertTrue(p.missing)
        self.assertTrue(any(l.startswith("MISSING") for l in p.log))


class ProvisioningMapping(unittest.TestCase):
    def schema(self, with_new=False):
        maps = [{"targetAttributeName": "title", "source": {"expression": "[jobTitle]", "name": "jobTitle", "type": "Attribute", "parameters": []},
                 "matchingPriority": 0, "flowType": "Always"}]
        attrs = [{"name": "title", "type": "String", "anchor": False, "required": False}, {"name": "manager", "type": "Reference"}]
        if with_new:
            maps += [{"targetAttributeName": "manager"}, {"targetAttributeName": "u_entra_object_id"}]
            attrs += [{"name": "u_entra_object_id"}]
        return {"directories": [{"name": "Microsoft Entra ID", "objects": []}, {"name": "ServiceNow", "objects": [{"name": "sys_user", "attributes": attrs}]}],
                "synchronizationRules": [{"objectMappings": [{"targetObjectName": "sys_user", "attributeMappings": maps}]}]}

    def test_adds_both_mappings_once(self):
        new, changed = mapping.change(self.schema())
        self.assertEqual(len(changed), 3)
        m = {x["targetAttributeName"]: x["source"]["expression"] for x in new["synchronizationRules"][0]["objectMappings"][0]["attributeMappings"]}
        self.assertEqual(m["manager"], "[manager]")
        self.assertEqual(m["u_entra_object_id"], "[objectId]")
        self.assertEqual(mapping.change(new)[1], [], "a second run changes nothing")

    def test_no_change_when_present(self):
        self.assertEqual(mapping.change(self.schema(with_new=True))[1], [])

    def test_stops_if_connector_lost_manager(self):
        s = self.schema()
        s["directories"][1]["objects"][0]["attributes"] = [{"name": "title"}]
        with self.assertRaises(SystemExit):
            mapping.change(s)


class Cleanup(unittest.TestCase):
    def test_refuses_req_numbers(self):
        with self.assertRaises(SystemExit):
            cleanup.clean(FakeSn(), ["REQ0010001"])

    def test_ritm_only_through_lab_items(self):
        sn = FakeSn({"sc_req_item": [{"sys_id": "r1", "number": "RITM0010009", "request": "q1",
                                      "_q": "number=RITM0010009^cat_item.nameINRequest app access,Report a leaver: remove app access"}],
                     "sc_request": [{"sys_id": "q1", "number": "REQ0010009", "_q": "sys_id=q1"}]})
        sn.query_orig = sn.query
        out = cleanup.clean(sn, ["RITM0010009"])
        self.assertIn("deleted sc_req_item RITM0010009", out)

    def test_demo_ritm_is_not_found(self):
        sn = FakeSn({"sc_req_item": [{"sys_id": "demo", "number": "RITM0010001", "_q": "number=RITM0010001"}]})
        self.assertEqual(cleanup.clean(sn, ["RITM0010001"]), ["not found RITM0010001"])


class UndoRequests(unittest.TestCase):
    """prove.py removes only what THIS run's requests granted (by request id)."""

    def run_undo(self, requests, assignments, settle_after=0):
        posts, polls = [], {"n": settle_after}
        prove.time.sleep = lambda s: None

        def graph(method, url, body=None):
            if method == "post":
                posts.append(body)
                return {"id": "rm"}
            if "/assignmentRequests/" in url:
                rid = url.split("/assignmentRequests/")[1].split("?")[0]
                r = dict(requests[rid])
                if polls["n"] > 0:
                    polls["n"] -= 1
                    r["state"] = "submitted"
                return r
            aid = url.rsplit("/", 1)[1]
            return {"state": assignments[aid]}
        prove.graph = graph
        out = []
        prove.undo_requests(list(requests), "STAMP", out)
        return posts, out

    def test_removes_the_assignment_of_each_own_request(self):
        posts, out = self.run_undo(
            {"r1": {"requestType": "adminAdd", "state": "delivered", "assignment": {"id": "a1"}},
             "r2": {"requestType": "adminAdd", "state": "deliveryFailed", "assignment": None}},
            {"a1": "delivered"})
        self.assertEqual([p["assignment"]["id"] for p in posts], ["a1"])
        self.assertIn("undo Entra request r1", posts[0]["justification"])

    def test_waits_for_an_add_still_in_flight(self):
        posts, out = self.run_undo({"r1": {"requestType": "adminAdd", "state": "delivered", "assignment": {"id": "a1"}}},
                                   {"a1": "delivered"}, settle_after=2)
        self.assertEqual(len(posts), 1)

    def test_assignment_already_gone_is_left_alone(self):
        posts, out = self.run_undo({"r1": {"requestType": "adminAdd", "state": "delivered", "assignment": {"id": "a1"}}}, {"a1": "expired"})
        self.assertEqual(posts, [])

    def test_refs_come_from_this_runs_tickets_and_setup_only(self):
        sn = FakeSn({"sc_req_item": [{"correlation_id": "pkg/r9", "_q": "number=RITM0010099^cat_item.name=Request app access"}]})
        ev = {"steps": {"uc1": {"ritm": "RITM0010099"}, "leaver": {"setup_request": "r5", "ritm": "RITM0010100"}}}
        self.assertEqual(prove.request_refs_of(sn, ev), ["r9", "r5"])


if __name__ == "__main__":
    unittest.main()
