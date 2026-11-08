"""Offline tests for configure-sync.py's leave-date mappings (no tenant, no az).

The scheduled leaver workflow triggers on employeeLeaveDateTime, so both hops
must carry it: HR job -> AD msDS-cloudExtensionAttribute2, then Cloud Sync
msDS-cloudExtensionAttribute2 -> EmployeeLeaveDateTime.
"""
import copy
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("configure_sync", HERE.parent / "configure-sync.py")
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

DEPT = {"name": "department", "type": "String", "anchor": False, "apiExpressions": [], "metadata": [], "referencedObjects": []}


def hr_schema():
    return {"directories": [{"name": "API", "objects": [{"name": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", "attributes": [copy.deepcopy(DEPT)]}]},
                            {"name": "Active Directory", "objects": [{"name": "user", "attributes": [copy.deepcopy(DEPT)]}]}],
            "synchronizationRules": [{"objectMappings": [{"attributeMappings": [cs.mapping("department", {"expression": "[department]"})]}]}]}


def cloudsync_rule():
    return {"objectMappings": [{"name": "Provision Active Directory users", "attributeMappings": []},
                               {"name": "Provision Active Directory inetOrgPersons", "attributeMappings": []},
                               {"name": "Provision Active Directory groups", "attributeMappings": []}]}


class LeaveDate(unittest.TestCase):
    def test_hr_job_maps_leave_time_into_attribute2_from_active(self):
        sch, seen = hr_schema(), []
        cs.hr_leave(sch, lambda e: seen.append(e) or {"expression": e})
        ad = sch["directories"][1]["objects"][0]["attributes"]
        self.assertIn("msDS-cloudExtensionAttribute2", [a["name"] for a in ad])
        maps = {m["targetAttributeName"]: m for m in sch["synchronizationRules"][0]["objectMappings"][0]["attributeMappings"]}
        self.assertEqual(maps["msDS-cloudExtensionAttribute2"]["flowType"], "Always")
        self.assertEqual(seen, [cs.LEAVE_EXPR])
        self.assertTrue(cs.LEAVE_EXPR.startswith('IIF([active]="False", '))
        self.assertIn('"yyyyMMddHHmmss.fZ"', cs.LEAVE_EXPR)   # the AD string format Learn gives
        self.assertIn("department", maps)                       # other mappings kept

    def test_hr_job_is_idempotent(self):
        sch = hr_schema()
        for _ in range(2):
            cs.hr_leave(sch, lambda e: {"expression": e})
        maps = [m["targetAttributeName"] for m in sch["synchronizationRules"][0]["objectMappings"][0]["attributeMappings"]]
        self.assertEqual(maps.count("msDS-cloudExtensionAttribute2"), 1)
        ad = [a["name"] for a in sch["directories"][1]["objects"][0]["attributes"]]
        self.assertEqual(ad.count("msDS-cloudExtensionAttribute2"), 1)

    def test_cloud_sync_maps_attribute2_to_employee_leave_datetime_for_users_only(self):
        rule = cloudsync_rule()
        cs.cloudsync_leave(rule)
        cs.cloudsync_leave(rule)
        users, inet, groups = rule["objectMappings"]
        for om in (users, inet):
            m = [x for x in om["attributeMappings"] if x["targetAttributeName"] == "EmployeeLeaveDateTime"]
            self.assertEqual(len(m), 1)
            self.assertEqual(m[0]["source"]["expression"], "[msDS-cloudExtensionAttribute2]")
        self.assertEqual(groups["attributeMappings"], [])

    def test_cloud_sync_without_user_mapping_stops(self):
        with self.assertRaises(SystemExit):
            cs.cloudsync_leave({"objectMappings": [{"name": "Provision Active Directory groups", "attributeMappings": []}]})


if __name__ == "__main__":
    unittest.main()
