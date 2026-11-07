"""Tests for compare_claims.py (stdlib unittest, no network)."""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import compare_claims as cc  # noqa: E402

CONTRACT = cc.load(os.path.join(os.path.dirname(cc.__file__), "claims-contract.json"))
UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
ROLE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
TENANT = "http://schemas.microsoft.com/identity/claims/tenantid"


def adfs():
    return {
        "source": "adfs", "signatureValid": True,
        "issuer": "http://sts.corp.contosohealthlab.com/adfs/services/trust",
        "nameId": {"value": "adfs-pilot@contosohealthlab.com",
                   "format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"},
        "attributes": {
            UPN: ["adfs-pilot@contosohealthlab.com"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["adfs-pilot@contosohealthlab.com"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Pilot"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["AdfsTest"],
            "urn:contoso:claims:department": ["Nursing"],
            "urn:contoso:claims:employeeid": ["ADFS-PILOT-1"],
            ROLE: ["ClaimsViewer.Clinician"],
            "urn:contoso:claims:shortname": ["adfs-pilot"],
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant": ["2026-11-07T00:00:00Z"],
        },
    }


def entra():
    d = adfs()
    d["source"] = "entra"
    d["issuer"] = "https://sts.windows.net/86a2e327-4951-4348-a3c4-6f4b79ffd8f2/"
    d["attributes"].pop("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant")
    d["attributes"][TENANT] = ["86a2e327-4951-4348-a3c4-6f4b79ffd8f2"]
    d["attributes"][UPN] = ["ADFS-Pilot@ContosoHealthLab.com"]   # case differs: casefold claim
    return d


class CompareTests(unittest.TestCase):
    def test_same_claims_pass_and_platform_claims_are_not_compared(self):
        rows, problems = cc.compare(adfs(), entra(), CONTRACT)
        self.assertEqual(problems, [])
        self.assertIn((TENANT, None, ["86a2e327-4951-4348-a3c4-6f4b79ffd8f2"], "platform (not compared)"), rows)

    def test_missing_role_fails(self):
        after = entra()
        del after["attributes"][ROLE]
        _, problems = cc.compare(adfs(), after, CONTRACT)
        self.assertTrue(any(ROLE in p and "MISSING after" in p for p in problems))

    def test_different_value_fails_for_exact_claim(self):
        after = entra()
        after["attributes"]["urn:contoso:claims:department"] = ["nursing"]
        _, problems = cc.compare(adfs(), after, CONTRACT)
        self.assertTrue(any("department" in p for p in problems))

    def test_extra_claim_fails(self):
        after = entra()
        after["attributes"]["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"] = ["x"]
        _, problems = cc.compare(adfs(), after, CONTRACT)
        self.assertTrue(any("extra claim" in p for p in problems))

    def test_bad_signature_fails(self):
        after = entra()
        after["signatureValid"] = False
        _, problems = cc.compare(adfs(), after, CONTRACT)
        self.assertIn("after: signature not valid", problems)

    def test_nameid_format_must_match_contract(self):
        after = entra()
        after["nameId"]["format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        _, problems = cc.compare(adfs(), after, CONTRACT)
        self.assertTrue(any("Name ID format" in p for p in problems))

    def test_two_adfs_captures_are_not_a_move(self):
        # Both files taken before cutover.sh entra: identical claims, no move.
        _, problems = cc.compare(adfs(), adfs(), CONTRACT)
        self.assertTrue(any("after: source is 'adfs'" in p for p in problems))

    def test_two_entra_captures_are_not_a_move(self):
        _, problems = cc.compare(entra(), entra(), CONTRACT)
        self.assertTrue(any("before: source is 'entra'" in p for p in problems))

    def test_source_label_must_match_issuer(self):
        after = entra()
        after["issuer"] = "http://sts.corp.contosohealthlab.com/adfs/services/trust"
        _, problems = cc.compare(adfs(), after, CONTRACT)
        self.assertTrue(any("does not match source" in p for p in problems))

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as t:
            b, a, bad = (os.path.join(t, n) for n in ("b.json", "a.json", "bad.json"))
            json.dump(adfs(), open(b, "w"))
            json.dump(entra(), open(a, "w"))
            json.dump({"signatureValid": True}, open(bad, "w"))
            self.assertEqual(cc.main([b, a]), 0)
            changed = entra()
            changed["attributes"][ROLE] = ["ClaimsViewer.Admin"]
            json.dump(changed, open(a, "w"))
            self.assertEqual(cc.main([b, a]), 1)
            self.assertEqual(cc.main([b, bad]), 2)
            self.assertEqual(cc.main([b, b]), 1)   # AD FS vs AD FS: not a move


if __name__ == "__main__":
    unittest.main()
