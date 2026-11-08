"""Offline tests for configure-sync.py hrapp --mail-domain (E121 follow-up).

Run: python3 -I -m unittest discover -s lab/scripts/dc/tests -v
No Graph call is made: the module's az() is replaced by a fake.
"""
import argparse
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("configure_sync", os.path.join(HERE, "..", "configure-sync.py"))
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)


def schema():
    return {
        "directories": [
            {"name": "API", "objects": [{"name": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                                         "attributes": [{"name": "department", "type": "String"}]}]},
            {"name": "AD", "objects": [{"name": "user", "attributes": [{"name": "department", "type": "String"}]}]},
        ],
        "synchronizationRules": [{"objectMappings": [{"attributeMappings": [
            {"targetAttributeName": "userPrincipalName", "source": {}},
            {"targetAttributeName": "mail", "flowType": "ObjectAddOnly",
             "source": {"expression": 'Join("@", x, DefaultDomain())'}},
        ]}]}],
    }


class FakeAz:
    def __init__(self):
        self.put = None
        self.sch = schema()

    def __call__(self, method, url, body=None, ok_missing=False):
        if url.endswith("/parseExpression"):
            return {"parsingSucceeded": True, "parsedExpression": {"expression": body["expression"]}}
        if method == "GET" and url.endswith("/schema"):
            return self.sch
        if method == "PUT" and url.endswith("/schema"):
            self.put = body
            return {}
        if method == "GET":
            return {"schedule": {"state": "Active"}}
        return {}


def args(mail_domain=None):
    return argparse.Namespace(sp="sp", job="job", domain="corp.example.com", default_ou="OU=W,DC=x",
                              parent_dn_file=None, mail_domain=mail_domain)


class MailDomain(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAz()
        self.real = cs.az
        cs.az = self.fake

    def tearDown(self):
        cs.az = self.real

    def mail_maps(self):
        maps = self.fake.put["synchronizationRules"][0]["objectMappings"][0]["attributeMappings"]
        return [m for m in maps if m["targetAttributeName"] == "mail"]

    def test_mail_domain_sets_always_mapping_with_verified_domain(self):
        cs.hrapp(args("contosohealthlab.com"))
        m = self.mail_maps()
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["flowType"], "Always")
        self.assertIn('"contosohealthlab.com")', m[0]["source"]["expression"])
        self.assertNotIn("DefaultDomain", m[0]["source"]["expression"])

    def test_without_mail_domain_the_template_mapping_is_left_alone(self):
        cs.hrapp(args(None))
        m = self.mail_maps()
        self.assertEqual(m[0]["flowType"], "ObjectAddOnly")

    def test_bad_domain_is_refused_before_any_write(self):
        for bad in ['x"), "evil', "no-dot", "", "a..b.com"]:
            with self.assertRaises(SystemExit):
                cs.mail_mapping_source(bad)


if __name__ == "__main__":
    unittest.main()
