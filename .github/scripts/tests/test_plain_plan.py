"""Tests for .github/scripts/plain-plan.py.

    python3 -m unittest discover -s .github/scripts/tests -v

fixtures/*.json are `terraform show -json` plans shaped like this lab's
envs/dev (module addresses, azuread 3.x ids, sensitive marks). They carry
fake "secret" values on purpose: no test may ever find one in the output.
"""

import importlib.util
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "plain-plan.py")
FIXTURES = os.path.join(HERE, "fixtures")

_spec = importlib.util.spec_from_file_location("plain_plan", SCRIPT)
pp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pp)


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def rc(address, rtype, actions, before=None, after=None, **change):
    """A minimal resource_changes entry."""
    entry = {"address": address, "mode": "managed", "type": rtype, "name": address.rsplit(".", 1)[-1],
             "change": {"actions": actions, "before": before, "after": after}}
    entry["change"].update(change)
    return entry


# Values the fixtures mark sensitive or hold only in `variables` / prior state.
SECRETS = [
    "secops-oncall@contoso-health.example", "old-oncall@contoso-health.example",
    "203.0.113.24", "11111111-2222-4333-8444-555555555555",
    "MIIC8DCCAdigAwIBAgIQ", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
]


class FixtureOutput(unittest.TestCase):
    maxDiff = None

    def test_update_access_package_resources(self):
        self.assertEqual(pp.summarize(load("plan_update_access_package.json")), (
            "**What this change does:** adds 1 access package and changes 1 existing one.\n"
            "\n"
            "- Adds access package **IT - Cloud Engineering Apps** with app group App-AWS-IdentityCenter-Users\n"
            "- Changes access package **Nurse - Clinical Apps**: removes app group App-AWS-IdentityCenter-Users\n"
        ))

    def test_update_access_package_resources_applied(self):
        self.assertEqual(pp.summarize(load("plan_update_access_package.json"), past=True), (
            "**Applied:** added 1 access package and changed 1 existing one.\n"
            "\n"
            "- Added access package **IT - Cloud Engineering Apps** with app group App-AWS-IdentityCenter-Users\n"
            "- Changed access package **Nurse - Clinical Apps**: removed app group App-AWS-IdentityCenter-Users\n"
        ))

    def test_add(self):
        # New group, its catalog entry, a package granting it (ids unknown
        # until apply: names come from the config refs and instance keys).
        self.assertEqual(pp.summarize(load("plan_add.json")), (
            "**What this change does:** adds 3 things and changes 1 access catalog. Nothing is removed.\n"
            "\n"
            "- Adds access package **IT - Cloud Engineering Apps** with app groups "
            "App-AWS-IdentityCenter-Users and App-CloudEng-Console-Users\n"
            "- Adds group **App-CloudEng-Console-Users**\n"
            "- Adds alarm rule **Contoso - Cloud console sign-in from a new country** (Sentinel)\n"
            "- Changes access catalog **Clinical**: adds group App-CloudEng-Console-Users\n"
        ))

    def test_delete(self):
        self.assertEqual(pp.summarize(load("plan_delete.json")), (
            "**What this change does:** changes 2 things, replaces 1 SAML signing certificate and removes 3 things.\n"
            "\n"
            "- Changes sign-in rule **CA003 - Block legacy authentication** (Conditional Access): "
            "turns it on (it was report-only, which logs but does not block)\n"
            "- Changes alert contact list **ag-identity-secops** (action group): updates who it emails (value hidden)\n"
            "- Replaces SAML signing certificate **CN=Contoso Health - ServiceNow SAML signing**: "
            "removes it and creates a new one, because its end date changes\n"
            "- Removes app access for **App-ServiceNow-Users** to **Contoso Health - ServiceNow**\n"
            "- Removes sign-in rule **CA010 - Block device code flow for all users** (Conditional Access)\n"
            "- Removes permission **Key Vault Secrets User** for **id-idlab-kv-reader** on **kv-idlab** (Azure RBAC)\n"
        ))

    def test_delete_applied_is_past_tense(self):
        out = pp.summarize(load("plan_delete.json"), past=True)
        self.assertTrue(out.startswith("**Applied:** changed 2 things, replaced 1 SAML signing certificate "
                                       "and removed 3 things.\n"))
        self.assertIn("removed it and created a new one, because its end date changed", out)
        self.assertIn("- Removed sign-in rule **CA010", out)

    def test_noop(self):
        self.assertEqual(pp.summarize(load("plan_noop.json")),
                         "**What this change does:** no changes to the live lab. It already matches the code.\n")
        self.assertEqual(pp.summarize(load("plan_noop.json"), past=True),
                         "**Applied:** nothing needed to change. The live lab already matched the code.\n")

    def test_never_prints_secrets(self):
        for name in sorted(os.listdir(FIXTURES)):
            for past in (False, True):
                out = pp.summarize(load(name), past=past)
                for secret in SECRETS:
                    self.assertNotIn(secret, out, f"{name} leaked {secret!r}")


class EdgeCases(unittest.TestCase):
    def test_empty_and_odd_input_never_crashes(self):
        odd = {"resource_changes": [
            None, {}, {"address": "x.y"}, {"address": "a.b", "change": "nope"},
            {"address": "a.c", "change": {"actions": "create"}},
            rc("azuread_group.no_values", "azuread_group", ["update"]),
            rc("azuread_group.str_after", "azuread_group", ["create"], after="weird"),
        ], "prior_state": {"values": {"root_module": {"resources": [None, {"no": "address"}]}}},
            "planned_values": "not a dict", "configuration": []}
        out = pp.summarize(odd)
        self.assertIn("- Changes group `azuread_group.no_values`", out)
        self.assertIn("- Adds group `azuread_group.str_after`", out)
        self.assertEqual(pp.summarize({}), pp.summarize({"resource_changes": []}))

    def test_unknown_types_get_a_generic_noun(self):
        out = pp.summarize({"resource_changes": [
            rc("acme_gizmo.thing", "acme_gizmo", ["create"], after={"size": 3}),
            rc("azurerm_frobnicator.f", "azurerm_frobnicator", ["create"], after={"name": "frob-01"}),
        ]})
        self.assertIn("- Adds setting `acme_gizmo.thing`", out)
        self.assertIn("- Adds Azure setting **frob-01**", out)
        self.assertTrue(out.startswith("**What this change does:** adds 2 things."))

    def test_sensitive_name_is_not_printed(self):
        out = pp.summarize({"resource_changes": [
            rc("azuread_group.secret", "azuread_group", ["create"],
               after={"display_name": "Project-Nightingale-Leads"}, after_sensitive={"display_name": True}),
            rc("azuread_user.all_secret", "azuread_user", ["delete"],
               before={"display_name": "Jane Roe"}, before_sensitive=True),
        ]})
        self.assertNotIn("Nightingale", out)
        self.assertNotIn("Jane Roe", out)
        self.assertIn("`azuread_group.secret`", out)

    def test_hidden_setting_is_named_secret_field_is_not(self):
        # owners hidden because they came from a sensitive variable: say WHAT
        # changed (its owners), never the ids; a client secret stays "a secret".
        out = pp.summarize({"resource_changes": [
            rc("azuread_service_principal.aws", "azuread_service_principal", ["update"],
               before={"display_name": "AWS IAM Identity Center", "owners": ["owner-id-old"]},
               after={"display_name": "AWS IAM Identity Center", "owners": ["owner-id-old", "owner-id-apply"]},
               before_sensitive={"owners": True}, after_sensitive={"owners": True}),
            rc("azuread_application_password.p", "azuread_application_password", ["update"],
               before={"display_name": "ci", "value": "old-secret-xyz"}, after={"display_name": "ci", "value": "new-secret-xyz"},
               before_sensitive={"value": True}, after_sensitive={"value": True}),
        ]})
        self.assertIn("- Changes enterprise app **AWS IAM Identity Center**: updates its owners (value hidden)\n", out)
        self.assertIn("- Changes app password **ci**: updates a secret value (not shown)\n", out)
        for leaked in ("owner-id-old", "owner-id-apply", "old-secret-xyz", "new-secret-xyz"):
            self.assertNotIn(leaked, out)

    def test_rename_and_fields(self):
        out = pp.summarize({"resource_changes": [
            rc("azuread_group.g", "azuread_group", ["update"],
               before={"display_name": "Old-Name", "description": "a", "owners": ["1"], "id": "/groups/1"},
               after={"display_name": "New-Name", "description": "b", "owners": ["2"], "id": "/groups/1"}),
            rc("azurerm_sentinel_alert_rule_scheduled.r", "azurerm_sentinel_alert_rule_scheduled", ["update"],
               before={"display_name": "Rule", "enabled": True, "query": "a", "severity": "Low"},
               after={"display_name": "Rule", "enabled": False, "query": "b", "severity": "High"}),
        ]})
        self.assertIn("- Changes group **New-Name**: renames it from Old-Name; updates its description and its owners", out)
        self.assertIn("- Changes alarm rule **Rule** (Sentinel): turns it off; "
                      "updates its detection query and its severity", out)

    def test_unknown_new_name_falls_back_to_current_name(self):
        out = pp.summarize({"resource_changes": [
            rc("azuread_application.app", "azuread_application", ["update"],
               before={"display_name": "Clinical Portal"}, after={"display_name": None},
               after_unknown={"display_name": True}),
        ]})
        self.assertIn("- Changes app registration **Clinical Portal**", out)

    def test_markdown_and_mentions_are_escaped(self):
        out = pp.summarize({"resource_changes": [
            rc("azuread_group.x", "azuread_group", ["create"],
               after={"display_name": "<img src=x> **bold** @octocat [link](http://e)"}),
        ]})
        self.assertNotIn("<img", out)
        self.assertNotIn("@octocat", out)
        self.assertIn("&lt;img src=x&gt; \\*\\*bold\\*\\* &#64;octocat \\[link\\](http://e)", out)

    def test_removed_package_swallows_its_links(self):
        plan = load("plan_update_access_package.json")
        nurse = 'module.entitlement[0].azuread_access_package.this["nurse"]'
        for entry in plan["resource_changes"]:
            if entry["address"] == nurse or entry["address"].endswith('groups["nurse.servicenow"]'):
                entry["change"]["actions"] = ["delete"]
                entry["change"]["after"] = None
        out = pp.summarize(plan)
        self.assertIn("- Removes access package **Nurse - Clinical Apps**\n", out)
        self.assertNotIn("removes app group", out)
        self.assertTrue(out.startswith("**What this change does:** adds 1 access package and removes 1 existing one."))

    def test_import_forget_replace_reason_and_cap(self):
        changes = [
            rc("azuread_group.imported", "azuread_group", ["no-op"], before={"display_name": "Imported"},
               after={"display_name": "Imported"}, importing={"id": "/groups/9"}),
            rc("azuread_group.forgotten", "azuread_group", ["forget"], before={"display_name": "Kept"}),
            rc("azuread_group.tainted", "azuread_group", ["delete", "create"], before={"display_name": "T"},
               after={"display_name": "T"}),
        ]
        changes[2]["action_reason"] = "replace_because_tainted"
        out = pp.summarize({"resource_changes": changes})
        self.assertIn("- Replaces group **T**: removes it and creates a new one, because it was marked as damaged", out)
        self.assertIn("- Starts managing existing group **Imported**: no change to it", out)
        self.assertIn("- Stops managing group **Kept**: it stays in place", out)
        self.assertIn("starts managing 1 existing group and stops managing 1", out)

        many = {"resource_changes": [rc(f"azuread_group.g{i}", "azuread_group", ["create"],
                                        after={"display_name": f"G{i}"}) for i in range(30)]}
        out = pp.summarize(many, max_items=5)
        self.assertEqual(out.count("\n- "), 6)
        self.assertIn("- ...and 25 more (listed in the technical plan)", out)
        self.assertTrue(out.startswith("**What this change does:** adds 30 groups. Nothing is removed."))


class CommandLine(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, SCRIPT, *args], input=stdin, capture_output=True, text=True)

    def test_file_and_stdin(self):
        path = os.path.join(FIXTURES, "plan_update_access_package.json")
        res = self.run_cli(path)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(res.stdout.startswith("**What this change does:** adds 1 access package"))
        with open(path, encoding="utf-8") as fh:
            res = self.run_cli("--applied", "-", stdin=fh.read())
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(res.stdout.startswith("**Applied:** added 1 access package"))

    def test_bad_input_exits_1_with_nothing_on_stdout(self):
        for stdin in ("not json", "[1, 2]"):
            res = self.run_cli("-", stdin=stdin)
            self.assertEqual(res.returncode, 1)
            self.assertEqual(res.stdout, "")
            self.assertIn("cannot read a Terraform JSON plan", res.stderr)
        res = self.run_cli(os.path.join(FIXTURES, "does-not-exist.json"))
        self.assertEqual(res.returncode, 1)


if __name__ == "__main__":
    unittest.main()
