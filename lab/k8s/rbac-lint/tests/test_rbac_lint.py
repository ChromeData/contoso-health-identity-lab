"""Offline tests for lab/k8s/rbac-lint/rbac_lint.py. No cluster, no network.

Run:  python3 -I -m unittest discover -s lab/k8s/rbac-lint/tests -v

Ported from the earlier Conjur-Kubernetes-KubiScan lab (pytest there, stdlib
unittest here like the lab's other Python tests), plus the tests for the
fixes made while porting. Each test marked NEW FAILS against the earlier
linter (checked 2026-11-06 by running this file against it):
  * a raw-API ClusterRoleList (items with no kind) was read as clean
  * a List with no items array, or a kind-less item in a generic List, was
    silently skipped
  * a missing file, a parse error and a crash exited 1, the "findings" code
  * reading zero Role/ClusterRole objects was reported as clean
  * verbs ["*"] on nodes was reported as escalate + bind + impersonate
"""

import io
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINT_DIR = Path(os.environ.get("RBAC_LINT_DIR", HERE.parent))
FIXTURES = HERE.parent / "fixtures"
sys.path.insert(0, str(LINT_DIR))

import rbac_lint  # noqa: E402


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    code = rbac_lint.run(list(args), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def write_tmp(text, suffix=".yaml"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


class TestSingleRule(unittest.TestCase):
    def test_escalate_flagged(self):
        r = {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["escalate"]}
        self.assertIn("escalate", rbac_lint.analyze_rule(r))

    def test_bind_flagged(self):
        r = {"resources": ["clusterroles"], "verbs": ["bind"]}
        self.assertIn("bind", rbac_lint.analyze_rule(r))

    def test_explicit_bind_flagged_on_any_resource(self):
        # The fixture's lab-bind puts bind on clusterrolebindings, where it does
        # nothing; an explicit escalation verb is still worth a look.
        r = {"resources": ["clusterrolebindings"], "verbs": ["bind"]}
        self.assertIn("bind", rbac_lint.analyze_rule(r))

    def test_secret_read_flagged(self):
        r = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}
        self.assertIn("secrets-read", rbac_lint.analyze_rule(r))

    def test_pod_create_flagged(self):
        self.assertIn("pods-create", rbac_lint.analyze_rule({"resources": ["pods"], "verbs": ["create"]}))

    def test_wildcard_flagged(self):
        r = {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}
        self.assertIn("wildcard-all", rbac_lint.analyze_rule(r))

    def test_token_create_flagged(self):
        r = {"resources": ["serviceaccounts/token"], "verbs": ["create"]}
        self.assertIn("token-create", rbac_lint.analyze_rule(r))

    def test_benign_rule_is_clean(self):
        r = {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}
        self.assertEqual(rbac_lint.analyze_rule(r), [])

    def test_listing_pods_is_not_creating_them(self):
        r = {"resources": ["pods"], "verbs": ["get", "list"]}
        self.assertNotIn("pods-create", rbac_lint.analyze_rule(r))

    def test_wildcard_verb_covers_specific_checks(self):
        self.assertIn("secrets-read", rbac_lint.analyze_rule({"resources": ["secrets"], "verbs": ["*"]}))

    def test_wildcard_verb_on_nodes_is_not_escalate_bind_impersonate(self):
        # NEW. k3s-cloud-controller-manager on a real k3s v1.31.4 cluster.
        r = {"apiGroups": [""], "resources": ["nodes"], "verbs": ["*"]}
        self.assertEqual(rbac_lint.analyze_rule(r), [])

    def test_wildcard_verb_on_clusterroles_is_escalate_and_bind(self):
        r = {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["*"]}
        self.assertTrue({"escalate", "bind"} <= set(rbac_lint.analyze_rule(r)))

    def test_wildcard_verb_on_identities_is_impersonate(self):
        for res in (["users"], ["serviceaccounts"], ["userextras/scopes"]):
            with self.subTest(res=res):
                self.assertIn("impersonate", rbac_lint.analyze_rule({"resources": res, "verbs": ["*"]}))

    def test_non_mapping_rule_is_an_error(self):
        with self.assertRaises(rbac_lint.LintError):
            rbac_lint.analyze_rule("verbs: ['*']")


class TestDocAndLists(unittest.TestCase):
    def test_non_rbac_doc_ignored(self):
        self.assertEqual(rbac_lint.analyze_doc({"kind": "ConfigMap"}), [])

    def test_kubectl_list_wrapper_is_traversed(self):
        doc = """
kind: List
apiVersion: v1
items:
  - kind: ClusterRole
    metadata: {name: sneaky}
    rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
"""
        self.assertTrue(any(f["risk"] == "wildcard-all" for f in rbac_lint.analyze_text(doc)))

    def test_typed_list_items_with_kind_are_traversed(self):
        doc = """
kind: ClusterRoleList
items:
  - kind: ClusterRole
    metadata: {name: sneaky}
    rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get"]}]
"""
        self.assertTrue(any(f["risk"] == "secrets-read" for f in rbac_lint.analyze_text(doc)))

    def test_typed_list_items_WITHOUT_kind_inherit_it(self):
        # NEW. The shape the Kubernetes API returns (kubectl get --raw ...):
        # the earlier linter read this as clean.
        doc = """
kind: ClusterRoleList
apiVersion: rbac.authorization.k8s.io/v1
items:
  - metadata: {name: sneaky}
    rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
"""
        findings = rbac_lint.analyze_text(doc)
        self.assertTrue(any(f["risk"] == "wildcard-all" and f["kind"] == "ClusterRole" for f in findings))

    def test_rolelist_items_without_kind_are_roles(self):
        doc = "kind: RoleList\nitems:\n  - metadata: {name: r}\n    rules: [{resources: [pods], verbs: [create]}]\n"
        self.assertEqual(rbac_lint.analyze_text(doc)[0]["kind"], "Role")

    def test_kindless_item_in_generic_list_is_an_error(self):
        # NEW. A generic List cannot say what a kind-less item is: refuse.
        doc = "kind: List\nitems:\n  - metadata: {name: x}\n    rules: [{resources: ['*'], verbs: ['*']}]\n"
        with self.assertRaises(rbac_lint.LintError):
            rbac_lint.analyze_text(doc)

    def test_list_without_items_array_is_an_error(self):
        # NEW. Must not read as an empty, clean list.
        for doc in ("kind: List\n", "kind: ClusterRoleList\nitems: null\n", "kind: List\nitems: {a: 1}\n"):
            with self.subTest(doc=doc):
                with self.assertRaises(rbac_lint.LintError):
                    rbac_lint.analyze_text(doc)

    def test_builtin_roles_are_classified_not_counted(self):
        doc = """
kind: ClusterRole
metadata:
  name: cluster-admin
  labels: {kubernetes.io/bootstrapping: rbac-defaults}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
"""
        findings = rbac_lint.analyze_text(doc)
        self.assertTrue(findings)
        self.assertTrue(all(f["builtin"] for f in findings))

    def test_custom_role_is_not_marked_builtin(self):
        doc = "kind: ClusterRole\nmetadata: {name: lab-wildcard}\nrules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n"
        self.assertTrue(all(not f["builtin"] for f in rbac_lint.analyze_text(doc)))


class TestFixtures(unittest.TestCase):
    def test_risky_fixture_trips_all_planted_risks(self):
        risks = {f["risk"] for f in rbac_lint.analyze_text((FIXTURES / "risky-rbac.yaml").read_text())}
        for expected in ("escalate", "bind", "impersonate", "secrets-read", "pods-create", "wildcard-all", "token-create"):
            self.assertIn(expected, risks)

    def test_clean_fixture_mirrors_lab_roles_and_is_clean(self):
        stats = {}
        findings = rbac_lint.analyze_text((FIXTURES / "clean-rbac.yaml").read_text(), stats)
        self.assertEqual(findings, [])
        self.assertEqual(stats["rbac_objects"], 2)


class TestExitCodes(unittest.TestCase):
    """NEW. 1 means findings and nothing else; every failure to run is 2."""

    def test_findings_exit_1(self):
        self.assertEqual(run_cli(str(FIXTURES / "risky-rbac.yaml"))[0], 1)

    def test_clean_exit_0(self):
        self.assertEqual(run_cli(str(FIXTURES / "clean-rbac.yaml"))[0], 0)

    def test_missing_file_exit_2(self):
        self.assertEqual(run_cli("/nonexistent/rbac.yaml")[0], 2)

    def test_parse_error_exit_2(self):
        self.assertEqual(run_cli(write_tmp("kind: [\n"))[0], 2)

    def test_no_rbac_objects_exit_2(self):
        code, _out, err = run_cli(write_tmp("kind: ConfigMap\nmetadata: {name: x}\n"))
        self.assertEqual(code, 2)
        self.assertIn("read no Role or ClusterRole", err)

    def test_no_args_and_unknown_flag_exit_2(self):
        self.assertEqual(run_cli()[0], 2)
        self.assertEqual(run_cli("--quiet", str(FIXTURES / "risky-rbac.yaml"))[0], 2)

    def test_main_turns_a_crash_into_exit_2(self):
        orig, orig_argv = rbac_lint.run, sys.argv
        rbac_lint.run = lambda *_a, **_k: 1 / 0
        sys.argv = ["rbac_lint.py", "x"]
        try:
            with self.assertRaises(SystemExit) as ctx:
                with unittest.mock.patch("sys.stderr", io.StringIO()):
                    rbac_lint.main()
            self.assertEqual(ctx.exception.code, 2)
        finally:
            rbac_lint.run, sys.argv = orig, orig_argv


if __name__ == "__main__":
    unittest.main()
