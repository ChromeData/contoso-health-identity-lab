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
import re
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINT_DIR = Path(os.environ.get("RBAC_LINT_DIR", HERE.parent))
FIXTURES = HERE.parent / "fixtures"
REPO = HERE.parents[3]
TF_IDENTITY = REPO / "lab" / "terraform" / "k8s" / "identity" / "main.tf"
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

    def test_label_alone_does_not_make_a_role_builtin(self):
        # Review (PR #209): anyone can add the label to a wildcard role.
        doc = """
kind: ClusterRole
metadata:
  name: totally-harmless
  labels: {kubernetes.io/bootstrapping: rbac-defaults}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
"""
        findings = rbac_lint.analyze_text(doc)
        self.assertTrue(findings)
        self.assertTrue(all(not f["builtin"] and f["claims_builtin"] for f in findings))
        code, out, _ = run_cli(write_tmp(doc))
        self.assertEqual(code, 1)
        self.assertIn("labelled rbac-defaults, but not a Kubernetes default name", out)

    def test_system_prefixed_default_is_builtin(self):
        doc = ("kind: ClusterRole\nmetadata:\n  name: system:controller:x\n"
               "  labels: {kubernetes.io/bootstrapping: rbac-defaults}\n"
               "rules: [{resources: ['*'], verbs: ['*']}]\n")
        self.assertTrue(all(f["builtin"] for f in rbac_lint.analyze_text(doc)))

    def test_malformed_rules_are_an_error_not_clean(self):
        # Review (PR #209): `or []` turned rules: false / 0 / "" into "no rules".
        for bad in ("false", "0", '""', "{a: 1}"):
            with self.subTest(rules=bad):
                with self.assertRaises(rbac_lint.LintError):
                    rbac_lint.analyze_text(f"kind: ClusterRole\nmetadata: {{name: x}}\nrules: {bad}\n")
                self.assertEqual(run_cli(write_tmp(f"kind: ClusterRole\nmetadata: {{name: x}}\nrules: {bad}\n"))[0], 2)

    def test_absent_or_null_rules_are_a_role_with_no_rules(self):
        for doc in ("kind: ClusterRole\nmetadata: {name: x}\n", "kind: ClusterRole\nmetadata: {name: x}\nrules: null\n"):
            with self.subTest(doc=doc):
                self.assertEqual(rbac_lint.analyze_text(doc), [])

    def test_namespace_is_kept_and_printed_for_roles(self):
        # Review (PR #209): same-named Roles in two namespaces must be told apart.
        doc = ("kind: List\nitems:\n"
               "  - {kind: Role, metadata: {name: r, namespace: a}, rules: [{resources: [pods], verbs: [create]}]}\n"
               "  - {kind: Role, metadata: {name: r, namespace: b}, rules: [{resources: [pods], verbs: [create]}]}\n")
        self.assertEqual({f["namespace"] for f in rbac_lint.analyze_text(doc)}, {"a", "b"})
        _code, out, _ = run_cli(write_tmp(doc))
        self.assertIn("Role/a/r:", out)
        self.assertIn("Role/b/r:", out)

    def test_custom_role_is_not_marked_builtin(self):
        doc = "kind: ClusterRole\nmetadata: {name: lab-wildcard}\nrules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n"
        self.assertTrue(all(not f["builtin"] for f in rbac_lint.analyze_text(doc)))


class TestFixtures(unittest.TestCase):
    def test_every_planted_role_is_caught_for_its_own_risk(self):
        # Review (PR #209): lab-wildcard alone trips every risk id, so the set
        # of ids cannot show that the other planted roles were caught.
        pairs = {(f["risk"], f["name"]) for f in rbac_lint.analyze_text((FIXTURES / "risky-rbac.yaml").read_text())}
        for want in (("escalate", "lab-escalate"), ("bind", "lab-bind"), ("secrets-read", "lab-secret-reader"),
                     ("pods-create", "lab-pod-creator"), ("wildcard-all", "lab-wildcard")):
            self.assertIn(want, pairs)

    def test_clean_fixture_matches_the_terraform_roles(self):
        # Review (PR #209): the negative control is a hand copy of
        # local.human_roles; fail if the Terraform changes and the copy does not.
        self.assertEqual(_fixture_roles(), _terraform_roles())

    def test_risky_fixture_trips_all_planted_risks(self):
        risks = {f["risk"] for f in rbac_lint.analyze_text((FIXTURES / "risky-rbac.yaml").read_text())}
        for expected in ("escalate", "bind", "impersonate", "secrets-read", "pods-create", "wildcard-all", "token-create"):
            self.assertIn(expected, risks)

    def test_clean_fixture_mirrors_lab_roles_and_is_clean(self):
        stats = {}
        findings = rbac_lint.analyze_text((FIXTURES / "clean-rbac.yaml").read_text(), stats)
        self.assertEqual(findings, [])
        self.assertEqual(stats["rbac_objects"], 2)


def _fixture_roles():
    """{role: sorted [(apiGroups, resources, verbs)]} from clean-rbac.yaml."""
    import yaml
    roles = {}
    for doc in yaml.safe_load_all((FIXTURES / "clean-rbac.yaml").read_text()):
        if doc:
            roles[doc["metadata"]["name"]] = sorted(
                (tuple(r["apiGroups"]), tuple(r["resources"]), tuple(r["verbs"])) for r in doc["rules"])
    return roles


def _terraform_roles():
    """The same shape, read from local.human_roles in the identity root.

    A small reader for the exact form main.tf uses ({ api_groups = [...],
    resources = [...], verbs = local.x | [...] } one per line). If the form
    changes so nothing is read, the test fails rather than passing on {}.
    """
    text = TF_IDENTITY.read_text()
    verbs_vars = {m.group(1): re.findall(r'"([^"]*)"', m.group(2))
                  for m in re.finditer(r"^\s*(\w+_verbs)\s*=\s*\[([^\]]*)\]", text, re.M)}
    block = text[text.index("human_roles = {"):]
    block = block[: block.index("\n  }\n")]
    roles, current = {}, None
    for line in block.splitlines():
        m = re.match(r'\s*"([\w-]+)"\s*=\s*\{', line)
        if m:
            current = m.group(1)
            roles[current] = []
            continue
        m = re.match(r"\s*\{\s*api_groups\s*=\s*\[([^\]]*)\],\s*resources\s*=\s*\[([^\]]*)\],"
                     r"\s*verbs\s*=\s*(local\.(\w+)|\[([^\]]*)\])", line)
        if m and current:
            verbs = verbs_vars[m.group(4)] if m.group(4) else re.findall(r'"([^"]*)"', m.group(5))
            roles[current].append((tuple(re.findall(r'"([^"]*)"', m.group(1))),
                                   tuple(re.findall(r'"([^"]*)"', m.group(2))), tuple(verbs)))
    if not roles or not all(roles.values()):
        raise AssertionError(f"could not read local.human_roles from {TF_IDENTITY}")
    return {k: sorted(v) for k, v in roles.items()}


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
