"""Every envs/dev variable documented as coming from a Repo Variable must be
passed to Terraform by BOTH deployment workflows (PR #233 review).

A variable whose description says "Repo Variable TF_X" is read by CI only if
terraform-plan.yml and terraform-apply.yml export TF_VAR_<name> from vars.TF_X.
Without that line, setting the Repo Variable changes nothing and the plan sees
the default (for operator_principal_ids: an empty list, so
enable_itdr_detections_v4 fails its required-id check).

    python3 -m unittest discover -s .github/scripts/tests -p 'test_*.py' -v
"""

import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
VARIABLES = os.path.join(ROOT, "lab", "terraform", "envs", "dev", "variables.tf")
WORKFLOWS = [os.path.join(ROOT, ".github", "workflows", w) for w in ("terraform-plan.yml", "terraform-apply.yml")]

VAR_RE = re.compile(r'variable "([a-z0-9_]+)" \{.*?description\s*=\s*"((?:[^"\\]|\\.)*)"', re.S)
REPO_VAR_RE = re.compile(r"Repo Variable (TF_[A-Z0-9_]+)")


def documented_repo_variables():
    with open(VARIABLES, encoding="utf-8") as f:
        text = f.read()
    return [(name, repo) for name, desc in VAR_RE.findall(text) for repo in REPO_VAR_RE.findall(desc)]


class TfVarMapping(unittest.TestCase):
    def test_there_is_something_to_check(self):
        self.assertIn(("operator_principal_ids", "TF_OPERATOR_PRINCIPAL_IDS"), documented_repo_variables())

    def test_both_workflows_export_every_documented_repo_variable(self):
        for wf in WORKFLOWS:
            with open(wf, encoding="utf-8") as f:
                text = f.read()
            for name, repo in documented_repo_variables():
                with self.subTest(workflow=os.path.basename(wf), variable=name):
                    pattern = r"^\s*TF_VAR_%s:\s*\$\{\{\s*vars\.%s\b" % (re.escape(name), re.escape(repo))
                    self.assertRegex(text, re.compile(pattern, re.M),
                                     "%s must set TF_VAR_%s from vars.%s" % (os.path.basename(wf), name, repo))


if __name__ == "__main__":
    unittest.main()
