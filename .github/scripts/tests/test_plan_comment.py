"""Tests for the PR plan comment script in terraform-plan.yml (PR #228 review).

The github-script body is pulled out of the workflow and run under Node with
stub `github`, `core` and `context` objects, so the real comment text is built
and measured. GitHub refuses a comment over 65,536 characters, which would fail
the required plan check after a successful plan.

    python3 -m unittest discover -s .github/scripts/tests -p 'test_*.py' -v
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(os.path.dirname(os.path.dirname(HERE)), "workflows", "terraform-plan.yml")
MARKER = "## Terraform plan — `lab/terraform/envs/dev`"

HARNESS = r"""
const fs = require('fs');
const posted = [];
const github = {
  paginate: async () => [],
  rest: { issues: {
    listComments: () => {},
    createComment: async (a) => { posted.push(a.body); },
    updateComment: async (a) => { posted.push(a.body); },
  } },
};
const core = { warning: () => {} };
const context = { sha: 'abcdef1234567', repo: { owner: 'o', repo: 'r' }, issue: { number: 7 } };
(async () => {
  const fn = new (Object.getPrototypeOf(async function () {}).constructor)(
    'require', 'github', 'core', 'context', fs.readFileSync(process.argv[2], 'utf8'));
  await fn(require, github, core, context);
  fs.writeFileSync(process.argv[3], JSON.stringify(posted));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def comment_script():
    """Return the `script: |` block that posts the plan comment (no PyYAML needed)."""
    with open(WORKFLOW) as f:
        lines = f.read().split("\n")
    for i, line in enumerate(lines):
        if line.strip() != "script: |":
            continue
        key_indent = len(line) - len(line.lstrip())
        block = []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= key_indent:
                break
            block.append(nxt)
        indent = min(len(b) - len(b.lstrip()) for b in block if b.strip())
        script = "\n".join(b[indent:] for b in block)
        if MARKER in script and "createComment" in script:
            return script
    raise AssertionError("plan comment step not found in terraform-plan.yml")


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class PlanCommentSizeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "script.js"), "w") as f:
            f.write(comment_script())
        with open(os.path.join(self.dir, "harness.js"), "w") as f:
            f.write(HARNESS)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def build(self, plan, summary, changeset):
        for name, text in (("plan.txt", plan), ("summary.md", summary), ("changeset.txt", changeset)):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write(text)
        env = dict(os.environ,
                   GITHUB_WORKSPACE=self.dir,
                   SUMMARY_FILE=os.path.join(self.dir, "summary.md"),
                   CHANGESET_FILE=os.path.join(self.dir, "changeset.txt"),
                   CHANGESET_SHA256="f" * 64,
                   FMT="success", INIT="success", VALIDATE="success", PLAN_EXIT="0",
                   DEPENDABOT_RUN="false")
        out = os.path.join(self.dir, "posted.json")
        r = subprocess.run(["node", os.path.join(self.dir, "harness.js"),
                            os.path.join(self.dir, "script.js"), out],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as f:
            posted = json.load(f)
        self.assertEqual(len(posted), 1)
        return posted[0]

    def test_large_plan_and_change_set_stay_under_limit(self):
        changeset = "".join(f"update module.big.azuread_x.r{i}\n" for i in range(2000))  # > 15,000 chars
        body = self.build("x" * 200000, "s" * 3000, changeset)
        self.assertLessEqual(len(body), 65536)
        self.assertIn("[truncated — see the full plan", body)
        self.assertIn("<!-- plan-changeset-sha256: " + "f" * 64 + " -->", body)
        self.assertTrue(body.startswith(MARKER))

    def test_huge_summary_is_capped_and_still_fits(self):
        body = self.build("x" * 200000, "s" * 80000, "create a.b\n" * 3000)
        self.assertLessEqual(len(body), 65536)
        self.assertIn("<!-- plan-changeset-sha256:", body)

    def test_small_plan_is_not_truncated(self):
        body = self.build("Plan: 1 to add, 0 to change, 0 to destroy.", "adds one thing", "create a.b\n")
        self.assertIn("Plan: 1 to add", body)
        self.assertNotIn("[truncated", body)


if __name__ == "__main__":
    unittest.main()
