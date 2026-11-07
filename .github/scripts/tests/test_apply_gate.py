"""Tests for apply-approval-gate.sh and plan-changeset.sh (karen-review A1, A2).

The gate runs against a stub `gh` on PATH that serves fixture JSON and records
what the gate posts, so no network and no real GitHub. Each case pins one
branch: the owner must name the saved plan's code, AI/delegated approvals are
refused, a change set that differs from the PR plan comment is refused, and
every "couldn't read" path fails closed.

    python3 -m unittest discover -s .github/scripts/tests -p 'test_*.py' -v
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
GATE = os.path.join(SCRIPTS, "apply-approval-gate.sh")
CHANGESET = os.path.join(SCRIPTS, "plan-changeset.sh")
MARKER = "## Terraform plan — `lab/terraform/envs/dev`"

STUB_GH = textwrap.dedent(r"""
    #!/usr/bin/env bash
    # Stub gh: fixtures in $STUB_DIR, every call appended to $STUB_DIR/calls.log
    echo "$*" >> "$STUB_DIR/calls.log"
    case "$1 $2" in
      "api repos/o/r/commits/abc1234567/pulls")
        [ -f "$STUB_DIR/pulls.fail" ] && exit 1
        cat "$STUB_DIR/pulls.json"; exit 0 ;;
      "api repos/o/r/pulls/7")
        [ -f "$STUB_DIR/pr.fail" ] && exit 1
        cat "$STUB_DIR/merged_by.txt"; exit 0 ;;
      "api repos/o/r/commits/abc1234567")
        echo "author1"; exit 0 ;;
      "api repos/o/r/issues/7/comments")
        cat "$STUB_DIR/pr_comments.json"; exit 0 ;;
      "api repos/o/r/issues/900/comments")
        cat "$STUB_DIR/issue_comments.json"; exit 0 ;;
      "issue create")
        while [ $# -gt 0 ]; do [ "$1" = "--body" ] && printf '%s' "$2" > "$STUB_DIR/issue_body.md"; shift; done
        echo "https://github.com/o/r/issues/900"; exit 0 ;;
      "issue comment")
        while [ $# -gt 0 ]; do [ "$1" = "--body" ] && printf '%s\n---\n' "$2" >> "$STUB_DIR/issue_replies.md"; shift; done
        exit 0 ;;
      "api -X")
        echo "$*" >> "$STUB_DIR/closed.log"; exit 0 ;;
    esac
    echo "stub gh: unexpected call: $*" >&2
    exit 2
""").lstrip()

PLAN_SHA = "a1b2c3d4" + "e" * 56
CODE = PLAN_SHA[:8]


def user(login, body, cid=1):
    return {"id": cid, "user": {"login": login, "type": "User"}, "body": body}


class GateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.bin = os.path.join(self.dir, "bin")
        os.mkdir(self.bin)
        with open(os.path.join(self.bin, "gh"), "w") as f:
            f.write(STUB_GH)
        os.chmod(os.path.join(self.bin, "gh"), 0o755)
        self.changeset = os.path.join(self.dir, "changeset.txt")
        self.write("changeset.txt", "create module.ca.azuread_x.this\n")
        self.write("summary.md", "**What this change does:** adds one thing.\n")
        self.pulls([{"number": 7, "title": "Add one thing", "user": {"login": "author1"}}])
        self.pr_comments([])
        self.issue_comments([])
        self.write("merged_by.txt", "author1\n")

    def tearDown(self):
        shutil.rmtree(self.dir)

    # ---- fixture helpers ----------------------------------------------------
    def write(self, name, text):
        with open(os.path.join(self.dir, name), "w") as f:
            f.write(text)

    def read(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            return ""
        with open(p) as f:
            return f.read()

    def pulls(self, data):
        self.write("pulls.json", json.dumps(data))

    def pr_comments(self, data):
        self.write("pr_comments.json", json.dumps(data))

    def issue_comments(self, data):
        self.write("issue_comments.json", json.dumps(data))

    def changeset_sha(self):
        with open(self.changeset, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def run_gate(self, **extra):
        env = {
            "PATH": self.bin + os.pathsep + os.environ["PATH"],
            "STUB_DIR": self.dir,
            "GH_TOKEN": "x", "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "1",
            "GITHUB_SHA": "abc1234567", "GITHUB_REPOSITORY_OWNER": "owner1",
            "GITHUB_EVENT_NAME": "push",
            "APPLY_APPROVERS": "owner1",
            "PLAN_SHA256": PLAN_SHA,
            "PLAN_CHANGESET_FILE": self.changeset,
            "PLAN_SUMMARY_FILE": os.path.join(self.dir, "summary.md"),
            "APPROVAL_POLL_SECONDS": "0",
            "APPROVAL_TIMEOUT_SECONDS": "2",
            "GITHUB_STEP_SUMMARY": os.path.join(self.dir, "summary_out.md"),
        }
        env.update(extra)
        env = {k: v for k, v in env.items() if v is not None}
        return subprocess.run(["bash", GATE], env=env, capture_output=True, text=True, timeout=60)

    # ---- the approval must name the saved plan ------------------------------
    def test_approve_with_plan_code_is_accepted(self):
        self.issue_comments([user("owner1", f"approve {CODE}")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("state_reason=completed", self.read("closed.log"))
        body = self.read("issue_body.md")
        self.assertIn(PLAN_SHA, body)
        self.assertIn("create module.ca.azuread_x.this", body)
        self.assertIn("adds one thing", body)
        self.assertIn(f"approve {CODE}", body)

    def test_bare_approve_is_not_accepted(self):
        self.issue_comments([user("owner1", "approve")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"approve {CODE}", self.read("issue_replies.md"))
        self.assertIn("No decision", r.stdout)

    def test_wrong_code_is_not_accepted(self):
        self.issue_comments([user("owner1", "approve deadbeef")])
        self.assertEqual(self.run_gate().returncode, 1)

    def test_code_on_next_line_is_accepted(self):
        self.issue_comments([user("owner1", f"approve\n{CODE}")])
        self.assertEqual(self.run_gate().returncode, 0)

    def test_non_approver_is_ignored(self):
        self.issue_comments([user("someone", f"approve {CODE}")])
        self.assertEqual(self.run_gate().returncode, 1)

    def test_deny_cancels(self):
        self.issue_comments([user("owner1", "deny")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("Denied", r.stdout)

    # ---- A1: no AI or delegated approvals ----------------------------------
    def test_claude_approval_is_refused(self):
        self.issue_comments([user("owner1", f"approve {CODE} - reviewed by Claude for @owner1")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("state_reason=not_planned", self.read("closed.log"))
        self.assertIn("AI assistant", r.stdout)

    def test_delegated_approval_is_refused(self):
        self.issue_comments([user("owner1", f"APPROVE {CODE} (Delegated, merge captain)")])
        self.assertEqual(self.run_gate().returncode, 1)

    # ---- A2: change set compared with the PR plan comment ------------------
    def pr_plan_comment(self, fp):
        return {"id": 5, "user": {"login": "github-actions[bot]", "type": "Bot"},
                "body": f"{MARKER}\n\nsummary\n\n<!-- plan-changeset-sha256: {fp} -->\n"}

    def test_matching_pr_change_set_is_shown_and_approvable(self):
        self.pr_comments([self.pr_plan_comment(self.changeset_sha())])
        self.issue_comments([user("owner1", f"approve {CODE}")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Matches the PR plan", self.read("issue_body.md"))

    def test_different_pr_change_set_is_refused(self):
        self.pr_comments([self.pr_plan_comment("0" * 64)])
        self.issue_comments([user("owner1", f"approve {CODE}")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("Does NOT match", self.read("issue_body.md"))
        self.assertIn("state_reason=not_planned", self.read("closed.log"))

    def test_user_copy_of_marker_is_not_trusted(self):
        fake = {"id": 6, "user": {"login": "owner1", "type": "User"},
                "body": f"{MARKER}\n<!-- plan-changeset-sha256: {self.changeset_sha()} -->"}
        self.pr_comments([fake])
        self.issue_comments([user("owner1", f"approve {CODE}")])
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertIn("no Terraform plan comment", self.read("issue_body.md"))

    def test_old_pr_comment_without_fingerprint_is_flagged(self):
        old = {"id": 5, "user": {"login": "github-actions[bot]", "type": "Bot"}, "body": f"{MARKER}\n\nold"}
        self.pr_comments([old])
        self.issue_comments([user("owner1", f"approve {CODE}")])
        self.assertEqual(self.run_gate().returncode, 0)
        self.assertIn("no change-set fingerprint", self.read("issue_body.md"))

    def test_dispatch_without_pr_says_not_compared(self):
        self.pulls([])
        self.issue_comments([user("owner1", f"approve {CODE}")])
        r = self.run_gate(GITHUB_EVENT_NAME="workflow_dispatch")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("this run has no pull request", self.read("issue_body.md"))

    # ---- fail closed ---------------------------------------------------------
    def test_missing_plan_sha_fails(self):
        r = self.run_gate(PLAN_SHA256=None)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.read("issue_body.md"), "")

    def test_bad_plan_sha_fails(self):
        self.assertEqual(self.run_gate(PLAN_SHA256="xyz").returncode, 1)

    def test_missing_change_set_file_fails(self):
        self.assertEqual(self.run_gate(PLAN_CHANGESET_FILE=os.path.join(self.dir, "nope")).returncode, 1)

    def test_unreadable_pr_lookup_fails(self):
        self.write("pulls.fail", "")
        r = self.run_gate()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.read("issue_body.md"), "")


class SeparationTest(GateTest):
    """APPLY_BOT_LOGIN: real two-identity separation when set, said plainly when not."""

    def bot_pr(self, author="agent-bot[bot]", merger="agent-bot[bot]"):
        self.pulls([{"number": 7, "title": "x", "user": {"login": author}}])
        self.write("merged_by.txt", merger + "\n")

    def test_unset_says_procedure_only_in_issue_and_summary(self):
        self.issue_comments([user("owner1", f"approve {CODE}")])
        r = self.run_gate()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        body = self.read("issue_body.md")
        self.assertIn("Change author: author1 (merged by author1)", body)
        self.assertIn("Approver must be: @owner1", body)
        self.assertIn("separation is by procedure only", body)
        self.assertIn("separation is by procedure only", self.read("summary_out.md"))

    def test_set_bot_authored_and_merged_owner_approves(self):
        self.bot_pr()
        self.issue_comments([user("owner1", f"approve {CODE}")])
        r = self.run_gate(APPLY_BOT_LOGIN="agent-bot[bot]")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        body = self.read("issue_body.md")
        self.assertIn("authored and merged by the bot", body)
        self.assertNotIn("procedure only", body)

    def test_set_refuses_human_author(self):
        self.bot_pr(author="owner1")
        r = self.run_gate(APPLY_BOT_LOGIN="agent-bot[bot]")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.read("issue_body.md"), "")

    def test_set_refuses_human_merger(self):
        self.bot_pr(merger="owner1")
        self.assertEqual(self.run_gate(APPLY_BOT_LOGIN="agent-bot[bot]").returncode, 1)

    def test_set_refuses_approver_who_is_merger(self):
        self.bot_pr()
        self.issue_comments([user("agent-bot[bot]", f"approve {CODE}")])
        r = self.run_gate(APPLY_BOT_LOGIN="agent-bot[bot]", APPLY_APPROVERS="owner1,agent-bot[bot]")
        self.assertEqual(r.returncode, 1)
        self.assertIn("authored or merged", self.read("issue_replies.md"))

    def test_set_refuses_run_without_pr(self):
        self.pulls([])
        self.assertEqual(self.run_gate(APPLY_BOT_LOGIN="agent-bot[bot]").returncode, 1)

    def test_unreadable_merger_fails_closed(self):
        self.write("pr.fail", "")
        r = self.run_gate()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.read("issue_body.md"), "")


class CheckModeTest(GateTest):
    """GATE_MODE=check (public repo): the checks and the plan for the reviewer,
    written to the job summary. No issue, no waiting: the approval is the
    Environment "production" (Review deployments)."""

    def test_check_mode_opens_no_issue_and_writes_summary(self):
        self.pr_comments([self.pr_plan_comment(self.changeset_sha())])
        r = self.run_gate(GATE_MODE="check", PLAN_LABEL="Plan fingerprint")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("issue create", self.read("calls.log"))
        out = self.read("summary_out.md")
        self.assertIn("Plan for owner review", out)
        self.assertIn("Matches the PR plan", out)
        self.assertIn("Review deployments", out)
        self.assertIn("Plan fingerprint", out)
        self.assertNotIn("approve " + CODE, out)

    def test_check_mode_refuses_change_set_mismatch(self):
        self.pr_comments([self.pr_plan_comment("0" * 64)])
        r = self.run_gate(GATE_MODE="check")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("issue create", self.read("calls.log"))
        self.assertIn("Does NOT match", self.read("summary_out.md"))

    def test_check_mode_still_enforces_bot_separation(self):
        r = self.run_gate(GATE_MODE="check", APPLY_BOT_LOGIN="lab-bot[bot]")
        self.assertEqual(r.returncode, 1)
        self.assertIn("APPLY_BOT_LOGIN", r.stdout)


class FingerprintTest(unittest.TestCase):
    """plan-fingerprint.py: same plan = same hash; any value change = new hash."""

    SCRIPT = os.path.join(SCRIPTS, "plan-fingerprint.py")

    def fp(self, plan):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "plan.json")
            with open(path, "w") as f:
                json.dump(plan, f)
            r = subprocess.run(["python3", "-I", self.SCRIPT, path], capture_output=True, text=True, check=True)
            return r.stdout.strip()
        finally:
            shutil.rmtree(d)

    @staticmethod
    def plan(value="a", order=False, prior="x"):
        rcs = [
            {"address": "b.one", "change": {"actions": ["update"], "before": {"v": "0"}, "after": {"v": value}}},
            {"address": "a.two", "change": {"actions": ["no-op"], "before": {}, "after": {}}},
            {"address": "c.three", "change": {"actions": ["create"], "before": None, "after": {"n": 1}}},
        ]
        if order:
            rcs.reverse()
        return {"resource_changes": rcs, "prior_state": {"p": prior}, "timestamp": prior}

    def test_same_plan_same_fingerprint_regardless_of_order_and_prior_state(self):
        self.assertEqual(self.fp(self.plan()), self.fp(self.plan(order=True, prior="y")))

    def test_value_change_changes_fingerprint(self):
        self.assertNotEqual(self.fp(self.plan("a")), self.fp(self.plan("b")))

    def test_output_is_only_a_digest(self):
        out = self.fp(self.plan("secret-looking-value"))
        self.assertRegex(out, r"^[0-9a-f]{64}$")


class ChangesetTest(unittest.TestCase):
    def run_cs(self, plan):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(plan, f)
        try:
            return subprocess.run(["bash", CHANGESET, f.name], capture_output=True, text=True)
        finally:
            os.unlink(f.name)

    def test_lists_changes_sorted_without_noop_or_read(self):
        plan = {"format_version": "1.2", "resource_changes": [
            {"address": "b.x", "change": {"actions": ["update"], "after": {"secret": "s3cr3t"}}},
            {"address": "a.y", "change": {"actions": ["delete", "create"]}},
            {"address": "c.z", "change": {"actions": ["no-op"]}},
            {"address": "data.d", "change": {"actions": ["read"]}},
        ]}
        r = self.run_cs(plan)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "delete+create a.y\nupdate b.x\n")
        self.assertNotIn("s3cr3t", r.stdout)

    def test_no_changes_is_empty(self):
        r = self.run_cs({"format_version": "1.2", "resource_changes": []})
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_not_a_plan_fails(self):
        r = self.run_cs({"hello": 1})
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main()
