"""Offline tests for lab/scripts/dc/rotate-build-admin.py (PR #262).

No Azure, no DC01, no real Keychain: keychain_read/keychain_write, the Key
Vault call, the token and run_on_dc are replaced by fakes. Fake passwords only.
What is held:
  * the Keychain goes back to the old value ONLY when DC01 proves AD was not
    touched (REFUSED, DEPENDENTS: FOUND, run command never created);
  * an error after the reset started, a missing result, or Ctrl+C keeps both
    values (new in the Keychain, old in Key Vault), never a rollback;
  * run-on-dc.py gets BOTH passwords from memory on stdin, not from the Keychain;
  * a second run is refused while one holds the lock;
  * differing Keychain / Key Vault copies stop the run before any write;
  * quote() round-trips spaces, quotes and backslashes the way security -i reads them.
"""
import importlib.util
import json
import os
import shlex
import subprocess
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("rba", os.path.join(HERE, "..", "rotate-build-admin.py"))

OLD = "fake-OLD-value 1"


def load():
    mod = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(mod)
    return mod


class Harness(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.mod.LOCK = os.path.join(self.tmp.name, "rotate.lock")
        self.keychain = {"value": OLD}
        self.vault = {"value": OLD, "tags": {"file-encoding": "utf-8"}}
        self.calls = []
        self.mod.keychain_read = lambda: self.keychain["value"]
        self.mod.keychain_write = lambda v: (self.calls.append(("keychain", v)), self.keychain.__setitem__("value", v))
        self.mod.get_token = lambda: "fake-token"

        def kv(method, token, body=None):
            self.calls.append(("kv", method))
            if method == "PUT":
                self.vault.update(body)
            return dict(self.vault)
        self.mod.kv = kv

    def tearDown(self):
        self.tmp.cleanup()

    def run_with(self, output=None, raises=None):
        def fake_run(new, old):
            self.calls.append(("run", new, old))
            if raises:
                raise raises
            return types.SimpleNamespace(stdout=output, stderr="", returncode=0)
        self.mod.run_on_dc = fake_run
        with mock.patch("builtins.print"):
            try:
                self.mod.main()
                return 0
            except SystemExit as e:
                return e.code
            except KeyboardInterrupt:
                return "interrupted"


class Rollback(Harness):
    def test_success_writes_both_copies(self):
        rc = self.run_with("DEPENDENTS: NONE\nRESET: DONE x\nKERBEROS: PASS t\nKERBEROS-OLD: REFUSED (bad password)\n")
        self.assertEqual(rc, 0)
        self.assertNotEqual(self.keychain["value"], OLD)
        self.assertEqual(self.vault["value"], self.keychain["value"])

    def test_dependents_found_rolls_back(self):
        rc = self.run_with("DEPENDENTS: FOUND services [x] tasks []; nothing changed\n")
        self.assertEqual(rc, 1)
        self.assertEqual(self.keychain["value"], OLD)
        self.assertNotIn(("kv", "PUT"), self.calls)

    def test_refused_account_rolls_back(self):
        self.run_with("REFUSED: 'x' is not the build admin (contosoadmin).\n")
        self.assertEqual(self.keychain["value"], OLD)

    def test_run_command_never_created_rolls_back(self):
        self.run_with("PUT failed: HTTP 403: ...\n")
        self.assertEqual(self.keychain["value"], OLD)

    def test_error_after_dependents_none_keeps_both(self):
        # Greptile #262: DEPENDENTS: NONE comes BEFORE the reset; an error after
        # it (e.g. Get-ADUser failing after Set-ADAccountPassword) is unknown.
        rc = self.run_with("DEPENDENTS: NONE (...)\nGet-ADUser : server not operational\nstate: Failed, exit code: 1\n")
        self.assertEqual(rc, 1)
        self.assertNotEqual(self.keychain["value"], OLD)  # new kept in the Keychain
        self.assertEqual(self.vault["value"], OLD)        # old kept in Key Vault

    def test_no_output_keeps_both(self):
        self.run_with("")
        self.assertNotEqual(self.keychain["value"], OLD)
        self.assertEqual(self.vault["value"], OLD)

    def test_ctrl_c_keeps_both(self):
        rc = self.run_with(raises=KeyboardInterrupt())
        self.assertEqual(rc, "interrupted")
        self.assertNotEqual(self.keychain["value"], OLD)
        self.assertEqual(self.vault["value"], OLD)
        self.assertEqual([c for c in self.calls if c[0] == "keychain"], [("keychain", self.keychain["value"])])

    def test_old_check_error_is_not_success(self):
        rc = self.run_with("DEPENDENTS: NONE\nRESET: DONE x\nKERBEROS: PASS t\nKERBEROS-OLD: ERROR: timeout (not proof)\n")
        self.assertEqual(rc, 2)


class CopiesDiffer(Harness):
    def test_mismatch_stops_before_any_write(self):
        # Greptile #262 (2nd pass): differing copies may follow a half-done run;
        # overwriting the Keychain could lose the only working password.
        self.vault["value"] = "fake-OTHER-value"
        rc = self.run_with("RESET: DONE\n")
        self.assertIn("differs", str(rc))
        self.assertEqual(self.keychain["value"], OLD)
        self.assertEqual(self.vault["value"], "fake-OTHER-value")
        self.assertFalse([c for c in self.calls if c[0] in ("keychain", "run") or c == ("kv", "PUT")])


class InMemoryHandOff(Harness):
    def test_run_on_dc_gets_the_generated_value_not_a_reread(self):
        self.run_with("DEPENDENTS: NONE\nRESET: DONE x\nKERBEROS: PASS t\nKERBEROS-OLD: REFUSED\n")
        run = [c for c in self.calls if c[0] == "run"][0]
        written = [c[1] for c in self.calls if c[0] == "keychain"][0]
        self.assertEqual(run[1], written)
        self.assertEqual(run[2], OLD)

    def test_real_run_on_dc_sends_both_on_stdin_not_argv(self):
        mod = load()
        with mock.patch.object(mod.subprocess, "run") as r:
            mod.run_on_dc("fake-NEW", "fake-OLD")
        argv, kwargs = r.call_args[0][0], r.call_args[1]
        self.assertNotIn("fake-NEW", " ".join(argv))
        self.assertNotIn("fake-OLD", " ".join(argv))
        self.assertIn("NewPassword=stdin:NewPassword", argv)
        self.assertNotIn("keychain:", " ".join(argv))
        self.assertEqual(json.loads(kwargs["input"]), {"NewPassword": "fake-NEW", "OldPassword": "fake-OLD"})


class Lock(Harness):
    def test_second_run_is_refused_while_locked(self):
        held = self.mod.take_lock()
        try:
            rc = self.run_with("RESET: DONE\n")
        finally:
            held.close()
        self.assertIn("lock", str(rc))
        self.assertEqual(self.keychain["value"], OLD)
        self.assertEqual(self.calls, [])


class Quote(unittest.TestCase):
    def test_round_trip(self):
        mod = load()
        for v in ['fake pass word', 'fa"ke\'q', 'back\\slash x', '-leading', '$d `t` #h']:
            # security -i splits like a POSIX shell for double-quoted words
            self.assertEqual(shlex.split(mod.quote(v)), [v], v)

    def test_line_break_refused(self):
        with self.assertRaises(SystemExit):
            load().quote("a\nb")


if __name__ == "__main__":
    unittest.main()
