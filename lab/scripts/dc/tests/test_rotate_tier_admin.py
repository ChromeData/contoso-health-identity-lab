"""Offline tests for lab/scripts/dc/rotate-tier-admin.py (PR #251).

No Azure, no DC01, no real Keychain: the Keychain calls and run_on_dc are
replaced by fakes. Fake passwords only. What is held (Greptile #251):
  * the main item goes back to the old value ONLY when DC01 proves AD was
    not touched (REFUSED, run command never created);
  * an error after the reset started, a missing result, or Ctrl+C keeps both
    values (new in the main item, old in the -previous item);
  * a -previous item left by a half-done run stops the next run before any write;
  * run-on-dc.py gets BOTH passwords from memory on stdin, not from the Keychain;
  * a second run for the same account is refused while one holds the lock;
  * contosoadmin and unknown accounts are refused before anything is read;
  * quote() round-trips spaces, quotes and backslashes the way security -i reads them.
"""
import importlib.util
import json
import os
import shlex
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("rta", os.path.join(HERE, "..", "rotate-tier-admin.py"))

SAM = "t0-adm-01"
MAIN = "contoso-lab-ad-t0-adm-01"
PREV = MAIN + "-previous"
OLD = 'fake OLD "value" 1'
DONE = "RESET: DONE x\nKERBEROS: PASS t\nKERBEROS-OLD: REFUSED (bad password)\n"


def load():
    mod = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(mod)
    return mod


class Harness(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory()
        self.mod.LOCK_DIR = self.tmp.name
        self.kc = {MAIN: OLD}
        self.calls = []
        m = self.mod

        def read(service, missing_ok=False):
            if service not in self.kc:
                if missing_ok:
                    return None
                raise SystemExit(f"Keychain item {service} not found")
            return self.kc[service]
        m.keychain_read = read
        m.keychain_write = lambda s, a, v: (self.calls.append(("write", s, v)), self.kc.__setitem__(s, v))
        m.keychain_delete = lambda s: (self.calls.append(("delete", s)), self.kc.pop(s, None))

    def tearDown(self):
        self.tmp.cleanup()

    def run_with(self, output=None, raises=None, argv=(SAM,)):
        def fake_run(sam, new, old):
            self.calls.append(("run", sam, new, old))
            if raises:
                raise raises
            return types.SimpleNamespace(stdout=output, stderr="", returncode=0)
        self.mod.run_on_dc = fake_run
        with mock.patch("builtins.print"):
            try:
                self.mod.main(list(argv))
                return 0
            except SystemExit as e:
                return e.code
            except KeyboardInterrupt:
                return "interrupted"


class Outcomes(Harness):
    def test_success_keeps_only_the_new_value(self):
        self.assertEqual(self.run_with(DONE), 0)
        self.assertNotEqual(self.kc[MAIN], OLD)
        self.assertNotIn(PREV, self.kc)

    def test_refused_rolls_back(self):
        self.assertEqual(self.run_with("REFUSED: 'x' is not a tier admin\n"), 1)
        self.assertEqual(self.kc, {MAIN: OLD})

    def test_run_command_never_created_rolls_back(self):
        self.run_with("PUT failed: HTTP 403: ...\n")
        self.assertEqual(self.kc, {MAIN: OLD})

    def test_error_after_reset_keeps_both(self):
        # Set-ADAccountPassword may have worked and Get-ADUser failed after it.
        self.assertEqual(self.run_with("Get-ADUser : server not operational\nstate: Failed, exit code: 1\n"), 1)
        self.assertNotEqual(self.kc[MAIN], OLD)
        self.assertEqual(self.kc[PREV], OLD)

    def test_no_output_keeps_both(self):
        self.run_with("")
        self.assertNotEqual(self.kc[MAIN], OLD)
        self.assertEqual(self.kc[PREV], OLD)

    def test_ctrl_c_keeps_both(self):
        self.assertEqual(self.run_with(raises=KeyboardInterrupt()), "interrupted")
        self.assertNotEqual(self.kc[MAIN], OLD)
        self.assertEqual(self.kc[PREV], OLD)

    def test_old_check_error_is_not_success(self):
        rc = self.run_with("RESET: DONE x\nKERBEROS: PASS t\nKERBEROS-OLD: ERROR: timeout (not proof)\n")
        self.assertEqual(rc, 2)

    def test_old_saved_before_new_is_written(self):
        self.run_with(DONE)
        writes = [c for c in self.calls if c[0] == "write"]
        self.assertEqual(writes[0], ("write", PREV, OLD))
        self.assertEqual(writes[1][1], MAIN)


class HalfDone(Harness):
    def test_previous_item_stops_before_any_write(self):
        self.kc[PREV] = "fake-OTHER"
        rc = self.run_with(DONE)
        self.assertIn("half way", str(rc))
        self.assertEqual(self.kc, {MAIN: OLD, PREV: "fake-OTHER"})
        self.assertEqual(self.calls, [])


class Accounts(Harness):
    def test_contosoadmin_refused(self):
        self.assertIn("usage", str(self.run_with(DONE, argv=("contosoadmin",))))
        self.assertEqual(self.calls, [])

    def test_unknown_refused(self):
        self.assertIn("usage", str(self.run_with(DONE, argv=("someone",))))


class InMemoryHandOff(Harness):
    def test_run_on_dc_gets_the_generated_value_not_a_reread(self):
        self.run_with(DONE)
        run = [c for c in self.calls if c[0] == "run"][0]
        written = [c[2] for c in self.calls if c[0] == "write" and c[1] == MAIN][0]
        self.assertEqual(run[2], written)
        self.assertEqual(run[3], OLD)

    def test_real_run_on_dc_sends_both_on_stdin_not_argv(self):
        mod = load()
        with mock.patch.object(mod.subprocess, "run") as r:
            mod.run_on_dc(SAM, "fake-NEW", "fake-OLD")
        argv, kwargs = r.call_args[0][0], r.call_args[1]
        self.assertNotIn("fake-NEW", " ".join(argv))
        self.assertNotIn("fake-OLD", " ".join(argv))
        self.assertIn("NewPassword=stdin:NewPassword", argv)
        self.assertNotIn("keychain:", " ".join(argv))
        self.assertEqual(json.loads(kwargs["input"]), {"NewPassword": "fake-NEW", "OldPassword": "fake-OLD"})


class Lock(Harness):
    def test_second_run_for_same_account_is_refused(self):
        held = self.mod.take_lock(SAM)
        try:
            rc = self.run_with(DONE)
        finally:
            held.close()
        self.assertIn("lock", str(rc))
        self.assertEqual(self.calls, [])

    def test_other_account_is_not_blocked(self):
        held = self.mod.take_lock("t1-adm-01")
        try:
            self.assertEqual(self.run_with(DONE), 0)
        finally:
            held.close()


class Quote(unittest.TestCase):
    def test_round_trip(self):
        mod = load()
        for v in ['fake pass word', 'fa"ke\'q', 'back\\slash x', '-leading', '$d `t` #h']:
            self.assertEqual(shlex.split(mod.quote(v)), [v], v)

    def test_line_break_refused(self):
        with self.assertRaises(SystemExit):
            load().quote("a\nb")

    def test_generated_value_needs_no_quoting(self):
        mod = load()
        for _ in range(50):
            pw = mod.new_password()
            self.assertEqual(shlex.split(pw), [pw])
            self.assertTrue(pw[0].isalpha())


if __name__ == "__main__":
    unittest.main()
