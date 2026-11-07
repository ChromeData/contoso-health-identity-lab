"""
Offline tests for ../tier2-device.py (stdlib unittest; pytest runs them too).
No Azure, no az, no Keychain: arm(), wait() and subprocess.run are mocks.
Fake passwords only; nothing here reads the real Keychain.

What is held (Greptile, PR #239):
  * build refuses an EXISTING VM and writes nothing to the Keychain;
  * the Keychain is written only AFTER Azure accepts the VM PUT, and before
    the provisioning wait;
  * a refused VM PUT leaves the Keychain untouched;
  * the password never reaches argv, and a failed Keychain write never
    prints it.

Run: python3 -I -m unittest discover -s lab/scripts/dc/tier-test/tests -v
"""
import importlib.util
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "tier2-device.py")


def load():
    spec = importlib.util.spec_from_file_location("tier2_device", SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # must not call az at import
    mod.SUB = "00000000-0000-0000-0000-000000000000"
    return mod


class FakeArm:
    """Records ARM calls. vm_exists: GET on the VM answers 200. vm_put_fails: PUT on the VM raises."""

    def __init__(self, mod, vm_exists=False, vm_put_fails=False, events=None):
        self.mod, self.vm_exists, self.vm_put_fails = mod, vm_exists, vm_put_fails
        self.calls = []
        self.events = events if events is not None else []

    def __call__(self, method, path, body=None, ok404=False):
        self.calls.append((method, path))
        is_vm = f"/virtualMachines/{self.mod.VM}?" in path
        if is_vm and method == "GET":
            if self.vm_exists:
                return 200, {"properties": {"provisioningState": "Succeeded"}}
            if ok404:
                return 404, {}
        if is_vm and method == "PUT":
            self.events.append("vm-put")
            if self.vm_put_fails:
                raise SystemExit("PUT vm: HTTP 409: OperationNotAllowed")
            return 201, {}
        if "/networkInterfaces/" in path and method == "GET":
            return 200, {"properties": {"ipConfigurations": [{"properties": {"privateIPAddress": "10.43.0.4"}}]}}
        return 200, {}


class BuildKeychainOrder(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.events = []
        self.run = mock.MagicMock(side_effect=self._run)

    def _run(self, args, **kw):
        self.events.append("keychain")
        self.assertEqual(args, ["security", "-i"], "only `security -i` (stdin) may be used")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def _build(self, arm):
        def wait(path, api, **kw):
            self.events.append("wait-vm" if "/virtualMachines/" in path else "wait")
            return {}
        with mock.patch.object(self.mod, "arm", arm), mock.patch.object(self.mod, "wait", wait), \
                mock.patch.object(self.mod.subprocess, "run", self.run), redirect_stdout(io.StringIO()) as out:
            self.mod.build()
        return out.getvalue()

    def test_existing_vm_is_refused_and_keychain_untouched(self):
        arm = FakeArm(self.mod, vm_exists=True, events=self.events)
        with self.assertRaises(SystemExit) as e:
            self._build(arm)
        self.assertIn("already exists", str(e.exception))
        self.run.assert_not_called()
        self.assertFalse([c for c in arm.calls if c[0] == "PUT"], "no resource may be written")

    def test_refused_vm_put_leaves_keychain_untouched(self):
        arm = FakeArm(self.mod, vm_put_fails=True, events=self.events)
        with self.assertRaises(SystemExit):
            self._build(arm)
        self.assertIn("vm-put", self.events)
        self.run.assert_not_called()

    def test_keychain_written_after_accepted_put_before_wait(self):
        arm = FakeArm(self.mod, events=self.events)
        out = self._build(arm)
        order = [e for e in self.events if e in ("vm-put", "keychain", "wait-vm")]
        self.assertEqual(order, ["vm-put", "keychain", "wait-vm"])
        # The password went over stdin, and it is in no printed line.
        stdin = self.run.call_args.kwargs["input"]
        pw = stdin.split('-w "')[1].split('"')[0]
        self.assertEqual(len(pw), 24)
        self.assertNotIn(pw, out)
        self.assertNotIn(pw, " ".join(self.run.call_args.args[0]))


class KeychainWrite(unittest.TestCase):
    def test_failed_write_hides_output_and_password(self):
        mod = load()
        fake = "Fake-Pass_word.123"
        failing = mock.Mock(return_value=mock.Mock(returncode=1, stdout=f"echo {fake}", stderr=f"err {fake}"))
        with mock.patch.object(mod.subprocess, "run", failing), self.assertRaises(SystemExit) as e:
            mod.save_to_keychain("svc-test", "acct", "label", fake)
        self.assertNotIn(fake, str(e.exception))
        self.assertNotIn(fake, " ".join(failing.call_args.args[0]))

    def test_test_passwords_makes_three_distinct_items(self):
        mod = load()
        seen = []
        with mock.patch.object(mod, "save_to_keychain", lambda s, a, l, p: seen.append((s, a, p))), \
                redirect_stdout(io.StringIO()) as out:
            mod.test_passwords()
        self.assertEqual(sorted(s for s, _, _ in seen), sorted(mod.TEST_PASSWORDS))
        self.assertEqual(len({p for _, _, p in seen}), 3)
        for _, _, p in seen:
            self.assertNotIn(p, out.getvalue())


if __name__ == "__main__":
    unittest.main()
