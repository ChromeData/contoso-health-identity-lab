"""Tests for check-adr-status.py (karen-review E2). Run: python3 -m unittest discover .github/scripts/tests"""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cas", os.path.join(HERE, "..", "check-adr-status.py"))
cas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cas)

LOG = 'id,utc,what,sha256,stored_at,public,operator\nE49,2026-11-05T10:55:51Z,"Invoke-BreakGlassDrill.ps1 ran",x,y,no,operator\n'


class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.adr = os.path.join(self.d, "adr")
        os.mkdir(self.adr)
        self.log = os.path.join(self.d, "log.csv")
        with open(self.log, "w") as fh:
            fh.write(LOG)

    def adr_file(self, body):
        with open(os.path.join(self.adr, "0003-x.md"), "w") as fh:
            fh.write(body)

    def test_contradiction_over_two_lines_fails(self):
        self.adr_file("- `Invoke-BreakGlassDrill.ps1` (drill checks, never\n  run)\n")
        self.assertEqual(len(cas.check(self.adr, self.log)), 1)

    def test_no_row_for_script_passes(self):
        self.adr_file("- `Convert-BuildAccountToEligible.ps1` (never run)\n")
        self.assertEqual(cas.check(self.adr, self.log), [])

    def test_claim_that_it_ran_passes(self):
        self.adr_file("- `Invoke-BreakGlassDrill.ps1` (ran 2026-11-05, E49)\n")
        self.assertEqual(cas.check(self.adr, self.log), [])

    def test_missing_log_is_exit_2_not_pass(self):
        self.adr_file("text\n")
        self.assertEqual(cas.main(["--adr-dir", self.adr, "--capture-log", os.path.join(self.d, "nope.csv")]), 2)

    def test_no_adrs_is_exit_2(self):
        self.assertEqual(cas.main(["--adr-dir", self.d, "--capture-log", self.log]), 2)


if __name__ == "__main__":
    unittest.main()
