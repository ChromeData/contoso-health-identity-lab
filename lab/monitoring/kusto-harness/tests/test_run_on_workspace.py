"""Offline tests for run-on-workspace.py (no workspace, no operator).

Run: python3 -I -m unittest discover -s lab/monitoring/kusto-harness/tests -v
"""
import importlib.util, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS_DIR = os.path.dirname(HERE)
sys.path.insert(0, HARNESS_DIR)
spec = importlib.util.spec_from_file_location("row", os.path.join(HARNESS_DIR, "run-on-workspace.py"))
row = importlib.util.module_from_spec(spec)
spec.loader.exec_module(row)
import harness  # noqa: E402


# The shape api.loganalytics.io/v1 .../query returns: typed numbers and
# booleans, a dynamic column as JSON text.
LA_RESPONSE = {"tables": [{"name": "PrimaryResult",
                           "columns": [{"name": "UserId", "type": "string"},
                                       {"name": "SignIns", "type": "long"},
                                       {"name": "NewAccount", "type": "bool"},
                                       {"name": "IPAddresses", "type": "dynamic"}],
                           "rows": [["11111111-1111-1111-1111-111111111111", 2, False, "[\"203.0.113.11\",\"203.0.113.10\"]"]]}]}


class DecodeTests(unittest.TestCase):
    def test_dynamic_list_is_a_list_and_types_survive(self):
        res = harness.primary_table(row.to_kusto_payload(LA_RESPONSE))
        r = res["rows"][0]
        self.assertEqual(r["IPAddresses"], ["203.0.113.11", "203.0.113.10"])
        self.assertIs(r["NewAccount"], False)
        self.assertEqual(r["SignIns"], 2)
        self.assertEqual([c for c, _ in res["columns"]], ["UserId", "SignIns", "NewAccount", "IPAddresses"])

    def test_list_expectation_matches_in_any_order(self):
        # make_set order is undefined; evaluate() compares lists as multisets.
        case = {"kind": "positive", "origin": "hand", "expect": [{"IPAddresses": ["203.0.113.10", "203.0.113.11"]}],
                "expectNone": [], "expectRows": 1}
        res = harness.primary_table(row.to_kusto_payload(LA_RESPONSE))
        fails, _ = harness.evaluate(case, res)
        self.assertEqual(fails, [])

    def test_empty_answer_keeps_the_output_columns(self):
        empty = {"tables": [{"columns": [{"name": "Severity", "type": "string"}], "rows": []}]}
        res = harness.primary_table(row.to_kusto_payload(empty))
        case = {"kind": "positive", "origin": "hand", "expect": [{"Severity": "High"}], "expectNone": [], "expectRows": None}
        fails, _ = harness.evaluate(case, res)
        self.assertEqual(fails, ["positive case returned no rows"])


class VerdictTests(unittest.TestCase):
    def test_all_passed(self):
        self.assertEqual(row.verdict_of({"PASS": 3, "FAIL": 0, "ERROR": 0, "SKIPPED": 0}), "PASS")

    def test_a_skipped_case_is_incomplete_not_pass(self):
        self.assertEqual(row.verdict_of({"PASS": 3, "FAIL": 0, "ERROR": 0, "SKIPPED": 1}), "INCOMPLETE")

    def test_failure_or_error_or_nothing_run_is_fail(self):
        self.assertEqual(row.verdict_of({"PASS": 3, "FAIL": 1, "ERROR": 0, "SKIPPED": 0}), "FAIL")
        self.assertEqual(row.verdict_of({"PASS": 3, "FAIL": 0, "ERROR": 1, "SKIPPED": 0}), "FAIL")
        self.assertEqual(row.verdict_of({"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIPPED": 2}), "FAIL")


if __name__ == "__main__":
    unittest.main()
