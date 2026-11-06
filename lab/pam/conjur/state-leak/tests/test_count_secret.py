"""Offline tests for count_secret.py (stdlib only, no Conjur, no Terraform).

Run:  python3 -I -m unittest discover -s lab/pam/conjur/state-leak/tests -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import count_secret  # noqa: E402

SECRET = "s3cr3t/with+slash\"and=quote0123"


def tmpfile(data, suffix=".json"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def run_main(*paths, secret=SECRET):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"STATE_LEAK_SECRET": secret}), redirect_stdout(out), redirect_stderr(err):
        code = count_secret.main(list(paths))
    return code, out.getvalue(), err.getvalue()


class CountTests(unittest.TestCase):
    def test_finds_value_as_terraform_writes_it_in_state(self):
        # State is JSON: quotes and slashes in the value arrive escaped.
        state = json.dumps({"resources": [{"instances": [{"attributes": {"value": SECRET}}]}]})
        self.assertEqual(count_secret.count_in_file(tmpfile(state.encode()), SECRET), 1)

    def test_finds_raw_value(self):
        self.assertEqual(count_secret.count_in_bytes(b"x " + SECRET.encode() + b" y", SECRET), 1)

    def test_plain_value_is_not_double_counted(self):
        plain = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
        self.assertEqual(count_secret.count_in_bytes(plain.encode(), plain), 1)

    def test_clean_state_counts_zero(self):
        state = json.dumps({"resources": [{"instances": [{"attributes": {"input": "marker"}}]}]})
        self.assertEqual(count_secret.count_in_file(tmpfile(state.encode()), SECRET), 0)

    def test_looks_inside_a_saved_plan_zip(self):
        path = tmpfile(b"", suffix=".tfplan")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("tfplan", b"header")
            zf.writestr("tfstate", json.dumps({"value": SECRET}).encode())
        self.assertEqual(count_secret.count_in_file(path, SECRET), 1)

    def test_main_never_prints_the_value(self):
        state = json.dumps({"value": SECRET}).encode()
        code, out, err = run_main(tmpfile(state))
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("1\t"))
        self.assertNotIn(SECRET, out + err)

    def test_missing_file_is_reported_absent_not_zero(self):
        code, out, _ = run_main("/nonexistent/terraform.tfstate.backup")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("absent\t"))

    def test_no_secret_in_env_fails_closed(self):
        code, _, err = run_main(tmpfile(b"{}"), secret="")
        self.assertEqual(code, 2)
        self.assertIn("STATE_LEAK_SECRET", err)

    def test_unreadable_file_fails_closed(self):
        d = tempfile.mkdtemp()  # a directory cannot be read as a file
        code, _, _ = run_main(d)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
