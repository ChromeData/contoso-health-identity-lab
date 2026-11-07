"""Tests for lab/setup/merge_tfvars.py (stdlib only, no tenant).

    python3 -I -m unittest discover -s lab/setup/tests -p 'test_merge_tfvars.py' -v
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, '..', 'merge_tfvars.py')
sys.path.insert(0, os.path.join(HERE, '..'))
import merge_tfvars as m  # noqa: E402

OLD = '''subscription_id = "old-sub"
log_analytics_workspace_id = "/subscriptions/x/loga"
pipeline_config_vault_name = "kv-custom-name"
pipeline_config_writer_object_ids = ["11111111-1111-1111-1111-111111111111"]

# Added after setup: the evidence pack.
enable_evidence_pack = true
evidence_storage_account_name = "stevidence"
'''

NEW = '''subscription_id = "new-sub"
log_analytics_workspace_id = "/subscriptions/x/loga"
pipeline_config_vault_name = "kv-custom-name"
pipeline_config_writer_object_ids = ["22222222-2222-2222-2222-222222222222"]
'''


def run(old, new, *args):
    with tempfile.TemporaryDirectory() as d:
        po, pn = os.path.join(d, 'old'), os.path.join(d, 'new')
        if old is not None:
            open(po, 'w').write(old)
        open(pn, 'w').write(new)
        return subprocess.run([sys.executable, '-I', SCRIPT, po, pn, *args], capture_output=True, text=True)


class MergeTests(unittest.TestCase):
    def test_new_keys_win(self):
        out = m.merge(OLD, NEW)
        self.assertIn('subscription_id = "new-sub"', out)
        self.assertNotIn('old-sub', out)

    def test_keys_only_in_old_are_kept_with_their_comment(self):
        out = m.merge(OLD, NEW)
        self.assertIn('enable_evidence_pack = true', out)
        self.assertIn('evidence_storage_account_name = "stevidence"', out)
        self.assertIn('# Added after setup: the evidence pack.', out)

    def test_keep_old_keeps_the_old_writer(self):
        out = m.merge(OLD, NEW, keep_old=['pipeline_config_writer_object_ids'])
        self.assertIn('11111111-1111-1111-1111-111111111111', out)
        self.assertNotIn('22222222-2222-2222-2222-222222222222', out)

    def test_no_old_file_is_the_new_file(self):
        r = run(None, NEW)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, NEW)

    def test_custom_vault_name_change_is_refused(self):
        new = NEW.replace('kv-custom-name', 'kv-idlab-cicd-20f1')
        r = run(OLD, new, '--refuse-change', 'pipeline_config_vault_name')
        self.assertEqual(r.returncode, 3)
        self.assertIn('pipeline_config_vault_name', r.stderr)
        self.assertEqual(r.stdout, '')

    def test_same_vault_name_is_fine(self):
        r = run(OLD, NEW, '--refuse-change', 'pipeline_config_vault_name')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('pipeline_config_vault_name = "kv-custom-name"', r.stdout)

    def test_first_run_vault_name_is_not_refused(self):
        r = run('subscription_id = "a"\n', NEW, '--refuse-change', 'pipeline_config_vault_name')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_inline_comment_is_not_a_change(self):
        old = OLD.replace('"kv-custom-name"', '"kv-custom-name" # pipeline config vault')
        r = run(old, NEW, '--refuse-change', 'pipeline_config_vault_name')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_hash_inside_the_string_still_counts(self):
        self.assertEqual(m.value_of('x = "a#b" # c\n'), '"a#b"')

    def test_empty_example_name_may_be_filled_in(self):
        old = OLD.replace('"kv-custom-name"', '""')
        r = run(old, NEW, '--refuse-change', 'pipeline_config_vault_name')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('pipeline_config_vault_name = "kv-custom-name"', r.stdout)

    def test_multiline_map_and_list_are_copied_whole(self):
        old = OLD + '''lab_list = [
  "a", # one
  "b",
]
lab_map = {
  "x" = "/subscriptions/1/resourceGroups/rg/providers/A/b"
  "y" = "{not a brace}"
}
'''
        out = m.merge(old, NEW)
        self.assertIn('lab_list = [\n  "a", # one\n  "b",\n]\n', out)
        self.assertIn('lab_map = {\n  "x" = "/subscriptions/1/resourceGroups/rg/providers/A/b"\n  "y" = "{not a brace}"\n}\n', out)
        # still a parseable file: every key appears once
        keys = [k for k, _ in m.parse(out)]
        self.assertEqual(len(keys), len(set(keys)))

    def test_least_privilege_settings_survive_a_rerun(self):
        # PR #246 (senior gap 8): step B does not write these, so the merge
        # must keep them, or the next bootstrap apply would widen APPLY back
        # to the subscription, delete the VM operator role and its PIM
        # eligibility, and remove the Key Vault delete locks.
        old = OLD + '''
apply_azure_scope                   = "resource_group"
enable_lab_vm_operator              = true
lab_vm_operator_eligible_object_ids = ["79feedc9-0000-4000-8000-000000000000"]
lab_vm_operator_eligibility_duration = "P180D"
cannot_delete_lock_resource_ids = {
  "kv-idlab"      = "/subscriptions/1/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-a"
  "kv-idlab-cicd" = "/subscriptions/1/resourceGroups/rg-identity-lab-cicd/providers/Microsoft.KeyVault/vaults/kv-b"
}
'''
        out = m.merge(old, NEW, keep_old=['pipeline_config_writer_object_ids'])
        merged = dict(m.parse(out))
        self.assertEqual(m.value_of(merged['apply_azure_scope']), '"resource_group"')
        self.assertEqual(m.value_of(merged['enable_lab_vm_operator']), 'true')
        self.assertIn('79feedc9-0000-4000-8000-000000000000', merged['lab_vm_operator_eligible_object_ids'])
        self.assertIn('"kv-idlab-cicd"', merged['cannot_delete_lock_resource_ids'])
        self.assertIn('kv-b', merged['cannot_delete_lock_resource_ids'])

    def test_unclosed_value_fails(self):
        with self.assertRaises(ValueError):
            m.parse('x = [\n  "a",\n')

    def test_bad_flag_is_usage_error(self):
        r = run(OLD, NEW, '--nope', 'x')
        self.assertEqual(r.returncode, 2)


if __name__ == '__main__':
    unittest.main()
