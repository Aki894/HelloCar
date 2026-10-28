"""Provisioning CLI regression using temporary, synthetic identities only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1]/'tools/identity.py'


class IdentityCliTests(unittest.TestCase):
    def command(self, path, name, data=None):
        return subprocess.run([sys.executable, str(TOOL), name, '--path', str(path)],
            input=data, capture_output=True, text=True, timeout=5)

    def test_init_preserves_identity_and_fixed_pin_updates_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'private'/'identity.json'
            created = self.command(path, 'init')
            self.assertEqual(created.returncode, 0)
            record = json.loads(path.read_bytes())
            self.assertNotIn(record['pin'], created.stdout)
            self.assertNotIn(record['device_id'], created.stdout)
            original = path.read_bytes()
            self.assertEqual(self.command(path, 'init').returncode, 0)
            self.assertEqual(path.read_bytes(), original)
            changed = self.command(path, 'set-pin', '012345\n')
            self.assertEqual(changed.returncode, 0)
            self.assertNotIn('012345', changed.stdout)
            self.assertEqual(json.loads(path.read_bytes())['device_id'], record['device_id'])
            self.assertEqual(self.command(path, 'show-pin').stdout, '012345\n')
            updated = path.read_bytes()
            self.assertNotEqual(self.command(path, 'set-pin', '9'*100000).returncode, 0)
            self.assertEqual(path.read_bytes(), updated)

    def test_duplicate_or_oversized_identity_is_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'identity.json'
            for data in ('{"schema":1,"schema":1}', 'x'*4097):
                path.write_text(data)
                path.chmod(0o600)
                failed = self.command(path, 'show-pin')
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(failed.stdout, '')

    @unittest.skipUnless(os.name == 'posix', 'Linux private directory mode')
    def test_world_accessible_parent_is_not_used_for_new_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            path = root/'identity.json'
            self.assertNotEqual(self.command(path, 'init').returncode, 0)
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
