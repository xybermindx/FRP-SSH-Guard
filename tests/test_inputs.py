"""Editable home files are data, never privileged shell scripts."""
import importlib.util
import os
from pathlib import Path
import pwd
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_data', ROOT / 'bin/frp-ssh-guard-input.py')
data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data)


class InputTests(unittest.TestCase):
    def test_settings_are_literal_and_only_policy_keys_are_allowed(self):
        self.assertEqual(data.settings('BAN_TIMEOUT="6h" # comment\nJAIL_PER_PORT=off\n')['BAN_TIMEOUT'], '6h')
        self.assertEqual(data.settings('LOGIN_USERS="$(id)"\n')['LOGIN_USERS'], '$(id)')
        for invalid in ('PATH=/tmp', 'touch /tmp/example', 'PER_IP_RATE=2; id'):
            with self.assertRaises(ValueError):
                data.settings(invalid)

    def test_list_scope_and_absolute_expiry(self):
        result = data.entries('198.51.100.7 all\n2001:db8::7 22001,22003 until=2030-01-01T00:00:00Z\n')
        self.assertEqual(result[0], ('198.51.100.7', '*', 0))
        self.assertEqual(result[1], ('2001:db8::7', '22001,22003', 1893456000))
        self.assertIn('until=2030-01-01T00:00:00Z', data.format_entry(*result[1]))
        for invalid in ('not-an-ip', '198.51.100.7 0', '198.51.100.7 23-22', '198.51.100.7 22001;flush'):
            with self.assertRaises(ValueError):
                data.entries(invalid)

    def test_edit_replaces_scope_expiry_and_remove_clears_all_scopes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'blocklist.conf'
            data.edit_list(path, 'block', 'add', '198.51.100.7', '*', 0)
            data.edit_list(path, 'block', 'add', '198.51.100.7', '22001', 1893456000)
            self.assertEqual(len(data.entries(path.read_text())), 2)
            data.edit_list(path, 'block', 'add', '198.51.100.7', '22001', 0)
            self.assertNotIn('until=', path.read_text())
            data.edit_list(path, 'block', 'remove', '198.51.100.7')
            self.assertEqual(data.entries(path.read_text()), [])

    def test_home_migration_preserves_accepted_state_and_custom_timer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in ('etc', 'state/lists', 'units', 'home'):
                (root / directory).mkdir(parents=True)
            (root / 'etc/settings.conf').write_text('PROTECTED_PORTS="22001"\nBAN_TIMEOUT=3h\n')
            (root / 'state/applied.conf').write_text('accepted sentinel\n')
            (root / 'state/lists/blocklist.conf').write_text('198.51.100.7\n')
            (root / 'units/custom.timer').write_text('OnUnitActiveSec=17min\n')
            account = types.SimpleNamespace(pw_dir=str(root / 'home'), pw_uid=os.geteuid(), pw_gid=os.getegid())
            with mock.patch.object(data.pwd, 'getpwnam', return_value=account):
                directory = data.migrate(root / 'etc', root / 'state', root / 'units', 'example')
            self.assertEqual((directory / 'settings.conf').read_bytes(), (root / 'etc/settings.conf').read_bytes())
            self.assertEqual((directory / 'blocklist.conf').read_text(), '198.51.100.7\n')
            self.assertEqual((root / 'state/applied.conf').read_text(), 'accepted sentinel\n')
            self.assertEqual((root / 'units/custom.timer').read_text(), 'OnUnitActiveSec=17min\n')
            self.assertEqual((directory / 'settings.conf').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
