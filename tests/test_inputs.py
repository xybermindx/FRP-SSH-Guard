"""Editable home files are data, never privileged shell scripts."""
import importlib.util
import os
from pathlib import Path
import pwd
import tempfile
import types
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guard_data', ROOT / 'bin/frp-ssh-guard-input.py')
data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data)


class InputTests(unittest.TestCase):
    def test_installer_owner_uses_sudo_or_explicit_override_not_home(self):
        accounts = {name: types.SimpleNamespace(pw_name=name, pw_uid=uid)
                    for name, uid in [('root', 0), ('operator', 1001), ('alternate', 1002)]}
        with mock.patch.object(data.pwd, 'getpwnam', side_effect=accounts.__getitem__):
            with mock.patch.dict(os.environ, {'HOME': '/home/unrelated', 'USER': 'unrelated'}, clear=True):
                self.assertEqual(data.installer_user(), 'root')
            with mock.patch.dict(os.environ, {'SUDO_USER': 'operator', 'SUDO_UID': '1001'}, clear=True):
                self.assertEqual(data.installer_user(), 'operator')
            with mock.patch.dict(os.environ, {'FRP_GUARD_CONFIG_USER': 'alternate', 'SUDO_USER': 'operator',
                                             'SUDO_UID': '1001'}, clear=True):
                self.assertEqual(data.installer_user(), 'alternate')
            with mock.patch.dict(os.environ, {'SUDO_USER': 'operator', 'SUDO_UID': '1002'}, clear=True):
                with self.assertRaises(ValueError):
                    data.installer_user()

    def test_automatic_reinstall_keeps_registered_owner_even_with_home_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'user-home.json').write_text('{"user":"operator","directory":"/home/operator/.frp-ssh-guard"}')
            with mock.patch.dict(os.environ, {'GUARD_LOCK_FILE': str(root / 'lock')}), \
                 mock.patch.object(data, 'installer_user', side_effect=AssertionError('Do not select a new owner')), \
                 mock.patch.object(data, 'migrate', side_effect=AssertionError('Do not recopy existing files')):
                self.assertEqual(data.auto_home(root, root, root, '/usr/sbin/frp-ssh-guard'),
                                 Path('/home/operator/.frp-ssh-guard'))

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
            self.assertTrue(all(row.expiry == 0 for row in data.records(path.read_text())))
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

    def test_migration_conflict_and_watcher_failure_keep_system_configuration(self):
        for conflict in (True, False):
            with self.subTest(conflict=conflict), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for directory in ('etc', 'state/lists', 'units', 'home/.frp-ssh-guard'):
                    (root / directory).mkdir(parents=True)
                original = 'PROTECTED_PORTS=22001\nBAN_TIMEOUT=3h\n'
                (root / 'etc/settings.conf').write_text(original)
                home_settings = root / 'home/.frp-ssh-guard/settings.conf'
                if conflict:
                    home_settings.write_text('PROTECTED_PORTS=22003\n')
                account = types.SimpleNamespace(pw_dir=str(root / 'home'), pw_uid=os.geteuid(), pw_gid=os.getegid())
                with mock.patch.object(data.pwd, 'getpwnam', return_value=account), \
                     mock.patch.object(data, 'follow_home', side_effect=OSError('watcher unavailable')):
                    with self.assertRaises((subprocess.CalledProcessError, OSError)):
                        data.migrate(root / 'etc', root / 'state', root / 'units', 'example', '/usr/sbin/frp-ssh-guard')
                self.assertEqual((root / 'etc/settings.conf').read_text(), original)
                self.assertFalse((root / 'etc/user-home.json').exists())
                self.assertFalse((root / 'units/frp-ssh-guard-lists.path.d/50-user-home.conf').exists())
                if conflict:
                    self.assertEqual(home_settings.read_text(), 'PROTECTED_PORTS=22003\n')

    def test_active_home_watcher_uses_transient_path_without_reloading_timers(self):
        with mock.patch.object(data.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(data.follow_home(Path('/home/operator/.frp-ssh-guard'), Path('/var/lib/frp-ssh-guard'),
                                             '/usr/sbin/frp-ssh-guard'))
        command = run.call_args.args[0]
        self.assertEqual(command[0], 'systemd-run')
        self.assertIn('--path-property=PathModified=/home/operator/.frp-ssh-guard/blocklist.conf', command)
        self.assertIn('--path-property=PartOf=frp-ssh-guard.service', command)
        self.assertEqual(command[-2:], ['/usr/sbin/frp-ssh-guard', 'apply'])
        for call in run.call_args_list:
            self.assertFalse({'daemon-reload', 'restart', 'enable', 'nft'} & set(call.args[0]))

    def test_home_directory_symlink_is_rejected_without_writing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.mkdir()
            link = root / '.frp-ssh-guard'
            link.symlink_to(target, target_is_directory=True)
            result = subprocess.run(['python3', str(ROOT / 'bin/frp-ssh-guard-input.py'),
                                     'create-home', str(link)], input='{"settings.conf":"PROTECTED_PORTS=22001"}',
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
