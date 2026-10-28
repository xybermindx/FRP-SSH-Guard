"""Configuration upgrades retain user values and never apply a firewall policy."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_inputs import ROOT, data

TEMPLATE = (ROOT / 'etc/settings.conf.example').read_text()


class ConfigUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'settings.conf'

    def upgrade(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return data.append_defaults(self.path, TEMPLATE)

    def test_missing_switches_follow_ports_and_preserve_comments_backup_metadata(self):
        original = (b'# My custom settings\r\nPROTECTED_PORTS="22001,22003"\r\n'
                    b'EXCLUDE_PORTS="22003" # keep this\r\n\r\n'
                    b'# My limit\r\nPER_IP_RATE=9\r\nBAN_TIMEOUT=43m')
        self.path.write_bytes(original)
        self.path.chmod(0o640)
        before = self.path.stat()
        keys = self.upgrade()
        content = self.path.read_bytes()
        self.assertIn('PROTECT_SERVER_SSH', keys)
        self.assertIn('JAIL_PER_PORT', keys)
        self.assertLess(content.index(b'EXCLUDE_PORTS='), content.index(b'PROTECT_SERVER_SSH=off'))
        self.assertLess(content.index(b'PROTECT_SERVER_SSH=off'), content.index(b'JAIL_PER_PORT=off'))
        self.assertLess(content.index(b'JAIL_PER_PORT=off'), content.index(b'PER_IP_RATE=9'))
        for line in original.splitlines(keepends=True):
            self.assertIn(line, content)
        after = self.path.stat()
        self.assertEqual((after.st_uid, after.st_gid, after.st_mode), (before.st_uid, before.st_gid, before.st_mode))
        backups = list(self.root.glob('settings.conf.before-upgrade-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.upgrade(), [])
        self.assertEqual(self.path.read_bytes(), content)
        self.assertEqual(self.path.stat().st_mtime_ns, after.st_mtime_ns)
        self.assertEqual(self.path.stat().st_ino, after.st_ino)
        self.assertEqual(list(self.root.glob('settings.conf.before-upgrade-*')), backups)

    def test_custom_switches_duplicate_assignments_and_empty_values_are_preserved(self):
        original = ('PROTECTED_PORTS=""\n# deliberate settings\n'
                    'export PROTECT_SERVER_SSH = "on" # keep enabled\nJAIL_PER_PORT=on\n'
                    'PER_IP_RATE=2\nPER_IP_RATE=9\nEXCLUDE_PORTS=""\n'
                    'SSH_AUTH_FAILURES=11\nLOGIN_USERS="$(id)"\n')
        self.path.write_text(original)
        self.upgrade()
        updated = self.path.read_text()
        lines = updated.splitlines()
        for line in original.splitlines():
            self.assertIn(line, lines)
        self.assertNotIn('PROTECT_SERVER_SSH=off', lines)
        self.assertNotIn('JAIL_PER_PORT=off', lines)
        # The new switch sits directly below the existing jail switch.
        between = lines[lines.index('JAIL_PER_PORT=on') + 1:lines.index('SSH_SLOW_PROTECTION=off')]
        self.assertTrue(between and all(not line or line.startswith('#') for line in between), between)
        self.assertLess(lines.index('SSH_SLOW_PROTECTION=off'), lines.index('PER_IP_RATE=2'))
        values = data.settings(updated)
        for key, value in data.settings(original).items():
            self.assertEqual(values[key], value)

    def test_missing_protected_ports_never_shadow_legacy_port_file(self):
        self.path = self.root / 'guard.conf'
        self.path.write_text('BAN_TIMEOUT=3h\n')
        (self.root / 'ports.conf').write_text('22001\n')
        self.upgrade()
        self.assertNotIn('PROTECTED_PORTS', data.settings(self.path.read_text()))
        self.assertEqual((self.root / 'ports.conf').read_text(), '22001\n')
        self.assertEqual(data.settings(self.path.read_text())['PROTECT_SERVER_SSH'], 'off')

    def test_slow_mode_becomes_one_switch_below_jail_switch(self):
        self.assertEqual(data.settings(TEMPLATE)['SSH_SLOW_PROTECTION'], 'on')
        self.assertNotIn('SSH_SLOW_MODE', data.settings(TEMPLATE))
        # Only explicit enforcement stays on; an upgrade never adds bans by itself.
        for mode, expected in (('enforce', 'on'), ('observe', 'off'), ('off', 'off'), (None, 'off')):
            with self.subTest(mode=mode):
                original = 'PROTECTED_PORTS="22001"\nJAIL_PER_PORT=on\nPER_IP_RATE=9\n'
                if mode is not None:
                    original += '# my note\nSSH_SLOW_MODE=' + mode + ' # operator choice\n'
                updated, keys = data.merge_defaults(original, TEMPLATE)
                values = data.settings(updated)
                lines = updated.splitlines()
                self.assertEqual(values['SSH_SLOW_PROTECTION'], expected)
                self.assertNotIn('SSH_SLOW_MODE', values)
                between = lines[lines.index('JAIL_PER_PORT=on') + 1:lines.index('SSH_SLOW_PROTECTION=' + expected)]
                self.assertTrue(all(not line or line.startswith('#') for line in between), between)
                if mode is not None:
                    self.assertIn('SSH_SLOW_MODE', keys)
                    self.assertIn('# my note', lines)  # user comments are kept
                    self.assertIn('# SSH_SLOW_MODE=' + mode + ' # operator choice', lines)
                self.assertEqual(values['PER_IP_RATE'], '9')
                self.assertEqual(data.merge_defaults(updated, TEMPLATE), (updated, []))
        self.assertEqual(data.merge_defaults(TEMPLATE, TEMPLATE), (TEMPLATE, []))

    def test_shipped_comments_header_and_renamed_log_size_are_replaced(self):
        for variant in data.LEGACY_SLOW_COMMENTS:
            with self.subTest(variant=variant[0]):
                original = ('# FRP-SSH-Guard settings (literal KEY=value assignments; no shell execution).\n'
                            + ''.join(line + '\n' for line in data.LEGACY_SETTINGS_HEADER)
                            + '\nPROTECTED_PORTS="22001"\nPROTECT_SERVER_SSH=on\nJAIL_PER_PORT=off\n\n'
                            + ''.join(line + '\n' for line in variant)
                            + 'SSH_SLOW_MODE=enforce\nSSH_SLOW_FAILURES=20\nSSH_SLOW_WINDOW=24h\n\n'
                            + ''.join(line + '\n' for line in data.LEGACY_RENAMED_COMMENTS['ALERT_LOG_MAX_SIZE'][0])
                            + 'ALERT_LOG_MAX_SIZE=2MiB\n')
                updated, keys = data.merge_defaults(original, TEMPLATE)
                values = data.settings(updated)
                self.assertEqual(values['SSH_SLOW_PROTECTION'], 'on')
                self.assertEqual(values['LOG_MAX_SIZE'], '2MiB')
                self.assertNotIn('ALERT_LOG_MAX_SIZE', values)
                for line in (data.LEGACY_SETTINGS_HEADER + variant
                             + data.LEGACY_RENAMED_COMMENTS['ALERT_LOG_MAX_SIZE'][0]):
                    self.assertNotIn(line, updated.splitlines())
                self.assertIn('# === When and how changes take effect ===', updated)
                lines = updated.splitlines()
                # New thresholds join the existing slow settings, not the end of the file.
                self.assertLess(lines.index('SSH_SLOW_TOTAL_CONNECTIONS=300'), lines.index('SSH_SLOW_FAILURES=20'))
                self.assertEqual(lines.index('SSH_SLOW_PORT_CONNECTIONS=100') + 1, lines.index('SSH_SLOW_FAILURES=20'))
                self.assertIn('instructions', keys)
                self.assertEqual(data.merge_defaults(updated, TEMPLATE), (updated, []))

    def test_admin_learning_is_added_above_login_users_and_shipped_comment_refreshed(self):
        self.assertEqual(data.settings(TEMPLATE)['LEARN_ADMINS'], 'on')
        original = ('PROTECTED_PORTS="22001"\nBAN_TIMEOUT=6h\n\n'
                    + ''.join(line + '\n' for line in data.REFRESHED_COMMENTS['LOGIN_USERS'][0])
                    + 'LOGIN_USERS="alice"\nMAX_LEARNED=500\n')
        updated, keys = data.merge_defaults(original, TEMPLATE)
        lines = updated.splitlines()
        self.assertEqual(data.settings(updated)['LEARN_ADMINS'], 'on')
        self.assertEqual(data.settings(updated)['LOGIN_USERS'], 'alice')
        self.assertLess(lines.index('LEARN_ADMINS=on'), lines.index('LOGIN_USERS="alice"'))
        self.assertLess(lines.index('BAN_TIMEOUT=6h'), lines.index('LEARN_ADMINS=on'))
        for line in data.REFRESHED_COMMENTS['LOGIN_USERS'][0]:
            self.assertNotIn(line, lines)
        self.assertEqual(data.merge_defaults(updated, TEMPLATE), (updated, []))
        custom = 'PROTECTED_PORTS="22001"\n# my admins\nLOGIN_USERS="alice"\n'
        kept = data.merge_defaults(custom, TEMPLATE)[0].splitlines()
        self.assertEqual(kept.index('# my admins') + 1, kept.index('LOGIN_USERS="alice"'))
        self.assertLess(kept.index('LEARN_ADMINS=on'), kept.index('# my admins'))

    def test_shipped_ban_and_strike_comments_refresh_but_values_stay(self):
        old = subprocess.run(['git', 'show', '13d2e8e:etc/settings.conf.example'], cwd=ROOT,
                             capture_output=True, text=True)
        if old.returncode:
            self.skipTest('needs the v0.0.6 template from git history')
        updated, keys = data.merge_defaults(old.stdout, TEMPLATE)
        values = data.settings(updated)
        for key, value in (('BAN_TIMEOUT', '6h'), ('STRIKE_LADDER', '2:1d 3:3d 4:7d 5:28d'), ('STRIKE_MAX', '28d')):
            self.assertEqual(values[key], value)  # an upgrade never changes chosen durations
        for blocks in (data.REFRESHED_COMMENTS[k] for k in ('BAN_TIMEOUT', 'STRIKE_WINDOW', 'STRIKE_LADDER', 'STRIKE_MAX')):
            for line in blocks[-1]:
                if line not in TEMPLATE.splitlines():
                    self.assertNotIn(line, updated.splitlines())
        self.assertIn('# source\'s previous ban ENDED moves one step up STRIKE_LADDER, and a source at the',
                      updated.splitlines())
        self.assertEqual(data.merge_defaults(updated, TEMPLATE), (updated, []))

    def test_upgrade_message_explains_how_to_enable_off_switch(self):
        self.path.write_text('PROTECTED_PORTS="22001"\nJAIL_PER_PORT=off\nSSH_SLOW_MODE=observe\n')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            data.append_defaults(self.path, TEMPLATE)
        self.assertIn('replaced obsolete SSH_SLOW_MODE with SSH_SLOW_PROTECTION=off', output.getvalue())
        self.assertIn('set SSH_SLOW_PROTECTION=on, then run: sudo frp-ssh-guard check && sudo frp-ssh-guard reload',
                      output.getvalue())

    def test_invalid_input_and_unsafe_file_types_are_unchanged(self):
        for kind in ('invalid', 'symlink', 'hardlink', 'fifo', 'directory'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'settings.conf'
                target = Path(tmp) / 'target'
                target.write_text('BAN_TIMEOUT=3h\n')
                if kind == 'invalid':
                    path.write_text('PER_IP_RATE=2; echo unsafe\n')
                elif kind == 'symlink':
                    path.symlink_to(target)
                elif kind == 'hardlink':
                    os.link(target, path)
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    path.mkdir()
                with self.assertRaises((OSError, ValueError)):
                    data.append_defaults(path, TEMPLATE)
                self.assertEqual(target.read_text(), 'BAN_TIMEOUT=3h\n')
                self.assertEqual(list(Path(tmp).glob('*.before-upgrade-*')), [])

    def test_concurrent_edit_or_replace_failure_keeps_original_or_new_user_edit(self):
        original = b'BAN_TIMEOUT=3h\n'
        self.path.write_bytes(original)
        with mock.patch.object(data.os, 'replace', side_effect=OSError('test replacement failure')):
            with self.assertRaises(OSError):
                self.upgrade()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.root.glob('.guard-*')), [])
        mkstemp = tempfile.mkstemp

        def edit_during_backup(*args, **kwargs):
            if kwargs.get('prefix', '').startswith('settings.conf.before-upgrade-'):
                self.path.write_bytes(b'BAN_TIMEOUT=7h\n')
            return mkstemp(*args, **kwargs)

        with mock.patch.object(data.tempfile, 'mkstemp', side_effect=edit_during_backup):
            with self.assertRaises(ValueError):
                self.upgrade()
        self.assertEqual(self.path.read_bytes(), b'BAN_TIMEOUT=7h\n')
        self.assertEqual(list(self.root.glob('.guard-*')), [])

    def test_registered_owner_handles_home_update_instead_of_installer(self):
        directory = self.root / 'home/.frp-ssh-guard'
        directory.mkdir(parents=True)
        self.path.write_text('BAN_TIMEOUT=3h\n')
        (self.root / 'user-home.json').write_text(json.dumps({'user': 'operator', 'directory': str(directory)}))
        with mock.patch.dict(os.environ, {'GUARD_LOCK_FILE': str(self.root / 'lock')}), \
             mock.patch.object(data, 'as_user') as run:
            data.upgrade_settings(self.root, ROOT / 'etc/settings.conf.example')
        run.assert_called_once_with('operator', ['upgrade-user-settings'],
                                    [str(directory / 'settings.conf'), TEMPLATE])
        self.assertEqual(self.path.read_text(), 'BAN_TIMEOUT=3h\n')

    def test_unavailable_home_leaves_system_copy_untouched_and_install_can_finish(self):
        self.path.write_text('BAN_TIMEOUT=3h\n')
        (self.root / 'user-home.json').write_text(json.dumps(
            {'user': data.pwd.getpwuid(os.geteuid()).pw_name,
             'directory': str(self.root / 'missing/.frp-ssh-guard')}))
        result = subprocess.run(['python3', str(ROOT / 'bin/frp-ssh-guard-input.py'),
                                 'upgrade-settings', str(self.root), str(ROOT / 'etc/settings.conf.example')],
                                env={**os.environ, 'GUARD_LOCK_FILE': str(self.root / 'lock')},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('existing configuration and active policy were retained', result.stderr)
        self.assertEqual(self.path.read_text(), 'BAN_TIMEOUT=3h\n')
        self.assertEqual(list(self.root.glob('*.before-upgrade-*')), [])


if __name__ == '__main__':
    unittest.main()
