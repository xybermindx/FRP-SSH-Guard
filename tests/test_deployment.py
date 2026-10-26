"""Deployment behavior using the real shell functions and isolated command fakes."""
import os
import json
import time
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from test_guard import LIBRARY, ROOT, SCRIPT

DISPATCH = SCRIPT.split('# ---------- main dispatch ----------', 1)[1]


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('etc', 'lists', 'logs', 'fakebin'):
            (self.root / directory).mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GUARD_')}
        self.env.update(GUARD_DIR=str(self.root), GUARD_LOCK_FILE=str(self.root / 'lock'),
                        GUARD_UNIT_FILE=str(self.root / 'unit'), GUARD_PACKAGED='1',
                        TMPDIR=str(self.root), TEST_ROOT=str(self.root),
                        GUARD_TRIAL_PENDING=str(self.root / 'trial.pending'))
        self.env['PATH'] = str(self.root / 'fakebin') + ':' + self.env['PATH']
        (self.root / 'unit').write_text('# Managed by frp-ssh-guard-persistent.sh\n')
        self.fake('nft', '''#!/bin/bash
case "$1" in
 -j) echo '{"nftables":[{"rule":{"comment":"manual-block v4","handle":42}}]}' ;;
 list) test -f "$TEST_ROOT/live.nft" ;;
 --check) test ! -f "$TEST_ROOT/fail-check" ;;
 --file)
   test ! -f "$TEST_ROOT/fail-apply" || exit 1
   if grep -q '^table inet ' "$2"; then cp "$2" "$TEST_ROOT/live.nft";
   else cat "$2" >> "$TEST_ROOT/live.nft"; fi ;;
 delete) rm -f "$TEST_ROOT/live.nft" ;;
 *) exit 0 ;;
esac
''')
        self.fake('ss', '''#!/bin/bash
if [[ -e "$TEST_ROOT/non-frps" ]]; then echo 'LISTEN users:(("sshd",pid=1,fd=1))';
elif [[ ! -e "$TEST_ROOT/no-listener" ]]; then echo 'LISTEN users:(("frps",pid=1,fd=1))'; fi
''')
        self.fake('systemctl', '''#!/bin/bash
printf '%s\n' "$*" >> "$TEST_ROOT/systemctl.calls"
case "$1" in
 is-active) test -f "$TEST_ROOT/service-active" ;;
 is-enabled) test -f "$TEST_ROOT/service-enabled" ;;
 start) touch "$TEST_ROOT/service-active" ;;
 restart) test ! -f "$TEST_ROOT/fail-helper" ;;
 enable) test ! -f "$TEST_ROOT/fail-enable" && touch "$TEST_ROOT/service-enabled" ;;
 disable) rm -f "$TEST_ROOT/service-active" "$TEST_ROOT/service-enabled" ;;
 *) exit 0 ;;
esac
''')
        self.fake('systemd-run', '''#!/bin/bash
test ! -f "$TEST_ROOT/fail-trial" || exit 1
touch "$TEST_ROOT/trial-scheduled"
''')
        self.fake('install', '''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args=sys.argv[1:]; paths=[]; directory=False; mode=0o755
while args:
    a=args.pop(0)
    if a in ('-o','-g'): args.pop(0)
    elif a=='-m': mode=int(args.pop(0),8)
    elif a=='-d': directory=True
    elif a=='--': continue
    else: paths.append(a)
if directory:
    for p in paths: pathlib.Path(p).mkdir(parents=True,exist_ok=True)
else:
    shutil.copyfile(*paths); os.chmod(paths[-1],mode)
''')
        self.settings('PROTECTED_PORTS="22001"\n')

    def fake(self, name, content):
        path = self.root / 'fakebin' / name
        path.write_text(content)
        path.chmod(0o755)

    def settings(self, content):
        (self.root / 'etc/settings.conf').write_text(content)

    def run_guard(self, action, *args):
        # Skip only the root CLI gate; dispatch, locking, validation, commit,
        # rollback, and runtime selection are the actual production functions.
        body = (LIBRARY + '\naction=' + shlex.quote(action) + '\n'
                'case "$action" in enable) action=install;; disable) action=remove;; esac\n'
                'NFTP=$(command -v nft)\n' + DISPATCH)
        harness = self.root / 'dispatch.sh'
        harness.write_text(body)
        return subprocess.run(['bash', str(harness), action, *args],
                              env=self.env, text=True, capture_output=True)

    def require_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_enable_accepts_single_file_and_refreshes_helpers(self):
        self.require_ok(self.run_guard('enable'))
        self.assertTrue((self.root / 'service-enabled').exists())
        self.assertIn('22001', (self.root / 'live.nft').read_text())
        calls = (self.root / 'systemctl.calls').read_text()
        self.assertIn('restart frp-ssh-guard-learn.service', calls)
        self.assertIn('PROTECTED_PORTS=22001:30:20', (self.root / 'applied.conf').read_text())

    def test_check_has_no_activation_side_effects(self):
        self.require_ok(self.run_guard('check'))
        self.assertFalse((self.root / 'live.nft').exists())
        self.assertFalse((self.root / 'applied.conf').exists())
        self.assertFalse((self.root / 'service-enabled').exists())

    def test_upgrade_uses_accepted_policy_and_refreshes_monitors(self):
        self.require_ok(self.run_guard('enable'))
        accepted = (self.root / 'applied.conf').read_text()
        # Simulate a previously accepted pre-observation policy and broken edits.
        (self.root / 'applied.conf').write_text(accepted.replace('OBSERVABILITY_VERSION=1', 'OBSERVABILITY_VERSION=0'))
        self.settings('PROTECTED_PORTS="22003"\nPER_IP_RATE=invalid\n')
        (self.root / 'no-listener').touch()
        (self.root / 'systemctl.calls').write_text('')
        self.require_ok(self.run_guard('_upgrade'))
        self.assertEqual((self.root / 'applied.conf').read_text(), accepted)
        self.assertIn('tcp dport 22001 ', (self.root / 'live.nft').read_text())
        self.assertNotIn('tcp dport 22003 ', (self.root / 'live.nft').read_text())
        self.assertIn('PER_IP_RATE=invalid', (self.root / 'etc/settings.conf').read_text())
        calls = (self.root / 'systemctl.calls').read_text()
        self.assertIn('restart frp-ssh-guard-auth.service', calls)
        self.assertIn('restart frp-ssh-guard-learn.service', calls)
        self.assertNotIn('daemon-reload', calls)
        self.assertNotIn('restart frp-ssh-guard.service', calls)
        self.assertNotIn('enable ', calls)
        self.assertNotIn('.timer', calls)

    def test_upgrade_does_not_activate_fresh_or_disabled_installations(self):
        self.require_ok(self.run_guard('_upgrade'))
        self.assertFalse((self.root / 'applied.conf').exists())
        self.require_ok(self.run_guard('enable'))
        self.require_ok(self.run_guard('disable'))
        self.require_ok(self.run_guard('_upgrade'))
        self.assertFalse((self.root / 'live.nft').exists())
        self.assertFalse((self.root / 'service-enabled').exists())

    def test_upgrade_preserves_trial_without_enabling_boot(self):
        self.require_ok(self.run_guard('trial'))
        (self.root / 'systemctl.calls').write_text('')
        self.require_ok(self.run_guard('_upgrade'))
        self.assertTrue((self.root / 'trial.pending').exists())
        self.assertFalse((self.root / 'service-enabled').exists())
        self.assertNotIn('enable ', (self.root / 'systemctl.calls').read_text())
        self.assertNotIn('stop ', (self.root / 'systemctl.calls').read_text())

    def test_upgrade_failure_keeps_previous_rules_and_policy(self):
        self.require_ok(self.run_guard('enable'))
        previous = (self.root / 'applied.conf').read_bytes()
        rules = (self.root / 'live.nft').read_bytes()
        for failure in ('fail-check', 'fail-apply'):
            with self.subTest(failure=failure):
                (self.root / failure).touch()
                (self.root / 'systemctl.calls').write_text('')
                result = self.run_guard('_upgrade')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.root / 'applied.conf').read_bytes(), previous)
                self.assertEqual((self.root / 'live.nft').read_bytes(), rules)
                self.assertNotIn('restart ', (self.root / 'systemctl.calls').read_text())
                (self.root / failure).unlink()

    def test_upgrade_helper_failure_is_reported(self):
        self.require_ok(self.run_guard('enable'))
        (self.root / 'fail-helper').touch()
        result = self.run_guard('_upgrade')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Updated rules active', result.stderr)
        self.assertTrue((self.root / 'live.nft').exists())

    def test_pending_settings_do_not_leak_through_apply_or_allow(self):
        self.require_ok(self.run_guard('enable'))
        self.settings('PROTECTED_PORTS="22003"\nPER_IP_RATE=8\n')
        self.require_ok(self.run_guard('apply'))
        self.require_ok(self.run_guard('allow', '198.51.100.1'))
        rules = (self.root / 'live.nft').read_text()
        self.assertIn('tcp dport 22001 ', rules)
        self.assertNotIn('tcp dport 22003 ', rules)
        self.assertIn('limit rate over 2/minute', rules)
        status = self.run_guard('status')
        self.require_ok(status)
        self.assertIn('Pending edits: yes', status.stdout)
        self.require_ok(self.run_guard('reload'))
        self.assertIn('tcp dport 22003 ', (self.root / 'live.nft').read_text())
        self.assertIn('Pending edits: no', self.run_guard('status').stdout)

    def test_invalid_reload_and_nft_failure_retain_previous_policy(self):
        self.require_ok(self.run_guard('enable'))
        accepted = (self.root / 'applied.conf').read_bytes()
        rules = (self.root / 'live.nft').read_bytes()
        for content in ('PROTECTED_PORTS="0"\n', 'PROTECTED_PORTS="22003"\nPER_IP_RATE=oops\n',
                        'PROTECTED_PORTS="unterminated\n'):
            self.settings(content)
            self.assertNotEqual(self.run_guard('reload').returncode, 0)
            self.assertEqual((self.root / 'applied.conf').read_bytes(), accepted)
            self.assertEqual((self.root / 'live.nft').read_bytes(), rules)
        self.settings('PROTECTED_PORTS="22003"\n')
        (self.root / 'fail-apply').touch()
        failed = self.run_guard('reload')
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('previous accepted settings', failed.stderr)
        self.assertEqual((self.root / 'applied.conf').read_bytes(), accepted)
        self.assertEqual((self.root / 'live.nft').read_bytes(), rules)

    def test_disable_with_broken_pending_settings(self):
        self.require_ok(self.run_guard('install'))
        self.settings('PROTECTED_PORTS="unterminated\n')
        self.require_ok(self.run_guard('disable'))
        self.assertFalse((self.root / 'live.nft').exists())
        self.assertFalse((self.root / 'service-enabled').exists())
        self.assertTrue((self.root / 'applied.conf').exists())

    def test_table_change_requires_disable(self):
        self.require_ok(self.run_guard('enable'))
        self.settings('PROTECTED_PORTS="22001"\nGUARD_TABLE=another_guard\n')
        failed = self.run_guard('reload')
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('cannot change while active', failed.stderr)
        self.require_ok(self.run_guard('disable'))
        self.require_ok(self.run_guard('enable'))
        self.assertIn('table inet another_guard', (self.root / 'live.nft').read_text())

    def test_recovery_uses_accepted_settings_without_listener(self):
        self.require_ok(self.run_guard('enable'))
        (self.root / 'live.nft').unlink()
        self.settings('PROTECTED_PORTS="broken')
        (self.root / 'no-listener').touch()
        self.require_ok(self.run_guard('apply'))
        self.assertIn('tcp dport 22001 ', (self.root / 'live.nft').read_text())

    def test_explicit_empty_ports_do_not_fall_back(self):
        (self.root / 'etc/ports.conf').write_text('22001\n')
        self.settings('PROTECTED_PORTS=""\n')
        self.assertNotEqual(self.run_guard('check').returncode, 0)

    def test_legacy_configuration_and_explicit_file_override(self):
        (self.root / 'etc/settings.conf').unlink()
        (self.root / 'etc/guard.conf').write_text('PER_IP_RATE=9\n')
        (self.root / 'etc/ports.conf').write_text('22003\n')
        self.require_ok(self.run_guard('enable'))
        self.assertIn('tcp dport 22003 ', (self.root / 'live.nft').read_text())
        self.assertIn('rate over 9/minute', (self.root / 'live.nft').read_text())
        override = self.root / 'override.conf'
        override.write_text('22004:50:60\n')
        self.require_ok(self.run_guard('install', str(override)))
        self.assertIn('tcp dport 22004 ', (self.root / 'live.nft').read_text())
        self.assertEqual((self.root / 'etc/ports.conf').read_text(), '22003\n')
        self.assertIn('Pending edits: yes', self.run_guard('status').stdout)

    def test_legacy_boot_freezes_policy_without_live_listener(self):
        (self.root / 'etc/settings.conf').unlink()
        (self.root / 'etc/guard.conf').write_text('PER_IP_RATE=9\n')
        (self.root / 'etc/ports.conf').write_text('22003\n')
        (self.root / 'no-listener').touch()
        self.require_ok(self.run_guard('apply'))
        self.assertTrue((self.root / 'applied.conf').exists())

    def test_listener_rejection(self):
        for marker in ('no-listener', 'non-frps'):
            path = self.root / marker
            path.touch()
            self.assertNotEqual(self.run_guard('check').returncode, 0)
            self.assertFalse((self.root / 'live.nft').exists())
            path.unlink()

    def test_help_ignores_invalid_configuration(self):
        self.settings('PROTECTED_PORTS="unterminated\n')
        for option in ('--help', '-h', 'help'):
            result = subprocess.run(['bash', str(ROOT / 'bin/frp-ssh-guard-persistent.sh'), option],
                                    env=self.env, text=True, capture_output=True)
            self.require_ok(result)
            self.assertIn('enable', result.stdout)
            self.assertIn(str(self.root / 'etc/settings.conf'), result.stdout)

    def test_helper_failure_reports_partial_success(self):
        (self.root / 'fail-helper').touch()
        result = self.run_guard('enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Rules active, but learning-service refresh failed', result.stderr)
        self.assertTrue((self.root / 'live.nft').exists())

    def test_trial_keep_and_expiry(self):
        self.require_ok(self.run_guard('trial'))
        self.assertTrue((self.root / 'trial.pending').exists())
        self.assertFalse((self.root / 'service-enabled').exists())
        self.assertNotEqual(self.run_guard('reload').returncode, 0)
        self.require_ok(self.run_guard('keep'))
        self.assertFalse((self.root / 'trial.pending').exists())
        self.assertTrue((self.root / 'service-enabled').exists())
        self.require_ok(self.run_guard('disable'))
        self.require_ok(self.run_guard('trial'))
        self.require_ok(self.run_guard('_expire'))
        self.assertFalse((self.root / 'live.nft').exists())
        self.assertFalse((self.root / 'service-enabled').exists())

    def test_trial_scheduling_failure_never_applies_rules(self):
        (self.root / 'fail-trial').touch()
        self.assertNotEqual(self.run_guard('trial').returncode, 0)
        self.assertFalse((self.root / 'live.nft').exists())
        self.assertFalse((self.root / 'applied.conf').exists())
        self.assertFalse((self.root / 'trial.pending').exists())

    def test_failed_trial_application_cancels_pending_trial(self):
        (self.root / 'fail-apply').touch()
        self.assertNotEqual(self.run_guard('trial').returncode, 0)
        self.assertFalse((self.root / 'trial.pending').exists())
        self.assertFalse((self.root / 'applied.conf').exists())
        self.assertFalse((self.root / 'live.nft').exists())

    def test_policy_validation_names_invalid_setting(self):
        for key, value in [('BAN_TIMEOUT', 'forever'), ('MAX_LEARNED', '0'),
                           ('EXCLUDE_PORTS', '20-10'), ('PORT_MIN', '65536'),
                           ('STRIKE_LADDER', '3:1d 2:2d'), ('LOGIN_USERS', '['),
                           ('GUARD_TABLE', 'invalid-name')]:
            with self.subTest(key=key):
                self.settings('PROTECTED_PORTS="22001"\n' + key + '=' + shlex.quote(value) + '\n')
                result = self.run_guard('check')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)
                self.assertFalse((self.root / 'live.nft').exists())

    def test_fresh_invalid_settings_do_not_block_status_or_disable(self):
        self.settings('PROTECTED_PORTS="broken')
        self.require_ok(self.run_guard('status'))
        self.require_ok(self.run_guard('disable'))

    def test_boot_enable_failure_is_explicit(self):
        (self.root / 'fail-enable').touch()
        result = self.run_guard('enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('enabling reboot restoration failed', result.stderr)
        self.assertTrue((self.root / 'live.nft').exists())

    def test_learning_uses_accepted_settings_and_ignores_pending_edits(self):
        record = dict(_UID='0', SYSLOG_IDENTIFIER='sshd-auth', _PID='42', __CURSOR='sample',
                      __REALTIME_TIMESTAMP=str(int(time.time() * 1000000)),
                      MESSAGE='Accepted publickey for alice from 198.51.100.55 port 12345 ssh2')
        self.fake('journalctl', '#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(json.dumps(record)) + '\n')
        self.fake('guard-test-command', '#!/bin/sh\nexit 0\n')
        self.env['GUARD_COMMAND'] = str(self.root / 'fakebin/guard-test-command')
        self.fake('fail2ban-client', '#!/bin/sh\nexit 1\n')
        self.require_ok(self.run_guard('enable'))
        self.settings('PROTECTED_PORTS="22001"\nLOGIN_USERS="alice"\n')
        helper = ['bash', str(ROOT / 'bin/frp-ssh-guard-learn.sh')]
        self.require_ok(subprocess.run(helper, env=self.env, text=True, capture_output=True))
        self.assertEqual((self.root / 'lists/learned.conf').read_text(), '')
        self.require_ok(self.run_guard('reload'))
        self.settings('LOGIN_USERS="unterminated')
        record['__REALTIME_TIMESTAMP'] = str(int(time.time() * 1000000))
        self.fake('journalctl', '#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(json.dumps(record)) + '\n')
        result = subprocess.run(helper, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)  # closed journal stream requests restart
        self.assertIn('198.51.100.55 source=learned until=', (self.root / 'lists/whitelist.conf').read_text())

    def test_strike_helper_uses_accepted_policy_with_broken_edits(self):
        self.settings('PROTECTED_PORTS="22001"\nGUARD_TABLE=accepted_table\n')
        self.require_ok(self.run_guard('enable'))
        self.settings('GUARD_TABLE="unterminated')
        # Force the helper to use PATH rather than the installed nft executable.
        # The real policy-loading subprocess and strike implementation still run.
        import runpy
        from unittest import mock
        real_run = subprocess.run
        nft_calls = []
        def run_command(args, **kwargs):
            if args[0] == 'bash': return real_run(args, **kwargs)
            nft_calls.append(args)
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch('subprocess.run', side_effect=run_command):
            runpy.run_path(str(ROOT / 'bin/frp-ssh-guard-strike.py'))
        self.assertTrue(nft_calls)
        self.assertTrue(all('accepted_table' in args for args in nft_calls))

    def test_hardban_file_matches_strike_helper(self):
        (self.root / 'lists/hardban.conf').write_text('198.51.100.22\n')
        self.require_ok(self.run_guard('enable'))
        self.assertIn('hardban4 { 198.51.100.22', (self.root / 'live.nft').read_text())

    def test_native_ssh_is_opt_in_and_has_its_own_listener_validation(self):
        self.fake('ss', '''#!/bin/bash
if [[ "$*" == *":22" ]]; then echo 'LISTEN users:(("sshd",pid=1,fd=1))';
else echo 'LISTEN users:(("frps",pid=2,fd=1))'; fi
''')
        self.require_ok(self.run_guard('enable'))
        self.assertNotIn('tcp dport 22 ', (self.root / 'live.nft').read_text())
        self.settings('PROTECTED_PORTS="22001"\nPROTECT_SERVER_SSH=on\n')
        self.require_ok(self.run_guard('reload'))
        self.assertIn('tcp dport 22 ', (self.root / 'live.nft').read_text())
        self.settings('PROTECTED_PORTS=""\nPROTECT_SERVER_SSH=on\n')
        self.require_ok(self.run_guard('reload'))
        self.assertNotIn('tcp dport 22001 ', (self.root / 'live.nft').read_text())

    def test_manual_updates_leave_jail_sets_and_timer_units_untouched(self):
        self.require_ok(self.run_guard('enable'))
        (self.root / 'systemctl.calls').write_text('')
        self.require_ok(self.run_guard('block', '198.51.100.7', '--ports', '22001', '--for', '6h'))
        rules = (self.root / 'live.nft').read_text()
        update = rules[rules.index('flush set'):]
        self.assertNotIn('delete table', update)
        self.assertNotIn('flush set inet frp_ssh_persistent_guard ban', update)
        self.assertNotIn('hardban', update)
        self.assertIn('198.51.100.7 . 22001 timeout', update)
        self.assertIn('until=', (self.root / 'lists/blocklist.conf').read_text())
        self.assertEqual((self.root / 'systemctl.calls').read_text(), '')

    def test_per_port_jails_use_concatenated_keys(self):
        self.settings('PROTECTED_PORTS="22001,22003"\nJAIL_PER_PORT=on\n')
        self.require_ok(self.run_guard('enable'))
        rules = (self.root / 'live.nft').read_text()
        self.assertIn('set ban4     { type ipv4_addr . inet_service;', rules)
        self.assertIn('add @ban4 { ip saddr . tcp dport timeout', rules)
        self.assertIn('ip saddr . tcp dport @ban4', rules)

    def test_settings_command_substitution_is_never_executed(self):
        marker = self.root / 'must-not-exist'
        self.settings('PROTECTED_PORTS="22001"\nLOGIN_USERS="$(touch ' + str(marker) + ')"\n')
        self.run_guard('check')
        self.assertFalse(marker.exists())

    def test_version_is_available_without_root_or_valid_settings(self):
        self.settings('invalid data')
        result = subprocess.run(['bash', str(ROOT / 'bin/frp-ssh-guard-persistent.sh'), '--version'],
                                env=self.env, text=True, capture_output=True)
        self.require_ok(result)
        self.assertEqual(result.stdout.strip(), 'FRP-SSH-Guard ' + (ROOT / 'VERSION').read_text().strip())


if __name__ == '__main__':
    unittest.main()
