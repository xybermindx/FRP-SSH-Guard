"""Local SSH outcome detection using invented identities and documentation IPs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('auth_guard', ROOT / 'bin/frp-ssh-guard-auth.py')
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)
POLICY = dict(PROTECT_SERVER_SSH='on', JAIL_PER_PORT='off', GUARD_TABLE='test_guard',
              BAN_TIMEOUT='6h', SSH_AUTH_FAILURES='5', SSH_INVALID_USER_FAILURES='3', SSH_AUTH_WINDOW='10m')


def event(message, index=1, stamp=1700000000, **extra):
    return dict(_UID='0', SYSLOG_IDENTIFIER='sshd', _PID=str(index), MESSAGE=message,
                __CURSOR='cursor-' + str(index), __REALTIME_TIMESTAMP=str(stamp * 1000000), **extra)


class AuthTests(unittest.TestCase):
    def test_whitelisted_native_source_is_not_added_to_auth_jail(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {'GUARD_LOCK_FILE': str(Path(tmp) / 'lock')}), \
             mock.patch.object(auth, 'load_policy', return_value=POLICY), \
             mock.patch.object(auth.lists, 'allowed', return_value=True), \
             mock.patch.object(auth.subprocess, 'run') as run:
            self.assertIsNone(auth.ban('198.51.100.7'))
            run.assert_not_called()

    def test_trusted_learning_covers_pam_and_new_sshd_identifiers(self):
        spec = importlib.util.spec_from_file_location('learning', ROOT / 'bin/frp-ssh-guard-learn.py')
        learner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(learner)
        for method in ('password', 'publickey', 'keyboard-interactive/pam'):
            for identity in ('sshd', 'sshd-session', 'sshd-auth'):
                record = event(f'Accepted {method} for alice from 198.51.100.7 port 45001 ssh2')
                record['SYSLOG_IDENTIFIER'] = identity
                users = lambda pattern: dict(LOGIN_USERS=pattern, LEARN_ADMINS='off', CONFIG_BASE='/nonexistent')
                self.assertEqual(learner.accepted(record, users('alice|bob')), ('198.51.100.7', 1700000000))
                self.assertIsNone(learner.accepted({**record, '_UID': '1001'}, users('alice')))
                self.assertIsNone(learner.accepted(record, users('bob')))
                self.assertIsNone(learner.accepted(record, users('')))

    def test_invalid_user_double_log_is_one_attempt(self):
        tracker = auth.Tracker(POLICY)
        first = event('Invalid user missing-example-user from 198.51.100.7 port 45001')
        duplicate = {**first, 'MESSAGE': 'Failed password for invalid user missing-example-user from 198.51.100.7 port 45001 ssh2', '__CURSOR': 'cursor-duplicate'}
        self.assertIsNone(tracker.process(first, 1700000000))
        self.assertIsNone(tracker.process(duplicate, 1700000000))
        self.assertEqual(len(tracker.state['attempts']['198.51.100.7']), 1)
        for index in (2, 3):
            result = tracker.process(event('Invalid user missing-example-user from 198.51.100.7 port 45002', index), 1700000000)
        self.assertEqual(result, '198.51.100.7')

    def test_success_clears_failures_and_restart_does_not_replay(self):
        tracker = auth.Tracker(POLICY)
        failed = event('Failed password for alice from 198.51.100.7 port 45001 ssh2')
        self.assertIsNone(tracker.process(failed, 1700000000))
        tracker = auth.Tracker(POLICY, json.loads(json.dumps(tracker.state)))
        self.assertIsNone(tracker.process(failed, 1700000000))
        self.assertEqual(len(tracker.state['attempts']['198.51.100.7']), 1)
        tracker.process(event('Accepted publickey for alice from 198.51.100.7 port 45001 ssh2: ED25519 example', 2), 1700000000)
        self.assertNotIn('198.51.100.7', tracker.state['attempts'])

    def test_repeated_failures_ipv6_and_expiration(self):
        tracker = auth.Tracker(POLICY)
        for index in range(1, 6):
            result = tracker.process(event('Failed password for alice from 2001:db8::7 port 45001 ssh2', index), 1700000000)
        self.assertEqual(result, '2001:db8::7')
        stale = event('Invalid user missing-example-user from 198.51.100.7 port 45001', 9, 1699990000)
        self.assertIsNone(tracker.process(stale, 1700000000))

    def test_untrusted_and_unrelated_records_do_not_count(self):
        record = event('Invalid user missing-example-user from 198.51.100.7 port 45001')
        for changed in ({'_UID': '1001'}, {'SYSLOG_IDENTIFIER': 'other'},
                        {'MESSAGE': 'Failed none for alice from 198.51.100.7 port 45001 ssh2'},
                        {'MESSAGE': 'Connection closed by invalid user missing-example-user 198.51.100.7 port 45001 [preauth]'},
                        {'MESSAGE': 'Failed password for alice from invalid-address port 45001 ssh2'},
                        {'MESSAGE': 'Invalid user missing-example-user from 127.0.0.1 port 45001'}):
            self.assertIsNone(auth.parse_event({**record, **changed}))

    def test_auth_ban_uses_configured_scope(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {'GUARD_LOCK_FILE': str(Path(tmp) / 'lock')}):
            for mode, expected in (('off', '{ 198.51.100.7 timeout 6h }'), ('on', '{ 198.51.100.7 . 22 timeout 6h }')):
                with mock.patch.object(auth.lists, 'allowed', return_value=False), \
                        mock.patch.object(auth.lists, 'sync'), \
                        mock.patch.object(auth, 'load_policy', return_value={**POLICY, 'JAIL_PER_PORT': mode}), \
                        mock.patch.object(auth.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                    self.assertTrue(auth.ban('198.51.100.7'))
                    self.assertEqual(run.call_args.args[0][-1], expected)


if __name__ == '__main__':
    unittest.main()
