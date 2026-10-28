"""Deterministic shared-event, alert, and accounting tests with invented data."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest import mock

from test_auth import auth, event

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('events', ROOT / 'bin/frp-ssh-guard-events.py')
events = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(events)
NOW = 1700000000


class EventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = events.data.settings((ROOT / 'etc/settings.conf.example').read_text())
        self.config.update(PROTECT_SERVER_SSH='on', CONFIG_BASE=str(self.root / 'etc'),
                           MANUAL_DIR=str(self.root / 'home'), OBSERVABILITY_VERSION='1')
        (self.root / 'home').mkdir()
        (self.root / 'etc').mkdir()
        self.store = events.Store(self.root / 'state', now=NOW)
        self.addCleanup(self.store.close)

    def failure(self, index, stamp=NOW, ip='198.51.100.7', invalid=False):
        prefix = 'Invalid user missing-example-user' if invalid else 'Failed password for alice'
        return event(f'{prefix} from {ip} port 45001', index, stamp)

    def process(self, record, now=None, trusted=False):
        return self.store.process(record, self.config, auth.parse_event(record),
                                  now if now is not None else int(record['__REALTIME_TIMESTAMP']) / 1000000, trusted)

    def count(self, kind):
        return self.store.db.execute('SELECT count(*) FROM events WHERE kind=?', (kind,)).fetchone()[0]

    def test_slow_switch_off_records_failures_without_threshold_or_ban(self):
        self.config['SSH_SLOW_PROTECTION'] = 'off'
        for i in range(20):
            record = self.failure(i, NOW + i * 1000)
            self.assertIsNone(self.process(record))
        self.assertEqual(self.count('slow-threshold'), 0)
        self.assertEqual(self.count('auth-failure'), 20)
        self.store.db.commit()
        resumed = events.Store(self.root / 'state')
        try:
            self.assertIsNone(resumed.process(record, self.config, auth.parse_event(record), NOW + 19000))
        finally:
            resumed.close()
        self.assertEqual(self.count('ban'), 0)

    def test_fresh_default_bans_slow_failures_only_at_long_threshold(self):
        self.assertEqual(self.config['SSH_SLOW_PROTECTION'], 'on')
        self.assertEqual(self.config['SSH_SLOW_FAILURES'], '20')
        for i in range(19):
            self.assertIsNone(self.process(self.failure(i, NOW + i * 1000)))
        self.assertEqual(self.process(self.failure(19, NOW + 19000)), 'ban')
        self.assertEqual(self.store.reason, 'slow-failed-logins')
        self.assertEqual(self.count('slow-threshold'), 1)

    def test_known_administrator_is_never_counted_by_slow_protection(self):
        def admin_failure(index, stamp):
            record = self.failure(index, stamp)
            # Whitelisted for a forwarded port only: not trusted on 22, but an administrator.
            return self.store.process(record, self.config, auth.parse_event(record), stamp, False, True)
        for i in range(25):
            self.assertIsNone(admin_failure(i, NOW + i * 1000))
        self.assertEqual(self.count('slow-threshold'), 0)
        # The fast failed-login detector still applies on a port it is not trusted for.
        later = NOW + 26 * 1000
        results = [admin_failure(i, later) for i in range(100, 105)]
        self.assertEqual(results[-1], 'ban')
        self.assertEqual(self.store.reason, 'failed-logins')

    def test_enforce_mixed_thresholds_one_ban_and_allow_precedence(self):
        self.config.update(SSH_SLOW_PROTECTION='on', SSH_SLOW_FAILURES='5')
        for i in range(4):
            self.assertIsNone(self.process(self.failure(i)))
        self.assertEqual(self.process(self.failure(4)), 'ban')
        self.assertEqual(self.count('slow-threshold'), 1)
        for i in range(5, 10):
            self.assertIsNone(self.process(self.failure(i), trusted=True))
        self.assertEqual(self.count('slow-threshold'), 1)

    def connection(self, message, cursor, pid, stamp=NOW):
        record = event(message, cursor, stamp)
        record['_PID'] = pid  # one sshd process per client connection
        return record

    def failures(self):
        return self.store.db.execute('SELECT count(*) FROM failures').fetchone()[0]

    def test_rejected_keys_before_a_successful_login_never_count(self):
        key = 'Failed publickey for alice from 198.51.100.7 port 45001 ssh2: ED25519 SHA256:example'
        for i in range(4):
            self.assertIsNone(self.process(self.connection(key, 'key-' + str(i), '700')))
        self.assertEqual(self.failures(), 1)  # several key offers are one attempt
        accepted = 'Accepted publickey for alice from 198.51.100.7 port 45001 ssh2: ED25519 SHA256:example'
        self.assertEqual(self.process(self.connection(accepted, 'ok', '700')), 'accepted')
        self.assertEqual(self.failures(), 0)  # nor do they count toward the 24-hour limit
        # Daily logins with several keys never approach the slow threshold.
        for day in range(30):
            for i in range(3):
                self.process(self.connection(key, f'd{day}-{i}', str(800 + day), NOW + day * 600))
            self.process(self.connection(accepted, f'd{day}-ok', str(800 + day), NOW + day * 600))
        self.assertEqual(self.failures(), 0)
        self.assertEqual(self.count('slow-threshold'), 0)

    def test_dropped_connections_count_once_each_and_passwords_count_singly(self):
        key = 'Failed publickey for alice from 198.51.100.7 port 45001 ssh2: ED25519 SHA256:example'
        results = []
        for connection in range(5):  # a bad network drops each attempt before success
            for i in range(3):
                results.append(self.process(self.connection(key, f'{connection}-{i}', str(900 + connection))))
        # The fifth separate attempt within ten minutes still bans, at its first rejected key.
        self.assertEqual(results, [None] * 12 + ['ban', None, None])
        self.assertEqual(self.store.reason, 'failed-logins')
        password = 'Failed password for bob from 198.51.100.8 port 45002 ssh2'
        outcomes = [self.process(self.connection(password, 'pw-' + str(i), '950')) for i in range(5)]
        self.assertEqual(outcomes[-1], 'ban')

    def test_failure_table_gains_method_column_on_existing_state(self):
        import sqlite3
        directory = self.root / 'old-state'
        directory.mkdir()
        with contextlib.closing(sqlite3.connect(directory / 'events.sqlite3')) as db:
            db.execute('CREATE TABLE failures (id TEXT PRIMARY KEY, stamp REAL, ip TEXT, conn TEXT, invalid INTEGER, short_on INTEGER)')
            db.execute("INSERT INTO failures VALUES ('old', ?, '198.51.100.7', ':1:45001', 0, 1)", (NOW,))
            db.commit()
        store = events.Store(directory, now=NOW)
        try:
            columns = [row[1] for row in store.db.execute('PRAGMA table_info(failures)')]
            self.assertIn('method', columns)
            record = self.failure(5)
            store.process(record, self.config, auth.parse_event(record), NOW)
            self.assertEqual(store.db.execute('SELECT count(*) FROM failures').fetchone()[0], 2)
        finally:
            store.close()

    def test_success_clears_only_short_counter_for_all_methods(self):
        for i in range(4):
            self.process(self.failure(i))
        for i, method in enumerate(('password', 'publickey', 'keyboard-interactive/pam')):
            self.assertEqual(self.process(event(f'Accepted {method} for alice from 198.51.100.7 port 45001', i + 100)), 'accepted')
        self.assertEqual(self.store.db.execute('SELECT sum(short_on) FROM failures').fetchone()[0], 0)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM failures').fetchone()[0], 4)
        self.assertEqual(self.count('new-source-login'), 3)
        for row in self.store.db.execute('SELECT detail FROM events'):
            self.assertNotIn('alice', row[0])

    def test_invalid_double_log_and_boot_connection_identity(self):
        record = self.failure(1, invalid=True)
        self.process(record)
        duplicate = {**record, '__CURSOR': 'different', 'MESSAGE': 'Failed password for invalid user missing-example-user from 198.51.100.7 port 45001'}
        self.process(duplicate)
        self.assertEqual(self.count('auth-failure'), 1)
        self.process({**duplicate, '__CURSOR': 'after-boot', '_BOOT_ID': 'different-boot'})
        self.assertEqual(self.count('auth-failure'), 2)

    def test_short_state_migration_preserves_counts_without_long_history(self):
        old = dict(attempts={'198.51.100.7': [[NOW - i, False, str(i)] for i in range(1, 5)]}, seen=['old-cursor'], cursor='old-cursor')
        (self.root / 'auth-state.json').write_text(json.dumps(old))
        with mock.patch.dict(os.environ, {'GUARD_DIR': str(self.root)}):
            self.store.migrate(self.config, NOW)
        self.assertEqual(self.process(self.failure(100)), 'ban')
        self.assertEqual(self.store.get('cursor_auth'), 'old-cursor')
        self.assertEqual(self.count('auth-failure'), 1)
        self.assertEqual(self.count('slow-threshold'), 0)

    def test_slow_episode_rearms_after_expiration(self):
        self.config.update(SSH_SLOW_FAILURES='2', SSH_AUTH_FAILURES='100', SSH_INVALID_USER_FAILURES='100', SSH_SLOW_WINDOW='1h')
        for index, stamp in enumerate((NOW, NOW + 1, NOW + 4000, NOW + 4001)):
            self.process(self.failure(index, stamp))
        self.assertEqual(self.count('slow-threshold'), 2)

    def test_subnet_report_distinct_automatic_sources_and_scope(self):
        self.config['SUBNET_REPORT_MIN_SOURCES'] = '2'
        self.store.record_ban('198.51.100.1', '*', NOW + 600, 'restored', self.config, NOW)
        self.store.record_ban('198.51.100.2', '*', NOW + 600, 'manual', self.config, NOW)
        self.store.record_ban('198.51.100.3', '*', NOW + 600, 'auth', self.config, NOW)
        self.store.record_ban('198.51.100.3', '*', NOW + 600, 'kernel', self.config, NOW + 1)
        self.store.record_ban('198.51.100.4', '22', NOW + 600, 'auth', self.config, NOW + 2)
        self.assertEqual(self.count('subnet-cluster'), 0)
        self.store.record_ban('198.51.100.5', '*', NOW + 600, 'kernel', self.config, NOW + 3)
        self.assertEqual(self.count('subnet-cluster'), 1)
        self.assertEqual(self.count('ban'), 3)
        self.store.record_ban('2001:db8::1', '*', NOW + 600, 'auth', self.config, NOW + 4)
        self.store.record_ban('2001:db8::2', '*', NOW + 600, 'auth', self.config, NOW + 5)
        self.assertEqual(self.count('subnet-cluster'), 2)

    def test_packet_deltas_survive_reopen_and_record_resets(self):
        def document(count, handle=1):
            return {'nftables': [{'table': {'handle': handle}}, {'rule': {'handle': 10, 'expr': [{'counter': {'packets': count}}, {'drop': None}]}}]}
        events.sample(self.store, self.config, NOW, document(10), baseline=True)
        events.sample(self.store, self.config, NOW + 60, document(35))
        events.sample(self.store, self.config, NOW + 120, document(4, 2))
        events.sample(self.store, self.config, NOW + 180, document(4, 2))
        rows = list(self.store.db.execute('SELECT packets,gap FROM samples'))
        self.assertEqual([tuple(r) for r in rows], [(25, 0), (4, 1), (0, 0)])
        self.store.emit('old', NOW - 100000, 'auth-failure')
        self.store.emit('new', NOW + 100, 'auth-failure')
        with mock.patch.object(events.time, 'time', return_value=NOW + 180), contextlib.redirect_stdout(io.StringIO()) as output:
            events.show(self.config, self.store, '1h')
        self.assertIn('auth-failure: 1', output.getvalue())
        self.assertIn('Sampled dropped packets: 29', output.getvalue())

    def test_added_counter_does_not_recount_existing_packets(self):
        first = {'nftables': [{'table': {'handle': 1}}, {'rule': {'handle': 10, 'expr': [{'counter': {'packets': 100}}, {'drop': None}]}}]}
        second = json.loads(json.dumps(first))
        second['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 105
        second['nftables'].append({'rule': {'handle': 11, 'expr': [{'counter': {'packets': 2}}, {'drop': None}]}})
        events.sample(self.store, self.config, NOW, first, baseline=True)
        events.sample(self.store, self.config, NOW + 60, second)
        self.assertEqual(self.store.db.execute('SELECT packets FROM samples').fetchone()[0], 7)

    def test_accept_classification_precedes_learning_and_shared_dedup(self):
        for method in ('password', 'publickey', 'keyboard-interactive/pam'):
            record = event(f'Accepted {method} for alice from 198.51.100.7 port 45001', method)
            seen = []
            self.config['LOGIN_USERS'] = 'alice'
            def sync(config, addition):
                seen.append(self.count('new-source-login'))
            with mock.patch.object(events, 'lock', contextlib.nullcontext), \
                 mock.patch.object(events, 'policy', return_value=self.config), \
                 mock.patch.object(events, 'root', return_value=self.root / 'state'), \
                 mock.patch.object(events.time, 'time', return_value=NOW), \
                 mock.patch.object(events.lists, 'allowed', return_value=False), \
                 mock.patch.object(events.lists, 'sync', side_effect=sync), \
                 mock.patch.object(events.shutil, 'which', return_value=None), \
                 mock.patch.dict(os.environ, {'GUARD_COMMAND': '/bin/true'}):
                self.assertTrue(events.handle(record, 'learn'))
                self.assertFalse(events.handle(record, 'auth'))
            self.assertEqual(len(seen), 1)
            self.assertGreater(seen[0], 0)

    def test_administrator_login_is_learned_with_no_login_users(self):
        record = event('Accepted publickey for root from 198.51.100.7 port 45001', 'admin-login')
        self.config.update(LOGIN_USERS='', LEARN_ADMINS='on')
        additions = []
        with mock.patch.object(events, 'lock', contextlib.nullcontext), \
             mock.patch.object(events, 'policy', return_value=self.config), \
             mock.patch.object(events, 'root', return_value=self.root / 'state'), \
             mock.patch.object(events.time, 'time', return_value=NOW), \
             mock.patch.object(events.lists, 'allowed', return_value=False), \
             mock.patch.object(events.lists, 'sync', side_effect=lambda config, addition: additions.append(addition)), \
             mock.patch.object(events.shutil, 'which', return_value=None), \
             mock.patch.dict(os.environ, {'GUARD_COMMAND': '/bin/true'}):
            self.assertTrue(events.handle(record, 'learn'))
            self.config['LEARN_ADMINS'] = 'off'
            other = event('Accepted publickey for root from 198.51.100.8 port 45002', 'admin-off')
            self.assertFalse(events.handle(other, 'learn'))
        self.assertEqual([(kind, row.ip, row.scope, row.source) for kind, row in additions],
                         [('allow', '198.51.100.7', '*', 'learned')])

    def test_two_readers_share_real_runtime_lock(self):
        from concurrent.futures import ThreadPoolExecutor
        self.config['LOGIN_USERS'] = 'alice'
        record = event('Accepted publickey for alice from 198.51.100.7 port 45001', 'parallel')
        with mock.patch.object(events, 'policy', return_value=self.config), \
             mock.patch.object(events, 'root', return_value=self.root / 'state'), \
             mock.patch.object(events.time, 'time', return_value=NOW), \
             mock.patch.object(events.lists, 'allowed', return_value=False), \
             mock.patch.object(events.lists, 'sync') as sync, \
             mock.patch.object(events.shutil, 'which', return_value=None), \
             mock.patch.dict(os.environ, {'GUARD_COMMAND': '/bin/true', 'GUARD_LOCK_FILE': str(self.root / 'lock')}):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda reader: events.handle(record, reader), ('learn', 'auth')))
            self.assertEqual(sorted(results), [False, True])
            sync.assert_called_once()
        self.assertEqual(self.count('new-source-login'), 1)
        self.assertEqual(len((self.root / 'home/frp-ssh-guard.log').read_text().splitlines()), 1)

    def test_existing_jail_is_not_renewed(self):
        live = [('ban4', events.data.Row('198.51.100.7', '*', NOW + 30, 'runtime'))]
        with mock.patch.object(events.lists, 'snapshot', return_value=live), \
             mock.patch.object(events.lists, 'read', return_value=''), \
             mock.patch.object(events.subprocess, 'run') as run:
            self.assertFalse(events.enforce(self.store, self.config, '198.51.100.7', NOW))
            run.assert_not_called()
        self.assertEqual(self.count('ban'), 0)

    def test_reban_after_manual_removal_records_new_auth_offense(self):
        import subprocess
        ip = '198.51.100.7'
        self.store.record_ban(ip, '*', NOW + 600, 'auth', self.config, NOW)
        # The editable-list watcher removed the previous jail, without a CLI
        # forgive. Its old accounting deadline still exists in the database.
        with mock.patch.object(events.lists, 'snapshot', return_value=[]), \
             mock.patch.object(events.lists, 'read', return_value=''), \
             mock.patch.object(events.lists, 'sync'), \
             mock.patch.object(events.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            self.assertTrue(events.enforce(self.store, self.config, ip, NOW + 10))
        self.assertEqual(self.count('ban'), 2)
        self.store.record_ban(ip, '*', NOW + 21610, 'kernel', self.config, NOW + 11)
        self.assertEqual(self.count('ban'), 2)

    def test_kernel_bans_are_logged_once_with_reason_and_strikes_once(self):
        def element(value, seconds):
            return {'elem': {'val': value, 'expires': seconds}}

        def document(bans, marks=(), strikes=()):
            return {'nftables': [{'table': {'handle': 1}},
                                 {'set': {'name': 'ban4', 'elem': [element(v, 3600) for v in bans]}},
                                 {'set': {'name': 'slowhit4', 'elem': [element(v, 500) for v in marks]}},
                                 {'set': {'name': 'hardban4', 'elem': [element(v, s) for v, s in strikes]}}]}
        events.sample(self.store, self.config, NOW, document([]), baseline=True)
        events.sample(self.store, self.config, NOW + 60,
                      document(['198.51.100.7', '198.51.100.8'], marks=['198.51.100.8'],
                               strikes=[('198.51.100.9', 86400)]))
        events.sample(self.store, self.config, NOW + 120,
                      document(['198.51.100.7', '198.51.100.8'], marks=['198.51.100.8'],
                               strikes=[('198.51.100.9', 86340)]))
        details = dict(self.store.db.execute("SELECT ip, detail FROM events WHERE kind='ban'").fetchall())
        self.assertEqual(len(details), 2)
        self.assertIn('reason=connection-rate limit=2/minute,burst=40', details['198.51.100.7'])
        self.assertIn('reason=slow-connections-all-ports limit=300/24h', details['198.51.100.8'])
        self.assertEqual(self.count('strike-ban'), 1)
        self.assertEqual(self.count('slow-threshold'), 1)

    def test_log_lines_show_ports_reason_and_skip_failures(self):
        self.store.emit('a' * 64, NOW, 'auth-failure', '198.51.100.7', '22')
        self.store.emit('b' * 64, NOW + 1, 'ban', '198.51.100.7', '22001',
                        'reason=slow-connections limit=100/24h until=2023-11-15T04:13:21Z')
        self.store.emit('c' * 64, NOW + 2, 'settings-applied', '', '*', 'slow-protection=on')
        with mock.patch.object(events.alerts, 'deliver', return_value=True) as deliver:
            self.store.export(self.config)
        lines = deliver.call_args[0][2].splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith('settings-applied slow-protection=on id=' + 'c' * 16))
        self.assertIn(' ban source=198.51.100.7 ports=22001 reason=slow-connections limit=100/24h ', lines[1])

    def test_invalid_new_settings_fail_validation(self):
        validator = events.module('validate')
        validator.validate(self.config)
        for key, value in (('SSH_SLOW_PROTECTION', 'enforce'), ('SSH_SLOW_PROTECTION', ''), ('LEARN_ADMINS', 'yes'),
                           ('SSH_SLOW_MODE', 'automatic'), ('SSH_SLOW_FAILURES', '0'),
                           ('SSH_SLOW_PORT_CONNECTIONS', '0'), ('SSH_SLOW_TOTAL_CONNECTIONS', '1000001'),
                           ('SSH_SLOW_WINDOW', 'forever'), ('SUBNET_REPORT_MIN_SOURCES', '-1'),
                           ('LOG_MAX_SIZE', '0MiB'), ('LOG_MAX_SIZE', '101MiB')):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validator.validate({**self.config, key: value})

    def test_readonly_status_does_not_write_database(self):
        self.store.db.commit()
        before = (self.root / 'state/events.sqlite3').read_bytes()
        state = events.Store(self.root / 'state', readonly=True)
        state.close()
        self.assertEqual(before, (self.root / 'state/events.sqlite3').read_bytes())


class AlertTests(unittest.TestCase):
    def test_newest_first_cap_complete_records_and_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'alerts.log'
            records = ''.join(f'2026-01-01T00:00:{i:02d}.000000Z type id={i} ' + 'x' * 100 + '\n' for i in range(30))
            events.alerts.merge(path, records, 1024)
            first = path.read_bytes()
            self.assertLessEqual(len(first), 1024)
            self.assertTrue(first.startswith(b'2026-01-01T00:00:29'))
            self.assertTrue(first.endswith(b'\n'))
            events.alerts.merge(path, records, 1024)
            self.assertEqual(first, path.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            events.alerts.merge(path, '', 512)
            self.assertLessEqual(path.stat().st_size, 512)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ['alerts.log'])

    def test_symlink_and_hardlink_targets_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'target').write_text('unchanged')
            (root / 'alerts.log').symlink_to(root / 'target')
            with self.assertRaises(OSError):
                events.alerts.merge(root / 'alerts.log', 'new\n', 1024)
            (root / 'alerts.log').unlink()
            os.link(root / 'target', root / 'alerts.log')
            with self.assertRaises(ValueError):
                events.alerts.merge(root / 'alerts.log', 'new\n', 1024)
            self.assertEqual((root / 'target').read_text(), 'unchanged')

    def test_offline_home_spools_then_merges_once_as_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir(mode=0o700)
            (root / 'etc').mkdir()
            home = root / '.frp-ssh-guard'
            (root / 'etc/user-home.json').write_text(json.dumps(dict(directory=str(home), user=pwd.getpwuid(os.getuid()).pw_name)))
            config = dict(LOG_MAX_SIZE='1KiB', CONFIG_BASE=str(root / 'etc'), MANUAL_DIR=str(home))
            record = '2026-01-01T00:00:00.000000Z new-source-login source=198.51.100.7 id=test\n'
            self.assertFalse(events.alerts.deliver(config, root / 'state', record))
            self.assertTrue((root / 'state/alerts-spool.log').exists())
            home.mkdir(mode=0o700)
            self.assertTrue(events.alerts.deliver(config, root / 'state', record))
            self.assertEqual((home / 'frp-ssh-guard.log').read_text(), record)
            self.assertFalse((root / 'state/alerts-spool.log').exists())
            self.assertEqual((home / 'frp-ssh-guard.log').stat().st_mode & 0o777, 0o600)

    def test_legacy_alerts_file_is_merged_once_newest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            old = '2026-01-01T00:00:00.000000Z new-source-login source=198.51.100.7 id=old\n'
            new = '2026-01-02T00:00:00.000000Z ban source=198.51.100.8 ports=all reason=connection-rate id=new\n'
            (home / 'alerts.log').write_text(old)
            events.alerts.merge(home / 'frp-ssh-guard.log', new, 1024, home / 'alerts.log')
            self.assertEqual((home / 'frp-ssh-guard.log').read_text(), new + old)
            self.assertFalse((home / 'alerts.log').exists())


if __name__ == '__main__':
    unittest.main()
