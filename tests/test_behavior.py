"""Restless-source rules and session learning, simulated without a firewall.

Only documentation addresses (198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
and invented ports are used.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('behavior_events', ROOT / 'bin/frp-ssh-guard-events.py')
events = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(events)
behavior = events.behavior
NOW = 1700000000
PORTS = [22001, 22002, 22003, 22004, 22005]
MINUTE, HOUR = 60, 3600
MAPPED = '::' + 'ffff:'


def element(ip, port, **extra):
    return {'elem': {'val': {'concat': [ip, port]}, 'expires': 3600, **extra}}


class Nft:
    """Records nft calls; every call succeeds."""

    def __init__(self):
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs.get('input', '')))
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')

    def text(self):
        return '\n'.join(' '.join(args) + ' ' + stdin for args, stdin in self.calls)


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patcher = mock.patch.dict(os.environ, {'GUARD_LIST_DIR': str(self.root / 'lists'),
                                               'GUARD_DIR': str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / 'lists').mkdir()
        self.config = events.data.template_settings((ROOT / 'etc/settings.conf.example').read_text())
        self.config.update(PROTECTED_PORTS=','.join(f'{p}:30:20' for p in PORTS), OBSERVABILITY_VERSION='1',
                           CONFIG_BASE=str(self.root / 'etc'), MANUAL_DIR=str(self.root / 'home'))
        self.store = events.Store(self.root / 'state', now=NOW)
        self.addCleanup(self.store.close)
        self.nft = Nft()
        self.packets = {}
        self.known = []
        self.bans = []

    def document(self):
        count = {'4': [], '6': []}
        for (ip, port), packets in self.packets.items():
            count['6' if ':' in ip else '4'].append(element(ip, port, counter={'packets': packets, 'bytes': 0}))
        sets = [{'set': {'name': 'count' + f, 'elem': count[f]}} for f in '46']
        sets += [{'set': {'name': 'known' + f, 'elem': [element(ip, port, expires=left)
                                                       for ip, port, left in self.known if (':' in ip) == (f == '6')]}}
                 for f in '46']
        sets += [{'set': {'name': 'ban4', 'elem': [{'elem': {'val': ip, 'expires': 3600}} for ip in self.bans]}}]
        return {'nftables': [{'table': {'handle': 7}}] + sets}

    def observe(self, now, sockets=()):
        return behavior.observe(self.store, self.config, self.document(), now, ['boot', 7], list(sockets),
                                run=self.nft, listed=lambda ip, now=None: False)

    def connect(self, ip, port, count=1):
        self.packets[(ip, port)] = self.packets.get((ip, port), 0) + count

    def simulate(self, schedule, hours, step=5 * MINUTE, start=NOW, sockets=None):
        """schedule(t) -> [(ip, port)] connections in the step ending at t; returns first ban time."""
        bans = []
        for t in range(start + step, start + int(hours * HOUR) + 1, step):
            for ip, port in schedule(t - start):
                self.connect(ip, port)
            applied = self.observe(t, sockets(t - start) if sockets else ())
            bans.extend((t - start, *ban) for ban in applied)
        return bans

    def rotation(self, ports, every):
        state = {'next': 0, 'index': 0}

        def schedule(elapsed):
            result = []
            while state['next'] < elapsed:
                result.append(('203.0.113.50', ports[state['index'] % len(ports)]))
                state['index'] += 1
                state['next'] += every
            return result
        return schedule

    def ban_lines(self):
        return [row['detail'] for row in self.store.db.execute("SELECT detail FROM events WHERE kind='ban'")]

    def test_parse_sockets_keeps_frps_sockets_and_normalizes_mapped_ipv4(self):
        text = ('0 0 192.0.2.1:22001 198.51.100.7:51234 users:(("frps",pid=10,fd=7))\n'
                '\t cubic bytes_sent:40000 bytes_acked:40001 bytes_received:900\n'
                # IPv4-mapped peers of a dual-stack listener (split so scanners see documentation addresses).
                '0 0 [' + MAPPED + '192.0.2.1]:22002 [' + MAPPED + '198.51.100.8]:40000 users:(("frps",pid=10,fd=8))\n'
                '\t cubic bytes_acked:120 bytes_received:900\n'
                '0 0 [2001:db8::1]:22003 [2001:db8::9]:40001 users:(("frps",pid=10,fd=9))\n'
                '0 0 192.0.2.1%eth0:22004 198.51.100.9:40002 users:(("sshd",pid=11,fd=3))\n'
                '\t cubic bytes_acked:99999999\n')
        self.assertEqual(behavior.parse_sockets(text), [('198.51.100.7', 51234, 22001, 40001),
                                                        ('198.51.100.8', 40000, 22002, 120),
                                                        ('2001:db8::9', 40001, 22003, 0)])

    def test_forwarded_ports_exclude_native_ssh_and_expand_ranges(self):
        self.assertEqual(behavior.forwarded({'PROTECTED_PORTS': '22001-22003,22:30:20', 'PROTECT_SERVER_SSH': 'on'}),
                         {22001, 22002, 22003})

    def test_rotation_across_ports_is_banned_on_all_ports_in_both_modes(self):
        for mode, set_name in (('off', 'ban4'), ('on', 'wideban4')):
            with self.subTest(jail_per_port=mode):
                self.setUp()
                self.config['JAIL_PER_PORT'] = mode
                bans = self.simulate(self.rotation(PORTS, 10 * MINUTE), hours=3)
                self.assertEqual([(scope, reason) for _, _, scope, reason in bans], [('*', 'restless-ports')])
                self.assertTrue(2 * HOUR <= bans[0][0] <= 2 * HOUR + 15 * MINUTE, bans)
                self.assertIn(f'add element inet frp_ssh_persistent_guard {set_name} {{ 203.0.113.50 timeout 12h }}',
                              self.nft.text())
                self.assertIn('reason=restless-ports limit=4ports/2h,pause=2h until=', self.ban_lines()[0])

    def test_three_ports_need_six_hours(self):
        bans = self.simulate(self.rotation(PORTS[:3], 10 * MINUTE), hours=7)
        self.assertEqual(len(bans), 1)
        self.assertTrue(6 * HOUR <= bans[0][0] <= 6 * HOUR + 15 * MINUTE, bans)
        self.assertEqual(bans[0][2:], ('*', 'restless-ports'))

    def test_connection_rule_follows_the_jail_mode(self):
        for mode, scope, value in (('off', '*', '203.0.113.50 timeout'), ('on', '22001', '203.0.113.50 . 22001 timeout')):
            with self.subTest(jail_per_port=mode):
                self.setUp()
                self.config['JAIL_PER_PORT'] = mode
                bans = self.simulate(self.rotation([22001], 9 * MINUTE), hours=13)  # 160 a day on one port
                self.assertEqual([(s, r) for _, _, s, r in bans], [(scope, 'restless-connections')])
                self.assertTrue(12 * HOUR <= bans[0][0] <= 12 * HOUR + 15 * MINUTE, bans)
                self.assertIn(value, self.nft.text())
                self.assertIn('limit=50/12h,pause=2h', self.ban_lines()[0])

    def test_per_port_mode_needs_each_port_to_reach_the_connection_rule(self):
        self.config['JAIL_PER_PORT'] = 'on'
        self.config['SSH_BEHAVIOR_RULES'] = '50c:12h'
        # Two ports at 80 connections per 12 hours each: both reach it, separately.
        bans = self.simulate(self.rotation([22001, 22002], 4 * MINUTE + 30), hours=13)
        self.assertEqual(sorted(scope for _, _, scope, _ in bans), ['22001', '22002'])

    def test_hourly_job_and_daytime_user_are_never_banned(self):
        hourly = self.simulate(self.rotation([22001], HOUR), hours=72)
        self.assertEqual(hourly, [])

        def daytime(elapsed):
            minute = elapsed % (24 * HOUR)
            # Checks six machines in ten minutes, three times a day.
            if any(start < minute <= start + 10 * MINUTE for start in (9 * HOUR, 13 * HOUR, 17 * HOUR)):
                return [('198.51.100.20', port) for port in PORTS + [22006]]
            return []
        self.config['PROTECTED_PORTS'] += ',22006:30:20'
        self.assertEqual(self.simulate(daytime, hours=48), [])

    def test_a_two_hour_pause_starts_the_streak_over(self):
        rotate = self.rotation(PORTS, 10 * MINUTE)

        def schedule(elapsed):
            # Active for 1h50, then quiet for 2h, repeatedly.
            return rotate(elapsed) if elapsed % (3 * HOUR + 50 * MINUTE) <= 110 * MINUTE else []
        self.assertEqual(self.simulate(schedule, hours=12), [])

    def test_flaky_user_known_after_one_good_session_is_never_judged(self):
        def sockets(elapsed):
            # The first session sends a shell; afterwards every session drops quickly.
            if elapsed == 5 * MINUTE:
                return [('198.51.100.30', 41000, 22001, 40 * 1024)]
            return [('198.51.100.30', 41000 + elapsed % 997, 22001, 2048)]

        def reconnects(elapsed):
            # Reconnects every five minutes for 12 hours, also to a second machine.
            return [('198.51.100.30', 22001), ('198.51.100.30', 22002)] if elapsed > 5 * MINUTE else []
        self.assertEqual(self.simulate(reconnects, hours=12, sockets=sockets), [])
        known = self.store.db.execute("SELECT count(*) FROM events WHERE kind='known-user'").fetchone()[0]
        self.assertEqual(known, 1)
        self.assertIn('add element inet frp_ssh_persistent_guard known4 { 198.51.100.30 . 22001 timeout 7776000s }',
                      self.nft.text())
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM streaks').fetchone()[0], 0)

    def test_a_long_session_clears_an_unknown_users_streak(self):
        rotate = self.rotation(PORTS[:3], 10 * MINUTE)

        def sockets(elapsed):
            # A real session from 3h to 3h10 (seen in three samples, 5 minutes apart).
            return [('203.0.113.50', 42000, 22001, 1000)] if 3 * HOUR <= elapsed <= 3 * HOUR + 10 * MINUTE else []
        self.assertEqual(self.simulate(rotate, hours=8, sockets=sockets), [])
        self.assertIn('reason=long-session', self.store.db.execute(
            "SELECT detail FROM events WHERE kind='known-user'").fetchone()[0])

    def test_young_small_or_unrelated_sockets_teach_nothing(self):
        self.observe(NOW, [('198.51.100.31', 41000, 22001, 1024), ('198.51.100.32', 41000, 23000, 10 ** 6)])
        self.observe(NOW + 2 * MINUTE, [('198.51.100.31', 41000, 22001, 1024), ('198.51.100.32', 41000, 23000, 10 ** 6)])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM known').fetchone()[0], 0)
        self.observe(NOW + 3 * MINUTE, [('198.51.100.31', 41000, 22001, 1024)])
        self.assertEqual([tuple(r) for r in self.store.db.execute('SELECT ip, port FROM known')], [('198.51.100.31', 22001)])

    def test_known_set_follows_the_database_and_forget(self):
        self.observe(NOW, [('2001:db8::31', 41000, 22001, 10 ** 6)])
        self.assertIn('known6 { 2001:db8::31 . 22001 timeout', self.nft.text())
        self.nft.calls.clear()
        self.known = [('2001:db8::31', 22001, 7776000 - 60), ('198.51.100.99', 22002, 500)]
        self.observe(NOW + MINUTE)
        self.assertNotIn('2001:db8::31', self.nft.text())  # present with the right time: untouched
        self.assertIn('delete element inet frp_ssh_persistent_guard known4 { 198.51.100.99 . 22002 }', self.nft.text())
        self.known = [('2001:db8::31', 22001, 3600)]  # renewed in the database, old in the kernel
        self.nft.calls.clear()
        self.observe(NOW + 2 * MINUTE)
        self.assertIn('delete element inet frp_ssh_persistent_guard known6 { 2001:db8::31 . 22001 }', self.nft.text())
        behavior.forget(self.store, self.config, '2001:db8::31', run=self.nft)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM known').fetchone()[0], 0)
        self.assertIn('delete element inet frp_ssh_persistent_guard known6 { 2001:db8::31 . 22001 }',
                      ' '.join(self.nft.calls[-1][0]))

    def test_learning_off_clears_known_users(self):
        self.observe(NOW, [('198.51.100.31', 41000, 22001, 10 ** 6)])
        self.config['LEARN_USERS'] = 'off'
        self.known = [('198.51.100.31', 22001, 3600)]
        self.observe(NOW + MINUTE, [('198.51.100.31', 41000, 22001, 10 ** 6)])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM known').fetchone()[0], 0)
        self.assertIn('delete element inet frp_ssh_persistent_guard known4 { 198.51.100.31 . 22001 }', self.nft.text())

    def test_counter_deltas_survive_recreation_and_new_tables(self):
        self.connect('203.0.113.60', 22001, 5)
        self.assertEqual(behavior.deltas(self.store, self.document(), ['b', 1]), {'203.0.113.60': {22001: 5}})
        self.connect('203.0.113.60', 22001, 2)
        self.assertEqual(behavior.deltas(self.store, self.document(), ['b', 1]), {'203.0.113.60': {22001: 2}})
        self.packets = {('203.0.113.60', 22001): 3}  # element expired and was recreated
        self.assertEqual(behavior.deltas(self.store, self.document(), ['b', 1]), {'203.0.113.60': {22001: 3}})
        self.packets = {('203.0.113.60', 22001): 4}  # a reload made a new table
        self.assertEqual(behavior.deltas(self.store, self.document(), ['b', 2]), {'203.0.113.60': {22001: 4}})
        self.packets = {}
        self.assertEqual(behavior.deltas(self.store, self.document(), ['b', 2]), {})
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM counters').fetchone()[0], 0)

    def test_covered_sources_are_not_banned_again(self):
        self.bans = ['203.0.113.50']  # already jailed by another limit
        self.assertEqual(self.simulate(self.rotation(PORTS, 10 * MINUTE), hours=3), [])
        self.assertNotIn('add element', self.nft.text())

    def test_older_tables_and_switches_off_leave_the_firewall_alone(self):
        self.connect('203.0.113.50', 22001, 500)
        document = {'nftables': [{'table': {'handle': 7}}, {'set': {'name': 'ban4', 'elem': []}}]}
        self.assertEqual(behavior.observe(self.store, self.config, document, NOW, None, [], run=self.nft,
                                          listed=lambda ip, now=None: False), [])
        for key, value in (('SSH_SLOW_BEHAVIOR', 'off'), ('SSH_SLOW_PROTECTION', 'off')):
            config = {**self.config, key: value}
            self.assertEqual(behavior.observe(self.store, config, self.document(), NOW, None, [], run=self.nft,
                                              listed=lambda ip, now=None: False), [])
        self.assertNotIn('add element', self.nft.text())

    def test_judge_uses_only_the_last_rule_window(self):
        self.assertEqual(behavior.rules('20b:30m'), [(20, 'b', 1800, '30m')])
        # The kernel enforces a burst rule, so a streak never matches it.
        self.assertEqual(behavior.judge(NOW - 7 * 86400, NOW, [(22001, int(NOW // 900), 500)],
                                        behavior.rules('20b:30m'), False, '2h'), [])
        entries = behavior.rules('4p:2h 50c:12h')
        slot = behavior.SLOT
        old = [(port, (NOW - 5 * HOUR) // slot, 1) for port in PORTS]  # spread, but long ago
        recent = [(22001, (NOW - HOUR) // slot, 10)]
        self.assertEqual(behavior.judge(NOW - 6 * HOUR, NOW, old + recent, entries, False, '2h'), [])
        recent = [(port, (NOW - HOUR) // slot, 1) for port in PORTS[:4]]
        self.assertEqual(behavior.judge(NOW - 6 * HOUR, NOW, old + recent, entries, False, '2h'),
                         [('*', 'restless-ports', '4ports/2h,pause=2h')])
        self.assertEqual(behavior.judge(NOW - HOUR, NOW, recent, entries, False, '2h'), [])  # streak too short

    def test_summary_lists_closest_streaks(self):
        self.simulate(self.rotation(PORTS[:3], 10 * MINUTE), hours=2)
        lines = behavior.summary(self.store, self.config, NOW + 2 * HOUR)
        self.assertEqual(lines[1], 'Active behavior streaks: 1')
        self.assertIn('203.0.113.50 streak=1h50m ports=3 connections=12', lines[2])
        state = events.Store(self.root / 'state', readonly=True)
        self.addCleanup(state.close)
        self.assertEqual(len(behavior.summary(state, self.config, NOW + 2 * HOUR, 0)), 2)


if __name__ == '__main__':
    unittest.main()
