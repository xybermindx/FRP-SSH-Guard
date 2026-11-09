"""Unprivileged rule-generation tests; no host firewall or services are changed."""
import importlib.util
import contextlib
import datetime
import gzip
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'bin/frp-ssh-guard-persistent.sh').read_text()
# Load actual declarations/functions without privileged CLI dispatch.
LIBRARY = (SCRIPT.split('action=${1:-help}')[0].replace(
    'LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)',
    'LIB_DIR=' + str(ROOT / 'bin')) +
           SCRIPT.split('# ---------- config readers ----------', 1)[1]
           .split('# ---------- main dispatch ----------', 1)[0])


def data_module():
    spec = importlib.util.spec_from_file_location('strike_inputs', ROOT / 'bin/frp-ssh-guard-input.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for d in ('etc', 'lists', 'logs'): (self.root / d).mkdir()
        self.env = {**os.environ, 'GUARD_DIR': str(self.root)}
        for key in list(self.env):
            if key.startswith('GUARD_') and key != 'GUARD_DIR': del self.env[key]
        self.env['GUARD_LOCK_FILE'] = str(self.root / 'guard.lock')
        self.env['TMPDIR'] = str(self.root)

    def run_guard(self, body):
        return subprocess.run(['bash', '-c', LIBRARY + '\nload_guard_config candidate\n' + body],
                              env=self.env, text=True, capture_output=True)

    def rules(self, ports='22001\n', config='', active=False):
        (self.root / 'etc/ports.conf').write_text(ports)
        (self.root / 'etc/guard.conf').write_text(config)
        result = self.run_guard('''
NFTP=false
''' + ('table_active() { return 0; }\n' if active else '') + '''
read_ban_conf
read_ports "$PORTS_FILE"
read_allow; read_blocklist; read_learned; read_hardban
compile_rules "$GUARD_DIR/rules.nft"
cat "$GUARD_DIR/rules.nft"
''')
        return result

    def test_empty_and_invalid_ports_fail(self):
        for ports in ('# nothing\n', '0\n', '65536\n', '22002-22001\n', '22001\n22001\n', '22; flush ruleset\n'):
            with self.subTest(ports=ports): self.assertNotEqual(self.rules(ports).returncode, 0)

    def test_ranges_exclusions_and_overrides(self):
        result = self.rules('22001-22003:44:55\n', 'EXCLUDE_PORTS=22002\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tcp dport != { 22001,22003 } return', result.stdout)
        self.assertNotIn('tcp dport 22002 ', result.stdout)
        self.assertIn('limit rate over 44/minute burst 55 packets', result.stdout)

    def test_ban_and_rate_sets_are_distinct(self):
        result = self.rules(config='PER_IP_RATE=7\nPER_IP_BURST=13\nBAN_TIMEOUT=3h\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        for family, addr in (('4', 'ip'), ('6', 'ip6')):
            self.assertIn(f'update @rate{family} {{ {addr} saddr . tcp dport limit rate over 7/minute burst 13 packets }} add @ban{family} {{ {addr} saddr timeout 3h }}', result.stdout)
        self.assertNotIn('add @ban4 { ip saddr limit', result.stdout)
        self.assertIn('size 65536;', result.stdout)

    def test_initial_and_replacement_transactions(self):
        initial = self.rules()
        self.assertTrue(initial.stdout.startswith('table inet '), initial.stderr)
        replacement = self.rules(active=True)
        self.assertTrue(replacement.stdout.startswith('delete table inet frp_ssh_persistent_guard\ntable inet '))
        self.assertNotIn('flush ruleset', replacement.stdout)

    def test_ipv4_ipv6_and_per_port_lists(self):
        (self.root / 'lists/whitelist.conf').write_text('198.51.100.1\n2001:db8::1 22001\n')
        (self.root / 'lists/blocklist.conf').write_text('203.0.113.0/24 22001,22003\n')
        result = self.rules('22001\n22003\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('allow4 { 198.51.100.1 }', result.stdout)
        self.assertIn('allow_pp6 { 2001:db8::1 . 22001 }', result.stdout)
        self.assertIn('block_pp4 { 203.0.113.0/24 . 22001,203.0.113.0/24 . 22003 }', result.stdout)

    def test_slow_protection_rules_follow_jail_mode_and_skip_native_ssh(self):
        shared = self.rules('22001\n22003\n', config='SSH_SLOW_PROTECTION=on\n')
        self.assertEqual(shared.returncode, 0, shared.stderr)
        # Known users and resent SYNs are not counted.
        self.assertIn('tcp dport 22001 ct state new tcp flags & (syn | ack) == syn ip saddr != @trusted4 '
                      'ip saddr . tcp dport != @known4 ip saddr . tcp sport . tcp dport . tcp sequence != @synseen4 '
                      'update @slow4 { ip saddr limit rate over 300/day burst 300 packets } '
                      'add @slowhit4 { ip saddr } add @ban4 { ip saddr timeout 12h } counter drop comment "22001 slow v4"',
                      shared.stdout)
        self.assertIn('set slow6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; size 65536; }', shared.stdout)
        # Global drops are not counted: the slow rule comes after the shared ceiling.
        self.assertLess(shared.stdout.index('"22001 global"'), shared.stdout.index('"22001 slow v4"'))
        per_port = self.rules('22001\n', config='SSH_SLOW_PROTECTION=on\nJAIL_PER_PORT=on\nSSH_SLOW_WINDOW=12h\n')
        self.assertIn('update @slow4 { ip saddr . tcp dport limit rate over 200/day burst 100 packets } '
                      'add @slowhit4 { ip saddr . tcp dport } add @ban4 { ip saddr . tcp dport timeout 12h }', per_port.stdout)
        weekly = self.rules('22001\n', config='SSH_SLOW_PROTECTION=on\nSSH_SLOW_WINDOW=3d\n')
        self.assertIn('limit rate over 700/week burst 300 packets', weekly.stdout)
        native = self.rules('22001\n', config='SSH_SLOW_PROTECTION=on\nPROTECT_SERVER_SSH=on\n')
        self.assertIn('"22001 slow v4"', native.stdout)
        self.assertNotIn('"22 slow v4"', native.stdout)  # port 22 counts failed logins instead
        off = self.rules('22001\n', config='SSH_SLOW_PROTECTION=off\n')
        self.assertNotIn(' slow v4', off.stdout)

    def test_burst_rule_acts_in_the_kernel_for_unproven_sources_only(self):
        on = 'SSH_SLOW_PROTECTION=on\nSSH_SLOW_BEHAVIOR=on\n'
        rules = 'SSH_BEHAVIOR_RULES="20b:30m 4p:2h"\n'
        shared = self.rules('22001\n', config=on + rules)
        self.assertEqual(shared.returncode, 0, shared.stderr)
        # Trusted and known sources skip it, and a resent SYN is not counted again.
        self.assertIn('tcp dport 22001 ct state new tcp flags & (syn | ack) == syn ip saddr != @trusted4 '
                      'ip saddr . tcp dport != @known4 ip saddr . tcp sport . tcp dport . tcp sequence != @synseen4 '
                      'update @burst4 { ip saddr limit rate over 40/hour burst 20 packets } '
                      'add @bursthit4 { ip saddr } add @ban4 { ip saddr timeout 12h } counter drop comment "22001 burst v4"',
                      shared.stdout)
        self.assertIn('set burst6 { type ipv6_addr; flags dynamic,timeout; timeout 30m; size 65536; }', shared.stdout)
        self.assertIn('"22001 burst v6"', shared.stdout)
        self.assertLess(shared.stdout.index('"22001 slow v4"'), shared.stdout.index('"22001 burst v4"'))
        self.assertLess(shared.stdout.index('"22001 burst v4"'), shared.stdout.index('"22001 first v4"'))
        per_port = self.rules('22001\n', config=on + rules + 'JAIL_PER_PORT=on\n')
        self.assertIn('update @burst4 { ip saddr . tcp dport limit rate over 40/hour burst 20 packets } '
                      'add @bursthit4 { ip saddr . tcp dport } add @ban4 { ip saddr . tcp dport timeout 12h }', per_port.stdout)
        self.assertIn('limit rate over 60/hour burst 20 packets',
                      self.rules('22001\n', config=on + 'SSH_BEHAVIOR_RULES="20b:20m"\n').stdout)
        native = self.rules('22001\n', config=on + rules + 'PROTECT_SERVER_SSH=on\n')
        self.assertIn('"22001 burst v4"', native.stdout)
        self.assertNotIn('"22 burst v4"', native.stdout)  # port 22 counts failed logins instead
        for config in ('SSH_SLOW_PROTECTION=off\nSSH_SLOW_BEHAVIOR=on\n' + rules,
                       'SSH_SLOW_PROTECTION=on\nSSH_SLOW_BEHAVIOR=off\n' + rules,
                       on + 'SSH_BEHAVIOR_RULES="4p:2h"\n'):
            with self.subTest(config=config):
                self.assertNotIn('burst4', self.rules('22001\n', config=config).stdout)

    def test_resent_syns_known_users_and_behavior_rules_in_both_jail_modes(self):
        on = 'SSH_SLOW_PROTECTION=on\nSSH_SLOW_BEHAVIOR=on\n'
        shared = self.rules('22001\n', config=on)
        self.assertEqual(shared.returncode, 0, shared.stderr)
        out = shared.stdout
        for family, addr in (('4', 'ip'), ('6', 'ip6')):
            key = f'{addr} saddr . tcp sport . tcp dport . tcp sequence'
            self.assertIn(f'set synseen{family} {{ typeof {key}; flags dynamic,timeout; timeout 2m; size 65536; }}', out)
            self.assertIn(f'set count{family} {{ type ipv{family}_addr . inet_service; flags dynamic,timeout; timeout 26h;', out)
            self.assertIn(f'set known{family} {{ type ipv{family}_addr . inet_service; flags timeout; size 65536; }}', out)
            # Every per-source meter only looks up; the single add follows them all.
            self.assertIn(f'syn {key} != @synseen{family} update @rate{family} {{', out)
            self.assertIn(f'{addr} saddr != @trusted{family} {addr} saddr . tcp dport != @known{family} {key} '
                          f'!= @synseen{family} update @count{family} {{ {addr} saddr . tcp dport counter }} '
                          f'comment "22001 observe v{family}"', out)
            self.assertIn(f'add @synseen{family} {{ {key} }} comment "22001 first v{family}"', out)
        order = ['"22001 per-IP v4"', '"22001 global"', '"22001 slow v4"', '"22001 observe v4"',
                 '"22001 first v4"', '"22001 ok"']
        self.assertEqual([out.index(name) for name in order], sorted(out.index(name) for name in order))
        self.assertNotIn('wideban', out)  # shared jails ban addresses in ban4/ban6 already
        per_port = self.rules('22001\n22003\n', config=on + 'JAIL_PER_PORT=on\nPROTECT_SERVER_SSH=on\n').stdout
        self.assertIn('set wideban4 { type ipv4_addr; flags timeout; size 65536; }', per_port)
        self.assertIn('tcp dport { 22001,22003,22 } ip  saddr @wideban4 counter drop comment "all-port ban v4"', per_port)
        self.assertLess(per_port.index('"all-port ban v6"'), per_port.index('"22001 banned v4"'))
        self.assertIn('"22003 observe v6"', per_port)
        self.assertNotIn('"22 observe v4"', per_port)  # native SSH counts failed logins
        self.assertIn('"22 first v4"', per_port)  # but its per-minute meter skips resends too
        # On by default: a file or accepted policy without the switch counts too.
        self.assertIn('"22001 observe v4"', self.rules('22001\n', config='SSH_SLOW_PROTECTION=on\n').stdout)
        for config in ('SSH_SLOW_PROTECTION=on\nSSH_SLOW_BEHAVIOR=off\n',
                       'SSH_SLOW_PROTECTION=off\nSSH_SLOW_BEHAVIOR=on\n'):
            with self.subTest(config=config):
                off = self.rules('22001\n', config=config).stdout
                self.assertNotIn('observe v4', off)
                self.assertNotIn('set count4', off)
                self.assertIn('"22001 first v4"', off)
                self.assertIn('set known4', off)

    def test_accepted_policy_from_an_older_build_gets_behavior_rules_on_refresh(self):
        # applied.conf written before these settings existed, as the package upgrade finds it.
        (self.root / 'applied.conf').write_text("GUARD_TABLE=frp_ssh_persistent_guard\nPROTECTED_PORTS=22001:30:20\n"
                                                "SSH_SLOW_PROTECTION=on\nJAIL_PER_PORT=on\nOBSERVABILITY_VERSION=1\n")
        result = self.run_guard('''
load_guard_config runtime
printf '%s|' "$SSH_SLOW_BEHAVIOR" "$LEARN_USERS" "$SSH_BEHAVIOR_RULES" "$LEARN_SESSION_AGE"
validate_policy
NFTP=false; read_ban_conf; selected_ports > "$GUARD_DIR/ports"; read_ports "$GUARD_DIR/ports"
read_allow; read_blocklist; read_learned; read_hardban
compile_rules "$GUARD_DIR/rules.nft"
write_accepted_config > "$GUARD_DIR/accepted"
echo; grep -c 'observe v4' "$GUARD_DIR/rules.nft" || true
grep -E '^(SSH_SLOW_BEHAVIOR|LEARN_USERS)=' "$GUARD_DIR/accepted"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], 'on|on|20b:30m 4p:2h 3p:6h 50c:12h|3m|')
        self.assertEqual(lines[1], '1')  # the automatic package refresh counts at once
        self.assertEqual(lines[2:], ['SSH_SLOW_BEHAVIOR=on', 'LEARN_USERS=on'])

    def test_per_port_address_strikes_escalate_live_in_saved_sets(self):
        import sqlite3
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        (self.root / 'etc/guard.conf').write_text('JAIL_PER_PORT=on\nSTRIKE_LADDER="2:3d"\n')
        (self.root / 'observations').mkdir()
        with contextlib.closing(sqlite3.connect(self.root / 'observations/events.sqlite3')) as db:
            db.execute('CREATE TABLE events (stamp INTEGER, ip TEXT, scope TEXT, kind TEXT)')
            # Two all-port behavior bans: the second came after the first one ended.
            db.executemany('INSERT INTO events VALUES (?,?,?,?)',
                           [(now - 45000, '203.0.113.70', '*', 'ban'), (now - 60, '203.0.113.70', '*', 'ban')])
            db.commit()
        real_run = subprocess.run
        def run_command(args, **kwargs):
            return real_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch('subprocess.run', side_effect=run_command) as run, \
             mock.patch('shutil.chown'), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'bin/frp-ssh-guard-strike.py'))
        self.assertIn('203.0.113.70 all source=strike until=', (self.root / 'lists/hardban.conf').read_text())
        batches = [call.kwargs.get('input', '') for call in run.call_args_list if call.args[0][-2:] == ['-f', '-']]
        self.assertEqual(len(batches), 1)
        lines = batches[0].splitlines()
        self.assertEqual(lines[1], 'delete element inet frp_ssh_persistent_guard saved_ban4 { 203.0.113.70 }')
        seconds = int(lines[2].split('timeout ')[1].rstrip('s }'))
        self.assertTrue(3 * 86400 - 120 <= seconds <= 3 * 86400)
        self.assertFalse(any('hardban4' in str(call.args[0]) and '203.0.113.70 }' in str(call.args[0])
                             for call in run.call_args_list))

    def test_any_whitelisted_source_is_trusted_without_overlaps(self):
        (self.root / 'lists/whitelist.conf').write_text(
            '[22001]\n198.51.100.0/24\n198.51.100.7\n[22003]\n198.51.100.7\n'
            '203.0.113.5 source=learned until=2030-01-01T00:00:00Z\n[all]\n2001:db8::/64\n2001:db8::1\n')
        result = self.rules('22001\n22003\n', config='SSH_SLOW_PROTECTION=on\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r'trusted4 \{ 198\.51\.100\.0/24,203\.0\.113\.5 timeout [0-9]+s \}')
        self.assertIn('trusted6 { 2001:db8::/64 }', result.stdout)

    def test_configured_default_manual_ban(self):
        (self.root / 'etc/guard.conf').write_text('BAN_TIMEOUT=3h\n')
        result = self.run_guard('NFTP=echo; table_active() { return 0; }; cmd_ban 198.51.100.1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('timeout 3h', result.stdout)

    @unittest.skipUnless(shutil.which('jq'), 'requires jq for JSON ban display')
    def test_ban_views_report_nft_json_expiry_in_seconds(self):
        (self.root / 'ban.json').write_text(json.dumps({'nftables': [{'set': {'elem': [
            {'elem': {'val': '198.51.100.7', 'expires': 1140}},
            {'elem': {'val': {'concat': ['2001:db8::7', 22001]}, 'expires': 900}}
        ]}}]}))
        for command in ('cmd_banned',):
            result = self.run_guard('fake_nft() { cat "$GUARD_DIR/ban.json"; }\n'
                                    'NFTP=fake_nft\ntable_active() { return 0; }\n' + command)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [line.split() for line in result.stdout.splitlines()]
            self.assertTrue(any('198.51.100.7' in row and row[-1] == '1140' for row in rows))
            self.assertTrue(any('2001:db8::7' in row and '22001' in row and row[-1] == '900' for row in rows))

    def test_source_service_recompiles_at_boot(self):
        result = self.run_guard('STAGE="$GUARD_DIR"; NFTP=/usr/sbin/nft; write_unit; cat "$STAGE/unit"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'ExecStart={self.root}/bin/frp-ssh-guard apply', result.stdout)
        self.assertIn(f'ExecStop={self.root}/bin/frp-ssh-guard _stop', result.stdout)
        self.assertNotIn('--file', result.stdout)

    def test_rotated_strikes_use_configured_table(self):
        (self.root / 'etc/guard.conf').write_text('GUARD_TABLE="custom_guard"\nSTRIKE_LADDER="2:1d"\nSTRIKE_MAX=3h\n')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        event = f'{stamp}  ban4 198.51.100.1\n'
        (self.root / 'logs/banned.log').write_text(event)
        with gzip.open(self.root / 'logs/banned.log.2.gz', 'wt') as f: f.write(event)
        real_run = subprocess.run
        def run_command(args, **kwargs):
            if args[0] == 'bash': return real_run(args, **kwargs)
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch('subprocess.run', side_effect=run_command) as run, \
             mock.patch('shutil.chown'), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'bin/frp-ssh-guard-strike.py'))
        self.assertTrue((self.root / 'lists/hardban.conf').read_text().startswith('198.51.100.1 all source=strike until='))
        self.assertIn('198.51.100.1\t2\t', (self.root / 'lists/strikes.tsv').read_text())
        self.assertTrue(all('custom_guard' in call.args[0] for call in run.call_args_list if call.args[0][0] != 'bash'))
        timeouts = [int(call.args[0][-1].split('timeout ')[1].split('s')[0]) for call in run.call_args_list if 'timeout ' in str(call.args[0])]
        self.assertTrue(timeouts and all(10790 <= seconds <= 10800 for seconds in timeouts))

    def test_packaged_paths(self):
        self.env.update(GUARD_ETC_DIR=str(self.root / 'etc'), GUARD_LIST_DIR=str(self.root / 'custom-lists'),
                        GUARD_LOG_DIR=str(self.root / 'custom-logs'), GUARD_ACTIVE_RULES=str(self.root / 'active.nft'))
        result = self.run_guard('printf "%s\\n" "$ALLOW_FILE" "$LOG_DIR" "$ACTIVE_RULES"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.root / 'custom-lists/whitelist.conf'), result.stdout)
        self.assertIn(str(self.root / 'custom-logs'), result.stdout)
        self.assertIn(str(self.root / 'active.nft'), result.stdout)

    def test_per_port_strikes_do_not_combine_different_ports(self):
        (self.root / 'etc/guard.conf').write_text('JAIL_PER_PORT=on\nSTRIKE_LADDER="2:1d"\n')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        rows = ['198.51.100.1 22001', '198.51.100.1 22003',
                '198.51.100.2 22001', '198.51.100.2 22001',
                '198.51.100.3 22003', '198.51.100.3 22003']
        (self.root / 'logs/banned.log').write_text(''.join(f'{stamp} ban4 {row}\n' for row in rows))
        (self.root / 'lists/whitelist.conf').write_text('198.51.100.3 22003\n')
        real_run = subprocess.run
        def run_command(args, **kwargs):
            return real_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch('subprocess.run', side_effect=run_command) as run, \
             mock.patch('shutil.chown'), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'bin/frp-ssh-guard-strike.py'))
        self.assertTrue((self.root / 'lists/hardban.conf').read_text().startswith('198.51.100.2 22001 source=strike until='))
        timeouts = [int(call.args[0][-1].split('timeout ')[1].split('s')[0])
                    for call in run.call_args_list if '{ 198.51.100.2 . 22001 timeout ' in str(call.args)]
        self.assertTrue(timeouts and all(86390 <= value <= 86400 for value in timeouts))

    def test_strike_history_scope_and_deadline_survive_mode_round_trip(self):
        import sqlite3
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        # Both legacy log and current event-store histories must retain scope.
        histories = [('198.51.100.11', '*'), ('198.51.100.12', '22001'),
                     ('198.51.100.13', '22001'), ('198.51.100.13', '22003')]
        (self.root / 'logs/banned.log').write_text(''.join(
            f'{stamp} ban4 {ip}' + ('' if scope == '*' else ' ' + scope) + '\n'
            for ip, scope in histories))
        (self.root / 'observations').mkdir()
        with contextlib.closing(sqlite3.connect(self.root / 'observations/events.sqlite3')) as db:
            db.execute('CREATE TABLE events (stamp INTEGER, ip TEXT, scope TEXT, kind TEXT)')
            db.executemany('INSERT INTO events VALUES (?,?,?,?)',
                           [(now, ip, scope, 'ban') for ip, scope in histories[:2]] +
                           [(now, '2001:db8::11', scope, 'ban') for scope in ('*', '*', '22003', '22003')])
            db.commit()
        expected = None
        real_run = subprocess.run
        def run_command(args, **kwargs):
            return real_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        for mode in ('on', 'off', 'on'):
            (self.root / 'etc/guard.conf').write_text(f'JAIL_PER_PORT={mode}\nSTRIKE_LADDER="2:1d"\n')
            with mock.patch.dict(os.environ, self.env, clear=True), \
                 mock.patch('subprocess.run', side_effect=run_command) as run, \
                 mock.patch('shutil.chown'), contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(ROOT / 'bin/frp-ssh-guard-strike.py'))
            text = (self.root / 'lists/hardban.conf').read_text()
            if expected is None:
                expected = text
            self.assertEqual(text, expected)
            self.assertIn('198.51.100.11 all source=strike until=', text)
            self.assertIn('198.51.100.12 22001 source=strike until=', text)
            self.assertIn('2001:db8::11 all source=strike until=', text)
            self.assertIn('2001:db8::11 22003 source=strike until=', text)
            self.assertNotIn('198.51.100.13', text)  # unrelated scoped offenses never combine
            writes = [call.args[0][-1] for call in run.call_args_list if 'element' in call.args[0]]
            self.assertTrue(writes)
            self.assertTrue(all((' . ' in value) == (mode == 'on') for value in writes))

    def run_strikes(self, offenses, excused=''):
        import sqlite3
        (self.root / 'etc/guard.conf').write_text('')  # shipped defaults: 12h, 3d, 7d, 30d, 90d
        (self.root / 'observations').mkdir(exist_ok=True)
        database = self.root / 'observations/events.sqlite3'
        database.unlink(missing_ok=True)
        with contextlib.closing(sqlite3.connect(database)) as db:
            db.execute('CREATE TABLE events (stamp INTEGER, ip TEXT, scope TEXT, kind TEXT)')
            db.executemany("INSERT INTO events VALUES (?, '198.51.100.40', '*', 'ban')", [(t,) for t in offenses])
            db.commit()
        (self.root / 'lists/excused.tsv').write_text(excused)
        real_run = subprocess.run
        def run_command(args, **kwargs):
            return real_run(args, **kwargs) if args[0] == 'bash' else subprocess.CompletedProcess(args, 0)
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch('subprocess.run', side_effect=run_command), \
             mock.patch('shutil.chown'), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'bin/frp-ssh-guard-strike.py'))
        rows = data_module().records((self.root / 'lists/hardban.conf').read_text())
        return {row.ip: row.expiry for row in rows}

    def test_offender_released_from_top_jail_gets_the_top_jail_again(self):
        day, now = 86400, int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        # Five offenses, each after the previous ban ended; the fifth earned 90 days,
        # which ended 60 days ago. A new offense now keeps the top step.
        chain = [now - 200 * day, now - 199 * day, now - 195 * day, now - 187 * day, now - 150 * day]
        self.assertEqual(self.run_strikes(chain), {})  # the 90-day jail is over
        expiry = self.run_strikes(chain + [now - 3600])['198.51.100.40']
        self.assertAlmostEqual(expiry, now - 3600 + 90 * day, delta=5)
        # The remembered step survives pruned history.
        self.assertAlmostEqual(self.run_strikes([now - 3600])['198.51.100.40'], expiry, delta=5)
        # A clean STRIKE_WINDOW after the release starts over at BAN_TIMEOUT (no strike ban).
        (self.root / 'lists/strike-levels.json').unlink()
        old_chain = [t - 150 * day for t in chain]
        self.assertEqual(self.run_strikes(old_chain + [now - 3600]), {})
        # unban/release forgives the remembered step.
        self.run_strikes(chain + [now - 3600])
        forgiven = f'198.51.100.40\t{now - 1800}\n'
        self.assertEqual(self.run_strikes([now - 60], excused=forgiven), {})

    def test_help_without_privileges(self):
        result = subprocess.run(['bash', str(ROOT / 'bin/frp-ssh-guard-persistent.sh'), '--help'],
                                env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Usage:', result.stdout)

    @unittest.skipUnless(os.environ.get('FRP_GUARD_LIVE_TESTS') == '1', 'requires root and isolated network namespace')
    def test_kernel_accepts_initial_and_replacement_rules(self):
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        # Covered and duplicate entries must not reach nftables interval sets.
        (self.root / 'lists/blocklist.conf').write_text(
            f'203.0.113.0/24 22001,22003\n203.0.113.9 22001\n203.0.113.0/24\n203.0.113.9\n'
            f'2001:db8::7 all until={expiry}\n2001:db8::/64\n'
            f'[22001-22003]\n198.51.100.78 source=runtime until={expiry}\n')
        (self.root / 'lists/whitelist.conf').write_text(
            f'[22,22001]\n198.51.100.77 source=learned until={expiry}\n[22003]\n198.51.100.0/24\n198.51.100.79\n')
        initial = self.rules('22001\n22003\n', config='SSH_SLOW_PROTECTION=on\nSSH_SLOW_BEHAVIOR=on\n')
        replacement = self.rules('22001\n22003\n', config='SSH_SLOW_PROTECTION=on\nSSH_SLOW_BEHAVIOR=on\n'
                                 'JAIL_PER_PORT=on\n', active=True)
        self.assertIn('slow v4', initial.stdout)
        self.assertIn('observe v4', initial.stdout)
        self.assertIn('set wideban4', replacement.stdout)
        self.assertEqual(initial.returncode, 0, initial.stderr)
        self.assertEqual(replacement.returncode, 0, replacement.stderr)
        a, b = self.root / 'initial.nft', self.root / 'replacement.nft'
        a.write_text(initial.stdout); b.write_text(replacement.stdout)
        # The element updates the sampler and strike manager make, on the live table.
        table = 'inet frp_ssh_persistent_guard'
        helpers = (f'add element {table} known4 {{ 198.51.100.77 . 22001 timeout 600s }}\n'
                   f'delete element {table} known4 {{ 198.51.100.77 . 22001 }}\n'
                   f'add element {table} known4 {{ 198.51.100.77 . 22001 timeout 900s }}\n'
                   f'add element {table} wideban4 {{ 203.0.113.70 timeout 12h }}\n'
                   f'add element {table} ban4 {{ 203.0.113.71 . 22003 timeout 12h }}\n'
                   f'add element {table} saved_ban4 {{ 203.0.113.72 timeout 1s }}\n'
                   f'delete element {table} saved_ban4 {{ 203.0.113.72 }}\n'
                   f'add element {table} saved_ban4 {{ 203.0.113.72 timeout 259200s }}\n')
        c = self.root / 'helpers.nft'
        c.write_text(helpers)
        subprocess.run(['unshare', '--net', 'sh', '-ec',
                        'nft -c -f "$1"; nft -f "$1"; nft -c -f "$2"; nft -f "$2"; nft -f "$3"; '
                        'nft -j list set inet frp_ssh_persistent_guard known4 | grep -q 198.51.100.77',
                        'sh', str(a), str(b), str(c)], check=True)


class SourceManifestTests(unittest.TestCase):
    def test_runtime_and_original_archives_excluded(self):
        spec = importlib.util.spec_from_file_location('build', ROOT / 'scripts/build.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        paths = [str(p.relative_to(ROOT)) for p in module.source_paths()]
        self.assertIn('bin/frp-ssh-guard-persistent.sh', paths)
        self.assertIn('packaging/postinst', paths)
        for p in paths:
            self.assertFalse(p.startswith(('lists/', 'logs/', '.git/', '.aws/', '.codex/', '.agents/', '.private-artifacts/')))
            self.assertFalse(p.endswith(('.zip', '.tar.gz', '.deb', '.tsv')))
            self.assertNotIn(p, ('etc/guard.conf', 'etc/settings.conf', 'etc/ports.conf', 'etc/active.nft'))


if __name__ == '__main__': unittest.main()
