"""Unprivileged rule-generation tests; no host firewall or services are changed."""
import importlib.util
import contextlib
import datetime
import gzip
import io
import os
from pathlib import Path
import runpy
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

    def test_configured_default_manual_ban(self):
        (self.root / 'etc/guard.conf').write_text('BAN_TIMEOUT=3h\n')
        result = self.run_guard('NFTP=echo; table_active() { return 0; }; cmd_ban 198.51.100.1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('timeout 3h', result.stdout)

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
        self.assertEqual((self.root / 'lists/hardban.conf').read_text(), '198.51.100.1\n')
        self.assertIn('198.51.100.1\t2\t', (self.root / 'lists/strikes.tsv').read_text())
        self.assertTrue(all('custom_guard' in call.args[0] for call in run.call_args_list if call.args[0][0] != 'bash'))
        self.assertTrue(any('timeout 10800s' in str(call.args[0]) for call in run.call_args_list))

    def test_packaged_paths(self):
        self.env.update(GUARD_ETC_DIR=str(self.root / 'etc'), GUARD_LIST_DIR=str(self.root / 'custom-lists'),
                        GUARD_LOG_DIR=str(self.root / 'custom-logs'), GUARD_ACTIVE_RULES=str(self.root / 'active.nft'))
        result = self.run_guard('printf "%s\\n" "$ALLOW_FILE" "$LOG_DIR" "$ACTIVE_RULES"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.root / 'custom-lists/whitelist.conf'), result.stdout)
        self.assertIn(str(self.root / 'custom-logs'), result.stdout)
        self.assertIn(str(self.root / 'active.nft'), result.stdout)

    def test_help_without_privileges(self):
        result = subprocess.run(['bash', str(ROOT / 'bin/frp-ssh-guard-persistent.sh'), '--help'],
                                env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Usage:', result.stdout)

    @unittest.skipUnless(os.environ.get('FRP_GUARD_LIVE_TESTS') == '1', 'requires root and isolated network namespace')
    def test_kernel_accepts_initial_and_replacement_rules(self):
        initial = self.rules('22001\n22003\n')
        replacement = self.rules('22001\n22003\n', active=True)
        self.assertEqual(initial.returncode, 0, initial.stderr)
        self.assertEqual(replacement.returncode, 0, replacement.stderr)
        a, b = self.root / 'initial.nft', self.root / 'replacement.nft'
        a.write_text(initial.stdout); b.write_text(replacement.stdout)
        subprocess.run(['unshare', '--net', 'sh', '-ec',
                        'nft -c -f "$1"; nft -f "$1"; nft -c -f "$2"; nft -f "$2"', 'sh', str(a), str(b)], check=True)


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
