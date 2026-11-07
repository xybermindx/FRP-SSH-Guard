"""Privacy regression fixtures use invented names and documentation addresses."""
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('privacy', ROOT / 'scripts/privacy.py')
privacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(privacy)


class PrivacyTests(unittest.TestCase):
    def test_public_attribution_exception_is_exact_and_keeps_ip_checks(self):
        line = 'Credit: example-private-host team.'
        rules = privacy.Rules([re.compile('example-private-host')], [hashlib.sha256(line.encode()).hexdigest()])
        approved = privacy.Audit(rules)
        approved.text('example', line.encode())
        self.assertFalse(approved.findings)
        for changed in (line + ' deployment', 'example-private-host', line + '\nexample-private-host tunnel'):
            audit = privacy.Audit(rules)
            audit.text('example', changed.encode())
            self.assertTrue(audit.findings)
        audit = privacy.Audit(privacy.Rules([], [hashlib.sha256(str(ipaddress.ip_address(1)).encode()).hexdigest()]))
        audit.text('example', str(ipaddress.ip_address(1)).encode())
        self.assertTrue(audit.findings)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(privacy, 'ROOT', self.root).start()
        mock.patch.dict(os.environ, {
            'FRP_GUARD_PRIVACY_RULES': json.dumps({'patterns': ['example-private-host']}),
            'FRP_GUARD_PRIVACY_RULES_FILE': '',
        }).start()

    def run_check(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = privacy.main(list(args))
        return status, output.getvalue()

    def git(self, *args):
        subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)

    def init_git(self):
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Example Contributor')
        self.git('config', 'user.email', 'contributor@example.invalid')

    def test_documentation_ips_pass_and_other_addresses_fail(self):
        audit = privacy.Audit([])
        audit.text('example', b'198.51.100.10 2001:db8::1 127.0.0.1 ::1')
        self.assertFalse(audit.findings)
        audit.text('example', str(ipaddress.ip_address(1)).encode())
        self.assertTrue(audit.findings)

    def test_private_content_and_path_are_not_printed(self):
        path = self.root / 'example-private-host.txt'
        path.write_text('Example-Private-Host')
        status, output = self.run_check('--artifacts', str(path), '--require-private')
        self.assertEqual(status, 1)
        self.assertNotIn('example-private-host', output.lower())
        self.assertIn('[private]', output)

    def test_identifiers_after_escaped_whitespace_are_checked(self):
        audit = privacy.Audit([re.compile(r'\b24001\b')])
        audit.text('example', b'22001\\n24001')
        self.assertTrue(audit.findings)

    def test_missing_or_invalid_private_rules_fail_closed(self):
        for value in ('', '{', '{"patterns":[]}', '{"patterns":["["]}'):
            with mock.patch.dict(os.environ, {'FRP_GUARD_PRIVACY_RULES': value}), \
                    mock.patch.object(privacy, 'git', side_effect=subprocess.CalledProcessError(1, 'git')):
                status, output = self.run_check('--require-private')
            self.assertEqual(status, 2)
            self.assertNotIn('Traceback', output)

    def test_staged_snapshot_is_checked_even_if_worktree_is_clean(self):
        self.init_git()
        path = self.root / 'example.txt'
        path.write_text('example-private-host')
        self.git('add', 'example.txt')
        path.write_text('public example')
        self.assertEqual(self.run_check('--staged', '--require-private')[0], 1)
        self.git('add', 'example.txt')
        self.assertEqual(self.run_check('--staged', '--require-private')[0], 0)

    def test_history_checks_removed_content_and_commit_messages(self):
        self.init_git()
        path = self.root / 'example.txt'
        path.write_text('example-private-host')
        self.git('add', 'example.txt')
        self.git('commit', '-m', 'Initial example')
        path.write_text('public example')
        self.git('add', 'example.txt')
        self.git('commit', '-m', 'Update example')
        self.assertEqual(self.run_check('--history', '--require-private')[0], 1)

    def test_archives_scan_content_and_reject_nested_archives(self):
        path = self.root / 'example.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('docs/example.txt', 'example-private-host')
        self.assertEqual(self.run_check('--artifacts', str(path), '--require-private')[0], 1)
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('backup.zip', b'opaque')
        self.assertEqual(self.run_check('--artifacts', str(path), '--require-private')[0], 1)

    @staticmethod
    def fake_rpm(files, header_text=b'example package', compress=None):
        """A minimal RPM: lead, signature and main headers, then a cpio payload."""
        import gzip
        import struct

        def header(blob):
            data = blob + b'\0'
            return (b'\x8e\xad\xe8\x01' + bytes(4) + struct.pack('>II', 1, len(data))
                    + struct.pack('>iiii', 1000, 6, 0, 1) + data)
        signature = header(b'signature')
        cpio = b''
        for name, content in list(files) + [('TRAILER!!!', b'')]:
            encoded = name.encode() + b'\0'
            mode = 0 if name == 'TRAILER!!!' else 0o100644
            entry = b'070701' + b''.join(b'%08x' % value for value in
                                         (0, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(encoded), 0))
            entry += encoded + bytes(-(110 + len(encoded)) % 4)
            cpio += entry + content + bytes(-len(content) % 4)
        return (b'\xed\xab\xee\xdb' + bytes(92) + signature + bytes(-(96 + len(signature)) % 8)
                + header(header_text) + (compress or gzip.compress)(cpio))

    def test_rpm_payload_and_scripts_are_scanned_without_rpm_tools(self):
        import lzma
        clean = self.root / 'example.noarch.rpm'
        clean.write_bytes(self.fake_rpm([('./usr/share/doc/example/README.md', b'198.51.100.10 example')]))
        self.assertEqual(self.run_check('--artifacts', str(clean), '--require-private')[0], 0)
        address = str(ipaddress.ip_address(1)).encode()  # not a documentation address
        for files, header, compress in (([('./usr/lib/example/run', address)], b'example package', None),
                                        ([('./etc/example.conf', b'example-private-host')], b'example', lzma.compress),
                                        ([('./usr/lib/example/run', b'#!/bin/sh')], b'%post\nexample-private-host', None),
                                        ([('./usr/lib/example/backup.zip', b'opaque')], b'example', None)):
            with self.subTest(files=files[0][0], header=header):
                path = self.root / 'planted.noarch.rpm'
                path.write_bytes(self.fake_rpm(files, header, compress))
                self.assertEqual(self.run_check('--artifacts', str(path), '--require-private')[0], 1)
        unknown = self.root / 'unknown.noarch.rpm'
        unknown.write_bytes(self.fake_rpm([('./x', b'x')], compress=lambda data: b'\x28\xb5\x2f\xfd' + data))
        with self.assertRaises(ValueError):
            privacy.Audit([]).artifact(unknown)

    def test_tracked_deployment_data_is_rejected_without_private_rules(self):
        audit = privacy.Audit([])
        audit.source('lists/learned.conf', b'198.51.100.10')
        audit.source('.private-artifacts/backup.bundle', b'example')
        audit.source('.frp-ssh-guard/blocklist.conf', b'198.51.100.10')
        audit.source('auth-state.json', b'{}')
        audit.source('etc/user-home.json', b'{}')
        self.assertEqual(len(audit.findings), 5)


if __name__ == '__main__':
    unittest.main()
