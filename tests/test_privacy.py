"""Privacy regression fixtures use invented names and documentation addresses."""
import contextlib
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

    def test_tracked_deployment_data_is_rejected_without_private_rules(self):
        audit = privacy.Audit([])
        audit.source('lists/learned.conf', b'198.51.100.10')
        audit.source('.private-artifacts/backup.bundle', b'example')
        self.assertEqual(len(audit.findings), 2)


if __name__ == '__main__':
    unittest.main()
