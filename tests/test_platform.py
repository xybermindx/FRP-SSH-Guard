"""Platform requirements and doctor facts, with stub commands; nothing is installed."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT / 'bin/frp-ssh-guard-platform.sh'
SPEC = importlib.util.spec_from_file_location('platform_events', ROOT / 'bin/frp-ssh-guard-events.py')
events = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(events)
TOOLS = ('nft', 'python3', 'ss', 'jq', 'flock', 'systemctl', 'journalctl')


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        # Only coreutils the helper needs, so real system tools cannot leak in.
        for tool in ('sort', 'sed', 'head'):
            (self.bin / tool).symlink_to(shutil.which(tool))
        (self.root / 'systemd').mkdir()

    def stub(self, name, output=''):
        path = self.bin / name
        path.write_text('#!/bin/sh\nprintf "%s\\n" ' + repr(output) + '\n')
        path.chmod(0o755)

    def run_helper(self, body, systemd=True):
        env = {'PATH': str(self.bin), 'GUARD_SYSTEMD_RUNTIME': str(self.root / ('systemd' if systemd else 'none'))}
        return subprocess.run([shutil.which('bash'), '-c', f'. {PLATFORM}; {body}'], env=env,
                              capture_output=True, text=True)

    def supported(self, nft='nftables v1.0.6 (Lester Gooch #5)', python='3.9'):
        for tool in TOOLS:
            self.stub(tool)
        self.stub('nft', nft)
        self.stub('python3', python)

    def test_version_comparison(self):
        for version, minimum, expected in (('1.0.6', '1.0.6', 0), ('1.0.10', '1.0.6', 0), ('1.1.0', '1.0.6', 0),
                                           ('1.0.5', '1.0.6', 1), ('0.9.8', '1.0.6', 1), ('3.13', '3.9', 0),
                                           ('3.6', '3.9', 1)):
            with self.subTest(version=version, minimum=minimum):
                self.assertEqual(self.run_helper(f'version_at_least {version} {minimum}').returncode, expected)

    def test_supported_system_has_no_problems(self):
        self.supported()
        result = self.run_helper('platform_problems')
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.run_helper('platform_report').returncode, 0)

    def test_old_versions_missing_tools_and_no_systemd_are_reported(self):
        self.supported(nft='nftables v1.0.2 (Lester Gooch)', python='3.6')
        (self.bin / 'jq').unlink()
        result = self.run_helper('platform_problems', systemd=False)
        self.assertEqual(result.stdout.splitlines(), ['missing command: jq', 'systemd is not the running init system',
                                                      'nftables 1.0.2 is older than 1.0.6',
                                                      'python3 3.6 is older than 3.9'])
        report = self.run_helper('platform_report', systemd=False)
        self.assertEqual(report.returncode, 1)
        self.assertIn('  missing command: jq\n', report.stderr)
        self.assertIn('Install the dependencies with:', report.stderr)

    def test_install_hint_follows_the_package_manager(self):
        for manager, expected in (('apt-get', 'apt-get install nftables python3 iproute2'),
                                  ('dnf', 'dnf install nftables python3 iproute jq'),
                                  ('zypper', 'zypper install nftables python3 iproute2'),
                                  ('pacman', 'pacman -S --needed nftables python iproute2')):
            with self.subTest(manager=manager):
                for other in ('apt-get', 'dnf', 'zypper', 'pacman'):
                    (self.bin / other).unlink(missing_ok=True)
                self.stub(manager)
                self.assertIn(expected, self.run_helper('package_hint').stdout)
        for other in ('apt-get', 'dnf', 'zypper', 'pacman'):
            (self.bin / other).unlink(missing_ok=True)
        self.assertIn('with your package manager', self.run_helper('package_hint').stdout)

    def test_minimum_matches_the_package_dependencies(self):
        minimum = re.search(r'GUARD_MIN_NFTABLES=([0-9.]+)', PLATFORM.read_text())[1]
        self.assertIn(f'nftables (>= {minimum})', (ROOT / 'packaging/control').read_text())

    def test_installer_preflight_changes_nothing(self):
        self.supported()
        for tool in ('bash', 'dirname'):
            (self.bin / tool).symlink_to(shutil.which(tool))
        result = subprocess.run([str(self.bin / 'bash'), str(ROOT / 'install.sh'), '--preflight'],
                                env={'PATH': str(self.bin), 'GUARD_SYSTEMD_RUNTIME': str(self.root / 'systemd')},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('meets the FRP-SSH-Guard requirements', result.stdout)

    def test_doctor_platform_lines(self):
        (self.root / 'etc').mkdir()
        (self.root / 'etc/os-release').write_text('NAME="Example Linux"\nPRETTY_NAME="Example Linux 9"\n')
        (self.root / 'sys/fs/selinux').mkdir(parents=True)
        (self.root / 'sys/fs/selinux/enforce').write_text('1\n')

        def run(args, **kwargs):
            output = {'nft': 'nftables v1.0.9 (Old Doc Yak #3)\n'}.get(args[0], 'active\n')
            return subprocess.CompletedProcess(args, 0, stdout=output)
        lines = events.platform_lines(run=run, root=self.root)
        self.assertTrue(lines[0].startswith('Platform: Example Linux 9 ('))
        self.assertTrue(lines[1].startswith('nftables: 1.0.9; Python: '))
        self.assertEqual(lines[2], 'SELinux: enforcing')
        self.assertIn('firewalld: active', lines[3])
        self.assertIn('flush ruleset', lines[4])


if __name__ == '__main__':
    unittest.main()
