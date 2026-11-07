"""Package ordering, metadata and deb/rpm payloads, without installing on the host."""
import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard_build', ROOT / 'scripts/build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class PackageVersionTests(unittest.TestCase):
    def test_debian_upgrade_order(self):
        versions = ['0.0.4', '0.0.5', '0.0.5-1', '0.0.5-2', '0.0.5-10', '0.0.6-1', '0.0.6-4', '0.0.7-1', '0.0.7-2', '0.0.7-3', '0.0.7-4', '0.0.8-1', '0.0.9-1']
        for older, newer in zip(versions, versions[1:]):
            with self.subTest(older=older, newer=newer):
                subprocess.run(['dpkg', '--compare-versions', newer, 'gt', older], check=True)

    def test_reject_invalid_version_inputs(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(build, 'ROOT', Path(tmp)):
            for upstream, revision in [('v0.0.5', '1'), ('0.0.5-1', '1'),
                                       ('0.0.5', '0'), ('0.0.5', '-1'), ('0.0.5', '01'),
                                       ('0.0.5', '1\n2'), ('0.0.5', '')]:
                with self.subTest(upstream=upstream, revision=revision):
                    (build.ROOT / 'VERSION').write_text(upstream)
                    (build.ROOT / 'PACKAGE_REVISION').write_text(revision)
                    with self.assertRaises(ValueError):
                        build.versions()

    def test_explicit_bump_keeps_application_version(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(build, 'ROOT', Path(tmp)):
            (build.ROOT / 'VERSION').write_text('0.0.5\n')
            (build.ROOT / 'PACKAGE_REVISION').write_text('9\n')
            with mock.patch('sys.argv', ['build.py', 'bump-revision']), contextlib.redirect_stdout(io.StringIO()):
                build.main()
            self.assertEqual(build.versions(), ('0.0.5', '0.0.5-10'))
            self.assertEqual((build.ROOT / 'VERSION').read_text(), '0.0.5\n')

    def test_package_metadata_and_export_retain_versions(self):
        upstream, package_version = build.versions()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            package = build.build_deb(package_version, 1792022400, output)
            self.assertEqual(package.name, f'frp-ssh-guard_{upstream}.deb')
            metadata = subprocess.check_output(['dpkg-deb', '-f', str(package), 'Version'], text=True)
            self.assertEqual(metadata.strip(), package_version)
            subprocess.run(['dpkg-deb', '-x', str(package), str(output / 'payload')], check=True)
            self.assertEqual((output / 'payload/usr/lib/frp-ssh-guard/VERSION').read_text().strip(), upstream)
            archive, _ = build.build_source(upstream, 1792022400, output)
            with tarfile.open(archive) as tar:
                prefix = f'frp-ssh-guard-{upstream}'
                for name in ('VERSION', 'PACKAGE_REVISION'):
                    self.assertEqual(tar.extractfile(f'{prefix}/{name}').read(), (ROOT / name).read_bytes())


class RpmPackageTests(unittest.TestCase):
    def staged_spec(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        stage = Path(tmp.name) / 'stage'
        build.stage_tree(stage)
        build.normalize(stage, 1792022400)
        return stage, build.render_spec(stage, '0.0.9-1')

    def test_spec_metadata_dependencies_and_scriptlets(self):
        _, spec = self.staged_spec()
        for line in ('Version:        0.0.9', 'Release:        1', 'BuildArch:      noarch', 'AutoReqProv:    no',
                     'Requires:       nftables >= ' + build.nftables_minimum(), 'Requires:       python3 >= 3.9',
                     'Requires:       (iproute or iproute2)', 'Requires:       systemd', 'Requires:       diffutils', 'Recommends:     logrotate'):
            self.assertIn(line + '\n', spec)
        self.assertIn('nftables (>= ' + build.nftables_minimum() + ')', (ROOT / 'packaging/control').read_text())
        sections = {}
        for part in spec.split('\n%')[1:]:
            name, _, body = part.partition('\n')
            sections[name] = body
        self.assertIn('/usr/lib/frp-ssh-guard/lifecycle.sh configure', sections['post'])
        # Only an erase (count 0) stops protection; upgrades and reinstalls keep it.
        self.assertIn('if [ "$1" -eq 0 ]; then\n    /usr/lib/frp-ssh-guard/lifecycle.sh before-remove', sections['preun'])
        self.assertIn('if [ "$1" -eq 1 ]; then', sections['pre'])
        self.assertIn('daemon-reload', sections['postun'])
        self.assertNotIn('@', spec.replace('noreply@', ''))

    def test_rpm_files_equal_the_deb_payload(self):
        stage, spec = self.staged_spec()
        files = spec.split('%defattr(-,root,root,-)\n', 1)[1].splitlines()
        listed = {line.split()[-1] for line in files if not line.startswith('%dir ')}
        owned = {line.split()[-1] for line in files if line.startswith('%dir ')}
        self.assertIn('%config(noreplace) %attr(0644,root,root) /etc/logrotate.d/frp-ssh-guard', files)
        self.assertIn('%attr(0755,root,root) /usr/lib/frp-ssh-guard/lifecycle.sh', files)
        self.assertIn('%doc %attr(0644,root,root) /usr/share/doc/frp-ssh-guard/README.md', files)
        self.assertIn('/usr/sbin/frp-ssh-guard', listed)
        self.assertEqual(owned, {'/usr/lib/frp-ssh-guard', '/usr/share/frp-ssh-guard', '/usr/share/doc/frp-ssh-guard',
                                 '/usr/share/doc/frp-ssh-guard/examples'})  # never /usr, /etc or systemd's directory
        with tempfile.TemporaryDirectory() as tmp:
            _, package_version = build.versions()
            package = build.build_deb(package_version, 1792022400, Path(tmp))
            deb = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)])
            with tarfile.open(fileobj=io.BytesIO(deb)) as tar:
                payload = {'/' + m.name.lstrip('./') for m in tar if not m.isdir()}
        self.assertEqual(listed, payload)

    @unittest.skipUnless(shutil.which('rpmbuild') and shutil.which('rpm'), 'requires rpmbuild and rpm')
    def test_rpm_metadata_name_and_reproducibility(self):
        upstream, package_version = build.versions()
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            first = build.build_rpm(package_version, 1792022400, Path(one))
            second = build.build_rpm(package_version, 1792022400, Path(two))
            self.assertEqual(first.name, f'frp-ssh-guard-{upstream}.noarch.rpm')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            query = subprocess.check_output(['rpm', '-qp', '--qf', '%{VERSION}-%{RELEASE} %{ARCH}', str(first)], text=True)
            self.assertEqual(query, package_version + ' noarch')


class LifecycleTests(unittest.TestCase):
    def test_debian_scripts_delegate_to_the_shared_lifecycle(self):
        postinst = (ROOT / 'packaging/postinst').read_text()
        prerm = (ROOT / 'packaging/prerm').read_text()
        self.assertIn('configure) exec /usr/lib/frp-ssh-guard/lifecycle.sh configure', postinst)
        self.assertIn('remove|deconfigure) exec /usr/lib/frp-ssh-guard/lifecycle.sh before-remove', prerm)
        self.assertNotIn('upgrade', prerm.split('case', 1)[1].split('esac')[0])  # upgrades never stop the guard

    def test_lifecycle_actions_and_usage(self):
        script = ROOT / 'packaging/lifecycle.sh'
        subprocess.run(['sh', '-n', str(script)], check=True)
        result = subprocess.run(['sh', str(script), 'unknown'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('configure|before-remove', result.stderr)
        text = script.read_text()
        # The shared steps keep every behavior of the previous Debian postinst.
        for step in ('auto-home', 'upgrade-settings', 'frp-ssh-guard-lists.py" upgrade', '_upgrade', 'policy-rc.d',
                     'settings.conf.default', 'Do not reload the systemd manager'):
            self.assertIn(step, text)


if __name__ == '__main__':
    unittest.main()
