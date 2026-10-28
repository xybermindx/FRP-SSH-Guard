"""Debian upgrade ordering and package metadata, without installing on the host."""
import contextlib
import importlib.util
import io
from pathlib import Path
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
        versions = ['0.0.4', '0.0.5', '0.0.5-1', '0.0.5-2', '0.0.5-10', '0.0.6-1', '0.0.6-4', '0.0.7-1', '0.0.7-2', '0.0.7-3']
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


if __name__ == '__main__':
    unittest.main()
