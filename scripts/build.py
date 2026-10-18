#!/usr/bin/env python3
"""Build reproducible, allowlisted source and architecture-independent deb files."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "frp-ssh-guard"
SOURCE_FILES = [
    ".gitignore", "VERSION", "LICENSE", "README.md", "README.zh-CN.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "SECURITY.md", "Makefile", "install.sh", "uninstall.sh",
]
SOURCE_DIRS = ["bin", "etc", "packaging", "scripts", "tests", "docs", ".github"]


def source_paths():
    paths = [ROOT / name for name in SOURCE_FILES]
    for directory in SOURCE_DIRS:
        for path in (ROOT / directory).rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".tmp"):
                continue
            if directory == "etc" and not path.name.endswith(".example"):
                continue
            paths.append(path)
    return sorted(paths)


def executable(path):
    return (path.suffix in (".sh", ".py") or
            path.parent.name == "packaging" and path.name in
            ("run", "preinst", "postinst", "prerm", "postrm"))


def copy(src, dest, mode=0o644):
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    dest.chmod(mode)


def build_source(version, epoch, output):
    prefix = f"{NAME}-{version}"
    tar_path = output / f"{prefix}.tar.gz"
    zip_path = output / f"{prefix}-src.zip"
    # ZIP's fixed 1980 timestamp is intentional; tar/deb use SOURCE_DATE_EPOCH.
    with tar_path.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar, zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for path in source_paths():
                name = str(Path(prefix) / path.relative_to(ROOT))
                data = path.read_bytes()
                mode = 0o755 if executable(path) else 0o644
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(data), epoch, mode
                info.uname = info.gname = "root"
                tar.addfile(info, io.BytesIO(data))
                zi = zipfile.ZipInfo(name)
                zi.create_system = 3
                zi.external_attr = (0o100000 | mode) << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(zi, data)
    return [tar_path, zip_path]


def build_deb(version, epoch, output):
    with tempfile.TemporaryDirectory(prefix="frp-ssh-guard-build-") as tmp:
        stage = Path(tmp) / NAME
        control = stage / "DEBIAN"
        control.mkdir(parents=True)
        (control / "control").write_text((ROOT / "packaging/control").read_text().replace("@VERSION@", version))
        for name in ("preinst", "postinst", "prerm", "postrm"):
            copy(ROOT / "packaging" / name, control / name, 0o755)
        for path in (ROOT / "bin").glob("*"):
            if path.suffix in (".sh", ".py"):
                copy(path, stage / "usr/lib" / NAME / path.name, 0o755)
        copy(ROOT / "packaging/run", stage / "usr/lib" / NAME / "run", 0o755)
        (stage / "usr/sbin").mkdir(parents=True)
        (stage / "usr/sbin" / NAME).symlink_to("../lib/frp-ssh-guard/run")
        for path in (ROOT / "packaging/systemd").iterdir():
            copy(path, stage / "usr/lib/systemd/system" / path.name)
        # A default is installed by postinst only on fresh installs, so upgrading
        # cannot mask a user's legacy guard.conf/ports.conf configuration.
        copy(ROOT / "etc/settings.conf.example", stage / "usr/share" / NAME / "settings.conf.default")
        copy(ROOT / "packaging/logrotate", stage / "etc/logrotate.d" / NAME)
        (control / "conffiles").write_text("/etc/logrotate.d/frp-ssh-guard\n")
        doc = stage / "usr/share/doc" / NAME
        for name in ("README.md", "README.zh-CN.md", "CHANGELOG.md", "SECURITY.md"):
            copy(ROOT / name, doc / name)
        copy(ROOT / "LICENSE", doc / "copyright")
        for path in (ROOT / "docs").glob("*.md"):
            copy(path, doc / path.name)
        for path in (ROOT / "etc").glob("*.example"):
            copy(path, doc / "examples" / path.name)
        payload = sorted(p for p in stage.rglob("*") if p.is_file() and not p.is_symlink() and control not in p.parents)
        size = sum(p.stat().st_size for p in payload)
        with (control / "control").open("a") as f:
            f.write(f"Installed-Size: {(size + 1023) // 1024}\n")
        (control / "md5sums").write_text("".join(
            f"{hashlib.md5(p.read_bytes()).hexdigest()}  {p.relative_to(stage)}\n" for p in payload))
        for path in sorted(stage.rglob("*"), reverse=True) + [stage]:
            if not path.is_symlink():
                if path.is_dir(): path.chmod(0o755)
                os.utime(path, (epoch, epoch))
        target = output / f"{NAME}_{version}.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(target)],
                       check=True, env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch)})
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["all", "deb", "source", "release"])
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        parser.error("VERSION must be MAJOR.MINOR.PATCH")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1792022400"))
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    artifacts = []
    if args.kind in ("all", "deb", "release"): artifacts.append(build_deb(version, epoch, output))
    if args.kind in ("all", "source"): artifacts.extend(build_source(version, epoch, output))
    if args.kind in ("all", "release"):
        sums = output / "SHA256SUMS"
        sums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in artifacts))
        artifacts.append(sums)
    for path in artifacts: print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
