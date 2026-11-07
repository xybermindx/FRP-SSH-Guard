#!/usr/bin/env python3
"""Build reproducible, allowlisted source archives and architecture-independent deb/rpm packages."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NAME = "frp-ssh-guard"
SOURCE_FILES = [
    ".gitignore", "VERSION", "PACKAGE_REVISION", "LICENSE", "README.md", "README.zh-CN.md", "CHANGELOG.md",
    "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "Makefile", "install.sh", "uninstall.sh",
]
SOURCE_DIRS = ["bin", "etc", "packaging", "scripts", "tests", "docs", ".github"]


def versions():
    upstream = (ROOT / "VERSION").read_text().strip()
    revision = (ROOT / "PACKAGE_REVISION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", upstream):
        raise ValueError("VERSION must be MAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[1-9][0-9]*", revision):
        raise ValueError("PACKAGE_REVISION must be a positive integer without leading zeros")
    return upstream, f"{upstream}-{revision}"


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
            path.parent.name == "hooks" or
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


def nftables_minimum():
    """One minimum for every package format, taken from the Debian control file."""
    match = re.search(r"nftables \(>= ([0-9.]+)\)", (ROOT / "packaging/control").read_text())
    if not match:
        raise ValueError("packaging/control must state the nftables minimum")
    return match[1]


def stage_tree(stage):
    """Installed files shared by the deb and rpm packages (identical payloads)."""
    for path in (ROOT / "bin").glob("*"):
        if path.suffix in (".sh", ".py"):
            copy(path, stage / "usr/lib" / NAME / path.name, 0o755)
    copy(ROOT / "packaging/run", stage / "usr/lib" / NAME / "run", 0o755)
    copy(ROOT / "packaging/lifecycle.sh", stage / "usr/lib" / NAME / "lifecycle.sh", 0o755)
    copy(ROOT / "VERSION", stage / "usr/lib" / NAME / "VERSION")
    (stage / "usr/sbin").mkdir(parents=True)
    (stage / "usr/sbin" / NAME).symlink_to("../lib/frp-ssh-guard/run")
    for path in (ROOT / "packaging/systemd").iterdir():
        copy(path, stage / "usr/lib/systemd/system" / path.name)
    # A default is installed by the lifecycle script only on fresh installs, so
    # upgrading cannot mask a user's legacy guard.conf/ports.conf configuration.
    copy(ROOT / "etc/settings.conf.example", stage / "usr/share" / NAME / "settings.conf.default")
    copy(ROOT / "packaging/logrotate", stage / "etc/logrotate.d" / NAME)
    doc = stage / "usr/share/doc" / NAME
    for name in ("README.md", "README.zh-CN.md", "CHANGELOG.md", "SECURITY.md"):
        copy(ROOT / name, doc / name)
    copy(ROOT / "LICENSE", doc / "copyright")
    for path in (ROOT / "docs").glob("*.md"):
        copy(path, doc / path.name)
    for path in (ROOT / "etc").glob("*.example"):
        copy(path, doc / "examples" / path.name)


def normalize(stage, epoch):
    for path in sorted(stage.rglob("*"), reverse=True) + [stage]:
        if not path.is_symlink():
            if path.is_dir(): path.chmod(0o755)
            os.utime(path, (epoch, epoch))


def build_deb(version, epoch, output):
    with tempfile.TemporaryDirectory(prefix="frp-ssh-guard-build-") as tmp:
        stage = Path(tmp) / NAME
        control = stage / "DEBIAN"
        control.mkdir(parents=True)
        (control / "control").write_text((ROOT / "packaging/control").read_text().replace("@VERSION@", version))
        for name in ("preinst", "postinst", "prerm", "postrm"):
            copy(ROOT / "packaging" / name, control / name, 0o755)
        stage_tree(stage)
        (control / "conffiles").write_text("/etc/logrotate.d/frp-ssh-guard\n")
        payload = sorted(p for p in stage.rglob("*") if p.is_file() and not p.is_symlink() and control not in p.parents)
        size = sum(p.stat().st_size for p in payload)
        with (control / "control").open("a") as f:
            f.write(f"Installed-Size: {(size + 1023) // 1024}\n")
        (control / "md5sums").write_text("".join(
            f"{hashlib.md5(p.read_bytes()).hexdigest()}  {p.relative_to(stage)}\n" for p in payload))
        normalize(stage, epoch)
        upstream = version.split("-", 1)[0]
        target = output / f"{NAME}_{upstream}.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(target)],
                       check=True, env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch)})
    return target


OWNED_DIRS = (f"/usr/lib/{NAME}", f"/usr/share/{NAME}", f"/usr/share/doc/{NAME}")


def rpm_files(stage):
    """%files entries for the staged tree: the package owns only its own directories."""
    lines = []
    for path in sorted(stage.rglob("*")):
        name = "/" + str(path.relative_to(stage))
        if path.is_symlink():
            lines.append(name)
        elif path.is_dir():
            if name.startswith(OWNED_DIRS):
                lines.append("%dir " + name)
        else:
            mode = f"{path.stat().st_mode & 0o777:04o}"
            marker = ("%config(noreplace) " if name.startswith("/etc/") else
                      "%doc " if name.startswith("/usr/share/doc/") else "")
            lines.append(f"{marker}%attr({mode},root,root) {name}")
    return lines


def render_spec(stage, version):
    upstream, release = version.split("-", 1)
    text = (ROOT / "packaging/rpm/frp-ssh-guard.spec.in").read_text()
    for key, value in (("@UPSTREAM@", upstream), ("@RELEASE@", release), ("@NFTABLES@", nftables_minimum()),
                       ("@STAGE@", str(stage)), ("@FILES@", "\n".join(rpm_files(stage)))):
        text = text.replace(key, value)
    return text


RPM_DEFINES = {
    # Reproducible output: fixed host/time, clamped mtimes, gzip payload, no post-processing.
    "_buildhost": "reproducible", "use_source_date_epoch_as_buildtime": "1",
    "clamp_mtime_to_source_date_epoch": "1", "_binary_payload": "w9.gzdio",
    "__os_install_post": "%{nil}", "debug_package": "%{nil}", "_build_id_links": "none",
}


def build_rpm(version, epoch, output):
    if not shutil.which("rpmbuild"):
        raise ValueError("rpmbuild is required to build the .rpm package (install the rpm package)")
    upstream, release = version.split("-", 1)
    with tempfile.TemporaryDirectory(prefix="frp-ssh-guard-rpm-") as tmp:
        tmp = Path(tmp)
        stage = tmp / "stage"
        stage_tree(stage)
        normalize(stage, epoch)
        spec = tmp / f"{NAME}.spec"
        spec.write_text(render_spec(stage, version))
        top = tmp / "top"
        for name in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            (top / name).mkdir(parents=True)
        command = ["rpmbuild", "-bb", "--quiet", "--define", f"_topdir {top}", "--define", f"_rpmdir {tmp / 'out'}"]
        for key, value in RPM_DEFINES.items():
            command += ["--define", f"{key} {value}"]
        subprocess.run(command + [str(spec)], check=True,
                       env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch), "LC_ALL": "C", "TZ": "UTC"})
        target = output / f"{NAME}-{upstream}.noarch.rpm"
        shutil.copyfile(tmp / "out/noarch" / f"{NAME}-{upstream}-{release}.noarch.rpm", target)
    return target


def rpm_available():
    if shutil.which("rpmbuild"):
        return True
    if os.environ.get("FRP_GUARD_REQUIRE_RPM") == "1":
        raise ValueError("rpmbuild is required for this release build (install the rpm package)")
    print("Note: rpmbuild not found; the .rpm package is skipped.", file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["all", "deb", "rpm", "source", "release", "version", "bump-revision"])
    args = parser.parse_args()
    try:
        version, package_version = versions()
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.kind == "version":
        print(package_version)
        return
    if args.kind == "bump-revision":
        revision = int(package_version.rsplit("-", 1)[1]) + 1
        (ROOT / "PACKAGE_REVISION").write_text(f"{revision}\n")
        print(f"{version}-{revision}")
        return
    subprocess.run([sys.executable, str(ROOT / 'scripts/privacy.py'), '--source'], check=True)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1792022400"))
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    artifacts = []
    if args.kind in ("all", "deb", "release"): artifacts.append(build_deb(package_version, epoch, output))
    try:
        if args.kind == "rpm" or args.kind in ("all", "release") and rpm_available():
            artifacts.append(build_rpm(package_version, epoch, output))
    except ValueError as error:
        parser.error(str(error))
    if args.kind in ("all", "source"): artifacts.extend(build_source(version, epoch, output))
    if args.kind in ("all", "release"):
        sums = output / "SHA256SUMS"
        sums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in artifacts))
        artifacts.append(sums)
    subprocess.run([sys.executable, str(ROOT / 'scripts/privacy.py'), '--artifacts',
                    *(str(path) for path in artifacts)], check=True)
    for path in artifacts: print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
