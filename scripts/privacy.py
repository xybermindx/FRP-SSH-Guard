#!/usr/bin/env python3
"""Check public source and packages without printing private values."""
import argparse
import hashlib
import importlib.util
import io
import ipaddress
import json
import lzma
import gzip
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 16 * 1024 * 1024
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
IPV6 = re.compile(r'(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![\w:])')
EXAMPLES = tuple(ipaddress.ip_network(n) for n in (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))
LOCAL = tuple(ipaddress.ip_address(n) for n in ('0.0.0.0', '127.0.0.1', '::', '::1'))
PRIVATE_DIRS = {'.private-artifacts', '.aws', '.codex', '.agents', '.frp-ssh-guard', 'lists', 'logs', 'observations'}
LIVE_FILES = {'etc/settings.conf', 'etc/guard.conf', 'etc/ports.conf', 'etc/active.nft',
              'events.sqlite3', 'events.sqlite3-journal', 'events.sqlite3-wal', 'events.sqlite3-shm', 'applied.conf', 'auth-state.json', 'unified-state.json', 'learn-cursor.json', 'etc/user-home.json'}
ARCHIVES = ('.zip', '.tar.gz', '.tgz', '.tar.xz', '.tar', '.deb', '.rpm', '.bundle')


def rpm_sections(data):
    """Header (names, scripts, descriptions) and decompressed payload of an RPM, without rpm tools."""
    if data[:4] != b'\xed\xab\xee\xdb' or len(data) < 112:
        raise ValueError('not an RPM package')

    def header(offset):
        if data[offset:offset + 3] != b'\x8e\xad\xe8':
            raise ValueError('invalid RPM header')
        count, size = struct.unpack('>II', data[offset + 8:offset + 16])
        end = offset + 16 + count * 16 + size
        if end > len(data):
            raise ValueError('truncated RPM header')
        return data[offset:end], end
    signature, offset = header(96)
    offset += -offset % 8  # the signature is padded to 8 bytes
    main, offset = header(offset)
    payload = data[offset:]
    if payload[:2] == b'\x1f\x8b':
        payload = gzip.decompress(payload)
    elif payload[:6] == b'\xfd7zXZ\x00':
        payload = lzma.decompress(payload)
    else:
        raise ValueError('unsupported RPM payload compression; review it separately')
    return signature + main, payload


def cpio_members(data):
    """(name, is_file, content) of each member of a newc/crc cpio archive."""
    offset = 0
    while True:
        head = data[offset:offset + 110]
        if len(head) < 110 or head[:6] not in (b'070701', b'070702'):
            raise ValueError('invalid cpio payload')
        mode, size, name_size = (int(head[i:i + 8], 16) for i in (14, 54, 94))
        name_end = offset + 110 + name_size
        name = data[offset + 110:name_end - 1].decode('utf-8', 'replace')
        start = name_end + (-name_end % 4)
        if name == 'TRAILER!!!':
            return
        yield name, mode & 0o170000 == 0o100000, data[start:start + size]
        offset = start + size + (-(start + size) % 4)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, stderr=subprocess.DEVNULL)


class Rules(list):
    def __init__(self, patterns, public_line_hashes=()):
        super().__init__(patterns)
        self.public_line_hashes = set(public_line_hashes)


def load_rules(required):
    value = os.environ.get('FRP_GUARD_PRIVACY_RULES', '')
    filename = os.environ.get('FRP_GUARD_PRIVACY_RULES_FILE', '')
    if not value and not filename:
        try:
            filename = git('config', '--get', 'frpGuard.privacyRules').decode().strip()
        except subprocess.CalledProcessError:
            pass
    if not value and filename:
        value = Path(filename).read_text()
    if not value:
        if required:
            raise ValueError('private rules required')
        return []
    config = json.loads(value)
    patterns = config['patterns']
    if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
        raise ValueError('invalid private rules')
    approved = config.get('public_line_hashes', [])
    if not isinstance(approved, list) or not all(isinstance(h, str) and re.fullmatch(r'[0-9a-f]{64}', h) for h in approved):
        raise ValueError('invalid public line hashes')
    return Rules([re.compile(p, re.IGNORECASE) for p in patterns], approved)


def private_ips(text):
    for regex in (IPV4, IPV6):
        for match in regex.finditer(text):
            try:
                ip = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if ip not in LOCAL and not any(ip.version == n.version and ip in n for n in EXAMPLES):
                yield match


class Audit:
    def __init__(self, rules):
        self.rules, self.findings, self.count = rules, set(), 0

    def report(self, location, reason):
        for rule in self.rules:
            location = rule.sub('[private]', location)
        for match in reversed(list(private_ips(location))):
            location = location[:match.start()] + '[private]' + location[match.end():]
        self.findings.add((location[:240], reason))

    def text(self, location, data):
        self.count += 1
        if len(data) > LIMIT:
            raise ValueError('file exceeds review limit')
        text = data.decode('utf-8', 'replace')
        # Source fixtures can encode line boundaries rather than contain newlines.
        text = re.sub(r'\\[nrt]', '\n', text)
        # Exact owner-approved public attribution can be exempted without
        # weakening deployment-name rules elsewhere. IP/key checks still apply.
        approved = getattr(self.rules, 'public_line_hashes', set())
        private_text = '\n'.join('' if hashlib.sha256(line.encode()).hexdigest() in approved else line
                                 for line in text.splitlines())
        if any(rule.search(private_text) for rule in self.rules):
            self.report(location, 'private identifier or deployment port')
        if any(private_ips(text)):
            self.report(location, 'non-documentation IP address')
        if re.search(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----', text):
            self.report(location, 'private key material')

    def source(self, name, data):
        if (any(p in PRIVATE_DIRS or p == '.env' or p.startswith('.env.') for p in Path(name).parts)
                or name in LIVE_FILES or name.endswith(ARCHIVES + ('.log', '.tsv'))):
            self.report(name, 'deployment data or archive must not be tracked')
        self.text(name, name.encode() + b'\n' + data)

    def member(self, location, name, data):
        if name.endswith(ARCHIVES):
            self.report(location, 'nested archive requires separate review')
        self.text(location, name.encode() + b'\n' + data)

    def archive(self, name, data):
        stream, total = io.BytesIO(data), 0
        if zipfile.is_zipfile(stream):
            with zipfile.ZipFile(stream) as archive:
                for m in archive.infolist():
                    total += m.file_size
                    if m.file_size > LIMIT or total > LIMIT * 8:
                        raise ValueError('archive exceeds review limit')
                    if not m.is_dir():
                        self.member(name + '::' + m.filename, m.filename, archive.read(m))
        else:
            with tarfile.open(fileobj=stream, mode='r:*') as archive:
                for m in archive:
                    total += m.size
                    if m.size > LIMIT or total > LIMIT * 8:
                        raise ValueError('archive exceeds review limit')
                    self.text(name + '::' + m.name, (m.name + '\n' + m.linkname).encode())
                    if m.isfile():
                        self.member(name + '::' + m.name, m.name, archive.extractfile(m).read())

    def artifact(self, path):
        if path.suffix == '.rpm':
            header, payload = rpm_sections(path.read_bytes())
            self.text(path.name + '::header', header)
            total = 0
            for name, regular, content in cpio_members(payload):
                total += len(content)
                if len(content) > LIMIT or total > LIMIT * 8:
                    raise ValueError('archive exceeds review limit')
                self.text(path.name + '::' + name, name.encode())
                if regular:
                    self.member(path.name + '::' + name, name, content)
        elif path.suffix == '.deb':
            for flag in ('--fsys-tarfile', '--ctrl-tarfile'):
                result = subprocess.run(['dpkg-deb', flag, str(path)], capture_output=True, check=True)
                self.archive(path.name, result.stdout)
        elif path.name.endswith(ARCHIVES):
            self.archive(path.name, path.read_bytes())
        else:
            self.text(path.name, path.read_bytes())


def source_paths():
    spec = importlib.util.spec_from_file_location('guard_build', ROOT / 'scripts/build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_paths()


def audit_index(audit):
    for entry in git('ls-files', '--stage', '-z').split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            mode, oid, stage = meta.split()
            if stage != b'0' or mode == b'160000':
                raise ValueError('unmerged entry or submodule needs review')
            audit.source(name.decode(), git('cat-file', 'blob', oid.decode()))


def audit_history(audit):
    seen = set()
    for commit in git('rev-list', '--all').decode().splitlines():
        audit.text('commit metadata', git('cat-file', 'commit', commit))
        for entry in git('ls-tree', '-rz', commit).split(b'\0'):
            if entry:
                meta, name = entry.split(b'\t', 1)
                mode, kind, oid = meta.split()
                if kind != b'blob':
                    raise ValueError('submodule needs review')
                if (name, oid) not in seen:
                    seen.add((name, oid))
                    audit.source(name.decode(), git('cat-file', 'blob', oid.decode()))
    for tag in git('for-each-ref', '--format=%(objectname)', 'refs/tags').decode().splitlines():
        if git('cat-file', '-t', tag).strip() == b'tag':
            audit.text('tag metadata', git('cat-file', 'tag', tag))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--source', action='store_true')
    mode.add_argument('--staged', action='store_true')
    mode.add_argument('--history', action='store_true')
    mode.add_argument('--artifacts', nargs='+', type=Path)
    parser.add_argument('--require-private', action='store_true')
    args = parser.parse_args(argv)
    try:
        audit = Audit(load_rules(args.require_private))
        if args.staged:
            audit_index(audit)
        elif args.history:
            audit_history(audit)
        elif args.artifacts:
            for path in args.artifacts:
                audit.artifact(path)
        elif args.source:
            for path in source_paths():
                audit.source(str(path.relative_to(ROOT)), path.read_bytes())
        else:
            for name in git('ls-files', '-z').decode().split('\0'):
                if name:
                    path = ROOT / name
                    audit.source(name, os.readlink(path).encode() if path.is_symlink() else path.read_bytes())
        for location, reason in sorted(audit.findings):
            print(f'Privacy check: {json.dumps(location)}: {reason}', file=sys.stderr)
        if audit.findings:
            return 1
        print(f'Privacy check passed ({audit.count} inputs; private rules {"enabled" if audit.rules else "not configured"}).')
        return 0
    except (OSError, ValueError, KeyError, TypeError, re.error, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile):
        print('Privacy check could not complete. Check private rules, inputs and tools locally.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
