#!/usr/bin/env python3
"""Bounded local activity log. Home I/O runs with the registered owner's privileges."""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys


LOG_NAME = 'frp-ssh-guard.log'
LEGACY_NAME = 'alerts.log'  # name used up to v0.0.6; merged into LOG_NAME once


def size_bytes(value):
    match = re.fullmatch(r'([1-9][0-9]*)(KiB|MiB)', value)
    if not match:
        raise ValueError('Invalid log size')
    size = int(match[1]) * (1024 if match[2] == 'KiB' else 1048576)
    if not 1024 <= size <= 104857600:
        raise ValueError('Log size must be 1KiB to 100MiB')
    return size


def read_owned(directory, name, cap):
    """Read a regular single-link file owned by this user; None if it is absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError('Unsafe log file')
        return source.read(cap + 1024).decode('utf-8', errors='replace')


def merge(path, incoming, cap, legacy=None):
    """Caller holds the runtime lock. Pin the directory and reject symlinks."""
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = None
    try:
        existing = read_owned(directory, path.name, cap) or ''
        old = None
        if legacy and Path(legacy).parent == path.parent and Path(legacy).name != path.name:
            old = read_owned(directory, Path(legacy).name, cap)
        # Each generated line starts with fixed-width UTC microseconds and has a
        # stable event ID. A set also makes spool retries idempotent.
        lines = sorted(set(existing.splitlines(keepends=True) + (old or '').splitlines(keepends=True)
                           + incoming.splitlines(keepends=True)), reverse=True)
        kept, used = [], 0
        for line in lines:
            length = len(line.encode())
            if not line.endswith('\n') or length > 1024:
                continue
            if used + length > cap:
                break
            kept.append(line)
            used += length
        temporary = '.log-' + os.urandom(12).hex()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as output:
            output.write(''.join(kept))
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        if old is not None:
            os.unlink(Path(legacy).name, dir_fd=directory)
        os.fsync(directory)
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def deliver(config, state_dir, lines=''):
    """Failure to write the log never interrupts detection or enforcement."""
    cap = size_bytes(config['LOG_MAX_SIZE'])
    spool = Path(state_dir) / 'alerts-spool.log'
    try:
        merge(spool, lines, cap)
        base = Path(config['CONFIG_BASE']) / 'user-home.json'
        if base.exists():
            owner = json.loads(base.read_text())
            account = pwd.getpwnam(owner['user'])
            kwargs = {}
            if os.geteuid() == 0:
                kwargs.update(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
            elif os.geteuid() != account.pw_uid:
                raise ValueError('Wrong alert owner')
            # Read only the private root spool here, never a user-controlled file.
            home = Path(owner['directory'])
            payload = [str(home / LOG_NAME), spool.read_text(), cap, str(home / LEGACY_NAME)]
            subprocess.run([sys.executable, str(Path(__file__).resolve()), 'write'],
                           input=json.dumps(payload), text=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
        else:
            merge(Path(config['MANUAL_DIR']) / LOG_NAME, spool.read_text(), cap, Path(config['MANUAL_DIR']) / LEGACY_NAME)
        spool.unlink()
        return True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('Activity log pending or unavailable; protection continues.', file=sys.stderr)
        return False


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['write']:
            merge(*json.load(sys.stdin))
        elif len(sys.argv) == 3 and sys.argv[1] == 'inspect':
            path = Path(sys.argv[2])
            if path.is_symlink() or path.parent.is_symlink() or not os.access(path.parent, os.W_OK | os.X_OK):
                raise ValueError('Unsafe or unavailable log directory')
            if path.exists() and (not path.is_file() or path.stat().st_uid != os.geteuid()
                                  or path.stat().st_nlink != 1 or not os.access(path, os.R_OK | os.W_OK)):
                raise ValueError('Unsafe or inaccessible log file')
        else:
            raise ValueError('Expected write or inspect')
    except (OSError, ValueError):
        sys.exit('Could not safely update the activity log.')
