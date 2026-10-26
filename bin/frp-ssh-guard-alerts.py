#!/usr/bin/env python3
"""Bounded local alerts. Home I/O runs with the registered owner's privileges."""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys


def size_bytes(value):
    match = re.fullmatch(r'([1-9][0-9]*)(KiB|MiB)', value)
    if not match:
        raise ValueError('Invalid alert size')
    size = int(match[1]) * (1024 if match[2] == 'KiB' else 1048576)
    if not 1024 <= size <= 104857600:
        raise ValueError('Alert size must be 1KiB to 100MiB')
    return size


def merge(path, incoming, cap):
    """Caller holds the runtime lock. Pin the directory and reject symlinks."""
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = None
    try:
        existing = ''
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            fd = None
        if fd is not None:
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                    raise ValueError('Unsafe alert file')
                existing = source.read(cap + 1024).decode('utf-8', errors='replace')
        # Each generated line starts with fixed-width UTC microseconds and has a
        # stable event ID. A set also makes spool retries idempotent.
        lines = sorted(set(existing.splitlines(keepends=True) + incoming.splitlines(keepends=True)), reverse=True)
        kept, used = [], 0
        for line in lines:
            length = len(line.encode())
            if not line.endswith('\n') or length > 1024:
                continue
            if used + length > cap:
                break
            kept.append(line)
            used += length
        temporary = '.alert-' + os.urandom(12).hex()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as output:
            output.write(''.join(kept))
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def deliver(config, state_dir, lines=''):
    """Failure to write alerts never interrupts detection or enforcement."""
    cap = size_bytes(config['ALERT_LOG_MAX_SIZE'])
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
            payload = [str(Path(owner['directory']) / 'alerts.log'), spool.read_text(), cap]
            subprocess.run([sys.executable, str(Path(__file__).resolve()), 'write'],
                           input=json.dumps(payload), text=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
        else:
            merge(Path(config['MANUAL_DIR']) / 'alerts.log', spool.read_text(), cap)
        spool.unlink()
        return True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('Local alerts pending or unavailable; protection continues.', file=sys.stderr)
        return False


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['write']:
            merge(*json.load(sys.stdin))
        elif len(sys.argv) == 3 and sys.argv[1] == 'inspect':
            path = Path(sys.argv[2])
            if path.is_symlink() or path.parent.is_symlink() or not os.access(path.parent, os.W_OK | os.X_OK):
                raise ValueError('Unsafe or unavailable alert directory')
            if path.exists() and (not path.is_file() or path.stat().st_uid != os.geteuid()
                                  or path.stat().st_nlink != 1 or not os.access(path, os.R_OK | os.W_OK)):
                raise ValueError('Unsafe or inaccessible alert file')
        else:
            raise ValueError('Expected write or inspect')
    except (OSError, ValueError):
        sys.exit('Could not safely update local alerts.')
