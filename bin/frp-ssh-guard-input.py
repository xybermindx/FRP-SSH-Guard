#!/usr/bin/env python3
"""Parse editable data without executing it; manage an administrator's home files."""
from contextlib import contextmanager
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time

POLICY_KEYS = set('GUARD_TABLE PORT_MIN PORT_MAX EXCLUDE_PORTS EDIT_USER PROTECTED_PORTS '
    'PER_IP_RATE PER_IP_BURST GLOBAL_RATE GLOBAL_BURST BAN_TIMEOUT LOGIN_USERS MAX_LEARNED '
    'LEARN_TIMEOUT STRIKE_WINDOW STRIKE_MAX STRIKE_LADDER PROTECT_SERVER_SSH JAIL_PER_PORT '
    'SSH_AUTH_FAILURES SSH_INVALID_USER_FAILURES SSH_AUTH_WINDOW'.split())


def settings(text):
    result = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*(?:export\s+)?([A-Z_][A-Z_0-9]*)\s*=\s*(.*?)\s*', line)
        if not match or match[1] not in POLICY_KEYS | {'GUARD_DIR'}:
            raise ValueError(f'Unsupported setting on line {number}; use plain KEY=value assignments.')
        values = shlex.split(match[2], comments=True, posix=True)
        if len(values) > 1:
            raise ValueError(f'Quote the setting value on line {number}.')
        if match[1] != 'GUARD_DIR':  # legacy path hint; never override trusted runtime paths
            result[match[1]] = values[0] if values else ''
    return result


def duration(value):
    match = re.fullmatch(r'([1-9][0-9]{0,8})([smhdw])', value)
    if not match:
        raise ValueError('Use a positive duration such as 30m, 6h or 7d.')
    return int(match[1]) * dict(s=1, m=60, h=3600, d=86400, w=604800)[match[2]]


def address(value):
    network = ipaddress.ip_network(value, strict=False)
    return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)


def ports(value):
    if value in ('', '*', 'all'):
        return '*'
    result = []
    for token in value.replace(',', ' ').split():
        if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', token):
            raise ValueError('Use all, or comma-separated TCP ports/ranges.')
        bounds = [int(p) for p in token.split('-')]
        if not 1 <= bounds[0] <= bounds[-1] <= 65535:
            raise ValueError('Ports must be 1–65535 and ranges ascending.')
        result.append('-'.join(map(str, bounds)))
    return ','.join(dict.fromkeys(result))


def entries(text, kind='block', now=None):
    now = int(time.time()) if now is None else now
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        words = line.split('#', 1)[0].split()
        if not words:
            continue
        try:
            ip = address(words.pop(0))
            expiry = 0
            if words and words[-1].startswith('until='):
                if kind != 'block':
                    raise ValueError('Only block entries support expiry.')
                stamp = words.pop()[6:]
                expiry = int(dt.datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc).timestamp())
            scope = ports(' '.join(words))
            result.append((ip, scope, expiry))
        except ValueError as error:
            raise ValueError(f'Invalid {kind} list entry on line {number}.') from error
    return result


def format_entry(ip, scope, expiry=0):
    line = address(ip) + (' ' + scope if scope != '*' else ' all')
    if expiry:
        line += ' until=' + dt.datetime.fromtimestamp(expiry, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return line


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.guard-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def location(base):
    path = Path(base) / 'user-home.json'
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    directory = data['directory']
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+/\.frp-ssh-guard', directory) or '..' in Path(directory).parts:
        raise ValueError('Invalid user configuration location.')
    return data


def as_user(user, args, data):
    account = pwd.getpwnam(user)
    kwargs = {}
    if os.geteuid() == 0:
        kwargs.update(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    elif account.pw_uid != os.geteuid():
        raise ValueError('Changing another account requires root.')
    subprocess.run([sys.executable, str(Path(__file__).resolve()), *args],
                   input=json.dumps(data), text=True, check=True, **kwargs)


def edit_list(path, kind, operation, ip, scope='*', expiry=0):
    path = Path(path)
    original = path.read_text() if path.exists() else ''
    entries(original, kind)  # reject malformed input before changing anything
    ip = address(ip)
    lines = []
    for line in original.splitlines():
        words = line.split('#', 1)[0].split()
        if words and address(words[0]) == ip:
            if operation == 'remove':
                continue
            previous = entries(line, kind)[0]
            if previous[1] == scope:
                continue  # replace this address/scope, including its expiry
        lines.append(line)
    if operation == 'add':
        lines.append(format_entry(ip, scope, expiry))
    atomic_write(path, '\n'.join(lines) + '\n')


def installer_user():
    """Use an explicit owner or sudo's invoking user; never guess from HOME/USER."""
    user = os.environ.get('FRP_GUARD_CONFIG_USER') or os.environ.get('SUDO_USER') or 'root'
    account = pwd.getpwnam(user)
    if not os.environ.get('FRP_GUARD_CONFIG_USER') and os.environ.get('SUDO_UID'):
        if str(account.pw_uid) != os.environ['SUDO_UID']:
            raise ValueError('Installer user metadata is inconsistent; existing configuration retained.')
    return account.pw_name


def follow_home(directory, state, command):
    """Retarget an active list watcher without daemon-reload or firewall changes."""
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'frp-ssh-guard-lists.path'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if active.returncode:
        return False
    # A transient path/service pair watches the new files until the next boot.
    # The persistent drop-in below handles later starts. Starting a path unit
    # does not run its service just because the watched files already exist.
    subprocess.run(['systemd-run', '--quiet', '--unit=frp-ssh-guard-home-lists',
        '--path-property=PathModified=' + str(directory / 'whitelist.conf'),
        '--path-property=PathModified=' + str(directory / 'blocklist.conf'),
        '--path-property=PartOf=frp-ssh-guard.service',
        '--property=PartOf=frp-ssh-guard.service',
        '--property=Requisite=frp-ssh-guard.service',
        '--property=After=frp-ssh-guard.service', '--property=Type=oneshot',
        '--setenv=GUARD_DIR=' + str(state), str(command), 'apply'], check=True)
    return True


def migrate(base, state, units, user, command=None):
    base, state, units = Path(base), Path(state), Path(units)
    existing = location(base)
    account = pwd.getpwnam(user)
    directory = Path(account.pw_dir) / '.frp-ssh-guard'
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+/\.frp-ssh-guard', str(directory)):
        raise ValueError('Home path must use ordinary letters, digits, dots, underscores or dashes.')
    if existing:
        if existing == {'user': user, 'directory': str(directory)}:
            return directory
        raise ValueError('A different home location is already configured; existing files were preserved.')
    source = base / 'settings.conf'
    if not source.exists():
        source = base / 'guard.conf'
    text = source.read_text()
    parsed = settings(text)
    if 'PROTECTED_PORTS' not in parsed and (base / 'ports.conf').exists():
        specs = [line.split('#', 1)[0].strip() for line in (base / 'ports.conf').read_text().splitlines()]
        text += '\nPROTECTED_PORTS=' + shlex.quote(','.join(s for s in specs if s)) + '\n'
    files = {'settings.conf': text}
    for name, kind in (('whitelist.conf', 'allow'), ('blocklist.conf', 'block')):
        path = state / 'lists' / name
        files[name] = path.read_text() if path.exists() else ''
        entries(files[name], kind)
    # File writes in a user-controlled home run as that user, not as root.
    as_user(user, ['create-home', str(directory)], files)
    dropin = units / 'frp-ssh-guard-lists.path.d'
    dropin.mkdir(parents=True, exist_ok=True)
    content = ('[Path]\nPathModified=\nPathModified=' + str(directory / 'whitelist.conf') +
               '\nPathModified=' + str(directory / 'blocklist.conf') + '\n')
    followed = False
    previous = (dropin / '50-user-home.conf').read_text() if (dropin / '50-user-home.conf').exists() else None
    try:
        followed = follow_home(directory, state, command) if command else False
        atomic_write(dropin / '50-user-home.conf', content, 0o644)
        atomic_write(base / 'user-home.json', json.dumps({'user': user, 'directory': str(directory)}) + '\n', 0o644)
    except Exception:
        if previous is None:
            (dropin / '50-user-home.conf').unlink(missing_ok=True)
        else:
            atomic_write(dropin / '50-user-home.conf', previous, 0o644)
        if followed:
            subprocess.run(['systemctl', 'stop', 'frp-ssh-guard-home-lists.path',
                            'frp-ssh-guard-home-lists.service'], check=False)
        raise
    if followed:
        # Only stop the old path watcher; leave the guard and timers running.
        stopped = subprocess.run(['systemctl', 'stop', 'frp-ssh-guard-lists.path'], check=False)
        if stopped.returncode:
            print('Home watcher is active; the old list watcher could not be stopped.', file=sys.stderr)
    return directory


@contextmanager
def installation_lock():
    # Match lifecycle/CLI lock order; installation never applies policy.
    lock_path = os.environ.get('GUARD_LOCK_FILE', '/run/frp-ssh-guard.lock')
    with open(lock_path + '.lifecycle', 'a') as lifecycle, open(lock_path, 'a') as runtime:
        deadline = time.monotonic() + 30
        for lock in (lifecycle, runtime):
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OSError('Another guard operation is running; configuration update was deferred.')
                    time.sleep(0.1)
        yield


def auto_home(base, state, units, command):
    with installation_lock():
        existing = location(base)
        if existing:
            return Path(existing['directory'])  # later upgrades retain the selected owner
        return migrate(base, state, units, installer_user(), command)


def merge_defaults(original, template):
    present = settings(original)
    settings(template)  # validate the trusted template before changing anything
    additions, switches, comments, keys = [], [], [], []
    for line in template.splitlines(keepends=True):
        parsed = settings(line)
        if not parsed:
            comments.append(line)
            continue
        key = next(iter(parsed))
        # An absent port selection can intentionally use legacy ports.conf.
        # Never shadow it with the template's empty selection.
        if key not in present and key != 'PROTECTED_PORTS':
            block = ''.join(comments) + line.rstrip('\r\n') + '\n'
            (switches if key in ('EXCLUDE_PORTS', 'PROTECT_SERVER_SSH', 'JAIL_PER_PORT') else additions).append(block)
            present[key] = parsed[key]
            keys.append(key)
        comments = []
    updated = original
    if switches:
        lines = original.splitlines(keepends=True)
        position = 0
        for number, line in enumerate(lines, 1):
            if {'PROTECTED_PORTS', 'EXCLUDE_PORTS'} & settings(line).keys():
                position = number
        before = ''.join(lines[:position])
        updated = (before + ('\n' if before and not before.endswith('\n') else '')
                   + '\n# Missing port settings and protection switches added during installation.\n'
                   + ''.join(switches) + '\n' + ''.join(lines[position:]))
    if additions:
        updated += ('\n\n# Missing defaults added by FRP-SSH-Guard during installation.\n'
                    '# Existing values are retained; policy changes need check/reload.\n'
                    + ''.join(additions))
    return updated, keys


def append_defaults(path, template):
    """Preserve the original bytes and metadata; save a private backup first."""
    path = Path(path)
    if path.parent.is_symlink():
        raise ValueError('Configuration directory must not be a symbolic link.')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        fcntl.flock(source, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError('Configuration must be a regular file owned by its selected administrator.')
        original = source.read()
        updated, keys = merge_defaults(original.decode('utf-8'), template)
        if not keys:
            return []
        descriptor, temporary = tempfile.mkstemp(prefix='.guard-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                # Changing files in a user home always runs as that user.
                target_info = os.fstat(output.fileno())
                if (target_info.st_uid, target_info.st_gid) != (info.st_uid, info.st_gid):
                    os.fchown(output.fileno(), info.st_uid, info.st_gid)
                os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
                output.write(updated.encode('utf-8'))
                output.flush()
                os.fsync(output.fileno())
            descriptor, backup = tempfile.mkstemp(prefix=path.name + '.before-upgrade-', dir=path.parent)
            with os.fdopen(descriptor, 'wb') as saved:
                os.fchmod(saved.fileno(), 0o600)
                saved.write(original)
                saved.flush()
                os.fsync(saved.fileno())
            # Detect a concurrent editor before replacing the file. Guard CLI
            # operations are already serialized by the installation locks.
            current = path.lstat()
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(current, field) != getattr(info, field) for field in fields):
                raise ValueError('Configuration changed during the update; retry installation.')
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print('Added missing settings: ' + ', '.join(keys) + '. Original saved as ' + Path(backup).name)
    return keys


def upgrade_settings(base, template):
    with installation_lock():
        selected = location(base)
        directory = Path(selected['directory']) if selected else Path(base)
        path = directory / 'settings.conf'
        if not path.exists() and not path.is_symlink() and (directory / 'guard.conf').exists():
            path = directory / 'guard.conf'
        defaults = Path(template).read_text()
        if selected:
            as_user(selected['user'], ['upgrade-user-settings'], [str(path), defaults])
        else:
            append_defaults(path, defaults)


def main():
    action, *args = sys.argv[1:]
    if action == 'settings':
        for key, value in settings(Path(args[0]).read_text()).items():
            print(key + '=' + shlex.quote(value))
    elif action == 'location':
        data = location(args[0])
        if data:
            print(data['directory'])
    elif action == 'host':
        print(ipaddress.ip_address(args[0]))
        if len(args) > 1:
            duration(args[1])
    elif action == 'snapshot':
        name = args[0]
        document = json.load(sys.stdin)
        for item in document.get('nftables', []):
            for element in item.get('set', {}).get('elem', []):
                value = element.get('elem', {}).get('val') if isinstance(element, dict) else element
                if isinstance(value, dict) and 'concat' in value:
                    ip, port = value['concat']
                    print(name, ipaddress.ip_address(ip), int(port))
                elif isinstance(value, str):
                    print(name, ipaddress.ip_address(value))
    elif action == 'read-list':
        path, kind = args
        now = int(time.time())
        for ip, scope, expiry in entries(Path(path).read_text(), kind):
            if expiry and expiry <= now:
                continue
            print(f'{6 if ":" in ip else 4}|{ip}|{scope}|{expiry}|{format_entry(ip, scope, expiry)}')
    elif action == 'edit-list':
        base, path, kind, operation, ip, scope, lifetime = args
        scope = ports(scope)
        expiry = int(time.time()) + duration(lifetime) if lifetime != 'forever' else 0
        entry = (path, kind, operation, address(ip), scope, expiry)
        data = location(base)
        if data and Path(path).parent == Path(data['directory']):
            as_user(data['user'], ['edit-user-list'], entry)
        else:
            edit_list(*entry)
    elif action == 'edit-user-list':
        edit_list(*json.load(sys.stdin))
    elif action == 'create-home':
        directory = Path(args[0])
        if directory.is_symlink():
            raise ValueError('The home configuration directory must not be a symbolic link.')
        directory.mkdir(mode=0o700, exist_ok=True)
        files = json.load(sys.stdin)
        for name, content in files.items():
            path = directory / name
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file() or path.read_text() != content:
                    raise ValueError('Existing home files differ; no configuration switch was made.')
        directory.chmod(0o700)
        for name, content in files.items():
            path = directory / name
            if not path.exists():
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as output:
                    output.write(content)
            path.chmod(0o600)
    elif action == 'migrate':
        print(migrate(*args))
    elif action == 'auto-home':
        try:
            print('Editable settings and manual lists: ' + str(auto_home(*args)))
        except (ValueError, OSError, KeyError, subprocess.CalledProcessError):
            # Do not leave a working package unconfigured because a home is
            # unavailable or contains conflicting files. No existing file is replaced.
            print('Automatic home setup could not complete; existing configuration was retained. '
                  'Check the settings path with frp-ssh-guard --help and retry config-home when ready.',
                  file=sys.stderr)
    elif action == 'upgrade-settings':
        try:
            upgrade_settings(*args)
        except (ValueError, OSError, KeyError, subprocess.CalledProcessError):
            print('Missing settings could not be added; existing configuration and active policy were retained. '
                  'Check file access/format and retry package installation with --reinstall.', file=sys.stderr)
    elif action == 'upgrade-user-settings':
        append_defaults(*json.load(sys.stdin))
    else:
        raise ValueError('Unknown input operation.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
