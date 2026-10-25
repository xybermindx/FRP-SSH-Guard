#!/usr/bin/env python3
"""Parse editable data without executing it; manage an administrator's home files."""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
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


def migrate(base, state, units, user):
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
    atomic_write(dropin / '50-user-home.conf', content, 0o644)
    atomic_write(base / 'user-home.json', json.dumps({'user': user, 'directory': str(directory)}) + '\n', 0o644)
    return directory


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
        directory.mkdir(mode=0o700, exist_ok=True)
        files = json.load(sys.stdin)
        for name, content in files.items():
            path = directory / name
            if path.exists() or path.is_symlink():
                if path.is_symlink() or path.read_text() != content:
                    raise ValueError('Existing home files differ; no configuration switch was made.')
        for name, content in files.items():
            path = directory / name
            if not path.exists():
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as output:
                    output.write(content)
    elif action == 'migrate':
        print(migrate(*args))
    else:
        raise ValueError('Unknown input operation.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
