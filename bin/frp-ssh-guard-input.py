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
from typing import NamedTuple

POLICY_KEYS = set('GUARD_TABLE PORT_MIN PORT_MAX EXCLUDE_PORTS EDIT_USER PROTECTED_PORTS '
    'PER_IP_RATE PER_IP_BURST GLOBAL_RATE GLOBAL_BURST BAN_TIMEOUT LOGIN_USERS MAX_LEARNED '
    'LEARN_TIMEOUT STRIKE_WINDOW STRIKE_MAX STRIKE_LADDER PROTECT_SERVER_SSH JAIL_PER_PORT '
    'SSH_AUTH_FAILURES SSH_INVALID_USER_FAILURES SSH_AUTH_WINDOW '
    'SSH_SLOW_PROTECTION SSH_SLOW_TOTAL_CONNECTIONS SSH_SLOW_PORT_CONNECTIONS SSH_SLOW_FAILURES SSH_SLOW_WINDOW '
    'LOG_MAX_SIZE SUBNET_REPORT_MIN_SOURCES SUBNET_REPORT_WINDOW '
    # Obsolete names, still read so older files keep working; upgrades convert them.
    'SSH_SLOW_MODE ALERT_LOG_MAX_SIZE'.split())

LIST_MARKER = '# FRP-SSH-Guard unified list'
_SECTIONS = [
    '# A section header chooses the ports for the lines below it:',
    '#   [all]                every protected port (and 22 when PROTECT_SERVER_SSH=on)',
    '#   [22]                 only this server\'s SSH port 22',
    '#   [22001]              only port 22001',
    '#   [22001,23000-23010]  several ports or ranges',
]
_APPLY = [
    '# Saving applies this file automatically while the guard is active; no reload',
    '# is needed. Apply at once: sudo frp-ssh-guard apply',
    '# Find mistakes: sudo frp-ssh-guard check (a rejected edit changes nothing).',
]
HEADERS = {
    'block': [LIST_MARKER,
        '# BLOCKLIST: sources listed here cannot open new connections to the chosen ports.',
        *_APPLY, '#', *_SECTIONS, '#',
        '# One IP or CIDR per line. A line WITHOUT a time is blocked FOREVER:',
        '#   203.0.113.10                     forever (nothing after the address)',
        '#   203.0.113.11 forever             forever (written out)',
        '#   198.51.100.0/24                  a whole subnet, forever',
        '#   2001:db8::10                     IPv6 works the same way',
        '# Timed blocks use tier= or until= (plain times such as 7d are rejected here):',
        '#   203.0.113.12 tier=1              BAN_TIMEOUT (default 6 hours)',
        '#   203.0.113.13 tier=2              1 day (tier=3: 3 days, tier=4: 7 days)',
        '#   203.0.113.14 tier=5              28 days (tiers 2-5 follow STRIKE_LADDER)',
        '#   203.0.113.15 until=2030-01-31T00:00:00Z   until this UTC date and time',
        '# The first apply adds until= to a tier line; delete until= to restart its period.',
        '#',
        '# The same from the command line (default: all protected ports, forever):',
        '#   sudo frp-ssh-guard block 203.0.113.10                  forever, all ports',
        '#   sudo frp-ssh-guard block 203.0.113.10 --ports 22001    forever, one port',
        '#   sudo frp-ssh-guard block 203.0.113.10 --for 7d         7 days',
        '#   sudo frp-ssh-guard unblock 203.0.113.10                remove its lines',
        '#   sudo frp-ssh-guard ban 203.0.113.10 12h                temporary (default BAN_TIMEOUT)',
        '#',
        '# Lines with source=runtime or source=strike are automatic bans; keep their until=.',
        '# Delete any line to unblock it (a new attack may add it again). To also forgive',
        '# its strike history: sudo frp-ssh-guard release 203.0.113.10',
        '# New automatic bans appear here within about 60 seconds. Reopen this file before',
        '# editing: saving an old copy removes newer automatic bans.',
        '# Whitelist entries win over this list; other firewalls are independent.'],
    'allow': [LIST_MARKER,
        '# WHITELIST: sources listed here bypass this guard\'s limits and bans on the chosen',
        '# ports, and are never counted by slow brute-force protection on any port.',
        *_APPLY, '#', *_SECTIONS, '#',
        '# One IP or CIDR per line. Manual entries never expire:',
        '#   198.51.100.10                    trusted on this section\'s ports',
        '#   198.51.100.0/24                  a whole subnet',
        '#   2001:db8::10                     IPv6 works the same way',
        '# The same from the command line:',
        '#   sudo frp-ssh-guard allow 198.51.100.10                 all protected ports',
        '#   sudo frp-ssh-guard allow 198.51.100.10 22001           one port',
        '#   sudo frp-ssh-guard unallow 198.51.100.10               remove its lines',
        '#',
        '# Lines with source=learned come from trusted logins to this server (LOGIN_USERS)',
        '# and expire at until=; keep that time. Delete any line to remove the trust',
        '# (a new trusted login may add it again).',
        '# Reopen this file before editing: saving an old copy removes newer learned entries.',
        '# Whitelist entries override this guard only; other firewalls are independent.'],
}
# The exact header shipped in v0.0.5 and v0.0.6. Only this text is refreshed.
_OLD_COMMON = [LIST_MARKER,
    '# [all] means every protected port (including 22 when enabled).',
    '# [22001] means only that port; comma-separated ports/ranges also work.',
    '# Add one IP or CIDR per line. A plain entry or explicit forever is permanent.',
    '# Block periods: forever or tier=1..5 (default 6h,1d,3d,7d,28d).',
    '# Tier 1 uses BAN_TIMEOUT; tiers 2..5 use STRIKE_LADDER, capped by STRIKE_MAX.',
    '# First apply saves until=. To start a new tier period, remove the old until=.',
    '# until=YYYY-MM-DDTHH:MM:SSZ is an absolute UTC expiry; never renewed by apply.']
_OLD_TAIL = ['# Delete an entry to remove it; a new login/attack may add it again.',
    '# Saves are watched while active. Apply now: sudo frp-ssh-guard apply',
    '# Settings changes still require check and reload. Do not edit a stale copy.',
    '# Kernel bans are sampled by the log timer (normally within 60 seconds).',
    '# Whitelist entries override this guard only; other firewalls are independent.']
LEGACY_HEADERS = {
    'block': _OLD_COMMON + ['# source=runtime/strike identifies automatic bans; keep their expiry.'] + _OLD_TAIL,
    'allow': _OLD_COMMON + ['# source=learned identifies learned trust; keep its expiry.'] + _OLD_TAIL,
}


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


class Row(NamedTuple):
    ip: str
    scope: str = '*'
    expiry: int = 0
    source: str = 'manual'
    tier: int = 0

    @property
    def key(self):
        return (self.ip, self.scope, self.source)


def list_lines(text, kind='block'):
    result = []
    section = '*'
    for number, line in enumerate(text.splitlines(), 1):
        words = line.split('#', 1)[0].split()
        if not words:
            continue
        try:
            if words[0].startswith('['):
                header = ' '.join(words)
                if not re.fullmatch(r'\[[^\[\]]+\]', header):
                    raise ValueError('Invalid section header; use [all], [22001] or [22001,23000-23010].')
                section = ports(header[1:-1])
                continue
            ip = address(words.pop(0))
            expiry, source, tier, scopes, seen, forever = 0, 'manual', 0, [], set(), False
            for word in words:
                if word == 'forever':
                    if forever:
                        raise ValueError('Duplicate forever.')
                    forever = True
                    continue
                if '=' not in word:
                    if not re.fullmatch(r'all|\*|[0-9][0-9,-]*', word):
                        raise ValueError(f'"{word}" is not a port list or option; use forever, '
                                         'tier=1..5 or until=YYYY-MM-DDTHH:MM:SSZ (no time means forever)')
                    scopes.append(word)
                    continue
                key, value = word.split('=', 1)
                if key in seen or key not in ('until', 'source', 'tier'):
                    raise ValueError(f'"{word}" is not a supported option; use forever, tier=, until= or source=')
                seen.add(key)
                if key == 'source':
                    source = value
                    continue
                if key == 'tier':
                    if kind != 'block':
                        raise ValueError('tier= is only used in the blocklist.')
                    if not re.fullmatch('[1-5]', value):
                        raise ValueError('Block tiers are 1 through 5.')
                    tier = int(value)
                    continue
                try:
                    stamp = dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
                except ValueError:
                    raise ValueError('until= needs a UTC time such as until=2030-01-31T00:00:00Z') from None
                expiry = int(stamp.replace(tzinfo=dt.timezone.utc).timestamp())
                if expiry <= 0:
                    raise ValueError('Expiry must be after the epoch.')
            if source not in (('manual', 'learned') if kind == 'allow' else ('manual', 'runtime', 'strike')):
                raise ValueError('Invalid entry source.')
            if source != 'manual' and not expiry:
                raise ValueError('Automatic entries need an absolute expiry.')
            if source != 'manual' and '/' in ip:
                raise ValueError('Automatic entries must be individual addresses.')
            if forever and (tier or expiry or source != 'manual'):
                raise ValueError('Choose forever or an expiry/tier.')
            if tier and source != 'manual':
                raise ValueError('Tiers apply to manual blocks.')
            if kind == 'allow' and expiry and '/' in ip:
                raise ValueError('Timed whitelist entries must be individual addresses.')
            if kind == 'allow' and expiry and source != 'learned':
                raise ValueError('Whitelist expiry belongs to learned entries.')
            scope = ports(' '.join(scopes)) if scopes else section
            result.append((number, Row(ip, scope, expiry, source, tier)))
        except ValueError as error:
            name = 'whitelist' if kind == 'allow' else 'blocklist'
            raise ValueError(f'Invalid {name} entry on line {number}: {error}') from error
    return result


def records(text, kind='block'):
    return [row for _, row in list_lines(text, kind)]


def entries(text, kind='block', now=None):
    return [(row.ip, row.scope, row.expiry) for row in records(text, kind)]


def trusted_sources(text, now=None):
    """Whitelisted on any port: never counted by slow brute-force protection.

    nftables interval sets reject overlapping elements, so permanent networks
    are collapsed and timed (learned) addresses inside them are dropped.
    """
    now = int(time.time()) if now is None else now
    permanent, timed = {4: [], 6: []}, {}
    for row in records(text, 'allow'):
        network = ipaddress.ip_network(row.ip, strict=False)
        if not row.expiry:
            permanent[network.version].append(network)
        elif row.expiry > now:
            timed[network] = max(timed.get(network, 0), row.expiry)
    collapsed = {version: list(ipaddress.collapse_addresses(networks)) for version, networks in permanent.items()}
    result = [(version, address(str(network)), 0) for version, networks in collapsed.items() for network in networks]
    for network, expiry in sorted(timed.items(), key=lambda item: (item[0].version, item[0])):
        if not any(network.subnet_of(wider) for wider in collapsed[network.version]):
            result.append((network.version, address(str(network)), expiry))
    return result


def format_entry(ip, scope, expiry=0, source='manual', tier=0):
    line = address(ip) + (' ' + scope if scope != '*' else ' all')
    if source != 'manual':
        line += ' source=' + source
    if tier:
        line += ' tier=' + str(tier)
    elif source == 'manual' and not expiry:
        line += ' forever'
    if expiry:
        line += ' until=' + dt.datetime.fromtimestamp(expiry, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return line


def resolve_tiers(rows, base, ladder, cap, now=None):
    now = int(time.time()) if now is None else now
    levels = {1: duration(base)}
    for token in ladder.split():
        threshold, value = token.split(':', 1)
        levels[int(threshold)] = min(duration(value), duration(cap))
    result = []
    for row in rows:
        if row.tier and not row.expiry:
            if row.tier not in levels:
                raise ValueError('This tier is absent from STRIKE_LADDER; configure its duration or use until=.')
            row = row._replace(expiry=now + levels[row.tier])
        result.append(row)
    return result


def refresh_header(original, kind):
    """Replace only the exact instructions an earlier release generated."""
    lines = original.splitlines()
    old = LEGACY_HEADERS[kind]
    if lines[:len(old)] != old:
        return original
    return '\n'.join(HEADERS[kind] + lines[len(old):]) + '\n'


def render_list(original, rows, kind):
    """Preserve comments and section order while replacing individual records."""
    original = refresh_header(original, kind)
    pending = {row.key: row for row in rows}
    indexed = dict(list_lines(original, kind))
    lines, scope = [], '*'
    if LIST_MARKER not in original.splitlines():
        lines.extend(HEADERS[kind] + ['', '[all]'])
    for number, line in enumerate(original.splitlines(), 1):
        old = indexed.get(number)
        if old is None:
            lines.append(line)
            stripped = line.split('#', 1)[0].strip()
            if stripped.startswith('['):
                scope = ports(stripped[1:-1])
            continue
        row = pending.pop(old.key, None)
        if row is None:
            continue
        if scope != row.scope:
            lines.append('[' + ('all' if row.scope == '*' else row.scope) + ']')
            scope = row.scope
        content = format_entry(*row).split(' ', 1)[1].split(' ', 1)
        # Scope belongs to the section, not to each address line.
        value = row.ip + (' ' + content[1] if len(content) > 1 else '')
        if '#' in line:
            value += ' #' + line.split('#', 1)[1]
        lines.append(value)
    for row in pending.values():
        if scope != row.scope:
            lines.extend(['', '[' + ('all' if row.scope == '*' else row.scope) + ']'])
            scope = row.scope
        flat = format_entry(*row).split(' ', 2)
        lines.append(row.ip + (' ' + flat[2] if len(flat) > 2 else ''))
    return '\n'.join(lines).rstrip() + '\n'


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


def replace_list(path, original, content):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('List paths must not be symbolic links.')
    current = path.read_text() if path.exists() else ''
    if current != original:
        raise ValueError('List changed while updating; retry apply.')
    atomic_write(path, content)


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
    rows = records(original, kind)  # reject malformed input before changing anything
    ip = address(ip)
    rows = [row for row in rows if not (row.ip == ip and
            (operation == 'remove' or row.scope == scope and row.source == 'manual'))]
    if operation == 'add':
        rows.append(Row(ip, scope, expiry))
    atomic_write(path, render_list(original, rows, kind))


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


# Text shipped by earlier releases. Only exact matches are replaced on upgrade.
LEGACY_SETTINGS_HEADER = [
    '# Edit this file, then: sudo frp-ssh-guard check && sudo frp-ssh-guard reload',
    '# First activation: sudo frp-ssh-guard enable',
    '# Saving alone does not change protection; reboot restores accepted settings.']
LEGACY_SLOW_COMMENTS = [
    ['# Independent long-window detector. observe reports without adding bans/strikes.',
     '# off disables it; enforce opts into the existing ban duration and jail scope.'],
    ['# Independent long-window detector, active only when PROTECT_SERVER_SSH=on.',
     '# Fresh installs enforce the existing ban duration and jail scope at the threshold.',
     '# observe reports without bans/strikes; off disables the long-window detector.',
     '# Upgrades preserve existing choices; legacy missing settings retain observe.'],
    ['# Preserve observation behavior for this older configuration.',
     '# Set enforce and check/reload to enable slow-probe bans.']]
# Renamed settings keep their value and position; the old comment is replaced.
RENAMED = {'ALERT_LOG_MAX_SIZE': 'LOG_MAX_SIZE'}
LEGACY_RENAMED_COMMENTS = {'ALERT_LOG_MAX_SIZE': [
    ['# Local alerts: newest complete record first, discard oldest records at the cap.',
     '# No rotated archives or remote notifications. Accepted settings change on reload.']]}
SWITCH_KEYS = ('EXCLUDE_PORTS', 'PROTECT_SERVER_SSH', 'JAIL_PER_PORT', 'SSH_SLOW_PROTECTION')
# Missing thresholds placed beside a related setting instead of at the end.
INSERT_BEFORE = {'SSH_SLOW_TOTAL_CONNECTIONS': 'SSH_SLOW_FAILURES',
                 'SSH_SLOW_PORT_CONNECTIONS': 'SSH_SLOW_FAILURES'}


def instructions(template):
    """The template's reload instructions, without its title line."""
    lines = template.splitlines()
    if '# === Ports and protection switches ===' not in lines:
        return []
    block = lines[1:lines.index('# === Ports and protection switches ===')]
    while block and not block[-1].strip():
        block.pop()
    return block


def template_comments(template):
    """Comment lines that precede each setting in the template."""
    result, comments = {}, []
    for line in template.splitlines(keepends=True):
        parsed = settings(line)
        if not parsed:
            comments.append(line)
            continue
        result[next(iter(parsed))] = ''.join(comments)
        comments = []
    return result


def merge_defaults(original, template):
    """Add missing settings and retire SSH_SLOW_MODE without changing other values."""
    present = settings(original)
    before = dict(present)
    settings(template)  # validate the trusted template before changing anything
    lines = original.splitlines(keepends=True)
    plain = [line.rstrip('\r\n') for line in lines]
    parsed_lines = [settings(line) for line in lines]
    edits, changes = [], []

    def where(*names):
        return [i for i, parsed in enumerate(parsed_lines) if set(names) & parsed.keys()]

    def edit(start, stop, text):
        edits.append((start, stop, text, len(edits)))

    def known_comments(index, blocks):
        # First line of a shipped comment block directly above line `index`.
        run = index
        while run > 0 and plain[run - 1].lstrip().startswith('#'):
            run -= 1
        for known in blocks:
            if plain[run:index][-len(known):] == known:
                return index - len(known)
        return index

    block = instructions(template)
    for index in range(len(plain) - len(LEGACY_SETTINGS_HEADER) + 1):
        if block and plain[index:index + len(LEGACY_SETTINGS_HEADER)] == LEGACY_SETTINGS_HEADER:
            edit(index, index + len(LEGACY_SETTINGS_HEADER), ''.join(line + '\n' for line in block))
            changes.append('instructions')
            break

    # Only explicit enforcement keeps slow bans; upgrades never add bans by themselves.
    legacy = present.get('SSH_SLOW_MODE')
    switch = present.get('SSH_SLOW_PROTECTION', 'on' if legacy == 'enforce' else 'off')
    for index in where('SSH_SLOW_MODE'):
        edit(known_comments(index, LEGACY_SLOW_COMMENTS), index + 1, '# Obsolete since 0.0.7; replaced by SSH_SLOW_PROTECTION=' + switch +
             ' (below JAIL_PER_PORT):\n# ' + plain[index].strip() + '\n')
    if legacy is not None:
        changes.append('SSH_SLOW_MODE')

    described = template_comments(template)
    for old_key, new_key in RENAMED.items():
        positions = where(old_key)
        for index in positions:
            if index == positions[-1] and new_key not in present:
                text = (described.get(new_key, '').lstrip('\r\n')
                        + re.sub(r'^(\s*(?:export\s+)?)' + old_key, r'\g<1>' + new_key, plain[index]) + '\n')
            else:
                text = '# Obsolete since 0.0.7; renamed ' + new_key + ':\n# ' + plain[index].strip() + '\n'
            edit(known_comments(index, LEGACY_RENAMED_COMMENTS.get(old_key, [])), index + 1, text)
        if positions:
            present.setdefault(new_key, present[old_key])
            changes.append(old_key)

    additions, switches, anchored, comments = [], [], {}, []
    for line in template.splitlines(keepends=True):
        parsed = settings(line)
        if not parsed:
            comments.append(line)
            continue
        key = next(iter(parsed))
        # An absent port selection can intentionally use legacy ports.conf.
        # Never shadow it with the template's empty selection.
        if key not in present and key != 'PROTECTED_PORTS':
            text = line.rstrip('\r\n') + '\n'
            if key == 'SSH_SLOW_PROTECTION':
                parsed[key] = switch
                text = ('# Converted from SSH_SLOW_MODE=' + legacy + ' during upgrade.\n' if legacy is not None else
                        '# Set to off during upgrade: this older configuration had no slow-probe bans.\n')
                if switch == 'off':
                    text += '# To enable it: set on, then sudo frp-ssh-guard check && sudo frp-ssh-guard reload\n'
                text += 'SSH_SLOW_PROTECTION=' + switch + '\n'
            text = ''.join(comments) + text
            if key in SWITCH_KEYS:
                switches.append((key, text))
            elif INSERT_BEFORE.get(key) in present:
                anchored.setdefault(INSERT_BEFORE[key], []).append(text)
            else:
                additions.append(text)
            present[key] = parsed[key]
            changes.append(key)
        comments = []

    # The slow switch belongs directly below an existing jail switch.
    jail = where('JAIL_PER_PORT')
    below_jail = [text for key, text in switches if key == 'SSH_SLOW_PROTECTION' and jail]
    group = [text for key, text in switches if not (key == 'SSH_SLOW_PROTECTION' and jail)]
    if group:
        ports = where('PROTECTED_PORTS', 'EXCLUDE_PORTS')
        position = ports[-1] + 1 if ports else 0
        edit(position, position, '\n# Missing port settings and protection switches added during installation.\n'
             + ''.join(group) + '\n')
    if below_jail:
        edit(jail[-1] + 1, jail[-1] + 1, ''.join(below_jail))
    for target, texts in anchored.items():
        position = where(target)[0]
        edit(position, position, ''.join(texts))

    # Apply from the bottom up. At one position, replace the existing line first,
    # then insert; earlier insertions stay above later ones.
    for start, stop, text, _ in sorted(edits, key=lambda item: (item[0], item[1] > item[0], item[3]), reverse=True):
        if start == len(lines) and lines and not lines[-1].endswith('\n'):
            text = '\n' + text
        lines[start:stop] = [text]
    updated = ''.join(lines)
    if additions:
        updated += ('\n\n# Missing defaults added by FRP-SSH-Guard during installation.\n'
                    '# Existing values are retained; policy changes need check/reload.\n'
                    + ''.join(additions))
    result = settings(updated)
    for old_key, new_key in RENAMED.items():
        if old_key in before:
            before.setdefault(new_key, before[old_key])
    obsolete = ('SSH_SLOW_MODE', *RENAMED)
    if (any(result.get(key) != value for key, value in before.items() if key not in obsolete)
            or any(key not in result for key in present if key not in obsolete)
            or any(key in result for key in obsolete)):
        raise ValueError('Settings merge would change an existing value; configuration retained.')
    return updated, changes


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
        if not keys or updated == original.decode('utf-8'):
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
    parts = []
    added = [key for key in keys if key not in ('SSH_SLOW_MODE', 'instructions', *RENAMED)]
    switch = settings(updated).get('SSH_SLOW_PROTECTION')
    if added:
        parts.append('added ' + ', '.join(added))
    if 'SSH_SLOW_MODE' in keys:
        parts.append('replaced obsolete SSH_SLOW_MODE with SSH_SLOW_PROTECTION=' + str(switch))
    for old_key, new_key in RENAMED.items():
        if old_key in keys:
            parts.append('renamed ' + old_key + ' to ' + new_key)
    if 'instructions' in keys:
        parts.append('refreshed the reload instructions')
    print('Settings updated: ' + '; '.join(parts) + '. Original saved as ' + Path(backup).name)
    if 'SSH_SLOW_PROTECTION' in keys and switch == 'off':
        print('Slow brute-force protection stays off for this older configuration. To enable it, set '
              'SSH_SLOW_PROTECTION=on, then run: sudo frp-ssh-guard check && sudo frp-ssh-guard reload')
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
        path, kind, *tier_settings = args
        now = int(time.time())
        rows = records(Path(path).read_text(), kind)
        if any(row.tier and not row.expiry for row in rows):
            if len(tier_settings) != 3:
                raise ValueError('Apply tier entries first so their expiry can be saved.')
            rows = resolve_tiers(rows, *tier_settings, now=now)
        # A runtime ban and a strike can share a key; restore the longer deadline
        # once. Keep both origins in the editable file, outside kernel encoding.
        automatic = {}
        for row in rows:
            if row.source in ('runtime', 'strike'):
                identity = (row.ip, row.scope)
                if identity not in automatic or row.expiry > automatic[identity].expiry:
                    automatic[identity] = row
        rows = [row for row in rows if row.source not in ('runtime', 'strike')] + list(automatic.values())
        for ip, scope, expiry, source, tier in rows:
            if expiry and expiry <= now:
                continue
            print(f'{6 if ":" in ip else 4}|{ip}|{scope}|{expiry}|{format_entry(ip, scope, expiry, source, tier)}')
    elif action == 'trusted':
        for version, value, expiry in trusted_sources(Path(args[0]).read_text()):
            print(f'{version}|{value}|{expiry}')
    elif action == 'replace-list':
        replace_list(*json.load(sys.stdin))
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
