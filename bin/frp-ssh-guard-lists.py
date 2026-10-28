#!/usr/bin/env python3
"""Unify editable and runtime lists without resetting the firewall or timers.

Callers hold the guard runtime lock. Home writes run as the registered owner.
The root cache allows boot and operation while that home is unavailable.
"""
import grp
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

LIB = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('guard_inputs', LIB / 'frp-ssh-guard-input.py')
data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(data)
KEYS = ('GUARD_TABLE', 'MANUAL_DIR', 'CONFIG_BASE', 'LEARN_TIMEOUT', 'STRIKE_MAX',
        'LOGIN_USERS', 'MAX_LEARNED', 'PROTECTED_PORTS', 'JAIL_PER_PORT', 'BAN_TIMEOUT', 'STRIKE_LADDER',
        'LEARN_ADMINS')
ADMIN_GROUPS = ('sudo', 'admin', 'wheel')


def policy():
    result = subprocess.run(['bash', '-ec',
        '. "$1"; load_guard_config runtime; shift; for key; do printf "%s\\0" "${!key-}"; done',
        'guard-lists', str(LIB / 'frp-ssh-guard-config.sh'), *KEYS],
        check=True, capture_output=True, text=True)
    return dict(zip(KEYS, result.stdout.split('\0')[:-1]))


def learning(config):
    return config.get('LEARN_ADMINS') == 'on' or bool(config.get('LOGIN_USERS'))


def learnable(user, config):
    """Whether a successful local login by this account teaches trust for its source.

    LEARN_ADMINS needs no configuration: root, the owner of the settings folder
    and members of the sudo, admin or wheel groups are administrators.
    LOGIN_USERS adds accounts by POSIX extended regex.
    """
    if config.get('LOGIN_USERS') and subprocess.run(['grep', '-Ex', '--', config['LOGIN_USERS']], input=user + '\n',
                                                    text=True, stdout=subprocess.DEVNULL).returncode == 0:
        return True
    if config.get('LEARN_ADMINS') != 'on':
        return False
    if user == 'root':
        return True
    try:
        owner = data.location(config['CONFIG_BASE'])
    except (OSError, ValueError, KeyError):
        owner = None
    if owner and owner.get('user') == user:
        return True
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        return False
    admins = set()
    for name in ADMIN_GROUPS:
        try:
            admins.add(grp.getgrnam(name).gr_gid)
        except KeyError:
            pass
    return bool(admins & set(os.getgrouplist(user, account.pw_gid)))


def state_directory():
    return Path(os.environ.get('GUARD_LIST_DIR', str(Path(os.environ.get('GUARD_DIR', '/opt/frp-ssh-guard')) / 'lists')))


def read(path):
    try:
        return path.read_text()
    except FileNotFoundError:
        return ''


def save(path, original, content, config):
    if content == original and path.exists():
        return
    owner = data.location(config['CONFIG_BASE'])
    if owner and path.parent == Path(owner['directory']):
        data.as_user(owner['user'], ['replace-list'], [str(path), original, content])
    else:
        data.replace_list(path, original, content)


def kernel_rows(document, now):
    result = []
    for item in document.get('nftables', []):
        obj = item.get('set', {})
        name = obj.get('name', '')
        # Scoped learned sets are derived exclusively from the editable file;
        # reimporting split port keys would duplicate a multi-port section.
        if name not in ('learned4', 'learned6',
                        'ban4', 'ban6', 'hardban4', 'hardban6'):
            continue
        source = 'learned' if name.startswith('learned') else ('strike' if name.startswith('hardban') else 'runtime')
        for element in obj.get('elem', []):
            if not isinstance(element, dict) or 'elem' not in element:
                continue
            elem = element['elem']
            value, seconds = elem.get('val'), elem.get('expires', 0)
            if not isinstance(seconds, (int, float)) or seconds <= 0:
                continue  # never turn a missing/expired timeout into a permanent ban
            if isinstance(value, dict) and 'concat' in value:
                ip, port = value['concat']
                scope = data.ports(str(port))
            else:
                ip, scope = value, '*'
            ip = str(ipaddress.ip_address(ip))
            result.append((name, data.Row(ip, scope, int(now + seconds), source)))
    return result


def snapshot(table, now):
    result = subprocess.run(['nft', '-j', 'list', 'table', 'inet', table],
                            capture_output=True, text=True)
    if result.returncode:
        return []
    return kernel_rows(json.loads(result.stdout), now)


def upgrade_sets(config):
    """Add new list sets before the existing first block rule, preserving handles."""
    result = subprocess.run(['nft', '-j', 'list', 'table', 'inet', config['GUARD_TABLE']],
                            capture_output=True, text=True, check=True)
    objects = json.loads(result.stdout)['nftables']
    existing = {item['set']['name'] for item in objects if 'set' in item}
    table, commands = config['GUARD_TABLE'], []
    # Trusted sources are only read by slow-protection rules, which an older table
    # lacks; list-only updates still flush and refill the set, so it must exist.
    for family in ('4', '6'):
        if 'trusted' + family not in existing:
            commands.append(f'add set inet {table} trusted{family} {{ type ipv{family}_addr; flags interval,timeout; }}')
    missing = [name + family for name in ('learned_pp', 'saved_ban', 'saved_ban_pp')
               for family in ('4', '6') if name + family not in existing]
    if not missing:
        return '\n'.join(commands)
    handles = [item['rule']['handle'] for item in objects if item.get('rule', {}).get('comment') == 'manual-block v4']
    if not handles:
        raise ValueError('Cannot locate the guard list rules; retry an explicit reload.')
    handle = int(handles[0])
    for name in missing:
        family = name[-1]
        concat = ' . inet_service' if '_pp' in name else ''
        flags = 'interval,timeout' if concat else 'timeout'
        commands.append(f'add set inet {table} {name} {{ type ipv{family}_addr{concat}; flags {flags}; }}')
        expr = ('ip6' if family == '6' else 'ip') + ' saddr' + (' . tcp dport' if concat else '')
        verdict = 'return' if name.startswith('learned') else 'counter drop'
        commands.append(f'insert rule inet {table} input position {handle} {expr} @{name} {verdict}')
    return '\n'.join(commands)


def key(row):
    return '|'.join(row.key)


def matches(row, ip, port, now):
    if row.expiry and row.expiry <= now:
        return False
    if ipaddress.ip_address(ip) not in ipaddress.ip_network(row.ip, strict=False):
        return False
    if row.scope == '*':
        return True
    return any(int(token.split('-')[0]) <= port <= int(token.split('-')[-1])
               for token in row.scope.split(','))


def allowed(ip, port, config=None):
    config = config or policy()
    # Use the last successfully applied lists; pending edits are not active policy.
    path = state_directory() / 'whitelist.conf'
    rows = data.records(read(path), 'allow')
    if not (state_directory() / 'unified-state.json').exists():
        rows += data.records(read(state_directory() / 'learned.conf'), 'allow')
    return any(matches(row, ip, port, time.time()) for row in rows)


def listed(ip, now=None):
    """Whitelisted on any port in the last applied list: a known administrator."""
    now = time.time() if now is None else now
    rows = data.records(read(state_directory() / 'whitelist.conf'), 'allow')
    address = ipaddress.ip_address(ip)
    return any((not row.expiry or row.expiry > now) and address in ipaddress.ip_network(row.ip, strict=False)
               for row in rows)


def reconcile(original, previous, live, tombstones, now, kind):
    """A deleted exported row suppresses that generation, not a future attack."""
    rows = {key(row): row for row in data.records(original, kind)}
    removed = []
    for identity, expiry in previous.items():
        if identity not in rows and expiry > now:
            tombstones[identity] = max(expiry, tombstones.get(identity, 0))
    for name, row in live:
        identity = key(row)
        if (row.source == 'learned') != (kind == 'allow'):
            continue
        if row.expiry <= tombstones.get(identity, 0) + 2:
            removed.append((name, row))
            continue
        prior = rows.get(identity)
        # nft reports whole seconds; don't churn the file for rounding alone.
        if prior and abs(prior.expiry - row.expiry) <= 2:
            continue
        if prior is None or row.expiry > prior.expiry:
            rows[identity] = row
    return [r for r in rows.values() if not r.expiry or r.expiry > now], removed


def sync(config=None, addition=None, remove=None, migrate_only=False):
    config = config or policy()
    root = state_directory()
    root.mkdir(mode=0o750, parents=True, exist_ok=True)
    state_path = root / 'unified-state.json'
    state = json.loads(read(state_path) or '{}')
    now = int(time.time())
    live = snapshot(config['GUARD_TABLE'], now)
    tombstones = {k: v for k, v in state.get('deleted', {}).items() if v + 2 > now}
    texts, paths, online = {}, {}, {}
    for kind, name in (('allow', 'whitelist.conf'), ('block', 'blocklist.conf')):
        home = Path(config['MANUAL_DIR']) / name
        online[kind] = home.parent.is_dir()
        paths[kind] = home if online[kind] else root / name
        texts[kind] = read(paths[kind])
        data.records(texts[kind], kind)  # validate BOTH files before any changes
        if paths[kind] != root / name:
            exported = state.get('exported', {}).get(kind, {})
            for row in data.records(read(root / name), kind):
                if row.source != 'manual' and row.expiry > exported.get(key(row), 0) + 2:
                    live.append(('', row))  # learned/banned while home was unavailable
    # Import legacy persistence once, or when an older running helper changes it.
    legacy = state.get('legacy', {})
    for name, source, lifetime, kind in (('learned.conf', 'learned', 'LEARN_TIMEOUT', 'allow'),
                                          ('hardban.conf', 'strike', 'STRIKE_MAX', 'block')):
        text = read(root / name)
        digest = hashlib.sha256(text.encode()).hexdigest()
        if legacy.get(name) != digest:
            for row in data.records(text, kind):
                if any(r.ip == row.ip and r.source == source and (row.scope == '*' or row.scope == r.scope) for _, r in live):
                    continue  # retain the actual remaining kernel lifetime
                if state_path.exists():
                    previous_text = state.get('legacy_rows', {}).get(name, [])
                    if any(list(row)[:4] == previous[:4] for previous in previous_text):
                        continue
                live.append(('', data.Row(row.ip, row.scope, row.expiry or now + data.duration(config[lifetime]), source)))
        legacy[name] = digest
        state.setdefault('legacy_rows', {})[name] = [list(row) for row in data.records(text, kind)]
    if addition:
        kind, row = addition
        live = [(name, r) for name, r in live if r.key != row.key]
        live.append(('', row))
        tombstones.pop(key(row), None)
    changes, deleted = {}, []
    for kind in texts:
        resolved = data.resolve_tiers(data.records(texts[kind], kind), config.get('BAN_TIMEOUT', '6h'),
                                      config.get('STRIKE_LADDER', '2:1d 3:3d 4:7d 5:28d'),
                                      config['STRIKE_MAX'], now)
        normalized = data.render_list(texts[kind], resolved, kind)
        previous = state.get('exported', {}).get(kind, {}) if online[kind] and not migrate_only else {}
        rows, removed = reconcile(normalized, previous, live, tombstones, now, kind)
        deleted.extend(removed)
        if addition and addition[0] == kind:
            incoming = addition[1]
            # Explicit login events have exact timestamps, unlike rounded nft
            # snapshots. Even a one-second newer success refreshes its expiry.
            old = next((r for r in rows if r.key == incoming.key), None)
            if old is None or incoming.expiry > old.expiry:
                rows = [r for r in rows if r.key != incoming.key] + [incoming]
        if remove:
            ip, sources = remove
            removed_rows = [row for row in rows if row.ip == ip and row.source in sources]
            for row in removed_rows:
                tombstones[key(row)] = row.expiry
            rows = [row for row in rows if row not in removed_rows]
            deleted.extend((name, row) for name, row in live if row.ip == ip and row.source in sources)
        if kind == 'allow':
            learned = sorted((r for r in rows if r.source == 'learned'), key=lambda r: r.expiry)
            evict = learned[:-int(config['MAX_LEARNED'])]
            rows = [r for r in rows if r not in evict]
            for row in evict:
                tombstones[key(row)] = row.expiry
                deleted.extend((name, r) for name, r in live if r.key == row.key)
        changes[kind] = data.render_list(texts[kind], rows, kind)
        if online[kind]:
            state.setdefault('exported', {})[kind] = {key(row): row.expiry for row in rows if row.source != 'manual'}
    # Save user edits before deleting corresponding live entries. A concurrent
    # editor causes a retry, never an overwrite of their newer file.
    for kind, content in changes.items():
        save(paths[kind], texts[kind], content, config)
    # Preserve accepted manual policy while caching automatic state immediately.
    # Installation must not adopt pending manual edits just to migrate jails.
    for kind, name in (('allow', 'whitelist.conf'), ('block', 'blocklist.conf')):
        cache = root / name
        if paths[kind] == cache:
            continue
        original = read(cache)
        rows = [r for r in data.records(original, kind) if r.source == 'manual']
        rows += [r for r in data.records(changes[kind], kind) if r.source != 'manual']
        content = data.render_list(original, rows, kind)
        if content != original:
            data.atomic_write(cache, content)
    for name, row in ([] if migrate_only else deleted):
        if not name:
            continue
        value = row.ip + (' . ' + row.scope if row.scope != '*' else '')
        subprocess.run(['nft', 'delete', 'element', 'inet', config['GUARD_TABLE'], name,
                        '{ ' + value + ' }'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state.update(legacy=legacy, deleted=tombstones)
    data.atomic_write(state_path, json.dumps(state, sort_keys=True) + '\n')
    return changes


def main():
    action, *args = sys.argv[1:]
    config = policy()
    if action == 'sync':
        sync(config)
    elif action == 'upgrade-sets':
        print(upgrade_sets(config))
    elif action == 'upgrade':
        # Package hooks only copy state; never apply rules or restart services.
        with data.installation_lock():
            sync(policy(), migrate_only=True)
    elif action == 'remember':
        ip = str(ipaddress.ip_address(args[0]))
        sync(config, addition=('allow', data.Row(ip, '*', int(time.time()) + data.duration(config['LEARN_TIMEOUT']), 'learned')))
    elif action in ('forget', 'unban'):
        ip = str(ipaddress.ip_address(args[0]))
        sync(config, remove=(ip, ('learned',) if action == 'forget' else ('runtime', 'strike')))
    else:
        raise ValueError('Unknown list operation.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        print('Could not synchronize lists; original data and active jails were retained. '
              'Check list format/access, then retry apply.', file=sys.stderr)
        sys.exit(0 if sys.argv[1:2] == ['upgrade'] else 1)
