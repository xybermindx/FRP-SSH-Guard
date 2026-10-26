#!/usr/bin/env python3
"""Shared journal processing and timestamped observations; callers serialize I/O.

No account names or raw journal messages enter this database. It is private
runtime state, never a package input. All times are UTC epoch seconds.
"""
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time

LIB = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location('events_' + name, LIB / ('frp-ssh-guard-' + name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


lists, alerts = module('lists'), module('alerts')
data = lists.data
KEYS = lists.KEYS + ('PROTECT_SERVER_SSH', 'SSH_AUTH_FAILURES', 'SSH_INVALID_USER_FAILURES',
    'SSH_AUTH_WINDOW', 'SSH_SLOW_MODE', 'SSH_SLOW_FAILURES', 'SSH_SLOW_WINDOW',
    'ALERT_LOG_MAX_SIZE', 'SUBNET_REPORT_MIN_SOURCES', 'SUBNET_REPORT_WINDOW',
    'OBSERVABILITY_VERSION', 'STRIKE_WINDOW')
SUCCESS = re.compile(r'^Accepted (password|publickey|keyboard-interactive(?:/pam)?) for (\S+) from ')
MAX_ROWS = 200000


def policy():
    result = subprocess.run(['bash', '-ec',
        '. "$1"; load_guard_config runtime; shift; for key; do printf "%s\\0" "${!key-}"; done',
        'guard-events', str(LIB / 'frp-ssh-guard-config.sh'), *KEYS],
        check=True, capture_output=True, text=True)
    return dict(zip(KEYS, result.stdout.split('\0')[:-1]))


def root():
    return Path(os.environ.get('GUARD_DIR', '/opt/frp-ssh-guard')) / 'observations'


@contextmanager
def lock():
    with open(os.environ.get('GUARD_LOCK_FILE', '/run/frp-ssh-guard.lock'), 'a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def utc(stamp):
    return dt.datetime.fromtimestamp(stamp, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


class Store:
    def __init__(self, directory=None, now=None, readonly=False):
        self.directory = Path(directory or root())
        if self.directory.is_symlink():
            raise ValueError('Unsafe state directory')
        if readonly:
            self.db = sqlite3.connect((self.directory / 'events.sqlite3').as_uri() + '?mode=ro', uri=True)
            self.db.row_factory = sqlite3.Row
            return
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        path = self.directory / 'events.sqlite3'
        if path.is_symlink():
            raise ValueError('Unsafe state file')
        self.db = sqlite3.connect(path)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            raise ValueError('Unsupported observation state version')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, stamp REAL);
            CREATE TABLE IF NOT EXISTS failures (id TEXT PRIMARY KEY, stamp REAL, ip TEXT, conn TEXT, invalid INTEGER, short_on INTEGER);
            CREATE INDEX IF NOT EXISTS failure_source ON failures(ip, stamp);
            CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, stamp REAL, kind TEXT, ip TEXT, scope TEXT, detail TEXT, count INTEGER, exported INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS event_time ON events(stamp);
            CREATE TABLE IF NOT EXISTS episodes (key TEXT PRIMARY KEY, stamp REAL);
            CREATE TABLE IF NOT EXISTS bans (ip TEXT, scope TEXT, expiry REAL, origin TEXT, PRIMARY KEY(ip, scope));
            CREATE TABLE IF NOT EXISTS samples (stamp REAL, start REAL, packets INTEGER, gap INTEGER);
            PRAGMA user_version=1;
        ''')
        self.now = time.time() if now is None else now
        if self.get('coverage_start') is None:
            self.set('coverage_start', self.now)
        self.db.commit()

    def close(self):
        self.db.close()

    def get(self, key, default=None):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))

    def emit(self, identity, stamp, kind, ip='', scope='*', detail='', count=0):
        self.db.execute('INSERT OR IGNORE INTO events(id,stamp,kind,ip,scope,detail,count) VALUES (?,?,?,?,?,?,?)',
                        (identity, stamp, kind, ip, scope, detail, count))

    def prune(self, config, now):
        window = max(data.duration(config[k]) for k in ('SSH_AUTH_WINDOW', 'SSH_SLOW_WINDOW', 'SUBNET_REPORT_WINDOW', 'STRIKE_WINDOW'))
        for table in ('seen', 'failures', 'events', 'samples', 'episodes'):
            self.db.execute(f'DELETE FROM {table} WHERE stamp<?', (now - max(window, 86400),))
            count = self.db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
            if count > MAX_ROWS:
                self.db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY stamp LIMIT ?)', (count - MAX_ROWS,))
                self.set('capacity_gap', now)
        self.db.execute('DELETE FROM bans WHERE expiry<?', (now - window,))
        excess = self.db.execute('SELECT count(*) FROM bans').fetchone()[0] - MAX_ROWS
        if excess > 0:
            self.db.execute('DELETE FROM bans WHERE rowid IN (SELECT rowid FROM bans ORDER BY expiry LIMIT ?)', (excess,))
            self.set('capacity_gap', now)

    def migrate(self, config, now):
        if self.get('legacy_migrated'):
            return
        path = Path(os.environ.get('GUARD_DIR', '/opt/frp-ssh-guard')) / 'auth-state.json'
        try:
            old = json.loads(path.read_text())
            for ip, attempts in old.get('attempts', {}).items():
                ip = str(ipaddress.ip_address(ip))
                for index, (stamp, invalid, conn) in enumerate(attempts):
                    if now - data.duration(config['SSH_AUTH_WINDOW']) <= stamp <= now + 5:
                        identity = 'legacy-' + hashlib.sha256(f'{ip}|{stamp}|{index}'.encode()).hexdigest()
                        # Migration contributes to short detection only. Long coverage starts now.
                        self.db.execute('INSERT OR IGNORE INTO failures VALUES (?,?,?,?,?,1)', (identity, stamp, ip, str(conn), int(bool(invalid))))
            for cursor in old.get('seen', []):
                self.db.execute('INSERT OR IGNORE INTO seen VALUES (?,?)', (digest(cursor), now))
            if old.get('cursor'):
                self.set('cursor_auth', old['cursor'])
        except FileNotFoundError:
            pass
        self.set('legacy_migrated', True)
        self.db.commit()

    def process(self, record, config, event, now, trusted=False):
        cursor = record.get('__CURSOR')
        if not cursor:
            return None
        identity = digest(cursor)
        inserted = self.db.execute('INSERT OR IGNORE INTO seen VALUES (?,?)', (identity, now)).rowcount
        if not inserted or not event:
            return None
        kind, ip, conn, stamp = event
        window = max(data.duration(config['SSH_AUTH_WINDOW']), data.duration(config['SSH_SLOW_WINDOW']))
        if stamp < max(now - window, self.get('coverage_start', now)) or stamp > now + 5:
            return None
        if kind == 'accepted':
            self.db.execute('UPDATE failures SET short_on=0 WHERE ip=?', (ip,))
            method = SUCCESS.match(record['MESSAGE'])
            if not trusted:
                self.emit(identity, stamp, 'new-source-login', ip, '22',
                          'trust=untrusted method=' + (method[1] if method else 'unknown'))
            return 'accepted'
        if config['PROTECT_SERVER_SSH'] != 'on':
            return None
        # All invalid-user records from a connection describe one invalid-user
        # attempt; normal authentication failures remain individually countable.
        conn = record.get('_BOOT_ID', '') + ':' + conn
        if kind == 'invalid' and self.db.execute('SELECT 1 FROM failures WHERE ip=? AND conn=? AND invalid=1 AND stamp>=?',
                                                (ip, conn, now - window)).fetchone():
            return None
        self.db.execute('INSERT INTO failures VALUES (?,?,?,?,?,1)', (identity, stamp, ip, conn, int(kind == 'invalid')))
        self.emit(identity, stamp, 'auth-failure', ip, '22')
        fast = self.db.execute('SELECT count(*),coalesce(sum(invalid),0) FROM failures WHERE ip=? AND short_on=1 AND stamp>=?',
                               (ip, now - data.duration(config['SSH_AUTH_WINDOW']))).fetchone()
        slow = self.db.execute("SELECT count(*) FROM failures WHERE ip=? AND stamp>=? AND id NOT LIKE 'legacy-%'",
                               (ip, now - data.duration(config['SSH_SLOW_WINDOW']))).fetchone()[0]
        key = 'slow|' + ip
        prior = self.db.execute('SELECT stamp FROM episodes WHERE key=?', (key,)).fetchone()
        # Rearm only after the previous episode has aged out below threshold.
        if prior and (slow - 1 < int(config['SSH_SLOW_FAILURES']) or prior[0] < now - data.duration(config['SSH_SLOW_WINDOW'])):
            self.db.execute('DELETE FROM episodes WHERE key=?', (key,))
            prior = None
        if config['SSH_SLOW_MODE'] != 'off' and slow >= int(config['SSH_SLOW_FAILURES']) and prior is None:
            self.db.execute('INSERT OR REPLACE INTO episodes VALUES (?,?)', (key, stamp))
            self.emit(identity + '-slow', stamp, 'slow-threshold', ip, '22',
                      'mode=' + config['SSH_SLOW_MODE'] + ' trust=' + ('allowed' if trusted else 'untrusted'), slow)
        fast_hit = fast[0] >= int(config['SSH_AUTH_FAILURES']) or fast[1] >= int(config['SSH_INVALID_USER_FAILURES'])
        if fast_hit:
            self.db.execute('UPDATE failures SET short_on=0 WHERE ip=?', (ip,))
        return 'ban' if not trusted and (fast_hit or slow >= int(config['SSH_SLOW_FAILURES']) and config['SSH_SLOW_MODE'] == 'enforce') else None

    def record_ban(self, ip, scope, expiry, origin, config, now):
        prior = self.db.execute('SELECT expiry,origin FROM bans WHERE ip=? AND scope=?', (ip, scope)).fetchone()
        self.db.execute('INSERT OR REPLACE INTO bans VALUES (?,?,?,?)', (ip, scope, expiry, origin))
        if origin not in ('auth', 'kernel') or prior and prior['expiry'] > now:
            return False
        identity = digest(f'ban|{ip}|{scope}|{now}')
        self.emit(identity, now, 'ban', ip, scope, 'origin=' + origin)
        address = ipaddress.ip_address(ip)
        prefix = str(ipaddress.ip_network(f'{ip}/{24 if address.version == 4 else 64}', strict=False))
        since = now - data.duration(config['SUBNET_REPORT_WINDOW'])
        sources = {row[0] for row in self.db.execute("SELECT DISTINCT ip FROM events WHERE kind='ban' AND scope=? AND stamp>=?", (scope, since))
                   if ipaddress.ip_address(row[0]) in ipaddress.ip_network(prefix)}
        key = 'subnet|' + prefix + '|' + scope
        previous = self.db.execute('SELECT stamp FROM episodes WHERE key=?', (key,)).fetchone()
        if len(sources) >= int(config['SUBNET_REPORT_MIN_SOURCES']) and (not previous or previous[0] < since):
            self.db.execute('INSERT OR REPLACE INTO episodes VALUES (?,?)', (key, now))
            self.emit(identity + '-subnet', now, 'subnet-cluster', prefix, scope, 'action=report-only', len(sources))
        return True

    def export(self, config, force=False):
        records = list(self.db.execute("SELECT * FROM events WHERE exported=0 AND kind IN ('new-source-login','slow-threshold','subnet-cluster') ORDER BY stamp DESC"))
        if not records and not force and not (self.directory / 'alerts-spool.log').exists():
            self.db.commit()
            return
        lines = ''.join(f"{utc(r['stamp'])} {r['kind']} source={r['ip']} scope={r['scope']} {r['detail']} count={r['count']} id={r['id']}\n" for r in records)
        # A bounded spool is the durable retry queue. Older records may be
        # discarded by the requested cap; do not regenerate discarded entries.
        delivered = alerts.deliver(config, self.directory, lines)
        if not delivered and not (self.directory / 'alerts-spool.log').is_file():
            return
        self.db.execute("UPDATE events SET exported=1 WHERE kind IN ('new-source-login','slow-threshold','subnet-cluster')")
        self.db.commit()


def digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def snapshot(config):
    result = subprocess.run(['nft', '-j', 'list', 'table', 'inet', config['GUARD_TABLE']], capture_output=True, text=True)
    return json.loads(result.stdout) if result.returncode == 0 else None


def sample(store, config, now, document=None, baseline=False):
    document = snapshot(config) if document is None else document
    previous = store.get('counter_checkpoint')
    if document is None:
        store.set('counter_checkpoint', None)
        store.set('last_sampling_gap', now)
        store.db.commit()
        return
    counters = {}
    for item in document.get('nftables', []):
        rule = item.get('rule', {})
        # Count packet drops only, not matches on other rules or connections.
        if not any('drop' in part for part in rule.get('expr', [])):
            continue
        for part in rule.get('expr', []):
            if 'counter' in part:
                counters[str(rule.get('handle'))] = part['counter'].get('packets', 0)
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        boot = ''
    table_handle = next((x['table'].get('handle') for x in document.get('nftables', []) if 'table' in x), None)
    generation = [boot, table_handle]
    same = previous and previous['generation'] == generation
    reset = not same or set(counters) != set(previous['counters']) or any(v < previous['counters'].get(k, 0) for k, v in counters.items())
    if previous and not baseline:
        delta = sum(counters.values()) if not same else sum(
            v - previous['counters'].get(k, 0) if v >= previous['counters'].get(k, 0) else v
            for k, v in counters.items())
        store.db.execute('INSERT INTO samples VALUES (?,?,?,?)', (now, previous['stamp'], delta, int(reset)))
    store.set('counter_checkpoint', dict(stamp=now, counters=counters, generation=generation))
    initialized = store.get('ban_baseline', False)
    live = {(row.ip, row.scope): row.expiry for name, row in lists.kernel_rows(document, now) if name in ('ban4', 'ban6')}
    for (ip, scope), expiry in live.items():
        store.record_ban(ip, scope, expiry, 'kernel' if initialized and not baseline else 'restored', config, now)
    store.set('ban_baseline', True)
    store.prune(config, now)
    store.db.commit()


def enforce(store, config, ip, now):
    scope = '22' if config['JAIL_PER_PORT'] == 'on' else '*'
    # Native allow precedence has already been checked. Existing restored/strike
    # entries count as a live jail; never extend their absolute expiry on replay.
    live = lists.snapshot(config['GUARD_TABLE'], now)
    cached = data.records(lists.read(lists.state_directory() / 'blocklist.conf'), 'block')
    if any(row.ip == ip and lists.matches(row, ip, 22, now) for row in cached + [r for _, r in live]):
        return False
    duration = data.duration(config['BAN_TIMEOUT'])
    value = ip + (' . 22' if scope == '22' else '')
    name = 'ban6' if ':' in ip else 'ban4'
    result = subprocess.run(['nft', 'add', 'element', 'inet', config['GUARD_TABLE'], name,
                             '{ ' + value + ' timeout ' + config['BAN_TIMEOUT'] + ' }'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        print('SSH authentication threshold reached; guard ban could not be applied.', file=sys.stderr, flush=True)
        return False
    store.record_ban(ip, scope, now + duration, 'auth', config, now)
    store.db.commit()
    lists.sync(config)
    return True


def handle(record, reader='auth'):
    auth = module('auth')
    event = auth.parse_event(record)
    if not event:
        return False
    learned_ip = None
    with lock():
        config = policy()
        if config['OBSERVABILITY_VERSION'] != '1':
            return False
        now = time.time()
        store = Store(now=now)
        try:
            trusted = lists.allowed(event[1], 22, config)
            result = store.process(record, config, event, now, trusted)
            if record.get('__CURSOR'):
                store.set('cursor_' + reader, record['__CURSOR'])
            store.set('heartbeat_' + reader, now)
            if result == 'ban':
                enforce(store, config, event[1], now)
            store.db.commit()
            if result == 'accepted' and config['LOGIN_USERS']:
                match = SUCCESS.match(record['MESSAGE'])
                if match and subprocess.run(['grep', '-Ex', '--', config['LOGIN_USERS']], input=match[2] + '\n', text=True,
                                            stdout=subprocess.DEVNULL).returncode == 0:
                    expiry = int(event[3]) + data.duration(config['LEARN_TIMEOUT'])
                    if expiry > now:
                        lists.sync(config, addition=('allow', data.Row(event[1], '*', expiry, 'learned')))
                        learned_ip = event[1]
            store.prune(config, now)
            store.export(config)
        finally:
            store.close()
    if learned_ip:
        command = os.environ.get('GUARD_COMMAND', str(Path(os.environ.get('GUARD_DIR', '/opt/frp-ssh-guard')) / 'bin/frp-ssh-guard'))
        subprocess.run([command, 'apply'], check=True, stdout=subprocess.DEVNULL)
        if shutil.which('fail2ban-client'):
            subprocess.run(['fail2ban-client', 'set', 'sshd', 'addignoreip', learned_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return bool(learned_ip)


def follow(reader):
    config = policy()
    store = Store(readonly=True)
    cursor = store.get('cursor_' + reader, '')
    since = store.get('coverage_start', time.time())
    store.close()
    command = ['journalctl', '--no-pager', '--output=json', '--follow', '_UID=0',
               'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session', 'SYSLOG_IDENTIFIER=sshd-auth']
    for resume in (True, False):
        position = ['--after-cursor=' + cursor] if resume and cursor else ['--since=@' + str(int(since))]
        process = subprocess.Popen(command + position, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            for line in process.stdout:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                handle(record, reader)
                cursor = record.get('__CURSOR', cursor)
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
            process.wait()
        if process.returncode == 0 or not cursor:
            break
    return 1


def show(config, store=None, window=None):
    print('Slow SSH detection: ' + config['SSH_SLOW_MODE'])
    print('Alerts: ' + str(Path(config['MANUAL_DIR']) / 'alerts.log'))
    print('Alert maximum size: ' + config['ALERT_LOG_MAX_SIZE'] + ' (oldest records discarded; no archives)')
    if store is None:
        print('Observation coverage: not activated; run check, then reload')
        return
    print('Observation coverage starts: ' + utc(store.get('coverage_start')))
    if window:
        since, now = time.time() - data.duration(window), time.time()
        print('Report window: ' + utc(since) + ' to ' + utc(now))
        if since < store.get('coverage_start'):
            print('Partial coverage: requested window starts before observation activation.')
        for kind in ('auth-failure', 'slow-threshold', 'new-source-login', 'ban', 'subnet-cluster'):
            count = store.db.execute('SELECT count(*) FROM events WHERE kind=? AND stamp>=? AND stamp<=?', (kind, since, now)).fetchone()[0]
            print(kind + ': ' + str(count))
        rows = list(store.db.execute('SELECT * FROM samples WHERE stamp>=? AND stamp<=?', (since, now)))
        print('Sampled dropped packets: ' + str(sum(r['packets'] for r in rows)))
        if rows:
            print('Packet sampling coverage: ' + utc(rows[0]['start']) + ' to ' + utc(rows[-1]['stamp']))
        else:
            print('Packet sampling coverage: no samples in this window')
        if store.get('last_sampling_gap'):
            print('Last unavailable-table sample: ' + utc(store.get('last_sampling_gap')))
        print('Counter reset/gap samples: ' + str(sum(r['gap'] for r in rows)))
        print('Sampling intervals may straddle the requested boundary; unsampled drops can be lost on crash/power loss.')
        if store.get('capacity_gap'):
            print('State capacity exceeded; older observations were discarded at ' + utc(store.get('capacity_gap')))


def main():
    # CLI callers already hold the runtime lock. Journal readers use handle().
    config = policy()
    action = sys.argv[1]
    if action == 'report':
        data.duration(sys.argv[2])
    if action in ('status', 'report', 'doctor'):
        store = Store(readonly=True) if (root() / 'events.sqlite3').is_file() else None
        try:
            show(config, store, sys.argv[2] if action == 'report' else None)
            if action == 'doctor':
                document = snapshot(config)
                print('Guard table present: ' + ('yes' if document else 'no'))
                print('Native SSH configured: ' + config['PROTECT_SERVER_SSH'])
                rules = [item['rule'] for item in (document or {}).get('nftables', []) if 'rule' in item]
                covered = all(any(rule.get('comment') == '22 banned v' + family
                                  and any('drop' in expression for expression in rule.get('expr', []))
                                  and any(expression.get('match', {}).get('right') == 22
                                          and expression.get('match', {}).get('left', {}).get('payload', {}).get('field') == 'dport'
                                          for expression in rule.get('expr', [])) for rule in rules) for family in ('4', '6'))
                print('Live native SSH ban rules (IPv4/IPv6): ' + ('present' if covered else 'missing'))
                owner = data.location(config['CONFIG_BASE'])
                account = __import__('pwd').getpwnam(owner['user']) if owner else None
                kwargs = dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[]) if account and os.geteuid() == 0 else {}
                result = subprocess.run([sys.executable, str(LIB / 'frp-ssh-guard-alerts.py'), 'inspect',
                                         str(Path(config['MANUAL_DIR']) / 'alerts.log')], capture_output=True, text=True, **kwargs)
                print('Alert file access as owner: ' + ('available' if result.returncode == 0 else 'unavailable or unsafe; system spool used'))
                print('Pending system alert spool: ' + ('yes' if (root() / 'alerts-spool.log').exists() else 'no'))
                print('Whitelist learning: ' + ('configured; trusts successful password/key/PAM logins for matching users' if config['LOGIN_USERS'] else 'off'))
                rows = data.records(lists.read(lists.state_directory() / 'whitelist.conf'), 'allow')
                native = sum(1 for r in rows if (not r.expiry or r.expiry > time.time()) and (r.scope == '*' or any(int(t.split('-')[0]) <= 22 <= int(t.split('-')[-1]) for t in r.scope.split(','))))
                print('Applied whitelist entries covering SSH: ' + str(native))
                for service in ('frp-ssh-guard-auth', 'frp-ssh-guard-learn'):
                    result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
                    print(service + ': ' + result.stdout.strip())
                result = subprocess.run(['journalctl', '--no-pager', '-n', '0'], capture_output=True)
                print('Journal readable: ' + ('yes' if result.returncode == 0 else 'no'))
                print('A new dynamic source is not trusted until an eligible login succeeds; keep recovery access.')
        finally:
            if store:
                store.close()
        return
    if config['OBSERVABILITY_VERSION'] != '1':
        return
    store = Store()
    try:
        now = time.time()
        if action == 'activate':
            store.migrate(config, now)
            sample(store, config, now, baseline=True)
        elif action == 'manual':
            ip, duration = sys.argv[2:4]
            for name, row in lists.snapshot(config['GUARD_TABLE'], now):
                if name in ('ban4', 'ban6') and row.ip == ip:
                    store.record_ban(row.ip, row.scope, row.expiry, 'manual', config, now)
        elif action == 'forgive':
            ip = str(ipaddress.ip_address(sys.argv[2]))
            store.db.execute('DELETE FROM bans WHERE ip=?', (ip,))
            store.db.execute('DELETE FROM failures WHERE ip=?', (ip,))
            store.db.execute('DELETE FROM episodes WHERE key=?', ('slow|' + ip,))
            store.db.commit()
        elif action in ('sample', 'checkpoint'):
            sample(store, config, now)
        else:
            raise ValueError('Unknown observation action')
        store.export(config, force=action == 'activate')
    finally:
        store.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError):
        sys.exit('Could not update private observation state; inspect storage and monitor health.')
