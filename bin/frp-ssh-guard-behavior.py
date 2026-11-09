#!/usr/bin/env python3
"""Restless-source rules for custom/FRP ports; called by the minute sampler.

Logins behind FRP are invisible here, so two facts are used instead:
- A connection that stays open past LEARN_SESSION_AGE, or that received more
  than LEARN_SESSION_BYTES, completed a login. Its source/port pair becomes a
  known user; nftables stops counting it (known4/known6).
- Every other new connection (a resent SYN is not one) is counted per source
  and port by nftables (count4/count6). Here the counters become streaks: runs
  of connections with no pause of SSH_BEHAVIOR_PAUSE, kept in 15-minute slots.
  A rule Np:T or Nc:T matches when the streak has lasted T and the last T held
  N ports or N connections. A matching source is banned.

The caller holds the runtime lock and commits the database. No account names,
packet contents or connection payloads are read or stored.
"""
import datetime as dt
import hashlib
import importlib.util
import ipaddress
from pathlib import Path
import re
import sqlite3
import subprocess

LIB = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location('behavior_lists', LIB / 'frp-ssh-guard-lists.py')
lists = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lists)
data = lists.data

SCHEMA = '''
    CREATE TABLE IF NOT EXISTS counters (ip TEXT, port INTEGER, packets INTEGER, PRIMARY KEY(ip, port));
    CREATE TABLE IF NOT EXISTS streaks (ip TEXT PRIMARY KEY, start REAL, last REAL);
    CREATE TABLE IF NOT EXISTS activity (ip TEXT, port INTEGER, slot INTEGER, connections INTEGER,
                                         PRIMARY KEY(ip, port, slot));
    CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, ip TEXT, port INTEGER, first REAL);
    CREATE TABLE IF NOT EXISTS known (ip TEXT, port INTEGER, expiry REAL, PRIMARY KEY(ip, port));
'''
SS = ['ss', '-H', '-t', '-i', '-n', '-p', 'state', 'established']
RULE = re.compile(r'([1-9][0-9]{0,6})([pcb]):([1-9][0-9]{0,8}[smhdw])')
MAX_ROWS = 200000
SLOT = 900  # seconds per activity slot


def digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


def until(stamp):
    return dt.datetime.fromtimestamp(stamp, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def size(value):
    match = re.fullmatch(r'([1-9][0-9]*)(KiB|MiB)', value)
    if not match:
        raise ValueError('Use a size such as 32KiB or 1MiB.')
    return int(match[1]) * (1024 if match[2] == 'KiB' else 1048576)


def rules(text):
    """'4p:2h 50c:12h' -> [(4, 'p', 7200, '2h'), (50, 'c', 43200, '12h')]."""
    result = []
    for entry in text.split():
        match = RULE.fullmatch(entry)
        if not match:
            raise ValueError('Invalid SSH_BEHAVIOR_RULES entry: ' + entry)
        result.append((int(match[1]), match[2], data.duration(match[3]), match[3]))
    return result


def forwarded(config):
    """Accepted custom/FRP ports; native port 22 with server protection is excluded."""
    ports = set()
    for spec in config.get('PROTECTED_PORTS', '').replace(' ', ',').split(','):
        token = spec.split(':')[0]
        if not token:
            continue
        bounds = [int(p) for p in token.split('-')]
        ports.update(range(bounds[0], bounds[-1] + 1))
    if config.get('PROTECT_SERVER_SSH') == 'on':
        ports.discard(22)
    return ports


def parse_sockets(text):
    """frps-owned established TCP sockets from `ss -Htinp`: (ip, peer port, port, bytes sent)."""
    rows, current = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():  # tcp_info line of the socket above
            sent = re.search(r'\bbytes_acked:([0-9]+)', line)
            if current is not None and sent:
                current[3] = int(sent[1])
            continue
        if current is not None:
            rows.append(tuple(current))
        current = None
        fields = line.split()
        if len(fields) < 4 or '(("frps",' not in line:
            continue
        try:
            port = int(fields[2].rsplit(':', 1)[1])
            host, peer_port = fields[3].rsplit(':', 1)
            address = ipaddress.ip_address(host.strip('[]').split('%')[0])
        except (ValueError, IndexError):
            continue
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped  # nftables sees these clients as IPv4
        current = [str(address), int(peer_port), port, 0]
    if current is not None:
        rows.append(tuple(current))
    return rows


def read_sockets(run=subprocess.run):
    result = run(SS, capture_output=True, text=True)
    return parse_sockets(result.stdout) if result.returncode == 0 else []


def _elements(document, names):
    for item in document.get('nftables', []):
        obj = item.get('set', {})
        if obj.get('name') not in names:
            continue
        for element in obj.get('elem', []):
            elem = element.get('elem') if isinstance(element, dict) else None
            value = elem.get('val') if isinstance(elem, dict) else None
            if not isinstance(value, dict) or 'concat' not in value:
                continue
            try:
                ip, port = value['concat']
                yield str(ipaddress.ip_address(ip)), int(port), elem
            except (TypeError, ValueError):
                continue


def counters(document):
    """Per source/port connection counters from count4/count6."""
    result = {}
    for ip, port, elem in _elements(document, ('count4', 'count6')):
        counter = elem.get('counter')
        if isinstance(counter, dict) and isinstance(counter.get('packets'), int):
            result[(ip, port)] = counter['packets']
    return result


def set_names(document):
    return {item['set'].get('name') for item in document.get('nftables', []) if 'set' in item}


def learn(store, config, sockets, ports, now, listed=lists.listed):
    """Record session ages; a proven login makes its source/port a known user."""
    db = store.db
    age = data.duration(config['LEARN_SESSION_AGE'])
    limit = size(config['LEARN_SESSION_BYTES'])
    lifetime = data.duration(config['LEARN_TIMEOUT'])
    previous = dict(db.execute('SELECT id, first FROM sessions'))
    db.execute('DELETE FROM sessions')  # only currently open sockets are kept
    proven = {}
    for ip, peer, port, sent in sockets:
        if port not in ports:
            continue
        identity = f'{ip}|{peer}|{port}'
        first = previous.get(identity, now)
        db.execute('INSERT OR REPLACE INTO sessions VALUES (?,?,?,?)', (identity, ip, port, first))
        if now - first >= age:
            proven[(ip, port)] = 'long-session'
        elif sent > limit:
            proven.setdefault((ip, port), 'session-data')
    for (ip, port), how in sorted(proven.items()):
        if listed(ip, now):
            continue  # whitelisted on any port: never counted anyway
        prior = db.execute('SELECT expiry FROM known WHERE ip=? AND port=?', (ip, port)).fetchone()
        expiry = now + lifetime
        db.execute('INSERT OR REPLACE INTO known VALUES (?,?,?)', (ip, port, expiry))
        forgive(store, ip)
        if not prior or prior[0] <= now:
            store.emit(digest(f'known|{ip}|{port}|{now}'), now, 'known-user', ip, str(port),
                       'reason=' + how + ' until=' + until(expiry))
    return proven


def sync_known(store, config, document, now, run=subprocess.run):
    """Make known4/known6 match the database (refills after reload, drops forgotten pairs)."""
    table = config['GUARD_TABLE']
    present = {(ip, port): elem.get('expires', 0) for ip, port, elem in _elements(document, ('known4', 'known6'))}
    wanted = {(ip, port): expiry for ip, port, expiry in store.db.execute(
        'SELECT ip, port, expiry FROM known WHERE expiry>?', (now,))}
    script = []
    for (ip, port), expiry in sorted(wanted.items()):
        name = 'known6' if ':' in ip else 'known4'
        remaining = int(expiry - now)
        have = present.get((ip, port))
        element = f'{{ {ip} . {port} timeout {remaining}s }}'
        if have is None:
            script.append(f'add element inet {table} {name} {element}')
        elif isinstance(have, (int, float)) and have < remaining - 86400:
            # add does not extend an element; a renewed session replaces it.
            script.append(f'delete element inet {table} {name} {{ {ip} . {port} }}')
            script.append(f'add element inet {table} {name} {element}')
    for (ip, port) in sorted(set(present) - set(wanted)):
        script.append(f'delete element inet {table} {"known6" if ":" in ip else "known4"} {{ {ip} . {port} }}')
    if script:
        run(['nft', '-f', '-'], input='\n'.join(script) + '\n', text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def deltas(store, document, generation):
    """New connections per source and port since the previous sample."""
    db = store.db
    if store.get('behavior_generation') != generation:
        db.execute('DELETE FROM counters')  # a new table restarts every counter at 0
        store.set('behavior_generation', generation)
    previous = {(ip, port): packets for ip, port, packets in db.execute('SELECT ip, port, packets FROM counters')}
    current = counters(document)
    result = {}
    for key, packets in current.items():
        old = previous.get(key, 0)
        delta = packets - old if packets >= old else packets  # recreated after expiry
        if delta > 0:
            result.setdefault(key[0], {})[key[1]] = delta
        if packets != old or key not in previous:
            db.execute('INSERT OR REPLACE INTO counters VALUES (?,?,?)', (key[0], key[1], packets))
    for key in set(previous) - set(current):
        db.execute('DELETE FROM counters WHERE ip=? AND port=?', key)
    return result


def track(store, changes, now, pause):
    """Extend or restart each source's streak with its new connections."""
    db = store.db
    slot = int(now // SLOT)
    for ip, ports in changes.items():
        row = db.execute('SELECT start, last FROM streaks WHERE ip=?', (ip,)).fetchone()
        if row is None or now - row[1] >= pause:
            db.execute('DELETE FROM activity WHERE ip=?', (ip,))  # the pause starts it over
            start = now
        else:
            start = row[0]
        db.execute('INSERT OR REPLACE INTO streaks VALUES (?,?,?)', (ip, start, now))
        for port, count in ports.items():
            updated = db.execute('UPDATE activity SET connections=connections+? WHERE ip=? AND port=? AND slot=?',
                                 (count, ip, port, slot)).rowcount
            if not updated:
                db.execute('INSERT INTO activity VALUES (?,?,?,?)', (ip, port, slot, count))


def streak(store, ip):
    """(start, last, [(port, slot, connections)]) of a source's current streak."""
    row = store.db.execute('SELECT start, last FROM streaks WHERE ip=?', (ip,)).fetchone()
    activity = list(store.db.execute('SELECT port, slot, connections FROM activity WHERE ip=?', (ip,)))
    return (row[0], row[1], activity) if row else None


def window(activity, now, seconds):
    """Connections per port within the last `seconds` (whole slots that overlap it)."""
    counts = {}
    for port, slot, connections in activity:
        if (slot + 1) * SLOT > now - seconds:
            counts[port] = counts.get(port, 0) + connections
    return counts


def judge(start, now, activity, entries, per_port, pause):
    """Rules met by one streak: [(scope, reason, limit)].

    Np:T / Nc:T match when the streak has lasted T (no pause in that time) and
    the last T held N different ports or N new connections. A port rule bans
    the source on all ports in both jail modes. A connection rule counts the
    source's total in shared mode and each port in per-port mode, where it bans
    only the ports that reached it.
    """
    length = now - start
    for number, kind, span, text in entries:
        if kind == 'p' and length >= span and len(window(activity, now, span)) >= number:
            return [('*', 'restless-ports', f'{number}ports/{text},pause={pause}')]
    hits = []
    for number, kind, span, text in entries:
        if kind != 'c' or length < span:
            continue
        counts = window(activity, now, span)
        limit = f'{number}/{text},pause={pause}'
        if not per_port:
            if sum(counts.values()) >= number:
                return [('*', 'restless-connections', limit)]
            continue
        for port, count in sorted(counts.items()):
            if count >= number and str(port) not in {hit[0] for hit in hits}:
                hits.append((str(port), 'restless-connections', limit))
    return hits


def covered(rows, ip, scope, now):
    address = ipaddress.ip_address(ip)
    for row in rows:
        if row.expiry and row.expiry <= now:
            continue
        try:
            inside = address in ipaddress.ip_network(row.ip, strict=False)
        except ValueError:
            continue
        if not inside:
            continue
        if row.scope == '*' or scope != '*' and lists.matches(row, ip, int(scope), now):
            return True
    return False


def ban(store, config, rows, ip, scope, reason, limit, now, run=subprocess.run):
    """Insert one behavior ban unless a live, saved, manual or strike block covers it."""
    if covered(rows, ip, scope, now):
        return False
    family = '6' if ':' in ip else '4'
    if scope == '*':
        name = ('wideban' if config['JAIL_PER_PORT'] == 'on' else 'ban') + family
        value = ip
    else:
        name, value = 'ban' + family, ip + ' . ' + scope
    result = run(['nft', 'add', 'element', 'inet', config['GUARD_TABLE'], name,
                  '{ ' + value + ' timeout ' + config['BAN_TIMEOUT'] + ' }'],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        return False
    store.record_ban(ip, scope, now + data.duration(config['BAN_TIMEOUT']), 'behavior', config, now, reason, limit)
    rows.append(data.Row(ip, scope, int(now + data.duration(config['BAN_TIMEOUT'])), 'runtime'))
    return True


def forgive(store, ip):
    """Forget a source's streak (unban, release, a proven login)."""
    store.db.execute('DELETE FROM streaks WHERE ip=?', (ip,))
    store.db.execute('DELETE FROM activity WHERE ip=?', (ip,))


def forget(store, config, ip, run=subprocess.run):
    """`forget IP`: no longer a known user of any port."""
    ports = [row[0] for row in store.db.execute('SELECT port FROM known WHERE ip=?', (ip,))]
    store.db.execute('DELETE FROM known WHERE ip=?', (ip,))
    store.db.execute('DELETE FROM sessions WHERE ip=?', (ip,))
    forgive(store, ip)
    name = 'known6' if ':' in ip else 'known4'
    for port in ports:
        run(['nft', 'delete', 'element', 'inet', config['GUARD_TABLE'], name, f'{{ {ip} . {port} }}'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def prune(store, config, now):
    db = store.db
    pause = data.duration(config['SSH_BEHAVIOR_PAUSE'])
    try:
        longest = max(span for _, _, span, _ in rules(config['SSH_BEHAVIOR_RULES']))
    except ValueError:
        longest = 0
    db.execute('DELETE FROM streaks WHERE last<=?', (now - pause,))
    db.execute('DELETE FROM activity WHERE ip NOT IN (SELECT ip FROM streaks) OR slot<?',
               (int((now - longest) // SLOT) - 1,))
    db.execute('DELETE FROM known WHERE expiry<=?', (now,))
    for table, order in (('known', 'expiry'), ('streaks', 'last'), ('activity', 'slot'), ('counters', 'packets')):
        count = db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
        if count > MAX_ROWS:
            db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY {order} LIMIT ?)',
                       (count - MAX_ROWS,))
            store.set('capacity_gap', now)


def observe(store, config, document, now, generation=None, sockets=None, run=subprocess.run, listed=lists.listed):
    """One minute of session learning and behavior rules. Returns bans applied."""
    if config.get('SSH_SLOW_PROTECTION') != 'on':
        return []
    ports = forwarded(config)
    if not ports:
        return []
    names = set_names(document)
    if config.get('LEARN_USERS') == 'on':
        learn(store, config, read_sockets(run) if sockets is None else sockets, ports, now, listed)
    else:
        store.db.execute('DELETE FROM known')  # switched off: nothing stays exempt
    prune(store, config, now)
    if 'known4' in names:  # older tables (before an upgrade refresh) have no such set
        sync_known(store, config, document, now, run)
    applied = []
    if config.get('SSH_SLOW_BEHAVIOR') == 'on' and 'count4' in names:
        changes = deltas(store, document, generation)
        known = {row[0] for row in store.db.execute('SELECT DISTINCT ip FROM known WHERE expiry>?', (now,))}
        for ip in [ip for ip in changes if ip in known]:
            forgive(store, ip)  # a proven login anywhere: this source is not judged
            changes.pop(ip)
        pause = data.duration(config['SSH_BEHAVIOR_PAUSE'])
        track(store, changes, now, pause)
        entries = rules(config['SSH_BEHAVIOR_RULES'])
        per_port = config['JAIL_PER_PORT'] == 'on'
        rows = [row for _, row in lists.kernel_rows(document, now)]
        rows += data.records(lists.read(lists.state_directory() / 'blocklist.conf'), 'block')
        for ip in sorted(changes):
            current = streak(store, ip)
            if not current:
                continue
            for scope, reason, limit in judge(current[0], now, current[2], entries, per_port,
                                              config['SSH_BEHAVIOR_PAUSE']):
                if ban(store, config, rows, ip, scope, reason, limit, now, run):
                    applied.append((ip, scope, reason))
                if scope == '*':
                    forgive(store, ip)
                else:
                    store.db.execute('DELETE FROM activity WHERE ip=? AND port=?', (ip, int(scope)))
    return applied


def span(seconds):
    minutes = int(seconds // 60)
    return f'{minutes // 60}h{minutes % 60:02d}m'


def summary(store, config, now, limit=10):
    """Read-only status lines; empty for state written by older releases."""
    try:
        known = store.db.execute('SELECT count(*) FROM known WHERE expiry>?', (now,)).fetchone()[0]
        streaks = list(store.db.execute('SELECT ip, start, last FROM streaks WHERE last>?',
                                        (now - data.duration(config['SSH_BEHAVIOR_PAUSE']),)))
        activity = {}
        for ip, port, slot, count in store.db.execute('SELECT ip, port, slot, connections FROM activity'):
            activity.setdefault(ip, []).append((port, slot, count))
    except sqlite3.OperationalError:
        return []
    lines = ['Known users of forwarded ports (source/port pairs): ' + str(known),
             'Active behavior streaks: ' + str(len(streaks))]
    try:
        entries = rules(config['SSH_BEHAVIOR_RULES'])
    except ValueError:
        entries = []

    def progress(row):
        best = 0.0
        for number, kind, seconds, _ in entries:
            if kind == 'b':  # enforced by nftables, not by streaks
                continue
            counts = window(activity.get(row[0], []), now, seconds)
            amount = len(counts) if kind == 'p' else sum(counts.values())
            best = max(best, min((row[2] - row[1]) / seconds, amount / number))
        return best
    for row in sorted(streaks, key=progress, reverse=True)[:limit]:
        counts = window(activity.get(row[0], []), now, row[2] - row[1] + SLOT)
        lines.append(f'  {row[0]} streak={span(row[2] - row[1])} ports={len(counts)} '
                     f'connections={sum(counts.values())} progress={int(progress(row) * 100)}%')
    return lines
