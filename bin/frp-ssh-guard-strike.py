#!/usr/bin/env python3
# frp-ssh-guard-strike.py -- repeat-offender ("strike") manager.
# Each automatic ban moves a source one step up STRIKE_LADDER when it happens
# within STRIKE_WINDOW after the source's previous ban ENDED; a source at the top
# stays there. A clean STRIKE_WINDOW after a ban starts over at BAN_TIMEOUT.
# Escalated bans go into the nft 'hardban' sets and hardban.conf, so the guard
# restores them on reload/reboot. Levels persist in strike-levels.json.
import os, re, subprocess, datetime, time, glob, gzip, fcntl, ipaddress
from pathlib import Path

GUARD_DIR = os.environ.get("GUARD_DIR", "/opt/frp-ssh-guard")
ETC_DIR = os.environ.get("GUARD_ETC_DIR", os.path.join(GUARD_DIR, "etc"))
LIST_DIR = os.environ.get("GUARD_LIST_DIR", os.path.join(GUARD_DIR, "lists"))
LOG_DIR = os.environ.get("GUARD_LOG_DIR", os.path.join(GUARD_DIR, "logs"))
LOG      = os.path.join(LOG_DIR, "banned.log")
STRIKES  = os.path.join(LIST_DIR, "strikes.tsv")
HARDBAN  = os.path.join(LIST_DIR, "hardban.conf")
EXCUSED  = os.path.join(LIST_DIR, "excused.tsv")
EDIT_USER = os.environ.get("EDIT_USER", "root")
TABLE    = os.environ.get("GUARD_TABLE", "frp_ssh_persistent_guard")
NFT      = "/usr/sbin/nft" if os.path.exists("/usr/sbin/nft") else "nft"

# Hold the same lock as CLI updates; read the accepted snapshot through Bash so
# quoted values have exactly the same meaning in every helper.
_lock = open(os.environ.get("GUARD_LOCK_FILE", "/run/frp-ssh-guard.lock"), "a")
fcntl.flock(_lock, fcntl.LOCK_EX)
config_lib = Path(__file__).with_name("frp-ssh-guard-config.sh")
keys = ["STRIKE_WINDOW", "STRIKE_MAX", "STRIKE_LADDER", "GUARD_TABLE", "EDIT_USER", "JAIL_PER_PORT", "MANUAL_DIR",
        "BAN_TIMEOUT"]
loaded = subprocess.run(
    ["bash", "-ec", '. "$1"; load_guard_config runtime; shift; for key; do printf "%s\\0" "${!key}"; done',
     "guard-config", str(config_lib), *keys], check=True, capture_output=True, text=True)
values = loaded.stdout.rstrip('\0').split('\0')
cfg = dict(zip(keys, values))
TABLE = cfg["GUARD_TABLE"]
EDIT_USER = cfg["EDIT_USER"]
PER_PORT = cfg["JAIL_PER_PORT"] == "on"

def parse_dur(s):
    m = re.match(r'^(\d+)([smhdw])$', s.strip())
    if not m:
        try: return int(s)
        except: return 0
    n = int(m.group(1))
    return n * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[m.group(2)]

window = parse_dur(cfg["STRIKE_WINDOW"])
ladder = []
for part in cfg["STRIKE_LADDER"].split():
    if ':' in part:
        k, v = part.split(':', 1)
        try: ladder.append((int(k), v))
        except: pass
ladder.sort()

def dur_for(strikes):
    d = None
    for k, v in ladder:
        if strikes >= k:
            d = v
    return d

def nft(*args):
    try:
        subprocess.run([NFT, *args], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

active = subprocess.run([NFT, "list", "table", "inet", TABLE],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

now = time.time()
excused = {}
if os.path.exists(EXCUSED):
    for line in Path(EXCUSED).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                excused[parts[0]] = float(parts[1])
            except ValueError:
                pass
offenses = {}
# Rotated logs hold offenses from before the private event store existed.
for log_path in sorted(glob.glob(LOG + '*')):
    if not os.path.isfile(log_path):
        continue
    open_log = gzip.open if log_path.endswith('.gz') else open
    with open_log(log_path, 'rt') as f:
        for line in f:
            p = line.split()
            if len(p) < 3:
                continue
            ts, ip = p[0], p[2]
            try:
                ip = str(ipaddress.ip_address(ip))
                # The recorded scope belongs to the offense. Current settings
                # apply to new bans, never reinterpret historical shared/scoped
                # offenses when the strike timer next runs after a mode switch.
                if len(p) >= 4:
                    if not 1 <= int(p[3]) <= 65535:
                        continue
                    key = ip + ' ' + str(int(p[3]))
                else:
                    key = ip
                ep = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=datetime.timezone.utc).timestamp()
            except Exception:
                continue
            if ep < excused.get(ip, 0):   # forgiven at release time
                continue
            offenses.setdefault(key, []).append(ep)

# New monitors record each automatic ban once in the private event store.
# The old log remains readable for pre-upgrade strikes and their deadlines.
import sqlite3
from contextlib import closing
observation_path = Path(GUARD_DIR) / 'observations/events.sqlite3'
if observation_path.is_file():
    with closing(sqlite3.connect(observation_path.as_uri() + '?mode=ro', uri=True)) as observations:
        for ep, ip, scope in observations.execute("SELECT stamp,ip,scope FROM events WHERE kind='ban'"):
            if ep < excused.get(ip, 0):
                continue
            key = ip if scope == '*' else ip + ' ' + scope
            offenses.setdefault(key, []).append(ep)

# Walk each source's offenses in order. Persisted levels let a chain outlive the
# event history: a source released from a 90-day ban that offends again within
# STRIKE_WINDOW gets the top step again instead of starting over.
import json
base = parse_dur(cfg["BAN_TIMEOUT"])


def step(level):
    d = dur_for(level)
    return min(parse_dur(d), parse_dur(cfg['STRIKE_MAX'])) if d else None


levels_path = Path(LIST_DIR) / 'strike-levels.json'
try:
    levels = {k: [int(v[0]), float(v[1]), float(v[2])] for k, v in json.loads(levels_path.read_text()).items()}
except (OSError, ValueError, TypeError, IndexError, AttributeError):
    levels = {}  # rebuilt from the available history
levels = {k: v for k, v in levels.items() if excused.get(k.split()[0], 0) <= v[1]}  # unban/release forgives
for key, times in offenses.items():
    level, seen, end = levels.get(key, (0, 0.0, 0.0))
    newest = seen
    for ep in sorted(times):
        if ep <= seen:
            continue  # processed by an earlier run
        level = level + 1 if level and ep <= end + window else 1
        end = ep + (step(level) or base)
        newest = ep
    levels[key] = [level, newest, end]
levels = {k: v for k, v in levels.items() if v[2] + window >= now}  # a clean window forgets the chain
counts = {k: v[0] for k, v in levels.items()}
last = {k: v[1] for k, v in levels.items()}

# strikes view
os.makedirs(os.path.dirname(STRIKES), exist_ok=True)
with open(STRIKES, "w") as f:
    for ip, c in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
        f.write("%s\t%d\t%s\n" % (ip, c,
                datetime.datetime.fromtimestamp(last[ip], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))

# Respect manual scope and CIDRs when deciding whether to escalate a source.
import importlib.util
_spec = importlib.util.spec_from_file_location('guard_inputs', Path(__file__).with_name('frp-ssh-guard-input.py'))
_inputs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_inputs)
manual_allow = Path(cfg['MANUAL_DIR']) / 'whitelist.conf'
if not manual_allow.exists():
    manual_allow = Path(LIST_DIR) / 'whitelist.conf'
good = []
for path in (manual_allow, Path(LIST_DIR) / 'learned.conf'):
    try:
        good.extend(_inputs.entries(path.read_text(), 'allow'))
    except FileNotFoundError:
        pass


def exempt(key):
    fields = key.split()
    ip = ipaddress.ip_address(fields[0])
    port = int(fields[1]) if len(fields) > 1 else None
    for network, scope, expiry in good:
        if expiry and expiry <= now:
            continue
        if ip not in ipaddress.ip_network(network, strict=False):
            continue
        if scope == '*':
            return True
        if port is not None:
            for token in scope.split(','):
                bounds = [int(p) for p in token.split('-')]
                if bounds[0] <= port <= bounds[-1]:
                    return True
    return False

# target hardbans: escalated steps whose ban is still running
target = {}
for ip, (level, seen, end) in levels.items():
    if exempt(ip) or not step(level):
        continue
    if int(end) > now:
        target[ip] = int(end)

cur = set()
legacy_hardban = os.path.join(LIST_DIR, 'hardguard.conf')
if not os.path.exists(HARDBAN) and os.path.exists(legacy_hardban):
    Path(HARDBAN).write_text(Path(legacy_hardban).read_text())
if os.path.exists(HARDBAN):
    for row in _inputs.records(Path(HARDBAN).read_text()):
        cur.add(row.ip if row.scope == '*' else row.ip + ' ' + row.scope)

# Absolute deadlines are derived from the latest offense, never the timer run.
import json
state_path = Path(LIST_DIR) / 'unified-state.json'
deleted = json.loads(state_path.read_text()).get('deleted', {}) if state_path.exists() else {}
for ip, expiry in list(target.items()):
    fields = ip.split()
    identity = '|'.join((fields[0], fields[1] if len(fields) > 1 else '*', 'strike'))
    if expiry <= deleted.get(identity, 0) + 2:
        target.pop(ip)
if active:
    for ip, expiry in target.items():
        # Opposite-mode bans remain in the scope-independent saved sets/list.
        # Do not insert a scoped key into an address-only set, or vice versa.
        if (' ' in ip) != PER_PORT:
            continue
        fam = "hardban6" if ':' in ip else "hardban4"
        value = ip.replace(' ', ' . ') if PER_PORT else ip
        nft("add", "element", "inet", TABLE, fam, "{ %s timeout %ss }" % (value, max(1, expiry - int(now))))
    for ip in cur - set(target):
        if (' ' in ip) != PER_PORT:
            continue
        fam = "hardban6" if ':' in ip else "hardban4"
        value = ip.replace(' ', ' . ') if PER_PORT else ip
        nft("delete", "element", "inet", TABLE, fam, "{ %s }" % value)

rows = []
for ip, expiry in sorted(target.items()):
    fields = ip.split()
    rows.append(_inputs.format_entry(fields[0], fields[1] if len(fields) > 1 else '*', expiry, 'strike'))
_inputs.atomic_write(HARDBAN, '\n'.join(rows) + ('\n' if rows else ''))
_inputs.atomic_write(levels_path, json.dumps(levels, sort_keys=True) + '\n', 0o640)

try:
    import shutil
    for pth in (HARDBAN, STRIKES, EXCUSED):
        if os.path.exists(pth):
            shutil.chown(pth, user=EDIT_USER)
except Exception:
    pass

print("strike manager: %d IPs with strikes, %d hard-banned" % (len(counts), len(target)))

fcntl.flock(_lock, fcntl.LOCK_UN)
_lock.close()
