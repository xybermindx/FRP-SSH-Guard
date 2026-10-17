#!/usr/bin/env python3
# frp-ssh-guard-strike.py -- repeat-offender ("strike") manager.
# Counts how many times each IP has been auto-banned within STRIKE_WINDOW and
# escalates repeat offenders into the nft 'hardban' set (kept at the cap), and
# persists them so the guard restores them on reload/reboot.
import os, re, subprocess, datetime, time, glob, gzip, fcntl
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
keys = ["STRIKE_WINDOW", "STRIKE_MAX", "STRIKE_LADDER", "GUARD_TABLE", "EDIT_USER"]
loaded = subprocess.run(
    ["bash", "-ec", '. "$1"; load_guard_config runtime; shift; for key; do printf "%s\\0" "${!key}"; done',
     "guard-config", str(config_lib), *keys], check=True, capture_output=True, text=True)
values = loaded.stdout.rstrip('\0').split('\0')
cfg = dict(zip(keys, values))
TABLE = cfg["GUARD_TABLE"]
EDIT_USER = cfg["EDIT_USER"]

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
counts, last = {}, {}
# Rotation must not discard offenses still inside STRIKE_WINDOW.
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
                ep = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=datetime.timezone.utc).timestamp()
            except Exception:
                continue
            if ep < excused.get(ip, 0):   # forgiven at release time
                continue
            if now - ep <= window:
                counts[ip] = counts.get(ip, 0) + 1
                last[ip] = max(last.get(ip, 0), ep)

# strikes view
os.makedirs(os.path.dirname(STRIKES), exist_ok=True)
with open(STRIKES, "w") as f:
    for ip, c in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
        f.write("%s\t%d\t%s\n" % (ip, c,
                datetime.datetime.fromtimestamp(last[ip], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))

# whitelisted / learned IPs are never escalated
good = set()
for path in (os.path.join(LIST_DIR, "whitelist.conf"),
             os.path.join(LIST_DIR, "learned.conf")):
    try:
        for line in Path(path).read_text().splitlines():
            line = line.split('#')[0].strip().split()[0] if line.split('#')[0].strip() else ''
            if line:
                good.add(line)
    except FileNotFoundError:
        pass

# target hardbans
target = {}
for ip, c in counts.items():
    if ip in good:
        continue
    d = dur_for(c)
    if d:
        d = str(min(parse_dur(d), parse_dur(cfg['STRIKE_MAX']))) + 's'
    if d:
        target[ip] = d

cur = set()
legacy_hardban = os.path.join(LIST_DIR, 'hardguard.conf')
if not os.path.exists(HARDBAN) and os.path.exists(legacy_hardban):
    Path(HARDBAN).write_text(Path(legacy_hardban).read_text())
if os.path.exists(HARDBAN):
    for line in Path(HARDBAN).read_text().splitlines():
        line = line.split('#')[0].strip()
        if line:
            cur.add(line.split()[0])

if active:
    for ip, d in target.items():
        fam = "hardban6" if ':' in ip else "hardban4"
        nft("add", "element", "inet", TABLE, fam, "{ %s timeout %s }" % (ip, d))
    for ip in cur - set(target):
        fam = "hardban6" if ':' in ip else "hardban4"
        nft("delete", "element", "inet", TABLE, fam, "{ %s }" % ip)

os.makedirs(os.path.dirname(HARDBAN), exist_ok=True)
with open(HARDBAN, "w") as f:
    for ip in sorted(target):
        f.write(ip + "\n")

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
