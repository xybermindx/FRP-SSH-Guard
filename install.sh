#!/usr/bin/env bash
# frp-ssh-guard installer.
# Asks ONLY for the ports to PROTECT and (optionally) the ports to EXCLUDE.
# Everything else uses sane defaults (editable later in etc/settings.conf).
set -euo pipefail

PREFIX=/opt/frp-ssh-guard
PROTECT=""
EXCLUDE=""
EXCLUDE_SET=0
EDIT_USER_SET=0
EDIT_USER="root"

usage() {
  cat <<'TXT'
Usage: sudo ./install.sh [--prefix DIR] [--ports LIST] [--exclude LIST] [--edit-user USER]

  --ports       ports to PROTECT  (required) e.g. 22001,22003 or 20000-20100
  --exclude     ports to EXCLUDE  (optional) e.g. 22002
  --prefix      install directory (default: /opt/frp-ssh-guard)
  --edit-user   user allowed to edit the lists/ dir (default: root)

If --ports is omitted and you're on a terminal, you'll be prompted for it.
TXT
}

while (( $# )); do
  case "$1" in
    --prefix)    PREFIX="${2:?}"; shift 2 ;;
    --ports)     PROTECT="${2:?}"; shift 2 ;;
    --exclude)   EXCLUDE="${2-}"; EXCLUDE_SET=1; shift 2 ;;
    --edit-user) EDIT_USER="${2:?}"; EDIT_USER_SET=1; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$PREFIX" =~ ^/([a-zA-Z0-9_-]+/)+[a-zA-Z0-9_-]+$ ]] || { echo "Use an absolute prefix with at least two components (for example /opt/frp-ssh-guard)." >&2; exit 2; }
[[ ! -e /usr/lib/frp-ssh-guard/run ]] || { echo "The Debian package is installed. Manage it with apt and frp-ssh-guard." >&2; exit 1; }
(( EUID == 0 )) || { echo "Run with sudo." >&2; exit 1; }

for t in nft systemctl ss python3 jq flock journalctl; do
  command -v "$t" >/dev/null || { echo "Missing dependency: $t (install nftables, iproute2, python3, jq)" >&2; exit 1; }
done

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --- only two things are asked ---
if [[ -z "$PROTECT" && ! -f "$PREFIX/etc/ports.conf" && ! -f "$PREFIX/etc/settings.conf" && -t 0 ]]; then
  read -rp "Ports to PROTECT (e.g. 22001,22003 or 20000-20100): " PROTECT
fi
[[ -n "$PROTECT" || -f "$PREFIX/etc/ports.conf" || -f "$PREFIX/etc/settings.conf" ]] || { echo "No protected ports specified. Use --ports." >&2; exit 1; }
if [[ "$EXCLUDE_SET" == 0 && ! -f "$PREFIX/etc/settings.conf" && ! -f "$PREFIX/etc/guard.conf" && -t 0 ]]; then
  read -rp "Ports to EXCLUDE (optional, Enter for none): " EXCLUDE || true
fi

BIN="$PREFIX/bin"; ETC="$PREFIX/etc"; LISTS="$PREFIX/lists"; LOGS="$PREFIX/logs"
install -d -o root -g root -m 0755 "$PREFIX" "$BIN" "$ETC" "$LISTS" "$LOGS"

install -o root -g root -m 0755 "$SRC/bin/frp-ssh-guard-persistent.sh" "$BIN/frp-ssh-guard"
install -o root -g root -m 0755 "$SRC/bin/frp-ssh-guard-learn.sh"       "$BIN/frp-ssh-guard-learn"
install -o root -g root -m 0755 "$SRC/bin/frp-ssh-guard-log.sh"         "$BIN/frp-ssh-guard-log"
install -o root -g root -m 0755 "$SRC/bin/frp-ssh-guard-strike.py"      "$BIN/frp-ssh-guard-strike"
for helper in frp-ssh-guard-config.sh frp-ssh-guard-validate.py; do
  install -o root -g root -m 0755 "$SRC/bin/$helper" "$BIN/$helper"
done

# New installations use one file; preserve existing settings and legacy deployments.
CONFIG="$ETC/settings.conf"
if [[ ! -f "$CONFIG" && -f "$ETC/guard.conf" ]]; then CONFIG="$ETC/guard.conf"; fi
python3 - "$SRC/etc/settings.conf.example" "$CONFIG" "$PROTECT" "$EXCLUDE" "$EDIT_USER" "$EXCLUDE_SET" "$EDIT_USER_SET" <<'PYCONFIG'
import pathlib, re, shlex, sys
example, dest, ports, exclude, user, set_exclude, set_user = sys.argv[1:]
p = pathlib.Path(dest)
fresh = not p.exists()
text = pathlib.Path(example).read_text() if fresh else p.read_text()
values = {}
if ports: values['PROTECTED_PORTS'] = ports
if fresh or set_exclude == '1': values['EXCLUDE_PORTS'] = exclude
if fresh or set_user == '1': values['EDIT_USER'] = user
for key, value in values.items():
    line = key + '=' + shlex.quote(value)
    if re.search(r'^' + key + '=', text, flags=re.M):
        text = re.sub(r'^' + key + '=.*$', lambda _: line, text, flags=re.M)
    else:
        text += '\n' + line + '\n'
p.write_text(text)
PYCONFIG
chmod 0640 "$CONFIG"

# lists (never overwrite existing)
for f in whitelist blocklist; do
  [[ -f "$LISTS/$f.conf" ]] || install -o root -g root -m 0644 "$SRC/etc/$f.conf.example" "$LISTS/$f.conf"
done
for f in learned.conf hardban.conf excused.tsv strikes.tsv; do
  [[ -f "$LISTS/$f" ]] || install -o root -g root -m 0644 /dev/null "$LISTS/$f"
done
[[ "$EDIT_USER" == root ]] || chown -R "$EDIT_USER" "$LISTS" 2>/dev/null || true
chmod 0644 "$LISTS"/* 2>/dev/null || true

# apply rules + create the (boot-persistent) guard service
GUARD_DIR="$PREFIX" "$BIN/frp-ssh-guard" enable

# ---- helper units (learn / history / strike / list watcher) ----
UNITS=/etc/systemd/system
cat > "$UNITS/frp-ssh-guard-learn.service" <<EOF
[Unit]
Description=FRP SSH guard - auto-learn whitelist from successful logins
After=network-online.target frp-ssh-guard.service
Wants=network-online.target
Requisite=frp-ssh-guard.service
PartOf=frp-ssh-guard.service

[Service]
Type=simple
Environment=GUARD_DIR=$PREFIX
ExecStart=$BIN/frp-ssh-guard-learn
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > "$UNITS/frp-ssh-guard-log.service" <<EOF
[Unit]
Description=FRP SSH guard - snapshot banned IPs to history
After=frp-ssh-guard.service
Requisite=frp-ssh-guard.service
PartOf=frp-ssh-guard.service

[Service]
Type=oneshot
Environment=GUARD_DIR=$PREFIX
ExecStart=$BIN/frp-ssh-guard-log
EOF

cat > "$UNITS/frp-ssh-guard-log.timer" <<EOF
[Unit]
Description=Run FRP SSH guard ban-history snapshot every minute
PartOf=frp-ssh-guard.service

[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=1s
Unit=frp-ssh-guard-log.service

[Install]
WantedBy=timers.target
EOF

cat > "$UNITS/frp-ssh-guard-strike.service" <<EOF
[Unit]
Description=FRP SSH guard - strike escalation manager
After=frp-ssh-guard.service
Requisite=frp-ssh-guard.service
PartOf=frp-ssh-guard.service

[Service]
Type=oneshot
Environment=GUARD_DIR=$PREFIX
ExecStart=$BIN/frp-ssh-guard-strike
EOF

cat > "$UNITS/frp-ssh-guard-strike.timer" <<EOF
[Unit]
Description=Run FRP SSH guard strike manager every 5 minutes
PartOf=frp-ssh-guard.service

[Timer]
OnBootSec=120
OnUnitActiveSec=300
AccuracySec=10s
Unit=frp-ssh-guard-strike.service

[Install]
WantedBy=timers.target
EOF

cat > "$UNITS/frp-ssh-guard-lists.service" <<EOF
[Unit]
Description=Apply FRP SSH guard lists after edits
After=frp-ssh-guard.service
Requisite=frp-ssh-guard.service
PartOf=frp-ssh-guard.service

[Service]
Type=oneshot
Environment=GUARD_DIR=$PREFIX
ExecStart=$BIN/frp-ssh-guard apply
EOF

cat > "$UNITS/frp-ssh-guard-lists.path" <<EOF
[Unit]
Description=Watch FRP SSH guard list files for edits
PartOf=frp-ssh-guard.service

[Path]
PathModified=$LISTS/whitelist.conf
PathModified=$LISTS/blocklist.conf
Unit=frp-ssh-guard-lists.service

[Install]
WantedBy=paths.target
EOF

systemctl daemon-reload
systemctl enable --now frp-ssh-guard-learn.service \
                       frp-ssh-guard-log.timer \
                       frp-ssh-guard-strike.timer \
                       frp-ssh-guard-lists.path

echo
echo "Installed to $PREFIX"
echo "  protecting: $PROTECT"
echo "  excluding : ${EXCLUDE:-none}"
echo "  manage    : sudo $BIN/frp-ssh-guard status"
