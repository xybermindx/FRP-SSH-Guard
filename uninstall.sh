#!/usr/bin/env bash
# frp-ssh-guard uninstaller.
# Removes the systemd units and the nft table. Keeps config/lists unless --purge.
set -euo pipefail

PREFIX=/opt/frp-ssh-guard
PURGE=0
while (( $# )); do
  case "$1" in
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --purge)  PURGE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$PREFIX" =~ ^/([a-zA-Z0-9_-]+/)+[a-zA-Z0-9_-]+$ ]] || { echo "Refusing unsafe prefix: $PREFIX" >&2; exit 2; }
[[ ! -e /usr/lib/frp-ssh-guard/run ]] || { echo "Use apt remove/purge frp-ssh-guard for the Debian package." >&2; exit 1; }
(( EUID == 0 )) || { echo "Run with sudo." >&2; exit 1; }

if (( PURGE )); then
  [[ ( -f "$PREFIX/etc/guard.conf" || -f "$PREFIX/etc/settings.conf" ) && -x "$PREFIX/bin/frp-ssh-guard" ]] || {
    echo "Refusing purge: $PREFIX does not contain a recognized installation." >&2; exit 1;
  }
fi

UNITS=/etc/systemd/system
for u in frp-ssh-guard-learn.service frp-ssh-guard-log.timer frp-ssh-guard-strike.timer frp-ssh-guard-lists.path; do
  systemctl disable --now "$u" 2>/dev/null || true
done
if [[ -x "$PREFIX/bin/frp-ssh-guard" ]]; then
  GUARD_DIR="$PREFIX" "$PREFIX/bin/frp-ssh-guard" remove 2>/dev/null || true
fi
rm -f "$UNITS"/frp-ssh-guard*.service "$UNITS"/frp-ssh-guard*.timer "$UNITS"/frp-ssh-guard*.path
systemctl daemon-reload

if (( PURGE )); then
  rm -rf "$PREFIX"
  echo "Removed units, firewall table and $PREFIX."
else
  echo "Removed units and firewall table. Config/data kept at $PREFIX (use --purge to delete)."
fi
