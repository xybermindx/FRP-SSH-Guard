#!/usr/bin/env bash
# frp-ssh-guard-log.sh -- append newly seen banned IPs to a persistent history.
# nft emits no per-add event, so a short-lived snapshot is taken on a timer.
set -uo pipefail

. "$(dirname -- "${BASH_SOURCE[0]}")/frp-ssh-guard-config.sh"
lock_guard || exit 1
load_guard_config runtime || exit 1
readonly TABLE="${GUARD_TABLE:-frp_ssh_persistent_guard}"
readonly STATE=/run/frp-ssh-guard-bans.state
readonly LOG="${GUARD_LOG_DIR:-$GUARD_DIR/logs}/banned.log"
readonly GUARD_BIN="${GUARD_COMMAND:-$GUARD_DIR/bin/frp-ssh-guard}"
readonly NFTP=$(command -v nft)

mkdir -p "$(dirname "$LOG")"
touch "$LOG" "$STATE" 2>/dev/null || true

if ! "$NFTP" list table inet "$TABLE" >/dev/null 2>&1; then
    unlock_guard
    "$GUARD_BIN" apply >/dev/null 2>&1 || true
    lock_guard || exit 1
fi
"$NFTP" list table inet "$TABLE" >/dev/null 2>&1 || exit 0

current=$(mktemp)
for set in ban4 ban6; do
    if command -v jq >/dev/null 2>&1; then
        "$NFTP" -j list set inet "$TABLE" "$set" 2>/dev/null \
            | jq -r --arg s "$set" '.nftables[]?.set?.elem[]? | "\($s) \(.elem.val)"' >> "$current"
    else
        "$NFTP" list set inet "$TABLE" "$set" 2>/dev/null | tr '\n' ' ' \
            | grep -o 'elements = {[^}]*}' | sed 's/^elements = {//; s/}$//' \
            | tr ',' '\n' | sed 's/^[[:space:]]*//' | while IFS= read -r e; do
                [[ -n "$e" ]] || continue
                printf '%s %s\n' "$set" "${e%% *}"
              done >> "$current"
    fi
done

# append only entries not present in the previous snapshot
if command -v comm >/dev/null; then
    comm -13 <(sort -u "$STATE") <(sort -u "$current") | while IFS= read -r e; do
        [[ -n "$e" ]] || continue
        printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$e" >> "$LOG"
    done
fi

sort -u "$current" > "$STATE"
rm -f "$current"
