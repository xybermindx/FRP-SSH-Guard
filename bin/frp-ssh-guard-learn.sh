#!/usr/bin/env bash
# frp-ssh-guard-learn.sh -- auto-learn whitelist from SUCCESSFUL SSH logins.
# Runs on the FRPS VPS. When an operator account logs in successfully
# (password or publickey), the source IP is added to the nft 'learned' set
# (rolling LEARN_TIMEOUT) and persisted so it survives reboot/reload.
set -uo pipefail

. "$(dirname -- "${BASH_SOURCE[0]}")/frp-ssh-guard-config.sh"
lock_guard || exit 1
load_guard_config runtime || exit 1
unlock_guard
TABLE="${GUARD_TABLE:-frp_ssh_persistent_guard}"
readonly LEARNED_FILE="${GUARD_LIST_DIR:-$GUARD_DIR/lists}/learned.conf"
readonly LOG="${GUARD_LOG_DIR:-$GUARD_DIR/logs}/learned.log"
readonly NFTP=$(command -v nft)
EDIT_USER="${EDIT_USER:-root}"
# Operator accounts allowed to teach the whitelist (regex alternation, from accepted settings).
USERS="${LOGIN_USERS:-}"
[[ -n "$USERS" ]] || { echo "Auto-learning disabled: set LOGIN_USERS in settings.conf and run reload to enable."; exit 0; } 
LEARN_TIMEOUT="${LEARN_TIMEOUT:-90d}"
MAX_LEARNED="${MAX_LEARNED:-500}"

mkdir -p "$(dirname "$LEARNED_FILE")" "$(dirname "$LOG")"
touch "$LEARNED_FILE" "$LOG"

table_active() { "$NFTP" list table inet "$TABLE" >/dev/null 2>&1; }

# Best-effort: also exempt a trusted IP from fail2ban's sshd jail at runtime.
f2b_ignore() {
    command -v fail2ban-client >/dev/null 2>&1 || return 0
    fail2ban-client status sshd >/dev/null 2>&1 || return 0
    fail2ban-client set sshd addignoreip "$1" >/dev/null 2>&1 || true
}

learn() {
    local ip=$1 fam set
    [[ -n "$ip" ]] || return 0
    if [[ "$ip" == *:* ]]; then fam=v6; set=learned6; else fam=v4; set=learned4; fi
    f2b_ignore "$ip"

    if grep -qxF "$ip" "$LEARNED_FILE" 2>/dev/null; then
        # already known: just refresh the nft TTL
        if table_active; then
            "$NFTP" add element inet "$TABLE" "$set" "{ $ip timeout $LEARN_TIMEOUT }" 2>/dev/null || true
        fi
        return 0
    fi

    echo "learning $ip ($fam) from successful login" >> "$LOG"
    echo "$ip" >> "$LEARNED_FILE"
    chown "$EDIT_USER" "$LEARNED_FILE" 2>/dev/null || true
    chmod 0644 "$LEARNED_FILE" 2>/dev/null || true
    if table_active; then
        "$NFTP" add element inet "$TABLE" "$set" "{ $ip timeout $LEARN_TIMEOUT }" 2>/dev/null \
            || echo "warn: could not add $ip to nft $set" >> "$LOG"
    fi

    # enforce cap: drop oldest lines beyond MAX_LEARNED
    local count
    count=$(grep -cvE '^\s*(#|$)' "$LEARNED_FILE" 2>/dev/null || echo 0)
    if (( count > MAX_LEARNED )); then
        local excess=$(( count - MAX_LEARNED )) tmp ip_old
        while IFS= read -r ip_old && (( excess > 0 )); do
            [[ -n "$ip_old" ]] || continue
            if table_active; then
                if [[ "$ip_old" == *:* ]]; then
                    "$NFTP" delete element inet "$TABLE" learned6 "{ $ip_old }" 2>/dev/null || true
                else
                    "$NFTP" delete element inet "$TABLE" learned4 "{ $ip_old }" 2>/dev/null || true
                fi
            fi
            echo "evicted oldest learned $ip_old" >> "$LOG"
            excess=$(( excess - 1 ))
        done < <(grep -vE '^\s*(#|$)' "$LEARNED_FILE")
        # rewrite file keeping only the newest MAX_LEARNED entries
        tmp=$(mktemp)
        grep -vE '^\s*(#|$)' "$LEARNED_FILE" | tail -n "$MAX_LEARNED" > "$tmp"
        mv "$tmp" "$LEARNED_FILE"
    fi
}

process_line() {
    local line=$1 ip
    lock_guard || return
    load_guard_config runtime || { unlock_guard; return; }
    TABLE=$GUARD_TABLE USERS=$LOGIN_USERS
    if [[ -z "$USERS" ]]; then unlock_guard; return; fi
    grep -qE "Accepted (password|publickey) for ($USERS) from " <<< "$line" || { unlock_guard; return 0; }
    ip=$(grep -oE "from [0-9a-fA-F:.]+" <<< "$line" | awk '{print $2}')
    learn "$ip"
    unlock_guard
}

# Read sshd records from the journal, including systems without auth.log.
journalctl --no-pager -n 1000 -f -o cat _COMM=sshd _COMM=sshd-session | while IFS= read -r line; do
    process_line "$line"
done
