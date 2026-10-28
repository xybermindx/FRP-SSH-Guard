#!/usr/bin/env bash
# Shared literal configuration parsing and trusted runtime serialization.
# Sourcing this library does not read user settings or touch the firewall.
GUARD_DIR="${GUARD_DIR:-/opt/frp-ssh-guard}"
CONFIG_BASE="${GUARD_ETC_DIR:-$GUARD_DIR/etc}"
INPUT_HELPER="$(dirname -- "${BASH_SOURCE[0]}")/frp-ssh-guard-input.py"
CONFIG_DIR=$CONFIG_BASE
MANUAL_DIR="${GUARD_LIST_DIR:-$GUARD_DIR/lists}"
if [[ -f "$CONFIG_BASE/user-home.json" ]]; then
    CONFIG_DIR=$(python3 "$INPUT_HELPER" location "$CONFIG_BASE") || return 1
    MANUAL_DIR=$CONFIG_DIR
fi
APPLIED_CONF="${GUARD_APPLIED_CONF:-$GUARD_DIR/applied.conf}"
LOCK_FILE="${GUARD_LOCK_FILE:-/run/frp-ssh-guard.lock}"

editable_config() {
    if [[ -f "$CONFIG_DIR/settings.conf" || ! -f "$CONFIG_DIR/guard.conf" ]]; then
        printf '%s\n' "$CONFIG_DIR/settings.conf"
    else
        printf '%s\n' "$CONFIG_DIR/guard.conf"
    fi
}

lock_guard() {
    [[ ${GUARD_LOCKED:-0} == 1 ]] && return 0
    exec 9>"$LOCK_FILE"
    flock -w 30 9 || { echo 'Another guard operation is running; try again shortly.' >&2; return 1; }
    GUARD_LOCKED=1
}

unlock_guard() {
    flock -u 9
    exec 9>&-
    GUARD_LOCKED=0
}

load_guard_config() {
    local mode=${1:-runtime} file assignments
    GUARD_TABLE=frp_ssh_persistent_guard
    PORT_MIN=1 PORT_MAX=65535 EXCLUDE_PORTS='' EDIT_USER=root
    PER_IP_RATE=2 PER_IP_BURST=40 GLOBAL_RATE=30 GLOBAL_BURST=20 BAN_TIMEOUT=6h
    LOGIN_USERS='' MAX_LEARNED=500 LEARN_TIMEOUT=90d
    STRIKE_WINDOW=90d STRIKE_MAX=28d STRIKE_LADDER='2:1d 3:3d 4:7d 5:28d'
    PROTECT_SERVER_SSH=off JAIL_PER_PORT=off
    SSH_AUTH_FAILURES=5 SSH_INVALID_USER_FAILURES=3 SSH_AUTH_WINDOW=10m
    # SSH_SLOW_PROTECTION has no fallback value here: see the conversion below.
    unset SSH_SLOW_PROTECTION
    SSH_SLOW_MODE='' SSH_SLOW_TOTAL_CONNECTIONS=300 SSH_SLOW_PORT_CONNECTIONS=100
    SSH_SLOW_FAILURES=20 SSH_SLOW_WINDOW=24h
    unset LOG_MAX_SIZE
    ALERT_LOG_MAX_SIZE='' SUBNET_REPORT_MIN_SOURCES=5 SUBNET_REPORT_WINDOW=24h
    OBSERVABILITY_VERSION=0
    unset PROTECTED_PORTS
    CONFIG_INPUT_DIGEST=''
    file=$(editable_config)
    if [[ "$mode" == candidate && "$CONFIG_DIR" != "$CONFIG_BASE" && ! -f "$file" ]]; then
        echo "Editable settings are unavailable: $file" >&2
        return 1
    fi
    if [[ "$mode" == runtime ]]; then
        if [[ -f "$APPLIED_CONF" ]]; then
            file=$APPLIED_CONF
        elif [[ "$file" == */settings.conf ]]; then
            # A new installation has no active policy yet. Pending edits must not
            # prevent status, list administration, disable, or package removal.
            file=/dev/null
        fi
    fi
    if [[ -f "$file" ]]; then
        if [[ "$file" == "$APPLIED_CONF" ]]; then
            # Only the root-owned, generated runtime snapshot is shell input.
            bash -n "$file" || return 1
            . "$file"
        else
            assignments=$(python3 "$INPUT_HELPER" settings "$file") || return 1
            eval "$assignments"  # parser emits only known keys and shell-quoted literal values
        fi
    fi
    if [[ -z ${SSH_SLOW_PROTECTION+x} ]]; then
        # Older files and accepted snapshots used SSH_SLOW_MODE. Only explicit
        # enforcement keeps slow bans; observe, off or a missing value become off.
        # Fresh installs set SSH_SLOW_PROTECTION=on in the shipped template.
        if [[ "$SSH_SLOW_MODE" == enforce ]]; then SSH_SLOW_PROTECTION=on; else SSH_SLOW_PROTECTION=off; fi
    fi
    # ALERT_LOG_MAX_SIZE is the pre-0.0.7 name of LOG_MAX_SIZE.
    [[ -n ${LOG_MAX_SIZE+x} ]] || LOG_MAX_SIZE=${ALERT_LOG_MAX_SIZE:-10MiB}
    DEFAULT_RATE=$GLOBAL_RATE DEFAULT_BURST=$GLOBAL_BURST
}

# Hash the editable inputs without executing them (status works with broken edits).
config_digest() {
    local file
    file=$(editable_config)
    { printf '%s\n' "$file"; if [[ -f "$file" ]]; then cat "$file"; fi
      if [[ -f "$CONFIG_DIR/ports.conf" ]]; then printf '\nlegacy-ports\n'; cat "$CONFIG_DIR/ports.conf"; fi
    } | sha256sum | cut -d ' ' -f 1
}

write_accepted_config() {
    local key
    for key in GUARD_TABLE PORT_MIN PORT_MAX EXCLUDE_PORTS EDIT_USER PROTECTED_PORTS \
        PER_IP_RATE PER_IP_BURST GLOBAL_RATE GLOBAL_BURST BAN_TIMEOUT LOGIN_USERS \
        MAX_LEARNED LEARN_TIMEOUT STRIKE_WINDOW STRIKE_MAX STRIKE_LADDER CONFIG_INPUT_DIGEST \
        PROTECT_SERVER_SSH JAIL_PER_PORT SSH_AUTH_FAILURES SSH_INVALID_USER_FAILURES SSH_AUTH_WINDOW \
        SSH_SLOW_PROTECTION SSH_SLOW_TOTAL_CONNECTIONS SSH_SLOW_PORT_CONNECTIONS SSH_SLOW_FAILURES SSH_SLOW_WINDOW \
        LOG_MAX_SIZE SUBNET_REPORT_MIN_SOURCES SUBNET_REPORT_WINDOW OBSERVABILITY_VERSION; do
        printf '%s=%q\n' "$key" "${!key-}"
    done
}
