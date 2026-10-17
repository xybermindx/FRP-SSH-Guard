#!/usr/bin/env bash
# Shared trusted-shell configuration and runtime serialization.
# Sourcing this library does not read user settings or touch the firewall.
GUARD_DIR="${GUARD_DIR:-/opt/frp-ssh-guard}"
CONFIG_DIR="${GUARD_ETC_DIR:-$GUARD_DIR/etc}"
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
    local mode=${1:-runtime} file
    GUARD_TABLE=frp_ssh_persistent_guard
    PORT_MIN=1 PORT_MAX=65535 EXCLUDE_PORTS='' EDIT_USER=root
    PER_IP_RATE=2 PER_IP_BURST=40 GLOBAL_RATE=30 GLOBAL_BURST=20 BAN_TIMEOUT=6h
    LOGIN_USERS='' MAX_LEARNED=500 LEARN_TIMEOUT=90d
    STRIKE_WINDOW=90d STRIKE_MAX=28d STRIKE_LADDER='2:1d 3:3d 4:7d 5:28d'
    unset PROTECTED_PORTS
    CONFIG_INPUT_DIGEST=''
    file=$(editable_config)
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
        bash -n "$file" || { echo "Invalid configuration syntax: $file" >&2; return 1; }
        # Configuration is trusted root-owned shell input, as in previous releases.
        . "$file"
    fi
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
        MAX_LEARNED LEARN_TIMEOUT STRIKE_WINDOW STRIKE_MAX STRIKE_LADDER CONFIG_INPUT_DIGEST; do
        printf '%s=%q\n' "$key" "${!key-}"
    done
}
