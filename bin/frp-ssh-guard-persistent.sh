#!/usr/bin/env bash
# Managed by frp-ssh-guard-persistent.sh
# VPS-side FRPS SSH guard: global per-port SYN limiter + per-IP auto-ban
# + curated allow-list + auto-learned whitelist. One dedicated nft table.
set -euo pipefail
umask 027

# Resolve paths without reading configuration, so help also works with broken edits.
LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
. "$LIB_DIR/frp-ssh-guard-config.sh"

GUARD_TABLE="${GUARD_TABLE:-frp_ssh_persistent_guard}"
readonly SERVICE=frp-ssh-guard.service
readonly TRIAL_UNIT=frp-ssh-guard-trial
readonly ETC_DIR="${GUARD_ETC_DIR:-$GUARD_DIR/etc}"
readonly BIN_DIR="${GUARD_BIN_DIR:-$GUARD_DIR/bin}"
readonly LIST_DIR="${GUARD_LIST_DIR:-$GUARD_DIR/lists}"
readonly LOG_DIR="${GUARD_LOG_DIR:-$GUARD_DIR/logs}"
readonly PORTS_FILE="$CONFIG_DIR/ports.conf"
GUARD_CONF=$(editable_config)
readonly ALLOW_FILE="$MANUAL_DIR/whitelist.conf"
readonly BLOCKLIST_FILE="$MANUAL_DIR/blocklist.conf"
readonly LEARNED_FILE="$LIST_DIR/learned.conf"
readonly HARDBAN_FILE="$LIST_DIR/hardban.conf"
readonly EXCUSED_FILE="$LIST_DIR/excused.tsv"
readonly ACTIVE_RULES="${GUARD_ACTIVE_RULES:-$ETC_DIR/active.nft}"
readonly INSTALLED_SCRIPT="${GUARD_COMMAND:-$BIN_DIR/frp-ssh-guard}"
readonly UNIT_FILE="${GUARD_UNIT_FILE:-/etc/systemd/system/frp-ssh-guard.service}"
readonly PENDING="${GUARD_TRIAL_PENDING:-/run/frp-ssh-guard-trial.pending}"
readonly UNIT_MARKER='# Managed by frp-ssh-guard-persistent.sh'
readonly TRIAL_MINUTES=30

# Baseline defaults; explicitly loaded settings replace these before dispatch.
PORT_MIN="${PORT_MIN:-1}"
PORT_MAX="${PORT_MAX:-65535}"
EXCLUDE_PORTS="${EXCLUDE_PORTS:-}"
EDIT_USER="${EDIT_USER:-root}"


# Configuration defaults are also shared with background helpers.
DEFAULT_RATE="${GLOBAL_RATE:-30}"
DEFAULT_BURST="${GLOBAL_BURST:-20}"
BAN_TIMEOUT="${BAN_TIMEOUT:-6h}"
PER_IP_RATE="${PER_IP_RATE:-2}"
PER_IP_BURST="${PER_IP_BURST:-40}"
GLOBAL_RATE="${GLOBAL_RATE:-30}"
GLOBAL_BURST="${GLOBAL_BURST:-20}"
MAX_LEARNED="${MAX_LEARNED:-500}"
LEARN_TIMEOUT="${LEARN_TIMEOUT:-90d}"
STRIKE_MAX="${STRIKE_MAX:-28d}"
STRIKE_WINDOW="${STRIKE_WINDOW:-90d}"

STAGE=''
declare -a SPECS=()
declare -a ALLOW4=()
declare -a ALLOW6=()
declare -a LEARNED4=()
declare -a LEARNED6=()
declare -a LEARNED_PP4=()
declare -a LEARNED_PP6=()
declare -a MANUAL4=()
declare -a MANUAL6=()
declare -a ALLOW_PP4=()
declare -a ALLOW_PP6=()
declare -a BLOCK_PP4=()
declare -a BLOCK_PP6=()
declare -a AUTO4=()
declare -a AUTO6=()
declare -a AUTO_PP4=()
declare -a AUTO_PP6=()
declare -a HARDBAN4=()
declare -a HARDBAN6=()
declare -a TRUSTED4=()
declare -a TRUSTED6=()

usage() {
    cat <<'TEXT'
Usage: sudo frp-ssh-guard ACTION [ARG]

Lifecycle / service:
  doctor               Read-only checks of SSH monitoring, lists and alert access.
  version / --version   Show the installed software version (no sudo needed).
  config-home [USER]    Put editable settings/manual lists in USER's ~/.frp-ssh-guard.
  enable [FILE]    Validate, apply now, and enable restoration after reboot.
  install [FILE]   Compatibility alias for enable.
  trial [FILE]     Fresh 30-minute trial; boot restoration stays disabled.
  keep             Retain an active trial AND enable restoration after reboot.
  reload           Validate the installed list and apply it atomically.
  apply            Reapply accepted policy and current lists (internal/compatibility).
  check [FILE]     Validate list, listeners and rules without installing.
  ports            Print accepted ports (configured ports before first activation).
  status           Service state, counters, and allow/learned/ban counts.
  disable          Stop protection and disable startup; retain settings/data.
  remove           Compatibility alias for disable.

Lists & administration:
  whitelist              Show allowed IPs (manual + learned).
  blocklist              Show blocked IPs (manual + active bans + strikes).
  strikes                Show per-IP strike counts.
  banned                 List currently banned IPs with remaining TTL.
  unban IP               Release auto bans/strikes for an IP (forgives history).
  release IP             Fully release: manual + auto + forgive (unblock+unban).
  ban IP [DURATION]      Temporary ban (default BAN_TIMEOUT); use block for permanent.
  block IP [PORTS]       Manual block, forever unless --for DURATION is given.
    --all | --ports PORTS   Select all protected ports (default), or specific ports.
    --forever | --for 6h    Choose permanent (default) or a fixed expiry.
  unblock IP             Remove every blocklist line for an IP/CIDR (manual and automatic).
  allow IP [PORTS]       Add an IP/CIDR to the manual whitelist.
  unallow IP             Remove every whitelist line for an IP/CIDR (manual and learned).
  learned                List auto-learned whitelist entries.
  remember IP / forget IP   Manually edit the auto-learned whitelist.
  report [WINDOW]        Summary: bans, learned, port-22 failures (default 24h).

PORTS argument (optional) for allow/block makes the entry fine-grained:
  allow 198.51.100.10              -> allowed on ALL guarded ports
  allow 198.51.100.10 22001        -> allowed only on 22001
  block 203.0.113.0/24 22011,22019
  block 203.0.113.8 22010-22012  -> only those ports/ranges

Settings edits take effect only after check, then reload (or enable the first time).
whitelist.conf/blocklist.conf edits apply automatically when saved.
Quick start:
  Edit the Settings file shown below, then:
  sudo frp-ssh-guard check
  sudo frp-ssh-guard enable
  sudo frp-ssh-guard status
After editing settings: sudo frp-ssh-guard reload
Help: frp-ssh-guard help (also --help / -h; no sudo required)

TEXT
    printf '\nSettings: %s\nLists: %s\nLogs: %s\n' "$GUARD_CONF" "$MANUAL_DIR" "$LOG_DIR"
}

die() { printf '%s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "Missing command: $1"; }
table_active() { "$NFTP" list table inet "$GUARD_TABLE" >/dev/null 2>&1; }

action=${1:-help}
case "$action" in enable) action=install ;; disable) action=remove ;; esac
case "$action" in
    version|--version|-V)
        if [[ -f "$LIB_DIR/VERSION" ]]; then version=$(cat "$LIB_DIR/VERSION"); else version=$(cat "$LIB_DIR/../VERSION"); fi
        printf 'FRP-SSH-Guard %s\n' "$version"; exit 0 ;;
    -h|--help|help) usage; exit 0 ;;
    install|trial|check|config-home) (( $# <= 2 )) || { usage >&2; exit 2; } ;;
    keep|reload|ports|status|doctor|remove|rollback|banned|learned|blocklist|whitelist|strikes|apply|_upgrade|_expire|_stop)
        (( $# == 1 )) || { usage >&2; exit 2; } ;;
    report)
        (( $# <= 2 )) || { usage >&2; exit 2; } ;;
    block) (( $# >= 2 && $# <= 7 )) || { usage >&2; exit 2; } ;;
    unban|ban|allow|unallow|remember|forget|unblock|release)
        (( $# >= 2 && $# <= 3 )) || { usage >&2; exit 2; } ;;
    *) usage >&2; exit 2 ;;
esac
if (( EUID != 0 )); then
    die "Run this command with sudo."
fi
need nft
NFTP=$(command -v nft)
readonly NFTP

# ---------- config readers ----------

read_ban_conf() {
    # Loading is explicit; never replace accepted policy with pending edits here.
    DEFAULT_RATE=$GLOBAL_RATE DEFAULT_BURST=$GLOBAL_BURST
}

validate_policy() {
    local key args=()
    for key in PORT_MIN PORT_MAX EXCLUDE_PORTS EDIT_USER GUARD_TABLE PER_IP_RATE PER_IP_BURST \
        GLOBAL_RATE GLOBAL_BURST BAN_TIMEOUT MAX_LEARNED LEARN_TIMEOUT STRIKE_WINDOW STRIKE_MAX STRIKE_LADDER \
        PROTECT_SERVER_SSH JAIL_PER_PORT SSH_AUTH_FAILURES SSH_INVALID_USER_FAILURES SSH_AUTH_WINDOW \
        SSH_SLOW_PROTECTION SSH_SLOW_TOTAL_CONNECTIONS SSH_SLOW_PORT_CONNECTIONS SSH_SLOW_FAILURES SSH_SLOW_WINDOW \
        SSH_SLOW_MODE LOG_MAX_SIZE SUBNET_REPORT_MIN_SOURCES SUBNET_REPORT_WINDOW; do
        args+=("$key=${!key}")
    done
    python3 "$LIB_DIR/frp-ssh-guard-validate.py" "${args[@]}" || exit 1
    if [[ -n "$LOGIN_USERS" ]]; then
        local result=0
        grep -E "$LOGIN_USERS" </dev/null >/dev/null 2>&1 || result=$?
        (( result != 2 )) || die 'Invalid LOGIN_USERS: expected a grep extended regular expression.'
    fi
}

selected_ports() {
    if [[ ${PROTECTED_PORTS+x} ]]; then
        printf '%s\n' "$PROTECTED_PORTS" | tr ', ' '\n\n'
    elif [[ -f "$PORTS_FILE" ]]; then
        cat "$PORTS_FILE"
    else
        die "No protected ports. Set PROTECTED_PORTS in $GUARD_CONF."
    fi
}


is_excluded() {
    local p=$1 e first last
    [[ -n "$EXCLUDE_PORTS" ]] || return 1
    for e in ${EXCLUDE_PORTS//,/ }; do
        if [[ "$e" == *-* ]]; then
            first=${e%-*}; last=${e#*-}
            (( p >= first && p <= last )) && return 0
        else
            [[ "$e" == "$p" ]] && return 0
        fi
    done
    return 1
}

read_ports() {
    local input=$1 line line_number=0 spec first last port rate burst previous native=0
    [[ "$PROTECT_SERVER_SSH" == on ]] && native=1
    [[ -f "$input" ]] || die "Port list not found: $input"
    SPECS=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        line=${line#$'\xef\xbb\xbf'}
        line=${line//$'\r'/}
        line=${line%%#*}
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        spec=$line
        if [[ "$spec" =~ ^([0-9]{1,5})(-([0-9]{1,5}))?(:([0-9]{1,7}):([0-9]{1,7}))?$ ]]; then
            first=$((10#${BASH_REMATCH[1]}))
            last=$first
            if [[ -n "${BASH_REMATCH[3]:-}" ]]; then last=$((10#${BASH_REMATCH[3]})); fi
            rate=$DEFAULT_RATE
            burst=$DEFAULT_BURST
            if [[ -n "${BASH_REMATCH[5]:-}" ]]; then
                rate=$((10#${BASH_REMATCH[5]}))
                burst=$((10#${BASH_REMATCH[6]}))
            fi
        else
            die "Invalid list entry on line $line_number: $spec"
        fi
        if (( ((first < PORT_MIN || last > PORT_MAX) && !(first == 22 && last == 22 && native == 1)) || first > last || rate < 1 || rate > 1000000 || burst < 1 || burst > 1000000 )); then
            die "Out of range on line $line_number. Ports: ${PORT_MIN}-${PORT_MAX}; rate/burst: 1-1000000."
        fi
        for ((port=first; port<=last; port++)); do
            if is_excluded "$port"; then
                echo "Skipping excluded port $port." >&2
                continue
            fi
            for previous in "${SPECS[@]}"; do
                [[ "${previous%%:*}" != "$port" ]] || die "Duplicate port $port in the list."
            done
            SPECS+=("$port:$rate:$burst")
        done
    done < "$input"
    if [[ "$PROTECT_SERVER_SSH" == on ]]; then
        is_excluded 22 && die 'Server SSH protection conflicts with excluding port 22.'
        local have_ssh=0
        for spec in "${SPECS[@]}"; do [[ "${spec%%:*}" == 22 ]] && have_ssh=1; done
        (( have_ssh )) || SPECS+=("22:$DEFAULT_RATE:$DEFAULT_BURST")
    fi
    (( ${#SPECS[@]} > 0 )) || die "No SSH ports selected after exclusions."
}

# Skip list entries a wider entry already covers (nftables rejects overlaps).
covered() { [[ ",$1," == *",$2,"* ]]; }

read_allow() {
    local input=${1:-$ALLOW_FILE} parsed family ip scope expiry canonical token suffix remaining now trusted skip
    ALLOW4=(); ALLOW6=(); ALLOW_PP4=(); ALLOW_PP6=(); ALLOW_SNAPSHOT=''
    LEARNED4=(); LEARNED6=(); LEARNED_PP4=(); LEARNED_PP6=(); TRUSTED4=(); TRUSTED6=()
    now=$(date +%s)
    if [[ ! -f "$input" && "$MANUAL_DIR" != "$LIST_DIR" ]]; then input="$LIST_DIR/whitelist.conf"; fi
    [[ -f "$input" ]] || return 0
    parsed=$(python3 "$INPUT_HELPER" read-list "$input" allow) || die 'Invalid manual allow list; no rules changed.'
    # Whitelisted on any port (an administrator): never counted by slow protection.
    trusted=$(python3 "$INPUT_HELPER" trusted "$input") || die 'Invalid manual allow list; no rules changed.'
    while IFS='|' read -r family ip expiry; do
        [[ -n "$family" ]] || continue
        suffix=''
        if (( expiry > 0 )); then
            remaining=$((expiry - now))
            (( remaining > 0 )) || continue
            suffix=" timeout ${remaining}s"
        fi
        if [[ "$family" == 6 ]]; then TRUSTED6+=("$ip$suffix"); else TRUSTED4+=("$ip$suffix"); fi
    done <<< "$trusted"
    while IFS='|' read -r family ip scope expiry canonical skip; do
        [[ -n "$family" ]] || continue
        ALLOW_SNAPSHOT+="$canonical"$'\n'
        if (( expiry > 0 )); then
            remaining=$((expiry - now))
            (( remaining > 0 )) || continue
            suffix=" timeout ${remaining}s"
            if [[ "$scope" == '*' ]]; then
                if [[ "$family" == 6 ]]; then LEARNED6+=("$ip$suffix"); else LEARNED4+=("$ip$suffix"); fi
            else
                for token in ${scope//,/ }; do
                    covered "$skip" "$token" && continue
                    if [[ "$family" == 6 ]]; then LEARNED_PP6+=("$ip . $token$suffix"); else LEARNED_PP4+=("$ip . $token$suffix"); fi
                done
            fi
            continue
        fi
        if [[ "$scope" == '*' ]]; then
            covered "$skip" '*' && continue
            if [[ "$family" == 6 ]]; then ALLOW6+=("$ip"); else ALLOW4+=("$ip"); fi
        else
            for token in ${scope//,/ }; do
                covered "$skip" "$token" && continue
                if [[ "$family" == 6 ]]; then ALLOW_PP6+=("$ip . $token"); else ALLOW_PP4+=("$ip . $token"); fi
            done
        fi
    done <<< "$parsed"
}

read_learned() {
    local input=${1:-$LEARNED_FILE} line
    [[ ! -f "$LIST_DIR/unified-state.json" ]] || return 0
    if [[ ! -f "$input" && -n "${SOURCE_SCRIPT:-}" && -f "${LIST_DIR}/learned.conf" ]]; then
        input="${LIST_DIR}/learned.conf"
    fi
    [[ -f "$input" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%%#*}
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        if [[ "$line" == *:* ]]; then LEARNED6+=("$line"); else LEARNED4+=("$line"); fi
    done < "$input"
}

read_blocklist() {
    local input=${1:-$BLOCKLIST_FILE} parsed family ip scope expiry canonical token suffix remaining now skip
    MANUAL4=(); MANUAL6=(); BLOCK_PP4=(); BLOCK_PP6=(); BLOCK_SNAPSHOT=''
    AUTO4=(); AUTO6=(); AUTO_PP4=(); AUTO_PP6=()
    if [[ ! -f "$input" && "$MANUAL_DIR" != "$LIST_DIR" ]]; then input="$LIST_DIR/blocklist.conf"; fi
    [[ -f "$input" ]] || return 0
    parsed=$(python3 "$INPUT_HELPER" read-list "$input" block "$BAN_TIMEOUT" "$STRIKE_LADDER" "$STRIKE_MAX") || die 'Invalid manual block list; no rules changed.'
    now=$(date +%s)
    while IFS='|' read -r family ip scope expiry canonical skip; do
        [[ -n "$family" ]] || continue
        suffix=''
        if (( expiry > 0 )); then
            remaining=$((expiry - now))
            (( remaining > 0 )) || continue
            suffix=" timeout ${remaining}s"
        fi
        BLOCK_SNAPSHOT+="$canonical"$'\n'
        if [[ "$canonical" == *' source=runtime '* || "$canonical" == *' source=strike '* ]]; then
            if [[ "$scope" == '*' ]]; then
                if [[ "$family" == 6 ]]; then AUTO6+=("$ip$suffix"); else AUTO4+=("$ip$suffix"); fi
            else
                for token in ${scope//,/ }; do
                    covered "$skip" "$token" && continue
                    if [[ "$family" == 6 ]]; then AUTO_PP6+=("$ip . $token$suffix"); else AUTO_PP4+=("$ip . $token$suffix"); fi
                done
            fi
            continue
        fi
        if [[ "$scope" == '*' ]]; then
            covered "$skip" '*' && continue
            if [[ "$family" == 6 ]]; then MANUAL6+=("$ip$suffix"); else MANUAL4+=("$ip$suffix"); fi
        else
            for token in ${scope//,/ }; do
                covered "$skip" "$token" && continue
                if [[ "$family" == 6 ]]; then BLOCK_PP6+=("$ip . $token$suffix"); else BLOCK_PP4+=("$ip . $token$suffix"); fi
            done
        fi
    done <<< "$parsed"
}

save_manual_snapshot() {
    [[ "$MANUAL_DIR" != "$LIST_DIR" ]] || return 0
    local temporary
    temporary=$(mktemp "${TMPDIR:-/run}/frp-ssh-guard.manual.XXXXXX")
    printf '%s' "$ALLOW_SNAPSHOT" > "$temporary"
    cmp -s "$temporary" "$LIST_DIR/whitelist.conf" || atomic_install "$temporary" "$LIST_DIR/whitelist.conf" 0640
    printf '%s' "$BLOCK_SNAPSHOT" > "$temporary"
    cmp -s "$temporary" "$LIST_DIR/blocklist.conf" || atomic_install "$temporary" "$LIST_DIR/blocklist.conf" 0640
    rm -f "$temporary"
}

read_hardban() {
    local input=${1:-$HARDBAN_FILE} parsed family ip scope expiry canonical token spec
    HARDBAN4=(); HARDBAN6=()
    [[ ! -f "$LIST_DIR/unified-state.json" ]] || return 0
    [[ -f "$input" ]] || input="$LIST_DIR/hardguard.conf"
    [[ -f "$input" ]] || return 0
    parsed=$(python3 "$INPUT_HELPER" read-list "$input" block) || die 'Invalid strike list.'
    while IFS='|' read -r family ip scope expiry canonical _; do
        [[ -n "$family" ]] || continue
        if [[ "$JAIL_PER_PORT" == on ]]; then
            if [[ "$scope" == '*' ]]; then
                scope=''
                for spec in "${SPECS[@]}"; do scope+=" ${spec%%:*}"; done
            fi
            for token in ${scope//,/ }; do
                if [[ "$family" == 6 ]]; then HARDBAN6+=("$ip . $token"); else HARDBAN4+=("$ip . $token"); fi
            done
        else
            if [[ "$family" == 6 ]]; then HARDBAN6+=("$ip"); else HARDBAN4+=("$ip"); fi
        fi
    done <<< "$parsed"
}

join_by() { local IFS=,; echo "$*"; }

seconds_of() {
    local value=$1 count=${1%?}
    case "${value: -1}" in
        s) echo $((10#$count)) ;; m) echo $((10#$count * 60)) ;; h) echo $((10#$count * 3600)) ;;
        d) echo $((10#$count * 86400)) ;; w) echo $((10#$count * 604800)) ;;
    esac
}

# Express "more than COUNT new connections within SSH_SLOW_WINDOW" as an nftables
# token bucket: COUNT at once, refilled at COUNT per window (approximate).
slow_limit() {
    local count=$1 window unit=day span=86400
    window=$(seconds_of "$SSH_SLOW_WINDOW")
    if (( window > 86400 )); then unit=week; span=604800; fi
    echo "$(( (count * span + window - 1) / window ))/$unit burst $count packets"
}

verify_listeners() {
    local spec port rate burst listeners listener active=0 unused=0
    for spec in "${SPECS[@]}"; do
        IFS=: read -r port rate burst <<< "$spec"
        listeners=$(ss -H -lntp "sport = :$port")
        if [[ -z "$listeners" ]]; then unused=$((unused + 1)); continue; fi
        while IFS= read -r listener; do
            if [[ "$port" == 22 && "$PROTECT_SERVER_SSH" == on ]]; then
                [[ "$listener" == *'"sshd"'* || "$listener" == *'"systemd"'* ]] || die 'Port 22 is not an SSH listener. No changes made.'
            else
                [[ "$listener" == *'"frps"'* ]] || die "Port $port has a listener not identified as FRPS. No changes made."
            fi
        done <<< "$listeners"
        active=$((active + 1))
    done
    (( active > 0 )) || die "No selected port has a host FRPS listener. Run on the frps VPS after frps starts."
    echo "Selected ports: ${#SPECS[@]}; active FRPS ports: $active; currently unused: $unused."
}

compile_rules() {
    local output=$1 spec port rate burst portset jail_type='' key4='ip saddr' key6='ip6 saddr' slow
    # Slow protection on custom ports counts new connections (logins are hidden by
    # the tunnel): per source across all custom ports in shared mode, or per source
    # and port in per-port mode. Its key and ban scope follow JAIL_PER_PORT.
    slow=$(slow_limit "$SSH_SLOW_TOTAL_CONNECTIONS")
    if [[ "$JAIL_PER_PORT" == on ]]; then
        jail_type=' . inet_service'; key4='ip saddr . tcp dport'; key6='ip6 saddr . tcp dport'
        slow=$(slow_limit "$SSH_SLOW_PORT_CONNECTIONS")
    fi
    local -a plist=()
    for spec in "${SPECS[@]}"; do
        IFS=: read -r port rate burst <<< "$spec"
        plist+=("$port")
    done
    portset=$(join_by "${plist[@]}")
    {
        if table_active; then echo "delete table inet $GUARD_TABLE"; fi
        echo "table inet $GUARD_TABLE {"
        echo "    set allow4   { type ipv4_addr; flags interval; }"
        echo "    set allow6   { type ipv6_addr; flags interval; }"
        echo "    set learned4 { type ipv4_addr; flags dynamic,timeout; timeout $LEARN_TIMEOUT; }"
        echo "    set learned6 { type ipv6_addr; flags dynamic,timeout; timeout $LEARN_TIMEOUT; }"
        echo "    set learned_pp4 { type ipv4_addr . inet_service; flags interval,timeout; }"
        echo "    set learned_pp6 { type ipv6_addr . inet_service; flags interval,timeout; }"
        echo "    set manual4  { type ipv4_addr; flags interval,timeout; }"
        echo "    set manual6  { type ipv6_addr; flags interval,timeout; }"
        echo "    set hardban4 { type ipv4_addr$jail_type; flags dynamic,timeout; timeout $STRIKE_MAX; }"
        echo "    set hardban6 { type ipv6_addr$jail_type; flags dynamic,timeout; timeout $STRIKE_MAX; }"
        echo "    set saved_ban4 { type ipv4_addr; flags timeout; }"
        echo "    set saved_ban6 { type ipv6_addr; flags timeout; }"
        echo "    set saved_ban_pp4 { type ipv4_addr . inet_service; flags interval,timeout; }"
        echo "    set saved_ban_pp6 { type ipv6_addr . inet_service; flags interval,timeout; }"
        echo "    set rate4 { type ipv4_addr . inet_service; flags dynamic,timeout; timeout $BAN_TIMEOUT; size 65536; }"
        echo "    set rate6 { type ipv6_addr . inet_service; flags dynamic,timeout; timeout $BAN_TIMEOUT; size 65536; }"
        echo "    set ban4     { type ipv4_addr$jail_type; flags dynamic,timeout; timeout $BAN_TIMEOUT; size 65536; }"
        echo "    set ban6     { type ipv6_addr$jail_type; flags dynamic,timeout; timeout $BAN_TIMEOUT; size 65536; }"
        echo "    set allow_pp4 { type ipv4_addr . inet_service; flags interval; }"
        echo "    set allow_pp6 { type ipv6_addr . inet_service; flags interval; }"
        echo "    set block_pp4 { type ipv4_addr . inet_service; flags interval,timeout; }"
        echo "    set block_pp6 { type ipv6_addr . inet_service; flags interval,timeout; }"
        echo "    set trusted4 { type ipv4_addr; flags interval,timeout; }"
        echo "    set trusted6 { type ipv6_addr; flags interval,timeout; }"
        echo "    set slow4 { type ipv4_addr$jail_type; flags dynamic,timeout; timeout $SSH_SLOW_WINDOW; size 65536; }"
        echo "    set slow6 { type ipv6_addr$jail_type; flags dynamic,timeout; timeout $SSH_SLOW_WINDOW; size 65536; }"
        echo "    set slowhit4 { type ipv4_addr$jail_type; flags dynamic,timeout; timeout 10m; size 65536; }"
        echo "    set slowhit6 { type ipv6_addr$jail_type; flags dynamic,timeout; timeout 10m; size 65536; }"
        echo "    chain input {"
        echo "        type filter hook input priority -7; policy accept;"
        echo "        iifname \"lo\" return"
        echo "        ct state established,related return"
        echo "        meta l4proto != tcp return"
        echo "        tcp dport != { $portset } return"
        echo "        ip  saddr @allow4   return"
        echo "        ip6 saddr @allow6   return"
        echo "        ip  saddr @learned4 return"
        echo "        ip6 saddr @learned6 return"
        echo "        ip  saddr . tcp dport @learned_pp4 return"
        echo "        ip6 saddr . tcp dport @learned_pp6 return"
        echo "        ip  saddr . tcp dport @allow_pp4 return comment \"allow-port v4\""
        echo "        ip6 saddr . tcp dport @allow_pp6 return comment \"allow-port v6\""
        echo "        ip saddr @saved_ban4 counter drop"
        echo "        ip6 saddr @saved_ban6 counter drop"
        echo "        ip saddr . tcp dport @saved_ban_pp4 counter drop"
        echo "        ip6 saddr . tcp dport @saved_ban_pp6 counter drop"
        echo "        tcp dport { $portset } ip  saddr @manual4  counter drop comment \"manual-block v4\""
        echo "        tcp dport { $portset } ip6 saddr @manual6  counter drop comment \"manual-block v6\""
        echo "        ip  saddr . tcp dport @block_pp4 counter drop comment \"block-port v4\""
        echo "        ip6 saddr . tcp dport @block_pp6 counter drop comment \"block-port v6\""
        echo "        tcp dport { $portset } $key4 @hardban4 counter drop comment \"strike-ban v4\""
        echo "        tcp dport { $portset } $key6 @hardban6 counter drop comment \"strike-ban v6\""
        for spec in "${SPECS[@]}"; do
            IFS=: read -r port rate burst <<< "$spec"
            echo "        tcp dport $port $key4 @ban4 counter drop comment \"$port banned v4\""
            echo "        tcp dport $port $key6 @ban6 counter drop comment \"$port banned v6\""
            echo "        tcp dport $port ct state new tcp flags & (syn | ack) == syn update @rate4 { ip saddr . tcp dport limit rate over ${PER_IP_RATE}/minute burst ${PER_IP_BURST} packets } add @ban4 { $key4 timeout $BAN_TIMEOUT } counter drop comment \"$port per-IP v4\""
            echo "        tcp dport $port ct state new tcp flags & (syn | ack) == syn update @rate6 { ip6 saddr . tcp dport limit rate over ${PER_IP_RATE}/minute burst ${PER_IP_BURST} packets } add @ban6 { $key6 timeout $BAN_TIMEOUT } counter drop comment \"$port per-IP v6\""
            echo "        tcp dport $port ct state new tcp flags & (syn | ack) == syn limit rate over $rate/minute burst $burst packets counter drop comment \"$port global\""
            # Port 22 with local SSH protection uses failed logins from sshd instead.
            if [[ "$SSH_SLOW_PROTECTION" == on && ! ( "$port" == 22 && "$PROTECT_SERVER_SSH" == on ) ]]; then
                echo "        tcp dport $port ct state new tcp flags & (syn | ack) == syn ip saddr != @trusted4 update @slow4 { $key4 limit rate over $slow } add @slowhit4 { $key4 } add @ban4 { $key4 timeout $BAN_TIMEOUT } counter drop comment \"$port slow v4\""
                echo "        tcp dport $port ct state new tcp flags & (syn | ack) == syn ip6 saddr != @trusted6 update @slow6 { $key6 limit rate over $slow } add @slowhit6 { $key6 } add @ban6 { $key6 timeout $BAN_TIMEOUT } counter drop comment \"$port slow v6\""
            fi
            echo "        tcp dport $port ct state new tcp flags & (syn | ack) == syn counter return comment \"$port ok\""
        done
        echo "    }"
        echo "}"
        if (( ${#ALLOW4[@]} )); then
            echo "add element inet $GUARD_TABLE allow4 { $(join_by "${ALLOW4[@]}") }"
        fi
        if (( ${#ALLOW6[@]} )); then
            echo "add element inet $GUARD_TABLE allow6 { $(join_by "${ALLOW6[@]}") }"
        fi
        if (( ${#MANUAL4[@]} )); then
            echo "add element inet $GUARD_TABLE manual4 { $(join_by "${MANUAL4[@]}") }"
        fi
        if (( ${#MANUAL6[@]} )); then
            echo "add element inet $GUARD_TABLE manual6 { $(join_by "${MANUAL6[@]}") }"
        fi
        if (( ${#ALLOW_PP4[@]} )); then
            echo "add element inet $GUARD_TABLE allow_pp4 { $(join_by "${ALLOW_PP4[@]}") }"
        fi
        if (( ${#ALLOW_PP6[@]} )); then
            echo "add element inet $GUARD_TABLE allow_pp6 { $(join_by "${ALLOW_PP6[@]}") }"
        fi
        if (( ${#BLOCK_PP4[@]} )); then
            echo "add element inet $GUARD_TABLE block_pp4 { $(join_by "${BLOCK_PP4[@]}") }"
        fi
        if (( ${#BLOCK_PP6[@]} )); then
            echo "add element inet $GUARD_TABLE block_pp6 { $(join_by "${BLOCK_PP6[@]}") }"
        fi
        if (( ${#LEARNED_PP4[@]} )); then
            echo "add element inet $GUARD_TABLE learned_pp4 { $(join_by "${LEARNED_PP4[@]}") }"
        fi
        if (( ${#LEARNED_PP6[@]} )); then
            echo "add element inet $GUARD_TABLE learned_pp6 { $(join_by "${LEARNED_PP6[@]}") }"
        fi
        if (( ${#TRUSTED4[@]} )); then echo "add element inet $GUARD_TABLE trusted4 { $(join_by "${TRUSTED4[@]}") }"; fi
        if (( ${#TRUSTED6[@]} )); then echo "add element inet $GUARD_TABLE trusted6 { $(join_by "${TRUSTED6[@]}") }"; fi
        if (( ${#AUTO4[@]} )); then echo "add element inet $GUARD_TABLE saved_ban4 { $(join_by "${AUTO4[@]}") }"; fi
        if (( ${#AUTO6[@]} )); then echo "add element inet $GUARD_TABLE saved_ban6 { $(join_by "${AUTO6[@]}") }"; fi
        if (( ${#AUTO_PP4[@]} )); then echo "add element inet $GUARD_TABLE saved_ban_pp4 { $(join_by "${AUTO_PP4[@]}") }"; fi
        if (( ${#AUTO_PP6[@]} )); then echo "add element inet $GUARD_TABLE saved_ban_pp6 { $(join_by "${AUTO_PP6[@]}") }"; fi
        local ip
        for ip in "${LEARNED4[@]:-}"; do
            [[ -n "$ip" ]] || continue
            [[ "$ip" == *" timeout "* ]] || ip+=" timeout $LEARN_TIMEOUT"
            echo "add element inet $GUARD_TABLE learned4 { $ip }"
        done
        for ip in "${LEARNED6[@]:-}"; do
            [[ -n "$ip" ]] || continue
            [[ "$ip" == *" timeout "* ]] || ip+=" timeout $LEARN_TIMEOUT"
            echo "add element inet $GUARD_TABLE learned6 { $ip }"
        done
        for ip in "${HARDBAN4[@]:-}"; do
            [[ -n "$ip" ]] || continue
            echo "add element inet $GUARD_TABLE hardban4 { $ip timeout $STRIKE_MAX }"
        done
        for ip in "${HARDBAN6[@]:-}"; do
            [[ -n "$ip" ]] || continue
            echo "add element inet $GUARD_TABLE hardban6 { $ip timeout $STRIKE_MAX }"
        done
    } > "$output"
}

atomic_install() {
    local source=$1 destination=$2 mode=$3 temporary
    [[ ! -d "$destination" ]] || die "Expected a file, found a directory: $destination"
    temporary=$(mktemp "${destination%/*}/.frp-ssh-guard.XXXXXX")
    if ! install -o root -g root -m "$mode" -- "$source" "$temporary"; then
        rm -f -- "$temporary"; return 1
    fi
    if ! mv -f -- "$temporary" "$destination"; then
        rm -f -- "$temporary"; return 1
    fi
}

write_unit() {
    cat > "$STAGE/unit" <<UNIT
$UNIT_MARKER
[Unit]
Description=FRP SSH port guard (global rate limit + per-IP auto-ban)
DefaultDependencies=no
After=local-fs.target nftables.service firewalld.service
Before=network-pre.target shutdown.target
Wants=network-pre.target frp-ssh-guard-learn.service frp-ssh-guard-auth.service frp-ssh-guard-log.timer frp-ssh-guard-strike.timer frp-ssh-guard-lists.path
Conflicts=shutdown.target
RequiresMountsFor=$GUARD_DIR $NFTP

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=GUARD_DIR=$GUARD_DIR
Environment=GUARD_TABLE=$GUARD_TABLE
ExecStart=$INSTALLED_SCRIPT apply
ExecReload=$INSTALLED_SCRIPT apply
ExecStop=$INSTALLED_SCRIPT _stop

[Install]
WantedBy=multi-user.target
UNIT
}

prepare() {
    STAGE=$(mktemp -d "${TMPDIR:-/run}/frp-ssh-guard.XXXXXX")
    if [[ -n "${1:-}" ]]; then cp -- "$1" "$STAGE/list.conf"; else selected_ports > "$STAGE/list.conf"; fi
    validate_policy
    read_ports "$STAGE/list.conf"
    read_allow; read_learned; read_blocklist; read_hardban
    verify_listeners
    compile_rules "$STAGE/candidate.nft"
    "$NFTP" --check --file "$STAGE/candidate.nft"
}

cleanup() {
    if [[ -n "$STAGE" ]]; then rm -rf -- "$STAGE"; fi
}
trap cleanup EXIT

# Called under the runtime lock. The accepted file is a normalized, complete
# snapshot, independent of further edits and legacy override files.
observe() { python3 "$LIB_DIR/frp-ssh-guard-events.py" "$@" || echo 'Observation update unavailable; protection continues.' >&2; }

commit_candidate() {
    local previous=0
    observe checkpoint
    OBSERVABILITY_VERSION=1
    if [[ -f "$APPLIED_CONF" ]]; then
        cp "$APPLIED_CONF" "$STAGE/previous.conf"
        previous=1
    fi
    PROTECTED_PORTS=$(join_by "${SPECS[@]}")
    if [[ "${action:-}" != _upgrade ]]; then
        CONFIG_INPUT_DIGEST=${candidate_digest:-$(config_digest)}
        if [[ -n "${input:-}" ]]; then CONFIG_INPUT_DIGEST="override:$CONFIG_INPUT_DIGEST"; fi
    fi
    write_accepted_config > "$STAGE/accepted.conf"
    atomic_install "$STAGE/accepted.conf" "$APPLIED_CONF" 0640
    if ! "$NFTP" --file "$STAGE/candidate.nft"; then
        if (( previous )); then
            atomic_install "$STAGE/previous.conf" "$APPLIED_CONF" 0640
        else
            rm -f "$APPLIED_CONF"
        fi
        if [[ ${action:-} == trial ]]; then cancel_trial; fi
        die 'Firewall application failed; previous accepted settings and live rules retained.'
    fi
    save_manual_snapshot
    observe activate
    atomic_install "$STAGE/candidate.nft" "$ACTIVE_RULES" 0640 || \
        die 'Rules and accepted settings are active, but writing the diagnostic rules snapshot failed.'
}


cancel_trial() {
    rm -f -- "$PENDING"
    if systemctl is-active --quiet "$TRIAL_UNIT.timer"; then
        systemctl stop "$TRIAL_UNIT.timer"
    fi
}

verify_unit_owner() {
    if [[ -e "$UNIT_FILE" ]]; then
        grep -Fqx -- "$UNIT_MARKER" "$UNIT_FILE" || die "Refusing to change an unrelated unit: $UNIT_FILE"
    fi
}

# ---------- admin commands ----------

sync_lists() { python3 "$LIB_DIR/frp-ssh-guard-lists.py" sync; }

reload_live() {
    local tmp full set family
    lock_guard
    sync_lists
    if [[ "$action" != apply ]] && ! table_active; then
        echo 'List saved. Protection is inactive; run enable when ready.'
        return 0
    fi
    tmp=$(mktemp "${TMPDIR:-/run}/frp-ssh-guard.ports.XXXXXX")
    selected_ports > "$tmp"
    read_ports "$tmp"
    rm -f "$tmp"
    read_allow
    read_learned
    read_blocklist
    read_hardban
    tmp=$(mktemp "${TMPDIR:-/run}/frp-ssh-guard.live.XXXXXX")
    compile_rules "$tmp"
    if table_active; then
        # Manual-list changes update only their sets. Auto bans, strikes, rate
        # buckets, counters, and their remaining timeouts stay in the kernel.
        full="$tmp.full"
        mv "$tmp" "$full"
        python3 "$LIB_DIR/frp-ssh-guard-lists.py" upgrade-sets > "$tmp" || { rm -f "$tmp" "$full"; return 1; }
        for set in saved_ban4 saved_ban6 saved_ban_pp4 saved_ban_pp6 learned_pp4 learned_pp6 allow4 allow6 allow_pp4 allow_pp6 manual4 manual6 block_pp4 block_pp6 learned4 learned6 trusted4 trusted6; do
            printf 'flush set inet %s %s\n' "$GUARD_TABLE" "$set" >> "$tmp"
        done
        awk '$1=="add" && $2=="element" && $5 ~ /^(allow[46]|allow_pp[46]|manual[46]|block_pp[46]|learned[46]|learned_pp[46]|saved_ban[46]|saved_ban_pp[46]|trusted[46])$/ {print}' "$full" >> "$tmp"
        rm -f "$full"
    fi
    "$NFTP" --check --file "$tmp" || { rm -f "$tmp"; die "Generated rules failed validation."; }
    if ! "$NFTP" --file "$tmp"; then rm -f "$tmp"; die 'Could not apply rules; existing rules retained.'; fi
    save_manual_snapshot
    rm -f "$tmp"
}

cmd_banned() {
    table_active || die "Guard is not active."
    local set ip exp s
    printf '%-6s %-40s %s\n' "SET" "IP" "EXPIRES(s)"
    for set in ban4 ban6 hardban4 hardban6 saved_ban4 saved_ban6 saved_ban_pp4 saved_ban_pp6; do
        if command -v jq >/dev/null 2>&1; then
            "$NFTP" -j list set inet "$GUARD_TABLE" "$set" 2>/dev/null \
                | jq -r --arg s "$set" '.nftables[]?.set?.elem[]? | [$s, (.elem.val | if type == "object" then (.concat | map(tostring) | join(" : ")) else . end), ((.elem.expires // 0)|tostring)] | @tsv' \
                | while IFS=$'\t' read -r s ip exp; do printf '%-6s %-40s %s\n' "$s" "$ip" "$exp"; done
        else
            "$NFTP" list set inet "$GUARD_TABLE" "$set" 2>/dev/null | tr '\n' ' ' \
                | grep -o 'elements = {[^}]*}' | sed 's/^elements = {//; s/}$//' \
                | tr ',' '\n' | sed 's/^[[:space:]]*//' | while IFS= read -r e; do
                    [[ -n "$e" ]] || continue
                    ip=${e%% *}
                    exp=$(sed -n 's/.*expires \([^ ]*\).*/\1/p' <<< "$e"); exp=${exp:--}
                    printf '%-6s %-40s %s\n' "$set" "$ip" "$exp"
                  done
        fi
    done
}

forgive() {
    local ip=$1 now tmp
    now=$(date +%s.%N)
    mkdir -p "$(dirname "$EXCUSED_FILE")"
    touch "$EXCUSED_FILE"
    tmp=$(mktemp)
    awk -F'\t' -v ip="$ip" '$1!=ip' "$EXCUSED_FILE" > "$tmp" 2>/dev/null || true
    printf '%s\t%s\n' "$ip" "$now" >> "$tmp"
    mv "$tmp" "$EXCUSED_FILE"
    fix_owner "$EXCUSED_FILE"
    observe forgive "$ip"
}

cmd_unban() {
    local ip set spec token
    ip=$(python3 "$INPUT_HELPER" host "$1") || exit 1
    table_active || die "Guard is not active."
    # Slow meters too: an exhausted connection budget would re-ban at once.
    for set in ban4 ban6 hardban4 hardban6 slow4 slow6 slowhit4 slowhit6; do
        if [[ "$JAIL_PER_PORT" == on ]]; then
            for spec in ${PROTECTED_PORTS//,/ }; do
                token=${spec%%:*}
                "$NFTP" delete element inet "$GUARD_TABLE" "$set" "{ $ip . $token }" 2>/dev/null || true
            done
        else
            "$NFTP" delete element inet "$GUARD_TABLE" "$set" "{ $ip }" 2>/dev/null || true
        fi
    done
    file_del_ip "$HARDBAN_FILE" "$ip" 2>/dev/null || true
    forgive "$ip"
    python3 "$LIB_DIR/frp-ssh-guard-lists.py" unban "$ip"
    reload_live
    echo "Released $ip from auto bans/strikes; past offenses forgiven."
}

cmd_release() {
    local ip=$1
    python3 "$INPUT_HELPER" edit-list "$CONFIG_BASE" "$BLOCKLIST_FILE" block remove "$ip" '*' forever || exit 1
    file_del_ip "$HARDBAN_FILE" "$ip" 2>/dev/null || true
    forgive "$ip"
    if table_active; then cmd_unban "$ip"; fi
    reload_live
    echo "Fully released $ip (manual + auto cleared, past offenses forgiven)."
}

cmd_block() {
    local ip=$1 scope='*' lifetime=forever selected=0 timed=0
    shift
    while (( $# )); do
        case "$1" in
            --all) (( selected == 0 )) || die 'Choose one port scope.'; scope='*'; selected=1; shift ;;
            --ports) (( selected == 0 && $# >= 2 )) || die 'Use --ports PORTS once.'; scope=$2; selected=1; shift 2 ;;
            --for) (( timed == 0 && $# >= 2 )) || die 'Use --for DURATION once.'; lifetime=$2; timed=1; shift 2 ;;
            --forever) (( timed == 0 )) || die 'Choose one duration.'; lifetime=forever; timed=1; shift ;;
            --*) die 'Unknown block option.' ;;
            *) (( selected == 0 )) || die 'Choose one port scope.'; scope=$1; selected=1; shift ;;
        esac
    done
    python3 "$INPUT_HELPER" edit-list "$CONFIG_BASE" "$BLOCKLIST_FILE" block add "$ip" "$scope" "$lifetime" || exit 1
    reload_live
    echo "Manual block saved: $ip; ports: $scope; duration: $lifetime"
}

cmd_unblock() {
    python3 "$INPUT_HELPER" edit-list "$CONFIG_BASE" "$BLOCKLIST_FILE" block remove "$1" '*' forever || exit 1
    reload_live
    echo "Removed from manual blocklist: $1"
}

cmd_blocklist() {
    sync_lists
    local display=$BLOCKLIST_FILE
    [[ -f "$display" ]] || display="$LIST_DIR/blocklist.conf"
    echo "=== BLOCKLIST (manual + runtime + strike): $display ==="
    cat "$display"
}

cmd_whitelist() {
    sync_lists
    local display=$ALLOW_FILE
    [[ -f "$display" ]] || display="$LIST_DIR/whitelist.conf"
    echo "=== WHITELIST (manual + learned): $display ==="
    cat "$display"
}

cmd_strikes() {
    local f="$LIST_DIR/strikes.tsv"
    if [[ -f "$f" ]] && [[ -s "$f" ]]; then
        printf '%-40s %-8s %s\n' "IP" "STRIKES" "LAST_SEEN"
        cat "$f"
    else
        echo "  (no strikes recorded)"
    fi
}

cmd_ban() {
    local ip dur=${2:-$BAN_TIMEOUT} set spec
    ip=$(python3 "$INPUT_HELPER" host "$1" "$dur") || exit 1
    table_active || die "Guard is not active."
    if [[ "$ip" == *:* ]]; then set=ban6; else set=ban4; fi
    if [[ "$JAIL_PER_PORT" == on ]]; then
        for spec in ${PROTECTED_PORTS//,/ }; do
            "$NFTP" add element inet "$GUARD_TABLE" "$set" "{ $ip . ${spec%%:*} timeout $dur }"
        done
    else
        "$NFTP" add element inet "$GUARD_TABLE" "$set" "{ $ip timeout $dur }"
    fi
    observe manual "$ip" "$dur"
    sync_lists
    echo "Banned $ip for $dur (temporary)."
}

fix_owner() { if [[ "$1" == "$LIST_DIR"/* ]]; then chown "$EDIT_USER" "$1" 2>/dev/null || true; chmod 0644 "$1" 2>/dev/null || true; fi; }
file_add() { local f=$1 ip=$2; touch "$f"; grep -qxF "$ip" "$f" || echo "$ip" >> "$f"; fix_owner "$f"; }
file_del() { local f=$1 ip=$2 tmp; tmp=$(mktemp); grep -vxF "$ip" "$f" > "$tmp" 2>/dev/null || true; mv "$tmp" "$f"; fix_owner "$f"; }
file_del_ip() { local f=$1 ip=$2 tmp; tmp=$(mktemp); awk -v ip="$ip" '{ if ($1==ip) next; print }' "$f" > "$tmp" 2>/dev/null || true; mv "$tmp" "$f"; fix_owner "$f"; }

cmd_allow() {
    local ip=$1 scope=${2:-'*'}
    python3 "$INPUT_HELPER" edit-list "$CONFIG_BASE" "$ALLOW_FILE" allow add "$ip" "$scope" forever || exit 1
    reload_live
    echo "Whitelisted: $ip; ports: $scope"
}
cmd_unallow() {
    python3 "$INPUT_HELPER" edit-list "$CONFIG_BASE" "$ALLOW_FILE" allow remove "$1" '*' forever || exit 1
    reload_live
    echo "Removed from whitelist: $1"
}

cmd_remember() { python3 "$LIB_DIR/frp-ssh-guard-lists.py" remember "$1"; reload_live; }
cmd_forget() { python3 "$LIB_DIR/frp-ssh-guard-lists.py" forget "$1"; reload_live; }

cmd_learned() {
    sync_lists
    echo "LEARNED (see $ALLOW_FILE):"
    python3 "$INPUT_HELPER" read-list "$ALLOW_FILE" allow | awk -F'|' '$5 ~ /source=learned/ {print $5}'
}

cmd_report() {
    python3 "$LIB_DIR/frp-ssh-guard-events.py" report "${1:-24h}"
}

# ---------- main dispatch ----------

# Lifecycle operations have a separate lock: never hold the runtime lock while
# waiting for systemd, whose ExecStart/ExecStop also takes that lock.
case "$action" in
    install|trial|reload|keep|remove|rollback|_upgrade|_expire|config-home)
        exec 8>"${LOCK_FILE}.lifecycle"
        flock -w 30 8 || die 'Another lifecycle operation is running.' ;;
esac
case "$action" in
    remove|rollback|_expire) ;; # stop helpers before taking the runtime lock
    *) lock_guard ;;
esac
case "$action" in
    check|install|trial|reload)
        old_table=''
        if [[ -f "$APPLIED_CONF" ]]; then
            load_guard_config runtime
            old_table=$GUARD_TABLE
            if [[ "$action" != check ]]; then sync_lists; fi
        fi
        candidate_digest=$(config_digest)
        load_guard_config candidate
        if [[ "$GUARD_CONF" == */guard.conf ]]; then
            echo 'Using legacy guard.conf/ports.conf; see docs/MIGRATING.md for settings.conf migration.' >&2
        fi
        if [[ -n "$SSH_SLOW_MODE" ]]; then
            echo "Note: SSH_SLOW_MODE is obsolete; slow protection uses SSH_SLOW_PROTECTION=$SSH_SLOW_PROTECTION." >&2
            echo "Delete the SSH_SLOW_MODE line from $GUARD_CONF (SSH_SLOW_PROTECTION=on/off sits below JAIL_PER_PORT)." >&2
        fi
        if [[ -n "$ALERT_LOG_MAX_SIZE" ]]; then
            echo "Note: ALERT_LOG_MAX_SIZE was renamed LOG_MAX_SIZE (now $LOG_MAX_SIZE); rename it in $GUARD_CONF." >&2
        fi
        if [[ -n "$old_table" && "$old_table" != "$GUARD_TABLE" ]] && \
            { systemctl is-active --quiet "$SERVICE" || "$NFTP" list table inet "$old_table" >/dev/null 2>&1; }; then
            die 'GUARD_TABLE cannot change while active. Run disable, then enable with the new settings.'
        fi ;;
    *) load_guard_config runtime ;;
esac

case "$action" in
    _upgrade)
        # Package upgrades refresh running code from the accepted policy. Never
        # activate an inactive installation or adopt unreviewed settings edits.
        if ! systemctl is-active --quiet "$SERVICE"; then
            echo 'Guard is inactive; automatic upgrade activation skipped.'
            exit 0
        fi
        [[ -f "$APPLIED_CONF" ]] || die 'Active guard has no accepted policy; automatic refresh refused.'
        verify_unit_owner
        sync_lists
        STAGE=$(mktemp -d "${TMPDIR:-/run}/frp-ssh-guard.XXXXXX")
        validate_policy
        selected_ports > "$STAGE/list.conf"
        read_ports "$STAGE/list.conf"
        read_allow; read_learned; read_blocklist; read_hardban
        # List snapshots retain absolute expiry and port scope. Replace rules in
        # one nftables transaction; no listener probe is needed for saved ports.
        compile_rules "$STAGE/candidate.nft"
        "$NFTP" --check --file "$STAGE/candidate.nft"
        commit_candidate
        unlock_guard
        # Existing unit definitions use stable launcher paths. Restart only the
        # long-running readers; leave guard enablement and timer deadlines alone.
        systemctl restart frp-ssh-guard-learn.service || die 'Updated rules active, but automatic learning-monitor refresh failed.'
        systemctl restart frp-ssh-guard-auth.service || die 'Updated rules active, but automatic SSH-monitor refresh failed.'
        echo 'Upgrade applied automatically; updated rules and monitors are active.'
        echo 'Accepted settings, saved ban expiry, boot enablement and timer schedules retained.'
        ;;
    config-home)
        owner=${2:-${SUDO_USER:-root}}
        directory=$(python3 "$INPUT_HELPER" migrate "$CONFIG_BASE" "$GUARD_DIR" "${GUARD_SYSTEMD_DIR:-/etc/systemd/system}" "$owner" "$INSTALLED_SCRIPT") || exit 1
        unlock_guard
        echo "Editable settings and manual lists: $directory"
        echo 'Accepted policy, bans and timer configuration were retained. The list watcher was refreshed.'
        echo 'Edit settings, then check/reload to change policy.'
        ;;
    check|install|trial|reload)
        for tool in ss mktemp cat install mv rm cp readlink grep rmdir sed; do need "$tool"; done
        SOURCE_SCRIPT=$(readlink -f -- "${BASH_SOURCE[0]}")
        if [[ "$action" == reload ]]; then
            systemctl is-active --quiet "$SERVICE" || die 'Guard is inactive. Run enable first.'
        fi
        input=${2:-}
        prepare "$input"
        [[ "$(config_digest)" == "$candidate_digest" ]] || die 'Configuration changed during validation; retry check/enable/reload.'
        if [[ "$action" == check ]]; then
            echo 'Settings, ports, listeners, lists and nftables rules validated. No changes made.'
            exit 0
        fi
        [[ ! -e "$PENDING" ]] || die 'A trial is pending. Use keep or disable before changing settings.'
        if [[ "$action" == trial ]]; then
            if systemctl is-active --quiet "$SERVICE" || systemctl is-enabled --quiet "$SERVICE"; then
                die 'Trial requires an inactive, disabled guard. Use reload for an existing installation.'
            fi
        fi
        verify_unit_owner
        install -d -o root -g root -m 0755 "$GUARD_DIR" "$ETC_DIR"
        install -d -o root -g root -m 0750 "$LIST_DIR" "$LOG_DIR"
        if [[ ! -f "$HARDBAN_FILE" && -f "$LIST_DIR/hardguard.conf" ]]; then
            atomic_install "$LIST_DIR/hardguard.conf" "$HARDBAN_FILE" 0640
        fi
        for file in "$LIST_DIR/whitelist.conf" "$LIST_DIR/blocklist.conf" "$LEARNED_FILE" "$HARDBAN_FILE" "$EXCUSED_FILE" "$LIST_DIR/strikes.tsv"; do
            [[ -f "$file" ]] || install -o root -g root -m 0640 /dev/null "$file"
        done
        if [[ "${GUARD_PACKAGED:-0}" != 1 ]]; then
            install -d -o root -g root -m 0755 "$BIN_DIR"
            [[ "$SOURCE_SCRIPT" == "$INSTALLED_SCRIPT" ]] || atomic_install "$SOURCE_SCRIPT" "$INSTALLED_SCRIPT" 0755
            for helper in frp-ssh-guard-config.sh frp-ssh-guard-validate.py frp-ssh-guard-input.py frp-ssh-guard-lists.py frp-ssh-guard-events.py frp-ssh-guard-alerts.py; do
                [[ "$LIB_DIR/$helper" == "$BIN_DIR/$helper" ]] || atomic_install "$LIB_DIR/$helper" "$BIN_DIR/$helper" 0755
            done
            write_unit
            atomic_install "$STAGE/unit" "$UNIT_FILE" 0644
        fi
        if [[ "$action" == trial ]]; then
            printf 'pending\n' > "$PENDING"
            if ! systemd-run --setenv="GUARD_DIR=$GUARD_DIR" --collect --unit="$TRIAL_UNIT" --on-active="${TRIAL_MINUTES}m" \
                --timer-property=AccuracySec=1s "$INSTALLED_SCRIPT" _expire; then
                rm -f "$PENDING"
                die 'Could not schedule trial expiry. No new firewall rules installed.'
            fi
        fi
        commit_candidate
        if [[ "$EDIT_USER" != root ]]; then
            chown "$EDIT_USER" "$LIST_DIR" "$LIST_DIR"/* || die 'Rules active, but updating list ownership failed.'
        fi
        unlock_guard
        systemctl daemon-reload
        # Rules are already active. ExecStart reuses accepted policy on fresh start.
        systemctl start "$SERVICE" || die "Rules active, but service activation failed. Inspect: systemctl status $SERVICE"
        if [[ "${GUARD_PACKAGED:-0}" == 1 ]] || systemctl cat frp-ssh-guard-learn.service >/dev/null 2>&1; then
            systemctl restart frp-ssh-guard-learn.service || die 'Rules active, but learning-service refresh failed. Inspect its journal and retry reload.'
        fi
        if [[ "${GUARD_PACKAGED:-0}" == 1 ]] || systemctl cat frp-ssh-guard-auth.service >/dev/null 2>&1; then
            systemctl restart frp-ssh-guard-auth.service || die 'Rules active, but SSH authentication monitoring could not start.'
        fi
        if [[ "$action" == trial ]]; then
            echo "Trial active for $TRIAL_MINUTES minutes; reboot restoration disabled. Run: sudo frp-ssh-guard keep"
        else
            systemctl enable "$SERVICE" || die 'Rules active NOW, but enabling reboot restoration failed. Retry enable.'
            echo 'Guard active. Restoration after reboot is enabled.'
        fi
        echo "Settings: $GUARD_CONF"
        echo "Protected ports: $PROTECTED_PORTS"
        ;;
    keep)
        verify_unit_owner
        [[ -e "$PENDING" ]] || die "No trial is pending. Use status to check the persistent guard."
        systemctl is-active --quiet "$SERVICE" || die "Trial service is not active; it may have expired."
        table_active || die "Trial rules are missing. They cannot be retained."
        unlock_guard
        systemctl enable "$SERVICE"
        cancel_trial
        echo "Trial retained; reboot restoration enabled. Counters were not reset."
        ;;
    _stop)
        if table_active; then observe checkpoint; "$NFTP" delete table inet "$GUARD_TABLE"; fi
        ;;
    remove|rollback|_expire)
        if [[ "$action" == _expire && ! -e "$PENDING" ]]; then exit 0; fi
        verify_unit_owner
        # Stop producers first so the history timer cannot recreate the table.
        systemctl disable --now frp-ssh-guard-learn.service frp-ssh-guard-log.timer \
            frp-ssh-guard-strike.timer frp-ssh-guard-lists.path 2>/dev/null || true
        systemctl stop frp-ssh-guard-auth.service frp-ssh-guard-log.service frp-ssh-guard-strike.service \
            frp-ssh-guard-lists.service 2>/dev/null || true
        if [[ -f "$UNIT_FILE" ]]; then systemctl disable --now "$SERVICE" 2>/dev/null || true; fi
        lock_guard
        load_guard_config runtime
        if table_active; then observe checkpoint; "$NFTP" delete table inet "$GUARD_TABLE"; fi
        if [[ "$action" == _expire ]]; then rm -f "$PENDING"; else cancel_trial; fi
        echo "Guard disabled for boot and removed from the firewall. Config files are saved."
        ;;
    ports)
        if [[ ! -f "$APPLIED_CONF" ]]; then load_guard_config candidate; fi
        selected_ports
        ;;
    doctor) python3 "$LIB_DIR/frp-ssh-guard-events.py" doctor ;;
    status)
        observe status
        printf 'Boot startup: '; systemctl is-enabled "$SERVICE" 2>/dev/null || true
        printf 'Service state: '; systemctl is-active "$SERVICE" 2>/dev/null || true
        printf 'Settings: %s\nLists: %s\n' "$GUARD_CONF" "$MANUAL_DIR"
        if [[ -n "$LOGIN_USERS" ]]; then echo 'Whitelist learning: enabled for configured LOGIN_USERS'; else echo 'Whitelist learning: disabled (set LOGIN_USERS, then check and reload)'; fi
        printf 'Server SSH protection: %s\nPer-port jails: %s\n' "$PROTECT_SERVER_SSH" "$JAIL_PER_PORT"
        if [[ -f "$APPLIED_CONF" ]]; then
            printf 'Accepted ports: %s\n' "$PROTECTED_PORTS"
            if [[ "$(config_digest)" == "$CONFIG_INPUT_DIGEST" ]]; then echo 'Pending edits: no'; else echo 'Pending edits: yes (run check, then reload)'; fi
        else
            echo 'Accepted settings: none; run check, then enable.'
        fi
        if [[ -e "$PENDING" ]]; then echo 'Trial: pending (30-minute expiry; run keep to retain)'; else echo 'Trial: none'; fi
        if table_active; then
            "$NFTP" list chain inet "$GUARD_TABLE" input | sed -n '1,5p'
            cnt() { "$NFTP" -j list set inet "$GUARD_TABLE" "$1" 2>/dev/null | jq '[.nftables[]?.set?.elem[]?] | length' 2>/dev/null | head -1; }
            echo "allow   (v4/v6): $(read_allow; echo "${#ALLOW4[@]}/${#ALLOW6[@]}")"
            echo "learned (v4/v6): $(read_allow; read_learned; echo "${#LEARNED4[@]}/${#LEARNED6[@]}")"
            echo "manual  (v4/v6): $(cnt manual4)/$(cnt manual6)   [manual blocklist]"
            echo "ban     (v4/v6): $(cnt ban4)/$(cnt ban6)         [temporary]"
            echo "hardban (v4/v6): $(cnt hardban4)/$(cnt hardban6) [strikes]"
            echo "saved   (v4/v6): $(cnt saved_ban4)/$(cnt saved_ban6) [restored shared bans]"
            echo "saved per-port: $(cnt saved_ban_pp4)/$(cnt saved_ban_pp6)"
            echo "strikes tracked: $(( $(wc -l < "$LIST_DIR/strikes.tsv" 2>/dev/null || echo 0) ))"
        else
            echo "No active guard table. If installed, use reload/install."
        fi
        ;;
    banned)   cmd_banned ;;
    unban)    cmd_unban "$2" ;;
    ban)      cmd_ban "$2" "${3:-}" ;;
    allow)    cmd_allow "$2" "${3:-}" ;;
    unallow)  cmd_unallow "$2" ;;
    learned)  cmd_learned ;;
    remember) cmd_remember "$2" ;;
    forget)   cmd_forget "$2" ;;
    block)    shift; cmd_block "$@" ;;
    unblock)  cmd_unblock "$2" ;;
    release)  cmd_release "$2" ;;
    blocklist) cmd_blocklist ;;
    whitelist) cmd_whitelist ;;
    strikes)  cmd_strikes ;;
    apply)
        if [[ ! -f "$APPLIED_CONF" ]]; then
            [[ -f "$ETC_DIR/guard.conf" && ! -f "$ETC_DIR/settings.conf" ]] || die 'No accepted settings. Run check, then enable.'
            # First start after upgrading a legacy installation: freeze its policy.
            STAGE=$(mktemp -d "${TMPDIR:-/run}/frp-ssh-guard.XXXXXX")
            validate_policy
            selected_ports > "$STAGE/list.conf"
            read_ports "$STAGE/list.conf"
            read_allow; read_learned; read_blocklist; read_hardban
            compile_rules "$STAGE/candidate.nft"
            "$NFTP" --check --file "$STAGE/candidate.nft"
            commit_candidate
        else
            reload_live
        fi
        echo 'Accepted policy and current lists applied.' ;;

    report)   cmd_report "${2:-24h}" ;;
esac
