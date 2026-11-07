#!/bin/sh
# Package lifecycle steps shared by every package format (deb, rpm).
#   configure      after install or upgrade (dpkg postinst configure, rpm %post)
#   before-remove  before the package is removed (dpkg prerm remove, rpm %preun on erase)
# Steps that run while this file is not installed (before unpacking, after
# removal) stay in each format's own scripts.
set -eu
LIB=/usr/lib/frp-ssh-guard
COMMAND=/usr/sbin/frp-ssh-guard

configure() {
    for directory in /var/lib/frp-ssh-guard/lists /var/log/frp-ssh-guard; do
        [ -d "$directory" ] || install -d -o root -g root -m 0750 "$directory"
    done
    for name in whitelist.conf blocklist.conf learned.conf hardban.conf excused.tsv strikes.tsv; do
        file=/var/lib/frp-ssh-guard/lists/$name
        if [ ! -e "$file" ]; then install -o root -g root -m 0640 /dev/null "$file"; fi
    done
    [ -d /etc/frp-ssh-guard ] || install -d -o root -g root -m 0755 /etc/frp-ssh-guard
    if [ ! -e /etc/frp-ssh-guard/settings.conf ] && [ ! -e /etc/frp-ssh-guard/guard.conf ]; then
        install -o root -g root -m 0640 /usr/share/frp-ssh-guard/settings.conf.default /etc/frp-ssh-guard/settings.conf
    fi
    # Do not reload the systemd manager: this can rebase timer deadlines.
    python3 "$LIB/frp-ssh-guard-input.py" auto-home \
        /etc/frp-ssh-guard /var/lib/frp-ssh-guard /etc/systemd/system "$COMMAND"
    python3 "$LIB/frp-ssh-guard-input.py" upgrade-settings \
        /etc/frp-ssh-guard /usr/share/frp-ssh-guard/settings.conf.default
    GUARD_DIR=/var/lib/frp-ssh-guard GUARD_ETC_DIR=/etc/frp-ssh-guard \
        python3 "$LIB/frp-ssh-guard-lists.py" upgrade
    if [ -d /run/systemd/system ] && systemctl is-active --quiet frp-ssh-guard.service; then
        # Honor administrator service policy in images and managed installs.
        permitted=0
        if [ -x /usr/sbin/policy-rc.d ]; then
            /usr/sbin/policy-rc.d frp-ssh-guard restart || permitted=$?
        fi
        case "$permitted" in
            0) "$COMMAND" _upgrade ;;
            101) echo 'Automatic refresh deferred by policy-rc.d; existing protection remains active.' ;;
            *) echo 'Service policy check failed; automatic refresh was not attempted.' >&2; exit "$permitted" ;;
        esac
    else
        echo 'FRP-SSH-Guard installed; fresh or inactive installations are not enabled automatically.'
        echo 'Edit the settings path shown by: frp-ssh-guard --help'
        echo 'Then run: sudo frp-ssh-guard check && sudo frp-ssh-guard enable'
    fi
    echo 'Verify: sudo frp-ssh-guard status | Help: frp-ssh-guard --help'
    echo 'Later settings edits still need: sudo frp-ssh-guard reload'
}

before_remove() {
    if [ -d /run/systemd/system ]; then
        "$COMMAND" remove
    else
        systemctl --root=/ disable frp-ssh-guard.service
    fi
}

case "${1:-}" in
    configure) configure ;;
    before-remove) before_remove ;;
    *) echo "Usage: $0 configure|before-remove" >&2; exit 2 ;;
esac
