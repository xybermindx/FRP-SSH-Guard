#!/bin/bash
# Run only inside a disposable Fedora/RHEL/Rocky/Alma/openSUSE container as root.
set -euo pipefail
trap 'echo "RPM smoke test failed at line $LINENO: $BASH_COMMAND" >&2' ERR
[[ ${FRP_GUARD_DISPOSABLE:-} == 1 && $EUID == 0 ]] || { echo 'Requires a disposable container and FRP_GUARD_DISPOSABLE=1.' >&2; exit 1; }
version=$(cat /src/VERSION)
package_version="$version-$(cat /src/PACKAGE_REVISION)"
package="/src/dist/frp-ssh-guard-$version.noarch.rpm"
if command -v dnf >/dev/null 2>&1; then
    add() { dnf install -y "$@"; }
    again() { dnf reinstall -y "$@"; }
    erase() { dnf remove -y frp-ssh-guard; }
else
    add() { zypper --non-interactive install --allow-unsigned-rpm "$@"; }
    again() { zypper --non-interactive install --force --allow-unsigned-rpm "$@"; }
    erase() { zypper --non-interactive remove frp-ssh-guard; }
fi
add "$package"
frp-ssh-guard --help >/dev/null
[[ $(frp-ssh-guard --version) == "FRP-SSH-Guard $version" ]]
[[ $(rpm -q --qf '%{VERSION}-%{RELEASE}' frp-ssh-guard) == "$package_version" ]]
[[ ! -e /var/lib/frp-ssh-guard/active.nft ]]
[[ ! -e /etc/systemd/system/multi-user.target.wants/frp-ssh-guard.service ]]
home_dir=$(python3 /usr/lib/frp-ssh-guard/frp-ssh-guard-input.py location /etc/frp-ssh-guard)
[[ "$home_dir" == /root/.frp-ssh-guard ]]
[[ $(stat -c %a "$home_dir") == 700 && $(stat -c %a "$home_dir/settings.conf") == 600 ]]
for line in PROTECT_SERVER_SSH=off JAIL_PER_PORT=off SSH_SLOW_PROTECTION=on SSH_SLOW_BEHAVIOR=on LEARN_USERS=on; do
    grep -qx "$line" "$home_dir/settings.conf"
done
printf '\nPROTECTED_PORTS=22001\nPER_IP_RATE=9\n' >> "$home_dir/settings.conf"
printf '198.51.100.1\n' > /var/lib/frp-ssh-guard/lists/learned.conf
cp "$home_dir/settings.conf" /tmp/expected-settings.conf
# A reinstall takes the upgrade path (%post count 2, old %preun count 1):
# nothing may be stopped, removed or reset.
again "$package"
cmp /tmp/expected-settings.conf "$home_dir/settings.conf"
grep -qx '198.51.100.1' /var/lib/frp-ssh-guard/lists/learned.conf
systemd-analyze verify /usr/lib/systemd/system/frp-ssh-guard*.service /usr/lib/systemd/system/frp-ssh-guard*.timer /usr/lib/systemd/system/frp-ssh-guard*.path
test -x /usr/lib/frp-ssh-guard/lifecycle.sh
test -f /usr/share/frp-ssh-guard/settings.conf.default
# Minimal images may skip documentation; check the shipped file list itself.
rpm -qlp "$package" > /tmp/frp-guard-package-files
grep -qx /usr/share/doc/frp-ssh-guard/README.zh-CN.md /tmp/frp-guard-package-files
grep -qx /usr/share/doc/frp-ssh-guard/examples/settings.conf.example /tmp/frp-guard-package-files
# Erasing keeps settings, lists and the home copy (RPM has no purge).
erase
test ! -e /usr/lib/frp-ssh-guard/run
test -f /etc/frp-ssh-guard/settings.conf
test -f /var/lib/frp-ssh-guard/lists/learned.conf
test -f "$home_dir/settings.conf"
add "$package"
cmp /tmp/expected-settings.conf "$home_dir/settings.conf"
erase
echo 'RPM package smoke test passed.'
