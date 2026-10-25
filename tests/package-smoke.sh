#!/bin/bash
# Run only inside a disposable Debian/Ubuntu container as root.
set -euo pipefail
trap 'echo "Package smoke test failed at line $LINENO: $BASH_COMMAND" >&2' ERR
[[ ${FRP_GUARD_DISPOSABLE:-} == 1 && $EUID == 0 ]] || { echo 'Requires a disposable container and FRP_GUARD_DISPOSABLE=1.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
package="/src/dist/frp-ssh-guard_$(cat /src/VERSION).deb"
apt-get install -y "$package"
frp-ssh-guard --help
[[ $(frp-ssh-guard --version) == "FRP-SSH-Guard $(cat /src/VERSION)" ]]
[[ ! -e /var/lib/frp-ssh-guard/active.nft ]]
[[ ! -e /etc/systemd/system/multi-user.target.wants/frp-ssh-guard.service ]]
printf '\nPROTECTED_PORTS=22001\nPER_IP_RATE=9\n' >> /etc/frp-ssh-guard/settings.conf
printf '198.51.100.1\n' > /var/lib/frp-ssh-guard/lists/learned.conf
cp /etc/frp-ssh-guard/settings.conf /tmp/expected-settings.conf
# Reinstall exercises configure without truncating settings/state.
dpkg -i "$package"
cmp /tmp/expected-settings.conf /etc/frp-ssh-guard/settings.conf
grep -qx 'PROTECTED_PORTS=22001' /etc/frp-ssh-guard/settings.conf
grep -qx '198.51.100.1' /var/lib/frp-ssh-guard/lists/learned.conf
systemd-analyze verify /usr/lib/systemd/system/frp-ssh-guard*.service /usr/lib/systemd/system/frp-ssh-guard*.timer /usr/lib/systemd/system/frp-ssh-guard*.path
apt-get remove -y frp-ssh-guard
test -f /etc/frp-ssh-guard/settings.conf
test -f /var/lib/frp-ssh-guard/lists/learned.conf
apt-get purge -y frp-ssh-guard
test ! -e /etc/frp-ssh-guard/settings.conf
test ! -e /var/lib/frp-ssh-guard
test ! -e /var/log/frp-ssh-guard

# Simulate an earlier package owning the old conffiles, then upgrade. This
# specifically checks dpkg's obsolete-conffile behavior, not old runtime behavior.
legacy=$(mktemp -d)
mkdir -p "$legacy/DEBIAN" "$legacy/etc/frp-ssh-guard"
cat > "$legacy/DEBIAN/control" <<'CONTROL'
Package: frp-ssh-guard
Version: 0.0.3
Architecture: all
Maintainer: Package smoke test <test@example.invalid>
Description: Legacy configuration upgrade fixture
CONTROL
printf 'PER_IP_RATE=9\n' > "$legacy/etc/frp-ssh-guard/guard.conf"
printf '22001\n' > "$legacy/etc/frp-ssh-guard/ports.conf"
printf '/etc/frp-ssh-guard/guard.conf\n/etc/frp-ssh-guard/ports.conf\n' > "$legacy/DEBIAN/conffiles"
dpkg-deb --build "$legacy" /tmp/legacy.deb
dpkg -i /tmp/legacy.deb
printf '\nBAN_TIMEOUT=3h\n' >> /etc/frp-ssh-guard/guard.conf
dpkg -i "$package"
test ! -e /etc/frp-ssh-guard/settings.conf
grep -qx 'BAN_TIMEOUT=3h' /etc/frp-ssh-guard/guard.conf
grep -qx '22001' /etc/frp-ssh-guard/ports.conf
# Minimal images can configure dpkg to exclude /usr/share/doc. Verify the
# shipped payload independently of those image-level installation filters.
dpkg-deb --fsys-tarfile "$package" | tar -tf - > /tmp/frp-guard-package-files
grep -qx './usr/share/doc/frp-ssh-guard/README.zh-CN.md' /tmp/frp-guard-package-files
grep -qx './usr/share/doc/frp-ssh-guard/examples/settings.conf.example' /tmp/frp-guard-package-files
test -f /usr/share/frp-ssh-guard/settings.conf.default
apt-get purge -y frp-ssh-guard
test ! -e /etc/frp-ssh-guard
