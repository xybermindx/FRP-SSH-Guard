#!/bin/bash
# Run only inside a disposable, privileged container of a supported distribution.
# Checks this distribution's own Bash, Python and nftables against the host kernel,
# then the package lifecycle: deb, rpm, or (source) the installer preflight.
set -euo pipefail
trap 'echo "Distribution smoke test failed at line $LINENO: $BASH_COMMAND" >&2' ERR
family=${1:?usage: distro-smoke.sh deb|rpm|source}
[[ ${FRP_GUARD_DISPOSABLE:-} == 1 && $EUID == 0 ]] || { echo 'Requires a disposable container and FRP_GUARD_DISPOSABLE=1.' >&2; exit 1; }
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y nftables python3 iproute2 jq util-linux systemd
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nftables python3 iproute jq util-linux systemd gawk diffutils
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install nftables python3 iproute2 jq util-linux systemd gawk diffutils
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed nftables python iproute2 jq util-linux systemd diffutils
else
    echo 'Unknown package manager.' >&2
    exit 1
fi
grep -m1 '^PRETTY_NAME=' /etc/os-release
nft --version
python3 --version
# Containers do not run systemd as init; every other requirement must hold.
GUARD_SYSTEMD_RUNTIME=/ bash /src/install.sh --preflight
work=$(mktemp -d)
cp -r /src/. "$work"
(cd "$work/tests" && FRP_GUARD_LIVE_TESTS=1 python3 -m unittest test_auth test_behavior test_events test_guard \
    test_inputs test_lists test_platform test_deployment)
case "$family" in
    deb) bash /src/tests/package-smoke.sh ;;
    rpm) bash /src/tests/rpm-smoke.sh ;;
    source) ;;
    *) echo "Unknown family: $family" >&2; exit 2 ;;
esac
echo "Distribution smoke test passed ($family)."
