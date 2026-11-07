#!/usr/bin/env bash
# Platform requirements shared by install.sh and check/enable. Sourcing this file
# reads nothing and changes nothing; it needs only Bash and coreutils.
# Keep GUARD_MIN_NFTABLES equal to the nftables minimum in packaging/control.
GUARD_MIN_NFTABLES=1.0.6
GUARD_MIN_PYTHON=3.9

# version_at_least VERSION MINIMUM
version_at_least() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]; }

# One line per unmet requirement; no output when the platform is supported.
platform_problems() {
    local tool version
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
        printf 'bash %s is older than 4.4\n' "$BASH_VERSION"
    fi
    for tool in nft python3 ss jq flock systemctl journalctl; do
        command -v "$tool" >/dev/null 2>&1 || printf 'missing command: %s\n' "$tool"
    done
    [[ -d "${GUARD_SYSTEMD_RUNTIME:-/run/systemd/system}" ]] || printf 'systemd is not the running init system\n'
    if command -v nft >/dev/null 2>&1; then
        version=$(nft --version 2>/dev/null | sed -n 's/^nftables v\([0-9][0-9.]*\).*/\1/p' | head -n 1)
        if [[ -n "$version" ]] && ! version_at_least "$version" "$GUARD_MIN_NFTABLES"; then
            printf 'nftables %s is older than %s\n' "$version" "$GUARD_MIN_NFTABLES"
        fi
    fi
    if command -v python3 >/dev/null 2>&1; then
        version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
        if [[ -n "$version" ]] && ! version_at_least "$version" "$GUARD_MIN_PYTHON"; then
            printf 'python3 %s is older than %s\n' "$version" "$GUARD_MIN_PYTHON"
        fi
    fi
}

# The install command for the dependencies on this system's package manager.
package_hint() {
    if command -v apt-get >/dev/null 2>&1; then
        echo 'sudo apt-get install nftables python3 iproute2 jq util-linux'
    elif command -v dnf >/dev/null 2>&1; then
        echo 'sudo dnf install nftables python3 iproute jq util-linux'
    elif command -v zypper >/dev/null 2>&1; then
        echo 'sudo zypper install nftables python3 iproute2 jq util-linux'
    elif command -v pacman >/dev/null 2>&1; then
        echo 'sudo pacman -S --needed nftables python iproute2 jq util-linux'
    else
        echo 'Install nftables 1.0.6+, Python 3.9+, iproute2 (ss), jq and util-linux with your package manager.'
    fi
}

# Print problems and the install hint; return 1 when the platform is unsupported.
platform_report() {
    local problems line
    problems=$(platform_problems)
    [[ -n "$problems" ]] || return 0
    printf 'This system does not meet FRP-SSH-Guard requirements:\n' >&2
    while IFS= read -r line; do printf '  %s\n' "$line" >&2; done <<< "$problems"
    printf 'Install the dependencies with: %s\n' "$(package_hint)" >&2
    printf 'Supported: Linux with systemd (Debian, Ubuntu, Fedora, RHEL/Rocky/Alma, openSUSE, Arch).\n' >&2
    return 1
}
