# v0.0.9 (pre-release)

FRP-SSH-Guard on every common systemd Linux family, with a new `.rpm`, a preflight check, and tested coverage of FRP's Linux architectures.

[English guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/README.md) ·
[Chinese guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/README.zh-CN.md)

This is a pre-release for testing. The stable release remains
[v0.0.8](https://github.com/xybermindx/FRP-SSH-Guard/releases/tag/v0.0.8). Protection
behavior is unchanged from v0.0.8.

## Changes

- **Supported systems:**

  | Family | Versions | Package |
  | --- | --- | --- |
  | Debian, Ubuntu | Debian 12 and 13, Ubuntu 24.04+ | `.deb` |
  | Fedora, RHEL, Rocky Linux, AlmaLinux | Fedora 42+, RHEL/Rocky/Alma 9+ | `.rpm` (new) |
  | openSUSE | Tumbleweed, Leap 16 | `.rpm` (new) |
  | Arch Linux and other systemd distributions | current | `install.sh` |

- **RPM:** upgrades and reinstalls refresh an active guard automatically and never
  stop it. An erase stops protection and keeps settings and state.
- **Preflight:** `./install.sh --preflight` (no root) checks systemd, nftables 1.0.6+,
  Python 3.9+, Bash 4.4+, jq, `ss`, `flock` and `cmp`, and prints the install command for
  your package manager. `check` and `enable` refuse an unsupported system the same way.
- **`doctor`** shows the distribution, architecture, kernel, nftables and Python
  versions, SELinux mode, and firewalld or `nftables.service` status.
- **Architectures:** the packages contain only scripts and run wherever a supported
  distribution ships the dependencies.
  - CI tests amd64 and arm64 on real kernels.
  - Debian armhf, armel, mips64el and riscv64 package install, upgrade and removal
    are tested under emulation.
  - loong64 needs Debian 14 (testing) and is not tested.
  - FRP's mips, mipsle and mips64 builds run on router systems such as OpenWrt, which
    are not supported.

## Installing or upgrading

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.9.deb                                    # Debian, Ubuntu
sudo dnf install ./frp-ssh-guard-0.0.9.noarch.rpm                             # Fedora, RHEL, Rocky, Alma
sudo zypper install --allow-unsigned-rpm ./frp-ssh-guard-0.0.9.noarch.rpm     # openSUSE
```

An active Debian/Ubuntu guard is refreshed automatically, as before. New RPM
installations stay inactive until you configure ports and run
`sudo frp-ssh-guard check && sudo frp-ssh-guard enable`. See the
[migration notes](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/docs/MIGRATING.md)
for RPM removal and purging.

## Limits

- The RPM is new. CI installs, reinstalls and removes it in Fedora, Rocky, Alma and
  openSUSE containers, and loads the rules with each distribution's own nftables. The
  SELinux-enforcing VM test with firewalld (`tests/vm-rpm.py`) has not been run yet.
- Containers cannot test firewalld or SELinux. Restarting `nftables.service` with a
  stock `flush ruleset` configuration removes the guard table until recovery restores
  it, within about a minute.

Validation status is recorded in
[VALIDATION.md](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/docs/VALIDATION.md).

<sub>An X-project by [XyberMind](http://www.xyber-mind.com/).</sub>
