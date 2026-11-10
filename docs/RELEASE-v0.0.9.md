# v0.0.9

FRP-SSH-Guard on every common systemd Linux family, with a new `.rpm`, a preflight check, and tested coverage of FRP's Linux architectures. It also stops short bursts of password guessing during the burst and makes `settings.conf` much shorter.

[English guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/README.md) ·
[Chinese guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/README.zh-CN.md)

Package revision 2 adds the burst limit and the short settings file to the first v0.0.9 build.

## Changes

- **Burst limit:** `SSH_BEHAVIOR_RULES` gains a burst rule, and the default becomes
  `20b:30m 4p:2h 3p:6h 50c:12h`. A source with no proven login is banned during the
  burst at about 20 new connections within 30 minutes. Bans follow `JAIL_PER_PORT` and
  are logged with the reason `burst-connections`. Whitelisted sources and known users
  are skipped.
- **Short settings file:** 15 everyday settings in five sections, with the others as
  one-line defaults under Advanced. Setting names and meanings are unchanged. The
  [settings reference](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/docs/SETTINGS.md)
  explains each one.
- **`tidy-settings`:** moves an existing file to the short layout. It keeps every
  changed value, saves a private backup and changes no firewall rule.
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

Upgrades keep your settings file and comments. If `SSH_BEHAVIOR_RULES` still has the
exact previous default, the upgrade adds `20b:30m` once and leaves a comment saying so.
An active guard applies it during the automatic refresh. Customized rules are not
changed. Before upgrading, whitelist monitoring probes, CI, backup jobs and scripts
that make many short connections. To turn the burst limit off, remove `20b:30m`, then
run `sudo frp-ssh-guard check && sudo frp-ssh-guard reload`.

## Limits

- A new source can still make about 20 connections before its first ban.
- The burst rule counts connections per source, so attempts spread thinly across many
  addresses are not caught. Key-only SSH login on the backend is the complete answer
  to password guessing.
- The RPM is new. CI installs, reinstalls and removes it in Fedora, Rocky, Alma and
  openSUSE containers, and loads the rules with each distribution's own nftables. The
  SELinux-enforcing VM test with firewalld (`tests/vm-rpm.py`) was not run.
- Containers cannot test firewalld or SELinux. Restarting `nftables.service` with a
  stock `flush ruleset` configuration removes the guard table until recovery restores
  it, within about a minute.

Validation status is recorded in
[VALIDATION.md](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.9/docs/VALIDATION.md).

<sub>An X-project by [XyberMind](http://www.xyber-mind.com/).</sub>
