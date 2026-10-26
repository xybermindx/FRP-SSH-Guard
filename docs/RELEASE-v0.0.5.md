# FRP-SSH-Guard v0.0.5

Protect FRP-forwarded SSH ports and optionally the server's SSH port 22, with
shared or per-port jails and upgrades that preserve your configuration.

Project credit: [XyberMind team](http://www.xyber-mind.com/).

[English guide](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/README.md) ·
[Chinese guide](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/README.zh-CN.md) ·
[Examples](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/docs/EXAMPLES.md) ·
[Migration instructions](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/docs/MIGRATING.md)

## What's new

- Optional native SSH protection: `PROTECT_SERVER_SSH=on` enables port-22
  connection limits and failed/invalid-user login detection. Default: `off`.
- Shared jails by default; `JAIL_PER_PORT=on` separates automatic bans by port.
- Settings and combined manual/automatic lists live in `~/.frp-ssh-guard/`.
  Lists have comments, `[all]` and per-port sections, origin labels and expiry times.
  Manual block entries support `forever` or `tier=1` through `tier=5`.
- Installation imports existing jails automatically, preserves their port scope
  and remaining lifetime, and adds missing settings without overwriting custom values.
- Trusted SSH login learning supports password, public key and PAM authentication.
  Configure `LOGIN_USERS` to enable it; successful logins refresh learned expiry.
- Upgrades preserve active jails and timer deadlines. Manual blocks can be permanent
  or timed, across all protected ports or selected ports.

## Install or upgrade

Download **`frp-ssh-guard_0.0.5.deb`** and **`SHA256SUMS`** from Assets:

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.5.deb
frp-ssh-guard --version
sudo frp-ssh-guard status
```

APT replaces the installed program files and keeps your settings. An internal
Debian revision lets it recognize newer builds; the release version is **v0.0.5**.
No manual uninstall or copying of jailed IPs is required.

Installation does not enable protection or adopt pending settings. Find the
settings path with `frp-ssh-guard --help`, then apply desired changes:

```bash
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard status
```

Use `enable` instead of `reload` for first activation. An explicit reload also
starts the updated SSH monitors. List edits are watched while active; use
`sudo frp-ssh-guard apply` to apply them immediately with the accepted settings.
Saved entries retain their original expiry across reload and reboot.

## Notes

- Whitelists override this guard only. Fail2ban and other firewall rules remain independent.
- Learning needs trusted `LOGIN_USERS` and local sshd journal records; forwarded
  SSH authentication outcomes are encrypted and unavailable to the guard.
- Kernel bans are sampled by the log timer, normally within 60 seconds. Unsampled
  entries can be lost on an abrupt restart. Legacy entries without a saved or live
  timeout receive the configured duration once during migration.
- The first upgrade from v0.0.4 can rebase a custom `OnActiveSec` deadline through
  that version's old removal hook. See the migration guide for older development packages.
- See the [validation record](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/docs/VALIDATION.md)
  for tested platforms and limitations. ARM/32-bit and full Ubuntu FRP/systemd
  runtime have not been verified.

The uploaded assets are the `.deb` and its checksum file. GitHub also provides
source ZIP and tar.gz downloads from the tag.
