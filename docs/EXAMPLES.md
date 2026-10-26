# Configuration and command examples

**English** | [简体中文](EXAMPLES.zh-CN.md) | [Project guide](../README.md)

The ports below are invented and the addresses use documentation-only ranges.
Replace them with your own choices locally; never publish deployment settings or
logs. These snippets change selected keys, not the rest of your settings file.

## Find and edit the configuration

```bash
frp-ssh-guard --help
frp-ssh-guard --version
dpkg-query -W frp-ssh-guard
```

Open the file shown after `Settings:`. A normal sudo installation selects the
invoking user's `~/.frp-ssh-guard/settings.conf`; direct root installation selects
root's home. Upgrades retain the original owner. Do not edit `applied.conf` or an
old system copy when the selected settings are in a home directory.

## Choose one protection setup

### FRP-forwarded SSH only

```ini
PROTECTED_PORTS="22001,22003"
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=off
JAIL_PER_PORT=off
```

Start those forwarded listeners in `frps` first. A ban applies to all selected
ports. The server's own port 22 is outside this selection.

### Only this server's SSH port 22

```ini
PROTECTED_PORTS=""
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=off
```

The SSH switch automatically includes port 22, applies connection limits and
starts local sshd failure monitoring. It requires a local SSH listener and sshd
records in journald. It does not collect attempted passwords.

### FRP and server SSH, with a separate jail per port

```ini
PROTECTED_PORTS="22001,22003"
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=on
```

An automatic ban from port `22001` affects that port only. A local authentication
ban affects port 22. Set `JAIL_PER_PORT=off` for bans shared across all selected
ports. This switch changes ban scope; per-port rate limits exist in both modes.

## Apply and verify settings

For an already active guard:

```bash
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard status
sudo frp-ssh-guard ports
```

For first activation, use `enable` instead of `reload`. Saving a file alone does
not apply it. Reboot also restores accepted policy, not unapproved edits. When
local SSH protection is enabled, status shows `Server SSH protection: on`.

An explicit reload rebuilds the table and clears temporary automatic bans and
rate meters. Manual lists remain; timed manual blocks retain their expiry.
Package installation and list updates preserve live automatic bans and timers.

## Manual allow and block examples

```bash
# Trust a source only on the chosen protected port.
sudo frp-ssh-guard allow 198.51.100.10 22001

# Block indefinitely across all protected ports.
sudo frp-ssh-guard block 203.0.113.20 --all

# Block two protected ports for six hours, in either jail mode.
sudo frp-ssh-guard block 203.0.113.21 --ports 22001,22003 --for 6h

# Inspect and remove a manual block.
sudo frp-ssh-guard blocklist
sudo frp-ssh-guard unblock 203.0.113.21

# Inspect temporary bans; release also removes manual blocks and strike history.
sudo frp-ssh-guard banned
sudo frp-ssh-guard release 203.0.113.20
```

`--all` means all **protected** ports, not every port on the machine. Manual
blocks are permanent unless a duration is given. Timed blocks store an absolute
expiry, so reload and reboot do not extend it. Lists in the selected home folder
can also be edited directly; changes are watched while the guard is running.
Allowlisted and established traffic keeps its precedence over guard blocks.
Fail2ban and other firewalls remain independent; an address banned there must be
released there too.

## Upgrade without reloading policy

```bash
sudo apt install ./frp-ssh-guard_0.0.5-3.deb
dpkg-query -W frp-ssh-guard
sudo frp-ssh-guard status
```

The installer adds missing commented defaults and creates a private
`settings.conf.before-upgrade-*` backup when it changes the file. It preserves
existing values, accepted policy, pending edits, live bans and timer deadlines.
New switches default to off. Complete files are unchanged on reinstall.
The first upgrade from v0.0.4 can rebase a custom `OnActiveSec` deadline because
of its old removal hook; see [migration instructions](MIGRATING.md).
