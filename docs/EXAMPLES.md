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
SSH_SLOW_PROTECTION=on
```

Start those forwarded listeners in `frps` first. A ban applies to all selected
ports. The server's own port 22 is outside this selection. With slow protection
on, a source with more than 300 new connections across both ports in 24 hours is
banned; whitelisted administrators are never counted.

### Only this server's SSH port 22

```ini
PROTECTED_PORTS=""
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=off
SSH_SLOW_PROTECTION=on
```

The SSH switch automatically includes port 22, applies connection limits and
starts local sshd failure monitoring. It requires a local SSH listener and sshd
records in journald. It does not collect attempted passwords. Slow protection
bans a source after 20 failed logins in 24 hours.

### FRP and server SSH, with a separate jail per port

```ini
PROTECTED_PORTS="22001,22003"
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=on
SSH_SLOW_PROTECTION=on
```

An automatic ban from port `22001` affects that port only. A local authentication
ban affects port 22. Set `JAIL_PER_PORT=off` for bans shared across all selected
ports. This switch changes ban scope; per-port rate limits exist in both modes.
In this mode slow protection counts each forwarded port separately (more than 100
new connections in 24 hours bans that port only).

### Slow brute-force thresholds

```ini
SSH_SLOW_PROTECTION=on           # off: no slow detection and no slow bans
SSH_SLOW_TOTAL_CONNECTIONS=300   # JAIL_PER_PORT=off: per source, all forwarded ports
SSH_SLOW_PORT_CONNECTIONS=100    # JAIL_PER_PORT=on: per source, one forwarded port
SSH_SLOW_FAILURES=20             # port 22 with PROTECT_SERVER_SSH=on: failed logins
SSH_SLOW_WINDOW=24h
```

Forwarded ports count connections because the tunnel hides login results. Put
administrators who use many forwarded machines in `whitelist.conf` (any port
section); listed addresses are never counted. Each ban, with its reason, appears in
`~/.frp-ssh-guard/frp-ssh-guard.log`.

## Apply and verify settings

For an already active guard:

```bash
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard status
sudo frp-ssh-guard ports
```

For first activation, or after `disable`, use `enable` instead of `reload`.
Saving a file alone does not apply it: `check` only validates, and `reload`
accepts and applies. `status` then shows `Pending edits: no`. Reboot also restores
accepted policy, not unapproved edits. List files are different: saving
`whitelist.conf` or `blocklist.conf` applies it automatically. When
local SSH protection is enabled, status shows `Server SSH protection: on`.

An explicit reload rebuilds the table and rate meters. Exported bans and learned
entries retain their original expiry. Unsampled kernel bans can be lost on an abrupt restart.
Package installation and list updates preserve live automatic bans and timers.

## Manual allow and block examples

```bash
# Trust a source only on the chosen protected port.
sudo frp-ssh-guard allow 198.51.100.10 22001

# Block forever across all protected ports (no duration means forever).
sudo frp-ssh-guard block 203.0.113.20
sudo frp-ssh-guard block 203.0.113.0/24 --all --forever

# Block forever, but only on one protected port.
sudo frp-ssh-guard block 203.0.113.22 --ports 22001

# A temporary ban instead (default BAN_TIMEOUT, or the given duration).
sudo frp-ssh-guard ban 203.0.113.23 12h

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
sudo apt install ./frp-ssh-guard_0.0.7.deb
dpkg-query -W frp-ssh-guard
sudo frp-ssh-guard status
```

The installer adds missing commented defaults and creates a private
`settings.conf.before-upgrade-*` backup when it changes the file. It preserves
existing values, accepted policy, pending edits, live bans and timer deadlines.
Local SSH protection and per-port jails default to off. `SSH_SLOW_MODE=enforce`
becomes `SSH_SLOW_PROTECTION=on`; `observe`, `off` or a missing value become `off`.
`ALERT_LOG_MAX_SIZE` becomes `LOG_MAX_SIZE`. Complete files are unchanged on reinstall.
The first upgrade from v0.0.4 can rebase a custom `OnActiveSec` deadline because
of its old removal hook; see [migration instructions](MIGRATING.md).

## Unified lists

Both `~/.frp-ssh-guard/whitelist.conf` and `blocklist.conf` accept this layout:

```ini
# All protected ports, including native SSH when enabled.
[all]
198.51.100.10

# Only native SSH port 22 (if protected).
[22]
203.0.113.10

# Only this selected FRP port.
[22001]
2001:db8::10
```

In the whitelist these entries allow access; in the blocklist they block access.
Plain entries are manual and permanent. Automatic entries appear in the same file
with `source=learned` (whitelist), `source=runtime` or `source=strike` (blocklist)
and `until=YYYY-MM-DDTHH:MM:SSZ`. Keep those absolute expiry timestamps; apply and
reboot do not renew them. Delete an entry to remove it. A new login/attack may add
it again; `unban` also forgives strike history. CIDRs are supported for manual entries.

Saving a list is watched while active; apply immediately with:

```bash
sudo frp-ssh-guard apply
sudo frp-ssh-guard whitelist
sudo frp-ssh-guard blocklist
```

Administrator learning is on by default (`LEARN_ADMINS=on`): after a successful
login to this server by root, the settings owner or a member of `sudo`, `admin` or
`wheel`, the source is added under `[all]` with `source=learned`. To trust other
accounts too, set `LOGIN_USERS="alice|bob"` (invented example names), then
`check` and `reload`. Logins to machines behind FRP cannot teach trust. `[all]` learned entries cover
every protected port; a `[22001]` whitelist entry does not cover 22. Other firewall
rules, including Fail2ban, remain independent.

### Block periods

```ini
[all]
198.51.100.19                             # no time written: forever
198.51.100.20 forever                     # forever, written out
198.51.100.21 tier=1                      # BAN_TIMEOUT (12 hours by default)
198.51.100.22 until=2030-01-31T00:00:00Z  # until this UTC time
[22]
203.0.113.20 tier=2                       # 3 days
[22001]
203.0.113.21 tier=5                       # 90 days
```

In `blocklist.conf`, an entry without a time and `forever` are both permanent.
Plain durations such as `7d` are rejected in the file (use `tier=`, `until=` or
`block IP --for 7d`); the error names the line. Default tiers 1–5 are 12 hours,
3 days, 7 days, 30 days and 90 days. Tier 1 uses `BAN_TIMEOUT`; tiers 2–5 use the
matching `STRIKE_LADDER` threshold, capped by `STRIKE_MAX`. A tier absent from a
custom ladder is rejected. These are manual duration choices, independent of
automatic strike counts. First apply saves `until=`; repeated apply, upgrades and
reboot keep that deadline. To start a new tier period, remove its old `until=`.

## Local observations (since v0.0.6)

Upgrading an active guard starts the updated monitors automatically; no manual
reload is needed. Use `enable` for first activation. Installation merges missing
settings while retaining custom values, accepted firewall policy, existing jail
expiries and timer deadlines.

The fast SSH detector keeps its 5 failures / 3 invalid-user connections / 10-minute
window. Slow detection is the `SSH_SLOW_PROTECTION` switch since v0.0.7; see
[Slow brute-force thresholds](#slow-brute-force-thresholds).
Successful logins clear short-window failures; long-window failures age out normally.

`~/.frp-ssh-guard/frp-ssh-guard.log` (formerly `alerts.log`) contains one event per
line, newest first: bans with their reason and end time, manual bans, strike
escalations, releases, accepted settings, previously untrusted successful logins
and suspected subnet clusters. A new source login is a review signal, not proof of
compromise. The file records UTC time, source, ports, reason, method where relevant,
and counts; it never records account names, passwords or raw messages. The default
cap is 10MiB; the oldest complete lines are removed without rotation or archives.
Change `LOG_MAX_SIZE`, then check/reload to trim to a new cap. `status` and
`report` show the cap. These files are private
local deployment data: do not commit or share them. If the home is unavailable,
a private system spool uses the same cap and merges when access returns.

Learning is on for administrators by default (`LEARN_ADMINS`), and `LOGIN_USERS`
adds other accounts. Password, public-key and PAM successes can teach trust, after
the login is classified. Trust applies to the
observed source IP: it does not automatically follow you to a new dynamic address,
and a successful compromised account could teach trust. Keep recovery access.
The guard does not change sshd authentication settings or Fail2ban's firewall rules.

```bash
sudo frp-ssh-guard doctor
sudo frp-ssh-guard report 24h
```

`doctor` reads native SSH rule coverage, monitor state, journal access, whitelist
coverage and alert-file access. Reports filter timestamped events and separate
failures, observed thresholds, new automatic bans and sampled dropped packets.
Packets are not connections or evidence of successful prevention. The existing
log timer checkpoints packet deltas; intervals can straddle a report boundary,
and unsampled drops can be lost during a crash. Reload checkpoints the old table
before replacing it. New long-window coverage begins at explicit activation;
recent legacy short-window attempts are imported without inventing long history.
Observation tables are bounded to 200,000 rows each; capacity loss is shown in reports.
Subnet reports group distinct automatically banned sources by jail scope and
IPv4 /24 or IPv6 /64; manual and restored bans do not count. No subnet is auto-blocked.
