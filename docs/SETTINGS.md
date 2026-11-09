# Settings reference

[中文](SETTINGS.zh-CN.md)

`settings.conf` holds plain `KEY=value` lines. It is read as data; shell commands
are not executed. Most people only set `PROTECTED_PORTS`.

Saving the file changes nothing. Accept your edits with:

```sh
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
```

Use `enable` instead of `reload` the first time. `status` shows `Pending edits: no`
once they are accepted. Reload keeps current bans; connection counters start again.
If `check` or `reload` fails, the previous settings stay active. `whitelist.conf` and
`blocklist.conf` are different: they apply when saved.

Times are a positive whole number followed by `s`, `m`, `h`, `d` or `w`. Counts are
whole numbers from 1 to 1000000 unless noted.

## Everyday settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `PROTECTED_PORTS` | empty | Public frps ports that forward SSH, as a list or ranges. Never include the frps control port or web ports. `22001:60:40` overrides that port's shared rate and burst. |
| `EXCLUDE_PORTS` | empty | Ports to skip inside `PROTECTED_PORTS`. |
| `PROTECT_SERVER_SSH` | `off` | `on` adds this server's port 22 and watches its login results. |
| `BAN_TIMEOUT` | `12h` | Length of a first ban. For a permanent block, add the address to `blocklist.conf` without a time. |
| `STRIKE_LADDER` | `2:3d 3:7d 4:30d 5:90d` | Ban length by repeat offense. A source at the top step stays there. Empty turns this off. |
| `JAIL_PER_PORT` | `off` | `off`: a ban covers every protected port. `on`: only the attacked port. A change affects new bans only. |
| `SSH_SLOW_PROTECTION` | `on` | Detects attacks that stay under the per-minute limits. `off` also stops the behavior rules. |
| `SSH_SLOW_BEHAVIOR` | `on` | Applies `SSH_BEHAVIOR_RULES`. Needs `SSH_SLOW_PROTECTION=on`. |
| `SSH_BEHAVIOR_RULES` | `20b:30m 4p:2h 3p:6h 50c:12h` | The patterns that ban a source. See below. |
| `LEARN_ADMINS` | `on` | Whitelists a source after root, the settings owner, or a `sudo`, `admin` or `wheel` member logs in to this server. Everyone sharing that public address is trusted too. |
| `LEARN_USERS` | `on` | Stops counting a source on a forwarded port once it has held a real session there. |
| `PER_IP_RATE`, `PER_IP_BURST` | `2`, `40` | New connections per minute, and the burst allowed, per source and port. Exceeding them bans the source. |
| `GLOBAL_RATE`, `GLOBAL_BURST` | `30`, `20` | The same for each port across all sources. Excess is dropped and nobody is banned. |

## Behavior rules

Only sources that never completed a login are judged. Whitelisted sources and known
users are skipped.

| Rule | Bans a source when | Scope of the ban |
| --- | --- | --- |
| `Nb:T` | It makes about N new connections within T. | Follows `JAIL_PER_PORT`. |
| `Np:T` | Its streak lasted T and the last T held N different ports. | All ports. |
| `Nc:T` | Its streak lasted T and the last T held N connections. | Follows `JAIL_PER_PORT`. |

A streak is a run of connections with no pause of `SSH_BEHAVIOR_PAUSE`.

`Nb:T` is the burst limit. The firewall applies it during the burst, with no streak
needed. It allows N connections at once, then refills at N per T, so the count is
approximate. Allowed: N from 2, T from 1m to 6h, and at most one such rule. Remove it
from the list to turn it off. For `Np:T` and `Nc:T`, T is from 15m to 7d, and N for
`Np:T` starts at 2.

Whitelist monitoring probes, CI, backup jobs and scripts that make many short
connections, because their short sessions never prove a login.

## Advanced settings

These already have defaults. To change one, remove the leading `# ` from its line.

| Setting | Default | Meaning |
| --- | --- | --- |
| `SSH_AUTH_FAILURES` | `5` | Failed local logins within `SSH_AUTH_WINDOW` before a ban. |
| `SSH_INVALID_USER_FAILURES` | `3` | Connections for unknown accounts within `SSH_AUTH_WINDOW` before a ban. |
| `SSH_AUTH_WINDOW` | `10m` | Window for the two limits above. |
| `SSH_SLOW_TOTAL_CONNECTIONS` | `300` | New connections per source across forwarded ports within `SSH_SLOW_WINDOW` (shared jails). |
| `SSH_SLOW_PORT_CONNECTIONS` | `100` | New connections per source on one port within `SSH_SLOW_WINDOW` (per-port jails). |
| `SSH_SLOW_FAILURES` | `20` | Failed logins per source on port 22 within `SSH_SLOW_WINDOW`. |
| `SSH_SLOW_WINDOW` | `24h` | Window for the three limits above. |
| `SSH_BEHAVIOR_PAUSE` | `2h` | Pause that starts a streak over, from 30m to 12h. |
| `LOGIN_USERS` | empty | Extra accounts that teach trust like `LEARN_ADMINS`, as an extended regular expression such as `alice\|bob`. |
| `MAX_LEARNED` | `500` | Most learned addresses kept; the oldest are removed first. |
| `LEARN_TIMEOUT` | `90d` | How long a learned address or known user lasts. Later logins renew it. |
| `LEARN_SESSION_AGE` | `3m` | A connection open this long proved a login, from 3m to 1d. Keep it above the backend's `LoginGraceTime`. |
| `LEARN_SESSION_BYTES` | `32KiB` | More data than this sent to the client proved a login, from 8KiB to 100MiB. Raise it for a long pre-login banner. |
| `STRIKE_WINDOW` | `90d` | A ban within this time after the previous ban ended moves one step up `STRIKE_LADDER`. |
| `STRIKE_MAX` | `90d` | Longest escalated ban. |
| `LOG_MAX_SIZE` | `10MiB` | Size of `frp-ssh-guard.log`, from 1KiB to 100MiB. The oldest lines are deleted. |
| `SUBNET_REPORT_MIN_SOURCES` | `5` | Banned sources in one /24 or /64 before a subnet cluster is reported. Subnets are never blocked automatically. |
| `SUBNET_REPORT_WINDOW` | `24h` | Window for that report. |
| `PORT_MIN`, `PORT_MAX` | `1`, `65535` | Allowed range for protected ports. |
| `EDIT_USER` | `root` | Local account that owns command-managed lists. Trusted accounts only. |
| `GUARD_TABLE` | `frp_ssh_persistent_guard` | The nftables table name. To change it: disable, edit, then enable. |

## Moving an older file to this layout

Upgrades keep your file and comments. To switch to the short layout:

```sh
sudo frp-ssh-guard tidy-settings
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
```

Every changed value is kept. Comments you wrote stay only in the private
`settings.conf.before-upgrade-*` copy saved beside the file. `tidy-settings` changes no
firewall rule, and it does not convert a legacy `guard.conf`.
