# v0.0.7

One on/off switch for slow brute-force protection, now covering forwarded ports, and an activity log that explains every ban.

[English guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.7/README.md) ·
[Chinese guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.7/README.zh-CN.md)

## Changes

- Package revision `0.0.7-3`: new default ban durations. First offense 12 hours,
  then 3 days, 7 days, 30 days and 90 days (`STRIKE_MAX=90d`). Existing settings
  keep their own values; see the migration notes to adopt the new ones.
- Package revision `0.0.7-3`: repeat offenders keep their step. A ban within 90 days
  after the previous ban *ended* moves one step up, and a source released from a
  90-day jail that offends again gets another 90 days instead of 12 hours. A clean
  90 days after a ban starts over; `unban`/`release` forgives.
- Package revision `0.0.7-2`: administrators on unstable networks are no longer
  banned by their own key retries. Keys rejected inside a login that then succeeds
  do not count; rejected keys in a dropped connection count once per connection.
- Package revision `0.0.7-2`: `LEARN_ADMINS=on` learns administrator addresses
  automatically from successful logins to this server (root, the settings owner,
  and `sudo`/`admin`/`wheel` members), with no usernames to type in. It is also
  enabled on upgrade; it only adds trust and never adds bans.
- `SSH_SLOW_PROTECTION=on/off` replaces `SSH_SLOW_MODE`. It sits directly below
  `JAIL_PER_PORT` and is on for new installations. `on` detects, logs and bans;
  `off` does none of these.
- Forwarded ports are now covered. Logins through the tunnel are invisible, so new
  connections are counted: more than 300 per source across all forwarded ports in
  24 hours with shared jails (banned on all ports), or 100 on one port with per-port
  jails (banned on that port). Port 22 keeps 20 failed logins in 24 hours.
- Sources in `whitelist.conf` under any port are known administrators and are never
  counted. Learned administrator addresses (`LOGIN_USERS`) count as whitelisted.
- `~/.frp-ssh-guard/frp-ssh-guard.log` replaces `alerts.log`. It records every ban
  with its reason, limit and end time, plus manual bans, strike escalations, releases
  and accepted settings; newest first, capped by `LOG_MAX_SIZE` (formerly
  `ALERT_LOG_MAX_SIZE`).
- `settings.conf` explains when and how changes take effect. `blocklist.conf`
  explains that an entry without a time is permanent and gives examples.
- Fix: a list holding a subnet plus an address inside it (same ports) no longer
  makes nftables reject every rule. Covered entries are skipped in the firewall and
  kept in the file; overlaps that cannot be stored are reported with both lines.
- List errors name the cause and line; several smaller fixes are listed in the changelog.

## Upgrading

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.7.deb
```

An active guard is refreshed automatically. Debian version `0.0.7-3` replaces
the earlier v0.0.7 packages (`0.0.7-1`, `0.0.7-2`) under the same download name;
download both files again and APT upgrades the earlier build. Upgrades never start bans you did
not choose: `SSH_SLOW_MODE=enforce` becomes `on` (which now also covers forwarded
ports), while `observe`, `off` or a missing value become `off`. To enable it later,
whitelist administrators who use many forwarded machines, set
`SSH_SLOW_PROTECTION=on`, then run `sudo frp-ssh-guard check && sudo frp-ssh-guard reload`.
The settings file is converted in place with a private backup, so `status` shows
pending edits until the next check and reload. See the
[migration notes](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.7/docs/MIGRATING.md).

## Limits

Connection counts are an approximate token bucket that refills across the window,
and a SYN retransmission counts as a new attempt. Heavy legitimate users of
forwarded ports who are not whitelisted can reach the limits. Kernel bans are
sampled about once a minute for the log. Validation status is recorded in
[VALIDATION.md](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.7/docs/VALIDATION.md).

<sub>An X-project by [XyberMind](http://www.xyber-mind.com/).</sub>
