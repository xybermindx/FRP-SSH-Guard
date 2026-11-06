# v0.0.8 (pre-release)

Bans slow bots that rotate across forwarded ports around the clock, while users who log in, including on unstable networks, are never judged.

[English guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.8/README.md) ·
[Chinese guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.8/README.zh-CN.md)

This is a pre-release for testing. The stable release remains
[v0.0.7](https://github.com/xybermindx/FRP-SSH-Guard/releases/tag/v0.0.7).

## Changes

- Restless-source rules (`SSH_SLOW_BEHAVIOR=on`, default, also after upgrades).
  A source that keeps connecting to forwarded ports with no 2-hour pause, and never
  completes a login, is banned when:
  - its last 2 hours touched 4 forwarded ports, or
  - its last 6 hours touched 3, or
  - its last 12 hours held 50 connections.

  Port rules ban all ports in both jail modes. The connection rule follows
  `JAIL_PER_PORT`. Bans climb the strike ladder and are logged as `restless-ports`
  or `restless-connections`. The rules act only where `SSH_SLOW_PROTECTION=on`.
  Pause and rules are set with `SSH_BEHAVIOR_PAUSE` and
  `SSH_BEHAVIOR_RULES="4p:2h 3p:6h 50c:12h"`.
- Known users (`LEARN_USERS=on`, also after upgrades). A forwarded connection open
  for 3 minutes, or delivering more than 32 KiB, proved a login. That source is
  then not counted on that port for 90 days, renewed by later sessions. Reconnecting
  on an unstable network costs nothing. `forget IP` removes a known user.
- A resent SYN (same source port and sequence number) counts once in the
  per-minute, slow and behavior limits; the shared per-port limit still counts
  every packet.
- Whitelisted sources and administrators learned from logins to this server are
  never counted, as before.
- `status` shows known users and all-port bans. `report` lists the streaks closest
  to a rule.

## Upgrading

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.8.deb
```

An active guard is refreshed automatically, as before; no reload is needed. The
new settings are added to `settings.conf` with a private backup, and the refreshed
guard applies them at once. Where `SSH_SLOW_PROTECTION=on`, the behavior rules then
start judging sources.

Before upgrading, whitelist monitoring probes, backups, CI and git automation that
connect around the clock with short, quiet sessions. To turn the rules off, set
`SSH_SLOW_BEHAVIOR=off`, then run `sudo frp-ssh-guard check && sudo frp-ssh-guard reload`.
`status` shows pending edits until the next check and reload. See the
[migration notes](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.8/docs/MIGRATING.md).

## Limits

- Session learning is sampled about once a minute, so shorter sessions are not seen.
- Learning by session age assumes the backend `LoginGraceTime` stays below
  `LEARN_SESSION_AGE`.
- Automation that connects around the clock with short, quiet sessions matches the
  rules and must be whitelisted.
- Sources behind one shared NAT share one status.

Unit tests and the kernel syntax test in CI cover this pre-release. The disposable
VM test with real FRP traffic (`tests/vm-behavior.py`) has not been run yet.
Validation status is recorded in
[VALIDATION.md](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.8/docs/VALIDATION.md).

<sub>An X-project by [XyberMind](http://www.xyber-mind.com/).</sub>
