# v0.0.6

Add observation-first slow SSH detection, private local alerts and timestamped reports.
Existing fast protection, jail scope and ban lifetimes stay in place.

Project credit: [XyberMind team](http://www.xyber-mind.com/).

[English guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.6/README.md) ·
[Chinese guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.6/README.zh-CN.md)

## Changes

- Independent 20-failure / 24-hour slow detector, default `SSH_SLOW_MODE=observe`.
  Observation adds no bans or strikes; `enforce` is an explicit opt-in.
- Shared journal deduplication and classification of successful logins before learning.
  Learning remains opt-in and supports password, public key and PAM successes.
- Newest-first `~/.frp-ssh-guard/alerts.log`, default 10MiB cap. Oldest complete
  records are discarded without archives. Offline homes use a bounded private spool.
- Suspected IPv4 /24 and IPv6 /64 clusters are reported, never automatically blocked.
- `doctor` checks monitoring and access. `report 24h` filters event timestamps and
  reports failures, thresholds, new bans and sampled packet drops separately.
- Authentication bans are recorded directly and reconciled with sampled kernel bans
  so one ban contributes one strike. Earlier strike history remains available.

## Install or upgrade

Download `frp-ssh-guard_0.0.6.deb` and `SHA256SUMS` from Assets:

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.6.deb
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard doctor
sudo frp-ssh-guard report 24h
```

Use `enable` instead of `reload` for first activation. Installation merges missing
settings and preserves custom values, accepted policy, active jails and timer
deadlines. It does not restart services; explicit reload starts updated monitors.
Native SSH protection and whitelist learning are not enabled automatically.

## Limits

New long-window coverage begins at activation; recent legacy short-window state
is imported. Packet sampling intervals may straddle report boundaries, and sudden
power loss can lose unsampled drops. Packet counts are not connection counts or
proof that no unauthorized login occurred. Observation tables are bounded and
reports disclose capacity loss. Subnet and new-source login alerts need review.

Learning trusts a source IP, not an identity across changing addresses. A successful
compromised account can teach trust. The guard does not change sshd authentication
configuration; Fail2ban and other firewalls remain independent.

See the [validation record](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.6/docs/VALIDATION.md)
for platforms and tests. Full Ubuntu FRP/systemd runtime and ARM/32-bit runtime
have not been verified. The v0.0.5 tag and package remain unchanged.
