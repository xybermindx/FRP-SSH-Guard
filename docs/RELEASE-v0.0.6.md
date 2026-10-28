# v0.0.6

Add automatic upgrade activation, slow SSH detection with enforcement for fresh installations, private local alerts and timestamped reports.
Existing fast protection, jail scope and ban lifetimes stay in place.

[English guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.6/README.md) ·
[Chinese guide](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.6/README.zh-CN.md)

## Changes

- Switching jail modes affects new bans only. Existing shared and per-port bans
  retain their original scopes and expiry in both directions. Strike history
  keeps the recorded scope so later timer runs cannot broaden old per-port bans
  or discard shared history. Explicit manual scopes and whitelist exceptions
  are unchanged. Settings changes still require check/reload.
- An active guard is refreshed automatically during
  `apt install`, including the running SSH monitors. No manual reload is needed.
  Accepted policy choices, pending edits, saved ban scope/expiry, boot enablement
  and timer schedules are retained. Firewall rate meters reset.
- Fresh settings default to `SSH_SLOW_MODE=enforce`: 20 failures / 24 hours
  trigger a ban when local SSH protection is enabled. Existing `off`, `observe`
  or `enforce` choices are retained; older missing settings preserve `observe`.
  Thresholds, jail scope, ban durations and learning preferences are unchanged.
- Shared journal deduplication and classification of successful logins before learning.
  Learning remains opt-in and supports password, public key and PAM successes.
- Newest-first `~/.frp-ssh-guard/alerts.log`, default 10MiB cap. Oldest complete
  records are discarded without archives. Offline homes use a bounded private spool.
- Suspected IPv4 /24 and IPv6 /64 clusters are reported, never automatically blocked.
- `doctor` checks monitoring and access. `report 24h` filters event timestamps and
  reports failures, thresholds, new bans and sampled packet drops separately.
- Authentication bans are recorded directly and reconciled with sampled kernel bans
  so one ban contributes one strike. Earlier strike history remains available.

## Validation

Local regression tests cover fresh enforcement, observation mode, preserved explicit
choices, legacy missing settings and accepted snapshots. Disposable VM checks and
CI results are recorded in [VALIDATION.md](https://github.com/xybermindx/FRP-SSH-Guard/blob/v0.0.6/docs/VALIDATION.md).

## Install or upgrade

Download `frp-ssh-guard_0.0.6.deb` and `SHA256SUMS` from Assets:

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.6.deb
```

For an already active installation, the updated guard takes effect automatically.
The download filename is unchanged; APT upgrades earlier v0.0.6 downloads automatically.
This maintainer-requested correction replaces the earlier v0.0.6 package and
checksum; download both files again. Older v0.0.4 and v0.0.5 releases are unchanged.

Fresh or disabled installations still require port selection and `enable`.
Native SSH protection and whitelist learning remain opt-in. An existing
observation-only installation stays observation-only after upgrading. To change
that policy, set `SSH_SLOW_MODE=enforce` and run check/reload once; package
installation itself requires no manual reload. Pending settings edits are not
applied by the upgrade. An active trial remains
temporary. Administrator service policy can defer refresh with a notice.
Refresh failures are reported to APT; failed firewall validation/application
retains previous protection. `status`, `doctor` and `report 24h` are optional checks.

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

<sub>An X-project by [XyberMind](http://www.xyber-mind.com/).</sub>
