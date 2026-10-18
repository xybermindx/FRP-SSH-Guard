# Contributing

Use your own clone and a feature branch. Keep operational configurations, real
IP addresses, auth logs, and transfer backups out of commits and test fixtures.
Use documentation addresses such as `198.51.100.0/24` and `2001:db8::/32`.

## Code map

- `bin/frp-ssh-guard-persistent.sh`: CLI, validation, nftables rules, source-install lifecycle.
- `bin/frp-ssh-guard-config.sh`: shared accepted/editable policy loading and runtime lock.
- `bin/frp-ssh-guard-validate.py`: policy validation before applying rules.
- `bin/frp-ssh-guard-learn.sh`: optional local sshd journal learning.
- `bin/frp-ssh-guard-log.sh`: periodic ban sampling and table recovery.
- `bin/frp-ssh-guard-strike.py`: history-based escalation and forgiveness.
- `etc/*.example`: public defaults and empty deployment templates.
- `packaging/`: Debian metadata, maintainer scripts, launcher, systemd units.
- `scripts/build.py`: deterministic package/source archive builder.
- `tests/`: rule-generation regressions, optional kernel checks, package lifecycle checks.

Run `make test` and `make release`. Tests use Python's standard library. Normal
tests exercise real Bash functions without invoking privileged CLI dispatch;
they do not install packages or touch the host firewall. They check port errors,
exclusions, list generation, configured defaults, package paths, and release inputs.

The optional kernel test creates an isolated network namespace:

```bash
sudo env FRP_GUARD_LIVE_TESTS=1 python3 -m unittest discover -s tests -v
```

This requires root, `unshare`, nftables, and network namespace support. It validates
and applies initial/replacement rules inside that namespace. It does not prove
end-to-end FRP traffic behavior or systemd boot behavior.

Package lifecycle tests must run in disposable containers only:

```bash
make release
docker run --rm -e FRP_GUARD_DISPOSABLE=1 -v "$PWD:/src:ro" debian:12 bash /src/tests/package-smoke.sh
docker run --rm -e FRP_GUARD_DISPOSABLE=1 -v "$PWD:/src:ro" ubuntu:24.04 bash /src/tests/package-smoke.sh
```

GitHub Actions runs these checks. For runtime changes, also test on a disposable
systemd VM with an actual `frps` listener and retain console access. Include the
commands, OS/kernel version, and observed results in your pull request. A passing
syntax or mocked rule test is not a live-firewall test.

Keep README.md and README.zh-CN.md equivalent when changing user-facing behavior.
Keep each language in its own README, with reciprocal language links at the top.
Record real runtime checks in docs/VALIDATION.md; distinguish fake-command tests
from actual kernel, systemd, and FRP tests.
