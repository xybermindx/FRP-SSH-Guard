# Contributing

Use your own clone and a feature branch. Keep operational configurations, real
IP addresses, auth logs, and transfer backups out of commits and test fixtures.
Use documentation addresses such as `198.51.100.0/24` and `2001:db8::/32`.
Treat real project, organization, machine, and tunnel names, domains, IP addresses,
and deployment port mappings as private. Use invented names and port examples;
never copy them from a live deployment, even into tests, comments, screenshots,
commit messages, or a public privacy-check denylist. Inspect source archives and
packages as well as source files before distribution. Local `.private-artifacts/`
backups must never be committed, attached to releases, or shared.

Before committing or pushing, enable the local privacy hooks:

```bash
git config core.hooksPath scripts/hooks
git config frpGuard.privacyRules /absolute/path/outside-checkout/privacy-rules.json
```

Keep that JSON file private (mode 0600), outside this repository. Its `patterns`
array contains case-insensitive regular expressions for private identifiers and
deployment ports. Never commit the actual rules or use real identifiers in tests.
The hooks require these rules, inspect the staged snapshot before committing,
and inspect all reachable revisions before pushing. Reinstall the hooks in new
clones; hooks can be bypassed and are not a substitute for reviewing staged files.

Configure the same JSON as the repository Actions secret `FRP_GUARD_PRIVACY_RULES`.
Trusted CI and release checks fail if it is unavailable. Fork pull requests get
generic checks without access to private rules and cannot upload release artifacts;
maintainers must run private checks before merging them. Ordinary builds check the
export inputs and generated archives, rejecting non-documentation IPs and private
data paths. Set `FRP_GUARD_PRIVACY_RULES_FILE` for private checks outside a Git clone.
Failures report categories and redacted paths, never the matched content.

After a privacy history rewrite, discard old clones and clone again instead of
merging old branches, which would restore the removed history.

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
