# Changelog

## 0.0.9

- Stop short bursts of password guessing. A new burst rule type, `Nb:T`, joins
  `SSH_BEHAVIOR_RULES`, and the default becomes `20b:30m 4p:2h 3p:6h 50c:12h`. A source
  with no proven login is banned during the burst at about 20 new connections within
  30 minutes, following `JAIL_PER_PORT`. The firewall enforces it directly. Whitelisted
  sources and known users are skipped. The logged reason is `burst-connections`.
- Upgrades add the rule once to a file or accepted policy that still has the exact
  previous default. Customized rules are not changed. Remove `20b:30m` to turn it off.
- `settings.conf` is much shorter: 15 everyday settings in five sections, and the
  others as one-line defaults under Advanced. Names and meanings are unchanged, and
  the new [settings reference](docs/SETTINGS.md) explains each one. Existing files
  are not rewritten.
- New `tidy-settings` command moves an existing file to the short layout. It keeps
  every changed value, saves a private backup and changes no firewall rule.
- The guides now open with why the tool is needed, what it does and does not stop,
  what it costs to run, and a short setup and tuning table.
- Support every common systemd Linux family. A noarch `.rpm` is added for Fedora,
  RHEL/Rocky/Alma 9+ and openSUSE (Tumbleweed, Leap 16), with the same files as the
  `.deb`. Arch Linux and other systemd distributions use `install.sh`.
- RPM upgrades and reinstalls refresh an active guard automatically and never stop
  it. An erase stops protection and keeps settings and state; the migration notes
  give the manual purge.
- Install, upgrade and removal steps are shared by both formats in `lifecycle.sh`.
  The Debian maintainer scripts call it, with unchanged behavior.
- `install.sh --preflight` checks a system without root, and `check`/`enable` refuse
  an unsupported system with the same checks: systemd, nftables 1.0.6+, Python 3.9+,
  Bash 4.4+, jq, `ss`, `flock`, `cmp`. Both print the install command for apt, dnf,
  zypper or pacman.
- `doctor` shows the distribution, architecture, kernel, nftables and Python
  versions, SELinux mode, and whether firewalld or `nftables.service` is active.
- Architectures: the packages run wherever a supported distribution ships the
  dependencies. CI tests amd64 and arm64 on real kernels in every listed
  distribution. Debian armhf, armel, mips64el and riscv64 package lifecycles are
  tested under emulation.
- The release scan now reads `.rpm` packages too, without needing rpm tools.

## 0.0.8

- Ban slow bots that stay under every limit by connecting a few dozen times a day
  per port, often rotating across all forwarded ports, without ever completing a
  login. With `SSH_SLOW_BEHAVIOR=on` (default, also on upgrade, where the automatic
  refresh applies it), each untrusted, unknown source has a streak that a pause of
  `SSH_BEHAVIOR_PAUSE` (2h) starts over. It is banned when its streak lasted T and the last T held
  `SSH_BEHAVIOR_RULES="4p:2h 3p:6h 50c:12h"`: 4 ports in 2 hours, 3 ports in 6
  hours, or 50 connections in 12 hours. Port rules ban all ports in both jail
  modes. The connection rule follows `JAIL_PER_PORT`. Logged reasons are
  `restless-ports` and `restless-connections`, and bans climb the strike ladder.
- Add known users (`LEARN_USERS=on`, also on upgrade). A forwarded connection still
  open after `LEARN_SESSION_AGE` (3m), or that delivered more than
  `LEARN_SESSION_BYTES` (32KiB), proved a login. Its source/port pair is then no
  longer counted by slow protection or the behavior rules for `LEARN_TIMEOUT`, so
  users on unstable networks can reconnect freely. `forget IP` removes it, and
  `known-user` log lines record new ones.
- A resent SYN (same source port and sequence number) now counts once in the
  per-minute, slow and behavior limits. Before, a lossy network counted each resend
  as a new connection. The shared per-port limit still counts every packet.
- In per-port mode, repeat offenses of all-port bans escalate at once in the
  address-keyed saved sets instead of after the next reload. `status` shows known
  users and all-port bans; `report` lists the streaks closest to a rule.

## 0.0.7

- Fix busy blocklists that repeated the same port header (for example `[22]`)
  many times, because new automatic bans were appended under a fresh header whenever
  the last section belonged to another port. Each port now has one section; new
  entries join it, and automatic bans follow the manual lines, sorted by address,
  so an address's `runtime` and `strike` lines sit together. Existing repeated
  headers are merged at the next update; comments and manual lines stay in place.
  The header explains `runtime`, `strike` and which `until=` applies.

- New default ban durations: first offense 12 hours (`BAN_TIMEOUT=12h`), then
  3 days, 7 days, 30 days and 90 days for the 2nd to 5th offense within
  `STRIKE_WINDOW` (`STRIKE_LADDER="2:3d 3:7d 4:30d 5:90d"`, `STRIKE_MAX=90d`).
  Blocklist tiers 1–5 follow the same values. Existing settings files keep their
  own values; the list headers shipped in v0.0.7 are refreshed with the new text.
- Repeat offenders keep their ladder step. An automatic ban within `STRIKE_WINDOW`
  after the previous ban *ended* moves one step up, and a source released from the
  top step that offends again gets the top duration again (90 days) instead of
  starting over at 12 hours. A clean `STRIKE_WINDOW` after a ban starts over.
  Steps persist across pruned history; `unban`/`release` forgives them. Shipped
  comments for the ban and strike settings are refreshed on upgrade.
- Stop banning administrators on unstable networks. Keys or
  typos rejected inside a login that then succeeds no longer count, and rejected
  public keys in a dropped connection count once per connection instead of once per
  key (sshd logs rejected offers from the third key on). Password failures and
  invalid users still count individually.
- Add `LEARN_ADMINS=on` (default, also on upgrade): a successful
  login to this server by root, the settings owner, or a member of the `sudo`,
  `admin` or `wheel` group whitelists that source for `LEARN_TIMEOUT`, without
  typing usernames. `LOGIN_USERS` still adds other accounts.
- Replace `SSH_SLOW_MODE` (off/observe/enforce) with one `SSH_SLOW_PROTECTION=on/off`
  switch, placed directly below `JAIL_PER_PORT` and on by default. `on` detects,
  logs and bans; there is no observe-only mode. Upgrades convert `enforce` to `on`
  and `observe`, `off` or a missing value to `off`, in both the settings file and the
  accepted policy, so no upgrade starts bans an operator did not choose.
- Extend slow protection to forwarded ports, where login results are invisible:
  more than 300 new connections per source across all forwarded ports in 24 hours
  with shared jails, or 100 on one port with per-port jails. Port 22 keeps 20 failed
  logins in 24 hours. Sources whitelisted under any port are never counted.
  `unban` also resets the slow counters.
- Rename `alerts.log` to `frp-ssh-guard.log` and record every ban with its reason,
  limit and end time, plus manual bans, strike escalations, releases and accepted
  settings. The old file is merged once. `ALERT_LOG_MAX_SIZE` becomes `LOG_MAX_SIZE`.
- Explain in `settings.conf` when and how changes take effect (check, reload or
  enable, status). Explain in `blocklist.conf` that an entry without a time is
  permanent, with examples for subnets, IPv6, tiers, `until=` and the matching
  commands. Refresh these instructions in existing files only when unchanged.
- Fix: a whitelist or blocklist holding a subnet plus an address inside it under the
  same ports made nftables reject the whole rule set ("File exists"), so enable,
  reload or apply failed. Covered entries are now kept out of nftables (they stay in
  the file and still match); partial overlaps are reported with both line numbers.
- Fixes: list errors now name the cause (for example `7d` instead of `tier=`/`until=`);
  the whitelist header no longer describes block-only tiers; `release` now removes
  its address from the legacy strike file; `unblock`/`unallow` help describes that
  they remove every line for the address; the examples guide no longer says a
  manual reload is needed after upgrading; monitors keep running when a list file
  being edited is invalid; the strike helper closes its database.

## 0.0.6

- Jail mode switches affect new bans only. Existing
  shared/per-port bans retain their original scopes and absolute expiry.
  Keep strike history keyed by the recorded scope, so later timer runs cannot
  broaden old per-port offenses or discard shared history after a mode switch.
  Manual block scopes and whitelist exceptions remain unchanged.
- Default fresh settings to slow SSH enforcement (20 failures / 24h)
  when optional local SSH protection is enabled. Existing choices are preserved;
  older settings without a slow mode keep observation behavior. Jail scope, ban
  durations and opt-in whitelist learning remain unchanged.
- Shared private SQLite journal deduplication and classification before whitelist learning.
- Bounded newest-first local alerts, owner-safe writes, offline-home spool, and report-only subnet clusters.
- Timestamped reports, persistent sampled packet deltas, and read-only doctor diagnostics.
- Direct authentication ban history avoids double-counting sampled bans and strikes.
- Automatically refresh an active guard after installation:
  atomically recompile accepted firewall policy and restart SSH monitors. No manual
  reload is needed. Preserve custom settings, pending edits, saved ban scope and
  absolute expiry, boot enablement and timer schedules. Rate meters reset.
- Fresh, disabled and service-policy-denied installations are not activated.
  Refresh failures are reported to APT; firewall validation/application failures
  retain the previous accepted policy and rules.
- Release titles use only the version number. English release notes link both language guides.

## 0.0.5

Released under tag `v0.0.5`; install `frp-ssh-guard_0.0.5.deb`.

- Merge manual and automatic whitelist/blocklist entries into commented home files
  with `[all]` and per-port sections, source labels and absolute expiry timestamps.
  Installation imports existing jails and legacy lists without resetting live bans.
- Fix local SSH learning for trusted sshd journal records, including PAM successes;
  refresh expiry on trusted login and honor whitelist scope in the auth detector.
- Keep the public download filename at the application version; retain an internal
  Debian revision so APT upgrades earlier builds automatically.
- Add optional server SSH port-22 protection using connection limits and local
  sshd failure/invalid-user outcomes. Passwords are never collected.
- Add `PROTECT_SERVER_SSH=off` and `JAIL_PER_PORT=off` beside port selection.
  Shared bans remain the default; per-port mode isolates automatic/authentication
  bans and strike history. Manual block scope is independent of this setting.
- Automatically create/migrate editable settings and manual lists into the
  installing sudo user's `~/.frp-ssh-guard/` (root for direct root installs).
  Retain the chosen owner and root-owned accepted policy/caches for boot.
- Add missing commented defaults during installation without overwriting custom
  values. Save an exact private backup first; complete configs remain unchanged.
- Preserve live jails, remaining ban lifetimes and timer deadlines on upgrades.
  Retarget list watching without reloading systemd. The installed v0.0.4 removal
  hook can still rebase a custom `OnActiveSec` deadline on its first upgrade.
- Support permanent or timed manual blocks for all selected ports or specific
  ports. Timed entries keep their absolute expiry across reload and reboot.
- Update manual lists without clearing automatic jails; correct ban-time display
  to use nftables JSON seconds.
- Add `version`, `--version`, and `-V`. Track Debian revisions separately so APT
  recognizes newer packages; use `make bump-revision` for a changed distribution.
- Update English/Chinese introductions, installation and migration instructions,
  native SSH activation steps, configuration examples and public release links.
- Validate source/history/artifacts for private deployment data and record actual
  Debian VM, FRP, local SSH, upgrade, reboot and package-lifecycle checks.

## 0.0.4

- Use v0.0.4 for the public release.
  Package metadata, filenames, source tags, and download links use 0.0.4.
- Publish only the Debian package and its checksum as release assets; use GitHub's
  automatic tag ZIP/tar.gz downloads for the complete source.

- Consolidate new deployment settings and protected ports in commented `settings.conf`.
- Add `enable`/`disable` commands while preserving existing aliases and trial controls.
- Require explicit configuration reload; persist accepted settings for background
  tasks, list updates, table recovery, and reboot restoration.
- Validate policy before application, restore accepted settings on nftables failure,
  serialize runtime updates, and refresh learning after successful policy changes.
- Preserve legacy settings on upgrade; provide migration and pending-edit reporting.
- Align persisted strike bans on `hardban.conf` and cap escalation at `STRIKE_MAX`.
- Add complete English/Simplified Chinese project homepages and deployment examples,
  attack-coverage limits, verification instructions, and full-source release guidance.
- Add unprivileged deployment regressions and extend package lifecycle checks.
- Live systemd/FRP and target-container validation remains pending in this preparation
  environment; see `docs/VALIDATION.md` before publishing a stable release.

## Development snapshot 1.0.1 (before public version numbering)

- Add architecture-independent Debian packaging with configuration preservation,
  explicit activation, systemd units, removal/purge handling, and log rotation.
- Add reproducible source archives, checksums, regression tests, and GitHub CI
  and release draft workflows.
- Keep deployment backups, private lists, and logs out of release artifacts.
- Separate connection-rate tracking from ban membership; preserve configured
  defaults for manual bans and support nftables 1.0.6 without `destroy table`.
- Stop helper timers when removing the guard so they cannot recreate its table.
- Preserve configuration and state during source reinstalls; pass custom prefixes
  to the guard and trial rollback.
- Make local SSH learning opt-in and read the systemd journal.
- Honor configured table names and Debian paths in the strike helper; count
  rotated history within the strike window.
- Recompile source-install rules on startup so saved table-deletion statements
  cannot prevent restoration after reboot.

## Development snapshot 1.0.0 (before public version numbering)

- Original source archive with nftables guard, SSH learning, ban history,
  strike escalation, and a source installer.
