# Changelog

## 0.0.6

- Package revision 3 defaults fresh settings to slow SSH enforcement (20 failures / 24h)
  when optional local SSH protection is enabled. Existing choices are preserved;
  older settings without a slow mode keep observation behavior. Jail scope, ban
  durations and opt-in whitelist learning remain unchanged.
- Shared private SQLite journal deduplication and classification before whitelist learning.
- Bounded newest-first local alerts, owner-safe writes, offline-home spool, and report-only subnet clusters.
- Timestamped reports, persistent sampled packet deltas, and read-only doctor diagnostics.
- Direct authentication ban history avoids double-counting sampled bans and strikes.
- Package revision 2 automatically refreshes an active guard after installation:
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
