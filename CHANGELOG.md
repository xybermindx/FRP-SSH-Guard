# Changelog

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
