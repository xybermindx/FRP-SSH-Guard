# Changelog

## 0.0.5 (local candidate; not published)

- Debian revision `0.0.5-2`: merge missing commented settings during package/source
  installation, keeping existing values, comments, permissions and registered
  owner. Save an exact private backup before changes; complete configs are untouched.
- Place missing local SSH and per-port jail switches just below the port selection
  and exclusions. Retain explicit switch values and legacy port-file behavior.
- Keep accepted policy, pending edits, live bans and timer deadlines unchanged
  while updating editable settings; defer unavailable/invalid files with a notice.
- Clarify the settings path in CLI help and group template controls near ports.

- Package as Debian version `0.0.5-1` so ordinary `sudo apt install ./FILE.deb`
  upgrades earlier local `0.0.5` builds without `--reinstall`. Track packaging
  revisions separately, add `make bump-revision`, and validate revisioned release
  tags and package metadata while keeping application version `0.0.5`.

- Add opt-in protection for this server's SSH port 22, including local sshd
  authentication failures and invalid-user attempts; never collect passwords.
- Add `PROTECT_SERVER_SSH=off` and `JAIL_PER_PORT=off`. Default jails cover all
  selected ports; opt-in per-port jails also separate ban history and escalation.
- Automatically create/migrate private editable settings and manual lists into
  the installing sudo user's `~/.frp-ssh-guard/` (root for direct root installs).
  Keep an existing owner on later upgrades; support `FRP_GUARD_CONFIG_USER` for
  first selection and `config-home [USER]` for retry. Retain old files on conflicts.
- Retarget an active manual-list watcher without resetting systemd timer
  deadlines; keep literal data parsing and root-owned runtime snapshots for boot.
- Correct displayed remaining ban times to use nftables JSON seconds.
- Add manual all-port or selected-port blocks, permanent by default, with optional
  `--for` duration saved as an absolute expiry that survives reload and reboot.
- Update manual lists without clearing automatic jails or their remaining timeouts.
- Preserve custom settings, live jails and timer deadlines on Debian/source
  upgrades; do not restart services, rebuild the firewall or reload systemd units.
- Add `version`, `--version`, and `-V`; reject overwriting an unrelated command.
- Extend privacy checks, regression coverage and disposable-VM acceptance testing.

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
