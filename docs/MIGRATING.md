# Migration to 0.0.5


## Upgrade while preserving settings and live jails

```bash
sudo apt install ./frp-ssh-guard_0.0.5.deb
frp-ssh-guard --version
sudo frp-ssh-guard status
```

The release filename is `frp-ssh-guard_0.0.5.deb`. Its internal Debian revision
lets APT recognize it as newer than earlier builds; no `--reinstall` is needed
for an upgrade. Use `frp-ssh-guard --version` to see the application version.

Do not purge, restart or reload just to upgrade. The installer replaces programs
and fills in missing commented options; it preserves custom values, manual lists,
accepted policy, history, live bans with their remaining timeouts, and service
and timer configuration. Store custom timer units/drop-ins in
`/etc/systemd/system/`, not package-owned `/usr/lib` files. Fail2ban's configuration
is not changed. New settings default to `off` even when absent in an old file.
New examples are available in `/usr/share/frp-ssh-guard/settings.conf.default`.

Starting with v0.0.5, neither installation nor removal hooks reload systemd during
an upgrade. The **already-installed v0.0.4** removal hook still calls
`daemon-reload` during the first upgrade. It retains configured intervals and
live bans, but systemd may recalculate a custom `OnActiveSec` next deadline.
Subsequent upgrades from v0.0.5 avoid that behavior. Other packages or an explicit
administrator `daemon-reload` can independently recalculate such deadlines.

Already-running Python monitors keep their code until explicit policy reload or
restart. New commands and timer invocations use updated programs immediately.
To enable a new feature, edit settings, then `check` and `reload`. An explicit
policy reload rebuilds the table: temporary automatic bans and rate meters reset;
persisted strike bans restore. Package upgrades themselves do not rebuild it.

## Adding new settings to an existing file

Package `0.0.5-2` merges missing commented defaults during installation. Missing
`PROTECT_SERVER_SSH=off` and `JAIL_PER_PORT=off` are inserted directly below the
port selection/exclusion lines; other missing defaults go at the end. Existing
assignments, comments, owner and permissions are retained. Explicit `on` values,
empty values and duplicate custom assignments are not overwritten. A missing
`PROTECTED_PORTS` remains absent to preserve legacy port-file behavior.

Before the atomic update, an exact private backup is saved beside the selected
file as `settings.conf.before-upgrade-*` (or `guard.conf.before-upgrade-*` for an
unmigrated legacy config), mode 0600. Home updates run as the registered owner,
even if another administrator installs the package. Reinstalling without missing
keys leaves the file and backups unchanged. Invalid/unavailable files or unsafe
links are left alone with a notice; after correcting access or format, retry
using `sudo apt install --reinstall ./frp-ssh-guard_0.0.5.deb`.

Accepted policy and its digest are not rewritten. Existing pending edits remain
unapplied, so status may show pending edits after defaults are added. No services,
jails or timers are restarted. Source upgrades use the same merge procedure.

## Automatic home configuration

Installing the `.deb` now creates `~/.frp-ssh-guard/` automatically and copies
existing settings, `whitelist.conf` and `blocklist.conf` there. A sudo installation
uses the invoking user; a direct root/unattended installation uses root's home.
Once selected, the location remains unchanged on subsequent upgrades, regardless
of who installs them. To select a different owner before the first migration:

```bash
sudo env FRP_GUARD_CONFIG_USER=USERNAME apt install ./frp-ssh-guard_0.0.5.deb
```

Legacy port-list input is converted when needed. Files have mode 0600 in a 0700
directory. Different existing home files are never overwritten. If the home is
unavailable, files conflict, or migration cannot complete, the installer reports
that it retained the existing configuration; the package remains usable. After
resolving the issue, retry with `sudo frp-ssh-guard config-home USERNAME`.
Use `frp-ssh-guard --help` to see the actual settings location.

Settings are literal assignments, not executable shell programs. Rewrite custom
shell expressions as explicit values before migrating. The selected administrator
owns the editable files and can change manual allow/block policy immediately;
only delegate this access to a trusted account. Configuration changes still need
explicit privileged `check`/`reload` before becoming accepted policy.

The original system files remain as snapshots/fallback. Accepted policy and
validated manual-list caches stay root-owned in system storage, so an unavailable
home directory or logged-out user does not prevent boot protection. An active
manual-list watcher is retargeted with transient systemd units; persistent path
configuration handles later boots. No systemd manager reload or firewall
reapplication is needed, so migration itself retains jails and timer deadlines.
Purge retains home files. Source installation and upgrades follow the same rules.

## New optional behavior

```bash
PROTECT_SERVER_SSH=off
JAIL_PER_PORT=off
```

`PROTECT_SERVER_SSH=on` adds this server's port 22 and local sshd failure detection.
`JAIL_PER_PORT=off` shares an IP ban across all protected ports; `on` isolates
automatic and strike bans by port. Manual scope remains explicit in either mode.
Old unscoped history cannot be attributed to a port and is ignored by per-port
escalation; existing unscoped persisted strike bans initially expand to selected
ports when restored. Changing scope is an explicit policy reload.

Manual blocks are permanent by default. Use `block IP --all` or
`block IP --ports PORTS --for 6h`; timed blocks save an absolute UTC expiry that
is not extended by reload or reboot. `unblock IP` removes all its manual scopes.

## Corrected public version numbering

The public release and download filename use **v0.0.5**. Earlier
pre-release packages used numerically higher Debian versions.
To replace one of those installations while preserving settings and state:

```bash
sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.5.deb
sudo frp-ssh-guard status
```

This is a release-number correction. Keep your existing settings; do not purge
or remove the package first. Fresh installations use the normal install command.
Earlier pre-release builds are superseded by the current version.

## Existing Debian installations (1.0.x)

1. Privately back up `/etc/frp-ssh-guard`, `/var/lib/frp-ssh-guard`, and any existing
   home configuration before changing versions.
2. Install the corrected version without purging or restarting the guard:

   ```bash
   sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.5.deb
   frp-ssh-guard --help
   sudo frp-ssh-guard status
   ```

3. Check the `Settings:` path printed by help. Successful automatic migration
   has already copied values from `guard.conf`, converted `ports.conf` to
   `PROTECTED_PORTS`, and added missing options in the chosen home. The old
   system files remain snapshots; editing them will not change the home policy.
4. If migration reports a conflict or unsupported shell syntax, keep both copies
   privately and reconcile the values as literal assignments. Retry
   `sudo frp-ssh-guard config-home USERNAME` after correcting the problem.
   Continue using the file indicated by help until that migration succeeds.
5. If manual port conversion is needed, preserve ranges and rate/burst overrides:

   ```text
   # Old ports.conf
   22001
   23000-23010:60:40
   ```

   becomes this assignment in the selected editable settings file:

   ```ini
   PROTECTED_PORTS="22001,23000-23010:60:40"
   ```

6. Retain exclusions, rates, durations and learning preferences. Keep the active
   `GUARD_TABLE` unchanged. Do not carry over source-install path settings.
   Apply reviewed policy changes explicitly:

   ```bash
   sudo frp-ssh-guard check && sudo frp-ssh-guard reload
   sudo frp-ssh-guard status
   ```

   Use `enable` for an inactive guard. An upgrade alone does not require this
   reload; it is only for adopting configuration edits.

`settings.conf` takes precedence as a whole over `guard.conf`. An absent
`PROTECTED_PORTS` still permits the legacy port file; an explicitly empty value
does not. Keep backups until access and reboot restoration are verified.

`install [FILE]`, `trial [FILE]`, and `check [FILE]` still accept a legacy port-list
override. An activation with an override snapshots those ports without rewriting
the editable files; `status` marks the inputs pending. A later `reload` returns to
the editable settings. Move persistent port choices into `settings.conf`.

## Source installation to Debian package

The package refuses installation when local source-managed service units exist.
Do not install source and Debian versions side by side.

1. Privately back up the source installation's settings, lists, and logs.
2. Run `sudo ./uninstall.sh --prefix /opt/frp-ssh-guard` with the actual old
   prefix. Do not use `--purge`. This stops protection during migration.
3. Install the `.deb` on the public FRP host.
4. Run `frp-ssh-guard --help` and restore reviewed settings into the **selected**
   settings file, not an old snapshot. Convert the old port list if necessary;
   omit source-specific paths. Reconcile any home-file conflict before retrying
   `config-home USERNAME` so existing custom data is not overwritten.
5. Restore manual allow/block files into the `Manual lists:` location shown by
   help, preserving that owner's access and private permissions. Restore learned
   and persisted strike state to `/var/lib/frp-ssh-guard/lists/`, and logs to
   `/var/log/frp-ssh-guard/`, with root ownership. `hardban.conf` is the canonical
   persisted strike list; merge older `hardguard.conf` entries privately if needed.
6. With `frps` and forwarded listeners running, run `check`, `enable`, and `status`.
7. Verify access and reboot restoration before retiring the backup.

Source installs remain supported under `/opt/frp-ssh-guard` or a custom prefix.
Repeat source installation preserves existing settings, including legacy files;
installer policy flags apply only on fresh installations. Upgrades do not rewrite
units, reapply rules or restart timers.

Private transfer backups are not imported automatically or included in releases.

## Automatic list migration

Installing the new `.deb` replaces package-owned program files and imports active
jails and legacy learned/strike entries into the home `whitelist.conf` and
`blocklist.conf`. Existing scopes and remaining kernel timeouts become section
headers and absolute UTC expiry timestamps. Existing manual entries and comments
are retained. The hooks do not restart the firewall or timers, and they do not
adopt pending settings. Legacy entries without a live kernel timeout or saved
expiry receive the accepted configured duration once during migration.

No manual uninstall or IP copying is required. Root caches, strike history and
legacy compatibility inputs are retained internally; do not delete these while
old monitors may still be running. Newly invoked commands/timers use the upgraded
programs; an explicit `check`/`reload` starts updated long-running SSH monitors.
If a home is unavailable or a list is malformed, installation reports a deferred
migration and preserves original data. Fix access/format and run `apply` to retry.
