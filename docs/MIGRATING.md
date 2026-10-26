# Migration to 0.0.5 (local candidate)


## Upgrade while preserving settings and live jails

```bash
sudo apt install ./frp-ssh-guard_0.0.5.deb
frp-ssh-guard --version
sudo frp-ssh-guard status
```

Do not purge, restart or reload just to upgrade. The installer replaces programs
and creates only missing files; it preserves custom settings, manual lists,
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

The public release remains **v0.0.4**; the local candidate uses **v0.0.5**. Earlier pre-release packages used
numerically higher Debian versions.
To replace one of those installations while preserving settings and state:

```bash
sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.5.deb
sudo frp-ssh-guard status
```

This is a release-number correction. Keep your existing settings; do not purge
or remove the package first. Fresh installations use the normal install command.
Earlier pre-release builds are superseded by the current version.

## Existing Debian installations (1.0.x)

Upgrades preserve `guard.conf`, `ports.conf`, lists, logs, and enablement. The new
package creates `settings.conf` only when neither configuration file exists.
Until migrated, the legacy files remain the editable inputs. The first successful
activation/reload—or legacy service start after upgrade—captures their policy in
`/var/lib/frp-ssh-guard/applied.conf`. Thereafter background activity and reboot
restore the accepted policy, not later edits.

1. Back up `/etc/frp-ssh-guard` and `/var/lib/frp-ssh-guard` privately.
2. Install the new `.deb` without restarting the guard:

   ```bash
   sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.5.deb
   sudo frp-ssh-guard status
   ```

3. Prepare the new file outside `/etc/frp-ssh-guard/settings.conf` first. Copy
   `/usr/share/doc/frp-ssh-guard/examples/settings.conf.example` to a private
   working file and merge policy values from the old `guard.conf`.
4. Convert uncommented `ports.conf` entries to `PROTECTED_PORTS`, preserving any
   `port:rate:burst` overrides. For example:

   ```text
   # Old ports.conf
   22001
   23000-23010:60:40
   ```

   becomes:

   ```bash
   PROTECTED_PORTS="22001,23000-23010:60:40"
   ```

5. Retain exclusions, rates, durations, and learning preferences. Do not copy
   `GUARD_DIR`; package paths are supplied by the launcher. Keep the active
   `GUARD_TABLE` value unchanged.
6. Install your reviewed file:

   ```bash
   sudo install -o root -g root -m 0640 ./settings.conf /etc/frp-ssh-guard/settings.conf
   sudo frp-ssh-guard check
   sudo frp-ssh-guard reload  # use enable if currently inactive
   sudo frp-ssh-guard status
   ```

`settings.conf` takes precedence as a whole; it is not merged with `guard.conf`.
If `PROTECTED_PORTS` is absent, the legacy port file remains a compatibility input;
an explicitly empty value does not fall back. Keep backups until access and
reboot restoration have been verified. Old files can remain for reference but
are not policy inputs once the new file defines `PROTECTED_PORTS`.

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
4. Merge settings into `/etc/frp-ssh-guard/settings.conf` as described above;
   convert the old port list if necessary. Do not copy source-specific paths.
5. Copy lists to `/var/lib/frp-ssh-guard/lists/` and logs to
   `/var/log/frp-ssh-guard/`. Keep root ownership and appropriate permissions.
   `hardban.conf` is the canonical persisted strike list. Old `hardguard.conf`
   deployments should merge those addresses into `hardban.conf` before activation.
6. With `frps` and forwarded listeners running, run `check`, `enable`, and `status`.
7. Verify access and reboot restoration before retiring the backup.

Source installs remain supported under `/opt/frp-ssh-guard` or a custom prefix.
Repeat source installation preserves existing settings, including legacy files;
installer policy flags apply only on fresh installations. Upgrades do not rewrite
units, reapply rules or restart timers.

Private transfer backups are not imported automatically or included in releases.
