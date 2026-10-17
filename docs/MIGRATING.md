# Migration to 0.0.4

## Corrected public version numbering

The public release uses **v0.0.4**. The initially published v1.1.0 package and
older 1.0.x development packages have numerically higher Debian versions.
To replace one of those installations while preserving settings and state:

```bash
sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.4_all.deb
# If protection was already active:
sudo systemctl restart frp-ssh-guard.service
sudo frp-ssh-guard status
```

This is a release-number correction. Keep your existing settings; do not purge
or remove the package first. Fresh installations use the normal install command.
The earlier v1.1.0 release is superseded by v0.0.4.

## Existing Debian installations (1.0.x)

Upgrades preserve `guard.conf`, `ports.conf`, lists, logs, and enablement. The new
package creates `settings.conf` only when neither configuration file exists.
Until migrated, the legacy files remain the editable inputs. The first successful
activation/reload—or legacy service start after upgrade—captures their policy in
`/var/lib/frp-ssh-guard/applied.conf`. Thereafter background activity and reboot
restore the accepted policy, not later edits.

1. Back up `/etc/frp-ssh-guard` and `/var/lib/frp-ssh-guard` privately.
2. Install the new `.deb`. If already active, restart the main service to load
   updated programs and units:

   ```bash
   sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.4_all.deb
   sudo systemctl restart frp-ssh-guard.service
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
explicit installer flags update their corresponding fields.

Private transfer backups are not imported automatically or included in releases.
