# Migration to 0.0.7

Install with `sudo apt install ./frp-ssh-guard_0.0.7.deb`; it upgrades v0.0.5 and
every v0.0.6 build. As in v0.0.6, an active guard is refreshed automatically during
installation: accepted policy is recompiled and the SSH monitors restart. Saved ban
scopes and expiry, boot enablement and timer deadlines are kept; rate meters reset.

## Ban durations and repeat offenders

New installations ban for 12 hours on a first offense, then 3 days, 7 days,
30 days and 90 days. Upgrades never change values already in your settings file,
so an existing server keeps its durations. To adopt the new ones, set:

```ini
BAN_TIMEOUT=12h
STRIKE_LADDER="2:3d 3:7d 4:30d 5:90d"
STRIKE_MAX=90d
```

then run `sudo frp-ssh-guard check && sudo frp-ssh-guard reload`. Current bans
keep their end time. Repeat-offender bans are recalculated from the latest offense
with the new ladder at the next strike-timer run, so some may become longer.

The meaning of `STRIKE_WINDOW` changes for every installation: offenses are now
remembered for that long after a ban **ends**, and a source at the top step stays
there while it keeps re-offending. On the first strike-timer run after upgrading,
each source's step is rebuilt from the ban history still available, so some
current repeat-offender bans can become longer.

## Administrator learning

If you installed v0.0.7 before, download it again; a normal
`sudo apt install ./frp-ssh-guard_0.0.7.deb` upgrades the earlier download. It adds
`LEARN_ADMINS=on` directly above `LOGIN_USERS` (also on upgrade) and refreshes the
shipped `LOGIN_USERS` comment when unchanged. Administrators (root, the settings
owner, `sudo`/`admin`/`wheel` members) are then whitelisted after a successful login
to this server. Set `LEARN_ADMINS=off`, then check and reload, to keep learning
limited to `LOGIN_USERS`. Failed-login counting changes as described in the
changelog; existing counts are kept and age out normally.

## One slow brute-force switch

`SSH_SLOW_MODE` (`off`, `observe`, `enforce`) is replaced by `SSH_SLOW_PROTECTION`
(`on`/`off`), placed directly below `JAIL_PER_PORT`. There is no observe-only mode:
`on` detects, logs and bans; `off` does none of these. Upgrades never start bans you
did not choose:

| Before | After the upgrade |
| --- | --- |
| `SSH_SLOW_MODE=enforce` | `SSH_SLOW_PROTECTION=on` |
| `observe`, `off`, or no slow setting | `SSH_SLOW_PROTECTION=off` |

The same conversion applies to the accepted policy, so the refreshed guard behaves
as the converted file says. `on` now also covers forwarded ports. With shared jails
it bans a source after more than 300 new connections across all forwarded ports in
24 hours (on all ports). With per-port jails the limit is 100 on one port (that port
only). Port 22 keeps 20 failed logins in 24 hours. Whitelisted sources, under any
port, are never counted.

The installer keeps your old line as a comment and replaces only the comment text
it shipped earlier; your own comments stay. It saves an exact private copy first
(`settings.conf.before-upgrade-*`) and prints what changed. The new thresholds
`SSH_SLOW_TOTAL_CONNECTIONS` and `SSH_SLOW_PORT_CONNECTIONS` are added beside
`SSH_SLOW_FAILURES`. `check` reports any leftover `SSH_SLOW_MODE` line and how it
was read; an invalid old value is rejected with a message.

To enable slow protection on an upgraded server, first whitelist administrators
who use many forwarded machines, then set `SSH_SLOW_PROTECTION=on` and run
`sudo frp-ssh-guard check && sudo frp-ssh-guard reload`.

## Activity log

`~/.frp-ssh-guard/alerts.log` becomes `frp-ssh-guard.log`. Its lines are merged
into the new file once, and the old file is removed. The log now records every
ban with its reason, plus manual bans, strike escalations, releases and accepted
settings. Bans from before the upgrade are not added, because no reason was
recorded for them. `ALERT_LOG_MAX_SIZE` is renamed `LOG_MAX_SIZE` and keeps its
value; the old name is still read if it remains.

## Instructions in your files

The reload instructions at the top of `settings.conf`, and the instruction
headers of `whitelist.conf` and `blocklist.conf`, are refreshed only while they
are exactly the text an earlier release shipped. List entries are never changed
by this. Because the settings file changes, `status` shows `Pending edits: yes`.
The converted file means the same as the accepted policy, so the next
`check && reload` changes nothing unless you had other pending edits.

# Migration to 0.0.6

Install `frp-ssh-guard_0.0.6.deb` with `sudo apt install ./frp-ssh-guard_0.0.6.deb`.
It upgrades v0.0.5 and earlier v0.0.6 downloads.
For an active guard, installation automatically recompiles its accepted policy
and restarts the long-running SSH monitors. No manual reload is needed.
Missing commented settings are merged without changing custom values. Pending
settings edits remain unapplied, including invalid edits. Newly supported runtime
defaults and the observation activation marker are added to the accepted snapshot;
its existing policy values and editable-input digest are retained.

Before the atomic firewall replacement, live bans and learned entries are saved
with their port scope and absolute expiry. They are restored with remaining time;
rate meters reset. The main service, its boot enablement, timers and trial deadline
are not restarted or re-enabled. No systemd manager reload is performed.
Validation/application failures retain the previous policy and rules and fail
package configuration. A monitor failure is reported even if new rules are active.

Fresh or inactive installations still require port selection and first activation.
An active trial is refreshed without making it persistent. An administrator's
`policy-rc.d` denial defers refresh with a notice. Installations without a running
systemd manager do not attempt service activation. Source installs retain their
existing explicit activation workflow.

Fresh settings default to `SSH_SLOW_MODE=enforce` when local SSH protection is
enabled. Existing modes remain unchanged; legacy files missing the key retain
`observe`, including their accepted runtime snapshots. To change that policy,
set `enforce` and check/reload once. Existing fast thresholds, SSH enablement,
jail scope, learning preferences and ban/strike lifetimes are unchanged.
Recent short-window JSON attempts and their journal cursor migrate on activation;
long-window coverage starts then. Old ban logs continue to supply earlier strikes.
New automatic bans are counted once from the private SQLite store. Existing jails
are restored without counting them as new attacks. The same log timer now samples
packet deltas and kernel bans; no extra timer is created.

Alerts use `~/.frp-ssh-guard/alerts.log`, newest first, with a configurable 10MiB cap
and no archives. Unavailable homes use a bounded private system spool. New runtime
state under `/var/lib/frp-ssh-guard/observations/` is private and must not be uploaded.
Use `doctor`, `status` and `report 24h` to review operation and coverage limits.

## Earlier migration details (v0.0.5)

The following sections describe the older v0.0.5 behavior. For automatic package
refresh in v0.0.6 revision 2, use the instructions above.


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

Since v0.0.5, installation merges missing commented defaults. Missing
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
