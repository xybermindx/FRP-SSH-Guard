# Architecture

FRP-SSH-Guard owns one nftables `inet` table with an input-hook chain. It returns
for loopback, established/related traffic, non-TCP traffic, and unselected ports.
It then checks trusted sources, manual blocks, persisted strike bans, temporary
bans, per-source/per-port SYN rate meters, and shared per-port SYN limits.

Meters (`rate4`/`rate6`) and bans (`ban4`/`ban6`) are separate sets. Per-source
meters are keyed by address and destination port. With `JAIL_PER_PORT=off`, bans
are keyed by address and cover all guarded ports. With `on`, both automatic and
strike sets use address/port tuples; history and escalation retain that scope.
The shared per-port limit spans sources and both IP families. None of these rules
inspect SSH credentials. Other firewall tables keep their existing behavior.

## Editable and accepted configuration

`settings.conf` contains literal assignments parsed by an allowlisted data parser.
Editable input is never sourced as shell code; only generated root-owned
`applied.conf` is sourced. Installation automatically places settings and manual lists in
`~/.frp-ssh-guard/` (directory 0700, new files 0600). Home writes run as the selected
user. A root-owned registry records the location. Accepted settings and cached
validated manual lists remain in system storage for boot with home unavailable.
An existing home registration always wins over a new installer's identity. A first
migration uses `FRP_GUARD_CONFIG_USER`, then `SUDO_USER`, then root; it does not
guess from `HOME` or `USER`. Conflicting home files or migration failure retain
the existing policy and report the problem. `config-home [USER]` can retry.
Legacy `guard.conf`/`ports.conf` remain supported when the new file is absent.
`PROTECTED_PORTS` can also be absent in a legacy-compatible configuration; an
explicitly empty selection is an error unless `PROTECT_SERVER_SSH=on` adds port 22.

`check`, `enable`, and `reload` read edited inputs and validate policy, port
syntax, lists, active host FRP listeners, and the candidate nftables transaction.
A successful activation stores normalized policy and expanded port specifications
in `applied.conf`. Background helpers and administrative commands read that
snapshot. A digest records the editable inputs for pending-change reporting.
Explicit port-file overrides are marked pending until reflected in editable inputs.

Settings files are not watched. Manual lists are watched and applied against
accepted policy. Boot and missing-table recovery recompile accepted policy and
current lists without requiring FRP listeners, because the guard starts before
network listeners. Legacy first startup captures the old configuration once.
While the table exists, list updates flush/repopulate only manual and learned
sets; automatic bans, strikes, counters and rate meters stay in place. Manual
expiry is an absolute UTC timestamp converted to remaining timeout during apply.

## Local SSH authentication monitoring

`PROTECT_SERVER_SSH=off` disables local SSH monitoring by default. When on, port 22
joins the protected selection (including SYN limits), and an optional service
follows trusted root sshd journal records. It counts failed authentications and
distinct invalid-user connections within a window, deduplicates overlapping
invalid-user messages, and clears recent failure counts on successful login.
It discards usernames and never reads passwords. Loopback events are ignored,
including connections forwarded to a local SSH backend by frpc.

The journal cursor, bounded recent cursors and recent failure counters are kept
in root-owned `auth-state.json`, avoiding replay on restart. A threshold event
adds to the existing automatic ban set under the shared runtime lock: IP for
shared jails or IP/22 for per-port jails. Authentication monitoring does not
inspect outcomes on remote FRP backends. Explicit policy reload restarts it.

## Serialization and errors

CLI rule/list updates and helper updates share a runtime flock. Lifecycle commands
also use a separate lifecycle lock. They release the runtime lock before waiting
for systemd, avoiding deadlock with ExecStart/ExecStop. The journal learner reloads
accepted policy under the runtime lock for each login event, and explicit policy
reload restarts it to handle enabling/disabling learning.

Candidate policy is staged under the runtime lock; validation happens before
live changes. Accepted settings are atomically replaced and the nftables batch is
applied as one transaction. If nftables rejects the batch, the old accepted file
is restored and the kernel retains its prior table. The lock prevents background
jobs from consuming the interim snapshot. A crash/power failure between file and
kernel operations is not a cross-filesystem/kernel transaction: reboot restores
the persisted accepted policy. `active.nft` is a diagnostic snapshot, not the
boot source of truth.

Service/helper startup and boot-enablement errors report partial activation
explicitly. `disable` stops background producers before removing the guard table;
its configuration comes from the accepted snapshot even if pending edits are broken.
Changing table names while active is rejected.

## Paths and lifecycle

The Debian launcher supplies program, configuration, state, and log directories.
The same runtime supports source installations with `GUARD_DIR` set to their prefix.
Package units are dpkg-owned; activation does not generate overriding `/etc` units.
The source installer generates equivalent units for its prefix.

The main packaged service brings up authentication monitoring, learning, history/strike timers, and manual-list
watching. They stop with it. Package installation initializes only missing state
and settings, without activating protection. `settings.conf` is maintainer-script
managed so upgrades cannot mask existing legacy configurations; it is preserved
on remove. Purge erases system state but intentionally retains user home files.
Updated examples ship under `/usr/share/doc`.

Package and source upgrades replace programs without restarting services or
reloading systemd units. Even `daemon-reload` can rebase custom `OnActiveSec`
deadlines. The installed v0.0.4 post-removal hook still invokes it once during the
first upgrade; v0.0.5 hooks avoid it on upgrade. New CLI/timer invocations use the
new programs; existing Python processes adopt new code on explicit reload/restart.
Home migration retargets an active list watcher using a transient systemd
path/service pair, then stops the old path watcher. It does not reload systemd,
restart the guard or touch timer deadlines. A persistent drop-in handles later
starts and boots. The transient units stop with the guard. Unchanged manual
caches are not rewritten, avoiding duplicate work if an old watcher is still
loaded. See [migration](MIGRATING.md).

`hardban.conf` is the shared strike-state filename. Ban history is sampled, and
persisted learned/strike addresses lack expiry timestamps. Rule reconstruction
renews their configured timeout and resets counters, meters, and temporary bans.
That happens on explicit policy reload, restart or reboot, not package upgrade or
ordinary manual-list updates. Timed manual blocks retain their original expiry.
See [verification](VALIDATION.md) for tested behavior and runtime limits.

### Adding missing configuration options

Installation merges commented template defaults into the selected editable file,
retaining existing assignments and comments. Missing port exclusions and SSH/jail
switches go beside port selection; other missing options go at the end. It never
adds an empty `PROTECTED_PORTS` over legacy port-file input. The original file is
backed up privately before atomic replacement, preserving its owner and mode.
Home writes run as the registered user. Inaccessible/invalid files are deferred
with a notice; complete files are left untouched. Both installation locks cover
the merge. Accepted policy/digests, pending edits, live jails and timer schedules
are not changed by this operation.
