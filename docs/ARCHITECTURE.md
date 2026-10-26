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

Before v0.0.6 activation, legacy monitoring retains its root-owned `auth-state.json`.
Explicit activation migrates recent short-window state to the shared SQLite store
described below; journal cursor deduplication prevents replay. A threshold event
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

`whitelist.conf` and `blocklist.conf` combine manual and automatic entries in
sectioned home files. `frp-ssh-guard-lists.py` imports legacy persistence and kernel
snapshots with absolute expiries, tracks exported/deleted generations, preserves
comments, and writes home files as their registered owner. Root caches retain
accepted manual policy and automatic state for unavailable homes. Legacy internal
files remain compatibility inputs, not additional user-maintained lists.

Live kernel bans retain their original sets. Saved automatic blocks restore into
separate `saved_ban*` sets so overlapping manual CIDRs cannot conflict. List apply
extends older active tables atomically before their existing first block rule;
allow precedence, rule handles, counters, rate meters and jail deadlines remain.
A deleted exported generation is suppressed until expiry; a later attack can
create a new generation. Strike expiry is based on the latest offense, not each
periodic timer execution. Successful trusted logins refresh learned expiry.

The installer imports lists under the installation locks without issuing firewall
mutations or restarting services. An active path watcher may then apply changed
list files using accepted policy. Explicit policy reload/reboot rebuilds rate
meters but restores exported entries with remaining time only. Kernel events not
yet sampled can be lost on abrupt restart. See [verification](VALIDATION.md).

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

## Shared observations (v0.0.6)

Explicit activation writes an internal accepted-state version. Upgrades of an
older installation leave that marker absent and retain the legacy monitor/timer
path until reload. Both journal readers then use the same handler and runtime
lock. A private versioned SQLite database deduplicates cursor hashes, stores
short/long failure windows and timestamped observations, tracks ban generations,
and checkpoints packet counters. No usernames or raw journal messages persist.
Successful login classification happens before any whitelist addition.

The timer and direct authentication enforcement share ban accounting; the strike
manager combines earlier rotated ban logs with the new database. Initial/restored
bans and explicit CLI temporary bans are excluded from automatic campaign counts.
Database tables are bounded by time and a 200,000-row limit; reports expose capacity
loss. SQLite retains reusable free pages rather than vacuuming during protection.

Alert delivery uses owner-privilege subprocesses, pinned directory descriptors,
O_NOFOLLOW, private modes, fsync and atomic rename. The runtime lock serializes
writers. Each line has a stable event ID; spool retries deduplicate complete lines.
The bounded spool is separate from logrotate. Alert failures do not stop enforcement.
Reports and doctor open existing observation state read-only.
