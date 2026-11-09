# Architecture

FRP-SSH-Guard owns one nftables `inet` table with an input-hook chain. It returns
for loopback, established/related traffic, non-TCP traffic, and unselected ports.
It then checks trusted sources, manual blocks, persisted strike bans, temporary
bans, per-source/per-port SYN rate meters, shared per-port SYN limits, and the
slow brute-force meters.

Meters (`rate4`/`rate6`) and bans (`ban4`/`ban6`) are separate sets. Per-source
meters are keyed by address and destination port. With `JAIL_PER_PORT=off`, bans
are keyed by address and cover all guarded ports. With `on`, both automatic and
strike sets use address/port tuples; history and escalation retain that scope.
The shared per-port limit spans sources and both IP families. None of these rules
inspect SSH credentials. Other firewall tables keep their existing behavior.

With `SSH_SLOW_PROTECTION=on`, each forwarded port gets one more rule after the
shared limit, so packets that limit already dropped are not counted. It updates
`slow4`/`slow6`, a token-bucket meter of `N` packets that refills at `N` per
`SSH_SLOW_WINDOW` (rate per day, or per week for windows over a day). The meter key
follows the jail mode: the source address alone (`SSH_SLOW_TOTAL_CONNECTIONS`,
counted across all forwarded ports) or the address/port pair
(`SSH_SLOW_PORT_CONNECTIONS`). When it overflows, the rule adds the same key to
`ban4`/`ban6` and to the 10-minute `slowhit4`/`slowhit6` marker that lets the
sampler record the ban reason. Sources in `trusted4`/`trusted6` are skipped: every
whitelist address under any port, with permanent networks collapsed and learned
addresses inside them dropped, because nftables interval sets reject overlaps.
List-only updates refill the trusted sets; `unban` also clears the meters. Native
port 22 is excluded and keeps its journal-based failed-login threshold.

Every per-source meter (per-minute, slow and behavior counting) first looks up
`synseen4`/`synseen6`, keyed by address, source port, destination port and TCP
sequence number (2-minute timeout). One rule after all lookups adds the SYN, so a
resent SYN is counted once; a new connection reusing a source port has a new
sequence number. The shared per-port limit still counts every packet, and a full
set fails open to the older counting.

`known4`/`known6` hold source/port pairs with a proven login; the slow and behavior
rules skip them. The minute sampler fills them: frps terminates each client TCP
connection, so `ss -tinp` lists frps sockets on forwarded ports with their bytes
acknowledged. A socket seen open for `LEARN_SESSION_AGE`, or with more than
`LEARN_SESSION_BYTES` sent, outlived sshd's pre-login limit, so its pair is known
for `LEARN_TIMEOUT`. The database is authoritative; each sample adds missing pairs
(a reload empties the set), replaces renewed ones and deletes forgotten ones.

With `SSH_SLOW_BEHAVIOR=on`, a rule per forwarded port updates a counter in
`count4`/`count6` (address/port, 26-hour timeout) for untrusted, unknown first SYNs.
The sampler takes per-minute differences (a lower value or a new table generation
restarts a counter) into 15-minute activity slots. A source's streak ends after a
`SSH_BEHAVIOR_PAUSE` without new connections. A rule `Np:T` or `Nc:T` matches once
the streak lasted T and the last T held N ports or N connections. Port rules ban
the address on all ports: in shared mode through `ban4/6`, in per-port mode through
the address-keyed `wideban4/6` with its own all-port drop rule. Connection rules
count the source total in shared mode and each port alone in per-port mode, where
they ban that address/port pair. Sources with any known pair are not judged.
Bans skip addresses a live, saved, manual or strike block already covers, and are
recorded like authentication bans, so strikes, subnet reports and the activity log
follow. In per-port mode the strike manager inserts address-wide escalations into
`saved_ban4/6`. Older tables without these sets are left alone until refreshed.

A rule `Nb:T` is compiled into the kernel instead of being judged by the sampler,
which would see a burst only after it ended. Each forwarded port gets one more rule
beside the slow rule, with the same `trusted`, `known` and `synseen` lookups, keyed by
jail mode. It updates `burst4`/`burst6`, a token bucket of N that refills at N per T,
and on overflow adds the key to `ban4`/`ban6` and to the 10-minute
`bursthit4`/`bursthit6` marker that records the `burst-connections` reason. An
upgrade adds the default burst rule once to a file or accepted snapshot that still
holds the exact default from before the burst rule; `BEHAVIOR_RULES_VERSION` and a comment in the file
record that, so going back to the old rules afterwards stays in effect.

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

The package launcher supplies program, configuration, state, and log directories.
The same runtime supports source installations with `GUARD_DIR` set to their prefix.
Package units are owned by the package manager; activation does not generate
overriding `/etc` units. The source installer generates equivalent units for its prefix.

The `.deb` and the noarch `.rpm` install an identical payload, staged once by
`scripts/build.py`. Their install, upgrade and removal steps live in one script,
`/usr/lib/frp-ssh-guard/lifecycle.sh`:

| Step | Debian | RPM |
| --- | --- | --- |
| `configure` | `postinst configure` | `%post` (count 1 install, 2 upgrade) |
| `before-remove` | `prerm remove` | `%preun` with count 0 |

Upgrades never stop protection: the old `%preun` sees count 1 and does nothing. The
steps that run while the script is not installed stay in each format: checks before
unpacking (`preinst`, `%pre`), and the systemd reload after removal (`postrm`,
`%postun`). RPM has no purge, so an erase keeps state like `dpkg remove`.

`bin/frp-ssh-guard-platform.sh` holds the requirements (systemd, nftables, Python,
Bash, jq, `ss`, `flock`, `cmp`). `install.sh --preflight` and `check`/`enable` share it, and
it prints the install command for the detected package manager. `doctor` reports the
distribution, architecture, kernel, nftables and Python versions, SELinux mode, and
whether firewalld or `nftables.service` is active.

The main packaged service brings up authentication monitoring, learning, history/strike timers, and manual-list
watching. They stop with it. Fresh package installation initializes only missing state
and settings, without activating protection. `settings.conf` is maintainer-script
managed so upgrades cannot mask existing legacy configurations; it is preserved
on remove. Purge erases system state but intentionally retains user home files.
Updated examples ship under `/usr/share/doc`.

Since v0.0.6, postinst refreshes an active guard through
the internal `_upgrade` action. Under the lifecycle/runtime locks it snapshots
live lists, compiles and validates accepted policy, atomically replaces the nftables
table, and restarts SSH readers after releasing the runtime lock. It preserves
pending edits and their digest; only newly supported runtime defaults and the
observation marker are added. Failed nft application restores the accepted file.
Helper failures are reported, rather than claiming successful activation.
Main-service enablement, trial expiry and timers are untouched. No systemd manager
reload is performed. The installed v0.0.4 removal hook can still invoke one during
its first upgrade. Inactive installs and service-policy-denied installs do not
activate. Source reinstalls retain their earlier explicit activation workflow.
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

The installer first imports lists under the installation locks, then automatically
refreshes active package installations. A path watcher may also apply changed
lists using accepted policy. Automatic refresh, explicit reload and reboot rebuild
rate meters but restore exported entries with remaining time only. Upgrades export
live entries before replacement; abrupt restarts can lose unsampled kernel events.
See [verification](VALIDATION.md).

### Adding missing configuration options

The template lists everyday settings as assignments and the rest as commented
defaults under Advanced, which installation does not add to existing files because
runtime defaults already cover them. `tidy-settings` rewrites a file in the current
layout under the installation locks, keeping every value that differs from a default.

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
Failures are keyed by boot, sshd process and client port, which identify one
connection. A later success on that connection deletes its failures (rejected key
offers and typos). Rejected public keys count once per connection; passwords count
individually. `LEARN_ADMINS` resolves administrators when a login succeeds: root,
the registered settings owner, and members of the `sudo`, `admin` or `wheel` groups
via the system group database; `LOGIN_USERS` adds accounts by regex.

The timer and direct authentication enforcement share ban accounting; the strike
manager combines earlier rotated ban logs with the new database. It walks each
source's bans in order: a ban within `STRIKE_WINDOW` after the previous ban ended
moves one ladder step up (the top step repeats), otherwise the step resets. Steps
persist in `lists/strike-levels.json`, so a chain outlives pruned history;
`unban`/`release` forgiveness drops it. Initial/restored
bans and explicit CLI temporary bans are excluded from automatic campaign counts.
Database tables are bounded by time and a 200,000-row limit; reports expose capacity
loss. SQLite retains reusable free pages rather than vacuuming during protection.

Activity-log delivery (`frp-ssh-guard.log`) uses owner-privilege subprocesses,
pinned directory descriptors, O_NOFOLLOW, private modes, fsync and atomic rename.
The runtime lock serializes writers. Each line has a stable event ID; spool retries
deduplicate complete lines, and a pre-0.0.7 `alerts.log` is merged once and removed.
Logged kinds are bans (with reason, limit and expiry), manual bans, strike
escalations, releases, accepted settings, new-source logins and subnet clusters;
failed logins stay in the database. The bounded spool is separate from logrotate.
Log failures, and list-view failures after a ban, do not stop enforcement.
Reports and doctor open existing observation state read-only.
