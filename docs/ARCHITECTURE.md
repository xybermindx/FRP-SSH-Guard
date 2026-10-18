# Architecture

FRP-SSH-Guard owns one nftables `inet` table with an input-hook chain. It returns
for loopback, established/related traffic, non-TCP traffic, and unselected ports.
It then checks trusted sources, manual blocks, persisted strike bans, temporary
bans, per-source/per-port SYN rate meters, and shared per-port SYN limits.

Meters (`rate4`/`rate6`) and bans (`ban4`/`ban6`) are separate sets. Per-source
meters are keyed by address and destination port; a ban covers all guarded ports.
The shared per-port limit spans sources and both IP families. None of these rules
inspect SSH credentials. Other firewall tables keep their existing behavior.

## Editable and accepted configuration

`settings.conf` contains ports and policy as trusted root-owned Bash assignments.
Legacy `guard.conf`/`ports.conf` remain supported when the new file is absent.
`PROTECTED_PORTS` can also be absent in a legacy-compatible configuration; an
explicitly empty selection is an error.

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

The main packaged service brings up learning, history/strike timers, and manual-list
watching. They stop with it. Package installation initializes only missing state
and settings, without activating protection. `settings.conf` is maintainer-script
managed so upgrades cannot mask existing legacy configurations; it is preserved
on remove and erased on purge. Updated examples ship under `/usr/share/doc`.
Upgrades require an explicit service restart to load updated running programs.

`hardban.conf` is the shared strike-state filename. Ban history is sampled, and
persisted learned/strike addresses lack expiry timestamps. Rule reconstruction
renews their configured timeout and resets counters, meters, and temporary bans.
See [verification](VALIDATION.md) for tested behavior and runtime limits.
