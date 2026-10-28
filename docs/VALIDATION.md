# v0.0.7 validation

## One section per port in lists (v0.0.7)

Checked on 2026-10-28 on the development host with synthetic addresses only.

- Local `make test`: 140 cases, 139 passing and the privileged namespace case
  skipped locally (CI runs it). New regressions: repeated port headers merge into
  one section, automatic bans sort numerically with runtime/strike pairs together,
  user comments and manual lines keep their place, re-rendering is stable, new CLI
  entries join the existing section, and every previously shipped header refreshes.

## Ban durations and repeat-offender steps (v0.0.7)

Checked on 2026-10-28 on the development host. No firewall was changed.

- Local `make test`: 138 cases, 137 passing and the privileged namespace case
  skipped locally (CI runs it). New regressions: shipped defaults resolve to
  12h/3d/7d/30d/90d; a source released from a 90-day jail that re-offends gets
  90 days again, also after its old history is pruned; a clean window resets;
  release forgives the step; every previously shipped list header refreshes;
  upgrading the real v0.0.6 template keeps chosen durations while refreshing
  shipped comments; a newer administrator login renews the learned period.
- Not run: real-traffic VM checks for these changes.

## Administrator counting and learning (v0.0.7)

Checked on 2026-10-28 on the development host. No firewall was changed.

- Local `make test`: 134 cases, 133 passing and the privileged namespace case
  skipped locally (CI runs it). New regressions: rejected keys inside a successful
  login are removed, dropped connections count once each while the fifth still
  bans, password failures count singly, the failure table gains its method column
  on existing state, administrators are recognized (root, settings owner,
  sudo/wheel members, LOGIN_USERS), and upgrades place `LEARN_ADMINS` above
  `LOGIN_USERS` and refresh only the shipped comment.
- Not run: real-traffic VM checks for these changes.

## Slow protection switch, activity log and instructions (v0.0.7)

Checked on 2026-10-27 on the development host only. No firewall was changed.

- Local `make test`: 127 cases, 126 passing and the privileged namespace case
  skipped (it needs root). New regressions cover the `SSH_SLOW_MODE` conversion
  matrix and its placement below `JAIL_PER_PORT`, replacement of only shipped
  comments, the `ALERT_LOG_MAX_SIZE` rename, accepted-snapshot conversion during
  `_upgrade`, slow rules in both jail modes, rate conversion, no connection rule on
  native port 22, collapsed trusted sets, administrator exemption, unban meter
  cleanup, ban reasons, single strike entries, log format, legacy log merge,
  list header refresh and clearer list errors.
- Source and history passed the private privacy rules; the built v0.0.7 package
  passed the artifact scan.
- The privileged namespace test, which loads the new rule syntax into a real
  kernel, and the Debian 12 / Ubuntu 24.04 package lifecycle checks run in CI for
  the tagged commit; the release workflow publishes only after they pass.
- Not run for this release: the disposable QEMU VM scripts
  `tests/vm-slow-defaults.py` and `tests/vm-observations.py` (real sshd and FRP
  traffic). Real-traffic behavior of the new connection limits is therefore covered
  by unit and kernel-syntax tests only.

# v0.0.6 validation

## Jail mode continuity (v0.0.6)

Validated on 2026-10-27 in an isolated Debian 12 QEMU VM, Linux
6.1.0-54-cloud-amd64, systemd 252, nftables 1.0.6 and real FRP 0.71.1.
No production firewall was changed.

- Local `make test`: 114 cases, 113 passing and the privileged namespace case
  skipped. Added both-direction scope/deadline tests, rejected reload rollback,
  offline home caching and legacy-log/SQLite strike-history regressions.
- `tests/vm-jail-modes.py` performed an ordinary APT upgrade from a previously
  published v0.0.6 build, retaining an unsampled live per-port jail, mixed saved shared/per-port
  bans, manual scopes, absolute deadlines and timer activation/deadline properties.
- Three actual switches (per-port to shared, back to per-port, back to shared)
  kept old bans at their original scopes. Real FRP SSH traffic from old scoped
  sources remained blocked only on their original port; old shared sources stayed
  blocked on both protected ports. New traffic created bans in the selected mode.
- Running the actual strike service after each switch retained historical scopes
  and expiry. IPv6 saved set keys and unchanged saved timestamps were verified.
  Same-package reinstallation and service restart retained the mixed jails.
- Source, history and built package passed the private privacy rules. CI also
  verifies privileged namespace rules, reproducibility and Debian/Ubuntu package
  lifecycle behavior. Full Ubuntu runtime and ARM/32-bit remain unverified.

Reproduce in a disposable systemd VM with no installed guard, no `guardmodes`
account and no `guard-client` namespace:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-jail-modes.py OLD.deb NEW.deb FRP_DIR
```

## Fresh-install slow enforcement (v0.0.6)

Validated on 2026-10-27 in an isolated Debian 12 QEMU overlay, Linux
6.1.0-54-cloud-amd64, systemd 252, nftables 1.0.6, OpenSSH and FRP 0.71.1.
No production firewall was changed.

- Local `make test`: 111 cases, 110 passing and the optional privileged kernel
  case skipped. Regression coverage checks default enforcement, spaced failures,
  observation-only behavior, preservation of explicit off/observe/enforce values,
  legacy missing settings, accepted-snapshot compatibility and merge idempotence.
- A fresh actual APT installation wrote `SSH_SLOW_MODE=enforce` while leaving
  native SSH protection and learning disabled. After explicitly enabling native
  SSH and raising only the fast thresholds, 20 real sshd invalid-user connections
  caused one slow-threshold event and one nftables ban; the first 19 caused no ban.
  Reinstallation retained enforcement and did not duplicate the offense.
- Actual ordinary APT upgrades from the previously published v0.0.6 build passed in both
  shared and per-port jail modes with real FRP listeners. No manual reload was
  issued: both monitor PIDs changed automatically while accepted policy, invalid
  pending edits, scoped lists, ban membership/expiry, service invocation, boot
  enablement and timer activation/deadline properties were preserved.
- Legacy settings and accepted policy retained observation mode. Reinstall and
  disabled/trial lifecycle checks use the existing automatic-upgrade VM procedure.
- CI repeats the full suite with privileged namespace coverage, reproducible
  builds and Debian 12 / Ubuntu 24.04 package lifecycle tests. Full Ubuntu
  FRP/systemd runtime and ARM/32-bit runtime remain unverified.

Reproduce the fresh-default check in a disposable VM with no installed guard and
no existing `guardslowfresh` account or `guard-slow-client` namespace:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-slow-defaults.py NEW.deb
# After cleaning disposable fixtures, run vm-auto-upgrade.py for both jail modes.
```

## Automatic upgrade correction (v0.0.6)

Validated on 2026-10-26 using a separate disposable Debian 12 QEMU overlay,
Linux 6.1.0-54-cloud-amd64, systemd 252, nftables 1.0.6 and actual FRP 0.71.1.
No production firewall was changed.

- All 109 regression cases passed in the VM, including the privileged network
  namespace case. The unprivileged workspace passed 108 with that one case skipped.
- Actual ordinary APT upgrades from published v0.0.5 in shared-jail mode and
  first published v0.0.6 build in per-port mode applied the new rules and changed both
  long-running monitor PIDs without a user reload.
- Accepted policy values and input digest, invalid pending edits, custom settings,
  scoped manual rules, saved ban membership and remaining expiry were retained.
  Older accepted snapshots gained observation defaults/activation metadata.
- Main-service invocation and boot enablement were unchanged. Timer activation
  timestamps and next deadlines were unchanged; firewall rate meters were rebuilt.
- Reinstall refreshed running code without renewing saved bans. Disabled installs
  remained disabled. Active trials retained their expiry and stayed temporary;
  `keep` enabled persistent startup.
- An actual `policy-rc.d` denial deferred refresh, kept monitor PIDs unchanged and
  reported the deferral. Unit regressions cover nftables validation/application
  rollback and reporting a monitor restart failure.
- A real VM reboot restored enabled, active protection and the saved ban. Accepted
  policy, user settings and the blocklist's absolute deadlines matched their
  pre-reboot hashes.

Reproduce each upgrade mode on a disposable VM without an installed guard and
with unused test accounts:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-auto-upgrade.py OLD.deb NEW.deb FRP_DIR off
# Clean the disposable fixtures before the second scenario.
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-auto-upgrade.py OLD.deb NEW.deb FRP_DIR on
```

## Original v0.0.6 checks

Validated on 2026-10-26, using invented identities, ports and documentation IPs.
No production firewall was modified.

- `make release`: 104 cases, 103 passing and one optional privileged kernel skip
  in the unprivileged workspace. Private source/artifact checks passed.
- Debian 12 disposable QEMU VM: Linux 6.1.0-54-cloud-amd64, nftables 1.0.6,
  systemd 252, OpenSSH and actual FRP 0.71.1. The complete 103-case suite,
  including the kernel namespace case, passed. A final regression covers a new
  authentication ban after editable-list removal; CI reruns all 104 cases with
  privileged namespace coverage.
- Actual APT upgrades from the released v0.0.5 package to v0.0.6 in both shared and
  per-port jail modes preserved the accepted policy bytes, jail remaining times,
  service invocation, timer activation/deadline properties, list scope, comments,
  ownership and permissions. New settings merged without applying pending edits.
- Actual SSH public-key login learning/refresh, native-22 whitelist precedence,
  FRP port scope, timed expiry and manual tier entries passed in both jail modes.
- Real sshd invalid-user events triggered the long-window observation alert without
  a ban. Explicit enforce/reload applied one ban; repeated sampling and monitor
  restart did not duplicate its event or extend its remaining lifetime.
- Removing an automatic entry from the editable list, then causing a fresh
  native SSH ban, recorded one new offense and escalated through the strike ladder.
  A following kernel sample did not duplicate that offense.
- Real dropped packets appeared as sampled deltas. Per-port native fast detection
  and a two-source test subnet alert passed without installing a subnet ban.
- Owner-private newest-first alerts, explicit reload trimming to 1KiB, no rotated
  archives, report-window filtering and live SSH rule diagnostics passed in the VM.
- Unit coverage includes both readers racing under the real runtime lock, accepted
  password/public-key/PAM classification before learning, overlap/replay dedup,
  short-state migration, allowed sources, IPv4/IPv6 scoped subnet grouping,
  manual/restored exclusions, existing-jail expiry protection, fresh offense accounting after list removal, counter resets and
  inserted counters, offline-home spool recovery, symlink/hardlink refusal, and
  read-only observation queries.

Reproduce on a disposable VM with a purged package and unused test account:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-unified-lists.py OLD.deb NEW.deb FRP_DIR off
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-observations.py
# Clean the disposable fixtures, then repeat with JAIL_PER_PORT=on.
```

The observation continuation explicitly releases only its invented test sources:
a reused journal can cause the old package to ban them before upgrading. It waits
for asynchronous alert delivery separately from the committed database event.

CI additionally checks reproducible builds and Debian 12 / Ubuntu 24.04 package
installation, reinstall, removal and purge. Full Ubuntu FRP/systemd runtime,
ARM/32-bit runtime and hostile high-volume performance have not been verified.
Short kernel bans can escape timer sampling; power loss can lose unsampled packet
deltas. Bounded state loss and sampling boundaries are disclosed in reports.

---

# Verification procedure and results

This document distinguishes expected behavior from tests actually run. It does
not claim a prevention percentage, maximum throughput, independent audit, or
production availability guarantee.

## Recorded checks for 0.0.5

Local validation dates: 2026-10-25 and 2026-10-26. The final v0.0.5 package adds
unified lists, automatic jail migration, trusted SSH learning and manual duration
tiers. Earlier checks below retain their original package versions for traceability.
The release workflow reruns automated checks before upload.
Privileged tests run in a disposable Debian 12 amd64 VM using unprivileged QEMU
TCG, kernel 6.1.0-54-cloud-amd64, nftables 1.0.6, systemd 252 and real FRP 0.71.1.
No production firewall is used. Test identities, addresses and port choices are
synthetic; raw host logs and configuration are excluded from the source export.

| Check | Result |
| --- | --- |
| Shell/Python syntax and regression suite | Passed locally: 85 tests and one privileged kernel test skipped (86 total). All 86 also passed as root in the disposable VM. Includes section parsing, deletion/reban generations, fixed expiry, manual tiers, trusted PAM/journal parsing, whitelist scope, Debian metadata and privacy exceptions. |
| Real nftables kernel validation | Passed in VM: initial/replacement tables, shared/per-port jail types, scoped CIDR blocks, timed IPv6 manual elements, multi-port learned entries and saved automatic port ranges. |
| Unified-list upgrade from the published package | Passed: ordinary APT upgrade imports live runtime/strike/learned entries into sectioned home files. Both shared and per-port scope, remaining TTLs, comments, ownership, accepted policy, service identity and custom timer deadlines retained. |
| Actual successful SSH learning | Passed: a real public-key login to native port 22 creates an expiring learned entry; a newer login refreshes it. Whitelist precedence over blocks verified on native SSH and real FRP; a port-22-only entry does not exempt the FRP port. Whitelisted failed attempts do not create auth bans. |
| Unified-list edits and duration tiers | Passed: overlapping manual CIDR and automatic host bans, unban after restoration, expiration without resurrection, and tier/forever entries applied together. Repeated apply retains the tier's saved deadline. |
| Automatic-ban reboot restoration with unavailable home | Passed: actual reboot restores per-port automatic entries from root cache at their original deadlines; returning the home and applying succeeds. |
| Active v0.0.4 → v0.0.5 Debian upgrade | Passed: custom settings, accepted policy, manual list, permissions, service invocation, timer settings, active ban and remaining expiry retained. |
| Home migration and same-version Debian reinstall | Passed: settings/lists moved with correct owner/private permissions; active bans retained; reinstall preserves custom timer deadlines including `OnActiveSec`. |
| Automatic installation migration (2026-10-26) | Passed: actual sudo apt reinstall over the earlier local v0.0.5 build selects the invoking user, copies existing configuration automatically and keeps service identity, live ban expiry and custom relative timer deadlines. A subsequent root reinstall retains that owner. |
| Ordinary APT revision upgrade (2026-10-26) | Passed: `sudo apt install ./frp-ssh-guard_NEW.deb` upgrades an earlier local v0.0.5 build without `--reinstall`. Existing home settings/manual lists, owner registry, accepted policy, service identity, timer deadlines and active ban expiry remain unchanged. |
| Missing defaults during revision upgrade | Passed: actual APT upgrade between two v0.0.5 builds inserts commented switches below ports and makes an exact owner-only backup. Custom values/comments, owner/mode, pending edits, accepted policy, bans and timer deadlines remain intact. Root reinstall preserves switches set to `on` and creates no extra backup. |
| Automatic migration list watcher | Passed: editing the home blocklist as its owner updates the live firewall without a policy reload or timer tick. After reboot, the persistent watcher handles edits when the temporarily unavailable home returns. |
| Real FRP connection bursts | Passed: new SYN traffic through actual forwarded SSH listeners triggered shared bans and per-port isolation as configured. |
| Native SSH invalid-user attempts | Passed: three separate invalid-user connections triggered the authentication monitor; shared and port-22-only scope both verified. |
| Manual blocks and expiry | Passed: selected-port block, permanent all-protected-port block, automatic expiry, and list updates preserving active automatic bans. |
| Actual reboot with unavailable home | Passed: accepted native SSH/per-port policy and cached manual lists restored; timed manual block retained its original expiry. Pending home settings were not adopted. |
| Debian package lifecycle | Passed again for the final v0.0.5 build in VM: fresh root install creates complete private home files; reinstall preserves custom values; remove/purge retain home files. Legacy conffile migration keeps custom settings/ports, adds missing SSH/jail switches and creates one private backup for the explicitly selected owner. |
| Source installation lifecycle | Passed in VM: fresh install with home files, version command, active reinstall with conflicting installer policy flags, unchanged settings/units/bans/timer deadlines, and uninstall retaining home files. |
| Automatic source migration (2026-10-26) | Passed: active v0.0.4 source upgrade copies settings to the selected user's home, retains accepted policy/live bans/relative timer deadlines and immediately watches edits there. |
| Remaining ban time display | Passed: both ban views display nftables JSON seconds correctly, including per-port IPv6 entries; the VM upgrade test compares the displayed value with the kernel expiry. |
| GitHub CI | Passed: private source/history/artifact scans, regression/kernel tests, reproducible builds and Debian 12/Ubuntu 24.04 package lifecycles. |
| Ubuntu full FRP/systemd runtime, ARM and 32-bit | Not tested locally; package-lifecycle CI does not establish full runtime compatibility. |

The unified-list runtime test is `tests/vm-unified-lists.py`; run it separately
with `off` and `on` in a fresh disposable systemd VM:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-unified-lists.py \
  /tmp/previous.deb /tmp/frp-ssh-guard_0.0.5.deb /tmp/frp-binaries on
```

It exercises an actual package upgrade, FRP traffic and successful SSH logins.
The kernel test also covers expiring learned entries in multiple port sections.
Initial VM test assertions were adjusted for elapsed seconds and nftables' JSON
representation of permanent elements; these were test-fixture issues. Learning
also now skips older replayed successes and refreshes even a one-second newer
login without treating the timestamp as rounded kernel output.

The VM acceptance script is `tests/vm-acceptance.py`. It deliberately installs
packages, changes firewall rules, starts real FRP processes and creates a network
namespace. Run it **only in a fresh disposable VM** with dependencies available:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-acceptance.py \
  /tmp/OLD.deb /tmp/NEW.deb /tmp/frp-binaries
FRP_GUARD_LIVE_TESTS=1 python3 -m unittest discover -s tests -v
```

The initial kernel test used an excessively distant expiry that nftables 1.0.6
rejected. The fixture now uses a one-hour absolute expiry, and the kernel test
passed on rerun. The first upgrade from v0.0.4 still runs that installed version's
old `postrm`, which calls `daemon-reload`; it can rebase custom `OnActiveSec`
deadlines. v0.0.5's upgrade hooks avoid the reload, verified by reinstalling with
an active custom relative timer. Configured intervals and live ban expiry survive
both paths. Explicit policy reload/restart still rebuilds temporary firewall state.

## Recorded checks for 0.0.4

Local preparation environment: Ubuntu 26.04.1 LTS, unprivileged workspace.

| Check | Result |
| --- | --- |
| Shell/Python syntax and unprivileged regression suite | Passed: 33 tests; one additional privileged kernel test skipped (34 total). |
| Debian artifact creation, checksum verification, repeat-build comparison | Passed during preparation: `.deb` and its SHA256SUMS generated and verified. CI repeats the release build and compares checksums. Source downloads are provided by GitHub from the release tag. |
| Package/source contents and local documentation links | Passed: both languages and all settings documented; source manifest excludes live configuration/state. |
| Real nftables kernel namespace test | Not run here: namespace creation is denied and passwordless sudo is unavailable. |
| Debian 12 / Ubuntu 24.04 package lifecycle containers | Not run here: Docker socket access is denied. CI includes these checks. |
| systemd boot, actual FRP traffic, trial expiry, and learning behavior on VMs | Not run here; complete the procedure below before publishing a stable release. |

Unprivileged tests exercise real shell parsing, dispatch, candidate validation,
accepted-policy commits, and rollback with fake external nftables/systemd commands.
They cover pending edits, recovery, aliases, legacy configuration, helper failures,
list behavior, and help with broken settings. Fakes do not establish real kernel,
boot, network, or service behavior. CI configuration is not evidence that CI passed.

## Disposable-host acceptance procedure

Use a disposable systemd VM with actual `frps` and `frpc`, a separate test client,
and console access. Record OS, kernel, nftables/FRP versions, selected ports,
settings, source addresses, timestamps, and observed results without publishing
private deployment data.

1. Before installing, capture `sudo nft list ruleset`. Install the `.deb` and
   confirm no guard table or enabled main service appeared.
2. Start a forwarded SSH listener on public port `22001`. Configure that port,
   run `check`, then `enable`. Verify `active` and `enabled` with `status`.
3. From a separate client, make an ordinary connection:

   ```bash
   ssh -p 22001 USER@YOUR_TEST_SERVER
   ```

   Expected: backend SSH works. Keep a management connection on an unprotected port.
4. From a separate, non-allowlisted test source, make a bounded set of short TCP
   connections. Replace the hostname with a server you own in this disposable lab:

   ```bash
   python3 - YOUR_TEST_SERVER 22001 <<'PY'
   import socket, sys
   host, port = sys.argv[1], int(sys.argv[2])
   connected = failed = 0
   for _ in range(80):
       try:
           with socket.create_connection((host, port), timeout=0.2):
               connected += 1
       except OSError:
           failed += 1
   print(f"connected={connected}, failed_or_timed_out={failed}")
   PY
   ```

   Expected with defaults: enough new SYN traffic can exceed the per-source burst
   and produce a ban; inspect `sudo frp-ssh-guard banned` and nftables counters on
   the server. The shared rate limit can drop earlier attempts, and timing/network
   conditions affect counts. Failed connects alone do not prove guard action—use
   counters and ban membership. This is a behavior check, not a load benchmark.
5. Release the test source with `sudo frp-ssh-guard release TEST_CLIENT_IP`.
   Verify normal access returns. Allow that address, repeat the bounded check,
   and confirm the guard's ban/rate rules are bypassed. Remove the allow entry.
6. Add a manual block and confirm new connections to selected ports are dropped.
   Verify an unprotected test service and already-established sessions behave as
   documented. Check both IPv4 and IPv6 where available.
7. Save another port/rate in `settings.conf` without reloading. Verify `status`
   reports pending edits, and list updates/timer ticks keep the accepted policy.
   On this disposable host only, delete the guard's table and wait for the
   minute recovery timer: accepted policy should return. Other tables must remain intact.
8. Run `reload`; verify the changed policy and a refreshed learning service.
   Try an invalid port and invalid rate: validation should fail with old protection
   retained. Restore valid edits. Test opt-in local sshd learning, then disable it.
9. Reboot with valid but unapplied edits present. Verify accepted policy returns,
   helpers start, and the editable changes remain pending. Apply them explicitly.
10. Disable protection. Verify the table stays absent across timer ticks and reboot.
    Test a fresh trial: allow 30 minutes to expire, verify removal, then separately
    test `keep`. A trial alone must not restore protection after reboot.
11. Upgrade/reinstall with custom settings and lists. Verify they are preserved.
    Test a 1.0.x upgrade, migration, remove (retain data), and purge (erase data).
12. To check strike escalation, generate separated observed ban episodes in the
    lab, allowing the history timer to sample each and the strike timer to run.
    Confirm the persisted `hardban.conf` is restored after rule reconstruction.
    Record the sampling window; do not equate sampled entries with exact offenses.

## Publishing results

Replace pending entries only with actual observations. Include test conditions,
commands, outcomes, and remaining limitations in release notes. Targets currently
listed in the README are supported design targets, not measured performance claims.
