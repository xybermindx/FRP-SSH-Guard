# Verification procedure and results

This document distinguishes expected behavior from tests actually run. It does
not claim a prevention percentage, maximum throughput, independent audit, or
production availability guarantee.

## Recorded checks for 0.0.5 local candidate

Validation date: 2026-10-25. This candidate has not been pushed or released.
Privileged tests run in a disposable Debian 12 amd64 VM using unprivileged QEMU
TCG, kernel 6.1.0-54-cloud-amd64, nftables 1.0.6, systemd 252 and real FRP 0.71.1.
No production firewall is used. Test identities, addresses and port choices are
synthetic; raw host logs and configuration are excluded from the source export.

| Check | Result |
| --- | --- |
| Shell/Python syntax and regression suite | Passed locally: 56 tests, one privileged test skipped (57 total). All 57 passed in the Debian VM. |
| Real nftables kernel validation | Passed in VM: initial/replacement tables, shared/per-port jail types, scoped CIDR blocks and timed IPv6 manual elements. |
| Active v0.0.4 → v0.0.5 Debian upgrade | Passed: custom settings, accepted policy, manual list, permissions, service invocation, timer settings, active ban and remaining expiry retained. |
| Home migration and same-version Debian reinstall | Passed: settings/lists moved with correct owner/private permissions; active bans retained; reinstall preserves custom timer deadlines including `OnActiveSec`. |
| Real FRP connection bursts | Passed: new SYN traffic through actual forwarded SSH listeners triggered shared bans and per-port isolation as configured. |
| Native SSH invalid-user attempts | Passed: three separate invalid-user connections triggered the authentication monitor; shared and port-22-only scope both verified. |
| Manual blocks and expiry | Passed: selected-port block, permanent all-protected-port block, automatic expiry, and list updates preserving active automatic bans. |
| Actual reboot with unavailable home | Passed: accepted native SSH/per-port policy and cached manual lists restored; timed manual block retained its original expiry. Pending home settings were not adopted. |
| Debian package lifecycle | Passed in VM: fresh install, reinstall, remove, purge and legacy conffile upgrade via `tests/package-smoke.sh`. |
| Source installation lifecycle | Passed in VM: fresh install with home files, version command, active reinstall with conflicting installer policy flags, unchanged settings/units/bans/timer deadlines, and uninstall retaining home files. |
| Ubuntu, ARM and 32-bit runtime | Not tested for this candidate. No new GitHub CI run has been triggered. |

The VM acceptance script is `tests/vm-acceptance.py`. It deliberately installs
packages, changes firewall rules, starts real FRP processes and creates a network
namespace. Run it **only in a fresh disposable VM** with dependencies available:

```bash
FRP_GUARD_DISPOSABLE=1 python3 tests/vm-acceptance.py \
  /tmp/frp-ssh-guard_0.0.4.deb /tmp/frp-ssh-guard_0.0.5.deb /tmp/frp-binaries
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
