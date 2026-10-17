# Verification procedure and results

This document distinguishes expected behavior from tests actually run. It does
not claim a prevention percentage, maximum throughput, independent audit, or
production availability guarantee.

## Recorded checks for 1.1.0

Local preparation environment: Ubuntu 26.04.1 LTS, unprivileged workspace.

| Check | Result |
| --- | --- |
| Shell/Python syntax and unprivileged regression suite | Passed: 33 tests; one additional privileged kernel test skipped (34 total). |
| Debian/source artifact creation, checksum verification, repeat-build comparison | Passed: `.deb`, tar.gz, ZIP, and SHA256SUMS generated; checksums verified; repeated builds produced identical checksums. |
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
