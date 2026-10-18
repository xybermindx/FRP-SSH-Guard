# FRP-SSH-Guard

**English** | [简体中文](README.zh-CN.md)

**[Download v0.0.4 .deb](https://github.com/nengwanx/FRP-SSH-Guard/releases/download/v0.0.4/frp-ssh-guard_0.0.4.deb)** · [All release files](https://github.com/nengwanx/FRP-SSH-Guard/releases/tag/v0.0.4) · Pre-release

Connection-rate protection for SSH services exposed through an FRP server (`frps`).
Install the guard on your public Linux server, select the forwarded TCP ports,
and use nftables to limit repeated connection attempts and block abusive sources.

**Version 0.0.4 · MIT licensed · Bash and Python · No proprietary runtime components**

[Deployment](#deploy-step-by-step) · [Configuration](#configuration) ·
[Commands](#commands) · [Attack coverage](#what-it-protects-against) ·
[Verification](#verify-that-protection-takes-effect) · [Build from source](#open-source-and-building)

## Observed deployment results

An operator-reported snapshot from one deployment, **October 13–17, 2026**
(approximately four days since the guard was last applied), recorded **3.2 million
packets dropped** and **zero backend failed logins in the latest 24 hours**.

| Metric | Before the guard (reported) | With the guard (reported) |
| --- | --- | --- |
| Guard-rule packet counters, approximately four days | — | **3,206,432 dropped; 967 passed** |
| Drop fraction of those packet counters | — | **99.97%** |
| SSH connections reaching backends, hourly | Approximately 200+/hour | **2 in the latest 60 minutes** |
| SSH connections reaching backends, latest 24 hours | — | **79** |
| Backend failed logins, 24-hour window | **6,442** | **0 observed** |
| All-proxy connections, hourly | Approximately 248/hour | **102/hour** |

The hourly SSH figures correspond to approximately **99% fewer backend connections**
against the reported baseline. The remaining all-proxy traffic was reported to be
mostly public web traffic on port 443, which this deployment intentionally left
outside the guarded ports.

The packet figure is `3,206,432 / (3,206,432 + 967)`. It describes the supplied
counters; established and allowlisted traffic can bypass those counters. It does
not measure unique attackers or attack-prevention accuracy. Zero recorded failed
logins means none were observed in that 24-hour window; successful logins and
other authentication activity are separate metrics.

These are observations from an existing deployment, supplied by its operator;
the exact deployed version and raw logs were not supplied for independent
verification. Traffic, settings, and logging coverage affect results. The operator
also reported CPU usage displaying approximately 0% and a few MB of process RAM;
the measurement method and kernel firewall costs were not provided, so these
resource figures are not a performance benchmark.

## Purpose and features

FRP exposes private services through a public server. Forwarded SSH ports can
attract automated probes and repeated connection attempts. This project adds a
host firewall policy specifically for the ports you choose:

- Per-source, per-port new-connection rate limits and temporary source bans.
- A shared per-port rate limit to reduce distributed connection bursts.
- IPv4/IPv6 IP and CIDR allow/block lists, optionally restricted to selected ports.
- Ban history and longer bans for repeatedly observed offenders.
- Optional trusted-source learning from successful logins to the public host's sshd.
- Explicit configuration activation, reboot restoration, and recovery of a missing guard table.
- An architecture-independent Debian package, complete source, and reproducible builds.

The guard observes new TCP SYN packets. It **cannot see passwords or login results
inside forwarded SSH sessions**. It complements authentication controls; it is not
an intrusion detection system or an upstream DDoS service.

## Where to deploy

```mermaid
flowchart LR
    A[Internet SSH clients] --> B[Public Linux host: nftables + FRP-SSH-Guard + frps]
    B -->|FRP tunnel| C[Private host: frpc]
    C --> D[Private SSH server]
```

Install on the **public `frps` host**, where the public forwarded ports listen.
Installing only on the private `frpc` host does not protect the public listeners.
For example, if public port `22001` forwards to a private machine's port `22`,
protect `22001` on the public server.

Target environment:

- Debian 12+ or Ubuntu 24.04+, systemd, nftables 1.0.6+, and kernel nftables support.
- Root access for installation and firewall changes.
- `frps` listening directly in the host network namespace. Container bridge/NAT
  port publishing is not covered by this input-hook design; validate that topology separately.
- One guard instance per host. Existing firewall rules still apply; the guard does
  not open a port blocked by another firewall.

Only explicitly selected TCP ports are filtered. Do not select your management
SSH port, FRP control port, or public web ports. The validator rejects selected
listeners not identified as `frps`, but cannot determine which application an
FRP tunnel carries: choose only the intended private services.

These are target platforms, not a claim that every kernel/distribution combination
has been tested. See [validation results](docs/VALIDATION.md).

## What it protects against

| Traffic or attack | Expected effect and limits |
| --- | --- |
| Many new connections from one source to one protected port | Exceeding the per-source limit adds a temporary source ban across guarded ports. |
| SSH brute-force tools that repeatedly reconnect | Can reduce attempts by limiting connections; does not detect incorrect passwords. |
| Distributed connection bursts | The shared per-port limit drops excess new attempts; legitimate traffic can also be affected. |
| Repeated observed bans | Strike escalation can impose longer bans; sampling can miss short or repeated events. |
| Known unwanted IPs/networks | Manual blocks drop matching traffic to guarded ports, subject to whitelist and established-connection precedence. |
| Slow attempts below thresholds or several guesses inside one connection | No reliable prevention through this guard. |
| Application exploits or stolen credentials | No application-level detection or prevention. |
| Bandwidth-saturating DDoS | No availability guarantee; host filtering cannot recover an already saturated upstream link. |
| Unconfigured ports, UDP, and other protocols | Outside the filtering scope. |

**Effectiveness depends on traffic, limits, and the deployment.** The observed
results above are specific to one deployment. No general prevention percentage,
throughput benchmark, or external security audit is claimed. New SYN
packets, including retransmissions, are measured—not exact sessions or login attempts.

## Download a release

Download from **[GitHub Releases](https://github.com/nengwanx/FRP-SSH-Guard/releases/tag/v0.0.4)**. Debian `.deb` files are
release assets; they do not appear in the GitHub **Packages** tab.
The public 0.0.4 pre-release contains:

| Artifact | Purpose |
| --- | --- |
| [frp-ssh-guard_0.0.4.deb](https://github.com/nengwanx/FRP-SSH-Guard/releases/download/v0.0.4/frp-ssh-guard_0.0.4.deb) | Install on the target Debian/Ubuntu host. |
| [SHA256SUMS](https://github.com/nengwanx/FRP-SSH-Guard/releases/download/v0.0.4/SHA256SUMS) | Verify the downloaded Debian package. |

The complete source remains in the repository. GitHub automatically provides
[Source code (zip)](https://github.com/nengwanx/FRP-SSH-Guard/archive/refs/tags/v0.0.4.zip)
and [Source code (tar.gz)](https://github.com/nengwanx/FRP-SSH-Guard/archive/refs/tags/v0.0.4.tar.gz)
for the release tag, including the runtime, build scripts, packaging, docs, and tests.
Separate source bundles are not uploaded as release assets. `SHA256SUMS` covers the `.deb`.

The package contains scripts rather than a CPU-specific compiled binary. Its
Debian metadata uses `Architecture: all`; dependencies are installed for the host
architecture. CI currently validates x64 (amd64); ARM and 32-bit systems have not
been verified. Checksums detect
corruption/changes; they are not publisher signatures. This pre-release has passed
CI, including nftables and package lifecycle checks; full FRP/systemd VM validation
remains pending. See the release notes for details.

## Deploy step by step

### 1. Start the intended FRP listeners

On the public server, start `frps` and connect the appropriate `frpc` clients.
For an example forwarded SSH port:

```bash
sudo ss -lntp 'sport = :22001'
```

The listener must identify as `frps`. Validation requires at least one selected
active FRP listener; selected unused ports are allowed, but selected non-FRP
listeners are rejected. Make sure the forwarded SSH service already works.

### 2. Verify and install the package

Download the `.deb` and `SHA256SUMS` into the same directory:

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.4.deb
```

Confirm the `.deb` reports `OK`. **Installation does not activate protection or
change firewall rules.** Dependencies are resolved through apt.

### 3. Configure your public forwarded ports

```bash
sudoedit /etc/frp-ssh-guard/settings.conf
```

For public ports `22001`, `22003`, and `23000–23010` except `23005`:

```bash
PROTECTED_PORTS="22001,22003,23000-23010"
EXCLUDE_PORTS="23005"
PER_IP_RATE=2
PER_IP_BURST=40
GLOBAL_RATE=30
GLOBAL_BURST=20
BAN_TIMEOUT=6h
LOGIN_USERS=""
```

These are examples: replace the ports with your actual forwarded SSH ports.
The shipped file leaves `PROTECTED_PORTS` empty, so activation requires your choice.
Keep the other defaults initially; shared NAT/VPN usage may require tuning.

### 4. Validate and activate

```bash
sudo frp-ssh-guard check
sudo frp-ssh-guard enable
sudo frp-ssh-guard status
```

`check` validates without activating. `enable` applies protection immediately and
enables restoration after reboot. Open another SSH connection to verify access;
keep an existing management session or console available during testing.

An optional first-install trial automatically expires after 30 minutes:

```bash
sudo frp-ssh-guard trial
# Test access from another connection, then retain protection:
sudo frp-ssh-guard keep
```

Use `trial` instead of `enable`, while the guard is inactive and disabled. A trial
is not restored after reboot; `keep` enables persistent startup. Finish a pending
trial with `keep` or `disable` before changing policy.

### 5. Change settings later

```bash
sudoedit /etc/frp-ssh-guard/settings.conf
sudo frp-ssh-guard check
sudo frp-ssh-guard reload
sudo frp-ssh-guard status
```

Saving alone does not apply settings. Background jobs, manual-list updates, table
recovery, and reboot use the last accepted policy. `reload` updates that policy
and refreshes the learning service. Validation or nftables application failure
keeps previous protection. Service/helper failures are reported separately; rules
may already be active when such an error is reported.

## Configuration

The complete [commented default](etc/settings.conf.example) explains each setting.
The file contains trusted Bash assignments: keep it root-owned and do not paste
untrusted shell commands into it. Configuration comments and CLI output are English.

| Setting | Default | Meaning |
| --- | --- | --- |
| `PROTECTED_PORTS` | Empty; required | Comma/space-separated ports or ranges. `22001:60:40` overrides that port's shared rate/burst. |
| `EXCLUDE_PORTS` | Empty | Ports/ranges omitted from the protected selection. |
| `PER_IP_RATE`, `PER_IP_BURST` | `2`, `40` | New SYN rate/minute and burst per source and port. |
| `GLOBAL_RATE`, `GLOBAL_BURST` | `30`, `20` | Shared new SYN rate/minute and burst per port, across sources and IP families. |
| `BAN_TIMEOUT` | `6h` | Temporary source-ban duration. |
| `LOGIN_USERS` | Empty; disabled | Extended regex of trusted local sshd accounts, e.g. `alice|bob`. |
| `MAX_LEARNED`, `LEARN_TIMEOUT` | `500`, `90d` | Learned-source cap and restored timeout. |
| `STRIKE_WINDOW` | `90d` | History window for observed ban events. |
| `STRIKE_LADDER` | `2:1d 3:3d 4:7d 5:28d` | Increasing strike thresholds and ban durations; empty disables escalation. |
| `STRIKE_MAX` | `28d` | Maximum escalation duration and timeout when persisted hardbans are restored. |
| `PORT_MIN`, `PORT_MAX` | `1`, `65535` | Inclusive validation bounds. |
| `EDIT_USER` | `root` | Trusted local account owning command-managed lists. |
| `GUARD_TABLE` | `frp_ssh_persistent_guard` | Dedicated nftables table; disable before changing its name. |

Durations use a positive integer followed by `s`, `m`, `h`, `d`, or `w`.
Rates, bursts, and the learned-source cap are integers from 1 to 1000000.
Burst allowances refill over time; they are not a fixed number of attempts per
calendar minute. Successful local-host login learning trusts source IPs and also
exempts them from an existing fail2ban `sshd` jail. It cannot learn successful
logins to SSH servers behind the FRP tunnel.

| Location | Purpose |
| --- | --- |
| `/etc/frp-ssh-guard/settings.conf` | User-edited policy and protected ports. |
| `/var/lib/frp-ssh-guard/applied.conf` | Generated accepted policy; do not edit. |
| `/var/lib/frp-ssh-guard/lists/` | Manual lists, learned sources, strike state. |
| `/var/log/frp-ssh-guard/` | Ban and learning history. |
| `/usr/lib/frp-ssh-guard/` | Package-managed runtime programs. |

Manual lists remain separate. Their edits are watched while the guard runs;
commands apply list changes using accepted policy without adopting pending edits.

## Commands

```bash
frp-ssh-guard --help                       # no root needed
sudo frp-ssh-guard check                    # validate edited configuration
sudo frp-ssh-guard enable                   # apply and enable reboot restoration
sudo frp-ssh-guard reload                   # accept edited settings while active
sudo frp-ssh-guard status                   # state, accepted ports, pending edits
sudo frp-ssh-guard ports                    # accepted port specifications
sudo frp-ssh-guard allow 198.51.100.10       # trust on all guarded ports
sudo frp-ssh-guard allow 2001:db8::10 22001  # trust only on one port
sudo frp-ssh-guard block 203.0.113.0/24 22001
sudo frp-ssh-guard banned
sudo frp-ssh-guard strikes
sudo frp-ssh-guard report
sudo frp-ssh-guard release 198.51.100.20     # remove blocks/bans and forgive history
sudo frp-ssh-guard disable                  # stop protection, retain settings/data
```

Addresses above are documentation examples, not real deployment entries.
`whitelist`, `blocklist`, `learned`, `unallow`, `unblock`, `unban`, `ban`, `remember`,
and `forget` provide additional administration. See `--help` for arguments.
`install`/`remove` remain aliases for `enable`/`disable`. `apply` reapplies accepted
policy and current lists; use `reload` to accept settings edits.

## Verify that protection takes effect

A successful activation should report the guard active and reboot restoration
enabled. `status` should show `enabled`, `active`, accepted ports, no pending edits,
and whether a trial is pending. These are **expected observations**, not benchmark results.

For reproducible checks on a disposable FRP deployment, including a bounded
connection-burst example, see [verification procedure and results](docs/VALIDATION.md).
Check normal access first, then excessive connection attempts, whitelist behavior,
releasing a ban, unchanged unprotected services, explicit reload, and reboot.
Inspect counters with:

```bash
sudo nft list table inet frp_ssh_persistent_guard
sudo frp-ssh-guard banned
sudo journalctl -u frp-ssh-guard.service -u frp-ssh-guard-learn.service --since '-10 min'
```

Operational limits:

- Sources behind shared NAT/VPN count together. Shared per-port limits can drop legitimate traffic during a flood.
- Existing established/related connections and loopback traffic bypass this guard. Whitelists precede blocks; they do not override unrelated firewall tables.
- Applying rules rebuilds the guard table, resetting counters, rate meters, and temporary bans. Manual lists, learned addresses, and persisted strike bans are restored.
- Persisted addresses do not retain expiry timestamps; restoring rules renews their configured timeout.
- History is sampled once a minute; short bans may be missed. Missing-table recovery also waits for that timer and only runs while the guard is active.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| No protected ports selected | Set `PROTECTED_PORTS`; exclusions must not remove every port. |
| No selected FRP listener | Start `frps` and the relevant `frpc` clients; inspect `sudo ss -lntp`. |
| Listener is not FRPS | Select the public forwarded ports on the correct host/network namespace. |
| Settings have no effect | Run `check`, then `reload`; inspect pending edits in `status`. |
| Guard inactive | Run `enable`; `reload` requires an active service. |
| Invalid configuration | Correct the named setting; `--help` works even with broken edits. |
| Rules active but helper/startup failed | Inspect the named systemd unit's journal; fix the cause and retry `reload`/`enable`. |
| Allowed address still cannot connect | Check existing firewall tables, FRP routing, and the backend SSH service. |

## Upgrade, migrate, or uninstall

```bash
sudo apt install ./frp-ssh-guard_NEW_VERSION.deb
# If previously active, load updated programs without adopting pending settings:
sudo systemctl restart frp-ssh-guard.service
sudo frp-ssh-guard status

sudo frp-ssh-guard disable
sudo apt remove frp-ssh-guard  # retain settings and state
sudo apt purge frp-ssh-guard   # also erase settings, state, and logs
```

If you installed a package from before the public version-number correction,
follow the [migration instructions](docs/MIGRATING.md#corrected-public-version-numbering)
to switch to v0.0.4 while retaining settings.

Upgrades do not restart services automatically. Existing `guard.conf`/`ports.conf`
installations remain supported until migrated; the package does not mask them with
an empty new settings file. Follow [migration instructions](docs/MIGRATING.md).
The generated `settings.conf` is preserved by maintainer scripts rather than being
replaced on package upgrades; updated defaults are available in the installed docs.

## Open source and building

All project runtime code is supplied as readable Bash/Python, under the **MIT
license**. The repository and source archives contain packaging, build scripts,
examples, documentation, and tests. There is no closed-source edition or required
project-hosted service. System dependencies retain their own licenses.

```bash
# In the extracted source directory, as a regular user:
make test
make release  # .deb and SHA256SUMS under dist/
make dist     # optional local source tar.gz/zip exports
```

Build prerequisites: Bash, Python 3, GNU Make, and `dpkg-deb`. GitHub source
downloads contain the files tracked at the release tag. Optional `make dist` exports
use an explicit manifest to exclude live settings, IP lists, logs, credentials, and
original deployment backups. See [release procedure](docs/RELEASING.md).

For a source deployment (the package is preferred):

```bash
sudo apt install nftables python3 jq iproute2 util-linux gawk
sudo ./install.sh --ports 22001,22003
# Optional: --exclude 22002 --prefix /opt/my-guard
sudo env GUARD_DIR=/opt/frp-ssh-guard /opt/frp-ssh-guard/bin/frp-ssh-guard status
```

Source installation activates protection and defaults to `/opt/frp-ssh-guard`.
Do not install source and Debian versions side by side. Repeated installs preserve
settings; explicit installer flags update their corresponding fields.

## Contributing, security, and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and tests,
[SECURITY.md](SECURITY.md) for vulnerability reporting, and
[architecture](docs/ARCHITECTURE.md) for implementation details.
Use synthetic addresses and never submit production configurations or authentication logs.

[MIT License](LICENSE): use, modify, and redistribute with the license and copyright
notice retained. The software is provided without warranty. See the license for full terms.
