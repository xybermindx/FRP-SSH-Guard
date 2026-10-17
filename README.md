# FRP SSH Guard

**English** | [简体中文](#简体中文)

**[Download v0.0.4 .deb](https://github.com/nengwanx/FRP-Guard/releases/download/v0.0.4/frp-ssh-guard_0.0.4_all.deb)** · [All release files](https://github.com/nengwanx/FRP-Guard/releases/tag/v0.0.4) · Pre-release

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
    A[Internet SSH clients] --> B[Public Linux host: nftables + FRP SSH Guard + frps]
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

Download from **[GitHub Releases](https://github.com/nengwanx/FRP-Guard/releases/tag/v0.0.4)**. Debian `.deb` files are
release assets; they do not appear in the GitHub **Packages** tab.
The public 0.0.4 pre-release contains:

| Artifact | Purpose |
| --- | --- |
| [frp-ssh-guard_0.0.4_all.deb](https://github.com/nengwanx/FRP-Guard/releases/download/v0.0.4/frp-ssh-guard_0.0.4_all.deb) | Install on the target Debian/Ubuntu host. |
| [SHA256SUMS](https://github.com/nengwanx/FRP-Guard/releases/download/v0.0.4/SHA256SUMS) | Verify the downloaded Debian package. |

The complete source remains in the repository. GitHub automatically provides
[Source code (zip)](https://github.com/nengwanx/FRP-Guard/archive/refs/tags/v0.0.4.zip)
and [Source code (tar.gz)](https://github.com/nengwanx/FRP-Guard/archive/refs/tags/v0.0.4.tar.gz)
for the release tag, including the runtime, build scripts, packaging, docs, and tests.
Separate source bundles are not uploaded as release assets. `SHA256SUMS` covers the `.deb`.

`all` means the package contains scripts rather than a CPU-specific compiled
binary. Dependencies are installed for the host architecture. Checksums detect
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
sudo apt install ./frp-ssh-guard_0.0.4_all.deb
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
sudo apt install ./frp-ssh-guard_NEW_VERSION_all.deb
# If previously active, load updated programs without adopting pending settings:
sudo systemctl restart frp-ssh-guard.service
sudo frp-ssh-guard status

sudo frp-ssh-guard disable
sudo apt remove frp-ssh-guard  # retain settings and state
sudo apt purge frp-ssh-guard   # also erase settings, state, and logs
```

If you installed the earlier v1.1.0 or 1.0.x package, use
`sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.4_all.deb` to adopt the
corrected public numbering without removing your settings.

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

## 简体中文

<details>
<summary>点击展开完整中文指南（在本页阅读）</summary>

[返回 English](#frp-ssh-guard)

<!-- Keep this guide in sync with README.zh-CN.md, starting at its download link. -->

**[下载 v0.0.4 .deb](https://github.com/nengwanx/FRP-Guard/releases/download/v0.0.4/frp-ssh-guard_0.0.4_all.deb)** · [全部发布文件](https://github.com/nengwanx/FRP-Guard/releases/tag/v0.0.4) · 预发布版本

为 FRP 服务端（`frps`）暴露的 SSH 服务提供连接速率防护。
将本工具安装在公网 Linux 服务器上，选择需要保护的转发 TCP 端口，
通过 nftables 限制重复连接尝试，并封禁异常来源。

**版本 0.0.4 · MIT 开源许可 · Bash 与 Python · 无闭源运行组件**

[部署步骤](#逐步部署) · [配置说明](#配置说明) · [命令](#常用命令) ·
[防护范围](#可以防护哪些攻击) · [验证效果](#验证防护是否生效) · [源码构建](#开源与源码构建)

## 部署观测数据

一位部署者提供了单个环境在 **2026 年 10 月 13–17 日**的观测快照：
距上次应用防护规则约四天，累计**丢弃约 320 万个数据包**，
最近 24 小时后端**未记录到 SSH 登录失败**。

| 指标 | 启用前（部署者提供） | 启用后（部署者提供） |
| --- | --- | --- |
| 防护规则包计数，约四天 | — | **丢弃 3,206,432；通过 967** |
| 上述包计数中的丢弃占比 | — | **99.97%** |
| 到达后端的 SSH 连接，按小时 | 约 200 次以上/小时 | **最近 60 分钟 2 次** |
| 最近 24 小时到达后端的 SSH 连接 | — | **79 次** |
| 24 小时窗口内后端登录失败 | **6,442 次** | **观测到 0 次** |
| 所有代理连接，按小时 | 约 248 次/小时 | **102 次/小时** |

相对于提供的小时基线，到达后端的 SSH 连接数量约**减少 99%**。
部署者报告，剩余的所有代理连接主要是 443 端口的公共 Web 流量，
该部署有意将这些端口排除在防护范围之外。

包丢弃占比的计算为 `3,206,432 / (3,206,432 + 967)`。
它表示所提供计数器中的丢弃比例；已建立连接和白名单流量可能绕过这些计数器。
这个比例不能直接表示独立攻击者数量或攻击识别准确率。
登录失败记录为零表示该 24 小时窗口内未观察到失败事件；成功登录及其他认证活动属于不同指标。

这些数据来自部署者提供的现有环境观测；未提供确切部署版本或原始日志供独立核验。
流量、配置和日志覆盖范围都会影响结果。
部署者还报告监控显示 CPU 使用率约为 0%、进程内存为数 MB；
由于未提供测量方法或内核防火墙开销，这些资源观测不构成性能基准测试。

## 项目目的与功能

FRP 可以通过公网服务器暴露内网服务，转发的 SSH 端口也可能受到自动扫描和大量连接尝试。
本项目为明确选择的端口增加主机防火墙策略：

- 按来源 IP、目标端口限制新连接速率，并临时封禁来源。
- 对每个端口设置共享速率上限，缓解分布式连接突发。
- 支持 IPv4/IPv6 地址、CIDR 网段以及按端口限定的白名单和黑名单。
- 记录封禁历史，对重复被观察到的违规来源延长封禁时间。
- 可选：通过公网服务器本机 sshd 的成功登录学习可信来源。
- 显式应用配置、重启恢复，以及防护表丢失后的恢复。
- 提供架构无关的 Debian 软件包、完整源码和可重复构建流程。

工具观察的是新 TCP SYN 数据包，**无法看到转发 SSH 会话中的密码或登录结果**。
它是身份认证措施的补充，不是入侵检测系统，也不是上游 DDoS 清洗服务。

## 应该部署在哪里

```mermaid
flowchart LR
    A[互联网 SSH 客户端] --> B[公网 Linux 主机：nftables + FRP SSH Guard + frps]
    B -->|FRP 隧道| C[内网主机：frpc]
    C --> D[内网 SSH 服务]
```

安装在 **运行 `frps` 的公网服务器**，即公网转发端口实际监听的主机。
只安装在内网 `frpc` 主机上，不能保护公网监听端口。
例如公网端口 `22001` 转发到内网机器的 `22` 端口，应在公网服务器上保护 `22001`。

目标环境：

- Debian 12+ 或 Ubuntu 24.04+，使用 systemd、nftables 1.0.6+，且内核支持 nftables。
- 安装和修改防火墙需要 root 权限。
- `frps` 直接在主机网络命名空间监听。容器桥接/NAT 端口映射不属于此 input hook 方案的覆盖范围，需要另行验证。
- 每台主机仅支持一个防护实例。其他防火墙规则仍然有效；本工具不会放行被其他规则阻止的端口。

只过滤明确选择的 TCP 端口。不要选择服务器管理 SSH 端口、FRP 控制端口或公共 Web 端口。
验证器会拒绝不是 `frps` 的已选监听端口，但无法识别 FRP 隧道中实际运行的应用，
因此需要由管理员选择正确的私有服务端口。

以上是目标平台，不代表所有系统和内核组合都经过测试。
实际验证范围见[验证记录](docs/VALIDATION.md)（英文）。

## 可以防护哪些攻击

| 流量或攻击 | 预期效果与边界 |
| --- | --- |
| 同一来源对受保护端口发起大量新连接 | 超过单来源限制后，临时封禁该来源访问所有受保护端口。 |
| 不断重新连接的 SSH 暴力破解工具 | 可以减少连接尝试，但不检测密码错误。 |
| 分布式连接突发 | 每端口共享上限丢弃过量新连接；正常用户也可能受影响。 |
| 多次被观察到的封禁 | 累犯策略可以延长封禁；采样可能漏掉短期或重复事件。 |
| 已知不需要的 IP 或网段 | 手动黑名单丢弃匹配流量，但白名单和已建立连接的优先规则仍然适用。 |
| 低于阈值的慢速尝试，或同一连接中多次猜密码 | 无法依靠本工具可靠阻止。 |
| 应用漏洞利用或被盗凭据 | 不提供应用层识别或阻止能力。 |
| 占满带宽的 DDoS | 不保证服务可用；主机过滤无法恢复已经被占满的上游链路。 |
| 未配置端口、UDP 和其他协议 | 不在过滤范围内。 |

**实际效果取决于流量、配置和部署方式。** 上述观测仅对应单个部署环境。
本项目不宣称通用防御成功率、吞吐性能或外部安全审计结果。
统计对象是新 SYN 包（包括重传），不是精确的会话数量或登录次数。

## 下载发布版本

请从 **[GitHub Releases](https://github.com/nengwanx/FRP-Guard/releases/tag/v0.0.4)** 下载。Debian `.deb` 文件作为发布附件提供，
不会显示在 GitHub 的 **Packages** 栏目中。公开的 0.0.4 预发布版本包含：

| 文件 | 用途 |
| --- | --- |
| [frp-ssh-guard_0.0.4_all.deb](https://github.com/nengwanx/FRP-Guard/releases/download/v0.0.4/frp-ssh-guard_0.0.4_all.deb) | 安装到目标 Debian/Ubuntu 主机。 |
| [SHA256SUMS](https://github.com/nengwanx/FRP-Guard/releases/download/v0.0.4/SHA256SUMS) | 校验下载的 Debian 软件包。 |

完整源码保留在仓库中。GitHub 会根据发布标签自动提供
[Source code (zip)](https://github.com/nengwanx/FRP-Guard/archive/refs/tags/v0.0.4.zip)
和 [Source code (tar.gz)](https://github.com/nengwanx/FRP-Guard/archive/refs/tags/v0.0.4.tar.gz)，
包含运行代码、构建脚本、打包文件、文档及测试。无需再上传重复的源码附件。
`SHA256SUMS` 仅校验 `.deb` 文件。

`all` 表示软件包包含脚本，而非针对特定 CPU 编译的二进制程序；依赖包按主机架构安装。
校验和可检测文件变化或损坏，但不是发布者签名。此预发布版本已通过 CI，
包括 nftables 和软件包生命周期检查；完整的 FRP/systemd 虚拟机验证仍待完成，详见发布说明。

## 逐步部署

### 1. 启动需要保护的 FRP 监听端口

在公网服务器启动 `frps`，并连接对应的 `frpc` 客户端。例如检查转发端口 `22001`：

```bash
sudo ss -lntp 'sport = :22001'
```

监听进程应显示为 `frps`。验证时至少需要一个已选端口具有活动的 FRP 监听；
允许其他已选端口暂时没有监听，但不允许它们由非 FRP 进程监听。
先确认原来的转发 SSH 服务可以正常使用。

### 2. 校验并安装软件包

把 `.deb` 和 `SHA256SUMS` 下载到同一目录：

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.4_all.deb
```

确认 `.deb` 显示 `OK`。**安装本身不会开启防护或修改防火墙规则。** apt 会处理依赖安装。

### 3. 设置公网转发端口

```bash
sudoedit /etc/frp-ssh-guard/settings.conf
```

例如保护 `22001`、`22003` 和 `23000–23010`，但排除 `23005`：

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

请把示例端口替换成真实的公网 SSH 转发端口。默认文件中的 `PROTECTED_PORTS` 为空，必须明确设置后才能启用。
其他参数可先保留默认值；多人共享 NAT/VPN 出口时可能需要调整阈值。

### 4. 验证并启用

```bash
sudo frp-ssh-guard check
sudo frp-ssh-guard enable
sudo frp-ssh-guard status
```

`check` 仅验证，不启用防护。`enable` 立即应用规则，并开启重启恢复。
请另外建立一个 SSH 连接验证访问；测试期间保留管理会话或控制台入口。

首次部署也可以选择 30 分钟自动到期的试运行：

```bash
sudo frp-ssh-guard trial
# 从另一个连接确认访问正常后，保留防护：
sudo frp-ssh-guard keep
```

在防护未运行且未设置开机恢复时，用 `trial` 代替 `enable`。
试运行不会在重启后恢复；`keep` 会启用持久启动。
试运行期间先执行 `keep` 或 `disable`，再修改策略。

### 5. 后续修改配置

```bash
sudoedit /etc/frp-ssh-guard/settings.conf
sudo frp-ssh-guard check
sudo frp-ssh-guard reload
sudo frp-ssh-guard status
```

仅保存文件不会生效。后台任务、手动名单更新、防护表恢复以及重启都会使用上次成功应用的策略。
`reload` 接受新设置并刷新学习服务。验证或 nftables 应用失败时，保留原有防护。
服务或辅助任务故障会单独报告；发生此类错误时，规则可能已经生效。

## 配置说明

完整参数说明见[带注释的默认配置](etc/settings.conf.example)。文件使用可信 Bash 赋值语法：
请保持 root 所有权，不要粘贴不可信的 shell 命令。默认配置注释和命令输出使用英文。

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PROTECTED_PORTS` | 空，必须设置 | 逗号或空格分隔的端口/范围；`22001:60:40` 覆盖该端口的共享速率和突发额度。 |
| `EXCLUDE_PORTS` | 空 | 从保护范围中排除的端口/范围。 |
| `PER_IP_RATE`, `PER_IP_BURST` | `2`, `40` | 每来源、每端口的新 SYN 每分钟速率及突发额度。 |
| `GLOBAL_RATE`, `GLOBAL_BURST` | `30`, `20` | 每端口共享的新 SYN 每分钟速率及突发额度，跨来源和 IP 协议族共享。 |
| `BAN_TIMEOUT` | `6h` | 临时封禁来源的时长。 |
| `LOGIN_USERS` | 空，禁用 | 可信的本机 sshd 账户扩展正则表达式，例如 `alice|bob`。 |
| `MAX_LEARNED`, `LEARN_TIMEOUT` | `500`, `90d` | 学习来源数量上限和恢复时使用的超时。 |
| `STRIKE_WINDOW` | `90d` | 观察到的封禁事件的历史统计窗口。 |
| `STRIKE_LADDER` | `2:1d 3:3d 4:7d 5:28d` | 递增的违规次数及封禁时长；空字符串禁用升级。 |
| `STRIKE_MAX` | `28d` | 升级封禁的时长上限，也是恢复持久封禁时的超时。 |
| `PORT_MIN`, `PORT_MAX` | `1`, `65535` | 端口校验的上下界，包含边界。 |
| `EDIT_USER` | `root` | 拥有命令管理名单的可信本机账户。 |
| `GUARD_TABLE` | `frp_ssh_persistent_guard` | 专用 nftables 表名；修改前先停用防护。 |

时长格式为正整数加 `s`、`m`、`h`、`d` 或 `w`（秒、分、小时、天、周）。
速率、突发额度及学习数量上限是 1–1000000 的整数。
突发额度随时间补充，不是每个自然分钟固定允许若干次尝试。
本机成功登录学习会信任来源 IP，也会将其加入现有 fail2ban `sshd` jail 的忽略名单。
它无法学习 FRP 隧道后端 SSH 服务的成功登录。

| 位置 | 用途 |
| --- | --- |
| `/etc/frp-ssh-guard/settings.conf` | 用户修改的策略及受保护端口。 |
| `/var/lib/frp-ssh-guard/applied.conf` | 生成的已接受策略，请勿手动修改。 |
| `/var/lib/frp-ssh-guard/lists/` | 手动名单、学习来源、累犯状态。 |
| `/var/log/frp-ssh-guard/` | 封禁与学习历史。 |
| `/usr/lib/frp-ssh-guard/` | 软件包管理的运行程序。 |

手动名单独立保存，防护运行期间会监听名单修改。
名单命令使用已接受策略，不会顺带应用尚未 reload 的配置。

## 常用命令

```bash
frp-ssh-guard --help                       # 无需 root
sudo frp-ssh-guard check                    # 验证编辑后的配置
sudo frp-ssh-guard enable                   # 立即应用并开启重启恢复
sudo frp-ssh-guard reload                   # 运行期间接受新配置
sudo frp-ssh-guard status                   # 状态、已接受端口、待应用修改
sudo frp-ssh-guard ports                    # 已接受的端口规格
sudo frp-ssh-guard allow 198.51.100.10       # 在所有受保护端口信任此来源
sudo frp-ssh-guard allow 2001:db8::10 22001  # 只在指定端口信任
sudo frp-ssh-guard block 203.0.113.0/24 22001
sudo frp-ssh-guard banned
sudo frp-ssh-guard strikes
sudo frp-ssh-guard report
sudo frp-ssh-guard release 198.51.100.20     # 移除封禁并豁免历史
sudo frp-ssh-guard disable                  # 停用防护，保留配置和数据
```

以上 IP 是文档示例，不是真实部署数据。
其他管理命令包括 `whitelist`、`blocklist`、`learned`、`unallow`、`unblock`、`unban`、
`ban`、`remember` 和 `forget`，具体参数见 `--help`。
`install`/`remove` 保留为 `enable`/`disable` 的兼容别名。
`apply` 重新应用已接受策略和当前名单；接受配置修改请使用 `reload`。

## 验证防护是否生效

成功启用后应报告防护正在运行、已启用重启恢复。
`status` 应显示 `enabled`、`active`、已接受的端口、无待应用修改，以及试运行状态。
这些是**预期现象**，不是性能测试结果。

在可丢弃的 FRP 测试环境中，按照[验证步骤与记录](docs/VALIDATION.md)（英文）检查：
正常连接、受控突发连接、白名单、解除封禁、未保护服务、显式 reload，以及重启恢复。
该文档还提供有次数上限的连接测试示例。查看计数器和日志：

```bash
sudo nft list table inet frp_ssh_persistent_guard
sudo frp-ssh-guard banned
sudo journalctl -u frp-ssh-guard.service -u frp-ssh-guard-learn.service --since '-10 min'
```

运行边界：

- 共用 NAT/VPN 出口的用户会一起计数；共享端口限制可能在攻击期间影响正常用户。
- 已建立/相关连接和回环流量绕过此防护。白名单优先于黑名单，但不能覆盖其他防火墙表。
- 应用规则会重建防护表，重置计数器、速率状态和临时封禁；手动名单、学习地址和持久累犯封禁会恢复。
- 持久记录保存地址而非到期时间，因此恢复规则会更新其超时。
- 历史每分钟采样一次，可能漏掉短期封禁。防护表丢失的恢复也要等待定时任务，且仅在防护运行期间执行。

## 故障排查

| 现象 | 处理方法 |
| --- | --- |
| 未选择受保护端口 | 设置 `PROTECTED_PORTS`，并确保排除项没有移除全部端口。 |
| 没有已选 FRP 监听 | 启动 `frps` 和对应 `frpc`，检查 `sudo ss -lntp`。 |
| 监听进程不是 FRPS | 确认主机、网络命名空间及公网转发端口。 |
| 配置没有生效 | 先 `check` 再 `reload`，通过 `status` 查看待应用修改。 |
| 防护未运行 | 执行 `enable`；`reload` 要求服务处于活动状态。 |
| 配置无效 | 修正错误信息指出的参数；配置损坏时仍可使用 `--help`。 |
| 规则已生效但辅助任务/开机设置失败 | 检查对应 systemd 单元日志，修复后重试 `reload`/`enable`。 |
| 白名单地址仍无法访问 | 检查其他防火墙规则、FRP 转发和后端 SSH 服务。 |

## 升级、迁移与卸载

```bash
sudo apt install ./frp-ssh-guard_NEW_VERSION_all.deb
# 如果之前已经启用，加载新程序，但不接受待应用的配置修改：
sudo systemctl restart frp-ssh-guard.service
sudo frp-ssh-guard status

sudo frp-ssh-guard disable
sudo apt remove frp-ssh-guard  # 保留配置和状态
sudo apt purge frp-ssh-guard   # 同时删除配置、状态和日志
```

如果已安装此前的 v1.1.0 或 1.0.x 软件包，请执行
`sudo apt install --allow-downgrades ./frp-ssh-guard_0.0.4_all.deb`，
切换到修正后的公开版本编号，并保留现有设置。

升级不会自动重启服务。原有 `guard.conf`/`ports.conf` 部署在迁移前仍可使用，
不会被空的新配置文件覆盖。详细操作见[迁移说明](docs/MIGRATING.md)（英文）。
`settings.conf` 由维护脚本创建并保留，不会在升级时被替换；新版本默认示例随软件包文档提供。

## 开源与源码构建

项目所有运行代码均为可阅读的 Bash/Python，并采用 **MIT 许可证**。
仓库和源码压缩包包含打包文件、构建脚本、示例、文档及测试。
没有闭源版本，也不依赖项目提供的在线服务。系统依赖保留各自的许可证。

```bash
# 在解压后的源码目录中，以普通用户执行：
make test
make release  # dist/ 下生成 .deb 和 SHA256SUMS
make dist     # 可选：导出本地源码 tar.gz/zip
```

构建需要 Bash、Python 3、GNU Make 和 `dpkg-deb`。
GitHub 源码下载包含发布标签所对应的仓库文件。可选的 `make dist` 本地导出使用明确的文件清单，
排除真实配置、IP 名单、日志、凭据和原始部署备份。
发布流程见[发布说明](docs/RELEASING.md)（英文）。

如需从源码部署（推荐使用软件包）：

```bash
sudo apt install nftables python3 jq iproute2 util-linux gawk
sudo ./install.sh --ports 22001,22003
# 可选：--exclude 22002 --prefix /opt/my-guard
sudo env GUARD_DIR=/opt/frp-ssh-guard /opt/frp-ssh-guard/bin/frp-ssh-guard status
```

源码安装会激活防护，默认路径是 `/opt/frp-ssh-guard`。
不要同时安装源码版与 Debian 软件包版。重复安装保留设置；明确提供的安装参数会更新对应字段。

## 贡献、安全与许可证

开发和测试参见 [CONTRIBUTING.md](CONTRIBUTING.md)，漏洞报告参见
[SECURITY.md](SECURITY.md)，实现细节参见[架构说明](docs/ARCHITECTURE.md)。
提交示例时使用测试地址，不要提交生产配置或认证日志。

[MIT 许可证](LICENSE)允许使用、修改及再分发，但须保留版权和许可声明。
软件不提供担保，完整条款以许可证文件为准。

[返回 English](#frp-ssh-guard)

</details>
