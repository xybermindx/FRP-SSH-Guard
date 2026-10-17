# FRP SSH Guard

[English](README.md) | **简体中文**

为 FRP 服务端（`frps`）暴露的 SSH 服务提供连接速率防护。
将本工具安装在公网 Linux 服务器上，选择需要保护的转发 TCP 端口，
通过 nftables 限制重复连接尝试，并封禁异常来源。

**版本 1.1.0 · MIT 开源许可 · Bash 与 Python · 无闭源运行组件**

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

进入本仓库的 **Releases** 页面，选择已发布版本。1.1.0 的发布文件为：

| 文件 | 用途 |
| --- | --- |
| `frp-ssh-guard_1.1.0_all.deb` | 安装到目标 Debian/Ubuntu 主机。 |
| `frp-ssh-guard-1.1.0.tar.gz` | 完整项目源码、构建脚本、打包文件、文档和测试。 |
| `frp-ssh-guard-1.1.0-src.zip` | 相同源码的 ZIP 格式。 |
| `SHA256SUMS` | 校验下载文件。 |

`all` 表示软件包包含脚本，而非针对特定 CPU 编译的二进制程序；依赖包按主机架构安装。
校验和可检测文件变化或损坏，但不是发布者签名。如果尚无公开版本，可以按下文从源码构建。
生成发布文件不会自动公开发布 Release。

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
sudo apt install ./frp-ssh-guard_1.1.0_all.deb
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
make release  # dist/ 下生成 .deb、源码包和 SHA256SUMS
```

构建需要 Bash、Python 3、GNU Make 和 `dpkg-deb`。
源码发布使用明确的文件清单，排除真实配置、IP 名单、日志、凭据和原始部署备份。
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
