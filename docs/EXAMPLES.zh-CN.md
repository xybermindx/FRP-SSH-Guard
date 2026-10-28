# 配置及命令示例

[English](EXAMPLES.md) | **简体中文** | [项目指南](../README.zh-CN.md)

以下端口为虚构示例，地址来自文档专用网段。请在本机替换为自己的选择，
不要公开实际部署配置或日志。以下片段只用于修改对应参数，不替换整个配置文件。

## 查找并编辑配置

```bash
frp-ssh-guard --help
frp-ssh-guard --version
dpkg-query -W frp-ssh-guard
```

打开 `Settings:` 后显示的文件。普通 sudo 安装使用调用者的
`~/.frp-ssh-guard/settings.conf`；直接 root 安装使用 root 家目录。
升级保留原先选定的用户。配置选在家目录后，不要改动 `applied.conf`
或旧的系统配置副本来代替当前配置。

## 选择一种防护方式

### 只保护 FRP 转发的 SSH

```ini
PROTECTED_PORTS="22001,22003"
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=off
JAIL_PER_PORT=off
SSH_SLOW_PROTECTION=on
```

先确保 `frps` 已监听这些转发端口。封禁共享所有已选端口，服务器自身的
22 端口不在此选择范围内。开启慢速防护时，同一来源 24 小时内在两个端口合计
超过 300 次新连接会被封禁；白名单中的管理员从不计数。

### 只保护服务器自身的 SSH 22 端口

```ini
PROTECTED_PORTS=""
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=off
SSH_SLOW_PROTECTION=on
```

SSH 开关会自动加入 22 端口、应用连接限制并启动本机 sshd 失败检测。
要求本机 SSH 正在监听，且 journald 中能读取到 sshd 记录。不收集尝试的密码。
慢速防护在 24 小时内 20 次失败登录后封禁来源。

### 同时保护 FRP 和本机 SSH，各端口独立封禁

```ini
PROTECTED_PORTS="22001,22003"
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=on
SSH_SLOW_PROTECTION=on
```

端口 `22001` 触发的自动封禁仅影响该端口，本机认证触发的封禁仅影响 22。
若希望所有已选端口共享封禁，设为 `JAIL_PER_PORT=off`。
该开关控制封禁范围；两种模式均有每端口连接速率限制。
此模式下慢速防护按每个转发端口单独统计（24 小时内超过 100 次新连接只封禁该端口）。

### 慢速暴力破解阈值

```ini
SSH_SLOW_PROTECTION=on           # off：不做慢速检测，也不做慢速封禁
SSH_SLOW_TOTAL_CONNECTIONS=300   # JAIL_PER_PORT=off：每来源，所有转发端口合计
SSH_SLOW_PORT_CONNECTIONS=100    # JAIL_PER_PORT=on：每来源，单个转发端口
SSH_SLOW_FAILURES=20             # PROTECT_SERVER_SSH=on 时 22 端口的失败登录
SSH_SLOW_WINDOW=24h
```

隧道隐藏了登录结果，因此转发端口统计的是连接次数。经常访问许多转发主机的管理员
请加入 `whitelist.conf`（任意端口分节）；名单中的地址从不计数。每次封禁及其原因
都会写入 `~/.frp-ssh-guard/frp-ssh-guard.log`。

## 应用并验证配置

防护已经运行时执行：

```bash
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard status
sudo frp-ssh-guard ports
```

首次启用或 `disable` 之后，用 `enable` 代替 `reload`。仅保存文件不会生效：
`check` 只做验证，`reload` 接受并应用，之后 `status` 显示 `Pending edits: no`。
重启也只恢复已接受的策略，不会应用待确认的修改。名单文件不同：保存
`whitelist.conf` 或 `blocklist.conf` 后自动生效。启用本机 SSH 防护后，状态应显示
`Server SSH protection: on`。

显式 reload 会重建防护表和速率计数；已保存的封禁及学习条目保留原到期时间。
突然重启可能丢失尚未采样的内核封禁。安装软件包及更新名单会保留当前自动封禁和定时任务。

## 手动白名单与黑名单

```bash
# 只在指定受保护端口信任这个来源。
sudo frp-ssh-guard allow 198.51.100.10 22001

# 在所有受保护端口永久封禁（不指定时长即为永久）。
sudo frp-ssh-guard block 203.0.113.20
sudo frp-ssh-guard block 203.0.113.0/24 --all --forever

# 永久封禁，但只针对一个受保护端口。
sudo frp-ssh-guard block 203.0.113.22 --ports 22001

# 改为临时封禁（默认 BAN_TIMEOUT，或指定时长）。
sudo frp-ssh-guard ban 203.0.113.23 12h

# 在两个受保护端口封禁六小时，两种 jail 模式都适用。
sudo frp-ssh-guard block 203.0.113.21 --ports 22001,22003 --for 6h

# 查看并删除手动封禁。
sudo frp-ssh-guard blocklist
sudo frp-ssh-guard unblock 203.0.113.21

# 查看临时封禁；release 同时移除手动封禁和累犯记录。
sudo frp-ssh-guard banned
sudo frp-ssh-guard release 203.0.113.20
```

`--all` 指所有**受保护**端口，不是机器上的全部端口。未指定时长时，手动封禁为永久。
限时封禁存储绝对到期时间，reload 和重启不会延长它。也可以直接编辑已选家目录内的
名单文件，防护运行时会监听变更。白名单和已建立连接仍优先于本工具的封禁规则。
Fail2ban 及其他防火墙相互独立；在那里被封禁的地址也需要在那里解除。

## 升级时不重载策略

```bash
sudo apt install ./frp-ssh-guard_0.0.7.deb
dpkg-query -W frp-ssh-guard
sudo frp-ssh-guard status
```

安装器补齐缺失的默认参数与注释，修改前在旁边保存私密的
`settings.conf.before-upgrade-*` 备份。现有值、已接受策略、待应用修改、当前封禁及
定时任务触发时间均保留。本机 SSH 防护和按端口封禁默认 off。`SSH_SLOW_MODE=enforce`
转换为 `SSH_SLOW_PROTECTION=on`；`observe`、`off` 或缺失则转换为 `off`。
`ALERT_LOG_MAX_SIZE` 更名为 `LOG_MAX_SIZE`。配置完整时重复安装不会更改文件。
首次从 v0.0.4 升级时，旧版本卸载钩子可能重算自定义 `OnActiveSec` 触发时间，
详见[迁移说明](MIGRATING.md)（英文）。

## 合并名单

`~/.frp-ssh-guard/whitelist.conf` 和 `blocklist.conf` 都支持以下格式：

```ini
# 所有受保护端口，包含已开启防护的本机 SSH。
[all]
198.51.100.10

# 仅本机 SSH 22 端口（需开启防护）。
[22]
203.0.113.10

# 仅此选定的 FRP 端口。
[22001]
2001:db8::10
```

在白名单中表示允许，在黑名单中表示封禁。纯 IP 条目是永久手动条目。
自动条目在同一文件内显示，白名单标记 `source=learned`，黑名单标记
`source=runtime` 或 `source=strike`，并带 `until=YYYY-MM-DDTHH:MM:SSZ`。
请保留绝对到期时间；apply 和重启不延长它。删除条目即可移除，新的登录/攻击可能重新添加；
`unban` 还会豁免累犯历史。手动条目也支持 CIDR 网段。

防护运行时会监听名单保存；也可立即执行：

```bash
sudo frp-ssh-guard apply
sudo frp-ssh-guard whitelist
sudo frp-ssh-guard blocklist
```

管理员学习默认开启（`LEARN_ADMINS=on`）：root、设置所有者或 `sudo`、`admin`、`wheel`
组成员成功登录本机后，来源会以 `source=learned` 加入 `[all]`。若还要信任其他账户，设置
`LOGIN_USERS="alice|bob"`（虚构示例名），然后执行 `check` 和 `reload`。FRP 后端主机的登录无法学习信任。学习的 `[all]` 条目覆盖所有受保护端口，
`[22001]` 白名单不覆盖 22。其他防火墙（包括 Fail2ban）规则仍独立生效。

### 封禁时长

```ini
[all]
198.51.100.19                             # 不写时间：永久
198.51.100.20 forever                     # 永久，显式写出
198.51.100.21 tier=1                      # BAN_TIMEOUT（默认 12 小时）
198.51.100.22 until=2030-01-31T00:00:00Z  # 到此 UTC 时间为止
[22]
203.0.113.20 tier=2                       # 3 天
[22001]
203.0.113.21 tier=5                       # 90 天
```

在 `blocklist.conf` 中，不写时间的条目和 `forever` 都表示永久。文件中不接受 `7d`
这类直接时长（请使用 `tier=`、`until=` 或 `block IP --for 7d`），错误信息会指出行号。默认 1–5 档为 12 小时、3 天、7 天、30 天、90 天。
第 1 档使用 `BAN_TIMEOUT`；第 2–5 档使用 `STRIKE_LADDER` 中相应次数对应的时长，
并受 `STRIKE_MAX` 限制。自定义 ladder 缺少某档时会拒绝该档。
这些是手动时长选择，不会改变自动累犯计数。首次应用写入 `until=`；重复 apply、升级和重启
保留原到期时间。需要重新开始某档时长时，请删除旧的 `until=`。

## 本地观察记录（自 v0.0.6 起）

已运行的守卫升级后会自动启动新版监控，无需手动 reload；首次启用使用 `enable`。
安装会补齐缺失设置，保留自定义值、已接受的防火墙策略、原封禁到期时间和定时器截止时间。

短窗口仍为 10 分钟内 5 次失败或 3 个无效用户连接。自 v0.0.7 起慢速检测由
`SSH_SLOW_PROTECTION` 开关控制，见[慢速暴力破解阈值](#慢速暴力破解阈值)。
成功登录清空短窗口失败，长窗口失败按时间自然过期。

`~/.frp-ssh-guard/frp-ssh-guard.log`（原 `alerts.log`）每行一个事件，最新在前：
封禁及其原因和结束时间、手动封禁、累犯升级、解除封禁、已接受的设置、此前不受信任
来源的成功登录和疑似子网群集。新来源登录是复核信号，不代表已被入侵。内容包括 UTC
时间、来源、端口、原因、适用时的认证方式和计数，不保存账户名、密码或原始日志。
默认上限 10MiB，超限删除最旧完整行，不轮转、不留档。修改 `LOG_MAX_SIZE` 后执行
check/reload 可按新上限裁剪；status 和 report 显示上限。这些文件属于本地私密部署数据，请勿提交或分享。家目录不可用时使用
相同上限的私密系统暂存文件，恢复访问后合并。

管理员学习默认开启（`LEARN_ADMINS`），`LOGIN_USERS` 可添加其他账户。密码、公钥及 PAM
成功登录均可在完成来源分类后学习信任。信任针对已观察到的来源 IP，不会自动跟随动态地址；
被盗账户的成功登录也可能建立信任，请保留恢复访问方式。本工具不修改 sshd
认证设置或 Fail2ban 的防火墙规则。

```bash
sudo frp-ssh-guard doctor
sudo frp-ssh-guard report 24h
```

doctor 只读取本机 SSH 规则覆盖、监控状态、journal 访问、白名单覆盖及告警文件
访问情况。report 按事件时间筛选，并区分认证失败、观察阈值、新增自动封禁和
采样丢弃包。包数不是连接数，也不能证明成功防御。现有日志定时器保存包计数增量；
采样区间可能跨越报告边界，崩溃时可能丢失尚未采样的数据。reload 在替换表前保存
旧表计数。新长窗口从明确启用时开始，迁入近期旧短窗口记录但不虚构长期历史。
各观察表上限为 200,000 行，容量导致的数据丢失会在报告中显示。
子网报告按 jail 范围和 IPv4 /24、IPv6 /64 汇总不同自动封禁来源，手动或恢复的
封禁不计入，绝不自动封禁子网。
