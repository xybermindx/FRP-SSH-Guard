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
```

先确保 `frps` 已监听这些转发端口。封禁共享所有已选端口，服务器自身的
22 端口不在此选择范围内。

### 只保护服务器自身的 SSH 22 端口

```ini
PROTECTED_PORTS=""
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=off
```

SSH 开关会自动加入 22 端口、应用连接限制并启动本机 sshd 失败检测。
要求本机 SSH 正在监听，且 journald 中能读取到 sshd 记录。不收集尝试的密码。

### 同时保护 FRP 和本机 SSH，各端口独立封禁

```ini
PROTECTED_PORTS="22001,22003"
EXCLUDE_PORTS=""
PROTECT_SERVER_SSH=on
JAIL_PER_PORT=on
```

端口 `22001` 触发的自动封禁仅影响该端口，本机认证触发的封禁仅影响 22。
若希望所有已选端口共享封禁，设为 `JAIL_PER_PORT=off`。
该开关控制封禁范围；两种模式均有每端口连接速率限制。

## 应用并验证配置

防护已经运行时执行：

```bash
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard status
sudo frp-ssh-guard ports
```

首次启用时用 `enable` 代替 `reload`。仅保存文件不会生效，重启也只恢复
已接受的策略，不会应用待确认的修改。启用本机 SSH 防护后，状态应显示
`Server SSH protection: on`。

显式 reload 会重建防护表和速率计数；已保存的封禁及学习条目保留原到期时间。
突然重启可能丢失尚未采样的内核封禁。安装软件包及更新名单会保留当前自动封禁和定时任务。

## 手动白名单与黑名单

```bash
# 只在指定受保护端口信任这个来源。
sudo frp-ssh-guard allow 198.51.100.10 22001

# 在所有受保护端口永久封禁。
sudo frp-ssh-guard block 203.0.113.20 --all

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
sudo apt install ./frp-ssh-guard_0.0.5.deb
dpkg-query -W frp-ssh-guard
sudo frp-ssh-guard status
```

安装器补齐缺失的默认参数与注释，修改前在旁边保存私密的
`settings.conf.before-upgrade-*` 备份。现有值、已接受策略、待应用修改、当前封禁及
定时任务触发时间均保留。新开关默认 off，配置完整时重复安装不会更改文件。
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

自动学习需将 `LOGIN_USERS="alice|bob"` 改成自己的可信本机账户，然后执行 `check` 和 `reload`。
这里的名字仅为虚构示例。仅开启 22 端口防护不会启用学习。学习的 `[all]` 条目覆盖所有受保护端口，
`[22001]` 白名单不覆盖 22。其他防火墙（包括 Fail2ban）规则仍独立生效。

### 封禁时长

```ini
[all]
198.51.100.20 forever
198.51.100.21 tier=1
[22]
203.0.113.20 tier=2
[22001]
203.0.113.21 tier=5
```

在 `blocklist.conf` 中，`forever` 表示永久；默认 1–5 档为 6 小时、1 天、3 天、7 天、28 天。
第 1 档使用 `BAN_TIMEOUT`；第 2–5 档使用 `STRIKE_LADDER` 中相应次数对应的时长，
并受 `STRIKE_MAX` 限制。自定义 ladder 缺少某档时会拒绝该档。
这些是手动时长选择，不会改变自动累犯计数。首次应用写入 `until=`；重复 apply、升级和重启
保留原到期时间。需要重新开始某档时长时，请删除旧的 `until=`。
