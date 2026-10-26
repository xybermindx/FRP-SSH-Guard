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

显式 reload 会重建防护表，清空临时自动封禁和速率计数。手动名单保留，
限时手动封禁保持原到期时间。安装软件包及更新名单会保留当前自动封禁和定时任务。

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
sudo apt install ./frp-ssh-guard_0.0.5-3.deb
dpkg-query -W frp-ssh-guard
sudo frp-ssh-guard status
```

安装器补齐缺失的默认参数与注释，修改前在旁边保存私密的
`settings.conf.before-upgrade-*` 备份。现有值、已接受策略、待应用修改、当前封禁及
定时任务触发时间均保留。新开关默认 off，配置完整时重复安装不会更改文件。
首次从 v0.0.4 升级时，旧版本卸载钩子可能重算自定义 `OnActiveSec` 触发时间，
详见[迁移说明](MIGRATING.md)（英文）。
