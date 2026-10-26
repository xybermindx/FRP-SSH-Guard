# FRP-SSH-Guard v0.0.5

Protect FRP-forwarded SSH ports and optionally the server's own SSH port 22,
with shared or per-port jails and configuration-preserving upgrades.

Application/tag: **v0.0.5**. Debian package: **0.0.5-3**.

[English guide](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/README.md) ·
[中文指南](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/README.zh-CN.md) ·
[Examples / 示例](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/docs/EXAMPLES.md) ·
[Migration instructions](https://github.com/nengwanx/FRP-SSH-Guard/blob/v0.0.5/docs/MIGRATING.md)

## What's new

- `PROTECT_SERVER_SSH=off`: opt in to port-22 connection limits and local sshd
  failure/invalid-user detection. Attempted passwords are never collected.
- `JAIL_PER_PORT=off`: shared bans by default; `on` isolates automatic bans per
  protected port. Both switches are beside port selection in the template.
- Installation creates/migrates `~/.frp-ssh-guard/`, retains the chosen owner and
  custom values, adds missing commented options, and saves private backups.
- Manual blocks support all selected ports or specific ports, with permanent
  bans by default or an explicit duration. Timed bans keep their original expiry.
- Upgrades and list updates preserve active jails and remaining ban lifetimes.
  Version commands and Debian revisions make package upgrades easier to verify.
- English/Chinese instructions and examples cover installation, configuration,
  native SSH activation, manual lists and migration.

## Install or upgrade

Download the `.deb` and `SHA256SUMS` from this release into the same directory:

```bash
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./frp-ssh-guard_0.0.5-3.deb
frp-ssh-guard --help
dpkg-query -W frp-ssh-guard
```

Installation does not enable protection or apply pending settings. Edit the file
shown after `Settings:`; set `PROTECT_SERVER_SSH=on` if desired, then run:

```bash
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
sudo frp-ssh-guard status
```

Use `enable` instead of `reload` for first activation. Saving alone does not apply
settings. Explicit reload clears temporary automatic bans; manual lists remain.
The first upgrade from v0.0.4 retains bans and configured timer intervals, but its
old removal hook can rebase a custom `OnActiveSec` deadline. Later v0.0.5 upgrades
avoid that manager reload. Older development packages numbered 1.0.x require the
documented version-correction/downgrade procedure.

## Validation and scope

Local checks: 73 tests passed, one privileged kernel test skipped; seven new
configuration-upgrade tests also passed as root in a disposable Debian 12 VM.
Actual FRP connections, local SSH failures, shared/per-port bans, manual expiry,
active upgrades, home configuration, package lifecycles and reboot restoration
were tested there. Source, history and artifacts pass private-data scans. The
release workflow also checks reproducibility, kernel rules and Debian/Ubuntu
package lifecycles before creating the draft.

ARM/32-bit and full Ubuntu FRP/systemd runtime have not been verified. Forwarded
SSH login results remain encrypted and unavailable to this guard. Fail2ban rules
and bans are independent. GitHub provides source ZIP/tar.gz downloads from the
tag; the uploaded assets are the `.deb` and its checksum file.

## 简体中文

v0.0.5 新增可选的服务器 SSH 22 端口防护、本机认证失败检测、共享或按端口独立封禁、
可限定端口和时长的手动黑名单，以及保留配置的升级流程。程序及标签版本为
**v0.0.5**，Debian 软件包版本为 **0.0.5-3**。

- `PROTECT_SERVER_SSH=off`：设为 `on` 启用本机 22 端口及 sshd 失败检测，不收集密码。
- `JAIL_PER_PORT=off`：默认共享封禁；设为 `on` 后自动封禁按端口隔离。
- 安装会创建/迁移 `~/.frp-ssh-guard/`，保留原用户和自定义值，补齐缺失参数及注释，
  修改前保存私密备份。升级与名单更新保留当前封禁、剩余时长和定时任务安排。
- 手动封禁默认永久，可选指定端口和时长；限时条目在 reload/重启后不延长到期时间。
- 已更新中英文说明与示例。使用上方命令安装，按 `--help` 显示的实际路径修改配置。
  保存后需明确执行 `check`、`reload`；首次启用用 `enable`。
- 显式 reload 会清空临时自动封禁，手动名单保留。从 v0.0.4 首次升级时，旧卸载钩子
  可能重算自定义 `OnActiveSec` 触发时间；1.0.x 旧开发版需按迁移说明修正版本编号。

本地测试通过 73 项，另跳过 1 项需特权的内核测试；新增 7 项配置升级测试还在
Debian 12 虚拟机内以 root 身份通过。已验证真实 FRP、SSH 失败、两种 jail、手动到期、
运行中升级、家目录配置、安装卸载及重启恢复。隐私检查覆盖源码、历史与构建产物；
发布流程另外检查可重复构建、内核规则及 Debian/Ubuntu 软件包生命周期。
ARM、32 位和完整 Ubuntu FRP/systemd 运行环境尚未验证。转发 SSH 的认证结果仍不可见，
Fail2ban 的规则和封禁相互独立。附件只包含 `.deb` 和校验文件，源码由 GitHub 标签下载提供。
