# 设置参考

[English](SETTINGS.md)

`settings.conf` 由普通的 `KEY=value` 行组成，只作为数据读取，不执行 shell 命令。
大多数情况下只需设置 `PROTECTED_PORTS`。

保存文件不会产生任何变化。用以下命令接受修改：

```sh
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
```

首次使用时用 `enable` 代替 `reload`。接受后，`status` 显示 `Pending edits: no`。
重新加载会保留当前封禁，连接计数重新开始。`check` 或 `reload` 失败时，之前的设置继续生效。
`whitelist.conf` 和 `blocklist.conf` 不同：保存后立即生效。

时间为正整数加 `s`、`m`、`h`、`d` 或 `w`。除非另有说明，数量为 1 到 1000000 的整数。

## 常用设置

| 设置 | 默认值 | 含义 |
| --- | --- | --- |
| `PROTECTED_PORTS` | 空 | 转发 SSH 的 frps 公网端口，可写列表或范围。不要包含 frps 控制端口或网页端口。`22001:60:40` 可覆盖该端口的共享速率和突发值。 |
| `EXCLUDE_PORTS` | 空 | 在 `PROTECTED_PORTS` 中跳过的端口。 |
| `PROTECT_SERVER_SSH` | `off` | `on` 时加入本机 22 端口并监控其登录结果。 |
| `BAN_TIMEOUT` | `12h` | 首次封禁时长。如需永久封禁，请在 `blocklist.conf` 中写入不带时间的地址。 |
| `STRIKE_LADDER` | `2:3d 3:7d 4:30d 5:90d` | 按重复违规次数决定的封禁时长。到达最高一级后保持不变。留空则关闭。 |
| `JAIL_PER_PORT` | `off` | `off`：封禁覆盖所有受保护端口。`on`：只封禁被攻击的端口。修改只影响新的封禁。 |
| `SSH_SLOW_PROTECTION` | `on` | 检测低于每分钟阈值的攻击。`off` 时行为规则也停止。 |
| `SSH_SLOW_BEHAVIOR` | `on` | 启用 `SSH_BEHAVIOR_RULES`。需要 `SSH_SLOW_PROTECTION=on`。 |
| `SSH_BEHAVIOR_RULES` | `20b:30m 4p:2h 3p:6h 50c:12h` | 触发封禁的行为模式，见下文。 |
| `LEARN_ADMINS` | `on` | root、设置文件所有者，或 `sudo`、`admin`、`wheel` 组成员登录本机后，将其来源加入白名单。共用该公网地址的所有人也会被信任。 |
| `LEARN_USERS` | `on` | 来源在某转发端口上有过真实会话后，不再统计其在该端口的连接。 |
| `PER_IP_RATE`, `PER_IP_BURST` | `2`, `40` | 每个来源、每个端口每分钟的新连接数及允许的突发值。超过则封禁该来源。 |
| `GLOBAL_RATE`, `GLOBAL_BURST` | `30`, `20` | 每个端口所有来源合计的同类限制。超出部分被丢弃，不封禁任何来源。 |

## 行为规则

只判断从未完成登录的来源。白名单来源和已知用户会被跳过。

| 规则 | 封禁条件 | 封禁范围 |
| --- | --- | --- |
| `Nb:T` | T 内产生约 N 次新连接。 | 跟随 `JAIL_PER_PORT`。 |
| `Np:T` | 连续记录已持续 T，且最近 T 内触及 N 个不同端口。 | 所有端口。 |
| `Nc:T` | 连续记录已持续 T，且最近 T 内有 N 次连接。 | 跟随 `JAIL_PER_PORT`。 |

连续记录是指中间没有出现 `SSH_BEHAVIOR_PAUSE` 停顿的一段连接。

`Nb:T` 是突发限制，由防火墙在突发过程中直接执行，不需要连续记录。它一次允许 N 次连接，
之后按每 T 恢复 N 次，因此数量是近似值。取值范围：N 从 2 起，T 为 1m 到 6h，最多一条。
从列表中删除即可关闭。`Np:T` 和 `Nc:T` 的 T 为 15m 到 7d，`Np:T` 的 N 从 2 起。

请将监控探测、CI、备份任务和产生大量短连接的脚本加入白名单，因为这些短会话无法证明已登录。

## 高级设置

这些设置已有默认值。如需修改，删除该行开头的 `# `。

| 设置 | 默认值 | 含义 |
| --- | --- | --- |
| `SSH_AUTH_FAILURES` | `5` | `SSH_AUTH_WINDOW` 内本机登录失败多少次后封禁。 |
| `SSH_INVALID_USER_FAILURES` | `3` | `SSH_AUTH_WINDOW` 内尝试不存在账户的连接数达到多少后封禁。 |
| `SSH_AUTH_WINDOW` | `10m` | 上述两项限制的时间窗口。 |
| `SSH_SLOW_TOTAL_CONNECTIONS` | `300` | `SSH_SLOW_WINDOW` 内每个来源在所有转发端口的新连接数（共享封禁）。 |
| `SSH_SLOW_PORT_CONNECTIONS` | `100` | `SSH_SLOW_WINDOW` 内每个来源在单个端口的新连接数（按端口封禁）。 |
| `SSH_SLOW_FAILURES` | `20` | `SSH_SLOW_WINDOW` 内每个来源在 22 端口的登录失败次数。 |
| `SSH_SLOW_WINDOW` | `24h` | 上述三项限制的时间窗口。 |
| `SSH_BEHAVIOR_PAUSE` | `2h` | 让连续记录重新开始的停顿时长，30m 到 12h。 |
| `LOGIN_USERS` | 空 | 与 `LEARN_ADMINS` 一样可建立信任的额外账户，使用扩展正则表达式，例如 `alice\|bob`。 |
| `MAX_LEARNED` | `500` | 保留的学习地址上限，最旧的最先移除。 |
| `LEARN_TIMEOUT` | `90d` | 学习地址或已知用户的有效期。之后的登录会续期。 |
| `LEARN_SESSION_AGE` | `3m` | 连接保持这么久即证明已登录，3m 到 1d。请保持高于后端的 `LoginGraceTime`。 |
| `LEARN_SESSION_BYTES` | `32KiB` | 发送给客户端的数据超过此值即证明已登录，8KiB 到 100MiB。登录前横幅较长时请调高。 |
| `STRIKE_WINDOW` | `90d` | 在上次封禁结束后的这段时间内再次被封禁，`STRIKE_LADDER` 上升一级。 |
| `STRIKE_MAX` | `90d` | 升级封禁的最长时长。 |
| `LOG_MAX_SIZE` | `10MiB` | `frp-ssh-guard.log` 的大小，1KiB 到 100MiB。最旧的行会被删除。 |
| `SUBNET_REPORT_MIN_SOURCES` | `5` | 同一 /24 或 /64 内有多少来源被封禁时报告子网聚集。不会自动封禁子网。 |
| `SUBNET_REPORT_WINDOW` | `24h` | 该报告的时间窗口。 |
| `PORT_MIN`, `PORT_MAX` | `1`, `65535` | 受保护端口的允许范围。 |
| `EDIT_USER` | `root` | 拥有命令管理名单的本地账户。仅限可信账户。 |
| `GUARD_TABLE` | `frp_ssh_persistent_guard` | nftables 表名。修改方法：先 disable，编辑后再 enable。 |

## 将旧文件转换为此布局

升级会保留你的文件和注释。如需切换到简短布局：

```sh
sudo frp-ssh-guard tidy-settings
sudo frp-ssh-guard check && sudo frp-ssh-guard reload
```

所有修改过的值都会保留。你自己写的注释只保留在文件旁边的私有副本
`settings.conf.before-upgrade-*` 中。`tidy-settings` 不改变任何防火墙规则，也不转换旧版 `guard.conf`。
