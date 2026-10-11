# ADR-0011：本机应急开关 `force_monitor`，签名配置包放宽规则的唯一例外

- 状态：已接受
- 日期：2026-10-12（依据 [Phase 2 实现规格](../impl/phase2-spec.md) D-60、[§9.6](../impl/phase2-spec.md#96-本机应急开关d-60)）
- 相关：[10 §5.2](../10-threat-model.md#52-所有者被锁定)、[01 §8](../01-architecture.md#8-部署与高可用)、[02 §6](../02-data-flow.md#6-配置模型与密钥下发)、[ADR-0010](0010-single-owner-model.md)

## 背景

- 设计规则：任何放宽都只能经所有者签名的配置包下发，吊销与通知只会收紧（[02 §6](../02-data-flow.md#6-配置模型与密钥下发)）。配置签名私钥在所有者工作站上，以 age 加密；Phase 3 之前没有控制面与 Console（[ADR-0010](0010-single-owner-model.md)）。
- Phase 2 让 enforce 更容易误伤：路由可以要求持有证明（`proof: required`）与交互级凭证（`min_level`），SDK 与站点模板的接入也可能出错。站点自 Phase 1 起只有 monitor 运行的经验。
- 所有者离开签名工作站时（出差、只有手机与 SSH），无法签发一个 monitor 配置包止损。威胁模型 v0.9 把"Edge 主机上的本地应急开关"列为待定的提议，并要求在 ADR 中写明它是例外（[10 §5.2](../10-threat-model.md#52-所有者被锁定)）。
- 能改 Edge 主机上 `edge.toml` 的人已经拥有 root：他也能替换二进制、读取凭证密钥（10 H2）。所以一个只在本机生效的放宽开关，不扩大主机失陷时的影响面。

## 决策

1. **开关**：`edge.toml` `[[sites]] force_monitor = true`（缺省 `false`）。它是主机本地配置，不在配置包中，签名配置包也无法打开或关闭它。
2. **效果**：
   - 该站点的有效模式为 monitor，覆盖配置包的 `monitor_only = false` 与路由级的 `mode: enforce`（I-36）。
   - 所有路由都是 monitor，所以 I-36 的"monitor 站点有 enforce 路由时超限请求仍拒绝"不适用，超限请求按 monitor 原样转发。
   - 路由选择之前的处理（协议上限、外部 Worker 等）按站点级 monitor 执行。
   - `/__mg/*` 端点照常工作，访客仍可完成挑战、取得凭证。
   - `/__mg/r` 的重新决策在有效 monitor 下只记录，照常刷新。
3. **可见性**：
   - 每次加载打一条 WARN 日志，生效期间每小时再打一条；
   - 仪表 `mg_site_forced_monitor{site} = 1`，持续超过 1 小时告警（`deploy/vmalert/mg-phase2.rules.yml`，或 `scripts/mg-daily-check.sh`）；
   - `mg-edge --check-config` 把它计入警告数，不阻止启动；
   - 决定事件中 `monitor_only = true`，并带顶层字段 `forced_monitor: true`。
4. **操作**（[规格 §19](../impl/phase2-spec.md#19-所有者运维手册代码之外) 第 10 步）：
   1. `sudoedit /etc/morphgate/edge.toml`，在该站点的 `[[sites]]` 下设 `force_monitor = true`；
   2. `sudo systemctl reload mg-edge`（`ExecReload` 先运行 `--check-config`，失败则旧进程继续服务）；
   3. 确认 `mg_site_forced_monitor{site="<site>"} = 1`；
   4. 回到签名工作站后，签发并部署一个 monitor 配置包；
   5. 撤销 `force_monitor`，再次 reload。
5. **不做**：
   - 不提供"强制放行"或"关闭某条规则"的本地开关，只有整站 monitor：monitor 照常求值并记录，事后可以复盘；
   - 不提供远程开关（HTTP 端点、Valkey 键）：远程开关本身会成为攻击面；
   - 不写单独的本地审计文件：WARN 日志（journald 命名空间 `morphgate`，14 天）、指标与决定事件已经记录开关的生效时段。提议原稿中的"写本地审计"由这三者代替。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| 只靠签名的 monitor 配置包 | 需要签名工作站；所有者不在工作站旁时无法止损 |
| 把配置签名私钥也放到 Edge 主机上 | Edge 失陷即可签发任意配置，削弱 CP-04 的隔离；应急只需要放宽，不需要签名能力 |
| 控制面或 Console 中的紧急停止 | Phase 3 才有；控制面不可用时同样需要不依赖它的通道（10 CON-06） |
| 远程开关（`/__mg/` 下的管理端点、Valkey 中的标志键） | 新的认证面与攻击面；Edge 的 ACL 本来就不能写配置类键 |
| 本地的"全部放行"开关 | monitor 已经放行并保留记录；完全绕过决策会失去事件，无法定位误伤原因 |
| 环境变量或命令行参数 | 要改 systemd 单元，比改 `edge.toml` 更容易出错；`ExecReload` 的配置检查也覆盖不到 |

## 后果

- 有 root 的人可以在不签名的情况下把站点放宽为 monitor。这不扩大主机失陷的影响面（他本来就能做更多），但会让一次遗忘变成长期的放宽：告警（持续超过 1 小时）与每小时的 WARN 日志用来防止遗忘。
- 开关只作用于本机。多台 Edge 时，每台都要分别设置；单机形态只有一台。
- 回滚 Edge 二进制到 Phase 1 之前，先删掉 `force_monitor` 与其他 Phase 2 键：Phase 1 的二进制拒绝未知键（[规格 §10.1](../impl/phase2-spec.md#101-edgetoml-新键wp-e2ae2c)）。
- 威胁模型 10 §5.2 的"本地应急开关"由待定改为已实现。
