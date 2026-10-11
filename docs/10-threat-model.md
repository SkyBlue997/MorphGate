# 10 威胁模型（STRIDE v1）

**结论**：v0 对应 Phase 0（2026-09-27）；v0.9（2026-09-28）按 Phase 1 的代码更新了 §4 的状态列（写出对应的测试），补充 Phase 1 中发现的威胁（EDG-13、EDG-14、CH-14、SDK-08）、新增密钥（AS-K12、AS-K13）与残余风险（R-11、R-12），v1 在所有者完成 Phase 1 验收（[规格 §17–§18](impl/phase1-spec.md#18-验收映射)）后定稿。模型覆盖 [07](07-roadmap.md) 推荐的个人部署：Cloudflare → Tunnel → Edge → 源站，外加一台大脑 VM。当前最需要守住的五条：

**v1**（2026-10-12）对应 Phase 2 的代码（[Phase 2 实现规格](impl/phase2-spec.md)，D-xx 见其 [§0.3](impl/phase2-spec.md#03-决定与偏离)，I-xx 见[集成者裁决](impl/phase2-spec.md#集成者裁决优先于正文)）：为 Phase 2 的组件补 STRIDE（§4.12 近线 worker、§4.13 出站与 Turnstile siteverify，以及 §4.1–§4.8 中新增的 EDG-15..18、DC-10..11、CH-15..21、SDK-09..12、CP-10 与 NL-*、OUT-*），把 Phase 2 交付的条目改为已实现并写出测试，新增资产 AS-K14、AS-K15 与残余风险 R-13..R-16。Phase 1 的所有者验收仍在进行，v1 不等它定稿；验收中发现的问题按 §7 的"事件触发"增量修订。Phase 2 新增的最需要守住的一条：**交互式 Challenge 不是安全边界**：`self_hold` 的检查除服务端时间窗外都依赖客户端自报的数据（CH-15、R-13），所以交互级凭证的人类证据不高于 `pow`、刷新缺省关闭。

1. **上游头伪造**：源站被绕过 Cloudflare 直接访问，访问者自带 `CF-Connecting-IP`、`x-mg-cf-*` 等头（CF-01）。Tunnel 模式下 Edge 只监听回环、只信任回环对端；上游认证失败时删除全部已知上游头族。
2. **Challenge 与凭证重放、拼接、降级**（CH-01 至 CH-05）：这是 Phase 1–2 的核心验收项。
3. **密钥保管**（§2、CP-04）：凭证密钥、Challenge 密封根密钥、配置与审计锚点签名密钥、Cloudflare API Token、Tunnel 凭证。已定为本机加密的密钥文件：主机上以 systemd credentials 交付，工作站上的签名私钥用 age 加密，云 KMS 可选，不部署 OpenBao（[06 §8](06-policy-console-observability.md#8-平台自身安全)）；剩余风险在主机或工作站失陷（H2、H3）。
4. **误伤与所有者被锁定**（§5）：依靠全局 monitor 开关、回退类操作不加摩擦、不依赖 Console 的应急通道。
5. **Validation Lab 被误用于非自有目标**（LAB-01、LAB-02）：两层都在 Phase 0 脚手架中：工具层白名单（`lab/internal/guard`）与 [07](07-roadmap.md) 要求的网络出口隔离（compose `lab` profile 的 `internal` 网络），由 `make lab-egress-check` 在 CI 中验证。

本文只写防御设计；威胁只点名，不展开攻击方法。

**状态口径**

| 状态 | 含义 |
|---|---|
| 设计已覆盖 | 设计文档已给出明确做法，属于该组件交付的一部分，不单独排期 |
| Phase N 实现 | 在 [07](07-roadmap.md) 的 Phase N 交付并验收；Phase 0 表示本阶段的仓库脚手架已包含该控制 |
| 待定 | 尚无确定方案，或需要所有者确认；在后续 ADR 或复审中决定 |

## 1. 范围与假设

**结论**：模型只覆盖"一个所有者、几个自有网站、Cloudflare 在前"的部署。Cloudflare 本身、源站应用自身的漏洞和 L3/L4 容量型攻击不在范围内。

**部署前提**（依据 [01](01-architecture.md)「部署与高可用」、[ADR-0007](adr/0007-lean-deployment.md)、[ADR-0010](adr/0010-single-owner-model.md)）

| 项 | 前提 |
|---|---|
| 使用者 | 只有所有者本人（唯一管理员），可选一个只读账号；不对他人提供服务 |
| 受保护对象 | 所有者自有的几个网站，流量以浏览器为主；移动端不在 v0 范围 |
| 入口 | Cloudflare（Free / Pro）→ Cloudflare Tunnel（每台 Edge 主机一个 cloudflared 副本）→ mg-edge 监听 127.0.0.1 → 源站（可同机）。AOP（自有 CA）是备选入口 |
| 大脑 VM | Valkey（AOF everysec）、配置包静态位置（Phase 1–2）/ mg-control + PostgreSQL / SQLite（Phase 3 起）、VictoriaMetrics（13 个月）+ vmalert、VictoriaLogs `vl-main`（30 天）与 `vl-short`（7 天）、可选 Grafana；与 Edge 同区域 / 同 VPC（[01 §8](01-architecture.md#8-部署与高可用)） |
| 内网 | Edge 与大脑 VM 之间走 VPC 私网或 WireGuard；配置拉取用 mTLS 或 WireGuard |
| 客户端 | Web SDK 运行在访客浏览器中，属于不可信执行环境 |
| 外部服务 | Cloudflare API（审计、IP 段、Turnstile widget）、Turnstile siteverify（可选 Provider）、对象存储（备份与审计锚点） |

Phase 2 的部署补充：近线 worker `mg-nearline` 运行在 Valkey 所在主机（单机形态即 Edge 主机），只经回环或 unix socket 连接 Valkey；Edge 唯一的出站 HTTP 是可选的 Turnstile siteverify，在后台服务上运行；Web SDK v1 在访客浏览器中持有会话密钥（IndexedDB，不可导出），站点模板自己引用 `/__mg/s/mg.js`（不做 Edge 侧注入）。单机形态推荐本机 Valkey（D-38）。

**假设**

| 编号 | 假设 | 不成立时的影响 |
|---|---|---|
| H1 | Cloudflare 按其文档运行，本身未失陷 | 所有上游信号与源站保护失效，超出本模型 |
| H2 | 所有者的云账户、Cloudflare 账户启用强 MFA，主机 SSH 只用密钥并及时打补丁 | 主机或账户层面被接管，所有控制可被关闭 |
| H3 | 所有者工作站未被完全控制 | Phase 1–2 的配置签名私钥在工作站（age 加密），失陷即可签发任意配置；passkey 只保护 Console 登录；超出本模型保证范围 |
| H4 | 同一 Edge 主机上不运行不可信进程（Edge 信任回环对端） | 本机进程可冒充上游，见 CF-01 |
| H5 | 源站应用自身的漏洞由应用负责；MorphGate 不是 WAF | — |
| H6 | L3/L4 容量型攻击由 Cloudflare 吸收 | — |

**威胁主体**

| 主体 | 目标 | 相关章节 |
|---|---|---|
| 自动化客户端（A1–A4，见 [01](01-architecture.md)「威胁模型」） | 抓取、撞库、批量注册、洪泛、未授权 AI 爬取 | §4 各组件 |
| 针对平台本身的攻击者 | 窃取密钥、篡改策略、关闭防护、借平台泄露访客数据 | §2、§4.6–4.9 |
| 供应链 | 投毒依赖、篡改 CI 或 SDK 构建 | §4.11 |
| 所有者自身的失误 | 误配置、误伤、把自己锁在外面 | §5 |

**信任边界图**（TB 编号见 §3）

```
  Visitors / bots / scanners                          Owner workstation
  (browser runs Web SDK: TB8)                          (passkey, mgctl + age key)
          |                                                   |
          | HTTPS                                             |
==========|===== TB1: Internet -> Cloudflare =============    |
          v                                                   |
  +--------------------------------------+                    |
  | Cloudflare zone (Free / Pro)         |                    |
  |  TLS, cache rules, WAF skip          |                    |
  |  Transform Rule sets x-mg-cf-*       |                    |
  |  Turnstile (optional provider)       |                    |
  +------------------+-------------------+                    |
                     | tunnel (dialed out from Edge host)     |
========== TB2: Cloudflare -> Edge (Tunnel / AOP) ========    |
                     v                                        |
  +-------------------------------------------------+         |
  | Edge host (one cloudflared replica per host)    |         |
  |  cloudflared -> 127.0.0.1:8080 mg-edge          |         |
  |                  - Decision Core (in-process)   |         |
  |                  - /__mg/* endpoints            |         |
  |                  - metrics on 127.0.0.1:9901    |         |
  |                  - siteverify out (TB6)         |         |
  |  - - - TB3: Edge -> origin (loopback) - - - - - |         |
  |                  v                              |         |
  |             origin app on 127.0.0.1:8081        |         |
  +------------------+------------------------------+         |
                     |                                        |
========== TB4: Edge <-> brain (VPC / WireGuard) =========    |
                     v                                        |
  +-------------------------------------------------+         |
  | Brain VM                                        |         |
  |  Valkey               mg-control (Go)           |         |
  |  mg-nearline (Go, Phase 2: consumes mg:ev,      |         |
  |    writes mg:v:* through mg_verdict_put)        |         |
  |  PostgreSQL / SQLite  VictoriaMetrics           |         |
  |  VictoriaLogs x2      Grafana (optional)        |<--------+  TB5: owner -> control plane
  +---------+------------------------------+--------+
            |                              |
     TB6: Cloudflare API           TB7: backups, audit anchors
            v                              v
     api.cloudflare.com             object storage

  Separate:  TB9 registries / CI -> build artifacts;  TB10 Lab (isolated) -> allowlisted targets
```

## 2. 资产清单

**结论**：最敏感的是能"让 Edge 相信某件事"的密钥（凭证密钥、Challenge 密封根密钥、配置签名密钥、AOP CA 与 Agent mTLS CA）和能改 Cloudflare 侧配置的 API Token。凭证、密封、Turnstile、MessageMAC 密钥按站点；配置签名与审计锚点签名是所有者各一对；Phase 1 另有所有者级的假名化密钥与上游密钥头值（AS-K12、AS-K13）。全部以本机加密文件交付（systemd credentials；工作站上 age），不进配置包、不进仓库（[02 §6](02-data-flow.md#6-配置模型与密钥下发)、[06 §8](06-policy-console-observability.md#8-平台自身安全)）。

| 编号 | 资产 | 所在位置 | 关键属性 | 泄露 / 篡改后果 | 轮换与保护 |
|---|---|---|---|---|---|
| AS-K1 | 凭证密钥（PASETO v4.local，按 `kid`，按站点） | Edge 主机（systemd credential）；Edge 内存 | 机密性、完整性 | 可伪造该站点任意等级的访问凭证 | 30 天滚动轮换；有 TPM2 时绑定；配置包只含 `kid`（[04 §5](04-challenge-and-tokens.md#5-短期访问凭证)、[06 §8](06-policy-console-observability.md#8-平台自身安全)） |
| AS-K2 | Challenge 密封根密钥 `K_seal_root`（按站点）及派生的 `k_epoch`、`k_bind_epoch` | 根密钥：Edge 主机（systemd credential）；epoch 密钥：Edge 内存 | 机密性、完整性 | 根密钥泄露可伪造该站点的 Challenge 或绕开 cData 绑定；单个 epoch 密钥泄露只影响该 epoch，不暴露根密钥 | 根密钥年更或泄露时轮换；各 Edge 以 HKDF-SHA256（info `mg-seal-v1` / `mg-bind-v1` ‖ site ‖ epoch_no）确定性派生 epoch 密钥，24 小时一换，无需每日分发（[04 §4.1](04-challenge-and-tokens.md#41-密封-challenge-与验证顺序)、[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)）。Phase 1：`seal.root.json` 含 1–2 个根，轮换分 add / promote / retire 三步（D-30）；epoch 只在日界前后几秒到两分钟内接受相邻的一个（04 §4.1） |
| AS-K3 | 配置签名密钥（所有者一对 Ed25519，签 `SignedBundle` 与吊销消息） | Phase 1–2：所有者工作站，age 加密，由 mgctl 使用；Phase 3 起：大脑 VM 的 mg-control（systemd credential）；Edge 只有公钥 | 完整性 | 可向 Edge 下发任意策略或吊销，包括关闭防护 | 按 `kid` 年更；不放在 Edge 上；见 CP-04 |
| AS-K4 | Turnstile secret（每站点一个 widget） | Edge 主机（systemd credential，配置只写 `secret_ref`）；Edge 内存 | 机密性 | 可冒用本站 widget 做 siteverify；影响限于该站点。Phase 2（D-51）：secret 不用 `secret_ref`，放在 `edge.toml` `[[sites]] turnstile_keys` 引用的 `mg-turnstile-keys` 文件（`[当前, 上一个]`），由 `mgctl turnstile secret import`、`rotate`、`drop-previous` 管理；`Debug`、日志、事件从不含它 | 轮换期间 Edge 同时持有新旧 secret；`invalid-input-secret` 自动禁用该 Provider（[09](09-interactive-challenge.md)） |
| AS-K5 | Cloudflare API Token（`cf-audit`、`cf-turnstile`、可选 `cf-push`） | mgctl / mg-control 所在主机（systemd credential；工作站上 age 加密） | 机密性 | 写权限 token 泄露可修改 zone 配置、关闭源站保护 | 按用途拆分、最小权限；`cf-push` 默认不创建（[06 §8](06-policy-console-observability.md#8-平台自身安全)） |
| AS-K6 | Tunnel 凭证 | 每台 Edge 主机 | 机密性 | 可在他处运行该 tunnel 的 connector，截走部分流量 | 仅 root 可读，cloudflared 以非特权用户运行；主机失陷即轮换（[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） |
| AS-K7 | AOP 自有 CA 私钥（仅 AOP 模式） | 离线保存 | 机密性 | 可签发被 Edge 信任的客户端证书 | 不放在 Edge 或大脑 VM；Edge 只持有 CA 证书（[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） |
| AS-K8 | 审计锚点签名密钥（所有者一对，与 AS-K3 分开） | 同 AS-K3 | 完整性 | 可伪造每日锚点，掩盖审计篡改 | 每年轮换，保管方式同 AS-K3；锚点写入开启对象锁的对象存储（[06 §6](06-policy-console-observability.md#6-审计)） |
| AS-K9 | 可选 MessageMAC Cookie 密钥 `K_cf`（Pro 及以上，按站点） | Edge 主机（systemd credential）；Cloudflare 规则（字面量） | 机密性 | 可让 Cloudflare 侧跳过 SBFM / 限速 | 独立于其他密钥（[08 §2.9](08-upstream-and-cloudflare.md#29-可选hmac-cookie-跳过pro-及以上)） |
| AS-K10 | 所有者登录凭证（passkey、TOTP、离线恢复码）与 mgctl API Token | 所有者设备；控制面只存哈希 | 机密性 | 完全控制平台 | passkey 至少注册两个；TOTP 使用会通知；API Token 限定范围、必须过期 |
| AS-K11 | Agent mTLS 客户端证书 CA 私钥（仅 `direct_tls`） | 离线保存 | 机密性 | 可签发被 Edge 信任的 Agent 证书，冒充注册 Agent | 同 AS-K7：不放在 Edge 或大脑 VM，Edge 只持有 CA 证书；客户端证书短有效期；Cloudflare 之后不可用（[05 §3.3](05-ai-agent-policy.md#33-其他身份来源)、[06 §8](06-policy-console-observability.md#8-平台自身安全)） |
| AS-K12 | 所有者假名化密钥 `K_pseudo`（所有者一把，Phase 1 新增，D-06） | 工作站（age 加密）；Edge 主机（systemd credential）；Edge 内存 | 机密性 | 可由 Valkey 键与 `mg:ev` 的 `ipk` / `pfk` 反推访客 IP 与前缀 | 不进配置包；`mgctl keys gen-pseudo` 生成；轮换会让现有 verdict 键与限速键失效（[04 §6.3](04-challenge-and-tokens.md#63-限速)） |
| AS-K13 | 上游密钥头值 `x-mg-upstream-key`（1–2 个，Phase 1 新增） | 工作站（age 加密）；Edge 主机（systemd credential）；Cloudflare Transform Rule（静态值） | 机密性 | 同机源站的 SSRF 可冒充经 Cloudflare 到达的请求（CF-01） | `mgctl keys gen-upstream --rotate`，Edge 同时接受新旧两个值（[08 §2.1](08-upstream-and-cloudflare.md#21-源站保护)） |
| AS-K14 | 访客的会话私钥（Phase 2，D-45） | 访客浏览器：IndexedDB 中不可导出的 P-256 密钥；回退为 localStorage 中可导出的 JWK，或只在内存 | 机密性 | 在凭证有效期内以该访客身份签 `MG-Proof`、续期与刷新 | 没有有效凭证或满 7 天即换新；公钥随每个证明发送，`jkt` 只以 `K_pseudo` 的 HMAC 出现在 Valkey 键中；localStorage 回退时站点自身的 XSS 能读走私钥（R-16） |
| AS-K15 | 近线 worker 的 Valkey ACL 口令（`mg-nearline`，Phase 2） | Valkey 所在主机（`LoadCredentialEncrypted`） | 机密性 | 可直接写本站点的 verdict（只能抬高风险，但能压过检测器的结论）、读 `mg:ev` | ACL 只允许 `mg:ev` 与本站点的 `mg:v:<site>:*`，没有 pub/sub；按需轮换 |
| AS-D1 | Valkey 数据：已用 nonce、jti、Provider token 重放集合、吊销集、限速计数、实体 verdict、Stream | 大脑 VM | 完整性、可用性 | 篡改可放行恶意流量或误伤；丢失导致重放检查失效 | 私网 + ACL；AOF everysec；每晚 RDB 备份 |
| AS-D2 | 事件中的访客个人信息（IP、UA、会话 ID、国家 / 地区、交互遥测） | Edge 缓冲、VictoriaLogs（`vl-main` / `vl-short`）、访问记录归档、备份 | 机密性、合规 | PIPL 风险；访客被追踪 | 最小化、假名化、限期保留（见 EVT-04，[06 §7](06-policy-console-observability.md#7-隐私与合规)） |
| AS-D3 | 审计日志（哈希链 + 每日锚点） | Phase 1–2：mgctl 本地追加日志；Phase 3 起：PostgreSQL / SQLite；镜像 `vl-main`；锚点在对象存储 | 完整性 | 操作无法追溯 | 哈希链、签名锚点、对象锁；`mgctl audit verify` |
| AS-D4 | 策略与配置包（`SignedBundle`） | 分发位置（Phase 1–2 大脑 VM 静态位置，Phase 3 起 mg-control）、Edge 本地 last-known-good | 完整性 | 防护被静默改变 | 签名校验；见 EDG-04、CP-02、CP-03 |
| AS-D5 | Web SDK 构建产物 | Edge、Cloudflare 缓存、访客浏览器 | 完整性 | 在所有者页面上执行被篡改的代码 | 内容哈希路径、可复现构建并签名（见 SDK-01） |
| AS-D6 | 备份 | 对象存储 | 机密性、可用性 | 以上数据整体泄露或无法恢复 | 加密后写入；备份凭证与审计锚点凭证分开 |
| AS-D7 | Validation Lab 白名单与录制会话 | 仓库（白名单）、本地（录制） | 完整性、机密性 | 白名单被扩大后误伤他人；录制含所有者个人信息 | 见 §4.10 |

Phase 2 对资产表的补充：AS-D1 增加 `MG-Proof` 的 `mg:jti:*` / `mg:jc:*`（40 s / 60 s）、Turnstile token 重放集合 `mg:rp:*`（300 s）与近线写出的 verdict；AS-D2 增加交互遥测、刷新时的遥测与可选的行为摘要（`vl-short`，7 天），以及 `kind=refresh`、`kind=verdict` 事件（只有伪名键）；AS-D5 增加稳定别名 `/__mg/s/mg.js`（`max-age=300`），npm 包改为带 provenance 发布（D-63）。

## 3. 信任边界

**结论**：最关键的是 TB2（Cloudflare → Edge）：只有上游认证通过，Edge 才采信上游头。其余边界的共同原则是"只在私网上暴露、每个角色一个凭证、默认拒绝"。

| 编号 | 边界 | 跨越的数据 | 认证 / 控制 | 主要风险 |
|---|---|---|---|---|
| TB1 | 互联网 → Cloudflare | 全部访客请求 | Cloudflare TLS；Cache Rule、WAF Skip、Transform Rule（模板在 `adapters/cloudflare/`） | 请求内容一律不可信；Cloudflare 侧配置漂移（CF-04） |
| TB2 | Cloudflare → Edge | 请求 + `CF-Connecting-IP` + `x-mg-cf-*` + 地理头 | 首选 Tunnel：Edge 只监听 127.0.0.1、只信任回环对端；备选 AOP（zone-level / per-hostname，自有 CA）+ 云防火墙只放行 Cloudflare 网段；认证失败时删除全部已知上游头族（[08](08-upstream-and-cloudflare.md)、[ADR-0003](adr/0003-upstream-profile-cdn-first.md)、[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） | 上游头伪造（CF-01、CF-02） |
| TB3 | Edge → 源站 | 放行的请求 + `MG-*` 头 | 源站只监听回环（或只接受 Edge）；Edge 删除客户端带来的 `MG-*` 头（[02](02-data-flow.md)「Edge 与源站的约定」）；可选 `MG-Origin-Auth` HMAC 签名（I-38） | 绕过 Edge 直达源站；`MG-*` 伪造（EDG-02） |
| TB4 | Edge ↔ 大脑 VM | Valkey 操作、配置拉取、事件批量写入、指标抓取 | VPC 私网或 WireGuard；配置拉取走 mTLS 或 WireGuard；Valkey ACL；配置包签名 | 未授权访问 Valkey（VK-01）；配置被替换（CP-02） |
| TB5 | 所有者 → 控制面 / Console / mgctl | 策略、名单、密钥操作、调查查询 | Phase 1–2 只有工作站上的 mgctl（签名私钥 age 加密）；Phase 3 起 passkey 为主、TOTP 备用；敏感操作重新认证 + 输入确认 + 可选生效延迟；Console 不暴露公网（[06](06-policy-console-observability.md)「管理后台」） | 冒充所有者（CP-01、CON-01） |
| TB6 | MorphGate → 第三方 API | Cloudflare API 调用；siteverify（含访客 IP、token） | TLS 证书校验；最小权限 token；带截止时间的调用 | token / secret 泄露（CF-06、CF-11）；Provider 故障（CH-11） |
| TB7 | 大脑 VM → 对象存储 | 备份、审计锚点 | 加密；只写凭证；对象锁（云厂商支持时） | 备份泄露或被删除 |
| TB8 | 访客浏览器 ↔ Web SDK | SDK 代码、遥测、Challenge 提交、持有证明 | SDK 输出一律视为不可信输入；签名只证明持有密钥 | 信号伪造（SDK-02）、SDK 被篡改（SDK-01） |
| TB9 | 依赖源 / CI → 构建产物 | crates.io、Go 模块代理、npm 依赖；CI 产物 | 锁文件、版本固定、最小权限 CI | 供应链投毒（SC-01、SC-02） |
| TB10 | Validation Lab → 目标 | Lab 生成的测试流量 | 工具层白名单 + 网络出口隔离（[07](07-roadmap.md)） | 流量发往非自有目标（LAB-01） |

Phase 2 对信任边界的补充：
- TB4 增加近线 worker 与 Valkey 之间的连接（独立 ACL 用户，只经回环或 unix socket）。
- TB6 的 siteverify 只允许精确的 URL，不读代理环境变量，回环 mock 只在 `MG_EDGE_TEST_OUTBOUND=1` 时可用（OUT-01）。
- TB8 增加会话密钥签名的 `MG-Proof`、续期、刷新与 `/__mg/t` 报告：签名只证明"持有该密钥的客户端"，不证明是人，交互遥测的值除服务端时间窗外都是客户端自报（CH-15）。
- 新的 Cookie `__Host-mg_st` 是脚本可读的，只有时间与绑定标记；三个 MorphGate Cookie 在转发源站前删除（TB3，EDG-16）。

## 4. STRIDE 分组件

**结论**：Phase 0 已落地的控制集中在"默认安全的骨架"：Edge 强制回环监听、固定上游、删除客户端 `MG-*` 头、`/__mg/*` 自答响应不缓存；内核不读系统时钟且 CI 编译 wasm32；Lab 工具层白名单与限速；锁文件、Pingora 版本与生成代码的 CI 检查。其余控制随 Phase 1–3 交付，交付时把状态列改为已实现并注明验收用例。Phase 1 已交付的条目在状态列写出测试：Rust 为 `<crate>/tests/<file>.rs::<测试名>` 或源文件内单元测试的 `<file>::<测试名>`（同一文件的后续测试简写为 `::<测试名>`），Go 为包名与 `TestXxx`；各条的 Phase 1 细节写在缓解列末尾的"Phase 1："之后，以 [Phase 1 实现规格](impl/phase1-spec.md) 为准（D-xx 见其 §0.3，I-xx 见集成者裁决）。

类别：S 仿冒、T 篡改、R 抵赖、I 信息泄露、D 拒绝服务、E 权限提升。

v1 的口径：Phase 2 交付的条目在状态列写"Phase 2 实现"并写出测试（Go 的近线测试在 `control-plane/internal/nearline`，SDK 的测试在 `sdk/web/test/`）；缓解列末尾的"Phase 2："之后是实际做法，以 [Phase 2 实现规格](impl/phase2-spec.md) 为准。Lab 的 Phase 2 否定性场景随 WP-L2 交付，状态见 [phase2-status](impl/phase2-status.md)。

### 4.1 Edge（`edge/`，mg-edge，Pingora 0.9）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| EDG-01 | S | 客户端伪造来源 IP 类请求头（`X-Forwarded-For`、`True-Client-IP`、`X-Real-IP`，以及源站可能信任的 `Client-IP` 等） | 限速、IP 前缀绑定、信誉与地理判断失真；源站采信伪造的客户端 IP | 只在上游认证通过时采信 `CF-Connecting-IP`；永不使用 XFF[0]、`True-Client-IP`、`X-Real-IP`；认证失败时以 TCP 对端为客户端 IP（[08](08-upstream-and-cloudflare.md)、[01](01-architecture.md)「接入模式」）。Phase 1：头族按小写、`_` 换成 `-` 后匹配，转发前删除，另删 I-29 的 7 个客户端 IP 类头；`CF-Connecting-IP` 缺失、非法或重复即视为 IP 未知（D-23） | Phase 1 实现（`edge/tests/upstream_trust.rs::upstream_families_are_stripped_including_underscore_spellings`、`::i29_client_ip_rewrite_and_override_headers_never_reach_the_origin`；`edge-core/tests/upstream_cloudflare.rs::repeated_trusted_headers_are_invalid`） |
| EDG-02 | S | 客户端自带 `MG-*` 头，冒充 Edge 的判定结果 | 源站误信分数或已验证身份 | Edge 转发前删除客户端请求中的全部 `MG-*` 头，包括 CGI 类源站（PHP、WSGI、Rack）会映射到同一 `HTTP_MG_*` 变量的 `MG_*` 写法（`edge/src/headers.rs`）；客户端 IP 以 `MG-Client-IP` 与改写为单值的 `X-Forwarded-For` 告知源站（[02 §8](02-data-flow.md#8-edge-与源站的约定)）。Phase 1：`Connection` 列出 `MG-Client-IP` 等名字也删不掉 Edge 写入的头；源站响应中的 `MG-*` / `MG_*` 同样删除。Phase 1 之后（I-38）：同主机或同一容器网络里能直接连到源站的其他进程也能写 `MG-*` 头；站点设 `origin_keys` 后，Edge 对转发的请求和 `MG-*` 头做带时间戳的 HMAC 签名（`MG-Origin-Auth`），源站校验通过前不信任 `MG-*` 头（参考实现 `adapters/origin/`） | Phase 0 实现（删除）；Phase 1 实现（`edge/tests/upstream_trust.rs::edge_headers_survive_connection_listings_and_mg_headers_are_stripped_both_ways`）；I-38 实现（`edge/tests/upstream_trust.rs::origin_auth_header_signs_what_the_origin_receives`、`edge-core/tests/origin_auth_kat.rs`、`adapters/origin/test/`；`make lab-e2e`：Lab 源站用参考实现校验，Edge 转发的请求全部通过、绕过 Edge 的未签名与伪造请求 401），源站侧校验由所有者接入 |
| EDG-03 | T | 请求走私 / 解析歧义（cloudflared、Edge、源站对同一请求解读不同） | 绕过路由匹配与判定 | Pingora 0.9 加固了 request-target 与 HTTP/2 `:path` 解析，并默认剥离逐跳头；Pingora 固定 `=0.9.0`，升级单独排期并跑完整回归；协议异常（冲突的 `Content-Length` / `Transfer-Encoding` 等）直接阻断（[03](03-risk-scoring.md)、[ADR-0002](adr/0002-edge-pingora-boringssl.md)）。Phase 0：Cloudflare 规则按规范化路径匹配、默认却把原始路径转发给 Edge，`/__mg/` 的 Skip 与缓存 Bypass 规则因此也会作用于 `//__mg/x`、`/%5F%5Fmg/x`、`/a/../__mg/x` 等写法；Edge 对原始路径、RFC 3986 规范化与 Cloudflare 规范化三种形式任一落在 `/__mg` 下的请求都自行应答、从不转发源站（`edge/src/routes.rs`）。Phase 1：`Connection` 列出的 `Content-Length` / `Transfer-Encoding` 从不删除（删除会让请求体与连接失步，形成请求走私）；路由按多个路径视图匹配，方法不区分大小写，列出 GET 的路由同样接纳 HEAD（D-25）；URL 改写与方法覆盖类头见 EDG-14 | Phase 0 实现（`/__mg` 命名空间按规范化路径判定）；Phase 1 实现（`edge/tests/upstream_trust.rs::connection_listed_framing_headers_cannot_smuggle_a_request`、`edge/tests/routing.rs::golden_bundle_routes_every_login_spelling_to_the_critical_route`、`edge-core/tests/upstream_headers.rs::hop_by_hop_never_removes_the_message_framing`） |
| EDG-04 | T | 加载被篡改或未签名的策略 / 配置 | 防护被静默关闭 | Phase 0 的配置是本地 TOML，只含监听与上游地址、不含策略，启动前由 `mg-edge --check-config` 校验（systemd `ExecStartPre`）；Phase 1 起策略包由 mgctl 编译并签名，Edge 校验签名与 schema，失败保留 last-known-good（`proto/morphgate/v1/config.proto` 的 `SignedBundle`，[02](02-data-flow.md)）。Phase 1：配置包由所有者 Ed25519 签名（Edge 信任 `[trust] owner_keys`），版本单调递增；站点状态 `active` / `bootstrap` / `lkg_invalid`，LKG 无法使用时 503（`on_lkg_invalid = "open"` 可改为放行并记录，I-3）；`--check-config` 改在 `ExecReload` 里、发信号之前运行（I-41 起为第二行），不再用 `ExecStartPre`（否则 LKG 无法使用时 Edge 起不来，也就无法靠轮询恢复）；`mg_bundle_published_version` 与 `mg_config_version` 持续 10 分钟不一致即告警（D-21） | Phase 1 实现（`edge-core/tests/bundle_verify.rs::bad_signature_is_rejected`、`edge-core/tests/bundle_poll.rs::rejects_bad_candidates_and_keeps_current`、`edge/tests/bundle_load.rs::check_config_fails_on_an_unusable_lkg`、`edge/tests/shipped_configs.rs::reload_checks_the_configuration_first`） |
| EDG-05 | R | 无法说明某个请求为何被放行或挑战 | 误伤无法排查 | 每个请求带 `MG-Request-Id`；DecisionEvent 记录 `rule_id`、规则集与模型版本、reason code；失败页展示 request_id（[02](02-data-flow.md)、[03](03-risk-scoring.md)）。Phase 1：`request_id` 为 128 位随机数，写入 `MG-Request-Id`、挑战 / 阻断页与 decision、access、feedback 三类事件。Phase 2：`kind=refresh` 记录每次刷新的结果与拒绝原因；决定事件另有 `forced_monitor`、`proof_required` 与证明字段 | Phase 1 实现（`edge/tests/events_sink.rs::four_kinds_with_envelopes_sampling_and_redaction`） |
| EDG-06 | I | 响应泄露检测细节（reason code、分数、失败原因） | 帮助对手调试 | `MG-Reasons` 默认关闭且只发往源站；失败响应统一；阻断页通用（[02](02-data-flow.md)、[04](04-challenge-and-tokens.md)）。Phase 1：`origin_headers.reasons` 缺省关闭；reason code 只进事件 | 设计已覆盖；Phase 1 实现（`edge/tests/challenge_flow.rs::submission_failures`） |
| EDG-07 | I | 指标端口暴露到公网 | 泄露流量与策略信息 | `metrics_listen` 默认 `127.0.0.1:9901`；生产只绑定私网 / WireGuard 地址供大脑 VM 抓取；配置校验拒绝通配地址（`0.0.0.0`、`::`）与公网地址，只接受回环、RFC 1918、ULA 与 100.64.0.0/10（`edge/src/config.rs`）；指标标签不含 IP、会话等个人信息（[06](06-policy-console-observability.md)「日志、指标与告警」）。Phase 1：`[events]` 中 `http://` 的 VictoriaLogs 地址同样只接受回环 / 私网 IP 字面量（I-11） | Phase 0 实现（回环默认值与地址校验）；Phase 1 实现（事件出口地址） |
| EDG-08 | D | 应用层洪泛、慢速连接耗尽 Edge 资源 | 站点不可用 | 容量型攻击由 Cloudflare 吸收；Pingora 0.9 默认的 HTTP/2 服务端上限；本地令牌桶 + Valkey GCRA；超时与请求体上限（[04](04-challenge-and-tokens.md)「限速」）。Phase 1：协议输入上限（414 / 431 / 400）只在 enforce 下拒绝，monitor 与 bootstrap 下原样转发、不求值（I-2）；在请求体读完之前应答时关闭连接，不替攻击者读完请求体；`/__mg/c` 正文须 5 s 内读完。Phase 2：新端点 `/__mg/c/renew`、`/__mg/r`、`/__mg/t` 各有进程内两级限速（`mg.c.renew`、`mg.r`、`mg.t`，D-67），在请求体读完之前应答时同样关闭连接 | Phase 1 实现（`edge/tests/protocol_limits.rs::enforce_rejects_every_cap`、`::early_rejection_closes_without_reading_the_body`、`edge/tests/ratelimit_valkey.rs::one_round_trip_per_request_and_shared_buckets`） |
| EDG-09 | D | 大脑 VM / Valkey 不可用 | 限速与重放检查失效 | 按降级表处理：本地计数、last-known-good；重放存储不可用时 `critical` 路由 fail-closed（不签发凭证，统一"稍后再试"），其余路由放行并标记、不发交互式 Challenge；单台 Edge 且 `local_replay_authoritative` 时本地集合即为结论（[01 §8](01-architecture.md#8-部署与高可用)）。Phase 1：Valkey 往返失败或超时即改用进程内状态（GCRA 表；固定容量、从不逐出未过期 nonce 的重放集合），连续 5 次失败后熔断（1 s 起翻倍，至多 30 s）；重放存储不可用时 C 所属路由 `fail_closed` → 429，其余签发带 `ruc` 的凭证，`fail_closed` 路由不接受（D-35、I-30，见 CH-14） | Phase 1 实现（`edge/tests/challenge_flow.rs::valkey_down_replay_unavailable`、`::full_local_replay_set`、`edge/tests/ratelimit_valkey.rs::outage_falls_back_to_local_and_recovers`、`edge-core/tests/state_service.rs::blackhole_fallback_breaker_doubling_and_recovery`） |
| EDG-10 | E | 解析器缺陷导致崩溃或代码执行 | 取得 Edge 主机权限、窃取 AS-K1、AS-K2、AS-K4 | Rust；依赖最小化；每个解析器（头、Cookie、C、提交体、配置包、工件、密钥文件、IR）都有确定性随机输入测试：固定种子 xorshift ≥ 10,000 个输入，断言返回错误而不是 panic（规格 §2.4）；systemd 以专用非特权用户运行，`NoNewPrivileges`、空能力集、`ProtectSystem=strict`、系统调用过滤等沙箱选项（`deploy/systemd/mg-edge.service`，[06](06-policy-console-observability.md)「平台自身安全」）。Phase 2：新的不可信输入解析器（JWK、`MG-Proof`、v2 提交、续期、交互遥测、`/__mg/t` 报告、siteverify 响应、`mg-turnstile-keys`）都有固定种子的随机输入测试与 cargo-fuzz 目标（`mg_proof`、`submission_v2`、`renew`、`ix_telemetry`、`refresh`、`telemetry`、`siteverify_response`、`turnstile_keys`，共 16 个）；Go 的 `mg:ev` v2 解析器有固定种子的随机输入测试 | Phase 0 实现（systemd 示例）；Phase 1 实现（随机输入测试：`edge-core/tests/{upstream,request,bundle,state}_fuzz.rs`、`challenge/tests/fuzz.rs`、`intel/tests/fuzz.rs`、JA4 预研的 ClientHello 解析器 `edge/src/tls/ja4.rs::tests::random_inputs_never_panic`，Lab 场景解析 `lab/internal/replay` 的 `TestRandomScenariosDoNotPanic`）；覆盖率引导的 cargo-fuzz：`fuzz/` 下 8 个目标（Cloudflare 头、请求限制与主机解析、配置包验签、密封 Challenge、凭证与 Cookie、路径视图与 `ret`、ClientHello / JA4、Challenge 提交），除不 panic 外还检查解析结果的不变式，`.github/workflows/fuzz.yml` 每天和改动解析器的 PR 上运行，`make fuzz` 本地运行；Phase 2 实现（`challenge/tests/fuzz_phase2.rs`、`edge-core/tests/events_telemetry_v2.rs::random_inputs_never_panic`、`edge-core/tests/outbound_fuzz.rs`、Go `nearline` 的 `TestParseRandomNeverPanics`；cargo-fuzz 目标增加到 16 个） |
| EDG-11 | E | Edge 被当作开放代理，转发到任意上游 | 被滥用为跳板 | 上游固定为配置中的 `origin`，不依据 Host 或请求内容选择上游；配置校验拒绝指向自身监听地址的 `origin`（`edge/src/proxy.rs`、`edge/src/config.rs`）。Phase 1：每个站点的 `origin` 在 `edge.toml`，配置校验拒绝与任一监听器或 `metrics_listen` 相同的地址 | Phase 0 实现 |
| EDG-12 | T | 回源连接被多个访客复用，把连接当作状态键导致串扰 | 一个访客的状态被套到另一个访客 | 不以下游连接作为任何状态的键；`x-mg-cf-tls-random` 只以 `client_conn_key = hash(...)` 在内存与近线窗口中使用，不进事件（[02 §9](02-data-flow.md#9-采样与保留)）。Phase 1：`x-mg-cf-tls-random` 只校验格式，不进入任何结构、日志或事件；`client_conn_key` 在 Phase 2 的近线使用 | Phase 1 实现（`edge-core/tests/upstream_cloudflare.rs::tls_random_row`、`::debug_output_redacts_client_ip_and_tls_random`） |
| EDG-13 | I | 应用日志或 `Debug` 输出含客户端 IP、Cookie、C、凭证、上游密钥或 `x-mg-cf-tls-random`（例如 Pingora 在 debug 级别打印整个请求头） | 日志泄露凭证与个人信息 | 任何级别的日志与 `Debug` 输出都不写这些值（D-31）：Pingora 的 debug / trace 记录一律丢弃，握手错误中的对端 IP 被替换；需要关联时写 `request_id`；journald 保留期 ≤ 14 天（[规格 §9.11](impl/phase1-spec.md#911-事件wp-c4-实现wp-e1d-接线)、[§17](impl/phase1-spec.md#17-所有者运维手册代码之外)）。Phase 2：D-31 的清单增加 `MG-Proof` 原文、会话公钥 JWK 与 `jkt` 明文、提交签名、Turnstile token 与 secret、`/__mg/t` 与交互遥测的内容 | Phase 1 实现（`edge/tests/upstream_trust.rs::logs_never_contain_client_secrets_even_at_trace_level`、`edge/tests/logs.rs::logs_never_contain_client_secrets`、`edge-core/tests/events_logs.rs::failure_logs_never_contain_event_content`）；Phase 2 实现（`edge/tests/logs.rs::logs_never_contain_proofs_keys_or_signatures`、`::redacted_route_paths_stay_out_of_proxy_error_logs`、`challenge/tests/clearance_v2.rs::debug_hides_the_key_binding`） |
| EDG-14 | T | 客户端借源站信任的改写头（`X-Original-URL`、`X-HTTP-Method-Override` 等）或请求中的 `_method` 参数，让源站执行与 Edge 路由判定不同的路径或方法 | 绕过 `critical` 路由的挑战、限速与 `fail_closed` | 转发前删除 URL 改写与方法覆盖类头（I-29，[08 §1.2](08-upstream-and-cloudflare.md#12-信任规则)）；`_method` 参数 Edge 删不掉：源站不得对受保护路由启用方法覆盖（所有者运行手册）；敏感路由优先不限定 `methods` | Phase 1 实现（请求头：`edge/tests/upstream_trust.rs::i29_client_ip_rewrite_and_override_headers_never_reach_the_origin`）；`_method` 由源站负责 |
| EDG-15 | D | 任意路由上的 `MG-Proof` 都触发椭圆曲线验签，或单个客户端用大量有效证明写满 `jti` 存储 | CPU 放大；本地集合溢出后重放检查"不可用" | Phase 2（规格 [§6.7](impl/phase2-spec.md#67-mg-proof-校验d-40edge-接线见-91)、[§9.1–§9.2](impl/phase2-spec.md#92-jti-防重放)，R1 S-3、S-4）：便宜的检查在前（格式、凭证有 `cnf.jkt`、指纹、`htm`、`htu`、`iat`），验签最后，点校验并入验签；只在路由要求证明或配置包有规则读取 `identity.proof.*` 时校验（`reads_field`）；`jti` 只在证明通过后写入，每把密钥每 60 s 至多 600 条，超出只影响这把密钥；进程内 `jti` 集合不逐出，溢出按"不可用"计数 | Phase 2 实现（`edge/tests/proof_flow.rs::verification_only_when_needed`、`::per_key_jti_quota`、`challenge/tests/proof.rs::first_failure_wins`、`edge-core/tests/state_phase2.rs::local_jti_per_key_quota_and_overflow`） |
| EDG-16 | I | MorphGate 的凭证与状态 Cookie 随请求转发给源站 | 凭证进入源站日志与源站代码 | Phase 2（D-61）：`schema_version = 2` 时，转发前从每个 `Cookie` 头删除名称精确等于 `__Host-mg_clr`、`__Host-mg_st`、`__Host-mg_a11y` 的 cookie 对，其余字节与顺序不变；`MG-Proof` 属于 `mg-` 头族，从不转发 | Phase 2 实现（`edge/tests/proof_flow.rs::edge_cookies_are_stripped_before_forwarding`、`edge/src/headers.rs::tests::edge_cookies_are_removed_exactly`）；`schema_version = 1` 时不删除（D-66） |
| EDG-17 | T | 升级二进制本身改变线上的决策、挑战或凭证 | 未经所有者配置就改变行为；回滚后旧 Edge 不认新凭证 | Phase 2（D-66）：`schema_version = 1` 的配置包让 Edge 严格按 Phase 1 运行：`identity.proof.*` 恒为 MISSING、只签发 v1 凭证、不设 `__Host-mg_st`、新端点 404、不删除 Cookie；带任何 Phase 2 字段的 schema 1 配置包无效 | Phase 2 实现（`edge/tests/interactive_flow.rs::renew_endpoint_answers_and_schema_1`、`edge/tests/refresh_telemetry.rs::refresh_gates_and_schema_1`、`edge-core/tests/bundle_phase2.rs::schema1_rejects_every_phase2_field`）；生产比较由所有者完成（规格 §19 第 3a 步） |
| EDG-18 | T | 本机应急开关 `force_monitor` 被遗忘，或被能登录主机的人打开 | 站点长期只记录、不处置 | Phase 2（D-60，[ADR-0011](adr/0011-local-emergency-monitor-switch.md)）：只在 `edge.toml`，改它需要 root（H2）；加载时与生效期间每小时打 WARN；`mg_site_forced_monitor = 1` 持续 1 小时告警；决定事件带 `forced_monitor: true` | Phase 2 实现（`edge/tests/proof_flow.rs::force_monitor`、`edge/tests/alerts.rs::daily_check_flags_each_condition`） |

### 4.2 Decision Core（`core/`，mg-core）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| DC-01 | S | UA 冒充搜索引擎等已验证爬虫 | 绕过爬虫策略与限额 | 官方 IP 段 + 异步 rDNS，均基于解析出的客户端 IP；验证明确失败归为 `IMPERSONATOR`（[05](05-ai-agent-policy.md#2-分类)、[03](03-risk-scoring.md#2-分类botclass)）。Phase 1：只发布 IP 段的运营方同步判定，需要 rDNS 的首个请求为 `DECLARED_AGENT`（D-18）；注册表逐条校验 CIDR 并有变化保护（D-36）；UA 声明按清洗后的完整 `User-Agent` 匹配，把标记放在第 512 字节之后也躲不开；已验证爬虫只在 GET / HEAD 或非 `require_clearance` 路由上直接放行 | Phase 1 实现（`edge/tests/crawler.rs::ip_ranges_operator_is_decided_synchronously`、`::padded_user_agent_still_claims_the_crawler`、`::rdns_is_pending_first_then_settles`、`intel/tests/artifacts.rs::registry_cidr_rules`）；Lab 验收：`make lab-e2e` 的 `phase1-impersonator` 场景（已定结果的冒充请求 13/13 为 `IMPERSONATOR` 且被阻断，`lab/internal/events` 断言） |
| DC-02 | S | 冒充授权 AI Agent | 进入授权范围或测试环境 | Web Bot Auth / HTTP Message Signatures 由 Edge 自行验签，`created` / `expires` 窗口与 nonce 重放键 `mg:jti:{site}:{keyid}:{H(nonce)}`（[05](05-ai-agent-policy.md)、[02 §7](02-data-flow.md#7-核心数据模型)） | Phase 3 实现 |
| DC-03 | T | 缺失信号被当作人类证据（如 Cloudflare 之后 JA4 缺失） | 系统性低估风险 | 信号三态 `PRESENT` / `ABSENT` / `MISSING`，按 `expected_mask` 区分：`MISSING`（profile 不提供或上游头未到达）不计入置信度，`ABSENT` 计入分母、降低置信度，两者都不是人类证据；上游应注入的头缺失另触发配置告警；`EDGE_TLS` 低权重、低封顶、先 shadow（[03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)、[08](08-upstream-and-cloudflare.md)） | Phase 1 实现（`core/src/detectors/tests.rs::missing_expectation_table`、`core/src/scoring/tests.rs::confidence_kappa_and_denominator`） |
| DC-04 | T | 策略编译器与数据面求值器语义不一致 | 规则在生产中的行为与预期不同 | 单一编译器（cel-go）产出受限 IR，带 `ir_version`；Rust 求值器用共享测试向量做一致性测试；热路径不用 `cel` crate（[06](06-policy-console-observability.md)「策略语言」、[ADR-0006](adr/0006-policy-cel-ir.md)）。Phase 1：一致性套件 `testdata/policy-ir/`（Go 生成 IR 字节与 `max_steps`，Rust 求值同一批用例）；Go 签名的 golden 配置包经 Rust 验签，每条规则都能转换（I-19） | Phase 1 实现（`proto/rust/tests/policy_ir_conformance.rs`、Go `policy` 包的 `TestIRConformance`、`edge-core/tests/bundle_golden.rs`） |
| DC-05 | T | 时钟偏差导致凭证 / Challenge 时间窗判断错误 | 误拒真人，或接受过期凭证 | 内核不读系统时钟，时间由 Edge 传入（`RequestContext::ts_ms`、`VerifyCtx::now_ms`），`core/clippy.toml` 禁止 `SystemTime::now` / `Instant::now`；主机启用 NTP；时间窗检查使用固定容差（[09](09-interactive-challenge.md)）。Phase 1：epoch 接受窗口按毫秒边界测试；`/__mg/c` 在正文读完之后重新取时钟，C 在正文到达期间过期即按过期处理 | Phase 0 实现（接口约束）；Phase 1 实现（`challenge/tests/kat.rs::accepted_epoch_windows`、`challenge/tests/sealed.rs::epoch_boundaries`、`edge/src/mg_endpoints/tests.rs::challenges_are_judged_when_the_body_has_arrived`） |
| DC-06 | I | reason code 或分数泄露给客户端 | 帮助对手校准 | reason code 仅内部使用；凭证对客户端不透明（PASETO v4.local）（[03](03-risk-scoring.md)、[04](04-challenge-and-tokens.md)） | 设计已覆盖；Phase 1 实现（`MG-Reasons` 缺省关闭，只发往源站） |
| DC-07 | D | 高代价策略表达式拖慢每个请求 | p99 附加延迟超过 5 ms | IR 非图灵完备；编译期估算代价并拒绝超预算规则；求值器设步数上限（[06](06-policy-console-observability.md)「策略语言」）。Phase 1：编译器按输入上限（D-26）计算每条规则的静态最坏步数，超过 100,000 编译失败，Edge 加载时复算；IR 嵌套 ≤ 50（I-8）；超限输入在 enforce 下直接拒绝，monitor 下不求值（I-2）；运行时步数断言失败计 `mg_policy_step_limit_total`（应恒为 0） | Phase 1 实现（`core/src/policy/tests/steps.rs::runtime_steps_never_exceed_the_static_bound`、一致性用例 `limits.depth-50` / `reject.depth-51`） |
| DC-08 | E | 客户端自行选择 Challenge 类型或 Provider | 降级到最弱的验证 | 升级路径与 Provider 由服务端决定，并密封进 C 的 `providers` 字段（[04](04-challenge-and-tokens.md)、[09](09-interactive-challenge.md)）。Phase 2：`select_providers` 是纯函数，结果密封进 C；提交的 Provider 不在集合中为 `ic.provider_not_offered`；客户端只能在集合内切换，切换不消费 nonce | Phase 2 实现（`core/src/providers/tests.rs::selection_without_turnstile`、`::selection_with_turnstile`、`edge/tests/interactive_flow.rs::replay_splice_tamper_and_cross_client`） |
| DC-09 | T | 数据面引入 I/O 或全局状态，破坏内核纯度 | 行为不可复现，WASM 目标失效 | mg-core 无 I/O、无线程、状态走 trait；`core/clippy.toml` 禁用时钟、线程、环境变量、文件与套接字 API；CI 编译 `wasm32-unknown-unknown`，目标缺失时失败而不是跳过（[ADR-0002](adr/0002-edge-pingora-boringssl.md)） | Phase 0 实现 |
| DC-10 | S | 以客户端控制的"导航"（`Sec-Fetch-Mode`、`Accept`）作为放行或豁免证明的条件 | 加一个请求头就能绕过证明或规则 | Phase 2（D-40，R1 S-1）：可豁免的导航只限 GET / HEAD 且所有命中路由的 channel 都是 `web`；声称是导航的 POST 与 `api` / `mobile` 路由上的一切请求都要求证明；动作为 `allow` 的规则以 `http.navigation` 为条件时构建器报错、Edge 拒绝该配置包 | Phase 2 实现（`edge/tests/proof_flow.rs::proofs_on_required_routes`、`edge-core/tests/bundle_phase2.rs::allow_rules_must_not_read_http_navigation`、Go `policy` 一致性用例） |
| DC-11 | T | 交互评分的阈值未经校准就 enforce | 辅助技术用户与低端设备被拒 | Phase 2（D-49）：只交付 shadow，`score` 只写事件；enforce 要求显式阈值，`t_pass` 必须高于所有者用辅助技术完成的样本的最高分；单次激活与 `pow_only` 不计指针特征，选择无障碍路径本身从不计分 | Phase 2 实现（`core/src/providers/tests.rs::shadow_never_changes_the_outcome`、`::accessible_paths_get_no_pointer_features`）；enforce 待所有者校准 |

### 4.3 Challenge 端点（`/__mg/*`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CH-01 | S | Challenge 重放、跨 Challenge 拼接字段 | 一次解答多次使用，或延长有效期 | prost 编码的 protobuf `SealedChallengeClaims`（长度分隔，不用字符串拼接）+ XChaCha20-Poly1305，aad = host ‖ type ‖ kid；验证时用 `SET NX` 消费 nonce，且在任何外部 Provider 调用之前（吸取 ALTCHA CVE-2025-68113 的教训）（[04 §4.1](04-challenge-and-tokens.md#41-密封-challenge-与验证顺序)、[09 §4](09-interactive-challenge.md#4-密封-challenge)、[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)）。Phase 1：`open` 只接受 `seal` 写出的规范信封编码（I-18）；nonce 与签发配额在同一个 Lua 脚本中原子处理；同一 C 换 Host 提交因 `aad` 不符而失败。Phase 2：交互式 C 同样密封；续期先消费旧 nonce 再签发（CH-16）；`mg_nonce_issue` v2 在一次调用中处理 nonce、Turnstile token 重放键与签发配额，之后才调用 siteverify | Phase 1 实现（无感 / PoW：`challenge/tests/sealed.rs::any_changed_byte_is_rejected`、`::envelope_is_canonical`、`::other_host_type_site_or_time`、`edge/tests/challenge_flow.rs::replay_is_refused_across_edges`）；Phase 2 实现（交互式：`edge/tests/interactive_flow.rs::replay_splice_tamper_and_cross_client`、`::concurrent_double_submission`、`challenge/tests/sealed.rs::interactive_round_trip_and_lifetimes`、`edge-core/tests/state_phase2.rs::mg_nonce_issue_v2_concurrent_double_submit`）；Lab 否定性场景随 WP-L2 |
| CH-02 | S | 在一个客户端取得 Challenge，在另一个客户端提交 | 解题外包、凭证收割 | C 与凭证按阶段绑定：Phase 1 `uah`（硬）+ `ipp`（软），Phase 2 起加 `cnf.jkt`（硬）与持有证明；`ctp` 仅 `cloudflare`、只 shadow；`tfp` 仅 `direct_tls`，不用原始 JA4、先 shadow（ADR-0002 勘误；[04 §5](04-challenge-and-tokens.md#5-短期访问凭证)）。Phase 1：`ipp` 的软 / 硬按签发时的 ASN（`bind.ipa`）判定（D-05）；`sub` / `sst` 只从通过校验、没有硬绑定失败且未超过会话上限的凭证沿用（D-29）。Phase 2：`cnf.jkt` 与 `MG-Proof` 已实现；C 经首次续期绑定会话密钥（D-41），已绑定的 C 换密钥或以 v1 提交一律失败；未绑定 C 的边界见 CH-17 | Phase 1 实现（`uah` / `ipp`：`challenge/tests/bind.rs::binding_truth_table`、`challenge/tests/clearance.rs::session_reuse_truth_table`、`edge/tests/decision.rs::clearance_cookie_is_verified`）；Phase 2 实现（`jkt`：`edge/tests/interactive_flow.rs::replay_splice_tamper_and_cross_client`、`challenge/tests/clearance_v2.rs::session_reuse_requires_the_same_key`、`edge/tests/proof_flow.rs::proofs_on_required_routes`） |
| CH-03 | T | 降级：提交未被提供的 Provider 的结果 | 绕开风险自适应升级 | C 内密封本次提供的 Provider 集合，服务端拒绝集合外的 Provider（[09](09-interactive-challenge.md)） | Phase 2 实现（`edge/tests/interactive_flow.rs::replay_splice_tamper_and_cross_client`、`challenge/tests/sealed.rs::phase2_claims_rules`）；Lab 场景随 WP-L2 |
| CH-04 | T | 利用返回路径构造开放重定向 | 钓鱼跳板 | `ret` 只保存同站相对路径的哈希，303 前校验（[09](09-interactive-challenge.md)）。Phase 1：`ret` 校验与 Edge 的 `/__mg` 归属判断是同一个函数。I-39 的 `/__mg/v?ret=` 解码后走同一校验，且只接受可见 ASCII，不合格时用 `fallback_ret`；它只签发挑战，从不直接跳转，也不让被阻断或限速的客户端绕过（按导航到 `ret` 决策） | Phase 1 实现（`challenge/tests/bind.rs::return_paths_rejected`、`::ret_rejections_match_edge_ownership`）；I-39 实现（`edge/src/mg_endpoints/tests.rs::verify_ret_decodes_one_valid_return_path`、`edge/tests/challenge_flow.rs::verify_entry_challenges_and_returns`） |
| CH-05 | T | 外部 Provider（Turnstile）的结果被错误采信 | 非本站或非本次 Challenge 的 token 通过 | hostname 精确匹配（widget 授权是后缀式的）、action 相等、cData 常量时间比较、challenge_ts 与 token 年龄检查；Turnstile token 永不直接当作 MorphGate 凭证；token 哈希写入重放集合（[09](09-interactive-challenge.md)）。Phase 2：`hostname` 必须等于请求的规范化主机且在配置的 `hostnames` 中；`cdata` 按规格 §6.9 重算、对每个根常量时间比较；token 重放键在 siteverify 之前与 nonce 一起写入；shadow 下的通过同样要求密封 C、nonce、绑定、签名与 PoW 全部通过 | Phase 2 实现（`edge-core/tests/outbound_siteverify.rs::binding_checks_and_metric_reasons`、`edge/tests/turnstile_flow.rs::turnstile_end_to_end`、`challenge/tests/kat_phase2.rs::cdata`），只用回环 mock siteverify（D-52） |
| CH-06 | T | 0-RTT 早期数据重放状态变更请求 | Challenge 提交 / 凭证刷新被重放 | 首选保持 0-RTT 关闭（`mgctl cf audit` 检查）；若开启，`/__mg/c`、`/__mg/c/renew`、`/__mg/r`、`/__mg/m/*` 对 `Early-Data: 1` 返回 425，其他请求按可重放处理（不签发 / 刷新凭证、不消费 nonce）；Cloudflare 是否透传 425 需实测（[04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt)、[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)）。Phase 1：任何 `Early-Data` 头都算（RFC 8470 §5.1），`Connection` 选项藏不住它；`critical` 路由上本应转发的决定与 `/__mg/c` 返回 425（[04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt)）。Phase 2：`/__mg/c/renew`、`/__mg/r`、`/__mg/t` 同样返回 425；`proof: required` 的路由上，425 只用于 enforce 下、不可豁免、决定会转发的请求（I-56） | Phase 1 实现（`edge/tests/challenge_flow.rs::connection_options_do_not_hide_early_data_or_content_encoding`、`edge/tests/decision.rs::unknown_client_ip_and_early_data`）；Phase 2 实现（`edge/tests/refresh_telemetry.rs::refresh_and_its_refusals`、`edge/tests/proof_flow.rs::proofs_on_required_routes`） |
| CH-07 | R | Challenge 结果无记录 | 无法发现通过率异常 | `mg_challenge_total{type,provider,result}`；事件带 request_id；失败页展示 request_id（[06 §5](06-policy-console-observability.md#5-日志指标与告警)、[09](09-interactive-challenge.md)）。Phase 1：`provider="none"`，`result` = issued / solved / failed / expired；每次提交一条 `kind=feedback` 事件。Phase 2：`provider` 取 `none` / `self_hold` / `pow_a11y` / `turnstile`，`result` 新增 `renewed`、`reissued`；`mg_challenge_renew_total`、`mg_provider_verify_total`、`mg_interactive_score`；`kind=feedback` 带 `ix`（评分摘要）与 `provider` | Phase 1 实现（`edge/tests/metrics.rs::every_family_is_served_with_its_labels`、`edge/tests/events_sink.rs::four_kinds_with_envelopes_sampling_and_redaction`）；Phase 2 实现（`edge/tests/phase2_events.rs::interactive_decision_and_renewal_feedback`） |
| CH-08 | I | 失败原因成为"预言机" | 对手逐项试探 | 所有失败统一响应，不区分原因（[04](04-challenge-and-tokens.md)） | 设计已覆盖；Phase 1 实现（`edge/tests/challenge_flow.rs::submission_failures`） |
| CH-09 | I | 个人化响应被 Cloudflare 缓存后发给其他访客 | 凭证、nonce 泄露 | 所有 `/__mg/*`（内容哈希的 SDK 构建除外）与 Challenge 响应带 `Cache-Control: no-store, private`；Challenge 用 403 / 429，不用 200；`/__mg/` 的 Bypass Cache Rule 放在最后；`mgctl cf audit` 检查"Eligible for cache + 覆盖 Edge TTL"规则（[04](04-challenge-and-tokens.md)、[08](08-upstream-and-cloudflare.md)）。Phase 0：`/__mg/*` 从不转发源站，Edge 自答的响应（healthz 与保留路径的 404）都带该头（`edge/src/routes.rs`） | Phase 0 实现（Edge 自答响应）；Phase 1 实现（挑战与阻断响应、`cf audit` 第 12、13 项：`edge/tests/challenge_flow.rs::challenge_page_to_clearance`、Go `cfaudit` 的 `TestAuditTTLStackedRules`）；经 Cloudflare 后的 `cf-cache-status` 待 monitor 周实测 |
| CH-10 | D | 大量索取或提交 Challenge | Edge / Valkey 过载 | 签发无状态（不写存储）；请求体上限 `/__mg/c`、`/__mg/c/renew` 8 KB，`/__mg/t`、`/__mg/r` 16 KB，带 `Content-Encoding` 一律拒绝、不解压；先校验大小与格式再做密码学运算；`/__mg/` 独立限速；Free 区唯一一条限速规则在边缘挡 `POST /__mg/` 洪泛，此时 Skip 规则不跳过 `http_ratelimit`（[02 §3](02-data-flow.md#3-challengesdk-遥测与凭证刷新)、[06 §8](06-policy-console-observability.md#8-平台自身安全)、[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)）。Phase 1：`/__mg/c` 正文 ≤ 8 KiB、5 s 内读完、带 `Content-Encoding` 即拒绝；提交限速 `mg.c.submit`、两级失败配额与签发配额都强制执行（D-28、D-37）；`/__mg/t`、`/__mg/r` 在 Phase 1 返回 404。Phase 2：交互式 C 的签发受进程内 `mg.ix.issue` 约束（不写状态）；`/__mg/c/renew` ≤ 8 KiB、`/__mg/r` 与 `/__mg/t` ≤ 16 KiB，各有两级限速；`/__mg/t` 至多 8 条报告；新的限速器都按 `ip` 实体加按 `ipp` 的宽松一级（D-67） | Phase 1 实现（`edge/tests/challenge_flow.rs::failure_quotas`、`::issuance_quota`、`::submission_failures`）；Phase 2 实现（`edge/tests/refresh_telemetry.rs::telemetry_limits_and_queue`、`edge/tests/interactive_flow.rs::renew_endpoint_answers_and_schema_1`） |
| CH-11 | D | 外部 Provider 故障或超时 | 交互式验证不可用 | verify 带截止时间；回退自研 `self_hold`；**绝不 fail-open**；`invalid-input-secret` 告警并自动禁用该 Provider（[09](09-interactive-challenge.md)、[01](01-architecture.md)「部署与高可用」）。Phase 2：外部 Provider 只有 Turnstile，回退只能是 `self_hold`（D-51，`fail_closed` 被拒绝）；60 s 内连续 5 次 `Unavailable` 熔断，`Misconfigured` 立即禁用并告警（`MgTurnstileDisabled`）；客户端加载失败或报错时在同一 C 内回退，不计失败 | Phase 2 实现（`edge-core/tests/outbound_breaker.rs::five_consecutive_unavailable_within_60s_open`、`::misconfigured_disables_until_reset`、`edge/tests/turnstile_flow.rs::turnstile_end_to_end`、`sdk/web/test/turnstile.test.ts`） |
| CH-12 | E | 人工代解中继取得交互级凭证 | 自动化获得"人类"等级 | 无法阻止，只抬成本：交互级凭证 30 分钟 TTL（`interactive_a11y` 15 分钟）+ 持有证明续期、按前缀 / ASN 的签发上限、解题时间分布监控；通过只算封顶的人类证据（[09](09-interactive-challenge.md)）。残余风险见 §6 R-01。Phase 2：交互级凭证 TTL 缺省 1800 s（`interactive_a11y` 900 s）；刷新缺省关闭且按级别封顶（CH-19）；交互级的人类证据保持 −0.4（D-68）；近线 `challenge_abuse` 检测器 | Phase 2 实现（签发配额与 TTL；刷新见 CH-19）；签发配额 Phase 1 已强制执行（D-37）；残余风险 R-01、R-13 |
| CH-13 | I | `/__mg/healthz` 泄露版本或内部状态，或被缓存 | 信息收集 | 只返回 `ok`；`Cache-Control: no-store, private` | Phase 0 实现 |
| CH-14 | E | 重放存储不可用期间，在非 `fail_closed` 路由换到的未经重放检查的凭证被用于 `fail_closed` 路由 | 绕过 `critical` 路由在 Valkey 故障时的 fail-closed | 这样签发的凭证带 `ruc = true`，`fail_closed` 路由把它视为级别不足并重新挑战（重放存储仍不可用时 429）；决定事件记 `token.replay_unchecked`（I-30） | Phase 1 实现（`edge/tests/challenge_flow.rs::replay_unchecked_clearance_is_refused_by_fail_closed_routes`、`challenge/tests/clearance.rs::replay_unchecked_claim`） |
| CH-15 | E | 自己控制客户端的自动化以很低的成本完成 `self_hold`：除服务端时间窗外，`trusted`、`hold.ms`、`single.wait_ms`、`mode`、`modality` 都由客户端自报 | 交互级凭证的成本下限只是 PoW 加 1.2–2.5 s 的等待（`pow_only` 为 `a11y_min_ms`） | Phase 2（[规格 §7.7](impl/phase2-spec.md#77-硬检查assess_interaction在消费-nonce-之前)，D-68、D-47）：交互式不是安全边界：交互级凭证的人类证据保持 −0.4，不高于 `pow`；刷新缺省关闭且按级别封顶；签发配额 `mg.ix.issue`、`mg.a11y.issue` 与凭证签发配额；短 TTL；硬检查只挡住不了解协议的脚本与时序不合理的提交，软评分在 shadow 中积累数据；近线 `challenge_abuse` | Phase 2 实现（`core/src/providers/tests.rs::hard_check_hold_bounds`、`::min_elapsed_boundaries`、`edge/tests/interactive_flow.rs::self_hold_end_to_end`）；接受为残余风险 R-13 |
| CH-16 | T | 用一个交互式 C 续出多个新 C（分叉续期链），或无限续期 | 一次解题的价值被放大；签发配额被绕过 | Phase 2（[规格 §7.4](impl/phase2-spec.md#74-post-mgcrenew续期与首次绑定d-41d-42)，I-55）：续期先以 `mg_nonce_issue` v2 消费旧 nonce 再签发，nonce 已用时不附新 C；过期与到顶的 C 同样要经过绑定、签名与 nonce 检查；链上限 `renew_no ≤ 6`；交互式 nonce 保留约 70 分钟，覆盖可续期的过期窗口（1 小时）；`mg.c.renew` 与 `mg.ix.issue` 限速 | Phase 2 实现（`edge/tests/interactive_flow.rs::renew_endpoint_answers_and_schema_1`、`challenge/tests/sealed.rs::open_for_renew_window`） |
| CH-17 | S | 首次绑定之前，未绑定会话密钥的 C 在同一 ASN 内被另一个客户端提交 | 解题外包在首次绑定之前仍有窗口 | Phase 2（D-41）：SDK 在用户操作之前先续期绑定；已绑定的 C 换密钥或以 v1 提交 100% 拒绝（`ic.bind_jkt`）；未绑定的 C 在 UA 家族不同、或 /24 与 ASN 都不同时拒绝；同一 ASN 内换 /24 只记 `ic.bind_ipp_soft` | Phase 2 实现（`edge/tests/interactive_flow.rs::replay_splice_tamper_and_cross_client`）；同一 ASN 内的边界接受为残余风险 R-14 |
| CH-18 | E | 大量使用无交互的 `pow_a11y` 取得交互级凭证 | 最容易自动化的路径成为主路径 | Phase 2（[规格 §7.9](impl/phase2-spec.md#79-失败升级与配额)）：`mg.a11y.issue` 强制执行（`ip` 实体 6 次 / 小时、`ipp` 120 次 / 小时），超限时附新 C 并把单次激活放在首位，不计失败（访客不会被锁在外面）；`interactive_a11y` TTL 900 s 且不可刷新；`a11y_min_ms` 时间窗 | Phase 2 实现（`edge/tests/interactive_flow.rs::single_activation_and_pow_a11y`、`edge-core/tests/state_phase2.rs::mg_nonce_issue_v2_semantics`） |
| CH-19 | E | 凭证静默刷新让一次解题长期有效，或为被导出的凭证续命 | 09 §13 依赖的"短 TTL"失效 | Phase 2（D-47，[规格 §9.3](impl/phase2-spec.md#93-post-mgr凭证静默刷新d-47)）：缺省关闭；要求 `MG-Proof` 且与 `cnf.jkt` 一致；按 `now − lat` 封顶，`interactive_a11y` 与 `invisible` 不可刷新；带 `ruc`、未绑定、绑定不符（含 `ipp` 软不符）、按路由 R 重新决策需要更高级别或决定为阻断时拒绝；`exp` 不超过会话上限；拒绝原因不返回客户端；`mg.r` 限速 | Phase 2 实现（`edge/tests/refresh_telemetry.rs::refresh_and_its_refusals`、`::refresh_with_route_r_decisions`、`core/src/providers/tests.rs::refresh_branches`、`challenge/tests/clearance_v2.rs::refresh_copies_and_renews`） |
| CH-20 | S | 重放或跨请求转用 `MG-Proof` | 绕过持有证明 | Phase 2（D-40）：`htm` 区分大小写；`htu` 的主机按规范化比较、路径按 Cloudflare 路径视图比较；`iat` 在 `[now − 30 s, now + 5 s]`；`jti` 一次性（Valkey 与进程内集合，40 s）；重放存储不可用时 `fail_closed` 的证明路由 429，其他路由计 `unchecked` | Phase 2 实现（`edge/tests/proof_flow.rs::proofs_on_required_routes`、`::replay_store_unavailable`、`challenge/tests/kat_phase2.rs::mg_proof`） |
| CH-21 | T | 续期或提交时已不满足条件（国家、主机、路由、`redact_path`）却仍沿用 C 中的 Turnstile | 绕过 `deny_countries`，或让第三方脚本运行在带令牌的页面上 | Phase 2（[规格 §5.4](impl/phase2-spec.md#54-provider-选择纯函数)，I-57）：续期与提交时按当前请求重新判断，不满足则去掉 Turnstile、不调用 siteverify、不计失败；`redact_path` 按 C 的 `route_class` 路由与 `ret` 命中的路由判断；配置包中已不存在的路由从不提供 Turnstile | Phase 2 实现（`edge/tests/turnstile_flow.rs::turnstile_end_to_end`、`core/src/providers/tests.rs::turnstile_eligibility_rules`、`::turnstile_country_rules`）；Lab 场景随 WP-L2 |

### 4.4 Web SDK（`sdk/web/`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| SDK-01 | T | SDK 在构建、存储、缓存或页面优化环节被篡改 | 在所有者页面上执行非预期代码 | 内容哈希路径；锁文件 + `--frozen-lockfile`；可复现构建并签名（[06](06-policy-console-observability.md)「平台自身安全」）；Rocket Loader 关闭或给 SDK 标签加 `data-cfasync="false"`（[08](08-upstream-and-cloudflare.md)）。Phase 1：SDK 文件名带内容哈希，Edge 启动时按 `manifest.json` 校验每个文件的 SHA-256，`/__mg/s/*` 只提供清单内的文件。Phase 2（D-63）：npm 包改由 GitHub Actions 以 trusted publishing 带 provenance 发布，发布前确认构建产物与 Edge 夹具逐字节一致；不对 SDK 目录做签名校验：Edge 主机上的 root 本来就能替换任何文件；稳定别名 `/__mg/s/mg.js` 只返回 manifest 中当前构建的字节，manifest 的 `files` 不得包含 `mg.js` | Phase 0 实现（锁文件）；Phase 1 实现（内容哈希与 Edge 加载校验）；Phase 2 实现（provenance 发布：`.github/workflows/publish-sdk.yml`；别名：`edge/tests/interactive_flow.rs::sdk_alias`）；SDK 签名改为 provenance（D-63） |
| SDK-02 | S | 伪造或回放 SDK 上报的信号 | 虚假的"人类"证据 | SDK 输出一律视为不可信输入；一致性判断放在服务端；遥测由会话密钥签名，只证明持有密钥、不证明是人；CLIENT 族封顶（[04](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)、[03](03-risk-scoring.md)）。Phase 1：挑战提交中的 `env` / `auto` 只做两项硬检查（`webdriver` 标志、UA 前缀一致），其余只记录。Phase 2：交互遥测除服务端时间窗外都是客户端自报（CH-15）；`/__mg/t` 的告警指标只计签名的报告（SDK-11）；遥测在 Phase 2 不影响任何决定 | 设计已覆盖；Phase 2 实现（交互遥测只进硬检查与 shadow 评分：`core/src/providers/tests.rs::shadow_never_changes_the_outcome`） |
| SDK-03 | S | 会话密钥被导出后在别处使用 | 凭证转移 | WebCrypto non-extractable 密钥；`cnf.jkt` 绑定；`MG-Proof` 含 `htm`、`htu`、`iat`、`jti`（[04](04-challenge-and-tokens.md)）。Phase 2（D-45）：IndexedDB 中不可导出的密钥；IndexedDB 不可用时回退 localStorage 中可导出的密钥（R-16），再不行只放在内存且不附证明；没有有效凭证或满 7 天即换新 | Phase 2 实现（`sdk/web/test/keystore.test.ts`、`challenge/tests/proof.rs::valid_proofs`、`edge/tests/proof_flow.rs::proofs_on_required_routes`） |
| SDK-04 | I | 采集超出必要的个人信息 | 违反最小化，PIPL 风险 | 端上摘要；不采原始轨迹、按键内容、画布哈希；交互遥测 ≤ 2 KB；高熵指纹默认关闭（[04](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)、[09](09-interactive-challenge.md)）。Phase 1：只有挑战页的环境摘要；`kind=telemetry` 只在提交带 `env` 时写出（I-32），按已知字段、带长度上限重新序列化，不含 `userAgent`。Phase 2：交互遥测 `t` ≤ 2048 字节，只有量化值，没有原始坐标与按键值；行为摘要缺省关闭，站点在 SDK 标签与配置包两处开启才采集与接收；解析与重新序列化在 edge-core 中只有一份实现（D-62） | Phase 1 实现（挑战页：`edge/tests/events_sink.rs::telemetry_only_for_submissions_with_env`、`edge-core/tests/events_encoding.rs::telemetry_env_drops_unknown_fields`）；Phase 2 实现（`edge-core/tests/events_telemetry_v2.rs::every_sample_has_its_expected_result`、`edge/tests/refresh_telemetry.rs::behavior_and_refresh_telemetry_when_enabled`、`sdk/web/test/telemetry.test.ts`） |
| SDK-05 | I | 第三方脚本（Turnstile api.js）进入页面 | 访客 IP、TLS 指纹、UA 发往 Cloudflare；页面脚本面扩大 | 只在选用 Turnstile 的 Challenge 页加载；CSP nonce + `frame-src https://challenges.cloudflare.com`，先 Report-Only 验证；按站点开关；隐私声明披露（[09](09-interactive-challenge.md)、[06](06-policy-console-observability.md#7-隐私与合规)）。Phase 2（D-70）：所有者决定大陆与国家未知的访客也可以选用 Turnstile（`deny_countries` 缺省为空），被选中的大陆访客的 IP 同样发给 Cloudflare；只在 Turnstile 是当前 Provider 时由 SDK 加载 api.js；只有提供了 Turnstile 的挑战页才放开 `strict-dynamic` 与 `frame-src`；隐私说明见 [模板](privacy-notice-template.md) | Phase 2 实现（`sdk/web/test/turnstile.test.ts`、`sdk/web/test/template-v2.test.ts`、`edge/tests/turnstile_flow.rs::turnstile_end_to_end`）；隐私说明由所有者更新 |
| SDK-06 | E | 受保护站点自身的 XSS 读取凭证或调用会话密钥 | 凭证在页面打开期间被利用 | 凭证 Cookie 使用 `__Host-` 前缀与 `HttpOnly`；密钥不可导出；注入脚本使用 CSP nonce（[04](04-challenge-and-tokens.md)）。页面打开期间的密钥调用无法阻止，见 §6 R-06。Phase 2：会话密钥在 IndexedDB 中不可导出；XSS 仍能在页面打开期间调用它签名（RFC 9449 同样承认）；localStorage 回退时能读走私钥（R-16） | Phase 1 实现（Cookie 属性：`challenge/tests/clearance.rs::set_cookie_header`）；Phase 2 实现（会话密钥：`sdk/web/test/keystore.test.ts`） |
| SDK-07 | D | SDK 异常导致页面功能损坏 | 所有访客受影响 | SDK 异常不影响页面；SDK 失败时相关 CLIENT 信号记为 `ABSENT`（计入置信度分母，不当人类证据，[03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)）；核心包 ≤ 30 KB gzip（[04 §7](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)）。Phase 2：站点代码不假设 `window.MorphGate` 存在；任何异常都不抛进页面；挑战页有纯 CSS 的兜底提示 `#mg-stuck`；单文件 ≤ 30,720 字节 gzip | Phase 2 实现（`sdk/web/test/runtime.test.ts`、`sdk/web/test/template-v2.test.ts`、`sdk/web/test/build-dist.test.ts`） |
| SDK-08 | T | 挑战页模板中的占位符处于不安全的上下文（未加引号的属性值、内联脚本或样式、注释），被请求路径等值注入脚本 | 在所有者域名下执行攻击者的脚本 | 占位符只允许出现在带引号的属性值或普通文本中，值按属性上下文转义；构建时（`scripts/build-dist.mjs` 的 `validateTemplate`）与 Edge 加载 SDK 目录时用同一套规则校验（I-28）；挑战页 CSP 只允许带 nonce 的脚本 | Phase 1 实现（`sdk/web/test/template.test.ts`、`edge/src/sdk.rs::rejects_every_contract_violation_like_validate_template`） |
| SDK-09 | D | 站点的 Service Worker 截获 `/__mg/` 请求，或别名 `/__mg/s/mg.js` 与它启动的 Worker 来自不同构建 | 挑战页无法加载，就地求解失败 | Phase 2（D-39）：运维手册要求 Service Worker 不处理 `/__mg/`；SDK 发现时上报 `sw_intercept`（`mg_sw_intercept_reports_total` 告警）；别名 `max-age=300` + `ETag`；Worker 先报告自己的 SDK 版本，不一致时用带版本参数的 URL 重建一次，仍不一致就在主线程计算 | Phase 2 实现（`edge/tests/interactive_flow.rs::sdk_alias`、`sdk/web/test/powv2.test.ts`）；Service Worker 的规则由所有者执行（规格 §19 第 3b 步） |
| SDK-10 | I | 页面上的第三方脚本或策略得知访客用过无障碍路径 | 无障碍用户被追踪或区别对待 | Phase 2（D-46、规格 §9.5）：脚本可读的 `__Host-mg_st` 只有 `iat`、`exp` 与绑定标记，不写级别；偏好 Cookie `__Host-mg_a11y` 为 HttpOnly，SDK 从不读写；二者不进入 `http.cookie_names`、策略字段、事件与 `mg:ev`，转发源站前删除 | Phase 2 实现（`challenge/tests/clearance_v2.rs::status_cookie`、`edge/src/context.rs::tests::caps_and_parsers`、`edge/tests/interactive_flow.rs::single_activation_and_pow_a11y`） |
| SDK-11 | S | 伪造或刷量 `/__mg/t` 报告，触发或淹没告警 | 告警噪声；`mg_double_challenge_total` 失真 | Phase 2（D-48）：两个告警指标只计带有效 `MG-Proof` 的报告，同一会话同一种报告 10 分钟至多计一次；`mg.t` 两级与按会话限速；报告数量与字段有上限；遥测进入独立的有界队列，满时决定事件不受影响；遥测从不影响决定 | Phase 2 实现（`edge/tests/refresh_telemetry.rs::telemetry_reports`、`::telemetry_limits_and_queue`、`edge-core/tests/events_drain.rs::telemetry_queue_is_separate_and_bounded`） |
| SDK-12 | D | 访客浏览器清除或禁用存储（Safari 7 天清理、隐私窗口、禁用 IndexedDB），会话密钥丢失 | `proof: required` 接口反复要求重新挑战，或无法使用 | Phase 2（D-45、规格 §9.1）：回退顺序 IndexedDB → localStorage → 内存；密钥丢失后的就地恢复（`mg_proof_required` 附一个绑定新公钥的 `pow` C，SDK 就地求解后重试）；`key_unavailable` 上报；隐私说明写明不能使用 `proof: required` 接口的情形 | Phase 2 实现（`sdk/web/test/keystore.test.ts`、`edge/tests/proof_flow.rs::in_place_recovery`）；实际丢失率待 shadow 期测量（规格 §21） |

### 4.5 Cloudflare 上游集成（`cloudflare` profile、`adapters/cloudflare/`、`mgctl cf`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CF-01 | S | 源站 / Edge 被绕过 Cloudflare 直接访问，访问者自带 `CF-Connecting-IP`、`x-mg-cf-*` 等头 | 伪造客户端 IP、TLS 信号与验证爬虫标记 | 首选 Tunnel：Edge 只监听 127.0.0.1、只信任回环对端，主机无公网入站端口；备选 AOP（zone-level 或 per-hostname，自有 CA，**不用**全局共享证书）+ TLS 前按 Cloudflare 网段过滤 + 云防火墙只放行 Cloudflare 网段（纵深防御）；上游认证失败时删除全部已知上游头族，以 TCP 对端为客户端 IP；源站应用同样只监听回环（[08](08-upstream-and-cloudflare.md)、[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)）。Phase 0 的 mg-edge 没有 TLS 监听器，配置校验拒绝非回环的 `listen`（`edge/src/config.rs`）。Phase 1：回环监听器拒绝非回环对端（403）；可叠加上游密钥头（`upstream_keys`）；AOP 监听器按所有者 CA 校验客户端证书，可按 `cloudflare-ips` 在 TLS 之前过滤 | Phase 0 实现（强制回环监听）；Phase 1 实现（`edge/tests/upstream_trust.rs::secret_header_is_required_when_configured`、`edge/tests/tls.rs::origin_mtls_requires_a_trusted_client_certificate`、`::cloudflare_ip_filter_drops_peers_outside_the_ranges`） |
| CF-02 | S | 其他 Cloudflare 客户的流量（如 Worker）经 Cloudflare 网络到达源站，或借此让客户端 IP 变成未知，绕过按 IP 的控制 | 被当作来自所有者 zone 的请求 | 不用全局 AOP 证书；拒绝 `CF-Worker` 头不属于所有者 zone 的请求（[08](08-upstream-and-cloudflare.md)）。Phase 1：外部 zone 的 `CF-Worker`（含非法值）直接 403，不进入决策；配置包生效前用 `bootstrap_owner_zones`（I-4）；`Connection: CF-Worker` 藏不住该头（I-12）；客户端 IP 未知时从不更宽松：限速用共享兜底桶，不签发 C 与凭证，`fail_closed` 路由 429（D-23） | Phase 1 实现（`edge/tests/upstream_trust.rs::foreign_zone_workers_are_rejected_and_counted`、`::bootstrap_owner_zones_decide_workers_before_the_first_bundle`、`::client_ip_unknown_is_never_more_permissive`、`edge-core/tests/upstream_cloudflare.rs::connection_listing_cannot_hide_trusted_headers`）；访客自带的 `CF-Worker` 是否被 Cloudflare 删除待实测 |
| CF-03 | S | 访客预先设置 `x-mg-cf-*` 同名头 | 信号污染 | Tier 0 Transform Rule 的 Set 覆盖同名头、值为空时删除，并删除 Tier 1 头名，Worker 未运行时伪造值不会留存（执行顺序需实测）；缺 `x-mg-cf-t1` 标记时 Tier 1 头按 `MISSING`；Edge 仍只在上游认证通过时采信；`mgctl cf audit` 检查 Transform Rule 是否齐全（[08 §2.3](08-upstream-and-cloudflare.md#23-信号转发-tier-0request-header-transform-rule)）。Phase 1：下划线写法永不解析，也不遮蔽 Cloudflare 写入的头；Tier 1 只在站点开启且标记有效时解析 | Phase 1 实现（`edge-core/tests/upstream_cloudflare.rs::underscore_variants_do_not_shadow_trusted_headers`、`::tier1_requires_site_flag_and_valid_marker`、Go `cfaudit` 的 `TestAuditErrorChecksFail`）；Worker 与 Transform Rule 的顺序待实测 |
| CF-04 | T | Cloudflare 侧配置漂移：Bot Fight Mode 被开启、`/__mg/` Bypass 规则顺序变化、误开 "Remove visitor IP headers"、Pseudo IPv4 改为 Overwrite、0-RTT、Rocket Loader、AI bot policy 默认值 | 误伤、缓存泄漏、丢失客户端 IP | `mgctl cf audit` 定时运行并告警；上游认证通过但缺 `CF-Connecting-IP` 时告警，不回退到 Cloudflare 对端 IP；修改 Cloudflare 配置后必跑审计（[08](08-upstream-and-cloudflare.md)、[07](07-roadmap.md)）。Phase 1：`mgctl cf audit` 的 21 项检查由所有者定时运行，`--metrics-textfile` 写 `mg_cf_audit_failed_checks` | Phase 1 实现（Go `cfaudit`：`TestAuditGreenTunnel`、`TestAuditErrorChecksFail`、`TestAuditWarnings`） |
| CF-05 | T | Cloudflare IP 段同步结果异常（为空、格式变化、被篡改） | 可信代理快照与安全组错误 | 带 etag 拉取 `GET /client/v4/ips`；校验列表形状与大小，失败保留上一版并告警（> 48 小时未成功）；与上一版的差异在 Console 展示（[08](08-upstream-and-cloudflare.md)、[06](06-policy-console-observability.md)）。Phase 1：`mgctl cf ips sync` 按规格校验条数与地址段，条数变化超过 30% 拒绝，失败不改写工件；工件随签名配置包下发；差异展示随 Console 在 Phase 3 | Phase 1 实现（Go `intelsync`：`TestCloudflareIPsValidation`、`TestCFIPsSyncChangeProtection`；`intel/tests/artifacts.rs::cloudflare_rules`） |
| CF-06 | I | Cloudflare API Token 泄露 | 修改 zone 配置、关闭源站保护 | 按用途拆分（`cf-audit` 只读、`cf-turnstile` 仅 Turnstile、`cf-push` 默认不创建）；按 AS-K5 的方式保管，不进配置包与仓库；定期轮换（[06 §8](06-policy-console-observability.md#8-平台自身安全)）。Phase 1：出站 User-Agent 一律 `morphgate-dev-tooling`，请求中不带所有者信息（I-7、I-15）。Phase 2：Turnstile 管理 token 的权限为 Account → Turnstile → Edit（规格 §16），与其他 token 一样以 age 加密保存在工作站 | Phase 1 实现（只读审计 token）；Phase 2 实现（Turnstile token 的权限名）；`cf-push` 的写权限名待定 |
| CF-07 | S | Tunnel 凭证被盗后在他处运行 connector | 部分访客流量流向非所有者主机 | 凭证仅 root 可读，cloudflared 以非特权用户运行；主机失陷即轮换；定期核对 tunnel 上的 connector 列表（查询方式需实测）（[06](06-policy-console-observability.md)「平台自身安全」）。Phase 1：`cf audit` 第 1 项读取 tunnel 状态（healthy），connector 列表的核对仍待定 | 待定（connector 核对） |
| CF-08 | S | AOP CA 私钥泄露（仅 AOP 模式） | 可签发被 Edge 信任的客户端证书 | CA 私钥离线保存，只在签发 / 轮换时使用；Edge 只持有 CA 证书；轮换时短期同时信任新旧 CA；证书剩余 < 30 天告警（`mg_aop_cert_expiry_seconds`，[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)）。Phase 1：到期检查为 `cf audit` 第 3 项（剩余 < 30 天警告）；握手失败计 `mg_upstream_auth_failures_total{reason="untrusted_ca"}` | 设计已覆盖（AOP 模式启用时实现） |
| CF-09 | D | 单个 cloudflared 或主机故障 | 站点不可用 | 每台 Edge 主机一个副本，免费主备；启用 SBFM 时 "Definitely Automated" 保持 Allow，避免隧道连接失败（[08](08-upstream-and-cloudflare.md)、[01](01-architecture.md)「部署与高可用」）。单副本部署的不可用是已知代价 | 设计已覆盖 |
| CF-10 | E | 可选 MessageMAC Cookie 密钥泄露 | Cloudflare 侧跳过 SBFM / 限速 | 独立密钥、短 TTL；只影响 Cloudflare 侧的跳过，MorphGate 仍独立判定（[08](08-upstream-and-cloudflare.md)） | 待定（Pro 及以上可选功能） |
| CF-11 | I | Turnstile secret 泄露 | 他人可用本站 widget 做 siteverify | 每站点一个 widget 限制影响面；经 API `rotate_secret` 轮换，轮换期间 Edge 同时持有新旧 secret；配置只写引用（[09](09-interactive-challenge.md)、[06](06-policy-console-observability.md)）。Phase 2：`mgctl turnstile secret rotate` 总是显式传 `invalidate_immediately`（泄露时为 `true`），先核对 widget 当前的 secret；secret 在 `mg-turnstile-keys` 文件中（D-51）；secret 错误时自动禁用该 Provider 并告警 | Phase 2 实现（Go `turnstile` 的 `TestRotateSecretSendsInvalidateImmediatelyExplicitly`、`mgctl` 的 `TestTurnstileSecretLifecycle`、`TestTurnstileRotateRefusals`、`edge-core/tests/outbound_siteverify.rs::previous_secret_is_tried_once_with_its_own_key`） |

### 4.6 控制面与 mgctl（`control-plane/`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CP-01 | S | 冒充所有者使用控制面 | 完全控制策略与密钥 | passkey 为主（建议注册两个）、TOTP 备用并通知；离线恢复码；控制面只绑定内网或 WireGuard 地址（[06](06-policy-console-observability.md)「管理后台」、[ADR-0010](adr/0010-single-owner-model.md)） | Phase 3 实现 |
| CP-02 | S | 冒充控制面向 Edge 下发配置，或冒充 Edge 拉取配置 | 注入恶意策略；配置外泄 | Phase 1–2：mgctl 上传到大脑 VM 上的静态位置，Edge 以 ETag 条件请求拉取；Phase 3 起向 mg-control 长轮询；链路均为 mTLS 或 WireGuard；配置包 Ed25519 签名，Edge 校验签名与 schema（[02 §6](02-data-flow.md#6-配置模型与密钥下发)、[ADR-0007](adr/0007-lean-deployment.md)）。Phase 1：Edge 按间隔（缺省 10 s）条件拉取，只跟随同源重定向，忽略代理环境变量；`http://` 的 `bundle_root` 只接受私网地址；新鲜度靠 `mg_bundle_published_version` 与 `mg_config_version` 的比较告警 | Phase 1 实现（静态位置：`edge-core/tests/bundle_fetch.rs::http_redirects_stay_on_origin`、`::proxy_environment_is_ignored`、`edge-core/tests/bundle_verify.rs::unknown_kid_is_rejected`）；Phase 3 实现（长轮询） |
| CP-03 | T | 旧的有效签名配置包被重新投递（回滚） | 已修复的策略被还原 | Edge 只接受版本号单调递增的配置包；所有者的"回滚"以内容为旧版、版本号更高的新包实现（[02 §6](02-data-flow.md#6-配置模型与密钥下发)）。Phase 1：`mgctl bundle publish` 同样拒绝不更新的版本；延迟生效（`not_before`）的配置包被更高版本取代后永不回退 | Phase 1 实现（`edge-core/tests/bundle_poll.rs::rejects_bad_candidates_and_keeps_current`、`::pending_bundle_is_superseded_and_never_rolled_back`、Go `bundle` 的 `TestPublish`） |
| CP-04 | T | 配置签名密钥被盗 | 任意签发 Edge 信任的配置 | 所有者一对 Ed25519（`kid` 区分，年更），不在 Edge 上：Phase 1–2 由 mgctl 在工作站使用，私钥 age 加密（口令或硬件密钥插件）；Phase 3 起移到大脑 VM 的 mg-control，以 systemd credentials 交付（有 TPM2 时绑定）；云 KMS 可选，不部署 OpenBao；审计锚点签名为另一对、保管相同；轮换属敏感操作并写审计（[06 §8](06-policy-console-observability.md#8-平台自身安全)、[ADR-0010](adr/0010-single-owner-model.md)）。Phase 1：age 的 scrypt 工作因子缺省 18，低于 18 必须显式 `--insecure-test-key`（只用于测试与 Lab）；Edge 的 `[trust] owner_keys` 可同时列两把公钥用于轮换 | 设计已覆盖；Phase 1 实现（工作站 age 加密：Go `keys` 的 `TestWorkFactor`、`TestOwnerKeyFiles`） |
| CP-05 | R | 单人无法两人审批，敏感操作缺少旁证 | 误操作或账号被盗后无法追溯 | 敏感操作重新认证 + 输入站点名确认 + 可选生效延迟（延迟期间立即通知）；审计哈希链，每日锚点签名写入对象存储；Phase 1–2 的 mgctl 操作写本地追加日志（同一格式与哈希链）（[06](06-policy-console-observability.md)「审计」、[ADR-0010](adr/0010-single-owner-model.md)）。Phase 1：mgctl 写本地 JSON Lines 哈希链，`mgctl audit verify` 校验；写命令在任何写入或出站请求之前先确认审计日志可追加，否则不写并返回 3（I-27） | Phase 1 实现（mgctl 本地审计：Go `audit` 的 `TestVerifyLocatesEveryTamperedByte`、`TestOpenFailsWhenTheLogIsNotWritable`，`intelsync` 的 `TestSyncsCheckTheAuditLogFirst`）；每日锚点与控制面 Phase 3 实现 |
| CP-06 | I | 密钥材料进入配置包、日志或仓库 | 密钥扩散 | 配置包只含 `kid` 与引用（`secret_refs`、`origin_pull_ca_ref`）；`.gitignore` 排除本地密钥与环境文件；CI 不持有生产密钥（[02](02-data-flow.md)、`proto/morphgate/v1/config.proto`）。Phase 1：工作站上的站点密钥、假名化密钥与上游密钥都是 age 加密文件，只经 `mgctl keys export` 管道交给 `systemd-creds encrypt`；密钥类型的 `Debug` / 格式化输出不含密钥。Phase 2：仓库的 secret scanning 与 push protection 由所有者开启（规格 §19 第 11 步），有意提交的测试密钥按"用于测试"关闭告警 | 设计已覆盖；Phase 1 实现（`challenge/tests/key_files.rs::debug_output_never_contains_keys`、Go `keys` 的 `TestKeysAreRedactedInFmt`）；仓库密钥扫描待所有者开启 |
| CP-07 | D | 控制面不可用 | 无法发布策略 | 控制面不在请求路径上；Edge 使用 last-known-good 并在配置陈旧时告警；吊销经 Valkey pub/sub（[01](01-architecture.md)「部署与高可用」） | 设计已覆盖 |
| CP-08 | E | 通过策略表达式或 Admin API 在控制面执行任意代码 | 取得大脑 VM | CEL 非图灵完备、编译期类型与代价检查；控制面容器以非 root 运行；Admin API 只在私网（[06](06-policy-console-observability.md)） | Phase 3 实现 |
| CP-09 | E | 可选只读账号或 mgctl API Token 越权 | 只读身份执行写操作 | 只有 `owner` 与 `viewer` 两个角色，服务端强制检查；API Token 限定范围、必须过期、服务端只存哈希（[06](06-policy-console-observability.md)） | Phase 3 实现 |
| CP-10 | I | `mgctl turnstile` 处理 secret 时泄露（审计条目、日志、文件权限） | 他人可用本站 widget 做 siteverify | Phase 2（规格 §16）：审计条目只记 sitekey、站点与操作；写出的密钥文件权限 0600；写文件之前先确认审计日志可追加（I-27）；出站 User-Agent 不带所有者身份 | Phase 2 实现（`mgctl` 的 `TestTurnstileAuditPreflight`、`keys` 的 `TestTurnstileKeysLimitsAndSecrecy`） |

### 4.7 Valkey

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| VK-01 | S | 未授权客户端连接 Valkey | 读写全部状态 | 只监听私网地址，不开放公网；与 Edge 同区域 / 同 VPC；按角色划分 ACL 用户（Edge、近线 worker、控制面）；链路经私网或 WireGuard（[01](01-architecture.md)「部署与高可用」）。Phase 1：Edge 使用独立 ACL 用户，`url` 不含口令，口令经 credential 交付；规格 §17 的 ACL 已在 Valkey 9.1.2 上实测。Phase 2：近线 worker 有独立的 ACL 用户 `mg-nearline`（只经回环或 unix socket）；单机形态的 Valkey 只监听回环或 unix socket（`unixsocketperm 770`） | Phase 1 实现（Edge ACL 用户：`edge/tests/valkey_acl.rs::edge_acl_user_can_do_exactly_what_the_edge_needs`）；Phase 2 实现（`mg-nearline` 用户：Go `nearline` 的 `TestACLUserRunsEveryOperation`）；部署由所有者按规格 §19 第 1a 步完成 |
| VK-02 | T | 篡改实体 verdict、吊销集、限速计数 | 放行恶意流量或误伤 | ACL 限制各角色可写的 key 前缀与命令（Edge 不能写 `mg:rev:*`、不能发布 `mg:pub:*`；Phase 1 已在 Valkey 9.1.2 上实测：Edge 只读 `mg:v:*`，不能访问 `mg:rev:*`、不能 `PUBLISH`，键选择器对 `EVALSHA` 传入的键同样生效）；吊销消息签名校验、只会收紧，任何放宽只经签名配置包（[02 §6](02-data-flow.md#6-配置模型与密钥下发)）；verdict 带 `source`、`version`、TTL；跨站共享只限 IP / ASN 类、按站点开关（[01 §10](01-architecture.md#10-站点模型)）；**已采纳**（D-10）：verdict 只能提高风险，贡献 `β_e · max(0, logit(R_e/100))`，封顶 4.0；Phase 1 的 verdict 只能由所有者手工写入（`mgctl verdict key` 计算键）。Phase 2：verdict 改由近线 worker 经 `mg_verdict_put` 写入：只抬高风险，从不覆盖所有者手写或无法解析的值，从不带 `scanner` 标签（D-53）；Edge 的 ACL 增加 `~mg:jti:* ~mg:jc:* ~mg:rp:*`，仍不能写 `mg:v:*` | Phase 1 实现（`edge/tests/valkey_acl.rs::edge_acl_user_can_do_exactly_what_the_edge_needs`、`edge/tests/verdicts.rs::verdicts_raise_risk_and_parse_errors_are_counted`）；Phase 2 实现（`edge-core/tests/state_phase2.rs::edge_user_is_limited_to_its_key_patterns`、Go `nearline` 的 `TestVerdictPutRules`） |
| VK-03 | T | 重放集合（nonce、jti）被逐出或清空 | 一次性 nonce 可被重用 | 重放类 key 与计数类 key 分开规划内存，重放集合不得被静默逐出；Valkey 不可用时按 EDG-09：`critical` 路由 fail-closed，其余放行并标记（[01 §8](01-architecture.md#8-部署与高可用)）。Phase 1：Valkey 设 `maxmemory-policy noeviction`，重放键与限速键分开规划内存（规格 §17）；进程内重放集合从不逐出未过期的 nonce，满时按不可用处理（D-35）。Phase 2：新的进程内集合 `jti`（`local_jti_capacity`）与 token 重放（`local_rp_capacity`）同样不逐出、溢出即"不可用"；交互式 C 的 nonce 存活约 70 分钟，`local_nonce_capacity` 按规格 §14.4 调高（单机建议 ≥ 400,000，`--check-config` 提示） | Phase 1 实现（`edge-core/tests/state_service.rs::local_replay_rules`、`edge/tests/challenge_flow.rs::full_local_replay_set`）；Phase 2 实现（`edge-core/tests/state_phase2.rs::local_jti_rules`、`::local_nonce_issue_v2_rules`） |
| VK-04 | I | Valkey 数据或 RDB 备份泄露 | 访客 IP 前缀、会话标识外泄 | 标识个人的 key 做哈希（`EntityVerdict.key`）；备份加密后写入对象存储（[02](02-data-flow.md)、[06](06-policy-console-observability.md)）。Phase 1：IP、前缀与限速器键用所有者假名化密钥 `K_pseudo` 的 HMAC（D-06）；`mg:ev` 只有 `ipk` / `pfk`，不写 IP 明文 | Phase 1 实现（`edge-core/tests/state_kat.rs::kh_matches_kat_entity_key_cases`） |
| VK-05 | D | 高基数 key 或 Stream 堆积耗尽内存 | 限速与重放检查失效 | 所有 key 带 TTL；设置 `maxmemory` 与告警；Stream 用 `XADD MAXLEN ~`，`mg:ev` 积压告警（[06 §5](06-policy-console-observability.md#5-日志指标与告警)、[ADR-0007](adr/0007-lean-deployment.md)）。Phase 1：键由脚本以 `PX` 设置 TTL；`ip` 实体按 IPv6 /64 计，单个用户不会制造无界的键（D-24）；`XADD MAXLEN ~ stream_maxlen`；进程内表满时落到溢出桶，从不逐出有效项。Phase 2：打开 `events.stream` 之前先设 `maxmemory = 24 小时峰值 × 2 + stream_maxlen × 400 B`；`used_memory / maxmemory > 0.8` 告警 | Phase 1 实现（`edge-core/tests/state_lua.rs::mg_gcra_matches_gcra_check_on_every_case`、`edge-core/tests/state_service.rs::local_table_overflow_bucket`） |
| VK-06 | E | 通过管理类命令（CONFIG、MODULE、DEBUG 等）扩大权限 | 取得大脑 VM | ACL 对非管理用户禁用管理类命令；Valkey 跟随安全更新。Phase 1：Edge 用户 `-@all` 之后只放行所需命令，`CONFIG`、`FLUSHALL`、`SCRIPT FLUSH` / `KILL` 等实测返回 NOPERM | Phase 1 实现（`edge/tests/valkey_acl.rs::edge_acl_user_can_do_exactly_what_the_edge_needs`） |
| VK-07 | S | 开发环境 Valkey 暴露到局域网 | 开发数据被读写 | `deploy/compose/` 中的端口只绑定 127.0.0.1；开发环境不使用生产密钥与数据 | Phase 0 实现 |

### 4.8 事件管道（EventSink → VictoriaLogs、Valkey Stream、VictoriaMetrics）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| EVT-01 | S | 向 VictoriaLogs / VictoriaMetrics 写入伪造事件或指标 | 分析被污染，调参被误导 | 只在私网 / 回环监听；写入端认证或只经 WireGuard（具体方式需实测）；事件不作为审计依据。Phase 1：`http://` 的 VictoriaLogs 地址只接受回环 / 私网 IP 字面量，否则必须 https（I-11） | Phase 1 实现（出口地址规则）；写入端认证需实测 |
| EVT-02 | T | 事件被篡改或删除以掩盖操作 | 调查结论错误 | 事件不是审计记录；审计日志独立成链（[06](06-policy-console-observability.md)「审计」） | 设计已覆盖 |
| EVT-03 | R | 事件静默丢失 | 无法复盘 | `mg_event_dropped_total`；缓冲满时先丢放行流量的采样事件，保留处置事件（[02](02-data-flow.md)、[01](01-architecture.md)「部署与高可用」）。Phase 1：VictoriaLogs、文件、`mg:ev` 三个输出各有积压队列与刷写任务，任一输出故障只丢自己的记录（I-25），计 `mg_event_dropped_total{sink, class}`。已知缺口：平滑重启期间仍在处理的请求的事件记为 `sink="buffer"` 丢弃。Phase 2（D-62）：关闭时事件刷写最多再等 `shutdown_drain_ms`（在升级宽限时间之内），这段时间内结束的请求照常写出；遥测是独立的第四个类别 | Phase 1 实现（`edge-core/tests/events_pipeline.rs::full_queue_drops_new_records_and_p0_goes_first`、`::hanging_victorialogs_does_not_hold_back_file_or_stream`）；Phase 2 实现（`edge-core/tests/events_drain.rs::drain_delivers_every_class_and_ends_when_empty`、`::drain_is_bounded_by_its_time_limit`） |
| EVT-04 | I | 事件中的访客个人信息被过度保留或越权查询 | PIPL 风险 | DecisionEvent 最小化；Cloudflare 精确位置头只保留国家、地区、时区；`x-mg-cf-tls-random` 不写入任何事件；保留期固定：DecisionEvent 明细 30 天（`vl-main`，IP 明文只在此处），Challenge / SDK 遥测事件 7 天（`vl-short`），不含个人标识的聚合随指标存 13 个月，最小访问记录（假名化、不采样）每日归档 ≥ 6 个月；越权查询见 CON-05（[02 §9](02-data-flow.md#9-采样与保留)、[06 §7](06-policy-console-observability.md#7-隐私与合规)）。Phase 1：路由设 `redact_path` 时事件与访问记录以 `/<route name>` 代替路径（D-31）；遥测按已知字段重新序列化。已知缺口：选中路由之前就应答的请求记录原始路径（R-12）。Phase 2（D-62，I-35 复审）：选中路由之前就应答的请求，路径 ≤ 8 KiB 且站点有路由表时同样按 `redact_path` 改写，超长路径只记 `/…` 与 `path_len`；`mg:ev` 的路径只有 `K_pseudo` 的 HMAC；遥测写 `vl-short`（7 天） | Phase 1 实现（`edge/tests/events_sink.rs::four_kinds_with_envelopes_sampling_and_redaction`、`edge-core/tests/events_encoding.rs::path_redaction_and_access_path`）；Phase 2 实现（`edge/tests/events_sink.rs::early_answers_follow_redact_path`、`edge-core/tests/events_stream_v2.rs::path_hash_and_entity_keys_match_the_samples`）；保留期由所有者在 VictoriaLogs 上配置 |
| EVT-05 | I | 访客可控的字符串（UA、路径、头名）在 vmui / Grafana / Console 中被当作 HTML 执行 | 所有者浏览器被 XSS | 结构化 JSON 编码写入；展示端一律转义（见 CON-04） | Phase 1 实现（结构化 JSON 写入）；展示端转义见 CON-04 |
| EVT-06 | D | 事件洪泛占满 Edge 内存或阻塞请求 | 延迟上升、OOM | 内存有界环形缓冲（可选小磁盘溢写），写出永不阻塞请求；按优先级丢弃（[ADR-0007](adr/0007-lean-deployment.md)）。Phase 1：三级有界队列、没有磁盘溢写，`try_send` 从不阻塞，队列满即丢弃并计数 | Phase 1 实现（`edge-core/tests/events_pipeline.rs::try_send_never_blocks_and_rejects_raw_newlines`） |
| EVT-07 | D | 指标高基数（按 IP、会话打标签） | VictoriaMetrics 内存耗尽 | 指标标签只用 site、route、action、class 等有界维度（[06](06-policy-console-observability.md)「日志、指标与告警」） | Phase 0 实现（只有请求计数器）；Phase 1 实现（`edge/tests/metrics.rs::every_family_is_served_with_its_labels`） |
| EVT-08 | E | 近线 worker 回写 verdict 时越权 | 任意改写状态 | worker 使用独立服务凭证与 ACL 用户，只能写 verdict 前缀（同 VK-02）。Phase 2：ACL 用户 `mg-nearline` 只能读写 `mg:ev` 与本站点的 `mg:v:<site>:*`，没有 pub/sub；ACL 无法限定"只经脚本写入"，"不覆盖所有者 verdict"是脚本的性质（NL-03） | Phase 2 实现（Go `nearline` 的 `TestACLUserRunsEveryOperation`、`TestVerdictPutRules`） |

### 4.9 Console

Phase 1–2 没有 Console，用 mgctl 与 vmui（或可选 Grafana）；Console v1 在 Phase 3 交付（[06](06-policy-console-observability.md)「管理后台」）。

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CON-01 | S | 钓鱼或会话劫持 | 所有者身份被冒用 | passkey（抗钓鱼）为主；`__Host-` 会话 Cookie、SameSite=Strict、会话超时；只绑定内网或 WireGuard 地址 | Phase 3 实现 |
| CON-02 | T | CSRF 触发策略变更 | 防护被关闭 | SameSite + CSRF token + Origin 校验；放宽类操作需重新认证（同 CP-05） | Phase 3 实现 |
| CON-03 | R | 查看含个人信息的明细没有记录 | 无法证明数据被正当使用 | 调查查询与导出写审计（[06](06-policy-console-observability.md)「审计」） | Phase 3 实现 |
| CON-04 | I | 展示访客可控数据时发生 XSS | 所有者会话被接管 | 严格 CSP；React 默认转义；事件数据不使用原始 HTML 渲染 | Phase 3 实现 |
| CON-05 | I | 只读账号看到明文个人信息 | 超出必要范围的访问 | `viewer` 默认脱敏 IP 等个人信息，不能导出含个人信息的明细（[06](06-policy-console-observability.md)「管理后台」） | Phase 3 实现 |
| CON-06 | D | Console 不可用，所有者无法处置误伤 | 误伤持续 | mgctl 作为不依赖 Console 的备用通道；回退类操作不加摩擦（见 §5.2） | Phase 3 实现 |

### 4.10 Validation Lab（`lab/`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| LAB-01 | E | Lab 被配置或误用为向非自有目标发送流量 | 干扰第三方，违反项目边界 | `lab/internal/guard` 在发出任何请求前强制目标白名单：默认只允许回环、`localhost`、`*.test`、`*.localhost`，另可登记自有 staging 主机（`owner_targets`），白名单外一律拒绝；Lab 只回放所有者自己的 E2E 用例与手工录制的真人会话，不包含任何针对第三方防护的代码（[07](07-roadmap.md)） | Phase 0 实现（工具层白名单） |
| LAB-02 | S | 域名解析或重定向把已放行的主机名导向白名单外的地址 | 同 LAB-01 | guard 在建立连接时对实际解析出的地址再次校验（防 DNS 重绑定），`allow_hosts` / `allow_suffixes` 只能解析到回环或私网地址，`owner_targets` 只能解析到登记的 `expected_cidrs`；每次重定向重新校验。以下地址无论配置如何都拒绝（配置中写入即报错）：链路本地 / 组播 / 未指定地址，可到达任意 IPv4 的 IPv6 过渡前缀（NAT64 `64:ff9b::/96`、`64:ff9b:1::/48`，6to4，Teredo），以及不在链路本地的云元数据端点（AWS `fd00:ec2::254` 位于 ULA 内、GCP `fd20:ce::254`、阿里云 `100.100.100.200`、Oracle `192.0.0.192`）。第二层：Lab 在 compose `lab` profile 的 `internal: true` 网络中运行，Docker 不提供离开本机的路由；该网络设置 `com.docker.network.bridge.inhibit_ipv4`，宿主机在其中没有地址（只设 `internal` 时容器仍可经网关地址访问宿主机上监听 0.0.0.0 的服务），只能访问同一网络中的 `*.lab.test` 服务（`deploy/compose/docker-compose.yml`、`lab/config/lab.compose.yaml`）；`scripts/lab-egress-check.sh` 以默认网络上的对照容器为参照，验证绕过工具的客户端在 `lab` 网络上连不到宿主机，并在 Linux 上确认宿主机在 `lab` 子网内没有地址（[07](07-roadmap.md)） | Phase 0 实现（工具层 + 网络出口层；出口层只在 CI 中实际运行） |
| LAB-03 | T | 白名单被随意扩大 | 同 LAB-01 | 白名单在仓库中版本化，变更经所有者自审；未知配置字段直接报错；`owner_targets` 必须声明 `expected_cidrs`；**提议**：登记自有主机前要求所有权证明（如在该主机放置校验文件） | 待定（所有权证明） |
| LAB-04 | D | Lab 回放压垮所有者的生产站点 | 自有站点不可用 | guard 对整个进程限速（默认 5 rps，配置上限 50 rps）；`owner_targets` 只登记 staging 主机，不登记生产主机（约定） | Phase 0 实现（速率上限） |
| LAB-05 | I | 录制的真人会话含所有者个人信息 | 隐私泄露 | 录制数据不进仓库，本地加密存放并脱敏 | 设计已覆盖（Phase 1 的 Lab 只回放仓库内固定的场景，不含录制会话） |
| LAB-06 | R | 无法追溯哪次运行访问了哪个目标 | 事后无法复查 | 每次运行记录目标、时间、用例与结果；被拒绝的目标同样记录 | 部分实现：`mglab replay` 逐请求输出目标、状态、耗时与判定，guard 拒绝的目标报错退出（`lab/internal/cli/cli_test.go`）；`make lab-e2e` 输出运行 ID 与逐项 PASS / FAIL；持久的运行记录待定 |

### 4.11 供应链与 CI（`.github/workflows/ci.yml`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| SC-01 | T | 依赖投毒（crates.io、Go 模块代理、npm） | 恶意代码进入 Edge 或 SDK | 提交锁文件（`Cargo.lock`、`go.sum`、`pnpm-lock.yaml`），CI 使用 `--frozen-lockfile`；Pingora 固定 `=0.9.0`；依赖最小化；引入 cargo-deny / cargo-audit、govulncheck、依赖审计 | Phase 0 实现（锁文件、`--frozen-lockfile`、CI 检查 Pingora 固定为 `=0.9.0`）；Phase 1 之后：漏洞与许可证扫描已引入（`.github/workflows/audit.yml`，每个 PR 与每周运行；`make audit`）：cargo-deny（`deny.toml`：RustSec 公告与已撤回版本失败、只允许宽松许可证、只允许 crates.io 来源）、两个 Go 模块的 govulncheck（也检查所用 Go 版本的标准库，所以 Go 跟随仍受支持的版本，现为 1.27）、Web SDK 的 `pnpm audit` |
| SC-02 | T | CI 流水线被篡改或第三方 Action 被劫持 | 构建产物被植入代码 | workflow 顶层 `permissions: contents: read`；checkout 使用 `persist-credentials: false`；PR 流水线（`pull_request`）不使用任何密钥；所有 Action 固定到 commit SHA（注释标出对应版本）；CI 下载的 protoc 发布包校验 SHA-256。Phase 1：CI 的 Valkey 服务容器按镜像 digest 固定 | Phase 0 实现 |
| SC-03 | I | 密钥进入 CI 日志或仓库 | 生产密钥泄露 | CI 不持有任何生产密钥；Turnstile 只用官方测试 sitekey / secret（[09](09-interactive-challenge.md)） | 设计已覆盖 |
| SC-04 | T | 生成代码与 `.proto` 不一致（生成代码被手改） | 数据契约在 Rust 与 Go 之间漂移 | Rust 在 `build.rs` 中生成；Go 生成代码由 `make proto` 产生并提交，CI 用同一版本的 protoc 重新生成并 `git diff --exit-code` | Phase 0 实现 |
| SC-05 | S | 部署的二进制不是由仓库构建 | 未知代码运行在 Edge | 在自有主机从源码构建；SBOM 与产物签名（cosign）（[06](06-policy-console-observability.md)「平台自身安全」） | 待定 |
| SC-06 | D | 0.x 依赖的破坏性升级 | 无法及时打补丁 | Pingora 代码只在 `edge/`；升级在分支上适配并跑完整回归后再改 pin；CI 检查 `Cargo.toml` 与 `Cargo.lock` 中的 Pingora 版本（[ADR-0002](adr/0002-edge-pingora-boringssl.md)） | Phase 0 实现 |
| SC-07 | E | 项目代码中混入进攻性能力（绕过第三方防护、对外发流量） | 违反项目边界 | 仓库约定（`CLAUDE.md`）写明只做防御、不写绕过任何防护的代码，除 Lab 外，测试流量只留在本机（回环测试：`scripts/edge-smoke.sh`、`edge/tests/`、Go `httptest`；`scripts/lab-egress-check.sh` 只用本机 Docker 网络）；Lab 白名单（LAB-01）；自审时检查新增的出站网络代码 | Phase 0 实现（约定） |

### 4.12 近线 worker（`control-plane/cmd/mg-nearline`，Phase 2）

近线 worker 消费 `mg:ev`（组 `nl`），在内存中维护窗口，按检测器 v1 写出 verdict（[02 §4](02-data-flow.md#4-近线会话与实体分析)、[规格 §13](impl/phase2-spec.md#13-近线-worker-mg-nearlinewp-n1mgev-v2-的写入归-wp-c5--e2b)）。它不在请求路径上：worker 停止时 stream 截断，已写的 verdict 按 TTL 过期，Edge 照常按规则评分。

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| NL-01 | S | 第三方网页让访客的浏览器请求诱饵路径或制造高速率，借近线给无辜访客加风险 | 误伤 | 浏览器代发的跨站子资源请求（`xs = 1`）与带有效凭证的请求不计入 `scanner` 与 `high_rate`；verdict 只抬高风险、从不带 `scanner` 标签，被抬高风险的人类访客仍能通过挑战（D-53） | Phase 2 实现（`TestScannerSkipsTokenAndCrossSite`、`TestHighRateCountsOnlyHTMLJSONOther`） |
| NL-02 | D | CGNAT、校园网与办公网的共享出口被当作单个实体 | 一个前缀上的所有访客都被挑战 | `high_rate` 在窗口内出现 ≥ 3 个不同会话或 UA 家族时视为共享出口，不产生 verdict；不产生 `asn` 类 verdict；检测器缺省 shadow，所有者按 ASN 检查误伤后逐个改为 enforce；所有者可写 `source = "owner"`、`risk = 0` 的 verdict 压住误伤，近线不会覆盖它 | Phase 2 实现（`TestHighRateSharedEgress`、`TestModesInVerdicts`）；enforce 前的误伤检查由所有者完成（规格 §19 第 6 步） |
| NL-03 | T | worker 覆盖所有者手写的 verdict，或越权写其他站点与其他键 | 所有者的压制失效；任意改写状态 | `mg_verdict_put` 从不覆盖所有者或无法解析的值，其他检测器的 verdict 只在新风险更高时覆盖；ACL 用户只能读写 `mg:ev` 与本站点的 `mg:v:<site>:*`，没有 pub/sub | Phase 2 实现（`TestVerdictPutRules`、`TestVerdictScriptMatchesSpec`、`TestACLUserRunsEveryOperation`） |
| NL-04 | D | 大量新键挤满窗口，或 worker 落后、stream 积压 | 检测失效；Valkey 内存不足 | 每类键至多 200,000 个，满时丢弃新键，已有键不被淘汰；`XADD MAXLEN ~`；`mg_nl_backlog > 10000` 或 `mg_nl_lag_seconds > 600` 告警；`MemoryMax=512M` | Phase 2 实现（`TestWindowFullDropsNewKeys`、`TestLagAndBacklog`、`TestReclaimManyEntries`） |
| NL-05 | I | worker 的日志、verdict 事件或指标泄露访客 IP | 隐私 | `mg:ev` 只有 `K_pseudo` 的 HMAC，没有 IP 明文、`jkt` 与路径原文；日志与 `kind=verdict` 只有伪名键；指标标签有界 | Phase 2 实现（`TestShadowAndEnforceOutputs`、`TestMetricsText`；`edge-core/tests/events_stream_v2.rs::entries_match_the_samples_field_for_field`） |
| NL-06 | E | worker 进程被利用后访问网络或其他资源 | 横向移动 | systemd `DynamicUser=yes`、`IPAddressAllow=localhost`、`IPAddressDeny=any`；Valkey URL 只能是 `unix://` 或回环 IP 字面量；配置值中只展开 `${CREDENTIALS_DIRECTORY}` | Phase 2 实现（`TestValkeyURLAndVLURL`、`TestCredentialsDirectoryRule`、`TestConfigRejects`） |
| NL-07 | R | 近线 verdict 无法追溯 | 无法解释为何风险被抬高 | verdict 带 `source = "nearline/<detector>"`、`version`、原因码与 `expires_at_ms`；可选 `kind=verdict` 写 `vl-main`，带证据计数；`mg_nl_verdicts_total{site, detector, mode}` | Phase 2 实现（`TestShadowAndEnforceOutputs`） |

### 4.13 出站与 Turnstile siteverify（`edge-core/src/outbound`，Phase 2）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| OUT-01 | S | siteverify 地址被改到攻击者控制的主机，或请求经代理 | 伪造的"通过" | 只允许精确的 siteverify URL；回环 mock 只在 `MG_EDGE_TEST_OUTBOUND=1` 时可用，否则启动与 `--check-config` 失败，生效时打 WARN 并置 `mg_outbound_override = 1`；reqwest `no_proxy()`，TLS 证书校验 | Phase 2 实现（`edge-core/tests/outbound_siteverify.rs::only_allowlisted_destinations_are_reached`、`edge-core/tests/outbound_no_proxy.rs::siteverify_ignores_proxy_environment`） |
| OUT-02 | T | 不合格或残缺的 siteverify 响应被当作通过 | 绕过 Turnstile 的绑定 | 只接受 200 与 `application/json`、≤ 16 KiB；`success = true` 却缺 `challenge_ts` / `hostname` / `action` / `cdata` 为 `Unavailable`；绑定全部满足才 `Pass`；外部 Provider 绝不 fail-open，它的通过也不能单独签发凭证 | Phase 2 实现（`edge-core/tests/outbound_siteverify.rs::shared_samples_map_as_specified`、`::binding_checks_and_metric_reasons`；cargo-fuzz `siteverify_response`） |
| OUT-03 | D | siteverify 缓慢或不可用拖住 Edge | 挑战端点变慢 | 截止时间 `min(timeout_ms, 5000)`；进程内并发上限 32（`busy` 不计入熔断）；熔断；校验只在后台服务 `mg-outbound` 上运行，没有到达它的校验为 `Unavailable` | Phase 2 实现（`edge-core/tests/outbound_siteverify.rs::concurrency_limit_answers_busy`、`::timeouts_retry_only_with_a_second_left`、`edge-core/tests/outbound_breaker.rs::half_open_allows_one_trial_and_backs_off`） |
| OUT-04 | I | secret 或 token 进入日志、事件或 `Debug` | secret 外泄 | `mg-turnstile-keys` 只经 systemd credential；`Debug` 不打印；D-31 清单增加 token 与 secret；文件格式错误时 `--check-config` 失败 | Phase 2 实现（`edge-core/tests/outbound_siteverify.rs::secrets_are_validated_and_never_printed`、`edge/tests/turnstile_flow.rs::check_config_rules`；cargo-fuzz `turnstile_keys`） |
| OUT-05 | I | 访客 IP、User-Agent 与 TLS 指纹经 Turnstile 发给 Cloudflare，包括大陆访客（D-70） | 跨境处理，PIPL 风险 | 只在所有者配置的主机、路由与国家范围内选用；`deny_countries` 可排除；隐私说明披露（[模板](privacy-notice-template.md)） | 设计已覆盖；隐私说明由所有者更新（规格 §19 第 2 步）；残余风险 R-08 |

## 5. 平台自身滥用与误伤风险

**结论**：对个人站点而言，误伤真人和把所有者锁在外面，比漏掉一部分自动化代价更高。所以默认姿态是先 shadow / monitor，放宽和回退永远比收紧容易；无障碍路径是 v1 的必需项，不是可选项。

### 5.1 误伤

| 风险 | 表现 | 控制 | 状态 |
|---|---|---|---|
| 新规则或新信号直接 enforce | 真人被挑战或阻断 | 一律 shadow → dry-run → 灰度；`EDGE_TLS` 与交互评分先 shadow；全局 monitor 开关（`SiteBundle.monitor_only`）；人类摩擦率告警（[03](03-risk-scoring.md)、[06](06-policy-console-observability.md)）。Phase 1：站点 YAML 的 `monitor_only` 缺省为 true；monitor 下超限请求也原样转发（I-2）。Phase 2：交互评分与近线检测器缺省 shadow；人类摩擦按 `mg_nl_interactive_visitor_share` 与 `mg_nl_interactive_abandon_share`（7 天）判断，超过阈值告警；本机应急开关 `force_monitor`（[ADR-0011](adr/0011-local-emergency-monitor-switch.md)） | Phase 1 实现（`edge/tests/decision.rs::monitor_evaluates_and_only_records`）；Phase 2 实现（摩擦率：Go `nearline` 的 `TestVisitorShare`、`TestAbandonShare`；告警：`edge/tests/alerts.rs::vmalert_rules_use_served_series`） |
| 缺失信号被当作自动化证据 | Cloudflare 之后的正常访客被加分 | `MISSING` 不计入置信度，`ABSENT` 只降低置信度，两者既不当人类证据，也不当自动化证据（[03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)） | Phase 1 实现 |
| 隐私工具用户（VPN、Tor、禁用第三方脚本、隐私浏览器） | 被当作自动化 | 这些特征单独不构成阻断依据；中风险优先 Challenge 而不是阻断（[03](03-risk-scoring.md#5-分级处置)）；Challenge 走第一方路径、不依赖第三方域名 | Phase 1 实现 |
| 合法自动化被拦（搜索引擎、RSS 阅读器、可用性监控、所有者自己的脚本、授权 Agent） | 收录下降、监控误报 | 已验证爬虫与用途矩阵；带过期时间和原因的允许名单；授权 Agent 与测试授权工单（[05](05-ai-agent-policy.md#2-分类)） | Phase 1 实现（爬虫、名单）；Phase 3 实现（Agent） |
| 双重挑战（Cloudflare 与 MorphGate 先后挑战） | 访客连续遇到两次验证 | Free 区关闭 Bot Fight Mode，`/__mg/` 的 Skip 规则只能跳过 `bic`、`securityLevel`；Pro 及以上可再 Skip SBFM；用限速规则挡 `POST /__mg/` 洪泛时不跳过 `http_ratelimit`（[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)）；SDK 处理 `cf-mitigated: challenge`，计入 `mg_double_challenge_total`（[08 §2.8](08-upstream-and-cloudflare.md#28-cf-mitigated-与双重挑战)）。Phase 2：SDK 收到 `cf-mitigated: challenge` 时重载并上报，同一页面 60 s 内只重载一次；`mg_double_challenge_total` 只计签名的报告 | Phase 1 实现（审计）；Phase 2 实现（SDK：`sdk/web/test/transport.test.ts`；指标：`edge/tests/refresh_telemetry.rs::telemetry_reports`） |
| 中国大陆访客 | 第三方 Challenge 不可用或很慢 | Turnstile 永不对大陆访客选用；自研 Challenge 走第一方 `/__mg/`，SDK ≤ 30 KB gzip（[09](09-interactive-challenge.md)）。Phase 2（D-70）：所有者决定大陆访客也可以选用 Turnstile；它在大陆不可用时，SDK 与 Edge 自动回退到内置验证、不计失败，最坏多等一次 5 s 的加载超时；所有者可以写 `deny_countries: [CN]` 恢复排除 | Phase 2 实现（回退：`sdk/web/test/turnstile.test.ts`、`edge/tests/turnstile_flow.rs::turnstile_end_to_end`）；大陆访客选用 Turnstile 后的实际效果待 shadow 期测量 |
| Cloudflare AI bot policy 默认值与 MorphGate 策略不一致 | 期望的爬虫在 Cloudflare 侧就被挡掉 | MorphGate 为唯一权威；`mgctl cf audit` 检查 AI bot policy（[05](05-ai-agent-policy.md)、[08](08-upstream-and-cloudflare.md)） | Phase 1 实现 |
| 误伤后无法定位原因 | 访客无从申诉 | 失败页带 request_id；按 request_id 检索判定解释（[06](06-policy-console-observability.md#7-隐私与合规)） | Phase 1 实现 |
| 近线检测器误伤共享出口、监控探针与代理出口 | 一个前缀或出口上的访客被抬高风险、被挑战 | 检测器缺省 shadow；按 ASN 检查 shadow verdict 至少 7 天再逐个 enforce；verdict 只抬高风险、不阻断；所有者可写 `risk = 0` 的 verdict 压住误伤（NL-02） | Phase 2 实现（shadow 与压制）；误伤检查由所有者完成 |
| 持有证明路由上的访客陷入挑战循环（密钥被清除、存储被禁用、跳转后的 `htu` 不符） | 接口反复失败 | 可豁免的导航不要求证明；就地恢复与时钟偏差校正；跳转后 GET / HEAD 用新证明重试一次；`proof: required` 路由上非 `valid` 的比例 > 5% 告警；先以 `mode: monitor` 观察（SDK-12） | Phase 2 实现（`edge/tests/proof_flow.rs::in_place_recovery`、`sdk/web/test/fetch.test.ts`）；分路由启用由所有者进行 |

### 5.2 所有者被锁定

| 场景 | 控制 | 状态 |
|---|---|---|
| 所有者自己的浏览被挑战或阻断 | 所有者也走同一套 Challenge（可以通过）；可选带过期时间的所有者允许名单；阻断页带 request_id 便于自查 | Phase 1 实现 |
| 策略错误导致全站被拦 | 全局 monitor 开关；回滚到上一版本不需要重新认证；Edge 保留 last-known-good | Phase 1 实现 |
| 控制面或 Console 不可用时需要止损 | **提议**：Edge 主机上的本地应急开关（经 SSH 修改本地文件，强制 monitor 模式并写本地审计），不依赖大脑 VM；它是"放宽只经签名配置包"（[02 §6](02-data-flow.md#6-配置模型与密钥下发)）的例外，需在 ADR 中写明。Phase 2（D-60）：已实现为 `edge.toml` `[[sites]] force_monitor = true`，经 SSH 修改后 reload 生效；用 WARN 日志、`mg_site_forced_monitor` 与决定事件的 `forced_monitor` 代替单独的本地审计文件（[ADR-0011](adr/0011-local-emergency-monitor-switch.md)） | Phase 2 实现（`edge/tests/proof_flow.rs::force_monitor`） |
| passkey 丢失 | 至少注册两个 passkey；TOTP 备用；一次性离线恢复码；TOTP 使用会通知（[06](06-policy-console-observability.md)「管理后台」） | Phase 3 实现 |
| 所有者的管理通路依赖被保护的站点 | Console 与 Admin API 只在内网 / WireGuard 上提供，不经过 Edge 的执法路径；主机管理走 WireGuard 或云厂商控制台，不依赖被保护的站点 | 设计已覆盖 |
| 生效延迟期间需要紧急回退 | 回退与止损类操作（回滚、吊销、紧急停止）不加摩擦（[06](06-policy-console-observability.md)「管理后台」） | Phase 3 实现 |

### 5.3 无障碍

交互式 Challenge 的无障碍要求见 [09](09-interactive-challenge.md) 与 [ADR-0008](adr/0008-interactive-challenge-self-built.md)，本节只列威胁模型关心的点。

| 风险 | 控制 | 状态 |
|---|---|---|
| 认知测试把部分用户挡在外面（WCAG 3.3.8 / 3.3.9） | 不做滑块、点选、旋转、扭曲文字、音频题 | 设计已覆盖 |
| 无法使用指针或无法长按 | 键盘按住 Space / Enter；"无法按住？"切换为两次按键；`pow_a11y` 非交互路径；站点有登录时提供 passkey 或邮件链接替代。Phase 2（D-65、D-56）：键盘与"无法按住？"合并为单次激活（按一次或点一次，不要求按住或第二次按下）；站点账号替代推迟 | Phase 2 实现（`sdk/web/test/interactive.test.ts`、`edge/tests/interactive_flow.rs::single_activation_and_pow_a11y`）；辅助技术实测由所有者完成（规格 §19 第 5 步） |
| 计时压力（WCAG 2.2.1） | 交互式 C 约 10 分钟有效，到期前 SDK 静默续期；无可见倒计时。Phase 2：交互式 C 600 s，SDK 在 `iat + 480 s` 之后静默续期，链上限 6 次（约 1 小时）；续期的结果从不改变状态文字 | Phase 2 实现（`edge/tests/interactive_flow.rs::renew_endpoint_answers_and_schema_1`、`sdk/web/test/interactive.test.ts`） |
| 无障碍模式被评分为可疑 | 键盘 / 切换 / 无障碍模式跳过指针特征，缺失的指针数据为中性；无障碍路径使用率与失败率单独监控。Phase 2：选择无障碍路径本身从不计分；`__Host-mg_a11y` 不进入策略与事件（SDK-10）；`mg.a11y.issue` 超限时改用单次激活，不计失败 | Phase 2 实现（`core/src/providers/tests.rs::accessible_paths_get_no_pointer_features`） |
| 读屏与动效 | 目的说明文本、aria-live、prefers-reduced-motion、zh-CN / en；验收要求用键盘与读屏完成验证（[07](07-roadmap.md)）。Phase 2：状态文字经 `#mg-status` 播报，每次转移一次；焦点不移动；reduced motion 与 forced colors 的样式；文案只来自规格 §12.7 | Phase 2 实现（`sdk/web/test/template-v2.test.ts`、`sdk/web/test/interactive.test.ts`）；读屏与仅键盘的实测由所有者完成 |

### 5.4 平台被滥用

| 风险 | 控制 | 状态 |
|---|---|---|
| 超出安全目的追踪访客 | 行为特征只用于区分自动化，不用于识别具体个人；不做跨站追踪；高熵指纹默认关闭；限期保留；隐私声明披露（[06](06-policy-console-observability.md#7-隐私与合规)）。Phase 2：会话公钥满 7 天或凭证失效即换新，`jkt` 只以 HMAC 出现在键中；行为摘要缺省关闭；隐私说明模板（[privacy-notice-template](privacy-notice-template.md)） | 设计已覆盖 |
| 平台被用来向他人发送流量 | Lab 白名单两层强制（LAB-01、LAB-02）；Edge 不是开放代理（EDG-11） | Phase 0 实现（工具层 + 网络出口层） |
| 平台被提供给他人使用 | 不对外提供，包括托管服务；将来要保护他人站点需新 ADR，重新评估租户隔离、JA4+ 许可与合规（[ADR-0010](adr/0010-single-owner-model.md)、[ADR-0009](adr/0009-ja4-only-licensing.md)） | 设计已覆盖 |

## 6. 残余风险与接受理由

**结论**：以下风险在个人预算与单人运维下无法消除，明确接受；每条都给出触发复审的信号。

| 编号 | 残余风险 | 为何无法消除 | 接受理由 | 监控信号 / 复审触发 |
|---|---|---|---|---|
| R-01 | 人工代解与打码服务通过交互式 Challenge | 已发表研究显示其对常见交互式 Challenge 成功率接近 100%，每千次约 $0.10–5 | 目标是抬高成本，不是不可绕过；交互通过只算封顶的人类证据，并受签发配额与短 TTL 限制 | 解题时间分布异常、通过率突然接近 100%、单前缀 / ASN 签发量接近上限；Phase 2：`mg_interactive_score` 分布、近线 `challenge_abuse` 的 shadow verdict |
| R-02 | 能执行 JS 的自动化浏览器 + 住宅代理（A3）部分漏过 | 没有单一控制点能覆盖 A3 / A4 | 个人站点的损失有限；多层信号、限速与业务侧限额叠加 | 自动化占比趋势、敏感路由的成功率异常 |
| R-03 | Cloudflare Free / Pro 之后没有访客的 TLS / HTTP/2 指纹 | 访客 JA4 只提供给购买了 Bot Management 的 Enterprise 客户，超出预算 | 以 `EDGE_TLS` 弱信号、SDK、行为与 Challenge 补足 | 套餐变化；`EDGE_TLS` shadow 数据显示可以提权 |
| R-04 | 依赖 Cloudflare 作为可信上游 | Cloudflare 自身失陷或行为变化超出本模型 | 单一供应商依赖换来零成本的源站隐藏与 DDoS 吸收 | Cloudflare 安全公告；`mgctl cf audit` 结果变化 |
| R-05 | 单人运维，没有第二个人审批 | 只有所有者一人 | 以重新认证、输入确认、生效延迟与通知、审计锚点补偿（[ADR-0010](adr/0010-single-owner-model.md)） | 审计中出现非预期的敏感操作；TOTP 被使用 |
| R-06 | 受保护站点自身的 XSS 在页面打开期间调用会话密钥 | 持有证明只证明"持有密钥的客户端"，不证明是人；站点应用漏洞不在范围 | 凭证短寿命、`HttpOnly`、不可导出密钥已限制影响 | 同一会话的请求模式突变 |
| R-07 | 大脑 VM 单点 | 个人预算只有一台大脑 VM | 故障只降级不宕机（`critical` 路由可能暂停签发凭证，见 EDG-09）；每晚备份 | 降级模式持续时间；备份恢复演练结果 |
| R-08 | 启用 Turnstile 时访客 IP、TLS 指纹、UA 发往 Cloudflare | Provider 工作方式决定 | 按站点启用、隐私声明披露；Phase 2 起大陆访客也可选用（D-70），所有者可按国家排除 | 隐私法规或 Turnstile 条款变化；Phase 2（D-70）起大陆访客也可能被选中，按 `deny_countries` 与隐私说明处理，选用后的实际效果在 shadow 期复审 |
| R-09 | 数据最小化与日志留存要求之间的张力 | 《网络安全法》要求网络日志留存不少于六个月 | DecisionEvent 明细 30 天、遥测事件 7 天；最小访问记录（假名化、不采样）每日归档 ≥ 6 个月（EVT-04）；归档是否需要 IP 明文等口径需法务确认 | 法规更新；法务意见；源站自身访问日志已满足要求时关闭归档 |
| R-10 | Pingora 0.x 与其他早期依赖的安全修复需要跟随破坏性升级 | 上游节奏不受控制 | Pingora 代码隔离在 `edge/`，升级走回归 | Pingora 安全公告；依赖审计报告 |
| R-11 | Valkey 不可用期间，非 `fail_closed` 路由签发未经重放检查的凭证（`ruc`） | 只有一台大脑 VM；全站 fail-closed 会把 Valkey 故障变成全站不可用 | 这类凭证受 `uah` / `ipp` 绑定、C ≤ 120 s 的寿命与本地签发配额约束，`fail_closed` 路由不接受（CH-14） | `mg_state_mode{mode="local"}` 告警；决定事件的 `token.replay_unchecked`（只在采样后的事件上） |
| R-12 | 选中路由之前就应答的请求（外部 Worker 403、监听器 403、monitor / bootstrap 下的超限请求）在事件中记录原始路径，不受 `redact_path` 约束 | 这些应答发生在路由匹配之前；超限请求为控制代价跳过路由匹配 | 实际多为攻击或配置错误的流量；访问记录中的路径截断到 1024 字节 | Phase 1 接受（[I-35](impl/phase1-spec.md#集成者裁决2026-09-28优先于正文)）；Phase 2 复审后（D-62）只剩 bootstrap 与 `lkg_invalid`（没有路由表）时记录原始路径，超长路径只记长度；`mg_cf_foreign_worker_total`、`mg_listener_rejected_total` 异常 |
| R-13 | `self_hold` 的检查除服务端时间窗外都依赖客户端自报的数据，自己控制客户端的自动化以 PoW 加 1.2–2.5 s 的等待就能取得交互级凭证（CH-15） | 浏览器端的任何信号都可以伪造；更强的检查需要学习型模型与足够的标签 | 交互级凭证的人类证据不高于 `pow`（D-68），刷新缺省关闭且封顶（D-47），签发配额与短 TTL；交互式只用于极少数会话 | 交互评分的 shadow 分布与所有者流量；考虑 enforce 之前（规格 §21）；`challenge_abuse` 的 shadow verdict |
| R-14 | 未绑定会话密钥的交互式 C 在同一 ASN 内可被另一个客户端提交（CH-17） | 首次挑战时客户端还没有绑定的密钥；同一 ASN 内的前缀变化本来就是软结果 | SDK 在用户操作之前先续期绑定，窗口只在首次续期之前；已绑定的 C 100% 拒绝跨客户端提交 | `ic.bind_ipp_soft` 的频率 |
| R-15 | 能登录 Edge 主机的人不经签名即可把站点放宽为 monitor（`force_monitor`，ADR-0011） | 所有者需要不依赖签名工作站的止损通道 | 改 `edge.toml` 需要 root，root 本来就能替换二进制或读密钥（H2）；生效期间每小时 WARN、指标持续 1 小时告警 | `mg_site_forced_monitor == 1`；主机登录记录 |
| R-16 | IndexedDB 不可用时会话私钥以可导出的 JWK 存在 localStorage，站点自身的 XSS 能读走它（SDK-06） | 部分浏览器与隐私设置下 IndexedDB 不可用；只放内存会让 `proof: required` 接口无法使用 | 凭证 Cookie 是 HttpOnly，读走私钥也拿不到凭证；密钥满 7 天或凭证失效即换新；遥测记录 `ks` 的分布 | `ix.ks = local` 的比例；按 `ks` 分组的重新挑战率（规格 §21） |

## 7. 复审节奏

**结论**：每个 Phase 结束必审（与 [07](07-roadmap.md)「贯穿各阶段」一致），另有事件触发的复审；平时用月度和季度的轻量检查维持。

| 频率 | 内容 | 产出 |
|---|---|---|
| 每个 Phase 结束 | 更新 §4 的状态列（写明验收用例）；为新组件补 STRIDE 表；复核 §6 | 文档新版本（v1 对应 Phase 1 结束） |
| 事件触发 | 新增对外端点、UpstreamProfile、Provider 或密钥类型；入口变化（Tunnel 改 AOP、源站暴露）；Cloudflare 套餐变化；Pingora 或关键依赖升级；安全公告；疑似密钥泄露或安全事件；新站点接入（尤其有登录、有收入或面向大陆访客） | 受影响章节的增量修订 |
| 每月 | `mgctl cf audit` 结果；Cloudflare API Token 与 tunnel connector 核对；密钥轮换状态；误伤申诉与人类摩擦率；事件丢弃计数 | 检查记录（写入审计或运维笔记） |
| 每季度 | 备份恢复演练；Lab 白名单复核；账号与凭证复核（passkey、TOTP、API Token、只读账号）；依赖漏洞报告 | 检查记录；必要时触发修订 |
| 每年 | 完整重做 STRIDE；评估是否安排经授权的第三方渗透测试（[06](06-policy-console-observability.md)「平台自身安全」） | 新主版本 |

**版本记录**

| 版本 | 日期 | 说明 |
|---|---|---|
| v0 | 2026-09-27 | Phase 0 初版：个人部署拓扑、资产、信任边界、分组件 STRIDE、误伤与残余风险；同日按 v0.2.1 一致性裁决修订（密钥保管、保留期、降级、Early-Data、请求体上限） |
| v0.9 | 2026-09-28 | Phase 1 代码完成后的勘误（WP-D1）：§4 状态列写出测试；新增 EDG-13（日志泄露）、EDG-14（源站信任的改写头与 `_method`）、CH-14（未经重放检查的凭证）、SDK-08（模板占位符上下文）、AS-K12、AS-K13、R-11、R-12；VK-02 的提议已采纳（D-10）。LAB 条目待 WP-L1 结束后更新；v1 在所有者验收后定稿 |
| v1 | 2026-10-12 | Phase 2 代码完成后的修订（WP-D2）：新增 §4.12 近线 worker、§4.13 出站与 Turnstile siteverify；新增 EDG-15..18、DC-10..11、CH-15..21（含 `self_hold` 检查除服务端时间窗外都依赖客户端自报数据的说明）、SDK-09..12、CP-10、NL-01..07、OUT-01..05、AS-K14、AS-K15、R-13..R-16；Phase 2 交付的条目改为已实现并写出测试；§5.2 的本机应急开关由提议改为 ADR-0011；Turnstile 的地区范围按 D-70 修订。Phase 1 的所有者验收仍在进行，验收中的发现按 §7 增量修订 |

## 参考

- Cloudflare AOP（zone-level）：https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/
- Cloudflare IP 段：https://api.cloudflare.com/client/v4/ips
- Cloudflare 0-RTT：https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/
- Cloudflare 缓存行为：https://developers.cloudflare.com/cache/concepts/cache-behavior/
- Super Bot Fight Mode：https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/
- Request Header Transform Rules：https://developers.cloudflare.com/rules/transform/request-header-modification/
- Turnstile 服务端校验：https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
- Turnstile 主机名管理：https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/
