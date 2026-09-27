# 10 威胁模型（STRIDE v0）

**结论**：v0 对应 Phase 0（2026-09-27），覆盖 [07](07-roadmap.md) 推荐的个人部署：Cloudflare → Tunnel → Edge → 源站，外加一台大脑 VM。当前最需要守住的五条：

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

**结论**：最敏感的是能"让 Edge 相信某件事"的密钥（凭证密钥、Challenge 密封根密钥、配置签名密钥、AOP CA 与 Agent mTLS CA）和能改 Cloudflare 侧配置的 API Token。凭证、密封、Turnstile、MessageMAC 密钥按站点；配置签名与审计锚点签名是所有者各一对。全部以本机加密文件交付（systemd credentials；工作站上 age），不进配置包、不进仓库（[02 §6](02-data-flow.md#6-配置模型与密钥下发)、[06 §8](06-policy-console-observability.md#8-平台自身安全)）。

| 编号 | 资产 | 所在位置 | 关键属性 | 泄露 / 篡改后果 | 轮换与保护 |
|---|---|---|---|---|---|
| AS-K1 | 凭证密钥（PASETO v4.local，按 `kid`，按站点） | Edge 主机（systemd credential）；Edge 内存 | 机密性、完整性 | 可伪造该站点任意等级的访问凭证 | 30 天滚动轮换；有 TPM2 时绑定；配置包只含 `kid`（[04 §5](04-challenge-and-tokens.md#5-短期访问凭证)、[06 §8](06-policy-console-observability.md#8-平台自身安全)） |
| AS-K2 | Challenge 密封根密钥 `K_seal_root`（按站点）及派生的 `k_epoch`、`k_bind_epoch` | 根密钥：Edge 主机（systemd credential）；epoch 密钥：Edge 内存 | 机密性、完整性 | 根密钥泄露可伪造该站点的 Challenge 或绕开 cData 绑定；单个 epoch 密钥泄露只影响该 epoch，不暴露根密钥 | 根密钥年更或泄露时轮换；各 Edge 以 HKDF-SHA256（info `mg-seal-v1` / `mg-bind-v1` ‖ site ‖ epoch_no）确定性派生 epoch 密钥，24 小时一换、接受当前与上一个，无需每日分发（[04 §4.1](04-challenge-and-tokens.md#41-密封-challenge-与验证顺序)、[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)） |
| AS-K3 | 配置签名密钥（所有者一对 Ed25519，签 `SignedBundle` 与吊销消息） | Phase 1–2：所有者工作站，age 加密，由 mgctl 使用；Phase 3 起：大脑 VM 的 mg-control（systemd credential）；Edge 只有公钥 | 完整性 | 可向 Edge 下发任意策略或吊销，包括关闭防护 | 按 `kid` 年更；不放在 Edge 上；见 CP-04 |
| AS-K4 | Turnstile secret（每站点一个 widget） | Edge 主机（systemd credential，配置只写 `secret_ref`）；Edge 内存 | 机密性 | 可冒用本站 widget 做 siteverify；影响限于该站点 | 轮换期间 Edge 同时持有新旧 secret；`invalid-input-secret` 自动禁用该 Provider（[09](09-interactive-challenge.md)） |
| AS-K5 | Cloudflare API Token（`cf-audit`、`cf-turnstile`、可选 `cf-push`） | mgctl / mg-control 所在主机（systemd credential；工作站上 age 加密） | 机密性 | 写权限 token 泄露可修改 zone 配置、关闭源站保护 | 按用途拆分、最小权限；`cf-push` 默认不创建（[06 §8](06-policy-console-observability.md#8-平台自身安全)） |
| AS-K6 | Tunnel 凭证 | 每台 Edge 主机 | 机密性 | 可在他处运行该 tunnel 的 connector，截走部分流量 | 仅 root 可读，cloudflared 以非特权用户运行；主机失陷即轮换（[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） |
| AS-K7 | AOP 自有 CA 私钥（仅 AOP 模式） | 离线保存 | 机密性 | 可签发被 Edge 信任的客户端证书 | 不放在 Edge 或大脑 VM；Edge 只持有 CA 证书（[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） |
| AS-K8 | 审计锚点签名密钥（所有者一对，与 AS-K3 分开） | 同 AS-K3 | 完整性 | 可伪造每日锚点，掩盖审计篡改 | 每年轮换，保管方式同 AS-K3；锚点写入开启对象锁的对象存储（[06 §6](06-policy-console-observability.md#6-审计)） |
| AS-K9 | 可选 MessageMAC Cookie 密钥 `K_cf`（Pro 及以上，按站点） | Edge 主机（systemd credential）；Cloudflare 规则（字面量） | 机密性 | 可让 Cloudflare 侧跳过 SBFM / 限速 | 独立于其他密钥（[08 §2.9](08-upstream-and-cloudflare.md#29-可选hmac-cookie-跳过pro-及以上)） |
| AS-K10 | 所有者登录凭证（passkey、TOTP、离线恢复码）与 mgctl API Token | 所有者设备；控制面只存哈希 | 机密性 | 完全控制平台 | passkey 至少注册两个；TOTP 使用会通知；API Token 限定范围、必须过期 |
| AS-K11 | Agent mTLS 客户端证书 CA 私钥（仅 `direct_tls`） | 离线保存 | 机密性 | 可签发被 Edge 信任的 Agent 证书，冒充注册 Agent | 同 AS-K7：不放在 Edge 或大脑 VM，Edge 只持有 CA 证书；客户端证书短有效期；Cloudflare 之后不可用（[05 §3.3](05-ai-agent-policy.md#33-其他身份来源)、[06 §8](06-policy-console-observability.md#8-平台自身安全)） |
| AS-D1 | Valkey 数据：已用 nonce、jti、Provider token 重放集合、吊销集、限速计数、实体 verdict、Stream | 大脑 VM | 完整性、可用性 | 篡改可放行恶意流量或误伤；丢失导致重放检查失效 | 私网 + ACL；AOF everysec；每晚 RDB 备份 |
| AS-D2 | 事件中的访客个人信息（IP、UA、会话 ID、国家 / 地区、交互遥测） | Edge 缓冲、VictoriaLogs（`vl-main` / `vl-short`）、访问记录归档、备份 | 机密性、合规 | PIPL 风险；访客被追踪 | 最小化、假名化、限期保留（见 EVT-04，[06 §7](06-policy-console-observability.md#7-隐私与合规)） |
| AS-D3 | 审计日志（哈希链 + 每日锚点） | Phase 1–2：mgctl 本地追加日志；Phase 3 起：PostgreSQL / SQLite；镜像 `vl-main`；锚点在对象存储 | 完整性 | 操作无法追溯 | 哈希链、签名锚点、对象锁；`mgctl audit verify` |
| AS-D4 | 策略与配置包（`SignedBundle`） | 分发位置（Phase 1–2 大脑 VM 静态位置，Phase 3 起 mg-control）、Edge 本地 last-known-good | 完整性 | 防护被静默改变 | 签名校验；见 EDG-04、CP-02、CP-03 |
| AS-D5 | Web SDK 构建产物 | Edge、Cloudflare 缓存、访客浏览器 | 完整性 | 在所有者页面上执行被篡改的代码 | 内容哈希路径、可复现构建并签名（见 SDK-01） |
| AS-D6 | 备份 | 对象存储 | 机密性、可用性 | 以上数据整体泄露或无法恢复 | 加密后写入；备份凭证与审计锚点凭证分开 |
| AS-D7 | Validation Lab 白名单与录制会话 | 仓库（白名单）、本地（录制） | 完整性、机密性 | 白名单被扩大后误伤他人；录制含所有者个人信息 | 见 §4.10 |

## 3. 信任边界

**结论**：最关键的是 TB2（Cloudflare → Edge）：只有上游认证通过，Edge 才采信上游头。其余边界的共同原则是"只在私网上暴露、每个角色一个凭证、默认拒绝"。

| 编号 | 边界 | 跨越的数据 | 认证 / 控制 | 主要风险 |
|---|---|---|---|---|
| TB1 | 互联网 → Cloudflare | 全部访客请求 | Cloudflare TLS；Cache Rule、WAF Skip、Transform Rule（模板在 `adapters/cloudflare/`） | 请求内容一律不可信；Cloudflare 侧配置漂移（CF-04） |
| TB2 | Cloudflare → Edge | 请求 + `CF-Connecting-IP` + `x-mg-cf-*` + 地理头 | 首选 Tunnel：Edge 只监听 127.0.0.1、只信任回环对端；备选 AOP（zone-level / per-hostname，自有 CA）+ 云防火墙只放行 Cloudflare 网段；认证失败时删除全部已知上游头族（[08](08-upstream-and-cloudflare.md)、[ADR-0003](adr/0003-upstream-profile-cdn-first.md)、[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） | 上游头伪造（CF-01、CF-02） |
| TB3 | Edge → 源站 | 放行的请求 + `MG-*` 头 | 源站只监听回环（或只接受 Edge）；Edge 删除客户端带来的 `MG-*` 头（[02](02-data-flow.md)「Edge 与源站的约定」） | 绕过 Edge 直达源站；`MG-*` 伪造（EDG-02） |
| TB4 | Edge ↔ 大脑 VM | Valkey 操作、配置拉取、事件批量写入、指标抓取 | VPC 私网或 WireGuard；配置拉取走 mTLS 或 WireGuard；Valkey ACL；配置包签名 | 未授权访问 Valkey（VK-01）；配置被替换（CP-02） |
| TB5 | 所有者 → 控制面 / Console / mgctl | 策略、名单、密钥操作、调查查询 | Phase 1–2 只有工作站上的 mgctl（签名私钥 age 加密）；Phase 3 起 passkey 为主、TOTP 备用；敏感操作重新认证 + 输入确认 + 可选生效延迟；Console 不暴露公网（[06](06-policy-console-observability.md)「管理后台」） | 冒充所有者（CP-01、CON-01） |
| TB6 | MorphGate → 第三方 API | Cloudflare API 调用；siteverify（含访客 IP、token） | TLS 证书校验；最小权限 token；带截止时间的调用 | token / secret 泄露（CF-06、CF-11）；Provider 故障（CH-11） |
| TB7 | 大脑 VM → 对象存储 | 备份、审计锚点 | 加密；只写凭证；对象锁（云厂商支持时） | 备份泄露或被删除 |
| TB8 | 访客浏览器 ↔ Web SDK | SDK 代码、遥测、Challenge 提交、持有证明 | SDK 输出一律视为不可信输入；签名只证明持有密钥 | 信号伪造（SDK-02）、SDK 被篡改（SDK-01） |
| TB9 | 依赖源 / CI → 构建产物 | crates.io、Go 模块代理、npm 依赖；CI 产物 | 锁文件、版本固定、最小权限 CI | 供应链投毒（SC-01、SC-02） |
| TB10 | Validation Lab → 目标 | Lab 生成的测试流量 | 工具层白名单 + 网络出口隔离（[07](07-roadmap.md)） | 流量发往非自有目标（LAB-01） |

## 4. STRIDE 分组件

**结论**：Phase 0 已落地的控制集中在"默认安全的骨架"：Edge 强制回环监听、固定上游、删除客户端 `MG-*` 头、`/__mg/*` 自答响应不缓存；内核不读系统时钟且 CI 编译 wasm32；Lab 工具层白名单与限速；锁文件、Pingora 版本与生成代码的 CI 检查。其余控制随 Phase 1–3 交付，交付时把状态列改为已实现并注明验收用例。

类别：S 仿冒、T 篡改、R 抵赖、I 信息泄露、D 拒绝服务、E 权限提升。

### 4.1 Edge（`edge/`，mg-edge，Pingora 0.9）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| EDG-01 | S | 客户端伪造来源 IP 类请求头（`X-Forwarded-For`、`True-Client-IP`、`X-Real-IP`） | 限速、IP 前缀绑定、信誉与地理判断失真 | 只在上游认证通过时采信 `CF-Connecting-IP`；永不使用 XFF[0]、`True-Client-IP`、`X-Real-IP`；认证失败时以 TCP 对端为客户端 IP（[08](08-upstream-and-cloudflare.md)、[01](01-architecture.md)「接入模式」） | Phase 1 实现 |
| EDG-02 | S | 客户端自带 `MG-*` 头，冒充 Edge 的判定结果 | 源站误信分数或已验证身份 | Edge 转发前删除客户端请求中的全部 `MG-*` 头，包括 CGI 类源站（PHP、WSGI、Rack）会映射到同一 `HTTP_MG_*` 变量的 `MG_*` 写法（`edge/src/headers.rs`）；客户端 IP 以 `MG-Client-IP` 与改写为单值的 `X-Forwarded-For` 告知源站（[02 §8](02-data-flow.md#8-edge-与源站的约定)） | Phase 0 实现（删除）；其余 Phase 1 实现 |
| EDG-03 | T | 请求走私 / 解析歧义（cloudflared、Edge、源站对同一请求解读不同） | 绕过路由匹配与判定 | Pingora 0.9 加固了 request-target 与 HTTP/2 `:path` 解析，并默认剥离逐跳头；Pingora 固定 `=0.9.0`，升级单独排期并跑完整回归；协议异常（冲突的 `Content-Length` / `Transfer-Encoding` 等）直接阻断（[03](03-risk-scoring.md)、[ADR-0002](adr/0002-edge-pingora-boringssl.md)）。Phase 0：Cloudflare 规则按规范化路径匹配、默认却把原始路径转发给 Edge，`/__mg/` 的 Skip 与缓存 Bypass 规则因此也会作用于 `//__mg/x`、`/%5F%5Fmg/x`、`/a/../__mg/x` 等写法；Edge 对原始路径、RFC 3986 规范化与 Cloudflare 规范化三种形式任一落在 `/__mg` 下的请求都自行应答、从不转发源站（`edge/src/routes.rs`） | Phase 0 实现（`/__mg` 命名空间按规范化路径判定）；其余 Phase 1 实现 |
| EDG-04 | T | 加载被篡改或未签名的策略 / 配置 | 防护被静默关闭 | Phase 0 的配置是本地 TOML，只含监听与上游地址、不含策略，启动前由 `mg-edge --check-config` 校验（systemd `ExecStartPre`）；Phase 1 起策略包由 mgctl 编译并签名，Edge 校验签名与 schema，失败保留 last-known-good（`proto/morphgate/v1/config.proto` 的 `SignedBundle`，[02](02-data-flow.md)） | Phase 1 实现 |
| EDG-05 | R | 无法说明某个请求为何被放行或挑战 | 误伤无法排查 | 每个请求带 `MG-Request-Id`；DecisionEvent 记录 `rule_id`、规则集与模型版本、reason code；失败页展示 request_id（[02](02-data-flow.md)、[03](03-risk-scoring.md)） | Phase 1 实现 |
| EDG-06 | I | 响应泄露检测细节（reason code、分数、失败原因） | 帮助对手调试 | `MG-Reasons` 默认关闭且只发往源站；失败响应统一；阻断页通用（[02](02-data-flow.md)、[04](04-challenge-and-tokens.md)） | 设计已覆盖 |
| EDG-07 | I | 指标端口暴露到公网 | 泄露流量与策略信息 | `metrics_listen` 默认 `127.0.0.1:9901`；生产只绑定私网 / WireGuard 地址供大脑 VM 抓取；配置校验拒绝通配地址（`0.0.0.0`、`::`）与公网地址，只接受回环、RFC 1918、ULA 与 100.64.0.0/10（`edge/src/config.rs`）；指标标签不含 IP、会话等个人信息（[06](06-policy-console-observability.md)「日志、指标与告警」） | Phase 0 实现（回环默认值与地址校验） |
| EDG-08 | D | 应用层洪泛、慢速连接耗尽 Edge 资源 | 站点不可用 | 容量型攻击由 Cloudflare 吸收；Pingora 0.9 默认的 HTTP/2 服务端上限；本地令牌桶 + Valkey GCRA；超时与请求体上限（[04](04-challenge-and-tokens.md)「限速」） | Phase 1 实现 |
| EDG-09 | D | 大脑 VM / Valkey 不可用 | 限速与重放检查失效 | 按降级表处理：本地计数、last-known-good；重放存储不可用时 `critical` 路由 fail-closed（不签发凭证，统一"稍后再试"），其余路由放行并标记、不发交互式 Challenge；单 Edge 且启用进程内 LRU 时可继续（[01 §8](01-architecture.md#8-部署与高可用)） | Phase 1 实现 |
| EDG-10 | E | 解析器缺陷导致崩溃或代码执行 | 取得 Edge 主机权限、窃取 AS-K1、AS-K2、AS-K4 | Rust；依赖最小化；cargo-fuzz 覆盖 `x-mg-cf-*` 头、凭证、Challenge 提交、签名头解析；systemd 以专用非特权用户运行，`NoNewPrivileges`、空能力集、`ProtectSystem=strict`、系统调用过滤等沙箱选项（`deploy/systemd/mg-edge.service`，[06](06-policy-console-observability.md)「平台自身安全」） | Phase 0 实现（systemd 示例）；模糊测试 Phase 1 实现 |
| EDG-11 | E | Edge 被当作开放代理，转发到任意上游 | 被滥用为跳板 | 上游固定为配置中的 `origin`，不依据 Host 或请求内容选择上游；配置校验拒绝指向自身监听地址的 `origin`（`edge/src/proxy.rs`、`edge/src/config.rs`） | Phase 0 实现 |
| EDG-12 | T | 回源连接被多个访客复用，把连接当作状态键导致串扰 | 一个访客的状态被套到另一个访客 | 不以下游连接作为任何状态的键；`x-mg-cf-tls-random` 只以 `client_conn_key = hash(...)` 在内存与近线窗口中使用，不进事件（[02 §9](02-data-flow.md#9-采样与保留)） | Phase 1 实现 |

### 4.2 Decision Core（`core/`，mg-core）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| DC-01 | S | UA 冒充搜索引擎等已验证爬虫 | 绕过爬虫策略与限额 | 官方 IP 段 + 异步 rDNS，均基于解析出的客户端 IP；验证明确失败归为 `IMPERSONATOR`（[05](05-ai-agent-policy.md#2-分类)、[03](03-risk-scoring.md#2-分类botclass)） | Phase 1 实现 |
| DC-02 | S | 冒充授权 AI Agent | 进入授权范围或测试环境 | Web Bot Auth / HTTP Message Signatures 由 Edge 自行验签，`created` / `expires` 窗口与 nonce 重放键 `mg:jti:{site}:{keyid}:{H(nonce)}`（[05](05-ai-agent-policy.md)、[02 §7](02-data-flow.md#7-核心数据模型)） | Phase 3 实现 |
| DC-03 | T | 缺失信号被当作人类证据（如 Cloudflare 之后 JA4 缺失） | 系统性低估风险 | 信号三态 `PRESENT` / `ABSENT` / `MISSING`，按 `expected_mask` 区分：`MISSING`（profile 不提供或上游头未到达）不计入置信度，`ABSENT` 计入分母、降低置信度，两者都不是人类证据；上游应注入的头缺失另触发配置告警；`EDGE_TLS` 低权重、低封顶、先 shadow（[03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)、[08](08-upstream-and-cloudflare.md)） | Phase 1 实现 |
| DC-04 | T | 策略编译器与数据面求值器语义不一致 | 规则在生产中的行为与预期不同 | 单一编译器（cel-go）产出受限 IR，带 `ir_version`；Rust 求值器用共享测试向量做一致性测试；热路径不用 `cel` crate（[06](06-policy-console-observability.md)「策略语言」、[ADR-0006](adr/0006-policy-cel-ir.md)） | Phase 1 实现 |
| DC-05 | T | 时钟偏差导致凭证 / Challenge 时间窗判断错误 | 误拒真人，或接受过期凭证 | 内核不读系统时钟，时间由 Edge 传入（`RequestContext::ts_ms`、`VerifyCtx::now_ms`），`core/clippy.toml` 禁止 `SystemTime::now` / `Instant::now`；主机启用 NTP；时间窗检查使用固定容差（[09](09-interactive-challenge.md)） | Phase 0 实现（接口约束）；其余 Phase 1 实现 |
| DC-06 | I | reason code 或分数泄露给客户端 | 帮助对手校准 | reason code 仅内部使用；凭证对客户端不透明（PASETO v4.local）（[03](03-risk-scoring.md)、[04](04-challenge-and-tokens.md)） | 设计已覆盖 |
| DC-07 | D | 高代价策略表达式拖慢每个请求 | p99 附加延迟超过 5 ms | IR 非图灵完备；编译期估算代价并拒绝超预算规则；求值器设步数上限（[06](06-policy-console-observability.md)「策略语言」） | Phase 1 实现 |
| DC-08 | E | 客户端自行选择 Challenge 类型或 Provider | 降级到最弱的验证 | 升级路径与 Provider 由服务端决定，并密封进 C 的 `providers` 字段（[04](04-challenge-and-tokens.md)、[09](09-interactive-challenge.md)） | Phase 2 实现 |
| DC-09 | T | 数据面引入 I/O 或全局状态，破坏内核纯度 | 行为不可复现，WASM 目标失效 | mg-core 无 I/O、无线程、状态走 trait；`core/clippy.toml` 禁用时钟、线程、环境变量、文件与套接字 API；CI 编译 `wasm32-unknown-unknown`，目标缺失时失败而不是跳过（[ADR-0002](adr/0002-edge-pingora-boringssl.md)） | Phase 0 实现 |

### 4.3 Challenge 端点（`/__mg/*`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CH-01 | S | Challenge 重放、跨 Challenge 拼接字段 | 一次解答多次使用，或延长有效期 | prost 编码的 protobuf `SealedChallengeClaims`（长度分隔，不用字符串拼接）+ XChaCha20-Poly1305，aad = host ‖ type ‖ kid；验证时用 `SET NX` 消费 nonce，且在任何外部 Provider 调用之前（吸取 ALTCHA CVE-2025-68113 的教训）（[04 §4.1](04-challenge-and-tokens.md#41-密封-challenge-与验证顺序)、[09 §4](09-interactive-challenge.md#4-密封-challenge)、[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)） | Phase 1 实现（无感）；Phase 2 实现（交互式） |
| CH-02 | S | 在一个客户端取得 Challenge，在另一个客户端提交 | 解题外包、凭证收割 | C 与凭证按阶段绑定：Phase 1 `uah`（硬）+ `ipp`（软），Phase 2 起加 `cnf.jkt`（硬）与持有证明；`ctp` 仅 `cloudflare`、只 shadow；`tfp` 仅 `direct_tls`、JA4 预研成功后（[04 §5](04-challenge-and-tokens.md#5-短期访问凭证)） | Phase 1 实现（`uah` / `ipp`）；Phase 2 实现（`jkt`） |
| CH-03 | T | 降级：提交未被提供的 Provider 的结果 | 绕开风险自适应升级 | C 内密封本次提供的 Provider 集合，服务端拒绝集合外的 Provider（[09](09-interactive-challenge.md)） | Phase 2 实现 |
| CH-04 | T | 利用返回路径构造开放重定向 | 钓鱼跳板 | `ret` 只保存同站相对路径的哈希，303 前校验（[09](09-interactive-challenge.md)） | Phase 2 实现 |
| CH-05 | T | 外部 Provider（Turnstile）的结果被错误采信 | 非本站或非本次 Challenge 的 token 通过 | hostname 精确匹配（widget 授权是后缀式的）、action 相等、cData 常量时间比较、challenge_ts 与 token 年龄检查；Turnstile token 永不直接当作 MorphGate 凭证；token 哈希写入重放集合（[09](09-interactive-challenge.md)） | Phase 2 实现 |
| CH-06 | T | 0-RTT 早期数据重放状态变更请求 | Challenge 提交 / 凭证刷新被重放 | 首选保持 0-RTT 关闭（`mgctl cf audit` 检查）；若开启，`/__mg/c`、`/__mg/c/renew`、`/__mg/r`、`/__mg/m/*` 对 `Early-Data: 1` 返回 425，其他请求按可重放处理（不签发 / 刷新凭证、不消费 nonce）；Cloudflare 是否透传 425 需实测（[04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt)、[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)） | Phase 1 实现 |
| CH-07 | R | Challenge 结果无记录 | 无法发现通过率异常 | `mg_challenge_total{type,provider,result}`；事件带 request_id；失败页展示 request_id（[06 §5](06-policy-console-observability.md#5-日志指标与告警)、[09](09-interactive-challenge.md)） | Phase 1 实现 |
| CH-08 | I | 失败原因成为"预言机" | 对手逐项试探 | 所有失败统一响应，不区分原因（[04](04-challenge-and-tokens.md)） | 设计已覆盖 |
| CH-09 | I | 个人化响应被 Cloudflare 缓存后发给其他访客 | 凭证、nonce 泄露 | 所有 `/__mg/*`（内容哈希的 SDK 构建除外）与 Challenge 响应带 `Cache-Control: no-store, private`；Challenge 用 403 / 429，不用 200；`/__mg/` 的 Bypass Cache Rule 放在最后；`mgctl cf audit` 检查"Eligible for cache + 覆盖 Edge TTL"规则（[04](04-challenge-and-tokens.md)、[08](08-upstream-and-cloudflare.md)）。Phase 0：`/__mg/*` 从不转发源站，Edge 自答的响应（healthz 与保留路径的 404）都带该头（`edge/src/routes.rs`） | Phase 0 实现（Edge 自答响应）；其余 Phase 1 实现 |
| CH-10 | D | 大量索取或提交 Challenge | Edge / Valkey 过载 | 签发无状态（不写存储）；请求体上限 `/__mg/c`、`/__mg/c/renew` 8 KB，`/__mg/t`、`/__mg/r` 16 KB，带 `Content-Encoding` 一律拒绝、不解压；先校验大小与格式再做密码学运算；`/__mg/` 独立限速；Free 区唯一一条限速规则在边缘挡 `POST /__mg/` 洪泛，此时 Skip 规则不跳过 `http_ratelimit`（[02 §3](02-data-flow.md#3-challengesdk-遥测与凭证刷新)、[06 §8](06-policy-console-observability.md#8-平台自身安全)、[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)） | Phase 1 实现 |
| CH-11 | D | 外部 Provider 故障或超时 | 交互式验证不可用 | verify 带截止时间；回退自研 `self_hold`；**绝不 fail-open**；`invalid-input-secret` 告警并自动禁用该 Provider（[09](09-interactive-challenge.md)、[01](01-architecture.md)「部署与高可用」） | Phase 2 实现 |
| CH-12 | E | 人工代解中继取得交互级凭证 | 自动化获得"人类"等级 | 无法阻止，只抬成本：交互级凭证 30 分钟 TTL（`interactive_a11y` 15 分钟）+ 持有证明续期、按前缀 / ASN 的签发上限、解题时间分布监控；通过只算封顶的人类证据（[09](09-interactive-challenge.md)）。残余风险见 §6 R-01 | Phase 2 实现 |
| CH-13 | I | `/__mg/healthz` 泄露版本或内部状态，或被缓存 | 信息收集 | 只返回 `ok`；`Cache-Control: no-store, private` | Phase 0 实现 |

### 4.4 Web SDK（`sdk/web/`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| SDK-01 | T | SDK 在构建、存储、缓存或页面优化环节被篡改 | 在所有者页面上执行非预期代码 | 内容哈希路径；锁文件 + `--frozen-lockfile`；可复现构建并签名（[06](06-policy-console-observability.md)「平台自身安全」）；Rocket Loader 关闭或给 SDK 标签加 `data-cfasync="false"`（[08](08-upstream-and-cloudflare.md)） | Phase 0 实现（锁文件）；签名 Phase 2 实现 |
| SDK-02 | S | 伪造或回放 SDK 上报的信号 | 虚假的"人类"证据 | SDK 输出一律视为不可信输入；一致性判断放在服务端；遥测由会话密钥签名，只证明持有密钥、不证明是人；CLIENT 族封顶（[04](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)、[03](03-risk-scoring.md)） | 设计已覆盖 |
| SDK-03 | S | 会话密钥被导出后在别处使用 | 凭证转移 | WebCrypto non-extractable 密钥；`cnf.jkt` 绑定；`MG-Proof` 含 `htm`、`htu`、`iat`、`jti`（[04](04-challenge-and-tokens.md)） | Phase 2 实现 |
| SDK-04 | I | 采集超出必要的个人信息 | 违反最小化，PIPL 风险 | 端上摘要；不采原始轨迹、按键内容、画布哈希；交互遥测 ≤ 2 KB；高熵指纹默认关闭（[04](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)、[09](09-interactive-challenge.md)） | Phase 2 实现 |
| SDK-05 | I | 第三方脚本（Turnstile api.js）进入页面 | 访客 IP、TLS 指纹、UA 发往 Cloudflare；页面脚本面扩大 | 只在选用 Turnstile 的 Challenge 页加载；CSP nonce + `frame-src https://challenges.cloudflare.com`，先 Report-Only 验证；按站点开关；隐私声明披露（[09](09-interactive-challenge.md)、[06](06-policy-console-observability.md#7-隐私与合规)） | Phase 2 实现 |
| SDK-06 | E | 受保护站点自身的 XSS 读取凭证或调用会话密钥 | 凭证在页面打开期间被利用 | 凭证 Cookie 使用 `__Host-` 前缀与 `HttpOnly`；密钥不可导出；注入脚本使用 CSP nonce（[04](04-challenge-and-tokens.md)）。页面打开期间的密钥调用无法阻止，见 §6 R-06 | Phase 2 实现 |
| SDK-07 | D | SDK 异常导致页面功能损坏 | 所有访客受影响 | SDK 异常不影响页面；SDK 失败时相关 CLIENT 信号记为 `ABSENT`（计入置信度分母，不当人类证据，[03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)）；核心包 ≤ 30 KB gzip（[04 §7](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)） | Phase 2 实现 |

### 4.5 Cloudflare 上游集成（`cloudflare` profile、`adapters/cloudflare/`、`mgctl cf`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CF-01 | S | 源站 / Edge 被绕过 Cloudflare 直接访问，访问者自带 `CF-Connecting-IP`、`x-mg-cf-*` 等头 | 伪造客户端 IP、TLS 信号与验证爬虫标记 | 首选 Tunnel：Edge 只监听 127.0.0.1、只信任回环对端，主机无公网入站端口；备选 AOP（zone-level 或 per-hostname，自有 CA，**不用**全局共享证书）+ TLS 前按 Cloudflare 网段过滤 + 云防火墙只放行 Cloudflare 网段（纵深防御）；上游认证失败时删除全部已知上游头族，以 TCP 对端为客户端 IP；源站应用同样只监听回环（[08](08-upstream-and-cloudflare.md)、[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)）。Phase 0 的 mg-edge 没有 TLS 监听器，配置校验拒绝非回环的 `listen`（`edge/src/config.rs`） | Phase 0 实现（强制回环监听）；上游认证与头剥离 Phase 1 实现 |
| CF-02 | S | 其他 Cloudflare 客户的流量（如 Worker）经 Cloudflare 网络到达源站 | 被当作来自所有者 zone 的请求 | 不用全局 AOP 证书；拒绝 `CF-Worker` 头不属于所有者 zone 的请求（[08](08-upstream-and-cloudflare.md)） | Phase 1 实现 |
| CF-03 | S | 访客预先设置 `x-mg-cf-*` 同名头 | 信号污染 | Tier 0 Transform Rule 的 Set 覆盖同名头、值为空时删除，并删除 Tier 1 头名，Worker 未运行时伪造值不会留存（执行顺序需实测）；缺 `x-mg-cf-t1` 标记时 Tier 1 头按 `MISSING`；Edge 仍只在上游认证通过时采信；`mgctl cf audit` 检查 Transform Rule 是否齐全（[08 §2.3](08-upstream-and-cloudflare.md#23-信号转发-tier-0request-header-transform-rule)） | Phase 1 实现 |
| CF-04 | T | Cloudflare 侧配置漂移：Bot Fight Mode 被开启、`/__mg/` Bypass 规则顺序变化、误开 "Remove visitor IP headers"、Pseudo IPv4 改为 Overwrite、0-RTT、Rocket Loader、AI bot policy 默认值 | 误伤、缓存泄漏、丢失客户端 IP | `mgctl cf audit` 定时运行并告警；上游认证通过但缺 `CF-Connecting-IP` 时告警，不回退到 Cloudflare 对端 IP；修改 Cloudflare 配置后必跑审计（[08](08-upstream-and-cloudflare.md)、[07](07-roadmap.md)） | Phase 1 实现 |
| CF-05 | T | Cloudflare IP 段同步结果异常（为空、格式变化、被篡改） | 可信代理快照与安全组错误 | 带 etag 拉取 `GET /client/v4/ips`；校验列表形状与大小，失败保留上一版并告警（> 48 小时未成功）；与上一版的差异在 Console 展示（[08](08-upstream-and-cloudflare.md)、[06](06-policy-console-observability.md)） | Phase 1 实现 |
| CF-06 | I | Cloudflare API Token 泄露 | 修改 zone 配置、关闭源站保护 | 按用途拆分（`cf-audit` 只读、`cf-turnstile` 仅 Turnstile、`cf-push` 默认不创建）；按 AS-K5 的方式保管，不进配置包与仓库；定期轮换（[06 §8](06-policy-console-observability.md#8-平台自身安全)） | Phase 1 实现（只读审计 token）；写权限的具体权限名待定 |
| CF-07 | S | Tunnel 凭证被盗后在他处运行 connector | 部分访客流量流向非所有者主机 | 凭证仅 root 可读，cloudflared 以非特权用户运行；主机失陷即轮换；定期核对 tunnel 上的 connector 列表（查询方式需实测）（[06](06-policy-console-observability.md)「平台自身安全」） | 待定（connector 核对） |
| CF-08 | S | AOP CA 私钥泄露（仅 AOP 模式） | 可签发被 Edge 信任的客户端证书 | CA 私钥离线保存，只在签发 / 轮换时使用；Edge 只持有 CA 证书；轮换时短期同时信任新旧 CA；证书剩余 < 30 天告警（`mg_aop_cert_expiry_seconds`，[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） | 设计已覆盖（AOP 模式启用时实现） |
| CF-09 | D | 单个 cloudflared 或主机故障 | 站点不可用 | 每台 Edge 主机一个副本，免费主备；启用 SBFM 时 "Definitely Automated" 保持 Allow，避免隧道连接失败（[08](08-upstream-and-cloudflare.md)、[01](01-architecture.md)「部署与高可用」）。单副本部署的不可用是已知代价 | 设计已覆盖 |
| CF-10 | E | 可选 MessageMAC Cookie 密钥泄露 | Cloudflare 侧跳过 SBFM / 限速 | 独立密钥、短 TTL；只影响 Cloudflare 侧的跳过，MorphGate 仍独立判定（[08](08-upstream-and-cloudflare.md)） | 待定（Pro 及以上可选功能） |
| CF-11 | I | Turnstile secret 泄露 | 他人可用本站 widget 做 siteverify | 每站点一个 widget 限制影响面；经 API `rotate_secret` 轮换，轮换期间 Edge 同时持有新旧 secret；配置只写引用（[09](09-interactive-challenge.md)、[06](06-policy-console-observability.md)） | Phase 2 实现 |

### 4.6 控制面与 mgctl（`control-plane/`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| CP-01 | S | 冒充所有者使用控制面 | 完全控制策略与密钥 | passkey 为主（建议注册两个）、TOTP 备用并通知；离线恢复码；控制面只绑定内网或 WireGuard 地址（[06](06-policy-console-observability.md)「管理后台」、[ADR-0010](adr/0010-single-owner-model.md)） | Phase 3 实现 |
| CP-02 | S | 冒充控制面向 Edge 下发配置，或冒充 Edge 拉取配置 | 注入恶意策略；配置外泄 | Phase 1–2：mgctl 上传到大脑 VM 上的静态位置，Edge 以 ETag 条件请求拉取；Phase 3 起向 mg-control 长轮询；链路均为 mTLS 或 WireGuard；配置包 Ed25519 签名，Edge 校验签名与 schema（[02 §6](02-data-flow.md#6-配置模型与密钥下发)、[ADR-0007](adr/0007-lean-deployment.md)） | Phase 1 实现（静态位置）；Phase 3 实现（长轮询） |
| CP-03 | T | 旧的有效签名配置包被重新投递（回滚） | 已修复的策略被还原 | Edge 只接受版本号单调递增的配置包；所有者的"回滚"以内容为旧版、版本号更高的新包实现（[02 §6](02-data-flow.md#6-配置模型与密钥下发)） | Phase 1 实现 |
| CP-04 | T | 配置签名密钥被盗 | 任意签发 Edge 信任的配置 | 所有者一对 Ed25519（`kid` 区分，年更），不在 Edge 上：Phase 1–2 由 mgctl 在工作站使用，私钥 age 加密（口令或硬件密钥插件）；Phase 3 起移到大脑 VM 的 mg-control，以 systemd credentials 交付（有 TPM2 时绑定）；云 KMS 可选，不部署 OpenBao；审计锚点签名为另一对、保管相同；轮换属敏感操作并写审计（[06 §8](06-policy-console-observability.md#8-平台自身安全)、[ADR-0010](adr/0010-single-owner-model.md)） | 设计已覆盖 |
| CP-05 | R | 单人无法两人审批，敏感操作缺少旁证 | 误操作或账号被盗后无法追溯 | 敏感操作重新认证 + 输入站点名确认 + 可选生效延迟（延迟期间立即通知）；审计哈希链，每日锚点签名写入对象存储；Phase 1–2 的 mgctl 操作写本地追加日志（同一格式与哈希链）（[06](06-policy-console-observability.md)「审计」、[ADR-0010](adr/0010-single-owner-model.md)） | Phase 1 实现（mgctl 本地审计）；Phase 3 实现（控制面） |
| CP-06 | I | 密钥材料进入配置包、日志或仓库 | 密钥扩散 | 配置包只含 `kid` 与引用（`secret_refs`、`origin_pull_ca_ref`）；`.gitignore` 排除本地密钥与环境文件；CI 不持有生产密钥（[02](02-data-flow.md)、`proto/morphgate/v1/config.proto`） | 设计已覆盖；仓库密钥扫描待定 |
| CP-07 | D | 控制面不可用 | 无法发布策略 | 控制面不在请求路径上；Edge 使用 last-known-good 并在配置陈旧时告警；吊销经 Valkey pub/sub（[01](01-architecture.md)「部署与高可用」） | 设计已覆盖 |
| CP-08 | E | 通过策略表达式或 Admin API 在控制面执行任意代码 | 取得大脑 VM | CEL 非图灵完备、编译期类型与代价检查；控制面容器以非 root 运行；Admin API 只在私网（[06](06-policy-console-observability.md)） | Phase 3 实现 |
| CP-09 | E | 可选只读账号或 mgctl API Token 越权 | 只读身份执行写操作 | 只有 `owner` 与 `viewer` 两个角色，服务端强制检查；API Token 限定范围、必须过期、服务端只存哈希（[06](06-policy-console-observability.md)） | Phase 3 实现 |

### 4.7 Valkey

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| VK-01 | S | 未授权客户端连接 Valkey | 读写全部状态 | 只监听私网地址，不开放公网；与 Edge 同区域 / 同 VPC；按角色划分 ACL 用户（Edge、近线 worker、控制面）；链路经私网或 WireGuard（[01](01-architecture.md)「部署与高可用」） | Phase 1 实现 |
| VK-02 | T | 篡改实体 verdict、吊销集、限速计数 | 放行恶意流量或误伤 | ACL 限制各角色可写的 key 前缀与命令（Edge 不能写 `mg:rev:*`、不能发布 `mg:pub:*`，规则需实测）；吊销消息签名校验、只会收紧，任何放宽只经签名配置包（[02 §6](02-data-flow.md#6-配置模型与密钥下发)）；verdict 带 `source`、`version`、TTL；跨站共享只限 IP / ASN 类、按站点开关（[01 §10](01-architecture.md#10-站点模型)）；**提议**：Valkey 中的 verdict 只能提高风险 | Phase 1 实现；提议待定（需写入 ADR） |
| VK-03 | T | 重放集合（nonce、jti）被逐出或清空 | 一次性 nonce 可被重用 | 重放类 key 与计数类 key 分开规划内存，重放集合不得被静默逐出；Valkey 不可用时按 EDG-09：`critical` 路由 fail-closed，其余放行并标记（[01 §8](01-architecture.md#8-部署与高可用)） | Phase 1 实现 |
| VK-04 | I | Valkey 数据或 RDB 备份泄露 | 访客 IP 前缀、会话标识外泄 | 标识个人的 key 做哈希（`EntityVerdict.key`）；备份加密后写入对象存储（[02](02-data-flow.md)、[06](06-policy-console-observability.md)） | Phase 1 实现 |
| VK-05 | D | 高基数 key 或 Stream 堆积耗尽内存 | 限速与重放检查失效 | 所有 key 带 TTL；设置 `maxmemory` 与告警；Stream 用 `XADD MAXLEN ~`，`mg:ev` 积压告警（[06 §5](06-policy-console-observability.md#5-日志指标与告警)、[ADR-0007](adr/0007-lean-deployment.md)） | Phase 1 实现 |
| VK-06 | E | 通过管理类命令（CONFIG、MODULE、DEBUG 等）扩大权限 | 取得大脑 VM | ACL 对非管理用户禁用管理类命令；Valkey 跟随安全更新 | Phase 1 实现 |
| VK-07 | S | 开发环境 Valkey 暴露到局域网 | 开发数据被读写 | `deploy/compose/` 中的端口只绑定 127.0.0.1；开发环境不使用生产密钥与数据 | Phase 0 实现 |

### 4.8 事件管道（EventSink → VictoriaLogs、Valkey Stream、VictoriaMetrics）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| EVT-01 | S | 向 VictoriaLogs / VictoriaMetrics 写入伪造事件或指标 | 分析被污染，调参被误导 | 只在私网 / 回环监听；写入端认证或只经 WireGuard（具体方式需实测）；事件不作为审计依据 | Phase 1 实现 |
| EVT-02 | T | 事件被篡改或删除以掩盖操作 | 调查结论错误 | 事件不是审计记录；审计日志独立成链（[06](06-policy-console-observability.md)「审计」） | 设计已覆盖 |
| EVT-03 | R | 事件静默丢失 | 无法复盘 | `mg_event_dropped_total`；缓冲满时先丢放行流量的采样事件，保留处置事件（[02](02-data-flow.md)、[01](01-architecture.md)「部署与高可用」） | Phase 1 实现 |
| EVT-04 | I | 事件中的访客个人信息被过度保留或越权查询 | PIPL 风险 | DecisionEvent 最小化；Cloudflare 精确位置头只保留国家、地区、时区；`x-mg-cf-tls-random` 不写入任何事件；保留期固定：DecisionEvent 明细 30 天（`vl-main`，IP 明文只在此处），Challenge / SDK 遥测事件 7 天（`vl-short`），不含个人标识的聚合随指标存 13 个月，最小访问记录（假名化、不采样）每日归档 ≥ 6 个月；越权查询见 CON-05（[02 §9](02-data-flow.md#9-采样与保留)、[06 §7](06-policy-console-observability.md#7-隐私与合规)） | Phase 1 实现 |
| EVT-05 | I | 访客可控的字符串（UA、路径、头名）在 vmui / Grafana / Console 中被当作 HTML 执行 | 所有者浏览器被 XSS | 结构化 JSON 编码写入；展示端一律转义（见 CON-04） | Phase 1 实现 |
| EVT-06 | D | 事件洪泛占满 Edge 内存或阻塞请求 | 延迟上升、OOM | 内存有界环形缓冲（可选小磁盘溢写），写出永不阻塞请求；按优先级丢弃（[ADR-0007](adr/0007-lean-deployment.md)） | Phase 1 实现 |
| EVT-07 | D | 指标高基数（按 IP、会话打标签） | VictoriaMetrics 内存耗尽 | 指标标签只用 site、route、action、class 等有界维度（[06](06-policy-console-observability.md)「日志、指标与告警」） | Phase 0 实现（只有请求计数器）；其余 Phase 1 实现 |
| EVT-08 | E | 近线 worker 回写 verdict 时越权 | 任意改写状态 | worker 使用独立服务凭证与 ACL 用户，只能写 verdict 前缀（同 VK-02） | Phase 2 实现 |

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
| LAB-05 | I | 录制的真人会话含所有者个人信息 | 隐私泄露 | 录制数据不进仓库，本地加密存放并脱敏 | Phase 1 实现 |
| LAB-06 | R | 无法追溯哪次运行访问了哪个目标 | 事后无法复查 | 每次运行记录目标、时间、用例与结果；被拒绝的目标同样记录 | Phase 1 实现 |

### 4.11 供应链与 CI（`.github/workflows/ci.yml`）

| 编号 | 类别 | 威胁 | 影响 | 缓解（设计依据） | 状态 |
|---|---|---|---|---|---|
| SC-01 | T | 依赖投毒（crates.io、Go 模块代理、npm） | 恶意代码进入 Edge 或 SDK | 提交锁文件（`Cargo.lock`、`go.sum`、`pnpm-lock.yaml`），CI 使用 `--frozen-lockfile`；Pingora 固定 `=0.9.0`；依赖最小化；引入 cargo-deny / cargo-audit、govulncheck、依赖审计 | Phase 0 实现（锁文件、`--frozen-lockfile`、CI 检查 Pingora 固定为 `=0.9.0`）；漏洞扫描 Phase 1 实现 |
| SC-02 | T | CI 流水线被篡改或第三方 Action 被劫持 | 构建产物被植入代码 | workflow 顶层 `permissions: contents: read`；checkout 使用 `persist-credentials: false`；PR 流水线（`pull_request`）不使用任何密钥；所有 Action 固定到 commit SHA（注释标出对应版本）；CI 下载的 protoc 发布包校验 SHA-256 | Phase 0 实现 |
| SC-03 | I | 密钥进入 CI 日志或仓库 | 生产密钥泄露 | CI 不持有任何生产密钥；Turnstile 只用官方测试 sitekey / secret（[09](09-interactive-challenge.md)） | 设计已覆盖 |
| SC-04 | T | 生成代码与 `.proto` 不一致（生成代码被手改） | 数据契约在 Rust 与 Go 之间漂移 | Rust 在 `build.rs` 中生成；Go 生成代码由 `make proto` 产生并提交，CI 用同一版本的 protoc 重新生成并 `git diff --exit-code` | Phase 0 实现 |
| SC-05 | S | 部署的二进制不是由仓库构建 | 未知代码运行在 Edge | 在自有主机从源码构建；SBOM 与产物签名（cosign）（[06](06-policy-console-observability.md)「平台自身安全」） | 待定 |
| SC-06 | D | 0.x 依赖的破坏性升级 | 无法及时打补丁 | Pingora 代码只在 `edge/`；升级在分支上适配并跑完整回归后再改 pin；CI 检查 `Cargo.toml` 与 `Cargo.lock` 中的 Pingora 版本（[ADR-0002](adr/0002-edge-pingora-boringssl.md)） | Phase 0 实现 |
| SC-07 | E | 项目代码中混入进攻性能力（绕过第三方防护、对外发流量） | 违反项目边界 | 仓库约定（`CLAUDE.md`）写明只做防御、不写绕过任何防护的代码，除 Lab 外，测试流量只留在本机（回环测试：`scripts/edge-smoke.sh`、`edge/tests/`、Go `httptest`；`scripts/lab-egress-check.sh` 只用本机 Docker 网络）；Lab 白名单（LAB-01）；自审时检查新增的出站网络代码 | Phase 0 实现（约定） |

## 5. 平台自身滥用与误伤风险

**结论**：对个人站点而言，误伤真人和把所有者锁在外面，比漏掉一部分自动化代价更高。所以默认姿态是先 shadow / monitor，放宽和回退永远比收紧容易；无障碍路径是 v1 的必需项，不是可选项。

### 5.1 误伤

| 风险 | 表现 | 控制 | 状态 |
|---|---|---|---|
| 新规则或新信号直接 enforce | 真人被挑战或阻断 | 一律 shadow → dry-run → 灰度；`EDGE_TLS` 与交互评分先 shadow；全局 monitor 开关（`SiteBundle.monitor_only`）；人类摩擦率告警（[03](03-risk-scoring.md)、[06](06-policy-console-observability.md)） | Phase 1 实现 |
| 缺失信号被当作自动化证据 | Cloudflare 之后的正常访客被加分 | `MISSING` 不计入置信度，`ABSENT` 只降低置信度，两者既不当人类证据，也不当自动化证据（[03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)） | Phase 1 实现 |
| 隐私工具用户（VPN、Tor、禁用第三方脚本、隐私浏览器） | 被当作自动化 | 这些特征单独不构成阻断依据；中风险优先 Challenge 而不是阻断（[03](03-risk-scoring.md#5-分级处置)）；Challenge 走第一方路径、不依赖第三方域名 | Phase 1 实现 |
| 合法自动化被拦（搜索引擎、RSS 阅读器、可用性监控、所有者自己的脚本、授权 Agent） | 收录下降、监控误报 | 已验证爬虫与用途矩阵；带过期时间和原因的允许名单；授权 Agent 与测试授权工单（[05](05-ai-agent-policy.md#2-分类)） | Phase 1 实现（爬虫、名单）；Phase 3 实现（Agent） |
| 双重挑战（Cloudflare 与 MorphGate 先后挑战） | 访客连续遇到两次验证 | Free 区关闭 Bot Fight Mode，`/__mg/` 的 Skip 规则只能跳过 `bic`、`securityLevel`；Pro 及以上可再 Skip SBFM；用限速规则挡 `POST /__mg/` 洪泛时不跳过 `http_ratelimit`（[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)）；SDK 处理 `cf-mitigated: challenge`，计入 `mg_double_challenge_total`（[08 §2.8](08-upstream-and-cloudflare.md#28-cf-mitigated-与双重挑战)） | Phase 1 实现（审计）；Phase 2 实现（SDK） |
| 中国大陆访客 | 第三方 Challenge 不可用或很慢 | Turnstile 永不对大陆访客选用；自研 Challenge 走第一方 `/__mg/`，SDK ≤ 30 KB gzip（[09](09-interactive-challenge.md)） | Phase 2 实现 |
| Cloudflare AI bot policy 默认值与 MorphGate 策略不一致 | 期望的爬虫在 Cloudflare 侧就被挡掉 | MorphGate 为唯一权威；`mgctl cf audit` 检查 AI bot policy（[05](05-ai-agent-policy.md)、[08](08-upstream-and-cloudflare.md)） | Phase 1 实现 |
| 误伤后无法定位原因 | 访客无从申诉 | 失败页带 request_id；按 request_id 检索判定解释（[06](06-policy-console-observability.md#7-隐私与合规)） | Phase 1 实现 |

### 5.2 所有者被锁定

| 场景 | 控制 | 状态 |
|---|---|---|
| 所有者自己的浏览被挑战或阻断 | 所有者也走同一套 Challenge（可以通过）；可选带过期时间的所有者允许名单；阻断页带 request_id 便于自查 | Phase 1 实现 |
| 策略错误导致全站被拦 | 全局 monitor 开关；回滚到上一版本不需要重新认证；Edge 保留 last-known-good | Phase 1 实现 |
| 控制面或 Console 不可用时需要止损 | **提议**：Edge 主机上的本地应急开关（经 SSH 修改本地文件，强制 monitor 模式并写本地审计），不依赖大脑 VM；它是"放宽只经签名配置包"（[02 §6](02-data-flow.md#6-配置模型与密钥下发)）的例外，需在 ADR 中写明 | 待定 |
| passkey 丢失 | 至少注册两个 passkey；TOTP 备用；一次性离线恢复码；TOTP 使用会通知（[06](06-policy-console-observability.md)「管理后台」） | Phase 3 实现 |
| 所有者的管理通路依赖被保护的站点 | Console 与 Admin API 只在内网 / WireGuard 上提供，不经过 Edge 的执法路径；主机管理走 WireGuard 或云厂商控制台，不依赖被保护的站点 | 设计已覆盖 |
| 生效延迟期间需要紧急回退 | 回退与止损类操作（回滚、吊销、紧急停止）不加摩擦（[06](06-policy-console-observability.md)「管理后台」） | Phase 3 实现 |

### 5.3 无障碍

交互式 Challenge 的无障碍要求见 [09](09-interactive-challenge.md) 与 [ADR-0008](adr/0008-interactive-challenge-self-built.md)，本节只列威胁模型关心的点。

| 风险 | 控制 | 状态 |
|---|---|---|
| 认知测试把部分用户挡在外面（WCAG 3.3.8 / 3.3.9） | 不做滑块、点选、旋转、扭曲文字、音频题 | 设计已覆盖 |
| 无法使用指针或无法长按 | 键盘按住 Space / Enter；"无法按住？"切换为两次按键；`pow_a11y` 非交互路径；站点有登录时提供 passkey 或邮件链接替代 | Phase 2 实现 |
| 计时压力（WCAG 2.2.1） | 交互式 C 约 10 分钟有效，到期前 SDK 静默续期；无可见倒计时 | Phase 2 实现 |
| 无障碍模式被评分为可疑 | 键盘 / 切换 / 无障碍模式跳过指针特征，缺失的指针数据为中性；无障碍路径使用率与失败率单独监控 | Phase 2 实现 |
| 读屏与动效 | 目的说明文本、aria-live、prefers-reduced-motion、zh-CN / en；验收要求用键盘与读屏完成验证（[07](07-roadmap.md)） | Phase 2 实现 |

### 5.4 平台被滥用

| 风险 | 控制 | 状态 |
|---|---|---|
| 超出安全目的追踪访客 | 行为特征只用于区分自动化，不用于识别具体个人；不做跨站追踪；高熵指纹默认关闭；限期保留；隐私声明披露（[06](06-policy-console-observability.md#7-隐私与合规)） | 设计已覆盖 |
| 平台被用来向他人发送流量 | Lab 白名单两层强制（LAB-01、LAB-02）；Edge 不是开放代理（EDG-11） | Phase 0 实现（工具层 + 网络出口层） |
| 平台被提供给他人使用 | 不对外提供，包括托管服务；将来要保护他人站点需新 ADR，重新评估租户隔离、JA4+ 许可与合规（[ADR-0010](adr/0010-single-owner-model.md)、[ADR-0009](adr/0009-ja4-only-licensing.md)） | 设计已覆盖 |

## 6. 残余风险与接受理由

**结论**：以下风险在个人预算与单人运维下无法消除，明确接受；每条都给出触发复审的信号。

| 编号 | 残余风险 | 为何无法消除 | 接受理由 | 监控信号 / 复审触发 |
|---|---|---|---|---|
| R-01 | 人工代解与打码服务通过交互式 Challenge | 已发表研究显示其对常见交互式 Challenge 成功率接近 100%，每千次约 $0.10–5 | 目标是抬高成本，不是不可绕过；交互通过只算封顶的人类证据，并受签发配额与短 TTL 限制 | 解题时间分布异常、通过率突然接近 100%、单前缀 / ASN 签发量接近上限 |
| R-02 | 能执行 JS 的自动化浏览器 + 住宅代理（A3）部分漏过 | 没有单一控制点能覆盖 A3 / A4 | 个人站点的损失有限；多层信号、限速与业务侧限额叠加 | 自动化占比趋势、敏感路由的成功率异常 |
| R-03 | Cloudflare Free / Pro 之后没有访客的 TLS / HTTP/2 指纹 | 访客 JA4 只提供给购买了 Bot Management 的 Enterprise 客户，超出预算 | 以 `EDGE_TLS` 弱信号、SDK、行为与 Challenge 补足 | 套餐变化；`EDGE_TLS` shadow 数据显示可以提权 |
| R-04 | 依赖 Cloudflare 作为可信上游 | Cloudflare 自身失陷或行为变化超出本模型 | 单一供应商依赖换来零成本的源站隐藏与 DDoS 吸收 | Cloudflare 安全公告；`mgctl cf audit` 结果变化 |
| R-05 | 单人运维，没有第二个人审批 | 只有所有者一人 | 以重新认证、输入确认、生效延迟与通知、审计锚点补偿（[ADR-0010](adr/0010-single-owner-model.md)） | 审计中出现非预期的敏感操作；TOTP 被使用 |
| R-06 | 受保护站点自身的 XSS 在页面打开期间调用会话密钥 | 持有证明只证明"持有密钥的客户端"，不证明是人；站点应用漏洞不在范围 | 凭证短寿命、`HttpOnly`、不可导出密钥已限制影响 | 同一会话的请求模式突变 |
| R-07 | 大脑 VM 单点 | 个人预算只有一台大脑 VM | 故障只降级不宕机（`critical` 路由可能暂停签发凭证，见 EDG-09）；每晚备份 | 降级模式持续时间；备份恢复演练结果 |
| R-08 | 启用 Turnstile 时访客 IP、TLS 指纹、UA 发往 Cloudflare | Provider 工作方式决定 | 按站点启用、隐私声明披露、大陆访客永不选用 | 隐私法规或 Turnstile 条款变化 |
| R-09 | 数据最小化与日志留存要求之间的张力 | 《网络安全法》要求网络日志留存不少于六个月 | DecisionEvent 明细 30 天、遥测事件 7 天；最小访问记录（假名化、不采样）每日归档 ≥ 6 个月（EVT-04）；归档是否需要 IP 明文等口径需法务确认 | 法规更新；法务意见；源站自身访问日志已满足要求时关闭归档 |
| R-10 | Pingora 0.x 与其他早期依赖的安全修复需要跟随破坏性升级 | 上游节奏不受控制 | Pingora 代码隔离在 `edge/`，升级走回归 | Pingora 安全公告；依赖审计报告 |

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

## 参考

- Cloudflare AOP（zone-level）：https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/
- Cloudflare IP 段：https://api.cloudflare.com/client/v4/ips
- Cloudflare 0-RTT：https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/
- Cloudflare 缓存行为：https://developers.cloudflare.com/cache/concepts/cache-behavior/
- Super Bot Fight Mode：https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/
- Request Header Transform Rules：https://developers.cloudflare.com/rules/transform/request-header-modification/
- Turnstile 服务端校验：https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
- Turnstile 主机名管理：https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/
