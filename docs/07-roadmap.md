# 07 分阶段开发路线

结论：工期按**单人开发**估算（按全职周计，非全职按实际投入折算）。主线 Phase 0 → 3 合计约 15–22 周；Phase 4、5 不设固定工期，由触发条件驱动。每个阶段结束时都要有一个能在所有者自有站点上运行、可验收的版本。

前提（见 [已决策](#已决策)）：平台仅所有者自用；站点以 Cloudflare 前置、浏览器流量为主；部署在公有云；交互式 Challenge 自研，Turnstile 为可选 Provider。本文只写阶段与验收：上游接入细节见 [08](08-upstream-and-cloudflare.md)，交互式 Challenge 见 [09](09-interactive-challenge.md)，指标、密钥与运维默认值见 [06](06-policy-console-observability.md)，选型理由见 [ADR](adr/README.md)。

## 总览

| 阶段 | 主题 | 预估（单人） | 核心产出 |
|---|---|---|---|
| Phase 0 | 基础 | 1–2 周 | Monorepo 骨架、ADR、数据模型、CI、STRIDE 初版、Validation Lab 骨架、compose 开发环境 |
| Phase 1 | MVP：Cloudflare 之后的 Edge | 4–6 周 | 在自有站点 Cloudflare 之后以 monitor 模式运行的 Edge；`mgctl cf audit` |
| Phase 2 | Web SDK 与自研交互式 Challenge | 5–7 周 | Web SDK v1、`cnf.jkt` 绑定、防重放、按住验证 + 无障碍路径、Provider trait + Turnstile 适配、近线 verdict |
| Phase 3 | AI Agent 治理与控制面 | 5–7 周 | mg-control（配置签名移到大脑 VM）、签名配置包长轮询与吊销、Agent Registry、Web Bot Auth、Console v1、审计哈希链迁入控制面 |
| Phase 4 | 分析与扩展 | 按需 | ClickHouse、GBDT、其他 UpstreamProfile、可选大陆验证码 Provider、图关联 |
| Phase 5 | Morph 与加固 | 持续 | SDK 多态构建、动态表单字段、Privacy Pass / PAT、内存困难 PoW、PROXY protocol |

```
P0 (1-2w) --> P1 (4-6w) --> P2 (5-7w) --> P3 (5-7w)        main line: 15-22 weeks
                  |
                  +--> P4 items (on demand: data volume, new upstream, mainland provider)
                  +--> P5 items (ongoing: morph, hardening)
```

Phase 4 / 5 的单项可在 Phase 1 稳定后按需插入（例如某站点改用境内 CDN 时提前做对应 UpstreamProfile），不必等 Phase 3 结束。

**当前进度**（2026-09-28）：Phase 0 完成；Phase 1 的实现阶段 1–3 已完成，接下来是所有者在真实 zone 上的运行步骤（见 [Phase 1 实现进度](#phase-1-实现进度)）。

## Phase 0：基础（1–2 周）

**Monorepo 结构**

```
Cargo.toml              Rust  workspace: core, edge, proto (Phase 1 adds challenge, intel, edge-core)
core/                   Rust  mg-core: pure kernel (signals, scoring, policy IR evaluator,
                              challenge claims); no I/O; builds for wasm32-unknown-unknown
challenge/              Rust  mg-challenge (Phase 1): sealed challenges, PoW, PASETO clearance tokens
intel/                  Rust  mg-intel (Phase 1): IP sets, GeoLite2, crawler registry + verification
edge-core/              Rust  mg-edge-core (Phase 1): Edge components that do not need Pingora
edge/                   Rust  mg-edge: thin Pingora adapter (pin =0.9.0, BoringSSL), UpstreamProfile
proto/                        shared protobuf definitions (Rust + Go codegen)
testdata/                     (Phase 1) cross-language fixtures: KAT vectors, key and artifact
                              samples, policy IR conformance cases
control-plane/          Go    Go module
  cmd/mgctl/                  CLI: policy compiler (cel-go -> IR), signing, cf audit, CF IP sync
  cmd/mg-control/             control plane service (Phase 3)
sdk/web/                TS    Web SDK
adapters/cloudflare/          Transform Rule template, Worker / Snippet templates
lab/                          Validation Lab (target allowlist enforced)
deploy/compose/               dev env: Valkey, PostgreSQL, VictoriaMetrics,
                              VictoriaLogs (vl-main + vl-short), Grafana (optional), mock origin
docs/                         design docs + adr/
```

不再预建：`pipeline/`（无 Kafka / 流处理，Phase 4 再定）、`sdk/ios/`、`sdk/android/`（移动端按需）、`console/`（Phase 3 再建）、通用网关 `adapters/`（Envoy / Nginx 等）、Helm（不用 Kubernetes）。

**交付物**

| 项 | 内容 |
|---|---|
| ADR | ADR-0001–0010：技术栈、Edge 框架（Pingora pin =0.9.x + BoringSSL）、UpstreamProfile、源站保护、凭证与密封 Challenge 格式（PASETO v4；prost 编码的 protobuf `SealedChallengeClaims` + XChaCha20-Poly1305）、策略 CEL → IR、精简部署、交互式 Challenge 自研、JA4 许可、单一所有者（索引见 [adr/README.md](adr/README.md)） |
| 数据模型 | Protobuf：`RequestContext`（含 UpstreamProfile 与信号溯源）、`Signal`、`RiskAssessment`、`Decision`、`DecisionEvent`、`EntityVerdict`；层级 Site → Environment → Route → Policy Set（无 Tenant）；定义以 [02 §7](02-data-flow.md#7-核心数据模型) 为准 |
| 开发环境 | `deploy/compose/`：Valkey、PostgreSQL、VictoriaMetrics、VictoriaLogs（`vl-main` / `vl-short`）、可选 Grafana、mock 源站 |
| CI | lint、单测、解析器模糊测试冒烟；mg-core 编译到 `wasm32-unknown-unknown` 的检查（保证纯内核无 I/O）；Pingora 版本锁定检查 |
| 威胁模型 | STRIDE 初版（[10](10-threat-model.md)），重点：Cloudflare → Edge 的信任边界（绕过 Cloudflare 直连源站、伪造上游头）、`/__mg/*` 端点、凭证与 Challenge 重放 |
| Validation Lab 骨架 | 目标白名单在工具配置和网络出口两层强制（隔离网络，只能访问 `localhost`、`*.test` 和登记的自有 staging 主机）；先支持回放自有 E2E 用例和所有者手工录制的真人会话 |

**验收**

- `docker compose up` 拉起全部开发依赖。
- CI 全绿，含 mg-core 的 wasm32 构建。
- Lab 对白名单外目标的请求被拒绝（用例覆盖工具层与出口层）。
- ADR 与数据模型由所有者自审定稿。

## Phase 1：MVP，Cloudflare 之后的 Edge（4–6 周）

| 领域 | 内容 |
|---|---|
| Edge | Pingora（BoringSSL）；systemd 运行，支持平滑升级；Tunnel 部署时只监听 127.0.0.1。实现：`edge.toml` v1（监听器与站点的主机本地配置，D-14）、站点状态机（`active` / `bootstrap` / `lkg_invalid`，D-21）、`mg-edge --check-config` |
| UpstreamProfile `cloudflare` | 上游认证：Cloudflare Tunnel（只信任回环对端）或 AOP（zone-level / per-hostname，自有 CA）；认证失败删除全部已知上游头族，以 TCP 对端为客户端 IP（[08 §1.2](08-upstream-and-cloudflare.md#12-信任规则)）。实现：可叠加上游密钥头；外部 zone 的 `CF-Worker` 403（D-23）；转发前另删客户端 IP、URL 改写与方法覆盖类头（I-29） |
| UpstreamProfile `direct_tls` | Edge 自己终止 TLS；**JA4 技术预研**：验证 BoringSSL 回调取 ClientHello → 计算 JA4 → 请求过滤器读取的链路（步骤见 [01 §9](01-architecture.md#9-技术选型建议)），结论写入 [ADR-0002](adr/0002-edge-pingora-boringssl.md)。预研期间 JA4 在策略与评分中恒为 MISSING（D-07） |
| 可信客户端 IP | 只取 `CF-Connecting-IP`；缺失即配置告警，不回退到 Cloudflare 对端 IP（[08 §2.2](08-upstream-and-cloudflare.md#22-客户端-ip)）。客户端 IP 未知时从不比已知时更宽松（[02 §2.1](02-data-flow.md#21-第-0-步上游认证与客户端-ip)） |
| 信号 | 解析 `x-mg-cf-*`（Tier 0 Transform Rule 模板在 `adapters/cloudflare/`；Tier 1 Worker / Snippet 可选）；`EDGE_TLS` 族只 shadow；在 Cloudflare 之后失真的信号标记为 MISSING（[08 §2.5](08-upstream-and-cloudflare.md#25-在-cloudflare-之后失真的信号)），策略中的求值语义见 [06 §2](06-policy-console-observability.md#2-策略语言)。协议输入上限：enforce 下 414 / 431 / 400，monitor 下跳过求值（D-26、I-2） |
| 路由与情报 | 路由匹配；GeoLite2 IP / ASN。实现：多路径视图、取最敏感路由（D-25，[02 §2.4](02-data-flow.md#24-路由匹配与输入上限phase-1)）；数据中心 ASN 与 Tor 出口文本名单；全部情报以签名配置包引用的工件下发 |
| 爬虫验证 | 官方 IP 段 + 异步 rDNS；冒充检测。实现：注册表由 `mgctl crawler sync` 生成（逐条校验 CIDR、单个运营方条数变化超过 50% 时拒绝，D-36）；rDNS 后缀须以 `.` 开头且至少两段，只在标签边界匹配（I-22） |
| 限速 | 本地 + Valkey GCRA；Edge 与 Valkey 同区域 / 同 VPC（RTT < 1 ms），否则退化为本地模式。实现：`ip` 维度按 IPv4 地址 / IPv6 /64 计（D-24），IP 未知时用共享兜底桶；`/__mg/c` 的提交限速、两级失败配额与凭证签发配额（D-28、D-37） |
| Decision Core v1 | 纯函数、无 I/O；信号框架、分族封顶规则评分、默认处置矩阵（见 [03](03-risk-scoring.md#5-分级处置)）。实现：18 个检测器、verdict 只升不降（D-10）、凭证已满足时的矩阵抑制（D-20） |
| 策略 | `mgctl` 用 cel-go 编译，在所有者工作站签名（配置签名私钥 age 加密，见 [06 §8](06-policy-console-observability.md#8-平台自身安全)），上传到大脑 VM 上的静态位置，Edge 以 ETag 条件请求拉取（[02 §6](02-data-flow.md#6-配置模型与密钥下发)）；`mgctl` 操作写本地追加审计日志（同一哈希链格式，[06 §6](06-policy-console-observability.md#6-审计)）；Phase 3 控制面复用同一编译器。实现：每条规则的静态步数上界（[ADR-0006](adr/0006-policy-cel-ir.md) 勘误）；Go 与 Rust 的 IR 一致性套件 |
| 动作 | allow / log / tag / rate_limit / block / 无感 Challenge（JS 执行 + SHA-256 PoW + 基础环境信号）；`/__mg/*`（内容哈希的 SDK 构建除外）与 Challenge 响应发 `Cache-Control: no-store, private`，Challenge 用 403 / 429。实现：失败后附的新 C 为 `pow` 且风险段升一级（D-27）；http 访客先 308 到 https（D-32） |
| 凭证 | PASETO v4.local 凭证 Cookie；Phase 1 绑定 `uah`（硬）+ `ipp`（软）；`bind.ctp` 仅 `cloudflare`、只 shadow，稳定性 ≥ 99% 后才可转为软绑定；`bind.tfp` 仅 `direct_tls`，预研结论为不用原始 JA4 硬绑定（ADR-0002 勘误），Phase 2 前不启用；Cloudflare 0-RTT 保持关闭，若开启则 `/__mg/*` 状态变更端点对 `Early-Data: 1` 返回 425（[04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt)） |
| 事件与指标 | DecisionEvent → Edge 有界缓冲 → 批量写入 VictoriaLogs `vl-main`（30 天）；最小访问记录每日归档到对象存储（≥ 6 个月）；pingora-prometheus → VictoriaMetrics（13 个月）；指标名见 [06 §5](06-policy-console-observability.md#5-日志指标与告警)。实现：三级队列、每个输出独立积压（I-25）；`kind=access` 已写入 `vl-main`，每日归档任务尚未实现 |
| 运维开关 | 全局 monitor 开关（实现为站点级 `monitor_only`，站点 YAML 缺省开启） |
| Cloudflare 集成 | `mgctl cf audit`（检查项见 [08 §2.10](08-upstream-and-cloudflare.md#210-mgctl-cf-audit)）；共存配置按套餐（[08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)）：Free 关闭 Bot Fight Mode，Skip 规则只能跳过 `bic` / `securityLevel`；Pro 及以上可 Skip SBFM；用限速规则挡 `POST /__mg/` 洪泛时（Free 唯一的一条即用于此），Skip 规则不跳过 `http_ratelimit`；`/__mg/` 缓存 Bypass 规则放在最后；定时同步 Cloudflare IP 段（带 etag）；API Token 最小权限。实现：`cf audit` 21 项检查、`cf ips sync`（条数变化超过 30% 时拒绝） |

**验收**（证据与责任人见 [规格 §18](impl/phase1-spec.md#18-验收映射)）

- 自有站点经 Cloudflare 以 monitor 模式连续运行 ≥ 1 周。
- 附加延迟 p99 < 5 ms：以生产或自有 staging 的 `mg_edge_added_latency_seconds{kind="site"}` 为准，不做压测（I-31）。
- Lab 用例：冒充爬虫 100% 识别（rDNS 方式的运营方按结论已定的请求计，热身请求为 `DECLARED_AGENT`，D-22）；不执行 JS 的脚本客户端在 enforce 下拿不到凭证。
- `mgctl cf audit` 全绿（`manual` 项逐一 `--ack`）。
- 真人浏览回归（手工 + 自有 E2E）无功能破坏。

### Phase 1 实现进度

实现契约是 [Phase 1 实现规格](impl/phase1-spec.md)（含集成者裁决 I-1..I-35，逐项偏离见其 §0.3），逐阶段的记录在 [phase1-status](impl/phase1-status.md)。截至 2026-09-28：

| 阶段 | 内容 | 状态 |
|---|---|---|
| 规格 | 18 个工作包、全部跨组件契约、两轮评审 | 完成 |
| 实现阶段 1 | 11 个并行工作包：`mg-core`、`mg-challenge`、`mg-intel`、`mg-edge-core`（4 个）、Go 策略编译器、`mgctl` 运维、Cloudflare 与情报同步、Web SDK 挑战页 | 完成 |
| 实现阶段 2 | `mg-edge` 接线：骨架、决策、Challenge 端点、事件与指标；最终安全审查与本机端到端；审查后修复 I-29..I-32 | 完成 |
| 实现阶段 3 | Validation Lab 验收场景与 `lab-e2e`、`direct_tls` 的 JA4 预研、设计文档勘误；集成裁决 I-33..I-35 | 完成 |
| 所有者运行步骤 | 在真实 zone 上部署规则、monitor 周、浏览器回归、`cf audit` 全绿（[规格 §17](impl/phase1-spec.md#17-所有者运维手册代码之外)） | 未开始 |

| 验收项 | 当前状态 |
|---|---|
| monitor 运行 ≥ 1 周 | 待所有者在真实 zone 上运行 |
| 附加延迟 p99 < 5 ms | 指标已提供（`kind="site"`），待生产数据 |
| 冒充爬虫 100% 识别；非 JS 客户端拿不到凭证 | `make lab-e2e` 本机通过：已定结果的冒充请求 13/13 为 `impersonator` 且被阻断，6 个真爬虫请求已验证；4 次挑战提交无一成功，受保护路由 0 个请求到达源站。CI 的 `lab-e2e` 作业已加入，待首次远端运行 |
| `mgctl cf audit` 全绿 | 工具已实现，待在真实 zone 上运行 |
| 真人浏览回归 | 待所有者执行 |
| JA4 预研结论 | 完成（[ADR-0002 勘误](adr/0002-edge-pingora-boringssl.md#勘误2026-09-28ja4-预研)）：链路可行、每握手约 0.5 µs、`ja4_spike` 缺省关闭；不以原始 JA4 做 `bind.tfp` 硬绑定 |

## Phase 2：Web SDK 与自研交互式 Challenge（5–7 周）

| 领域 | 内容 |
|---|---|
| Web SDK v1 | 环境 / 自动化 / 行为摘要、会话密钥、`MG-Proof`、JSON Challenge、静默刷新、遥测；第一方 `/__mg/` 提供，≤ 30 KB gzip，无第三方域名依赖（见 [04](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)） |
| `cf-mitigated` 处理 | 对 `/__mg/*` 或受保护 fetch 收到 `cf-mitigated: challenge` 时视为"上游挑战"，不计为 MorphGate 失败（[08 §2.8](08-upstream-and-cloudflare.md#28-cf-mitigated-与双重挑战)）；"双重挑战"计数进指标，Phase 3 在 Console 展示 |
| 绑定与防重放 | 凭证加 `cnf.jkt`（硬，SDK 会话密钥，配合 `MG-Proof`）；jti、服务端 nonce（在任何外部 Provider 调用之前 `SET NX` 消费）、吊销集 |
| 自研交互式 Challenge | 密封 C（prost 编码的 protobuf `SealedChallengeClaims` + XChaCha20-Poly1305，[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)）；`self_hold` 按住验证（按住期间 Web Worker 中运行 PoW）；服务端交互评分先 shadow，用所有者自己的流量定阈值。细节见 [09](09-interactive-challenge.md) |
| 无障碍路径 | 键盘按住 Space / Enter；"无法按住？"切换；`pow_a11y` Provider（签发 `lvl=interactive_a11y`，更短 TTL、更严配额）；站点有登录时提供 passkey 或邮件链接替代；aria-live、prefers-reduced-motion、zh-CN / en |
| Provider | trait `InteractiveChallengeProvider` 与 `self_hold` / `pow_a11y` 在 mg-core，`turnstile` 在 mg-edge（经注入的 `OutboundHttp`）；Turnstile 只用于非大陆访客，故障时回退自研、绝不 fail-open（[09 §7](09-interactive-challenge.md#7-provider-选择策略)）；`mgctl` 管理 Turnstile widget 与 secret 轮换；CI 用测试 sitekey / secret |
| 近线 | Go worker 消费 Valkey Stream `mg:ev`（组 `nl`，`XADD MAXLEN ~`）：会话聚合、实体 verdict、扫描器识别、verdict 回灌 |

**验收**

- 重放 / 拼接的 C 100% 拒绝。
- 跨客户端提交（C 在客户端 A 签发、由客户端 B 提交）100% 拒绝。
- 人类会话被要求交互式 Challenge 的比例 < 0.1%（基于所有者站点 shadow 数据）。
- 按住模式人类中位完成时间 < 4 s；无障碍 PoW 中位 < 10 s。
- 仅用键盘、以及使用读屏软件均能完成验证。
- Turnstile 故障（api.js 加载失败、siteverify 超时或报错）时正确回退自研，且不放行。

## Phase 3：AI Agent 治理与控制面（5–7 周）

| 领域 | 内容 |
|---|---|
| 控制面服务 | `mg-control`（Go，PostgreSQL 或 SQLite）：Admin API、策略编译与签名（复用 `mgctl` 编译器；配置签名从工作站移到大脑 VM，密钥由 `systemd-creds` 交付，见 [06 §8](06-policy-console-observability.md#8-平台自身安全)）；Phase 1 的 `mgctl` 定时任务（Cloudflare IP 段同步等）迁入 |
| 配置下发 | Edge 以 ETag 长轮询拉取签名配置包，吊销经 Valkey pub/sub，控制面不可用时用 last-known-good（[02 §6](02-data-flow.md#6-配置模型与密钥下发)） |
| Agent 治理 | Agent Registry（分类见 [05](05-ai-agent-policy.md#2-分类)）、授权、测试授权工单（单人流程，见 [05 §5](05-ai-agent-policy.md#5-测试授权工单)） |
| 身份验证 | Web Bot Auth（`web-bot-auth` crate，`httpsig` 作通用 RFC 9421 回退）；Crawler Registry 与情报同步；robots.txt / AIPREF 管理 |
| Cloudflare 对齐 | Cloudflare AI bot policy 与 MorphGate 策略对齐（[05 §7.4](05-ai-agent-policy.md#74-与-cloudflare-ai-bot-policies-对齐)） |
| Console v1（精简） | 站点与路由、策略编辑 / 回放模拟 / 发布、Agent 管理、调查、审计查看、"双重挑战"计数 |
| 后台安全 | passkey（WebAuthn）登录，TOTP 备用，可选只读账号；敏感操作重新认证 + 明确确认 |
| 审计 | 控制面数据库中的哈希链（迁入 Phase 1–2 的 `mgctl` 本地审计日志）；每日锚点签名后写入对象存储（云厂商支持时开启对象锁） |

**验收**

- Lab 中非授权自动化 100% 被拒绝；授权 Agent 只能在授权范围与时间窗内访问；吊销 < 5 s 在 Edge 生效。
- Web Bot Auth：合法签名验证通过；篡改、过期或未登记密钥的签名 100% 拒绝。
- 所有控制面写操作可在审计中追溯，哈希链与每日锚点校验通过。
- 一条策略从提交到全量生效完整走过发布流程（含重新认证确认）；停掉控制面后 Edge 以 last-known-good 继续服务。
- `mgctl cf audit` 的 AI bot policy 检查项与 MorphGate 策略一致。

## Phase 4：分析与扩展（按需）

每项有独立触发条件，满足时才做。

| 项 | 触发条件 | 内容 | 验收 |
|---|---|---|---|
| 单节点 ClickHouse | 开始做 ML / 复杂 SQL，或大脑 VM ≥ 8 GB | LTS 版本、低内存配置、`async_insert=1` + `wait_for_async_insert=1`；不用 ClickHouse Cloud | 事件双写期间两边计数一致；不引入逐请求 INSERT |
| ML v1 | 标签量足以训练与评估（门槛需按实际数据确定） | 标签管道、特征快照、GBDT、概率校准、TreeSHAP reason code、Rust 内联推理、shadow 与灰度、漂移监控 | FPR ≤ 0.1% 下召回率高于 v1 规则（提升门槛按 Phase 2 基线确定）；模型回退演练通过 |
| 其他 UpstreamProfile | 某站点实际改用对应前置 | `cloudfront` / `gcp_alb` / `esa` / `edgeone` / `alicdn` / `tencent_cdn` / `envoy` / `openresty`（信号表见 [08](08-upstream-and-cloudflare.md)） | 该 profile 的上游认证与头剥离 Lab 用例通过；"预期信号"声明与实测一致 |
| 大陆验证码 Provider（可选、付费） | 大陆用户需要熟悉的滑块等交互 | `tencent` / `aliyun_v2`，接同一 Provider trait；不采纳厂商"服务故障时默认通过"的建议 | Provider 不可用或返回故障票据时不放行；回退自研正确 |
| 图关联 | 近线 verdict 稳定且有调查需求 | 会话密钥 × 账号 × IP 前缀 × 指纹簇 | 在 Lab 回放数据上能关联出已知同源会话 |

## Phase 5：Morph 与加固（持续）

| 项 | 前提 / 说明 |
|---|---|
| SDK 多态构建、动态表单字段、后期 Challenge VM | 见 [04](04-challenge-and-tokens.md#8-morph-动态变形)；Turnstile 的 api.js 不能进入多态构建 |
| Privacy Pass / PAT（`privacy_pass` Provider） | 确认有可用的生产 issuer 之后 |
| 内存困难 PoW | 在 SHA-256 PoW 之外提高批量求解成本 |
| PROXY protocol（`proxy_protocol{v1\|v2, allowed_src_cidrs}`） | 仅 L4 负载均衡场景；Pingora 0.9 的 PreTlsProcess（仅 TLS 监听器）+ ppp / proxy-header crate |
| 移动 SDK | 仅在确有 App 需要时 |
| 第三方渗透测试（可选） | 仅针对自有部署，书面授权 |

每项上线前走 shadow → dry-run → 灰度；变形与加固不得破坏无障碍路径。

## 不再规划或推迟的项目

| 项 | 原计划 | 现状 | 原因 |
|---|---|---|---|
| 多租户、跨租户情报共享、RBAC / SSO、两人审批 | Phase 3 | 删除 | 平台仅所有者自用；两人审批改为重新认证 + 明确确认 + 可选生效延迟 |
| Kafka / Redpanda、Kubernetes / Helm | Phase 1、部署 | 删除 | KRaft 生产需 ≥ 3 控制器、每个 1 GB 堆；EKS 约 $73/月；k3s ≥ 2 GB；Valkey Stream + VictoriaLogs 足够 |
| HTTP/2 帧级指纹 | Phase 2 | 无限期推迟 | Cloudflare 之后描述的是 Cloudflare 的连接；HTTP/1 头字节与大小写在 `direct_tls` 下可直接取 |
| ClickHouse + 流处理 | Phase 1 | 推迟到 Phase 4 | VictoriaLogs 单二进制、支持高基数字段，早期足够 |
| Decision API、网关 / 中间件适配器（原 M2 / M3：Envoy ext_proc、Nginx、Go / Node、APISIX 等） | Phase 2、5 | 按需、未排期 | 站点以 Cloudflare 前置 + Edge 为主 |
| API 防护（API Key、OpenAPI 正向模型） | Phase 2 | 按需、未排期 | 流量以浏览器为主 |
| Mobile SDK、统一凭证、鸿蒙 SDK | Phase 4、5 | Phase 5，仅在需要时 | 移动端降为按需、后期 |
| 多区域、等保测评准备、数据驻留 | Phase 5 | 删除 | 自用平台不需要作为服务通过等保测评；访客数据合规义务仍在（见 [06](06-policy-console-observability.md#7-隐私与合规)） |

## 贯穿各阶段

- 每个阶段结束做一次安全自审，更新 STRIDE 威胁模型。
- 解析器持续模糊测试（`x-mg-cf-*` 等上游头、ClientHello、Challenge 提交、策略包）。Phase 1 的做法：每个解析器都有固定种子、≥ 10,000 个输入的随机输入测试（断言返回错误而不 panic），随 `make check` 运行。
- 新检测能力一律 shadow → dry-run → 灰度；`EDGE_TLS` 与交互评分先 shadow。
- 所有测试流量只发往 Validation Lab 白名单内的自有目标（`localhost`、`*.test`、登记的自有 staging 主机）；白名单在工具配置与网络出口两层强制，白名单外的主机一律拒绝。
- Pingora 升级单独进行：先在分支上适配 mg-edge 并跑完整回归，再改 pin。
- 修改任何 Cloudflare 配置后运行 `mgctl cf audit`。
- 每阶段结束核对月成本是否仍在目标区间（见风险表"成本蔓延"）。
- 新增客户端信号前更新隐私说明（见 [06](06-policy-console-observability.md#7-隐私与合规)）。

## 主要风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| Cloudflare 隐藏协议层信号 | Free / Pro 下源站看到的是 Cloudflare（或 cloudflared）的连接；访客 JA3 / JA4 只提供给购买了 Bot Management 的 Enterprise 客户（Tier 2，超预算）；JA4、HTTP/2 指纹、头顺序与大小写、TCP 特征、`Accept-Encoding`、`Connection` 失真 | 这些信号在 `cloudflare` profile 下标记为 MISSING，不计入置信度、不当人类证据；以 Tier 0 / Tier 1 转发可得信号；更多依赖 Web SDK、行为、Challenge 与限速；`direct_tls` 站点保留 Edge 自算 JA4 |
| 源站被绕过 Cloudflare 直连 | 伪造 `CF-Connecting-IP` / `x-mg-cf-*` 等头 | Tunnel（Edge 只听回环）或 AOP（自有 CA）；未认证连接删除全部已知上游头族；云防火墙只放行 Cloudflare IP 段作纵深防御 |
| Turnstile 在中国大陆不受支持 | Cloudflare 官方声明 Turnstile 不支持中国大陆；未走 China Network 时大陆访客经境外节点访问，官方文档记载有明显延迟与可靠性问题；`challenges.cloudflare.com` 的大陆可达性与延迟无官方数据（需实测） | 大陆访客永不选用 Turnstile；客户端在 unsupported-callback、200500、api.js 超时（约 5 s）时回退自研；自研 Challenge 走第一方 `/__mg/`、SDK ≤ 30 KB gzip、无第三方域名依赖 |
| `EDGE_TLS` 稳定性未知 | 扩展哈希的排序与 GREASE 处理未文档化，个别字段拼写需实测（[08 §2.5](08-upstream-and-cloudflare.md#25-在-cloudflare-之后失真的信号)）；按浏览器的稳定性未知 | 低权重、低封顶、先 shadow；按浏览器（Chrome / Firefox / Safari）实测稳定性后再调权；未实测前不用于硬绑定或高权重；`bind.ctp` 只用粗粒度字段、先 shadow，稳定性 ≥ 99% 后才可转为软绑定 |
| Pingora 0.x 破坏性变更 | 2025-05 至 2026-09 发布了 0.5–0.9 共 5 个小版本，每个都有破坏性变更；升级成本不可控 | pin =0.9.x；Pingora 代码只在 mg-edge 薄适配层；Decision Core 为纯函数、无 I/O；升级单独排期并跑完整回归 |
| 数据量小，ML 难以成立 | 几个站点的流量与标签不足以训练和评估 GBDT，阈值不稳定 | 先规则后模型；ML 以标签量为触发条件（Phase 4 按需）；交互评分与规则阈值用所有者流量 shadow 标定；Lab 标注数据只做回归，不作主要训练来源 |
| 成本蔓延 | 组件与付费服务逐步累加：托管数据库 / Valkey、ClickHouse、Workers Paid（最低 $5/月；Free 每天 100,000 请求上限且按路由内全部请求计）、大陆验证码按次计费（约 ¥0.005/次） | 目标：单机全合一约 $25–50/月，2 Edge + 1 大脑约 $50–80/月；不用 Kafka / Kubernetes；带流量套餐的 VPS 优先；托管服务只在想省运维时用；ClickHouse 仅在 Phase 4 触发；Worker 路由只覆盖 HTML 与 `/__mg/*`；付费 Provider 设签发配额 |
| Cloudflare 配置漂移与双重挑战 | Bot Fight Mode 被开启、`/__mg/` 缓存 Bypass 规则顺序错误、Rocket Loader、0-RTT、"Remove visitor IP headers"、Transform Rule 缺失，导致误挑战、误缓存或丢客户端 IP | `mgctl cf audit` 定时运行并告警；缺 `CF-Connecting-IP` 即告警；SDK 处理 `cf-mitigated`；Console 展示"双重挑战"计数 |
| 大脑 VM 单点 | Valkey、控制面、可观测组件同机 | 故障只降级：Edge 用 last-known-good 配置与本地计数；每晚备份 Valkey RDB、pg_dump / SQLite、VictoriaMetrics / VictoriaLogs 快照到对象存储 |
| 误伤影响访问 | 真人被挑战或拦截 | shadow → dry-run → 灰度；全局 monitor 开关；受攻击模式手动开关；失败页带 request_id；无障碍路径 |
| 单人范围过大 | 主线拖期 | 严格按阶段裁剪；Phase 4 / 5 只按触发条件做；每阶段都产出可独立运行的版本 |
| JA4+ 许可 | JA4+ 为 FoxIO License 1.1、patent pending；有收入站点是否属于非商业用途存在不确定性 | 默认只用 JA4（BSD-3）；JA4+ 放在默认关闭的 Cargo feature `ja4plus` 后，有收入站点启用前先咨询 FoxIO；永不作为托管服务提供给他人 |
| 隐私合规 | 受保护网站的访客数据仍受 PIPL 等约束；启用 Turnstile 会把访客 IP、TLS 指纹、UA 发往 Cloudflare | 默认最小化；启用 Turnstile 的站点在隐私声明中说明；保留"日志留存 ≥ 6 个月"提示（见 [06](06-policy-console-observability.md#7-隐私与合规)） |

## 已决策

| # | 决策 | 对路线的影响 |
|---|---|---|
| 1 | 技术栈：Rust（数据面：Pingora Edge + Decision Core）+ Go（控制面） | Cargo workspace + Go module 的 monorepo；策略由 Go 侧 cel-go 编译，Rust 侧只求值 IR |
| 2 | 大部分站点已有 CDN / 网关，**Cloudflare 优先**；流量以浏览器为主；移动端按需、后期 | Phase 1 以 `cloudflare` profile 为主线；HTTP/2 帧级指纹无限期推迟；移动 SDK 移到 Phase 5 |
| 3 | 部署在公有云 | 精简拓扑：Cloudflare → Tunnel → Edge（systemd）→ 源站，外加一台大脑 VM；不用 Kubernetes |
| 4 | 交互式 Challenge **自研**，并接入 Cloudflare（前置 CDN + Turnstile 可选 Provider） | Phase 2 做自研按住验证、无障碍路径与 Provider trait；Turnstile 只用于非大陆访客且必须可回退 |
| 5 | 平台**仅所有者自用**，只用于其几个网站 | 去掉多租户、SaaS、多人审批；工期按单人估算；成本是一级约束 |

## 仍待确认

| 问题 | 影响 | 最晚何时需要 |
|---|---|---|
| 各 Cloudflare zone 的套餐（Free / Pro） | Tier 1 用 Worker（Free）还是 Snippet（Pro 及以上）；Skip 规则能否跳过 SBFM（Free 无 SBFM，只能跳过 products）；可选 MessageMAC Cookie 优化仅 Pro 及以上 | Phase 1 开始前 |
| 站点是否备案 / 是否有大陆主机 | 源站区域（未备案默认香港 / 东京 / 新加坡）；是否需要境内 CDN 的 profile（`esa` / `edgeone`，Phase 4） | Phase 1 部署前 |
| 源站所在云与区域 | Edge 与 Valkey 必须同区域 / 同 VPC；大脑 VM 选址；云安全组同步目标 | Phase 1 部署前 |
| 站点是否有登录 | 无障碍替代方式（passkey 或邮件链接） | Phase 2 开始前 |
| 站点是否有收入（广告、付费内容） | JA4+ 能否启用 | 启用 JA4+ 之前（不阻塞主线） |
| Bot Fight Mode 当前是否开启 | Free 区需关闭，否则会在 `/__mg/*` 前插入不可控挑战 | Phase 1 monitor 上线前 |
| 真实 zone 上的实测项：经 Tunnel 到达的 `CF-Connecting-IP`；访客自带的 `CF-Worker` 头是否被 Cloudflare 删除或覆盖；Cloudflare 是否把源站的 414 / 431 / 425 原样回传；`cf.tls_*` 字段在各套餐与 HTTP/3 下的可用性及 `ciphers_sha1` 的有效拼写；`bot_management` 接口在各套餐下的字段；挑战页经 Cloudflare 后的 `cf-cache-status` 是否为 `DYNAMIC` / `BYPASS` | 客户端 IP；`CF-Worker` 不被删除时访客只能让自己被 403；EDGE_TLS 缺失告警的噪声；`cf audit` 第 9、10、16 项的自动化程度；超长请求与早期数据的用户体验；缓存泄漏 | Phase 1 monitor 周内（[规格 §19](impl/phase1-spec.md#19-待实测与未决)；Valkey ACL 一项已在 9.1.2 上实测通过） |
| 首次 `mgctl crawler sync` 前核对官方 IP 段 URL 与 UA 标识 | 源文件中的 URL 取自规格、未用工具重新抓取；失效的 URL 首次同步即失败 | 首次同步前 |

## 参考

- Cloudflare China Network FAQ（Turnstile 不支持中国大陆；境外节点访问的延迟与可靠性）：https://developers.cloudflare.com/china-network/faq/
- Cloudflare Bot Management variables（JA3 / JA4 仅限 Enterprise Bot Management）：https://developers.cloudflare.com/bots/reference/bot-management-variables/
- Cloudflare Request Header Transform Rules：https://developers.cloudflare.com/rules/transform/request-header-modification/
- Cloudflare Snippets（Free 不可用）：https://developers.cloudflare.com/rules/snippets/
- Cloudflare IP 段 API：https://api.cloudflare.com/client/v4/ips
- Pingora（CHANGELOG 中的版本与破坏性变更）：https://github.com/cloudflare/pingora
