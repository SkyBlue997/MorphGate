# 01 整体架构

> 本文是总纲。上游模型与 Cloudflare 集成细节见 [08](08-upstream-and-cloudflare.md)，自研交互式 Challenge 见 [09](09-interactive-challenge.md)，数据模型与保留期见 [02](02-data-flow.md)，关键取舍的记录见 [ADR](adr/README.md)。

## 1. 目标与设计原则

**目标**：为所有者自己的几个网站（以浏览器网页为主，API 为辅）提供自动化流量识别与分级处置、AI Agent / AI 爬虫的身份区分与授权治理，以及可审计、可灰度、可解释的策略运营。平台**仅所有者自用**，不做多租户，不作为 SaaS 或托管服务提供给他人；优先精简、低成本、单人可运维。

**前提**（所有者已确认）

| 项 | 结论 |
|---|---|
| 使用者 | 仅所有者本人；无租户、无多人审批 |
| 流量 | 以浏览器网页为主；API 为辅；移动端按需、后期 |
| 前置 | 大部分站点已有 CDN / 网关，**Cloudflare 优先**（Free / Pro 套餐） |
| 部署 | 公有云；未备案时源站区域默认香港 / 东京 / 新加坡 |
| 技术栈 | Rust 数据面（Pingora Edge + Decision Core）、Go 控制面 |
| 交互式 Challenge | 自研为默认；Turnstile 等作为可选 Provider（见 [09](09-interactive-challenge.md)） |

**设计原则**

1. **一个内核，多种上游**：判定语义集中在 Decision Core（纯函数、无 I/O）。Edge 通过 `UpstreamProfile` 适配不同前置（Cloudflare、直连 TLS 等），只负责认证上游、采集上下文和执行动作。
2. **快慢分离**：内联路径只做 O(1) 查表与轻量计算（目标附加延迟 p50 < 1 ms、p99 < 5 ms）；会话、行为等重分析放在近线，结果以实体 verdict 回灌内联路径。
3. **身份优先于猜测**：可密码学验证的身份（授权 Agent 签名、已验证爬虫、持有证明）优先于启发式判断。
4. **证据不足时收集证据，而不是直接阻断**：中等风险、低置信度优先走 Challenge；每个判定都带可解释的 reason code。
5. **渐进式执法**：新规则 / 模型先 shadow → monitor → 灰度 enforce，可一键回滚；另有全局 monitor 开关。
6. **每个控制点都有明确的威胁模型**：说清楚它防什么、不防什么。目标是提高自动化的成本，而不是追求"不可绕过"。
7. **信号有来源，缺失有语义**：只采信经认证上游转发的信号头；信号状态分 `PRESENT` / `ABSENT` / `MISSING`（语义见 [03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)）。上游本就不提供的信号为 `MISSING`，不计入置信度，绝不当作人类证据。
8. **测试环境默认拒绝自动化**：预发 / 测试环境对自动化采用白名单模型，只有持有有效授权的 Agent 可进入。
9. **精简优先**：不引入 Kafka / Kubernetes / 独立密钥服务；任一有状态组件故障时数据面只降级、不停服。
10. **隐私最小化与平台自身安全**：客户端原始信号在端上摘要化；数据按站点隔离，密钥范围见 §10；配置签名下发；不向客户端泄露检测细节。

## 2. 范围与非目标

| 在范围内 | 不在范围内 |
|---|---|
| L7 自动化流量识别与处置（爬取、撞库、批量注册、抢购、接口滥用、扫描探测、未授权 AI 自动化） | L3/L4 容量型 DDoS（依赖 Cloudflare 等上游） |
| 应用层洪泛（CC）的限速与挑战 | 通用 WAF 的完整规则集（由前置 CDN 或可选的 OWASP Coraza + CRS 提供，不重造） |
| Web（浏览器）与 API 的统一凭证与判定；API 保护（API Key、OpenAPI 正向模型）按需、未排期；移动端按需、后期 | 业务风控决策（交易反欺诈等），只输出信号供业务消费 |
| AI Agent 身份验证、授权与访问策略 | 多租户、SaaS、为他人提供托管服务 |
| 自研交互式 Challenge；Turnstile 与大陆验证码作为可选 Provider | 对第三方产品（含前置 CDN 的防护与 CAPTCHA）的对抗、绕过研究 |
| 与 Cloudflare 前置的集成：上游认证、信号转发、配置审计（见 [08](08-upstream-and-cloudflare.md)） | Cloudflare Enterprise 能力（Bot Management、China Network）；HTTP/2 帧级与 TCP 层指纹（在 Cloudflare 之后不可得，无限期推迟） |

## 3. 威胁模型（防御视角）

**业务威胁**：凭证填充、批量注册、内容 / 价格 / 库存抓取、抢购与库存占用、短信 / 邮件轰炸、营销活动滥用、API 枚举（对象级越权探测）、漏洞扫描、未授权 AI 爬取与 Agent 自动化、应用层洪泛。

**自动化能力分级**（用于校准各控制点的预期效果）：

| 级别 | 典型形态 | 主要依靠的控制点 |
|---|---|---|
| A1 | 脚本化 HTTP 客户端 | 凭证缺失、不执行 JS 拿不到凭证、限速；协议层一致性（JA4 vs 声明的 UA）仅在 `direct_tls` 下可用，Cloudflare 之后退化为 `EDGE_TLS` 弱信号 |
| A2 | 无头 / 自动化浏览器 | 浏览器完整性信号、Challenge、行为序列、IP 类型 |
| A3 | 定制自动化 + 代理池（数据中心 / 住宅） | 凭证绑定与持有证明、实体关联（指纹簇 × IP × 账号）、行为模型、经济成本（PoW、限额） |
| A4 | 真实设备农场 / 人工辅助 / 打码服务 | 业务层限额、账号关联、凭证签发配额（按前缀 / ASN）、解题时间分布监控；不追求单点拦截 |

没有单一控制点能覆盖 A3/A4，系统依靠多层信号叠加与成本抬升。已发表研究显示，自动求解与打码服务对常见交互式 Challenge（图像、滑块、Turnstile 等）的成功率接近 100%，打码服务价格约每千次 $0.10–5。因此交互式 Challenge 通过只算**封顶的人类证据**，其价值在于一次性 nonce 与绑定、PoW 成本、服务端评分和签发配额（见 [09](09-interactive-challenge.md)）。平台自身的 STRIDE 威胁模型见 [10](10-threat-model.md)。

**部署相关威胁**（由前置 CDN 引入，均在 [08](08-upstream-and-cloudflare.md) 展开）：

| 威胁 | 对策 |
|---|---|
| 不经 CDN 直连源站并伪造上游头（`CF-Connecting-IP`、`x-mg-cf-*` 等） | Tunnel 或 AOP（自有 CA）认证上游；未认证时删除全部已知上游头族，以 TCP 对端为客户端 IP |
| 伪造 `X-Forwarded-For` 左侧 / `True-Client-IP` | `cloudflare` profile 只取 `CF-Connecting-IP` |
| 回源连接被多个访客复用，导致状态串扰 | 不以下游连接作为任何状态的键 |
| 缓存把挑战或凭证响应发给其他访客 | `/__mg/*`（内容哈希的 SDK 构建除外）与 Challenge 响应 `no-store, private`；Challenge 用 403/429；最后一条 Cache Rule 对 `/__mg/` Bypass；控制面审计 |
| 上游自带的 Bot 功能在 `/__mg/*` 前插入不可控挑战（双重挑战） | 共存配置 + `mgctl cf audit`；SDK 识别 `cf-mitigated: challenge` |

## 4. 分层架构总览

```
                    Visitor (browser / API client)
                                   |
                                   v
+----------------------------------+----------------------------------+
| Cloudflare zone (Free / Pro)                                        |
|   TLS termination, DDoS, cache, visitor location headers            |
|   Tier 0: Transform Rule -> x-mg-cf-*                               |
|   Tier 1 (optional): Snippet (Pro+) or Worker (Free)                |
+----------------------------------+----------------------------------+
                                   | Cloudflare Tunnel (preferred)
                                   | or AOP mTLS with own CA
                                   v
+----------------------------------+----------------------------------+
| Edge host x N (systemd; may be the origin host)                     |
|   cloudflared -> MorphGate Edge (Pingora + BoringSSL, 127.0.0.1)    |
|   0 UpstreamProfile   authenticate upstream; map / strip headers    |
|   1 Signal Extractor  x-mg-cf-* | JA4 (direct_tls only) | headers   |
|   2 Identity          token / proof / agent signature / crawler     |
|   3 Enrichment        IP-ASN-Geo / lists / entity verdicts          |
|   4 Rate Limiter      local + global GCRA                           |
|   5 Decision Core     detectors -> score -> policy (pure, no I/O)   |
|   6 Challenge API     /__mg/*  issue / verify / refresh             |
|                       InteractiveChallengeProvider                  |
|   7 EventSink         bounded ring buffer -> batch writer           |
+---+------------------+--------------------+-------------------^-----+
    | allow +          | DecisionEvents     | Valkey pipeline   | signed config
    | MG-* headers     | (batched)          | + pub/sub         | (ETag pull)
    v                  v                    v                   |
 Origin   +-----------------------------------------------------+-----+
          | Brain VM (4-8 GB)                                         |
          | VictoriaLogs         Valkey (AOF everysec)                |
          |   vl-main  events      counters / nonce / jti / verdicts  |
          |   vl-short telemetry   revocation set + pub/sub           |
          | VictoriaMetrics        Stream -> Go near-line worker      |
          |   + vmalert                   -> verdicts back to Valkey  |
          | Grafana (optional)                                        |
          | Go control plane: Admin API, Console, mgctl,              |
          |   policy compiler (cel-go), registries, audit hash chain, |
          |   PostgreSQL or SQLite                                    |
          +-----------------------------+-----------------------------+
                                        | Cloudflare API: cf audit,
                                        | IP range sync, Turnstile widgets
                                        v
                                api.cloudflare.com

 Optional: Edge -> challenges.cloudflare.com (Turnstile siteverify),
           only inside POST /__mg/c when Turnstile is the chosen provider
 Phase 4:  single-node ClickHouse as an additional EventSink target
 No CDN:   Visitor --TLS--> Edge on a public listener (direct_tls)
```

- **数据面**：每请求内联执行，只依赖本地内存和同区域的 Valkey；不同步调用控制面、日志存储或近线 worker。唯一的外部调用是交互式 Challenge 选用外部 Provider 时，在 `POST /__mg/c` 内带截止时间调用其校验接口，不在普通请求路径上。
- **近线**（Phase 2）：Go worker 消费 Valkey Stream，做会话聚合、实体 verdict、扫描器识别，结论写回 Valkey，下一请求即生效。
- **分析**：VictoriaLogs 按保留期分两个实例：`vl-main` 存 DecisionEvent 等（30 天），`vl-short` 存 Challenge / SDK 遥测（7 天）；Phase 4 开始 ML / 复杂 SQL 时再加单节点 ClickHouse。
- **控制面**：配置、注册表与审计的唯一来源。Edge 主动拉取签名配置包（ETag 条件请求，mTLS 或 WireGuard 内网；Phase 1–2 从大脑 VM 上的静态位置拉取，Phase 3 起长轮询 mg-control），吊销经 Valkey pub/sub 即时通知；控制面不可用时 Edge 使用 last-known-good（流程见 [02 §6](02-data-flow.md#6-配置模型与密钥下发)）。控制面还通过 Cloudflare API 做配置审计、IP 段同步与 Turnstile widget 管理。

## 5. 组件划分

| 组件 | 平面 | 职责 | 状态 | 阶段 |
|---|---|---|---|---|
| **MorphGate Edge** | 数据面 | Pingora 反向代理（BoringSSL）；按 UpstreamProfile 认证上游、映射或删除上游头、确定可信客户端 IP；信号提取、内联判定与处置；托管 `/__mg/*` 端点 | 无状态（本地缓存） | P1 |
| **UpstreamProfile 处理**（Edge 内） | 数据面 | 每监听器声明上游认证方式、上游头 → 规范信号映射、预期可得信号集（见 §6） | 配置 | P1：`cloudflare`、`direct_tls`；其余按需 |
| **Decision Core** | 数据面（库） | `RequestContext → Signals → RiskAssessment → Policy → Action`；纯函数、无 I/O、状态走 trait，可编译到 `wasm32-unknown-unknown` | 无状态 | P1 |
| **Challenge Service** | 数据面 | Challenge 下发与校验，凭证签发 / 刷新 / 吊销（逻辑属于 Decision Core，端点由 Edge 托管） | 无状态 + 重放集合（Valkey） | P1 无感；P2 交互式 |
| **InteractiveChallengeProvider** | 数据面（trait） | Provider 抽象：trait 与 `self_hold`（默认）、`pow_a11y` 在 mg-core；`turnstile`（非大陆）、`tencent` / `aliyun_v2` 在 mg-edge 经注入的 `OutboundHttp` 调用。Provider 由 Decision Core 选定，外部 Provider 故障回退自研，绝不 fail-open（见 [09](09-interactive-challenge.md)） | 无状态 | P2；大陆 Provider P4 |
| **EventSink** | 数据面（trait） | 内存有界环形缓冲（可选小磁盘溢写）→ 批量写 VictoriaLogs（`vl-main` / `vl-short`）；近线事件以 `XADD MAXLEN ~` 写 Valkey Stream。以后可加 ClickHouse 或换 NATS JetStream（单节点）而不改 Decision Core | 缓冲 | P1 |
| **Cloudflare 模板**（`adapters/cloudflare/`） | 接入 | Tier 0 Transform Rule、Tier 1 Snippet / Worker、缓存 Bypass 与 Skip 规则模板 | — | P0–P1 |
| **Web SDK** | 客户端 | 环境 / 自动化 / 行为摘要、会话密钥与 MG-Proof、无感与交互式 Challenge UI、静默刷新、遥测、`cf-mitigated` 处理；第一方 `/__mg/` 提供，≤ 30 KB gzip | — | P1 无感脚本；P2 v1 |
| **Mobile SDK** | 客户端 | 设备证明、硬件密钥签名；仅在需要时 | — | P5 |
| **Morph Engine** | 构建 | SDK 与 Challenge 脚本多态构建与轮换；动态表单字段 | 构建产物 | P5 |
| **State Store** | 状态 | Valkey 单实例（AOF everysec）：限速计数、nonce / jti、会话状态、实体 verdict、吊销集、事件 Stream；与 Edge 同区域 | 有状态 | P1 |
| **Near-line Worker** | 近线 | Go worker 消费 Valkey Stream：会话聚合、实体 verdict、扫描器识别，回写 Valkey | 窗口状态（Valkey） | P2 |
| **Log / Event Store** | 分析 | VictoriaLogs 两个实例：`vl-main`（DecisionEvent、最小访问记录、审计镜像、应用日志，30 天）、`vl-short`（Challenge / SDK 遥测，7 天）；保留期见 [02 §9](02-data-flow.md#9-采样与保留) | 有状态 | P1 |
| **Metrics** | 可观测 | VictoriaMetrics 单节点抓取 Edge（pingora-prometheus）、控制面、node_exporter，保留 13 个月；vmalert 少量告警；Grafana 可选 | 有状态 | P1 |
| **Analytics Store** | 分析 | 单节点 ClickHouse LTS（低内存配置），开始 ML / 复杂 SQL 时再加 | 有状态 | P4 |
| **ML Pipeline** | 离线 | 标签、GBDT、概率校准、TreeSHAP、漂移监控，模型签名下发 | — | P4 |
| **Intel Sync** | 控制面任务 | IP / ASN / 地理库（GeoLite2）、云厂商网段、Tor 出口、爬虫官方 IP 段、Agent 密钥目录的同步与校验 | — | P1 起 |
| **Control Plane** | 控制面 | Go：`mgctl`（cel-go 编译策略包；Phase 1–2 在所有者工作站签名）、`mg-control`（Admin API、配置包服务、Agent / 爬虫注册表、测试授权工单单人流程、密钥轮换；Phase 3 起承担配置签名） | PostgreSQL 或 SQLite | P1 `mgctl`；P3 服务 |
| **Cloudflare 集成** | 控制面 | `mgctl cf audit` 经 Cloudflare API 检查共存配置（检查项见 [08 §2.10](08-upstream-and-cloudflare.md#210-mgctl-cf-audit)）；同步 Cloudflare IP 段到 Edge 可信代理快照与云安全组；管理 Turnstile widget 与 secret 轮换；API Token 按用途拆分、最小权限 | — | P1 audit 与 IP 同步；P2 widget |
| **Console** | 控制面 | 精简管理后台；passkey 登录（TOTP 备用），可选只读账号 | — | P3 |
| **Audit Log** | 控制面 | 追加写、哈希链；每日锚点签名后写入对象存储（云厂商支持时开启对象锁） | 有状态 | P1 `mgctl` 本地哈希链日志；P3 起由控制面承载 |
| **Validation Lab** | 测试 | 在自有目标上回放标注流量并评估检测效果；目标白名单在工具内强制 | — | P0 |

## 6. 接入模式

**结论**：个人版只有一种主形态——Edge 作为反向代理位于源站之前；前面是谁、如何认证、能提供哪些信号，由每个监听器配置的 `UpstreamProfile` 描述。原 M1–M5 中"M1 位于 CDN 之后"的笼统说法由 UpstreamProfile 取代；其余形态降为按需。

**UpstreamProfile 声明三件事**：(a) 上游如何被认证；(b) 上游头 → 规范信号的映射；(c) 该上游**预期能提供**哪些信号，用于区分"上游本就不提供"与"缺失且可疑"。

| UpstreamProfile | 典型上游 | 上游认证（`auth_method`） | 协议层信号概况 | 阶段 |
|---|---|---|---|---|
| `cloudflare`（首要） | Cloudflare Free / Pro | `loopback`（Tunnel，首选）或 `origin_mtls`（zone-level / per-hostname AOP，自有 CA，不用全局共享证书）；可叠加 `secret_header` | 访客 JA4 / H2 / 头顺序为 MISSING；Tier 0 转发 `x-mg-cf-*`（见 §7） | P1 |
| `direct_tls` | 无 CDN，Edge 自己终止 TLS | `none`（公网直连） | JA4 由 Edge 自算；HTTP/1 原始头顺序与大小写 | P1 |
| `proxy_protocol{v1\|v2, allowed_src_cidrs}` | L4 负载均衡 | `src_cidr` | 同 `direct_tls` | P5 |
| `cloudfront` / `gcp_alb` | AWS CloudFront / GCP 外部 ALB | `origin_mtls` 或 `secret_header` | 可转发 JA4 等（需配置） | P4，按需 |
| `esa` / `edgeone` | 阿里云 ESA / 腾讯云 EdgeOne | `origin_mtls` 或 `secret_header` | 非 Enterprise：基本只有 IP + 地理 | P4，按需 |
| `alicdn` / `tencent_cdn` | 阿里云 CDN / 腾讯云 CDN | `secret_header` | 只有 IP（+ 端口） | P4，按需 |
| `envoy` / `openresty` | 自建网关 | `origin_mtls` | Envoy ≥ 1.35、OpenResty ≥ 1.29.2.1 + lua-resty-ja4 可转发 JA4 | P4，按需 |

各 profile 的头名、认证细节与逐项信号表见 [08](08-upstream-and-cloudflare.md)。AWS ALB 不能转发 JA3/JA4，不要放在 Edge 前。

**信任规则**（所有 profile 通用；判定顺序与删除清单见 [08 §1.2](08-upstream-and-cloudflare.md#12-信任规则)）

- profile 绑定在监听器上，不看 Host 头。只有上游认证通过才采信该 profile 的信号头；否则删除全部已知上游头族，以 TCP 对端为客户端 IP。云防火墙只放行 CDN IP 段属于纵深防御，不作为唯一依据。
- `cloudflare` 下客户端 IP 只取 `CF-Connecting-IP`（Pseudo IPv4 = Overwrite 时取 `CF-Connecting-IPv6`，建议保持关闭），**永远不用** `X-Forwarded-For` 最左项、`True-Client-IP`、`X-Real-IP`。认证通过却缺少 `CF-Connecting-IP` → 配置告警，不回退到 Cloudflare 对端 IP。AOP 对 Tunnel 主机名不生效，同一主机名不混用两条路线。
- 信号带来源与认证状态（如 `tls.ja4 {value, source, authenticated}`），CDN 转发的 JA4 权重略低于 Edge 自算。回源连接被多个访客复用：**不得以下游连接作为任何状态的键**。

**其他形态**

| 形态 | 说明 | 个人版状态 |
|---|---|---|
| Edge 反向代理 | 流量经 Edge；上游由 UpstreamProfile 描述 | 主形态，P1 |
| Web SDK | 叠加在任意 profile 上，提供浏览器信号与持有证明 | P1 无感脚本，P2 v1 |
| Mobile SDK | 设备证明、硬件密钥 | 仅在需要时（P5） |
| 网关插件 / 服务端中间件（原 M2 / M3，Decision API） | 无法改变流量路径的应用 | 按需、未排期 |
| Cloudflare Worker 内运行 Decision Core（WASM） | Decision Core 保持可编译到 wasm32；Workers 无线程、无 tokio 网络，nonce 与重放状态需 Durable Objects 而非 KV | 按需、未排期 |
| 旁路分析 | 只收日志、不内联处置 | 不做；Edge 以全局 monitor 模式运行即可替代 |

## 7. 信号可用性矩阵

**结论**：在 `cloudflare` profile 下，Edge 看到的 TLS、HTTP/2、TCP 连接属于 Cloudflare（或 cloudflared），不是访客；访客 JA4 只对 Enterprise + Bot Management 提供，超出预算。因此 TLS 族与部分 HTTP 信号为 `MISSING`，由 Tier 0 Transform Rule 免费转发的 `x-mg-cf-*` 构成低权重的 `EDGE_TLS` 族补位，主要证据转向 Web SDK、Challenge、凭证绑定、限速与 IP / ASN。

下表按信号族概括 Phase 1 两种 profile。逐信号矩阵与状态语义以 [03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性) 为准；Transform Rule 映射、套餐可用性与待实测项见 [08 §2](08-upstream-and-cloudflare.md#2-cloudflare-前置cloudflare-profile)，其他上游见 [08 §3](08-upstream-and-cloudflare.md#3-其他-cdn-与云负载均衡)。

| 信号族 | `direct_tls` | `cloudflare`（Tier 0） |
|---|---|---|
| NETWORK（IP、ASN、地理、RTT） | TCP 对端 + 本地 IP 库；RTT 未规划 | `CF-Connecting-IP` + 本地 IP 库；`x-mg-cf-asn`、`cf-ipcountry`、`cf-timezone` 只作交叉校验；`x-mg-cf-rtt` / `x-mg-cf-quic-rtt` |
| TLS（JA4） | Edge 自算 | MISSING |
| EDGE_TLS（`x-mg-cf-tls-*`） | 不适用 | 可得；低权重、低封顶，Phase 1 只 shadow |
| HTTP | 头顺序 / 大小写（HTTP/1）、`Accept-Encoding`、`Connection` 为原值；HTTP/2 帧指纹无限期推迟 | 头顺序 / 大小写、`Accept-Encoding`、`Connection`、HTTP/2 帧指纹为 MISSING；头名集合（`x-mg-cf-hdr-names`，只当集合用）与 HTTP 版本可得；Client Hints、Fetch Metadata、Cookie 等原样透传 |
| EXTERNAL（上游 bot verdict） | 不适用 | `x-mg-cf-vbot` / `x-mg-cf-vbot-cat`，只作佐证 |
| CLIENT / BEHAVIOR | Web SDK / 近线 | 同左 |
| 每连接键（`client_conn_key`） | Edge 下游连接 | `hash(x-mg-cf-tls-random)`；不以回源连接为键 |
| 凭证 TLS 绑定 | `bind.tfp`（JA4 预研成功后启用） | `bind.ctp`：仅 shadow，稳定性 ≥ 99% 后才可转为软绑定（见 [04](04-challenge-and-tokens.md)） |

- Tier 1（可选：Pro 及以上用 Snippet，Free 用只路由 HTML 与 `/__mg/*` 的 Worker）另补 `x-mg-cf-priority`、`x-mg-cf-accept-encoding`、`x-mg-cf-as-org`；Tier 2（Enterprise Bot Management 的 `cf-ja4` / `cf-bot-score`）超出预算，不规划。
- `MISSING`（profile 不提供，或上游应注入的头未到达 / 来源不可确认）不计入置信度，绝不当作人类证据；Tier 0 头缺失另外触发配置告警（`mg_upstream_signal_missing_total`），Tier 1 未运行（含 Worker fail-open）不告警（[08 §1.4](08-upstream-and-cloudflare.md#14-信号溯源与预期信号)）。`ABSENT`（profile 应能提供但本请求没有，如首个请求尚无 SDK 遥测）计入分母，置信度下降。
- `EDGE_TLS` 的扩展哈希稳定性未文档化，未经实测不得用于硬绑定或高权重；族定义、权重与转 active 条件见 [03](03-risk-scoring.md)。

## 8. 部署与高可用

**结论**：推荐拓扑为 Cloudflare → Cloudflare Tunnel → Edge（systemd）→ 源站，外加一台"大脑" VM。高可用来自同一 tunnel 的多个 cloudflared 副本（免费主备）；大脑 VM 故障只降级。不用 Kafka / Redpanda / Kubernetes。

**形态**

| 形态 | 组成 | 估算月成本 |
|---|---|---|
| 开发 | `deploy/compose/`：Valkey、PostgreSQL、VictoriaMetrics、VictoriaLogs（`vl-main` / `vl-short`）、可选 Grafana、mock 源站 | 本机 |
| 最小生产 | 1 台 VM 全合一：cloudflared + Edge + 源站 + 大脑组件 | 约 $25–50 |
| 推荐生产 | 2 台 Edge 主机（各一个 cloudflared 副本，Edge 可与源站同机）+ 1 台大脑 VM（4–8 GB） | 约 $50–80 |
| 全托管（不推荐） | EC2 + RDS + ElastiCache | 约 $120–180 |

```
                         Cloudflare (Free / Pro)
                  |                                   |
                  | tunnel replica 1                  | tunnel replica 2
                  v                                   v
   +--------------+--------------+     +--------------+--------------+
   | edge-1 (region A)           |     | edge-2 (region A)           |
   | cloudflared                 |     | cloudflared                 |
   | mg-edge on 127.0.0.1        |     | mg-edge on 127.0.0.1        |
   | origin app (optional)       |     | origin app (optional)       |
   +--------------+--------------+     +--------------+--------------+
                  |                                   |
                  +-----------------+-----------------+
                                    | private network (VPC / WireGuard), RTT < 1 ms
                                    v
              +---------------------+---------------------+
              | brain VM (region A, 4-8 GB)               |
              | Valkey (AOF everysec)                     |
              | mg-control + PostgreSQL / SQLite          |
              | VictoriaMetrics  vmalert                  |
              | VictoriaLogs: vl-main, vl-short           |
              | Grafana (optional)                        |
              +---------------------+---------------------+
                                    | nightly backup
                                    v
                             object storage
```

**要点**

| 项 | 做法 |
|---|---|
| 入口 | cloudflared 与 Edge 同机，Edge 只监听 127.0.0.1、只信任回环对端，主机无需公网入站端口；同一 tunnel 的副本是就近路由而非负载均衡（[08 §2.1](08-upstream-and-cloudflare.md#21-源站保护)） |
| AOP 路线 | 不用 Tunnel 时 Edge 公网监听：TLS 前用 Pingora ConnectionFilter 按 Cloudflare IP 段过滤，并要求链到自有 AOP CA 的客户端证书 |
| Edge 进程 | systemd + Pingora 平滑升级（监听 socket 迁移），宽限期内完成的请求不中断；WebSocket 等长连接仍可能被切断 |
| Edge 与 Valkey | **必须同区域 / 同 VPC（RTT < 1 ms）**；否则该 Edge 以本地模式运行（本地计数、本地 verdict 缓存，重放检查按降级表处理）。多区域不规划 |
| 大脑 VM | Valkey（AOF everysec）、Go 控制面 + PostgreSQL（容器；也可 SQLite）、VictoriaMetrics（13 个月）、VictoriaLogs `vl-main`（30 天）与 `vl-short`（7 天）、可选 Grafana；各类数据保留期见 [02 §9](02-data-flow.md#9-采样与保留) |
| 配置下发 | Edge 拉取签名配置包（mTLS 或 WireGuard 内网），吊销经 Valkey pub/sub 即时通知；分阶段做法见 [02 §6](02-data-flow.md#6-配置模型与密钥下发) |
| 密钥 | 各主机上的密钥以 systemd credentials 交付，不部署独立密钥服务（§9、§10） |
| 区域 | 未备案 → 香港 / 东京 / 新加坡；带流量套餐的 VPS 最省（如腾讯 Lighthouse 香港 2C2G $6、4C8G $36；阿里 SAS 2C4G $19；Lightsail 4 GB $24） |
| 托管服务 | 只在想省运维时使用；数据面从不同步访问数据库，自动暂停的 serverless PostgreSQL 可用，但控制面要容忍 15–30 s 冷连接 |
| 备份 | 每晚把 Valkey RDB、pg_dump / SQLite 文件、VictoriaMetrics / VictoriaLogs 快照写入对象存储 |

**不用的组件**

| 组件 | 原因 |
|---|---|
| Kafka（KRaft） | 生产部署需 ≥ 3 个控制器，默认每个 1 GB 堆；对个人站点的遥测量不成比例 |
| Redpanda | 生产要求 ≥ 3 个 broker、每核 ≥ 2 GB 内存 |
| Kubernetes | EKS 约 $73/月；k3s server 节点 ≥ 2 GB 内存；对 1–3 台 VM 无收益 |
| ClickHouse（Phase 4 前） | 官方建议 32 GB 以上内存，< 16 GB 需专门调优；早期 VictoriaLogs 足够 |
| ClickHouse Cloud | 无香港 / 中国区域，增加跨区流量 |
| OpenBao 等独立密钥服务 | 多一个需要运维的有状态组件；个人版用本机加密的密钥文件（§9） |

**降级策略**（按路由配置 fail-open / fail-closed）

| 故障 | 默认行为 |
|---|---|
| 单台 Edge 主机或 cloudflared 故障 | 同一 tunnel 的其他副本继续服务；单副本部署时站点不可用（单机形态的已知代价） |
| Valkey（重放存储）不可用（或 Edge 不在 Valkey 所在区域） | 限速退化为本地计数；凭证仍可无状态验证；重放检查（jti、Challenge nonce）失效：`critical` 路由 **fail-closed**（不签发凭证，返回"稍后再试"），其余路由放行并标记、不下发交互式 Challenge；单 Edge 且启用进程内 LRU 重放集合时可照常继续 |
| 事件写出失败（EventSink：VictoriaLogs 或 Valkey Stream 不可用） | 本地有界环形缓冲（可选小磁盘溢写），从不阻塞请求；缓冲满时先丢放行流量的采样事件，保留处置事件；近线 verdict 暂停更新，已有 verdict 按 TTL 过期 |
| 大脑 VM 整体故障 | 等同于 Valkey、EventSink、控制面同时不可用：Edge 用 last-known-good 配置与本地计数继续服务 |
| 控制面不可用 | 使用 last-known-good 签名配置，持续告警；配置陈旧超过阈值时告警 |
| 外部交互式 Provider 故障（如 Turnstile 加载超时、siteverify 超时或 5xx、`invalid-input-secret`） | 客户端与服务端回退到自研 `self_hold`，**绝不 fail-open**；错误分类、重试与自动禁用规则见 [09](09-interactive-challenge.md) |
| Cloudflare 挑战挡在 `/__mg/*` 前（响应带 `cf-mitigated: challenge`） | SDK 视为"上游挑战"，不计为 MorphGate 失败；计入 `mg_double_challenge_total`，`mgctl cf audit` 定位配置原因（见 [08 §2.8](08-upstream-and-cloudflare.md#28-cf-mitigated-与双重挑战)） |
| 上游认证失败 | 删除全部上游头族，以 TCP 对端为客户端 IP；认证通过但缺 `CF-Connecting-IP` → 配置告警，不回退到 Cloudflare 对端 IP |
| Tier 1 Worker 超额或故障（fail-open） | 对应 `x-mg-cf-*` 视为 `MISSING`，不当作人类证据 |
| 情报数据过期（含 Cloudflare IP 段同步失败） | 按数据年龄衰减相关信号置信度；IP 段沿用上一份快照并告警 |
| 模型加载失败 | 回退到规则评分 |

**全局 monitor 开关**：一键把全部站点切为只记录、不处置（Phase 1 验收要求以此模式运行 ≥ 1 周）。**"受攻击模式"**：站点级开关，临时提高先验风险、收紧限速、对新会话默认无感 Challenge。

## 9. 技术选型建议

| 领域 | 建议 | 理由 / 备注 |
|---|---|---|
| Edge | **Rust + Pingora**，锁定 0.9.x 的精确版本 | Pingora 仍是 0.x，每个小版本都有破坏性变更；所有 Pingora 相关代码放在薄适配 crate（`edge/`，mg-edge），升级成本可控；Linux 为 tier 1 |
| TLS 后端 | **BoringSSL** | 回调面最完整，可取原始 ClientHello；rustls 在 Pingora 中仍标为实验性 |
| Decision Core | 纯 Rust crate（`core/`，mg-core）：无 I/O，状态走 trait | 可编译到 `wasm32-unknown-unknown`，为以后可能的 Cloudflare Worker 适配保留 |
| JA4 计算（`direct_tls`） | boring select-certificate 回调取 `ClientHello::as_bytes()` → 计算 JA4（huginn-net-tls，MIT/Apache，或自研解析器对照其测试向量）→ ex_data → `handshake_complete_callback` → `SslDigest.extension` → 请求过滤器中读取 | 该链路由 API 推断、尚未实际构建，Phase 1 做技术预研验证 |
| HTTP/2 帧级指纹 | 无限期推迟 | Cloudflare 之后无意义；Pingora / h2 不暴露 SETTINGS 等帧信息。HTTP/1 原始头字节与大小写 Pingora 可直接取（`direct_tls` 时有用） |
| PROXY protocol | Phase 1 不做 | 只在 L4 负载均衡场景需要；将来用 Pingora 0.9 的 PreTlsProcess（仅 TLS 监听器）+ ppp / proxy-header crate |
| 控制面 | **Go**（`control-plane/`：cmd/mgctl、cmd/mg-control） | cel-go 做策略类型检查与编译；Cloudflare API 集成 |
| 策略语言 | **CEL 语法**；cel-go v0.30 编译为受限 IR，数据面自研 Rust IR 求值器 | 非图灵完备、可静态检查；**不在热路径用 `cel` crate**（无类型检查器、一致性测试大量跳过） |
| 凭证 | pasetors 0.8（PASETO v4.local / v4.public） | — |
| 签名 | 全工作区统一一个 Ed25519 实现（ed25519-dalek 3.x 或 aws-lc-rs） | dalek 3.0 为新大版本，部分依赖可能仍停留在 2.x |
| Web Bot Auth | Cloudflare `web-bot-auth` crate 0.7（Apache-2.0）；`httpsig` 作通用 RFC 9421 回退 | httpsig 面向 hyper，需从 Pingora 请求头做小适配 |
| HTML 注入 | lol_html 3.x | 需先处理上游压缩 |
| 状态存储 | **Valkey**（BSD-3）单实例，AOF everysec | 兼任近线事件 Stream；故障切换可能丢失少量 XADD，DecisionEvent 为尽力而为的遥测，可接受 |
| 事件管道 | `EventSink` trait：环形缓冲 → VictoriaLogs；近线 → Valkey Stream | 以后可换 NATS JetStream（单节点 R1）；不用 Kafka / Redpanda |
| 日志 / 事件存储 | **VictoriaLogs**（Apache-2.0），两个实例：`vl-main`（30 天）、`vl-short`（7 天） | 单二进制、低内存、支持高基数字段、内置 UI，替代 Loki；保留期按实例设置（`-retentionPeriod` 或磁盘上限），因此按保留期拆成两个实例 |
| 分析存储 | Phase 4 起单节点 ClickHouse LTS（低内存配置，`async_insert=1` + `wait_for_async_insert=1`） | 不用 ClickHouse Cloud（无香港 / 中国区域） |
| 配置库 | PostgreSQL（容器）或 SQLite | 数据面从不同步访问 |
| 密钥保管 | **本机加密的密钥文件**：Edge / 控制面主机上以 systemd credentials（`systemd-creds`，有 TPM2 时绑定）交付；所有者工作站上的配置签名私钥用 age 加密（口令或硬件密钥插件）；云 KMS 可选；**不部署 OpenBao** | 少一个有状态组件；密钥范围见 §10，轮换周期与敏感操作要求见 [06 §8](06-policy-console-observability.md#8-平台自身安全) |
| 可观测性 | VictoriaMetrics 单节点（抓取 pingora-prometheus，`-retentionPeriod=13` 即 13 个月）+ VictoriaLogs + vmalert；Grafana 可选 | VictoriaMetrics 默认只保留 31 天，需显式设置；Grafana 为 AGPL，自用且未修改即可 |
| 机器学习 | Phase 4：Python（LightGBM / scikit-learn）训练，导出后由 Rust 内联推理 | GBDT 在内联路径上是微秒级；可解释、可校准 |
| Web SDK / Console | TypeScript（`sdk/web/`）；Console 使用 React，保持精简 | SDK ≤ 30 KB gzip |
| Mobile SDK | 仅在需要时 | — |
| IP 数据 | MaxMind GeoLite2（IP / ASN / 地理） | Cloudflare 头只作交叉校验；记录数据年龄 |
| 进程与部署 | systemd（Edge）+ docker compose / systemd（有状态组件） | 不用 Kubernetes |

**JA4 / JA4+ 许可**（非法律意见）

| 方法 | 许可 | 对本项目的含义 |
|---|---|---|
| JA4（TLS 客户端指纹） | BSD-3-Clause（LICENSE-JA4）；FoxIO 声明对 JA4 无专利主张 | 可自由实现或嵌入，保留 BSD 声明 |
| JA4+（JA4S、JA4H、JA4L、JA4LS、JA4X、JA4T、JA4TS 等） | FoxIO License 1.1：只允许非商业用途，定义包括"个人使用"与"不直接将软件变现的内部业务用途"，排除以托管（hosted）或代管（managed）服务方式提供给他人；FAQ 称所有 JA4+ 方法 patent pending | 所有者只保护自己的站点，字面上属于允许范围；但若受保护站点有收入（广告、付费内容），FAQ 中"为付费客户提供价值（即使不直接暴露指纹）需 OEM 许可"的例子是否适用不确定；专利许可只覆盖许可方提供形式的软件，独立重新实现是否被覆盖也不明确 |

结论：**默认只用 JA4**；JA4+ 放在默认关闭的 Cargo feature `ja4plus` 之后，有收入的站点启用前先咨询 FoxIO；MorphGate 永不作为托管服务提供给他人（[ADR-0009](adr/0009-ja4-only-licensing.md)）。在 Cloudflare 之后 JA4H / JA4T / JA4L 本身价值也很低。依赖选择上，huginn-net-tls 声明不含 JA4+ 组件；FoxIO 自己的 Rust crate 是 pcap / tshark 命令行工具（专有许可），不作为依赖。

## 10. 站点模型

```
Site            hostnames, UpstreamProfile, Cloudflare zone, certificates
 +- Environment production | staging | test | dev
     +- Route   path pattern + method + channel (web|api|mobile)
         |      + sensitivity (low|medium|high|critical)
         +- Policy Set  rules, rate limits, challenge config (providers),
                        agent grants
```

- **无租户层**：所有者一人管理全部站点，层级为 Site → Environment → Route → Policy Set。
- **数据隔离**：按站点即可——Valkey 键带 `{site}` 段（如 `mg:v:{site}:{type}:{key}`，命名见 [02 §7](02-data-flow.md#7-核心数据模型)），DecisionEvent 带 `site_id`。
- **跨站点共享**（本节为规范口径）：只共享 IP / ASN 类实体 verdict（ip、prefix、asn）；session、device、account、指纹簇 verdict 永不共享。每个站点一个开关，默认关：开启的站点把自己产生的 IP / ASN 类 verdict 同时写入 `mg:v:all:{type}:{key}`（`site_id = "all"`），并在判定时同时读取本站与 `all` 的 verdict，本站 verdict 优先；关闭的站点只读写本站。
- **密钥**（完整清单与轮换周期以 [06 §8](06-policy-console-observability.md#8-平台自身安全) 为准）：配置签名密钥为所有者**一对**（Ed25519，按 `kid` 年更），签全部站点的配置包；Phase 1–2 由 `mgctl` 在工作站用 age 加密的私钥签名，Phase 3 起由大脑 VM 上的 `mg-control` 签名（systemd credentials），Edge 只持公钥。凭证密钥、Challenge 密封根密钥（每日 epoch 密钥由它派生，[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)）、Turnstile secret 与可选的 MessageMAC Cookie 密钥（[08 §2.9](08-upstream-and-cloudflare.md#29-可选hmac-cookie-跳过pro-及以上)）按站点，以 systemd credentials 交付到主机，配置包只含 `kid` 或引用。
- **后台账号**：所有者本人，passkey（WebAuthn）为主、TOTP 备用；可选只读账号。
- **敏感操作**：单人无法两人审批，改为**重新认证 + 明确确认（输入站点名）+ 可选生效延迟**，全部写审计。适用于生产策略发布、带 scan 能力的测试工单、密钥轮换、删除审计外数据（见 [06](06-policy-console-observability.md)）。
- **合规**：平台自用不需要作为服务通过等保测评，但受保护网站的访客数据仍受 PIPL 等约束；网站作为网络运营者，日志留存 ≥ 6 个月，由最小访问记录每日归档满足（见 [02 §9](02-data-flow.md#9-采样与保留)、[06 §7](06-policy-console-observability.md#7-隐私与合规)）。

## 参考

Cloudflare

- Cloudflare Tunnel：https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/
- Tunnel 副本与可用性：https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-availability/
- Authenticated Origin Pulls：https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/
- AOP zone-level 设置：https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/
- 源站保护方案：https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/
- 回源 HTTP 头：https://developers.cloudflare.com/fundamentals/reference/http-headers/
- IP 段：https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/ ，API `GET https://api.cloudflare.com/client/v4/ips`
- Request Header Transform Rules：https://developers.cloudflare.com/rules/transform/request-header-modification/
- Managed Transforms 参考：https://developers.cloudflare.com/rules/transform/managed-transforms/reference/
- Snippets：https://developers.cloudflare.com/rules/snippets/
- JA3 / JA4 指纹（Enterprise Bot Management）：https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- China Network FAQ：https://developers.cloudflare.com/china-network/faq/

实现与许可

- Pingora README：https://github.com/cloudflare/pingora/blob/main/README.md
- Pingora CHANGELOG：https://github.com/cloudflare/pingora/blob/main/CHANGELOG.md
- Pingora 平滑升级：https://github.com/cloudflare/pingora/blob/main/docs/user_guide/graceful.md
- Pingora systemd：https://github.com/cloudflare/pingora/blob/main/docs/user_guide/systemd.md
- FoxIO JA4 仓库与许可：https://github.com/FoxIO-LLC/ja4 ，https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE ，https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md
- huginn-net：https://github.com/biandratti/huginn-net
- web-bot-auth：https://github.com/cloudflare/web-bot-auth

存储与部署

- Valkey Streams：https://valkey.io/topics/streams-intro/
- VictoriaLogs：https://docs.victoriametrics.com/victorialogs/
- VictoriaMetrics 单节点：https://docs.victoriametrics.com/victoriametrics/single-server-victoriametrics/
- ClickHouse 运维建议：https://clickhouse.com/docs/operations/tips
- ClickHouse 异步插入：https://clickhouse.com/docs/optimize/asynchronous-inserts
- Kafka KRaft：https://kafka.apache.org/43/operations/kraft/
- NATS JetStream 集群：https://docs.nats.io/running-a-nats-service/configuration/clustering/jetstream_clustering
- K3s 系统要求：https://docs.k3s.io/installation/requirements
- EKS 价格：https://aws.amazon.com/eks/pricing/
- Lightsail 价格：https://aws.amazon.com/lightsail/pricing/
- Grafana 许可：https://grafana.com/licensing/

研究

- 打码服务成功率与价格（Ousat et al., Broken Gates，预印本，2026）：https://arxiv.org/abs/2607.18659
- reCAPTCHA v2 图像挑战自动求解（Plesner et al., COMPSAC 2024）：https://arxiv.org/abs/2409.08831
