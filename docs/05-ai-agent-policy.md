# 05 AI Agent 与 AI 爬虫策略

## 1. 目标

1. 区分**经授权的 AI Agent**、**公开爬虫**和**未知自动化客户端**。
2. 默认不允许未知 AI Agent 自动扫描、测试或高频访问受保护站点。
3. 只有所有者明确授权的 Agent 才能进入对应的测试环境或接口，授权有范围、有期限、可随时吊销、全程审计。
4. 以可密码学验证的身份为主，启发式识别为辅。
5. **单一权威**：AI 爬虫 / Agent 策略只在 MorphGate 一处定义。前置 CDN（Cloudflare）要么放行，要么执行由控制面下推的同一份策略（§7.4）。

**Cloudflare 之后的三条硬约束**（详见 [08](08-upstream-and-cloudflare.md)）：

| 约束 | 原因 |
|---|---|
| Web Bot Auth 签名由 Edge 自行验证 | Cloudflare 把客户端请求头原样转发到源站，签名头可到达 Edge |
| 所有基于 IP 的验证（官方 IP 段、rDNS、授权的 `source_ips`）只用 UpstreamProfile 解析出的客户端 IP | `cloudflare` profile 下 TCP 对端是 Cloudflare 边缘或 cloudflared 回环地址，不是访客 |
| Cloudflare 的 verified bot 标记只作佐证 | 它是另一方的判断，粒度与 MorphGate 的分类不同，且 2026-07-01 起包含已签名 Agent |

## 2. 分类

| 类别 | 定义 | 身份依据 | 默认策略 |
|---|---|---|---|
| `AUTHORIZED_AGENT` | 所有者在 Agent Registry 中注册并授权的 Agent | 注册公钥签名（HTTP Message Signatures）、mTLS 客户端证书（仅 `direct_tls`，见 §3.3）或 OAuth 客户端凭证 | 仅在授权范围内放行，独立限额，全量审计 |
| `VERIFIED_CRAWLER` | 公开的搜索 / AI 爬虫，身份可验证 | 运营方公开的 IP 段、rDNS 正反向校验（均基于解析出的客户端 IP）、Web Bot Auth 签名 | 按站点"爬虫用途 × 动作"矩阵处理 |
| `SIGNED_AGENT` | 带有效 Web Bot Auth 签名、运营方可识别，但未被本站授权 | 签名验证通过，密钥目录可信 | 仅公开内容、限额；测试环境拒绝 |
| `DECLARED_AGENT` | 通过 UA 或其他方式自我声明为 Bot / Agent，但无法验证 | 仅声明；Cloudflare verified bot 标记不改变类别（§3.4） | 仅公开内容、更低限额；测试环境拒绝 |
| `IMPERSONATOR` | 声称是已知爬虫 / Agent，验证失败 | 验证明确失败（不含"无法验证"） | 阻断 |
| `AUTOMATION_LIKELY` | 无声明，被信号判定为自动化 | 启发式 | 按风险分级 Challenge / 阻断 |

**`delegated` 标签**：在用户真实浏览器中代用户操作的 Agent（Agent 浏览器、浏览器扩展）。它不是独立类别，而是附加在 `SIGNED_AGENT`、`HUMAN_LIKELY` 或 `AUTOMATION_LIKELY` 上的标签（依据：签名声明或行为信号）。默认允许浏览，敏感操作要求人工确认（见 §8）。

类别与 [03 §2](03-risk-scoring.md#2-分类botclass) 的 BotClass 保持一致。Cloudflare 的 verified bot 标记不对应任何一个类别，只作为 §3.4 所述的佐证信号。

## 3. 身份验证

### 3.1 Web Bot Auth（HTTP Message Signatures）

基于 RFC 9421 的 IETF webbotauth 工作组草案，协议细节以最新草案为准。要点：

```
Signature-Agent: sig1="https://agent.example.com"
Signature-Input: sig1=("@authority" "signature-agent";key="sig1");
                 created=1790000000;expires=1790000300;
                 keyid="<JWK SHA-256 thumbprint>";nonce="...";tag="web-bot-auth"
Signature: sig1=:<base64 signature>:
```

- 覆盖组件至少包含 `@authority`（或 `@target-uri`），且签名覆盖 `Signature-Agent` 头本身。
- 密钥为 Ed25519；密钥目录：`https://<agent-origin>/.well-known/http-message-signatures-directory`，媒体类型 `application/http-message-signatures-directory+json`，JWKS 格式。
- 密钥查找以（目录 URL，keyid）二元组为键，不能只凭 keyid。

**实现选型**

| 组件 | 选型 | 说明 |
|---|---|---|
| Web Bot Auth 验证 | Cloudflare `web-bot-auth` crate 0.7（Apache-2.0） | 实现 draft-meunier-webbotauth-httpsig-protocol；README 附 Rust 验证示例，用于互通测试 |
| 密钥目录解析 | 同仓库的 `http-signature-directory` crate | 由控制面 Intel Sync 使用前需评估 |
| 通用 RFC 9421 回退 | `httpsig` 0.0.x（MIT，README 标注 Work in Progress） | 面向 hyper，需要从 Pingora `RequestHeader` 做一层薄适配；只用于非 Web Bot Auth 的注册 Agent 签名 |

版本锁定与升级策略随 Edge 其他 crate，见 [01 §9](01-architecture.md#9-技术选型建议)。

**MorphGate 的验证流程**

1. 解析三个头，格式错误直接 400。
2. 校验 `tag = "web-bot-auth"`，或本平台注册 Agent 使用的 `tag = "morphgate-agent"`。
3. 查找密钥：注册 Agent 使用 Agent Registry 中登记的公钥（不访问外部）；公开 Agent 使用 Intel Sync 预先抓取、缓存的密钥目录。**请求路径上不同步拉取外部目录**，未知目录按"未验证"处理并异步抓取。
4. 检查覆盖组件是否包含已知会被上游改写的头（§3.2）；包含则结果记为 `component_rewritten`，按"未验证"处理，不判 `IMPERSONATOR`。
5. 验签；校验 `created` / `expires`：本平台要求 `expires - created ≤ 300s`、时钟偏差 ≤ 30s，严于草案允许的上限。
6. `nonce` 重放检查：`SET mg:jti:{site}:{keyid}:{H(nonce)} NX`，TTL = 签名有效窗口（键沿用 [02 §7](02-data-flow.md#7-核心数据模型) 的 `mg:jti:*`）。注册 Agent 强制带 `nonce`。
7. 有请求体的请求要求覆盖 `content-digest`（RFC 9530），注册 Agent 还要求覆盖 `@method`、`@path`、`@query`。
8. 产出 `agent_id`、`operator`、验证方式、验证结果（`valid` / `invalid` / `unverified` / `component_rewritten` / `replay`），写入 RequestContext。

签名是端到端的，验证结果不依赖上游是否认证；但同一请求上的 IP 类校验仍受 §3.3 约束。

### 3.2 Cloudflare 之后的签名验证

**结论**：签名头能到达 Edge，Edge 自己验证；要防的是 Cloudflare 或所有者自己的 Cloudflare 规则改写了被签名的组件。

| 组件 | Cloudflare 行为（来自调研摘要） | 对签名的影响 | 处理 |
|---|---|---|---|
| `Signature` / `Signature-Input` / `Signature-Agent` | 原样转发 | 无 | Edge 验证 |
| `accept-encoding` | 总是改写为 `br, gzip` | 覆盖此头的签名必然失败 | 记为 `component_rewritten`；在 Agent 接入文档中写明"不要签 accept-encoding" |
| `connection` | 总是改写为 `Keep-Alive` | 同上 | 同上 |
| `x-forwarded-for` | 追加而非覆盖 | 同上 | 同上 |
| `x-forwarded-proto` | 设为客户端实际使用的协议 | 可能变化 | 同上 |
| `x-real-ip` | 无 Worker 子请求时被删除 | 同上 | 同上 |
| `@authority` | 预期保持 Host（需实测） | 若所有者在 Origin Rules 或 cloudflared 的 `httpHostHeader` 中改写 Host，签名失败 | 签名流量所在主机名不改写 Host；`mgctl cf audit` 提示（检查项需确认可行） |
| `@path` / `@query` | 预期保持（需实测） | URL Rewrite 规则会改变它们 | 同上，不对签名流量路径做 URL Rewrite |
| `x-mg-cf-*` | 由本站 Transform Rule 设置，覆盖客户端同名头 | Agent 不应签这些头 | 覆盖即视为 `component_rewritten` |
| 请求体（`content-digest`） | 未见改写的记载 | — | 需实测 |

- 若将来用 Worker / Snippet 重建请求（Tier 1），必须保留三个签名头及所有被签组件。
- `component_rewritten` 单独计数（`mg_wba_verify_total` 的 `result` 标签，[06 §5](06-policy-console-observability.md#5-日志指标与告警)）。持续出现说明某个 Agent 的签名组件选择与 Cloudflare 不兼容，或所有者的 Cloudflare 规则改写了组件，两者都需要人工处理，不能放宽验证。

### 3.3 其他身份来源

| 方式 | 适用 | Cloudflare 之后 |
|---|---|---|
| mTLS 客户端证书 | 服务端到服务端的注册 Agent；证书由所有者自有 CA 签发（私钥与 AOP CA 同样离线保存，见 [06 §8](06-policy-console-observability.md#8-平台自身安全)），短有效期 | **不可用**：客户端 TLS 在 Cloudflare 终止，Edge 看不到客户端证书；Cloudflare 侧 mTLS 结果（`cf-cert-*` 头）不规划。mTLS 只在 `direct_tls` 监听器上可用，其他 Agent 改用 HTTP Message Signatures |
| OAuth 2.x 客户端凭证 + 发送方约束（DPoP） | 已有 OAuth 基础设施的 API（API 防护按需、未排期，见 [07](07-roadmap.md#不再规划或推迟的项目)） | 可用（基于请求头）；mTLS 绑定的令牌同上不可用 |
| 公开爬虫 IP 段 | 运营方公开的 IP 段 JSON，由 Intel Sync 定期同步 | 用解析出的客户端 IP 匹配 |
| rDNS 正反向校验 | 反查主机名属于运营方域名，再正向解析回同一 IP；结果按 IP 缓存，异步执行 | 对解析出的客户端 IP 执行 |

**IP 类验证的客户端 IP**：IP 段、rDNS、`source_ips` 只用 UpstreamProfile 解析出的客户端 IP（解析规则见 [08 §2.2](08-upstream-and-cloudflare.md#22-客户端-ip)；`direct_tls` 或上游认证失败时为 TCP 对端）。`cloudflare` 下认证通过却缺少 `CF-Connecting-IP` 时：配置告警（`mg_cf_connecting_ip_missing_total`），IP 类验证结果记为 `unverifiable`，不回退到 Cloudflare 对端 IP，不判 `IMPERSONATOR`（签名验证照常）。

### 3.4 Cloudflare verified bot 标记（佐证）

`cloudflare` profile 的 Transform Rule 转发 `x-mg-cf-vbot`（`to_string(cf.client.bot)`，所有套餐可用）与 `x-mg-cf-vbot-cat`（`cf.verified_bot_category`，类别取值需实测），映射见 [08 §2.3](08-upstream-and-cloudflare.md#23-信号转发-tier-0request-header-transform-rule)。

- 只在上游认证通过时采信，否则随上游头族一起删除。
- 2026-07-01 起，Cloudflare 把 Web Bot Auth 已签名 Agent 也归为 verified bot（分 Direct / Intermediary 两类）。所以 `x-mg-cf-vbot=true` 不一定是传统爬虫，也可能是已签名 Agent。
- Cloudflare 正在试验用 `Forwarded`（RFC 7239）头转发 Intermediary Agent 的终端用户身份。该功能仍是实验性质，不依赖。

**与 MorphGate 自身验证的组合**（分类以自有验证为准，Cloudflare 标记只贡献证据、不推翻结论；EXTERNAL 族的取值见 [03 §3.9](03-risk-scoring.md#39-上游-verdictexternal)。分歧计入 `mg_cf_vbot_disagree_total{direction}`）

| MorphGate 验证（签名 / IP 段 / rDNS） | `x-mg-cf-vbot` | 结果 |
|---|---|---|
| 通过 | `true` | 按 MorphGate 结果分类；记为一致 |
| 通过 | `false` 或缺失 | 按 MorphGate 结果分类；记录分歧 `mg_pass_cf_false`（可能是 Cloudflare 未收录该运营方） |
| 明确失败（冒充已知运营方） | `true` | 仍判 `IMPERSONATOR`（上游标记不能推翻自有验证）；记录分歧 `mg_fail_cf_true`，触发该运营方 IP 段 / 密钥目录的异步刷新，并告警，供人工确认本地情报是否过期 |
| 明确失败 | `false` 或缺失 | `IMPERSONATOR`；`false` 作为冒充的佐证 |
| 无法验证（未知运营方或 `unverifiable`） | `true` | `DECLARED_AGENT`；标记作为自动化证据，不升级为 `VERIFIED_CRAWLER`；提示检查 Crawler Registry 是否缺该运营方 |
| 无法验证 | `false` 或缺失 | `DECLARED_AGENT` 或按通用评分；`false` 不算人类证据 |

Cloudflare 标记永远不能单独产生 `VERIFIED_CRAWLER`、`AUTHORIZED_AGENT` 或 `IMPERSONATOR`，不能单独决定放行或阻断，也不能进入测试环境。

## 4. Agent Registry 与授权模型

```yaml
agent:
  id: agt_qa_crawler
  name: "QA regression agent"
  purpose: "staging regression and DAST"
  auth:
    method: http_message_signatures    # tag = "morphgate-agent"
    keys:
      - { kid: "<thumbprint>", jwk: { kty: OKP, crv: Ed25519, x: "..." }, not_after: "2026-12-31" }
  status: active                       # active | suspended | revoked

grants:
  - id: grt_staging_regression
    agent: agt_qa_crawler
    site: shop.example.com
    environments: [staging]
    routes:
      - { path: "/api/**",  methods: [GET, POST] }
      - { path: "/admin/**", methods: [GET] }
    deny_routes:
      - { path: "/api/payments/**" }
    source_ips: ["203.0.113.0/24"]     # optional; matched against the resolved client IP (3.3)
    rate: { rps: 20, burst: 40, concurrency: 8 }
    schedule: { tz: "Asia/Shanghai", windows: ["Mon-Fri 09:00-19:00"] }
    valid_from: "2026-10-01T00:00:00+08:00"
    valid_until: "2026-10-31T23:59:59+08:00"   # required, max 90 days
    capabilities: [read, write]        # read | write | scan
    confirmed_at: "2026-09-30T21:05:11+08:00"  # owner re-auth + typed confirmation
    ticket: tkt_2026_10_regression     # required when capabilities include scan
```

- 授权必须有过期时间，默认上限 90 天；即将过期时提醒。`scan` 能力只在所关联工单的时间窗内生效（工单默认上限 72 小时，§5）。
- 授权的创建与扩权属于敏感操作，走重新认证（5 分钟窗口）+ 明确确认（见 [06 §4](06-policy-console-observability.md#4-管理后台)）；暂停、吊销不需要额外确认。
- 变更随签名配置包下发（Edge 拉取，分阶段做法见 [02 §6](02-data-flow.md#6-配置模型与密钥下发)；Phase 3 起由大脑 VM 上的 mg-control 签名，密钥保管见 [06 §8](06-policy-console-observability.md#8-平台自身安全)）；暂停与吊销另经 Valkey pub/sub（`mg:pub:rev`）即时通知 Edge，秒级生效。
- Agent 请求落在授权之外：默认 `403 agent_scope_denied` + 告警，不降级到通用人机评分，避免授权 Agent 在范围外"看起来像人"而被放行。

## 5. 测试授权工单

满足"安全测试只针对授权资产"的要求：任何带 `scan` 能力的授权必须关联一张工单；Validation Lab 的目标白名单也只从生效中的工单生成。

平台只有所有者一人，无法做"两人审批"。改为单人流程：**重新认证 + 明确确认 + 可选生效延迟 + 强制范围与时间窗 + 紧急停止**。

| 字段 | 说明 |
|---|---|
| 范围 | 站点、环境、路由白名单与黑名单；只能选择平台内已登记的自有站点，不接受通配主机 |
| 时间窗 | 开始 / 结束时间必填，过期自动失效；带 `scan` 的工单默认上限 72 小时（可配置） |
| 执行方 | 关联的 Agent 与来源 IP（按 §3.3 的客户端 IP 规则匹配） |
| 测试类型 | 回归、DAST、负载测试（负载测试需单独的速率上限） |
| 确认 | 5 分钟内完成的 passkey 重新认证（UV）+ 输入站点名；记录确认时间与认证方式（TOTP 回退等规则见 [06 §4](06-policy-console-observability.md#4-管理后台)） |
| 生效延迟 | 可选，默认 0；延迟期间工单处于 `pending`，可取消。生产环境 `scan` 建议启用 |
| 应急 | 紧急停止：一键吊销该工单下所有授权，无需重新认证或延迟 |

```mermaid
sequenceDiagram
    autonumber
    participant O as Owner
    participant C as Console / mgctl
    participant CP as Control Plane
    participant V as Valkey
    participant E as Edge
    participant L as Validation Lab
    O->>C: draft ticket (scope, window, agent, type, rate)
    C->>CP: validate: own sites only, window <= max, scan vs env rules
    CP-->>C: scope summary
    O->>C: passkey re-auth (UV, within 5 min) + type site name
    CP->>CP: audit record; if delay > 0: state = pending, notify owner
    Note over CP: pending ticket can be cancelled
    CP->>L: target allowlist from active tickets
    E->>CP: ETag poll, Phase 3+ long-poll (Edge pulls; never pushed)
    CP-->>E: signed config bundle with the ticket's grants
    O->>C: emergency stop (no re-auth, no delay)
    CP->>V: publish revocation (pub/sub)
    V-->>E: revoked within seconds
```

**为什么这样足以替代两人审批**

| 两人审批原本防的 | 单人流程中的替代控制 |
|---|---|
| 会话被劫持后被滥用 | 敏感操作前必须重新认证（passkey + 用户验证） |
| 误操作（选错站点 / 环境） | 输入站点名确认；范围摘要回显；时间窗强制 |
| 账号被盗后悄悄开放扫描 | 创建时立即通知到告警渠道；可选延迟提供发现与取消窗口；全部写入哈希链审计 |
| 授权无限期存在 | 时间窗必填、到期自动失效、紧急停止 |

生产环境默认不允许 `scan` 能力：站点级开关 `allow_prod_scan` 默认关，打开它本身也是敏感操作（[06 §4](06-policy-console-observability.md#4-管理后台)）。工单的创建、确认、生效、使用、结束与紧急停止全部写入审计日志。

## 6. 按环境的默认姿态

| 环境 | 人类用户 | 授权 Agent | 公开爬虫 | 已签名未授权 / 声明型 Agent | 未知自动化 |
|---|---|---|---|---|---|
| `production` | 正常评分 | 授权范围内放行 | 按爬虫策略矩阵 | 仅公开内容，低限额；禁止扫描特征 | 按风险 Challenge / 阻断 |
| `staging` / `test` | 仅限所有者配置的访问方式（IP 白名单、WireGuard 或站点登录） | 仅授权范围内放行 | 拒绝 | 拒绝 | 拒绝 |
| `dev` | 同上 | 同上 | 拒绝 | 拒绝 | 拒绝 |

测试类环境采用白名单模型，数据面不可用时 fail-closed。测试环境若也在 Cloudflare 之后，IP 白名单同样按 §3.3 的客户端 IP 规则匹配。

## 7. 公开爬虫策略

### 7.1 用途 × 动作矩阵

按站点配置，也可细化到路由：

| 用途 | 示例 | 默认 |
|---|---|---|
| 搜索索引 | 搜索引擎爬虫 | 允许，限额 |
| AI 训练 | 训练数据采集爬虫 | 拒绝（可改为允许或"需许可"） |
| AI 搜索 / 检索 | 为 AI 搜索结果抓取 | 允许，限额 |
| 用户触发抓取 | 用户在 AI 产品中让其读取某个页面 | 允许，严格限额，仅公开页面 |
| 归档 / 研究 | 网页归档、学术爬虫 | 按站点决定 |

### 7.2 Crawler Registry

- 记录运营方、UA 标识、用途类别、验证方式（IP 段 URL、rDNS 域名、Web Bot Auth 目录），由控制面 Intel Sync 定期刷新；站点只需按运营方或用途类别选择策略。
- 所有 IP 类验证按 §3.3 使用解析出的客户端 IP；Cloudflare 标记按 §3.4 只作佐证。
- **冒充**：UA 声称已知爬虫，但 IP 不在官方段、rDNS 不符、也没有有效签名 → `IMPERSONATOR`，阻断。Cloudflare 标记不能推翻这一结论，但两者分歧会触发情报刷新与告警（§3.4）；缺少客户端 IP 导致的 `unverifiable` 不算失败（§3.3）。

### 7.3 robots.txt 与内容使用偏好

- 平台可代管 `robots.txt`（RFC 9309）以及 IETF AIPREF 草案定义的内容使用偏好（`Content-Usage`，以最新草案为准）。对已验证爬虫，Edge 按同一份配置强制执行，让声明不只停留在"建议"。
- Cloudflare 默认缓存 `robots.txt`：更新后需要清除该 URL 的缓存，或给 `robots.txt` 设置较短的缓存时间。
- Cloudflare Free 也提供托管 `robots.txt`。由 MorphGate 代管时关闭 Cloudflare 的托管 `robots.txt`，只保留一个来源。
- **可选 402**：对"需许可"的用途返回 `402` 并附带许可说明链接，为后续内容授权留接口。

### 7.4 与 Cloudflare AI bot policies 对齐

Cloudflare AI bot policies 所有套餐可用，分 Search、Agent、Training 三类，每类可设 Block、Block on pages with ads 或 Allow。其默认值（2026-09-15 起新 zone 在有广告的页面阻止 Training 与 Agent）、混合爬虫被误拦等细节见 [08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)。要点：Cloudflare 在边缘拦下的请求不会到达 Edge，MorphGate 看不到、也记录不到。

**两种模式，只能选一种**

| 模式 | Cloudflare 侧设置 | 适用 | 代价 |
|---|---|---|---|
| A. MorphGate 唯一权威（默认） | 三类全部 Allow | 需要完整日志、按路由细化、`402`、与 Web Bot Auth / Registry 联动 | 被拒爬虫的流量仍到达源站主机，由 Edge 拒绝 |
| B. 下推 | 控制面把同一份策略中"整站拒绝"的部分编译为 Cloudflare AI bot policy 设置或自定义规则并下推 | 某类爬虫量大，想在边缘节省带宽 | 只能下推 Cloudflare 支持的粒度；边缘拦下的请求只剩 Cloudflare 侧统计 |

- 策略源始终是 MorphGate；Cloudflare 侧状态是派生物，不在 Cloudflare 控制台手工修改。下推属于 Cloudflare 写操作，需重新认证 + 输入 zone 名（[06 §4](06-policy-console-observability.md#4-管理后台)）。
- Cloudflare 三个类别与 §7.1 各用途的对应关系需确认；无法一一对应的用途不下推，留在 Edge 执行。
- `mgctl cf audit` 读取每个 zone 的 AI bot policy（检查项见 [08 §2.10](08-upstream-and-cloudflare.md#210-mgctl-cf-audit)）：模式 A 下任何非 Allow 都报告为失败（新 zone 尤其要检查默认值）；模式 B 下与控制面期望值不一致即报告漂移。结果计入 `mg_cf_audit_failed_checks`，在 Console 的 Cloudflare 集成页展示（见 [06 §4](06-policy-console-observability.md#4-管理后台)）。
- Cloudflare 侧其他会提前处理爬虫的功能（Bot Fight Mode、Super Bot Fight Mode 等）的共存设置见 [08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)。

## 8. 未声明 Agent 的识别

未声明的 Agent 走通用识别链路（[03](03-risk-scoring.md)），另加 Agent 相关特征：

- 页面被请求但静态资源、SDK 从未执行；以"阅读速度"逐页访问却没有交互事件。
- 大量页面只取正文、按站点结构系统性遍历；对表单做结构化探测。
- 来自托管 Agent 平台常用的云 ASN（弱信号，只作为先验；ASN 以本地 IP 库为准，`cloudflare` 下的 `x-mg-cf-asn` 只作交叉校验，见 [03 §3.2](03-risk-scoring.md#32-网络层network)）。
- 真实浏览器中由自动化协议或扩展驱动的交互：输入事件缺少人类时序特征，焦点与可见性变化模式异常。
- **扫描特征**：敏感路径探测（`/.env`、`/.git/`、与站点技术栈无关的管理路径）、高 404 比例、注入载荷、参数模糊测试。命中即 `SCANNER`，无论是否为 Agent。

带 `delegated` 标签的流量处理原则：允许浏览，但支付、改密、删除数据等敏感操作要求 step-up（人工确认、交互式 Challenge（见 [09](09-interactive-challenge.md)）或站点登录的 passkey），并在站点侧可配置为完全禁止。

## 9. 为授权 Agent 提供正规通道（后期）

与其让 Agent 模拟人去操作页面，不如给它结构化入口：

- 授权 Agent 专用的 API 或 MCP 端点，按授权范围暴露只读 / 读写能力。
- 每个调用都带 Agent 身份与授权 ID，便于审计和计量。
- 正规通道可用后，对同一运营方的"模拟人类操作页面"流量收紧策略。

## 10. 审计与可观测

- 每个 Agent 请求记录 `agent_id`、`grant_id`、`ticket_id`、验证方式、验证结果、授权匹配结果，以及 `cf_vbot` / `cf_vbot_cat`（若有）和 `cf_ray`。
- 指标名称与标签见 [06 §5](06-policy-console-observability.md#5-日志指标与告警)。
- 后台按 Agent 展示：请求量、路由分布、超范围尝试、错误率、授权剩余时间。
- 告警：超范围访问、签名失败或 `component_rewritten` 激增、冒充激增、`mg_fail_cf_true` 分歧出现、测试环境出现非授权自动化、授权即将过期、`mg_cf_audit_failed_checks` 中 AI bot policy 检查失败。阈值与通知出口见 [06 §5](06-policy-console-observability.md#5-日志指标与告警)。

## 参考

- Cloudflare Web Bot Auth：https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/
- Cloudflare verified bots：https://developers.cloudflare.com/bots/concepts/bot/verified-bots/
- 字段 `cf.client.bot`：https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.client.bot/
- 字段 `cf.verified_bot_category`：https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.verified_bot_category/
- Cloudflare 转发到源站的 HTTP 头：https://developers.cloudflare.com/fundamentals/reference/http-headers/
- AI bot policies：https://developers.cloudflare.com/bots/additional-configurations/block-ai-bots/
- Cloudflare Free 套餐 Bot 功能：https://developers.cloudflare.com/bots/plans/free/
- 缓存默认行为（含 robots.txt）：https://developers.cloudflare.com/cache/concepts/default-cache-behavior/
- `web-bot-auth` crate：https://github.com/cloudflare/web-bot-auth
- `httpsig` crate：https://github.com/junkurihara/httpsig-rs
