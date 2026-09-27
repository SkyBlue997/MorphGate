# 06 策略引擎、管理后台与审计

平台只由所有者一人使用，服务于其自有的几个网站。本文的取舍：去掉租户、多角色和两人审批；敏感操作改为"重新认证 + 明确确认 + 可选生效延迟"；可观测性用 VictoriaMetrics + VictoriaLogs 的精简组合。本文是策略字段（§2）、指标名（§5）、运维默认值（§4、§5）与密钥保管（§8）的唯一来源，其他文档引用这里。

## 1. 策略模型

**层级继承**：全局默认 → 站点 → 环境 → 路由，下层覆盖上层。全局或站点级可标记 `locked` 规则（例如"测试环境默认拒绝自动化"），下层不可覆盖；修改 `locked` 规则属于敏感操作（§4）。

**执行阶段**（按顺序）：

| 阶段 | 内容 |
|---|---|
| `identity` | 允许 / 拒绝名单、授权 Agent 与授权范围、已验证爬虫与爬虫策略、冒充 |
| `protocol` | 协议异常、请求走私特征；API 防护（API Key、OpenAPI 正向模型）按需、未排期 |
| `rate_limit` | 限速器（可产出信号或直接动作） |
| `bot` | 基于风险评分与分类的规则 |
| `custom` | 所有者自定义规则 |
| `default` | 路由的默认处置矩阵（[03 §5](03-risk-scoring.md#5-分级处置)） |

终止型动作（ALLOW / BLOCK / CHALLENGE / RATE_LIMIT / TARPIT）结束评估；非终止型动作（LOG / TAG / SET_SIGNAL / ADD_HEADER）继续向下执行。TARPIT 只在 `direct_tls` 站点可选：`cloudflare` profile 下编译期报错（Cloudflare 回源读超时 125 s，且回源连接被多个访客共享），默认处置用 RATE_LIMIT / BLOCK。

**规则结构**：`id`、`phase`、`priority`、`expr`、`action`、`params`、`mode`（enforce / dry_run / disabled）、`rollout`（百分比）、`expires_at`（临时规则必填）、`description`。

## 2. 策略语言

使用 CEL 语法。`mgctl` 与控制面用 cel-go v0.30 解析、类型检查、估算执行代价，编译为受限 IR（Protobuf AST）；数据面用自研 Rust IR 求值器执行，热路径不用 `cel` crate（无类型检查器、一致性测试大量跳过）。

**可用字段**（命名以本表为准；RequestContext 其余字段按同名路径可用，见 [02 §7](02-data-flow.md#7-核心数据模型)）

| 命名空间 | 主要字段 |
|---|---|
| `req` | `method`、`host`、`path`、`query`、`headers`、`channel` |
| `net` | `ip`（UpstreamProfile 解析出的客户端 IP）、`asn`、`country`、`conn_type`、`tor` |
| `upstream` | `profile`（`cloudflare` / `direct_tls` / …）、`authenticated`、`auth_method`（`loopback` / `origin_mtls` / `secret_header` / `src_cidr` / `none`） |
| `tls` / `http` | `tls.ja4`（`{value, source, authenticated}`）、`tls.version`、`http.version`、`http.header_order`（仅 `direct_tls`） |
| `edge_tls` | 仅 `cloudflare` profile，由 `x-mg-cf-tls-*` 解析（EDGE_TLS 族，先 shadow）：`version`、`cipher`、`ciphers_sha1`、`ext_sha1`（排序未文档化，实测前不得用于绑定或高权重）、`hello_len` |
| `identity` | `token.level`（`invisible` / `pow` / `interactive` / `interactive_a11y` / `interactive_ext:{provider}`）、`token.age`、`proof.valid`、`agent.id`、`agent.grant_id`、`crawler.operator`、`crawler.verified`、`crawler.purpose`、`crawler.cf_vbot`、`crawler.cf_vbot_cat` |
| `risk` | `score`、`confidence`、`class`（即 RiskAssessment 的 `bot_class`）、`reasons`（即 `top_reasons`） |
| `route` | `name`、`sensitivity`、`env` |
| `rate` | 各限速器利用率 |
| `labels` | 实体标签（`scanner`、`delegated` 等） |

- `identity.crawler.cf_vbot` 来自 `x-mg-cf-vbot`，只作佐证：编译器对"仅凭它放行或阻断"的规则报警告（见 [05 §3.4](05-ai-agent-policy.md#34-cloudflare-verified-bot-标记佐证)）。
- HTTP/2 帧级指纹在个人版中无限期推迟，不提供 `http.h2_fp`。

扩展函数：`ip_in(ip, list)`、`list(name)`、`glob(path, pattern)`；`has(x)` 判断字段是否可用。

**缺失输入的求值语义**（信号状态定义见 [03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性)）

| 字段状态 | `has(x)` | 读取 `x` 的比较表达式 |
|---|---|---|
| `PRESENT` | true | 正常求值 |
| `ABSENT`（profile 应提供、本请求没有，如尚无凭证） | true | 按零值求值（空串 / 0 / false），例如没有持有证明时 `identity.proof.valid` 为 false |
| `MISSING`（profile 不提供，或上游应注入的头未到达 / 来源不可确认） | false | 结果为"未知" |

- "未知"在 `&&` / `||` 中按 CEL 规则被确定值吸收（`false && 未知` 为 false，`true || 未知` 为 true），`!未知` 仍为未知。`expr` 最终为未知时，整条规则按**不匹配**处理，dry-run 日志记 `missing_input`（附字段名）。
- 输入缺失时仍要命中（fail-closed）或需要改用替代信号的规则，显式用 `has(x)`：见下方示例 `test-env-default-deny`，或 `has(tls.ja4) ? tls.ja4.value in list("bad_ja4") : edge_tls.ciphers_sha1 in list("bad_cf_ciphers")`。
- 编译期按站点的 UpstreamProfile 检查字段：引用该 profile 下恒为 MISSING 的字段（如 `cloudflare` 下的 `tls.ja4`、`http.header_order`，见 [08 §2.5](08-upstream-and-cloudflare.md#25-在-cloudflare-之后失真的信号)）且未用 `has()` 守卫时报警告。

**示例**

```yaml
policies:
  - id: test-env-default-deny
    phase: identity
    locked: true
    expr: >
      route.env in ["staging", "test", "dev"]
      && risk.class != "AUTHORIZED_AGENT"
      && (!has(net.ip) || !ip_in(net.ip, list("owner_cidrs")))
    action: block

  - id: block-impersonators
    phase: identity
    expr: risk.class == "IMPERSONATOR"
    action: block

  - id: deny-ai-training-crawlers
    phase: identity
    expr: identity.crawler.verified && identity.crawler.purpose == "ai_training"
    action: block

  - id: scanner-block
    phase: protocol
    expr: '"scanner" in labels'
    action: block

  - id: login-require-proof
    phase: bot
    expr: route.name == "login" && !identity.proof.valid
    action: challenge
    params: { type: invisible }

  - id: login-high-risk
    phase: bot
    expr: route.name == "login" && risk.score >= 60
    action: challenge
    params: { type: interactive }
    mode: dry_run
```

## 3. 发布流程

```
Draft
  -> Validate   syntax, types, cost, field availability per UpstreamProfile,
                shadowed / conflicting rules
  -> Simulate   replay recent DecisionEvents from VictoriaLogs (ClickHouse after
                Phase 4), weighted by sample_rate: which requests change action,
                by class / route, estimated human friction
  -> Confirm    production / locked rules: re-auth + type site name + optional delay
  -> Dry-run    log-only in production, per-rule hit metrics
  -> Canary     x% of traffic or one Edge
  -> Enforce    100%
  -> Rollback   automatic on guardrail breach; manual to any previous version
```

- 发布产物是 Ed25519 签名的配置包（密钥见 §8）；Edge 校验签名后原子切换，失败保留 last-known-good；拉取与吊销通知见 [02 §6](02-data-flow.md#6-配置模型与密钥下发)。
- Phase 1–2 没有控制面服务：`mgctl` 在所有者工作站编译、签名后上传到大脑 VM 上的静态位置，Edge 以 ETag 条件请求经 mTLS / WireGuard 拉取，同样要求输入站点名确认。Phase 3 起编译与签名移到大脑 VM 的 mg-control（复用同一编译器），Edge 改为向 mg-control 长轮询（[02 §6](02-data-flow.md#6-配置模型与密钥下发) 为准）。
- 回放只能基于已记录的字段和采样事件，结论作为参考，最终以 dry-run 数据为准；回滚与全局 monitor 开关不经过 Confirm 的延迟（见 §4 敏感操作表）。

## 4. 管理后台

**阶段**：Phase 1–2 没有 Console，用 `mgctl`、VictoriaMetrics / VictoriaLogs 自带的 vmui（或可选 Grafana）。Console v1 在 Phase 3 交付，只保留个人使用需要的模块。

| 模块 | 功能 |
|---|---|
| 总览 | 按类别 / 动作 / 站点的流量趋势、分数分布、Challenge 漏斗（按 Provider）、双重挑战计数、Top ASN / 国家 / 路由 |
| 站点与接入 | 站点、主机名、UpstreamProfile、源站保护方式（Tunnel / AOP）、环境与路由（敏感度标注）、接入自检：该 profile 预期提供的信号与实际到达率对比 |
| Cloudflare 集成 | 见下表 |
| 策略 | CEL 编辑器（字段补全、实时校验）、限速器、Challenge 与 Provider 配置、默认处置矩阵、回放模拟、版本与灰度、全局 monitor 开关 |
| Agent 与爬虫 | Agent Registry、授权、测试授权工单、爬虫策略矩阵、robots.txt 与内容使用偏好、Cloudflare AI bot policy 对齐状态（见 [05](05-ai-agent-policy.md)） |
| 调查 | 按 request_id / `cf_ray` / 会话 / IP / Agent 检索；会话时间线；判定解释（reason code + 信号明细）；一键加入名单或标记误报 |
| 名单 | IP / CIDR / ASN / Agent 的允许与拒绝名单，必须填写过期时间和原因 |
| 审计 | 检索、哈希链与每日锚点校验、导出 |
| 系统 | passkey 与 TOTP 管理、只读账号、API Token、密钥轮换状态、Edge 节点与配置版本、备份状态 |

模型管理（版本、shadow 对比、灰度）在 Phase 4 引入模型时再加。

**Cloudflare 集成页**（只做展示与告警；检查项与流程的定义在 [08](08-upstream-and-cloudflare.md#2-cloudflare-前置cloudflare-profile)）

| 区块 | 内容 | 数据来源 |
|---|---|---|
| `mgctl cf audit` 结果 | 每个 zone 各检查项（[08 §2.10](08-upstream-and-cloudflare.md#210-mgctl-cf-audit)）的结果、级别与最近运行时间 | 控制面定时运行（只读 Token） |
| Cloudflare IP 段同步 | 最近同步时间、etag、段数与差异、推送到 Edge 快照与云安全组的结果（[08 §2.11](08-upstream-and-cloudflare.md#211-ip-段同步)） | `GET https://api.cloudflare.com/client/v4/ips` |
| Turnstile widget | 每站点 sitekey、主机名、secret 轮换状态、siteverify 结果分布与延迟、是否被自动禁用、pre-clearance（默认关）（[09 §8](09-interactive-challenge.md#8-turnstile-适配)） | Cloudflare API + Edge 指标 |
| 源站保护 | Tunnel / AOP 模式、上游认证失败计数、AOP 证书到期时间 | Edge 指标、控制面配置 |
| 双重挑战 | SDK 上报的 `cf-mitigated: challenge` 次数（按站点 / 路由）及可能原因（BFM 开启、SBFM 无 Skip、该路径有 Cloudflare 托管挑战规则） | `mg_double_challenge_total` |

**账号与角色**

| 角色 | 权限 |
|---|---|
| `owner` | 全部；敏感操作需重新认证 + 确认 |
| `viewer`（可选） | 只读：总览、调查（IP 等个人信息默认脱敏）、审计检索；不能导出含个人信息的明细，不能发起任何写操作 |

- 登录：passkey（WebAuthn）为主，建议至少注册两个（例如手机 + 硬件密钥）；TOTP 备用；另保存一次性离线恢复码。
- 机器身份：`mgctl` 使用限定范围的 API Token；Edge 使用 mTLS 证书或 WireGuard 密钥；Go worker 使用独立的服务凭证。

**敏感操作**（替代原"两人审批"）

原则：放宽或扩权类操作加摩擦，回退与止损类操作不加摩擦。

| 操作 | 重新认证 | 输入确认 | 生效延迟 |
|---|---|---|---|
| 生产环境策略发布、灰度提升到 enforce | 是 | 站点名 | 可选（默认 0） |
| 修改 `locked` 规则 | 是 | 站点名 | 可选 |
| 带 `scan` 能力的测试工单（默认上限 72 小时）、打开站点级 `allow_prod_scan`（默认关） | 是 | 站点名 | 可选（生产环境建议启用） |
| 创建或扩大 Agent 授权 | 是 | 站点名 | 可选 |
| 密钥轮换（§8 密钥清单） | 是 | 按站点的密钥输站点名；所有者级密钥（配置签名、审计锚点）输密钥用途名 | 可选 |
| 删除审计以外的数据（事件、名单批量、Agent、站点） | 是 | 站点名 | 可选 |
| Cloudflare 写操作（下推 AI bot policy、创建或修改规则） | 是 | zone 名 | 否 |
| 新增 passkey、重置 TOTP、创建 API Token、创建只读账号 | 是 | — | 可选 |
| 全局 monitor 开关（会关闭拦截） | 是 | — | 否 |
| 回滚到上一版本、吊销授权、工单紧急停止 | 否（有效会话即可） | 否 | 否 |

- 重新认证：5 分钟内完成一次带用户验证（UV）的 passkey 断言；TOTP 仅在无可用 passkey 时使用，审计中标记 `auth=totp` 并发送通知。
- 生效延迟：延迟期间变更处于 `pending`，可取消；进入 `pending` 时立即向告警渠道发送操作摘要。这是单人模式下替代"第二个人"的发现窗口。
- 所有敏感操作写入审计，包括认证方式、确认文本、计划生效时间与实际生效时间。

**访问入口**：Console 与 Admin API 默认只绑定内网或 WireGuard 地址（或经 SSH 端口转发访问），不直接暴露到公网。

## 5. 日志、指标与告警

**组件**（全部部署在"大脑" VM 上）：mg-edge / mg-control / node_exporter 的 `/metrics` → VictoriaMetrics → vmalert 告警；事件与应用日志（批量 JSON 行）→ VictoriaLogs `vl-main` / `vl-short`；Grafana 可选，两者都可作数据源。部署拓扑见 [01 §8](01-architecture.md#8-部署与高可用)。

| 组件 | 用途 | 说明 |
|---|---|---|
| VictoriaMetrics 单节点 | 直接抓取 Edge（`pingora-prometheus`）、Go 控制面、node_exporter | `-retentionPeriod=13`（单位为月；默认只有 31 天，必须显式设置）；自带 vmui |
| VictoriaLogs × 2 | `vl-main`（30 天）：DecisionEvent、最小访问记录（`kind=access`）、verdict / feedback、审计镜像、应用日志；`vl-short`（7 天）：Challenge / SDK 遥测事件 | 保留期按实例设置，因此拆成两个实例（[02 §9](02-data-flow.md#9-采样与保留)）；替代 Loki；自带 Web UI |
| Grafana（可选） | 看板 | AGPL-3.0，自用且不修改属于正常使用 |
| vmalert | 少量告警规则 | 通知出口（Alertmanager 或控制面内置的 Webhook 接收端）选最简方案，需确认 |

不单独部署追踪后端：用 `request_id` 与 `cf_ray` 串联 Edge、控制面与 Cloudflare 日志。以后需要时再接 OpenTelemetry（VictoriaLogs 可接收 OTLP 日志）。

**Edge 指标**（指标名以本节为准；标签只用有界维度，不含 IP、会话、账号等个人信息，按实体的统计走 VictoriaLogs）

| 指标 | 标签 |
|---|---|
| `mg_requests_total` | site、env、route、action、class |
| `mg_decision_latency_seconds`（直方图） | site |
| `mg_challenge_total` | type（invisible / pow / interactive）、provider（交互级的 `interactive_a11y` / `interactive_ext:*` 由它区分）、result（issued / solved / failed / expired） |
| `mg_provider_verify_total` | provider（self_hold / pow_a11y / turnstile / tencent / aliyun_v2）、outcome（pass / fail / unavailable / misconfigured）、reason |
| `mg_provider_verify_latency_seconds`（直方图） | provider |
| `mg_double_challenge_total` | site、route（来自 SDK 上报的 `cf-mitigated: challenge`） |
| `mg_upstream_auth_failures_total` | listener、profile、reason（no_client_cert / untrusted_ca / non_loopback_peer / bad_secret_header / src_not_allowed） |
| `mg_upstream_headers_stripped_total` | profile（未认证请求携带已知上游头族） |
| `mg_cf_connecting_ip_missing_total` | site（认证通过但缺少 `CF-Connecting-IP`） |
| `mg_upstream_signal_missing_total` | profile、signal（profile 预期提供但缺失，例如 `x-mg-cf-tls-version`） |
| `mg_token_verify_total`、`mg_proof_verify_total` | result |
| `mg_ratelimit_exceeded_total` | limiter |
| `mg_agent_requests_total` | agent、grant、result |
| `mg_wba_verify_total` | result（valid / invalid / unverified / component_rewritten / replay） |
| `mg_crawler_verify_total` | method（ip_range / rdns / wba）、result（pass / fail / unverifiable） |
| `mg_cf_vbot_disagree_total` | direction（mg_pass_cf_false / mg_fail_cf_true），含义见 [05 §3.4](05-ai-agent-policy.md#34-cloudflare-verified-bot-标记佐证) |
| `mg_event_dropped_total`、`mg_valkey_rtt_seconds`、`mg_config_version`、`mg_config_age_seconds` | — |

**控制面指标**：`mg_cf_audit_failed_checks`（zone、check）、`mg_cf_ips_sync_age_seconds`、`mg_turnstile_secret_rotation_pending`、`mg_audit_anchor_last_success_timestamp`、`mg_aop_cert_expiry_seconds`、Valkey Stream `mg:ev`（组 `nl`）积压（`XPENDING` / 长度）、事件到 verdict 延迟。模型相关指标（分数分布 PSI、特征漂移、shadow 分歧率）在 Phase 4 引入。

**SLO（初始值）**

| 项目 | 目标 |
|---|---|
| Edge 可用性 | 99.9% |
| 判定附加延迟 | p99 < 5ms |
| 配置下发生效 | < 30s |
| 吊销生效 | < 5s |
| 事件入库 VictoriaLogs | < 60s |

**vmalert 告警**（只配少量；业务类事件在 Console 展示并每日汇总）

| 告警 | 触发（未注明为定值的阈值按自有流量调整） | 级别 |
|---|---|---|
| Edge 不可用 | 抓取失败 ≥ 2 分钟 | 紧急 |
| Valkey 不可用或 RTT 过高 | 连接失败，或 p99 RTT > 1ms 持续 5 分钟（Edge 与 Valkey 须同区域 / 同 VPC，否则 Edge 退化为本地模式） | 紧急 |
| 配置过期 | `mg_config_age_seconds` 超过 10 分钟，或拉取连续失败 | 高 |
| 上游认证失败激增 | `mg_upstream_auth_failures_total` 5 分钟增量超过基线 | 高 |
| 缺失 `CF-Connecting-IP` | 5 分钟内增量 > 0（通常是误开 "Remove visitor IP headers"） | 高 |
| 上游信号缺失 | 某 `x-mg-cf-*` 缺失率 > 5%（Transform Rule 被改或删除） | 中 |
| Provider 异常 | 出现 `misconfigured`（如 Turnstile `invalid-input-secret`，Provider 已自动禁用），`unavailable` 比例 > 5%，或付费 Provider 达到日上限（[09 §7](09-interactive-challenge.md#7-provider-选择策略)） | 高 |
| Challenge 率 / 通过率异常 | Challenge 率突增；通过率突然接近 100%（可能是外部代解）或骤降（可能是 SDK 故障）；解题时间分布偏移、单前缀 / ASN 凭证签发持续超限（[09 §13](09-interactive-challenge.md#13-收割防护的边界)） | 中 |
| 双重挑战 | `mg_double_challenge_total` 1 小时增量超过阈值 | 中 |
| 事件丢弃 | `mg_event_dropped_total` 持续增长 | 中 |
| `mg:ev` Stream 积压 | 积压 > 10 万条，或最老未确认条目 > 10 分钟（初始值；近线 worker 停滞或过慢） | 中 |
| 审计锚点失败 | 距上次成功锚定 > 26 小时（定值） | 高 |
| Cloudflare 配置漂移 | `mg_cf_audit_failed_checks` > 0，或 IP 段同步 > 48 小时未成功（定值） | 中 |
| AOP 证书将过期 | `mg_aop_cert_expiry_seconds` 剩余 < 30 天（定值） | 中 |

## 6. 审计

- **范围**：控制面与 `mgctl` 的所有写操作（策略、名单、Agent、授权、工单、密钥、账号与凭证、设置、Cloudflare 写操作）、敏感操作的确认与延迟、登录与重新认证、API Token 使用、数据导出、查看含个人信息明细的调查操作。
- **记录格式**：`{id, ts, actor, actor_kind (owner|viewer|api_token|system), auth (passkey|totp|token), reauth_at, actor_ip, site, action, resource_type, resource_id, diff, reason, confirm_text, effective_at, request_id, prev_hash, hash}`。
- **完整性**：哈希链 `hash = H(prev_hash || canonical(record))`。每日生成锚点（日期、最后一条记录的 hash、记录数），用独立的审计签名密钥（§8）签名后写入对象存储；云厂商支持时开启对象锁（WORM），写入凭证只有写权限、没有删除权限。`mgctl audit verify` 校验哈希链与锚点。
- **存储**：PostgreSQL / SQLite 为主存储，同时镜像到 VictoriaLogs `vl-main` 便于检索；每晚随备份进入对象存储。Phase 1–2 的 `mgctl` 操作写本地追加日志（同一格式与哈希链），Phase 3 迁入控制面。
- **保留**：默认 ≥ 1 年，可按合规要求延长。

## 7. 隐私与合规

以下为设计层面的考虑，具体口径需法务确认。

- **定位**：平台只供所有者自用，不作为服务提供给他人，不需要作为服务通过等级保护测评。但受保护网站的访客数据仍受《个人信息保护法》《网络安全法》《数据安全法》等约束；有欧盟用户时评估 GDPR / ePrivacy。站点隐私政策需披露出于安全目的的数据处理。
- **数据分类**：IP、设备标识、账号标识、行为数据、指纹均按个人信息处理：最小化、假名化、限期保留。行为特征只用于区分自动化，不用于识别具体个人。
- **Cloudflare 转发的数据**："Add visitor location headers" 会带来城市、经纬度、邮编等精确位置，Edge 只保留国家、地区、时区，其余不写入事件；`x-mg-cf-tls-random` 只以 `client_conn_key = hash(...)` 的形式在内存与近线使用，不进任何事件；其余 `x-mg-cf-*`（TLS 特征、RTT、ASN）与自算信号同等对待。
- **Turnstile（启用时）**：按 Turnstile Privacy Addendum（2025-06-18 更新），访客 IP、TLS 指纹、User-Agent 以及 sitekey 与来源站点会发送给 Cloudflare；Cloudflare 在机器人检测上作为处理者，在用这些信号改进 Turnstile 时作为控制者；附录未写明保留期限。启用的站点须在隐私政策中写明（Invisible 模式必须引用该附录，MorphGate 用 Managed 模式，仍建议引用）；按站点启用、永不对中国大陆访客提供，对非大陆访客的跨境评估需法务确认；可选的腾讯云 / 阿里云验证码同样需要披露（[09 §8](09-interactive-challenge.md#8-turnstile-适配)）。
- **日志留存**：《网络安全法》要求网络日志留存不少于六个月，站点作为网络运营者适用。DecisionEvent 明细只热存 30 天；留存要求由最小访问记录（`kind=access`，假名化、不采样）每日归档到对象存储满足（导出方式见 [02 §9](02-data-flow.md#9-采样与保留)；归档是否保留 IP 明文需法务确认）。源站自身访问日志已满足要求时可关闭归档。
- **默认保留期**

| 数据 | 保留 |
|---|---|
| DecisionEvent 明细 | 30 天（VictoriaLogs `vl-main`） |
| Challenge / SDK 遥测 | 事件明细 7 天（`vl-short`）；聚合（量化分布，不含个人标识）随指标存于 VictoriaMetrics，13 个月 |
| Edge 指标 | 13 个月（VictoriaMetrics） |
| 最小访问记录归档 | 对象存储 ≥ 6 个月 |
| 审计日志 | ≥ 1 年 |
| 备份 | 滚动覆盖；删除请求在备份过期后完全生效 |

- **数据驻留**：默认区域为香港 / 东京 / 新加坡（无需 ICP）。若站点面向中国大陆访客，其个人信息在境外收集与存储，是否涉及出境规则及需要的告知 / 同意，需法务确认。
- **可配置性**：高熵指纹、行为采集可按站点 / 地区关闭；支持按假名化账号标识检索和删除数据。
- **申诉**：Challenge 失败页带 request_id，访客可凭它申诉；所有者在调查模块按 request_id 定位判定。

## 8. 平台自身安全

| 领域 | 措施 |
|---|---|
| 后台访问 | passkey 为主、TOTP 备用、离线恢复码；会话超时；敏感操作重新认证；Console 不暴露到公网（§4） |
| API Token（MorphGate 自身） | 限定范围、必须过期、服务端只存哈希 |
| 密钥保管 | 默认用**本机加密的密钥文件**：Edge 与大脑 VM 上由 systemd credentials（`systemd-creds`，有 TPM2 时绑定）交付给进程；所有者工作站上的签名私钥用 age 加密（口令或硬件密钥插件）；云 KMS 可选；**不部署 OpenBao**。密钥不进配置包、仓库与日志；轮换属敏感操作（§4），访问与轮换写审计 |
| Cloudflare API Token | 按用途拆分、最小权限：`cf-audit`（相关 zone 只读，用于 `mgctl cf audit` 与读取 AI bot policy）、`cf-turnstile`（仅 Turnstile Sites Write）、`cf-push`（可选，`mgctl cf apply` 或 [05 §7.4](05-ai-agent-policy.md#74-与-cloudflare-ai-bot-policies-对齐) 模式 B 下推时短期启用）；IP 段同步无需 Token；zone 级权限名需确认（[08 §2.10](08-upstream-and-cloudflare.md#210-mgctl-cf-audit)）；按密钥保管 |
| Turnstile secret | 配置中只写 `secret_ref`（如 `cred://turnstile/<site>`，指向本机 systemd credential；`kms://` 可选），永不内联；`invalid-input-secret` 触发告警并自动禁用该 Provider、回退自研；轮换流程见 [09 §8](09-interactive-challenge.md#8-turnstile-适配) |
| 自有 CA、Tunnel 凭证 | AOP 自有 CA 与 Agent mTLS 客户端证书 CA（仅 `direct_tls`，[05 §3.3](05-ai-agent-policy.md#33-其他身份来源)）的私钥离线保存（不放在 Edge 或大脑 VM），Edge 只持有 CA 证书，轮换时短期同时信任新旧 CA；cloudflared 凭证仅 root 可读、以非特权用户运行、主机失陷即轮换；同机不部署不可信进程，按用户限制回环连接的本机防火墙需实测（[ADR-0004](adr/0004-origin-protection-tunnel-aop.md)） |
| 上游信任 | 上游认证失败时删除全部已知上游头族，以 TCP 对端为客户端 IP（见 [08](08-upstream-and-cloudflare.md)） |
| 配置下发 | 配置包签名、Edge 校验；Edge 与控制面之间 mTLS 或 WireGuard |
| 备份 | 每晚把 Valkey RDB、pg_dump / SQLite 文件、VictoriaMetrics / VictoriaLogs 快照加密后写入对象存储；备份凭证与审计锚点凭证分开 |
| 供应链 | SBOM、镜像签名（cosign）、依赖扫描；Web SDK 可复现构建并签名（它运行在受保护站点的页面上） |
| 端点自保护 | `/__mg/*` 限速；拒绝任何带 `Content-Encoding` 的请求体（不解压）；`/__mg/c`、`/__mg/c/renew` ≤ 8 KB，`/__mg/t`、`/__mg/r` ≤ 16 KB（[02 §3](02-data-flow.md#3-challengesdk-遥测与凭证刷新)）；不在响应中暴露检测细节 |
| 解析器健壮性 | 对 ClientHello 解析（`direct_tls` JA4）、`x-mg-cf-*` 头解析、凭证解析、签名头解析、Challenge 提交解码做模糊测试（cargo-fuzz） |
| 安全测试 | 每个组件做 STRIDE 威胁建模；只在自有环境测试；可选安排经授权的第三方渗透测试 |

**密钥清单**

| 密钥 | 范围与位置 | 轮换 |
|---|---|---|
| 配置签名（Ed25519） | 所有者一对，`kid` 区分；Phase 1–2 在所有者工作站由 `mgctl` 使用，Phase 3 起移到大脑 VM 的 mg-control | 每年 |
| 审计锚点签名 | 所有者一对，与配置签名分开、保管方式相同 | 每年 |
| 凭证密钥（PASETO v4.local） | 按站点 | 30 天 |
| Challenge 密封根密钥 `K_seal_root`；由它派生的每日 `k_epoch = HKDF-SHA256(K_seal_root, info = "mg-seal-v1" ‖ site ‖ epoch_no)` 与 Turnstile `cData` 绑定密钥 `k_bind_epoch`（info `"mg-bind-v1"`，同法派生） | 按站点；根密钥以 systemd credential 交付，各 Edge 确定性派生同一 epoch 密钥、无需每日分发（[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)） | 根密钥每年或泄露时；epoch 密钥 24 小时，接受当前与上一个 epoch，泄露不暴露根密钥 |
| Turnstile secret | 按站点（每站点一个 widget） | 按需，轮换期间新旧并存 |
| MessageMAC Cookie 密钥 `K_cf`（可选，Pro 及以上） | 按站点，独立于以上所有密钥；Edge 侧以 systemd credentials 交付，同时以字面量写在 Cloudflare 规则中（[08 §2.9](08-upstream-and-cloudflare.md#29-可选hmac-cookie-跳过pro-及以上)） | 按需，规则同时接受新旧 key |

## 参考

- VictoriaMetrics 单节点：https://docs.victoriametrics.com/victoriametrics/single-server-victoriametrics/
- VictoriaLogs：https://docs.victoriametrics.com/victorialogs/
- Grafana 许可：https://grafana.com/licensing/
- Pingora CHANGELOG（`pingora-prometheus`）：https://github.com/cloudflare/pingora/blob/main/CHANGELOG.md
- Cloudflare IP 段：https://api.cloudflare.com/client/v4/ips
- Cloudflare HTTP/2 to Origin（回源读超时 125 s）：https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/
- Turnstile 隐私附录：https://www.cloudflare.com/turnstile-privacy-policy/
- Turnstile widget 管理 API：https://developers.cloudflare.com/turnstile/get-started/widget-management/api/
- Turnstile secret 轮换：https://developers.cloudflare.com/turnstile/troubleshooting/rotate-secret-key/
- AOP（zone-level）：https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/
- 托管变换参考：https://developers.cloudflare.com/rules/transform/managed-transforms/reference/
