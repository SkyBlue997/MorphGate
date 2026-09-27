# 03 信号与风险评分

**结论**：身份判定在评分之前。每个信号都带可用性状态（`PRESENT` / `ABSENT` / `MISSING`，本文 §3.1 为唯一定义），状态由站点配置的 `UpstreamProfile` 决定（见 [08](08-upstream-and-cloudflare.md)）。上游本来就不提供的信号不算任何方向的证据。同族信号的贡献有上限，人类证据也有上限。新增的信号族先跑 shadow，用所有者自己的流量校准后再启用。

## 1. 判定分层

```
Request
  -> [Ingress]         UpstreamProfile: authenticate upstream, strip untrusted upstream headers,
                       map headers -> canonical signals, mark MISSING via expected-signal set
  -> [L0 Identity]     agent signature / crawler verification / token / proof / API key
  -> [L1 Hard rules]   allow/deny lists, impersonation, replay, grant violation
  -> [L2 Signals]      detectors emit Signal{value, confidence, state, source, reason}
  -> [L3 Scoring]      family-capped log-odds (v1) or calibrated GBDT (v2); shadow families logged only
  -> [L4 Entity risk]  fresh verdicts: session / device / ip / prefix / fp-cluster / account
  -> RiskAssessment{score, confidence, bot_class, top_reasons}
  -> Policy -> Decision
```

Ingress 由 Edge 的适配层负责：认证上游、删除不可信的上游头、把上游头映射为规范信号（见 [08](08-upstream-and-cloudflare.md)）。Decision Core 只接收规范化后的信号和各信号的状态，不直接读上游头。

## 2. 分类（BotClass）

| 类别 | 判定依据 | 默认处理方向 |
|---|---|---|
| `AUTHORIZED_AGENT` | 注册 Agent 签名有效，且请求落在授权范围内 | 按授权范围放行，独立限额，全量审计 |
| `VERIFIED_CRAWLER` | 公开爬虫身份经自有验证（官方 IP 段 / rDNS / Web Bot Auth）通过；上游的 verified-bot 标记只作佐证（§3.9） | 按站点爬虫策略（见 [05](05-ai-agent-policy.md)） |
| `API_PARTNER` | API Key / mTLS 认证的服务端调用方。mTLS 只在 `direct_tls` 监听器上可用（Cloudflare 之后 TLS 终止在 Cloudflare）；API 防护按需、未排期（[07](07-roadmap.md)） | 按合作方配额 |
| `SIGNED_AGENT` | Web Bot Auth 签名有效、运营方可识别，但未被本站授权 | 仅公开内容 + 限额；测试环境拒绝 |
| `DECLARED_AGENT` | 自我声明为 Bot / Agent，但未注册或无法验证 | 仅公开内容 + 更低限额；测试环境拒绝 |
| `IMPERSONATOR` | 声称是已知爬虫 / Agent，但自有验证失败（上游标记不能推翻这一结论） | 阻断 |
| `SCANNER` | 扫描探测特征（敏感路径、载荷、404 比例） | 阻断并告警 |
| `AUTOMATION_LIKELY` | 无身份，评分高 | 挑战或阻断 |
| `HUMAN_LIKELY` | 评分低，且置信度达到阈值（阈值按 UpstreamProfile 校准） | 放行 |
| `UNKNOWN` | 证据不足 | 按路由敏感度决定是否挑战以收集证据 |

类别之外可附加标签，例如 `delegated`：在用户真实浏览器中代用户操作的 Agent（见 [05 §2](05-ai-agent-policy.md#2-分类)），可与 `HUMAN_LIKELY`、`AUTOMATION_LIKELY`、`SIGNED_AGENT` 同时出现。

## 3. 信号体系

每个检测器输出 `Signal{id, family, value ∈ [-1,1], confidence ∈ [0,1], state, source, reason_code}`。`value > 0` 表示自动化证据，`value < 0` 表示人类证据。**`ABSENT` / `MISSING` 不等于人类证据**，只影响置信度。

### 3.1 信号状态与上游可用性

| 状态 | 含义 | 取值 | 对置信度的影响 |
|---|---|---|---|
| `PRESENT` | 检测器拿到了输入并给出结果 | 按检测结果 | 计入覆盖度 |
| `ABSENT` | 当前 profile 应该能提供，但本请求没有（如首个请求还没有 SDK 遥测，或没有凭证） | 0 | 计入分母、不计入分子，置信度下降 |
| `MISSING` | 当前 profile 本来就不提供（不在预期信号集合 E(p) 内，如 `cloudflare` 下的 JA4）；或应由上游注入的头没有到达、来源无法确认（Transform Rule 缺失、Tier 1 未运行） | 0 | 分子分母都不计入（§4.1）；只有 Tier 0 头缺失另触发配置告警 |

- 上游注入的头只在认证通过的连接上采信（未认证连接上的在 Ingress 删除），其缺失不能算到访客头上：Tier 0 头在认证请求上缺失 → `MISSING` + 配置告警（`mg_upstream_signal_missing_total`，阈值见 [06 §5](06-policy-console-observability.md#5-日志指标与告警)）；Tier 1 未运行（含 Worker fail-open、无 `x-mg-cf-t1` 标记）→ `MISSING`，不告警。
- 客户端能控制的"缺失"不属于状态问题。例如 UA 声明 Chromium 却不带 `Sec-CH-UA`，由对应检测器输出一个 `PRESENT` 信号。
- 每个信号记录来源 `source`（`self` / `cloudflare` / `cloudfront` / `gcp_alb` / `esa` / `envoy` / `openresty` / `sdk`）和 `authenticated`，写入 DecisionEvent，供漂移分析使用。例：`tls.ja4 {value, source, authenticated}`。
- 与上游信号同名的客户端头：Tier 0 由 Transform Rule 的 Set 覆盖（值为空即删除）；同一条规则还删除 Tier 1 头名，客户端伪造的值不会留存（[08 §2.3](08-upstream-and-cloudflare.md#23-信号转发-tier-0request-header-transform-rule)、§2.4；Worker 与 Transform Rule 的执行顺序需实测）。
- 策略（CEL）读取 `MISSING` 字段时结果为"未知"、规则按不匹配处理，见 [06 §2](06-policy-console-observability.md#2-策略语言)。

**Phase 1 两种 profile 的逐信号可用性**（本表为规范；族级概括见 [01 §7](01-architecture.md#7-信号可用性矩阵)，头映射与待实测项见 [08 §2](08-upstream-and-cloudflare.md#2-cloudflare-前置cloudflare-profile)，其他 profile 见 [08 §3](08-upstream-and-cloudflare.md#3-其他-cdn-与云负载均衡)）。"不适用""未规划""MISSING"都不在 E(p) 内。

| 信号 | `direct_tls` | `cloudflare`（Tier 0：Transform Rule） | `cloudflare` + Tier 1（Worker / Snippet） |
|---|---|---|---|
| 客户端 IP | TCP 对端 | `CF-Connecting-IP` | 同左 |
| ASN / 地理 | 本地 IP 库 | 本地 IP 库为准；`x-mg-cf-asn`、`cf-ipcountry`、`cf-timezone` 只作交叉校验 | 另有 `x-mg-cf-as-org` |
| 客户端 RTT | 未规划 | `x-mg-cf-rtt` / `x-mg-cf-quic-rtt` | 同左 |
| JA4（TLS 族） | Edge 自己计算 | MISSING | MISSING |
| 边缘 TLS 字段（EDGE_TLS 族） | 不适用 | `x-mg-cf-tls-*` | 同左 |
| HTTP/2 帧指纹 | 个人版无限期推迟 | MISSING | MISSING；只有 `x-mg-cf-priority`（浏览器 HTTP/2 优先级） |
| 请求头顺序 / 大小写 | HTTP/1 原始头可取 | MISSING；`x-mg-cf-hdr-names` 只当集合用 | 同左 |
| `Accept-Encoding` | 原值 | MISSING（被改写为 `br, gzip`） | `x-mg-cf-accept-encoding` |
| `Connection` | 原值 | MISSING（被改写） | MISSING |
| HTTP 版本 | Edge 协商结果 | `x-mg-cf-http-version` | 同左 |
| TCP 层特征 | 未规划 | MISSING | MISSING |
| Client Hints / Fetch Metadata / Cookie / Referer / Origin | 原样 | 原样透传 | 同左 |
| 上游 bot verdict（EXTERNAL 族） | 不适用 | `x-mg-cf-vbot` / `x-mg-cf-vbot-cat` | 同左 |
| 每连接键 `client_conn_key` | Edge 下游连接 | `hash(x-mg-cf-tls-random)`（回源连接被多个访客复用，§3.8） | 同左 |
| SDK 信号（CLIENT 族） | 全部 | 全部 | 全部 |

### 3.2 网络层（NETWORK）

| 信号 | 说明 | 强度 |
|---|---|---|
| 连接类型 | 数据中心 / 云厂商 / 住宅 / 移动 / 教育；数据中心 IP 访问面向消费者的页面是正向证据 | 中 |
| 匿名网络 | Tor 出口、公开代理、商业 VPN 段；`cloudflare` 下 `cf-ipcountry = T1` 表示 Tor | 中 |
| ASN 风险 | ASN 在本平台的历史滥用率（来自实体 verdict）；ASN 以本地 IP 库为准，与 `x-mg-cf-asn` 不一致时只记数据质量日志，不计分 | 中 |
| 会话内 IP 漂移 | 同一会话在短时间内跨 ASN / 跨国家切换 | 中高 |
| 地理一致性 | IP 国家 vs 时区 / 语言（SDK 提供）；`cloudflare` 下还可用 `cf-timezone`。只作弱信号 | 弱 |
| 会话内 RTT 突变 | 与 IP 漂移联合判断。大陆访客经境外节点访问，RTT 普遍偏高，高 RTT 本身不是证据。先 shadow | 弱 |

### 3.3 TLS 层（TLS）

**结论**：TLS 族只在能拿到访客 ClientHello 的 profile 下可用：`direct_tls` 由 Edge 自己计算 JA4；`cloudfront` / `gcp_alb` / `esa` / `envoy` / `openresty` 可以转发 JA4（有些需要特定套餐或版本，见 [08](08-upstream-and-cloudflare.md)）。`cloudflare` 下整族为 `MISSING`，由 §3.4 的 EDGE_TLS 部分替代。

| 信号 | 说明 | 强度 |
|---|---|---|
| UA 家族一致性 | JA4 是否落在声明浏览器家族 / 版本的已知指纹集合内（集合由本平台自有流量统计生成） | 高 |
| 指纹稀有度 | JA4 在站点流量中出现的频率 | 中 |
| 指纹簇扩散 | 同一 JA4 + UA 组合短时间内出现在大量不相关 IP 上 | 中高 |
| 协议参数 | TLS 版本、ALPN 与声明的客户端能力不符 | 中 |

- 来源权重：`w_s` 乘以 `λ_src`（§4.1）。来源未认证的 JA4 在 Ingress 丢弃。
- 默认只用 JA4（BSD-3）。JA4+ 放在默认关闭的 Cargo feature `ja4plus` 之后，默认构建不产生 JA4+ 信号；许可见 [ADR-0009](adr/0009-ja4-only-licensing.md) 与 [01 §9](01-architecture.md#9-技术选型建议)。

### 3.4 Cloudflare 边缘 TLS（EDGE_TLS）

**结论**：`cloudflare` profile 下，Cloudflare 能免费转发的 ClientHello 衍生字段只构成一个不完整的画像，不等于 JA4。这些字段在参考文档中没有套餐标注，据此推断所有套餐都可用，仍需在所有者的 zone 上实测。因此 EDGE_TLS 定为弱信号族：低权重，低封顶（`C = 1.0`）。Phase 1 只跑 shadow，实测稳定后再启用。

**输入**：Tier 0 Transform Rule 写入的 `x-mg-cf-tls-version`、`-tls-cipher`、`-tls-ciphers-sha1`、`-tls-ext-sha1`、`-tls-hello-len`（源字段、拼写待实测项见 [08 §2.3](08-upstream-and-cloudflare.md)）。ClientHello 长度使用前先分桶；扩展哈希的排序与 GREASE 处理未文档化。`x-mg-cf-tls-random` 不是 EDGE_TLS 的输入，只作连接键（§3.8）。

**信号**

| 信号 | 输入 | 说明 | 强度 | 初始状态 |
|---|---|---|---|---|
| 粗粒度家族一致性 | version + cipher + ciphers_sha1 + hello_len 分桶 | 该元组是否落在声明浏览器家族 / 主版本的已知集合内。集合只用所有者自己的 shadow 流量生成 | 弱 | shadow |
| 元组稀有度 | 同上 | 该元组在站点流量中出现的频率 | 弱 | shadow |
| 元组簇扩散 | 元组 + UA | 同一组合短时间内出现在大量不相关的 IP / ASN 上 | 弱 | shadow |
| 协议参数 | version + cipher | 与声明的客户端能力不符 | 弱 | shadow |
| 扩展哈希 | ext_sha1 | 只记录，权重为 0 | — | 仅记录 |

**从 shadow 转为 active 的条件**（须全部满足；门槛均为初始值）：

1. 已在所有者的 zone 上实测以下几点：套件哈希字段两种拼写中哪一种可用；HTTP/3 连接和 TLS 会话恢复时这些字段是否有值。文档对这两点都没有说明。
2. 稳定性：按浏览器家族 + 主版本统计，同一会话（Phase 1 为同一凭证 `sub`，Phase 2 起为同一 `cnf.jkt`）内元组一致的比例 ≥ 99%。
3. 区分度：各主要浏览器家族的元组集合重叠较小，足以支撑一致性判断。
4. 误伤：shadow 对比显示，启用后可能为人的会话进入中 / 高分段的比例，增量不超过 §9 的门槛。

扩展哈希单独评估，证明稳定之前不能用于高权重信号或硬绑定。凭证绑定 `bind.ctp` 使用同一个粗粒度元组（不含扩展哈希），仅 `cloudflare` profile、仅 shadow；满足上面第 2 条（≥ 99%）后才可转为软绑定（见 [04 §5](04-challenge-and-tokens.md)）。

### 3.5 HTTP 层（HTTP）

| 信号 | 说明 | 强度 | `cloudflare` 下 |
|---|---|---|---|
| HTTP/2 指纹一致性 | SETTINGS、WINDOW_UPDATE、优先级、伪首部顺序与声明浏览器不符 | 高 | MISSING。个人版在 `direct_tls` 下也无限期推迟 |
| 请求头顺序 / 大小写 | 与声明浏览器的典型形态不符 | 中高 | MISSING |
| 请求头集合 | 缺少浏览器必带的头，或出现非浏览器的头 | 中 | 以 `x-mg-cf-hdr-names` 为准，只当集合用；名称保留原大小写（有文档），大小写只在 shadow 中研究（[08 §2.5](08-upstream-and-cloudflare.md#25-在-cloudflare-之后失真的信号)） |
| `Accept-Encoding` 一致性 | 与声明浏览器不符 | 中 | MISSING。Tier 1 下改用 `x-mg-cf-accept-encoding`；Transform Rule 能否读到原值以实测为准 |
| `Connection` | 取值不像浏览器 | 弱 | MISSING |
| 协议版本 | 声明现代浏览器，却使用 HTTP/1.x | 弱 | 用 `x-mg-cf-http-version` |
| 请求优先级 | 浏览器的 HTTP/2 优先级参数与声明浏览器不符 | 弱 | 仅 Tier 1（`x-mg-cf-priority`），先 shadow |
| Client Hints | 声明 Chromium 却缺失 `Sec-CH-UA*`，或与 UA 矛盾 | 中 | 可用 |
| Fetch Metadata | `Sec-Fetch-Site/Mode/Dest` 与实际请求类型矛盾（如 API 端点收到 navigate） | 中 | 可用 |
| 首方状态 | 长期不携带首方 Cookie / 凭证，或 Referer / Origin 异常 | 中 | 可用。忽略 Cloudflare 自己的 Cookie（`__cf_bm`、`cf_clearance`、`_cfuvid` 等） |
| 协议异常 | 冲突的 `Content-Length` / `Transfer-Encoding`、非法 Host、重复关键头 | 高（直接阻断） | 可用 |

### 3.6 客户端（CLIENT，来自 SDK）

采集设计见 [04 §7](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)。

| 信号 | 说明 | 强度 |
|---|---|---|
| 自动化标志 | 标准的 WebDriver 标志、无头环境特征、调试协议注入痕迹 | 高 |
| 环境一致性 | UA / Client Hints / 屏幕 / 图形栈 / 时区 / 语言之间相互矛盾 | 中高 |
| 执行完整性 | SDK 被篡改、Challenge 执行耗时异常、结果与 nonce 绑定失败 | 高 |
| 页面已加载但 SDK 从未运行 | HTML 被请求过，但会话内没有遥测，也没有 Challenge 提交。`cloudflare` 下先排除两种情况：上游挑战（SDK 上报的 `cf-mitigated` 计数）和 Rocket Loader 干扰（见 [08](08-upstream-and-cloudflare.md)） | 中高 |
| 设备证明（移动，后期按需） | App Attest / Play Integrity 等结果；应用签名、调试 / 注入检测 | 高 |

交互式 Challenge 的交互遥测只在 Challenge 校验时评分，评分方法与 §4.1 相同（按族封顶）。特征与硬检查见 [09](09-interactive-challenge.md)。

### 3.7 行为（BEHAVIOR，近线产出，经 verdict 回灌）

见 §6。

### 3.8 限速、连接与身份（RATE / IDENTITY）

- 限速器利用率本身就是信号（接近阈值即加分），不只是硬性拦截条件。
- **每连接特征**（每连接请求数、每连接出现的 UA 数 / 会话数）统一以 `client_conn_key` 为键（定义见 [02 §2.3](02-data-flow.md#23-要点)）：`direct_tls` 取 Edge 的下游连接；`cloudflare` 下回源连接（含 Tunnel 中 cloudflared 到 Edge 的连接）被多个访客复用，**不得以下游连接作为任何状态的键**，改取 `hash(x-mg-cf-tls-random)`，只在内存与近线短期使用，不写入 DecisionEvent。该值由客户端生成，只能用于计数类特征，不能用于授权或绑定；没有值时（HTTP/3、会话恢复下是否有值需实测）这些特征为 `MISSING`。
- 凭证状态：缺失 / 过期 / 无效 / 重放；持有证明是否有效。绑定按阶段（详见 [04 §5](04-challenge-and-tokens.md)）：Phase 1 为 `uah`（硬）+ `ipp`（软）；Phase 2 起加 `cnf.jkt`（硬，SDK 会话密钥）；`tfp`（硬）仅 `direct_tls`，JA4 预研成功后启用；`ctp` 仅 `cloudflare`、仅 shadow，达标后才可转为软绑定（§3.4）。
- Agent 签名；爬虫验证（官方 IP 段 + 异步 rDNS）。
- 凭证和 Challenge 通过带来的负向贡献有上限，见 §4.1。

### 3.9 上游 verdict（EXTERNAL）

**结论**：上游 CDN 自带的 bot 判定只能作佐证。封顶 `C = 1.0`，只取非负值，**永远不作为权威**：它不能单独得出 `VERIFIED_CRAWLER` 或 `IMPERSONATOR`，也不能单独决定放行或阻断。

输入：`cloudflare` 下的 `x-mg-cf-vbot` / `x-mg-cf-vbot-cat`（所有套餐，见 [05 §3.4](05-ai-agent-policy.md#34-cloudflare-verified-bot-标记佐证)）；`edgeone` 下的 `EO-Bot-Tag`（仅其 Bot 管理开启时出现，Phase 4 按需，字段格式待确认）。上游头来自未认证连接时已在 Ingress 删除。分类结果（含与自有验证分歧时的处理和 `mg_cf_vbot_disagree_total`）以 [05 §3.4](05-ai-agent-policy.md#34-cloudflare-verified-bot-标记佐证) 为准；本节只定义 EXTERNAL 的取值：

| 情况 | EXTERNAL 取值 |
|---|---|
| vbot = true，自有验证通过 | 0（分类由 L0 决定） |
| vbot = true，自有验证未通过或未覆盖 | 小正值（自动化证据），不升级为 `VERIFIED_CRAWLER` |
| vbot = false，UA 声称是已知爬虫 | 小正值（冒充佐证） |
| vbot = false，没有任何声明 | 0，**不算人类证据**（绝大多数流量的 vbot 都是 false） |

上游 verdict 不作为训练标签（§8）。Enterprise Bot Management 的 bot score 与 JA4（Tier 2）超出预算，不规划。

## 4. 评分模型

### 4.1 v1：分族封顶的对数几率模型（可解释，MVP）

```
z        = z0(route) + Σ_{f∈active} clip( Σ_{s∈f} λ_src(s) · w_s · c_s · v_s , L_f , U_f )
                     + Σ_e β_e · clip(logit(R_e / 100))
z_shadow = z + Σ_{f∈shadow} clip( ... )        (logged in DecisionEvent, never enforced)
score    = round(100 · sigmoid(z))
```

| 符号 | 含义 |
|---|---|
| `z0(route)` | 路由先验，取 `logit(该路由历史自动化占比)`。登录、注册、短信接口的先验高于静态页；"受攻击模式"下额外 +Δ |
| `w_s` | 信号权重（近似对数似然比）。初期人工设定，积累标签后用逻辑回归拟合 |
| `λ_src(s)` | 来源系数：Edge 自己计算的为 1.0，CDN / 网关转发的为 0.8（初始值） |
| `c_s`, `v_s` | 信号的置信度与取值。`MISSING` / `ABSENT` 时 `v_s = 0` |
| `[L_f, U_f]` | 族区间，防止同族内高度相关的信号重复计分。默认为 `[-C_f, +C_f]`，初始值见下表 |
| `active` / `shadow` | 族的运行模式。shadow 族照常计算，只写入 `z_shadow` 用于对比，不影响处置 |
| `R_e`, `β_e` | 未过期的实体 verdict 及其权重（session 0.6、device 0.5、account 0.5、fp-cluster 0.4、ip 0.3、prefix 0.2） |

**族区间**（初始值，用所有者的 shadow 数据校准）

| 族 | `[L_f, U_f]` | `direct_tls` | `cloudflare` | 说明 |
|---|---|---|---|---|
| NETWORK | ±1.5 | 可用 | 可用 | §3.2 |
| TLS | ±2.5 | JA4 由 Edge 自算 | MISSING | 其他 profile 转发的 JA4 乘 `λ_src` |
| EDGE_TLS | ±1.0 | 不适用 | Phase 1 shadow，达标后转 active | §3.4 |
| HTTP | ±2.0 | 可用 | 部分为 MISSING | §3.5 |
| CLIENT | ±3.0 | SDK | SDK | §3.6 |
| BEHAVIOR | ±3.0 | 近线 | 近线 | §6 |
| REPUTATION | ±3.0 | 可用 | 可用 | 情报名单命中（控制面 Intel Sync 下发） |
| RATE | ±2.0 | 可用 | 可用（连接键 `client_conn_key`） | §3.8 |
| IDENTITY | [−1.5, +2.0] | 可用 | 可用 | 负向为凭证 / Challenge 通过（上限见下表），正向为软绑定不符等；重放与硬绑定不符走 §4.2 |
| EXTERNAL | [0, +1.0] | 不适用 | 可用 | 只作佐证，§3.9 |

**人类证据的上限**：通过 Challenge 只能证明"完成了 Challenge"，不能证明"是人"——公开研究显示自动求解与商用打码对主流验证码（含 Turnstile）成功率接近 100%（数字见 [09 §1](09-interactive-challenge.md#1-定位)）。因此交互式 Challenge 通过只作为**封顶的人类证据**，其价值来自 09 中的服务端机制：密封一次性 nonce 及绑定、PoW 成本、交互遥测评分、签发与尝试配额。

| 证据（有效凭证的 `lvl`） | 负向贡献上限（初始值） | 说明 |
|---|---|---|
| `pow` | −0.3 | PoW 是成本杠杆，不是识别手段 |
| `invisible` | −0.5 | 执行了 JS、完成了轻量 PoW，环境信号已采集 |
| `interactive`（`self_hold`） | −0.8 | 封顶的人类证据 |
| `interactive_a11y`（`pow_a11y`） | −0.8 | 与 `interactive` 相同，无障碍用户不因路径不同而承担更高风险分；以更短 TTL（15 分钟 vs 30 分钟）与更严配额补偿（见 [04 §5](04-challenge-and-tokens.md)） |
| `interactive_ext:{provider}`（如 `turnstile`） | −0.8 | 同 `interactive`，第三方 Provider 的通过不高于自研 |
| `attested`（保留给后期移动端） | −1.2 | 平台设备证明 |
| 所有族的负向贡献合计 | ≥ `H_min`（初始 −4.0） | 人类证据不能抵消强自动化证据 |

通过之后仍然要监控：按前缀 / ASN 统计凭证签发数、解题时间分布、通过率突然接近 100%（`mg_challenge_total` 按 `provider` 分，告警见 [06 §5](06-policy-console-observability.md)）。Challenge 通过不会重置实体 verdict。

**置信度**：按 profile 的预期信号集合计算，避免上游本来就不提供的信号让请求显得可疑。

```
E(p)       = signals the UpstreamProfile p is expected to provide (in the signed config bundle)
S(r)       = { s ∈ E(p) : state_s(r) ≠ MISSING }        (drops expected upstream headers that did not arrive)
cov_f      = Σ_{s∈f∩S(r)} a_s · present_s  /  Σ_{s∈f∩S(r)} a_s
confidence = κ(p) · Σ_{f∈F(r)} A_f · cov_f  /  Σ_{f∈F(r)} A_f ,   F(r) = { f : f∩S(r) ≠ ∅ }
```

- `MISSING` 的信号（不在 E(p) 中，或在 E(p) 中但上游头未到达 / 来源无法确认）不进入 S(r)，分子分母都不计入。因此 Cloudflare 后面的正常浏览器不会因上游原因被判为"低置信度 → 挑战"；配置问题由告警暴露（§3.1）。
- `ABSENT` 的信号计入分母、不计入分子。首个请求、没有 SDK、没有凭证时，置信度低，这一点与原设计相同。
- `κ(p)` 表示该上游下可得信息的上限（初始值：`direct_tls` 1.0，`cloudflare` 0.9）。它用统一的方式体现 `MISSING` 带来的信息损失：同一 profile 下所有请求的 κ 都相同，所以不会让个别请求显得可疑。§5 中的置信度阈值按 profile 分别校准。

### 4.2 硬规则（在评分之外）

| 条件 | 结果 |
|---|---|
| 允许 / 拒绝名单（均带过期时间） | 直接定结论，仍记录日志 |
| 注册 Agent 签名有效 | 分类为 `AUTHORIZED_AGENT`，改用授权范围检查和 Agent 专属限额，不走通用人机评分 |
| Agent 签名有效但超出授权范围 | 默认阻断 + 告警 |
| 声称是已知爬虫，但自有验证失败 | 判为 `IMPERSONATOR`，score 下限 90 |
| 凭证重放、密钥绑定不符 | score 下限 90，吊销该凭证 |
| 实体带 `scanner` 标签 | score 下限 85 |
| `/__mg/*` 状态变更端点收到 `Early-Data: 1` | 返回 425；首选关闭 0-RTT，其他请求按可重放处理（见 [04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt)） |
| 上游信号头来自未认证的连接 | 在 Ingress 删除，按 `MISSING` 处理，不进入评分 |
| 上游 verdict（EXTERNAL） | 不触发任何硬规则 |

### 4.3 会话风险

```
R_session(t) = max( r_t , R_session(t_prev) · exp(-(t - t_prev) / τ) ),   τ ≈ 10 min
```

一次高风险行为会在一段时间内抬高整个会话的风险，之后随时间衰减。会话键取自凭证（§6），不使用连接。

### 4.4 v2：校准后的 GBDT（积累标签后，Phase 4 按需）

- **特征**：所有信号（`value × confidence`）、原始数值特征（计数、比例）、类别特征（频率编码的 JA4 家族、EDGE_TLS 粗粒度元组、ASN 类别、UpstreamProfile）、实体 verdict。`MISSING` / `ABSENT` 按原生缺失值输入模型，不填充为中性值。
- **模型**：LightGBM 二分类（输出自动化概率），约 200–400 棵树、深度 6–8；按 profile 分别做等渗回归校准，得到 `score = 100 · p`。
- **组合**：`z = logit(p_model) + 硬规则调整`；保留 v1 规则层，用于模型不可用时的回退和解释。
- **解释**：把 TreeSHAP 贡献映射为 reason code，取 top-k。
- **内联推理**：在 Rust 中求值树模型，预算 < 50µs。
- **漂移监控**：按站点监控分数分布的 PSI 和关键特征漂移，超过阈值时告警，并可自动回退到上一版本。
- **小流量**：标签不足时继续使用 v1（见 §9）。

## 5. 分级处置

### 5.1 默认处置矩阵（按路由覆盖）

| 分段 | 分数 | 普通路由 | `critical` 路由（登录 / 注册 / 支付 / 短信） |
|---|---|---|---|
| 低 | 0–29 | ALLOW | ALLOW（仍要求有效凭证 + 持有证明） |
| 中 | 30–59 | ALLOW + TAG；置信度 < θ_c 时无感 Challenge | 无感 Challenge |
| 高 | 60–84 | 无感 Challenge，失败则升级为交互式；收紧限速 | 交互式 Challenge 或阻断 |
| 极高 | 85–100 | BLOCK（仅 `direct_tls` 下可选 TARPIT） | BLOCK |

**规则**：

1. 置信度低于 θ_c（初始值 0.4，按 UpstreamProfile 用 shadow 数据校准）且处于中 / 高分段时，优先 Challenge（收集证据），不直接阻断。
2. API 渠道无法展示 HTML Challenge：有 SDK 的客户端返回 JSON Challenge；纯服务端调用方必须使用 API Key / mTLS（仅 `direct_tls`）/ Agent 注册，未知的高风险调用返回 403 / 429。
3. 阻断页面只包含请求 ID 和申诉入口，不暴露任何检测细节。
4. Challenge 和阻断响应使用 403 / 429（不用 200），并带 `Cache-Control: no-store, private`，防止在 Cloudflare 前置时被缓存（见 [08](08-upstream-and-cloudflare.md)）。
5. 交互式 Challenge 的 Provider 由 Decision Core 选择，客户端不能选：默认为 `self_hold`；无障碍路径为 `pow_a11y`；`turnstile` 可选，大陆访客永远不会被分配 Turnstile（见 [09](09-interactive-challenge.md)）。
6. 上游挑战（响应带 `cf-mitigated: challenge`）不算 MorphGate 的 Challenge 失败，不累计失败次数，也不加分。
7. 所有动作都支持 `dry_run`（只记录"本应执行的动作"），另有全局 monitor 开关。

### 5.2 处置动作

| 动作 | 用途 |
|---|---|
| `ALLOW` / `LOG` | 放行 / 放行并全量记录 |
| `TAG` | 放行，向源站附加分数与分类，由业务自行决策 |
| `RATE_LIMIT` | 429 + `Retry-After` |
| `CHALLENGE` | 无感 / PoW / 交互式（自研按住验证、`pow_a11y`、可选 Turnstile；见 [09](09-interactive-challenge.md)）/ 设备证明（移动，后期）；见 [04](04-challenge-and-tokens.md) |
| `TARPIT` | 延迟响应，拖慢确定性高的自动化，不消耗源站资源。不作为默认动作，只在 `direct_tls` 下可选。`cloudflare` profile 下不用：延迟受回源读超时 125 s 限制（超时返回 524），且占用多个访客共享的回源连接（见 [08 §2.5](08-upstream-and-cloudflare.md#25-在-cloudflare-之后失真的信号)），改用 `RATE_LIMIT` / `BLOCK` |
| `BLOCK` | 403 通用页面 |

## 6. 会话与行为序列分析

**会话标识**：Web 用凭证中的假名化 `sub`（首方），API 用账号 / API Key / 设备 ID。不使用连接作为会话键：`cloudflare` 下回源连接被多个访客复用，需要连接级特征时按 §3.8 处理。

**服务端序列特征**（由 DecisionEvent 在近线计算）：

| 类别 | 特征 |
|---|---|
| 时序 | 请求间隔的均值 / 方差 / 变异系数、最小间隔、周期性（自相关峰）、突发度 |
| 导航 | 路径模板化（`/item/{id}`）后的转移对数似然（站点基线马尔可夫模型）、路径熵、深度 / 广度比、回退率 |
| 资源 | HTML 与静态资源的比例、HTML 之后是否拉取关键资源、SDK 是否执行。Cloudflare 缓存命中的静态资源不会到达 Edge，这类比例只统计回源请求，或改用 SDK 上报 |
| 枚举 | 有序 ID 访问、参数扫描、分页深度 |
| 结果 | 4xx / 5xx 比例、登录失败率、每会话 / 每设备的不同用户名数 |

**客户端行为摘要**（SDK 在端上计算后上报，不含按键内容）：指针速度与曲率分布、停顿、点击按下到释放的时长、键入间隔分布、滚动动力学、触控面积与压力（移动端）、焦点 / 可见性变化、表单填写时长、粘贴使用。交互式 Challenge 的遥测字段见 [09](09-interactive-challenge.md)。

**模型演进**：阈值规则 + 马尔可夫似然 → 会话级 GBDT → 离线训练、近线运行的序列模型（小型 GRU / Transformer）。序列模型不进入内联路径。个人版按数据量决定演进到哪一步。

**图关联**（Phase 4）：构建带时间衰减的实体二部图，识别以下模式：一个设备对应多个账号（批量注册 / 养号）；一个账号对应多个设备和多个 IP（撞库成功后的接管）；指纹簇在短时间内跨越大量住宅 IP（代理池）；多个会话在时序上同步（协同行动）。输出簇级 verdict。

## 7. 异常请求识别

- **协议异常**：请求走私特征、非法 Host、绝对形式 URI、异常方法，直接阻断。
- **接口正向模型**（按需、未排期，见 [07](07-roadmap.md)）：按路由导入 OpenAPI，把未知端点、多余参数、类型不符记为异常；可选开启严格模式直接拒绝。
- **业务序列约束**：例如未经购物车直接下单、未请求验证码页面就提交验证码。
- **一致性**：`Content-Type` 与请求体、Fetch Metadata 与端点类型、Origin / Referer 与站点。

## 8. 标签与反馈

| 来源 | 标签 | 注意 |
|---|---|---|
| Validation Lab（自有测试环境中的自有自动化脚本） | 自动化 | 分布与真实攻击不同，只用于回归与下限评估 |
| 蜜罐（对人不可见的链接 / 表单字段） | 自动化 | 高精度，覆盖低 |
| 冒充、重放、扫描命中 | 自动化 | 高精度 |
| 业务回传（确认的撞库、批量注册、欺诈） | 滥用 | 延迟到达 |
| 长期登录、有真实交易的账号会话 | 可能是人 | 有噪声；需隐私约束 |
| Challenge 结果 | 弱标签 | **不能**当作干净的人类标签 |
| 误报申诉 | 误报 | 优先级最高，进入复盘 |

上游 verdict（EXTERNAL 族）只作为特征，不作为标签。

## 9. 评估指标与上线门槛

| 指标 | 目标（初始值，按站点调整） |
|---|---|
| 检测率 | 在固定误报率（≤ 0.1%）下的召回率 |
| 人类摩擦率 | 可能为人的会话被 Challenge 的比例 < 1%；交互式 < 0.1% |
| 误报申诉率 | 持续下降，每条复盘 |
| 附加延迟 | p50 < 1ms，p99 < 5ms |
| 业务指标 | 登录失败率、虚假注册量、受保护接口抓取量、短信费用 |

**上线流程**：shadow ≥ 7 天 → 与现网对比（摩擦率增量、检测增益都达到门槛）→ 灰度 5% → 25% → 100%。自动回滚的触发条件：Challenge 率突增、4xx 突增、转化率下降超过阈值。

**小流量站点（个人自用）**：门槛和流程不变，变的只是各阶段的持续时间。

- 所有阈值都由所有者自己的 shadow 数据校准，本文给出的数值只是起点。这些阈值包括：§5 的分段和 θ_c、§3.4 的元组集合、§4.1 的初始权重 / 区间 / κ(p)、以及 [09](09-interactive-challenge.md) 中的交互评分阈值。
- shadow 以样本量达标作为结束条件，而不只是满 7 天；每个路由类别单独计算。统计下限：如果观察到 0 次误报，误报率的 95% 置信上限约为 3/n（三分法则），所以要论证误报率 ≤ 0.1%，该路由类别需要约 3,000 个可能为人的会话且没有误报。样本达不到时，延长 shadow，或只对该路由启用较轻的处置（TAG / 无感 Challenge，不 BLOCK）。
- 灰度的 5% / 25% 阶段在小流量下样本很少，每个阶段同样以样本量为准延长，也可以按路由类别分批代替按比例放量。
- 自动回滚条件中的"突增"同时看绝对计数和比例，避免几个请求的波动就触发回滚。
- v2 GBDT 需要足够的标签，标签不足时保持 v1。

## 10. 误伤控制

- **CGNAT / 企业出口 / 校园网**：大量真人共用 IP。IP 级阈值按连接类型区分（移动运营商 ASN 放宽），更多依赖会话和设备维度。
- **隐私浏览器与防指纹设置**：指纹被随机化或受限时记为"信号可用性降低"，不当作自动化证据。
- **上游缺失的信号**：`cloudflare` 下 JA4、HTTP/2 指纹、请求头顺序 / 大小写、`Accept-Encoding`、`Connection` 都是 `MISSING`，不算任何方向的证据（§3.1）。
- **TLS 中间设备**：企业 TLS 代理或本地安全软件可能改变 ClientHello，导致 TLS / EDGE_TLS 与 UA 不一致。这是这两族封顶较低、而且先跑 shadow 的原因之一。
- **双重挑战**：上游挑战（`cf-mitigated: challenge`）不计入 MorphGate 的 Challenge 失败，也不触发"SDK 从未运行"信号；计数为 `mg_double_challenge_total`，处理流程见 [08 §2.8](08-upstream-and-cloudflare.md)。
- **大陆访客**：经境外节点访问，RTT 高，偶有丢包。不把 RTT 作为惩罚依据，PoW / Challenge 的超时放宽，交互式 Challenge 不分配 Turnstile（见 [09](09-interactive-challenge.md)）。
- **无障碍访问**：行为模型不能要求鼠标轨迹；交互式 Challenge 必须提供无障碍替代方式。键盘 / 切换 / 无障碍模式下，缺失的指针数据按中性处理（见 09）。
- **低端设备与弱网**：PoW 难度按设备类别自适应，超时放宽。
- **申诉闭环**：阻断页带请求 ID，所有者可以在后台一键查看判定依据并标记误报。

## 参考

- Cloudflare Request Header Transform Rules：https://developers.cloudflare.com/rules/transform/request-header-modification/
- Cloudflare Managed Transforms（visitor location headers 等）：https://developers.cloudflare.com/rules/transform/managed-transforms/reference/
- Cloudflare Snippets（套餐与限制）：https://developers.cloudflare.com/rules/snippets/
- Cloudflare HTTP/2 to Origin（多路复用、回源读超时）：https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/
- Cloudflare 0-RTT（`Early-Data: 1`）：https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/
- Cloudflare Bot Management variables（Enterprise 字段，不规划）：https://developers.cloudflare.com/bots/reference/bot-management-variables/
- 验证码求解研究的来源与数字见 [09 §1](09-interactive-challenge.md#1-定位) 与 09 的参考小节。
