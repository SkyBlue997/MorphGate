# 04 Challenge 与访问凭证

结论先行：

- Challenge 的价值来自**服务端密封且一次性的 nonce、与会话密钥 / UA / IP 前缀的绑定、PoW 成本、服务端评分和签发配额**，不来自题目难度。通过任何 Challenge 都只是封顶的人类证据（[03](03-risk-scoring.md) §4.1）。
- 默认形态是 `cloudflare` UpstreamProfile，JA4 不可用。凭证按阶段绑定：Phase 1 为 `uah`（硬）+ `ipp`（软），Phase 2 起加 `cnf.jkt`（硬）；`ctp` 只 shadow，`tfp` 只在 `direct_tls`（§5）。
- 分工：本文负责通用 Challenge、凭证、持有证明、防重放、限速与协议约定；交互式 Challenge（按住验证、无障碍路径、密封 C 字段、Provider、Turnstile、交互评分）见 [09](09-interactive-challenge.md)；Cloudflare 侧配置见 [08](08-upstream-and-cloudflare.md)。
- Web SDK 是重点；移动端（设备证明、Mobile SDK）后期 / 按需。

## 1. 各机制的防护目标

| 机制 | 防什么 | 不防什么 |
|---|---|---|
| 无感 JS Challenge | 不执行 JS 的脚本客户端；同时收集环境信号 | 能执行 JS 的自动化浏览器（靠信号与行为） |
| 工作量证明（PoW） | 抬高大规模请求的边际成本 | 算力充足的少量请求 |
| 交互式 Challenge | 纯自动化；给每次通过加上 PoW 成本、绑定与配额；收集量化交互证据 | 人工辅助 / 打码服务（对各类交互式 Challenge 成功率接近 100%，每千次 $0.10–5，[09](09-interactive-challenge.md) §1） |
| 设备证明（后期 / 按需） | 模拟器、被篡改的 App、非官方客户端 | 真机农场 |
| 短期凭证 | 每请求重复判定的开销；提供会话连续性 | 凭证被导出到别的客户端（由绑定与持有证明解决） |
| 持有证明 | 凭证窃取 / 转移、请求重放 | 控制了客户端本身的自动化；串通的人工代解中继 |
| 限速与签发配额 | 高频滥用、资源消耗、批量收割凭证 | 低频、分布式的慢速滥用（靠实体关联与行为） |

## 2. Challenge 类型

| 类型 | 用户感知 | 渠道 | 服务端验证内容 | 阶段 |
|---|---|---|---|---|
| `passive` | 无 | 全部 | 只看信号，不下发 Challenge | Phase 1 |
| `invisible` | 无（约 100–500 ms） | Web | SDK 已执行、环境信号、轻量 PoW、与 nonce 绑定 | Phase 1 |
| `pow` | 无感或轻微延迟 | Web / 带 SDK 的 API 客户端 | 难度自适应的 PoW | Phase 1 |
| `interactive` | 需要交互 | Web | 选定的 Provider（默认 `self_hold`）+ PoW + 量化交互遥测，必须提供无障碍路径（[09](09-interactive-challenge.md)） | Phase 2 |
| `step_up` | 视情况 | 敏感操作 | 单次操作的持有证明（§6.1，带 `bh` 与服务端 nonce），可叠加 PoW / 交互 | Phase 2 |
| `attestation` | 无 | Mobile | 平台设备证明 + 服务端校验 | 后期 / 按需 |

- 交互式 Provider：`self_hold`（默认）、`pow_a11y`（无障碍）、`turnstile`（可选，非大陆）、`tencent` / `aliyun_v2`（可选，Phase 4）。由 Decision Core 选定并密封进 C，客户端不能选。接口、选择与回退见 [09](09-interactive-challenge.md) §6–§7，签发的 `lvl` 见 §5。
- 移动端（后期 / 按需）：iOS 用 App Attest；Android 有 GMS 时用 Play Integrity，国内大量设备没有 GMS，退化为 Android Key Attestation（可用性因厂商而异）+ SDK 信号；鸿蒙待调研。

## 3. 流程

时序以 `cloudflare` profile 为例：Cloudflare 终止客户端 TLS，经 Tunnel 或 AOP 回源到 Edge；Edge 只在上游认证通过时采信 `CF-Connecting-IP` 与 `x-mg-cf-*`（[08](08-upstream-and-cloudflare.md)）。`direct_tls` 下去掉 Cloudflare 一跳。

### 3.1 状态机

```
NONE --risk requires--> ISSUED(type, providers)
ISSUED --solved--> CLEARED(lvl) --refresh (PoP, ~80% of TTL)--> CLEARED
ISSUED(interactive) --renew (~80% of exp, not mid-hold)--> ISSUED(interactive, fresh C)
ISSUED(invisible | pow) --failed--> ISSUED(interactive)
ISSUED(interactive) --failed--> ISSUED(interactive, fresh C, attempt_no + 1)
ISSUED(interactive) --failed x N--> ISSUED(interactive, other provider | a11y path)
ISSUED(interactive) --failed x M--> BLOCKED(429, Retry-After) --> NONE
ISSUED --expired, not renewed--> NONE
CLEARED --binding violation / replay / risk spike--> REVOKED --> NONE
```

| 转移 | 规则 |
|---|---|
| renew | 仅 `interactive`。SDK 在 C 寿命约 80% 时调用 `POST /__mg/c/renew {C, jwk, sig}`，**按住进行中不续期**。要求旧 C 未过期、未使用、绑定一致；Edge 先用 `SET NX` 消费旧 nonce，再签发新 C（新 nonce、`iat`、`exp`，继承 `type` / `providers` / `risk_band` / `attempt_no` / `ret` / `ui_seed`）。不计为失败。每条续期链上限 6 次（约 1 小时）；超出上限或旧 C 已过期（如标签页休眠）时返回 `mg_challenge_failed` 并附新 C（计入签发配额、不计失败，§9）。用户不必和倒计时赛跑（WCAG 2.2.1） |
| failed | 统一失败响应（§9），附新 C：重新随机化 `ui_seed`、PoW 参数与按住时长 |
| failed × N / × M | 初值 N = 2：换 Provider 或突出无障碍路径；M = 5：临时阻断，`429` + `Retry-After`。评分阈值见 [09](09-interactive-challenge.md) §11.3 |
| refresh | 见 §5 |

- 升级路径与 Provider 都由服务端决定。
- Provider 返回 `Unavailable` / `Misconfigured` 不算用户失败，按其 `on_unavailable` 回退（[09](09-interactive-challenge.md) §7.2）。
- 收到 Cloudflare 的 `cf-mitigated: challenge`（上游挑战）不改变 MorphGate 状态，也不计入失败（§7）。

### 3.2 浏览器导航：无感 Challenge

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant CF as Cloudflare
    participant E as Edge
    participant V as Valkey
    participant O as Origin
    B->>CF: GET /product/42 (no clearance)
    CF->>E: Tunnel / AOP + CF-Connecting-IP + x-mg-cf-*
    E->>E: authenticate upstream, score 45, confidence 0.2 -> CHALLENGE(invisible)
    E-->>B: 403 challenge page (no-store, private) + sealed C, via Cloudflare, not cached
    B->>CF: GET /__mg/s/{build}.js (content-hashed, edge-cacheable)
    B->>B: env signals, PoW(C); Phase 2+: session key + sig
    B->>CF: POST /__mg/c {C, solution, signals, [jwk, sig]}
    CF->>E: forward (cache Bypass + Skip rule, see 08)
    E->>E: checks in section 4.1 order
    E->>V: SET mg:n:{site}:{nonce} NX EX ttl
    E-->>B: 303 -> ret + Set-Cookie __Host-mg_clr, no-store, via Cloudflare
    B->>CF: GET /product/42 + cookie
    CF->>E: forward
    E->>O: forward + MG-Bot-Score / MG-Bot-Class
    O-->>B: 200 via Edge and Cloudflare
```

### 3.3 XHR / API（Web SDK）

```mermaid
sequenceDiagram
    participant A as Page JS + Web SDK
    participant CF as Cloudflare
    participant E as Edge
    participant O as Origin API
    A->>CF: POST /api/login + clearance + MG-Proof
    CF->>E: forward + CF-Connecting-IP + x-mg-cf-*
    E->>E: critical route: Early-Data, clearance, proof, replay, score
    alt low risk
        E->>O: forward
        O-->>A: 200 via Edge and Cloudflare
    else MorphGate challenge required
        E-->>A: 403 {"error":"mg_challenge","type":"pow","challenge":"..."} no-store
        A->>A: SDK solves (may escalate to interactive UI)
        A->>CF: POST /__mg/c
        CF->>E: forward
        E-->>A: 200 {"ok":true} + Set-Cookie renewed clearance
        A->>CF: retry POST /api/login (new proof, new jti)
    else Cloudflare challenged upstream
        CF-->>A: challenge page, cf-mitigated: challenge
        A->>A: not a MorphGate failure: record telemetry, top-level reload
    end
```

### 3.4 交互式 Challenge（概要）

完整时序、Provider 调用、评分与无障碍路径见 [09](09-interactive-challenge.md) §5。与本文相关的约束只有两条：本地检查全部通过后、任何外部 Provider 调用**之前**消费 nonce（§4.1 第 10 步）；续期规则见 §3.1。

### 3.5 移动端设备证明（后期 / 按需）

`POST /__mg/m/attest/init` 取密封 challenge → App 在 Secure Enclave / Keystore 生成硬件密钥 → 平台证明覆盖 `hash(nonce, 公钥)` → `POST /__mg/m/attest {challenge, attestation, 公钥, app signals}` → Edge 校验证书链或调用平台校验 API → 签发 `lvl=attested`、`cnf` 为密钥指纹的凭证 → 之后每个 API 请求附凭证与请求签名。Cloudflare 之后每一跳同样经过 Cloudflare。

## 4. Challenge 实现要点

### 4.1 密封 Challenge 与验证顺序

**无状态**：签发时不写存储，大量索取 Challenge 不能耗尽后端状态。所有类型共用一种格式：prost 编码的 protobuf 消息 `SealedChallengeClaims`，外层 XChaCha20-Poly1305，`aad = host ‖ type ‖ kid`，**绝不用字符串拼接**（ALTCHA CVE-2025-68113 的教训）。字段与编码细节见 [09](09-interactive-challenge.md) §4。密钥：每站点一把长期根密钥 `K_seal_root`（systemd credential 交付，年更或泄露时轮换）；每日 `k_epoch = HKDF-SHA256(K_seal_root, info = "mg-seal-v1" ‖ site ‖ epoch_no)`，Turnstile `cData` 的 `k_bind_epoch` 同法以 info `"mg-bind-v1"` 派生；各 Edge 确定性派生同一 epoch 密钥，无需每日分发，接受当前与上一个 epoch；epoch 密钥泄露不暴露根密钥（[ADR-0005](adr/0005-token-and-sealed-challenge-format.md)）。

| 类型 | C 有效期 | 到期后 |
|---|---|---|
| `invisible` / `pow` | `exp − iat ≤ 120 s` | 重新请求原资源获取新 C |
| `interactive`（含 `pow_a11y`） | 约 10 分钟 | SDK 静默续期（§3.1） |

**验证顺序**（`POST /__mg/c`，所有类型相同）：

1. 限速（按 ipp / 会话）。
2. `Early-Data: 1` → `425`（§4.3）。
3. 请求体：带 `Content-Encoding` 一律拒绝（不解压）；≤ 8 KB；schema。
4. 打开 C（AEAD；`aad` 校验 host / type / kid）。
5. `exp`；最短时间窗（`interactive` 的计算见 [09](09-interactive-challenge.md) §11.1）。
6. `provider_id ∈ C.providers`（仅 `interactive`，防降级）。
7. 绑定（§5）。
8. 会话密钥签名（Phase 2 起）：覆盖 `hash(C)`、Provider 载荷哈希、遥测哈希、PoW 解、`ret` 哈希与 `client_ts`。
9. PoW。
10. 消费 nonce：`SET mg:n:{site}:{nonce} NX EX ttl`，`ttl ≥ exp − now + 60 s`。**必须在任何外部 Provider 调用之前**，保证并发重复提交只有一个进入 Provider 校验。
11. `provider.verify`（仅需要出站校验的 Provider，有截止时间）。
12. 评分（交互评分 + 挑战前风险）→ 签发凭证，或统一失败（§9）。

- nonce 消费后 Provider 校验失败或超时：换新 C 重来，不重试同一 C。
- nonce 集合：只有一个 Edge 进程时可用进程内 LRU，多台 Edge 必须用 Valkey。Valkey 不可用时 `critical` 路由 fail-closed（不签发凭证，返回"稍后再试"），其他路由放行并标记、不发交互式 Challenge（[01 §8](01-architecture.md#8-部署与高可用)）。
- 失败计数按会话与 IP 前缀累计，指数退避；无感 / PoW 失败升级为交互式。
- 失败响应统一，不返回原因，避免成为调试"预言机"；原因只进内部 reason code 与日志（[09](09-interactive-challenge.md) §12.4）。

### 4.2 PoW

- SHA-256 hashcash（WebCrypto，附纯 JS 回退；Rust 侧校验开销可忽略）。
- 难度由风险分段与设备类别决定，中位设备耗时：低风险 0，中风险 ≤ 0.3 s，高风险 ≤ 1.5 s；`pow_a11y` 中位 3–8 s。交互式把 PoW 放在按住期间的 Web Worker 中（[09](09-interactive-challenge.md) §2.1）。
- 受攻击模式下整体提高难度。内存困难 / 抗 GPU PoW 放到 Phase 5（[09](09-interactive-challenge.md) §14）。
- 定位是成本杠杆，不是识别手段。

### 4.3 Early-Data（0-RTT）

首选关闭 0-RTT：Cloudflare 侧保持默认关闭（其行为与 `mgctl cf audit` 检查项见 [08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)），`direct_tls` 下 Edge 监听器也不启用。若开启，Edge 按下表处理带 `Early-Data: 1` 的请求。

| 请求 | 处理 |
|---|---|
| `/__mg/*` 状态变更端点：`/__mg/c`、`/__mg/c/renew`、`/__mg/r`、`/__mg/m/*` | 带 `Early-Data: 1` 一律返回 `425` |
| 其他请求 | 视为可重放：不签发 / 刷新凭证，不消费 nonce，不写一次性状态；`critical` 路由返回 `425` |

Cloudflare 是否把源站的 `425` 回传浏览器、浏览器是否自动重试，需实测；在此之前以"保持关闭"为主。

### 4.4 缓存

Free / Pro / Business 下 Cloudflare 的 Origin Cache Control 始终开启，`no-cache` / `max-age=0` 仍会被缓存，所以只用 `no-store`。

| 响应 | 头 |
|---|---|
| `GET /__mg/s/{build}.js`（内容哈希构建） | `Cache-Control: public, max-age=31536000, immutable`，允许 Cloudflare 边缘缓存 |
| 其他所有 `/__mg/*` | `Cache-Control: no-store, private` |
| Challenge 页面与 JSON Challenge | `403`（限速 / 超限为 `429`），不用 200；`no-store, private`；HTML 另加 `X-Robots-Tag: noindex` |

Cloudflare 侧另需一条放在**最后**的 `/__mg/` Bypass Cache Rule（`/__mg/s/` 除外），并禁止"Eligible for cache + 覆盖 Edge TTL"的规则覆盖可能返回 Challenge 的路径；表达式与 `mgctl cf audit` 检查项见 [08 §2.6](08-upstream-and-cloudflare.md#26-缓存)。

## 5. 短期访问凭证

**格式**：PASETO v4.local（pasetors 0.8），对客户端不透明，不泄露分数与分类；Edge 按站点持有密钥，按 `kid` 轮换。源站需要独立验证时，另签一枚只含最少字段的 v4.public（Ed25519）凭证。

```json
{
  "v": 1, "kid": "s1-2026-09",
  "sid": "site", "env": "production",
  "sub": "pseudonymous session id",
  "lvl": "invisible | pow | interactive | interactive_a11y | interactive_ext:{provider}",
  "iat": 1790000000, "exp": 1790001800,
  "cnf": { "jkt": "JWK thumbprint of the SDK session key (Phase 2+)" },
  "bind": {
    "uah": "hash(ua family + major)",
    "ipp": "hash(ip /24 | /48)",
    "ctp": "hash(tls_version, cipher, ciphers_sha1, hello_len bucket); cloudflare only, shadow",
    "tfp": "hash(ja4); direct_tls only, after the JA4 spike"
  },
  "rb": "risk band at issuance",
  "jti": "unique id"
}
```

| 项目 | 设计 |
|---|---|
| `lvl` | `invisible`、`pow`、`interactive`（`self_hold`）、`interactive_a11y`（`pow_a11y`）、`interactive_ext:{provider}`（`turnstile` / `tencent` / `aliyun_v2`）；`attested` 保留给后期移动端。三种交互级的人类证据封顶相同（[03](03-risk-scoring.md) §4.1 的 −0.8） |
| 有效期 | `invisible` / `pow` 15–30 分钟；`interactive`、`interactive_ext:*` 30 分钟；`interactive_a11y` 15 分钟且配额更严；`attested`（后期）1–24 小时，配合每请求签名；静默刷新可延续到站点配置的会话上限；`critical` 路由可要求最低级别与最大凭证年龄 |
| 级别要求 | "交互级"同时包含 `interactive`、`interactive_a11y`、`interactive_ext:*`，不得把无障碍路径排除在外 |
| 存储 | Web：`__Host-mg_clr`，`HttpOnly; Secure; SameSite=Lax; Path=/`；移动端（后期）：`MG-Clearance` 请求头 |
| 刷新 | SDK 在寿命 80% 时调用 `POST /__mg/r`，附持有证明与最新遥测；服务端重新评分，风险升高则拒绝刷新并要求 Challenge |
| 签发配额 | 按 ipp / ASN 限制凭证签发数，监控解题时间分布，对抗人工代解中继的批量收割（[09](09-interactive-challenge.md) §13） |
| 吊销 | 以短寿命为主；紧急吊销按 `sub` / `jti` 写入吊销集 `mg:rev:{site}`（成员随凭证寿命过期），Edge 本地用布隆过滤器加速（[02](02-data-flow.md)） |

**绑定策略**（C 的 `bind` 与凭证同口径）

| 绑定项 | 适用 profile | 阶段 | 强度 | 不一致时 |
|---|---|---|---|---|
| `uah`（UA 家族 + 主版本） | 全部 | Phase 1 | 硬 | 重新 Challenge |
| `ipp`（IP 前缀，v4 /24、v6 /48） | 全部 | Phase 1 | 软 | 同 ASN 内变化 → 风险信号；跨 ASN / 国家 → 重新 Challenge |
| `cnf.jkt`（SDK 会话密钥） | 全部 | Phase 2 起 | 硬 | 持有证明失败即拒绝并重新 Challenge |
| `ctp`（`x-mg-cf-tls-*` 的 TLS 版本、cipher、套件哈希、ClientHello 长度分桶） | 仅 `cloudflare` | Phase 1 起，仅 shadow | 只记录；稳定性 ≥ 99% 后才可转为软绑定（[03](03-risk-scoring.md) §3.4） | shadow 期只记录 |
| `tfp`（JA4 哈希） | 仅 `direct_tls` | JA4 预研成功后 | 硬 | 重新无感 Challenge |

- `cloudflare` profile 下 Edge 看到的是 Cloudflare 自己的回源 TLS，访客 JA4 只有 Enterprise Bot Management 提供（超出预算），因此不启用 `tfp`。
- `ctp` 不含扩展哈希：其排序与 GREASE 处理未文档化，未经实测不得用于绑定或高权重。
- `ipp` 依赖可信客户端 IP：只取认证上游的 `CF-Connecting-IP`，从不用 `X-Forwarded-For[0]`（[08](08-upstream-and-cloudflare.md) §2.2）。

**可选：Cloudflare 放行 Cookie**（Pro 及以上）：另签 `__Host-mg_cfp`（MessageMAC 格式、独立密钥），供 Cloudflare 规则校验后跳过其通用 Bot 功能、避免双重挑战。它不是 MorphGate 凭证，也不是人类证据；规则写法及限速是否可跳过见 [08](08-upstream-and-cloudflare.md) §2.7、§2.9。

## 6. 持有证明、防重放与限速

### 6.1 请求级持有证明（参考 RFC 9449 DPoP）

Phase 2 起，SDK 在 Challenge 时生成会话密钥（Web：WebCrypto ECDSA P-256，non-extractable，存 IndexedDB；移动端后期用 Secure Enclave / Keystore），凭证以 `cnf.jkt` 绑定该密钥。受保护请求携带：

```
MG-Proof: <compact JWS, ES256, header.jwk = session public key>
  payload: { htm, htu, iat, jti, ath = hash(clearance), bh = hash(body) }   // bh: critical routes only
```

- **校验**：签名有效；`thumbprint(jwk) == cnf.jkt`；`htm` / `htu` 与请求一致；`|now − iat| ≤ 30 s`；`ath` 匹配；`bh` 匹配请求体；`jti` 未出现过（`SET mg:jti:{site}:{jkt}:{jti} NX EX 60`）。
- **服务端 nonce**：最高风险操作要求带上前一个响应下发的 `MG-Nonce`，防止预先批量生成证明。
- `critical` 路由强制，其他路由可选。它证明"请求来自持有该密钥的客户端且未被重放"，**不证明是人**。
- 所有一次性状态以会话 / 密钥 / nonce 为键，**不以下游连接为键**：Cloudflare 的回源连接被多个访客复用。

### 6.2 其他防重放点

- Challenge nonce 一次性使用（§4.1）；续期时旧 nonce 同样被消费（§3.1）。
- 第三方 Provider token：哈希写入 `mg:rp:*` 重放集合，TTL = token 寿命（[09](09-interactive-challenge.md) §12.1）。
- `Early-Data: 1` 的请求视为可重放（§4.3）。
- Agent 签名：`created` / `expires` 窗口 + `nonce` 重放缓存（[05](05-ai-agent-policy.md)）。
- 凭证 `jti` 与吊销集。

### 6.3 限速

| 设计点 | 方案 |
|---|---|
| 维度 | ip、ip 前缀（v4 /24、v6 /48 或 /56）、asn、会话、设备、账号（从请求体字段或源站回传头提取并哈希）、Agent、指纹簇（JA4 + UA）、路由，以及组合键 |
| 算法 | GCRA（单 key、O(1)、Valkey Lua 原子执行）；需要"每窗口 N 次"语义时用滑动窗口；昂贵接口用带租约的并发上限 |
| 两级 | 本地内存限速挡住明显洪泛；精确的低频限额（如每账号 15 分钟 5 次登录）走 Valkey |
| 高基数 | Count-Min Sketch / heavy hitter 找出头部来源，再提升为精确跟踪 |
| 自适应 | 按路由维护周内时段基线（EWMA），超过 k·σ 告警或收紧；受攻击模式整体收紧 |
| 超限动作 | 信号 / Challenge / 429 / 阻断；每个限速器可先 log-only |

```yaml
rate_limits:
  - id: login-per-account
    match: { route: login }
    key: [account]              # from JSON body field "username", hashed
    algorithm: gcra
    rate: 5/15m
    burst: 3
    on_exceed: { action: challenge, type: interactive }
  - id: api-per-prefix
    match: { channel: api }
    key: [ip_prefix]
    rate: 600/1m
    on_exceed: { action: signal, weight: 1.5 }
```

- 指纹簇在 `cloudflare` profile 下没有 JA4，以 UA 家族为主，`ctp` 只在 shadow 中参与。
- Challenge 端点自身受限：按 ipp / 会话限制 Challenge 签发与 `/__mg/c`、`/__mg/c/renew` 提交；按 ipp / ASN 限制凭证签发（§5）。交互式的具体限速器见 [09](09-interactive-challenge.md) §12.3。
- **Cloudflare 边缘泄压**：Free 区唯一一条限速规则可用于在边缘挡 `POST /__mg/` 洪泛，阈值远高于 Edge 限额，精确限额仍由 Edge 负责。使用这条规则的 zone，`/__mg/` 的 Skip 规则**不得**跳过 `http_ratelimit`；规则约束见 [08 §2.7](08-upstream-and-cloudflare.md#27-与-cloudflare-自带功能共存)。

## 7. 客户端信号采集（Web / Mobile SDK）

**原则**

- Web SDK 优先（Phase 2 交付）；Mobile SDK 后期 / 按需。
- 最小必要：端上计算摘要，不上传渲染图像、按键内容、表单值、原始轨迹。
- 高熵指纹（画布 / 音频渲染哈希等）默认关闭，仅在所有者开启并完成合规评审后作为一致性特征，短期保留，不做跨站追踪（[06](06-policy-console-observability.md#7-隐私与合规)）。
- 性能：核心包 gzip 后 ≤ 30 KB，行为模块懒加载，空闲时采集，不阻塞首屏。
- 第一方：SDK、按住组件与 PoW Worker 都从本站 `/__mg/` 下发，不依赖第三方域名、字体或统计脚本，保证大陆访客可用。
- 稳健：SDK 异常不影响页面功能；SDK 失败时相关 CLIENT 信号记为 `ABSENT`（[03](03-risk-scoring.md) §3.1）。

**Web SDK 模块**

| 模块 | 内容 |
|---|---|
| env | UA 与 Client Hints、语言、时区、屏幕与视口、硬件并发、触控能力、图形栈家族摘要、存储可用性 |
| automation | 标准 WebDriver 标志、无头环境特征、自动化注入痕迹、关键原生函数完整性 |
| behavior | 指针 / 键入 / 滚动 / 触控的统计摘要，按页面批量上报（`POST /__mg/t`） |
| challenge | 渲染服务端选定的 Provider、Web Worker 中运行 PoW、量化交互遥测、C 续期（[09](09-interactive-challenge.md)） |
| crypto | 会话密钥、提交签名、请求级持有证明 |
| transport | 可选的 fetch / XHR 包装：为受保护路由附加 `MG-Proof`；处理 `mg_challenge` / `mg_challenge_failed` 并重试；识别 `cf-mitigated: challenge` |

**在 Cloudflare 之后**（配置细节见 [08](08-upstream-and-cloudflare.md) §2.7–§2.8）

- 注入的 SDK 标签带 `data-cfasync="false"`（放在 `src` 之前）与 CSP nonce，例如 `<script data-cfasync="false" src="/__mg/s/{build}.js" nonce="..."></script>`，避免 Rocket Loader 改写；或直接关闭 Rocket Loader。
- 对 `/__mg/*` 或受保护 fetch 收到 `cf-mitigated: challenge`：视为"上游挑战"，不算 MorphGate 失败，本地记录后顶层重载，随下一批遥测上报，计入 `mg_double_challenge_total`。
- Cookie 类信号忽略 Cloudflare 自有 Cookie（`__cf_bm`、`cf_clearance`、`_cfuvid` 等）；`cf_clearance` 永不作为 MorphGate 证据。
- Turnstile 只在选用它的页面按官方方式加载（[09](09-interactive-challenge.md) §8.2）。

一致性判断放在服务端，SDK 只负责采集：属性之间，以及与服务端观测到的 UA、TLS（`direct_tls` 为 JA4 家族；`cloudflare` 为 `EDGE_TLS` 族，低权重、shadow）、IP 地理（含 `cf-timezone`，弱信号）之间。

**Mobile SDK 模块（后期 / 按需）**

| 模块 | 内容 |
|---|---|
| attestation | iOS App Attest；Android Play Integrity（有 GMS）/ Key Attestation；鸿蒙待调研 |
| app integrity | 包签名校验、调试器 / 注入 / Hook 检测、Root / 越狱检测、模拟器检测 |
| keys | Secure Enclave / Android Keystore（优先 StrongBox）中的不可导出密钥 |
| device | 系统版本、机型、传感器可用性摘要；只用应用范围内的随机 ID，不采集 IMEI 等硬件标识 |
| transport | OkHttp Interceptor / URLSession 封装：附加凭证与请求签名，处理 Challenge |

端上完整性检测会被有能力的对手绕过，定位是成本抬升；以服务端验证的设备证明为主。

## 8. Morph 动态变形

目的：让客户端逻辑和部分请求特征不再静态不变，抬高针对本站编写和维护自动化脚本的成本。它补充而不替代服务端验证。

| 能力 | 做法 | 阶段 |
|---|---|---|
| SDK 多态构建 | 按 epoch 生成多个变体（含 `self_hold` 组件）：标识符随机化、控制流平坦化、字符串加密、模块重排、提交载荷编码随机化；服务端按 build ID 解码；旧构建保留宽限期 | Phase 5 |
| Challenge VM | Challenge 逻辑编译为自定义字节码，由 SDK 内的小型解释器执行；每个构建随机化操作码映射；结果与 nonce 绑定，服务端重算验证 | Phase 5 后期 |
| 动态表单字段 | 对登录 / 注册等敏感表单，由 Edge 按会话重命名字段并插入蜜罐字段，转发源站前映射回原名 | Phase 5 |
| 动态接口令牌 | `critical` 接口必须携带基于会话密钥与服务端 nonce 的一次性证明（§6.1）；可选按会话为高价值接口生成路径别名 | 证明：Phase 2；别名：Phase 5 可选 |

**取舍**

- 混淆不是安全边界，所有判定都在服务端验证。
- 静态 SDK 按 epoch 轮换而不是每请求变化，保证 Cloudflare 边缘与浏览器缓存有效；按会话变化只用于本就不可缓存的敏感页面。
- 字段重命名保留 `autocomplete`、`id`、`label` 关联，用主流密码管理器与辅助技术做回归。
- 注入脚本使用 CSP nonce / hash；多态构建与 SRI 冲突时在注入时计算 integrity。
- 第三方 Provider 脚本（含 Turnstile api.js）按官方方式直连加载，**永远不进入 Morph 构建**或 `/__mg/` 路径。
- 可调试性：每个 build ID 保存映射与私有 source map；支持按站点临时关闭 Morph。

## 9. 协议约定

本节是 `/__mg/*` 与 Challenge 响应的唯一口径，[09](09-interactive-challenge.md) 引用本节。

| 场景 | 响应 |
|---|---|
| HTML 导航需要 Challenge | `403` + Challenge 页面，`no-store, private`，`X-Robots-Tag: noindex`；脚本带 CSP nonce 与 `data-cfasync="false"` |
| API / XHR 需要 Challenge | `403` + `{"error":"mg_challenge","type":"...","challenge":"...","retry":true}`，响应头 `MG-Challenge`，`no-store, private` |
| 请求体 | `/__mg/*` 拒绝任何带 `Content-Encoding` 的请求体（不解压）；上限 `/__mg/c`、`/__mg/c/renew` 8 KB，`/__mg/t`、`/__mg/r` 16 KB（[02](02-data-flow.md) §3）；不合规时 `/__mg/c` 按 Challenge 失败处理，其余端点直接拒绝 |
| `POST /__mg/c` 成功 | 页面导航提交：`303` → 已校验的同站 `ret`；fetch 提交：`200` + `{"ok":true}`；均带 `Set-Cookie: __Host-mg_clr` 与 `Cache-Control: no-store, private` |
| Challenge 失败（任何原因） | `403` + `{"error":"mg_challenge_failed","retry":true,"request_id":"...","challenge":"<new C>"}`；HTML 为通用失败页（中性文字、帮助链接、request_id）；不区分原因 |
| 交互式失败超过 M 次（初值 5） | `429` + `Retry-After` |
| `POST /__mg/c/renew` | `200` + `{"challenge":"<new C>","exp":...}`，`no-store, private`，旧 C 作废；不可续期时返回 `mg_challenge_failed`（附新 C，计入签发配额，不计入失败次数） |
| `POST /__mg/r` 凭证刷新 | 成功 `200` + `Set-Cookie`；风险升高则 `403` + `mg_challenge` |
| 状态变更端点带 `Early-Data: 1` | `425`（§4.3） |
| 需要持有证明或服务端 nonce | `403` + `{"error":"mg_proof_required"}`，响应头 `MG-Nonce` |
| 限速 | `429` + `Retry-After` |
| 阻断 | `403` 通用页面或 `{"error":"mg_blocked","request_id":"..."}` |
| 授权 Agent 超出范围 | `403` + `{"error":"agent_scope_denied","request_id":"..."}` |
| 上游 Cloudflare 挑战（非 MorphGate 响应） | Cloudflare 挑战页，带 `cf-mitigated: challenge`；SDK 按 §7 处理 |

所有 `/__mg/*` 响应（内容哈希的 SDK 构建除外）与所有 Challenge 响应都带 `Cache-Control: no-store, private`（§4.4）。

## 10. 参考

- Cloudflare Cache-Control 与 Origin Cache Control：https://developers.cloudflare.com/cache/concepts/cache-control/
- Cloudflare Cache Rules 顺序与设置：https://developers.cloudflare.com/cache/how-to/cache-rules/order/ 、https://developers.cloudflare.com/cache/how-to/cache-rules/settings/
- Cloudflare 0-RTT：https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/
- Rocket Loader 排除脚本：https://developers.cloudflare.com/speed/optimization/content/rocket-loader/ignore-javascripts/
- 识别 Cloudflare 挑战响应（`cf-mitigated`）：https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
- Cloudflare 限速规则：https://developers.cloudflare.com/waf/rate-limiting-rules/
- JA4 字段（Enterprise Bot Management）：https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.ja4/
- ALTCHA CVE-2025-68113 公告：https://github.com/altcha-org/altcha-lib/security/advisories/GHSA-6gvq-jcmp-8959
- WCAG 2.2 SC 2.2.1 Timing Adjustable：https://www.w3.org/WAI/WCAG22/Understanding/timing-adjustable.html
- pasetors：https://github.com/brycx/pasetors
