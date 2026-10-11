# Phase 2 实现规格：Web SDK 与自研交互式 Challenge

**结论**：Phase 2 拆成 12 个工作包（WP），分三个阶段。

- **阶段 1（7 个 WP，按文件互不重叠，可以并行）**：
  - mg-core 的 Provider 实现、Provider 选择与交互评分（R4）；
  - mg-challenge 的交互式 C、会话密钥与持有证明原语、凭证 v2（R5）；
  - mg-edge-core 的状态层扩展（C5），以及出站 HTTP 与 Turnstile 客户端（C6）；
  - Go 侧的站点 YAML、配置包与 Turnstile 命令（G4）；
  - 近线 worker（N1）；
  - Web SDK v1（W2）。
- **阶段 2（3 个 WP，按顺序合入 mg-edge）**：交互式挑战与续期（E2a）；持有证明、凭证刷新、遥测与观测（E2b）；Turnstile（E2c）。
- **阶段 3**：Validation Lab 与端到端（L2）；设计文档勘误与威胁模型 v1（D2）。

本文写死 Phase 2 新增或改动的全部跨组件契约。实现者按本文编码，不需要再协商；需要改契约时先改本文。这些契约包括：
- 密封 C 的新字段与寿命、PoW v2；
- 会话密钥与提交签名、`MG-Proof`、凭证 v2；
- 端点 `/__mg/c` v2、`/__mg/c/renew`、`/__mg/r`、`/__mg/t`，以及挑战页模板 v2；
- 配置包与站点 YAML 的新字段、`edge.toml` 的新键；
- Valkey 键、Lua 脚本与 ACL；`mg:ev` v2；
- 近线 worker 的输入与输出；
- 事件与指标。

- **设计依据**：[07 Phase 2](../07-roadmap.md)、[04](../04-challenge-and-tokens.md)、[09](../09-interactive-challenge.md)、[08 §2.8](../08-upstream-and-cloudflare.md)、[02](../02-data-flow.md)、[03](../03-risk-scoring.md)、[06](../06-policy-console-observability.md)、[ADR-0005](../adr/0005-token-and-sealed-challenge-format.md)、[ADR-0008](../adr/0008-interactive-challenge-self-built.md)。设计文档说"是什么、为什么"，本文说"Phase 2 具体怎么做"。两者冲突时，Phase 2 实现以本文为准；WP-D2 负责把设计文档改到一致，§0.3 列出了全部偏离。
- **与 Phase 1 规格的关系**：[Phase 1 规格](phase1-spec.md)冻结，其契约在本文没有重述的地方继续有效。本文改动 Phase 1 契约时，在 §0.3 的决定里写明所改的 Phase 1 章节，并在本文中完整重述新契约。决定与裁决的编号接续 Phase 1：决定从 D-38 起，裁决从 I-43 起。代码注释与测试直接引用编号，所以不重新从 1 开始。
- **规范用语**：同 Phase 1。"必须 / 不得"是硬性要求；"应"是默认做法，偏离时在该 WP 的 PR 描述里写明理由；"可"是可选。
- **贯穿全文的约束**。Phase 1 的三条照旧：
  - 客户端 IP 未知时，Edge 从不比 IP 已知时更宽松，新端点同样适用；
  - 配置或信任出错时不静默放开；
  - 攻击者可控的输入大小不能让规则失效。

  Phase 2 新增：
  - **外部 Provider 绝不 fail-open**。
  - **中国大陆访客与国家未知的访客从不选用 Turnstile**。
  - **交互式通过只是封顶的人类证据**（03 §4.1 的 −0.8），不是安全边界。
  - **改变决策、挑战或凭证要求的行为，都由配置包或 `edge.toml` 开关控制**。`schema_version = 1` 的配置包让 Edge 严格按 Phase 1 运行（D-66），所以升级二进制本身不改变线上的决策与挑战。以下改动随新二进制无条件生效，它们不改变决策：D-62 的脱敏、关闭时的事件刷写与 `ruc` 事件；`mg:ev` v2；JSON 应答中的 `"v": 2`；`/__mg/s/mg.js` 别名。
  - **只做防御**：测试与 CI 不访问任何外部服务，Turnstile 一律用回环 mock；Validation Lab 不含任何求解逻辑。
- 逐轮评审的处置见 §23。

## 集成者裁决（优先于正文）

尚无。实现中的裁决从 I-43 起编号，按 Phase 1 的格式追加在此表，覆盖正文中对应的条目；WP-D2 把它们同步到设计文档。

| 编号 | 裁决 | 覆盖 |
|---|---|---|

## 0. 范围、决定与待落地文件

### 0.1 范围

| 在范围内（代码与测试） | 不在范围内 |
|---|---|
| Edge：交互式挑战 `self_hold` 与 `pow_a11y`（密封 C、挑战页模板 v2 与 JSON 挑战、按住与 PoW 的服务端校验、交互评分 shadow）；`/__mg/c` v2（会话密钥签名、Provider 载荷、交互遥测）；`/__mg/c/renew`（含首次绑定密钥）；失败升级；`/__mg/v` 签发交互式（D-58）；路由 `proof: required` 的 `MG-Proof` 校验与 `jti` 防重放；`min_level`（D-64）；`/__mg/r` 凭证静默刷新；`/__mg/t` 遥测；`/__mg/s/mg.js` 稳定别名；Turnstile Provider（可选，经 `OutboundHttp`）；转发前删除 MorphGate Cookie（D-61）；本机应急开关（D-60）；I-35 复审；`mg:ev` v2；事件与指标 | Edge 侧 HTML 注入（D-39）；页内覆盖层（D-57）；`MG-Nonce`、`step_up`、`bh`（D-55）；吊销集与 pub/sub（D-54，Phase 3）；站点账号替代路径（D-56）；大陆 Provider `tencent` / `aliyun_v2`（Phase 4）；双 Provider 升级、学习型交互模型、内存困难 PoW、Privacy Pass（09 §14）；按设备类别定难度；`mg:w:*` 与按连接的特征；`bind.tfp`；`bind.ctp` 转为软绑定（仍只 shadow）；每日访问记录归档（§22） |
| mg-core：`self_hold` / `pow_a11y` 的 Provider 实现、Provider 选择（纯函数）、交互评分（硬检查 + 软特征）、失败升级函数、`min_level`、`identity.proof` 的可用性、刷新判定 | Decision Core 在每个请求上使用 SDK 遥测（CLIENT / BEHAVIOR 族只经挑战提交与近线 verdict 进入评分，§5.6） |
| mg-challenge：交互式 C 的字段与寿命、epoch 窗口、`ui_seed` 派生、PoW v2、JWK 与指纹、ES256 验签、提交与续期签名、`MG-Proof`、凭证 v2、Turnstile `cData` 与幂等键 | — |
| mg-edge-core：Valkey 键与 Lua 脚本 v2、`jti` / Provider token 重放集合（含本地模式）、`mg:ev` v2 写入、出站 HTTP 与 siteverify 客户端、回环 mock siteverify、遥测 schema 单一实现 | — |
| Go：站点 YAML 新字段、配置包构建与校验、`mgctl turnstile`、近线 worker `mg-nearline` | mg-control 服务的新功能（Phase 3）；`mgctl cf apply` |
| Web SDK v1：会话密钥、`MG-Proof`、fetch 包装（就地求解、刷新、`cf-mitigated`）、交互式界面（按住、键盘、切换、`pow_a11y`）、续期、Turnstile 加载、遥测、zh-CN / en、挑战页模板 v2、npm provenance | 高熵指纹（画布、音频等）；Morph 构建 |
| Validation Lab：交互式挑战的否定性场景、CN / 未知国家从不下发 Turnstile、近线在回环上的端到端 | 任何求解逻辑；面向非白名单目标的流量；负载生成 |

**所有者操作**（代码之外，见 §19）：
- Phase 1 验收收尾；
- 单机部署改为本机 Valkey；
- 站点模板加入 SDK 标签；
- 分路由启用 `proof` 与交互式；
- 辅助技术实测；
- 隐私说明更新；
- 可选：Turnstile widget 与 secret。

### 0.2 WP 编号

| 编号 | 名称 | 阶段 |
|---|---|---|
| WP-R4 | mg-core：`self_hold` / `pow_a11y` Provider、Provider 选择、交互评分、失败升级、`min_level` 与矩阵、`identity.proof` 字段与可用性、刷新判定、`ChallengeResult` / `Identity` 新字段 | 1 |
| WP-R5 | mg-challenge：交互式 C（字段、寿命、epoch 窗口、`ui_seed`）、PoW v2、JWK / 指纹 / ES256、提交与续期签名、`MG-Proof`、凭证 v2 与 `lat`、`cData` 与幂等键、`testdata/phase2` KAT | 1 |
| WP-C5 | mg-edge-core `state`、`events` 与 `bundle`：`mg_nonce_issue` v2、`jti` 与 token 重放（Valkey 与本地）、`mg:ev` v2、遥测 schema 单一实现、关闭时的事件刷写、配置包新字段的校验 | 1 |
| WP-C6 | mg-edge-core `outbound`：`OutboundHttp` 实现、siteverify 客户端与错误映射、熔断与健康状态、回环 mock siteverify（testkit） | 1 |
| WP-G4 | Go：站点 YAML 与配置包新字段、构建与校验、`mgctl turnstile`、密钥文件 `mg-turnstile-keys`、审计条目 | 1 |
| WP-N1 | Go：近线 worker `mg-nearline`（消费 `mg:ev` v2、检测器 v1、verdict 写入、指标、systemd 单元） | 1 |
| WP-W2 | Web SDK v1：会话密钥、`MG-Proof`、fetch 包装、交互式界面与无障碍、续期与刷新、Turnstile 加载、遥测、模板 v2、构建与发布 | 1 |
| WP-E2a | mg-edge 交互式：配置转换、交互式签发与挑战页 v2、`/__mg/c` v2、`/__mg/c/renew`、失败升级、`/__mg/v`、SDK 目录 v2 与 `/__mg/s/mg.js` | 2（第 1 个） |
| WP-E2b | mg-edge 证明与观测：`MG-Proof` 与 `jti`、`min_level`、`/__mg/r`、`/__mg/t`、Cookie 删除、`force_monitor`、`mg:ev` v2 接线、I-35 复审、事件与指标、ACL | 2（第 2 个） |
| WP-E2c | mg-edge Turnstile：Provider 接线、国家判定、CSP、token 重放、熔断与自动禁用、`edge.toml` 凭证 | 2（第 3 个） |
| WP-L2 | Validation Lab Phase 2 场景、近线端到端、`lab-e2e` 扩展 | 3 |
| WP-D2 | 设计文档勘误、威胁模型 v1（含 Phase 2 组件的 STRIDE）、ADR-0011、隐私说明模板、CLAUDE.md / README | 3 |

本文中"WP-E2"泛指 E2a–E2c。

### 0.3 决定与偏离

WP-D2 把"需改设计文档"一栏为"是"的条目写回设计文档或 ADR。改动 Phase 1 契约的条目在"决定"一栏写明所改章节。

| # | 决定 | 理由 | 需改设计文档 |
|---|---|---|---|
| D-38 | **状态后端**：Phase 2 的共享与一次性状态以 Valkey 为准，包括近线的输入 `mg:ev` 与输出 `mg:v:*`、`MG-Proof` 的 `jti`、Turnstile token 重放集合、跨重启仍有效的交互式 C nonce。单机形态推荐本机 Valkey：`mode = "valkey"`、`local_replay_authoritative = true`、配置包 `events.stream = true`。`mode = "local"` 继续支持，按以下方式降级：没有近线与 verdict；`jti` 与 token 重放用进程内集合（D-35 规则：不逐出，溢出即"不可用"）；本进程启动前签发的交互式 C 按"重放存储不可用"处理：续期返回 429；提交按 I-30（`fail_closed` 路由 429，其他路由签发带 `ruc` 的凭证）；SDK 遇到 429 时等待 `Retry-After` 后重新加载页面，取得新 C（§7.10、§12.6） | local 模式下近线既没有输入也没有效果；10 分钟的交互式 C 在每次重启后都会失效；01 §8 本来就推荐本机 Valkey | 是（01 §8 单机形态、02 §4） |
| D-39 | **不做 Edge 侧 HTML 注入**。站点在自己的模板中、自身脚本之前加入 `<script data-cfasync="false" src="/__mg/s/mg.js" defer></script>`。Edge 新增稳定别名 `/__mg/s/mg.js`：内容与当前构建字节相同，`Cache-Control: public, max-age=300`，带 `ETag`；内容哈希的文件名照旧提供。manifest 的 `files` 不得包含 `mg.js`（Edge 拒绝该目录）。站点须做到三点（§19 第 3b 步）：CSP 允许同源脚本与 `worker-src 'self'`（或经 `script-src` 回退），否则就地求解退回主线程；Service Worker 不处理 `/__mg/` 下的任何请求；站点代码不假设 `window.MorphGate` 存在（§12.1）。别名可能被缓存，页面脚本与它启动的 Worker 可能来自不同构建，所以 Worker 先报告自己的 SDK 版本，不一致时按 §12.6 处理 | 改写 HTML 要先解压源站响应、改写源站 CSP，而且每个响应都多一次流式解析，挤占附加延迟预算；模板由所有者自己控制。改 Phase 1 规格 §0.1 的"SDK 注入源站 HTML（Phase 2）" | 是（02 §8、04 §7、01 §9） |
| D-40 | **`MG-Proof` 规范**（§6.7、§9.1）：紧凑 JWS，`ES256`，头为 `{"alg":"ES256","typ":"mg-proof+jwt","jwk":{…}}`，载荷只有 `htm`、`htu`、`iat`、`jti`。**不含** `ath`：凭证 Cookie 是 HttpOnly，页面脚本无法计算它的哈希。**不含** `bh`：它要求 Edge 在决策前缓冲请求体。**不含**服务端 nonce（D-55）。路由为 `proof: required` 时，只有**可豁免的导航**不要求证明：`http.navigation` 为真、方法为 GET / HEAD、且所有命中路由的 channel 都是 `web`。其余请求都必须带有效证明，包括声称是导航的 POST 等请求，以及 `api` / `mobile` 路由上的一切请求 | 04 §6.1 的原稿在浏览器中无法实现。`Sec-Fetch-*` 与 `Accept` 由客户端控制，所以豁免只能限于安全方法：证明约束 API 路由与非安全方法；GET / HEAD 导航上的凭证只受 `uah` / `ipp` 绑定保护 | 是（04 §5、§6.1、§9；02 §7） |
| D-41 | **首次挑战的密钥绑定**（bind-on-first-use）：导航得到的交互式 C 起初不绑定密钥；SDK 在用户操作之前先调用 `/__mg/c/renew`，把 C 绑定到自己的会话密钥（新 C 带 `bind.jkt`，计一次续期）。非交互式 C 只在触发请求带有效 `MG-Proof` 时绑定。失败或续期附带的新 C 同样先绑定（§12.6）。验收项"跨客户端提交 100% 拒绝"只对已绑定的 C 声明；未绑定的 C 在 UA 家族不同、或 /24 与 ASN 都不同时拒绝，同一 ASN 内换 /24 只记 `ic.bind_ipp_soft`（Phase 1 的软绑定，已知边界） | 否则同一 /24、同一浏览器版本的两个客户端可以互换 C。多出的一次往返发生在页面加载时，不占用户的按住时间 | 是（09 §4.2、§15；07 Phase 2 验收措辞） |
| D-42 | **交互式 C 的寿命固定为 600 s**；SDK 在约 80%（480 s）且用户未操作时续期，一条续期链至多 6 次，由新的密封字段 `renew_no` 计数。接受的 epoch 窗口改为：日界后 605 s 内另接受上一个 epoch，所有类型共用。`seal` 的寿命上限按类型：交互式 600 s，其他 120 s。改 Phase 1 规格 §6.1、§6.2 与 I-18；新的已知答案向量在 `testdata/phase2/kat.json`，Phase 1 的 `accepted_epochs` 向量作废 | 09 §4.3、04 §3.1。Phase 1 的 120 s 上限与 125 s 窗口硬编码在 mg-challenge 中 | 是（09 §4.1、ADR-0005 勘误） |
| D-43 | **PoW**：`invisible` / `pow` 仍用 `sha256-hashcash-v1`。交互式 C 用新算法 `sha256-hashcash-v2`：k 个子题（1–8），`digest_i = SHA-256("mg-pow-v2" ‖ 0x00 ‖ SHA-256(C) ‖ u8(i) ‖ u64be(counter_i))`，每个子题的前导零位数 ≥ 难度。`self_hold` 与 `pow_a11y` 的难度分别密封在 C 中（`pow.difficulty`、`pow.a11y_difficulty`）。09 §2.1 的 `SHA-256(C.nonce, pow_salt, counter)` 作废 | SDK 不解析 C，拿不到 nonce。子题降低耗时方差；`pow_a11y` 没有倒计时，长尾等待更难接受 | 是（09 §2.1、04 §4.2） |
| D-44 | **交互式挑战的明文参数 `ix` 与 C 一起下发**：挑战页模板 v2 增加占位符 `{{ix}}`（JSON，按属性值转义），JSON 挑战增加字段 `ix`。SDK 只用它渲染界面；按住时长、按钮偏移与难度都由服务端从 C 重算，从不信任 `ix` | SDK 不解析 C | 否（09 §6.1 `ChallengeSpec` 的落地） |
| D-45 | **会话密钥**：WebCrypto ECDSA P-256，存 IndexedDB，不可导出。IndexedDB 不可用时（含 1.5 s 超时），改用可导出的密钥并存 localStorage（键 `mg_sk_v1`，各标签页共享）；再不行只放在内存，这时 SDK 不附证明。WebCrypto 不可用时，非交互式提交退回 v1，交互式无法完成。遥测记录 `ks = idb \| local \| memory \| none`。密钥在首次需要时生成：挑战页上，或首个需要证明的请求之前；没有有效凭证时（`__Host-mg_st` 缺失或已过期），或密钥已用满 7 天时，生成新密钥（§12.4） | 04 §6.1 没有定义 IndexedDB 不可用时的行为。sessionStorage 按标签页隔离，而凭证 Cookie 由所有标签页共享：每个标签页一把密钥，会让绑定 `cnf.jkt` 的接口在标签页之间来回失败。凭证 Cookie 是 HttpOnly，XSS 读到私钥也拿不到凭证；RFC 9449 本来就承认 XSS 能在页面上在线签名。定期换密钥，避免公钥成为跨会话的长期标识 | 是（04 §6.1） |
| D-46 | **凭证 v2**：claims `v = 2`，在 v1 字段之外增加 `cnf: {jkt}`（可缺）与 `lat`（获得该级别的时间，Unix 秒）。Edge 同时接受 v1 与 v2，只在需要 v2 字段时签发 v2。凭证 Cookie 之外另设一个脚本可读的 Cookie `__Host-mg_st`，值为 `<iat>.<exp>.<b>`（签发时间与过期时间为 Unix 秒，`b` 为 1 表示绑定了密钥），不含级别与秘密，供 SDK 安排刷新、判断 Cookie 是否可用。改 Phase 1 规格 §6.5、§6.6 | 现有 claims 拒绝未知字段，新增字段会让旧 Edge 判为 `invalid`；凭证 Cookie 是 HttpOnly，SDK 无法得知过期时间。状态 Cookie 不写级别，避免页面上的第三方脚本得知访客用了无障碍路径 | 是（04 §5、ADR-0005 勘误） |
| D-47 | **凭证静默刷新 `POST /__mg/r`，缺省关闭**（`clearance.refresh = false`）。要求 `MG-Proof` 且与凭证的 `cnf.jkt` 一致；新凭证保留 `lvl`、`sub`、`sst`、`lat`、`bind`、`cnf`，`iat` / `exp` 更新。按级别设上限：`interactive` 缺省 4 小时，`interactive_ext:*` 缺省 2 小时，`pow` 为 `2 × ttl_pow_s`；`interactive_a11y` 与 `invisible` 不可刷新。另外以下情况拒绝：凭证带 `ruc`；没有 `cnf`；绑定硬失败或 `ipp` 软不符；按 `select_route(env, GET, "/")` 选中的路由重新决策后需要更高级别，或决定为阻断 / 限速（§9.3） | 04 §5 只给了方向。刷新会成倍放大每次解题的价值：人工代解或自动化得到的凭证若能长期刷新，09 §13 依赖的"短 TTL"就失效了；`interactive_a11y` 的短 TTL 正是它的补偿控制 | 是（04 §5、§9） |
| D-48 | **遥测 `POST /__mg/t`**：报告种类为 `behavior`、`upstream_challenge`、`cache_hit`。SDK 有会话密钥时附 `MG-Proof`，否则 `signed = false`；告警指标只计 `signed` 的报告。按 `ip`、`ipp` 与会话限速，写入 `vl-short` 的独立队列。行为采集缺省关闭：站点在 SDK 标签上写 `data-mg-telemetry="behavior"` 开启，Edge 按配置包 `events.telemetry_behavior` 决定是否接收 | 02 §3 只给了方向；新的客户端信号上线前须更新隐私说明（07 贯穿各阶段） | 是（02 §3） |
| D-49 | **交互评分**在 mg-core 中实现，是纯函数。Phase 2 只交付 `scoring_mode = shadow`：硬检查照常执行，软评分与特征只写入事件。`enforce` 的阈值 `T_pass` / `T_block` 由所有者在 shadow 数据之后设置，构建器要求显式给出。09 §11.1 的"PoW 下限"为配置项 `min_pow_ms`，缺省 0 | 09 §11.3 要求先 shadow；阈值目前没有数据来源 | 否 |
| D-50 | **失败升级**：站点启用交互式后，`invisible` / `pow` 提交失败时附的新 C 改为交互式（`risk_band` 仍按 `after_failure` 升级）。交互式失败附新的交互式 C，`attempt_no + 1`。`attempt_no > N`（缺省 2）时把 `pow_a11y` 放在首位；若 Turnstile 为 `escalate_after_fail` 且可用，同时把它加入。次数上限仍由失败配额 `mg.c.fail` / `mg.c.fail.prefix` 执行。站点未启用交互式时，保持 D-08、D-27 | 04 §3.1。`attempt_no` 可以通过重新请求页面清零，真正的上限只能放在服务端 | 是（04 §3.1；09 §11.3 的"M 次"措辞） |
| D-51 | **Provider 配置重写**（§3.2）：配置包只放公开配置：`sitekey`、主机名、路由、选择方式、超时、回退。回退只能是 `self_hold`：内置 Provider 总在集合中（无障碍要求，§5.4），访客随时可以改用它们，所以 `fail_closed` 不增加保护，只降低可用性；`fail_closed` 与 `fail_open_with_signal` 都被构建器与 Edge 拒绝。Turnstile secret 是部署属性，放在 `edge.toml` `[[sites]] turnstile_keys`（凭证，1–2 个值）。`InteractiveChallengeProvider::on_unavailable` 的缺省改为 `UseProvider(self_hold)` | 与 `upstream_keys`、`origin_keys` 的做法一致（D-14、I-38）；09 §6.3 与 proto 的字段不一致；proto 允许 fail-open | 是（09 §6.3、06 §8） |
| D-52 | **Turnstile 只用回环 mock siteverify 测试**（edge-core testkit）；任何测试与 CI 作业都不访问 `challenges.cloudflare.com`。所有者在 staging 上用 Cloudflare 的测试 sitekey 手工核对一次（§19） | CLAUDE.md 的范围约束：测试流量只留在本机 | 是（07 Phase 2、09 §8.6、§15） |
| D-53 | **近线 worker**：Go 命令 `mg-nearline`（`control-plane/cmd/mg-nearline`，包 `internal/nearline`），消费 `mg:ev`（组 `nl`），使用独立的 Valkey ACL 用户。`mg:ev` v2 增加方法、路径哈希、内容类型类别、扫描诱饵、跨站与凭证标记、证明结果。检测器 v1 有四个：扫描器、凭证共享、挑战滥用、高速率。近线写出的 verdict 只抬高风险（标签 `nl_*`），从不带矩阵会直接阻断的 `scanner` 标签；浏览器发出的跨站请求与带有效凭证的请求不计入扫描器与高速率。窗口状态放在 worker 内存中。shadow 模式只记日志与指标，不写 verdict。不用 `mg:pub:inv` 与 `mg:w:*`。verdict 经 Lua 脚本写入，不覆盖所有者手工写的 verdict | `mg-control` 是 Phase 3，`mgctl` 不连 Valkey；Edge 的 verdict 缓存只有 2 s，不需要失效通知。按单个 IP 实体直接阻断会误伤 CGNAT 与办公网的邻居，而第三方网页可以让访客的浏览器发出诱饵请求 | 是（02 §4、01 §5、03 §2） |
| D-54 | **吊销集与 pub/sub 留在 Phase 3**，07 的 Phase 2 表改为 Phase 3。Phase 2 中，近线的会话 verdict（`shared_token`）起软吊销作用：它抬高该会话的风险，并阻止该会话在重新挑战时沿用 `sub`（§6.8） | 01、02、04 与 Phase 1 规格都把它放在 Phase 3；Phase 2 验收不依赖它 | 是（07） |
| D-55 | **`MG-Nonce` 与 `step_up`（含 `bh`）推迟**到需要时（Phase 3 或按需）；I-19 的拒绝照旧。Phase 2 中"服务端 nonce"只指 C 的一次性 nonce | 04 §2、§8 与 07 不一致；`bh` 需要 Edge 缓冲请求体 | 是（04 §2、§6.1、§8） |
| D-56 | **推迟无障碍路径 D**（站点账号替代：passkey / 邮件链接）。`self_hold` 与 `pow_a11y` 都不是认知测试，已满足 WCAG 3.3.8；站点账号替代需要源站到 Edge 的签名断言，另行设计 | 09 §3.1 | 是（09 §3.1、§3.2） |
| D-57 | **SDK 的 fetch 处理**：`invisible` / `pow` 的 JSON 挑战就地求解（Worker 中，同一时刻至多一个），然后 `POST /__mg/c`（JSON），请求体可重放时再重试原请求；`mg_proof_required` 附带的 `pow` C 同样就地求解；`interactive` 按 I-39 的方式跳转 `/__mg/v?…&min=interactive`。不做页内覆盖层 | 覆盖层要应付源站的 CSP 与任意 DOM；I-39 已有跳转入口 | 是（09 §2.1 载体） |
| D-58 | **`/__mg/v` 签发的挑战类型**取以下四者中最高的一个：决策要求的类型、`ret` 所命中路由的 `min_level`、请求所带有效凭证的级别、可选参数 `min`（只能为 `interactive`，只能抬高，§7.10）。交互式不可用时按 `pow`。SDK 因 JSON 挑战的类型为 `interactive` 而跳转时带 `min=interactive`。改 I-39 | 否则交互级路由永远拿不到交互级凭证：要求交互式的常常是页面调用的 API 路由（`min_level`、交互式限速器），而 `ret` 是页面路径，按页面决策只会签发 `pow`。密钥丢失后的重新挑战也不应把交互级凭证降成 `pow` | 否 |
| D-59 | **Lab 仍不含求解逻辑**。交互式的完整性验收（重放、拼接、跨客户端、并发双提交）在 `edge/tests` 中用 mg-challenge 的测试辅助完成；Lab 只回放固定请求，做否定性检查 | CLAUDE.md；Phase 1 规格 §16 | 否 |
| D-60 | **本机应急开关**：`edge.toml` `[[sites]] force_monitor = true` 让该站点整站只记录（所有路由按 monitor 处理）；每次加载打一条 WARN 日志，`mg_site_forced_monitor{site} = 1`。这是"只能经签名配置包放宽"的例外，由 ADR-0011 记录 | 10 §5.2：enforce 加上交互式后误伤风险更高；所有者离开签名工作站时，需要能经 SSH 止损 | 是（新 ADR-0011、10 §5.2） |
| D-61 | **转发前删除 MorphGate 自己的 Cookie**（`schema_version = 2` 时）：Edge 转发给源站前，从 `Cookie` 头中删除 `__Host-mg_clr`、`__Host-mg_st`、`__Host-mg_a11y`，其余 Cookie 原样保留 | 凭证不应出现在源站日志中，源站也不需要它 | 是（02 §8） |
| D-62 | **遥测 schema 只保留一份实现**（edge-core）。**I-35 复审**：(a) 选中路由之前就应答的请求，路径不超限时同样做路由匹配并按 `redact_path` 改写，超限的路径只记长度；(b) 关闭时事件刷写最多再等 `shutdown_drain_ms`（缺省按升级宽限时间计算，§10.1）。带 `ruc` 凭证的决定事件强制写入，并计数 | Phase 1 进度记录 §4；I-35 | 否 |
| D-63 | **SDK 供应链**：npm 包改由 GitHub Actions 带 provenance 发布（trusted publishing）；CI 继续比对构建产物与 Edge 夹具。不对 SDK 目录做签名校验 | 10 SDK-01；Edge 主机上的 root 本来就能替换任何文件 | 是（10 SDK-01） |
| D-64 | **路由新增 `min_level`**（`invisible` / `pow` / `interactive`）：要求凭证，且级别不低于它；不满足时，挑战类型取矩阵结果与 `min_level` 中较高的一个 | 04 §5 写了"critical 路由可要求最低级别"，但 `Route` 没有对应字段 | 否 |
| D-65 | **无障碍路径调整**（改 09 §3.1 的路径 A、B）：键盘路径与"无法按住？"路径合并为**单次激活**。在按钮上按一次 Space / Enter，或点一次，控件就自动走完所需时长与 PoW 后提交，既不要求按住，也不要求第二次按下；签发 `interactive`。指针按住路径照旧，按 WCAG 2.5.2 只在抬起时提交：抬起时指针在控件内且已达到时长才提交。提前松开、`pointercancel`、指针移出控件、窗口失焦或页面隐藏一律中止，不计失败 | WCAG 2.1.1 的 Understanding 文档把"按住某个键一段时间才生效"列为对单次按键的特定时序要求（A 级）；原设计的第二次按下同样依赖时机 | 是（09 §2.2、§2.3、§3.1、§3.2） |
| D-66 | **`schema_version = 1` 时严格按 Phase 1 运行**：`identity.proof.*` 恒为 MISSING，不解析、不校验 `MG-Proof`，不写 `jti`；接受 v2 提交（照常验签），但只签发 v1 凭证，不设 `__Host-mg_st`；`/__mg/c/renew`、`/__mg/r`、`/__mg/t` 返回 404；D-61 不生效。`schema_version = 1` 而任一 Phase 2 字段非零的配置包无效；`schema_version ∉ {1, 2}` 同样无效 | 升级二进制必须不改变线上行为。否则 Phase 1 中只得到警告的规则（读取 `identity.proof`）会在升级时开始命中，回滚时还会签发旧 Edge 不认的凭证 | 否 |
| D-67 | **新的内置限速器都分两级**，同 D-28：按 `ip` 实体的主限额，加按 `ipp` 的宽松限额（缺省为 4 倍；`mg.a11y.issue` 为 20 倍，§7.9）。只按 `/24` 计数时，CGNAT、校园网或移动网段中的一个客户端就能让整个前缀被拒 | 09 §12.3 写的是"ipp、会话"，而挑战前没有会话 | 是（09 §12.3） |
| D-68 | **Phase 2 中所有级别的凭证证据保持 −0.4**（`identity.clearance`）。交互级的更强证据（03 §4.1 的 −0.8）只能在交互评分改为 `enforce` 之后，以新裁决引入 | `self_hold` 的检查除服务端时间窗外都依赖客户端自报的数据；交互级凭证的成本下限只是 PoW 加 1.2–2.5 s 等待，不能给它两倍于 `pow` 的人类证据 | 是（03 §4.1、09 §11.2） |
| D-69 | **本文改动的其他 Phase 1 契约**（Phase 1 规格的章节，均在本文完整重述）：§0.1（D-39）；§6.1、§6.2（D-42）；§6.5、§6.6（D-46）；§8.1（`edge.toml` 新键，§10.1）；§8.2、§8.3（站点 YAML 与缺省值，§3.2、§10.2）；§9.5（`http.cookie_names` 排除新 Cookie，§9.5）；§9.7（`mg_nonce_issue` v2 与新键，§14）；§9.9（D-61）；§10.2、§10.3（JSON 应答的 `v`、失败时附的 C，§7、§11.2）；§10.4（SDK 别名）；§10.5 与 I-39（D-58）；§11.1、§11.2（manifest v2 与模板 v2，§12.2、§12.3）；§11.3（交互式 PoW 不受 60 s 总时限，§12.6）；§13.3–§13.6（事件与 `mg:ev` v2，§13.1、§15）；§17 第 2 步（Edge ACL，§14.5）；D-27 与 I-10（D-50）；I-32（遥测写入条件，§15.2） | Phase 1 规格冻结；实现者只读本文即可知道哪些 Phase 1 契约已改 | 否 |

### 0.4 规格评审通过后先行落地的契约文件

本规格合入后、阶段 1 开始前，集成者用一个单独的 PR 落地下列文件。做法同 Phase 1 §0.4：各 WP 从这些文件出发，不重新定义它们。

| 文件 | 内容 | 之后的所有者 |
|---|---|---|
| `proto/morphgate/v1/challenge.proto` | `SealedChallengeClaims.renew_no = 16`；`Pow.k = 3`、`Pow.a11y_difficulty = 4`；字段注释改为 §3.1 的 Phase 2 语义 | 只读契约 |
| `proto/morphgate/v1/config.proto` | §3.2 的全部新字段与枚举 | 只读契约 |
| `proto/morphgate/v1/decision.proto` | §3.3 的新字段 | WP-R4 |
| `control-plane/gen/morphgate/v1/*.pb.go` | 按上述 proto 重新生成 | 生成文件只随 proto 变更 |
| 根 `Cargo.toml`、`Cargo.lock`、`fuzz/Cargo.lock` | `[workspace.dependencies]` 增加 `aws-lc-rs`，版本与特性同 `Cargo.lock` 中已有的那一份（reqwest / rustls 已经编译它），所以不新增任何 crate；`fuzz/Cargo.lock` 同步 | 阶段 1 只按 §2.3 追加 |
| `challenge/Cargo.toml` | 依赖 `aws-lc-rs`，只用其 `signature::ECDSA_P256_SHA256_FIXED` 验签；测试中的签名也用它 | WP-R5 |
| `control-plane/go.mod`、`go.sum` | 近线 worker 的 Valkey 客户端（落地时选定纯 Go、许可宽松、仍在维护的最新稳定版，版本号记入落地 PR） | WP-N1 |
| `testdata/phase2/kat.json`、`testdata/phase2/README.md`、`testdata/phase2/samples/**`、`testdata/phase2/gen/kat.mjs`、`testdata/policy-ir/fields.json` | §6.11 的已知答案向量；样例：`mg-turnstile-keys` 文件、siteverify 响应、`MG-Proof`、v2 提交、`t` 与 `/__mg/t` 的遥测（§7.6、§12.8，有效与无效各若干）、`mg:ev` v2 条目（每行一个条目，字段与值以 TAB 分隔，空值为空串）；`fields.json` 列出全部策略字段路径、类型与大小上限，Go 与 Rust 的测试都读取（§22）。生成器只用 Node 内置模块（`node:crypto`、WebCrypto）；ECDSA 向量只用于验签 | 只读；修改需先改本文 |
| `core/src/challenge.rs` | `on_unavailable` 的缺省改为 `UseProvider(SelfHold)`（D-51）；`ChallengeSpec` 不变（`ix` 由 Edge 组装，§7.2） | WP-R4 |
| `core/src/sealed.rs`、`core/src/context.rs`、`core/src/decision.rs`、`core/src/extras.rs`、`core/src/telemetry.rs`（新） | §3.4 的新类型字段与 `SealedChallengeClaims::check` 的 Phase 2 规则（§6.2）；`IxTelemetry` 及其子类型（§7.6 的全部字段，量化后的整数与枚举，不含解析）。只含类型与校验，不含其他逻辑。这样 WP-R5、WP-C5 都不依赖 WP-R4 的代码 | WP-R4（语义为只读契约） |
| 编译修复 | 同一个落地 PR 给 `edge/`、`edge-core/src/state/builtin.rs` 等处受影响的结构体字面量补上新字段的零值（或改为 `..Default::default()`），并按 §6.2 更新 `challenge/tests/sealed.rs` 与 `core/src/sealed.rs` 中与新规则冲突的用例。落地后 `make check` 全绿，行为不变 | 集成者 |
| `.github/workflows/ci.yml` | `go` 作业加上与 `rust` 作业相同的、按摘要固定的 Valkey 服务容器，并设置 `MG_TEST_VALKEY_URL` 与 `MG_REQUIRE_VALKEY=1`，供 WP-N1 的测试使用。作业名不变（§2.3） | 阶段 2 起 WP-E2a |
| 空模块与包：`core/src/providers.rs`、`challenge/src/{jwk,sig,proof,ui,turnstile}.rs`、`edge-core/src/outbound.rs`、`edge-core/src/testkit/siteverify.rs`、`control-plane/cmd/mg-nearline/main.go`、`control-plane/internal/nearline/doc.go`、`control-plane/internal/turnstile/doc.go`；`edge-core/src/lib.rs` 与 `testkit.rs` 中对应的模块声明 | 可编译的空实现；文档注释写明负责的 WP | 各 WP |
| `CLAUDE.md` | 本文与 `testdata/phase2/` 的索引 | WP-D2 |

## 1. 架构

### 1.1 组件与数据流

```
                    owner workstation
  site.yaml (providers, routes.proof / min_level, challenge.interactive) ──mgctl bundle build / sign / publish──> bundle dir
  mgctl turnstile secret rotate | import ──> mg-turnstile-keys (systemd credential on the Edge host)

Browser: site page (owner template) + <script data-cfasync="false" src="/__mg/s/mg.js" defer>
         SDK: session key (IndexedDB) · MG-Proof on fetch · in-place pow · refresh · telemetry · cf-mitigated
   │
   v
Cloudflare ─> cloudflared ─> mg-edge 127.0.0.1 ─(ALLOW / TAG / LOG)─> origin   (Cookie without the 3 MorphGate cookies)
                               │  /__mg/c (v1 | v2) · /__mg/c/renew · /__mg/r · /__mg/t · /__mg/v · /__mg/s/*
                               ├─> Valkey: MGET mg:v:* · EVALSHA mg_gcra · EVALSHA mg_jti · EVALSHA mg_nonce_issue v2 (+ mg:rp:*) · XADD mg:ev (v2)
                               ├─> Turnstile siteverify (only when a C offered turnstile; after the nonce is consumed)
                               └─> VictoriaLogs vl-main / vl-short; /metrics
mg-nearline ── XREADGROUP mg:ev (group nl) ── detectors ── EVALSHA mg_verdict_put ──> mg:v:{site}:{type}:{key}
            └─> /metrics; kind=verdict lines to vl-main (optional)
```

### 1.2 Rust crate 与依赖

依赖关系与 Phase 1 相同（Phase 1 规格 §1.2），不新增 crate：

| crate | 新增的直接依赖 | 约束 |
|---|---|---|
| `mg-core` | 无 | Provider 实现与交互评分都是纯函数；仍然必须能编译到 `wasm32-unknown-unknown` |
| `mg-proto` | 无 | 只重新生成 |
| `mg-challenge` | `aws-lc-rs`（已在 `Cargo.lock` 中，reqwest / rustls 本来就编译它） | 只用于 ES256 验签（`ECDSA_P256_SHA256_FIXED`，汇编优化，比纯 Rust 实现快数倍）。签名只出现在测试中；生产路径从不持有私钥 |
| `mg-edge-core` | 无（`reqwest` 已在） | `outbound` 模块是出站 HTTP 的唯一实现，只在后台 service 的运行时上执行 |
| `mg-edge` | 无 | |

`serde_json` 解析 `MG-Proof` 头与载荷时，必须拒绝重复键与未知成员：用 `#[serde(deny_unknown_fields)]` 结构体，serde 会把重复字段报为错误。

### 1.3 Go 包

| 包 | 作用 | WP |
|---|---|---|
| `internal/sitecfg`、`internal/bundle` | 站点 YAML 新字段、配置包构建与校验（§10.2） | WP-G4 |
| `internal/policy` | `identity.proof.*`、`identity.token.bound` / `level_age`、`http.navigation` 的字段模式和可用性（§4）；一致性用例 | WP-G4 |
| `internal/keys` | 密钥文件 `mg-turnstile-keys`（§8.7） | WP-G4 |
| `internal/turnstile` | Cloudflare Turnstile widget API 的最小客户端：列出 widget、轮换 secret | WP-G4 |
| `internal/mgctl` | `mgctl turnstile …` 命令分发与审计条目（§16） | WP-G4 |
| `internal/nearline`、`cmd/mg-nearline` | 近线 worker（§13） | WP-N1 |

### 1.4 Edge 请求处理顺序（Phase 2）

在 Phase 1 规格 §1.4 的基础上增加或改变的步骤以 `+` / `~` 标出：

```
request_filter
  0  request_id, now_ms
  1  listener: peer / client cert / secret header
  2  protocol limits; header hygiene
~    MG-Proof is read from the raw headers before the family strip (it is never forwarded)
  3  Host -> site; site state; foreign CF-Worker -> 403
+    edge.toml force_monitor -> every route is treated as monitor (D-60)
~ 4  /__mg/* -> healthz | s/{file | mg.js} | c (v1 | v2) | c/renew | r | t | v | reserved 404
  5  environment; route over every path view, most sensitive match wins
+    proof = required if any matched route requires it; min_level = the highest over matched routes
  6  RequestContext
+    identity.proof present / valid / replayed only when verified: schema 2, not an exempt navigation (GET / HEAD,
     every matched route web), and a route requires proof or the policy reads identity.proof (§9.1); else MISSING
~ 7  identity: clearance v1 | v2 (cnf.jkt), crawler; + MG-Proof verification, cheap checks first (§6.7)
+    proof route + Early-Data -> 425
~ 8  state: ONE round trip = MGET verdicts + EVALSHA mg_gcra + EVALSHA mg_jti (when a proof passed section 6.7)
~ 9  Decision Core (interactive_available, effective min_level)
~10  monitor / forced monitor -> dry_run, forward
     enforce: CHALLENGE -> page v2 or JSON (interactive with ix); proof route + not exempt + no valid proof
     -> 403 mg_proof_required (JSON with now_ms, maybe a bound pow C; HTML for non-exempt navigations)
upstream_request_filter: strip MG-* / families; + strip the cookies __Host-mg_clr, __Host-mg_st, __Host-mg_a11y (exact names, D-61, schema 2 only); add MG-*
logging: events (+ force-sample decisions with an ruc token; kind=access + sess, ct); mg:ev v2; metrics
```

## 2. 工作包与文件所有权

### 2.1 阶段、依赖与修复规则

```
stage 0 (integrator):  pre-land the contracts of §0.4
stage 1 (parallel):    R4  R5  |  C5  C6  |  G4  N1  |  W2
                                     \ all merged /
stage 2 (sequential):  E2a ──> E2b ──> E2c          (edge/, deploy/systemd, Makefile, CI)
                                     \ E2c merged /
stage 3 (parallel):    L2 (lab/, scripts/lab-e2e.sh)    D2 (docs/)
```

- **阶段 1**：WP 之间没有编译期依赖，每个 WP 只使用本文、§0.4 的已落地文件和现有代码。
  - WP-R5 只用 mg-core 中已落地的类型（§0.4），不依赖 WP-R4 新增的逻辑。
  - WP-C5 把 `t` 解析为已落地的 `mg_core::IxTelemetry`；WP-R4 只消费这个类型。
  - WP-N1 按 §13.1 的 `mg:ev` v2 格式与 `testdata/phase2/samples/` 的样例编写测试，不依赖 WP-C5 的写入实现。
  - WP-W2 按 `testdata/phase2/kat.json` 测试 PoW v2、签名与 `MG-Proof`，不依赖 WP-R5。
  - WP-C6 不依赖 WP-R5：`cdata` 的比较由调用方传入的闭包完成（§8.4）。
  - **策略一致性**：WP-R4 先于 WP-G4 合入。G4 的新上下文与用例在 R4 合入之后加入，由 R4 的求值器在 G4 那个 PR 的 CI 中验证（同 Phase 1 规格 §2.1 的"后合入者负责全绿"）。
  - **Phase 2 golden 配置包**：`control-plane/testdata/sites/golden/golden-phase2.bundle` 由 WP-G4 生成；`edge-core/tests/bundle_golden.rs::golden_phase2_bundle_verifies` 由 G4 与 C5 中后合入者添加；WP-E2a 在 `edge/tests/bundle_load.rs` 中复验。
- **阶段 2**：阶段 1 全部合入后开始。E2a → E2b → E2c 依次合入，每个都是一个可评审的 PR，合入时 `make check` 全绿；同一时间只有一个 E2 子 WP 在改 `edge/`。
- **阶段 3**：E2c 合入后开始。
- **SDK 模板 v2 的切换**：Phase 1 的 Edge 只接受 manifest `v = 1`、恰好 10 个占位符的模板。所以按下面三步切换，保证每一步 `make check` 都全绿：
  1. WP-W2 在 `build-dist.mjs` 中导出常量 `DEFAULT_MANIFEST_VERSION`，阶段 1 中为 1。构建、`check-package.mjs` 与测试都按它选择模板文件（`challenge.html` 或 `challenge.v2.html`）与校验规则，两份模板各有按文件名的测试。SDK 只在 v2 模板的页面（`#mg-challenge` 带 `data-mg-ix`）上发送 v2 提交与续期；在 v1 模板的页面上，继续发送 Phase 1 的 v1 提交。fetch 包装的就地求解（§12.5）只在 `DEFAULT_MANIFEST_VERSION = 2` 的构建中启用。SDK 代码改变时，W2 照常把构建产物复制到 `edge/tests/fixtures/sdk/`：Edge 只校验 JS 文件的哈希，不校验其内容。
  2. WP-E2a 让 Edge 同时接受 manifest v1 与 v2（§12.2）。切换之前，它先把当时的夹具冻结为 `edge/tests/fixtures/sdk-v1/`，供"manifest v1 目录照常工作"的测试使用。
  3. 在同一个 PR 中，WP-E2a 把 `DEFAULT_MANIFEST_VERSION` 改为 2，删除 v1 模板及其专属测试，把 SDK 版本改为 0.3.0（`package.json` 与 `SDK_VERSION`），并更新夹具。这是 §2.2 所有权的明确例外，范围包括 `sdk/web/test/**` 中只针对 v1 模板的用例。
- **合入后的修复**：同 Phase 1 规格 §2.1。原 WP 负责人以小 PR 维护自己的文件；其他 WP 发现缺陷时，加一个跳过的复现测试并通知负责人。阶段 3 中 `edge/` 的缺陷由 WP-E2c 的负责人修。

### 2.2 文件所有权矩阵

一个路径只有一个所有者 WP，其他 WP 只读。"只读契约"文件的修改先改本文，再由表中的所有者或集成者提交。

| 路径 | 所有者 | 说明 |
|---|---|---|
| `core/**`、`proto/rust/**`、`proto/morphgate/v1/decision.proto` 及其生成文件 | WP-R4 | §0.4 已落地的类型字段语义为只读契约 |
| `proto/morphgate/v1/{challenge,config,common,policy_ir}.proto` | 只读契约 | |
| `challenge/**` | WP-R5 | |
| `testdata/phase1/**`、`testdata/phase2/**` | 只读契约 | |
| `edge-core/src/{state,events,bundle}.rs`、`edge-core/src/{state,events,bundle}/**`（含 `lua/*.lua`）、`edge-core/src/testkit/{valkey,vl,http}.rs`、`edge-core/tests/{state,events,bundle}_*.rs` | WP-C5 | |
| `edge-core/src/outbound.rs`、`edge-core/src/outbound/**`、`edge-core/src/testkit/siteverify.rs`、`edge-core/tests/outbound_*.rs` | WP-C6 | |
| `edge-core/Cargo.toml`、`edge-core/src/lib.rs`、`edge-core/src/testkit.rs` | 集成者（已落地） | 只按 §2.3 追加依赖行 |
| `control-plane/internal/{sitecfg,bundle,policy,keys,mgctl,cli,turnstile}/**`、`control-plane/testdata/**`、`testdata/policy-ir/**`、`control-plane/README.md` | WP-G4 | README 也写 `mg-nearline` 的用法，内容按 §13 |
| `control-plane/cmd/mg-nearline/**`、`control-plane/internal/nearline/**`、`deploy/systemd/mg-nearline.service`（新） | WP-N1 | `go.mod` / `go.sum` 的依赖已在 §0.4 落地 |
| `sdk/web/**`、`.github/workflows/publish-sdk.yml`（新） | WP-W2 | 另负责复制 `edge/tests/fixtures/sdk/**`（生成文件）；模板切换见 §2.1 |
| `edge/**`、`deploy/systemd/{mg-edge.service,edge.toml.example}`、`deploy/vmalert/**`（新）、`scripts/edge-smoke.sh`、`scripts/mg-daily-check.sh`（新）、根 `Cargo.toml`、`Cargo.lock`、`deny.toml`、`fuzz/**`、`Makefile`、`.github/workflows/{ci,fuzz}.yml`、`deploy/compose/**` | WP-E2a → E2b → E2c（依次） | 阶段 2 |
| `lab/**`、`scripts/lab-e2e.sh` | WP-L2 | 阶段 3 |
| `docs/**`（`docs/impl/` 除外）、`README.md`、`CLAUDE.md` | WP-D2 | 阶段 3 |
| `docs/impl/phase2-spec.md` | 集成者 | 契约变更先改这里 |

### 2.3 共享文件规则

- **阶段 1 只做加法**：阶段 1 的 WP 不得改变 `edge/` 已使用的公共项的形状与行为，如 `MintParams`、`DecisionEntry`、`FeedbackEntry`、`RoundTrip1`、`NonceIssue`。新内容放进新类型与新入口，例如 `MintV2Params` / `mint_v2`、`StreamEntry::decision_v2` / `feedback_v2`、`RoundTrip1V2`、`NonceIssueV2`。`mg:ev` v1 编码、`mg_nonce_issue` v1 的调用与 Phase 1 行为保留到 E2a / E2b 切换，切换的 PR 删除旧入口。
- **`Cargo.lock` 与 `fuzz/Cargo.lock`**：阶段 1 的 Rust WP 只使用已在根 `[workspace.dependencies]` 声明并锁定的依赖。确需新增依赖时，只追加本 WP 的那一段，在 PR 中说明，并运行 `cp Cargo.lock fuzz/Cargo.lock && make fuzz-lock-check`。
- **`go.mod` / `go.sum`**：只有 WP-N1 的依赖已经落地；其他 Go WP 只用已有依赖与标准库。
- **生成代码**：proto 只由所有者 WP 修改，改后运行 `make proto`。
- **必需的 CI 检查名称**：`master` 的规则集按名称要求 10 项检查（如 `Validation Lab end to end (Phase 1 scenarios)`），所以**任何 WP 都不得改这些作业的名字**，也不得给 `ci.yml` / `audit.yml` 加路径过滤或作业级 `if:`。新作业可以加，它们不是必需检查。
- **README**：`sdk/web/README.md` 归 WP-W2，`control-plane/README.md` 归 WP-G4，`lab/README.md` 归 WP-L2；根 README 与 CLAUDE.md 由 WP-D2 修改。

### 2.4 通用完成定义

Phase 1 规格 §2.4 的 8 条全部适用，另加：

9. 每个新的不可信输入解析器都有固定种子的随机输入测试（≥ 10,000 个输入，同 Phase 1 第 3 条）。cargo-fuzz 目标与种子由阶段 2 的 WP 添加，并同步 Makefile 的 `FUZZ_TARGETS` 与 `fuzz.yml` 的矩阵：E2a 添加 `mg_proof`、`submission_v2`、`renew`、`ix_telemetry`；E2b 添加 `refresh`、`telemetry`；E2c 添加 `siteverify_response`、`turnstile_keys`。Go 的解析器（`mg:ev` v2 条目）只有固定种子的随机输入测试。
10. D-31 的"永不写入日志与 `Debug`"清单增加：`MG-Proof` 原文、会话公钥 JWK 与 `jkt` 明文、提交签名、Turnstile token 与 secret、`/__mg/t` 与交互遥测的内容。`jkt` 只以 `K_pseudo` 的 HMAC 形式出现在 Valkey 键中（§14.1）。
11. 无障碍：交互式界面的四条路径（按住、键盘、切换、`pow_a11y`）各有自动测试；界面文案只来自 §12.7 的文案表。
12. 第三方请求：`self_hold` / `pow_a11y` 的挑战页不引用任何第三方源，测试同时检查模板与 CSP；只有提供了 Turnstile 的挑战页才出现 `challenges.cloudflare.com`。

## 3. 数据模型改动

所有改动都是新增字段或新增枚举值，线格式与 Phase 1 兼容。用到 Phase 2 字段的配置包，其 `schema_version = 2`（§3.2），所以 Phase 1 的 Edge 拒绝它（继续使用上一个有效的配置包），不会静默忽略新字段。

### 3.1 `challenge.proto`（§0.4 落地）

```proto
message SealedChallengeClaims {
  message Pow {
    string alg = 1;              // "sha256-hashcash-v1" (invisible / pow) | "sha256-hashcash-v2" (interactive)
    uint32 difficulty = 2;       // v1: the single puzzle; v2: every sub-puzzle, provider self_hold (or turnstile)
    uint32 k = 3;                // v2 only: number of sub-puzzles, 1..8; v1: 0
    uint32 a11y_difficulty = 4;  // v2 only: every sub-puzzle, provider pow_a11y; v1: 0
  }
  // fields 1-15 as in Phase 1, with these Phase 2 meanings:
  // providers  (7):  interactive: non-empty, unique, contains "pow_a11y", subset of {self_hold, pow_a11y, turnstile}
  // attempt_no (9):  interactive: 1-based attempt number; invisible / pow: 0
  // ui_seed   (12):  interactive: random, non-zero; invisible / pow: 0
  // bind.jkt  (15.3): bind_hash("jkt", <43-char thumbprint>) when the C is bound to a session key (D-41)
  uint32 renew_no = 16;          // interactive: renewals so far in this chain, 0..6; invisible / pow: 0
}
```

### 3.2 `config.proto`（§0.4 落地）

```proto
message Route {
  // fields 1-13 as in Phase 1
  ProofMode proof = 14;          // D-40; an unknown value makes the bundle invalid
  ChallengeType min_level = 15;  // D-64; UNSPECIFIED | INVISIBLE | POW | INTERACTIVE, anything else is invalid
}
enum ProofMode { PROOF_MODE_OFF = 0; PROOF_MODE_REQUIRED = 1; }

message ChallengeConfig {
  // fields 1-11 as in Phase 1
  InteractiveConfig interactive = 12;
  string default_lang = 13;      // "zh-CN" | "en": page language when Accept-Language has neither (section 12.7)
  string help_path = 14;         // site-relative path of the "troubleshooting" link, validated like ret (section 12.3)
  string privacy_path = 15;      // site-relative path of the privacy notice link, validated like ret
}
message InteractiveConfig {
  bool enabled = 1;              // false: Phase 1 behaviour, interactive runs as pow (D-08)
  ChallengeConfig.PowBits pow_bits = 2;  // self_hold, per sub-puzzle, by risk band; each 8..22
  uint32 pow_k = 3;              // sub-puzzles for every interactive C, 1..8
  uint32 a11y_bits = 4;          // pow_a11y, per sub-puzzle; 12..24
  uint32 escalate_after = 5;     // N of D-50, 1..5
  string scoring_mode = 6;       // "shadow" | "enforce" (enforce requires t_pass and t_block)
  float t_pass = 7;              // enforce only: 0 < t_pass < t_block <= 1
  float t_block = 8;
  uint32 min_pow_ms = 9;         // PoW floor of the minimum-time check for hold / single (section 7.7), 0..5000
  uint32 issue_rate = 10;        // limiter mg.ix.issue: interactive C issued per ip entity (renewals included);
  uint32 issue_period_s = 11;    //   the ipp limit is 4x (D-67)
  uint32 issue_burst = 12;
  uint32 a11y_issue_per_ip = 13;   // limiter mg.a11y.issue: interactive_a11y clearances per ip entity
  uint32 a11y_issue_period_s = 14; //   (both dimensions share the period)
  uint32 a11y_min_ms = 15;       // minimum-time check for pow_only (section 7.7), 0..10000
  uint32 renew_rate = 16;        // limiter mg.c.renew per ip entity; ipp 4x
  uint32 renew_period_s = 17;
  uint32 renew_burst = 18;
  uint32 a11y_issue_per_ipp = 19;  // limiter mg.a11y.issue: per ipp, >= a11y_issue_per_ip (section 7.9)
}

message ClearanceConfig {
  // fields 1-4 as in Phase 1
  uint32 ttl_interactive_s = 5;          // 300..7200
  uint32 ttl_interactive_a11y_s = 6;     // 300..3600
  uint32 ttl_interactive_ext_s = 7;      // 300..7200
  bool refresh = 8;                      // accept POST /__mg/r (D-47); default false
  uint32 refresh_max_interactive_s = 9;  // 900..86400: now - lat cap for interactive
  uint32 refresh_max_ext_s = 10;         // 900..86400: now - lat cap for interactive_ext:*
  uint32 refresh_max_pow_s = 11;         // 0..86400: now - lat cap for pow (0 = pow tokens never refresh)
}                                        // interactive_a11y and invisible never refresh

message ProviderConfig {                 // Phase 2: id "turnstile" only; self_hold and pow_a11y are built in
  string id = 1;
  bool enabled = 2;
  string sitekey = 3;                    // public widget sitekey
  repeated string secret_refs = 4;       // must be empty (D-51): the secret is in edge.toml
  repeated string allowed_countries = 5; // must be empty
  repeated string denied_countries = 6;  // ISO 3166-1 alpha-2, added to the hard-coded CN
  repeated string route_ids = 7;         // empty = every route
  uint32 timeout_ms = 8;                 // 1000..5000
  string fallback = 9;                   // Phase 2: "self_hold" only (D-51); anything else makes the bundle invalid
  string mode = 10;                      // "shadow" | "enforce"
  repeated string hostnames = 11;        // exact FQDNs in the widget; the request Host must be one of them
  string selection = 12;                 // "first" | "escalate_after_fail"
}

message EventConfig {
  // fields 1-3 as in Phase 1
  bool telemetry_behavior = 4;           // accept behavior reports on /__mg/t (D-48)
  bool scanner_baits_builtin = 5;        // flag the built-in scanner paths in mg:ev v2 (section 13.1)
  repeated string scanner_baits = 6;     // extra globs, same syntax as route paths, at most 64
}

message SiteBundle {
  // schema_version (11): 1, or 2 when any Phase 2 field or value is set (a limiter with challenge_type
  //   INTERACTIVE included); the Phase 2 Edge accepts both (D-66)
  // providers (6): at most one entry, id "turnstile" (section 8.2)
}
```

**`schema_version` 的校验**（D-66，构建器与 Edge 都执行）：
- `schema_version ∉ {1, 2}` → 配置包无效。
- `schema_version = 1`：
  - 下列字段必须全部为零值或为空，否则配置包无效：`Route.proof`、`Route.min_level`、`ChallengeConfig` 的 12–15 号字段、`ClearanceConfig` 的 5–11 号字段、`EventConfig` 的 4–6 号字段、`SiteBundle.providers`；限速器的 `challenge_type` 不得为 `INTERACTIVE`（同 Phase 1）。
  - Edge 严格按 Phase 1 运行（D-66）。Phase 2 字段的有效值固定为：交互式关闭、`proof` 为 off、未设 `min_level`、`refresh = false`、`telemetry_behavior = false`、`scanner_baits_builtin = true`、`scanner_baits` 为空、没有 Provider。
- `schema_version = 2`：
  - `challenge`、`challenge.interactive`、`clearance`、`events` 必须存在，本节的每个 Phase 2 字段都必须在 §10.2 的范围内（不论功能是否启用），否则配置包无效。Phase 1"整条消息缺省时回填 Phase 1 规格 §8.3 的缺省值"的规则只适用于 Phase 1 字段。
  - 限速器的 `challenge_type` 可以为 `INTERACTIVE`。

构建器把缺省值显式写进配置包；Edge 只校验，不回填 Phase 2 字段。出现任何 Phase 2 键或取值（如 `type: interactive` 的限速器）时，构建器写 `schema_version = 2`。WP-C5 与 WP-G4 各为上述每条规则加反例。

### 3.3 `decision.proto`（§0.4 落地，之后归 WP-R4）

```proto
message Http {
  // fields 1-15 as in Phase 1
  bool navigation = 16;          // the Phase 1 navigation test (Phase 1 section 9.9), exposed as http.navigation
}

message Identity {
  message Token {
    // fields 1-4 as in Phase 1
    bool bound = 5;              // the clearance carries cnf.jkt
    uint32 level_age = 6;        // now - lat in seconds (v1 tokens: now - iat)
  }
  message Proof {
    bool valid = 1;              // as in Phase 1
    bool replayed = 2;           // as in Phase 1
    bool present = 3;            // an MG-Proof header was present
  }
}

message ChallengeResult {
  // fields 1-12 as in Phase 1; outcome (6) now also takes unavailable / misconfigured
  uint32 renew_no = 13;
  bool bound = 14;               // the submitted C carried bind.jkt
  InteractionSummary ix = 15;    // interactive only
  ProviderOutcome provider = 16; // only when an external provider was verified
}
message InteractionSummary {
  string mode = 1;               // "shadow" | "enforce"
  float score = 2;               // 0..1, section 7.8
  string a11y_mode = 3;          // none | single | pow_only (D-65)
  string input_modality = 4;     // mouse | touch | pen | keyboard | mixed | none
  uint32 hold_ms = 5;            // reported by the client, 10 ms resolution
  uint32 required_hold_ms = 6;   // recomputed from ui_seed
  uint32 elapsed_ms = 7;         // server clock: body read complete - C.iat
  map<string, float> features = 8;  // the soft features of section 7.8; bounded key set
  uint32 act_ms = 9;             // reported by the client: first activation to submission, 100 ms resolution (section 7.6)
}
message ProviderOutcome {
  string id = 1;                 // "turnstile"
  string outcome = 2;            // pass | fail | unavailable | misconfigured
  string mode = 3;               // shadow | enforce
  uint32 latency_ms = 4;
  repeated string error_codes = 5;  // siteverify error codes from the bounded set of section 8.5
}
```

### 3.4 mg-core 原生类型改动汇总（字段在 §0.4 落地，逻辑归 WP-R4）

| 类型 | 改动 |
|---|---|
| `SealedChallengeClaims` | 新增 `renew_no`；`PowParams` 新增 `k`、`a11y_difficulty`；新常量 `MAX_RENEW_NO = 6`、`MAX_POW_K = 8`，寿命上限沿用已有的 `MAX_INTERACTIVE_LIFETIME_MS`（600 000）；`check()` 的 Phase 2 规则见 §6.2 |
| `Proof` | 新增 `present` |
| `Token`（`Identity.Token`） | 新增 `bound`、`level_age` |
| `Http` | 新增 `navigation: bool` |
| `RouteInfo`（`core/src/extras.rs`） | 新增 `proof_required: bool`（命中路由的"或"）、`min_level: Option<ChallengeType>`（命中路由中最高的） |
| `ChallengeResult` | 新增 `renew_no`、`bound`、`ix: Option<InteractionSummary>`、`provider: Option<ProviderOutcome>`；`InteractionSummary` 含 `f32`，所以去掉 `Eq` 派生，只保留 `PartialEq` |
| `IxTelemetry`（`core/src/telemetry.rs`，新） | §7.6 的全部字段，量化后的整数与枚举；不含解析（解析在 edge-core，§15.2） |
| `EngineConfig` | `interactive_available` 由 Edge 按配置包与 SDK 目录设置（§5.1），不再固定为 `false` |
| `core/src/providers.rs`（新） | `SelfHold`、`PowA11y`、`select_providers`、`assess_interaction`、`next_challenge_after_failure`、`refresh_check`（§5） |

## 4. 策略字段与 MISSING 语义（WP-R4 实现，WP-G4 同步编译器）

### 4.1 新增与改变的字段

| 字段 | 类型 | 含义 | 何时可用 |
|---|---|---|---|
| `http.navigation` | bool | 导航请求：`Sec-Fetch-Mode: navigate`，或没有 `Sec-Fetch-Mode` 而 `Accept` 含 `text/html`（与 Phase 1 规格 §9.9 的判定相同）。由客户端的请求头决定，不是安全边界 | 总是 |
| `identity.proof.present` | bool | 请求带 `MG-Proof` 头 | 除"可豁免的导航"（D-40：GET / HEAD 导航，且所有命中路由的 channel 都是 `web`）之外的请求，并且需要校验时（§9.1）；否则为 MISSING |
| `identity.proof.valid` | bool | 证明通过 §6.7 的全部检查，`jti` 不是重放，且凭证带 `cnf.jkt` 并与之一致 | 同上 |
| `identity.proof.replayed` | bool | 证明的 `jti` 已用过，或该密钥超出了 `jti` 配额（§9.2） | 同上；重放存储不可用时为 MISSING |
| `identity.token.level` | string | 取值增加 `interactive`、`interactive_a11y`、`interactive_ext:turnstile` | 同 Phase 1 |
| `identity.token.bound` | bool | 凭证带 `cnf.jkt` | 与 `identity.token.level` 相同 |
| `identity.token.level_age` | int（秒） | `now − lat`（v1 凭证为 `now − iat`） | 与 `identity.token.level` 相同 |

### 4.2 MISSING 规则（改 D-07）

- `schema_version = 1` 的配置包下，`identity.proof.*` 恒为 MISSING，与 Phase 1 相同（D-66）。
- `schema_version = 2` 时，`identity.proof.*` 不再恒为 MISSING，按上表取值。没有 `MG-Proof` 头时 `present = false`、`valid = false`，是可用的普通值。可豁免的导航上它们仍为 MISSING：浏览器的页面跳转无法携带请求头，这样写成 `!identity.proof.valid` 的规则不会造成挑战循环。
- 只有路由要求证明，或配置包中有规则读取 `identity.proof.*` 时，Edge 才校验证明（§9.1）；不校验时这三个字段为 MISSING。
- 求值语义沿用 Phase 1 规格 §4 的 MISSING 规则。
- `identity.agent.*` 与 `direct_tls` 下的 `tls.ja4` 保持 MISSING，D-07 的这两部分不变。
- **Go 编译器**（`availability.go`）：
  - 把 `identity.proof` 从"恒为 MISSING"改为"在可豁免的导航上为 MISSING"，不再对使用它的规则发出 Phase 1 的警告；
  - 动作为 `allow` 的规则若以 `http.navigation` 为条件，报错：它与 `Sec-Fetch-*`、`Accept` 一样由客户端控制，攻击者加一个请求头就能命中；其他动作的规则用它只给警告。
  - 条件含 `identity.proof.present && !identity.proof.valid` 而动作为 `block` 时给出提示：密钥被清除的普通访客（Safari 的 7 天清理、隐私窗口）也会命中（`proof.jkt`），这类条件只应用于 `challenge`。
- **一致性用例**（`testdata/policy-ir/cases.json`）新增：可豁免导航、非安全方法的"导航"与非导航三种上下文下的 `identity.proof.*` 与 `http.navigation`，以及 `identity.token.bound` / `level_age`。

## 5. Decision Core 的变化（WP-R4）

### 5.1 交互式是否可用（改 D-08）

`EngineConfig.interactive_available = schema_version = 2 ∧ 配置包 challenge.interactive.enabled ∧ SDK 目录为 manifest v2`。为 `false` 时：
- 决策与 Phase 1 相同：`interactive` 按 `pow` 执行，命中记录写 `phase1.interactive_as_pow`。
- 仍在进行的交互式 C（配置包关闭了交互式，或 SDK 目录换回了 v1）：`/__mg/c/renew` 在第 4 步之后失败并附 `pow` 新 C；`type = interactive` 的提交在第 4 步之后同样失败并附 `pow` 新 C，不读取 `InteractiveConfig`。两者的 reason 都是 `ic.interactive_unavailable`，不计失败。配置包回到 `schema_version = 1` 时，续期端点返回 404（D-66），SDK 重新加载页面（§12.6）。

配置包启用了交互式而 SDK 目录仍是 v1 时，`--check-config` 给出警告，仪表 `mg_interactive_available{site}` 为 0（§15.5）。

### 5.2 `min_level` 与矩阵（D-64）

- 路由要求凭证的条件，改为 `require_clearance ∨ min_level 已设`。
- 有效凭证满足要求的条件：`level_rank(lvl) ≥ challenge_rank(effective_challenge(min_level, interactive_available))`，未设 `min_level` 时为 `invisible`。`effective_challenge` 在交互式不可用时把 `interactive` 降为 `pow`，否则不变；否则 `min_level: interactive` 的路由在交互式不可用时会无休止地重新挑战。三种交互级同为第 3 级（Phase 1 已如此）。
- `matrix.clearance.required` 给出的挑战类型，取 Phase 1 规则（风险段 high 时 `pow`，否则 `invisible`）与 `min_level` 中较高的一个。
- D-20 的"凭证已满足"抑制与刷新判定（§5.7 的 `ChallengeRequired`）按同样的有效类型比较。D-20 的抑制同样适用于限速器发出的挑战：凭证已满足限速器要求的类型时，`on_exceed: challenge` 不再发出挑战。
- 带 `ruc` 的凭证在 `fail_closed` 路由上仍视为级别不足（I-30）。
- 限速器的 `on_exceed: challenge` 可以指定 `interactive`。交互式不可用时，按 `pow` 执行，同 D-08。

### 5.3 失败升级（D-50）

```rust
/// (type, band, attempt_no) of the C attached to a failure response.
pub fn next_challenge_after_failure(prev: ChallengeType, prev_band: RiskBand, prev_attempt: u32,
                                    interactive_available: bool) -> (ChallengeType, RiskBand, u32);
```

| 前一个 C | 交互式可用 | 结果 |
|---|---|---|
| `invisible` / `pow` | 是 | `(interactive, after_failure(band), 1)` |
| `invisible` / `pow` | 否 | `(pow, after_failure(band), 0)`（Phase 1 D-27） |
| `interactive` | 是 | `(interactive, after_failure(band), prev_attempt + 1)` |
| `interactive` | 否 | `(pow, after_failure(band), 0)`（§5.1） |

`attempt_no` 的上限不由这里执行：失败配额 `mg.c.fail`（`ip` 实体）与 `mg.c.fail.prefix` 照旧在 `/__mg/c` 的往返 1 中检查（Phase 1 规格 §9.8）。

### 5.4 Provider 选择（纯函数）

```rust
pub struct SelectionInput<'a> {
    pub country_geo: Option<&'a str>,   // GeoLite2 country of the client IP (None: unknown or no artifact)
    pub country_cf: Option<&'a str>,    // authenticated cf-ipcountry (cloudflare profile, location headers on)
    pub route_id: &'a str,
    pub redact_path: bool,              // any matched route has redact_path
    pub host: &'a str,                  // normalized request host (Phase 1 section 9.4)
    pub attempt_no: u32,                // of the C being issued, 1-based
    pub escalate_after: u32,            // N
    pub a11y_pref: bool,                // cookie __Host-mg_a11y=1 (section 9.5)
    pub turnstile: Option<TurnstileChoice<'a>>,
}
pub struct TurnstileChoice<'a> {
    pub selection: Selection,           // First | EscalateAfterFail
    pub route_ids: &'a [String],
    pub hostnames: &'a [String],
    pub denied_countries: &'a [String],
    pub usable: bool,                   // enabled, secret present, health Healthy or Degraded (section 8.6)
}
pub fn select_providers(input: &SelectionInput<'_>) -> Vec<ProviderId>;
```

规则，按顺序执行：

1. 国家：任一来源为 `CN`，按 CN 处理；两个来源都缺，按"未知"处理。
2. Turnstile 只在以下条件**全部**满足时才可选：
   - `turnstile` 已配置且 `usable`；
   - `route_ids` 为空或包含本路由；
   - 没有任何命中路由带 `redact_path`：这类路由的 URL 可能含一次性令牌，不应让第三方脚本运行在这样的页面上；
   - `host` 精确等于 `hostnames` 之一（小写比较）；
   - 国家已知；两个来源中的任何一个都不是 `CN`，也不在 `denied_countries` 中（两个来源不一致时，任一来源命中即不提供）。

   续期与提交时按当前请求重新判断本条（§7.4、§7.5）。
3. 起点为 `[self_hold, pow_a11y]`。
4. 若 Turnstile 可选，并且 `selection = First`，或者（`selection = EscalateAfterFail` 且 `attempt_no > escalate_after`），则在首位插入 `turnstile`。
5. `attempt_no > escalate_after` 时，把 `pow_a11y` 移到 `self_hold` 之前（在第 4 步插入的 `turnstile` 之后）。
6. `a11y_pref` 时，把 `pow_a11y` 移到首位。

结果总是包含 `self_hold` 与 `pow_a11y`。客户端只能在集合内切换，切换不消费 nonce。提交的 Provider 不在 `C.providers` 中时，提交失败（`ic.provider_not_offered`）。

### 5.5 交互评估（纯函数）

```rust
pub struct InteractionInput<'a> {
    pub provider: ProviderId,           // self_hold | pow_a11y | turnstile
    pub telemetry: &'a IxTelemetry,     // parsed section 7.6 object (pointer fields absent in single / pow_only)
    pub required_hold_ms: u32,          // section 6.3, recomputed from ui_seed
    pub elapsed_ms: u32,                // server clock: body read complete - C.iat
    pub pow_bits: u32,                  // difficulty of the submitted provider (pow.difficulty or pow.a11y_difficulty)
    pub pow_k: u32,
    pub risk_band: RiskBand,
    pub mode: ScoringMode,              // Shadow | Enforce { t_pass, t_block }
}
pub struct InteractionAssessment {
    pub hard_failure: Option<&'static str>,   // first failed hard check of section 7.7, never ic.too_fast
    pub score: f32,                           // 0..1 (section 7.8)
    pub features: BTreeMap<&'static str, f32>,
    pub a11y_mode: A11yMode,                  // None | Single | PowOnly
    pub input_modality: InputModality,
    pub outcome: IxOutcome,                   // Pass | Retry (counts as a failure) | Block
}
/// Expected hashes per millisecond of a desktop browser; pow_too_fast compares pow.ms with k * 2^bits / this.
pub const DESKTOP_HASHES_PER_MS: u64 = 4_000;
/// Server-side minimum time of section 7.7 (hold / single: hold + PoW floor + 250 ms; pow_only: a11y_min_ms).
pub fn min_elapsed_ms(mode: IxMode, required_hold_ms: u32, min_pow_ms: u32, a11y_min_ms: u32) -> u32;
pub fn assess_interaction(input: &InteractionInput<'_>) -> InteractionAssessment;
```

- §7.5 第 6 步只调用 `min_elapsed_ms`（`hold`、`single`、`pow_only` 都适用；提交没有 `ix` 时按 `pow_only`）；第 11 步调用 `assess_interaction`，其 `hard_failure` 不含 `ic.too_fast`。
- `mode = Shadow` 时，`outcome` 只由硬检查决定：通过即 `Pass`，否则 `Retry`。`score` 与 `features` 只写入事件。`Enforce` 时按 §7.8 的阈值决定。

### 5.6 不进入每个请求评分的内容

SDK 遥测与交互特征只影响挑战提交本身（硬检查与评分）；它们对后续请求的影响只经近线 verdict 进入评分（BEHAVIOR 族，03 §3.7）。`RequestContext.client`（`ClientSignals`）在 Phase 2 仍为 `None`，CLIENT 族的探测器照旧缺席。这样，Phase 2 不需要按会话保存遥测的在线状态。

凭证的人类证据：所有级别的 `identity.clearance` 都保持 Phase 1 的 −0.4（D-68）。交互级只在能满足的挑战要求上高于 `pow`（§5.2）。

### 5.7 刷新判定

```rust
pub struct RefreshInput<'a> {
    pub level: TokenLevel,
    pub ruc: bool,
    pub bound: bool,                   // cnf.jkt present and the request's MG-Proof matched it
    pub bind: BindCheck,               // Phase 1 section 6.4: uah, ipp (match / soft_mismatch / mismatch)
    pub level_age_s: u64,              // now - lat
    pub refresh_max_s: u64,            // per level (section 6.8); 0 = this level never refreshes
    pub decision: &'a Decision,        // the Decision Core outcome for select_route(env, GET, "/") (section 9.3)
}
pub enum RefreshDenied { NotRefreshable, Ruc, NotBound, Binding, TooOld, ChallengeRequired(ChallengeType), Blocked }
pub fn refresh_check(input: &RefreshInput<'_>) -> Result<(), RefreshDenied>;
```

判定顺序如下，前一条成立就拒绝：
1. `refresh_max_s = 0` → `NotRefreshable`（`interactive_a11y`、`invisible`，以及 `refresh_max_pow_s = 0` 时的 `pow`）；
2. `ruc` → `Ruc`；
3. `!bound` → `NotBound`；
4. `uah` 不符，或 `ipp` 不是 `match`（软不符也拒绝，否则每次刷新都会把凭证重新绑定到新的前缀）→ `Binding`；
5. `level_age_s > refresh_max_s` → `TooOld`；
6. 决定为 BLOCK 或 RATE_LIMIT → `Blocked`；
7. 决定为 CHALLENGE，且挑战等级高于凭证级别（D-20 的比较）→ `ChallengeRequired(type)`。

都不成立时允许刷新。

## 6. 密码学与协议原语（`mg-challenge`，WP-R5）

所有字节级公式在 `testdata/phase2/kat.json` 中有已知答案向量（§6.11），WP-R5 与 WP-W2 的测试必须逐条通过。Phase 1 的公式（Phase 1 规格 §6）在这里没有重述的部分全部不变。

### 6.1 寿命与 epoch 窗口（改 Phase 1 §6.1、I-18）

| 项 | 规范 |
|---|---|
| 寿命上限 | `invisible` / `pow`：`exp − iat ≤ 120_000` ms（不变）；`interactive`：`exp − iat ≤ 600_000` ms（mg-core 已有的 `SealedChallengeClaims::MAX_INTERACTIVE_LIFETIME_MS`）。Edge 总是签发 600 s 的交互式 C。`seal` 与 `open` 都按类型检查 |
| 接受的 epoch | `e = epoch_no(now)`，`d = now_ms − e · 86_400_000`。接受 `e`；`d ≤ 605_000` 时另接受 `e − 1`（最长寿命 600 s 加 5 s 时钟偏差）；`86_400_000 − d ≤ 5_000` 时另接受 `e + 1`。所有类型共用这一窗口 |
| 向量 | `kat.json` 的 `accepted_epochs`（Phase 2）。`testdata/phase1/kat.json` 的同名部分作废：读取它的测试改为跳过该部分，并注明本条 |

### 6.2 密封 claims 的 Phase 2 规则（`SealedChallengeClaims::check`，字段在 §0.4 落地）

| 类型 | 规则 |
|---|---|
| `invisible` / `pow` | `providers` 为空；`attempt_no = 0`；`ui_seed = 0`；`renew_no = 0`；`pow.alg = "sha256-hashcash-v1"`；`pow.k = 0`；`pow.a11y_difficulty = 0`；寿命 ≤ 120 s |
| `interactive` | `providers` 非空、不重复、包含 `pow_a11y`、是 `{self_hold, pow_a11y, turnstile}` 的子集；`attempt_no ≥ 1`；`ui_seed ≠ 0`；`renew_no ≤ 6`；`pow.alg = "sha256-hashcash-v2"`；`1 ≤ pow.k ≤ 8`；`pow.difficulty ≤ 32` 且 `pow.a11y_difficulty ≤ 32`；寿命 ≤ 600 s |
| 共同 | `bind.jkt` 若有必须是 16 字节；其余同 Phase 1（`uah`、`ipp` 必有，其他绑定字段缺失或 16 字节） |

`len(C) ≤ 1024` 不变。交互式 C 的 claims 最长约 400 字节，base64url 后约 560 字符，留有余量。

### 6.3 `ui_seed` 派生

```
u                = SHA-256("mg-ui-v1" ‖ 0x00 ‖ u64be(ui_seed))
required_hold_ms = 1200 + (u16be(u[0..2]) mod 1301)        // 1200..2500
offset_x_px      = (u[2] mod 33) − 16                      // −16..16
offset_y_px      = (u[3] mod 17) − 8                       // −8..8
```

按住时长的范围是常量，不进配置包：C 签发后配置包可能变化，服务端重算的结果必须与签发时一致。

### 6.4 PoW v2（D-43）

```
prefix2   = "mg-pow-v2" ‖ 0x00 ‖ SHA-256(C as ASCII)                 // 42 bytes
digest_i  = SHA-256(prefix2 ‖ u8(i) ‖ u64be(counter_i)),  i = 0 .. k−1  // a 51-byte message: one compression
solved    ⇔ ∀ i: leading_zero_bits(digest_i) ≥ d  and  counter_i < 2^53
d         = pow.a11y_difficulty when the submitted provider is pow_a11y, else pow.difficulty
```

- 提交的 `pow.counters` 恰好有 `k` 项，依次对应 `i = 0 .. k−1`。
- 参考求解器（`#[doc(hidden)]`，只用于测试）对每个子题从 0 开始逐个尝试，所以求得的第一个解是规范解，向量据此给出。
- 期望工作量是 `k · 2^d` 次哈希。缺省难度见 §10.2，数值按 monitor / shadow 期间的 `pow_solve_ms` 遥测校准。

### 6.5 会话公钥、指纹与 ES256

| 项 | 规范 |
|---|---|
| JWK | JSON 对象，**恰好**有 `kty = "EC"`、`crv = "P-256"`、`x`、`y` 四个成员。`x`、`y` 是无填充 base64url，各自解码为 32 字节。其他成员（包括 WebCrypto 导出时带的 `ext`、`key_ops`）一律拒绝，SDK 只发送这四个成员。点是否在曲线上，在验签时一并检查：以 `0x04 ‖ x ‖ y` 交给 `aws-lc-rs`，无效的点与无效的签名同样失败 |
| 指纹 `jkt` | RFC 7638：`base64url_nopad(SHA-256('{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}'))`，43 字符（成员按字典序，无空白） |
| C 中的绑定 | `bind.jkt = bind_hash("jkt", jkt)`（Phase 1 规格 §6.4 的 `bind_hash`） |
| 签名 | ES256：ECDSA P-256 + SHA-256。签名为 64 字节 `r ‖ s`（IEEE P1363，WebCrypto 的输出格式），以无填充 base64url 传输（86 字符）。DER 编码拒绝；高 S 值接受（WebCrypto 不做规范化），签名本身从不作为标识使用 |

### 6.6 提交签名与续期签名

```
lp(x) = u16be(len(x)) ‖ x            (x ≤ 65535 bytes; strings as UTF-8)
H(x)  = SHA-256(x)

submission (mg-sub-v2):
  "mg-sub-v2" ‖ 0x00 ‖ lp(c) ‖ lp(type) ‖ lp(p) ‖ lp(H(pp)) ‖ lp(H(t)) ‖ lp(counters) ‖ lp(ret) ‖ u64be(ts) ‖ lp(build)
renew (mg-renew-v1):
  "mg-renew-v1" ‖ 0x00 ‖ lp(c) ‖ u64be(ts)
```

- `c`、`type`、`p`、`ret`、`build` 是提交中的字符串。`p` 在非交互式提交中为空串。
- `pp` 与 `t` 是提交中两个**字符串字段**的 UTF-8 字节，即 JSON 解码后的值；缺省为空串。两边对同一串字节求哈希，不需要 JSON 规范化。
- `counters` 是十进制计数器以 `,` 连接的串，不含空格，例如 `387,10648`。
- `ts` 是提交中的客户端毫秒时间，只作特征。
- 签名用提交中的 `jwk` 验证（§7.5 第 8 步）。

### 6.7 `MG-Proof` 校验（D-40；Edge 接线见 §9.1）

**格式**：

- 请求头 `MG-Proof` 恰好一个，值是紧凑 JWS `B64(header) "." B64(payload) "." B64(sig)`。各段为无填充 base64url，总长 ≤ 4096 字节。
- `header` 恰好为 `{"alg":"ES256","typ":"mg-proof+jwt","jwk":<§6.5 的 JWK>}`，成员顺序不限，不得有其他成员。
- `payload` 恰好有以下四个成员：
  - `htm`：浏览器实际发出的方法字符串，≤ 32 字节。fetch 只把 `DELETE`、`GET`、`HEAD`、`OPTIONS`、`POST`、`PUT` 规范化为大写，其他方法（如 `patch`）保持原样，SDK 按同样的规则计算；
  - `htu`：`https://<host><path>`，≤ 2048 字节，不含 userinfo；可以带查询串与片段，校验时忽略；
  - `iat`：整数，Unix 秒；
  - `jti`：16 字节的无填充 base64url，即 22 个字符。
- 签名输入是 `B64(header) "." B64(payload)` 的 ASCII 字节。

**检查**按顺序执行，便宜的检查在前，任一失败即返回对应原因：

1. 格式与大小，JSON 解析（拒绝重复键与未知成员）→ `proof.malformed`；
2. 请求没有有效凭证，或凭证没有 `cnf.jkt` → `proof.unbound`。这一步不做任何椭圆曲线运算；
3. 用 JWK 的 `x`、`y` 文本按 §6.5 计算指纹（只做 SHA-256），与凭证的 `cnf.jkt` 比较，不等 → `proof.jkt`；
4. `htm` 与请求方法字符串不等（区分大小写）→ `proof.htm`；
5. `htu` → `proof.htu`：
   - scheme 必须是 `https`，且请求的有效 scheme 也是 `https`（`cloudflare` profile 下来自认证过的 `CF-Visitor`，`direct_tls` 下为 `https`）；
   - 主机按 RFC 3986 拆出（不允许 userinfo；IP 字面量与端口原样比较），按 Phase 1 规格 §9.4 规范化后，必须等于请求的规范化主机；
   - 路径取 `htu` 中第一个 `?` 或 `#` 之前的原文，不做点段或百分号规范化；它与请求的原始路径两边都取 `mg_core::paths::cloudflare_view` 后比较；
6. `iat < now − 30` 或 `iat > now + 5` → `proof.iat`；
7. ES256 签名（含 JWK 的点是否在曲线上）→ `proof.sig`。

JWK 的成员与长度在第 1 步检查（`proof.malformed`）。

通过后返回 `{jti, iat}`。`jti` 的防重放与按密钥的配额由 Edge 完成（§9.2，`proof.replay`）。

### 6.8 清关凭证 v2（D-46；改 Phase 1 §6.5、§6.6）

```json
{"v":2,"kid":"blog-t-20261012","sid":"blog","env":"production","sub":"<b64url 16>","sst":1790000000,
 "lvl":"interactive","iat":1790000000,"exp":1790001800,"lat":1790000000,
 "cnf":{"jkt":"<43-char thumbprint>"},
 "bind":{"uah":"…","ipp":"…","ipa":"…"},"rb":"medium","jti":"<b64url 16>"}
```

| 项 | 规范 |
|---|---|
| 版本 | `v = 1` 的载荷与 Phase 1 完全相同，不得含 `lat`、`cnf`。`v = 2` 必须含 `lat`（`sst ≤ lat ≤ iat`），可含 `cnf`：一个对象，恰好有一个成员 `jkt`，值为 43 字符的无填充 base64url。两个版本都可含 `ruc`（I-30），都拒绝未知字段 |
| 签发哪个版本 | 有 `cnf`、`lvl ∉ {invisible, pow}` 或 `lat ≠ iat`（刷新得到的凭证）时签发 v2，否则签发 v1。`schema_version = 1` 时只签发 v1（D-66）。Edge 二进制回滚到 Phase 1 时，只有用到 Phase 2 功能的凭证失效 |
| 有效期 | 按级别：`invisible` 用 `ttl_invisible_s`、`pow` 用 `ttl_pow_s`、`interactive` 用 `ttl_interactive_s`、`interactive_a11y` 用 `ttl_interactive_a11y_s`、`interactive_ext:*` 用 `ttl_interactive_ext_s`（§10.2）。`exp − iat ≤ 86400` 不变 |
| 刷新 | 新凭证的 `exp = min(now + ttl(lvl), sst + session_max_s)`；`exp − now < 60` 时拒绝刷新，结果记 `too_old`（由 Edge 在 `refresh_check` 通过之后检查，§9.3）。原样保留 `sub`、`sst`、`lat`、`lvl`、`cnf`、`rb`、`bind`、`sid`、`env`；`kid` 取当前的 `token_key_ids[0]`；`jti` 新生成。刷新上限按级别：`interactive` 用 `refresh_max_interactive_s`，`interactive_ext:*` 用 `refresh_max_ext_s`，`pow` 用 `refresh_max_pow_s`，`interactive_a11y` 与 `invisible` 不可刷新（D-47） |
| 校验 | Phase 1 §6.5 的步骤，加上：`v ∈ {1, 2}`、v2 的规则、`cnf.jkt` 的形状。状态映射不变 |
| `sub` / `sst` 复用 | Phase 1 §6.5 的规则，另要求：新提交的 `jkt` 与旧凭证的 `cnf.jkt` 相同，或旧凭证没有 `cnf`；并且该 `sub` 没有生效的近线会话 verdict（`/__mg/c` 的往返 1 另读 `mg:v:{site}:session:{sub}`，§14.3）。否则开始新会话 |
| 状态 Cookie | `schema_version = 2` 时，与 `__Host-mg_clr` 一起设置 `__Host-mg_st=<iat>.<exp>.<b>; Max-Age=<同上>; Path=/; Secure; SameSite=Lax`（**不带** HttpOnly），写在 `__Host-mg_clr` 之后。`iat` 与 `exp` 为凭证的十进制 Unix 秒，`b` 为 `1`（凭证带 `cnf`）或 `0`。它不含级别与秘密，只供 SDK 安排刷新、判断 Cookie 是否可用；Edge 从不读取它做判定，它也不进入 `http.cookie_names`、事件与 `mg:ev`（§9.5） |

### 6.9 Turnstile `cData` 与幂等键

```
k_bind          = derive_bind_epoch_key(root, site_id, epoch of C.kid)     (Phase 1 section 6.1, label "mg-bind-v1")
cdata           = base64url_nopad(HMAC-SHA256(k_bind, "mg-ts-cdata-v1" ‖ 0x00 ‖ lp(site_id) ‖ lp(nonce)))   // 43 chars
idempotency_key = uuid_v4_format(SHA-256("mg-ts-idem-v1" ‖ 0x00 ‖ nonce)[0..16])
```

- 签发时用 `roots[0]` 计算 `cdata`。校验时对每个根各算一次，任一相等即通过；比较为常量时间。
- `uuid_v4_format`：把字节 6 的高 4 位置为 `0100`，字节 8 的高 2 位置为 `10`，再按 8-4-4-4-12 的小写十六进制输出。
- 用旧 secret 重试时（§8.4），幂等键改用 `uuid_v4_format(SHA-256("mg-ts-idem-v1" ‖ 0x00 ‖ nonce ‖ 0x01)[0..16])`，以免 Cloudflare 按幂等键返回缓存的结果。

### 6.10 公共 API（新增与改变）

```rust
// challenge/src/keys.rs (changed): MAX_C_LIFETIME_MS stays 120_000 for invisible / pow; interactive C use
// mg_core::SealedChallengeClaims::MAX_INTERACTIVE_LIFETIME_MS (600_000); seal and open check per type
pub fn accepted_epochs(now_ms: i64) -> std::ops::RangeInclusive<u64>;          // section 6.1 window
// challenge/src/sealed.rs (new items; Sealer::open and OpenError unchanged)
pub const RENEW_MAX_EXPIRED_MS: i64 = 3_600_000;
pub enum RenewOpenError { TooOld, Open(OpenError) }
impl Sealer {
    /// Opens an interactive C for /__mg/c/renew (section 7.4 step 4): as open, but the epochs of
    /// now_ms - RENEW_MAX_EXPIRED_MS are accepted too and a C that expired at most that long ago opens.
    /// Returns the claims and whether the C has expired; an older C (or an older epoch) is TooOld.
    pub fn open_for_renew(&self, c: &str, host: &str, now_ms: i64)
        -> Result<(SealedChallengeClaims, bool), RenewOpenError>;
}
// challenge/src/ui.rs
pub struct UiParams { pub required_hold_ms: u32, pub offset_x_px: i8, pub offset_y_px: i8 }
pub fn ui_params(ui_seed: u64) -> UiParams;
// challenge/src/pow.rs
pub const POW_ALG_V2: &str = "sha256-hashcash-v2";
pub const MAX_POW_K: usize = 8;
pub fn pow_prefix_v2(c: &str) -> [u8; 42];
pub fn pow_verify_v2(c: &str, difficulty: u32, counters: &[u64]) -> bool;   // false if counters.len() not in 1..=8
#[doc(hidden)] pub fn pow_solve_v2(c: &str, difficulty: u32, k: usize, max_iterations: u64) -> Option<Vec<u64>>;
// challenge/src/jwk.rs
pub struct SessionKey { /* 65-byte uncompressed point + thumbprint; verified through aws-lc-rs */ }
impl SessionKey {
    pub fn from_jwk_json(json: &[u8]) -> Result<Self, JwkError>;              // section 6.5, strict members
    pub fn thumbprint(&self) -> &str;                                         // 43 chars
    pub fn verify_es256(&self, msg: &[u8], sig_b64url: &str) -> bool;         // 64-byte r||s only
}
// challenge/src/sig.rs
pub struct SubmissionFields<'a> { pub c: &'a str, pub ty: &'a str, pub p: &'a str, pub pp: &'a str, pub t: &'a str,
                                  pub counters: &'a [u64], pub ret: &'a str, pub ts: u64, pub build: &'a str }
pub fn submission_message(f: &SubmissionFields<'_>) -> Vec<u8>;
pub fn renew_message(c: &str, ts: u64) -> Vec<u8>;
// challenge/src/proof.rs
pub struct ProofRequest<'a> { pub method: &'a str, pub scheme: &'a str, pub host: &'a str, pub path: &'a str,
                              pub now_s: i64, pub expected_jkt: Option<&'a str> }
pub struct VerifiedProof { pub jti: [u8; 16], pub iat: i64 }
pub enum ProofError { Malformed, Unbound, Jkt, Htm, Htu, Iat, Sig }
impl ProofError { pub fn reason_code(&self) -> &'static str; }               // proof.*
pub fn verify_proof(header: &str, req: &ProofRequest<'_>) -> Result<VerifiedProof, ProofError>;
// challenge/src/clearance.rs (changed)
pub const CLAIMS_V1: u32 = 1; pub const CLAIMS_V2: u32 = 2;
pub struct ClearanceClaims { /* v1 fields */ pub lat: Option<i64>, pub cnf: Option<Cnf>, pub ruc: bool }
pub struct Cnf { pub jkt: String }
// MintParams and mint stay unchanged until the E2a / E2b switch (section 2.3); v2 goes through new items
pub struct MintV2Params<'a> { pub base: MintParams<'a>, pub cnf_jkt: Option<&'a str>, pub lat: Option<i64>,
                              pub allow_v2: bool }                            // allow_v2 = schema_version 2
pub fn mint_v2(keys: &TokenKeySet, site_id: &str, p: &MintV2Params<'_>, rng: &dyn Rng)
    -> Result<(String, ClearanceClaims), TokenError>;                        // version rule of section 6.8
pub fn mint_refresh(keys: &TokenKeySet, site_id: &str, old: &ClearanceClaims, now_s: i64, ttl_s: u32,
                    session_max_s: u32, rng: &dyn Rng) -> Result<(String, ClearanceClaims), TokenError>;
                                                                             // section 6.8 refresh row; no 60 s rule
pub fn status_cookie_value(iat: i64, exp: i64, bound: bool) -> String;     // "<iat>.<exp>.<b>"
// challenge/src/turnstile.rs
pub fn turnstile_cdata(root: &SealRoot, site_id: &str, epoch: u64, nonce: &[u8; 16]) -> String;
pub fn turnstile_cdata_matches(keys: &SealKeys, site_id: &str, epoch: u64, nonce: &[u8; 16], cdata: &str) -> bool;
pub fn idempotency_key(nonce: &[u8; 16], previous_secret: bool) -> String;
```

### 6.11 测试与已知答案向量

`testdata/phase2/kat.json`（`version: 1`）包含下列部分。每个 ECDSA 向量由生成器用固定的测试私钥签出，只用于验签。

| 部分 | 内容 |
|---|---|
| `accepted_epochs` | 日界后 0、125.001、605.000、605.001 s，日界前 5.000、5.001 s |
| `ui_params` | 不少于 8 个 `ui_seed`（含 1 与 `u64::MAX`）及其三个派生值 |
| `pow_v2` | `(C, d, k)` → 规范计数器与每个 `digest_i`；k = 1..4 |
| `jwk_thumbprint` | RFC 7638 §3.1 的示例（RSA，仅作公式核对），以及 4 个 P-256 公钥 |
| `es256` | 有效签名；改一字节的消息；高 S 的等价签名（必须接受）；DER 编码（必须拒绝）；不在曲线上的点 |
| `submission_message`、`renew_message` | 字段 → 十六进制消息字节 |
| `mg_proof` | 有效证明，以及每个 `ProofError` 各一个反例：重复键、未知成员、多余的 `ext` 成员、`iat` 的边界 −30 s / +5 s、非 ASCII 路径、`%2F`、点段、IP 字面量、带端口的主机、userinfo、小写的 `patch`。反例按 §6.7 的新顺序给出原因码 |
| `cdata`、`idempotency_key`（含旧 secret 的变体）、`bind_jkt` | 输入 → 输出 |

另需测试：
- 交互式 C 的 `seal` → `open` 往返；§6.2 每条规则各一个反例；
- 600 s 边界、`renew_no = 7`、`k = 9`；`open_for_renew` 的 1 小时边界与跨日界的旧 epoch；
- 凭证 v1 / v2 的往返，v1 带 `lat` 或 v2 缺 `lat` 时为 `invalid`；
- `sub` 复用在 `jkt` 变化时开始新会话；
- 全部解析器（JWK、`MG-Proof`、凭证 v2）的随机输入不 panic（§2.4）。

## 7. 交互式挑战（WP-E2a 接线；评估函数归 WP-R4）

### 7.1 何时签发与 C 的内容

满足 `interactive_available`（§5.1），并且出现以下任一情况时签发交互式 C：
- 决定为 `CHALLENGE(interactive)`，来源可以是矩阵的 `matrix.critical.high`、策略规则、限速器，或 `min_level = interactive`；
- 失败升级（§5.3）；
- `/__mg/v` 按 D-58 取得的类型为交互式。

Phase 1 的前置规则照旧：客户端 IP 未知时返回 429 且不签发（D-23）；http 访客的 GET / HEAD 先 308 到 https（D-32）。

| 字段 | 取值 |
|---|---|
| `type` | `interactive` |
| `providers` | `select_providers(…)`（§5.4） |
| `risk_band` | 挑战前的风险段；失败升级时按 §5.3 |
| `attempt_no` | 首次为 1，失败升级时按 §5.3 |
| `renew_no` | 0 |
| `ui_seed` | 64 位随机数（`getrandom`），为 0 时重取 |
| `iat` / `exp` | `now` / `now + 600_000` |
| `pow` | `{alg: "sha256-hashcash-v2", difficulty: interactive.pow_bits[risk_band], k: interactive.pow_k, a11y_difficulty: interactive.a11y_bits}` |
| `ret` | Phase 1 规则（GET / HEAD 取原始路径与查询串，其他方法取 `fallback_ret`） |
| `bind` | `uah`、`ipp`、`ipa`、`ctp` 同 Phase 1；`jkt`：仅当触发请求带有效 `MG-Proof` 时，为其公钥指纹的 `bind_hash`（D-41） |

签发受进程内限速器 `mg.ix.issue` 约束（D-67）：按 `ip` 实体超限时返回 429 + `Retry-After`；按 `ipp`（4 倍）超限只计数，不拒绝签发。参数见 §7.9。它不需要 Valkey 往返：交互式 C 不写状态，囤积的 C 只有 10 分钟价值，限速只是防止大量囤积。

### 7.2 明文参数 `ix`（D-44）

```json
{"v": 1, "providers": ["self_hold", "pow_a11y"], "hold_ms": 1834, "offset": [-3, 5], "min_ms": 2084, "a11y_min_ms": 2000,
 "pow": {"alg": "sha256-hashcash-v2", "k": 8, "bits": 16, "a11y_bits": 17},
 "attempt": 1, "now_ms": 1790000000123, "exp_ms": 1790000600123, "bound": false,
 "a11y_first": false, "a11y_quota": false,
 "turnstile": {"sitekey": "<public sitekey>", "action": "login", "cdata": "<43 chars>", "lang": "zh-cn"}}
```

- `ix` 由 Edge（WP-E2a）组装：`hold_ms` 与 `offset` 来自 `mg_challenge::ui_params(ui_seed)`（§6.3）；`pow`、`attempt`、`exp_ms`、`bound` 来自 C；`now_ms` 来自服务端时钟；`turnstile` 来自配置包与 §6.9。mg-core 的 Provider 只返回 `ChallengeSpec { provider, params: {} }`。
- `min_ms = hold_ms + min_pow_ms + 250`：SDK 不早于"收到该 C 的本地时刻 + `min_ms` + 100 ms"提交，避免 §7.7 的时间窗把正常用户判为过快。`pow_a11y` 的下限为 `a11y_min_ms`，SDK 从配置无从得知，所以 `ix` 另给出 `a11y_min_ms`（省略时为 0）。
- `now_ms` 等于 `C.iat`，是服务端时间；SDK 用它估计时钟偏差、安排续期。
- `bound` 表示 C 是否已绑定会话密钥（D-41）。`a11y_first` 表示 `providers[0] = pow_a11y`（偏好 Cookie 或 `attempt_no > N`）。`a11y_quota` 表示 `mg.a11y.issue` 已超限（§7.9），SDK 据此把单次激活放在首位。
- `turnstile` 只在 `providers` 含 `turnstile` 时出现。`lang` 为 `zh-cn`（页面语言为 zh-CN）或 `en`。
- 序列化后 ≤ 1024 字节。
- `ix` 不含秘密，客户端改动它不会带来任何好处：服务端一律从 C 重算。

### 7.3 挑战页与 JSON 挑战

- **HTML**：用 SDK 目录中的模板 v2 渲染（§12.3）。`{{type}} = interactive`；`{{pow_bits}}` 为 `pow.difficulty`（交互式页面上 SDK 忽略它，以 `ix` 为准）；`{{ix}}` 为 `ix` 的 JSON，按 HTML 属性值转义。CSP 同 Phase 1 规格 §10.2；提供了 Turnstile 时按 §8.3 追加。
- **JSON**（非导航请求）：403，`MG-Challenge: interactive`：

```json
{"v": 2, "error": "mg_challenge", "type": "interactive", "challenge": "<C>", "ix": {"...": "..."},
 "ret": "/account/login", "retry": true, "request_id": "<id>"}
```

非交互式的 JSON 挑战与 Phase 1 相同，只多一个 `"v": 2`。SDK 遇到交互式 JSON 挑战时，跳转 `/__mg/v?ret=<页面路径>&min=interactive`（D-57、D-58），不在页内渲染。

页面语言：`Accept-Language` 的第一个语言标签以 `zh` 开头时为 zh-CN，以 `en` 开头时为 en，其他情况取 `challenge.default_lang`（改 Phase 1 规格 §11.2 的"其余为 en"）。

### 7.4 `POST /__mg/c/renew`：续期与首次绑定（D-41、D-42）

**请求**：只接受 `application/json`（`charset` 若有必须是 `utf-8`），≤ 8 KiB：

```json
{"v": 2, "c": "<C>", "jwk": {"kty": "EC", "crv": "P-256", "x": "…", "y": "…"}, "ts": 1790000000123, "sig": "<86 chars>"}
```

**检查顺序**（"失败"均为 403 `mg_challenge_failed` 的 JSON；失败附的"新 C"按 §5.3 与 §7.1 签发，即与提交失败一样升级 `attempt_no`）：

| # | 检查 | 结果 |
|---|---|---|
| 0 | 客户端 IP 未知 | 429 + `Retry-After: 5` |
| 1 | `Early-Data` | 425 |
| 2 | 进程内限速器 `mg.c.renew`（两级，D-67） | 429（`ic.rate_limited`） |
| 3 | 请求体与字段规则（同 §7.5 的 JSON 规则） | 失败，不附新 C（`ic.body`，计失败） |
| 4 | `Sealer::open_for_renew`（§6.10）：以"允许过期"的方式打开 C（声明 `interactive`），过期不超过 1 小时的 C 仍能打开 | 过期超过 1 小时（`TooOld`，例如标签页休眠了半天）：失败，不附新 C，不计失败（`ic.c_expired`），SDK 重新加载页面；其他无法打开的情况：失败，不附新 C（`ic.c_invalid` / `ic.c_kid`，计失败） |
| 4a | 交互式不可用（§5.1） | 失败并附 `pow` 新 C（`ic.interactive_unavailable`，不计失败），不做第 5–9 步 |
| 4b | 旧 C 的 `renew_no ≥ 1`（不是首次绑定）时，进程内限速器 `mg.ix.issue`（两级） | `ip` 实体超限：429（`ic.rate_limited`）；`ipp` 超限只计数 |
| 5 | 绑定 `uah`；C 已有 `bind.jkt` 时，`jwk` 的指纹必须与之一致；`ipp`：C 未绑定密钥时必须匹配（含 Phase 1 的软结果），C 已绑定密钥时允许变化（同一把密钥换了网络，例如 Wi-Fi 与蜂窝网络切换），新 C 绑定当前请求 | `ic.bind_uah` / `ic.bind_jkt` 计失败并附新 C；未绑定 C 的 `ic.bind_ipp` 计失败并附新 C；已绑定 C 的前缀变化不算失败，记 `outcome = renew_rebind` |
| 6 | 用 `jwk` 验证续期签名（§6.6） | `ic.sig`，计失败，附新 C |
| 7 | 消费旧 nonce：`mg_nonce_issue` v2，不带重放键与限速器（§14.2） | 已用过：`ic.nonce_reused`，不计失败（续期在后台进行，响应可能丢失），**不附新 C**（否则一个旧 C 能续出多个新 C），SDK 重新加载页面（§12.6）；重放存储不可用：429 + `Retry-After: 5`（`ic.replay_unavailable`）。第 8、9 步从不在未消费旧 nonce 的情况下签发 C |
| 8 | C 已过期（例如标签页休眠）或 `renew_no = 6` | 失败并附新 C（`ic.c_expired` / `ic.renew_cap`，不计失败）。新 C 继承 `route_class`、`ret`、`risk_band`、`attempt_no`、`ui_seed` 与 `bind.jkt`（按住时长与按钮位置不变），`renew_no = 0`，Provider 按当前请求重新选择 |
| 9 | 签发续期的 C：继承 `type`、`risk_band`、`attempt_no`、`ret`、`ui_seed`、`pow`；Provider 沿用，但按当前请求重新执行 §5.4 第 2 条，不再满足时去掉 `turnstile`；`renew_no + 1`；新 nonce、`iat`、`exp`；`bind.uah` / `ipp` / `ipa` / `ctp` 取当前请求；`bind.jkt` = `jwk` 的指纹 | 200 `{"v": 2, "challenge": "<C>", "ix": {…}}` |

- 过期与到顶的 C 同样要经过第 5–7 步：一个旧 C 只能续出一个新 C，不能被反复分叉。第 5、6 步失败时附的新 C 已按 §5.3 升级，绑定发出请求的客户端，与重新请求页面得到的 C 相比没有任何好处；旧 C 仍归它原来的持有者。
- 首次绑定的续期（`renew_no` 从 0 到 1）不计入 `mg.ix.issue`（第 4b 步），其余续期计入。
- SDK 对任何 `ix.bound = false` 的 C，在装入后、用户操作之前先续期一次（D-41）：不只页面加载时，也包括失败响应与续期失败附带的新 C。之后在 `iat + 480 s` 之后、控件处于 `READY`、`WAIT` 或 `EXTERNAL` 时续期。
- 续期的任何结果都不改变控件上的状态文字（§12.6）。
- 一条链最多 6 次续期，约 1 小时。
- 续期不计入失败次数，第 3–6 步的失败除外（已绑定 C 的前缀变化不算失败）。
- 计 `mg_challenge_renew_total{result}`（§15.5）。

### 7.5 `POST /__mg/c` v2

**编码**：同 Phase 1 规格 §10.3，即表单字段 `mg` 或 `application/json`。交互式提交由 SDK 用 fetch 以 JSON 发送（§12.6），这样失败、新 C 与 429 都能在控件内处理，不需要整页刷新。非交互式提交照旧用表单导航。

```json
{"v": 2, "type": "interactive", "c": "<C>", "p": "self_hold", "pp": "",
 "t": "{\"env\":{…},\"auto\":{…},\"ix\":{…}}",
 "pow": {"counters": [12, 3401, 77, 912, 4005, 18, 230, 6600]}, "ret": "/account/login",
 "ts": 1790000000123, "build": "<hex16>",
 "jwk": {"kty": "EC", "crv": "P-256", "x": "…", "y": "…"}, "sig": "<86 chars>"}
```

| 字段 | 规则 |
|---|---|
| `v` | 2。`v = 1` 的提交按 Phase 1 规则接受，只用于 `invisible` / `pow`（交互式的 v1 提交 → `ic.body`），签发的凭证没有 `cnf`；但 C 带 `bind.jkt` 时，`v = 1` 以及缺 `jwk` 或 `sig` 的提交一律失败（`ic.bind_jkt`，计失败）。v1 提交失败附的新 C 按 §5.3。v2 提交只读 `t` 中的 `env` / `auto`，顶层的 `env` / `auto` 忽略 |
| `type` | `invisible` / `pow` / `interactive`，用于 aad |
| `p` | 交互式：Provider id，必须在 `C.providers` 中；其他类型：空串或缺省 |
| `pp` | 字符串，≤ 4096 字节；Turnstile 时为其 token（≤ 2048 字符），其他 Provider 为空串 |
| `t` | 字符串，≤ 2048 字节，内容是一个 JSON 对象：`env`、`auto`（Phase 1 的 schema）与 `ix`（§7.6），各自可缺省。`t` 内的 JSON 适用与请求体相同的规则（UTF-8、嵌套 ≤ 16、对象键不得重复） |
| `pow.counters` | 每项为 `< 2^53` 的非负整数。第 3 步只检查项数：v1 恰好 1 项，v2 为 1–8 项；项数与 C 的 `pow.k` 不等时在第 9 步报 `ic.pow` |
| `ts` | v2：`0..2^53` 的整数（签名用 `u64be(ts)`），否则 `ic.body`；v1 同 Phase 1 |
| `ret`、`build`、`c` | 同 Phase 1 |
| `jwk`、`sig` | v2 必有：§6.5 的 JWK 与 §6.6 的提交签名 |
| JSON 整体 | 同 Phase 1：UTF-8、嵌套 ≤ 16、对象键不得重复、顶层未知字段忽略；整个请求体 ≤ 8 KiB |

**检查顺序**（04 §4.1 的完整形式；"交互式"行只用于交互式）：

| # | 检查 | 失败 |
|---|---|---|
| 0 | 客户端 IP 未知 | 429（`ic.no_client_ip`），不计失败 |
| 1 | `Early-Data` | 425（`ic.too_early`） |
| 2 | 往返 1：`mg.c.submit`、`mg.c.fail` / `mg.c.fail.prefix`（只检查）、`mg.clr.issue.ipp` / `asn`（只检查）、`mg.a11y.issue` 的两级（只检查，不论 `p`；第 3 步得知 `p` 之后才使用其结果）；另 `MGET` 所带旧凭证的会话 verdict `mg:v:{site}:session:{sub}`（§6.8） | 429（`ic.rate_limited` / `ic.issue_quota`） |
| 3 | 请求体、字段规则；`t` 解析为 JSON 对象 | 统一失败（`ic.body`），不附新 C |
| 4 | 打开 C | 统一失败（`ic.c_*`），不附新 C |
| 4a | `type = interactive` 而交互式不可用（§5.1） | 统一失败并附 `pow` 新 C（`ic.interactive_unavailable`，不计失败），不读取 `InteractiveConfig` |
| 5 | 交互式：`p ∈ C.providers`；`p = turnstile` 时，还要按当前请求满足 §5.4 第 2 条（国家、主机、路由），不满足则不调用 siteverify、不计失败；`p = pow_a11y` 且第 2 步的 `mg.a11y.issue` 超限时，返回统一失败并附新 C，不校验 PoW、不消费 nonce、不计失败，新 C 的 `ix.a11y_quota = true`（SDK 把单次激活放在首位） | `ic.provider_not_offered`（turnstile 的这种情况不计失败）；`ic.a11y_quota` |
| 6 | 交互式：最短时间窗 `elapsed_ms ≥ min_elapsed_ms(…)`（§5.5、§7.7；提交没有 `ix` 时按 `pow_only`） | `ic.too_fast` |
| 7 | 绑定 `uah` / `ipp`；C 有 `bind.jkt` 时 `jwk` 的指纹必须一致 | `ic.bind_uah` / `ic.bind_ipp` / `ic.bind_jkt` |
| 8 | v2：JWK 与签名 | `ic.sig` |
| 9 | PoW（v1 或 v2；v2 的难度按 `p` 选择，§6.4） | `ic.pow` |
| 10 | `ret` | `ic.ret` |
| 11 | 基础环境（Phase 1 第 8 步：`ic.automation_flag`、`ic.ua_mismatch`，只读 `t` 中的 `env` / `auto`）；交互式：`assess_interaction` 的其余硬检查（§7.7） | 各自的 reason |
| 12 | 往返 2：`mg_nonce_issue` v2：nonce、签发配额（`p = pow_a11y` 时含 `mg.a11y.issue` 的两级），`p = turnstile` 时另含 token 重放键（§14.2） | `ic.nonce_reused`；`ic.ts_dup`；配额 429；重放存储不可用按 Phase 1 规格 §9.7 第 4、5 条 |
| 13 | 交互式且 `p = turnstile`：siteverify（§8.4），截止时间为 `min(timeout_ms, 5000)` | §8.5 |
| 14 | 交互式：评估（§7.8）；`mode = enforce` 时按阈值 | `Retry` → `ic.score_high`；`Block` → 429（`ic.score_block`） |
| 15 | 签发凭证：`lvl` 按 `p`（`self_hold` → `interactive`，`pow_a11y` → `interactive_a11y`，`turnstile` → `interactive_ext:turnstile`；非交互式同 Phase 1）；v2 时 `cnf.jkt` 为 `jwk` 的指纹；`lat = now`；`sub` / `sst` 按 §6.8 复用；设置 `__Host-mg_clr`，`schema_version = 2` 时另设 `__Host-mg_st`；`p = pow_a11y` 时写入 `__Host-mg_a11y`，`p = self_hold` 且请求带着它时删除（§9.5） | 随机数失败 → 503 |

**响应**：
- 成功：导航提交 303，同 Phase 1；fetch 提交 200 `{"ok": true, "ret": "…", "v": 2, "now_ms": …}`。Cookie 见第 15 步。
- 第 5 步及之后的统一失败：附新 C。新 C 的类型、`attempt_no` 与 `risk_band` 按 §5.3。交互式的新 C 带新的 `ui_seed`，并重新选择 Provider；JSON 中带 `ix`。提交的签名已通过第 8 步时，新 C 带该 `jwk` 的 `bind.jkt`，SDK 不必再做绑定续期。
- 配额与限速：429，同 Phase 1。

**计为失败**（写入 `mg.c.fail` / `mg.c.fail.prefix`）的 reason：
- Phase 1 的全部；
- `ic.provider_not_offered`、`ic.too_fast`、`ic.bind_jkt`、`ic.sig`、`ic.ix_mode`、`ic.hold_short`、`ic.hold_long`、`ic.no_trusted_input`、`ic.score_high`；
- `mode = enforce` 时的 `ic.ts_fail`、`ic.ts_hostname`、`ic.ts_action`、`ic.ts_cdata`、`ic.ts_time`、`ic.ts_dup`。

**不计**：
- Phase 1 的不计项；
- `ic.renew_cap`、`ic.interactive_unavailable`；
- `ic.provider_unavailable`、`ic.provider_misconfigured`；
- `mode = shadow` 时 Turnstile 的全部失败（D-51 / 09 §6.3：shadow 下只回退）；
- `ic.a11y_quota`：附新 C 的统一失败，访客改用其他路径；
- `ic.score_block`：它是 429，本身就是限额。

### 7.6 交互遥测 `t.ix`（v1，SDK 端量化）

```json
{"v": 1, "mode": "hold", "modality": "mouse", "locale": "zh-CN", "ks": "idb", "sv": "0.3.0", "fallback": null,
 "trusted": 3, "act_ms": 2300,
 "pre":    {"moves": 5, "path_px": 9, "straight": 0.7, "speed_mean": 6, "speed_sd": 4, "dir_changes": 3,
            "render_to_input_ms": 11, "to_target_ms": 9},
 "hold":   {"ms": 1910, "offset": [0.1, -0.2], "jitter_px": 2, "moves": 3, "cancels": 0,
            "pressure": 0.5, "pressure_var": 0, "contact_var": 0},
 "single": {"wait_ms": 1880},
 "page":   {"vis": 0, "vis_during": 0, "focus": 0, "frame_mean": 4, "frame_sd": 1},
 "pow":    {"ms": 8, "worker": true, "impl": "js"}}
```

| 字段 | 取值与量化 |
|---|---|
| `mode` | `hold`（指针按住）、`single`（单次激活：键盘、读屏合成的点击、短按或"无法按住？"，D-65）、`pow_only`（`pow_a11y`）、`external`（Turnstile） |
| `modality` | `mouse` / `touch` / `pen` / `keyboard` / `mixed` / `none`；`single` 模式取最近一次输入的类型 |
| `locale` | `zh-CN` / `en` |
| `ks` | 会话密钥存放处：`idb` / `local` / `memory`；WebCrypto 不可用时为 `none`（D-45、§12.4） |
| `sv` | SDK 的语义版本（`SDK_VERSION`），≤ 16 个 `[0-9A-Za-z.+-]` 字符 |
| `fallback` | `null` 或 `ts_unsupported` / `ts_load_timeout` / `ts_error` / `ts_config`（§8.3） |
| `trusted` | `isTrusted` 输入事件比例的分桶：0（无）、1（< 0.5）、2（< 1）、3（全部） |
| `act_ms` | 从第一次激活（`pointerdown`、`click` 或选择 `pow_a11y`）到发出提交，100 ms 精度，上限 600000；用于验收中的完成时间（§20），不用于硬检查 |
| `hold.cancels` | 这个 C 上按住被 `pointercancel` 中止的次数，0–15 |
| `page.vis`、`page.vis_during` | 页面被隐藏的次数：整个页面期间（对数分桶）；控件处于 `HOLDING`、`WAITING` 或 `POW` 期间（0–15） |
| 计数与毫秒 | 对数分桶 `logBucket`（0–31，`sdk/web/src/behavior.ts`）；`straight` 与 `offset` 取 0.1 的步长；`hold.ms` 与 `single.wait_ms` 取 10 ms 精度、上限 60000 |
| 速度与帧间隔 | `speed_mean`、`speed_sd`（px/s）与 `frame_mean`、`frame_sd`（ms）取 `logBucket` |
| 压力与接触面 | `pressure` 取 0.1 的步长（0–1）；`pressure_var`、`contact_var` 为 0 或 1 |
| `pow` | `ms` 取 `logBucket`；`worker` 为布尔；`impl ∈ {js, wasm}` |
| 缺省 | `pre` 与 `hold` 只在指针模式出现；`single` 只在 `single` 模式出现；未知字段丢弃 |

整个 `t` ≤ 2048 字节。超出时按 `ix.pre`、`ix.page`、`env`、`auto` 的顺序丢弃；仍超出就不提交，控件显示重试。只收量化后的摘要：没有原始坐标、轨迹、按键值，也没有跨站标识（09 §10）。解析与重新序列化在 edge-core 中只有一份实现（D-62、§15.2），产出 `mg_core::IxTelemetry`。

### 7.7 硬检查（`assess_interaction`，在消费 nonce 之前）

| 检查 | 适用 | 失败 |
|---|---|---|
| `ix` 存在且 `mode` 与 Provider 相符：`self_hold` → `hold` / `single`；`pow_a11y` → `pow_only`；`turnstile` → `external` | 交互式 | `ic.ix_mode`（`pow_a11y` 允许缺少 `ix`） |
| `trusted ≥ 1` | `hold`、`single` | `ic.no_trusted_input` |
| `0.95 × required_hold_ms ≤ hold.ms ≤ 30000` | `hold` | `ic.hold_short` / `ic.hold_long` |
| `single.wait_ms ≥ 0.95 × required_hold_ms` | `single` | `ic.hold_short` |
| 服务端时间窗 `elapsed_ms ≥ required_hold_ms + min_pow_ms + 250` | `hold`、`single`（§7.5 第 6 步） | `ic.too_fast` |
| `elapsed_ms ≥ a11y_min_ms`（缺省 2000） | `pow_only` | `ic.too_fast` |

`elapsed_ms` 取请求体读完时的服务端时钟减 `C.iat`。续期得到的 C，其 `iat` 是续期时间：最短时间窗从最近一次续期算起。SDK 只在用户没有按住时续期，所以这不影响正常操作。

**这些检查能挡住什么**：除服务端时间窗外，表中的值（`trusted`、`hold.ms`、`single.wait_ms`、`mode`、`modality`）都由客户端自报。所以对自己控制客户端的自动化来说，交互级凭证的成本下限只是 PoW 加上 1.2–2.5 s 的等待（`pow_only` 为 `a11y_min_ms`）。硬检查只挡住不了解协议的脚本与时序不合理的提交，软评分在 shadow 中积累数据。正因如此，交互级凭证的人类证据不高于 `pow`（D-68），刷新也受限（D-47）。WP-D2 把这一点写入威胁模型 v1。

### 7.8 软评分（shadow）

| 特征（`features` 的键） | 条件 | 适用 | 初始权重 |
|---|---|---|---|
| `no_pre_move` | 按下前没有移动（`pre.moves = 0`） | `hold` + mouse / pen | +0.15 |
| `straight_long` | `straight ≥ 0.9` 且 `path_px ≥ 10`（≥ 512 px） | `hold` + mouse | +0.15 |
| `fast_target` | `to_target_ms` 的桶 ≤ 7（< 128 ms） | `hold` + mouse / pen（触屏没有悬停，不计） | +0.10 |
| `zero_jitter` | `hold.ms ≥ 1000` 且 `jitter_px = 0` 且 `moves = 0` | `hold` + mouse / pen（读屏与切换控制产生的触摸本来就静止，不计） | +0.20 |
| `untrusted` | `trusted < 3` | `hold`、`single` | +0.20 |
| `hidden` | `page.vis_during > 0`（按住、等待或 PoW 期间页面被隐藏） | 全部 | +0.10 |
| `pow_too_fast` | `pow.ms` 比期望耗时 `k · 2^bits / DESKTOP_HASHES_PER_MS` 快 10 倍以上（§5.5） | 全部 | +0.20 |
| `ts_fallback` | `fallback` 不为空 | 全部 | +0.05 |
| `touch_natural` | `pressure_var > 0` 或 `contact_var > 0` | `hold` + touch | −0.10 |
| `prior` | 风险段：low 0、medium 0.05、high 0.10、very_high 0.15 | 全部 | 见左 |

- `score = clamp(Σ, 0, 1)`。
- `single` 与 `pow_only` 模式不计指针特征，缺失的指针数据是中性的（09 §11）。选择无障碍路径本身从不计分：这两种模式只可能命中 `untrusted`（`single`）、`hidden`、`pow_too_fast`、`ts_fallback` 与 `prior`。
- 改为 `enforce` 之前，所有者按 §19 第 5 步用辅助技术完成样本；`t_pass` 必须高于这些样本中 `ix.score` 的最大值。构建器在 `scoring.mode: enforce` 时打印这条提醒（§10.2）。
- `mode = shadow`（缺省）时，`score` 与 `features` 只写入 `kind=feedback` 的 `ix`，并计入直方图 `mg_interactive_score`。
- `enforce` 时：`score < t_pass` 通过；`t_pass ≤ score < t_block` 为 `Retry`（`ic.score_high`，计失败）；`≥ t_block` 为 `Block`（429，`ic.score_block`）。

权重与特征阈值是初值，按 shadow 数据调整。调整走配置包之外的代码变更，并记录在本节。

### 7.9 失败、升级与配额

- 统一失败附的新 C 按 §5.3 生成；交互式的新 C 重新选择 Provider（§5.4），`attempt_no > N` 时 `pow_a11y` 置首。
- 次数上限由 `mg.c.fail`（`ip` 实体）与 `mg.c.fail.prefix` 执行，超出时 429 + `Retry-After`（Phase 1 规格 §9.8），SDK 在控件内显示"请稍后再试"。
- 新的内置限速器都分两级（D-67）：按 `ip` 实体的主限额，加按 `ipp` 的宽松限额。

| 限速器 | `ip` 实体 | `ipp` | 会话（`sub`） | 后端 | 超限 | 参数 |
|---|---|---|---|---|---|---|
| `mg.ix.issue`：交互式 C 的签发与续期（首次绑定的续期不计） | 30 / 600 s，burst 20 | 4 倍，只计数 | — | 进程内 | 429 + `Retry-After` | `interactive.issue` |
| `mg.c.renew` | 30 / 600 s，burst 10 | 4 倍 | — | 进程内 | 429（`ic.rate_limited`） | `interactive.renew` |
| `mg.a11y.issue`：`interactive_a11y` 凭证的签发 | 6 / 3600 s | 120 / 3600 s | — | Valkey（本地模式为进程内） | 附新 C 的统一失败（`ic.a11y_quota`，不计失败） | `interactive.a11y_issue` |
| `mg.r`：`/__mg/r` | 30 / 600 s，burst 10 | 4 倍 | 10 / 600 s，burst 3（凭证验证之后） | 进程内 | 429 | 常量 |
| `mg.t`：`/__mg/t` | 60 / 60 s，burst 30 | 4 倍 | 30 / 60 s，burst 15（证明有效时） | 进程内 | 429 | 常量 |

- "4 倍"指速率与 burst 都是 `ip` 实体的 4 倍。进程内限速器同 Phase 1 的进程内表：容量有界，满时按 Phase 1 规格 §9.7 的溢出规则处理。
- `mg.a11y.issue` 超限时，新 C 的 `ix.a11y_quota = true`，SDK 把单次激活放在首位。`pow_a11y` 是最容易自动化的路径（没有交互），所以它的签发配额强制执行（解决 09 §12.3 与 04 §5 的分歧）。按 `ip` 实体计数，CGNAT 与校园网背后的其他访客不受某一个人的影响；超限时访客仍可用单次激活或按住完成验证，不会被锁在外面。

### 7.10 `/__mg/v`、重启与本地模式

- `/__mg/v`：签发的类型按 D-58 取最高者。可选参数 `min` 只接受 `interactive`；出现多次或取其他值时忽略。其他行为同 I-39。
- 重启：Valkey 模式下，nonce 在 Valkey 中，重启不影响进行中的交互式挑战。本地模式下按 D-35：本进程启动前签发的 C 视为"重放存储不可用"，这时：
  - 续期：429 + `Retry-After: 5`，SDK 等待后重试一次，仍是 429 就重新加载页面（§12.6）；
  - 提交，C 的路由 `fail_closed`：429 + `Retry-After: 5`，SDK 等待后重新加载页面，取得新 C；
  - 提交，其余路由：照常签发，凭证带 `ruc`（I-30）。

## 8. Provider 与 Turnstile（WP-C6 客户端，WP-E2c 接线）

Turnstile 是可选的、零成本的外部 Provider，只用于非大陆访客。它的通过不能单独签发凭证：只有密封 C、已消费的 nonce、绑定、会话密钥签名与 PoW 都通过，才采纳它的结果（09 §6.1）。没有配置 Turnstile 的站点不受本节影响。

### 8.1 国家判定

| 来源 | 取值 |
|---|---|
| GeoLite2 | 配置包的 `geoip-country` 工件；没有该工件或查不到时为"无" |
| Cloudflare | 站点 `cloudflare.location_headers = true` 且上游认证通过时的 `cf-ipcountry`（Phase 1 规格 §9.3）；`XX`、`T1` 与格式不对的值为"无" |

任一来源为 `CN`，按 CN 处理；两个来源都为"无"，按"未知"处理。两种情况都不提供 Turnstile（§5.4 第 2 条）。Cloudflare 官方说明 Turnstile 不支持中国大陆，所以这条规则是硬编码的，配置只能在其上追加国家。

### 8.2 配置与校验

- **配置包**（§3.2 `ProviderConfig`，公开配置），由构建器与 Edge 共同校验：
  - 至多一项，`id = "turnstile"`；
  - `sitekey` 匹配 `[0-9A-Za-z_-]{1,64}`；
  - `hostnames` 非空，每项必须是站点的主机名之一；
  - `route_ids` 中的路由必须存在；
  - `timeout_ms` 在 1000–5000；
  - `fallback = self_hold`（D-51），`mode ∈ {shadow, enforce}`，`selection ∈ {first, escalate_after_fail}`；
  - `denied_countries` 为大写二位代码；
  - `secret_refs` 与 `allowed_countries` 为空。

  任一不满足，构建器报错，Edge 视该配置包无效。
- **`edge.toml`**：`[[sites]] turnstile_keys = "cred://<name>"`（§10.1），指向 `mg-turnstile-keys` 文件（§8.7）。配置包启用了 Turnstile 而 `edge.toml` 没有对应凭证时，`--check-config` 失败；运行中加载到这样的配置包时，该 Provider 不可用（健康状态 `disabled(no_secret)`），打一条 ERROR 日志，站点其余功能照常。
- **可用**：配置包启用 ∧ 有凭证 ∧ 健康状态不是 `disabled` 或熔断打开（§8.6）。

### 8.3 客户端参数与 CSP

- **加载**：只在 Turnstile 是当前 Provider 时加载，即它在 `C.providers` 的首位，或用户在控件内切换到了它。SDK 创建带页面 nonce 的 `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit">`。该脚本不代理、不缓存、不加 SRI，也不进入 `/__mg/`。
- **渲染**：`turnstile.render(container, params)`，容器不带 `cf-turnstile` class。参数如下：
  - `sitekey`、`action`、`cData`、`language` 取自 `ix.turnstile`；
  - `appearance: "interaction-only"`、`execution: "render"`、`"response-field": false`；
  - `theme: "auto"`、`retry: "auto"`、`"refresh-expired": "auto"`。
- **回调**：
  - `callback(token)`：立即提交，`p = "turnstile"`、`pp = token`。
  - `error-callback(code)`：按错误码处理。
    - 110xxx（110600、110620 除外）、400xxx、200100 是配置问题，不重试，立即回退（`fallback = ts_config`）。
    - 110600、110620、200500、300xxx、600xxx：先让控件自己重试一次，仍失败则回退（`ts_error`）。
  - `unsupported-callback`：回退（`ts_unsupported`）。
  - 加载 api.js 超过 5 s 未就绪：回退（`ts_load_timeout`）。
  - `expired-callback`：等待控件自动刷新。
- **回退**：切换到 `C.providers` 中的下一个 Provider，不消费 nonce，也不计失败。续期得到新 C 后，先 `turnstile.remove` 再重新渲染（`cData` 随 nonce 变化）。
- **界面**：Turnstile 是当前 Provider 时（控件状态 `EXTERNAL`，§12.6），`#mg-status` 写"正在进行安全检查…"；`#mg-hold` 改名为"改用按住验证"并保持可用，切换不消费 nonce，键盘与读屏用户不必操作 Turnstile 的复选框。`EXTERNAL` 也是可续期的状态。容器宽度小于 300 px 时用 `size: "compact"`。
- **CSP**：只在 C 提供了 Turnstile 的挑战页上，把 Phase 1 的 `script-src 'nonce-<N>'` 换成 `script-src 'nonce-<N>' 'strict-dynamic'`，并追加 `frame-src https://challenges.cloudflare.com`。不支持 pre-clearance（Phase 2 恒关闭），`connect-src` 不变。上线前先用 `Content-Security-Policy-Report-Only` 核对，`script-src`、`frame-src` 与 `style-src` 都要核对（§21）。

### 8.4 siteverify（`OutboundHttp`，WP-C6）

| 项 | 规范 |
|---|---|
| 实现 | `mg_edge_core::outbound`。reqwest 客户端在后台 service 的运行时上创建一次：`no_proxy()`、rustls、User-Agent `morphgate-dev-tooling`、连接超时 2 s、每主机至多 8 个空闲连接。是 `mg_core::challenge::OutboundHttp` 的唯一实现。进程内并发上限 32：拿不到许可时按 `Unavailable` 处理，但不计入熔断（§8.6） |
| 目的地 | 只允许精确的 URL `https://challenges.cloudflare.com/turnstile/v0/siteverify`。`edge.toml` `[outbound] turnstile_siteverify_url` 只能改成 `http://127.0.0.1:<port>/…` 或 `http://[::1]:<port>/…`（测试用的 mock），而且只在环境变量 `MG_EDGE_TEST_OUTBOUND=1` 时接受，否则启动与 `--check-config` 都失败：配置错误不能静默放宽校验。生效时仪表 `mg_outbound_override{target="siteverify"} = 1`，每次加载打一条 WARN |
| 请求 | `POST`，`Content-Type: application/json`，`{"secret", "response", "remoteip", "idempotency_key"}`。`remoteip` 为 Edge 认定的可信客户端 IP（IP 未知的提交在第 0 步已 429），`idempotency_key` 见 §6.9；请求体 ≤ 4 KiB |
| 响应 | 只接受 200 与 `application/json`，≤ 16 KiB。读取 `success`、`challenge_ts`（RFC 3339）、`hostname`、`error-codes`（≤ 8 项）、`action`、`cdata`，其余字段忽略。不合格的响应按 `Unavailable` 处理 |
| 本地预检 | token 为空、超过 2048 字符或含可见 ASCII 以外的字符 → 直接 `Fail`（`ic.ts_fail`），不发请求 |
| 重试 | 只重试一次，条件是：传输错误、超时（剩余截止时间 ≥ 1 s）、HTTP 5xx，或 `error-codes` 含 `internal-error`。重试用同一个 `idempotency_key`。`timeout-or-duplicate` 与 `invalid-input-response` 从不重试 |
| 旧 secret | `invalid-input-secret` 且凭证文件有第二个值时，用第二个值重试一次（轮换窗口），幂等键改用 §6.9 的旧 secret 变体 |
| 截止时间 | `min(timeout_ms, 5000)`，从第 13 步开始算 |

**接口**（WP-C6；edge-core 不依赖 mg-challenge）：

```rust
pub struct SiteverifyExpect<'a> {
    pub host: &'a str, pub hostnames: &'a [String], pub action: &'a str,
    pub c_iat_ms: i64, pub now_ms: i64, pub deadline_ms: i64,
    pub cdata_ok: &'a (dyn Fn(&str) -> bool + Sync),   // built by WP-E2c with mg_challenge::turnstile_cdata_matches
}
impl Siteverify {
    pub async fn verify(&self, req: &SiteverifyRequest<'_>, expect: &SiteverifyExpect<'_>) -> ProviderVerdict;
}
```

Turnstile 不实现 `InteractiveChallengeProvider`。`BindingMac` 与 `VerifyCtx.binder` 在 Phase 2 不使用，§6.9 的公式是 `cdata` 的唯一规范。

### 8.5 通过条件与错误映射

以下条件**全部**满足才为 `Pass`：
- `success = true`；
- `hostname` 精确等于请求的规范化主机，且在配置的 `hostnames` 中；
- `action = C.route_class`；
- `cdata` 与 §6.9 的重算值相等（常量时间比较，区分大小写）；
- `C.iat − 5 s ≤ challenge_ts ≤ now + 5 s` 且 `now − challenge_ts ≤ 300 s`。

token 重放键已在第 12 步写入（§14.2）。

| siteverify 结果 | `outcome` | reason | `enforce` 下计失败 |
|---|---|---|---|
| 成功且绑定全部满足 | Pass | — | — |
| 成功但 `hostname` / `action` / `cdata` / 时间不符 | Fail | `ic.ts_hostname` / `ic.ts_action` / `ic.ts_cdata` / `ic.ts_time` | 是 |
| `invalid-input-response`、`missing-input-response` | Fail | `ic.ts_fail` | 是 |
| `timeout-or-duplicate` | Fail | `ic.ts_dup` | 是 |
| `bad-request` | Unavailable，打一条 ERROR 日志 | `ic.provider_unavailable` | 否 |
| `missing-input-secret`、`invalid-input-secret`（旧 secret 重试之后） | Misconfigured：自动禁用（§8.6） | `ic.provider_misconfigured` | 否 |
| 重试后仍为 `internal-error`、传输错误、5xx、超时、响应不合格 | Unavailable | `ic.provider_unavailable` | 否 |

- `Unavailable` / `Misconfigured`：nonce 已消费，返回统一失败并附新 C；新 C 的 Provider 集合排除 Turnstile。
- `mode = shadow`：`Pass` 照常签发 `interactive_ext:turnstile`（它同样要求密封 C、nonce、绑定、签名与 PoW 全部通过）；`Fail` 与 `Unavailable` 都不计失败，新 C 排除 Turnstile，访客回退到 `self_hold`。shadow 用于试运行 Turnstile 而不让它的失败影响访客。
- 每次校验写入 `ChallengeResult.provider`（§3.3），计 `mg_provider_verify_total` 与 `mg_provider_verify_latency_seconds`（§15.5）。

### 8.6 熔断与自动禁用

- 状态按 `(site, provider)` 保存在进程内：`healthy` → `open` → `half_open`，另有 `disabled`。
- 60 s 内连续 5 次 `Unavailable`：熔断打开 30 s，每次再打开时加倍，上限 300 s。到期后进入 `half_open`，只放行一次校验，成功即回到 `healthy`。
- `Misconfigured` 立即进入 `disabled(misconfigured)`，打一条 ERROR 日志，直到配置包版本变化或进程重新加载凭证（`systemctl reload`）。
- 仪表 `mg_provider_state{site, provider, state}`。
- 状态在进程重启后丢失（A1 SH-11）。这可以接受：最坏的情况是重启后再触发一次熔断。

### 8.7 secret 的存放与轮换

- 文件格式：`{"v": 1, "kind": "mg-turnstile-keys", "site": "<site id>", "values": ["<current>", "<previous>"]}`。`values` 有 1–2 个值，当前值在前，每个是 1–256 个可见 ASCII 字符；未知字段拒绝；文件 ≤ 64 KiB。读写两侧都用 `testdata/phase2/samples/keys/` 的有效与无效样例测试。文件格式错误、或 `site` 与 `[[sites]] id` 不同：`--check-config` 失败，运行中重新加载时同 I-38 的凭证规则；文件缺失：见 §8.2。以 systemd credential 交付，Edge 同时持有当前值与上一个值。secret 从不进入配置包、日志、事件与 `Debug` 输出。
- 轮换（`mgctl turnstile secret rotate`，§16）调用 Cloudflare API 的 `rotate_secret`，并**总是显式**传 `invalidate_immediately`：常规轮换传 `false`，旧 secret 保留 2 小时，此期间不能再次轮换；疑似泄露时传 `true`。
- 新 secret 写入 `[新, 旧]` 两个值的凭证文件；所有者部署并 reload 后，用 `mgctl turnstile secret drop-previous` 写回只含新值的文件。
- Cloudflare API token 只授予 Account → Turnstile → Edit，与其他 token 一样以 age 加密保存在工作站。

## 9. 持有证明、凭证刷新与遥测（WP-E2b）

### 9.1 路由上的 `MG-Proof`（D-40）

- **读取**：Edge 在头部清洗之前，从原始请求头读取 `MG-Proof`。出现多个即视为格式错误。它属于 `mg-` 头族，所以从不转发给源站（Phase 1 规格 §9.3）。
- **可豁免的导航**（D-40）：`http.navigation ∧ 方法 ∈ {GET, HEAD} ∧ 所有命中路由的 channel 都是 web`。CORS 预检（`OPTIONS` 且带 `Access-Control-Request-Method`）同样不要求证明。可豁免的导航上忽略该头，`identity.proof.*` 为 MISSING。
- **何时校验**：`schema_version = 2`，请求不是可豁免的导航，并且命中路由有 `proof = required`，或配置包中有规则读取 `identity.proof.valid` / `identity.proof.replayed`。Edge 在加载配置包时遍历策略 IR 得出后一条（WP-R4 提供 `reads_field`）。不满足时不解析、不校验，`identity.proof.*` 为 MISSING，不写 `jti`。
- **校验**：按 §6.7 的顺序，先做不需要椭圆曲线运算的检查；`expected_jkt` 取请求中有效凭证的 `cnf.jkt`。
- **`Early-Data`**：`proof = required` 的路由上，带 `Early-Data: 1` 的请求返回 425；证明照常校验，`jti` 照常写入。
- **结果**：`present` 表示头是否存在；`valid` 为"校验通过且 `jti` 不是重放"；`replayed` 来自 §9.2。重放存储不可用时，`replayed` 为 MISSING，`valid` 只表示校验通过，并计 `mg_proof_verify_total{result="unchecked"}`。
- **执行**（执行层，在 Decision Core 之后）：同时满足以下条件时，返回 403，`rule_id = edge.proof_required`：
  - 站点与路由都处于 enforce（不是 monitor，也没有 `force_monitor`）；
  - 命中路由中有 `proof = required`；
  - 请求不是可豁免的导航；
  - Decision Core 的决定会转发（ALLOW / TAG / LOG）；
  - `identity.proof.valid` 为假。

  应答：非导航请求为 JSON `{"v": 2, "error": "mg_proof_required", "now_ms": …, "request_id": "…"}`，带 `MG-Error: mg_proof_required`；不可豁免的导航（例如表单 POST）按 Phase 1 规格 §9.9 的阻断页格式返回 HTML。决定为 CHALLENGE、BLOCK 或 RATE_LIMIT 时，按该决定执行。monitor 下只记录（`dry_run`）。
- **就地恢复**：同时满足以下条件时，JSON 应答另带 `"challenge"`：一个 `pow` C，`bind.jkt` 为该证明公钥的指纹，`ret` 按 Phase 1 规则。条件：
  - 请求带有效凭证，失败原因是 `proof.unbound` 或 `proof.jkt`（访客的密钥被清除或换了）；
  - 证明的签名有效。这时才验签：执行层在限速器之后，所以验签成本受限速约束；
  - 路由要求的级别不高于 `pow`。

  SDK 就地求解后重试原请求，不离开页面（§12.5）。没有附 C 时，SDK 按 I-39 跳转 `/__mg/v`：D-58 会按凭证的级别签发，交互级凭证不会降级。
- **重放存储不可用**：`proof = required` 的路由若同时 `fail_closed`，返回 429 + `Retry-After: 5`；否则按"校验通过"放行，并如上计数。
- 每次校验计 `mg_proof_verify_total{result}`。`result` 取 `valid`、`missing`、`malformed`、`unbound`、`jkt`、`htm`、`htu`、`iat`、`sig`、`replay`、`unchecked`。`missing` 只计命中 `proof = required` 路由、不可豁免、却没有带证明的请求。

### 9.2 `jti` 防重放

- 键为 `mg:jti:{site}:{kj}:{jti}`，其中 `kj = kh("mg-jti-v1", "jkt", jkt)`（Phase 1 规格 §9.7 的 `kh`，32 个十六进制字符），`jti` 为证明中的 22 字符原文。每把密钥另有计数键 `mg:jc:{site}:{kj}`。
- 只在证明通过 §6.7 时，在请求的往返 1 管线中执行 `mg_jti` v1（§14.2）：计数键加一（新建时 60 s 后过期）；计数超过 600 时按重放处理（`proof.replay`），只影响这把密钥，不算全局溢出；否则 `SET mg:jti:… 1 NX EX 40`，返回空即为重放。
- **本地集合**：在所有模式下，Edge 都先查后插进程内 TTL 集合（容量 `local_jti_capacity`，缺省 100,000，项在 40 s 后过期），并按同样的规则在进程内按密钥计数（每把密钥每 60 s 至多 600 条）。遵循 D-35：不逐出未过期的项；溢出即"不可用"。
- **结论**：有 Valkey 的结论时以它为准，本地集合命中同样算重放。没有 Valkey 的结论时（本地模式或往返失败），本地结论只在 `local_replay_authoritative = true`、集合未溢出、且 `iat − 5 ≥` 本进程启动时间（秒）时算数；否则为"重放存储不可用"。证明的 `iat` 最多比 `now` 晚 5 s（§6.7），所以满足最后一条的证明不可能在本进程启动之前被接受过。
- **容量**：`local_jti_capacity` 至少取"同时活跃的会话密钥数 × 每把密钥 40 s 内的请求数"；缺省值按每把密钥每秒 1 个请求，可容纳约 2,500 把同时活跃的密钥。
- 计 `mg_state_local_overflow_total{table="jti"}`。

### 9.3 `POST /__mg/r`：凭证静默刷新（D-47）

`schema_version = 1` 时整个端点返回 404（D-66）。下文的路由 R 指 `select_route(env, GET, "/")` 选中的路由：它不一定叫 `default`，构建器在用户路由为 `paths: ["/**"]` 时会省略 `default` 路由。

**请求**：`application/json`，≤ 16 KiB，正文 `{"v": 2}`；可带 `"t": "<遥测 JSON 文本>"`，只在 `events.telemetry_behavior = true` 时记录，否则忽略。必须带 `MG-Proof`：`htm = "POST"`，`htu` 为 `https://<host>/__mg/r`。

| # | 检查 | 结果 |
|---|---|---|
| 0 | 客户端 IP 未知 | 429 + `Retry-After: 5` |
| 1 | `Early-Data` | 425 |
| 2 | 进程内限速器 `mg.r` 的 `ip` 与 `ipp` 两级（§7.9） | 429 |
| 3 | 请求体 | 403 `mg_refresh_denied` |
| 4 | 凭证 `valid`，且 `clearance.refresh = true` | 403 `mg_refresh_denied` |
| 5 | `MG-Proof` 校验（§6.7，`expected_jkt = cnf.jkt`） | 403 `mg_refresh_denied` |
| 6 | `mg.r` 按会话（已验证凭证的 `sub`）的限额 | 429 |
| 7 | 一次往返：`MGET` verdict、`EVALSHA mg_gcra`（路由 R 的 global 限速器，`write = 0`）、`EVALSHA mg_jti` | 重放 → 403 `mg_refresh_denied`；`jti` 重放存储不可用：R 为 `fail_closed` 时 429 + `Retry-After: 5`，否则照常并计 `mg_proof_verify_total{result="unchecked"}` |
| 8 | 以路由 R 对本请求运行 Decision Core，然后 `refresh_check`（§5.7），再检查 `exp − now ≥ 60`（§6.8） | `Blocked` → 403 `mg_blocked`；其余拒绝 → 403 `mg_refresh_denied`。有效 monitor（含 `force_monitor`）下，`Blocked` 与 `ChallengeRequired` 只记入 `kind=refresh`，照常刷新 |
| 9 | `mint_refresh`（§6.8），设置两个 Cookie | 200 `{"v": 2, "ok": true, "iat": …, "exp": …, "now_ms": …}` |

- 拒绝的具体原因不返回给客户端，只写入 `kind=refresh` 事件（§15.3）。刷新只写 `kind=refresh`，不写 `kind=decision` 与 `mg:ev` 的决定条目，也不计入 `mg_requests_total`（I-42）。
- 全部应答为 JSON，带 `MG-Error`（§11.2）。
- SDK 收到 `mg_refresh_denied` 后不再为这个 `exp` 刷新，让凭证自然过期；收到 `mg_blocked` 后停止本页的刷新与后台上报（§12.5）。
- 计 `mg_token_refresh_total{result}`，`result` 取 `ok`、`disabled`、`invalid`、`not_refreshable`、`ruc`、`not_bound`、`binding`、`too_old`、`challenge`、`blocked`、`replay`、`rate_limited`。

### 9.4 `POST /__mg/t`：遥测（D-48）

`schema_version = 1` 时整个端点返回 404（D-66）。

**请求**：`application/json`，≤ 16 KiB；`MG-Proof` 可选（`htu` 为 `https://<host>/__mg/t`）。

```json
{"v": 1, "reports": [
  {"kind": "upstream_challenge", "scope": "protected_fetch", "path": "/api/save", "count": 1},
  {"kind": "cache_hit", "path": "/__mg/c"},
  {"kind": "behavior", "page": "/articles", "summary": {"...": "section 12.8, <= 2048 bytes"}}]}
```

`reports` 至多 8 条，其中 `upstream_challenge` 与 `cache_hit` 各至多 1 条；超出即整个请求不合格。

| 报告 | 字段 | 处理 |
|---|---|---|
| `upstream_challenge` | `scope ∈ {navigation, protected_fetch, mg_endpoint}`；`path` 为页面路径，不含查询串，≤ 512 字节；`count` 1–100，只记录 | 计 `mg_double_challenge_total{site, route}`。`route` 由 `path` 按 Phase 1 规格 §9.4 匹配，匹配不到时为 `default`，所以标签值有界 |
| `cache_hit` | `path` 为 `/__mg/s/` 以外的一个 `/__mg/*` 路径，SDK 在它的响应上看到 `cf-cache-status: HIT`。`/__mg/s/` 本来就允许缓存，这类报告丢弃并计 `invalid` | 计 `mg_endpoint_cache_hit_reports_total{site}`：Cloudflare 的 `/__mg/` Bypass 规则失效（08 §2.6） |
| `behavior` | `page` 同上；`summary` 为 §12.8 的 schema | 只在 `events.telemetry_behavior = true` 时接受，否则丢弃并计 `disabled` |
| `sw_intercept` | `path` 为 SDK 所在页面的路径：它以 `/__mg/` 开头，页面上却没有 `#mg-challenge`（站点的 Service Worker 截获了 `/__mg/`，§19 第 3b 步） | 计 `mg_sw_intercept_reports_total{site}` |
| `key_unavailable` | `reason ∈ {no_idb, no_storage, no_webcrypto}`（§12.4） | 只计 `mg_telemetry_reports_total` |

**两个告警指标只计可信的报告**：`mg_double_challenge_total` 与 `mg_endpoint_cache_hit_reports_total` 只计 `signed = true` 的报告，且同一会话（`sub`）同一种报告每 10 分钟至多计 1 次（进程内有界表，满时不计）。其余报告只计入 `mg_telemetry_reports_total{kind, result="unsigned" | "suppressed"}`。§19 的告警只用这两个指标。

**处理顺序**：
1. 客户端 IP 未知 → 429。
2. `Early-Data` → 425。
3. 进程内限速器 `mg.t` 的 `ip` 与 `ipp` 两级 → 429。
4. 请求体与 schema 不合格 → 400 `{"v": 2, "error": "mg_bad_request", "request_id": "…"}`。
5. 有 `MG-Proof`、通过 §6.7、且 `jti` 不在本地集合中（先查后插，不做 Valkey 往返）时 `signed = true`，这时再按会话检查 `mg.t` → 429。证明无效时不拒绝报告，`signed = false`。
6. `path` 与 `page` 按路由匹配，命中 `redact_path` 的路由记为 `/<route name>`。
7. 每条报告写一行 `kind=telemetry`（`vl-short`，`source = "sdk"`，带 `signed`），进入独立的有界队列 `queue_telemetry`（缺省 2048）：满时只丢遥测（计 `mg_event_dropped_total{sink="buffer", class="telemetry"}`），决定事件及其 `mg:ev` 条目不受影响。计 `mg_telemetry_reports_total{kind, result}`，`result` 取 `accepted`、`unsigned`、`suppressed`、`invalid`、`disabled`。
8. 返回 204。

遥测在 Phase 2 不影响任何决定（§5.6）。

### 9.5 Cookie

| Cookie | 写入方 | 属性 | 用途 |
|---|---|---|---|
| `__Host-mg_clr` | Edge（`/__mg/c`、`/__mg/r`） | 同 Phase 1：`HttpOnly; Secure; SameSite=Lax; Path=/` | 清关凭证 |
| `__Host-mg_st` | Edge，`schema_version = 2` 时紧接着上一个写入 | `Secure; SameSite=Lax; Path=/`，**不带** HttpOnly；`Max-Age` 同凭证 | `<iat>.<exp>.<b>`（§6.8），供 SDK 安排刷新、判断 Cookie 是否可用 |
| `__Host-mg_a11y` | Edge：`p = pow_a11y` 的提交成功时写入；`p = self_hold` 的提交成功且请求带着它时以 `Max-Age=0` 删除 | 值 `1`；`HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=31536000` | Provider 选择时把 `pow_a11y` 放在首位（§5.4）。SDK 从 `ix.a11y_first` 得知这一偏好，从不读写它。不含任何标识 |

- **不进入策略与事件**：`http.cookie_names`（Phase 1 规格 §9.5）同样排除 `__Host-mg_st` 与 `__Host-mg_a11y`；二者不进入任何策略字段、事件与 `mg:ev`。Edge 只在 Provider 选择时读取 `__Host-mg_a11y`。这样页面上的第三方脚本读不到访客用过无障碍路径，策略与检测器也无法区别对待这些访客（10 §5.3、09 §11）。
- **转发前删除**（D-61，`upstream_request_filter`，`schema_version = 2` 时）：
  - 逐个处理请求的每个 `Cookie` 头（HTTP/2 可能有多个），删除名称精确等于上表三者的 cookie 对。
  - 其余 cookie 对的字节与顺序保持不变；删除后为空的头整体去掉。
  - 测试覆盖：重复名、大小写变体（`__host-mg_clr` 不删除，Cookie 名区分大小写）、无空格分隔、超长头。

### 9.6 本机应急开关（D-60）

`edge.toml` `[[sites]] force_monitor = true` 时：
- 该站点的有效模式为 monitor，覆盖配置包的 `monitor_only = false` 与 I-36 的路由级 `mode: enforce`；I-36 的超限例外不适用（所有路由都是 monitor，超限请求按 monitor 原样转发）；
- 路由选择前的处理（协议上限、外部 Worker 等）按站点级 monitor 执行；
- `/__mg/*` 端点照常工作；
- 加载时打一条 WARN 日志，生效期间每小时再打一条；`mg_site_forced_monitor{site} = 1`；`--check-config` 把它计入警告数；
- 决定事件中 `monitor_only = true`，并加顶层字段 `forced_monitor: true`。

### 9.7 I-35 复审与采样（D-62）

1. **选中路由之前就应答的请求**：包括外部 Worker 403、监听器 403、站点不可用 503，以及 monitor / bootstrap 下原样转发的超限请求。
   - 路径 ≤ 8 KiB 且站点有路由表时：按 Phase 1 规格 §9.4 的路径视图匹配路由，命中 `redact_path` 的路由则记为 `/<route name>`。
   - 路径超过 8 KiB 时：访问记录与事件中 `path = "/…"`，另记 `path_len`。
   - bootstrap 与 `lkg_invalid` 时没有路由表，与 Phase 1 相同，按原样记录路径（运维手册注明）。
2. **关闭时的事件**：收到关闭信号后，事件刷写任务继续运行，直到队列清空或经过 `[events] shutdown_drain_ms`（缺省与范围见 §10.1）。这段时间内结束的请求，其事件照常写出；超时后仍按 Phase 1 计为 `sink="buffer"` 的丢弃。
3. **`ruc` 凭证**：带 `ruc` 凭证的请求，决定事件不受 `allow_sample_rate` 采样影响，总是写出；同时计 `mg_token_ruc_total{site}`。

## 10. 配置

### 10.1 `edge.toml` 新键（WP-E2a–E2c）

```toml
[valkey]
local_jti_capacity = 100000         # in-process MG-Proof jti set (section 9.2), 1000..10000000
local_rp_capacity = 10000           # in-process provider-token replay set (section 14.4), 100..1000000

[events]
# shutdown_drain_ms (section 9.7): absent -> min(2000, max(0, grace_period_seconds * 1000 - 1000));
#   when set: 0..10000 and <= grace_period_seconds * 1000 - 1000 (only 0 when the grace period is <= 1 s)
queue_telemetry = 2048              # bounded queue of kind=telemetry records (section 9.4), 64..65536

[outbound]
turnstile_siteverify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
# any other value is accepted only with MG_EDGE_TEST_OUTBOUND=1 in the environment (section 8.4)

[[sites]]
turnstile_keys = "cred://mg-turnstile-keys-blog"   # optional; mg-turnstile-keys file (section 8.7)
force_monitor = false                               # D-60
```

- `config_version` 仍为 1：新键都是可选的，缺省值即上面的值。
- **所有权**：`[events]` 的新键属于 edge-core 的 `EventsConfig`（WP-C5：字段与范围）；`shutdown_drain_ms` 缺省值的计算与它对 `[server]` 的交叉检查在 `EdgeConfig::validate`（WP-E2b）；其余新键属于 WP-E2a–E2c。
- Phase 1 的二进制拒绝未知键，所以回滚 Edge 二进制之前，先删掉这些键（§19）。
- 凭证名沿用 Phase 1 规格 §8.1 的规则 `[A-Za-z0-9_.-]{1,64}`。
- **`--check-config` 的新警告**（计入警告数，不阻止启动）：
  - 配置包 `events.stream = true` 而 `[valkey] mode = "local"`：本地模式没有 `mg:ev`，近线不工作；
  - 本地模式且有站点启用了交互式：每次 reload 后，进行中的交互式挑战在 ≤ 10 分钟内无法续期（D-38）；`local_nonce_capacity < 400000` 时另提示按 §14.4 的公式调高；
  - `force_monitor = true` 的站点（D-60）；
  - 启用了 Turnstile 的站点，见 §8.2。
- **`--check-config` 失败**：`turnstile_siteverify_url` 不是缺省值且没有 `MG_EDGE_TEST_OUTBOUND=1`；`turnstile_keys` 文件格式错误或 `site` 不符（§8.7）；配置包启用了 Turnstile 而缺少 `turnstile_keys`（§8.2）。

### 10.2 站点 YAML 新字段（WP-G4）

```yaml
clearance:
  ttl_interactive_s: 1800            # 300..7200
  ttl_interactive_a11y_s: 900        # 300..3600
  ttl_interactive_ext_s: 1800        # 300..7200
  refresh: false                     # POST /__mg/r (D-47)
  refresh_max_interactive_s: 14400   # 900..86400
  refresh_max_ext_s: 7200            # 900..86400
  refresh_max_pow_s: 3600            # 0..86400; absent: 2 x ttl_pow_s; 0: pow tokens never refresh

challenge:
  default_lang: zh-CN                # zh-CN | en: page language when Accept-Language has neither
  help_path: /help/verification      # site-relative, validated like ret; default "/"
  privacy_path: /privacy             # site-relative, validated like ret; default "/"
  interactive:
    enabled: false
    pow_bits: {low: 14, medium: 16, high: 18, very_high: 19}   # each 8..22, non-decreasing
    pow_k: 8                         # 1..8
    a11y_bits: 17                    # 12..24
    escalate_after: 2                # 1..5
    scoring: {mode: shadow}          # or {mode: enforce, t_pass: 0.4, t_block: 0.8}
    min_pow_ms: 0                    # 0..5000
    a11y_min_ms: 2000                # 0..10000
    issue: {rate: 30/10m, burst: 20}                       # mg.ix.issue per ip entity; ipp 4x (counted only)
    renew: {rate: 30/10m, burst: 10}                       # mg.c.renew per ip entity; ipp 4x
    a11y_issue: {per_ip: 6, per_ipp: 120, period_s: 3600}  # mg.a11y.issue

providers:                           # at most one entry in Phase 2
  - id: turnstile
    enabled: true
    sitekey: "<public sitekey>"
    hostnames: [example.com, www.example.com]   # each must be a site host
    routes: [login, signup]          # empty or absent: every route
    selection: escalate_after_fail   # or first
    mode: shadow                     # or enforce
    timeout_ms: 4000                 # 1000..5000
    fallback: self_hold              # the only value in Phase 2 (D-51)
    deny_countries: []               # added to CN

events:
  telemetry_behavior: false
  scanner_baits: {builtin: true, extra: []}     # extra: route-path globs, at most 64

environments:
  - name: production
    routes:
      - name: api
        paths: [/api/**]
        channel: api
        sensitivity: medium
        proof: required              # off (default) | required
        min_level: pow               # invisible | pow | interactive
    rate_limits:
      - id: signup-per-ip
        on_exceed: {action: challenge, type: interactive}   # interactive now allowed (schema_version 2)
```

**校验**（构建器报错，Edge 加载时同样拒绝）：
- 各值必须在注释给出的范围内；`pow_bits` 必须随风险段不减；`scoring.mode = enforce` 时必须给出 `0 < t_pass < t_block ≤ 1`；`a11y_issue.per_ipp ≥ per_ip`；
- `help_path` 与 `privacy_path` 按 `ret` 的规则校验（Phase 1 规格 §6.4）；
- `proof: required` 或 `min_level` 不得与 `never_challenge` 同时用在一条路由上：`sendBeacon` 带不了请求头，也走不了挑战；
- 动作为 `allow` 的规则不得以 `http.navigation` 为条件（§4.2）；
- `providers` 的规则见 §8.2；
- `scanner_baits.extra` 用路由路径的 glob 语法。

**只给警告**：
- `min_level: interactive` 或限速器的 `type: interactive`，而 `challenge.interactive.enabled = false`：此时按 `pow` 执行（D-08、§5.2）；
- `proof: required` 的路由，`channel` 为 `web` 且允许非安全方法：表单 POST 必须改用 `MorphGate.fetch` 发送，否则带不上证明（D-40）；
- `min_level: interactive` 或交互式限速器只作用于含 POST、不含 GET 的路由：访客通过挑战后会丢失表单输入，应在页面路由（GET）上要求；
- `scoring.mode: enforce`：提醒 `t_pass` 必须高于所有者用辅助技术完成的样本的最高分（§7.8、§19 第 5 步）；
- 启用了 Turnstile，但站点既没有 `geoip-country` 工件，也没有开启 `cloudflare.location_headers`：国家永远未知，Turnstile 永远不会被选中；
- `events.telemetry_behavior: true`：提醒先更新隐私说明（07 贯穿各阶段）。

**`schema_version`**：YAML 中出现任何一个 Phase 2 键或取值（如 `type: interactive` 的限速器）时，配置包写 `schema_version = 2`；否则写 1，与 Phase 1 构建器的输出逐字节相同。golden 配置包同时保留两种（§17 WP-G4）。

## 11. HTTP 接口

### 11.1 端点（改 Phase 1 规格 §10.1）

| 方法与路径 | 作用 | 请求体上限 | 缓存头 | Phase 2 |
|---|---|---|---|---|
| `GET` / `HEAD /__mg/healthz` | 存活 | — | `no-store, private` | 不变 |
| `GET` / `HEAD /__mg/s/<file>` | 内容哈希的 SDK 构建文件 | — | `public, max-age=31536000, immutable` | 不变 |
| `GET` / `HEAD /__mg/s/mg.js` | 当前构建的稳定别名（D-39），字节与 `manifest.sdk` 相同；带 `ETag: "<build>"`，`If-None-Match` 相符时 304；查询串忽略 | — | `public, max-age=300` | 新 |
| `POST /__mg/c` | 提交解答：v1（Phase 1）与 v2（§7.5） | 8 KiB | `no-store, private` | 扩展 |
| `POST /__mg/c/renew` | 交互式 C 的续期与首次绑定（§7.4） | 8 KiB | `no-store, private` | 新 |
| `POST /__mg/r` | 凭证静默刷新（§9.3） | 16 KiB | `no-store, private` | 新 |
| `POST /__mg/t` | 遥测（§9.4） | 16 KiB | `no-store, private` | 新 |
| `GET` / `HEAD /__mg/v?ret=…[&min=interactive]` | fetch 被挑战后的验证入口（I-39、D-58、§7.10） | — | `no-store, private` | 扩展 |
| 其他 `/__mg/*` | 保留 | — | `no-store, private` | 404 |

- 站点处于 `bootstrap` 时，`/__mg/c`、`/__mg/c/renew`、`/__mg/r`、`/__mg/t` 与 `/__mg/v` 返回 404；处于 `lkg_invalid` / `bootstrap_closed` 时返回 503。
- `schema_version = 1` 时，`/__mg/c/renew`、`/__mg/r`、`/__mg/t` 返回 404（D-66）。
- 其他方法返回 405 + `Allow`。
- 状态变更端点（`/__mg/c`、`/__mg/c/renew`、`/__mg/r`、`/__mg/t`）对任何 `Early-Data` 都返回 425。
- `/__mg/c/renew`、`/__mg/r`、`/__mg/t` 的全部应答（含 425、429、503）为 JSON，不做导航判定。
- 签发凭证的应答先写 `Set-Cookie: __Host-mg_clr`，再写 `__Host-mg_st`。
- SDK 目录的 manifest 中，`files` 不得包含 `mg.js`，否则 Edge 拒绝该目录（D-39）。
- 在请求体读完之前应答时关闭连接，同 Phase 1；读完之后应答时保持连接。

### 11.2 JSON 响应目录

- Edge 的 JSON 响应都带 `"v": 2`。Phase 1 的 SDK（0.2.x）只认它需要的字段，不受多出的字段影响。
- Edge 生成的每个 JSON 错误响应都带头 `MG-Error: <error>`，`mg_challenge` 另带 `MG-Challenge: <type>`。Edge 删除源站响应中的 `MG-*` 头（Phase 1 规格 §9.9），所以源站无法伪造它们；SDK 只把带这两个头之一的 403 / 429 当作 MorphGate 的应答（§12.5）。

| `error` / 结果 | 状态码 | 字段 | 出现于 |
|---|---|---|---|
| `mg_challenge` | 403 | `type`、`challenge`、`pow`（非交互式）或 `ix`（交互式）、`ret`、`retry`、`request_id` | 受保护请求、`/__mg/v` 的非导航请求 |
| `mg_challenge_failed` | 403 | `retry`、`request_id`；附新 C 时另有 `challenge`、`type`、`pow` / `ix` | `/__mg/c`、`/__mg/c/renew` |
| 成功 | 200 | `{"ok": true, "ret": …, "now_ms": …}` | `/__mg/c`（fetch） |
| 续期成功 | 200 | `{"challenge": …, "ix": …}` | `/__mg/c/renew` |
| 刷新成功 | 200 | `{"ok": true, "iat": …, "exp": …, "now_ms": …}` | `/__mg/r` |
| `mg_proof_required` | 403 | `now_ms`、`request_id`；就地恢复时另有 `challenge`、`type: "pow"`、`pow`（§9.1） | `proof: required` 的路由 |
| `mg_refresh_denied` | 403 | `request_id` | `/__mg/r` |
| `mg_bad_request` | 400 | `request_id` | `/__mg/t` |
| `mg_rate_limited` | 429，`Retry-After` | `retry_after`、`request_id` | 全部端点 |
| `mg_too_early` | 425 | — | 状态变更端点、`proof: required` 的路由 |
| `mg_blocked` | 403 | `request_id` | 阻断、`/__mg/r` 的 `Blocked` |

## 12. Web SDK v1（WP-W2）

### 12.1 模块与公开 API

| 模块 | 内容 |
|---|---|
| `crypto` | 会话密钥（§12.4）、ES256 签名、RFC 7638 指纹（已有，接入构建） |
| `proof` | `MG-Proof` 的构造（§6.7）、时钟偏差（§12.5） |
| `transport` | `MorphGate.fetch` 包装（§12.5）、响应分类（已有）、`cf-mitigated` 处理 |
| `refresh` | 读取 `__Host-mg_st`、安排 `/__mg/r`（§12.5） |
| `challenge` | Phase 1 的非交互式挑战页流程。v2 模板页（`#mg-challenge` 带 `data-mg-ix`）上发送 v2 提交（带 `jwk` 与 `sig`）；v1 模板页上、或 WebCrypto 不可用时，发送 Phase 1 的 v1 提交 |
| `interactive` | 交互式控件：按住、单次激活、`pow_a11y`、Turnstile 加载、续期、提交（§12.6） |
| `pow` | v1 与 v2 求解器，以及 Worker 协议（同一个脚本在 Worker 中运行） |
| `telemetry` | 交互遥测的量化与 2 KB 预算（已有，接入构建）；`/__mg/t` 的批量上报与离页队列 |
| `behavior` | 行为摘要的采集器，只在开启时运行（§12.8） |

- **`window.MorphGate`**：保留 Phase 1 的 7 个成员，`fetch()` 的行为扩展为 §12.5。新增三个成员：
  - `ready()`：返回一个在密钥存储初始化后兑现的 Promise，从不拒绝；
  - `proofHeader(method, url)`：返回 `Promise<string | null>`，供 XHR 与 axios 拦截器使用，规则同 §12.5 第 1 步；
  - `onBeforeNavigate(cb)`：注册回调。SDK 主动离开页面（`verify()`、上游挑战后的重载）之前同步调用它，预算 50 ms，站点可借此保存草稿。

  它仍是冻结对象；重复加载脚本时，返回第一个实例。
- **脚本属性**：Phase 1 的 `data-mg-path-prefix`、`data-mg-site`、`data-mg-debug` 不变，另外新增：
  - `data-mg-proof="auto" | "off"`：缺省 `auto`，即持有绑定凭证时，给经 `MorphGate.fetch` 发出的同源请求附上证明；
  - `data-mg-refresh="auto" | "off"`：缺省 `auto`；
  - `data-mg-telemetry="behavior"`：缺省不采集行为。

  `document.currentScript` 为空时，`findOwnScript` 依次匹配 `script[data-mg-path-prefix]`、`script[data-mg-site]` 与 `script[src$="/__mg/s/mg.js"]`。
- **站点接入约定**（sdk/web README 与 §19 第 3b 步）：
  - SDK 标签放在站点自身脚本之前；
  - 站点代码不得假设 `window.MorphGate` 存在：`const mgFetch = (...a) => (window.MorphGate?.fetch ?? window.fetch)(...a);`。脚本加载失败（跨境丢包、浏览器扩展、Edge 回滚）时，站点照常工作；
  - 模块脚本或 `async` 脚本在顶层调用前先 `await window.MorphGate?.ready()`；
  - 用 XHR 或 axios 访问 `proof: required` 的路由时，在拦截器中用 `proofHeader()` 加上 `MG-Proof`。
- **浏览器下限**：Chromium ≥ 80、Safari / iOS ≥ 14，以及当前的微信 XWeb / X5 内核。更旧的浏览器解析不了这个脚本，挑战页用纯 CSS 的提示兜底（§12.3）。
- **不变的约束**：任何异常都不抛进页面；SDK 失败时页面照常工作。

### 12.2 构建产物与 manifest v2

- **产物**：`dist/sdk/mg.<hex16>.js`（单一文件）、`dist/sdk/challenge.html`（模板 v2）、`dist/sdk/manifest.json`。阶段 1 中的模板选择见 §2.1 的 `DEFAULT_MANIFEST_VERSION`。
- **manifest**：`{"v": 2, "build", "sdk", "files": {sdk: sha256}, "templates": {"challenge.html": sha256}}`，其余规则同 Phase 1；`files` 不得包含 `mg.js`。
- **大小**：整个文件仍 ≤ 30,720 字节 gzip（`size-check`），不拆分懒加载模块，因为 Worker 复用同一个 URL（D-13）。
- **npm 包**：仍为 7 个文件。
- **Edge 接受两种 SDK 目录**：
  - manifest v1：使用 Phase 1 的模板契约，交互式不可用（§5.1）；
  - manifest v2：使用 §12.3 的模板契约。

  `/__mg/s/mg.js` 返回 `manifest.sdk` 的字节，在两种目录下都可用。

### 12.3 挑战页模板 v2 的契约

在 Phase 1 规格 §11.2 与 I-28 的全部规则之上：

- **占位符**：Phase 1 的 10 个，加上 `{{ix}}`、`{{help_href}}` 与 `{{privacy_href}}`。
  - `{{ix}}` 恰好出现一次，位于 `<main id="mg-challenge">` 的 `data-mg-ix="{{ix}}"` 属性中。非交互式页面上，Edge 填入空串。
  - `{{help_href}}` 与 `{{privacy_href}}` 各至少出现一次，只能出现在带引号的 `href` 属性中。Edge 填入配置包的 `challenge.help_path` 与 `challenge.privacy_path`（缺省 `/`）。
  - `{{lang}}` 的取值规则见 §7.3。
- **新增的必需结构**（在 `<main>` 内）：
  - `<div id="mg-ix" hidden>`，其中包含：
    - `<p id="mg-purpose">`：目的说明，中英文都有；
    - `<button id="mg-hold" type="button" aria-describedby="mg-purpose">`：按钮内有文字标签，以及 `aria-hidden="true"`、`pointer-events: none` 的进度填充层；
    - `<button id="mg-alt-single" type="button">`；
    - `<button id="mg-alt-pow" type="button">`；
    - `<div id="mg-progress" role="progressbar" aria-labelledby="mg-purpose" hidden>`：只用于 PoW 的确定进度；
    - `<div id="mg-turnstile" hidden>`。
  - `<a id="mg-help" href="{{help_href}}">` 与 `<a id="mg-privacy" href="{{privacy_href}}">`。
  - `<p id="mg-stuck">`：纯 CSS 的兜底提示。它在 10 s 后由 `animation: mg-reveal 0s 10s forwards` 显示；SDK 启动时给 `#mg-challenge` 设 `data-mg-phase`，同时把它隐藏。这一动画只是延时显示，没有运动，在 reduced motion 下同样适用。
  - Phase 1 的 `<p id="mg-status" role="status" aria-live="polite">` 保持在初始标记中：live region 必须先存在，内容才能被播报。交互式页面上，SDK 显示控件时清空它（清空不会被播报）。
- **样式**（只用带 nonce 的 `<style>`）：
  - 所有可操作元素不小于 24 × 24 CSS px，`#mg-hold` 不小于 44 × 44 CSS px；都有可见的 `:focus-visible` 焦点环；
  - 只在 `#mg-hold` 上设 `touch-action: none`、`-webkit-touch-callout: none`、`-webkit-user-select: none`、`user-select: none`；
  - `prefers-reduced-motion: reduce` 时，进度改为分段填充，不做动画；
  - `forced-colors: active` 时，进度用边框或系统色 `Highlight` 绘制；
  - 按钮偏移只用 margin 实现，容器两侧各留 ≥ 16 px；宽 320 CSS px 时没有横向滚动；按钮不设固定高度；
  - 对比度按 AAA 设计；红色只用于图标（09 §2.3）。
- **校验**：`validateTemplate` 的 v2 规则（`build-dist.mjs`）与 Edge 加载 SDK 目录时的检查，逐条一致（I-28）。另需检查：每个新增的 `id` 恰好出现一次；不出现任何外部 URL（Turnstile 的脚本由 SDK 在运行时创建）；上面每条样式规则各有一个模板测试。

### 12.4 会话密钥存储（D-45）

| 层 | 做法 |
|---|---|
| IndexedDB | 数据库 `mg-v1`，对象仓库 `keys`，键 `session`。值为 `{pair: CryptoKeyPair, created_ms}`，私钥 `extractable: false`，公钥可导出（WebCrypto 总是如此）。每个操作 1.5 s 超时，超时与 `onblocked` 都按不可用处理 |
| 生成 | 在一个 readwrite 事务中：`get`，不存在才 `add`；`add` 抛 `ConstraintError` 时重新 `get` 并使用已存的密钥。`navigator.locks` 可用时，外面再包 `navigator.locks.request("mg-key")`。这样同时打开的两个标签页不会各自持有一把密钥 |
| 回退 1 | IndexedDB 不可用时，生成可导出的密钥对，以 JWK 存入 localStorage 键 `mg_sk_v1`（各标签页共享），生成规则同上 |
| 回退 2 | 都不可用时只放在内存中。这时 SDK 不附证明；收到 `mg_proof_required` 时不跳转，把原响应返回给调用方，每个页面上报一次 `key_unavailable`（§9.4）。这类访客无法使用 `proof: required` 的路由（§19） |
| WebCrypto 不可用 | `ks = none`：非交互式提交退回 v1（凭证没有 `cnf`）；交互式无法完成，控件显示"当前浏览器无法完成验证…" |
| 轮换 | 没有有效凭证时（`__Host-mg_st` 不存在或已过期），在下次需要密钥之前删除旧密钥、生成新密钥；`created_ms` 满 7 天后同样换新。公钥随每个证明发送，不轮换就会成为跨会话的长期标识 |
| 重新注册 | 密钥丢失（Safari 的 7 天存储清理、隐私窗口、用户清除站点数据）时，静默生成新密钥。旧凭证上的证明会失败（`proof.jkt`），由 §12.5 的流程恢复 |
| 遥测 | `ix.ks = idb \| local \| memory \| none` |

### 12.5 fetch 包装与刷新

**`MorphGate.fetch(input, init)`**：

1. **附加证明**：请求同源、`data-mg-proof` 为 `auto`、已有会话密钥，且 `__Host-mg_st` 显示凭证已绑定、未过期时，附加 `MG-Proof`：
   - `htm` 为浏览器实际发出的方法字符串：fetch 只把 `DELETE`、`GET`、`HEAD`、`OPTIONS`、`POST`、`PUT` 转成大写，其他方法（如 `patch`）原样发出，所以 SDK 也原样签名；
   - `htu` 为 `https://<host><path>`，不含查询串与片段；超过 2048 字节时不附证明；
   - `iat = floor((Date.now() + skew) / 1000)`；
   - `jti` 为 16 个随机字节；
   - 受保护头（base64url）按密钥缓存，每个请求只签载荷。
2. 调用原生 `fetch`（同源时带凭证）。浏览器跟随跳转时会把同一个 `MG-Proof` 发给跳转目标，在那里因 `htu` 不符而失败：最终响应为 `mg_proof_required` 且 `response.redirected` 为真时，若原请求是 GET / HEAD，SDK 用新证明直接请求 `response.url` 一次；其他方法原样返回。`proof: required` 的路由应避免返回跳转（§19）。
3. 按响应分类处理。只有带 `MG-Error` 或 `MG-Challenge` 头的 403 / 429 才是 MorphGate 的应答（§11.2），其余原样返回：
   - **`cf-mitigated: challenge`**（只看经 `MorphGate.fetch` 发出的站点请求）：把一条 `upstream_challenge` 报告（`scope = protected_fetch`）写入 sessionStorage 队列，下次页面加载后用 keepalive 发送；然后调用 `onBeforeNavigate`，以 `location.assign(location.href)` 重载页面。同一页面路径 60 s 内只重载一次（sessionStorage `mg_cfm:<path>`）；没有 sessionStorage 时不重载，只上报。SDK 自己的后台请求（`/__mg/r`、`/__mg/t`、续期）遇到它时从不重载，只上报，并停止本页的后台活动。
   - **403 `mg_challenge`，类型为 `invisible` / `pow`**：
     - 难度检查：v1 的 `bits > 24`，或 v2 的 `k · 2^bits > 2^28` 时不求解，改为 `verify()`；
     - 单飞：同一页面同一时刻至多一个就地求解，其他被挑战的请求等待它的结果后重试（共享 Promise）；`navigator.locks` 可用时，用 `request("mg-solve")` 跨标签页互斥。拿到锁后重新读取 `__Host-mg_st`：其他标签页已获得满足要求的凭证时，直接重试原请求；
     - 在 Worker 中求解，以 JSON 向 `/__mg/c` 提交（v2；WebCrypto 不可用时 v1）。得到 200 后，若原请求体可以重放（字符串、`URLSearchParams`、`Blob`、`ArrayBuffer`、`FormData`；`ReadableStream` 不行），把原请求重试一次（重新生成证明），返回重试的响应；否则返回原响应。
   - **403 `mg_challenge`，类型为 `interactive`**：调用 `verify()`，跳转 `/__mg/v?ret=<页面路径>&min=interactive`，受 I-39 的 60 s 规则约束。
   - **403 `mg_proof_required`**，按顺序：
     1. 请求带了证明，且应答的 `now_ms` 与本地估计的服务端时间相差超过 5 s：校正偏差，用新证明重试原请求一次；
     2. 应答附有 `pow` C（§9.1）：就地求解（同上，单飞），然后重试原请求；
     3. `ks` 为 `memory` 或 `none`：原样返回，按 §12.4 上报；
     4. 否则 `verify()`。
   - **其他响应**（含 429）：原样返回。
- **时钟偏差**：从任何 MorphGate JSON 应答的 `now_ms`，或任何同源响应的 `Date` 头（秒级，对 ±30 s 的窗口已足够）更新，存入 sessionStorage `mg_skew`，页面加载时读取。
- SDK 发起的每次离开页面（`verify()`、上游挑战后的重载），都先同步调用 `onBeforeNavigate` 注册的回调。

**刷新**（`data-mg-refresh = auto`，且 `__Host-mg_st` 的 `b = 1`）：
- 页面可见时，用定时器在 `iat + 0.8 × (exp − iat)` 刷新，但不早于 `exp − 600 s`、不晚于 `exp − 60 s`。页面隐藏时暂停，变为可见时立即检查一次。SPA 与长时间停留在一个页面上的访客（如模拟考试）因此也会得到刷新。
- 单飞：`navigator.locks` 可用时用 `request("mg-refresh")` 跨标签页互斥；拿到锁后重新读取 `__Host-mg_st`，`exp` 已变（其他标签页刷新过）就不再刷新。
- 发起 `POST /__mg/r`，带 `MG-Proof`。网络失败时 30 s 后重试，至多 3 次；同一页面每分钟至多一次。
- 收到 `mg_refresh_denied` 后写入 sessionStorage `mg_rd:<exp>`，对这个 `exp` 不再尝试；收到 `mg_blocked` 后停止本页的刷新与后台上报。

### 12.6 交互式控件

**状态**：

```
LOADING ──ix.bound = false──> BINDING (renew, section 7.4) ──> READY      input is accepted during BINDING (see rules)
READY ──primary pointerdown on #mg-hold──> HOLDING ──pointerup inside, held >= hold_ms──> FINISHING ──pow done──> SUBMITTING
HOLDING ──early pointerup / pointercancel / pointer leaves / blur / page hidden──> READY   (status message, not a failure)
READY ──click on #mg-hold (keyboard, screen reader, short tap) or #mg-alt-single──> WAITING ──hold_ms, pow done──> SUBMITTING
READY ──#mg-alt-pow, or ix.a11y_first after binding──> POW_ONLY ──pow done──> SUBMITTING
READY (turnstile first or chosen) ──> EXTERNAL ──callback(token)──> SUBMITTING;  errors -> next provider (section 8.3)
SUBMITTING ──200──> DONE (location.replace(ret)) | 403 + new C ──> READY (new ix; BINDING first if unbound)
SUBMITTING ──403 without C / 429 / no answer in 15 s / network error──> RELOAD   (rules below; the C is never reused)
```

"重新加载"指挑战页上 `location.replace(location.href)`，`/__mg/v` 页同样重新加载自身：Edge 会签发新 C。

| 规则 | 规范 |
|---|---|
| 指针按住（D-65） | `pointerdown` 只接受主指针（`isPrimary`）的主按钮、触摸与笔，按下时开始进度。触摸会隐式捕获指针，所以在 `pointermove` 中用 `hold.contains(document.elementFromPoint(x, y))` 判断指针是否仍在控件内，移出即中止。只在 `pointerup` 发生在控件内且已达到 `hold_ms` 时提交（WCAG 2.5.2）。阻止控件上的 `contextmenu`。按住中收到 `pointercancel` 且没有位移时（某些 WebView 会拦截长按），`#mg-status` 写"无法按住？可以直接点击"，并计入 `hold.cancels`。按住超过 28 s 后才松开：回到 `READY`，提示改为点击，不发送注定失败的提交（`ic.hold_long`） |
| `#mg-hold` 上的 click | (a) 同一指针序列已完成按住（`FINISHING` / `SUBMITTING`）时忽略；(b) 状态不是 `READY` 时一律忽略，包括 Enter 的自动重复；(c) 其余任何 click（键盘的 Space / Enter、读屏合成的点击、短按、`detail = 0`）都进入 `WAITING`：`ix.mode = single`，`modality` 取最近一次输入的类型。读屏软件的激活不是键盘事件，所以不按键盘来区分；单次激活与按住签发同一级别（D-65），这样分类不影响安全性 |
| 单次激活（D-65） | `WAITING`：进度自动走完 `hold_ms`，PoW 完成后提交，不要求第二次按下。点 `#mg-alt-single` 后，焦点移到 `#mg-hold`，按钮名改为"按一下以验证" |
| `pow_a11y` | 进度为 k 段的确定进度：`#mg-progress` 的 `aria-valuemax = k`、`aria-valuenow` 为已完成的子题数；它不是 live region，也不是倒计时。开始 10 s 后仍未完成时，`#mg-status` 写一次"仍在验证，较慢的设备可能需要一分钟"，之后至多每 30 s 一次。`ix.a11y_first` 时，绑定续期完成后自动进入 `POW_ONLY` 并播报；`#mg-hold` 改名为"改用按住验证"，点击后回到 `READY`（`self_hold` 成功时 Edge 删除偏好 Cookie，§9.5） |
| PoW | 主线程 → Worker：`{t: "mg-pow2", prefix: Uint8Array(42), bits, k, sv}`。Worker → 主线程：收到合法请求立即回 `{t: "mg-pow2-ack", sv}`；每完成一个子题回 `{t: "mg-pow2-part", i, counter}`；最后回 `{t: "mg-pow2-ok", counters}` 或 `{t: "mg-pow2-err"}`。Worker 的 `sv` 与页面的不同时（别名被缓存，D-39），终止它，用 `/__mg/s/mg.js?sv=<SDK_VERSION>` 重建一次（新 URL 绕过 HTTP 缓存），仍不同就改在主线程计算。2 s 内没有 ack 才改在主线程计算。主线程按时间分片：每片 ≤ 8 ms，片间用 `scheduler.yield()`（没有时用 `setTimeout(0)`）让出 |
| PoW 的时机 | 绑定续期完成后，立即在 Worker 中开始 `self_hold` 难度的 PoW，不等用户按下。松开不终止 Worker，已完成的子题保留；切换 Provider 时，已完成且满足新难度的子题保留，其余从当前计数器继续。交互式 PoW 没有客户端总时限，不沿用 Phase 1 的 60 s；开始前若 C 的剩余寿命不足 120 s，先续期 |
| 绑定续期 | 任何 `ix.bound = false` 的 C 装入后（页面加载、失败或续期附带的新 C）都先续期一次（D-41）。续期在途时用户按下：照常显示按住进度，PoW 在续期返回后用新 C 开始；续期因网络失败时继续用旧 C（未绑定） |
| 续期 | 在服务端时间 `iat + 480 s` 之后，且状态为 `READY`、`WAIT` 或 `EXTERNAL` 时续期。页面变为可见时，若估计的服务端时间已过 `iat + 480 s`，先续期再接受输入。结果：200 → 换上新 C 与 `ix`；403 附新 C → 换上它（未绑定时先绑定）；403 不附新 C（`ic.nonce_reused`、`ic.c_*`、`ic.body`）→ 重新加载；429 → 等待 `Retry-After` 后重试一次，仍失败则重新加载；404（Edge 回到 `schema_version = 1`）→ 重新加载。续期的任何结果都不改变 `#mg-status` |
| 提交 | 交互式一律用 fetch 以 JSON 提交（`credentials: "same-origin"`），且不早于"收到该 C 的本地时刻 + `min_ms` + 100 ms"（`pow_only` 为 `a11y_min_ms` + 100 ms）。`trusted = 0` 时不提交，提示改用自动验证。结果：200 → `document.cookie` 中没有 `__Host-mg_st` 时不跳转，`#mg-status` 写"请允许本站使用 Cookie 后重试"并上报一次，否则调用 `onBeforeNavigate` 后 `location.replace(ret)`（不留下挑战页的历史记录）；403 附新 C → 用新 C 与 `ix` 重置控件；403 不附新 C → 重新加载；429 → `#mg-status` 写"请稍后再试。"，等待 `Retry-After` 后写"现在可以重试"，然后重新加载；15 s 没有应答或网络错误 → 写"网络连接不稳定，正在重新加载…"，然后重新加载。从不重发同一个 C：nonce 可能已经消费 |
| 播报（WCAG 4.1.3） | 每个状态转移对应的可见文字都写入 `#mg-status`，每次转移只写一次，不随进度更新。按住达到 `hold_ms` 时写"可以松开了"；提前松开写"请按住稍久一些"。`#mg-hold` 的可访问名称只在切换到单次激活或"改用按住验证"时改变 |
| 焦点 | 控件节点在页面生命周期内不替换、不重建。忙碌状态用 `aria-disabled="true"` 并忽略激活，从不对拥有焦点的元素设 `disabled` 或 `hidden`。进入 `POW_ONLY` 后 `#mg-alt-pow` 保持可见（`aria-disabled`），焦点不动。失败、新 C 重置与 429 之后，焦点留在原控件上，结果只经 `#mg-status` 播报。页面加载时不主动移动焦点 |
| WebCrypto 不可用 | 交互式无法完成：`#mg-status` 写"当前浏览器无法完成验证，请更新或换用其他浏览器"，并显示请求 ID |

### 12.7 文案（zh-CN / en）

规则沿用 09 §2.3：
- 文案要短、中性，各状态的标签彼此可以区分；
- 不出现"机器人""可疑""已被拦截"等措辞；
- 不显示倒计时，不说明失败原因；
- 帮助信息放在单独的"排查问题"链接里（`#mg-help`，指向 `challenge.help_path`）；
- 页面语言按 §7.3 选择，两种语言都不匹配时用 `challenge.default_lang`。

| 位置 | zh-CN | en |
|---|---|---|
| 目的说明 | 为防止自动化滥用，请按住或点击"按住以验证"按钮完成验证。 | To protect this site from automated abuse, press and hold, or click, the "Press and hold to verify" button. |
| 按钮名 | 按住以验证 | Press and hold to verify |
| 按住中 | 继续按住… | Keep holding… |
| 达到时长 | 可以松开了 | You can let go now |
| 提前松开 | 请按住稍久一些 | Hold a little longer |
| 按住被系统中断 | 无法按住？可以直接点击 | Can't hold? You can click instead |
| 按住过久 | 按住时间过长，请改为点击 | That took too long. Please click instead. |
| PoW 收尾 | 正在完成… | Finishing… |
| 提交中 | 正在验证… | Verifying… |
| 成功 | 验证完成 | Verified |
| 单次激活入口 | 无法按住？改为按一下 | Can't press and hold? Press once instead |
| 单次激活按钮名 | 按一下以验证 | Press to verify |
| 单次激活进行中 | 正在验证，请稍候… | Verifying, please wait… |
| 无障碍入口 | 改用自动验证（较慢） | Verify automatically (slower) |
| `pow_a11y` 进行中 | 正在验证，通常需要几秒钟 | Verifying. This usually takes a few seconds. |
| `pow_a11y` 较慢 | 仍在验证，较慢的设备可能需要一分钟 | Still verifying. Slower devices can take up to a minute. |
| 改回按住 | 改用按住验证 | Use press and hold instead |
| Turnstile 进行中 | 正在进行安全检查… | Running a security check… |
| 失败 | 验证未完成，请重试。 | Verification didn't complete. Please try again. |
| 临时阻断 | 请稍后再试。 | Please try again later. |
| 等待结束 | 现在可以重试 | You can try again now |
| 网络问题 | 网络连接不稳定，正在重新加载… | Connection problem. Reloading… |
| Cookie 被阻止 | 请允许本站使用 Cookie 后重试 | Please allow cookies for this site, then try again |
| 浏览器不支持 | 当前浏览器无法完成验证，请更新或换用其他浏览器 | This browser can't complete the check. Please update it or use another browser. |
| 页面无响应（`#mg-stuck`） | 页面没有响应？请更新浏览器或换用其他浏览器 · 请求 ID：{request_id} | Page not responding? Please update your browser or use another one · Request ID: {request_id} |
| 失败附加 | 排查问题 · 请求 ID：{request_id} | Troubleshoot · Request ID: {request_id} |
| 无 JS | 此页面需要启用 JavaScript 完成验证。请求 ID：{request_id} | JavaScript is required to complete this check. Request ID: {request_id} |
| 隐私链接 | 隐私说明 | Privacy |

交互式页面上，`#mg-status` 的初始文字为空（Phase 1 的"请稍候…"只用于非交互式页面）。

### 12.8 行为摘要（缺省关闭，D-48）

只在 `data-mg-telemetry="behavior"` 时采集。每个页面汇总一次。页面可见时每 20 s 预先签好一个 `/__mg/t` 的证明；页面隐藏时同步用 `fetch(…, {keepalive: true})` 发出，没有可用证明时以 `signed = false` 发送。`sendBeacon` 带不了请求头，所以不用它。

摘要 schema（`v = 1`），在端上量化：

```json
{"v": 1,
 "ptr":    {"speed": [16 counts], "curv": [16 counts], "pauses": b},
 "keys":   {"iki": [16 counts]},
 "scroll": {"dist": b, "speed": [8 counts]},
 "touch":  {"area_var": 0, "pressure_var": 0},
 "focus": b, "vis": b,
 "form":   {"fill_ms": b, "paste": b}}
```

- `b` 为 `logBucket`（0–31）；数组为各桶的计数，每项 0–65535；`area_var`、`pressure_var` 为 0 或 1。
- 按键只记间隔（`iki`），不含按键内容。
- 未知字段丢弃。整个摘要 ≤ 2048 字节，不含原始轨迹、按键值、表单内容、页面文本与任何标识。
- 有效与无效样例在 `testdata/phase2/samples/telemetry/`，WP-C5（解析与重新序列化）与 WP-W2（生成）都按它测试。

### 12.9 发布

- 从 WP-E2a 起，`mg-edge` 的版本为 0.2.0。SDK 版本 `0.3.0`（`package.json` 与 `SDK_VERSION`）在 E2a 的切换 PR 中确定（§2.1），要求 `mg-edge ≥ 0.2.0`；Edge 继续支持 0.2.x 的目录。sdk/web README 列出 SDK 与 Edge 的兼容表。
- 0.3.x 的 dist-tag 仍为 `preview`；Phase 2 验收通过后的版本改用 `latest`。
- 发布改由 `.github/workflows/publish-sdk.yml` 完成：手动触发，在打了 `web-sdk-v*` 标签的提交上运行，npm ≥ 11.5，用 npm trusted publishing 并带 provenance（D-63），不需要长期 npm token。工作流先确认构建产物与 `edge/tests/fixtures/sdk/` 逐字节一致，再发布。
- trusted publisher 需要所有者在 npmjs.com 上一次性登记（仓库与 `publish-sdk.yml`，§19）。

### 12.10 测试

- **已知答案向量**：`testdata/phase2/kat.json` 的 `pow_v2`、`jwk_thumbprint`、`es256`（用 WebCrypto 验签）、`submission_message`、`renew_message`、`mg_proof`（构造的证明能被向量中的验证规则接受）、`ui_params`。
- **控件状态机**：用可注入的最小 DOM 与假时钟测试。覆盖四条路径；中止的每种原因；WCAG 2.5.2 的抬起提交；`pointercancel`；指针移出（进度层不影响判定）；失焦；非主指针被忽略；按住超过 28 s。
- **click 分类**：读屏式的"按下、立即抬起、click"进入 `WAITING`；完成按住之后的 click 被忽略；Enter 自动重复只产生一次 `WAITING`。
- **无障碍规则**：模板 v2 的结构、按钮名、`aria-describedby`；每个可见的状态文字在每次转移时恰好经 `#mg-status` 写入一次；失败重置、模式切换与 429 → `READY` 之后 `document.activeElement` 不变；reduced motion 与 forced colors 的样式存在。
- **提交与续期**：每种应答的转移（200、403 有无新 C、429、超时、网络错误、404）；Cookie 被阻止时不跳转；从不重发同一个 C；绑定续期在途时按下。
- **PoW 协议**：ack、part、ok、err；`sv` 不同时重建一次再退到主线程；2 s 内无 ack 退到主线程；切换 Provider 时保留子题。
- **transport**：每种响应分类；没有 `MG-Error` / `MG-Challenge` 的 403 原样返回；难度过高时不求解；请求体可重放与不可重放；5 个并发的被挑战请求只产生 1 次提交；`cf-mitigated` 的 60 s 保护与无存储时不重载；`mg_proof_required` 的四步流程；跳转后的重试；`htm` 的大小写规则。
- **密钥存储**：IndexedDB 超时 → localStorage → 内存；两个标签页同时生成时得到同一把密钥（`ConstraintError` 分支）；轮换条件。
- **其他**：刷新定时器的计算与跨标签页单飞；遥测预算与丢弃顺序；离页队列；用假的 `turnstile` 对象测试 Turnstile 加载（每类错误码都回退）；大小预算。
- 没有真实浏览器的 CI 作业。真实浏览器与辅助技术的验收由所有者完成（§19、§20）。

## 13. 近线 worker `mg-nearline`（WP-N1；`mg:ev` v2 的写入归 WP-C5 / E2b）

近线 worker 只在 Valkey 模式且配置包 `events.stream = true` 时有输入（D-38、D-53）。它从不在请求路径上：worker 停止时，stream 按 `MAXLEN ~` 截断，已写的 verdict 按 TTL 过期，Edge 照常按规则评分（02 §4）。

### 13.1 `mg:ev` v2 条目

决定条目（每个求值过的请求一条，不采样）。v1 的字段在前、顺序不变，v2 的字段依次追加在后：

```
v 2 kind decision site <site> ts <ms> rid <request_id> sess <sub | ""> route <route> action <action> dry <0|1>
class <class> score <0-100> ipk <kh ip | ""> pfk <kh prefix | ""> asn <n | 0> status <http status | 0>
m <method> ph <16 hex | ""> ct <h|a|j|o|""> bt <0|1> xs <0|1> tk <0|1> pf <-|v|u|j|r|x> uf <ua family | "">
fam <4|6|""> ctype <invisible|pow|interactive|"">
```

| 字段 | 含义 |
|---|---|
| `m` | 请求方法，截断到 16 字节 |
| `ph` | `lower_hex(HMAC-SHA256(K_pseudo, "mg-path-v1" ‖ 0x00 ‖ site ‖ 0x00 ‖ p))[0..16]`。`p` 是 `rfc3986_view` 去掉查询串后的路径；站点 `case_insensitive_paths` 时转为小写；命中 `redact_path` 路由的请求，`p` 为 `/<route name>`，所以拿到 `K_pseudo` 也无法核对带令牌的 URL。worker 只用它统计不同路径的个数，拿不到路径本身 |
| `ct` | 源站响应 `Content-Type` 的类别：`h` = `text/html`；`a` = 静态资源（`text/css`、`*/javascript`、`image/*`、`font/*`）；`j` = `application/json` 或 `+json`；`o` = 其他；空串 = 没有源站响应（Edge 自己应答） |
| `bt` | 路径命中扫描诱饵名单时为 1（见下） |
| `xs` | `Sec-Fetch-Site` 为 `cross-site` 或 `same-site`，且 `Sec-Fetch-Mode` 不是 `navigate` 时为 1：由别的站点发起、浏览器代发的子资源请求。第三方页面能让访客的浏览器发出这类请求，所以扫描器与高速率检测器不计它们。代价是自称跨站的客户端不进入这两个检测器，但它们仍受逐请求的评分约束 |
| `tk` | 请求带有效凭证时为 1 |
| `pf` | 证明结果：`-` 没有校验（或没有证明）、`v` 有效、`u` 未绑定、`j` 与凭证的 `cnf.jkt` 不符、`r` 重放、`x` 其他失败 |
| `uf` | UA 家族（`mg_core::ua::parse` 的 family，不含版本），≤ 16 字节 |
| `fam` | 客户端 IP 的地址族：`4` 或 `6`；IP 未知时为空串 |
| `ctype` | `action = challenge` 时的挑战类型，否则为空串 |

- 反馈条目（`/__mg/c`、续期中计失败的结果与 `renew_rebind`）：v1 的字段（`v kind site ts rid route outcome type pfk asn`）在前，v2 追加 `p <provider | ""> ipk <kh ip | ""> sess <新凭证的 sub | ""> lvl <lvl | "">`。
- 不写客户端 IP 明文、`client_conn_key`、`jkt` 或路径原文。
- `testdata/phase2/samples/mg-ev-v2.txt` 给出样例（格式见 §0.4）。WP-C5 的写入与 WP-N1 的解析都按它测试。
- worker 也接受 v1 条目，用不到的字段视为缺失。

**内置扫描诱饵**（glob，按 Phase 1 规格 §9.4 的完全解码视图、不区分大小写匹配）：
`/.env`、`/.env.*`、`/.git/**`、`/.svn/**`、`/.hg/**`、`/.DS_Store`、`/wp-login.php`、`/wp-admin/**`、`/xmlrpc.php`、`/phpmyadmin/**`、`/pma/**`、`/server-status`、`/actuator/**`、`/vendor/phpunit/**`、`/cgi-bin/**`、`/.aws/**`、`/boaform/**`、`/HNAP1`。

站点若真的提供其中某个路径（例如自己就是 WordPress），设 `scanner_baits.builtin: false`，再用 `extra` 列出自己的诱饵。

### 13.2 消费

- 启动时，若消费组 `nl` 不存在，执行 `XGROUP CREATE mg:ev nl $ MKSTREAM`，只消费新条目。然后用 `XINFO CONSUMERS` 找出没有待确认条目的旧消费者（以前的进程），执行 `XGROUP DELCONSUMER` 删除它们。
- 启动时与之后每 60 s，用 `XAUTOCLAIM mg:ev nl <consumer> 60000 0-0 COUNT 512` 认领空闲超过 60 s 的待确认条目，包括已退出的消费者留下的条目。
- 主循环：`XREADGROUP GROUP nl <consumer> COUNT 512 BLOCK 1000 STREAMS mg:ev >`。逐条解析、更新窗口、执行检测器，写完 verdict 后再 `XACK`。语义是至少一次，窗口计数可以容忍重复。
- `<consumer>` 为 `<hostname>-<pid>`。只运行一个实例（systemd 单元），对应 02 §4 的"单一消费者"。
- 解析失败的条目照样 `XACK`，计 `mg_nl_parse_errors_total`。不在配置 `sites` 中的站点，条目确认后忽略。

### 13.3 窗口与检测器 v1

窗口按站点保存在 worker 内存中，以 1 分钟为桶滑动。每类键至多 200,000 个；满时丢弃新键并计 `mg_nl_window_dropped_total`，已有的键不被淘汰，所以大量新键无法冲掉正在累积的计数。检测是尽力而为的，worker 重启后窗口从零开始。键为空（例如 IP 未知时 `ipk` 为空）的条目不进入对应窗口。

| 检测器 | 键 | 窗口 | 计入的条目 | 条件（缺省） | verdict |
|---|---|---|---|---|---|
| `scanner` | `ipk` | 10 分钟 | 决定条目，`tk = 0` 且 `xs = 0` | `bt = 1` 的不同 `ph` ≥ 2；或者状态码为 404 / 403 / 405 的不同 `ph` ≥ 30，且这些状态占该实体全部计入条目的 ≥ 60% | `ip`，risk 80，labels `[nl_scanner]`，TTL 15 分钟 |
| `shared_token` | `sess` | 10 分钟 | 决定条目，`pf = j` | 同一 `sess` 的条目 ≥ 3，且来自 ≥ 2 个不同的 `pfk` | `session`，risk 85，labels `[nl_shared_token]`，TTL 1 小时 |
| `challenge_abuse` | `pfk` | 10 分钟 | 反馈条目 | `outcome = fail` ≥ 30，且通过率 < 10% | `prefix`，risk 70，labels `[nl_challenge_abuse]`，TTL 30 分钟 |
| `high_rate` | `ipk` | 5 分钟 | 决定条目，`ct ∈ {h, j, o}`、`tk = 0`、`xs = 0` | 连续 5 个 1 分钟的桶里每分钟都 ≥ 600；窗口内该 `ipk` 出现 ≥ 3 个不同的 `sess` 或 `uf` 时视为共享出口（网吧、学校、补习班），不产生 verdict | `ip`，risk 75，labels `[nl_high_rate]`，TTL 15 分钟 |

- **IPv6**：`fam = 6` 的条目另按 `pfk`（/48）建 `scanner` 与 `high_rate` 窗口，阈值为上表的 4 倍，产生 `prefix` verdict（风险与 TTL 同上）。持有 /48 的客户端可以在 65,536 个 /64 之间轮换，只按 `ipk` 计数就永远达不到阈值。
- **只抬高风险**：近线的 verdict 只经评分抬高风险（D-10），从不带矩阵会直接阻断的 `scanner` 标签：`scanner` 标签只用于所有者手写的 verdict（D-53）。按单个 IP 直接阻断会误伤 CGNAT、校园网与办公网的邻居，而第三方网页可以让访客的浏览器发出诱饵请求。被抬高风险的人类访客仍能通过挑战。
- **`shared_token`**：`pf = j` 表示请求带着有效凭证，证明却来自另一把密钥，即同一个凭证被另一个持有自己会话密钥的客户端使用。正常访客只在密钥被清除后的短时间内产生它（§9.1 的就地恢复几秒内就会结束），也很少在 10 分钟内跨两个前缀。只换网络（Wi-Fi 与蜂窝网络切换、多节点代理）不会产生 `pf = j`。
- Phase 2 不产生 `asn` 类型的 verdict：范围太大，误伤成本高。

**验收比例**（§20）：worker 另按站点计算两个 7 天比例，按天保存去重集合（每天每站点至多 200,000 个键，超出时当天的比例记为不可用）：
- `mg_nl_interactive_visitor_share{site}`：收到交互式 C（决定条目 `action = challenge`、`ctype = interactive`）的不同 `ipk`，除以有 `ct = h` 请求的不同 `ipk`；
- `mg_nl_interactive_abandon_share{site}`：收到交互式 C、且 10 分钟内没有通过（同一 `ipk` 没有 `outcome = pass` 的反馈条目）的不同 `ipk`，除以收到交互式 C 的不同 `ipk`。

分母少于 2,000 时，两个比例都不导出（不足以判断）。

### 13.4 verdict 输出

- 值为 `EntityVerdict` 的 JSON（Phase 1 格式）：
  - `source = "nearline/<detector>"`、`version = "p2.1"`；
  - `reasons` 为检测器的原因码，如 `nl.scanner.bait`；
  - `expires_at_ms = now + TTL`。
- 写入经 Lua 脚本 `mg_verdict_put`（§14.2）。它从不覆盖所有者手工写的（`source` 不以 `nearline/` 开头的）未过期 verdict；覆盖其他检测器的 verdict 只在新风险更高时，同一检测器的 verdict 则可以刷新。
- **所有者压住误伤**：写一条 `source = "owner"`、`risk = 0`、带 `expires_at_ms` 的 verdict 到同一个键（§19 给出命令）。近线不会覆盖它，到期后自然恢复。
- `mode = shadow`（每个检测器的缺省）时不写 Valkey，只打一条 INFO 日志并计数，日志中只有伪名键，没有 IP。
- 配置了 `verdict_events.vl_main` 时，每个 verdict（shadow 也算）另写一行 `kind=verdict`（§15.3）。
- 不用 `mg:pub:inv`：Edge 的 verdict 缓存只有 2 s。

### 13.5 配置文件

```yaml
version: 1
valkey:
  url: "unix:///run/valkey/valkey.sock"     # or redis://127.0.0.1:6379/ ; loopback only
  user: mg-nearline
  password_file: "${CREDENTIALS_DIRECTORY}/mg-nearline-valkey"
stream: {key: "mg:ev", group: nl, batch: 512, block_ms: 1000, reclaim_idle_ms: 60000, reclaim_every_s: 60}
sites: [blog]
verdict_events: {vl_main: "http://127.0.0.1:9428"}    # optional; same URL rules as edge.toml (I-11)
metrics_listen: "127.0.0.1:9902"
windows: {max_keys: 200000, ipv6_prefix_factor: 4}
detectors:
  scanner:         {mode: shadow, bait_distinct: 2, distinct_404: 30, share_404: 0.6, risk: 80, ttl: 15m}
  shared_token:    {mode: shadow, proof_mismatch: 3, distinct_prefix: 2, risk: 85, ttl: 1h}
  challenge_abuse: {mode: shadow, fails: 30, max_pass_ratio: 0.1, risk: 70, ttl: 30m}
  high_rate:       {mode: shadow, per_minute: 600, minutes: 5, shared_egress: 3, risk: 75, ttl: 15m}
acceptance: {window_days: 7, min_denominator: 2000, max_keys_per_day: 200000}
```

- 未知键报错。配置值中只展开 `${CREDENTIALS_DIRECTORY}`，其他 `${…}` 报错。
- `mg-nearline --check-config` 校验配置文件并连通 Valkey 后退出。
- 出站 HTTP（只有 `vl_main`）使用 User-Agent `morphgate-dev-tooling`。

### 13.6 部署与 ACL

- **systemd 单元**：`deploy/systemd/mg-nearline.service`。
  - `DynamicUser=yes`；连 unix socket 时加 `SupplementaryGroups=valkey`（socket 的 `unixsocketperm` 为 0770），或改用回环 TCP；
  - `LoadCredentialEncrypted=mg-nearline-valkey:/etc/credstore.encrypted/mg-nearline-valkey`；
  - `IPAddressAllow=localhost`、`IPAddressDeny=any`；`MemoryMax=512M`；`Restart=on-failure`；日志写入 journald 命名空间 `morphgate`。
- **Valkey ACL 用户 `mg-nearline`**（每个配置的站点一项 `~mg:v:<site>:*`，不含 `mg:v:all:*`）：

  ```
  ACL SETUSER mg-nearline on >… resetkeys resetchannels -@all +get +set +xreadgroup +xack +xautoclaim +xgroup|create +xgroup|delconsumer +xinfo|groups +xinfo|consumers +xpending +xlen +evalsha +script|load +ping +hello +select +client|setname +client|setinfo ~mg:ev ~mg:v:blog:*
  ```

  - Valkey 对脚本内执行的命令同样做 ACL 检查，所以 `mg_verdict_put` 需要 `+get +set`；`EVALSHA` 的声明键要求同一个键模式兼有读与写，所以 verdict 键用完整的 `~` 模式。
  - ACL 无法限定"只经脚本写入"：持有这个用户的进程可以直接写本站点的 verdict。"不覆盖所有者 verdict"只是脚本的性质。
  - 它不能读写其他键，也不能用 pub/sub（10 EVT-08）。§0.4 的落地 PR 记录所选 Go 客户端连接时发送的命令，并据此核对本列表。
- Edge 的 ACL 见 §14.5。

### 13.7 指标

worker 在 `metrics_listen` 上以文本格式暴露以下指标：

| 指标 | 类型 | 标签 |
|---|---|---|
| `mg_nl_entries_total` | counter | site, kind |
| `mg_nl_parse_errors_total` | counter | — |
| `mg_nl_verdicts_total` | counter | site, detector, mode |
| `mg_nl_lag_seconds` | gauge | — |
| `mg_nl_backlog` | gauge | — |
| `mg_nl_pending` | gauge | — |
| `mg_nl_window_dropped_total` | counter | detector |
| `mg_nl_errors_total` | counter | op |
| `mg_nl_last_batch_timestamp_seconds` | gauge | — |
| `mg_nl_interactive_visitor_share` | gauge | site |
| `mg_nl_interactive_abandon_share` | gauge | site |

- `mg_nl_backlog`：`XINFO GROUPS` 中组 `nl` 的 `lag`（尚未投递的条目数，Valkey ≥ 7.2），每 15 s 读取一次。告警用它：消费者停止时，积压只体现在这里。
- `mg_nl_lag_seconds`：组已追上（`lag = 0` 且没有待确认条目）时为 0，否则为当前时间减最早的未确认或未投递条目的 `ts`。站点夜间没有流量时它保持 0，不会误报。
- `mg_nl_pending`：`XPENDING` 的条目数，正常时不超过一个批次。
- 告警见 §19。

## 14. 状态层（WP-C5）

### 14.1 键（Phase 1 规格 §9.7 之外新增或改变的）

| 键 | 类型 | 操作 | TTL |
|---|---|---|---|
| `mg:jti:{site}:{kj}:{jti}` | String `1` | Edge：往返 1 中的 `mg_jti` v1（§9.2） | 40 s |
| `mg:jc:{site}:{kj}` | String（整数） | Edge：`mg_jti` v1 内，每把密钥 60 s 内的 `jti` 计数 | 60 s |
| `mg:rp:{site}:turnstile:{th}` | String `1` | Edge：`mg_nonce_issue` v2 内（§14.2）；`th = lower_hex(SHA-256(token))[0..32]` | 300 s |
| `mg:v:{site}:{type}:{key}` | `EntityVerdict` JSON | Edge `MGET`；近线 `EVALSHA mg_verdict_put` | 写入方设置 |
| `mg:ev` | Stream（条目 v2） | Edge `XADD`；近线 `XREADGROUP` / `XACK` / `XAUTOCLAIM` | `MAXLEN ~` |

### 14.2 Lua 脚本

`mg_nonce_issue` v2 取代 v1，Edge 只加载 v2：

```lua
-- mg_nonce_issue v2
-- KEYS[1]            = mg:n:{site}:{nonce_hex}
-- KEYS[2 .. 1+R]     = provider-token replay keys mg:rp:{site}:{provider}:{th}   (R = ARGV[3], 0 or 1)
-- KEYS[2+R ..]       = issuance limiters mg:rl:{site}:{limiter}:{kh} (may be none)
-- ARGV[1]            = nonce TTL in ms (>= 1)
-- ARGV[2]            = now_us ("0" = server clock)
-- ARGV[3]            = R
-- ARGV[4]            = replay-key TTL in ms (ignored when R = 0)
-- ARGV[5 + 3(i-1)]   = interval_us, ARGV[6 + 3(i-1)] = burst, ARGV[7 + 3(i-1)] = cost   (i-th limiter)
-- returns {0} when the nonce was already used; {2} when a provider token was already used (the nonce IS consumed);
--         otherwise {1, allowed, retry_after_us, tat_minus_now_us, ...}, 3 integers per limiter; limiters are
--         written only when all of them allow
if not redis.call('SET', KEYS[1], '1', 'NX', 'PX', tonumber(ARGV[1])) then
  return {0}
end
local r = tonumber(ARGV[3])
for j = 1, r do
  if not redis.call('SET', KEYS[1 + j], '1', 'NX', 'PX', tonumber(ARGV[4])) then
    return {2}
  end
end
local now = tonumber(ARGV[2])
if now == 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
end
local out = {1}
local writes = {}
local all_allowed = true
for i = 2 + r, #KEYS do
  local base = 5 + (i - 2 - r) * 3
  local interval = tonumber(ARGV[base])
  local burst = tonumber(ARGV[base + 1])
  local cost = tonumber(ARGV[base + 2])
  local dvt = interval * burst
  local tat = tonumber(redis.call('GET', KEYS[i]) or '0')
  if tat < now then tat = now end
  local new_tat = tat + interval * cost
  local allow_at = new_tat - dvt
  if now < allow_at then
    all_allowed = false
    out[#out + 1] = 0
    out[#out + 1] = allow_at - now
    out[#out + 1] = tat - now
  else
    writes[#writes + 1] = {KEYS[i], new_tat}
    out[#out + 1] = 1
    out[#out + 1] = 0
    out[#out + 1] = new_tat - now
  end
end
if all_allowed then
  for _, w in ipairs(writes) do
    local ttl_ms = math.ceil((w[2] - now) / 1000)
    if ttl_ms < 1 then ttl_ms = 1 end
    redis.call('SET', w[1], string.format('%d', w[2]), 'PX', ttl_ms)
  end
end
return out
```

`mg_jti` v1（Edge，§9.2）：

```lua
-- mg_jti v1
-- KEYS[1] = mg:jti:{site}:{kj}:{jti}
-- KEYS[2] = mg:jc:{site}:{kj}
-- ARGV[1] = per-key limit (600)
-- ARGV[2] = counter window in ms (60000)
-- ARGV[3] = jti TTL in s (40)
-- returns {0} fresh, {1} replay, {2} per-key quota exceeded (treated as a replay of this key only)
local n = tonumber(redis.call('GET', KEYS[2]) or '0') + 1
if n > tonumber(ARGV[1]) then
  return {2}
end
if n == 1 then
  redis.call('SET', KEYS[2], '1', 'PX', tonumber(ARGV[2]))
else
  redis.call('SET', KEYS[2], tostring(n), 'KEEPTTL')
end
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[3])) then
  return {1}
end
return {0}
```

它只用 `GET` 与 `SET`，所以 Edge 的 ACL 不需要新命令。

`mg_verdict_put` v1（近线）：

```lua
-- mg_verdict_put v1
-- KEYS[1] = mg:v:{site}:{type}:{key}
-- ARGV[1] = verdict JSON (EntityVerdict with source "nearline/<detector>")
-- ARGV[2] = TTL in ms (>= 1000)
-- ARGV[3] = risk of the new verdict (0..100)
-- ARGV[4] = now_ms
-- ARGV[5] = source of the new verdict ("nearline/<detector>")
-- returns 1 when written, 0 when an existing live verdict wins
local cur = redis.call('GET', KEYS[1])
if cur then
  local ok, v = pcall(cjson.decode, cur)
  if not ok or type(v) ~= 'table' then
    return 0
  end
  local exp = tonumber(v['expires_at_ms']) or 0
  if exp > tonumber(ARGV[4]) then
    local src = v['source']
    if type(src) ~= 'string' or string.sub(src, 1, 9) ~= 'nearline/' then
      return 0
    end
    if src ~= ARGV[5] and (tonumber(v['risk']) or 0) >= tonumber(ARGV[3]) then
      return 0
    end
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', tonumber(ARGV[2]))
return 1
```

- 所有者手写的或无法解析的值从不被覆盖。
- 其他检测器的未过期 verdict 只在新风险更高时被覆盖；风险相等时保留原值，以免丢掉它的标签、缩短它的 TTL。
- 同一检测器可以刷新自己的 verdict。

三个脚本都按本文逐字节实现。连接建立时用 SHA 核对，与 Phase 1 相同。WP-C5（`mg_nonce_issue` v2、`mg_jti` v1）与 WP-N1（`mg_verdict_put` v1）各自对真实 Valkey、以各自的 ACL 用户测试脚本，包括并发双提交、重放键已存在、按密钥的配额、所有者 verdict 与无法解析的值不被覆盖、风险相等时不覆盖。

### 14.3 往返（每请求至多 2 次，同 02 §1）

| 路径 | 往返 1 | 往返 2 |
|---|---|---|
| 普通请求 | `MGET` verdict + `EVALSHA mg_gcra` + `EVALSHA mg_jti`（只在证明通过 §6.7 时） | — |
| `POST /__mg/c` | 同 Phase 1；另加 `mg.a11y.issue` 两级的检查（不论 `p`，§7.5 第 2 步），以及所带旧凭证的会话 verdict（`MGET mg:v:{site}:session:{sub}`，§6.8） | `EVALSHA mg_nonce_issue` v2：nonce、token 重放键（`p = turnstile`）、签发配额（`p = pow_a11y` 时含 `mg.a11y.issue`） |
| `POST /__mg/c/renew` | — | `EVALSHA mg_nonce_issue` v2：只有 nonce（`R = 0`，没有限速器） |
| `POST /__mg/r` | `MGET` + `EVALSHA mg_gcra`（`write = 0`）+ `EVALSHA mg_jti` | — |
| `POST /__mg/t` | — | — |

Turnstile 的 siteverify 是出站 HTTP，不是 Valkey 往返；它发生在往返 2 之后（§7.5 第 13 步）。

### 14.4 本地模式

- **新增的进程内集合**：`jti`（容量 `local_jti_capacity`，TTL 40 s，另有按密钥的计数）与 token 重放（容量 `local_rp_capacity`，TTL 300 s）。规则同 D-35：从不逐出未过期的项，溢出即"不可用"，计 `mg_state_local_overflow_total{table="jti" | "rp"}`。
- 本地模式下 `mg_nonce_issue` v2 的语义由同一组进程内表实现：先 nonce，再重放键，最后配额。`mg.a11y.issue` 在本地模式下也是进程内的。
- `mg.ix.issue`、`mg.c.renew`、`mg.r`、`mg.t` 总是进程内的限速器（GCRA 表与 Phase 1 相同，限速器 id 不同）。
- **`local_nonce_capacity`**：交互式 C 的 nonce 存活 660 s（寿命 600 s 加 60 s），续期也写入，Phase 1 按 120 s 估算的容量约小 3.7 倍。启用交互式时按 `(submit_rate / submit_period_s + renew_rate / renew_period_s) × 660 × 预计同时活跃的前缀数` 估算；单机站点建议 ≥ 400,000（`--check-config` 在低于它时提示，§10.1）。

### 14.5 Edge 的 ACL（改 Phase 1 规格 §17 第 2 步）

完整规则（在 Phase 1 的基础上增加键模式 `~mg:jti:* ~mg:jc:* ~mg:rp:*`，命令不变）：

```
ACL SETUSER edge on >… resetkeys resetchannels -@all +get +set +mget +evalsha +script|load +ping +xadd +time +select +client|setinfo +client|setname %R~mg:v:* ~mg:rl:* ~mg:n:* ~mg:jti:* ~mg:jc:* ~mg:rp:* %W~mg:ev
```

仍然没有频道、不能读 `mg:rev:*`，也不能写 `mg:v:*`。`edge/tests/valkey_acl.rs` 按这一行更新（WP-E2b）；`mg-nearline` 用户的测试由 WP-N1 对真实 Valkey 完成。

## 15. 事件与指标

### 15.1 `kind=feedback`（vl-main，改 Phase 1 规格 §13.3）

Phase 1 的字段之外，新增 §3.3 的 `renew_no`、`bound`、`ix`、`provider`：
- `provider_id` 为实际提交的 Provider；
- `outcome` 可为 `unavailable` / `misconfigured`；
- `lvl` 可为交互级；
- `attempt_no` 为 C 中的值。

`msg = "challenge <outcome> <type>/<provider> route=<route>"`。`ix.features` 只含 §7.8 表中的键。

续期只在两种情况下写 `kind=feedback`：计失败的结果（`outcome = fail`），以及已绑定 C 换了前缀（`outcome = renew_rebind`）；两者都带 `renew: true`。成功的续期只计指标。

### 15.2 `kind=telemetry`（vl-short，改 Phase 1 规格 §13.5，D-62）

| `source` | 来自 | 内容 |
|---|---|---|
| `challenge` | `/__mg/c` 的 `t` | `env`、`auto`（Phase 1 schema）、`ix`（§7.6）；只在至少有一项时写出（同 I-32） |
| `sdk` | `/__mg/t` 的每条报告 | `kind`、`signed`、报告字段；`behavior` 的 `summary` |
| `refresh` | `/__mg/r` 的 `t`，只在 `events.telemetry_behavior = true` 时 | 同 `challenge` 的 schema |

- 三者共用 edge-core 中唯一的一份实现：按已知字段与长度上限重新序列化，丢弃未知字段，不含 `userAgent`。`t.ix` 解析为 `mg_core::IxTelemetry`（§0.4）。
- `sdk` 来源的行进入独立队列 `queue_telemetry`（§9.4）。
- `edge/src/submission.rs` 中的重复实现删除。

### 15.3 新的事件种类与决定事件的新字段

- **`kind=refresh`**（vl-main）：`{request_id, result, reason, lvl, level_age_s, bound}`，`msg = "refresh <result> lvl=<lvl>"`。`reason` 取 §5.7 的拒绝原因，或 `proof.*`。
- **`kind=access`**（改 Phase 1 规格 §13.4）：增加 `sess`（请求所带有效凭证的 `sub`，没有时省略）与 `ct`（§13.1 的类别）。§20 的人为摩擦按它计算。
- **`kind=verdict`**（vl-main，由近线写出）：`EntityVerdict` 的字段，加上 `detector`、`mode`（`shadow` / `enforce`）、`written`（脚本是否写入）、`evidence`（计数，例如 `{"bait": 3, "distinct_404": 41}`）。只有伪名键，没有 IP。
- **决定事件**：
  - `ctx.http.navigation`；
  - `ctx.identity.proof.{present, valid, replayed}`；
  - `ctx.identity.token.{bound, level_age}`；
  - 交互式挑战的 `decision.provider_id`（`C.providers` 的首个）；
  - 顶层字段 `forced_monitor: true`（D-60）、`proof_required: true`（应用了 `edge.proof_required` 时）。
- 带 `ruc` 凭证的决定事件总是写出（D-62）。

### 15.4 `mg:ev`

见 §13.1。

### 15.5 指标（Phase 1 规格 §13.7 之外新增或改变的）

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `mg_challenge_total` | counter | type, provider, result | `provider` 取 `none` / `self_hold` / `pow_a11y` / `turnstile`。`result` 新增 `renewed`（续期签发的 C）与 `reissued`（失败应答附的新 C）；`issued` 只计决策签发的 C（受保护请求与 `/__mg/v`） |
| `mg_challenge_renew_total` | counter | result | `ok`、`rebind`、`cap`、`expired`、`invalid`、`body`、`binding`、`sig`、`nonce_reused`、`unavailable`、`interactive_unavailable`、`rate_limited`、`no_client_ip`、`too_early` |
| `mg_interactive_score` | histogram | provider, mode | 桶 0.1 … 1.0，步长 0.1 |
| `mg_interactive_available` | gauge | site | §5.1 |
| `mg_navigations_total` | counter | site | 到达决策步骤的导航请求（`http.navigation` 且方法为 GET），含 `/__mg/v`；人为摩擦的分母（§20） |
| `mg_provider_verify_total` | counter | provider, outcome, reason | `reason` 取 `ok`、`hostname`、`action`、`cdata`、`time`、`fail`、`dup`、`bad_request`、`secret`、`internal`、`transport`、`timeout`、`http`、`malformed`、`precheck`、`busy` |
| `mg_provider_verify_latency_seconds` | histogram | provider | 桶 0.05、0.1、0.25、0.5、1、2、3、5 s |
| `mg_provider_state` | gauge | site, provider, state | `healthy` / `open` / `half_open` / `disabled` |
| `mg_outbound_override` | gauge | target | `target="siteverify"`：非缺省的 siteverify URL 生效（§8.4） |
| `mg_proof_verify_total` | counter | result | §9.1；`missing` 只计命中 `proof = required` 路由、不可豁免、却没有带证明的请求 |
| `mg_token_refresh_total` | counter | result | §9.3 |
| `mg_telemetry_reports_total` | counter | kind, result | `result` 取 `accepted`、`unsigned`、`suppressed`、`invalid`、`disabled`、`rate_limited` |
| `mg_double_challenge_total` | counter | site, route | §9.4，只计可信的报告 |
| `mg_endpoint_cache_hit_reports_total` | counter | site | §9.4，只计可信的报告 |
| `mg_sw_intercept_reports_total` | counter | site | §9.4 |
| `mg_token_ruc_total` | counter | site | D-62 |
| `mg_site_forced_monitor` | gauge | site | D-60 |
| `mg_state_local_overflow_total` | counter | table | `table` 新增 `jti`、`rp` |
| `mg_event_dropped_total` | counter | sink, class | `class` 新增 `telemetry`（§9.4）；关闭时的刷写见 §9.7 |
| `mg_protocol_rejected_total` | counter | listener, reason | `reason` 新增 `bad_target`（§22） |

标签都是有界值。`mg_double_challenge_total` 的 `route` 来自配置包的路由名。`edge/tests/metrics.rs::every_family_is_served_with_its_labels` 同步更新。

## 16. mgctl 命令（WP-G4）

| 命令 | 作用 | 审计条目 |
|---|---|---|
| `mgctl site check` / `bundle build` | 接受 §10.2 的新字段，写出 `schema_version` 1 或 2 | 同 Phase 1 |
| `mgctl bundle verify` | 另列出：交互式配置、Provider（不含秘密）、`proof: required` 的路由、`min_level` 的路由、`help_path` 与 `privacy_path`；`scoring.mode: enforce` 时打印 §7.8 的提醒 | — |
| `mgctl turnstile widgets --account <id>` | 列出 widget（`GET /accounts/{id}/challenges/widgets`；列表不含 secret） | — |
| `mgctl turnstile secret import --account <id> --sitekey <k> --site <site> --out <file>` | 读取 widget（响应含 secret），写出只含当前值的 `mg-turnstile-keys` 文件（权限 0600） | `turnstile.secret.import` |
| `mgctl turnstile secret rotate --account <id> --sitekey <k> --keys <file> [--invalidate-immediately]` | 调用 `rotate_secret`，**显式**传 `invalidate_immediately`（缺省 `false`），写出 `[新, 旧]` | `turnstile.secret.rotate` |
| `mgctl turnstile secret drop-previous --keys <file>` | 写出只含当前值的文件 | `turnstile.secret.drop_previous` |

- `turnstile` 子命令从 `--cf-token-file <file.age>` 读取 Cloudflare API token（只授予 Account → Turnstile → Edit），以 age 解密。
- 出站请求的 User-Agent 为 `morphgate-dev-tooling`，不带所有者身份（I-7、I-15）。
- 写文件之前先确认审计日志可用（I-27）。
- 审计条目只记 sitekey、站点与操作，不记 secret。

## 17. 工作包说明

每个 WP 都满足 §2.4 的完成定义。下面只列交付物与必须的测试，测试名或注释引用本文章节号。

### WP-R4 mg-core（阶段 1）

- **交付**：
  - `core/src/providers.rs`：`SelfHold` / `PowA11y`（实现 `InteractiveChallengeProvider`：`prepare` 返回 `ChallengeSpec { provider, params: {} }`，`ix` 由 Edge 组装（§7.2）；`verify` 不做网络调用，直接给出 `Pass`，硬检查与评分由 `assess_interaction` 完成）、`select_providers`（§5.4）、`min_elapsed_ms` 与 `assess_interaction`（§5.5、§7.7、§7.8）、`next_challenge_after_failure`（§5.3）、`refresh_check`（§5.7）；
  - 矩阵与规则引擎中的 `min_level` 与 `effective_challenge`（§5.2）；
  - `identity.proof` 与 `http.navigation` 字段及其可用性（§4）；策略 IR 的字段引用查询 `reads_field`（§9.1 用它决定是否校验证明）；
  - `ChallengeResult` / `Identity` / `Http` 新字段的 serde 与 proto 往返；
  - `Net` 的 `Debug` 不再打印 `ip_prefix`。
- **测试**：
  - 选择规则的真值表：国家来源组合（含两个来源不一致）、`selection`、`attempt_no` 越过 N、`a11y_pref`、主机与路由不匹配、`redact_path`、不可用；
  - `min_elapsed_ms` 与每条硬检查的边界：`0.95 ×`、30 s、`250 ms` 时间窗、`a11y_min_ms`；
  - 软特征按模态生效（触屏不计 `fast_target` 与 `zero_jitter`；`single` 与 `pow_only` 不计指针特征；`hidden` 只看 `vis_during`）；
  - shadow 不改变结果，enforce 的两个阈值；
  - 升级表（含交互式不可用）；刷新判定的每个拒绝分支；
  - `min_level` 与 D-20 的组合，以及交互式不可用时的有效类型；
  - 仍能编译到 `wasm32-unknown-unknown`。

### WP-R5 mg-challenge（阶段 1）

- **交付**：§6 的全部内容（`keys.rs`、`sealed.rs`、`ui.rs`、`pow.rs`、`jwk.rs`、`sig.rs`、`proof.rs`、`clearance.rs`、`turnstile.rs`）。凭证 v2 只经新入口 `MintV2Params` / `mint_v2` / `mint_refresh`，`MintParams` 与 `mint` 不变（§2.3）。测试辅助：签名、PoW v2 求解、构造证明，只在 `#[cfg(test)]` 与 `testkit` 特性下可用，供 WP-E2 的集成测试使用。
- **测试**：§6.11 全部向量；往返与每条反例；`MG-Proof` 每个失败原因按 §6.7 的顺序给出；刷新复制的字段与 `kid`；随机输入不 panic；`Debug` 不打印密钥、nonce、凭证、JWK 与签名。

### WP-C5 mg-edge-core state / events / bundle（阶段 1）

- **交付**（按 §2.3 只做加法）：
  - `mg_nonce_issue` v2 与本地等价实现（§14.2、§14.4），经新入口 `NonceIssueV2` / `RoundTrip1V2`；`mg_jti` v1 与本地等价实现（§9.2）；
  - `mg:ev` v2 的编码（§13.1），经 `StreamEntry::decision_v2` / `feedback_v2`；
  - 遥测 schema 的唯一实现（§15.2）：`t` 解析为 `mg_core::IxTelemetry`，`behavior` 摘要按 §12.8；
  - `EventsConfig` 的 `shutdown_drain_ms`（字段与 0..10000 的范围）与 `queue_telemetry`（§10.1）；关闭时的刷写（§9.7）；
  - `verify_bundle`：§3.2 新字段的范围检查，`schema_version` 1 / 2 的全部规则，`schema_version = 2` 时接受 `RateLimit.challenge_type = INTERACTIVE`；
  - `edge-core/tests/bundle_golden.rs::golden_phase2_bundle_verifies`（若晚于 WP-G4 合入，§2.1）。
- **测试**：
  - 对真实 Valkey（`MG_REQUIRE_VALKEY` 规则不变）：nonce 已用、重放键已存在（返回 `{2}` 且 nonce 已消费）、配额全有或全无、`jti` 重放、按密钥的 `jti` 配额；
  - 本地模式的溢出与 D-35 规则，本地 `jti` 结论的启动时间条件；
  - `mg:ev` v2 的字段顺序与样例文件一致；
  - 遥测的有效与无效样例（`testdata/phase2/samples/`）；
  - 关闭刷写的时限；
  - 配置包的每个新字段的越界反例；`schema_version` 的每条规则各一个反例。

### WP-C6 mg-edge-core outbound（阶段 1）

- **交付**：
  - `OutboundHttp` 的实现（§8.4），含进程内并发上限；
  - siteverify 客户端、结果解析与 §8.5 的映射（入口与 `SiteverifyExpect` 见 §8.4，返回 `ProviderVerdict`）；
  - siteverify URL 的校验函数：缺省 URL 总是接受，回环 URL 只在调用方传入"允许测试目的地"时接受（WP-E2c 按 `MG_EDGE_TEST_OUTBOUND` 传入）；
  - 熔断与健康状态（§8.6）；
  - `testkit::siteverify`：回环 mock，可编程每个请求的响应、延迟、断连，并记录收到的请求。
- **测试**：
  - 每个错误码与绑定不符的组合；`cdata_ok` 闭包的调用；
  - 重试规则：只重试一次、相同幂等键、不重试 `timeout-or-duplicate`；
  - 旧 secret 重试与它的幂等键；截止时间；并发上限（`busy`，不计入熔断）；
  - 拒绝非白名单 URL；不读代理环境变量；
  - User-Agent；
  - 熔断的打开、半开与禁用。

### WP-G4 Go（阶段 1）

- **交付**：
  - 站点 YAML 与构建器（§10.2），含 `default_lang`、`help_path`、`privacy_path`、按级别的刷新上限与限速器参数；`bundle verify` 的输出；
  - 构建器的全部报错与警告（§4.2、§10.2），`schema_version` 的判定（§3.2）；
  - `availability.go` 与一致性用例（§4.2）；R4 合入之后再加入依赖 R4 新字段的用例（§2.1）；
  - `internal/keys` 的 `mg-turnstile-keys` 读写（§8.7）；
  - `internal/turnstile` 客户端与 `mgctl turnstile` 命令（§16）；
  - `control-plane/README.md`，含 `mg-nearline` 的用法（内容按 §13）。
- **测试**：
  - 每条校验与警告；`schema_version` 的判定（含 `type: interactive` 的限速器）；
  - golden 配置包：Phase 1 形状逐字节不变，另加 `control-plane/testdata/sites/golden/golden-phase2.bundle`（含 §10.2 的全部新键、`type: interactive` 的限速器与 Turnstile Provider）；
  - Turnstile API 客户端对 `httptest` 的请求形状，确认 `invalidate_immediately` 总是显式发送；
  - 审计条目不含 secret。

### WP-N1 近线 worker（阶段 1）

- **交付**：`cmd/mg-nearline` 与 `internal/nearline`（§13）、`mg_verdict_put`、配置校验（含 `${CREDENTIALS_DIRECTORY}` 的展开规则）、`/metrics`（含验收比例）、systemd 单元（§13.6）。
- **测试**：
  - 对真实 Valkey（测试自启实例，或用 `MG_TEST_VALKEY_URL`；CI 的 `go` 作业带 Valkey 服务，§0.4）：消费组创建、周期性 `XAUTOCLAIM`、删除旧消费者、至少一次语义下的重复条目；
  - 每个检测器的阈值边界；`xs = 1`、`tk = 1` 的条目不计入；共享出口不产生 verdict；IPv6 前缀窗口；窗口满时丢弃新键；shadow 不写；
  - `mg_verdict_put`：所有者与无法解析的值不被覆盖，风险相等时不覆盖，同一检测器可以刷新；
  - 以 §13.6 的 ACL 用户执行脚本与全部操作，并确认它读写不了其他站点与其他键；
  - 验收比例的计算与"分母不足时不导出"；
  - `mg:ev` v2 与 v1 样例的解析；随机条目不 panic；
  - `mg_nl_lag_seconds` 与 `mg_nl_backlog` 的定义（追上时为 0）。

### WP-W2 Web SDK v1（阶段 1）

- **交付**：§12 的全部内容；`DEFAULT_MANIFEST_VERSION` 与两份模板（§2.1），阶段 1 中保持 1；`publish-sdk.yml`（§12.9）；sdk/web README 的接入约定、Service Worker 一节与兼容表（§12.1、§19 第 3b 步）。
- **测试**：§12.10。构建产物照常复制到 `edge/tests/fixtures/sdk/`。

### WP-E2a mg-edge 交互式（阶段 2 第 1 个）

- **交付**：
  - 配置包新字段的转换；`interactive_available`；`schema_version = 1` 的严格 Phase 1 行为中属于本 WP 的部分（只签发 v1 凭证、不设 `__Host-mg_st`、续期 404）；
  - 交互式签发与挑战页 v2、JSON 挑战、`ix` 的组装、页面语言（§7.1–§7.3）；
  - `/__mg/c` v2（§7.5）；`/__mg/c/renew`（§7.4）；`__Host-mg_a11y` 的写入与删除（§9.5）；
  - 失败升级与新的限速器（§7.9）；`/__mg/v` 与 `min`（D-58、§7.10）；
  - SDK 目录 v1 / v2 的加载、`/__mg/s/mg.js`（`ETag` 与 304）；
  - 切换 PR（§2.1）：冻结 `edge/tests/fixtures/sdk-v1/`，`DEFAULT_MANIFEST_VERSION = 2`，SDK 版本 0.3.0，`mg-edge` 版本 0.2.0，更新夹具；
  - cargo-fuzz 目标 `mg_proof`、`submission_v2`、`renew`、`ix_telemetry`（§2.4）；`deny.toml` 的注释（§22）。
- **测试**（`edge/tests`，回环）：
  - 用 mg-challenge 的测试辅助走通 `self_hold`、单次激活与 `pow_a11y` 的完整流程；
  - 重放、拼接、篡改 C；
  - 换密钥或 UA 提交（D-41 的两种情况）；已绑定的 `pow` C 以 v1 提交失败；同一 ASN 内换 /24 只记 `ic.bind_ipp_soft`；
  - 并发双提交只有一个进入签发；
  - `provider` 不在集合中；`mg.a11y.issue` 超限；
  - 续期链上限，过期后续期（一个旧 C 只换出一个新 C），`ic.nonce_reused` 不附新 C，已绑定 C 换前缀；
  - 本地模式下重启前签发的 C；
  - 交互式不可用时退回 Phase 1 行为，进行中的交互式 C 得到 `pow` 新 C；
  - 页面路由不要求交互式、API 路由 `min_level: interactive` 时，经 `/__mg/v?…&min=interactive` 得到的凭证让 API 请求通过；
  - manifest v1 目录照常工作；含 `mg.js` 的 manifest 被拒绝；
  - `schema_version = 1` 的配置包下行为与 Phase 1 相同。

### WP-E2b mg-edge 证明与观测（阶段 2 第 2 个）

- **交付**：
  - `MG-Proof` 与 `jti`（§9.1、§9.2）：可豁免导航、按需校验、`Early-Data`、就地恢复的 `pow` C；`min_level` 的执行；
  - `/__mg/r`、`/__mg/t`（§9.3、§9.4），含独立的遥测队列与可信报告的计数规则；
  - Cookie 规则（`http.cookie_names` 的排除）与转发前删除（§9.5）；`force_monitor`（§9.6）；I-35 复审（§9.7）；`shutdown_drain_ms` 的缺省值与交叉检查（§10.1）；
  - `schema_version = 1` 的严格 Phase 1 行为中属于本 WP 的部分（`identity.proof.*` 恒为 MISSING、`/__mg/r` 与 `/__mg/t` 404、不删除 Cookie）；
  - `mg:ev` v2 接线；事件与指标（§15），含 `kind=access` 的新字段与 `mg_navigations_total`；
  - Edge ACL 与 `valkey_acl.rs`（§14.5）；
  - `mg_protocol_rejected_total` 新增 `reason="bad_target"`：无法解析的请求目标不再计为 `bad_method`（§22）；
  - cargo-fuzz 目标 `refresh`、`telemetry`（§2.4）；
  - 告警：`deploy/vmalert/mg-phase2.rules.yml` 与 `scripts/mg-daily-check.sh`（§19 第 8 步），各附一个对样例 `/metrics` 的测试；
  - `edge.toml.example` 与 `shipped_configs.rs`。
- **测试**：
  - 证明的每种失败与 §6.7 的顺序；可豁免导航不受影响，声称是导航的 POST 与 `api` 路由上的请求要求证明；不读取证明字段的配置包不校验；
  - `proof: required` 在 monitor / enforce 下的行为；就地恢复的条件；
  - 重放、按密钥的配额与重放存储不可用；
  - 刷新的每个拒绝分支，`exp` 不超过会话上限，路由 R 的选择，monitor 下照常刷新；
  - 遥测的接受、丢弃与限速；报告数量上限；未签名的报告不进入告警指标；遥测队列满时决定事件不受影响；
  - 源站收到的 Cookie 不含 MorphGate 的三个 Cookie，其余字节不变；
  - 日志不含证明、JWK、签名与遥测内容（`logs_never_contain_client_secrets` 扩展）；
  - 指标族与标签。

### WP-E2c mg-edge Turnstile（阶段 2 第 3 个）

- **交付**：Provider 接线（`cdata_ok` 闭包，§8.4）；国家判定（§8.1）；CSP（§8.3）；token 重放；熔断与自动禁用的接线；`turnstile_keys` 凭证与文件校验；`[outbound]` 配置与 `MG_EDGE_TEST_OUTBOUND`；cargo-fuzz 目标 `siteverify_response`、`turnstile_keys`（§2.4）；告警规则与每日检查脚本中 Turnstile 的部分（§19 第 8 步）。
- **测试**（用 WP-C6 的 mock siteverify，绝不访问外网）：
  - CN、未知国家与 `denied_countries`（任一来源命中）从不提供 Turnstile；续期与提交时国家变为 CN 或未知则去掉 Turnstile、不调用 siteverify；
  - 主机不在 `hostnames` 中、或路由带 `redact_path` 时不提供；
  - §8.5 的每一行；shadow 下 `Pass` 签发 `interactive_ext:turnstile`、失败不计；
  - 缺少凭证时 `--check-config` 失败，运行中为 `disabled(no_secret)` 并记录 ERROR 日志；文件格式错误与 `site` 不符；
  - 秘密错误触发禁用并记录 ERROR 日志；
  - 没有 `MG_EDGE_TEST_OUTBOUND=1` 时拒绝回环 URL；
  - 只有提供了 Turnstile 的页面带 `strict-dynamic` 与 `frame-src`。

### WP-L2 Validation Lab（阶段 3）

- **交付**：
  - 新场景（只回放固定请求，不含求解逻辑，D-59）：
    - 交互式挑战页不引用第三方源；
    - CN / 未知国家的请求从不得到带 Turnstile 的 C（配合 Edge 的回环 mock 配置）；
    - 重放录制的交互式提交、篡改 C、`provider` 不在集合中，一律失败；
    - 外部 `CF-Worker` 照旧 403。
  - `lab-e2e` 加入 `mg-nearline`：用 Lab 的诱饵请求触发 `scanner`（shadow 下产生 `kind=verdict` 与日志），再切到 enforce，确认之后的请求带上来源为 `nearline/scanner` 的 verdict，结果是风险抬高（挑战），而不是阻断；
  - `mglab events` 的新断言。
- **约束**：CI 作业名不变（§2.3）。

### WP-D2 文档（阶段 3）

- 把 §0.3 中"需改设计文档"为"是"的条目，以及实现中产生的裁决，写回 docs/01–10 与 ADR；
- ADR-0011（本机应急开关）；
- 威胁模型 v1：为 Phase 2 组件补 STRIDE，并更新各行状态；
- 隐私说明模板：交互遥测、刷新时的遥测、行为摘要（可选）、Turnstile（可选）；
- 威胁模型 v1 写明：`self_hold` 的检查除服务端时间窗外都依赖客户端自报的数据（§7.7）；
- `CLAUDE.md`、`README.md`、07 的进度表。

## 18. 测试策略与 CI

Phase 1 规格 §16 的分层全部保留：单元测试、多语言共读的已知答案向量、共享格式样例、Go 与 Rust 的一致性、Go 签名的 golden 配置包、回环上的 Edge 集成测试。另加：

| 层 | Phase 2 |
|---|---|
| 已知答案向量 | `testdata/phase2/kat.json` 由 Rust（mg-challenge）与 TypeScript（SDK）共同读取；生成器只用 Node 内置模块 |
| Turnstile | 一律用 `edge-core` testkit 的回环 mock siteverify（D-52）。没有任何测试访问 `challenges.cloudflare.com`；SDK 的 Turnstile 加载用假对象测试 |
| Valkey | 新脚本与 ACL 对真实 Valkey 测试，规则同 Phase 1：`MG_TEST_VALKEY_URL`，或自启的 `valkey-server`，CI 中 `MG_REQUIRE_VALKEY=1`。Go 作业因 WP-N1 增加 Valkey 服务（§0.4） |
| 端到端 | `make lab-e2e` 加入 Phase 2 的否定性场景与 `mg-nearline`（WP-L2）；`make edge-smoke` 覆盖新端点的 404（`schema_version = 1`）/ 405 / 425 |
| 模糊测试 | 阶段 1 的 WP 只交付固定种子的随机输入测试；cargo-fuzz 新目标由 E2a–E2c 添加（§2.4 第 9 条）：`mg_proof`、`submission_v2`、`renew`、`ix_telemetry`、`refresh`、`telemetry`、`siteverify_response`、`turnstile_keys`；种子放在 `fuzz/seeds/` |
| 浏览器 | CI 中没有真实浏览器；SDK 用 vitest 与可注入的 DOM / 时钟测试。真实浏览器与辅助技术的验收由所有者完成（§19、§20） |

**不做**：
- 不做负载生成；
- 不访问回环与白名单之外的目标；
- Lab 场景中不含任何求解逻辑；
- 不调用任何第三方验证码服务；
- 不改必需检查的作业名（§2.3）。

## 19. 所有者运维手册（代码之外）

| 步骤 | 内容 |
|---|---|
| 0 | 完成 Phase 1 验收：monitor 期指标、附加延迟、`cf audit` 全绿、浏览器回归（Phase 1 规格 §17、§18） |
| 1a | **单机改用本机 Valkey**（D-38）。安装 Valkey（≥ 7.2）：只监听回环或 unix socket（`unixsocketperm 770`），`appendonly yes`、`appendfsync everysec`，`maxmemory-policy noeviction`，先设一个宽松的 `maxmemory`。按 §14.5 与 §13.6 的完整规则建 ACL 用户，密码以 systemd credential 交付。`edge.toml` `[valkey] mode = "valkey"`，`local_replay_authoritative = true` 保留；配置包的 `events.stream` 仍为 `false`。在流量低时 reload：进行中的挑战可能失败一次，访客重试即可。确认 `mg_state_mode{mode="valkey"} = 1`，观察 `used_memory` 24 小时 |
| 1b | 设 `maxmemory = 24 小时峰值 × 2 + stream_maxlen × 400 B`（缺省 `MAXLEN ~ 300000` 约 120 MB），然后在站点 YAML 设 `events.stream: true`。`noeviction` 下内存不足会让 `XADD` 与限速写入失败，所以这一步不能省略 |
| 2 | **隐私说明**（在任何新的客户端信号上线之前）：会话公钥与证明；交互遥测；刷新时的遥测（若开启 `telemetry_behavior`）；行为摘要（若开启）；Turnstile（若开启）。说明不能使用 `proof: required` 接口的情形（浏览器禁用存储时，§12.4） |
| 3a | **换二进制**：部署新的 `mg-edge` 与 `mgctl`，保留 SDK 0.2.x 目录与 `schema_version = 1` 的配置包。确认决策分布与挑战比例同升级前一致（只比较 Phase 1 已有的指标族）。预期的差异：`/__mg/s/mg.js` 别名可用；JSON 应答带 `"v": 2`；`mg:ev` 条目为 v2；新的指标族。`schema_version = 1` 下源站仍收到 MorphGate 的 Cookie（D-61 不生效） |
| 3b | **站点模板与接入**：<br>- 模板改用 `<script data-cfasync="false" src="/__mg/s/mg.js" defer></script>`，放在站点自身脚本之前（别名对 v1 目录同样可用）；站点代码按 §12.1 的接入约定调用 `MorphGate`。<br>- 站点 CSP 允许同源脚本与 `worker-src 'self'`（或经 `script-src` 回退），否则就地求解在主线程运行。<br>- **Service Worker**：站点的 Service Worker 不得处理 `/__mg/` 下的任何请求。fetch 处理器对 `new URL(event.request.url).pathname.startsWith('/__mg/')` 直接返回（不调用 `respondWith`）；用 Workbox 时设 `navigateFallbackDenylist: [/^\/__mg\//]`，且不为 `/__mg/` 注册任何缓存路由。核对：Service Worker 生效时打开 `/__mg/v?ret=/`，页面含 `#mg-challenge`；开发者工具中 `/__mg/s/mg.js` 不是 "from ServiceWorker"。`mg_sw_intercept_reports_total` 增加说明仍有截获。<br>- 需要证明或就地解挑战的接口改用 `MorphGate.fetch`（XHR / axios 用 `proofHeader()`）；`proof: required` 的路由不返回跳转 |
| 3c | **换 SDK 0.3 目录**，并把配置包改为 `schema_version = 2`：在站点 YAML 中显式写出 `clearance.refresh: false`，构建器即写 `schema_version = 2`，功能仍全关（交互式关闭、没有 `proof`）。保留上一个 SDK 目录在主机上，供应急使用（第 10 步）。确认源站不再收到 MorphGate 的 Cookie（D-61） |
| 4 | **证明**：给选定的接口路由设 `proof: required`，先配 `mode: monitor`（I-36），观察 `mg_proof_verify_total` 与 dry_run 事件数日，再改为 enforce |
| 5 | **交互式**：`challenge.interactive.enabled: true`，评分保持 shadow。<br>- 测试路由：`name: mg-test`、`paths: [/__test-interactive]`、`mode: enforce`、`min_level: interactive`；重复测试时在开发者工具中删除 `__Host-mg_clr`，或用隐私窗口。<br>- 浏览器：四条路径分别在微信内置浏览器（Android、iOS）、QQ 浏览器、UC、华为 / 小米自带浏览器、Safari、Chrome 上走完；另在 200% 缩放、320 CSS px 宽度与 reduced motion 下各走一遍。<br>- 辅助技术：VoiceOver（iOS / macOS）、TalkBack 或厂商的屏幕朗读、点明安卓、NVDA、争渡读屏；只用键盘；iOS 切换控制或语音控制。<br>- 每条路径记录：目的说明被读出、开始与结果被播报、失败后焦点位置、完成时间（`ix.act_ms`）。<br>- 改为 `enforce` 之前，上述辅助技术与仅键盘的路径各完成 ≥ 5 次，记录 `kind=feedback` 的 `ix.score`；`t_pass` 必须高于这些样本的最大值（§7.8） |
| 6 | **近线**：安装 `mg-nearline`（配置、`LoadCredentialEncrypted`、`SupplementaryGroups=valkey` 或回环 TCP、systemd 单元），检测器全部 shadow。观察 `kind=verdict` 与 `mg_nl_*` 至少 7 天，按 ASN 检查 shadow verdict 的误伤：电信 AS4134 / AS4812、联通 AS4837、移动 AS9808 / AS56040，以及常见的代理出口与监控探针。没有误伤再逐个改为 enforce。压住一条误伤的近线 verdict：<br>`valkey-cli --user owner … SET 'mg:v:<site>:<type>:<key>' '{"risk":0,"labels":[],"source":"owner","version":"owner","reasons":["owner.suppress"],"expires_at_ms":<ms>}' PX <ttl_ms>`<br>（`<key>` 取 `kind=verdict` 事件中的伪名键；近线不会覆盖它，到期后自然恢复） |
| 7 | **Turnstile（可选，只用于非大陆访客）**：<br>1. 在 Cloudflare 控制台创建 widget：Managed 模式，主机名只列生产 FQDN，`region: world`。<br>2. 运行 `mgctl turnstile secret import`，部署 credential（缺少它时 `--check-config` 失败，§8.2）。<br>3. Provider 配置为 `mode: shadow`、`selection: escalate_after_fail`。<br>4. 在 staging 上用 Cloudflare 的测试 sitekey 在浏览器里手工核对一次（D-52）。<br>5. 用 `Content-Security-Policy-Report-Only` 核对 `script-src`、`frame-src` 与 `style-src`，确认没有违规。<br>6. 隐私说明已含 Turnstile（第 2 步）后再启用 |
| 8 | **告警**，两种形式任选其一（都由 WP-E2b 交付，WP-E2c 补上 Turnstile 的部分）：<br>- 有 VictoriaMetrics 时，用 vmagent 抓取 `/metrics`、用 vmalert 加载 `deploy/vmalert/mg-phase2.rules.yml`（含下列每条表达式；日志类条件用 vmalert 对 VictoriaLogs 的查询）；<br>- 没有时，每日运行 `scripts/mg-daily-check.sh`：它在状态文件中保存上一次的 `/metrics` 快照与 `MainPID`（进程变了就只报告不比较，计数器在 reload 后归零），打印增量与比例，并按 01 §8 的方法核对 `cf audit` 第 18 项。<br>条件：<br>- `mg_provider_verify_total` 中 `unavailable` / `misconfigured` 的比例 > 5%（1 小时）；<br>- `mg_double_challenge_total` 1 小时增加 > 10；<br>- `mg_nl_backlog > 10000` 持续 10 分钟，或 `mg_nl_lag_seconds > 600`；<br>- `mg_site_forced_monitor == 1` 持续超过 1 小时；<br>- `mg_endpoint_cache_hit_reports_total`、`mg_sw_intercept_reports_total`、`mg_token_ruc_total`、`mg_state_local_overflow_total` 任一增加；<br>- `mg_challenge_renew_total{result="unavailable"}` 增加；<br>- 启用了交互式的站点 `mg_interactive_available == 0`；<br>- `proof: required` 路由上 `mg_proof_verify_total` 中非 `valid` 的比例 > 5%（访客在循环）；<br>- `kind=feedback` 中 `ic.too_fast`、`ic.hold_short`、`ic.no_trusted_input` 占交互式提交的比例 > 5%（SDK 或界面回归）；<br>- Valkey `used_memory / maxmemory > 0.8`（脚本用 `valkey-cli INFO memory`）；<br>- 人为摩擦超过 §20 的阈值 |
| 9 | **回滚**，按顺序：<br>① 配置包关掉 Phase 2 功能（交互式、`proof`、Provider、`clearance.refresh: false`），发布 `schema_version = 1` 的配置包：此后只签发 v1 凭证；<br>② 换回 SDK 0.2.x 目录；<br>③ 等待实际配置的 `max(ttl_*)`（≤ 7200 s），让 v2 凭证全部过期；<br>④ 站点模板去掉 SDK 标签，或改回 0.2.x 的哈希文件名：回滚后的 Phase 1 二进制没有 `/__mg/s/mg.js` 别名；<br>⑤ 删除 `edge.toml` 的 Phase 2 键；<br>⑥ 换回 Edge 二进制 |
| 10 | **应急**：<br>- 整站只记录：`sudoedit /etc/morphgate/edge.toml`，在该站点的 `[[sites]]` 下设 `force_monitor = true`；`sudo systemctl reload mg-edge`（`ExecReload` 先运行 `--check-config`）；确认 `mg_site_forced_monitor{site="<site>"} = 1`。然后签发并部署一个 monitor 配置包，最后撤销 `force_monitor` 并再次 reload（D-60）。<br>- SDK 故障：把 `[sdk] dir` 改回保留的上一个目录并 reload。别名在 Cloudflare 与浏览器各最多缓存 300 s，Service Worker 若违反第 3b 步的规则还会更久 |
| 11 | **仓库与发布**：<br>- 开启 GitHub secret scanning 与 push protection（10 CP-06）。仓库中有意提交的测试密钥，按"用于测试"关闭告警。<br>- 在 npmjs.com 上为 `@ermiaodada/morphgate-web-sdk` 一次性登记 trusted publisher：本仓库与 `.github/workflows/publish-sdk.yml`（§12.9） |

## 20. 验收映射

| 验收项（07 Phase 2、09 §15） | 证据 | 谁 |
|---|---|---|
| 重放、拼接、篡改的 C 100% 拒绝 | `edge/tests` 的完整性用例；Lab 的否定性场景 | WP-E2a、WP-L2 |
| 跨客户端提交 100% 拒绝（只对已绑定的 C 声明） | 已绑定的 C 换密钥提交、或以 v1 提交 → `ic.bind_jkt`。未绑定的 C 在 UA 家族不同、或 /24 与 ASN 都不同时 → `ic.bind_uah` / `ic.bind_ipp`；同一 ASN 内换 /24 只记 `ic.bind_ipp_soft` 并接受，这是 D-41 的已知边界 | WP-E2a |
| 并发双提交恰好一个进入签发 | 对真实 Valkey 的并发测试 | WP-C5、WP-E2a |
| Turnstile 绑定失败 100% 拒绝 | mock siteverify：子域主机名、`action` 不符、他人 nonce 的 `cdata`、`challenge_ts` 越界、重复 token | WP-E2c |
| Turnstile 故障时正确回退且不放行 | api.js 加载失败（SDK 测试）；siteverify 超时、5xx、secret 错误（Edge 测试） | WP-W2、WP-E2c |
| CN 与未知国家从不得到 Turnstile | 选择函数真值表；续期与提交时的重新判断；Edge 测试；Lab 场景 | WP-R4、WP-E2c、WP-L2 |
| 人类被要求交互式挑战的比例 < 0.1% | 所有者 shadow 数据，两个数都看：<br>- **访客级**（主）：`mg_nl_interactive_visitor_share`（7 天，分母 ≥ 2,000 时才有值，§13.3），同时报告 `mg_nl_interactive_abandon_share`：收到挑战却没有通过的访客才是真正的摩擦；<br>- **请求级**（辅）：7 天内 `mg_challenge_total{type="interactive", result="issued"}` 的增量除以 `mg_navigations_total` 的增量。交互式 JSON 挑战之后的 `/__mg/v` 会再计一次，所以它是上界。<br>两者都只算告警的 7 天窗口，不按天判定：本站每天的流量下 0.1% 只有几个访客 | 所有者、WP-N1 |
| 按住中位 < 4 s；`pow_a11y` 中位 < 10 s | 真实设备上 `kind=feedback` 的 `ix.act_ms`（从第一次激活到提交）按 Provider 取中位数，含低端机。`elapsed_ms` 含阅读页面的时间，只用于硬检查 | 所有者 |
| 只用键盘、用读屏软件都能完成 | 所有者按 §19 第 5 步的矩阵手工验证；SDK 的结构、播报与焦点测试 | 所有者、WP-W2 |
| 页面打开 30 分钟后仍能完成，不显示倒计时 | 假时钟下的续期链测试；所有者手工验证 | WP-E2a、所有者 |
| `self_hold` 页面零第三方请求 | 模板与 CSP 测试；Lab 场景；所有者在浏览器网络面板中核对。由 Cloudflare 注入、被 CSP 拦截的请求（Rocket Loader、Web Analytics 的自动注入）不算第三方请求；挑战页应关闭 Web Analytics 的自动注入 | WP-W2、WP-L2、所有者 |
| 挑战页与 `/__mg/*` 为 `no-store, private` | Edge 测试（`/__mg/s/` 除外，§11.1） | WP-E2a |
| 遥测 ≤ 2 KB，没有原始坐标与按键值 | SDK 与 Edge 解析器测试；共享样例 | WP-W2、WP-C5 |
| 近线：事件到 verdict 的 p95 < 10 s | `lab-e2e` 中测量；生产中看 `mg_nl_lag_seconds` 与 `mg_nl_backlog` | WP-N1、WP-L2、所有者 |
| 附加延迟 p99 < 5 ms 仍成立（含证明校验） | 生产或 staging 的 `mg_edge_added_latency_seconds{kind="site"}` | 所有者 |
| Turnstile 的通过、失败、重复 token 三条路径在 CI 中覆盖 | mock siteverify 的用例（替代 Cloudflare 测试密钥，D-52） | WP-C6、WP-E2c |
| 升级二进制不改变线上行为 | `schema_version = 1` 的 Edge 测试（D-66）；所有者按 §19 第 3a 步比较升级前后 | WP-E2a、WP-E2b、所有者 |

## 21. 待实测与未决

| 项 | 影响 | 何时 |
|---|---|---|
| Turnstile：siteverify 返回的 `hostname` 与 `cdata` 是否保留大小写；`remoteip` 不一致时的行为；`idempotency_key` 被记住多久，旧 secret 重试换用另一个幂等键之后是否仍可能得到缓存的结果；Free 套餐的 siteverify 限速；`hagen.` / `brunhild.challenges.cloudflare.com` 是否需要 CSP 条目；widget `region` 字段的语义；从 Edge 主机到 siteverify 的延迟 | §8 的通过条件、超时与 CSP | 启用 Turnstile 前（§19 第 7 步） |
| `cf-mitigated` 响应的状态码；所有者站点上双重挑战的频率 | SDK 的识别；是否需要 HMAC 放行 Cookie（08 §2.9） | shadow 期 |
| Safari 的存储清理与隐私窗口造成的密钥丢失率（`ix.ks` 的分布），以及按 `ks` 分组的重新挑战率 | `proof: required` 接口的重新挑战次数；就地恢复是否足够 | shadow 期 |
| iOS 锁定模式等禁用 JIT 的环境：PoW 慢 45–65 倍，`a11y_bits = 17` 时 `pow_a11y` 平均约 17 s | 可访问性；是否需要为这类设备降低难度，或提供 WASM 内核（挑战页 CSP 需要 `'wasm-unsafe-eval'`，JavaScriptCore 上约快 1.7 倍） | shadow 期：按 `pow.impl` 与 `worker` 记录 `pow.ms` 的分布，结论记入本节 |
| 真实低端设备上的哈希速率 | `pow_bits` / `a11y_bits` 的缺省值 | shadow 期 |
| `T_pass` / `T_block` 与 §7.8 的特征权重 | `enforce` 能否开启 | shadow ≥ 7 天、且完成 §19 第 5 步的辅助技术样本之后 |
| 微信等内置浏览器中 `visibilitychange` 与定时器在后台是否可靠 | 凭证刷新的时机（§12.5） | shadow 期 |
| 所有者站点的 `cf audit` 第 18 项：RTT 信号 24 h 缺失率 69.7%（在 I-42 修正口径之前测得） | EDGE_TLS / RTT 信号的可用性 | 升级到含 I-42 的版本后重新测量；若仍偏高，检查 Transform Rule 字段在 HTTP/3 与连接复用下的可用性 |
| 单机上 `mg:ev` v2 条目的实际大小与 Valkey 的内存占用 | `maxmemory` 的公式（§19 第 1b 步按每条 400 B 估算） | 第 1a、1b 步 |
| 行为摘要的价值与隐私成本 | 是否开启 `telemetry_behavior` | shadow 之后 |
| `scanner` 与 `high_rate` 检测器在 enforce 下是否误伤监控探针、共享出口与代理出口 | 诱饵名单、阈值与共享出口的判定 | 第 6 步 |

## 22. Phase 1 遗留项的处置

| 遗留项 | 处置 |
|---|---|
| I-35 (a)、(b) | Phase 2：D-62、§9.7 |
| `/__mg/r` 保留给静默刷新（I-39） | Phase 2：§9.3 |
| D-07 的 `identity.proof` | Phase 2：§4 |
| D-08 交互式按 `pow` 执行 | Phase 2：§5.1；交互式未启用时保留 |
| D-10 verdict 只由所有者写入 | Phase 2：近线 worker（§13） |
| D-11 JSON 提交"供 Phase 2 SDK" | Phase 2：交互式提交（§7.5、§12.6） |
| D-27 / D-28 失败升级与配额 | Phase 2：§5.3、§7.9。按会话的配额不加：挑战前没有会话 |
| epoch 窗口；`k_bind_epoch` | Phase 2：§6.1、§6.9 |
| 遥测 schema 有两份实现 | Phase 2：D-62、§15.2 |
| `token.replay_unchecked` 只在采样事件中出现 | Phase 2：D-62 |
| 无法解析的请求目标计为 `bad_method` | Phase 2（WP-E2b）：新增 `reason="bad_target"` |
| `Net` 的 `Debug` 打印前缀 | Phase 2（WP-R4） |
| `verify_bundle` 不校验 `providers` | Phase 2（WP-C5） |
| Go 与 Rust 之间没有固定的策略字段夹具 | Phase 2：`testdata/policy-ir/fields.json`（字段路径、类型、大小上限），由 §0.4 落地、只读；Go（WP-G4）与 `core/src/policy/fields.rs` 的测试（WP-R4）都读取 |
| `validateTemplate` 基于正则 | Phase 2（WP-W2）：v2 规则覆盖新增结构；字符引用解码记为已知限制，CSP 兜底 |
| SDK 构建的签名与可复现 | Phase 2：D-63 |
| 人类摩擦率指标与告警；本机应急开关 | Phase 2：§19、§20；D-60 |
| Turnstile API token 的写权限名（10 CF-06） | Phase 2：§16 |
| 仓库 secret scanning（10 CP-06） | Phase 2：§19 第 11 步 |
| 威胁模型 v1 与 STRIDE | Phase 2（WP-D2） |
| 文档陈旧处：07 进度、06 "cargo-fuzz 尚未接入"、`mgctl cf apply` 的阶段、`attestation` 保持拒绝 | Phase 2（WP-D2）；`deny.toml` 头部注释（WP-E2a） |
| `step_up`、`attestation`、`tarpit` | 保持拒绝（I-19、D-55） |
| 吊销集与 pub/sub | Phase 3（D-54） |
| `mg:w:*` 与 `client_conn_key` | 以后 |
| `bind.ctp` 转软绑定；EDGE_TLS 权重 | 保持 shadow，按数据再定 |
| Pingora 自己的 400 带 `Server: Pingora` | 以后（随 Pingora 升级） |
| Lab 没有持久的运行记录（10 LAB-06） | 以后 |
| 每日访问记录归档（≥ 6 个月） | 以后；所有者决定，源站日志可能已覆盖 |
| 受攻击模式、`mgctl cf apply`、HMAC 放行 Cookie、AOP 证书到期指标 | 以后 |
| rDNS 过期作业的结果缓存；`#` 的有损 UTF-8 重建；`mg_cf_ip_filter_active` 的刷新延迟 | 不处理（Phase 1 进度记录 §4 的理由） |

## 23. 评审处置

规格合入前经过三份独立评审，每条意见都在下表中处置：
- R1：安全与密码学，27 条（blocker 1、major 10、minor 16）；
- R2：可实现性与一致性，56 条（blocker 3、major 28、minor 25）；
- R3：无障碍、浏览器现实与运维，42 条（blocker 2、major 18、minor 22）。

"核实 / 理由"一栏："已核对"表示集成者亲自在源码或文档中确认过；"评审引用"表示依据评审给出的源码位置；"部分采纳"与"不采纳"写明理由，互相冲突的意见写明取舍。之后实现中的契约变更，以 I-43 起的裁决记录在开头的表中。

### 23.1 R1（安全与密码学）

| # | 级别 | 意见 | 处置 | 核实 / 理由 | 落点 |
|---|---|---|---|---|---|
| S-1 | blocker | "导航"由客户端请求头判定，持有导出凭证的客户端加上 `Accept: text/html` 就能绕过 `proof: required` | 采纳 | 评审引用 `edge/src/enforce.rs:46-52` 的导航判定 | D-40；§4.1、§4.2（`allow` 以 `http.navigation` 为条件时报错）；§9.1 可豁免导航；§10.2；E2b 测试 |
| S-2 | major | 配置包仍为 schema 1 时，换二进制也会改变线上行为（`identity.proof`、v2 凭证、Cookie 删除等） | 采纳 | 评审引用 `control-plane/internal/policy/availability.go` 与 `core/src/detectors.rs:455` | D-66；§3.2；§6.8；§9.5；§11.1；§19 第 3a、9 步 |
| S-3 | major | 椭圆曲线验签排在便宜的检查之前，且任何路由上的任意证明都校验，形成 CPU 放大 | 采纳；点校验并入验签（aws-lc-rs 验签时检查点） | — | §6.7；§9.1；WP-R4 `reads_field` |
| S-4 | major | 每个有效证明都写 `jti`，单个客户端就能让本地集合溢出或写满 Valkey；交互式 C 让 `local_nonce_capacity` 小约 3.7 倍 | 采纳；计数只用 `GET` / `SET … KEEPTTL`，Edge 的 ACL 不需要新命令 | 已核对 Phase 1 规格 §9.7 的容量公式按 120 s 估算 | §9.2；§14.1、§14.2 `mg_jti` v1；§14.4；§14.5；§10.1 |
| S-5 | minor | 本地结论依赖客户端选的 `iat`；Valkey 模式下不查本地集合；`iat` 窗口 61 s 而记录只存 60 s；`Early-Data` 未定义 | 采纳 | — | §6.7 第 6 步；§9.1；§9.2；§6.11 |
| S-6 | minor | 总长 1024 与 `htu` 2048 矛盾；`htu` 解析未定义；`PATCH` 的大小写；同源跳转；303 表单流程拿不到 `now_ms` | 部分采纳：跳转不用 `redirect: "manual"`（浏览器只给出不透明的跳转响应，读不到目标），改为跟随后对 `response.url` 重试一次（GET / HEAD），并要求证明路由不返回跳转 | — | §6.7；§11.2；§12.5 |
| S-7 | major | 已绑定的非交互式 C 可以用不带签名的 v1 提交；未绑定 C 的 /24 描述与软绑定不符 | 采纳 | 评审引用 `edge/src/mg_endpoints.rs:692-704` | §7.5 `v` 行；D-41；§20；E2a 测试 |
| S-8 | major | `self_hold` 的检查几乎都靠客户端自报；刷新放大每次解题的价值；交互级证据强度未定 | 采纳；`pow_only` 的下限用独立的 `a11y_min_ms`（缺省 2000），不复用 `min_pow_ms` | 评审引用 `core/src/detectors.rs:454`（所有级别 −0.4） | D-47；D-68；§3.2；§5.7；§6.8；§7.7；§10.2 |
| S-9 | major | 新的内置限速器只按 `ipp` 计数，一个客户端就能让整个前缀被拒 | 采纳；`mg.a11y.issue` 的取值按 U-33 | — | D-67；§7.1；§7.9；§10.2 |
| S-10 | major | 近线的 `scanner` verdict 会被矩阵直接阻断；第三方页面能让访客的浏览器触发它 | 采纳 | 评审引用 `core/src/classify.rs:68`、`core/src/policy/matrix.rs:87` | D-53；§13.1 `xs`、`tk`；§13.3；§13.4；§19 第 6 步 |
| S-11 | major | `shared_token` 的条件永远不成立；会话 verdict 会被合法持有者带回 | 部分采纳：检测器改按 `pf = j`（证明与凭证的密钥不符）判定；不加 `bs` 字段，绑定不符的凭证本来就无效，会被重新挑战 | 评审引用 `edge/src/identity.rs:185-189` | §13.1 `pf`；§13.3；§6.8；§7.5 第 2 步；D-54 |
| S-12 | minor | 近线用户缺 `+get +set`，脚本写不了；风险相等的 verdict 互相覆盖 | 采纳；verdict 键用完整的 `~mg:v:<site>:*`：`EVALSHA` 的声明键要求同一个模式兼有读写，评审建议的 `%R~` 加 `%W~` 组合不满足这一点，由 WP-N1 的真实 Valkey 测试确认 | — | §13.6；§14.2 |
| S-13 | major | `/__mg/t` 接受未签名报告，可以刷告警指标、挤占事件队列；路径不脱敏；签名报告可重放 | 采纳 | 评审引用 `edge/src/events.rs:460` 与 `queue_sampled` 的容量 | D-48；§9.4；§10.1；§15.5；§19 第 8 步 |
| S-14 | minor | 往返 1 时还不知道 `p`，无法按 `p = pow_a11y` 检查 | 采纳；与 C-4 冲突，取本条：往返 1 总是检查，第 3 步之后使用结果，超限时不消费 nonce | 评审引用 `edge/src/mg_endpoints.rs:591-617` | §7.5 第 2、5 步；§14.3 |
| S-15 | minor | 续期的过期与到顶分支不检查绑定与签名、不消费 nonce，一个旧 C 可以无限分叉 | 采纳；与 C-5 冲突，取本条，继承的字段按 C-5 | — | §7.4；§6.10 `open_for_renew` |
| S-16 | minor | 刷新没有说明 `bind` 与 `kid`；按会话的限速在凭证验证之前 | 采纳；与 C-47 冲突，取本条：`bind` 原样复制 | — | §5.7；§6.8；§9.3 |
| S-17 | minor | shadow 的 `Pass` 未定义；`fail_closed` 只在校验之后生效；siteverify 没有并发上限；旧 secret 重试用同一个幂等键 | 部分采纳：Phase 2 只接受 `fallback: self_hold`，因为内置 Provider 总在集合中，`fail_closed` 不增加保护；缺少凭证时 `--check-config` 失败。其余采纳 | — | D-51；§6.9；§8.2；§8.4；§8.5 |
| S-18 | minor | 续期与提交时不重新判断国家，可能把大陆访客的 IP 发给 Cloudflare；`redact_path` 页面会加载 api.js | 采纳 | — | §5.4；§7.4 第 9 步；§7.5 第 5 步 |
| S-19 | minor | siteverify URL 可以指向任意回环端口，配置错误会静默放宽校验 | 采纳 | — | §8.4；§10.1；§15.5 |
| S-20 | minor | 脚本可读的 Cookie 暴露访客用过无障碍路径；两者都进入 `http.cookie_names` 与事件 | 采纳；状态 Cookie 另加 `iat`（C-51、U-14） | 评审引用 `edge/src/context.rs:70-81` | D-46；§6.8；§9.5 |
| S-21 | minor | `ph` 对带令牌的路径计算；刷新时的遥测是新的收集；会话公钥成为长期标识 | 采纳 | — | §13.1；§9.3；§12.4；§19 第 2 步 |
| S-22 | minor | SDK 只凭 JSON 体判断 403，源站可诱导它求解或跳转；没有存储时可能循环重载 | 采纳 | — | §11.2；§12.5 |
| S-23 | minor | 密钥丢失后经 `/__mg/v` 重新挑战，会把交互级凭证降成 `pow` | 采纳，并按 U-1 增加 `min` 参数 | — | D-58；§7.10 |
| S-24 | minor | 别名被缓存时页面与 Worker 可能来自不同构建；站点 CSP 需要 `worker-src` | 采纳 | — | D-39；§12.6；§19 第 3b 步 |
| S-25 | minor | `schema_version = 1` 时 Phase 2 字段非零没有校验 | 采纳 | — | §3.2；WP-C5、WP-G4 的反例 |
| S-26 | minor | IPv6 客户端可以在 /64 之间轮换来逃避检测，还能冲掉其他键的窗口 | 采纳：另按 `pfk` 建窗口（新增 `fam` 字段）；窗口满时丢弃新键，从不淘汰已有的键 | — | §13.1；§13.3 |
| S-27 | minor | 只在内存中的密钥让每个页面一把密钥，`proof` 路由循环挑战 | 采纳；另按 U-11 把第一层回退改为 localStorage | — | D-45；§12.4；§12.5 |

### 23.2 R2（可实现性与一致性）

| # | 级别 | 意见 | 处置 | 核实 / 理由 | 落点 |
|---|---|---|---|---|---|
| C-1 | blocker | 阶段 1 的 WP 必须改动 `edge/` 使用的公共结构，却不能改 `edge/`；§0.4 的落地同样会破坏编译 | 采纳 | 已核对 `MintParams` 的字面量在 `edge/src/identity.rs:567`、`edge/src/mg_endpoints.rs:794`、`edge/tests/decision.rs:518`；`ClearanceClaims` 只在 `challenge/src/clearance.rs` 内构造，加字段不影响 `edge/` | §2.3；§0.4 编译修复；§6.10；§17 WP-R5、WP-C5 |
| C-2 | blocker | `shutdown_drain_ms` 缺省 2000 与回环配置 0–1 s 的宽限时间冲突，Edge 会拒绝启动；所有权分裂 | 采纳 | 评审引用 `scripts/lab-e2e.sh:331`、`edge/config/edge.dev.toml:26` | §9.7；§10.1；§17 WP-C5、WP-E2b |
| C-3 | blocker | 近线 ACL 没有 `+get +set`，脚本内的命令会被拒绝 | 采纳（与 S-12 合并） | — | §13.6 |
| C-4 | major | 往返 1 时不知道 `p` | 不采纳"删除往返 1 的检查"，取 S-14 | 往返 2 才发现超限时，nonce 已经消费，用户白算了 PoW | §7.5 |
| C-5 | major | 过期的 C 打不开，拿不到 claims；续期请求没有 `ret` | 部分采纳：继承字段采纳；过期的 C 改为允许过期地打开（S-15），过期超过 1 小时才不附新 C | 评审引用 `challenge/src/sealed.rs:227-231`；已核对 `Sealer::open` 先检查 epoch 再解密，所以另设 `open_for_renew` | §6.10；§7.4 |
| C-6 | major | mg-core 不能依赖 edge-core，`IxTelemetry` 会有两份 | 采纳 | — | §0.4 `core/src/telemetry.rs`；§3.4；§15.2 |
| C-7 | major | 策略一致性把 R4 与 G4 耦合在阶段 1；共享字段夹具没有路径 | 采纳 | — | §2.1；§0.4；§22 |
| C-8 | major | Phase 2 golden 配置包的跨语言检查没有归属 | 采纳 | 评审引用 `edge-core/tests/bundle_golden.rs:31-64` | §2.1；§17 WP-G4、WP-C5、WP-E2a |
| C-9 | major | C6 需要 R5 的 `cdata` 重算，edge-core 又不依赖 mg-challenge；`BindingMac` 的约定与 §6.9 不同 | 采纳 | 评审引用 `core/src/challenge.rs:161-169` | §8.4 接口；§17 WP-C6、WP-E2c |
| C-10 | major | 模板切换只豁免了常量与夹具，没覆盖只针对 v1 模板的测试；切换后 Edge 测试仍需 v1 目录 | 采纳 | 评审引用 `sdk/web/test/build-dist.test.ts`、`edge/src/sdk.rs:936-942` | §2.1 |
| C-11 | major | 阶段 1 的 SDK 发 v2 提交，而合入 E2a 之前的 Edge 只接受 v1 | 采纳 | 评审引用 `edge/src/submission.rs:320` | §2.1；§12.1 |
| C-12 | major | "Edge 不回填缺省值"与 Phase 1 相反；schema 2 的消息能否缺省未定义；schema 1 时 Phase 2 字段的零值关掉了诱饵标记 | 采纳 | 评审引用 `edge/src/sites/convert.rs:582-660` | §3.2 |
| C-13 | major | 交互式不可用时 `min_level: interactive` 的路由永远不满足 | 采纳 | 评审引用 `core/src/policy/matrix.rs:22-39` | §5.2 `effective_challenge` |
| C-14 | major | "未绑定的 C 在 /24 不同时拒绝"与软绑定不符 | 采纳（与 S-7 合并） | — | D-41；§20 |
| C-15 | major | 声称是导航即可跳过 `proof: required` | 采纳（与 S-1 合并） | — | D-40；§9.1 |
| C-16 | major | `MG-Proof` 总长 1024 与 `htu` 2048 矛盾 | 采纳 | 评审实测：`htu` 480 字节时证明为 1049 字节 | §6.7；§12.5 |
| C-17 | major | `mg.c.renew` 等新限速器没有参数，`mg.r` / `mg.t` 的维度未定 | 采纳；按 D-67 分两级，交互式的三个可配置，`mg.r` 与 `mg.t` 为常量 | — | §7.9；§3.2；§10.2 |
| C-18 | major | SDK 的恢复路径未定义或无法实现（429 不带 C、续期永远 429、403 不附新 C 等） | 采纳；续期的 `ic.nonce_reused` 按 U-9 不计失败 | — | D-38；§7.4；§7.10；§12.6 |
| C-19 | major | `ic.too_fast` 在第 6 步，而 `assess_interaction` 只返回第一个失败；`pow_too_fast` 缺难度参数 | 采纳 | — | §5.5 `min_elapsed_ms`、`DESKTOP_HASHES_PER_MS`；§7.5 第 6、11 步 |
| C-20 | major | "升级二进制本身不改变线上行为"与多处无条件生效的改动矛盾 | 采纳；D-66 之后，无条件生效的只剩不改变决策的几项 | — | 开头的约束；§19 第 3a 步 |
| C-21 | major | 人为摩擦的验收在 `vl-main` 上算不出来 | 采纳；另按 U-17 以近线的访客级比例为主 | 评审引用 `edge/src/events.rs:343-401` | §15.3 `kind=access`；§13.3；§20 |
| C-22 | major | 没收到过 `now_ms` 的页面无法校正时钟，证明接口永远失败 | 采纳；另按 U-12 用 `Date` 头并持久化偏差 | — | §9.1；§11.2；§12.5 |
| C-23 | major | 提交失败附的交互式 C 从不绑定，跨客户端保证在重试时失效 | 采纳 | — | §7.5 响应；§12.6 绑定续期 |
| C-24 | major | 交互式变为不可用时，进行中的交互式 C 行为未定义，schema 1 的零值会导致 503 | 采纳 | 评审引用 `challenge/src/clearance.rs:295-298` | §5.1；§5.3；§7.4 第 4a 步；§7.5 第 4a 步 |
| C-25 | major | "环境的 default 路由"可能不存在；刷新在 monitor、`jti` 不可用、事件与指标方面未定义 | 采纳 | 评审引用 `control-plane/internal/sitecfg/env.go:95-109` | §9.3 |
| C-26 | major | v2 的 Worker 协议去掉了 ack，2 s 回退会在低端机上并行重复计算 | 采纳 | 评审引用 `sdk/web/src/pow.ts:21-26` | §12.6 PoW 行 |
| C-27 | major | `http.navigation` 需要 proto 与原生类型的字段；`RouteInfo` 所在文件不在落地清单中 | 采纳 | 已核对 `decision.proto` 的 `Http` 用到 15 号字段 | §3.3；§3.4；§0.4 |
| C-28 | major | 交互式限速器会被 C5 与 Edge 拒绝；它只是取值，不会触发 schema 2 | 采纳 | 评审引用 `edge-core/src/bundle/validate.rs:424-432` | §3.2；§10.2；§17 WP-C5 |
| C-29 | major | 阶段 1 的 WP 无法添加 cargo-fuzz 目标（文件归 E2） | 采纳 | — | §2.4 第 9 条；§17；§18 |
| C-30 | major | mg-core 无法计算 `hold_ms` 与 `offset`；`ix` 的组装者未定 | 采纳 | 评审引用 `core/Cargo.toml:12-15` | §0.4；§7.2；§17 WP-R4、WP-E2a |
| C-31 | major | 行为摘要只有文字描述，C5 与 W2 会实现出不同的 schema；报告数量无上限 | 采纳；报告上限取 S-13 的 8 条 | — | §12.8；§9.4；§0.4 |
| C-32 | minor | 若干交叉引用错误与遗漏 | 采纳 | — | 各处 |
| C-33 | minor | §14.5 只写了增量，容易与测试固定的完整规则脱节 | 采纳 | 评审引用 `edge/tests/valkey_acl.rs:36-38` | §14.5 |
| C-34 | minor | 顶层消息引用嵌套的 `PowBits` 无法解析；`ChallengeResult` 的 `Eq` 派生无法编译 | 采纳 | 已核对 `config.proto` 中 `PowBits` 嵌套在 `ChallengeConfig` 内 | §3.2；§3.4 |
| C-35 | minor | 类型与常量名与代码不一致 | 采纳 | 已核对 `core/src/sealed.rs:141` 的 `MAX_INTERACTIVE_LIFETIME_MS` 与 `core/src/context.rs:448` 的 `Token` | §3.3；§3.4；§6.1；§6.10 |
| C-36 | minor | `ts` 的类型、`counters` 项数的检查时机与 `t` 内的 JSON 规则未定义 | 采纳 | 评审引用 `edge/src/submission.rs:347` | §7.5 字段表 |
| C-37 | minor | `straight_long` 的桶与像素下限不一致 | 采纳 | 评审引用 `sdk/web/src/behavior.ts:24-39` | §7.8 |
| C-38 | minor | 别名可能与 manifest 中同名的文件冲突；站点 CSP 需要 `worker-src` | 采纳 | 评审引用 `edge/src/sdk.rs:289-296` | D-39；§11.1；§12.2 |
| C-39 | minor | 报告路径不脱敏；`cache_hit` 覆盖了本来就允许缓存的 `/__mg/s/` | 采纳 | — | §9.4 |
| C-40 | minor | §1.4 按前缀删除 Cookie，D-61 按三个精确的名字 | 采纳 | — | §1.4 |
| C-41 | minor | 新端点的 425 / 429 / 503 是 JSON 还是 HTML、两个 `Set-Cookie` 的顺序未定义 | 采纳 | 评审引用 `edge/src/enforce.rs:138-176` | §11.1；§9.4 |
| C-42 | minor | Turnstile 的错误类别有重叠 | 采纳 | — | §8.3 |
| C-43 | minor | 两个国家来源不一致时 `denied_countries` 的判定未定义 | 采纳 | — | §5.4 第 2 条 |
| C-44 | minor | `deny.toml`、模块声明与 SDK 0.3.0 的版本号没有归属；p256 的说明有误 | 采纳；验签改用已在 `Cargo.lock` 中的 aws-lc-rs，p256 的说明不再适用 | 已核对 `Cargo.lock` 中有 aws-lc-rs 1.18.1，没有 p256 | §2.2；§0.4；§1.2；§12.9 |
| C-45 | minor | `XAUTOCLAIM` 只在启动时运行，旧消费者的待确认条目无人认领 | 采纳 | — | §13.2；§13.6 |
| C-46 | minor | 反馈条目 v2 不是 v1 的前缀扩展；样例文件的格式未定义 | 采纳 | 评审引用 `edge-core/src/events/stream.rs:126-142` | §13.1；§0.4 |
| C-47 | minor | 60 s 规则不能放在 `refresh_check` 里；新凭证 `bind` 的来源未定义 | 部分采纳：60 s 规则由 Edge 检查；`bind` 按 S-16 原样复制，不取当前请求 | 取当前请求会让软不符的凭证每次刷新都换到新的前缀 | §6.8；§9.3 第 8 步 |
| C-48 | minor | "排查问题"与"隐私说明"链接没有目标 | 部分采纳：按 U-26 改为配置包字段与模板占位符，而不是写死页内锚点与 `/privacy` | — | §3.2；§12.3；§12.7 |
| C-49 | minor | 若干重述的 Phase 1 契约没有写明所改的章节 | 采纳；编号为 D-69（D-66 已用于 schema 1 的严格模式） | — | D-69 |
| C-50 | minor | 切换之后 v1 提交失败附什么 C、v2 提交能否带顶层 `env` / `auto` 未定义 | 采纳 | 评审引用 `edge/src/submission.rs:354-355` | §7.5 `v` 行 |
| C-51 | minor | 刷新阈值用了 SDK 无从得知的"该级别缺省 TTL" | 部分采纳：状态 Cookie 增加 `iat`，但按 S-20 不含级别；刷新时机按 U-14 | — | D-46；§6.8；§12.5 |
| C-52 | minor | 指标缺少若干取值，siteverify 延迟用了不合适的桶 | 采纳 | 评审引用 `edge/src/metrics.rs:45-60` | §15.5 |
| C-53 | minor | 旧 secret 重试复用同一个幂等键 | 采纳（同 S-17），并列入 §21 待实测 | — | §6.9；§8.4；§21 |
| C-54 | minor | `DynamicUser` 的单元连不上 unix socket；`${CREDENTIALS_DIRECTORY}` 的展开规则未定义 | 采纳 | — | §13.5；§13.6 |
| C-55 | minor | `turnstile_keys` 文件格式错误时 `--check-config` 的结果未定义 | 采纳 | 同 I-38 的规则 | §8.7；§10.1 |
| C-56 | minor | 速度、帧间隔、压力与 `pow.impl` 的量化未定义 | 采纳 | — | §7.6 |

### 23.3 R3（无障碍、浏览器与运维）

| # | 级别 | 意见 | 处置 | 核实 / 理由 | 落点 |
|---|---|---|---|---|---|
| U-1 | blocker | 只有 API 路由要求交互式时，`/__mg/v` 按页面路径只签发 `pow`，访客永远拿不到交互级凭证 | 采纳 | — | D-58；§7.10；§12.5；WP-E2a 测试 |
| U-2 | blocker | 站点的 Service Worker 会截获 `/__mg/*`，挑战页与 SDK 升级都可能失效 | 采纳 | 这类问题 Edge、CI 与 Lab 都观察不到，只能靠接入要求与客户端上报 | D-39；§19 第 3b 步；§9.4 `sw_intercept`；WP-W2 README |
| U-3 | major | `#mg-hold` 上的 click 如何分类未定义，两种读法各伤一类用户 | 采纳 | — | §12.6；§12.10 |
| U-4 | major | 状态文字只显示、不播报（WCAG 4.1.3） | 采纳 | — | §12.6 播报行；§12.7；§12.10 |
| U-5 | major | 失败、重置与模式切换时焦点丢失 | 采纳 | — | §12.6 焦点行；§12.10 |
| U-6 | major | `pow_a11y` 在最需要它的设备上最慢；60 s 总时限；不确定进度 | 采纳 (a)–(d)；WASM 内核列入 §21 | — | §10.2 `a11y_bits: 17`；§12.6；§21 |
| U-7 | major | 缺省的软特征会惩罚辅助技术与普通的人类输入 | 采纳 | — | §7.8；§19 第 5 步；§10.2 警告 |
| U-8 | major | 时序竞争把及时操作的用户判为失败；`ix` 不带 `min_pow_ms`；新 C 不重新绑定 | 采纳 | — | §7.2 `min_ms`；§7.4；§7.5；§12.6 |
| U-9 | major | `SUBMITTING` 的失败情况没有规则 | 采纳 | — | §7.4 第 7 步；§12.6 提交行 |
| U-10 | major | 后台续期在换网络时计为失败 | 采纳 | — | §7.4 第 5 步（`renew_rebind`）；§12.6 |
| U-11 | major | 密钥存储的失败模式未定义，其中两种会循环 | 采纳 | — | D-45；§12.4；§21 |
| U-12 | major | 设备时钟偏差会把用户锁在 `proof: required` 的路由之外 | 采纳（与 C-22 合并） | — | §11.2；§12.5 |
| U-13 | major | 并发的挑战与刷新没有合并，消耗签发配额 | 采纳 | — | §12.5；§12.10 |
| U-14 | major | 长时间停留在一个页面上时不刷新；WeChat 的 `visibilitychange` 不可靠 | 采纳；状态 Cookie 不含级别（S-20） | — | §6.8；§12.5；§21 |
| U-15 | major | 站点页面没有接入约定（加载失败、加载顺序、XHR、选项丢失） | 采纳 | — | §12.1；§19 第 3b 步 |
| U-16 | major | 靠跳转恢复会丢掉页面状态 | 采纳 (a)–(c) | — | §9.1 就地恢复；§12.1 `onBeforeNavigate`；§10.2 警告 |
| U-17 | major | 人为摩擦的验收算不出来，而且分子不含真正的摩擦 | 采纳 | — | §13.1 `ctype`；§13.3；§15.5 `mg_navigations_total`；§20 |
| U-18 | major | 单机上没有 vmalert，告警无法计算，另缺若干告警 | 采纳；两种形式都交付 | — | §19 第 8 步；§2.2 |
| U-19 | major | 升级与回滚的顺序会让页面出错 | 部分采纳：步骤拆分、schema 1 接受 v2 提交、回滚顺序都采纳；不加 `[sdk] previous_dir`，因为模板先改用别名，旧的哈希文件名不再被引用 | — | §19 第 3a–3c、9 步；D-66 |
| U-20 | major | 按 IP 与 /24 的检测器会误伤本站受众的共享地址 | 部分采纳：`high_rate` 的共享出口与 `scanner` 只计无凭证的请求都采纳；`shared_token` 改为按 `pf = j` 判定（S-11），不加 /16 与 UA 家族条件 | — | §13.3；§19 第 6 步 |
| U-21 | minor | 尺寸与焦点规则只覆盖 `#mg-hold`；强制颜色、320 px 与文字间距 | 采纳 | — | §12.3；§8.3 |
| U-22 | minor | 文案问题：按位置指代、措辞误导、缺少字符串、初始状态文字、语言回退 | 采纳 | 已核对 Phase 1 规格 §11.2 的语言规则（非 zh 一律 en） | §12.7；§7.3；§3.2 `default_lang` |
| U-23 | minor | 偏好 Cookie 由脚本写入、点击即写入、`pow_a11y` 置首时的行为未定义 | 采纳 | — | §9.5；§12.6 |
| U-24 | minor | Cookie 被阻止时循环；返回键回到挑战页 | 采纳 | — | §12.6 提交行 |
| U-25 | minor | 指针规则的实现陷阱；SDK 发送注定失败的提交 | 采纳 | — | §12.6 指针按住行；§7.6 `hold.cancels` |
| U-26 | minor | 帮助与隐私链接没有目标；Cloudflare 注入的请求影响第三方核对 | 采纳 | — | §3.2；§12.3；§20 |
| U-27 | minor | 没有浏览器下限，SDK 无法运行时没有兜底 | 采纳；不降低 esbuild 目标，以下限为准 | — | §12.1；§12.3 `#mg-stuck` |
| U-28 | minor | 测试矩阵与大陆受众不符 | 采纳 | — | §19 第 5 步 |
| U-29 | minor | 别名没有校验器；页面与 Worker 可能来自不同缓存层；别名下丢失构建号 | 部分采纳：`ETag` / 304 与 Worker 的版本握手采纳，`sv` 放进 `t.ix`；不把界面拆成第二个文件（单文件规则不变，大小在预算内） | 已核对 `edge/src/routes.rs` 按不含查询串的路径分类，`?sv=` 不影响取文件 | §11.1；§12.6；§7.6 |
| U-30 | minor | 主线程回退会阻塞页面；站点 CSP 会迫使就地求解在主线程运行 | 采纳 | — | §12.6 PoW 行；§19 第 3b 步 |
| U-31 | minor | 上游挑战报告会丢失；离页摘要来不及签名；后台请求触发重载；重载的方式 | 采纳 | — | §12.5；§12.8 |
| U-32 | minor | 未认证的 ECDSA 成本；证明在所有路由上都校验 | 采纳（与 S-3 合并）；验签用 aws-lc-rs | — | §6.7；§9.1；§1.2 |
| U-33 | minor | 按 /24 的新配额最先伤到 CGNAT 与校园网后的用户 | 采纳 | — | §7.9；§10.2 |
| U-34 | minor | 近线指标的含义与告警假设不符；指标名不一致 | 采纳 | — | §13.7；§9.4 |
| U-35 | minor | Valkey 与近线步骤的缺口（内存、socket、凭证路径、完整 ACL、模式切换） | 采纳 | — | §19 第 1a、1b、6 步；§13.6；§10.1 |
| U-36 | minor | `force_monitor` 容易被遗忘；与 I-36 的关系；缺少命令；SDK 故障没有手段 | 采纳 | 已核对 I-36 的超限例外与 `deploy/systemd/mg-edge.service` 的路径和 `ExecReload` | §9.6；§19 第 10 步 |
| U-37 | minor | 发布的版本号、dist-tag 与 trusted publisher 的登记未定义 | 采纳 | — | §12.9；§19 第 11 步 |
| U-38 | minor | 完成时间的验收量错了区间 | 采纳 | — | §7.6 `act_ms`；§3.3；§20 |
| U-39 | minor | 隐私说明排在新信号上线之后；测试路由没有做法 | 采纳 | — | §19 第 2、5 步 |
| U-40 | minor | Turnstile 状态下的界面与续期问题 | 采纳 | — | §8.3；§12.6 |
| U-41 | minor | WebCrypto 不可用时 0.3 的挑战页反而无法通过 | 采纳 | — | D-45；§12.1；§12.4 |
| U-42 | minor | 一条自然的所有者规则会命中密钥被清除的普通用户 | 采纳 | — | §4.2 |
