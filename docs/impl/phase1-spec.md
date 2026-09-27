# Phase 1 实现规格：Cloudflare 之后的 Edge

**结论**：Phase 1 拆成 18 个工作包（WP），分三个阶段。阶段 1 的 11 个 WP 按文件互不重叠、可以并行：Rust `core/`、`challenge/`、`intel/`；不依赖 Pingora 的 Edge 组件 `edge-core/`（上游信任与请求上限、配置包客户端、Valkey 状态层、事件出口各一个 WP）；Go 策略编译器、mgctl 运维命令、Cloudflare 与情报同步；Web SDK。阶段 2 由四个按顺序合入的 WP 把这些组件接进 Pingora（`edge/`）。阶段 3 做 Validation Lab 场景与端到端脚本、JA4 预研、文档勘误。本文把所有跨组件契约写死：IR proto、Rust / Go 公共 API、`edge.toml` v1、站点 YAML v1、`/__mg/*` 请求与响应、Cookie、Valkey 键与 Lua 脚本、事件 JSON 行与 VictoriaLogs 调用、指标、工件与密钥文件格式。实现者按本文编码，不需要再协商；需要改契约时先改本文。

- 设计依据：[07 Phase 1](../07-roadmap.md)、[02](../02-data-flow.md)、[03](../03-risk-scoring.md)、[04](../04-challenge-and-tokens.md)、[06](../06-policy-console-observability.md)、[08](../08-upstream-and-cloudflare.md)、[09 §4](../09-interactive-challenge.md#4-密封-challenge)、[ADR](../adr/README.md)。设计文档说"是什么、为什么"，本文说"Phase 1 具体怎么做"；两者冲突时，Phase 1 实现以本文为准，WP-D1 负责把设计文档改到一致（§0.3 列出了全部偏离）。
- 规范用语："必须 / 不得"是硬性要求；"应"是默认做法，偏离时在该 WP 的 PR 描述里写明理由；"可"是可选。
- 本文的提交已经落地了一部分契约文件与共享夹具（§0.4），各 WP 从这些文件出发，不重新定义它们。
- 贯穿全文的安全约束：**客户端 IP 未知时，Edge 从不比 IP 已知时更宽松**（§9.3.2）；**配置或信任出错时不静默放开**（§9.10）；**攻击者可控的输入大小不能让规则失效**（§5.3、§9.3.1）。
- 两轮评审的逐条处置见 §20。

## 0. 范围、决定与已落地文件

### 0.1 范围

| 在范围内（代码与测试） | 不在范围内 |
|---|---|
| Edge：`cloudflare` profile（Tunnel 回环信任、AOP 客户端证书）、`direct_tls` TLS 监听器；上游头族剥离与可信头解析；协议输入上限；站点 / 环境 / 路由匹配；RequestContext 构建；GeoLite2（可选）；爬虫验证（官方 IP 段 + 异步 rDNS）；凭证校验；本地 + Valkey 限速；Decision Core v1（检测器、分族封顶评分、BotClass、策略 IR、默认处置矩阵）；执行动作 allow / log / tag / rate_limit / block / 无感 Challenge（`invisible`、`pow`）；`/__mg/c`、`/__mg/s/*`；签名配置包拉取与 last-known-good；EventSink（VictoriaLogs + `mg:ev`）；指标 | 交互式 Challenge、Provider、Turnstile（Phase 2）；`/__mg/c/renew`、`/__mg/r`、`/__mg/t`（Phase 2，Phase 1 返回 404）；`cnf.jkt`、`MG-Proof`、会话密钥（Phase 2）；近线 worker 与 verdict 生成（Phase 2；Phase 1 只读 `mg:v:*`）；吊销集与 pub/sub（Phase 3）；Web Bot Auth、Agent Registry（Phase 3）；SDK 注入源站 HTML（Phase 2）；TARPIT；PROXY protocol；随机 `/__mg/` 前缀 |
| mgctl：策略编译到 IR、站点 YAML、密钥生成与导出、配置包构建 / 签名 / 校验 / 发布、本地哈希链审计日志、verdict 键计算、`cf audit`、`cf ips sync`、`crawler sync` | mg-control 服务的任何新功能（Phase 3）；`mgctl cf apply`（写 Cloudflare 规则，按需） |
| Web SDK：挑战页客户端（Worker 中的 SHA-256 PoW、基础环境摘要、表单提交跟随 303）与挑战页模板 | SDK 遥测、行为采集、`cf-mitigated` 处理、fetch 包装（Phase 2） |
| Validation Lab：冒充爬虫场景、非 JS 客户端拿不到凭证场景、端到端脚本 | 任何面向非白名单目标的流量；负载生成 |
| JA4 技术预研（`direct_tls`），结论写入 ADR-0002 勘误 | JA4 进入评分或绑定（`tfp`） |

**所有者操作**（代码之外，见 §17）：在真实 zone 上部署 Transform Rule 等规则、以 monitor 模式在 Cloudflare 之后运行 ≥ 1 周、人工浏览回归、用生产指标确认附加延迟。

### 0.2 WP 编号

| 编号 | 名称 | 阶段 |
|---|---|---|
| WP-R1 | mg-core：检测器、评分 v1、BotClass、默认处置矩阵、策略 IR 求值器（含静态步数上界）与规则引擎、UA 解析、`Glob`；IR 线格式转换（`proto/rust/src/ir.rs`） | 1 |
| WP-R2 | mg-challenge：密封 C、epoch 密钥、PoW、PASETO 凭证与绑定 | 1 |
| WP-R3 | mg-intel：IP 集合、GeoLite2、爬虫注册表校验与验证、Cloudflare IP 段 | 1 |
| WP-C1 | mg-edge-core `upstream` 与 `request`：头族剥离、`cloudflare` 可信头解析、`CF-Worker` 校验、Host 一致性、协议输入上限 | 1 |
| WP-C2 | mg-edge-core `bundle`：配置包拉取、验签、边界校验、LKG、工件缓存 | 1 |
| WP-C3 | mg-edge-core `state`：Valkey 管线与 Lua、熔断、本地模式；Valkey 测试夹具与故障注入转发器 | 1 |
| WP-C4 | mg-edge-core `events`：事件队列、VictoriaLogs 批量写入、文件出口、`mg:ev` 条目 | 1 |
| WP-G1 | Go 策略编译器：CEL → IR、静态步数上界、参考求值器（MISSING 语义）、跨语言一致性夹具 | 1 |
| WP-G2 | mgctl 运维：站点 YAML、密钥、配置包、审计日志、verdict 键、命令分发、`go.mod` | 1 |
| WP-G3 | mgctl Cloudflare 与情报同步：`cf audit`、`cf ips sync`、`crawler sync`；`adapters/cloudflare/` | 1 |
| WP-W1 | Web SDK：挑战页客户端与模板 | 1 |
| WP-E1a | mg-edge 骨架：`edge.toml` v1 与凭证、进程与运行时模型、监听器与 TLS、上游信任与协议上限接线、站点状态机与配置包接线、路由、monitor 转发与源站头、systemd / 冒烟 / CI | 2（第 1 个） |
| WP-E1b | mg-edge 决策：RequestContext / Activation / MissingSet、凭证与爬虫验证（rDNS）、状态层与限速接线、Decision Core、阻断与限速响应 | 2（第 2 个） |
| WP-E1c | mg-edge 挑战：Challenge 签发与挑战页、`/__mg/s/*`、`/__mg/c` 全流程 | 2（第 3 个） |
| WP-E1d | mg-edge 观测：事件接线（decision / access / feedback / telemetry / stream）、完整指标、附加延迟、守护进程模式冒烟 | 2（第 4 个） |
| WP-L1 | Validation Lab Phase 1 场景与端到端脚本 | 3 |
| WP-J1 | `direct_tls` JA4 预研与 ADR-0002 勘误 | 3 |
| WP-D1 | 设计文档勘误、CLAUDE.md / README、威胁模型状态更新 | 3 |

本文中"WP-E1"泛指阶段 2 的 E1a–E1d；需要指定时写子 WP 编号。"WP-C*"泛指 C1–C4。

### 0.3 决定与偏离

下表是本文相对设计文档或集成指引作出的决定。WP-D1 把"需改设计文档"一栏为"是"的条目写回设计文档或 ADR。

| # | 决定 | 理由 | 需改设计文档 |
|---|---|---|---|
| D-01 | 预注册工作区成员 `challenge`、`intel`、`edge-core`，并在本提交中给出可编译的空 crate、依赖声明与根 `[workspace.dependencies]` 条目（已锁定）；阶段 1 的 Rust WP 不改根 `Cargo.toml` 的已有条目 | 避免并行 WP 争用根 `Cargo.toml` 与 `Cargo.lock` | 否 |
| D-02 | 策略 IR 的线格式→原生结构转换放在 `mg-proto`（`proto/rust/src/ir.rs`），`mg-proto` 依赖 `mg-core`；`mg-core` 不引入 prost | `mg-core` 保持最小依赖与 wasm32 可编译；一致性测试需要同时看到两边 | 否 |
| D-03 | Valkey 客户端用 **redis-rs**（`redis` 1.7），不用 fred | redis-rs 2026-09 仍在发版、有 `ConnectionManager` 自动重连、管线、`Script`（EVALSHA + NOSCRIPT 回退）；fred 最近一次发版在 2025-02 | 否 |
| D-04 | MorphGate 自己的代码只用一个 Ed25519 实现：**ed25519-compact**（pasetors 的 `v4` 特性本来就依赖它），用于 Edge 验证配置包签名；Go 侧用标准库 `crypto/ed25519`。Pingora 的 BoringSSL 与 reqwest 的 rustls（aws-lc-rs）只做 TLS，不用于签名 | ADR-0005 的"只用一个 Ed25519 实现"按"自有代码路径"执行：TLS 库自带的密码学无法去掉（BoringSSL 是 Pingora 的前提；rustls 的提供者只能在 aws-lc-rs 与 ring 之间选） | 是（ADR-0005 勘误） |
| D-05 | 凭证与 C 的绑定新增 `ipa = hash(ASN)`（`SealedChallengeClaims.Bind.ipa`，凭证 `bind.ipa`），用于判定 `ipp` 的软 / 硬结果 | 04 §5 要求"同 ASN 内变化 → 风险信号；跨 ASN → 重新 Challenge"，没有签发时的 ASN 无法判断 | 是（04 §5、09 §4.2、ADR-0005） |
| D-06 | 实体与限速器的 Valkey 键中，标识个人的部分用所有者级假名化密钥 `K_pseudo` 做 HMAC（§9.7）；新增密钥文件 `pseudo.key.json` | 10 VK-04 要求标识个人的键做哈希；`mg:v:all:*` 跨站共享要求哈希与站点无关 | 是（02 §7、06 §8 密钥清单） |
| D-07 | Phase 1 中 `identity.proof.*`、`identity.agent.*` 恒为 MISSING；`direct_tls` 下 `tls.ja4` 恒为 MISSING（JA4 只是预研） | 能力在 Phase 2 / 3 才有；按 ABSENT（零值）处理会让 `login-require-proof` 之类规则永远命中、造成挑战循环 | 是（06 §2 注明阶段） |
| D-08 | Phase 1 没有交互式 Challenge：规则或矩阵要求 `interactive` 时按 `pow`（该请求风险段的难度）执行；规则触发时在其 hit 的 `fields` 记 `phase1.interactive_as_pow`，矩阵触发时由 `rule_id = matrix.critical.high` 与 `challenge_type = pow` 表明；编译器对 `params.type: interactive` 给警告 | 交互式在 Phase 2 | 否（阶段性行为） |
| D-09 | TARPIT 在 Phase 1 不实现：配置包构建时对 `tarpit` 动作报错 | 03 只把它列为 `direct_tls` 可选项 | 否 |
| D-10 | 实体 verdict 在 Phase 1 只能抬高风险：`β_e · max(0, logit(R_e/100))`，封顶 4.0 | 采纳 10 VK-02 的提议；Phase 1 的 verdict 只能由所有者手工写入（键用 `mgctl verdict key` 计算，§14.1） | 是（03 §4.1、10 VK-02 标为已采纳） |
| D-11 | 挑战页提交走**表单导航**（`application/x-www-form-urlencoded`，字段 `mg`），成功 303 → `ret`，由浏览器跟随；`application/json` 提交返回 200 `{"ok":true}`（供 Phase 2 SDK 与测试） | 303 由浏览器原生跟随，Set-Cookie 与导航在同一响应链上，不依赖 fetch 的重定向限制 | 否（与 04 §9 一致） |
| D-12 | PoW 搜索用纯 JS SHA-256（Worker 中同步计算，预计算前缀），WebCrypto 只做自检 | WebCrypto `digest` 是逐次异步调用，hashcash 搜索慢一个数量级以上 | 是（04 §4.2 措辞） |
| D-13 | SDK 构建产物带内容哈希文件名 `mg.<hex16>.js`，Worker 用同一脚本 URL 启动（脚本自身识别 Worker 上下文）；Edge 只从 SDK 目录的 `manifest.json` 白名单提供 `/__mg/s/*` | 一个可缓存文件；CSP 只需 `worker-src 'self'` | 否 |
| D-14 | 监听器（绑定地址、TLS 文件、上游认证方式、上游密钥头）与站点的源站地址是主机本地配置，只在 `edge.toml`；站点的 Cloudflare 属性（visitor location 头、Tier 1、owner zones、Pseudo IPv4）在签名配置包 | 监听器无法热更换且每台主机不同；zone 属性与 `cf audit` 结果绑定，属于策略 | 是（08 §1.5 示意） |
| D-15 | Phase 1 不做 `mg:pub:cfg` 通知，Edge 只按间隔（默认 10 s）条件拉取 | Phase 1 的 mgctl 在工作站运行，不连 Valkey；10 s 满足"配置生效 < 30 s" | 否（02 §6 已写两阶段口径，注明 Phase 1 无提示） |
| D-16 | 事件 JSON 行在 `mg_core::DecisionEvent` 的 JSON 上加信封字段（`kind`、`site`、`ts`、`msg`）；`/insert/jsonline` 以 `_stream_fields=kind,site`、`_time_field=ts`、`_msg_field=msg` 写入 | VictoriaLogs 文档（2026-09-27 核对）：jsonline 端点、查询参数与嵌套字段展平规则 | 否 |
| D-17 | `mg_event_dropped_total`、`mg_config_version`、`mg_config_age_seconds` 带有界标签（`sink` / `site`） | 多站点 Edge 需要按站点区分配置版本；按出口区分丢弃 | 是（06 §5 标签列） |
| D-18 | 爬虫注册表的验证方式分 `ip_ranges`、`rdns`、`ip_ranges_or_rdns`：只有 `ip_ranges` 的运营方，IP 不在官方段即同步判为失败；需要 rDNS 的，首个请求为 `pending`（`DECLARED_AGENT`），异步反查后结论入缓存；`pending` 期间 IP 不在已发布段时给正向风险信号（§5.7） | 满足"rDNS 不在请求路径上同步执行"，同时让只发布 IP 段的运营方能 100% 同步识别冒充；rDNS 被挤满时冒充者也不是零风险 | 是（05 §7.2 补充） |
| D-19 | 策略规则的阶段内顺序：`priority` 大者先，同优先级按 `id` 字节序；`disabled` 与已过期的规则不进配置包 | 06 §1 未定义 `priority` 方向 | 是（06 §1） |
| D-20 | 默认处置矩阵增加"凭证已满足"抑制：请求带有效凭证且其级别不低于矩阵要下发的 Challenge 类型时，改为 TAG（`matrix.satisfied`） | 否则高分的真人每个请求都被重复挑战 | 是（03 §5.1 注释） |
| D-21 | 站点状态机（§9.10）：从未有过配置包（没有 LKG 文件）→ `bootstrap`，按 `edge.toml` 站点的 `bootstrap = "open"`（缺省：全部放行并记录，`rule_id = "bootstrap"`、`bundle_version = 0`）或 `"closed"`（503）；有 LKG 但无法使用（验签、解码、校验失败）→ `lkg_invalid`，一律 503，且 `mg-edge --check-config` 失败；LKG 可用但部分工件不在缓存 → 照常应用，缺失工件对应的字段为 MISSING | 首次安装保持可用；配置或信任出错时不静默放开 | 否 |
| D-22 | Validation Lab 的"冒充爬虫 100% 识别"按**结论已确定的请求**计：`ip_ranges` 方式从第一个请求起；`rdns` 方式在热身请求触发反查之后；热身请求本身须为 `DECLARED_AGENT` 且从不判为 `VERIFIED_CRAWLER` | 与 D-18 一致 | 否 |
| D-23 | 客户端 IP 未知时从不比已知时更宽松（§9.3.2）：外部 zone 的 `CF-Worker` 直接 403；限速维度未知时用共享兜底桶 `?`；不签发 C、不签发凭证（429）；C 与凭证恒绑定 `ipp`；源站收到 `MG-Client-IP: unknown` | 原稿把外部 Worker 当作"IP 未知"继续处理，任何 Cloudflare 账号都能借此绕过按 IP 的限速、绑定与名单 | 是（02 §2.1、04 §5、08 §2.2） |
| D-24 | `ip` 实体：IPv4 为地址本身，IPv6 为所在 /64（`Net::entity_of`）；用于 `ip` 维度限速、`ip` verdict 键、`mg:ev` 的 `ipk`。`net.ip` 仍是完整地址，`ipp` 仍是 /24、/48 | 一个 IPv6 用户至少拥有一个 /64，隐私扩展地址随时轮换；按完整地址计数等于没有限速，还会制造无界的键 | 是（02 §7、04 §6.3） |
| D-25 | 路由按多个路径视图匹配（原始、RFC 3986、Cloudflare、完全解码去参数），每个视图也比较切换末尾 `/` 后的形式；多个路由命中时取敏感度最高者，`require_clearance` / `fail_closed` 取所有命中路由的"或"；站点可设 `case_insensitive_paths` | 路由是 `require_clearance` 与 `critical` 的安全边界；源站框架常把 `/Account/Login/`、`/account%2Flogin`、`/account/login;x` 交给同一个处理器 | 是（02 §2 路由匹配、06 §1） |
| D-26 | 策略输入有硬上限（§9.3.1）：路径、查询串各 ≤ 8 KiB，否则 414；单个头值 ≤ 8 KiB（`Cookie`、`Authorization`、`Proxy-Authorization` 除外）、头名 ≤ 256 字节、清洗后至多 128 个不同头名，否则 431；方法 ≤ 32 字节，否则 400。monitor 与 bootstrap 下同样执行。编译器按这些上限计算每条规则的静态最坏步数 `max_steps`，超过 100,000 的规则编译失败，Edge 加载时复算 | ADR-0006 决策 8 要求超出代价上限的规则编译失败；原稿在运行时超限后判"不命中"，攻击者加长路径即可让阻断规则失效 | 是（ADR-0006 勘误、06 §2） |
| D-27 | Phase 1 挑战升级：`invisible` 的难度固定为 `pow_bits.low`，`pow` 取风险段难度；提交失败后附的新 C 一律为 `pow`，风险段升一级（`min(risk_band + 1, high)`；`attempt_no` 保持 0，它只用于交互式）；重试次数由失败配额（D-28）约束。凭证的人类证据不分级别（§5.7） | 04 §4.1 的"无感 / PoW 失败升级为交互式"在 Phase 1 没有交互式可升；否则机器人可以在最低难度上无限重试；原稿里两种级别难度相同而证据权重不同，互相矛盾 | 是（04 §3.1、§4.2） |
| D-28 | 失败配额分两级：`mg.c.fail` 按 `ip` 实体（`max_failures`），`mg.c.fail.prefix` 按 `ipp`（4 × `max_failures`）；`ic.c_expired`、`ic.replay_unavailable`、`ic.no_client_ip`、`ic.issue_quota`、`ic.rate_limited`、`ic.too_early` 不计为失败 | 只按 /24 计时，同一 CGNAT / 移动网段中的一个客户端能让整个前缀无法通过挑战；Phase 1 挑战前没有会话，04 §4.1 的"按会话"由 `ip` 实体代替 | 是（04 §4.1） |
| D-29 | 凭证 claims 增加 `sst`（会话开始时间，Unix 秒）；`sub` 只从通过站点 / 环境校验、没有硬绑定失败且 `now − sst ≤ session_max_s` 的凭证沿用（可以已过期）；凭证必须带 `bind.ipp`；未知或已退役 kid 的凭证按 `expired`（ABSENT）处理；只用 pasetors 的底层 `LocalToken` 接口，`iat` / `exp` 保持 Unix 秒 | 原规则允许把别的浏览器的会话接到新客户端上，且每次重签都重置 `iat`，会话可以无限续期 | 是（04 §5、ADR-0005） |
| D-30 | `seal.root.json` 含 1–2 个根密钥：`roots[0]` 封装，全部用于打开（按顺序试 AEAD）；轮换分三步（§17） | 多台 Edge 逐台更换根密钥时，cloudflared 按连接选择副本，另一台签发的 C 会打不开 | 是（ADR-0005、06 §8） |
| D-31 | 路由可设 `redact_path`：事件与访问记录以 `/<route name>` 代替路径；Edge 应用日志（Pingora 错误日志、`log` 输出、journald）从不写客户端 IP、Cookie、C、凭证、上游密钥与 `x-mg-cf-tls-random`；遥测 `env` 只按 SDK schema 的已知字段、带长度上限重新序列化 | 路径里可能有找回密码、邮箱验证等一次性令牌；06 §7 的数据最小化 | 是（06 §6、§7） |
| D-32 | `cloudflare` profile 下访客协议为 http 时，CHALLENGE 对 GET / HEAD 改为 308 跳转到 https；`mgctl cf audit` 新增 error 级检查 `always_use_https` | `__Host-` Cookie 要求 Secure，http 访客永远拿不到凭证，`require_clearance` 路由会无限挑战 | 是（04 §5、08 §2.10） |
| D-33 | 不依赖 Pingora 的 Edge 代码放在预注册 crate `mg-edge-core`（`edge-core/`），由 4 个阶段 1 WP 并行完成；阶段 2 拆成按顺序合入的 E1a–E1d；WP 合入后的缺陷按 §2.1 的修复规则处理 | 原稿的单个阶段 2 WP 是整个关键路径，且合入后的缺陷没有修复负责人 | 否 |
| D-34 | 源站契约补充：内容随 `MG-*` 头变化的响应必须带 `Cache-Control: private` 或 `no-store`；源站不得因为 `REMOTE_ADDR` 是回环地址就信任请求；客户端 IP 未知时 `MG-Client-IP: unknown`；Edge 把上游请求的 `Host` 设为用于选站点的规范化主机名，并先删除客户端 `Connection` 头及其列出的头 | Cloudflare 对非图片内容不理会 `Vary`；Edge 与源站同主机时回环地址不代表可信；逐跳头滥用可以删掉 Edge 写入的头 | 是（02 §8） |
| D-35 | 进程内重放集合是固定容量的 TTL 集合，从不逐出未过期的 nonce，满时按"重放存储不可用"处理；Valkey 模式下也同时写入本地集合；进程内集合是唯一可用的重放存储时，`iat_ms` 早于本进程启动时间的 C 按"重放存储不可用"处理（覆盖平滑升级后的 ≤ 120 s 窗口） | 10 VK-03：重放集合不得被静默逐出；LRU 满时逐出已用 nonce 即可重放 | 是（01 §8 降级表注明） |
| D-36 | 爬虫注册表逐条校验 CIDR（§12.3：规范网络地址；IPv4 前缀 ≥ /16、IPv6 ≥ /32；拒绝私有、回环、链路本地、组播、CGNAT、保留段；文档段只在 `test: true` 的注册表中允许），`crawler sync` 对任一运营方的条数变化超过 50% 时拒绝（`--accept-change` 放行）；`VERIFIED_CRAWLER` 只在 GET / HEAD 或非 `require_clearance` 路由上由矩阵放行 | 注册表来自第三方 JSON；一条 `0.0.0.0/0` 就会让任何带 Googlebot UA 的请求越过挑战与 `very_high` 阻断 | 是（05 §7.2、03 §5.1） |
| D-37 | 凭证签发配额 `mg.clr.issue.ipp` / `mg.clr.issue.asn` 强制执行（超额 429，reason `ic.issue_quota`）；nonce 消费与配额计数在同一个 Lua 脚本 `mg_nonce_issue` 里完成，nonce 已用过时不计配额 | 04 §5、§6.3 要求按 ipp / ASN 限制签发；原稿只记信号，而 `/__mg/c` 上没有 Decision Core 消费该信号 | 否（与 04 一致；撤销原稿的偏离） |

### 0.4 本提交已落地的契约文件

| 文件 | 内容 | 之后的所有者 |
|---|---|---|
| `Cargo.toml`、`Cargo.lock` | 成员 `challenge`、`intel`、`edge-core`；`[workspace.dependencies]` 含 §1.2 中阶段 1 crate 与 mg-edge 的全部第三方依赖，已离线解析并锁定 | 阶段 1 只按 §2.3 追加；阶段 2 起 WP-E1a |
| `challenge/`、`intel/` | 可编译的空 crate（`Cargo.toml` 已声明依赖，`lib.rs` 只有文档注释） | WP-R2、WP-R3 |
| `edge-core/` | `mg-edge-core` 空 crate：`Cargo.toml`（依赖已声明，特性 `testkit`）、`lib.rs`（模块已注册）、每个模块与 `testkit/*` 的占位文件 | 模块按 §2.2 分给 WP-C1–C4；`Cargo.toml`、`lib.rs`、`testkit.rs` 由集成者维护 |
| `core/src/paths.rs` | `/__mg` 归属与路由匹配共用的路径视图（`is_reserved`、`rfc3986_view`、`cloudflare_view`、`decoded_view`、`route_candidates`），从 `edge/src/routes.rs` 移入；`routes.rs` 改为调用它 | WP-R1（语义为只读契约） |
| `core/src/gcra.rs`、`core/testdata/gcra-cases.json` | GCRA 纯函数（§9.7）与共享用例表（由一个独立的 Lua 语义模型生成） | WP-R1（语义为只读契约）；WP-C3 用同一张表测 Lua |
| `core/src/context.rs`、`core/src/sealed.rs` | `ChallengeBind.ipa`；`BindResult::SoftMismatch`（`soft_mismatch`）；`Net::entity_of`（D-24）；`Net::prefix_of` 先还原 IPv4 映射地址 | WP-R1 |
| `proto/morphgate/v1/policy_ir.proto` | 策略 IR 的最终定义（§3.1），`PolicyExpr.max_steps` 为规范字段 | WP-G1 与 WP-R1 共同只读；修改需先改本文 |
| `proto/morphgate/v1/config.proto` | Phase 1 配置包 schema（§3.2），含 `Route.redact_path`、`SiteBundle.case_insensitive_paths` | WP-G2、WP-C2 与 WP-E1 共同只读 |
| `proto/morphgate/v1/challenge.proto` | `Bind.ipa`（D-05） | WP-R2 只读 |
| `proto/rust/` | `build.rs`、`Cargo.toml`（依赖 `mg-core`；开发依赖 `base64`）、`src/ir.rs` 占位、`tests/roundtrip.rs` | WP-R1 |
| `control-plane/gen/morphgate/v1/*.pb.go` | 已按上述 proto 重新生成 | 生成文件只随 proto 变更 |
| `control-plane/internal/cli/` | mgctl 子命令契约 `cli.Env`、`cli.AuditEvent`、退出码（§14.1） | WP-G2（只可追加字段） |
| `control-plane/internal/intelsync/`、`cfaudit.RunCLI` | 子命令入口桩 | WP-G3 |
| `control-plane/internal/mgctl/` | 分发已接好 `cf audit`、`cf ips`、`crawler`；测试不再固定策略告警条数、IR 版本与 `docs06-examples.yaml` 的规则条数和顺序（按 id 查找） | WP-G2 |
| `control-plane/internal/policy/compile.go` | `CheckedRule.Lists`（规则引用的名单名，排序去重）及测试 `TestReferencedLists` | WP-G1 |
| `testdata/phase1/kat.json` | 密钥派生与接受的 epoch、aad、绑定哈希、`ret` 哈希、实体与限速器键（含兜底值 `?`）、`ip` 实体、PoW 的已知答案向量 | 只读；修改需先改本文 |
| `testdata/phase1/keys/`、`testdata/phase1/artifacts/`、`testdata/phase1/README.md` | 密钥文件与工件的规范样例（有效与无效各若干）、规范 JSON 形式与生成输入（§12.0） | 只读；修改需先改本文 |
| `CLAUDE.md` | 新 crate、`testdata/` 与本文的索引 | WP-D1 |

## 1. 架构

### 1.1 组件与数据流

```
                    owner workstation                                    brain VM (static dir over WireGuard / mTLS)
  site.yaml + policies/*.yaml + artifacts ──mgctl bundle build──> *.sitebundle.pb ──mgctl bundle sign──> blog.bundle
  (keys: owner-2026.key.age)                 mgctl cf audit / cf ips sync / crawler sync       │ mgctl bundle publish (dir) + rsync
                                                                                              v
Visitor ─> Cloudflare ─> cloudflared ─> mg-edge 127.0.0.1 ─(ALLOW / TAG)─> origin     /srv/mg/{bundles,artifacts}/
                                          │  ▲                                                 ▲
                                          │  └──── GET bundles/<site>.bundle (If-None-Match), artifacts/<sha256>
                                          ├──> Valkey: MGET mg:v:*, EVALSHA mg_gcra / mg_nonce_issue, XADD mg:ev
                                          ├──> VictoriaLogs vl-main / vl-short: POST /insert/jsonline
                                          └──> /metrics (scraped by VictoriaMetrics)
```

### 1.2 Rust crate 与依赖

```
mg-core (pure, wasm32)  <──  mg-proto (prost types + ir.rs conversion)
   ^  ^  ^                       ^  ^
   |  |  └──── mg-challenge ─────┘  |   (pasetors, chacha20poly1305, hkdf, sha2, hmac, base64)
   |  └─────── mg-intel             |   (maxminddb, sha2)
   └────────── mg-edge-core ────────┘   (tokio, redis, reqwest, ed25519-compact, prometheus; no Pingora)
mg-edge ──> mg-core, mg-proto, mg-challenge, mg-intel, mg-edge-core, pingora =0.9.0, hickory-resolver, arc-swap
```

| crate | 第三方依赖（版本已在根 `Cargo.toml` 声明并锁定） | 约束 |
|---|---|---|
| `mg-core` | 无 | 纯函数；wasm32 可编译；`core/clippy.toml` 继续生效 |
| `mg-proto` | 无（普通依赖 `mg-core`；开发依赖 `base64`、`serde_json`） | 只放生成代码与线格式转换 |
| `mg-challenge` | `pasetors 0.8.1`（`default-features = false`，`std` + `v4`）、`chacha20poly1305 0.11.0`（`alloc` + `zeroize`）、`hkdf 0.13.0`、`sha2 0.11.0`、`hmac 0.13.0`、`subtle 2.6.1`、`zeroize 1.8`、`base64 0.23.1` | 无网络 / 文件 I/O、不读时钟、随机数经注入的 `Rng`；唯一例外是 pasetors 内部用 OS RNG 生成 PASETO nonce。不要求 wasm32 |
| `mg-intel` | `maxminddb 0.32.0`、`sha2 0.11.0` | 无网络 I/O；DNS 经 `DnsResolver` trait |
| `mg-edge-core` | `tokio 1.53`（`rt`、`time`、`sync`、`macros`、`net`、`io-util`）、`redis 1.7.1`（`tokio-comp`、`connection-manager`、`script`）、`reqwest 0.13.5`（`default-features = false`，`rustls`）、`ed25519-compact 2.6.0`、`getrandom 0.4.3`、`prometheus 0.14.0`（与 `pingora-prometheus` 同一版本，共用默认 registry）、`sha2`、`hmac`、`subtle`、`base64`、`prost`、`serde_json` | 不依赖 Pingora；异步代码只在调用方提供的 tokio 运行时上执行（§9.1.1）；出站 HTTP 必须 `ClientBuilder::no_proxy()` |
| `mg-edge` | 以上 crate 加 `hickory-resolver 0.26.3`（默认特性：`system-config` + `tokio`）、`arc-swap 1.9`、`tokio`、`getrandom`；`pingora` 追加特性 `connection_filter`（WP-E1a 添加） | 只有 mg-edge 依赖 Pingora |

版本全部在 crates.io 核对过（2026-09-27），并已按 `rust-version = 1.88` 解析锁定（resolver v3）。`reqwest` 的 `rustls` 特性带 aws-lc-rs：构建需要 cmake 与 C 编译器（BoringSSL 已经需要），CI 的 `rust` 作业因此多编译一个密码库（冷缓存约多 2–4 分钟，仍在 45 分钟预算内）。reqwest 0.13 无论特性如何都会读取 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`（`default-features = false` 只去掉平台代理查询），所以"不读代理环境变量"靠代码中的 `no_proxy()` 保证，并有测试（§9.10）。

### 1.3 Go 包

| 包 | 作用 | WP |
|---|---|---|
| `internal/policy` | 策略解析、类型检查、CEL → IR、静态步数上界、参考求值器 | WP-G1 |
| `internal/cli` | 子命令契约（已落地） | WP-G2 维护 |
| `internal/mgctl` | 命令分发 | WP-G2 |
| `internal/sitecfg` | 站点 YAML v1 解析与校验 | WP-G2 |
| `internal/keys` | 所有者签名密钥（age）、站点密钥、假名化密钥、上游密钥头、密钥导出、verdict 键计算 | WP-G2 |
| `internal/bundle` | 配置包构建、签名、校验、发布、golden 夹具生成器 | WP-G2 |
| `internal/audit` | 本地追加哈希链审计日志 | WP-G2 |
| `internal/cfapi` | Cloudflare API 只读客户端 | WP-G3 |
| `internal/cfaudit` | `mgctl cf audit` 检查 | WP-G3 |
| `internal/intelsync` | `cf ips sync`、`crawler sync`、工件写出与校验 | WP-G3 |

### 1.4 Edge 请求处理顺序

```
request_filter
  0  request_id (32 lower-hex from the OS CSPRNG; RNG failure -> 503), now_ms
  1  listener: peer / client cert / secret header           fail -> 403 or TLS close          (§9.2)
  2  protocol limits: path / query (414), header value / name / count (431), method (400)      (§9.3.1)
     header hygiene: drop Connection-listed headers, strip families, parse trusted headers      (§9.3)
  3  Host (= :authority = absolute-form authority, else 400) -> site; listener allowed?
     unknown host -> 404; site state closed / lkg_invalid -> 503; foreign CF-Worker -> 403     (§9.4)
  4  /__mg/* ?  -> healthz | s/{file} | c | reserved 404    (never reaches the origin)           (§10)
  5  environment by host; route: every path view, most sensitive match wins                    (§9.4)
  6  RequestContext: upstream, net (+GeoLite2), http, edge_tls, tls                             (§9.5)
  7  identity: clearance cookie (mg-challenge), crawler claim (mg-intel, rDNS async)             (§9.6)
  8  state: ONE round trip = MGET verdicts + EVALSHA mg_gcra (global limiters); local limiters   (§9.7, §9.8)
  9  Decision Core: detectors -> ScorerV1 -> BotClass -> rules + limiter outcomes + matrix       (§5.4, §5.5)
 10  bootstrap-open / monitor_only -> dry_run, forward; enforce: ALLOW/TAG/LOG forward |
     CHALLENGE 403 (client IP unknown -> 429; http visitor GET/HEAD -> 308) | RATE_LIMIT 429 | BLOCK 403  (§9.9)
upstream_request_filter: Host = resolved host; strip MG-* / x-mg-* / upstream families; add MG-*; XFF single value
response_filter: strip MG-* from origin responses
logging: DecisionEvent + access record -> EventSink; XADD summary; metrics                      (§9.11, §13)
```

## 2. 工作包与文件所有权

### 2.1 阶段、依赖与修复规则

```
stage 1 (parallel):   R1  R2  R3  |  C1  C2  C3  C4  |  G1  G2  G3  |  W1
                                         \ all merged /
stage 2 (sequential): E1a ──> E1b ──> E1c ──> E1d          (edge/, deploy/systemd, Makefile, CI)
                                         \ E1d merged /
stage 3 (parallel):   L1 (lab/, scripts/lab-e2e.sh)   J1 (edge/src/tls/, ADR-0002)   D1 (docs/)
```

- **阶段 1**：WP 之间没有编译期依赖，每个 WP 只用本文与 §0.4 的已落地文件。WP-C* 只依赖 `mg-core` 中已落地的部分（`gcra`、`paths`、`context` 与 `decision` 的现有类型）和 `mg-proto` 的生成类型，不依赖 WP-R1 新增的 API；WP-G2 只用 `policy` 包现有的公共 API（`NewCompiler`、`Check`、`CheckedRule.Proto()`、`CheckedRule.Lists`），WP-G1 让 `Proto()` 填上 IR 后，WP-G2 的代码不需要改。
- **阶段 2**：阶段 1 全部合入后开始。E1a → E1b → E1c → E1d 依次合入，每个都是一个可评审的 PR，合入时 `make check` 全绿；后一个以前一个合入后的主干为基（可以提前在分支上准备）。同一时间只有一个 E1 子 WP 在改 `edge/`。
- **阶段 3**：E1d 合入后开始。
- **跨 WP 测试耦合**只有两处，规则相同：所需夹具不存在时测试打印 `SKIPPED: <why>` 并通过；两边都合入后必须全绿；**后合入的 PR** 负责在合入前让 `make check` 变绿。
  1. 策略 IR 一致性套件：WP-G1 产出 `testdata/policy-ir/`，WP-R1 的 Rust 测试读取。
  2. `control-plane/testdata/sites/golden/golden-rules.bundle`：由 WP-G2 的生成器（`go test ./internal/bundle -run TestGolden -update`）产生，需要 WP-G1 的 IR。WP-G1 与 WP-G2 中后合入者运行生成器并提交该文件；这是 §2.2 所有权的唯一例外（生成文件，同生成代码）。
  其余共享夹具（`testdata/phase1/`、`core/testdata/gcra-cases.json`）已落地，不存在先后问题。
- **分歧**：先按本文判定哪一边偏离规范，由偏离的一方修复；本文本身有歧义时由集成者先改本文。
- **合入后的修复**：WP 合入后，它的文件由原 WP 负责人（不在时由集成者）以小的修复 PR 维护。其他 WP 发现缺陷时，在自己的 PR 中加一个复现测试并标记为跳过（Rust `#[ignore = "blocked on <WP>: <issue>"]`，Go `t.Skip`，TS `it.skip`），通知负责人，不直接改别人的文件；修复 PR 合入时去掉跳过标记。阶段 3 中 `edge/` 的缺陷（WP-L1 发现的）由 WP-E1d 的负责人修；WP-J1 只改 §2.2 列给它的文件，需要在其他 `edge/` 文件接入时与 E1d 负责人协调。

### 2.2 文件所有权矩阵

一个路径只有一个所有者 WP；其他 WP 只读。"只读契约"文件的修改先改本文，再由表中所有者（或集成者）提交。

| 路径 | 所有者 | 说明 |
|---|---|---|
| `core/**` | WP-R1 | 含已落地的 `src/paths.rs`、`src/gcra.rs`、`testdata/gcra-cases.json`：语义为只读契约 |
| `proto/rust/src/ir.rs`、`proto/rust/tests/policy_ir_conformance.rs`（新）、`proto/rust/tests/roundtrip.rs` | WP-R1 | |
| `proto/morphgate/v1/decision.proto` 及其生成文件 `control-plane/gen/morphgate/v1/decision.pb.go` | WP-R1 | 改动见 §3.4；改后运行 `make proto`，只提交 `decision.pb.go` 的变化 |
| `proto/morphgate/v1/{policy_ir,config,challenge,common}.proto` | 只读契约 | |
| `challenge/**` | WP-R2 | |
| `intel/**` | WP-R3 | 含 `intel/testdata/`（测试用 mmdb 与生成器） |
| `testdata/phase1/**` | 只读契约 | WP-R2、R3、C*、G2、G3、W1、E1 读取 |
| `edge-core/src/upstream.rs`、`edge-core/src/upstream/**`、`edge-core/src/request.rs`、`edge-core/src/request/**`、`edge-core/tests/upstream_*.rs`、`edge-core/tests/request_*.rs` | WP-C1 | |
| `edge-core/src/bundle.rs`、`edge-core/src/bundle/**`、`edge-core/src/testkit/http.rs`、`edge-core/tests/bundle_*.rs` | WP-C2 | |
| `edge-core/src/state.rs`、`edge-core/src/state/**`（含 `lua/*.lua`）、`edge-core/src/testkit/valkey.rs`、`edge-core/tests/state_*.rs` | WP-C3 | |
| `edge-core/src/events.rs`、`edge-core/src/events/**`、`edge-core/src/testkit/vl.rs`、`edge-core/tests/events_*.rs` | WP-C4 | |
| `edge-core/Cargo.toml`、`edge-core/src/lib.rs`、`edge-core/src/testkit.rs` | 集成者（已落地） | WP-C* 只按 §2.3 在 `Cargo.toml` 追加依赖行 |
| `control-plane/internal/policy/**`、`control-plane/testdata/policies/**`、`testdata/policy-ir/**` | WP-G1 | |
| `control-plane/internal/{mgctl,cli,sitecfg,keys,bundle,audit}/**`、`control-plane/go.mod`、`control-plane/go.sum`、`go.work.sum`、`control-plane/testdata/sites/**`、`control-plane/README.md` | WP-G2 | `cli` 只可追加字段；`golden-rules.bundle` 见 §2.1；README 写全 §14.1 的所有命令（含 G1 / G3 的，按本文描述） |
| `control-plane/internal/{cfapi,cfaudit,intelsync}/**`、`control-plane/testdata/cloudflare/**`、`control-plane/testdata/intel/**`、`deploy/intel/**`、`adapters/**` | WP-G3 | 不需要新的 Go 依赖（只用标准库） |
| `sdk/web/**` | WP-W1 | |
| `edge/**`、`deploy/systemd/**`、`scripts/edge-smoke.sh`、根 `Cargo.toml`、`Cargo.lock`、`Makefile`、`.github/workflows/ci.yml`、`deploy/compose/**` | WP-E1a → E1b → E1c → E1d（依次） | 阶段 2 |
| `lab/**`、`scripts/lab-e2e.sh`（新） | WP-L1 | 阶段 3；可在 `Makefile` 与 `ci.yml` 中追加 `lab-e2e` 目标与作业 |
| `edge/src/tls/**`（新）、`edge/tests/ja4_spike.rs`（新）、`direct_tls` 监听器的 `ja4_spike` 配置项与 `EdgeTlsAccept` 的扩展（§9.2）、`docs/adr/0002-edge-pingora-boringssl.md` | WP-J1 | 阶段 3；WP-L1 与 WP-D1 不改 `edge/` |
| `docs/**`（除 `docs/impl/` 与 ADR-0002）、`README.md`、`CLAUDE.md` | WP-D1 | 阶段 3 |
| `docs/impl/phase1-spec.md` | 集成者 | 契约变更先改这里 |

### 2.3 共享文件规则

- **`Cargo.lock`**：阶段 1 的 Rust WP（R*、C*）只使用已在根 `[workspace.dependencies]` 声明且已被本提交锁定的依赖。已预先批准的开发依赖：`mg-proto` 的 `base64`（已加入）；`mg-edge-core` 的测试直接用 `tokio`（已是普通依赖）与自身的 `testkit` 特性。WP-R3 测试 `async fn` 时用 `std::task::Waker::noop()`（Rust 1.85 起稳定）驱动立即就绪的 future，不引入执行器。确需新增依赖时，只追加根 `Cargo.toml` 中本 WP 的那一段与本 crate 的 `Cargo.toml`，并在 PR 中说明；两个 PR 的 `Cargo.lock` 冲突时，取任一边后运行 `cargo check --workspace` 重新生成，不手改。
- **`go.mod` / `go.sum`**：只有 WP-G2 改动（`filippo.io/age`、`golang.org/x/term`、`github.com/oschwald/maxminddb-golang/v2`）。WP-G1、WP-G3 只用已有依赖与标准库。
- **生成代码**：proto 只在所有者 WP 中改，改后 `make proto`；CI 的漂移检查保证 Go 生成代码与 proto 一致。
- **`testdata/phase1/**`**：只读。实现与样例不一致时，先确认本文的公式与格式，不改样例。
- **README**：`control-plane/README.md` 归 WP-G2（见 §2.2）；`sdk/web/README.md` 归 WP-W1；`lab/README.md` 归 WP-L1；`edge-core` 与 `edge` 用 crate 文档注释，没有 README；根 README 与 CLAUDE.md 由 WP-D1 统一改。

### 2.4 通用完成定义

每个 WP 合入前必须满足：

1. `make check` 全绿（本地没有 wasm 目标时 `wasm-check` 跳过，CI 必跑）。
2. 新代码有单元测试；本文列出的每个"测试"条目都有对应测试，测试名或注释引用本文章节号。
3. 所有解析器（头、Cookie、C、提交体、配置包、工件、密钥文件、IR）有"确定性随机输入不 panic"测试：固定种子的 xorshift 生成 ≥ 10,000 个输入，断言返回错误而不是 panic。
4. 不出现 `todo!()`、`unimplemented!()`、`panic!` 用于可恢复错误；Rust 公共类型实现 `Debug`，但不打印密钥、nonce、凭证原文。
5. 日志（任何级别）与 `Debug` 输出不含客户端 IP 明文、Cookie、C、凭证、密钥、上游密钥头值与 `x-mg-cf-tls-random`（D-31）。
6. 生产路径上的随机数（C 的 `xnonce` 与 `nonce`、凭证的 `sub` 与 `jti`、`request_id`、CSP nonce、轮询抖动）来自 OS CSPRNG（`getrandom`）；确定性 RNG 只出现在 `#[cfg(test)]` 与 `testkit` 中。
7. 不在任何出站请求中放入所有者的个人信息；出站 User-Agent 为 `mgctl/<version>` 或 `mg-edge/<version>`（开发工具抓取资料时用 `morphgate-dev-tooling`）。
8. 该 WP 改动过的 README / 注释与行为一致；不改他人拥有的文件（§2.1 的修复规则）。

## 3. 数据模型改动

### 3.1 `policy_ir.proto`（已落地，最终定义）

```proto
message PolicyExpr {
  uint32 ir_version = 1;       // 1
  Expr root = 2;               // must evaluate to bool
  repeated string fields = 3;  // sorted unique field paths the expression reads or has()-tests (informational)
  uint64 max_steps = 4;        // static worst-case evaluation steps (§5.3); compiler and Edge must agree, <= 100000
}

message Expr {
  oneof kind {
    Literal literal = 1;
    string field = 2;          // schema field by dotted CEL path: "net.ip", "req.headers", "rate", "labels"
    string has = 3;            // has(<path>): false iff MISSING; never UNKNOWN / ERROR
    ListLiteral list = 4;
    Unary not = 5;
    Nary and = 6;              // >= 2 args
    Nary or = 7;               // >= 2 args
    Cond cond = 8;
    Compare compare = 9;
    Binary in_list = 10;       // lhs in rhs(list)
    Binary in_map = 11;        // lhs(string) in rhs(map): key presence
    Binary index_map = 12;     // lhs(map)[rhs(string)]; absent key -> ERROR
    Unary size = 13;           // size(string | list | map)
    StringCall string_call = 14;
    Binary ip_in = 15;         // ip_in(lhs string, rhs list(string))
    string named_list = 16;    // list("<name>")
    Glob glob = 17;            // glob(subject, "<literal pattern>")
  }
}

message Literal { oneof value { bool bool_value = 1; int64 int_value = 2; double double_value = 3; string string_value = 4; } }
message ListLiteral { repeated Expr elements = 1; }
message Unary { Expr arg = 1; }
message Binary { Expr lhs = 1; Expr rhs = 2; }
message Nary { repeated Expr args = 1; }
message Cond { Expr cond = 1; Expr then_expr = 2; Expr else_expr = 3; }
enum CompareOp { COMPARE_OP_UNSPECIFIED = 0; COMPARE_OP_EQ = 1; COMPARE_OP_NE = 2;
                 COMPARE_OP_LT = 3; COMPARE_OP_LE = 4; COMPARE_OP_GT = 5; COMPARE_OP_GE = 6; }
message Compare { CompareOp op = 1; Expr lhs = 2; Expr rhs = 3; }
enum StringFunction { STRING_FUNCTION_UNSPECIFIED = 0; STRING_FUNCTION_STARTS_WITH = 1;
                      STRING_FUNCTION_ENDS_WITH = 2; STRING_FUNCTION_CONTAINS = 3; }
message StringCall { StringFunction function = 1; Expr target = 2; Expr arg = 3; }
message Glob { Expr subject = 1; string pattern = 2; }
```

`CompiledRule.expr_ir` = `PolicyExpr` 的序列化字节（Go：`proto.MarshalOptions{Deterministic: true}`），`CompiledRule.ir_version = 1`。IR 不含表达式 id、源码位置或类型：同一个已检查表达式总得到同一串字节。`max_steps` 是规范字段（§5.3 静态步数上界）：编译器写入，Edge 加载时复算并比较，不相等或超过 100,000 时拒绝该规则（从而拒绝整个配置包）。

### 3.2 `config.proto` 的 Phase 1 schema（已落地）

在 Phase 0 消息上只做了追加（字段号不复用、不改语义）。新增字段与消息：

| 消息 | 新增 | 说明 |
|---|---|---|
| `UpstreamProfile` | — | Phase 1 只用 `kind` 与 `expected_mask`；字段 2–7 留给后续 profile，构建器必须留空 |
| `Route` | `paths = 9`（repeated glob）、`require_clearance = 10`、`redact_path = 11` | `path_glob` 弃用：构建器只写 `paths`，Edge 把非空的 `path_glob` 当作 `paths` 的一项；`redact_path` 见 D-31 |
| `CompiledRule` | — | `params` 在 Phase 1 只允许 `type`、`label`、`limiter`、`retry_after_s` |
| `RateLimit` | `route_ids = 10`、`scope = 11`、`retry_after_s = 12`、`challenge_type = 13`、`signal_weight = 14` | `route_id` 弃用 |
| `Environment` | `hosts = 6` | |
| `ArtifactRef` | `size = 5` | |
| `SiteBundle` | `schema_version = 11`、`hosts = 12`、`allowed_listeners = 13`、`challenge = 14`、`clearance = 15`、`scoring = 16`、`crawler_policy = 17`、`events = 18`、`lists = 19`、`cloudflare = 20`、`origin_headers = 21`、`share_ip_verdicts = 22`、`source_digest = 23`、`case_insensitive_paths = 24` | `case_insensitive_paths` 见 D-25 |
| 新消息 | `ChallengeConfig`（含 `PowBits`）、`ClearanceConfig`、`ScoringConfig`、`CrawlerPolicy`、`EventConfig`、`NamedList`、`CloudflareSiteConfig`、`OriginHeaderConfig` | 字段见 `proto/morphgate/v1/config.proto`；默认值见 §8.3 |
| `SignedBundle` | — | 签名输入固定为 `"mg-bundle-v1" ‖ 0x00 ‖ bundle` |

### 3.3 `challenge.proto`（已落地）

`SealedChallengeClaims.Bind` 新增 `optional bytes ipa = 6;`（D-05）。`mg_core::ChallengeBind` 已新增 `ipa: Option<Vec<u8>>`，`proto/rust/tests/roundtrip.rs` 的逐字段映射已更新。

### 3.4 `decision.proto` 改动（WP-R1 负责）

WP-R1 在同一个 PR 里改 `decision.proto`、`mg-core` 原生类型与 `roundtrip.rs` 的完整性测试（JSON 字段名必须与 proto 一致），然后运行 `make proto`：

```proto
message Identity {
  message Crawler {
    // ...fields 1-6 unchanged...
    string verification = 7;  // none | pending | verified | failed | unverifiable
    string method = 8;        // ip_range | rdns | "" (how the verified / failed result was reached)
    bool outside_ranges = 9;  // pending only: the operator publishes ranges and the IP is not in them (D-18)
  }
}

message Decision {
  // ...fields 1-7 unchanged...
  repeated string tags = 8;   // labels added by TAG rules, forwarded as MG-Tags
}

// One policy rule (or rate limiter) that matched, or could not be evaluated, on this request.
message RuleHit {
  string rule_id = 1;         // CompiledRule.id, or "ratelimit.<limiter id>"
  string outcome = 2;         // matched | missing_input | eval_error
  string mode = 3;            // enforce | dry_run
  Action action = 4;          // the rule's (would-be) action
  repeated string fields = 5; // missing_input: MISSING field paths read; eval_error: [error kind]
}

message DecisionEvent {
  // ...fields 1-9 unchanged...
  repeated RuleHit hits = 10; // at most 16, in evaluation order
}
```

同时：`Identity.Token.Bind.ipp` 的取值扩展为 `match | soft_mismatch | mismatch`（字符串，只需更新 proto 注释）；对应的 `mg_core::BindResult::SoftMismatch`（`soft_mismatch`）已在本提交中加入，供 WP-R2 并行使用。

### 3.5 `mg-core` 原生类型改动汇总（WP-R1）

| 类型 | 改动 |
|---|---|
| `context::Crawler` | 加 `verification: Option<CrawlerVerification>`（wire：`none`/`pending`/`verified`/`failed`/`unverifiable`）、`method: Option<CrawlerMethod>`（`ip_range`/`rdns`）、`outside_ranges: bool`（JSON 省略 false） |
| `context::BindResult` | `SoftMismatch` 已落地（§0.4） |
| `context::Net` | `entity_of` 已落地（§0.4，D-24） |
| `decision::Decision` | 加 `tags: Vec<String>`（JSON 省略空列表）；`Decision::validate` 增加：`tags` 非空时 `action ∈ {Tag}`，每个标签匹配 `[a-z0-9_.-]{1,32}`，至多 8 个 |
| `decision::DecisionEvent` | 加 `hits: Vec<RuleHit>` |
| `pipeline` | trait 签名按 §5.6 改（`Detector::detect`、`Scorer::score`、`PolicyEvaluator::evaluate` 都接收 `RequestExtras`） |

## 4. 策略字段模式与 MISSING 语义

### 4.1 字段表

策略可读的字段是固定的模式（Go `internal/policy/context.go` 的 `Input` 与 Rust `mg_core::policy::Activation` 必须完全一致）。表中"Edge 来源"是 WP-E1b 构建 Activation 的规范；"MISSING 条件"是 WP-E1b 构建 `MissingSet` 的规范（§4.3）。

| 路径 | 类型 | Edge 来源（ABSENT 时的零值） | MISSING 条件（Phase 1） |
|---|---|---|---|
| `req.method` | string | 请求方法（大写） | 从不 |
| `req.host` | string | Host（小写、去端口、去末尾点） | 从不 |
| `req.path` | string | 原始路径（不含查询串，不解码） | 从不 |
| `req.query` | string | 原始查询串（不含 `?`） | 从不 |
| `req.headers` | map(string, string) | 头部清洗（§9.3）后的客户端头；名称小写；重复头以 `", "` 连接；排除 `cookie`、`authorization`、`proxy-authorization`；§9.3.1 保证至多 128 项、键 ≤ 256 字节、值 ≤ 8 KiB（连接后仍超过 8 KiB 的请求被 431 拒绝） | 从不 |
| `req.channel` | string | 路由的 channel：`web`/`api`/`mobile` | 从不 |
| `net.ip` | string | 客户端 IP（完整地址；IPv6 用 RFC 5952 文本） | 客户端 IP 未知（认证通过但缺 `CF-Connecting-IP` 或值非法；外部 zone 的 `CF-Worker` 已在 §9.4 被 403，不会到这里） |
| `net.asn` | int | GeoLite2 ASN；库中查不到为 0（ABSENT）。0 只是策略里的零值：`ipa` 绑定、`asn` 限速维度与签发配额把 0 当作"未知"（§6.4、§9.7） | 没有 `geoip-asn` 工件，或 `net.ip` MISSING |
| `net.country` | string | GeoLite2 国家（ISO alpha-2）；查不到为 `""` | 没有 `geoip-country` 工件，或 `net.ip` MISSING |
| `net.conn_type` | string | ASN ∈ `datacenter-asns` → `datacenter`，否则 `unknown` | 没有 `datacenter-asns` 工件，或 `net.asn` MISSING |
| `net.tor` | bool | IP ∈ `tor-exits`，或（`cloudflare` 且信任 location 头且 `cf-ipcountry = T1`） | 两个来源都没有 |
| `upstream.profile` / `authenticated` / `auth_method` | string / bool / string | 监听器 | 从不 |
| `tls.ja4.value` / `source` / `authenticated` | string / string / bool | —（Phase 1 无） | 总是（`cloudflare` 因为 profile；`direct_tls` 因为 D-07） |
| `tls.version` | string | `direct_tls` 协商的版本（`TLSv1.2` / `TLSv1.3`） | `cloudflare` |
| `http.version` | string | `direct_tls`：`HTTP/1.1` / `HTTP/2`；`cloudflare`：`x-mg-cf-http-version` | `cloudflare` 且该头缺失或非法 |
| `http.header_order` | list(string) | `direct_tls` 且 HTTP/1.x：**不重复的头名，按首次出现的顺序**，保留原大小写，至多 128 项（Pingora 的头表把重复名归到首次出现处，交错的重复头顺序无法还原；检测器与策略不得依赖它） | `cloudflare`；`direct_tls` 的 HTTP/2 |
| `edge_tls.version` / `cipher` / `ciphers_sha1` / `ext_sha1` | string | 对应 `x-mg-cf-tls-*` | `direct_tls`；`cloudflare` 下对应头缺失或非法（逐字段） |
| `edge_tls.hello_len` | int | `x-mg-cf-tls-hello-len` | 同上 |
| `identity.token.level` | string | 有效凭证的 `lvl`，否则 `""` | 从不 |
| `identity.token.age` | int | 有效凭证自 `iat` 起的秒数，否则 0 | 从不 |
| `identity.proof.valid` | bool | — | 总是（Phase 1，D-07） |
| `identity.agent.id` / `grant_id` | string | — | 总是（Phase 1，D-07） |
| `identity.crawler.claimed` / `operator` / `purpose` / `verified` | bool / string / string / bool | 爬虫验证结果（§9.6）；未声明时为零值 | 没有 `crawler-registry` 工件 |
| `identity.crawler.cf_vbot` | bool | `x-mg-cf-vbot` | `direct_tls`；`cloudflare` 下头缺失或非法 |
| `identity.crawler.cf_vbot_cat` | string | `x-mg-cf-vbot-cat`；缺失为 `""` | 与 `cf_vbot` 相同（`cf_vbot` 可得时类别缺失是 ABSENT） |
| `risk.score` | int | `RiskAssessment.score` | 从不 |
| `risk.confidence` | double | `RiskAssessment.confidence` | 从不 |
| `risk.class` | string | `BotClass` 的**大写**名，如 `IMPERSONATOR`（事件 JSON 里是小写 wire 名） | 从不 |
| `risk.reasons` | list(string) | `RiskAssessment.top_reasons` | 从不 |
| `route.name` / `sensitivity` / `env` | string | 匹配到的路由；`sensitivity` 为 `low`/`medium`/`high`/`critical` | 从不 |
| `rate` | map(string, double) | 对本请求生效的每个限速器 id → 利用率 `[0, 1]`（§9.8） | 从不（某限速器没跑就没有这个键） |
| `labels` | list(string) | `RiskAssessment.labels` ∪ 生效 verdict 的 labels（去重、排序） | 从不 |

Go `Input` 需要新增 `identity.crawler.claimed`，并给所有字段加上与 `cel` 标签同名的 `json` 标签（WP-G1）；`http.header_order` 的字段注释写明上表的"不重复、首次出现顺序"语义（Rust `Activation` 同样）。

**大小上限**（规范；Go `env.go` 的 `sizeHints` 与 Rust 的静态步数上界都按这张表，WP-G1 让 `sizeHints` 与之完全一致）：

| 路径 | 上限 | 由谁保证 |
|---|---|---|
| `req.path`、`req.query` | 8192 字节 | §9.3.1：超出 → 414 |
| `req.method` | 32 字节 | §9.3.1：超出 → 400 |
| `req.host` | 253 字节 | §9.4 |
| `req.headers` | 128 项；键 ≤ 256 字节；值 ≤ 8192 字节 | §9.3.1：超出 → 431 |
| `http.header_order` | 128 项，每项 ≤ 256 字节 | 构建时截断 |
| `labels` | 64 项 | 构建时截断（排序后取前 64） |
| `risk.reasons` | 32 项（实际 ≤ 5） | 评分器 |
| `rate` | 64 项 | 配置包校验：每个环境至多 64 个限速器 |
| `tls.ja4.value` | 36 字节 | Phase 1 恒 MISSING |
| `edge_tls.ciphers_sha1`、`edge_tls.ext_sha1` | 40 字节 | §9.3 解析校验 |
| 命名列表（`list("x")`） | 10,000 项，每项 ≤ 256 字节 | 配置包校验（§8.2） |
| 其他字符串 | 256 字节 | 各自的解析校验（§9.3、§9.5） |
| 其他列表 / map | 64 项 | 同上 |

### 4.2 Activation JSON

一致性夹具（§5.8）用同一个 JSON 对象描述请求上下文。它就是 Go `Input` 与 Rust `Activation` 的 serde 形式：键名等于 CEL 名，省略的键取零值。

```json
{
  "req": {"method": "GET", "host": "example.com", "path": "/account/login", "query": "next=%2F",
          "headers": {"accept": "text/html", "user-agent": "Mozilla/5.0 ..."}, "channel": "web"},
  "net": {"ip": "203.0.113.7", "asn": 64500, "country": "HK", "conn_type": "unknown", "tor": false},
  "upstream": {"profile": "cloudflare", "authenticated": true, "auth_method": "loopback"},
  "tls": {"ja4": {"value": "", "source": "", "authenticated": false}, "version": ""},
  "http": {"version": "HTTP/2", "header_order": []},
  "edge_tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "ciphers_sha1": "", "ext_sha1": "", "hello_len": 512},
  "identity": {"token": {"level": "invisible", "age": 120}, "proof": {"valid": false},
               "agent": {"id": "", "grant_id": ""},
               "crawler": {"claimed": false, "operator": "", "purpose": "", "verified": false, "cf_vbot": false, "cf_vbot_cat": ""}},
  "risk": {"score": 12, "confidence": 0.6, "class": "HUMAN_LIKELY", "reasons": []},
  "route": {"name": "login", "sensitivity": "critical", "env": "production"},
  "rate": {"login-per-ip": 0.2},
  "labels": []
}
```

### 4.3 MissingSet

- 一个请求的 MISSING 状态用"路径集合"表示：元素是模式中的路径（命名空间、结构体字段或叶字段），例如 `tls`、`http.header_order`、`edge_tls.hello_len`、`identity.proof`。
- 路径 `p` 被视为 MISSING，当且仅当集合中存在 `m` 使 `p == m` 或 `p` 以 `m + "."` 开头。读取 MISSING 的字段得到 UNKNOWN；`has(p)` 为 false。
- 集合中的每个元素必须是模式路径（或其前缀）；`MissingSet::new` 校验并对非法路径返回 `UnknownField`（在 Edge 中这是编程错误，测试覆盖）。
- WP-E1b 按 §4.1 的"MISSING 条件"列逐请求构建；Phase 1 常量部分（按 profile）可以预先计算。

### 4.4 编译期可用性检查（WP-G1 更新 `availability.go`）

| profile | 恒为 MISSING 的前缀（未用 `has()` 守卫时告警） |
|---|---|
| `cloudflare` | `tls`、`http.header_order`、`identity.proof`（"arrives in Phase 2"）、`identity.agent`（"arrives in Phase 3"） |
| `direct_tls` | `edge_tls`、`identity.crawler.cf_vbot`、`identity.crawler.cf_vbot_cat`、`tls.ja4`（"JA4 is a Phase 1 spike only"）、`identity.proof`、`identity.agent` |

`checkCorroboration`（仅凭 Cloudflare verified-bot 放行或阻断时告警）不变。

## 5. 策略 IR、求值语义与规则引擎

### 5.1 CEL → IR 映射（WP-G1）

降级在 cel-go 类型检查之后进行，依据已检查 AST 的调用函数名与 overload id（`checker` 的 reference map）。

| CEL | cel-go 函数 / overload | IR |
|---|---|---|
| `true`、`42`、`-1`、`0.5`、`"s"` | 字面量（负数字面量由解析器给出） | `literal` |
| `a.b.c`（根为命名空间的结构体字段选择链） | Select 链 | `field: "a.b.c"` |
| `rate`、`labels`、`req.headers`（map / list 类型的命名空间或字段） | Ident / Select | `field` |
| `req.headers.accept`（对 map 类型字段再做选择） | Select on map | `index_map(field "req.headers", literal "accept")` |
| `has(a.b.c)` | Select（test-only） | `has: "a.b.c"` |
| `[x, y]` | List | `list`：元素必须是同一种标量类型（bool、int、double、string）的表达式 |
| `!x` | `logical_not` | `not` |
| `x && y && z` | `_&&_` | `and`：把直接嵌套的 `&&` 展平成一个 `Nary`，保持从左到右的顺序 |
| `x \|\| y` | `_\|\|_` | `or`：同上展平 |
| `c ? a : b` | `_?_:_` | `cond` |
| `==` / `!=` | `equals` / `not_equals` | `compare EQ / NE`；两侧必须是同一种标量类型（bool、int、double、string） |
| `<` `<=` `>` `>=` | `less_int64`、`less_double`、`less_string`、`less_equals_*`、`greater_*`、`greater_equals_*` | `compare LT/LE/GT/GE`；只允许 int、double、string |
| `x in l` | `in_list` | `in_list` |
| `k in m` | `in_map` | `in_map` |
| `m[k]` | `index_map` | `index_map` |
| `size(x)`、`x.size()` | `size_string`、`size_list`、`size_map`、`string_size`、`list_size`、`map_size` | `size` |
| `s.startsWith(t)`、`s.endsWith(t)`、`s.contains(t)` | `starts_with_string`、`ends_with_string`、`contains_string` | `string_call` |
| `ip_in(ip, l)` | `ip_in_string_list_string` | `ip_in` |
| `list("name")` | `list_string`（参数必须是字符串字面量） | `named_list: "name"` |
| `glob(s, "p")` | `glob_string_string`（模式必须是非空字面量） | `glob` |

cel-go 环境保持 `CrossTypeNumericComparisons(false)`（默认值），因此 `1 < 1.5`、`1 == 1.0` 在类型检查时就被拒绝；另外**必须**加 `cel.HomogeneousAggregateLiterals()`。已用 cel-go v0.30.0（本仓库的版本）实测：没有这个选项时，`[1.0, "a"]` 的类型是 `list(dyn)`，`1 in [1.0, "a"]` 通过类型检查且求值为 `true`（cel-go 对异构元素用数值相等），`[1, 2.0]` 也能编译，而 §5.3 的 `in_list` 是"同类型且相等"，两边会不一致；加上后这些表达式在类型检查时报错。`walk()` 另外拒绝元素不是标量的列表字面量（如 `[[1]]`）与左侧不是标量的 `in`（§5.2）。这样 IR 中既没有跨类型数值比较，也没有异构列表。

### 5.2 拒绝的构造

`mgctl policy check` 与 `compile` 对下列构造报错（错误级，规则不进配置包），消息格式 `unsupported in policy IR: <what>`：

算术（`+ - * / %`、非字面量的一元负号）、字符串拼接、`matches`、宏与推导式（`all`、`exists`、`exists_one`、`map`、`filter`）、类型转换与类型函数（`int`、`uint`、`double`、`string`、`bytes`、`dyn`、`type`）、`timestamp` / `duration`、`uint` / `bytes` / `null` 字面量、map 字面量与消息字面量、列表下标 `l[i]`、bool 的大小比较、列表或 map 的相等比较、元素类型不一致或不是标量的列表字面量（`[1, "a"]`、`[1, 2.0]`、`[[1]]`；前两种由 `HomogeneousAggregateLiterals` 在类型检查时拒绝）、左侧不是标量的 `in`、把结构体字段整体当值（如 `tls.ja4 == x`）、对 map 键用 `has()`（提示改用 `"k" in m`）、可选语法。

另一类编译错误是代价：静态步数上界（§5.3）超过 100,000 的规则报 `rule exceeds the evaluation step bound: <n> > 100000`（ADR-0006 决策 8）。cel-go 自己的代价估算（`Options.MaxCost`，现有代码）保留，但它只是附加检查，规范以步数上界为准。

### 5.3 求值语义（规范）

**值**：`Bool`、`Int`（i64）、`Double`（f64）、`String`、`List`、`Map`（键为 string）。每个节点的结果是一个值、`Unknown(paths)` 或 `Error(kind)`。

| 节点 | 语义 |
|---|---|
| `literal` | 值 |
| `field p` | `p` 为 MISSING → `Unknown({p})`；否则 Activation 中的值（ABSENT 字段为零值） |
| `has p` | `Bool(!missing(p))`；从不 UNKNOWN / ERROR |
| `and(a1..an)` | 从左到右求值全部参数。任一为 `false` → `false`；否则任一为 UNKNOWN → `Unknown(所有 UNKNOWN 参数路径的并集)`；否则任一为 ERROR 或非 bool → 第一个这样的参数的 ERROR（非 bool 为 `no_such_overload`）；否则 `true`。实现可以在遇到 `false` 时短路（结果不变） |
| `or(a1..an)` | 与 `and` 对称：任一 `true` → `true`；否则 UNKNOWN 优先于 ERROR；否则 `false` |
| `cond(c, t, e)` | 先求 `c`：`true` → 求 `t`；`false` → 求 `e`；UNKNOWN → 该 UNKNOWN（不求分支）；ERROR 或非 bool → ERROR |
| **严格节点**：`not`、`compare`、`in_list`、`in_map`、`index_map`、`size`、`string_call`、`ip_in`、`glob`、`list` | 从左到右求值全部子节点；任一为 ERROR → 按子节点顺序的第一个 ERROR；否则任一为 UNKNOWN → 并集 UNKNOWN；否则执行运算，类型不符 → `Error(no_such_overload)` |
| `not x` | `Bool b` → `!b` |
| `compare` | 两侧同类型：`Bool`（仅 EQ/NE）、`Int`、`Double`（IEEE：NaN 的比较全为 false，NE 为 true）、`String`（按 Unicode 标量值序，等价于 UTF-8 字节序） |
| `in_list x l` | `l` 为 List；存在与 `x` **同类型且相等**的元素 → `true`；类型不同的元素视为不相等，不报错（编译器保证列表字面量同类型、`list()` 与字段列表都是字符串，所以与 cel-go 的结果一致） |
| `in_map k m` | `m` 为 Map、`k` 为 String → 键存在 |
| `index_map m k` | `m` 为 Map、`k` 为 String；键不存在 → `Error(no_such_key)` |
| `size x` | String → Unicode 标量值个数；List / Map → 元素个数 |
| `string_call` | 两侧 String；`startsWith` / `endsWith` / `contains` 按 Unicode 标量序列比较 |
| `ip_in ip l` | `ip` 为 String、`l` 为 String 列表。`ip` 不是合法 IP（不带 zone 的 IPv4 点分或 IPv6）→ `false`。**逐项校验全部条目**：条目是 IP 或 CIDR；IPv4 映射的 IPv6 CIDR（`::ffff:a.b.c.d/n`，`n ≥ 96`）规范化为 IPv4 `/n-96`；带 zone 或无法解析 → `Error(invalid_argument)`（即使前面的条目已匹配）。IPv4 映射的 IPv6 地址先还原为 IPv4 再比较 |
| `named_list name` | 配置包中该名单的条目（String 列表）；不存在 → `Error(unknown_list)`（配置包校验后不应发生） |
| `glob s p` | `s` 为 String；`*` 匹配不含 `/` 的任意串，连续 ≥ 2 个 `*` 视为 `**`，匹配含 `/` 的任意串，`?` 匹配一个非 `/` 字符，其他字符原样匹配；按 Unicode 标量值、区分大小写（与 `funcs.go` 的 `glob` 相同） |

**规则结果**：根为 `Bool(true)` → 命中；`Bool(false)` → 不命中；`Unknown(paths)` → 不命中，记 `missing_input`（排序后的路径）；`Error(kind)` → 不命中，记 `eval_error`；根为非 bool → `Error(no_such_overload)`。

**错误种类**（wire 字符串）：`no_such_overload`、`no_such_key`、`invalid_argument`、`unknown_list`、`step_limit`。

**结构上限**（Rust 加载时检查）：IR 节点数 ≤ 4096、嵌套深度 ≤ 64、字符串字面量 ≤ 4096 字节、列表字面量 ≤ 1000 项。

**步数**：求值一个节点花费 `cost(node)` 步，再加上它求值过的子节点的步数。`|x|` 是子表达式结果的大小：字符串为 UTF-8 字节数，列表 / map 为元素数。

| 节点 | `cost(node)` |
|---|---|
| `literal`、`field`、`has`、`named_list`、`list`、`not`、`and`、`or`、`cond` | 1 |
| `compare` | 字符串：`1 + ⌈(\|lhs\| + \|rhs\|) / 64⌉`；其他：1 |
| `in_list` | `1 + \|rhs\|` |
| `in_map`、`index_map` | 2 |
| `size` | 字符串：`1 + ⌈\|x\| / 64⌉`；其他：1 |
| `string_call` | `1 + ⌈(\|target\| + \|arg\|) / 64⌉` |
| `ip_in` | `1 + \|rhs\|` |
| `glob` | `1 + ⌊\|subject\| · len(pattern) / 16⌋`（`len` 为字节数） |

**静态步数上界** `max_steps(root)`：用同一张表，把每个 `|x|` 换成上界 `S(x)`，并假定所有子节点都被求值（`and` / `or` 不按短路打折；`cond` 取 `1 + steps(c) + max(steps(t), steps(e))`）。`S`：字面量为实际大小；`field` 为 §4.1 的大小上限；`index_map(req.headers, k)` 为 8192；`index_map(rate, k)` 与标量字段为 0；`named_list` 为 10,000；`list` 为元素个数；`cond` 为两个分支的较大者；布尔与数值结果为 0。上界用 `u64` 饱和运算。

- WP-G1 在降级时计算 `max_steps` 并写入 `PolicyExpr.max_steps`，超过 100,000 编译失败（§5.2）。
- WP-R1 的 `decode_program` 用同一规则复算：与 `max_steps` 不相等（`IrError::Steps`）或超过 100,000 时拒绝。一致性套件（§5.8）逐用例比较两边的值。
- 运行时仍然计步，作为断言：累计超过 100,000 时**整条规则**立即终止，结果为 `Error(step_limit)`，不被 `&&` / `||` 吸收，计 `mg_policy_step_limit_total`。由于 §9.3.1 保证所有输入不超过 §4.1 的上限，这在正确的实现中不可达；它不是性能调节手段。
- 路由匹配（§9.4）不经过 IR 求值器，不计步数；它的成本由 §8.2 的路由上限与 8 KiB 路径上限约束。

Go 参考语义（只用于一致性测试，不计步数）：先把表达式中所有 `has(p)` 按 MissingSet 替换为布尔字面量，再以 MissingSet 中每个路径作为未知属性模式（`cel.AttributePattern`，按路径段 `QualString`）运行 cel-go 部分求值（`cel.EvalOptions(cel.OptPartialEval)`）；结果 `types.Bool` / `*types.Unknown` / `*types.Err` 分别对应 true|false / unknown / error。cel-go v0.30 的严格函数先返回 ERROR、再合并 UNKNOWN，`&&` / `||` 中 UNKNOWN 优先于 ERROR，与上表一致。

### 5.4 规则引擎（WP-R1）

输入：已按顺序排列的规则（阶段 `identity < protocol < rate_limit < bot < custom < default`，同阶段 `priority` 降序，再按 `id` 字节序升序；Edge 加载时再排序一次，与构建器一致）、限速器观测（§9.8）、矩阵配置。

```
tags = []; force_log = false; hits = []
eval_rules(identity); eval_rules(protocol)
apply_limiters()                 // enforce-mode limiter that is exceeded -> terminal decision (below)
eval_rules(rate_limit); eval_rules(bot); eval_rules(custom); eval_rules(default)
return finish(matrix())          // §5.5

eval_rules(phase):
  for r in rules of phase:
    if r.expires_at_ms != 0 && now_ms >= r.expires_at_ms: continue
    if !in_rollout(r): continue
    res = eval(r.program)
    if res is Unknown or Error: record hit(missing_input | eval_error); continue
    if res is false: continue
    record hit(matched, r.mode, r.action)
    if r.mode == dry_run: continue
    match r.action:
      log  -> force_log = true
      tag  -> tags += r.params.label
      allow | block | challenge | rate_limit -> return finish(decision(r))   // terminal
```

- `in_rollout(r)`：`rollout_percent ≥ 100` → 是；`0` → 否；否则 `fnv1a64("mg-rollout-v1" ‖ 0x00 ‖ rule_id ‖ 0x00 ‖ unit) % 100 < rollout_percent`，`unit` 依次取 `session_id`、`net.ip_prefix`、`request_id` 中第一个非空值。FNV-1a 64 位：偏移基 `0xcbf29ce484222325`，质数 `0x100000001b3`。
- `apply_limiters()`：按配置包声明顺序（内置限速器在前）遍历本请求的限速器观测。`exceeded && mode == enforce` 时：`rate_limit` → `RATE_LIMIT`，状态 429，`retry_after_s` 取限速器配置值，为 0 时取 GCRA 给出的等待时间向上取整、至少 1 秒，`rule_id = "ratelimit.<id>"`；`block` → `BLOCK` 403；`challenge` → `CHALLENGE(challenge_type)`；`signal` → 不产生决定（已在评分前变成 RATE 信号，§5.7 检测器 `rate.exceeded`）。`exceeded && mode == dry_run` → 记一条 `matched`、`dry_run` 的 hit。
- `decision(r)`：`allow` → ALLOW；`block` → BLOCK 403；`challenge` → `CHALLENGE(params.type)`（缺省 `invisible`；`interactive` 在 Phase 1 按 D-08 变为 `pow`，该规则的 hit 记 `fields = ["phase1.interactive_as_pow"]`）；`rate_limit` → RATE_LIMIT 429，`retry_after_s = params.retry_after_s`（缺省 60）。
- `finish(d)`：若 `d.action == ALLOW` 且 `tags` 非空 → 改为 `TAG`；若 `d.action == ALLOW` 且 `force_log` → 改为 `LOG`（TAG 优先于 LOG）；`d.tags = dedup(tags)`（至多 8 个）；`hits` 至多 16 条，超出的丢弃。`force_log` 另外让本请求的决定事件 100% 采样。
- `Decision.status`：CHALLENGE 403；BLOCK 403；RATE_LIMIT 429 + `retry_after_s`；ALLOW / TAG / LOG 无状态码。
- 全局 monitor（`SiteBundle.monitor_only`）与 bootstrap 不在引擎里处理：Edge 在引擎之后把 `dry_run = true` 并按 ALLOW 转发（§9.9）。客户端 IP 未知时的 CHALLENGE → 429、http 访客的 308 也在 Edge 的执行层处理（§9.9），不改变引擎给出的决定与事件中的 `decision`。

### 5.5 默认处置矩阵（WP-R1）

03 §5.1 的规范化实现。`band = risk.score.band()`；`critical = route.sensitivity == Critical`；Phase 1 的 `interactive` 按 D-08 执行为 `pow`。

```
matrix():
  match risk.bot_class:
    VerifiedCrawler ->
      if crawler_policy.action(purpose) == block    -> BLOCK "matrix.crawler.block"
      if method in {GET, HEAD} || !route.require_clearance
                                                     -> ALLOW "matrix.crawler.allow"
      // otherwise fall through: a verified crawler never bypasses require_clearance for writes (D-36)
    Impersonator    -> BLOCK "matrix.class.impersonator"
    Scanner         -> BLOCK "matrix.class.scanner"
  if band == VeryHigh                                -> BLOCK "matrix.very_high"
  if route.require_clearance && token.status != Valid
                                                     -> CHALLENGE(band == High ? pow : invisible) "matrix.clearance.required"
  if token.status == BindingMismatch                 -> CHALLENGE(invisible) "matrix.clearance.binding"
  want = match (band, critical):
    (Low, _)        -> ALLOW "matrix.low"
    (Medium, false) -> confidence < theta_c ? CHALLENGE(invisible) "matrix.medium.low_confidence"
                                            : TAG "matrix.medium"
    (Medium, true)  -> CHALLENGE(invisible) "matrix.critical.medium"
    (High, false)   -> CHALLENGE(invisible) "matrix.high"
    (High, true)    -> CHALLENGE(interactive) "matrix.critical.high"
  if want is CHALLENGE(t) && token.status == Valid && rank(token.level) >= rank(effective(t))
                                                     -> TAG "matrix.satisfied"          // D-20
  return want
rank: invisible = 1, pow = 2, interactive | interactive_a11y | interactive_ext:* = 3
effective(interactive) = pow in Phase 1 (D-08)
```

`crawler_policy.action(purpose)`：`purposes[purpose]`，缺省 `default_action`，再缺省 `allow`。矩阵产生的 TAG 不带标签（`MG-Tags` 只来自规则）。

### 5.6 Rust API（WP-R1）

`mg-core` 新增模块与公开签名（名字可以加私有辅助项，公开项按此实现）。`paths` 与 `gcra` 已由本提交落地（§0.4），这里列出签名供其他 WP 使用：

```rust
// core/src/extras.rs — per-request inputs that are not part of the logged RequestContext
pub struct RouteInfo {
    pub id: String, pub name: String, pub env: String,
    pub channel: Channel, pub sensitivity: RouteSensitivity,
    // OR over every route that matched any path view (§9.4), not only the selected one
    pub require_clearance: bool, pub fail_closed: bool,
}
pub enum LimiterAction { Signal { weight: f32 }, Challenge(ChallengeType), RateLimit { retry_after_s: u32 }, Block }
pub struct RateObservation {
    pub limiter_id: String,          // "mg.c.submit", "login-per-ip", ...
    pub utilization: f32,            // [0, 1]; 1.0 when exceeded
    pub exceeded: bool,
    pub retry_after_ms: u64,         // from GCRA when exceeded
    pub action: LimiterAction,
    pub dry_run: bool,
}
pub struct RequestExtras<'a> {
    pub route: &'a RouteInfo,
    pub headers: &'a [(String, String)],   // §4.1 req.headers, sorted by name
    pub query: &'a str,
    pub rate: &'a [RateObservation],
    pub missing: &'a policy::MissingSet,
    pub ua: &'a ua::UaInfo,
    pub secure_context: bool,              // visitor used https (direct_tls, or CF-Visitor scheme https)
}

// core/src/ua.rs — normative UA family / major parser (feeds detectors and bind.uah)
pub struct UaInfo { pub family: &'static str, pub major: u32, pub mobile: bool,
                    pub claims_browser: bool, pub library: bool, pub declared_bot: bool }
pub fn parse(ua: &str) -> UaInfo;

// core/src/pipeline.rs (changed)
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn families(&self) -> FamilyMask;
    fn detect(&self, ctx: &RequestContext, extras: &RequestExtras<'_>, out: &mut Vec<Signal>);
}
pub trait Scorer: Send + Sync {
    fn score(&self, ctx: &RequestContext, extras: &RequestExtras<'_>, signals: &[Signal]) -> RiskAssessment;
}
pub struct PolicyInput<'a> {
    pub ctx: &'a RequestContext, pub extras: &'a RequestExtras<'a>,
    pub signals: &'a [Signal], pub risk: &'a RiskAssessment,
}
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyOutcome;
}
pub struct PolicyOutcome { pub decision: Decision, pub hits: Vec<RuleHit>, pub force_log: bool }
pub struct Evaluation { pub signals: Vec<Signal>, pub risk: RiskAssessment, pub outcome: PolicyOutcome }
impl DecisionCore {
    pub fn evaluate(&self, ctx: &RequestContext, extras: &RequestExtras<'_>) -> Evaluation;
}

// core/src/scoring.rs
pub enum FamilyMode { Active, Shadow, Off }
pub struct ScoringConfig {
    pub theta_c: f32,                        // 0.4
    pub kappa: Option<f32>,                  // None = profile default
    pub z0: [f32; 4],                        // by RouteSensitivity Low..Critical
    pub family_modes: BTreeMap<SignalFamily, FamilyMode>,
    pub weights: BTreeMap<String, f32>,      // detector signal id -> w_s override
    pub h_min: f32,                          // -4.0
    pub ruleset_version: String,
}
impl Default for ScoringConfig { /* §5.7 initial values */ }
pub struct ScorerV1 { /* ... */ }
impl ScorerV1 { pub fn new(cfg: ScoringConfig) -> Self; }
impl Scorer for ScorerV1 { /* §5.7 */ }
pub fn phase1_detectors() -> Vec<Box<dyn Detector>>;         // §5.7 table, in table order

// core/src/classify.rs
pub fn derive_bot_class(ctx: &RequestContext, signals: &[Signal], score: Score,
                        confidence: Confidence, theta_c: f32) -> (BotClass, Vec<String>);

// core/src/gcra.rs — PRE-LANDED. Pure GCRA; integer microseconds; equals the Lua script of §9.7 bit for bit
pub const MAX_DVT_US: u64 = 7 * 86_400 * 1_000_000;   // keeps every Lua value < 2^53
pub struct GcraParams { pub interval_us: u64, pub burst: u32 }
impl GcraParams {
    /// None if rate, period_s or burst is 0, if interval_us rounds to 0, or if interval_us * burst > MAX_DVT_US.
    /// interval_us = period_s * 1_000_000 / rate (floor).
    pub fn new(rate: u32, period_s: u32, burst: u32) -> Option<Self>;
    pub fn dvt_us(&self) -> u64;
}
pub struct GcraOutcome { pub allowed: bool, pub retry_after_us: u64, pub tat_minus_now_us: u64,
                         pub new_tat_us: Option<u64> /* Some iff allowed; the caller stores it to consume */ }
impl GcraOutcome { pub fn utilization(&self, p: &GcraParams) -> f32; } // allowed: min(1, tat_minus_now/dvt); denied: 1.0
pub fn gcra_check(p: &GcraParams, stored_tat_us: Option<u64>, now_us: u64, cost: u32) -> GcraOutcome;
// shared case table: core/testdata/gcra-cases.json {params: [...], checks: [{interval_us, burst, cost,
// stored_tat_us, now_us, allowed, retry_after_us, tat_minus_now_us, new_tat_us}]}

// core/src/paths.rs — PRE-LANDED. Path views (callers strip the query string first)
pub const EDGE_PREFIX: &str = "/__mg";
pub fn is_reserved(path: &str) -> bool;                 // raw, rfc3986_view, cloudflare_view: /__mg or /__mg/...
pub fn rfc3986_view(path: &str) -> Cow<'_, str>;
pub fn cloudflare_view(path: &str) -> Cow<'_, str>;
pub fn decoded_view(path: &str) -> Cow<'_, str>;        // all %XX, '\' -> '/', ;params removed, '//' merged, dots removed
pub fn route_candidates(path: &str, case_insensitive: bool) -> Vec<String>; // §9.4, deduplicated, ordered

// core/src/policy/{mod,fields,ir,eval,engine,matrix,glob,ip}.rs
pub struct Activation { pub req: ReqNs, pub net: NetNs, pub upstream: UpstreamNs, pub tls: TlsNs,
    pub http: HttpNs, pub edge_tls: EdgeTlsNs, pub identity: IdentityNs, pub risk: RiskNs,
    pub route: RouteNs, pub rate: BTreeMap<String, f64>, pub labels: Vec<String> }  // serde = §4.2
impl Activation {
    pub fn build(ctx: &RequestContext, extras: &RequestExtras<'_>, risk: &RiskAssessment) -> Self;
}
pub struct MissingSet { /* sorted paths */ }
impl MissingSet {
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(paths: I) -> Result<Self, UnknownField>;
    pub fn is_missing(&self, path: &str) -> bool;
    pub fn paths(&self) -> impl Iterator<Item = &str>;
}
pub enum FieldId { /* one variant per leaf / map / list path of §4.1 */ }
impl FieldId { pub fn from_path(p: &str) -> Option<Self>; pub fn path(self) -> &'static str; }
pub enum Expr { /* native tree mirroring policy_ir.proto; fields resolved to FieldId, lists to ListId */ }
pub struct Program { /* root, fields, node count, max_steps */ }
pub const MAX_STEPS: u64 = 100_000;
/// §5.3 static step bound of a native expression, using the §4.1 size caps (saturating).
pub fn max_steps(root: &Expr) -> u64;

// core/src/policy/glob.rs — the one glob implementation (policy glob() and route paths)
pub struct Glob { /* tokens, literal prefix */ }
pub enum GlobError { Empty, TooLong /* > 4096 bytes */ }
impl Glob {
    pub fn new(pattern: &str) -> Result<Self, GlobError>;   // §5.3 glob syntax
    pub fn matches(&self, s: &str) -> bool;                 // compares the literal prefix before the DP matcher
    pub fn literal_prefix(&self) -> &str;                   // characters before the first '*' or '?'
    pub fn wildcard_count(&self) -> usize;                  // '*', '**' (a run counts once) and '?'
}
pub struct NamedLists { /* name -> entries, lazily pre-parsed IP prefixes */ }
impl NamedLists { pub fn new(lists: BTreeMap<String, Vec<String>>) -> Self; pub fn contains(&self, name: &str) -> bool; }
pub enum EvalError { NoSuchOverload, NoSuchKey, InvalidArgument, UnknownList, StepLimit }
pub enum EvalResult { True, False, Unknown(Vec<&'static str>), Error(EvalError) }
pub fn eval(p: &Program, act: &Activation, missing: &MissingSet, lists: &NamedLists) -> EvalResult;

pub enum Phase { Identity, Protocol, RateLimit, Bot, Custom, Default }
pub enum RuleMode { Enforce, DryRun }
pub enum RuleAction { Allow, Log, Tag { label: String }, RateLimit { retry_after_s: u32 }, Challenge(ChallengeType), Block }
pub struct Rule { pub id: String, pub phase: Phase, pub priority: i32, pub program: Program,
    pub action: RuleAction, pub mode: RuleMode, pub rollout_percent: u8, pub expires_at_ms: i64 }
pub struct CrawlerPolicy { pub purposes: BTreeMap<String, CrawlerAction>, pub default_action: CrawlerAction }
pub enum CrawlerAction { Allow, Block }
pub struct EngineConfig { pub theta_c: f32, pub crawler_policy: CrawlerPolicy, pub interactive_available: bool }
pub struct SitePolicy { /* rules sorted per §5.4, lists, config */ }
impl SitePolicy { pub fn new(rules: Vec<Rule>, lists: NamedLists, config: EngineConfig) -> Self; }
impl PolicyEvaluator for SitePolicy { /* §5.4 + §5.5 */ }
```

`mg-proto`（`proto/rust/src/ir.rs`）：

```rust
pub enum IrError { Decode(prost::DecodeError), Version(u32), UnknownField(String), BadHas(String),
                   UnknownList(String), Limits(&'static str), Malformed(&'static str),
                   Steps { declared: u64, computed: u64 } }
/// Decodes and validates a serialized PolicyExpr (§5.3 limits, schema paths, list names,
/// max_steps recomputed: must equal the declared value and be <= MAX_STEPS).
pub fn decode_program(bytes: &[u8], lists: &mg_core::policy::NamedLists) -> Result<mg_core::policy::Program, IrError>;
pub fn program_from_proto(p: &v1::PolicyExpr, lists: &mg_core::policy::NamedLists) -> Result<mg_core::policy::Program, IrError>;
/// Full CompiledRule -> Rule (phase, mode, action + params per §3.2, rollout, expiry). Rejects
/// ir_version != 1, unknown params, disabled rules (the builder never emits them).
pub fn rule_from_proto(r: &v1::CompiledRule, lists: &mg_core::policy::NamedLists) -> Result<mg_core::policy::Rule, IrError>;
```

### 5.7 Phase 1 检测器与评分 v1（WP-R1）

评分公式按 03 §4.1。每个检测器对每个请求**至多输出一个** Signal：`PRESENT`（值可以是 0，表示"有输入、无异常"，计入覆盖度）、`ABSENT` 或 `MISSING`；表中注明"不输出"的情况不产生信号，也不影响覆盖度。事件只记录 `PRESENT` 且值非 0、`ABSENT`、以及"期望但缺失"的 `MISSING` 信号。

| 信号 id | 族 | 期望的 profile | 输入与判定 | 值 / 置信度 | 缺省 `w_s` |
|---|---|---|---|---|---|
| `net.client_ip` | NETWORK | 两者 | `net.ip` 已知 → PRESENT 0；未知 → MISSING | 0 | 1.0 |
| `net.datacenter` | NETWORK | 两者 | `conn_type == datacenter` | +0.6 / 0.8 | 1.0 |
| `net.tor` | NETWORK | 两者 | `net.tor` | +0.5 / 0.9 | 1.0 |
| `tls.proto_old` | TLS | `direct_tls` | 声称现代浏览器（`ua.claims_browser` 且 Chrome/Edge ≥ 70、Firefox ≥ 63、Safari ≥ 13）而 `tls.version` < TLSv1.2 | +0.5 / 0.8 | 1.0 |
| `edge_tls.proto_mismatch` | EDGE_TLS | `cloudflare` | 同上条件，`edge_tls.version ∈ {SSLv3, TLSv1, TLSv1.1}` | +0.4 / 0.6 | 1.0 |
| `http.ua_missing` | HTTP | 两者 | UA 为空 | +0.8 / 1.0 | 1.5 |
| `http.ua_library` | HTTP | 两者 | `ua.library`（标记表见下文"UA 解析"） | +1.0 / 1.0 | 2.0 |
| `http.accept_language_missing` | HTTP | 两者 | 导航请求（`sec-fetch-mode: navigate`，或 GET 且 `accept` 含 `text/html`）、`ua.claims_browser`、无 `accept-language` | +0.5 / 0.8 | 1.0 |
| `http.client_hints` | HTTP | 两者 | Chromium 系（chrome / edge / opera，非 iOS）且 major ≥ 90、安全上下文（`extras.secure_context`）：缺 `sec-ch-ua` → +0.5 / 0.7；`sec-ch-ua` 中 `"Chromium"` 或 `"Google Chrome"` 品牌的主版本与 UA 不一致 → +0.7 / 0.8 | 见左 | 1.0 |
| `http.fetch_metadata_missing` | HTTP | 两者 | 现代浏览器（Chrome/Edge ≥ 80、Firefox ≥ 90、Safari ≥ 17）且无 `sec-fetch-mode` | +0.5 / 0.7 | 1.0 |
| `http.fetch_metadata_mismatch` | HTTP | 两者 | 路由 channel 为 `api` 且 `sec-fetch-mode: navigate` | +0.4 / 0.6 | 1.0 |
| `http.version_old` | HTTP | 两者 | `ua.claims_browser` 且 `http.version == "HTTP/1.0"`；`http.version` MISSING → MISSING | +0.6 / 0.8 | 1.0 |
| `rate.utilization` | RATE | 两者 | `u = max(extras.rate[*].utilization)`：值 `clamp((u − 0.7) / 0.3, 0, 1) · 0.8`；本路由没有任何限速器 → MISSING（路由不提供该输入，不是客户端缺失） | 见左 / 1.0 | 1.0 |
| `rate.exceeded` | RATE | 两者 | 本路由有 `LimiterAction::Signal` 限速器时 PRESENT（没有则 MISSING）；超限者的值 `min(1, Σweight / 2)`，reason `rl.<limiter id>`；都未超限为 0 | 见左 / 1.0 | 2.0 |
| `identity.clearance` | IDENTITY | 两者 | 凭证 `none` / `expired` → ABSENT；`valid`（任一级别）→ −0.4 / 1.0；`invalid` → +0.5 / 0.6；`binding_mismatch` → +0.3 / 0.8。Phase 1 的两种级别都只证明"执行了 JS 并付出了 PoW 成本"，人类证据相同；级别只决定能满足哪种挑战要求（§5.5 `rank`） | 见左 | 1.0 |
| `identity.bind_ipp_soft` | IDENTITY | 两者 | 只在凭证有效时输出：`bind.ipp == soft_mismatch` → +0.4 / 0.6，否则 PRESENT 0；无有效凭证时不输出 | 见左 | 1.0 |
| `identity.crawler_failed` | IDENTITY | 两者 | 只在 UA 声称已知爬虫时输出：验证 `failed` → +1.0 / 1.0；`pending` 且 `outside_ranges`（运营方发布了 IP 段而 IP 不在其中，rDNS 结论未出）→ +0.5 / 0.6（D-18）；其余 PRESENT 0 | 见左 | 2.0 |
| `external.cf_vbot` | EXTERNAL | `cloudflare` | 按 03 §3.9：vbot true 且自有验证通过 → 0；vbot true 且未通过 → +0.3 / 0.8；vbot false 且 UA 声称已知爬虫 → +0.3 / 0.8；其余 0；头缺失 → MISSING | 见左 | 1.0 |

- 不在 profile 期望集合内的检测器输出 `MISSING`（例如 `cloudflare` 下的 `tls.proto_old`）。
- **族模式缺省**：`edge_tls` = shadow；其余 active；`client`、`behavior`、`reputation` 在 Phase 1 没有检测器。
- **族区间**：NETWORK ±1.5、TLS ±2.5、EDGE_TLS ±1.0、HTTP ±2.0、RATE ±2.0、IDENTITY [−1.5, +2.0]、EXTERNAL [0, +1.0]（03 §4.1）。
- **来源系数** `λ_src`：`self` 1.0；`cloudflare` 转发的输入 0.8（`edge_tls.*`、`external.*`、`http.version_old` 在 `cloudflare` 下）。
- **先验** `z0`：low −2.197、medium −1.735、high −1.386、critical −1.099（即 10%、15%、20%、25%）。
- **实体 verdict**（D-10）：只取 `active_verdicts()` 中 `applies_to_site(site)` 的项；每种实体取风险最高的一条；贡献 `β_e · min(4, max(0, logit(R/100)))`，`R = 100` 视为 4；`β`：session 0.6、ip 0.3、prefix 0.2、asn 0.2（03 §4.1 未列 asn，取 0.2）。
- **人类证据下限**：所有 active 族的负向贡献之和不低于 `h_min`（−4.0）。
- **硬规则**：爬虫验证 `failed` → `score = max(score, 90)`；labels 含 `scanner` → `score = max(score, 85)`。
- **置信度**：`A_f` 为 NETWORK 1.0、TLS 1.5、HTTP 1.0、RATE 0.5、IDENTITY 1.5；shadow / off 族与 EXTERNAL 不计入；`a_s` 全部 1.0；`κ`：`direct_tls` 1.0、`cloudflare` 0.9。
- **`top_reasons`**：按 `|贡献|` 降序的前 5 个 reason code（正向优先），reason code 缺省等于信号 id。
- **`shadow_score`**：把 shadow 族按同一公式加入后的分数。
- **`ruleset_version`**：取配置包 `scoring.ruleset_version`，缺省 `"v1"`。

**UA 解析**（`mg_core::ua::parse`，规范；`bind.uah = hash("uah", family + "/" + major)`）：按下列顺序取第一个命中的标记，`major` 为其后的十进制主版本（无则 0）：`HeadlessChrome/` → `headless_chrome`；`Edg/`（含 `EdgA/`、`EdgiOS/`）→ `edge`；`OPR/` → `opera`；`SamsungBrowser/` → `samsung`；`FxiOS/` → `firefox_ios`；`Firefox/` → `firefox`；`CriOS/` → `chrome_ios`；`Chrome/` 或 `Chromium/` → `chrome`；同时含 `Safari/` 与 `Version/` → `safari`（major 取 `Version/`）；其他 → `other`。`mobile` = 含 `Mobile`；`claims_browser` = 以 `Mozilla/5.0` 开头且 family 不是 `other` / `headless_chrome`；`library` = 小写 UA 含下列任一标记：`curl/`、`wget/`、`python-requests`、`python-urllib`、`aiohttp`、`httpx`、`go-http-client`、`okhttp`、`java/`、`apache-httpclient`、`libwww-perl`、`node-fetch`、`axios/`、`undici`、`scrapy`、`headlesschrome`、`phantomjs`、`puppeteer`、`playwright`；`declared_bot` = 小写 UA 含 `bot/`、`bot;`、`bot)`、`crawler`、`spider`、`slurp`、`+http` 之一（不用裸 `bot`，避免误中 `CUBOT` 等机型名）。

**BotClass 推导**（`derive_bot_class`，顺序即优先级）：爬虫 `verified` → `VERIFIED_CRAWLER`；爬虫 `failed` → `IMPERSONATOR`；labels 含 `scanner` → `SCANNER`；爬虫 `pending` / `unverifiable`，或 `ua.declared_bot` → `DECLARED_AGENT`（并加 label `declared_bot`）；`score ≥ 60` → `AUTOMATION_LIKELY`；`score < 30` 且 `confidence ≥ θ_c` → `HUMAN_LIKELY`；否则 `UNKNOWN`。

### 5.8 跨语言一致性套件

**文件**（WP-G1 维护，WP-R1 只读）：

- `testdata/policy-ir/cases.json`（手写）：

```json
{
  "version": 1,
  "lists": {"owner_cidrs": ["10.0.0.0/8", "2001:db8::/32"], "bad_ja4": ["t13d1516h2_8daaf6152771_02713d6af862"]},
  "contexts": {
    "cf_browser": {"input": { "...": "Activation JSON, §4.2" },
                   "missing": ["tls", "http.header_order", "identity.proof", "identity.agent"]}
  },
  "cases": [
    {"name": "docs06.block-impersonators.match", "expr": "risk.class == \"IMPERSONATOR\"",
     "context": "cf_impersonator", "expect": "true"},
    {"name": "missing.and.false-absorbs", "expr": "false && tls.version == \"TLSv1.3\"",
     "context": "cf_browser", "expect": "false"},
    {"name": "reject.arith", "expr": "risk.score + 1 > 2", "context": "cf_browser",
     "compile_error": "unsupported in policy IR"}
  ]
}
```

  `expect ∈ {"true", "false", "unknown", "error"}`；带 `compile_error` 的用例断言编译失败且错误信息包含该子串，不出现在 IR 文件中。

- `testdata/policy-ir/cases.ir.json`（由 Go 生成，提交入库）：

```json
{"version": 1, "ir_version": 1, "generator": "control-plane/internal/policy (cel-go v0.30.0)",
 "cases": [{"name": "docs06.block-impersonators.match", "ir": "<base64 (std, padded) of PolicyExpr bytes>"}]}
```

  用例按 `cases.json` 的顺序；JSON 以两个空格缩进、末尾换行。

**Go**（`internal/policy/conformance_test.go`）：`go test ./internal/policy -run TestIRConformance`（1）编译每个用例（`list()` 名称取自 `lists`），（2）降级为 IR，与 `cases.ir.json` 逐字节比较，带 `-update` 标志时重写该文件，（3）用参考求值器（§5.3）求值并断言 `expect`。CI 不带 `-update`，所以 IR 文件与编译器不一致时 `make go-check` 失败。

**Rust**（`proto/rust/tests/policy_ir_conformance.rs`）：读取两个文件，用 `ir::decode_program` 解码（其中复算 `max_steps` 并与 IR 中的值比较），按上下文 JSON 构建 `Activation` 与 `MissingSet`，求值并断言与 `expect` 一致；另断言 `unknown` 用例返回的路径集合非空且都在 MissingSet 之下，且每个用例求值实际花费的步数不超过 `max_steps`。

**覆盖要求**（≥ 150 个用例）：`docs/06` §2 的全部示例与 `control-plane/testdata/policies/valid/*.yaml` 的全部表达式（每条至少一个命中与一个不命中上下文）；每种 IR 节点各自的 true / false / unknown / error（适用时）；`&&` / `||` 的吸收表（`false && unknown`、`true && unknown`、`unknown && error`、`error && false`、`true || unknown`、`false || unknown`、`unknown || error`）；`!unknown`；条件为 unknown 的三元式；`has()` 对 PRESENT / ABSENT / MISSING 字段及其父路径；map 下标缺键；`"k" in rate`；多字节字符串的 `size`、`startsWith`、`contains`；`ip_in` 的 IPv4、IPv6、IPv4 映射地址、映射 CIDR、非法地址（false）、非法条目（error，含"前面已匹配"）；`glob` 的 `*`、`**`、`?`、连续星号、Unicode；命名列表；§5.2 每类拒绝构造至少一个 `compile_error` 用例，其中必须有 `1 in [1.0, "a"]`、`1 in [1.0]`、`"a" in [1, "a"]`、`[1, 2.0] == [1, 2.0]`、`[[1]] == [[1]]`，以及一个静态步数超过 100,000 的规则（例如对 `req.path` 连续 7 个 32 字节模式的 `glob`）；步数上界接近 100,000 但未超出的规则至少一条（`expect` 照常）。

## 6. 挑战与凭证密码学（`mg-challenge`，WP-R2）

所有字节级公式在 `testdata/phase1/kat.json` 中有已知答案向量，WP-R2 的测试必须逐条通过；密钥文件的解析用 `testdata/phase1/keys/` 的有效与无效样例测试。

### 6.1 密钥与 epoch

| 项 | 规范 |
|---|---|
| 根密钥 | `K_seal_root`：32 字节。站点密钥文件 `seal.root.json`（§12.7）含 1–2 个根：`roots[0]` 用于封装，全部用于打开（D-30）；以 systemd credential 交付 |
| epoch | `epoch_no = floor(now_ms / 86_400_000)`（UTC 日） |
| kid | `"e" + 十进制 epoch_no`，例如 `e20724`（kid 不区分根：打开时按 `roots` 顺序逐个尝试 AEAD） |
| 派生 | `k_epoch = HKDF-SHA256(salt = 空, ikm = K_seal_root, info = "mg-seal-v1" ‖ 0x00 ‖ site_id ‖ 0x00 ‖ u64be(epoch_no), L = 32)`；`k_bind_epoch` 同法、标签 `"mg-bind-v1"`（Phase 2 Turnstile `cData` 用，Phase 1 只提供函数） |
| 接受的 epoch | 设 `e = epoch_no(now)`、`d = now_ms − e · 86_400_000`（当日已过的毫秒）。接受 `e`；`d ≤ 125_000`（C 最长寿命 120 s + 5 s 时钟偏差）时另接受 `e − 1`；`86_400_000 − d ≤ 5_000` 时另接受 `e + 1`。其余一律 `ic.c_kid`。KAT：`kat.json` 的 `accepted_epochs`。Phase 2 引入更长寿命的交互式 C 时把 120 s 换成最长寿命 |
| 缓存 | 派生结果按 `(root 序号, site, epoch)` 缓存，至多 8 项；`Debug` 不打印密钥；密钥类型实现 `Zeroize` |

### 6.2 密封 C

```
C          = base64url_nopad( prost(SealedChallenge { v: 1, kid, xnonce, ct }) )      len(C) <= 1024
xnonce     = 24 random bytes (Rng)
ct         = XChaCha20-Poly1305.seal(k_epoch[kid] of roots[0], xnonce, prost(SealedChallengeClaims), aad)
aad        = u16be(len(host)) ‖ host ‖ u16be(len(type)) ‖ type ‖ u16be(len(kid)) ‖ kid   (UTF-8)
host       = request Host, lower-case, without port and trailing dot
type       = ChallengeType wire name: "invisible" | "pow" | "interactive"
```

Phase 1 签发的 claims：`v = 1`；`kid` 与信封相同；`nonce` 16 个随机字节；`site`；`route_class` = 选中的路由名（§9.4）；`type` 为 `invisible` 或 `pow`；`providers` 为空；`risk_band` = 挑战前风险段（失败后的新 C 为升级后的段，§6.3）；`attempt_no = 0`（该字段只用于交互式）；`iat_ms` = now；`exp_ms = iat_ms + challenge.ttl_s · 1000`（≤ 120 s）；`ui_seed = 0`；`pow = {alg: "sha256-hashcash-v1", difficulty}`（§6.3）；`ret` = `ret_hash(ret)`；`bind`：`uah` 与 `ipp` **必有**（客户端 IP 未知时不签发 C，§9.9），`ipa` 在 ASN 已知且不为 0 时有，`ctp` 在 `cloudflare`、`clearance.ctp_shadow` 且四个输入齐全时有，`jkt` / `tfp` 为空。

**打开**（`Sealer::open`）按以下顺序，任一步失败即返回对应 `OpenError`（括号内为内部 reason code）；每一步都先检查长度再调用密码学接口，任何输入都不 panic（`chacha20poly1305` 的定长构造只在长度检查之后调用）：

1. `len(C) ≤ 1024`（`ic.c_invalid`）→ base64url 解码（`ic.c_invalid`）→ prost 解码信封，`v == 1`，`len(xnonce) == 24`，`len(ct) ≥ 16`（`ic.c_invalid`）。
2. 解析 kid，epoch 在接受范围内（§6.1，`ic.c_kid`）。
3. 按 `roots` 顺序派生密钥并做 AEAD 打开（`aad` 用请求 Host 与提交中声明的 type），全部失败 → `ic.c_invalid`。
4. prost 解码 claims（`ic.c_invalid`）→ `claims.kid == 信封 kid`、`claims.site == 站点`、`claims.challenge_type == 声明的 type`、`len(nonce) == 16`、`pow` 存在且 `alg == POW_ALG`、`difficulty ≤ MAX_POW_BITS`、`len(ret) == 16`、`bind.uah` 与 `bind.ipp` 存在且各 16 字节、`bind` 的其他字段缺失或为 16 字节（`ic.c_invalid`）。
5. `SealedChallengeClaims::check(now_ms)`（`Expired` → `ic.c_expired`，其余 → `ic.c_invalid`）。

### 6.3 PoW

| 项 | 规范 |
|---|---|
| 算法名 | `sha256-hashcash-v1` |
| 输入 | `prefix = "mg-pow-v1" ‖ 0x00 ‖ SHA-256(C 的 ASCII 字节)`（42 字节）；`digest = SHA-256(prefix ‖ u64be(counter))` |
| 判定 | `leading_zero_bits(digest) ≥ difficulty` |
| 取值 | 协议上 `0 ≤ difficulty ≤ 32`；配置包的 `pow_bits` 每项必须在 8–24（§8.2）；`counter < 2^53`（JS 安全整数）；Phase 1 提交恰好一个 counter |
| 缺省难度 | `low` 14、`medium` 16、`high` 18、`very_high` 20（配置包 `challenge.pow_bits`） |
| 难度选择（D-27） | `invisible`：`pow_bits.low`（保持"无感"：中位设备几十毫秒）；`pow`：`pow_bits[risk_band]`；提交失败后附的新 C：`type = pow`，`risk_band = min(原 risk_band + 1, high)`，难度 `pow_bits[新 risk_band]`。重试次数由失败配额约束（§9.8，D-28） |

### 6.4 绑定哈希与返回路径

| 项 | 规范 |
|---|---|
| 绑定哈希 | `bind_hash(kind, value) = SHA-256("mg-bind-v1" ‖ 0x00 ‖ kind ‖ 0x00 ‖ value)[0..16]`；凭证 JSON 中为 base64url（无填充） |
| `uah` | `value = family + "/" + major`（`mg_core::ua::parse`，例如 `chrome/131`）；硬 |
| `ipp` | `value = Net::prefix_of(ip)`（`203.0.113.0/24`、`2001:db8:abcd::/48`）；软；C 与凭证**总是**带 `ipp`（D-23） |
| `ipa` | `value = ASN 十进制`；ASN 已知且不为 0 时才绑定（GeoLite2 查不到的 0 与"未知"同样处理，从不计算 `hash("0")`）；决定 `ipp` 的软 / 硬 |
| `ctp` | `value = version + "\|" + cipher + "\|" + ciphers_sha1 + "\|" + min(hello_len / 64, 31)`（分隔符是一个竖线字符）；只记录 |
| `ret` 校验 | 以 `/` 开头、不以 `//` 或 `/\` 开头、不含 `\`、控制字符（< 0x20 或 0x7f）与 `#`、≤ 512 字节；去掉查询串后的路径 `p` 满足 `!mg_core::paths::is_reserved(p)`（与 Edge 的 `/__mg` 归属判断是同一个函数） |
| `ret_hash` | `SHA-256("mg-ret-v1" ‖ 0x00 ‖ ret)[0..16]` |

**绑定比较**（C 提交与凭证校验共用）：

| 项 | 结果 |
|---|---|
| `uah` | 相等 → `match`；否则 `mismatch`（C：失败 `ic.bind_uah`；凭证：`binding_mismatch`） |
| `ipp` | 当前前缀相等 → `match`；不等（含当前 IP 未知）时，若 `ipa` 已绑定且当前 ASN 已知、不为 0 且相等 → `soft_mismatch`，否则 `mismatch`（C：失败 `ic.bind_ipp`；凭证：`binding_mismatch`）。`ipp` 缺失的 C 在打开时已被拒绝，缺失的凭证为 `invalid`（§6.5） |
| `ctp` | 两边都有 → `match` / `mismatch`，只记录，不影响结果 |

### 6.5 清关凭证（PASETO v4.local）

```json
{"v":1,"kid":"blog-t-20260927","sid":"blog","env":"production",
 "sub":"<base64url 16 random bytes>","sst":1790000000,"lvl":"invisible","iat":1790000000,"exp":1790001800,
 "bind":{"uah":"iXRgjCj6tPt2cFcPqeHr_A","ipp":"JxTqJG6DMjc-DDCAwG3WYw","ipa":"3jB742LLBC_uwzOiZPFFLg"},
 "rb":"medium","jti":"<base64url 16 random bytes>"}
```

| 项 | 规范 |
|---|---|
| 载荷 | 上面的 JSON（`serde_json`，未知字段拒绝）。`iat`、`exp`、`sst`（会话开始）为 Unix 秒；`bind.uah`、`bind.ipp` 必有，`ipa`、`ctp` 可缺省 |
| PASETO 接口 | 只用 `pasetors::version4::LocalToken::{encrypt, decrypt}` 与 MorphGate 自己的 claims 校验，不用 pasetors 的 `claims` / `ClaimsValidationRules`：PASETO 规范把 `iat` / `exp` 定义为 ISO 8601 字符串，这里是整数（D-29） |
| footer | `{"kid":"<kid>"}`（明文，用于选密钥） |
| implicit assertion | `"mg-clr-v1" ‖ 0x00 ‖ site_id` |
| 密钥 | 站点 `token.keys.json`（§12.7）中 kid ∈ 配置包 `token_key_ids` 的密钥；`token_key_ids[0]` 签发，全部可验证 |
| 有效期 | `invisible` 1800 s、`pow` 1800 s（配置包 `clearance`，每项 ≤ 86400，§8.2）；`exp − iat ≤ 86400` |
| 校验 | 长度 ≤ 1024 → 解析 footer（≤ 128 字节 JSON）→ 按 kid 选密钥（kid 不在当前 `token_key_ids` → `UnknownKid`）→ `LocalToken::decrypt`（带 implicit assertion）→ 解析 claims → `v == 1`、`kid == footer.kid`、`sid == 站点`、`env == 请求所在环境` → `bind.uah`、`bind.ipp` 存在且为 16 字节的 base64url → `sst ≤ iat ≤ now + 5`、`exp − iat ≤ 86400` → `exp > now`（否则 `Expired`）→ `lvl` 可解析为 `TokenLevel` |
| `sub` / `sst` 复用 | 签发时，若请求带有这样一个凭证：通过上述全部校验（允许已过期），`check_clearance_bind` 没有硬失败（`uah` 为 `match`，`ipp` 为 `match` 或 `soft_mismatch`），且 `now − sst ≤ clearance.session_max_s`（缺省 86400），则沿用其 `sub` 与 `sst`；否则新生成 `sub`，`sst = now` |
| 状态映射 | 无 Cookie → `none`；`UnknownKid`（未知或已退役的 kid）或过期 → `expired`（ABSENT，不加风险）；其他解密 / 解析 / 校验失败、站点 / 环境不符 → `invalid`；绑定硬失败 → `binding_mismatch`；其余 → `valid`（`TokenStatus`） |

### 6.6 Cookie

- 签发：`Set-Cookie: __Host-mg_clr=<token>; Max-Age=<exp − now>; Path=/; Secure; HttpOnly; SameSite=Lax`。只出现在 `/__mg/c` 的成功响应上，从不附加到源站响应（02 §8）。`__Host-` 要求 Secure，所以 http 访客拿不到凭证；Edge 在挑战 http 访客前先 308 到 https（§9.9，D-32）。
- 解析：遍历所有 `Cookie` 头（合计只看前 16 KiB），按 `;` 分割、去空白，名称精确等于 `__Host-mg_clr` 的取值；至多尝试前 2 个候选，任一 `valid` 即用它，否则取第一个候选的状态。

### 6.7 公共 API

```rust
// challenge/src/rng.rs
#[derive(Debug)]
pub struct RngError;
/// Production implementations are backed by the OS CSPRNG (mg-edge: getrandom). Deterministic
/// test RNGs exist only under #[cfg(test)] or in callers' test code. A failure is returned,
/// never a panic; the Edge answers 503 (§9.9).
pub trait Rng: Send + Sync { fn fill(&self, dst: &mut [u8]) -> Result<(), RngError>; }

// challenge/src/keys.rs
pub struct SealRoot(/* [u8; 32], zeroize */);
impl SealRoot { pub fn from_bytes(key: [u8; 32]) -> Self; }
pub struct SealKeys { /* 1..=2 roots; roots[0] seals */ }
impl SealKeys {
    pub fn new(roots: Vec<SealRoot>) -> Result<Self, KeyError>;           // 1 or 2 roots
    /// Parses seal.root.json (§12.7); checks kind, v, site, 1-2 roots, unknown fields.
    pub fn from_key_file(json: &[u8], site_id: &str) -> Result<Self, KeyError>;
}
pub const MAX_C_LIFETIME_MS: i64 = 120_000;
pub const CLOCK_SKEW_MS: i64 = 5_000;
pub fn epoch_no(now_ms: i64) -> u64;
pub fn epoch_kid(epoch: u64) -> String;
pub fn parse_epoch_kid(kid: &str) -> Option<u64>;
pub fn accepted_epochs(now_ms: i64) -> std::ops::RangeInclusive<u64>;                  // §6.1, kat.json accepted_epochs
pub fn derive_epoch_key(root: &SealRoot, site_id: &str, epoch: u64) -> [u8; 32];      // k_epoch
pub fn derive_bind_epoch_key(root: &SealRoot, site_id: &str, epoch: u64) -> [u8; 32]; // k_bind_epoch
pub struct TokenKeySet { /* active kid + keys */ }
impl TokenKeySet {
    /// Parses token.keys.json; keeps only kids listed in `allowed_kids`; `allowed_kids[0]` must exist.
    pub fn from_key_file(json: &[u8], site_id: &str, allowed_kids: &[String]) -> Result<Self, KeyError>;
    pub fn active_kid(&self) -> &str;
}

// challenge/src/sealed.rs
pub const MAX_C_LEN: usize = 1024;
pub fn aad(host: &str, ty: ChallengeType, kid: &str) -> Vec<u8>;
pub fn random_nonce(rng: &dyn Rng) -> Result<[u8; 16], RngError>;
pub struct Sealer { /* site, keys, epoch key cache */ }
impl Sealer {
    pub fn new(site_id: &str, keys: SealKeys) -> Self;
    /// Seals `claims` (whose kid must be epoch_kid(epoch_no(claims.iat_ms))) for `host` with roots[0].
    pub fn seal(&self, claims: &SealedChallengeClaims, host: &str, rng: &dyn Rng) -> Result<String, SealError>;
    pub fn open(&self, c: &str, host: &str, claimed: ChallengeType, now_ms: i64) -> Result<SealedChallengeClaims, OpenError>;
}
pub enum SealError { Rng, Kid, TooLong, Invalid(ClaimsError) }
pub enum OpenError { TooLong, Encoding, Envelope, Kid, Aead, Claims, Shape, Mismatch, Expired, Invalid(ClaimsError) }
impl OpenError { pub fn reason_code(&self) -> &'static str; }  // §6.2 (Shape: length, pow and bind checks of step 4)

// challenge/src/pow.rs
pub const POW_ALG: &str = "sha256-hashcash-v1";
pub const MAX_POW_BITS: u32 = 32;
pub fn pow_prefix(c: &str) -> [u8; 42];
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32;
pub fn pow_verify(c: &str, difficulty: u32, counter: u64) -> bool;   // false for difficulty > 32 or counter >= 2^53
#[doc(hidden)] // reference solver for tests; never called on a request path
pub fn pow_solve(c: &str, difficulty: u32, max_iterations: u64) -> Option<u64>;

// challenge/src/bind.rs
pub fn bind_hash(kind: &str, value: &str) -> [u8; 16];
pub fn uah(ua_family: &str, ua_major: u32) -> [u8; 16];
pub fn ipp(prefix: &str) -> [u8; 16];
pub fn ipa(asn: u32) -> Option<[u8; 16]>;                              // None for 0
pub fn ctp(version: &str, cipher: &str, ciphers_sha1: &str, hello_len: u32) -> [u8; 16];
pub fn ret_hash(ret: &str) -> [u8; 16];
pub fn validate_ret(ret: &str) -> Result<(), RetError>;                // uses mg_core::paths::is_reserved
pub struct BindInputs { pub uah: [u8; 16], pub ipp: Option<[u8; 16]>, pub ipa: Option<[u8; 16]>, pub ctp: Option<[u8; 16]> }
pub struct BindCheck { pub uah: BindResult, pub ipp: BindResult, pub ctp: Option<BindResult> } // mg_core::BindResult
pub fn check_challenge_bind(sealed: &ChallengeBind, current: &BindInputs) -> BindCheck;
impl BindCheck { pub fn hard_failure(&self) -> bool; }                 // uah or ipp == Mismatch

// challenge/src/clearance.rs
pub const COOKIE_NAME: &str = "__Host-mg_clr";
pub const MAX_TOKEN_LEN: usize = 1024;
pub const MAX_TOKEN_LIFETIME_S: i64 = 86_400;
#[derive(Serialize, Deserialize)]
pub struct ClearanceClaims { pub v: u32, pub kid: String, pub sid: String, pub env: String, pub sub: String,
    pub sst: i64, pub lvl: TokenLevel, pub iat: i64, pub exp: i64, pub bind: ClearanceBind, pub rb: RiskBand,
    pub jti: String }
#[derive(Serialize, Deserialize)]
pub struct ClearanceBind { pub uah: String, pub ipp: String, pub ipa: Option<String>, pub ctp: Option<String> }
pub struct MintParams<'a> { pub env: &'a str, pub session: Option<(&'a str, i64)> /* reused (sub, sst) */,
    pub lvl: TokenLevel, pub now_s: i64, pub ttl_s: u32, pub bind: ClearanceBind, pub rb: RiskBand }
pub fn mint(keys: &TokenKeySet, site_id: &str, p: &MintParams<'_>, rng: &dyn Rng) -> Result<(String, ClearanceClaims), TokenError>;
pub fn verify(keys: &TokenKeySet, site_id: &str, env: &str, token: &str, now_s: i64) -> Result<ClearanceClaims, TokenError>;
/// Same checks as `verify` except expiry; for `sub` / `sst` reuse only (§6.5).
pub fn verify_ignoring_expiry(keys: &TokenKeySet, site_id: &str, env: &str, token: &str, now_s: i64) -> Result<ClearanceClaims, TokenError>;
/// (sub, sst) to carry into a new token, or None (§6.5).
pub fn reusable_session(prev: &ClearanceClaims, bind: &BindCheck, now_s: i64, session_max_s: u32) -> Option<(String, i64)>;
pub enum TokenError { TooLong, Footer, UnknownKid, Decrypt, Claims, Site, Env, Binding, Lifetime, NotYetValid, Expired, Rng }
impl TokenError { pub fn status(&self) -> TokenStatus; }               // §6.5 mapping (UnknownKid, Expired -> Expired)
pub fn check_clearance_bind(claims: &ClearanceClaims, current: &BindInputs) -> BindCheck;
pub fn set_cookie_value(token: &str, max_age_s: u32) -> String;           // the Set-Cookie header value
pub fn clearance_cookies<'a>(cookie_headers: &[&'a str]) -> Vec<&'a str>; // at most 2 candidates
```

### 6.8 测试

KAT（`kat.json` 的 `epoch_keys`、`accepted_epochs`、`aad`、`bind`、`ret`、`pow`）；`seal` → `open` 往返；改动 C 的任一字节、换 host、换声明的 type、换站点、过期 → 各自的 `OpenError`；epoch 边界：日界后 125 s 内 `e − 1` 可打开、125.001 s 起不行，`e − 2` 任何时候都不行，`e + 1` 只在日界前 5 s 内可打开；步骤 1 与 4 的每一项长度 / 存在性检查各一个反例（24 字节以外的 `xnonce`、短于 16 字节的 `ct`、缺 `pow`、`difficulty = 33`、缺 `bind.ipp`、15 字节的 `nonce`），都返回错误而不 panic；两个 `Sealer`（同一根密钥，模拟两台 Edge）互相打开；轮换：`[old]` 封装的 C 能被 `[new, old]` 与 `[old, new]` 打开，`[new, old]` 封装的 C 能被 `[old, new]` 打开；`Rng` 失败时 `seal` / `mint` 返回错误；`mint` → `verify` 往返；换站点、换环境、过期、篡改任一字节各自失败；未知 kid 的 `status()` 为 `expired`；`exp − iat > 86400`、缺 `bind.ipp`、`sst > iat` 为 `invalid`；用 verify-only（非首位）kid 签发的凭证仍能通过验证；`sub` / `sst` 复用的真值表（有效、已过期、`uah` 不同、`ipp` 硬失败、`ipp` 软失败、超过 `session_max_s`、别的环境）；绑定比较真值表（§6.4，含 ASN 0）；Cookie 解析（多个 Cookie 头、重复名、超长）；`validate_ret` 正反例（含 `/%5F%5Fmg/c?x=1`、`//__mg/c`、`/a/../__mg/c`）；`testdata/phase1/keys/` 的 `token.keys*.json`、`seal.root*.json` 有效样例被接受，`keys/invalid/` 中对应的样例被拒绝；解析器随机输入不 panic（§2.4）。

## 7. 情报数据（`mg-intel`，WP-R3）

### 7.1 IP 集合

`IpSet`：由 IP / CIDR 文本构建；IPv4-mapped IPv6 条目与查询都还原为 IPv4；内部为排序后合并的区间（IPv4 `u32`、IPv6 `u128`），`contains` 为 O(log n)；至多 1,000,000 条；非法条目报错并带行号。

### 7.2 GeoLite2

- 输入是 `.mmdb` 字节（Edge 从工件缓存读入内存）。`geoip-asn` 的 `database_type` 必须含 `ASN`；`geoip-country` 必须含 `Country` 或 `City`，否则拒绝加载。
- 读取的记录：ASN 库 `autonomous_system_number`、`autonomous_system_organization`；国家库 `country.iso_code`，缺失时取 `registered_country.iso_code`。
- 结果区分三种状态：`Lookup::Found(v)`、`Lookup::NotFound`（库里没有该 IP，映射为 ABSENT 零值）、`Lookup::Unavailable`（没有该库，映射为 MISSING）。ASN 库里 `autonomous_system_number == 0` 的记录也返回 `NotFound`：ASN 0 在 MorphGate 中从不是一个"已知 ASN"（§6.4 `ipa`、§9.7 `asn` 维度）。

### 7.3 爬虫注册表与验证

注册表工件格式见 §12.3。验证结果状态机：

| 情况 | 结果 |
|---|---|
| UA 不匹配任何运营方的 `ua_tokens`（不区分大小写的子串） | `NotClaimed` |
| 客户端 IP 未知 | `Unverifiable { reason: "no_client_ip" }`（05 §3.3：不判冒充） |
| IP ∈ 运营方 `cidrs` | `Verified { method: IpRange }` |
| 模式为 `ip_ranges` 且 IP ∉ `cidrs` | `Failed { method: IpRange }`（同步，D-18） |
| 模式为 `rdns` 或 `ip_ranges_or_rdns`，rDNS 缓存命中 | 缓存中的 `Verified` / `Failed { method: Rdns }` / `Unverifiable { reason: "dns_error" }` |
| 同上，缓存未命中 | `Pending { outside_ranges }`（运营方的 `cidrs` 非空且 IP 不在其中时为 true，D-18），并返回一个 `RdnsJob`；同一 `(ip, operator)` 同时只有一个在途任务，在途期间的请求得到 `Pending` 与 `None` |

**rDNS 算法**（`resolve_rdns`）：PTR 查询 `ip`，取至多 5 个名字；对每个以运营方某个 `rdns_suffixes` 结尾的名字（不区分大小写、去掉末尾点；后缀以 `.` 开头时按标签边界匹配，不以 `.` 开头时要求整名相等）做正向查询（A 与 AAAA）；任一正向结果包含 `ip` → `Pass`；PTR 返回 `NoRecords` 或没有名字匹配 → `Fail`；任何 `Timeout` / `Server` 错误 → `DnsError`。一次 `resolve_rdns` 至多 1 次 PTR + 5 次正向查询。**每次查询**的超时由 `DnsResolver` 实现负责（Edge 的 hickory 实现：`dns_timeout_ms`，§9.6）；调用方另外给整个 future 一个截止时间（Edge：`2 × dns_timeout_ms + 1 s`），超时视为 `DnsError`。

**在途任务**：`check()` 发出任务时记下 `(ip, operator)` 与到期时间 `now + inflight_ttl_ms`（缺省 5 s）；`complete()` 或 `abandon()` 清除它；到期后仍未清除的在途项视为不存在，下一次 `check()` 重新发出任务（任务丢失、被关闭打断或 panic 时不会让该 IP 永远停在 `Pending`）。调用方不执行某个任务时（并发已满、按前缀限流、关闭中）必须调用 `abandon(&job)`。

**缓存**：键 `(ip, operator_id)`；`Pass` 24 h、`Fail` 1 h、`DnsError` 5 min；容量缺省 100,000 项，满时淘汰最早过期的项；所有时间由调用方传入 `now_ms`。

**注册表校验**：`CrawlerRegistry::from_artifact` 执行 §12.3 的全部校验（与 WP-G3 的写入方相同，D-36），任一条不合格即拒绝整个工件；`test: true` 的注册表可以加载，Edge 在日志中警告。

**指标映射**（WP-E1b 记录）：`mg_crawler_verify_total{method="ip_range"|"rdns", result="pass"|"fail"|"unverifiable"}`，`Pending` 不计数，异步结果落定时计数。

### 7.4 DNS 解析器

```rust
pub enum DnsError { Timeout, NoRecords, Server(String) }
pub trait DnsResolver: Send + Sync {
    fn reverse(&self, ip: IpAddr) -> mg_core::BoxFuture<'_, Result<Vec<String>, DnsError>>;
    fn forward(&self, name: &str) -> mg_core::BoxFuture<'_, Result<Vec<IpAddr>, DnsError>>;
}
```

`StaticResolver` 从 JSON 构建（测试与 Validation Lab 用，Edge 配置 `dns_resolver = "static:<path>"`）：

```json
{"v": 1,
 "ptr": {"198.51.100.7": ["crawl-198-51-100-7.googlebot.com."], "198.51.100.8": ["host.example.test."]},
 "a":   {"crawl-198-51-100-7.googlebot.com": ["198.51.100.7"]}}
```

不在表中的查询返回 `NoRecords`。

### 7.5 其他工件

- `cloudflare-ips`（§12.2）→ `IpSet`（v4 + v6）与元数据（`fetched_at`、`etag`）。
- `datacenter-asns`、`tor-exits`（§12.4）→ ASN 集合 / `IpSet`。

### 7.6 公共 API

```rust
// intel/src/ipset.rs
pub struct IpSet { /* ... */ }
impl IpSet {
    pub fn parse<'a, I: IntoIterator<Item = &'a str>>(entries: I) -> Result<Self, IntelError>;
    pub fn from_text(text: &str) -> Result<Self, IntelError>;   // one entry per line, '#' comments
    pub fn contains(&self, ip: IpAddr) -> bool;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}

// intel/src/geo.rs
pub enum Lookup<T> { Found(T), NotFound, Unavailable }
pub struct GeoInfo { pub asn: Lookup<u32>, pub as_org: Lookup<String>, pub country: Lookup<String> }
pub struct GeoDb { /* maxminddb::Reader<Vec<u8>> x2 */ }
impl GeoDb {
    pub fn load(asn_mmdb: Option<Vec<u8>>, country_mmdb: Option<Vec<u8>>) -> Result<Self, IntelError>;
    pub fn empty() -> Self;
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo;
}

// intel/src/crawler.rs
pub enum VerifyMode { IpRanges, Rdns, IpRangesOrRdns }
pub struct Operator { pub id: String, pub name: String, pub purpose: String, pub ua_tokens: Vec<String>,
    pub mode: VerifyMode, pub rdns_suffixes: Vec<String>, pub cidrs: IpSet }
pub struct CrawlerRegistry { /* ... */ }
impl CrawlerRegistry {
    pub fn from_artifact(json: &[u8]) -> Result<Self, IntelError>;   // §12.3, every validation rule
    pub fn is_test(&self) -> bool;                                   // "test": true (documentation ranges allowed)
    pub fn match_ua(&self, ua: &str) -> Option<&Operator>;           // first operator in file order
}
pub enum VerifyMethod { IpRange, Rdns }
pub enum CrawlerStatus {
    NotClaimed,
    Verified { operator: String, purpose: String, method: VerifyMethod },
    Failed { operator: String, purpose: String, method: VerifyMethod },
    Pending { operator: String, purpose: String, outside_ranges: bool },
    Unverifiable { operator: String, purpose: String, reason: &'static str },
}
pub struct RdnsJob { pub ip: IpAddr, pub operator_id: String, pub suffixes: Vec<String> }
pub enum RdnsOutcome { Pass, Fail, DnsError }
pub struct CacheConfig { pub capacity: usize, pub pass_ttl_ms: i64, pub fail_ttl_ms: i64, pub error_ttl_ms: i64,
                         pub inflight_ttl_ms: i64 /* default 5_000 */ }
pub struct CrawlerVerifier { /* registry + cache + in-flight set; Sync */ }
impl CrawlerVerifier {
    pub fn new(registry: std::sync::Arc<CrawlerRegistry>, cache: CacheConfig) -> Self;
    pub fn check(&self, ua: &str, ip: Option<IpAddr>, now_ms: i64) -> (CrawlerStatus, Option<RdnsJob>);
    pub fn complete(&self, job: &RdnsJob, outcome: RdnsOutcome, now_ms: i64);
    /// Releases the in-flight mark without caching a result (the job will not run).
    pub fn abandon(&self, job: &RdnsJob);
    pub fn registry(&self) -> &CrawlerRegistry;
}
pub async fn resolve_rdns(job: &RdnsJob, resolver: &dyn DnsResolver) -> RdnsOutcome;
pub struct StaticResolver { /* ... */ }
impl StaticResolver { pub fn from_json(json: &[u8]) -> Result<Self, IntelError>; }
impl DnsResolver for StaticResolver { /* ... */ }

// intel/src/cfips.rs, intel/src/lists.rs
pub struct CloudflareIps { pub set: IpSet, pub fetched_at: String, pub etag: String }
pub fn parse_cloudflare_ips(json: &[u8]) -> Result<CloudflareIps, IntelError>;
pub fn parse_asn_list(text: &str) -> Result<std::collections::BTreeSet<u32>, IntelError>;

// intel/src/artifact.rs
pub enum ArtifactKind { GeoipAsn, GeoipCountry, CloudflareIps, CrawlerRegistry, DatacenterAsns, TorExits }
impl ArtifactKind { pub fn from_name(name: &str) -> Option<Self>; pub fn max_size(self) -> u64; }
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), IntelError>;
```

### 7.7 测试数据与测试

- 测试用 mmdb 放在 `intel/testdata/mmdb/`：`test-asn.mmdb`（`database_type = "GeoLite2-ASN"`）、`test-country.mmdb`（`"GeoLite2-Country"`），各含几个文档地址段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`）与固定的 ASN / 国家。生成器是 `intel/testdata/mmdb-gen/`（独立 Go module，用 `github.com/maxmind/mmdbwriter`，不在 `go.work` 中，用 `GOWORK=off go run .` 手动运行）；生成的 `.mmdb` 与生成器一起提交，README 写明命令。`make check` 不运行生成器。
- 测试：`IpSet` 边界（/0、/32、/128、映射地址、合并）；GeoDb 的 Found / NotFound / Unavailable，ASN 0 记录为 NotFound；错误 `database_type` 被拒；`testdata/phase1/artifacts/` 的有效样例（`cloudflare-ips.json`、`crawler-registry.json`、`crawler-registry.test.json`、两个文本名单）全部接受，`artifacts/invalid/` 中每个样例都被拒绝；状态机每一行（含 `outside_ranges` 的两种取值）；rDNS 算法（后缀标签边界、正向不含该 IP、多个 PTR、`Timeout` 与 `Server` 都得到 `DnsError`）；缓存 TTL 与淘汰；在途去重、`abandon` 后立即可重新发任务、在途项到期后重新发任务；`StaticResolver`；工件哈希校验；解析器随机输入不 panic。异步函数用 `std::task::Waker::noop()` 与 `Future::poll` 驱动（`StaticResolver` 的 future 立即就绪），不引入执行器（§2.3）。

## 8. 配置

### 8.1 `edge.toml` v1（WP-E1a）

主机本地配置，只含 bootstrap 与主机相关项；策略全部来自签名配置包。未知键一律报错（`deny_unknown_fields`）。Phase 0 的单站点格式不再接受：`config_version` 缺失时报错并提示迁移。

```toml
config_version = 1                         # required, must be 1
edge_id        = "edge-1"                  # required, [a-z0-9][a-z0-9-]{0,31}; logged as DecisionEvent.edge_id
metrics_listen = "127.0.0.1:9901"          # loopback / RFC 1918 / ULA / 100.64.0.0/10 only (Phase 0 rule)
state_dir      = "/var/lib/morphgate"      # required: bundles/<site>.bundle (LKG) + artifacts/<sha256>

[server]                                   # unchanged from Phase 0
threads = 2
pid_file = "/run/morphgate/mg-edge.pid"
upgrade_sock = "/run/morphgate/mg-edge-upgrade.sock"
grace_period_seconds = 10
graceful_shutdown_timeout_seconds = 5

[trust]
owner_keys = ["/etc/morphgate/owner-keys/owner-2026.pub"]   # >= 1 public key file (§12.6)

[[listeners]]                              # >= 1
name = "cf-tunnel"                         # [a-z0-9][a-z0-9-]{0,31}, unique
bind = "127.0.0.1:8080"
profile = "cloudflare"                     # cloudflare | direct_tls
auth = "loopback"                          # cloudflare: loopback (default) | origin_mtls; direct_tls: none (only value)
upstream_keys = "cred://mg-upstream-keys"  # cloudflare only, optional: when set, x-mg-upstream-key is required (§12.7)
# tls_cert / tls_key: required for origin_mtls and direct_tls
# tls_cert = "/etc/morphgate/tls/edge.pem"
# tls_key  = "cred://mg-edge-tls-key"
# client_ca = "/etc/morphgate/tls/owner-aop-ca.pem"   # origin_mtls only, required there
# cloudflare_ip_filter = true                          # origin_mtls only: drop TCP peers outside cloudflare-ips before TLS
# ja4_spike = false                                    # direct_tls only; added by WP-J1 (stage 3)

[[sites]]                                  # >= 1
id = "blog"                                # [a-z0-9][a-z0-9_-]{0,63}
hosts = ["example.com", "www.example.com"] # lower-case, no port; unique across sites; must equal SiteBundle.hosts
listeners = ["cf-tunnel"]                  # listener names that route to this site
origin = "127.0.0.1:3000"                  # plain HTTP origin (Phase 0 rule: not a listener / metrics address)
bundle_root = "file:///srv/mg/"            # file:// | https:// (http:// only to loopback / private / WireGuard hosts), ends with "/"
bundle_poll_seconds = 10                   # 2..300
bootstrap = "open"                         # open | closed: behaviour before this site ever had a bundle (D-21)
token_keys = "cred://mg-blog-token-keys"   # token.keys.json (§12.7)
seal_root = "cred://mg-blog-seal-root"     # seal.root.json (§12.7)

[bundle_client]                            # optional; used for https bundle_root
# ca_file = "/etc/morphgate/brain-ca.pem"
# client_cert = "/etc/morphgate/edge-client.pem"
# client_key = "cred://mg-edge-client-key"
timeout_ms = 5000

[pseudo]
key = "cred://mg-pseudo-key"               # required: pseudo.key.json (§12.7)

[valkey]
mode = "valkey"                            # valkey | local
url = "redis://edge@10.0.0.5:6379/0"       # required for mode = valkey; never contains a password
# password = "cred://mg-valkey-password"   # file with the ACL user's password (one line)
timeout_ms = 10                            # per round trip
connect_timeout_ms = 500
local_replay_authoritative = false         # true only when exactly one Edge serves these sites (§9.7)
local_limiter_capacity = 200000            # in-process GCRA entries; full -> overflow bucket (§9.7)
local_nonce_capacity = 200000              # in-process replay set; never evicts live nonces; full -> unavailable (§9.7)

[events]
# vl_main  = "http://10.0.0.5:9428"        # optional; absent = no VictoriaLogs sink
# vl_short = "http://10.0.0.5:9429"
# file     = "/var/lib/morphgate/events.jsonl"   # optional JSONL sink for tests / the Lab
flush_interval_ms = 1000
max_batch_lines = 1000
max_batch_bytes = 1048576
queue_priority = 8192                      # P0: non-allow decisions, feedback
queue_access = 16384                       # P1: kind=access
queue_sampled = 8192                       # P2: sampled allow decisions, telemetry
stream_maxlen = 300000                     # XADD mg:ev MAXLEN ~

[intel]
dns_resolver = "system"                    # system | static:<path to StaticResolver JSON, §7.4>
dns_timeout_ms = 2000                      # per DNS query
rdns_concurrency = 16
rdns_jobs_per_prefix_per_min = 10          # new rDNS jobs per ip_prefix (§9.6)
rdns_cache_capacity = 100000

[sdk]
dir = "/opt/morphgate/sdk"                 # required: manifest.json + files (§11.1)
```

**校验规则**（`mg-edge --check-config` 执行全部；不访问网络，但读取并解析所有本地文件、凭证与 LKG）：

| 规则 | 说明 |
|---|---|
| 监听器地址 | `cloudflare` + `loopback`：`bind` 必须是回环地址；`origin_mtls` 与 `direct_tls`：必须配 `tls_cert` / `tls_key`，`origin_mtls` 还要 `client_ca`；`bind` 不得与其他监听器、`metrics_listen`、任一 `origin` 相同 |
| 上游密钥头 | `cloudflare` + `loopback` 监听器没有 `upstream_keys`，而它服务的某个站点的 `origin` 是回环地址（Edge 与源站同主机）时**警告**：源站侧的 SSRF 可以伪造 `CF-Connecting-IP` 直接访问 Edge（ADR-0004、08 §2.1），应启用密钥头 |
| 站点 | `hosts` 在站点间不重复；`listeners` 引用存在的监听器（站点 profile 在配置包里，加载配置包时再检查 `upstream.kind` 与每个监听器的 profile 一致，§9.10） |
| `bundle_root` | 以 `/` 结尾；`file://` 目录可读；`http://` 的主机必须是回环、RFC 1918、ULA 或 100.64.0.0/10 地址（与 `metrics_listen` 同规则），否则只接受 `https://` |
| LKG | `state_dir/bundles/<site>.bundle` 存在时，按 §9.10 完整校验（验签、解码、边界、`hosts`、监听器 profile）；任一站点的 LKG 存在但无法使用 → **失败**（退出码 1，指出站点与原因）；LKG 引用的工件不在缓存 → 警告 |
| 凭证引用 | 形如 `cred://<name>`（`name` 为 `[A-Za-z0-9_.-]{1,64}`）解析为 `$CREDENTIALS_DIRECTORY/<name>`；也接受绝对路径。`CREDENTIALS_DIRECTORY` 未设置时使用 `cred://` 是错误。非 credential 路径的密钥文件若对组或其他用户可读，打印警告 |
| 密钥文件 | 解析 `token_keys`、`seal_root`、`pseudo.key`、`upstream_keys`（格式 §12.7，未知字段报错），`site` 字段必须与站点 id 一致 |
| SDK | `sdk/manifest.json` 存在、schema 有效、列出的文件存在且 SHA-256 一致；挑战页模板占位符完整（§11.2） |

`deploy/systemd/edge.toml.example`、`edge/config/edge.dev.toml`、`scripts/edge-smoke.sh`、`edge/tests/shipped_configs.rs` 由 WP-E1a 同步更新；systemd 单元增加 `LoadCredential=`（或 `LoadCredentialEncrypted=`）示例行与 `StateDirectory=morphgate` 的使用说明，并把 `ExecReload=` 的第一行改为 `mg-edge --check-config`（检查失败时不向运行中的进程发 `SIGQUIT`，旧进程继续服务）。

### 8.2 站点 YAML v1（WP-G2）

所有者手写、`mgctl bundle build` 的输入。未知键报错；不支持 YAML 锚点与多文档（与策略文件相同）；相对路径相对于该 YAML 文件所在目录。

```yaml
version: 1
site: blog                            # [a-z0-9][a-z0-9_-]{0,63}
profile: cloudflare                   # cloudflare | direct_tls
hosts: [example.com, www.example.com, staging.example.com]
allowed_listeners: [cf-tunnel]
monitor_only: true                    # default true: Phase 1 runs in monitor mode first
# not_before: "2026-10-01T00:00:00Z"  # optional delayed activation
share_ip_verdicts: false
case_insensitive_paths: false         # true: route patterns and paths compared lower-cased (D-25)

cloudflare:                           # required iff profile == cloudflare
  zone: example.com
  location_headers: true              # set only after `mgctl cf audit` confirms the Managed Transform is on
  tier1: false
  owner_zones: [example.com]
  pseudo_ipv4_overwrite: false
  origin_mode: tunnel                 # tunnel | aop — used by `mgctl cf audit` only, not bundled
  # account_id: "..."                 # optional, cf audit: tunnel status
  # tunnel_id: "..."

token:
  active_kid: blog-t-20260927         # must exist in the site's token.keys.json on every Edge
  verify_kids: []                     # previous kids still accepted during rotation

clearance: {ttl_invisible_s: 1800, ttl_pow_s: 1800, session_max_s: 86400, ctp_shadow: true}
challenge:
  ttl_s: 120
  pow_bits: {low: 14, medium: 16, high: 18, very_high: 20}
  fallback_ret: /
  max_failures: 5                     # per ip entity; the per-ipp ceiling is 4x (D-28)
  failure_window_s: 600
  submit: {rate: 30, period_s: 60, burst: 10}
  issue: {per_ipp: 60, per_asn: 600, period_s: 3600}   # enforced (D-37)
scoring:
  theta_c: 0.4
  kappa: 0                            # 0 = profile default
  z0: {low: -2.197, medium: -1.735, high: -1.386, critical: -1.099}
  family_modes: {edge_tls: shadow}
  weights: {}                         # e.g. {"http.ua_library": 2.0}
  h_min: -4.0
  ruleset_version: v1
crawlers:
  default_action: allow               # allow | block
  purposes: {ai_training: block}      # search | ai_training | ai_search | user_triggered | archive | other
events: {allow_sample_rate: 0.1, access_log: true, stream: true}
origin_headers: {scores: true, reasons: false, session: true}
lists:
  owner_cidrs: [203.0.113.0/24]
list_files: {}                        # name -> text file, one entry per line, '#' comments
artifacts:                            # all optional
  geoip_asn: /var/lib/geoip/GeoLite2-ASN.mmdb
  geoip_country: /var/lib/geoip/GeoLite2-Country.mmdb
  cloudflare_ips: intel/cloudflare-ips.json
  crawler_registry: intel/crawler-registry.json
  # datacenter_asns: intel/datacenter-asns.txt
  # tor_exits: intel/tor-exits.txt

environments:
  - name: production                  # production | staging | test | dev
    hosts: [example.com, www.example.com]
    policies: [policies/production.yaml]   # may be empty
    routes:                           # "default" (/**, low, web) is appended if absent; matching: §9.4
      - name: login                   # [a-z0-9_-]{1,32}
        paths: ["/account/login", "/api/login"]
        methods: [GET, POST]          # optional; default any
        channel: web                  # web | api | mobile
        sensitivity: critical         # low | medium | high | critical
        require_clearance: true       # default: true iff sensitivity == critical
        fail_closed: true             # default: true iff sensitivity == critical
      - name: reset
        paths: ["/account/reset/**"]
        sensitivity: high
        redact_path: true             # events log "/reset" instead of the tokenized path (D-31)
      - name: api
        paths: ["/api/**"]
        channel: api
        sensitivity: medium
    rate_limits:
      - id: login-per-ip
        routes: [login]               # empty = every route of this environment
        key: [ip]                     # ip | ip_prefix | asn | session | route (ip = ip entity, D-24)
        rate: 20/1m                   # <n>/<duration>, duration = [<n>]s|m|h, e.g. 5/15m, 600/1m, 10/s
        burst: 5                      # default 1
        scope: global                 # global | local
        on_exceed: {action: rate_limit, retry_after_s: 60}   # signal{weight} | challenge{type} | rate_limit{retry_after_s} | block
        mode: enforce                 # enforce | dry_run
  - name: staging
    hosts: [staging.example.com]
    policies: [policies/staging.yaml]
    automation_allowlist_only: true
```

**校验规则**（错误级；WP-C2 在 Edge 加载配置包时对进入配置包的项再做一遍，任一不满足即拒绝整个配置包）：

| 项 | 规则 |
|---|---|
| 环境与主机 | 环境的 `hosts` 恰好划分站点 `hosts`；每个环境至多 64 个路由、64 个限速器 |
| 路由 | 路由名在环境内唯一；`paths` 1–16 项，每项以 `/` 开头、只含可见 ASCII、≤ 128 字节、至多 4 个通配符（`*`、`**` 算一个、`?`）；`methods` 为大写 HTTP 方法；`case_insensitive_paths` 时模式按小写存入配置包 |
| 限速器 | id 匹配 `[a-z0-9][a-z0-9_.-]{0,63}` 且不以 `mg.` 开头；`rate` 解析后 `1 ≤ rate`、`1 ≤ period_s ≤ 86400`、`1 ≤ burst ≤ 100000`，且 `GcraParams::new(rate, period_s, burst)` 不为 `None`（即 `interval_us · burst ≤ 7 天`，保证 Lua 中的数值 < 2^53）；`signal.weight ∈ (0, 2]`；`challenge.type ∈ {invisible, pow}` |
| `challenge` | `10 ≤ ttl_s ≤ 120`；`pow_bits` 每项 8–24；`fallback_ret` 通过 `validate_ret`（§6.4）；`1 ≤ max_failures ≤ 1000`、`60 ≤ failure_window_s ≤ 86400`；`submit`、`issue` 各自满足限速器的数值规则 |
| `clearance` | `60 ≤ ttl_invisible_s, ttl_pow_s ≤ 86400`；`ttl ≤ session_max_s ≤ 30 天` |
| 策略 | 文件存在、`profile:` 与站点一致或未声明；每条规则的 `CheckedRule.Lists` 都在 `lists` 或 `list_files` 中；每个名单 ≤ 10,000 条、每条 ≤ 256 字节；`tarpit` 动作报错（D-09）；`params.type: interactive` 告警（D-08）；静态步数上界 > 100,000 的规则报错（§5.2） |
| 其他 | `token.active_kid` 与 `verify_kids` 匹配 `[a-z0-9][a-z0-9._-]{0,63}`；序列化后的配置包 ≤ 8 MiB |

### 8.3 站点 YAML → SiteBundle 与缺省值（WP-G2 构建、WP-C2 校验、WP-E1 回填）

| SiteBundle 字段 | 来源 / 缺省 |
|---|---|
| `schema_version` | 1 |
| `version` | `--version`，缺省为构建时的 Unix 秒 |
| `created_at_ms` | 构建时间 |
| `upstream.kind` / `expected_mask` | profile；`cloudflare`：NETWORK \| HTTP \| EDGE_TLS \| IDENTITY \| RATE \| EXTERNAL；`direct_tls`：NETWORK \| TLS \| HTTP \| IDENTITY \| RATE |
| `case_insensitive_paths` | YAML 同名键，缺省 false |
| `environments[].routes` | 声明顺序；末尾追加 `{id: "default", name: "default", paths: ["/**"], channel: WEB, sensitivity: LOW}`（除非已有 `paths == ["/**"]` 的路由）；`Route.id = Route.name`；`redact_path` 缺省 false |
| `environments[].rules` | 该环境所有策略文件的规则，去掉 `mode: disabled` 与已过期的，按 §5.4 排序；`expr_ir` 由 `CheckedRule.Proto()` 填入。**任一规则 `ir_version != 1` 或 `expr_ir` 为空时 `Build` 失败**（错误 `policy IR unavailable`），所以 WP-G1 合入前的构建器不会产生 Edge 无法加载的配置包 |
| `environments[].rate_limits` | 声明顺序；`algorithm = "gcra"`；`route_ids` 为空表示全部路由 |
| `token_key_ids` | `[active_kid] + verify_kids` |
| `challenge` | `ttl_s` 120、`pow_bits` 14/16/18/20、`fallback_ret` `/`、`max_failures` 5、`failure_window_s` 600、`submit_*` 30/60/10、`issue_*` 60/600/3600 |
| `clearance` | 1800 / 1800 / 86400 / `ctp_shadow = true` |
| `scoring` | §5.7 的初始值；`family_modes` 缺省 `{edge_tls: shadow}` |
| `crawler_policy` | `default_action` 缺省 `allow` |
| `events` | `allow_sample_rate` 0.1、`access_log` true、`stream` true |
| `origin_headers` | `scores` true、`reasons` false、`session` true |
| `lists` | `lists` 与 `list_files` 合并（同名报错）；`Build` 另外检查每条规则 IR 中的 `named_list` 名都在其中（兜底） |
| `artifacts` | 每个配置的工件：`name`（§12.1 表）、`uri = "artifacts/<sha256>"`、`sha256`、`size`、`version`（JSON 工件取 `fetched_at` / `generated_at`；mmdb 取其元数据 `build_epoch`，用 `maxminddb-golang/v2` 读取，并按 §7.2 的规则检查 `database_type`，不符即构建失败）；JSON 与文本工件在构建时按 §12 校验 |
| `source_digest` | `sha256`（小写十六进制）依次覆盖：站点 YAML 字节、每个策略文件字节、每个名单文件字节（按出现顺序） |

**缺省值与 proto3**：proto3 的标量无法区分"未设置"与零值（`ctp_shadow = false`、`theta_c = 0` 都是合法的显式值）。所以构建器**总是**写出完整填充的 `challenge`、`clearance`、`scoring`、`crawler_policy`、`events`、`origin_headers` 消息；Edge 只在整条消息缺失（prost 的 `Option` 为 `None`）时用上表缺省值回填，从不按字段回填。WP-G2 用一个最小站点 YAML 测试这些消息全部存在且字段等于上表。

## 9. Edge 行为规范（`mg-edge-core` WP-C1–C4，`mg-edge` WP-E1a–E1d）

### 9.1 模块划分

**`mg-edge-core`**（阶段 1，不依赖 Pingora；输入是普通 Rust 类型：头名 / 值切片、`SocketAddr`、字节）：

| 模块 | 职责 | WP |
|---|---|---|
| `upstream` | 头族判定（§9.3）、`Connection` 列出的头、`cloudflare` 可信头解析为 `CfHeaders`、`CF-Worker` 所属 zone 判定、Tier 1 标记 | C1 |
| `request` | 协议输入上限（§9.3.1）、Host / `:authority` / 绝对形式一致性与规范化（§9.4）、`header_order` | C1 |
| `bundle` | 配置包拉取（`file://` / HTTP(S) + ETag）、Ed25519 验签、结构与边界校验（§8.2 中进入配置包的项）、LKG 读写、工件缓存与校验、轮询循环 | C2 |
| `state` | Valkey 连接与管线、`mg_gcra` / `mg_nonce_issue` 脚本、verdict `MGET`、熔断、本地模式（GCRA 表、重放集合）、异步失败计数通道 | C3 |
| `events` | `EventSink`、三级队列、VictoriaLogs 批量发送与重试、文件出口、`mg:ev` 条目编码 | C4 |
| `testkit`（特性） | Valkey 夹具与故障注入转发器（C3）、HTTP 配置包服务器（C2）、伪 VictoriaLogs（C4） | C2–C4 |

**`mg-edge`**（阶段 2）：

| 模块 | 职责 | WP |
|---|---|---|
| `config.rs`、`creds.rs`、`main.rs`、`server.rs` | `edge.toml` v1、`cred://`、密钥文件加载、`--check-config`、进程与运行时模型（§9.1.1） | E1a |
| `listener.rs`、`tls.rs` | 每个监听器一个 proxy service；`EdgeTlsAccept`（§9.2）；`ConnectionFilter` | E1a |
| `sites.rs` | 站点状态机（§9.10）、配置包 → 站点运行时（规则、名单、路由、限速器、密钥集、工件）、路由匹配（§9.4） | E1a |
| `proxy.rs`、`headers.rs`、`routes.rs`、`enforce.rs` | 请求流水线骨架、monitor / bootstrap 转发、源站 `MG-*` 头（§9.9） | E1a |
| `context.rs` | `RequestContext`、`RequestExtras`、`MissingSet`、`Activation` 输入（§9.5） | E1b |
| `identity.rs`、`dns.rs` | 凭证校验、爬虫验证与 rDNS 任务；hickory 实现 `DnsResolver`（§9.6） | E1b |
| `ratelimit.rs`、`decide.rs` | 限速器集合与状态层接线（§9.8）；组装 `DecisionCore` 与 `SitePolicy`；阻断 / 429 页 | E1b |
| `challenge.rs`、`pages.rs`、`mg_endpoints.rs` | Challenge 签发、挑战页与 JSON、`/__mg/c`、`/__mg/s/*`（§10） | E1c |
| `events.rs`、`metrics.rs` | 事件组装与接线（§9.11、§13）、完整指标、附加延迟（§13.7） | E1d |

#### 9.1.1 进程与运行时模型（规范）

Pingora 0.9 的 `Server::run_forever()` 在守护进程模式（`-d`，systemd 单元用 `Type=forking`）下先 `fork`，之后才为每个 service 创建 tokio 运行时。`fork` 之前创建的线程与运行时在子进程中不存在，所以：

1. `main()` 只做同步工作：解析参数与 `edge.toml`，读凭证与密钥文件，读取并校验 LKG 文件与已缓存的工件（C2 的校验函数是同步的），为每个站点构造初始运行时（`active` / `bootstrap` / `lkg_invalid`，§9.10），注册指标，创建有界队列与共享句柄。可以在 `main()` 中创建的只有不需要运行时的对象：`Arc<ArcSwap<…>>`、`tokio::sync::mpsc` 通道（发送端用 `try_send`）、原子量。
2. 所有异步客户端与循环在 Pingora `BackgroundService` 中创建与运行（守护进程化之后）：
   - `mg-state`：Valkey `ConnectionManager`、`SCRIPT LOAD`、熔断与健康探测、异步失败计数的消费者。**Valkey I/O 只在这个 service 的运行时上发生**：proxy 通过有界 `mpsc` 发送 `StateRequest`，在 `timeout_ms` 内等待 `oneshot` 回复（超时即按本地模式处理，§9.7）。这样 redis-rs 的连接驱动与重连任务不会落在 proxy 的运行时上。
   - `mg-bundles`：每个站点的轮询循环（C2 的 `poll` 函数），通过 `ArcSwap<SiteRuntime>` 切换站点运行时。
   - `mg-events`：flusher（C4），同一个 service 内持有 reqwest 客户端；`mg:ev` 的 `XADD` 批次交给 `mg-state` 执行。
   - `mg-rdns`：hickory 解析器与 rDNS 任务执行者；proxy 用有界 `mpsc` 提交 `RdnsJob`，满则 `abandon`（§9.6）。
3. proxy service 不依赖后台 service 就绪：`mg-state` 就绪前按本地模式处理，`mg-events` 就绪前事件进入队列，`mg-rdns` 就绪前任务被放弃。
4. 关闭：后台 service 在 Pingora 的关闭信号后停止；flusher 在退出前尽力发送队列中剩余的 P0 记录（至多 2 s）。`-u`（平滑升级）启动的新进程从 `state_dir` 读 LKG，配置不会回退到 bootstrap；进程内重放集合的交接见 §9.7（D-35）。
5. 测试：`scripts/edge-smoke.sh` 以 `-d` 启动 mg-edge，断言守护进程化之后配置包轮询（发布新版本后 `mg_config_version` 变化）与事件写出（`events.file` 收到行）仍在发生（WP-E1d）。

### 9.2 监听器与上游认证

| 情况 | 行为 |
|---|---|
| 每个 `[[listeners]]` | 一个 `http_proxy_service`，`EdgeProxy` 持有监听器名与 profile |
| `cloudflare` + `loopback` | TCP 对端必须是回环地址，否则 403（`reason="non_loopback_peer"`）；认证通过，`auth_method = loopback` |
| 配置了 `upstream_keys` | 请求必须带 `x-mg-upstream-key`，与密钥文件中任一值常量时间相等；否则 403 纯文本 `forbidden`、`no-store`，计 `reason="bad_secret_header"`，不回退为直连处理；通过时 `auth_method = secret_header` |
| TLS 监听器的构造 | `origin_mtls` 与 `direct_tls` 都用 `TlsSettings::with_callbacks(Box::new(EdgeTlsAccept{..}))` 构造，再通过 `DerefMut` 在上下文上设置证书链与私钥（`set_certificate_chain_file`、`set_private_key_file`）、ALPN（`h2`、`http/1.1`）与客户端验证。Pingora 只在 `with_callbacks` 的设置下调用 `handshake_complete_callback`；`EdgeTlsAccept` 的 `certificate_callback` 什么也不做，它的 `handshake_complete_callback` 返回 `Arc<TlsFacts { sni, alpn }>`，经 `SslDigest.extension` 到达请求过滤器。WP-J1 在 `edge/src/tls/` 中扩展同一个结构（加 JA4），不另起一套构造 |
| `cloudflare` + `origin_mtls` | BoringSSL：`SslVerifyMode::PEER \| FAIL_IF_NO_PEER_CERT`，信任 `client_ca`；握手失败即断开；验证回调对链上每张证书各调用一次，所以 `reason="untrusted_ca"` 只在深度 0 的失败时计一次（每个握手至多一次）；`auth_method = origin_mtls` |
| `cloudflare_ip_filter` | 启用 pingora 特性 `connection_filter`；`should_accept(peer)` 查当前所有站点 `cloudflare-ips` 工件的并集；尚无工件时放行并把 `mg_cf_ip_filter_active` 置 0 |
| `direct_tls` | TLS 监听，`auth_method = none`，删除全部上游头族，客户端 IP = TCP 对端 |
| 失败计数 | `mg_upstream_auth_failures_total{listener, profile, reason}` |

### 9.3 头部清洗与可信头解析（WP-C1 实现，WP-E1a 接线）

**头族**（名称先转小写，并把 `_` 换成 `-` 再匹配；因此 `CF_Connecting_IP`、`X_MG_CF_ASN` 同样命中）：前缀 `cf-`、`x-mg-`、`cloudfront-`、`ali-`、`esa-`、`eo-`、`x-forwarded-`、`mg-`；全名 `tls-ja3`、`tls-ja4`、`tls-hash`、`x-forward-port`、`forwarded`、`true-client-ip`、`x-real-ip`。

**处理顺序**：

1. 协议输入上限（§9.3.1）。
2. 记下客户端头名（`direct_tls` 的 `http.header_names` 与 `header_order`：不重复的名称，按首次出现顺序，保留原大小写）。
3. 删除客户端的 `Connection` 头以及它列出的每个头名（逐跳头；防止客户端用 `Connection: MG-Client-IP, X-Forwarded-For` 让 Edge 写入的头在转发时被删掉）；`Keep-Alive`、`Proxy-Connection`、`TE`、`Upgrade`（非 WebSocket 升级时）同样删除。
4. 认证通过的 `cloudflare` 请求：只按下表解析**精确的连字符小写名**；下划线变体永不解析。
5. 从请求中删除所有命中头族的头（包括认证通过时 Cloudflare 添加的），然后为源站重新写入 §9.9 规定的头。`direct_tls`（或未认证）请求只要带了任一头族，计一次 `mg_upstream_headers_stripped_total{profile}`。

**`cloudflare` 解析表**（值非法按缺失处理；"告警"指计入 `mg_upstream_signal_missing_total{profile="cloudflare", signal}`，`signal` 取头名去掉 `x-mg-cf-` 前缀）：

| 头 | 校验 | 目标 | 缺失 / 非法时 |
|---|---|---|---|
| `cf-connecting-ip` | 严格解析为 IP（无端口、无方括号）；映射地址还原 | `net.ip`、`ip_source = cf_connecting_ip` | 客户端 IP 未知（§9.3.2）：`client_ip_header_missing = true`，计 `mg_cf_connecting_ip_missing_total{site}` |
| `cf-connecting-ipv6` | 同上，必须是 IPv6 | 仅 `pseudo_ipv4_overwrite` 时优先使用，`ip_source = cf_connecting_ipv6` | 回退 `cf-connecting-ip` |
| `cf-ray` | `[A-Za-z0-9-]{1,64}` | `upstream.cf_ray` | 忽略 |
| `cf-visitor` | JSON `{"scheme":"http"\|"https"}`，≤ 64 字节 | 访客协议（TLS 字段的条件性、`X-Forwarded-Proto`、§9.9 的 308） | 视为 https |
| `cf-worker` | 小写 zone 名 ≤ 253；非法值视为外部 zone | 存在且不在 `cloudflare.owner_zones` → 请求在 §9.4 被 403 拒绝（D-23） | — |
| `cf-ipcountry` | `[A-Z]{2}`；`XX` 视为缺失；`T1` → `net.tor` 来源之一 | `net.upstream_country` | 仅 `location_headers` 时解析 |
| `cf-region`、`cf-region-code`、`cf-timezone` | ≤ 64 字节可见 ASCII；时区 `[A-Za-z0-9/_+-]{1,64}` | `net.upstream_region`（取 region-code）、`upstream_timezone` | 同上；`cf-ipcity`、经纬度、邮编等一律丢弃 |
| `x-mg-cf-tls-version` | `[A-Za-z0-9._-]{1,16}` | `edge_tls.version` | 访客 scheme 为 https 时告警 |
| `x-mg-cf-tls-cipher` | `[A-Za-z0-9_-]{1,64}` | `edge_tls.cipher` | 同上 |
| `x-mg-cf-tls-ciphers-sha1`、`-tls-ext-sha1` | base64，解码后 20 字节 | `edge_tls.ciphers_sha1`、`ext_sha1` | 同上 |
| `x-mg-cf-tls-hello-len` | 十进制 1–65535 | `edge_tls.hello_len` | 同上 |
| `x-mg-cf-tls-random` | base64，解码后 32 字节 | Phase 1 只校验（`client_conn_key` 在 Phase 2 近线使用），值不进任何结构、不进日志 | 同上 |
| `x-mg-cf-http-version` | `HTTP/1.0`、`HTTP/1.1`、`HTTP/2`、`HTTP/3` | `http.version`、`version_source = cloudflare` | 告警 |
| `x-mg-cf-rtt` / `-quic-rtt` | 十进制 0–60000；`0` 视为缺失 | `net.rtt_ms`（HTTP/3 用 quic，其余用 tcp） | 对应的那一个缺失时告警 |
| `x-mg-cf-asn` | 十进制 1–4294967295 | `net.upstream_asn` | 告警 |
| `x-mg-cf-vbot` | `true` / `false` | `identity.crawler.cf_vbot` | 告警 |
| `x-mg-cf-vbot-cat` | `[A-Za-z0-9 ()/&.,_-]{1,64}` | `identity.crawler.cf_vbot_cat` | 不告警（非爬虫时本来就没有） |
| `x-mg-cf-hdr-names` | 逗号分隔，每项为 1–64 个 HTTP token 字符（RFC 9110 `tchar`），至多 128 项 | `http.header_names`（集合语义，保留原大小写） | 告警 |
| `x-mg-cf-t1` | `snippet` / `worker` | 仅 `cloudflare.tier1` 且标记有效时解析下面三项 | Tier 1 全部 MISSING，不告警 |
| `x-mg-cf-priority` | `[A-Za-z0-9=;,._-]{1,128}` | `http.priority` | MISSING |
| `x-mg-cf-accept-encoding` | ≤ 256 字节可见 ASCII | `http.accept_encoding_orig` | MISSING |
| `x-mg-cf-as-org` | 百分号解码后为 UTF-8，≤ 256 字节 | `net.as_org` 的交叉校验值（Phase 1 只记录） | MISSING |
| `x-mg-upstream-key` | §9.2 | — | — |

#### 9.3.1 协议输入上限（D-26）

在解析可信头与决策之前检查（不同头名的个数在 §9.3 第 5 步清洗之后检查）；拒绝在所有模式下执行（包括 monitor 与 bootstrap），因为它们是策略输入的不变量（§4.1 大小上限），不是策略决定。响应为 Edge 生成的纯文本（§9.9 的通用头），计 `mg_protocol_rejected_total{listener, reason}`，写访问记录（`route = "__protocol"`），不产生决定事件。

| 条件 | 响应 | `reason` |
|---|---|---|
| 路径（不含查询串）> 8192 字节，或查询串 > 8192 字节 | 414 | `uri_too_long` |
| 任一头值 > 8192 字节（`cookie`、`authorization`、`proxy-authorization` 除外；Cookie 的解析只看前 16 KiB，§6.6）；同名头以 `", "` 连接后 > 8192 字节；头名 > 256 字节；清洗后（§9.3 第 5 步之后）不同头名超过 128 个 | 431 | `header_too_large` |
| 方法不是 1–32 个 `tchar` | 400 | `bad_method` |
| `Host` 与 `:authority` 或绝对形式请求目标的主机不一致、缺少 Host、Host 不是合法主机名（§9.4） | 400 | `bad_host` |

Cloudflare 自身的上限（URL 约 16 KiB、请求头合计约 32 KiB）比这里宽；常见源站（如 nginx 的 8 KiB 请求行缓冲）已经拒绝这些请求，所以这些拒绝不影响正常访客。

#### 9.3.2 客户端 IP 未知（D-23）

**原则：客户端 IP 未知时，Edge 从不比 IP 已知时更宽松。** `cloudflare` profile 下 Cloudflare 总会写入 `CF-Connecting-IP`，所以"IP 未知"只来自配置错误（有告警），或来自外部 zone 的 Worker 子请求——后者任何 Cloudflare 账号都能发出，因此直接拒绝。具体规则：

| 情况 | 行为 |
|---|---|
| 带 `CF-Worker` 且其 zone 不在 `owner_zones`（含值非法） | §9.4 第 4 步：403 纯文本 `forbidden`、`no-store`，计 `mg_cf_foreign_worker_total{site}`，写访问记录；不进入决策（ADR-0004、08 §2.2、10 CF-02） |
| 认证通过但 `CF-Connecting-IP` 缺失或非法 | 继续处理，`net.ip` 与 NETWORK 族 MISSING，加 label `client_ip_unknown`，计 `mg_cf_connecting_ip_missing_total{site}`（应恒为 0，§17 告警） |
| 限速维度 `ip` / `ip_prefix` / `asn` 未知 | 使用共享兜底值 `?`（§9.7），不跳过限速器；内置限速器同样适用 |
| 决定为 CHALLENGE | 不签发 C：429 + `Retry-After: 5`，`rule_id = "hard.client_ip_unknown"`（§9.9） |
| `POST /__mg/c` | 429 + `Retry-After: 5`，reason `ic.no_client_ip`，不签发凭证（§10.3） |
| 带凭证 | `ipp` 比较结果为 `mismatch` → `binding_mismatch`（§6.4），因此不会作为有效凭证 |
| `fail_closed` 路由 | 429（§9.9） |
| 爬虫声明 | `Unverifiable`，BotClass 为 `DECLARED_AGENT`，永远不会是 `VERIFIED_CRAWLER` |
| 源站头 | `MG-Client-IP: unknown`；删除 `X-Forwarded-For`；不转发 `CF-Connecting-IP`（§9.9） |

规则读取 `net.ip` 时得到 UNKNOWN（记 `missing_input`，不命中）；需要在这种情况下动作的策略用 `!has(net.ip)` 显式处理。

### 9.4 站点、环境与路由

1. **Host**（C1 的 `request` 模块）：HTTP/1 取 `Host` 头，HTTP/2 取 `:authority`；两者都在时必须一致；请求目标是绝对形式时其主机也必须一致；否则 400（§9.3.1）。规范化：小写、去端口与末尾点，必须是合法 DNS 主机名或 IP 字面量，≤ 253 字节。不在任何站点 `hosts` 中 → 404 纯文本 `unknown site`、`no-store`，计 `mg_unknown_host_total{listener}`。发往源站的请求的 `Host` 设为这个规范化主机名（§9.9）。
2. **监听器**必须同时在 `edge.toml` 站点的 `listeners` 与配置包的 `allowed_listeners` 中（尚无配置包时只看前者），否则 403 并计 `mg_listener_rejected_total{listener, site}`。
3. **站点状态**（§9.10）：`lkg_invalid` 或 `bootstrap = "closed"` 的 `bootstrap` → 503 纯文本、`Retry-After: 30`，计 `mg_site_unavailable_total{site}`（`/__mg/healthz` 照常）；`bootstrap = "open"` 继续。
4. **外部 Worker**：`cloudflare` 且 `CF-Worker` 存在但不属于 `owner_zones` → 403（§9.3.2）。bootstrap 状态下没有 `owner_zones`：任何 `CF-Worker` 都视为外部。
5. **环境**：`hosts` 含该 Host 的环境。
6. **路由**（D-25）：去掉查询串后，用 `mg_core::paths::route_candidates(path, site.case_insensitive_paths)` 得到候选串（原始路径、`rfc3986_view`、`cloudflare_view`、`decoded_view`，各自再加切换末尾 `/` 的形式，去重）。对每个候选串，按声明顺序找第一个命中的路由：`hosts` 为空或含该 Host、`methods` 为空或含该方法、任一 `paths` 模式（`mg_core::policy::Glob`，§5.3 语义）命中。所有候选串命中的路由中，取**敏感度最高**者为选中路由（相同时取声明在前者）；其 `RouteInfo.require_clearance` 与 `fail_closed` 是所有命中路由对应值的"或"。都不命中时用 `default`。
   - 例：`paths: ["/account/login"]` 的 `critical` 路由同样命中 `/account/login/`、`/account%2Flogin`、`/account/login;jsessionid=1`、`//account/./login`；`case_insensitive_paths` 时还命中 `/Account/Login`。
   - 成本：路由匹配不经过 IR 求值器，不计步数（§5.3）；§8.2 的上限（每环境 ≤ 64 个路由、每个 ≤ 16 个模式、模式 ≤ 128 字节且至多 4 个通配符）加上 8 KiB 路径上限约束了最坏情况；`Glob::matches` 先比较字面前缀，只有前缀命中才运行 DP；相同的候选串只匹配一次。
   - `/__mg/*` 在第 4 步之后、第 5 步之前分派（§10.1）；归属仍按 `mg_core::paths::is_reserved`（原始路径与 Cloudflare 的两种规范化），不用 `decoded_view`。

### 9.5 RequestContext 构建（WP-E1b）

| 字段 | 来源 |
|---|---|
| `request_id` | 32 个小写十六进制字符（128 位，`getrandom`；失败时 503，不 panic） |
| `ts_ms` | 请求到达时间 |
| `site_id`、`env`、`route_id`、`channel` | §9.4（`route_id` 为选中路由） |
| `upstream` | `profile`、`authenticated`、`auth_method`、`cf_ray`、`client_ip_header_missing` |
| `net` | `ip` / `ip_prefix` / `ip_source`；`asn` / `as_org` / `country`（GeoLite2，§7.2）；`conn_type`、`tor`（§4.1）；`upstream_*`、`rtt_ms`（§9.3） |
| `tls` | `direct_tls`：`available = true`、`version`（`SslDigest`）、`alpn` 与 `sni`（`EdgeTlsAccept` 的 `TlsFacts`，§9.2）；`ja4` 为空（WP-J1 在 `ja4_spike = true` 的监听器上只写入事件，D-07） |
| `edge_tls` | §9.3（`cloudflare` 且至少一项有值时为 `Some`） |
| `http` | `version` / `version_source`；`method`、`host`、`path`（原始；路由 `redact_path` 时事件中改写，§9.11）；`query_keys`（至多 32 个，每个 ≤ 64 字节）；`header_order`（§4.1）；`header_names`；`user_agent`（≤ 512 字节）；`cookie_names`（至多 32 个，排除 Cloudflare Cookie `__cf_bm`、`cf_clearance`、`_cfuvid`、`__cflb`、`__cfseq`、`__cfwaitingroom`、`cf_chl_*` 与 `__Host-mg_clr`）；`body_size`（`Content-Length`）；`content_type`（`;` 之前，≤ 64 字节）；`early_data`（`Early-Data: 1`）；Tier 1 字段 |
| `identity.token` | §9.6 |
| `identity.proof`、`agent` | 缺省（Phase 1 MISSING） |
| `identity.crawler` | §9.6 |
| `session_id` | 有效凭证的 `sub` |
| `availability_mask` | 本请求至少有一个 PRESENT 信号的族（Decision Core 运行后回填） |
| `expected_mask` | 配置包 `upstream.expected_mask` |
| `client` | `None`（Phase 1） |
| `verdicts` | §9.7 MGET 得到的 EntityVerdict |

事件中的 `ctx` 与内存中的一致（上面的截断规则已经保证了事件大小），唯一的改写是 `redact_path`。`RequestExtras.headers` 按 §4.1 `req.headers` 规则构建；`RequestExtras.secure_context` 为访客使用 https（`direct_tls`，或 `cf-visitor` 的 scheme 为 https）。

### 9.6 身份（WP-E1b）

- **凭证**：取 Cookie 候选（§6.6），`mg_challenge::verify` 验证；再以当前请求算出 `BindInputs`（`uah` 来自 `mg_core::ua::parse`；`ipp` 在 IP 已知时；`ipa` 在 ASN 已知且不为 0 时；`ctp` 在 `ctp_shadow` 且四项齐全时）做 `check_clearance_bind`。结果写入 `identity.token`（`status`、`level`、`age`、`bind`），状态映射按 §6.5（未知 kid → `expired`），计 `mg_token_verify_total{result}`（`none` / `valid` / `expired` / `invalid` / `binding_mismatch`）。
- **爬虫**：配置包含 `crawler-registry` 工件时，用 `CrawlerVerifier::check(ua, ip, now)`。返回 `RdnsJob` 时：若该 `ip_prefix` 在最近一分钟内新建的任务已达 `rdns_jobs_per_prefix_per_min`（进程内 GCRA，§9.7 的本地表）、在途任务数已达 `rdns_concurrency`，或向 `mg-rdns` 的提交队列已满，则 `abandon(&job)` 并计 `mg_rdns_lookups_total{result="dropped"}`（§17 告警）；否则提交给 `mg-rdns`，它在任务外包一个 `2 × dns_timeout_ms + 1 s` 的整体截止时间执行 `resolve_rdns`，然后 `complete(job, outcome, now)`；任务被取消、超时或 panic 时由 drop guard 调用 `abandon`。映射：

| `CrawlerStatus` | `claimed` | `operator` / `purpose` | `verified` | `verification` | `method` | `outside_ranges` |
|---|---|---|---|---|---|---|
| `NotClaimed` | false | 空 | false | `none` | 空 | false |
| `Verified` | true | 运营方 | true | `verified` | `ip_range` / `rdns` | false |
| `Failed` | true | 运营方 | false | `failed` | `ip_range` / `rdns` | false |
| `Pending` | true | 运营方 | false | `pending` | 空 | 同 `CrawlerStatus` |
| `Unverifiable` | true | 运营方 | false | `unverifiable` | 空 | false |

  同时按 05 §3.4 计 `mg_cf_vbot_disagree_total{direction}`：`verified` 且 `cf_vbot == false` → `mg_pass_cf_false`；`failed` 且 `cf_vbot == true` → `mg_fail_cf_true`。
- **hickory**：`dns.rs` 用 `hickory_resolver` 的 tokio 解析器与系统配置（`/etc/resolv.conf`）实现 `DnsResolver`，`ResolverOpts { timeout: dns_timeout_ms, attempts: 1 }`，并对每次 `reverse` / `forward` 调用再包一层 `tokio::time::timeout(dns_timeout_ms)`（超时 → `DnsError::Timeout`）。hickory 0.26 的正向查询缺省同时查 AAAA 与 A（`Ipv6AndIpv4`），不需要另查。错误映射：`NetError::Dns(DnsError::NoRecordsFound(n))` 且 `n.response_code` 为 `NXDomain` 或 `NoError` → `NoRecords`；其他 `NoRecordsFound`、`DnsError::ResponseCode(_)`（如 SERVFAIL、REFUSED）与其他错误 → `Server`（不能映射成 `NoRecords`，否则暂时故障会被当成 `Fail` 缓存 1 小时）。`dns_resolver = "static:<path>"` 时改用 `mg_intel::StaticResolver` 并在启动日志中警告。

### 9.7 状态层（Valkey；WP-C3 实现，WP-E1b / E1c 接线）

**键**（02 §7 的命名，Phase 1 实际读写的部分）：

| 键 | 类型 | 操作 | TTL |
|---|---|---|---|
| `mg:v:{site}:{type}:{key}` | String：`mg_core::EntityVerdict` 的 JSON | Edge 只 `MGET` | 由写入方设置 |
| `mg:rl:{site}:{limiter}:{kh}` | String：TAT（微秒，十进制整数） | `EVALSHA mg_gcra` / `mg_nonce_issue` | 脚本以 `PX` 设置 |
| `mg:n:{site}:{nonce_hex}` | String `1` | `mg_nonce_issue` 内的 `SET … NX PX` | `exp_ms − now_ms + 60000` |
| `mg:ev` | Stream | `XADD mg:ev MAXLEN ~ <stream_maxlen> * …` | — |

**键中的假名化**（D-06）：`kh(domain, type, value) = lower_hex(HMAC-SHA256(K_pseudo, domain ‖ 0x00 ‖ type ‖ 0x00 ‖ value))[0..32]`（KAT：`kat.json` 的 `entity_key`）。

| 实体 | `{type}` | `{key}` |
|---|---|---|
| IP | `ip` | `kh("mg-ent-v1", "ip", Net::entity_of(ip))`：IPv4 为地址，IPv6 为所在 /64（D-24；KAT `ip_entity`） |
| 前缀 | `prefix` | `kh("mg-ent-v1", "prefix", Net::prefix_of(ip))`（/24、/48） |
| ASN | `asn` | 十进制 ASN（不哈希；从不为 0） |
| 会话 | `session` | 凭证 `sub`（本身是随机假名） |

**限速器键**：`{kh} = kh("mg-rl-v1", limiter_id, dims)`，`dims` 按限速器 `key` 的声明顺序以 `&` 连接 `name=value`：`ip=<ip 实体>`、`ip_prefix=<前缀>`、`asn=<n>`、`session=<sub>`、`route=<路由名>`。分量未知时（D-23）：

| 分量 | 未知时 |
|---|---|
| `ip`、`ip_prefix` | 值为 `?`：所有 IP 未知的请求共用一个兜底桶（按站点 + 限速器 + 其余维度），从不跳过 |
| `asn` | 本请求的 ASN 未知（IP 未知，或 GeoLite2 查不到 / 为 0）→ `?`；站点根本没有可用的 `geoip-asn` 工件 → 该限速器对所有请求跳过（这是站点配置状态，不是客户端能选的；用户限速器的 `asn` 维度在构建时要求配置 `geoip_asn`，§8.2） |
| `session` | 没有有效凭证 → 本请求跳过该限速器。会话维度的限速器保护不了无会话的流量，应与 `ip` / `ip_prefix` 维度的限速器搭配（02 §2.1） |
| `route` | 总是已知 |

KAT：`kat.json` 的 `entity_key` 含 `ip=2001:db8:abcd:12::/64`、`ip=?` 等用例。

**Verdict 读取**：键顺序为 ip、prefix、asn、session；`share_ip_verdicts` 时追加 `mg:v:all:ip:…`、`mg:v:all:prefix:…`、`mg:v:all:asn:…`；缺少输入的键不读（verdict 只能抬高风险，D-10；IP 未知不是客户端能选择的状态，§9.3.2）。解析失败的值忽略并计 `mg_verdict_parse_errors_total`。本地缓存 2 s（含"没有 verdict"的结果），至多 50,000 项。

**GCRA 脚本 `mg_gcra`**（Lua 5.1；与 `mg_core::gcra_check` 逐位一致，WP-C3 用 `core/testdata/gcra-cases.json` 同时测两者）：

```lua
-- mg_gcra v1
-- KEYS[i]           = mg:rl:{site}:{limiter}:{kh}
-- ARGV[1]           = now_us ("0" = use the server clock: TIME)
-- ARGV[2 + 4(i-1)]  = interval_us  (period_s * 1e6 / rate, floor)
-- ARGV[3 + 4(i-1)]  = burst        (>= 1)
-- ARGV[4 + 4(i-1)]  = cost         (>= 1)
-- ARGV[5 + 4(i-1)]  = write        (1 = store the new TAT when allowed, 0 = check only)
-- returns a flat array, 3 integers per key: allowed (1|0), retry_after_us, tat_minus_now_us
local now = tonumber(ARGV[1])
if now == 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
end
local out = {}
for i = 1, #KEYS do
  local base = 2 + (i - 1) * 4
  local interval = tonumber(ARGV[base])
  local burst = tonumber(ARGV[base + 1])
  local cost = tonumber(ARGV[base + 2])
  local write = tonumber(ARGV[base + 3])
  local dvt = interval * burst
  local tat = tonumber(redis.call('GET', KEYS[i]) or '0')
  if tat < now then tat = now end
  local new_tat = tat + interval * cost
  local allow_at = new_tat - dvt
  if now < allow_at then
    out[#out + 1] = 0
    out[#out + 1] = allow_at - now
    out[#out + 1] = tat - now
  else
    if write == 1 then
      local ttl_ms = math.ceil((new_tat - now) / 1000)
      if ttl_ms < 1 then ttl_ms = 1 end
      redis.call('SET', KEYS[i], string.format('%d', new_tat), 'PX', ttl_ms)
    end
    out[#out + 1] = 1
    out[#out + 1] = 0
    out[#out + 1] = new_tat - now
  end
end
return out
```

`string.format('%d')` 是必须的：Lua 5.1 的 `tostring` 会把 1.8e15 写成科学计数法。所有数值 < 2^53 由 `GcraParams::new` 的上限保证（§8.2）。生产调用传 `now_us = 0`（以 Valkey 时钟为准）；测试传显式时间（用例表中没有 0），与 `mg_core::gcra_check` 对照。Rust 侧见 §5.6（已落地）。

**nonce 与签发配额脚本 `mg_nonce_issue`**（D-37；只在 nonce 首次使用时计配额，且所有配额都允许时才写入）：

```lua
-- mg_nonce_issue v1
-- KEYS[1]          = mg:n:{site}:{nonce_hex}
-- KEYS[1 + i]      = mg:rl:{site}:{limiter}:{kh}      issuance limiters, i >= 1 (may be none)
-- ARGV[1]          = nonce TTL in ms (>= 1)
-- ARGV[2]          = now_us ("0" = server clock)
-- ARGV[3 + 3(i-1)] = interval_us, ARGV[4 + 3(i-1)] = burst, ARGV[5 + 3(i-1)] = cost
-- returns {1, allowed, retry_after_us, tat_minus_now_us, ...} or {0} when the nonce was already used
if not redis.call('SET', KEYS[1], '1', 'NX', 'PX', tonumber(ARGV[1])) then
  return {0}
end
local now = tonumber(ARGV[2])
if now == 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
end
local out = {1}
local writes = {}
local all_allowed = true
for i = 2, #KEYS do
  local base = 3 + (i - 2) * 3
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

**往返**（每请求至多 2 次，02 §1）：

| 路径 | 往返 1 | 往返 2 |
|---|---|---|
| 普通请求 | `MGET` verdict 键 + 一次 `EVALSHA mg_gcra`（本请求全部 global 限速器，write 1） | — |
| `POST /__mg/c` | `EVALSHA mg_gcra`：`mg.c.submit`（write 1）、`mg.c.fail` 与 `mg.c.fail.prefix`（write 0：再失败一次是否超限）、`mg.clr.issue.ipp` 与 `mg.clr.issue.asn`（write 0：是否已无配额） | 本地检查全部通过后：`EVALSHA mg_nonce_issue`（nonce + 两个签发配额） |
| 提交失败后 | 异步：失败计数请求进入有界通道（容量 1024），由 `mg-state` 的单个消费者执行 `EVALSHA mg_gcra`：`mg.c.fail`、`mg.c.fail.prefix`（write 1）；通道满时丢弃并计 `mg_state_async_dropped_total` | — |

连接用 `redis::aio::ConnectionManager`，只在 `mg-state` 后台 service 中创建与使用（§9.1.1）；连接建立与收到 `NOSCRIPT` 时 `SCRIPT LOAD`，管线内用 `EVALSHA`，`NOSCRIPT` 时重载并重试一次；每次往返的超时为 `timeout_ms`（从 proxy 提交请求算起），计 `mg_valkey_rtt_seconds`。

**本地模式与熔断**：`mode = "local"`，或往返失败 / 超时 / `mg-state` 尚未就绪时，本请求改用进程内状态：

- **GCRA 表**：与 `gcra_check` 同一数学，分片 `Mutex<HashMap>`；TAT ≤ now 的项等价于"无状态"，惰性删除并由周期清理移除；容量 `local_limiter_capacity`，满时新键落到该限速器的溢出桶（`dims = "~overflow"`，同样按 GCRA 计数），从不逐出仍然有效的项，计 `mg_state_local_overflow_total{table="gcra"}`。
- **重放集合**：固定容量 `local_nonce_capacity` 的 TTL 集合，项在 `exp_ms + 60 s` 过期；**从不逐出未过期的项**；满时按"重放存储不可用"处理（下文），计 `mg_state_local_overflow_total{table="nonce"}`。容量取值：`submit_rate / submit_period_s × (ttl_s + 60) × 预计同时活跃的前缀数`，缺省 200,000 覆盖约 1,000 个前缀以缺省提交限速连续提交（D-35）。
- **没有 verdict**。
- 连续 5 次失败后熔断：1 s 内不再访问 Valkey，之后每次熔断翻倍至 30 s 上限，期间以 `PING` 探测恢复；`mg_state_mode{mode}` 为当前模式的 0/1 仪表。

**重放检查**（`POST /__mg/c` 第 10 步，D-35）：

1. 无论什么模式，先在本地重放集合中检查并插入：已存在 → `ic.nonce_reused`。
2. Valkey 可用：往返 2 的 `mg_nonce_issue` 返回 `{0}` → `ic.nonce_reused`；成功 → 已检查。往返 2 失败或超时 → 本地插入保留，按第 3 条判断。
3. 没有得到 Valkey 的结论时：若 `local_replay_authoritative = true`、本地集合没有溢出、且 `claims.iat_ms ≥` 本进程启动时间，则本地检查即为结论；否则为**重放存储不可用**。
4. 重放存储不可用：该 C 所属路由 `fail_closed` → 429 + `Retry-After: 5`（"稍后再试"），reason `ic.replay_unavailable`，不签发凭证；否则照常签发，reason `ic.replay_unchecked`（01 §8 降级表）。
5. **"所属路由"的判定**：`/__mg/c` 在路由匹配之前应答，没有自己的路由。用请求 Host 所在环境中名为 `claims.route_class` 的路由的 `fail_closed`（`route_class` 在 AEAD 内，可信），再"或"上按 §9.4 对 `ret` 的路径（GET）匹配出的 `fail_closed`；环境中已经没有该名称的路由（配置包已更新）→ 视为 `fail_closed`。

签发配额在 Valkey 不可用时用本地 GCRA 表计数（与普通限速器相同的回退）。

### 9.8 限速（WP-E1b 接线）

- 对普通请求：取所在环境中 `route_ids` 为空或包含选中路由的限速器；`scope = local` 只用进程内状态，`global` 用 Valkey（失败时回退本地）。每个限速器产生一个 `RateObservation`（§5.6）：`utilization` 取 `GcraOutcome::utilization`，超限时 `exceeded = true`；`rate` 映射（§4.1）以限速器 id 为键。
- 内置限速器（只用于 `/__mg/c` 流程，参数来自配置包 `challenge`；键规则同上，未知分量为 `?`）：

| id | 键 | 参数 | 超限 |
|---|---|---|---|
| `mg.c.submit` | `[ip_prefix]` | `submit_rate / submit_period_s`，burst `submit_burst` | 429，reason `ic.rate_limited`（`Retry-After` = GCRA 等待时间向上取整秒） |
| `mg.c.fail` | `[ip]`（ip 实体） | `max_failures / failure_window_s`，burst = `max_failures` | 429，`ic.rate_limited` |
| `mg.c.fail.prefix` | `[ip_prefix]` | `4 × max_failures / failure_window_s`，burst = `4 × max_failures` | 429，`ic.rate_limited` |
| `mg.clr.issue.ipp` | `[ip_prefix]` | `issue_per_ipp / issue_period_s`，burst = `issue_per_ipp` | 429，reason `ic.issue_quota`，不签发凭证（D-37） |
| `mg.clr.issue.asn` | `[asn]` | `issue_per_asn / issue_period_s`，burst = `issue_per_asn` | 同上；没有可用的 `geoip-asn` 工件时跳过 |

- **计为失败**（写入 `mg.c.fail` 与 `mg.c.fail.prefix`，D-28）的 reason：`ic.body`、`ic.c_invalid`、`ic.c_kid`、`ic.bind_uah`、`ic.bind_ipp`、`ic.pow`、`ic.ret`、`ic.automation_flag`、`ic.ua_mismatch`、`ic.nonce_reused`。不计：`ic.c_expired`（标签页休眠）、`ic.replay_unavailable`、`ic.no_client_ip`、`ic.issue_quota`、`ic.rate_limited`、`ic.too_early`。
- 超限计 `mg_ratelimit_exceeded_total{limiter}`（`dry_run` 限速器也计）。

### 9.9 动作执行（WP-E1a 转发与源站头，E1b 阻断与限速，E1c 挑战）

| 最终动作 | Edge 行为 |
|---|---|
| ALLOW / TAG / LOG | 转发源站。`upstream_request_filter`：`Host` 设为 §9.4 的规范化主机名；删除 §9.3 的逐跳头与头族；写入 `MG-Client-IP`（客户端 IP，未知时为字面量 `unknown`）、`MG-Request-Id`；`origin_headers.scores` 时 `MG-Bot-Score`（0–100）、`MG-Bot-Class`（小写 wire 名）、`MG-Verified`（已验证爬虫：`crawler:<operator>`）；`origin_headers.session` 且有会话时 `MG-Session`；TAG 时 `MG-Tags: a,b`；`origin_headers.reasons` 时 `MG-Reasons`（`top_reasons` 逗号分隔）。`X-Forwarded-For` 改写为单值客户端 IP（未知时删除）；`X-Forwarded-Proto`：`cloudflare` 取 `cf-visitor` 的 scheme，`direct_tls` 为 `https`。认证通过的 `cloudflare` 请求原样转发 `CF-IPCountry`（仅 `location_headers`）、`Cf-Ray`、`CF-Visitor`，以及**客户端 IP 已知时**的 `CF-Connecting-IP`（未知或非法时不转发）。`response_filter` 删除源站响应中的 `MG-*` 与 `MG_*` 头 |
| CHALLENGE | 客户端 IP 未知 → 429 + `Retry-After: 5`，`rule_id = "hard.client_ip_unknown"`，不签发 C（D-23）。`cloudflare` 且访客 scheme 为 http、方法为 GET / HEAD → 308 到 `https://<host><path>[?query]`，计 `mg_https_redirect_total{site}`（D-32；其他方法照常挑战）。否则 403：导航请求（`sec-fetch-mode: navigate`，或没有该头且 `accept` 含 `text/html`）返回挑战页（§10.2），其余返回 JSON。C 按 §6.2 签发、难度按 §6.3；`ret`：GET / HEAD 导航为原始 `path[?query]`（校验失败或 > 512 字节时用 `fallback_ret`），其他方法为 `fallback_ret`。计 `mg_challenge_total{type, provider="none", result="issued"}` |
| RATE_LIMIT | 429 + `Retry-After`；导航请求返回简短 HTML（中英文"请求过多"+ request_id），否则 `{"error":"mg_rate_limited","retry_after":N,"request_id":"…"}` |
| BLOCK | 403；导航请求返回通用阻断页（只含 request_id 与"如有疑问请联系站点所有者"），否则 `{"error":"mg_blocked","request_id":"…"}` |
| monitor（`SiteBundle.monitor_only`）与 bootstrap-open | 引擎给出的决定原样记入事件，`decision.dry_run = true`、`monitor_only = true`；按 ALLOW 转发（带 `MG-*` 头，`MG-Bot-Class` 等反映评分结果）。§9.3.1 的协议拒绝、§9.4 的外部 Worker 403 与站点不可用 503 不受 monitor 影响 |
| `fail_closed` 路由且客户端 IP 未知 | 决定改为 RATE_LIMIT 429、`Retry-After: 5`、`rule_id = "hard.client_ip_unknown"`（monitor 时同样只记录） |
| `Early-Data: 1` | `http.early_data = true`：不签发凭证、不消费 nonce；`critical` 路由直接 425（monitor 时只记录） |
| 随机数失败 | 生成 `request_id`、C、CSP nonce 或凭证时 `getrandom` 失败 → 503，计 `mg_edge_request_errors_total`，不 panic |

- Edge 自己生成的所有响应（上表、§9.3.1、§9.4、§10）都带 `Cache-Control: no-store, private`（`/__mg/s/*` 除外）与 `X-Content-Type-Options: nosniff`；HTML 另加 `X-Robots-Tag: noindex`、`Referrer-Policy: same-origin`、`X-Frame-Options: DENY`。Edge 生成的响应里不出现 `MG-*` 头，唯一例外是 JSON Challenge 的 `MG-Challenge: <type>`。
- **在请求体读完之前应答**时（`request_filter` 中的 403 / 429 / 413 / 414 / 431 / 503，以及 `/__mg/c` 的正文超限），调用 `session.set_keepalive(None)`：Pingora 0.9 复用 keep-alive 连接前会 `drain_request_body()`，而缺省没有总超时，否则 Edge 会把攻击者的大请求体读完。
- **源站契约**（02 §8，D-34，WP-D1 写回）：内容随 `MG-*` 头变化的响应必须带 `Cache-Control: private` 或 `no-store`（Cloudflare 对非图片内容不理会 `Vary`，否则机器人版本与真人版本会互相串缓存）；源站不得因为 `REMOTE_ADDR` 是回环地址就信任请求（Edge 与源站可能同主机）；`MG-Client-IP: unknown` 表示客户端 IP 不可知。

### 9.10 配置包加载与站点状态（WP-C2 实现，WP-E1a 接线）

**站点状态**（D-21）：

| 状态 | 条件 | 行为 | `mg_site_state{site, state}` |
|---|---|---|---|
| `active` | 有一个已验证、已应用的配置包 | 正常 | `active` |
| `bootstrap` | 从未有过配置包：没有 LKG 文件，且尚未拉取成功 | `bootstrap = "open"`：全部放行并记录（`rule_id = "bootstrap"`、`bundle_version = 0`、`dry_run = true`），没有 C 与凭证（`/__mg/c` → 404）；`"closed"`：503 | `bootstrap_open` / `bootstrap_closed` |
| `lkg_invalid` | LKG 文件存在但无法使用：验签失败（如所有者轮换密钥后删掉了旧 `.pub`）、未知 `key_id`、解码失败、校验失败、`hosts` 或监听器 profile 不符 | 一律 503（不管 `bootstrap` 设置）；继续轮询，任何一个通过校验的配置包都会把站点带回 `active`；`--check-config` 在这种情况下失败 | `lkg_invalid` |

LKG 可用但它引用的某些工件不在 `state_dir/artifacts/` 中（例如缓存被清空而大脑 VM 暂时不可达）：照常应用，缺失工件对应的字段按"没有该工件"处理为 MISSING（§4.1），`mg_artifact_missing{site, name}` 置 1，之后每次轮询重试获取；获取成功后重新构建站点运行时。

```
on start (main(), synchronous), per site:
  if state_dir/bundles/<site>.bundle exists:
       verify + validate (same checks as a candidate, except "version > current")
       ok  -> load cached artifacts (missing ones -> MISSING fields) -> state active
       err -> state lkg_invalid (log the reason; --check-config fails)
  else: state bootstrap (open | closed per edge.toml)
every bundle_poll_seconds (±20% jitter), per site (mg-bundles background service):
  GET <bundle_root>bundles/<site>.bundle   (file:// -> read; ETag = sha256 of the bytes)
      If-None-Match: <last ETag>            (http(s); response ETag stored as returned)
  304 / same sha256          -> last_fetch_ok = now
  200                        -> candidate
  error / timeout            -> mg_config_fetch_failures_total{site}++, keep current
candidate:
  size <= 8 MiB; decode SignedBundle; key_id in [trust].owner_keys;
  ed25519 verify("mg-bundle-v1" || 0x00 || bundle); decode SiteBundle
  schema_version == 1; site_id == site; hosts == edge.toml hosts (as sets)
  upstream.kind == profile of every edge.toml listener serving this site
  bounds of §8.2 re-checked (pow_bits, ttl_s, clearance TTLs, limiter numbers, route limits, fallback_ret)
  version > current.version (equal version with identical bytes = no-op; otherwise reject)
  every token_key_ids[*] present in token.keys.json; lists / rules / IR (incl. max_steps) / routes / limiters convert
  artifacts: for each ref, cache hit state_dir/artifacts/<sha256> or GET <bundle_root>artifacts/<sha256>;
             sha256 and size must match; parse by kind (mg-intel, incl. registry validation); any failure -> reject
  if not_before_ms > now: keep as pending, swap when due
  swap: ArcSwap<SiteRuntime> (in-flight requests keep the old Arc); persist signed bytes to
        state_dir/bundles/<site>.bundle via tmp + fsync + rename; state active; last_applied = now
  reject -> mg_config_reload_total{site, result="rejected"} and a log line with the reason; keep current
```

- `mg_config_version{site}` = 当前生效版本（bootstrap 与 lkg_invalid 为 0）；`mg_config_age_seconds{site}` = `now − last_fetch_ok`（最近一次成功拉取，含 304；从未成功过时为进程运行时长）——它衡量的是**拉取是否正常**，不是配置是否最新；`mg_config_reload_total{site, result="applied"|"rejected"|"unchanged"}`。
- **新鲜度**：静态服务器陈旧或 http 链路上的中间人可以一直返回旧的配置包（或 304）而不触发 `mg_config_age_seconds` 告警。所以 `mgctl bundle publish --metrics-textfile` 写出 `mg_bundle_published_version{site}`，§17 的告警比较它与各 Edge 的 `mg_config_version{site}`（持续 10 分钟不相等即告警）；`bundle_root` 的 `http://` 只允许私网地址（§8.1）。
- 出站请求（C2 与 C4）：`reqwest`，必须调用 `ClientBuilder::no_proxy()`（reqwest 0.13 无论特性如何都读取 `HTTP_PROXY` 等环境变量），`redirect::Policy::custom`：只跟随同源重定向、至多 3 次；User-Agent `mg-edge/<version>`；`bundle_client` 的 CA / 客户端证书用于 https；超时 `timeout_ms`。测试：设置了 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 指向一个会记录连接的本地监听器时，拉取仍直连目标且该监听器没有收到连接。
- 工件缓存的清理：成功切换后删除既不被当前配置包、也不被持久化的 LKG 引用的文件（二者通常相同）；pending 配置包引用的文件也保留。从不删除 LKG 引用的工件。

### 9.11 事件（WP-C4 实现，WP-E1d 接线）

```rust
pub enum EventClass { Priority, Access, Sampled }        // P0 / P1 / P2
pub struct EventRecord { pub class: EventClass, pub target: Sink, pub line: String, pub stream: Option<StreamEntry> }
pub enum Sink { Main, Short }                            // vl-main / vl-short
pub trait EventSink: Send + Sync {
    /// Never blocks; returns false (and counts a drop) when the class queue is full.
    fn try_send(&self, record: EventRecord) -> bool;
}
```

- 三个有界队列，容量为 `queue_priority` / `queue_access` / `queue_sampled`；满时丢弃新记录并计 `mg_event_dropped_total{sink="buffer", class}`。后台 flusher 每 `flush_interval_ms` 或攒满 `max_batch_lines` / `max_batch_bytes` 时，按 P0、P1、P2 的顺序取出，分别发往 `vl_main` / `vl_short`（§13.1），同时写 `file` 出口（若配置）。
- 发送失败重试 3 次（退避 200 ms、1 s、5 s），仍失败则丢弃该批并计 `mg_event_dropped_total{sink="victorialogs"}`。写出从不阻塞请求路径。
- `mg:ev`：同一个 flusher 把本批的 `StreamEntry` 交给 `mg-state` 用一个管线 `XADD` 出去（§13.6），失败计 `mg_event_dropped_total{sink="stream"}`，不重试。
- 采样（`kind=decision`）：以下情况 `sample_rate = 1`：动作不是 ALLOW / TAG / LOG；路由敏感度为 high / critical；`force_log`；存在 `missing_input` / `eval_error` / `dry_run` 的 hit；monitor 模式下被记为非 ALLOW 的决定。其余以 `events.allow_sample_rate` 抽样，事件中记录该值。
- **路径脱敏**（D-31）：选中路由（或 `/__mg/c` 的 `route_class` 路由）设了 `redact_path` 时，决定事件的 `ctx.http.path` 与 `ctx.http.query_keys`、访问记录的 `path` 都写成 `/<route name>`（查询键清空）。
- **遥测**：`kind=telemetry` 的 `env` / `auto` 按 SDK schema（`sdk/web/src/env.ts`，`v = 1`）解析成类型化结构后重新序列化：只保留已知字段，每个字符串 ≤ 256 字节、每个数组 ≤ 16 项、嵌套深度 ≤ 4，未知字段丢弃；解析失败则省略 `env`。
- **应用日志**（`log` 输出、Pingora 错误日志、journald）从不写客户端 IP、Cookie、C、凭证、上游密钥、`x-mg-cf-tls-random` 与请求体（任何级别，§2.4）；需要关联时写 `request_id`。journald 的保留期见 §17。

### 9.12 平滑升级与关闭

见 §9.1.1（进程与运行时模型）与 §9.7（重放集合在升级后的处理，D-35）。

## 10. HTTP 接口（WP-E1c）

### 10.1 端点

| 方法与路径 | 作用 | 请求体上限 | 缓存头 | Phase 1 |
|---|---|---|---|---|
| `GET` / `HEAD /__mg/healthz` | 存活 | — | `no-store, private` | 已有 |
| `GET` / `HEAD /__mg/s/<file>` | SDK 构建文件 | — | `public, max-age=31536000, immutable` | 实现 |
| `POST /__mg/c` | 提交 Challenge 解答 | 8 KiB | `no-store, private` | 实现（站点 `bootstrap` 时 404，`lkg_invalid` / `bootstrap_closed` 时 503） |
| `/__mg/c/renew`、`/__mg/r`、`/__mg/t`、其他 `/__mg/*` | 保留 | — | `no-store, private` | 404 |

`/__mg/*` 由 Edge 在站点解析之后（§9.4 第 4 步之后）、路由匹配与决策之前应答，从不转发源站（包括 `mg_core::paths::is_reserved` 识别的所有规范化写法）。非允许的方法返回 405 与 `Allow`。在请求体读完之前应答时关闭 keep-alive（§9.9）。

### 10.2 挑战页与 JSON Challenge

- **HTML**：403，`Content-Type: text/html; charset=utf-8`，§9.9 的通用头，另加 `Content-Security-Policy: default-src 'none'; script-src 'nonce-<N>'; style-src 'nonce-<N>'; worker-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`（`<N>` 为每响应 128 位 `getrandom` 随机数的 base64）。正文由 SDK 目录中的模板渲染（§11.2）。HEAD 请求只返回头。
- **JSON**：403，`Content-Type: application/json`，`MG-Challenge: <type>`：

```json
{"error": "mg_challenge", "type": "pow", "challenge": "<C>", "pow": {"alg": "sha256-hashcash-v1", "bits": 16},
 "ret": "/account/login", "retry": true, "request_id": "<id>"}
```

### 10.3 `POST /__mg/c`

**请求**（两种编码，内容相同）：

- 导航提交：媒体类型 `application/x-www-form-urlencoded`，正文恰好一个字段 `mg=<URL 编码的提交 JSON>`（字段重复、出现其他字段 → `ic.body`）。
- fetch 提交：媒体类型 `application/json`，正文即提交 JSON。
- `Content-Type` 按媒体类型解析：类型与子类型不区分大小写，允许参数，`charset` 若有必须是 `utf-8`（不区分大小写），其他参数忽略；例如 `application/x-www-form-urlencoded; charset=UTF-8` 合法。

```json
{"v": 1, "type": "pow", "c": "<C>", "pow": {"counters": [38467]}, "ret": "/account/login",
 "ts": 1790000000123, "build": "<sdk build id>",
 "env": { "...": "EnvSummary (sdk/web/src/env.ts, v = 1)" },
 "auto": {"v": 1, "webdriver": false}}
```

| 字段 | 规则 |
|---|---|
| `v` | 1 |
| `type` | `invisible` / `pow`，用于 aad；与 C 内 type 不符即失败 |
| `c` | ≤ 1024 字符 |
| `pow.counters` | 恰好 1 个非负整数，`< 2^53` |
| `ret` | §6.4 校验；`ret_hash(ret)` 必须等于 C 中的 `ret` |
| `ts` | 客户端毫秒时间，只作特征 |
| `build` | `[0-9a-f]{16}`，只记录 |
| `env`、`auto` | 可缺省；有则按 SDK 的 schema 解析为类型化结构（未知字段丢弃，§9.11），解析失败视为缺省 |
| JSON 整体 | UTF-8；嵌套深度 ≤ 16；对象键不得重复（重复 → `ic.body`）；顶层未知字段忽略 |

**校验顺序**（04 §4.1 的 Phase 1 子集；任一步失败都走"统一失败"，reason code 只进事件）：

| # | 检查 | 失败 |
|---|---|---|
| 0 | 客户端 IP 未知（§9.3.2） | 429 + `Retry-After: 5`（`ic.no_client_ip`），不计失败 |
| 1 | `Early-Data: 1` | 425 `{"error":"mg_too_early"}`（`ic.too_early`） |
| 2 | 往返 1：`mg.c.submit` 超限，或 `mg.c.fail` / `mg.c.fail.prefix` 的检查结果为超限 | 429（`ic.rate_limited`） |
| 2b | 往返 1：`mg.clr.issue.ipp` / `mg.clr.issue.asn` 已无配额 | 429（`ic.issue_quota`，D-37） |
| 3 | 带 `Content-Encoding`；`Content-Length`（若有）> 8192；实际读到的正文 > 8192（最多读 8193 字节即停）；正文 5 s 内未读完；媒体类型不是上述两种；表单或 JSON 不符合上面的规则 | 统一失败（`ic.body`），不附新 C；未读完正文时关闭连接（§9.9） |
| 4 | 打开 C（§6.2） | 统一失败（`ic.c_*`），不附新 C（客户端回到 `ret` 重新触发挑战） |
| 5 | 绑定（§6.4）：`uah` 硬；`ipp` 硬失败 / 软 | `ic.bind_uah` / `ic.bind_ipp`；软结果只记 `ic.bind_ipp_soft` |
| 6 | PoW（难度取 C 中的 `pow.difficulty`） | `ic.pow` |
| 7 | `ret` | `ic.ret` |
| 8 | 基础环境：`auto.webdriver == true` → 失败；`env.ua.userAgent` 非空且不是请求 `User-Agent` 的前缀 → 失败 | `ic.automation_flag` / `ic.ua_mismatch` |
| 9 | 签发配额与 nonce：往返 2 `mg_nonce_issue`（§9.7） | nonce 已用过 → `ic.nonce_reused`；配额在往返 1 之后用尽 → 429（`ic.issue_quota`）；重放存储不可用 → §9.7 第 4、5 条 |
| 10 | 签发：`lvl = invisible`（type invisible）或 `pow`；`rb = claims.risk_band`；绑定取当前请求（`ipp` 必有）；`sub` / `sst` 按 §6.5 复用；`mint`（随机数失败 → 503） | — |

**响应**：

| 结果 | 导航提交 | fetch 提交 |
|---|---|---|
| 成功 | 303，`Location: <ret>`，`Set-Cookie`（§6.6） | 200 `{"ok":true,"ret":"<ret>"}`，`Set-Cookie` |
| 统一失败 | 403 挑战页（模板 `state = "failed"`，附新 C 时可自动重试一次） | 403 `{"error":"mg_challenge_failed","retry":true,"request_id":"…","challenge":"<new C>","type":"pow","pow":{"alg":"sha256-hashcash-v1","bits":18}}`（无新 C 时省略后三项） |
| 失败配额 / 提交限速 / 签发配额 / IP 未知 | 429 + `Retry-After`，简短 HTML | 429 `{"error":"mg_rate_limited","retry_after":N,"request_id":"…"}` |
| 重放存储不可用且 `fail_closed` | 429 + `Retry-After: 5` | 同上 |

- 第 5 步及之后的失败附新 C（D-27）：`type = pow`，`route_class` 与 `ret` 同原 C，`risk_band = min(原 risk_band + 1, high)`，难度 `pow_bits[新 risk_band]`；失败计数按 §9.8 异步写入。
- 每次提交都产生一条 `kind=feedback` 事件（§13.3）与 `mg_challenge_total{type, provider="none", result="solved"|"failed"|"expired"}`（`expired` 指 `ic.c_expired`）；带 `env` 时另写一条 `kind=telemetry`（§13.5）。

### 10.4 `/__mg/s/<file>`

只提供 `sdk/manifest.json` 的 `files` 中列出的文件名（精确匹配，`[A-Za-z0-9._-]{1,64}`）；`Content-Type: text/javascript; charset=utf-8`；`Cache-Control: public, max-age=31536000, immutable`；`X-Content-Type-Options: nosniff`；文件在启动时读入内存并校验 SHA-256。其他名字 → 404（`no-store, private`）。

## 11. Web SDK Phase 1（WP-W1）

### 11.1 构建产物

`pnpm run build` 产生：

| 文件 | 说明 |
|---|---|
| `dist/mg.js` | 与现在相同（`size-check` 继续检查 gzip ≤ 30,720 字节） |
| `dist/sdk/mg.<hex16>.js` | 与 `dist/mg.js` 字节相同；`hex16` = 内容 SHA-256 的前 16 个十六进制字符 |
| `dist/sdk/challenge.html` | 挑战页模板（§11.2） |
| `dist/sdk/manifest.json` | 见下；Edge 的 `[sdk] dir` 指向 `dist/sdk/` 的副本 |

```json
{"v": 1, "build": "0123456789abcdef", "sdk": "mg.0123456789abcdef.js",
 "files": {"mg.0123456789abcdef.js": "<sha256 hex>"},
 "templates": {"challenge.html": "<sha256 hex>"}}
```

`files` 中的文件经 `/__mg/s/<name>` 提供；`templates` 只由 Edge 读取，不对外提供。构建由 `sdk/web/scripts/build-dist.mjs`（新增）在 esbuild 之后完成；`check` 脚本顺序保持 `typecheck && test && build && size`，`build` 内部调用 `build-dist.mjs`。`build-dist.mjs` 导出纯函数 `buildDist({ bundle, template }, outDir) -> manifest`（输入为内存中的构建产物与模板，输出写入给定目录并返回 manifest）；vitest 在临时目录中调用它测试 manifest，因此 `test` 先于 `build` 运行也不依赖已有的 `dist/`。

### 11.2 挑战页模板契约

- 占位符恰好是：`{{lang}}`、`{{nonce}}`、`{{sdk_src}}`、`{{prefix}}`、`{{c}}`、`{{type}}`、`{{pow_bits}}`、`{{ret}}`、`{{request_id}}`、`{{state}}`。每个至少出现一次；模板中不得出现其他 `{{…}}`。Edge 按 HTML 属性上下文转义所有值（`&` `<` `>` `"` `'`）后做纯文本替换。
- 必需结构：

```html
<!doctype html>
<html lang="{{lang}}">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>…</title>
  <style nonce="{{nonce}}">/* inline only */</style>
</head>
<body>
  <main id="mg-challenge" data-mg-state="{{state}}" data-mg-c="{{c}}" data-mg-type="{{type}}"
        data-mg-pow-bits="{{pow_bits}}" data-mg-ret="{{ret}}" data-mg-rid="{{request_id}}"
        data-mg-prefix="{{prefix}}">
    <p id="mg-status" role="status" aria-live="polite">…</p>
    <a id="mg-retry" href="{{ret}}" hidden>…</a>
    <noscript>…</noscript>
    <p>… {{request_id}} …</p>
  </main>
  <script data-cfasync="false" src="{{sdk_src}}" nonce="{{nonce}}" data-mg-path-prefix="{{prefix}}"></script>
</body>
</html>
```

- 取值：`lang` 为 `zh-CN`（`Accept-Language` 第一个语言标签以 `zh` 开头）或 `en`；`state` 为 `challenge` 或 `failed`；`c` 可为空（失败页没有新 C 时）；`prefix` 为 `/__mg/`；`sdk_src` 为 `/__mg/s/mg.<hex16>.js`。模板同时包含中英文文案，按 `<html lang>` 显示；`prefers-reduced-motion` 下不做动画。
- 限制：UTF-8、≤ 32 KiB、不引用任何外部资源（不含 `http:`、`https:`、`//` 开头的 URL）；每个 `<script>`、`<style>` 都带 `nonce="{{nonce}}"`；SDK 的 `<script>` 标签把 `data-cfasync="false"` 写在 `src` 之前（Rocket Loader，08 §2.7）。WP-W1 用测试检查这些规则；Edge 在加载 SDK 目录时再检查一次。

### 11.3 挑战客户端流程

1. SDK 在文档中执行时照常 `bootstrap()`，并在存在 `#mg-challenge` 时运行挑战流程；在 Worker 中执行时（`typeof WorkerGlobalScope !== "undefined" && self instanceof WorkerGlobalScope`）只安装 PoW 消息处理器。
2. `state = challenge` 且 `c` 非空：状态文字显示"正在验证"；计算 `prefix = "mg-pow-v1" ‖ 0x00 ‖ SHA-256(c)`；以当前脚本 URL 启动 Worker（`new Worker(document.currentScript.src)`），发送 `{t: "mg-pow", prefix: <Uint8Array(42)>, bits}`，Worker 回复 `{t: "mg-pow-ok", counter}` 或 `{t: "mg-pow-err"}`；Worker 创建失败或 2 s 内无任何回复时改为主线程分片计算（每片 50,000 次哈希，片间 `setTimeout(0)`）。整体超过 60 s 显示重试链接。
3. 收集 `collectEnv()`、`collectAutomation()`。
4. 组装提交 JSON（§10.3），创建隐藏的 `<form method="POST" action="{prefix}c" enctype="application/x-www-form-urlencoded" accept-charset="UTF-8">`，只含 `<input type="hidden" name="mg">`，调用 `submit()`；浏览器跟随 303 回到 `ret`，此时已带上 `__Host-mg_clr`。
5. `state = failed`：有新 C 时，每个 `ret` 至多自动重试 1 次（`sessionStorage` 键 `mg_retry:<ret>`，存取包在 try/catch 里）；否则显示重试链接（`href = ret`）。
6. 任何异常都不抛进页面；状态文字改为"验证失败，请重试"并显示重试链接。

### 11.4 PoW 实现

- `src/sha256.ts`：纯 TypeScript SHA-256（压缩函数 + 通用 `digest`）。PoW 的消息是 42 字节前缀加 8 字节计数器，共 50 字节，填充后恰好是一个 64 字节块，所以每次尝试只做一次压缩：预先填好块的前 42 字节与填充 / 长度字段，循环中只改 8 个计数器字节。
- 计数器从 0 开始递增，上限 `2^53 − 1`；判定为前导零位数 ≥ `bits`。
- WebCrypto 只用于启动时的自检（对一个固定输入比较纯 JS 与 `crypto.subtle.digest` 的结果），不一致时不启动挑战并显示重试链接。

### 11.5 测试

NIST SHA-256 测试向量；`testdata/phase1/kat.json` 的全部 `pow` 用例（`first_counter` 与 `digest_hex` 完全一致；测试直接读取该文件）；Worker 消息处理器（直接调用处理函数）；提交 JSON 的形状与 `ret` 取值（没有重复键、嵌套 ≤ 16）；表单构建（经可注入的最小 DOM 接口，测试中用假对象；表单只有一个 `mg` 字段）；模板占位符 / nonce / 外部资源规则；`buildDist` 在临时目录中生成的 `manifest.json` 哈希与文件名一致；构建产物大小仍 ≤ 30 KB gzip（`size` 步骤）。

## 12. 工件与密钥文件格式

### 12.0 规范 JSON 与共享样例

mgctl 写出的所有 JSON 文件（工件、密钥文件、`.age` 内的明文）都是**规范 JSON**：Go `encoding/json` 的 `Encoder`，`SetIndent("", "  ")`、`SetEscapeHTML(false)`，对象键按本节示例中的顺序，末尾一个换行；二进制值为 base64url（无填充）。读取方不依赖格式（任何合法 JSON 都按字段解析），但**拒绝未知字段**。

`testdata/phase1/` 有每种格式的有效样例与无效样例，以及生成有效样例所用的确定性输入（`testdata/phase1/README.md`）：

- 写入方：WP-G2 的密钥生成（给定随机字节流与时间）必须写出与 `keys/*.json`、`keys/owner-test.pub` 逐字节相同的文件；WP-G3 的 `cf ips sync`（给定对应的 API 响应与 `fetched_at`）必须写出与 `artifacts/cloudflare-ips.json` 逐字节相同的文件；爬虫注册表样例要求"解析 → 校验 → 重新编码"得到相同字节。
- 读取方：WP-R2（`token.keys`、`seal.root`）、WP-R3（全部工件）、WP-C2（所有者公钥）、WP-E1a（其余密钥文件）接受全部有效样例，拒绝 `invalid/` 下对应种类的每个样例；WP-G3 的 Go 校验同样拒绝 `artifacts/invalid/` 的每个样例。

### 12.1 发布目录

```
<dest>/
  bundles/<site>.bundle        SignedBundle (binary protobuf), replaced atomically (tmp + rename)
  artifacts/<sha256>           content-addressed artifact files, never modified once written
```

`mgctl bundle publish` 先写 `artifacts/` 再写 `bundles/`。复制到大脑 VM 同样分两步、先工件后配置包：`rsync -a <dest>/artifacts/ brain:/srv/mg/artifacts/ && rsync -a <dest>/bundles/ brain:/srv/mg/bundles/`（或 `scp` 同顺序）。大脑 VM 上用任何带 ETag 的静态文件服务器（如 nginx / caddy），只绑定 WireGuard 地址或要求 mTLS。

| `ArtifactRef.name` | 格式 | 上限 | 站点 YAML 键 |
|---|---|---|---|
| `geoip-asn` | MaxMind DB | 128 MiB | `artifacts.geoip_asn` |
| `geoip-country` | MaxMind DB | 128 MiB | `artifacts.geoip_country` |
| `cloudflare-ips` | JSON §12.2 | 1 MiB | `artifacts.cloudflare_ips` |
| `crawler-registry` | JSON §12.3 | 16 MiB | `artifacts.crawler_registry` |
| `datacenter-asns` | 文本 §12.4 | 4 MiB | `artifacts.datacenter_asns` |
| `tor-exits` | 文本 §12.4 | 16 MiB | `artifacts.tor_exits` |

### 12.2 `cloudflare-ips.json`

```json
{"v": 1, "kind": "mg-cloudflare-ips", "source": "https://api.cloudflare.com/client/v4/ips",
 "fetched_at": "2026-09-27T10:00:00Z", "etag": "38f79d050aa027e3be3865e495dcc9bc",
 "ipv4_cidrs": ["173.245.48.0/20", "103.21.244.0/22"], "ipv6_cidrs": ["2400:cb00::/32"]}
```

校验（写入方与读取方相同）：`v == 1`、`kind`；IPv4 5–64 条、IPv6 2–32 条；每条是规范网络地址（主机位为 0）；IPv4 前缀长度 8–32、IPv6 16–128；不含私有、回环、链路本地、组播、未指定与文档地址段。样例：`testdata/phase1/artifacts/cloudflare-ips.json` 与 `invalid/cloudflare-ips.*.json`。

### 12.3 爬虫注册表

**源文件**（所有者维护，`deploy/intel/crawler-registry.yaml`，WP-G3 提供初始内容）：

```yaml
version: 1
operators:
  - id: googlebot                     # [a-z0-9][a-z0-9_-]{0,31}, unique
    name: Googlebot
    purpose: search                   # search | ai_training | ai_search | user_triggered | archive | other
    ua_tokens: [Googlebot]            # case-insensitive substrings, 1-8 tokens of 3-64 chars
    verify:
      mode: ip_ranges_or_rdns         # ip_ranges | rdns | ip_ranges_or_rdns
      rdns_suffixes: [.googlebot.com, .google.com]
      ip_ranges:
        - url: https://developers.google.com/static/crawling/ipranges/common-crawlers.json
          format: prefixes_json       # prefixes_json | cidr_text
```

初始运营方（WP-G3 在实现时以 User-Agent `morphgate-dev-tooling` 核对 URL 与 UA 标记；2026-09-27 均返回 200）：Googlebot（上例）、Bingbot（`https://www.bing.com/toolbox/bingbot.json`，rDNS `.search.msn.com`，`ip_ranges_or_rdns`）、Applebot（`https://search.developer.apple.com/applebot.json`，rDNS `.applebot.apple.com`）、GPTBot（`https://openai.com/gptbot.json`，`ip_ranges`，`ai_training`）、OAI-SearchBot（`https://openai.com/searchbot.json`，`ip_ranges`，`ai_search`）、ChatGPT-User（`https://openai.com/chatgpt-user.json`，`ip_ranges`，`user_triggered`）。

**工件**（`mgctl crawler sync` 输出）：

```json
{"v": 1, "kind": "mg-crawler-registry", "generated_at": "2026-09-27T10:00:00Z",
 "operators": [
  {"id": "googlebot", "name": "Googlebot", "purpose": "search", "ua_tokens": ["Googlebot"],
   "verify": {"mode": "ip_ranges_or_rdns", "rdns_suffixes": [".googlebot.com", ".google.com"]},
   "cidrs": ["66.249.64.0/27", "2001:4860:4801:10::/64"],
   "sources": [{"url": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
                "format": "prefixes_json", "fetched_at": "2026-09-27T10:00:00Z",
                "creation_time": "2026-09-25T14:49:23.000000", "sha256": "<hex of fetched body>",
                "stale": false}]}
 ]}
```

`prefixes_json` 格式：`{"creationTime": "...", "prefixes": [{"ipv4Prefix": "..."} | {"ipv6Prefix": "..."}]}`；`cidr_text`：每行一个 CIDR。工件顶层可带 `"test": true`（缺省 false，false 时不写出）：只用于 Validation Lab 与测试（`testdata/phase1/artifacts/crawler-registry.test.json`）。

**校验**（D-36；WP-G3 写入前与 WP-R3 加载时相同，任一条不满足即拒绝整个工件）：

- `v == 1`、`kind == "mg-crawler-registry"`；运营方 id 唯一；`purpose`、`verify.mode` 取表内值；`ua_tokens` 1–8 个、每个 3–64 字符。
- `mode` 含 rDNS 时 `rdns_suffixes` 非空，每项小写、1–253 字节；`ip_ranges` 模式的 `cidrs` 非空；每个运营方至多 20,000 条 CIDR。
- **每条 CIDR**：规范网络地址（主机位为 0，不接受单个地址以外的非规范写法）；IPv4 前缀长度 ≥ 16、IPv6 ≥ 32（更宽的段一律拒绝，例如 `0.0.0.0/0`、`66.0.0.0/8`、`2600::/16`）；不与私有（RFC 1918、ULA）、回环、链路本地、组播、未指定、CGNAT（100.64.0.0/10）、保留段（240.0.0.0/4 等）相交；文档段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、2001:db8::/32）只在 `test: true` 时允许。
- `sources[].sha256` 为 64 位小写十六进制；`fetched_at` 为 RFC 3339。

运营方按文件顺序匹配 UA。样例：`testdata/phase1/artifacts/crawler-registry*.json` 与 `invalid/crawler-registry.*.json`。

### 12.4 文本名单

UTF-8，每行一项，`#` 开始注释，空行忽略。`datacenter-asns`：十进制 ASN 1–4294967295，可带不区分大小写的 `AS` 前缀（0 非法）；`tor-exits`：IP 或规范 CIDR。非法行报错并带行号。样例：`testdata/phase1/artifacts/*.txt`。

### 12.5 MaxMind DB

所有者用自己的 MaxMind 账号下载 GeoLite2-ASN 与 GeoLite2-Country（或 City）（§17）；Edge 只接受 §7.2 的 `database_type`。仓库中只有测试用的生成库（§7.7）。

### 12.6 所有者签名密钥

- `<kid>.key.age`：age v1 文件，scrypt 口令接收方（`filippo.io/age` 的 `NewScryptRecipient`），明文为：

```json
{"v": 1, "kind": "mg-owner-ed25519", "kid": "owner-2026", "seed": "<base64url 32 bytes>", "created_at": "2026-09-27T10:00:00Z"}
```

- `<kid>.pub`（Edge `[trust] owner_keys` 引用）：

```json
{"v": 1, "kind": "mg-owner-ed25519-pub", "kid": "owner-2026", "public_key": "<base64url 32 bytes>", "created_at": "2026-09-27T10:00:00Z"}
```

- `kid` 匹配 `[a-z0-9][a-z0-9._-]{0,63}`。口令来源：环境变量 `MGCTL_PASSPHRASE_FILE`（文件第一行，去掉行尾换行；测试与自动化用），否则从 TTY 无回显读取（`golang.org/x/term`；生成时输入两次）；口令从不出现在命令行参数里。私钥文件 0600，公钥 0644；不覆盖已有文件。
- scrypt 工作因子缺省 18（`filippo.io/age` 的缺省）。`MGCTL_AGE_WORK_FACTOR` 可设 10–22，但**小于 18 时必须同时给出 `--insecure-test-key`**，否则报用法错误；使用该标志时审计记录的 `diff` 含 `"work_factor": <n>, "insecure_test_key": true`，命令在 stderr 打印警告。只有测试与 Lab 脚本使用它。

### 12.7 站点密钥与其他密钥

Edge 读取的是下面的明文 JSON（systemd credential 或 0600 文件）；`key` 为 base64url（无填充）编码的 32 个随机字节。在所有者工作站上，mgctl 把它们写成 age 加密文件 `<name>.json.age`（与所有者私钥同样的口令流程），从不在工作站上留下明文；`mgctl keys export --in <file.json.age>` 把明文写到 stdout，用于直接通过管道交给 Edge 主机上的 `systemd-creds encrypt`（§17），`--out <file>` 写 0600 明文文件（测试与 Lab 用）。

```json
{"v": 1, "kind": "mg-site-token-keys", "site": "blog",
 "keys": [{"kid": "blog-t-20260927", "key": "<b64url>", "created_at": "2026-09-27T10:00:00Z"}]}
```

```json
{"v": 1, "kind": "mg-site-seal-root", "site": "blog",
 "roots": [{"root_id": "blog-r-20260927", "key": "<b64url>", "created_at": "2026-09-27T10:00:00Z"}]}
```

```json
{"v": 1, "kind": "mg-pseudo-key", "id": "pseudo-20260927", "key": "<b64url>", "created_at": "2026-09-27T10:00:00Z"}
```

```json
{"v": 1, "kind": "mg-upstream-keys", "values": ["<43-char b64url>", "<previous value>"], "created_at": "2026-09-27T10:00:00Z"}
```

`token.keys.json` 新的在前，1–3 个，kid 唯一；`kid` 形如 `<site>-t-<YYYYMMDD>`（同日重复时加 `-2` 等后缀）。`seal.root.json` 的 `roots` 1–2 个（D-30），`roots[0]` 封装；`root_id` 形如 `<site>-r-<YYYYMMDD>`。`mg-upstream-keys` 1–2 个值，`values[0]` 写入 Cloudflare Tier 0 规则的静态值。所有字段必填（`created_at` 为 RFC 3339），未知字段拒绝。有效与无效样例：`testdata/phase1/keys/`。

### 12.8 审计日志

JSON Lines，每行一条（06 §6 的记录格式，Phase 1 取值）：

```json
{"id":"<32 hex>","ts":"2026-09-27T10:00:00.123456789Z","actor":"owner","actor_kind":"owner","auth":"local",
 "reauth_at":null,"actor_ip":"","site":"blog","action":"bundle.sign","resource_type":"bundle",
 "resource_id":"blog@1790000000","diff":{"version":1790000000,"sha256":"…","rules":12,"monitor_only":true},
 "reason":"","confirm_text":"","effective_at":"2026-09-27T10:00:00.123456789Z","request_id":"",
 "prev_hash":"<64 hex>","hash":"<64 hex>"}
```

- `hash = lower_hex(SHA-256(prev_hash ‖ "\n" ‖ canonical))`；`canonical` 是去掉 `hash` 键后的记录，按上面的键顺序、无多余空白、不做 HTML 转义的 JSON；第一条的 `prev_hash` 为 64 个 `0`。
- 路径：`--audit-log`，否则 `MGCTL_AUDIT_LOG`，否则 `$XDG_STATE_HOME/morphgate/audit.jsonl`（缺省 `~/.local/state/morphgate/audit.jsonl`）；文件 0600、目录 0700；追加时对 `audit.jsonl.lock` 持排他 `flock`，写后 `fsync`。
- `action` 取值：`keys.gen`、`keys.gen_pseudo`、`keys.gen_upstream`、`keys.export`、`site_keys.gen`、`site_keys.rotate_token`、`site_keys.rotate_seal`、`bundle.sign`、`bundle.publish`、`cf.ips.sync`、`crawler.sync`。`diff` 从不含密钥材料（`keys.export` 只记文件种类、kid 与输出目标是否为终端 / 管道 / 文件）。

## 13. 事件与指标

### 13.1 VictoriaLogs 调用

```
POST {vl_main | vl_short}/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg
Content-Type: application/stream+json
User-Agent: mg-edge/<version>

<json line>\n<json line>\n…
```

2xx 视为接收；429、5xx、超时（5 s）按 §9.11 重试；其他 4xx 丢弃该批不重试（记一条日志）。嵌套对象由 VictoriaLogs 展平为点分字段（如 `ctx.net.ip`）；`ts` 为 Unix 毫秒。

### 13.2 `kind=decision`（vl-main）

`mg_core::DecisionEvent` 的 JSON，在对象开头加入信封字段：

```json
{"kind": "decision", "site": "blog", "ts": 1790000000123,
 "msg": "challenge matrix.critical.medium route=login score=45",
 "ctx": {"request_id": "…", "ts_ms": 1790000000123, "site_id": "blog", "env": "production", "route_id": "login", "...": "…"},
 "signals": [], "risk": {}, "decision": {}, "hits": [],
 "latency_us": 180, "sample_rate": 1.0, "edge_id": "edge-1", "bundle_version": 1790000000, "monitor_only": true}
```

`msg = "<action> <rule_id> route=<route> score=<score>"`，`dry_run` 时追加 ` dry_run`。

### 13.3 `kind=feedback`（vl-main）

`mg_core::ChallengeResult` 的 JSON 加信封（`msg = "challenge <outcome> <type> route=<route>"`）。Phase 1 取值：`provider_id` 省略、`outcome ∈ {pass, fail}`、`lvl`（通过时）、`attempt_no = 0`、`solve_ms = now − C.iat_ms`（服务端测得）、`risk_band`、`reason_codes`（§10.3 的 `ic.*`）、`cf_ray`。

### 13.4 `kind=access`（vl-main，不采样）

```json
{"kind": "access", "site": "blog", "ts": 1790000000123, "msg": "GET /account/login 403",
 "env": "production", "edge_id": "edge-1", "request_id": "…", "cf_ray": "…",
 "method": "GET", "host": "example.com", "path": "/account/login", "status": 403,
 "action": "challenge", "dry_run": false, "route": "login",
 "ip_prefix": "203.0.113.0/24", "asn": 64500, "country": "HK", "bytes_out": 1234, "latency_ms": 12}
```

`path` 不含查询串，≤ 1024 字节，路由 `redact_path` 时为 `/<route name>`（§9.11）；未知值省略。只在 `events.access_log` 时写。`/__mg/*` 请求同样写访问记录（`route = "__mg"`、`action` 省略），但不产生 `kind=decision` 事件，也不计入 `mg_requests_total`；§9.3.1 的协议拒绝写 `route = "__protocol"`，§9.4 的外部 Worker 403 与站点不可用 503 写 `route = "__site"`。

### 13.5 `kind=telemetry`（vl-short）

```json
{"kind": "telemetry", "site": "blog", "ts": 1790000000123, "msg": "challenge env", "source": "challenge",
 "request_id": "…", "build": "0123456789abcdef", "solve_ms": 312,
 "env": {"v": 1, "ua": {"brands": [], "mobile": false, "platform": "macOS"}, "languages": ["zh-CN"],
         "timeZone": "Asia/Shanghai", "...": "EnvSummary without ua.userAgent"},
 "auto": {"v": 1, "webdriver": false}}
```

### 13.6 `mg:ev` 条目

每个请求一条（不采样，`events.stream` 时），由 flusher 批量 `XADD mg:ev MAXLEN ~ <stream_maxlen> *`，字段依次为：

`v 1 kind decision site <site> ts <ms> rid <request_id> sess <sub | ""> route <route> action <action> dry <0|1> class <class> score <0-100> ipk <kh ip | ""> pfk <kh prefix | ""> asn <n | 0> status <http status | 0>`（`ipk` / `pfk` 与 §9.7 的 `ip` / `prefix` verdict 键相同：`ipk` 基于 ip 实体，IPv6 为 /64；IP 未知时为空）

`/__mg/c` 另写 `kind feedback`，字段为 `v kind site ts rid route outcome type pfk asn`。不写客户端 IP 明文，不写 `client_conn_key`。

### 13.7 指标

直方图桶（秒）：`0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1`。

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `mg_requests_total` | counter | site, env, route, action, class | 每个非 `/__mg/*` 请求；`action` 为执行前的决定（monitor 下即"本应"的动作） |
| `mg_decision_latency_seconds` | histogram | site | Decision Core `evaluate` 耗时 |
| `mg_edge_added_latency_seconds` | histogram | site | Edge 附加延迟（Phase 1 验收 p99 < 5 ms 的依据）：Edge 自己的各段耗时之和——`request_filter` 全程（含 Valkey 往返、Decision Core、`/__mg` 的正文读取）+ `upstream_peer` + `upstream_request_filter` + `response_filter` 与 `response_body_filter` 的累计。不含源站连接：Pingora 0.9 在取得上游连接（新建或复用）之后才调用 `upstream_request_filter`。每段在 CTX 中计时，`logging` 中记录一次 |
| `mg_origin_connect_seconds` | histogram | site | 新增：`upstream_peer` 结束到 `connected_to_upstream`（只记新建连接），供所有者把源站成本与 Edge 成本分开看 |
| `mg_challenge_total` | counter | type, provider, result | `provider="none"`；`result` = issued / solved / failed / expired |
| `mg_upstream_auth_failures_total` | counter | listener, profile, reason | reason：`non_loopback_peer`、`bad_secret_header`、`untrusted_ca` |
| `mg_upstream_headers_stripped_total` | counter | profile | |
| `mg_cf_connecting_ip_missing_total` | counter | site | |
| `mg_cf_foreign_worker_total` | counter | site | 新增 |
| `mg_upstream_signal_missing_total` | counter | profile, signal | |
| `mg_token_verify_total` | counter | result | |
| `mg_ratelimit_exceeded_total` | counter | limiter | |
| `mg_crawler_verify_total` | counter | method, result | |
| `mg_cf_vbot_disagree_total` | counter | direction | |
| `mg_event_dropped_total` | counter | sink, class | sink：`buffer` / `victorialogs` / `stream` / `file` |
| `mg_valkey_rtt_seconds` | histogram | — | 每次管线 |
| `mg_valkey_errors_total` | counter | op | 新增；op：`pipeline`、`script_load`、`stream` |
| `mg_state_mode` | gauge | mode | 新增；`valkey` / `local`，当前为 1 |
| `mg_config_version` | gauge | site | |
| `mg_config_age_seconds` | gauge | site | |
| `mg_config_reload_total` | counter | site, result | 新增 |
| `mg_config_fetch_failures_total` | counter | site | 新增 |
| `mg_site_state` | gauge | site, state | 新增；`active` / `bootstrap_open` / `bootstrap_closed` / `lkg_invalid`，当前为 1（§9.10） |
| `mg_site_unavailable_total` | counter | site | 新增；站点 503（§9.4） |
| `mg_artifact_missing` | gauge | site, name | 新增；LKG 引用但缓存中没有的工件为 1 |
| `mg_protocol_rejected_total` | counter | listener, reason | 新增；`uri_too_long` / `header_too_large` / `bad_method` / `bad_host`（§9.3.1） |
| `mg_https_redirect_total` | counter | site | 新增；http 访客被 308 到 https（§9.9） |
| `mg_policy_step_limit_total` | counter | site | 新增；运行时步数断言失败（§5.3，应恒为 0） |
| `mg_state_local_overflow_total` | counter | table | 新增；`gcra` / `nonce`（§9.7） |
| `mg_state_async_dropped_total` | counter | — | 新增；异步失败计数通道满（§9.7） |
| `mg_unknown_host_total` | counter | listener | 新增 |
| `mg_listener_rejected_total` | counter | listener, site | 新增 |
| `mg_verdict_parse_errors_total` | counter | — | 新增 |
| `mg_rdns_lookups_total` | counter | result | 新增；`pass` / `fail` / `dns_error` / `dropped` |
| `mg_cf_ip_filter_active` | gauge | listener | 新增 |
| `mg_edge_info`、`mg_edge_requests_total`、`mg_edge_request_duration_seconds`、`mg_edge_request_errors_total` | — | — | Phase 0 已有，保留 |

标签只取有界值：`route` 来自配置包的路由名，`limiter` 来自配置包，`signal` 来自 §9.3 的固定表。

mgctl 用 node_exporter textfile 格式输出（`--metrics-textfile <path>`，原子写）：WP-G3 的 `mg_cf_audit_failed_checks{zone, check}`（0/1）、`mg_cf_audit_last_run_timestamp_seconds{zone}`、`mg_cf_ips_sync_timestamp_seconds`（最近一次成功同步的时间；告警表达式用 `time() - mg_cf_ips_sync_timestamp_seconds` 得到 06 §5 的 `mg_cf_ips_sync_age_seconds`）；WP-G2 的 `mg_bundle_published_version{site}`（`bundle publish` 写出，§9.10 的新鲜度告警用）。

## 14. mgctl 命令（WP-G2、WP-G3）

### 14.1 命令一览与约定

| 命令 | 作用 | 审计 action | WP |
|---|---|---|---|
| `mgctl keys gen --kid <kid> --out-dir <dir> [--insecure-test-key]` | 所有者 Ed25519 签名密钥（§12.6） | `keys.gen` | G2 |
| `mgctl keys gen-pseudo --out <file.json.age>` | 假名化密钥（age 加密，§12.7） | `keys.gen_pseudo` | G2 |
| `mgctl keys gen-upstream --out <file.json.age> [--rotate]` | 上游密钥头值；`--rotate` 读取现有文件，新值放前，保留 2 个；另把 `values[0]` 打印到 stdout（写入 Cloudflare 规则用） | `keys.gen_upstream` | G2 |
| `mgctl keys export --in <file.json.age> [--out <file> \| -]` | 解密站点 / 假名化 / 上游密钥文件；缺省写 stdout（管道到 `systemd-creds encrypt`，§17），`--out` 写 0600 明文 | `keys.export` | G2 |
| `mgctl site keys gen --site <id> --out-dir <dir> [--date YYYYMMDD]` | `token.keys.json.age` + `seal.root.json.age` | `site_keys.gen` | G2 |
| `mgctl site keys rotate-token --site <id> --file <token.keys.json.age> [--date YYYYMMDD]` | 新 token key 放前，至多保留 3 个；打印新 kid | `site_keys.rotate_token` | G2 |
| `mgctl site keys rotate-seal --site <id> --file <seal.root.json.age> --step add\|promote\|retire [--date YYYYMMDD]` | 根密钥轮换三步（§17）：`add` 把新根放在第二位，`promote` 交换两个根，`retire` 删除第二个根 | `site_keys.rotate_seal` | G2 |
| `mgctl verdict key --pseudo-key <file.json.age> --site <id\|all> --type ip\|prefix\|asn\|session --value <v>` | 打印 verdict 的完整 Valkey 键（`ip` 按 §9.7 先取 ip 实体），供所有者手工 `SET`（D-10）；只读，不写审计 | — | G2 |
| `mgctl site check --site-config <site.yaml>` | 只校验站点 YAML 与策略（不复制工件） | — | G2 |
| `mgctl bundle build --site-config <site.yaml> --out-dir <dir> [--version N]` | 写 `<dir>/<site>.sitebundle.pb`、`<dir>/<site>.sitebundle.json`（protojson，只供人看）与 `<dir>/artifacts/<sha256>` | — | G2 |
| `mgctl bundle sign --in <pb> --key <kid>.key.age --out <file.bundle>` | 签名（§3.2 的签名输入） | `bundle.sign` | G2 |
| `mgctl bundle verify --in <file.bundle> --pub <kid>.pub… [--site <id>] [--json]` | 验签、解码、打印摘要 | — | G2 |
| `mgctl bundle publish --in <file.bundle> --artifacts <dir> --dest <dir> --pub <kid>.pub… --confirm <site> [--metrics-textfile <path>]` | 验签后发布到目录（§12.1）；版本必须大于目标目录中已有的版本；写 `mg_bundle_published_version{site}`（§9.10） | `bundle.publish` | G2 |
| `mgctl audit verify [--audit-log <path>]` | 校验哈希链；打印条数与最后的 hash；断链时报出行号 | — | G2 |
| `mgctl cf audit --site-config <site.yaml> [flags]` | §14.3 | — | G3 |
| `mgctl cf ips sync --out <file> [flags]` | §14.4 | `cf.ips.sync` | G3 |
| `mgctl crawler sync --registry <src.yaml> --out <file> [--previous <file>] [--accept-change]` | §14.5 | `crawler.sync` | G3 |

- 退出码：`0` 成功；`1` 输入无效或检查失败；`2` 用法错误 / 尚未实现；`3` I/O 或内部错误（含审计追加失败）。
- 写文件一律先写临时文件再 `rename`；不覆盖已有密钥文件。
- 环境变量：`MGCTL_PASSPHRASE_FILE`、`MGCTL_AGE_WORK_FACTOR`（< 18 需要 `--insecure-test-key`，§12.6）、`MGCTL_AUDIT_LOG`、`CLOUDFLARE_API_TOKEN`、`MGCTL_CF_API_BASE`（缺省 `https://api.cloudflare.com/client/v4`，测试指向 httptest）。
- 写入类命令都接受 `--audit-log`；成功写入后调用一次 `env.Audit`；`--confirm` 缺省时若 stdin 是 TTY 则提示输入站点 id，否则报用法错误。
- 出站请求 User-Agent：`mgctl/<version>`；不读 `HTTP_PROXY` 之外的任何身份信息；请求中不带所有者的个人信息。

### 14.2 Go API（WP-G2）

```go
// internal/sitecfg
type Site struct { /* §8.2, one field per YAML key; Dir = directory of the YAML file */ }
type Diagnostic struct { File string; Line, Col int; Severity string /* error|warning */; Message string }
func Load(path string) (*Site, []Diagnostic, error)
func Parse(file string, data []byte) (*Site, []Diagnostic)

// internal/keys
type OwnerKey struct { KID string; Private ed25519.PrivateKey; CreatedAt time.Time }
type OwnerPublicKey struct { KID string; Public ed25519.PublicKey; CreatedAt time.Time }
func GenerateOwnerKey(kid string, now time.Time, rnd io.Reader) (*OwnerKey, error)
func WriteOwnerKey(dir string, k *OwnerKey, passphrase []byte, workFactor int) (keyPath, pubPath string, err error)
func LoadOwnerKey(path string, passphrase []byte) (*OwnerKey, error)
func LoadOwnerPublicKey(path string) (*OwnerPublicKey, error)
// Generators return canonical plaintext JSON (§12.0); callers age-encrypt it. Random bytes are drawn in the
// order of testdata/phase1/README.md, so fixed inputs reproduce testdata/phase1/keys/* byte for byte.
func GenerateSiteKeys(site string, date time.Time, rnd io.Reader) (tokenJSON, sealJSON []byte, err error)
func RotateTokenKey(tokenJSON []byte, date time.Time, rnd io.Reader) (newJSON []byte, newKID string, err error)
func RotateSealRoot(sealJSON []byte, step string, date time.Time, rnd io.Reader) ([]byte, error) // add | promote | retire
func GeneratePseudoKey(date time.Time, rnd io.Reader) ([]byte, error)
func GenerateUpstreamKeys(previous []byte, now time.Time, rnd io.Reader) ([]byte, error)
func EncryptFile(path string, plaintext, passphrase []byte, workFactor int) error  // age scrypt, 0600, no overwrite
func DecryptFile(path string, passphrase []byte) ([]byte, error)
func VerdictKey(pseudoJSON []byte, site, typ, value string) (string, error)        // "mg:v:{site}:{type}:{key}", §9.7
func ReadPassphrase(env cli.Env, confirm bool) ([]byte, error)

// internal/bundle
type BuildOptions struct { Version uint64; Now time.Time; MaxCost uint64 }
// Build fails when a rule has ir_version != 1 or empty expr_ir ("policy IR unavailable"), when an IR
// named_list is not in lists, or when an artifact fails its §12 validation (mmdb: database_type, §7.2).
type BuildResult struct {
    Bundle    *morphgatev1.SiteBundle
    Bytes     []byte            // deterministic marshal
    Artifacts map[string]string // sha256 -> source path
    Warnings  []string
}
func Build(site *sitecfg.Site, opts BuildOptions) (*BuildResult, error)
func SigningInput(bundle []byte) []byte // "mg-bundle-v1" || 0x00 || bundle
func Sign(bundle []byte, key *keys.OwnerKey) (*morphgatev1.SignedBundle, error)
func Verify(signed *morphgatev1.SignedBundle, trusted []*keys.OwnerPublicKey) (*morphgatev1.SiteBundle, error)
type PublishResult struct { BundlePath string; ArtifactsWritten, ArtifactsSkipped int; PreviousVersion uint64 }
func Publish(signed []byte, artifactsDir, dest string, trusted []*keys.OwnerPublicKey, confirmSite string) (*PublishResult, error)

// Golden fixtures (control-plane/testdata/sites/golden/): TestGolden builds golden/site.yaml (no rules) and
// golden/site-rules.yaml with Version 1790000000 and Now 2026-09-27T10:00:00Z, signs both with the
// testdata/phase1 owner test seed and compares with golden-norules.bundle / golden-rules.bundle; -update
// rewrites them. golden-rules.bundle is skipped (and must not exist) while policy.IRVersion == 0 (§2.1).

// internal/audit
type Record struct { /* §12.8, fields in that order */ }
func DefaultPath(getenv func(string) string) (string, error)
func Open(path string) (*Log, error)
func (l *Log) Append(ev cli.AuditEvent, now time.Time) (*Record, error)
func Verify(path string) (count int, lastHash string, err error) // err names the first broken line
```

`internal/mgctl` 的 `newEnv` 把 `Audit` 接到 `audit.Log.Append`（日志路径解析失败时，写入类命令以退出码 3 失败）。

### 14.3 `mgctl cf audit`（WP-G3）

输入：`--site-config`（只读取 `site`、`hosts`、`profile`、`cloudflare.*`；完整校验由 `sitecfg` 负责，cfaudit 用一个只含这些键的宽松结构解析，避免依赖 WP-G2 的包）；可选 `--cf-ips <artifact>`（并读取同目录的 `<artifact>.state.json`）、`--vm-url`、`--sdk-dir`、`--ack <check>=<note>`（把 `manual` 记为已人工确认）、`--strict`（`manual` 视为失败）、`--json`、`--metrics-textfile`。Token 取 `CLOUDFLARE_API_TOKEN`（只读权限，06 §8 的 `cf-audit`）。

| # | id | 级别 | 数据来源（Cloudflare API v4） | 通过条件 |
|---|---|---|---|---|
| 1 | `origin_protection` | error | tunnel：`GET /accounts/{acc}/cfd_tunnel/{id}`（有 `account_id` / `tunnel_id` 时，`status == healthy`，否则 manual）；aop：`GET /zones/{z}/origin_tls_client_auth/settings`、`…/hostnames/{host}`、`/settings/tls_client_auth` | tunnel 健康；或 zone-level / 每个 host 的 per-hostname AOP 已启用，且不是只有全局 AOP |
| 2 | `ssl_mode` | error | `GET /zones/{z}/settings/ssl`（仅 aop） | `full` 或 `strict` |
| 3 | `aop_cert_expiry` | warning | `GET /zones/{z}/origin_tls_client_auth`（仅 aop） | 所有证书 `expires_on` 剩余 ≥ 30 天 |
| 4 | `remove_visitor_ip_headers` | error | `GET /zones/{z}/managed_headers` | `remove_visitor_ip_headers` 未启用 |
| 5 | `visitor_location_headers` | warning | 同上 | `cloudflare.location_headers` 为 true 时 `add_visitor_location_headers` 已启用 |
| 6 | `transform_rule_signals` | error | `GET /zones/{z}/rulesets/phases/http_request_late_transform/entrypoint` | 存在 `ref` 匹配 `^mg_signals_v\d+$` 的启用规则；13 个 Tier 0 头的 `set` 表达式与期望表一致（`ciphers_sha1` 允许两种拼写）；4 个 Tier 1 头名为 `remove`；表达式为 `true` 或覆盖站点全部 host。期望表写在 Go 代码中（`adapters/` 在 Go module 之外，无法 embed），另有测试把它与 `adapters/cloudflare/transform-rule.request-headers.json` 逐项比对 |
| 7 | `pseudo_ipv4` | error | `GET /zones/{z}/settings/pseudo_ipv4` | `off`，或 `overwrite_header` 且 `pseudo_ipv4_overwrite` |
| 8 | `zero_rtt` | warning | `GET /zones/{z}/settings/0rtt` | `off` |
| 9 | `bot_fight_mode` | error | `GET /zones/{z}/bot_management`（Free） | `fight_mode == false`；读取被拒时 manual |
| 10 | `sbfm_skip` | error | 同上（Pro+）与 custom rules 入口规则集 | SBFM 各组为 allow；或 `mg_skip_mg_paths` 覆盖 `/__mg/` 且 `phases` 含 `http_request_sbfm`；tunnel 时 definitely automated 必须 allow |
| 11 | `skip_rule_order` | warning | `…/phases/http_request_firewall_custom/entrypoint`、`…/http_ratelimit/entrypoint` | `mg_skip_mg_paths` 排在所有 block / challenge 规则之前；存在匹配 `/__mg/` 的限速规则时 Skip 的 `phases` 不含 `http_ratelimit`；`mg_skip_cleared`（若有）表达式排除 `/__mg/` |
| 12 | `cache_bypass_mg` | error | `…/phases/http_request_cache_settings/entrypoint` | 最后一条规则的 `ref` 为 `mg_bypass_mg_paths`，动作 bypass，表达式与模板一致（空白规范化后比较） |
| 13 | `ttl_override_trap` | error | 同上 | 没有"可缓存 + `edge_ttl.mode = override_origin` 或 `status_code_ttl`"且表达式未限定静态扩展名的规则（可用 `--ack` 按规则 ref 确认例外） |
| 14 | `cf_challenge_overlap` | warning | custom rules | 没有 challenge 类动作的规则表达式为 `true` 或提到站点路由路径 |
| 15 | `rocket_loader` | warning | `GET /zones/{z}/settings/rocket_loader`；`--sdk-dir` 的模板 | `off`，或模板 SDK 标签带 `data-cfasync="false"` |
| 16 | `ai_bot_policy` | warning | `GET /zones/{z}/bot_management` 的 AI bot 相关字段 | 模式 A：全部 allow（字段缺失时 manual） |
| 17 | `precursor` | warning | 读取接口需确认 | 总是 manual（除非 `--ack`） |
| 18 | `runtime_metrics` | error / warning | `--vm-url` 的 `/api/v1/query`（`increase(…[24h])`） | `mg_cf_connecting_ip_missing_total`、`mg_upstream_auth_failures_total{reason="bad_secret_header"}`、`mg_cf_foreign_worker_total` 增量为 0（error）；`mg_upstream_signal_missing_total` 缺失率 < 1%（warning）；无 `--vm-url` 时 skip |
| 19 | `ip_snapshot_age` | warning | `--cf-ips` 的 `.state.json` | `last_success` 在 48 h 内；无参数时 skip |
| 20 | `optional_rules` | info | 限速入口规则集 | 只报告 `/__mg/` 洪泛限速规则是否存在 |
| 21 | `always_use_https` | error | `GET /zones/{z}/settings/always_use_https` | `on`（`__Host-` 凭证 Cookie 只在 https 下保存，D-32）；另报告 HSTS（`security_header`）是否开启（info） |

- 状态：`pass`、`fail`、`warn`（warning / info 级失败）、`manual`、`skip`。退出码：任一 error 级为 `fail`（或 `--strict` 下为 `manual`）→ 1，否则 0。
- 入口规则集返回 404 视为"没有规则"。API 权限不足（403）时对应检查为 `manual` 并在明细中写出缺少的权限。
- 输出：人读表格（`#`、`id`、级别、状态、明细）；`--json` 输出 `{"zone","plan","checks":[{"n","id","level","status","detail"}],"errors":N}`。套餐由 `GET /zones?name=<zone>` 的 `plan.legacy_id` 判断。
- 测试：`internal/cfapi` 与 `internal/cfaudit` 的测试全部用 `httptest` 伪造 API（夹具在 `control-plane/testdata/cloudflare/<scenario>/`），至少覆盖"全绿"、每个 error 级检查各自失败、403 → manual、404 入口规则集。

### 14.4 `mgctl cf ips sync`（WP-G3）

`GET https://api.cloudflare.com/client/v4/ips`（无需认证；`--url` 覆盖，只接受 https）→ 要求 `success == true`，取 `result.ipv4_cidrs`、`ipv6_cidrs`、`etag` → §12.2 校验 → 与 `--previous`（缺省为 `--out` 的现有文件）比较：`etag` 相同 → 不改工件；条数变化超过 30% → 拒绝（退出码 1），除非 `--accept-change`；否则原子写 `--out`。无论是否变化，成功时写 `<out>.state.json`（`{"v":1,"last_success":"<RFC 3339>","etag":"…"}`）并更新 `--metrics-textfile`。有变化时写审计。只有内容变化才改变工件字节，所以配置包里的工件哈希不会因每日同步而变化。

### 14.5 `mgctl crawler sync`（WP-G3）

读源文件（§12.3），逐个抓取 `ip_ranges[*].url`（https，至多 3 次同为 https 的重定向，响应 ≤ 16 MiB，超时 30 s），按 `format` 解析，逐条按 §12.3 校验（任一 CIDR 不合格 → 该运营方抓取失败），合并去重后写工件。某个运营方抓取失败时：若 `--previous`（缺省为 `--out` 的现有文件）中有该运营方，沿用其 `cidrs` 并标记 `stale: true`、打印警告；否则整个命令失败（退出码 1）。**变化保护**（D-36）：与 `--previous` 相比，任一运营方的 CIDR 条数变化超过 50%（增或减），或新出现的 CIDR 覆盖的地址数超过原有总数的一倍，则拒绝（退出码 1、打印差异），除非给出 `--accept-change`。测试用 `httptest.NewTLSServer`，并用 `testdata/phase1/artifacts/` 的样例。

## 15. 工作包说明

每个 WP 的"完成定义"都包含 §2.4 的全部条目，下面只列各自特有的内容。"所有权"一律见 §2.2。

### WP-R1 mg-core 与 IR 转换（阶段 1）

- **输入**：§3.4、§3.5、§4、§5；已落地的 `core/src/{paths,gcra}.rs`；`testdata/policy-ir/`（WP-G1 产出，合入前可先用自己写的少量 IR 用例开发）。
- **输出**：§5.6 的全部公共 API（`paths`、`gcra` 已落地，只需保持）；`phase1_detectors()`；`ScorerV1`；`derive_bot_class`；`SitePolicy`；`ua::parse`；`policy::Glob`；`policy::max_steps`；`proto/rust/src/ir.rs`（含 `max_steps` 复算）；`decision.proto` 改动（§3.4，含 `outside_ranges`）与重新生成的 `decision.pb.go`。
- **测试**：每个检测器的正反例与 MISSING / ABSENT 分支；评分公式（族封顶、shadow、`h_min`、verdict 只升不降、硬规则下限、置信度 κ 与分母）用手算的固定用例；BotClass 优先级；矩阵每一格（含 `matrix.satisfied`、`require_clearance`、爬虫策略、已验证爬虫的非 GET 请求落到后续分支）；规则引擎（阶段顺序、优先级、dry_run 不终止、LOG / TAG 累积、过期、rollout 分桶的确定性与大致比例、hits 上限）；静态步数上界（每种节点、饱和、`cond` 取较大分支）与运行时步数不超过上界（随机 Activation 下）；`Glob`（与 `funcs.go` 的 `glob` 相同的用例表、字面前缀、通配符计数）；IR 加载的各项上限、非法 IR 与 `max_steps` 不符；一致性套件全部通过；`make wasm-check` 在 CI 通过（mg-core 不得引入新依赖）。
- **完成**：`DecisionCore` 能对一个手工构造的 `RequestContext` + `RequestExtras` 端到端给出 `Evaluation`。

### WP-R2 mg-challenge（阶段 1）

- **输入**：§6、`kat.json`、`testdata/phase1/keys/`、`mg_core::SealedChallengeClaims`（含 `ipa`）、`mg_core::paths`。
- **输出**：§6.7 的 API。
- **测试**：§6.8。
- **完成**：Edge 需要的全部密码学操作都能用 `mg-challenge` 的公共 API 完成，调用方不需要直接使用 pasetors / chacha20poly1305。

### WP-R3 mg-intel（阶段 1）

- **输入**：§7、§12.2–§12.4、`testdata/phase1/artifacts/`。
- **输出**：§7.6 的 API；`intel/testdata/mmdb/*.mmdb` 与生成器。
- **测试**：§7.7。

### WP-C1 mg-edge-core `upstream` 与 `request`（阶段 1）

- **输入**：§9.2（密钥头比较）、§9.3、§9.3.1、§9.3.2、§9.4 第 1 步、§4.1 大小上限。
- **输出**（签名可加私有辅助项）：

```rust
// edge-core/src/upstream.rs
pub fn is_upstream_family(name: &str) -> bool;                  // lower-case, '_' -> '-', §9.3 list
pub fn connection_listed(headers: &[(&str, &[u8])]) -> Vec<String>; // lower-cased names listed by Connection
pub struct CloudflareSite<'a> { pub location_headers: bool, pub tier1: bool, pub owner_zones: &'a [String],
                                pub pseudo_ipv4_overwrite: bool }
pub enum ClientIp { Known(IpAddr, IpSource), Unknown { header_missing: bool } }
pub enum WorkerZone { None, Owner, Foreign }
pub struct CfHeaders { pub client_ip: ClientIp, pub worker: WorkerZone, pub cf_ray: Option<String>,
    pub visitor_https: bool, pub edge_tls: Option<mg_core::EdgeTls>, pub http_version: Option<String>,
    pub rtt_ms: Option<u32>, pub upstream_asn: Option<u32>, pub upstream_country: Option<String>,
    pub upstream_region: Option<String>, pub upstream_timezone: Option<String>, pub cf_vbot: Option<bool>,
    pub cf_vbot_cat: Option<String>, pub header_names: Option<Vec<String>>, pub tier1: Option<Tier1>,
    pub missing_signals: Vec<&'static str> /* for mg_upstream_signal_missing_total */ }
pub fn parse_cloudflare(headers: &[(&str, &[u8])], site: &CloudflareSite<'_>) -> CfHeaders;
pub fn secret_header_ok(value: Option<&[u8]>, accepted: &[Vec<u8>]) -> bool;   // constant time

// edge-core/src/request.rs
pub enum Reject { UriTooLong, HeaderTooLarge, BadMethod, BadHost }
impl Reject { pub fn status(self) -> u16; pub fn reason(self) -> &'static str; }
pub fn check_limits(method: &str, path: &str, query: &str, headers: &[(&str, &[u8])]) -> Result<(), Reject>;
pub fn check_header_count(distinct_names_after_hygiene: usize) -> Result<(), Reject>;
pub fn resolve_host(host_header: Option<&str>, authority: Option<&str>, absolute_form_host: Option<&str>)
    -> Result<String, Reject>;                                   // normalized: lower-case, no port / trailing dot
pub fn header_order(raw_names_in_arrival_order: &[&str]) -> Vec<String>; // distinct, first occurrence, <= 128
```

- **测试**：`upstream_*.rs`、`request_*.rs`：头族判定（大小写与下划线变体、全名表）；`Connection` 列出的头；`cloudflare` 解析表的每一行（有效、非法、缺失；Tier 1 标记有 / 无；`location_headers` 关闭时忽略位置头）；`CF-Connecting-IP` 缺失 / 非法 / 映射地址；`CF-Worker` 为 owner zone、外部 zone、非法值（视为外部）；密钥头常量时间比较（等长、不等长、两个有效值）；每个协议上限的边界（8192 / 8193 字节、128 / 129 个头名、Cookie 例外）；Host 与 `:authority`、绝对形式不一致 → `BadHost`；随机输入不 panic。
- **完成**：E1a 只需把 Pingora 的请求头适配成切片即可调用。

### WP-C2 mg-edge-core `bundle`（阶段 1）

- **输入**：§3.2、§8.2（进入配置包的边界）、§8.3、§9.10、§12.1、§12.6（公钥文件）、`testdata/phase1/keys/owner-test.pub` 与 seed。
- **输出**：

```rust
// edge-core/src/bundle.rs
pub struct OwnerKeys { /* kid -> ed25519_compact::PublicKey */ }
impl OwnerKeys { pub fn from_pub_files(files: &[(&str, &[u8])]) -> Result<Self, BundleError>; }
pub struct VerifiedBundle { pub bytes: Vec<u8> /* SignedBundle */, pub bundle: mg_proto::v1::SiteBundle, pub sha256: [u8; 32] }
/// Synchronous: size, SignedBundle decode, key_id, Ed25519 over "mg-bundle-v1" || 0x00 || bundle,
/// SiteBundle decode, schema_version, site_id, hosts (as sets), §8.2 bounds. No version check.
pub fn verify_bundle(bytes: &[u8], keys: &OwnerKeys, site_id: &str, hosts: &[String]) -> Result<VerifiedBundle, BundleError>;
pub enum Source { File(PathBuf), Http(reqwest::Url) }
pub struct Fetcher { /* reqwest client built with no_proxy(), same-origin redirect policy (<= 3), UA, CA / client cert */ }
impl Fetcher {
    pub fn new(cfg: &FetcherConfig) -> Result<Self, BundleError>;
    pub async fn fetch_bundle(&self, root: &Source, site: &str, etag: Option<&str>) -> Result<Fetched, BundleError>;
    pub async fn fetch_artifact(&self, root: &Source, sha256_hex: &str, max_size: u64) -> Result<Vec<u8>, BundleError>;
}
pub enum Fetched { NotModified, Body { bytes: Vec<u8>, etag: String } }
pub struct StateDir { /* state_dir/bundles, state_dir/artifacts */ }
impl StateDir {
    pub fn read_lkg(&self, site: &str) -> std::io::Result<Option<Vec<u8>>>;
    pub fn write_lkg(&self, site: &str, signed: &[u8]) -> std::io::Result<()>;   // tmp + fsync + rename
    pub fn artifact(&self, sha256_hex: &str) -> std::io::Result<Option<Vec<u8>>>; // verifies the hash
    pub fn store_artifact(&self, sha256_hex: &str, bytes: &[u8]) -> std::io::Result<()>;
    pub fn gc(&self, keep: &BTreeSet<String>) -> std::io::Result<usize>;
}
/// One site's poll loop; calls `apply` with each new verified candidate (the caller converts it with
/// mg-core / mg-challenge / mg-intel and swaps the runtime). Runs until `shutdown` fires.
pub async fn poll_loop(site: SiteSource, fetcher: Arc<Fetcher>, dir: Arc<StateDir>, keys: Arc<OwnerKeys>,
                       apply: impl Fn(VerifiedBundle, BTreeMap<String, Vec<u8>>) -> Result<(), String> + Send + Sync,
                       shutdown: tokio::sync::watch::Receiver<bool>);
```

- **测试**：`bundle_*.rs`：用 `ed25519-compact` 与 owner 测试 seed 在测试中签名构造配置包（辅助函数 `testkit::http::sign_test_bundle(site: &SiteBundle, seed: &[u8; 32], kid: &str) -> Vec<u8>`，供 E1 复用）；坏签名、未知 kid、截断、超长、`schema_version`、`site_id`、`hosts` 不符、§8.2 边界的每一项；`file://` 与 `testkit::http`（ETag / 304 / 重定向同源与跨源 / 超时 / 超大响应）；设置 `HTTP_PROXY` 等环境变量时仍直连（§9.10）；LKG 写入的原子性（写到一半的临时文件不会被读到）；工件哈希与大小不符；`gc` 不删除保留集合中的文件；随机输入不 panic。
- **完成**：E1a 只需提供"把 `VerifiedBundle` 转成站点运行时"的函数与 `ArcSwap`。

### WP-C3 mg-edge-core `state`（阶段 1）

- **输入**：§9.7、§9.8（内置限速器的参数形状）、`core/src/gcra.rs` 与 `core/testdata/gcra-cases.json`、`kat.json` 的 `entity_key` 与 `ip_entity`。
- **输出**：

```rust
// edge-core/src/state.rs
pub fn kh(k_pseudo: &[u8; 32], domain: &str, typ: &str, value: &str) -> String;   // §9.7, 32 lower-hex
pub struct LimiterKey { pub site: String, pub limiter: String, pub dims: String }  // dims per §9.7 ('?' for unknown)
pub struct LimitCheck { pub key: LimiterKey, pub params: mg_core::gcra::GcraParams, pub cost: u32, pub write: bool }
pub struct RoundTrip1 { pub verdict_keys: Vec<String>, pub limits: Vec<LimitCheck> }
pub struct RoundTrip1Result { pub verdicts: Vec<Option<String>>, pub limits: Vec<mg_core::gcra::GcraOutcome>, pub mode: StateMode }
pub struct NonceIssue { pub site: String, pub nonce: [u8; 16], pub ttl_ms: u64, pub limits: Vec<LimitCheck> }
/// Fresh / Unavailable carry the issuance-quota outcomes (from Valkey, or from the local table when Valkey
/// gave no answer); Unavailable = no authoritative replay check (§9.7 rules 3-4), the caller decides by fail_closed.
pub enum NonceResult { Reused, Fresh { limits: Vec<mg_core::gcra::GcraOutcome> }, Unavailable { limits: Vec<mg_core::gcra::GcraOutcome> } }
pub enum StateMode { Valkey, Local }
pub struct StateConfig { /* edge.toml [valkey] */ }
/// Handle used by proxies: sends requests to the StateService over a bounded channel (§9.1.1).
#[derive(Clone)] pub struct StateHandle { /* mpsc sender, local tables, breaker */ }
impl StateHandle {
    pub async fn round_trip1(&self, req: RoundTrip1) -> RoundTrip1Result;            // falls back to local
    pub async fn nonce_issue(&self, req: NonceIssue, now_ms: i64, c_iat_ms: i64) -> NonceResult; // §9.7 replay rules
    pub fn record_failure(&self, limits: Vec<LimitCheck>) -> bool;                   // async, bounded; false = dropped
    pub async fn xadd_batch(&self, maxlen: u64, entries: Vec<Vec<(&'static str, String)>>) -> Result<(), StateError>;
    pub fn local_check(&self, check: &LimitCheck, now_us: u64) -> mg_core::gcra::GcraOutcome; // scope = local
}
/// Owns the Valkey connection; runs inside a Pingora background service (mg-edge wraps it).
pub struct StateService { /* ConnectionManager, scripts, breaker */ }
impl StateService { pub fn new(cfg: StateConfig) -> (Self, StateHandle); pub async fn run(self, shutdown: tokio::sync::watch::Receiver<bool>); }
pub const MG_GCRA_LUA: &str = include_str!("state/lua/mg_gcra.lua");
pub const MG_NONCE_ISSUE_LUA: &str = include_str!("state/lua/mg_nonce_issue.lua");

// edge-core/src/testkit/valkey.rs (feature "testkit")
pub struct ValkeyFixture { /* url, key prefix, child process */ }
impl ValkeyFixture { pub async fn start() -> Option<Self>; pub fn url(&self) -> &str; pub fn site(&self) -> &str; }
pub struct FaultProxy { /* 127.0.0.1:0 listener -> target (tcp or unix) */ }
impl FaultProxy {
    pub async fn start(target: &str) -> std::io::Result<Self>;
    pub fn url(&self) -> String;                  // redis://127.0.0.1:<port>/
    pub fn set_mode(&self, mode: FaultMode);      // Pass | Refuse | Blackhole | ResetExisting
    pub fn round_trips(&self) -> u64;             // client->server bursts answered by server->client bursts
}
```

- **测试**：`state_*.rs`：`kh` 与 `kat.json` 一致（含 `?` 与 /64 用例）；`mg_gcra` 在真实 Valkey 上对 `gcra-cases.json` 的每个用例（显式 `now_us`）与 `mg_core::gcra_check` 逐项一致；`mg_nonce_issue`：首次 / 重复 nonce、配额允许 / 拒绝、拒绝时不写任何 TAT、重复 nonce 时不计配额；每个请求类型的往返次数（经 `FaultProxy::round_trips`：普通请求 1 次、`/__mg/c` 2 次）；`FaultProxy` 置为 `Blackhole` 后在 `timeout_ms` 内回退本地、熔断打开与翻倍、恢复后回到 Valkey（服务容器与自启实例都能跑）；本地 GCRA 表的溢出桶；本地重放集合满时返回 `Unavailable`、从不逐出未过期项；`local_replay_authoritative` 与"C 早于进程启动"的判定；异步失败通道满时丢弃计数；随机输入不 panic。
- **完成**：E1b / E1c 只需构造请求并解释结果。

### WP-C4 mg-edge-core `events`（阶段 1）

- **输入**：§9.11、§13.1–§13.6。
- **输出**：§9.11 的 `EventSink`、`EventRecord`、`EventClass`、`Sink`；`StreamEntry`（有序字段列表）；`EventQueues::new(cfg) -> (EventQueues, Flusher)`；`Flusher::run(self, vl: Option<VlClient>, file: Option<PathBuf>, stream: Option<Arc<dyn StreamWriter>>, shutdown)`，`trait StreamWriter { async fn xadd_batch(&self, maxlen: u64, entries: Vec<StreamEntry>) -> Result<(), String>; }`（mg-edge 用 `StateHandle::xadd_batch` 实现）；`envelope(kind, site, ts_ms, msg, body: serde_json::Value) -> String`（§13.2 的信封字段放在对象开头）；`TelemetryEnv::from_json(&[u8]) -> Option<Self>` 与其规范重新序列化（§9.11）。
- **测试**：`events_*.rs`：`testkit::vl` 收到的查询参数、`Content-Type`、行格式与信封字段；批量阈值（行数、字节数、间隔）；重试与退避、429 / 5xx 重试、其他 4xx 不重试；队列满时的丢弃计数与 P0 优先；文件出口；`StreamWriter` 收到的字段顺序（§13.6）；关闭时 P0 尽力发送；遥测重新序列化丢弃未知字段并截断超长字符串；出站请求不走代理环境变量。

### WP-G1 策略编译器与一致性套件（阶段 1）

- **输出**：
  - `IRVersion = 1`；`func Lower(cr *CheckedRule) (*morphgatev1.PolicyExpr, error)`；`func MaxSteps(e *morphgatev1.Expr) uint64`（§5.3 静态上界，按 §4.1 大小上限）；`(*CheckedRule).Proto()` 填 `ExprIr`（确定性字节，含 `max_steps`）与 `IrVersion`；`CompiledRuleJSON` 增加 `expr_ir`（标准 base64）与 `max_steps`；`Compiler.Check` 对 §5.2 的构造与步数上界超限报错（在 `walk` 中完成，错误定位到子表达式）。
  - cel-go 环境加 `cel.HomogeneousAggregateLiterals()`（§5.1）；`sizeHints` 与 §4.1 大小上限表完全一致。
  - `Input` 增加 `identity.crawler.claimed` 与全部 `json` 标签；`http.header_order` 的注释；`availability.go` 按 §4.4 更新。
  - 参考求值器：`func (e *Evaluator) EvalWithMissing(cr *CheckedRule, in *Input, missing []string) (Result, error)`，`type Result int`（`ResultFalse`、`ResultTrue`、`ResultUnknown`、`ResultError`），语义按 §5.3 最后一段；现有 `Eval` 保留（等价于没有 MISSING）。
  - `CheckedRule.Lists` 已落地，保持。
  - `testdata/policy-ir/cases.json` 与生成的 `cases.ir.json`（§5.8）。
- **测试**：`TestIRConformance`；拒绝构造的诊断信息（含异构列表与步数上界）；`all-fields.yaml`、`cloudflare-site.yaml`、`docs06-examples.yaml` 全部能降级为 IR；`&&` / `||` 展平；IR 字节在两次运行之间相同；`MaxSteps` 的手算用例。
- **跨 WP**：与 WP-G2 中后合入者按 §2.1 生成 `golden-rules.bundle`。
- **完成**：`mgctl policy compile` 输出每条规则的 `expr_ir` 与 `max_steps`；`make go-check` 中的一致性检查全绿。

### WP-G2 mgctl 运维（阶段 1）

- **输入**：§8.2、§8.3、§12.0、§12.1、§12.6–§12.8、§14.1、§14.2；`policy` 包的现有公共 API（含 `CheckedRule.Lists`）；`testdata/phase1/keys/`。
- **输出**：§14.2 的包；`mgctl` 新命令与帮助文本；`go.mod` 增加 `filippo.io/age`、`golang.org/x/term`、`github.com/oschwald/maxminddb-golang/v2`；`control-plane/testdata/sites/` 下的有效 / 无效站点 YAML 夹具与 `golden/`（`site.yaml`、`site-rules.yaml`、`golden-norules.bundle`，§14.2 的 `TestGolden`）；`control-plane/README.md`（全部 mgctl 命令）。
- **测试**：站点 YAML 的每条校验规则（§8.2 表的每一行至少一个反例）；构建结果的确定性（同样输入同样字节，`--version` 固定时）；缺省值消息完整填充（§8.3）；默认路由追加；规则排序与过滤（disabled / 过期）；缺 IR 的规则让 `Build` 失败；工件哈希与复制、mmdb `database_type` 校验；签名输入的域前缀（与 `kat.json` 的 `bundle_signature.domain_prefix_hex` 一致）；Go 签名 → Go 验签；错误密钥 / 篡改字节 / 未知 kid 被拒；密钥生成在固定随机流与时间下与 `testdata/phase1/keys/*` 逐字节相同；age 加密往返（`MGCTL_AGE_WORK_FACTOR=10` 加 `--insecure-test-key`）；没有该标志时工作因子 < 18 被拒；错误口令；`keys export` 到 stdout 与文件；`rotate-seal` 三步；`verdict key` 与 `kat.json` 的 `entity_key` 一致；发布的版本单调、先工件后配置包、写出 textfile 指标；审计日志追加、链校验、篡改任一字节可定位到行；`--confirm` 不符被拒；审计失败时退出码 3；`TestGolden`。
- **跨语言验证**：`golden-norules.bundle`（阶段 1 即可生成）与 `golden-rules.bundle`（§2.1）由 WP-E1a 的测试用 Rust 验签与解码。

### WP-G3 Cloudflare 与情报同步（阶段 1）

- **输入**：§12.0、§12.2、§12.3、§13.7、§14.3–§14.5；08 §2.10、§2.11；`testdata/phase1/artifacts/`。
- **输出**：`internal/cfapi`、重写的 `internal/cfaudit`（保留 `RunCLI` 签名，21 项检查）、`internal/intelsync`（替换桩）；`deploy/intel/crawler-registry.yaml`；`control-plane/testdata/cloudflare/**` 与 `control-plane/testdata/intel/**` 夹具；`adapters/cloudflare/` 中可选的 `set x-mg-upstream-key` 规则模板（§17）与相应的 `adapters-check` 测试。
- **测试**：§14.3 所列（含 `always_use_https`）；IP 段同步的 etag 不变、变化、超 30% 被拒、非法 CIDR、私有地址段，以及对样例 API 响应写出与 `artifacts/cloudflare-ips.json` 逐字节相同的文件；爬虫同步的两种格式、重定向、超大响应、单个运营方失败沿用旧值与无旧值时失败、`artifacts/invalid/crawler-registry.*.json` 的每种 CIDR 问题被拒、变化保护与 `--accept-change`、`crawler-registry.json` 往返不变。

### WP-W1 Web SDK（阶段 1）

- **输入**：§10.2、§10.3、§11、`kat.json`。
- **输出**：`src/challenge.ts`、`src/sha256.ts`、`src/pow.ts`（Worker 协议与搜索）、`scripts/build-dist.mjs`（导出 `buildDist`）、`templates/challenge.html`；`SDK_VERSION = "0.1.0-phase1"`；README 更新。
- **测试**：§11.5。
- **完成**：`dist/sdk/` 可直接作为 Edge 的 `[sdk] dir`。

### WP-E1a mg-edge 骨架（阶段 2，第 1 个）

- **输入**：阶段 1 全部产出；§8.1、§9.1、§9.1.1、§9.2、§9.3（接线）、§9.4、§9.9（转发与源站头）、§9.10（接线）、§16。
- **输出**：`edge.toml` v1 与 `--check-config`（含 LKG 与上游密钥头检查）；进程与运行时模型（后台 service：`mg-bundles`，以及 `mg-state` / `mg-events` / `mg-rdns` 的空壳与句柄）；`EdgeTlsAccept`；上游信任、协议上限、站点状态机、外部 Worker 403、路由匹配、monitor / bootstrap 转发与源站头；配置包 → 站点运行时（规则经 `mg_proto::ir::rule_from_proto`、名单、路由的 `Glob`、限速器参数、`TokenKeySet`、`SealKeys`、工件经 mg-intel 解析）；`OsRng`（`getrandom`）；更新后的样例配置、冒烟脚本、systemd 单元（`ExecReload` 先 `--check-config`）；`Makefile` 与 `ci.yml`（§16：Valkey 服务容器、SDK 夹具、MSRV 作业）；根 `Cargo.toml` 的 `pingora` 特性 `connection_filter`。
- **测试夹具**（本 WP 提交，E1b–E1d 共用）：`edge/tests/fixtures/sdk/`（最小的 `manifest.json`、一个 JS 文件与满足 §11.2 的 `challenge.html`，使 `rust` 作业不需要 Node）、`edge/tests/fixtures/keys/`（复制 `testdata/phase1/keys/` 的明文样例，或在测试中直接引用它们）、用 WP-C2 的测试签名辅助函数在测试中生成的配置包。
- **测试**（`edge/tests/`，全部只用回环地址）：`upstream_trust.rs`（头族剥离含下划线变体、密钥头、非回环对端、`CF-Connecting-IP` 缺失 / 非法、**外部 zone Worker → 403 且计数**、Tier 1 标记、`MG-*` 双向剥离、`Connection: MG-Client-IP` 不能删掉 Edge 写入的头、XFF 单值、IP 未知时 `MG-Client-IP: unknown` 且不转发 `CF-Connecting-IP`、上游 `Host` 为规范化主机名）；`protocol_limits.rs`（414 / 431 / 400 各一例，monitor 下同样拒绝；1 MiB 请求体的早期拒绝后连接被关闭、Edge 没有读完正文）；`routing.rs`（`/account/login/`、`/Account/Login`（开 / 关 `case_insensitive_paths`）、`/account%2Flogin`、`/account/login;x` 都选中 critical 路由；多路由命中取最高敏感度；flags 取"或"）；`bundle_load.rs`（`golden-norules.bundle` 与 `golden-rules.bundle` 验签与解码；坏签名、未知 kid、版本回退、同版本不同字节、hosts 不符、工件哈希不符、`not_before`；LKG 重启恢复；三种站点状态与 503；LKG 缺工件时照常应用且字段 MISSING；`--check-config` 在 LKG 无效时失败）；`tls.rs`（`direct_tls` 的 SNI 与 ALPN 经 `EdgeTlsAccept` 到达请求；`origin_mtls` 的错误 CA 只计一次 `untrusted_ca`）；`smoke.rs` 与 `shipped_configs.rs` 更新为 v1 配置。
- **完成**：`make check` 与 CI 全绿；`scripts/edge-smoke.sh` 用 v1 配置（本地文件配置包、local 状态模式）通过；一个 monitor 模式的站点能在 Cloudflare 之后运行（决策层此时为占位：一律 ALLOW 并记录 `rule_id = "e1a.passthrough"`，E1b 替换）。

### WP-E1b mg-edge 决策（阶段 2，第 2 个）

- **输入**：§4.3、§5（通过 mg-core）、§9.5–§9.8、§9.9（阻断与限速）。
- **输出**：`RequestContext` / `RequestExtras` / `MissingSet` / Activation 输入；凭证校验；爬虫验证、`mg-rdns` service、hickory `DnsResolver` 与错误映射、按前缀的任务限流与 `abandon`；`mg-state` service 与限速器接线（local / global、兜底键 `?`、溢出桶）；verdict 读取；`DecisionCore` + `SitePolicy`；RATE_LIMIT / BLOCK 响应；`fail_closed` 且 IP 未知的 429。
- **测试**：`decision.rs`（一个请求从头到尾：各检测器的输入到达、`missing_input` 的 hit、monitor 下只记录）；`crawler.rs`（`StaticResolver` 配置下的 `ip_ranges` 同步失败、`rdns` 首请求 pending 与后续结论、`outside_ranges` 信号、并发满时 `abandon` 后下次请求重新发任务）；`ratelimit_valkey.rs`（通过 `FaultProxy`：普通请求 1 次往返、Valkey 断开后本地回退与熔断恢复、IP 未知的请求共用 `?` 桶、IPv6 同一 /64 的不同地址共用一个桶）；`verdicts.rs`（手工写入的 verdict 抬高分数、解析失败计数）。
- **完成**：enforce 模式下的阻断与限速在本地端到端可用。

### WP-E1c mg-edge 挑战（阶段 2，第 3 个）

- **输入**：§6（通过 mg-challenge）、§9.9（挑战）、§10、§11.2。
- **输出**：Challenge 签发（C、难度、`ret`、IP 未知 → 429、http 访客 → 308）；挑战页渲染与 CSP；`/__mg/s/*`；`/__mg/c` 全流程（§10.3 的每一步、正文规则、重放检查与 `fail_closed` 判定、签发配额、失败升级、失败计数）。
- **测试**：`challenge_flow.rs`：GET → 403 挑战页（CSP、nonce、占位符已替换、无 `{{`）；JSON Challenge；用 `mg_challenge::pow_solve` 解题后表单提交 → 303 + Cookie → 带 Cookie 的请求放行且 `MG-Session` 存在；重放同一提交 → 403；篡改 C、换 UA、换 Host、超长正文、`Content-Encoding`、`Early-Data`、重复 `mg` 字段、带 charset 参数的媒体类型 → 各自结果；失败配额（按 ip 实体与按前缀）→ 429；签发配额用尽 → 429 且没有 `Set-Cookie`；**客户端 IP 未知时的 CHALLENGE 与 `/__mg/c` → 429 且没有 C / Cookie**；**Valkey 不可用（`FaultProxy`）且 C 签发于 critical 路由 → 429、没有 `Set-Cookie`**，非 critical 路由 → 签发且 reason `ic.replay_unchecked`；路由已从配置包删除 → 按 `fail_closed`；本地重放集合填满后按不可用处理；失败后的新 C 为 `pow` 且风险段升一级；http 访客 GET → 308；bootstrap 下 `/__mg/c` → 404。
- **完成**：不执行 JS 的客户端在 enforce 下拿不到凭证（§18）。

### WP-E1d mg-edge 观测（阶段 2，第 4 个）

- **输入**：§9.1.1（第 5 条）、§9.11、§13。
- **输出**：`mg-events` service 与各类事件的组装（decision / access / feedback / telemetry / stream）、路径脱敏、采样；§13.7 的全部指标与附加延迟的分段计时；`scripts/edge-smoke.sh` 的守护进程模式检查。
- **测试**：`events_sink.rs`（本地伪 VictoriaLogs 收到的四种 `kind`、信封字段、`redact_path`、采样规则）；`metrics.rs`（§13.7 的指标名与标签出现在 `/metrics` 中；附加延迟不含源站连接时间：源站人为延迟连接时 `mg_edge_added_latency_seconds` 不变而 `mg_origin_connect_seconds` 增加）；`logs.rs`（捕获日志，断言不含测试请求的客户端 IP、Cookie 值、C 与凭证）；冒烟脚本 `-d` 模式。
- **完成**：阶段 3 可以开始；E1d 的负责人在阶段 3 继续负责 `edge/` 的缺陷修复（§2.1）。

### WP-L1 Validation Lab（阶段 3）

- **replay 扩展**（`lab/internal/replay`）：请求级字段 `delay_ms`（0–10000，发送前等待）、`expect_status_in`（列表）、`expect_header`（头名 → 期望子串）、`expect_header_absent`（头名列表）、`expect_cookie_absent`（Cookie 名列表，检查响应的 `Set-Cookie`）、`expect_body_contains`；场景级 `vars`（在 `path`、头值、正文中替换 `${name}`，值来自 `-var name=value` 命令行参数，供 e2e 脚本注入端口等）。仍不生成载荷、不变异、不并发；目标仍经 `guard`。
- **场景**（`lab/testdata/scenarios/`，请求只发往 `127.0.0.1`）：
  - `phase1-impersonator.yaml`：以 `CF-Connecting-IP`（模拟 Cloudflare 回环隧道，对象是本地 Edge）声称 Googlebot / GPTBot 但来自不在官方段的文档地址；`ip_ranges` 运营方从第一个请求起 403；`rdns` 运营方第一个请求为非 403（`DECLARED_AGENT`），`delay_ms` 之后的请求全部 403；另有来自注册表官方段（`crawler-registry.test.json` 的文档地址段）的真爬虫请求放行。
  - `phase1-nonjs-clearance.yaml`：对 `require_clearance` 路由的 GET → 403 且无 `__Host-mg_clr`；提交一个录制好的过期 / 伪造 C → 403 且无 Cookie；再次 GET → 仍 403；带外部 zone `CF-Worker` 的请求 → 403。场景只回放固定请求，不包含任何求解逻辑。
- **e2e 脚本** `scripts/lab-e2e.sh`：临时目录中生成测试密钥（`MGCTL_PASSPHRASE_FILE`、`MGCTL_AGE_WORK_FACTOR=10` 加 `--insecure-test-key`）、站点密钥与假名化密钥，并用 `mgctl keys export --out` 写成 Edge 读取的明文文件；用 `lab/testdata/e2e/` 的站点 YAML、测试注册表（`test: true`，CIDR 为文档地址段）与 `StaticResolver` JSON 构建、签名、发布配置包（`monitor_only: false`，enforce）；启动 `valkey-server`（或 `MG_TEST_VALKEY_URL`）、python 源站、mg-edge（`events.file` 出口）；运行两个场景；再从事件文件断言：冒充请求的 `risk.bot_class == "impersonator"` 占比 100%（按 D-22 计），非 JS 场景没有任何 `feedback.outcome == "pass"`。全部只用回环地址；缺少依赖时给出明确的跳过信息。
- **Makefile / CI**：新增 `make lab-e2e`（不进 `make check`）；CI 新增 `lab-e2e` 作业：下载 `rust` 作业上传的 `mg-edge` 二进制工件（避免在该作业再编译 BoringSSL 与 aws-lc），装 Go（构建 `mgctl`、`mglab`）、Node + pnpm（构建 SDK）、Valkey 服务容器与 `python3`。
- **完成**：本地与 CI 的 `lab-e2e` 通过；`lab/README.md` 更新。

### WP-J1 JA4 预研（阶段 3）

- **做法**：ADR-0002 决策 4 的链路——在 E1a 的 `TlsSettings::with_callbacks` 设置上（`DerefMut` 到 `SslAcceptorBuilder`）加 BoringSSL select-certificate 回调，取 `ClientHello::as_bytes()`；用自研解析器（对照 huginn-net-tls 或 FoxIO JA4 规范的测试向量；不引入 pcap / pnet 依赖）计算 JA4；写入 SSL ex_data；在 `EdgeTlsAccept::handshake_complete_callback` 返回的 `TlsFacts` 中加 `ja4`；请求过滤器读出并填 `ctx.tls.ja4 = {value, source: self, authenticated: true}`。只在 `direct_tls` 监听器的 `ja4_spike = true` 时启用（配置项，不是 cargo 特性）。策略与评分侧继续按 D-07 视为 MISSING（只进事件，便于 shadow 观察）。
- **测试**：用 boring 客户端以固定参数握手，断言事件中的 JA4 等于手算值；会话恢复与 HTTP/2 下的行为记录在测试注释中；回调中的分配与耗时测量（criterion 不必，普通计时测试记录数量级）。
- **输出**：ADR-0002 勘误段落（日期、结论：链路是否可行、每握手开销、限制与后续建议），状态保持"已接受"。

### WP-D1 文档勘误（阶段 3）

把 §0.3 中"需改设计文档"为"是"的决定写回设计文档与 ADR（ADR-0005 勘误：Ed25519 实现口径、`ipa`、凭证 claims（`sst`）与 kid 格式、根密钥轮换；ADR-0006 勘误：静态步数上界；01 §8：本地重放集合的语义与平滑升级窗口；02 §2 / §2.1 / §7 / §8：外部 Worker 拒绝、未知 IP 原则、路由多视图匹配、`ip` 实体、键哈希、`mg:ev` 字段、`MG-Tags`、源站契约补充；03：verdict 只升不降、矩阵抑制、已验证爬虫与写方法；04 §3.1 / §4.1 / §4.2 / §5 / §6.3：挑战升级、失败配额、PoW 实现与难度、凭证绑定与 http 访客、签发配额；05 §7.2：验证模式、注册表校验、`outside_ranges`；06 §1 / §2 / §5 / §6 / §7 / §8：规则顺序、阶段性 MISSING、输入上限、指标标签与新增指标、路径脱敏与日志内容、`pseudo` 密钥；08 §1.5 / §2.10：监听器与站点配置的划分、`always_use_https` 检查；10：把 Phase 1 实现的威胁条目状态改为"Phase 1 实现"并注明测试名，VK-02 标为已采纳）；更新根 README 的索引（链接本文）与 CLAUDE.md 的命令表（`make lab-e2e`）。`make docs-check` 必须通过。

## 16. 测试策略与 CI

| 层 | 做法 |
|---|---|
| 单元测试 | 每个 crate / 包内；纯函数优先；解析器随机输入测试（§2.4） |
| 已知答案向量 | `testdata/phase1/kat.json`：Rust（WP-R2、WP-C3）与 TypeScript（WP-W1 的 PoW）读同一个文件；`core/testdata/gcra-cases.json`：Rust 与 Lua 读同一个文件 |
| 共享格式样例 | `testdata/phase1/keys/`、`testdata/phase1/artifacts/`：Go 写入方逐字节产生有效样例，Rust / Go 读取方接受有效样例、拒绝无效样例（§12.0） |
| 跨语言一致性 | `testdata/policy-ir/`：Go 生成并校验 IR 字节（含 `max_steps`）与 cel-go 结果，Rust 求值同一批用例 |
| 跨语言签名 | WP-G2 的 `golden-norules.bundle` / `golden-rules.bundle` 由 Rust 验签（WP-E1a） |
| Edge 集成测试 | `edge/tests/`，回环地址，真实 mg-edge 二进制或进程内服务 |
| Valkey | `mg_edge_core::testkit::valkey::ValkeyFixture`：有 `MG_TEST_VALKEY_URL` 时连接它（用随机站点 id 做键前缀，从不 `FLUSHALL`）；否则 PATH 中有 `valkey-server`（或 `redis-server`）时启动一个只监听 unix socket 的临时实例（`--port 0 --unixsocket <tmp>/v.sock --unixsocketperm 700 --save "" --appendonly no`，没有端口竞争），测试结束时终止；都没有则打印 `SKIPPED: no valkey-server (set MG_TEST_VALKEY_URL or install valkey)` 并跳过。`MG_REQUIRE_VALKEY=1` 时跳过改为失败。故障与往返计数一律经 `FaultProxy`（绑定 `127.0.0.1:0` 的 TCP 转发器，目标可以是服务容器的 TCP 或自启实例的 unix socket），所以断连、黑洞与恢复测试在 CI 的服务容器上同样运行；不用 `MONITOR` 计数（并行测试共享服务器时噪声太大） |
| CI | WP-E1a 在 `rust` 作业中加入 Valkey 服务容器（`valkey/valkey:9.1.2-alpine`，按 digest 固定）并设置 `MG_TEST_VALKEY_URL`、`MG_REQUIRE_VALKEY=1`；`rust` 作业用 `edge/tests/fixtures/sdk/`，不需要 Node；新增 `msrv` 作业：`dtolnay/rust-toolchain`（按 SHA 固定）装 1.88，运行 `cargo check --workspace --all-targets --locked`（工作区代码的 1.89+ API 另由 clippy 的 `incompatible_msrv` 在 `-D warnings` 下拦截）；`rust` 作业上传 `mg-edge` 发布二进制供 `lab-e2e` 使用；WP-L1 新增 `lab-e2e` 作业（§15）。`make check` 不依赖 Docker |
| 不做 | 负载生成、对任何非回环 / 非白名单目标的请求；Lab 场景中的求解逻辑 |

附加延迟的验收不做压测：以生产（或所有者自有 staging）的 `mg_edge_added_latency_seconds` p99 为准（§17）；开发期可以用 `cargo test` 中的计时测试观察 Decision Core 的数量级。

## 17. 所有者运维手册（代码之外）

1. **Cloudflare 侧**：确认套餐（07"仍待确认"）；关闭 Bot Fight Mode（Free）；部署 Tier 0 Transform Rule（`adapters/cloudflare/transform-rule.request-headers.json`；启用上游密钥头时加一条 `set x-mg-upstream-key` 静态值，值取 `mgctl keys gen-upstream` 打印的 `values[0]`）；开启 "Add visitor location headers"、确认 "Remove visitor IP headers" 关闭；开启 Always Use HTTPS（建议同时开 HSTS）；部署 `/__mg/` Skip 规则与放在最后的 Cache Bypass 规则；保持 0-RTT、Pseudo IPv4 关闭；Rocket Loader 关闭或保留 `data-cfasync`。
2. **大脑 VM**：
   - Valkey：`maxmemory` 与 `maxmemory-policy noeviction`；内存规划分两块：重放键（`mg:n:*`，约 `提交速率 × 180 s × 100 字节`）与限速键（`mg:rl:*`，约 `不同键数 × TTL 内存活比例 × 100 字节`；`ip` 实体按 /64 计后，单个 IPv6 用户不会制造无界的键），各留 50% 余量；`used_memory / maxmemory > 70%` 告警（10 VK-03、VK-05）。
   - Valkey ACL（Edge 用户，按选择器写，实测后记录；10 VK-02、VK-06）：`ACL SETUSER edge on >… resetkeys resetchannels -@all +get +set +mget +evalsha +script|load +ping +xadd +time +select +client|setinfo +client|setname %R~mg:v:* ~mg:rl:* ~mg:n:* %W~mg:ev`。Edge 不能写 `mg:v:*`（verdict 在 Phase 1 由所有者手工写）、不能访问 `mg:rev:*`、不能 `PUBLISH`、不能 `SCRIPT FLUSH` / `SCRIPT KILL`、`FLUSHALL`、`CONFIG`。WP-E1b 在 `edge/tests/valkey_acl.rs` 中对测试实例（自启实例或服务容器上的随机用户名）建立这个用户，断言 Edge 的全部操作成功、上述每个被禁操作被拒。所有者的管理用户另建。
   - VictoriaLogs `vl-main` / `vl-short`、VictoriaMetrics（`-retentionPeriod=13`）；静态文件服务器（`/srv/mg/`，只绑定 WireGuard 或要求 mTLS）。
   - 告警（vmalert）：`mg_site_state{state!="active"} == 1`（持续 5 分钟）；`mg_bundle_published_version != on(site) max by (site)(mg_config_version)` 持续 10 分钟（配置未生效或被扣留，§9.10）；`increase(mg_cf_foreign_worker_total[1h]) > 0`；`increase(mg_cf_connecting_ip_missing_total[1h]) > 0`；`increase(mg_rdns_lookups_total{result="dropped"}[10m]) > 0`；`increase(mg_policy_step_limit_total[1h]) > 0`；`mg_config_age_seconds > 120`；`mg_state_mode{mode="local"} == 1`（Valkey 模式的 Edge 上持续 5 分钟）。
3. **所有者工作站**：`mgctl keys gen`、`keys gen-pseudo`、`keys gen-upstream`、每个站点 `site keys gen`（密钥文件都是 `.age`，工作站上没有明文）；用 MaxMind 账号下载 GeoLite2-ASN / Country；`mgctl cf ips sync`、`mgctl crawler sync`（定时任务每日运行；变化保护拒绝时人工核对后 `--accept-change`）；写站点 YAML 与策略；`bundle build → sign → publish --metrics-textfile …`；两步 rsync 到大脑 VM。
4. **Edge 主机**：cloudflared 隧道指向 `127.0.0.1:8080`；密钥交付不在任何磁盘留下明文：`mgctl keys export --in blog/token.keys.json.age | ssh edge 'sudo systemd-creds encrypt --name=mg-blog-token-keys - /etc/credstore.encrypted/mg-blog-token-keys'`（`seal.root`、`pseudo.key`、`upstream-keys`、Valkey 口令同理），单元中 `LoadCredentialEncrypted=`；复制 SDK 目录（`sdk/web/dist/sdk/`）；写 `edge.toml` v1；`mg-edge --check-config`；启动。journald 保留期设为 ≤ 14 天（`SystemMaxRetentionSec=14day`）：应用日志不含个人数据（D-31），但错误日志不需要更久。
5. **密钥轮换顺序**：
   - **凭证密钥**：`site keys rotate-token` → 在每台 Edge 上更新 `token.keys` credential 并 `systemctl reload mg-edge`（新 kid 必须先出现在所有 Edge 的密钥文件里）→ 站点 YAML 把新 kid 设为 `active_kid`、旧 kid 放进 `verify_kids` → `bundle publish`（否则配置包因 `token_key_ids` 不在密钥文件中而被拒）→ 至少一个凭证有效期之后，从 `verify_kids` 删除旧 kid 并发布；再过一个周期可从密钥文件删除。删除后仍带旧 kid 的凭证按 `expired` 处理（不加风险，重新挑战）。
   - **封装根密钥**（D-30）：`rotate-seal --step add`（新根在第二位）→ 部署到所有 Edge 并 reload；`--step promote`（新根封装）→ 部署并 reload；至少 125 s 后 `--step retire` → 部署并 reload。任一时刻所有 Edge 都能打开彼此签发的 C。
   - **所有者签名密钥**：新 `.pub` 先加入每台 Edge 的 `[trust] owner_keys` 并 reload → 用新密钥签发并发布新版本 → 所有 Edge 的 `mg_config_version` 都更新后，才从 `[trust]` 删除旧 `.pub`（否则现有 LKG 无法验证，站点进入 `lkg_invalid` 并 503；`--check-config` 会先报出来）。
6. **monitor 周**：站点 YAML `monitor_only: true` 连续运行 ≥ 7 天；每日看 vmui：`mg_edge_added_latency_seconds` p99 < 5 ms、`mg_cf_connecting_ip_missing_total`、`bad_secret_header` 与 `mg_cf_foreign_worker_total` 为 0、`mg_upstream_signal_missing_total` 缺失率、`mg_config_age_seconds`、`mg_event_dropped_total`、`mg_protocol_rejected_total`；在 VictoriaLogs 中按路由统计"本应"的挑战 / 阻断比例，校准 θ_c、z0 与权重（改站点 YAML 发新版本）。
7. **真人浏览回归**：主流浏览器（含移动端）手工浏览关键路径；把一个测试路由临时设为 `require_clearance` 并在 enforce 下确认挑战页能自动通过、跳回原页面、Cookie 生效；自有 E2E（若有）通过。
8. **收尾**：`mgctl cf audit --site-config … --vm-url … --cf-ips …` 全绿（`manual` 项逐一 `--ack`）；`mgctl audit verify` 通过。

## 18. 验收映射

| 07 Phase 1 验收项 | 证据 | 谁 |
|---|---|---|
| 自有站点经 Cloudflare 以 monitor 模式连续运行 ≥ 1 周 | §17 第 6 步；`mg_config_version` 与请求计数的时间序列 | 所有者 |
| 附加延迟 p99 < 5 ms | `mg_edge_added_latency_seconds` 的 p99（生产 / 自有 staging；定义见 §13.7） | 所有者（指标由 WP-E1d 提供） |
| 冒充爬虫 100% 识别 | `make lab-e2e` 的 `phase1-impersonator` 场景与事件断言（D-22） | WP-L1 |
| 不执行 JS 的脚本客户端在 enforce 下拿不到凭证 | `make lab-e2e` 的 `phase1-nonjs-clearance` 场景；`edge/tests/challenge_flow.rs` | WP-L1、WP-E1c |
| `mgctl cf audit` 全绿 | §17 第 8 步 | 所有者（工具由 WP-G3 提供） |
| 真人浏览回归无功能破坏 | §17 第 7 步 | 所有者 |
| JA4 预研结论写入 ADR-0002 | ADR-0002 勘误 | WP-J1 |

## 19. 待实测与未决

| 项 | 影响 | 处理 |
|---|---|---|
| `cf.tls_ciphers_sha1` 与 `cf.tls_client_ciphers_sha1` 哪个拼写有效；HTTP/3 与会话恢复时 `cf.tls_*` 是否有值 | EDGE_TLS 缺失告警的噪声 | monitor 周观察 `mg_upstream_signal_missing_total{signal}`；`cf audit` 两种拼写都接受 |
| Tunnel 下 `CF-Connecting-IP` 等头是否到达 | 客户端 IP | monitor 周首日确认 `mg_cf_connecting_ip_missing_total` 为 0 |
| 普通访客自己发送的 `CF-Worker` 头是否被 Cloudflare 删除或覆盖 | 若不删除，任何访客都能让自己的请求被 403（只影响自己，不再能获得更宽松的处理，D-23） | monitor 周用 `curl -H 'CF-Worker: example.org'` 对自有站点实测，结果写入 WP-D1 的 08 §2.2 更新 |
| `GET /zones/{z}/bot_management` 在各套餐下的字段（BFM、SBFM、AI bot） | `cf audit` 9 / 10 / 16 | 字段缺失时 `manual`，所有者确认后 `--ack` |
| Valkey ACL 选择器（`%R~`、`%W~`）在 9.1 上对脚本内访问的键是否按预期生效 | VK-02 | `edge/tests/valkey_acl.rs` 实测；结果写入 WP-D1 的文档更新 |
| 挑战页在 Cloudflare 之后 403 + `no-store` 是否被缓存 | CH-09 | monitor 周用 `cf-cache-status` 抽查（应为 `DYNAMIC` / `BYPASS`） |
| Cloudflare 是否把源站的 `425`、`414`、`431` 原样回传浏览器 | 早期数据与协议上限的用户体验 | monitor 周抽查；414 / 431 只影响超长请求 |

## 20. 评审处置

两轮评审（R1：安全与语义；R2：可实现性与工程）的每条意见。"核实"一栏记录对照真实源码或文档得到的结论；"部分采纳"与"不采纳"写明理由。

### 20.1 R1（安全与语义）

| # | 级别 | 意见 | 处置 | 核实 / 理由 | 落点 |
|---|---|---|---|---|---|
| R1-1 | blocker | 客户端 IP 未知让 Edge 更宽松，外部 zone 的 Worker 可以主动进入该状态 | 采纳 | ADR-0004、02 §2.1、08 §2.2、10 CF-02 都要求拒绝外部 zone 的 `CF-Worker`；原稿确有偏离且未列入 §0.3 | D-23；§9.3.2；§9.4；§9.7 兜底键 `?`；§6.2 / §6.4 / §6.5（`ipp` 必有）；§10.3 第 0 步；§19；E1a / E1c 测试 |
| R1-2 | major | `/__mg/c` 没有路由，重放存储不可用时不知道用哪个 `fail_closed` | 采纳 | — | §9.7 重放检查第 5 条（`route_class` 路由 ∨ `ret` 路由，找不到则 fail_closed）；E1c 测试 |
| R1-3 | major | LRU nonce 集合会逐出未过期的 nonce | 采纳 | 10 VK-03 要求不得静默逐出 | D-35；§9.7 本地模式与重放检查；§8.1 `local_nonce_capacity`；C3 / E1c 测试 |
| R1-4 | major | 路由只按一个规范化视图、大小写敏感地匹配，可被绕过 | 采纳 | — | D-25；§9.4；已落地 `mg_core::paths::route_candidates`；`SiteBundle.case_insensitive_paths`；E1a `routing.rs` |
| R1-5 | major | 运行时步数超限判"不命中"，攻击者加长路径即可让阻断规则失效 | 采纳（改为拒绝超限输入） | ADR-0006 决策 8；`env.go` 的 `sizeHints` 假设 8 KiB 但原稿没有执行。超长输入直接 414 / 431，而不是当作信号：否则上界仍不成立 | D-26；§4.1 大小上限；§5.3 静态步数上界（`PolicyExpr.max_steps` 已落地）；§9.3.1 |
| R1-6 | major | `1 in [1.0, "a"]` 在 cel-go 中为 true，与 Rust 语义不一致 | 采纳 | 已用 cel-go v0.30.0 实测：确为 true、`[1, 2.0]` 可编译；加 `HomogeneousAggregateLiterals()` 后三者都在类型检查时报错 | §5.1；§5.2；§5.8 的 `compile_error` 用例 |
| R1-7 | major | `ip` 维度按完整 IPv6 地址，可轻易绕过且键无界 | 采纳 | — | D-24；已落地 `Net::entity_of` 与 `kat.json` 的 `ip_entity`；§9.7 本地表容量与溢出桶；§17 内存规划 |
| R1-8 | major | LKG 存在但不可用时落到 bootstrap（全部放行） | 采纳 | — | D-21 重写；§9.10 站点状态；§8.1 `bootstrap` 与 LKG 检查；`mg_site_state`；systemd `ExecReload` 先检查；§17 告警 |
| R1-9 | major | 签发配额只记信号，没有消费者 | 采纳（强制执行） | 04 §5、§6.3 要求限制签发 | D-37；§9.7 `mg_nonce_issue`（nonce 首次使用才计配额）；§9.8；§10.3 第 2b、9 步 |
| R1-10 | major | 爬虫注册表的 CIDR 未校验，一条宽泛段就让伪造 UA 越过挑战 | 采纳 | — | D-36；§12.3 校验；§14.5 变化保护；§5.5 已验证爬虫的写方法；`testdata/phase1/artifacts/invalid/` |
| R1-11 | minor | epoch 接受范围与测试矛盾、上一 epoch 全天有效、根密钥无法平滑轮换、退役 kid 当作 invalid | 采纳 | 原公式在日界后 5 s 内确实接受 `e − 2` | §6.1；`kat.json` 的 `accepted_epochs`；D-30；D-29；§17 轮换顺序 |
| R1-12 | minor | 打开 C 缺少长度检查、RNG 无失败路径 | 采纳 | `chacha20poly1305` 的定长构造对错误长度会 panic | §6.2 第 1、4 步；§6.7 `Rng` 返回 `Result`；§2.4 第 6 条；§9.9 随机数失败 503 |
| R1-13 | minor | `pow_bits`、`fallback_ret`、GCRA 数值、TTL 缺少边界 | 采纳 | Lua 双精度要求所有值 < 2^53 | §8.2 校验表（WP-C2 加载时复查）；已落地 `GcraParams::new` 的 `MAX_DVT_US`；§6.5 `exp − iat ≤ 86400` |
| R1-14 | minor | 失败配额只按 /24，一个客户端可锁住整个 CGNAT 前缀；过期也计失败；异步写无界 | 采纳 | 04 §4.1 说"按会话与 IP 前缀"；Phase 1 挑战前没有会话，用 `ip` 实体代替 | D-28；§9.8；§9.7 有界通道 |
| R1-15 | minor | ASN 0 是否算已知未定义 | 采纳 | — | §4.1；§6.4；§7.2；§9.7 |
| R1-16 | minor | `sub` 可从别的浏览器的凭证沿用，会话可无限续期 | 采纳 | — | D-29；§6.5（`sst`）；§6.7 `reusable_session` |
| R1-17 | minor | 失败后在最低难度上无限重试；`invisible` 与 `pow` 难度相同却证据不同 | 部分采纳 | 不用 `attempt_no` 计升级：已有的 `SealedChallengeClaims::check`（core/src/sealed.rs）要求非交互式 C 的 `attempt_no == 0`，改它会改变 ADR-0005 的封装语义。改为每次失败风险段升一级、次数由失败配额限制；`invisible` 固定最低难度；两种级别的人类证据统一为 −0.4 | D-27；§6.3；§5.7；§10.3 |
| R1-18 | minor | Host 选择、`Connection` 逐跳头、IP 未知时的源站头 | 采纳 | — | §9.3 第 3 步；§9.3.1 `bad_host`；§9.4 第 1 步；§9.9；D-34 |
| R1-19 | minor | 源站按 `MG-*` 变化内容会造成缓存串用 | 部分采纳 | 源站契约采纳。可选的 `cf audit` 警告不做：API 无法判断哪些路由的源站实际依赖 `MG-*` 头，且源站头默认开启，警告会恒为真 | D-34；§9.9 源站契约 |
| R1-20 | minor | Valkey ACL 无法表达"mg:* 除 mg:rev:*"，且允许 `SCRIPT` 全部子命令 | 采纳 | — | §17 第 2 步的选择器；`edge/tests/valkey_acl.rs`；§19 |
| R1-21 | minor | 应用日志、路径与遥测的内容与保留期 | 采纳 | — | D-31；§9.11；`Route.redact_path`（已落地）；§2.4 第 5 条；§17 journald |
| R1-22 | minor | 同主机部署时没有提示启用上游密钥头 | 采纳 | — | §8.1 校验表"上游密钥头"警告 |
| R1-23 | minor | 测试用的低工作因子可用于真实密钥；站点密钥明文留在工作站 | 采纳 | — | §12.6（< 18 需要 `--insecure-test-key`）；§12.7 `.json.age` 与 `keys export`；§17 第 4 步 |
| R1-24 | minor | http 访客拿不到 `__Host-` Cookie，会无限挑战 | 采纳（两者都做） | — | D-32；§9.9 的 308；`cf audit` 第 21 项 |
| R1-25 | minor | rDNS 被挤满时冒充者永远不会被判 IMPERSONATOR | 采纳 | — | D-18 补充；§5.7 `outside_ranges` 信号；§9.6 按前缀限流；§17 告警 |
| R1-26 | minor | 请求体读取截止时间、媒体类型参数、重复字段、JSON 深度 | 采纳 | — | §10.3 |
| R1-27 | minor | PASETO 注册 claim 名的类型 | 采纳（保留整数，只用底层接口） | 已核对 pasetors 0.8.1：`version4::LocalToken::{encrypt, decrypt}` 不做 claims 校验。改名会与 04 §5 的示例不一致，收益小 | §6.5 |
| R1-28 | minor | `http://` bundle_root 与 304 让新鲜度指标失真 | 采纳 | — | §8.1；§9.10 新鲜度；`mg_bundle_published_version`；§17 告警 |

### 20.2 R2（可实现性与工程）

| # | 级别 | 意见 | 处置 | 核实 / 理由 | 落点 |
|---|---|---|---|---|---|
| R2-1 | major | 没有进程与运行时模型；守护进程化会丢掉 `fork` 前创建的运行时 | 采纳 | 已核对 pingora-core 0.9.0 `server/mod.rs`：`run()` 在 `conf.daemon` 时先 `daemonize`，之后才 `create_runtime`；支持 service 依赖与就绪通知 | §9.1.1；E1d 的 `-d` 冒烟检查 |
| R2-2 | major | `validate_ret` 需要 mg-edge 的 `routes::classify`，会形成依赖环或第二份实现 | 采纳（方案 a） | — | 已落地 `core/src/paths.rs`（`edge/src/routes.rs` 改为调用它）；§6.4；§6.7 |
| R2-3 | major | `CrawlerVerifier` 没有释放丢弃任务的接口，在途项会永久卡住 | 采纳 | — | §7.3 在途任务；§7.6 `abandon`、`inflight_ttl_ms`；§9.6 drop guard |
| R2-4 | major | `golden.bundle` 在 G1 之前生成就无法被 Edge 加载，且没有人能再生成 | 采纳 | 已核对 `compile.go`：`IRVersion = 0`，`Proto()` 不填 `ExprIr` | §2.1 第 2 项耦合；§8.3 `Build` 缺 IR 即失败；§14.2 `TestGolden` 与两个 golden 文件 |
| R2-5 | major | 附加延迟指标包含源站连接时间 | 采纳 | 已核对 pingora-proxy 0.9.0：`lib.rs` 在 `get_http_session` 之后才进入 `proxy_h1.rs` 的 `upstream_request_filter` | §13.7 重新定义；`mg_origin_connect_seconds`；E1d 测试 |
| R2-6 | major | CI 的服务容器无法被杀掉，端口竞争，`MONITOR` 计数有噪声 | 采纳 | 故障注入改用转发器后与服务容器无关。"ubuntu-24.04 没有 valkey 包"一点未核实，也不影响方案 | §16 Valkey 行；`testkit::valkey::{ValkeyFixture, FaultProxy}`（C3） |
| R2-7 | major | 写入方与读取方分属不同 WP，格式差异要到阶段 3 才暴露 | 采纳（预先落地样例） | — | 已落地 `testdata/phase1/{keys,artifacts,README.md}`；§12.0 |
| R2-8 | major | 单个阶段 2 WP 是整个关键路径，合入后的缺陷没有修复负责人 | 采纳（结构调整） | 没有拆成 7 个顺序子 WP，而是把不依赖 Pingora 的四块（上游信任、配置包客户端、状态层、事件）移到阶段 1 的预注册 crate `mg-edge-core` 并行完成，剩余集成拆成 4 个顺序 PR | D-33；§0.2；§2.1 修复规则；§2.2；§9.1；§15 |
| R2-9 | minor | `Glob` 没有公共签名；GCRA 用例表没有位置 | 采纳 | — | §5.6 `policy::Glob`；已落地 `core/testdata/gcra-cases.json` 与 `core/src/gcra.rs` |
| R2-10 | minor | 读取 mmdb `build_epoch` 需要额外依赖 | 采纳 | — | §2.3 允许 `maxminddb-golang/v2`；§8.3 构建时检查 `database_type` |
| R2-11 | minor | 名单引用校验需要规则引用的名单名 | 采纳（预先落地） | — | 已落地 `CheckedRule.Lists` 与 `TestReferencedLists`；§8.3 IR 兜底检查 |
| R2-12 | minor | 早期应答后 Pingora 会读完剩余请求体 | 采纳 | 已核对 pingora-core 0.9.0 `protocols/http/server.rs`：`drain_request_body`、`set_total_drain_timeout`、`set_keepalive` | §9.9；§10.1；E1a 测试 |
| R2-13 | minor | reqwest 总会读取代理环境变量；D-04 的理由不成立 | 采纳 | 已核对 reqwest 0.13.5 `Cargo.toml`：`rustls` 特性带 aws-lc-rs，`system-proxy` 只是缺省特性之一；`ClientBuilder::no_proxy` 存在 | D-04 改写；§1.2；§9.10 与测试 |
| R2-14 | minor | `rust` 作业没有 SDK 与签名夹具；`lab-e2e` 作业缺工具链 | 采纳 | — | §15 E1a 测试夹具；§15 L1 下载 `mg-edge` 二进制；§16 |
| R2-15 | minor | proto3 标量无法区分"未设置"，不能按字段回填缺省值 | 采纳 | — | §8.3 末段 |
| R2-16 | minor | manifest 测试在 `build` 之前运行 | 采纳 | — | §11.1 `buildDist` 纯函数；§11.5 |
| R2-17 | minor | 阶段 1 的测试需要未声明的开发依赖 | 采纳 | — | 已落地 `mg-proto` 的 `base64` 开发依赖；§2.3（`Waker::noop()`） |
| R2-18 | minor | MSRV 1.88 只在 1.91 上构建 | 采纳 | — | §16 `msrv` 作业 |
| R2-19 | minor | 所有权矩阵的空隙 | 采纳（README 部分改为单一所有者） | 各 WP 在同一个 README 追加小节会在并行 PR 间冲突；改为 G2 按本文写全所有命令 | 已落地 `mgctl_test.go` 放宽与 `cli.go` 注释修正；`adapters/**` → G3；§2.2；§2.3 |
| R2-20 | minor | rDNS 每次查询的超时与 hickory 错误映射 | 采纳（更正一处事实） | 已核对 hickory-net 0.26.3 `error.rs`：SERVFAIL 以 `DnsError::ResponseCode(ServFail)` 返回，不是 `NoRecordsFound`；`NoRecordsFound` 只用于 NXDOMAIN 与无答案的 NOERROR。映射规则按实际类型写；缺省查找策略确为 `Ipv6AndIpv4` | §9.6；§7.3 |
| R2-21 | minor | `header_order` 无法还原交错的重复头 | 采纳 | — | §4.1；§9.3 第 2 步 |
| R2-22 | minor | SNI 只能经 `with_callbacks` 的握手回调取得；`untrusted_ca` 重复计数；JA4 开关不一致 | 采纳 | 已核对 pingora-core 0.9.0：`TlsSettings::with_callbacks` 不加载证书，`SslDigest` 没有 SNI 字段，`TlsAccept::handshake_complete_callback` 的返回值进入 `SslDigest.extension` | §9.2 `EdgeTlsAccept`；§9.5；§15 J1 用配置项 `ja4_spike`；§19 删除 SNI 未决项 |
| R2-23 | minor | 平滑升级丢失重放集合、bootstrap 下的 `/__mg/c`、手工 verdict 键、密钥轮换顺序 | 采纳 | — | D-35（进程启动前签发的 C 按不可用处理）；§9.10 与 §10.1（bootstrap 时 404）；`mgctl verdict key`；§17 第 5 步 |

没有整条不采纳的意见；部分采纳的 R1-5、R1-17、R1-19、R1-27、R2-8、R2-19、R2-20 的理由见上表。
