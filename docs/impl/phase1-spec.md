# Phase 1 实现规格：Cloudflare 之后的 Edge

**结论**：Phase 1 拆成 11 个工作包（WP），分三个阶段。阶段 1 的 7 个 WP（Rust `core/`、`challenge/`、`intel/`，Go 策略编译器、mgctl 运维命令、Cloudflare 与情报同步，Web SDK）按目录互不重叠，可以并行；阶段 2 由一个 WP 独占 `edge/` 完成集成；阶段 3 做 Validation Lab 场景与端到端脚本、JA4 预研、文档勘误。本文把所有跨组件契约写死：IR proto、Rust / Go 公共 API、`edge.toml` v1、站点 YAML v1、`/__mg/*` 请求与响应、Cookie、Valkey 键与 Lua 脚本、事件 JSON 行与 VictoriaLogs 调用、指标、工件与密钥文件格式。实现者按本文编码，不需要再协商；需要改契约时先改本文。

- 设计依据：[07 Phase 1](../07-roadmap.md)、[02](../02-data-flow.md)、[03](../03-risk-scoring.md)、[04](../04-challenge-and-tokens.md)、[06](../06-policy-console-observability.md)、[08](../08-upstream-and-cloudflare.md)、[09 §4](../09-interactive-challenge.md#4-密封-challenge)、[ADR](../adr/README.md)。设计文档说"是什么、为什么"，本文说"Phase 1 具体怎么做"；两者冲突时，Phase 1 实现以本文为准，WP-D1 负责把设计文档改到一致（§0.3 列出了全部偏离）。
- 规范用语："必须 / 不得"是硬性要求；"应"是默认做法，偏离时在该 WP 的 PR 描述里写明理由；"可"是可选。
- 本文的提交已经落地了一部分契约文件（§0.4），各 WP 从这些文件出发，不重新定义它们。

## 0. 范围、决定与已落地文件

### 0.1 范围

| 在范围内（代码与测试） | 不在范围内 |
|---|---|
| Edge：`cloudflare` profile（Tunnel 回环信任、AOP 客户端证书）、`direct_tls` TLS 监听器；上游头族剥离与可信头解析；站点 / 环境 / 路由匹配；RequestContext 构建；GeoLite2（可选）；爬虫验证（官方 IP 段 + 异步 rDNS）；凭证校验；本地 + Valkey 限速；Decision Core v1（检测器、分族封顶评分、BotClass、策略 IR、默认处置矩阵）；执行动作 allow / log / tag / rate_limit / block / 无感 Challenge（`invisible`、`pow`）；`/__mg/c`、`/__mg/s/*`；签名配置包拉取与 last-known-good；EventSink（VictoriaLogs + `mg:ev`）；指标 | 交互式 Challenge、Provider、Turnstile（Phase 2）；`/__mg/c/renew`、`/__mg/r`、`/__mg/t`（Phase 2，Phase 1 返回 404）；`cnf.jkt`、`MG-Proof`、会话密钥（Phase 2）；近线 worker 与 verdict 生成（Phase 2；Phase 1 只读 `mg:v:*`）；吊销集与 pub/sub（Phase 3）；Web Bot Auth、Agent Registry（Phase 3）；SDK 注入源站 HTML（Phase 2）；TARPIT；PROXY protocol；随机 `/__mg/` 前缀 |
| mgctl：策略编译到 IR、站点 YAML、密钥生成、配置包构建 / 签名 / 校验 / 发布、本地哈希链审计日志、`cf audit`、`cf ips sync`、`crawler sync` | mg-control 服务的任何新功能（Phase 3）；`mgctl cf apply`（写 Cloudflare 规则，按需） |
| Web SDK：挑战页客户端（Worker 中的 SHA-256 PoW、基础环境摘要、表单提交跟随 303）与挑战页模板 | SDK 遥测、行为采集、`cf-mitigated` 处理、fetch 包装（Phase 2） |
| Validation Lab：冒充爬虫场景、非 JS 客户端拿不到凭证场景、端到端脚本 | 任何面向非白名单目标的流量；负载生成 |
| JA4 技术预研（`direct_tls`），结论写入 ADR-0002 勘误 | JA4 进入评分或绑定（`tfp`） |

**所有者操作**（代码之外，见 §17）：在真实 zone 上部署 Transform Rule 等规则、以 monitor 模式在 Cloudflare 之后运行 ≥ 1 周、人工浏览回归、用生产指标确认附加延迟。

### 0.2 WP 编号

| 编号 | 名称 | 阶段 |
|---|---|---|
| WP-R1 | mg-core：检测器、评分 v1、BotClass、默认处置矩阵、策略 IR 求值器与规则引擎、GCRA 数学；IR 线格式转换（`proto/rust/src/ir.rs`） | 1 |
| WP-R2 | mg-challenge：密封 C、epoch 密钥、PoW、PASETO 凭证与绑定 | 1 |
| WP-R3 | mg-intel：IP 集合、GeoLite2、爬虫注册表与验证、Cloudflare IP 段 | 1 |
| WP-G1 | Go 策略编译器：CEL → IR、参考求值器（MISSING 语义）、跨语言一致性夹具 | 1 |
| WP-G2 | mgctl 运维：站点 YAML、密钥、配置包、审计日志、命令分发、`go.mod` | 1 |
| WP-G3 | mgctl Cloudflare 与情报同步：`cf audit`、`cf ips sync`、`crawler sync` | 1 |
| WP-W1 | Web SDK：挑战页客户端与模板 | 1 |
| WP-E1 | mg-edge 集成（独占 `edge/`、根 `Cargo.toml` 的依赖段、`Makefile`、CI） | 2 |
| WP-L1 | Validation Lab Phase 1 场景与端到端脚本 | 3 |
| WP-J1 | `direct_tls` JA4 预研与 ADR-0002 勘误 | 3 |
| WP-D1 | 设计文档勘误、CLAUDE.md / README、威胁模型状态更新 | 3 |

### 0.3 决定与偏离

下表是本文相对设计文档或集成指引作出的决定。WP-D1 把"需改设计文档"一栏为"是"的条目写回设计文档或 ADR。

| # | 决定 | 理由 | 需改设计文档 |
|---|---|---|---|
| D-01 | 预注册工作区成员 `challenge`、`intel`，并在本提交中给出可编译的空 crate、依赖声明与根 `[workspace.dependencies]` 条目；阶段 1 的 Rust WP 不改根 `Cargo.toml` | 避免并行 WP 争用根 `Cargo.toml` 与 `Cargo.lock` | 否 |
| D-02 | 策略 IR 的线格式→原生结构转换放在 `mg-proto`（`proto/rust/src/ir.rs`），`mg-proto` 依赖 `mg-core`；`mg-core` 不引入 prost | `mg-core` 保持最小依赖与 wasm32 可编译；一致性测试需要同时看到两边 | 否 |
| D-03 | Valkey 客户端用 **redis-rs**（`redis` 1.7），不用 fred | redis-rs 2026-09 仍在发版、有 `ConnectionManager` 自动重连、管线、`Script`（EVALSHA + NOSCRIPT 回退）；fred 最近一次发版在 2025-02 | 否 |
| D-04 | 全工作区唯一的 Ed25519 实现定为 **ed25519-compact**（pasetors 的 `v4` 特性本来就依赖它），用于 Edge 验证配置包签名；Go 侧用标准库 `crypto/ed25519` | ADR-0005 要求全工作区只用一个 Ed25519 实现；选 dalek 3 或 aws-lc-rs 都会与 pasetors 的依赖并存 | 是（ADR-0005 勘误） |
| D-05 | 凭证与 C 的绑定新增 `ipa = hash(ASN)`（`SealedChallengeClaims.Bind.ipa`，凭证 `bind.ipa`），用于判定 `ipp` 的软 / 硬结果 | 04 §5 要求"同 ASN 内变化 → 风险信号；跨 ASN → 重新 Challenge"，没有签发时的 ASN 无法判断 | 是（04 §5、09 §4.2、ADR-0005） |
| D-06 | 实体与限速器的 Valkey 键中，标识个人的部分用所有者级假名化密钥 `K_pseudo` 做 HMAC（§9.7）；新增密钥文件 `pseudo.key.json` | 10 VK-04 要求标识个人的键做哈希；`mg:v:all:*` 跨站共享要求哈希与站点无关 | 是（02 §7、06 §8 密钥清单） |
| D-07 | Phase 1 中 `identity.proof.*`、`identity.agent.*` 恒为 MISSING；`direct_tls` 下 `tls.ja4` 恒为 MISSING（JA4 只是预研） | 能力在 Phase 2 / 3 才有；按 ABSENT（零值）处理会让 `login-require-proof` 之类规则永远命中、造成挑战循环 | 是（06 §2 注明阶段） |
| D-08 | Phase 1 没有交互式 Challenge：规则或矩阵要求 `interactive` 时按 `pow`（该请求风险段的难度）执行；规则触发时在其 hit 的 `fields` 记 `phase1.interactive_as_pow`，矩阵触发时由 `rule_id = matrix.critical.high` 与 `challenge_type = pow` 表明；编译器对 `params.type: interactive` 给警告 | 交互式在 Phase 2 | 否（阶段性行为） |
| D-09 | TARPIT 在 Phase 1 不实现：配置包构建时对 `tarpit` 动作报错 | 03 只把它列为 `direct_tls` 可选项 | 否 |
| D-10 | 实体 verdict 在 Phase 1 只能抬高风险：`β_e · max(0, logit(R_e/100))`，封顶 4.0 | 采纳 10 VK-02 的提议；Phase 1 的 verdict 只能由所有者手工写入 | 是（03 §4.1、10 VK-02 标为已采纳） |
| D-11 | 挑战页提交走**表单导航**（`application/x-www-form-urlencoded`，字段 `mg`），成功 303 → `ret`，由浏览器跟随；`application/json` 提交返回 200 `{"ok":true}`（供 Phase 2 SDK 与测试） | 303 由浏览器原生跟随，Set-Cookie 与导航在同一响应链上，不依赖 fetch 的重定向限制 | 否（与 04 §9 一致） |
| D-12 | PoW 搜索用纯 JS SHA-256（Worker 中同步计算，预计算前缀），WebCrypto 只做自检 | WebCrypto `digest` 是逐次异步调用，hashcash 搜索慢一个数量级以上 | 是（04 §4.2 措辞） |
| D-13 | SDK 构建产物带内容哈希文件名 `mg.<hex16>.js`，Worker 用同一脚本 URL 启动（脚本自身识别 Worker 上下文）；Edge 只从 SDK 目录的 `manifest.json` 白名单提供 `/__mg/s/*` | 一个可缓存文件；CSP 只需 `worker-src 'self'` | 否 |
| D-14 | 监听器（绑定地址、TLS 文件、上游认证方式、上游密钥头）与站点的源站地址是主机本地配置，只在 `edge.toml`；站点的 Cloudflare 属性（visitor location 头、Tier 1、owner zones、Pseudo IPv4）在签名配置包 | 监听器无法热更换且每台主机不同；zone 属性与 `cf audit` 结果绑定，属于策略 | 是（08 §1.5 示意） |
| D-15 | Phase 1 不做 `mg:pub:cfg` 通知，Edge 只按间隔（默认 10 s）条件拉取 | Phase 1 的 mgctl 在工作站运行，不连 Valkey；10 s 满足"配置生效 < 30 s" | 否（02 §6 已写两阶段口径，注明 Phase 1 无提示） |
| D-16 | 事件 JSON 行在 `mg_core::DecisionEvent` 的 JSON 上加信封字段（`kind`、`site`、`ts`、`msg`）；`/insert/jsonline` 以 `_stream_fields=kind,site`、`_time_field=ts`、`_msg_field=msg` 写入 | VictoriaLogs 文档（2026-09-27 核对）：jsonline 端点、查询参数与嵌套字段展平规则 | 否 |
| D-17 | `mg_event_dropped_total`、`mg_config_version`、`mg_config_age_seconds` 带有界标签（`sink` / `site`） | 多站点 Edge 需要按站点区分配置版本；按出口区分丢弃 | 是（06 §5 标签列） |
| D-18 | 爬虫注册表的验证方式分 `ip_ranges`、`rdns`、`ip_ranges_or_rdns`：只有 `ip_ranges` 的运营方，IP 不在官方段即同步判为失败；需要 rDNS 的，首个请求为 `pending`（`DECLARED_AGENT`），异步反查后结论入缓存 | 满足"rDNS 不在请求路径上同步执行"，同时让只发布 IP 段的运营方能 100% 同步识别冒充 | 是（05 §7.2 补充） |
| D-19 | 策略规则的阶段内顺序：`priority` 大者先，同优先级按 `id` 字节序；`disabled` 与已过期的规则不进配置包 | 06 §1 未定义 `priority` 方向 | 是（06 §1） |
| D-20 | 默认处置矩阵增加"凭证已满足"抑制：请求带有效凭证且其级别不低于矩阵要下发的 Challenge 类型时，改为 TAG（`matrix.satisfied`） | 否则高分的真人每个请求都被重复挑战 | 是（03 §5.1 注释） |
| D-21 | 没有配置包（首次启动且拉取失败）时，站点以 bootstrap 模式运行：全部放行、记录事件（`rule_id = "bootstrap"`、`bundle_version = 0`）并告警 | 保持站点可用；放宽从未经签名包生效，因为 bootstrap 等价于 monitor | 否 |
| D-22 | Validation Lab 的"冒充爬虫 100% 识别"按**结论已确定的请求**计：`ip_ranges` 方式从第一个请求起；`rdns` 方式在热身请求触发反查之后；热身请求本身须为 `DECLARED_AGENT` 且从不判为 `VERIFIED_CRAWLER` | 与 D-18 一致 | 否 |

### 0.4 本提交已落地的契约文件

| 文件 | 内容 | 之后的所有者 |
|---|---|---|
| `Cargo.toml`、`Cargo.lock` | 成员加入 `challenge`、`intel`；`[workspace.dependencies]` 加入 `mg-challenge`、`mg-intel` 与 §1.2 中这两个 crate 的第三方依赖（已锁定） | WP-E1（阶段 2 起） |
| `challenge/`、`intel/` | 可编译的空 crate（`Cargo.toml` 已声明依赖，`lib.rs` 只有文档注释） | WP-R2、WP-R3 |
| `proto/morphgate/v1/policy_ir.proto` | 策略 IR 的最终消息定义（§3.1） | WP-G1 与 WP-R1 共同只读；修改需先改本文 |
| `proto/morphgate/v1/config.proto` | Phase 1 配置包 schema（§3.2） | WP-G2 与 WP-E1 共同只读 |
| `proto/morphgate/v1/challenge.proto` | `Bind.ipa`（D-05） | WP-R2 只读 |
| `core/src/sealed.rs`、`core/src/context.rs` | `ChallengeBind.ipa`；`BindResult::SoftMismatch`（`soft_mismatch`） | WP-R1 |
| `proto/rust/`（`build.rs`、`Cargo.toml`、`src/ir.rs` 占位、`tests/roundtrip.rs`） | 编译 `policy_ir.proto`；`mg-proto` 依赖 `mg-core` | WP-R1 |
| `control-plane/gen/morphgate/v1/*.pb.go` | 已按上述 proto 重新生成 | 生成文件只随 proto 变更 |
| `control-plane/internal/cli/` | mgctl 子命令契约 `cli.Env`、`cli.AuditEvent`、退出码（§14.1） | WP-G2（只可追加字段） |
| `control-plane/internal/intelsync/`、`cfaudit.RunCLI` | 子命令入口桩 | WP-G3 |
| `control-plane/internal/mgctl/` | 分发已接好 `cf audit`、`cf ips`、`crawler`；测试不再固定策略告警条数与 IR 版本 | WP-G2 |
| `testdata/phase1/kat.json` | 密钥派生、aad、绑定哈希、`ret` 哈希、实体键、PoW 的已知答案向量（§6、§9.7） | 只读；修改需先改本文 |
| `CLAUDE.md` | 新 crate、`testdata/`、本文的索引 | WP-D1 |

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
                                          ├──> Valkey: MGET mg:v:*, EVALSHA mg_gcra, SET NX mg:n:*, XADD mg:ev
                                          ├──> VictoriaLogs vl-main / vl-short: POST /insert/jsonline
                                          └──> /metrics (scraped by VictoriaMetrics)
```

### 1.2 Rust crate 与依赖

```
mg-core (pure, wasm32)  <──  mg-proto (prost types + ir.rs conversion)
      ^   ^                         ^
      |   └──────── mg-challenge ───┘   (pasetors, chacha20poly1305, hkdf, sha2, hmac, base64)
      └──────────── mg-intel            (maxminddb, sha2)
mg-edge ──> mg-core, mg-proto, mg-challenge, mg-intel, pingora =0.9.0, redis, hickory-resolver, reqwest, ...
```

| crate | 新增第三方依赖（版本已在根 `Cargo.toml` 或由 WP-E1 添加） | 约束 |
|---|---|---|
| `mg-core` | 无 | 纯函数；wasm32 可编译；`core/clippy.toml` 继续生效 |
| `mg-proto` | 无（新增对 `mg-core` 的普通依赖） | 只放生成代码与线格式转换 |
| `mg-challenge` | `pasetors 0.8.1`（`default-features = false`，`std` + `v4`）、`chacha20poly1305 0.11.0`（`alloc` + `zeroize`）、`hkdf 0.13.0`、`sha2 0.11.0`、`hmac 0.13.0`、`subtle 2.6.1`、`zeroize 1.8`、`base64 0.23.1` | 无网络 / 文件 I/O、不读时钟、随机数经注入的 `Rng`；唯一例外是 pasetors 内部用 OS RNG 生成 PASETO nonce。不要求 wasm32 |
| `mg-intel` | `maxminddb 0.32.0`、`sha2 0.11.0` | 无网络 I/O；DNS 经 `DnsResolver` trait |
| `mg-edge`（WP-E1 添加） | `redis = { version = "1.7.1", default-features = false, features = ["tokio-comp", "connection-manager", "script"] }`、`hickory-resolver = "0.26.3"`（默认特性：`system-config` + `tokio`）、`reqwest = { version = "0.13.5", default-features = false, features = ["rustls"] }`、`tokio = { version = "1", features = ["rt", "time", "sync", "macros"] }`、`arc-swap = "1.9"`、`ed25519-compact = "2.6"`（与 pasetors 同一版本）、`getrandom = "0.4"`、`sha2`、`hmac`、`base64`、`prost`、`serde_json`；`pingora` 追加特性 `connection_filter` | 只有 mg-edge 依赖 Pingora；出站 HTTP 不读系统代理环境变量 |

版本全部在 crates.io 核对过（2026-09-27）。`reqwest` 的 `rustls` 特性带 aws-lc-rs，构建需要 cmake 与 C 编译器（BoringSSL 已经需要）。

### 1.3 Go 包

| 包 | 作用 | WP |
|---|---|---|
| `internal/policy` | 策略解析、类型检查、CEL → IR、参考求值器 | WP-G1 |
| `internal/cli` | 子命令契约（已落地） | WP-G2 维护 |
| `internal/mgctl` | 命令分发 | WP-G2 |
| `internal/sitecfg` | 站点 YAML v1 解析与校验 | WP-G2 |
| `internal/keys` | 所有者签名密钥（age）、站点密钥、假名化密钥、上游密钥头 | WP-G2 |
| `internal/bundle` | 配置包构建、签名、校验、发布 | WP-G2 |
| `internal/audit` | 本地追加哈希链审计日志 | WP-G2 |
| `internal/cfapi` | Cloudflare API 只读客户端 | WP-G3 |
| `internal/cfaudit` | `mgctl cf audit` 检查 | WP-G3 |
| `internal/intelsync` | `cf ips sync`、`crawler sync`、工件写出 | WP-G3 |

### 1.4 Edge 请求处理顺序

```
request_filter
  0  request_id (32 lower-hex), now_ms
  1  listener: peer / client cert / secret header          fail -> 403 or TLS close      (§9.2)
  2  header hygiene: strip families, parse trusted headers                                (§9.3)
  3  Host -> site (edge.toml hosts); listener allowed?      unknown host -> 404            (§9.4)
  4  /__mg/* ?  -> healthz | s/{file} | c | reserved 404    (never reaches the origin)      (§10)
  5  environment by host, route by method + normalized path                               (§9.4)
  6  RequestContext: upstream, net (+GeoLite2), http, edge_tls, tls                       (§9.5)
  7  identity: clearance cookie (mg-challenge), crawler claim (mg-intel, rDNS async)       (§9.6)
  8  state: ONE pipeline = MGET verdicts + EVALSHA mg_gcra (global limiters); local limiters (§9.7, §9.8)
  9  Decision Core: detectors -> ScorerV1 -> BotClass -> rules + limiter outcomes + matrix (§5.4, §5.5)
 10  monitor_only -> dry_run; enforce: ALLOW/TAG/LOG proxy | CHALLENGE 403 | RATE_LIMIT 429 | BLOCK 403 (§9.9)
upstream_request_filter: strip MG-* / x-mg-* / upstream families, add MG-* headers, XFF single value
response_filter: strip MG-* from origin responses
logging: DecisionEvent + access record -> EventSink; XADD summary; metrics                (§9.11, §13)
```

## 2. 工作包与文件所有权

### 2.1 阶段与依赖

```
stage 1 (parallel):  WP-R1  WP-R2  WP-R3  WP-G1  WP-G2  WP-G3  WP-W1
                        \      |      |      |      |      |      /
stage 2:                 └──────────── WP-E1 (edge/, Makefile, CI) ──────┘
stage 3 (parallel):          WP-L1 (lab/, scripts/lab-e2e.sh)   WP-J1 (edge/src/tls/)   WP-D1 (docs/)
```

- 阶段 1 的 WP 之间没有编译期依赖：每个 WP 只用本文与 §0.4 的已落地文件。WP-G2 构建配置包时用的是 `policy` 包现有的公共 API（`NewCompiler`、`Check`、`CheckedRule.Proto()`）；WP-G1 让 `Proto()` 填上 IR 后，WP-G2 的代码不需要改。
- 阶段 2 在阶段 1 全部合入后开始。阶段 3 在 WP-E1 合入后开始。
- 合入顺序无要求；每个 WP 合入时 `make check` 必须全绿。
- 唯一的跨 WP 测试耦合是策略 IR 一致性套件（WP-G1 产出夹具，WP-R1 的 Rust 测试读取）：夹具文件不存在时 Rust 测试打印 `SKIPPED` 并通过；两者都合入后必须全绿。出现分歧时先按 §5.3 判定哪一边偏离规范，由偏离的一方修复；后合入的 PR 负责在合入前让 `make check` 变绿。

### 2.2 文件所有权矩阵

一个路径只有一个所有者 WP；其他 WP 只读。"只读契约"文件的修改先改本文，再由表中所有者提交。

| 路径 | 所有者 | 说明 |
|---|---|---|
| `core/**` | WP-R1 | |
| `proto/rust/src/ir.rs`、`proto/rust/tests/policy_ir_conformance.rs`（新）、`proto/rust/tests/roundtrip.rs` | WP-R1 | |
| `proto/morphgate/v1/decision.proto` 及其生成文件 `control-plane/gen/morphgate/v1/decision.pb.go` | WP-R1 | 改动见 §3.4；改后运行 `make proto`，只提交 `decision.pb.go` 的变化 |
| `proto/morphgate/v1/{policy_ir,config,challenge,common}.proto` | 只读契约 | |
| `challenge/**` | WP-R2 | |
| `testdata/phase1/kat.json` | 只读契约 | WP-R2、WP-W1、WP-E1 读取 |
| `intel/**` | WP-R3 | 含 `intel/testdata/`（测试用 mmdb 与生成器） |
| `control-plane/internal/policy/**`、`control-plane/testdata/policies/**`、`testdata/policy-ir/**` | WP-G1 | |
| `control-plane/internal/{mgctl,cli,sitecfg,keys,bundle,audit}/**`、`control-plane/go.mod`、`control-plane/go.sum`、`go.work.sum`、`control-plane/testdata/sites/**`、`control-plane/README.md` | WP-G2 | `cli` 只可追加字段，不改已有字段语义 |
| `control-plane/internal/{cfapi,cfaudit,intelsync}/**`、`control-plane/testdata/cloudflare/**`、`control-plane/testdata/intel/**`、`deploy/intel/**` | WP-G3 | 不需要新的 Go 依赖（只用标准库） |
| `sdk/web/**` | WP-W1 | |
| `edge/**`、`deploy/systemd/**`、`scripts/edge-smoke.sh`、根 `Cargo.toml`、`Cargo.lock`、`Makefile`、`.github/workflows/ci.yml`、`deploy/compose/**` | WP-E1 | 阶段 2 |
| `lab/**`、`scripts/lab-e2e.sh`（新） | WP-L1 | 阶段 3；可在 `Makefile` 与 `ci.yml` 中追加 `lab-e2e` 目标与作业（此时 WP-E1 已合入） |
| `edge/**`（阶段 3，只做预研所需的增量改动：新增 `edge/src/tls/`、`edge/tests/ja4_spike.rs`，在监听器配置与 TLS 设置处接入）、`docs/adr/0002-edge-pingora-boringssl.md` | WP-J1 | 阶段 3；此时 WP-E1 已合入，WP-L1 与 WP-D1 不改 `edge/` |
| `docs/**`（除 `docs/impl/` 与 ADR-0002）、`README.md`、`CLAUDE.md` | WP-D1 | 阶段 3 |
| `docs/impl/phase1-spec.md` | 集成者 | 契约变更先改这里 |

### 2.3 共享文件规则

- **`Cargo.lock`**：阶段 1 的 Rust WP 只能使用已在根 `[workspace.dependencies]` 中声明且已被本提交锁定的依赖；确需新增依赖时，只追加根 `Cargo.toml` 中本 WP 的那一段，并在 PR 中说明；两个 PR 的 `Cargo.lock` 冲突时，取任一边后运行 `cargo check --workspace` 重新生成，不手改。
- **`go.mod` / `go.sum`**：只有 WP-G2 改动（它需要 `filippo.io/age` 与 `golang.org/x/term`）。WP-G1、WP-G3 只用已有依赖与标准库。
- **生成代码**：proto 只在所有者 WP 中改，改后 `make proto`；CI 的漂移检查保证 Go 生成代码与 proto 一致。
- **`testdata/phase1/kat.json`**：只读。实现与向量不一致时，先确认本文公式，不改向量。
- **README**：每个 WP 更新自己目录下的 README（`control-plane/README.md`、`sdk/web/README.md`、`lab/README.md`、`edge` 没有 README）；根 README 与 CLAUDE.md 由 WP-D1 统一改。

### 2.4 通用完成定义

每个 WP 合入前必须满足：

1. `make check` 全绿（本地没有 wasm 目标时 `wasm-check` 跳过，CI 必跑）。
2. 新代码有单元测试；本文列出的每个"测试"条目都有对应测试，测试名或注释引用本文章节号。
3. 所有解析器（头、Cookie、C、提交体、配置包、工件、IR）有"确定性随机输入不 panic"测试：固定种子的 xorshift 生成 ≥ 10,000 个输入，断言返回错误而不是 panic。
4. 不出现 `todo!()`、`unimplemented!()`、`panic!` 用于可恢复错误；Rust 公共类型实现 `Debug`，但不打印密钥、nonce、凭证原文。
5. 不在任何出站请求中放入所有者的个人信息；出站 User-Agent 为 `mgctl/<version>` 或 `mg-edge/<version>`（开发工具抓取资料时用 `morphgate-dev-tooling`）。
6. 该 WP 改动过的 README / 注释与行为一致；不改他人拥有的文件。

## 3. 数据模型改动

### 3.1 `policy_ir.proto`（已落地，最终定义）

```proto
message PolicyExpr {
  uint32 ir_version = 1;       // 1
  Expr root = 2;               // must evaluate to bool
  repeated string fields = 3;  // sorted unique field paths the expression reads or has()-tests (informational)
  uint64 cost_max = 4;         // cel-go worst-case cost estimate at compile time (informational)
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

`CompiledRule.expr_ir` = `PolicyExpr` 的序列化字节（Go：`proto.MarshalOptions{Deterministic: true}`），`CompiledRule.ir_version = 1`。IR 不含表达式 id、源码位置或类型：同一个已检查表达式总得到同一串字节。

### 3.2 `config.proto` 的 Phase 1 schema（已落地）

在 Phase 0 消息上只做了追加（字段号不复用、不改语义）。新增字段与消息：

| 消息 | 新增 | 说明 |
|---|---|---|
| `UpstreamProfile` | — | Phase 1 只用 `kind` 与 `expected_mask`；字段 2–7 留给后续 profile，构建器必须留空 |
| `Route` | `paths = 9`（repeated glob）、`require_clearance = 10` | `path_glob` 弃用：构建器只写 `paths`，Edge 把非空的 `path_glob` 当作 `paths` 的一项 |
| `CompiledRule` | — | `params` 在 Phase 1 只允许 `type`、`label`、`limiter`、`retry_after_s` |
| `RateLimit` | `route_ids = 10`、`scope = 11`、`retry_after_s = 12`、`challenge_type = 13`、`signal_weight = 14` | `route_id` 弃用 |
| `Environment` | `hosts = 6` | |
| `ArtifactRef` | `size = 5` | |
| `SiteBundle` | `schema_version = 11`、`hosts = 12`、`allowed_listeners = 13`、`challenge = 14`、`clearance = 15`、`scoring = 16`、`crawler_policy = 17`、`events = 18`、`lists = 19`、`cloudflare = 20`、`origin_headers = 21`、`share_ip_verdicts = 22`、`source_digest = 23` | |
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
| `context::Crawler` | 加 `verification: Option<CrawlerVerification>`（wire：`none`/`pending`/`verified`/`failed`/`unverifiable`）、`method: Option<CrawlerMethod>`（`ip_range`/`rdns`） |
| `context::BindResult` | `SoftMismatch` 已落地（§0.4） |
| `decision::Decision` | 加 `tags: Vec<String>`（JSON 省略空列表）；`Decision::validate` 增加：`tags` 非空时 `action ∈ {Tag}`，每个标签匹配 `[a-z0-9_.-]{1,32}`，至多 8 个 |
| `decision::DecisionEvent` | 加 `hits: Vec<RuleHit>` |
| `pipeline` | trait 签名按 §5.6 改（`Detector::detect`、`Scorer::score`、`PolicyEvaluator::evaluate` 都接收 `RequestExtras`） |

## 4. 策略字段模式与 MISSING 语义

### 4.1 字段表

策略可读的字段是固定的模式（Go `internal/policy/context.go` 的 `Input` 与 Rust `mg_core::policy::Activation` 必须完全一致）。表中"Edge 来源"是 WP-E1 构建 Activation 的规范；"MISSING 条件"是 WP-E1 构建 `MissingSet` 的规范（§4.3）。

| 路径 | 类型 | Edge 来源（ABSENT 时的零值） | MISSING 条件（Phase 1） |
|---|---|---|---|
| `req.method` | string | 请求方法（大写） | 从不 |
| `req.host` | string | Host（小写、去端口、去末尾点） | 从不 |
| `req.path` | string | 原始路径（不含查询串，不解码） | 从不 |
| `req.query` | string | 原始查询串（不含 `?`） | 从不 |
| `req.headers` | map(string, string) | 头部清洗（§9.3）后的客户端头；名称小写；重复头以 `", "` 连接；排除 `cookie`、`authorization`、`proxy-authorization`；至多 128 项，值超过 8 KiB 的项丢弃 | 从不 |
| `req.channel` | string | 路由的 channel：`web`/`api`/`mobile` | 从不 |
| `net.ip` | string | 客户端 IP（IPv6 用 RFC 5952 文本） | 客户端 IP 未知（认证通过但缺 `CF-Connecting-IP`、值非法、或外部 zone 的 `CF-Worker`） |
| `net.asn` | int | GeoLite2 ASN；库中查不到为 0 | 没有 `geoip-asn` 工件，或 `net.ip` MISSING |
| `net.country` | string | GeoLite2 国家（ISO alpha-2）；查不到为 `""` | 没有 `geoip-country` 工件，或 `net.ip` MISSING |
| `net.conn_type` | string | ASN ∈ `datacenter-asns` → `datacenter`，否则 `unknown` | 没有 `datacenter-asns` 工件，或 `net.asn` MISSING |
| `net.tor` | bool | IP ∈ `tor-exits`，或（`cloudflare` 且信任 location 头且 `cf-ipcountry = T1`） | 两个来源都没有 |
| `upstream.profile` / `authenticated` / `auth_method` | string / bool / string | 监听器 | 从不 |
| `tls.ja4.value` / `source` / `authenticated` | string / string / bool | —（Phase 1 无） | 总是（`cloudflare` 因为 profile；`direct_tls` 因为 D-07） |
| `tls.version` | string | `direct_tls` 协商的版本（`TLSv1.2` / `TLSv1.3`） | `cloudflare` |
| `http.version` | string | `direct_tls`：`HTTP/1.1` / `HTTP/2`；`cloudflare`：`x-mg-cf-http-version` | `cloudflare` 且该头缺失或非法 |
| `http.header_order` | list(string) | `direct_tls` 且 HTTP/1.x：按到达顺序的头名（保留大小写，至多 64） | `cloudflare`；`direct_tls` 的 HTTP/2 |
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

Go `Input` 需要新增 `identity.crawler.claimed`，并给所有字段加上与 `cel` 标签同名的 `json` 标签（WP-G1）。

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
- WP-E1 按 §4.1 的"MISSING 条件"列逐请求构建；Phase 1 常量部分（按 profile）可以预先计算。

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
| `[x, y]` | List | `list` |
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

cel-go 环境保持 `CrossTypeNumericComparisons(false)`（默认值），因此 `1 < 1.5`、`1 == 1.0` 在类型检查时就被拒绝，IR 中不存在跨类型数值比较。

### 5.2 拒绝的构造

`mgctl policy check` 与 `compile` 对下列构造报错（错误级，规则不进配置包），消息格式 `unsupported in policy IR: <what>`：

算术（`+ - * / %`、非字面量的一元负号）、字符串拼接、`matches`、宏与推导式（`all`、`exists`、`exists_one`、`map`、`filter`）、类型转换与类型函数（`int`、`uint`、`double`、`string`、`bytes`、`dyn`、`type`）、`timestamp` / `duration`、`uint` / `bytes` / `null` 字面量、map 字面量与消息字面量、列表下标 `l[i]`、bool 的大小比较、列表或 map 的相等比较、把结构体字段整体当值（如 `tls.ja4 == x`）、对 map 键用 `has()`（提示改用 `"k" in m`）、可选语法。

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
| `in_list x l` | `l` 为 List；存在与 `x` **同类型且相等**的元素 → `true`；类型不同的元素视为不相等，不报错 |
| `in_map k m` | `m` 为 Map、`k` 为 String → 键存在 |
| `index_map m k` | `m` 为 Map、`k` 为 String；键不存在 → `Error(no_such_key)` |
| `size x` | String → Unicode 标量值个数；List / Map → 元素个数 |
| `string_call` | 两侧 String；`startsWith` / `endsWith` / `contains` 按 Unicode 标量序列比较 |
| `ip_in ip l` | `ip` 为 String、`l` 为 String 列表。`ip` 不是合法 IP（不带 zone 的 IPv4 点分或 IPv6）→ `false`。**逐项校验全部条目**：条目是 IP 或 CIDR；IPv4 映射的 IPv6 CIDR（`::ffff:a.b.c.d/n`，`n ≥ 96`）规范化为 IPv4 `/n-96`；带 zone 或无法解析 → `Error(invalid_argument)`（即使前面的条目已匹配）。IPv4 映射的 IPv6 地址先还原为 IPv4 再比较 |
| `named_list name` | 配置包中该名单的条目（String 列表）；不存在 → `Error(unknown_list)`（配置包校验后不应发生） |
| `glob s p` | `s` 为 String；`*` 匹配不含 `/` 的任意串，连续 ≥ 2 个 `*` 视为 `**`，匹配含 `/` 的任意串，`?` 匹配一个非 `/` 字符，其他字符原样匹配；按 Unicode 标量值、区分大小写（与 `funcs.go` 的 `glob` 相同） |

**规则结果**：根为 `Bool(true)` → 命中；`Bool(false)` → 不命中；`Unknown(paths)` → 不命中，记 `missing_input`（排序后的路径）；`Error(kind)` → 不命中，记 `eval_error`；根为非 bool → `Error(no_such_overload)`。

**错误种类**（wire 字符串）：`no_such_overload`、`no_such_key`、`invalid_argument`、`unknown_list`、`step_limit`。

**资源上限**（Rust 在加载时与求值时执行）：IR 节点数 ≤ 4096、嵌套深度 ≤ 64、字符串字面量 ≤ 4096 字节、列表字面量 ≤ 1000 项；求值步数 ≤ 100,000（每个节点 1 步；`in_list` / `ip_in` 每检查一个元素 1 步；字符串运算每 64 字节 1 步；`glob` 为 `len(s)·len(p)/16 + 1` 步），超出 → `Error(step_limit)`。

Go 参考语义：先把表达式中所有 `has(p)` 按 MissingSet 替换为布尔字面量，再以 MissingSet 中每个路径作为未知属性模式（`cel.AttributePattern`，按路径段 `QualString`）运行 cel-go 部分求值（`cel.EvalOptions(cel.OptPartialEval)`）；结果 `types.Bool` / `*types.Unknown` / `*types.Err` 分别对应 true|false / unknown / error。cel-go v0.30 的严格函数先返回 ERROR、再合并 UNKNOWN，`&&` / `||` 中 UNKNOWN 优先于 ERROR，与上表一致。

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
- 全局 monitor（`SiteBundle.monitor_only`）不在引擎里处理：Edge 在引擎之后把 `dry_run = true` 并按 ALLOW 转发（§9.9）。

### 5.5 默认处置矩阵（WP-R1）

03 §5.1 的规范化实现。`band = risk.score.band()`；`critical = route.sensitivity == Critical`；Phase 1 的 `interactive` 按 D-08 执行为 `pow`。

```
matrix():
  match risk.bot_class:
    VerifiedCrawler -> crawler_policy.action(purpose) == block ? BLOCK "matrix.crawler.block"
                                                              : ALLOW "matrix.crawler.allow"
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
```

`crawler_policy.action(purpose)`：`purposes[purpose]`，缺省 `default_action`，再缺省 `allow`。矩阵产生的 TAG 不带标签（`MG-Tags` 只来自规则）。

### 5.6 Rust API（WP-R1）

`mg-core` 新增模块与公开签名（名字可以加私有辅助项，公开项按此实现）：

```rust
// core/src/extras.rs — per-request inputs that are not part of the logged RequestContext
pub struct RouteInfo {
    pub id: String, pub name: String, pub env: String,
    pub channel: Channel, pub sensitivity: RouteSensitivity,
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

// core/src/gcra.rs — pure GCRA; integer microseconds; must equal the Lua script of §9.7 bit for bit
pub struct GcraParams { pub interval_us: u64, pub burst: u32 }
impl GcraParams {
    /// None if rate == 0, period_s == 0 or burst == 0. interval_us = period_s * 1_000_000 / rate (floor).
    pub fn new(rate: u32, period_s: u32, burst: u32) -> Option<Self>;
    pub fn dvt_us(&self) -> u64 { self.interval_us * u64::from(self.burst) }
}
pub struct GcraOutcome { pub allowed: bool, pub retry_after_us: u64, pub tat_minus_now_us: u64,
                         pub new_tat_us: Option<u64> /* Some iff allowed; the caller stores it to consume */ }
impl GcraOutcome { pub fn utilization(&self, p: &GcraParams) -> f32; } // allowed: min(1, tat_minus_now/dvt); denied: 1.0
pub fn gcra_check(p: &GcraParams, stored_tat_us: Option<u64>, now_us: u64, cost: u32) -> GcraOutcome;

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
pub struct Program { /* root, fields, node count */ }
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
                   UnknownList(String), Limits(&'static str), Malformed(&'static str) }
/// Decodes and validates a serialized PolicyExpr (§5.3 limits, schema paths, list names).
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
| `identity.clearance` | IDENTITY | 两者 | 凭证 `none` / `expired` → ABSENT；`valid` → `invisible` −0.5、`pow` −0.3（置信度 1.0）；`invalid` → +0.5 / 0.6；`binding_mismatch` → +0.3 / 0.8 | 见左 | 1.0 |
| `identity.bind_ipp_soft` | IDENTITY | 两者 | 只在凭证有效时输出：`bind.ipp == soft_mismatch` → +0.4 / 0.6，否则 PRESENT 0；无有效凭证时不输出 | 见左 | 1.0 |
| `identity.crawler_failed` | IDENTITY | 两者 | 只在 UA 声称已知爬虫时输出：验证 `failed` → +1.0 / 1.0，其余 PRESENT 0 | 见左 | 2.0 |
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

**Rust**（`proto/rust/tests/policy_ir_conformance.rs`）：读取两个文件，用 `ir::decode_program` 解码，按上下文 JSON 构建 `Activation` 与 `MissingSet`，求值并断言与 `expect` 一致；另断言 `unknown` 用例返回的路径集合非空且都在 MissingSet 之下。

**覆盖要求**（≥ 150 个用例）：`docs/06` §2 的全部示例与 `control-plane/testdata/policies/valid/*.yaml` 的全部表达式（每条至少一个命中与一个不命中上下文）；每种 IR 节点各自的 true / false / unknown / error（适用时）；`&&` / `||` 的吸收表（`false && unknown`、`true && unknown`、`unknown && error`、`error && false`、`true || unknown`、`false || unknown`、`unknown || error`）；`!unknown`；条件为 unknown 的三元式；`has()` 对 PRESENT / ABSENT / MISSING 字段及其父路径；map 下标缺键；`"k" in rate`；多字节字符串的 `size`、`startsWith`、`contains`；`ip_in` 的 IPv4、IPv6、IPv4 映射地址、映射 CIDR、非法地址（false）、非法条目（error，含"前面已匹配"）；`glob` 的 `*`、`**`、`?`、连续星号、Unicode；命名列表；§5.2 每类拒绝构造至少一个 `compile_error` 用例。

## 6. 挑战与凭证密码学（`mg-challenge`，WP-R2）

所有字节级公式在 `testdata/phase1/kat.json` 中有已知答案向量，WP-R2 的测试必须逐条通过。

### 6.1 密钥与 epoch

| 项 | 规范 |
|---|---|
| 根密钥 | `K_seal_root`：32 字节，来自站点密钥文件 `seal.root.json`（§12.7），以 systemd credential 交付 |
| epoch | `epoch_no = floor(now_ms / 86_400_000)`（UTC 日） |
| kid | `"e" + 十进制 epoch_no`，例如 `e20724` |
| 派生 | `k_epoch = HKDF-SHA256(salt = 空, ikm = K_seal_root, info = "mg-seal-v1" ‖ 0x00 ‖ site_id ‖ 0x00 ‖ u64be(epoch_no), L = 32)`；`k_bind_epoch` 同法、标签 `"mg-bind-v1"`（Phase 2 Turnstile `cData` 用，Phase 1 只提供函数） |
| 接受的 epoch | `epoch(now − 5 s) − 1 ≤ e ≤ epoch(now + 5 s)`：当前与上一个 epoch，外加日界附近 5 s 的时钟偏差 |
| 缓存 | 派生结果按 `(site, epoch)` 缓存，至多 4 项；`Debug` 不打印密钥；密钥类型实现 `Zeroize` |

### 6.2 密封 C

```
C          = base64url_nopad( prost(SealedChallenge { v: 1, kid, xnonce, ct }) )      len(C) <= 1024
xnonce     = 24 random bytes (Rng)
ct         = XChaCha20-Poly1305.seal(k_epoch[kid], xnonce, prost(SealedChallengeClaims), aad)
aad        = u16be(len(host)) ‖ host ‖ u16be(len(type)) ‖ type ‖ u16be(len(kid)) ‖ kid   (UTF-8)
host       = request Host, lower-case, without port and trailing dot
type       = ChallengeType wire name: "invisible" | "pow" | "interactive"
```

Phase 1 签发的 claims：`v = 1`；`kid` 与信封相同；`nonce` 16 个随机字节；`site`；`route_class` = 路由名；`type` 为 `invisible` 或 `pow`；`providers` 为空；`risk_band` = 挑战前风险段；`attempt_no = 0`；`iat_ms` = now；`exp_ms = iat_ms + challenge.ttl_s · 1000`（≤ 120 s）；`ui_seed = 0`；`pow = {alg: "sha256-hashcash-v1", difficulty: pow_bits[risk_band]}`；`ret` = `ret_hash(ret)`；`bind`：`uah` 必有，`ipp` / `ipa` 在客户端 IP / ASN 已知时有，`ctp` 在 `cloudflare`、`clearance.ctp_shadow` 且四个输入齐全时有，`jkt` / `tfp` 为空。

**打开**（`Sealer::open`）按以下顺序，任一步失败即返回对应 `OpenError`（括号内为内部 reason code）：长度 ≤ 1024（`ic.c_invalid`）→ base64url 解码（`ic.c_invalid`）→ prost 解码信封，`v == 1`（`ic.c_invalid`）→ 解析 kid、epoch 在接受范围内（`ic.c_kid`）→ 派生密钥、AEAD 打开（`aad` 用请求 Host 与提交中声明的 type，`ic.c_invalid`）→ prost 解码 claims（`ic.c_invalid`）→ `claims.kid == 信封 kid`、`claims.site == 站点`、`claims.challenge_type == 声明的 type`（`ic.c_invalid`）→ `SealedChallengeClaims::check(now_ms)`（`Expired` → `ic.c_expired`，其余 → `ic.c_invalid`）。

### 6.3 PoW

| 项 | 规范 |
|---|---|
| 算法名 | `sha256-hashcash-v1` |
| 输入 | `prefix = "mg-pow-v1" ‖ 0x00 ‖ SHA-256(C 的 ASCII 字节)`（42 字节）；`digest = SHA-256(prefix ‖ u64be(counter))` |
| 判定 | `leading_zero_bits(digest) ≥ difficulty` |
| 取值 | `0 ≤ difficulty ≤ 32`；`counter < 2^53`（JS 安全整数）；Phase 1 提交恰好一个 counter |
| 缺省难度 | `low` 14、`medium` 16、`high` 18、`very_high` 20（配置包 `challenge.pow_bits`） |

### 6.4 绑定哈希与返回路径

| 项 | 规范 |
|---|---|
| 绑定哈希 | `bind_hash(kind, value) = SHA-256("mg-bind-v1" ‖ 0x00 ‖ kind ‖ 0x00 ‖ value)[0..16]`；凭证 JSON 中为 base64url（无填充） |
| `uah` | `value = family + "/" + major`（`mg_core::ua::parse`，例如 `chrome/131`）；硬 |
| `ipp` | `value = Net::prefix_of(ip)`（`203.0.113.0/24`、`2001:db8:abcd::/48`）；软 |
| `ipa` | `value = ASN 十进制`；决定 `ipp` 的软 / 硬 |
| `ctp` | `value = version + "|" + cipher + "|" + ciphers_sha1 + "|" + min(hello_len / 64, 31)`；只记录 |
| `ret` 校验 | 以 `/` 开头、不以 `//` 或 `/\` 开头、不含 `\`、控制字符（< 0x20 或 0x7f）与 `#`、≤ 512 字节、不在 `/__mg` 命名空间（按 `routes::classify` 判断） |
| `ret_hash` | `SHA-256("mg-ret-v1" ‖ 0x00 ‖ ret)[0..16]` |

**绑定比较**（C 提交与凭证校验共用）：

| 项 | 结果 |
|---|---|
| `uah` | 相等 → `match`；否则 `mismatch`（C：失败 `ic.bind_uah`；凭证：`binding_mismatch`） |
| `ipp` | 未绑定 → 不检查；当前前缀相等 → `match`；不等（含当前 IP 未知）时，若 `ipa` 已绑定且当前 ASN 已知且相等 → `soft_mismatch`，否则 `mismatch`（C：失败 `ic.bind_ipp`；凭证：`binding_mismatch`） |
| `ctp` | 两边都有 → `match` / `mismatch`，只记录，不影响结果 |

### 6.5 清关凭证（PASETO v4.local）

```json
{"v":1,"kid":"blog-t-20260927","sid":"blog","env":"production",
 "sub":"<base64url 16 random bytes>","lvl":"invisible","iat":1790000000,"exp":1790001800,
 "bind":{"uah":"iXRgjCj6tPt2cFcPqeHr_A","ipp":"JxTqJG6DMjc-DDCAwG3WYw","ipa":"3jB742LLBC_uwzOiZPFFLg"},
 "rb":"medium","jti":"<base64url 16 random bytes>"}
```

| 项 | 规范 |
|---|---|
| 载荷 | 上面的 JSON（`serde_json`），`iat` / `exp` 为 Unix 秒；`bind.uah` 必有，其余可缺省 |
| footer | `{"kid":"<kid>"}`（明文，用于选密钥） |
| implicit assertion | `"mg-clr-v1" ‖ 0x00 ‖ site_id` |
| 密钥 | 站点 `token.keys.json`（§12.7）中 kid ∈ 配置包 `token_key_ids` 的密钥；`token_key_ids[0]` 签发，全部可验证 |
| 有效期 | `invisible` 1800 s、`pow` 1800 s（配置包 `clearance`）；`exp − iat ≤ 86400` |
| 校验 | 长度 ≤ 1024 → 解析 footer（≤ 128 字节 JSON）→ 按 kid 选密钥 → `LocalToken::decrypt`（带 implicit assertion）→ 解析 claims → `v == 1`、`kid == footer.kid`、`sid == 站点`、`env == 请求所在环境` → `iat ≤ now + 5`、`exp > now`（否则 `Expired`）→ `lvl` 可解析为 `TokenLevel` |
| `sub` 复用 | 签发时，请求若带有本站可解密的凭证且 `iat ≥ now − clearance.session_max_s`（缺省 86400，允许已过期），沿用其 `sub`；否则新生成 |
| 状态映射 | 无 Cookie → `none`；解密或解析失败、站点 / 环境不符 → `invalid`；过期 → `expired`；绑定硬失败 → `binding_mismatch`；其余 → `valid`（`TokenStatus`） |

### 6.6 Cookie

- 签发：`Set-Cookie: __Host-mg_clr=<token>; Max-Age=<exp − now>; Path=/; Secure; HttpOnly; SameSite=Lax`。只出现在 `/__mg/c` 的成功响应上，从不附加到源站响应（02 §8）。
- 解析：遍历所有 `Cookie` 头（合计只看前 16 KiB），按 `;` 分割、去空白，名称精确等于 `__Host-mg_clr` 的取值；至多尝试前 2 个候选，任一 `valid` 即用它，否则取第一个候选的状态。

### 6.7 公共 API

```rust
// challenge/src/rng.rs
pub trait Rng: Send + Sync { fn fill(&self, dst: &mut [u8]); }

// challenge/src/keys.rs
pub struct SealRoot(/* [u8; 32], zeroize */);
impl SealRoot {
    pub fn from_bytes(key: [u8; 32]) -> Self;
    /// Parses seal.root.json (§12.7); checks kind, v and that `site` matches.
    pub fn from_key_file(json: &[u8], site_id: &str) -> Result<Self, KeyError>;
}
pub fn epoch_no(now_ms: i64) -> u64;
pub fn epoch_kid(epoch: u64) -> String;
pub fn parse_epoch_kid(kid: &str) -> Option<u64>;
pub fn accepted_epochs(now_ms: i64) -> std::ops::RangeInclusive<u64>;
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
pub fn random_nonce(rng: &dyn Rng) -> [u8; 16];
pub struct Sealer { /* site, root, epoch key cache */ }
impl Sealer {
    pub fn new(site_id: &str, root: SealRoot) -> Self;
    /// Seals `claims` (whose kid must be epoch_kid(epoch_no(claims.iat_ms))) for `host`.
    pub fn seal(&self, claims: &SealedChallengeClaims, host: &str, rng: &dyn Rng) -> Result<String, SealError>;
    pub fn open(&self, c: &str, host: &str, claimed: ChallengeType, now_ms: i64) -> Result<SealedChallengeClaims, OpenError>;
}
pub enum OpenError { TooLong, Encoding, Envelope, Kid, Aead, Claims, Mismatch, Expired, Invalid(ClaimsError) }
impl OpenError { pub fn reason_code(&self) -> &'static str; }  // §6.2

// challenge/src/pow.rs
pub const POW_ALG: &str = "sha256-hashcash-v1";
pub const MAX_POW_BITS: u32 = 32;
pub fn pow_prefix(c: &str) -> [u8; 42];
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32;
pub fn pow_verify(c: &str, difficulty: u32, counter: u64) -> bool;
#[doc(hidden)] // reference solver for tests; never called on a request path
pub fn pow_solve(c: &str, difficulty: u32, max_iterations: u64) -> Option<u64>;

// challenge/src/bind.rs
pub fn bind_hash(kind: &str, value: &str) -> [u8; 16];
pub fn uah(ua_family: &str, ua_major: u32) -> [u8; 16];
pub fn ipp(prefix: &str) -> [u8; 16];
pub fn ipa(asn: u32) -> [u8; 16];
pub fn ctp(version: &str, cipher: &str, ciphers_sha1: &str, hello_len: u32) -> [u8; 16];
pub fn ret_hash(ret: &str) -> [u8; 16];
pub fn validate_ret(ret: &str) -> Result<(), RetError>;
pub struct BindInputs { pub uah: [u8; 16], pub ipp: Option<[u8; 16]>, pub ipa: Option<[u8; 16]>, pub ctp: Option<[u8; 16]> }
pub struct BindCheck { pub uah: BindResult, pub ipp: Option<BindResult>, pub ctp: Option<BindResult> } // mg_core::BindResult
pub fn check_challenge_bind(sealed: &ChallengeBind, current: &BindInputs) -> BindCheck;

// challenge/src/clearance.rs
pub const COOKIE_NAME: &str = "__Host-mg_clr";
pub const MAX_TOKEN_LEN: usize = 1024;
#[derive(Serialize, Deserialize)]
pub struct ClearanceClaims { pub v: u32, pub kid: String, pub sid: String, pub env: String, pub sub: String,
    pub lvl: TokenLevel, pub iat: i64, pub exp: i64, pub bind: ClearanceBind, pub rb: RiskBand, pub jti: String }
#[derive(Serialize, Deserialize)]
pub struct ClearanceBind { pub uah: String, pub ipp: Option<String>, pub ipa: Option<String>, pub ctp: Option<String> }
pub struct MintParams<'a> { pub env: &'a str, pub sub: Option<&'a str>, pub lvl: TokenLevel, pub now_s: i64,
    pub ttl_s: u32, pub bind: ClearanceBind, pub rb: RiskBand }
pub fn mint(keys: &TokenKeySet, site_id: &str, p: &MintParams<'_>, rng: &dyn Rng) -> Result<(String, ClearanceClaims), TokenError>;
pub fn verify(keys: &TokenKeySet, site_id: &str, env: &str, token: &str, now_s: i64) -> Result<ClearanceClaims, TokenError>;
pub enum TokenError { TooLong, Footer, UnknownKid, Decrypt, Claims, Site, Env, NotYetValid, Expired }
pub fn check_clearance_bind(claims: &ClearanceClaims, current: &BindInputs) -> BindCheck;
pub fn set_cookie_value(token: &str, max_age_s: u32) -> String;           // the Set-Cookie header value
pub fn clearance_cookies<'a>(cookie_headers: &[&'a str]) -> Vec<&'a str>; // at most 2 candidates
```

### 6.8 测试

KAT（`kat.json` 的 `epoch_keys`、`aad`、`bind`、`ret`、`pow`）；`seal` → `open` 往返；改动 C 的任一字节、换 host、换声明的 type、换站点、用 `e−2` 或 `e+2` 的 kid、过期 → 各自的 `OpenError`；两个 `Sealer`（同一根密钥，模拟两台 Edge）互相打开；`mint` → `verify` 往返；换站点、换环境、过期、篡改任一字节、未知 kid 各自失败；用 verify-only（非首位）kid 签发的凭证仍能通过验证；绑定比较真值表（§6.4）；Cookie 解析（多个 Cookie 头、重复名、超长）；`validate_ret` 正反例；解析器随机输入不 panic（§2.4）。

## 7. 情报数据（`mg-intel`，WP-R3）

### 7.1 IP 集合

`IpSet`：由 IP / CIDR 文本构建；IPv4-mapped IPv6 条目与查询都还原为 IPv4；内部为排序后合并的区间（IPv4 `u32`、IPv6 `u128`），`contains` 为 O(log n)；至多 1,000,000 条；非法条目报错并带行号。

### 7.2 GeoLite2

- 输入是 `.mmdb` 字节（Edge 从工件缓存读入内存）。`geoip-asn` 的 `database_type` 必须含 `ASN`；`geoip-country` 必须含 `Country` 或 `City`，否则拒绝加载。
- 读取的记录：ASN 库 `autonomous_system_number`、`autonomous_system_organization`；国家库 `country.iso_code`，缺失时取 `registered_country.iso_code`。
- 结果区分三种状态：`Lookup::Found(v)`、`Lookup::NotFound`（库里没有该 IP，映射为 ABSENT 零值）、`Lookup::Unavailable`（没有该库，映射为 MISSING）。

### 7.3 爬虫注册表与验证

注册表工件格式见 §12.3。验证结果状态机：

| 情况 | 结果 |
|---|---|
| UA 不匹配任何运营方的 `ua_tokens`（不区分大小写的子串） | `NotClaimed` |
| 客户端 IP 未知 | `Unverifiable { reason: "no_client_ip" }`（05 §3.3：不判冒充） |
| IP ∈ 运营方 `cidrs` | `Verified { method: IpRange }` |
| 模式为 `ip_ranges` 且 IP ∉ `cidrs` | `Failed { method: IpRange }`（同步，D-18） |
| 模式为 `rdns` 或 `ip_ranges_or_rdns`，rDNS 缓存命中 | 缓存中的 `Verified` / `Failed { method: Rdns }` / `Unverifiable { reason: "dns_error" }` |
| 同上，缓存未命中 | `Pending`，并返回一个 `RdnsJob`（同一 `(ip, operator)` 同时只有一个在途） |

**rDNS 算法**（`resolve_rdns`）：PTR 查询 `ip`，取至多 5 个名字；对每个以运营方某个 `rdns_suffixes` 结尾的名字（不区分大小写、去掉末尾点；后缀以 `.` 开头时按标签边界匹配，不以 `.` 开头时要求整名相等）做 A / AAAA 正向查询；任一正向结果包含 `ip` → `Pass`；PTR 无记录或无名字匹配 → `Fail`；任何超时或 SERVFAIL → `DnsError`。每次查询超时由调用方（Edge，缺省 2 s）控制。

**缓存**：键 `(ip, operator_id)`；`Pass` 24 h、`Fail` 1 h、`DnsError` 5 min；容量缺省 100,000 项，满时淘汰最早过期的项；所有时间由调用方传入 `now_ms`。

**指标映射**（WP-E1 记录）：`mg_crawler_verify_total{method="ip_range"|"rdns", result="pass"|"fail"|"unverifiable"}`，`Pending` 不计数，异步结果落定时计数。

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
    pub fn from_artifact(json: &[u8]) -> Result<Self, IntelError>;   // §12.3
    pub fn match_ua(&self, ua: &str) -> Option<&Operator>;           // first operator in file order
}
pub enum VerifyMethod { IpRange, Rdns }
pub enum CrawlerStatus {
    NotClaimed,
    Verified { operator: String, purpose: String, method: VerifyMethod },
    Failed { operator: String, purpose: String, method: VerifyMethod },
    Pending { operator: String, purpose: String },
    Unverifiable { operator: String, purpose: String, reason: &'static str },
}
pub struct RdnsJob { pub ip: IpAddr, pub operator_id: String, pub suffixes: Vec<String> }
pub enum RdnsOutcome { Pass, Fail, DnsError }
pub struct CacheConfig { pub capacity: usize, pub pass_ttl_ms: i64, pub fail_ttl_ms: i64, pub error_ttl_ms: i64 }
pub struct CrawlerVerifier { /* registry + cache + in-flight set; Sync */ }
impl CrawlerVerifier {
    pub fn new(registry: std::sync::Arc<CrawlerRegistry>, cache: CacheConfig) -> Self;
    pub fn check(&self, ua: &str, ip: Option<IpAddr>, now_ms: i64) -> (CrawlerStatus, Option<RdnsJob>);
    pub fn complete(&self, job: &RdnsJob, outcome: RdnsOutcome, now_ms: i64);
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
- 测试：`IpSet` 边界（/0、/32、/128、映射地址、合并）；GeoDb 的 Found / NotFound / Unavailable；错误 `database_type` 被拒；注册表解析正反例；状态机每一行；rDNS 算法（后缀标签边界、正向不含该 IP、多个 PTR、超时）；缓存 TTL 与淘汰；在途去重；`StaticResolver`；工件哈希校验；解析器随机输入不 panic。

## 8. 配置

### 8.1 `edge.toml` v1（WP-E1）

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

[[sites]]                                  # >= 1
id = "blog"                                # [a-z0-9][a-z0-9_-]{0,63}
hosts = ["example.com", "www.example.com"] # lower-case, no port; unique across sites; must equal SiteBundle.hosts
listeners = ["cf-tunnel"]                  # listener names that route to this site
origin = "127.0.0.1:3000"                  # plain HTTP origin (Phase 0 rule: not a listener / metrics address)
bundle_root = "file:///srv/mg/"            # file:// | http:// | https://, ends with "/": fetches bundles/<id>.bundle
bundle_poll_seconds = 10                   # 2..300
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
timeout_ms = 10                            # per pipeline
connect_timeout_ms = 500
local_replay_authoritative = false         # true only when exactly one Edge serves these sites (§9.7)

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
dns_timeout_ms = 2000
rdns_concurrency = 16
rdns_cache_capacity = 100000

[sdk]
dir = "/opt/morphgate/sdk"                 # required: manifest.json + files (§11.1)
```

**校验规则**（`mg-edge --check-config` 执行全部；不访问网络，但读取并解析所有本地文件与凭证）：

| 规则 | 说明 |
|---|---|
| 监听器地址 | `cloudflare` + `loopback`：`bind` 必须是回环地址；`origin_mtls` 与 `direct_tls`：必须配 `tls_cert` / `tls_key`，`origin_mtls` 还要 `client_ca`；`bind` 不得与其他监听器、`metrics_listen`、任一 `origin` 相同 |
| 站点 | `hosts` 在站点间不重复；`listeners` 引用存在的监听器（站点 profile 在配置包里，加载配置包时再检查 `upstream.kind` 与每个监听器的 profile 一致，§9.10） |
| `bundle_root` | 以 `/` 结尾；`file://` 目录可读 |
| 凭证引用 | 形如 `cred://<name>`（`name` 为 `[A-Za-z0-9_.-]{1,64}`）解析为 `$CREDENTIALS_DIRECTORY/<name>`；也接受绝对路径。`CREDENTIALS_DIRECTORY` 未设置时使用 `cred://` 是错误。非 credential 路径的密钥文件若对组或其他用户可读，打印警告 |
| 密钥文件 | 解析 `token_keys`、`seal_root`、`pseudo.key`、`upstream_keys`，`site` 字段必须与站点 id 一致 |
| SDK | `sdk/manifest.json` 存在、schema 有效、列出的文件存在且 SHA-256 一致；挑战页模板占位符完整（§11.2） |

`deploy/systemd/edge.toml.example`、`edge/config/edge.dev.toml`、`scripts/edge-smoke.sh`、`edge/tests/shipped_configs.rs` 由 WP-E1 同步更新；systemd 单元增加 `LoadCredential=`（或 `LoadCredentialEncrypted=`）示例行与 `StateDirectory=morphgate` 的使用说明。

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
  max_failures: 5
  failure_window_s: 600
  submit: {rate: 30, period_s: 60, burst: 10}
  issue: {per_ipp: 60, per_asn: 600, period_s: 3600}
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
    policies: [policies/production.yaml]
    routes:                           # first match wins; "default" (/**, low, web) is appended if absent
      - name: login                   # [a-z0-9_-]{1,32}
        paths: ["/account/login", "/api/login"]
        methods: [GET, POST]          # optional; default any
        channel: web                  # web | api | mobile
        sensitivity: critical         # low | medium | high | critical
        require_clearance: true       # default: true iff sensitivity == critical
        fail_closed: true             # default: true iff sensitivity == critical
      - name: api
        paths: ["/api/**"]
        channel: api
        sensitivity: medium
    rate_limits:
      - id: login-per-ip
        routes: [login]               # empty = every route of this environment
        key: [ip]                     # ip | ip_prefix | asn | session | route
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

**校验规则**：环境的 `hosts` 恰好划分站点 `hosts`；路由名在环境内唯一；`paths` 非空且每项以 `/` 开头、只含可见 ASCII；`methods` 为大写 HTTP 方法；限速器 id 匹配 `[a-z0-9][a-z0-9_.-]{0,63}` 且不以 `mg.` 开头；`rate` 解析后 `rate ≥ 1`、`period_s ≥ 1`；`signal.weight ∈ (0, 2]`；`challenge.type ∈ {invisible, pow}`；策略文件存在、`profile:` 与站点一致或未声明；规则中引用的 `list("x")` 在 `lists` 或 `list_files` 中；每个名单 ≤ 10,000 条；`token.active_kid` 与 `verify_kids` 匹配 `[a-z0-9][a-z0-9._-]{0,63}`；`tarpit` 动作报错（D-09）；`params.type: interactive` 告警（D-08）；序列化后的配置包 ≤ 8 MiB。

### 8.3 站点 YAML → SiteBundle 与缺省值（WP-G2 构建、WP-E1 防御性回填）

| SiteBundle 字段 | 来源 / 缺省 |
|---|---|
| `schema_version` | 1 |
| `version` | `--version`，缺省为构建时的 Unix 秒 |
| `created_at_ms` | 构建时间 |
| `upstream.kind` / `expected_mask` | profile；`cloudflare`：NETWORK \| HTTP \| EDGE_TLS \| IDENTITY \| RATE \| EXTERNAL；`direct_tls`：NETWORK \| TLS \| HTTP \| IDENTITY \| RATE |
| `environments[].routes` | 声明顺序；末尾追加 `{id: "default", name: "default", paths: ["/**"], channel: WEB, sensitivity: LOW}`（除非已有 `paths == ["/**"]` 的路由）；`Route.id = Route.name` |
| `environments[].rules` | 该环境所有策略文件的规则，去掉 `mode: disabled` 与已过期的，按 §5.4 排序；`expr_ir` 由 `CheckedRule.Proto()` 填入 |
| `environments[].rate_limits` | 声明顺序；`algorithm = "gcra"`；`route_ids` 为空表示全部路由 |
| `token_key_ids` | `[active_kid] + verify_kids` |
| `challenge` | `ttl_s` 120、`pow_bits` 14/16/18/20、`fallback_ret` `/`、`max_failures` 5、`failure_window_s` 600、`submit_*` 30/60/10、`issue_*` 60/600/3600 |
| `clearance` | 1800 / 1800 / 86400 / `ctp_shadow = true` |
| `scoring` | §5.7 的初始值；`family_modes` 缺省 `{edge_tls: shadow}` |
| `crawler_policy` | `default_action` 缺省 `allow` |
| `events` | `allow_sample_rate` 0.1、`access_log` true、`stream` true |
| `origin_headers` | `scores` true、`reasons` false、`session` true |
| `lists` | `lists` 与 `list_files` 合并（同名报错） |
| `artifacts` | 每个配置的工件：`name`（§12.1 表）、`uri = "artifacts/<sha256>"`、`sha256`、`size`、`version`（JSON 工件取 `fetched_at` / `generated_at`；mmdb 取其 `build_epoch`） |
| `source_digest` | `sha256`（小写十六进制）依次覆盖：站点 YAML 字节、每个策略文件字节、每个名单文件字节（按出现顺序） |

## 9. Edge 行为规范（`mg-edge`，WP-E1）

### 9.1 模块划分

| 模块 | 职责 | 依赖 Pingora |
|---|---|---|
| `config.rs`、`creds.rs` | `edge.toml` v1、`cred://` 解析、密钥文件加载 | 否 |
| `listener.rs` | 每个监听器一个 proxy service；TLS 设置（`origin_mtls`、`direct_tls`）；`ConnectionFilter` | 是 |
| `upstream.rs` | 上游认证、头族剥离、可信头解析（`x-mg-cf-*` 等） | 否（输入为头名 / 值切片） |
| `sites.rs` | 站点运行时（配置包派生）、环境与路由匹配 | 否 |
| `bundle.rs` | 配置包拉取、验签、校验、工件获取、LKG、原子切换 | 否 |
| `context.rs` | `RequestContext`、`RequestExtras`、`MissingSet`、`Activation` 输入 | 否 |
| `identity.rs`、`dns.rs` | 凭证校验、爬虫验证与 rDNS 任务；hickory 实现 `DnsResolver` | 否 |
| `state.rs`、`ratelimit.rs` | Valkey 客户端、Lua、管线、本地模式与熔断；限速器集合 | 否 |
| `decide.rs` | 组装 `DecisionCore` 与 `SitePolicy` | 否 |
| `enforce.rs`、`pages.rs` | 动作执行、源站 `MG-*` 头、挑战页 / 阻断页 / 429 页渲染 | 部分 |
| `mg_endpoints.rs` | `/__mg/c`、`/__mg/s/*`、healthz | 是 |
| `events.rs` | EventSink、队列、VictoriaLogs / 文件 / Stream 出口 | 否 |
| `metrics.rs`、`proxy.rs`、`server.rs`、`routes.rs`、`headers.rs` | 现有模块扩展 | 是 |

非 Pingora 模块只接收普通 Rust 类型（头名 / 值切片、`SocketAddr` 等），可以脱离 Pingora 做单元测试。

### 9.2 监听器与上游认证

| 情况 | 行为 |
|---|---|
| 每个 `[[listeners]]` | 一个 `http_proxy_service`，`EdgeProxy` 持有监听器名与 profile |
| `cloudflare` + `loopback` | TCP 对端必须是回环地址，否则 403（`reason="non_loopback_peer"`）；认证通过，`auth_method = loopback` |
| 配置了 `upstream_keys` | 请求必须带 `x-mg-upstream-key`，与密钥文件中任一值常量时间相等；否则 403 纯文本 `forbidden`、`no-store`，计 `reason="bad_secret_header"`，不回退为直连处理；通过时 `auth_method = secret_header` |
| `cloudflare` + `origin_mtls` | BoringSSL：`SslVerifyMode::PEER \| FAIL_IF_NO_PEER_CERT`，信任 `client_ca`；验证回调中 `preverify_ok == false` 时计 `reason="untrusted_ca"`；握手失败即断开；`auth_method = origin_mtls` |
| `cloudflare_ip_filter` | 启用 pingora 特性 `connection_filter`；`should_accept(peer)` 查当前所有站点 `cloudflare-ips` 工件的并集；尚无工件时放行并把 `mg_cf_ip_filter_active` 置 0 |
| `direct_tls` | TLS 监听（ALPN `h2`、`http/1.1`），`auth_method = none`，删除全部上游头族，客户端 IP = TCP 对端 |
| 失败计数 | `mg_upstream_auth_failures_total{listener, profile, reason}` |

### 9.3 头部清洗与可信头解析

**头族**（名称先转小写，并把 `_` 换成 `-` 再匹配；因此 `CF_Connecting_IP`、`X_MG_CF_ASN` 同样命中）：前缀 `cf-`、`x-mg-`、`cloudfront-`、`ali-`、`esa-`、`eo-`、`x-forwarded-`、`mg-`；全名 `tls-ja3`、`tls-ja4`、`tls-hash`、`x-forward-port`、`forwarded`、`true-client-ip`、`x-real-ip`。

**处理顺序**：

1. 记下客户端原始头名（`direct_tls` 的 `http.header_names` / `header_order` 用）。
2. 认证通过的 `cloudflare` 请求：只按下表解析**精确的连字符小写名**；下划线变体永不解析。
3. 从请求中删除所有命中头族的头（包括认证通过时 Cloudflare 添加的），然后为源站重新写入 §9.9 规定的头。`direct_tls`（或未认证）请求只要带了任一头族，计一次 `mg_upstream_headers_stripped_total{profile}`。

**`cloudflare` 解析表**（值非法按缺失处理；"告警"指计入 `mg_upstream_signal_missing_total{profile="cloudflare", signal}`，`signal` 取头名去掉 `x-mg-cf-` 前缀）：

| 头 | 校验 | 目标 | 缺失 / 非法时 |
|---|---|---|---|
| `cf-connecting-ip` | 严格解析为 IP（无端口、无方括号）；映射地址还原 | `net.ip`、`ip_source = cf_connecting_ip` | `client_ip_header_missing = true`，计 `mg_cf_connecting_ip_missing_total{site}` |
| `cf-connecting-ipv6` | 同上，必须是 IPv6 | 仅 `pseudo_ipv4_overwrite` 时优先使用，`ip_source = cf_connecting_ipv6` | 回退 `cf-connecting-ip` |
| `cf-ray` | `[A-Za-z0-9-]{1,64}` | `upstream.cf_ray` | 忽略 |
| `cf-visitor` | JSON `{"scheme":"http"\|"https"}`，≤ 64 字节 | 访客协议（TLS 字段的条件性、`X-Forwarded-Proto`） | 视为 https |
| `cf-worker` | 小写 zone 名 ≤ 253 | 不在 `cloudflare.owner_zones` → 客户端 IP 视为未知、label `foreign_worker`、计 `mg_cf_foreign_worker_total{site}` | — |
| `cf-ipcountry` | `[A-Z]{2}`；`XX` 视为缺失；`T1` → `net.tor` 来源之一 | `net.upstream_country` | 仅 `location_headers` 时解析 |
| `cf-region`、`cf-region-code`、`cf-timezone` | ≤ 64 字节可见 ASCII；时区 `[A-Za-z0-9/_+-]{1,64}` | `net.upstream_region`（取 region-code）、`upstream_timezone` | 同上；`cf-ipcity`、经纬度、邮编等一律丢弃 |
| `x-mg-cf-tls-version` | `[A-Za-z0-9._-]{1,16}` | `edge_tls.version` | 访客 scheme 为 https 时告警 |
| `x-mg-cf-tls-cipher` | `[A-Za-z0-9_-]{1,64}` | `edge_tls.cipher` | 同上 |
| `x-mg-cf-tls-ciphers-sha1`、`-tls-ext-sha1` | base64，解码后 20 字节 | `edge_tls.ciphers_sha1`、`ext_sha1` | 同上 |
| `x-mg-cf-tls-hello-len` | 十进制 1–65535 | `edge_tls.hello_len` | 同上 |
| `x-mg-cf-tls-random` | base64，解码后 32 字节 | Phase 1 只校验（`client_conn_key` 在 Phase 2 近线使用），值不进任何结构 | 同上 |
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

### 9.4 站点、环境与路由

1. Host：HTTP/1 取 `Host` 头，HTTP/2 取 `:authority`；小写、去端口与末尾点。不在任何站点 `hosts` 中 → 404 纯文本 `unknown site`、`no-store`，计 `mg_unknown_host_total{listener}`。
2. 监听器必须同时在 `edge.toml` 站点的 `listeners` 与配置包的 `allowed_listeners` 中（尚无配置包时只看前者），否则 403 并计 `mg_listener_rejected_total{listener, site}`。
3. 环境：`hosts` 含该 Host 的环境。
4. 路由：路径先做 `routes::cloudflare_view` 规范化（解码非保留字符、`\` 变 `/`、合并 `//`、去点段），再按路由声明顺序匹配：`hosts` 为空或含该 Host、`methods` 为空或含该方法、任一 `paths` glob（§5.3 语义）命中。第一个命中的路由生效；都不命中时用 `default`。

### 9.5 RequestContext 构建

| 字段 | 来源 |
|---|---|
| `request_id` | 32 个小写十六进制字符（128 位随机） |
| `ts_ms` | 请求到达时间 |
| `site_id`、`env`、`route_id`、`channel` | §9.4 |
| `upstream` | `profile`、`authenticated`、`auth_method`、`cf_ray`、`client_ip_header_missing` |
| `net` | `ip` / `ip_prefix` / `ip_source`；`asn` / `as_org` / `country`（GeoLite2，§7.2）；`conn_type`、`tor`（§4.1）；`upstream_*`、`rtt_ms`（§9.3） |
| `tls` | `direct_tls`：`available = true`、`version`（SslDigest）、`alpn`；`sni` 在能从 Pingora 取得时填，否则留空；`ja4` 为空（WP-J1 在 `ja4` 特性下填） |
| `edge_tls` | §9.3（`cloudflare` 且至少一项有值时为 `Some`） |
| `http` | `version` / `version_source`；`method`、`host`、`path`（原始）；`query_keys`（至多 32 个，每个 ≤ 64 字节）；`header_order`（§4.1）；`header_names`；`user_agent`（≤ 512 字节）；`cookie_names`（至多 32 个，排除 Cloudflare Cookie `__cf_bm`、`cf_clearance`、`_cfuvid`、`__cflb`、`__cfseq`、`__cfwaitingroom`、`cf_chl_*` 与 `__Host-mg_clr`）；`body_size`（`Content-Length`）；`content_type`（`;` 之前，≤ 64 字节）；`early_data`（`Early-Data: 1`）；Tier 1 字段 |
| `identity.token` | §9.6 |
| `identity.proof`、`agent` | 缺省（Phase 1 MISSING） |
| `identity.crawler` | §9.6 |
| `session_id` | 有效凭证的 `sub` |
| `availability_mask` | 本请求至少有一个 PRESENT 信号的族（Decision Core 运行后回填） |
| `expected_mask` | 配置包 `upstream.expected_mask` |
| `client` | `None`（Phase 1） |
| `verdicts` | §9.7 MGET 得到的 EntityVerdict |

事件中的 `ctx` 与内存中的一致（上面的截断规则已经保证了事件大小）。`RequestExtras.headers` 按 §4.1 `req.headers` 规则构建。

### 9.6 身份

- **凭证**：取 Cookie 候选（§6.6），`mg_challenge::verify` 验证；再以当前请求算出 `BindInputs`（`uah` 来自 `mg_core::ua::parse`，`ipp` / `ipa` 在 IP / ASN 已知时，`ctp` 在 `ctp_shadow` 且四项齐全时）做 `check_clearance_bind`。结果写入 `identity.token`（`status`、`level`、`age`、`bind`），计 `mg_token_verify_total{result}`（`none` / `valid` / `expired` / `invalid` / `binding_mismatch`）。
- **爬虫**：配置包含 `crawler-registry` 工件时，用 `CrawlerVerifier::check(ua, ip, now)`；返回 `RdnsJob` 时，若在途任务数 < `rdns_concurrency`，在 tokio 上启动任务：`resolve_rdns`（每次查询 `dns_timeout_ms` 超时）→ `complete(job, outcome, now)`；否则丢弃该任务（下次请求会再触发）。映射：

| `CrawlerStatus` | `claimed` | `operator` / `purpose` | `verified` | `verification` | `method` |
|---|---|---|---|---|---|
| `NotClaimed` | false | 空 | false | `none` | 空 |
| `Verified` | true | 运营方 | true | `verified` | `ip_range` / `rdns` |
| `Failed` | true | 运营方 | false | `failed` | `ip_range` / `rdns` |
| `Pending` | true | 运营方 | false | `pending` | 空 |
| `Unverifiable` | true | 运营方 | false | `unverifiable` | 空 |

  同时按 05 §3.4 计 `mg_cf_vbot_disagree_total{direction}`：`verified` 且 `cf_vbot == false` → `mg_pass_cf_false`；`failed` 且 `cf_vbot == true` → `mg_fail_cf_true`。
- **hickory**：`dns.rs` 用 `hickory_resolver` 的 tokio 解析器与系统配置（`/etc/resolv.conf`）实现 `DnsResolver`；`dns_resolver = "static:<path>"` 时改用 `mg_intel::StaticResolver` 并在启动日志中警告。

### 9.7 状态层（Valkey）

**键**（02 §7 的命名，Phase 1 实际读写的部分）：

| 键 | 类型 | 操作 | TTL |
|---|---|---|---|
| `mg:v:{site}:{type}:{key}` | String：`mg_core::EntityVerdict` 的 JSON | Edge 只 `MGET` | 由写入方设置 |
| `mg:rl:{site}:{limiter}:{kh}` | String：TAT（微秒，十进制整数） | `EVALSHA mg_gcra` | 脚本以 `PX` 设置 |
| `mg:n:{site}:{nonce_hex}` | String `1` | `SET … NX PX` | `exp_ms − now_ms + 60000` |
| `mg:ev` | Stream | `XADD mg:ev MAXLEN ~ <stream_maxlen> * …` | — |

**键中的假名化**（D-06）：`kh(domain, type, value) = lower_hex(HMAC-SHA256(K_pseudo, domain ‖ 0x00 ‖ type ‖ 0x00 ‖ value))[0..32]`（KAT：`kat.json` 的 `entity_key`）。

| 实体 | `{type}` | `{key}` |
|---|---|---|
| IP | `ip` | `kh("mg-ent-v1", "ip", ip 文本)` |
| 前缀 | `prefix` | `kh("mg-ent-v1", "prefix", "203.0.113.0/24")` |
| ASN | `asn` | 十进制 ASN（不哈希） |
| 会话 | `session` | 凭证 `sub`（本身是随机假名） |

限速器：`{kh} = kh("mg-rl-v1", limiter_id, dims)`，`dims` 按限速器 `key` 的声明顺序以 `&` 连接 `name=value`：`ip=<ip>`、`ip_prefix=<prefix>`、`asn=<n>`、`session=<sub>`、`route=<route name>`。任一分量未知（例如没有会话）时，本请求跳过该限速器（不产生观测）。

**Verdict 读取**：键顺序为 ip、prefix、asn、session；`share_ip_verdicts` 时追加 `mg:v:all:ip:…`、`mg:v:all:prefix:…`、`mg:v:all:asn:…`；缺少输入的键不读。解析失败的值忽略并计 `mg_verdict_parse_errors_total`。本地缓存 2 s（含"没有 verdict"的结果），至多 50,000 项。

**GCRA 脚本 `mg_gcra`**（Lua 5.1；与 `mg_core::gcra_check` 必须逐位一致，WP-E1 用同一组用例同时测两者）：

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

`string.format('%d')` 是必须的：Lua 5.1 的 `tostring` 会把 1.8e15 写成科学计数法。生产调用传 `now_us = 0`（以 Valkey 时钟为准）；测试传显式时间，与 `mg_core::gcra_check` 对照。Rust 侧全部用 `u64`：`tat = max(stored.unwrap_or(0), now)`、`new_tat = tat + interval · cost`、`allow_at = new_tat.saturating_sub(dvt)`，`now < allow_at` 为拒绝（`retry_after = allow_at − now`、`tat_minus_now = tat − now`），否则允许（`new_tat_us = Some(new_tat)`、`tat_minus_now = new_tat − now`），与 Lua 的有符号运算结果一致；"只检查"由调用方不保存 `new_tat` 实现。

**管线**（每请求至多 2 次往返，02 §1）：

| 路径 | 往返 1 | 往返 2 |
|---|---|---|
| 普通请求 | `MGET` verdict 键 + 一次 `EVALSHA mg_gcra`（本请求全部 global 限速器） | — |
| `POST /__mg/c` | `EVALSHA mg_gcra`：`mg.c.submit`（write 1）+ `mg.c.fail`（write 0：再失败一次是否会超限） | 本地检查全部通过后：`SET mg:n:… NX PX` + `EVALSHA mg_gcra`：`mg.clr.issue.ipp`、`mg.clr.issue.asn`（write 1） |
| 提交失败后 | 异步（不在响应路径上）：`EVALSHA mg_gcra`：`mg.c.fail`（write 1） | — |

连接用 `redis::aio::ConnectionManager`（自动重连）；启动与收到 `NOSCRIPT` 时 `SCRIPT LOAD`，管线内用 `EVALSHA`，`NOSCRIPT` 时重载并重试一次；每次管线的超时为 `timeout_ms`，计 `mg_valkey_rtt_seconds`。

**本地模式与熔断**：`mode = "local"`，或管线失败 / 超时时，本请求改用进程内状态：GCRA 状态表（与 `gcra_check` 同一数学，分片 `Mutex<HashMap>`，过期项定期清理）、nonce 集合（LRU，100,000 项，按 TTL 过期）、无 verdict。连续 5 次失败后熔断：1 s 内不再访问 Valkey，之后每次熔断翻倍至 30 s 上限，期间以 `PING` 探测恢复；`mg_state_mode{mode}` 为当前模式的 0/1 仪表。

**重放存储不可用**（本地模式且 `local_replay_authoritative = false`）：`POST /__mg/c` 在消费 nonce 那一步——路由 `fail_closed` → 429 + `Retry-After: 5`（"稍后再试"），reason `ic.replay_unavailable`，不签发凭证；否则照常签发，reason `ic.replay_unchecked`（01 §8 降级表）。

### 9.8 限速

- 对普通请求：取所在环境中 `route_ids` 为空或包含当前路由的限速器；`scope = local` 只用进程内状态，`global` 用 Valkey（失败时回退本地）。每个限速器产生一个 `RateObservation`（§5.6）：`utilization` 取 `GcraOutcome::utilization`，超限时 `exceeded = true`；`rate` 映射（§4.1）以限速器 id 为键。
- 内置限速器（只用于 `/__mg/c` 流程，参数来自配置包 `challenge`）：

| id | 键 | 参数 | 超限 |
|---|---|---|---|
| `mg.c.submit` | `[ip_prefix]` | `submit_rate / submit_period_s / submit_burst` | 429（`Retry-After` = GCRA 等待时间向上取整秒） |
| `mg.c.fail` | `[ip_prefix]` | `max_failures / failure_window_s`，burst = `max_failures` | 429 |
| `mg.clr.issue.ipp` | `[ip_prefix]` | `issue_per_ipp / issue_period_s` | 只记信号与指标（仍签发） |
| `mg.clr.issue.asn` | `[asn]` | `issue_per_asn / issue_period_s` | 同上 |

- 超限计 `mg_ratelimit_exceeded_total{limiter}`（`dry_run` 限速器也计）。

### 9.9 动作执行

| 最终动作 | Edge 行为 |
|---|---|
| ALLOW / TAG / LOG | 转发源站。`upstream_request_filter` 写入：`MG-Client-IP`（客户端 IP 未知时不写）、`MG-Request-Id`；`origin_headers.scores` 时 `MG-Bot-Score`（0–100）、`MG-Bot-Class`（小写 wire 名）、`MG-Verified`（已验证爬虫：`crawler:<operator>`）；`origin_headers.session` 且有会话时 `MG-Session`；TAG 时 `MG-Tags: a,b`；`origin_headers.reasons` 时 `MG-Reasons`（`top_reasons` 逗号分隔）。`X-Forwarded-For` 改写为单值客户端 IP（未知时删除）；`X-Forwarded-Proto`：`cloudflare` 取 `cf-visitor` 的 scheme，`direct_tls` 为 `https`。认证通过的 `cloudflare` 请求原样转发 `CF-Connecting-IP`、`CF-IPCountry`（仅 `location_headers`）、`Cf-Ray`、`CF-Visitor`。`response_filter` 删除源站响应中的 `MG-*` 与 `MG_*` 头 |
| CHALLENGE | 403：导航请求（`sec-fetch-mode: navigate`，或没有该头且 `accept` 含 `text/html`）返回挑战页（§10.2），其余返回 JSON。C 按 §6.2 签发；`ret`：GET / HEAD 导航为原始 `path[?query]`（校验失败或 > 512 字节时用 `fallback_ret`），其他方法为 `fallback_ret`。计 `mg_challenge_total{type, provider="none", result="issued"}` |
| RATE_LIMIT | 429 + `Retry-After`；导航请求返回简短 HTML（中英文"请求过多"+ request_id），否则 `{"error":"mg_rate_limited","retry_after":N,"request_id":"…"}` |
| BLOCK | 403；导航请求返回通用阻断页（只含 request_id 与"如有疑问请联系站点所有者"），否则 `{"error":"mg_blocked","request_id":"…"}` |
| monitor（`SiteBundle.monitor_only`） | 引擎给出的决定原样记入事件，`decision.dry_run = true`、`monitor_only = true`；按 ALLOW 转发（带 `MG-*` 头，`MG-Bot-Class` 等反映评分结果） |
| `fail_closed` 路由且客户端 IP 未知 | 决定改为 RATE_LIMIT 429、`Retry-After: 5`、`rule_id = "hard.client_ip_unknown"`（monitor 时同样只记录） |
| `Early-Data: 1` | `http.early_data = true`：不签发凭证、不消费 nonce；`critical` 路由直接 425（monitor 时只记录） |

Edge 自己生成的所有响应（上表、§10）都带 `Cache-Control: no-store, private`（`/__mg/s/*` 除外）与 `X-Content-Type-Options: nosniff`；HTML 另加 `X-Robots-Tag: noindex`、`Referrer-Policy: same-origin`、`X-Frame-Options: DENY`。Edge 生成的响应里不出现 `MG-*` 头，唯一例外是 JSON Challenge 的 `MG-Challenge: <type>`。

### 9.10 配置包加载

```
on start, per site:
  if state_dir/bundles/<site>.bundle exists: verify + validate + load artifacts -> apply (LKG)
  else: bootstrap mode (D-21)
every bundle_poll_seconds (±20% jitter), per site:
  GET <bundle_root>bundles/<site>.bundle   (file:// -> read; ETag = sha256 of the bytes)
      If-None-Match: <last ETag>            (http(s); response ETag stored as returned)
  304 / same sha256          -> last_ok = now
  200                        -> candidate
  error / timeout            -> mg_config_fetch_failures_total{site}++, keep current
candidate:
  size <= 8 MiB; decode SignedBundle; key_id in [trust].owner_keys;
  ed25519 verify("mg-bundle-v1" || 0x00 || bundle); decode SiteBundle
  schema_version == 1; site_id == site; hosts == edge.toml hosts (as sets)
  upstream.kind == profile of every edge.toml listener serving this site
  version > current.version (equal version with identical bytes = no-op; otherwise reject)
  every token_key_ids[*] present in token.keys.json; lists / rules / IR / routes / limiters convert
  artifacts: for each ref, cache hit state_dir/artifacts/<sha256> or GET <bundle_root>artifacts/<sha256>;
             sha256 and size must match; parse by kind (mg-intel); any failure -> reject whole bundle
  if not_before_ms > now: keep as pending, swap when due
  swap: ArcSwap<SiteRuntime> (in-flight requests keep the old Arc); persist signed bytes to
        state_dir/bundles/<site>.bundle via tmp + rename; last_ok = now
  reject -> mg_config_reload_total{site, result="rejected"} and a log line with the reason; keep current
```

- `mg_config_version{site}` = 当前生效版本（bootstrap 为 0）；`mg_config_age_seconds{site}` = `now − last_ok`（从未成功过时为进程运行时长）；`mg_config_reload_total{site, result="applied"|"rejected"|"unchanged"}`。
- 出站请求：`reqwest`，不读系统代理环境变量，User-Agent `mg-edge/<version>`，`bundle_client` 的 CA / 客户端证书用于 https，超时 `timeout_ms`，只跟随同源重定向（至多 3 次）。
- 工件缓存不做自动清理之外的删除：保留当前与上一个配置包引用的文件，其余在成功切换后删除。

### 9.11 事件

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
- `mg:ev`：同一个 flusher 把本批的 `StreamEntry` 用一个管线 `XADD` 出去（§13.6），失败计 `mg_event_dropped_total{sink="stream"}`，不重试。
- 采样（`kind=decision`）：以下情况 `sample_rate = 1`：动作不是 ALLOW / TAG / LOG；路由敏感度为 high / critical；`force_log`；存在 `missing_input` / `eval_error` / `dry_run` 的 hit；monitor 模式下被记为非 ALLOW 的决定。其余以 `events.allow_sample_rate` 抽样，事件中记录该值。

### 9.12 平滑升级与关闭

后台任务（配置包轮询、事件 flusher、rDNS 任务）在 Pingora 的关闭信号后停止；flusher 在退出前尽力发送队列中剩余的 P0 记录（至多 2 s）。`--upgrade` 启动的新进程从 `state_dir` 读取 LKG，所以升级期间配置不回退到 bootstrap。

## 10. HTTP 接口

### 10.1 端点

| 方法与路径 | 作用 | 请求体上限 | 缓存头 | Phase 1 |
|---|---|---|---|---|
| `GET` / `HEAD /__mg/healthz` | 存活 | — | `no-store, private` | 已有 |
| `GET` / `HEAD /__mg/s/<file>` | SDK 构建文件 | — | `public, max-age=31536000, immutable` | 实现 |
| `POST /__mg/c` | 提交 Challenge 解答 | 8 KiB | `no-store, private` | 实现 |
| `/__mg/c/renew`、`/__mg/r`、`/__mg/t`、其他 `/__mg/*` | 保留 | — | `no-store, private` | 404 |

`/__mg/*` 由 Edge 在路由匹配、决策之前应答，从不转发源站（包括 `routes.rs` 识别的所有规范化写法）。非允许的方法返回 405 与 `Allow`。

### 10.2 挑战页与 JSON Challenge

- **HTML**：403，`Content-Type: text/html; charset=utf-8`，§9.9 的通用头，另加 `Content-Security-Policy: default-src 'none'; script-src 'nonce-<N>'; style-src 'nonce-<N>'; worker-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`（`<N>` 为每响应 128 位随机数的 base64）。正文由 SDK 目录中的模板渲染（§11.2）。HEAD 请求只返回头。
- **JSON**：403，`Content-Type: application/json`，`MG-Challenge: <type>`：

```json
{"error": "mg_challenge", "type": "pow", "challenge": "<C>", "pow": {"alg": "sha256-hashcash-v1", "bits": 16},
 "ret": "/account/login", "retry": true, "request_id": "<id>"}
```

### 10.3 `POST /__mg/c`

**请求**（两种编码，内容相同）：

- 导航提交：`Content-Type: application/x-www-form-urlencoded`，正文只有一个字段 `mg=<URL 编码的提交 JSON>`。
- fetch 提交：`Content-Type: application/json`，正文即提交 JSON。

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
| `env`、`auto` | 可缺省；有则按 SDK 的 schema 解析，解析失败视为缺省 |

**校验顺序**（04 §4.1 的 Phase 1 子集；任一步失败都走"统一失败"，reason code 只进事件）：

| # | 检查 | 失败 |
|---|---|---|
| 1 | `Early-Data: 1` | 425 `{"error":"mg_too_early"}` |
| 2 | 往返 1：`mg.c.submit` 超限，或 `mg.c.fail` 的检查结果为超限 | 429（`ic.rate_limited`） |
| 3 | 带 `Content-Encoding`；`Content-Length`（若有）> 8192；实际读到的正文 > 8192（最多读 8193 字节即停）；Content-Type 不是上述两种；JSON / 表单解析失败 | 统一失败（`ic.body`），不附新 C |
| 4 | 打开 C（§6.2） | 统一失败（`ic.c_*`），不附新 C（客户端回到 `ret` 重新触发挑战） |
| 5 | 绑定（§6.4）：`uah` 硬；`ipp` 硬失败 / 软 | `ic.bind_uah` / `ic.bind_ipp`；软结果只记 `ic.bind_ipp_soft` |
| 6 | PoW | `ic.pow` |
| 7 | `ret` | `ic.ret` |
| 8 | 基础环境：`auto.webdriver == true` → 失败；`env.ua.userAgent` 非空且不是请求 `User-Agent` 的前缀 → 失败 | `ic.automation_flag` / `ic.ua_mismatch` |
| 9 | 往返 2：`SET mg:n:{site}:{nonce_hex} 1 NX PX …` | 已存在 → `ic.nonce_reused`；存储不可用按 §9.7 |
| 10 | 签发：`lvl = invisible`（type invisible）或 `pow`；`rb = claims.risk_band`；绑定取当前请求；`mint` | — |

**响应**：

| 结果 | 导航提交 | fetch 提交 |
|---|---|---|
| 成功 | 303，`Location: <ret>`，`Set-Cookie`（§6.6） | 200 `{"ok":true,"ret":"<ret>"}`，`Set-Cookie` |
| 统一失败 | 403 挑战页（模板 `state = "failed"`，附新 C 时可自动重试一次） | 403 `{"error":"mg_challenge_failed","retry":true,"request_id":"…","challenge":"<new C>","type":"pow","pow":{"alg":"sha256-hashcash-v1","bits":16}}`（无新 C 时省略后三项） |
| 超过失败配额 / 提交限速 | 429 + `Retry-After`，简短 HTML | 429 `{"error":"mg_rate_limited","retry_after":N,"request_id":"…"}` |
| 重放存储不可用且 `fail_closed` | 429 + `Retry-After: 5` | 同上 |

第 5 步及之后的失败附新 C：与原 C 相同 type、`route_class`、`ret`，风险段取原 C 的 `risk_band`。每次提交都产生一条 `kind=feedback` 事件（§13.3）与 `mg_challenge_total{type, provider="none", result="solved"|"failed"|"expired"}`（`expired` 指 `ic.c_expired`）；带 `env` 时另写一条 `kind=telemetry`（§13.5）。

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

`files` 中的文件经 `/__mg/s/<name>` 提供；`templates` 只由 Edge 读取，不对外提供。构建由 `sdk/web/scripts/build-dist.mjs`（新增）在 esbuild 之后完成；`check` 脚本顺序变为 `typecheck && test && build && size`（不变），`build` 内部调用 `build-dist.mjs`。

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

NIST SHA-256 测试向量；`testdata/phase1/kat.json` 的全部 `pow` 用例（`first_counter` 与 `digest_hex` 完全一致；测试直接读取该文件）；Worker 消息处理器（直接调用处理函数）；提交 JSON 的形状与 `ret` 取值；表单构建（经可注入的最小 DOM 接口，测试中用假对象）；模板占位符 / nonce / 外部资源规则；`manifest.json` 的哈希与文件名一致；构建产物大小仍 ≤ 30 KB gzip。

## 12. 工件与密钥文件格式

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

校验（写入方与读取方相同）：`v == 1`、`kind`；IPv4 5–64 条、IPv6 2–32 条；每条是规范网络地址（主机位为 0）；IPv4 前缀长度 8–32、IPv6 16–128；不含私有、回环、链路本地、组播、未指定与文档地址段。

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

`prefixes_json` 格式：`{"creationTime": "...", "prefixes": [{"ipv4Prefix": "..."} | {"ipv6Prefix": "..."}]}`；`cidr_text`：每行一个 CIDR。校验：id 唯一；`mode` 含 rDNS 时 `rdns_suffixes` 非空（小写）；`ip_ranges` 模式的 `cidrs` 非空；每个运营方至多 20,000 条 CIDR。运营方按文件顺序匹配 UA。

### 12.4 文本名单

UTF-8，每行一项，`#` 开始注释，空行忽略。`datacenter-asns`：十进制 ASN（可带 `AS` 前缀）；`tor-exits`：IP 或 CIDR。

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

- `kid` 匹配 `[a-z0-9][a-z0-9._-]{0,63}`。口令来源：环境变量 `MGCTL_PASSPHRASE_FILE`（文件第一行，去掉行尾换行；测试与自动化用），否则从 TTY 无回显读取（`golang.org/x/term`；生成时输入两次）；口令从不出现在命令行参数里。`MGCTL_AGE_WORK_FACTOR`（10–22）只供测试缩短 scrypt 时间。私钥文件 0600，公钥 0644；不覆盖已有文件。

### 12.7 站点密钥与其他密钥

均为明文 JSON（0600），供所有者在 Edge 主机上用 `systemd-creds encrypt` 封装后以 `LoadCredentialEncrypted=` 交付（§17）；`key` 为 base64url（无填充）编码的 32 个随机字节。

```json
{"v": 1, "kind": "mg-site-token-keys", "site": "blog",
 "keys": [{"kid": "blog-t-20260927", "key": "<b64url>", "created_at": "2026-09-27T10:00:00Z"}]}
```

```json
{"v": 1, "kind": "mg-site-seal-root", "site": "blog", "root_id": "blog-r-20260927", "key": "<b64url>", "created_at": "2026-09-27T10:00:00Z"}
```

```json
{"v": 1, "kind": "mg-pseudo-key", "id": "pseudo-20260927", "key": "<b64url>", "created_at": "2026-09-27T10:00:00Z"}
```

```json
{"v": 1, "kind": "mg-upstream-keys", "values": ["<43-char b64url>", "<previous value>"], "created_at": "2026-09-27T10:00:00Z"}
```

`token.keys.json` 新的在前，至多 3 个；`kid` 形如 `<site>-t-<YYYYMMDD>`（同日重复时加 `-2` 等后缀）。`mg-upstream-keys` 至多 2 个值，`values[0]` 写入 Cloudflare Tier 0 规则的静态值。

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
- `action` 取值：`keys.gen`、`keys.gen_pseudo`、`keys.gen_upstream`、`site_keys.gen`、`site_keys.rotate_token`、`bundle.sign`、`bundle.publish`、`cf.ips.sync`、`crawler.sync`。`diff` 从不含密钥材料。

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

`path` 不含查询串，≤ 1024 字节；未知值省略。只在 `events.access_log` 时写。`/__mg/*` 请求同样写访问记录（`route = "__mg"`、`action` 省略），但不产生 `kind=decision` 事件，也不计入 `mg_requests_total`。

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

`v 1 kind decision site <site> ts <ms> rid <request_id> sess <sub | ""> route <route> action <action> dry <0|1> class <class> score <0-100> ipk <kh ip | ""> pfk <kh prefix | ""> asn <n | 0> status <http status | 0>`

`/__mg/c` 另写 `kind feedback`，字段为 `v kind site ts rid route outcome type pfk asn`。不写客户端 IP 明文，不写 `client_conn_key`。

### 13.7 指标

直方图桶（秒）：`0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1`。

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `mg_requests_total` | counter | site, env, route, action, class | 每个非 `/__mg/*` 请求；`action` 为执行前的决定（monitor 下即"本应"的动作） |
| `mg_decision_latency_seconds` | histogram | site | Decision Core `evaluate` 耗时 |
| `mg_edge_added_latency_seconds` | histogram | site | Edge 附加延迟：`request_filter` 开始到向源站发出请求，加上响应过滤耗时（Phase 1 验收 p99 < 5 ms 的依据） |
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
| `mg_unknown_host_total` | counter | listener | 新增 |
| `mg_listener_rejected_total` | counter | listener, site | 新增 |
| `mg_verdict_parse_errors_total` | counter | — | 新增 |
| `mg_rdns_lookups_total` | counter | result | 新增；`pass` / `fail` / `dns_error` / `dropped` |
| `mg_cf_ip_filter_active` | gauge | listener | 新增 |
| `mg_edge_info`、`mg_edge_requests_total`、`mg_edge_request_duration_seconds`、`mg_edge_request_errors_total` | — | — | Phase 0 已有，保留 |

标签只取有界值：`route` 来自配置包的路由名，`limiter` 来自配置包，`signal` 来自 §9.3 的固定表。

mgctl（WP-G3）用 node_exporter textfile 格式输出（`--metrics-textfile <path>`，原子写）：`mg_cf_audit_failed_checks{zone, check}`（0/1）、`mg_cf_audit_last_run_timestamp_seconds{zone}`、`mg_cf_ips_sync_timestamp_seconds`（最近一次成功同步的时间；告警表达式用 `time() - mg_cf_ips_sync_timestamp_seconds` 得到 06 §5 的 `mg_cf_ips_sync_age_seconds`）。

## 14. mgctl 命令（WP-G2、WP-G3）

### 14.1 命令一览与约定

| 命令 | 作用 | 审计 action | WP |
|---|---|---|---|
| `mgctl keys gen --kid <kid> --out-dir <dir>` | 所有者 Ed25519 签名密钥（§12.6） | `keys.gen` | G2 |
| `mgctl keys gen-pseudo --out <file>` | 假名化密钥 | `keys.gen_pseudo` | G2 |
| `mgctl keys gen-upstream --out <file> [--rotate]` | 上游密钥头值；`--rotate` 读取现有文件，新值放前，保留 2 个 | `keys.gen_upstream` | G2 |
| `mgctl site keys gen --site <id> --out-dir <dir> [--date YYYYMMDD]` | `token.keys.json` + `seal.root.json` | `site_keys.gen` | G2 |
| `mgctl site keys rotate-token --site <id> --file <token.keys.json> [--date YYYYMMDD]` | 新 token key 放前，至多保留 3 个；打印新 kid | `site_keys.rotate_token` | G2 |
| `mgctl site check --site-config <site.yaml>` | 只校验站点 YAML 与策略（不复制工件） | — | G2 |
| `mgctl bundle build --site-config <site.yaml> --out-dir <dir> [--version N]` | 写 `<dir>/<site>.sitebundle.pb`、`<dir>/<site>.sitebundle.json`（protojson，只供人看）与 `<dir>/artifacts/<sha256>` | — | G2 |
| `mgctl bundle sign --in <pb> --key <kid>.key.age --out <file.bundle>` | 签名（§3.2 的签名输入） | `bundle.sign` | G2 |
| `mgctl bundle verify --in <file.bundle> --pub <kid>.pub… [--site <id>] [--json]` | 验签、解码、打印摘要 | — | G2 |
| `mgctl bundle publish --in <file.bundle> --artifacts <dir> --dest <dir> --pub <kid>.pub… --confirm <site>` | 验签后发布到目录（§12.1）；版本必须大于目标目录中已有的版本 | `bundle.publish` | G2 |
| `mgctl audit verify [--audit-log <path>]` | 校验哈希链；打印条数与最后的 hash；断链时报出行号 | — | G2 |
| `mgctl cf audit --site-config <site.yaml> [flags]` | §14.3 | — | G3 |
| `mgctl cf ips sync --out <file> [flags]` | §14.4 | `cf.ips.sync` | G3 |
| `mgctl crawler sync --registry <src.yaml> --out <file> [--previous <file>]` | §14.5 | `crawler.sync` | G3 |

- 退出码：`0` 成功；`1` 输入无效或检查失败；`2` 用法错误 / 尚未实现；`3` I/O 或内部错误（含审计追加失败）。
- 写文件一律先写临时文件再 `rename`；不覆盖已有密钥文件。
- 环境变量：`MGCTL_PASSPHRASE_FILE`、`MGCTL_AGE_WORK_FACTOR`、`MGCTL_AUDIT_LOG`、`CLOUDFLARE_API_TOKEN`、`MGCTL_CF_API_BASE`（缺省 `https://api.cloudflare.com/client/v4`，测试指向 httptest）。
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
func GenerateSiteKeys(site string, date time.Time, rnd io.Reader) (tokenJSON, sealJSON []byte, err error)
func RotateTokenKey(tokenJSON []byte, date time.Time, rnd io.Reader) (newJSON []byte, newKID string, err error)
func GeneratePseudoKey(date time.Time, rnd io.Reader) ([]byte, error)
func GenerateUpstreamKeys(previous []byte, now time.Time, rnd io.Reader) ([]byte, error)
func ReadPassphrase(env cli.Env, confirm bool) ([]byte, error)

// internal/bundle
type BuildOptions struct { Version uint64; Now time.Time; MaxCost uint64 }
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

- 状态：`pass`、`fail`、`warn`（warning / info 级失败）、`manual`、`skip`。退出码：任一 error 级为 `fail`（或 `--strict` 下为 `manual`）→ 1，否则 0。
- 入口规则集返回 404 视为"没有规则"。API 权限不足（403）时对应检查为 `manual` 并在明细中写出缺少的权限。
- 输出：人读表格（`#`、`id`、级别、状态、明细）；`--json` 输出 `{"zone","plan","checks":[{"n","id","level","status","detail"}],"errors":N}`。套餐由 `GET /zones?name=<zone>` 的 `plan.legacy_id` 判断。
- 测试：`internal/cfapi` 与 `internal/cfaudit` 的测试全部用 `httptest` 伪造 API（夹具在 `control-plane/testdata/cloudflare/<scenario>/`），至少覆盖"全绿"、每个 error 级检查各自失败、403 → manual、404 入口规则集。

### 14.4 `mgctl cf ips sync`（WP-G3）

`GET https://api.cloudflare.com/client/v4/ips`（无需认证；`--url` 覆盖，只接受 https）→ 要求 `success == true`，取 `result.ipv4_cidrs`、`ipv6_cidrs`、`etag` → §12.2 校验 → 与 `--previous`（缺省为 `--out` 的现有文件）比较：`etag` 相同 → 不改工件；条数变化超过 30% → 拒绝（退出码 1），除非 `--accept-change`；否则原子写 `--out`。无论是否变化，成功时写 `<out>.state.json`（`{"v":1,"last_success":"<RFC 3339>","etag":"…"}`）并更新 `--metrics-textfile`。有变化时写审计。只有内容变化才改变工件字节，所以配置包里的工件哈希不会因每日同步而变化。

### 14.5 `mgctl crawler sync`（WP-G3）

读源文件（§12.3），逐个抓取 `ip_ranges[*].url`（https，至多 3 次同为 https 的重定向，响应 ≤ 16 MiB，超时 30 s），按 `format` 解析并校验，合并去重后写工件。某个运营方抓取失败时：若 `--previous` 工件中有该运营方，沿用其 `cidrs` 并标记 `stale: true`、打印警告；否则整个命令失败（退出码 1）。测试用 `httptest.NewTLSServer`。

## 15. 工作包说明

每个 WP 的"完成定义"都包含 §2.4 的全部条目，下面只列各自特有的内容。

### WP-R1 mg-core 与 IR 转换

- **所有权**：§2.2。
- **输入**：§3.4、§3.5、§4、§5；`testdata/policy-ir/`（WP-G1 产出，合入前可先用自己写的少量 IR 用例开发）。
- **输出**：§5.6 的全部公共 API；`phase1_detectors()`；`ScorerV1`；`derive_bot_class`；`SitePolicy`；`gcra_check`；`ua::parse`；`proto/rust/src/ir.rs`；`decision.proto` 改动与重新生成的 `decision.pb.go`。
- **测试**：每个检测器的正反例与 MISSING / ABSENT 分支；评分公式（族封顶、shadow、`h_min`、verdict 只升不降、硬规则下限、置信度 κ 与分母）用手算的固定用例；BotClass 优先级；矩阵每一格（含 `matrix.satisfied`、`require_clearance`、爬虫策略）；规则引擎（阶段顺序、优先级、dry_run 不终止、LOG / TAG 累积、过期、rollout 分桶的确定性与大致比例、hits 上限）；`gcra_check` 的边界（burst、只检查不保存、时钟倒退、`now < dvt` 时的饱和减法、`u64` 边界）并导出一组用例表供 WP-E1 与 Lua 对照；IR 加载的各项上限与非法 IR；一致性套件全部通过；`make wasm-check` 在 CI 通过（mg-core 不得引入新依赖）。
- **完成**：`DecisionCore` 能对一个手工构造的 `RequestContext` + `RequestExtras` 端到端给出 `Evaluation`。

### WP-R2 mg-challenge

- **输入**：§6、`kat.json`、`mg_core::SealedChallengeClaims`（含 `ipa`）。
- **输出**：§6.7 的 API。
- **测试**：§6.8。
- **完成**：Edge 需要的全部密码学操作都能用 `mg-challenge` 的公共 API 完成，调用方不需要直接使用 pasetors / chacha20poly1305。

### WP-R3 mg-intel

- **输入**：§7、§12.2–§12.4。
- **输出**：§7.6 的 API；`intel/testdata/mmdb/*.mmdb` 与生成器。
- **测试**：§7.7。

### WP-G1 策略编译器与一致性套件

- **所有权**：`control-plane/internal/policy/**`、`control-plane/testdata/policies/**`、`testdata/policy-ir/**`。
- **输出**：
  - `IRVersion = 1`；`func Lower(cr *CheckedRule) (*morphgatev1.PolicyExpr, error)`；`(*CheckedRule).Proto()` 填 `ExprIr`（确定性字节）与 `IrVersion`；`CompiledRuleJSON` 增加 `expr_ir`（标准 base64）；`Compiler.Check` 对 §5.2 的构造报错（在 `walk` 中完成，错误定位到子表达式）。
  - `Input` 增加 `identity.crawler.claimed` 与全部 `json` 标签；`availability.go` 按 §4.4 更新。
  - 参考求值器：`func (e *Evaluator) EvalWithMissing(cr *CheckedRule, in *Input, missing []string) (Result, error)`，`type Result int`（`ResultFalse`、`ResultTrue`、`ResultUnknown`、`ResultError`），语义按 §5.3 最后一段；现有 `Eval` 保留（等价于没有 MISSING）。
  - `testdata/policy-ir/cases.json` 与生成的 `cases.ir.json`（§5.8）。
- **测试**：`TestIRConformance`；拒绝构造的诊断信息；`all-fields.yaml`、`cloudflare-site.yaml`、`docs06-examples.yaml` 全部能降级为 IR；`&&` / `||` 展平；IR 字节在两次运行之间相同。
- **完成**：`mgctl policy compile` 输出每条规则的 `expr_ir`；`make go-check` 中的一致性检查全绿。

### WP-G2 mgctl 运维

- **所有权**：§2.2。
- **输入**：§8.2、§8.3、§12.1、§12.6–§12.8、§14.1、§14.2；`policy` 包的现有公共 API。
- **输出**：§14.2 的包；`mgctl` 新命令与帮助文本；`go.mod` 增加 `filippo.io/age`、`golang.org/x/term`；`control-plane/testdata/sites/` 下的有效 / 无效站点 YAML 夹具；`control-plane/README.md` 更新。
- **测试**：站点 YAML 的每条校验规则；构建结果的确定性（同样输入同样字节，`--version` 固定时）；默认路由追加；规则排序与过滤（disabled / 过期）；工件哈希与复制；签名输入的域前缀（与 `kat.json` 的 `bundle_signature.domain_prefix_hex` 一致）；Go 签名 → Go 验签；错误密钥 / 篡改字节 / 未知 kid 被拒；age 加密往返（`MGCTL_AGE_WORK_FACTOR=10`）；错误口令；发布的版本单调与先工件后配置包；审计日志追加、链校验、篡改任一字节可定位到行；`--confirm` 不符被拒；审计失败时退出码 3。
- **跨语言验证**：WP-G2 在 `control-plane/testdata/sites/golden/` 提交一个由固定测试密钥（种子写在测试里，仅供测试）签名的 `golden.bundle` 与其 `.pub`；WP-E1 的测试用它验证 Rust 端验签与解码。

### WP-G3 Cloudflare 与情报同步

- **所有权**：§2.2。不改 `go.mod`（只用标准库与已有依赖）。
- **输入**：§12.2、§12.3、§13.7、§14.3–§14.5；08 §2.10、§2.11。
- **输出**：`internal/cfapi`、重写的 `internal/cfaudit`（保留 `RunCLI` 签名）、`internal/intelsync`（替换桩）；`deploy/intel/crawler-registry.yaml`；`control-plane/testdata/cloudflare/**` 与 `control-plane/testdata/intel/**` 夹具。
- **测试**：§14.3 所列；IP 段同步的 etag 不变、变化、超 30% 被拒、非法 CIDR、私有地址段；爬虫同步的两种格式、重定向、超大响应、单个运营方失败沿用旧值与无旧值时失败。

### WP-W1 Web SDK

- **所有权**：`sdk/web/**`。
- **输入**：§10.2、§10.3、§11、`kat.json`。
- **输出**：`src/challenge.ts`、`src/sha256.ts`、`src/pow.ts`（Worker 协议与搜索）、`scripts/build-dist.mjs`、`templates/challenge.html`；`SDK_VERSION = "0.1.0-phase1"`；README 更新。
- **测试**：§11.5。
- **完成**：`dist/sdk/` 可直接作为 Edge 的 `[sdk] dir`。

### WP-E1 mg-edge 集成（阶段 2）

- **所有权**：§2.2。
- **输入**：阶段 1 全部产出与本文 §8.1、§9、§10、§13。
- **输出**：§9.1 的模块；`edge.toml` v1 与更新后的样例 / 冒烟脚本 / systemd 单元；`Makefile`、`ci.yml` 中 Valkey 测试所需的改动（§16）；根 `Cargo.toml` 的 mg-edge 依赖（§1.2）。
- **建议的内部里程碑**（同一 WP 内顺序完成，每个都保持 `make check` 绿）：① 配置与凭证、监听器与上游认证、头部清洗；② 配置包加载与 bootstrap；③ 路由、RequestContext、Decision Core 接线、monitor 模式、源站头；④ 挑战签发、`/__mg/s`、`/__mg/c`；⑤ Valkey 状态层与限速；⑥ 事件与指标；⑦ 爬虫验证与 rDNS。
- **测试**（`edge/tests/`，全部只用回环地址）：
  - `upstream_trust.rs`：头族剥离（含下划线变体）、密钥头、非回环对端、`CF-Connecting-IP` 缺失 / 非法 / 外部 zone Worker、Tier 1 标记、`MG-*` 双向剥离、XFF 单值。
  - `bundle_load.rs`：`file://` 与本地 HTTP 服务器（手写 `TcpListener`，支持 ETag / 304）；WP-G2 的 `golden.bundle`；坏签名、未知 kid、版本回退、同版本不同字节、hosts 不符、工件哈希不符、`not_before`；LKG 重启恢复；bootstrap 模式。
  - `challenge_flow.rs`：GET → 403 挑战页（CSP、nonce、占位符已替换、无 `{{`）；JSON Challenge；用 `mg_challenge::pow_solve` 解题后表单提交 → 303 + Cookie → 带 Cookie 的请求放行且 `MG-Session` 存在；重放同一提交 → 403；篡改 C、换 UA、换 Host、超长正文、`Content-Encoding`、`Early-Data` → 各自结果；失败配额 → 429。
  - `ratelimit_valkey.rs`：Lua 与 `mg_core::gcra_check` 在同一用例表上逐项一致（显式 `now_us`）；管线往返次数（用 `MONITOR` 或计数包装验证每请求 ≤ 1 次往返）；Valkey 被杀后本地回退与熔断恢复；nonce `SET NX`。
  - `events_sink.rs`：本地伪 VictoriaLogs（手写 HTTP 服务器）收到的查询参数、Content-Type、行格式与信封字段；队列满时的丢弃计数；文件出口；`XADD` 字段。
  - `crawler.rs`：`StaticResolver` 配置下的 `ip_ranges` 同步失败、`rdns` 首请求 pending 与后续结论。
  - `metrics.rs`：§13.7 的指标名与标签出现在 `/metrics` 中。
  - `smoke.rs` 与 `shipped_configs.rs` 更新为 v1 配置。
- **完成**：`make check` 与 CI（含 Valkey 服务容器）全绿；`scripts/edge-smoke.sh` 用 v1 配置（本地文件配置包、local 状态模式）通过。

### WP-L1 Validation Lab（阶段 3）

- **所有权**：`lab/**`、`scripts/lab-e2e.sh`、阶段 3 的 `Makefile` 与 `ci.yml`。
- **replay 扩展**（`lab/internal/replay`）：请求级字段 `delay_ms`（0–10000，发送前等待）、`expect_status_in`（列表）、`expect_header`（头名 → 期望子串）、`expect_header_absent`（头名列表）、`expect_cookie_absent`（Cookie 名列表，检查响应的 `Set-Cookie`）、`expect_body_contains`；场景级 `vars`（在 `path`、头值、正文中替换 `${name}`，值来自 `-var name=value` 命令行参数，供 e2e 脚本注入端口等）。仍不生成载荷、不变异、不并发；目标仍经 `guard`。
- **场景**（`lab/testdata/scenarios/`，请求只发往 `127.0.0.1`）：
  - `phase1-impersonator.yaml`：以 `CF-Connecting-IP`（模拟 Cloudflare 回环隧道，对象是本地 Edge）声称 Googlebot / GPTBot 但来自不在官方段的文档地址；`ip_ranges` 运营方从第一个请求起 403；`rdns` 运营方第一个请求为非 403（`DECLARED_AGENT`），`delay_ms` 之后的请求全部 403；另有来自注册表官方段（测试注册表中的文档地址段）的真爬虫请求放行。
  - `phase1-nonjs-clearance.yaml`：对 `require_clearance` 路由的 GET → 403 且无 `__Host-mg_clr`；提交一个录制好的过期 / 伪造 C → 403 且无 Cookie；再次 GET → 仍 403。场景只回放固定请求，不包含任何求解逻辑。
- **e2e 脚本** `scripts/lab-e2e.sh`：临时目录中生成测试密钥（`MGCTL_PASSPHRASE_FILE`、`MGCTL_AGE_WORK_FACTOR=10`）、站点密钥与假名化密钥；用 `lab/testdata/e2e/` 的站点 YAML、测试注册表（CIDR 为文档地址段）与 `StaticResolver` JSON 构建、签名、发布配置包（`monitor_only: false`，enforce）；启动 `valkey-server`（或 `MG_TEST_VALKEY_URL`）、python 源站、mg-edge（`events.file` 出口）；运行两个场景；再从事件文件断言：冒充请求的 `risk.bot_class == "impersonator"` 占比 100%（按 D-22 计），非 JS 场景没有任何 `feedback.outcome == "pass"`。全部只用回环地址；缺少依赖时给出明确的跳过信息。
- **Makefile / CI**：新增 `make lab-e2e`（不进 `make check`）；CI 新增 `lab-e2e` 作业（Valkey 服务容器或安装 `valkey-server`，Node + pnpm 构建 SDK）。
- **完成**：本地与 CI 的 `lab-e2e` 通过；`lab/README.md` 更新。

### WP-J1 JA4 预研（阶段 3）

- **所有权**：`edge/**` 中为预研所需的增量改动（新增 `edge/src/tls/`、`direct_tls` 监听器的 `ja4 = true` 配置项、`edge/tests/ja4_spike.rs`），以及 `docs/adr/0002-edge-pingora-boringssl.md`。
- **做法**：ADR-0002 决策 4 的链路——在 `TlsSettings`（`DerefMut` 到 `SslAcceptorBuilder`）上设置 BoringSSL select-certificate 回调，取 `ClientHello::as_bytes()`；用自研解析器（对照 huginn-net-tls 或 FoxIO JA4 规范的测试向量；不引入 pcap / pnet 依赖）计算 JA4；写入 SSL ex_data；`TlsAccept::handshake_complete_callback` 返回 `Arc<Ja4>` 进入 `SslDigest.extension`；请求过滤器读出并填 `ctx.tls.ja4 = {value, source: self, authenticated: true}`。策略与评分侧继续按 D-07 视为 MISSING（只进事件，便于 shadow 观察）。
- **测试**：用 boring 客户端以固定参数握手，断言事件中的 JA4 等于手算值；会话恢复与 HTTP/2 下的行为记录在测试注释中；回调中的分配与耗时测量（criterion 不必，普通计时测试记录数量级）。
- **输出**：ADR-0002 勘误段落（日期、结论：链路是否可行、每握手开销、限制与后续建议），状态保持"已接受"。

### WP-D1 文档勘误（阶段 3）

把 §0.3 中"需改设计文档"为"是"的决定写回设计文档与 ADR（ADR-0005 勘误：Ed25519 实现、`ipa`、凭证 claims 与 kid 格式；02 §7 / §8：键哈希、`mg:ev` 字段、`MG-Tags`；03：verdict 只升不降、矩阵抑制；04 §4.2：PoW 实现；05 §7.2：验证模式；06 §1 / §2 / §5 / §8：规则顺序、阶段性 MISSING、指标标签与新增指标、`pseudo` 密钥；08 §1.5：监听器与站点配置的划分；10：把 Phase 1 实现的威胁条目状态改为"Phase 1 实现"并注明测试名）；更新根 README 的索引（链接本文）与 CLAUDE.md 的命令表（`make lab-e2e`）。`make docs-check` 必须通过。

## 16. 测试策略与 CI

| 层 | 做法 |
|---|---|
| 单元测试 | 每个 crate / 包内；纯函数优先；解析器随机输入测试（§2.4） |
| 已知答案向量 | `testdata/phase1/kat.json`：Rust（WP-R2、WP-E1 的实体键）与 TypeScript（WP-W1 的 PoW）读同一个文件 |
| 跨语言一致性 | `testdata/policy-ir/`：Go 生成并校验 IR 字节与 cel-go 结果，Rust 求值同一批用例 |
| 跨语言签名 | WP-G2 的 `golden.bundle` 由 Rust 验签 |
| Edge 集成测试 | `edge/tests/`，回环地址，真实 mg-edge 二进制或进程内服务 |
| Valkey | 测试辅助 `edge/tests/common/valkey.rs`：有 `MG_TEST_VALKEY_URL` 时连接它（用随机站点 id 做键前缀，从不 `FLUSHALL`）；否则 PATH 中有 `valkey-server`（或 `redis-server`）时在随机空闲端口启动（`--save "" --appendonly no --bind 127.0.0.1`），测试结束时终止；都没有则打印 `SKIPPED: no valkey-server (set MG_TEST_VALKEY_URL or install valkey)` 并跳过。`MG_REQUIRE_VALKEY=1` 时跳过改为失败 |
| CI | WP-E1 在 `rust` 作业中加入 Valkey 服务容器（`valkey/valkey:9.1.2-alpine`，按 digest 固定）并设置 `MG_TEST_VALKEY_URL`、`MG_REQUIRE_VALKEY=1`；WP-L1 新增 `lab-e2e` 作业。`make check` 不依赖 Docker |
| 不做 | 负载生成、对任何非回环 / 非白名单目标的请求；Lab 场景中的求解逻辑 |

附加延迟的验收不做压测：以生产（或所有者自有 staging）的 `mg_edge_added_latency_seconds` p99 为准（§17）；开发期可以用 `cargo test` 中的计时测试观察 Decision Core 的数量级。

## 17. 所有者运维手册（代码之外）

1. **Cloudflare 侧**：确认套餐（07"仍待确认"）；关闭 Bot Fight Mode（Free）；部署 Tier 0 Transform Rule（`adapters/cloudflare/transform-rule.request-headers.json`；启用上游密钥头时加一条 `set x-mg-upstream-key` 静态值，值取 `upstream-keys.json` 的 `values[0]`）；开启 "Add visitor location headers"、确认 "Remove visitor IP headers" 关闭；部署 `/__mg/` Skip 规则与放在最后的 Cache Bypass 规则；保持 0-RTT、Pseudo IPv4 关闭；Rocket Loader 关闭或保留 `data-cfasync`。
2. **大脑 VM**：Valkey（`maxmemory-policy noeviction`、ACL 用户 `edge` 只允许 `GET SET MGET EVALSHA SCRIPT PING XADD TIME` 与 `mg:*` 键模式、禁止写 `mg:rev:*` 与 `PUBLISH`，实测 ACL 规则）；VictoriaLogs `vl-main` / `vl-short`、VictoriaMetrics（`-retentionPeriod=13`）；静态文件服务器（`/srv/mg/`，只绑定 WireGuard）。
3. **所有者工作站**：`mgctl keys gen`、`keys gen-pseudo`、`keys gen-upstream`、每个站点 `site keys gen`；用 MaxMind 账号下载 GeoLite2-ASN / Country；`mgctl cf ips sync`、`mgctl crawler sync`（定时任务每日运行）；写站点 YAML 与策略；`bundle build → sign → publish`；两步 rsync 到大脑 VM。
4. **Edge 主机**：cloudflared 隧道指向 `127.0.0.1:8080`；用 `systemd-creds encrypt` 封装 `token.keys.json`、`seal.root.json`、`pseudo.key.json`、`upstream-keys.json`、Valkey 口令，在单元中 `LoadCredentialEncrypted=`；复制 SDK 目录（`sdk/web/dist/sdk/`）；写 `edge.toml` v1；`mg-edge --check-config`；启动。
5. **monitor 周**：站点 YAML `monitor_only: true` 连续运行 ≥ 7 天；每日看 vmui：`mg_edge_added_latency_seconds` p99 < 5 ms、`mg_cf_connecting_ip_missing_total` 与 `bad_secret_header` 为 0、`mg_upstream_signal_missing_total` 缺失率、`mg_config_age_seconds`、`mg_event_dropped_total`；在 VictoriaLogs 中按路由统计"本应"的挑战 / 阻断比例，校准 θ_c、z0 与权重（改站点 YAML 发新版本）。
6. **真人浏览回归**：主流浏览器（含移动端）手工浏览关键路径；把一个测试路由临时设为 `require_clearance` 并在 enforce 下确认挑战页能自动通过、跳回原页面、Cookie 生效；自有 E2E（若有）通过。
7. **收尾**：`mgctl cf audit --site-config … --vm-url … --cf-ips …` 全绿（`manual` 项逐一 `--ack`）；`mgctl audit verify` 通过。

## 18. 验收映射

| 07 Phase 1 验收项 | 证据 | 谁 |
|---|---|---|
| 自有站点经 Cloudflare 以 monitor 模式连续运行 ≥ 1 周 | §17 第 5 步；`mg_config_version` 与请求计数的时间序列 | 所有者 |
| 附加延迟 p99 < 5 ms | `mg_edge_added_latency_seconds` 的 p99（生产 / 自有 staging） | 所有者（指标由 WP-E1 提供） |
| 冒充爬虫 100% 识别 | `make lab-e2e` 的 `phase1-impersonator` 场景与事件断言（D-22） | WP-L1 |
| 不执行 JS 的脚本客户端在 enforce 下拿不到凭证 | `make lab-e2e` 的 `phase1-nonjs-clearance` 场景；`edge/tests/challenge_flow.rs` | WP-L1、WP-E1 |
| `mgctl cf audit` 全绿 | §17 第 7 步 | 所有者（工具由 WP-G3 提供） |
| 真人浏览回归无功能破坏 | §17 第 6 步 | 所有者 |
| JA4 预研结论写入 ADR-0002 | ADR-0002 勘误 | WP-J1 |

## 19. 待实测与未决

| 项 | 影响 | 处理 |
|---|---|---|
| `cf.tls_ciphers_sha1` 与 `cf.tls_client_ciphers_sha1` 哪个拼写有效；HTTP/3 与会话恢复时 `cf.tls_*` 是否有值 | EDGE_TLS 缺失告警的噪声 | monitor 周观察 `mg_upstream_signal_missing_total{signal}`；`cf audit` 两种拼写都接受 |
| Tunnel 下 `CF-Connecting-IP` 等头是否到达 | 客户端 IP | monitor 周首日确认 `mg_cf_connecting_ip_missing_total` 为 0 |
| `GET /zones/{z}/bot_management` 在各套餐下的字段（BFM、SBFM、AI bot） | `cf audit` 9 / 10 / 16 | 字段缺失时 `manual`，所有者确认后 `--ack` |
| Valkey ACL 规则能否精确限制 Edge 用户 | VK-02 | §17 第 2 步实测后写入 WP-D1 的文档更新 |
| Pingora 能否取得 `direct_tls` 的 SNI | `tls.sni` | WP-E1 取不到时留空；WP-J1 的回调可以顺带取得 |
| 挑战页在 Cloudflare 之后 403 + `no-store` 是否被缓存 | CH-09 | monitor 周用 `cf-cache-status` 抽查（应为 `DYNAMIC` / `BYPASS`） |
