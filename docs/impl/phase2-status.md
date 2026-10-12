# Phase 2 进度记录

**更新时间**：2026-10-12
**分支**：每个工作包一个 PR，合入 `master`（PR #19–#43 已合入）；本文件由 WP-D2 的 PR #40 添加，之后的小 PR 补记了 WP-L2 的合入、修复与最后的裁决。
**状态**：规格、契约落地、阶段 1（7 个 WP）与阶段 2（E2a → E2b → E2c）已合入；阶段 3 的 Validation Lab 场景与近线端到端（WP-L2，PR #39）已合入，设计文档勘误（WP-D2，PR #40）已合入。代码侧的 Phase 2 功能全部关闭在配置之后：`schema_version = 1` 的配置包让新二进制严格按 Phase 1 运行（D-66）。下一步是所有者按 [规格 §19](phase2-spec.md#19-所有者运维手册代码之外) 逐步启用。

## 0. 给所有者的摘要

**已经就绪的**
- Edge 0.2.0、SDK 0.3.0、`mgctl` 与新的近线 worker `mg-nearline`，以及它们的测试、cargo-fuzz 目标、systemd 单元、告警规则（`deploy/vmalert/mg-phase2.rules.yml`）与每日检查脚本（`scripts/mg-daily-check.sh`）。
- 功能：自研交互式验证（按住、单次激活、自动验证 `pow_a11y`）、会话密钥与持有证明 `MG-Proof`、凭证 v2 与可选的静默刷新、`/__mg/t` 遥测、路由的 `proof` 与 `min_level`、可选的 Turnstile（大陆访客也可以选用，失败自动回退）、近线检测器 v1、本机应急开关 `force_monitor`。
- 升级二进制本身不改变线上行为：配置包保持 `schema_version = 1` 时，Edge 严格按 Phase 1 运行。
- 文档：设计文档 01–10 与 ADR 的 Phase 2 勘误、威胁模型 v1、[ADR-0011](../adr/0011-local-emergency-monitor-switch.md)（本机应急开关）、[隐私说明模板](../privacy-notice-template.md)。

**需要你按顺序做的**（[规格 §19](phase2-spec.md#19-所有者运维手册代码之外)，每一步确认无误再进行下一步）
1. **第 0 步**：完成 Phase 1 验收（monitor 期指标、附加延迟、`cf audit` 全绿、浏览器回归）。
2. **第 1a、1b 步**：单机改用本机 Valkey（只监听回环或 unix socket，`noeviction`，两个 ACL 用户），观察 24 小时内存后设 `maxmemory`，再打开 `events.stream`。
3. **第 2 步**：按隐私说明模板更新站点的隐私说明（新的客户端信号上线之前）。
4. **第 3a 步**：换 Edge 与 `mgctl` 二进制，保留 SDK 0.2.x 目录与 `schema_version = 1` 的配置包，确认决策分布不变。
5. **第 3b 步**：站点模板加入 `<script data-cfasync="false" src="/__mg/s/mg.js" defer></script>`；CSP 允许同源脚本与 `worker-src 'self'`；Service Worker 不处理 `/__mg/`；需要证明的接口改用 `MorphGate.fetch`。
6. **第 3c 步**：换 SDK 0.3 目录，站点 YAML 写 `clearance.refresh: false`，让配置包变为 `schema_version = 2`（功能仍全关）；确认源站不再收到 MorphGate 的 Cookie。
7. **第 4 步**：给选定接口设 `proof: required`，先 `mode: monitor` 观察数日再 enforce。
8. **第 5 步**：开启交互式（评分保持 shadow），在微信、QQ、UC、厂商浏览器、Safari、Chrome 上走完四条路径，用读屏软件与仅键盘各完成 ≥ 5 次，再考虑 enforce。
9. **第 6 步**：安装 `mg-nearline`，检测器全部 shadow 至少 7 天，按 ASN 检查误伤后逐个 enforce。
10. **第 7 步**（可选）：Turnstile：创建 widget、`mgctl turnstile secret import`、Provider 先 shadow、在 staging 上用测试 sitekey 手工核对、CSP Report-Only 核对。
11. **第 8 步**：配置告警（vmalert 或每日检查脚本），列出启用了交互式的站点。
12. **第 11 步**：开启 GitHub secret scanning 与 push protection；在 npmjs.com 登记 trusted publisher。
13. 出问题时：第 9 步是回滚顺序，第 10 步是应急（`force_monitor` 与换回旧 SDK 目录）。

**仍未决的**（[规格 §21](phase2-spec.md#21-待实测与未决)，都要在你的站点上实测）：Turnstile 的若干服务端行为与大陆访客选用后的实际效果；`cf-mitigated` 的状态码与双重挑战频率；Safari 与隐私窗口的密钥丢失率；禁用 JIT 的设备上 `pow_a11y` 的耗时；低端设备的哈希速率与 PoW 难度缺省值；交互评分的阈值 `T_pass` / `T_block`；微信等内置浏览器的后台定时器；`cf audit` 第 18 项的 RTT 缺失率；`mg:ev` v2 的实际大小与 Valkey 内存；行为摘要是否值得开启；`scanner` 与 `high_rate` 是否误伤监控探针与共享出口。

## 1. 总体进度

| 阶段 | 内容 | 状态 | PR |
|---|---|---|---|
| 规格 | [phase2-spec.md](phase2-spec.md)：12 个 WP、决定 D-38..D-70、全部跨组件契约；三份独立评审（R1 安全与密码学、R2 可实现性、R3 无障碍与运维）的处置；所有者决定 D-70（大陆访客也可以选用 Turnstile） | 完成 | #19 |
| 契约落地 | proto 新字段、`testdata/phase2/` 已知答案向量与样例、`fields.json`、mg-core 新类型、空模块、CI 的 Go 作业加 Valkey 服务 | 完成 | #20 |
| 阶段 1 | 7 个并行 WP：R4、R5、C5、C6、G4、N1、W2（见 §2） | 完成 | #22–#30 |
| 阶段 2 | E2a → E2b → E2c 依次合入 `mg-edge`（见 §2） | 完成 | #32–#37 |
| 裁决 | I-43..I-47（契约落地）、I-48..I-54（阶段 1）、I-55..I-57（阶段 2）、I-58..I-59（阶段 3 与集成修复） | 完成 | #21、#31、#38、#43 |
| 集成修复 | schema 1 的配置包同样标记内置扫描诱饵（I-59，WP-L2 发现） | 完成 | #42 |
| 阶段 3 | WP-L2：Validation Lab 的 Phase 2 场景与近线端到端 | 完成 | #39 |
| 阶段 3 | WP-D2：设计文档勘误、威胁模型 v1、ADR-0011、隐私说明模板、本文件 | 完成 | #40 |
| 所有者运行步骤 | 规格 §19 第 0–11 步 | 未开始 | — |

每个 PR 都在 `master` 规则集要求的全部检查通过后合入。

## 2. 各工作包

| WP | 内容 | PR |
|---|---|---|
| R4 mg-core | `self_hold` / `pow_a11y` Provider；`select_providers`（D-70 的国家规则）与 `turnstile_eligible`；`min_elapsed_ms` 与 `assess_interaction`（硬检查与 shadow 评分）；`next_challenge_after_failure`（D-50）；`refresh_check`（D-47）；`min_level` 与有效挑战类型（D-64）；`identity.proof`、`http.navigation`、`identity.token.bound` / `level_age`；`reads_field`；`Net` 的 `Debug` 不再打印前缀；仍可编译到 wasm32 | #22 |
| R5 mg-challenge | 交互式 C（600 s、`renew_no`、`ui_seed`、`open_for_renew`）、epoch 窗口 605 s、PoW v2、JWK / RFC 7638 指纹 / ES256 验签（`aws-lc-rs`）、提交与续期签名、`MG-Proof` 校验、凭证 v2（`mint_v2`、`mint_refresh`、状态 Cookie）、Turnstile `cData` 与幂等键；`kat.json` 的全部向量 | #23 |
| C6 mg-edge-core outbound | `OutboundHttp` 的唯一实现、siteverify 客户端与 §8.5 的错误映射、重试与旧 secret 重试、熔断与健康状态、回环 mock siteverify（testkit） | #24 |
| G4 Go | 站点 YAML 的 Phase 2 字段与构建器的报错 / 警告、`schema_version` 1 / 2 的判定、`mg-turnstile-keys` 读写、`internal/turnstile` 与 `mgctl turnstile`、Phase 2 golden 配置包、策略一致性用例 | #25、#27 |
| N1 近线 | `mg-nearline`：`mg:ev` v1 / v2 解析、消费组与认领、检测器 v1、`mg_verdict_put`、验收比例、指标、配置校验、systemd 单元；Valkey 客户端 `valkey-go`（I-46） | #26 |
| C5 mg-edge-core state / events / bundle | `mg_nonce_issue` v2 与 `mg_jti` v1（含本地等价实现）、`mg:ev` v2 编码、遥测 schema 的唯一实现、关闭时的事件刷写与遥测队列、配置包 Phase 2 校验、golden 配置包复验 | #28、#29 |
| W2 Web SDK v1 | 会话密钥存储、`MG-Proof`、`MorphGate.fetch` 的就地求解与刷新、`/__mg/t` 上报与可选的行为摘要、交互式控件（四条路径、绑定与续期、Turnstile 加载）、PoW v2 与 Worker 协议、模板 v2、`publish-sdk.yml`（provenance） | #30 |
| E2a mg-edge 交互式 | 配置包 schema 1 / 2、交互式签发与挑战页 v2 / JSON 挑战、`/__mg/c` v2、`/__mg/c/renew`、失败升级、`mg.ix.issue` / `mg.c.renew` / `mg.a11y.issue`、`/__mg/v?min=interactive`、SDK 目录 v1 / v2 与 `/__mg/s/mg.js`；manifest v2 切换（SDK 0.3.0、mg-edge 0.2.0）；cargo-fuzz `mg_proof`、`submission_v2`、`renew`、`ix_telemetry` | #32 |
| E2b mg-edge 证明与观测 | 路由上的 `MG-Proof` 与 `jti`、就地恢复、D-61 Cookie 删除、`force_monitor`（D-60）、`/__mg/r`、`/__mg/t`、`mg:ev` v2 接线、Phase 2 事件与指标、I-35 复审、关闭时的刷写、Edge ACL、告警规则与每日检查脚本；cargo-fuzz `refresh`、`telemetry` | #33、#34、#35 |
| E2c mg-edge Turnstile | Provider 接线、国家判定、CSP、token 重放、后台服务 `mg-outbound`、熔断与自动禁用、`turnstile_keys` 凭证、`[outbound]` 与 `MG_EDGE_TEST_OUTBOUND`；cargo-fuzz `siteverify_response`、`turnstile_keys`；`MgTurnstileDisabled` 告警 | #36、#37 |
| L2 Validation Lab | Phase 2 的否定性场景（交互式挑战页不引用第三方源、`denied_countries` 中的国家不得到 Turnstile、重放 / 篡改 / 未提供的 Provider 一律失败、外部 `CF-Worker` 403）与 `lab-e2e` 中的近线端到端：同一个回环 Edge 上另有一个 `schema_version = 2` 的站点（交互式与 Turnstile，siteverify 为记录每次调用的回环 mock，`deny_countries: [CN]`）；场景 `phase2-challenge-page`、`phase2-submissions`、`phase2-nearline-baits` / `-after`；`mglab events providers` 与 `nearline` | #39 |
| D2 文档 | 01–10 与 ADR-0005 / 0006 / 0007 / 0008 / 0010 的 Phase 2 勘误（2026-10-12）、威胁模型 v1、ADR-0011、隐私说明模板、07 进度表、README 与 CLAUDE.md | #40 |

## 3. 集成者裁决

实现中产生的契约变更以裁决记录在 [规格开头的表中](phase2-spec.md#集成者裁决优先于正文)，它们覆盖正文。各 WP 在 PR 描述中列出的"偏离"都已收进这些裁决，没有未处置的偏离。

| 编号 | 来源 | 要点 |
|---|---|---|
| I-43..I-47 | 契约落地（#20、#21） | 密封 claims 的错误值与"所有 C 都带 PoW"；遥测中 0.1 步长的整数表示；`testdata/phase2` 样例写死的原因码取舍；近线的 Valkey 客户端；`kat.mjs --check` 进 `docs-check` |
| I-48 | R4（#22） | `pow_a11y` 可以不带 `ix`；`min_level` 同样抬高规则与限速器的挑战；Edge 必须按配置包设置 `schema_version`；`reads_field` 等公开接口 |
| I-49 | R5（#23） | `mint_v2` 在不允许 v2 时签发 v1；`htu` 必须以小写 `https://` 开头；规范 base64url |
| I-50 | C6（#24） | siteverify 的重试预算、错误码优先级、不合格响应与熔断的映射 |
| I-51 | G4（#25、#27） | `rotate` 的核对；`refresh_max_pow_s` 的上限；只读 `identity.proof.valid` 的配置包保持 schema 1；Provider 的缺省值 |
| I-52 | C5（#28、#29） | 关闭刷写的信号时机；遥测是第四个事件类别；遥测解析的细则；配置包的补充规则 |
| I-53 | N1（#26） | 滞后与积压的计算；窗口与上报节奏；验收比例的口径；配置的范围 |
| I-54 | W2（#30） | 切换 Provider 时保留子题；密钥轮换的 10 分钟下限；就地恢复需要 `ret`；续期的状态；读屏的等待 |
| I-55 | E2a（#32） | 交互式 nonce 保留约 70 分钟；`.prefix` 限速器 id；`/__mg/v` 的基础类型；失败附 C 同样受 `mg.ix.issue` 约束；`ic.score_block` 的 `Retry-After` |
| I-56 | E2b（#33–#35） | 证明路由上 425 的范围；CORS 预检豁免；就地恢复 C 的归属；路由 R 的求值；结果标签；关闭时的两段等待；告警的站点列表与 Valkey 指标名 |
| I-57 | E2c（#36、#37） | `turnstile_cdata_for`；续期与提交时 `redact_path` 的判定；`ix.turnstile.lang`；没有到达 `mg-outbound` 的校验；`MgTurnstileDisabled` |
| I-58 | L2（#39） | Lab 的 `scanner` 风险 100、按运行区分的消费组、Provider 用例的覆盖范围 |
| I-59 | 集成者（#42） | schema 1 同样标记内置扫描诱饵 |

WP-D2 的偏离：没有改变契约。两处写法需要说明：
- D-70 推翻了 ADR-0008 决策 5（"Turnstile 仅用于非大陆访客"）。它是所有者的决定，ADR-0008 的核心结论不变，所以写成 ADR-0008 的勘误，没有另写取代它的 ADR。
- 威胁模型 v0.9 原计划在 Phase 1 验收之后定稿 v1；v1 改为对应 Phase 2 的代码，Phase 1 验收中的发现按 10 §7 增量修订。

## 4. 验收状态

| 验收项（[规格 §20](phase2-spec.md#20-验收映射)） | 状态 | 谁 |
|---|---|---|
| 重放、拼接、篡改的 C 100% 拒绝 | `edge/tests/interactive_flow.rs` 通过；Lab `make lab-e2e` 的 `phase2-submissions` 场景通过（录制的提交重放两次、篡改与截断的 C、未提供的 Provider 一律失败，没有 Cookie、跳转或新 C） | WP-E2a、WP-L2（完成） |
| 跨客户端提交 100% 拒绝（只对已绑定的 C 声明） | `edge/tests/interactive_flow.rs::replay_splice_tamper_and_cross_client` 通过；同一 ASN 内换 /24 只记软结果（D-41 的已知边界） | WP-E2a（完成） |
| 并发双提交恰好一个进入签发 | 对真实 Valkey 的并发测试通过 | WP-C5、WP-E2a（完成） |
| Turnstile 绑定失败 100% 拒绝；故障时回退且不放行；通过、失败、重复 token 三条路径在 CI 中覆盖 | mock siteverify 用例与 SDK 回退测试通过 | WP-C6、WP-E2c、WP-W2（完成） |
| `denied_countries` 中的国家从不得到 Turnstile；大陆访客的 Turnstile 失败时回退且不计失败 | 选择函数真值表、Edge 与 SDK 测试通过；Lab `phase2-challenge-page` 通过（CN、未知、`XX`、`T1` 与格式错误的国家在页面、JSON 挑战与 `/__mg/v` 上都不得到 Turnstile，US / DE 作正向对照；siteverify mock 没有收到调用） | WP-R4、WP-E2c、WP-W2、WP-L2（完成） |
| 人类被要求交互式挑战的比例 < 0.1% | 指标已提供（`mg_nl_interactive_visitor_share`、`mg_nl_interactive_abandon_share`、`mg_navigations_total`），待 shadow 数据 | 所有者 |
| 按住中位 < 4 s；`pow_a11y` 中位 < 10 s | `kind=feedback` 的 `ix.act_ms` 已提供，待真实设备数据 | 所有者 |
| 只用键盘、用读屏软件都能完成 | SDK 的结构、播报与焦点测试通过；辅助技术实测待所有者 | WP-W2（完成）、所有者 |
| 页面打开 30 分钟后仍能完成，不显示倒计时 | 续期链测试通过；手工验证待所有者 | WP-E2a（完成）、所有者 |
| `self_hold` 页面零第三方请求 | 模板与 CSP 测试通过；Lab `phase2-challenge-page` 通过；浏览器网络面板核对待所有者 | WP-W2、WP-L2（完成）、所有者 |
| 挑战页与 `/__mg/*` 为 `no-store, private` | Edge 测试通过 | WP-E2a（完成） |
| 遥测 ≤ 2 KB，没有原始坐标与按键值 | SDK 与解析器测试、共享样例通过 | WP-W2、WP-C5（完成） |
| 近线事件到 verdict 的 p95 < 10 s | `lab-e2e` 中 shadow 与 enforce 的 verdict 都在触发请求后 ≤ 10 s 出现，enforce 的 verdict 让下一个请求被挑战而不是阻断；生产按 `mg_nl_lag_seconds` 与 `mg_nl_backlog` 待所有者 | WP-N1、WP-L2（完成）、所有者 |
| 附加延迟 p99 < 5 ms（含证明校验） | 待生产或 staging 数据 | 所有者 |
| 升级二进制不改变线上行为 | `schema_version = 1` 的 Edge 测试通过；升级前后比较待所有者（§19 第 3a 步） | WP-E2a、WP-E2b（完成）、所有者 |

## 5. 推迟与已知限制

- 吊销集与 pub/sub 在 Phase 3（D-54）；Phase 2 中近线的 `shared_token` verdict 起软吊销作用。
- `MG-Nonce`、`step_up` 与 `bh` 推迟（D-55）；站点账号替代路径推迟（D-56）；不做 Edge 侧 HTML 注入（D-39）与页内覆盖层（D-57）。
- 交互评分只交付 shadow（D-49）；交互级凭证的人类证据保持 −0.4（D-68）。`self_hold` 的检查除服务端时间窗外都依赖客户端自报的数据，交互级凭证的成本下限只是 PoW 加 1.2–2.5 s 等待（10 CH-15、R-13）。
- 未绑定会话密钥的 C 在同一 ASN 内换 /24 只记软结果（D-41，10 R-14）。
- 本地模式（`[valkey] mode = "local"`）没有近线，reload 后进行中的交互式挑战在 10 分钟内无法续期（D-38）。
- Turnstile 的熔断与禁用状态在进程重启后丢失。
- bootstrap 与 `lkg_invalid` 时没有路由表，早期应答仍记原始路径（I-35 复审的剩余部分）。
- 双 Provider 升级、学习型交互模型、内存困难 PoW、Privacy Pass、`mg:w:*` 与按连接的特征、`bind.tfp`、`bind.ctp` 转软绑定、每日访问记录归档：以后或按需（[规格 §22](phase2-spec.md#22-phase-1-遗留项的处置)）。

## 6. 环境注意事项

- 磁盘空间：所有 cargo 工作只用仓库内共享的 `target/`，不为并行 agent 单独设构建目录。
- 测试与 CI 只访问回环：Turnstile 一律用 `edge-core` testkit 的回环 mock siteverify（D-52），从不访问 `challenges.cloudflare.com`；Validation Lab 不含任何求解逻辑（D-59）。
- `testdata/phase2/` 中的测试密钥与 `mg-turnstile-keys` 样例是有意提交的测试数据，不保护任何东西。
