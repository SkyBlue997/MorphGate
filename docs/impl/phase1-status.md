# Phase 1 进度记录

**更新时间**：2026-10-12
**分支**：Phase 1 已通过 [PR #1](https://github.com/SkyBlue997/MorphGate/pull/1) 合并至 `master`（合并提交 `30e3963`）；远程历史分支为 `phase-1/edge-behind-cloudflare`。2026-10-07 公开前重写过一次提交历史（只去掉提交说明中的尾注，文件树不变），之前记录的提交号都已失效，本文件中的提交号均为重写后的。
**状态**：Stage 1–3 与 Phase 1 之后的增补（I-36..I-42）完成；所有者站点自 2026-09-28 起以 monitor 模式运行，下一步是按规范 §17、§18 完成验收。

## 1. 总体进度

| 阶段 | 内容 | 状态 | 提交 |
|---|---|---|---|
| Phase 0 | 设计文档、ADR、monorepo 骨架 | 完成 | `bdc66c2` |
| Phase 1 规范 | [phase1-spec.md](phase1-spec.md)（含集成者裁决 I-1..I-35） | 完成 | `a7a6fa0` … `88104ea` |
| Stage 1 | 11 个并行 WP：mg-core、mg-challenge、mg-intel、mg-edge-core（C1–C4）、Go 编译器 / mgctl / Cloudflare 与情报同步、Web SDK | 完成，逐个对抗验证 | `ef6e21d` |
| Stage 2 | WP-CLEANUP（I-20..I-27）、WP-E1a 骨架、E1b 决策接线、E1c Challenge 端点、E1d 事件与指标；最终安全审查与本机端到端 | 完成，逐个对抗验证 | `e6ab232` |
| 审查后修复 | I-29 额外删除客户端 IP / URL 改写 / 方法覆盖类请求头；I-30 重放未校验时签发的凭证（`ruc`）不被 fail_closed 路由接受；I-31 延迟指标按 `kind` 拆分；I-32 无 `env` 时不写 telemetry；测试端口竞争修复 | 完成 | `35c6853` |
| Stage 3 | WP-L1（Lab 验收场景、`mglab events`、`scripts/lab-e2e.sh`、`make lab-e2e`、CI `lab-e2e` 作业）、WP-J1（`direct_tls` JA4 预研，ADR-0002 勘误）、WP-D1（设计文档勘误，含 I-8..I-32 的同步）；集成：裁决 I-33..I-35（接受阶段 2 的执行层细化、补齐正文未列的字段与接口、接受两项已知限制），`edge.toml.example` 的 AOP `client_ca` 注释改为所有者自有 CA 并加 `ja4_spike` 说明，07 / 01 / 04 / 09 / 10 / ADR-0005 与 JA4 结论对齐 | 完成 | `1c6bf64` |
| Phase 1 之后 | 裁决 I-36：路由级 `mode: monitor \| enforce`（`Route.mode`；Go 构建器、`mgctl bundle verify` 与审计、Edge 执行层；多路径视图取最严；站点 monitor 且有 enforce 路由时超限请求按 enforce 拒绝） | 完成 | PR #4 |
| Phase 1 之后 | 裁决 I-37：路由级 `never_challenge`（`Route.never_challenge`；只允许 low / medium 且不 `require_clearance` 的路由；多路径视图取"与"；CHALLENGE 只记录，BLOCK / RATE_LIMIT 照常；Go 构建器、`mgctl bundle verify` 与审计、Edge 执行层） | 完成 | PR #6 |
| Phase 1 之后 | 裁决 I-38：Edge → 源站认证头 `MG-Origin-Auth`（edge.toml `[[sites]] origin_keys`，`mg-origin-keys` 密钥文件；HMAC-SHA256 覆盖时间戳、方法、请求目标与 MG-* 头，60 秒时间窗；`mgctl keys gen-origin`；`adapters/origin` 源站参考校验；`kat.json` `origin_auth` 向量） | 完成 | PR #7 |
| Phase 1 之后 | 裁决 I-39：fetch 被挑战后的验证入口 `GET /__mg/v?ret=`（按导航到 `ret` 决策；阻断、限速照常，其余一律 `pow` 挑战，`rule_id = edge.verify`；`ret` 解码后按 §6.4 校验，无效时用 `fallback_ret`；SDK `MorphGate.fetch()` / `verify()` / `verifyUrl()`，每个页面路径 60 秒只跳一次；Lab 无 JS 场景加一步） | 完成 | PR #8 |
| Phase 1 之后 | 裁决 I-40：源站头 `MG-Client-IP-Prefix`（IPv4 `/32`、IPv6 所在 `/64`，未知时 `unknown`；列入 `MG-Origin-Auth` 签名，`kat.json` 增加 IPv6 向量） | 完成 | PR #9 |
| Phase 1 之后 | 构建提交号：`mg-edge --version` 输出 `0.1.0 (<12 位提交号>)`，启动日志与 `mg_edge_info{commit}` 相同（`edge/build.rs`；没有 Git 检出时为 `unknown`，可用 `MG_EDGE_COMMIT` 指定） | 完成 | PR #9 |
| Phase 1 之后 | 运维文档：单机形态（本机 Valkey + `local_replay_authoritative`，没有 VictoriaMetrics 时 `cf audit` 第 18 项用 `/metrics` 快照判定，01 §8）；mg-edge 日志写入独立的 journald 命名空间 `morphgate`，保留 14 天（`deploy/systemd/journald@morphgate.conf`） | 完成 | PR #10 |
| Phase 1 之后 | Lab 验收用例：`phase1-route-modes.yaml`（`mode: monitor` 路由与 `never_challenge` 路由只记录挑战并转发，阻断照常；客户端伪造的源站头被替换）；`lab-e2e` 的源站改用 `adapters/origin/` 参考实现校验 `MG-Origin-Auth`，绕过 Edge 的未签名与伪造请求 401 | 完成 | PR #11 |
| Phase 1 之后 | 依赖审计：`deny.toml` 与 `.github/workflows/audit.yml`（cargo-deny、govulncheck、`pnpm audit`；每个 PR 与每周）、`make audit`；首轮发现已处理：SDK 构建依赖 source-map-js 升到 1.2.2（GHSA-68fv-2mgg-jv7q，只影响构建工具）；yoke-derive 0.8.3 已撤回，升到 0.8.4；derivative 无人维护（RUSTSEC-2024-0388，只有固定版本的 pingora-core 用到，记入 `deny.toml` 的 ignore）；Go 1.25 已停止维护，govulncheck 报 9 个标准库漏洞，Go 升到 1.27 | 完成 | PR #12 |
| Phase 1 之后 | 裁决 I-41：`mg-edge.service` 的 `ExecReload=` 第一行改为不读凭据的 `mg-edge --version`（systemd 255 不给第一行凭据，`--check-config` 在第一行必然失败，reload 做不成），并加 `RefreshOnReload=credentials`；轮换后凭据何时生效按 systemd 版本写进单元注释与 §17 | 完成，已在 systemd 255 的真实主机上验证 reload | PR #13 |
| Phase 1 之后 | 裁决 I-42：`mg_upstream_signal_missing_total` 改为与 `mg_requests_total` 同口径（只计到达决策步骤的请求），`/__mg/*` 请求和提前应答的请求不再推高缺失率；`cf audit` 只读 token 的权限名实测后写入 `adapters/cloudflare/README.md`，`managed_headers` 的提示改为 Bot Management Read（真实站点反馈） | 完成 | PR #14 |
| Phase 1 之后 | 覆盖率引导的模糊测试：`fuzz/`（cargo-fuzz，8 个目标：Cloudflare 头、请求限制与主机解析、配置包验签、密封 Challenge、凭证与 Cookie、路径视图与 `ret`、ClientHello / JA4、Challenge 提交；种子在 `fuzz/seeds/`）、`make fuzz`、`.github/workflows/fuzz.yml`（每天，以及改动解析器的 PR）；`edge-core` 的 `testkit::upstream` 抽出 Cloudflare 头不变式供随机输入测试与 cargo-fuzz 共用 | 完成 | PR #15 |
| Phase 1 之后 | Web SDK `0.2.0-preview.1`（含 I-39 的 `MorphGate.fetch()` / `verify()` / `verifyUrl()`；需要 `710beea` 及之后的 Edge），npm `preview` 与 `latest` 分发标签 | 完成 | PR #16 |

## 2. 当前代码状态

Stage 3 集成验证（2026-09-28，本机 macOS arm64，共享 `target/`）：

| 检查 | 结果 |
|---|---|
| `MG_REQUIRE_VALKEY=1 make check` | 通过：Rust 916 个测试通过、0 失败、1 个忽略（`proxy_env_child`，子进程辅助）；Go（control-plane、lab）；Web SDK 203；适配器 21；compose；文档链接。`wasm-check` 本机跳过（Homebrew rustc 无 wasm32 目标），CI 运行 |
| `make edge-smoke` | 通过（含 daemon 模式） |
| `make lab-e2e` | 连续两次通过（自启 `valkey-server`，unix socket）；另以 `MG_TEST_VALKEY_URL`（回环 TCP 上的同一实例）+ `MG_LAB_E2E_REQUIRE=1` + `MG_EDGE_BIN` 连续两次通过，并用 `cargo build --release --locked -p mg-edge` 的发布二进制与 pnpm 构建的 SDK 再通过一次（与 CI 作业相同的路径；`target/release` 事后已删除）。每次：已定结果的冒充请求 13/13 为 `impersonator`（100%，5 个 rDNS 热身请求按 D-22 排除）、6 个真爬虫请求已验证；4 次挑战提交 0 次成功、3 条 feedback 无 `pass`、受保护路由 5 个请求 0 个转发 |
| `make proto` | 生成结果与提交一致（`gen-proto.sh --check` 通过） |
| `cargo fmt --all --check`、`scripts/check_doc_links.py` | 通过 |
| actionlint v1.7.12（`.github/workflows/ci.yml`） | 0 个问题（本机没有 shellcheck，`run` 脚本未经 shellcheck 检查） |
| `ja4_spike` | 缺省关闭（`config::tests`）；非 `direct_tls` 监听器上 `--check-config` 退出 2；未开启的 `direct_tls` 监听器照常握手且事件中没有 JA4（`edge/tests/ja4_spike.rs`、`edge/tests/tls.rs`） |

远端验证：合并提交 `30e3963e8963d3b8a77e9cb1b024ae9035306d2f`（重写前为 `6395330`，文件树相同，CI 运行页显示的是重写前的提交号）的 [CI run 37568198825](https://github.com/SkyBlue997/MorphGate/actions/runs/37568198825) 已全部通过，包括 Rust fmt / clippy / test / wasm / edge smoke、MSRV 1.88、Go 与生成代码、Web SDK、Compose 与 Lab 网络隔离、文档脚本，以及依赖 Rust release 二进制和新构建 SDK 的 Lab 端到端作业。上表测试数量是 2026-09-28 的本机记录；远端各次运行以其日志为准。

## 3. 验收状态与下一步

| 验收项（规范 §18） | 状态 | 谁 |
|---|---|---|
| 冒充爬虫 100% 识别 | 本机证明：`make lab-e2e` 的 `phase1-impersonator` 与 `mglab events impersonator` | WP-L1（完成） |
| 不执行 JS 的脚本客户端在 enforce 下拿不到凭证 | 本机证明：`phase1-nonjs-clearance` 与 `mglab events clearance`；`edge/tests/challenge_flow.rs` | WP-L1、WP-E1c（完成） |
| JA4 预研结论写入 ADR-0002 | 完成：链路可行、默认关闭、每握手约 0.5 µs，不以原始 JA4 做 `bind.tfp` 硬绑定 | WP-J1（完成） |
| monitor 模式经 Cloudflare 连续运行 ≥ 1 周 | 运行中：所有者站点自 2026-09-28 起经 Cloudflare Tunnel 以 monitor 模式运行（已超过 1 周），已更新到最新版；待核对该期间的指标 | 所有者（§17 第 6 步） |
| 附加延迟 p99 < 5 ms（`kind="site"`，I-31） | 指标已提供，待生产 / staging 数据 | 所有者 |
| `mgctl cf audit` 全绿 | 工具已实现，待真实 zone | 所有者（§17 第 8 步） |
| 真人浏览回归无功能破坏 | 未开始 | 所有者（§17 第 7 步） |

下一步是所有者的运行步骤（规范 §17 运行手册）：核对 monitor 期间的指标（附加延迟 p99、信号缺失率、`bad_secret_header`、外部 Worker 等应为 0 的计数）、浏览器回归、`cf audit` 全绿，之后再讨论切到 enforce。远端 CI 的 `lab-e2e` 作业已通过；它使用回环测试环境，不替代真实站点验收。

## 4. 已知的低优先级遗留

- Pingora 自己生成的 400 响应带 `Server: Pingora`、不带 `nosniff`（Pingora 0.9 行为）。
- 无法解析的请求目标以 `reason="bad_method"` 计数；目标中的 `#` 以有损 UTF-8 重建。
- `mg_cf_ip_filter_active` 在配置包切换后要到下一个连接才刷新；代理回环检查不识别通配地址绑定。
- rDNS 过期作业的结果仍会写入缓存（I-26 只约束在途标记）。
- 遥测 schema 在 `edge/src/submission.rs` 与 `edge-core` 中各有一份实现（边界一致），Phase 2 合并。
- 决策事件中 `token.replay_unchecked` 只出现在采样后的决策事件上。
- I-35：选中路由之前的应答不做 `redact_path` 改写；关闭信号之后完成的请求的事件计为 `sink="buffer"` 丢弃（Phase 2 复审）。
- JA4（`ja4_spike`）只进按 `allow_sample_rate` 采样的决定事件，访问记录不带；shadow 观察期需调高采样率或先改规范（ADR-0002 勘误）。
- Lab 没有持久的运行记录（10 LAB-06 部分实现）。

## 5. 环境注意事项

- 磁盘空间：所有 cargo 工作只用仓库内共享的 `target/`，不要为并行 agent 单独设构建目录（曾因此写满磁盘）。
- 本机用 Homebrew 安装了 `valkey`（测试自行启动实例）；Docker 守护进程未运行。
- 测试 TLS 证书与私钥（`edge/tests/fixtures/tls/`，仅回环名，`gen.sh` 可重新生成）与测试密钥材料（`testdata/phase1/keys/`）是有意提交的测试数据，不保护任何东西。

## 6. 仍待所有者确认

- 各 Cloudflare zone 的套餐（Free / Pro），Bot Fight Mode 当前是否开启。
- 站点是否备案、源站所在区域。
- 站点是否有登录（决定无障碍替代路径）；是否有站点产生收入（决定能否启用 JA4+）。
- 真实 zone 上的实测项（规范 §19）：访客自带的 `CF-Worker` 头是否被 Cloudflare 删除；Cloudflare 如何透传源站的 414 / 431 / 425；`cf.tls_*` 字段在各套餐的可用性。
- 首次 `mgctl crawler sync` 前，核对 `deploy/intel/crawler-registry.yaml` 中官方 IP 段 URL 与 UA 标识。
