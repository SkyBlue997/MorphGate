# Phase 1 进度记录

**更新时间**：2026-09-28
**分支**：`phase-1/edge-behind-cloudflare`（尚未合并到 `master`，没有远端）
**状态**：Stage 1–3 完成；下一步是所有者的运行步骤（规范 §17、§18）。

## 1. 总体进度

| 阶段 | 内容 | 状态 | 提交 |
|---|---|---|---|
| Phase 0 | 设计文档、ADR、monorepo 骨架 | 完成 | `2a4bc27` |
| Phase 1 规范 | [phase1-spec.md](phase1-spec.md)（含集成者裁决 I-1..I-35） | 完成 | `3ee5b2d` … `230db47` |
| Stage 1 | 11 个并行 WP：mg-core、mg-challenge、mg-intel、mg-edge-core（C1–C4）、Go 编译器 / mgctl / Cloudflare 与情报同步、Web SDK | 完成，逐个对抗验证 | `7e2fbee` |
| Stage 2 | WP-CLEANUP（I-20..I-27）、WP-E1a 骨架、E1b 决策接线、E1c Challenge 端点、E1d 事件与指标；最终安全审查与本机端到端 | 完成，逐个对抗验证 | `12f52ba` |
| 审查后修复 | I-29 额外删除客户端 IP / URL 改写 / 方法覆盖类请求头；I-30 重放未校验时签发的凭证（`ruc`）不被 fail_closed 路由接受；I-31 延迟指标按 `kind` 拆分；I-32 无 `env` 时不写 telemetry；测试端口竞争修复 | 完成 | `3dbb48e` |
| Stage 3 | WP-L1（Lab 验收场景、`mglab events`、`scripts/lab-e2e.sh`、`make lab-e2e`、CI `lab-e2e` 作业）、WP-J1（`direct_tls` JA4 预研，ADR-0002 勘误）、WP-D1（设计文档勘误，含 I-8..I-32 的同步）；集成：裁决 I-33..I-35（接受阶段 2 的执行层细化、补齐正文未列的字段与接口、接受两项已知限制），`edge.toml.example` 的 AOP `client_ca` 注释改为所有者自有 CA 并加 `ja4_spike` 说明，07 / 01 / 04 / 09 / 10 / ADR-0005 与 JA4 结论对齐 | 完成 | 见本次提交 |

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

只在 CI 中验证：wasm32 检查、MSRV 1.88、Valkey 服务容器、`lab-egress-check`（需要 Docker）、使用 `rust` 作业 release 二进制的 `lab-e2e` 作业（尚无远端，未运行过）。

## 3. 验收状态与下一步

| 验收项（规范 §18） | 状态 | 谁 |
|---|---|---|
| 冒充爬虫 100% 识别 | 本机证明：`make lab-e2e` 的 `phase1-impersonator` 与 `mglab events impersonator` | WP-L1（完成） |
| 不执行 JS 的脚本客户端在 enforce 下拿不到凭证 | 本机证明：`phase1-nonjs-clearance` 与 `mglab events clearance`；`edge/tests/challenge_flow.rs` | WP-L1、WP-E1c（完成） |
| JA4 预研结论写入 ADR-0002 | 完成：链路可行、默认关闭、每握手约 0.5 µs，不以原始 JA4 做 `bind.tfp` 硬绑定 | WP-J1（完成） |
| monitor 模式经 Cloudflare 连续运行 ≥ 1 周 | 未开始 | 所有者（§17 第 6 步） |
| 附加延迟 p99 < 5 ms（`kind="site"`，I-31） | 指标已提供，待生产 / staging 数据 | 所有者 |
| `mgctl cf audit` 全绿 | 工具已实现，待真实 zone | 所有者（§17 第 8 步） |
| 真人浏览回归无功能破坏 | 未开始 | 所有者（§17 第 7 步） |

下一步是所有者的运行步骤（规范 §17 运行手册）：在真实 Cloudflare zone 上配置规则、monitor 模式运行 ≥ 1 周、浏览器回归、`cf audit` 全绿；首次推送后确认 CI 的 `lab-e2e` 作业通过。

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
