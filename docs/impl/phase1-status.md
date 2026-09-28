# Phase 1 进度记录

**更新时间**：2026-09-28
**分支**：`phase-1/edge-behind-cloudflare`（尚未合并到 `master`，没有远端）
**状态**：Stage 1、Stage 2 完成并已提交；下一步是 Stage 3。

## 1. 总体进度

| 阶段 | 内容 | 状态 | 提交 |
|---|---|---|---|
| Phase 0 | 设计文档、ADR、monorepo 骨架 | 完成 | `2a4bc27` |
| Phase 1 规范 | [phase1-spec.md](phase1-spec.md)（含集成者裁决 I-1..I-32） | 完成 | `3ee5b2d` … `230db47` |
| Stage 1 | 11 个并行 WP：mg-core、mg-challenge、mg-intel、mg-edge-core（C1–C4）、Go 编译器 / mgctl / Cloudflare 与情报同步、Web SDK | 完成，逐个对抗验证 | `7e2fbee` |
| Stage 2 | WP-CLEANUP（I-20..I-27）、WP-E1a 骨架、E1b 决策接线、E1c Challenge 端点、E1d 事件与指标；最终安全审查与本机端到端 | 完成，逐个对抗验证 | `12f52ba` |
| 审查后修复 | I-29 额外删除客户端 IP / URL 改写 / 方法覆盖类请求头；I-30 重放未校验时签发的凭证（`ruc`）不被 fail_closed 路由接受；I-31 延迟指标按 `kind` 拆分；I-32 无 `env` 时不写 telemetry；测试端口竞争修复 | 完成 | 见本次提交 |
| Stage 3 | WP-L1（Lab 验收场景 + e2e + CI 任务）、WP-J1（direct_tls JA4 预研）、WP-D1（设计文档勘误，含 I-8..I-32 的同步） | **未开始** | — |

## 2. 当前代码状态

- `MG_REQUIRE_VALKEY=1 make check` 通过：888 个 Rust 测试、Go（control-plane、lab）、Web SDK 203 个测试、适配器测试、compose 与文档链接检查；`make edge-smoke` 通过（含 daemon 模式）。
- 本机端到端（最终审查，均在本机回环地址）：bootstrap / enforce / monitor 三种模式、挑战页与 JSON 挑战、无 JS 客户端拿不到凭证、完整 PoW 求解流程与 Cookie、冒充爬虫阻断与已验证爬虫放行（IP 段与 rDNS）、路由与 `/__mg` 编码绕过探测、超长输入（enforce 拒绝 / monitor 转发）、外部 `CF-Worker`、Valkey 中途停止（fail_closed 路由 429）、日志中无客户端 IP / 凭证 / C。
- 只在 CI 中验证：wasm32 检查、MSRV 1.88、Valkey 服务容器镜像摘要、`lab-egress-check`（需要 Docker）。

## 3. 下一步：Stage 3

- **WP-L1**：Lab Phase 1 场景（冒充爬虫 100% 识别、不执行 JS 的客户端在 enforce 下拿不到凭证、外部 CF-Worker）、`scripts/lab-e2e.sh`、`make lab-e2e`、CI 任务（复用 mg-edge 二进制产物）。注意 rDNS 模式爬虫首个请求处于 pending，验收只统计已定结果的请求（规范 D-36 / 交接记录）。
- **WP-J1**：`direct_tls` 的 JA4 预研（BoringSSL 回调 → 自研 JA4 解析 → 请求上下文），结论写入 ADR-0002 勘误。
- **WP-D1**：设计文档勘误：把规范中标为需要同步的 D 条目与裁决 I-8..I-32 写回 docs/01–10 与 ADR（清单见 [stage2-handoff.md](stage2-handoff.md) 与各 WP 报告）。

之后是所有者的运行步骤（规范 §17 运行手册、§18 验收）：在真实 Cloudflare zone 上配置规则、monitor 模式运行 ≥ 1 周、浏览器回归。

## 4. 已知的低优先级遗留

- Pingora 自己生成的 400 响应带 `Server: Pingora`、不带 `nosniff`（Pingora 0.9 行为）。
- 无法解析的请求目标以 `reason="bad_method"` 计数；目标中的 `#` 以有损 UTF-8 重建。
- `mg_cf_ip_filter_active` 在配置包切换后要到下一个连接才刷新；代理回环检查不识别通配地址绑定。
- rDNS 过期作业的结果仍会写入缓存（I-26 只约束在途标记）。
- 遥测 schema 在 `edge/src/submission.rs` 与 `edge-core` 中各有一份实现（边界一致），Phase 2 合并。
- 决策事件中 `token.replay_unchecked` 只出现在采样后的决策事件上。

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
