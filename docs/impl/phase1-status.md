# Phase 1 进度与暂停记录

**暂停时间**：2026-09-28（所有者要求暂停）
**分支**：`phase-1/edge-behind-cloudflare`，最后一次提交 `fc6b4d1`
**工作区**：约 98 个未提交路径（60 个已跟踪文件修改、38 个新文件），内容是 stage 2 进行中的工作，**尚未提交**。

## 1. 总体进度

| 阶段 | 内容 | 状态 | 提交 |
|---|---|---|---|
| Phase 0 | 设计文档、ADR、monorepo 骨架 | 完成 | `2a4bc27` |
| Phase 1 规范 | [phase1-spec.md](phase1-spec.md)（含集成者裁决 I-1..I-28） | 完成 | `3ee5b2d` `c430062` `b7c910d` `fc6b4d1` |
| Stage 1 | 11 个并行 WP：mg-core、mg-challenge、mg-intel、mg-edge-core（C1–C4）、Go 编译器 / mgctl / Cloudflare 与情报同步、Web SDK | 完成并逐个对抗验证；`make check` 通过（669 个 Rust 测试、245 个 IR 一致性用例） | `7e2fbee` |
| Stage 2 · WP-CLEANUP | 裁决 I-20..I-24、I-26、I-27（计算 map 拒绝、ip_in 用例、rDNS 后缀标签边界、限速器 id 全站唯一、路由上限、RdnsJob 序号、审计预检） | 完成 + 已验证 | 未提交 |
| Stage 2 · WP-E1a | Edge 骨架：edge.toml v1 与 `--check-config`、后台服务运行模型、上游信任接线、站点状态机（含 I-3 / I-4）、多视图路由匹配、monitor / bootstrap 转发、配置包 → 运行时转换、systemd、CI（Valkey 服务容器、msrv 任务） | 完成 + 已验证 | 未提交 |
| Stage 2 · WP-E1b | 决策接线：RequestContext / Activation / MissingSet、凭证校验、爬虫验证 + rDNS 服务、Valkey 状态与限速、verdict、DecisionCore + SitePolicy、阻断 / 429、Valkey ACL 测试 | 完成 + 已验证 | 未提交 |
| Stage 2 · WP-E1c | Challenge 端点 | **进行中（第二次尝试被暂停打断）** | 未提交 |
| Stage 2 · WP-E1d | 事件与指标、I-25 输出解耦 | 未开始 | — |
| Stage 2 · 最终审查 | 整条请求路径安全审查、`make check`、本机端到端 | 未开始 | — |
| Stage 3 | WP-L1（Lab 验收场景 + e2e）、WP-J1（direct_tls JA4 预研）、WP-D1（设计文档勘误） | 未开始 | — |

## 2. 暂停时的代码状态

- `cargo check --workspace --all-targets`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`：**通过**。
- **暂停后没有重新运行测试**。第一次 E1c 尝试中断后跑过一次 `make check`，当时因格式与一个未使用的常量失败；这两处之后已消失，但完整测试结果未知。
- E1c 的半成品主要在 `edge/src/challenge.rs`、`submission.rs`、`sdk.rs`、`pages.rs`、`enforce.rs`（`edge/src/` 下其他新文件多属 E1a / E1b）。续做前先看 `git status` 与 `git diff`，保留正确部分再补完。

## 3. 续做时 WP-E1c 需要完成的内容

按规范 §15 与交接记录：C 的签发（难度规则、客户端 IP 未知 → 429、http 访客 GET/HEAD → 308）、挑战页与 CSP、`/__mg/s/*` 静态 SDK、完整的 `POST /__mg/c` 流程（请求体规则、`mg_nonce_issue` 签发配额、重放检查与 fail_closed 判定、失败升级 `RiskBand::after_failure`、失败计数），以及裁决 I-28（表单 `+` 解码、`env` 可选字段为 `null`、build 全零合法、SDK 模板校验与 `validateTemplate` 一致）。E1b 留下的接入点：`EdgeResponse::for_enforcement` 中 `Enforcement::Challenge` 目前返回占位的 `challenge_required`（详见 [stage2-handoff.md](stage2-handoff.md)）。

之后依次：WP-E1d（事件组装、全部指标、日志内容测试、daemon 冒烟、I-25）→ 最终安全审查与本机端到端 → Stage 3。

## 4. 如何继续

**同一个 Claude Code 会话内**：恢复原工作流，已完成的步骤从缓存返回，从 E1c 继续：

```
Workflow({scriptPath: "/Users/bluesky/.claude/projects/-private-tmp-claude-501--Users-bluesky-MorphGate-11ae85ad-3285-4143-b175-07fa46e2f2c7/11ae85ad-3285-4143-b175-07fa46e2f2c7/workflows/scripts/morphgate-phase1-stage2-wf_05f72d24-e3b.js", resumeFromRunId: "wf_05f72d24-e3b"})
```

**新会话**（工作流恢复只在原会话有效）：让 Claude 读取本文件、[phase1-spec.md](phase1-spec.md) 的"集成者裁决"表与 [stage2-handoff.md](stage2-handoff.md)，从 WP-E1c 继续（保留工作区已有的半成品），然后执行 E1d、最终审查、提交，再进入 Stage 3。

## 5. 环境注意事项

- **磁盘空间紧张**：系统盘约剩 22 GB。第一次暂停前，各 agent 使用独立的 Rust 构建目录，占用 40 GB 把磁盘写满（ENOSPC），导致进行中的 agent 中断。以后只使用仓库内共享的 `target/`，不要为并行 agent 单独设构建目录；构建前先看 `df -h /`。
- 本机已用 Homebrew 安装 `valkey`（测试自行启动实例，未注册为系统服务）；Docker 守护进程未运行；wasm32 检查只在 CI 中真正执行；MSRV 1.88 检查只在 CI 中执行。
- 中断的另一个原因是会话用量上限，大型工作流可能再次触发。

## 6. 仍待所有者确认

- 各 Cloudflare zone 的套餐（Free / Pro），Bot Fight Mode 当前是否开启。
- 站点是否备案、源站所在区域。
- 站点是否有登录（决定无障碍替代路径）。
- 是否有站点产生收入（决定能否启用 JA4+）。
- 需在真实 zone 上实测的项（规范 §19）：普通访客自带的 `CF-Worker` 头是否被 Cloudflare 删除；Cloudflare 如何透传源站的 414 / 431 / 425；`cf.tls_*` 字段在各套餐的可用性等。
