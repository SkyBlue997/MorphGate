# 架构决策记录（ADR）

记录影响整体结构、难以回退的决策。格式沿用 Michael Nygard 的 ADR：标题、状态、日期、背景、决策、备选方案、后果。设计细节写在 docs/01–10（索引见 [README](../../README.md)），ADR 只记录"为什么这样选"以及代价。

## 索引

| 编号 | 标题 | 状态 | 日期 | 相关文档 |
|---|---|---|---|---|
| [0001](0001-tech-stack-rust-go.md) | 技术栈：Rust 数据面 + Go 控制面 | 已接受 | 2026-09-27 | [01](../01-architecture.md)、[07](../07-roadmap.md) |
| [0002](0002-edge-pingora-boringssl.md) | Edge 基于 Pingora 0.9 + BoringSSL，内核与适配层分离 | 已接受 | 2026-09-27（2026-09-28 勘误） | [01](../01-architecture.md)、[08](../08-upstream-and-cloudflare.md) |
| [0003](0003-upstream-profile-cdn-first.md) | 以 UpstreamProfile 描述上游，Cloudflare 优先 | 已接受 | 2026-09-27（2026-09-28 勘误） | [08](../08-upstream-and-cloudflare.md)、[03](../03-risk-scoring.md) |
| [0004](0004-origin-protection-tunnel-aop.md) | 源站保护：Cloudflare Tunnel 优先，AOP（自有 CA）备选 | 已接受 | 2026-09-27（2026-09-28 勘误） | [08](../08-upstream-and-cloudflare.md)、[10](../10-threat-model.md) |
| [0005](0005-token-and-sealed-challenge-format.md) | 凭证用 PASETO v4，密封 Challenge 用 protobuf（prost）编码 + XChaCha20-Poly1305 | 已接受 | 2026-09-27（2026-09-28 勘误） | [04](../04-challenge-and-tokens.md)、[09](../09-interactive-challenge.md) |
| [0006](0006-policy-cel-ir.md) | 策略语言：CEL 语法，控制面编译为 IR，数据面只求值 IR | 已接受 | 2026-09-27（2026-09-28 勘误） | [06](../06-policy-console-observability.md) |
| [0007](0007-lean-deployment.md) | 精简部署：不用 Kafka / K8s，Valkey Streams + VictoriaLogs，Edge 拉取配置 | 已接受 | 2026-09-27（2026-09-28 勘误） | [01](../01-architecture.md)、[02](../02-data-flow.md)、[07](../07-roadmap.md) |
| [0008](0008-interactive-challenge-self-built.md) | 交互式 Challenge 自研（按住验证）+ 可插拔 Provider，Turnstile 仅用于非大陆访客 | 已接受 | 2026-09-27（2026-09-28 勘误） | [09](../09-interactive-challenge.md)、[04](../04-challenge-and-tokens.md) |
| [0009](0009-ja4-only-licensing.md) | 只使用 JA4，JA4+ 放在默认关闭的 Cargo feature `ja4plus` 之后 | 已接受 | 2026-09-27 | [01](../01-architecture.md)、[03](../03-risk-scoring.md) |
| [0010](0010-single-owner-model.md) | 单一所有者模型与个人版密钥保管 | 已接受 | 2026-09-27（2026-09-28 勘误） | [01](../01-architecture.md)、[05](../05-ai-agent-policy.md)、[06](../06-policy-console-observability.md)、[10](../10-threat-model.md) |

## 约定

- 文件名 `NNNN-kebab-case.md`，编号递增、不复用。
- 状态取值：提议 / 已接受 / 已废弃 / 已被 ADR-NNNN 取代。
- 已接受的 ADR 不改写结论；推翻时新写一条 ADR，并把旧 ADR 的状态改为"已被 ADR-NNNN 取代"。可以补充勘误或把"待定"项定稿，但要在日期行注明修订日期与依据。
- 勘误写在 ADR 末尾（"参考"之前）的"## 勘误（YYYY-MM-DD，…）"小节，只记与实现不同的做法，细节链接到实现规格；索引的日期列同步注明勘误日期。Phase 1 的勘误以 [Phase 1 实现规格](../impl/phase1-spec.md) 为依据（D-xx 与集成者裁决 I-xx）。
- 事实性表述（版本、限额、价格、头名）注明来源与核实日期；未核实的写"需实测 / 需确认"。引用外部来源时在末尾加"参考"小节。
- 新增或变更 ADR 时，同步更新本索引与相关设计文档。
- 只记录防御设计，不描述绕过任何第三方防护的方法。

## 模板

````markdown
# ADR-NNNN：<决策标题，一句话写清选了什么>

- 状态：提议
- 日期：YYYY-MM-DD
- 相关：[NN 文档](../NN-xxx.md)、[ADR-NNNN](NNNN-xxx.md)

## 背景

- 需要解决的问题、约束（预算、单人维护、上游形态）与已知事实（附来源）。

## 决策

1. 选定的方案，写到可执行的粒度（版本、边界、默认值）。
2. 明确"不做"的部分。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| ... | ... |

## 后果

- 正面与负面影响、新增的约束、需要实测或后续决策的事项。

## 参考

- 用到的官方 URL。
````
