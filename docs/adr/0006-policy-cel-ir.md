# ADR-0006：策略语言采用 CEL 语法，控制面编译为 IR，数据面只求值 IR

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：MISSING 求值语义、签名密钥位置）
- 相关：[06 策略引擎、后台与审计](../06-policy-console-observability.md)、[ADR-0001](0001-tech-stack-rust-go.md)、[ADR-0003](0003-upstream-profile-cdn-first.md)、[ADR-0010](0010-single-owner-model.md)

## 背景

- 策略需要：非图灵完备、可静态类型检查、可估算执行代价，并能在编译期检查字段在站点的 UpstreamProfile 下是否可用（例如 `cloudflare` profile 下 `tls.ja4` 为 MISSING）。
- cel-go 最新 v0.30.0（2026-07-25），具备解析、类型检查与代价估算。
- Rust 侧 `cel` crate（0.14.5，MIT；原 `cel-interpreter` 止于 0.10.0）自述为解析器与解释器，没有与 cel-go 对等的类型检查器；其一致性测试的忽略列表约 1,149 行，说明大量 cel-spec 用例仍被跳过。
- 若控制面与数据面各自解析 CEL，两份实现会产生语义漂移。

## 决策

1. 策略写成 CEL 表达式，策略文件纳入版本管理；Console 后期再提供编辑器。
2. `mgctl`（Go，cel-go v0.30）负责：解析 → 按 MorphGate 字段模式做类型检查 → 代价估算 → 按站点 UpstreamProfile 检查字段可用性 → 编译为受限 IR（protobuf AST）→ 打包并用 Ed25519 签名。签名密钥为所有者的一对 Ed25519 密钥（`kid` 轮换，年更）：Phase 1 由 mgctl 在工作站签名（私钥 age 加密），Phase 3 起移到大脑 VM 的 mg-control（保管方式见 ADR-0010）。
3. mg-core 内置自研 Rust IR 求值器；热路径**不使用** `cel` crate。
4. Phase 1 的 `mgctl` 与 Phase 3 的控制面服务复用同一编译器，语义只有一个来源。
5. **MISSING 语义**：读取 MISSING 字段的比较表达式结果为"未知"；`expr` 最终为未知时规则整体按不匹配处理，并在 dry-run 日志中记为 `missing_input`；策略可用 `has(x)` 判断字段是否可用。"未知"在 `&&` / `||` 中的吸收规则、ABSENT 的零值语义与字段表见 [06 §2](../06-policy-console-observability.md#2-策略语言)。
6. 扩展函数（`ip_in`、`list`、`glob` 等）在 cel-go 中声明签名，在 Rust 求值器中实现，两边用同一组用例测试。
7. 一致性：维护"表达式 + 输入 + 期望结果"的黄金用例（含 MISSING 输入），CI 中同时用 cel-go 与 Rust IR 求值器执行，结果必须一致。
8. IR 求值设代价上限，超出上限的策略编译失败。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| 数据面直接用 `cel` crate 解释 CEL | 无类型检查器，一致性测试大量跳过，重新引入双实现漂移 |
| 自定义 YAML / JSON 匹配 DSL | 组合条件的表达力不足，最终会长成一门临时语言 |
| Rego（OPA） | 表达力超出需要，数据面需要额外嵌入运行时 |
| Lua / WASM 插件 | 图灵完备，难以静态估算代价与审计 |

## 后果

- 需要自行实现并维护 IR 求值器与黄金用例；IR 算子集合刻意保持小。
- cel-go 版本固定，升级时重跑黄金用例。
- 新增字段需同时更新字段模式（含各 profile 下的可用性）与 Rust 侧 RequestContext 映射。
- 签名策略包是 Edge 拉取的配置包的一部分（ADR-0007），Edge 验签后原子替换。

## 参考

- https://proxy.golang.org/github.com/google/cel-go/@latest
- https://github.com/cel-rust/cel-rust
