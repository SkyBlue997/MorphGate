# ADR-0006：策略语言采用 CEL 语法，控制面编译为 IR，数据面只求值 IR

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：MISSING 求值语义、签名密钥位置）；2026-09-28 Phase 1 勘误（决策 2、6、7、8 的落地方式，见文末"勘误"，依据 [Phase 1 实现规格](../impl/phase1-spec.md) D-02、D-19、D-26 与裁决 I-8、I-9、I-19、I-20、I-21）
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

## 勘误（2026-09-28，Phase 1 实现）

结论不变；下表记录决策在 Phase 1 中的具体落地方式与相对原文的修正。逐项契约见 [Phase 1 实现规格 §5](../impl/phase1-spec.md#5-策略-ir求值语义与规则引擎)。

| 决策 | Phase 1 落地 | 依据 |
|---|---|---|
| 8：代价上限 | 不在运行时按"超限判不命中"处理（攻击者加长输入即可让阻断规则失效），改为**静态步数上界**：编译器按策略输入的硬上限（路径、查询串各 ≤ 8 KiB，头值 ≤ 8 KiB，至多 128 个头名等）算出每条规则的最坏步数 `max_steps` 并写入 IR（`PolicyExpr.max_steps`），超过 100,000 编译失败；Edge 加载时复算，不相等或超限即拒绝整个配置包。Edge 在求值之前拒绝超出上限的请求（enforce 下 414 / 431 / 400；monitor 与 bootstrap 下跳过求值原样转发），所以上界总成立；运行时计步只是断言（超出 → `step_limit` 错误，计 `mg_policy_step_limit_total`，正确实现中不可达）。路由匹配不经过 IR 求值器 | D-26、I-2 |
| 8：结构上限 | IR 节点 ≤ 4096、嵌套深度 ≤ 50、字符串字面量 ≤ 4096 字节、列表字面量 ≤ 1000 项，编译器与 Edge 都检查。深度原定 64：Edge 用 prost 解码 IR，其固定递归上限为 100 层消息，根以下每个节点占两层，深于 50 的树根本无法解码 | I-8 |
| 2：代价估算 | cel-go 自己的代价估算保留为附加检查，规范以步数上界为准；cel-go 对 `contains()`、`glob()` 的估算改用同一步数公式，避免拒绝步数上界之内的规则 | 规格 §5.2 |
| 2：编译为受限 IR | IR 是 `proto/morphgate/v1/policy_ir.proto` 中 17 种节点的 protobuf AST，不含表达式 id、源码位置与类型：同一个已检查的表达式总得到同一串字节。线格式到原生结构的转换放在 `mg-proto`，`mg-core` 不依赖 prost、保持 wasm32 可编译 | D-02 |
| 2：拒绝的构造 | 错误级，消息 `unsupported in policy IR: <what>`：算术、字符串拼接、`matches`、宏与推导式、类型转换、时间类型、map 与消息字面量、列表下标、元素类型不一致的列表（cel-go 须开 `HomogeneousAggregateLiterals`，否则 `1 in [1.0, "a"]` 为 true，与 Rust 语义不一致）、跨类型数值比较、对 map 键用 `has()`、可选语法，以及对 `?:` 计算出的 map 取下标（`(c ? m1 : m2)[k]` 改写为 `c ? m1[k] : m2[k]`，这样步数上界与"错误优先于未知"的语义都没有歧义） | 规格 §5.1、§5.2；I-20 |
| 6：扩展函数 | `ip_in`：左侧不是合法 IP（含带 zone 的）→ `false`，不校验条目；否则逐项校验全部条目，任一非法（含前缀 < 96 的 IPv4 映射 CIDR）→ `invalid_argument` 错误，即使前面已匹配；字面量中的非法条目编译失败。`list()` 的参数与 `glob()` 的模式必须是字面量；`glob` 按 Unicode 标量、区分大小写，`*` 不跨 `/`、`**` 跨 `/` | I-9、I-21 |
| 7：一致性 | `testdata/policy-ir/cases.json`（手写，含 MISSING 上下文）与 Go 生成的 `cases.ir.json`（逐字节比较 IR 与 `max_steps`）；Go 参考求值器用 cel-go 部分求值实现 MISSING 语义，Rust 求值同一批用例，另断言实际步数不超过 `max_steps`。2026-09-28 共 316 个用例，其中 253 个编译出 IR、其余为编译失败用例 | 规格 §5.8 |
| 规则顺序 | 阶段 `identity < protocol < rate_limit < bot < custom < default`；阶段内 `priority` 大者先，同优先级按 `id` 字节序；`disabled` 与已过期的规则不进配置包 | D-19 |
| 分阶段的构造 | `tarpit` 动作与 Phase 2 的挑战类型由 `mgctl policy check` 照常接受，由 `mgctl bundle build` 与 Edge 加载时拒绝；`params.type: interactive` 在 Phase 1 按 `pow` 执行，编译器告警 | D-08、D-09、I-19 |

## 参考

- https://proxy.golang.org/github.com/google/cel-go/@latest
- https://github.com/cel-rust/cel-rust
