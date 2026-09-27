# ADR-0001：技术栈采用 Rust 数据面 + Go 控制面

- 状态：已接受
- 日期：2026-09-27
- 相关：[01 整体架构](../01-architecture.md)、[07 分阶段路线](../07-roadmap.md)、[ADR-0002](0002-edge-pingora-boringssl.md)、[ADR-0006](0006-policy-cel-ir.md)

## 背景

- 数据面对每个请求内联执行，目标附加延迟 p99 < 5 ms；无 CDN 时（`direct_tls`）需要在 TLS 握手阶段拿到原始 ClientHello 计算 JA4。
- 控制面以配置管理、策略编译与签名、Cloudflare API 集成、近线 worker 为主，对延迟不敏感。
- 策略语言采用 CEL。成熟的类型检查器在 cel-go（v0.30.0）；Rust 侧 `cel` crate 没有同等的类型检查器（见 ADR-0006）。
- 平台仅所有者自用，单人开发与维护，语言与工具链数量需要控制。

## 决策

| 部分 | 语言 | 位置 | 说明 |
|---|---|---|---|
| Decision Core | Rust | `core/`（mg-core） | 纯函数内核，无 I/O，可编译到 wasm32 |
| Edge | Rust | `edge/`（mg-edge） | Pingora 薄适配层，唯一依赖 Pingora 的 crate |
| 控制面 | Go | `control-plane/`（cmd/mg-control、cmd/mgctl） | 配置、策略编译、签名配置包、Cloudflare 集成 |
| 近线 worker | Go | `control-plane/` | 消费 Valkey Stream，回写 verdict |
| Web SDK | TypeScript | `sdk/web/` | 无感 / 交互式 Challenge、会话密钥、遥测 |
| 共享契约 | Protobuf | `proto/` | RequestContext、Decision、DecisionEvent、配置包 |

- 两种语言之间只通过 protobuf 契约与签名配置包交互，不共享运行时代码。
- 策略语义只有一份：Go 侧编译为 IR，Rust 侧只求值 IR（ADR-0006）。
- Mobile SDK 不在当前范围，按需再定。

## 备选方案

| 方案 | 优点 | 不采用的原因 |
|---|---|---|
| 全部 Go | 单语言、开发快 | 数据面有 GC 停顿；没有可深度控制 TLS 回调的同类代理框架，`direct_tls` 下 JA4 需要自建 TLS 层或多一跳代理 |
| 全部 Rust | 单语言、单工具链 | 没有与 cel-go 对等的 CEL 类型检查器；控制面 CRUD 与云 API 集成的开发成本更高 |
| Envoy + ext_proc + Rust 决策服务 | 代理成熟 | 多一跳、多一个进程与配置面，对单人部署偏重（见 ADR-0002） |

## 后果

- 维护 Cargo 与 Go 两套构建、lint、测试流水线，在 Phase 0 一并建立。
- protobuf 是跨语言边界，字段变更需要兼容性检查（只增字段、不改编号）。
- Decision Core 的纯函数约束让单元测试、事件回放与模糊测试可以脱离网络运行。
- 单人需要同时维护 Rust 与 Go 代码；控制面刻意保持小（单一所有者，见 ADR-0010）。

## 参考

- https://proxy.golang.org/github.com/google/cel-go/@latest
- https://github.com/cel-rust/cel-rust
