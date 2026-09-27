# ADR-0002：Edge 基于 Pingora 0.9 + BoringSSL，内核与适配层分离

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：外部 Provider 实现位置）
- 相关：[01 整体架构](../01-architecture.md)、[08 上游接入与 Cloudflare 集成](../08-upstream-and-cloudflare.md)、[ADR-0001](0001-tech-stack-rust-go.md)、[ADR-0003](0003-upstream-profile-cdn-first.md)

## 背景

- Pingora 最新版 0.9.0（crates.io 2026-09-09，Apache-2.0），仍是 0.x，每个小版本都有破坏性变更。0.9 的例子：`RequestHeader` / `ResponseHeader` 不再实现 `DerefMut`；Prometheus 移到独立的 `pingora-prometheus`；改用 boring-rs 5.x API；默认剥离上游 hop-by-hop 头。MSRV 1.85（pingora-foundations 需 1.88）。
- TLS 后端由 Cargo feature 选择：openssl、boringssl、rustls（README 标为实验性）、s2n，默认不启用。`certificate_callback` 只支持 openssl / boringssl。
- boring 的 select-certificate 回调可取得 `ClientHello::as_bytes()`（原始 ClientHello），足以计算 JA4；openssl crate 的 ClientHello 回调没有列出全部扩展类型的方法。
- 在 Cloudflare 之后，Edge 看到的 ClientHello 来自 Cloudflare 或 cloudflared，JA4 只在 `direct_tls` 下有意义。
- 下游 HTTP/2 基于 h2 crate，不暴露 SETTINGS、WINDOW_UPDATE、PRIORITY 与伪头顺序；HTTP/1 的原始头字节与大小写可以直接读取。
- 将来可能把 Decision Core 放进 Cloudflare Worker：Workers 单线程、无 tokio 网络，强一致状态需要 Durable Objects 而非 KV。

## 决策

1. **版本固定**：Pingora 写精确版本（当前 `=0.9.0`），提交 `Cargo.lock`；只在 0.9.x 补丁之间手动升级，升级到 0.10 作为独立任务，只改 mg-edge。
2. **分层**：
   - `core/`（mg-core）：纯函数 `RequestContext + 快照 -> RiskAssessment + Action`；无 I/O、无 tokio、不引用 Pingora 类型；状态经 trait 访问（限速、nonce、verdict、EventSink）。CI 检查可编译到 `wasm32-unknown-unknown`。
   - `edge/`（mg-edge）：薄适配 crate，负责 Pingora 会话与 RequestContext 的转换、执行 Action、托管 `/__mg/*`，并实现需要出站校验的 Challenge Provider（经注入的 `OutboundHttp`，见 [ADR-0008](0008-interactive-challenge-self-built.md)）；是唯一依赖 Pingora 的 crate。
3. **TLS 后端**：BoringSSL。
4. **JA4（仅 `direct_tls`）**：select-certificate 回调取 `ClientHello::as_bytes()` → 计算 JA4（huginn-net-tls，MIT / Apache-2.0；或自研解析器并对照其测试向量）→ 写入 SSL ex_data → `handshake_complete_callback` 返回结果 → `SslDigest.extension` → 请求过滤器读取。回调内保持低分配。该链路目前由 API 推断、尚未运行，Phase 1 做技术预研端到端验证。
5. **可观测与运行**：启用 `pingora-prometheus`；systemd 运行，使用 Pingora 的平滑升级（监听 socket 交接）。
6. **不做**：HTTP/2 帧级指纹（无限期推迟）；HTTP/3；PROXY protocol（Phase 5，届时用 0.9 的 PreTlsProcess 钩子 + ppp / proxy-header crate，仅 TLS 监听器）。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| rustls 后端 | Pingora 中仍标为实验性；`certificate_callback` 不可用 |
| openssl 后端 | 取完整扩展列表需要裸 FFI |
| Envoy（≥ 1.35 可把 `%TLS_JA4_FINGERPRINT%` 写入请求头）+ ext_proc | 多一跳与一个进程；将来作为 `envoy` UpstreamProfile 接入即可 |
| 基于 hyper 自建代理 | 需要自建连接管理、上游连接池、平滑升级等代理能力 |
| 在 PreTlsProcess 中读取 ClientHello 后 rewind | 与 TLS 后端无关，但与握手卸载线程池的配合未验证；仅作回退方案 |

## 后果

- Pingora 升级成本集中在 mg-edge；mg-core 不受影响，并保留编译到 wasm32 的可能。
- mg-core 的依赖受 wasm32 约束（无线程、无网络 I/O）。
- boring 同步回调在握手路径内执行，其开销以及与 0.9 新增的 TLS 握手卸载线程池的配合需实测。
- 平滑升级只保证宽限期内完成的请求，WebSocket 等长连接可能被切断。
- `cloudflare` profile 下 Edge 不使用自身看到的 TLS 指纹（描述的是 Cloudflare 或 cloudflared 的连接）。

## 参考

- https://github.com/cloudflare/pingora/releases/tag/0.9.0
- https://github.com/cloudflare/pingora/blob/main/CHANGELOG.md
- https://github.com/cloudflare/pingora/blob/main/docs/user_guide/graceful.md
- https://github.com/cloudflare/pingora/blob/main/docs/user_guide/systemd.md
- https://docs.rs/huginn-net-tls/latest/huginn_net_tls/
- https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
