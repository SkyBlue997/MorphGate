# ADR-0002：Edge 基于 Pingora 0.9 + BoringSSL，内核与适配层分离

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：外部 Provider 实现位置）；2026-09-28 勘误：JA4 预研结论（依据 [Phase 1 实现规格](../impl/phase1-spec.md) §15 WP-J1、D-07，见文末"勘误"）
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
4. **JA4（仅 `direct_tls`）**：select-certificate 回调取 `ClientHello::as_bytes()` → 计算 JA4（huginn-net-tls，MIT / Apache-2.0；或自研解析器并对照其测试向量）→ 写入 SSL ex_data → `handshake_complete_callback` 返回结果 → `SslDigest.extension` → 请求过滤器读取。回调内保持低分配。该链路目前由 API 推断、尚未运行，Phase 1 做技术预研端到端验证（2026-09-28 已验证，结论见文末"勘误"）。
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

## 勘误（2026-09-28，JA4 预研）

**结论**：决策 4 的链路可行，已在 mg-edge 中端到端跑通，默认关闭；常见客户端每次握手的附加开销约 0.5 µs（约为一次 TLS 1.3 握手的 0.2%，在测量噪声内；客户端刻意构造的 16 KiB ClientHello 最多约 78 µs）。同一客户端的 JA4 会随 TLS 1.3 会话恢复与 ClientHello 长度变化，**不建议**把原始 JA4 作为 `bind.tfp` 硬绑定；Phase 1 维持 D-07（`tls.ja4` 对策略恒为 MISSING，JA4 只进决定事件）。依据：规格 [§15 WP-J1](../impl/phase1-spec.md#wp-j1-ja4-预研阶段-3)，测试 `edge/tests/ja4_spike.rs` 与 `edge/src/tls/` 的单元测试。

### 实现

| 环节 | 做法 |
|---|---|
| 开关 | `edge.toml` 监听器项 `ja4_spike = true`（配置项，不是 Cargo feature）；只用于 `direct_tls`，缺省关闭，写在其他监听器上 `--check-config` 报错 |
| 取 ClientHello | 在 `TlsSettings::with_callbacks` 的设置上经 `DerefMut` 调 `set_select_certificate_callback`；`ClientHello::as_bytes()` 是已重组的握手消息体（从 `legacy_version` 起，不含记录头与握手头），由它算出的 JA4 与中继记录的线上字节算出的一致。该回调（`SSL_CTX_set_select_certificate_cb`）与 Pingora 自己挂起握手用的 `SSL_set_cert_cb` 不冲突 |
| 解析与计算 | 自研零拷贝解析器与 JA4（`edge/src/tls/client_hello.rs`、`ja4.rs`）：按 FoxIO 规范（BSD-3-Clause）独立实现，源码注明出处；只实现 JA4，不含任何 JA4+ 方法（[ADR-0009](0009-ja4-only-licensing.md)）；未引入 huginn-net-tls，新增依赖为零（只用已有的 `sha2`） |
| 传递 | 结果（36 字节的 `Copy` 值）写入 SSL ex_data → `EdgeTlsAccept::handshake_complete_callback` → `TlsFacts.ja4` → `SslDigest.extension` → `ctx.tls.ja4 = {value, source: self, authenticated: true}` |
| 策略 | MissingSet 仍含 `tls.ja4`：`has(tls.ja4)` 为 false，读 `tls.ja4.value` 的规则记为 `missing_input`，评分不读它（D-07） |
| 失败处理 | 解析失败时不写 JA4，握手照常（由 BoringSSL 自己判断报文）；回调从不返回错误；解析放在 `catch_unwind` 中（panic 穿过 BoringSSL 的 C 栈会中止进程） |

### 验证

| 项 | 方法 | 结果 |
|---|---|---|
| FoxIO 公布的示例 | `technical_details/JA4.md` 的 Chromium 示例（含 padding）与"无签名算法"示例；JA4 README 2023-10 至 2026-08 的 Chromium 示例（ECH GREASE、会话恢复）与 QUIC 的 `b` 段；FoxIO 测试抓包的期望输出：`tls12.pcap`（Firefox）、`sigalg-grease.pcapng`（带 GREASE 签名算法的 Chrome，即现行 README 的 `t13d1517h2_8daaf6152771_cb7bf5808d99`）、`badcurveball.pcap`；按这些客户端的套件、扩展、签名算法构造 ClientHello，插入 GREASE 并打乱扩展顺序 | 全部一致；输入的 SHA-256 前缀另用 Python `hashlib` 复核 |
| 真实客户端 | BoringSSL 客户端固定参数（TLS 1.3 / 1.2、有无 SNI 与 ALPN、GREASE 开关、长主机名）与 rustls（reqwest）；回环中继记录线上的 ClientHello | 决定事件中的 JA4 = 手算值（`hashlib`）= 线上字节的 JA4，例如 BoringSSL TLS 1.3 为 `t13d0611h1_d9a339d1b048_0c936b6b1637`；未开 `ja4_spike` 的监听器事件中没有 JA4 |
| 规范细节 | GREASE（套件、扩展类型、`supported_versions`、签名算法）、扩展排序、签名算法保序、ALPN（缺失、空、单字符、非字母数字按十六进制（规范的 8 个示例）、非 ASCII）、无 SNI、TLS 1.2 / 1.3 / 未知版本、无扩展块、计数封顶 99、超过 128 项、重复扩展 | 单元测试覆盖 |
| 畸形输入 | 每个截断前缀；30,000 个固定种子的随机与变异输入（规格 §2.4 第 3 条） | 从不 panic；截断只在"无扩展块"这一合法边界上成功 |
| 线上的恶意 ClientHello | 各自一个连接：解析器拒绝而 BoringSSL 仍交给回调的报文（ALPN 列表越界）、16 KiB 报文（约 8,100 个套件）、套件与版本全为 GREASE、BoringSSL 在回调前就拒绝的截断报文；另有真实客户端的 16 KiB ClientHello（约 1,770 个 ALPN 名） | Edge 逐个应答或关闭、不挂起；之后正常客户端照常得到 JA4，16 KiB 的那个也有 JA4（与普通客户端相同） |
| HTTP/2 | 同一 h2 连接上的两个流 | 两个决定事件的 JA4 相同：JA4 属于连接，不属于请求 |
| HelloRetryRequest | 客户端首选 Edge 不接受的 P-521，只带它的 key share，Edge 要求改用 X25519；中继记录两个 ClientHello（第一个因 P-521 key share 变长而带 padding，两者 JA4 不同） | 事件中的 JA4 是第一个 ClientHello 的 |

### 开销

Apple M3 Max，release（thin LTO），回环；解析器源码原样编译，回调逻辑与 mg-edge 相同。

| 测量 | 结果 |
|---|---|
| `ja4()`，1.5–1.8 KB 的 ClientHello（BoringSSL 默认客户端；带后量子 key share 的类 Chromium 报文） | 约 0.33–0.36 µs，0 次堆分配 |
| `ja4()`，150 个套件 / 20 个扩展 | 约 1.1 µs，1 次分配（超过 128 项的列表转到堆上） |
| 回调整体（`catch_unwind` + 解析 + 写 ex_data），在真实握手中计时 | 平均 0.54–0.62 µs；1 次 Rust 分配（ex_data 槽中的 36 字节 Box），另有 BoringSSL 自己的 ex_data 簿记；boring 分发回调时另取一次进程级互斥锁查闭包（与 Pingora 已用的 ALPN 回调相同，未计入） |
| 完整 TLS 1.3 握手（ECDSA P-256），开 / 关回调各 3000 次交替 | 服务端 `accept()` p50 约 247–267 µs，两者之差 < 1 µs（噪声内） |
| `ja4()` 最坏情况：BoringSSL 允许的最大 ClientHello（不要求客户端证书时 16 KiB），约 8,100 个套件 | 约 78 µs（排序并散列最长的列表；4,000 个空扩展约 43 µs）。只有客户端自己发送 16 KiB 报文并完成一次握手才会触发，约为一次握手的 1/3，放大有界 |
| debug 构建（`edge/tests/ja4_spike.rs`，只看数量级） | 解析约 13 µs（最坏情况约 3.4 ms）；经 mg-edge 的握手 p50 约 1.8–1.9 ms，开 / 关之差在噪声内 |

### 限制

| 限制 | 说明 |
|---|---|
| 会话恢复改变 JA4 | BoringSSL 在决定是否恢复之前调用回调，恢复的握手也有 JA4。TLS 1.3 恢复带 `pre_shared_key`（0029），`c` 段必变；扩展数是否变化取决于客户端：Chromium 多一个（FoxIO 示例 `t13d1516h2_8daaf6152771_02713d6af862` → `t13d1517h2_8daaf6152771_b0da82dd1658`），rustls 同时去掉 `session_ticket`（数量不变）。TLS 1.2 票据恢复不改变 JA4 |
| 长度相关的 `padding` | BoringSSL（以及基于它的 Chromium）把 256–511 字节的 ClientHello 用 RFC 7685 `padding`（0015）补到 512 字节（余量不足 5 字节时 padding 仍带 1 字节数据，报文略超 512）：同一 BoringSSL 客户端只因主机名变长就从 `t13d0611h1_…_0c936b6b1637` 变为 `t13d0612h1_…_303605e647f4`；会话票据与 key share 的大小同样影响它 |
| 只看第一个 ClientHello | BoringSSL 只在读第一个 ClientHello 时调用该回调（`handshake_server.cc` 中唯一的调用点，后续协商也以第一个为准），HelloRetryRequest 之后的第二个 ClientHello 不再计算（测试 `hello_retry_request_fingerprints_the_first_client_hello`）；FoxIO 的 Rust 工具同样只取每个 TCP 流的第一个 ClientHello（其 Python 工具逐个编号输出 `JA4.1`、`JA4.2`…） |
| ALPN 的非字母数字字节 | 按规范取首尾字节的十六进制（`0xAB` → `ab`）；FoxIO 自己的 Python / Rust 工具与规范不一致（非 ASCII 字节记为 `9`，ASCII 标点原样输出，其测试抓包 `tls-non-ascii-alpn.pcapng` 为 `…99_…`）。这类客户端的 JA4 与用 FoxIO 工具建立的指纹库对不上；常见的 `h2`、`http/1.1`、`h3` 不受影响 |
| 只有 `direct_tls` | 原决策不变：`cloudflare` profile 下看到的是 Cloudflare / cloudflared 的 ClientHello |
| ECH | Edge 未配置 ECH 密钥，指纹取自 ClientHelloOuter；若将来由 Edge 解密 ECH，回调看到的是 inner |
| 只进决定事件 | `kind=access` 不带 JA4，决定事件按 `allow_sample_rate` 采样；shadow 观察期需调高采样率，或另行规定把 JA4 写进访问记录或指标（属于 WP-E1d 的文件，需先改规格） |
| Pingora 升级 | Pingora 没有导出 boring 的 `ex_data::Index` 类型，索引保存在 `Any` 中、按构造函数的类型取回；升级 Pingora 或 boring 时复查这一点与回调顺序 |
| 握手卸载线程池 | Pingora 0.9 的 `set_offload_threadpool` 未启用，未测；回调同步执行、没有线程局部状态，预期不受影响 |

### `bind.tfp` 的建议

| 建议 | 理由 |
|---|---|
| 不以原始 JA4 做硬绑定 | 浏览器经常恢复 TLS 1.3 会话，恢复后 `c` 段必变；按 04 §5 的硬绑定语义，每次恢复都会让真人重新挑战 |
| 若要启用，只取恢复时不变的部分，并先 shadow | 候选 `tfp = hash(版本 ‖ SNI 标记 ‖ 套件数 ‖ ALPN ‖ b)`，即去掉扩展数与 `c`；在 `ja4_spike` 的 monitor 期按会话（同一 `sub`）统计稳定性，与 `ctp` 同一门槛（≥ 99%）后才考虑软绑定 |
| 开启 `ja4_spike` 的时机 | 开销可忽略且只进事件，`direct_tls` 站点上线后即可开启做 shadow 观察；当前部署全部在 Cloudflare 之后，`tfp` 暂无适用对象，Phase 2 前不需要决定 |

## 参考

- https://github.com/cloudflare/pingora/releases/tag/0.9.0
- https://github.com/cloudflare/pingora/blob/main/CHANGELOG.md
- https://github.com/cloudflare/pingora/blob/main/docs/user_guide/graceful.md
- https://github.com/cloudflare/pingora/blob/main/docs/user_guide/systemd.md
- https://docs.rs/huginn-net-tls/latest/huginn_net_tls/
- https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4
- https://www.rfc-editor.org/rfc/rfc8701（GREASE）、https://www.rfc-editor.org/rfc/rfc7685（ClientHello padding）
