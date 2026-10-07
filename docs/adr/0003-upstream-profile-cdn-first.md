# ADR-0003：以 UpstreamProfile 描述上游，Cloudflare 优先

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：删除清单、信号三态、`auth_method` 取值）；2026-09-28 勘误：Phase 1 实现口径（依据 [Phase 1 实现规格](../impl/phase1-spec.md) D-07、D-14、D-23、I-12、I-29，见文末"勘误"）
- 相关：[08 上游接入与 Cloudflare 集成](../08-upstream-and-cloudflare.md)（规范细节以 08 为准）、[01 整体架构](../01-architecture.md)、[03 信号与风险评分](../03-risk-scoring.md)、[ADR-0004](0004-origin-protection-tunnel-aop.md)

## 背景

- 所有者的大部分站点前面已有 CDN 或网关，以 Cloudflare 为主；流量以浏览器网页为主。
- 原设计只有"M1 位于 CDN 之后 + 可信代理网段"的笼统说法，回答不了三个问题：怎样确认请求确实来自该上游；该上游的哪些头能映射成信号；哪些信号该上游本来就不提供。
- Cloudflare 之后：JA4、HTTP/2 指纹、头顺序与大小写、TCP 特征描述的都是 Cloudflare 的连接；`Accept-Encoding` 被改写为 `br, gzip`；XFF 是追加而非覆盖，左侧由客户端控制；访客 JA4 只对 Enterprise + Bot Management 提供。回源连接被多个访客复用。
- 不同上游暴露的信号差异很大：CloudFront 可转发 JA3/JA4 与头顺序，阿里云 CDN / 腾讯云 CDN 只有 IP。

## 决策

1. Edge 的每个监听器 / 站点配置一个 `UpstreamProfile`，声明：(a) 上游认证方式；(b) 上游头 → 规范信号的映射；(c) 该上游预期提供的信号集合。
2. 规范取值：`cloudflare`、`direct_tls`、`proxy_protocol{v1|v2, allowed_src_cidrs}`、`cloudfront`、`gcp_alb`、`esa`、`edgeone`、`alicdn`、`tencent_cdn`、`envoy`、`openresty`。**Phase 1 只实现 `cloudflare` 与 `direct_tls`**，其余按站点实际需要再做。
3. 信任规则：`UpstreamInfo.auth_method ∈ {loopback, origin_mtls, secret_header, src_cidr, none}`（`secret_header` 即轮换的 `x-mg-upstream-key`）。只有认证通过才采信该 profile 的信号头；否则删除全部已知上游头族（`cf-*`、`x-mg-*`、`CloudFront-*`、`Tls-Ja3/Ja4/Hash`、`ali-*`、`Ali-Cdn-*`、`EO-*`、`Esa-*`、`X-Forwarded-*`、`X-Forward-Port`、`Forwarded`、`True-Client-IP`、`X-Real-IP`），客户端 IP 取 TCP 对端地址。清单以 [08 §1.2](../08-upstream-and-cloudflare.md) 为准。
4. 信号溯源：RequestContext 记录来源，例如 `tls.ja4 {value, source: self|cloudfront|gcp_alb|esa|envoy|openresty, authenticated}`；CDN 提供的 JA4 权重略低于 Edge 自算。
5. 信号三态 `PRESENT` / `ABSENT` / `MISSING`（语义以 [03 §3.1](../03-risk-scoring.md) 为准）：profile 本就不提供、或应由上游注入的头未到达 / 来源不可确认 → `MISSING`，不计入置信度，绝不当作人类证据，上游注入头缺失另触发配置告警；profile 应能提供而本请求没有 → `ABSENT`，计入置信度分母。
6. `cloudflare` profile：客户端 IP 只取 `CF-Connecting-IP`（缺失时告警、不回退到 Cloudflare 对端 IP）；免费 Transform Rule 转发的 `x-mg-cf-*` 形成低权重的 `EDGE_TLS` 族，先 shadow；不以下游连接作为任何状态的键。规范见 [08 §2](../08-upstream-and-cloudflare.md#2-cloudflare-前置cloudflare-profile)。
7. Decision Core 只消费规范信号及其可用性，不感知具体 CDN；策略编译时按站点 profile 检查字段可用性（ADR-0006）。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| 单一"可信代理网段 + XFF 从右向左" | 证明不了请求来自所有者自己的 Cloudflare 账号；表达不了预期信号集 |
| 只支持 `direct_tls`，取消 CDN | 与现状冲突，失去 CDN 的缓存与容量防护 |
| 购买 Enterprise Bot Management 取 `cf-ja4` / `cf-bot-score` | 超出个人预算 |
| 在 Cloudflare Worker 中运行 Decision Core | Workers Free 每请求 10 ms CPU；nonce 需要 Durable Objects；列为后期可选 |

## 后果

- `cloudflare` profile 下协议层信号族大多为 MISSING，判定更依赖 Web SDK、Challenge、限速、IP / ASN 与身份信号。
- `x-mg-cf-tls-*`（尤其扩展哈希）的稳定性未文档化，需 shadow 实测后才能提高权重或用于绑定。
- 新增上游只需新增 profile 与映射，不改 Decision Core。
- 需要 `mgctl cf audit` 核对 Cloudflare 侧配置与 profile 的假设是否一致。

## 勘误（2026-09-28，Phase 1 实现）

结论不变。Phase 1 按下表实现（D-xx 见规格 [§0.3](../impl/phase1-spec.md#03-决定与偏离)，I-xx 见[集成者裁决](../impl/phase1-spec.md#集成者裁决2026-09-28优先于正文)）：

| 决策 | Phase 1 实际做法 |
|---|---|
| 1 | profile 绑定在主机本地 `edge.toml` 的 `[[listeners]]`；站点 YAML 的 `profile` 进入签名配置包的 `upstream.kind`，必须等于服务该站点的每个监听器的 profile，混用是配置错误（D-14，规格 [§8.1](../impl/phase1-spec.md#81-edgetoml-v1wp-e1a)、[§9.10](../impl/phase1-spec.md#910-配置包加载与站点状态wp-c2-实现wp-e1a-接线)）。`expected_mask`：`cloudflare` 为 NETWORK、HTTP、EDGE_TLS、IDENTITY、RATE、EXTERNAL；`direct_tls` 为 NETWORK、TLS、HTTP、IDENTITY、RATE |
| 3 | `auth_method` 只有 `loopback`、`origin_mtls`、`secret_header`、`none`（`src_cidr` 随 `proxy_protocol` 在 Phase 5）；`secret_header` 是叠加在 `cloudflare` 监听器上的 `upstream_keys`。头族按名称小写、`_` 换成 `-` 后匹配，前缀另含 `mg-`，全名另加 I-29 的客户端 IP、URL 改写与方法覆盖类头（共 19 个）；`Connection` 列出的头族名不在逐跳删除中删掉，留给解析后统一剥离（I-12）。清单以 [08 §1.2](../08-upstream-and-cloudflare.md#12-信任规则) 为准 |
| 4 | `tls.ja4` 恒为 MISSING（`direct_tls` 的 JA4 只在 WP-J1 预研中写入事件，D-07）；`net.ip_source` 只有 `cf_connecting_ip`、`cf_connecting_ipv6`、`tcp_peer` |
| 5 | `x-mg-cf-hdr-names` 的缺失照常计数，但不计入告警的缺失率：任何客户端发一个超过 64 字节的头名就能让它缺失（I-12）；TLS 字段只对 https 访客计缺失 |
| 6 | `CF-Connecting-IP` 缺失、非法或重复 → 客户端 IP 未知，Edge 从不因此更宽松；外部 zone 的 `CF-Worker` 直接 403（D-23，[08 §2.2](../08-upstream-and-cloudflare.md#22-客户端-ip)） |

## 参考

- https://developers.cloudflare.com/fundamentals/reference/http-headers/
- https://developers.cloudflare.com/rules/transform/request-header-modification/
- https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/
