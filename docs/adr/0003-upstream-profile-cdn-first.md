# ADR-0003：以 UpstreamProfile 描述上游，Cloudflare 优先

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：删除清单、信号三态、`auth_method` 取值）
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

## 参考

- https://developers.cloudflare.com/fundamentals/reference/http-headers/
- https://developers.cloudflare.com/rules/transform/request-header-modification/
- https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/
