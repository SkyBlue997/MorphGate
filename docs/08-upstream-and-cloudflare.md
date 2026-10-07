# 08 上游接入与 Cloudflare 集成

本文定义 Edge 如何认证前方的上游（CDN / 负载均衡 / 网关）、从上游头取得哪些信号，以及 Cloudflare 作为首要上游时的配置规范。上游头名、剥离清单与 `upstream.auth_method` 取值以本文为准；RequestContext 的完整定义见 [02 §7](02-data-flow.md#7-核心数据模型)，Edge 与源站之间的头约定见 [02 §8](02-data-flow.md#8-edge-与源站的约定)。事实性内容以文末"参考"中的官方文档为准（截至 2026-09-27）；标"需实测 / 需确认"的条目在 Phase 1 用所有者自己的 zone 验证，汇总见 §5。

**结论**

- Edge 的每个监听器绑定一个 `UpstreamProfile`，声明认证方式、头 → 信号映射与预期信号。Phase 1 只实现 `cloudflare` 与 `direct_tls`。
- 只有认证通过的上游，其信号头才被采信；否则删除全部已知上游头族，客户端 IP 取 TCP 对端地址。
- Cloudflare 源站保护首选 **Cloudflare Tunnel**（Edge 只监听 127.0.0.1）；其次 **zone-level / per-hostname AOP**（自有 CA）+ 防火墙只放行 Cloudflare IP 段。不用全局共享 AOP 证书。
- 客户端 IP 只取 `CF-Connecting-IP`；不用 `X-Forwarded-For[0]`、`True-Client-IP`、`X-Real-IP`。
- Free / Pro / Business 下源站拿不到访客的 JA4、HTTP/2 指纹、头顺序与 TCP 特征（状态为 `MISSING`）。一条 Request Header Transform Rule（所有套餐，免费）可以转发部分 TLS 参数、RTT、ASN、HTTP 版本、已验证爬虫标志和头名集合，作为低权重的 `EDGE_TLS` 族（先 shadow）。
- 与 Cloudflare 自带功能共存：Free 关闭 Bot Fight Mode；`/__mg/*`（内容哈希的 SDK 构建除外）与 Challenge 响应一律 `no-store, private`，并用最后一条 Cache Rule Bypass；MorphGate 挑战的路径不叠加 Cloudflare 挑战。`mgctl cf audit` 自动检查这些配置。

**Phase 1 实现状态**（2026-09-28 勘误；细节以 [Phase 1 实现规格](impl/phase1-spec.md) 为准，D-xx 见规格 [§0.3](impl/phase1-spec.md#03-决定与偏离)，I-xx 见[集成者裁决](impl/phase1-spec.md#集成者裁决2026-09-28优先于正文)；Cloudflare 侧模板与设置清单见 [`adapters/cloudflare/README.md`](../adapters/cloudflare/README.md)）

| 本文内容 | Phase 1 做法 | 规格 |
|---|---|---|
| profile 与认证（§1.1–§1.2） | `cloudflare`（`loopback` 或 `origin_mtls`，可叠加 `upstream_keys`）与 `direct_tls`；监听器在主机本地的 `edge.toml`，站点的 profile 在配置包中，两者必须一致 | [§8.1](impl/phase1-spec.md#81-edgetoml-v1wp-e1a)、[§9.2](impl/phase1-spec.md#92-监听器与上游认证) |
| 头族与清洗（§1.2） | 规范清单加 I-29 的 12 个头名；名称先小写、`_` 换成 `-` 再匹配；`Connection` 列出的头族名与消息分帧头不在逐跳删除中删掉 | [§9.3](impl/phase1-spec.md#93-头部清洗与可信头解析wp-c1-实现wp-e1a-接线) |
| 可信头（§1.4、§2.3、§2.4） | 只解析精确的小写连字符名，按格式校验，非法按缺失处理 | [§9.3](impl/phase1-spec.md#93-头部清洗与可信头解析wp-c1-实现wp-e1a-接线) |
| 客户端 IP 与 `CF-Worker`（§2.2） | IP 未知时从不更宽松；外部 zone 的 `CF-Worker` 直接 403（D-23）；配置包生效前用 `bootstrap_owner_zones`（I-4） | [§9.3.2](impl/phase1-spec.md#932-客户端-ip-未知d-23)、[§9.4](impl/phase1-spec.md#94-站点环境与路由) |
| 配置划分（§1.5） | `edge.toml` 与站点 YAML（D-14） | [§8.1](impl/phase1-spec.md#81-edgetoml-v1wp-e1a)、[§8.2](impl/phase1-spec.md#82-站点-yaml-v1wp-g2) |
| `mgctl cf audit`（§2.10） | 21 项检查，只读 token，所有者在工作站运行 | [§14.3](impl/phase1-spec.md#143-mgctl-cf-auditwp-g3) |
| IP 段同步（§2.11） | `mgctl cf ips sync`（工作站），工件随签名配置包下发 | [§12.2](impl/phase1-spec.md#122-cloudflare-ipsjson)、[§14.4](impl/phase1-spec.md#144-mgctl-cf-ips-syncwp-g3) |
| 未实现 | HMAC Cookie 跳过（§2.9）、`mgctl cf apply`、SDK 侧的 `cf-mitigated` 处理（§2.8）、其他 CDN 与 PROXY protocol（§3–§4）；`direct_tls` 的 JA4 仍在预研（D-07） | [§0.1](impl/phase1-spec.md#01-范围) |

## 1. UpstreamProfile 上游模型

### 1.1 取值与阶段

决策记录见 [ADR-0003](adr/0003-upstream-profile-cdn-first.md)。profile 绑定在**监听器**（bind 地址 + TLS 配置）上，不由 Host 头决定（Host 由客户端控制）。一个站点可以接受多个监听器（例如国际流量经 Cloudflare Tunnel、已备案的境内流量经 ESA），每个监听器只有一个 profile；请求从站点未声明的监听器进入时拒绝并告警。每个 profile 声明三件事：(a) 上游如何被认证；(b) 上游头 → 规范信号的映射；(c) 该上游**预期能提供**哪些信号（§1.4）。

Phase 1：profile 绑定在 `edge.toml` 的 `[[listeners]]`；站点 YAML 的 `profile` 成为配置包的 `upstream.kind`，加载时必须等于服务该站点的每个监听器的 profile。一个站点挂在不同 profile 的监听器上是配置错误（`--check-config` 拒绝）。请求从站点未声明的监听器（`edge.toml` 站点的 `listeners` 与配置包的 `allowed_listeners` 都要包含）进入时 403，计 `mg_listener_rejected_total{listener, site}`。

| profile | 场景 | 认证方式 | 客户端 IP 来源 | TLS 指纹 | 阶段 |
|---|---|---|---|---|---|
| `cloudflare` | Cloudflare 橙云代理 | Tunnel 回环对端，或 AOP 客户端证书（自有 CA）；可叠加 `x-mg-upstream-key` | `CF-Connecting-IP` | 无 JA4；`EDGE_TLS`（cf.tls_*） | Phase 1 |
| `direct_tls` | 无 CDN，Edge 终止 TLS | 无上游 | TCP 对端 | Edge 自算 JA4 | Phase 1 |
| `proxy_protocol{v1\|v2, allowed_src_cidrs}` | L4 负载均衡在前，Edge 终止 TLS | TCP 对端 ∈ `allowed_src_cidrs` + PROXY 头 | PROXY 头中的源地址 | Edge 自算 JA4 | Phase 5 |
| `cloudfront` | AWS CloudFront | 源站 mTLS 或密钥头；源站前缀列表只做安全组 | `CloudFront-Viewer-Address` | JA3 / JA4（转发） | Phase 4 按需 |
| `gcp_alb` | GCP 外部应用负载均衡（含 Cloud CDN） | 后端 mTLS 或密钥头 | `{client_ip_address}` 变量注入的头 | JA3 / JA4（转发） | Phase 4 按需 |
| `esa` | 阿里云 ESA | 回源客户端证书或密钥头；Origin Protection IP 列表只做安全组 | `ali-real-client-ip`（可改名） | 仅 Enterprise | Phase 4 按需 |
| `edgeone` | 腾讯云 EdgeOne | 回源 mTLS（API 层面存在）或密钥头；Origin Protection 只做安全组 | `EO-Connecting-IP` 或自定义客户端 IP 头 | 不可转发 | Phase 4 按需 |
| `alicdn` | 阿里云 CDN | 密钥头 | `Ali-Cdn-Real-Ip` | 无 | Phase 4 按需 |
| `tencent_cdn` | 腾讯云 CDN | 密钥头 | `x-mg-tc-ip`（`$client_ip`） | 无 | Phase 4 按需 |
| `envoy` | 自建 Envoy ≥ 1.35 在前 | Envoy → Edge mTLS | Envoy 设置的头 | JA4（`%TLS_JA4_FINGERPRINT%`） | Phase 4 按需 |
| `openresty` | 自建 OpenResty ≥ 1.29.2.1 在前 | OpenResty → Edge mTLS | OpenResty 设置的头 | JA4（lua-resty-ja4） | Phase 4 按需 |

### 1.2 信任规则

| `auth_method` | 用于 | Edge 侧校验 | 失败处理 |
|---|---|---|---|
| `loopback` | `cloudflare`（Tunnel） | 监听器只绑定 127.0.0.1 / ::1，对端必须是回环地址 | 对端不是回环地址时 403（`reason="non_loopback_peer"`）；主机上不运行不受信的本地进程 |
| `origin_mtls` | `cloudflare`（AOP）、`cloudfront`、`gcp_alb`、`esa`、`edgeone`、`envoy`、`openresty` | 要求客户端证书，链到该 profile 配置的**所有者自有 CA**（可再固定叶证书指纹）；Phase 1 为 BoringSSL `PEER \| FAIL_IF_NO_PEER_CERT` + `client_ca` | 握手失败，断开；计 `reason="untrusted_ca"`（每个握手至多一次；未出示证书的握手不计） |
| `secret_header` | 所有 CDN profile（单独使用或叠加在 mTLS 上） | `x-mg-upstream-key` 常量时间比较，同时接受新旧两个值以便轮换；Phase 1 由 `edge.toml` 监听器的 `upstream_keys` 开启（仅 `cloudflare`），叠加在 `loopback` / `origin_mtls` 上 | 403 纯文本 `forbidden`（`reason="bad_secret_header"`）；CDN 专用监听器不回退为"直连"处理 |
| `src_cidr` | `proxy_protocol`（Phase 5） | TCP 对端 ∈ `allowed_src_cidrs` | 断开 |
| `none` | `direct_tls`，或未通过认证 | — | 按下方第 3 步处理 |

云防火墙 / 安全组的 IP 白名单在 Edge 之外执行，只做纵深防御，**永远不作为唯一依据**：IP 段只证明"来自该 CDN 网络"，其他客户的流量也能通过。认证失败计入 `mg_upstream_auth_failures_total`（reason 取值见 [06 §5](06-policy-console-observability.md#5-日志指标与告警)）。

判定顺序（每个请求最先执行，早于路由匹配）：

1. 由监听器确定 profile 与 `upstream.auth_method`。
2. 认证通过：只保留该 profile 声明的头名并按映射解析，其余上游头族（含未声明的 `x-mg-*`）删除；无论如何都删除 `True-Client-IP`、`X-Real-IP` 与客户端发来的 `MG-*`。`cloudflare` 声明的头名：`CF-Connecting-IP`、`CF-Connecting-IPv6`（仅 Pseudo IPv4 = Overwrite 时）、`Cf-Ray`、`CF-Visitor`、`CF-Worker`（校验用，§2.2）、已确认开启的 visitor location 头、Tier 0 / Tier 1 的 `x-mg-cf-*`、启用时的 `x-mg-upstream-key`。
3. 认证未通过或 profile 为 `direct_tls`：删除全部已知上游头族（计入 `mg_upstream_headers_stripped_total`），客户端 IP = TCP 对端地址。
4. 认证通过但缺少该 profile 的客户端 IP 头：记配置告警（`cloudflare` 下计入 `mg_cf_connecting_ip_missing_total`），**不回退**到上游对端 IP（对端是 CDN 节点，用它限速会误伤所有访客）。该请求按"客户端 IP 未知"处理，见 [02 §2.1](02-data-flow.md#21-第-0-步上游认证与客户端-ip)。

**Phase 1 处理顺序**（[规格 §9.3](impl/phase1-spec.md#93-头部清洗与可信头解析wp-c1-实现wp-e1a-接线)）：

| 步 | 做法 |
|---|---|
| ① | 监听器认证（上表） |
| ② | 协议输入上限（路径、查询串、头值、头名、头个数、方法；[规格 §9.3.1](impl/phase1-spec.md#931-协议输入上限d-26)） |
| ③ | 删除 `Connection` 及其列出的头，以及 `Keep-Alive`、`Proxy-Connection`、`TE`、非 WebSocket 的 `Upgrade`。例外：列出的名字属于上游头族时留给 ④ 解析、⑤ 剥离，否则 `Connection: CF-Worker` 就能藏起外部 Worker（I-12）；`Content-Length` / `Transfer-Encoding` 从不在此删除，删掉会让请求体与连接失步，形成请求走私 |
| ④ | 认证通过的 `cloudflare` 请求只按**精确的小写连字符名**解析可信头；下划线写法永不解析，也不遮蔽 Cloudflare 写入的头；同名头重复即按非法处理 |
| ⑤ | 删除全部头族（包括 Cloudflare 添加的），再为源站重新写入 `MG-*` 与保留的 Cloudflare 头（[02 §8](02-data-flow.md#8-edge-与源站的约定)）。`direct_tls` 与未认证请求带任一头族时计 `mg_upstream_headers_stripped_total{profile}` |

**已知上游头族（剥离清单，规范口径）**：`cf-*`、`x-mg-*`、`CloudFront-*`、`Tls-Ja3` / `Tls-Ja4` / `Tls-Hash`、`ali-*`、`Ali-Cdn-*`、`Esa-*`（如 ESA 的 `Esa-User-Risk`）、`EO-*`、`X-Forwarded-*`、`X-Forward-Port`（腾讯云 CDN）、`Forwarded`（RFC 7239；Cloudflare 在试验用它转发 Intermediary Agent 的终端用户身份）、`True-Client-IP`、`X-Real-IP`。

Phase 1 按名称小写并把 `_` 换成 `-` 后匹配（`CF_Connecting_IP`、`MG_Bot_Score` 同样命中；前缀另含 `mg-`），并另外删除 I-29 的三类头（它们也不进入策略的 `req.headers`）：

| 类 | 头名 | 源站信任它们的后果 |
|---|---|---|
| 客户端 IP | `client-ip`、`x-client-ip`、`x-cluster-client-ip`、`fastly-client-ip`、`x-originating-ip`、`x-remote-ip`、`x-remote-addr` | 采信伪造的客户端 IP（如 PHP 的 `HTTP_CLIENT_IP`） |
| URL 改写 | `x-original-url`、`x-rewrite-url` | 源站执行的路径与 Edge 路由判定的不同 |
| 方法覆盖 | `x-http-method-override`、`x-http-method`、`x-method-override` | 源站执行的方法与 Edge 路由判定的不同，可绕过按方法限定的敏感路由 |

### 1.3 转发给源站前的处理

出站方向（附加 `MG-Client-IP` 等 `MG-*` 头、`X-Forwarded-For` 改写为单值、`X-Forwarded-Proto`、保留的 Cloudflare 标准头、`x-mg-*` 一律不转发、源站只接受 Edge 流量）以 [02 §8](02-data-flow.md#8-edge-与源站的约定) 为准，本文不重复。

请求体（以及 POST 的查询串）中的 `_method` 参数 Edge 删不掉（Symfony / Laravel 等框架的方法覆盖）：源站不得对受保护路由启用方法覆盖（I-29，写入所有者运行手册）。

### 1.4 信号溯源与预期信号

与上游相关的 RequestContext 字段（名称与 [06 §2](06-policy-console-observability.md#2-策略语言) 的 CEL 字段一致）：

| 字段 | 取值 / 来源 | 说明 |
|---|---|---|
| `upstream.profile`、`upstream.authenticated` | §1.1、§1.2 | — |
| `upstream.auth_method` | `loopback` \| `origin_mtls` \| `secret_header` \| `src_cidr` \| `none` | §1.2 |
| `upstream.cf_ray` | `Cf-Ray` | 写入 DecisionEvent，便于与 Cloudflare 日志对照 |
| `upstream.client_ip_header_missing` | §1.2 第 4 步 | 配置告警 |
| `net.ip`、`net.ip_source` | `tcp_peer`、`cf_connecting_ip`、`cf_connecting_ipv6`、`proxy_v2` 等（完整取值见 02 §7） | Phase 1 只有前三个 |
| `net.upstream_asn` / `upstream_country` / `upstream_region` / `upstream_timezone`、`net.rtt_ms` | `x-mg-cf-asn`、visitor location 头、`x-mg-cf-rtt` / `x-mg-cf-quic-rtt` | 只作交叉核对；ASN / 地理以本地 GeoLite2 为准 |
| `tls.ja4` | `{value, source: self \| cloudfront \| gcp_alb \| esa \| envoy \| openresty, authenticated}` | 转发的 JA4 权重为 Edge 自算的 0.8 倍（初值，用自有流量校准）；`authenticated = false` 的值不进入评分。Phase 1 恒为 MISSING（`direct_tls` 的 JA4 只在预研中写入事件，D-07） |
| `edge_tls.{version, cipher, ciphers_sha1, ext_sha1, hello_len}` | `x-mg-cf-tls-*`（§2.3） | 仅 `cloudflare` |

RequestContext **不含** `client_random`：`x-mg-cf-tls-random` 只在内存与近线中以 `client_conn_key = hash(value)` 使用，不进入事件。

profile 编译出 `expected_mask`（该上游应提供的信号族），请求实际得到 `availability_mask`。状态语义以 [03 §3.1](03-risk-scoring.md#31-信号状态与上游可用性) 为准，与上游相关的情况如下：

| 情况 | 状态 | 告警 |
|---|---|---|
| 上游本就不提供（不在 `expected_mask`，如 `cloudflare` 下的 JA4） | `MISSING` | 否 |
| 上游应注入的头未到达（如 Tier 0 Transform Rule 被改 / 删） | `MISSING` | 计入 `mg_upstream_signal_missing_total`，缺失率超阈值告警。Tier 0 头由 Set 覆盖写入、客户端无法删除，这类缺失是配置问题，不计入客户端风险。例外：`hdr-names` 照常计数但不进告警的缺失率，因为任何客户端发一个超过 64 字节的头名就能让它缺失（I-12）。Phase 1 只统计通过 403 / 503 检查、且不是 `/__mg/healthz` 的请求 |
| Tier 1 未运行（未启用、路由未覆盖、fail-open）或来源无法确认（缺少 `x-mg-cf-t1`，§2.4） | `MISSING` | 否 |
| 条件性字段：明文 HTTP 没有 TLS 字段；TCP 客户端没有 QUIC RTT，QUIC 客户端没有 TCP RTT | `MISSING` | 不计入 `mg_upstream_signal_missing_total`，不告警（Phase 1：TLS 字段只对 `cf-visitor` 为 https 的请求计缺失；HTTP/3 看 QUIC RTT，其余看 TCP RTT） |
| profile 能提供、但本请求没有的客户端侧输入（SDK 遥测、凭证） | `ABSENT` | 见 03 |

`MISSING` 不计入置信度的分子与分母，绝不当作人类证据。

### 1.5 配置示意

Phase 1 按 D-14 分成两处（完整字段见 [规格 §8.1](impl/phase1-spec.md#81-edgetoml-v1wp-e1a)、[§8.2](impl/phase1-spec.md#82-站点-yaml-v1wp-g2)）：监听器（绑定地址、TLS 文件、上游认证、上游密钥文件）与站点的源站地址每台主机不同、无法热更换，只写在主机本地的 `edge.toml`；站点的 Cloudflare 属性与 `mgctl cf audit` 的结果绑定，属于策略，写在站点 YAML，随签名配置包下发。

```toml
# edge.toml (host-local, never in a bundle)
[[listeners]]
name = "cf-tunnel"
bind = "127.0.0.1:8080"                      # cloudflared -> http://127.0.0.1:8080
profile = "cloudflare"
auth = "loopback"                            # or origin_mtls: tls_cert, tls_key, client_ca (owner CA), cloudflare_ip_filter
upstream_keys = "cred://mg-upstream-keys"    # optional: x-mg-upstream-key required (2.1)

[[listeners]]
name = "direct"
bind = "0.0.0.0:443"
profile = "direct_tls"
auth = "none"
tls_cert = "/etc/morphgate/tls/edge.pem"
tls_key = "cred://mg-edge-tls-key"

[[sites]]
id = "blog"
hosts = ["example.com", "www.example.com"]   # must equal the bundle's hosts
listeners = ["cf-tunnel"]
origin = "127.0.0.1:3000"
bundle_root = "file:///srv/mg/"
bootstrap = "open"                           # before the first bundle: open | closed
# bootstrap_owner_zones = ["example.com"]    # CF-Worker zones trusted before the first bundle (I-4)
```

```yaml
# site YAML (compiled into the signed bundle)
site: blog
profile: cloudflare                   # must equal the profile of every listener serving the site
hosts: [example.com, www.example.com]
allowed_listeners: [cf-tunnel]
cloudflare:
  zone: example.com
  location_headers: true              # only after mgctl cf audit confirms the Managed Transform
  tier1: false
  owner_zones: [example.com]          # CF-Worker from other zones -> 403 (2.2)
  pseudo_ipv4_overwrite: false
  origin_mode: tunnel                 # tunnel | aop; used by mgctl cf audit only
```

## 2. Cloudflare 前置（`cloudflare` profile）

### 2.1 源站保护

决策记录见 [ADR-0004](adr/0004-origin-protection-tunnel-aop.md)。同一主机名不混用 Tunnel 与 AOP。

| 方案 | 套餐 | 证明什么 | 取舍 |
|---|---|---|---|
| **① Cloudflare Tunnel（推荐）** | 所有套餐 | 只有经 cloudflared 的流量能到达 Edge；源站无公网入站端口 | 多一个守护进程；源站与 Cloudflare 绑定；AOP 对 Tunnel 主机名不生效 |
| ② AOP zone-level / per-hostname（自有 CA）+ 防火墙 | 所有套餐 | 连接来自**本账号**的 zone | 需要公网 443；需管理证书到期 |
| 不采用：全局 AOP（共享证书） | 所有套餐 | 只证明"来自 Cloudflare 网络" | 其他 Cloudflare 客户（例如他们的 Worker）经 Cloudflare 发出的流量也能通过 |
| 不采用：只做 IP 白名单 | — | 只证明"来自 Cloudflare 网络" | Cloudflare 自评为 moderately secure，存在 IP 伪造风险 |

**Tunnel（推荐）**

```
Browser --HTTPS, TLS ends at Cloudflare--> Cloudflare zone (Free / Pro)
                                             Transform Rule    -> x-mg-cf-*
                                             Cache Rule (last) -> bypass /__mg/
                                             Skip rule for /__mg/
          ^ outbound-only tunnel from cloudflared (4 long-lived conns per replica, 2+ CF data centers)
host A: cloudflared (replica 1) -> http://127.0.0.1:8080 -> MorphGate Edge (Pingora, systemd;
        listen 127.0.0.1 only, trust loopback peer) -> origin app (127.0.0.1:3000 or unix socket)
host B: same layout, cloudflared replica 2
both hosts: inbound firewall deny all (admin via VPN / WireGuard only)
```

| 要点 | 说明 |
|---|---|
| 副本 | 每台 Edge 主机一个 cloudflared 副本，共享同一个 tunnel：请求发往地理上最近的副本，连接失败时 Cloudflare 重试其他副本，一台主机宕机时其余副本继续服务。这是就近路由而非负载均衡；加权或健康检查分流需付费的 Load Balancer（不在范围内） |
| ingress | 只指向 Edge，不能直接指向源站 |
| 同机 SSRF | Edge 与源站同机时，源站应用的 SSRF 可向 127.0.0.1:8080 发出带伪造 `CF-Connecting-IP` 的请求 → 启用上游密钥头：`edge.toml` 监听器的 `upstream_keys` 指向 `mgctl keys gen-upstream` 生成的密钥文件；Cloudflare 侧另部署一条只设置 `x-mg-upstream-key` 静态值的 Transform Rule（`ref` = `mg_upstream_key_v1`，模板 `adapters/cloudflare/transform-rule.upstream-key.json`）。轮换时密钥文件保留新旧两个值，Edge 同时接受。回环监听器服务的站点源站也在回环地址、却没有配置 `upstream_keys` 时，`mg-edge --check-config` 警告 |
| 网络 | 出站端口 7844（TCP/UDP，默认 QUIC）；默认 `edge-ip-version 4`，纯 IPv6 主机设为 `6` 或 `auto`（纯 IPv6 端到端未经验证） |
| SBFM | 使用 SBFM 的 zone 须保持 "Definitely Automated" = Allow，否则 tunnel 连接可能以 `websocket: bad handshake` 失败 |
| 代理头 | `CF-Connecting-IP` 等头经 Tunnel 到达源站的行为应与 AOP 一致，官方页面未明写 → **需实测**（Phase 1 验收项：monitor 周首日确认 `mg_cf_connecting_ip_missing_total` 为 0） |

**AOP（备选）**：Browser → Cloudflare（SSL 模式 Full (strict)；AOP zone-level 或 per-hostname，客户端证书由所有者 CA 签发）→ 云安全组（443 只放行 Cloudflare 段，§2.11）→ Edge :443（要求客户端证书，链到所有者 AOP CA）→ 源站。

- SSL 模式须为 Full 或 Full (strict)，推荐 Full (strict)。
- 上传的必须是叶证书（上传根 CA 返回 `missing leaf certificate`），源站安装签发它的根 CA。per-hostname 优先于 zone-level，zone-level 优先于全局，三者是独立开关。可配置 Cloudflare 在证书到期前 30 / 14 天告警。
- Edge 只在通过客户端证书校验的连接上采信 `CF-Connecting-IP` 与 `x-mg-cf-*`。`client_ca` 是签发上传证书的**所有者自有 CA**，不是 Cloudflare 全局 origin-pull 证书的 CA。纵深防御：Pingora `ConnectionFilter` 在 TLS 之前丢弃来源不在 Cloudflare IP 段内的连接（快照来自 §2.11；Phase 1 为 `origin_mtls` 监听器的 `cloudflare_ip_filter = true`，用各站点 `cloudflare-ips` 工件的并集，尚无工件时放行并把 `mg_cf_ip_filter_active` 置 0）。
- Worker 子请求回源时是否出示 zone-level AOP 证书 → **需实测**（与 §2.4 的 Worker 组合前验证）。

### 2.2 客户端 IP

| 头 | 是否使用 | 原因 |
|---|---|---|
| `CF-Connecting-IP` | **唯一来源** | 单个访客 IP；只出现在边缘到源站的流量上 |
| `CF-Connecting-IPv6` | Pseudo IPv4 = Overwrite 时使用 | 此时 `CF-Connecting-IP` 与 XFF 变为 Class E 伪 IPv4，真实地址在该头中 |
| `X-Forwarded-For` | 只作交叉核对 | Cloudflare 追加而不是覆盖，左侧由客户端控制 |
| `True-Client-IP` | 不用，删除 | 仅 Enterprise 的 Managed Transform 添加；非 Enterprise 时客户端可伪造 |
| `X-Real-IP` | 不用，删除 | 无 Worker 子请求时 Cloudflare 会剥离；Worker 代码可改写 |
| `CF-Worker` | 校验 | 只出现在 Worker 子请求上，值为 Worker 所属 zone；不属于所有者 zone（含值非法）时 403 纯文本，计 `mg_cf_foreign_worker_total{site}`，不进入决策（D-23） |

- Pseudo IPv4 在所有套餐默认关闭，建议保持关闭（API 设置名 `pseudo_ipv4`，取值 `off` / `add_header` / `overwrite_header`）。
- 认证通过的请求缺 `CF-Connecting-IP` 时按 §1.2 第 4 步处理。最常见的原因是误开了 Managed Transform "Remove visitor IP headers"（`remove_visitor_ip_headers`），它删除 `cf-connecting-ip`、`true-client-ip`，以及前面还有其他 CDN 时 XFF 中的访客部分。
- 同 zone 的 Worker 子请求中，`CF-Connecting-IP` 反映 `x-real-ip`，后者可被 Worker 代码修改 → Worker 代码不得设置 `x-real-ip`。
- Phase 1（[规格 §9.3.2](impl/phase1-spec.md#932-客户端-ip-未知d-23)）：客户端 IP 未知时 Edge 从不比已知时更宽松。`CF-Connecting-IP` 缺失、非法或重复 → IP 未知：NETWORK 族 MISSING，限速维度用共享兜底值 `?`，不签发 C 与凭证（429），`fail_closed` 路由 429，爬虫声明只能是 `DECLARED_AGENT`，源站收到 `MG-Client-IP: unknown`（D-23）。
- `owner_zones` 来自配置包；尚无配置包时用 `edge.toml` 站点的 `bootstrap_owner_zones`，未配置则任何 `CF-Worker` 都视为外部（I-4）。`Connection: CF-Worker` 藏不住该头（§1.2 Phase 1 处理顺序第 ③ 步）。
- 待实测（规格 [§19](impl/phase1-spec.md#19-待实测与未决)）：访客自己发送的 `CF-Worker` 头是否被 Cloudflare 删除或覆盖。不删除时，访客只能让自己的请求被 403，不能借此得到更宽松的处理。

### 2.3 信号转发 Tier 0：Request Header Transform Rule

所有套餐可用，不产生费用。一条规则（`ref` = `mg_signals_v1`）写入 `http_request_late_transform` 阶段，用动态值设置下列头；模板见 `adapters/cloudflare/transform-rule.request-headers.json`。

| 头 | 表达式 | 用途 | 说明 |
|---|---|---|---|
| `x-mg-cf-tls-version` | `cf.tls_version` | EDGE_TLS | 例 `TLSv1.2` |
| `x-mg-cf-tls-cipher` | `cf.tls_cipher` | EDGE_TLS | |
| `x-mg-cf-tls-ciphers-sha1` | `cf.tls_ciphers_sha1` | EDGE_TLS | 按接收顺序的密码套件列表 SHA-1，Base64。Transform Rules 字段表另写作 `cf.tls_client_ciphers_sha1`，哪一个被接受**需实测** |
| `x-mg-cf-tls-ext-sha1` | `cf.tls_client_extensions_sha1` | EDGE_TLS，仅 shadow | 排序与 GREASE 处理未文档化；实测稳定前不得用于绑定或高权重 |
| `x-mg-cf-tls-hello-len` | `to_string(cf.tls_client_hello_length)` | EDGE_TLS | 按区间分桶使用 |
| `x-mg-cf-tls-random` | `cf.tls_client_random` | `client_conn_key = hash(value)` | 32 字节，Base64；每个访客 TLS 连接的临时标识，用于"每连接请求数"类特征；只在内存与近线中使用，不进入事件 |
| `x-mg-cf-http-version` | `http.request.version` | HTTP | 例 `HTTP/1.1`、`HTTP/3` |
| `x-mg-cf-rtt` | `to_string(cf.timings.client_tcp_rtt_msec)` | NETWORK 弱信号 | 仅 TCP 客户端有值 |
| `x-mg-cf-quic-rtt` | `to_string(cf.timings.client_quic_rtt_msec)` | NETWORK 弱信号 | 仅 QUIC 客户端有值 |
| `x-mg-cf-asn` | `to_string(ip.src.asnum)` | 与本地 ASN 库交叉核对 | 本地 GeoLite2 为准 |
| `x-mg-cf-vbot` | `to_string(cf.client.bot)` | 05 爬虫佐证 | MorphGate 自己的 IP 段 / rDNS / Web Bot Auth 验证为准 |
| `x-mg-cf-vbot-cat` | `cf.verified_bot_category` | 05 爬虫佐证 | |
| `x-mg-cf-hdr-names` | `join(http.request.headers.names, ",")` | HTTP 头集合 | 名称保留原大小写，**顺序不保证**，只当集合用；重复头会重复出现；头过多时截断（`http.request.headers.truncated`） |

同一条规则还：

- `remove` Tier 1 头名 `x-mg-cf-priority`、`x-mg-cf-accept-encoding`、`x-mg-cf-as-org`、`x-mg-cf-t1`：Tier 1 未运行（未启用或 fail-open）时，这些名字不会带着客户端伪造的值到达 Edge。Snippet 在 Request Header Transforms 之后执行（有文档）；Worker 与 Transform Rule 的先后顺序**需实测**。
- 上游密钥头不在这条规则里：启用 `upstream_keys` 时另部署一条只设置 `x-mg-upstream-key` 的规则（`ref` = `mg_upstream_key_v1`，§2.1），密钥与信号规则分开，轮换只改那一条；值不进仓库，`mgctl cf audit` 从不打印它，发现模板占位符时报错。
- 表达式必须覆盖该站点的全部主机名（模板用 `true` 覆盖整个 zone，也可写 `http.host in {...}`，主机名必须小写：字符串比较区分大小写），否则未覆盖的主机名上客户端可以自带 `x-mg-cf-*`。`mgctl cf audit` 检查覆盖范围。

另开启 Managed Transform "Add visitor location headers"（`add_visitor_location_headers`），得到 `cf-ipcountry`、`cf-ipcity`、`cf-ipcontinent`、`cf-iplatitude`、`cf-iplongitude`、`cf-region`、`cf-region-code`、`cf-metro-code`、`cf-postal-code`、`cf-timezone`。`cf-ipcountry` 为 ISO-3166-1 alpha-2，外加 `XX`（无数据）和 `T1`（Tor）。`cf-timezone` 与 SDK 上报的时区对比，作为弱地理一致性信号；本地 IP 库仍为权威。这些头只在 `mgctl cf audit` 确认该 Managed Transform 已开启时采信。Phase 1 以站点 YAML 的 `cloudflare.location_headers: true` 表示已确认，只解析 `cf-ipcountry`（`XX` 视为缺失，`T1` 另作为 `net.tor` 的来源之一）、`cf-region-code`、`cf-timezone`，其余位置头（城市、经纬度、邮编等）一律丢弃。

**约束**

| 项 | 内容 |
|---|---|
| 头名 / 值 | 头名只能含 `[A-Za-z0-9-_]`，不能以 `cf-` / `x-cf-` 开头；值为受限字符集，最长 4 KB |
| Set 语义 | 覆盖客户端同名头；表达式结果为空串或 undefined 时删除该头 |
| 不可修改 | `x-forwarded-for`、`true-client-ip`、`x-real-ip`、`x-forwarded-proto` 与 `Accept-Encoding` 等 forbidden header；`cf-connecting-ip` 是唯一可删除的 `cf-` 头（不要删） |
| 同阶段 | 字段值不可变：后面的规则匹配的仍是原始值 |
| 配额 | 见 §2.12；正则需 Business 及以上；Tier 0 占 1 条 |
| 套餐可用性 | TLS、timings、ASN、verified bot 字段在字段参考中无套餐标注，"Add visitor location headers" 的可用性同样是推断 → **需实测**：`GET /zones/{id}/managed_headers` 只返回本套餐可用的项 |
| `accept-encoding` | 规则内 `http.request.headers["accept-encoding"]` 返回原值还是改写后的 `br, gzip` 未文档化 → 不依赖 |

**Edge 端校验**（Phase 1，[规格 §9.3](impl/phase1-spec.md#93-头部清洗与可信头解析wp-c1-实现wp-e1a-接线) 的解析表）：每个头只接受规定格式（例如 `x-mg-cf-tls-ciphers-sha1` 为解码后 20 字节的 base64，`x-mg-cf-asn` 为 1–4294967295，`x-mg-cf-rtt` 的 `0` 视为缺失），非法值按缺失处理；`x-mg-cf-tls-random` 只校验，不进入任何结构、日志或事件（`client_conn_key` 在 Phase 2 的近线使用）；`x-mg-cf-hdr-names` 每项 1–64 个 token 字符、至多 128 项。`mgctl cf audit` 第 6 项接受 `ciphers_sha1` 的两种拼写。

**API**：`PUT /client/v4/zones/{zone_id}/rulesets/{ruleset_id}` 会整体替换该阶段的规则列表，`mgctl` 以 `ref` 前缀 `mg_` 识别自己的规则并保留其他规则。Managed Transform 用 `PATCH /client/v4/zones/{zone_id}/managed_headers`：`add_visitor_location_headers` 开启，`remove_visitor_ip_headers` 关闭。

### 2.4 信号转发 Tier 1：Snippet / Worker（可选）

Tier 0 拿不到的值只存在于 `request.cf`。实现见 `adapters/cloudflare/snippet/mg-signals.js` 与 `adapters/cloudflare/worker/`（两者逻辑相同）。

| 头 | 来源 | 用途 |
|---|---|---|
| `x-mg-cf-priority` | `request.cf.requestPriority`（浏览器 HTTP/2 优先级，如 `weight=192;exclusive=0;group=3;group-weight=127`） | HTTP 族弱信号（与声明浏览器对比） |
| `x-mg-cf-accept-encoding` | `request.cf.clientAcceptEncoding`（改写前的原值） | 恢复 Accept-Encoding 一致性检测 |
| `x-mg-cf-as-org` | `request.cf.asOrganization`（UTF-8 百分号编码，Edge 解码） | Console 展示、与本地库交叉核对 |
| `x-mg-cf-t1` | 固定值 `snippet` / `worker` | 标明 Tier 1 已运行；缺少时其余 Tier 1 头一律按 `MISSING` 处理 |

Phase 1：只在站点 YAML `cloudflare.tier1: true` 且 `x-mg-cf-t1` 有效时解析；`x-mg-cf-as-org` 只记录，写在决定事件的顶层字段 `upstream_as_org`。

| 载体 | 套餐 | 限制 | 选择 |
|---|---|---|---|
| Snippet | Pro 及以上（数量见 §2.12） | 5 ms 执行、2 MB 内存、32 KB 代码包；子请求 Pro 2 / Business 3 / Enterprise 5；无 secret、无 KV / DO；不参与 Version Management | Pro 及以上首选，零边际成本；规则表达式限定范围，例如 `http.request.headers["sec-fetch-dest"][0] == "document" or starts_with(http.request.uri.path, "/__mg/")` |
| Worker | Workers Free：100,000 请求/天、10 ms CPU；Paid：$5/月起，含 1,000 万请求，超出 $0.30/百万 | 在缓存之前运行，路由命中的每个请求都计费（含静态资源）；超出 Free 额度时按配置 fail closed（Error 1027）或 fail open（跳过 Worker） | Free zone 使用；路由只挂 `/__mg/*` 与少量关键 HTML 路径 |

- 每个头要么取 Cloudflare 的值，要么删除，绝不透传客户端的值；从不修改 `x-real-ip`（同 zone 子请求中它会成为 `CF-Connecting-IP`）。
- Worker fail-open、未命中路由或超出额度时 Tier 1 头缺失 → `MISSING`，不作为通过或风险证据。Worker 子请求带 `CF-Worker`（§2.2）。
- **Tier 2**（Enterprise Bot Management 的 `cf-ja4`、`cf-ja3-hash`、`cf-bot-score`、`cf-verified-bot`，即 Managed Transform `add_bot_protection_headers`）超出预算，不规划。
- 在 Worker 中以 WASM 运行 Decision Core 属于后期选项，见 [01](01-architecture.md) §9 与 [ADR-0003](adr/0003-upstream-profile-cdn-first.md)。

### 2.5 在 Cloudflare 之后失真的信号

Cloudflare 终止访客连接，再自建连接回源。以下信号在 `cloudflare` profile 下为 `MISSING`（不在 `expected_mask` 中，绝不当作人类证据）：

| 信号 | 源站看到的 | 处理 |
|---|---|---|
| JA4 / JA3 | Cloudflare（或 cloudflared）自己的 ClientHello。访客 JA4 只以 `cf.bot_management.ja4` 提供，需 Enterprise + Bot Management；即使有，明文 HTTP、跳过 BM、TLS 会话恢复时也为空 | `MISSING`；`bind.tfp` 不可用；`bind.ctp` 仅 shadow，稳定性达标（≥ 99%）后才可转为软绑定（见 [04](04-challenge-and-tokens.md)） |
| HTTP/2 / HTTP/3 帧指纹 | 回源连接的帧参数 | `MISSING`；HTTP/2 帧级指纹在个人版无限期推迟 |
| 请求头顺序 | 不保证顺序 | `MISSING`；头**集合**用 `x-mg-cf-hdr-names`（剔除 Cloudflare 自加头） |
| 请求头大小写 | 回源走 HTTP/2 时全小写；Cloudflare 也可能改用别的大小写 | `MISSING`（边缘名称字段保留原大小写，只在 shadow 中研究） |
| TCP 特征（TTL、窗口、MSS） | 不可见 | `MISSING` |
| `Accept-Encoding` | 恒为 `br, gzip` | `MISSING`；Tier 1 可恢复 |
| `Connection` | 恒为 `Keep-Alive`（HTTP/2、HTTP/3 客户端也一样） | `MISSING` |
| 访客 TLS 客户端证书 | 不可见（TLS 终止在 Cloudflare） | Agent / API 的 mTLS 认证只在 `direct_tls` 监听器上可用 |
| 下游连接 | "HTTP/2 to Origin" 所有套餐默认开启（源站须通过 ALPN 声明 h2）；Free / Pro / Business 的多路复用不可关闭（每连接并发流文档写 100 或 200，两处不一），空闲超时 900 s | **不得以下游连接作为任何状态的键**；每连接类特征用 `client_conn_key = hash(x-mg-cf-tls-random)` |
| 含 `.` 等非法字符的头名 | 可能被丢弃 | 不依赖 |
| Web Bot Auth 签名 | `Signature` / `Signature-Input` 原样到达；若签名覆盖了被改写的头（如 `accept-encoding`）则验证失败 | 见 [05](05-ai-agent-policy.md) |

新增弱信号族 **`EDGE_TLS`**（来自 `x-mg-cf-tls-*`）：以 TLS 版本、cipher、密码套件列表哈希、ClientHello 长度分桶与声明浏览器家族做一致性检查；低权重、低族上限，先 shadow，评分见 [03](03-risk-scoring.md) §3.4。扩展哈希的稳定性未文档化，不得用于硬绑定或高权重；`cf.tls_*` 在 HTTP/3 与 TLS 会话恢复时是否有值也未文档化，需实测。

超时约束：Cloudflare 回源读超时 125 s（超时返回 524），握手超时 19 s（522）。因此 `cloudflare` profile 下 TARPIT 不作为默认动作（延迟会占用被多个访客共享的回源连接），只在 `direct_tls` 下可选（见 [03 §5](03-risk-scoring.md#5-分级处置)）。

### 2.6 缓存

Cloudflare 默认行为（Free / Pro / Business）：

| 情况 | 行为 |
|---|---|
| HTML、JSON | 默认不缓存 |
| `.js`、`.css`、图片、字体、压缩包、`robots.txt` | 按扩展名默认缓存 |
| 无 Cache-Control / Expires 时的默认边缘 TTL | 200 / 206 / 301：120 分钟；302 / 303：20 分钟；404 / 410：3 分钟；其他状态码不缓存 |
| Origin Cache Control（OCC） | Free / Pro / Business **始终开启**（Enterprise 可关）。`no-store` → 不缓存；`no-cache` 与 `max-age=0` → **缓存**并每次回源校验 |
| 默认缓存级别 + `Set-Cookie` | OCC 开启时不缓存并保留 `Set-Cookie`（BYPASS） |
| Cache Rule "Eligible for cache"，未覆盖 TTL | 保留 `Set-Cookie`，不缓存（每次 MISS） |
| "Eligible for cache" + 覆盖 Edge TTL（`override_origin` 或 Status code TTL） | **剥离 `Set-Cookie` 并缓存**：每用户的 Challenge 或凭证响应会发给其他用户，且丢失 Cookie |
| 多条 Cache Rule 同时匹配 | 可叠加；设置冲突时**最后一条匹配规则胜出** |

MorphGate 的规则（[04](04-challenge-and-tokens.md) 与 `adapters/cloudflare/cache-rule.bypass-mg.json` 与本节一致）：

| # | 规则 |
|---|---|
| 1 | `/__mg/s/{build}.js`（内容哈希构建）发送 `Cache-Control: public, max-age=31536000, immutable`，允许边缘缓存；其余所有 `/__mg/*` 与所有 Challenge / 拦截页发送 `Cache-Control: no-store, private` |
| 2 | Challenge 使用 403 / 429，不用 200：两者不在默认缓存 TTL 列表中 |
| 3 | 一条 Cache Rule（`ref` = `mg_bypass_mg_paths`）设为 Bypass cache，表达式 `starts_with(http.request.uri.path, "/__mg/") and not starts_with(http.request.uri.path, "/__mg/s/")`（语法**需实测**），放在所有 Cache Rule 的**最后**；以后新增的 Cache Rule 插在它之前。站点把 `/__mg/` 配成随机前缀时（见 [02](02-data-flow.md) §3），规则由 `mgctl` 按实际前缀生成 |
| 4 | 覆盖可能返回 Challenge 的 HTML 路径的 "Eligible for cache" 规则不得带 `override_origin` 或 Status code TTL（控制面审计） |
| 5 | SDK 在同源 fetch 中读到 `/__mg/*` 响应的 `cf-cache-status` 为 `HIT` 时立即上报告警（Phase 2 的 SDK 功能；Phase 1 在 monitor 周人工抽查）。Bypass 规则生效时为 `DYNAMIC`；`BYPASS` 表示在响应阶段才决定不缓存，例如 Eligible 规则遇到源站 `no-store` |

`mgctl cf audit` 第 13 项（Phase 1）把叠加的规则当作整体判断：一条规则设 Eligible for cache、另一条只覆盖 Edge TTL，对两者都匹配的请求同样是陷阱。只按静态扩展名限定、且为纯合取（没有 `or` / `xor`，否定不包住扩展名条件）的表达式才算"静态"；确认过的例外用 `--ack ttl_override_trap:<rule ref>=<说明>` 登记覆盖 Edge TTL 的那条规则。

Speed Brain 在 Free 上默认开启：预取只从缓存返回、不到达源站，也不预取不可缓存的 HTML 或运行 Worker 的路由，不会在 Edge 产生"无交互导航"的假事件，保持默认即可。

### 2.7 与 Cloudflare 自带功能共存

安全阶段执行顺序：custom rules（`http_request_firewall_custom`）→ rate limiting（`http_ratelimit`）→ managed rules（`http_request_firewall_managed`）→ Super Bot Fight Mode（`http_request_sbfm`）。custom rules 的 Skip 动作可以跳过后面三个阶段，并可通过 `products` 跳过 Ruleset Engine 之外的功能（`bic`、`securityLevel`、`uaBlock`、`zoneLockdown`、`hot` 等）。Bot Fight Mode 不能被跳过。

| 功能 | 套餐 | 建议 | 原因 |
|---|---|---|---|
| Bot Fight Mode | Free | **关闭** | 不运行在 Ruleset Engine 上，Skip / Allow 规则都无效，不能按路径排除；会强制开启 JS Detections、注入 `/cdn-cgi/challenge-platform/` 脚本，并可能挑战 API / XHR，在 `/__mg/*` 前插入不可控的挑战 |
| Super Bot Fight Mode | Pro（Definitely automated）；Business 及以上（+ Likely automated） | 各组设为 Allow；或保留并加 Skip 规则（下表）。用 Tunnel 时 Definitely Automated 必须为 Allow | 可按路径跳过；已不支持通过 Rulesets API 更新 SBFM 规则 |
| Managed Challenge / JS Challenge 规则 | 所有套餐 | 不覆盖 MorphGate 挑战的路径 | 双重挑战；Cloudflare 也警告挑战与 Rules 功能组合可能形成挑战循环 |
| Precursor | 未写明（需确认） | 关闭 | Maximize Security 模式要求有效 `cf_clearance`，不带 Cookie 的 fetch 会失败 |
| Rocket Loader | 所有套餐 | 关闭，或给 SDK / Challenge 脚本标签（及其依赖脚本）加 `data-cfasync="false"` | 会延迟并改写脚本加载，干扰计时与完整性检查 |
| 0-RTT Connection Resumption | 所有套餐，默认关闭 | 首选保持关闭（API 设置名 `0rtt`）。若开启，`/__mg/*` 的状态变更端点对 `Early-Data: 1` 返回 425（Cloudflare 是否透传 425 **需实测**），见 [04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt)（含 Phase 1 的实现语义） | 0-RTT 只存在于客户端与 Cloudflare 之间，只覆盖 GET / HEAD / OPTIONS；开启时源站看到 `Early-Data: 1` |
| Pseudo IPv4 | 所有套餐，默认关闭 | 保持关闭 | 见 §2.2 |
| Remove visitor IP headers | Managed Transform | **必须关闭** | 否则拿不到客户端 IP |
| AI bot policies（Search / Agent / Training） | 所有套餐 | MorphGate 为唯一权威时设为 Allow | 2026-09-15 起新 zone 默认在有广告的页面上阻止 Training 与 Agent（Search 仍允许）；混合 Search + Training 的爬虫会被任何训练阻止配置拦下；旧的 "Block AI bots" 开关已弃用。不改则 Cloudflare 先在边缘拦截，MorphGate 看不到也记录不到。需要在边缘省流量时，由控制面把 [05](05-ai-agent-policy.md) 的同一份策略下推为 Cloudflare 规则（Free 只有 5 条 custom rules） |
| AI Labyrinth、managed robots.txt | Free 起 | 由 [05](05-ai-agent-policy.md) 管理 robots.txt 时关闭 | 单一权威；两者叠加的行为需确认 |
| 限速规则 | Free 1 / Pro 2 / Business 5 | Free 的唯一一条用于在边缘挡 `/__mg/` 提交端点的洪泛（Free 只能按 Path 匹配，能否按方法需实测）；有这条规则时 Skip 规则不得跳过 `http_ratelimit` | Free：只能用 Path 与 Verified Bot 字段，按 IP 计数，周期与封禁均为 10 s；Pro 周期最长 1 分钟；Business 最长 10 分钟并支持 IP + NAT 计数 |

**`/__mg/` Skip 规则**（custom rule，`ref` = `mg_skip_mg_paths`，表达式 `starts_with(http.request.uri.path, "/__mg/")`，模板 `adapters/cloudflare/waf-skip.mg.json`）：让 SDK 对 MorphGate 端点的 XHR / fetch 不会收到 Cloudflare 的 HTML 挑战。

| 套餐 | `phases` | `products` |
|---|---|---|
| Free（没有 SBFM） | 不填 | `bic`、`securityLevel` |
| Pro 及以上 | `http_request_sbfm`；**仅当**没有 `/__mg/` 洪泛限速规则时才可再加 `http_ratelimit`（否则该限速规则一起失效） | `bic`、`securityLevel` |

- Skip 规则必须排在任何可能对 `/__mg/` 执行 Block / Challenge 的自定义规则之前。
- Cloudflare 的 Cookie（`__cf_bm`、`cf_clearance`、`_cfuvid`、`__cflb`、`__cfseq`、`__cfwaitingroom`）不作为 MorphGate 的任何证据，基于 Cookie 的信号应忽略它们。

### 2.8 `cf-mitigated` 与双重挑战

Cloudflare 的所有挑战页响应都带 `cf-mitigated: challenge`（该头唯一的取值），`content-type` 为 `text/html`。SDK 对 `/__mg/*` 或受保护 fetch 收到该头时视为"上游挑战"：

1. SDK 记 `upstream_challenge=1`，顶层重载当前页面（导航请求）。
2. 访客在 Cloudflare 挑战页完成挑战后，页面与 SDK 经 Edge 正常加载。
3. SDK 以 `POST /__mg/t {upstream_challenge: 1}` 上报。

- 不计入 MorphGate Challenge 失败率，不触发失败计数，也不触发"SDK 从未运行"信号（[03](03-risk-scoring.md)）。
- 计入 `mg_double_challenge_total`；Console 按站点、路由、国家展示。计数持续非零说明 §2.7 的某项配置有冲突。
- Web SDK 的实现属于 Phase 2（见 [04 §7](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)）；`mg_double_challenge_total` 随之出现。Phase 1 靠 `mgctl cf audit` 第 9、10、11、14 项预防双重挑战。

### 2.9 可选：HMAC Cookie 跳过（Pro 及以上）

Phase 1 未实现（仅在双重挑战计数确实出现后才考虑）。

用途：Pro 及以上保留 SBFM / Security Level / 限速时，让已通过 MorphGate 的会话不再被 Cloudflare 重复挑战。依赖 `is_timed_hmac_valid_v0()` 与 `http.request.cookies`，两者都需要 Pro / Business / Enterprise。仅在双重挑战计数确实出现后启用。

| 项 | 规范 |
|---|---|
| Cookie | `__Host-mg_cfp`（`Secure; HttpOnly; SameSite=Lax; Path=/`），签发凭证时一并设置 |
| 值 | MessageMAC 格式 `{sid}{ts}-{mac}`：`sid` 为 22 字符 base64url 随机值，分隔符长度为 0，`ts` 为 10 位 Unix 秒，`mac = base64url_nopad(HMAC-SHA256(K_cf, sid ‖ ts))`（43 字符）。MAC 计算方式以 Cloudflare "HMAC token generation" 文档为准，**需实测** |
| 密钥 `K_cf` | 独立密钥，不同于任何凭证密钥。它以字符串字面量写在 Cloudflare 规则里，有 zone 读权限的人都能看到，因此只授权"跳过 Cloudflare 的通用 Bot 功能"；MorphGate 仍对每个请求校验自己的 PASETO 凭证 |
| TTL 与轮换 | 不长于对应的 MorphGate 凭证（如 1800 s）；轮换期间规则同时接受新旧两个 key（两个函数调用用 `or` 连接） |
| 规则 | `ref` = `mg_skip_cleared`；表达式 `is_timed_hmac_valid_v0("<K_cf>", http.request.cookies["__Host-mg_cfp"][0], 1800, http.request.timestamp.sec, 0, "s") and not starts_with(http.request.uri.path, "/__mg/")`；`phases`：`http_request_sbfm`、`http_ratelimit`；`products`：`securityLevel`、`bic`。排除 `/__mg/` 是为了让洪泛限速规则对其继续生效（`/__mg/` 已由 `mg_skip_mg_paths` 处理） |

### 2.10 `mgctl cf audit`

Go 控制面通过 Cloudflare API 检查每个 zone，输出表格；有"错误"级别项时退出码非零，失败项计入 `mg_cf_audit_failed_checks`（zone、check）。Phase 1 验收要求全绿。

Phase 1 由所有者在工作站运行 `mgctl cf audit --site-config <site.yaml> [--cf-ips <工件>] [--vm-url <url>] [--sdk-dir <dir>]`（只读 token `CLOUDFLARE_API_TOKEN`；User-Agent `morphgate-dev-tooling`，I-15）。每项的状态为 `pass`、`fail`、`warn`（警告 / 提示级失败）、`manual`（token 权限不足或没有读取接口；在 Dashboard 确认后用 `--ack <id>=<说明>` 记为已确认）或 `skip`；任一错误级 `fail`（`--strict` 时含 `manual`）→ 退出码 1。`--json` 输出机器可读结果，`--metrics-textfile` 写 `mg_cf_audit_failed_checks{zone, check}` 与 `mg_cf_audit_last_run_timestamp_seconds{zone}`。判定细节见 [规格 §14.3](impl/phase1-spec.md#143-mgctl-cf-auditwp-g3)。

| # | id | 期望 | 数据来源 | 级别 |
|---|---|---|---|---|
| 1 | `origin_protection` | Tunnel 为 healthy（站点 YAML 给出 `account_id` / `tunnel_id` 时，否则 manual）；或 zone-level / 每个主机的 per-hostname AOP 已启用，且不是只有全局 AOP | `cfd_tunnel`、`origin_tls_client_auth`（settings、hostnames）、`settings/tls_client_auth` | 错误 |
| 2 | `ssl_mode` | AOP 时为 Full 或 Full (strict) | `settings/ssl` | 错误 |
| 3 | `aop_cert_expiry` | AOP 客户端证书剩余 ≥ 30 天 | `origin_tls_client_auth` 证书列表 | 警告 |
| 4 | `remove_visitor_ip_headers` | 关闭 | `managed_headers` | 错误 |
| 5 | `visitor_location_headers` | 站点 `location_headers: true` 时已开启 | 同上 | 警告 |
| 6 | `transform_rule_signals` | `mg_signals_v*` 存在且启用；13 个 Tier 0 头的表达式与模板一致（`ciphers_sha1` 两种拼写都接受）；4 个 Tier 1 头名为 `remove`；表达式为 `true` 或覆盖站点全部主机名；上游密钥规则 `mg_upstream_key_v1` 的值不是模板占位符（值从不打印） | `http_request_late_transform` 入口规则集 | 错误 |
| 7 | `pseudo_ipv4` | `off`，或 `overwrite_header` 且站点 `pseudo_ipv4_overwrite: true` | `settings/pseudo_ipv4` | 错误 |
| 8 | `zero_rtt` | `off`（若开启，Edge 按 [04 §4.3](04-challenge-and-tokens.md#43-early-data0-rtt) 返回 425） | `settings/0rtt` | 警告 |
| 9 | `bot_fight_mode` | Free 上 `fight_mode` 为 false；读取被拒时 manual | `bot_management` | 错误 |
| 10 | `sbfm_skip` | Pro+ 的 SBFM 各组 Allow，或 `mg_skip_mg_paths` 覆盖 `/__mg/` 且 `phases` 含 `http_request_sbfm`；Tunnel 时 Definitely Automated 必须 Allow | `bot_management`、custom rules | 错误 |
| 11 | `skip_rule_order` | `mg_skip_mg_paths` 排在所有 block / challenge 规则之前；有 `/__mg/` 洪泛限速规则时 Skip 不含 `http_ratelimit`；`mg_skip_cleared`（若有）排除 `/__mg/`（§2.9） | custom rules、`http_ratelimit` 入口规则集 | 警告 |
| 12 | `cache_bypass_mg` | 最后一条 Cache Rule 为 `mg_bypass_mg_paths`，动作 bypass，表达式同 §2.6 | `http_request_cache_settings` 入口规则集 | 错误 |
| 13 | `ttl_override_trap` | 没有"可缓存 + 覆盖 Edge TTL"且未只限定静态扩展名的规则；叠加规则按 §2.6 一并判断 | 同上 | 错误 |
| 14 | `cf_challenge_overlap` | 没有 challenge 类规则的表达式为 `true` 或提到站点路由路径；简单的 `not …` 排除项（如 `and not starts_with(…, "/__mg/")`）不算覆盖 | custom rules | 警告 |
| 15 | `rocket_loader` | `off`，或 `--sdk-dir` 模板的 SDK 标签带 `data-cfasync="false"` | `settings/rocket_loader` + 本地模板 | 警告 |
| 16 | `ai_bot_policy` | 与 [05](05-ai-agent-policy.md) 的单一权威一致：模式 A 全部 Allow；字段缺失时 manual | `bot_management` | 警告 |
| 17 | `precursor` | 关闭 | 没有读取接口：总是 manual，`--ack` 确认 | 警告 |
| 18 | `runtime_metrics` | 24 h 增量：`mg_cf_connecting_ip_missing_total`、`mg_upstream_auth_failures_total{reason="bad_secret_header"}`、`mg_cf_foreign_worker_total` 为 0（错误）；`mg_upstream_signal_missing_total` 缺失率 < 1%，不含 `hdr-names`（警告，I-12）；没有 `mg_requests_total` 样本时 warn，样本非有限值时失败；无 `--vm-url` 时 skip。`/__mg/*` 的 `cf-cache-status: HIT` 与 `mg_double_challenge_total` 在 Phase 2 由 SDK 提供 | VictoriaMetrics `/api/v1/query` | 错误 / 警告 |
| 19 | `ip_snapshot_age` | `--cf-ips` 工件旁 `.state.json` 的 `last_success` 在 48 小时内；无参数时 skip | 本地文件 | 警告 |
| 20 | `optional_rules` | 报告 `/__mg/` 洪泛限速规则是否存在 | `http_ratelimit` 入口规则集 | 提示 |
| 21 | `always_use_https` | 开启（`__Host-` 凭证 Cookie 只在 https 下保存，D-32）；另报告 HSTS 是否开启 | `settings/always_use_https` | 错误 |

第 11、14、20 项判断规则是否覆盖 `/__mg/` 时忽略简单的 `not …` 排除项，否定复合条件或无法解析的表达式按字面理解（仍算覆盖）；`mg_skip_cleared` 的表达式只要有顶层 `or` / `xor` 就视为没有排除 `/__mg/`。入口规则集返回 404 视为"没有规则"。测试全部用 `httptest` 伪造的 API（`control-plane/testdata/cloudflare/<scenario>/`）。

其他职责：

- **模板下发**（可选写权限）：`mgctl cf apply` 按 §2.3、§2.6、§2.7 生成并更新规则，只改 `ref` 以 `mg_` 开头的规则（Phase 3；Phase 1 由所有者按 [`adapters/cloudflare/README.md`](../adapters/cloudflare/README.md) 手工应用模板）。
- **Turnstile widget 管理**：见 [09 §8.1](09-interactive-challenge.md#81-widget-与控制面)。
- **API Token 最小权限**：审计只用 zone 级只读权限；启用 `apply` 时才加对应的写权限；Turnstile 只需 Turnstile Sites Write。zone 级权限的具体名称需确认。

### 2.11 IP 段同步

- 来源：`GET https://api.cloudflare.com/client/v4/ips`（无需认证），返回 `ipv4_cidrs`、`ipv6_cidrs`、`etag`；纯文本版在 `https://www.cloudflare.com/ips-v4` 与 `/ips-v6`。2026-09-27 为 15 个 IPv4 段、7 个 IPv6 段。只有购买 China Network 时才加 `?networks=jdcloud`（返回 `jdcloud_cidrs`，当日 90 条）。
- Cloudflare 很少变更 IP 段，新段先公布再启用。控制面每日拉取，按 etag 判断变化；校验格式与数量，数量突变时需人工确认；失败保留上一版并告警（超过 48 小时未成功同步即告警，[06 §5](06-policy-console-observability.md#5-日志指标与告警)）。结果推送到 Edge 可信代理快照（随签名配置包下发）和云安全组。
- AWS：路由目标为内部地址、且范围**宽于** 172.16.0.0/12 的 VPC 路由（如 172.x 的 /8 超网）会吞掉发往 172.64.0.0/13 的流量；恰好是 /12 的路由不重叠。控制面在 AWS 上检查路由表。
- Tunnel 模式下源站没有入站端口，IP 段主要用于 AOP 模式的安全组，以及识别异常来源。

**Phase 1 实现**（[规格 §12.2](impl/phase1-spec.md#122-cloudflare-ipsjson)、[§14.4](impl/phase1-spec.md#144-mgctl-cf-ips-syncwp-g3)）：所有者工作站上每日运行 `mgctl cf ips sync --out <file>`（`--url` 只接受 https；User-Agent `morphgate-dev-tooling`）。要求 `success == true`；按规格校验（IPv4 5–64 条、IPv6 2–32 条，规范网络地址，前缀长度 IPv4 8–32、IPv6 16–128，不与 I-13 的特殊地址段相交，文档段一律拒绝）；`etag` 不变时不改写工件，配置包里的工件哈希不会因每日同步而变化；条数变化超过 30% 时拒绝，确认后加 `--accept-change`；成功时写 `<out>.state.json`（`cf audit` 第 19 项读取），`--metrics-textfile` 写 `mg_cf_ips_sync_timestamp_seconds`（告警用 `time() - …` 得到同步年龄）。工件 `cloudflare-ips` 随签名配置包下发，Edge 用于 `origin_mtls` 监听器的 `cloudflare_ip_filter`。云安全组同步与 AWS 路由表检查未实现，由所有者手工维护。

### 2.12 套餐能力对照

| 能力 | Free | Pro | Business | Enterprise |
|---|---|---|---|---|
| Cloudflare Tunnel | Y | Y | Y | Y |
| AOP（全局 / zone-level / per-hostname） | Y | Y | Y | Y |
| Request Header Transform Rules | 10 | 25 | 50 | 300 |
| Transform Rule 中的 `cf.tls_*`、`cf.timings.*`、`ip.src.asnum`、`cf.client.bot` | 无套餐标注，需实测 | 同左 | 同左 | Y |
| Managed Transform：visitor location | 无限制说明，需实测 | 同左 | 同左 | Y |
| Managed Transform：bot protection headers（cf-ja4 等） | N | N | N | 需 Bot Management |
| `True-Client-IP` | N | N | N | Y |
| Snippets | N | 25 | 50 | 300 |
| Workers（账号级，与 zone 套餐无关） | Workers Free 或 Paid（$5/月起） | 同左 | 同左 | 同左 |
| WAF custom rules（含 Skip） | 5 | 20 | 100 | 1,000 |
| 限速规则 | 1（Path / Verified Bot，IP，10 s） | 2（IP，周期 ≤ 1 min） | 5（IP 或 IP + NAT，周期 ≤ 10 min） | 需确认 |
| Cache Rules | 10 | 25 | 50 | 300 |
| Origin Cache Control 可关闭 | N（常开） | N | N | Y |
| Bot 功能 | Bot Fight Mode（不可跳过） | SBFM：Definitely automated | SBFM：+ Likely automated | Bot Management（附加） |
| `is_timed_hmac_valid_v0()`、`http.request.cookies` | N | Y | Y | Y |
| 正则匹配 | N | N | Y | Y |
| AI bot policies | Y | Y | Y | Y |
| JA3 / JA4 / bot score | N | N | N | 需 Bot Management |
| China Network | N | N | N | 另购 + ICP |
| Precursor | 需确认 | 需确认 | 需确认 | 需确认 |

Turnstile 与 zone 套餐无关，额度见 [09 §8.1](09-interactive-challenge.md#81-widget-与控制面)。

### 2.13 中国大陆

- Cloudflare China Network（京东云机房）需要 Enterprise、单独订阅，且每个顶级域名都要有 ICP 备案。个人预算不考虑。
- 没有 China Network 时，大陆访客访问境外数据中心，Cloudflare 文档写明这条路径存在明显的延迟与可靠性问题 → Challenge 路径保持第一方、轻量（SDK ≤ 30 KB gzip），不依赖第三方域名。
- Turnstile 官方声明不支持中国大陆（China Network zone 与全局 zone 都不支持）→ 大陆访客永不选用（[09](09-interactive-challenge.md)）。Cloudflare 自己的挑战页在全局 zone 下对大陆访客是否受同样影响没有文档说明（需确认），这也是不叠加 Cloudflare 挑战的原因之一。
- 源站区域默认香港 / 东京 / 新加坡。ICP 备案只针对大陆服务器；阿里云会阻断解析到其大陆服务器的未备案域名。源站需能访问 `challenges.cloudflare.com` 才能调用 Turnstile siteverify，这三个区域没有问题。
- 站点已备案并使用境内 CDN 时：ESA 与 EdgeOne 的"中国内地"或"全球"加速区域都要求 ICP，否则只能选"全球（不含中国内地）"。非 Enterprise 套餐下只能拿到 IP + 地理，需另配 `esa` / `edgeone` profile 并走独立监听器（例如国际流量走 Cloudflare、境内流量走 ESA）。

## 3. 其他 CDN 与云负载均衡

本节只写入设计，不在 Phase 1 实现（见 [07](07-roadmap.md) Phase 4）。

### 3.1 信号可用性

图例：Y = 有文档且可转发到源站；E = 仅 Enterprise / 付费附加；R = 只能在该厂商自己的规则 / WAF 中使用，不可转发；N = 不提供；? = 未确认。"本地"表示 Edge 用自有 GeoLite2 查询，不依赖上游。

| 上游 | 客户端 IP（+端口） | JA3 | JA4 | TLS 版本 / cipher | HTTP 版本 | 头顺序 / 数量 | ASN | 地理 |
|---|---|---|---|---|---|---|---|---|
| Cloudflare（Free–Business） | Y `CF-Connecting-IP` | E | E | Y（Transform Rule） | Y（Transform Rule） | N（仅名称集合） | Y（Transform Rule） | Y（visitor location） |
| AWS CloudFront | Y `CloudFront-Viewer-Address`（ip:port） | Y | Y | Y `CloudFront-Viewer-TLS` | Y | **Y**（唯一能恢复头顺序的 CDN） | Y | Y |
| GCP 外部 ALB（全局 / 经典） | Y `{client_ip_address}` `{client_port}` | Y | Y | Y | Y `{client_protocol}` | N | Y `{asn}` | Y（含城市） |
| GCP 外部 ALB（区域） | Y | Y | Y | Y | Y | N | **N** | 部分（无城市、城市经纬度、region_subdivision） |
| AWS ALB | Y XFF（可选端口） | R（仅 AWS WAF） | R（仅 AWS WAF） | Y `x-amzn-tls-version` / `x-amzn-tls-cipher-suite`（属性默认关闭） | N | N | N | N |
| 阿里云 ESA | Y `ali-real-client-ip`（可改名） | E `Tls-Ja3` | E `Tls-Ja4` | E `Tls-Hash`（语义未文档化） | ? | N | N | Y `ali-ip-country` / `ali-ip-city` |
| 腾讯云 EdgeOne | Y `EO-Connecting-IP` / 自定义客户端 IP 头 / `${http.request.ip}` `${http.request.ip.port}` | R（Web 防护，需 Bot 管理） | R（仅限速统计维度） | N | Y `http.request.version` | N | R（规则内）；边缘函数 `request.eo.geo.asn` 可转发 | Y 自定义国家头、城市变量 |
| 阿里云 CDN | Y `Ali-Cdn-Real-Ip` + `$http_Ali_Cdn_Real_Port` | N | N | N（仅 `X-Client-Scheme`） | N | N | N | N |
| 腾讯云 CDN | Y XFF、`X-Forward-Port`；变量 `$client_ip`、`$remote_port` | N | N | N | N | N | N | N |
| Envoy ≥ 1.35（自建） | Y | Y | Y | Y | Y | N | 本地 | 本地 |
| OpenResty ≥ 1.29.2.1 + lua-resty-ja4 | Y | 模块 | Y | Y | Y | N | 本地 | 本地 |
| Traefik / Caddy / APISIX / Kong | Y | N | N（Caddy 仅第三方模块） | — | — | N | 本地 | 本地 |

结论：非 Enterprise 下能把访客 JA4 转发到源站的托管上游只有 CloudFront 与 GCP 外部 ALB；ESA / EdgeOne 把 JA3 / JA4 放在 Enterprise 后面，或只在其自身规则里可用。对只有 IP + 地理的上游，更依赖 Web SDK、Challenge、凭证 / PoW 成本与限速，缺失的 JA4 永不视为人类证据。

### 3.2 认证方式

| 上游 | mTLS（源站校验客户端证书） | 密钥头 | 回源 IP 列表（只做安全组） |
|---|---|---|---|
| CloudFront | 源站 mTLS（2026-02-02 发布）：仅 Business / Premium 固定费率套餐或按量付费，Free 不可用；证书由 AWS Private CA 或第三方私有 CA 签发，EKU clientAuth，RSA-2048 或 ECDSA P-256，导入 us-east-1 的 ACM，无自动续期；只在源站请求时发送；链深度 ≤ 3；不支持 WebSocket、gRPC、VPC origins、Lambda@Edge 回源触发器、embedded POP；源站须出示公网可信证书 | 自定义源站头（CloudFront 覆盖查看器发来的同名头） | 托管前缀列表 `com.amazonaws.global.cloudfront.origin-facing`（及 IPv6 版）或 `ip-ranges.json` 的 `CLOUDFRONT_ORIGIN_FACING`（2026-09-27：IPv4 46 条、IPv6 35 条）；只证明"来自某个 CloudFront 分发" |
| GCP 外部 ALB | 后端 mTLS：全局与区域均支持，全局 internet NEG 后端不支持 | 自定义请求头（LB 覆盖同名头） | 需确认 |
| ESA | 回源客户端证书：站点级 `UploadSiteOriginClientCertificate` / `GetSiteOriginClientCertificate`，主机名级 `GetOriginClientCertificate` + `SetOriginClientCertificateHostnames`；测试可用自签名；套餐限制需确认 | 规则设置自定义头 | Origin Protection（Pro / Premium / Enterprise，不含 Entrance）；可用 `GetOriginProtection`（含 `DiffIPWhitelist`、`NeedUpdate`）与 `UpdateOriginProtectionIpWhiteList` 自动化。Functions / Pages 的 `fetch()` 仍使用整合前的节点 IP |
| EdgeOne | 回源 mTLS 在 API 中存在（`UpstreamCertInfo.UpstreamMutualTLS`），套餐与配置页需确认 | 修改回源请求头 | Origin Protection 仅付费套餐；`DescribeOriginProtection`（关注 `NextOriginACL`）；平均 3–6 个月变更一次，提前 14 / 7 / 3 / 1 天通知，14 天后自动切换且回源失败不计入 SLA；列表可能含少量非 EdgeOne IP |
| 阿里云 CDN | N | 自定义回源头 | 仅日峰值 ≥ 1 Gbps 且提工单后可用 `DescribeL2VipsByDomain`；手工申请渠道已停止 → 个人站点实际拿不到 |
| 腾讯云 CDN | N | 自定义回源头（每域名最多 10 条规则，约 100 个标准头不可配置） | 控制台"回源节点查询"；旧 API `DescribeCdnOriginIp` 已弃用 |

通用规则：优先 mTLS（所有者自有私有 CA），其次密钥头（`x-mg-upstream-key`，双值轮换），IP 列表只做纵深防御。除 GCP ALB 与 CloudFront 自定义源站头外，其余上游是否覆盖客户端发来的同名信号头（`CloudFront-Viewer-*`、`Tls-Ja4`、`ali-real-client-ip`、`Ali-Cdn-Real-Ip`、`EO-Client-IP`）都未文档化，所以这些头必须在认证通过后才采信。控制面对需要手动导入的客户端证书（如 CloudFront 的 ACM 证书）做到期告警。

### 3.3 各上游要点

**CloudFront（`cloudfront`）**

- 需要自定义 origin request policy：所有查看器头 + 下表 10 个 CloudFront 头。每个策略的头配额是 10（可申请提高），每账号最多 20 个自定义策略；"所有查看器头"模式下 CloudFront-* 是否计入这 10 个需确认。托管策略 `AllViewerAndCloudFrontHeaders-2022-06` 只含 2022 年 6 月前发布的头，**不含** JA3、JA4、Header-Order、Header-Count，不能直接使用。TLS 类头、Viewer-Address 与 Viewer-ASN 只能放在 origin request policy 中（不能放在 cache policy 中），不进入缓存键。
- 全局 CloudFront 不服务中国大陆；CloudFront 中国区是独立服务，需要 ICP，JA3 / JA4 在那里是否可用未确认。VPC origins（无公网 IP 的源站）是另一种源站保护方式，不能与源站 mTLS 组合使用。

| 头 | 格式 / 解析 |
|---|---|
| `CloudFront-Viewer-Address` | `IP:源端口`，在最后一个 `:` 处切分；IPv6 的格式需实测 |
| `CloudFront-Viewer-ASN` | ASN |
| `CloudFront-Viewer-JA4-Fingerprint` / `-JA3-Fingerprint` | 仅 HTTPS |
| `CloudFront-Viewer-TLS` | `{version}:{cipher}:{fullHandshake\|sessionResumed\|connectionReused}` |
| `CloudFront-Viewer-Http-Version` | HTTP 版本 |
| `CloudFront-Viewer-Header-Order` | 按请求顺序、以 `:` 分隔的头名；超过 7,680 字符截断。HTTP/2、HTTP/3 下是否保留大小写和伪首部需实测 |
| `CloudFront-Viewer-Header-Count` | 头总数；与 Header-Order 数量不符或发生截断时产生 reason code |
| `CloudFront-Viewer-Country`、`CloudFront-Forwarded-Proto` | ISO 国家码、协议 |

**GCP 外部 ALB（`gcp_alb`）**

- 用自定义请求头注入变量；LB 覆盖同名头；每个后端服务最多 16 个自定义头、合计 8 KB；变量值未知时展开为空串。JA3 / JA4 在客户端使用 HTTPS、HTTP/2 或 HTTP/3 时才有值；JA4 于 2025-07-28 在全局外部 ALB GA。没有头顺序变量。
- 映射（11 个，含密钥头）：`x-mg-gcp-ja4: {tls_ja4_fingerprint}`、`x-mg-gcp-ja3: {tls_ja3_fingerprint}`、`x-mg-gcp-ip: {client_ip_address}`、`x-mg-gcp-port: {client_port}`、`x-mg-gcp-tls: {tls_version}`、`x-mg-gcp-cipher: {tls_cipher_suite}`、`x-mg-gcp-proto: {client_protocol}`、`x-mg-gcp-rtt: {client_rtt_msec}`、`x-mg-gcp-asn: {asn}`（仅全局 / 经典）、`x-mg-gcp-region: {client_region}`、`x-mg-upstream-key`。
- 直连后端的路径必须封死（后端 mTLS 或防火墙）。

**AWS ALB / Azure Application Gateway：不要放在 Edge 前面。** 两者都终止 TLS 且不转发 JA4：ALB 只能通过属性 `routing.http.x_amzn_tls_version_and_cipher_suite.enabled`（默认 false）转发 TLS 版本与 cipher，JA3 / JA4 只能在 AWS WAF 中匹配。在 AWS 上改用 NLB 直通或不用负载均衡（§4.2）。

**阿里云 ESA（`esa`）**

- Managed Transforms 可添加 `ali-real-client-ip`（默认名，可改；建议改成不易猜的名字，且只在认证后采信）、`ali-ip-country`、`ali-ip-city`、`Tls-Hash` / `Tls-Ja3` / `Tls-Ja4`（仅 Enterprise 站点有值）、`Esa-User-Risk`。
- `ali-real-client-ip` 是与 POP 建立 TCP 连接的客户端 IP；访客经 IPv6 POP 接入时为 IPv6（可关闭 IPv6 强制 IPv4）。
- 边缘函数运行时没有文档化的客户端 IP、地理、TLS 属性，不依赖它补充信号。L4 代理（PROXY v1 / v2 / Simple Proxy Protocol）仅 Enterprise。

**腾讯云 EdgeOne（`edgeone`）**

- 默认回源头：`EO-Connecting-IP`（连接 IP；访客走代理时是代理 IP）、`X-Forwarded-For`（追加，不能盲信）、`X-Forwarded-Proto`（http / https / quic）、`CDN-Loop`、`EO-LOG-UUID`；开启 Bot 管理时还有 `EO-Bot-Tag`（JSON，可作为外部参考）。
- 可按站点或按规则添加自定义客户端 IP 头（如 `EO-Client-IP`）与国家头（如 `EO-Client-IPCountry`，ISO alpha-2，不解析 IPv6）。
- "修改回源请求头"支持变量，例如 `x-mg-eo-port: ${http.request.ip.port}`。不可修改 `EO-Connecting-IP`、`X-Forwarded-For`、`Expect`、`EO-LOG-UUID`、`X-Tencent-Ua`；每个动作最多 30 个操作。
- ASN 只能通过边缘函数（`request.eo.geo.asn`）转发，增加成本与复杂度，可选。开启 Bot 管理后 L7 实时日志中有 JA3Hash / JA4Fingerprint，可按 `EO-LOG-UUID` 异步关联（离线用途）。L4 代理（PROXY v1 / v2）仅 Enterprise。

**阿里云 CDN（`alicdn`）/ 腾讯云 CDN（`tencent_cdn`）**：两者只映射客户端 IP 与端口，以密钥头认证，没有 TLS 信号。

| 上游 | 默认回源头 | 自定义头可用变量 | 建议 |
|---|---|---|---|
| 阿里云 CDN | `Ali-Cdn-Real-Ip`、`X-Forwarded-For`、`X-Client-Scheme`、`Via` | `$http_Ali_Cdn_Real_Port`、`$http_Ali_Cdn_Real_Ip`、`$proxy_add_x_forwarded_for` | 取 `Ali-Cdn-Real-Ip`（认证后） |
| 腾讯云 CDN | `X-Forwarded-For`、`X-Forwarded-Proto`、`X-Forward-Port`（固定为 `$remote_port`，不可改） | `$remote_port`、`$client_ip` | `x-mg-tc-ip: $client_ip`，不用 XFF |

## 4. 网关与 L4 负载均衡

### 4.1 网关

网关与 Edge 之间必须使用 mTLS（`origin_mtls`）；网关必须覆盖（而不是追加）`x-mg-gw-*` 头。

| 网关 | JA4 | 方式 | 建议 |
|---|---|---|---|
| Envoy ≥ 1.35 | Y | 监听过滤器 `envoy.filters.listener.tls_inspector` 设 `enable_ja4_fingerprinting: true`（1.35.0 新增，默认 false）；路由 / 虚拟主机级 `request_headers_to_add` 加 `x-mg-gw-ja4: "%TLS_JA4_FINGERPRINT%"`，`append_action: OVERWRITE_IF_EXISTS_OR_ADD`（字段以所用版本文档为准）。UDP 未实现，不覆盖 QUIC / HTTP/3 | 已在用 Envoy 时采用 `envoy` profile；Envoy 的 geoip 过滤器也可加国家 / 城市 / ASN 头，但 Edge 本地查询即可 |
| OpenResty ≥ 1.29.2.1 | Y | 第三方 lua-resty-ja4 0.2.0（MIT，2026-06-26）在 `ssl_client_hello_by_lua*` 中计算，经 `ngx.ctx` 传给请求阶段，再以头转发；文档未说明支持 HTTP/3 | 优先于 FoxIO ja4-nginx-module：后者需要打补丁重编 nginx，且采用 FoxIO License 1.1、包含 JA4+（与"默认只用 JA4、JA4+ 在默认关闭的 `ja4plus` 特性后"冲突，见 [ADR-0009](adr/0009-ja4-only-licensing.md)） |
| Traefik | N | 2021 年的需求已关闭未实现；相关 issue 维护者表示近期不在路线图 | 不做依赖 JA4 的适配；需要 TLS 指纹时把 Edge 放到它前面 |
| Caddy | 仅第三方模块 | 未审计质量 | 同上 |
| APISIX / Kong | N（未找到） | 基于 OpenResty，插件能否挂 `ssl_client_hello` 未确认 | 同上 |

### 4.2 L4 负载均衡与 PROXY protocol

原则：优先选择原生保留客户端 IP、不需要 PROXY protocol 的负载均衡（对应 `direct_tls`）；只在必须时使用 PPv2（`proxy_protocol{v2}`），PPv1 只用于 GCP 代理型 NLB。

| 云 | 负载均衡 | PROXY protocol | 客户端 IP 保留 | 建议 |
|---|---|---|---|---|
| AWS | NLB | 仅 v2（目标组属性 `proxy_protocol_v2.enabled`）；在前面追加自己的头，不删除客户端发来的 PROXY 头；TLS 监听器不接受传入的 PROXY 头；QUIC 不支持 PPv2；健康检查带不含客户端信息的 PPv2 头 | `preserve_client_ip.enabled`：instance 目标默认开，TCP/TLS 下的 IP 目标默认关；要求目标在同一或对等 VPC | 用 instance 目标 + 客户端 IP 保留，不开 PP；PrivateLink 时 TLV `0xEA` 携带 VPC 端点 ID |
| GCP | 直通 NLB | 不需要（直接服务器返回，保留源地址与端口） | Y | 首选 |
| GCP | 代理 NLB（TCP / SSL proxy） | 仅 v1（`--proxy-header PROXY_V1`，健康检查可同样设置） | N | 尽量不用；若用，Edge 需解析 v1 文本 |
| Azure | Standard Load Balancer | 不支持 | Y（直通） | 首选；Private Link Service 的 TCP Proxy V2 带 TLV `0xEE`（LinkID）；Application Gateway 为终止型代理，不放在 Edge 前 |
| 阿里云 | NLB | 仅 v2（监听器级开关）；TCPSSL 监听器、IP 类型服务器组、IPv6 访问 IPv4 时必须开 | ECS 类型服务器组可开"客户端地址保持" | TCP 监听器 + ECS 服务器组 + 客户端地址保持 |
| 阿里云 | CLB 四层 | 仅 v2，可选；开启需重启后端，共享后端的所有监听器都要开 | 默认透传 | 直接透传 |
| 腾讯云 | CLB 四层 | TCP 监听器可选 ProxyProtocol，版本未写明（需确认） | 默认透传；跨地域绑定 / 混合云需 TOA 内核模块 | 直接透传，避免跨地域绑定 |

| profile | 链路 |
|---|---|
| `proxy_protocol` | Client →（TCP，TLS 端到端到 Edge）→ L4 LB（NLB / CLB，前置 PROXY v2 头）→ Edge :443（源地址须 ∈ `allowed_src_cidrs`；`PreTlsProcess` 解析 PPv2 后再做 TLS，自算 JA4）→ 源站 |
| `direct_tls` | Client →（TLS，Edge 看到 ClientHello）→ [可选 L4 LB 直通，保留客户端 IP] → Edge :443（BoringSSL，自算 JA4；客户端 IP = TCP 对端）→ 源站 |

### 4.3 Pingora 实现要点

- Pingora 没有内置 PROXY protocol 解析器。0.9.0 新增 `PreTlsProcess` trait 与 `Listeners::set_pre_tls_callback()`（0.8.1 中没有），在 TCP accept 之后、TLS 握手之前拿到原始流，可更新 socket digest 中的对端地址。它**只在 TLS 监听器上执行**；在明文监听器上执行的 PR #1003 尚未合并。解析可用 ppp 2.3.0（Apache-2.0）或 proxy-header 0.1.3（MIT）。
- PROXY 接收器要求：每个监听器单独开启；对端必须在 `allowed_src_cidrs` 内，否则断开；只接受一个头，设短读超时与大小上限；`LOCAL` 命令（健康检查）视为"无客户端信息"；TLV（AWS `0xEA`、Azure `0xEE`）作为可选元数据；**开了 PP 的监听器绝不能被公网直接访问**。
- Pingora 0.7 起的 `ConnectionFilter`（feature `connection_filter`）可在 TLS 之前按 `SocketAddr` 接受或丢弃连接，用于限制公网监听器的来源。
- `direct_tls` 下的 JA4 计算链路（BoringSSL select-certificate 回调 → ex_data → `handshake_complete_callback` → `SslDigest.extension`）见 [01](01-architecture.md) §9 与 [ADR-0002](adr/0002-edge-pingora-boringssl.md)。
- 版本 pin `=0.9.x`，PROXY 相关代码放在 Pingora 适配 crate 中。PROXY protocol 在路线图中属于 Phase 5。

## 5. 待实测 / 待确认

| 项 | 影响 | 何时 |
|---|---|---|
| `cf.tls_ciphers_sha1` 与 `cf.tls_client_ciphers_sha1` 哪个被 Rulesets API 接受 | Tier 0 模板（`cf audit` 两种拼写都接受） | Phase 1 |
| Free / Pro 上 `cf.tls_*`、`cf.timings.*` 等字段与 visitor location 是否可用 | Tier 0 | Phase 1 |
| `cf.tls_*` 在 Chrome / Firefox / Safari、HTTP/3、会话恢复下的稳定性（GREASE、扩展顺序随机化） | EDGE_TLS 权重、`bind.ctp` | Phase 1–2 shadow |
| `CF-Connecting-IP` 等头经 Tunnel 到达源站 | 客户端 IP | Phase 1 验收 |
| `/__mg/` Bypass Cache Rule 表达式（含 `not starts_with`）被接受且按预期匹配 | 缓存 | Phase 1 |
| Worker 子请求回源是否出示 AOP 证书；Worker 与 Transform Rule 的执行顺序（确认 `x-mg-cf-t1: worker` 与 Tier 0 头同时到达） | Tier 1 + AOP 组合 | 启用 Tier 1 前 |
| Transform Rule 中 `accept-encoding` 取到的是原值还是改写值 | Accept-Encoding 检测 | 可选 |
| BFM、SBFM、AI bot policies、Precursor、Rocket Loader、SSL 模式的 API 读取方式；Precursor 的套餐可用性 | `mgctl cf audit` 自动化程度、共存清单 | Phase 1 |
| Free 限速规则支持的表达式（能否按方法、支持哪些运算符） | `/__mg/` 洪泛规则 | Phase 1 |
| 0-RTT 开启时 Cloudflare 是否把源站的 425 透传给浏览器 | 0-RTT 策略 | 仅在需开启 0-RTT 时 |
| 访客自己发送的 `CF-Worker` 头是否被 Cloudflare 删除或覆盖 | 不删除时访客只能让自己被 403（§2.2） | Phase 1 monitor 周 |
| Cloudflare 是否把源站（Edge）的 414 / 431 原样回传浏览器 | 超长请求的用户体验（只影响超长请求） | Phase 1 monitor 周 |
| 挑战页（403 + `no-store`）经 Cloudflare 后的 `cf-cache-status` 应为 `DYNAMIC` / `BYPASS` | 缓存泄漏（10 CH-09） | Phase 1 monitor 周 |
| HMAC token 的 MAC 计算与 `is_timed_hmac_valid_v0` 一致 | §2.9 | 启用前 |
| Cloudflare 挑战页对大陆访客的可用性（全局 zone） | 大陆策略 | 观察 |
| 纯 IPv6 主机上运行 cloudflared | 更便宜的 VPS 选项 | 可选 |
| CloudFront：`Viewer-Address` 的 IPv6 格式；HTTP/2 下 Header-Order 的大小写；10 头配额的计法 | `cloudfront` profile | Phase 4 |
| ESA `Tls-Hash` 与 `Tls-Ja4` 的格式；回源证书的套餐限制 | `esa` profile | Phase 4 |
| EdgeOne 回源 mTLS 的配置页与套餐；Bot 管理所需套餐 | `edgeone` profile | Phase 4 |
| 各 CDN 是否覆盖客户端发来的同名信号头 | 头采信规则 | Phase 4 |
| 腾讯云 CLB ProxyProtocol 版本 | `proxy_protocol` profile | Phase 5 |

## 参考

**Cloudflare**

- 请求头与客户端 IP：https://developers.cloudflare.com/fundamentals/reference/http-headers/ 、Pseudo IPv4 https://developers.cloudflare.com/network/pseudo-ipv4/ 、还原访客 IP https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/
- 协议：0-RTT https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/ 、HTTP/2 to Origin https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/
- Transform Rules：https://developers.cloudflare.com/rules/transform/ 、Request Header https://developers.cloudflare.com/rules/transform/request-header-modification/ 、头名与值格式 https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format/ 、可用字段与函数 https://developers.cloudflare.com/rules/transform/request-header-modification/reference/fields-functions/ 、Managed Transforms https://developers.cloudflare.com/rules/transform/managed-transforms/reference/ 、https://developers.cloudflare.com/rules/transform/managed-transforms/configure/
- Rules 语言：字段 https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ 、函数（含 `is_timed_hmac_valid_v0`）https://developers.cloudflare.com/ruleset-engine/rules-language/functions/ 、阶段 https://developers.cloudflare.com/ruleset-engine/reference/phases-list/
- Snippets 与 Workers：https://developers.cloudflare.com/rules/snippets/ 、https://developers.cloudflare.com/rules/snippets/when-to-use/ 、`request.cf` https://developers.cloudflare.com/workers/runtime-apis/request/ 、限制 https://developers.cloudflare.com/workers/platform/limits/ 、价格 https://developers.cloudflare.com/workers/platform/pricing/
- 源站保护：AOP https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/ 、zone-level https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/ 、per-hostname https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/per-hostname/ 、全局 https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/global/ 、方案对比 https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/ 、IP 段 https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/ 、https://api.cloudflare.com/client/v4/ips 、https://www.cloudflare.com/ips-v4 、https://www.cloudflare.com/ips-v6
- Tunnel：https://developers.cloudflare.com/tunnel/ 、https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/ 、源站参数 https://developers.cloudflare.com/tunnel/reference/origin-parameters/ 、可用性与副本 https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-availability/
- 缓存：默认行为 https://developers.cloudflare.com/cache/concepts/default-cache-behavior/ 、Cache-Control 与 OCC https://developers.cloudflare.com/cache/concepts/cache-control/ 、Set-Cookie https://developers.cloudflare.com/cache/concepts/cache-behavior/ 、响应状态 https://developers.cloudflare.com/cache/concepts/cache-responses/ 、Cache Rules https://developers.cloudflare.com/cache/how-to/cache-rules/ 、设置 https://developers.cloudflare.com/cache/how-to/cache-rules/settings/ 、顺序 https://developers.cloudflare.com/cache/how-to/cache-rules/order/ 、Speed Brain https://developers.cloudflare.com/speed/optimization/content/speed-brain/
- WAF：执行顺序 https://developers.cloudflare.com/waf/feature-interoperability/ 、Skip 选项 https://developers.cloudflare.com/waf/custom-rules/skip/options/ 、custom rules https://developers.cloudflare.com/waf/custom-rules/ 、限速规则 https://developers.cloudflare.com/waf/rate-limiting-rules/
- Bot：Bot Fight Mode https://developers.cloudflare.com/bots/get-started/bot-fight-mode/ 、SBFM https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/ 、套餐 https://developers.cloudflare.com/bots/plans/free/ 、https://developers.cloudflare.com/bots/plans/pro/ 、https://developers.cloudflare.com/bots/plans/biz-and-ent/ 、JA3 / JA4 https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/ 、BM 变量 https://developers.cloudflare.com/bots/reference/bot-management-variables/ 、已验证爬虫 https://developers.cloudflare.com/bots/concepts/bot/verified-bots/ 、Web Bot Auth https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/ 、AI bot policies https://developers.cloudflare.com/bots/additional-configurations/block-ai-bots/
- 挑战：JS Detections https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/ 、`cf-mitigated` https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/ 、Precursor https://developers.cloudflare.com/cloudflare-challenges/precursor/ 、Cookies https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/
- Rocket Loader：https://developers.cloudflare.com/speed/optimization/content/rocket-loader/ 、https://developers.cloudflare.com/speed/optimization/content/rocket-loader/ignore-javascripts/
- China Network：https://developers.cloudflare.com/china-network/ 、FAQ https://developers.cloudflare.com/china-network/faq/ 、可用产品 https://developers.cloudflare.com/china-network/reference/available-products/

**其他 CDN / 云**

- CloudFront：添加的头 https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html 、托管 origin request policy https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-origin-request-policies.html 、配额 https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-limits.html 、自定义源站头 https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html 、源站 mTLS https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-mtls-authentication.html
- AWS：IP 段 https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html 、https://ip-ranges.amazonaws.com/ip-ranges.json 、ALB https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html
- GCP：自定义头 https://docs.cloud.google.com/load-balancing/docs/https/custom-headers-global 、https://docs.cloud.google.com/load-balancing/docs/https/custom-headers-regional 、发布说明 https://cloud.google.com/load-balancing/docs/release-notes
- 阿里云：ESA 托管转换 https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/managed-conversion 、ESA 源站防护 https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/origin-protection 、ESA 回源客户端证书 https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/use-terraform-to-configure-origin-client-certificate 、CDN 自定义回源头 https://www.alibabacloud.com/help/en/cdn/user-guide/configure-custom-request-headers 、ICP 备案 https://www.alibabacloud.com/help/en/icp-filing/basic-icp-service/product-overview/what-is-an-icp-filing
- 腾讯云：EdgeOne https://edgeone.ai/document/54211 、https://edgeone.ai/document/74787 、https://edgeone.ai/document/52690 、https://edgeone.ai/document/48535 、https://edgeone.ai/document/63620 、CDN 回源头 https://cloud.tencent.com/document/product/228/45078

**网关、L4 与 Pingora**

- Envoy：tls_inspector https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/listener/tls_inspector/v3/tls_inspector.proto 、替换格式符 https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/substitution_formatter 、1.35.0 https://www.envoyproxy.io/docs/envoy/latest/version_history/v1.35/v1.35.0
- OpenResty / nginx：lua-resty-ja4 https://opm.openresty.org/package/nemethhh/lua-resty-ja4/ 、ngx.ssl.clienthello https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl/clienthello.md 、ja4-nginx-module https://github.com/FoxIO-LLC/ja4-nginx-module
- Traefik issue：https://github.com/traefik/traefik/issues/12421
- L4：AWS NLB 目标组属性 https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html 、GCP 直通 / 代理 NLB https://docs.cloud.google.com/load-balancing/docs/passthrough-network-load-balancer 、https://docs.cloud.google.com/load-balancing/docs/proxy-network-load-balancer 、Azure https://learn.microsoft.com/en-us/azure/load-balancer/network-load-balancing-aws-to-azure-how-to 、阿里云 NLB https://www.alibabacloud.com/help/en/slb/network-load-balancer/use-cases/obtain-client-ip-addresses 、阿里云 CLB https://www.alibabacloud.com/help/en/slb/classic-load-balancer/use-cases/enable-proxy-protocol-for-a-layer-4-listener-to-retrieve-client-ip-addresses 、腾讯云 CLB https://cloud.tencent.com/document/product/214/36386
- Pingora：listeners（PreTlsProcess）https://github.com/cloudflare/pingora/blob/main/pingora-core/src/listeners/mod.rs 、PROXY protocol issue / PR https://github.com/cloudflare/pingora/issues/132 、https://github.com/cloudflare/pingora/pull/1003 、client_cert 示例 https://github.com/cloudflare/pingora/blob/main/pingora-core/examples/client_cert.rs 、ppp / proxy-header https://crates.io/api/v1/crates/ppp 、https://crates.io/api/v1/crates/proxy-header
