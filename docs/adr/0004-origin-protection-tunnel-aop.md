# ADR-0004：源站保护采用 Cloudflare Tunnel，AOP（自有 CA）为备选

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：同机密钥头、凭证与 CA 保管）；2026-09-28 勘误：Phase 1 实现口径（依据 [Phase 1 实现规格](../impl/phase1-spec.md) D-23、I-4，见文末"勘误"）
- 相关：[08 上游接入与 Cloudflare 集成](../08-upstream-and-cloudflare.md#2-cloudflare-前置cloudflare-profile)、[10 威胁模型](../10-threat-model.md)、[ADR-0003](0003-upstream-profile-cdn-first.md)、[ADR-0007](0007-lean-deployment.md)

## 背景

- `cloudflare` profile 采信 `CF-Connecting-IP` 与 `x-mg-cf-*` 的前提是：能证明请求经由所有者自己的 Cloudflare 账号到达，否则直连源站即可伪造这些头。Cloudflare 的评级：Tunnel、Authenticated Origin Pulls（AOP）为"非常安全"；HTTP 头校验、IP 白名单为"中等安全"，后者易受伪造。
- AOP 所有套餐可用，分全局、zone-level、per-hostname 三级，要求 SSL 模式为 Full 或 Full (strict)。全局证书由所有 Cloudflare 账号共享，只能证明"来自 Cloudflare 网络"，其他 Cloudflare 客户的流量同样能通过；zone-level / per-hostname 使用所有者上传、由自有 CA 签发的证书。AOP 对经 Tunnel 的主机名不生效。
- Tunnel（cloudflared）只建立出站连接，源站无需公网入站端口，所有套餐可用、免费。多个 cloudflared 副本可共享一个隧道：按就近路由（不是负载均衡），连接失败时重试其他副本。
- Cloudflare IP 段可由 `GET https://api.cloudflare.com/client/v4/ips` 获取（带 etag；2026-09-27 为 15 个 IPv4 段、7 个 IPv6 段）。

## 决策

| 顺序 | 方案 | Edge 的信任依据 |
|---|---|---|
| 首选 | Cloudflare Tunnel：cloudflared 与 Edge 同机，Edge 只监听 `127.0.0.1`；每台 Edge 主机一个 cloudflared 副本，提供免费主备 | 只信任回环对端 |
| 备选 | AOP zone-level 或 per-hostname，使用所有者自有 CA；Edge 的 TLS 监听器要求客户端证书并校验链到该 CA | 客户端证书链 |
| 纵深（配合备选） | 云防火墙 / 安全组只放行 Cloudflare IP 段；Pingora ConnectionFilter 在 TLS 之前按来源地址丢弃 | 不作为唯一依据 |
| 可选叠加（Tunnel 且 Edge 与源站同机） | Tier 0 Transform Rule 以静态值设置 `x-mg-upstream-key`（mgctl 轮换，Edge 同时接受新旧值），防源站 SSRF 向回环口伪造请求 | 常量时间比较 |

- 不使用全局 AOP 证书；同一主机名不混用 Tunnel 与 AOP。
- 控制面定时同步 `/client/v4/ips`（按 etag），校验列表形态后下发到 Edge 可信代理快照与云安全组。
- 请求带 `CF-Worker` 头且其 zone 不在 `owner_zones` 内时丢弃并告警（[08 §2.2](../08-upstream-and-cloudflare.md)）。
- `mgctl cf audit` 检查上述配置及 Cloudflare 侧相关开关（清单见 08）。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| 全局 AOP 证书 | 其他 Cloudflare 客户的流量也能通过 |
| 仅 IP 白名单 | "中等安全"；其他 Cloudflare 客户的请求同样来自这些 IP 段 |
| 只用共享密钥请求头 | "中等安全"；只作为 Tunnel 上的可选叠加，以及其他上游（如 CloudFront 自定义源站头）的认证方式 |
| Cloudflare Load Balancer + 多隧道 | 只在需要按权重 / 健康度分配时有价值，当前规模不需要 |

## 后果

- 源站与 Edge 不需要公网 IPv4 与入站端口；主备由 cloudflared 副本提供，无需付费负载均衡。
- Tunnel 把入口绑定到 Cloudflare；非 Cloudflare 上游需要单独的监听器与 profile。
- 需实测：经 Tunnel 到达的请求是否与普通代理一样携带 `CF-Connecting-IP` 等头（预期如此，文档未明确）；仅 IPv6 主机把 cloudflared 的 `edge-ip-version` 设为 6 或 auto 后的端到端行为。
- Pro 及以上若启用 Super Bot Fight Mode，"Definitely Automated" 需保持 Allow，否则隧道连接可能以 `websocket: bad handshake` 失败。
- 每台主机的 cloudflared 凭证仅 root 可读，cloudflared 以非特权用户运行；主机失陷即轮换凭证。
- 采用 AOP 时需要管理自有 CA：CA 私钥离线保存（不放在 Edge 或大脑 VM），Edge 只持有 CA 证书，轮换时短期同时信任新旧 CA；证书续期有 Cloudflare 的 30 / 14 天提醒，vmalert 按 `mg_aop_cert_expiry_seconds` < 30 天告警（[06](../06-policy-console-observability.md)）。

## 勘误（2026-09-28，Phase 1 实现）

结论不变。Phase 1 按下表实现（细节见规格 [§9.2](../impl/phase1-spec.md#92-监听器与上游认证)、[§9.3.2](../impl/phase1-spec.md#932-客户端-ip-未知d-23)、[§14.3](../impl/phase1-spec.md#143-mgctl-cf-auditwp-g3)、[§14.4](../impl/phase1-spec.md#144-mgctl-cf-ips-syncwp-g3)）：

| 项 | Phase 1 |
|---|---|
| Tunnel | `loopback` 监听器对非回环对端返回 403（`non_loopback_peer`）。上游密钥头由监听器的 `upstream_keys` 开启；回环监听器服务的站点源站也在回环地址、却没有配置时，`mg-edge --check-config` 警告。Cloudflare 侧的密钥头是单独一条 Transform Rule（`mg_upstream_key_v1`），与信号规则分开轮换 |
| AOP | `origin_mtls` 监听器：BoringSSL 要求并校验客户端证书，`client_ca` 为所有者自有 CA；`cloudflare_ip_filter = true` 时按各站点 `cloudflare-ips` 工件的并集在 TLS 之前丢弃连接（尚无工件时放行） |
| `CF-Worker` | 外部 zone 与非法值一律 403，计 `mg_cf_foreign_worker_total`（原文"丢弃并告警"），不进入决策（D-23）；配置包生效前用 `edge.toml` 的 `bootstrap_owner_zones`，未配置时任何 `CF-Worker` 都视为外部（I-4） |
| IP 段同步 | Phase 1 没有控制面服务：所有者在工作站每日运行 `mgctl cf ips sync`（校验形状、条数变化超过 30% 拒绝），工件随签名配置包下发到 Edge；云安全组由所有者手工维护 |
| `mgctl cf audit` | 第 1 项读取 tunnel 状态（`cfd_tunnel`）或 AOP 设置，第 3 项检查 AOP 证书剩余 ≥ 30 天（原文的 `mg_aop_cert_expiry_seconds` 指标在 Phase 1 不存在）；由所有者定时运行 |
| 待实测 | 经 Tunnel 到达的 `CF-Connecting-IP`：monitor 周首日确认 `mg_cf_connecting_ip_missing_total` 为 0（规格 [§19](../impl/phase1-spec.md#19-待实测与未决)） |

## 参考

- https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/
- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/explanation/
- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/
- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/per-hostname/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-availability/
- https://blog.cloudflare.com/tunnel-for-everyone/
- https://api.cloudflare.com/client/v4/ips
- https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/
