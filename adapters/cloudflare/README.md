# Cloudflare 接入模板

所有者手工应用到自己 zone 上的模板。仓库里没有任何代码会修改 Cloudflare zone 或部署它们；Phase 3 的 `mgctl cf apply` 会按同样的内容自动下发，`mgctl cf audit`（Phase 1，只读 API token）负责检查，见文末"用 `mgctl cf audit` 复查"。设计依据见 [08 上游与 Cloudflare](../../docs/08-upstream-and-cloudflare.md) §2。

## 文件

| 文件 | 作用 | 套餐 |
|---|---|---|
| `transform-rule.request-headers.json` | Tier 0：一条 Request Header Transform Rule，把 TLS / RTT / ASN / 验证爬虫 / 头名集合写入 `x-mg-cf-*`；同时删除客户端自带的 Tier 1 头名 | 所有套餐 |
| `transform-rule.upstream-key.json` | 可选：单独一条 Transform Rule（`mg_upstream_key_v1`），以静态值设置 `x-mg-upstream-key`；只在 Edge 的 `edge.toml` 配置了 `upstream_keys` 时部署。值是密钥，模板里只有占位符 | 所有套餐 |
| `cache-rule.bypass-mg.json` | `/__mg/*` 不缓存（内容哈希的 SDK 构建 `/__mg/s/` 除外）；**必须是最后一条 Cache Rule** | 所有套餐 |
| `waf-skip.mg.json` | `/__mg/*` 跳过 SBFM、Browser Integrity Check、Security Level；**不跳过限速规则**，`/__mg/` 洪泛限速规则继续生效 | Pro 及以上（Free 用法见下） |
| `waf-skip.mg.no-flood-limit.json` | 同上，另跳过限速规则（`http_ratelimit`）；**只用于没有任何限速规则保护 `/__mg/` 的 zone**，与上一个文件二选一 | Pro 及以上 |
| `snippet/mg-signals.js` | Tier 1（Snippet）：转发 `request.cf` 的 `requestPriority`、`clientAcceptEncoding`、`asOrganization` | Pro 及以上 |
| `worker/` | Tier 1 的 Worker 版本（`src/index.ts`、`wrangler.toml.example`），供 Free zone 使用 | Workers Free / Paid |
| `test/adapters.test.mjs` | 离线校验：JSON 结构、头名规则、Snippet 与 Worker 的行为 | — |

五个 JSON 文件都是 Rulesets API "创建 zone ruleset" 的请求体（`kind`、`phase`、`rules`），`ref` 以 `mg_` 开头，`mgctl` 以此识别自己的规则。

## 设置清单

按顺序完成。每一项都会在 `mgctl cf audit` 中复查。

| # | 项目 | 要求 | 原因 |
|---|---|---|---|
| 1 | 源站保护 | 首选 **Cloudflare Tunnel**：cloudflared 与 Edge 同机，Edge 只监听 `127.0.0.1`，只信任回环对端；每台 Edge 主机一个 cloudflared 副本。备选 **Authenticated Origin Pulls（zone-level 或 per-hostname，自有 CA）** + 云防火墙只放行 Cloudflare IP 段 | 全局 AOP 证书只证明"来自 Cloudflare 网络"，其他 Cloudflare 客户的流量也能通过；AOP 对 Tunnel 主机名不生效 |
| 2 | "Remove visitor IP headers"（Managed Transform） | **关闭** | 开启后没有 `CF-Connecting-IP`，Edge 拿不到客户端 IP（Edge 会告警，不回退到 Cloudflare 对端 IP） |
| 3 | "Add visitor location headers"（Managed Transform） | 开启 | 免费得到 `cf-ipcountry`、`cf-timezone` 等地理头 |
| 4 | Pseudo IPv4 | 关闭 | 设为 Overwrite 时 `CF-Connecting-IP` 变成伪 IPv4 |
| 5 | Tier 0 Transform Rule | 应用 `transform-rule.request-headers.json` | 见下文 |
| 6 | Bot Fight Mode（Free） | **关闭** | 不在 Ruleset Engine 上，无法按路径跳过，会在 `/__mg/*` 前插入不可控挑战 |
| 7 | Super Bot Fight Mode（Pro 及以上） | 各组设为 Allow，或应用 `waf-skip.mg.json`（不跳过限速规则）；使用 Tunnel 时 "Definitely Automated" 必须为 Allow | 否则 SDK 对 `/__mg/*` 的请求可能收到 Cloudflare 挑战；Tunnel 连接可能失败 |
| 8 | Cloudflare Managed Challenge / JS Challenge 规则 | 不覆盖 MorphGate 挑战的路径 | 避免双重挑战与挑战循环 |
| 9 | Precursor | 关闭 | Maximize Security 模式要求 `cf_clearance`，不带 Cookie 的 fetch 会失败 |
| 10 | Rocket Loader | 关闭，或 SDK 标签带 `data-cfasync="false"`（Edge 注入的标签默认带） | 会延迟、改写脚本加载 |
| 11 | 0-RTT Connection Resumption | 关闭 | 0-RTT 请求可被重放；若开启，Edge 对带 `Early-Data: 1` 的状态变更请求返回 425 |
| 12 | AI bot policies（Search / Agent / Training） | MorphGate 为唯一权威时设为 Allow | 2026-09-15 起新 zone 默认在有广告的页面上阻止 Training 与 Agent；不改则 Cloudflare 先拦截，MorphGate 看不到 |
| 13 | `/__mg/` 缓存 Bypass | 应用 `cache-rule.bypass-mg.json`，并确认它是**最后一条** Cache Rule | 多条规则匹配时最后一条胜出；带 Edge TTL 覆盖的 "Eligible for cache" 规则会剥离 `Set-Cookie` 并缓存每用户响应 |
| 14 | Always Use HTTPS | 开启（建议同时开 HSTS） | 凭证 Cookie 是 `__Host-` 前缀，只在 https 下保存；http 访客永远拿不到凭证（Edge 对 http 访客的 GET / HEAD 挑战改为 308 到 https） |
| 15 | 上游密钥头（可选） | Edge 与源站同机时建议启用：`mgctl keys gen-upstream` 生成，Edge 的 `upstream_keys` 指向它，Cloudflare 侧部署 `transform-rule.upstream-key.json` 并把占位符换成打印出的 `values[0]` | 同机源站的 SSRF 可以向 `127.0.0.1` 发出带伪造 `CF-Connecting-IP` 的请求；带密钥头才被 Edge 当作经 Cloudflare 的请求 |
| 16 | Tier 1（可选） | Pro 及以上用 Snippet；Free 用窄路由 Worker | 见下文 |

## 套餐能力

| 能力 | Free | Pro | Business |
|---|---|---|---|
| Cloudflare Tunnel、AOP（zone-level / per-hostname） | 可用 | 可用 | 可用 |
| Request Header Transform Rules | 10 条 | 25 条 | 50 条 |
| Transform Rule 中的 `cf.tls_*`、`cf.timings.*`、`ip.src.asnum`、`cf.client.bot` | 文档无套餐标注，需实测 | 同左 | 同左 |
| Cache Rules | 10 条 | 25 条 | 50 条 |
| WAF custom rules（含 Skip） | 5 条 | 20 条 | 100 条 |
| 限速规则 | 1 条（Path / Verified Bot 字段，按 IP，周期 10 s） | 2 条（周期 ≤ 1 分钟） | 5 条（周期 ≤ 10 分钟，可 IP + NAT） |
| Bot 功能 | Bot Fight Mode（不可跳过） | SBFM（可 Skip / Allow） | SBFM（增加 Likely automated） |
| Snippets | 不可用 | 25 个 | 50 个 |
| Workers（账号级，与 zone 套餐无关） | Workers Free：100,000 请求/天、10 ms CPU；Paid $5/月起 | 同左 | 同左 |
| `is_timed_hmac_valid_v0()`（可选 HMAC Cookie 跳过） | 不可用 | 可用 | 可用 |
| 规则中的正则 | 不可用 | 不可用 | 可用（模板不依赖） |

Enterprise Bot Management 的 `cf-ja4`、`cf-bot-score`（Tier 2）超出预算，不规划。

## 应用 Rulesets 模板

先把各文件里的示例值换成自己的：站点若把 `/__mg/` 配置为其他前缀，替换全部 `"/__mg/"` 与 `"/__mg/s/"`。

```bash
ZONE=<zone_id>
API=https://api.cloudflare.com/client/v4
AUTH="Authorization: Bearer $CLOUDFLARE_API_TOKEN"

# 1) 查看该阶段是否已有 zone ruleset（phase 取 http_request_late_transform / http_request_cache_settings / http_request_firewall_custom）
curl -sS -H "$AUTH" "$API/zones/$ZONE/rulesets/phases/http_request_late_transform/entrypoint"

# 2a) 不存在：直接用模板创建
curl -sS -X POST -H "$AUTH" --json @transform-rule.request-headers.json "$API/zones/$ZONE/rulesets"

# 2b) 已存在（最常见）：只追加这一条规则，不动其他规则；新规则默认追加在末尾
jq '.rules[0]' transform-rule.request-headers.json \
  | curl -sS -X POST -H "$AUTH" --json @- "$API/zones/$ZONE/rulesets/$RULESET_ID/rules"
```

- 不要用 `PUT .../rulesets/{id}` 或 `PUT .../phases/{phase}/entrypoint` 提交模板：`PUT` 会整体替换该阶段的规则列表，删掉已有规则。
- Cache Rule 追加后位于末尾；以后再加其他 Cache Rule 时，用 `position: {"before": "<mg_bypass_mg_paths 的 rule id>"}` 放在它前面。
- API Token 只给对应产品的编辑权限（Transform Rules、Cache Rules、Zone WAF）加 Account Rulesets 读权限；具体权限名以 Cloudflare 文档为准。审计只需只读 token。
- 每次修改后在 Cloudflare Trace 或 Edge 调试日志中确认 `x-mg-cf-*` 已到达。

## 模板说明

### Tier 0：`transform-rule.request-headers.json`

- 表达式为 `true`，覆盖 zone 下所有主机名：客户端伪造的同名头会被 Set 覆盖，值为空时被删除。若 zone 内有不经 MorphGate 的主机名，可改成 `http.host in {"www.example.com" "example.com"}`（主机名写小写：规则里的字符串比较区分大小写，`"Example.com"` 永远不匹配），但必须覆盖该站点的全部主机名，否则未覆盖的主机名上客户端可以自带 `x-mg-cf-*`。
- **字段拼写需实测**：规则里用字段参考页的 `cf.tls_ciphers_sha1`；Transform Rules 的"可用字段"列表写作 `cf.tls_client_ciphers_sha1`。API 若拒绝前者（未知字段），改成后者；两者都被拒绝时删除 `x-mg-cf-tls-ciphers-sha1` 这一项。此后该信号在 Edge 上为 `MISSING`：不计入置信度，既不当风险也不当人类证据；作为应到达的 Tier 0 头，它的缺失同时计入 `mg_upstream_signal_missing_total`（缺失率超阈值告警）。
- 数值字段用 `to_string()` 转成字符串；`x-mg-cf-rtt` 只在 TCP、`x-mg-cf-quic-rtt` 只在 QUIC 客户端有值。
- `x-mg-cf-hdr-names` 的顺序不保证，只当集合用；`x-mg-cf-tls-ext-sha1` 的稳定性未文档化，实测前只做 shadow；`x-mg-cf-tls-random` 只在内存中作为"每个访客 TLS 连接"的临时标识，不写入事件。
- 同一条规则还 `remove` 了 `x-mg-cf-priority`、`x-mg-cf-accept-encoding`、`x-mg-cf-as-org`、`x-mg-cf-t1`：Tier 1 未运行时，这些名字不会带着客户端的值到达 Edge。Snippet 在 Request Header Transforms 之后执行（有文档）；**Worker 与 Transform Rule 的先后顺序需实测**（08 §2.3）：若 Worker 先于 Transform Rule 运行，这条规则会把 Worker 写入的 Tier 1 头一并删除，Tier 1 信号在 Edge 上恒为 `MISSING`。启用 Worker 后按文末"需实测"表确认 `x-mg-cf-t1: worker` 能到达 Edge。
- 上游密钥头 `x-mg-upstream-key`（08 §2.3）不放在这条规则里，而是单独的 `transform-rule.upstream-key.json`（`ref` = `mg_upstream_key_v1`）：密钥与信号规则分开，轮换时只改那一条。见下文"上游密钥头"。
- 即使规则齐全，Edge 也只在上游认证通过（Tunnel 回环对端或 AOP 客户端证书）时采信 `x-mg-*`，否则全部删除。

### 上游密钥头：`transform-rule.upstream-key.json`（可选）

- 只在 Edge 的 `edge.toml` 为该监听器配置了 `upstream_keys` 时部署；此后 Edge 拒绝（403）不带正确密钥头的请求，所以表达式必须与 Tier 0 规则一样覆盖站点全部主机名（模板为 `true`）。
- 值取 `mgctl keys gen-upstream --out …` 打印到 stdout 的 `values[0]`（43 个 base64url 字符）。只在 Dashboard 或 API 请求里填写，**不要写回模板或提交到仓库**；模板里的 `REPLACE-ME …` 占位符永远不会被 Edge 接受，`mgctl cf audit` 第 6 项发现占位符时报错。
- 轮换：`mgctl keys gen-upstream --rotate`（密钥文件保留新旧两个值）→ 更新每台 Edge 的 credential 并 reload → 把规则的值改成新的 `values[0]`。Edge 在此期间同时接受两个值。
- 已有 `http_request_late_transform` 入口规则集时，与 Tier 0 规则一样只追加这一条（`jq '.rules[0]' transform-rule.upstream-key.json | curl … /rules`）；把值替换后再提交。
- `mgctl cf audit` 从不打印这个头的值。

### 缓存：`cache-rule.bypass-mg.json`

- `/__mg/*` 设为 Bypass cache，内容哈希的 SDK 构建 `/__mg/s/{build}.js`（Edge 发送 `immutable`）除外，以便 SDK 在 Cloudflare 边缘缓存，改善大陆访客的加载。
- **必须是最后一条 Cache Rule**：Cache Rules 可叠加，设置冲突时最后匹配的规则胜出。
- Edge 对 `/__mg/*` 与所有 Challenge 响应都发送 `Cache-Control: no-store, private`，Challenge 用 403 / 429；这条规则是第二道防线。
- 不要让任何带 Edge TTL 覆盖的 "Eligible for cache" 规则覆盖可能返回 Challenge 的 HTML 路径。设置会叠加：一条规则设 "Eligible for cache"、另一条只覆盖 Edge TTL，对两者都匹配的请求同样是这个陷阱。

### Skip：`waf-skip.mg.json`

- 让 SDK 对 MorphGate 端点的请求不会收到 Cloudflare 的 HTML 挑战；MorphGate 自己对 `/__mg/*` 做大小、速率与重放检查。
- 默认模板的 `phases` 只有 `http_request_sbfm`，**不跳过 `http_ratelimit`**：用 Cloudflare 限速规则挡 `POST /__mg/` 洪泛时（Free 的唯一一条限速规则就适合做这个），跳过 `http_ratelimit` 会让这条限速规则对 `/__mg/*` 一起失效。
- 只有 zone 上**没有任何**保护 `/__mg/` 的限速规则时，才可改用 `waf-skip.mg.no-flood-limit.json`（`phases` 另含 `http_ratelimit`，其余相同，`ref` 也相同，二者只应用一个）。以后新增 `/__mg/` 洪泛限速规则时，先换回 `waf-skip.mg.json`；`mgctl cf audit` 第 11 项检查这一点。
- Free zone 没有 SBFM：`phases` 去掉 `http_request_sbfm`，只保留 `products`（BIC、Security Level）。Bot Fight Mode 无论如何都不能被跳过，只能关闭。
- Skip 规则要排在任何可能对 `/__mg/` 执行 Block / Challenge 的自定义规则之前。

### Tier 1：Snippet 与 Worker

两者逻辑相同（测试同时覆盖）：

| 头 | 来源 | 编码 |
|---|---|---|
| `x-mg-cf-priority` | `request.cf.requestPriority` | 原样（可打印 ASCII，≤ 256 字符） |
| `x-mg-cf-accept-encoding` | `request.cf.clientAcceptEncoding`（Cloudflare 改写 `Accept-Encoding` 前的原值） | 原样 |
| `x-mg-cf-as-org` | `request.cf.asOrganization` | `encodeURIComponent`（UTF-8 百分号编码），Edge 解码 |
| `x-mg-cf-t1` | 固定 `snippet` 或 `worker` | 标明哪个 Tier 1 转发器运行过 |

- 每个头要么取 Cloudflare 的值，要么删除，绝不透传客户端的值；取不到值、超长或含不可打印字符时删除。
- 从不修改 `x-real-ip` / `CF-Connecting-IP`：同 zone 子请求中 Cloudflare 用 `x-real-ip` 生成 `CF-Connecting-IP`，改它等于伪造客户端 IP。
- 任何异常都原样转发请求（fail open）：Edge 看到缺少 `x-mg-cf-t1` 时，把全部 Tier 1 信号记为 `MISSING`（来源无法确认）：不计入置信度，既不当通过也不当风险，也不告警（Tier 1 本就可选）。

**Snippet（Pro 及以上）**：在 Rules > Snippets 中创建，代码为 `snippet/mg-signals.js`，Snippet 规则表达式只选页面导航与 MorphGate 端点：

```
http.request.headers["sec-fetch-dest"][0] == "document" or starts_with(http.request.uri.path, "/__mg/")
```

Snippet 限制：5 ms 执行、2 MB 内存、32 KB 代码包，没有 secret；本文件远小于上限，保持如此。

**Worker（Free）**：复制 `worker/wrangler.toml.example` 为 `wrangler.toml`，替换域名后 `wrangler deploy`。

- 路由**必须窄**：只挂 `/__mg/*` 和 HTML 页面路径，不挂静态资源、不用 `example.com/*`。Worker 在缓存之前运行，路由命中的每个请求都计费，并占用 Free 的 100,000 请求/天。
- Free 额度用尽时，在路由上选择 fail open：请求绕过 Worker 直达源站，没有 Tier 1 头，MorphGate 把 Tier 1 信号记为 `MISSING`（不告警）。
- Worker 与 Tier 0 Transform Rule 的执行顺序**需实测**（见上文 Tier 0 说明）：Transform Rule 若在 Worker 之后运行，会删除 Worker 写入的 Tier 1 头。
- 路由模式只支持开头或结尾的 `*`，不支持中间通配；需要排除静态子路径时，在 Dashboard 为该子路径添加一条不绑定 Worker 的路由。

## 需在所有者 zone 上实测 / 确认

| 项目 | 验证方法 |
|---|---|
| `cf.tls_ciphers_sha1` 与 `cf.tls_client_ciphers_sha1` 哪个被 Rulesets API 接受 | 创建规则时看 API 是否报错；到达源站的头是否有值 |
| Transform Rule 中 TLS / timings / ASN / verified bot 字段在本套餐是否可用 | 部署后在 Edge 调试日志确认各头有值 |
| "Add visitor location headers" 在本套餐是否可用 | `GET /zones/{id}/managed_headers`（只返回本套餐可用项） |
| `x-mg-cf-tls-*` 在 HTTP/3（QUIC）与 TLS 会话恢复时是否有值；各浏览器下哈希是否稳定 | Edge shadow 统计 |
| Worker 与 Transform Rule 的先后顺序；Worker 的同 zone 子请求是否再次执行 Transform Rule | 文档间接表明 Transform Rules 与 Snippets 都在 Worker 之前执行，仍需实测：部署 Worker 后确认 `x-mg-cf-t1: worker` 与 Tier 0 头同时到达，且 Tier 0 值与直连时一致 |
| AOP 模式下 Worker 子请求是否出示 zone-level 客户端证书 | 同时启用 AOP 与 Worker 时，Edge 日志中的上游认证结果 |
| Tunnel 源站是否收到与 AOP 源站相同的代理头（`CF-Connecting-IP` 等） | Edge 调试日志 |
| Precursor 的套餐可用性与当前状态 | Dashboard：Security > Settings |
| Workers 路由 fail open / fail closed 设置的当前名称与位置 | Dashboard |

## 用 `mgctl cf audit` 复查

```bash
export CLOUDFLARE_API_TOKEN=…   # 只读 token（docs/06 §8 的 cf-audit）
mgctl cf audit --site-config site.yaml --cf-ips intel/cloudflare-ips.json \
  --vm-url http://10.0.0.5:8428 --sdk-dir sdk/web/dist/sdk --ack precursor="Dashboard 确认已关闭"
```

- 21 项检查（spec §14.3）覆盖上面的设置清单、`/__mg/` Skip 规则顺序、TTL 覆盖陷阱、Edge 运行时指标与 IP 段快照时效。任一 error 级检查失败时退出码为 1。
- token 读不到的项显示为 `manual`（明细里写出大概需要的读权限）；在 Dashboard 确认后用 `--ack <check>=<说明>` 记为已确认。`--strict` 把 error 级的 `manual` 也当作失败。
- 第 13 项（TTL 覆盖陷阱）确认过的例外按规则 `ref` 登记：`--ack ttl_override_trap:<ref>=<说明>`（规则叠加时登记覆盖 Edge TTL 的那条）。只按扩展名限定静态文件的纯合取表达式（不含任何 `or` / `xor`，否定不包住扩展名条件）才算"静态"，其余一律按陷阱报告。
- 第 14 项把 `and not starts_with(http.request.uri.path, "/__mg/")` 这类简单排除项视为不覆盖；否定一个复合条件（`not (a and …)`）仍算覆盖。
- `--json` 输出机器可读结果；`--metrics-textfile` 写 `mg_cf_audit_failed_checks{zone, check}` 与 `mg_cf_audit_last_run_timestamp_seconds{zone}`，供 node_exporter textfile collector 采集。

## 本地校验

```bash
node --test adapters/cloudflare/test/adapters.test.mjs      # Node >= 22.18（直接导入 Worker 的 .ts）
for f in adapters/cloudflare/*.json; do python3 -m json.tool "$f" > /dev/null || echo "bad: $f"; done
pnpm -C sdk/web exec tsc -p ../../adapters/cloudflare/worker/tsconfig.json   # Worker 类型检查（借用 sdk/web 的 TypeScript）
```

## 参考

- Request Header Transform Rules：https://developers.cloudflare.com/rules/transform/request-header-modification/
- 通过 API 创建 Request Header Transform Rule：https://developers.cloudflare.com/rules/transform/request-header-modification/create-api/
- Transform Rule 可用字段：https://developers.cloudflare.com/rules/transform/request-header-modification/reference/fields-functions/
- 头名与值格式限制：https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format/
- 字段参考 `cf.tls_ciphers_sha1`：https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_ciphers_sha1/
- Managed Transforms：https://developers.cloudflare.com/rules/transform/managed-transforms/reference/
- Cache Rules：https://developers.cloudflare.com/cache/how-to/cache-rules/ 、https://developers.cloudflare.com/cache/how-to/cache-rules/settings/
- Skip 选项：https://developers.cloudflare.com/waf/custom-rules/skip/options/
- Snippets：https://developers.cloudflare.com/rules/snippets/
- Workers 路由：https://developers.cloudflare.com/workers/configuration/routing/routes/
- Cloudflare 请求头（`CF-Connecting-IP`、`x-real-ip`）：https://developers.cloudflare.com/fundamentals/reference/http-headers/
- Bot Fight Mode：https://developers.cloudflare.com/bots/get-started/bot-fight-mode/
- Super Bot Fight Mode：https://developers.cloudflare.com/bots/get-started/super-bot-fight-mode/
