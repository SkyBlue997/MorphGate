# 隐私说明模板：安全验证与反自动化

**用途**：所有者在受保护站点的隐私政策中加入这一节（或单独成页），说明 MorphGate 出于安全目的处理哪些访客数据。挑战页的"隐私说明"链接指向站点 YAML 的 `challenge.privacy_path`，应指向包含这一节的页面。

**何时更新**：任何新的客户端信号上线之前（[07 贯穿各阶段](07-roadmap.md#贯穿各阶段)、[Phase 2 规格 §19](impl/phase2-spec.md#19-所有者运维手册代码之外) 第 2 步）。具体地：启用交互式 Challenge 或 `proof: required` 之前，开启行为摘要（`events.telemetry_behavior`）之前，启用 Turnstile 之前。

**怎么用**：
- 按 §1 的对照表，只保留站点实际启用的段落；
- 把 `{…}` 换成站点的信息；
- 正文按需要改写语气，但不要删掉数据项、保存期限与第三方；
- 本模板不是法律意见。PIPL 的告知要求、跨境处理（尤其是大陆访客的数据经 Turnstile 发给 Cloudflare）、日志留存的口径，以及是否需要单独同意，都需法务确认（[06 §7](06-policy-console-observability.md#7-隐私与合规)）。

数据项与保存期限以设计文档为准：采集见 [04 §7](04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk) 与 [09 §10](09-interactive-challenge.md#10-交互遥测)，保留期见 [02 §9](02-data-flow.md#9-采样与保留) 与 [06 §7](06-policy-console-observability.md#7-隐私与合规)。配置改变保留期（例如 VictoriaLogs 的保留参数、journald 的保存时长）时，同步修改正文。

## 1. 功能与段落的对照

| 站点启用的功能 | 配置 | 需要的段落（§2） |
|---|---|---|
| MorphGate Edge（任何站点） | — | 2.1、2.2 的"基础"、2.4、2.5、2.6、2.7 |
| 无感 / PoW Challenge（Phase 1 起） | 缺省 | 2.2 的"浏览器环境摘要" |
| 会话密钥与持有证明（Phase 2） | 配置包 `schema_version = 2`（凭证绑定会话密钥）；路由 `proof: required` | 2.2 的"会话公钥与证明"、2.3 的本地存储、2.8 |
| 交互式验证（Phase 2） | `challenge.interactive.enabled: true` | 2.2 的"交互遥测"、2.3 的 `__Host-mg_a11y` |
| 凭证静默刷新（Phase 2） | `clearance.refresh: true` | 2.2 的"会话公钥与证明"；开启行为摘要时另加"刷新时的遥测" |
| 行为摘要（Phase 2，可选） | SDK 标签 `data-mg-telemetry="behavior"` 且 `events.telemetry_behavior: true` | 2.2 的"行为摘要"、"刷新时的遥测" |
| Turnstile（Phase 2，可选） | 站点 YAML 的 `providers` 含 `turnstile` | 2.2 的"Cloudflare Turnstile"、2.5 的 Turnstile 一行 |
| 近线检测（Phase 2） | 本机 Valkey 且 `events.stream: true` | 2.2 的"自动化检测" |

## 2. 正文（zh-CN）

### 2.1 我们为什么处理这些数据

为保护 {站点名称} 免受自动化滥用（例如批量抓取、撞库、批量注册与恶意请求），我们在网站前部署了自建的安全防护服务。它会检查访问请求，在必要时要求浏览器完成一次验证。这些数据只用于识别和限制自动化访问、排查误拦截，不用于广告、画像或识别具体个人，也不在网站之间追踪您。

### 2.2 我们处理哪些数据

**基础（每个请求）**
- 您的 IP 地址，以及由它得出的国家 / 地区与网络运营商（ASN）；
- 请求的地址（页面路径）、方法、时间，以及浏览器发送的请求头，例如 User-Agent、语言；
- 请求携带的 Cookie 的名称（不记录 Cookie 的值）；
- 安全判定的结果（例如放行、要求验证、限速）与一个随机的请求编号。

**浏览器环境摘要**（只在验证页面上采集）：浏览器与系统的版本标识、语言、时区、屏幕与窗口尺寸、像素比、处理器核数与内存档位、是否支持触控、Cookie 与本地存储是否可用，以及浏览器是否处于自动化控制状态。我们不采集画布、WebGL、音频等渲染指纹。

**会话公钥与证明**：完成验证时，您的浏览器会生成一对加密密钥，私钥保存在浏览器中、不会离开您的设备；公钥会随验证提交与之后的部分请求一起发送，用来证明这些请求来自同一个浏览器，防止验证结果被转移到别的设备。公钥在您的验证凭证失效后或最迟 7 天后更换，不作为长期标识；我们的数据库中只保存它的不可逆摘要。

**交互遥测**（只在您完成交互式验证时）：在您的浏览器中先量化、再发送的统计值，例如完成方式（按住、点击或自动验证）、输入设备类型、按住与等待的时长（精确到 10 毫秒）、按下前指针移动的大致距离与速度档位、按住期间的抖动档位、页面是否被切到后台、计算耗时、验证组件的版本与语言。整份数据不超过 2 KB，**不包含**鼠标或手指的原始坐标与轨迹、按键内容、表单内容或页面文字。

**刷新时的遥测**（只在本站开启行为摘要时）：凭证在后台自动续期时，可附带与上面相同格式的统计值。

**行为摘要**（只在本站开启时）：每个页面汇总一次的分桶计数，例如指针移动速度与曲率的分布、按键间隔的分布（不含按了哪个键）、滚动距离、页面切换次数、表单填写耗时与是否粘贴。不包含原始轨迹、按键内容、表单内容、页面文字或任何标识。

**Cloudflare Turnstile**（只在本站启用、且系统为您选择了它时）：验证页面会从 Cloudflare 加载 Turnstile 组件，它会把您的 IP 地址、浏览器的 TLS 指纹与 User-Agent、本站的 sitekey 与来源页面发送给 Cloudflare, Inc.；我们的服务器随后把验证令牌与您的 IP 地址发给 Cloudflare 核验。这同样适用于中国大陆的访客。Cloudflare 对这些数据的处理以其 Turnstile 隐私附录为准（https://www.cloudflare.com/turnstile-privacy-policy/）。如果 Turnstile 无法加载或出错，页面会自动改用我们自建的验证方式，不会因此判定验证失败。{如站点按国家排除 Turnstile，在此写明：来自 {国家 / 地区} 的访客不会被提供 Turnstile。}

**自动化检测**：我们会对一段时间内的请求做汇总统计（例如是否访问常见的漏洞探测路径、请求频率、验证失败次数），以发现扫描器、凭证共享与滥用验证的行为。统计用的是 IP 地址与会话的不可逆摘要，结果只会让后续请求更可能被要求验证，不会仅凭它拦截访问。

### 2.3 Cookie 与浏览器本地存储

| 名称 | 类型 | 用途 | 保存时长 |
|---|---|---|---|
| `__Host-mg_clr` | Cookie（HttpOnly，脚本无法读取） | 验证通过的凭证，避免您反复验证 | 按本站配置，缺省 15–30 分钟；开启后台续期时最长到 {会话上限，缺省 24 小时} |
| `__Host-mg_st` | Cookie | 凭证的签发与到期时间，供页面脚本安排后台续期；不含验证方式与秘密 | 同上 |
| `__Host-mg_a11y` | Cookie（HttpOnly） | 您选择过"改用自动验证"时记住这一偏好，下次优先提供；不含任何标识 | 1 年，改用按住验证通过后删除 |
| IndexedDB 数据库 `mg-v1` | 浏览器本地存储 | 会话密钥（私钥不可导出） | 凭证失效后或最迟 7 天后更换 |
| localStorage `mg_sk_v1` | 浏览器本地存储 | 浏览器不支持上一项时的会话密钥 | 同上 |
| sessionStorage `mg_skew`、`mg_tq`、`mg_cfm:*`、`mg_rd:*`、`mg_retry:*`、`mg_verify:*` | 浏览器会话存储 | 时钟偏差、待发送的诊断报告与防重复的标记 | 关闭标签页即清除 |

这些都是安全所必需的存储，不用于广告或统计分析。{站点的 CDN 可能另设 Cloudflare 自己的 Cookie，例如 `__cf_bm`，见 Cloudflare 的说明。}

### 2.4 保存期限

| 数据 | 保存时长 |
|---|---|
| 安全判定记录（含 IP 地址） | 30 天 |
| 验证与浏览器遥测（交互遥测、行为摘要、诊断报告） | 7 天 |
| 不含个人标识的统计汇总（例如验证通过率、耗时分布） | 13 个月 |
| 服务运行日志（不含 IP、Cookie 值与验证内容） | 14 天 |
| 最小访问记录（IP 只保留到网段） | {按法律要求，不少于 6 个月；若源站访问日志已满足要求，删掉这一行} |
| 自动化检测的中间统计（只有不可逆摘要） | 只在服务内存中，重启即清空：检测窗口 5–10 分钟；统计验证比例用的去重集合 7 天。检测结果按其有效期（15 分钟至 1 小时）失效 |

### 2.5 第三方与数据所在地

| 接收方 | 何时 | 数据 |
|---|---|---|
| Cloudflare, Inc.（CDN） | 每个请求 | 本站经 Cloudflare 提供服务，请求先到达 Cloudflare |
| Cloudflare, Inc.（Turnstile） | 只在本站启用且为您选择了 Turnstile 时 | 见 2.2 |

安全防护服务与上述记录存放在 {服务器所在地区，例如中国香港}。{面向中国大陆访客时，写明境外处理的告知与依据（需法务确认）。}

### 2.6 我们不做的事

- 不采集鼠标或手指的原始轨迹、按键内容、表单内容；
- 不采集画布、WebGL、音频等渲染指纹；
- 不出售或共享这些数据用于广告；
- 不在不同网站之间追踪您；
- 不仅凭交互遥测或行为摘要做出拦截决定。

### 2.7 被误拦截时

验证失败或被拦截的页面会显示一个请求编号。请把它连同大致时间发给 {联系方式}，我们会据此查明原因。

### 2.8 浏览器禁用存储时

如果您的浏览器禁用了 Cookie、IndexedDB 与本地存储（例如部分隐私模式），验证可能无法完成，本站的 {需要持有证明的功能，例如"提交表单""账号操作"} 可能无法使用。允许本站使用 Cookie 与存储后重试即可。

### 2.9 您的权利

{按站点的隐私政策写明查询、复制、更正、删除等权利的行使方式与联系方式。安全记录按上述期限自动删除。}

## 3. English version

**Security checks and anti-automation.** To protect {site name} from automated abuse (bulk scraping, credential stuffing, mass sign-ups and malicious requests), we run a self-hosted security service in front of the site. It inspects requests and may ask your browser to complete a check. The data below is used only to detect and limit automated access and to investigate wrongful blocks; it is not used for advertising or profiling and is not used to track you across sites.

**What we process.**
- *Every request*: your IP address and the country / region and network (ASN) derived from it; the requested path, method and time; request headers such as User-Agent and language; the **names** of cookies sent (never their values); the security decision and a random request ID.
- *Browser environment summary* (check pages only): browser and OS version identifiers, languages, time zone, screen and window size, pixel ratio, CPU core count and memory tier, touch support, whether cookies and storage are available, and whether the browser is under automation control. No canvas, WebGL or audio fingerprints.
- *Session public key and proofs*: when you pass a check, your browser creates a key pair. The private key stays in your browser; the public key is sent with the check and with some later requests to prove they come from the same browser. It is replaced when your clearance ends or after at most 7 days; our database only keeps an irreversible digest of it.
- *Interaction telemetry* (interactive checks only): statistics quantised in your browser, such as how you completed the check (press and hold, click or automatic), input type, hold and wait time (10 ms resolution), bucketed pointer movement and speed before pressing, jitter while holding, whether the page went to the background, computation time, widget version and language. At most 2 KB; it never contains raw pointer coordinates or paths, keystrokes, form contents or page text.
- *Refresh telemetry and behaviour summary* (only if this site enables them): per-page bucketed counts of pointer speed and curvature, key intervals (not which keys), scrolling, focus changes, form fill time and pasting. No raw paths, keystrokes, form contents, page text or identifiers.
- *Cloudflare Turnstile* (only if enabled and chosen for you): the widget sends your IP address, your browser's TLS fingerprint and User-Agent, this site's sitekey and the page origin to Cloudflare, Inc.; our server then sends the token and your IP address to Cloudflare for verification. This applies to visitors in mainland China as well. See the Turnstile privacy addendum (https://www.cloudflare.com/turnstile-privacy-policy/). If Turnstile fails to load or errors, the page switches to our own check and this does not count as a failed check.
- *Automation detection*: aggregate counts over time (probes of common exploit paths, request rates, failed checks), keyed by irreversible digests of IP addresses and sessions. The result can only make a later check more likely; it never blocks access on its own.

**Cookies and storage**: `__Host-mg_clr` (HttpOnly clearance), `__Host-mg_st` (issue and expiry times, no level or secret), `__Host-mg_a11y` (HttpOnly preference for the automatic check, 1 year), the IndexedDB database `mg-v1` or localStorage `mg_sk_v1` (session key), and sessionStorage entries starting with `mg_` (cleared when the tab closes). All are strictly necessary for security.

**Retention**: security decisions with IP address 30 days; check and browser telemetry 7 days; aggregate statistics without personal identifiers 13 months; service logs 14 days; {minimal access records, IP truncated to the network: at least 6 months, if required}.

**If you are blocked**, send the request ID shown on the page to {contact}. If your browser blocks cookies and storage, the check may not complete and {features that need proofs} may not work.
