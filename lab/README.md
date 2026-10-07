# lab — Validation Lab

Go 模块 `morphgate/lab`。只向所有者自己的目标发送流量；`internal/guard` 是安全边界，任何未明确允许的目标一律拒绝。

## 两层强制

1. **工具内（本模块）**：`guard.CheckURL` 校验每个 URL（含每一跳重定向）；`guard.DialContext` 在 DNS 解析之后、`connect(2)` 之前再次校验实际 IP（防 DNS 重绑定）；HTTP 客户端忽略代理环境变量、最多 5 次重定向、固定超时、全进程令牌桶限速（默认 5 req/s，硬上限 50）。
2. **网络出口**：compose 的 `lab` profile（`deploy/compose/docker-compose.yml`）把 `mglab` 放在 `internal: true` 的 `lab` 网络上，Docker 不为它提供任何离开本机的路由；该网络还设置了 `com.docker.network.bridge.inhibit_ipv4`，宿主机在其中没有地址（只有 `internal` 时宿主机持有网关地址，容器可经它访问宿主机上监听 0.0.0.0 的任何服务）。因此只能访问同一网络中别名为 `*.lab.test` 的服务（配置 `config/lab.compose.yaml`）。`make lab-egress-check`（需要 Docker 守护进程，CI 必跑）同时验证两层：工具层拒绝白名单外目标；绕过工具的普通 HTTP 客户端在 `lab` 网络上也连不到宿主机上的监听端口，而默认网络上的对照容器可以连到；在 Linux 上还确认宿主机在 `lab` 子网内没有任何地址。本机运行的 mg-edge（`make edge-run`、`make lab-e2e`）只监听回环、运行在宿主机上，不在 `lab` 网络中；对它回放时只有工具层。

## 允许规则（默认配置 = `config/lab.example.yaml`）

| 配置 | 匹配 | 连接时允许的 IP |
|---|---|---|
| `allow_hosts` | 精确主机名（如 `localhost`、compose 服务名） | 仅回环 / 私有（RFC 1918、ULA） |
| `allow_suffixes` | 按标签对齐的后缀（`.test`、`.localhost`）；拒绝 `.com` 等公共后缀 | 仅回环 / 私有 |
| `allow_cidrs` | URL 主机是 IP 字面量 | 该 IP 本身 |
| `owner_targets` | 所有者登记的 staging 主机 | 仅其 `expected_cidrs` |

主机规范化：小写、去掉一个结尾点、IDNA 转 ASCII（同形字会变成 `xn--` 而不匹配）。十进制 / 八进制 / 十六进制 IPv4 与 IPv4 映射 IPv6 按其真实地址判断，只有该地址在 `allow_cidrs` 内才允许，并改写为规范写法。拒绝 userinfo、反斜杠、主机中的百分号编码、IPv6 zone、非 http(s)。以下地址无论配置如何都永远拒绝（URL 字面量与 DNS 解析结果都算，配置中写入会报错）：链路本地（含 169.254.169.254）、组播、未指定地址；可到达任意 IPv4 的 IPv6 过渡前缀（NAT64 `64:ff9b::/96`、`64:ff9b:1::/48`，6to4，Teredo）；不在链路本地的云元数据端点（AWS `fd00:ec2::254`、GCP `fd20:ce::254`、阿里云 `100.100.100.200`、Oracle `192.0.0.192`）。

## 用法

```sh
go run ./cmd/mglab check http://localhost:8080/
go run ./cmd/mglab check -resolve -config config/lab.example.yaml https://app.test/
go run ./cmd/mglab replay -base http://127.0.0.1:8080 testdata/scenarios/edge-smoke.yaml

# *.test 站点名没有 DNS 记录：-map-host 把它指到回环 Edge（Edge 按 Host 选站点）
go run ./cmd/mglab replay -map-host site.lab.test=127.0.0.1 -base http://site.lab.test:8080 \
  -var run=r1 testdata/scenarios/phase1-impersonator.yaml
go run ./cmd/mglab events impersonator -site lab -impersonators /lab/impersonator/r1/ events.jsonl

# 隔离网络内（在仓库根目录执行）
docker compose -f deploy/compose/docker-compose.yml --profile lab up -d lab-origin
docker compose -f deploy/compose/docker-compose.yml --profile lab run --rm mglab \
  replay -config /etc/mglab/lab.yaml /lab/testdata/scenarios/lab-origin.yaml
```

| 命令 | 作用 |
|---|---|
| `check [-config] [-map-host name=ip]… [-resolve] <url>` | 判断 URL 是否允许及原因；`-resolve` 另外解析并校验每个地址（不建立连接） |
| `replay [-config] [-map-host name=ip]… [-base URL] [-rps N] [-var name=value]… <scenario>` | 按顺序回放场景 |
| `events impersonator\|clearance … <events.jsonl>` | 检查 Edge 的 JSONL 事件文件（只读本地文件，不发流量），见下文 |

`-map-host name=ip`（可重复）只替换名字解析，相当于 `curl --resolve`：名字本身仍须在白名单内，映射出的地址与 DNS 应答一样按该名字的规则校验（`allow_hosts` / `allow_suffixes` 只能是回环 / 私有地址），连接前再查一次。所以映射不会让 Lab 到达白名单之外的目标；`site.lab.test=93.184.216.34` 在连接时被拒绝。

退出码：0 允许 / 全部符合预期 / 检查通过；1 被拒绝、有失败或检查不通过；2 用法或配置错误。

## 场景文件

`replay` 只按顺序发送场景文件里记录的请求（方法、origin-form 路径、头、正文），不生成载荷、不变异、不并发，也不根据响应计算任何东西（没有求解逻辑）。场景中不能设置 `Host`、`Content-Length`、`Transfer-Encoding` 等由客户端管理的头，同一请求中的头名不区分大小写地不得重复（YAML 合并键覆盖时写法须一致，否则发出哪个值取决于 map 顺序）；路径必须以单个 `/` 开头，不能指向其他主机。未知字段报错。

| 字段 | 层级 | 含义 |
|---|---|---|
| `name`、`description`、`base_url` | 场景 | `-base` 覆盖 `base_url` |
| `vars` | 场景 | 声明变量与缺省值（`~` 表示必须用 `-var` 给出）；`path`、头值、`body` 中的 `${name}` 在发送前替换一次，`$${` 表示字面 `${`；替换后的请求重新校验（值不能把路径变成别的主机） |
| `method`、`path`、`headers`、`body` | 请求 | 录制的请求 |
| `delay_ms` | 请求 | 发送前等待 0–10000 ms |
| `expect_status` / `expect_status_in` | 请求 | 期望状态码 / 可接受的状态码列表（二选一） |
| `expect_header` | 请求 | 头名 → 最终响应中该头某个值须包含的子串（`""` 表示头存在即可） |
| `expect_header_absent` | 请求 | 不得出现的响应头（最终响应与跟随的每一跳重定向都检查，所以 `Location` 表示没有发生重定向） |
| `expect_cookie_absent` | 请求 | 不得被 `Set-Cookie` 设置的 Cookie 名（含跟随的重定向各跳；名字不区分大小写，手工解析，畸形行也算）；只报告名字，不打印值 |
| `expect_body_contains` | 请求 | 响应正文前 1 MiB 须包含的子串 |

任一期望不满足计为 unexpected response，`replay` 退出码 1。

## Phase 1 验收（`make lab-e2e`）

规格 [§15 WP-L1、§18](../docs/impl/phase1-spec.md#wp-l1-validation-lab阶段-3)。`scripts/lab-e2e.sh` 全部在回环地址上运行：

| 步骤 | 内容 |
|---|---|
| 构建 | `go build` mgctl、mglab；mg-edge 取 `MG_EDGE_BIN`（CI：`rust` 作业上传的发布二进制），否则 `cargo build -p mg-edge`；SDK 目录取 `MG_LAB_SDK_DIR`，否则有 pnpm / node 时 `pnpm -C sdk/web run build`，否则 `edge/tests/fixtures/sdk`（`MG_LAB_SDK=fixture` 强制） |
| 密钥与配置包 | 临时目录中用 `MGCTL_PASSPHRASE_FILE`、`MGCTL_AGE_WORK_FACTOR=10`、`--insecure-test-key` 生成所有者签名密钥、假名化密钥与站点 `lab` 的密钥，`keys export --out` 写成 Edge 的凭证文件；用 `testdata/e2e/site.yaml` build / sign / publish（enforce），审计日志也在临时目录并 `audit verify` |
| 进程 | 临时 `valkey-server`（只监听临时目录中的 unix socket；或 `MG_TEST_VALKEY_URL`，必须在本机：回环地址的 `redis://` 或 `unix://`）、python3 源站、mg-edge（`cloudflare` 回环监听器、Valkey 状态、`static:testdata/e2e/dns.json`、JSONL 事件文件；二进制与 SDK 目录先复制到临时目录，并发的重新构建不影响本次运行）；等到站点 active、配置包版本生效、状态层为 valkey |
| 场景 | mglab 经 guard 回放下表两个场景（`-map-host site.lab.test=127.0.0.1`、`-var run=<本次 id>`） |
| 断言 | `mglab events impersonator` / `clearance` 检查事件文件；源站日志中没有受保护路由、`/__mg`、已判定的冒充请求，已验证爬虫带 `MG-Verified` 到达；打印 PASS / FAIL 汇总 |
| 清理 | trap 停止全部进程并删除临时目录（`MG_LAB_E2E_KEEP=1` 保留） |

缺少 python3 / go / curl / valkey-server（且无 `MG_TEST_VALKEY_URL`）/ cargo（且无 `MG_EDGE_BIN`）时打印 `SKIPPED: …` 并以 0 退出；`MG_LAB_E2E_REQUIRE=1`（CI）时改为失败。`MG_LAB_E2E_TIMEOUT` 为每个等待的秒数（缺省 60）。

| 场景 | 内容 | 事件断言 |
|---|---|---|
| `phase1-impersonator.yaml` | 声称 GPTBot（`ip_ranges`）、Googlebot（`ip_ranges_or_rdns`）、Applebot（`rdns`）但来自官方段之外或 rDNS 不成立（仿冒后缀 `evilgooglebot.com`（I-22）、无 PTR、正向不含该 IP、PTR 不在后缀内、IPv6、UA 填充到 512 字节之后、大写标记）：`ip_ranges` 从第一个请求起 403；rDNS 运营方每个地址先有一个热身请求（pending，转发），`delay_ms` 之后全部 403；注册表段内或 rDNS 成立的真爬虫放行 | 已定结果的冒充请求 13/13 为 `impersonator` 且 enforce 阻断；热身请求为 `declared_agent`、从不 `verified_crawler`（D-22）；每条访问记录都有决定事件；6 个真爬虫请求为 `verified_crawler` |
| `phase1-nonjs-clearance.yaml` | 对 `require_clearance` 路由的 HTML 与 JSON 请求 → 403 挑战、无 `__Host-mg_clr`；提交录制的过期 C（表单）、伪造 C（JSON）、畸形 C → 403、无 Cookie、无 303；再次请求仍 403；HTTP 库 UA → 403；外部 zone `CF-Worker` → 403 | 没有 `outcome = pass` 的 feedback（3 条均为 fail）；`/__mg/c` 没有成功应答；受保护路由的请求没有被转发 |

`testdata/e2e/`：`site.yaml`（站点 `lab`、主机 `site.lab.test`、`monitor_only: false`、路由 `members` 为 critical、决定事件不采样）、`crawler-registry.test.json`（`test: true`，只用文档地址段；rDNS 后缀按 I-22 以 `.` 开头、至少两段标签）、`dns.json`（`StaticResolver` 表）。场景只针对这套配置与全新的 Edge（rDNS 缓存为空）。
