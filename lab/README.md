# lab — Validation Lab

Go 模块 `morphgate/lab`。只向所有者自己的目标发送流量；`internal/guard` 是安全边界，任何未明确允许的目标一律拒绝。

## 两层强制

1. **工具内（本模块）**：`guard.CheckURL` 校验每个 URL（含每一跳重定向）；`guard.DialContext` 在 DNS 解析之后、`connect(2)` 之前再次校验实际 IP（防 DNS 重绑定）；HTTP 客户端忽略代理环境变量、最多 5 次重定向、固定超时、全进程令牌桶限速（默认 5 req/s，硬上限 50）。
2. **网络出口**：compose 的 `lab` profile（`deploy/compose/docker-compose.yml`）把 `mglab` 放在 `internal: true` 的 `lab` 网络上，Docker 不为它提供任何离开本机的路由；该网络还设置了 `com.docker.network.bridge.inhibit_ipv4`，宿主机在其中没有地址（只有 `internal` 时宿主机持有网关地址，容器可经它访问宿主机上监听 0.0.0.0 的任何服务）。因此只能访问同一网络中别名为 `*.lab.test` 的服务（配置 `config/lab.compose.yaml`）。`make lab-egress-check`（需要 Docker 守护进程，CI 必跑）同时验证两层：工具层拒绝白名单外目标；绕过工具的普通 HTTP 客户端在 `lab` 网络上也连不到宿主机上的监听端口，而默认网络上的对照容器可以连到；在 Linux 上还确认宿主机在 `lab` 子网内没有任何地址。Phase 0 的 mg-edge 只监听回环、运行在宿主机上，不在 `lab` 网络中；对它回放时只有工具层。

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

# 隔离网络内（在仓库根目录执行）
docker compose -f deploy/compose/docker-compose.yml --profile lab up -d lab-origin
docker compose -f deploy/compose/docker-compose.yml --profile lab run --rm mglab \
  replay -config /etc/mglab/lab.yaml /lab/testdata/scenarios/lab-origin.yaml
```

`replay` 只按顺序发送场景文件里记录的请求（方法、origin-form 路径、头、正文），不生成载荷、不变异、不并发。场景中不能设置 `Host`、`Content-Length`、`Transfer-Encoding` 等由客户端管理的头；路径必须以单个 `/` 开头，不能指向其他主机。

退出码：0 允许 / 全部符合预期；1 被拒绝或有失败；2 用法或配置错误。
