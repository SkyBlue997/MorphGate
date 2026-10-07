# control-plane

Go 模块 `morphgate/control-plane`：`mgctl`（所有者工作站上的运维 CLI）与 `mg-control`（控制面服务）。设计见 [docs/06](../docs/06-policy-console-observability.md)，Phase 1 的命令与文件格式以 [Phase 1 实现规格](../docs/impl/phase1-spec.md) §8.2、§8.3、§12、§14 为准。

## 当前状态（Phase 1）

| 组件 | 内容 |
|---|---|
| `mgctl policy check / compile` | 策略 YAML 校验、cel-go 类型检查、CEL → 策略 IR（`expr_ir`、静态步数上界 `max_steps`，规格 §5）（`internal/policy`） |
| `mgctl site check`、`bundle build / sign / verify / publish` | 站点 YAML v1、签名配置包的构建、签名、校验与发布（`internal/sitecfg`、`internal/bundle`） |
| `mgctl keys …`、`site keys …`、`verdict key` | 所有者签名密钥、站点密钥、假名化密钥、上游密钥头、导出与轮换、verdict 键计算（`internal/keys`） |
| `mgctl audit verify` | 本地哈希链审计日志（`internal/audit`） |
| `mgctl cf audit`、`cf ips sync`、`crawler sync` | Cloudflare zone 审计与情报工件同步（`internal/cfapi`、`internal/cfaudit`、`internal/intelsync`） |
| `mg-control` | `GET /healthz`、`GET /v1/bundles/{site}` → 404 `{"error":"not_implemented","phase":3}`、优雅退出；配置包分发与管理 API 在 Phase 3 |

`gen/morphgate/v1` 是 `scripts/gen-proto.sh` 生成并提交的代码，不要手改；`scripts/gen-proto.sh --check` 检查是否过期。

## 命令一览

| 命令 | 作用 | 审计 action |
|---|---|---|
| `mgctl policy check [flags] <file\|dir>…` | 校验策略文件（`-profile cloudflare\|direct_tls`、`-max-cost N`） | — |
| `mgctl policy compile [flags] [-o out.json] <file\|dir>…` | 输出每条规则的 JSON（含 `expr_ir`（标准 base64）与 `max_steps`） | — |
| `mgctl site check --site-config <site.yaml>` | 校验站点 YAML、策略、名单与工件，不写任何文件 | — |
| `mgctl bundle build --site-config <site.yaml> --out-dir <dir> [--version N]` | 写 `<dir>/<site>.sitebundle.pb`、`<dir>/<site>.sitebundle.json`（protojson，只供人看）与 `<dir>/artifacts/<sha256>`；`--version` 缺省为构建时的 Unix 秒 | — |
| `mgctl bundle sign --in <pb> --key <kid>.key.age --out <file.bundle>` | 用所有者密钥签名（签名输入 `"mg-bundle-v1" ‖ 0x00 ‖ bundle`） | `bundle.sign` |
| `mgctl bundle verify --in <file.bundle> --pub <kid>.pub… [--site <id>] [--json]` | 验签、解码并打印摘要（`--pub` 可重复） | — |
| `mgctl bundle publish --in <file.bundle> --artifacts <dir> --dest <dir> --pub <kid>.pub… --confirm <site> [--metrics-textfile <path>]` | 验签后先写 `<dest>/artifacts/<sha256>`、再写 `<dest>/bundles/<site>.bundle`；版本必须大于已发布的版本；`--metrics-textfile` 写 `mg_bundle_published_version{site}` | `bundle.publish` |
| `mgctl keys gen --kid <kid> --out-dir <dir> [--insecure-test-key]` | 所有者 Ed25519 签名密钥：`<kid>.key.age`（0600）与 `<kid>.pub`（0644） | `keys.gen` |
| `mgctl keys gen-pseudo --out <file.json.age> [--insecure-test-key]` | 假名化密钥 `K_pseudo`（Valkey 键中标识个人部分的 HMAC 密钥） | `keys.gen_pseudo` |
| `mgctl keys gen-upstream --out <file.json.age> [--rotate] [--insecure-test-key]` | 上游密钥头值；`--rotate` 把新值放前、保留 2 个；`values[0]` 打印到 stdout，用于 Cloudflare 的 `set x-mg-upstream-key` 规则 | `keys.gen_upstream` |
| `mgctl keys export --in <file.json.age> [--out <file> \| -]` | 解密站点 / 假名化 / 上游密钥文件；缺省写 stdout（管道到 `systemd-creds encrypt`），`--out` 写新的 0600 明文文件；所有者签名密钥不可导出 | `keys.export` |
| `mgctl site keys gen --site <id> --out-dir <dir> [--date YYYYMMDD]` | `token.keys.json.age` 与 `seal.root.json.age` | `site_keys.gen` |
| `mgctl site keys rotate-token --site <id> --file <token.keys.json.age> [--date YYYYMMDD]` | 新 token key 放前，至多保留 3 个；打印新 kid | `site_keys.rotate_token` |
| `mgctl site keys rotate-seal --site <id> --file <seal.root.json.age> --step add\|promote\|retire [--date YYYYMMDD]` | 封装根密钥三步轮换：`add` 新根放第二位，`promote` 交换，`retire` 删除第二个 | `site_keys.rotate_seal` |
| `mgctl verdict key --pseudo-key <file.json.age> --site <id\|all> --type ip\|prefix\|asn\|session --value <v>` | 打印 verdict 的完整 Valkey 键（`ip` 先取 ip 实体：IPv4 地址或 IPv6 /64；`prefix` 接受地址或其 /24、/48），供所有者手工 `SET`；只读 | — |
| `mgctl audit verify` | 校验审计日志哈希链；打印条数与最后的 hash，断链时指出行号 | — |
| `mgctl cf audit --site-config <site.yaml> [--cf-ips <artifact>] [--vm-url <url>] [--sdk-dir <dir>] [--ack <check>=<note>]… [--strict] [--json] [--metrics-textfile <path>]` | 用只读 API Token（`CLOUDFLARE_API_TOKEN`）审计所有者 zone 的 21 项设置（规格 §14.3）；任一 error 级失败（`--strict` 下含 `manual`）退出码 1 | — |
| `mgctl cf ips sync --out <file> [flags]` | 同步 Cloudflare IP 段工件（`cloudflare-ips.json`，规格 §12.2、§14.4）；条数变化超过 30% 需 `--accept-change`；写 `<out>.state.json` | `cf.ips.sync` |
| `mgctl crawler sync --registry <src.yaml> --out <file> [--previous <file>] [--accept-change]` | 抓取各爬虫运营方的官方 IP 段并写注册表工件（规格 §12.3、§14.5）；变化保护同上（50%）；`rdns_suffixes` 每项以 `.` 开头、其后至少两段标签（如 `.googlebot.com`，裁决 I-22；Edge 只按标签边界匹配） | `crawler.sync` |

### 约定

- **退出码**：`0` 成功；`1` 输入无效或检查失败；`2` 用法错误或尚未实现；`3` I/O 或内部错误（含审计追加失败）。
- **全局标志 `--audit-log <path>`**：可写在命令行任意位置（`--` 之前），所有写入类命令（含 `cf ips sync`、`crawler sync`）都追加到同一个日志，并且在抓取或写入任何文件之前先确认日志可用，不可用时什么都不写、退出码 3（集成者裁决 I-27）。
- **环境变量**：`MGCTL_PASSPHRASE_FILE`（口令文件，取第一行；测试与自动化用，否则从终端无回显读取，生成时输入两次；口令从不出现在命令行）、`MGCTL_AGE_WORK_FACTOR`（10–22，缺省 18；小于 18 必须加 `--insecure-test-key`，只用于测试与 Lab）、`MGCTL_AUDIT_LOG`、`CLOUDFLARE_API_TOKEN`、`MGCTL_CF_API_BASE`（缺省 `https://api.cloudflare.com/client/v4`，测试指向 httptest）。
- **文件写入**：一律先写临时文件、fsync 后再 `rename`（或硬链接）；密钥文件与工件从不覆盖已有文件（轮换命令原子替换 `--file` 指定的文件）。
- **出站请求**（`cf audit`、`cf ips sync`、`crawler sync`）：User-Agent 一律为 `morphgate-dev-tooling`（集成者裁决 I-7，覆盖规格 §14.1 的 `mgctl/<version>`），不带所有者的邮箱或其他身份信息。

## 站点 YAML v1

格式与校验规则见规格 §8.2，映射到 `SiteBundle` 的方式与缺省值见 §8.3；样例：`testdata/sites/valid/full.yaml`（规格中的示例）、`testdata/sites/valid/minimal.yaml`（全部取缺省值）。实现细节：

- 未知键、YAML 锚点 / 别名、多文档都是错误；诊断信息带 `文件:行:列`。相对路径相对于 YAML 文件所在目录。
- 缺省值：`monitor_only: true`；`channel: web`；`require_clearance` 与 `fail_closed` 在 `sensitivity: critical` 时为 true；限速器 `burst: 1`、`scope: global`、`mode: enforce`；`automation_allowlist_only` 对 `production` 以外的环境为 true。`sensitivity`、限速器的 `key`、`rate`、`on_exceed` 必填。
- 每个环境末尾追加 `{name: default, paths: ["/**"], channel: web, sensitivity: low}`，除非已有一个 `paths: ["/**"]` 且不限定 `hosts` / `methods` 的路由；`default` 这个名字只能用于这样的路由。每个环境至多 64 条**声明**路由，追加的 `default` 不计入（配置包中至多 65 条，与 Edge 的校验一致，裁决 I-24）。
- 限速器 id 在整个站点内唯一（跨环境，裁决 I-23）：Valkey 键 `mg:rl:{site}:{limiter}:{kh}` 不含环境，两个环境共用一个 id 会共用同一组 GCRA 桶。
- 构建时额外检查：策略规则只允许 Phase 1 参数（`challenge` 的 `type: invisible|pow|interactive`、`tag` 必需的 `label`、`rate_limit` 的 `limiter` 与 `retry_after_s`）；`tarpit` 报错（D-09），`interactive` 告警（D-08，按 `pow` 执行）；规则引用的名单都必须在 `lists` / `list_files` 中定义，IR 中 `ip_in()` 用到的名单必须全是 IP 或 CIDR；规则缺 IR（`ir_version != 1` 或 `expr_ir` 为空）时构建失败，所以不会产生 Edge 无法加载的配置包；工件按 Edge（mg-intel）的解析规则校验：MaxMind DB 完整校验并检查 `database_type`；JSON 工件逐字段严格读取（成员名大小写须一致，重复成员、缺失成员与 `null` 都是错误，只有注册表的 `test` 可省略）；IPv6 段只接受全球单播 `2000::/3` 且不与 `2001::/23`、文档段 `3fff::/20` 相交；时间戳为 `Z` 或 `±hh:mm`（小时 ≤ 23）的 RFC 3339；`tor-exits` 至多 1,000,000 条，ASN 至多 10 位数字。任何一项 Edge 会拒绝的内容都会让整个配置包被拒，所以构建时就报错。
- 构建结果是确定性的：同样的输入与 `--version` 得到同样的字节；`challenge`、`clearance`、`scoring`、`crawler_policy`、`events`、`origin_headers` 总是完整写出（proto3 无法区分"未设置"与零值）。

## 密钥与发布流程

```sh
export MGCTL_PASSPHRASE_FILE=...            # 或在终端输入口令
mgctl keys gen --kid owner-2026 --out-dir ~/mg/keys
mgctl keys gen-pseudo --out ~/mg/keys/pseudo.key.json.age
mgctl keys gen-upstream --out ~/mg/keys/upstream-keys.json.age
mgctl site keys gen --site blog --out-dir ~/mg/blog
mgctl bundle build --site-config ~/mg/blog/site.yaml --out-dir ~/mg/out
mgctl bundle sign --in ~/mg/out/blog.sitebundle.pb --key ~/mg/keys/owner-2026.key.age --out ~/mg/out/blog.bundle
mgctl bundle publish --in ~/mg/out/blog.bundle --artifacts ~/mg/out/artifacts --dest ~/mg/publish \
  --pub ~/mg/keys/owner-2026.pub --confirm blog --metrics-textfile /var/lib/node_exporter/mg_bundle.prom
rsync -a ~/mg/publish/artifacts/ brain:/srv/mg/artifacts/ && rsync -a ~/mg/publish/bundles/ brain:/srv/mg/bundles/
mgctl keys export --in ~/mg/blog/token.keys.json.age | ssh edge 'sudo systemd-creds encrypt --name=mg-blog-token-keys - /etc/credstore.encrypted/mg-blog-token-keys'
```

- 工作站上的密钥文件都是 age（scrypt 口令）加密的 `.age`，明文只经 `keys export` 流向 Edge 主机。明文格式（规范 JSON，§12.0）与有效 / 无效样例在 `testdata/phase1/keys/`；生成器在固定随机流与时间下逐字节重现这些样例。
- 轮换顺序（凭证密钥、封装根密钥、所有者签名密钥）见规格 §17 第 5 步。
- `testdata/sites/golden/` 的 `golden-norules.bundle` 与 `golden-rules.bundle` 由 `go test ./internal/bundle -run TestGolden -update` 生成（版本 1790000000、时间 2026-09-27T10:00:00Z、`testdata/phase1` 的所有者测试密钥），mg-edge 的测试用 Rust 验签与解码；策略 IR 或配置包 schema 变化后重新生成并提交。

## 审计日志

JSON Lines，每条记录的字段与哈希链见规格 §12.8：`hash = lower_hex(SHA-256(prev_hash ‖ "\n" ‖ canonical))`，第一条的 `prev_hash` 为 64 个 `0`。路径依次取 `--audit-log`、`MGCTL_AUDIT_LOG`、`$XDG_STATE_HOME/morphgate/audit.jsonl`、`~/.local/state/morphgate/audit.jsonl`；文件 0600、目录 0700，追加时持 `audit.jsonl.lock` 上的排他 `flock` 并 fsync。写入类命令在改动任何东西之前先打开日志并检查最后一条记录，日志不可用时以退出码 3 失败；`diff` 从不含密钥材料。`mgctl audit verify` 逐行校验：任何一个字节被改动（含空白）都会定位到所在行。

## 用法示例

```sh
go run ./cmd/mgctl policy check testdata/policies/valid
go run ./cmd/mgctl policy check -profile cloudflare testdata/policies/valid   # 未声明 profile: 的文件按 cloudflare 检查
go run ./cmd/mgctl policy compile -o /tmp/rules.json testdata/policies/valid
go run ./cmd/mgctl site check --site-config testdata/sites/valid/full.yaml
go run ./cmd/mg-control -listen 127.0.0.1:8090
```

## 策略语言要点

- 命名空间：`req`、`net`、`upstream`、`tls`、`http`、`edge_tls`、`identity`、`risk`、`route`、`rate`（`map(string, double)`）、`labels`（`list(string)`）。字段定义在 `internal/policy/context.go`，拼错字段是编译错误。
- 策略文件可在顶层声明站点的 UpstreamProfile：`profile: cloudflare`（取值为 UpstreamProfileKind 小写名；目前只有 `cloudflare`、`direct_tls` 有字段可用性表，其他取值跳过检查并给出告警）。声明后，读取该 profile 下恒为 `MISSING` 的字段（规格 §4.4）且表达式中没有同路径 `has()` 守卫的规则会得到告警。未声明时不检查；`-profile` 只作用于未声明的文件，与声明冲突是错误。`bundle build` 按站点的 `profile` 检查它引用的策略文件。
- `allow` / `block` 规则读取 `identity.crawler.cf_vbot` 或 `cf_vbot_cat`，但顶层 `&&` 条件中没有 MorphGate 自有验证（`identity.crawler.verified` 或 `risk.class == "..."`）时告警：Cloudflare 标记只作佐证。
- 扩展函数：`ip_in(string, list(string)) bool`、`list(string) list(string)`（命名列表，参数必须是字符串字面量）、`glob(string, string) bool`（`*` 不跨 `/`，`**` 跨 `/`，`?` 单个非 `/` 字符；模式必须是字面量）。
- 编译器把 CEL 降级为受限 IR（规格 §5.1）；不支持的构造（算术、宏、类型转换等，§5.2）与静态步数上界超过 100,000 的规则是编译错误。只能对 map 字段直接取下标（`req.headers["accept"]`、`req.headers.accept`、`rate["login"]`）；对 `?:` 算出的 map 取下标或选择报 `unsupported in policy IR: computed map`，改写为 `c ? m[k] : m[k]`（裁决 I-20）。`internal/policy` 的参考求值器与 Rust IR 求值器按 `testdata/policy-ir/` 的一致性用例对齐；数据面不运行 cel-go。
