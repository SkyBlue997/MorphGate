# control-plane

Go 模块 `morphgate/control-plane`：`mgctl`（所有者工作站上的运维 CLI）、`mg-control`（控制面服务）与近线 worker `mg-nearline`。设计见 [docs/06](../docs/06-policy-console-observability.md)，Phase 1 的命令与文件格式以 [Phase 1 实现规格](../docs/impl/phase1-spec.md) §8.2、§8.3、§12、§14 为准；Phase 2 的新增与改动以 [Phase 2 实现规格](../docs/impl/phase2-spec.md) §3.2、§4.2、§8、§10.2、§13、§16 为准。

## 当前状态

| 组件 | 内容 |
|---|---|
| `mgctl policy check / compile` | 策略 YAML 校验、cel-go 类型检查、CEL → 策略 IR（`expr_ir`、静态步数上界 `max_steps`，规格 §5）（`internal/policy`） |
| `mgctl site check`、`bundle build / sign / verify / publish` | 站点 YAML v1、签名配置包的构建、签名、校验与发布（`internal/sitecfg`、`internal/bundle`） |
| `mgctl keys …`、`site keys …`、`verdict key` | 所有者签名密钥、站点密钥、假名化密钥、上游密钥头、导出与轮换、verdict 键计算（`internal/keys`） |
| `mgctl audit verify` | 本地哈希链审计日志（`internal/audit`） |
| `mgctl cf audit`、`cf ips sync`、`crawler sync` | Cloudflare zone 审计与情报工件同步（`internal/cfapi`、`internal/cfaudit`、`internal/intelsync`） |
| `mg-control` | `GET /healthz`、`GET /v1/bundles/{site}` → 404 `{"error":"not_implemented","phase":3}`、优雅退出；配置包分发与管理 API 在 Phase 3 |
| Phase 2：站点 YAML 与配置包 | 交互式挑战、刷新、遥测、扫描诱饵、路由 `proof` / `min_level`、Turnstile Provider 的新键；构建器按是否出现 Phase 2 键写 `schema_version` 1 或 2（见下文"站点 YAML：Phase 2 字段"）（`internal/sitecfg`、`internal/bundle`） |
| Phase 2：策略 | 新字段 `http.navigation`、`identity.proof.present` / `replayed`、`identity.token.bound` / `level_age`；`identity.proof` 不再恒为 MISSING（`internal/policy`） |
| `mgctl turnstile …` | Turnstile widget 列表、secret 导入与轮换、`mg-turnstile-keys` 凭证文件（`internal/turnstile`、`internal/keys`） |
| `mg-nearline` | 近线 worker：消费 `mg:ev`、检测器 v1、verdict 写入（`internal/nearline`，WP-N1；用法见下文） |

`gen/morphgate/v1` 是 `scripts/gen-proto.sh` 生成并提交的代码，不要手改；`scripts/gen-proto.sh --check` 检查是否过期。

## 命令一览

| 命令 | 作用 | 审计 action |
|---|---|---|
| `mgctl policy check [flags] <file\|dir>…` | 校验策略文件（`-profile cloudflare\|direct_tls`、`-max-cost N`） | — |
| `mgctl policy compile [flags] [-o out.json] <file\|dir>…` | 输出每条规则的 JSON（含 `expr_ir`（标准 base64）与 `max_steps`） | — |
| `mgctl site check --site-config <site.yaml>` | 校验站点 YAML、策略、名单与工件，不写任何文件；接受 Phase 2 的新键 | — |
| `mgctl bundle build --site-config <site.yaml> --out-dir <dir> [--version N]` | 写 `<dir>/<site>.sitebundle.pb`、`<dir>/<site>.sitebundle.json`（protojson，只供人看）与 `<dir>/artifacts/<sha256>`；`--version` 缺省为构建时的 Unix 秒；`schema_version` 为 1 或 2 | — |
| `mgctl bundle sign --in <pb> --key <kid>.key.age --out <file.bundle>` | 用所有者密钥签名（签名输入 `"mg-bundle-v1" ‖ 0x00 ‖ bundle`） | `bundle.sign` |
| `mgctl bundle verify --in <file.bundle> --pub <kid>.pub… [--site <id>] [--json]` | 验签、解码并打印摘要（`--pub` 可重复）；校验 `schema_version` 规则；`schema_version 2` 时另列出交互式配置、Provider（只有公开字段）、`proof: required` 与 `min_level` 的路由、`help_path` 与 `privacy_path`，`scoring.mode: enforce` 时打印提醒 | — |
| `mgctl bundle publish --in <file.bundle> --artifacts <dir> --dest <dir> --pub <kid>.pub… --confirm <site> [--metrics-textfile <path>]` | 验签后先写 `<dest>/artifacts/<sha256>`、再写 `<dest>/bundles/<site>.bundle`；版本必须大于已发布的版本；`--metrics-textfile` 写 `mg_bundle_published_version{site}` | `bundle.publish` |
| `mgctl keys gen --kid <kid> --out-dir <dir> [--insecure-test-key]` | 所有者 Ed25519 签名密钥：`<kid>.key.age`（0600）与 `<kid>.pub`（0644） | `keys.gen` |
| `mgctl keys gen-pseudo --out <file.json.age> [--insecure-test-key]` | 假名化密钥 `K_pseudo`（Valkey 键中标识个人部分的 HMAC 密钥） | `keys.gen_pseudo` |
| `mgctl keys gen-upstream --out <file.json.age> [--rotate] [--insecure-test-key]` | 上游密钥头值；`--rotate` 把新值放前、保留 2 个；`values[0]` 打印到 stdout，用于 Cloudflare 的 `set x-mg-upstream-key` 规则 | `keys.gen_upstream` |
| `mgctl keys gen-origin --out <file.json.age> [--rotate] [--insecure-test-key]` | Edge → 源站认证密钥（`mg-origin-keys`，裁决 I-38）；`--rotate` 同上；不打印密钥，文件经 `keys export` 先给源站（接受全部值）、再给 Edge 的 `origin_keys` 凭证（用 `values[0]` 签名） | `keys.gen_origin` |
| `mgctl keys export --in <file.json.age> [--out <file> \| -]` | 解密站点 / 假名化 / 上游 / 源站密钥文件；缺省写 stdout（管道到 `systemd-creds encrypt`），`--out` 写新的 0600 明文文件；所有者签名密钥不可导出 | `keys.export` |
| `mgctl site keys gen --site <id> --out-dir <dir> [--date YYYYMMDD]` | `token.keys.json.age` 与 `seal.root.json.age` | `site_keys.gen` |
| `mgctl site keys rotate-token --site <id> --file <token.keys.json.age> [--date YYYYMMDD]` | 新 token key 放前，至多保留 3 个；打印新 kid | `site_keys.rotate_token` |
| `mgctl site keys rotate-seal --site <id> --file <seal.root.json.age> --step add\|promote\|retire [--date YYYYMMDD]` | 封装根密钥三步轮换：`add` 新根放第二位，`promote` 交换，`retire` 删除第二个 | `site_keys.rotate_seal` |
| `mgctl verdict key --pseudo-key <file.json.age> --site <id\|all> --type ip\|prefix\|asn\|session --value <v>` | 打印 verdict 的完整 Valkey 键（`ip` 先取 ip 实体：IPv4 地址或 IPv6 /64；`prefix` 接受地址或其 /24、/48），供所有者手工 `SET`；只读 | — |
| `mgctl audit verify` | 校验审计日志哈希链；打印条数与最后的 hash，断链时指出行号 | — |
| `mgctl cf audit --site-config <site.yaml> [--cf-ips <artifact>] [--vm-url <url>] [--sdk-dir <dir>] [--ack <check>=<note>]… [--strict] [--json] [--metrics-textfile <path>]` | 用只读 API Token（`CLOUDFLARE_API_TOKEN`）审计所有者 zone 的 21 项设置（规格 §14.3）；任一 error 级失败（`--strict` 下含 `manual`）退出码 1 | — |
| `mgctl cf ips sync --out <file> [flags]` | 同步 Cloudflare IP 段工件（`cloudflare-ips.json`，规格 §12.2、§14.4）；条数变化超过 30% 需 `--accept-change`；写 `<out>.state.json` | `cf.ips.sync` |
| `mgctl crawler sync --registry <src.yaml> --out <file> [--previous <file>] [--accept-change]` | 抓取各爬虫运营方的官方 IP 段并写注册表工件（规格 §12.3、§14.5）；变化保护同上（50%）；`rdns_suffixes` 每项以 `.` 开头、其后至少两段标签（如 `.googlebot.com`，裁决 I-22；Edge 只按标签边界匹配） | `crawler.sync` |
| `mgctl turnstile widgets --account <id> --cf-token-file <file.age>` | 列出账户的 Turnstile widget（`GET /accounts/{id}/challenges/widgets`，列表不含 secret） | — |
| `mgctl turnstile secret import --account <id> --sitekey <k> --site <site> --out <file> --cf-token-file <file.age>` | 读取 widget（响应含 secret），写出只含当前值的 `mg-turnstile-keys` 文件（0600，从不覆盖） | `turnstile.secret.import` |
| `mgctl turnstile secret rotate --account <id> --sitekey <k> --keys <file> [--invalidate-immediately] --cf-token-file <file.age>` | 先确认文件的当前值就是 widget 的当前 secret，再调用 `rotate_secret`，**总是显式**发送 `invalidate_immediately`（缺省 `false`）；写出 `[新, 旧]`（`--invalidate-immediately` 时只写新值） | `turnstile.secret.rotate` |
| `mgctl turnstile secret drop-previous --keys <file>` | 写回只含当前值的文件 | `turnstile.secret.drop_previous` |

### 约定

- **退出码**：`0` 成功；`1` 输入无效或检查失败；`2` 用法错误或尚未实现；`3` I/O 或内部错误（含审计追加失败）。
- **全局标志 `--audit-log <path>`**：可写在命令行任意位置（`--` 之前），所有写入类命令（含 `cf ips sync`、`crawler sync`）都追加到同一个日志，并且在抓取或写入任何文件之前先确认日志可用，不可用时什么都不写、退出码 3（集成者裁决 I-27）。
- **环境变量**：`MGCTL_PASSPHRASE_FILE`（口令文件，取第一行；测试与自动化用，否则从终端无回显读取，生成时输入两次；口令从不出现在命令行）、`MGCTL_AGE_WORK_FACTOR`（10–22，缺省 18；小于 18 必须加 `--insecure-test-key`，只用于测试与 Lab）、`MGCTL_AUDIT_LOG`、`CLOUDFLARE_API_TOKEN`、`MGCTL_CF_API_BASE`（缺省 `https://api.cloudflare.com/client/v4`，测试指向 httptest；`cf audit` 与 `turnstile` 共用）。
- **文件写入**：一律先写临时文件、fsync 后再 `rename`（或硬链接）；密钥文件与工件从不覆盖已有文件（轮换命令原子替换 `--file` 指定的文件）。
- **出站请求**（`cf audit`、`cf ips sync`、`crawler sync`、`turnstile`）：User-Agent 一律为 `morphgate-dev-tooling`（集成者裁决 I-7，覆盖规格 §14.1 的 `mgctl/<version>`），不带所有者的邮箱或其他身份信息。

## 站点 YAML v1

格式与校验规则见规格 §8.2，映射到 `SiteBundle` 的方式与缺省值见 §8.3；样例：`testdata/sites/valid/full.yaml`（规格中的示例）、`testdata/sites/valid/minimal.yaml`（全部取缺省值）。实现细节：

- 未知键、YAML 锚点 / 别名、多文档都是错误；诊断信息带 `文件:行:列`。相对路径相对于 YAML 文件所在目录。
- 路由可设 `mode: monitor | enforce` 覆盖站点的 `monitor_only`（规格 I-36）：多条路由经不同路径视图命中同一请求时取最严者；`mgctl bundle verify` 列出覆盖的路由，签名的审计记录带 `route_modes`。
- 路由可设 `never_challenge: true`（规格 I-37，只允许 `low` / `medium` 且不 `require_clearance` 的路由）：该路由上的 CHALLENGE 只记录并转发，BLOCK 与 RATE_LIMIT 照常；多条路由命中同一请求时要全部带该标志，精确路径同时列出 `/x` 与 `/x/`。限速器 `on_exceed: challenge` 显式列出这样的路由是错误，覆盖全部路由时给警告；签名的审计记录带 `never_challenge`。
- 缺省值：`monitor_only: true`；`channel: web`；`require_clearance` 与 `fail_closed` 在 `sensitivity: critical` 时为 true；限速器 `burst: 1`、`scope: global`、`mode: enforce`；`automation_allowlist_only` 对 `production` 以外的环境为 true。`sensitivity`、限速器的 `key`、`rate`、`on_exceed` 必填。
- 每个环境末尾追加 `{name: default, paths: ["/**"], channel: web, sensitivity: low}`，除非已有一个 `paths: ["/**"]` 且不限定 `hosts` / `methods` 的路由；`default` 这个名字只能用于这样的路由。每个环境至多 64 条**声明**路由，追加的 `default` 不计入（配置包中至多 65 条，与 Edge 的校验一致，裁决 I-24）。
- 限速器 id 在整个站点内唯一（跨环境，裁决 I-23）：Valkey 键 `mg:rl:{site}:{limiter}:{kh}` 不含环境，两个环境共用一个 id 会共用同一组 GCRA 桶。
- 构建时额外检查：策略规则只允许 Phase 1 参数（`challenge` 的 `type: invisible|pow|interactive`、`tag` 必需的 `label`、`rate_limit` 的 `limiter` 与 `retry_after_s`）；`tarpit` 报错（D-09），`interactive` 告警（D-08，按 `pow` 执行）；规则引用的名单都必须在 `lists` / `list_files` 中定义，IR 中 `ip_in()` 用到的名单必须全是 IP 或 CIDR；规则缺 IR（`ir_version != 1` 或 `expr_ir` 为空）时构建失败，所以不会产生 Edge 无法加载的配置包；工件按 Edge（mg-intel）的解析规则校验：MaxMind DB 完整校验并检查 `database_type`；JSON 工件逐字段严格读取（成员名大小写须一致，重复成员、缺失成员与 `null` 都是错误，只有注册表的 `test` 可省略）；IPv6 段只接受全球单播 `2000::/3` 且不与 `2001::/23`、文档段 `3fff::/20` 相交；时间戳为 `Z` 或 `±hh:mm`（小时 ≤ 23）的 RFC 3339；`tor-exits` 至多 1,000,000 条，ASN 至多 10 位数字。任何一项 Edge 会拒绝的内容都会让整个配置包被拒，所以构建时就报错。
- 构建结果是确定性的：同样的输入与 `--version` 得到同样的字节；`challenge`、`clearance`、`scoring`、`crawler_policy`、`events`、`origin_headers` 总是完整写出（proto3 无法区分"未设置"与零值）。

## 站点 YAML：Phase 2 字段

新键与取值范围见 Phase 2 规格 §10.2，样例为 `testdata/sites/golden/site-phase2.yaml`（每个新键、`type: interactive` 的限速器与 Turnstile Provider 各至少出现一次）。实现细节：

- **`schema_version`**（规格 §3.2、D-66）：YAML 中出现任何一个 Phase 2 键（即使写的是缺省值，如 `refresh: false`、路由的 `proof: off`）或取值（`on_exceed: {action: challenge, type: interactive}`），或配置包中的规则读取 Phase 2 策略字段（`http.navigation`、`identity.proof.present` / `replayed`、`identity.token.bound` / `level_age`）时，构建器写 `schema_version = 2`，并把全部 Phase 2 字段的缺省值显式写进配置包；否则写 1，与 Phase 1 构建器的输出逐字节相同。Phase 1 的 Edge 拒绝 `schema_version = 2` 的配置包（继续用上一个有效的）。`bundle sign`、`verify`、`publish` 与构建器都执行规格 §3.2 的 `schema_version` 规则（`internal/bundle` 的 `CheckSchema`）。
- 规则只读 `identity.proof.valid`（Phase 1 字段）不会让配置包变成 2：`schema_version = 1` 时它恒为 MISSING，构建器为此告警。
- 缺省值：`clearance` 的 `ttl_interactive_s` 1800、`ttl_interactive_a11y_s` 900、`ttl_interactive_ext_s` 1800、`refresh` false、`refresh_max_interactive_s` 14400、`refresh_max_ext_s` 7200、`refresh_max_pow_s` 为 `2 × ttl_pow_s`（超过 86400 时取 86400）；`challenge.default_lang` zh-CN、`help_path` 与 `privacy_path` 为 `/`；`challenge.interactive` 见规格 §10.2 的示例值（`enabled: false`、`scoring: {mode: shadow}`）；`events.scanner_baits.builtin` true；Provider 的 `enabled` true、`selection` escalate_after_fail、`mode` shadow、`timeout_ms` 4000、`fallback` self_hold、`deny_countries` 为空。
- `scoring.mode: shadow` 时写 `t_pass` / `t_block` 是错误；`enforce` 时两者必填，`0 < t_pass < t_block ≤ 1`（按配置包中的 float32 比较），并打印 §7.8 的提醒。
- `issue` 与 `renew` 的 `rate` 用限速器的 `<n>/<duration>` 语法；`ipp` 一级是速率与 burst 的 4 倍（D-67），两级都必须是有效的 GCRA 参数。
- `providers` 至多一项，只能是 `turnstile`；`self_hold` / `pow_a11y` 是内置的，不在这里配置；`fallback` 只能是 `self_hold`（D-51）；YAML 里没有 `secret_refs` 与 `allowed_countries`：secret 在 `edge.toml` 的 `[[sites]] turnstile_keys`（见下文）。`routes` 中的路由名必须在某个环境中存在；`hostnames` 必须是站点的主机名。
- 策略编译器（规格 §4.2）：`identity.proof` 不再恒为 MISSING，读取它不再告警；`allow` 规则以 `http.navigation` 为条件是错误，其他动作给警告；`block` 规则同时读取 `identity.proof.present` 与 `identity.proof.valid` 时提示改用 `challenge`。`params.type: interactive` 的规则只在站点 `challenge.interactive.enabled: false` 时由构建器告警"按 pow 执行"（D-08）。
- 警告（不阻止构建）：`min_level: interactive` 或交互式限速器而交互式未启用；`proof: required` 的 `web` 路由允许非安全方法；`min_level: interactive` 或交互式限速器只作用于含 POST、不含 GET 的路由；启用了 Turnstile、`deny_countries` 非空，但既没有 `geoip_country` 工件也没有 `cloudflare.location_headers`；`events.telemetry_behavior: true`（先更新隐私说明）。

## Turnstile secret

Turnstile 是可选的外部 Provider（规格 §8）。配置包只放公开配置；secret 是 Edge 的部署凭证，格式为 `mg-turnstile-keys`（规格 §8.7）：`{"v": 1, "kind": "mg-turnstile-keys", "site": "<site>", "values": ["<当前>", "<上一个>"]}`，1–2 个值，每个 1–256 个可见 ASCII 字符，文件 ≤ 64 KiB，未知字段报错。`mgctl` 写出的字节与 `testdata/phase2/samples/keys/valid/` 的规范 JSON 相同。

```sh
age -p -o ~/mg/keys/cf-turnstile-token.age    # 粘贴只授予 Account > Turnstile > Edit 的 API token
mgctl turnstile widgets --account <account-id> --cf-token-file ~/mg/keys/cf-turnstile-token.age
mgctl turnstile secret import --account <account-id> --sitekey <sitekey> --site blog \
  --out ~/mg/blog/turnstile-keys.json --cf-token-file ~/mg/keys/cf-turnstile-token.age
ssh edge 'sudo systemd-creds encrypt --name=mg-turnstile-keys-blog - /etc/credstore.encrypted/mg-turnstile-keys-blog' < ~/mg/blog/turnstile-keys.json
# 常规轮换：旧 secret 在 Cloudflare 保留 2 小时，此期间不能再次轮换
mgctl turnstile secret rotate --account <account-id> --sitekey <sitekey> --keys ~/mg/blog/turnstile-keys.json \
  --cf-token-file ~/mg/keys/cf-turnstile-token.age
# 部署新文件并 systemctl reload mg-edge 之后：
mgctl turnstile secret drop-previous --keys ~/mg/blog/turnstile-keys.json
```

- API token 以 age（口令）加密保存，`--cf-token-file` 解密后只作为 bearer token 发给 `MGCTL_CF_API_BASE`（https，或回环上的测试服务器），不跟随重定向。
- `rotate` 总是显式发送 `invalidate_immediately`；疑似泄露时加 `--invalidate-immediately`，旧 secret 立即失效，文件只写新值，应尽快部署（部署之前 Turnstile 校验失败，访客回退到 `self_hold`）。`rotate` 先读取 widget，确认文件的当前值就是 widget 的当前 secret，否则不轮换；轮换成功而写文件失败时用 `secret import` 恢复到新文件。
- 写文件之前先确认审计日志可用（裁决 I-27），`rotate` 在调用 Cloudflare 之前确认。审计条目只记 sitekey、站点与操作，从不记 secret；命令也从不在输出中打印 secret。
- 测试只用 `net/http/httptest`；任何测试都不访问 Cloudflare。

## 近线 worker `mg-nearline`

`mg-nearline` 消费 Edge 写入 Valkey 的 `mg:ev` 流（消费组 `nl`），在内存窗口中运行检测器 v1，把只抬高风险的 verdict 写回 `mg:v:<site>:*`（规格 §13、D-53）。它从不在请求路径上：worker 停止时 Edge 照常按规则评分，已写的 verdict 按 TTL 过期。实现由 WP-N1 交付；本节按规格 §13 说明用法。

- **前提**：Edge 用 Valkey 模式，配置包 `events.stream = true`（缺省）。本地模式（`[valkey] mode = "local"`）没有 `mg:ev`，近线没有输入（D-38）。
- **配置文件**（YAML，未知键报错；值中只展开 `${CREDENTIALS_DIRECTORY}`，其他 `${…}` 报错）：

  ```yaml
  version: 1
  valkey:
    url: "unix:///run/valkey/valkey.sock"     # 或 redis://127.0.0.1:6379/ ；只允许回环
    user: mg-nearline
    password_file: "${CREDENTIALS_DIRECTORY}/mg-nearline-valkey"
  stream: {key: "mg:ev", group: nl, batch: 512, block_ms: 1000, reclaim_idle_ms: 60000, reclaim_every_s: 60}
  sites: [blog]
  verdict_events: {vl_main: "http://127.0.0.1:9428"}    # 可选
  metrics_listen: "127.0.0.1:9902"
  windows: {max_keys: 200000, ipv6_prefix_factor: 4}
  detectors:
    scanner:         {mode: shadow, bait_distinct: 2, distinct_404: 30, share_404: 0.6, risk: 80, ttl: 15m}
    shared_token:    {mode: shadow, proof_mismatch: 3, distinct_prefix: 2, risk: 85, ttl: 1h}
    challenge_abuse: {mode: shadow, fails: 30, max_pass_ratio: 0.1, risk: 70, ttl: 30m}
    high_rate:       {mode: shadow, per_minute: 600, minutes: 5, shared_egress: 3, risk: 75, ttl: 15m}
  acceptance: {window_days: 7, min_denominator: 2000, max_keys_per_day: 200000}
  ```

- **检查**：`mg-nearline --check-config` 校验配置文件并连通 Valkey 后退出。
- **检测器**（缺省都是 `shadow`：只记日志与指标，不写 Valkey）：`scanner`（按 `ipk`，扫描诱饵或大量 404 / 403 / 405）、`shared_token`（同一会话凭证被另一把会话密钥使用，`pf = j`）、`challenge_abuse`（按前缀的挑战失败）、`high_rate`（连续 5 分钟每分钟 ≥ 600 次，共享出口除外）。IPv6 另按 /48 计数，阈值为 4 倍。verdict 只抬高风险（标签 `nl_*`），从不带会直接阻断的 `scanner` 标签；浏览器代发的跨站请求（`xs = 1`）与带有效凭证的请求（`tk = 1`）不计入扫描器与高速率。阈值见规格 §13.3。
- **部署**：`deploy/systemd/mg-nearline.service`（`DynamicUser=yes`，`LoadCredentialEncrypted=mg-nearline-valkey:…`，`IPAddressAllow=localhost`，`MemoryMax=512M`，日志写入 journald 命名空间 `morphgate`）。只运行一个实例。
- **Valkey ACL 用户 `mg-nearline`**（每个站点一项 `~mg:v:<site>:*`，不含 `mg:v:all:*`）：

  ```
  ACL SETUSER mg-nearline on >… resetkeys resetchannels -@all +get +set +xreadgroup +xack +xautoclaim +xgroup|create +xgroup|delconsumer +xinfo|groups +xinfo|consumers +xpending +xlen +evalsha +script|load +ping +hello +select +client|setname +client|setinfo ~mg:ev ~mg:v:blog:*
  ```

- **压住误伤**：用 `mgctl verdict key --pseudo-key … --site blog --type ip --value <ip>` 算出键，写一条 `source = "owner"`、`risk = 0`、带 `expires_at_ms` 的 verdict 到这个键；近线从不覆盖所有者写的 verdict，到期后自然恢复。
- **指标**（`metrics_listen` 上的 `/metrics`）：`mg_nl_entries_total`、`mg_nl_parse_errors_total`、`mg_nl_verdicts_total`、`mg_nl_lag_seconds`、`mg_nl_backlog`（告警用它：消费者停止时积压只体现在这里）、`mg_nl_pending`、`mg_nl_window_dropped_total`、`mg_nl_errors_total`、`mg_nl_last_batch_timestamp_seconds`，以及验收比例 `mg_nl_interactive_visitor_share`、`mg_nl_interactive_abandon_share`（分母少于 2,000 时不导出）。
- 出站 HTTP（只有 `vl_main`）的 User-Agent 为 `morphgate-dev-tooling`。

## 密钥与发布流程

```sh
export MGCTL_PASSPHRASE_FILE=...            # 或在终端输入口令
mgctl keys gen --kid owner-2026 --out-dir ~/mg/keys
mgctl keys gen-pseudo --out ~/mg/keys/pseudo.key.json.age
mgctl keys gen-upstream --out ~/mg/keys/upstream-keys.json.age
mgctl keys gen-origin --out ~/mg/keys/origin-keys.json.age     # 可选：源站校验 MG-Origin-Auth 时
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
- `testdata/sites/golden/` 的 `golden-norules.bundle`、`golden-rules.bundle`（`schema_version 1`）与 `golden-phase2.bundle`（`schema_version 2`，来自 `site-phase2.yaml`）由 `go test ./internal/bundle -run TestGolden -update` 生成（版本 1790000000、时间 2026-09-27T10:00:00Z、`testdata/phase1` 的所有者测试密钥），edge-core 与 mg-edge 的测试用 Rust 验签与解码；策略 IR 或配置包 schema 变化后重新生成并提交。Phase 1 的两个 golden 配置包必须保持逐字节不变。

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
