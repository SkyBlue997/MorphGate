# control-plane

Go 模块 `morphgate/control-plane`：`mgctl`（运维 CLI）与 `mg-control`（控制面服务）。设计见 [docs/06](../docs/06-policy-console-observability.md)。

## 当前状态（Phase 0）

| 组件 | 已实现 | 后续阶段 |
|---|---|---|
| `mgctl policy check` | YAML 模式校验（拒绝未知字段、临时规则必须有 `expires_at`）、cel-go v0.30 类型检查、输出必须为 bool、代价估算与上限、`list()` / `glob()` / `ip_in()` 字面量检查；告警：按文件声明的 `profile:`（或 `-profile`）检查恒为 `MISSING` 且未用 `has()` 守卫的字段，以及仅凭 `identity.crawler.cf_vbot` / `cf_vbot_cat` 放行或阻断的规则 | Phase 1：求值期 `MISSING` 语义（"未知"、`missing_input`） |
| `mgctl policy compile` | 输出已检查规则的 JSON 数组（字段名对齐 `morphgate.v1.CompiledRule`，附 `cost`、`fields`、`source`） | Phase 1：CEL → 受限 IR（当前 `ir_version: 0`，不输出 `expr_ir`）、策略包签名 |
| `mgctl cf audit` | 只打印计划检查项，退出码 2 | Phase 1：通过 Cloudflare API 实现（只读最小权限 Token） |
| `mg-control` | `GET /healthz`、`GET /v1/bundles/{site}` → 404 `{"error":"not_implemented","phase":3}`、优雅退出 | Phase 3：配置包分发、管理 API、存储 |

`gen/morphgate/v1` 是 `scripts/gen-proto.sh` 生成并提交的代码，不要手改；`scripts/gen-proto.sh --check` 检查是否过期。

## 用法

```sh
go run ./cmd/mgctl policy check testdata/policies/valid
go run ./cmd/mgctl policy check -profile cloudflare testdata/policies/valid   # 未声明 profile: 的文件按 cloudflare 检查
go run ./cmd/mgctl policy compile -o /tmp/rules.json testdata/policies/valid
go run ./cmd/mg-control -listen 127.0.0.1:8090
```

退出码：0 通过；1 策略错误；2 用法错误或命令尚未实现。

## 策略语言要点

- 命名空间：`req`、`net`、`upstream`、`tls`、`http`、`edge_tls`、`identity`、`risk`、`route`、`rate`（`map(string, double)`）、`labels`（`list(string)`）。字段定义在 `internal/policy/context.go`，拼错字段是编译错误。
- 策略文件可在顶层声明站点的 UpstreamProfile：`profile: cloudflare`（取值为 UpstreamProfileKind 小写名；目前只有 `cloudflare`、`direct_tls` 有字段可用性表，其他取值跳过检查并给出告警）。声明后，读取该 profile 下恒为 `MISSING` 的字段（`cloudflare`：`tls.*`、`http.header_order`；`direct_tls`：`edge_tls.*`、`identity.crawler.cf_vbot`、`identity.crawler.cf_vbot_cat`）且表达式中没有同路径 `has()` 守卫的规则会得到告警。未声明时不检查；`-profile` 只作用于未声明的文件，与声明冲突是错误。
- `allow` / `block` 规则读取 `identity.crawler.cf_vbot` 或 `cf_vbot_cat`，但顶层 `&&` 条件中没有 MorphGate 自有验证（`identity.crawler.verified` 或 `risk.class == "..."`）时告警：Cloudflare 标记只作佐证。
- 扩展函数：`ip_in(string, list(string)) bool`、`list(string) list(string)`（命名列表，参数必须是字符串字面量）、`glob(string, string) bool`（`*` 不跨 `/`，`**` 跨 `/`，`?` 单个非 `/` 字符；模式必须是字面量）。
- `internal/policy` 的 `Evaluator` 是参考语义，Phase 1 的 Rust IR 求值器以它为准做一致性测试；数据面不运行 cel-go。
