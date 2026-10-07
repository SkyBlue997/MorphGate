# @morphgate/web-sdk

MorphGate 第一方 Web SDK（私有包）。设计见 [04 §7](../../docs/04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)；Phase 1 契约见 [实现规格 §10–§11](../../docs/impl/phase1-spec.md#11-web-sdk-phase-1wp-w1)。

## 现状：Phase 1（`SDK_VERSION = "0.1.0-phase1"`）

Phase 1 的 SDK 只做一件有网络副作用的事：在 Edge 下发的挑战页上完成无感 Challenge（SHA-256 PoW）并以表单导航提交 `POST /__mg/c`。遥测上传、会话密钥、`MG-Proof`、fetch 包装在 Phase 2。

| 模块 | Phase 1 | 后续 |
|---|---|---|
| `index.ts` | 入口。文档中：从脚本标签 `data-mg-*` 读取配置，暴露只读的 `window.MorphGate`（`version`、`config`、`snapshot()`、`classifyResponse`），页面有 `#mg-challenge` 时运行挑战流程。Worker 中（`self instanceof WorkerGlobalScope`）：只安装 PoW 消息处理器 | Phase 2：静默刷新、遥测 |
| `config.ts` | `data-mg-*` 解析、路径前缀规范化（只接受同源绝对路径） | |
| `challenge.ts` | 挑战页客户端：读取并校验 `#mg-challenge` 的数据属性、SHA-256 自检、Worker / 主线程 PoW、组装提交 JSON、隐藏表单提交、失败页的一次自动重试、状态文字与重试链接 | Phase 2：交互式 Challenge、Provider |
| `pow.ts` | `sha256-hashcash-v1`：前缀、midstate 搜索、校验、Worker 消息协议 | |
| `sha256.ts` | 纯 TypeScript SHA-256（压缩函数可从任意轮开始，供 midstate 复用） | |
| `env.ts` | 环境摘要：UA / 低熵 Client Hints、语言、时区、屏幕与视口（量化）、核心数、触控、存储可用性。字符串截断不拆开代理对；含孤立代理项的值记为 `null`（`JSON.stringify` 会把它写成 `\udXXX`，Edge 的严格 JSON 解析会拒绝整个提交） | Phase 2：图形栈家族摘要（只取家族，不取渲染器字符串） |
| `automation.ts` | 只读标准 `navigator.webdriver` | Phase 2：其他自动化特征 |
| `behavior.ts` | 纯函数量化器：`logBucket`、`roundToStep`、`clamp`、`logHistogram` | Phase 2：指针 / 键盘 / 滚动 / 触控采集 |
| `crypto.ts` | WebCrypto ECDSA P-256 会话密钥（`extractable: false`）、RFC 7638 JWK 指纹（`cnf.jkt`） | Phase 2：IndexedDB 持久化、`MG-Proof`（ES256 JWS） |
| `transport.ts` | 识别 `cf-mitigated: challenge` → `upstream_challenge`；解析 MorphGate JSON（`mg_challenge` 等）；429 / 425 | Phase 2：fetch / XHR 包装、重试 |
| `telemetry.ts` | 载荷类型、UTF-8 字节数、2 KB 预算检查与按序裁剪 | Phase 2：会话密钥签名、`POST /__mg/t` |

隐私：不采集画布 / WebGL / 音频渲染哈希、渲染器字符串、字体 / 插件列表、高熵 Client Hints。任何采集异常只让对应字段为 `null`，不影响页面。

## 构建产物（§11.1）

`pnpm run build` = esbuild（IIFE、压缩、ES2020）→ `scripts/build-dist.mjs`：

| 文件 | 说明 |
|---|---|
| `dist/mg.js` | SDK 包；`size` 步骤要求 gzip ≤ 30,720 字节（当前约 7.3 KB） |
| `dist/sdk/mg.<hex16>.js` | 与 `dist/mg.js` 字节相同；`hex16` = 内容 SHA-256 的前 16 个十六进制字符 |
| `dist/sdk/challenge.html` | 挑战页模板（源文件 `templates/challenge.html`） |
| `dist/sdk/manifest.json` | `{"v":1,"build":"<hex16>","sdk":"mg.<hex16>.js","files":{"mg.<hex16>.js":"<sha256>"},"templates":{"challenge.html":"<sha256>"}}` |

`dist/sdk/` 整个目录复制到 Edge 主机，`edge.toml` 的 `[sdk] dir` 指向它。Edge 只经 `/__mg/s/<name>` 提供 `files` 中的文件，`templates` 只由 Edge 读取；两者的哈希与模板规则 Edge 在加载时再校验一次。

`build-dist.mjs` 导出纯函数 `buildDist({ bundle, template }, outDir) -> manifest`（输入在内存中，写入给定目录；删除目录中过期的 `mg.*.js`）与 `validateTemplate(template) -> string[]`；模板违反下述契约时构建失败。

## 挑战页模板契约（§11.2）

- 占位符恰好是 `{{lang}}` `{{nonce}}` `{{sdk_src}}` `{{prefix}}` `{{c}}` `{{type}}` `{{pow_bits}}` `{{ret}}` `{{request_id}}` `{{state}}`，每个至少一次，没有其他 `{{…}}`。Edge 按 HTML 属性上下文转义（`&` `<` `>` `"` `'`）后做纯文本替换。
- 结构：`<html lang="{{lang}}">`；`<main id="mg-challenge">` 带 `data-mg-state` / `-c` / `-type` / `-pow-bits` / `-ret` / `-rid` / `-prefix`；`<p id="mg-status" role="status" aria-live="polite">`；`<a id="mg-retry" href="{{ret}}" hidden>`；`<noscript>`；正文中的 `{{request_id}}`。
- UTF-8、≤ 32 KiB、不引用外部资源（不含 `http:` / `https:`、`//` 开头的 URL、CSS `@import`）；每个 `<script>` / `<style>` 带 `nonce="{{nonce}}"`；没有内联事件处理器与 `style` 属性（nonce-only CSP 会拦截）；SDK 的 `<script>` 把 `data-cfasync="false"` 写在 `src` 之前（Rocket Loader）。
- 占位符只能出现在带引号的属性值或普通文本中：不得出现在无引号属性值、属性名或标签名、`<script>` / `<style>` 内容与 HTML 注释中。Edge 的转义（`&` `<` `>` `"` `'`）只在这两种上下文里让取值失去标记含义；否则像 `ret = "/a/;alert(1)//"` 这样的值会变成脚本或标记。
- 中英文文案都在页面中，CSS 按 `<html lang>` 只显示一种；`prefers-reduced-motion` 下不做动画；深色模式跟随系统。SDK 在 `#mg-challenge` 上设置 `data-mg-phase`（`start` / `work` / `retry`），模板据此显示进度指示。

## 挑战流程（§11.3）

1. 读取并校验数据属性：`c` 为 base64url（≤ 1024 字符），`type` 为 `invisible` / `pow`，`pow_bits` 为 0–32，`ret` 满足 §6.4 的客户端子集（以 `/` 开头、非 `//`、无 `\`、控制字符与 `#`、≤ 512 字节、路径不是 `/__mg` 也不在 `/__mg/` 之下；Edge 的校验为准）。客户端检查不得比 Edge 严格，否则 Edge 签发的挑战在页面上永远无法完成：保留路径的判断与 `mg_core::paths::is_reserved` 的原始路径规则一样区分大小写（`/__MG/c` 是普通源站路径）。不合格即显示重试链接。
2. `state = failed`：有新 C 时每个 `ret` 至多自动重试一次（`sessionStorage` 键 `mg_retry:<ret>`，存取失败时不自动重试）；否则显示重试链接（`href = ret`）。
3. 自检：纯 JS SHA-256 对已知答案、midstate 搜索路径对通用路径、WebCrypto（可用时）对纯 JS；不一致则不启动。
4. PoW：`prefix = "mg-pow-v1" ‖ 0x00 ‖ SHA-256(C)`，以当前脚本 URL 启动 Worker。Worker 创建失败、报错、回复 `mg-pow-err` 或无效解，或 2 s 内没有任何回复时，改为主线程分片（每片 50,000 次哈希，片间 `setTimeout(0)`）。整体超过 60 s 停止计算并显示重试链接。
5. 组装提交 JSON（键序 `v, type, c, pow, ret, ts, build, env, auto`；`build` 取脚本文件名中的 `hex16`，取不到时为 16 个 `0`）；URL 编码后的正文超过 8 KiB 时依次去掉 `env`、`auto`。
6. 创建隐藏的 `<form method="POST" action="<prefix>c" enctype="application/x-www-form-urlencoded" accept-charset="UTF-8">`，唯一字段 `mg`，挂到 `body` 后 `submit()`；浏览器跟随 303 回到 `ret`，带上 `__Host-mg_clr`。
7. 任何异常都不抛进页面：状态文字改为"验证失败，请重试"并显示重试链接。

**Worker 协议**（Worker 与页面是同一个 SDK 文件）：

```
page   -> worker  {t: "mg-pow", prefix: Uint8Array(42), bits}
worker -> page    {t: "mg-pow-ack"}                       收到合法请求后立即发送
worker -> page    {t: "mg-pow-ok", counter} | {t: "mg-pow-err"}
```

`mg-pow-ack` 是对规格 §11.3 的补充：高难度下 Worker 的搜索可能超过 2 s，没有确认消息时"2 s 内无任何回复"会把正在工作的 Worker 误判为失效。页面在收到任何消息后取消 2 s 计时，Worker 的结果在提交前用通用 SHA-256 路径复核。

PoW 搜索从 0 开始、上限 `2^53 − 1`，每次尝试一次压缩（前 10 轮的 midstate 预先算好，消息扩展与轮函数合并在同一个循环里）；Node 26 / Apple M 系列上约 5 M 次/秒。

## 嵌入

```html
<script data-cfasync="false" src="/__mg/s/mg.<hex16>.js" nonce="..." data-mg-path-prefix="/__mg/"></script>
```

| 属性 | 默认 | 说明 |
|---|---|---|
| `data-mg-path-prefix` | `/__mg/` | 只接受同源绝对路径；非法值（`//host/`、`..`、URL）回退默认值 |
| `data-mg-site` | 无 | 站点 ID，仅供调试 |
| `data-mg-debug` | `false` | `true` 时在控制台打印快照 |

`data-cfasync="false"` 让 Cloudflare Rocket Loader 不改写该脚本。挑战页的 CSP 需要 `worker-src 'self'`（Worker 用同一个脚本 URL 启动）与 `form-action 'self'`。

## 命令

```bash
pnpm install
pnpm run check      # typecheck && test && build && size
pnpm run build      # esbuild -> dist/mg.js，然后 build-dist.mjs -> dist/sdk/
pnpm run size       # gzip(dist/mg.js) 必须 ≤ 30720 字节
```

## 测试（§11.5）

| 文件 | 内容 |
|---|---|
| `test/sha256.test.ts` | NIST SHA-256 向量（含 100 万个 `a`）；0–200 字节长度与 Node 的 SHA-256 对照 |
| `test/pow.test.ts` | 直接读取 `testdata/phase1/kat.json` 的全部 `pow` 用例（前缀、`first_counter`、`digest_hex`）；计数器高位与 `2^53 − 1` 边界；Worker 消息处理器（直接调用）；随机输入不抛异常 |
| `test/challenge.test.ts` | 数据属性解析与 `ret` 校验；提交 JSON 的形状、键序、无重复键、嵌套 ≤ 16、8 KiB 上限；表单构建（假 DOM，只有一个 `mg` 字段）；自动重试配额；自检；完整流程（假 Worker、假计时器：Worker 路径、各类回退、2 s / 60 s 计时、异常处理）；浏览器接线 |
| `test/template.test.ts` | 模板占位符、nonce、外部资源、`data-cfasync` 顺序、结构与双语；Edge 式渲染；每条规则的反例；随机输入不抛异常 |
| `test/build-dist.test.ts` | `buildDist` 在临时目录中生成的 manifest 与文件哈希、文件名一致；过期构建清理；非法模板与空包被拒绝 |

测试在 Node 中运行，不依赖已有的 `dist/`。包里没有 `@types/node`（`src/` 是浏览器代码）；测试用到的几个 Node 内置模块在 `test/node-shim.d.ts` 中声明。
