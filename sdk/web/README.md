# @morphgate/web-sdk

MorphGate 第一方 Web SDK（私有包）。设计见 [04 §7](../../docs/04-challenge-and-tokens.md#7-客户端信号采集web--mobile-sdk)。

## 现状：Phase 0 骨架

| 模块 | Phase 0 | 后续 |
|---|---|---|
| `index.ts` | 从脚本标签 `data-mg-*` 读取配置，暴露只读的 `window.MorphGate`（`version`、`config`、`snapshot()`、`classifyResponse`）；不发网络请求 | Phase 2：Challenge 流程、静默刷新 |
| `env.ts` | 环境摘要类型与采集器：UA / 低熵 Client Hints、语言、时区、屏幕与视口（量化）、核心数、触控、存储可用性 | Phase 2：图形栈家族摘要（只取家族，不取渲染器字符串） |
| `automation.ts` | 只读标准 `navigator.webdriver` | Phase 2：其他自动化特征 |
| `behavior.ts` | 纯函数量化器：`logBucket`、`roundToStep`、`clamp`、`logHistogram` | Phase 2：指针 / 键盘 / 滚动 / 触控采集 |
| `crypto.ts` | WebCrypto ECDSA P-256 会话密钥（`extractable: false`）、RFC 7638 JWK 指纹（`cnf.jkt`） | Phase 2：IndexedDB 持久化、`MG-Proof`（ES256 JWS） |
| `transport.ts` | 识别 `cf-mitigated: challenge` → `upstream_challenge`；解析 MorphGate JSON（`mg_challenge` 等）；429 / 425 | Phase 2：fetch / XHR 包装、重试 |
| `telemetry.ts` | 载荷类型、UTF-8 字节数、2 KB 预算检查与按序裁剪 | Phase 2：会话密钥签名、`POST /__mg/t` |

隐私：不采集画布 / WebGL / 音频渲染哈希、渲染器字符串、字体 / 插件列表、高熵 Client Hints。任何采集异常只让对应字段为 `null`，不影响页面。

## 嵌入

```html
<script data-cfasync="false" src="/__mg/s/{build}.js" data-mg-path-prefix="/__mg/" nonce="..."></script>
```

| 属性 | 默认 | 说明 |
|---|---|---|
| `data-mg-path-prefix` | `/__mg/` | 只接受同源绝对路径；非法值（`//host/`、`..`、URL）回退默认值 |
| `data-mg-site` | 无 | 站点 ID，仅供调试 |
| `data-mg-debug` | `false` | `true` 时在控制台打印快照 |

`data-cfasync="false"` 让 Cloudflare Rocket Loader 不改写该脚本。

## 命令

```bash
pnpm install
pnpm run check      # typecheck && test && build && size
pnpm run build      # esbuild -> dist/mg.js（IIFE、压缩、ES2020）
pnpm run size       # gzip(dist/mg.js) 必须 ≤ 30720 字节
```

当前 Phase 0 构建约 2.5 KB gzip（`crypto.ts`、`telemetry.ts` 尚未被入口引用，不进包）。测试在 Node 的 WebCrypto 下运行，覆盖 RFC 7638 / RFC 8037 指纹向量。
