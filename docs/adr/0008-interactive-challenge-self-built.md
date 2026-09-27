# ADR-0008：交互式 Challenge 自研（按住验证）+ 可插拔 Provider，Turnstile 仅用于非大陆访客

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：Provider 实现位置、a11y 封顶与 TTL）
- 相关：[09 自研交互式 Challenge](../09-interactive-challenge.md)、[04 Challenge 与访问凭证](../04-challenge-and-tokens.md)、[ADR-0005](0005-token-and-sealed-challenge-format.md)

## 背景

- 研究结果（只引用结果数字）：USENIX Security 2023 用户研究汇总的文献中，自动求解准确率 85–100%（多数 > 96%），人类 50–85%；Geetest 滑块人类 28–30 s，文献中的机器约 5.3 s、96%。2024 年研究对 reCAPTCHA v2 图像题求解率 100%。2026 年预印本测得打码服务对 reCAPTCHA v2 与 Turnstile managed / invisible 成功率 100%、hCaptcha 58–100%，价格每千次 $0.10–5.00。
- 结论：题目难度不能作为安全边界。交互式 Challenge 的价值来自服务端密封的一次性 nonce 及其绑定、PoW 成本、服务端评分的量化交互遥测、风险自适应升级、签发与尝试配额；通过只是封顶的人类证据。
- WCAG 2.2：3.3.8 / 3.3.9 限制认证流程中的认知功能测试；2.5.7 要求拖拽有单指针替代；2.2.1 要求时限可调整。
- Cloudflare 文档声明 Turnstile 不支持中国大陆；api.js 必须从 Cloudflare 的固定 URL 加载，不可代理或缓存。Turnstile 免费计划：每账号 20 个 widget、每 widget 10 个主机名。

## 决策

1. **v1 自研"按住验证"**（`self_hold`，默认 Provider）：按住期间在 Web Worker 中运行 SHA-256 hashcash PoW（纯 JS 回退）；按住时长每次随机 1.2–2.5 s；目标 ≥ 44×44 CSS px；难度按风险分段（中风险中位 ≤ 0.3 s，高风险 ≤ 1.5 s）；由第一方 `/__mg/` 提供，大陆可用。
2. **无障碍路径（v1 必须）**：键盘按住 Space / Enter；"无法按住？"切换为两次按压；`pow_a11y` Provider（非交互 PoW，中位 3–8 s，签发 `lvl=interactive_a11y`：人类证据封顶与 `interactive` 相同，靠更短 TTL（15 分钟）与更严配额控制风险）；站点有登录时提供 passkey 或邮件链接。
3. **Provider 接口**：Rust trait `InteractiveChallengeProvider` 与纯计算的 `self_hold` / `pow_a11y` 实现位于 mg-core；需要出站校验的 `turnstile` / `tencent` / `aliyun_v2` 在 mg-edge 实现，经注入的 `OutboundHttp` 做网络 I/O，mg-core 保持无 I/O、可编译到 wasm32（[09 §6](../09-interactive-challenge.md#6-provider-接口)）。Provider 由 Decision Core 选定，客户端不能选；本次提供的 Provider 集合密封进 `C`，服务端拒绝未提供的 Provider。ID：`self_hold`、`pow_a11y`、`turnstile`、`tencent`、`aliyun_v2`，后续 `privacy_pass`。
4. **Provider 的通过不直接成为凭证**：只在 MorphGate 自己的签名提交、有效 `C`、已消费的 nonce 与绑定之内被接受，最终由 MorphGate 签发 PASETO（`lvl=interactive_ext:{provider}`）。
5. **Turnstile**：可选，只用于非大陆访客（`denied_regions: [CN]`）；服务端 siteverify 严格校验 hostname、action、cdata 与时间；**绝不 fail-open**；客户端在不支持、加载失败或超时时回退 `self_hold`。
6. **不做**：滑块、点选、旋转、扭曲文字、音频题。大陆用户需要熟悉的滑块时接入腾讯 / 阿里云 Provider（约 ¥0.005/次），不自研；不采纳厂商"服务故障时默认通过"的建议。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| 只用 Turnstile | 大陆不支持；api.js 不能第一方托管；打码服务成功率接近 100% |
| 自研滑块 / 图像题 | 人类更慢而机器更快；属认知测试或拖拽操作；需要持续的素材流水线 |
| hCaptcha | 大陆低延迟接入仅 Enterprise；相对 Turnstile 增益小 |
| 只做非交互 PoW | 最简单、最无障碍，但缺少交互遥测；保留为 `pow_a11y` |
| 腾讯 / 阿里云作为默认 | 付费；API 无 MorphGate nonce 字段，绑定较弱；保留为可选 |

## 后果

- 单人实现估计 2–4 周（控件、Worker、Rust 校验、Turnstile 适配与测试）。
- 签名绑定能阻止诚实客户端的凭证被盗与重放，不能阻止串通的人工代解中继；依靠短窗口、交互级凭证 30 分钟 TTL + 持有证明续期、按前缀 / ASN 的签发上限与解题时间分布监控。
- 评分阈值先 shadow，用所有者自己的流量确定。
- 启用 Turnstile 时需更新隐私声明（IP、TLS 指纹、UA 发往 Cloudflare）；CSP 只在选用 Turnstile 的页面放开；CI 使用测试 sitekey / secret。
- 引用的 2026 年结果多为预印本，数字只作参考。

## 参考

- https://www.usenix.org/system/files/usenixsecurity23-searles.pdf
- https://arxiv.org/abs/2409.08831
- https://arxiv.org/abs/2607.18659
- https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html
- https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html
- https://developers.cloudflare.com/china-network/faq/
- https://developers.cloudflare.com/turnstile/plans/
