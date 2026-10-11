# ADR-0008：交互式 Challenge 自研（按住验证）+ 可插拔 Provider，Turnstile 仅用于非大陆访客

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：Provider 实现位置、a11y 封顶与 TTL）；2026-09-28 勘误：Phase 1 的 PoW 实现与阶段性行为（依据 [Phase 1 实现规格](../impl/phase1-spec.md) D-08、D-12、D-27、D-37，见文末"勘误"）；2026-10-12 勘误：Phase 2 实现口径（依据 [Phase 2 实现规格](../impl/phase2-spec.md) D-43、D-49、D-50、D-51、D-56、D-65、D-68、D-70，见文末"勘误"）
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

## 勘误（2026-09-28，Phase 1 实现）

结论不变，交互式 Challenge 与 Provider 仍在 Phase 2。Phase 1 中与本 ADR 相关的做法（D-xx 见规格 [§0.3](../impl/phase1-spec.md#03-决定与偏离)）：

| 项 | Phase 1 |
|---|---|
| 阶段性行为（D-08） | 规则或矩阵要求 `interactive` 时按 `pow`（该请求风险段的难度）执行，事件中可区分；策略编译器对 `params.type: interactive` 给警告 |
| PoW 实现（决策 1，D-12） | 浏览器端在 Web Worker 中用纯 JS SHA-256 同步搜索（前缀预先填好，每次尝试只做一次压缩），WebCrypto 只做启动自检：`crypto.subtle.digest` 逐次异步调用，hashcash 搜索慢一个数量级以上。算法 `sha256-hashcash-v1`（规格 [§6.3](../impl/phase1-spec.md#63-pow)），交互式沿用 |
| 失败升级（D-27） | 失败后附的新 C 为风险段更高的 `pow`（`attempt_no` 保持 0，它只用于交互式）；次数由失败配额约束 |
| 签发配额（D-37） | 按 ipp / ASN 的凭证签发配额已强制执行（超额 429），交互式沿用 |

## 勘误（2026-10-12，Phase 2 实现）

结论（交互式 Challenge 自研、可插拔 Provider、外部 Provider 绝不 fail-open）不变。Phase 2 中与本 ADR 不同的做法（D-xx 见规格 [§0.3](../impl/phase2-spec.md#03-决定与偏离)，I-xx 见[集成者裁决](../impl/phase2-spec.md#集成者裁决优先于正文)）：

| 项 | Phase 2 |
|---|---|
| Turnstile 的地区（决策 5，D-70） | 所有者决定（2026-10-12）大陆与国家未知的访客也可以选用 Turnstile，标题与决策 5 中"仅用于非大陆访客"不再成立；不另提供 Turnstile 以外的外部方案。没有硬编码的 `denied_regions`，`deny_countries` 缺省为空，所有者可以写 `CN` 恢复排除。大陆访客的 api.js 加载失败、控件报错或 siteverify 不可用时自动回退到内置验证，不计失败。被选中的大陆访客的 IP 经 siteverify 发给 Cloudflare，隐私说明须写明 |
| 大陆 Provider（决策 6） | `tencent` / `aliyun_v2` 不再规划（D-70） |
| 无障碍路径（决策 2，D-65、D-56） | 键盘路径与"无法按住？"合并为单次激活：按一次或点一次，控件自动走完时长与 PoW 后提交，不要求按住，也不要求第二次按下；指针按住只在抬起时提交。站点账号替代（passkey / 邮件链接）推迟 |
| PoW（决策 1，D-43） | 交互式用 `sha256-hashcash-v2`，k 个子题；`self_hold` 与 `pow_a11y` 的难度分别密封在 C 中；绑定续期完成后立即开始，不等按下 |
| Provider 配置（决策 3、5，D-51） | 配置包只放公开配置，回退只能是 `self_hold`（`fail_closed` 只降低可用性）；secret 在 `edge.toml` 引用的 `mg-turnstile-keys` 文件中。Turnstile 不实现 `InteractiveChallengeProvider`，siteverify 在 `mg-edge-core` 的 `outbound` 模块 |
| 评分与证据（D-49、D-68） | 只交付 shadow；`self_hold` 的检查除服务端时间窗外都依赖客户端自报的数据，所以交互级凭证的人类证据保持 −0.4，不是 03 §4.1 的 −0.8 |
| 失败升级（D-50） | 失败附交互式新 C，`attempt_no > N` 时 `pow_a11y` 置首；次数上限由失败配额执行 |
| CI（后果） | 不用 Cloudflare 的测试 sitekey / secret，全部用回环 mock siteverify（D-52） |

## 参考

- https://www.usenix.org/system/files/usenixsecurity23-searles.pdf
- https://arxiv.org/abs/2409.08831
- https://arxiv.org/abs/2607.18659
- https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html
- https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html
- https://developers.cloudflare.com/china-network/faq/
- https://developers.cloudflare.com/turnstile/plans/
