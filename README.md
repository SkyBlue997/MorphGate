# MorphGate

所有者自用的 Bot 防护平台（Bot Management），只保护所有者自己的几个网站：在已有 CDN（Cloudflare 优先）之后以反向代理方式接入网页流量，提供自动化流量识别、分级处置、自研交互式 Challenge、AI Agent 访问治理，以及配套的策略、日志、指标与审计能力。约束是精简、低成本、单人可开发与维护。

## 适用范围

| 项目 | 取值 |
|---|---|
| 使用者 | 仅所有者本人（可选一个只读账号）；无多租户、无 SaaS、无多人审批（[ADR-0010](docs/adr/0010-single-owner-model.md)） |
| 受保护对象 | 所有者自有的几个网站，以浏览器网页流量为主；移动端按需、后期 |
| 上游 | Cloudflare 优先，经 Cloudflare Tunnel 回源；无 CDN 时由 Edge 直接终止 TLS（[08](docs/08-upstream-and-cloudflare.md)） |
| 部署 | 公有云 1–3 台 VM，未备案时选香港 / 东京 / 新加坡；不用 Kafka / Kubernetes（[ADR-0007](docs/adr/0007-lean-deployment.md)） |
| 技术栈 | Rust 数据面（Pingora Edge + Decision Core）+ Go 控制面（[ADR-0001](docs/adr/0001-tech-stack-rust-go.md)） |

## 使用边界

- 仅部署在所有者自有的站点上；不作为托管服务或 SaaS 提供给他人（这也是 JA4+ 许可的前提，见 [ADR-0009](docs/adr/0009-ja4-only-licensing.md)）。
- 所有安全测试与验证仅在本地环境、自有测试环境和自有站点中进行；测试工具（Validation Lab）内置目标白名单，拒绝向白名单外的主机发送流量。
- 不研究、不复现、不提供绕过任何第三方 Bot 防护或验证码产品（含 Cloudflare、Turnstile）的方法；对成熟产品仅参考其公开文档与功能方向，引用求解研究时只引用结果数字。
- 客户端信号采集遵循最小必要原则。平台自用，但受保护网站的访客数据仍受 PIPL 等法规约束，上线前完成隐私与合规检查（见 [06](docs/06-policy-console-observability.md#7-隐私与合规)）。

## 设计文档

| 文档 | 内容 |
|---|---|
| [01 整体架构](docs/01-architecture.md) | 设计原则、威胁模型、分层架构、组件划分、接入方式、信号可用性、部署与技术选型 |
| [02 数据流](docs/02-data-flow.md) | 内联快路径 / 近线 / 离线链路、配置下发、SDK 遥测、事件管道、核心数据模型 |
| [03 信号与风险评分](docs/03-risk-scoring.md) | 信号体系、评分模型、分级处置、会话与行为分析、评估指标 |
| [04 Challenge 与访问凭证](docs/04-challenge-and-tokens.md) | Challenge 类型与流程、短期凭证与绑定、持有证明、防重放、限速 |
| [05 AI Agent 策略](docs/05-ai-agent-policy.md) | Agent 分类、身份验证（Web Bot Auth）、授权注册、测试授权工单、爬虫策略 |
| [06 策略引擎、后台与审计](docs/06-policy-console-observability.md) | 策略模型与 CEL、发布流程、管理后台、日志 / 指标 / 审计、隐私合规、平台自身安全 |
| [07 分阶段路线](docs/07-roadmap.md) | 按单人工期估算的里程碑、交付物与验收标准 |
| [08 上游接入与 Cloudflare 集成](docs/08-upstream-and-cloudflare.md) | UpstreamProfile、源站保护、可信客户端 IP、`x-mg-cf-*` 信号转发、缓存与 Cloudflare Bot 功能共存、其他 CDN 信号表 |
| [09 自研交互式 Challenge](docs/09-interactive-challenge.md) | 按住验证、无障碍路径、密封 Challenge、Provider 接口与 Turnstile 适配、遥测与服务端评分 |
| [10 威胁模型](docs/10-threat-model.md) | STRIDE v0：资产、信任边界、分组件威胁、平台自身滥用与误伤、残余风险 |
| [架构决策记录（ADR）](docs/adr/README.md) | 技术栈、Edge 与 TLS、上游模型、源站保护、凭证与密封 Challenge 格式、策略语言、精简部署、交互式 Challenge、JA4 许可、单一所有者与密钥保管 |
