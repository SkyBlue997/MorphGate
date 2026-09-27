# ADR-0009：只使用 JA4，JA4+ 放在默认关闭的 Cargo feature `ja4plus` 之后

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：统一特性开关名）
- 相关：[01 整体架构](../01-architecture.md)、[03 信号与风险评分](../03-risk-scoring.md)、[ADR-0002](0002-edge-pingora-boringssl.md)、[ADR-0010](0010-single-owner-model.md)

## 背景

- JA4（TLS 客户端指纹）以 BSD-3-Clause 发布，LICENSE-JA4 明确只覆盖 JA4、不覆盖其余 JA4+；FoxIO 表示对 JA4 没有专利主张。维护者在 issue #315（2026-08-31）中再次确认这一划分。
- JA4+ 其余方法（JA4S、JA4H、JA4L、JA4LS、JA4X、JA4T、JA4TS、JA4TScan、JA4D、JA4D6、JA4SScan、JA4E、JA4SSH）使用 FoxIO License 1.1：
  - 只允许非商业用途；个人使用，以及不直接将软件变现的内部业务使用，属于非商业。
  - 排除：以 hosted / managed service 方式向他人提供；为使用或访问软件直接或间接收费。
  - License FAQ 示例：用 JA4+ 为付费客户提供价值（即使不直接暴露指纹）需要 OEM 许可；所有 JA4+ 方法标注为 patent pending；专利许可只覆盖许可方提供形式的软件，独立重新实现是否被覆盖不明确。
- 所有者的站点若有收入（广告、付费内容），是否仍属"非商业"存在不确定性。
- Cloudflare 之后 JA4H / JA4T / JA4L 本来就失真，收益有限；FoxIO 的 Rust crate 是专有许可的 pcap / tshark 命令行工具，不是可嵌入的库。

## 决策

1. 默认只计算和使用 JA4（TLS 客户端）。实现用 huginn-net-tls（MIT / Apache-2.0，声明不含 JA4+ 组件）或自研解析器；若嵌入 FoxIO 的 JA4 代码，保留 BSD-3 声明。
2. 任何 JA4+ 方法的代码放在 Cargo feature `ja4plus`（默认关闭）之后，默认构建不编译、不启用；默认字段模式中不出现 JA4+ 字段。01 §9、03 与本 ADR 统一使用这一名称。
3. 启用条件：受保护站点无任何收入时，可按个人非商业使用启用，并写一条新 ADR 记录；站点有收入时，启用前先咨询 FoxIO 并保留书面答复。
4. 不以自研方式复刻 JA4+ 方法作为替代（独立实现的专利覆盖不明确）；与 JA4+ 无关的自有特征（如 HTTP/1 头大小写、`x-mg-cf-hdr-names` 头名集合）按普通信号处理。
5. MorphGate 永不作为托管服务提供给他人（与 ADR-0010 一致）。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| 直接使用 JA4+（自用即非商业） | 有收入站点的适用性不确定，且方法处于 patent pending |
| 购买 OEM 许可 | 对自用平台成本不相称，Cloudflare 之后收益有限 |
| 自研 JA4+ 等价特征 | 专利许可对独立实现的覆盖不明确 |

## 后果

- TLS 层指纹只有 JA4，且只在 `direct_tls` 下可用（Cloudflare 只向 Enterprise + Bot Management 提供访客 JA4）；`cloudflare` profile 下由 `EDGE_TLS` 弱信号族部分替代。
- 默认构建不含 JA4+ 代码，许可审查面最小。
- 若将来启用 JA4+，必须随代码附带 FoxIO License 文本与声明，并在 FoxIO 更新许可时复核。
- 本 ADR 不构成法律意见。

## 参考

- https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE
- https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/LICENSE-JA4
- https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md
- https://github.com/FoxIO-LLC/ja4/issues/315
- https://docs.rs/huginn-net-tls/latest/huginn_net_tls/
