# ADR-0007：精简部署：不用 Kafka / Kubernetes，Valkey Streams + VictoriaLogs，Edge 拉取配置

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：VictoriaLogs 双实例与保留期、密钥保管、分阶段配置下发）
- 相关：[01 整体架构](../01-architecture.md)、[02 数据流](../02-data-flow.md)、[07 分阶段路线](../07-roadmap.md)、[ADR-0004](0004-origin-protection-tunnel-aop.md)

## 背景

- 平台只保护所有者的几个网站，流量小，运维由一人承担，预算按每月几十美元计。
- Kafka KRaft 生产部署需要 3 或 5 个 controller，启动脚本默认 1 GB 堆；Redpanda 生产要求 ≥ 3 个 broker、每核 ≥ 2 GB 内存。EKS 约 $73/月；k3s server 节点至少 2 核 2 GB。
- Valkey 本来就用于限速、nonce、verdict；其 Streams 支持消费组，但消息持久性依赖 AOF 强 fsync，故障切换可能丢失已写入的消息。
- ClickHouse 官方建议 ≥ 32 GB 内存，< 16 GB 需专门调优；ClickHouse Cloud 没有香港 / 中国区域。VictoriaLogs 是单二进制，支持高基数字段与 JSON 行写入。

## 决策

```
visitor -> Cloudflare (Free/Pro) -> cloudflared --loopback--> mg-edge (127.0.0.1) -> origin
                                    [one cloudflared per Edge host; Edge may share the origin host]
                                                         |
                                                         | same region / VPC, RTT < 1 ms
                                                         v
   brain VM (4-8 GB): Valkey (AOF everysec), mg-control + PostgreSQL or SQLite,
                      VictoriaMetrics, VictoriaLogs (vl-main, vl-short), Grafana (optional)
```

- **运行方式**：Edge 用 systemd（支持平滑升级）；有状态组件用 docker compose 或 systemd。
- **事件管道**：Edge 内存有界环形缓冲（可选小磁盘溢写）→ 批量写入 VictoriaLogs（每事件一行 JSON）。VictoriaLogs 按保留期拆成两个实例：`vl-main`（DecisionEvent 等，30 天）与 `vl-short`（Challenge / SDK 遥测，7 天）；保留期全表见 [02 §9](../02-data-flow.md)。近线用 Valkey：计数、有序集合，加一个 `XADD MAXLEN ~` 的 Stream（`mg:ev`），由 Go worker 消费并回写 verdict。以 `EventSink` trait 抽象，以后可换 NATS JetStream（单节点 R1）。
- **分析存储**：Phase 4 前只用 VictoriaLogs；开始做 ML / 复杂 SQL 或大脑 VM ≥ 8 GB 时，再加单节点 ClickHouse LTS（低内存配置，`async_insert=1` + `wait_for_async_insert=1`）。不用 ClickHouse Cloud。
- **可观测**：VictoriaMetrics 单节点直接抓取（Edge 启用 pingora-prometheus，`-retentionPeriod=13` 即 13 个月）；VictoriaLogs 替代 Loki；Grafana 可选；vmalert 只配少量告警（清单与阈值见 [06](../06-policy-console-observability.md)）。
- **配置下发**：Edge 以 ETag 条件请求拉取签名配置包（Phase 1–2 从大脑 VM 上的静态位置，Phase 3 起长轮询 mg-control；mTLS 或 WireGuard 内网）；吊销经 Valkey pub/sub 即时通知；控制面不可用时用 last-known-good。
- **区域与备份**：未备案选香港 / 东京 / 新加坡；Edge 与 Valkey 同区域 / 同 VPC，否则 Edge 退化为本地模式。每晚把 Valkey RDB、pg_dump 或 SQLite 文件、VictoriaMetrics / VictoriaLogs 快照写入对象存储；最小访问记录每日归档到对象存储（≥ 6 个月）。
- **密钥**：本机加密的密钥文件（systemd credentials 交付），云 KMS 可选；不部署 OpenBao，少一个需要运维与备份的有状态组件（[ADR-0010](0010-single-owner-model.md)）。
- **成本估算**：单机全合一约 $25–50/月；2 Edge + 1 大脑约 $50–80/月；对照 EC2 + RDS + ElastiCache 约 $120–180/月。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| Kafka（KRaft）/ Redpanda | 至少 3 个节点与 GB 级内存，对当前流量没有收益 |
| Kubernetes（EKS / k3s） | 约 $73/月或 ≥ 2 GB 内存开销，1–3 台 VM 没有收益 |
| 第一天就上 ClickHouse | 内存需求高，Phase 4 前没有 SQL / ML 需求 |
| 控制面 gRPC 流推送配置 | 控制面需维护到每个 Edge 的长连接；拉取更简单，且与 last-known-good 自然配合 |
| 托管 Valkey / PostgreSQL | 只在想省运维时使用；数据面从不同步访问数据库，控制面需容忍 15–30 s 冷连接 |

## 后果

- 大脑 VM 故障只降级：Edge 用 last-known-good 配置与本地计数，近线 verdict 暂停更新。
- Valkey 故障切换可能丢失 Stream 中的事件；DecisionEvent 属尽力而为的遥测，可以接受。
- 不支持多区域；需要时通过 `EventSink` 与新的 ADR 扩展。
- VictoriaLogs 不适合复杂 SQL 与训练集导出，这正是引入 ClickHouse 的触发条件。

## 参考

- https://kafka.apache.org/43/operations/kraft/
- https://docs.redpanda.com/current/deploy/redpanda/manual/production/requirements/
- https://aws.amazon.com/eks/pricing/
- https://docs.k3s.io/installation/requirements
- https://valkey.io/topics/streams-intro/
- https://clickhouse.com/docs/operations/tips
- https://docs.victoriametrics.com/victorialogs/
