# ADR-0005：凭证采用 PASETO v4，密封 Challenge 采用 protobuf（prost）编码 + XChaCha20-Poly1305

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：编码与 AEAD 定稿、按阶段绑定、TTL 与 epoch、epoch 密钥派生、Early-Data）；2026-09-28 勘误：Phase 1 实现口径（依据 [Phase 1 实现规格](../impl/phase1-spec.md) D-04、D-05、D-23、D-29、D-30、I-14、I-18、I-30，见文末"勘误"）
- 相关：[04 Challenge 与访问凭证](../04-challenge-and-tokens.md)、[09 自研交互式 Challenge](../09-interactive-challenge.md)、[ADR-0008](0008-interactive-challenge-self-built.md)、[ADR-0010](0010-single-owner-model.md)

## 背景

- 需要两类密码学对象：访问凭证（Cookie `__Host-mg_clr`，对客户端不透明）与密封 Challenge `C`（下发时不写状态，验证时由 Edge 打开）。
- ALTCHA 的 CVE-2025-68113（2025-12，CVSS 6.5）：HMAC 作用于参数与 nonce 的歧义拼接，导致过期时间与 nonce 可被拼接替换、解答在过期后仍可复用。修复方式是显式分隔参数，公告同时建议服务端重放存储。
- pasetors 0.8.1（MIT，2026-08-30）实现 PASETO v4.local / v4.public，`forbid(unsafe_code)`，MSRV 1.88，未经第三方安全审计；rusty_paseto 0.10 可作备选。ed25519-dalek 3.0.0（2026-07）是新主版本，可能与仍依赖 2.x 的 crate 冲突；aws-lc-rs 活跃维护。
- Cloudflare Free / Pro 之后拿不到访客 JA4，`bind.tfp = hash(ja4)` 会绑定到 Cloudflare 的 TLS 栈；会话密钥要到 Phase 2 的 Web SDK 才有。

## 决策

**访问凭证**（字段、刷新与吊销见 [04 §5](../04-challenge-and-tokens.md)）

- PASETO v4.local（pasetors 0.8），按站点持有密钥、按 `kid` 轮换；源站需要独立验证时，另签只含最少字段的 v4.public（Ed25519）。全工作区只用一个 Ed25519 实现（ed25519-dalek 3.x 或 aws-lc-rs，Phase 0 选定）。
- `lvl`：`invisible | pow | interactive | interactive_a11y | interactive_ext:{provider}`；`attested` 保留给后期移动端；凭证中不含 `tid`。TTL 初值：`interactive` / `interactive_ext:*` 30 分钟，`interactive_a11y` 15 分钟（配额更严）。
- 绑定按阶段（C 与凭证同口径）：Phase 1 为 `uah`（UA 家族 + 主版本，硬）+ `ipp`（IP 前缀，软）；Phase 2 起加 `cnf.jkt`（SDK 会话密钥，硬）；`ctp = hash(tls_version ‖ cipher ‖ ciphers_sha1 ‖ hello_len 分桶)` 仅 `cloudflare`、仅 shadow，稳定性 ≥ 99% 后才可转为软绑定；`tfp`（JA4 哈希）仅 `direct_tls`，JA4 预研成功后启用。

**密封 Challenge**（字段表见 [09 §4](../09-interactive-challenge.md#4-密封-challenge)，续期规则见 [04 §3.1](../04-challenge-and-tokens.md#31-状态机)）

```
C  = base64url(prost(SealedChallenge { v, kid, xnonce, ct }))
ct = XChaCha20-Poly1305.seal(k_epoch[kid], xnonce, prost(SealedChallengeClaims), aad = host ‖ type ‖ kid)
```

- claims 与 `aad` 都按长度分隔编码（prost 生成的 protobuf 消息 `SealedChallengeClaims`），无歧义；封装与打开都在同一份 Rust 代码中，不需要跨实现的规范化，**绝不用字符串拼接**。claims：`v, kid, nonce(128 bit), site, route_class, type, providers, risk_band, attempt_no, iat, exp, ui_seed, pow{alg, difficulty}, ret, bind{uah, ipp, jkt?, ctp?, tfp?}`。`providers` 密封本次提供的 Provider 集合（防降级）；`ret` 是同站返回路径的哈希（防开放重定向）。下发不写状态；验证时在任何外部 Provider 调用之前用 `SET NX` 消费 nonce。
- 有效期：交互式约 10 分钟，SDK 到期前经 `POST /__mg/c/renew` 静默续期，续期链上限 6 次（约 1 小时）；invisible / pow ≤ 120 s。`k_epoch` 按站点、**24 小时**轮换，同时接受当前与上一个 epoch。
- 密钥派生：每站点一把长期根密钥 `K_seal_root`（systemd credential 交付，年更或泄露时轮换）；每日 `k_epoch = HKDF-SHA256(K_seal_root, info = "mg-seal-v1" ‖ site ‖ epoch_no)`，Turnstile `cData` 绑定密钥 `k_bind_epoch` 同法以 info `"mg-bind-v1"` 派生（域分离）；所有 Edge 各自确定性派生同一 epoch 密钥，无需每日分发；epoch 密钥泄露不暴露根密钥。凭证密钥、`K_seal_root`、`__Host-mg_cfp`（HMAC skip Cookie）密钥彼此独立；保管方式见 [ADR-0010](0010-single-owner-model.md) 决策 5。
- Early-Data：首选关闭 0-RTT；若开启，`/__mg/*` 的状态变更端点对 `Early-Data: 1` 返回 425（Cloudflare 是否透传 425 需实测）。

## 备选方案

| 方案 | 不采用的原因 |
|---|---|
| JWT / JWE | 算法与参数组合多，需要自行约束；PASETO 的版本即确定了算法 |
| HMAC 签名的明文 Challenge（字符串拼接） | 正是 ALTCHA CVE 的失误类型，且向客户端暴露 claims |
| 下发时写入状态的有状态 Challenge | 大量索取 Challenge 即可消耗后端状态 |
| 确定性 CBOR 编码 | 多一个编解码依赖与确定性规则；C 只由 Rust 端封装和打开，`proto/` 已用 protobuf |
| AES-256-GCM | 96 bit nonce，随机生成时需限制每个密钥的加密次数；XChaCha20-Poly1305 的 192 bit nonce 可直接随机生成 |
| `tfp` 在 `cloudflare` profile 下做硬绑定 | Cloudflare 之后绑定的是 Cloudflare 的连接 |

## 后果

- pasetors 未经审计：用官方测试向量、往返测试与模糊测试补足，并固定版本。
- `C` 只由 Edge（Rust）编码和打开，SDK 只对 `hash(C)` 签名，不存在跨语言编码一致性问题；对打开与解码路径做模糊测试，未知 `v` 一律拒绝。
- dalek 2 / 3 的版本分裂可能带来依赖调整。
- Phase 1 没有会话密钥，凭证只靠 `uah` + `ipp` 与短 TTL；`cloudflare` profile 下 Phase 2 起主要依赖 `cnf.jkt` 与 `uah`，`ctp` 只有在实测稳定后才考虑提升。

## 勘误（2026-09-28，Phase 1 实现）

结论（PASETO v4.local 凭证；prost 编码 + XChaCha20-Poly1305 的密封 C）不变。Phase 1 按下表实现，字节级格式见规格 [§6](../impl/phase1-spec.md#6-挑战与凭证密码学mg-challengewp-r2) 与 `testdata/phase1/kat.json`（D-xx 见规格 [§0.3](../impl/phase1-spec.md#03-决定与偏离)，I-xx 见[集成者裁决](../impl/phase1-spec.md#集成者裁决2026-09-28优先于正文)）：

| 项 | Phase 1 |
|---|---|
| Ed25519 实现（D-04） | "全工作区只用一个 Ed25519 实现"按自有代码执行：自有代码只用 ed25519-compact（pasetors 的 `v4` 特性本就依赖它）验证配置包签名，Go 侧用标准库 `crypto/ed25519`；Pingora 的 BoringSSL 与 reqwest 的 rustls（aws-lc-rs）只做 TLS。原文"ed25519-dalek 3.x 或 aws-lc-rs"与 dalek 2 / 3 的版本分裂不再适用 |
| 凭证 claims（D-29、I-30） | 新增 `sst`（会话开始，Unix 秒）；`sub`、`jti` 为 16 个随机字节的 base64url；`bind.uah`、`bind.ipp` 必有，`bind.ipa`、`bind.ctp` 可缺省；`ruc` 只出现在重放存储不可用时签发的凭证上，取值 true（`"ruc": false` 被拒），`fail_closed` 路由不接受这种凭证；`iat` / `exp` 保持 Unix 秒，只用 pasetors 的 `LocalToken::{encrypt, decrypt}` 加自有 claims 校验；footer `{"kid"}`，implicit assertion `"mg-clr-v1" ‖ 0x00 ‖ site`；`rb` 在解析时校验（未知值 → `invalid`）；Phase 1 的 `lvl` 只有 `invisible` / `pow`，TTL 缺省 1800 s |
| 会话沿用（D-29） | `sub` / `sst` 只从通过站点 / 环境校验、没有硬绑定失败且 `now − sst ≤ session_max_s` 的凭证沿用（可以已过期），重签不延长会话上限；未知或已退役 kid 的凭证按 `expired`（ABSENT，不加风险） |
| 绑定（D-05、D-23） | 新增 `ipa = hash(ASN)`（ASN 已知且不为 0 时）：`ipp` 前缀变化时，只有签发时绑定了 ASN 且当前 ASN 相同才是软结果，否则硬失败；客户端 IP 未知时不签发 C 与凭证，所以二者恒带 `ipp` |
| 密钥 id（I-14） | `token.keys.json` 的 `kid` 为 `<site>-t-<YYYYMMDD>`，`seal.root.json` 的 `root_id` 为 `<site>-r-<YYYYMMDD>`，同日重复加 `-N`；密钥文件 ≤ 64 KiB；配置包 `token_key_ids` 的每一项都必须在 Edge 的 `token.keys.json` 中，否则拒绝该配置包 |
| 根密钥（D-30） | `seal.root.json` 含 1–2 个根：`roots[0]` 封装，全部用于打开（按顺序试 AEAD）；轮换分 add / promote / retire 三步，任一时刻所有 Edge 都能打开彼此签发的 C |
| epoch 与编码 | kid 为 `e<epoch_no>`；info 为 `"mg-seal-v1" ‖ 0x00 ‖ site ‖ 0x00 ‖ u64be(epoch_no)`；接受窗口收紧为当前 epoch，日界后 125 s 内另接受上一个、日界前 5 s 内另接受下一个（原文"接受当前与上一个 epoch"会让上一个 epoch 全天有效）；`aad` 各段带 u16be 长度前缀；`len(C) ≤ 1024`；`open` 只接受 `seal` 写出的规范信封编码，`seal` 拒绝 `open` 会拒绝的一切，且对所有类型要求 `exp − iat ≤ 120 s`（I-18） |
| Early-Data | 任何 `Early-Data` 头都视为早期数据（RFC 8470 §5.1），见 [04 §4.3](../04-challenge-and-tokens.md#43-early-data0-rtt) |
| `tfp` | 仍不签发。JA4 预研（[ADR-0002 勘误](0002-edge-pingora-boringssl.md#bindtfp-的建议)）表明原始 JA4 随 TLS 1.3 会话恢复与 ClientHello 长度变化，决策中"`tfp`（JA4 哈希）硬绑定"改为：只取恢复时不变的部分，先 shadow，Phase 2 前不启用 |

## 参考

- https://github.com/altcha-org/altcha-lib/security/advisories/GHSA-6gvq-jcmp-8959
- https://github.com/brycx/pasetors
- https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/
