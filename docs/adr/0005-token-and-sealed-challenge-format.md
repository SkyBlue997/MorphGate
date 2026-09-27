# ADR-0005：凭证采用 PASETO v4，密封 Challenge 采用 protobuf（prost）编码 + XChaCha20-Poly1305

- 状态：已接受
- 日期：2026-09-27（同日按 v0.2.1 一致性裁决修订：编码与 AEAD 定稿、按阶段绑定、TTL 与 epoch、epoch 密钥派生、Early-Data）
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

## 参考

- https://github.com/altcha-org/altcha-lib/security/advisories/GHSA-6gvq-jcmp-8959
- https://github.com/brycx/pasetors
- https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/
