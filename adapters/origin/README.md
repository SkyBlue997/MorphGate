# 源站侧：校验 `MG-Origin-Auth`

`edge.toml` 的 `[[sites]]` 设了 `origin_keys` 后，Edge 转发给源站的每个请求都带 `MG-Origin-Auth`，它是对请求方法、请求目标和 Edge 写入的 `MG-*` 头所做的 HMAC 签名，格式见[规格](../../docs/impl/phase1-spec.md)裁决 I-38。源站在校验通过之前，不应信任任何 `MG-*` 头（`MG-Client-IP`、`MG-Session`、`MG-Bot-Score` 等）。这样，同一台主机或同一个容器网络里能连到源站的其他进程，就没法冒充 Edge。

| 文件 | 作用 |
|---|---|
| `verify-origin-auth.mjs` | 参考实现，只依赖 `node:crypto`，可以直接复制到源站：`loadOriginKeys` 读密钥文件，`verifyOriginAuth` 校验一个请求 |
| `test/verify-origin-auth.test.mjs` | 用 `testdata/phase1/kat.json` 的 `origin_auth` 向量测试；Edge 的签名代码用的是同一组向量 |

## 设置

1. 在工作站上生成密钥文件：`mgctl keys gen-origin --out ~/mg/keys/blog-origin-keys.json.age`。
2. 用 `mgctl keys export --in <file>` 导出明文，**先**交给源站（源站接受文件里的每个值），再交给 Edge 主机的 systemd credential（`mg-blog-origin-keys`），然后在 `edge.toml` 里写 `origin_keys = "cred://mg-blog-origin-keys"`，并在 `mg-edge.service` 里加上对应的 `LoadCredentialEncrypted=` 行（`deploy/systemd/` 的样例里有注释掉的写法）。
3. 源站对每个请求调用 `verifyOriginAuth`，失败时按"来源未知"处理：不采用 `MG-Client-IP`，不信任 `MG-Session`。
4. 轮换：`mgctl keys gen-origin --rotate` 会把新值放在前面并保留旧值，按第 2 步的顺序先更新源站、再更新 Edge。

Edge 和源站之间如果还有一层反向代理，它必须原样转发请求目标和 `MG-*` 头。用 nginx 时，`proxy_pass` 不要带 URI 部分。时间戳允许和源站时钟相差 60 秒以内。
