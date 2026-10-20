# uilz/report

公开的**加密静态保险箱**：仓库里只有密文与一个明文外壳 SPA；必须输入密码才能在本机浏览器解密浏览。

## 结构

| 路径 | 说明 |
|---|---|
| `index.html` / `app.js` / `app.css` / `vendor/` | 明文外壳（无任何秘密；无 CDN，全部本地） |
| `key.enc` | 被密码包裹的主密钥（Argon2id → AES-256-GCM） |
| `manifest.enc` | 加密的清单（文件名/标题只在此密文内） |
| `blobs/<id>-<rev>.enc` | 加密的报告内容（`id` 为不透明哈希） |
| `bin/report` | 本机加密 / 发布 / 同步 CLI（Python3） |
| `SPEC.md` | 格式与同步协议规范 v1.1 |

## 本机使用

```bash
python3 bin/report init                  # 首次：生成主密钥 + 设置密码（会打印 base64 主密钥，离线抄录）
python3 bin/report add FILE --title T     # 加入一份报告
python3 bin/report sync                   # 加密 → 提交 → 推送
python3 bin/report rekey                  # 更换密码（只重包主密钥，内容不动）
python3 bin/report unlock-mk --out ~/mk   # 导出主密钥（恢复凭据）
```

机器密钥：`~/.config/uilz-report/mk.key`（chmod 600，**绝不在本仓库内**）。

## 平台接入（contract 0.1）

供个人助手平台（MCP 包装）调用的稳定 CLI 界面，详见 **[PLATFORM.md](PLATFORM.md)**：

```bash
report --version
report health --json
report publish --file <path> --no-sync --json   # 默认不推送 -> pending
report status --id <publish_id> --json
report list --json
```

- `publish` 默认 `--no-sync`（只加密入库，`status=pending`）；`--sync` 才推送。
- stdout 只输出单行 JSON；退出码 `0/2/1`；错误码固定 + `retryable`。
- 单文件默认上限 10 MB（超限 `INVALID_INPUT`）。

## 安全边界

- 仓库是**公开**的：密文可被任何人下载并离线爆破，安全性 = **密码强度**。
- 旧版 `/md/*` 曾是**明文**公开内容，加密保险箱只对**将来**有效。
- 详细威胁模型与残余风险见 `SPEC.md` §1 / §10。