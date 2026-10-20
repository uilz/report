# report 平台接入契约（contract v0.1）

面向个人助手平台的 CLI 调用面。**平台负责 MCP 薄包装**，report 只提供本文件描述的命令。

- `tool_version`：`0.2.0`
- `contract_version`：`0.1`
- 范围：仅 `report` 工具（worklog 不在此契约内）

---

## 1. 命令

```bash
report --version
report health --json

report publish --file <path> [--title <t>] [--no-sync | --sync] [--max-bytes N] [--json]
report status --id <publish_id> --json
report list --json

# 兼容现有命令（平台无需调用）
report add <file>
report sync [--dry-run] [--no-push]
report pull
report convert [--dry-run]
report init / unlock-mk / rekey
```

约定：

- `publish / status --id / list / health / --version` **stdout 只输出单行 JSON**；日志/诊断走 stderr。
- `--json` 为兼容参数：上述命令即使省略也输出 JSON。
- 退出码：`0` 成功；`2` 入参/输入错误（`FILE_NOT_FOUND`、`INVALID_INPUT`、argparse 用法错误）；`1` 运行期失败（`VAULT_UNAVAILABLE`、`SYNC_FAILED`、`UNKNOWN`）。

---

## 2. 输出 schema

### 成功

```json
{"ok":true,"tool_version":"0.2.0","contract_version":"0.1","result":{"publish_id":"pub_<32hex>","file":"summary.md","version":1,"status":"published","sha256":"<64hex>","published_at":"2026-10-20T12:34:56Z"}}
```

- `publish_id` = `pub_` + manifest 中持久化的报告 `id`（跨重启稳定）。
- `version` = 报告 `rev`；内容变化时 +1。
- `status` ∈ `published | pending | failed`（墓碑条目为 `deleted`）。

### 失败

```json
{"ok":false,"tool_version":"0.2.0","contract_version":"0.1","code":"SYNC_FAILED","message":"...","retryable":true}
```

### `list --json`

```json
{"ok":true,"tool_version":"0.2.0","contract_version":"0.1","result":{"items":[{"publish_id":"pub_...","file":"summary.md","version":1,"status":"pending","sha256":"...","published_at":"..."}]}}
```

`list` **默认包含 pending 条目**（用 `status` 区分）；墓碑（已删除）不返回。

---

## 3. `--no-sync` 语义（平台默认路径）

- `publish` **默认不推送**（等价 `--no-sync`）：写入母版 → 加密 → 本地 commit → `status=pending`。
- `--sync` 才推送到远端（opt-in；平台 MVP 不调用）。
- 之后可由用户/平台显式执行 `report sync`，再用 `status --id` 查询。
- 重复 publish 同内容为 no-op（不产生新提交、id/version 不变）。

---

## 4. 错误码

| code | 触发 | retryable | 退出码 |
|---|---|---|---|
| `FILE_NOT_FOUND` | 入参文件不存在 / `--id` 不存在 | `false` | 2 |
| `INVALID_INPUT` | 参数非法、文件超 `--max-bytes`、文件类型不可发布 | `false` | 2 |
| `VAULT_UNAVAILABLE` | vault/母版不可写、MK 缺失或无法解密、非 git 仓 | `true` | 1 |
| `SYNC_FAILED` | fetch/push/merge 失败（网络、冲突、远端拒绝） | `true` | 1 |
| `UNKNOWN` | 未分类 | `false` | 1 |

- `--max-bytes` 默认 **10 MB（10485760）**；超过 → `INVALID_INPUT`（非重试）。传 `0` 关闭限制。
- 任何输出都不包含主密钥、密码、SSH 私钥、token。

---

## 5. `mk.key` provision（不含密钥内容）

首次（新 vault）：

```bash
report init --yes        # 生成 mk.key(600) + key.enc；交互设置密码
```

已有 vault（平台部署机）：

1. 由 vault 所有者把既有机器密钥放到 `~/.config/uilz-report/mk.key`；
2. 权限必须为 `600`：

```bash
install -m 600 /path/to/mk.key ~/.config/uilz-report/mk.key
```

3. 确认：`report health --json` 返回 `mk_present:true`。

> 平台**不得**读取、打印或提交 `mk.key` 内容；本仓库永不包含它。

---

## 6. health

```json
{"ok":true,"tool_version":"0.2.0","contract_version":"0.1","result":{"vault_writable":true,"master_writable":true,"mk_present":true,"git_repo":true,"remote_configured":true,"remote_reachable":true,"pending":0,"last_sync_at":"2026-10-20T12:00:00Z"}}
```

- `ok = vault_writable && master_writable && mk_present && git_repo`。
- `remote_reachable=false` 不阻塞本地 publish（但 `--sync` 会 `SYNC_FAILED`）。
- vault 不可用 → `ok:false` + `VAULT_UNAVAILABLE`（附 `result` 明细）。

---

## 7. 幂等与稳定性

| 情形 | 行为 |
|---|---|
| 同路径、同内容 | 同 `publish_id`、同 `version`，不新增提交 |
| 同路径、内容变化 | 同 `publish_id`、`version+1` |
| 新路径 | 新 `publish_id`、`version=1` |

- `publish` 对同名路径**覆盖**（不使用 `add` 的自动改名）。
- `publish_id` 来自持久化 manifest，**跨进程/跨重启稳定**。

---

## 8. 示例

```bash
report --version
report health --json

printf '# demo\n\nhello\n' > /tmp/demo.md
report publish --file /tmp/demo.md --no-sync --json
# => {"ok":true,...,"result":{"publish_id":"pub_...","status":"pending",...}}

report status --id pub_<id> --json
report list --json
```

---

## 9. 限制

1. 平台只拿回执/状态，**不能解密** vault；原件留在平台受控目录。
2. `--sync` 需要网络（推密文到 git 远端）；失败可重试（本地提交保留）。
3. 单文件默认上限 10 MB；超大文件 push 会更慢。
4. CLI 内部 `flock`：同一 vault 并发 publish 串行化；平台单写者即可。
