# uilz/report — 规范 (SPEC v1.1)

> 加密静态保险箱：明文外壳 SPA + 信封加密内容。仓库存密文，浏览器持密码解密浏览。
> 本文件是**契约**。Python CLI 与浏览器 SPA 两个实现必须字节级一致。
> **v1.1 变更**：吸收 Oracle 复审的 P0/P1/P2（见 §11）。

---

## 1. 目标与威胁模型

- 目标：在**公开**的 GitHub Pages 上托管 md/html 报告，只有持密码者可见内容。
- 威胁模型：
  - 敌手可完整下载仓库全部密文、无限次离线爆破。**安全性 = 密码熵 + KDF 成本**。
  - 敌手不应获得：文件名、标题、内容。
  - **不防**：持有已解锁浏览器的设备被入侵（MK 存于 localStorage）；持有 `mk.key` 的机器。
  - 已知残余（§10）：报告条数 / 密文大小（≈明文大小）/ git 时间戳 / 墓碑留存会泄露元信息；回滚旧 manifest 无法检测；`robots.txt`/`noindex` 仅是建议。

## 2. 加密原语与常量（冻结）

| 名称 | 定义 |
|---|---|
| 密码 | 人类输入；**先做 Unicode NFC 归一化**，再 UTF-8 编码 |
| MK | 主密钥，**32 随机字节**（256-bit），展示为 base64 |
| KEK | `Argon2id(pw, salt=16B random, t=3, m=65536(64MiB), p=1, hashLen=32, version=0x13)` |
| 包裹 | `AES-256-GCM(key=KEK, iv=12B random, pt=MK, aad=b"uilz-report/v1/key")` |
| 内容密钥 CK | `HKDF-SHA256(ikm=MK, salt=b"", info=INFO(id,rev), L=32)` |
| 清单密钥 | `HKDF-SHA256(ikm=MK, salt=b"", info=b"uilz-report/v1/manifest", L=32)` |
| 内容加密 | `AES-256-GCM(key=CK, iv=12B random, aad=INFO(id,rev))`，tag 16B |
| INFO(id,rev) | `b"uilz-report/v1/blob:" + id.encode("ascii") + b":" + str(rev).encode("ascii")` |

- `salt=b""` 双方都必须传**空 salt**（HMAC 会补零，空 ≡ 全零，安全）。
- 版本前缀字面量 `uilz-report/v1/...` **不得改动**。
- 解密方从 `key.enc.kdf` 读取 KDF 参数，不硬编码。
- **CK 随 `rev` 旋转**（info 含 rev）→ 消除「同一 id 永久同密钥」的 nonce 上限问题；同时 `rev` 被 AAD 绑定 → 防同一 id 旧版本回放。

### 2.1 强一致性要求
- Argon2id 必须**逐字节**与标准一致。cross-impl 已实测：`test-password` + salt `0102..0f` + t=3/m=65536/p=1/32B/v19 → KEK hex `3626d52a3888fe544a112a76b7060c0b2ac907a8bad774e1a37e4de169cdf74b`（Python argon2-cffi 与浏览器 argon2-browser 一致）。
- `argon2-browser` **必须显式** `type: argon2.ArgonType.Argon2id`、`version: 0x13`、salt 传 **Uint8Array 原始 16 字节**（勿传字符串）、`mem=65536`(KiB)、`time=3`、`parallelism=1`、`hashLen=32`；结果取 **原始字节**（`.hash`）而非 hex。
- 密码非 ASCII 时，NFC 归一化必须在两侧一致执行。

## 3. 文件格式（冻结）

### 3.1 `key.enc`（公开，UTF-8 JSON，缩进 2）
```json
{
  "v": 1,
  "kdf": { "algo": "argon2id", "version": 19, "t": 3, "m": 65536, "p": 1, "hashLen": 32, "salt": "<base64>" },
  "wrapped": { "iv": "<base64 12B>", "ct": "<base64, 含 16B tag>" }
}
```
PBKDF2 回退分支（仅当 §7 实测不一致才启用）：
`"kdf": { "algo": "pbkdf2-sha256", "iterations": 600000, "hash": "sha256", "hashLen": 32, "salt": "<base64>" }`
解密方按 `kdf.algo` 分派。

### 3.2 `manifest.enc`（公开，二进制）
```
bytes = IV(12) || AES-256-GCM(manifestKey, IV, JSON, aad=b"uilz-report/v1/manifest")
```
明文 JSON：
```json
{
  "v": 1,
  "updatedAt": "2026-09-28T12:00:00Z",
  "reports": [
    { "id":"<32 lowercase hex>", "path":"report.html", "title":"...", "kind":"html",
      "rev":1, "sha256":"<lowercase hex>", "size":123,
      "updatedAt":"2026-09-28T12:00:00Z", "deleted":false }
  ]
}
```
- `id`：**32 位小写 hex**（16 字节，`secrets.token_hex(16)`），不透明、不含路径信息。
- `size`：**UTF-8 字节长度**。
- 日期：**`YYYY-MM-DDTHH:MM:SSZ` UTC，无毫秒/无偏移**（否则 §4 字典序排序会崩）。
- 墓碑 `deleted:true` **保留**，且**必须 bump `rev` 与 `updatedAt`**。

### 3.3 `blobs/<id>-<rev>.enc`（公开，二进制）
```
bytes = MAGIC(4B, b"UZR1") || IV(12) || AES-256-GCM(CK, IV, plaintext, aad=INFO(id,rev))
```
- 文件名含 `rev` → 并发不同版本**不会在 git 层冲突**。
- 内容 = 单个自包含文件（html 或 md 原文），附件已由来源打包进该单文件。

### 3.4 仓库布局
```
index.html      # SPA 外壳（公开，无秘密；含严格 CSP）
app.js app.css  # SPA 代码（公开）
vendor/*        # argon2-browser, marked, katex, dompurify（公开，已 pin 版本）
key.enc         # 见 3.1
manifest.enc    # 见 3.2
blobs/<id>-<rev>.enc
robots.txt      # Disallow: /
.nojekyll
```

## 4. SPA 行为规范

1. **启动**：读 `localStorage["uilz.report.mk"]`（base64 MK）。有→直接用；无→密码门。
2. **密码门**：密码 → NFC → Argon2id(参数取自 `key.enc.kdf`) → 解包 MK。GCM 认证失败 → 「密码错误」；成功 → `localStorage` 存 MK。
3. **清单**：`fetch("manifest.enc")` → 解密 → 列表（title/updatedAt/kind），搜索 + 按 updatedAt 倒序。
4. **打开报告**：读 manifest 条目的 `id/rev/sha256` → 派生 `CK=HKDF(MK,INFO(id,rev))` → `fetch("blobs/<id>-<rev>.enc")` → 校验 MAGIC → 解密（AAD=INFO）→ **校验明文 sha256 === manifest.sha256**（不符 → 拒绝渲染并报错）。
   - `kind==="md"`：marked 渲染 → KaTeX auto-render → **DOMPurify 清洗最终 HTML** → 注入 iframe。
   - `kind==="html"`：原文注入 iframe（仍走沙箱）。
   - KaTeX 关闭 `trust`，不用 `\href`（除非明确需要）。
5. **沙箱（硬性）**：`<iframe sandbox="allow-scripts allow-popups" srcdoc="...">`，**永不**加 `allow-same-origin` / `allow-popups-to-escape-sandbox`；报告 HTML **只**经 `srcdoc` 属性注入，绝不写入父文档。SPA 若有 `message` 监听，必须校验 `event.origin === "null"`。
6. **CSP**：报告经 `iframe[srcdoc]` 渲染并**继承本页 CSP**，故需放行报告自带资源：`default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' data: https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'`。报告的脚本/样式只在沙箱（不透明源、无 allow-same-origin）内运行，无法触达父页 localStorage 与主密钥；外壳自身仍只加载 `'self'` 本地资源。
7. **路由**：hash 路由 `#/<id>`；启动解析 hash 直达。
8. **锁定**：清除 `localStorage["uilz.report.mk"]` 并回密码门。
9. **元信息**：`<meta name="robots" content="noindex,nofollow">`；移动端响应式。
10. **每次打开重建 iframe**：曾隐藏后才收到首个文档的复用 iframe 会丢弃后续 `srcdoc` 导航（报告渲染空白），故每次 `openReport` 新建 iframe 再赋 `srcdoc`。
11. **沉浸阅读**：报告视图提供放大/缩小切换（`html.immerse` 隐藏外壳、报告铺满视口，仅留右上角「缩小」；Esc 退出）；主题偏好独立于锁定，不被清除。

## 5. CLI 规范（Python3，stdlib + `cryptography` + `argon2-cffi`）

- 可执行：`report/bin/report`。
- 配置：`~/.config/uilz-report/config.json`
  ```json
  { "repo_dir": "/home/apple/develop/github/uilz/report",
    "master_dir": "/home/apple/develop/githubio-sharing-report",
    "remote": "origin", "branch": "main" }
  ```
- 机器密钥：`~/.config/uilz-report/mk.key`（**600**，base64 MK 单行）。cron 靠它免交互；**绝不入库**。它是「离线 MK 备份」的机器副本，也是密码丢失时的恢复凭据。
- **本地基线状态**：`<master_dir>/.report-state.json`（**不入库、非仓库**）：
  ```json
  { "lastSync":"ISO", "entries": { "<id>": { "rev":1, "sha256":"...", "path":"..." } } }
  ```
  记录**上次成功同步**时每文件的 `rev/sha256`，用于区分「本地改」与「远端改」。**没有它，§6 的冲突判定不可能实现。**

### 命令
| 命令 | 行为 |
|---|---|
| `init` | 生成 MK → 写 `mk.key`(600)；交互输密码（两次）→ 写 `key.enc`；初始化空 `manifest.enc`；写 `.nojekyll`/`robots.txt`；打印 MK base64 要求**抄录确认**（提示会留在终端滚动缓冲，注意清理） |
| `add <file> [--title T]` | 拷入 `master_dir`（重名加后缀），下次 `sync` 生效 |
| `sync [--dry-run] [--no-push]` | 见 §6 |
| `pull` | 仅拉取解密远端 → 落地 `master_dir` **并更新基线**（不重加密、不推） |
| `unlock-mk --out <path>` | 导出 base64 MK（交互确认） |
| `status` | 列出本地/远端/基线差异 |
| `rekey` | 用新密码重新包裹 MK（信封重加密，内容 blob 不变）；随后 `sync` 发布新 `key.enc` |

- MK 获取优先级：`--mk-file` → env `UZR_MK` → `~/.config/uilz-report/mk.key` → 交互 getpass（仅 `init` 需要密码）。

## 6. 同步协议 v1.1（核心，冻结）

**铁律**：`获取锁 → git fetch → 读远端 manifest → 逻辑合并（Python 内解密双方）→ 落地/落地删除 → 重加密本地变更 → 写 manifest → commit → push → 更新基线 → 释放锁`。

**绝不**用 `git pull --rebase`/`git merge` 处理 `manifest.enc`（二进制，双方都改必冲突，会卡死整个流程）。远端 manifest 用 `git show <remote>/<branch>:manifest.enc` 读出后在 Python 内解密合并。

### 6.1 sync 步骤
1. 取锁 `flock`（见 §8）；确认工作树干净（否则中止并提示）。
2. `git fetch <remote>`（**不动工作树**）。
3. 读远端 manifest（`git show` 或远端 ref）解密 → `R`；读本地 `manifest.enc` 解密 → `L`；读基线 `.report-state.json` → `B`。
4. 对 `id` 的并集做三方判定（base=B[id]，remote=R[id]，local 文件 = 现哈希）：
   - **仅远端变**（remoteRev≠baseRev 且 localSha==baseSha）→ 采纳远端；非删除则落地到 `master_dir`；删除则删本地副本（仅当本副本 sha 与 base 一致）。
   - **仅本地变**（localSha≠baseSha 且 remoteRev==baseRev）→ 保留本地，`rev+=1`。
   - **双方都变** → **冲突，保留双份**：远端版落地为 `path`；本地版另存 `path.conflict-<id8>-<rev>` 并作为**新 id** 条目；**绝不静默丢弃**。
   - **本地删除**（`B` 有、`master_dir` 缺、且远端未改）→ 墓碑 `deleted:true`，`rev=max+1`，`updatedAt=now`。
   - **仅远端新增**（B 与 L 都无、R 有）→ 采纳远端并落地。
5. **中止保护**：任何一步（fetch/解密/落地）失败 → **立即中止，绝不写墓碑**。仅对「基线中存在」的 id 才判定删除。
6. 重加密所有本地变更 → `blobs/<id>-<rev>.enc`；**仅当逻辑内容变化时才重写 `manifest.enc`**（否则每次同步的新 IV 都会弄脏工作树、产生空提交）。
7. `git add -A`；有变更则 `commit`；`push`（除 `--no-push`）。
8. 更新 `.report-state.json`（记录本次 R∪L 结果与各 rev/sha）。
9. 释放锁。

- `--dry-run`：**只 fetch + 计算差异并打印**，不落地、不重加密、不 commit、不更新基线（工作树零变更）。
- cron 与手动 `report sync` **共用同一把锁**。
- **读取一致性**：读文件 → 算 sha → 若期间被编辑则重读（避免半写快照）。`add` 也建议短暂持锁。

## 7. 跨实现一致性（强制门）

- **已完成**：Argon2id 实测一致（见 §2.1）。
- 每个实现完成后必须复跑该测试向量。
- 若未来出现不一致 → 回退 `PBKDF2-HMAC-SHA256`（Python `hashlib.pbkdf2_hmac` ↔ 浏览器 WebCrypto，天然一致），迭代 `600000`，`key.enc.kdf.algo="pbkdf2-sha256"` 且带 `iterations`/`hash` 字段。

## 8. 运维（本机 WSL）

- **cron**（`cron.service` 常驻）：每 10 分钟
  `flock -n ~/.cache/uzr-sync.lock <wrapper> sync >> ~/.cache/uzr-sync.log 2>&1`。
- 锁文件放 **`~/.cache/`**（非 `/tmp`）。
- 非交互 git：`uilz/report` 用**独立 deploy key**，`GIT_SSH_COMMAND="ssh -i <key> -o IdentitiesOnly=yes"`。
- push 被拒 → 记录并退出，**不 force**。

## 9. 迁移（旧 /md）

- 有价值旧文件入 `master_dir` → `sync` 发布。
- 主仓 `uilz.github.io` 删 `/md`，为旧 URL 生成跳转桩 `/md/<file>.html → ../report/`。
- 双仓加 `robots.txt` + `noindex`。
- 默认**不重写主仓历史**（旧明文仍在历史/缓存中，前向有效）。

## 10. 残余风险（已接受，不再讨论）

- 元信息泄露：报告条数、密文大小（≈明文大小）、git 提交时间、墓碑留存、`manifest.enc` 体积变化；`robots.txt`/`noindex` 仅建议性。
- **回滚/重放**：GCM 只防篡改，不防「整份旧 manifest + 旧 blob」回滚，无新鲜度锚。CK 随 rev 旋转 + AAD 绑定 rev 只解决同一 id 的版本回放。
- `mk.key` 与 env `UZR_MK` 使机器**绕过密码**（密码仅保护 `key.enc`）。
- 移动端 64MiB Argon2id 可能 OOM（低端机解锁失败）。
- `sync` 在远端领先时执行 `reset --hard`：会丢弃**未推送的本地提交**（密文可由 `master_dir` 重建；对 shell/文档等非派生文件的改动请先 push）。被丢弃的提交仍可从 `git reflog` 恢复。

## 11. 变更日志

- **v1.1.2**（SPA 修复）：放宽 CSP 以放行报告自带的 `cdn.jsdelivr.net` KaTeX/字体/内联脚本（`srcdoc` 继承父 CSP）；亮暗主题切换 + 持久化；缓存主密钥自动进入的瞬态容错；报告沉浸式放大/缩小；**修复报告空白**——复用且曾隐藏的 iframe 会丢弃后续 `srcdoc` 导航，改为每次新建 iframe 挂载；顶栏下滑收起/上滑出现；报告视图铺满到底并移除页脚与内容框。
- **v1.1.1**（实现落地）：`rekey` 命令（信封重加密）；`sync` 仅在逻辑内容变化时重写 `manifest.enc`、仅在 `changed` 时 push（幂等，防 cron 空提交）；CSP 增补 `'wasm-unsafe-eval'`（Argon2 WASM 必需）；主仓 `/md` 退役并加 `404.html` 跳转至 `/report/`。
- **v1.1**：`id` 改 32 hex；blob 名含 rev；CK 随 rev 旋转 + AAD 绑定；SPA 校验 sha256；引入本地基线状态；同步改 fetch + 逻辑合并（弃 git merge manifest）；墓碑 bump rev；`--dry-run` 不动工作树；密码 NFC；Argon2 显式参数；CSP/沙箱/DOMPurify 顺序冻结；PBKDF2 分支字段补全；锁移 `~/.cache`；补残余风险。
- v1.0：初版。