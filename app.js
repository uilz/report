"use strict";

/*
 * uilz/report — browser SPA for the encrypted static vault.
 * Contract: SPEC.md v1.1 §2 (primitives), §3 (file formats), §4 (SPA behavior).
 *
 * Guarantees implemented here:
 *   - Argon2id runs with the parameters read from key.enc.kdf (version 19, raw 32-byte output).
 *   - AES-256-GCM via WebCrypto: 12-byte IV, 16-byte tag appended, exact ASCII AAD literals.
 *   - HKDF-SHA256 over the MK with a zero-length salt and the frozen info strings.
 *   - Blob plaintext must match manifest.sha256 before anything is rendered.
 *   - Report HTML reaches the page only through iframe[srcdoc] inside
 *     sandbox="allow-scripts allow-popups" (never allow-same-origin, never the parent DOM).
 */

(() => {
  /* ------------------------------------------------------------- constants */

  const LS_MK = "uilz.report.mk";
  const LS_THEME = "uilz.report.theme";

  const AAD_KEY = enc("uilz-report/v1/key");
  const INFO_MANIFEST = enc("uilz-report/v1/manifest");
  const MAGIC = [0x55, 0x5a, 0x52, 0x31]; // "UZR1"
  const blobInfo = (id, rev) => enc(`uilz-report/v1/blob:${id}:${rev}`);

  const ID_RE = /^[0-9a-f]{32}$/;
  const REV_RE = /^[0-9]+$/;
  const SHA_RE = /^[0-9a-f]{64}$/;
  const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  const BLANK_DOC = "<!doctype html><meta charset='utf-8'><title></title>";

  const DOC_SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans SC', " +
    "'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif";
  const DOC_MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

  const PDF_DPR_MAX = 2;
  const KIND_LABELS = { md: "MD", html: "HTML", pdf: "PDF", text: "TXT" };

  // pdf.js renders in the parent document: the sandboxed iframe cannot load
  // vendor scripts, and Chromium blocks its native PDF plugin under sandbox.
  if (window.pdfjsLib) {
    window.pdfjsLib.GlobalWorkerOptions.workerSrc =
      new URL("vendor/pdfjs/pdf.worker.min.js", document.baseURI).href;
  }

  /* ------------------------------------------------------------- DOM nodes */

  const el = (id) => document.getElementById(id);
  const nodes = {
    gate: el("view-gate"),
    list: el("view-list"),
    report: el("view-report"),
    gateCard: el("gate-card"),
    gateForm: el("gate-form"),
    pw: el("pw"),
    pwToggle: el("pw-toggle"),
    gateError: el("gate-error"),
    unlockBtn: el("unlock-btn"),
    unlockLabel: el("unlock-label"),
    kdfMeta: el("kdf-meta"),
    lockBtn: el("lock-btn"),
    themeBtn: el("theme-btn"),
    topbar: document.querySelector(".topbar"),
    query: el("q"),
    listMeta: el("list-meta"),
    reportList: el("report-list"),
    listEmpty: el("list-empty"),
    listSkeleton: el("list-skeleton"),
    listBanner: el("list-banner"),
    listBannerText: el("list-banner-text"),
    listBannerRetry: el("list-banner-retry"),
    reportTitle: el("report-title"),
    reportMeta: el("report-meta"),
    frame: el("report-frame"),
    reportLoading: el("report-loading"),
    reportError: el("report-error"),
    reportErrorMsg: el("report-error-msg"),
    reportRetry: el("report-retry"),
    reportExpand: el("report-expand"),
    reportCollapse: el("report-collapse"),
    pdfView: el("pdf-view"),
    pdfPages: el("pdf-pages"),
    pdfPagecount: el("pdf-pagecount"),
    pdfFit: el("pdf-fit"),
    pdfOpen: el("pdf-open"),
    topbarActions: document.querySelector(".topbar-actions"),
    reportHead: document.querySelector(".report-head"),
  };

  /* ----------------------------------------------------------------- state */

  const state = {
    mk: null,
    unlocked: false,
    manifest: null,
    reports: [],
    query: "",
    activeId: null,
    keyDocPromise: null,
    enteredViaCache: false,
  };
  let openToken = 0;
  let manifestBusy = false;
  let autoRetryLeft = 1;
  let pdfResizeTimer = 0;

  const pdfState = {
    task: null, // pdfjsLib loading task; destroy() frees the worker and document
    doc: null,
    render: null, // the in-flight page render task
    session: 0, // bumped on teardown so stale async renders stop appending
    fit: true,
    width: 0,
    bytes: null,
    urls: new Set(),
  };

  /* ---------------------------------------------------------------- errors */

  class VaultError extends Error {
    constructor(code, message) {
      super(message);
      this.name = "VaultError";
      this.code = code;
    }
  }

  const fail = (code, message) => {
    throw new VaultError(code, message);
  };

  // Only genuine auth/format failures invalidate a cached MK. A network hiccup
  // or an unexpected error must never bounce the operator back to the gate.
  const FATAL_CODES = new Set(["auth", "format"]);
  const isFatalVaultError = (err) => err instanceof VaultError && FATAL_CODES.has(err.code);

  /* ---------------------------------------------------------------- bytes */

  function enc(text) {
    return new TextEncoder().encode(text);
  }

  function dec(bytes) {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }

  function b64encode(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  function b64decode(text) {
    let bin;
    try {
      bin = atob(String(text).trim());
    } catch {
      fail("format", "base64 解码失败");
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function needB64(value, label) {
    if (typeof value !== "string" || value.length === 0) {
      fail("format", `缺少字段 ${label}`);
    }
    return b64decode(value);
  }

  const hexOf = (bytes) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

  async function sha256Hex(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return hexOf(new Uint8Array(digest));
  }

  /* --------------------------------------------------------------- crypto */

  async function gcmOpen(rawKey, iv, ciphertext, aad) {
    const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      ciphertext
    );
    return new Uint8Array(plain);
  }

  async function hkdfKey(mk, info) {
    const base = await crypto.subtle.importKey("raw", mk, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
      base,
      256
    );
    return new Uint8Array(bits);
  }

  /* ------------------------------------------------------------------ KDF */

  async function deriveKek(password, kdf) {
    if (!kdf || typeof kdf !== "object") fail("format", "key.enc 缺少 kdf 字段");
    const salt = needB64(kdf.salt, "kdf.salt");

    if (kdf.algo === "argon2id") {
      if (!window.argon2) fail("internal", "argon2 库未加载（vendor/argon2-bundled.min.js）");
      if (kdf.version !== undefined && kdf.version !== 19) {
        fail("format", `不支持的 Argon2 版本：${kdf.version}`);
      }
      let result;
      try {
        result = await argon2.hash({
          pass: password, // NFC-normalized by the caller, UTF-8 inside argon2-browser
          salt, // raw 16 bytes, never a string
          time: kdf.t,
          mem: kdf.m, // KiB
          hashLen: kdf.hashLen || 32,
          parallelism: kdf.p,
          type: argon2.ArgonType.Argon2id,
          version: 0x13,
        });
      } catch (err) {
        const detail = err && err.message ? err.message : String(err);
        fail("internal", `Argon2id 派生失败：${detail}`);
      }
      return new Uint8Array(result.hash); // raw bytes, not hex
    }

    if (kdf.algo === "pbkdf2-sha256") {
      const wantsSha256 = String(kdf.hash || "sha256").toLowerCase() === "sha256";
      if (!wantsSha256) fail("format", `不支持的 PBKDF2 哈希：${kdf.hash}`);
      if (!Number.isInteger(kdf.iterations) || kdf.iterations < 1) {
        fail("format", "PBKDF2 iterations 非法");
      }
      const base = await crypto.subtle.importKey("raw", enc(password), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: kdf.iterations, hash: "SHA-256" },
        base,
        (kdf.hashLen || 32) * 8
      );
      return new Uint8Array(bits);
    }

    fail("format", `不支持的 KDF 算法：${kdf.algo}`);
  }

  /* ---------------------------------------------------------------- fetch */

  async function fetchBytes(path) {
    let res;
    try {
      res = await fetch(path, { cache: "no-store" });
    } catch {
      fail("network", `无法获取 ${path}（请通过 HTTP 打开本页）`);
    }
    if (!res.ok) fail("network", `无法获取 ${path}（HTTP ${res.status}）`);
    return new Uint8Array(await res.arrayBuffer());
  }

  function keyDoc() {
    if (!state.keyDocPromise) {
      state.keyDocPromise = fetchBytes("key.enc").then((bytes) => {
        let doc;
        try {
          doc = JSON.parse(dec(bytes));
        } catch {
          fail("format", "key.enc 不是合法 JSON");
        }
        if (!doc || typeof doc !== "object") fail("format", "key.enc 结构异常");
        return doc;
      });
      state.keyDocPromise.catch(() => {
        state.keyDocPromise = null; // allow a retry on the next attempt
      });
    }
    return state.keyDocPromise;
  }

  /* ---------------------------------------------------------------- vault */

  async function unlockWithPassword(password) {
    const doc = await keyDoc();
    const wrapped = doc.wrapped || {};
    const kek = await deriveKek(password.normalize("NFC"), doc.kdf);
    let mk;
    try {
      mk = await gcmOpen(
        kek,
        needB64(wrapped.iv, "wrapped.iv"),
        needB64(wrapped.ct, "wrapped.ct"),
        AAD_KEY
      );
    } catch (err) {
      if (err instanceof VaultError) throw err;
      fail("auth", "密码错误");
    }
    if (mk.length !== 32) fail("format", "MK 长度必须为 32 字节");
    return mk;
  }

  async function loadManifest(mk) {
    const raw = await fetchBytes("manifest.enc");
    if (raw.length < 12 + 16) fail("format", "manifest.enc 长度异常");
    const manifestKey = await hkdfKey(mk, INFO_MANIFEST);
    let plain;
    try {
      plain = await gcmOpen(manifestKey, raw.subarray(0, 12), raw.subarray(12), INFO_MANIFEST);
    } catch {
      fail("auth", "manifest 解密失败");
    }
    let doc;
    try {
      doc = JSON.parse(dec(plain));
    } catch {
      fail("format", "manifest JSON 解析失败");
    }
    if (!doc || !Array.isArray(doc.reports)) fail("format", "manifest 缺少 reports 数组");
    return doc;
  }

  function blobPath(entry) {
    const id = String(entry.id || "");
    const rev = String(entry.rev ?? "");
    if (!ID_RE.test(id) || !REV_RE.test(rev)) fail("format", "manifest 条目的 id/rev 非法");
    return `blobs/${id}-${rev}.enc`;
  }

  async function loadBlob(mk, entry) {
    const raw = await fetchBytes(blobPath(entry));
    if (raw.length < 4 + 12 + 16) fail("format", "blob 长度异常");
    for (let i = 0; i < MAGIC.length; i += 1) {
      if (raw[i] !== MAGIC[i]) fail("format", "blob MAGIC 校验失败（缺少 UZR1 前缀）");
    }
    const info = blobInfo(entry.id, entry.rev);
    const ck = await hkdfKey(mk, info);
    let plain;
    try {
      plain = await gcmOpen(ck, raw.subarray(4, 16), raw.subarray(16), info);
    } catch {
      fail("auth", "内容解密失败（rev/AAD 不匹配或数据损坏）");
    }
    const want = String(entry.sha256 || "").toLowerCase();
    if (!SHA_RE.test(want)) fail("format", "manifest 条目缺少合法的 sha256");
    const got = await sha256Hex(plain);
    if (got !== want) {
      fail("integrity", `sha256 校验失败：期望 ${want.slice(0, 12)}…，实际 ${got.slice(0, 12)}…。已拒绝渲染。`);
    }
    return plain;
  }

  /* ------------------------------------------------------------- rendering */

  const escapeHtml = (text) =>
    String(text).replace(/[&<>"']/g, (ch) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch])
    );

  const DOC_CSS = `
    :root {
      color-scheme: dark;
      --bg: #0d1116; --surface: #131820; --surface-2: #171d26;
      --line: #232b35; --ink: #e7ecf2; --ink-dim: #aab4c1; --brass: #d9a05b;
    }
    * { box-sizing: border-box; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0;
      padding: 2rem 1.25rem 4rem;
      background: var(--bg);
      color: var(--ink);
      font: 16px/1.7 ${DOC_SANS};
      -webkit-font-smoothing: antialiased;
    }
    main.uzr-doc { max-width: 72ch; margin: 0 auto; }
    h1, h2, h3, h4, h5, h6 { line-height: 1.25; letter-spacing: -0.01em; margin: 2.1em 0 0.6em; }
    h1 { font-size: 1.75rem; margin-top: 0.2em; }
    h2 { font-size: 1.35rem; }
    h3 { font-size: 1.12rem; }
    p, ul, ol, blockquote, pre, table { margin: 0 0 1.1em; }
    ul, ol { padding-left: 1.4em; }
    a { color: var(--brass); text-decoration: underline; text-underline-offset: 2px; }
    code, pre, kbd { font-family: ${DOC_MONO}; font-size: 0.9em; }
    :not(pre) > code {
      padding: 0.12em 0.38em; border: 1px solid var(--line); border-radius: 6px;
      background: var(--surface-2);
    }
    pre {
      padding: 1rem; overflow-x: auto; border: 1px solid var(--line);
      border-radius: 10px; background: var(--surface);
    }
    pre code { border: 0; padding: 0; background: none; }
    blockquote {
      margin-left: 0; padding: 0.2em 0 0.2em 1rem;
      border-left: 3px solid var(--brass); color: var(--ink-dim);
    }
    hr { border: 0; border-top: 1px solid var(--line); margin: 2rem 0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.5rem 0.7rem; border: 1px solid var(--line); text-align: left; }
    th { background: var(--surface-2); }
    img, video { max-width: 100%; height: auto; }
    .katex-display { overflow-x: auto; overflow-y: hidden; padding: 0.25rem 0; }
    ::selection { background: rgba(217, 160, 91, 0.25); }
  `;

  function markdownDocument(source, entry) {
    if (!window.marked || !window.DOMPurify) fail("internal", "markdown 渲染库未加载");
    let raw;
    try {
      raw = marked.parse(source);
    } catch {
      fail("format", "Markdown 解析失败");
    }
    const host = document.createElement("div");
    // First gate: neutralize anything hostile before KaTeX touches the tree.
    host.innerHTML = DOMPurify.sanitize(raw);
    if (typeof window.renderMathInElement === "function") {
      window.renderMathInElement(host, {
        delimiters: [
          { left: "$$", right: "$$", display: true },
          { left: "\\[", right: "\\]", display: true },
          { left: "\\(", right: "\\)", display: false },
          { left: "$", right: "$", display: false },
        ],
        throwOnError: false,
        trust: false, // no \href / \htmlClass / \includegraphics passthrough
        strict: "ignore",
      });
    }
    // SPEC §4.4: DOMPurify runs on the FINAL html (KaTeX output included).
    const body = DOMPurify.sanitize(host.innerHTML, { ADD_ATTR: ["encoding"] });
    return [
      "<!doctype html>",
      '<html lang="zh-CN"><head><meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      `<title>${escapeHtml(entry.title || "报告")}</title>`,
      '<link rel="stylesheet" href="vendor/katex/katex.min.css">',
      `<style>${DOC_CSS}</style>`,
      `</head><body><main class="uzr-doc">${body}</main></body></html>`,
    ].join("\n");
  }

  const TEXT_DOC_CSS = `
    :root { color-scheme: dark; --bg: #0d1116; --surface: #131820; --line: #232b35; --ink: #e7ecf2; }
    html { -webkit-text-size-adjust: 100%; }
    body { margin: 0; padding: 1.25rem; background: var(--bg); }
    pre {
      margin: 0; padding: 1rem;
      border: 1px solid var(--line); border-radius: 10px; background: var(--surface);
      color: var(--ink); font: 13px/1.65 ${DOC_MONO};
      white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; tab-size: 4;
    }
  `;

  function textDocument(source, entry) {
    return [
      "<!doctype html>",
      '<html lang="zh-CN"><head><meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      `<title>${escapeHtml(entry.title || "报告")}</title>`,
      `<style>${TEXT_DOC_CSS}</style>`,
      `</head><body><pre>${escapeHtml(source)}</pre></body></html>`,
    ].join("\n");
  }

  function srcdocFor(entry, plain) {
    if (entry.kind === "md") return markdownDocument(dec(plain), entry);
    if (entry.kind === "html") return dec(plain); // raw, but still confined to the sandbox
    if (entry.kind === "text") return textDocument(dec(plain), entry);
    fail("format", `不支持的 kind：${entry.kind}`);
  }

  /* ---------------------------------------------------------------- format */

  function formatDate(iso) {
    if (typeof iso !== "string" || !ISO_RE.test(iso)) return String(iso || "");
    const [date, time] = iso.split("T");
    return `${date} ${time.slice(0, 5)} UTC`;
  }

  function formatSize(size) {
    if (!Number.isFinite(size) || size < 0) return "";
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(size < 10240 ? 1 : 0)} KB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }

  function describeKdf(kdf) {
    if (!kdf || typeof kdf !== "object") return "KDF：未知";
    if (kdf.algo === "argon2id") {
      const mib = Number.isFinite(kdf.m) ? Math.round(kdf.m / 1024) : "?";
      return `KDF：Argon2id · t=${kdf.t} · m=${mib} MiB · p=${kdf.p} · ${kdf.hashLen || 32}B · v${kdf.version ?? "?"}`;
    }
    if (kdf.algo === "pbkdf2-sha256") {
      return `KDF：PBKDF2-SHA256 · ${kdf.iterations} 次 · ${kdf.hashLen || 32}B`;
    }
    return `KDF：${kdf.algo}`;
  }

  function describe(err) {
    if (err instanceof VaultError) return err.message;
    if (err instanceof Error && err.message) return err.message;
    return "发生未知错误。";
  }

  /* ------------------------------------------------------------ list view */

  function findEntry(id) {
    return state.reports.find((entry) => entry && entry.id === id) || null;
  }

  function sortedReports() {
    return state.reports
      .filter((entry) => entry && !entry.deleted)
      .sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));
  }

  function metaLine(entry, withSha = true) {
    const kind = String(entry.kind || "");
    const bits = [KIND_LABELS[kind] || kind.toUpperCase(), `r${entry.rev}`];
    if (Number.isFinite(entry.size)) bits.push(formatSize(entry.size));
    if (entry.updatedAt) bits.push(formatDate(entry.updatedAt));
    if (withSha && typeof entry.sha256 === "string" && entry.sha256) {
      bits.push(`sha ${entry.sha256.slice(0, 12)}`);
    }
    return bits.filter(Boolean).join(" · ");
  }

  function renderList() {
    const query = state.query.trim().toLowerCase();
    const all = sortedReports();
    const rows = all.filter((entry) => {
      if (!query) return true;
      const title = String(entry.title || "").toLowerCase();
      return title.includes(query) || String(entry.id || "").startsWith(query);
    });

    nodes.reportList.textContent = "";
    rows.forEach((entry, index) => {
      const item = document.createElement("li");
      if (index < 12) item.style.setProperty("--i", String(index));

      const link = document.createElement("a");
      link.className = "row";
      link.href = `#/${entry.id}`;
      link.setAttribute("aria-label", `打开报告：${entry.title || entry.id}`);

      const main = document.createElement("span");
      main.className = "row-main";

      const title = document.createElement("span");
      title.className = "row-title";
      title.textContent = String(entry.title || entry.id || "未命名报告");

      const sub = document.createElement("span");
      sub.className = "row-sub";
      sub.textContent = metaLine(entry, false);

      main.append(title, sub);

      const side = document.createElement("span");
      side.className = "row-side";

      const chip = document.createElement("span");
      const kind = KIND_LABELS[entry.kind] ? entry.kind : "";
      chip.className = kind ? `chip chip-${kind}` : "chip";
      chip.textContent = KIND_LABELS[kind] || String(entry.kind || "?").toUpperCase();

      const rev = document.createElement("span");
      rev.className = "row-rev";
      rev.textContent = `r${entry.rev}`;

      const go = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      go.setAttribute("class", "row-go");
      go.setAttribute("viewBox", "0 0 24 24");
      go.setAttribute("aria-hidden", "true");
      go.setAttribute("focusable", "false");
      const goPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
      goPath.setAttribute("d", "M9.5 5.5L16 12l-6.5 6.5");
      goPath.setAttribute("fill", "none");
      goPath.setAttribute("stroke", "currentColor");
      goPath.setAttribute("stroke-width", "1.7");
      goPath.setAttribute("stroke-linecap", "round");
      goPath.setAttribute("stroke-linejoin", "round");
      go.appendChild(goPath);

      side.append(chip, rev, go);
      link.append(main, side);
      item.appendChild(link);
      nodes.reportList.appendChild(item);
    });

    nodes.listEmpty.hidden = rows.length > 0;

    const tombstones = state.reports.length - all.length;
    const bits = [`共 ${all.length} 份`];
    if (query) bits.push(`匹配 ${rows.length}`);
    if (tombstones > 0) bits.push(`墓碑 ${tombstones}`);
    if (state.manifest && state.manifest.updatedAt) {
      bits.push(`清单 ${formatDate(state.manifest.updatedAt)}`);
    }
    nodes.listMeta.textContent = bits.join(" · ");
  }

  function setListLoading(loading) {
    nodes.listSkeleton.hidden = !loading;
    if (loading) {
      nodes.reportList.textContent = "";
      nodes.listEmpty.hidden = true;
      nodes.listMeta.textContent = "解密清单…";
    }
  }

  function showListBanner(tone, message, withRetry) {
    nodes.listBanner.dataset.tone = tone;
    nodes.listBannerText.textContent = message;
    nodes.listBannerRetry.hidden = !withRetry;
    nodes.listBanner.hidden = false;
  }

  function hideListBanner() {
    nodes.listBanner.hidden = true;
    nodes.listBannerRetry.hidden = true;
  }

  /* ---------------------------------------------------------- report view */

  function clearFrame() {
    nodes.frame.hidden = true;
    nodes.frame.setAttribute("srcdoc", BLANK_DOC);
  }

  function resetViews() {
    clearFrame();
    hidePdf();
  }

  // A reused iframe that was hidden when it first received a document can silently
  // drop later srcdoc navigations (reports paint blank); mount a fresh one instead.
  function mountFrame(doc) {
    const frame = document.createElement("iframe");
    frame.id = "report-frame";
    frame.className = "report-frame";
    frame.setAttribute("sandbox", "allow-scripts allow-popups");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.title = "报告内容";
    frame.hidden = false;
    nodes.frame.replaceWith(frame);
    nodes.frame = frame;
    frame.setAttribute("srcdoc", doc);
  }

  function showReportHead(entry) {
    nodes.reportTitle.textContent = entry && entry.title ? String(entry.title) : "报告";
    const narrow = window.matchMedia && window.matchMedia("(max-width: 40rem)").matches;
    nodes.reportMeta.textContent = entry ? metaLine(entry, !narrow) : "";
  }

  function showReportError(message, entry) {
    showReportHead(entry);
    resetViews();
    nodes.reportLoading.hidden = true;
    nodes.reportErrorMsg.textContent = message;
    nodes.reportError.hidden = false;
    showView("report");
  }

  /* -------------------------------------------------------------- pdf viewer */

  function revokePdfUrls() {
    pdfState.urls.forEach((url) => URL.revokeObjectURL(url));
    pdfState.urls.clear();
  }

  function destroyPdf() {
    pdfState.session += 1; // stale paint loops stop on their next page
    if (pdfState.render) {
      try { pdfState.render.cancel(); } catch { /* already settled */ }
      pdfState.render = null;
    }
    const task = pdfState.task;
    pdfState.task = null;
    pdfState.doc = null;
    pdfState.width = 0;
    pdfState.bytes = null;
    if (task) {
      try {
        const done = task.destroy();
        if (done && typeof done.catch === "function") done.catch(() => {});
      } catch { /* already destroyed */ }
    }
    revokePdfUrls();
  }

  function hidePdf() {
    destroyPdf();
    nodes.pdfView.hidden = true;
    nodes.pdfPages.textContent = "";
    nodes.pdfPagecount.textContent = "";
  }

  function pdfPageWidth() {
    const styles = getComputedStyle(nodes.pdfPages);
    const padding = (parseFloat(styles.paddingLeft) || 0) + (parseFloat(styles.paddingRight) || 0);
    const width = nodes.pdfPages.clientWidth - padding - 2;
    return width > 40 ? width : 600;
  }

  async function paintPdf(doc, token, session) {
    const total = doc.numPages;
    const dpr = Math.min(window.devicePixelRatio || 1, PDF_DPR_MAX);
    const host = nodes.pdfPages;
    host.textContent = "";
    nodes.pdfPagecount.textContent = total ? `渲染中… 0/${total}` : "空 PDF";

    for (let number = 1; number <= total; number += 1) {
      if (token !== openToken || session !== pdfState.session) return;
      const page = await doc.getPage(number);
      const base = page.getViewport({ scale: 1 });
      const width = pdfPageWidth();
      if (pdfState.fit) pdfState.width = width;
      const viewport = page.getViewport({ scale: pdfState.fit ? width / base.width : 1 });

      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.floor(viewport.width * dpr));
      canvas.height = Math.max(1, Math.floor(viewport.height * dpr));
      canvas.style.width = `${Math.floor(viewport.width)}px`;
      canvas.style.height = `${Math.floor(viewport.height)}px`;

      const shell = document.createElement("div");
      shell.className = "pdf-page";
      shell.appendChild(canvas);
      host.appendChild(shell);

      const task = page.render({
        canvasContext: canvas.getContext("2d", { alpha: false }),
        viewport,
        transform: dpr === 1 ? null : [dpr, 0, 0, dpr, 0, 0],
      });
      pdfState.render = task;
      try {
        await task.promise;
      } finally {
        if (pdfState.render === task) pdfState.render = null;
      }
      if (token !== openToken || session !== pdfState.session) return;
      nodes.pdfPagecount.textContent = `${number} / ${total} 页`;
    }
    nodes.pdfPagecount.textContent = `共 ${total} 页`;
  }

  async function renderPdf(plain, token) {
    if (!window.pdfjsLib) fail("internal", "pdf.js 未加载（vendor/pdfjs/pdf.min.js）");
    const session = pdfState.session;
    pdfState.bytes = plain; // kept for the "open in new tab" blob URL
    const data = plain.slice(); // the worker takes ownership of this buffer
    let task;
    try {
      task = window.pdfjsLib.getDocument({ data });
    } catch (err) {
      fail("render", `PDF 解析失败：${describe(err)}`);
    }
    pdfState.task = task;
    let doc;
    try {
      doc = await task.promise;
    } catch (err) {
      if (session === pdfState.session) {
        pdfState.task = null;
        pdfState.bytes = null;
      }
      fail("render", `PDF 解析失败：${describe(err)}`);
    }
    if (token !== openToken || session !== pdfState.session) return;
    pdfState.doc = doc;
    await paintPdf(doc, token, session);
  }

  async function rerenderPdf() {
    if (!pdfState.doc || nodes.pdfView.hidden) return;
    const session = pdfState.session;
    const token = openToken;
    try {
      await paintPdf(pdfState.doc, token, session);
    } catch (err) {
      if (session === pdfState.session && token === openToken) {
        showReportError(describe(err), findEntry(state.activeId));
      }
    }
  }

  function maybeRefitPdf() {
    if (!pdfState.fit || !pdfState.doc || nodes.pdfView.hidden || nodes.report.hidden) return;
    if (Math.abs(pdfPageWidth() - pdfState.width) >= 8) void rerenderPdf();
  }

  async function openReport(id) {
    const token = (openToken += 1);
    state.activeId = id;
    const entry = findEntry(id);

    if (!entry || entry.deleted) {
      showReportError(
        entry ? "该报告已删除（墓碑条目）。" : "未找到该报告，可能已从 manifest 移除。",
        entry
      );
      return;
    }

    showReportHead(entry);
    resetViews();
    nodes.reportError.hidden = true;
    nodes.reportLoading.hidden = false;
    showView("report");

    try {
      const plain = await loadBlob(state.mk, entry);
      if (token !== openToken) return;
      if (entry.kind === "pdf") {
        nodes.reportLoading.hidden = true;
        nodes.pdfView.hidden = false;
        nodes.pdfPagecount.textContent = "加载中…";
        await renderPdf(plain, token);
        if (token !== openToken) return;
        nodes.reportTitle.focus({ preventScroll: true });
        return;
      }
      mountFrame(srcdocFor(entry, plain));
      nodes.reportLoading.hidden = true;
      nodes.reportTitle.focus({ preventScroll: true });
    } catch (err) {
      if (token !== openToken) return;
      showReportError(describe(err), entry);
    }
  }

  /* ---------------------------------------------------------------- router */

  function routeId() {
    const raw = location.hash.replace(/^#\/?/, "").replace(/\/+$/, "");
    return ID_RE.test(raw) ? raw : null;
  }

  function applyRoute() {
    if (!state.unlocked) {
      showView("gate");
      return;
    }
    const id = routeId();
    if (!id) {
      state.activeId = null;
      openToken += 1;
      resetViews();
      showView("list");
      return;
    }
    if (id === state.activeId && (!nodes.frame.hidden || !nodes.pdfView.hidden)) return;
    void openReport(id);
  }

  /* ----------------------------------------------------------------- views */

  function placeActions(inReport) {
    if (inReport) nodes.reportHead.insertBefore(nodes.topbarActions, nodes.reportExpand);
    else nodes.topbar.appendChild(nodes.topbarActions);
    nodes.topbar.classList.remove("is-hidden");
    nodes.reportHead.classList.remove("is-hidden");
  }

  function showView(name) {
    const inReport = name === "report";
    nodes.gate.hidden = name !== "gate";
    nodes.list.hidden = name !== "list";
    nodes.report.hidden = name !== "report";
    document.documentElement.classList.toggle("viewing-report", inReport);
    placeActions(inReport);
    if (!inReport) setImmerse(false);
  }

  function setImmerse(on) {
    document.documentElement.classList.toggle("immerse", on);
    nodes.reportCollapse.hidden = !on;
    maybeRefitPdf();
  }

  function setGateError(message) {
    nodes.gateError.textContent = message || "";
    nodes.gateError.hidden = !message;
  }

  function setBusy(busy) {
    nodes.unlockBtn.disabled = busy;
    nodes.unlockBtn.classList.toggle("is-busy", busy);
    nodes.unlockLabel.textContent = busy ? "派生密钥中…" : "解锁";
    nodes.pw.disabled = busy;
  }

  function refreshGateMeta() {
    keyDoc()
      .then((doc) => {
        if (!nodes.gate.hidden) nodes.kdfMeta.textContent = describeKdf(doc.kdf);
      })
      .catch((err) => {
        if (!nodes.gate.hidden) nodes.kdfMeta.textContent = describe(err);
      });
  }

  function showGate(message) {
    setBusy(false);
    setGateError(message || "");
    showView("gate");
    refreshGateMeta();
    nodes.pw.value = "";
    window.setTimeout(() => nodes.pw.focus(), 0);
  }

  function wipeMk() {
    if (state.mk) state.mk.fill(0);
    state.mk = null;
    state.unlocked = false;
    state.manifest = null;
    state.reports = [];
    state.activeId = null;
    openToken += 1;
    try {
      localStorage.removeItem(LS_MK);
    } catch {
      /* storage unavailable */
    }
    autoRetryLeft = 1;
    nodes.lockBtn.hidden = true;
    resetViews();
  }

  function readCachedMk() {
    let text = null;
    try {
      text = localStorage.getItem(LS_MK);
    } catch {
      return null;
    }
    if (!text) return null;
    try {
      const bytes = b64decode(text);
      if (bytes.length !== 32) return null;
      return bytes;
    } catch {
      return null;
    }
  }

  function writeCachedMk(mk) {
    try {
      localStorage.setItem(LS_MK, b64encode(mk));
    } catch {
      /* storage unavailable: session-only unlock */
    }
  }

  function retryManifest() {
    if (!state.mk) {
      showGate();
      return;
    }
    void enterVault({ viaCache: state.enteredViaCache }).catch((err) => {
      wipeMk();
      showGate(err instanceof VaultError && err.code === "auth"
        ? "本机缓存的密钥已失效，请重新输入密码。"
        : describe(err));
    });
  }

  async function refreshManifest() {
    if (!state.unlocked || !state.mk || document.hidden) return;
    try {
      const manifest = await loadManifest(state.mk);
      state.manifest = manifest;
      state.reports = manifest.reports.filter((entry) => entry && typeof entry === "object");
      renderList();
    } catch {
      return;
    }
  }

  async function enterVault(opts) {
    if (manifestBusy) return false;
    manifestBusy = true;
    const viaCache = !!(opts && opts.viaCache);
    try {
      state.enteredViaCache = viaCache;
      state.unlocked = true;
      nodes.lockBtn.hidden = false;
      hideListBanner();
      setListLoading(true);
      showView("list");

      let manifest;
      try {
        manifest = await loadManifest(state.mk);
      } catch (err) {
        if (isFatalVaultError(err)) throw err;
        // Transient (network / unexpected): stay unlocked, keep the cached key,
        // and surface a retryable state instead of the password gate.
        setListLoading(false);
        nodes.listMeta.textContent = "清单未加载";
        const willRetry = autoRetryLeft > 0;
        if (willRetry) {
          autoRetryLeft -= 1;
          window.setTimeout(retryManifest, 1200);
        }
        showListBanner("error", `${describe(err)}${willRetry ? " · 正在自动重试…" : ""}`, true);
        return false;
      }

      state.manifest = manifest;
      state.reports = manifest.reports.filter((entry) => entry && typeof entry === "object");
      setListLoading(false);
      renderList();
      if (viaCache) showListBanner("info", "已使用本机缓存的密钥自动解锁", false);
      applyRoute();
      return true;
    } finally {
      manifestBusy = false;
    }
  }

  /* ----------------------------------------------------------------- theme */

  function readStoredTheme() {
    try {
      const value = localStorage.getItem(LS_THEME);
      return value === "light" || value === "dark" ? value : null;
    } catch {
      return null; // storage unavailable: fall back to the OS preference
    }
  }

  // Mirrors the inline bootstrap in index.html <head>; keep the two in sync.
  function preferredTheme() {
    return readStoredTheme() ||
      (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }

  function paintTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const next = theme === "dark" ? "light" : "dark";
    nodes.themeBtn.setAttribute("aria-label", next === "dark" ? "切换到暗色" : "切换到亮色");
  }

  function initTheme() {
    paintTheme(preferredTheme());
    nodes.themeBtn.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      paintTheme(next);
      try {
        localStorage.setItem(LS_THEME, next);
      } catch {
        /* storage unavailable: the choice lives for this session only */
      }
    });
  }

  /* ---------------------------------------------------------------- events */

  const nextPaint = () =>
    new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));

  function shakeGate() {
    nodes.gateCard.classList.remove("is-shaking");
    void nodes.gateCard.offsetWidth; // restart the animation
    nodes.gateCard.classList.add("is-shaking");
    window.setTimeout(() => nodes.gateCard.classList.remove("is-shaking"), 600);
  }

  async function onUnlockSubmit(event) {
    event.preventDefault();
    if (nodes.unlockBtn.disabled) return;
    const password = nodes.pw.value;
    if (!password) {
      setGateError("请输入密码。");
      nodes.pw.focus();
      return;
    }

    setBusy(true);
    setGateError("");
    try {
      await nextPaint();
      const mk = await unlockWithPassword(password);
      state.mk = mk;
      writeCachedMk(mk);
      nodes.pw.value = "";
      await enterVault();
    } catch (err) {
      wipeMk();
      showGate(describe(err));
      if (err instanceof VaultError && err.code === "auth") shakeGate();
      return;
    } finally {
      setBusy(false);
    }
  }

  function lock() {
    wipeMk();
    if (location.hash && location.hash !== "#/") location.hash = "#/";
    showGate();
  }

  function wireEvents() {
    nodes.gateForm.addEventListener("submit", onUnlockSubmit);

    nodes.pwToggle.addEventListener("click", () => {
      const hidden = nodes.pw.type === "password";
      nodes.pw.type = hidden ? "text" : "password";
      nodes.pwToggle.textContent = hidden ? "隐藏" : "显示";
      nodes.pwToggle.setAttribute("aria-label", hidden ? "隐藏密码" : "显示密码");
      nodes.pw.focus();
    });

    nodes.lockBtn.addEventListener("click", lock);

    nodes.query.addEventListener("input", () => {
      state.query = nodes.query.value;
      renderList();
    });

    nodes.reportRetry.addEventListener("click", () => {
      if (state.activeId) void openReport(state.activeId);
    });

    nodes.reportExpand.addEventListener("click", () => setImmerse(true));
    nodes.reportCollapse.addEventListener("click", () => setImmerse(false));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") setImmerse(false);
    });

    nodes.pdfFit.addEventListener("click", () => {
      pdfState.fit = !pdfState.fit;
      nodes.pdfFit.setAttribute("aria-pressed", pdfState.fit ? "true" : "false");
      void rerenderPdf();
    });

    nodes.pdfOpen.addEventListener("click", () => {
      if (!pdfState.bytes) return;
      const url = URL.createObjectURL(new Blob([pdfState.bytes], { type: "application/pdf" }));
      pdfState.urls.add(url);
      window.open(url, "_blank", "noopener");
    });

    nodes.listBannerRetry.addEventListener("click", retryManifest);

    window.addEventListener("hashchange", applyRoute);

    const activeChrome = () =>
      document.documentElement.classList.contains("viewing-report") ? nodes.reportHead : nodes.topbar;
    const wireScrollHide = (el, readY) => {
      let last = readY();
      el.addEventListener("scroll", () => {
        const y = readY();
        const bar = activeChrome();
        if (y > last + 6 && y > 48) bar.classList.add("is-hidden");
        else if (y < last - 6) bar.classList.remove("is-hidden");
        last = y;
      }, { passive: true });
    };
    wireScrollHide(window, () => window.scrollY || 0);
    wireScrollHide(nodes.pdfPages, () => nodes.pdfPages.scrollTop || 0);

    window.addEventListener("resize", () => {
      window.clearTimeout(pdfResizeTimer);
      pdfResizeTimer = window.setTimeout(maybeRefitPdf, 200);
    }, { passive: true });

    const refresh = () => void refreshManifest();
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    // No window "message" listener exists on purpose: the sandbox has an opaque
    // origin, so any future listener must check event.origin === "null" (SPEC §4.5).
  }

  /* ------------------------------------------------------------------ boot */

  async function boot() {
    initTheme();
    wireEvents();
    const cached = readCachedMk();
    if (!cached) {
      showGate();
      return;
    }
    state.mk = cached;
    try {
      await enterVault({ viaCache: true });
    } catch (err) {
      // Only a genuine auth/format failure invalidates the cached key;
      // transient failures keep it and are handled inside enterVault().
      wipeMk();
      showGate(err instanceof VaultError && err.code === "auth"
        ? "本机缓存的密钥已失效，请重新输入密码。"
        : describe(err));
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => void boot(), { once: true });
  } else {
    void boot();
  }
})();