"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const hash = "a".repeat(64), other = "b".repeat(64);
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.className = ""; this._text = ""; }
  appendChild(child) { this.children.push(child); return child; }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map((node) => node.textContent).join(""); }
}
const document = { createElement: (tag) => new Element(tag), addEventListener() {} };
let messages = 0;
const popup = { document, module: { exports: {} }, URL, console,
  chrome: { runtime: { sendMessage() { messages++; } } } };
vm.runInNewContext(read("extension/popup/popup.js"), popup);
const { PopupRenderer, popupVtHashMismatch, popupVtNotQueried } = popup.module.exports;
const pageUrl = "https://download.example.test/";
const legacy = { filename: "01-Forza.Horizon.6.Update.v354.221.to.v440.853.rar", kind: "archive",
  sha256: "", pe: { isPe: false, signed: false, skipped: true, signatureUnscanned: true, reason: "too-large" },
  vt: { success: true, found: null, notFound: false, unknown: true, summary: "", guiUrl: "" },
  nested: [], archiveFormat: "rar", archiveNote: "RAR 文件过大（约 28293MB），未完整读取，未进行包内文件与数字签名扫描",
  status: "allowed", allowed: true, title: "未达拦截阈值，已放行下载",
  guiUrl: "https://www.virustotal.com/gui/home/upload", tabId: 1, pageUrl, timestamp: Date.now() };
function render(info) {
  const renderer = Object.create(PopupRenderer.prototype);
  renderer.root = new Element("div"); renderer.activeTabId = 1; renderer.activeTabUrl = pageUrl;
  renderer._vtDetailsRefreshes = new Set(); renderer._nestedSignatureRefreshes = new Set();
  renderer.appendPackageVt(info, pageUrl);
  renderer.maybeRefreshVtEngineDetails(info);
  renderer.maybeRefreshNestedSignatures(info);
  return renderer.root;
}
function allNodes(node) { return [node, ...node.children.flatMap(allNodes)]; }

async function main() {
  for (const sample of [legacy, { ...legacy, status: "unscanned", partialScan: true,
    vt: { ...legacy.vt, success: false, queryState: "not-requested", skipped: true } }]) {
    assert.equal(popupVtHashMismatch(sample), false);
    assert.equal(popupVtNotQueried(sample), true);
    const tree = render(sample), text = tree.textContent;
    assert.ok(text.includes("文件未完整读取，检测未完成"));
    assert.ok(text.includes("未生成整包 SHA256，未查询外壳 VT"));
    assert.ok(text.includes("28293MB"));
    assert.doesNotMatch(text, /不匹配|重新查询|配置 API|在 VirusTotal 查看|无 VT 记录|已放行/);
    assert.equal(allNodes(tree).some((node) => /vt-ok|sig-valid/.test(node.className)), false);
  }
  assert.equal(messages, 0);
  console.log("PASS: new and cached 28293 MB RAR reports render unscanned, without retry or green verdict");

  // A real report without an outer hash, or two different hashes, must still be rejected.
  for (const vt of [ { found: true, hash, total: 70, statsPolicyVersion: 4 },
    { unknown: true, hash }, { found: null, unknown: true, signerFromVt: "Other Publisher" } ]) {
    assert.equal(popupVtHashMismatch({ ...legacy, vt }), true);
    assert.equal(popupVtNotQueried({ ...legacy, vt }), false);
  }
  assert.equal(popupVtHashMismatch({ sha256: hash, vt: { unknown: true, hash: other } }), true);
  assert.equal(popupVtHashMismatch({ sha256: hash, vt: { unknown: true, hash } }), false);
  assert.equal(popupVtHashMismatch({ sha256: hash, vt: { found: true, hash, statsPolicyVersion: 4 } }), false);
  console.log("PASS: absent query is distinct from actual foreign/unbound VT results");

  const rangedZip = { ...legacy, filename: "large.zip", archiveFormat: "zip", archiveNote: "ZIP 分段扫描",
    nested: [{ name: "inner.exe", kind: "pe", sha256: hash, signed: true, sigTrust: "valid",
      vt: { hash, found: true, statsPolicyVersion: 4, total: 70, malicious: 0, suspicious: 0,
        sigTrustFromVt: "valid", trustedPolicyVersion: 4 } }] };
  const partialText = render(rangedZip).textContent;
  assert.ok(partialText.includes("VT 有效")); assert.ok(partialText.includes("检出 0/70"));
  assert.ok(partialText.includes("未查询外壳 VT")); assert.doesNotMatch(partialText, /不匹配/);
  assert.equal(messages, 0);
  console.log("PASS: unqueried ZIP shell does not hide verified nested-file results");

  let fetches = 0, vtQueries = 0, cancellations = 0;
  const NS = {};
  const store = {};
  const chrome = { runtime: { sendMessage(_m, cb) { cb?.(); } }, storage: { local: {
    get(_keys, cb) { cb(store); }, set(values, cb) { Object.assign(store, values); cb?.(); }
  } }, tabs: { get(_id, cb) { cb({ url: pageUrl }); } } };
  const context = { self: { SilverfoxBackground: NS }, chrome, URL, console, setTimeout, clearTimeout,
    AbortController, Map, crypto: require("node:crypto").webcrypto,
    fetch: async () => { fetches++; return { ok: true, status: 200,
      headers: { get: (name) => name === "content-length" ? String(28293 * 1048576) : "application/octet-stream" },
      body: { cancel: async () => { cancellations++; } } }; } };
  vm.runInNewContext(read("extension/background/pe-vt-bg.js"), context);
  NS.lookupVirusTotalHash = async () => { vtQueries++; throw new Error("VT must not run without a file hash"); };
  for (const extension of ["rar", "7z", "exe"]) {
    const info = await NS.inspectPackageUrl("https://download.example.test/file." + extension, { filename: "file." + extension });
    assert.equal(info.sha256, ""); assert.equal(info.partialScan, true);
    assert.equal(info.vt.queryState, "not-requested"); assert.equal(info.vt.notFound, false);
    assert.equal(info.signature.trust, "unknown");
    assert.equal(popupVtHashMismatch(info), false);
    const tree = render({ ...legacy, ...info, status: "unscanned" });
    assert.doesNotMatch(tree.textContent, /不匹配|待重新查询/);
    if (extension === "exe") assert.ok(tree.textContent.includes("未检测（文件超过650MB，未完整读取）"));
  }
  NS.probeDownloadExecutableAsync({ id: 1, tabId: 1, url: "https://download.example.test/file.rar", filename: "file.rar" }, {});
  for (let i = 0; i < 20 && NS._latestExeVtMem?.status !== "unscanned"; i++) await new Promise((r) => setImmediate(r));
  assert.equal(NS._latestExeVtMem.status, "unscanned");
  assert.equal(NS._latestExeVtMem.partialScan, true);
  assert.equal(NS._latestExeVtMem.sha256, "");
  assert.equal(vtQueries, 0); assert.equal(fetches, cancellations);
  console.log("PASS: large RAR/7z/PE skip VT; final background report preserves terminal unscanned state");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
