"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const hash = "a".repeat(64), url = "https://cdn.example.test/Setup.exe", page = "https://example.test/download";
const report = (hard = false) => ({ success: true, kind: "pe", sha256: hash, nested: [],
  pe: { isPe: true, signed: true }, signature: { trust: "present" },
  vt: { found: true, hash, statsPolicyVersion: 4, trustedPolicyVersion: 4, malicious: hard ? 20 : 0,
    suspicious: 0, total: 70, engineDetailsAvailable: true, trustedScoreHardBlock: hard,
    trustedScore: hard ? 8 : 0, trustedEngineCount: hard ? 3 : 0 } });
function fixture() {
  const tasks = [], releases = [], deletions = [], cancellations = [], messages = [], notifications = [], store = {};
  const NS = { tabNavState: new Map([[1, { lastGoodUrl: page }]]),
    _activeRiskTxnByTab: new Map([[1, { url: page, analysisTxn: "test" }]]),
    _riskNavigationSeqByTab: new Map([[1, 1]]),
    showBlockedNotification(...args) { notifications.push(args); } };
  const chrome = { runtime: { sendMessage(msg, cb) { messages.push(msg); cb?.(); } },
    tabs: { sendMessage(_id, msg, _options, cb) { messages.push(msg); cb?.(); } },
    downloads: {
      download(opts, cb) { releases.push(opts); cb(100 + releases.length); },
      removeFile(id, cb) { deletions.push(id); cb(); }, cancel(id, cb) { cancellations.push(id); cb(); }
    }, storage: { local: {
      get(_keys, cb) { cb(store); }, set(data, cb) { Object.assign(store, data); cb?.(); }
    } } };
  vm.runInNewContext(read("extension/background/pe-vt-bg.js"), { self: { SilverfoxBackground: NS }, chrome,
    URL, Map, setTimeout, clearTimeout, console: { log() {}, warn() {} }, crypto: require("node:crypto").webcrypto });
  NS.inspectPackageUrl = (_url, opts) => new Promise(resolve => tasks.push({ opts, resolve }));
  NS.lookupVirusTotalHash = async () => report(true).vt;
  const start = gate => NS.probeDownloadExecutableAsync({ id: 1, tabId: 1, url, filename: "Setup.exe" }, { gate });
  return { NS, start, tasks, releases, deletions, cancellations, messages, notifications, store };
}
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.className = ""; this._text = ""; }
  appendChild(child) { this.children.push(child); return child; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(""); }
}
function render(info) {
  const context = { document: { createElement: tag => new Element(tag), addEventListener() {} },
    module: { exports: {} }, URL, console };
  vm.runInNewContext(read("extension/popup/popup.js"), context);
  const renderer = Object.create(context.module.exports.PopupRenderer.prototype);
  renderer.root = new Element("div"); renderer.activeTabId = 1; renderer.activeTabUrl = page;
  renderer.appendPackageVt(info, page);
  return renderer.root;
}
async function main() {
  const f = fixture(); f.start(false); await tick();
  f.tasks[0].opts.onPartial({ stage: "vt", report: report(true) });
  assert.equal(f.deletions.length, 0); assert.equal(f.cancellations.length, 0);
  f.tasks[0].resolve(report(true)); await tick();
  assert.equal(f.deletions.length, 0); assert.equal(f.cancellations.length, 0);
  const entry = f.NS._latestExeVtMem;
  assert.equal(entry.sampleOnly, true); assert.equal(entry.downloadIdentityVerified, false);
  assert.match(entry.title, /^来源样本：/); assert.match(entry.message, /尚未核验实际下载文件/);
  assert.equal(entry.sha256, hash);
  assert.equal(f.notifications.length, 1); assert.match(f.notifications[0][0], /^来源样本：/);
  for (const msg of f.messages.filter(m => /show-page-threat-toast|arm-page-download-guard/.test(m.type))) {
    assert.match(msg.title, /^来源样本：/); assert.match(msg.message, /尚未核验实际下载文件/);
  }
  const g = fixture(); g.start(true); await tick();
  g.tasks[0].opts.onPartial({ stage: "vt", report: report(false) });
  assert.equal(g.releases.length, 0); assert.equal(g.NS._latestExeVtMem.status, "checking");
  g.tasks[0].resolve(report(true)); await tick();
  assert.equal(g.releases.length, 0); assert.equal(g.NS._latestExeVtMem.status, "blocked");
  assert.match(g.store.latestNotice.title, /^来源样本：/);
  const clean = fixture(); clean.start(true); await tick();
  clean.tasks[0].opts.onPartial({ stage: "vt", report: report(false) });
  assert.equal(clean.releases.length, 0);
  clean.tasks[0].resolve(report(false)); await tick();
  assert.equal(clean.releases.length, 1);
  assert.equal(clean.store.latestExeVt.sampleOnly, true);

  // Legacy reports with an actual downloadId/releasedDownloadId are still URL samples.
  for (const gated of [false, true]) {
    const legacy = fixture();
    legacy.store.latestExeVt_1 = { ...report(false), url, pageUrl: page, downloadId: 1,
      releasedDownloadId: gated ? 101 : null, gated, tabId: 1, status: "done", title: "检测完成" };
    const refreshed = await legacy.NS.refreshStoredVirusTotalDetails(hash, 1);
    assert.equal(refreshed.success, true);
    assert.equal(legacy.deletions.length, 0); assert.equal(legacy.cancellations.length, 0);
    assert.equal(legacy.store.latestExeVt_1.sampleOnly, true);
    assert.match(legacy.store.latestExeVt_1.title, /^来源样本：/);
  }
  const tree = render(clean.store.latestExeVt_1);
  assert.match(tree.textContent, /来源样本 SHA256/); assert.match(tree.textContent, /尚未核验实际下载文件/);
  const statusRow = tree.children.find(n => n.textContent.startsWith("文件检测:"));
  assert.ok(statusRow); assert.equal(statusRow.children.some(n => n.className === "vt-ok"), false);
  console.log("PASS: partial/final/refresh never delete unbound files; no partial release; sample scope consistent in popup/notices");
}
main().catch(e => { console.error(e); process.exitCode = 1; });
