"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const slice = (file, first, last) => { const s = read(file); const a = s.indexOf(first); const b = s.indexOf(last, a + first.length); assert.ok(a >= 0 && b > a); return s.slice(a, b); };
const tick = () => new Promise((r) => setImmediate(r));

async function main() {
  // Repeated locking must write src only once, then restore original sandbox/source.
  let now = 1000, writes = 0;
  const attrs = new Map([["src", "https://example.test/frame"], ["sandbox", "allow-scripts"]]);
  const styles = new Map();
  const frame = { tagName: "IFRAME", isConnected: true,
    getAttribute: (k) => attrs.has(k) ? attrs.get(k) : null, hasAttribute: (k) => attrs.has(k),
    setAttribute(k, v) { if (k === "src") writes++; attrs.set(k, v); }, removeAttribute(k) { attrs.delete(k); },
    style: { getPropertyValue: (k) => styles.get(k)?.value || "", getPropertyPriority: (k) => styles.get(k)?.priority || "",
      setProperty: (k, value, priority) => styles.set(k, { value, priority }), removeProperty: (k) => styles.delete(k) }
  };
  const stateNS = { isTopFrame: () => true, caches: {} };
  vm.runInNewContext(slice("extension/content/state.js", "  const lockedFrames", "  NS.addSignal"), {
    NS: stateNS, document: { querySelectorAll: () => [frame] }, Date: { now: () => now }
  });
  stateNS.neutralizePageFramesForGuard(true); assert.equal(writes, 1);
  now += 1000; stateNS.neutralizePageFramesForGuard(true); assert.equal(writes, 1);
  stateNS.neutralizePageFramesForGuard(false);
  assert.equal(attrs.get("src"), "https://example.test/frame"); assert.equal(attrs.get("sandbox"), "allow-scripts");
  assert.equal(styles.size, 0);
  console.log("PASS: iframe locking is idempotent and reversible");

  // The offscreen watchdog must terminate the worker, not just abandon its promise.
  let handler, watchdog, terminated = 0, answered = 0;
  class Worker { addEventListener() {} postMessage() {} terminate() { terminated++; } }
  vm.runInNewContext(read("extension/offscreen/archive.js"), { Worker,
    setTimeout: (fn) => { watchdog = fn; return 1; }, clearTimeout() {},
    chrome: { runtime: { getURL: (p) => p, onMessage: { addListener(fn) { handler = fn; } } } }
  });
  handler({ target: "archive-offscreen", type: "silverfox-archive-extract", taskId: "fixture" }, {}, (r) => {
    answered++; assert.equal(r.error, "archive-worker-timeout");
  });
  watchdog(); watchdog(); assert.equal(terminated, 1); assert.equal(answered, 1);
  console.log("PASS: timed-out archive worker actually terminates, responds once");

  let timeout, reply, sends = 0;
  const probeNS = { caches: { probeCache: new Map() } };
  vm.runInNewContext(slice("extension/content/intel-network.js", "  const downloadProbeInflight", "  // --- ICP"), {
    NS: probeNS, URL, location: { href: "https://example.test" },
    setTimeout: (fn) => { timeout = fn; return 1; }, clearTimeout() {},
    chrome: { runtime: { sendMessage(_msg, cb) { sends++; reply = cb; } } }
  });
  const probe = probeNS.probeDownloadBehavior("/download?id=1");
  const again = probeNS.probeDownloadBehavior("/download?id=1");
  assert.equal(probe, again); assert.equal(sends, 1);
  timeout(); assert.equal((await probe).isDownload, null); assert.equal(probeNS.caches.probeCache.size, 0);
  reply({ success: true, isDownload: false }); assert.equal(probeNS.caches.probeCache.size, 0);
  const retry = probeNS.probeDownloadBehavior("/download?id=1");
  reply({ success: true, isDownload: true }); await retry;
  await probeNS.probeDownloadBehavior("/download?id=1"); assert.equal(sends, 2);
  console.log("PASS: bounded click probe, shared work, no negative cache on failure");

  let requests = 0, probeReply;
  const probeDone = new Promise((resolve) => { probeReply = resolve; });
  const bgContext = { NS: { isAllowedFetchUrl: () => true }, URL, AbortController,
    setTimeout: (fn) => setTimeout(fn, 10), clearTimeout,
    fetch: (_url, opts) => { requests++; return new Promise((_resolve, reject) => {
      opts.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    }); } };
  vm.runInNewContext(slice("extension/background/message-handler-bg.js", "  function handleProbeDownloadBehavior", "  function canonicalReportUrl")
    + "\nthis.probe = handleProbeDownloadBehavior;", bgContext);
  bgContext.probe({ url: "https://example.test/download?id=1" }, probeReply);
  const bounded = await probeDone;
  assert.equal(bounded.success, false); assert.equal(bounded.isDownload, null); assert.equal(requests, 1);
  console.log("PASS: background probe aborts stalled request without another GET");

  // Full production background module: two downloads in one tab must both finish.
  const tasks = [], released = [], messages = [], protectedTabs = [], storage = {};
  const page = "https://example.test/download", url = "https://cdn.example.test/Setup.exe";
  const NS = { tabNavState: new Map([[1, { lastGoodUrl: page }]]),
    _activeRiskTxnByTab: new Map([[1, { analysisTxn: "original", url: page }]]),
    _riskNavigationSeqByTab: new Map([[1, 1]]), markTabProtected: (...args) => protectedTabs.push(args) };
  const chrome = { runtime: { sendMessage(_m, cb) { cb?.(); } },
    tabs: { sendMessage(_id, msg, _opts, cb) { messages.push(msg); cb?.(); } },
    downloads: { download(opts, cb) { released.push(opts); cb(100 + released.length); } },
    storage: { local: { get(keys, cb) { cb(storage); }, set(data, cb) { Object.assign(storage, data); cb?.(); }, remove(keys, cb) { for (const key of keys) delete storage[key]; cb?.(); } } }
  };
  const context = vm.createContext({ self: { SilverfoxBackground: NS }, chrome, URL, Map, setTimeout, clearTimeout, console,
    crypto: require("node:crypto").webcrypto });
  vm.runInContext(read("extension/background/pe-vt-bg.js"), context);
  NS.inspectPackageUrl = () => new Promise((resolve) => tasks.push(resolve));
  const start = (id) => NS.probeDownloadExecutableAsync({ id, tabId: 1, url, filename: "Setup.exe" }, { gate: true });
  const result = (char, hard = false) => ({ success: true, kind: "pe", sha256: char.repeat(64), nested: [],
    pe: { isPe: true, signed: true }, signature: { trust: "present" },
    vt: { found: true, hash: char.repeat(64), statsPolicyVersion: 4, trustedPolicyVersion: 4,
      malicious: hard ? 20 : 0, suspicious: 0, total: 70, engineDetailsAvailable: true,
      trustedScoreHardBlock: hard, trustedScore: hard ? 8 : 0, trustedEngineCount: hard ? 3 : 0 } });
  start(1); start(2); await tick(); assert.equal(tasks.length, 2);
  tasks[1](result("b")); await tick(); tasks[0](result("a")); await tick();
  assert.equal(released.length, 2);
  assert.equal(NS._latestExeVtMem.sha256, "b".repeat(64));
  assert.equal(NS._latestExeVtMem.downloadId, 2);
  console.log("PASS: newer download suppresses stale UI, not earlier download completion");

  start(3); await tick();
  NS._activeRiskTxnByTab.set(1, { analysisTxn: "new-document", url: page });
  tasks[2](result("c", true)); await tick();
  assert.equal(messages.filter((m) => m.type === "arm-page-download-guard").length, 0);
  assert.equal(protectedTabs.length, 0);
  start(4); await tick(); tasks[3](result("d", true)); await tick();
  assert.equal(messages.filter((m) => m.type === "arm-page-download-guard").length, 1);
  assert.equal(protectedTabs.length, 1);
  NS._latestExeVtMem = { tabId: 2, pageUrl: "https://other.test" };
  const previous = NS._vtProbeGenByTab.get(1);
  NS.clearLatestExeVtIfStaleForTab(1, "https://new.test");
  assert.equal(NS._vtProbeGenByTab.get(1), previous + 1);
  assert.equal(NS._latestExeVtMem.tabId, 2);
  console.log("PASS: old document cannot arm new page; invalidation independent of global latest file");

  const popupContext = { document: { addEventListener() {} }, module: { exports: {} }, URL, console };
  vm.runInNewContext(read("extension/popup/popup.js"), popupContext);
  const { PopupRenderer, popupVtHashMismatch } = popupContext.module.exports;
  assert.equal(popupVtHashMismatch(result("a")), false);
  assert.equal(popupVtHashMismatch({ ...result("a"), vt: { ...result("a").vt, statsPolicyVersion: 3 } }), true);
  const renderer = Object.create(PopupRenderer.prototype);
  renderer.activeTabUrl = page;
  assert.equal(renderer.sanitizeSpoofBrandName("在线修复主机", { confirmedIdentity: true }), "");
  const current = { url: page, analysisTxn: "new", spoofBrand: "Wrong", brandFinalSnapshot: {
    final: true, brand: "Steam", url: page, analysisTxn: "new" } };
  assert.equal(renderer.brandSpoofFromData(current), "Steam");
  assert.equal(renderer.brandSpoofFromData({ ...current, brandFinalSnapshot: null }), "");
  assert.equal(renderer.brandSpoofFromData({ ...current, analysisTxn: "stale" }), "");
  console.log("PASS: popup accepts current VT policy and final brand snapshot only");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
