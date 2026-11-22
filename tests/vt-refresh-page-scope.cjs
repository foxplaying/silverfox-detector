"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const page = "https://example.test/download", url = "https://cdn.example.test/Setup.exe", hash = "a".repeat(64);
const report = (hard = false) => ({ success: true, kind: "pe", sha256: hash, nested: [],
  pe: { isPe: true, signed: true }, signature: { trust: "present" },
  vt: { found: true, hash, statsPolicyVersion: 4, trustedPolicyVersion: 4, malicious: hard ? 20 : 0,
    suspicious: 0, total: 70, engineDetailsAvailable: true, trustedScoreHardBlock: hard,
    trustedScore: hard ? 8 : 0, trustedEngineCount: hard ? 3 : 0 } });

function fixture() {
  const store = {}, pageMessages = [], protectedTabs = [], contentActions = [], removals = [];
  const location = new URL(page);
  const hookMessages = [], hookActions = [];
  let hookReceive, hookTimer = 0;
  const hooksWindow = { addEventListener(_type, fn) { hookReceive = fn; },
    __silverfoxNavApi: { setOfficialSafe(value) { hookActions.push({ action: "official", value }); },
      setGuard(value) { hookActions.push({ action: "guard", value }); } } };
  // Exercise the actual MAIN bridge, starting with an already trusted light
  // page. Its officialSafe shortcut used to swallow the first guard arm.
  const hooksPolicy = { officialSafe: true, lightPage: true, guardEnabled: false,
    forceDesktopDlKit: false, blockedHops: new Set(), syncNavBoot() {} };
  const hookSource = read("extension/page-hooks/index.js");
  const hookFirst = hookSource.indexOf("    _installContentBridge() {");
  const hookLast = hookSource.indexOf("\n  NS.PageHooks =", hookFirst);
  assert.ok(hookFirst >= 0 && hookLast > hookFirst);
  vm.runInNewContext(`class Fixture { ${hookSource.slice(hookFirst, hookLast)}
    const hooks = new Fixture(); hooks.policy = policy; hooks.restoreList = []; hooks._installContentBridge();`, {
    policy: hooksPolicy, window: hooksWindow, NS: {}, CONTENT_SOURCE: "fixture-content", document: {},
    DomGuard: { restoreNativeDomProtos() {}, restoreNeutralizedFrames() {}, restoreFetchInspection() {},
      enableFetchInspection() { hookActions.push({ action: "fetch-guard" }); },
      scrubHostileLoadingOverlaysMain() {}, scrubDesktopForceDownloadDom() {} },
    DownloadUi: { restoreAllDownloadButtonsInPage() {}, disableAllDownloadButtonsInPage() {} },
    setTimeout() { return ++hookTimer; }, clearTimeout() {}
  });
  let receive;
  const content = { caches: {}, state: { _analysisTxn: "original" }, isTopFrame: () => true,
    showPageToast: (...args) => contentActions.push({ action: "toast", args }),
    installDownloadGuard(...args) {
      content.postToHooks({ type: "set-guard", enabled: true });
      contentActions.push({ action: "guard", args, mainGuardAccepted: hooksPolicy.guardEnabled });
    },
    disableAllDownloadIntentControls() {},
    postToHooks(message) {
      hookMessages.push(message);
      hookReceive({ source: hooksWindow, data: { source: "fixture-content", ...message } });
    }, addSignal() {}, emitRiskReport() {} };
  const lifecycle = read("extension/content/lifecycle.js");
  const first = lifecycle.indexOf("  NS.installPageNavigationWatchers =");
  const last = lifecycle.indexOf("  NS.installParentGuardInheritance =", first);
  assert.ok(first >= 0 && last > first);
  vm.runInNewContext(lifecycle.slice(first, last), {
    NS: content, location, history: {}, window: { addEventListener() {} }, setInterval() {},
    chrome: { runtime: { onMessage: { addListener(fn) { receive = fn; } } } }
  });
  content.installPageNavigationWatchers();

  const NS = { tabNavState: new Map([[1, { lastGoodUrl: page }]]),
    _activeRiskTxnByTab: new Map([[1, { url: page, analysisTxn: "original" }]]),
    _riskNavigationSeqByTab: new Map([[1, 7]]),
    markTabProtected(...args) { protectedTabs.push(args); } };
  const chrome = { runtime: { sendMessage(_msg, cb) { cb?.(); } },
    tabs: { sendMessage(tabId, msg, _options, cb) {
      let reply;
      receive(msg, {}, value => { reply = value; });
      pageMessages.push({ tabId, msg, reply }); cb?.();
    } },
    downloads: { removeFile(id, cb) { removals.push(id); cb?.(); }, cancel(id, cb) { removals.push(id); cb?.(); } },
    storage: { local: { get(_keys, cb) { cb(store); }, set(values, cb) { Object.assign(store, values); cb?.(); } } }
  };
  vm.runInNewContext(read("extension/background/pe-vt-bg.js"), {
    self: { SilverfoxBackground: NS }, chrome, URL, Map, setTimeout, clearTimeout,
    crypto: require("node:crypto").webcrypto, console: { log() {}, warn() {} }
  });
  NS.inspectPackageUrl = async () => report(false);
  NS.lookupVirusTotalHash = async () => report(true).vt;
  async function start() {
    NS.probeDownloadExecutableAsync({ id: 1, tabId: 1, url, filename: "Setup.exe" }, { gate: false });
    for (let i = 0; i < 20 && store.latestExeVt_1?.status !== "done"; i++) await tick();
    assert.equal(store.latestExeVt_1.status, "done");
  }
  return { NS, content, location, start, store, pageMessages, protectedTabs, contentActions, removals,
    hooksPolicy, hookMessages, hookActions };
}

async function main() {
  const live = fixture(); await live.start();
  assert.equal(live.store.latestExeVt_1.sourceAnalysisTxn, "original");
  assert.equal(live.store.latestExeVt_1.sourcePageUrl, page);
  assert.equal(live.store.latestExeVt_1.sourceNavigationSeq, 7);
  assert.equal((await live.NS.refreshStoredVirusTotalDetails(hash, 1)).success, true);
  assert.equal(live.contentActions.filter(a => a.action === "guard").length, 1);
  assert.equal(live.contentActions.find(a => a.action === "guard").mainGuardAccepted, true,
    "first arm from installDownloadGuard must not be swallowed by officialSafe");
  assert.equal(live.hooksPolicy.officialSafe, false); assert.equal(live.hooksPolicy.guardEnabled, true);
  assert.equal(live.hookMessages[0].type, "set-official-safe"); assert.equal(live.hookMessages[0].enabled, false);
  assert.equal(live.hookActions.some(a => a.action === "fetch-guard"), true);
  assert.equal(live.contentActions.filter(a => a.action === "toast").length, 1);
  assert.equal(live.protectedTabs.length, 1);
  for (const { msg, reply } of live.pageMessages) {
    assert.equal(msg.sourceAnalysisTxn, "original"); assert.equal(msg.sourcePageUrl, page);
    assert.equal(reply.ok, true); assert.equal(reply.skipped, undefined);
  }
  assert.equal(live.store.latestExeVt_1.sampleOnly, true);
  assert.equal(live.store.latestExeVt_1.downloadIdentityVerified, false);
  assert.equal(live.store.latestExeVt_1.sourceNavigationSeq, 7);
  assert.equal((await live.NS.refreshStoredVirusTotalDetails(hash, 1)).success, true);
  assert.equal(live.contentActions.filter(a => a.action === "guard").length, 1, "same consensus must not rearm repeatedly");
  assert.equal(live.removals.length, 0);
  console.log("PASS: VT refresh preserves source transaction, revokes MAIN officialSafe before first arm, and enables content/background protection once");

  for (const change of [
    f => { f.NS._activeRiskTxnByTab.set(1, { url: page, analysisTxn: "reloaded" }); f.content.state._analysisTxn = "reloaded"; },
    f => { f.NS._riskNavigationSeqByTab.set(1, 8); },
    f => { f.NS._activeRiskTxnByTab.set(1, { url: "https://other.example/", analysisTxn: "new" }); f.location.href = "https://other.example/"; },
    f => { f.NS._activeRiskTxnByTab.clear(); }
  ]) {
    const f = fixture(); await f.start();
    let finish;
    f.NS.lookupVirusTotalHash = () => new Promise(resolve => { finish = resolve; });
    const pending = f.NS.refreshStoredVirusTotalDetails(hash, 1);
    await tick(); change(f); finish(report(true).vt);
    assert.equal((await pending).success, true);
    assert.equal(f.store.latestExeVt_1.vt.malicious, 20);
    assert.equal(f.store.latestExeVt_1.sourceAnalysisTxn, "original", "refresh must not manufacture the current page identity");
    assert.equal(f.store.latestExeVt_1.sourcePageUrl, page);
    assert.equal(f.pageMessages.length, 0); assert.equal(f.protectedTabs.length, 0); assert.equal(f.removals.length, 0);
  }
  console.log("PASS: same-URL reload, changed navigation, different URL and missing live transaction cannot receive old refresh effects");

  const legacy = fixture(); await legacy.start();
  for (const name of ["sourceAnalysisTxn", "sourcePageUrl", "sourceNavigationSeq"]) delete legacy.store.latestExeVt_1[name];
  assert.equal((await legacy.NS.refreshStoredVirusTotalDetails(hash, 1)).success, true);
  assert.equal(legacy.store.latestExeVt_1.vt.malicious, 20);
  assert.equal(legacy.pageMessages.length, 0); assert.equal(legacy.protectedTabs.length, 0);
  assert.equal(legacy.store.latestExeVt_1.sourceAnalysisTxn, "");

  const foreign = fixture(); await foreign.start();
  foreign.store.latestExeVt.tabId = 2; delete foreign.store.latestExeVt_1;
  const foreignResult = await foreign.NS.refreshStoredVirusTotalDetails(hash, 1);
  assert.equal(foreignResult.success, false); assert.equal(foreignResult.error, "stale-report");
  assert.equal(foreign.pageMessages.length, 0); assert.equal(foreign.store.latestExeVt_1, undefined);
  console.log("PASS: unbound legacy reports update file evidence only; another tab's global record is never retargeted");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
