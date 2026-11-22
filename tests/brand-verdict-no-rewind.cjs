"use strict";
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const read = file => fs.readFileSync(path.join(__dirname, "../extension", file), "utf8");
const location = new URL("https://www.dingtalk-dl.com/downloads");
const attrs = new Map([["href", "/download/windows"], ["title", "钉钉"]]);
const link = { tagName: "A", textContent: "下载", dataset: {},
  getAttribute: k => attrs.get(k) ?? null, setAttribute: (k,v) => attrs.set(k,v),
  removeAttribute: k => attrs.delete(k), set href(v) { attrs.set("href",v); },
  style: { getPropertyValue: () => "", getPropertyPriority: () => "", setProperty() {}, removeProperty() {} },
  addEventListener() {} };
const document = {
  title: "钉钉下载", querySelectorAll: () => [link],
  querySelector(selector) {
    for (const attr of ["href","data-threat-original-href"]) {
      if (selector.includes('a[' + attr + '*="download"]') && attrs.get(attr)?.includes("download")) return link;
    }
    return null;
  }
};
const snapshot = { final: true, brand: "钉钉", url: location.href, analysisTxn: "current",
  decisionGeneration: 5, noticeSequence: 1 };
const state = { _brandSpoofFinalPresented: true, _brandSpoofFinalSnapshot: snapshot, downloadGuardInstalled: true,
  _analysisDone: true, _analysisTxn: "current", spoofBrand: "钉钉",
  _brandSpoofDecisionGeneration: 5, _brandSpoofDecisionUrl: location.href };
const NS = { state, caches: {}, rotateAnalysisTransaction() { state._analysisTxn = "new"; } };
const ctx = vm.createContext({ window: { SilverfoxContent: NS }, location, document, queueMicrotask });
for (const file of ["shared/control-state.js","content/guard.js","content/brand-spoof-detector.js"]) vm.runInContext(read(file), ctx);
const fingerprint = NS.captureBrandElectionIdentityFingerprint();
assert.match(fingerprint, /钉钉.*download:1$/);
NS.nudgeBrandElectionAfterHydration("first");
Object.assign(NS, { ensureBrandElectionHydrationWatch() {}, isPureLatinSpoofBrand: () => false,
  isBrandSpoofIdentityVerificationSettled: () => true, canPresentSoftBrandSpoofNotice: () => true });
state._brandElectionIdentityFingerprintAt -= 1000;
for (let i = 0; i < 3; i++) {
  assert.equal(NS.commitBrandSpoofPresentation({ brand: "钉钉" }), "钉钉");
  assert.equal(NS.getCurrentBrandSpoofFinalSnapshot()?.decisionGeneration, 5, "a repeated scan invalidated the published snapshot");
  NS.disableOneSuspiciousElement(link, "/download/windows");
  assert.equal(link.getAttribute("title"), "已拦截可疑安装包下载");
  assert.equal(NS.captureBrandElectionIdentityFingerprint(), fingerprint);
  assert.equal(NS.nudgeBrandElectionAfterHydration("dom-hydration"), false);
  NS.reEnableOneThreatElement(link);
  assert.equal(NS.nudgeBrandElectionAfterHydration("popup-request"), false);
}
attrs.delete("href");
assert.equal(NS.nudgeBrandElectionAfterHydration("dom-hydration"), false);
assert.equal(state._brandSpoofFinalSnapshot, snapshot);
assert.equal(state._analysisTxn, "current"); assert.equal(state._analysisDone, true);
document.title = "不同软件的下载页";
assert.equal(NS.nudgeBrandElectionAfterHydration("dom-hydration"), true);
assert.equal(state._analysisTxn, "new"); assert.equal(state._brandSpoofFinalSnapshot, null);

const pop = { module: { exports: {} }, URL, document: { addEventListener() {} } };
vm.runInNewContext(read("popup/popup.js"), pop);
const p = new pop.module.exports.PopupRenderer({});
p.activeTabId = 1; p.activeTabUrl = location.href;
const report = { analysisTxn: "current", url: location.href, analysisTxnStartedAt: 20, analysisComplete: true };
p.coalesceReport(report, location.href);
p.clearRoot = () => assert.fail("stale storage response erased current verdict");
p.renderRisk({ ...report, analysisTxn: "old", analysisTxnStartedAt: 10, analysisComplete: false }, null, location.href);
assert.equal(p.coalesceReport({ ...report, analysisTxn: "new", analysisTxnStartedAt: 30, analysisComplete: false }, location.href).analysisComplete, false);
console.log("PASS: guard DOM writes and late storage reports preserve current verdict; real identity/navigation changes re-open analysis");
