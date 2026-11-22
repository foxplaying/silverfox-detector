"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const read = file => fs.readFileSync(path.join(__dirname, "../extension", file), "utf8");
const ctx = vm.createContext({ self: {}, URL, module: { exports: {} }, document: { addEventListener() {} } });
for (const f of ["shared/ssl-evidence.js", "shared/risk-report.js", "background/message-handler-bg.js", "popup/popup.js"]) vm.runInContext(read(f), ctx);
const url = "https://www.dingtalk-dl.com/downloads";
const base = { url, tabId: 1, timestamp: 500, analysisTxn: "page", analysisTxnStartedAt: 100,
  score: 0, riskLevel: "low", analysisComplete: false, details: [], brandFinalSnapshot: null };
const pending = { ...base, reportSequence: 1 };
const unknown = { ...pending, reportSequence: 2, identityVerificationUnavailable: true };
const risk = { ...base, analysisComplete: true, reportSequence: 3, score: 38, riskLevel: "high",
  downloadGuardInstalled: true, brandSpoofPortal: true, spoofBrand: "钉钉",
  brandFinalSnapshot: { url, analysisTxn: "page", final: true, brand: "钉钉" } };
const update = { ...base, reportSequence: 4 };
const orders = items => !items.length ? [[]] : items.flatMap((x, i) =>
  orders(items.filter((_, j) => i !== j)).map(rest => [x, ...rest]));
let checked = 0;
for (const trace of orders([pending, unknown, risk, update])) {
  const p = new ctx.module.exports.PopupRenderer({});
  p.activeTabId = 1;
  let stored, displayed;
  for (const msg of trace) {
    stored = ctx.self.SilverfoxBackground.mergeThreatRiskReport(stored, msg);
    displayed = p.coalesceReport(msg, url);
  }
  for (const result of [stored, displayed]) {
    assert.equal(result.analysisComplete, true, "older timeout/pending displaced confirmed verdict: " + trace.map(x=>x.reportSequence));
    assert.equal(result.brandFinalSnapshot?.brand, "钉钉", "partial report erased validated snapshot");
    assert.equal(result.downloadGuardInstalled, true);
  }
  const freshFailure = { ...unknown, reportSequence: 5 };
  assert.equal(p.coalesceReport(freshFailure, url).identityVerificationUnavailable, true);
  assert.equal(p.coalesceReport(risk, url).identityVerificationUnavailable, true, "late completion erased newer timeout");
  const reload = { ...pending, analysisTxn: "reload", analysisTxnStartedAt: 200 };
  assert.equal(p.coalesceReport(reload, url).analysisComplete, false);
  assert.equal(ctx.self.SilverfoxBackground.mergeThreatRiskReport(stored, reload).brandFinalSnapshot, null);
  checked++;
}
console.log("PASS: " + checked + " arrival orders agree in background and popup; current uncertainty and reload remain visible");

// Execute the background handler with independently delayed notice reads.
let handler, noticeRead, removals = 0;
const bg = ctx.self.SilverfoxBackground, store = {};
bg.safeSetBadge = () => {};
ctx.chrome = {runtime: {onMessage: {addListener(cb) { handler = cb; }}}, storage: {local: {
  get(keys, cb) { if (keys.includes("latestNotice")) noticeRead = cb; else cb(store); },
  set(obj, cb) { Object.assign(store, obj); cb?.(); }, remove(keys, cb) { removals++; cb?.(); }
}}};
bg.installMessageHandler();
const send = r => handler({ ...r, type:"threat-risk" }, { frameId:0, documentId:"doc", tab:{ id:1, url } }, () => {});
const clean = {...pending, analysisComplete:true, reportSequence:2};
send(clean);
assert.equal(typeof noticeRead, "function");
send(risk);
noticeRead({latestNotice:{url, analysisTxn:"page", timestamp:499, tabId:1}});
assert.equal(removals, 0, "stale clean callback deleted current threat notice");
noticeRead = null;
send(clean);
assert.equal(noticeRead, null, "late clean report scheduled a removal before being merged");
assert.equal(store.risk_1.brandFinalSnapshot.brand, "钉钉");
send({...clean, reportSequence:6, timestamp:550});
noticeRead({latestNotice:{url, analysisTxn:"page", timestamp:549, tabId:1}});
assert.equal(removals, 1, "genuinely newer clean verdict must still clear its own notice");
