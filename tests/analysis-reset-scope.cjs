"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync(path.join(__dirname, "../extension/background/message-handler-bg.js"), "utf8");

function fixture(active = { analysisTxn: "current", startedAt: 200, url: "https://current.example/", documentId: "current-doc" }) {
  let handler;
  const effects = [];
  const NS = {
    _activeRiskTxnByTab: new Map(active ? [[1, active]] : []),
    isTabProtected: () => true, isOnProtectedOrigin: () => false,
    pauseNavBlocking: () => effects.push("pause"), clearTabAnalysisState: () => effects.push("clear-analysis"),
    clearTabRiskStorage: () => effects.push("clear-storage")
  };
  const chrome = { runtime: { onMessage: { addListener(fn) { handler = fn; } } },
    storage: { local: { set(data, cb) { effects.push({ write: data }); cb?.(); } } } };
  vm.runInNewContext(source, { self: { SilverfoxBackground: NS }, chrome, URL, console });
  NS.installMessageHandler();
  const send = (fields, sender = {}) => {
    let reply;
    handler({ type: "page-analysis-reset", ...fields }, {
      tab: { id: 1, url: "https://current.example/" }, frameId: 0, documentId: "current-doc", ...sender
    }, data => { reply = data; });
    return reply;
  };
  return { NS, effects, send };
}

for (const [fields, sender] of [
  [{ url: "https://old.example/", analysisTxn: "old", analysisTxnStartedAt: 100 }, { documentId: "old-doc" }],
  [{ url: "https://current.example/", analysisTxn: "old", analysisTxnStartedAt: 100 }, { documentId: "old-doc" }],
  [{ url: "https://current.example/", analysisTxn: "current", analysisTxnStartedAt: 200 }, { documentId: "old-doc" }],
  [{ url: "https://old.example/" }, {}],
  [{ url: "https://current.example/" }, {}]
]) {
  const f = fixture();
  assert.equal(f.send(fields, sender).ignored, "stale-analysis-transaction");
  assert.equal(f.effects.length, 0, "rejected reset must not mutate storage, protection or navigation");
  assert.equal(f.NS._activeRiskTxnByTab.get(1).analysisTxn, "current");
  assert.equal(f.NS._riskReportSeqByTab, undefined);
}
const current = fixture();
assert.equal(current.send({ url: "https://current.example/", analysisTxn: "new", analysisTxnStartedAt: 300 }).success, true);
assert.equal(current.NS._activeRiskTxnByTab.get(1).analysisTxn, "new");
assert.equal(current.effects[0].write.risk_1.analysisTxn, "new");
assert.deepEqual(current.effects.slice(1), ["pause", "clear-analysis"]);
const subframe = fixture();
assert.equal(subframe.send({ analysisTxn: "new" }, { frameId: 2 }).ignored, "subframe");
assert.equal(subframe.effects.length, 0);
const legacyStale = fixture(null);
assert.equal(legacyStale.send({ url: "https://old.example/" }).ignored, "stale-analysis-transaction");
assert.equal(legacyStale.effects.length, 0);
const legacyCurrent = fixture(null);
assert.equal(legacyCurrent.send({ url: "https://current.example/" }).success, true);
assert.deepEqual(legacyCurrent.effects, ["clear-storage", "pause", "clear-analysis"]);
console.log("PASS: rejected/stale/legacy/subframe reset has no side effects; current reset still advances and clears old protection");
