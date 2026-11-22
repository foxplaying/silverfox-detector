"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
let receive; const store = {}, ids = new Map(), pauses = [];
const chrome = { runtime: { getURL: p => p, onMessage: { addListener(fn) { receive = fn; } } },
  notifications: { getAll() { throw new Error("no global cleanup from page"); },
    create(id, opts, cb) { ids.set(id, opts); cb(); }, clear(id, cb) { ids.delete(id); cb(); } },
  storage: { local: { get(_keys, cb) { cb(structuredClone(store)); }, set(data, cb) { Object.assign(store, data); cb?.(); },
    remove(keys, cb) { for (const key of keys) delete store[key]; cb?.(); } } } };
const NS = { protectedTabs: new Set([1]), protectedTabMeta: new Map() };
const ctx = vm.createContext({ self: { SilverfoxBackground: NS }, chrome, URL, Map, console });
for (const f of ["notification-bg", "nav-protection-bg", "message-handler-bg"]) {
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/background", f + ".js"), "utf8"), ctx);
}
Object.assign(NS, { withExistingTab() {}, disarmHostileNavDnr() {}, isOnProtectedOrigin: () => false,
  isTabProtected: id => NS.protectedTabs.has(id), pauseNavBlocking: id => pauses.push(id) });
NS.installMessageHandler();
const url = "https://current.example/";
const send = (type, fields = {}) => new Promise(resolve => receive({ type, url, analysisTxn: "current",
  ...fields }, { frameId: 0, documentId: "doc", tab: { id: 1, url } }, resolve));
(async () => {
  for (const type of ["page-analysis-reset", "set-tab-protect"]) {
    assert.equal((await send(type, { url: "https://old.example/", force: true })).ignored, "stale-analysis-transaction");
    assert.equal(NS._activeRiskTxnByTab.size, 0); assert.deepEqual(pauses, []); assert.deepEqual(store, {});
  }
  await send("page-analysis-reset"); await send("set-tab-protect", { enabled: false, force: true });
  assert.equal(store.risk_1.analysisTxn, "current"); assert.equal(NS.protectedTabs.size, 0);
  for (const tab of [1, 2]) for (const kind of ["brand-spoof", "page-threat"]) {
    await NS.showBlockedNotification(kind, String(tab), tab, true, {channelKey: kind + ":" + tab, versionToken: "v1"});
  }
  await NS.showBlockedNotification("file", "report.exe", 1, true);
  assert.equal(ids.size, 5); await send("clear-threat-notice");
  assert.equal(ids.size, 3);
  assert.ok(ids.has(NS.notificationIdFromKey("brand-spoof:2")));
  assert.ok(ids.has(NS.notificationIdFromKey("page-threat:2")));
  assert.ok(ids.has(NS.notificationIdFromKey(NS.contentNoticeKey("file", "report.exe"))));
  console.log("PASS: cold stale reset/protect-off ignored; accepted reset retained; page clears only its own channels");
})().catch(e => { console.error(e); process.exitCode = 1; });
