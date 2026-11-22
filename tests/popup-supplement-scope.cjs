"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), assert = require("node:assert/strict");
const hash = "a".repeat(64), url = "https://site.test/page";
const timers = [], requests = [], store = { risk_latest: { tabId: 2, url, score: 88 } };
const chrome = { runtime: { sendMessage(m, cb) { requests.push({ m, cb }); } },
  storage: { local: { get(keys, cb) { cb(store); } } } };
const ctx = { chrome, URL, document: { addEventListener() {} }, module: {exports: {}},
  setTimeout(fn) { timers.push(fn); } };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../extension/popup/popup.js"), "utf8"), ctx);
const Popup = ctx.module.exports.PopupRenderer;
const p = new Popup({});
p.activeTabId = 1; p.activeTabUrl = url;
let rendered;
p.renderRisk = data => { rendered = data; };
p.refresh(url); assert.equal(rendered, null, "global risk from another tab must not render");
store.risk_latest.tabId = 1; p.refresh(url); assert.equal(rendered.score, 88);
delete store.risk_latest.tabId; p.refresh(url); assert.equal(rendered, null);
store.risk_1 = { url, score: 1 }; p.refresh(url); assert.equal(rendered.score, 1);
const sample = { downloadId: 3, sha256: hash, vt: { found: true, hash, malicious: 2, statsPolicyVersion: 4 } };
p.refresh = () => p.maybeRefreshVtEngineDetails(sample);
p.refresh(); p.refresh(); assert.equal(requests.length, 1);
requests[0].cb({success:false, error:"stale-report"});
p.refresh(); assert.equal(requests.length, 1); timers.shift()(); assert.equal(requests.length, 2);
requests[1].cb({success:false}); timers.shift()(); assert.equal(requests.length, 3);
requests[2].cb({success:false}); p.refresh(); assert.equal(requests.length, 3); assert.equal(timers.length, 0);
sample.downloadId++; p.refresh(); assert.equal(requests.length, 4, "new transaction at same SHA gets its own budget");
requests[3].cb({success:false}); p.activeTabId = 2; timers.shift()(); assert.equal(requests.length, 4);
console.log("PASS: tab-owned risk fallback and bounded, transaction-scoped VT retries");
