"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const page = "https://example.test/download", url = "https://cdn.example.test/Setup.exe";
const hash = "a".repeat(64), innerHash = "b".repeat(64);
const vt = hash => ({ found: true, hash, statsPolicyVersion: 4, trustedPolicyVersion: 4,
  malicious: 0, suspicious: 0, total: 70, sigTrustFromVt: "valid", signerFromVt: "Example Ltd" });
const report = () => ({ success: true, kind: "pe", sha256: hash, nested: [],
  pe: { isPe: true, signed: true }, signature: { trust: "present" }, vt: vt(hash) });

function fixture() {
  const store = {}, messages = [], grants = [], revokes = [], replay = [], callbacks = [];
  const NS = { tabNavState: new Map([[1, { lastGoodUrl: page }]]) };
  const chrome = { runtime: { sendMessage(msg, cb) { messages.push(msg); cb?.(); } },
    storage: { local: { get(_keys, cb) { cb(structuredClone(store)); },
      set(data, cb) { Object.assign(store, structuredClone(data)); cb?.(); } } },
    downloads: { download(opts, cb) { replay.push(opts); callbacks.push(cb); } } };
  vm.runInNewContext(read("extension/background/pe-vt-bg.js"), {
    self: { SilverfoxBackground: NS }, chrome, URL, Map, setTimeout, clearTimeout,
    console: { log() {}, warn() {} }, crypto: require("node:crypto").webcrypto
  });
  NS.inspectPackageUrl = async () => report();
  NS.lookupVirusTotalHash = async hash => vt(hash);
  NS.grantVtPassUrl = (...args) => grants.push(args);
  NS.revokeVtPassUrl = (...args) => revokes.push(args);
  const start = (id = 1) => NS.probeDownloadExecutableAsync({ id, tabId: 1, url, filename: "Setup.exe" }, { gate: true });
  return { NS, chrome, store, messages, grants, revokes, replay, callbacks, start };
}

function cancellation(fails) {
  const source = read("extension/background/background.js");
  const first = source.indexOf("      if (protectedTab && !verdict.trustedSource && isPkg");
  const last = source.indexOf("      if (isPkg)", first);
  assert.ok(first >= 0 && last > first);
  const actions = [];
  const chrome = { runtime: {}, downloads: {
    cancel(_id, cb) { actions.push("cancel"); if (fails) chrome.runtime.lastError = { message: "already complete" }; cb(); delete chrome.runtime.lastError; },
    erase(_query, cb) { actions.push("erase"); cb(); }
  } };
  vm.runInNewContext(`(function () { ${source.slice(first, last)} })();`, {
    chrome, protectedTab: true, verdict: { trustedSource: false }, isPkg: true, dlUrl: url,
    item: { id: 1 }, tabId: 1, markHandled() {}, console: { warn() {} },
    NS: { safeSetBadge() { actions.push("badge"); }, probeDownloadExecutableAsync(_item, opts) { actions.push(opts); } }
  });
  assert.equal(actions.includes("erase"), !fails);
  assert.equal(actions.includes("badge"), !fails);
  assert.equal(actions.at(-1).gate, !fails);
  assert.equal(actions.at(-1).sourceTabId, 1);
}

async function main() {
  cancellation(true); cancellation(false);
  console.log("PASS: failed cancellation preserves original history and never gates/replays it; successful cancellation still gates");

  for (const outcome of ["error", "missing-id", "throw", "missing-api", "success"]) {
    const f = fixture();
    if (outcome === "throw") f.chrome.downloads.download = () => { throw new Error("API failure"); };
    if (outcome === "missing-api") delete f.chrome.downloads.download;
    f.start(); await tick();
    if (f.callbacks.length) {
      assert.equal(f.store.latestExeVt_1.status, "checking", "do not claim allowed before the browser accepts a replay");
      if (outcome === "error") f.chrome.runtime.lastError = { message: "network error" };
      f.callbacks[0](outcome === "success" ? 101 : undefined);
      delete f.chrome.runtime.lastError;
    }
    await tick();
    const entry = f.store.latestExeVt_1;
    assert.equal(entry.status, outcome === "success" ? "allowed" : "error");
    assert.equal(entry.allowed, outcome === "success");
    assert.equal(entry.success, outcome === "success");
    assert.equal(entry.releasedDownloadId, outcome === "success" ? 101 : null);
    assert.equal(f.revokes.length, outcome === "success" ? 0 : 1);
    assert.equal(f.messages.filter(m => m.type === "exe-vt-result").at(-1).vtInfo.status, entry.status);
    if (outcome !== "success") assert.match(entry.message, /请手动重试下载/);
  }
  console.log("PASS: asynchronous callback errors, missing IDs/APIs and synchronous throws report replay failure; success alone reports allowed");

  for (const sample of [null, { ...report(), responseMismatch: true, error: "different response" },
    { success: false, partialScan: true, kind: "archive", archiveNote: "too large", nested: [] }]) {
    const f = fixture(); f.NS.inspectPackageUrl = async () => sample;
    f.start(); await tick(); assert.equal(f.callbacks.length, 1);
    f.chrome.runtime.lastError = { message: "cannot restart" };
    f.callbacks[0](); delete f.chrome.runtime.lastError; await tick();
    assert.equal(f.store.latestExeVt_1.status, "error");
    assert.equal(f.store.latestExeVt_1.allowed, false);
    assert.match(f.store.latestExeVt_1.message, /请手动重试下载/);
  }
  console.log("PASS: timeout, mismatched responses and oversized unscanned files cannot hide replay failures");

  const raced = fixture(); raced.start(1); await tick(); raced.start(2); await tick();
  raced.callbacks[1](102); await tick();
  raced.chrome.runtime.lastError = { message: "old failure" }; raced.callbacks[0](); delete raced.chrome.runtime.lastError;
  await tick();
  assert.equal(raced.store.latestExeVt_1.downloadId, 2);
  assert.equal(raced.store.latestExeVt_1.status, "allowed");
  assert.equal(raced.store.latestExeVt_1.releasedDownloadId, 102);
  console.log("PASS: late replay failure cannot overwrite a newer successful download");

  const nestedReport = () => ({ sha256: hash, tabId: 1, pageUrl: page, url, status: "done",
    timestamp: 1, downloadId: 1, probeId: "original", nested: [{ name: "inner.exe", kind: "pe",
      sha256: innerHash, signed: true, sigTrust: "present" }] });
  const foreign = fixture(); foreign.store.latestExeVt = { ...nestedReport(), tabId: 2 };
  const rejected = await foreign.NS.refreshStoredNestedSignatures(hash, 1);
  assert.equal(rejected.error, "stale-report"); assert.equal(foreign.store.latestExeVt_1, undefined);
  assert.equal(foreign.messages.length, 0);

  const valid = fixture(); valid.store.latestExeVt_1 = nestedReport();
  assert.equal((await valid.NS.refreshStoredNestedSignatures(hash, 1)).success, true);
  assert.equal(valid.store.latestExeVt_1.nested[0].sigTrust, "valid");
  assert.equal(valid.store.latestExeVt_1.tabId, 1);
  for (const mutate of [
    f => { f.store.latestExeVt_1 = { ...nestedReport(), downloadId: 2, probeId: "new-download", timestamp: 2 }; },
    f => { f.store.latestExeVt_1.message = "newer refresh"; },
    f => { f.store.latestExeVt = f.store.latestExeVt_1; delete f.store.latestExeVt_1; },
    f => { delete f.store.latestExeVt_1; f.store.latestExeVt = { ...nestedReport(), tabId: 2 }; },
    f => { f.NS._latestExeVtMem = { ...nestedReport(), probeId: "pending-storage-write" }; },
    f => { f.NS._vtProbeGenByTab.set(1, 2); }
  ]) {
    const f = fixture(); f.store.latestExeVt_1 = { ...nestedReport(), probeGen: 1 };
    f.NS._vtProbeGenByTab.set(1, 1);
    let finish;
    f.NS.lookupVirusTotalHash = () => new Promise(resolve => { finish = resolve; });
    const pending = f.NS.refreshStoredNestedSignatures(hash, 1); await tick();
    assert.equal(typeof finish, "function"); mutate(f);
    const snapshot = JSON.stringify(f.store);
    finish(vt(innerHash));
    assert.equal((await pending).error, "stale-report");
    assert.equal(JSON.stringify(f.store), snapshot); assert.equal(f.messages.length, 0);
  }
  console.log("PASS: nested signature refresh respects tab ownership, report revisions, same-hash new downloads and generation invalidation");

  for (const releasedDownloadId of [null, 101]) {
    const f = fixture();
    f.store.latestExeVt_1 = { ...nestedReport(), status: "blocked", title: "VT blocked",
      vt: { trustedPolicyVersion: 1 }, gated: true, allowed: false, releasedDownloadId };
    const result = await f.NS.refreshStoredVirusTotalDetails(hash, 1);
    assert.equal(result.success, true);
    const record = f.store.latestExeVt_1;
    assert.equal(record.status, releasedDownloadId == null ? "done" : "allowed");
    assert.equal(record.allowed, releasedDownloadId != null);
    if (!releasedDownloadId) assert.match(record.title, /未恢复/);
    assert.equal(f.replay.length, 0, "a refresh is read-only with respect to the browser download");
  }
  const concurrent = fixture();
  concurrent.store.latestExeVt_1 = nestedReport();
  let finishOuter;
  concurrent.NS.lookupVirusTotalHash = async h => h === hash
    ? new Promise(resolve => { finishOuter = resolve; }) : vt(h);
  const outer = concurrent.NS.refreshStoredVirusTotalDetails(hash, 1);
  await tick();
  assert.equal((await concurrent.NS.refreshStoredNestedSignatures(hash, 1)).updated, true);
  finishOuter(vt(hash));
  assert.equal((await outer).error, "stale-report");
  assert.equal(concurrent.store.latestExeVt_1.nested[0].sigTrust, "valid");
  console.log("PASS: outer VT refresh preserves nested updates and cannot claim an unreleased download was restored");

  for (const direction of ["outer", "nested"]) {
    const f = fixture();
    const high = { ...vt(innerHash), malicious: 12 };
    f.store.latestExeVt_1 = { ...nestedReport(), kind: "archive", filename: "sample.zip",
      status: direction === "outer" ? "flagged" : "done", allowed: direction !== "outer",
      title: direction === "outer" ? "VT archive warning" : "clean",
      vt: { ...vt(hash), trustedPolicyVersion: direction === "outer" ? 1 : 4 },
      nested: [{ ...nestedReport().nested[0], vt: direction === "outer" ? high : null }] };
    f.NS.lookupVirusTotalHash = async h => h === hash ? vt(hash) : high;
    const result = direction === "outer" ? await f.NS.refreshStoredVirusTotalDetails(hash, 1)
      : await f.NS.refreshStoredNestedSignatures(hash, 1);
    assert.equal(result.updated, true);
    const r = f.store.latestExeVt_1;
    assert.equal(r.allowed, false); assert.equal(r.status, "flagged"); assert.match(r.title, /inner\.exe/);
    assert.equal(r.nestedVtPrimary.sha256, innerHash);
    assert.equal(r.nested[0].vt.malicious, 12); assert.equal(r.vt.malicious, 0);
    assert.equal(f.replay.length, 0);
  }
  console.log("PASS: outer clean never masks high nested detections, including newly refreshed members");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
