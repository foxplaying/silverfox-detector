"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const src = fs.readFileSync(path.join(__dirname, "../extension/page-hooks/index.js"), "utf8");
const a = src.indexOf("    _installContentBridge() {"), b = src.indexOf("\n  NS.PageHooks =", a);
assert.ok(a >= 0 && b > a);
function fixture() {
  const tasks = [], observers = [], inspected = []; let receive, disabled = false, restores = 0, disables = 0;
  const policy = { guardEnabled: false, forceDesktopDlKit: false, officialSafe: false, syncNavBoot() {}, blockedHops: new Set() };
  const window = { addEventListener(_type, fn) { receive = fn; } };
  class MutationObserver {
    constructor(fn) { this.fn = fn; this.disconnected = false; observers.push(this); }
    observe() {} disconnect() { this.disconnected = true; }
  }
  vm.runInNewContext(`class Fixture { ${src.slice(a, b)}
    const hooks = new Fixture(); hooks.policy = policy; hooks._installContentBridge();`, {
    window, policy, CONTENT_SOURCE: "fixture", document: { documentElement: {},
      createTreeWalker(node) { let i = 0; return { nextNode: () => node.children?.[i++] || null }; } }, NS: {}, MutationObserver,
    DomGuard: { restoreNeutralizedFrames() {}, restoreFetchInspection() {}, enableFetchInspection() {},
      scrubHostileLoadingOverlaysMain() {}, scrubDesktopForceDownloadDom() {}, restoreNativeDomProtos() {} },
    DownloadUi: { isDownloadIntentText() { return true; }, greyOut(node) { inspected.push(node); },
      disableAllDownloadButtonsInPage() { disabled = true; disables++; },
      restoreAllDownloadButtonsInPage() { disabled = false; restores++; } },
    setTimeout(fn, ms) { const task = { fn, ms, cancelled: false }; tasks.push(task); return task; },
    clearTimeout(task) { task.cancelled = true; }
  });
  return { tasks, observers, policy, window, inspected, disabled: () => disabled, counts: () => [restores, disables],
    send(type, enabled) { receive({ source: window, data: { source: "fixture", type, enabled } }); },
    runAll() { for (const t of tasks.slice().sort((a, b) => a.ms - b.ms)) t.fn(); } // Include callbacks already queued before cancellation.
  };
}
for (const unlock of ["set-guard", "set-official-safe"]) {
  const f = fixture(); f.send("set-guard", true);
  const stale = f.tasks.slice(), oldObserver = f.observers[0];
  f.send(unlock, unlock === "set-official-safe");
  assert.equal(f.disabled(), false); assert.equal(f.policy.guardEnabled, false);
  const counts = f.counts();
  stale.forEach(t => { assert.equal(t.cancelled, true); t.fn(); }); oldObserver.fn();
  assert.deepEqual(f.counts(), counts, "cancelled arm timers and observer must never re-disable controls");
  f.runAll(); assert.equal(f.disabled(), false);
}
const armed = fixture(); armed.send("set-guard", false);
const staleRestore = armed.tasks.slice(); armed.send("set-guard", true);
const counts = armed.counts(); staleRestore.forEach(t => t.fn());
assert.deepEqual(armed.counts(), counts, "old unlock callbacks must not release a new guard");
armed.runAll(); assert.equal(armed.disabled(), true);

const renewed = fixture(); renewed.send("set-guard", true);
const oldTasks = renewed.tasks.slice(), oldObserver = renewed.observers[0];
renewed.send("set-guard", false); renewed.send("set-guard", true);
const latestObserver = renewed.window.__silverfoxGuardMo;
oldTasks.forEach(t => t.fn()); oldObserver.fn();
assert.equal(renewed.window.__silverfoxGuardMo, latestObserver);
assert.equal(latestObserver.disconnected, false, "old expiry must not disconnect a newly installed observer");
assert.equal(renewed.disabled(), true);
console.log("PASS: stale arm/unlock timers and observer callbacks cannot reverse newer guard state; current hard protection remains active");

const burst = fixture(); burst.send("set-guard", true);
const node = () => ({ nodeType: 1, isConnected: true, matches: () => true });
const root = node(); root.children = Array.from({length: 240}, node);
for (let i = 0; i < 60; i++) burst.observers[0].fn([{ addedNodes: [root] }]);
burst.send("set-guard", true); // repeated arm must not schedule another initial scan
assert.equal(burst.tasks.filter(t => t.ms === 32).length, 1);
assert.equal(burst.inspected.length, 0);
let seen = 0;
for (const task of burst.tasks) {
  if (task.ms !== 32) continue;
  task.fn(); assert.ok(burst.inspected.length - seen <= 96);
  seen = burst.inspected.length;
}
assert.equal(seen, 241); assert.equal(burst.counts()[1], 1);
console.log("PASS: mutation storms coalesce, keep dynamic controls disabled, and visit at most 96 elements per turn");
