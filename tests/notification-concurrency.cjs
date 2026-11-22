"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync(path.join(__dirname, "../extension/background/notification-bg.js"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const NS = {}, creates = [], storage = {};
  const chrome = { runtime: { getURL: p => p }, notifications: {
    create(id, opts, cb) { creates.push({ id, opts, cb }); }, clear(_id, cb) { cb(); }
  }, storage: { local: {
    get(_keys, cb) { cb(structuredClone(storage)); }, set(values, cb) { Object.assign(storage, values); cb?.(); }
  } } };
  vm.runInNewContext(source, { self: { SilverfoxBackground: NS }, chrome, console: { warn() {} } });
  function finish(index, fail = false) {
    chrome.runtime.lastError = fail ? { message: "fixture failure" } : undefined;
    creates[index].cb(); delete chrome.runtime.lastError;
  }
  return { NS, creates, finish, storage, chrome };
}
async function main() {
  for (const force of [false, true]) {
    const f = fixture();
    const first = f.NS.showBlockedNotification("Blocked", "Setup.exe", 1, force);
    const second = f.NS.showBlockedNotification("Blocked", "Setup.exe", 2, force);
    await tick(); assert.equal(f.creates.length, 1); assert.equal(await second, false);
    f.finish(0); assert.equal(await first, true);
    assert.equal(await f.NS.showBlockedNotification("Blocked", "Setup.exe", 1, force), false);
  }
  const retry = fixture();
  const failed = retry.NS.showBlockedNotification("Blocked", "Retry.exe", 1, true);
  await tick(); retry.finish(0, true); retry.finish(1, true); assert.equal(await failed, false);
  const next = retry.NS.showBlockedNotification("Blocked", "Retry.exe", 1, true);
  await tick(); assert.equal(retry.creates.length, 3); retry.finish(2); assert.equal(await next, true);

  const f = fixture(), opts = versionToken => ({ channelKey: "brand:1", versionToken });
  const old = f.NS.showBlockedNotification("Old", "old", 1, true, opts("old"));
  const current = f.NS.showBlockedNotification("Current", "current", 1, true, opts("new"));
  const duplicate = f.NS.showBlockedNotification("Current", "current", 1, true, opts("new"));
  await tick(); assert.equal(await old, false); assert.equal(await duplicate, false);
  assert.equal(f.creates.length, 1); assert.equal(f.creates[0].opts.title, "Current");
  f.finish(0); assert.equal(await current, true);
  const cleared = fixture();
  const pending = cleared.NS.showBlockedNotification("Old", "old", 1, true, opts("old"));
  cleared.NS.clearNotificationChannel("brand:1");
  assert.equal(await pending, false); assert.equal(cleared.creates.length, 0);
  const concurrent = fixture();
  concurrent.chrome.storage.local.set = (values, cb) => setImmediate(() => {
    Object.assign(concurrent.storage, values); cb?.();
  });
  const notices = ["A.exe", "B.exe"].map(name => concurrent.NS.showBlockedNotification("Blocked", name, 1));
  await tick(); concurrent.finish(0); concurrent.finish(1); await Promise.all(notices);
  assert.deepEqual(Object.keys(concurrent.storage.silverfoxNoticeCooldown).sort(), ["Blocked::A.exe", "Blocked::B.exe"]);
  const reservations = await Promise.all(["a.zip", "b.zip", "a.zip"].map(n => concurrent.NS.shouldNotifyDownloadBlock(n)));
  assert.deepEqual(reservations, [true, true, false]);
  assert.deepEqual(Object.keys(concurrent.storage.silverfoxDownloadNoticeCooldown).sort(), ["a.zip", "b.zip"]);
  console.log("PASS: simultaneous notifications coalesce; failed creation retries; newer/cleared brand channel wins");
}
main().catch(e => { console.error(e); process.exitCode = 1; });
