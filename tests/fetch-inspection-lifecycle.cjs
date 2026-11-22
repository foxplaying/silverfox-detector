"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync(path.join(__dirname, "../extension/page-hooks/dom-guard.js"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const bytes = text => new TextEncoder().encode(text);
const payload = '{"url":"https://cdn.example.test/random.exe"}';

function fixture(response) {
  const messages = [], timers = new Map();
  let nextTimer = 0;
  const originalPromise = Promise.resolve(response);
  const originalFetch = () => originalPromise;
  const hooks = { PackageHeuristics: { isPackageFileUrl: url => /\.(?:exe|zip)(?:[?#]|$)/i.test(url),
    isClearOrStrongProductPackageUrl: () => false }, DownloadUi: { greyOut() {} } };
  const window = { SilverfoxPageHooks: hooks, fetch: originalFetch };
  vm.runInNewContext(source, { window, document: { querySelectorAll: () => [] }, TextDecoder,
    setTimeout(fn) { const id = ++nextTimer; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); } });
  const policy = { guardEnabled: true, lightPage: false, officialSafe: false,
    _rememberHop() {}, post: message => messages.push(message) };
  const guard = hooks.DomGuard;
  guard.enableFetchInspection(policy);
  return { window, policy, guard, messages, timers, originalPromise, originalFetch };
}

function streamed(chunks = null, headers = {}) {
  let resolveRead;
  const state = { clones: 0, reads: 0, cancels: 0, released: 0 };
  const reader = {
    read() {
      state.reads++;
      if (chunks) return Promise.resolve(chunks.length ? { done: false, value: chunks.shift() } : { done: true });
      return new Promise(resolve => { resolveRead = resolve; });
    },
    // Deliberately never settle cancellation: native tee cancellation may
    // wait for the untouched original branch and must not hold cleanup open.
    cancel() { state.cancels++; return new Promise(() => {}); },
    releaseLock() { state.released++; }
  };
  const response = { headers: { get: name => headers[name] ?? null }, body: { getReader() {} },
    clone() { state.clones++; return { body: { getReader: () => reader } }; } };
  return { response, state, finish() { resolveRead?.({ done: false, value: bytes(payload) }); } };
}

async function main() {
  {
    const stream = streamed(), f = fixture(stream.response);
    const result = f.window.fetch("/api.php");
    assert.equal(result, f.originalPromise, "inspection must return the exact original fetch promise");
    assert.equal(await result, stream.response, "headers must be delivered before inspection completes");
    await tick();
    assert.equal(stream.state.reads, 1);
    f.messages.length = 0;
    for (const expire of [...f.timers.values()]) expire();
    await tick();
    assert.equal(stream.state.cancels, 1);
    assert.equal(f.guard._fetchInspection.pending.size, 0);
    assert.equal(f.timers.size, 0);
    stream.finish(); await tick();
    assert.equal(f.messages.length, 0, "late timed-out bytes must not mutate guard state");
  }
  console.log("PASS: slow/endless fetch body never delays response; timeout cancels and releases inspection slot");

  for (const change of ["safe", "disabled", "restore-and-reenable", "replace-policy"]) {
    const stream = streamed(), f = fixture(stream.response);
    await f.window.fetch("/api.php"); await tick(); f.messages.length = 0;
    if (change === "safe") f.policy.officialSafe = true;
    if (change === "disabled") f.policy.guardEnabled = false;
    if (change === "restore-and-reenable") { f.guard.restoreFetchInspection(); f.guard.enableFetchInspection(f.policy); }
    if (change === "replace-policy") f.guard.enableFetchInspection({ ...f.policy });
    stream.finish(); await tick();
    assert.equal(f.messages.length, 0, `${change}: old body must not re-arm or disable page controls`);
    assert.equal(f.timers.size, 0);
    f.guard.restoreFetchInspection();
  }
  console.log("PASS: stale body completions cannot mutate a cleared/replaced/re-enabled guard");

  for (const mode of ["declared", "streamed", "binary"]) {
    const stream = streamed([new Uint8Array(65537)], mode === "declared" ? { "content-length": "65537" }
      : mode === "binary" ? { "content-type": "application/octet-stream" } : {});
    const f = fixture(stream.response);
    await f.window.fetch("/api.php"); f.messages.length = 0; await tick();
    assert.equal(f.messages.length, 0);
    assert.equal(f.guard._fetchInspection.pending.size, 0);
    assert.equal(stream.state.clones, mode === "streamed" ? 1 : 0);
    if (mode === "streamed") assert.equal(stream.state.cancels, 1);
  }
  {
    const stream = streamed(), f = fixture(stream.response);
    for (let i = 0; i < 8; i++) f.window.fetch(`/api.php?id=${i}`);
    await tick();
    assert.equal(stream.state.clones, 4, "concurrent inspections must remain bounded");
    f.guard.restoreFetchInspection(); await tick();
    assert.equal(f.timers.size, 0);
    assert.equal(f.window.fetch, f.originalFetch);
  }
  console.log("PASS: byte/type/concurrency limits bound response inspection");

  {
    // Also exercise native Response.clone()/ReadableStream, not only mocks.
    const f = fixture(new Response(payload, { headers: { "content-type": "application/json" } }));
    const read = f.guard._readFetchInspectionText;
    let inspection;
    f.guard._readFetchInspectionText = (...args) => (inspection = read.call(f.guard, ...args));
    const response = await f.window.fetch("/api.php");
    assert.equal(await response.text(), payload);
    assert.equal(await inspection, payload);
    await tick();
    assert.ok(f.messages.some(m => m.type === "blocked-download" && m.href.endsWith("random.exe")), "valid current response still detects package links");
    f.guard.restoreFetchInspection();
  }
  console.log("PASS: current small API bodies still trigger protection without consuming the page response");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
