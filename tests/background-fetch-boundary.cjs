"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync(path.join(__dirname, "../extension/background/message-handler-bg.js"), "utf8");

function fixture(respond) {
  let handler;
  const requests = [], timers = new Map();
  let timerId = 0;
  const NS = {};
  const chrome = { runtime: { onMessage: { addListener(fn) { handler = fn; } } } };
  vm.runInNewContext(source, { self: { SilverfoxBackground: NS }, chrome, URL, AbortController, TextDecoder,
    setTimeout(fn) { timers.set(++timerId, fn); return timerId; }, clearTimeout(id) { timers.delete(id); },
    fetch: async (url, options) => {
      requests.push({ url, ...options, headers: { ...options.headers } });
      assert.equal(options.redirect, "manual", "automatic follow would request private targets before validation");
      return respond(url, options, requests.length);
    }
  });
  NS.installMessageHandler();
  const send = fields => new Promise(resolve => handler({ type: "fetchPageText", ...fields }, {}, resolve));
  return { NS, send, requests, timers };
}

function response(url, status = 200, fields = {}) {
  let reads = 0, cancels = 0;
  const content = new TextEncoder().encode(fields.text || "ok");
  return {
    status, ok: status >= 200 && status < 300, url, type: fields.type || "basic",
    headers: new Headers(fields.headers || {}),
    body: {
      cancel() { cancels++; return Promise.resolve(); },
      getReader() { return {
        async read() { reads++; return reads === 1 ? { done: false, value: content } : { done: true }; },
        cancel() { cancels++; return Promise.resolve(); }, releaseLock() {}
      }; }
    },
    get reads() { return reads; }, get cancels() { return cancels; },
    text() { throw new Error("must not buffer unbounded response.text()"); }
  };
}

async function main() {
  const boundary = fixture(() => { throw new Error("unexpected network"); });
  for (const url of ["http://localhost/", "http://localhost./", "http://a.localhost/", "http://printer.local/",
    "http://router.home.arpa/", "http://intranet/", "http://127.1/", "http://2130706433/", "http://0x7f000001/",
    "http://0177.0.0.1/", "http://0.0.0.0/", "http://10.1.2.3/", "http://169.254.169.254/",
    "http://172.16.0.1/admin", "http://172.31.255.254/", "http://192.168.0.1/", "http://100.64.0.1/",
    "http://224.0.0.1/", "http://[::1]/", "http://[::]/", "http://[fd00::1]/", "http://[fe80::1]/",
    "http://[fec0::1]/", "http://[ff02::1]/", "http://[::ffff:127.0.0.1]/", "http://[2002:7f00:1::]/",
    "http://[64:ff9b::a00:1]/", "file:///tmp/secret", "https://user:password@public.example/"]) {
    assert.equal(boundary.NS.isAllowedFetchUrl(url), false, url);
    assert.equal((await boundary.send({ url })).error, "url-not-allowed", url);
  }
  assert.equal(boundary.requests.length, 0);
  for (const url of ["https://beiancx.com/icp.php", "https://myssl.com/", "https://github.com/",
    "https://public.example/", "https://192.2.3.4/", "http://172.15.255.255/", "http://172.32.0.1/",
    "https://8.8.8.8/", "https://[2606:4700:4700::1111]/", "https://[2001:4860:4860::8888]/"]) {
    assert.equal(boundary.NS.isAllowedFetchUrl(url), true, url);
  }
  for (const target of ["http://172.16.0.1/admin", "http://[::1]/", "http://[fd00::1]/", "http://127.1/file.zip"]) {
    const f = fixture(url => response(url, 302, { headers: { Location: target } }));
    assert.equal((await f.send({ url: "https://public.example/" })).error, "url-not-allowed");
    assert.equal(f.requests.length, 1, "private redirect must not be requested");
    assert.equal(f.timers.size, 0);
  }
  const normal = fixture((url, _init, n) => n === 1 ? response(url, 302, { headers: { Location: "/final" } }) : response(url));
  const normalResult = await normal.send({ url: "https://public.example/start" });
  assert.equal(normalResult.text, "ok"); assert.equal(normalResult.url, "https://public.example/final");
  assert.equal(normal.requests.length, 2); assert.equal(normal.timers.size, 0);
  const manual = fixture(url => response(url, 302, { headers: { Location: "/final" } }));
  assert.equal((await manual.send({ url: "https://public.example/start", redirect: "manual" })).redirectLocation, "https://public.example/final");
  assert.equal(manual.requests.length, 1);
  const opaque = fixture(() => response("", 0, { type: "opaqueredirect" }));
  assert.equal((await opaque.send({ url: "https://public.example/" })).error, "redirect-unavailable");
  assert.equal(opaque.requests.length, 1, "opaque redirect must never be retried with follow");
  const loop = fixture(url => response(url, 302, { headers: { Location: "/" } }));
  assert.equal((await loop.send({ url: "https://public.example/" })).error, "redirect-loop");
  const limit = fixture((url, _opts, n) => response(url, 302, { headers: { Location: `/hop${n}` } }));
  assert.equal((await limit.send({ url: "https://public.example/" })).error, "redirect-limit");
  assert.equal(limit.requests.length, 6);
  const post = fixture((url, _opts, n) => n === 1 ? response(url, 303, { headers: { Location: "/final" } }) : response(url));
  assert.equal((await post.send({ url: "https://public.example/", method: "POST", body: "domain=public.example" })).success, true);
  assert.equal(post.requests[0].method, "POST"); assert.equal(post.requests[1].method, "GET");
  assert.equal(post.requests[1].body, undefined);
  const crossPost = fixture(url => response(url, 307, { headers: { Location: "https://other.example/" } }));
  assert.equal((await crossPost.send({ url: "https://public.example/", method: "POST", body: "private=value" })).error, "cross-origin-post-redirect");
  assert.equal(crossPost.requests.length, 1);
  const bigResponse = response("https://public.example/", 200, { text: "x".repeat(600000) });
  const bounded = fixture(() => bigResponse);
  assert.equal((await bounded.send({ url: "https://public.example/" })).text.length, 120000);
  assert.equal(bigResponse.reads, 1); assert.equal(bigResponse.cancels, 1);
  const packageRedirect = fixture(url => response(url, 302, { headers: { Location: "https://cdn.example/file.zip" } }));
  assert.equal((await packageRedirect.send({ url: "https://public.example/" })).error, "package-url-blocked");
  assert.equal(packageRedirect.requests.length, 1);
  const timeout = fixture((_url, opts) => new Promise((_resolve, reject) => {
    opts.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })), { once: true });
  }));
  const pending = timeout.send({ url: "https://public.example/" });
  for (const fn of timeout.timers.values()) fn();
  assert.equal((await pending).error, "timeout"); assert.equal(timeout.timers.size, 0);
  console.log("PASS: literal/private/local URL boundaries, per-hop redirect validation, opaque failure, POST semantics, timeout and bounded streaming");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
