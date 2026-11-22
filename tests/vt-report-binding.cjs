"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "extension/background/pe-vt-bg.js"), "utf8");
const hash = "a".repeat(64), other = "b".repeat(64);
const gui = "https://www.virustotal.com/gui/file/" + hash;
const api = "https://www.virustotal.com/ui/files/" + hash;
const report = (id = hash, sha = id) => ({ data: { type: "file", id, attributes: {
  sha256: sha, last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 70, harmless: 0 },
  meaningful_name: "SteamSetup.exe"
} } });

async function main() {
  const NS = {};
  const context = vm.createContext({ self: { SilverfoxBackground: NS }, URL, console,
    setTimeout, clearTimeout, AbortController, chrome: { runtime: {} } });
  vm.runInContext(source.replace("})(self.SilverfoxBackground ??= {});", `
    NS.test = { parseVtPageFetchPayload, vtFileIdentityMatchesTarget, vtShouldHardBlock };
  })(self.SilverfoxBackground ??= {});`), context);
  const payload = (body) => ({ targetHash: hash, pageUrl: gui, captureUrl: api,
    status: 200, text: JSON.stringify(body),
    pageHint: `${other} 62/67 security vendors flagged this file as malicious`,
    domRatios: [{ detections: 62, total: 67 }],
    pageSignatureInfo: { verified: "Signed file, valid signature", signers: "Unrelated Publisher" }
  });
  const parse = (p) => NS.test.parseVtPageFetchPayload(p, hash, gui);
  const clean = parse(payload(report()));
  assert.equal(clean.malicious, 0);
  assert.equal(clean.total, 70);
  assert.equal(clean.ratio, "0/70");
  assert.equal(clean.signerFromVt, "");
  assert.equal(clean.sigTrustFromVt, "");
  assert.equal(clean.statsPolicyVersion, 4);
  assert.equal(parse(payload(report(other))), null);
  assert.equal(parse(payload(report(hash, other))), null);
  assert.equal(parse(payload(report("malformed", hash))), null);
  assert.equal(parse(payload({ related_files: [report()] })), null);
  assert.equal(parse({ ...payload(report()), text: "", domRatios: [{ detections: 62, total: 67 }] }), null);
  assert.equal(parse({ ...payload(report()), captureUrl: api.replace(hash, other) }), null);
  assert.equal(parse({ ...payload(report()), pageUrl: gui.replace(hash, other) }), null);
  assert.equal(parse({ ...payload(report()), captureUrl: api.replace("www.virustotal.com", "example.test") }), null);
  assert.equal(parse({ ...payload(report()), text: JSON.stringify(report()).slice(0, -1) }), null);
  assert.equal(parse(payload({ error: { code: "NotFoundError" } })).verifiedNotFound, true);
  assert.equal(parse(payload({ error: { code: "RecaptchaRequired" } })), null);
  const signed = report();
  signed.data.attributes.signature_info = { verified: "Signed", signers: "Valve Corp." };
  const signedHit = parse(payload(signed));
  assert.equal(signedHit.sigTrustFromVt, "valid");
  assert.ok(signedHit.signerFromVt.includes("Valve"));
  const maliciousVt = { ...clean, trustedScoreHardBlock: true, engineDetailsAvailable: true,
    trustedScore: 8, trustedEngineCount: 3 };
  assert.equal(NS.test.vtShouldHardBlock({ sha256: other, vt: maliciousVt }, {}).block, false);
  assert.equal(NS.test.vtShouldHardBlock({ sha256: hash, vt: maliciousVt }, {}).block, true);
  console.log("PASS: exact root SHA binding; unrelated DOM/stats/signatures ignored");

  // Exercise the real capture hook with requested/redirected/mixed responses.
  let nextBody = report(), responseUrl = api;
  const window = { fetch: async () => ({ status: 200, url: responseUrl,
    clone: () => ({ text: async () => JSON.stringify(nextBody) }) }) };
  const hookContext = vm.createContext({ window, URL,
    location: { origin: "https://www.virustotal.com", pathname: "/gui/file/" + hash } });
  vm.runInContext(fs.readFileSync(path.join(root, "extension/content/vt-hook-main.js"), "utf8"), hookContext);
  await window.fetch(api);
  await Promise.resolve();
  assert.equal(JSON.parse(window.__sfVtCaptures[hash].text).data.id, hash);
  for (const bad of [report(other), report(hash, other), { data: { id: other, related: report() } }]) {
    window.__sfVtCaptures = {};
    nextBody = bad;
    await window.fetch(api); await Promise.resolve();
    assert.equal(window.__sfVtCaptures[hash], undefined);
  }
  window.__sfVtCaptures = {}; nextBody = report(); responseUrl = api.replace(hash, other);
  await window.fetch(api); await Promise.resolve();
  assert.equal(window.__sfVtCaptures[hash], undefined);
  console.log("PASS: capture hook rejects other files, conflicting identities and redirects");

  // Use the production scheduler with a controlled lookup backend.
  const start = source.indexOf("  const vtLookupInflight = new Map();");
  const end = source.indexOf("  async function lookupVirusTotalHashUnshared", start);
  let calls = 0, finish;
  const scheduler = {};
  vm.runInNewContext(source.slice(start, end), { NS: scheduler, Map, Promise, Date,
    lookupVirusTotalHashUnshared: () => { calls++; return new Promise((r) => { finish = r; }); } });
  const first = scheduler.lookupVirusTotalHash(hash, { requireSignature: false });
  const second = scheduler.lookupVirusTotalHash(hash, { requireSignature: true });
  assert.equal(calls, 1); assert.equal(first, second);
  finish({ hash, found: true, signatureIncomplete: true }); await first;
  const cached = await scheduler.lookupVirusTotalHash(hash);
  assert.equal(calls, 1); assert.equal(cached.cached, true);
  assert.ok(cached.retryAfterMs > 0);
  const forced = scheduler.lookupVirusTotalHash(hash, { force: true });
  assert.equal(calls, 2); finish({ hash, found: true }); await forced;
  console.log("PASS: same-SHA queries share work; incomplete signature cooldown; explicit retry");

  // Upgrade an unsafe v3 cache once, then reuse the exact v4 API result without opening pages.
  let fetches = 0, tabOpens = 0;
  const storage = { vtApiKey: "test-key", ["vtOk_" + hash]: { at: Date.now(),
    result: { ...clean, malicious: 62, statsPolicyVersion: 3, trustedPolicyVersion: 4 } } };
  const freshNS = {};
  const apiContext = vm.createContext({ self: { SilverfoxBackground: freshNS }, URL, console,
    setTimeout, clearTimeout, AbortController,
    fetch: async () => { fetches++; return { status: 200, ok: true, text: async () => JSON.stringify(signed) }; },
    chrome: { runtime: {}, tabs: { create() { tabOpens++; } }, storage: { local: {
      get(_keys, cb) { cb(storage); }, set(values, cb) { Object.assign(storage, values); cb?.(); },
      remove(keys, cb) { keys.forEach((k) => delete storage[k]); cb?.(); }
    } } }
  });
  vm.runInContext(source, apiContext);
  const upgraded = await freshNS.lookupVirusTotalHash(hash);
  assert.equal(upgraded.ratio, "0/70"); assert.equal(upgraded.statsPolicyVersion, 4);
  assert.equal(upgraded.sigTrustFromVt, "valid");
  await freshNS.lookupVirusTotalHash(hash);
  assert.equal(fetches, 1); assert.equal(tabOpens, 0);
  console.log("PASS: old contaminated cache replaced once; new API report/signature reused");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
