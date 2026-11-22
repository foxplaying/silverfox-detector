"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const host = "download.example.test", now = Date.now();
const oldOv = { host, validation: "OV", organization: "Acme Systems Limited", source: "crt.sh",
  issuer: "Acme Issuing CA", unexpiredHostVerified: true, notBefore: now - 100000,
  at: now - 2000, observedAt: now - 2000, fingerprintSha256: "a".repeat(64) };
const liveDv = { host, validation: "DV", organization: "", source: "edgeone",
  issuer: "Acme Issuing CA", liveTlsLeafVerified: true, notBefore: now - 50000,
  at: now - 1000, observedAt: now - 1000, fingerprintSha256: "b".repeat(64) };
function context(extra = {}) {
  const ctx = vm.createContext({ console, URL, setTimeout, clearTimeout, ...extra });
  vm.runInContext(read("extension/shared/ssl-evidence.js"), ctx);
  return ctx;
}

async function main() {
  const ctx = context({ self: { SilverfoxBackground: {} } });
  const evidence = ctx.SilverfoxSslEvidence;
  assert.equal(evidence.choose(oldOv, liveDv), liveDv, "current live DV replaces old CT OV");
  assert.equal(evidence.choose(liveDv, { ...oldOv, at: now, observedAt: now }), liveDv,
    "a later CT response cannot replace a live leaf");
  assert.equal(evidence.choose(liveDv, { ...oldOv, liveTlsLeafVerified: true }), liveDv,
    "a delayed older live response cannot roll back a new leaf");
  assert.equal(evidence.choose(liveDv, { ...oldOv, liveTlsLeafVerified: true, observedAt: now }).validation, "OV",
    "a genuinely newer live leaf can replace DV");
  const enriched = evidence.choose(liveDv, { ...oldOv, fingerprintSha256: liveDv.fingerprintSha256 });
  assert.equal(enriched.validation, "OV", "same certificate DER may enrich its classification");
  assert.equal(enriched.liveTlsLeafVerified, true);
  assert.equal(enriched.observedAt, liveDv.observedAt, "CT does not invent a new TLS observation timestamp");
  const emptyNewOv = { ...liveDv, validation: "OV", fingerprintSha256: "c".repeat(64), observedAt: now };
  assert.equal(evidence.choose({ ...oldOv, liveTlsLeafVerified: true }, emptyNewOv).organization, "",
    "never borrow an organization from another certificate");
  assert.equal(evidence.choose(liveDv, { ...oldOv, queriedHost: "example.test", liveTlsLeafVerified: true }), liveDv,
    "parent host live proof is not current host proof");
  assert.equal(evidence.choose({ ...oldOv, host: `www.${host}` }, liveDv), liveDv,
    "www and apex do not share certificate state");

  vm.runInContext(read("extension/background/ssl-cert-bg.js"), ctx);
  const bg = ctx.self.SilverfoxBackground;
  bg.storeSslCertInfo(host, oldOv);
  bg.storeSslCertInfo(host, liveDv);
  assert.equal(bg.getSslCertInfoForHost(host).validation, "DV");
  assert.equal(bg.getSslCertInfoForHost(host).organization, "");
  bg.storeSslCertInfo(host, { ...oldOv, at: now, observedAt: now });
  assert.equal(bg.getSslCertInfoForHost(host).validation, "DV");
  bg.storeSslCertInfo(`www.${host}`, { ...oldOv, host: `www.${host}` });
  assert.equal(bg.getSslCertInfoForHost(`www.${host}`).validation, "OV");
  assert.equal(bg.getSslCertInfoForHost(host).validation, "DV");
  bg.probeSslCertForHost = async () => ({ ...liveDv, observedAt: now + 1 });
  assert.equal((await bg.resolveSslCertInfo(host, { force: true })).validation, "DV");
  bg.probeSslCertForHost = async () => ({ ...oldOv, observedAt: now + 2 });
  assert.equal((await bg.resolveSslCertInfo(host, { force: true })).validation, "DV",
    "forced refresh also uses current-leaf precedence");

  const content = { state: {}, caches: {}, emitRiskReport() {} };
  const contentCtx = context({ window: { SilverfoxContent: content }, location: new URL(`https://${host}/`) });
  vm.runInContext(read("extension/content/intel-gates.js"), contentCtx);
  // Avoid unrelated DOM/identity heuristics in this certificate propagation test.
  content.hasOrganizationValidatedSsl = () => false;
  content.evaluateMatureLegitimateSiteProfile = () => null;
  content.hasAuthoritativeMatureOrganizationIdentity = () => false;
  assert.equal(content.applySslCertInfo(oldOv), true);
  assert.equal(content.applySslCertInfo(liveDv), true);
  assert.equal(content.state.sslInfo.validation, "DV");
  assert.equal(content.state.sslInfo.organization, "");
  assert.equal(content.applySslCertInfo({ ...oldOv, observedAt: now }), false);
  assert.equal(content.applySslCertInfo({ ...oldOv, host: `www.${host}` }), false);
  assert.equal(content.state.sslInfo.observedAt, liveDv.observedAt);

  const popupCtx = context({ document: { addEventListener() {} }, module: { exports: {} } });
  vm.runInContext(read("extension/popup/popup.js"), popupCtx);
  const choosePopup = popupCtx.module.exports.chooseStrongerSslInfo;
  assert.equal(choosePopup(oldOv, liveDv), liveDv);
  assert.equal(choosePopup(liveDv, { ...oldOv, observedAt: now }), liveDv);

  const messageCtx = context({ self: { SilverfoxBackground: {} } });
  vm.runInContext(read("extension/background/message-handler-bg.js"), messageCtx);
  const chooseBackground = messageCtx.self.SilverfoxBackground.chooseStrongerSslInfo;
  assert.equal(chooseBackground(oldOv, liveDv), liveDv);
  assert.equal(chooseBackground(liveDv, { ...oldOv, observedAt: now }), liveDv);

  // Full message handler: a first CT-only OV must schedule follow-up work,
  // and a later cached live DV must reach the tab even if the fast probe keeps
  // returning the CT result. No real timers or provider requests are used.
  let receive, cachedLeaf = oldOv, timerId = 0;
  const timers = new Map(), messages = [];
  const scheduleBg = {
    getSslCertInfoForHost: () => cachedLeaf,
    probeSslCertForHost: async () => oldOv,
    storeSslCertInfo(_host, value) { cachedLeaf = evidence.choose(cachedLeaf, value); }
  };
  const scheduleCtx = context({ self: { SilverfoxBackground: scheduleBg },
    setTimeout(fn, delay) { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout(id) { timers.delete(id); },
    chrome: { runtime: { onMessage: { addListener(fn) { receive = fn; } } },
      tabs: { sendMessage(tabId, message, cb) { messages.push({ tabId, ...message }); cb?.(); } } }
  });
  vm.runInContext(read("extension/background/message-handler-bg.js"), scheduleCtx);
  scheduleBg.installMessageHandler();
  await new Promise(resolve => receive({ type: "get-ssl-cert", host },
    { tab: { id: 1, url: `https://${host}/` } }, resolve));
  const fire = async delay => {
    const entry = [...timers.entries()].find(([, item]) => item.delay === delay);
    assert.ok(entry, `missing scheduled ${delay}ms refresh`);
    timers.delete(entry[0]); entry[1].fn(); await tick();
  };
  await fire(50);
  assert.equal(scheduleBg._sslUpgradeJobsByHost.has(host), true,
    "a historical OV must not close the refresh job before live evidence");
  cachedLeaf = liveDv;
  await fire(3000);
  assert.equal(messages.at(-1).sslInfo.validation, "DV");
  assert.equal(messages.at(-1).sslInfo.fingerprintSha256, liveDv.fingerprintSha256);
  assert.equal(cachedLeaf.validation, "DV");
  const countAfterLive = messages.length;
  await fire(10000);
  assert.ok(messages.slice(countAfterLive).every(message => message.sslInfo.validation === "DV"),
    "repeated historical result must not repaint stale OV");
  await fire(45000);
  assert.equal(timers.size, 0); assert.equal(scheduleBg._sslUpgradeJobsByHost.has(host), false);

  // Exercise the actual asynchronous source race without network access. A CT
  // result may resolve first; a slower live source must still update the cache.
  const raceCtx = context({ self: { SilverfoxBackground: {} },
    setTimeout(fn, ms) { const timer = setTimeout(fn, ms); timer.unref(); return timer; } });
  let source = read("extension/background/ssl-cert-bg.js");
  source = source.replace('  NS.installSslCertCapture = function',
    '  NS._testProbe = probeSslCertOnce; NS._testSource = runCachedSslSource;\n  NS.installSslCertCapture = function');
  vm.runInContext(source, raceCtx);
  const raceBg = raceCtx.self.SilverfoxBackground;
  for (const provider of ["ssllabs", "certspotter", "crtsh", "shodan", "networkcalc", "myssl", "edgeone"]) {
    raceBg._sslSourceCache.set(`${provider}|${host}`, { at: now, ttl: 60000,
      value: provider === "crtsh" ? oldOv : null });
  }
  raceBg._sslSourceCache.delete(`edgeone|${host}`);
  let resolveLive;
  raceBg._sslSourceInflight.set(`edgeone|${host}`, new Promise(resolve => { resolveLive = resolve; }));
  assert.equal((await raceBg._testProbe(host, true)).validation, "OV");
  resolveLive(liveDv);
  await tick();
  assert.equal(raceBg.getSslCertInfoForHost(host).validation, "DV",
    "late live evidence is retained after the first-hit response");
  raceBg._sslSourceCache.set(`fixture|${host}`, { at: now - 1000, ttl: 60000, value: liveDv });
  const cachedSource = await raceBg._testSource("fixture", host, () => { throw new Error("cache miss"); });
  assert.equal(cachedSource.observedAt, liveDv.observedAt, "cache reads never refresh observation time");
  console.log("SSL current-certificate regressions passed (cache, race, content, popup, background).");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
