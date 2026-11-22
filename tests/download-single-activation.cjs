"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync(path.join(__dirname, "../extension/content/scanner.js"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture(target = "_blank", baseTarget = "") {
  let reply, reject, probes = 0, blocked = 0;
  const opens = [], navigations = [], topNavigations = [], parentNavigations = [], toasts = [];
  const userActivation = { isActive: true };
  const location = new URL("https://site.example/versions");
  const destination = "https://cdn.example/getdown?id=1";
  const NS = { state: { protectedTargets: [], _analysisTxn: "current" }, caches: { probeCache: new Map() },
    getElementDownloadHref: () => destination,
    getFilenameFromUrl: h => h.split("/").pop(), formatPackageLabel: h => h,
    probeDownloadBehavior: () => { probes++; return new Promise((a, b) => { reply = a; reject = b; }); },
    applyConfirmedDownloadBlock: () => { blocked++; return true; }, disableAllDownloadIntentControls() {}, showGuardOverlay() {},
    showPageToast: (...args) => toasts.push(args) };
  const window = { SilverfoxContent: NS, open: (...a) => opens.push(a),
    top: { location: { set href(h) { topNavigations.push(h); } } },
    parent: { location: { set href(h) { parentNavigations.push(h); } } },
    location: { set href(h) { navigations.push(h); } } };
  vm.runInNewContext(source, { window, location, document: { querySelector: s => s === "base[target]" && baseTarget
    ? { getAttribute: () => baseTarget } : null }, navigator: { userActivation }, URL, console });
  for (const name of ["pageLooksLikeSearchEngineResultsPage", "isDeclarativeDisclosureControl", "isPlainSameOriginDocumentNavigation",
    "isProvisionalDownloadIdentityPending", "shouldRejectOfficialDownloadShortcut", "shouldNeverArmProtection",
    "looksLikeMatureOfficialPortal", "pageLooksLikeLegitimateOfficialDownload", "looksLikeOfficialProductDownloadEndpoint",
    "isClearProductOrAndroidPackage", "isBenignShortInstallerName", "looksLikeStrongProductInstallerName",
    "isAllowlistedProductPackageUrl", "isContentAddressedPackageName", "isTrustedOfficialDownloadContext",
    "looksLikeSafeOfficialContext", "isSamePageBrandApex", "isHrefSuspiciousPackageSync", "isHrefSuspiciousPackage",
    "hasRealHardKitThreat", "hasHardThreatKitLocked", "isDownloadIntentElement"]) NS[name] = () => false;
  NS.needsDownloadBehaviorProbe = () => true;
  const element = { tagName: "A", getAttribute: k => k === "target" ? target : k === "href" ? destination : "" };
  function fire(type, extra = {}) {
    const event = { type, button: 0, key: "Enter", prevented: false,
      preventDefault() { this.prevented = true; }, stopPropagation() {}, stopImmediatePropagation() {}, ...extra };
    assert.equal(NS.blockPackageDownloadAction(event, element), true);
    return event;
  }
  return { NS, element, fire, location, destination, opens, navigations, topNavigations, parentNavigations, toasts, userActivation,
    reply: r => reply(r), reject: () => reject(new Error("timeout")), probes: () => probes, blocked: () => blocked };
}
async function main() {
  const f = fixture();
  f.fire("pointerdown"); f.fire("mousedown");
  await tick(); assert.equal(f.probes(), 0); assert.equal(f.opens.length, 0);
  const event = f.fire("click"); assert.equal(event.prevented, true);
  f.NS.blockPackageDownloadAction(event, f.element); // same event reaches a second path
  f.fire("click"); // reactivation while the same element is awaiting its query
  await tick(); assert.equal(f.probes(), 1);
  f.reply({ success: true, isDownload: false }); await tick();
  assert.equal(f.opens.length, 1); assert.equal(f.navigations.length, 0);
  assert.equal(f.opens[0][0], f.destination);
  // A later intentional click is not permanently disabled.
  f.fire("click"); await tick(); f.reply({ isDownload: false }); await tick();
  assert.equal(f.opens.length, 2);
  console.log("PASS: pointerdown/mousedown/click owns one probe and one new tab; later clicks remain possible");

  for (const target of ["_blank", "_self"]) {
    const c = fixture(target);
    c.NS.caches.probeCache.set(c.destination, { success: true, isDownload: false, expiresAt: Date.now() + 10000 });
    c.fire("pointerdown"); c.fire("mousedown"); c.fire("click"); await tick();
    assert.equal(c.probes(), 0);
    assert.equal(c.opens.length, target === "_blank" ? 1 : 0);
    assert.equal(c.navigations.length, target === "_self" ? 1 : 0);
  }
  const k = fixture(); k.fire("keydown"); k.fire("keydown", { repeat: true }); k.fire("click");
  await tick(); assert.equal(k.probes(), 1); k.reply({ isDownload: false }); await tick();
  assert.equal(k.opens.length, 1);
  console.log("PASS: cached destinations preserve target; keyboard activation/repeat does not duplicate pending work");

  for (const cached of [true, false]) {
    for (const [target, base, effective] of [["_TOP", "", "_top"], ["_parent", "", "_parent"],
      ["DownloadFrame", "", "DownloadFrame"], ["", "BaseFrame", "BaseFrame"], ["_self", "BaseFrame", "_self"]]) {
      const c = fixture(target, base);
      if (cached) c.NS.caches.probeCache.set(c.destination, { success: true, isDownload: false, expiresAt: Date.now() + 10000 });
      c.fire("click"); await tick();
      if (!cached) { c.reply({ isDownload: false }); await tick(); }
      assert.equal(c.topNavigations.length, effective === "_top" ? 1 : 0);
      assert.equal(c.parentNavigations.length, effective === "_parent" ? 1 : 0);
      assert.equal(c.navigations.length, effective === "_self" ? 1 : 0);
      assert.equal(c.opens.length, effective.endsWith("Frame") ? 1 : 0);
      if (c.opens.length) assert.equal(c.opens[0][1], effective);
    }
  }
  const locked = fixture();
  locked.NS.shouldNeverArmProtection = () => true;
  locked.NS.hasHardThreatKitLocked = () => true;
  let stopped = 0;
  const lockedEvent = locked.fire("click", { stopPropagation() { stopped++; }, stopImmediatePropagation() { stopped++; } });
  assert.equal(lockedEvent.prevented, true); assert.equal(stopped, 2);
  assert.equal(locked.probes(), 0); assert.equal(locked.opens.length, 0);
  console.log("PASS: top/parent/named/base targets preserved; hard kit wins over trusted-page shortcut and cancels event");

  for (const cached of [true, false]) {
    for (const modifiers of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { ctrlKey: true, shiftKey: true }]) {
      for (const target of ["_self", "_parent", "DownloadFrame"]) {
        const c = fixture(target);
        if (cached) c.NS.caches.probeCache.set(c.destination, { success: true, isDownload: false, expiresAt: Date.now() + 10000 });
        c.fire("pointerdown", modifiers); c.fire("mousedown", modifiers);
        assert.equal(c.opens.length, 0, "no speculative blank tab on button-down");
        const event = c.fire("click", modifiers);
        c.NS.blockPackageDownloadAction(event, c.element);
        await tick();
        if (!cached) { c.reply({ success: true, isDownload: false }); await tick(); }
        assert.equal(c.opens.length, 1); assert.equal(c.opens[0][0], c.destination); assert.equal(c.opens[0][1], "_blank");
        assert.equal(c.opens[0][2].includes("popup=yes"), !!modifiers.shiftKey && !modifiers.ctrlKey && !modifiers.metaKey);
        assert.equal(c.navigations.length + c.topNavigations.length + c.parentNavigations.length, 0);
      }
    }
  }
  const snapshot = fixture("_self");
  const modified = snapshot.fire("click", { ctrlKey: true }); modified.ctrlKey = false;
  await tick(); snapshot.reply({ isDownload: false }); await tick();
  assert.equal(snapshot.opens.length, 1); assert.equal(snapshot.navigations.length, 0);
  const expired = fixture("_self"); expired.fire("click", { ctrlKey: true }); await tick();
  expired.userActivation.isActive = false;
  expired.reply({ success: true, isDownload: false }); await tick();
  assert.equal(expired.opens.length, 0); assert.equal(expired.navigations.length, 0); assert.equal(expired.toasts.length, 1);
  expired.NS.caches.probeCache.set(expired.destination, { success: true, isDownload: false, expiresAt: Date.now() + 10000 });
  expired.userActivation.isActive = true;
  expired.fire("click", { ctrlKey: true }); await tick();
  assert.equal(expired.opens.length, 1); assert.equal(expired.probes(), 1);
  const modifiedBlock = fixture("_self"); modifiedBlock.fire("click", { shiftKey: true }); await tick();
  modifiedBlock.reply({ isDownload: true }); await tick();
  assert.equal(modifiedBlock.blocked(), 1); assert.equal(modifiedBlock.opens.length, 0);
  console.log("PASS: Ctrl/Meta/Shift intent survives cached/async probes; no duplicate or speculative blank tab; expired activation requires a fresh click");

  for (const change of [f => { f.location.pathname = "/other"; },
    f => { f.NS.state._analysisTxn = "new"; }, f => { f.NS.state.downloadGuardInstalled = true; }]) {
    const c = fixture(); c.fire("click"); await tick(); change(c);
    c.reply({ isDownload: false }); await tick(); assert.equal(c.opens.length, 0);
  }
  const b = fixture(); b.fire("pointerdown"); b.fire("mousedown"); b.fire("click");
  await tick(); b.reply({ isDownload: true, filename: "bad.exe" }); await tick();
  assert.equal(b.blocked(), 1); assert.equal(b.opens.length, 0);
  const allowed = fixture();
  allowed.NS.applyConfirmedDownloadBlock = () => false;
  allowed.NS.disableAllDownloadIntentControls = () => assert.fail("safe attachment disabled controls");
  allowed.fire("click"); await tick(); allowed.reply({ isDownload: true }); await tick();
  assert.equal(allowed.opens.length, 1); assert.equal(allowed.opens[0][0], allowed.destination);
  const err = fixture(); err.fire("click"); await tick(); err.reject(); await tick();
  assert.equal(err.opens.length, 0); err.fire("click"); await tick();
  assert.equal(err.probes(), 2); err.reply({ isDownload: null }); await tick();
  assert.equal(err.opens.length, 1);
  console.log("PASS: stale navigation/transaction/new guard cannot replay; confirmed downloads block once; rejected probe can retry");
}
main().catch(e => { console.error(e); process.exitCode = 1; });
