"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
function section(file, from, to) {
  const s = read(file), a = s.indexOf(from), b = s.indexOf(to, a + from.length);
  assert.ok(a >= 0 && b > a); return s.slice(a, b);
}
class Element {
  constructor(tag, attrs = {}) {
    this.tagName = tag; this.nodeType = 1; this.isConnected = true;
    this.attrs = new Map(Object.entries(attrs)); this.dataset = {}; this.writes = 0;
    const styles = new Map();
    this.style = { getPropertyValue: k => styles.get(k)?.value || "", getPropertyPriority: k => styles.get(k)?.priority || "",
      setProperty: (k, value, priority) => { this.writes++; styles.set(k, { value, priority }); },
      removeProperty: k => { this.writes++; styles.delete(k); } };
  }
  getAttribute(k) { return this.attrs.get(k) ?? null; }
  hasAttribute(k) { return this.attrs.has(k); }
  setAttribute(k, v) { this.writes++; this.attrs.set(k, v); }
  removeAttribute(k) { this.writes++; this.attrs.delete(k); }
  addEventListener() {}
  get href() { return this.getAttribute("href"); }
  set href(v) { this.setAttribute("href", v); }
}
class Frame extends Element {
  constructor(attrs) { super("IFRAME", attrs); }
  get src() { return this.getAttribute("src"); }
  set src(v) { this.setAttribute("src", v); }
}
const NS = {}, nodes = [], document = { querySelectorAll: () => nodes };
const shared = read("extension/shared/control-state.js");
vm.runInNewContext(shared + section("extension/content/guard.js", "  NS.disableOneSuspiciousElement =", "  NS.noteHardThreatFromArm ="), { NS, document });
const hooksForControls = {};
vm.runInNewContext(shared + read("extension/page-hooks/download-ui.js"), { window: { SilverfoxPageHooks: hooksForControls }, document });
for (const order of ["main-content", "content-main", "main", "content"]) {
  const button = new Element("BUTTON", { "aria-disabled": "true", title: "Site-owned title" });
  button.disabled = true;
  button.style.setProperty("opacity", "0.8", "important");
  button.style.setProperty("cursor", "wait", "");
  const ui = hooksForControls.DownloadUi;
  for (const layer of order.split("-")) {
    if (layer === "main") { ui.greyOut(button); ui.greyOut(button); }
    else { NS.disableOneSuspiciousElement(button); NS.disableOneSuspiciousElement(button); }
  }
  nodes.push(button); ui.restoreAllDownloadButtonsInPage(); NS.reEnableOneThreatElement(button);
  assert.equal(button.disabled, true); assert.equal(button.getAttribute("aria-disabled"), "true");
  assert.equal(button.getAttribute("title"), "Site-owned title");
  assert.equal(button.style.getPropertyValue("opacity"), "0.8");
  assert.equal(button.style.getPropertyPriority("opacity"), "important");
  assert.equal(button.style.getPropertyValue("cursor"), "wait");
  assert.equal(button.style.getPropertyValue("filter"), "");
  assert.equal(button.dataset.silverfoxControlBefore, undefined);
  nodes.pop();
}
for (const placeholder of ["javascript:void(0)", "about:blank", "about:black"]) {
  const link = new Element("A", { href: "https://example.test/original" });
  for (let i = 0; i < 5; i++) {
    NS.disableOneSuspiciousElement(link, link.href);
    link.href = placeholder;
  }
  assert.equal(link.getAttribute("data-threat-original-href"), "https://example.test/original");
  NS.reEnableOneThreatElement(link);
  assert.equal(link.href, "https://example.test/original");
  const writes = link.writes; NS.reEnableOneThreatElement(link); assert.equal(link.writes, writes);
}
console.log("PASS: repeated disabling cannot overwrite original href with javascript/about:blank placeholders");

const hooks = { PackageHeuristics: { isPackageFileUrl: u => /\.exe$/.test(u), isStrongProductInstallerUrl: () => false,
  looksLikeObjectStoragePackageUrl: () => false }, PageContext: {} };
vm.runInNewContext(read("extension/page-hooks/dom-guard.js"), {
  window: { SilverfoxPageHooks: hooks }, document, Element, HTMLIFrameElement: Frame
});
const guard = hooks.DomGuard;
const content = { caches: {}, isTopFrame: () => true };
let now = 1000;
vm.runInNewContext(section("extension/content/state.js", "  const lockedFrames", "  NS.addSignal"), {
  NS: content, document, Date: { now: () => now }
});
const policy = { guardEnabled: true, forceDesktopDlKit: false, _shouldBlockUrl: () => true,
  _rememberHop() {}, _emitBlocked() {}, post() {}, tryBlockNavigation: () => false };
for (const first of ["main", "content"]) {
  for (const tag of ["IFRAME", "EMBED", "OBJECT"]) {
    const attrs = { src: "https://example.test/frame", sandbox: "allow-scripts", allow: "fullscreen", type: "text/html" };
    if (tag === "OBJECT") attrs.data = "https://example.test/object";
    if (tag === "IFRAME") attrs.srcdoc = "<p>Original embedded page</p>";
    const el = new Element(tag, attrs); nodes.splice(0, nodes.length, el);
    policy.guardEnabled = true; now += 1000;
    if (first === "main") { guard.neutralizeFrameEl(el); content.neutralizePageFramesForGuard(true); }
    else { content.neutralizePageFramesForGuard(true); guard.neutralizeFrameEl(el); }
    const writes = el.writes;
    for (let i = 0; i < 4; i++) { now += 1000; guard.neutralizeFrameEl(el); content.neutralizePageFramesForGuard(true); }
    assert.equal(el.writes, writes, "locking must be idempotent");
    guard.restoreNeutralizedFrames(policy); assert.equal(el.writes, writes, "active guard must not restore");
    content.neutralizePageFramesForGuard(false);
    policy.guardEnabled = false; guard.restoreNeutralizedFrames(policy);
    for (const [key, value] of Object.entries(attrs)) assert.equal(el.getAttribute(key), value, `${first} ${tag} ${key}`);
    assert.equal(el.hasAttribute("data-silverfox-frame-locked"), false);
    assert.equal(el.hasAttribute("data-silverfox-frame-owner"), false);
    const restored = el.writes;
    content.neutralizePageFramesForGuard(false); guard.restoreNeutralizedFrames(policy);
    assert.equal(el.writes, restored, "unlocked frames must not reload on cleanup");
  }
}
console.log("PASS: either guard layer may lock first; iframe/embed/object originals survive and restore exactly once");

guard._patchSetAttribute(policy, []);
guard._patchIframeSrcProto(policy, []);
for (const setter of ["property", "attribute"]) {
  const frame = new Frame({ src: "about:blank", sandbox: "allow-scripts" });
  policy.guardEnabled = true;
  const destination = "https://example.test/Setup.exe";
  if (setter === "property") frame.src = destination;
  else frame.setAttribute("src", destination);
  assert.equal(frame.getAttribute("srcdoc"), "<!--sf-blocked-->");
  policy.guardEnabled = false; policy.forceDesktopDlKit = true;
  guard.restoreNeutralizedFrames(policy); assert.equal(frame.getAttribute("srcdoc"), "<!--sf-blocked-->");
  policy.forceDesktopDlKit = false;
  guard.restoreNeutralizedFrames(policy);
  assert.equal(frame.src, destination, "pending URL must survive a stale hop cache during unlock");
  assert.equal(frame.getAttribute("srcdoc"), null); assert.equal(frame.getAttribute("sandbox"), "allow-scripts");
}
console.log("PASS: blocked src property/setAttribute preserves pending destination; hard locks remain; cleared guard restores through stale cache");

// Production content bridge must invoke frame restoration when guard is cleared.
const source = read("extension/page-hooks/index.js"), a = source.indexOf("    _installContentBridge() {"),
  b = source.indexOf("\n  NS.PageHooks =", a);
assert.ok(a >= 0 && b > a);
let receive;
const window = { addEventListener(_type, fn) { receive = fn; } };
const bridgePolicy = { ...policy, guardEnabled: true, syncNavBoot() {}, blockedHops: new Set() };
const frame = new Frame({ src: "https://example.test/bridge" }); guard.neutralizeFrameEl(frame);
vm.runInNewContext(`class Fixture { ${source.slice(a, b)}
const instance = new Fixture(); instance.policy = policy; instance._installContentBridge();`, {
  window, policy: bridgePolicy, CONTENT_SOURCE: "fixture", DomGuard: guard, NS: {},
  DownloadUi: { restoreAllDownloadButtonsInPage() {} }, setTimeout() {}, document
});
receive({ source: window, data: { source: "fixture", type: "set-guard", enabled: false } });
assert.equal(frame.src, "https://example.test/bridge"); assert.equal(frame.hasAttribute("srcdoc"), false);
console.log("PASS: actual set-guard(false) bridge restores frame URL");
