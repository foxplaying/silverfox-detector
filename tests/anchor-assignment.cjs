"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
let clicks = 0, armed = 0, probes = 0, blocked = 0;
class Element {
  constructor(tag) { this.tagName = tag; this.attrs = new Map(); this.style = { setProperty() {} }; }
  setAttribute(k, v) { this.attrs.set(k.toLowerCase(), String(v)); }
  getAttribute(k) { return this.attrs.get(k) || null; }
}
class Anchor extends Element {
  constructor() { super("A"); }
  get href() { return this.getAttribute("href") || ""; }
  set href(v) { this.attrs.set("href", String(v)); }
  click() { clicks++; }
}
const document = { createElement: tag => tag.toLowerCase() === "a" ? new Anchor() : new Element(tag.toUpperCase()) };
const hooks = { PageContext: { isSearchUrlShapeOnly: () => false, pageLooksLikeSerpUrl: () => false },
  CloakingKit: {}, PackageHeuristics: {
    isPackageFileUrl: u => /\.zip$/.test(u), isStrongProductInstallerUrl: () => false,
    looksLikeOpaqueDownloadHopUrl: () => false, looksLikeObjectStoragePackageUrl: () => true
  } };
const policy = { guardEnabled: false, forceDesktopDlKit: false, blockedHops: new Set(),
  noteTrustedDownloadIntent() {}, armDesktopForceDownloadKit() { armed++; }, _rememberHop() {},
  _emitBlocked() { blocked++; }, post() {}, _shouldBlockUrl: () => true,
  tryBlockNavigation() { probes++; return policy.guardEnabled; }, _tryBlock: () => false };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../extension/page-hooks/dom-guard.js"), "utf8"), {
  window: { SilverfoxPageHooks: hooks }, document, Element, HTMLElement: Element, HTMLAnchorElement: Anchor
});
hooks.DomGuard._wrapCreateElement(policy, []);
hooks.DomGuard._patchSetAttribute(policy, []);
const url = "https://bucket.oss-cn.example.test/source.zip";
const a = document.createElement("a");
assert.equal(Object.hasOwn(a, "href"), true); assert.equal(Object.hasOwn(Element.prototype, "__silverfoxSetAttr"), true);
a.href = url; assert.equal(a.href, url);
a.setAttribute("href", url + "?v=1"); assert.equal(a.href, url + "?v=1");
const area = new Element("AREA"); area.setAttribute("href", url); assert.equal(area.getAttribute("href"), url);
assert.equal(armed, 0); assert.equal(blocked, 0); assert.equal(probes, 0);
a.click(); assert.equal(probes, 1); assert.equal(clicks, 1);
policy.guardEnabled = true;
a.click(); assert.equal(clicks, 1);
const guarded = document.createElement("a"); guarded.href = url;
assert.equal(guarded.href, ""); guarded.setAttribute("href", url); assert.equal(guarded.href, "");
assert.equal(blocked, 2); assert.equal(armed, 0);
console.log("PASS: assigning anchor/area URL is inert; navigation is still checked; active guard still rejects package URLs");
