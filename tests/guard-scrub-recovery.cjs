"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
class Element {
  constructor(tagName, attrs = {}) {
    this.tagName = tagName; this.nodeType = 1; this.attrs = new Map(Object.entries(attrs));
    this.dataset = {}; this.isConnected = true; this.parentNode = null; this.children = [];
    const styles = new Map();
    this.style = { getPropertyValue: k => styles.get(k)?.value || "", getPropertyPriority: k => styles.get(k)?.priority || "",
      setProperty: (k, value, priority) => styles.set(k, { value, priority }), removeProperty: k => styles.delete(k) };
  }
  getAttribute(k) { return this.attrs.get(k) ?? null; } hasAttribute(k) { return this.attrs.has(k); }
  setAttribute(k, value) { this.attrs.set(k, value); } removeAttribute(k) { this.attrs.delete(k); }
  remove() { this.isConnected = false; }
  querySelector() { return null; } closest() { return null; }
  appendChild(node) { return this.insertBefore(node, null); }
  insertBefore(node, ref) {
    if (node.parentNode) node.parentNode.removeChild(node);
    const index = ref ? this.children.indexOf(ref) : this.children.length;
    assert.ok(index >= 0); this.children.splice(index, 0, node); node.parentNode = this; return node;
  }
  removeChild(node) { this.children.splice(this.children.indexOf(node), 1); node.parentNode = null; return node; }
  replaceChild(node, old) { this.insertBefore(node, old); this.removeChild(old); return old; }
  append(...children) { for (const node of children) this.appendChild(node); }
}
const nodes = [], kit = new Element("DIV"), document = { querySelectorAll(selector) {
  if (selector.startsWith(".dlp-overlay")) return [kit];
  if (selector.startsWith("a[download]")) return nodes;
  if (selector.startsWith("[data-silverfox-greyed")) return nodes.filter(n => n.dataset.silverfoxGreyed === "1" || n.hasAttribute("data-threat-original-href"));
  return [];
} };
const hooks = { PageContext: {}, CloakingKit: { isDesktopForceDownloadKitBlob: () => false, isDesktopForceDownloadNode: node => !!node.kit },
  PackageHeuristics: { isPackageFileUrl: u => /\.(?:zip|exe)$/.test(u), isStrongProductInstallerUrl: () => false } };
const context = vm.createContext({ window: { SilverfoxPageHooks: hooks }, document, Element, Node: Element });
for (const name of ["download-ui", "dom-guard"]) vm.runInContext(fs.readFileSync(path.join(__dirname, `../extension/page-hooks/${name}.js`), "utf8"), context);
const guard = hooks.DomGuard, ui = hooks.DownloadUi;
const policy = { guardEnabled: true, forceDesktopDlKit: false, lightPage: false, officialSafe: false,
  isLightPage: () => false, post() {}, _rememberHop() {}, armDesktopForceDownloadKit() {} };
const link = new Element("A", { href: "https://example.test/source.zip", download: "source.zip" });
const frames = ["IFRAME", "EMBED", "OBJECT"].map(tag => new Element(tag, {
  [tag === "OBJECT" ? "data" : "src"]: "https://example.test/setup.exe", style: "display:none", type: "application/octet-stream"
}));
nodes.push(link, ...frames);
for (const inactive of [undefined, { ...policy, guardEnabled: false }, { ...policy, officialSafe: true }, { ...policy, lightPage: true }]) {
  guard.scrubDesktopForceDownloadDom(inactive);
  assert.equal(link.getAttribute("href"), "https://example.test/source.zip"); assert.equal(kit.isConnected, true);
}
guard.scrubDesktopForceDownloadDom(policy);
assert.equal(kit.isConnected, false, "actual kit overlay must still be scrubbed");
assert.equal(link.isConnected, true); assert.equal(link.getAttribute("href"), null);
assert.equal(link.getAttribute("download"), "source.zip");
assert.equal(link.getAttribute("data-threat-original-href"), "https://example.test/source.zip");
assert.equal(link.dataset.silverfoxGreyed, "1", "download button remains disabled while guarded");
for (const frame of frames) { assert.equal(frame.isConnected, true); assert.equal(frame.getAttribute("src"), null); assert.equal(frame.getAttribute("data"), null); }
guard.scrubDesktopForceDownloadDom(policy);
assert.equal(link.getAttribute("data-threat-original-href"), "https://example.test/source.zip", "repeat scrub cannot overwrite original address");
policy.guardEnabled = false;
guard.restoreNeutralizedFrames(policy); ui.restoreAllDownloadButtonsInPage();
assert.equal(link.isConnected, true); assert.equal(link.getAttribute("href"), "https://example.test/source.zip");
assert.equal(link.getAttribute("download"), "source.zip"); assert.equal(link.dataset.silverfoxGreyed, undefined);
for (const frame of frames) assert.equal(frame.getAttribute(frame.tagName === "OBJECT" ? "data" : "src"), "https://example.test/setup.exe");
console.log("PASS: inactive/safe scrub does nothing; normal ZIP/download controls and frames survive blocking and recover, kit overlay removed");

guard._wrapInsertMethods(policy, []);
for (const method of ["appendChild", "insertBefore", "replaceChild", "append"]) {
  policy.guardEnabled = true;
  const parent = new Element("DIV"), ref = new Element("DIV"); parent.appendChild(ref);
  const injected = new Element("A", { href: "https://example.test/source.zip", download: "source.zip" });
  nodes.push(injected);
  parent[method](injected, ...(method === "insertBefore" || method === "replaceChild" ? [ref] : []));
  assert.equal(injected.parentNode, parent, `${method}: ordinary anchor must remain in intended DOM position`);
  assert.equal(injected.getAttribute("href"), null);
  assert.equal(injected.getAttribute("data-threat-original-href"), "https://example.test/source.zip");
  assert.equal(injected.dataset.silverfoxGreyed, "1");
  assert.equal(injected.getAttribute("download"), "source.zip");
  policy.guardEnabled = false;
  ui.restoreAllDownloadButtonsInPage();
  assert.equal(injected.getAttribute("href"), "https://example.test/source.zip");
  assert.equal(injected.parentNode, parent); assert.equal(parent.children.filter(node => node === injected).length, 1);
}
policy.guardEnabled = true;
const kitAnchor = new Element("A", { href: "https://bad.example/file.exe" }); kitAnchor.kit = true;
const parent = new Element("DIV"); parent.appendChild(kitAnchor);
assert.equal(kitAnchor.parentNode, null, "actual kit injection must still be rejected");
const brokenAnchor = new Element("A", { href: "https://example.test/file.zip" });
brokenAnchor.removeAttribute = () => { throw new Error("cannot neutralize"); };
parent.appendChild(brokenAnchor);
assert.equal(brokenAnchor.parentNode, null, "failed neutralization must not insert a live download link");
console.log("PASS: dynamically inserted package anchors retain DOM placement/filename and recover; actual kits and failed neutralization remain blocked");
