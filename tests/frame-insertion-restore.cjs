"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
class Element {
  constructor(tag, attrs = {}) {
    this.tagName = tag; this.nodeType = 1; this.parentNode = null; this.children = []; this.attrs = new Map(Object.entries(attrs));
    const styles = new Map();
    this.style = { getPropertyValue: k => styles.get(k)?.value || "", getPropertyPriority: k => styles.get(k)?.priority || "",
      setProperty: (k, value, priority) => styles.set(k, { value, priority }), removeProperty: k => styles.delete(k) };
  }
  getAttribute(k) { return this.attrs.get(k) ?? null; } hasAttribute(k) { return this.attrs.has(k); }
  setAttribute(k, v) { this.attrs.set(k, v); } removeAttribute(k) { this.attrs.delete(k); }
  closest() { return null; } querySelector() { return null; }
  appendChild(node) { return this.insertBefore(node, null); }
  insertBefore(node, ref) {
    if (node.parentNode) node.parentNode.removeChild(node);
    const index = ref ? this.children.indexOf(ref) : this.children.length;
    assert.ok(index >= 0); this.children.splice(index, 0, node); node.parentNode = this; return node;
  }
  replaceChild(node, old) { this.insertBefore(node, old); this.removeChild(old); return old; }
  removeChild(node) { this.children.splice(this.children.indexOf(node), 1); node.parentNode = null; return node; }
  append(...nodes) { for (const node of nodes) this.appendChild(node); }
}
class Frame extends Element {
  constructor() { super("IFRAME"); }
  get srcdoc() { return this.getAttribute("srcdoc") || ""; }
  set srcdoc(value) { this.setAttribute("srcdoc", value); }
}
class ObjectFrame extends Element {
  constructor() { super("OBJECT"); }
  get data() { return this.getAttribute("data") || ""; }
  set data(value) { this.setAttribute("data", value); }
}
const hooks = { PackageHeuristics: { isPackageFileUrl: u => /\.exe$/.test(u), isStrongProductInstallerUrl: () => false },
  PageContext: {}, CloakingKit: { isDesktopForceDownloadNode: node => !!node.kit, isDesktopForceDownloadKitBlob: () => false } };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../extension/page-hooks/dom-guard.js"), "utf8"), {
  window: { SilverfoxPageHooks: hooks }, Element, Node: Element, HTMLIFrameElement: Frame, HTMLObjectElement: ObjectFrame
});
const guard = hooks.DomGuard, policy = { guardEnabled: true, forceDesktopDlKit: false, isLightPage: () => false,
  post() {}, _rememberHop() {}, _emitBlocked() {}, _shouldBlockUrl: () => false, armDesktopForceDownloadKit() {} };
guard._patchSetAttribute(policy, []);
guard._patchIframeSrcProto(policy, []);
guard._wrapInsertMethods(policy, []);
for (const tag of ["IFRAME", "EMBED", "OBJECT"]) {
  for (const method of ["appendChild", "insertBefore", "replaceChild", "append"]) {
    for (const destination of ["https://example.test/player", "https://example.test/Setup.exe"]) {
      policy.guardEnabled = true;
      const parent = new Element("DIV"), ref = new Element("DIV"); parent.appendChild(ref);
      const attrs = tag === "OBJECT" ? { data: destination, type: "text/html" } : { src: destination };
      const frame = new Element(tag, attrs);
      parent[method](frame, ...(method === "insertBefore" || method === "replaceChild" ? [ref] : []));
      assert.equal(frame.parentNode, parent, `${tag} ${method}: inert frame must occupy original DOM position`);
      if (method === "insertBefore") assert.equal(parent.children[0], frame);
      if (method === "replaceChild") assert.equal(ref.parentNode, null);
      assert.equal(frame.getAttribute("src"), null); assert.equal(frame.getAttribute("data"), null);
      if (tag === "IFRAME") assert.equal(frame.getAttribute("srcdoc"), "<!--sf-blocked-->");
      guard.restoreNeutralizedFrames(policy); assert.equal(frame.getAttribute("src"), null);
      policy.guardEnabled = false; guard.restoreNeutralizedFrames(policy);
      assert.equal(frame.parentNode, parent);
      for (const [key, value] of Object.entries(attrs)) assert.equal(frame.getAttribute(key), value);
      assert.equal(parent.children.filter(node => node === frame).length, 1);
      guard.restoreNeutralizedFrames(policy); assert.equal(parent.children.filter(node => node === frame).length, 1);
    }
  }
}
policy.guardEnabled = true;
const parent = new Element("DIV"), kit = new Element("IFRAME", { src: "https://bad.example/payload.exe" }); kit.kit = true;
parent.appendChild(kit); assert.equal(kit.parentNode, null, "actual malicious kit nodes must still be rejected");
const broken = new Element("IFRAME", { src: "https://bad.example/unmodified" });
broken.removeAttribute = () => { throw new Error("cannot neutralize"); };
parent.appendChild(broken); assert.equal(broken.parentNode, null, "never insert a frame if resource neutralization failed");
console.log("PASS: inert iframe/embed/object insertion preserves append/insert/replace order and restores once; kit and failed neutralization still rejected");

for (const mode of ["property", "attribute"]) {
  policy.guardEnabled = true;
  const parent = new Element("DIV"), frame = new Frame(), object = new ObjectFrame();
  parent.appendChild(frame); parent.appendChild(object);
  const markup = "<p>Requested embedded content</p>", destination = "https://example.test/object";
  if (mode === "property") { frame.srcdoc = markup; object.data = destination; }
  else { frame.setAttribute("srcdoc", markup); object.setAttribute("data", destination); }
  assert.equal(frame.srcdoc, "<!--sf-blocked-->", "later srcdoc must not activate an inert frame");
  assert.equal(object.data, "", "later object.data must remain held");
  policy.guardEnabled = false; guard.restoreNeutralizedFrames(policy);
  assert.equal(frame.srcdoc, markup); assert.equal(object.data, destination);
  assert.equal(frame.parentNode, parent); assert.equal(object.parentNode, parent);
}
console.log("PASS: later srcdoc/object.data writes remain inert through property and setAttribute paths, then restore on unlock");
