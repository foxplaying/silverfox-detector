"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
function element(tag, attrs = {}) {
  const data = new Map(Object.entries(attrs)), styles = new Map([
    ["pointer-events", "none"], ["opacity", "0"], ["filter", "blur(1px)"], ["cursor", "wait"]
  ]);
  let writes = 0, disabled = true;
  const el = { tagName: tag, dataset: {}, textContent: "下载客户端", className: "", id: "",
    getAttribute: k => data.get(k) ?? null,
    setAttribute(k, v) { writes++; data.set(k, v); }, removeAttribute(k) { writes++; data.delete(k); },
    style: { removeProperty(k) { writes++; styles.delete(k); }, setProperty(k, v) { writes++; styles.set(k, v); } },
    get disabled() { return disabled; }, set disabled(v) { writes++; disabled = v; },
    writes: () => writes, styles, classList: { remove() {} }
  };
  return el;
}
for (const mode of ["page-hooks", "content"]) {
  const nativePause = element("BUTTON", { "aria-label": "暂停", "aria-disabled": "true" });
  const nativePlay = element("A", { href: "javascript:void(0)", title: "播放" });
  const nativeDownload = element("BUTTON", { "aria-disabled": "true" });
  const guarded = element("BUTTON", { "aria-disabled": "true" });
  guarded.dataset.silverfoxGreyed = "1";
  const link = element("A", { href: "javascript:void(0)", "data-threat-original-href": "https://cdn.example/setup.exe" });
  const nodes = [nativePause, nativePlay, nativeDownload, guarded, link], selectors = [];
  // Return a superset too: direct ownership checks must protect against unrelated elements.
  const document = { querySelectorAll(selector) { selectors.push(selector); return nodes; } };
  let restore, restoreOne;
  if (mode === "page-hooks") {
    const NS = {};
    vm.runInNewContext(read("extension/page-hooks/download-ui.js"), { window: { SilverfoxPageHooks: NS }, document });
    restore = NS.DownloadUi.restoreAllDownloadButtonsInPage;
    restoreOne = NS.DownloadUi.restoreGreyed;
  } else {
    const NS = { getAllDownloadIntentElements() { throw new Error("must not scan unowned controls"); } };
    const source = read("extension/content/guard.js");
    const start = source.indexOf("  NS.reEnableOneThreatElement =");
    const end = source.indexOf("  NS.noteHardThreatFromArm =", start);
    assert.ok(start >= 0 && end > start);
    vm.runInNewContext(source.slice(start, end), { NS, document });
    restore = NS.reEnableAllThreatDisabledElements;
    restoreOne = NS.reEnableOneThreatElement;
  }
  restore();
  assert.equal(guarded.disabled, false); assert.equal(guarded.dataset.silverfoxGreyed, undefined);
  assert.equal(link.getAttribute("href"), "https://cdn.example/setup.exe");
  assert.equal(link.getAttribute("data-threat-original-href"), null);
  const after = nodes.map(el => el.writes());
  // Official-safe / clear-guard schedules multiple restoration passes.
  for (let i = 0; i < 6; i++) restore();
  assert.deepEqual(nodes.map(el => el.writes()), after, "repeated restore must be a no-op");
  for (const el of [nativePause, nativePlay, nativeDownload]) {
    restoreOne(el);
    assert.equal(el.writes(), 0); assert.equal(el.disabled, true);
    assert.equal(el.styles.get("pointer-events"), "none"); assert.equal(el.styles.get("opacity"), "0");
  }
  for (const selector of selectors) {
    assert.doesNotMatch(selector, /button\[aria-disabled|a\[href='javascript|^a, button/);
  }
  console.log(`PASS: ${mode} restores only extension-owned controls; player/native disabled states untouched across repeated cleanup`);
}
