"use strict";
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const source = name => fs.readFileSync(path.join(__dirname, "../extension", name), "utf8");

async function firstVisit({ hit = false, accepted = false, stale = false } = {}) {
  const state = { protectedTargets: [], _analysisTxn: "first" }, el = { disabled: false };
  const location = new URL("https://portal.example/");
  const NS = { state }, context = { window: { SilverfoxContent: NS }, location, URL };
  vm.runInNewContext(source("content/brand-spoof-detector.js"), context);
  const href = "https://portal.example/download", pkg = "https://cdn.example/client.zip";
  let respond, requests = 0, arms = 0;
  Object.assign(NS, {
    collectProactiveDownloadTargets: () => ({ landing: [{ href, el }], probe: [] }),
    getParentPageBrandSpoofContext: () => ({}),
    fetchWithRedirectChain() { requests++; return new Promise(resolve => { respond = resolve; }); },
    analyzeFetchedDownloadLandingHtml: () => ({ hit, staticPackageLanding: hit, packages: [pkg] }),
    installDownloadGuard() { arms++; return state.downloadGuardInstalled = accepted; },
    disableOneSuspiciousElement(node) { node.disabled = true; },
    disableAllDownloadIntentControls() { el.disabled = true; },
    addSignal() {}, emitRiskReport() {}
  });
  const scan = () => NS.proactivelyProbeDownloadButtons({ force: true });
  const task = scan();
  assert.equal(requests, 1);
  assert.equal(await scan(), false); assert.equal(await scan(), false);
  assert.equal(requests, 1, "overlapping scans must not release the owner's busy flag");
  if (stale) state._analysisTxn = "next";
  respond({ chain: [], finalText: "download ".repeat(8) });
  assert.equal(await task, accepted && !stale);
  assert.equal(arms, Number(hit && !stale));
  assert.equal(el.disabled, accepted && !stale);
  assert.deepEqual(state.protectedTargets, accepted && !stale ? [pkg] : []);
}

async function main() {
  await firstVisit(); // ordinary package on a clean landing
  await firstVisit({ hit: true }); // soft verdict deferred/rejected
  await firstVisit({ hit: true, accepted: true });
  await firstVisit({ hit: true, accepted: true, stale: true });
  for (const world of ["content", "page-hooks"]) {
    const frameButton = { dataset: {}, disabled: false, tagName: "BUTTON", textContent: "Download",
      getAttribute: () => null, setAttribute() {}, removeAttribute() {}, addEventListener() {},
      style: { setProperty() {}, removeProperty() {} } };
    const childOnly = { ...frameButton, disabled: true, dataset: { silverfoxGreyed: "1" } };
    const frameDoc = { querySelectorAll: s => s.includes("data-silverfox-greyed")
      ? [frameButton, childOnly] : [frameButton] };
    const document = { querySelectorAll: s => s === "iframe" ? [{ contentDocument: frameDoc }] : [] };
    const window = {};
    vm.runInNewContext(source(world === "content" ? "content/guard.js" : "page-hooks/download-ui.js"), { window, document });
    if (world === "content") {
      vm.runInNewContext(source("content/package-heuristics.js"), { window, document });
      const NS = window.SilverfoxContent;
      Object.assign(NS, { state: { downloadGuardInstalled: true, protectedTargets: [] },
        getAllDownloadIntentElements: () => [], isDownloadIntentElement: () => true });
      NS.disableAllDownloadIntentControls(); assert.equal(frameButton.disabled, true);
      NS.state.downloadGuardInstalled = false;
      NS.reEnableAllThreatDisabledElements();
    } else {
      const hooks = window.SilverfoxPageHooks;
      hooks.PageContext = { pageLooksLikeSerpUrl: () => false };
      hooks.DownloadUi.disableAllDownloadButtonsInPage(); assert.equal(frameButton.disabled, true);
      hooks.DownloadUi.restoreAllDownloadButtonsInPage();
    }
    assert.equal(frameButton.disabled, false, world + " must restore same-origin frame controls on unlock");
    assert.equal(childOnly.disabled, true, world + " must leave child-only locks intact");
  }
  console.log("PASS: first-load clean, deferred, stale and confirmed verdicts; iframe unlock without reload");
}
main().catch(err => { console.error(err); process.exitCode = 1; });
