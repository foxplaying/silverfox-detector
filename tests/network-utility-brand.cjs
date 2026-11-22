"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8").replace(/\r\n/g, "\n");
const slice = (file, first, last) => {
  const s = read(file), a = s.indexOf(first), b = s.indexOf(last, a + first.length);
  assert.ok(a >= 0 && b > a); return s.slice(a, b);
};
const element = (text, attrs = {}) => ({ textContent: text, className: "", getAttribute: (k) => attrs[k] || null });
const app = element("下载APP", { href: "https://app.example.test/llxsq_v1.0.4.apk" });
const run = element("开始");
const meta = element("", { content: "web版流量杀手，消耗流量和测速的小工具" });
let hasControls = true;
let html = `<!-- <a href="https://old.test/Old_Setup.exe">旧测速源</a> -->
  <select><option value="https://test.test/BaiduNetdisk_7.54.exe">百度网盘</option>
  <option value='https://test.test/iQIYIMedia_000.dmg'>爱奇艺</option></select>
  <a href="${app.getAttribute("href")}">下载APP</a>`;
const document = {
  title: "流量消失器",
  body: { textContent: "测速源 自定义链接 运行线程 每秒实时流量 已运行时长 开始 停止" },
  querySelector(selector) {
    if (selector === 'meta[name="description"]') return meta;
    if (selector === "select option[value], input[type='url']") return hasControls ? {} : null;
    return null;
  },
  querySelectorAll(selector) {
    if (selector.startsWith("button, [role='button']")) return hasControls ? [run] : [];
    if (selector.startsWith("a[href], a[data-href], a[data-url], [data-download]")) return [app];
    if (selector.startsWith("a[href],") || selector === "a[href]") return [app, run];
    return [];
  },
  getElementById() { return null; }
};
const NS = { state: { details: [], score: 0, signalSet: new Set(), protectedTargets: [] },
  PACKAGE_EXT: /\.(zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|$)/i,
  PACKAGE_NAME: /\.(zip|exe|apk|dmg|msi|rar|7z)$/i,
  DOWNLOAD_TEXT: /下载|download|安装/i,
  getThreatScanHtml: () => html, getHtmlSlice: () => html,
  collectHeadingText: () => "",
  getRegistrableDomain: (h) => h.split(".").slice(-2).join("."),
  looksLikeSafeOfficialContext: () => false, looksLikeMatureOfficialPortal: () => false
};
const ctx = vm.createContext({ window: { SilverfoxContent: NS }, NS, document, URL, console,
  location: new URL("https://unrelated.example.test/"), _silverfoxDebug: false });
for (const file of ["page-context.js", "package-heuristics.js", "brand-spoof-detector.js"]) {
  vm.runInContext(read(`extension/content/${file}`), ctx);
}
vm.runInContext(slice("extension/content/state.js", "  NS.addSignal =", "  /**\n   * 缓存页面 HTML"), ctx);
// Keep unrelated classifiers out of this fixture; execute production utility/shell logic.
for (const key of ["pageLooksLikeSearchEngineResultsPage", "pageLooksLikeAppMarketOrAppStoreListing",
  "pageLooksLikeSoftwareCatalogPortal", "pageLooksLikeBareJsAppShell", "pageLooksLikeEditorialArticleOrNewsPost",
  "pageLooksLikeHighVolumePackageArchive"]) NS[key] = () => false;
NS.pageClaimsOfficialDownload = () => /官网/.test(document.title);
NS.pageClaimsBrandDownloadLanding = () => /官网/.test(document.title);
NS.evaluateDomainKeywordRelevance = () => ({ related: false, mismatch: true, hostMatch: "none", brand: "流量消失器" });
assert.equal(NS.pageLooksLikeInteractiveNetworkUtility(), true);
assert.equal(NS.evaluateSoftwareDownloadLandingShell().ok, false);
assert.equal(NS.getParentPageBrandSpoofContext().mismatch, false);
assert.equal(NS.canPresentSoftBrandSpoofNotice(), false);
const packageBrandGate = slice("extension/content/scanner.js", "        const networkUtility =", "        if (brandish)");
const proactiveBrandGate = slice("extension/content/brand-spoof-detector.js", "      const parentCtx =", "      if (parentBrand &&");
const checkFallbacks = (expected) => {
  const env = { NS, document, location: ctx.location, state: NS.state, pkgHitBrandNear: true,
    brandTok: "流量消失器", titleHot: true };
  assert.equal(vm.runInNewContext(packageBrandGate + "\nbrandish;", { ...env }), expected);
  assert.equal(vm.runInNewContext(proactiveBrandGate + "\nparentMismatch;", { ...env }), expected);
};
checkFallbacks(false);
assert.deepEqual(Array.from(NS.collectAllPagePackageHrefs()), [app.getAttribute("href")]);
// Samples/comments cannot trigger embedded-package detection; genuine app still can.
NS.isEmbeddedPackageThreat = (name) => /BaiduNetdisk|iQIYI|Old_Setup/.test(name);
assert.equal(NS.scanEmbeddedPackageThreats(), null);
NS.isEmbeddedPackageThreat = (name) => /llxsq/.test(name);
assert.match(NS.scanEmbeddedPackageThreats(), /llxsq/);
// No blanket site trust: download handlers and scripts retain their evidence.
html += `<button onclick="location.href='https://bad.test/Evil_Setup.exe'">下载</button>
  <script><!--\nlocation.href='https://bad.test/Script_Setup.exe';\n//--></script>
  <option value="https://test.test/Sample.exe" onclick="location.href='https://bad.test/Handler_Setup.exe'">样本</option>`;
const urls = NS.collectAllPagePackageHrefs();
for (const name of ["Evil_Setup.exe", "Script_Setup.exe", "Handler_Setup.exe"]) assert.ok(urls.some(u => u.endsWith(name)), name);
assert.ok(!urls.some(u => u.endsWith("Sample.exe")));
NS.hasRealHardKitThreat = () => true;
assert.equal(NS.canPresentSoftBrandSpoofNotice(), true);
NS.hasRealHardKitThreat = () => false;
// Identity/functional words alone cannot exempt a page without actual controls.
hasControls = false;
assert.equal(NS.pageLooksLikeInteractiveNetworkUtility(), false);
hasControls = true;
document.title = "流量消失器 官方下载";
assert.equal(NS.pageLooksLikeInteractiveNetworkUtility(), false);
assert.equal(NS.evaluateSoftwareDownloadLandingShell().ok, true);
assert.equal(NS.getParentPageBrandSpoofContext().mismatch, true);
checkFallbacks(true);
console.log("PASS: network utility samples are not brand-spoof evidence; real downloads/hard threats remain inspectable");

const name = "仿冒品牌官网下载站";
NS.addSignal("无ICP备案信息", 10, "independent");
NS.addSignal(name, 20, "package-path");
NS.addSignal(name, 24, "brand-path");
assert.equal(NS.state.score, 34);
assert.equal(NS.state.details.filter(d => d.name === name).length, 1);
assert.equal(NS.addSignal(name, 18, "weaker-path"), false);
assert.equal(NS.state.score, 34);
assert.equal(NS.state.details.find(d => d.name === name).reason, "brand-path");
assert.deepEqual(Array.from(NS.state.signalSet), ["无ICP备案信息:10", `${name}:24`]);
NS.state.details.push({ name, weight: 20, reason: "old duplicate" });
NS.state.signalSet.add(`${name}:20`); NS.state.score += 20;
NS.addSignal(name, 18, "weaker-path");
assert.equal(NS.state.score, 34); assert.equal(NS.state.details.length, 2);
console.log("PASS: correlated brand verdict uses max weight, normalizes old duplicates, preserves independent signals");
