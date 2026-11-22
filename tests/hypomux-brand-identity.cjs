"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const read = (file) => fs.readFileSync(path.join(__dirname, "..", file), "utf8");

function brandPage(host, brand, title = `${brand} 官网`, h1 = brand) {
  const NS = { caches: {}, state: { details: [], signalSet: new Set(), protectedTargets: [] } };
  const location = new URL(`https://${host}/`);
  const meta = { "og:site_name": brand, "og:title": title, keywords: brand, description: `${brand} 开源软件` };
  const document = { title,
    querySelector(selector) {
      if (selector === "h1") return { textContent: h1 };
      const keys = [...selector.matchAll(/(?:name|property)="([^"]+)"/g)].map(m => m[1]);
      const key = keys.find(k => meta[k]);
      return key ? { getAttribute: () => meta[key] } : null;
    }, querySelectorAll: () => [] };
  const ctx = vm.createContext({ window: { SilverfoxContent: NS }, document, location, URL, console });
  for (const file of ["brand-domain-match.js", "brand-heuristics.js", "brand-correlation.js", "brand-spoof-detector.js"]) {
    vm.runInContext(read(`extension/content/${file}`), ctx);
  }
  NS.getRegistrableDomain = h => String(h).split(".").slice(-2).join(".");
  // Domain youth is risk context, not evidence that the exact spelling is padded.
  NS.isYoungUnverifiedRegistration = () => true;
  return NS;
}
for (const [title, h1] of [
  ["HypoMux 官网｜Windows 网络管理与诊断工具", "让每一条连接，都有更好的选择"],
  ["Windows 安装包下载与官方发布渠道 | HypoMux", "下载 HypoMux"]
]) {
  const NS = brandPage("hypomux.com", "HypoMux", title, h1);
  assert.equal(NS.apexLabelLooksLikeMarketingPaddedBrand("hypomux"), false);
  assert.equal(NS.pickHostAlignedLatinBrandFromPage("hypomux.com"), "HypoMux");
  const rel = NS.evaluateDomainKeywordRelevance();
  assert.equal(rel.related, true); assert.equal(rel.squat, false); assert.equal(rel.hostMatch, "exact");
  assert.equal(NS.getCleanApexMutualLatinExactEvidence("hypomux.com").displayBrand, "HypoMux");
  assert.equal(NS.detectBrandSpoofDownloadPortal(), false);
  assert.equal(NS.tryArmChineseBrandDownloadHomeSpoof(), false);
  // A stale soft flag is cleared by exact mutual identity, not turned into site trust.
  NS.state._brandSpoofPortalDetected = true; NS.state.spoofBrand = "错误品牌";
  assert.equal(NS.reconcileSoftBrandSpoofWithMutualLatinExact("hypomux.com"), true);
  assert.equal(NS.state._brandSpoofPortalDetected, false);
  NS.hasRealHardKitThreat = () => true;
  assert.equal(NS.reconcileSoftBrandSpoofWithMutualLatinExact("hypomux.com"), false);
}
for (const [brand, host] of [["Telegram", "telegram.org"], ["Asterflux", "asterflux.com"]]) {
  const NS = brandPage(host, brand);
  assert.equal(NS.evaluateDomainKeywordRelevance().related, true, host);
}
{
  const host = "app-todesk.com";
  const NS = brandPage(host, "ToDesk", "ToDesk远程桌面下载", "下载 ToDesk");
  assert.equal(NS.resolveHostBrandCore(host), "todesk");
  assert.equal(NS.resolveSpoofDisplayBrand(host), "ToDesk");
  const rel = NS.evaluateDomainKeywordRelevance();
  assert.equal(rel.related, false); assert.equal(rel.squat, true);
  assert.equal(NS.getCleanApexMutualLatinExactEvidence(host), null);
}
for (const [brand, host] of [["ToDesk", "todeskze.com"], ["ToDesk", "todeskx.com"],
  ["ToDesk", "to-desk.com"], ["ToDesk", "pc-todeskr.com"], ["Huorong", "huorongr.com"]]) {
  const NS = brandPage(host, brand), rel = NS.evaluateDomainKeywordRelevance();
  assert.equal(rel.related, false, host); assert.equal(rel.squat, true, `${host}: ${JSON.stringify(rel)}`);
  assert.equal(NS.getCleanApexMutualLatinExactEvidence(host), null, host);
}
console.log("PASS: HypoMux home/download exact identity; real page-brand padding remains suspicious; hard threats preserved");

// Exercise the actual content report serializer with an orphan portal flag.
const url = "https://hypomux.com/", messages = [];
const NS = { state: { score: 9, details: [{ name: "域名注册不足30天", weight: 9 }],
  signalSet: new Set(), protectedTargets: [], _analysisDone: true, _analysisTxn: "current",
  _analysisTxnUrl: url, _icpQuerySettled: true, _sslIdentitySettled: true, _sslIdentityUrl: url,
  _brandSpoofPortalDetected: true, spoofBrand: "", icpInfo: "备案查询失败" },
  caches: { intelDoneForUrl: url }, isBrandSpoofIdentityVerificationSettled: () => true };
vm.runInNewContext(read("extension/content/guard.js"), {
  window: { SilverfoxContent: NS }, document: {}, location: new URL(url), URL, console,
  chrome: { runtime: { id: "test", sendMessage: msg => messages.push(msg) } }
});
NS.emitRiskReport(true);
const report = messages.find(m => m.type === "threat-risk");
assert.ok(report); assert.equal(report.brandSpoofPortal, false);
assert.equal(report.spoofBrand, ""); assert.equal(report.brandFinalSnapshot, null);
assert.equal(report.score, 9); assert.equal(report.riskLevel, "low");
assert.equal(report.details[0].name, "域名注册不足30天");
console.log("PASS: orphan content flag cannot publish a spoof verdict; domain-age risk remains");

class Element {
  constructor() { this.children = []; this._text = ""; }
  appendChild(child) { this.children.push(child); return child; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(""); }
  set innerHTML(value) { this._text = String(value); this.children = []; }
}
const popupDocument = { createElement: () => new Element(), createTextNode: text => ({ textContent: text }), addEventListener() {} };
const ctx = { document: popupDocument, module: { exports: {} }, URL, console };
vm.runInNewContext(read("extension/popup/popup.js"), ctx);
const { PopupRenderer } = ctx.module.exports;
function render(data, notice = null) {
  const p = Object.create(PopupRenderer.prototype);
  Object.assign(p, { root: new Element(), activeTabId: 1, activeTabUrl: url,
    _activeRiskTxnByTab: new Map(), _lastCompletedByTab: new Map() });
  p.appendPackageVt = () => {}; p.requestRiskReportOnce = () => {};
  p.renderRisk(data, notice, url, null);
  return p.root.textContent;
}
const orphan = { ...report, brandSpoofPortal: true };
const snapshot = { final: true, brand: "HypoMux", url, analysisTxn: "current" };
const notice = { url, tabId: 1, analysisTxn: "current", timestamp: Date.now(), guardKind: "brand-spoof",
  title: "已识别仿冒「错误品牌」官网", message: "疑似仿冒官网" };
for (const brandFinalSnapshot of [null, { ...snapshot, final: false },
  { ...snapshot, url: "https://other.test/" }, { ...snapshot, analysisTxn: "old" }]) {
  const text = render({ ...orphan, brandFinalSnapshot }, notice);
  assert.doesNotMatch(text, /已识别仿冒|错误品牌/);
  assert.match(text, /评分: 9/); assert.match(text, /域名注册不足30天/);
}
// Even if other download protection is active, a stale brand notice cannot return.
assert.doesNotMatch(render({ ...orphan, downloadGuardInstalled: true }, notice), /已识别仿冒|错误品牌/);
const confirmed = { ...orphan, score: 30, brandFinalSnapshot: snapshot, downloadGuardInstalled: true };
assert.match(render(confirmed, notice), /已识别仿冒「HypoMux」官网/);
assert.doesNotMatch(render(confirmed, notice), /错误品牌/);
assert.doesNotMatch(render({ ...confirmed, brandSpoofPortal: false }, notice), /已识别仿冒/);
const legacy = { ...confirmed, spoofBrand: "HypoMux" }; delete legacy.brandFinalSnapshot;
assert.match(render(legacy), /已识别仿冒「HypoMux」官网/);
console.log("PASS: popup rejects null/stale/contradictory snapshots and notices; confirmed/legacy verdicts still render");
