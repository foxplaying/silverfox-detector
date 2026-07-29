const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.resolve(__dirname, "../extension/content/guard.js"), "utf8");
const ns = {
  PACKAGE_EXT: /\.(zip|exe)$/i,
  PACKAGE_NAME: /\.(zip|exe)$/i,
  state: {},
  caches: { pageToastLastAt: new Map(), sentNoticeKeys: new Set(), sentNoticeLastAt: new Map() }
};
const context = {
  window: { SilverfoxContent: ns },
  document: { readyState: "complete", title: "" },
  location: { hostname: "www.hr-huorong.hl.cn", href: "https://www.hr-huorong.hl.cn/" },
  console,
  Date,
  URL,
  setTimeout,
  clearTimeout
};
vm.createContext(context);
vm.runInContext(source, context);

assert.equal(ns.resolveReportRiskLevel({ score: 40, signalCount: 3 }), "high");
assert.equal(ns.resolveReportRiskLevel({ score: 39, signalCount: 3 }), "medium");
assert.equal(ns.resolveReportRiskLevel({ score: 24, signalCount: 2, hasPackageThreat: true }), "high");
assert.equal(ns.resolveReportRiskLevel({ score: 10, signalCount: 1, downloadGuardInstalled: true }), "medium");

ns.state = { _unverifiedIcpIdentityThreat: true, details: [] };
ns.hasValidIcpRecord = () => false;
ns.getWhoisAgeDays = () => 10;
ns.isWhoisAgeUltraMature = () => false;
ns.looksLikeUltraMatureIcpDomain = () => false;
assert.equal(ns.hasHardThreatKitLocked(), true);

let notice = null;
ns.state = {
  spoofBrand: "Shield",
  _brandSpoofPortalDetected: true,
  _brandSpoofNoticeSent: false,
  _brandSpoofNoticeKey: "",
  details: []
};
ns.collectPrimaryBrandKeywords = () => ({
  display: "火绒安全",
  scores: {
    "火绒安全": { votes: 6, sources: ["title", "h1", "keywords", "description", "footer", "domain"] },
    shield: { votes: 2, sources: ["span", "footer"] }
  }
});
ns.normalizeDisplayBrandName = (value) => value;
ns.isWeakChineseBrandToken = () => false;
ns.looksLikeAssetGarbageToken = () => false;
assert.equal(ns.reconcileActiveSpoofBrand({ force: true }), "火绒安全");
assert.equal(ns.state.spoofBrand, "火绒安全");
ns.showGuardOverlay = (href, opts) => {
  notice = { href, opts };
  ns.state._brandSpoofNoticeSent = true;
  ns.state._brandSpoofNoticeKey = `${opts.title}::${opts.message}`;
  return true;
};
assert.equal(ns.ensureBrandSpoofNotice(false), true);
assert.equal(notice.opts.title, "已识别仿冒「火绒安全」官网");
assert.equal(notice.opts.message, "页面标题/正文品牌「火绒安全」与当前域名不匹配，疑似仿冒官网。");
assert.equal(ns.ensureBrandSpoofNotice(false), false);

console.log("risk level smoke tests passed");
