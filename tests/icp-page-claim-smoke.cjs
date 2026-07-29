const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "extension/content/intel-gates.js"), "utf8");

const footerText = "© 2026 汽水音乐(杭州)网络科技有限公司 · 浙ICP备2026000888号-1";
const signals = [];
const nsState = { score: 15 };
const guardCalls = [];
const nsMock = {
  state: nsState,
  addSignal(name, weight, reason) {
    signals.push({ name, weight, reason });
    nsState.score += Number(weight) || 0;
    return true;
  },
  installDownloadGuard(reason, options) {
    guardCalls.push({ reason, options });
    nsState.downloadGuardInstalled = true;
  }
};
const context = {
  window: { SilverfoxContent: nsMock },
  document: {
    body: { innerText: footerText, textContent: footerText },
    querySelectorAll: () => [{ innerText: footerText, textContent: footerText }]
  },
  location: { hostname: "qishuiyinyuer.com.cn" },
  Date,
  URL,
  setTimeout,
  clearTimeout
};
vm.createContext(context);
vm.runInContext(source, context);
const ns = context.window.SilverfoxContent;

assert.deepEqual(Array.from(ns.extractPageDeclaredIcpLicenses()), ["浙ICP备2026000888-1"]);

const missing = ns.reconcilePageIcpClaim("", true);
assert.equal(missing.unverifiedClaim, true);
assert.equal(missing.mismatch, false);
assert.equal(signals.length, 1);
assert.equal(signals[0].name, "假冒ICP备案信息：浙ICP备2026000888-1");
assert.equal(signals[0].weight, 25);
assert.equal(ns.state.score, 40);
assert.equal(ns.isHighConfidenceUnverifiedIcpThreat(missing, 10), true);
assert.equal(ns.isHighConfidenceUnverifiedIcpThreat(missing, 30), false);
assert.equal(ns.enforceUnverifiedPageIcpDownloadBlock(missing, 10), true);
assert.equal(ns.state._unverifiedIcpIdentityThreat, true);
assert.equal(guardCalls.length, 1);
assert.equal(guardCalls[0].options.guardKind, "site-identity");
assert.match(guardCalls[0].options.message, /qishuiyinyuer\.com\.cn/);

// 即使早期品牌扫描未命中，假备案确认阶段也必须重算拼写仿冒并发品牌通知。
ns.state.downloadGuardInstalled = false;
guardCalls.length = 0;
ns.evaluateDomainKeywordRelevance = () => ({
  related: false,
  squat: true,
  hostMatch: "typo",
  brand: "汽水音乐",
  brandToken: "qishuiyinyue"
});
assert.equal(ns.enforceUnverifiedPageIcpDownloadBlock(missing, 10), true);
assert.equal(ns.state.spoofBrand, "汽水音乐");
assert.equal(ns.state._brandSpoofPortalDetected, true);
assert.equal(guardCalls.length, 1);
assert.equal(guardCalls[0].options.guardKind, "brand-spoof");
assert.equal(guardCalls[0].options.title, "已识别仿冒「汽水音乐」官网");
assert.equal(
  guardCalls[0].options.message,
  "页面标题/正文品牌「汽水音乐」与当前域名不匹配，疑似仿冒官网。"
);
assert.equal(signals.some((item) => item.name === "仿冒品牌官网下载站" && item.weight === 24), true);

signals.length = 0;
const same = ns.reconcilePageIcpClaim("浙ICP备2026000888号-2", false);
assert.equal(same.matches, true);
assert.equal(same.mismatch, false);
assert.equal(signals.length, 0);
assert.equal(ns.enforceUnverifiedPageIcpDownloadBlock(same, 10), false);
assert.equal(ns.state._unverifiedIcpIdentityThreat, false);

const stale = ns.reconcilePageIcpClaim("浙ICP备2025123456号-1", false);
assert.equal(stale.remoteFound, true);
assert.equal(stale.mismatch, true);
assert.equal(stale.unverifiedClaim, false);
assert.equal(signals.length, 0);
ns.state.icpInfo = stale.remote;
ns.state.icpMatchedHost = "qishuiyinyuer.com.cn";
ns.intelHostIsValidAttribution = () => true;
assert.equal(ns.hasValidIcpRecord(), true);

console.log("ICP page-claim smoke tests passed");
