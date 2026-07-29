const assert = require("assert");

global.self = global;
self.SilverfoxBackground = {};
require("../extension/background/filename-heuristics-bg.js");
assert.equal(self.SilverfoxBackground.PackageHeuristicsBg.looksLikeProductPackageName("Soda_Music_12.8.1_x64.zip"), true);
assert.equal(self.SilverfoxBackground.PackageHeuristicsBg.isSuspiciousPackageFilename("Soda_Music_12.8.1_x64.zip"), false);
require("../extension/background/message-handler-bg.js");

const merge = self.SilverfoxBackground.mergeThreatRiskReport;
const oldHigh = {
  url: "https://qishuiyinyuer.com.cn/",
  tabId: 9,
  timestamp: 100,
  analysisComplete: true,
  score: 40,
  riskLevel: "high",
  details: [{ name: "假冒ICP备案信息：浙ICP备2026000888-1", weight: 25 }],
  packageBlocked: true,
  protectedTargets: ["Soda_Music_12.8.1_x64.zip"]
};
const refreshing = {
  url: "https://qishuiyinyuer.com.cn/",
  tabId: 9,
  timestamp: 200,
  analysisComplete: false,
  score: 0,
  riskLevel: "low",
  details: [],
  packageBlocked: false,
  protectedTargets: []
};

const stable = merge(oldHigh, refreshing);
assert.equal(stable.analysisComplete, true);
assert.equal(stable.score, 40);
assert.equal(stable.riskLevel, "high");
assert.equal(stable.packageBlocked, true);
assert.equal(stable.details[0].name, "假冒ICP备案信息：浙ICP备2026000888-1");
assert.equal(stable.timestamp, 200);

const otherHost = merge(oldHigh, { ...refreshing, url: "https://example.com/" });
assert.equal(otherHost.analysisComplete, false);
assert.equal(otherHost.score, 0);

const completedClean = merge(oldHigh, { ...refreshing, analysisComplete: true });
assert.equal(completedClean.score, 0);
assert.equal(completedClean.riskLevel, "low");

const originalDocument = global.document;
global.document = {
  addEventListener() {},
  createElement() { return {}; },
  createTextNode(text) { return { textContent: text }; },
  getElementById() { return null; }
};
const { PopupRenderer } = require("../extension/popup/popup.js");
const renderer = new PopupRenderer({ firstChild: null, removeChild() {}, appendChild() {} });
renderer.activeTabId = 9;
renderer.coalesceReport(oldHigh, oldHigh.url);
const popupStable = renderer.coalesceReport(refreshing, refreshing.url);
assert.equal(popupStable.score, 40);
assert.equal(popupStable.riskLevel, "high");
assert.equal(renderer.isCompletedReport(refreshing), false);
assert.equal(renderer.identityRiskFromData(oldHigh).name, "假冒ICP备案信息：浙ICP备2026000888-1");
global.document = originalDocument;

console.log("report stability smoke tests passed");
