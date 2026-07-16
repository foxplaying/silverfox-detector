/**
 * 导航保护：标签页保护状态、DNR 短脉冲 arm/disarm、脚本自动跳转强制拉回、
 * webNavigation beforeNavigate/committed 决策。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristicsBg } = NS;

  // --- URL 形态工具 ---
  NS.isSearchTrapUrl = function (url) {
    try {
      const u = new URL(url);
      const path = (u.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
      const q = u.search || "";
      if (!q || q.length < 2) return false;
      if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search)=[^&]+/i.test(q)) return true;
      if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p)=[^&]+/i.test(q)) return true;
      if (/\/(?:url|link|redirect|rd|jump)$/i.test(path) && /[?&](?:q|url|u|target|to|redir|redirect)=[^&]+/i.test(q)) return true;
      return false;
    } catch { return false; }
  };

  NS.isPackageNavUrl = function (url) {
    try {
      const u = new URL(url);
      if (PackageHeuristicsBg.PACKAGE_NAME_RE.test(u.pathname)) return true;
      if (PackageHeuristicsBg.PACKAGE_NAME_RE.test(u.href.split("?")[0])) return true;
      return false;
    } catch { return PackageHeuristicsBg.PACKAGE_NAME_RE.test(String(url || "")); }
  };

  NS.isHostileAutoTarget = function (url) { return NS.isSearchTrapUrl(url) || NS.isPackageNavUrl(url); };

  NS.isUserDrivenTransition = function (details) {
    const t = details.transitionType || "";
    return t === "typed" || t === "generated" || t === "auto_toplevel" || t === "reload" || t === "keyword" || t === "keyword_generated";
  };

  NS.dnrIdsForTab = function (tabId) {
    const base = 500000 + (Math.abs(tabId) % 50000) * 20;
    return Array.from({ length: 12 }, (_, i) => base + i);
  };

  NS.getTabNav = function (tabId) {
    let st = NS.tabNavState.get(tabId);
    if (!st) { st = { lastGoodUrl: "", landedAt: 0, reversing: false, dnrArmedUntil: 0 }; NS.tabNavState.set(tabId, st); }
    return st;
  };

  NS.withExistingTab = function (tabId, fn) {
    if (tabId == null || tabId < 0 || typeof tabId !== "number") return;
    try {
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab) return;
        try { fn(tab); } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
  };

  NS.safeSetBadge = function (tabId, text, color) {
    NS.withExistingTab(tabId, () => {
      try {
        chrome.action.setBadgeText({ tabId, text: text || "" }, () => { void chrome.runtime.lastError; });
        if (color) chrome.action.setBadgeBackgroundColor({ tabId, color }, () => { void chrome.runtime.lastError; });
      } catch { /* ignore */ }
    });
  };

  NS.notifyContentPageUrlChanged = function (tabId, url) {
    if (tabId == null || tabId < 0) return;
    try { chrome.tabs.sendMessage(tabId, { type: "page-url-changed", url: url || "" }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
  };

  NS.onTabUrlChangedForAnalysis = function (tabId, newUrl) {
    if (tabId == null || tabId < 0) return;
    NS.clearTabRiskStorage(tabId);
    if (newUrl && !/^https?:\/\//i.test(String(newUrl))) return;
    NS.notifyContentPageUrlChanged(tabId, newUrl);
  };

  NS.clearTabRiskStorage = function (tabId) {
    if (tabId == null || tabId < 0) return;
    NS.withExistingTab(tabId, () => {
      try {
        chrome.action.setBadgeText({ tabId, text: "" }, () => { void chrome.runtime.lastError; });
        chrome.action.setTitle({ tabId, title: "Threat Detector" }, () => { void chrome.runtime.lastError; });
      } catch { /* ignore */ }
    });
    chrome.storage.local.remove([`risk_${tabId}`], () => { void chrome.runtime.lastError; });
    chrome.storage.local.get(["latestNotice", "risk_latest"], (r) => {
      const toRemove = [];
      if (r.latestNotice && r.latestNotice.tabId === tabId) toRemove.push("latestNotice");
      if (r.risk_latest && r.risk_latest.tabId === tabId) toRemove.push("risk_latest");
      if (toRemove.length) chrome.storage.local.remove(toRemove, () => { void chrome.runtime.lastError; });
    });
  };

  NS.clearTabAnalysisState = function (tabId) {
    if (tabId == null) return;
    NS.protectedTabs.delete(tabId);
    NS.protectedTabMeta.delete(tabId);
    NS.disarmHostileNavDnr(tabId);
    NS.withExistingTab(tabId, () => {
      try {
        chrome.action.setBadgeText({ tabId, text: "" }, () => { void chrome.runtime.lastError; });
        chrome.action.setTitle({ tabId, title: "Threat Detector" }, () => { void chrome.runtime.lastError; });
      } catch { /* ignore */ }
    });
    chrome.storage.local.remove([`risk_${tabId}`, `protect_tab_${tabId}`], () => { void chrome.runtime.lastError; });
    chrome.storage.local.get(["latestNotice"], (r) => {
      if (r.latestNotice && r.latestNotice.tabId === tabId) chrome.storage.local.remove(["latestNotice"], () => { void chrome.runtime.lastError; });
    });
  };

  NS.looksLikeDownloadPhishLandingUrl = function (url) {
    try {
      if (!url || !/^https?:/i.test(url)) return false;
      if (NS.isSearchTrapUrl(url) || NS.isPackageNavUrl(url)) return false;
      const u = new URL(url);
      const host = u.hostname.toLowerCase().replace(/^www\./, "");
      if (PackageHeuristicsBg.looksLikeOpaqueHopUrl(url)) return true;
      const label = (host.split(".")[0] || "").replace(/-/g, "");
      const randomHost = label.length >= 6 && /[a-z]/i.test(label) && /\d/.test(label);
      const path = (u.pathname || "").toLowerCase();
      const blob = `${path}${u.search || ""}`;
      if (/\/(?:\d{2,}down|down\d{2,}|dl\d{2,}|getfile|getdown)(?:\/|$)/i.test(path)) return true;
      if (/(?:download|down|client|setup|install|soft|app)(?:\/|$)/i.test(path) && randomHost) return true;
      if (randomHost && (path === "/" || path === "" || path.length < 4)) return true;
      if (randomHost && /download|down|client|setup|install/i.test(blob)) return true;
      return false;
    } catch { return false; }
  };

  NS.isOnProtectedOrigin = function (tabId, url) {
    if (!NS.protectedTabs.has(tabId)) return false;
    const meta = NS.protectedTabMeta.get(tabId);
    if (!meta || !meta.origin) return NS.protectedTabs.has(tabId);
    try { return new URL(url).origin === meta.origin; } catch { return false; }
  };

  NS.markTabProtected = function (tabId, pageUrl, opts = {}) {
    if (tabId == null || tabId < 0) return;
    const mode = opts.mode === "provisional" ? "provisional" : "full";
    const prev = NS.protectedTabMeta.get(tabId);
    const nextMode = prev && prev.mode === "full" ? "full" : mode;
    NS.protectedTabs.add(tabId);
    try {
      const u = new URL(pageUrl || "https://invalid.local/");
      NS.protectedTabMeta.set(tabId, { origin: u.origin, url: u.href, setAt: Date.now(), mode: nextMode });
    } catch { NS.protectedTabMeta.set(tabId, { origin: "", url: pageUrl || "", setAt: Date.now(), mode: nextMode }); }
    const st = NS.getTabNav(tabId);
    if (pageUrl && !NS.isHostileAutoTarget(pageUrl)) { st.lastGoodUrl = pageUrl; if (!st.landedAt) st.landedAt = Date.now(); }
    NS.armHostileNavDnr(tabId, nextMode === "provisional" ? 8000 : 12000);
  };

  NS.releaseProtectionIfLeftOrigin = function (tabId, newUrl, opts = {}) {
    if (!NS.protectedTabs.has(tabId) && !opts.force) { NS.disarmHostileNavDnr(tabId); return false; }
    const st = NS.getTabNav(tabId);
    if (st.reversing && !opts.force) return false;
    if (!opts.force && newUrl && NS.isOnProtectedOrigin(tabId, newUrl)) return false;
    NS.clearTabAnalysisState(tabId);
    return true;
  };

  NS.pauseNavBlocking = function (tabId, reason) {
    if (tabId == null || tabId < 0) return;
    try { const st = NS.getTabNav(tabId); st.dnrGen = (st.dnrGen || 0) + 1; st.dnrArmedUntil = 0; } catch { /* ignore */ }
    NS.disarmHostileNavDnr(tabId);
    void reason;
  };

  NS.injectNavBoot = function (tabId, frameId = 0) {
    if (tabId == null || tabId < 0 || typeof tabId !== "number") return;
    if (!chrome.scripting || !chrome.scripting.executeScript) return;
    const run = () => {
      const target = frameId === 0 ? { tabId, allFrames: false } : { tabId, frameIds: [frameId] };
      try {
        const ret = chrome.scripting.executeScript({ target, world: "MAIN", injectImmediately: true, files: ["nav-boot/package-classifier.js", "nav-boot/sso-detector.js", "nav-boot/page-shell-detector.js", "nav-boot/cloaking-kit-scanner.js", "nav-boot/gesture-tracker.js", "nav-boot/nav-blocker.js", "nav-boot/location-guard.js", "nav-boot/index.js"] });
        if (ret && typeof ret.then === "function") ret.catch(() => { /* tab gone */ });
      } catch { /* ignore */ }
    };
    NS.withExistingTab(tabId, (tab) => { const u = tab.url || ""; if (!u || !/^https?:\/\//i.test(u)) return; run(); });
  };

  NS.ensureRegisteredNavBoot = function () {
    if (!chrome.scripting || !chrome.scripting.registerContentScripts) return;
    try {
      chrome.scripting.getRegisteredContentScripts((scripts) => {
        const has = (scripts || []).some((s) => s.id === "silverfox-nav-boot");
        if (has) return;
        chrome.scripting.registerContentScripts([{ id: "silverfox-nav-boot", matches: ["http://*/*", "https://*/*"], js: ["nav-boot/package-classifier.js", "nav-boot/sso-detector.js", "nav-boot/page-shell-detector.js", "nav-boot/cloaking-kit-scanner.js", "nav-boot/gesture-tracker.js", "nav-boot/nav-blocker.js", "nav-boot/location-guard.js", "nav-boot/index.js"], runAt: "document_start", world: "MAIN", allFrames: true, persistAcrossSessions: true }], () => { void chrome.runtime.lastError; });
      });
    } catch { /* ignore */ }
  };

  NS.clearAllHostileNavDnr = function () {
    if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.getSessionRules) return;
    try {
      chrome.declarativeNetRequest.getSessionRules((rules) => {
        if (chrome.runtime.lastError || !rules || !rules.length) return;
        const ids = rules.map((r) => r.id).filter((id) => id >= 500000 && id < 2000000);
        if (!ids.length) return;
        chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }, () => { void chrome.runtime.lastError; });
      });
    } catch { /* ignore */ }
  };

  /** 短脉冲 SERP 跳转网络阻断（仅保护态标签页；永不自动续期）。 */
  NS.armHostileNavDnr = function (tabId, ms = 12000) {
    if (tabId == null || tabId < 0) return;
    if (!NS.protectedTabs.has(tabId)) return;
    if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateSessionRules) return;
    const windowMs = Math.max(3000, Math.min(ms || 12000, 15000));
    const ids = NS.dnrIdsForTab(tabId);
    const filters = ["search?*q=", "search?*query=", "search?*keyword=", "search?*wd=", "search?*text=", "/s?*wd=", "/s?*word=", "/s?*q=", "/web?*query=", "/web?*keyword=", "/link?*url=", "/url?*q="];
    const rules = filters.map((urlFilter, i) => ({ id: ids[i], priority: 1, action: { type: "block" }, condition: { tabIds: [tabId], urlFilter, resourceTypes: ["main_frame"] } }));
    try {
      chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids, addRules: rules }, () => { void chrome.runtime.lastError; });
      const st = NS.getTabNav(tabId);
      st.dnrGen = (st.dnrGen || 0) + 1;
      const gen = st.dnrGen;
      st.dnrArmedUntil = Date.now() + windowMs;
      setTimeout(() => { try { const cur = NS.tabNavState.get(tabId); if (!cur || cur.dnrGen !== gen) return; cur.dnrArmedUntil = 0; chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } }, windowMs + 50);
    } catch { /* ignore */ }
  };

  NS.disarmHostileNavDnr = function (tabId) {
    if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateSessionRules) return;
    try {
      const st = NS.tabNavState.get(tabId);
      if (st) { st.dnrGen = (st.dnrGen || 0) + 1; st.dnrArmedUntil = 0; }
      chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: NS.dnrIdsForTab(tabId) }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
  };

  /** 通过 tabs.update 强制拉回（非 goBack，location.replace 清历史）。 */
  NS.forceRestoreTab = function (tabId, restoreUrl, trapUrl) {
    if (!restoreUrl || restoreUrl === trapUrl) return false;
    const st = NS.getTabNav(tabId);
    if (st.reversing) return true;
    st.reversing = true;
    const done = (ok) => {
      const cur = NS.tabNavState.get(tabId);
      if (cur) cur.reversing = false;
      if (!ok) return;
      NS.markTabProtected(tabId, restoreUrl, { mode: "full" });
      NS.safeSetBadge(tabId, "!", "#d93025");
      try { NS.showBlockedNotification("已拦截脚本自动跳转", NS.isSearchTrapUrl(trapUrl) ? "页面脚本试图跳转到搜索引擎（已拉回）" : "页面脚本试图打开安装包（已拉回）", tabId).catch(() => {}); } catch { /* ignore */ }
      try { chrome.storage.local.set({ latestNotice: { title: "已拦截脚本自动跳转", message: String(trapUrl || "").slice(0, 180), tabId, url: restoreUrl || "", timestamp: Date.now() } }); } catch { /* ignore */ }
      NS.injectNavBoot(tabId, 0);
      NS.armHostileNavDnr(tabId, 10000);
    };
    NS.withExistingTab(tabId, () => {
      try {
        const p = chrome.tabs.update(tabId, { url: restoreUrl });
        if (p && typeof p.then === "function") p.then(() => done(true)).catch(() => done(false));
        else chrome.tabs.update(tabId, { url: restoreUrl }, () => { done(!chrome.runtime.lastError); });
      } catch { done(false); }
    });
    setTimeout(() => { const cur = NS.tabNavState.get(tabId); if (cur && cur.reversing) cur.reversing = false; }, 3000);
    return true;
  };

  /** 仅拉回纯脚本自动跳转（client_redirect）；永不反转 typed/link 导航。 */
  NS.shouldForceRestoreHostileNav = function (tabId, url, details) {
    const st = NS.getTabNav(tabId);
    if (!st.lastGoodUrl || st.lastGoodUrl === url) return false;
    if (!NS.isHostileAutoTarget(url)) return false;
    if (NS.isUserDrivenTransition(details)) return false;
    const clientRedir = (details.transitionQualifiers || []).includes("client_redirect");
    if (!clientRedir) return false;
    if (NS.isPackageNavUrl(url)) {
      try {
        const name = PackageHeuristicsBg.basenameFromPath(url) || PackageHeuristicsBg.basenameFromPath(new URL(url).pathname);
        const base = String(name || "").replace(/\.[^.]+$/, "");
        const clearPkg = PackageHeuristicsBg.looksLikeProductPackageName(name) || PackageHeuristicsBg.isBenignShortInstallerName(name) || PackageHeuristicsBg.looksLikeAndroidPackageIdName(base);
        const strongProduct = /[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base) && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base));
        if ((clearPkg || strongProduct) && !PackageHeuristicsBg.isSuspiciousPackageFilename(name)) {
          if (strongProduct || clearPkg) { try { if (PackageHeuristicsBg.isSuspiciousPackageFilename(name)) { /* fall through */ } else return false; } catch { return false; } }
        }
      } catch { /* fall through */ }
    }
    if (NS.protectedTabs.has(tabId) && NS.isOnProtectedOrigin(tabId, st.lastGoodUrl)) return true;
    if (NS.looksLikeDownloadPhishLandingUrl(st.lastGoodUrl) && st.landedAt && Date.now() - st.landedAt < 20000) return true;
    return false;
  };

  /** beforeNavigate：脚本 client_redirect -> 拉回；其余离开 -> 解锁 + 清 DNR。 */
  NS.onMainFrameBeforeNavigate = function (details) {
    if (details.frameId !== 0) return;
    const tabId = details.tabId;
    if (tabId == null || tabId < 0) return;
    const url = details.url || "";
    if (!/^https?:/i.test(url)) return;
    const st = NS.getTabNav(tabId);
    if (st.reversing) return;
    const clientRedir = (details.transitionQualifiers || []).includes("client_redirect");
    if (NS.isUserDrivenTransition(details)) {
      NS.pauseNavBlocking(tabId, "user-driven");
      NS.releaseProtectionIfLeftOrigin(tabId, url, { userDriven: true, force: true });
      if (!NS.isHostileAutoTarget(url)) { st.lastGoodUrl = url; st.landedAt = Date.now(); }
      NS.injectNavBoot(tabId, 0);
      return;
    }
    if (NS.shouldForceRestoreHostileNav(tabId, url, details)) { NS.forceRestoreTab(tabId, st.lastGoodUrl, url); return; }
    if (!clientRedir && NS.protectedTabs.has(tabId)) {
      if (!NS.isOnProtectedOrigin(tabId, url) || NS.isHostileAutoTarget(url)) {
        NS.pauseNavBlocking(tabId, "user-leave");
        NS.clearTabAnalysisState(tabId);
        if (!NS.isHostileAutoTarget(url)) { st.lastGoodUrl = url; st.landedAt = Date.now(); }
        NS.injectNavBoot(tabId, 0);
        return;
      }
    }
    if (!NS.isHostileAutoTarget(url)) {
      NS.releaseProtectionIfLeftOrigin(tabId, url);
      st.lastGoodUrl = url; st.landedAt = Date.now();
      if (NS.looksLikeDownloadPhishLandingUrl(url)) NS.markTabProtected(tabId, url, { mode: "provisional" });
      NS.injectNavBoot(tabId, 0);
      return;
    }
    NS.injectNavBoot(tabId, 0);
  };

  NS.noteCommittedNavigation = function (details) {
    if (details.frameId !== 0) return;
    const url = details.url || "";
    if (!/^https?:/i.test(url)) return;
    const tabId = details.tabId;
    if (tabId == null || tabId < 0) return;
    const st = NS.getTabNav(tabId);
    if (st.reversing) { NS.injectNavBoot(tabId, 0); return; }
    const clientRedir = (details.transitionQualifiers || []).includes("client_redirect");
    if (!NS.isOnProtectedOrigin(tabId, url)) { if (!clientRedir || !NS.isHostileAutoTarget(url)) NS.releaseProtectionIfLeftOrigin(tabId, url, { force: !clientRedir }); }
    if (NS.shouldForceRestoreHostileNav(tabId, url, details)) { NS.forceRestoreTab(tabId, st.lastGoodUrl, url); return; }
    if (NS.isHostileAutoTarget(url) && !clientRedir && NS.protectedTabs.has(tabId)) { NS.pauseNavBlocking(tabId, "serp-user-land"); NS.clearTabAnalysisState(tabId); NS.injectNavBoot(tabId, 0); return; }
    if (!NS.isHostileAutoTarget(url)) {
      st.lastGoodUrl = url;
      if (NS.isUserDrivenTransition(details) || !clientRedir) st.landedAt = Date.now();
      if (NS.looksLikeDownloadPhishLandingUrl(url) && !NS.protectedTabs.has(tabId)) NS.markTabProtected(tabId, url, { mode: "provisional" });
    } else if (NS.protectedTabs.has(tabId) && !NS.isOnProtectedOrigin(tabId, url) && !clientRedir) {
      NS.releaseProtectionIfLeftOrigin(tabId, url, { force: true });
    }
    NS.injectNavBoot(tabId, 0);
  };
})(self.SilverfoxBackground ??= {});
