/**
 * 导航保护：标签页保护状态、DNR 短脉冲 arm/disarm、脚本自动跳转强制拉回、
 * webNavigation beforeNavigate/committed 决策。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristicsBg } = NS;
  const PROVISIONAL_PROTECTION_TTL_MS = 45000;

  NS.PROVISIONAL_PROTECTION_TTL_MS = PROVISIONAL_PROTECTION_TTL_MS;
  NS._protectionMutationAtByTab ??= new Map();
  NS._protectionMutationVersion = Number(NS._protectionMutationVersion || 0);

  function protectionStorageKey(tabId) {
    return `protect_tab_${tabId}`;
  }

  /**
   * 仅释放导航/下载保护，不触碰当前风险报告或下载信任。
   * 可信身份落定与 provisional 超时时必须走这里，避免异步 remove(risk_*)
   * 把刚到达的新报告一起删掉。
   */
  NS.clearTabProtectionState = function (tabId) {
    if (tabId == null || tabId < 0) return false;
    NS._protectionMutationVersion += 1;
    NS._protectionMutationAtByTab.set(tabId, NS._protectionMutationVersion);
    const hadProtection = NS.protectedTabs.has(tabId) || NS.protectedTabMeta.has(tabId);
    NS.protectedTabs.delete(tabId);
    NS.protectedTabMeta.delete(tabId);
    NS.disarmHostileNavDnr(tabId);
    try {
      chrome.storage.local.remove([protectionStorageKey(tabId)], () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
    return hadProtection;
  };

  NS.persistTabProtection = function (tabId) {
    if (tabId == null || tabId < 0) return;
    const meta = NS.protectedTabMeta.get(tabId);
    if (!NS.protectedTabs.has(tabId) || !meta) {
      try { chrome.storage.local.remove([protectionStorageKey(tabId)], () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
      return;
    }
    const value = {
      version: 2,
      enabled: true,
      origin: String(meta.origin || ""),
      url: String(meta.url || ""),
      mode: meta.mode === "provisional" ? "provisional" : "full",
      analysisTxn: String(meta.analysisTxn || ""),
      setAt: Number(meta.setAt) || Date.now(),
      expiresAt: meta.mode === "provisional" ? Number(meta.expiresAt || 0) : 0
    };
    try { chrome.storage.local.set({ [protectionStorageKey(tabId)]: value }); } catch { /* ignore */ }
  };

  /** 恢复 SW 落盘状态；过期 provisional 不再复活。 */
  NS.restoreTabProtection = function (tabId, stored, related = {}) {
    if (tabId == null || tabId < 0 || !stored) return false;
    const now = Date.now();
    let meta = null;
    if (stored && typeof stored === "object") {
      const mode = stored.mode === "provisional" ? "provisional" : "full";
      const setAt = Number(stored.setAt) || now;
      const expiresAt = mode === "provisional"
        ? (Number(stored.expiresAt) || (setAt + PROVISIONAL_PROTECTION_TTL_MS))
        : 0;
      meta = {
        origin: String(stored.origin || ""),
        url: String(stored.url || ""),
        setAt,
        mode,
        analysisTxn: String(stored.analysisTxn || ""),
        expiresAt
      };
    } else if (stored === true) {
      // v1 只落了 boolean，无法区分 full/provisional。仅有真实硬风险证据时
      // 恢复成 full；其余旧软保护视为已过期，防止浏览器重启后永久误拦截。
      const risk = related.risk && typeof related.risk === "object" ? related.risk : null;
      const notice = related.notice && typeof related.notice === "object" ? related.notice : null;
      const hardRisk = !!(risk && (
        risk.downloadGuardInstalled || risk.packageBlocked
        || (Array.isArray(risk.protectedTargets) && risk.protectedTargets.length > 0)
      ));
      const noticeKind = String((notice && notice.guardKind) || "").toLowerCase();
      const noticeUrl = String((notice && notice.url) || "");
      const hardNotice = !!(notice && Number(notice.tabId) === Number(tabId)
        && /^(?:package|package-vt|brand-spoof|nav|hard)$/.test(noticeKind)
        && noticeUrl);
      if (hardRisk || hardNotice) {
        const url = String((risk && risk.url) || (notice && notice.url) || "");
        let origin = "";
        try { origin = new URL(url).origin; } catch { /* ignore */ }
        meta = { origin, url, setAt: Number((risk && risk.timestamp) || (notice && notice.timestamp)) || now, mode: "full", expiresAt: 0 };
      }
    }
    if (!meta || (meta.mode === "provisional" && meta.expiresAt <= now)) {
      try { chrome.storage.local.remove([protectionStorageKey(tabId)], () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
      return false;
    }
    // A delayed storage callback must never downgrade protection established
    // by the current document while restoration was in flight.
    const live = NS.protectedTabMeta.get(tabId);
    if (live) {
      if (live.mode === "full" && meta.mode !== "full") return true;
      if ((Number(live.setAt) || 0) >= (Number(meta.setAt) || 0)) return true;
    }
    NS.protectedTabs.add(tabId);
    NS.protectedTabMeta.set(tabId, meta);
    return true;
  };

  /** 所有后台判定统一经过这里，顺手懒清过期 provisional。 */
  NS.isTabProtected = function (tabId, now = Date.now()) {
    if (tabId == null || tabId < 0 || !NS.protectedTabs.has(tabId)) return false;
    const meta = NS.protectedTabMeta.get(tabId);
    if (!meta || meta.mode !== "provisional") return true;
    const setAt = Number(meta.setAt) || Number(now);
    const expiresAt = Number(meta.expiresAt) || (setAt + PROVISIONAL_PROTECTION_TTL_MS);
    if (!meta.expiresAt) {
      meta.expiresAt = expiresAt;
      NS.protectedTabMeta.set(tabId, meta);
      NS.persistTabProtection(tabId);
    }
    if (expiresAt > Number(now)) return true;
    NS.clearTabProtectionState(tabId);
    return false;
  };

  /**
   * content 的 provisional 核验事务正常/超时收口时主动释放软保护。
   * full/hard 永远不能通过这条路径释放；URL 不一致也拒绝旧文档越权清理。
   */
  NS.releaseProvisionalTabProtection = function (tabId, pageUrl, analysisTxn) {
    if (!NS.isTabProtected(tabId)) return false;
    const meta = NS.protectedTabMeta.get(tabId);
    if (!meta || meta.mode !== "provisional") return false;
    const ownerTxn = String(meta.analysisTxn || "");
    const releaseTxn = String(analysisTxn || "");
    // New protection records are transaction-bound. Legacy records without a
    // token may age out by TTL, but an old same-URL document cannot clear a
    // newer transaction after reload.
    // Ownerless records are navigation hints. They may expire by TTL, but are
    // never actively releasable by a document because same-URL reloads cannot
    // prove ownership without a transaction token.
    if (!ownerTxn || !releaseTxn || ownerTxn !== releaseTxn) return false;
    const currentUrl = String(pageUrl || "");
    if (meta.url && currentUrl) {
      let normalized = currentUrl;
      try { normalized = new URL(currentUrl).href; } catch { /* keep raw URL */ }
      if (normalized !== meta.url) return false;
    }
    return NS.clearTabProtectionState(tabId);
  };

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
    NS.clearTabRiskStorage(tabId, newUrl);
    if (newUrl && !/^https?:\/\//i.test(String(newUrl))) return;
    NS.notifyContentPageUrlChanged(tabId, newUrl);
  };

  NS.clearTabRiskStorage = function (tabId, newUrl) {
    if (tabId == null || tabId < 0) return;
    const exactHostOf = (u) => {
      try { return new URL(u || "").hostname.toLowerCase().replace(/\.+$/g, ""); } catch { return ""; }
    };
    const nextUrl = String(newUrl || "");
    const nextHost = exactHostOf(nextUrl);
    const navState = NS.getTabNav(tabId);
    const previousAnalysisUrl = String(navState.analysisUrl || navState.lastGoodUrl || "");
    navState.analysisUrl = nextUrl;
    const memoryRisk = NS._lastRiskReportByTab instanceof Map
      ? NS._lastRiskReportByTab.get(tabId)
      : null;
    const knownPreviousHost = exactHostOf((memoryRisk && memoryRisk.url) || previousAnalysisUrl);
    // 每次 URL 事件都推进代次；即使本次同 host 无需清理，也必须让上一次
    // 尚未返回的跨站 storage.get 回调失效（A→B→A 快速切换）。
    NS._riskNavigationSeqByTab ??= new Map();
    const navSeq = (NS._riskNavigationSeqByTab.get(tabId) || 0) + 1;
    NS._riskNavigationSeqByTab.set(tabId, navSeq);

    // history/hash/同 host SPA 切换仍属于同一站点事务。保留当前报告和 badge，
    // 只让 content 根据 current URL 继续更新；绝不能先 remove 再等它重报。
    if (nextHost && knownPreviousHost && nextHost === knownPreviousHost) return;

    const vtTabKey = `latestExeVt_${tabId}`;
    const riskTabKey = `risk_${tabId}`;
    chrome.storage.local.get([riskTabKey, "latestNotice", "risk_latest", "latestExeVt", vtTabKey], (r) => {
      if (NS._riskNavigationSeqByTab.get(tabId) !== navSeq) return;
      const liveMemoryRisk = NS._lastRiskReportByTab instanceof Map
        ? NS._lastRiskReportByTab.get(tabId)
        : null;
      const storedRisk = r && r[riskTabKey];
      const currentRisk = liveMemoryRisk || storedRisk || null;
      const currentRiskHost = exactHostOf(currentRisk && currentRisk.url);
      // storage.get 等待期间新页面已送达报告：新报告优先，旧清理回调直接作废。
      if (nextHost && currentRiskHost && nextHost === currentRiskHost) return;
      // 没有任何证据表明发生跨 host，不做破坏性清理。
      if (nextHost && !currentRiskHost && (!knownPreviousHost || nextHost === knownPreviousHost)) return;

      // 已确认跨 host：此刻才失效合并序列和内存，避免迟到旧回调复活。
      if (NS._riskReportSeqByTab instanceof Map) {
        NS._riskReportSeqByTab.set(tabId, (NS._riskReportSeqByTab.get(tabId) || 0) + 1);
      }
      if (NS._lastRiskReportByTab instanceof Map) NS._lastRiskReportByTab.delete(tabId);
      NS.withExistingTab(tabId, () => {
        try {
          chrome.action.setBadgeText({ tabId, text: "" }, () => { void chrome.runtime.lastError; });
          chrome.action.setTitle({ tabId, title: "Threat Detector" }, () => { void chrome.runtime.lastError; });
        } catch { /* ignore */ }
      });

      const toRemove = [riskTabKey];
      const belongsToOldHost = (entry, urlField = "url") => {
        if (!entry || Number(entry.tabId) !== Number(tabId)) return false;
        const host = exactHostOf(entry[urlField] || entry.pageUrl);
        return !nextHost || !host || host !== nextHost;
      };
      if (belongsToOldHost(r.latestNotice)) toRemove.push("latestNotice");
      if (belongsToOldHost(r.risk_latest)) toRemove.push("risk_latest");
      const shouldDropVt = (vt) => {
        if (!vt || typeof vt !== "object") return false;
        // 仅处理本 tab 或未标 tab 的全局粘连
        if (vt.tabId != null && Number(vt.tabId) !== Number(tabId)) return false;
        // 检测进行中且仍属同一下载来源主机：保留（避免误杀进行中的分析）
        const atHost = String(vt.pageHost || "").toLowerCase().replace(/\.+$/g, "") || exactHostOf(vt.pageUrl);
        const inFlight = (vt.status === "checking" || vt.status === "uploading")
          && (Date.now() - (Number(vt.timestamp) || 0) < 120000);
        if (inFlight && nextHost && atHost && nextHost === atHost) return false;
        // 换站 / 无来源主机：清掉，避免源标签页 VT 粘到新域名
        if (!nextHost || !atHost || nextHost !== atHost) return true;
        return false;
      };
      try {
        if (shouldDropVt(r.latestExeVt)) toRemove.push("latestExeVt");
        if (shouldDropVt(r[vtTabKey])) toRemove.push(vtTabKey);
      } catch {
        toRemove.push("latestExeVt", vtTabKey);
      }
      // 同步清内存，避免迟到的 write 又把旧结果写回 storage
      try {
        if (typeof NS.clearLatestExeVtIfStaleForTab === "function") {
          NS.clearLatestExeVtIfStaleForTab(tabId, newUrl);
        } else if (NS._latestExeVtMem) {
          const m = NS._latestExeVtMem;
          if (m.tabId == null || Number(m.tabId) === Number(tabId)) {
            const mh = String(m.pageHost || "").toLowerCase().replace(/\.+$/g, "") || exactHostOf(m.pageUrl);
            if (!nextHost || !mh || nextHost !== mh) NS._latestExeVtMem = null;
          }
        }
      } catch { /* ignore */ }
      if (toRemove.length) {
        chrome.storage.local.remove([...new Set(toRemove)], () => { void chrome.runtime.lastError; });
      }
    });
  };

  NS.clearTabAnalysisState = function (tabId) {
    if (tabId == null) return;
    NS.clearTabProtectionState(tabId);
    if (typeof NS.clearTrustedDownloadSource === "function") NS.clearTrustedDownloadSource(tabId);
    else if (NS.trustedDownloadTabs) NS.trustedDownloadTabs.delete(tabId);
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
    if (!NS.isTabProtected(tabId)) return false;
    const meta = NS.protectedTabMeta.get(tabId);
    if (!meta || !meta.origin) return NS.isTabProtected(tabId);
    try { return new URL(url).origin === meta.origin; } catch { return false; }
  };

  NS.markTabProtected = function (tabId, pageUrl, opts = {}) {
    if (tabId == null || tabId < 0) return;
    NS._protectionMutationVersion += 1;
    NS._protectionMutationAtByTab.set(tabId, NS._protectionMutationVersion);
    // 新的真实/临时保护信号会撤销此前的可信下载来源状态。
    if (typeof NS.clearTrustedDownloadSource === "function") NS.clearTrustedDownloadSource(tabId);
    else if (NS.trustedDownloadTabs) NS.trustedDownloadTabs.delete(tabId);
    const mode = opts.mode === "provisional" ? "provisional" : "full";
    const prev = NS.isTabProtected(tabId) ? NS.protectedTabMeta.get(tabId) : null;
    const nextMode = prev && prev.mode === "full" ? "full" : mode;
    const now = Date.now();
    NS.protectedTabs.add(tabId);
    let nextUrl = String(pageUrl || "");
    let nextOrigin = "";
    try {
      const u = new URL(pageUrl || "https://invalid.local/");
      nextOrigin = u.origin;
      nextUrl = u.href;
    } catch { /* keep raw URL */ }
    const requestedTxn = String(opts.analysisTxn || "");
    const sameProvisionalScope = nextMode === "provisional" && prev && prev.mode === "provisional"
      && (!nextUrl || nextUrl === prev.url)
      && !!requestedTxn && requestedTxn === String(prev.analysisTxn || "");
    const setAt = sameProvisionalScope ? (Number(prev.setAt) || now) : now;
    const expiresAt = nextMode === "provisional"
      ? (sameProvisionalScope
        ? (Number(prev.expiresAt) || (setAt + PROVISIONAL_PROTECTION_TTL_MS))
        : now + PROVISIONAL_PROTECTION_TTL_MS)
      : 0;
    const analysisTxn = String(requestedTxn || (sameProvisionalScope && prev && prev.analysisTxn) || "");
    NS.protectedTabMeta.set(tabId, { origin: nextOrigin, url: nextUrl, setAt, mode: nextMode, expiresAt, analysisTxn });
    NS.persistTabProtection(tabId);
    const st = NS.getTabNav(tabId);
    if (pageUrl && !NS.isHostileAutoTarget(pageUrl)) { st.lastGoodUrl = pageUrl; if (!st.landedAt) st.landedAt = Date.now(); }
    NS.armHostileNavDnr(tabId, nextMode === "provisional" ? 8000 : 12000);
  };

  NS.releaseProtectionIfLeftOrigin = function (tabId, newUrl, opts = {}) {
    if (!NS.isTabProtected(tabId) && !opts.force) { NS.disarmHostileNavDnr(tabId); return false; }
    const st = NS.getTabNav(tabId);
    if (st.reversing && !opts.force) return false;
    const meta = NS.protectedTabMeta.get(tabId);
    if (!opts.force && meta && meta.mode === "provisional" && meta.url && newUrl) {
      let nextHref = String(newUrl || "");
      try { nextHref = new URL(newUrl).href; } catch { /* keep raw */ }
      // A provisional verdict is page-exact, not origin-wide. Moving from a
      // download route to another route on the same site must release it.
      if (nextHref !== meta.url) return NS.clearTabProtectionState(tabId);
    }
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

  /**
   * 曾用全局 DNR upgradeScheme 把 image/css/font/media 的 http→https。
   * 问题：规则无「仅当主文档是 HTTPS」条件，会误伤纯 HTTP 页
   *（AdGuard Home / 路由器管理台 http://192.168.x.x 的 CSS 被升成 https 后加载失败）。
   * script/main_frame 本就不在规则内，但 stylesheet 升 HTTPS 已足以弄坏局域网 SPA。
   *
   * Chrome 在 HTTPS 页已自动升级混合内容；页内 mixed-content-quiet 仅在 https: 文档生效。
   * 此处只负责清掉历史动态规则，不再安装全局 upgradeScheme。
   */
  NS.ensureMixedContentUpgradeDnr = function () {
    if (!chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateDynamicRules) return;
    const RULE_IDS = [100, 101, 102, 103];
    try {
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: RULE_IDS,
        addRules: []
      }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
  };

  /** 短脉冲 SERP 跳转网络阻断（仅保护态标签页；永不自动续期）。 */
  NS.armHostileNavDnr = function (tabId, ms = 12000) {
    if (tabId == null || tabId < 0) return;
    if (!NS.isTabProtected(tabId)) return;
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
    if (NS.isTabProtected(tabId) && NS.isOnProtectedOrigin(tabId, st.lastGoodUrl)) return true;
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
    if (!clientRedir && NS.isTabProtected(tabId)) {
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
    try {
      if (typeof NS.markTabRiskAnalysisPending === "function") {
        NS.markTabRiskAnalysisPending(tabId, url, {
          documentId: details.documentId || "",
          navigationId: details.navigationId || ""
        });
      }
    } catch { /* report isolation must not interrupt navigation safety */ }
    const st = NS.getTabNav(tabId);
    if (st.reversing) { NS.injectNavBoot(tabId, 0); return; }
    const clientRedir = (details.transitionQualifiers || []).includes("client_redirect");
    if (!NS.isOnProtectedOrigin(tabId, url)) { if (!clientRedir || !NS.isHostileAutoTarget(url)) NS.releaseProtectionIfLeftOrigin(tabId, url, { force: !clientRedir }); }
    if (NS.shouldForceRestoreHostileNav(tabId, url, details)) { NS.forceRestoreTab(tabId, st.lastGoodUrl, url); return; }
    if (NS.isHostileAutoTarget(url) && !clientRedir && NS.isTabProtected(tabId)) { NS.pauseNavBlocking(tabId, "serp-user-land"); NS.clearTabAnalysisState(tabId); NS.injectNavBoot(tabId, 0); return; }
    if (!NS.isHostileAutoTarget(url)) {
      st.lastGoodUrl = url;
      if (NS.isUserDrivenTransition(details) || !clientRedir) st.landedAt = Date.now();
      if (NS.looksLikeDownloadPhishLandingUrl(url) && !NS.isTabProtected(tabId)) NS.markTabProtected(tabId, url, { mode: "provisional" });
    } else if (NS.isTabProtected(tabId) && !NS.isOnProtectedOrigin(tabId, url) && !clientRedir) {
      NS.releaseProtectionIfLeftOrigin(tabId, url, { force: true });
    }
    NS.injectNavBoot(tabId, 0);
  };
})(self.SilverfoxBackground ??= {});
