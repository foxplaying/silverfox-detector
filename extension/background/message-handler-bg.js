/**
 * 消息处理：content -> background 的 fetchPageText / probeDownloadBehavior /
 * threat-risk / set-tab-protect / threat-notice / 分析重置等。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristicsBg } = NS;

  NS.ICP_FETCH_HOSTS = new Set([
    "icp.aizhan.com",
    "beiancx.com",
    "uapis.cn",
    "rdap.ss",
    "whoiscx.com"
  ]);

  NS.isAllowedFetchUrl = function (rawUrl) {
    try {
      const u = new URL(rawUrl);
      if (u.protocol !== "https:" && u.protocol !== "http:") return false;
      const host = u.hostname.toLowerCase();
      if (NS.ICP_FETCH_HOSTS.has(host)) return true;
      if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0)/i.test(host)) return false;
      return true;
    } catch { return false; }
  };

  function handleFetchPageText(msg, sendResponse) {
    const url = msg.url;
    if (!url || !NS.isAllowedFetchUrl(url)) { sendResponse({ success: false, error: "url-not-allowed" }); return true; }
    try {
      if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(new URL(url).pathname) || /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(url)) {
        sendResponse({ success: false, error: "package-url-blocked", url }); return true;
      }
    } catch { /* continue */ }
    const method = String(msg.method || "GET").toUpperCase() === "POST" ? "POST" : "GET";
    let timeoutMs = Number(msg.timeoutMs);
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) timeoutMs = 5000;
    if (timeoutMs > 15000) timeoutMs = 15000;
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => { try { controller.abort(); } catch { /* ignore */ } }, timeoutMs) : null;
    const redirectMode = msg.redirect === "manual" ? "manual" : "follow";
    const init = { credentials: "omit", redirect: redirectMode, method, cache: "no-store", signal: controller ? controller.signal : undefined, headers: { Accept: "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8" } };
    if (method === "POST") {
      let body = msg.body;
      if (body != null && typeof body !== "string") { try { body = String(body); } catch { body = ""; } }
      if (typeof body === "string" && body.length > 0 && body.length < 8192) init.body = body;
      const ct = msg.contentType || "application/x-www-form-urlencoded;charset=UTF-8";
      init.headers = { ...init.headers, "Content-Type": ct };
    }
    (async () => {
      try {
        const response = await fetch(url, init);
        if (timer) clearTimeout(timer);
        if (redirectMode === "manual" && response.status >= 300 && response.status < 400) {
          const loc = response.headers.get("Location") || response.headers.get("location") || "";
          sendResponse({ success: true, status: response.status, text: "", url: response.url || url, redirectLocation: loc });
          return;
        }
        const finalUrl = response.url || url;
        if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(finalUrl)) { sendResponse({ success: false, error: "package-url-blocked", status: response.status, url: finalUrl }); return; }
        const text = await response.text();
        const maxLen = 120000;
        const capped = text.length > maxLen ? text.slice(0, maxLen) : text;
        sendResponse({ success: true, status: response.status, text: capped, url: finalUrl, ok: response.ok });
      } catch (error) {
        if (timer) clearTimeout(timer);
        const aborted = error && (error.name === "AbortError" || /abort/i.test(error.message || ""));
        sendResponse({ success: false, error: aborted ? "timeout" : (error?.message || "fetch-failed") });
      }
    })();
    return true;
  }

  function handleProbeDownloadBehavior(msg, sendResponse) {
    const url = msg.url;
    if (!url || !NS.isAllowedFetchUrl(url)) { sendResponse({ success: false, isDownload: false, error: "url-not-allowed" }); return true; }
    const PACKAGE_RE = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i;
    try {
      const u0 = new URL(url);
      if (PACKAGE_RE.test(u0.pathname) || PACKAGE_RE.test(u0.href)) {
        const fn = (u0.pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
        sendResponse({ success: true, isDownload: true, reason: "package-url-no-fetch", filename: fn, finalUrl: url, chain: [url] });
        return true;
      }
    } catch { /* continue probe */ }
    function parseFilename(cd) { if (!cd) return ""; const m = cd.match(/filename\*?=(?:UTF-8''|")?([^\";]+)/i); return m ? decodeURIComponent(m[1].replace(/"/g, "").trim()) : ""; }
    function looksDownloadHeaders(status, headers, finalUrl) {
      const cd = headers.get("content-disposition") || headers.get("Content-Disposition") || "";
      const ct = (headers.get("content-type") || headers.get("Content-Type") || "").toLowerCase();
      const filename = parseFilename(cd);
      if (/attachment/i.test(cd) || /filename\s*=/i.test(cd)) return { isDownload: true, reason: "content-disposition", filename, finalUrl, contentType: ct };
      if (PACKAGE_RE.test(finalUrl) || PACKAGE_RE.test(filename)) return { isDownload: true, reason: "package-url-or-name", filename, finalUrl, contentType: ct };
      if (/application\/(zip|x-zip|x-rar|x-7z|x-msdownload|octet-stream|vnd\.android|java-archive|x-msdos-program)/i.test(ct)) { if (/text\/html/i.test(ct)) return { isDownload: false, reason: "html", finalUrl, contentType: ct }; return { isDownload: true, reason: "binary-content-type", filename, finalUrl, contentType: ct }; }
      if (/text\/html/i.test(ct) && status >= 200 && status < 300) return { isDownload: false, reason: "html", finalUrl, contentType: ct };
      return null;
    }
    async function abortBody(res) { try { if (res && res.body) { if (typeof res.body.cancel === "function") await res.body.cancel(); else if (typeof res.body.getReader === "function") { const r = res.body.getReader(); await r.cancel(); } } } catch { /* ignore */ } }
    (async () => {
      const chain = [];
      let current = url;
      try {
        for (let hop = 0; hop < 5; hop++) {
          if (chain.includes(current)) break;
          chain.push(current);
          try { if (PACKAGE_RE.test(new URL(current).pathname)) { sendResponse({ success: true, isDownload: true, reason: "package-url-no-fetch", finalUrl: current, filename: (current.split("/").pop() || "").split("?")[0], chain }); return; } } catch { /* ignore */ }
          let res = null;
          try { res = await fetch(current, { method: "HEAD", redirect: "manual", credentials: "omit", cache: "no-store" }); } catch { res = null; }
          if (!res || res.status === 405 || res.status === 501) { try { res = await fetch(current, { method: "GET", redirect: "manual", credentials: "omit", cache: "no-store", headers: { Range: "bytes=0-0" } }); await abortBody(res); } catch { res = null; } }
          if (!res) { sendResponse({ success: false, isDownload: false, error: "probe-head-failed", chain }); return; }
          const verdict = looksDownloadHeaders(res.status, res.headers, current);
          if (verdict) { await abortBody(res); sendResponse({ success: true, chain, ...verdict }); return; }
          if (res.status >= 300 && res.status < 400) { const loc = res.headers.get("Location") || res.headers.get("location"); if (!loc) break; current = new URL(loc, current).href; if (PACKAGE_RE.test(current)) { sendResponse({ success: true, isDownload: true, reason: "redirect-to-package", finalUrl: current, filename: (current.split("/").pop() || "").split("?")[0], chain: [...chain, current] }); return; } continue; }
          sendResponse({ success: true, isDownload: false, reason: "not-download", finalUrl: current, contentType: res.headers.get("content-type") || "", chain }); return;
        }
        sendResponse({ success: true, isDownload: false, reason: "probe-exhausted", finalUrl: current, chain });
      } catch (e) { sendResponse({ success: false, isDownload: false, error: e?.message || "probe-failed" }); }
    })();
    return true;
  }

  /** 注册 chrome.runtime.onMessage 监听。 */
  NS.installMessageHandler = function () {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg.type === "page-analysis-reset") {
        const tabId = sender.tab?.id ?? msg.tabId ?? null;
        if (tabId != null) {
          NS.clearTabRiskStorage(tabId);
          const pageUrl = sender.tab?.url || msg.url || "";
          if (pageUrl && NS.protectedTabs.has(tabId) && !NS.isOnProtectedOrigin(tabId, pageUrl)) { NS.pauseNavBlocking(tabId, "content-url-reset"); NS.clearTabAnalysisState(tabId); }
        }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "clear-threat-notice") {
        const tabId = sender.tab?.id ?? msg.tabId ?? null;
        if (tabId != null) {
          chrome.storage.local.get(["latestNotice"], (r) => { if (r.latestNotice && (r.latestNotice.tabId == null || r.latestNotice.tabId === tabId)) chrome.storage.local.remove(["latestNotice"], () => { void chrome.runtime.lastError; }); });
        }
        try {
          if (typeof NS.clearAllSilverfoxNotifications === "function") NS.clearAllSilverfoxNotifications();
          else {
            chrome.notifications.getAll((all) => {
              void chrome.runtime.lastError;
              const ids = Object.keys(all || {});
              for (const id of ids) {
                try { chrome.notifications.clear(id, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
              }
            });
          }
        } catch { /* ignore */ }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "threat-risk") {
        try {
          // 子 frame（广告 iframe）报告不写 risk_tab，避免盖掉顶层结果
          if (sender.frameId != null && sender.frameId !== 0) {
            try { sendResponse({ success: true, ignored: "subframe" }); } catch { /* ignore */ }
            return;
          }
          const tabId = sender.tab?.id ?? null;
          let riskLevel = msg.riskLevel || "low";
          if ((msg.downloadGuardInstalled || msg.packageBlocked) && riskLevel === "low") riskLevel = msg.packageBlocked ? "high" : "medium";
          let badgeText = ""; let badgeColor = "#2e7d32";
          if (riskLevel === "high") { badgeText = "!"; badgeColor = "#d93025"; }
          else if (riskLevel === "medium") { badgeText = "!"; badgeColor = "#f59e0b"; }
          else if ((msg.score || 0) > 0) { badgeText = "·"; badgeColor = "#f59e0b"; }
          const cleanReport = !msg.downloadGuardInstalled && !msg.packageBlocked && !(Array.isArray(msg.protectedTargets) && msg.protectedTargets.length > 0) && (riskLevel === "low") && (Number(msg.score) || 0) < 12;
          if (tabId != null && cleanReport) {
            chrome.storage.local.get(["latestNotice"], (r) => { if (r.latestNotice && (r.latestNotice.tabId == null || r.latestNotice.tabId === tabId)) chrome.storage.local.remove(["latestNotice"], () => { void chrome.runtime.lastError; }); });
          }
          const storeRisk = (stamped) => {
            if (tabId != null) {
              NS.safeSetBadge(tabId, badgeText, badgeColor);
              chrome.storage.local.set({ [`risk_${tabId}`]: stamped }, () => { if (chrome.runtime.lastError) console.warn("background: store risk_tab failed", chrome.runtime.lastError.message); });
              chrome.storage.local.set({ risk_latest: stamped }, () => { if (chrome.runtime.lastError) console.warn("background: store risk_latest failed", chrome.runtime.lastError.message); });
            } else {
              chrome.storage.local.set({ risk_latest: stamped }, () => { if (chrome.runtime.lastError) console.warn("background: store risk_latest failed", chrome.runtime.lastError.message); });
            }
          };
          const stamped = { ...msg, url: msg.url || sender.tab?.url || "", tabId, riskLevel };
          // 同主机：incomplete 合并进已 complete，禁止盖成「正在分析」
          if (tabId != null && msg.analysisComplete === false) {
            chrome.storage.local.get([`risk_${tabId}`], (r) => {
              try {
                const prev = r && r[`risk_${tabId}`];
                if (prev && (prev.analysisComplete === true || typeof prev.score === "number")) {
                  let sameHost = false;
                  try {
                    const a = new URL(prev.url || "").hostname.replace(/^www\./, "");
                    const b = new URL(stamped.url || "").hostname.replace(/^www\./, "");
                    sameHost = !!(a && b && a === b);
                  } catch { sameHost = false; }
                  if (sameHost) {
                    storeRisk({
                      ...prev,
                      ...stamped,
                      url: stamped.url || prev.url,
                      tabId,
                      analysisComplete: true,
                      score: typeof stamped.score === "number" ? stamped.score : prev.score,
                      riskLevel: stamped.riskLevel || prev.riskLevel,
                      icpInfo: stamped.icpInfo || prev.icpInfo,
                      whoisInfo: stamped.whoisInfo || prev.whoisInfo,
                      details: (Array.isArray(stamped.details) && stamped.details.length) ? stamped.details : prev.details
                    });
                    return;
                  }
                }
              } catch { /* fall through */ }
              // 无 prev 时：有 score 也标 complete，避免只剩「正在分析」
              if (typeof stamped.score === "number" && stamped.riskLevel) {
                stamped.analysisComplete = true;
              }
              storeRisk(stamped);
            });
          } else {
            storeRisk(stamped);
          }
        } catch (e) { console.warn("background: error handling threat-risk", e && e.message ? e.message : e); }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "set-tab-protect") {
        const tabId = sender.tab?.id ?? msg.tabId ?? null;
        if (tabId != null) {
          if (msg.enabled) {
            const pageUrl = sender.tab?.url || msg.url || "";
            const mode = msg.provisional || msg.mode === "provisional" ? "provisional" : "full";
            NS.markTabProtected(tabId, pageUrl, { mode });
            const st = NS.getTabNav(tabId);
            if (pageUrl && !NS.isHostileAutoTarget(pageUrl)) { st.lastGoodUrl = pageUrl; if (!st.landedAt) st.landedAt = Date.now(); }
          } else {
            const pageUrl = sender.tab?.url || msg.url || "";
            if (msg.force || !pageUrl || !NS.isOnProtectedOrigin(tabId, pageUrl)) { NS.pauseNavBlocking(tabId, "set-protect-off"); NS.clearTabAnalysisState(tabId); }
            else { NS.pauseNavBlocking(tabId, "same-origin-boot"); }
          }
          chrome.storage.local.set({ [`protect_tab_${tabId}`]: !!msg.enabled || NS.protectedTabs.has(tabId) });
        }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "pause-nav-blocking" || msg.type === "user-leave-intent") {
        const tabId = sender.tab?.id ?? msg.tabId ?? null;
        if (tabId != null) { NS.pauseNavBlocking(tabId, msg.reason || msg.type); if (msg.clearProtect) NS.clearTabAnalysisState(tabId); }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "early-arm-protect" || msg.type === "request-guard-bg") {
        const tabId = sender.tab?.id ?? msg.tabId ?? null;
        if (tabId != null) { const pageUrl = sender.tab?.url || msg.url || ""; const mode = msg.mode === "full" ? "full" : "provisional"; NS.markTabProtected(tabId, pageUrl, { mode }); NS.safeSetBadge(tabId, "!", "#d93025"); }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "threat-notice") {
        const title = msg.title || "已拦截可疑下载文件";
        const message = String(msg.message || "已拦截可疑下载文件操作").slice(0, 200);
        const tabId = sender.tab?.id ?? msg.tabId ?? null;
        const isIdentityNotice = msg.guardKind === "brand-spoof" || msg.guardKind === "nav-trap" || /仿冒|官网|域名|跳转|搜索引擎/i.test(`${title} ${message}`);
        if (!isIdentityNotice) {
          const noticeName = PackageHeuristicsBg.basenameFromPath(message) || String(message).split(/\s+/).pop() || message;
          const nameLooksLikeFile = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/i.test(String(noticeName));
          if (nameLooksLikeFile && (PackageHeuristicsBg.looksLikeProductPackageName(noticeName) || PackageHeuristicsBg.looksLikeProductSetupWithBuildId(String(noticeName).replace(/\.[^.]+$/, "")) || PackageHeuristicsBg.isBenignShortInstallerName(noticeName))) {
            try { sendResponse({ success: true, ignored: "clear-product-package" }); } catch { /* ignore */ }
            return true;
          }
        }
        if (tabId != null) {
          const pageUrl = sender.tab?.url || msg.url || "";
          NS.markTabProtected(tabId, pageUrl);
          const st = NS.getTabNav(tabId);
          if (pageUrl) { st.lastGoodUrl = pageUrl; st.landedAt = Date.now(); }
          NS.safeSetBadge(tabId, "!", "#d93025");
          NS.withExistingTab(tabId, () => { try { chrome.action.setTitle({ tabId, title: `${title}: ${message}` }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } });
        }
        chrome.storage.local.set({ latestNotice: { title, message, tabId, url: sender.tab?.url || msg.url || "", timestamp: Date.now() } });
        // 仿冒/跳转身份类：始终 force，避免 40min 冷却吞掉右下角系统通知
        const forceNotice = !!msg.force || isIdentityNotice;
        NS.showBlockedNotification(title, message, tabId, forceNotice).then((ok) => { try { sendResponse({ success: !!ok }); } catch { /* ignore */ } }).catch(() => { try { sendResponse({ success: false }); } catch { /* ignore */ } });
        return true;
      }
      if (msg.type === "fetchPageText") return handleFetchPageText(msg, sendResponse);
      if (msg.type === "probeDownloadBehavior") return handleProbeDownloadBehavior(msg, sendResponse);
    });
  };
})(self.SilverfoxBackground ??= {});
