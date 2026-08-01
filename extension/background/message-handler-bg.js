/**
 * 消息处理：content -> background 的 fetchPageText / probeDownloadBehavior /
 * threat-risk / set-tab-protect / threat-notice / 分析重置等。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristicsBg } = NS;

  // 情报/SSL 常用公共 API 主机（优先放行；其余 HTTPS 仍允许，仅拦私网）
  NS.ICP_FETCH_HOSTS = new Set([
    // ICP
    "icp.aizhan.com",
    "beiancx.com",
    "uapis.cn",
    // WHOIS / RDAP
    "who-dat.as93.net",
    "rdap.ss",
    "whoiscx.com",
    "api.tian.hu",
    "rdap.org",
    "rdap.verisign.com",
    "rdap.publicinterestregistry.org",
    "rdap.identitydigital.services",
    // SSL / CT
    "api.ssllabs.com",
    "api.certspotter.com",
    "crt.sh",
    "ctl.shodan.io",
    "urlscan.io",
    "networkcalc.com",
    // 安装包 VT（试验）
    "www.virustotal.com",
    "virustotal.com"
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

  function sameReportHost(a, b) {
    try {
      const left = new URL(a || "").hostname.toLowerCase().replace(/^www\./, "");
      const right = new URL(b || "").hostname.toLowerCase().replace(/^www\./, "");
      return !!(left && right && left === right);
    } catch {
      return false;
    }
  }

  /**
   * 刷新/重扫刚启动时会先产生 analysisComplete:false 的空白报告。
   * 同一主机已有完成结论时，保留旧结论直到本轮扫描真正完成，避免 UI 在
   * 「严重风险 → 低风险 → 严重风险」之间闪动。
   */
  NS.mergeThreatRiskReport = function (previous, incoming) {
    if (!incoming || incoming.analysisComplete !== false) return incoming;
    if (!previous || previous.analysisComplete !== true || !sameReportHost(previous.url, incoming.url)) return incoming;
    return {
      ...incoming,
      ...previous,
      url: incoming.url || previous.url,
      tabId: incoming.tabId ?? previous.tabId ?? null,
      timestamp: incoming.timestamp || previous.timestamp || Date.now(),
      analysisComplete: true,
      icpInfo: incoming.icpInfo || previous.icpInfo || "",
      whoisInfo: incoming.whoisInfo || previous.whoisInfo || "",
      sslInfo: incoming.sslInfo || previous.sslInfo || null
    };
  };

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
      if (msg.type === "relay-page-threat-toast") {
        const tabId = sender.tab?.id ?? null;
        // 只接受 content script 的子 frame 转发；页面脚本无法调用 runtime.sendMessage。
        if (tabId != null && Number.isInteger(sender.frameId) && sender.frameId > 0) {
          try {
            chrome.tabs.sendMessage(tabId, {
              type: "show-page-threat-toast",
              title: String(msg.title || "已拦截可疑下载文件").slice(0, 120),
              message: String(msg.message || "可疑下载已被拦截").slice(0, 240),
              force: msg.force !== false
            }, { frameId: 0 }, () => { void chrome.runtime.lastError; });
          } catch { /* ignore */ }
        }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "set-tab-download-trust") {
        const tabId = sender.tab?.id ?? null;
        // 仅顶层 content script 可设置；子 frame 不能替整个标签页建立信任。
        if (tabId != null && (sender.frameId == null || sender.frameId === 0)) {
          if (msg.enabled) {
            const pageUrl = sender.tab?.url || msg.url || "";
            // 可信来源建立时同步清除之前的软保护残留，再写入信任状态。
            NS.clearTabAnalysisState(tabId);
            if (typeof NS.setTrustedDownloadSource === "function") NS.setTrustedDownloadSource(tabId, pageUrl);
          } else {
            if (typeof NS.clearTrustedDownloadSource === "function") NS.clearTrustedDownloadSource(tabId);
            else NS.trustedDownloadTabs.delete(tabId);
          }
        }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "trusted-download-intent") {
        const tabId = sender.tab?.id ?? null;
        // 顶层候选始终登记来源供页内提示；只有 content 核验身份后才登记可信放行。
        if (tabId != null && (sender.frameId == null || sender.frameId === 0)
          && typeof NS.rememberTrustedDownloadIntent === "function") {
          if (typeof NS.rememberDownloadSourceIntent === "function") {
            NS.rememberDownloadSourceIntent(tabId, msg.href || "");
          }
          if (msg.identityVerified === true && typeof NS.setTrustedDownloadSource === "function") {
            NS.setTrustedDownloadSource(tabId, sender.tab?.url || msg.url || "");
            // setTrustedDownloadSource 会清掉该 tab 的旧来源候选，恢复本次精确 URL。
            if (typeof NS.rememberDownloadSourceIntent === "function") {
              NS.rememberDownloadSourceIntent(tabId, msg.href || "");
            }
          }
          if (msg.identityVerified === true) NS.rememberTrustedDownloadIntent(tabId, msg.href || "");
        }
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
          const cleanReport = msg.analysisComplete !== false
            && !msg.downloadGuardInstalled && !msg.packageBlocked
            && !(Array.isArray(msg.protectedTargets) && msg.protectedTargets.length > 0)
            && (riskLevel === "low") && (Number(msg.score) || 0) < 12;
          if (tabId != null && cleanReport) {
            const reportAt = Date.now();
            chrome.storage.local.get(["latestNotice"], (r) => {
              if (r.latestNotice
                && (r.latestNotice.tabId == null || r.latestNotice.tabId === tabId)
                && (Number(r.latestNotice.timestamp) || 0) <= reportAt) {
                chrome.storage.local.remove(["latestNotice"], () => { void chrome.runtime.lastError; });
              }
            });
          }
          const storeRisk = (stamped) => {
            const storedLevel = stamped.riskLevel || "low";
            let badgeText = ""; let badgeColor = "#2e7d32";
            if (storedLevel === "high") { badgeText = "!"; badgeColor = "#d93025"; }
            else if (storedLevel === "medium") { badgeText = "!"; badgeColor = "#f59e0b"; }
            else if ((stamped.score || 0) > 0) { badgeText = "·"; badgeColor = "#f59e0b"; }
            if (tabId != null) {
              NS.safeSetBadge(tabId, badgeText, badgeColor);
              chrome.storage.local.set({ [`risk_${tabId}`]: stamped, risk_latest: stamped }, () => {
                if (chrome.runtime.lastError) console.warn("background: store risk report failed", chrome.runtime.lastError.message);
              });
            } else {
              chrome.storage.local.set({ risk_latest: stamped }, () => { if (chrome.runtime.lastError) console.warn("background: store risk_latest failed", chrome.runtime.lastError.message); });
            }
          };
          const stamped = { ...msg, url: msg.url || sender.tab?.url || "", tabId, riskLevel, timestamp: Number(msg.timestamp) || Date.now() };
          // 同主机：incomplete 合并进已 complete，禁止盖成「正在分析」
          if (tabId != null && msg.analysisComplete === false) {
            NS._riskReportSeqByTab ??= new Map();
            const seq = (NS._riskReportSeqByTab.get(tabId) || 0) + 1;
            NS._riskReportSeqByTab.set(tabId, seq);
            chrome.storage.local.get([`risk_${tabId}`], (r) => {
              // 较新的报告已经到达时，丢弃这个异步回调，避免旧中间态反向覆盖。
              if (NS._riskReportSeqByTab.get(tabId) !== seq) return;
              const prev = r && r[`risk_${tabId}`];
              storeRisk(NS.mergeThreatRiskReport(prev, stamped));
            });
          } else {
            if (tabId != null) {
              NS._riskReportSeqByTab ??= new Map();
              NS._riskReportSeqByTab.set(tabId, (NS._riskReportSeqByTab.get(tabId) || 0) + 1);
            }
            storeRisk(stamped);
          }
        } catch (e) { console.warn("background: error handling threat-risk", e && e.message ? e.message : e); }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return;
      }
      if (msg.type === "get-ssl-cert") {
        // 保留 www（www.gov.cn / www.12306.cn）；缓存键在 ssl-cert-bg 内再去 www
        let host = String(msg.host || "").toLowerCase().replace(/\.$/, "");
        if (!host && sender.tab && sender.tab.url) {
          try { host = new URL(sender.tab.url).hostname.toLowerCase(); } catch { /* ignore */ }
        }
        const tabId = sender.tab?.id ?? null;
        const force = !!msg.force;
        // 页面已是 HTTPS 时，CT 全失败仍可回退展示 DV
        let pageHttps = msg.https !== false;
        if (msg.https == null && sender.tab && sender.tab.url) {
          try { pageHttps = /^https:/i.test(sender.tab.url); } catch { pageHttps = true; }
        }
        (async () => {
          try {
            let info = null;
            if (!force && typeof NS.getSslCertInfoForHost === "function") {
              info = NS.getSslCertInfoForHost(host);
            }
            // 仅忽略旧版空占位；https-assumed 可展示
            if (info && (info.source === "https-reachability" || info.source === "page-https")) info = null;
            // 无机构名的 OV/EV 也强制再探（补 Subject.O）
            const needOrg = info && /^(OV|EV)$/i.test(String(info.validation || ""))
              && !String(info.organization || "").trim();
            if ((!info || needOrg || force) && typeof NS.resolveSslCertInfo === "function") {
              info = await NS.resolveSslCertInfo(host, { force: force || needOrg, https: pageHttps });
            }
            if (info && (info.source === "https-reachability" || info.source === "page-https")) info = null;
            if (info && tabId != null) {
              try {
                chrome.tabs.sendMessage(tabId, { type: "ssl-cert-info", sslInfo: info }, () => {
                  void chrome.runtime.lastError;
                });
              } catch { /* ignore */ }
            }
            try { sendResponse({ success: true, sslInfo: info || null, host }); } catch { /* ignore */ }

            // 首次 DV / 无 org 的 OV：后台再探（Labs 常稍后 READY 才有 certs PEM）
            const v0 = String((info && info.validation) || "").toUpperCase();
            const org0 = String((info && info.organization) || "").trim();
            if (info && (v0 === "DV" || (v0 === "OV" && !org0))
              && typeof NS.probeSslCertForHost === "function" && tabId != null) {
              const upgradeHost = host;
              const rank0 = v0 === "OV" ? 2 : 1;
              const tryUpgrade = async () => {
                try {
                  const up = await NS.probeSslCertForHost(upgradeHost);
                  if (!up || !up.validation) return false;
                  const ru = String(up.validation).toUpperCase() === "EV" ? 3
                    : String(up.validation).toUpperCase() === "OV" ? 2 : 1;
                  const orgUp = String(up.organization || "").trim();
                  if (ru < rank0) return false;
                  if (ru === rank0 && !(orgUp && !org0)) return false;
                  if (typeof NS.storeSslCertInfo === "function") NS.storeSslCertInfo(upgradeHost, up);
                  try {
                    chrome.tabs.sendMessage(tabId, { type: "ssl-cert-info", sslInfo: up }, () => {
                      void chrome.runtime.lastError;
                    });
                  } catch { /* ignore */ }
                  return !!(orgUp || ru > rank0);
                } catch {
                  return false;
                }
              };
              // 50ms 立即；3s/10s/20s 再试（等 SSL Labs 全局 READY 写满 certs[] PEM）
              // xinhuanet 等多 IP 站 IN_PROGRESS→READY 常超过 8s
              setTimeout(() => { void tryUpgrade(); }, 50);
              if (v0 === "OV" && !org0) {
                setTimeout(() => { void tryUpgrade(); }, 3000);
                setTimeout(() => { void tryUpgrade(); }, 10000);
                setTimeout(() => { void tryUpgrade(); }, 20000);
              }
            }
          } catch (e) {
            try { sendResponse({ success: false, error: e && e.message ? e.message : "ssl-fail", host }); } catch { /* ignore */ }
          }
        })();
        return true;
      }
      if (msg.type === "vt-api-key-updated") {
        try {
          if (typeof NS.clearVtLookupCache === "function") NS.clearVtLookupCache();
        } catch { /* ignore */ }
        try { sendResponse({ success: true }); } catch { /* ignore */ }
        return false;
      }
      if (msg.type === "refresh-vt-engine-details") {
        (async () => {
          try {
            if (typeof NS.refreshStoredVirusTotalDetails !== "function") {
              sendResponse({ success: false, error: "vt-refresh-unavailable" });
              return;
            }
            const tabId = Number.isInteger(msg.tabId) && msg.tabId >= 0 ? msg.tabId : null;
            const result = await NS.refreshStoredVirusTotalDetails(msg.sha256, tabId);
            sendResponse(result || { success: false, error: "vt-refresh-fail" });
          } catch (e) {
            try {
              sendResponse({ success: false, error: e && e.message ? e.message : "vt-refresh-fail" });
            } catch { /* ignore */ }
          }
        })();
        return true;
      }
      if (msg.type === "refresh-nested-vt-signatures") {
        (async () => {
          try {
            if (typeof NS.refreshStoredNestedSignatures !== "function") {
              sendResponse({ success: false, error: "nested-signature-refresh-unavailable" });
              return;
            }
            const tabId = Number.isInteger(msg.tabId) && msg.tabId >= 0 ? msg.tabId : null;
            const result = await NS.refreshStoredNestedSignatures(msg.sha256, tabId);
            sendResponse(result || { success: false, error: "nested-signature-refresh-fail" });
          } catch (e) {
            try {
              sendResponse({
                success: false,
                error: e && e.message ? e.message : "nested-signature-refresh-fail"
              });
            } catch { /* ignore */ }
          }
        })();
        return true;
      }
      if (msg.type === "inspect-package-vt" || msg.type === "inspect-exe-vt") {
        // 手动/探测：对安装包 URL 做哈希 + VT（及 PE 签名粗检）
        const url = String(msg.url || "").trim();
        const filename = String(msg.filename || "").trim();
        (async () => {
          try {
            if (!url || !/^https?:\/\//i.test(url)) {
              sendResponse({ success: false, error: "bad-url" });
              return;
            }
            if (typeof NS.inspectPackageUrl !== "function") {
              sendResponse({ success: false, error: "pe-vt-unavailable" });
              return;
            }
            const report = await NS.inspectPackageUrl(url, { filename });
            sendResponse({ success: !!report.success, report });
          } catch (e) {
            try {
              sendResponse({ success: false, error: e && e.message ? e.message : "inspect-fail" });
            } catch { /* ignore */ }
          }
        })();
        return true;
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
        chrome.storage.local.set({ latestNotice: { title, message, tabId, url: sender.tab?.url || msg.url || "", timestamp: Date.now(), guardKind: msg.guardKind || (isIdentityNotice ? "identity" : "package") } });
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
