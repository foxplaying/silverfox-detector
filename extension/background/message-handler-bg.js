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
    "networkcalc.com",
    "myssl.com",
    "www.myssl.com",
    "api.edgeone.ai",
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
      let responseStatus = 0;
      let responseUrl = url;
      try {
        const response = await fetch(url, init);
        responseStatus = Number(response.status) || 0;
        responseUrl = response.url || url;
        if (redirectMode === "manual" && response.status >= 300 && response.status < 400) {
          if (timer) clearTimeout(timer);
          const loc = response.headers.get("Location") || response.headers.get("location") || "";
          sendResponse({ success: true, status: response.status, text: "", url: response.url || url, redirectLocation: loc });
          return;
        }
        const finalUrl = response.url || url;
        if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(finalUrl)) {
          if (timer) clearTimeout(timer);
          sendResponse({ success: false, error: "package-url-blocked", status: response.status, url: finalUrl }); return;
        }
        // beiancx 404 的短 nginx body 会保持连接不关闭；调用方只需状态码。
        if (msg.statusOnly404 === true && response.status === 404) {
          if (timer) clearTimeout(timer);
          try { if (response.body && typeof response.body.cancel === "function") response.body.cancel(); } catch { /* ignore */ }
          sendResponse({ success: true, status: 404, text: "", url: finalUrl, ok: false });
          return;
        }
        const text = await response.text();
        if (timer) clearTimeout(timer);
        const maxLen = 120000;
        const capped = text.length > maxLen ? text.slice(0, maxLen) : text;
        sendResponse({ success: true, status: response.status, text: capped, url: finalUrl, ok: response.ok });
      } catch (error) {
        if (timer) clearTimeout(timer);
        const aborted = error && (error.name === "AbortError" || /abort/i.test(error.message || ""));
        sendResponse({ success: false, error: aborted ? "timeout" : (error?.message || "fetch-failed"), status: responseStatus, url: responseUrl });
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

  function sslValidationRank(infoOrValidation) {
    const value = typeof infoOrValidation === "object"
      ? infoOrValidation && infoOrValidation.validation
      : infoOrValidation;
    const validation = String(value || "").toUpperCase();
    if (validation === "EV") return 3;
    if (validation === "OV") return 2;
    if (validation === "DV") return 1;
    return 0;
  }

  function sslInfoHostKey(info) {
    return String((info && (info.host || info.queriedHost)) || "")
      .toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  }

  function isBogusSslOrganization(org) {
    return /internet\s*widgits|some[-\s]?state|default\s+company/i.test(String(org || ""));
  }

  function usableSslOrganization(info) {
    const org = String((info && info.organization) || "").trim();
    if (!org || isBogusSslOrganization(org)) return "";
    return org;
  }

  function hasBoundSslOrganization(info) {
    if (!usableSslOrganization(info)) return false;
    return info.sniChainVerified === true || info.liveTlsLeafVerified === true
      || info.unexpiredHostVerified === true;
  }

  function effectiveSslValidationRank(info) {
    const rank = sslValidationRank(info);
    const org = String((info && info.organization) || "").trim();
    return rank >= 2 && org && isBogusSslOrganization(org) ? 0 : rank;
  }

  function sslCertificateIdentity(info) {
    const fingerprint = String((info && (info.fingerprintSha256 || info.fingerprint)) || "")
      .toLowerCase().replace(/[^a-f0-9]/g, "");
    if (fingerprint.length >= 32) return `fp:${fingerprint}`;
    const certId = String((info && (info.certId || info.certificateId)) || "").trim();
    return certId ? `id:${certId}` : "";
  }

  /** 同一主机证书只能单调升级；同级保留已验证机构，旧 DV 不得覆盖 OV/EV。 */
  function chooseStrongerSslInfo(previous, incoming) {
    if (!previous) return incoming || null;
    if (!incoming) return previous || null;
    const previousHost = sslInfoHostKey(previous);
    const incomingHost = sslInfoHostKey(incoming);
    if (previousHost && incomingHost && previousHost !== incomingHost) return incoming;

    const previousRank = effectiveSslValidationRank(previous);
    const incomingRank = effectiveSslValidationRank(incoming);
    if (previousRank !== incomingRank) return incomingRank > previousRank ? incoming : previous;

    const quality = (info) => {
      let score = 0;
      if (usableSslOrganization(info)) score += 8;
      if (info && info.sniChainVerified === true) score += 4;
      if (info && info.liveTlsLeafVerified === true) score += 4;
      if (info && info.unexpiredHostVerified === true) score += 2;
      if (!/^(?:https-reachability|page-https|https-assumed)$/i.test(String((info && info.source) || ""))) score += 1;
      return score;
    };
    const primary = quality(incoming) >= quality(previous) ? incoming : previous;
    const secondary = primary === incoming ? previous : incoming;
    const primaryIdentity = sslCertificateIdentity(primary);
    const secondaryIdentity = sslCertificateIdentity(secondary);
    // 只有确认为同一张证书时才补字段；不同证书必须整条择优，禁止拼出虚假验证身份。
    if (primaryIdentity && primaryIdentity === secondaryIdentity) {
      return {
        ...secondary,
        ...primary,
        organization: usableSslOrganization(primary) || usableSslOrganization(secondary),
        sniChainVerified: primary.sniChainVerified === true || secondary.sniChainVerified === true,
        liveTlsLeafVerified: primary.liveTlsLeafVerified === true || secondary.liveTlsLeafVerified === true,
        unexpiredHostVerified: primary.unexpiredHostVerified === true || secondary.unexpiredHostVerified === true
      };
    }
    return { ...primary };
  }

  NS.chooseStrongerSslInfo = chooseStrongerSslInfo;

  /**
   * 刷新/重扫刚启动时会先产生 analysisComplete:false 的空白报告。
   * 同一主机已有完成结论时，保留旧结论直到本轮扫描真正完成，避免 UI 在
   * 「严重风险 → 低风险 → 严重风险」之间闪动。
   */
  NS.mergeThreatRiskReport = function (previous, incoming) {
    if (!incoming) return incoming;
    if (!previous || !sameReportHost(previous.url, incoming.url)) return incoming;
    const incomingIsHttps = !incoming.url || /^https:/i.test(String(incoming.url));
    const sslInfo = incomingIsHttps
      ? chooseStrongerSslInfo(previous.sslInfo, incoming.sslInfo)
      : (incoming.sslInfo || null);

    // 已完成报告也可能乱序到达；较旧报告只允许补强 SSL，不回滚其它结论。
    const previousAt = Number(previous.timestamp) || 0;
    const incomingAt = Number(incoming.timestamp) || 0;
    if (previous.analysisComplete === true && incoming.analysisComplete !== false
      && previousAt && incomingAt && incomingAt < previousAt) {
      return { ...previous, sslInfo };
    }
    if (incoming.analysisComplete !== false || previous.analysisComplete !== true) {
      const merged = { ...incoming, sslInfo };
      const incomingHasBrandRisk = !!(merged.brandSpoofPortal
        || (Array.isArray(merged.details) && merged.details.some((d) => /仿冒品牌官网|主动探测仿冒/i.test(d && d.name || ""))));
      if (incomingHasBrandRisk && !merged.spoofBrand && previous.spoofBrand) {
        merged.spoofBrand = previous.spoofBrand;
      }
      return merged;
    }
    return {
      ...incoming,
      ...previous,
      url: incoming.url || previous.url,
      tabId: incoming.tabId ?? previous.tabId ?? null,
      timestamp: incoming.timestamp || previous.timestamp || Date.now(),
      analysisComplete: true,
      icpInfo: incoming.icpInfo || previous.icpInfo || "",
      whoisInfo: incoming.whoisInfo || previous.whoisInfo || "",
      sslInfo
    };
  };

  /** 同一 host 共享一条补查链，避免多个 content 请求叠加 SSL Labs 轮询。 */
  function scheduleSslCertUpgrade(host, tabId, initialInfo) {
    const upgradeHost = String(host || "").toLowerCase().replace(/\.$/, "");
    const initialRank = effectiveSslValidationRank(initialInfo);
    if (!upgradeHost || tabId == null || initialRank < 1
      || typeof NS.probeSslCertForHost !== "function") return;

    NS._sslUpgradeJobsByHost ??= new Map();
    let job = NS._sslUpgradeJobsByHost.get(upgradeHost);
    const initialHasOrg = initialRank >= 2 && hasBoundSslOrganization(initialInfo);
    const addTarget = (targetJob) => {
      const previous = targetJob.targets.get(tabId);
      targetJob.targets.set(tabId, {
        rank: Math.max(initialRank, Number(previous && previous.rank) || 0),
        hasOrg: !!((previous && previous.hasOrg) || initialHasOrg)
      });
    };
    if (job && !job.closed) {
      addTarget(job);
      return;
    }

    job = {
      closed: false,
      inFlight: null,
      pendingRefresh: false,
      lastWeakBustAt: 0,
      targets: new Map(),
      timers: new Set()
    };
    addTarget(job);
    NS._sslUpgradeJobsByHost.set(upgradeHost, job);

    const finish = () => {
      if (job.closed) return;
      job.closed = true;
      for (const timer of job.timers) clearTimeout(timer);
      job.timers.clear();
      if (NS._sslUpgradeJobsByHost.get(upgradeHost) === job) {
        NS._sslUpgradeJobsByHost.delete(upgradeHost);
      }
    };

    const queueAttempt = (delay, refreshWeakSource) => {
      const timer = setTimeout(() => {
        job.timers.delete(timer);
        void tryUpgrade(refreshWeakSource);
      }, delay);
      job.timers.add(timer);
    };

    const tryUpgrade = async (refreshWeakSource) => {
      if (job.closed) return false;
      if (job.inFlight) {
        job.pendingRefresh = job.pendingRefresh || !!refreshWeakSource;
        return job.inFlight;
      }

      if (refreshWeakSource && Date.now() - job.lastWeakBustAt >= 5000
        && typeof NS.invalidateWeakSslSourceCacheForHost === "function") {
        // 仅清理 SSL Labs 弱/空结果；其它源缓存与 429 熔断保持不变。
        NS.invalidateWeakSslSourceCacheForHost(upgradeHost, ["ssllabs"]);
        job.lastWeakBustAt = Date.now();
      }

      job.inFlight = (async () => {
        try {
          const up = await NS.probeSslCertForHost(upgradeHost);
          if (job.closed || !up || !up.validation) return false;
          const upRank = effectiveSslValidationRank(up);
          if (upRank < 1) return false;
          const upHasOrg = upRank >= 2 && hasBoundSslOrganization(up);
          let improved = false;
          for (const [targetTabId, target] of job.targets.entries()) {
            const rankImproved = upRank > target.rank;
            const orgImproved = upRank >= target.rank && upHasOrg && !target.hasOrg;
            if (!rankImproved && !orgImproved) continue;
            improved = true;
            target.rank = Math.max(target.rank, upRank);
            if (upHasOrg && upRank >= target.rank) target.hasOrg = true;
            try {
              chrome.tabs.sendMessage(targetTabId, { type: "ssl-cert-info", sslInfo: up }, () => {
                void chrome.runtime.lastError;
              });
            } catch { /* ignore */ }
          }
          if (improved && typeof NS.storeSslCertInfo === "function") {
            NS.storeSslCertInfo(upgradeHost, up);
          }
          if (job.targets.size > 0 && [...job.targets.values()].every((target) => target.hasOrg)) {
            finish();
          }
          return improved;
        } catch {
          return false;
        }
      })();

      try {
        return await job.inFlight;
      } finally {
        job.inFlight = null;
        if (!job.closed && job.pendingRefresh) {
          const pendingRefresh = job.pendingRefresh;
          job.pendingRefresh = false;
          queueAttempt(250, pendingRefresh);
        }
      }
    };

    // 首次复用现有缓存；后续仅按 host 刷新弱 SSL Labs 结果。
    queueAttempt(50, false);
    queueAttempt(3000, true);
    queueAttempt(10000, true);
    queueAttempt(20000, true);
    const cleanupTimer = setTimeout(finish, 45000);
    job.timers.add(cleanupTimer);
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
          // 所有报告都先与内存和落盘结果合并：完成态中的旧 DV 同样不能覆盖已知 OV/EV。
          if (tabId != null) {
            NS._riskReportSeqByTab ??= new Map();
            NS._lastRiskReportByTab ??= new Map();
            const seq = (NS._riskReportSeqByTab.get(tabId) || 0) + 1;
            NS._riskReportSeqByTab.set(tabId, seq);
            const memoryMerged = NS.mergeThreatRiskReport(NS._lastRiskReportByTab.get(tabId), stamped);
            NS._lastRiskReportByTab.set(tabId, memoryMerged);
            chrome.storage.local.get([`risk_${tabId}`], (r) => {
              // 较新的报告已经到达时，丢弃旧回调，避免任何旧完成态/中间态反向覆盖。
              if (NS._riskReportSeqByTab.get(tabId) !== seq) return;
              const prev = r && r[`risk_${tabId}`];
              const merged = NS.mergeThreatRiskReport(prev, memoryMerged);
              NS._lastRiskReportByTab.set(tabId, merged);
              storeRisk(merged);
            });
          } else {
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

            // 首次 DV / 无已验证 org 的 OV/EV：后台再探（Labs 常稍后 READY 才有 certs PEM）
            const v0 = String((info && info.validation) || "").toUpperCase();
            const hasBoundOrg0 = /^(?:OV|EV)$/.test(v0) && hasBoundSslOrganization(info);
            if (info && (v0 === "DV" || (/^(?:OV|EV)$/.test(v0) && !hasBoundOrg0))
              && typeof NS.probeSslCertForHost === "function" && tabId != null) {
              scheduleSslCertUpgrade(host, tabId, info);
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
      // 已废弃：禁止向网页 inject pinyin-pro（全站卡死根因）。兼容旧消息直接成功。
      if (msg.type === "inject-brand-libs") {
        try { sendResponse({ success: true, mode: "sw-only", injected: false }); } catch { /* ignore */ }
        return true;
      }
      // 品牌拼音：SW 内 pinyin-pro（默认词典），content 只传短候选
      if (msg.type === "brand-pinyin-align") {
        try {
          const host = String(msg.host || "").toLowerCase();
          const candidates = Array.isArray(msg.candidates) ? msg.candidates : [];
          const strongCandidates = Array.isArray(msg.strongCandidates) ? msg.strongCandidates : [];
          const hit = typeof NS.alignChineseBrandToHostBg === "function"
            ? NS.alignChineseBrandToHostBg(host, candidates, strongCandidates)
            : { brand: "", pinyin: "", score: -1 };
          sendResponse({
            success: true,
            brand: (hit && hit.brand) || "",
            matchedChinese: (hit && hit.matchedChinese) || "",
            pinyin: (hit && hit.pinyin) || "",
            hostForm: (hit && hit.hostForm) || "",
            relation: (hit && hit.relation) || "none",
            score: (hit && hit.score) != null ? hit.score : -1
          });
        } catch (e) {
          try {
            sendResponse({ success: false, brand: "", error: (e && e.message) || "align-failed" });
          } catch { /* ignore */ }
        }
        return true;
      }
      if (msg.type === "brand-pinyin-batch") {
        try {
          const list = typeof NS.brandPinyinBatchBg === "function"
            ? NS.brandPinyinBatchBg(msg.texts || [])
            : [];
          sendResponse({ success: true, results: list });
        } catch (e) {
          try {
            sendResponse({ success: false, results: [], error: (e && e.message) || "batch-failed" });
          } catch { /* ignore */ }
        }
        return true;
      }
      if (msg.type === "fetchPageText") return handleFetchPageText(msg, sendResponse);
      if (msg.type === "probeDownloadBehavior") return handleProbeDownloadBehavior(msg, sendResponse);
    });
  };
})(self.SilverfoxBackground ??= {});
