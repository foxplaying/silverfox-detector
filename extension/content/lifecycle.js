/**
 * 生命周期：finalize / SPA URL 变更重置 / 导航观察 / hooks 消息桥 / ICP-WHOIS 流水线 / boot。
 */
;(function (NS) {
  "use strict";

  NS.finalize = function () {
    const state = NS.state;
    const c = NS.caches;
    if (c.finalizeScheduled) return;
    if (state._analysisDone && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected && !state._seoCloakKitDetected) { NS.emitRiskReport(true); return; }
    c.finalizeScheduled = true;
    try {
      if (NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode || NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.enterIntelLightMode("finalize-mature"); NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("finalize-mature"); return; }
      if (state._perfBenign && !state.downloadGuardInstalled) { NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("finalize-benign"); return; }
      if (!state._analysisDone || state.downloadGuardInstalled || state.score >= 12) { NS.detectDomAbnormalities(); if (!state._perfBenign) NS.detectLandingPageImpersonation(); NS.detectContentMismatch(); }
      NS.maybeLiftDownloadGuard();
      NS.markAnalysisComplete("finalize");
    } finally { c.finalizeScheduled = false; }
  };

  NS.resetAnalysisStateForPageChange = function (reason) {
    const state = NS.state;
    const c = NS.caches;
    const prevHost = state._analyzedHost || "";
    const hostChanged = !prevHost || prevHost !== (location.hostname || "");
    state.score = 0; state.details = [];
    if (state.signalSet && typeof state.signalSet.clear === "function") state.signalSet.clear(); else state.signalSet = new Set();
    state.mutationCount = 0; state.iframeCount = 0; state.hiddenCount = 0; state.overlayCount = 0;
    state.scriptInjectionCount = 0; state.dynamicExecCount = 0; state.popupCount = 0; state.redirectCount = 0;
    state.fetchCount = 0; state.crossOriginCount = 0;
    if (state.hosts && typeof state.hosts.clear === "function") state.hosts.clear(); else state.hosts = new Set();
    state.textLength = 0; state.resourceCount = 0; state.formCount = 0; state.inputCount = 0;
    state.visibleLinks = 0; state.visibleTextLength = 0; state.visibleElements = 0;
    state.remoteDownloadDispatchDetected = false; state.downloadGuardInstalled = false;
    state.protectedTargets = []; state.protectionNoticeSent = false; state.spoofBrand = "";
    state.contextCache = null; state.contextCacheAt = 0;
    state._perfBenign = false; state._perfBenignAt = 0; state._intelLightMode = false; state._serpLightNotified = false;
    state._analysisDone = false; state._analysisDoneAt = 0;
    state._pendingSoftBrandSpoof = false; state._icpQuerySettled = false; state._icpQueryFailed = false;
    state._pageBootAt = Date.now(); state._pendingEncryptedSpa = false; state._encryptedSpaRescanArmed = false;
    state._scanBusy = false; state._lastFastScanAt = 0;
    state._earlyShellArmed = false; state._guardRedisableArmed = false;
    state._seoCloakKitDetected = false; state._indexNowPhishTemplate = false; state._multiPlatformSerpTrap = false;
    state._brandSpoofPortalDetected = false; state._fakeSpaDetected = false; state._brandResourceMismatchDetected = false;
    state._fakeBrandShellDetected = false; state._cloneOfficialDetected = false; state._cloneScanAt = 0;
    state._desktopForceDlKit = false; state._remoteGarbleDlDetected = false;
    state._remoteApiChecked = false; state._antiDebugChecked = false;
    c.finalizeScheduled = false; c.lastReportAt = 0;
    NS.invalidateHtmlCache();
    if (hostChanged) { state.icpInfo = ""; state.whoisInfo = ""; state.icpMatchedHost = ""; }
    state._analyzedHost = location.hostname || "";
    try { NS.postToHooks({ type: "set-guard", enabled: false }); NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
    try {
      if (chrome?.runtime?.id) {
        chrome.runtime.sendMessage({ type: "page-analysis-reset", url: location.href, reason: reason || "page-url-changed" }, () => { void chrome.runtime.lastError; });
        chrome.runtime.sendMessage({ type: "set-tab-protect", enabled: false, force: hostChanged, url: location.href }, () => { void chrome.runtime.lastError; });
      }
    } catch { /* ignore */ }
    try { c.sentNoticeKeys.clear(); c.sentNoticeLastAt.clear(); c.pageToastLastAt.clear(); } catch { /* ignore */ }
    NS.emitRiskReport(true);
    c.intelDoneForUrl = "";
    state._intelUrlKey = "";
    c.intelGeneration += 1;
  };

  NS.scheduleRescanAfterPageChange = function () {
    const c = NS.caches;
    if (c.pageNavRescanTimer) { try { clearTimeout(c.pageNavRescanTimer); } catch { /* ignore */ } c.pageNavRescanTimer = null; }
    c.pageNavRescanTimer = setTimeout(() => {
      c.pageNavRescanTimer = null;
      NS.startIcpWhoisIntelEarly("page-url-changed");
      try { NS.tryEarlyShellProtect(); NS.armImmediatePackageBlock(); NS.scanSuspiciousPackagesFast(true); } catch (e) { console.warn("page-change early rescan failed", e); }
      NS.scheduleIdle(() => {
        try {
          if (NS.looksLikeUltraMatureIcpDomain() || NS.state._intelLightMode || NS.state._perfBenign) { NS.emitRiskReport(true); return; }
          if (!NS.state._perfBenign) NS.detectLandingPageImpersonation();
          NS.scanSuspiciousPackagesFast(true);
          NS.emitRiskReport(true);
        } catch { /* ignore */ }
      }, 900);
      NS.scheduleIdle(() => {
        try {
          if (NS.looksLikeUltraMatureIcpDomain() || NS.state._intelLightMode || NS.state._perfBenign || NS.isBenignContentPage() || NS.shouldNeverArmProtection()) { NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true); return; }
          NS.scanSuspiciousPackagesFast(true);
          if (NS.state._perfBenign || NS.isBenignContentPage()) { NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true); return; }
          NS.detectLinkedLandingPageSources().catch(() => {}).finally(() => { NS.maybeLiftDownloadGuard(); NS.finalize(); });
        } catch { NS.finalize(); }
      }, 1400);
    }, 120);
  };

  NS.handlePageUrlChanged = function (reason, incomingUrl) {
    const c = NS.caches;
    const url = (incomingUrl && String(incomingUrl)) || location.href;
    const live = location.href;
    const key = live || url;
    if (!NS.isHttpOrHttpsPage(key) && !NS.isHttpOrHttpsPage(live)) { NS.silverfoxLog("nav-skip", "non-http-protocol", String(key).slice(0, 80)); return; }
    if (c.lastAnalyzedUrl && key === c.lastAnalyzedUrl) return;
    if (c.pageNavResetBusy) { setTimeout(() => NS.handlePageUrlChanged(reason || "url-changed-retry", incomingUrl), 80); return; }
    c.pageNavResetBusy = true;
    try { c.lastAnalyzedUrl = key; NS.resetAnalysisStateForPageChange(reason || "url-changed"); NS.scheduleRescanAfterPageChange(); }
    finally { c.pageNavResetBusy = false; }
  };

  NS.installPageNavigationWatchers = function () {
    const c = NS.caches;
    c.lastAnalyzedUrl = location.href;
    NS.state._analyzedHost = location.hostname || "";
    const onNav = (reason) => { try { requestAnimationFrame(() => NS.handlePageUrlChanged(reason)); } catch { setTimeout(() => NS.handlePageUrlChanged(reason), 0); } };
    window.addEventListener("popstate", () => onNav("popstate"), true);
    window.addEventListener("hashchange", () => onNav("hashchange"), true);
    window.addEventListener("pageshow", (ev) => { if (ev && ev.persisted) onNav("pageshow-bfcache"); else if (location.href !== c.lastAnalyzedUrl) onNav("pageshow"); });
    try {
      const wrap = (method) => { const orig = history[method]; if (typeof orig !== "function") return; history[method] = function patchedHistoryMethod(...args) { const ret = orig.apply(this, args); onNav(method); return ret; }; };
      wrap("pushState"); wrap("replaceState");
    } catch { /* ignore */ }
    try {
      if (chrome?.runtime?.onMessage) {
        chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
          try { if (msg && msg.type === "page-url-changed") { NS.handlePageUrlChanged("bg-page-url-changed", msg.url || ""); try { sendResponse({ ok: true }); } catch { /* ignore */ } return false; } } catch { /* ignore */ }
          return false;
        });
      }
    } catch { /* ignore */ }
    let pollTicks = 0;
    const pollId = setInterval(() => {
      pollTicks += 1;
      if (pollTicks > 600) { try { clearInterval(pollId); } catch { /* ignore */ } return; }
      try { if (location.href !== c.lastAnalyzedUrl) NS.handlePageUrlChanged("poll"); } catch { /* ignore */ }
    }, 1000);
  };

  /** MAIN-world hooks -> isolated content 消息桥。 */
  NS.installHooksMessageBridge = function () {
    window.addEventListener("message", (event) => {
      if (event.source !== window) return;
      const data = event.data;
      if (!data || data.source !== NS.HOOK_SOURCE) return;
      const state = NS.state;
      const c = NS.caches;
      if (NS.silverfoxLog) NS.silverfoxLog("hooks-in", data.type, data.name || "", String(data.reason || data.href || "").slice(0, 100));

      if (data.type === "signal" && data.name) {
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.notifyHooksOfficialSafe(true); return; }
        if (NS.isBenignContentPage() && !/安装包|下载|远程|PHP|API|仿冒|手势|跳转/i.test(data.name || "")) return;
        if (/非用户手势|自动下载|自动跳转/i.test(data.name || "") || /非用户手势|auto-nav-no-gesture|kit-or-relay-auto-external/i.test(data.reason || "")) {
          const r = String(data.reason || "");
          const m = r.match(/([A-Za-z0-9][A-Za-z0-9._-]{2,120}\.(?:zip|exe|apk|msi|dmg|rar|7z))/i);
          const maybeName = m ? m[1] : "";
          const hrefFromReason = (r.match(/https?:\/\/[^\s"'<>\\]+/i) || [])[0] || "";
          if (hrefFromReason && NS.isAuthSsoOrLoginRedirectUrl(hrefFromReason)) return;
          if (/非用户手势自动跳转/i.test(data.name || "") && hrefFromReason && !NS.isPackageFileUrl(hrefFromReason) && !NS.looksLikeOpaqueDownloadHopUrl(hrefFromReason) && !state._seoCloakKitDetected) return;
          if (maybeName && (NS.looksLikeStrongProductInstallerName(maybeName) || NS.isClearProductOrAndroidPackage(maybeName) || NS.looksLikeProductPackageName(maybeName) || NS.isBenignShortInstallerName(maybeName) || NS.isContentAddressedPackageName(maybeName) || NS.isAllowlistedProductPackageUrl(maybeName))) return;
          if (hrefFromReason && (NS.isAllowlistedProductPackageUrl(hrefFromReason) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(hrefFromReason)))) return;
          if (NS.looksLikeSafeOfficialContext() || NS.isTrustedOfficialDownloadContext()) return;
        }
        if (/安装配置拉取|配置拉取|info-only/i.test(data.name || "")) { NS.addSignal(data.name, data.weight || 0, data.reason || ""); return; }
        if (/桌面端强制弹窗下载/i.test(data.name || "") || /dlp|强制弹窗下载/i.test(data.reason || "")) {
          NS.addSignal(data.name, data.weight || 0, data.reason || "");
          if (!state._desktopForceDlKit) { state._desktopForceDlKit = true; NS.installDownloadGuard(data.reason || data.name, { notify: true, forceNotify: true, title: "已拦截强制弹窗下载", message: data.reason || "桌面端强制弹窗下载套件" }); NS.postToHooks({ type: "set-guard", enabled: true }); NS.disableAllDownloadIntentControls(); }
          else if (state.downloadGuardInstalled) { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); }
          return;
        }
        if (/已拦截页面下载拉取|guard-block/i.test(data.name || "") || /guard-block-all-download|保护模式下拦截/i.test(data.reason || "")) {
          NS.addSignal(data.name, data.weight || 0, data.reason || "");
          if (state.downloadGuardInstalled) { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); }
          return;
        }
        NS.addSignal(data.name, data.weight || 0, data.reason || "");
        if (/远程|API|下载|手势|跳转/i.test(data.name || "")) {
          const r = String(data.reason || "");
          const m = r.match(/([A-Za-z0-9][A-Za-z0-9._-]{2,120}\.(?:zip|exe|apk|msi|dmg|rar|7z))/i);
          if (m && (NS.looksLikeStrongProductInstallerName(m[1]) || (NS.looksLikeProductPackageName(m[1]) && !NS.looksLikeOversimplifiedBrandInstallerName(m[1])) || NS.isClearProductOrAndroidPackage(m[1]))) return;
          const hrefM = (r.match(/https?:\/\/[^\s"'<>]+/i) || [])[0] || "";
          if (hrefM && (NS.isAllowlistedProductPackageUrl(hrefM) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(hrefM)))) return;
          if ((data.weight || 0) <= 8 && !/手势|仿冒|跳转|下发|API动态/i.test(data.name || "")) return;
          NS.installDownloadGuard(data.reason || data.name, { notify: true, href: hrefM || "", message: data.reason || data.name });
        }
        return;
      }
      if (data.type === "blocked-download") {
        const href = data.href || "";
        const reason = data.reason || "";
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.notifyHooksOfficialSafe(true); return; }
        if (href && NS.isAuthSsoOrLoginRedirectUrl(href)) return;
        if (/非用户手势自动跳转/i.test(reason) && href && NS.isAuthSsoOrLoginRedirectUrl(href)) return;
        if (href && NS.isSiteHomeUrl(href) && !NS.isPackageFileUrl(href)) return;
        const fn = href ? NS.getFilenameFromUrl(href) : "";
        if (href && (NS.isAllowlistedProductPackageUrl(href) || NS.looksLikeStrongProductInstallerName(fn) || NS.isClearProductOrAndroidPackage(href) || NS.isClearProductOrAndroidPackage(fn) || NS.looksLikeProductPackageName(fn) || NS.isBenignShortInstallerName(fn) || NS.isContentAddressedPackageName(fn)) && !NS.looksLikeBrandNearMissPackageName(fn) && !NS.isSuspiciousDownloadFilename(fn)) return;
        const autoNoGesture = /auto-nav-no-gesture|auto-search-trap|auto-external|phish-shell-auto|非用户手势|programmatic-a\.click|programmatic/i.test(reason);
        if (!NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href) && !autoNoGesture) {
          if (/api\.php|download_link|远程API|远程下发|download_uri/i.test(reason)) NS.installDownloadGuard(reason || "可疑下载", { notify: true, href: "", message: reason || "远程动态下载" });
          return;
        }
        if (autoNoGesture && href && !NS.isPackageFileUrl(href) && NS.isAuthSsoOrLoginRedirectUrl(href)) return;
        if (autoNoGesture && href && !NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href) && /非用户手势自动跳转|kit-or-relay-auto-external|auto-external/i.test(reason) && !state._seoCloakKitDetected && !state._brandSpoofPortalDetected) return;
        if (autoNoGesture && (NS.looksLikeSafeOfficialContext() || NS.isTrustedOfficialDownloadContext()) && !state._seoCloakKitDetected && !state._brandSpoofPortalDetected) return;
        if (autoNoGesture && href && (NS.isAllowlistedProductPackageUrl(href) || NS.looksLikeStrongProductInstallerName(fn))) return;
        if (href && !state.protectedTargets.includes(href)) state.protectedTargets.push(href);
        NS.markRemoteDownloadDispatch(reason || `blocked -> ${href}`, href);
        let msg = NS.formatPackageLabel(href);
        try { const u = new URL(href, location.href); if (!NS.PACKAGE_EXT.test(u.pathname)) msg = `${u.hostname}${u.pathname}`; } catch { /* ignore */ }
        if (autoNoGesture) NS.installDownloadGuard(reason || "非用户手势自动下载", { notify: true, href, message: msg || "自动下载已拦截", forceNotify: !state.protectionNoticeSent });
        else { NS.showGuardOverlay(href, { title: "已拦截可疑下载", message: msg }); NS.installDownloadGuard(reason || `已拦截可疑下载: ${msg}`, { notify: true, href, message: msg, forceNotify: false }); }
        NS.disableSuspiciousDownloadButtons();
        return;
      }
      if (data.type === "request-guard") {
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.notifyHooksOfficialSafe(true); return; }
        try {
          const rr = String(data.reason || "");
          if (/非用户手势自动跳转|auto-nav-no-gesture|kit-or-relay-auto-external/i.test(rr)) { const hrefM = rr.match(/https?:\/\/[^\s"'<>\\]+/i); if (hrefM && NS.isAuthSsoOrLoginRedirectUrl(hrefM[0])) return; }
          const hrefAny = rr.match(/https?:\/\/[^\s"'<>]+/i);
          if (hrefAny && NS.isAuthSsoOrLoginRedirectUrl(hrefAny[0]) && !NS.isPackageFileUrl(hrefAny[0])) return;
        } catch { /* ignore */ }
        try {
          const rr = String(data.reason || "");
          const hrefM = rr.match(/https?:\/\/[^\s"'<>]+/i);
          const nameM = rr.match(/([A-Za-z0-9][A-Za-z0-9._-]{2,120}\.(?:zip|exe|apk|msi|dmg|rar|7z))/i);
          const hrefHit = hrefM && (NS.isAllowlistedProductPackageUrl(hrefM[0]) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(hrefM[0])) || NS.isClearProductOrAndroidPackage(hrefM[0]) || NS.looksLikeProductPackageName(NS.getFilenameFromUrl(hrefM[0])));
          const nameHit = nameM && (NS.looksLikeStrongProductInstallerName(nameM[1]) || NS.isClearProductOrAndroidPackage(nameM[1]) || NS.looksLikeProductPackageName(nameM[1]) || NS.isBenignShortInstallerName(nameM[1]));
          if (hrefHit || nameHit) return;
        } catch { /* ignore */ }
        NS.armBackgroundProtect("full");
        try { chrome.runtime.sendMessage({ type: "request-guard-bg", mode: "full", url: location.href, reason: data.reason || "" }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
        NS.installDownloadGuard(data.reason || "页面行为触发下载保护", { notify: true, message: data.reason || "可疑下载保护" });
        NS.disableSuspiciousDownloadButtons();
        NS.scanSuspiciousPackagesFast();
        return;
      }
      if (data.type === "stat") {
        if (data.key === "host" && data.value) { state.hosts.add(data.value); return; }
        if (data.key && typeof data.delta === "number" && data.key in state) state[data.key] = (state[data.key] || 0) + data.delta;
        return;
      }
      if (data.type === "hooks-ready") { if (state.downloadGuardInstalled) NS.postToHooks({ type: "set-guard", enabled: true }); }
    });
  };

  async function runIcpWhoisIntel(genOpt, urlKeyOpt) {
    const state = NS.state;
    const c = NS.caches;
    const gen = genOpt != null ? genOpt : c.intelGeneration;
    const urlKey = urlKeyOpt || location.href;
    const pageHost = NS.normalizeDomain(location.hostname);
    if (!pageHost || !/^https?:/i.test(String(location.protocol || ""))) { if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey; return; }
    let whois = null;
    try { whois = await NS.detectWhoisRegistrationAge(pageHost || location.hostname); } catch { whois = { success: false }; }
    if (gen !== c.intelGeneration || location.href !== urlKey) return;
    NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true);
    if (!NS.whoisHasResult(whois)) {
      state.icpInfo = ""; state.icpMatchedHost = "";
      state._icpQuerySettled = true; state._icpQueryFailed = false;
      if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
      if (state._pendingSoftBrandSpoof && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
        state._pendingSoftBrandSpoof = false;
        try { if (NS.detectBrandSpoofDownloadPortal()) state._brandSpoofPortalDetected = true; } catch { /* ignore */ }
      }
      NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true);
      return;
    }
    try {
      if (!pageHost) { state.icpInfo = ""; state.icpMatchedHost = ""; state._icpQuerySettled = true; state._icpQueryFailed = false; if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey; NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true); return; }
      const icpCheck = await NS.detectIcpDomain(pageHost);
      if (gen !== c.intelGeneration || location.href !== urlKey) return;
      if (!icpCheck.success) { NS.silverfoxLog("intel-icp", "api-fail"); state._icpQueryFailed = true; state._icpQuerySettled = false; if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey; NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true); return; }
      let record = (icpCheck.icpRecord && NS.looksLikeIcpLicense(icpCheck.icpRecord)) ? icpCheck.icpRecord : "";
      const matched = icpCheck.matchedHost || icpCheck.queriedHost || pageHost;
      if (record && !NS.intelHostIsValidAttribution(matched, pageHost)) record = "";
      const missing = !record && (icpCheck.icpMissing || !icpCheck.icpRecord);
      state.icpMatchedHost = record ? NS.normalizeDomain(matched || pageHost) : "";
      const tried = Array.isArray(icpCheck.triedHosts) ? icpCheck.triedHosts : [];
      state.icpInfo = record ? (matched && matched !== pageHost ? `${record}（主域 ${matched}）` : record) : (missing ? "未查询到备案信息" : "");
      state._icpQuerySettled = true; state._icpQueryFailed = false;
      NS.silverfoxLog("intel-icp", record ? "valid" : (missing ? "missing" : "empty"), String(state.icpInfo || "").slice(0, 80), "host=", pageHost);
      const ageDays = NS.getWhoisAgeDays();
      const skipMissingIcp = state._perfBenign || state._intelLightMode || NS.isBenignContentPage() || (ageDays != null && ageDays >= 365) || NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeLongLivedWhoisDomain();
      if (missing && !skipMissingIcp) {
        const whoisNote = whois.queriedHost && whois.queriedHost !== pageHost ? `，WHOIS 经 ${whois.queriedHost}` : "";
        const triedNote = tried.length ? `，ICP 候选 ${tried.join(" -> ")}` : "";
        NS.addSignal("无ICP备案信息", 6, `当前域名 ${location.hostname}${whoisNote}${triedNote} 未查询到备案信息`);
      }
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit) {
        NS.clearBrandSpoofFalsePositive("valid-icp");
        state._pendingSoftBrandSpoof = false;
        state._perfBenign = true; state._perfBenignAt = Date.now();
        try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ }
        if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
        NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("valid-icp"); NS.emitRiskReport(true);
        if (!(NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain() || (ageDays != null && ageDays >= 3650))) return;
      }
      if (!NS.hasValidIcpRecord() && state._pendingSoftBrandSpoof && state._icpQuerySettled && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
        state._pendingSoftBrandSpoof = false;
        try { if (NS.detectBrandSpoofDownloadPortal()) state._brandSpoofPortalDetected = true; } catch { /* ignore */ }
      }
      if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain() || (NS.hasValidIcpRecord() && ageDays != null && ageDays >= 3650)) {
        NS.enterIntelLightMode("whois-ultra-mature"); NS.clearBrandSpoofFalsePositive("whois-ultra-mature");
        if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
        NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("whois-ultra-mature"); NS.emitRiskReport(true); return;
      }
      if (NS.looksLikeLongLivedWhoisDomain() || (NS.hasValidIcpRecord() && ageDays != null && ageDays >= 1825)) {
        NS.enterIntelLightMode("whois-mature-5y");
        if (NS.hasValidIcpRecord()) NS.clearBrandSpoofFalsePositive("icp-mature-5y");
        try { const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || ""; if (lab.length >= 4 && (document.title || "").toLowerCase().includes(lab)) NS.clearBrandSpoofFalsePositive("host-in-title-5y"); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
    NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true);
  }

  NS.startIcpWhoisIntelEarly = function (reason) {
    const c = NS.caches;
    void reason;
    if (!NS.isHttpOrHttpsPage()) return;
    const urlKey = location.href;
    if (c.intelDoneForUrl === urlKey) return;
    if (c.intelBusy && c.intelDoneForUrl === "" && NS.state._intelUrlKey === urlKey) return;
    if (NS.state._intelUrlKey && NS.state._intelUrlKey !== urlKey) c.intelGeneration += 1;
    NS.state._intelUrlKey = urlKey;
    const gen = c.intelGeneration;
    c.intelBusy = true;
    Promise.resolve().then(() => runIcpWhoisIntel(gen, urlKey)).catch(() => {}).finally(() => { if (gen === c.intelGeneration) c.intelBusy = false; });
  };

  // 修复：startIcpWhoisIntelEarly 里引用了未定义的 state，用 NS.state

  // === Boot 入口 ===
  const bootIsSearchUrl = (() => { try { return typeof NS.isSearchUrlShapeOnly === "function" && NS.isSearchUrlShapeOnly(); } catch { return false; } })();

  if (bootIsSearchUrl) {
    const state = NS.state;
    state._perfBenign = true; state._perfBenignAt = Date.now();
    state._intelLightMode = true; state._serpLightNotified = true;
    try { NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    try { NS.markAnalysisComplete("boot-search-light"); } catch { /* ignore */ }
    try { NS.startIcpWhoisIntelEarly("boot-search-light"); } catch (e) { console.warn("early WHOIS/ICP start failed", e); }
  } else {
    const state = NS.state;
    NS.detectMutationBomb();
    NS.detectEnvironmentalAnomalies();
    NS.detectInteractionAbuse();
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    NS.installHooksMessageBridge();

    try { NS.startIcpWhoisIntelEarly("boot-document-start"); } catch (e) { console.warn("early WHOIS/ICP start failed", e); }

    try {
      NS.scheduleIdle(() => { try { if (NS.pageLooksLikeLegitimateOfficialDownload() || NS.looksLikeMatureOfficialPortal()) { NS.notifyHooksOfficialSafe(true); if (state.downloadGuardInstalled || state._earlyShellArmed) NS.clearDownloadGuard("boot-official-portal"); } } catch { /* ignore */ } }, 400);
      NS.scheduleIdle(() => { try { if (NS.pageLooksLikeLegitimateOfficialDownload() || NS.looksLikeMatureOfficialPortal() || NS.shouldNeverArmProtection()) { NS.notifyHooksOfficialSafe(true); NS.maybeLiftDownloadGuard(); } } catch { /* ignore */ } }, 2000);
    } catch { /* ignore */ }

    try { if (chrome?.runtime?.id) chrome.runtime.sendMessage({ type: "set-tab-protect", enabled: false, url: location.href }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }

    try {
      let lastPauseAt = 0;
      const pauseDnrOnGesture = (e) => {
        try {
          if (e && e.isTrusted === false) return;
          if (e && typeof e.button === "number" && e.button !== 0) return;
          if (state._intelLightMode || state._perfBenign || NS.isSearchUrlShapeOnly()) return;
          try { const t = e && e.target; const tag = t && (t.tagName || "").toUpperCase(); if (tag === "INPUT" || tag === "TEXTAREA") return; } catch { /* ignore */ }
          const now = Date.now(); if (now - lastPauseAt < 400) return; lastPauseAt = now;
          if (!chrome?.runtime?.id) return;
          chrome.runtime.sendMessage({ type: "pause-nav-blocking", reason: "user-gesture", url: location.href }, () => { void chrome.runtime.lastError; });
        } catch { /* ignore */ }
      };
      const gOpts = { capture: true, passive: true };
      for (const t of ["pointerdown", "mousedown", "keydown", "touchstart"]) window.addEventListener(t, pauseDnrOnGesture, gOpts);
      window.addEventListener("pagehide", () => { try { chrome.runtime.sendMessage({ type: "pause-nav-blocking", reason: "pagehide", clearProtect: false, url: location.href }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } }, { capture: true });
    } catch { /* ignore */ }

    try {
      if (!NS.isSearchUrlShapeOnly()) {
        NS.tryEarlyShellProtect();
        const titleEl = document.querySelector("title");
        if (titleEl && typeof MutationObserver !== "undefined") {
          let titleKick = null;
          const mo = new MutationObserver(() => { if (titleKick) return; titleKick = setTimeout(() => { titleKick = null; try { NS.tryEarlyShellProtect(); } catch { /* ignore */ } }, 200); });
          try { mo.observe(titleEl, { childList: true, characterData: true, subtree: true }); } catch { /* ignore */ }
          setTimeout(() => { try { mo.disconnect(); } catch { /* ignore */ } }, 4000);
        }
        setTimeout(() => NS.tryEarlyShellProtect(), 300);
      }
    } catch { /* ignore */ }

    try {
      if (NS.isSearchUrlShapeOnly() || NS.pageLooksLikeSearchEngineResultsPage()) {
        state._perfBenign = true; state._perfBenignAt = Date.now(); state._intelLightMode = true;
        NS.postToHooks({ type: "set-light-page", enabled: true });
      } else { NS.watchSuspiciousPackagesLive(); }
    } catch (e) {
      console.warn("watchSuspiciousPackagesLive failed", e);
      try { if (!NS.isSearchUrlShapeOnly()) NS.armImmediatePackageBlock(); } catch { /* ignore */ }
    }

    try { NS.emitRiskReport(true); } catch { /* ignore */ }

    const runEarlyHeuristics = () => {
      try {
        if (state._analysisDone && !state.downloadGuardInstalled) return;
        NS.tryEarlyShellProtect();
        NS.scanSuspiciousPackagesFast();
        NS.scheduleIdle(() => {
          try {
            if (state._perfBenign && !state._pendingEncryptedSpa && state._analysisDone) { NS.emitRiskReport(true); return; }
            if (NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan(); try { NS.invalidateHtmlCache(); } catch { /* ignore */ } NS.scanSuspiciousPackagesFast(true); NS.emitRiskReport(true); return; }
            if (state._analysisDone) { NS.emitRiskReport(true); return; }
            if (/官网|官方下载|客户端/i.test(document.title || "")) NS.detectLandingPageImpersonation();
            if (!state._analysisDone) NS.markAnalysisComplete("early-idle"); else NS.emitRiskReport(true);
          } catch { /* ignore */ }
        }, 800);
      } catch (e) { console.warn("early heuristics failed", e); }
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => { NS.scheduleIdle(runEarlyHeuristics, 400); }, { once: true });
    else NS.scheduleIdle(runEarlyHeuristics, 300);

    window.addEventListener("load", () => { try { if (NS.caches.intelDoneForUrl !== location.href) NS.startIcpWhoisIntelEarly("load-retry"); } catch { /* ignore */ } }, { once: true });

    window.addEventListener("load", () => {
      NS.scheduleIdle(() => {
        if (state._pendingEncryptedSpa || NS.shouldDeferAnalysisCompleteForEncryptedSpa()) {
          state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan();
          try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
          if (state._analysisDone && !state.downloadGuardInstalled) state._analysisDone = false;
          NS.scanSuspiciousPackagesFast(true); NS.emitRiskReport(true); return;
        }
        if (state._analysisDone && !state.downloadGuardInstalled) { NS.emitRiskReport(true); return; }
        if (NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode) { NS.enterIntelLightMode("load-ultra-mature"); NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-ultra-mature"); return; }
        NS.scanSuspiciousPackagesFast();
        if (state._pendingEncryptedSpa || NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { NS.armEncryptedSpaLateRescan(); NS.emitRiskReport(true); return; }
        if (state._perfBenign || NS.isBenignContentPage() || NS.shouldNeverArmProtection()) { NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-benign"); return; }
        if (state._analysisDone) { NS.emitRiskReport(true); return; }
        NS.detectLinkedLandingPageSources().catch(() => {}).finally(() => { NS.maybeLiftDownloadGuard(); NS.finalize(); });
      }, 600);
      setTimeout(() => {
        if (state._analysisDone && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) return;
        if (NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { NS.armEncryptedSpaLateRescan(); return; }
        NS.maybeLiftDownloadGuard(); NS.finalize();
      }, 2500);
    }, { once: true });

    let visibilityTimer = null;
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible") return;
      if (state._analysisDone && !state.downloadGuardInstalled) return;
      if (state._perfBenign && !state.downloadGuardInstalled) return;
      if (visibilityTimer) clearTimeout(visibilityTimer);
      visibilityTimer = setTimeout(() => {
        if (state._analysisDone && !state.downloadGuardInstalled) return;
        state.contextCache = null;
        NS.scanSuspiciousPackagesFast();
        if (!state._analysisDone) NS.finalize();
      }, 2000);
    });
  }
})(window.SilverfoxContent ??= {});
