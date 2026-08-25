/**
 * 生命周期：finalize / SPA URL 变更重置 / 导航观察 / hooks 消息桥 / ICP-WHOIS 流水线 / boot。
 */
;(function (NS) {
  "use strict";

  function restoreForcedMissingIcpState() {
    try {
      const state = NS.state;
      const preserve = typeof NS.shouldPreserveForcedMissingIcp === "function"
        ? NS.shouldPreserveForcedMissingIcp()
        : !!state._icpForcedMissingByFallbackWhois;
      if (!preserve) return false;
      state.icpInfo = "未查询到备案信息";
      state.icpMatchedHost = "";
      state._icpQueryFailed = false;
      if (typeof NS.addSignal === "function") {
        NS.addSignal("无ICP备案信息", 6, `当前域名 ${location.hostname} 未查询到备案信息`);
      }
      return true;
    } catch { return false; }
  }

  NS.finalize = function () {
    const state = NS.state;
    const c = NS.caches;
    if (c.finalizeScheduled) return;
    if (state._analysisDone && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected && !state._seoCloakKitDetected) { NS.emitRiskReport(true); return; }
    c.finalizeScheduled = true;
    try {
      // 海量镜像/ISO：禁止 finalize 再跑 DOM 仿冒等重检测
      if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
        state._perfBenign = true;
        state._intelLightMode = true;
        NS.maybeLiftDownloadGuard();
        NS.markAnalysisComplete("finalize-skip-heavy");
        return;
      }
      if (NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode || NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.enterIntelLightMode("finalize-mature"); NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("finalize-mature"); return; }
      if (state._perfBenign && !state.downloadGuardInstalled) { NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("finalize-benign"); return; }
      if (!state._analysisDone || state.downloadGuardInstalled || state.score >= 12) {
        if (!(typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan())) {
          NS.detectDomAbnormalities();
          if (!state._perfBenign) NS.detectLandingPageImpersonation();
          NS.detectContentMismatch();
        }
      }
      NS.maybeLiftDownloadGuard();
      NS.markAnalysisComplete("finalize");
    } finally { c.finalizeScheduled = false; }
  };

  NS.resetAnalysisStateForPageChange = function (reason) {
    const state = NS.state;
    const c = NS.caches;
    try {
      if (state._brandSpoofFinalSnapshot
        && typeof NS.invalidateBrandSpoofNoticeSnapshot === "function") {
        NS.invalidateBrandSpoofNoticeSnapshot(state._brandSpoofFinalSnapshot, reason || "page-url-changed");
      }
    } catch { /* ignore */ }
    // Rotate before every early-return branch.  A same-host SPA route is a new
    // report transaction even when its trusted identity/intel can be reused.
    try {
      if (typeof NS.rotateAnalysisTransaction === "function") {
        NS.rotateAnalysisTransaction(String(location.href || ""), reason || "page-url-changed");
      }
    } catch { /* keep reset operational */ }
    // Navigation owns the identity transaction boundary. Invalidate the old
    // hold before any keep-light/keep-trusted early return, otherwise an SPA
    // can leave a download route and later revive its orphaned waiting lock.
    state._provisionalDownloadAnalysisGeneration = Number(state._provisionalDownloadAnalysisGeneration || 0) + 1;
    state._provisionalDownloadIdentityHold = false;
    state._provisionalDownloadIdentityUrl = "";
    state._provisionalDownloadIdentityDeadlineAt = 0;
    state._identityVerificationUnavailable = false;
    state._identityVerificationUnavailableUrl = "";
    try {
      if (c._provisionalDownloadController && typeof c._provisionalDownloadController.cancel === "function") {
        c._provisionalDownloadController.cancel("page-change");
      }
    } catch { /* ignore */ }
    c._provisionalDownloadController = null;
    state._officialDownloadScanQuiet = false;
    state._officialDownloadScanQuietUrl = "";
    try {
      if (c && typeof c._stopSuspiciousLiveWatch === "function") c._stopSuspiciousLiveWatch();
    } catch { /* ignore */ }
    try {
      if (c && c._brandElectionHydrationWatch
        && typeof c._brandElectionHydrationWatch.stop === "function") {
        c._brandElectionHydrationWatch.stop();
      }
    } catch { /* ignore */ }
    if (c) c._brandElectionHydrationWatch = null;
    state._brandElectionIdentityFingerprint = "";
    state._brandElectionIdentityFingerprintUrl = "";
    state._brandElectionIdentityFingerprintAt = 0;
    state._brandElectionIdentityRevision = 0;
    try {
      if (state._brandElectionHydrationStableTimer) clearTimeout(state._brandElectionHydrationStableTimer);
    } catch { /* ignore */ }
    state._brandElectionHydrationStableTimer = null;
    state._brandElectionHydrationNudgeBusy = false;
    state._brandElectionHydrationResumeScheduled = false;
    state._brandPinyinRequestSequence = Number(state._brandPinyinRequestSequence || 0) + 1;
    state._brandPinyinRequestFingerprint = "";
    state._brandSpoofFinalSnapshot = null;
    state._brandSpoofNoticeSequence = 0;
    const prevHost = state._analyzedHost || "";
    const hostChanged = !prevHost || prevHost !== (location.hostname || "");
    // 在清威胁标志之前判定是否同站 keep-light（依赖当前 state）
    const keepLight = !hostChanged && typeof NS.shouldKeepLightOnSameHostSoftNav === "function" && NS.shouldKeepLightOnSameHostSoftNav();
    // 同站成熟正规站：轻量路径——只换 URL 报告，不清既有情报。
    const keepTrustedOnce = !hostChanged
      && typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()
      && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
    if (keepLight || keepTrustedOnce) {
      if (keepTrustedOnce) {
        state._trustedBrandIdentityUrl = String(location.href || "");
        state._trustedBrandIdentityAt = Date.now();
        try {
          if (typeof NS.cancelPendingSoftBrandDecision === "function") {
            NS.cancelPendingSoftBrandDecision("soft-nav-keep-trusted");
          }
        } catch { /* ignore */ }
      }
      state._perfBenign = true;
      state._perfBenignAt = Date.now();
      state._intelLightMode = true;
      state._analysisDone = true;
      state._analysisDoneAt = Date.now();
      state._scanBusy = false;
      state._analyzedHost = location.hostname || "";
      try {
        const hk = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
        state._stickyComplete = true;
        state._stickyCompleteHost = hk;
      } catch { /* ignore */ }
      // 保留 icp/whois/_icpQuerySettled/score/details；勿发 page-analysis-reset 清 storage
      try {
        if (typeof NS.markAnalysisComplete === "function") NS.markAnalysisComplete(keepTrustedOnce ? "reset-keep-trusted" : "reset-keep-light");
        else NS.emitRiskReport(true);
      } catch { /* ignore */ }
      // The route has a fresh report transaction and an exact URL. Re-run the
      // (normally cached) identity pipeline so the serializer can complete
      // that new transaction; never reuse the previous path's completion bit.
      try { NS.startIcpWhoisIntelEarly(keepTrustedOnce ? "reset-keep-trusted" : "reset-keep-light"); } catch { /* ignore */ }
      try { NS.ensureBrandElectionHydrationWatch(); } catch { /* ignore */ }
      NS.silverfoxLog && NS.silverfoxLog("nav-reset", "keep-light-or-trusted-once", reason || "", keepTrustedOnce ? "trusted" : "light");
      return;
    }
    // 使上一 URL 尚在运行的品牌 Promise/retry 全部失效。
    state._brandSpoofDecisionGeneration = Number(state._brandSpoofDecisionGeneration || 0) + 1;
    state._brandSpoofDecisionUrl = String(location.href || "");
    state._trustedBrandIdentityUrl = "";
    state._trustedBrandIdentityAt = 0;
    state.score = 0; state.details = [];
    if (state.signalSet && typeof state.signalSet.clear === "function") state.signalSet.clear(); else state.signalSet = new Set();
    // A same-host SPA reset clears signals, but it must not erase a previously
    // proven fallback-WHOIS rejection. Rebuild the host-level verdict now;
    // a later definitive ICP result may still replace it.
    if (!hostChanged) restoreForcedMissingIcpState();
    state.mutationCount = 0; state.iframeCount = 0; state.hiddenCount = 0; state.overlayCount = 0;
    state.scriptInjectionCount = 0; state.dynamicExecCount = 0; state.popupCount = 0; state.redirectCount = 0;
    state.fetchCount = 0; state.crossOriginCount = 0;
    if (state.hosts && typeof state.hosts.clear === "function") state.hosts.clear(); else state.hosts = new Set();
    state.textLength = 0; state.resourceCount = 0; state.formCount = 0; state.inputCount = 0;
    state.visibleLinks = 0; state.visibleTextLength = 0; state.visibleElements = 0;
    state.remoteDownloadDispatchDetected = false; state.downloadGuardInstalled = false;
    state.protectedTargets = []; state.protectionNoticeSent = false; state.spoofBrand = "";
    state._brandSpoofNoticeSent = false; state._brandSpoofNoticeKey = "";
    state._lastGuardNoticeKind = ""; state._lastGuardNoticeKey = ""; state._lastGuardNoticeVersion = "";
    state._spoofBrandReconciledAt = 0;
    state._spoofPinyinUpgradeScheduled = false;
    state._spoofPinyinUpgradeDone = false;
    state._spoofBrandChineseLocked = false;
    state._brandSpoofFinalPresented = false;
    state._brandSpoofFinalSnapshot = null;
    state._brandSpoofNoticeSequence = 0;
    state._brandSpoofFinalizeScheduled = false;
    state._brandSpoofPresentationDeferred = false;
    state._softBrandIdentityReady = false;
    state._softBrandIdentityUrl = "";
    state._brandSpoofLatinOnly = false;
    state._brandElectionSettledUrl = "";
    state._brandElectionSettledAt = 0;
    state._brandElectionAwaitingDom = false;
    state._brandElectionDomListenerInstalled = false;
    state._brandElectionFinalAttempts = 0;
    state._brandElectionRetryPending = false;
    try { if (state._brandElectionRetryTimer) clearTimeout(state._brandElectionRetryTimer); } catch { /* ignore */ }
    state._brandElectionRetryTimer = null;
    state._analysisCompletionDeferredForBrand = false;
    state._brandCompletionResumeScheduled = false;
    state._brandSpoofLatinUpgradeAttempts = 0;
    state._brandPinyinEvidence = null;
    state._brandPinyinHostMatch = "";
    try { NS.ensureBrandElectionHydrationWatch(); } catch { /* ignore */ }
    try {
      if (typeof NS.clearChinesePinyinMatchCache === "function") NS.clearChinesePinyinMatchCache();
    } catch { /* ignore */ }
    state.contextCache = null; state.contextCacheAt = 0;
    state._perfBenign = false; state._perfBenignAt = 0;
    state._officialDownloadScanQuiet = false; state._officialDownloadScanQuietUrl = "";
    state._officialDownloadForceScanAllowed = false;
    state._intelLightMode = false; state._serpLightNotified = false;
    state._analysisDone = false; state._analysisDoneAt = 0;
    // 仅换主机时清粘性 complete；同站 soft-nav 全量 reset 也清（否则永远不复扫）
    state._stickyComplete = false;
    state._stickyCompleteHost = "";
    state._pendingSoftBrandSpoof = false;
    // 同站：保留 ICP 结算状态与备案文案，避免 soft-nav 重查卡死
    if (hostChanged) {
      state._icpQuerySettled = false;
      state._icpQueryFailed = false;
      state._icpForcedMissingByFallbackWhois = false;
      state._icpForcedMissingHost = "";
      state.icpInfo = "";
      state.whoisInfo = "";
      state.sslInfo = null;
      state._sslIdentityUrl = String(location.href || "");
      state._sslIdentityStartedAt = 0;
      state._sslIdentityObserved = false;
      state._sslIdentitySettled = false;
      state._sslIdentityTimedOut = false;
      state.icpMatchedHost = "";
      state.pageDeclaredIcp = "";
      state._icpPageMismatch = false;
      state._unverifiedPageIcpClaim = false;
      state._unverifiedIcpIdentityThreat = false;
    } else {
      // 同 host 全量重扫保留可复用证书，但把归属 URL 切到当前页。
      state._sslIdentityUrl = String(location.href || "");
      state._sslIdentityStartedAt = 0;
      state._sslIdentityObserved = !!state.sslInfo;
      state._sslIdentitySettled = !!state.sslInfo;
      state._sslIdentityTimedOut = false;
    }
    state._pageBootAt = Date.now(); state._pendingEncryptedSpa = false; state._encryptedSpaRescanArmed = false;
    state._scanBusy = false; state._lastFastScanAt = 0;
    state._proactiveProbeAt = 0; state._proactiveProbeBusy = false;
    state._earlyShellArmed = false; state._guardRedisableArmed = false;
    state._seoCloakKitDetected = false; state._indexNowPhishTemplate = false; state._multiPlatformSerpTrap = false;
    state._brandSpoofPortalDetected = false; state._fakeSpaDetected = false; state._brandResourceMismatchDetected = false;
    state._fakeBrandShellDetected = false; state._cloneOfficialDetected = false; state._cloneScanAt = 0;
    state._desktopForceDlKit = false; state._remoteGarbleDlDetected = false;
    state._remoteApiChecked = false; state._antiDebugChecked = false;
    c.finalizeScheduled = false; c.lastReportAt = 0;
    NS.invalidateHtmlCache();
    state._analyzedHost = location.hostname || "";
    try {
      NS.postToHooks({ type: "set-guard", enabled: false });
      try { NS.applyDownloadGuardDomLock(false); } catch { /* ignore */ }
      NS.reEnableAllThreatDisabledElements();
    } catch { /* ignore */ }
    try {
      if (chrome?.runtime?.id) {
        chrome.runtime.sendMessage({
          type: "page-analysis-reset",
          url: location.href,
          reason: reason || "page-url-changed",
          analysisTxn: state._analysisTxn || "",
          analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
        }, () => { void chrome.runtime.lastError; });
        chrome.runtime.sendMessage({
          type: "set-tab-protect", enabled: false, force: hostChanged, url: location.href,
          analysisTxn: state._analysisTxn || "",
          analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
        }, () => { void chrome.runtime.lastError; });
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
    const state = NS.state;
    // SPA 首页进入 /download 时不会重新执行 document_start boot；复用同一性能静默
    // 与身份收口流程，禁止再排 120/900/1400ms 三轮全页扫描。
    try {
      if (typeof NS.looksLikeProvisionalDownloadPathShape === "function"
        && NS.looksLikeProvisionalDownloadPathShape()
        && typeof NS.startProvisionalDownloadRouteAnalysis === "function") {
        if (c.pageNavRescanTimer) {
          try { clearTimeout(c.pageNavRescanTimer); } catch { /* ignore */ }
          c.pageNavRescanTimer = null;
        }
        NS.startProvisionalDownloadRouteAnalysis("spa-download-route");
        return;
      }
    } catch { /* ignore */ }
    // 已 light / 成熟正规站 / 大型内容 SPA：不排队多轮重扫
    try {
      const trustedOnce = typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity()
        && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
      if (state._intelLightMode || state._perfBenign || trustedOnce
        || (typeof NS.shouldKeepLightOnSameHostSoftNav === "function" && NS.shouldKeepLightOnSameHostSoftNav())
        || NS.looksLikeUltraMatureWhoisDomain()
        || NS.looksLikeUltraMatureIcpDomain()) {
        if (!state._intelLightMode) NS.enterIntelLightMode(trustedOnce ? "page-change-trusted-once" : "page-change-light");
        else { state._perfBenign = true; state._analysisDone = true; }
        NS.markAnalysisComplete(trustedOnce ? "page-change-trusted-once" : "page-change-light");
        NS.emitRiskReport(true);
        return;
      }
    } catch { /* ignore */ }
    if (c.pageNavRescanTimer) { try { clearTimeout(c.pageNavRescanTimer); } catch { /* ignore */ } c.pageNavRescanTimer = null; }
    c.pageNavRescanTimer = setTimeout(() => {
      c.pageNavRescanTimer = null;
      try {
        const trustedOnce2 = typeof NS.pageHasStrongTrustedIdentity === "function"
          && NS.pageHasStrongTrustedIdentity()
          && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
        if (NS.state._intelLightMode || NS.state._perfBenign || trustedOnce2
          || NS.looksLikeUltraMatureWhoisDomain()
          || NS.looksLikeUltraMatureIcpDomain()
          || (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa())) {
          NS.enterIntelLightMode(trustedOnce2 ? "page-change-trusted-once-deferred" : "page-change-light-deferred");
          NS.markAnalysisComplete(trustedOnce2 ? "page-change-trusted-once" : "page-change-light");
          NS.emitRiskReport(true);
          return;
        }
      } catch { /* ignore */ }
      // 同站已有备案文案：勿再 startIcpWhois 整链（易卡 analysisComplete）
      const sameHostIcp = !!(NS.state.icpInfo && typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord());
      if (!sameHostIcp) NS.startIcpWhoisIntelEarly("page-url-changed");
      try { NS.tryEarlyShellProtect(); NS.armImmediatePackageBlock(); NS.scanSuspiciousPackagesFast(true); } catch (e) { console.warn("page-change early rescan failed", e); }
      NS.scheduleIdle(() => {
        try {
          if ((typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity())
            || NS.looksLikeUltraMatureIcpDomain() || NS.looksLikeUltraMatureWhoisDomain()
            || NS.state._intelLightMode || NS.state._perfBenign) {
            if (!NS.state._analysisDone) NS.markAnalysisComplete("page-change-idle-icp-or-light");
            NS.emitRiskReport(true); return;
          }
          if (!NS.state._perfBenign) NS.detectLandingPageImpersonation();
          NS.scanSuspiciousPackagesFast(true);
          NS.emitRiskReport(true);
        } catch { /* ignore */ }
      }, 900);
      NS.scheduleIdle(() => {
        try {
          const hasDlTargets = typeof NS.pageHasProactiveDownloadButtonTargets === "function"
            && NS.pageHasProactiveDownloadButtonTargets();
          // 有下载按钮目标：即使长文首页被标 benign 也必须主动 fetch 按钮地址
          const lightSkip = (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity())
            || NS.looksLikeUltraMatureIcpDomain() || NS.looksLikeUltraMatureWhoisDomain()
            || NS.state._intelLightMode || NS.shouldNeverArmProtection()
            || ((NS.state._perfBenign || NS.isBenignContentPage()) && !hasDlTargets);
          if (lightSkip) {
            NS.maybeLiftDownloadGuard();
            if (!NS.state._analysisDone) NS.markAnalysisComplete("page-change-idle-light-skip");
            NS.emitRiskReport(true); return;
          }
          NS.scanSuspiciousPackagesFast(true);
          if ((NS.state._perfBenign || NS.isBenignContentPage()) && !hasDlTargets) {
            NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true); return;
          }
          const probe = typeof NS.proactivelyProbeDownloadButtons === "function"
            ? NS.proactivelyProbeDownloadButtons({ force: true, reason: "idle-scan" })
            : NS.detectLinkedLandingPageSources();
          Promise.resolve(probe).catch(() => {}).finally(() => { NS.maybeLiftDownloadGuard(); NS.finalize(); });
        } catch { NS.finalize(); }
      }, 1400);
    }, 120);
  };

  NS.handlePageUrlChanged = function (reason, incomingUrl) {
    const c = NS.caches;
    const state = NS.state;
    const url = (incomingUrl && String(incomingUrl)) || location.href;
    const live = location.href;
    const key = live || url;
    if (!NS.isHttpOrHttpsPage(key) && !NS.isHttpOrHttpsPage(live)) { NS.silverfoxLog("nav-skip", "non-http-protocol", String(key).slice(0, 80)); return; }
    if (c.lastAnalyzedUrl && key === c.lastAnalyzedUrl) return;
    // 同站 soft-nav + 成熟正规身份 / light：禁止 reset+全量复扫。
    try {
      let prevHost = "";
      try { prevHost = c.lastAnalyzedUrl ? new URL(c.lastAnalyzedUrl).hostname : (state._analyzedHost || ""); } catch { prevHost = state._analyzedHost || ""; }
      const newHost = location.hostname || "";
      // Identity/report transactions use the exact hostname.  www and bare
      // hosts may have different ICP attribution and cannot share a shortcut.
      const sameHost = !!(prevHost && newHost
        && prevHost.toLowerCase().replace(/\.+$/g, "") === newHost.toLowerCase().replace(/\.+$/g, ""));
      const trustedOnce = sameHost && typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity()
        && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
      const keep = sameHost && (
        trustedOnce
        || (typeof NS.shouldKeepLightOnSameHostSoftNav === "function" && NS.shouldKeepLightOnSameHostSoftNav())
      );
      if (keep) {
        // A light/trusted SPA shortcut is still a new page transaction. Tear
        // down the previous route's bounded click hold/controller first; its
        // timer must not wake later and mutate or release protection for this
        // URL.
        state._provisionalDownloadAnalysisGeneration = Number(state._provisionalDownloadAnalysisGeneration || 0) + 1;
        state._provisionalDownloadIdentityHold = false;
        state._provisionalDownloadIdentityUrl = "";
        state._provisionalDownloadIdentityDeadlineAt = 0;
        state._identityVerificationUnavailable = false;
        state._identityVerificationUnavailableUrl = "";
        try {
          if (c._provisionalDownloadController && typeof c._provisionalDownloadController.cancel === "function") {
            c._provisionalDownloadController.cancel("soft-nav-keep");
          }
        } catch { /* ignore */ }
        c._provisionalDownloadController = null;
        state._officialDownloadScanQuiet = false;
        state._officialDownloadScanQuietUrl = "";
        try {
          if (typeof NS.rotateAnalysisTransaction === "function") {
            NS.rotateAnalysisTransaction(key, reason || "soft-nav-keep-light");
          }
        } catch { /* keep navigation operational */ }
        c.lastAnalyzedUrl = key;
        state._analyzedHost = newHost;
        state._perfBenign = true;
        state._perfBenignAt = Date.now();
        state._intelLightMode = true;
        state._analysisDone = true;
        state._analysisDoneAt = Date.now();
        state._scanBusy = false;
        try {
          if (typeof NS.markAnalysisComplete === "function") {
            NS.markAnalysisComplete(trustedOnce ? "soft-nav-trusted-once" : "soft-nav-keep-light");
          } else {
            NS.emitRiskReport(true);
          }
        } catch { try { NS.emitRiskReport(true); } catch { /* ignore */ } }
        try { NS.startIcpWhoisIntelEarly(trustedOnce ? "soft-nav-trusted-once" : "soft-nav-keep-light"); } catch { /* ignore */ }
        NS.silverfoxLog && NS.silverfoxLog("nav-skip", trustedOnce ? "soft-nav-trusted-once" : "soft-nav-keep-light", reason || "");
        return;
      }
    } catch { /* ignore */ }
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
          try {
            if (msg && msg.type === "page-url-changed") {
              NS.handlePageUrlChanged("bg-page-url-changed", msg.url || "");
              try { sendResponse({ ok: true }); } catch { /* ignore */ }
              return false;
            }
            if (msg && msg.type === "silverfox-request-risk-report") {
              const requestedUrl = String(msg.url || "");
              if (requestedUrl && requestedUrl !== String(location.href || "")) {
                try { sendResponse({ ok: false, stale: true }); } catch { /* ignore */ }
                return false;
              }
              // Popup may be opened after Edge froze this tab's timers. Wake the
              // event-driven identity controller and emit a fresh snapshot; no
              // report is never equivalent to a clean 0-score conclusion.
              try { NS.nudgeProvisionalDownloadSettlement("popup-request"); } catch { /* ignore */ }
              try { NS.nudgeBrandElectionAfterHydration("popup-request"); } catch { /* ignore */ }
              try {
                if (!NS.state._analysisDone
                  && NS.state._icpQuerySettled === true
                  && NS.caches.intelDoneForUrl === String(location.href || "")) {
                  NS.invalidateHtmlCache();
                  NS.markAnalysisComplete("popup-request");
                } else {
                  NS.emitRiskReport(true);
                }
              } catch { /* ignore */ }
              try {
                sendResponse({
                  ok: true,
                  complete: !!NS.state._analysisDone,
                  analysisTxn: NS.state._analysisTxn || "",
                  url: NS.state._analysisTxnUrl || String(location.href || "")
                });
              } catch { /* ignore */ }
              return false;
            }
            if (msg && msg.type === "show-page-threat-toast") {
              // 后台下载取消或子 frame 拦截统一在顶层页面显示，避免 Toast 落在隐藏 iframe。
              try {
                if (typeof NS.isTopFrame !== "function" || NS.isTopFrame()) {
                  NS.showPageToast(
                    String(msg.title || "已拦截可疑下载文件"),
                    String(msg.message || "可疑下载已被拦截"),
                    {
                      force: msg.force !== false,
                      guardKind: String(msg.guardKind || ""),
                      brandSnapshot: msg.brandSnapshot || null
                    }
                  );
                }
              } catch { /* ignore */ }
              try { sendResponse({ ok: true }); } catch { /* ignore */ }
              return false;
            }
            // VT 权威引擎共识删盘后：同步禁用本页下载按钮 + arm guard（仅 toast 不够）
            if (msg && msg.type === "arm-page-download-guard") {
              try {
                if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) {
                  try { sendResponse({ ok: true, skipped: "frame" }); } catch { /* ignore */ }
                  return false;
                }
                const state = NS.state;
                const reason = String(msg.reason || "vt-trusted-consensus").slice(0, 80);
                const title = String(msg.title || "VT 检出可疑安装包").slice(0, 120);
                const message = String(msg.message || "权威引擎检出恶意，已禁用本页下载").slice(0, 240);
                try {
                  state._vtConsensusThreat = true;
                  state._remoteGarbleDlDetected = true;
                } catch { /* ignore */ }
                try {
                  NS.addSignal(
                    "VT权威引擎共识恶意",
                    28,
                    String(msg.detail || message).slice(0, 280)
                  );
                } catch { /* ignore */ }
                if (typeof NS.installDownloadGuard === "function") {
                  NS.installDownloadGuard(`VT 权威引擎共识: ${reason}`, {
                    notify: msg.notify !== false,
                    href: String(msg.href || "").slice(0, 500),
                    message,
                    title,
                    forceNotify: true,
                    guardKind: "package",
                    lockHard: true
                  });
                }
                try { NS.disableAllDownloadIntentControls(); } catch { /* ignore */ }
                try {
                  NS.postToHooks({ type: "set-guard", enabled: true });
                  NS.postToHooks({ type: "set-official-safe", enabled: false });
                } catch { /* ignore */ }
                try {
                  if (chrome?.runtime?.id) {
                    chrome.runtime.sendMessage({
                      type: "set-tab-protect",
                      enabled: true,
                      mode: "full",
                      url: location.href,
                      analysisTxn: NS.state._analysisTxn || "",
                      analysisTxnStartedAt: Number(NS.state._analysisTxnStartedAt) || Date.now()
                    }, () => { void chrome.runtime.lastError; });
                  }
                } catch { /* ignore */ }
                try { NS.emitRiskReport(true); } catch { /* ignore */ }
              } catch { /* ignore */ }
              try { sendResponse({ ok: true }); } catch { /* ignore */ }
              return false;
            }
            if (msg && msg.type === "ssl-cert-info" && msg.sslInfo) {
              if (typeof NS.applySslCertInfo === "function") NS.applySslCertInfo(msg.sslInfo);
              try { sendResponse({ ok: true }); } catch { /* ignore */ }
              return false;
            }
            // SW 热启动/扩展重载后：若本页仍处于拦截态，重新登记 protect
            if (msg && msg.type === "silverfox-sw-awake") {
              try {
                if (NS.state && (NS.state.downloadGuardInstalled || (NS.state.protectedTargets && NS.state.protectedTargets.length))) {
                  chrome.runtime.sendMessage({
                    type: "set-tab-protect",
                    enabled: true,
                    mode: "full",
                    url: location.href,
                    analysisTxn: NS.state._analysisTxn || "",
                    analysisTxnStartedAt: Number(NS.state._analysisTxnStartedAt) || Date.now()
                  }, () => { void chrome.runtime.lastError; });
                } else if (typeof NS.pageHasStrongTrustedIdentity === "function"
                  && NS.pageHasStrongTrustedIdentity()
                  && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())) {
                  NS.notifyBackgroundDownloadTrust(true, "sw-awake-trusted");
                }
              } catch { /* ignore */ }
              try { sendResponse({ ok: true }); } catch { /* ignore */ }
              return false;
            }
          } catch { /* ignore */ }
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

  /**
   * iframe 内：接收顶层盗版 arm 广播，本地灰下载按钮 + MAIN set-guard。
   * （不在子 frame 弹仿冒 toast，只继承拦截。）
   */
  NS.installParentGuardInheritance = function () {
    try {
      if (typeof NS.isTopFrame === "function" && NS.isTopFrame()) {
        const reLockFrames = () => {
          try {
            if (!NS.state.downloadGuardInstalled) return;
            if (typeof NS.neutralizePageFramesForGuard === "function") NS.neutralizePageFramesForGuard(true);
            // 再次广播，覆盖晚创建的跨源 frame 内 content 脚本
            NS.postToHooks({ type: "set-guard", enabled: true });
          } catch { /* ignore */ }
        };
        // 新 iframe 插入后立即补锁（持续，不 disconnect）
        if (typeof MutationObserver !== "undefined" && !NS.caches._frameGuardMo) {
          let moT = 0;
          NS.caches._frameGuardMo = new MutationObserver(() => {
            if (!NS.state.downloadGuardInstalled) return;
            // 合并抖动：短防抖 + 必跑
            if (moT) return;
            moT = setTimeout(() => { moT = 0; reLockFrames(); }, 40);
          });
          const root = document.documentElement || document.body;
          if (root) NS.caches._frameGuardMo.observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ["src"] });
        }
        // 定时补锁：对抗「等一会再插 iframe / 改 src」的晚加载下载壳
        if (!NS.caches._frameGuardInterval) {
          let ticks = 0;
          NS.caches._frameGuardInterval = setInterval(() => {
            ticks += 1;
            if (!NS.state.downloadGuardInstalled) {
              // 未 arm 时不忙等；仍保留 interval 以便 arm 后立刻生效
              if (ticks > 1200) { try { clearInterval(NS.caches._frameGuardInterval); NS.caches._frameGuardInterval = null; } catch { /* ignore */ } }
              return;
            }
            reLockFrames();
            // arm 后最多盯 15 分钟
            if (ticks > 900) { try { clearInterval(NS.caches._frameGuardInterval); NS.caches._frameGuardInterval = null; } catch { /* ignore */ } }
          }, 1000);
        }
        return;
      }
      window.addEventListener("message", (event) => {
        try {
          const data = event.data;
          if (!data || data.source !== NS.CONTENT_SOURCE) return;
          if (data.type !== "set-guard") return;
          // 来自顶层或其它祖先 frame
          if (event.source === window) return;
          const on = !!data.enabled;
          NS.state.downloadGuardInstalled = on;
          if (on) {
            try { NS.disableAllDownloadIntentControls(); } catch { /* ignore */ }
            try { NS.applyDownloadGuardDomLock(true); } catch { /* ignore */ }
            try { window.postMessage({ source: NS.CONTENT_SOURCE, type: "set-guard", enabled: true }, "*"); } catch { /* ignore */ }
          } else {
            try { NS.applyDownloadGuardDomLock(false); } catch { /* ignore */ }
            try { NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
            try { window.postMessage({ source: NS.CONTENT_SOURCE, type: "set-guard", enabled: false }, "*"); } catch { /* ignore */ }
          }
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
  };

  /** MAIN-world hooks -> isolated content 消息桥。 */
  NS.installHooksMessageBridge = function () {
    const releaseTrustedHookBlock = (reason) => {
      try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ }
      let lifted = false;
      try {
        if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
          lifted = NS.forceLiftSoftProtectionForTrustedPortal(reason || "trusted-hook-block") === true;
        }
      } catch { lifted = false; }
      // Hook 已先于情报结果改过 DOM 时，即使没有旧 guard 状态也要主动还原链接。
      if (!lifted) {
        try { NS.state.downloadGuardInstalled = false; } catch { /* ignore */ }
        try { NS.applyDownloadGuardDomLock(false); } catch { /* ignore */ }
        try { NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
      }
      [0, 80, 300, 800].forEach((ms) => setTimeout(() => {
        try {
          NS.notifyHooksOfficialSafe(true);
          NS.applyDownloadGuardDomLock(false);
          NS.reEnableAllThreatDisabledElements();
        } catch { /* ignore */ }
      }, ms));
    };
    window.addEventListener("message", (event) => {
      if (event.source !== window) return;
      const data = event.data;
      if (!data || data.source !== NS.HOOK_SOURCE) return;
      const state = NS.state;
      const c = NS.caches;
      if (NS.silverfoxLog) NS.silverfoxLog("hooks-in", data.type, data.name || "", String(data.reason || data.href || "").slice(0, 100));

      if (data.type === "trusted-download-intent") {
        try {
          const validIcp = typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord();
          const ageDays = typeof NS.getWhoisAgeDays === "function" ? NS.getWhoisAgeDays() : null;
          const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
          // 有效 ICP + ≥1 年 WHOIS 是强身份组合：即使页面结构误中下载套件，也只放行刚上报的精确 URL。
          const trusted = !realHard && typeof NS.pageHasStrongTrustedIdentity === "function"
            && NS.pageHasStrongTrustedIdentity();
          if (chrome?.runtime?.id && data.href) {
            chrome.runtime.sendMessage({
              type: "trusted-download-intent",
              href: data.href,
              url: location.href,
              identityVerified: trusted,
              analysisTxn: state._analysisTxn || "",
              analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
            }, () => { void chrome.runtime.lastError; });
          }
        } catch { /* ignore */ }
        return;
      }

      if (data.type === "signal" && data.name) {
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { releaseTrustedHookBlock("trusted-hook-signal"); return; }
        if (NS.isBenignContentPage() && !/安装包|下载|远程|PHP|API|仿冒|手势|跳转/i.test(data.name || "")) return;
        if (/非用户手势|自动下载|自动跳转|跨域跳转/i.test(data.name || "") || /非用户手势|auto-nav-no-gesture|kit-or-relay-auto-external|auto-external/i.test(data.reason || "")) {
          const r = String(data.reason || "");
          const m = r.match(/([A-Za-z0-9][A-Za-z0-9._-]{2,120}\.(?:zip|exe|apk|msi|dmg|rar|7z))/i);
          const maybeName = m ? m[1] : "";
          const hrefFromReason = (r.match(/https?:\/\/[^\s"'<>\\]+/i) || [])[0] || "";
          if (hrefFromReason && NS.isAuthSsoOrLoginRedirectUrl(hrefFromReason)) return;
          // 无安装包的自动/跨域跳转：仅提示、不 arm（pcsoft 等正版软件站广告/统计跨域）
          const noPkg = !maybeName
            && (!hrefFromReason || (!NS.isPackageFileUrl(hrefFromReason) && !NS.looksLikeOpaqueDownloadHopUrl(hrefFromReason)));
          if (noPkg && !state._seoCloakKitDetected && !state._desktopForceDlKit && !state._fakeSpaDetected && !state._fakeBrandShellDetected) {
            return;
          }
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
          // 纯跨域跳转信号：无安装包不 arm
          if (/跨域跳转|自动跳转|搜索引擎跳转/i.test(data.name || "")
            && !m && (!hrefM || (!NS.isPackageFileUrl(hrefM) && !NS.looksLikeOpaqueDownloadHopUrl(hrefM)))
            && !state._seoCloakKitDetected && !state._desktopForceDlKit) return;
          if ((data.weight || 0) <= 8 && !/手势|仿冒|下发|API动态/i.test(data.name || "")) return;
          NS.installDownloadGuard(data.reason || data.name, { notify: true, href: hrefM || "", message: data.reason || data.name });
        }
        return;
      }
      if (data.type === "blocked-download") {
        const href = data.href || "";
        const reason = data.reason || "";
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { releaseTrustedHookBlock("trusted-hook-blocked-download"); return; }
        if (href && NS.isAuthSsoOrLoginRedirectUrl(href)) return;
        if (/非用户手势自动跳转/i.test(reason) && href && NS.isAuthSsoOrLoginRedirectUrl(href)) return;
        if (href && NS.isSiteHomeUrl(href) && !NS.isPackageFileUrl(href)) return;
        const fn = href ? NS.getFilenameFromUrl(href) : "";
        // 内容寻址哈希 APK 等：不要求再过 isSuspicious（旧逻辑会自相矛盾）
        if (href && (NS.isAllowlistedProductPackageUrl(href) || NS.looksLikeStrongProductInstallerName(fn) || NS.isClearProductOrAndroidPackage(href) || NS.isClearProductOrAndroidPackage(fn) || NS.looksLikeProductPackageName(fn) || NS.isBenignShortInstallerName(fn) || NS.isContentAddressedPackageName(fn)) && !NS.looksLikeBrandNearMissPackageName(fn)) return;
        const autoNoGesture = /auto-nav-no-gesture|auto-search-trap|auto-external|phish-shell-auto|非用户手势|programmatic-a\.click|programmatic/i.test(reason);
        if (!NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href) && !autoNoGesture) {
          if (/api\.php|download_link|远程API|远程下发|download_uri/i.test(reason)) NS.installDownloadGuard(reason || "可疑下载", { notify: true, href: "", message: reason || "远程动态下载" });
          return;
        }
        if (autoNoGesture && href && !NS.isPackageFileUrl(href) && NS.isAuthSsoOrLoginRedirectUrl(href)) return;
        // 无安装包的跨域/自动跳转：不 arm（与 signal 路径一致）
        if (autoNoGesture && href && !NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href)
          && /非用户手势|kit-or-relay-auto-external|auto-external|auto-nav-no-gesture/i.test(reason)
          && !state._seoCloakKitDetected && !state._desktopForceDlKit && !state._fakeSpaDetected && !state._fakeBrandShellDetected && !state._brandSpoofPortalDetected) return;
        if (autoNoGesture && (NS.looksLikeSafeOfficialContext() || NS.isTrustedOfficialDownloadContext()) && !state._seoCloakKitDetected && !state._brandSpoofPortalDetected) return;
        if (autoNoGesture && href && (NS.isAllowlistedProductPackageUrl(href) || NS.looksLikeStrongProductInstallerName(fn))) return;
        if (href && !state.protectedTargets.includes(href)) state.protectedTargets.push(href);
        NS.markRemoteDownloadDispatch(reason || `blocked -> ${href}`, href, { forceNotify: true });
        let msg = NS.formatPackageLabel(href);
        try { const u = new URL(href, location.href); if (!NS.PACKAGE_EXT.test(u.pathname)) msg = `${u.hostname}${u.pathname}`; } catch { /* ignore */ }
        if (autoNoGesture) NS.installDownloadGuard(reason || "非用户手势自动下载", { notify: true, href, message: msg || "自动下载已拦截", forceNotify: !state.protectionNoticeSent });
        else { NS.showGuardOverlay(href, { title: "已拦截可疑下载", message: msg }); NS.installDownloadGuard(reason || `已拦截可疑下载: ${msg}`, { notify: true, href, message: msg, forceNotify: false }); }
        NS.disableSuspiciousDownloadButtons();
        return;
      }
      if (data.type === "request-guard") {
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { releaseTrustedHookBlock("trusted-hook-request-guard"); return; }
        try {
          const rr = String(data.reason || "");
          if (/非用户手势自动跳转|auto-nav-no-gesture|kit-or-relay-auto-external|auto-external/i.test(rr)) {
            const hrefM = rr.match(/https?:\/\/[^\s"'<>\\]+/i);
            if (hrefM && NS.isAuthSsoOrLoginRedirectUrl(hrefM[0])) return;
            // 无安装包的「自动跳转/跨域」request-guard：不 arm（正版软件站广告/外链）
            if (hrefM && !NS.isPackageFileUrl(hrefM[0]) && !NS.looksLikeOpaqueDownloadHopUrl(hrefM[0])
              && !state._seoCloakKitDetected && !state._desktopForceDlKit && !state._fakeSpaDetected && !state._fakeBrandShellDetected) {
              return;
            }
            if (!hrefM && !state._seoCloakKitDetected && !state._desktopForceDlKit) return;
          }
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
        const rr = String(data.reason || "");
        const hard = /下载壳|远程|API|download_uri|强制弹窗|SEO|乱码|绑定可疑|仿冒/i.test(rr);
        if (hard) state.remoteDownloadDispatchDetected = true;
        NS.installDownloadGuard(data.reason || "页面行为触发下载保护", { notify: true, message: data.reason || "可疑下载保护", forceNotify: true, lockHard: hard });
        NS.disableSuspiciousDownloadButtons();
        NS.disableAllDownloadIntentControls();
        NS.scanSuspiciousPackagesFast();
        return;
      }
      if (data.type === "stat") {
        if (data.key === "host" && data.value) { state.hosts.add(data.value); return; }
        if (data.key && typeof data.delta === "number" && data.key in state) state[data.key] = (state[data.key] || 0) + data.delta;
        return;
      }
      if (data.type === "hooks-ready") {
        // MAIN 脚本可能晚于 ICP/WHOIS 结果就绪；握手时必须重放当前可信状态。
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) {
          releaseTrustedHookBlock("trusted-hooks-ready");
        } else if (state.downloadGuardInstalled) {
          NS.postToHooks({ type: "set-guard", enabled: true });
        }
      }
    });
  };

  async function runIcpWhoisIntel(genOpt, urlKeyOpt) {
    const state = NS.state;
    const c = NS.caches;
    const gen = genOpt != null ? genOpt : c.intelGeneration;
    const urlKey = urlKeyOpt || location.href;
    // 情报主机保留 www（www.gov.cn 不得被 normalizeDomain 打成 gov.cn）
    const pageHost = typeof NS.normalizeHostForIntel === "function"
      ? NS.normalizeHostForIntel(location.hostname)
      : String(location.hostname || "").trim().toLowerCase();
    if (!pageHost || !/^https?:/i.test(String(location.protocol || ""))) { if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey; return; }
    // WHOIS 与 ICP 彼此独立：同时启动、分别完整收敛。旧版先等 WHOIS 再发 ICP，
    // 两组网络耗时被串行相加，导致 popup 很久才得到备案最终态。
    const icpPromise = Promise.resolve()
      .then(() => NS.detectIcpDomain(pageHost))
      .catch(() => ({ success: false, icpRecord: "", icpMissing: false }));
    let whois = null;
    try { whois = await NS.detectWhoisRegistrationAge(pageHost); } catch { whois = { success: false }; }
    if (gen !== c.intelGeneration || location.href !== urlKey) return;
    NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true);
    // WHOIS 无结果：仍核验页脚自称备案（仿冒站常无 WHOIS，但页脚写假 ICP）
    // 注意：ICP 查到真号时必须把 rec0 传给 finalize/deferred，禁止一律 "",true 把真号降级成「待核验」
    if (!NS.whoisHasResult(whois)) {
      state.icpInfo = ""; state.icpMatchedHost = "";
      state._icpQueryFailed = true;
      try {
        let pageIcp = { declared: [], unverifiedClaim: false, remoteMissing: false };
        let rec0 = "";
        let miss0 = false;
        let fallbackWhoisRejected0 = false;
        try {
          let icpCheck0 = await icpPromise;
          if (gen !== c.intelGeneration || location.href !== urlKey) return;
          if (!(icpCheck0 && icpCheck0.success) && restoreForcedMissingIcpState()) {
            icpCheck0 = { success: true, icpRecord: "", icpMissing: true, attributionRejected: true, queriedHost: pageHost, source: "preserved-fallback-whois" };
          }
          if (icpCheck0 && icpCheck0.success) {
            // A definitive ICP response (record or missing) is not a query
            // failure, even when the parallel WHOIS lookup had no result.
            state._icpQueryFailed = false;
            fallbackWhoisRejected0 = icpCheck0.attributionRejected === true;
            rec0 = (icpCheck0.icpRecord && NS.looksLikeIcpLicense(icpCheck0.icpRecord)) ? icpCheck0.icpRecord : "";
            miss0 = !rec0 && !!(icpCheck0.icpMissing || !icpCheck0.icpRecord);
            const matched0 = icpCheck0.matchedHost || icpCheck0.queriedHost || pageHost;
            const recordHost0 = icpCheck0.domainExplicit === true && icpCheck0.domain
              ? icpCheck0.domain
              : (icpCheck0.recordHost || matched0);
            let fallbackSupported0 = true;
            if (rec0 && typeof NS.icpFallbackHasWhoisSupport === "function") {
              fallbackSupported0 = await NS.icpFallbackHasWhoisSupport(recordHost0, pageHost, whois);
              // Always check navigation after the async proof, including the
              // successful branch; otherwise an old page may write into a new one.
              if (gen !== c.intelGeneration || location.href !== urlKey) return;
            }
            if (rec0 && !fallbackSupported0) {
              NS.silverfoxLog("intel-icp", "reject-fallback-without-whois", recordHost0, "page=", pageHost);
              rec0 = "";
              miss0 = true;
              fallbackWhoisRejected0 = true;
            }
            if (fallbackWhoisRejected0) {
              state._icpForcedMissingByFallbackWhois = true;
              state._icpForcedMissingHost = pageHost;
            } else {
              state._icpForcedMissingByFallbackWhois = false;
              state._icpForcedMissingHost = "";
            }
            if (typeof NS.reconcilePageIcpClaim === "function") {
              pageIcp = NS.reconcilePageIcpClaim(rec0, miss0);
            }
            if (rec0) {
              state.icpInfo = rec0;
              state.icpMatchedHost = typeof NS.normalizeHostForIntel === "function"
                ? NS.normalizeHostForIntel(recordHost0 || pageHost)
                : String(recordHost0 || pageHost).toLowerCase();
              state._icpQueryFailed = false;
              if (typeof NS.clearPendingIcpClaimSignals === "function") NS.clearPendingIcpClaimSignals();
              if (typeof NS.clearFakeIcpClaimSignals === "function") NS.clearFakeIcpClaimSignals();
            } else if (pageIcp.declared && pageIcp.declared.length) {
              // 查询明确未备案时直接收口为假冒；查询失败才保留待核验。
              const ph = pageIcp.declared.some((d) =>
                typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
              );
              const normal = pageIcp.declared.some((d) => {
                const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
                return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
              });
              if (ph || miss0) {
                state.icpInfo = `假冒宣称 ${pageIcp.declared.join(" / ")}`;
                state._unverifiedPageIcpClaim = true;
              } else if (normal || pageIcp.unverifiedClaim) {
                state.icpInfo = normal
                  ? `页脚宣称 ${pageIcp.declared.join(" / ")}（第三方待核验）`
                  : `假冒宣称 ${pageIcp.declared.join(" / ")}`;
                state._unverifiedPageIcpClaim = !normal;
              }
              if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
            } else if (miss0) {
              state.icpInfo = "未查询到备案信息";
              if (typeof NS.addSignal === "function") {
                NS.addSignal("无ICP备案信息", 6, `当前域名 ${location.hostname} 未查询到备案信息`);
              }
            }
          } else if (typeof NS.reconcilePageIcpClaim === "function") {
            rec0 = "";
            miss0 = false;
            state.icpInfo = icpCheck0 && icpCheck0.partialMissing
              ? "查询未确认（部分来源未找到备案记录）"
              : "备案查询失败";
            pageIcp = NS.reconcilePageIcpClaim("", false);
            if (pageIcp.declared && pageIcp.declared.length) {
              const ph = pageIcp.declared.some((d) =>
                typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
              );
              const normal = pageIcp.declared.some((d) => {
                const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
                return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
              });
              state.icpInfo = ph || !normal
                ? `假冒宣称 ${pageIcp.declared.join(" / ")}`
                : `页脚宣称 ${pageIcp.declared.join(" / ")}（第三方待核验）`;
              state._unverifiedPageIcpClaim = !!(ph || !normal);
              if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
            }
          }
        } catch {
          rec0 = "";
          miss0 = false;
          if (!state.icpInfo) state.icpInfo = "备案查询失败";
          try {
            if (typeof NS.reconcilePageIcpClaim === "function") {
              pageIcp = NS.reconcilePageIcpClaim("", false);
              if (pageIcp.declared && pageIcp.declared.length) {
                const normal = pageIcp.declared.some((d) => {
                  const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
                  return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
                });
                state.icpInfo = normal
                  ? `页脚宣称 ${pageIcp.declared.join(" / ")}（第三方待核验）`
                  : `假冒宣称 ${pageIcp.declared.join(" / ")}`;
              }
            }
          } catch { /* ignore */ }
        }
        state._icpQuerySettled = true;
        try {
          // 必须带上 rec0/miss0；空串+true 会把已命中的真号刷成「待核验」
          if (typeof NS.finalizeIcpClaimSignals === "function") {
            const fin = NS.finalizeIcpClaimSignals(rec0, miss0);
            if (fin) pageIcp = fin;
          }
        } catch { /* ignore */ }
        try {
          if (typeof NS.scheduleDeferredIcpClaimRescan === "function") {
            NS.scheduleDeferredIcpClaimRescan(rec0, miss0);
          }
        } catch { /* ignore */ }
        if (typeof NS.enforceUnverifiedPageIcpDownloadBlock === "function") {
          NS.enforceUnverifiedPageIcpDownloadBlock(pageIcp, NS.getWhoisAgeDays());
        }
      } catch {
        state._icpQuerySettled = true;
        if (!state.icpInfo) state.icpInfo = "备案查询失败";
        try { if (typeof NS.finalizeIcpClaimSignals === "function") NS.finalizeIcpClaimSignals("", false); } catch { /* ignore */ }
        try { if (typeof NS.scheduleDeferredIcpClaimRescan === "function") NS.scheduleDeferredIcpClaimRescan("", false); } catch { /* ignore */ }
      }
      if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
      try {
        state._softBrandIdentityReady = true;
        state._softBrandIdentityUrl = urlKey;
      } catch { /* ignore */ }
      // 已 light/内容门户/粘性 complete：禁止把 analysisDone 打回 false（否则 popup 闪一下再卡「正在分析」）
      const needsBrandAuthority = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity(pageHost);
      const stayDone = !needsBrandAuthority && !!(state._perfBenign || state._intelLightMode || state._stickyComplete
        || (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
        || (typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()));
      if (!stayDone && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
        try {
          if (state._pendingSoftBrandSpoof || !state._brandSpoofPortalDetected) {
            if (NS.detectBrandSpoofDownloadPortal()) state._brandSpoofPortalDetected = true;
          }
          NS.scanSuspiciousPackagesFast(true);
        } catch { /* ignore */ }
      }
      NS.maybeLiftDownloadGuard();
      if (!state._analysisDone) NS.markAnalysisComplete("intel-whois-empty");
      else NS.emitRiskReport(true);
      return;
    }
    try {
      if (!pageHost) { state.icpInfo = ""; state.icpMatchedHost = ""; state._icpQuerySettled = true; state._icpQueryFailed = false; if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey; NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true); return; }
      // ICP 与 WHOIS 同一 pageHost（含 www）
      let icpCheck = await icpPromise;
      if (gen !== c.intelGeneration || location.href !== urlKey) return;
      if (!(icpCheck && icpCheck.success) && restoreForcedMissingIcpState()) {
        icpCheck = { success: true, icpRecord: "", icpMissing: true, attributionRejected: true, queriedHost: pageHost, source: "preserved-fallback-whois" };
      }
      if (!icpCheck.success) {
        // API 失败：仍核对页脚自称/占位号，避免仿冒页假备案漏检
        NS.silverfoxLog("intel-icp", "api-fail-settle-missing");
        state.icpInfo = icpCheck && icpCheck.partialMissing
          ? "查询未确认（部分来源未找到备案记录）"
          : "备案查询失败";
        state.icpMatchedHost = "";
        state._icpQueryFailed = true; state._icpQuerySettled = true;
        try {
          if (typeof NS.finalizeIcpClaimSignals === "function") NS.finalizeIcpClaimSignals("", false);
          else if (typeof NS.reconcilePageIcpClaim === "function") NS.reconcilePageIcpClaim("", false);
        } catch { /* ignore */ }
        try { if (typeof NS.scheduleDeferredIcpClaimRescan === "function") NS.scheduleDeferredIcpClaimRescan("", false); } catch { /* ignore */ }
        if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
        try {
          state._softBrandIdentityReady = true;
          state._softBrandIdentityUrl = urlKey;
        } catch { /* ignore */ }
        const needsBrandAuthority = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
          && NS.hostNeedsAuthoritativeBrandIdentity(pageHost);
        const stayDoneIcp = !needsBrandAuthority && !!(state._perfBenign || state._intelLightMode || state._stickyComplete
          || (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || (typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()));
        if (!stayDoneIcp && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
          try {
            if (state._pendingSoftBrandSpoof || !state._brandSpoofPortalDetected) {
              if (NS.detectBrandSpoofDownloadPortal()) state._brandSpoofPortalDetected = true;
            }
            NS.scanSuspiciousPackagesFast(true);
          } catch { /* ignore */ }
        }
        NS.maybeLiftDownloadGuard();
        if (!state._analysisDone) NS.markAnalysisComplete("intel-icp-api-fail");
        else NS.emitRiskReport(true);
        return;
      }
      let record = (icpCheck.icpRecord && NS.looksLikeIcpLicense(icpCheck.icpRecord)) ? icpCheck.icpRecord : "";
      const matched = icpCheck.matchedHost || icpCheck.queriedHost || pageHost;
      const recordHost = icpCheck.domainExplicit === true && icpCheck.domain
        ? icpCheck.domain
        : (icpCheck.recordHost || matched);
      let fallbackWhoisRejected = icpCheck.attributionRejected === true;
      if (record && !NS.intelHostIsValidAttribution(recordHost, pageHost)) {
        record = "";
        fallbackWhoisRejected = true;
      }
      let fallbackSupported = true;
      if (record && typeof NS.icpFallbackHasWhoisSupport === "function") {
        fallbackSupported = await NS.icpFallbackHasWhoisSupport(recordHost, pageHost, whois);
        // The lookup may finish after a SPA navigation or full navigation.
        if (gen !== c.intelGeneration || location.href !== urlKey) return;
      }
      if (record && !fallbackSupported) {
        NS.silverfoxLog("intel-icp", "reject-fallback-without-whois", recordHost, "page=", pageHost,
          "whois=", whois && whois.queriedHost || "-");
        record = "";
        fallbackWhoisRejected = true;
      }
      const missing = !record && (fallbackWhoisRejected || icpCheck.icpMissing || !icpCheck.icpRecord);
      const forcedMissing = fallbackWhoisRejected;
      if (forcedMissing) {
        state._icpForcedMissingByFallbackWhois = true;
        state._icpForcedMissingHost = pageHost;
      } else {
        state._icpForcedMissingByFallbackWhois = false;
        state._icpForcedMissingHost = "";
      }
      // 权威源已命中：立刻清掉历史「备案待核验 / 假冒」残留，避免 UI 卡在待核验
      if (record) {
        try {
          if (typeof NS.clearPendingIcpClaimSignals === "function") NS.clearPendingIcpClaimSignals();
          if (typeof NS.clearFakeIcpClaimSignals === "function") NS.clearFakeIcpClaimSignals();
        } catch { /* ignore */ }
      }
      // 再抽一次页脚（晚挂载的 foot-bottom）；有宣称则按 missing 核验假冒
      let declaredNow = typeof NS.extractPageDeclaredIcpLicenses === "function"
        ? NS.extractPageDeclaredIcpLicenses()
        : [];
      const pageIcp = typeof NS.reconcilePageIcpClaim === "function"
        ? NS.reconcilePageIcpClaim(record, missing, declaredNow.length ? declaredNow : undefined)
        : { declared: declaredNow, mismatch: false, unverifiedClaim: false };
      declaredNow = pageIcp.declared || declaredNow;
      state.icpMatchedHost = record
        ? (typeof NS.normalizeHostForIntel === "function"
          ? NS.normalizeHostForIntel(recordHost || pageHost)
          : String(recordHost || pageHost).toLowerCase())
        : "";
      const tried = Array.isArray(icpCheck.triedHosts) ? icpCheck.triedHosts : [];
      const recordLabel = record && recordHost && recordHost !== pageHost ? `${record}（主域 ${recordHost}）` : record;
      // OV/EV 组织证书：不展示「未查询到备案信息」（境外正规站常见）
      const orgSsl = typeof NS.hasOrganizationValidatedSsl === "function" && NS.hasOrganizationValidatedSsl();
      // 页脚有宣称 + 来源明确 missing：无论号码外观是否正常，都属于当前域名的假冒声明。
      const looksNormalDeclared = (list) => (list || []).some((d) => {
        const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
        return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
      });
      const anyPlaceholderDeclared = (list) => (list || []).some((d) =>
        typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
      );
      const fakeIcp = !!(pageIcp.unverifiedClaim && declaredNow && declaredNow.length && missing);
      state.icpInfo = record
        ? recordLabel
        : (fakeIcp && declaredNow.length
          ? `假冒宣称 ${declaredNow.join(" / ")}`
          : (missing && (forcedMissing || !orgSsl) ? "未查询到备案信息" : ""));
      state._icpQuerySettled = true; state._icpQueryFailed = false;
      NS.silverfoxLog("intel-icp", record ? "valid" : (fakeIcp ? "fake-claim" : (missing ? "missing" : "empty")), String(state.icpInfo || "").slice(0, 80), "host=", pageHost, "declared=", (declaredNow || []).join(",") || "-");
      const ageDays = NS.getWhoisAgeDays();
      const needsBrandAuthorityForIcp = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity(pageHost);
      const skipMissingIcp = !needsBrandAuthorityForIcp && (
        state._perfBenign || state._intelLightMode || NS.isBenignContentPage()
        || (ageDays != null && ageDays >= 365) || NS.looksLikeUltraMatureWhoisDomain()
        || NS.looksLikeLongLivedWhoisDomain() || orgSsl
      );
      // 收口：再抽页脚；按 record/missing 真实状态核验（禁止强行 remoteMissing=true）
      try {
        const fin = typeof NS.finalizeIcpClaimSignals === "function"
          ? NS.finalizeIcpClaimSignals(record, missing)
          : null;
        if (fin) {
          pageIcp.unverifiedClaim = !!fin.unverifiedClaim || pageIcp.unverifiedClaim;
          pageIcp.declared = fin.declared || pageIcp.declared;
          declaredNow = pageIcp.declared || declaredNow;
        }
      } catch { /* ignore */ }
      const declaredFinal = (declaredNow && declaredNow.length)
        ? declaredNow
        : (typeof NS.extractPageDeclaredIcpLicenses === "function" ? NS.extractPageDeclaredIcpLicenses() : []);
      if (declaredFinal.length) {
        if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
        if (typeof NS.reconcilePageIcpClaim === "function") {
          NS.reconcilePageIcpClaim(record, !!missing, declaredFinal);
        }
        if (!record) {
          const ph = anyPlaceholderDeclared(declaredFinal);
          const normal = looksNormalDeclared(declaredFinal);
          if (ph || missing) {
            state.icpInfo = `假冒宣称 ${declaredFinal.join(" / ")}`;
            state._unverifiedPageIcpClaim = true;
          } else if (normal) {
            state.icpInfo = `页脚宣称 ${declaredFinal.join(" / ")}（第三方待核验）`;
            state._unverifiedPageIcpClaim = false;
          } else {
            state.icpInfo = `假冒宣称 ${declaredFinal.join(" / ")}`;
            state._unverifiedPageIcpClaim = true;
          }
          state.pageDeclaredIcp = declaredFinal.join(" / ");
        }
      } else if (missing && (forcedMissing || !skipMissingIcp) && !pageIcp.unverifiedClaim) {
        const whoisNote = whois.queriedHost && whois.queriedHost !== pageHost ? `，WHOIS 经 ${whois.queriedHost}` : "";
        const triedNote = tried.length ? `，ICP 候选 ${tried.join(" -> ")}` : "";
        NS.addSignal("无ICP备案信息", 6, `当前域名 ${location.hostname}${whoisNote}${triedNote} 未查询到备案信息`);
      }
      // 双保险：只要详情里已有假冒 ICP，清掉无 ICP
      try {
        if ((state.details || []).some((d) => /^假冒ICP备案信息/i.test(String(d && d.name || "")))
          && typeof NS.clearMissingIcpSignal === "function") {
          NS.clearMissingIcpSignal();
        }
      } catch { /* ignore */ }
      // 页脚晚挂载 / 隐藏节点：延迟再抽，避免只剩「无ICP备案信息」
      try {
        if (typeof NS.scheduleDeferredIcpClaimRescan === "function") {
          NS.scheduleDeferredIcpClaimRescan(record, missing);
        }
      } catch { /* ignore */ }
      // 高置信身份欺诈组合：新注册域名 + 权威源确认未备案 + 页脚自称备案。
      // 这不是单纯加分，必须同步禁用/拦截本页下载入口。
      if (typeof NS.enforceUnverifiedPageIcpDownloadBlock === "function") {
        NS.enforceUnverifiedPageIcpDownloadBlock(pageIcp, ageDays);
      }
      // 真硬套件（SEO/强制弹窗/乱码）即使有 ICP 也不得 officialSafe
      const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      // 只有“成熟 WHOIS + 干净页面 + 正规页面”的组合门可以抬软误报；
      // ICP、超长 WHOIS、干净域名任一单项都不能直接放行。
      const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      const authoritativeMatureIdentity = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
        && NS.hasAuthoritativeMatureOrganizationIdentity(matureProfile);
      if (!realHard && matureProfile && (matureProfile.trusted || authoritativeMatureIdentity)) {
        try {
          if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
            NS.forceLiftSoftProtectionForTrustedPortal(
              NS.hasValidIcpRecord()
                ? (pageIcp.mismatch ? "valid-icp-page-stale-force-lift" : "valid-icp-force-lift")
                : "whois-ultra-force-lift"
            );
          } else {
            NS.clearBrandSpoofFalsePositive("valid-icp");
            state.remoteDownloadDispatchDetected = false;
            NS.enterIntelLightMode("valid-icp");
            NS.maybeLiftDownloadGuard();
          }
        } catch { /* ignore */ }
        if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
        NS.markAnalysisComplete(NS.hasValidIcpRecord() ? "valid-icp" : "whois-ultra-mature");
        NS.emitRiskReport(true);
        return;
      }
      if (realHard && state.downloadGuardInstalled) {
        try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
      }
      if (!NS.hasValidIcpRecord() && state._icpQuerySettled && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
        const needsBrandAuthority = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
          && NS.hostNeedsAuthoritativeBrandIdentity(pageHost);
        const stayDoneSoft = !needsBrandAuthority && !!(state._perfBenign || state._intelLightMode || state._stickyComplete
          || (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || (typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()));
        // 成熟门已判定「非信任」且无有效备案：允许软仿冒补弹（情报管道内显式放行）
        state._softBrandIdentityReady = true;
        state._softBrandIdentityUrl = urlKey;
        if (!stayDoneSoft && (state._pendingSoftBrandSpoof || !state._brandSpoofPortalDetected)) {
          try {
            if (NS.detectBrandSpoofDownloadPortal()) state._brandSpoofPortalDetected = true;
            // 假备案已 arm 身份异常时，再升格夹带域品牌 toast（huorongr → 仿冒「Huorong」）
            if (!state._brandSpoofPortalDetected
              && state._unverifiedIcpIdentityThreat
              && typeof NS.promoteUnverifiedIcpTypoToBrandSpoof === "function") {
              NS.promoteUnverifiedIcpTypoToBrandSpoof();
            }
            if (state._brandSpoofPortalDetected && typeof NS.ensureBrandSpoofNotice === "function") {
              NS.ensureBrandSpoofNotice(false);
            }
            NS.scanSuspiciousPackagesFast(true);
          } catch { /* ignore */ }
        } else if (!stayDoneSoft && state._brandSpoofPortalDetected
          && typeof NS.ensureBrandSpoofNotice === "function") {
          // 品牌已检出但 toast 被身份异常占先 → 强制补发品牌通知
          try { NS.ensureBrandSpoofNotice(false); } catch { /* ignore */ }
        }
      }
      if (matureProfile && matureProfile.trusted) {
        try { if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") NS.forceLiftSoftProtectionForTrustedPortal("whois-ultra-mature"); } catch { /* ignore */ }
        NS.enterIntelLightMode("whois-ultra-mature"); NS.clearBrandSpoofFalsePositive("whois-ultra-mature");
        if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
        NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("whois-ultra-mature"); NS.emitRiskReport(true); return;
      }
      if (matureProfile && matureProfile.trusted) {
        NS.enterIntelLightMode("whois-mature-5y");
        if (NS.hasValidIcpRecord()) NS.clearBrandSpoofFalsePositive("icp-mature-5y");
        try { const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || ""; if (lab.length >= 4 && (document.title || "").toLowerCase().includes(lab)) NS.clearBrandSpoofFalsePositive("host-in-title-5y"); } catch { /* ignore */ }
      }
      // 公开代码仓 + 下载成熟度（forge / 同站 ICP·WHOIS）→ 清软仿冒误报
      try {
        // 强制失效 forge 阴性缓存后再判（DOM 可能刚挂上 GitHub 链）
        try {
          if (NS.caches) {
            NS.caches._forgePresenceCache = null;
            NS.caches._forgePresenceAt = 0;
          }
        } catch { /* ignore */ }
        if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          NS.clearBrandSpoofFalsePositive("trusted-opensource");
          try { NS.maybeLiftDownloadGuard(); } catch { /* ignore */ }
          NS.silverfoxLog && NS.silverfoxLog("intel", "lift-trusted-opensource", ageDays);
        }
      } catch { /* ignore */ }
    } catch {
      if (!state.icpInfo) state.icpInfo = "备案查询失败";
      state._icpQuerySettled = true;
      state._icpQueryFailed = true;
    }
    if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
    // 情报全链结束：身份门可定论；此前禁止软仿冒 toast
    try {
      state._softBrandIdentityReady = true;
      state._softBrandIdentityUrl = urlKey;
    } catch { /* ignore */ }
    NS.maybeLiftDownloadGuard();
    try { NS.nudgeProvisionalDownloadSettlement("intel-pipeline-done"); } catch { /* ignore */ }
    const recoveredIdentity = typeof NS.recoverIdentityVerificationAvailability === "function"
      && NS.recoverIdentityVerificationAvailability("intel-pipeline-late-recovery");
    // 情报结束必须 complete，禁止只 emit incomplete 覆盖 popup
    if (recoveredIdentity) return;
    if (!state._analysisDone) NS.markAnalysisComplete("intel-pipeline-done");
    else NS.emitRiskReport(true);
  }

  NS.startIcpWhoisIntelEarly = function (reason) {
    const c = NS.caches;
    void reason;
    try { if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) return; } catch { /* ignore */ }
    if (!NS.isHttpOrHttpsPage()) return;
    // TLS 分类：先 DV 占位保证显示，再后台 CT 升级 OV/EV
    try {
      if (typeof NS.ensureSslPlaceholder === "function") NS.ensureSslPlaceholder();
      if (typeof NS.requestSslCertInfo === "function") {
        NS.requestSslCertInfo(false);
        // 只补查未完成、弱 DV 或缺组织名的 OV/EV；可信结果不再无条件绕过缓存重扫六个源。
        setTimeout(() => {
          try {
            const info = NS.state && NS.state.sslInfo;
            if (!info || !info.validation) {
              NS.requestSslCertInfo(false); // 首轮尚在途时由 background 合并并发
              return;
            }
            const validation = String(info.validation || "").toUpperCase();
            const organization = String(info.organization || "").trim();
            const source = String(info.source || "");
            const weakDv = validation === "DV"
              && /^(?:https-assumed|ct-meta|crt\.sh-meta)$/i.test(source);
            const missingOrg = /^(?:OV|EV)$/.test(validation) && !organization;
            if (weakDv || missingOrg) NS.requestSslCertInfo(true);
          } catch { /* ignore */ }
        }, 2500);
      }
    } catch { /* ignore */ }
    const urlKey = location.href;
    if (c.intelDoneForUrl === urlKey) return;
    if (c.intelBusy && c.intelDoneForUrl === "" && NS.state._intelUrlKey === urlKey) return;
    if (NS.state._intelUrlKey && NS.state._intelUrlKey !== urlKey) c.intelGeneration += 1;
    NS.state._intelUrlKey = urlKey;
    const gen = c.intelGeneration;
    c.intelBusy = true;
    Promise.resolve().then(() => runIcpWhoisIntel(gen, urlKey)).catch((error) => {
      // An unexpected provider/parser failure used to be swallowed here.  The
      // tab then kept `intelBusy`/identity pending forever (especially after
      // Edge froze and later restored a background tab).  Close this analysis
      // transaction as explicitly unavailable; never turn it into a clean
      // completed report, and still allow a late SSL/identity result to recover.
      if (gen !== c.intelGeneration || String(location.href) !== urlKey) return;
      const state = NS.state;
      state._icpQuerySettled = true;
      state._icpQueryFailed = true;
      if (!state.icpInfo) state.icpInfo = "备案查询失败";
      c.intelDoneForUrl = urlKey;
      state._softBrandIdentityReady = true;
      state._softBrandIdentityUrl = urlKey;
      state._identityVerificationUnavailable = true;
      state._identityVerificationUnavailableUrl = urlKey;
      try { NS.debugLog("intel-pipeline-error", error && error.message ? error.message : String(error || "unknown")); } catch { /* ignore */ }
      try { NS.nudgeProvisionalDownloadSettlement("intel-pipeline-error"); } catch { /* ignore */ }
      try {
        if (!state._analysisDone) NS.markAnalysisComplete("intel-pipeline-error");
        else NS.emitRiskReport(true);
      } catch { /* ignore */ }
    }).finally(() => { if (gen === c.intelGeneration) c.intelBusy = false; });
  };

  /**
   * 下载目录的有界性能静默。它只暂停重复 DOM 全扫，绝不直接认定官网；
   * ICP/WHOIS/SSL 全部结束后，可信站收口，不可信站恰好执行一次最终扫描。
   */
  NS.nudgeProvisionalDownloadSettlement = function (reason) {
    try {
      const controller = NS.caches && NS.caches._provisionalDownloadController;
      if (!controller || controller.active !== true || typeof controller.settle !== "function") return false;
      controller.settle(reason || "external-nudge");
      return true;
    } catch { return false; }
  };

  NS.recoverIdentityVerificationAvailability = function (reason) {
    try {
      const state = NS.state;
      const c = NS.caches;
      const urlKey = String(location.href || "");
      if (!state._identityVerificationUnavailable
        || state._identityVerificationUnavailableUrl !== urlKey) return false;
      const intelReady = !!(state._icpQuerySettled === true
        && state._icpQueryFailed !== true
        && c && c.intelDoneForUrl === urlKey);
      const sslReady = !/^https:/i.test(String(location.protocol || ""))
        || (state._sslIdentitySettled === true && state._sslIdentityTimedOut !== true);
      if (!intelReady || !sslReady) return false;
      state._identityVerificationUnavailable = false;
      state._identityVerificationUnavailableUrl = "";
      state._brandElectionSettledUrl = "";
      state._brandElectionSettledAt = 0;
      state._analysisDone = false;
      state._stickyComplete = false;
      state._stickyCompleteHost = "";
      try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
      try { NS.markAnalysisComplete(reason || "identity-verification-recovered"); } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  function releaseBackgroundProvisionalProtection(urlKey, reason, analysisTxn) {
    try {
      if (!chrome?.runtime?.id) return;
      chrome.runtime.sendMessage({
        type: "release-provisional-tab-protect",
        url: String(urlKey || location.href || ""),
        reason: String(reason || "provisional-identity-terminal"),
        analysisTxn: String(analysisTxn || (NS.state && NS.state._analysisTxn) || "")
      }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
  }

  NS.startProvisionalDownloadRouteAnalysis = function (reason) {
    const state = NS.state;
    const c = NS.caches;
    const urlKey = String(location.href || "");
    const previous = c && c._provisionalDownloadController;
    if (previous && previous.active === true && previous.url === urlKey) {
      try { previous.settle(`${String(reason || "clean-download")}-reuse`); } catch { /* ignore */ }
      return true;
    }
    try {
      if (previous && typeof previous.cancel === "function") previous.cancel("superseded");
    } catch { /* ignore */ }
    const generation = Number(state._provisionalDownloadAnalysisGeneration || 0) + 1;
    const ownerAnalysisTxn = String(state._analysisTxn || "");
    state._provisionalDownloadAnalysisGeneration = generation;
    NS.silverfoxLog && NS.silverfoxLog("boot", "provisional-clean-download", location.hostname, location.pathname, reason || "");
    let quietEntered = false;
    try {
      quietEntered = typeof NS.enterOfficialDownloadScanQuiet === "function"
        && NS.enterOfficialDownloadScanQuiet(reason || "clean-download-path");
    } catch { quietEntered = false; }
    // 已有真实硬威胁/guard 时性能静默会拒绝进入；此时必须立刻回到正常裁决，
    // 不能因调用方已 return 而让页面永久停在“正在核验”。
    if (!quietEntered) {
      try { NS.startIcpWhoisIntelEarly(`${String(reason || "clean-download")}-quiet-rejected`); } catch { /* ignore */ }
      state._officialDownloadForceScanAllowed = true;
      try { NS.scanSuspiciousPackagesFast(true); } catch { /* ignore */ }
      state._officialDownloadForceScanAllowed = false;
      try { NS.markAnalysisComplete("clean-download-quiet-rejected"); } catch { /* ignore */ }
      return false;
    }
    const provisionalDeadline = Date.now() + 26000;
    state._provisionalDownloadIdentityHold = true;
    state._provisionalDownloadIdentityUrl = urlKey;
    state._provisionalDownloadIdentityDeadlineAt = provisionalDeadline;
    state._identityVerificationUnavailable = false;
    state._identityVerificationUnavailableUrl = "";
    try { NS.armImmediatePackageBlock(); } catch { /* ignore */ }
    // Bind a webNavigation-created provisional record to this exact content
    // transaction. Otherwise a stale same-URL document could release an
    // ownerless record belonging to a reload.
    try {
      if (typeof NS.armBackgroundProtect === "function") NS.armBackgroundProtect("provisional");
    } catch { /* ignore */ }
    try { NS.notifyBackgroundDownloadTrust(false, `${String(reason || "clean-download")}-pending-identity`); } catch { /* ignore */ }
    try { NS.startIcpWhoisIntelEarly(`${String(reason || "clean-download")}-pending-identity`); } catch (e) { console.warn("early WHOIS/ICP start failed", e); }
    try { NS.emitRiskReport(true); } catch { /* ignore */ }

    let finished = false;
    let settling = false;
    let surfaceEvaluated = false;
    let surfaceOk = false;
    let timer = null;
    const cleanupListeners = [];
    const clearTimer = () => {
      if (!timer) return;
      try { clearTimeout(timer); } catch { /* ignore */ }
      timer = null;
    };
    const clearOwnedHold = () => {
      if (state._provisionalDownloadIdentityUrl === urlKey) {
        state._provisionalDownloadIdentityHold = false;
        state._provisionalDownloadIdentityUrl = "";
        state._provisionalDownloadIdentityDeadlineAt = 0;
      }
    };
    const cleanup = (clearQuiet) => {
      clearTimer();
      cleanupListeners.splice(0).forEach((off) => { try { off(); } catch { /* ignore */ } });
      clearOwnedHold();
      if (clearQuiet && state._officialDownloadScanQuietUrl === urlKey) {
        state._officialDownloadScanQuiet = false;
        state._officialDownloadScanQuietUrl = "";
      }
      if (c && c._provisionalDownloadController === controller) c._provisionalDownloadController = null;
      controller.active = false;
    };
    const finishWithFinalScan = (finishReason, timedOut) => {
      if (finished) return;
      finished = true;
      // Deadline only releases the click hold.  It is not a fabricated
      // ICP/WHOIS/TLS verdict: keep the real source flags untouched and mark
      // identity unavailable, so soft brand mismatch can neither toast nor arm
      // a permanent guard.  Late callbacks clear this state and may re-elect.
      if (timedOut) {
        state._identityVerificationUnavailable = true;
        state._identityVerificationUnavailableUrl = urlKey;
      }
      cleanup(true);
      state._officialDownloadForceScanAllowed = true;
      try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
      try { NS.scanSuspiciousPackagesFast(true); } catch { /* ignore */ }
      state._officialDownloadForceScanAllowed = false;
      const hardAfterScan = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      if (!hardAfterScan) {
        releaseBackgroundProvisionalProtection(urlKey, finishReason || "clean-download-final-scan", ownerAnalysisTxn);
      }
      try {
        if (!state._analysisDone) NS.markAnalysisComplete(finishReason || "clean-download-final-scan");
        else NS.emitRiskReport(true);
      } catch { /* ignore */ }
    };
    const schedule = () => {
      if (finished || timer) return;
      timer = setTimeout(() => {
        timer = null;
        settle("timer");
      }, 250);
    };
    const settle = (settleReason) => {
      if (finished || settling) return;
      settling = true;
      try {
      if (generation !== Number(state._provisionalDownloadAnalysisGeneration || 0)
        || String(location.href || "") !== urlKey
        || state._provisionalDownloadIdentityUrl !== urlKey) {
        finished = true;
        cleanup(false);
        return;
      }
      const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      const intelSettled = !!(state._icpQuerySettled === true
        && NS.caches && NS.caches.intelDoneForUrl === urlKey);
      const sslStartedForUrl = /^https:/i.test(String(location.protocol || ""))
        && String(state._sslIdentityUrl || "") === urlKey
        && Number(state._sslIdentityStartedAt || 0) > 0;
      const sslObservedForUrl = /^https:/i.test(String(location.protocol || ""))
        && String(state._sslIdentityUrl || "") === urlKey
        && state._sslIdentityObserved === true;
      const sslSettled = !/^https:/i.test(String(location.protocol || ""))
        || (state._sslIdentitySettled === true
          && state._sslIdentityTimedOut !== true
          && (sslStartedForUrl || sslObservedForUrl));
      const identitySettled = intelSettled && sslSettled;
      const domReady = document.readyState !== "loading";
      const deadlineReached = Date.now() >= provisionalDeadline;
      if (realHard) {
        finishWithFinalScan("clean-download-hard-threat", false);
        return;
      }
      if ((!identitySettled || !domReady) && !deadlineReached) {
        schedule();
        return;
      }

      if (identitySettled && !surfaceEvaluated) {
        surfaceEvaluated = true;
        try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
        surfaceOk = !!(!realHard
          && typeof NS.pageLooksLikeLegitimateOfficialDownload === "function"
          && NS.pageLooksLikeLegitimateOfficialDownload());
      }

      let trusted = false;
      if (!realHard && surfaceOk && identitySettled) {
        const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
          ? NS.evaluateMatureLegitimateSiteProfile() : null;
        const authoritative = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
          && NS.hasAuthoritativeMatureOrganizationIdentity(profile);
        trusted = !!(profile && (profile.trusted || authoritative));
      }

      if (trusted) {
        finished = true;
        cleanup(true);
        state._identityVerificationUnavailable = false;
        state._identityVerificationUnavailableUrl = "";
        releaseBackgroundProvisionalProtection(urlKey, "clean-download-identity-confirmed", ownerAnalysisTxn);
        try { NS.enterIntelLightMode("clean-download-identity-confirmed"); } catch { /* ignore */ }
        try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ }
        try { NS.maybeLiftDownloadGuard(); } catch { /* ignore */ }
        try { NS.markAnalysisComplete("clean-download-identity-confirmed"); } catch { /* ignore */ }
        return;
      }
      finishWithFinalScan(deadlineReached && !identitySettled
        ? "clean-download-identity-timeout"
        : "clean-download-final-scan", deadlineReached && !identitySettled);
      } catch {
        finishWithFinalScan("clean-download-settle-error", true);
      } finally {
        settling = false;
      }
    };
    const controller = {
      active: true,
      url: urlKey,
      generation,
      deadlineAt: provisionalDeadline,
      settle,
      cancel: () => {
        if (finished) return;
        finished = true;
        cleanup(false);
        releaseBackgroundProvisionalProtection(urlKey, "provisional-controller-cancel", ownerAnalysisTxn);
      }
    };
    if (c) c._provisionalDownloadController = controller;
    const listen = (target, type, handler, options) => {
      try {
        target.addEventListener(type, handler, options);
        cleanupListeners.push(() => target.removeEventListener(type, handler, options));
      } catch { /* ignore */ }
    };
    listen(document, "visibilitychange", () => {
      if (document.visibilityState === "visible") settle("visibility-visible");
    }, true);
    listen(window, "pageshow", () => settle("pageshow"), true);
    listen(window, "focus", () => settle("focus"), true);
    if (document.readyState === "loading") {
      listen(document, "DOMContentLoaded", () => settle("dom-content-loaded"), { once: true });
    }
    // 立即裁决一次；timer 只是兜底，ICP/SSL、Popup 与页面恢复事件都会主动 nudge。
    try { queueMicrotask(() => settle("start")); } catch { setTimeout(() => settle("start"), 0); }
    schedule();
    return true;
  };

  // 修复：startIcpWhoisIntelEarly 里引用了未定义的 state，用 NS.state

  // === Boot 入口 ===
  // 子 frame（广告/热门视频 iframe）只继承 guard，不跑全量分析、不写 risk 报告
  const bootIsTop = (() => { try { return typeof NS.isTopFrame !== "function" || NS.isTopFrame(); } catch { return true; } })();
  if (!bootIsTop) {
    try { NS.installParentGuardInheritance(); } catch (e) { console.warn("installParentGuardInheritance failed", e); }
    try { NS.installHooksMessageBridge(); } catch { /* ignore */ }
  } else {
  // Install the bounded identity watcher even when document_start sees an
  // empty SPA shell.  Waiting until pageNeedsFinalBrandElection() is true
  // would miss the exact first-load case where title/H1/CTA hydrate later.
  try { NS.ensureBrandElectionHydrationWatch(); } catch { /* ignore */ }
  const bootIsSearchUrl = (() => { try { return typeof NS.isSearchUrlShapeOnly === "function" && NS.isSearchUrlShapeOnly(); } catch { return false; } })();
  const bootIsPrivateLocal = (() => {
    try {
      return typeof NS.isPrivateOrLocalNetworkHost === "function" && NS.isPrivateOrLocalNetworkHost();
    } catch { return false; }
  })();
  // /download 路径和干净英文主域仅作佐证。document_start 时 WHOIS 与页面
  // 正规性尚未就绪，禁止据此进入轻量模式。
  const bootIsCleanOfficialDownload = (() => {
    try {
      const pathHint = typeof NS.looksLikeCleanOfficialDownloadHostPath === "function"
        && NS.looksLikeCleanOfficialDownloadHostPath();
      const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      return !!(pathHint && profile && profile.trusted);
    } catch { return false; }
  })();
  // 仅用于性能调度：干净品牌根结构 + 下载路径可在 document_start 暂停重型观察器，
  // 但绝不据此认定官网；身份、品牌、ICP/WHOIS/SSL 仍按完整流水线收口。
  const bootIsProvisionalCleanDownload = (() => {
    try {
      return typeof NS.looksLikeProvisionalDownloadPathShape === "function"
        && NS.looksLikeProvisionalDownloadPathShape();
    } catch { return false; }
  })();

  if (bootIsSearchUrl) {
    const state = NS.state;
    state._perfBenign = true; state._perfBenignAt = Date.now();
    state._intelLightMode = true; state._serpLightNotified = true;
    try { NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    try { NS.markAnalysisComplete("boot-search-light"); } catch { /* ignore */ }
    try { NS.startIcpWhoisIntelEarly("boot-search-light"); } catch (e) { console.warn("early WHOIS/ICP start failed", e); }
  } else if (bootIsPrivateLocal) {
    const state = NS.state;
    state._perfBenign = true; state._perfBenignAt = Date.now();
    state._intelLightMode = true;
    try { NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
    try { NS.postToHooks({ type: "set-official-safe", enabled: true }); } catch { /* ignore */ }
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    try {
      NS.markAnalysisComplete("boot-private-local");
    } catch { /* ignore */ }
  } else if (bootIsCleanOfficialDownload) {
    const state = NS.state;
    state._perfBenign = true; state._perfBenignAt = Date.now();
    state._intelLightMode = true;
    const bootReason = "boot-official-download";
    try {
      if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode(bootReason);
      else {
        NS.postToHooks({ type: "set-light-page", enabled: true });
        NS.postToHooks({ type: "set-official-safe", enabled: true });
      }
    } catch { /* ignore */ }
    // 仅保留 URL 变化监听 + 轻量情报；不装 package block / mutation / frame 补锁
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    try { NS.installHooksMessageBridge(); } catch { /* ignore */ }
    try { NS.markAnalysisComplete(bootReason); } catch { /* ignore */ }
    try { NS.startIcpWhoisIntelEarly(bootReason); } catch (e) { console.warn("early WHOIS/ICP start failed", e); }
  } else if (bootIsProvisionalCleanDownload) {
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    try { NS.installHooksMessageBridge(); } catch { /* ignore */ }
    try { NS.installParentGuardInheritance(); } catch { /* ignore */ }
    NS.startProvisionalDownloadRouteAnalysis("boot-clean-download-path");
  } else {
    const state = NS.state;
    NS.detectMutationBomb();
    NS.detectEnvironmentalAnomalies();
    NS.detectInteractionAbuse();
    try { NS.installPageNavigationWatchers(); } catch (e) { console.warn("installPageNavigationWatchers failed", e); }
    NS.installHooksMessageBridge();
    try { NS.installParentGuardInheritance(); } catch (e) { console.warn("installParentGuardInheritance failed", e); }

    try { NS.startIcpWhoisIntelEarly("boot-document-start"); } catch (e) { console.warn("early WHOIS/ICP start failed", e); }

    try {
      NS.scheduleIdle(() => {
        try {
          if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) {
            NS.disableAllDownloadIntentControls();
            NS.postToHooks({ type: "set-guard", enabled: true });
            return;
          }
          if (NS.pageLooksLikeLegitimateOfficialDownload() || NS.looksLikeMatureOfficialPortal()) {
            const trustedNow = typeof NS.pageHasStrongTrustedIdentity === "function"
              && NS.pageHasStrongTrustedIdentity();
            if (trustedNow) {
              NS.notifyHooksOfficialSafe(true);
              NS.maybeLiftDownloadGuard();
            } else if (!state._analysisDone
              && typeof NS.startProvisionalDownloadRouteAnalysis === "function") {
              // 页面结构只能触发“性能静默 + 有界身份等待”，不能提前宣告官网、
              // 清除 guard，或留下一个没有 owner 的永久 quiet 状态。
              NS.startProvisionalDownloadRouteAnalysis("boot-official-surface-400ms");
            }
          }
        } catch { /* ignore */ }
      }, 400);
      NS.scheduleIdle(() => {
        try {
          if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) {
            NS.disableAllDownloadIntentControls();
            NS.postToHooks({ type: "set-guard", enabled: true });
            return;
          }
          if (NS.pageLooksLikeLegitimateOfficialDownload() || NS.looksLikeMatureOfficialPortal() || NS.shouldNeverArmProtection()) {
            const trustedNow = typeof NS.pageHasStrongTrustedIdentity === "function"
              && NS.pageHasStrongTrustedIdentity();
            if (trustedNow || NS.shouldNeverArmProtection()) {
              NS.notifyHooksOfficialSafe(true);
              NS.maybeLiftDownloadGuard();
            } else if (!state._analysisDone
              && typeof NS.startProvisionalDownloadRouteAnalysis === "function") {
              NS.startProvisionalDownloadRouteAnalysis("boot-official-surface-2000ms");
            }
          }
        } catch { /* ignore */ }
      }, 2000);
    } catch { /* ignore */ }

    try {
      if (chrome?.runtime?.id) {
        // 新文档先撤销旧页面下载信任；情报核验完成后再显式建立。
        NS.notifyBackgroundDownloadTrust(false, "boot-reset-download-trust");
        chrome.runtime.sendMessage({
          type: "set-tab-protect", enabled: false, url: location.href,
          analysisTxn: state._analysisTxn || "",
          analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
        }, () => { void chrome.runtime.lastError; });
      }
    } catch { /* ignore */ }

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
          chrome.runtime.sendMessage({
            type: "pause-nav-blocking",
            reason: "user-gesture",
            url: location.href,
            analysisTxn: state._analysisTxn || "",
            analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
          }, () => { void chrome.runtime.lastError; });
        } catch { /* ignore */ }
      };
      const gOpts = { capture: true, passive: true };
      for (const t of ["pointerdown", "mousedown", "keydown", "touchstart"]) window.addEventListener(t, pauseDnrOnGesture, gOpts);
      window.addEventListener("pagehide", () => { try { chrome.runtime.sendMessage({
        type: "pause-nav-blocking",
        reason: "pagehide",
        clearProtect: false,
        url: location.href,
        analysisTxn: state._analysisTxn || "",
        analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
      }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } }, { capture: true });
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
      } else if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
        // 镜像/ISO 页：boot 即 light + complete，不挂 MutationObserver 连环扫
        state._perfBenign = true; state._perfBenignAt = Date.now(); state._intelLightMode = true;
        try {
          if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("boot-skip-heavy");
          else NS.postToHooks({ type: "set-light-page", enabled: true });
        } catch { /* ignore */ }
        NS.markAnalysisComplete("boot-skip-heavy");
      } else if ((typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
        || (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa())) {
        // 天气/资讯/大型内容站：light + complete；仅保留精准包证据观察，
        // 不做定时/全页重扫，避免 CSS/广告/Quill 水合拖慢主线程。
        state._perfBenign = true; state._perfBenignAt = Date.now(); state._intelLightMode = true;
        try {
          if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("boot-content-portal");
          else NS.postToHooks({ type: "set-light-page", enabled: true });
        } catch { /* ignore */ }
        NS.markAnalysisComplete("boot-content-portal");
        try { NS.watchSuspiciousPackagesLive({ evidenceOnly: true }); } catch { /* ignore */ }
      } else if (
        // 成熟门户 / 永不保护：light + complete（干净 /download 已在上方独立 boot 分支处理）
        ((typeof NS.looksLikeMatureOfficialPortal === "function" && NS.looksLikeMatureOfficialPortal())
          || (typeof NS.shouldNeverArmProtection === "function" && NS.shouldNeverArmProtection()))
        && !(typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof())
      ) {
        state._perfBenign = true; state._perfBenignAt = Date.now(); state._intelLightMode = true;
        try {
          if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("boot-mature-portal");
          else NS.postToHooks({ type: "set-light-page", enabled: true });
        } catch { /* ignore */ }
        NS.markAnalysisComplete("boot-mature-portal");
        try { NS.watchSuspiciousPackagesLive({ evidenceOnly: true }); } catch { /* ignore */ }
      } else { NS.watchSuspiciousPackagesLive(); }
    } catch (e) {
      console.warn("watchSuspiciousPackagesLive failed", e);
      try { if (!NS.isSearchUrlShapeOnly()) NS.armImmediatePackageBlock(); } catch { /* ignore */ }
    }

    try { NS.emitRiskReport(true); } catch { /* ignore */ }

    const runEarlyHeuristics = () => {
      try {
        if (state._analysisDone && !state.downloadGuardInstalled) return;
        if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
          state._perfBenign = true; state._intelLightMode = true;
          NS.markAnalysisComplete("early-skip-heavy");
          return;
        }
        NS.tryEarlyShellProtect();
        NS.scanSuspiciousPackagesFast();
        NS.scheduleIdle(() => {
          try {
            if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
              NS.markAnalysisComplete("early-idle-skip-heavy"); return;
            }
            if (state._perfBenign && !state._pendingEncryptedSpa && state._analysisDone) { NS.emitRiskReport(true); return; }
            if (NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan(); try { NS.invalidateHtmlCache(); } catch { /* ignore */ } NS.scanSuspiciousPackagesFast(true); NS.emitRiskReport(true); return; }
            if (state._analysisDone) { NS.emitRiskReport(true); return; }
            if (/官网|官方下载|客户端/i.test(document.title || "")
              && !(typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan())) {
              NS.detectLandingPageImpersonation();
            }
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
        // 海量镜像/ISO：load 路径禁止 hasDlTargets 触发主动探测，立即 complete
        if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
          state._perfBenign = true;
          state._intelLightMode = true;
          state._scanBusy = false;
          try { if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("load-skip-heavy"); } catch { /* ignore */ }
          NS.maybeLiftDownloadGuard();
          state._analysisDone = false;
          NS.markAnalysisComplete("load-skip-heavy");
          return;
        }
        // 天气/资讯/大型内容：load 立即 complete，不因附属 APK 去主动探测
        if ((typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa())
          || state._intelLightMode || state._perfBenign) {
          state._perfBenign = true;
          state._intelLightMode = true;
          state._scanBusy = false;
          try { if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("load-content-portal"); } catch { /* ignore */ }
          NS.maybeLiftDownloadGuard();
          NS.markAnalysisComplete("load-content-portal");
          return;
        }
        if (state._pendingEncryptedSpa || NS.shouldDeferAnalysisCompleteForEncryptedSpa()) {
          state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan();
          try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
          // 内容门户 / 粘性 complete：勿把 done 打回 false
          try {
            const portal = typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal();
            const sticky = !!(state._stickyComplete && state._stickyCompleteHost
              === String(location.hostname || "").toLowerCase().replace(/^www\./, ""));
            if (state._analysisDone && !state.downloadGuardInstalled && !portal && !sticky) state._analysisDone = false;
          } catch {
            if (state._analysisDone && !state.downloadGuardInstalled) state._analysisDone = false;
          }
          NS.scanSuspiciousPackagesFast(true); NS.emitRiskReport(true); return;
        }
        // 早扫可能在 DOM/脚本未就绪时 primary-clean；load 时对下载壳/挂起品牌强制复扫
        if (state._analysisDone && !state.downloadGuardInstalled && !state._pendingSoftBrandSpoof && !state._pendingEncryptedSpa) {
          let needRescan = false;
          try {
            // 勿因 [class*='download'] / 裸 /download 路径在镜像站上强制复扫
            // 勿因「安卓下载」二维码在天气站强制复扫
            if (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal()) {
              needRescan = false;
            } else {
              needRescan = !!(document.querySelector(".download-btn, #mainDownloadBtn, a.download-uri, a.btn-download")
                || /官方客户端|官方正版|立即免费下载/i.test(document.title || "")
                || state._pendingSoftBrandSpoof);
            }
          } catch { /* ignore */ }
          if (!needRescan) { NS.emitRiskReport(true); return; }
          state._analysisDone = false;
          state._remoteApiChecked = false;
        }
        if (NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode) { NS.enterIntelLightMode("load-ultra-mature"); NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-ultra-mature"); return; }
        // load 时 DOM 已就绪：复检品牌对齐开源仓，清 home-fast 误报
        try {
          if (NS.caches) { NS.caches._forgePresenceCache = null; NS.caches._forgePresenceAt = 0; }
          if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
            && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
            if (typeof NS.clearBrandSpoofFalsePositive === "function") {
              NS.clearBrandSpoofFalsePositive("trusted-opensource");
            }
            NS.maybeLiftDownloadGuard();
            NS.silverfoxLog && NS.silverfoxLog("load", "lift-trusted-opensource");
          }
        } catch { /* ignore */ }
        NS.scanSuspiciousPackagesFast(true);
        if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
          NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-skip-heavy-after-scan"); return;
        }
        if ((typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa())) {
          NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-content-after-scan"); return;
        }
        if (state._pendingEncryptedSpa || NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { NS.armEncryptedSpaLateRescan(); NS.emitRiskReport(true); return; }
        const hasDlTargets = typeof NS.pageHasProactiveDownloadButtonTargets === "function"
          && NS.pageHasProactiveDownloadButtonTargets();
        // 首页有下载按钮：不因 benign 跳过主动 fetch
        if (NS.shouldNeverArmProtection()) { NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-trusted"); return; }
        if ((state._perfBenign || NS.isBenignContentPage()) && !hasDlTargets) {
          NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-benign"); return;
        }
        // 内容站 hasDlTargets 误报时仍 complete
        if ((state._perfBenign || NS.isBenignContentPage()) && hasDlTargets) {
          NS.maybeLiftDownloadGuard(); NS.markAnalysisComplete("load-benign-ignore-soft-dl"); return;
        }
        if (state._analysisDone && !hasDlTargets) { NS.emitRiskReport(true); return; }
        // 主动探测下载按钮上的地址（与 scan 内互补；load 时再补一轮）
        const probe = typeof NS.proactivelyProbeDownloadButtons === "function"
          ? NS.proactivelyProbeDownloadButtons({ force: true, reason: "load-scan" })
          : NS.detectLinkedLandingPageSources();
        Promise.resolve(probe).catch(() => {}).finally(() => { NS.maybeLiftDownloadGuard(); NS.finalize(); });
      }, 600);
      setTimeout(() => {
        if (state._analysisDone && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) return;
        if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
          state._analysisDone = false;
          NS.maybeLiftDownloadGuard();
          NS.markAnalysisComplete("load-timeout-skip-heavy");
          return;
        }
        if ((typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || state._perfBenign || state._intelLightMode) {
          NS.maybeLiftDownloadGuard();
          NS.markAnalysisComplete("load-timeout-content-portal");
          return;
        }
        if (NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { NS.armEncryptedSpaLateRescan(); return; }
        NS.maybeLiftDownloadGuard(); NS.finalize();
      }, 1800);
      // 兜底：2.5s 仍未 complete 则强制 complete，避免 popup 永久「正在分析」
      setTimeout(() => {
        try {
          if (state._analysisDone) { NS.emitRiskReport(true); return; }
          if (state.downloadGuardInstalled || state._brandSpoofPortalDetected || state._seoCloakKitDetected) {
            NS.markAnalysisComplete("load-timeout-threat");
            return;
          }
          state._scanBusy = false;
          const urlKey = String(location.href || "");
          const intelSettled = state._icpQuerySettled === true
            && NS.caches && NS.caches.intelDoneForUrl === urlKey;
          const sslSettled = !/^https:/i.test(String(location.protocol || ""))
            || (state._sslIdentitySettled === true
              && state._sslIdentityTimedOut !== true
              && String(state._sslIdentityUrl || "") === urlKey);
          if (intelSettled && sslSettled) {
            NS.markAnalysisComplete("load-timeout-identity-settled");
          } else {
            // Keep the report incomplete; the ICP/WHOIS/TLS callbacks (or
            // their bounded watchdogs) own the eventual terminal decision.
            NS.emitRiskReport(true);
          }
        } catch { /* ignore */ }
      }, 2500);
    }, { once: true });

    let visibilityTimer = null;
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible") return;
      try { NS.nudgeProvisionalDownloadSettlement("visibility-resume"); } catch { /* ignore */ }
      try { NS.nudgeBrandElectionAfterHydration("visibility-resume"); } catch { /* ignore */ }
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
  } // bootIsTop
})(window.SilverfoxContent ??= {});
