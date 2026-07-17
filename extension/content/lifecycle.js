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
    const prevHost = state._analyzedHost || "";
    const hostChanged = !prevHost || prevHost !== (location.hostname || "");
    // 在清威胁标志之前判定是否同站 keep-light（依赖当前 state）
    const keepLight = !hostChanged && typeof NS.shouldKeepLightOnSameHostSoftNav === "function" && NS.shouldKeepLightOnSameHostSoftNav();
    // 同站 + 有效 ICP：轻量路径——只换 URL 报告，不清备案/评分结果（避免 popup 卡「正在分析」）
    const keepIcpOnce = !hostChanged && typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()
      && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
    if (keepLight || keepIcpOnce) {
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
        if (typeof NS.markAnalysisComplete === "function") NS.markAnalysisComplete(keepIcpOnce ? "reset-keep-icp" : "reset-keep-light");
        else NS.emitRiskReport(true);
      } catch { /* ignore */ }
      NS.silverfoxLog && NS.silverfoxLog("nav-reset", "keep-light-or-icp-once", reason || "", keepIcpOnce ? "icp" : "light");
      return;
    }
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
    state._perfBenign = false; state._perfBenignAt = 0;
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
      state.icpInfo = "";
      state.whoisInfo = "";
      state.icpMatchedHost = "";
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
    const state = NS.state;
    // 已 light / 有效 ICP 同站 / 大型内容 SPA / WHOIS 超成熟：不排队多轮重扫
    try {
      const icpOnce = typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()
        && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
      if (state._intelLightMode || state._perfBenign || icpOnce
        || (typeof NS.shouldKeepLightOnSameHostSoftNav === "function" && NS.shouldKeepLightOnSameHostSoftNav())
        || NS.looksLikeUltraMatureWhoisDomain()
        || NS.looksLikeUltraMatureIcpDomain()) {
        if (!state._intelLightMode) NS.enterIntelLightMode(icpOnce ? "page-change-icp-once" : "page-change-light");
        else { state._perfBenign = true; state._analysisDone = true; }
        NS.markAnalysisComplete(icpOnce ? "page-change-icp-once" : "page-change-light");
        NS.emitRiskReport(true);
        return;
      }
    } catch { /* ignore */ }
    if (c.pageNavRescanTimer) { try { clearTimeout(c.pageNavRescanTimer); } catch { /* ignore */ } c.pageNavRescanTimer = null; }
    c.pageNavRescanTimer = setTimeout(() => {
      c.pageNavRescanTimer = null;
      try {
        const icpOnce2 = typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()
          && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
        if (NS.state._intelLightMode || NS.state._perfBenign || icpOnce2
          || NS.looksLikeUltraMatureWhoisDomain()
          || NS.looksLikeUltraMatureIcpDomain()
          || (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa())) {
          NS.enterIntelLightMode(icpOnce2 ? "page-change-icp-once-deferred" : "page-change-light-deferred");
          NS.markAnalysisComplete(icpOnce2 ? "page-change-icp-once" : "page-change-light");
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
          if (NS.hasValidIcpRecord() || NS.looksLikeUltraMatureIcpDomain() || NS.looksLikeUltraMatureWhoisDomain()
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
          const lightSkip = (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord())
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
    // 同站 soft-nav + 有效 ICP / light：禁止 reset+全量复扫；只更新报告 URL
    try {
      let prevHost = "";
      try { prevHost = c.lastAnalyzedUrl ? new URL(c.lastAnalyzedUrl).hostname : (state._analyzedHost || ""); } catch { prevHost = state._analyzedHost || ""; }
      const newHost = location.hostname || "";
      const sameHost = !!(prevHost && newHost && prevHost.replace(/^www\./, "") === newHost.replace(/^www\./, ""));
      const icpOnce = sameHost && typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()
        && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat());
      const keep = sameHost && (
        icpOnce
        || (typeof NS.shouldKeepLightOnSameHostSoftNav === "function" && NS.shouldKeepLightOnSameHostSoftNav())
      );
      if (keep) {
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
            NS.markAnalysisComplete(icpOnce ? "soft-nav-icp-once" : "soft-nav-keep-light");
          } else {
            NS.emitRiskReport(true);
          }
        } catch { try { NS.emitRiskReport(true); } catch { /* ignore */ } }
        NS.silverfoxLog && NS.silverfoxLog("nav-skip", icpOnce ? "soft-nav-icp-once" : "soft-nav-keep-light", reason || "");
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
        if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.notifyHooksOfficialSafe(true); return; }
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
        try { chrome.runtime.sendMessage({ type: "request-guard-bg", mode: "full", url: location.href, reason: data.reason || "" }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
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
      if (data.type === "hooks-ready") { if (state.downloadGuardInstalled) NS.postToHooks({ type: "set-guard", enabled: true }); }
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
    let whois = null;
    try { whois = await NS.detectWhoisRegistrationAge(pageHost); } catch { whois = { success: false }; }
    if (gen !== c.intelGeneration || location.href !== urlKey) return;
    NS.maybeLiftDownloadGuard(); NS.emitRiskReport(true);
    // WHOIS ↔ ICP 绑定：无有效 WHOIS 则不查 ICP、不展示 ICP
    if (!NS.whoisHasResult(whois)) {
      state.icpInfo = ""; state.icpMatchedHost = "";
      state._icpQuerySettled = true; state._icpQueryFailed = true;
      if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
      // 已 light/内容门户/粘性 complete：禁止把 analysisDone 打回 false（否则 popup 闪一下再卡「正在分析」）
      const stayDone = !!(state._perfBenign || state._intelLightMode || state._stickyComplete
        || (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
        || (typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()));
      if (!stayDone && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
        try {
          if (state._pendingSoftBrandSpoof || !state._brandSpoofPortalDetected) {
            state._pendingSoftBrandSpoof = false;
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
      const icpCheck = await NS.detectIcpDomain(pageHost);
      if (gen !== c.intelGeneration || location.href !== urlKey) return;
      if (!icpCheck.success) {
        // API 失败视为门控已定论（查不到），否则软品牌仿冒会永久 pending
        NS.silverfoxLog("intel-icp", "api-fail-settle-missing");
        state.icpInfo = ""; state.icpMatchedHost = "";
        state._icpQueryFailed = true; state._icpQuerySettled = true;
        if (gen === c.intelGeneration) c.intelDoneForUrl = urlKey;
        const stayDoneIcp = !!(state._perfBenign || state._intelLightMode || state._stickyComplete
          || (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || (typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()));
        if (!stayDoneIcp && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
          try {
            if (state._pendingSoftBrandSpoof || !state._brandSpoofPortalDetected) {
              state._pendingSoftBrandSpoof = false;
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
      // 真硬套件（SEO/强制弹窗/乱码）即使有 ICP 也不得 officialSafe
      const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      // 有效 ICP 或超成熟 WHOIS：强制抬软误报（百度/pcsoft 等不应再显示「可疑安装包已禁用」）
      if (!realHard && (NS.hasValidIcpRecord() || (ageDays != null && ageDays >= 3650) || NS.looksLikeUltraMatureWhoisDomain())) {
        try {
          if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
            NS.forceLiftSoftProtectionForTrustedPortal(NS.hasValidIcpRecord() ? "valid-icp-force-lift" : "whois-ultra-force-lift");
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
        const stayDoneSoft = !!(state._perfBenign || state._intelLightMode || state._stickyComplete
          || (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal())
          || (typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()));
        if (!stayDoneSoft && (state._pendingSoftBrandSpoof || !state._brandSpoofPortalDetected)) {
          state._pendingSoftBrandSpoof = false;
          try {
            if (NS.detectBrandSpoofDownloadPortal()) state._brandSpoofPortalDetected = true;
            NS.scanSuspiciousPackagesFast(true);
          } catch { /* ignore */ }
        }
      }
      if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain() || (NS.hasValidIcpRecord() && ageDays != null && ageDays >= 3650)) {
        try { if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") NS.forceLiftSoftProtectionForTrustedPortal("whois-ultra-mature"); } catch { /* ignore */ }
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
    NS.maybeLiftDownloadGuard();
    // 情报结束必须 complete，禁止只 emit incomplete 覆盖 popup
    if (!state._analysisDone) NS.markAnalysisComplete("intel-pipeline-done");
    else NS.emitRiskReport(true);
  }

  NS.startIcpWhoisIntelEarly = function (reason) {
    const c = NS.caches;
    void reason;
    try { if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) return; } catch { /* ignore */ }
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
  // 子 frame（广告/热门视频 iframe）只继承 guard，不跑全量分析、不写 risk 报告
  const bootIsTop = (() => { try { return typeof NS.isTopFrame !== "function" || NS.isTopFrame(); } catch { return true; } })();
  if (!bootIsTop) {
    try { NS.installParentGuardInheritance(); } catch (e) { console.warn("installParentGuardInheritance failed", e); }
    try { NS.installHooksMessageBridge(); } catch { /* ignore */ }
  } else {
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
            NS.notifyHooksOfficialSafe(true);
            if (state.downloadGuardInstalled || state._earlyShellArmed) NS.clearDownloadGuard("boot-official-portal");
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
            NS.notifyHooksOfficialSafe(true);
            NS.maybeLiftDownloadGuard();
          }
        } catch { /* ignore */ }
      }, 2000);
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
        // 天气/资讯/大型内容站：light + complete，不挂 live 观察（CSS/广告脚本狂变）
        state._perfBenign = true; state._perfBenignAt = Date.now(); state._intelLightMode = true;
        try {
          if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("boot-content-portal");
          else NS.postToHooks({ type: "set-light-page", enabled: true });
        } catch { /* ignore */ }
        NS.markAnalysisComplete("boot-content-portal");
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
          state._perfBenign = true;
          state._intelLightMode = true;
          state._scanBusy = false;
          NS.markAnalysisComplete("load-timeout-force-complete");
        } catch { /* ignore */ }
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
  } // bootIsTop
})(window.SilverfoxContent ??= {});
