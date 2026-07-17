/**
 * 扫描调度 + 点击拦截：scanSuspiciousPackagesFast 主链、armImmediatePackageBlock、
 * blockPackageDownloadAction 捕获阶段拦截、watchSuspiciousPackagesLive。
 */
;(function (NS) {
  "use strict";

  NS.getInteractiveElementForGuard = function (target) {
    if (!target) return null;
    let el = null;
    if (target.nodeType === Node.TEXT_NODE && target.parentElement) el = target.parentElement.closest("a, button, [role='button'], input[type='button']");
    else if (typeof target.closest === "function") el = target.closest("a, button, [role='button'], input[type='button']");
    if (!el) return null;
    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
      if (href && NS.isPackageFileUrl(href)) return el;
      return null;
    }
    if (NS.isDownloadIntentElement(el) || el.matches("a[href], a[data-href], a[data-threat-original-href]")) return el;
    return null;
  };

  NS.isPrimaryActivationEvent = function (event) {
    if (!event) return false;
    const type = event.type || "";
    if (type === "keydown") return event.key === "Enter" || event.key === " ";
    if (typeof event.button === "number" && event.button !== 0) return false;
    if (typeof event.buttons === "number" && type === "pointerdown" && event.buttons !== 0 && (event.buttons & 1) === 0) return false;
    return true;
  };

  NS.blockPackageDownloadAction = function (event, element) {
    if (!element) return false;
    if (!NS.isPrimaryActivationEvent(event)) return false;
    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      const hrefSerp = NS.getElementDownloadHref(element) || (element.getAttribute && (element.getAttribute("href") || element.getAttribute("data-href"))) || "";
      if (!hrefSerp || !NS.isPackageFileUrl(hrefSerp)) return false;
      if (NS.isHrefSuspiciousPackageSync(hrefSerp, element)) { event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation(); return true; }
      return false;
    }
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal() || NS.pageLooksLikeLegitimateOfficialDownload()) {
      const state = NS.state;
      // 硬套件已命中时禁止点击路径清 guard
      if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) {
        try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
        return true;
      }
      if (state.downloadGuardInstalled || (state.protectedTargets && state.protectedTargets.length) || document.querySelector("[data-threat-detector-disabled='1']")) { NS.clearDownloadGuard("official-portal-click"); NS.notifyHooksOfficialSafe(true); }
      return false;
    }
    const href = NS.getElementDownloadHref(element) || (element.getAttribute && (element.getAttribute("href") || element.getAttribute("data-href"))) || "";
    const state = NS.state;
    if (state.downloadGuardInstalled && NS.isDownloadIntentElement(element)) {
      const fn = href ? NS.getFilenameFromUrl(href) : "";
      if (href && (NS.looksLikeStrongProductInstallerName(fn) || NS.looksLikeOfficialProductDownloadEndpoint(href) || NS.isBenignShortInstallerName(fn))) { /* allow strong product */ }
      else {
        event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation();
        NS.disableOneSuspiciousElement(element, href || state.protectedTargets[0] || "js-download");
        NS.disableAllDownloadIntentControls();
        NS.postToHooks({ type: "set-guard", enabled: true });
        const target = state.protectedTargets[0] || href || "可疑安装包";
        NS.showGuardOverlay(target, { title: "已拦截可疑下载", message: NS.formatPackageLabel(target) || "保护模式下已禁止本页一切安装包拉取", toast: true, userAction: true, forceNotify: true });
        return true;
      }
    }
    if (href && NS.looksLikeOfficialProductDownloadEndpoint(href)) return false;
    if (href && (NS.isClearProductOrAndroidPackage(href) || NS.isBenignShortInstallerName(NS.getFilenameFromUrl(href)) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(href)) || (NS.isAllowlistedProductPackageUrl(href) && !NS.looksLikeOversimplifiedBrandInstallerName(NS.getFilenameFromUrl(href))) || (NS.isContentAddressedPackageName(NS.getFilenameFromUrl(href)) && !NS.looksLikeHighRiskBlobPackageUrl(href)))) return false;
    if (NS.isTrustedOfficialDownloadContext() && href && NS.isSamePageBrandApex(href)) return false;
    if (NS.looksLikeSafeOfficialContext() && href && !NS.looksLikeHighRiskBlobPackageUrl(href) && !NS.isAnonymousPublicObjectHost((() => { try { return new URL(href, location.href).hostname; } catch { return ""; } })())) return false;
    if (href && NS.isSamePageBrandApex(href) && !NS.looksLikeOpaqueDownloadHopUrl(href) && !NS.isPackageFileUrl(href)) {
      try { const path = new URL(href, location.href).pathname.toLowerCase().replace(/\/+$/, "") || "/"; if (/^\/(?:win|windows|mac|osx|macos|linux|android|ios|pc|download|downloads)(?:\/|$)/i.test(path)) return false; } catch { /* ignore */ }
    }
    if ((state.downloadGuardInstalled || state.protectedTargets.length > 0) && NS.isDownloadIntentElement(element)) {
      if (href && (NS.looksLikeOfficialProductDownloadEndpoint(href) || (NS.isSamePageBrandApex(href) && !NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href)))) return false;
      if (NS.pageLooksLikeLegitimateOfficialDownload() || NS.isTrustedOfficialDownloadContext()) {
        if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) {
          try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
          event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation();
          return true;
        }
        NS.clearDownloadGuard("guard-fp-official-cta"); NS.notifyHooksOfficialSafe(true); return false;
      }
      event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation();
      NS.disableOneSuspiciousElement(element, href || state.protectedTargets[0] || "js-download");
      NS.disableAllDownloadIntentControls();
      const target = state.protectedTargets[0] || href || "可疑安装包";
      const msg = NS.formatPackageLabel(target) || target;
      NS.showGuardOverlay(target, { title: "已拦截可疑下载", message: msg, toast: true, userAction: true, forceNotify: true });
      state.protectionNoticeSent = true;
      NS.markRemoteDownloadDispatch(`blocked-download-button -> ${msg}`, NS.isPackageFileUrl(target) ? target : "");
      return true;
    }
    if (NS.isHrefSuspiciousPackageSync(href, element) || NS.isHrefSuspiciousPackage(href, element)) {
      event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation();
      NS.disableOneSuspiciousElement(element, href);
      NS.disableAllDownloadIntentControls();
      if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
      NS.markRemoteDownloadDispatch(`blocked -> ${href}`, href);
      let msg = NS.formatPackageLabel(href);
      try { const u = new URL(href, location.href); if (!NS.PACKAGE_EXT.test(u.pathname)) msg = `${u.hostname}${u.pathname}`; } catch { /* ignore */ }
      NS.showGuardOverlay(href, { title: "已拦截可疑下载", message: msg, toast: true, userAction: true, forceNotify: true });
      return true;
    }
    if (href && NS.needsDownloadBehaviorProbe(href, element) && !NS.shouldNeverArmProtection() && !NS.looksLikeMatureOfficialPortal()) {
      event.preventDefault(); event.stopImmediatePropagation(); event.stopPropagation();
      const abs = (() => { try { return new URL(href, location.href).href; } catch { return href; } })();
      const cached = NS.caches.probeCache.get(abs);
      if (cached && cached.isDownload === false) { try { if (element.tagName === "A" && href && href !== "#") window.location.href = abs; } catch { /* ignore */ } return true; }
      if (cached && cached.isDownload) { NS.applyConfirmedDownloadBlock(href, element, cached); NS.disableAllDownloadIntentControls(); NS.showGuardOverlay(href, { title: "已拦截可疑下载", message: cached.filename || href }); return true; }
      NS.probeDownloadBehavior(href).then((result) => {
        if (result && result.isDownload) { NS.applyConfirmedDownloadBlock(href, element, result); NS.disableAllDownloadIntentControls(); NS.showGuardOverlay(href, { title: "已拦截可疑下载", message: result.filename || NS.formatPackageLabel(href) }); }
        else { try { const tgt = (element.getAttribute("target") || "_self").toLowerCase(); if (tgt === "_blank") window.open(abs, "_blank", "noopener,noreferrer"); else window.location.href = abs; } catch { /* ignore */ } }
      });
      return true;
    }
    return false;
  };

  let immediateBlockArmed = false;

  NS.armImmediatePackageBlock = function () {
    const state = NS.state;
    if (immediateBlockArmed) return;
    if (state._intelLightMode || state._perfBenign || NS.isSearchUrlShapeOnly() || NS.pageLooksLikeSearchEngineResultsPage()) { immediateBlockArmed = true; return; }
    immediateBlockArmed = true;
    const onPointer = (event) => {
      if (!NS.isPrimaryActivationEvent(event)) return;
      if (state._intelLightMode || state._perfBenign) return;
      if (NS.isSearchUrlShapeOnly()) return;
      try { const t = event.target; const tag = t && (t.tagName || "").toUpperCase(); if (tag === "INPUT" || tag === "TEXTAREA" || (t && t.isContentEditable)) return; } catch { /* ignore */ }
      const el = NS.getInteractiveElementForGuard(event.target);
      if (el && NS.blockPackageDownloadAction(event, el)) el.setAttribute("data-threat-detector-blocked", "1");
    };
    document.addEventListener("mousedown", onPointer, true);
    document.addEventListener("pointerdown", onPointer, true);
    document.addEventListener("click", onPointer, true);
    document.addEventListener("keydown", (event) => { if (event.key !== "Enter" && event.key !== " ") return; onPointer(event); }, true);
  };

  NS.needsDownloadBehaviorProbe = function (href, element) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
    if (NS.isPackageFileUrl(href)) return false;
    try { const u = new URL(href, location.href); if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(u.pathname + u.search)) return false; } catch { /* ignore */ }
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return false;
    if (NS.looksLikeSafeOfficialContext() && !NS.hostLooksLikeBrandMarketingSpoof()) return false;
    if (NS.hostLooksLikeBrandMarketingSpoof()) {
      try { const u = new URL(href, location.href); const base = (u.pathname.split("/").pop() || "").toLowerCase(); if (/^(?:download|down|getdown)\.(?:php|asp|aspx)$/i.test(base)) return true; if (!NS.isSamePageBrandApex(href)) return true; } catch { /* ignore */ }
    }
    if (NS.looksLikeOfficialProductDownloadEndpoint(href)) return false;
    if (NS.isTrustedOfficialDownloadContext() && NS.isSamePageBrandApex(href)) return false;
    try {
      const u = new URL(href, location.href);
      if (NS.looksLikeOpaqueDownloadHopUrl(href)) return true;
      if (NS.looksLikeRandomDownloadHost(u.hostname)) return true;
      if (element && NS.isDownloadIntentElement(element) && u.origin !== location.origin) {
        if (NS.isSamePageBrandApex(href)) return false;
        try {
          const pageHost = location.hostname.toLowerCase().replace(/^www\./, "");
          const pkgHost = u.hostname.toLowerCase().replace(/^www\./, "");
          const pageCore = pageHost.split(".")[0].replace(/\d+/g, "") || pageHost.split(".")[0];
          const pkgFlat = pkgHost.replace(/[^a-z0-9]/g, "");
          if (pageCore.length >= 2 && pkgFlat.includes(pageCore)) return false;
          const pageDigits = (pageHost.match(/\d{2,4}/g) || []).join("");
          if (pageDigits.length >= 2 && pkgHost.includes(pageDigits)) return false;
        } catch { /* ignore */ }
        return true;
      }
      return false;
    } catch { return false; }
  };

  /**
   * 快速路径：同步包 + 内嵌 Nuxt/base64 威胁 + 异步 probe。节流。
   */
  NS.scanSuspiciousPackagesFast = function (force = false) {
    const state = NS.state;
    const c = NS.caches;
    if (!NS.isHttpOrHttpsPage()) { NS.silverfoxLog("scan-skip", "non-http-protocol"); return false; }
    const now = Date.now();
    if (!force && state._analysisDone && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected && !(state._pendingEncryptedSpa && NS.shouldDeferAnalysisCompleteForEncryptedSpa())) { NS.silverfoxLog("scan-skip", "analysis-done", "force=", force); return false; }
    if (!force && state._scanBusy) { NS.silverfoxLog("scan-skip", "busy"); return; }
    if (!force && now - (state._lastFastScanAt || 0) < 700) { NS.silverfoxLog("scan-skip", "throttle"); return; }
    const titleHotEarly = /官网|官方下载|官方正版|官方网站/i.test(document.title || "")
      && !/iso|镜像|发行版|Arch\s*Linux|Ubuntu|Debian/i.test(document.title || "");
    // 海量可点下载 / 发行版 ISO：整页 light + 立即 analysisComplete（popup 不再卡「正在分析」）
    const skipHeavy = typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan();
    const archiveHeavy = skipHeavy
      || (typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList())
      || (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())
      || (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive());
    if (archiveHeavy && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected && !titleHotEarly) {
      NS.silverfoxLog("scan-gate", "skip-heavy-page", "links≈", (document.links && document.links.length) || 0);
      state._lastFastScanAt = now;
      state._scanBusy = false;
      state._perfBenign = true;
      state._perfBenignAt = now;
      state._intelLightMode = true;
      try {
        if (typeof NS.enterIntelLightMode === "function") NS.enterIntelLightMode("skip-heavy-page");
        else NS.postToHooks({ type: "set-light-page", enabled: true });
      } catch { /* ignore */ }
      // 强制完成：即使此前 analysisDone 被 load 路径清掉，也立刻上报 complete
      state._analysisDone = false;
      NS.markAnalysisComplete("skip-heavy-page");
      return false;
    }
    if (archiveHeavy && !force && !titleHotEarly && now - (state._lastFastScanAt || 0) < 2500) {
      NS.silverfoxLog("scan-skip", "archive-throttle");
      return;
    }
    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      NS.silverfoxLog("scan-gate", "serp");
      state._lastFastScanAt = now; state._perfBenign = true; state._perfBenignAt = now; state._scanBusy = false;
      if (state.downloadGuardInstalled || state._earlyShellArmed || document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']")) { try { NS.clearDownloadGuard("serp-light-mode"); } catch { /* ignore */ } try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ } }
      NS.markAnalysisComplete("serp-scan");
      return false;
    }
    if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked() && state.downloadGuardInstalled) {
      // 硬套件已锁：禁止 ultra-mature/official 扫描门直接 light 化并抬锁
      try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
    } else if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode) {
      NS.silverfoxLog("scan-gate", "ultra-mature-or-light");
      state._lastFastScanAt = now; state._scanBusy = false;
      NS.enterIntelLightMode("ultra-mature-whois-scan");
      if (!(typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked())) {
        state._brandSpoofPortalDetected = false; state.spoofBrand = "";
      }
      NS.markAnalysisComplete("ultra-mature");
      return false;
    } else if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) {
      // 有下载按钮导流时仍允许 brand-spoof / 主动 fetch（勿整页 mature 短路）
      const stillNeedDlProbe = typeof NS.pageHasProactiveDownloadButtonTargets === "function"
        && NS.pageHasProactiveDownloadButtonTargets();
      if (!stillNeedDlProbe) {
        NS.silverfoxLog("scan-gate", "mature-official");
        state._lastFastScanAt = now; state._scanBusy = false;
        NS.enterIntelLightMode("mature-official-scan");
        if (!(typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked())) {
          state._brandResourceMismatchDetected = false; state._brandSpoofPortalDetected = false;
        }
        NS.markAnalysisComplete("mature-official");
        return false;
      }
      NS.silverfoxLog("scan-gate", "mature-but-has-download-btns");
    }
    const hasDlBtnHome = typeof NS.pageHasProactiveDownloadButtonTargets === "function"
      && NS.pageHasProactiveDownloadButtonTargets();
    if (!force && state._perfBenign && !state.downloadGuardInstalled && !titleHotEarly && !state._fakeSpaDetected
      && !hasDlBtnHome
      && now - (state._perfBenignAt || 0) < 12000 && now - (state._lastFastScanAt || 0) < 8000) {
      NS.silverfoxLog("scan-gate", "perf-benign-throttle"); NS.markAnalysisComplete("perf-benign-throttle"); return;
    }
    state._lastFastScanAt = now; state._scanBusy = true;
    NS.silverfoxLog("scan-start", "force=", force, "title=", (document.title || "").slice(0, 80));

    let found = false; let firstHref = "";
    const toProbe = [];
    try {
      if (force || !c._htmlCache || (Date.now() - c._htmlCacheAt > 4000)) NS.invalidateHtmlCache();
      const titleHot = /官网|官方下载|官方正版|官方网站/i.test(document.title || "") && !NS.looksLikeMatureOfficialPortal();

      // ① 品牌类优先：壳 → 仿冒门户 → 品牌资源失配，再跑 SEO/包扫描
      // 仅顶层 frame 做仿冒 toast/arm；iframe 内由顶层 set-guard 广播继承拦截，避免广告框误报
      const isTop = typeof NS.isTopFrame !== "function" || NS.isTopFrame();
      if (isTop && !state._fakeBrandShellDetected) {
        if (NS.runDetector("FakeBrandDownloadShell", NS.detectFakeBrandDownloadShell)) {
          state._fakeBrandShellDetected = true;
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "仿冒品牌下载";
        }
      }
      // 仿冒官网：夹带域（huorong-pc）即使稍后才有 ICP 结果，也先跑快速路径
      if (isTop && !state._brandSpoofPortalDetected) {
        try {
          if (typeof NS.tryArmChineseBrandDownloadHomeSpoof === "function" && NS.tryArmChineseBrandDownloadHomeSpoof()) {
            state._brandSpoofPortalDetected = true;
            found = true;
            firstHref = firstHref || "仿冒官网下载";
            NS.silverfoxLog("detect", "BrandSpoofHomeFast", "hit");
          }
        } catch (e) { NS.silverfoxLog && NS.silverfoxLog("detect", "BrandSpoofHomeFast", "err", e && e.message); }
      }
      if (isTop && !state._brandSpoofPortalDetected && !NS.hasValidIcpRecord()) {
        if (NS.runDetector("BrandSpoofDownloadPortal", NS.detectBrandSpoofDownloadPortal)) {
          state._brandSpoofPortalDetected = true;
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载";
        }
      } else if (isTop && NS.hasValidIcpRecord() && state._brandSpoofPortalDetected && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._fakeBrandShellDetected) {
        // 仅非夹带的软误报才 clear；营销夹带 + 下载门户保留
        let paddedKeep = false;
        try {
          const lr = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          const c0 = typeof NS.inferMarketingPaddedBrandCore === "function" ? (NS.inferMarketingPaddedBrandCore(lr) || "") : "";
          paddedKeep = !!(c0 && typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lr.replace(/-/g, ""), c0));
        } catch { /* ignore */ }
        if (!paddedKeep) {
          NS.silverfoxLog("brand-spoof", "clear-by-icp");
          NS.clearBrandSpoofFalsePositive("scan-icp-present");
        }
      } else if (NS.hasValidIcpRecord() && !state._brandSpoofPortalDetected) {
        NS.silverfoxLog("detect", "BrandSpoofDownloadPortal", "skip-valid-icp");
      }
      if (!state._brandResourceMismatchDetected) {
        if (NS.runDetector("BrandResourceDomainMismatch", NS.detectBrandResourceDomainMismatch)) {
          state._brandResourceMismatchDetected = true;
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "仿冒官网域名不一致";
        }
      }
      if (!state._seoCloakKitDetected) { if (NS.runDetector("SeoCloakingRedirectKit", NS.detectSeoCloakingRedirectKit)) { found = true; firstHref = firstHref || "SEO伪装跳转"; } }
      if (!state._desktopForceDlKit) { if (NS.runDetector("DesktopForceDownloadKit", NS.detectDesktopForceDownloadKit)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "桌面端强制弹窗下载"; } }
      if (!state._remoteGarbleDlDetected) { if (NS.runDetector("RemoteGarblePackageDispatch", NS.detectRemoteGarblePackageDispatch)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "远程乱码安装包"; } }
      if (!state._indexNowPhishTemplate) { if (NS.runDetector("IndexNowSeoPhishTemplate", NS.detectIndexNowSeoPhishTemplate)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "SEO收录仿冒模板"; } }
      if (!state._multiPlatformSerpTrap) { if (NS.runDetector("MultiPlatformSerpDownloadTrap", NS.detectMultiPlatformSerpDownloadTrap)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "多平台搜索引擎跳转"; } }
      if (!state._fakeSpaDetected) {
        if (NS.runDetector("FakeOfficialDownloadSpa", NS.detectFakeOfficialDownloadSpa)) { state._fakeSpaDetected = true; state._pendingEncryptedSpa = false; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载"; }
        else if (NS.pageLooksLikePendingEncryptedDownloadSpa()) { NS.silverfoxLog("encrypted-spa", "pending-hydrate"); state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan(); }
      }

      // 下载壳/远程绑定信号：即使主链未命中也要进二级
      // 内容门户（天气/资讯）上的「安卓下载/手机看天气」不当成下载壳
      const contentPortal = typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal();
      let downloadShellSignals = titleHot || state._fakeBrandShellDetected;
      if (!downloadShellSignals && !contentPortal) {
        try {
          if (document.querySelector(".download-btn, .download-btn-nav, #mainDownloadBtn, a.download-uri, .download-uri, [class*='btn-download'], .platform-btn")) downloadShellSignals = true;
          else if (/download_uri|api\.php|windowsDownload|macDownload|fetchDownloadLink|download_link|getdown|getlink|initDownloadLinks/i.test(NS.getHtmlSlice(16000) || "")) downloadShellSignals = true;
          else {
            const nodes = document.querySelectorAll("a, button, [role='button']");
            const lim = Math.min(nodes.length || 0, 48);
            for (let i = 0; i < lim; i++) {
              const tx = (nodes[i].textContent || "").replace(/\s+/g, " ").trim();
              // 仅强下载话术；裸「下载」在资讯页太常见
              if (/立即下载|免费下载|官方下载|客户端下载|安装包|云电脑下载/i.test(tx) && tx.length <= 40) {
                downloadShellSignals = true; break;
              }
            }
          }
        } catch { /* ignore */ }
      }

      if (!found && !state.downloadGuardInstalled && !state._seoCloakKitDetected && !state._indexNowPhishTemplate && !state._fakeSpaDetected && !titleHot && !state._pendingEncryptedSpa
        && (!downloadShellSignals || contentPortal)) {
        try {
          if (document.body && (contentPortal || NS.isBenignContentPage())) {
            NS.silverfoxLog("scan-exit", contentPortal ? "content-portal-early" : "benign-early");
            state._perfBenign = true; state._perfBenignAt = now; state._intelLightMode = true;
            NS.markAnalysisComplete(contentPortal ? "content-portal-early" : "benign-early");
            return found;
          }
        } catch { /* continue */ }
      }
      // 高密度版本表/资源站：主链无硬威胁则立即 light，跳过二级大扫描与持续 live 复扫
      if (archiveHeavy && !found && !titleHot && !state.downloadGuardInstalled
        && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._brandSpoofPortalDetected
        && !state._desktopForceDlKit && !state._remoteGarbleDlDetected && !state._indexNowPhishTemplate) {
        NS.silverfoxLog("scan-exit", "high-volume-archive-light");
        state._perfBenign = true;
        state._perfBenignAt = now;
        NS.markAnalysisComplete("high-volume-archive");
        return found;
      }
      if (!found && !titleHot && !state.downloadGuardInstalled && !state._pendingEncryptedSpa && !downloadShellSignals) {
        NS.silverfoxLog("scan-exit", "primary-clean", "titleHot=", titleHot);
        NS.markAnalysisComplete("primary-clean");
        return found;
      }

      // 品牌壳/主链已 arm：退出前再刷一遍禁用 + set-guard（防止 ICP 路径抢先 lift 后按钮复活）
      if (found && state.downloadGuardInstalled && (state._fakeBrandShellDetected || state._seoCloakKitDetected || state._desktopForceDlKit || state._fakeSpaDetected || state._indexNowPhishTemplate || state._remoteGarbleDlDetected || state._brandSpoofPortalDetected || state._brandResourceMismatchDetected || state._multiPlatformSerpTrap)) {
        try {
          NS.disableAllDownloadIntentControls();
          NS.postToHooks({ type: "set-guard", enabled: true });
          [100, 400, 1200, 3000].forEach((ms) => {
            setTimeout(() => {
              if (state.downloadGuardInstalled) {
                try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
              }
            }, ms);
          });
        } catch { /* ignore */ }
        NS.silverfoxLog("scan-exit", state._fakeBrandShellDetected ? "brand-shell-first" : "primary-threat-armed");
        NS.markAnalysisComplete("threat-found");
        return found;
      }

      if (!state._remoteApiChecked) {
        state._remoteApiChecked = true;
        if (NS.runDetector("RemoteDownloadApiBinding", NS.detectRemoteDownloadApiBinding)) {
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "远程动态下载";
        }
      }
      if (!state._fakeSpaDetected) {
        if (NS.runDetector("FakeOfficialDownloadSpa#2", NS.detectFakeOfficialDownloadSpa)) {
          state._fakeSpaDetected = true;
          state._pendingEncryptedSpa = false;
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载";
        } else if (NS.pageLooksLikePendingEncryptedDownloadSpa()) {
          state._pendingEncryptedSpa = true;
          NS.armEncryptedSpaLateRescan();
        }
      }

      if (!state._antiDebugChecked) { state._antiDebugChecked = true; NS.runDetector("AntiAnalysisBehavior", NS.detectAntiAnalysisBehavior); }
      if (!state._cloneOfficialDetected) {
        const cloneGap = now - (state._cloneScanAt || 0);
        if (!state._cloneScanAt || cloneGap >= 2500) {
          state._cloneScanAt = now;
          if (NS.runDetector("ClonedOfficialDownloadPage", NS.detectClonedOfficialDownloadPage)) { state._cloneOfficialDetected = true; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网克隆页"; }
        } else { NS.silverfoxLog("detect", "ClonedOfficialDownloadPage", "skip-throttle"); }
      }

      const embedded = NS.scanEmbeddedPackageThreats();
      if (embedded) { found = true; firstHref = firstHref || embedded; NS.addSignal("页面嵌入可疑安装包", 16, `源码/配置中发现可疑安装包: ${NS.formatPackageLabel(embedded)}`); }

      // 包扫描：只收集/禁用单链，不在此直接 arm；arm 前优先补跑品牌检测与品牌化 toast
      let pkgHitBrandNear = false;
      // 归档站大幅降采样，避免 200+ 行表格每次扫描卡顿
      if (!(archiveHeavy && !titleHot && !state._brandSpoofPortalDetected)) {
        const pkgSel = "a[href], a[data-href], a[data-url], a.download-btn, a.download-btn-nav, .download-btn, .download-btn-nav, .new-down, #mainDownloadBtn, button, .platform-btn, [onclick], [class*='download'], [class*='platform']";
        let pkgNodes;
        try { pkgNodes = document.querySelectorAll(pkgSel); } catch { pkgNodes = []; }
        const pkgLimit = Math.min(pkgNodes.length || 0, archiveHeavy ? 36 : 120);
        for (let pi = 0; pi < pkgLimit; pi++) {
          const el = pkgNodes[pi];
          const href = NS.getElementDownloadHref(el);
          if (!href || /^(javascript:|#)$/i.test(href)) continue;
          if (NS.looksLikeOfficialProductDownloadEndpoint(href)) continue;
          const fn = NS.getFilenameFromUrl(href);
          if (NS.isHrefSuspiciousPackageSync(href, el) || NS.looksLikeObjectStoragePackageUrl(href) || NS.looksLikeBrandNearMissPackageName(fn)) {
            found = true; if (!firstHref) firstHref = href;
            if (NS.looksLikeBrandNearMissPackageName(fn) || (typeof NS.packageMismatchesPageBrand === "function" && NS.packageMismatchesPageBrand(href))) pkgHitBrandNear = true;
            if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
            NS.disableOneSuspiciousElement(el, href);
            continue;
          }
          if (toProbe.length < 6 && NS.needsDownloadBehaviorProbe(href, el)) toProbe.push({ href, el });
        }

        if (!found) {
          try {
            const allPkgs = NS.collectAllPagePackageHrefs();
            const lim = Math.min(allPkgs.length, archiveHeavy ? 24 : 80);
            for (let i = 0; i < lim; i++) {
              const href = allPkgs[i];
              if (NS.looksLikeOfficialProductDownloadEndpoint(href)) continue;
              const fn = NS.getFilenameFromUrl(href);
              if (NS.looksLikeObjectStoragePackageUrl(href) || NS.looksLikeHighRiskBlobPackageUrl(href) || NS.looksLikeBrandNearMissPackageName(fn) || NS.isHrefSuspiciousPackageSync(href, null)) {
                found = true; firstHref = firstHref || href;
                if (NS.looksLikeBrandNearMissPackageName(fn)) pkgHitBrandNear = true;
                if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
                break;
              }
            }
          } catch { /* ignore */ }
        }
      }

      // 包已命中但品牌检测未 arm：补跑品牌门户，避免只出「DeepSeek_xxx.zip」弱提示
      if (found && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected && !state._fakeBrandShellDetected && (titleHot || pkgHitBrandNear || /官网|官方|下载/i.test(document.title || ""))) {
        try {
          if (!NS.hasValidIcpRecord() && NS.detectBrandSpoofDownloadPortal()) {
            state._brandSpoofPortalDetected = true;
          }
        } catch { /* ignore */ }
      }

      if (found && !state.downloadGuardInstalled) {
        const hrefForGuard = firstHref && (NS.isPackageFileUrl(firstHref) || /^https?:\/\//i.test(String(firstHref))) ? firstHref : "";
        const label = hrefForGuard ? (NS.formatPackageLabel(hrefForGuard) || hrefForGuard) : (firstHref && !/^https?:/i.test(String(firstHref)) ? String(firstHref) : "可疑安装包");
        const fnGuard = hrefForGuard ? NS.getFilenameFromUrl(hrefForGuard) : "";
        let brandTok = state.spoofBrand || "";
        if (!brandTok || (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(String(brandTok).toLowerCase()))) {
          try {
            // 中文产品名优先；禁止 CMS 词 Template/Aurora 进 toast
            const corr = NS.evaluateTitleHostBrandCorrelation();
            if (typeof NS.pickBrandDisplayName === "function") {
              brandTok = NS.pickBrandDisplayName({
                title: document.title || "",
                displayBrand: corr && corr.displayBrand,
                brandToken: (corr && corr.brandToken) || ""
              }) || "";
            } else {
              const primary = typeof NS.pickPrimaryTitleBrandToken === "function"
                ? NS.pickPrimaryTitleBrandToken(document.title || "", (location.hostname || "").split(".")[0] || "")
                : "";
              const raw = (corr && corr.displayBrand) || (primary && primary.length >= 5 ? primary : "") || (corr && corr.brandToken) || "";
              brandTok = typeof NS.formatBrandTokenForDisplay === "function" ? NS.formatBrandTokenForDisplay(raw) : raw;
            }
            if (brandTok && NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(String(brandTok).toLowerCase())) brandTok = "";
          } catch { /* ignore */ }
        }
        const brandish = pkgHitBrandNear || !!brandTok || titleHot || /官网|官方下载/i.test(document.title || "");
        if (brandish) {
          const noticeTitle = brandTok ? `已识别仿冒「${brandTok}」官网` : "已识别仿冒品牌官网下载";
          const noticeMsg = brandTok
            ? `域名 ${location.hostname} 与标题品牌「${brandTok}」不匹配，已拦截安装包 ${label}`
            : `页面宣称官方下载，但域名/安装包异常，已拦截 ${label}`;
          if (brandTok) state.spoofBrand = brandTok;
          try { NS.addSignal("仿冒品牌官网下载站", 20, noticeMsg); } catch { /* ignore */ }
          NS.installDownloadGuard(brandTok ? `仿冒品牌官网下载站（仿冒「${brandTok}」）: ${label}` : `仿冒品牌官网下载: ${label}`, {
            notify: true,
            href: hrefForGuard,
            message: noticeMsg,
            title: noticeTitle,
            forceNotify: true,
            guardKind: "brand-spoof",
            lockHard: true
          });
        } else {
          NS.installDownloadGuard(`已拦截可疑下载: ${label}`, {
            notify: true,
            href: hrefForGuard,
            message: `目标: ${label}`,
            title: "已拦截可疑安装包",
            forceNotify: true
          });
        }
        NS.disableAllDownloadIntentControls();
      } else if (found && state.downloadGuardInstalled) {
        // 品牌检测已 arm 时仍把包链禁用，并补强 toast（若先前只有弱通知则 force）
        NS.disableAllDownloadIntentControls();
        if (!state.protectionNoticeSent || state._brandSpoofPortalDetected || state._fakeBrandShellDetected) {
          try {
            const hrefForGuard = firstHref && (NS.isPackageFileUrl(firstHref) || /^https?:\/\//i.test(String(firstHref))) ? firstHref : "";
            const label = hrefForGuard ? (NS.formatPackageLabel(hrefForGuard) || hrefForGuard) : "";
            if (label && (state._brandSpoofPortalDetected || state._fakeBrandShellDetected || state.spoofBrand)) {
              const brandTok = state.spoofBrand || "";
              NS.showGuardOverlay(hrefForGuard, {
                title: brandTok ? `已识别仿冒「${brandTok}」官网` : "已识别仿冒品牌官网下载",
                message: brandTok ? `已拦截安装包 ${label}` : `已拦截 ${label}`,
                toast: true,
                forceNotify: true,
                guardKind: "brand-spoof"
              });
            }
          } catch { /* ignore */ }
        }
      }

      if (toProbe.length > 0 && !state.downloadGuardInstalled && !NS.shouldNeverArmProtection() && !NS.looksLikeMatureOfficialPortal() && !NS.looksLikeSafeOfficialContext()) {
        const unique = []; const seen = new Set();
        for (const item of toProbe.slice(0, 4)) {
          try { const abs = new URL(item.href, location.href).href; if (seen.has(abs)) continue; if (NS.isPackageFileUrl(abs)) continue; seen.add(abs); unique.push(item); } catch { /* ignore */ }
        }
        if (unique.length) {
          Promise.all(unique.map(async ({ href, el }) => { const result = await NS.probeDownloadBehavior(href); if (result && result.isDownload) { NS.applyConfirmedDownloadBlock(href, el, result); NS.disableAllDownloadIntentControls(); return true; } return false; })).then((results) => { if (results.some(Boolean)) { NS.disableSuspiciousDownloadButtons(); NS.disableAllDownloadIntentControls(); NS.emitRiskReport(true); } }).catch(() => {});
        }
      }

      // 主动 fetch 下载按钮上的地址（download.html 等），无需用户点击
      // 有 download.html / 下载 CTA 时必须 fetch：勿被 mature / 已 arm 首页 brand-spoof 挡掉
      const hasDlBtnTargets = typeof NS.pageHasProactiveDownloadButtonTargets === "function"
        && NS.pageHasProactiveDownloadButtonTargets();
      const titleWantsDl = /下载|download|客户端|安装|官网|官方/i.test(document.title || "")
        || /官网|官方下载|免费下载|客户端下载/i.test(String(document.querySelector('meta[name="keywords"]')?.getAttribute("content") || ""));
      const wantProbe = hasDlBtnTargets
        || found || titleHot || state._brandSpoofPortalDetected || state._pendingSoftBrandSpoof
        || titleWantsDl
        || (() => {
          try {
            return !!document.querySelector(".download-btn, .btn-download, .btn-header, a[href*='download'], a[href*='Download'], a[href*='download.html'], [class*='download']");
          } catch { return false; }
        })();
      if (wantProbe && !archiveHeavy
        && !(typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())
        && typeof NS.proactivelyProbeDownloadButtons === "function") {
        NS.silverfoxLog && NS.silverfoxLog("scan", "proactive-fetch-download-btns", "hasTargets=", hasDlBtnTargets, "guard=", !!state.downloadGuardInstalled);
        Promise.resolve()
          .then(() => NS.proactivelyProbeDownloadButtons({ force: true, reason: "scan-end" }))
          .then((hit) => { if (hit) { try { NS.emitRiskReport(true); } catch { /* ignore */ } } })
          .catch(() => {});
      }

      if (found) NS.markAnalysisComplete("threat-found");
      else if (NS.shouldDeferAnalysisCompleteForEncryptedSpa()) { state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan(); NS.emitRiskReport(true); }
      else if (!state._analysisDone) { state._pendingEncryptedSpa = false; NS.markAnalysisComplete("scan-clean"); }
      else NS.emitRiskReport(true);
      return found;
    } catch { return found; }
    finally { state._scanBusy = false; }
  };

  /** 实时观察 DOM 晚插入的下载按钮（SPA / 延迟 HTML）。 */
  NS.watchSuspiciousPackagesLive = function () {
    const state = NS.state;
    let scheduled = false; let liveObs = null; let stopped = false;
    let bulkTableNoise = 0;
    const shouldStopLive = () => {
      try {
        if (NS.pageLooksLikeSearchEngineResultsPage()) return true;
        if (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) return true;
        if (state._intelLightMode && state._analysisDone && !state.downloadGuardInstalled) return true;
        // 有效 ICP 且已完成：CSS/DOM 噪声不再连环扫
        if (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()
          && state._analysisDone && !state.downloadGuardInstalled
          && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())) return true;
        if (state._stickyComplete && state._analysisDone && !state.downloadGuardInstalled
          && !state._pendingEncryptedSpa) return true;
      } catch { /* ignore */ }
      return false;
    };
    const run = () => {
      scheduled = false;
      if (stopped) return;
      if (shouldStopLive()) { stopLiveWatch(); return; }
      const heavyList = (typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList())
        || (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())
        || (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive());
      if (heavyList && !state.downloadGuardInstalled && !state._pendingEncryptedSpa && !state._brandSpoofPortalDetected) {
        // 海量下载列表 / 归档站：最多一次 light 化后停表，禁止 MutationObserver 连环扫
        NS.scanSuspiciousPackagesFast(false);
        state._perfBenign = true;
        state._perfBenignAt = Date.now();
        stopLiveWatch();
        return;
      }
      if (state._pendingEncryptedSpa) { try { NS.invalidateHtmlCache(); } catch { /* ignore */ } }
      NS.scanSuspiciousPackagesFast(!!state._pendingEncryptedSpa);
      if (shouldStopLive() || (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa && document.readyState === "complete")) stopLiveWatch();
    };
    const kick = (delayMs) => {
      if (stopped || scheduled) return;
      if (shouldStopLive()) return;
      if (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) return;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return;
      scheduled = true;
      setTimeout(run, delayMs != null ? delayMs : 400);
    };
    const stopLiveWatch = () => { if (stopped) return; stopped = true; try { if (liveObs) liveObs.disconnect(); } catch { /* ignore */ } liveObs = null; };

    NS.armImmediatePackageBlock();

    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      state._perfBenign = true; state._perfBenignAt = Date.now();
      NS.scheduleIdle(() => { try { NS.scanSuspiciousPackagesFast(true); } catch { /* ignore */ } }, 800);
      return;
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => { if (NS.pageLooksLikeSearchEngineResultsPage()) { state._perfBenign = true; state._perfBenignAt = Date.now(); stopLiveWatch(); return; } NS.scanSuspiciousPackagesFast(); }, { once: true });
    } else { NS.scheduleIdle(() => NS.scanSuspiciousPackagesFast(), 600); }

    [200, 900, 1600].forEach((ms) => { setTimeout(() => { if (!stopped && !NS.pageLooksLikeSearchEngineResultsPage()) { if (state._pendingEncryptedSpa) { try { NS.invalidateHtmlCache(); } catch { /* ignore */ } NS.scanSuspiciousPackagesFast(true); } else NS.scanSuspiciousPackagesFast(); } }, ms); });

    try {
      liveObs = new MutationObserver((mutations) => {
        if (stopped) return;
        if (shouldStopLive()) { stopLiveWatch(); return; }
        if (state._perfBenign && !state._pendingEncryptedSpa) return;
        if (NS.pageLooksLikeSearchEngineResultsPage()) { stopLiveWatch(); return; }
        let interesting = false;
        let tableish = 0;
        for (const m of mutations) {
          // style/class/CSS 噪声：不触发全量复扫
          if (m.type === "attributes") {
            const an = String(m.attributeName || "").toLowerCase();
            if (an === "style" || an === "class" || an === "className") continue;
            if (an !== "href" && an !== "data-href" && an !== "src") continue;
            if (an === "href" || an === "data-href") {
              const t = m.target;
              try {
                const h = (t && t.getAttribute && (t.getAttribute("href") || t.getAttribute("data-href"))) || "";
                if (h && !/^(javascript:|#)$/i.test(h) && (/\.(apk|zip|exe|dmg|msi|rar|7z)(?:\?|#|$)/i.test(h) || /download|getdown|getfile/i.test(h))) {
                  interesting = true; break;
                }
              } catch { interesting = true; break; }
            }
            continue;
          }
          if (!m.addedNodes || !m.addedNodes.length) continue;
          for (let i = 0; i < m.addedNodes.length; i++) {
            const n = m.addedNodes[i];
            if (!n || n.nodeType !== 1) continue;
            const tag = (n.tagName || "").toUpperCase();
            // STYLE/LINK CSS / 文本节点类：不当「有趣」
            if (tag === "STYLE" || tag === "LINK" || tag === "META" || tag === "BR" || tag === "HR") continue;
            // 大表逐行插入：不当成「有趣变更」立即全扫
            if (tag === "TR" || tag === "TD" || tag === "TH" || tag === "TBODY" || tag === "THEAD"
              || tag === "SPAN" || tag === "I" || tag === "IMG" || tag === "FONT" || tag === "B" || tag === "SMALL") {
              tableish++;
              continue;
            }
            if (tag === "SCRIPT" || tag === "A" || tag === "BUTTON"
              || (n.id && /nuxt|app|root|next/i.test(n.id))
              || (n.className && /download|nuxt|platform-btn/i.test(String(n.className)))) {
              interesting = true; break;
            }
            if (state._pendingEncryptedSpa) { interesting = true; break; }
          }
          if (interesting) break;
        }
        if (interesting) { kick(450); return; }
        if (tableish > 0) {
          bulkTableNoise += tableish;
          // 版本表批量灌入：合并为一次延迟扫描，避免 400ms 连打
          if (bulkTableNoise >= 8) {
            bulkTableNoise = 0;
            kick(1200);
          }
        }
      });
      liveObs.observe(document.documentElement || document, { childList: true, subtree: true, attributes: true, attributeFilter: ["href", "data-href"] });
      // 归档站 6s 后停表；一般页 14s
      const stopMs = (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) ? 6000 : 14000;
      setTimeout(stopLiveWatch, stopMs);
    } catch { /* ignore */ }
  };
})(window.SilverfoxContent ??= {});
