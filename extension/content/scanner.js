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
      if (NS.pageLooksLikeLegitimateOfficialDownload() || NS.isTrustedOfficialDownloadContext()) { NS.clearDownloadGuard("guard-fp-official-cta"); NS.notifyHooksOfficialSafe(true); return false; }
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
    const titleHotEarly = /官网|官方下载|官方正版|官方网站/i.test(document.title || "");
    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      NS.silverfoxLog("scan-gate", "serp");
      state._lastFastScanAt = now; state._perfBenign = true; state._perfBenignAt = now; state._scanBusy = false;
      if (state.downloadGuardInstalled || state._earlyShellArmed || document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']")) { try { NS.clearDownloadGuard("serp-light-mode"); } catch { /* ignore */ } try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ } }
      NS.markAnalysisComplete("serp-scan");
      return false;
    }
    if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode) {
      NS.silverfoxLog("scan-gate", "ultra-mature-or-light");
      state._lastFastScanAt = now; state._scanBusy = false;
      NS.enterIntelLightMode("ultra-mature-whois-scan");
      state._brandSpoofPortalDetected = false; state.spoofBrand = "";
      NS.markAnalysisComplete("ultra-mature");
      return false;
    }
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) {
      NS.silverfoxLog("scan-gate", "mature-official");
      state._lastFastScanAt = now; state._scanBusy = false;
      NS.enterIntelLightMode("mature-official-scan");
      state._brandResourceMismatchDetected = false; state._brandSpoofPortalDetected = false;
      NS.markAnalysisComplete("mature-official");
      return false;
    }
    if (!force && state._perfBenign && !state.downloadGuardInstalled && !titleHotEarly && !state._fakeSpaDetected && now - (state._perfBenignAt || 0) < 12000 && now - (state._lastFastScanAt || 0) < 8000) { NS.silverfoxLog("scan-gate", "perf-benign-throttle"); NS.markAnalysisComplete("perf-benign-throttle"); return; }
    state._lastFastScanAt = now; state._scanBusy = true;
    NS.silverfoxLog("scan-start", "force=", force, "title=", (document.title || "").slice(0, 80));

    let found = false; let firstHref = "";
    const toProbe = [];
    try {
      if (force || !c._htmlCache || (Date.now() - c._htmlCacheAt > 4000)) NS.invalidateHtmlCache();
      const titleHot = /官网|官方下载|官方正版|官方网站/i.test(document.title || "") && !NS.looksLikeMatureOfficialPortal();

      if (!state._seoCloakKitDetected) { if (NS.runDetector("SeoCloakingRedirectKit", NS.detectSeoCloakingRedirectKit)) { found = true; firstHref = firstHref || "SEO伪装跳转"; } }
      if (!state._desktopForceDlKit) { if (NS.runDetector("DesktopForceDownloadKit", NS.detectDesktopForceDownloadKit)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "桌面端强制弹窗下载"; } }
      if (!state._remoteGarbleDlDetected) { if (NS.runDetector("RemoteGarblePackageDispatch", NS.detectRemoteGarblePackageDispatch)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "远程乱码安装包"; } }
      if (!state._indexNowPhishTemplate) { if (NS.runDetector("IndexNowSeoPhishTemplate", NS.detectIndexNowSeoPhishTemplate)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "SEO收录仿冒模板"; } }
      if (!state._multiPlatformSerpTrap) { if (NS.runDetector("MultiPlatformSerpDownloadTrap", NS.detectMultiPlatformSerpDownloadTrap)) { found = true; firstHref = firstHref || state.protectedTargets[0] || "多平台搜索引擎跳转"; } }
      if (!state._brandSpoofPortalDetected && !NS.hasValidIcpRecord()) { if (NS.runDetector("BrandSpoofDownloadPortal", NS.detectBrandSpoofDownloadPortal)) { state._brandSpoofPortalDetected = true; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载"; } }
      else if (NS.hasValidIcpRecord() && state._brandSpoofPortalDetected && !state._seoCloakKitDetected && !state._fakeSpaDetected) { NS.silverfoxLog("brand-spoof", "clear-by-icp"); NS.clearBrandSpoofFalsePositive("scan-icp-present"); }
      else if (NS.hasValidIcpRecord()) { NS.silverfoxLog("detect", "BrandSpoofDownloadPortal", "skip-valid-icp"); }
      if (!state._brandResourceMismatchDetected) { if (NS.runDetector("BrandResourceDomainMismatch", NS.detectBrandResourceDomainMismatch)) { state._brandResourceMismatchDetected = true; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网域名不一致"; } }
      if (!state._fakeSpaDetected) {
        if (NS.runDetector("FakeOfficialDownloadSpa", NS.detectFakeOfficialDownloadSpa)) { state._fakeSpaDetected = true; state._pendingEncryptedSpa = false; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载"; }
        else if (NS.pageLooksLikePendingEncryptedDownloadSpa()) { NS.silverfoxLog("encrypted-spa", "pending-hydrate"); state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan(); }
      }

      if (!found && !state.downloadGuardInstalled && !state._seoCloakKitDetected && !state._indexNowPhishTemplate && !state._fakeSpaDetected && !titleHot && !state._pendingEncryptedSpa) {
        try { if (document.body && NS.isBenignContentPage()) { NS.silverfoxLog("scan-exit", "benign-early"); state._perfBenign = true; state._perfBenignAt = now; NS.markAnalysisComplete("benign-early"); return found; } } catch { /* continue */ }
      }
      if (!found && !titleHot && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) { NS.silverfoxLog("scan-exit", "primary-clean", "titleHot=", titleHot); NS.markAnalysisComplete("primary-clean"); return found; }
      if (found && state.downloadGuardInstalled && (state._seoCloakKitDetected || state._desktopForceDlKit || state._fakeSpaDetected || state._indexNowPhishTemplate || state._remoteGarbleDlDetected || state._brandSpoofPortalDetected || state._brandResourceMismatchDetected || state._multiPlatformSerpTrap)) { NS.silverfoxLog("scan-exit", "primary-threat-armed"); NS.markAnalysisComplete("threat-found"); return found; }

      if (!state._remoteApiChecked) { state._remoteApiChecked = true; NS.runDetector("RemoteDownloadApiBinding", NS.detectRemoteDownloadApiBinding); }
      if (!state._antiDebugChecked) { state._antiDebugChecked = true; NS.runDetector("AntiAnalysisBehavior", NS.detectAntiAnalysisBehavior); }
      if (!state._fakeSpaDetected) {
        if (NS.runDetector("FakeOfficialDownloadSpa#2", NS.detectFakeOfficialDownloadSpa)) { state._fakeSpaDetected = true; state._pendingEncryptedSpa = false; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载"; }
        else if (NS.pageLooksLikePendingEncryptedDownloadSpa()) { state._pendingEncryptedSpa = true; NS.armEncryptedSpaLateRescan(); }
      }
      if (!state._fakeBrandShellDetected) { if (NS.runDetector("FakeBrandDownloadShell", NS.detectFakeBrandDownloadShell)) { state._fakeBrandShellDetected = true; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒品牌下载"; } }
      if (!state._cloneOfficialDetected) {
        const cloneGap = now - (state._cloneScanAt || 0);
        if (!state._cloneScanAt || cloneGap >= 2500) {
          state._cloneScanAt = now;
          if (NS.runDetector("ClonedOfficialDownloadPage", NS.detectClonedOfficialDownloadPage)) { state._cloneOfficialDetected = true; found = true; firstHref = firstHref || state.protectedTargets[0] || "仿冒官网克隆页"; }
        } else { NS.silverfoxLog("detect", "ClonedOfficialDownloadPage", "skip-throttle"); }
      }

      const embedded = NS.scanEmbeddedPackageThreats();
      if (embedded) { found = true; firstHref = firstHref || embedded; NS.addSignal("页面嵌入可疑安装包", 16, `源码/配置中发现可疑安装包: ${NS.formatPackageLabel(embedded)}`); }

      const pkgSel = "a[href], a[data-href], a[data-url], a.download-btn, a.download-btn-nav, .download-btn, .download-btn-nav, .new-down, #mainDownloadBtn, button, .platform-btn, [onclick], [class*='download'], [class*='platform']";
      let pkgNodes;
      try { pkgNodes = document.querySelectorAll(pkgSel); } catch { pkgNodes = []; }
      const pkgLimit = Math.min(pkgNodes.length || 0, 120);
      for (let pi = 0; pi < pkgLimit; pi++) {
        const el = pkgNodes[pi];
        const href = NS.getElementDownloadHref(el);
        if (!href || /^(javascript:|#)$/i.test(href)) continue;
        if (NS.looksLikeOfficialProductDownloadEndpoint(href)) continue;
        if (NS.isHrefSuspiciousPackageSync(href, el) || NS.looksLikeObjectStoragePackageUrl(href) || NS.looksLikeBrandNearMissPackageName(NS.getFilenameFromUrl(href))) {
          found = true; if (!firstHref) firstHref = href;
          if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
          NS.disableOneSuspiciousElement(el, href);
          continue;
        }
        if (toProbe.length < 6 && NS.needsDownloadBehaviorProbe(href, el)) toProbe.push({ href, el });
      }

      if (!found) {
        try {
          for (const href of NS.collectAllPagePackageHrefs()) {
            if (NS.looksLikeOfficialProductDownloadEndpoint(href)) continue;
            if (NS.looksLikeObjectStoragePackageUrl(href) || NS.looksLikeHighRiskBlobPackageUrl(href) || NS.looksLikeBrandNearMissPackageName(NS.getFilenameFromUrl(href)) || NS.isHrefSuspiciousPackageSync(href, null)) {
              found = true; firstHref = firstHref || href;
              if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
              break;
            }
          }
        } catch { /* ignore */ }
      }

      if (found && !state.downloadGuardInstalled) {
        const hrefForGuard = firstHref && (NS.isPackageFileUrl(firstHref) || /^https?:\/\//i.test(String(firstHref))) ? firstHref : "";
        const label = hrefForGuard ? (NS.formatPackageLabel(hrefForGuard) || hrefForGuard) : (firstHref && !/^https?:/i.test(String(firstHref)) ? String(firstHref) : "可疑安装包");
        NS.installDownloadGuard(`已拦截可疑下载: ${label}`, { notify: true, href: hrefForGuard, message: label, forceNotify: !state.protectionNoticeSent });
        NS.disableAllDownloadIntentControls();
      } else if (found && state.downloadGuardInstalled) { NS.disableAllDownloadIntentControls(); }

      if (toProbe.length > 0 && !state.downloadGuardInstalled && !NS.shouldNeverArmProtection() && !NS.looksLikeMatureOfficialPortal() && !NS.looksLikeSafeOfficialContext()) {
        const unique = []; const seen = new Set();
        for (const item of toProbe.slice(0, 3)) {
          try { const abs = new URL(item.href, location.href).href; if (seen.has(abs)) continue; if (NS.isPackageFileUrl(abs)) continue; seen.add(abs); unique.push(item); } catch { /* ignore */ }
        }
        if (unique.length) {
          Promise.all(unique.map(async ({ href, el }) => { const result = await NS.probeDownloadBehavior(href); if (result && result.isDownload) { NS.applyConfirmedDownloadBlock(href, el, result); NS.disableAllDownloadIntentControls(); return true; } return false; })).then((results) => { if (results.some(Boolean)) { NS.disableSuspiciousDownloadButtons(); NS.disableAllDownloadIntentControls(); NS.emitRiskReport(true); } }).catch(() => {});
        }
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
    const run = () => {
      scheduled = false;
      if (stopped) return;
      if (NS.pageLooksLikeSearchEngineResultsPage() || (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa)) { stopLiveWatch(); return; }
      if (state._pendingEncryptedSpa) { try { NS.invalidateHtmlCache(); } catch { /* ignore */ } }
      NS.scanSuspiciousPackagesFast(!!state._pendingEncryptedSpa);
      if (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa && document.readyState === "complete") stopLiveWatch();
    };
    const kick = () => {
      if (stopped || scheduled) return;
      if (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) return;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return;
      scheduled = true;
      setTimeout(run, 400);
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
        if (state._perfBenign && !state._pendingEncryptedSpa) return;
        if (NS.pageLooksLikeSearchEngineResultsPage()) { stopLiveWatch(); return; }
        for (const m of mutations) {
          if (m.type === "attributes" && (m.attributeName === "href" || m.attributeName === "data-href")) { kick(); return; }
          if (m.addedNodes && m.addedNodes.length) {
            for (let i = 0; i < m.addedNodes.length; i++) {
              const n = m.addedNodes[i];
              if (!n || n.nodeType !== 1) continue;
              const tag = (n.tagName || "").toUpperCase();
              if (tag === "SCRIPT" || tag === "A" || tag === "BUTTON" || (n.id && /nuxt|app|root|next/i.test(n.id)) || (n.className && /download|nuxt/i.test(String(n.className)))) { kick(); return; }
              if (state._pendingEncryptedSpa) { kick(); return; }
              kick(); return;
            }
          }
        }
      });
      liveObs.observe(document.documentElement || document, { childList: true, subtree: true, attributes: true, attributeFilter: ["href", "data-href"] });
      setTimeout(stopLiveWatch, 14000);
    } catch { /* ignore */ }
  };
})(window.SilverfoxContent ??= {});
