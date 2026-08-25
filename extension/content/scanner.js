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

  function hasActiveClickProtection(state) {
    try {
      return !!((state && state.downloadGuardInstalled)
        || (state && Array.isArray(state.protectedTargets) && state.protectedTargets.length > 0)
        || (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())
        || (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()));
    } catch {
      return true;
    }
  }

  /**
   * Bootstrap/ARIA disclosure controls only open local UI.  A label such as
   * "download game" must not turn a modal trigger into a network download.
   */
  NS.isDeclarativeDisclosureControl = function (element) {
    try {
      if (!element || hasActiveClickProtection(NS.state)) return false;
      const toggle = String(element.getAttribute("data-bs-toggle")
        || element.getAttribute("data-toggle") || "").trim().toLowerCase();
      if (!/^(?:modal|collapse|offcanvas|dropdown|tab|pill)$/.test(toggle)) return false;
      if (element.hasAttribute("download") || element.hasAttribute("data-download")
        || element.hasAttribute("data-down")) return false;
      const href = String(element.getAttribute("href") || element.getAttribute("data-href")
        || element.getAttribute("data-url") || "").trim();
      if (href && !href.startsWith("#")) return false;
      const handler = `${element.getAttribute("onclick") || ""} ${element.getAttribute("onmousedown") || ""}`;
      if (/window\.open|location\s*[.=]|fetch\s*\(|download|\.click\s*\(/i.test(handler)) return false;
      return true;
    } catch {
      return false;
    }
  };

  /**
   * Version archives often label an ordinary same-origin detail link as
   * "download".  Let the browser perform that document navigation without
   * running page-wide brand/identity scans in the capture handler.  Actual
   * files, opaque hops, query-driven attachments and guarded pages stay on
   * the normal protection path.
   */
  NS.isPlainSameOriginDocumentNavigation = function (element, rawHref) {
    try {
      if (!element || String(element.tagName || "").toUpperCase() !== "A") return false;
      if (hasActiveClickProtection(NS.state)) return false;
      if (element.hasAttribute("download") || element.hasAttribute("data-download")
        || element.hasAttribute("data-down")) return false;
      const href = String(rawHref || "").trim();
      if (!href || /^(?:javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
      const handler = `${element.getAttribute("onclick") || ""} ${element.getAttribute("onmousedown") || ""}`;
      if (/window\.open|location\s*[.=]|fetch\s*\(|download|\.click\s*\(/i.test(handler)) return false;
      const u = new URL(href, location.href);
      if (!/^https?:$/i.test(u.protocol) || u.origin !== location.origin) return false;
      if (NS.isPackageFileUrl(u.href) || NS.looksLikeOpaqueDownloadHopUrl(u.href)) return false;
      if (/[?&](?:download|attachment|file(?:name)?|downurl|downloadurl|target|token|sig(?:nature)?|expires)=/i.test(u.search)) return false;
      const path = String(u.pathname || "/").toLowerCase();
      if (/\.(?:exe|msi|msix|dmg|pkg|apk|xapk|apks|zip|rar|7z|iso|bin)$/i.test(path)) return false;
      const last = path.split("/").filter(Boolean).pop() || "";
      const htmlDocument = /\.html?$/.test(last);
      const detailRoute = /(?:^|\/)(?:info|details?|versions?|releases?|changelog)(?:\/|$)/i.test(path);
      const versionListContext = htmlDocument && typeof element.closest === "function"
        && !!element.closest("table, tbody, [class*='version'], [id*='version'], [class*='release'], [id*='release']");
      return detailRoute || versionListContext;
    } catch {
      return false;
    }
  };

  NS.isActualDownloadHandoff = function (element, href) {
    try {
      if (NS.isDeclarativeDisclosureControl(element)) return false;
      if (element && (element.hasAttribute("download") || element.hasAttribute("data-download")
        || element.hasAttribute("data-down"))) return true;
      const raw = String(href || "").trim();
      if (!raw || /^(?:javascript:|#)$/i.test(raw)) return !!(element && NS.isDownloadIntentElement(element));
      if (NS.isPackageFileUrl(raw) || NS.looksLikeOpaqueDownloadHopUrl(raw)
        || NS.looksLikeOfficialProductDownloadEndpoint(raw)) return true;
      const u = new URL(raw, location.href);
      if (u.origin === location.origin) return false;
      const downloadContext = element && typeof element.closest === "function"
        && element.closest(".download-item, .download-action, .modal, [role='dialog'], [class*='download'], [id*='download']");
      return !!downloadContext || !!(element && NS.isDownloadIntentElement(element));
    } catch {
      return false;
    }
  };

  /**
   * A clean-looking /download route is only a performance hint. Until the
   * current URL has completed the authoritative identity decision, it must
   * not inherit any of the normal "official download" click allow-lists.
   */
  NS.isProvisionalDownloadIdentityPending = function () {
    try {
      const state = NS.state;
      const urlKey = String(location.href || "");
      if (!state._provisionalDownloadIdentityHold
        || state._provisionalDownloadIdentityUrl !== urlKey) return false;
      // 真硬风险必须进入正式 guard 文案，不能被“正在核验”遮住。
      if ((typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())
        || (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked())
        || state.downloadGuardInstalled
        || (Array.isArray(state.protectedTargets) && state.protectedTargets.length > 0)) return false;
      if (state._trustedBrandIdentityUrl === urlKey) return false;
      // A background tab may have received ICP/SSL callbacks while its polling
      // timer was frozen.  The activation itself is an event-driven wake-up;
      // settle first, then decide whether a hold still exists.
      if (typeof NS.nudgeProvisionalDownloadSettlement === "function") {
        try { NS.nudgeProvisionalDownloadSettlement("download-click"); } catch { /* ignore */ }
      }
      // 绝对截止时间到达时同步唤醒收口。Edge 后台标签可能冻结 timer，
      // 但用户恢复页面并点击时不能继续使用已经过期的等待锁。
      if (Number(state._provisionalDownloadIdentityDeadlineAt || 0) > 0
        && Date.now() >= Number(state._provisionalDownloadIdentityDeadlineAt || 0)
        && typeof NS.nudgeProvisionalDownloadSettlement === "function") {
        try { NS.nudgeProvisionalDownloadSettlement("download-click-deadline"); } catch { /* ignore */ }
      }
      if (!state._provisionalDownloadIdentityHold
        || state._provisionalDownloadIdentityUrl !== urlKey) return false;
      return true;
    } catch { return false; }
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
    const state = NS.state;
    const directHref = (element.getAttribute && (element.getAttribute("href")
      || element.getAttribute("data-href") || element.getAttribute("data-url"))) || "";
    // These two decisions use attributes only.  They must run before
    // getElementDownloadHref(), whose hrefless fallback scans scripts/HTML.
    if (NS.isDeclarativeDisclosureControl(element)) return false;
    if (NS.isPlainSameOriginDocumentNavigation(element, directHref)) return false;
    const href = NS.getElementDownloadHref(element) || directHref || "";
    // Scan quiet is never a download allow-list. Only the user's actual
    // download activation is held while identity sources are settling.
    if (typeof NS.isProvisionalDownloadIdentityPending === "function"
      && NS.isProvisionalDownloadIdentityPending()
      && NS.isActualDownloadHandoff(element, href)) {
      event.preventDefault();
      event.stopImmediatePropagation();
      event.stopPropagation();
      try {
        NS.showPageToast(
          "正在核验下载来源",
          "网站身份尚未核验完成，请稍候后重试下载。",
          { force: false }
        );
      } catch { /* ignore */ }
      return true;
    }
    // 仿冒 download.html（夹带域 / 下载 CTA→必应）不得走正站点击放行
    const rejectOfficialDlShortcut = typeof NS.shouldRejectOfficialDownloadShortcut === "function"
      && NS.shouldRejectOfficialDownloadShortcut();
    if (!rejectOfficialDlShortcut
      && (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal() || NS.pageLooksLikeLegitimateOfficialDownload())) {
      // 硬套件已命中时禁止点击路径清 guard
      if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) {
        try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
        return true;
      }
      if (state.downloadGuardInstalled || (state.protectedTargets && state.protectedTargets.length) || document.querySelector("[data-threat-detector-disabled='1']")) { NS.clearDownloadGuard("official-portal-click"); NS.notifyHooksOfficialSafe(true); }
      return false;
    }
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
    if (!rejectOfficialDlShortcut && NS.isTrustedOfficialDownloadContext() && href && NS.isSamePageBrandApex(href)) return false;
    if (!rejectOfficialDlShortcut && NS.looksLikeSafeOfficialContext() && href && !NS.looksLikeHighRiskBlobPackageUrl(href) && !NS.isAnonymousPublicObjectHost((() => { try { return new URL(href, location.href).hostname; } catch { return ""; } })())) return false;
    if (href && NS.isSamePageBrandApex(href) && !NS.looksLikeOpaqueDownloadHopUrl(href) && !NS.isPackageFileUrl(href)) {
      try { const path = new URL(href, location.href).pathname.toLowerCase().replace(/\/+$/, "") || "/"; if (/^\/(?:win|windows|mac|osx|macos|linux|android|ios|pc|download|downloads)(?:\/|$)/i.test(path)) return false; } catch { /* ignore */ }
    }
    if ((state.downloadGuardInstalled || state.protectedTargets.length > 0) && NS.isDownloadIntentElement(element)) {
      if (href && (NS.looksLikeOfficialProductDownloadEndpoint(href) || (NS.isSamePageBrandApex(href) && !NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href)))) return false;
      if (!rejectOfficialDlShortcut
        && (NS.pageLooksLikeLegitimateOfficialDownload() || NS.isTrustedOfficialDownloadContext())) {
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

  NS.isOfficialDownloadScanQuiet = function () {
    try {
      const state = NS.state;
      return !!(state._officialDownloadScanQuiet
        && state._officialDownloadScanQuietUrl === String(location.href || "")
        && !state.downloadGuardInstalled
        && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()));
    } catch { return false; }
  };

  NS.enterOfficialDownloadScanQuiet = function (reason) {
    try {
      const state = NS.state;
      if (state.downloadGuardInstalled) return false;
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return false;
      state._officialDownloadScanQuiet = true;
      state._officialDownloadScanQuietUrl = String(location.href || "");
      state._officialDownloadForceScanAllowed = false;
      state._pendingEncryptedSpa = false;
      try {
        const stopLive = NS.caches && NS.caches._stopSuspiciousLiveWatch;
        if (typeof stopLive === "function") stopLive();
      } catch { /* ignore */ }
      NS.silverfoxLog && NS.silverfoxLog("scan-quiet", reason || "official-download-surface");
      return true;
    } catch { return false; }
  };

  NS.armImmediatePackageBlock = function () {
    const state = NS.state;
    if (immediateBlockArmed) return;
    // Do not mark the listener as installed when a light/search state merely
    // skips this attempt. A same-tab SPA may later navigate to a route that
    // genuinely needs the provisional click guard.
    if (state._intelLightMode || state._perfBenign || NS.isSearchUrlShapeOnly() || NS.pageLooksLikeSearchEngineResultsPage()) return;
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

  NS.getDownloadProbePageContext = function () {
    const c = NS.caches || {};
    const urlKey = String(location.href || "");
    const now = Date.now();
    if (c._downloadProbePageContext && c._downloadProbePageContextUrl === urlKey
      && now - Number(c._downloadProbePageContextAt || 0) < 800) {
      return c._downloadProbePageContext;
    }
    const ctx = {
      search: false, neverArm: false, mature: false,
      safeOfficial: false, trustedDownload: false, hostSpoof: false
    };
    try { ctx.search = !!NS.pageLooksLikeSearchEngineResultsPage(); } catch { /* ignore */ }
    try { ctx.neverArm = !!NS.shouldNeverArmProtection(); } catch { /* ignore */ }
    try { ctx.mature = !!NS.looksLikeMatureOfficialPortal(); } catch { /* ignore */ }
    try { ctx.hostSpoof = !!NS.hostLooksLikeBrandMarketingSpoof(); } catch { /* ignore */ }
    try { ctx.safeOfficial = !!NS.looksLikeSafeOfficialContext(); } catch { /* ignore */ }
    try { ctx.trustedDownload = !!NS.isTrustedOfficialDownloadContext(); } catch { /* ignore */ }
    c._downloadProbePageContext = ctx;
    c._downloadProbePageContextUrl = urlKey;
    c._downloadProbePageContextAt = now;
    return ctx;
  };

  NS.needsDownloadBehaviorProbe = function (href, element) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    const pageCtx = typeof NS.getDownloadProbePageContext === "function"
      ? NS.getDownloadProbePageContext() : null;
    if (pageCtx ? pageCtx.search : NS.pageLooksLikeSearchEngineResultsPage()) return false;
    if (NS.isPackageFileUrl(href)) return false;
    try { const u = new URL(href, location.href); if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(u.pathname + u.search)) return false; } catch { /* ignore */ }
    if (pageCtx ? (pageCtx.neverArm || pageCtx.mature) : (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal())) return false;
    const hostSpoof = pageCtx ? pageCtx.hostSpoof : NS.hostLooksLikeBrandMarketingSpoof();
    if ((pageCtx ? pageCtx.safeOfficial : NS.looksLikeSafeOfficialContext()) && !hostSpoof) return false;
    if (hostSpoof) {
      try { const u = new URL(href, location.href); const base = (u.pathname.split("/").pop() || "").toLowerCase(); if (/^(?:download|down|getdown)\.(?:php|asp|aspx)$/i.test(base)) return true; if (!NS.isSamePageBrandApex(href)) return true; } catch { /* ignore */ }
    }
    if (NS.looksLikeOfficialProductDownloadEndpoint(href, hostSpoof)) return false;
    if ((pageCtx ? pageCtx.trustedDownload : NS.isTrustedOfficialDownloadContext()) && NS.isSamePageBrandApex(href)) return false;
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
  NS.scanSuspiciousPackagesFast = function (force = false, scanOptions = null) {
    const state = NS.state;
    const c = NS.caches;
    const lateExplicitEvidence = !!(scanOptions && scanOptions.lateExplicitEvidence === true);
    if (!NS.isHttpOrHttpsPage()) { NS.silverfoxLog("scan-skip", "non-http-protocol"); return false; }
    const now = Date.now();
    if (typeof NS.isOfficialDownloadScanQuiet === "function" && NS.isOfficialDownloadScanQuiet()
      && !state._officialDownloadForceScanAllowed && !lateExplicitEvidence) {
      NS.silverfoxLog("scan-skip", "official-download-quiet");
      return false;
    }
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
    if (!lateExplicitEvidence && archiveHeavy && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected && !titleHotEarly) {
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
    } else if (!lateExplicitEvidence && (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()
      || (state._intelLightMode && !(typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity())))) {
      NS.silverfoxLog("scan-gate", "ultra-mature-or-light");
      state._lastFastScanAt = now; state._scanBusy = false;
      NS.enterIntelLightMode("ultra-mature-whois-scan");
      if (!(typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked())) {
        state._brandSpoofPortalDetected = false; state.spoofBrand = "";
      }
      NS.markAnalysisComplete("ultra-mature");
      return false;
    } else if (!lateExplicitEvidence && (
      NS.shouldNeverArmProtection()
      || NS.looksLikeMatureOfficialPortal()
    )) {
      // 正站下载中心（dingtalk.com/download 等）本身就有大量下载按钮——
      // 旧逻辑仍跑完整仿冒/选举链，会把页面卡死。
      // 仅当主机是营销夹带/squat 时才继续重扫；干净根 + 正站下载页直接 light。
      const spoofHost = (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof())
        || (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function" && (() => {
          try {
            const ap = typeof NS.getRegistrableDomain === "function"
              ? NS.getRegistrableDomain(location.hostname) : location.hostname;
            return NS.apexLabelLooksLikeMarketingPaddedBrand((String(ap || "").split(".")[0] || ""));
          } catch { return false; }
        })());
      // 干净 /download 只作佐证，必须通过成熟正规站组合门才能 light。
      const cleanDlPath = typeof NS.looksLikeCleanOfficialDownloadHostPath === "function"
        && NS.looksLikeCleanOfficialDownloadHostPath()
        && typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        && NS.evaluateMatureLegitimateSiteProfile().trusted;
      if (!spoofHost || cleanDlPath) {
        NS.silverfoxLog("scan-gate", "mature-official-or-legit-download");
        state._lastFastScanAt = now; state._scanBusy = false;
        NS.enterIntelLightMode("mature-official-scan");
        if (!(typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked())) {
          state._brandResourceMismatchDetected = false; state._brandSpoofPortalDetected = false;
        }
        // 仍保留点击级拦截；不做 MutationObserver 连环全页扫描
        try { NS.armImmediatePackageBlock(); } catch { /* ignore */ }
        NS.markAnalysisComplete("mature-official");
        return false;
      }
      NS.silverfoxLog("scan-gate", "mature-but-spoof-host");
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
      // 仿冒官网：快速路径可先形成候选；最终状态/提示由官网身份核验门控统一定稿。
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
      const strongIdentity = typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity();
      if (isTop && !state._brandSpoofPortalDetected && !strongIdentity) {
        if (NS.runDetector("BrandSpoofDownloadPortal", NS.detectBrandSpoofDownloadPortal)) {
          state._brandSpoofPortalDetected = true;
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "仿冒官网下载";
        }
      } else if (isTop && strongIdentity && state._brandSpoofPortalDetected
        && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._fakeBrandShellDetected) {
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
      } else if (strongIdentity && !state._brandSpoofPortalDetected) {
        NS.silverfoxLog("detect", "BrandSpoofDownloadPortal", "skip-strong-identity");
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
      // 导航「下载」→ /download.html（汽水仿冒首页）必须算下载壳，否则 primary-clean 提前退出、永不主动 fetch
      let hasDownloadLandingNav = false;
      if (!downloadShellSignals && !contentPortal) {
        try {
          if (document.querySelector(
            ".download-btn, .download-btn-nav, #mainDownloadBtn, a.download-uri, .download-uri, "
            + "[class*='btn-download'], .platform-btn, button.btn-download, "
            + "a[href*='download.html'], a[href*='down.html'], a[href*='install.html']"
          )) downloadShellSignals = true;
          else if (/download_uri|GLOBAL_DOWNLOAD_URL|api\.php|windowsDownload|macDownload|fetchDownloadLink|download_link|getdown|getlink|initDownloadLinks/i.test(NS.getHtmlSlice(16000) || "")) {
            downloadShellSignals = true;
          } else {
            const nodes = document.querySelectorAll("a, button, [role='button']");
            const lim = Math.min(nodes.length || 0, 48);
            for (let i = 0; i < lim; i++) {
              const el = nodes[i];
              const tx = (el.textContent || "").replace(/\s+/g, " ").trim();
              const hr = (el.getAttribute && (el.getAttribute("href") || el.getAttribute("data-href"))) || "";
              // 仅强下载话术；裸「下载」在资讯页太常见——但 href 指向 download.html 必须认
              if (/download\.html|down\.html|install\.html|(?:^|\/)download(?:\/|$)/i.test(hr)) {
                downloadShellSignals = true;
                hasDownloadLandingNav = true;
                break;
              }
              if (/立即下载|免费下载|官方下载|客户端下载|安装包|云电脑下载|下载中心/i.test(tx) && tx.length <= 40) {
                downloadShellSignals = true; break;
              }
            }
          }
          if (document.querySelector("a[href*='download.html'], a[href*='down.html']")) {
            hasDownloadLandingNav = true;
            downloadShellSignals = true;
          }
        } catch { /* ignore */ }
      } else {
        try {
          hasDownloadLandingNav = !!document.querySelector("a[href*='download.html'], a[href*='down.html']");
        } catch { /* ignore */ }
      }

      if (!lateExplicitEvidence && !found && !state.downloadGuardInstalled && !state._seoCloakKitDetected && !state._indexNowPhishTemplate && !state._fakeSpaDetected && !titleHot && !state._pendingEncryptedSpa
        && (!downloadShellSignals || contentPortal) && !hasDownloadLandingNav) {
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
      if (!lateExplicitEvidence && archiveHeavy && !found && !titleHot && !state.downloadGuardInstalled
        && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._brandSpoofPortalDetected
        && !state._desktopForceDlKit && !state._remoteGarbleDlDetected && !state._indexNowPhishTemplate
        && !hasDownloadLandingNav) {
        NS.silverfoxLog("scan-exit", "high-volume-archive-light");
        state._perfBenign = true;
        state._perfBenignAt = now;
        NS.markAnalysisComplete("high-volume-archive");
        return found;
      }
      // 有 download.html 导航时绝不可 primary-clean 提前退出（否则永不主动 fetch）
      if (!lateExplicitEvidence && !found && !titleHot && !state.downloadGuardInstalled && !state._pendingEncryptedSpa
        && !downloadShellSignals && !hasDownloadLandingNav) {
        NS.silverfoxLog("scan-exit", "primary-clean", "titleHot=", titleHot);
        NS.markAnalysisComplete("primary-clean");
        return found;
      }

      // 多平台 GLOBAL_DOWNLOAD_URL / 远程绑定：尽早命中（勿等二级链 / primary-clean 之后）
      if (!state._remoteApiChecked) {
        state._remoteApiChecked = true;
        if (NS.runDetector("RemoteDownloadApiBinding", NS.detectRemoteDownloadApiBinding)) {
          found = true;
          firstHref = firstHref || state.protectedTargets[0] || "远程动态下载";
        }
      }

      // 品牌壳/主链已 arm：退出前再刷一遍禁用 + set-guard；仍异步 fetch download.html 补包链
      if (found && state.downloadGuardInstalled && (state._fakeBrandShellDetected || state._seoCloakKitDetected || state._desktopForceDlKit || state._fakeSpaDetected || state._indexNowPhishTemplate || state._remoteGarbleDlDetected || state._brandSpoofPortalDetected || state._brandResourceMismatchDetected || state._multiPlatformSerpTrap || state.remoteDownloadDispatchDetected)) {
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
        // 主链已 arm 时旧逻辑直接 return，导致 nav「下载」→ download.html 永不 fetch
        if (hasDownloadLandingNav || (typeof NS.pageHasProactiveDownloadButtonTargets === "function"
          && NS.pageHasProactiveDownloadButtonTargets())) {
          try {
            if (typeof NS.proactivelyProbeDownloadButtons === "function") {
              Promise.resolve()
                .then(() => NS.proactivelyProbeDownloadButtons({ force: true, reason: "primary-armed-still-fetch-landing" }))
                .then((hit) => { if (hit) try { NS.emitRiskReport(true); } catch { /* ignore */ } })
                .catch(() => {});
            }
          } catch { /* ignore */ }
        }
        NS.silverfoxLog("scan-exit", state._fakeBrandShellDetected ? "brand-shell-first" : "primary-threat-armed");
        NS.markAnalysisComplete("threat-found");
        return found;
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
      if (lateExplicitEvidence || !(archiveHeavy && !titleHot && !state._brandSpoofPortalDetected)) {
        const pkgSel = "a[href], a[data-href], a[data-url], a.download-btn, a.download-btn-nav, .download-btn, .download-btn-nav, .new-down, #mainDownloadBtn, button, .platform-btn, [onclick], [class*='download'], [class*='platform']";
        let pkgNodes;
        try { pkgNodes = document.querySelectorAll(pkgSel); } catch { pkgNodes = []; }
        const pkgLimit = Math.min(pkgNodes.length || 0, archiveHeavy ? 36 : 120);
        const scanPageCtx = typeof NS.getDownloadProbePageContext === "function"
          ? NS.getDownloadProbePageContext() : null;
        const endpointCache = new Map();
        const officialEndpoint = (href) => {
          const key = String(href || "");
          if (endpointCache.has(key)) return endpointCache.get(key);
          const value = NS.looksLikeOfficialProductDownloadEndpoint(
            key, scanPageCtx ? scanPageCtx.hostSpoof : undefined
          );
          endpointCache.set(key, value);
          return value;
        };
        for (let pi = 0; pi < pkgLimit; pi++) {
          const el = pkgNodes[pi];
          const directHref = String((el.getAttribute && (
            el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-url")
            || el.getAttribute("data-download") || el.getAttribute("data-down") || ""
          )) || "").trim();
          const tag = String(el.tagName || "").toUpperCase();
          if (tag === "A") {
            const hint = `${String(el.className || "")} ${String(el.id || "")} ${String(el.textContent || "").slice(0, 80)}`;
            const relevant = !!(directHref && (NS.isPackageFileUrl(directHref)
              || /(?:download|down|install|setup|client|package|\.exe|\.msi|\.zip|\.rar|\.7z|\.apk|\.dmg)/i.test(directHref)))
              || /download|down|install|setup|platform|Windows|macOS|Android|iOS|下载|安装|客户端/i.test(hint)
              || !!(el.hasAttribute && (el.hasAttribute("onclick") || el.hasAttribute("onmousedown") || el.hasAttribute("ondblclick")));
            if (!relevant) continue;
          }
          const href = NS.getElementDownloadHref(el);
          if (!href || /^(javascript:|#)$/i.test(href)) continue;
          if (officialEndpoint(href)) continue;
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
              if (officialEndpoint(href)) continue;
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
          if (!(typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity())
            && NS.detectBrandSpoofDownloadPortal()) {
            state._brandSpoofPortalDetected = true;
          }
        } catch { /* ignore */ }
      }

      if (found && !state.downloadGuardInstalled) {
        const hrefForGuard = firstHref && (NS.isPackageFileUrl(firstHref) || /^https?:\/\//i.test(String(firstHref))) ? firstHref : "";
        const label = hrefForGuard ? (NS.formatPackageLabel(hrefForGuard) || hrefForGuard) : (firstHref && !/^https?:/i.test(String(firstHref)) ? String(firstHref) : "可疑安装包");
        const fnGuard = hrefForGuard ? NS.getFilenameFromUrl(hrefForGuard) : "";
        let brandTok = state.spoofBrand || "";
        if (brandTok && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          brandTok = NS.canonicalizeBrandDisplayCandidate(brandTok);
          if (!brandTok) state.spoofBrand = "";
        }
        if (!brandTok || (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(String(brandTok).toLowerCase()))) {
          try {
            // brandToken 只是域名相关性核，不能进入 toast；只认页面身份共识。
            const primary = typeof NS.collectPrimaryBrandKeywords === "function"
              ? NS.collectPrimaryBrandKeywords()
              : null;
            brandTok = typeof NS.resolveSpoofDisplayBrand === "function"
              ? (NS.resolveSpoofDisplayBrand(location.hostname, primary) || "")
              : ((primary && primary.display) || "");
            if (brandTok && NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(String(brandTok).toLowerCase())) brandTok = "";
            if (brandTok && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
              brandTok = NS.canonicalizeBrandDisplayCandidate(brandTok);
            }
          } catch { /* ignore */ }
        }
        const brandish = pkgHitBrandNear || !!brandTok || titleHot || /官网|官方下载/i.test(document.title || "");
        if (brandish) {
          const noticeTitle = brandTok ? `已识别仿冒「${brandTok}」官网` : "已识别仿冒品牌官网下载";
          const noticeMsg = brandTok
            ? `页面标题/正文品牌「${brandTok}」与当前域名不匹配，疑似仿冒官网。`
            : `页面宣称官方下载，但域名/安装包异常，已拦截 ${label}`;
          if (brandTok) state.spoofBrand = brandTok;
          try { NS.addSignal("仿冒品牌官网下载站", 20, noticeMsg); } catch { /* ignore */ }
          // 软品牌近失/标题热：勿 lockHard——否则绕过 ICP 软门，保护页会整包误杀曲包
          NS.installDownloadGuard(brandTok ? `仿冒品牌官网下载站（仿冒「${brandTok}」）: ${label}` : `仿冒品牌官网下载: ${label}`, {
            notify: true,
            href: hrefForGuard,
            message: noticeMsg,
            title: noticeTitle,
            forceNotify: true,
            guardKind: "brand-spoof",
            lockHard: false
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
        // 品牌检测已 arm 时仍把包链禁用，但不要再用“已拦截安装包 …”改写
        // 同一个品牌 toast。包名留在风险详情，页面只维持一条稳定的品牌通知。
        NS.disableAllDownloadIntentControls();
        if (state._brandSpoofPortalDetected || state._fakeBrandShellDetected || state.spoofBrand) {
          try {
            if (typeof NS.ensureBrandSpoofNotice === "function") NS.ensureBrandSpoofNotice(false);
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
  NS.watchSuspiciousPackagesLive = function (watchOptions = null) {
    const state = NS.state;
    const evidenceOnly = !!(watchOptions && watchOptions.evidenceOnly === true);
    let scheduled = false; let lateEvidenceScheduled = false; let liveObs = null; let stopped = false;
    let archiveRowsObserved = 0; let archiveReclassScheduled = false;
    const packageOrDownloadUrl = (raw) => {
      const value = String(raw || "").trim();
      if (!value || /^(?:javascript:|#)$/i.test(value)) return false;
      return /\.(?:apk|zip|exe|dmg|msi|pkg|rar|7z|msix|appx)(?:[?#]|$)/i.test(value)
        || /(?:^|[/?#_.=&-])(?:download|getdown|getfile|installer|setup)(?:[/?#_.=&-]|$)/i.test(value);
    };
    const nodeHasDownloadEvidence = (node) => {
      try {
        if (!node || node.nodeType !== 1) return false;
        const tag = String(node.tagName || "").toUpperCase();
        const get = (name) => String((node.getAttribute && node.getAttribute(name)) || "");
        const hrefLike = [get("href"), get("data-href"), get("data-url"), get("data-download"), get("data-down"), get("src")];
        if (hrefLike.some(packageOrDownloadUrl)) return true;

        if (tag === "SCRIPT") {
          // 普通业务脚本/水合 chunk 不触发；仅检查有界的明确下载变量或包 URL。
          const scriptText = String(node.textContent || "").slice(0, 6000);
          return /download_uri|GLOBAL_DOWNLOAD_URL|download_link|fetchDownloadLink|getdown|getfile/i.test(scriptText)
            || /(?:https?:)?\/\/[^\s"'<>]+\.(?:exe|msi|msix|dmg|pkg|apk|zip|rar|7z)(?:[?#][^\s"'<>]*)?/i.test(scriptText);
        }

        const interactive = tag === "A" || tag === "BUTTON" || get("role").toLowerCase() === "button";
        if (!interactive) return false;
        const identity = `${get("id")} ${get("class")} ${get("name")}`.slice(0, 240);
        const label = String(node.textContent || "").replace(/\s+/g, " ").trim().slice(0, 100);
        if (/download|down-btn|btn-down|installer|setup/i.test(identity)) return true;
        return /官方下载|立即下载|免费下载|客户端下载|下载客户端|安装包下载|下载中心|download\s+now|get\s+(?:the\s+)?(?:app|client)/i.test(label);
      } catch {
        return false;
      }
    };
    const shouldStopLive = () => {
      try {
        if (NS.pageLooksLikeSearchEngineResultsPage()) return true;
        if (typeof NS.isOfficialDownloadScanQuiet === "function" && NS.isOfficialDownloadScanQuiet()) return true;
        if (state._perfBenign && !state.downloadGuardInstalled && !state._pendingEncryptedSpa) return true;
        if (state._intelLightMode && state._analysisDone && !state.downloadGuardInstalled) return true;
        // 成熟正规站且已完成：CSS/DOM 噪声不再连环扫
        if (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()
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
    const scanLateEvidenceOnce = () => {
      if (lateEvidenceScheduled) return;
      lateEvidenceScheduled = true;
      setTimeout(() => {
        try {
          // 已完成/可信/性能轻量页也可能晚插真正的安装包链接。只对这一批
          // 明确证据强制扫描一次；普通 Quill/图片/文本 hydrate 仍直接停表。
          try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
          NS.scanSuspiciousPackagesFast(true, { lateExplicitEvidence: true });
        } catch { /* ignore */ }
        finally {
          lateEvidenceScheduled = false;
          try { if (shouldStopLive()) stopLiveWatch(); } catch { /* ignore */ }
        }
      }, 80);
    };
    const stopLiveWatch = () => {
      if (stopped) return;
      stopped = true;
      try { if (liveObs) liveObs.disconnect(); } catch { /* ignore */ }
      liveObs = null;
      try {
        if (NS.caches && NS.caches._stopSuspiciousLiveWatch === stopLiveWatch) {
          NS.caches._stopSuspiciousLiveWatch = null;
        }
      } catch { /* ignore */ }
    };
    const scheduleArchiveHydrationReclass = () => {
      if (archiveReclassScheduled || stopped) return;
      archiveReclassScheduled = true;
      setTimeout(() => {
        archiveReclassScheduled = false;
        if (stopped) return;
        try {
          const c = NS.caches || {};
          c._highDensityDl = null; c._highDensityDlAt = 0;
          c._highVolArchive = null; c._highVolArchiveAt = 0;
          c._skipHeavy = null; c._skipHeavyAt = 0;
          const archive = typeof NS.pageLooksLikeHighVolumePackageArchive === "function"
            && NS.pageLooksLikeHighVolumePackageArchive();
          if (archive && !state.downloadGuardInstalled && !state._brandSpoofPortalDetected
            && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())) {
            // Performance-only classification: this does not establish an
            // official/trusted identity and a later explicit package still
            // goes through the evidence-only observer/downloads pipeline.
            state._perfBenign = true;
            state._perfBenignAt = Date.now();
            try { NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
            stopLiveWatch();
          }
        } catch { /* ignore */ }
      }, 60);
    };
    try { if (NS.caches) NS.caches._stopSuspiciousLiveWatch = stopLiveWatch; } catch { /* ignore */ }

    if (!evidenceOnly) NS.armImmediatePackageBlock();
    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      state._perfBenign = true; state._perfBenignAt = Date.now();
      if (!evidenceOnly) {
        NS.scheduleIdle(() => { try { NS.scanSuspiciousPackagesFast(true); } catch { /* ignore */ } }, 800);
      }
      return;
    }
    if (!evidenceOnly) {
      let fullDomScanDone = false;
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
          if (NS.pageLooksLikeSearchEngineResultsPage()) {
            state._perfBenign = true; state._perfBenignAt = Date.now(); stopLiveWatch(); return;
          }
          // 首屏 200ms 早扫可能只看见半成品 DOM；完整 DOM 必须强制重选一次品牌。
          fullDomScanDone = true;
          try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
          NS.scanSuspiciousPackagesFast(true);
        }, { once: true });
      } else {
        fullDomScanDone = true;
        NS.scheduleIdle(() => {
          if (!stopped && !shouldStopLive()) NS.scanSuspiciousPackagesFast();
        }, 600);
      }

      // DOMContentLoaded 是完整 DOM 的唯一强制首扫；事件未到时只做一次有界兜底。
      // 旧 200/900/1600ms 三轮会与 encrypted-SPA 五轮、load 扫描叠加并锁死 Edge 主线程。
      setTimeout(() => {
        if (stopped || fullDomScanDone || shouldStopLive() || NS.pageLooksLikeSearchEngineResultsPage()) return;
        fullDomScanDone = true;
        try { NS.invalidateHtmlCache(); } catch { /* ignore */ }
        NS.scanSuspiciousPackagesFast(!!state._pendingEncryptedSpa);
      }, 1800);
    }

    try {
      liveObs = new MutationObserver((mutations) => {
        if (stopped) return;
        if (NS.pageLooksLikeSearchEngineResultsPage()) { stopLiveWatch(); return; }
        // 不可在读取本批 mutation 前因 trusted/perf 状态直接退出：否则完成态
        // 之后才挂载的真实 .exe/.msi 链接会被当作普通 hydrate 丢掉。
        const stopAfterMutation = shouldStopLive()
          || (state._perfBenign && !state._pendingEncryptedSpa);
        let interesting = false;
        let inspected = 0;
        let subtreeQueries = 0;
        for (const m of mutations) {
          if (m.type === "attributes") {
            const an = String(m.attributeName || "").toLowerCase();
            if (an !== "href" && an !== "data-href" && an !== "data-url" && an !== "data-download" && an !== "data-down") continue;
            if (nodeHasDownloadEvidence(m.target)) { interesting = true; break; }
            continue;
          }
          if (!m.addedNodes || !m.addedNodes.length) continue;
          for (let i = 0; i < m.addedNodes.length; i++) {
            const n = m.addedNodes[i];
            if (!n || n.nodeType !== 1) continue;
            const tag = String(n.tagName || "").toUpperCase();
            if (tag === "TR") archiveRowsObserved++;
            else if ((tag === "TBODY" || tag === "TABLE" || tag === "DIV")
              && typeof n.querySelectorAll === "function") {
              try {
                archiveRowsObserved += Math.min(24, n.querySelectorAll(
                  "table tbody tr, #table-version tr, .version-list .version-item"
                ).length);
              } catch { /* ignore */ }
            }
            if (++inspected > 160) break;
            if (nodeHasDownloadEvidence(n)) { interesting = true; break; }
            // 大块一次性挂载时只做少量定向查询；不遍历 Quill/表格等普通内联节点。
            if (subtreeQueries < 8 && n.childElementCount > 0 && typeof n.querySelectorAll === "function") {
              subtreeQueries++;
              // 先用原生 selector 跨过普通候选顺序，包链即使位于第 17 个以后也优先命中。
              try {
                const priority = n.querySelector(
                  "a[href*='.exe' i], a[href*='.msi' i], a[href*='.msix' i], a[href*='.dmg' i], "
                  + "a[href*='.pkg' i], a[href*='.apk' i], a[href*='.zip' i], a[href*='.rar' i], a[href*='.7z' i], "
                  + "a[href*='download' i], a[data-href*='download' i], [data-download], .download-uri, .download-btn"
                );
                if (priority && nodeHasDownloadEvidence(priority)) { interesting = true; break; }
              } catch { /* selector flags unavailable: bounded fallback below */ }
              let candidates = [];
              try { candidates = n.querySelectorAll("a[href], a[data-href], button, [role='button'], script"); } catch { candidates = []; }
              const lim = Math.min(candidates.length || 0, Math.max(0, 160 - inspected));
              for (let j = 0; j < lim; j++) {
                inspected++;
                if (nodeHasDownloadEvidence(candidates[j])) { interesting = true; break; }
              }
              if (interesting) break;
            }
          }
          if (interesting) break;
          if (inspected > 160) break;
        }
        if (archiveRowsObserved >= 20) {
          archiveRowsObserved = -1000000;
          scheduleArchiveHydrationReclass();
        }
        if (interesting) {
          if (stopAfterMutation) {
            scanLateEvidenceOnce();
            stopLiveWatch();
          } else {
            kick(450);
          }
          return;
        }
        // 完成态后的普通 mutation 不再触发扫描，但观察器保留到既有 TTL；
        // 否则 Quill 先挂一段正文、稍后才挂下载链接时仍会漏检。
        // 精准过滤后这条等待路径不做 DOM 全扫，成本受 14s 硬上限约束。
        if (stopAfterMutation) return;
      });
      liveObs.observe(document.documentElement || document, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["href", "data-href", "data-url", "data-download", "data-down"]
      });
      // 归档站 6s 后停表；一般页 14s
      const stopMs = (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) ? 6000 : 14000;
      setTimeout(stopLiveWatch, stopMs);
    } catch { /* ignore */ }
  };
})(window.SilverfoxContent ??= {});
