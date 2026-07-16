/**
 * 下载保护 guard：arm/lift、toast/overlay、风险报告、元素禁用/恢复。
 */
;(function (NS) {
  "use strict";

  const { PACKAGE_EXT, PACKAGE_NAME } = NS;

  NS.dismissPageToast = function () {
    try {
      const box = document.getElementById("silverfox-threat-toast");
      if (box) { try { clearTimeout(box.__silverfoxHideTimer); } catch { /* ignore */ } box.remove(); }
      NS.caches.pageToastLastAt.clear();
      try { NS.caches.sentNoticeKeys.clear(); NS.caches.sentNoticeLastAt.clear(); } catch { /* ignore */ }
    } catch { /* ignore */ }
  };

  NS.showPageToast = function (title, message, opts = {}) {
    try {
      const c = NS.caches;
      const key = `${title}::${message}`;
      const now = Date.now();
      const last = c.pageToastLastAt.get(key) || 0;
      if (!opts.force && last && now - last < 1800) return;
      c.pageToastLastAt.set(key, now);
      const id = "silverfox-threat-toast";
      let box = document.getElementById(id);
      if (!box) {
        box = document.createElement("div");
        box.id = id;
        box.setAttribute("role", "alert");
        Object.assign(box.style, {
          position: "fixed", top: "16px", right: "16px", zIndex: "2147483646", maxWidth: "360px",
          padding: "12px 14px 12px 12px", background: "linear-gradient(135deg, #1d4ed8 0%, #2563eb 55%, #3b82f6 100%)",
          color: "#fff", font: "13px/1.45 system-ui,Segoe UI,sans-serif", borderRadius: "10px",
          boxShadow: "0 8px 28px rgba(37, 99, 235, 0.35)", pointerEvents: "auto", display: "flex",
          gap: "10px", alignItems: "flex-start", opacity: "1", transition: "opacity 0.2s ease"
        });
        document.documentElement.appendChild(box);
      }
      box.style.opacity = "0";
      box.textContent = "";
      const icon = document.createElement("div");
      icon.textContent = "🛡"; icon.style.fontSize = "18px"; icon.style.lineHeight = "1.2";
      const body = document.createElement("div"); body.style.flex = "1";
      const t = document.createElement("div"); t.style.fontWeight = "700"; t.style.marginBottom = "4px"; t.textContent = title;
      const m = document.createElement("div"); m.style.opacity = "0.95"; m.textContent = message;
      body.appendChild(t); body.appendChild(m);
      box.appendChild(icon); box.appendChild(body);
      try { void box.offsetWidth; box.style.opacity = "1"; } catch { /* ignore */ }
      clearTimeout(box.__silverfoxHideTimer);
      box.__silverfoxHideTimer = setTimeout(() => {
        try { box.style.opacity = "0"; setTimeout(() => { try { box.remove(); } catch { /* ignore */ } }, 220); }
        catch { try { box.remove(); } catch { /* ignore */ } }
      }, 6500);
    } catch { /* ignore */ }
  };

  NS.showGuardOverlay = function (href, opts = {}) {
    const state = NS.state;
    const targetLabel = NS.formatPackageLabel(href);
    const title = opts.title || "已拦截可疑下载文件";
    const message = opts.message || targetLabel;
    const key = `${title}::${message}`;
    const userAction = !!opts.userAction || !!opts.forceNotify;
    const isIdentityNotice = opts.guardKind === "brand-spoof" || opts.guardKind === "nav-trap" || /仿冒|官网|域名|跳转|搜索引擎/i.test(`${title} ${message}`);
    try {
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return;
      if (!isIdentityNotice) {
        const fn = href ? NS.getFilenameFromUrl(href) : "";
        const msgFn = NS.normalizeFileName(String(message || "").split(/[\s/\\]/).pop() || "");
        const isClearProductFile = (name) => {
          if (!name || !PACKAGE_NAME.test(name)) return false;
          return NS.isClearProductOrAndroidPackage(name) || NS.looksLikeStrongProductInstallerName(name) || NS.isBenignShortInstallerName(name) || (NS.looksLikeProductPackageName(name) && !NS.looksLikeOversimplifiedBrandInstallerName(name));
        };
        if (isClearProductFile(fn) || isClearProductFile(msgFn)) return;
      }
    } catch { /* fall through */ }
    const c = NS.caches;
    const now = Date.now();
    const lastSys = c.sentNoticeLastAt.get(key) || 0;
    const canSys = !c.sentNoticeKeys.has(key) || (userAction && now - lastSys >= 8000) || (opts.forceNotify && now - lastSys >= 3000);
    if (canSys) {
      c.sentNoticeKeys.add(key);
      c.sentNoticeLastAt.set(key, now);
      const noticePayload = { type: "threat-notice", title, message, url: location.href, timestamp: now, force: !!(userAction || opts.forceNotify), guardKind: opts.guardKind || "" };
      try {
        if (chrome?.runtime?.id) {
          chrome.runtime.sendMessage(noticePayload, () => {
            if (chrome.runtime.lastError) {
              const msg = chrome.runtime.lastError.message || "";
              if (!/message port closed|Extension context invalidated/i.test(msg)) console.warn("threat-notice send failed", msg);
            }
          });
        }
      } catch (err) {
        const msg = err && err.message ? err.message : String(err);
        if (!/Extension context invalidated/i.test(msg)) console.warn("showGuardOverlay failed", msg);
      }
    }
    if (opts.toast !== false) NS.showPageToast(title, message, { force: userAction || !!opts.forceNotify || isIdentityNotice });
  };

  NS.emitRiskReport = function (force = false) {
    const state = NS.state;
    const c = NS.caches;
    const now = Date.now();
    if (state._analysisDone && !force && now - c.lastReportAt < 2500) return;
    if (!force && now - c.lastReportAt < 600) return;
    c.lastReportAt = now;
    const threatDetails = state.details.filter((d) => (d.weight || 0) > 0);
    const signalCount = threatDetails.length;
    const hasPackageThreat = state.downloadGuardInstalled || state.remoteDownloadDispatchDetected
      || threatDetails.some((d) => /安装包|下载拦截|仿冒|可疑下载|远程配置|PHP 下载/i.test(d.name || ""));
    let riskLevel = "low";
    if (state.remoteDownloadDispatchDetected || (hasPackageThreat && state.score >= 24)) riskLevel = "high";
    else if (hasPackageThreat || state.downloadGuardInstalled || (state.score >= 12 && signalCount >= 2)) riskLevel = "medium";
    else if (state.score >= 40 && signalCount >= 3) riskLevel = "high";
    else if (state.score >= 18 && signalCount >= 2) riskLevel = "medium";
    let score = Math.min(100, state.score);
    if (state.downloadGuardInstalled && score < 16) score = Math.max(score, 16);
    if (state.remoteDownloadDispatchDetected && score < 28) score = Math.max(score, 28);
    const pkgTargets = (state.protectedTargets || []).filter((t) => {
      try { return NS.isPackageFileUrl(t) || /\.(zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|$)/i.test(String(t)); } catch { return false; }
    }).slice(0, 5);
    const payload = {
      type: "threat-risk", score, riskLevel, analysisComplete: !!state._analysisDone,
      details: state.details.filter((d) => {
        if (d.name === "已查询到ICP备案号") return false;
        if (d.name === "无ICP备案信息" && (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeLongLivedWhoisDomain() || (NS.getWhoisAgeDays() != null && NS.getWhoisAgeDays() >= 365))) return false;
        if (/仿冒品牌官网|仿冒站下载拦截/i.test(d.name || "") && (NS.hasValidIcpRecord() || NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain())) return false;
        return true;
      }).slice(0, 12),
      icpInfo: state.icpInfo || "", whoisInfo: state.whoisInfo || "", url: location.href,
      downloadGuardInstalled: !!state.downloadGuardInstalled, packageBlocked: !!state.remoteDownloadDispatchDetected,
      protectedTargets: pkgTargets, spoofBrand: state.spoofBrand || "",
      brandSpoofPortal: !!(state._brandSpoofPortalDetected || state.spoofBrand) || threatDetails.some((d) => /仿冒品牌官网/i.test(d.name || ""))
    };
    try {
      if (!chrome?.runtime?.id) return;
      chrome.runtime.sendMessage(payload, () => {
        if (chrome.runtime.lastError) {
          const msg = chrome.runtime.lastError.message || "";
          if (!/message port closed|Extension context invalidated/i.test(msg)) console.warn("threat-risk send failed", msg);
        }
      });
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      if (!/Extension context invalidated/i.test(msg)) console.warn("emitRiskReport failed", msg);
    }
  };

  NS.markRemoteDownloadDispatch = function (reason, href) {
    const state = NS.state;
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return;
    if (href && (
      NS.looksLikeOfficialProductDownloadEndpoint(href) || NS.isClearProductOrAndroidPackage(href) || NS.isAllowlistedProductPackageUrl(href)
      || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(href) || href) || NS.isBenignShortInstallerName(NS.getFilenameFromUrl(href) || href)
      || NS.looksLikeProductPackageName(NS.getFilenameFromUrl(href) || href) || NS.isContentAddressedPackageName(NS.getFilenameFromUrl(href) || href)
      || (NS.isTrustedOfficialDownloadContext() && NS.isSamePageBrandApex(href)) || (NS.looksLikeSafeOfficialContext() && !NS.looksLikeHighRiskBlobPackageUrl(href))
    )) return;
    if (href && !NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href)) {
      try {
        const abs = new URL(href, location.href).href;
        const cached = NS.caches.probeCache.get(abs);
        if (!(cached && cached.isDownload)) return;
        if (NS.looksLikeOfficialProductDownloadEndpoint(abs)) return;
      } catch { return; }
    }
    if (!state.remoteDownloadDispatchDetected) { state.remoteDownloadDispatchDetected = true; NS.addSignal("已拦截可疑安装包下载", 20, reason); }
    else NS.addSignal("已拦截可疑下载链接", 8, reason);
    NS.installDownloadGuard(reason, { notify: true, href, forceNotify: false });
    NS.emitRiskReport(true);
  };

  NS.disableOneSuspiciousElement = function (el, href) {
    if (!el || el.dataset.threatDetectorDisabled === "1") return;
    try {
      el.dataset.threatDetectorDisabled = "1";
      el.style.setProperty("pointer-events", "none", "important");
      el.style.setProperty("opacity", "0.45", "important");
      el.style.setProperty("filter", "grayscale(0.6)", "important");
      el.style.setProperty("cursor", "not-allowed", "important");
      el.setAttribute("aria-disabled", "true");
      el.setAttribute("title", "已拦截可疑安装包下载");
      if (href) el.setAttribute("data-threat-original-href", href);
      if (el.tagName === "A") el.removeAttribute("href");
      if (el.tagName === "BUTTON" || el.tagName === "INPUT") el.disabled = true;
    } catch { /* ignore */ }
  };

  NS.reEnableOneThreatElement = function (el) {
    if (!el) return;
    try {
      if (el.dataset.threatDetectorDisabled === "1") delete el.dataset.threatDetectorDisabled;
      el.style.removeProperty("pointer-events"); el.style.removeProperty("opacity"); el.style.removeProperty("filter"); el.style.removeProperty("cursor");
      if (el.getAttribute("aria-disabled") === "true") el.removeAttribute("aria-disabled");
      if (el.getAttribute("title") === "已拦截可疑安装包下载") el.removeAttribute("title");
      const orig = el.getAttribute("data-threat-original-href");
      if (orig && el.tagName === "A" && !el.getAttribute("href")) { if (orig !== "js-download" && !/^javascript:/i.test(orig)) el.setAttribute("href", orig); }
      el.removeAttribute("data-threat-original-href");
      if (el.tagName === "BUTTON" || el.tagName === "INPUT") el.disabled = false;
    } catch { /* ignore */ }
  };

  NS.reEnableAllThreatDisabledElements = function () {
    try {
      document.querySelectorAll("[data-threat-detector-disabled='1'], a[data-threat-original-href], button[aria-disabled='true']").forEach((el) => NS.reEnableOneThreatElement(el));
      NS.getAllDownloadIntentElements().forEach((el) => NS.reEnableOneThreatElement(el));
    } catch { /* ignore */ }
  };

  NS.shouldLiftDownloadGuard = function () {
    try {
      const state = NS.state;
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { state._brandResourceMismatchDetected = false; return true; }
      if (state._seoCloakKitDetected || state._brandSpoofPortalDetected || state._fakeSpaDetected || state._brandResourceMismatchDetected) return false;
      if (NS.hostLooksLikeBrandMarketingSpoof()) return false;
      const html = NS.getThreatScanHtml(120000);
      if (NS.hasEncryptedNuxtDownloadConfig(html) && NS.countTransparentProductPackages(html) === 0) return false;
      const badPkg = (state.protectedTargets || []).some((t) => {
        if (NS.looksLikeOfficialProductDownloadEndpoint(t)) return false;
        if (NS.looksLikeHighRiskBlobPackageUrl(t)) return true;
        const n = NS.getFilenameFromUrl(t) || NS.normalizeFileName(t);
        if (!n) return false;
        if (NS.isClearProductOrAndroidPackage(n) || NS.isBenignShortInstallerName(n) || NS.looksLikeProductPackageName(n)) return false;
        if (NS.isContentAddressedPackageName(n)) return /https?:\/\//i.test(String(t)) && NS.looksLikeHighRiskBlobPackageUrl(t);
        return NS.isSuspiciousDownloadFilename(n);
      });
      if ((NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) && !state._fakeSpaDetected && !NS.hasEncryptedNuxtDownloadConfig(html)) {
        const hasHighRiskBlob = (state.protectedTargets || []).some((t) => NS.looksLikeHighRiskBlobPackageUrl(t));
        if (!hasHighRiskBlob) return true;
      }
      if (badPkg && !(NS.looksLikeMatureOfficialPortal() || NS.looksLikeSafeOfficialContext())) return false;
      const onlyOfficialTargets = (state.protectedTargets || []).length > 0 && (state.protectedTargets || []).every((t) => {
        if (NS.looksLikeOfficialProductDownloadEndpoint(t) || NS.isSamePageBrandApex(t)) return true;
        if (NS.looksLikeHighRiskBlobPackageUrl(t)) return false;
        const n = NS.getFilenameFromUrl(t) || NS.normalizeFileName(t);
        return !n || NS.isClearProductOrAndroidPackage(n) || NS.isBenignShortInstallerName(n) || NS.looksLikeProductPackageName(n) || NS.isContentAddressedPackageName(n);
      });
      if (onlyOfficialTargets && NS.isTrustedOfficialDownloadContext()) return true;
      if (NS.isTrustedOfficialDownloadContext()) return true;
      if (typeof NS.pageLooksLikeLegitimateOfficialDownload === "function" && NS.pageLooksLikeLegitimateOfficialDownload()) return true;
      if (NS.looksLikeOfficialBrandDownloadPage(html)) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      if (NS.looksLikeOfficialClientDownloadPage()) return true;
      const whoisOld = /已注册\s*(\d+)\s*天/.exec(state.whoisInfo || "");
      const days = whoisOld ? parseInt(whoisOld[1], 10) : null;
      const hasIcp = state.icpInfo && !/未查询到/.test(state.icpInfo);
      if (hasIcp && days != null && days >= 365) {
        if (onlyOfficialTargets || !badPkg) return true;
        const onlyHashOrClear = (state.protectedTargets || []).every((t) => {
          if (NS.looksLikeHighRiskBlobPackageUrl(t)) return false;
          const n = NS.getFilenameFromUrl(t) || NS.normalizeFileName(t);
          return !n || NS.isContentAddressedPackageName(n) || NS.isClearProductOrAndroidPackage(n) || NS.isBenignShortInstallerName(n) || NS.looksLikeProductPackageName(n);
        });
        if (onlyHashOrClear) return true;
      }
      if (hasIcp && days != null && days >= 365 && NS.countTransparentProductPackages(html) >= 1) return true;
      return false;
    } catch { return false; }
  };

  NS.clearDownloadGuard = function (reason) {
    const state = NS.state;
    const hadGuard = state.downloadGuardInstalled || state._earlyShellArmed;
    state.downloadGuardInstalled = false;
    state._earlyShellArmed = false;
    state.protectionNoticeSent = false;
    state.remoteDownloadDispatchDetected = false;
    state.protectedTargets = [];
    state._guardRedisableArmed = false;
    try { NS.caches.sentNoticeKeys.clear(); } catch { /* ignore */ }
    NS.postToHooks({ type: "set-guard", enabled: false });
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) NS.notifyHooksOfficialSafe(true);
    NS.reEnableAllThreatDisabledElements();
    [50, 200, 600, 1500].forEach((ms) => setTimeout(() => { if (!state.downloadGuardInstalled) NS.reEnableAllThreatDisabledElements(); }, ms));
    try {
      if (chrome?.runtime?.id) {
        chrome.runtime.sendMessage({ type: "set-tab-protect", enabled: false, force: true, url: location.href }, () => { void chrome.runtime.lastError; });
        chrome.runtime.sendMessage({ type: "clear-threat-notice", url: location.href, reason: reason || "lift-guard" }, () => { void chrome.runtime.lastError; });
      }
    } catch { /* ignore */ }
    const softRe = /已启用安装包下载拦截|已启用仿冒站下载拦截|已启用异常跳转拦截|SEO伪装跳转|SEO收录仿冒|多平台下载指向搜索引擎|非用户手势|仿冒品牌官网|仿冒官网|页面嵌入可疑安装包|可疑安装包链接|探测到跳转\/附件下载|探测到下载行为|已拦截可疑|域名与品牌资源不一致|多版本下载同一|无透明安装包/;
    if (Array.isArray(state.details)) state.details = state.details.filter((d) => !softRe.test(d.name || "") && !softRe.test(d.reason || ""));
    if (state.signalSet && typeof state.signalSet.clear === "function") {
      state.signalSet.clear();
      let score = 0;
      for (const d of state.details) { const w = Number(d.weight) || 0; state.signalSet.add(`${d.name}:${w}`); score += w; }
      state.score = score;
    }
    if (hadGuard || reason) NS.emitRiskReport(true);
  };

  NS.maybeLiftDownloadGuard = function () {
    try {
      const state = NS.state;
      if (!NS.shouldLiftDownloadGuard()) return false;
      const locked = state.downloadGuardInstalled || state._earlyShellArmed || !!document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']");
      if (!locked && !(state.protectedTargets && state.protectedTargets.length)) {
        NS.postToHooks({ type: "set-guard", enabled: false });
        return false;
      }
      NS.clearDownloadGuard("official-or-safe-page");
      return true;
    } catch { return false; }
  };

  NS.isHrefSuspiciousPackageSync = function (href, element) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    if (!NS.isPackageFileUrl(href)) return false;
    if (NS.isAllowlistedProductPackageUrl(href)) return false;
    const fileName = NS.getFilenameFromUrl(href);
    if (NS.looksLikeStrongProductInstallerName(fileName) || NS.isClearProductOrAndroidPackage(fileName) || NS.isClearProductOrAndroidPackage(href) || NS.isBenignShortInstallerName(fileName)) return false;
    try {
      const host = new URL(href, location.href).hostname;
      if (NS.isAnonymousPublicObjectHost(host) && !NS.looksLikeStrongProductInstallerName(fileName)) return true;
      if (NS.hostLooksLikePublicObjectStorageEndpoint(host) && NS.looksLikeObjectStoragePackageUrl(href)) return true;
    } catch { /* ignore */ }
    if (NS.looksLikeHighRiskBlobPackageUrl(href) || NS.isThreatObjectStoragePackage(href, element)) return true;
    if (NS.looksLikeBrandNearMissPackageName(fileName)) return true;
    if (NS.isContentAddressedPackageName(fileName)) {
      if (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) return NS.looksLikeHighRiskBlobPackageUrl(href);
      return NS.looksLikeHighRiskBlobPackageUrl(href) || NS.looksLikeObjectStoragePackageUrl(href);
    }
    if (NS.isThreatObjectStoragePackage(href, element)) return true;
    if (NS.looksLikeProductPackageName(fileName) && !NS.looksLikeObjectStoragePackageUrl(href)) return false;
    if (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) return NS.looksLikeHighRiskBlobPackageUrl(href);
    return NS.isSuspiciousDownloadFilename(fileName) || NS.looksLikeHiddenPackagePath(href) || NS.isSuspiciousDownloadTarget(href, element);
  };

  NS.isHrefSuspiciousPackage = function (href, element) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    if (NS.looksLikeOfficialProductDownloadEndpoint(href)) return false;
    if (NS.isClearProductOrAndroidPackage(href)) return false;
    if (NS.isBenignShortInstallerName(NS.getFilenameFromUrl(href))) return false;
    if (NS.isContentAddressedPackageName(NS.getFilenameFromUrl(href)) && (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) && !NS.looksLikeHighRiskBlobPackageUrl(href)) return false;
    if (NS.isTrustedOfficialDownloadContext() && NS.isSamePageBrandApex(href)) return false;
    if (NS.isHrefSuspiciousPackageSync(href, element)) return true;
    try {
      const abs = new URL(href, location.href).href;
      const cached = NS.caches.probeCache.get(abs);
      if (cached && cached.isDownload) {
        if (NS.looksLikeOfficialProductDownloadEndpoint(abs)) return false;
        const fn = cached.filename || cached.fileName || NS.getFilenameFromUrl(abs);
        if (NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(abs)) return false;
        if (NS.isBenignShortInstallerName(fn)) return false;
        if (NS.isContentAddressedPackageName(fn) && (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) && !NS.looksLikeHighRiskBlobPackageUrl(abs)) return false;
        return true;
      }
    } catch { /* ignore */ }
    return false;
  };

  NS.isSuspiciousDownloadTarget = function (href, element) {
    const trimmed = (href || "").trim();
    if (!trimmed || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(trimmed)) return false;
    if (!NS.isPackageFileUrl(trimmed)) return false;
    try {
      const fileName = NS.getFilenameFromUrl(trimmed);
      if (NS.isThreatObjectStoragePackage(trimmed, element)) return true;
      if (NS.looksLikeProductPackageName(fileName) && !NS.looksLikeObjectStoragePackageUrl(trimmed)) return false;
      const fileNameSuspicious = NS.isSuspiciousDownloadFilename(fileName);
      const obfuscatedPhp = NS.looksLikeObfuscatedPhpDownloadUrl(trimmed);
      const hiddenPath = NS.looksLikeHiddenPackagePath(trimmed);
      const brandMismatch = NS.packageMismatchesPageBrand(trimmed);
      const queryDownload = /(filename|file|url|downurl|downloadurl)=/i.test(trimmed) && PACKAGE_EXT.test(trimmed);
      const path = new URL(trimmed, location.href).pathname.toLowerCase();
      const garbledPath = /\/(?:ins\d+|id\d+|[a-f0-9]{10,})\//i.test(path);
      if (obfuscatedPhp) return true;
      if (fileNameSuspicious) return true;
      if (hiddenPath && (fileNameSuspicious || brandMismatch)) return true;
      if (brandMismatch && (fileNameSuspicious || hiddenPath)) return true;
      if (queryDownload && (fileNameSuspicious || garbledPath || obfuscatedPhp)) return true;
      if (garbledPath && PACKAGE_EXT.test(path)) return true;
      if (element && NS.isDownloadIntentElement(element) && fileNameSuspicious) return true;
      return false;
    } catch { return false; }
  };

  NS.applyConfirmedDownloadBlock = function (href, el, probeInfo) {
    if (!href) return;
    if (NS.looksLikeOfficialProductDownloadEndpoint(href) || NS.isTrustedOfficialDownloadContext()) return;
    const probeName = probeInfo?.filename || probeInfo?.fileName || "";
    if (NS.isClearProductOrAndroidPackage(probeName) || NS.isClearProductOrAndroidPackage(href) || NS.looksLikeStrongProductInstallerName(probeName) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(href)) || NS.isAllowlistedProductPackageUrl(href)) return;
    const state = NS.state;
    if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
    if (el) NS.disableOneSuspiciousElement(el, href);
    NS.disableSuspiciousDownloadButtons();
    NS.disableAllDownloadIntentControls();
    let label = NS.formatPackageLabel(href);
    try { const u = new URL(href, location.href); if (!PACKAGE_EXT.test(u.pathname)) label = probeInfo?.filename || `${u.hostname}${u.pathname}`; } catch { /* ignore */ }
    const reason = probeInfo?.reason ? `探测到下载行为(${probeInfo.reason}): ${label}` : `已拦截可疑下载: ${label}`;
    NS.addSignal("探测到跳转/附件下载", 14, reason);
    NS.installDownloadGuard(reason, { notify: true, href, message: label, forceNotify: !state.protectionNoticeSent });
  };

  NS.disableSuspiciousDownloadButtons = function () {
    const state = NS.state;
    Array.from(document.querySelectorAll("a[href], a[data-href], a[data-threat-original-href]")).forEach((el) => {
      try {
        const href = (el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-threat-original-href") || "").trim();
        if (!href || /^(javascript:|#)$/i.test(href)) return;
        if (!NS.isHrefSuspiciousPackageSync(href, el) && !NS.isHrefSuspiciousPackage(href, el)) return;
        NS.disableOneSuspiciousElement(el, href);
      } catch { /* ignore */ }
    });
    if (state.downloadGuardInstalled || state.protectedTargets.length > 0) NS.disableAllDownloadIntentControls();
  };

  NS.armBackgroundProtect = function (mode = "full") {
    try {
      if (!chrome?.runtime?.id) return;
      chrome.runtime.sendMessage({ type: "set-tab-protect", enabled: true, mode, provisional: mode === "provisional", url: location.href }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
  };

  NS.pageLooksLikeThinCloakingRelay = function () {
    try {
      if (NS.pageLooksLikeLegitimateOfficialDownload()) return false;
      if (!document.body) return false;
      try {
        const htmlHead = NS.getHtmlSlice(60000);
        if (/window\.__DATA__\s*=/.test(htmlHead) && /DownloadLink|win_installer|\.exe"/i.test(htmlHead) && NS.countTransparentProductPackages(htmlHead) >= 1) return false;
        const spaRoot = document.querySelector("#ice-container, #root, #app, #__next, #__nuxt, [data-reactroot]");
        if (spaRoot) {
          const externalScripts = Array.from(document.scripts || []).filter((s) => s.src).length;
          const title = document.title || "";
          if (externalScripts >= 2 && /官网|官方|下载|客户端/i.test(title) && NS.countTransparentProductPackages(htmlHead) >= 1) return false;
        }
      } catch { /* ignore */ }
      const text = ((document.body && document.body.textContent) || "").replace(/\s+/g, "");
      if (text.length < 48) {
        const scripts = document.scripts ? document.scripts.length : 0;
        const inlineHeavy = Array.from(document.scripts || []).some((s) => !s.src && (s.textContent || "").length > 2000);
        const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
        if (scripts >= 1 && inlineHeavy && ext <= 1) return true;
        if (scripts >= 1 && ext === 0) return true;
        return false;
      }
      if (text.length < 220) {
        const scripts = document.scripts ? document.scripts.length : 0;
        let interactive = 0;
        try { interactive = document.body.querySelectorAll("a[href], button, input, img, video, form, [class*='download']").length; } catch { interactive = 0; }
        const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
        if (scripts >= 1 && interactive < 4 && ext <= 1) return true;
      }
      try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i) || ""; if (/^zhizhu[_-]/i.test(k)) return true; } } catch { /* ignore */ }
      return false;
    } catch { return false; }
  };

  NS.tryEarlyShellProtect = function () {
    try {
      const state = NS.state;
      if (state.downloadGuardInstalled || state._earlyShellArmed) return;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return;
      if (NS.pageLooksLikeLegitimateOfficialDownload()) return;
      try {
        const path = (location.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
        const q = location.search || "";
        if (q.length > 1) {
          if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word)=[^&]+/i.test(q)) return;
          if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|wd|word)=[^&]+/i.test(q)) return;
        }
      } catch { /* ignore */ }
      const title = document.title || "";
      const titleHit = /官网|官方下载|官网下载|客户端下载|下载页面|免费下载|官方正版|官方网站/.test(title);
      let domHit = false;
      try { domHit = !!document.querySelector(".download-uri, a.download-uri, [class~='download-uri']"); } catch { /* ignore */ }
      let uriHit = false;
      try { uriHit = typeof window.download_uri === "string" && window.download_uri.length > 4; } catch { /* ignore */ }
      const thinRelay = NS.pageLooksLikeThinCloakingRelay();
      if (!titleHit && !domHit && !uriHit && !thinRelay) return;
      if (!thinRelay && !domHit && !uriHit) return;
      if (thinRelay && NS.pageLooksLikeLegitimateOfficialDownload()) return;
      state._earlyShellArmed = true;
      NS.armBackgroundProtect("provisional");
    } catch { /* ignore */ }
  };

  /** arm 下载保护 guard：DNR / 包取消 / DOM 禁用 / toast。 */
  NS.installDownloadGuard = function (reason = "检测到可疑安装包下载，已启用文件拦截保护", opts = {}) {
    const state = NS.state;
    NS.silverfoxLog("guard-arm?", "reason=", String(reason || "").slice(0, 120), "kind=", opts.guardKind || "package", "title=", opts.title || "");
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { NS.silverfoxLog("guard-skip", "mature-official"); NS.notifyHooksOfficialSafe(true); return; }
    try {
      const blob = `${reason || ""} ${opts.message || ""} ${opts.title || ""}`;
      const m = blob.match(/([a-z0-9.-]+\.[a-z.]{2,})\s*[≠!=]+\s*([a-z0-9.-]+\.[a-z.]{2,})/i) || blob.match(/盗用\s*([a-z0-9.-]+\.[a-z.]{2,})/i);
      if (m) {
        const left = m[1] || location.hostname;
        const right = m[2] || m[1];
        if (right && (NS.apexSameBrandFamily(left, right) || NS.pageIsSameBrandFamilySite(left, right) || NS.pageIsSameBrandFamilySite(location.hostname, right))) { NS.silverfoxLog("guard-skip", "same-brand-family", left, right); return; }
      }
    } catch { /* ignore */ }
    const hrefOpt = opts.href || "";
    const msgOpt = opts.message || "";
    const messageFilename = NS.normalizeFileName((hrefOpt && NS.getFilenameFromUrl(hrefOpt)) || String(msgOpt).split(/[\s/\\]/).pop() || String(reason).split(/[\s/\\]/).pop() || "");
    const guardKind = opts.guardKind || "package";
    const isIdentityGuard = guardKind === "brand-spoof" || guardKind === "nav-trap" || /仿冒|官网|域名|跳转/i.test(String(reason || "") + String(msgOpt || ""));
    const hrefFn = hrefOpt ? NS.getFilenameFromUrl(hrefOpt) : "";
    if (!isIdentityGuard && hrefOpt && (NS.looksLikeStrongProductInstallerName(hrefFn) || NS.isBenignShortInstallerName(hrefFn) || NS.looksLikeAndroidPackageIdName(hrefFn) || (NS.isContentAddressedPackageName(hrefFn) && !NS.looksLikeHighRiskBlobPackageUrl(hrefOpt) && !NS.looksLikeOversimplifiedBrandInstallerName(hrefFn))) && !NS.looksLikeOversimplifiedBrandInstallerName(hrefFn) && !NS.looksLikeObjectStoragePackageUrl(hrefOpt) && !NS.looksLikeHighRiskBlobPackageUrl(hrefOpt)) return;
    if (!isIdentityGuard && messageFilename && PACKAGE_NAME.test(messageFilename) && (NS.looksLikeStrongProductInstallerName(messageFilename) || NS.looksLikeProductSetupWithBuildId(messageFilename.replace(/\.[^.]+$/, "")) || NS.isBenignShortInstallerName(messageFilename)) && !NS.looksLikeOversimplifiedBrandInstallerName(messageFilename) && !NS.looksLikeHighRiskBlobPackageUrl(hrefOpt || messageFilename)) return;
    try {
      const reasonHref = (String(reason || "").match(/https?:\/\/[^\s"'<>]+/i) || [])[0] || "";
      if (reasonHref && (NS.isAllowlistedProductPackageUrl(reasonHref) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(reasonHref)))) return;
    } catch { /* ignore */ }
    if (guardKind === "brand-spoof" && NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected) { NS.silverfoxLog("guard-skip", "brand-spoof-blocked-by-icp"); NS.clearBrandSpoofFalsePositive("guard-arm-blocked-by-icp"); return; }
    if (guardKind === "brand-spoof" && !NS.hasValidIcpRecord() && !NS.icpSettledForSoftBrandSpoof() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit && !state._remoteGarbleDlDetected && !state._indexNowPhishTemplate) { NS.silverfoxLog("guard-defer", "soft-brand-spoof-wait-icp"); state._pendingSoftBrandSpoof = true; return; }
    NS.silverfoxLog("guard-arm", "ok", String(reason || "").slice(0, 100));
    const firstTime = !state.downloadGuardInstalled;
    if (state.downloadGuardInstalled && !opts.forceNotify && !opts.userAction && opts.notify === false) { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); return; }
    NS.armBackgroundProtect("full");
    NS.armImmediatePackageBlock();
    NS.postToHooks({ type: "set-guard", enabled: true });
    NS.disableSuspiciousDownloadButtons();
    NS.disableAllDownloadIntentControls();
    state.downloadGuardInstalled = true;
    if (guardKind === "brand-spoof") NS.addSignal("已启用仿冒站下载拦截", 10, reason);
    else if (guardKind === "nav-trap") NS.addSignal("已启用异常跳转拦截", 10, reason);
    else NS.addSignal("已启用安装包下载拦截", 12, reason);
    const shouldNotify = opts.notify !== false && (firstTime || opts.forceNotify || !state.protectionNoticeSent || guardKind === "brand-spoof" || guardKind === "nav-trap");
    if (shouldNotify) {
      state.protectionNoticeSent = true;
      const href = opts.href || "";
      const label = opts.message || (href && NS.isPackageFileUrl(href) ? NS.formatPackageLabel(href) : "") || reason || "可疑下载行为";
      const noticeTitle = opts.title || (guardKind === "brand-spoof" ? "已识别仿冒品牌官网" : guardKind === "nav-trap" ? "已拦截异常下载跳转" : "已拦截可疑安装包");
      NS.showGuardOverlay(href, { title: noticeTitle, message: label, toast: true, forceNotify: !!opts.forceNotify || firstTime || guardKind === "brand-spoof" || guardKind === "nav-trap", userAction: !!opts.userAction, guardKind });
    }
    if (!state._guardRedisableArmed) {
      state._guardRedisableArmed = true;
      [400, 2000].forEach((ms) => setTimeout(() => { if (state.downloadGuardInstalled) { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } }, ms));
    }
    NS.emitRiskReport(true);
  };
})(window.SilverfoxContent ??= {});
