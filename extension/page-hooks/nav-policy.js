/**
 * 导航拦截策略：决定是否阻断 JS 跳转/下载，并记住已拦截 hop。
 * 持有 guardEnabled / officialSafe / lightPage / forceDesktopDlKit / blockedHops 状态。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristics, PageContext, CloakingKit, DownloadUi } = NS;
  const SOURCE = "silverfox-detector-hooks";
  const USER_GESTURE_MS = 2500;
  const CHAIN_GESTURE_MS = 20000;
  const GESTURE_SS_KEY = "__silverfox_ug_at";

  class NavPolicy {
    constructor(post) {
      this.post = post;
      this.guardEnabled = false;
      this.officialSafe = false;
      this.lightPage = false;
      this.forceDesktopDlKit = false;
      this.cloakingKitFlag = false;
      this.blockedHops = new Set();
      this.lastTrustedGestureAt = 0;
      if (PageContext.hostIsMajorPlatformOrigin()) {
        this.lightPage = true;
        this.officialSafe = true;
      }
      this._installGestureListeners();
    }

    _installGestureListeners() {
      const mark = (e) => this._markTrustedGesture(e);
      ["pointerdown", "mousedown", "click", "touchstart"].forEach((type) => {
        try { window.addEventListener(type, mark, true); document.addEventListener(type, mark, true); } catch { /* ignore */ }
      });
      try { window.addEventListener("keydown", mark, true); } catch { /* ignore */ }
    }

    _persistGestureAt(ts) {
      try { sessionStorage.setItem(GESTURE_SS_KEY, String(ts)); } catch { /* ignore */ }
    }

    _readChainGestureAt() {
      try {
        const n = parseInt(sessionStorage.getItem(GESTURE_SS_KEY) || "0", 10);
        return Number.isFinite(n) ? n : 0;
      } catch { return 0; }
    }

    _markTrustedGesture(event, persist) {
      try {
        if (event && event.isTrusted === false) return;
        this.lastTrustedGestureAt = Date.now();
        if (persist !== false) this._persistGestureAt(this.lastTrustedGestureAt);
      } catch {
        this.lastTrustedGestureAt = Date.now();
        if (persist !== false) this._persistGestureAt(this.lastTrustedGestureAt);
      }
    }

    /** 优先用 nav-boot 的手势时钟（含跨文档链）。 */
    isUserGestureActive() {
      try {
        if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.hasGesture === "function") return window.__silverfoxNavApi.hasGesture();
      } catch { /* fall through */ }
      try {
        if (typeof navigator !== "undefined" && navigator.userActivation && navigator.userActivation.isActive) return true;
      } catch { /* ignore */ }
      const now = Date.now();
      if (now - this.lastTrustedGestureAt < USER_GESTURE_MS) return true;
      const chainAt = this._readChainGestureAt();
      if (chainAt > 0 && now - chainAt < CHAIN_GESTURE_MS) return true;
      return false;
    }

    isAuthSsoRedirectUrl(url) {
      try {
        if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.isAuthSsoRedirectUrl === "function") return window.__silverfoxNavApi.isAuthSsoRedirectUrl(url);
      } catch { /* fall through */ }
      try {
        const u = new URL(String(url || ""), location.href);
        if (!/^https?:$/i.test(u.protocol)) return false;
        const path = (u.pathname || "").toLowerCase();
        const host = (u.hostname || "").toLowerCase();
        const q = u.search || "";
        if (PackageHeuristics.PACKAGE_EXT.test(path) || PackageHeuristics.PACKAGE_EXT.test(u.href)) return false;
        if (/\/(?:saml2?|sso|oauth2?|oidc|openid(?:-connect)?|adfs|cas|idp)(?:\/|$)/i.test(path)) return true;
        if (/\/default\/saml\//i.test(path) || /\/idp\/(?:sso|login|profile|start)/i.test(path)) return true;
        if (/\/oauth2?\/(?:v\d+\/)?(?:authorize|auth|token|logout)/i.test(path)) return true;
        if (/\/(?:login|signin|sign-in|logon|authenticate)(?:\/|$)/i.test(path) && /[?&](?:SAMLRequest|SAMLResponse|RelayState|client_id|response_type|redirect_uri|code_challenge|scope)=/i.test(q)) return true;
        if (/(?:^|\.)(?:login|sso|auth|accounts|access|idp|sts|adfs|signin)\./i.test(host) && /saml|sso|oauth|openid|authorize|idp|login|auth/i.test(path + q)) return true;
        if (/(?:^|\.)(?:okta\.com|auth0\.com|microsoftonline\.com|windows\.net|google\.com|onelogin\.com|pingidentity\.com|duo\.com|cloudflareaccess\.com)$/i.test(host)) return true;
        return false;
      } catch {
        return false;
      }
    }

    isLightPage() {
      if (this.officialSafe || this.lightPage) return true;
      try {
        if (PageContext.isSearchUrlShapeOnly() || PageContext.pageLooksLikeSerpUrl()) { this.lightPage = true; return true; }
      } catch { /* ignore */ }
      return false;
    }

    markLightPage() { this.lightPage = true; }

    _shouldBlockUrl(href) {
      if (!href || typeof href !== "string") return false;
      if (/^\s*#/.test(href) || href.trim() === "") return false;
      if (PackageHeuristics.isStrongProductInstallerUrl(href)) return false;
      try {
        const abs = new URL(href, location.href).href;
        if (this.blockedHops.has(href) || this.blockedHops.has(abs)) return true;
      } catch {
        if (this.blockedHops.has(href)) return true;
      }
      if (PackageHeuristics.isSiteHomeUrl(href) && !PackageHeuristics.isPackageFileUrl(href)) return false;
      if (PackageHeuristics.looksLikeOpaqueDownloadHopUrl(href)) return true;
      if (!PackageHeuristics.isPackageFileUrl(href)) return false;
      try {
        const fileName = PackageHeuristics.getFilenameFromUrl(href);
        const baseName = (fileName || "").replace(/\.[^.]+$/, "");
        const strongProduct = PackageHeuristics.isStrongProductInstallerUrl(href);
        const clearPkg = PackageHeuristics.looksLikeProductPackageName(fileName)
          || PackageHeuristics.isBenignShortInstallerName(fileName)
          || PackageHeuristics.looksLikeAndroidPackageIdName(fileName)
          || PackageHeuristics.looksLikeAndroidPackageIdName(baseName)
          || strongProduct;
        if (this.guardEnabled && PackageHeuristics.isPackageFileUrl(href) && !strongProduct) return true;
        if (strongProduct) return false;
        if (clearPkg && !PackageHeuristics.isSuspiciousPackageFilename(fileName)) {
          if (PackageHeuristics.looksLikeObjectStoragePackageUrl(href) || PackageHeuristics.looksLikeHighRiskBlobPackageUrl(href)) return true;
          return false;
        }
        if (PackageHeuristics.looksLikeHighRiskBlobPackageUrl(href)) return true;
        try {
          if (PackageHeuristics.isAnonymousPublicObjectHost(new URL(href, location.href).hostname)) return true;
        } catch { /* ignore */ }
        if (PackageHeuristics.looksLikeObjectStoragePackageUrl(href)) {
          try { if (PackageHeuristics.isAnonymousPublicObjectHost(new URL(href, location.href).hostname)) return true; } catch { /* ignore */ }
          if (this.guardEnabled) return true;
          return true;
        }
        const highConfidence = PackageHeuristics.isSuspiciousPackageFilename(fileName)
          || (PackageHeuristics.looksLikeHiddenPackagePath(href) && !PackageHeuristics.looksLikeProductPackageName(fileName));
        if (highConfidence) return true;
        if (!this.guardEnabled) return false;
        const u = new URL(href, location.href);
        const path = u.pathname.toLowerCase();
        if (/\.php(?:\/|$)/i.test(path) && PackageHeuristics.PACKAGE_EXT.test(u.href)) {
          if (/\/([a-f0-9]{10,}|[a-z0-9_-]{12,})\//i.test(path) || fileName.length >= 16) return true;
        }
        if (/\/(?:ins\d+|id\d+|[a-f0-9]{10,})\//i.test(path) && PackageHeuristics.PACKAGE_EXT.test(path)) return true;
        return false;
      } catch {
        return false;
      }
    }

    _emitBlocked(href, reason) {
      this.post({ type: "blocked-download", href: href || "", reason: reason || "" });
    }

    _rememberHop(url) {
      if (!url) return;
      if (PackageHeuristics.isClearOrStrongProductPackageUrl(url)) return;
      this.blockedHops.add(url);
      try { this.blockedHops.add(new URL(url, location.href).href); } catch { /* ignore */ }
      try {
        if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.rememberHop === "function") window.__silverfoxNavApi.rememberHop(url);
      } catch { /* ignore */ }
    }

    _tryBlock(href, reason) {
      if (!this._shouldBlockUrl(href)) return false;
      this._rememberHop(href);
      this._emitBlocked(href, reason);
      return true;
    }

    _emitAutoNavBlock(href, reason, signalName) {
      this._rememberHop(href);
      this._emitBlocked(href, reason);
      this.post({ type: "request-guard", reason: `非用户手势自动跳转: ${(href || "").slice(0, 160)}` });
      this.post({ type: "signal", name: signalName || "非用户手势自动跳转", weight: 14, reason: `脚本在无用户点击时触发跳转/下载: ${(href || "").slice(0, 200)}` });
    }

    /** 桌面强制下载套件 arm：置 flag、scrub DOM、灰按钮、发 guard+signal。 */
    armDesktopForceDownloadKit(reason) {
      if (this.officialSafe) return;
      const first = !this.forceDesktopDlKit;
      this.forceDesktopDlKit = true;
      this.guardEnabled = true;
      try {
        if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.setGuard === "function") window.__silverfoxNavApi.setGuard(true);
      } catch { /* ignore */ }
      DomGuard.scrubDesktopForceDownloadDom();
      DownloadUi.disableAllDownloadButtonsInPage();
      if (first) {
        this.post({ type: "request-guard", reason: reason || "桌面端强制弹窗下载套件 (dlp)" });
        this.post({ type: "signal", name: "桌面端强制弹窗下载", weight: 24, reason: reason || "dlp-overlay + auto zip download kit" });
        [100, 300, 800, 2000, 5000].forEach((ms) => setTimeout(() => { if (this.forceDesktopDlKit) DomGuard.scrubDesktopForceDownloadDom(); }, ms));
      }
    }

    /**
     * 阻断 JS 跳转/下载。
     * - guard 开：所有安装包拉取（timer/modal/a.click/location）除强产品外
     * - 无手势：自动包 / SERP 跳转
     * - 下载空壳或薄跳板或 guard：无手势跨域跳转
     */
    tryBlockNavigation(url, reason) {
      if (url == null || url === "") return false;
      const href = PackageHeuristics.coerceHref(url).trim();
      if (!href) return false;
      if (/^\s*#/.test(href)) return false;
      if (this.isAuthSsoRedirectUrl(href)) return false;
      if (PackageHeuristics.isSameApexOfficialDownloadPath(href)) return false;
      if (PackageHeuristics.isStrongProductInstallerUrl(href)) return false;
      if (this.officialSafe && !this._pageHasCloakingKit() && PackageHeuristics.isStrongProductInstallerUrl(href)) return false;
      const kit = this._pageHasCloakingKit();
      const phishShell = PageContext.pageLooksLikeDownloadPhishShell();
      const cloakingRelay = PageContext.pageLooksLikeCloakingRelay(this.cloakingKitFlag);
      const hostile = this.guardEnabled || kit || phishShell || (cloakingRelay && kit);

      // guard / 桌面套件：阻断所有安装包拉取
      if ((this.guardEnabled || this.forceDesktopDlKit) && !this.officialSafe) {
        if (PackageHeuristics.isPackageFileUrl(href) || PackageHeuristics.looksLikeOpaqueDownloadHopUrl(href)
          || PackageHeuristics.looksLikeDownloadOrPackageNav(href) || PackageHeuristics.looksLikeObjectStoragePackageUrl(href)) {
          if (!PackageHeuristics.isStrongProductInstallerUrl(href) && !PackageHeuristics.isSameApexOfficialDownloadPath(href)) {
            this._rememberHop(href);
            this._emitBlocked(href, `guard-block-all-download -> ${reason || href}`);
            this.post({ type: "request-guard", reason: `保护模式下拦截下载: ${(href || "").slice(0, 160)}` });
            this.post({ type: "signal", name: "已拦截页面下载拉取", weight: 12, reason: `guard: ${(href || "").slice(0, 200)}` });
            return true;
          }
        }
      }

      if (href.toLowerCase() === "about:blank") {
        if (!this.isUserGestureActive() && hostile) {
          this._emitAutoNavBlock(href, `auto-blank -> ${reason}`, "非用户手势自动跳转");
          return true;
        }
        return false;
      }

      if (this._tryBlock(href, reason)) return true;
      if (!PackageHeuristics.isCrossOrigin(href) && !PackageHeuristics.looksLikeDownloadOrPackageNav(href)) return false;

      if (!this.isUserGestureActive()) {
        if (PackageHeuristics.looksLikeDownloadOrPackageNav(href)) {
          if (PackageHeuristics.isStrongProductInstallerUrl(href)) return false;
          try {
            const fn = PackageHeuristics.getFilenameFromUrl(href);
            const base = (fn || "").replace(/\.[^.]+$/, "");
            if (/^[a-f0-9]{16,64}$/i.test(base) && !PackageHeuristics.isSuspiciousPackageFilename(fn)) return false;
          } catch { /* ignore */ }
          if (this.officialSafe && !kit && !this.guardEnabled) return false;
          this._emitAutoNavBlock(href, `auto-nav-no-gesture -> ${reason || href}`, "非用户手势自动下载");
          return true;
        }
        if (PackageHeuristics.isSearchEngineTrapRedirect(href)) {
          this._emitAutoNavBlock(href, `auto-search-trap -> ${reason || href}`, "非用户手势搜索引擎跳转");
          return true;
        }
        if (hostile && PackageHeuristics.isCrossOrigin(href)) {
          this._emitAutoNavBlock(href, `kit-or-relay-auto-external -> ${reason || href}`, "非用户手势跨域跳转");
          return true;
        }
      }
      return false;
    }

    _pageHasCloakingKit() {
      if (this.cloakingKitFlag) return true;
      if (PageContext.pageLooksLikeOfficialDownloadPayload()) return false;
      try {
        if (typeof window.zhizhuDebug === "object" && window.zhizhuDebug) { this.cloakingKitFlag = true; return true; }
      } catch { /* ignore */ }
      try {
        for (let i = 0; i < localStorage.length; i++) {
          if (/^zhizhu[_-]/i.test(localStorage.key(i) || "")) { this.cloakingKitFlag = true; return true; }
        }
      } catch { /* ignore */ }
      try {
        let blob = "";
        const scripts = document.scripts || [];
        const maxScripts = Math.min(scripts.length, 30);
        for (let i = 0; i < maxScripts && blob.length < 80000; i++) {
          if (scripts[i].src) continue;
          const t = scripts[i].textContent || "";
          if (t.length >= 80) blob += `${t.slice(0, 6000)}\n`;
        }
        if (CloakingKit.scoreCloakingKitBlob(blob) >= 10) {
          if (PageContext.pageLooksLikeOfficialDownloadPayload()) return false;
          this.cloakingKitFlag = true;
          return true;
        }
      } catch { /* ignore */ }
      return false;
    }

    /** 把完整策略同步进 nav-boot（若 boot 已 patch location）。 */
    syncNavBoot() {
      try {
        const api = window.__silverfoxNavApi;
        if (!api) return;
        if (typeof api.setGuard === "function") api.setGuard(this.guardEnabled);
        if (typeof api.setExtraPolicy === "function") {
          // 避免递归：extraPolicy 不得再调 nav-boot tryBlock
          api.setExtraPolicy((href) => this._extraPolicy(href));
        }
      } catch { /* ignore */ }
    }

    _extraPolicy(href) {
      try {
        if (!href) return false;
        if (PackageHeuristics.isClearOrStrongProductPackageUrl(href)) return false;
        if (PackageHeuristics.isSameApexOfficialDownloadPath(href)) return false;
        if (this.isAuthSsoRedirectUrl(href)) return false;
        if (this.isUserGestureActive()) return false;
        if (this.blockedHops.has(href)) return true;
        try { if (this.blockedHops.has(new URL(href, location.href).href)) return true; } catch { /* ignore */ }
        if (PackageHeuristics.looksLikeOpaqueDownloadHopUrl(href)) return true;
        const phish = PageContext.pageLooksLikeDownloadPhishShell();
        const kit = this._pageHasCloakingKit();
        const hostile = this.guardEnabled || phish || kit;
        if (hostile && PackageHeuristics.isSearchEngineTrapRedirect(href)) return true;
        if (hostile && PackageHeuristics.isCrossOrigin(href) && !PackageHeuristics.isPackageFileUrl(href) && !this.isAuthSsoRedirectUrl(href)) return true;
        return false;
      } catch {
        return false;
      }
    }
  }

  // 前向引用：DomGuard 在后面定义，运行时已存在
  let DomGuard;
  NS.NavPolicy = NavPolicy;
  NS._setDomGuard = (cls) => { DomGuard = cls; };
})(window.SilverfoxPageHooks ??= {});
