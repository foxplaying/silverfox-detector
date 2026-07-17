/**
 * 导航拦截策略：决定是否阻断某 URL 的自动跳转/下载，并记住已拦截 hop。
 * 持有 hops / guard / extraPolicy 状态，组合手势、包分类、SSO、壳层、套件扫描器。
 */
;(function (NS) {
  "use strict";

  const { PackageClassifier, SsoDetector, PageShellDetector } = NS;

  class NavBlocker {
    constructor(gesture, kitScanner, post) {
      this.gesture = gesture;
      this.kitScanner = kitScanner;
      this.post = post;
      this.hops = new Set();
      this.guard = false;
      this.extraPolicy = null;
    }

    setGuard(v) { this.guard = !!v; }
    setCloakingKit(v) {
      this.kitScanner.cloakingKit = !!v;
      if (v) this.guard = true;
    }
    setExtraPolicy(fn) {
      this.extraPolicy = typeof fn === "function" ? fn : null;
    }
    rememberHop(u) { this._remember(u); }

    /** 记住已拦截的 hop（强产品安装包永不 sticky-block）。 */
    _remember(url) {
      const h = PackageClassifier.hrefOf(url);
      if (!h) return;
      if (PackageClassifier.isPkg(h) && PackageClassifier.isStrongProductPkg(h)) return;
      this.hops.add(h);
      try {
        this.hops.add(new URL(h, location.href).href);
      } catch { /* ignore */ }
    }

    /** 是否应阻断该 URL。 */
    shouldBlock(url) {
      const h = PackageClassifier.hrefOf(url).trim();
      if (!h || h.charAt(0) === "#") return false;

      // 强产品安装包永远放行（软 Brand_v4_win 仍在 guard 下拦截）
      if (PackageClassifier.isPkg(h) && PackageClassifier.isStrongProductPkg(h)) return false;
      // 企业 SAML/OAuth 多跳永不拦截
      if (SsoDetector.isAuthSsoRedirectUrl(h)) return false;

      try {
        if (this.hops.has(h) || this.hops.has(new URL(h, location.href).href)) return true;
      } catch {
        if (this.hops.has(h)) return true;
      }
      if (typeof this.extraPolicy === "function") {
        try {
          if (this.extraPolicy(h)) return true;
        } catch { /* ignore */ }
      }

      const noGesture = !this.gesture.hasGesture();
      // 决策前再扫一次套件（脚本可能刚解析完）
      this.kitScanner.scanForCloakingKit(false);
      const phishShell = PageShellDetector.pageLooksLikeDownloadPhishShell();
      const cloakingKit = this.kitScanner.cloakingKit;
      const hostileStrong = this.guard || cloakingKit || phishShell;

      // Guard / 确认套件：阻断所有安装包（强产品除外，模态自动下载）
      if (this.guard || cloakingKit) {
        if (PackageClassifier.isPkg(h)) return !PackageClassifier.isStrongProductPkg(h);
        if (noGesture && PackageClassifier.isSearchTrap(h)) return true;
        if (noGesture && PackageClassifier.crossOrigin(h) && cloakingKit) return true;
        return false;
      }

      // Guard 关闭：阻断自动乱码包；放行清晰产品 / 短 CDN / 哈希包
      if (noGesture && PackageClassifier.isPkg(h)) {
        if (PackageClassifier.isClearProductPkg(h)) return false;
        try {
          let name = "";
          try {
            name = (new URL(h, location.href).pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
          } catch {
            name = String(h || "").split("?")[0].split("/").pop() || "";
          }
          const base = name.replace(/\.[^.]+$/, "");
          // 内容寻址：纯 hex / 资源号_哈希（如 105065437_ecfe…bc97.exe）
          if ((/^[a-f0-9]{16,64}$/i.test(base)
            || /^\d{4,20}[._-][a-f0-9]{16,64}$/i.test(base)
            || /^[a-f0-9]{16,64}[._-]\d{4,20}$/i.test(base)) && !hostileStrong) return false;
        } catch { /* ignore */ }
        return true;
      }

      if (noGesture && PackageClassifier.isSearchTrap(h)) return true; // 无手势 SERP 跳转
      if (noGesture && PackageClassifier.crossOrigin(h) && hostileStrong) return true;
      return false;
    }

    /** 执行拦截：记住 hop、发 blocked-download、按包/跳转发 guard+signal。 */
    tryBlock(url, reason) {
      if (!this.shouldBlock(url)) return false;
      const h = PackageClassifier.hrefOf(url);
      this._remember(h);
      this.post({ type: "blocked-download", href: h, reason: reason || "nav-boot-block" });
      if (PackageClassifier.isPkg(h)) {
        this.post({ type: "request-guard", reason: `非用户手势自动下载: ${(h || "").slice(0, 160)}` });
        this.post({ type: "signal", name: "非用户手势自动下载", weight: 14, reason: `early-nav-boot: ${(h || "").slice(0, 200)}` });
      } else {
        // 伪装跳转：arm 页面保护，后续 hop 仍被拦
        this.post({ type: "request-guard", reason: `非用户手势自动跳转: ${(h || "").slice(0, 160)}` });
        this.post({ type: "signal", name: "非用户手势自动跳转", weight: 12, reason: `early-nav-boot: ${(h || "").slice(0, 200)}` });
      }
      return true;
    }
  }

  NS.NavBlocker = NavBlocker;
})(window.SilverfoxNavBoot ??= {});
