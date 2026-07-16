/**
 * page-hooks 入口：MAIN-world 第二脚本，升级 nav-boot 策略并安装其余原型钩子。
 *
 * 职责：download_uri、动态 href、远程 API 绑定、点击拦截、DOM 注入守卫。
 * nav-boot 已先安装 Location 锁；本文件升级策略并补齐其余 hook。
 */
;(function (NS) {
  "use strict";

  if (window.__silverfoxPageHooksInstalled) return;

  // 仅 hook http(s) 页面
  try {
    const p = String(location.protocol || "").toLowerCase();
    if (p !== "http:" && p !== "https:") return;
  } catch { return; }

  const { PackageHeuristics, PageContext, DownloadUi, DomGuard, NavPolicy } = NS;
  const CONTENT_SOURCE = "silverfox-detector-content";

  /** 向 content (isolated) 发消息。 */
  function post(payload) {
    try { window.postMessage({ source: "silverfox-detector-hooks", ...payload }, "*"); } catch { /* ignore */ }
  }

  class PageHooks {
    constructor() {
      this.policy = new NavPolicy(post);
      this.restoreList = [];
      // document_start：URL-only light（在任何 wrap 抖动前）
      try { if (PageContext.isSearchUrlShapeOnly()) this.policy.lightPage = true; } catch { /* ignore */ }
    }

    /** 搜索页 no-op：不装任何原型 wrap，仅监听 content 消息。 */
    installSearchLight() {
      window.__silverfoxPageHooksInstalled = true;
      window.__silverfoxSearchLight = true;
      try {
        window.addEventListener("message", (event) => {
          if (event.source !== window) return;
          const data = event.data;
          if (!data || data.source !== CONTENT_SOURCE) return;
          // 忽略 set-guard / set-official-safe -- 搜索页永不 arm 下载拦截
        });
      } catch { /* ignore */ }
      try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    }

    install() {
      window.__silverfoxPageHooksInstalled = true;

      // 同步策略到 nav-boot（boot 可能已 patch location）
      this.policy.syncNavBoot();
      try { setTimeout(() => this.policy.syncNavBoot(), 0); setTimeout(() => this.policy.syncNavBoot(), 50); setTimeout(() => this.policy.syncNavBoot(), 200); setTimeout(() => this.policy.syncNavBoot(), 500); } catch { /* ignore */ }

      // DOM 原型 wrap（fetch / createElement / href / click / src / setAttribute / insert*）
      DomGuard.install(this.policy, this.restoreList);
      // 实时 scrub + 已有套件扫描 + download_uri 陷阱
      DomGuard.installLiveScrub(this.policy);
      DomGuard.scanExisting(this.policy);
      DomGuard.installDownloadUriTrap(this.policy);

      // 点击拦截（捕获阶段）
      this._installClickInterceptor();
      // Location / window.open / Navigation API fallback（nav-boot 未装时）
      this._installLocationFallback();
      this._installNavigationApiPatch();
      // meta refresh + programmatic click
      this._installMetaRefreshStrip();
      this._installProgrammaticClickPatch();
      // 搜索框聚焦 -> light（建议列表即将爆炸 DOM）
      this._installSearchFocusPromote();
      // content -> MAIN 消息桥
      this._installContentBridge();

      try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    }

    _installClickInterceptor() {
      const policy = this.policy;
      const onUserActivate = (event) => {
        if (event && typeof event.button === "number" && event.button !== 0) return; // 右键原生菜单
        if (event && event.type === "contextmenu") return;
        if (policy.lightPage || policy.officialSafe || policy.isLightPage()) return;
        const t = event.target;
        if (!t || typeof t.closest !== "function") return;
        try {
          const tag = (t.tagName || "").toUpperCase();
          if (tag === "INPUT" || tag === "TEXTAREA" || t.isContentEditable) return; // 搜索框输入
        } catch { /* ignore */ }
        const el = t.closest("a, button, [role='button'], .download-btn, .download-btn-nav, .btn-download, #mainDownloadBtn");
        if (!el) return;
        const href = (el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-threat-original-href") || "").trim();

        // SERP：永不拦截出站结果点击
        if (PageContext.pageLooksLikeSerpUrl()) {
          if (!href || !PackageHeuristics.isPackageFileUrl(href)) return;
        }
        if (href && (PackageHeuristics.isStrongProductInstallerUrl(href) || PackageHeuristics.isSameApexOfficialDownloadPath(href))) return;

        // guard 开：阻断所有下载意图 UI（SERP 除外）
        if (PageContext.pageLooksLikeSerpUrl()) {
          /* SERP 跳过 guard UI 阻断 */
        } else if (policy.guardEnabled && !policy.officialSafe && DownloadUi.isDownloadIntentText(el)) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation();
          DownloadUi.greyOut(el);
          policy.post({ type: "blocked-download", href: href || [...policy.blockedHops][0] || "js-download", reason: "guard-block-download-button" });
          return;
        }

        if (!href || href === "#") {
          // 无 href 下载按钮：guard 或已记住 hop 时阻断
          if (DownloadUi.isDownloadIntentText(el) && (policy.guardEnabled || policy.blockedHops.size > 0) && !policy.officialSafe) {
            let onlyStrong = policy.blockedHops.size > 0;
            try {
              for (const h of policy.blockedHops) {
                if (PackageHeuristics.isPackageFileUrl(h) && !PackageHeuristics.isStrongProductInstallerUrl(h)) { onlyStrong = false; break; }
                if (!PackageHeuristics.isPackageFileUrl(h) && PackageHeuristics.looksLikeOpaqueDownloadHopUrl(h)) { onlyStrong = false; break; }
              }
            } catch { onlyStrong = false; }
            if (onlyStrong && !policy.guardEnabled) return;
            if (policy.guardEnabled || !onlyStrong) {
              event.preventDefault();
              event.stopPropagation();
              event.stopImmediatePropagation();
              DownloadUi.greyOut(el);
              policy.post({ type: "request-guard", reason: "下载按钮已绑定可疑远程地址" });
            }
          }
          return;
        }
        if (policy._tryBlock(href, `page-click -> ${href}`) || policy.tryBlockNavigation(href, `page-click-nav -> ${href}`)) {
          event.preventDefault();
          event.stopPropagation();
          event.stopImmediatePropagation();
          DownloadUi.greyOut(el);
        }
      };

      try {
        if (!this.policy.lightPage && !PageContext.isSearchUrlShapeOnly()) {
          document.addEventListener("mousedown", onUserActivate, true);
          document.addEventListener("click", onUserActivate, true);
          document.addEventListener("pointerdown", onUserActivate, true);
        }
      } catch { /* ignore */ }
    }

    _installLocationFallback() {
      // nav-boot 已装 Location/open；仅 boot 未运行时兜底
      if (window.__silverfoxNavBootInstalled) return;
      const policy = this.policy;
      const installLocationHooks = (LocationCtor) => {
        if (!LocationCtor || !LocationCtor.prototype) return;
        const proto = LocationCtor.prototype;
        try {
          const origAssign = proto.assign;
          if (origAssign && !proto.__silverfoxAssignPatched) {
            proto.__silverfoxAssignPatched = true;
            proto.assign = function (url) {
              if (policy.tryBlockNavigation(url, `location.assign -> ${PackageHeuristics.coerceHref(url)}`)) return;
              return origAssign.call(this, url);
            };
          }
        } catch { /* ignore */ }
        try {
          const origReplace = proto.replace;
          if (origReplace && !proto.__silverfoxReplacePatched) {
            proto.__silverfoxReplacePatched = true;
            proto.replace = function (url) {
              if (policy.tryBlockNavigation(url, `location.replace -> ${PackageHeuristics.coerceHref(url)}`)) return;
              return origReplace.call(this, url);
            };
          }
        } catch { /* ignore */ }
        try {
          const hrefDesc = Object.getOwnPropertyDescriptor(proto, "href");
          if (hrefDesc && hrefDesc.set && !proto.__silverfoxHrefPatched) {
            proto.__silverfoxHrefPatched = true;
            Object.defineProperty(proto, "href", {
              configurable: true, enumerable: true,
              get() { return hrefDesc.get.call(this); },
              set(v) {
                if (policy.tryBlockNavigation(v, `location.href -> ${PackageHeuristics.coerceHref(v)}`)) return;
                return hrefDesc.set.call(this, v);
              }
            });
          }
        } catch { /* ignore */ }
      };
      try { installLocationHooks(window.Location || Location); } catch { /* ignore */ }
      try {
        const origOpen = window.open.bind(window);
        if (!window.__silverfoxOpenPatched) {
          window.__silverfoxOpenPatched = true;
          window.open = function (...args) {
            const target = args[0];
            if (target != null && target !== "" && policy.tryBlockNavigation(target, `window.open -> ${PackageHeuristics.coerceHref(target)}`)) return null;
            return origOpen(...args);
          };
        }
      } catch { /* ignore */ }
    }

    _installNavigationApiPatch() {
      try {
        if (typeof navigation !== "undefined" && navigation.navigate && !navigation.__silverfoxNavPatched) {
          navigation.__silverfoxNavPatched = true;
          const origNav = navigation.navigate.bind(navigation);
          navigation.navigate = function (url, options) {
            if (this.policy.tryBlockNavigation(url, `navigation.navigate -> ${PackageHeuristics.coerceHref(url)}`)) {
              try { return origNav(location.href, { ...options, history: "replace" }); } catch { return undefined; }
            }
            return origNav(url, options);
          }.bind(this);
        }
      } catch { /* ignore */ }
    }

    _installMetaRefreshStrip() {
      const policy = this.policy;
      const stripHostileMetaRefresh = (root) => {
        if (policy.isLightPage() || policy.officialSafe) return;
        try {
          const scope = root || document;
          scope.querySelectorAll('meta[http-equiv="refresh"], meta[http-equiv="Refresh"]').forEach((meta) => {
            const content = meta.getAttribute("content") || "";
            const m = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
            const target = m ? m[1] : "";
            if (target && policy.tryBlockNavigation(target, `meta-refresh -> ${target}`)) {
              meta.remove();
            } else if (!policy.isUserGestureActive() && target && PackageHeuristics.isCrossOrigin(target) && PageContext.pageLooksLikeDownloadPhishShell()) {
              meta.remove();
              policy._emitAutoNavBlock(target, `meta-refresh-strip -> ${target}`, "非用户手势自动跳转");
            }
          });
        } catch { /* ignore */ }
      };
      try {
        if (!policy.isLightPage()) {
          stripHostileMetaRefresh(document);
          let metaKick = null;
          const mo = new MutationObserver((mutations) => {
            if (policy.isLightPage() || policy.officialSafe) return;
            if (metaKick) return;
            let need = false;
            for (const m of mutations) {
              if (!m.addedNodes) continue;
              for (let i = 0; i < m.addedNodes.length; i++) {
                const n = m.addedNodes[i];
                if (n && n.nodeType === 1 && n.tagName === "META") { need = true; break; }
              }
              if (need) break;
            }
            if (!need) return;
            metaKick = setTimeout(() => { metaKick = null; try { stripHostileMetaRefresh(document); } catch { /* ignore */ } }, 150);
          });
          mo.observe(document.documentElement || document, { childList: true, subtree: true });
          setTimeout(() => { try { mo.disconnect(); } catch { /* ignore */ } }, 6000);
        }
      } catch { /* ignore */ }
    }

    _installProgrammaticClickPatch() {
      const policy = this.policy;
      try {
        const origClick = HTMLElement.prototype.click;
        if (origClick && !HTMLElement.prototype.__silverfoxClickPatched) {
          HTMLElement.prototype.__silverfoxClickPatched = true;
          HTMLElement.prototype.click = function (...args) {
            try {
              if (this && this.tagName === "A") {
                const href = this.getAttribute("href") || this.href || "";
                if (policy.tryBlockNavigation(href, `programmatic-a.click -> ${href}`)) return; // 合成点击非新用户手势
              }
              if ((policy.guardEnabled || policy.forceDesktopDlKit) && !policy.officialSafe) {
                if (this && this.tagName === "A") {
                  const href2 = this.getAttribute("href") || this.href || "";
                  if (href2 && PackageHeuristics.isPackageFileUrl(href2) && !PackageHeuristics.isStrongProductInstallerUrl(href2)) {
                    policy._rememberHop(href2);
                    policy._emitBlocked(href2, "programmatic-a-package-click");
                    return;
                  }
                }
                if (this && DownloadUi.isDownloadIntentText(this)) {
                  try {
                    DownloadUi.greyOut(this);
                    policy.post({ type: "blocked-download", href: (this.getAttribute && (this.getAttribute("href") || this.getAttribute("data-href"))) || "js-download", reason: "guard-block-programmatic-click" });
                  } catch { /* ignore */ }
                  return;
                }
              }
            } catch { /* ignore */ }
            return origClick.apply(this, args);
          };
        }
      } catch { /* ignore */ }
    }

    _installSearchFocusPromote() {
      const policy = this.policy;
      try {
        const promoteSearchFocus = (e) => {
          if (policy.lightPage || policy.officialSafe) return;
          try {
            const t = e && e.target;
            if (!t || t.nodeType !== 1) return;
            const tag = (t.tagName || "").toUpperCase();
            if (tag !== "INPUT" && tag !== "TEXTAREA") return;
            const type = (t.getAttribute("type") || "").toLowerCase();
            const name = (t.getAttribute("name") || "").toLowerCase();
            const role = (t.getAttribute("role") || "").toLowerCase();
            if (type === "search" || name === "q" || name === "wd" || name === "word" || name === "query" || name === "search" || name === "text"
              || t.getAttribute("aria-autocomplete") || role === "searchbox" || role === "combobox") {
              policy.markLightPage();
            }
          } catch { /* ignore */ }
        };
        document.addEventListener("focusin", promoteSearchFocus, true);
        document.addEventListener("pointerdown", promoteSearchFocus, true);
      } catch { /* ignore */ }
    }

    _installContentBridge() {
      const policy = this.policy;
      window.addEventListener("message", (event) => {
        if (event.source !== window) return;
        const data = event.data;
        if (!data || data.source !== CONTENT_SOURCE) return;
        if (data.type === "set-official-safe" || data.type === "set-light-page") {
          if (data.type === "set-official-safe") policy.officialSafe = !!data.enabled;
          if (data.type === "set-light-page" && data.enabled) policy.lightPage = true;
          if (policy.officialSafe) {
            policy.guardEnabled = false;
            policy.lightPage = true;
            try { if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.setGuard === "function") window.__silverfoxNavApi.setGuard(false); } catch { /* ignore */ }
          }
          if (policy.lightPage || policy.officialSafe) {
            try { DomGuard.restoreNativeDomProtos(this.restoreList); } catch { /* ignore */ }
          }
          return;
        }
        if (data.type === "set-guard") {
          if (policy.officialSafe && data.enabled) {
            policy.guardEnabled = false;
            try { if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.setGuard === "function") window.__silverfoxNavApi.setGuard(false); } catch { /* ignore */ }
            DownloadUi.restoreAllDownloadButtonsInPage();
            return;
          }
          policy.guardEnabled = !!data.enabled;
          try { if (window.__silverfoxNavApi && typeof window.__silverfoxNavApi.setGuard === "function") window.__silverfoxNavApi.setGuard(policy.guardEnabled); } catch { /* ignore */ }
          policy.syncNavBoot();
          if (policy.guardEnabled) {
            DownloadUi.disableAllDownloadButtonsInPage();
            [50, 200, 500, 1200, 3000].forEach((ms) => setTimeout(DownloadUi.disableAllDownloadButtonsInPage, ms));
            try {
              if (!window.__silverfoxGuardMo && typeof MutationObserver !== "undefined") {
                window.__silverfoxGuardMo = new MutationObserver(() => {
                  if (!policy.guardEnabled) return;
                  DownloadUi.disableAllDownloadButtonsInPage();
                });
                window.__silverfoxGuardMo.observe(document.documentElement || document.body, { childList: true, subtree: true });
                setTimeout(() => { try { if (window.__silverfoxGuardMo) { window.__silverfoxGuardMo.disconnect(); window.__silverfoxGuardMo = null; } } catch { /* ignore */ } }, 15000);
              }
            } catch { /* ignore */ }
          } else {
            try { if (window.__silverfoxGuardMo) { window.__silverfoxGuardMo.disconnect(); window.__silverfoxGuardMo = null; } } catch { /* ignore */ }
            DownloadUi.restoreAllDownloadButtonsInPage();
            [50, 200, 600].forEach((ms) => setTimeout(DownloadUi.restoreAllDownloadButtonsInPage, ms));
          }
        }
      });
    }
  }

  NS.PageHooks = PageHooks;

  const hooks = new PageHooks();
  if (PageContext.isSearchUrlShapeEarly()) {
    hooks.installSearchLight();
  } else {
    hooks.install();
  }
})(window.SilverfoxPageHooks ??= {});
