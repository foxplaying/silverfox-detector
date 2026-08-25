/**
 * nav-boot 入口：组合各模块，安装最早的 Location 钩子与套件扫描。
 *
 * MAIN world, document_start - 首个 content script。
 * 必须在首 tick 安装 Location 钩子，使页面脚本看到 patched Location。
 * （Chrome 在页面 JS 之前注入 document_start MAIN 脚本。）
 */
;(function (NS) {
  "use strict";

  if (window.__silverfoxNavBootInstalled) return;

  // 仅 hook http(s) 页面 -- 永不 chrome:// / file:// / about: / 扩展页
  try {
    const p = String(location.protocol || "").toLowerCase();
    if (p !== "http:" && p !== "https:") return;
  } catch {
    return;
  }

  // 本机/局域网管理台（AdGuard Home、路由器等）：不装 Location/导航钩子，避免干扰 SPA
  function isPrivateOrLocalHost() {
    try {
      const h = String(location.hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
      if (!h) return false;
      if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "0.0.0.0") return true;
      if (h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".home.arpa")) return true;
      if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
      if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
      if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
      if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
      if (/^fe80:/i.test(h) || /^f[cd][0-9a-f]{0,2}:/i.test(h)) return true;
      return false;
    } catch { return false; }
  }
  if (isPrivateOrLocalHost()) {
    window.__silverfoxNavBootInstalled = true;
    window.__silverfoxPrivateLocalLight = true;
    window.__silverfoxNavApi = {
      setGuard() {},
      setOfficialSafe() {},
      setCloakingKit() {},
      rememberHop() {},
      clearHops() {},
      setExtraPolicy() {},
      tryBlock() { return false; },
      hasGesture() { return true; },
      isAuthSsoRedirectUrl() { return false; },
      markGesture() {}
    };
    try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    return;
  }

  const { PackageClassifier, SsoDetector, PageShellDetector, CloakingKitScanner, GestureTracker, NavBlocker, LocationGuard } = NS;

  /** 向 content.js (isolated) 发消息。 */
  function post(msg) {
    try {
      window.postMessage({ source: "silverfox-detector-hooks", ...msg }, "*");
    } catch { /* ignore */ }
  }

  class NavBoot {
    constructor() {
      this.gesture = new GestureTracker();
      this.kitScanner = new CloakingKitScanner(post);
      this.blocker = new NavBlocker(this.gesture, this.kitScanner, post);
    }

    /** 搜索页 no-op API：不装任何钩子，避免 SERP 抖动。 */
    installSearchLight() {
      window.__silverfoxNavBootInstalled = true;
      window.__silverfoxSearchLight = true;
      window.__silverfoxNavApi = {
        setGuard() {},
        setOfficialSafe() {},
        setCloakingKit() {},
        rememberHop() {},
        clearHops() {},
        setExtraPolicy() {},
        tryBlock() { return false; },
        hasGesture() { return true; },
        isAuthSsoRedirectUrl() { return false; },
        markGesture() {}
      };
      try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    }

    _activateNavigationHooks() {
      if (this._navigationHooksActive) return;
      this._navigationHooksActive = true;
      // ---- 立即/按需安装 Location 钩子 ----
      try {
        LocationGuard.patchLoc((typeof Location !== "undefined" ? Location : window.Location).prototype, this.blocker);
      } catch { /* ignore */ }
      LocationGuard.patchWindowOpen(this.blocker);
      LocationGuard.patchNavigation(this.gesture, this.blocker);
      this._installKitScan();
    }

    _publishFunctionalApi(lazyActivate) {
      const activate = () => {
        if (lazyActivate) this._activateNavigationHooks();
      };
      window.__silverfoxNavApi = {
        setGuard: (v) => {
          this.blocker.setGuard(v);
          if (v) activate();
        },
        setOfficialSafe: (v) => this.blocker.setOfficialSafe(v),
        setCloakingKit: (v) => {
          this.blocker.setCloakingKit(v);
          if (v) activate();
        },
        rememberHop: (u) => this.blocker.rememberHop(u),
        clearHops: () => this.blocker.clearHops(),
        setExtraPolicy: (fn) => {
          this.blocker.setExtraPolicy(fn);
          if (typeof fn === "function") activate();
        },
        tryBlock: (u, reason) => {
          if (this.blocker.guard || this.blocker.kitScanner.cloakingKit || this.blocker.extraPolicy) activate();
          return this.blocker.tryBlock(u, reason);
        },
        hasGesture: () => this.gesture.hasGesture(),
        isAuthSsoRedirectUrl: (u) => SsoDetector.isAuthSsoRedirectUrl(u),
        markGesture: (e) => this.gesture.markGesture(e)
      };
    }

    /** URL 形态只控制性能；风险消息到达时可懒激活完整导航保护。 */
    installPerformanceLight() {
      window.__silverfoxNavBootInstalled = true;
      window.__silverfoxPerformanceLight = true;
      this._publishFunctionalApi(true);
      try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    }

    install() {
      window.__silverfoxNavBootInstalled = true;
      this._activateNavigationHooks();
      this._publishFunctionalApi(false);
      try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    }

    /** 套件扫描：防抖（曾对每个 DOM 突变强扫，卡死大 SPA）。 */
    _installKitScan() {
      try {
        if (PageShellDetector.looksLikeSearchPageShape()) return;
        let kitKick = null;
        const scheduleKitScan = (force) => {
          if (this.kitScanner.cloakingKit) return;
          if (kitKick) return;
          kitKick = setTimeout(() => {
            kitKick = null;
            this.kitScanner.scanForCloakingKit(!!force);
          }, 200);
        };
        this.kitScanner.scanForCloakingKit(true);
        if (typeof MutationObserver !== "undefined") {
          const mo = new MutationObserver((mutations) => {
            if (this.kitScanner.cloakingKit || PageShellDetector.looksLikeSearchPageShape()) return;
            // 仅对新 SCRIPT 节点反应（套件是内联的）-- 非 text 节点
            for (const m of mutations) {
              if (!m.addedNodes) continue;
              for (let i = 0; i < m.addedNodes.length; i++) {
                const n = m.addedNodes[i];
                if (n && n.nodeType === 1 && n.tagName === "SCRIPT") {
                  scheduleKitScan(false);
                  return;
                }
              }
            }
          });
          mo.observe(document.documentElement || document, { childList: true, subtree: true });
          setTimeout(() => { try { mo.disconnect(); } catch { /* ignore */ } }, 4000);
        }
        document.addEventListener("DOMContentLoaded", () => this.kitScanner.scanForCloakingKit(true), { once: true });
        setTimeout(() => this.kitScanner.scanForCloakingKit(true), 400);
      } catch { /* ignore */ }
    }
  }

  NS.NavBoot = NavBoot;

  // 搜索页为 no-op；干净 /download 仅性能轻量，风险到达后可懒激活钩子。
  const boot = new NavBoot();
  const searchLightEarly = !!PageShellDetector.isSearchUrlShapeEarly();
  const performanceLightEarly = !searchLightEarly
    && typeof PageShellDetector.shouldUseLightNavBootEarly === "function"
    && PageShellDetector.shouldUseLightNavBootEarly();
  if (searchLightEarly) {
    boot.installSearchLight();
  } else if (performanceLightEarly) {
    boot.installPerformanceLight();
  } else {
    boot.install();
  }
})(window.SilverfoxNavBoot ??= {});
