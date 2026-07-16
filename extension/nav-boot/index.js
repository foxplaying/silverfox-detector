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
        setCloakingKit() {},
        rememberHop() {},
        setExtraPolicy() {},
        tryBlock() { return false; },
        hasGesture() { return true; },
        isAuthSsoRedirectUrl() { return false; },
        markGesture() {}
      };
      try { window.postMessage({ source: "silverfox-detector-hooks", type: "hooks-ready" }, "*"); } catch { /* ignore */ }
    }

    install() {
      window.__silverfoxNavBootInstalled = true;

      // ---- 立即安装 Location 钩子（先于本文件其余代码）----
      try {
        LocationGuard.patchLoc((typeof Location !== "undefined" ? Location : window.Location).prototype, this.blocker);
      } catch { /* ignore */ }
      LocationGuard.patchWindowOpen(this.blocker);
      LocationGuard.patchNavigation(this.gesture, this.blocker);

      // 导出 nav api 供 page-hooks/content 复用
      window.__silverfoxNavApi = {
        setGuard: (v) => this.blocker.setGuard(v),
        setCloakingKit: (v) => this.blocker.setCloakingKit(v),
        rememberHop: (u) => this.blocker.rememberHop(u),
        setExtraPolicy: (fn) => this.blocker.setExtraPolicy(fn),
        tryBlock: (u, reason) => this.blocker.tryBlock(u, reason),
        hasGesture: () => this.gesture.hasGesture(),
        isAuthSsoRedirectUrl: (u) => SsoDetector.isAuthSsoRedirectUrl(u),
        markGesture: (e) => this.gesture.markGesture(e)
      };

      this._installKitScan();
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

  // 搜索页：no-op 轻路径；否则全量安装（大站 light 由 content 侧 soft-nav 结构逻辑负责，非域名名单）
  const boot = new NavBoot();
  if (PageShellDetector.isSearchUrlShapeEarly()) {
    boot.installSearchLight();
  } else {
    boot.install();
  }
})(window.SilverfoxNavBoot ??= {});
