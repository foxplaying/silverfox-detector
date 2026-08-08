/**
 * DOM 原型级守卫：wrap appendChild/insertBefore/setAttribute/click/href/src，
 * 拦截桌面强制下载套件 DOM/CSS 注入与动态下载地址写入。
 * 纯静态方法，状态由 NavPolicy 持有（通过 shouldRejectInjectedNode 回调）。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristics, PageContext, CloakingKit, DownloadUi } = NS;

  class DomGuard {
    /** 保存原生原型方法以便 light page 时恢复（消除 DevTools 对扩展的误报）。 */
    static saveProtoMethod(restoreList, proto, method, orig) {
      if (!proto || !orig) return;
      restoreList.push({ proto, method, orig });
    }

    /** 保存访问器完整描述符；直接赋值无法正确恢复 href/src setter。 */
    static saveProtoDescriptor(restoreList, proto, property, descriptor, marker) {
      if (!proto || !property || !descriptor) return;
      restoreList.push({ proto, property, descriptor, marker });
    }

    static restoreNativeDomProtos(restoreList) {
      DomGuard.restoreFetchInspection();
      DomGuard.stopFetchUrlObserver();
      while (restoreList.length) {
        const item = restoreList.pop();
        try {
          if (item && item.docMethod && item.orig) {
            // document.createElement 等文档级方法（不在 prototype 上）
            document[item.docMethod] = item.orig;
            if (item.marker) {
              try { delete document[item.marker]; } catch { /* ignore */ }
            }
          } else if (item && item.proto && item.property && item.descriptor) {
            Object.defineProperty(item.proto, item.property, item.descriptor);
            if (item.marker) {
              try { delete item.proto[item.marker]; } catch { /* ignore */ }
            }
          } else if (item && item.proto && item.method && item.orig) {
            item.proto[item.method] = item.orig;
          }
        } catch { /* ignore */ }
      }
      try { if (Element.prototype.__silverfoxSetAttr) delete Element.prototype.__silverfoxSetAttr; } catch { /* ignore */ }
      try { if (document.__silverfoxCreateElement) delete document.__silverfoxCreateElement; } catch { /* ignore */ }
    }

    /** 清除页面中已存在的 dlp 套件 DOM/CSS、ld-wrap 全屏加载层与隐藏的自动下载 a/iframe。 */
    static scrubDesktopForceDownloadDom() {
      try {
        document.querySelectorAll(
          ".dlp-overlay, .dlp-topbar, .dlp-modal, [class*='dlp-overlay'], [class*='dlp-topbar'], [class*='dlp-modal']"
        ).forEach((el) => {
          try { el.remove(); } catch { try { el.style.setProperty("display", "none", "important"); } catch { /* ignore */ } }
        });
        // 全屏「请稍等正在加载」(.ld-wrap / fixed z-index 999999)
        DomGuard.scrubHostileLoadingOverlaysMain();
        document.querySelectorAll("style").forEach((st) => {
          if (CloakingKit.isDesktopForceDownloadKitBlob(st.textContent || "")) {
            try { st.remove(); } catch { try { st.textContent = ""; } catch { /* ignore */ } }
          }
        });
        document.querySelectorAll("a[download], a[href], iframe[src], embed[src]").forEach((el) => {
          try {
            const href = el.getAttribute("href") || el.getAttribute("src") || "";
            if (!href || !PackageHeuristics.isPackageFileUrl(href) || PackageHeuristics.isStrongProductInstallerUrl(href)) return;
            const st = (el.getAttribute("style") || "") + (el.style && el.style.cssText || "");
            if (/display\s*:\s*none/i.test(st) || (el.style && el.style.display === "none") || el.hasAttribute("download")) {
              el.removeAttribute("href");
              el.removeAttribute("src");
              el.removeAttribute("download");
              try { el.remove(); } catch { /* ignore */ }
            }
          } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
    }

    /** MAIN-world：删全屏加载遮罩（与 content scrubHostileLoadingOverlays 同语义） */
    static scrubHostileLoadingOverlaysMain() {
      try {
        const kill = (el) => {
          if (!el || el.nodeType !== 1) return;
          try {
            if (el.id && /silverfox/i.test(el.id)) return;
            if (el.className && /silverfox/i.test(String(el.className))) return;
          } catch { /* ignore */ }
          try { el.remove(); } catch {
            try { el.style.setProperty("display", "none", "important"); } catch { /* ignore */ }
          }
        };
        document.querySelectorAll(".ld-wrap, .ld-spinner, .ld-text, [class*='ld-wrap'], [class*='ld-spinner']").forEach((el) => {
          try {
            let p = el;
            for (let i = 0; i < 5 && p; i++) {
              const s = (p.style && p.style.cssText) || p.getAttribute("style") || "";
              const zi = parseInt((p.style && p.style.zIndex) || "0", 10) || 0;
              if (/position\s*:\s*fixed/i.test(s) && (zi >= 999 || /z-index\s*:\s*999/i.test(s))) {
                kill(p);
                return;
              }
              p = p.parentElement;
            }
            kill(el.parentElement || el);
          } catch { /* ignore */ }
        });
        document.querySelectorAll("div").forEach((el) => {
          try {
            const st = el.getAttribute("style") || "";
            if (!/position\s*:\s*fixed/i.test(st)) return;
            const zi = el.style ? parseInt(el.style.zIndex || "0", 10) : 0;
            if (zi < 9999 && !/z-index\s*:\s*999/i.test(st)) return;
            const t = (el.textContent || "").replace(/\s+/g, " ").trim();
            if (t.length > 80) return;
            if (!/请稍等|正在加载|加载中|请稍候|loading/i.test(t)) return;
            if (!/100%|100vw|100vh|top:\s*0/i.test(st)) return;
            kill(el);
          } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
    }

    /**
     * 锁死 iframe/embed，避免 about:blank + sandbox="" 组合。
     * 空 sandbox 的 about:blank 会在控制台刷：
     *   Blocked script execution in 'about:blank' because the document's frame is sandboxed…
     * 改用空 srcdoc / 去 src，不写 sandbox、不导航 about:blank。
     */
    static neutralizeFrameEl(node) {
      if (!node || node.nodeType !== 1) return;
      const tag = (node.tagName || "").toUpperCase();
      try {
        if (tag === "IFRAME") {
          try { node.removeAttribute("src"); } catch { /* ignore */ }
          try { node.removeAttribute("sandbox"); } catch { /* ignore */ }
          try { node.setAttribute("srcdoc", "<!--sf-blocked-->"); } catch { /* ignore */ }
        } else if (tag === "EMBED" || tag === "OBJECT") {
          try { node.removeAttribute("src"); } catch { /* ignore */ }
          try { node.removeAttribute("data"); } catch { /* ignore */ }
          try { node.removeAttribute("type"); } catch { /* ignore */ }
        } else {
          try { node.removeAttribute("src"); } catch { /* ignore */ }
        }
        try { node.setAttribute("data-silverfox-frame-locked", "1"); } catch { /* ignore */ }
        try { node.style.setProperty("pointer-events", "none", "important"); } catch { /* ignore */ }
      } catch { /* ignore */ }
    }

    /** 注入节点是否应拒绝（dlp 套件 / 隐藏包 iframe）。 */
    static shouldRejectInjectedNode(node, policy) {
      if (!node || node.nodeType !== 1) return false;
      if (policy.isLightPage() || policy.officialSafe) return false;
      const tag = (node.tagName || "").toUpperCase();
      const cls = typeof node.className === "string" ? node.className : "";
      const id = node.id || "";
      const maybeDlp = tag === "STYLE" || tag === "SCRIPT" || /dlp-/i.test(cls) || /dlp-/i.test(id)
        || tag === "IFRAME" || tag === "EMBED" || (tag === "A" && (policy.forceDesktopDlKit || policy.guardEnabled));
      if (!maybeDlp) return false;

      if (CloakingKit.isDesktopForceDownloadNode(node)) {
        policy.armDesktopForceDownloadKit("拦截 dlp 套件 DOM/CSS 注入");
        return true;
      }
      // 全屏「请稍等正在加载」/ .ld-wrap 注入（常在 guard 后延迟插入）
      try {
        const t = (node.textContent || "").replace(/\s+/g, " ").trim().slice(0, 60);
        const st = (node.getAttribute && node.getAttribute("style")) || "";
        const cls = typeof node.className === "string" ? node.className : "";
        if (/\bld-(?:wrap|spinner|text)\b/i.test(cls)
          || (policy.guardEnabled && /position\s*:\s*fixed/i.test(st)
            && /z-index\s*:\s*999/i.test(st) && /请稍等|正在加载|加载中/i.test(t))) {
          if (policy.guardEnabled || policy.forceDesktopDlKit) {
            policy.post({ type: "signal", name: "保护模式清除加载遮罩", weight: 0, reason: "ld-wrap / 全屏加载层" });
            return true;
          }
        }
        if (node.querySelector && node.querySelector(".ld-wrap, .ld-spinner, .ld-text")) {
          if (policy.guardEnabled || policy.forceDesktopDlKit) return true;
        }
      } catch { /* ignore */ }
      try {
        if (/dlp/i.test(cls + id) && node.querySelector) {
          const hit = node.querySelector(".dlp-overlay, .dlp-topbar, .dlp-modal");
          if (hit && CloakingKit.isDesktopForceDownloadNode(hit)) {
            policy.armDesktopForceDownloadKit("拦截 dlp 套件子树注入");
            return true;
          }
        }
        if (tag === "STYLE" && CloakingKit.isDesktopForceDownloadKitBlob(node.textContent || "")) {
          policy.armDesktopForceDownloadKit("拦截 dlp 套件 style 注入");
          return true;
        }
      } catch { /* ignore */ }
      if ((policy.forceDesktopDlKit || policy.guardEnabled) && (tag === "IFRAME" || tag === "EMBED" || tag === "A")) {
        try {
          const href = node.getAttribute("href") || node.getAttribute("src") || "";
          if (href && PackageHeuristics.isPackageFileUrl(href) && !PackageHeuristics.isStrongProductInstallerUrl(href)) {
            policy._rememberHop(href);
            return true;
          }
          // guard 开启：拒绝再注入 iframe/embed（盗版页常用晚加载 HTML 壳，非 .exe 直链）
          if (policy.guardEnabled && (tag === "IFRAME" || tag === "EMBED" || tag === "OBJECT")) {
            DomGuard.neutralizeFrameEl(node);
            policy.post({ type: "signal", name: "保护模式拦截框架注入", weight: 0, reason: `guard 下拒绝 ${tag}` });
            return true;
          }
        } catch { /* ignore */ }
      }
      return false;
    }

    /** 安装 DOM 原型 wrap；fetch 仅在 guard 真正启用后按需安装。 */
    static install(policy, restoreList) {
      DomGuard.installFetchUrlObserver(policy);
      DomGuard._wrapCreateElement(policy, restoreList);
      DomGuard._patchAnchorHrefProto(policy, restoreList);
      DomGuard._patchAnchorClickProto(policy, restoreList);
      DomGuard._patchIframeSrcProto(policy, restoreList);
      DomGuard._patchSetAttribute(policy, restoreList);
      DomGuard._wrapInsertMethods(policy, restoreList);
    }

    /** 仅按 Resource Timing 观察可疑下载 API URL，不替换页面 fetch，也不读取响应体。 */
    static installFetchUrlObserver(policy) {
      try {
        if (!policy || policy.lightPage || policy.officialSafe
          || typeof PerformanceObserver === "undefined" || DomGuard._fetchUrlObserver) return;
        const observer = new PerformanceObserver((list) => {
          try {
            if (policy.lightPage || policy.officialSafe) {
              DomGuard.stopFetchUrlObserver();
              return;
            }
            const entries = list && typeof list.getEntries === "function" ? list.getEntries() : [];
            for (const entry of entries) {
              const initiator = String(entry && entry.initiatorType || "").toLowerCase();
              if (initiator !== "fetch" && initiator !== "xmlhttprequest") continue;
              DomGuard.noteDownloadDistributionApi(policy, String(entry && entry.name || ""), "resource");
            }
          } catch { /* ignore */ }
        });
        DomGuard._fetchUrlObserver = observer;
        try { observer.observe({ type: "resource", buffered: true }); }
        catch { observer.observe({ entryTypes: ["resource"] }); }
      } catch {
        DomGuard.stopFetchUrlObserver();
      }
    }

    static stopFetchUrlObserver() {
      try {
        if (DomGuard._fetchUrlObserver) DomGuard._fetchUrlObserver.disconnect();
      } catch { /* ignore */ }
      DomGuard._fetchUrlObserver = null;
    }

    /** 与旧 fetch 前置检测同语义；去重后向 content 请求开启完整 guard。 */
    static noteDownloadDistributionApi(policy, rawUrl, source) {
      try {
        if (!policy || policy.lightPage || policy.officialSafe) return false;
        const urlStr = String(rawUrl || "");
        if (!urlStr || PackageHeuristics.isPackageFileUrl(urlStr)
          || PackageHeuristics.isClearOrStrongProductPackageUrl(urlStr)) return false;
        const looksLikeVendorClientConfig = /\.(?:json|txt)(?:\?|#|$)/i.test(urlStr)
          && (/(?:^|[/_-])(?:pc_app|app_config|version|client_config|package_info)(?:[._-]|\.|$)/i.test(urlStr)
            || /\/official\//i.test(urlStr));
        if (!/api\.php|page-admin|download[_-]?api|getdown|getlink/i.test(urlStr)
          || looksLikeVendorClientConfig) return false;
        policy._downloadApiSignalUrls ??= new Set();
        const key = urlStr.slice(0, 500);
        if (policy._downloadApiSignalUrls.has(key)) return true;
        policy._downloadApiSignalUrls.add(key);
        if (policy._downloadApiSignalUrls.size > 40) {
          const first = policy._downloadApiSignalUrls.values().next().value;
          if (first) policy._downloadApiSignalUrls.delete(first);
        }
        policy.post({
          type: "signal",
          name: "远程API动态绑定下载",
          weight: 18,
          reason: `${source === "resource" ? "资源请求" : "fetch"} 下载分发 API: ${urlStr.slice(0, 200)}`
        });
        policy.post({ type: "request-guard", reason: "远程 API 动态下载绑定" });
        return true;
      } catch {
        return false;
      }
    }

    static enableFetchInspection(policy) {
      if (!policy || policy.lightPage || policy.officialSafe || !policy.guardEnabled) return;
      DomGuard._wrapFetch(policy);
    }

    static restoreFetchInspection() {
      try {
        const state = DomGuard._fetchInspection;
        if (!state) return;
        state.active = false;
        // 页面若后来自行替换 fetch，不得用旧原生函数把页面的新 wrapper 覆盖掉。
        if (window.fetch === state.installed) {
          window.fetch = state.original;
        }
        // 即使页面在外层又包装/替换了 fetch，也丢弃这份失活状态；
        // 下次启用时会以页面当前 fetch 为基底重新安装一层守卫。
        DomGuard._fetchInspection = null;
      } catch { /* ignore */ }
    }

    static _wrapFetch(policy) {
      try {
        if (!policy || policy.lightPage || policy.officialSafe || !policy.guardEnabled) return;
        const existing = DomGuard._fetchInspection;
        if (existing) {
          if (window.fetch === existing.installed) {
            existing.policy = policy;
            existing.active = true;
            return;
          }
          // 页面在安装后替换了 fetch。先让旧层变成透明转发，再包装当前函数；
          // 即使页面的新 wrapper 调用了旧层，也只会有一个活跃检查层。
          existing.active = false;
          DomGuard._fetchInspection = null;
        }
        const origFetch = window.fetch;
        if (typeof origFetch !== "function") return;
        const callOriginal = (thisArg, args) => Reflect.apply(origFetch, thisArg || window, args);
        const state = { original: origFetch, installed: null, policy, active: true };
        const wrappedFetch = function (...args) {
          const livePolicy = state.policy;
          if (!state.active || !livePolicy || livePolicy.officialSafe || livePolicy.lightPage
            || !livePolicy.guardEnabled) return callOriginal(this, args);
          const input = args[0];
          const url = typeof input === "string" ? input : input && input.url;
          const urlStr = String(url || "");
          try {
            if (PackageHeuristics.isPackageFileUrl(urlStr) || PackageHeuristics.isClearOrStrongProductPackageUrl(urlStr)) return callOriginal(this, args);
            if (url) DomGuard.noteDownloadDistributionApi(livePolicy, urlStr, "fetch");
          } catch { /* ignore */ }

          const p = callOriginal(this, args);
          try {
            if (PackageHeuristics.isPackageFileUrl(urlStr) || PackageHeuristics.isClearOrStrongProductPackageUrl(urlStr)) return p;
            const looksLikeVendorClientConfig = /\.(?:json|txt)(?:\?|#|$)/i.test(urlStr)
              && (/(?:^|[/_-])(?:pc_app|app_config|version|client_config|package_info)(?:[._-]|\.|$)/i.test(urlStr) || /\/official\//i.test(urlStr) || /download\.[a-z0-9.-]+/i.test(urlStr));
            const looksLikeAdminApi = /api\.php|page-admin|download[_-]?api|getdown|getlink|download_link/i.test(urlStr)
              && !/\.(?:exe|zip|dmg|msi|apk|rar|7z)(?:\?|#|$)/i.test(urlStr) && !looksLikeVendorClientConfig;
            if (url && (looksLikeAdminApi || looksLikeVendorClientConfig)) {
              return p.then(async (response) => {
                try {
                  if (!state.active || !livePolicy || livePolicy.officialSafe || livePolicy.lightPage
                    || !livePolicy.guardEnabled) return response;
                  const clone = response.clone();
                  const text = await clone.text();
                  let links = [];
                  try {
                    const data = JSON.parse(text);
                    for (const k of ["primary", "secondary", "download_link", "downloadUrl", "download_url", "down_url", "url", "link", "packageUrl", "windowsDownload", "pcDownload"]) {
                      const v = data && data[k];
                      if (typeof v === "string" && /^https?:\/\//i.test(v)) links.push(v);
                    }
                  } catch {
                    const m = text.match(/https?:\/\/[^"'\\\s]+/gi) || [];
                    links = m.slice(0, 8);
                  }
                  links = [...new Set(links)];
                  const threatLinks = links.filter((l) => PackageHeuristics.isPackageFileUrl(l) && !PackageHeuristics.isClearOrStrongProductPackageUrl(l));
                  if (!threatLinks.length) return response;
                  for (const link of threatLinks) {
                    livePolicy._rememberHop(link);
                    livePolicy.post({ type: "signal", name: "远程下发下载地址", weight: 16, reason: `API 返回下载地址: ${String(link).slice(0, 200)}` });
                    livePolicy.post({ type: "blocked-download", href: link, reason: `api-download-link -> ${link}` });
                    livePolicy.post({ type: "request-guard", reason: `远程下发: ${link}` });
                    try {
                      document.querySelectorAll("a.download-btn, a.download-btn-nav, .download-btn, #mainDownloadBtn, a[href]").forEach((a) => {
                        const h = a.getAttribute("href") || "";
                        if (h === link || h === "#" || /download/i.test(a.className || "")) {
                          try {
                            a.setAttribute("data-threat-original-href", link);
                            a.removeAttribute("href");
                            a.style.setProperty("pointer-events", "none", "important");
                            a.style.setProperty("opacity", "0.45", "important");
                          } catch { /* ignore */ }
                        }
                      });
                    } catch { /* ignore */ }
                  }
                } catch { /* ignore */ }
                return response;
              });
            }
          } catch { /* ignore */ }
          return p;
        };
        state.installed = wrappedFetch;
        window.fetch = wrappedFetch;
        DomGuard._fetchInspection = state;
      } catch { /* ignore */ }
    }

    static _wrapCreateElement(policy, restoreList) {
      try {
        if (document.__silverfoxCreateElement) return;
        const origCreate = document.createElement.bind(document);
        // light/official 必须能还原：React SPA 每帧 create 大量 div，wrap 不拆会卡死
        if (restoreList) {
          restoreList.push({ docMethod: "createElement", orig: origCreate, marker: "__silverfoxCreateElement" });
        }
        document.__silverfoxCreateElement = true;
        document.createElement = function (tagName, ...args) {
          // light/正站：直接原生，零额外属性劫持（钉钉等 SPA 依赖此路径）
          if (policy.lightPage || policy.officialSafe) return origCreate(tagName, ...args);
          const tag = String(tagName || "").toLowerCase();
          // 未 arm 时：绝大多数 create（div/span）直通原生。
          // 旧逻辑给每个 div 重定义 className，React 水合会直接卡死主线程。
          const armed = !!(policy.guardEnabled || policy.forceDesktopDlKit);
          if (!armed && tag !== "a" && tag !== "iframe" && tag !== "embed" && tag !== "style") {
            return origCreate(tagName, ...args);
          }
          const el = origCreate(tagName, ...args);
          if (tag === "style") {
            try {
              const checkStyle = () => {
                if (CloakingKit.isDesktopForceDownloadKitBlob(el.textContent || el.innerHTML || "")) {
                  policy.armDesktopForceDownloadKit("createElement(style) dlp CSS");
                  try { el.textContent = ""; } catch { /* ignore */ }
                }
              };
              const desc = Object.getOwnPropertyDescriptor(Node.prototype, "textContent");
              if (desc && desc.set) {
                Object.defineProperty(el, "textContent", {
                  configurable: true, enumerable: true,
                  get() { return desc.get.call(this); },
                  set(v) {
                    if (policy.officialSafe || policy.lightPage) return desc.set.call(this, v);
                    if (CloakingKit.isDesktopForceDownloadKitBlob(v)) {
                      policy.armDesktopForceDownloadKit("style.textContent dlp CSS");
                      return desc.set.call(this, "");
                    }
                    return desc.set.call(this, v);
                  }
                });
              }
              // 不使用已废弃的 DOMNodeInserted（会额外拖慢插入）
              try { checkStyle(); } catch { /* ignore */ }
            } catch { /* ignore */ }
          }
          if (tag === "a") {
            const origClick = el.click.bind(el);
            el.click = function (...clickArgs) {
              const href = el.getAttribute("href") || el.href || "";
              policy.noteTrustedDownloadIntent(href);
              if (policy.officialSafe || policy.lightPage) return origClick(...clickArgs);
              if (policy.tryBlockNavigation(href, `dynamic-anchor-click -> ${href}`) || policy._tryBlock(href, `dynamic-anchor-click -> ${href}`)) return;
              if ((policy.forceDesktopDlKit || policy.guardEnabled) && href && PackageHeuristics.isPackageFileUrl(href) && !PackageHeuristics.isStrongProductInstallerUrl(href)) return;
              return origClick(...clickArgs);
            };
            try {
              const desc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, "href") || Object.getOwnPropertyDescriptor(HTMLElement.prototype, "href");
              if (desc && desc.set) {
                Object.defineProperty(el, "href", {
                  configurable: true, enumerable: true,
                  get() { return desc.get.call(this); },
                  set(v) {
                    policy.noteTrustedDownloadIntent(v);
                    if (policy.officialSafe || policy.lightPage) return desc.set.call(this, v);
                    const val = String(v || "");
                    if (policy._shouldBlockUrl(val) || PackageHeuristics.looksLikeOpaqueDownloadHopUrl(val) || policy.blockedHops.has(val)
                      || PackageHeuristics.looksLikeObjectStoragePackageUrl(val)
                      || ((policy.forceDesktopDlKit || policy.guardEnabled) && PackageHeuristics.isPackageFileUrl(val) && !PackageHeuristics.isStrongProductInstallerUrl(val))) {
                      policy._rememberHop(val);
                      policy._emitBlocked(val, `href-assign -> ${val}`);
                      policy.post({ type: "request-guard", reason: `动态写入下载地址: ${val}` });
                      if (PackageHeuristics.looksLikeObjectStoragePackageUrl(val) || policy.forceDesktopDlKit) {
                        policy.armDesktopForceDownloadKit(`a.href 写入安装包: ${val.slice(0, 120)}`);
                      }
                      try {
                        this.setAttribute("data-threat-original-href", val);
                        this.style.setProperty("pointer-events", "none", "important");
                        this.style.setProperty("opacity", "0.45", "important");
                      } catch { /* ignore */ }
                      return;
                    }
                    desc.set.call(this, v);
                  }
                });
              }
            } catch { /* ignore */ }
          }
          if (tag === "iframe" || tag === "embed") {
            try {
              // guard 下创建的框架直接锁死，防止晚插入下载壳（勿 sandbox="" + about:blank）
              if (policy.guardEnabled) {
                DomGuard.neutralizeFrameEl(el);
              }
              const desc = Object.getOwnPropertyDescriptor(tag === "iframe" ? HTMLIFrameElement.prototype : HTMLEmbedElement.prototype, "src");
              if (desc && desc.set) {
                Object.defineProperty(el, "src", {
                  configurable: true, enumerable: true,
                  get() { return desc.get.call(this); },
                  set(v) {
                    if (policy.officialSafe || policy.lightPage) return desc.set.call(this, v);
                    const val = String(v || "");
                    if (policy.tryBlockNavigation(val, `${tag}.src-create -> ${val}`)) return;
                    if ((policy.forceDesktopDlKit || policy.guardEnabled) && PackageHeuristics.isPackageFileUrl(val) && !PackageHeuristics.isStrongProductInstallerUrl(val)) {
                      policy._rememberHop(val);
                      DomGuard.neutralizeFrameEl(this);
                      return;
                    }
                    // guard：拦截一切非 blank 的框架导航（HTML 下载落地页也拦）
                    if (policy.guardEnabled && val && !/^about:blank$/i.test(val) && !/^javascript:/i.test(val)) {
                      policy._rememberHop(val);
                      policy.post({ type: "signal", name: "保护模式拦截框架加载", weight: 0, reason: `${tag}.src 被拦: ${val.slice(0, 160)}` });
                      DomGuard.neutralizeFrameEl(this);
                      return;
                    }
                    return desc.set.call(this, v);
                  }
                });
              }
            } catch { /* ignore */ }
          }
          // className 劫持仅在已 arm 时启用（dlp 弹层注入）；未 arm 时上面已对 div 直通
          if (armed && (tag === "div" || tag === "section" || tag === "span")) {
            try {
              const cDesc = Object.getOwnPropertyDescriptor(Element.prototype, "className");
              if (cDesc && cDesc.set) {
                Object.defineProperty(el, "className", {
                  configurable: true, enumerable: true,
                  get() { return cDesc.get.call(this); },
                  set(v) {
                    if (policy.officialSafe || policy.lightPage) return cDesc.set.call(this, v);
                    const s = String(v || "");
                    if (/\bdlp-(?:overlay|modal|topbar|btn|badge)\b/i.test(s)) {
                      policy.armDesktopForceDownloadKit(`className 注入 ${s.slice(0, 40)}`);
                      return cDesc.set.call(this, "silverfox-blocked-dlp");
                    }
                    return cDesc.set.call(this, v);
                  }
                });
              }
            } catch { /* ignore */ }
          }
          return el;
        };
      } catch { /* ignore */ }
    }

    static _patchAnchorHrefProto(policy, restoreList) {
      try {
        const proto = HTMLAnchorElement.prototype;
        const desc = Object.getOwnPropertyDescriptor(proto, "href");
        if (desc && desc.set && !proto.__silverfoxHrefPatched) {
          DomGuard.saveProtoDescriptor(restoreList, proto, "href", desc, "__silverfoxHrefPatched");
          proto.__silverfoxHrefPatched = true;
          Object.defineProperty(proto, "href", {
            configurable: true, enumerable: true,
            get() { return desc.get.call(this); },
            set(v) {
              policy.noteTrustedDownloadIntent(v);
              if (policy.officialSafe) return desc.set.call(this, v);
              const val = String(v || "");
              if (policy._shouldBlockUrl(val) || PackageHeuristics.looksLikeOpaqueDownloadHopUrl(val) || policy.blockedHops.has(val)) {
                policy._rememberHop(val);
                policy._emitBlocked(val, `proto-href-assign -> ${val}`);
                policy.post({ type: "request-guard", reason: `动态写入下载地址: ${val}` });
                try {
                  this.setAttribute("data-threat-original-href", val);
                  this.style.setProperty("pointer-events", "none", "important");
                  this.style.setProperty("opacity", "0.45", "important");
                  return;
                } catch { /* fall through */ }
              }
              desc.set.call(this, v);
            }
          });
        }
      } catch { /* ignore */ }
    }

    static _patchAnchorClickProto(policy, restoreList) {
      try {
        const origAnchorClick = HTMLAnchorElement.prototype.click;
        DomGuard.saveProtoMethod(restoreList, HTMLAnchorElement.prototype, "click", origAnchorClick);
        HTMLAnchorElement.prototype.click = function (...args) {
          const href = this.getAttribute("href") || this.href || "";
          policy.noteTrustedDownloadIntent(href);
          if (policy.officialSafe) return origAnchorClick.apply(this, args);
          if (policy._tryBlock(href, `anchor.click -> ${href}`)) return;
          return origAnchorClick.apply(this, args);
        };
      } catch { /* ignore */ }
    }

    static _patchIframeSrcProto(policy, restoreList) {
      const patchSrc = (proto, tag) => {
        if (!proto || proto.__silverfoxSrcPatched) return;
        const desc = Object.getOwnPropertyDescriptor(proto, "src");
        if (!desc || !desc.set) return;
        DomGuard.saveProtoDescriptor(restoreList, proto, "src", desc, "__silverfoxSrcPatched");
        proto.__silverfoxSrcPatched = true;
        Object.defineProperty(proto, "src", {
          configurable: true, enumerable: true,
            get() { return desc.get.call(this); },
            set(v) {
              if (policy.officialSafe) {
                policy.noteTrustedDownloadIntent(v);
                return desc.set.call(this, v);
              }
            const val = String(v || "");
            if (policy.tryBlockNavigation(val, `${tag}.src -> ${val}`)) return;
            if ((policy.forceDesktopDlKit || policy.guardEnabled) && PackageHeuristics.isPackageFileUrl(val)
              && !PackageHeuristics.isStrongProductInstallerUrl(val)) {
              policy._rememberHop(val);
              DomGuard.neutralizeFrameEl(this);
              return;
            }
            // 盗版 guard：晚加载 HTML 下载壳（非 .exe）也必须拦
            if (policy.guardEnabled && val && !/^about:blank$/i.test(val) && !/^javascript:/i.test(val)
              && !policy.officialSafe) {
              policy._rememberHop(val);
              policy.post({ type: "signal", name: "保护模式拦截框架加载", weight: 0, reason: `${tag}.src 被拦: ${val.slice(0, 160)}` });
              DomGuard.neutralizeFrameEl(this);
              return;
            }
            return desc.set.call(this, v);
          }
        });
      };
      try { if (typeof HTMLIFrameElement !== "undefined") patchSrc(HTMLIFrameElement.prototype, "iframe"); } catch { /* ignore */ }
      try { if (typeof HTMLEmbedElement !== "undefined") patchSrc(HTMLEmbedElement.prototype, "embed"); } catch { /* ignore */ }
    }

    static _patchSetAttribute(policy, restoreList) {
      try {
        try {
          if (PageContext.isSearchUrlShapeOnly() || PageContext.pageLooksLikeSerpUrl()
            || (typeof policy.isLightPage === "function" && policy.isLightPage())) policy.lightPage = true;
        } catch { /* ignore */ }
        // light：绝不包装 setAttribute（viewport target-densitydpi 会经包装器冒泡到扩展堆栈）
        if (policy.lightPage || policy.officialSafe) return;
        const origSetAttr = Element.prototype.setAttribute;
        if (origSetAttr && !Element.prototype.__silverfoxSetAttr) {
          Element.prototype.__silverfoxSetAttr = true;
          DomGuard.saveProtoMethod(restoreList, Element.prototype, "setAttribute", origSetAttr);
          Element.prototype.setAttribute = function (name, value) {
            if (policy.lightPage || policy.officialSafe) return origSetAttr.call(this, name, value);
            try {
              const n = String(name || "").toLowerCase();
              if (n === "content" && NS.MixedContentQuiet
                && typeof NS.MixedContentQuiet.sanitizeLegacyViewportContent === "function") {
                value = NS.MixedContentQuiet.sanitizeLegacyViewportContent(this, n, value);
              }
              if (n === "sandbox") return origSetAttr.call(this, name, value); // 永不碰沙箱
              // content/viewport 等：原样透传且不进入威胁分支（减少无关键堆栈）
              if (n === "content" || n === "name" || n === "http-equiv" || n === "charset" || n === "property") {
                return origSetAttr.call(this, name, value);
              }
              if (n !== "class" && n !== "classname" && n !== "href" && n !== "src") return origSetAttr.call(this, name, value);
              const v = String(value || "");
              if (n === "class" || n === "classname") {
                if (v.length < 8 || v.indexOf("dlp-") === -1) return origSetAttr.call(this, name, value);
                if (/\bdlp-(?:overlay|modal|topbar|btn|badge|close)\b/i.test(v)) {
                  policy.armDesktopForceDownloadKit(`setAttribute(class) ${v.slice(0, 40)}`);
                  return origSetAttr.call(this, name, "silverfox-blocked-dlp");
                }
              }
              if (n === "href" || n === "src") {
                if (PackageHeuristics.isPackageFileUrl(v) && !PackageHeuristics.isStrongProductInstallerUrl(v)
                  && (policy._shouldBlockUrl(v) || PackageHeuristics.looksLikeObjectStoragePackageUrl(v) || policy.forceDesktopDlKit || policy.guardEnabled)) {
                  policy._rememberHop(v);
                  policy._emitBlocked(v, `setAttribute(${n}) -> ${v}`);
                  if (PackageHeuristics.looksLikeObjectStoragePackageUrl(v) || policy.forceDesktopDlKit) policy.armDesktopForceDownloadKit(`setAttribute ${n} 安装包`);
                  return;
                }
                // guard：iframe/embed setAttribute('src', 下载壳HTML) 也必须拦
                if (n === "src" && policy.guardEnabled && !policy.officialSafe && v && !/^about:blank$/i.test(v)) {
                  const tag = (this.tagName || "").toUpperCase();
                  if (tag === "IFRAME" || tag === "EMBED" || tag === "OBJECT") {
                    policy._rememberHop(v);
                    policy.post({ type: "signal", name: "保护模式拦截框架加载", weight: 0, reason: `setAttribute(src) ${tag}: ${v.slice(0, 160)}` });
                    DomGuard.neutralizeFrameEl(this);
                    return;
                  }
                }
              }
            } catch { /* ignore */ }
            return origSetAttr.call(this, name, value);
          };
        }
      } catch { /* ignore */ }
    }

    static _wrapInsertMethods(policy, restoreList) {
      try {
        try {
          if (PageContext.isSearchUrlShapeOnly() || PageContext.pageLooksLikeSerpUrl()
            || (typeof policy.isLightPage === "function" && policy.isLightPage())) policy.lightPage = true;
        } catch { /* ignore */ }
        if (policy.lightPage || policy.officialSafe) return;
        const wrapInsert = (proto, method) => {
          if (!proto || !proto[method] || proto[method].__silverfoxWrapped) return;
          const orig = proto[method];
          DomGuard.saveProtoMethod(restoreList, proto, method, orig);
          const wrapped = function (...args) {
            // light/safe：直接原生路径（拆 wrap 后此函数不应再被调用）
            if (policy.lightPage || policy.officialSafe) return orig.apply(this, args);
            try {
              const node = method === "replaceChild" ? args[0] : args[0];
              // META/LINK/TITLE：透传（CSP Report-Only 等页面自有策略勿经威胁分支拉长堆栈）
              if (node && node.nodeType === 1) {
                const tag0 = node.tagName || "";
                if (tag0 === "META" || tag0 === "LINK" || tag0 === "TITLE" || tag0 === "BASE") {
                  return orig.apply(this, args);
                }
              }
              if (DomGuard.shouldRejectInjectedNode(node, policy)) return method === "replaceChild" ? args[1] : node;
              if (node && node.nodeType === 1 && node.tagName === "STYLE" && CloakingKit.isDesktopForceDownloadKitBlob(node.textContent || "")) {
                policy.armDesktopForceDownloadKit("append style dlp CSS");
                try { node.textContent = ""; } catch { /* ignore */ }
                return node;
              }
            } catch { /* ignore */ }
            return orig.apply(this, args);
          };
          wrapped.__silverfoxWrapped = true;
          proto[method] = wrapped;
        };
        wrapInsert(Element.prototype, "appendChild");
        wrapInsert(Element.prototype, "insertBefore");
        wrapInsert(Element.prototype, "replaceChild");
        wrapInsert(Node.prototype, "appendChild");
        wrapInsert(Node.prototype, "insertBefore");
        if (Element.prototype.append) {
          const origAppend = Element.prototype.append;
          DomGuard.saveProtoMethod(restoreList, Element.prototype, "append", origAppend);
          Element.prototype.append = function (...nodes) {
            if (policy.lightPage || policy.officialSafe) return origAppend.apply(this, nodes);
            const kept = [];
            for (const n of nodes) {
              if (DomGuard.shouldRejectInjectedNode(n, policy)) continue;
              if (n && n.nodeType === 1 && n.tagName === "STYLE" && CloakingKit.isDesktopForceDownloadKitBlob(n.textContent || "")) {
                policy.armDesktopForceDownloadKit("append() style dlp");
                continue;
              }
              kept.push(n);
            }
            if (!kept.length) return undefined;
            return origAppend.apply(this, kept);
          };
        }
      } catch { /* ignore */ }
    }

    /** 实时 scrub：套件在 load 后注入 / 重新显示模态。短生命周期，无 characterData。 */
    static installLiveScrub(policy) {
      try {
        if (typeof MutationObserver === "undefined" || policy.isLightPage()) return;
        let scrubKick = null;
        let seenNodes = 0;
        const dlpMo = new MutationObserver((mutations) => {
          if (policy.lightPage || policy.officialSafe) return;
          let hit = false;
          let budget = 24;
          try {
            for (let mi = 0; mi < mutations.length && budget > 0; mi++) {
              const m = mutations[mi];
              if (!m.addedNodes || !m.addedNodes.length) continue;
              for (let i = 0; i < m.addedNodes.length && budget > 0; i++) {
                const n = m.addedNodes[i];
                budget--;
                if (!n || n.nodeType !== 1) continue;
                const tag = n.tagName || "";
                if (tag !== "STYLE" && tag !== "SCRIPT" && tag !== "IFRAME" && tag !== "EMBED" && tag !== "A" && !/dlp/i.test(String(n.className || "") + (n.id || ""))) continue;
                if (DomGuard.shouldRejectInjectedNode(n, policy)) {
                  hit = true;
                  try { if (n.parentNode) n.parentNode.removeChild(n); } catch { /* ignore */ }
                }
              }
            }
          } catch { /* ignore */ }
          if (hit || policy.forceDesktopDlKit) {
            if (!scrubKick) {
              scrubKick = setTimeout(() => {
                scrubKick = null;
                if (!policy.lightPage && !policy.officialSafe) DomGuard.scrubDesktopForceDownloadDom();
              }, 150);
            }
          }
          seenNodes += mutations.length;
          if (seenNodes > 400 && !policy.forceDesktopDlKit) { try { dlpMo.disconnect(); } catch { /* ignore */ } }
        });
        dlpMo.observe(document.documentElement || document, { childList: true, subtree: true }); // 无 characterData
        setTimeout(() => { try { dlpMo.disconnect(); } catch { /* ignore */ } }, policy.forceDesktopDlKit ? 30000 : 12000);
      } catch { /* ignore */ }
    }

    /** 扫描已存在的 style/script（套件常晚注入）。 */
    static scanExisting(policy) {
      try {
        if (policy.isLightPage()) return;
        const scanExisting = () => {
          if (policy.isLightPage() || policy.officialSafe) return;
          try {
            const styles = document.querySelectorAll("style");
            const n = Math.min(styles.length, 20);
            for (let i = styles.length - n; i < styles.length; i++) {
              if (i < 0) continue;
              const el = styles[i];
              if (CloakingKit.isDesktopForceDownloadKitBlob(el.textContent || "")) {
                policy.armDesktopForceDownloadKit("页面已有 dlp 套件脚本/样式");
                try { el.remove(); } catch { el.textContent = ""; }
              }
            }
            if (document.querySelector(".dlp-overlay, .dlp-topbar, .dlp-modal")) {
              policy.armDesktopForceDownloadKit("页面已有 dlp 弹窗 DOM");
            }
          } catch { /* ignore */ }
        };
        scanExisting();
        if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scanExisting, { once: true });
        setTimeout(scanExisting, 500);
        setTimeout(scanExisting, 2500);
      } catch { /* ignore */ }
    }

    /** window.download_uri 拦截：写入时主动 arm（不依赖用户点击下载按钮）。 */
    static installDownloadUriTrap(policy) {
      try {
        let downloadUriValue = "";
        Object.defineProperty(window, "download_uri", {
          configurable: true, enumerable: true,
          get() { return downloadUriValue; },
          set(v) {
            downloadUriValue = String(v || "");
            if (policy.officialSafe) return;
            if (!downloadUriValue) return;
            let multiBind = false;
            try {
              multiBind = document.getElementsByClassName("download-uri").length >= 1
                || document.querySelectorAll(".download-uri, a.download-uri, .download-btn, .download-btn-nav, #mainDownloadBtn, a[class*='download'], button[class*='download']").length >= 1;
            } catch { /* ignore */ }
            const isPkg = PackageHeuristics.PACKAGE_EXT.test(downloadUriValue) || PackageHeuristics.PACKAGE_NAME.test(downloadUriValue.split("/").pop() || "");
            const isHop = PackageHeuristics.looksLikeOpaqueDownloadHopUrl(downloadUriValue);
            // 有安装包/跳板 URL，或页上存在下载按钮壳，均应主动 request-guard（勿等点击）
            if (!multiBind && !isPkg && !isHop) return;
            const reason = isPkg || isHop
              ? `全局 download_uri 下发: ${downloadUriValue}`
              : `下载按钮已绑定可疑远程地址`;
            policy.post({ type: "request-guard", reason });
            policy.post({ type: "signal", name: "远程API动态绑定下载", weight: 18, reason: `download_uri -> ${downloadUriValue.slice(0, 160)}` });
            policy._rememberHop(downloadUriValue);
            policy.guardEnabled = true;
            try { DomGuard.enableFetchInspection(policy); } catch { /* ignore */ }
            DownloadUi.disableAllDownloadButtonsInPage();
          }
        });
      } catch { /* ignore */ }
    }
  }

  NS.DomGuard = DomGuard;
  if (NS._setDomGuard) NS._setDomGuard(DomGuard);
})(window.SilverfoxPageHooks ??= {});
