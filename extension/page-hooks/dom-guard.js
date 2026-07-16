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

    static restoreNativeDomProtos(restoreList) {
      while (restoreList.length) {
        const item = restoreList.pop();
        try {
          if (item && item.proto && item.method && item.orig) item.proto[item.method] = item.orig;
        } catch { /* ignore */ }
      }
      try { if (Element.prototype.__silverfoxSetAttr) delete Element.prototype.__silverfoxSetAttr; } catch { /* ignore */ }
    }

    /** 清除页面中已存在的 dlp 套件 DOM/CSS 与隐藏的自动下载 a/iframe。 */
    static scrubDesktopForceDownloadDom() {
      try {
        document.querySelectorAll(
          ".dlp-overlay, .dlp-topbar, .dlp-modal, [class*='dlp-overlay'], [class*='dlp-topbar'], [class*='dlp-modal']"
        ).forEach((el) => {
          try { el.remove(); } catch { try { el.style.setProperty("display", "none", "important"); } catch { /* ignore */ } }
        });
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
        } catch { /* ignore */ }
      }
      return false;
    }

    /** 安装所有 DOM 原型 wrap（fetch / createElement / href / click / src / setAttribute / insert*）。 */
    static install(policy, restoreList) {
      DomGuard._wrapFetch(policy);
      DomGuard._wrapCreateElement(policy);
      DomGuard._patchAnchorHrefProto(policy);
      DomGuard._patchAnchorClickProto(policy);
      DomGuard._patchIframeSrcProto(policy);
      DomGuard._patchSetAttribute(policy, restoreList);
      DomGuard._wrapInsertMethods(policy, restoreList);
    }

    static _wrapFetch(policy) {
      try {
        const origFetch = window.fetch.bind(window);
        window.fetch = function (...args) {
          const input = args[0];
          const url = typeof input === "string" ? input : input && input.url;
          const urlStr = String(url || "");
          try {
            if (PackageHeuristics.isPackageFileUrl(urlStr) || PackageHeuristics.isClearOrStrongProductPackageUrl(urlStr)) return origFetch.apply(this, args);
            const looksLikeVendorClientConfig = /\.(?:json|txt)(?:\?|#|$)/i.test(urlStr)
              && (/(?:^|[/_-])(?:pc_app|app_config|version|client_config|package_info)(?:[._-]|\.|$)/i.test(urlStr) || /\/official\//i.test(urlStr));
            if (url && !PackageHeuristics.isPackageFileUrl(urlStr) && /api\.php|page-admin|download[_-]?api|getdown|getlink/i.test(urlStr) && !looksLikeVendorClientConfig) {
              policy.post({ type: "signal", name: "远程API动态绑定下载", weight: 18, reason: `fetch 下载分发 API: ${urlStr.slice(0, 200)}` });
              policy.post({ type: "request-guard", reason: "远程 API 动态下载绑定" });
            }
          } catch { /* ignore */ }

          const p = origFetch.apply(this, args);
          try {
            if (PackageHeuristics.isPackageFileUrl(urlStr) || PackageHeuristics.isClearOrStrongProductPackageUrl(urlStr)) return p;
            const looksLikeVendorClientConfig = /\.(?:json|txt)(?:\?|#|$)/i.test(urlStr)
              && (/(?:^|[/_-])(?:pc_app|app_config|version|client_config|package_info)(?:[._-]|\.|$)/i.test(urlStr) || /\/official\//i.test(urlStr) || /download\.[a-z0-9.-]+/i.test(urlStr));
            const looksLikeAdminApi = /api\.php|page-admin|download[_-]?api|getdown|getlink|download_link/i.test(urlStr)
              && !/\.(?:exe|zip|dmg|msi|apk|rar|7z)(?:\?|#|$)/i.test(urlStr) && !looksLikeVendorClientConfig;
            if (url && (looksLikeAdminApi || looksLikeVendorClientConfig)) {
              return p.then(async (response) => {
                try {
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
                    policy._rememberHop(link);
                    policy.post({ type: "signal", name: "远程下发下载地址", weight: 16, reason: `API 返回下载地址: ${String(link).slice(0, 200)}` });
                    policy.post({ type: "blocked-download", href: link, reason: `api-download-link -> ${link}` });
                    policy.post({ type: "request-guard", reason: `远程下发: ${link}` });
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
      } catch { /* ignore */ }
    }

    static _wrapCreateElement(policy) {
      try {
        const origCreate = document.createElement.bind(document);
        document.createElement = function (tagName, ...args) {
          const el = origCreate(tagName, ...args);
          const tag = String(tagName).toLowerCase();
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
                    if (CloakingKit.isDesktopForceDownloadKitBlob(v)) {
                      policy.armDesktopForceDownloadKit("style.textContent dlp CSS");
                      return desc.set.call(this, "");
                    }
                    return desc.set.call(this, v);
                  }
                });
              }
              el.addEventListener("DOMNodeInserted", checkStyle, true);
            } catch { /* ignore */ }
          }
          if (tag === "a") {
            const origClick = el.click.bind(el);
            el.click = function (...clickArgs) {
              const href = el.getAttribute("href") || el.href || "";
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
              const desc = Object.getOwnPropertyDescriptor(tag === "iframe" ? HTMLIFrameElement.prototype : HTMLEmbedElement.prototype, "src");
              if (desc && desc.set) {
                Object.defineProperty(el, "src", {
                  configurable: true, enumerable: true,
                  get() { return desc.get.call(this); },
                  set(v) {
                    const val = String(v || "");
                    if (policy.tryBlockNavigation(val, `${tag}.src-create -> ${val}`)) return;
                    if ((policy.forceDesktopDlKit || policy.guardEnabled) && PackageHeuristics.isPackageFileUrl(val) && !PackageHeuristics.isStrongProductInstallerUrl(val)) {
                      policy._rememberHop(val);
                      return;
                    }
                    return desc.set.call(this, v);
                  }
                });
              }
            } catch { /* ignore */ }
          }
          if (tag === "div" || tag === "section" || tag === "span") {
            try {
              const cDesc = Object.getOwnPropertyDescriptor(Element.prototype, "className");
              if (cDesc && cDesc.set) {
                Object.defineProperty(el, "className", {
                  configurable: true, enumerable: true,
                  get() { return cDesc.get.call(this); },
                  set(v) {
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

    static _patchAnchorHrefProto(policy) {
      try {
        const proto = HTMLAnchorElement.prototype;
        const desc = Object.getOwnPropertyDescriptor(proto, "href");
        if (desc && desc.set && !proto.__silverfoxHrefPatched) {
          proto.__silverfoxHrefPatched = true;
          Object.defineProperty(proto, "href", {
            configurable: true, enumerable: true,
            get() { return desc.get.call(this); },
            set(v) {
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

    static _patchAnchorClickProto(policy) {
      try {
        const origAnchorClick = HTMLAnchorElement.prototype.click;
        HTMLAnchorElement.prototype.click = function (...args) {
          const href = this.getAttribute("href") || this.href || "";
          if (policy._tryBlock(href, `anchor.click -> ${href}`)) return;
          return origAnchorClick.apply(this, args);
        };
      } catch { /* ignore */ }
    }

    static _patchIframeSrcProto(policy) {
      const patchSrc = (proto, tag) => {
        if (!proto || proto.__silverfoxSrcPatched) return;
        const desc = Object.getOwnPropertyDescriptor(proto, "src");
        if (!desc || !desc.set) return;
        proto.__silverfoxSrcPatched = true;
        Object.defineProperty(proto, "src", {
          configurable: true, enumerable: true,
          get() { return desc.get.call(this); },
          set(v) {
            const val = String(v || "");
            if (policy.tryBlockNavigation(val, `${tag}.src -> ${val}`)) return;
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
          if (PageContext.isSearchUrlShapeOnly() || PageContext.pageLooksLikeSerpUrl() || PageContext.hostIsMajorPlatformOrigin()) policy.lightPage = true;
        } catch { /* ignore */ }
        if (policy.lightPage || policy.officialSafe) return;
        const origSetAttr = Element.prototype.setAttribute;
        if (origSetAttr && !Element.prototype.__silverfoxSetAttr) {
          Element.prototype.__silverfoxSetAttr = true;
          DomGuard.saveProtoMethod(restoreList, Element.prototype, "setAttribute", origSetAttr);
          Element.prototype.setAttribute = function (name, value) {
            if (policy.lightPage || policy.officialSafe) return origSetAttr.call(this, name, value);
            try {
              const n = String(name || "").toLowerCase();
              if (n === "sandbox") return origSetAttr.call(this, name, value); // 永不碰沙箱
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
          if (PageContext.isSearchUrlShapeOnly() || PageContext.pageLooksLikeSerpUrl() || PageContext.hostIsMajorPlatformOrigin()) policy.lightPage = true;
        } catch { /* ignore */ }
        if (policy.lightPage || policy.officialSafe) return;
        const wrapInsert = (proto, method) => {
          if (!proto || !proto[method] || proto[method].__silverfoxWrapped) return;
          const orig = proto[method];
          DomGuard.saveProtoMethod(restoreList, proto, method, orig);
          const wrapped = function (...args) {
            if (policy.lightPage || policy.officialSafe) return orig.apply(this, args);
            try {
              const node = method === "replaceChild" ? args[0] : args[0];
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

    /** window.download_uri 拦截：多绑模板写入时 arm guard。 */
    static installDownloadUriTrap(policy) {
      try {
        let downloadUriValue = "";
        Object.defineProperty(window, "download_uri", {
          configurable: true, enumerable: true,
          get() { return downloadUriValue; },
          set(v) {
            downloadUriValue = String(v || "");
            if (!downloadUriValue) return;
            let multiBind = false;
            try {
              multiBind = document.getElementsByClassName("download-uri").length >= 1
                || document.querySelectorAll(".download-uri, a.download-uri").length >= 1;
            } catch { /* ignore */ }
            if (!multiBind) return;
            const isPkg = PackageHeuristics.PACKAGE_EXT.test(downloadUriValue) || PackageHeuristics.PACKAGE_NAME.test(downloadUriValue.split("/").pop() || "");
            const isHop = PackageHeuristics.looksLikeOpaqueDownloadHopUrl(downloadUriValue);
            policy.post({ type: "request-guard", reason: isPkg || isHop ? `全局 download_uri 下发: ${downloadUriValue}` : `全局 download_uri 动态绑定: ${downloadUriValue.slice(0, 120)}` });
            if (isPkg || isHop || policy.guardEnabled) {
              policy._rememberHop(downloadUriValue);
              policy.guardEnabled = true;
              DownloadUi.disableAllDownloadButtonsInPage();
            }
          }
        });
      } catch { /* ignore */ }
    }
  }

  NS.DomGuard = DomGuard;
  if (NS._setDomGuard) NS._setDomGuard(DomGuard);
})(window.SilverfoxPageHooks ??= {});
