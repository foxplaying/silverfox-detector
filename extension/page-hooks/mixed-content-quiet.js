/**
 * HTTPS 页 Mixed Content 降噪与同站升级。
 *
 * 背景：政府/新闻等站 HTML 仍写 http:// 图片，Chrome 会自动升级并刷屏：
 *   "Mixed Content: ... automatically upgraded to HTTPS"
 * 扩展的 DOM wrap 还可能出现在相关堆栈里，被误当成「插件报错」。
 *
 * 策略（均不碰主文档导航、不拦安装包判定）：
 * 1) 同站 / 同 apex 的被动资源 URL 在写入前 http→https
 * 2) 尽早扫一遍已有 img/source/video/audio/link
   * 3) 不包装页面 console；浏览器原生安全提示保留，避免污染网站错误的堆栈归属
 */
;(function (NS) {
  "use strict";

  class MixedContentQuiet {
    static _pageIsHttps() {
      try {
        return String(location.protocol || "").toLowerCase() === "https:";
      } catch {
        return false;
      }
    }

    /** 粗 apex（仅用于同站升级判断，勿当公共后缀库） */
    static _apexOf(host) {
      const h = String(host || "").toLowerCase().replace(/\.$/, "");
      const parts = h.split(".").filter(Boolean);
      if (parts.length <= 2) return h;
      const last = parts[parts.length - 1] || "";
      const second = parts[parts.length - 2] || "";
      if (last === "cn" && /^(?:com|net|org|gov|edu|ac|mil)$/i.test(second)) {
        return parts.slice(-3).join(".");
      }
      if (last.length === 2 && /^(com|net|org|co|ac|gov|edu)$/i.test(second)) {
        return parts.slice(-3).join(".");
      }
      return parts.slice(-2).join(".");
    }

    /**
     * 仅升级「同站/同可注册域」的 http URL，避免误伤仅 HTTP 的外链。
     * 返回原字符串（无需改）或 https URL。
     */
    static upgradeSameSiteHttp(raw) {
      const s = String(raw == null ? "" : raw).trim();
      if (!s || !/^http:\/\//i.test(s)) return s;
      if (!MixedContentQuiet._pageIsHttps()) return s;
      try {
        const u = new URL(s, location.href);
        if (u.protocol !== "http:") return s;
        const pageHost = String(location.hostname || "").toLowerCase();
        const tHost = String(u.hostname || "").toLowerCase();
        if (!pageHost || !tHost) return s;
        if (tHost === pageHost
          || tHost.endsWith("." + pageHost)
          || pageHost.endsWith("." + tHost)
          || MixedContentQuiet._apexOf(tHost) === MixedContentQuiet._apexOf(pageHost)) {
          u.protocol = "https:";
          return u.href;
        }
      } catch { /* ignore */ }
      return s;
    }

    /** srcset: "a.jpg 1x, http://x/b.jpg 2x" */
    static upgradeSrcset(raw) {
      const s = String(raw == null ? "" : raw);
      if (!s || !/http:\/\//i.test(s)) return s;
      return s.replace(/(?:^|[\s,])(http:\/\/[^\s,]+)/gi, (m, url) => {
        const up = MixedContentQuiet.upgradeSameSiteHttp(url);
        return m.replace(url, up);
      });
    }

    static upgradeAttrValue(name, value) {
      const n = String(name || "").toLowerCase();
      if (n === "srcset") return MixedContentQuiet.upgradeSrcset(value);
      if (n === "src" || n === "poster" || n === "data-src" || n === "data-original"
        || n === "data-lazy-src" || n === "data-url" || n === "href") {
        return MixedContentQuiet.upgradeSameSiteHttp(value);
      }
      return value;
    }

    static upgradeElement(el) {
      if (!el || el.nodeType !== 1) return;
      try {
        const tag = String(el.tagName || "").toUpperCase();
        // 被动媒体 + 样式表
        const attrs = ["src", "srcset", "poster", "data-src", "data-original", "data-lazy-src"];
        if (tag === "LINK") {
          const rel = String(el.getAttribute("rel") || "").toLowerCase();
          if (/\bstylesheet\b|\bpreload\b|\bicon\b/.test(rel)) attrs.push("href");
        }
        if (tag === "SOURCE" || tag === "IMG" || tag === "VIDEO" || tag === "AUDIO"
          || tag === "TRACK" || tag === "EMBED" || tag === "INPUT") {
          /* attrs already cover */
        }
        for (const a of attrs) {
          if (!el.hasAttribute(a)) continue;
          const cur = el.getAttribute(a);
          const next = MixedContentQuiet.upgradeAttrValue(a, cur);
          if (next !== cur) {
            try { el.setAttribute(a, next); } catch { /* ignore */ }
          }
        }
        // style="background:url(http://...)" 同站升级
        const st = el.getAttribute("style");
        if (st && /url\s*\(\s*['"]?http:\/\//i.test(st)) {
          const nextSt = st.replace(/url\s*\(\s*(['"]?)(http:\/\/[^'")\s]+)\1\s*\)/gi, (m, q, url) => {
            const up = MixedContentQuiet.upgradeSameSiteHttp(url);
            return `url(${q || ""}${up}${q || ""})`;
          });
          if (nextSt !== st) {
            try { el.setAttribute("style", nextSt); } catch { /* ignore */ }
          }
        }
      } catch { /* ignore */ }
    }

    static scanTree(root) {
      if (!MixedContentQuiet._pageIsHttps()) return;
      try {
        const scope = root && root.querySelectorAll ? root : document;
        const sel = [
          "img[src^='http://'], img[srcset*='http://'], img[data-src^='http://']",
          "source[src^='http://'], source[srcset*='http://']",
          "video[src^='http://'], video[poster^='http://']",
          "audio[src^='http://']",
          "link[href^='http://']",
          "embed[src^='http://']",
          "input[src^='http://']",
          "[style*='http://']"
        ].join(",");
        if (root && root.nodeType === 1) MixedContentQuiet.upgradeElement(root);
        scope.querySelectorAll(sel).forEach((el) => MixedContentQuiet.upgradeElement(el));
      } catch { /* ignore */ }
    }

    /**
     * 不再包装 console。
     * console 包装会让所有网站日志的首个堆栈帧都指向扩展，造成“插件抛错”的假象；
     * Chrome 自己输出的 Mixed Content 安全消息也不保证经过页面 console，包装收益很低。
     */
    static installConsoleQuiet() {
      // Intentionally empty. Keep the method for compatibility with existing callers.
    }

    /**
     * 原型级：写入 src/srcset 时同站升级。
     * 独立于 DomGuard restoreList，light 页还原守卫后仍保留，避免再次刷屏。
     */
    static installProtoUpgrades() {
      if (!MixedContentQuiet._pageIsHttps()) return;
      try {
        if (Element.prototype.__silverfoxMixedUpgrade) return;
        Element.prototype.__silverfoxMixedUpgrade = true;

        const origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function (name, value) {
          try {
            const n = String(name || "").toLowerCase();
            if (n === "src" || n === "srcset" || n === "poster" || n === "href"
              || n === "data-src" || n === "data-original" || n === "data-lazy-src") {
              // link 仅样式/图标升级 href；普通 a[href] 也只升同站 http（避免把外链 http 误升）
              if (n === "href") {
                const tag = String(this.tagName || "").toUpperCase();
                if (tag === "A" || tag === "AREA") {
                  value = MixedContentQuiet.upgradeSameSiteHttp(value);
                } else {
                  value = MixedContentQuiet.upgradeAttrValue(n, value);
                }
              } else {
                value = MixedContentQuiet.upgradeAttrValue(n, value);
              }
            }
          } catch { /* ignore */ }
          return origSetAttr.call(this, name, value);
        };

        const patchSrcProp = (proto) => {
          if (!proto) return;
          try {
            const desc = Object.getOwnPropertyDescriptor(proto, "src");
            if (!desc || !desc.set || proto.__silverfoxMixedSrc) return;
            proto.__silverfoxMixedSrc = true;
            Object.defineProperty(proto, "src", {
              configurable: true,
              enumerable: desc.enumerable !== false,
              get() { return desc.get.call(this); },
              set(v) { return desc.set.call(this, MixedContentQuiet.upgradeSameSiteHttp(v)); }
            });
          } catch { /* ignore */ }
        };

        try { patchSrcProp(HTMLImageElement.prototype); } catch { /* ignore */ }
        try { patchSrcProp(HTMLSourceElement.prototype); } catch { /* ignore */ }
        try { patchSrcProp(HTMLVideoElement.prototype); } catch { /* ignore */ }
        try { patchSrcProp(HTMLAudioElement.prototype); } catch { /* ignore */ }
        try { patchSrcProp(HTMLEmbedElement.prototype); } catch { /* ignore */ }
        try { patchSrcProp(HTMLInputElement.prototype); } catch { /* ignore */ }

        try {
          const imgProto = HTMLImageElement.prototype;
          const sd = Object.getOwnPropertyDescriptor(imgProto, "srcset");
          if (sd && sd.set && !imgProto.__silverfoxMixedSrcset) {
            imgProto.__silverfoxMixedSrcset = true;
            Object.defineProperty(imgProto, "srcset", {
              configurable: true,
              enumerable: sd.enumerable !== false,
              get() { return sd.get.call(this); },
              set(v) { return sd.set.call(this, MixedContentQuiet.upgradeSrcset(v)); }
            });
          }
        } catch { /* ignore */ }
      } catch { /* ignore */ }
    }

    static installObserver() {
      if (!MixedContentQuiet._pageIsHttps()) return;
      try {
        if (window.__silverfoxMixedObs) return;
        window.__silverfoxMixedObs = true;
        const mo = new MutationObserver((records) => {
          try {
            for (const rec of records) {
              if (rec.type === "attributes" && rec.target) {
                MixedContentQuiet.upgradeElement(rec.target);
              }
              if (rec.addedNodes && rec.addedNodes.length) {
                for (const n of rec.addedNodes) {
                  if (n && n.nodeType === 1) MixedContentQuiet.scanTree(n);
                }
              }
            }
          } catch { /* ignore */ }
        });
        const arm = () => {
          try {
            const root = document.documentElement || document;
            mo.observe(root, {
              childList: true,
              subtree: true,
              attributes: true,
              attributeFilter: ["src", "srcset", "poster", "href", "style", "data-src", "data-original", "data-lazy-src"]
            });
          } catch { /* ignore */ }
        };
        if (document.documentElement) arm();
        else document.addEventListener("DOMContentLoaded", arm, { once: true });
      } catch { /* ignore */ }
    }

    static install() {
      if (!MixedContentQuiet._pageIsHttps()) return;
      try {
        if (window.__silverfoxMixedContentQuiet) return;
        window.__silverfoxMixedContentQuiet = true;
      } catch { return; }

      MixedContentQuiet.installConsoleQuiet();
      MixedContentQuiet.installProtoUpgrades();
      MixedContentQuiet.installObserver();

      // 尽早扫 + 后续补扫（静态 HTML 解析后）
      try { MixedContentQuiet.scanTree(document); } catch { /* ignore */ }
      try {
        [0, 50, 200, 800, 2000].forEach((ms) => {
          setTimeout(() => { try { MixedContentQuiet.scanTree(document); } catch { /* ignore */ } }, ms);
        });
      } catch { /* ignore */ }
      try {
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", () => {
            try { MixedContentQuiet.scanTree(document); } catch { /* ignore */ }
          }, { once: true });
        }
      } catch { /* ignore */ }
    }
  }

  NS.MixedContentQuiet = MixedContentQuiet;

  // document_start 立即安装（先于大量页面脚本写 src）
  try { MixedContentQuiet.install(); } catch { /* ignore */ }
})(window.SilverfoxPageHooks ??= {});
