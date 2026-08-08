/**
 * HTTPS 页 Mixed Content 降噪与同站升级。
 *
 * 背景：政府/新闻等站 HTML 仍写 http:// 图片，Chrome 会自动升级并刷屏：
 *   "Mixed Content: ... automatically upgraded to HTTPS"
 * 扩展的 DOM wrap 还可能出现在相关堆栈里，被误当成「插件报错」。
 *
 * 策略（均不碰主文档导航、不拦安装包判定）：
 * 1) 主文档 https: 时，公网被动资源（图/CSS/字体/音视频）写入前 http→https
 *    （含跨站 CDN，如 netease.com → 126.net；与 Chromium 自动升级一致，尽早改写）
 * 2) 纯 http: / 局域网目标一律不改写
 * 3) 永不升级 script / iframe / xhr / main_frame
 * 4) 不包装页面 console（包装会把所有站点日志首帧指到扩展）
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
     * HTTPS 文档上的被动资源 http→https。
     * - 同站/同 apex：必升（与浏览器 Mixed Content 自动升级一致）
     * - 跨站公网 CDN（如 netease.com 页加载 static.ws.126.net）：也升
     *   Chrome 本就会自动升级并打日志；我们尽早改写可减少「堆栈指到扩展」的误归因
     * - 本机/局域网：永不升
     * 返回原字符串或 https URL。
     */
    static upgradeSameSiteHttp(raw) {
      // TrustedScriptURL / TrustedURL 等对象必须原样交给原生 sink；字符串化会丢失 Trusted Types 身份。
      if (typeof raw !== "string") return raw;
      const s = raw.trim();
      if (!s || !/^http:\/\//i.test(s)) return raw;
      // 主文档是 http:（局域网 AdGuard 等）→ 绝不上调 HTTPS
      if (!MixedContentQuiet._pageIsHttps()) return raw;
      try {
        const u = new URL(s, location.href);
        if (u.protocol !== "http:") return raw;
        const th = String(u.hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
        // 本机/局域网目标主机：即便主文档是 https 也不强升（自签/无 TLS）
        if (th === "localhost" || th === "127.0.0.1" || th === "::1"
          || /\.local$|\.localhost$|\.home\.arpa$/i.test(th)
          || /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(th)
          || /^192\.168\.\d{1,3}\.\d{1,3}$/.test(th)
          || /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(th)
          || /^169\.254\.\d{1,3}\.\d{1,3}$/.test(th)
          || /^fe80:/i.test(th) || /^f[cd][0-9a-f]{0,2}:/i.test(th)) {
          return raw;
        }
        // 公网 http 被动资源：与 Chromium 自动升级策略一致，统一 https
        u.protocol = "https:";
        return u.href;
      } catch { /* ignore */ }
      return raw;
    }

    /** srcset: "a.jpg 1x, http://x/b.jpg 2x" */
    static upgradeSrcset(raw) {
      if (typeof raw !== "string") return raw;
      const s = raw;
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

    /** 仅被动资源参与 mixed-content 升级；SCRIPT/IFRAME 等 Trusted Types sink 完全透传。 */
    static isPassiveResourceAttribute(el, name) {
      const tag = String(el && el.tagName || "").toUpperCase();
      const n = String(name || "").toLowerCase();
      if (n === "src") return /^(?:IMG|SOURCE|VIDEO|AUDIO|EMBED|INPUT|TRACK)$/.test(tag);
      if (n === "srcset") return tag === "IMG" || tag === "SOURCE";
      if (n === "poster") return tag === "VIDEO";
      if (n === "href") return tag === "LINK";
      if (n === "data-src" || n === "data-original" || n === "data-lazy-src") {
        return /^(?:IMG|SOURCE|VIDEO|AUDIO)$/.test(tag);
      }
      return false;
    }

    /**
     * Chromium no longer supports the legacy viewport target-densitydpi key and
     * emits a console warning at the JavaScript caller. Because this module wraps
     * setAttribute, an otherwise harmless site warning is then attributed to the
     * extension. Drop only that ignored directive and preserve every supported
     * viewport directive.
     */
    static sanitizeLegacyViewportContent(el, name, value) {
      if (String(name || "").toLowerCase() !== "content") return value;
      try {
        if (String(el && el.tagName || "").toUpperCase() !== "META") return value;
        if (typeof value !== "string") return value;
        const text = value;
        if (!/(?:^|[,;]\s*)target-densitydpi(?:\s*=|\s*(?:[,;]|$))/i.test(text)) return value;
        const metaName = String(el.getAttribute("name") || "").toLowerCase();
        if (metaName && metaName !== "viewport") return value;
        return text
          .split(/[,;]/)
          .map((part) => part.trim())
          .filter((part) => part && !/^target-densitydpi(?:\s*=|$)/i.test(part))
          .join(", ");
      } catch {
        return value;
      }
    }

    /**
     * iframe allow / Permissions-Policy 特性里 Chromium 尚不识别 private-network，
     * 会在 setAttribute 调用栈打 "Unrecognized feature: 'private-network'"。
     * 包装器在栈上时被误当成扩展报错 → 写入前剥掉该 token。
     */
    static sanitizeAllowFeatureList(name, value) {
      const n = String(name || "").toLowerCase();
      if (n !== "allow") return value;
      if (typeof value !== "string" || !/private-network/i.test(value)) return value;
      try {
        return value
          .split(/;/)
          .map((part) => part.trim())
          .filter((part) => {
            if (!part) return false;
            const feat = part.split(/[\s=]/)[0] || "";
            return !/^private-network(?:-access)?$/i.test(feat);
          })
          .join("; ");
      } catch {
        return value;
      }
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
          if (!MixedContentQuiet.isPassiveResourceAttribute(el, a)) continue;
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
     * light/official 时会 uninstall 还原，避免 SPA 埋点 Image.src 与全树 MO 卡死页面。
     */
    static installProtoUpgrades() {
      if (!MixedContentQuiet._pageIsHttps()) return;
      if (MixedContentQuiet._disabled) return;
      try {
        if (Element.prototype.__silverfoxMixedUpgrade) return;
        Element.prototype.__silverfoxMixedUpgrade = true;

        const origSetAttr = Element.prototype.setAttribute;
        MixedContentQuiet._origSetAttribute = origSetAttr;
        Element.prototype.setAttribute = function (name, value) {
          if (MixedContentQuiet._disabled) return origSetAttr.call(this, name, value);
          try {
            const n = String(name || "").toLowerCase();
            // 非被动资源 / 非已知降噪属性：尽快回原生，缩短无关告警堆栈
            if (n === "allow") {
              value = MixedContentQuiet.sanitizeAllowFeatureList(n, value);
              return origSetAttr.call(this, name, value);
            }
            if (n === "sandbox" || n === "permissions-policy" || n === "policy") {
              return origSetAttr.call(this, name, value);
            }
            // https/相对路径占绝大多数：无 http:// 时不进升级逻辑
            if (typeof value === "string" && value.indexOf("http://") === -1 && value.indexOf("HTTP://") === -1) {
              if (n === "content") value = MixedContentQuiet.sanitizeLegacyViewportContent(this, n, value);
              return origSetAttr.call(this, name, value);
            }
            value = MixedContentQuiet.sanitizeLegacyViewportContent(this, n, value);
            if (typeof value === "string" && MixedContentQuiet.isPassiveResourceAttribute(this, n)) {
              value = MixedContentQuiet.upgradeAttrValue(n, value);
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
            MixedContentQuiet._srcRestore = MixedContentQuiet._srcRestore || [];
            MixedContentQuiet._srcRestore.push({ proto, property: "src", descriptor: desc, marker: "__silverfoxMixedSrc" });
            Object.defineProperty(proto, "src", {
              configurable: true,
              enumerable: desc.enumerable !== false,
              get() { return desc.get.call(this); },
              set(v) {
                if (MixedContentQuiet._disabled) return desc.set.call(this, v);
                // 埋点/CDN 几乎全是 https：快路径直通原生
                if (typeof v !== "string" || v.length < 8 || (v.charCodeAt(4) !== 58 /*:*/ && !/^http:\/\//i.test(v))) {
                  return desc.set.call(this, v);
                }
                if (!/^http:\/\//i.test(v)) return desc.set.call(this, v);
                return desc.set.call(this, MixedContentQuiet.upgradeSameSiteHttp(v));
              }
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
            MixedContentQuiet._srcRestore = MixedContentQuiet._srcRestore || [];
            MixedContentQuiet._srcRestore.push({ proto: imgProto, property: "srcset", descriptor: sd, marker: "__silverfoxMixedSrcset" });
            Object.defineProperty(imgProto, "srcset", {
              configurable: true,
              enumerable: sd.enumerable !== false,
              get() { return sd.get.call(this); },
              set(v) {
                if (MixedContentQuiet._disabled) return sd.set.call(this, v);
                if (typeof v !== "string" || v.indexOf("http://") === -1) return sd.set.call(this, v);
                return sd.set.call(this, MixedContentQuiet.upgradeSrcset(v));
              }
            });
          }
        } catch { /* ignore */ }
      } catch { /* ignore */ }
    }

    /**
     * 不再装全树 MutationObserver。
     * SPA（钉钉/阿里系）每帧 mutation 会把主线程拖死；原型 setAttribute/src 升级已够用。
     */
    static installObserver() {
      // intentionally empty
    }

    /** light/official：拆掉 Image.src / setAttribute wrap 与 MutationObserver，还主线程给页面。 */
    static uninstall(reason) {
      try {
        if (MixedContentQuiet._disabled) return;
        MixedContentQuiet._disabled = true;
      } catch { /* ignore */ }
      try {
        if (MixedContentQuiet._moTimer) {
          clearTimeout(MixedContentQuiet._moTimer);
          MixedContentQuiet._moTimer = null;
        }
      } catch { /* ignore */ }
      try {
        if (MixedContentQuiet._mo) {
          MixedContentQuiet._mo.disconnect();
          MixedContentQuiet._mo = null;
        }
      } catch { /* ignore */ }
      try { window.__silverfoxMixedObs = false; } catch { /* ignore */ }
      try {
        if (MixedContentQuiet._scanTimers && MixedContentQuiet._scanTimers.length) {
          for (const t of MixedContentQuiet._scanTimers) {
            try { clearTimeout(t); } catch { /* ignore */ }
          }
          MixedContentQuiet._scanTimers = null;
        }
      } catch { /* ignore */ }
      try {
        if (MixedContentQuiet._origSetAttribute
          && Element.prototype.setAttribute !== MixedContentQuiet._origSetAttribute
          && Element.prototype.__silverfoxMixedUpgrade) {
          Element.prototype.setAttribute = MixedContentQuiet._origSetAttribute;
        }
        try { delete Element.prototype.__silverfoxMixedUpgrade; } catch { /* ignore */ }
      } catch { /* ignore */ }
      try {
        const list = MixedContentQuiet._srcRestore || [];
        while (list.length) {
          const item = list.pop();
          try {
            if (item && item.proto && item.property && item.descriptor) {
              Object.defineProperty(item.proto, item.property, item.descriptor);
              if (item.marker) {
                try { delete item.proto[item.marker]; } catch { /* ignore */ }
              }
            }
          } catch { /* ignore */ }
        }
        MixedContentQuiet._srcRestore = null;
      } catch { /* ignore */ }
      try { window.__silverfoxMixedContentQuiet = false; } catch { /* ignore */ }
      void reason;
    }

    static install() {
      if (!MixedContentQuiet._pageIsHttps()) return;
      if (MixedContentQuiet._disabled) return;
      // 搜索 / 干净品牌正站（含钉钉首页）：document_start 就不装
      try {
        const PC = NS.PageContext;
        if (PC && typeof PC.shouldUseLightHooksEarly === "function" && PC.shouldUseLightHooksEarly()) {
          MixedContentQuiet._disabled = true;
          return;
        }
      } catch { /* ignore */ }
      try {
        if (window.__silverfoxMixedContentQuiet) return;
        window.__silverfoxMixedContentQuiet = true;
      } catch { return; }

      MixedContentQuiet.installConsoleQuiet();
      MixedContentQuiet.installProtoUpgrades();
      // 不装全树 MO

      // 仅一次静态扫 + DOMContentLoaded 补扫；不做定时连环 scanTree
      try { MixedContentQuiet.scanTree(document); } catch { /* ignore */ }
      try {
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", () => {
            try {
              if (!MixedContentQuiet._disabled) MixedContentQuiet.scanTree(document);
            } catch { /* ignore */ }
          }, { once: true });
        }
      } catch { /* ignore */ }
      // 短 TTL 后拆掉原型 wrap，避免长期拖慢 Image/setAttribute
      try {
        MixedContentQuiet._moTimer = setTimeout(() => {
          try { MixedContentQuiet.uninstall("ttl"); } catch { /* ignore */ }
        }, 4000);
      } catch { /* ignore */ }
    }
  }

  NS.MixedContentQuiet = MixedContentQuiet;

  // document_start 立即安装（先于大量页面脚本写 src）；light 路径会跳过
  try { MixedContentQuiet.install(); } catch { /* ignore */ }
})(window.SilverfoxPageHooks ??= {});
