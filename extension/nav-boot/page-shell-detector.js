/**
 * 页面壳层识别（纯静态，无状态）。
 * 判定当前文档是否为：搜索结果页 / 官方下载 SPA 载荷 / 下载钓鱼空壳 / 薄跳板中继页。
 */
;(function (NS) {
  "use strict";

  class PageShellDetector {
    /** 仅 URL 形态判定搜索页（document_start 安全，无 DOM 依赖）。 */
    static isSearchUrlShapeEarly() {
      try {
        const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
        if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)) return true;
        const q = location.search || "";
        if (/\/(?:s|web)$/i.test(path)
          && /[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
        return false;
      } catch {
        return false;
      }
    }

    /**
     * 干净品牌根主机（dingtalk.com / todesk.com），不要求 /download 路径。
     * document_start 安全：不读 DOM。用于官网首页 SPA 跳过 Location/套件 MO。
     * 仅结构启发：短无连字符 apex 左标；营销填充/仿冒主机返回 false。
     */
    static looksLikeCleanOfficialBrandHostEarly() {
      try {
        const host = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
        if (!host || host.split(".").length < 2) return false;
        const parts = host.split(".").filter(Boolean);
        let label = parts[0] || "";
        if (parts.length >= 3) {
          const last = parts[parts.length - 1] || "";
          const second = parts[parts.length - 2] || "";
          if ((last === "cn" && /^(?:com|net|org|gov|edu|ac)$/i.test(second))
            || (last.length === 2 && /^(com|net|org|co|ac|gov|edu)$/i.test(second))) {
            label = parts[parts.length - 3] || label;
          } else {
            label = parts[parts.length - 2] || label;
          }
        } else if (parts.length === 2) {
          label = parts[0] || "";
        }
        if (!label || label.length < 3 || label.length > 16) return false;
        // 纯字母品牌根（允许单数字如 web2）；拒绝连字符/下划线/长数字填充
        if (/[-_]/.test(label)) return false;
        if (/\d{2,}/.test(label)) return false;
        if (!/^[a-z][a-z0-9]*$/i.test(label)) return false;
        // 营销子域不当「品牌正站」
        if (parts.length >= 3) {
          const sub = parts[0] || "";
          if (/^(?:win|pc|download|down|dl|soft|vip|free|get|safe|official|cdn|static)$/i.test(sub)) return false;
        }
        return true;
      } catch {
        return false;
      }
    }

    /**
     * 干净品牌根 + /download|/client（dingtalk.com/download）。
     * document_start 安全：不读 DOM。命中则 nav-boot 不装 Location/套件 MO。
     */
    static looksLikeCleanOfficialDownloadHostPathEarly() {
      try {
        if (!PageShellDetector.looksLikeCleanOfficialBrandHostEarly()) return false;
        const path = String(location.pathname || "").toLowerCase();
        if (!/\/(download|downloads|client|app|apps|get|install)(\/|$|\.)/i.test(path)
          && !/\/(pc|desktop|mobile)\/(download|client)/i.test(path)) {
          return false;
        }
        return true;
      } catch {
        return false;
      }
    }

    /** document_start：搜索 / 干净 /download 路径 → 不装重型 Location/套件钩子。 */
    static shouldUseLightNavBootEarly() {
      try {
        if (PageShellDetector.isSearchUrlShapeEarly()) return true;
        // 禁止干净品牌根首页 light：huorongr.com.cn 会被当成正站跳过仿冒检测
        if (PageShellDetector.looksLikeCleanOfficialDownloadHostPathEarly()) return true;
        return false;
      } catch {
        return false;
      }
    }

    /** 搜索页结构形态（含少量 DOM 探测，不遍历整树）。 */
    static looksLikeSearchPageShape() {
      try {
        const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
        const q = location.search || "";
        if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)) return true;
        if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search)=/i.test(q)) return true;
        if (/(?:^|\/)(?:search|results?|web|s)(?:\/|$)/i.test(path)
          && /[?&](?:q|query|keyword|text|wd|word|p|search)=/i.test(q)) return true;
        if (path === "/") {
          try {
            if (document.querySelector(
              'input[type="search"], input[name="q"], input[name="wd"], '
              + 'input[aria-autocomplete], [role="searchbox"]'
            )) return true;
          } catch { /* ignore */ }
        }
        return false;
      } catch {
        return false;
      }
    }

    /** 官方 SPA 下载载载荷（钉钉 __DATA__ / 产品 .exe / Android APK）——绝不当作套件。 */
    static pageLooksLikeOfficialDownloadPayload() {
      try {
        // 短缓存：shouldBlock / kitScan 热路径会连打，禁止每次读 60KB HTML
        const now = Date.now();
        if (PageShellDetector._officialPayloadCache
          && now - PageShellDetector._officialPayloadCacheAt < 2500) {
          return PageShellDetector._officialPayloadCache;
        }
        // 永不 outerHTML 多 MB 搜索门户——会卡死标签页
        if (PageShellDetector.looksLikeSearchPageShape()) {
          PageShellDetector._officialPayloadCache = true;
          PageShellDetector._officialPayloadCacheAt = now;
          return true;
        }
        if (PageShellDetector.looksLikeCleanOfficialBrandHostEarly()
          || PageShellDetector.looksLikeCleanOfficialDownloadHostPathEarly()) {
          PageShellDetector._officialPayloadCache = true;
          PageShellDetector._officialPayloadCacheAt = now;
          return true;
        }
        let html = "";
        try {
          const de = document.documentElement;
          const head = de && de.querySelector("head");
          // 只读 head + body 开头，禁止 body.innerHTML 整树序列化（大 SPA 卡死）
          const body = de && de.querySelector("body");
          html = `${head ? String(head.innerHTML || "").slice(0, 12000) : ""}\n${
            body ? String(body.innerHTML || "").slice(0, 8000) : ""
          }`;
        } catch {
          html = "";
        }
        let hit = false;
        if (html && html.length >= 200) {
          if (/https?:\/\/[^"'\\<>\s]+\/[A-Za-z][A-Za-z0-9._-]{2,60}\.(?:exe|dmg|msi|pkg|apk)(?:\?|"|'|\\)/i.test(html)
            && /_v\d+\.\d+|win_installer|DownloadLink|com\.[a-z0-9_]+\.[a-z0-9_]+/i.test(html)) {
            hit = true;
          } else if (/com\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:[._-]\d{2,16})?\.apk/i.test(html)
            && document.querySelector("#ice-container, #root, #app, #__next, #__nuxt")) {
            hit = true;
          } else if (/window\.__DATA__\s*=/.test(html)
            && /DownloadLink|win_installer/i.test(html) && /\.exe/i.test(html)) {
            hit = true;
          } else if (document.querySelector("#ice-container, #root, #app, #__next, #__nuxt")) {
            let ext = 0;
            try {
              const scripts = document.scripts || [];
              const n = Math.min(scripts.length, 40);
              for (let i = 0; i < n; i++) if (scripts[i].src) ext++;
            } catch { ext = 0; }
            if (ext >= 2 && /官网|官方|下载|客户端/i.test(document.title || "")
              && /DownloadLink|download.*\.exe|\.exe"|com\.[a-z0-9_.]+\.apk/i.test(html)) hit = true;
          }
        }
        PageShellDetector._officialPayloadCache = hit;
        PageShellDetector._officialPayloadCacheAt = now;
        return hit;
      } catch {
        return false;
      }
    }

    /** 早期钓鱼空壳信号（无域名白名单）。用于 content.js 设 guard 前拦截 location->Bing 跳转。 */
    static pageLooksLikeDownloadPhishShell() {
      try {
        const now = Date.now();
        if (PageShellDetector._phishShellCache
          && now - PageShellDetector._phishShellCacheAt < 1500) {
          return PageShellDetector._phishShellCache;
        }
        if (PageShellDetector.pageLooksLikeOfficialDownloadPayload()) {
          PageShellDetector._phishShellCache = false;
          PageShellDetector._phishShellCacheAt = now;
          return false;
        }
        const title = document.title || "";
        try {
          if (document.querySelector(".download-uri, a.download-uri, [class*='download-uri']")) {
            PageShellDetector._phishShellCache = true;
            PageShellDetector._phishShellCacheAt = now;
            return true;
          }
        } catch { /* ignore */ }
        try {
          if (typeof window.download_uri === "string" && window.download_uri.length > 4) {
            PageShellDetector._phishShellCache = true;
            PageShellDetector._phishShellCacheAt = now;
            return true;
          }
        } catch { /* ignore */ }
        // 绝不用 body.innerText：会强制整页 layout reflow，钉钉等 SPA 直接卡死
        let thin = !document.body;
        if (!thin) {
          try {
            // textContent 不触发布局；只估前几块子节点长度
            const body = document.body;
            let len = 0;
            const kids = body.childNodes;
            const maxKids = Math.min(kids.length || 0, 12);
            for (let i = 0; i < maxKids && len < 500; i++) {
              const n = kids[i];
              if (!n) continue;
              if (n.nodeType === 3) len += String(n.nodeValue || "").length;
              else if (n.nodeType === 1) len += String(n.textContent || "").length;
            }
            if (len === 0) {
              try { len = String(body.textContent || "").slice(0, 500).length; } catch { len = 0; }
            }
            thin = len < 400;
          } catch {
            thin = true;
          }
        }
        const downloadPitch = /官方下载|官网下载|客户端下载|下载页面|免费下载|官方正版|立即下载/i.test(title)
          || (/官网/i.test(title) && /下载|安装包|客户端/i.test(title) && thin);
        let hit = !!(downloadPitch && thin);
        if (!hit) {
          try {
            const author = document.querySelector('meta[name="author"]')?.getAttribute("content") || "";
            if (author && /官网|官方下载|下载/.test(title) && /[a-z0-9.-]+\.[a-z]{2,}/i.test(author) && thin) hit = true;
          } catch { /* ignore */ }
        }
        PageShellDetector._phishShellCache = hit;
        PageShellDetector._phishShellCacheAt = now;
        return hit;
      } catch {
        return false;
      }
    }

    /**
     * 薄跳板中继页：近乎空页面，仅用于 location.replace 逃逸。
     * @param {boolean} cloakingKit 是否已确认 SEO 伪装套件
     */
    static pageLooksLikeCloakingRelay(cloakingKit) {
      try {
        if (PageShellDetector.pageLooksLikeOfficialDownloadPayload()) return false;
        if (cloakingKit) return true;
        if (!document.body) return false; // document_start 无 body，非跳板信号
        try {
          const spaRoot = document.querySelector("#app, #root, #__next, #__nuxt, #ice-container");
          const extScripts = Array.from(document.scripts || []).filter((s) => s.src);
          if (spaRoot && extScripts.length >= 2) return false;
          if (spaRoot && extScripts.some((s) => /\/assets\/|type=["']module["']/i.test(s.outerHTML || s.src || ""))) return false;
        } catch { /* ignore */ }
        const text = (document.body.innerText || "").replace(/\s+/g, "");
        const scripts = document.scripts ? document.scripts.length : 0;
        const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
        if (text.length < 48 && scripts >= 1 && ext <= 1) return true;
        if (text.length < 220) {
          let interactive = 0;
          try {
            interactive = document.body.querySelectorAll(
              "a[href], button, input, img, video, form, [class*='download']"
            ).length;
          } catch { interactive = 0; }
          if (scripts >= 1 && interactive < 4 && ext <= 1) return true;
        }
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i) || "";
            if (/^zhizhu[_-]/i.test(k)) return true;
          }
        } catch { /* ignore */ }
        return false;
      } catch {
        return false;
      }
    }
  }

  NS.PageShellDetector = PageShellDetector;
})(window.SilverfoxNavBoot ??= {});
