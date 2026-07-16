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
        // 永不 outerHTML 多 MB 搜索门户——会卡死标签页
        if (PageShellDetector.looksLikeSearchPageShape()) return true;
        let html = "";
        try {
          const de = document.documentElement;
          const head = de && de.querySelector("head");
          const body = de && de.querySelector("body");
          html = `${head ? String(head.innerHTML || "").slice(0, 20000) : ""}\n${
            body ? String(body.innerHTML || "").slice(0, 40000) : ""
          }`;
        } catch {
          html = "";
        }
        if (!html || html.length < 400) return false;
        if (/https?:\/\/[^"'\\<>\s]+\/[A-Za-z][A-Za-z0-9._-]{2,60}\.(?:exe|dmg|msi|pkg|apk)(?:\?|"|'|\\)/i.test(html)
          && /DingTalk_|ToDesk_|_v\d+\.\d+|win_installer|DownloadLink|com\.[a-z0-9_]+\.[a-z0-9_]+/i.test(html)) {
          return true;
        }
        if (/com\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:[._-]\d{2,16})?\.apk/i.test(html)
          && document.querySelector("#ice-container, #root, #app, #__next, #__nuxt")) return true;
        if (/window\.__DATA__\s*=/.test(html)
          && /DownloadLink|win_installer/i.test(html) && /\.exe/i.test(html)) return true;
        if (document.querySelector("#ice-container, #root, #app, #__next, #__nuxt")) {
          const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
          if (ext >= 2 && /官网|官方|下载|客户端/i.test(document.title || "")
            && /DownloadLink|download.*\.exe|\.exe"|com\.[a-z0-9_.]+\.apk/i.test(html)) return true;
        }
        return false;
      } catch {
        return false;
      }
    }

    /** 早期钓鱼空壳信号（无域名白名单）。用于 content.js 设 guard 前拦截 location->Bing 跳转。 */
    static pageLooksLikeDownloadPhishShell() {
      try {
        if (PageShellDetector.pageLooksLikeOfficialDownloadPayload()) return false;
        const title = document.title || "";
        try {
          if (document.querySelector(".download-uri, a.download-uri, [class*='download-uri']")) return true;
        } catch { /* ignore */ }
        try {
          if (typeof window.download_uri === "string" && window.download_uri.length > 4) return true;
        } catch { /* ignore */ }
        const bodyText = ((document.body && document.body.innerText) || "").replace(/\s+/g, "");
        const thin = !document.body || bodyText.length < 400;
        const downloadPitch = /官方下载|官网下载|客户端下载|下载页面|免费下载|官方正版|立即下载/i.test(title)
          || (/官网/i.test(title) && /下载|安装包|客户端/i.test(title) && thin);
        if (downloadPitch && thin) return true;
        try {
          const author = document.querySelector('meta[name="author"]')?.getAttribute("content") || "";
          if (author && /官网|官方下载|下载/.test(title) && /[a-z0-9.-]+\.[a-z]{2,}/i.test(author) && thin) return true;
        } catch { /* ignore */ }
        return false;
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
