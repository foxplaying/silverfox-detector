/**
 * 页面上下文判定：SERP / light page / 钓鱼空壳 / 官方下载载荷（纯静态）。
 * document_start 安全，不遍历整树。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristics } = NS;

  class PageContext {
    /** 大型第一方平台（Microsoft Store 等）注入沙箱 iframe，跳过重型原型 wrap。 */
    static hostIsMajorPlatformOrigin() {
      try {
        const h = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
        if (!h) return false;
        if (h === "apps.microsoft.com" || h === "www.microsoft.com") return true;
        return /(?:^|\.)(?:microsoft|windows|office|live|xbox|msn|bing|github|google|gstatic|apple|amazon|cloudflare|akamai|azure|office365)\.(?:com|net|org|cn|com\.cn)$/i.test(h);
      } catch {
        return false;
      }
    }

    /** 仅 URL 形态判定搜索页（document_start 安全，无 DOM 依赖）。 */
    static isSearchUrlShapeEarly() {
      try {
        const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
        if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)) return true;
        const q = location.search || "";
        if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
        return false;
      } catch {
        return false;
      }
    }

    static isSearchUrlShapeOnly() {
      try {
        const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
        const q = location.search || "";
        if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)) return true;
        if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
        if (/(?:^|\/)(?:search|results?|web|s)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
        return false;
      } catch {
        return false;
      }
    }

    static pageLooksLikeSerpUrl() {
      try {
        if (PageContext.isSearchUrlShapeOnly()) return true;
        const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
        const q = location.search || "";
        const title = document.title || "";
        if (/官网|官方下载|官方正版|官方网站|下载中心|立即下载/i.test(title)) return false;
        if (/[-–—|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title) && /[?&](?:q|query|keyword|text|wd|word|p|search)=/i.test(q)) return true;
        if (path === "/" || /(?:^|\/)(?:search|results?|web|s)(?:\/|$)/i.test(path)) {
          const searchInput = document.querySelector(
            'input[type="search"], input[name="q"], input[name="wd"], '
            + 'input[aria-autocomplete], [role="searchbox"]'
          );
          if (searchInput) {
            if (/[?&](?:q|query|keyword|text|wd|word|p|search)=/i.test(q)) return true;
            if (path === "/" && (
              searchInput.getAttribute("type") === "search"
              || searchInput.getAttribute("aria-autocomplete")
              || searchInput.getAttribute("role") === "searchbox"
            )) return true;
          }
        }
        return false;
      } catch {
        return false;
      }
    }

    /** 轻量页面上下文（无域名白名单）：钓鱼空壳 / 官方下载载荷 / 薄跳板。 */
    static pageLooksLikeDownloadPhishShell() {
      try {
        if (PageContext.pageLooksLikeOfficialDownloadPayload()) return false;
        const title = document.title || "";
        if (document.querySelector(".download-uri, a.download-uri, [class*='download-uri']")) return true;
        try {
          if (typeof window.download_uri === "string" && window.download_uri.length > 4) return true;
        } catch { /* ignore */ }
        const bodyText = ((document.body && document.body.innerText) || "").replace(/\s+/g, "");
        const thin = !document.body || bodyText.length < 400;
        const downloadPitch = /官方下载|官网下载|客户端下载|下载页面|免费下载|立即下载/i.test(title)
          || (/官网/i.test(title) && /下载|安装包|客户端/i.test(title) && thin);
        if (downloadPitch && thin) return true;
        const author = document.querySelector('meta[name="author"]')?.getAttribute("content") || "";
        if (/官网|官方下载/.test(title) && author && /[a-z0-9.-]+\.[a-z]{2,}/i.test(author) && thin) return true;
        return false;
      } catch {
        return false;
      }
    }

    static pageLooksLikeOfficialDownloadPayload() {
      try {
        let html = "";
        try {
          const head = document.head ? document.head.innerHTML : "";
          const body = document.body ? document.body.innerHTML : "";
          html = `${head}\n${body.length > 80000 ? body.slice(0, 80000) : body}`;
        } catch { html = ""; }
        if (/[A-Za-z][A-Za-z0-9]{3,}[._-](?:official[_-]?)?(?:setup|install|installer)[._-]\d+(?:\.\d+){1,4}/i.test(html)
          || /[A-Za-z][A-Za-z0-9]{4,}[._-](?:setup|installer)[._-]\d{4,}/i.test(html)) return true;
        if (!html || html.length < 200) {
          if (document.querySelector("#app, #root, #__next, #__nuxt")
            && Array.from(document.scripts || []).filter((s) => s.src).length >= 2) return true;
          return false;
        }
        if (/https?:\/\/[^"'\\<>\s]+\/[A-Za-z][A-Za-z0-9._-]{2,60}\.(?:exe|dmg|msi|pkg|apk)(?:\?|"|'|\\)/i.test(html)
          && /[A-Za-z]{3,}[._-].*\d+\.\d+|win_installer|DownloadLink|com\.[a-z0-9_]+\.[a-z0-9_]+|_setup_|_installer_/i.test(html)) return true;
        if (/com\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:[._-]\d{2,16})?\.apk/i.test(html)
          && document.querySelector("#ice-container, #root, #app, #__next, #__nuxt")) return true;
        if (/window\.__DATA__\s*=/.test(html) && /DownloadLink|win_installer/i.test(html) && /\.exe/i.test(html)) return true;
        if (document.querySelector("#ice-container, #root, #app, #__next, #__nuxt")) {
          const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
          if (ext >= 2 && /官网|官方|下载|客户端|setup|installer|download/i.test(`${document.title || ""} ${html.slice(0, 5000)}`)
            && /DownloadLink|download.*\.exe|\.exe"|com\.[a-z0-9_.]+\.apk|_setup_|\d+\.\d+\.\d+/i.test(html)) return true;
          if (ext >= 2 && /\/assets\/|polyfill|index-[a-f0-9]+\.js/i.test(html)) return true;
        }
        return false;
      } catch {
        return false;
      }
    }

    /** 薄跳板中继页：近空 + 仅内联脚本（非多 CDN 官方 SPA）。 */
    static pageLooksLikeCloakingRelay(cloakingKitFlag) {
      try {
        if (PageContext.pageLooksLikeOfficialDownloadPayload()) return false;
        if (cloakingKitFlag) return true;
        if (!document.body) return false;
        const spaRoot = document.querySelector("#app, #root, #__next, #__nuxt, #ice-container, [data-reactroot]");
        const extScripts = Array.from(document.scripts || []).filter((s) => s.src);
        const moduleOrAssets = extScripts.filter((s) =>
          /type\s*=\s*["']module["']/i.test(s.getAttribute("type") || "")
          || /\/assets\/|polyfill|index-[a-f0-9]+\.js/i.test(s.src || "")
        ).length;
        if (spaRoot && (extScripts.length >= 2 || moduleOrAssets >= 1)) return false;
        const text = (document.body.innerText || "").replace(/\s+/g, "");
        const scripts = document.scripts ? document.scripts.length : 0;
        const ext = extScripts.length;
        if (text.length < 48 && scripts >= 1 && ext <= 1) return true;
        if (text.length < 220) {
          let interactive = 0;
          try {
            interactive = document.body.querySelectorAll("a[href], button, input, img, video, form, [class*='download']").length;
          } catch { interactive = 0; }
          if (scripts >= 1 && interactive < 4 && ext <= 1) return true;
        }
        return false;
      } catch {
        return false;
      }
    }
  }

  NS.PageContext = PageContext;
  void PackageHeuristics;
})(window.SilverfoxPageHooks ??= {});
