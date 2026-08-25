/**
 * 页面上下文判定：SERP / light page / 钓鱼空壳 / 官方下载载荷（纯静态）。
 * document_start 安全，不遍历整树。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristics } = NS;

  class PageContext {
    /** 同一事件循环内复用结构计数，避免 promote/导航钩子重复遍历。 */
    static _getStructureSnapshot() {
      const now = Date.now();
      const ready = String(document.readyState || "");
      const title = String(document.title || "");
      const cached = PageContext._structureSnapshotCache;
      if (cached && cached.ready === ready && cached.title === title && now - cached.at < 80) return cached;
      let nodes = 0; let links = 0; let scripts = 0;
      try { nodes = document.getElementsByTagName("*").length; } catch { nodes = 0; }
      try { links = document.links ? document.links.length : 0; } catch { links = 0; }
      try { scripts = document.scripts ? document.scripts.length : 0; } catch { scripts = 0; }
      const snapshot = { at: now, ready, title, nodes, links, scripts };
      PageContext._structureSnapshotCache = snapshot;
      return snapshot;
    }

    /**
     * 大型内容应用壳（行为/结构启发，无域名名单）。
     * 用于跳过 setAttribute 等重型原型 wrap：节点/链接密集且无仿冒下载话术。
     * 另：viewport 含 target-densitydpi 时 wrap 会污染 DevTools 堆栈，亦走 light。
     */
    static pageLooksLikeHeavyContentAppShell() {
      try {
        const snapshot = PageContext._getStructureSnapshot();
        const title = snapshot.title;
        // 中文「官网/官方下载」标题多为仿冒落地：默认保留全量 hook
        // 但多平台正品目录（firefox.com/download/all）可单独 light
        const cnOfficialPitch = /官网|官方下载|官方正版|官方网站|官方客户端|电脑版官网|立即免费下载|全平台官方/i.test(title);
        if (cnOfficialPitch) return false;
        // densitydpi：行为信号（常见于部分门户），非域名名单
        try {
          const vp = document.querySelector('meta[name="viewport"]');
          if (vp && /target-densitydpi/i.test(String(vp.getAttribute("content") || ""))) return true;
        } catch { /* ignore */ }
        // 明确下载控件继续保留全量 hook；正品多平台目录由独立 catalog 门判定。
        if (document.querySelector(
          ".download-uri, a.download-uri, .download-btn, #mainDownloadBtn, [class*='btn-download'], [data-download]"
        )) return false;
        try {
          if (typeof window.download_uri === "string" && window.download_uri.length > 4) return false;
        } catch { /* ignore */ }
        if (snapshot.nodes >= 1200 && snapshot.links >= 30) return true;
        if (snapshot.nodes >= 800 && snapshot.links >= 40 && snapshot.scripts >= 6) return true;
        if (snapshot.nodes >= 2000) return true;
        return false;
      } catch {
        return false;
      }
    }

    /**
     * 多平台正品下载目录（结构启发，无域名名单）。
     * 例：/zh-CN/download/all/ 同时列 Windows/macOS/Linux + 清晰安装包名。
     * 尽早 light + 还原 DOM 原型，避免 appendChild wrap 出现在页面 CSP 控制台堆栈。
     */
    static pageLooksLikeMultiPlatformProductDownloadCatalog() {
      try {
        const path = String(location.pathname || "").toLowerCase();
        const title = String(document.title || "");
        const pathHit = /(?:^|\/)download(?:\/|$)/i.test(path) || /\/download\//i.test(path);
        const titleHit = /\bdownload\b|下载|安装包|installer|get\s+firefox|get\s+chrome/i.test(title);
        if (!pathHit && !titleHit) return false;
        // 先走路径/标题廉价门，普通文章页不再为 catalog 执行载荷采样。
        if (typeof PageContext.pageLooksLikeDownloadPhishShell === "function"
          && PageContext.pageLooksLikeDownloadPhishShell()) return false;
        // 营销夹带主机（ie-huorong / huorong-pc）绝不当正品目录
        try {
          const lab = String(location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          if (/^(?:ie|im|aa|bb|cc|ca|get|pr|ott|app)[-_]/i.test(lab)) return false;
          if (/[-_](?:pc|app|soft|safe|vip|pro|cn|win|download|client|free|official)$/i.test(lab)) return false;
        } catch { /* ignore */ }

        let textSample = title;
        try {
          textSample += ` ${((document.body && document.body.innerText) || "").replace(/\s+/g, " ").slice(0, 6000)}`;
        } catch { /* ignore */ }
        let osHits = 0;
        if (/\bwindows\b|win64|win32|windows\s*10|windows\s*11/i.test(textSample)) osHits++;
        if (/\bmac\s*os\b|\bmacos\b|\bos\s*x\b|\.dmg\b|apple\s*silicon|intel\s*mac/i.test(textSample)) osHits++;
        if (/\blinux\b|ubuntu|fedora|\.tar\.(?:gz|xz|bz2)\b/i.test(textSample)) osHits++;
        if (/\bandroid\b|\.apk\b|\bios\b|iphone|ipad/i.test(textSample)) osHits++;
        if (osHits < 2) return false;

        let strong = 0;
        let suspicious = 0;
        let pkgLinks = 0;
        try {
          const links = document.querySelectorAll("a[href]");
          const lim = Math.min(links.length, 100);
          for (let i = 0; i < lim; i++) {
            const h = links[i].href || links[i].getAttribute("href") || "";
            if (!h || h.length < 8) continue;
            if (!PackageHeuristics.isPackageFileUrl(h) && !/\.(?:exe|dmg|msi|pkg|apk|zip)(?:$|\?)/i.test(h)) continue;
            pkgLinks++;
            const fn = typeof PackageHeuristics.getFilenameFromUrl === "function"
              ? PackageHeuristics.getFilenameFromUrl(h)
              : (h.split("/").pop() || "");
            if (typeof PackageHeuristics.isStrongProductInstallerUrl === "function"
              && PackageHeuristics.isStrongProductInstallerUrl(h)) strong++;
            else if (typeof PackageHeuristics.looksLikeProductPackageName === "function"
              && PackageHeuristics.looksLikeProductPackageName(fn)) strong++;
            else if (typeof PackageHeuristics.isSuspiciousPackageFilename === "function"
              && PackageHeuristics.isSuspiciousPackageFilename(fn)) suspicious++;
            else if (/firefox|chrome|edge|opera|brave|thunderbird|libreoffice|vlc/i.test(fn)
              && /setup|installer|install|\d+\.\d+/i.test(fn)) strong++;
          }
        } catch { /* ignore */ }

        if (suspicious > 0) return false;
        if (strong >= 2 && osHits >= 2) return true;
        let linkCount = 0;
        try { linkCount = document.links ? document.links.length : 0; } catch { linkCount = 0; }
        // SPA 目录：多 OS 文案 + 大量导航链，包链可能尚未展开
        if (osHits >= 3 && linkCount >= 24) return true;
        if (osHits >= 2 && linkCount >= 40 && pathHit && (strong >= 1 || pkgLinks === 0)) return true;
        return false;
      } catch {
        return false;
      }
    }

    /**
     * 干净品牌根主机（dingtalk.com 首页/任意路径）。document_start 安全。
     * 仅结构启发，不读品牌字典。
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
        if (/[-_]/.test(label)) return false;
        if (/\d{2,}/.test(label)) return false;
        if (!/^[a-z][a-z0-9]*$/i.test(label)) return false;
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
     * 廉价：干净品牌根 + /download|/client 路径（dingtalk.com/download）。
     */
    static looksLikeCleanOfficialDownloadHostPathEarly() {
      try {
        if (!PageContext.looksLikeCleanOfficialBrandHostEarly()) return false;
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

    /**
     * document_start 即可判定：应跳过重型 DOM 原型 wrap。
     * 仅 URL 形态 / 已有 head 信号，不读域名白名单。
     */
    static shouldUseLightHooksEarly() {
      try {
        if (PageContext.isSearchUrlShapeEarly()) return true;
        if (PageContext.isSearchUrlShapeOnly()) return true;
        // 仅干净「/download」路径轻量；禁止把 huorongr 这类拼写仿冒当品牌正站 light
        // （干净品牌根仅在 content 侧 ICP/WHOIS 证实后 enterIntelLightMode）
        if (PageContext.looksLikeCleanOfficialDownloadHostPathEarly()) return true;
        // 标题已是仿冒下载壳 → 必须全量 hook
        if (/官网|官方下载|官方正版|官方客户端|立即免费下载/i.test(document.title || "")) return false;
        try {
          const vp = document.querySelector('meta[name="viewport"]');
          if (vp && /target-densitydpi/i.test(String(vp.getAttribute("content") || ""))) return true;
        } catch { /* ignore */ }
        return false;
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

    /**
     * 有界载荷快照：只采样 meta、script 和下载属性，不读取 body.innerHTML。
     * 同一短时间窗口复用，供 promote / navigation / cloaking 多个调用方共享。
     */
    static _getBoundedPayloadSnapshot() {
      const now = Date.now();
      const title = String(document.title || "");
      const ready = String(document.readyState || "");
      const scripts = document.scripts || [];
      const scriptCount = scripts.length || 0;
      let linkCount = 0;
      try { linkCount = document.links ? document.links.length : 0; } catch { linkCount = 0; }
      const cache = PageContext._payloadSnapshotCache;
      if (cache && cache.ready === ready && cache.title === title
        && cache.scriptCount === scriptCount && cache.linkCount === linkCount
        && now - cache.at < 250) return cache;

      const chunks = [title];
      let total = title.length;
      let extScripts = 0;
      const append = (raw, limit) => {
        if (total >= 90000) return;
        const value = String(raw || "");
        if (!value) return;
        const room = Math.min(limit || value.length, 90000 - total);
        if (room <= 0) return;
        chunks.push(value.slice(0, room));
        total += room;
      };
      try {
        const heads = document.querySelectorAll("meta[content], link[href]");
        const lim = Math.min(heads.length || 0, 40);
        for (let i = 0; i < lim; i++) {
          append(`${heads[i].getAttribute("name") || heads[i].getAttribute("rel") || ""} ${heads[i].getAttribute("content") || heads[i].getAttribute("href") || ""}`, 1200);
        }
      } catch { /* ignore */ }
      try {
        const lim = Math.min(scriptCount, 36);
        for (let i = 0; i < lim && total < 90000; i++) {
          const script = scripts[i];
          const src = String((script && (script.src || script.getAttribute("src"))) || "");
          if (src) {
            extScripts++;
            append(src, 1600);
          } else {
            append(String((script && script.textContent) || ""), 6000);
          }
        }
        // 上限以外的外链脚本仍只计数，不读取正文。
        for (let i = lim; i < scriptCount; i++) {
          if (scripts[i] && (scripts[i].src || scripts[i].getAttribute("src"))) extScripts++;
        }
      } catch { /* ignore */ }
      try {
        const links = document.querySelectorAll("a[href], a[data-href], [data-download], [data-url]");
        const lim = Math.min(links.length || 0, 80);
        for (let i = 0; i < lim && total < 90000; i++) {
          const el = links[i];
          const value = String(el.getAttribute("href") || el.getAttribute("data-href")
            || el.getAttribute("data-download") || el.getAttribute("data-url") || "");
          if (/download|installer|setup|\.(?:exe|msi|msix|dmg|pkg|apk|zip|rar|7z)(?:[?#]|$)/i.test(value)) append(value, 2000);
        }
      } catch { /* ignore */ }

      let spaRoot = false;
      try { spaRoot = !!document.querySelector("#ice-container, #root, #app, #__next, #__nuxt"); } catch { spaRoot = false; }
      const snapshot = {
        at: now,
        ready,
        title,
        scriptCount,
        linkCount,
        extScripts,
        spaRoot,
        html: chunks.join("\n")
      };
      PageContext._payloadSnapshotCache = snapshot;
      return snapshot;
    }

    /** 轻量页面上下文（无域名白名单）：钓鱼空壳 / 官方下载载荷 / 薄跳板。 */
    static pageLooksLikeDownloadPhishShell() {
      try {
        const title = document.title || "";
        const selectorHit = !!document.querySelector(".download-uri, a.download-uri, [class*='download-uri']");
        let globalDownloadUri = false;
        try {
          globalDownloadUri = typeof window.download_uri === "string" && window.download_uri.length > 4;
        } catch { /* ignore */ }
        const titleCandidate = /官方下载|官网下载|客户端下载|下载页面|免费下载|立即下载/i.test(title)
          || (/官网/i.test(title) && /下载|安装包|客户端/i.test(title));
        // 普通内容页/导航调用在此廉价返回，不采样脚本、更不读取正文。
        if (!selectorHit && !globalDownloadUri && !titleCandidate) return false;
        if (PageContext.pageLooksLikeOfficialDownloadPayload()) return false;
        if (selectorHit || globalDownloadUri) return true;
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
        const snapshot = PageContext._getBoundedPayloadSnapshot();
        if (typeof snapshot.officialPayload === "boolean") return snapshot.officialPayload;
        const done = (value) => {
          snapshot.officialPayload = !!value;
          return snapshot.officialPayload;
        };
        const html = snapshot.html || "";
        if (/[A-Za-z][A-Za-z0-9]{3,}[._-](?:official[_-]?)?(?:setup|install|installer)[._-]\d+(?:\.\d+){1,4}/i.test(html)
          || /[A-Za-z][A-Za-z0-9]{4,}[._-](?:setup|installer)[._-]\d{4,}/i.test(html)) return done(true);
        if (!html || html.length < 200) {
          if (snapshot.spaRoot && snapshot.extScripts >= 2) return done(true);
          return done(false);
        }
        if (/https?:\/\/[^"'\\<>\s]+\/[A-Za-z][A-Za-z0-9._-]{2,60}\.(?:exe|dmg|msi|pkg|apk)(?:\?|"|'|\\)/i.test(html)
          && /[A-Za-z]{3,}[._-].*\d+\.\d+|win_installer|DownloadLink|com\.[a-z0-9_]+\.[a-z0-9_]+|_setup_|_installer_/i.test(html)) return done(true);
        if (/com\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:[._-]\d{2,16})?\.apk/i.test(html)
          && snapshot.spaRoot) return done(true);
        if (/window\.__DATA__\s*=/.test(html) && /DownloadLink|win_installer/i.test(html) && /\.exe/i.test(html)) return done(true);
        if (snapshot.spaRoot) {
          if (snapshot.extScripts >= 2 && /官网|官方|下载|客户端|setup|installer|download/i.test(`${document.title || ""} ${html.slice(0, 5000)}`)
            && /DownloadLink|download.*\.exe|\.exe"|com\.[a-z0-9_.]+\.apk|_setup_|\d+\.\d+\.\d+/i.test(html)) return done(true);
          if (snapshot.extScripts >= 2 && /\/assets\/|polyfill|index-[a-f0-9]+\.js/i.test(html)) return done(true);
        }
        return done(false);
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
