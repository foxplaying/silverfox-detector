/**
 * 页面上下文：SERP 检测、benign 内容页判定、DOM 异常 / 环境异常扫描。
 */
;(function (NS) {
  "use strict";

  NS.isSearchUrlShapeOnly = function () {
    try {
      const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
      const q = location.search || "";
      if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)) return true;
      if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
      if (/(?:^|\/)(?:search|results?|web|s)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
      return false;
    } catch { return false; }
  };

  NS.pageHasStructuralSearchChrome = function () {
    try {
      const title = document.title || "";
      if (/官网|官方下载|官方正版|官方网站|官方客户端|下载中心|立即下载|正版下载/i.test(title)) return false;
      const path = (location.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
      const q = location.search || "";
      const pathSearchish = path === "/" || /(?:^|\/)(?:search|results?|web|s|so|find|query)(?:\/|$)/i.test(path);
      if (!pathSearchish) return false;
      if (/[?&](?:q|query|keyword|text|wd|word|p|search|kw)=/i.test(q)) return true;
      if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)) return true;
      const searchInput = document.querySelector('input[type="search"], input[name="q"], input[name="wd"], input[aria-autocomplete], [role="searchbox"]');
      if (!searchInput) return false;
      if (path === "/" || path === "") {
        if (searchInput.getAttribute("type") === "search") return true;
        if (searchInput.getAttribute("aria-autocomplete")) return true;
        if (searchInput.getAttribute("role") === "searchbox") return true;
      }
      return false;
    } catch { return false; }
  };

  NS.pageLooksLikeSearchEngineResultsPage = function () {
    try {
      const c = NS.caches;
      const now = Date.now();
      const href = location.href || "";
      if (c._serpCache != null && c._serpCacheUrl === href && now - c._serpCacheAt < 3000) return c._serpCache;
      let result = false;
      if (NS.isSearchUrlShapeOnly()) result = true;
      else if (typeof NS.looksLikeSearchEngineLandingUrl === "function" && NS.looksLikeSearchEngineLandingUrl(href)) result = true;
      else {
        const path = (location.pathname || "/").toLowerCase();
        const q = location.search || "";
        const title = document.title || "";
        if (/[-–|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title) || /\s[-–]\s*(搜索|Search)\s*$/i.test(title)) {
          if (/[?&](?:q|query|keyword|text|wd|word|p|search)=/i.test(q) || /(?:^|\/)(?:search|s|web|results?)(?:\/|$)/i.test(path)) result = true;
        }
        if (!result && NS.pageHasStructuralSearchChrome()) result = true;
      }
      c._serpCache = result;
      c._serpCacheAt = now;
      c._serpCacheUrl = href;
      if (result && !NS.state._serpLightNotified) {
        NS.state._serpLightNotified = true;
        try { NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
      }
      return result;
    } catch { return false; }
  };

  NS.estimatePageContext = function (force = false) {
    const state = NS.state;
    const now = Date.now();
    if (!force && state.contextCache && now - state.contextCacheAt < 2500) return state.contextCache;
    let visibleTextLength = 0;
    try {
      const t = (document.body && (document.body.textContent || document.body.innerText)) || "";
      visibleTextLength = t.replace(/\s+/g, " ").trim().length;
    } catch { visibleTextLength = 0; }
    let visibleLinks = 0;
    try { visibleLinks = document.links ? document.links.length : document.querySelectorAll("a[href]").length; } catch { visibleLinks = 0; }
    let total = 0;
    try { total = document.body ? document.body.getElementsByTagName("*").length : 0; } catch { total = 0; }
    const visibleElements = total;
    const ctx = { visibleTextLength, visibleLinks, visibleElements, totalElements: total };
    state.visibleLinks = visibleLinks;
    state.visibleTextLength = visibleTextLength;
    state.visibleElements = visibleElements;
    state.contextCache = ctx;
    state.contextCacheAt = now;
    return ctx;
  };

  NS.looksLikeNormalContent = function (context) {
    return context.visibleTextLength > 600 || context.visibleLinks > 20 || context.visibleElements > 250;
  };

  /**
   * 科技博客 / 资讯文章页（评测、开源推荐、B 站安利等）。
   * 标题会提第三方软件名，但页面是文章而非「该软件仿冒官网下载壳」。
   * 例：xiaoyi.vc「这么牛逼，初中生开发杀毒软件：西瓜杀毒…」
   */
  NS.pageLooksLikeEditorialArticleOrNewsPost = function () {
    try {
      const title = (document.title || "").trim();
      // 明确官网下载壳不按资讯放过
      if (/(?:官方客户端|电脑版官网|全平台官方|官方正版下载|官网免费下载|官方网站下载)/i.test(title)) return false;
      if (/(?:官方下载|官方正版|官网下载).{0,8}(?:中心|客户端|安装包)/i.test(title)
        && !/(?:趣闻|评测|开源|体验|推荐|刷到|初中生|B站|下一篇|上一篇)/i.test(title)) {
        return false;
      }

      let score = 0;
      const ogType = String(document.querySelector('meta[property="og:type"]')?.getAttribute("content") || "").toLowerCase();
      if (ogType === "article") score += 3;
      if (document.querySelector('meta[property="article:published_time"], meta[property="article:modified_time"]')) score += 2;
      if (document.querySelector('meta[name="author"], meta[property="article:author"], [rel="author"]')) score += 1;

      try {
        const scripts = document.querySelectorAll('script[type="application/ld+json"]');
        const n = Math.min(scripts.length, 8);
        for (let i = 0; i < n; i++) {
          const raw = scripts[i].textContent || "";
          if (/"@type"\s*:\s*"Article"/i.test(raw) || /"@type"\s*:\s*\[\s*"[^"]*Article/i.test(raw)
            || /"@type"\s*:\s*"NewsArticle"/i.test(raw) || /"@type"\s*:\s*"BlogPosting"/i.test(raw)) {
            score += 3;
            break;
          }
        }
      } catch { /* ignore */ }

      if (document.querySelector("article.post, article.hentry, .post-navigation, nav.post-navigation, .entry-content, .post-content, .kratos-entry, #comments, .comments-area")) score += 2;
      if (document.querySelector(".nav-previous, .nav-next, a[rel='prev'], a[rel='next'], .post-navigation")) score += 1;

      const desc = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").slice(0, 280);
      const siteName = String(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "").trim();
      const headBlob = `${title} ${desc}`;
      if (/(?:B站|刷到|初中生|高中生|开源|科技趣闻|软件推荐|评测|体验|安利|种草|下一篇|上一篇)/i.test(headBlob)) score += 2;
      // 标题党 + 站名后缀：… - 小羿
      if (/[，,].{6,}[-–—]\s*[一-鿿A-Za-z0-9]{2,16}\s*$/.test(title) && siteName && title.includes(siteName)) score += 1;
      if (siteName && title.endsWith(siteName) && /[：:]/.test(title)) score += 1;

      // WordPress 文章常见结构（非仿冒壳专属）
      try {
        const htmlHead = String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 40000);
        if (/\/wp-content\/(?:themes|uploads|plugins)\//i.test(htmlHead) && (ogType === "article" || score >= 3)) score += 1;
      } catch { /* ignore */ }

      if (score < 4) return false;

      // 反例：多平台下载 CTA + 官方话术的仿冒落地（即便套了 WP 壳）
      try {
        const bodyHead = ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").slice(0, 2500);
        const platformDl = document.querySelectorAll(".platform-btn, button.platform-btn, .download-btn, a.download-btn, [class*='platform-']").length;
        const officialPitch = /官方下载|官方客户端|全平台官方|电脑版官网|立即免费下载/i.test(`${title} ${bodyHead}`);
        if (platformDl >= 4 && officialPitch) return false;
        if (officialPitch && document.querySelectorAll("a[href*='.exe'], a[href*='.zip'], a[href*='.msi']").length >= 2) return false;
      } catch { /* ignore */ }

      return true;
    } catch { return false; }
  };

  /**
   * 软件「下载落地页壳」统一门控（品牌仿冒 / 下载页检测共用）。
   * 必须同时具备：下载门户话术（pitch）+ 下载壳证据（CTA/安装包/多平台/hub…）。
   * 资讯博客、普通内容页即使提到产品名也不应 ok。
   * @returns {{ ok:boolean, pitch:boolean, softPitch:boolean, shellScore:number, hardShell:boolean,
   *   ctaCount:number, pkgCount:number, hrefless:number, multiPlatform:boolean, hasHub:boolean,
   *   editorial:boolean, reasons:string[] }}
   */
  NS.evaluateSoftwareDownloadLandingShell = function () {
    const empty = {
      ok: false, pitch: false, softPitch: false, shellScore: 0, hardShell: false,
      ctaCount: 0, pkgCount: 0, hrefless: 0, multiPlatform: false, hasHub: false,
      editorial: false, reasons: []
    };
    try {
      if (typeof NS.pageLooksLikeSearchEngineResultsPage === "function" && NS.pageLooksLikeSearchEngineResultsPage()) {
        return { ...empty, reasons: ["serp"] };
      }
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) {
        return { ...empty, reasons: ["app-market"] };
      }
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
        return { ...empty, reasons: ["software-catalog"] };
      }

      const title = (document.title || "").trim();
      const path = (location.pathname || "").toLowerCase();
      const desc = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").slice(0, 420);
      // keywords 常写「火绒安全官网」；兼容错误写法 <meta name="keywords" , content="...">
      let keywords = "";
      try {
        keywords = String(document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "");
        if (!keywords) {
          for (const el of Array.from(document.querySelectorAll("meta")).slice(0, 40)) {
            const n = String(el.getAttribute("name") || el.getAttribute("property") || "").toLowerCase();
            if (n === "keywords" || n.includes("keyword")) {
              const c = el.getAttribute("content");
              if (c) { keywords = String(c); break; }
            }
          }
        }
      } catch { /* ignore */ }
      keywords = keywords.slice(0, 420);
      const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(1400) : "";
      // 导航/Hero 下载按钮文案也算话术（title 可能只有「安静·纯净·强悍」）
      let ctaTextBlob = "";
      try {
        ctaTextBlob = Array.from(document.querySelectorAll(
          "a[href], button, .btn-header, .btn-primary, .btn-lg, .download-btn, [role='button']"
        )).slice(0, 40).map((el) => (el.textContent || "").replace(/\s+/g, " ").trim())
          .filter((t) => t.length >= 2 && t.length <= 24 && /下载|官方|客户端|安装|免费/i.test(t))
          .join(" ");
      } catch { /* ignore */ }
      const claim = `${title} ${headings} ${desc} ${keywords} ${ctaTextBlob}`;

      // 强下载门户话术（勿用裸「杀毒软件/安全软件」）
      const strongPitchRe = /官网|官方下载|官方正版|官方网站|官方客户端|电脑版官网|全平台官方|下载中心|客户端下载|官方桌面|正版下载|免费下载_官方|立即免费下载|全平台客户端|官方渠道|安全官网|软件官网/i;
      let pitch = strongPitchRe.test(claim)
        || (typeof NS.pageClaimsOfficialDownload === "function" && NS.pageClaimsOfficialDownload());
      // 弱下载意图：标题/keywords/按钮「免费下载」；安静·纯净·强悍 类标题靠 CTA + keywords
      let softPitch = /免费下载|立即下载|客户端下载|安装包|下载中心|官方下载|官网/i.test(title)
        || /免费下载|立即下载|官方下载|官网下载|安全官网|软件官网|安全下载/i.test(keywords)
        || /免费下载|立即免费下载|立即下载|官方下载|客户端下载|个人版下载/i.test(ctaTextBlob)
        || (/全平台|客户端/i.test(title) && /下载|安装/i.test(claim));

      const dlText = NS.DOWNLOAD_TEXT || /下载|download|安装|客户端|安装包|免费下载|立即下载|官方下载/i;
      let ctaCount = 0;
      let hrefless = 0;
      let pkgCount = 0;
      let hasHub = /download\.html|(?:^|\/)download(?:\/|$)|download\.php/i.test(path);
      let platformHint = 0;
      let hubLinkCount = 0;

      try {
        const nodes = document.querySelectorAll(
          "a[href], a[data-href], a[data-url], button, [role='button'], [onclick], .btn-p, .btn-g, .nav-cta, .btn-header, .btn-download, .download-btn, a.download-btn, a.btn-primary, a.btn-lg, .platform-btn, button.platform-btn"
        );
        const lim = Math.min(nodes.length, 140);
        for (let i = 0; i < lim; i++) {
          const el = nodes[i];
          let href = "";
          try {
            href = (typeof NS.getElementDownloadHref === "function" ? NS.getElementDownloadHref(el) : "")
              || el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-url") || "";
          } catch { href = el.getAttribute("href") || ""; }
          const text = (el.textContent || "").replace(/\s+/g, " ").trim();
          if (text.length > 80) continue;
          const cls = String(el.className || "");
          const isCta = dlText.test(text)
            || /立即下载|免费下载|立即免费下载|立即使用|前往\s*App\s*Store|Windows\s*版|查看其他平台|下载中心|获取客户端|个人版下载/i.test(text)
            || /download\.php|download\.html|\/download/i.test(href)
            || (typeof NS.isPackageFileUrl === "function" && NS.isPackageFileUrl(href))
            || /startDownload\s*\(|openDownloadModal/i.test(el.getAttribute("onclick") || "")
            // btn-header / btn-primary 是仿冒首页典型 CTA（勿只认 download-btn）
            || (/download-btn|btn-download|platform-btn|btn-header|btn-primary|btn-lg/i.test(cls)
              && text.length >= 1 && text.length < 40 && /下载|免费|官方|客户端|个人版/i.test(text));
          if (!isCta) continue;
          ctaCount++;
          if (!href || href === "#" || /^javascript:/i.test(href)) hrefless++;
          if (typeof NS.isPackageFileUrl === "function" && NS.isPackageFileUrl(href)) pkgCount++;
          // 同域 download.html / 下载中心：首页导流到下载落地（主动 fetch 目标）
          try {
            if (href && typeof NS.looksLikeSameOriginLandingPageUrl === "function" && NS.looksLikeSameOriginLandingPageUrl(href)) {
              hasHub = true;
              hubLinkCount++;
            } else if (/download\.html|download\.php|(?:^|\/)download(?:\/|$|\?)/i.test(href)) {
              hasHub = true;
              hubLinkCount++;
            }
          } catch {
            if (/download\.html|download\.php|(?:^|\/)download(?:\/|$|\?)/i.test(href)) {
              hasHub = true;
              hubLinkCount++;
            }
          }
          if (/Windows|macOS|\bMac\b|Linux|Android|iOS|鸿蒙|Win(?:dows)?\s*\d/i.test(text)) platformHint++;
        }
      } catch { /* ignore */ }

      // 页面内安装包链（含非 CTA 文本的 a[href]）
      try {
        if (typeof NS.collectAllPagePackageHrefs === "function") {
          pkgCount = Math.max(pkgCount, (NS.collectAllPagePackageHrefs() || []).length);
        } else {
          const anchors = document.querySelectorAll("a[href]");
          const alim = Math.min(anchors.length, 200);
          let n = 0;
          for (let i = 0; i < alim; i++) {
            try {
              if (typeof NS.isPackageFileUrl === "function" && NS.isPackageFileUrl(anchors[i].getAttribute("href") || "")) n++;
            } catch { /* ignore */ }
          }
          pkgCount = Math.max(pkgCount, n);
        }
      } catch { /* ignore */ }

      const html = typeof NS.getHtmlSlice === "function"
        ? NS.getHtmlSlice(60000)
        : String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 60000);
      const bodyHead = ((document.body && (document.body.innerText || document.body.textContent)) || "")
        .replace(/\s+/g, " ").trim().slice(0, 2800);
      const multiPlatform = platformHint >= 2
        || (ctaCount >= 3 && /Windows|macOS|Android|iOS|Linux|鸿蒙/i.test(`${bodyHead} ${html.slice(0, 6000)}`));
      const cloudDriveQr = /夸克|百度网盘|扫码.*下载|二维码/i.test(html)
        && /openDownloadModal|qr-grid|qr-item|modal/i.test(html);
      const seoTemplate = /seo[_-]?templates?/i.test(html);
      const encryptedDl = typeof NS.hasEncryptedNuxtDownloadConfig === "function"
        && NS.hasEncryptedNuxtDownloadConfig(html);
      const schemaApp = /"@type"\s*:\s*"SoftwareApplication"/i.test(html)
        && /downloadUrl|installUrl|operatingSystem/i.test(html);
      // pageClaimsBrandDownloadLanding 可能偏松：仅当已有 CTA/包时采信
      if (!pitch && typeof NS.pageClaimsBrandDownloadLanding === "function" && NS.pageClaimsBrandDownloadLanding()
        && (ctaCount >= 1 || pkgCount >= 1 || multiPlatform || hasHub)) {
        pitch = true;
      }

      let shellScore = 0;
      const reasons = [];
      if (ctaCount >= 1) { shellScore += 1; reasons.push("dl-cta"); }
      if (ctaCount >= 3) { shellScore += 1; reasons.push("dl-cta-many"); }
      if (pkgCount >= 1) { shellScore += 2; reasons.push("pkg"); }
      if (hasHub) { shellScore += 2; reasons.push("hub"); }
      if (hubLinkCount >= 2) { shellScore += 1; reasons.push("hub-links"); }
      if (multiPlatform) { shellScore += 2; reasons.push("multi-platform"); }
      if (hrefless >= 3) { shellScore += 2; reasons.push("hrefless-shell"); }
      if (cloudDriveQr) { shellScore += 2; reasons.push("cloud-qr"); }
      if (seoTemplate) { shellScore += 2; reasons.push("seo-template"); }
      if (encryptedDl) { shellScore += 2; reasons.push("encrypted-dl"); }
      if (schemaApp) { shellScore += 1; reasons.push("schema-app"); }
      if (/(?:^|\/)download(?:\.html)?$/i.test(path) || /download\.php/i.test(path)) {
        shellScore += 1;
        reasons.push("path-dl");
      }

      // 首页导流壳：多个「免费下载」→ download.html + 官网/关键词 pitch（包链在子页，靠主动 fetch）
      const hubPortalShell = hasHub && hubLinkCount >= 1 && ctaCount >= 1 && (pitch || softPitch);

      // 营销夹带主机 huorong-pc / im-todesk + 下载 CTA → 强制门户壳
      let paddedMktHost = false;
      try {
        const labRaw = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const labFlat = labRaw.replace(/-/g, "");
        const core = typeof NS.inferMarketingPaddedBrandCore === "function"
          ? (NS.inferMarketingPaddedBrandCore(labRaw) || "")
          : "";
        paddedMktHost = !!(core && core.length >= 4 && (
          (typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(labFlat, core))
          || /[-_](pc|app|soft|safe|vip|pro|download|client)$/i.test(labRaw)
        ));
      } catch { /* ignore */ }

      let hardShell = pkgCount >= 1
        || hasHub
        || hubPortalShell
        || (paddedMktHost && ctaCount >= 1)
        || (multiPlatform && ctaCount >= 2)
        || hrefless >= 4
        || seoTemplate
        || encryptedDl
        || cloudDriveQr
        || (ctaCount >= 3 && (pitch || softPitch));

      const editorial = typeof NS.pageLooksLikeEditorialArticleOrNewsPost === "function"
        && NS.pageLooksLikeEditorialArticleOrNewsPost();

      // 资讯文除非硬下载壳，一律不当下载落地
      if (editorial && !hardShell) {
        return {
          ok: false, pitch: !!pitch, softPitch: !!softPitch, shellScore, hardShell: false,
          ctaCount, pkgCount, hrefless, multiPlatform, hasHub, editorial: true, reasons: reasons.concat(["editorial"])
        };
      }

      // 绝对底线：无任何下载壳痕迹 → 非落地页
      if (ctaCount === 0 && pkgCount === 0 && !hasHub && !seoTemplate && !encryptedDl && !cloudDriveQr && !schemaApp && !paddedMktHost) {
        return {
          ok: false, pitch: !!pitch, softPitch: !!softPitch, shellScore: 0, hardShell: false,
          ctaCount, pkgCount, hrefless, multiPlatform, hasHub, editorial, reasons: ["no-shell"]
        };
      }

      // CTA「免费下载」+ 同域 download.html：补 pitch（仿冒火绒首页典型形态）
      if (!pitch && !softPitch && hasHub && ctaCount >= 1
        && /免费下载|立即下载|官方下载|个人版|客户端/i.test(ctaTextBlob + claim)) {
        softPitch = true;
      }
      if (paddedMktHost && ctaCount >= 1) softPitch = true;

      // 与下载页检测绑死：话术 + 壳，或硬壳 + 弱话术/包，或首页→download.html 导流
      let ok = false;
      if (hardShell && (pitch || softPitch || pkgCount >= 1)) ok = true;
      // 首页仅有 download.html 导流 + 下载 CTA（包在子页）→ 必须 ok，供 brand-spoof / 主动 fetch
      else if (hasHub && ctaCount >= 1 && (pitch || softPitch || hubLinkCount >= 1)) ok = true;
      else if (paddedMktHost && (ctaCount >= 1 || /下载|官网|官方|安静|纯净|强悍/i.test(title + claim))) ok = true;
      else if (hubPortalShell) ok = true;
      else if (pitch && shellScore >= 2) ok = true;
      else if (pitch && ctaCount >= 2) ok = true;
      else if (softPitch && shellScore >= 3 && ctaCount >= 2) ok = true;
      else if (softPitch && hasHub && ctaCount >= 1) ok = true;
      else if (pkgCount >= 1 && ctaCount >= 1 && (pitch || softPitch)) ok = true;

      return {
        ok: !!ok,
        pitch: !!pitch,
        softPitch: !!softPitch,
        shellScore,
        hardShell: !!hardShell,
        ctaCount,
        pkgCount,
        hrefless,
        multiPlatform,
        hasHub,
        editorial: !!editorial,
        reasons
      };
    } catch {
      return empty;
    }
  };

  /** 是否呈软件下载落地页壳（品牌仿冒硬前提） */
  NS.pageLooksLikeSoftwareDownloadLandingShell = function () {
    try {
      const r = typeof NS.evaluateSoftwareDownloadLandingShell === "function"
        ? NS.evaluateSoftwareDownloadLandingShell()
        : null;
      return !!(r && r.ok);
    } catch { return false; }
  };

  /**
   * 第三方软件下载门户 / 软件库详情页（中华网软件、华军、太平洋下载等形态）。
   * 标题常为「360安全卫士…下载 - 中华网软件」——是门户分发，不是仿冒 360 官网。
   * 纯结构/文案启发，非域名白名单。
   */
  NS.pageLooksLikeSoftwareCatalogPortal = function () {
    try {
      const title = (document.title || "").trim();
      const path = (location.pathname || "").toLowerCase();
      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      const hostLabel = (host.split(".")[0] || "");
      const desc = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").trim();
      const siteName = String(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "").trim();
      // 真仿冒「XX 官方客户端/电脑版官网」壳：无门户后缀时不放过
      const pureOfficialShell = /(?:官方客户端|电脑版官网|全平台官方下载|官方正版下载|立即免费下载)/i.test(title)
        && !/中华网|华军|太平洋|天空下载|下载之家|软件园|电脑之家|驱动人生|ZOL|PConline|yesky|软件频道|软件中心/i.test(title + siteName);
      if (pureOfficialShell) return false;

      // 标题门户后缀：…下载 - 中华网软件
      const portalTitleSuffix = /[-–—_|]\s*(?:中华网软件|中华网|华军软件(?:园)?|太平洋(?:电脑网)?下载|天空下载|下载之家|绿色资源网|软件天堂|统一下载|当下软件园|IT之家|电脑之家|ZOL下载|PConline|太平洋下载|yesky|天极下载|驱动人生|软件频道|软件中心)\s*$/i.test(title)
        || /(?:中华网软件|华军软件园|太平洋电脑网下载|天空下载站)\s*$/i.test(title);
      // 路径：/soft/1109443.html  /down/  /softdown/
      const portalPath = /\/(?:soft|down|softdown|softinfo|software)\/(?:list|detail|\d+)/i.test(path)
        || /\/soft\/\d+\.html?/i.test(path)
        || /\/down\/\d+\.html?/i.test(path);
      // 频道子域 soft./download.
      const portalHost = /^(?:soft|download|down|app|game)\./i.test(host)
        || /^(?:soft|download|down)$/i.test(hostLabel);

      let body = "";
      try {
        body = ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").slice(0, 4000);
      } catch { body = ""; }
      const headBlob = `${title} ${siteName} ${desc.slice(0, 200)} ${body.slice(0, 800)}`;
      // 门户壳：站点名、分类导航、人工检测、最新收录、软件详情栅格
      const portalChrome = /中华网软件|华军软件|人工检测[，,\s]*安心下载|最新收录|软件分类|相关软件|大家都在下|软件大小|更新时间|版本号|次下载|安全软件|实用工具/i.test(headBlob)
        || /Copyright\s*(?:&copy;|©)?\s*中华网/i.test(body)
        || !!document.querySelector(
          ".soft-page, .s-soft-art, #baseinfo, .m-soft-detail, .soft-detail, .soft-info, "
          + ".download-info, .soft_info, #soft-info, .app-detail, .softname"
        );
      let logoPortal = false;
      try {
        const logoT = String(document.querySelector(".logo, .logo-link, [class*='logo'] a, header a")?.textContent || "").trim();
        logoPortal = /中华网|华军|软件园|下载站|软件频道|电脑之家/i.test(logoT + siteName);
      } catch { /* ignore */ }

      // 标题含产品「官网」字样但整页是门户详情（…官网免费版下载 - 中华网软件）
      const productOnPortal = portalTitleSuffix
        && /下载|软件|安全|客户端|电脑版/i.test(title)
        && (portalChrome || logoPortal || portalPath);

      if (productOnPortal) return true;
      if (portalTitleSuffix && (portalChrome || logoPortal || portalPath)) return true;
      if (portalPath && portalChrome && (portalHost || logoPortal || /软件|下载|版本|大小/i.test(title))) return true;
      if (portalHost && portalPath && portalChrome) return true;
      if (logoPortal && portalPath && /下载|软件/i.test(title)) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 应用商店 / 手机助手 应用详情页（如百度手机助手钉钉详情）。
   * 标题常为「钉钉APP免费下载…_百度手机助手」——是商店分发 App，不是仿冒该 App 官网。
   * 纯结构/文案启发，非域名白名单。
   */
  NS.pageLooksLikeAppMarketOrAppStoreListing = function () {
    try {
      const title = (document.title || "").trim();
      const desc = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").trim();
      const path = (location.pathname || "").toLowerCase();
      const head = `${title} ${desc}`.slice(0, 900);
      // 纯仿冒「XX 官网/官方客户端」壳：无商店品牌话术时不按应用商店放过
      const pureOfficialShell = /(?:官方客户端|电脑版官网|全平台官方下载|官方正版下载)/i.test(title)
        && !/手机助手|应用商店|应用市场|应用宝|App\s*Store|Google\s*Play|手机APP下载|软件商店/i.test(head);
      if (pureOfficialShell) return false;

      // 商店/助手品牌出现在标题或描述
      const marketBrand = /百度手机助手|手机助手|应用商店|应用市场|软件商店|应用宝|豌豆荚|华为应用市场|小米应用商店|OPPO软件商店|vivo应用商店|酷安|App\s*Store|Google\s*Play|Play\s*Store|Microsoft\s*Store|应用汇|360手机助手|腾讯应用宝/i.test(head);
      // 标题形态：App + 下载安装 + 市场后缀（钉钉APP免费下载安装2026最新版_手机APP下载_百度手机助手）
      const titleListing = (
        /(?:APP|app|应用).{0,16}(?:免费)?下载安装|(?:下载安装)\d{4}最新版|_手机APP下载_|手机APP下载/i.test(title)
        && /手机助手|应用商店|应用市场|应用宝|App\s*Store|Play|软件商店/i.test(title)
      ) || /_手机APP下载_/.test(title)
        || /免费下载安装\d{4}最新版.+手机助手/i.test(title);
      // 描述：商店为您提供某 App 下载
      const descListing = /(?:手机助手|应用商店|应用市场|应用宝|软件商店).{0,12}为您提供/i.test(desc)
        || /为您提供.{0,48}(?:APP|应用|客户端).{0,16}下载/i.test(desc);
      // URL：应用详情路径
      const pathListing = /\/(?:appitemp?|appitem|app\/(?:detail|info|view)|soft\/\d|store\/apps|android\/details|detail\/app|package\/|appinfo\/)/i.test(path);

      let struct = false;
      try {
        const body = ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").slice(0, 3500);
        const marketInBody = /手机助手|应用商店|应用市场|应用宝|相关推荐|大家还在下|安装次数|次安装|应用权限|开发者|隐私权限/i.test(body);
        const appMeta = /版本|大小|更新|下载/.test(body);
        struct = marketInBody && appMeta;
      } catch { /* ignore */ }

      if (titleListing) return true;
      if (marketBrand && (descListing || pathListing || struct)) return true;
      if (pathListing && (marketBrand || descListing || /APP|应用|下载安装/i.test(title))) return true;
      return false;
    } catch { return false; }
  };

  /**
   * Linux 发行版 ISO / 镜像列表下载页（Arch/Ubuntu 等）。
   * 含 .iso、磁力、校验和、全球镜像 —— 非银狐 exe/zip 仿冒下载壳。
   */
  NS.pageLooksLikeOsDistroIsoDownload = function () {
    try {
      const title = (document.title || "").trim();
      const host = (location.hostname || "").toLowerCase();
      const path = (location.pathname || "").toLowerCase();
      // 仿冒「XX 客户端官方下载」壳不按发行版放过
      if (/官方客户端|官方正版|电脑版官网|立即免费下载|\.exe|客户端下载/i.test(title)) return false;
      const html = typeof NS.getHtmlSlice === "function"
        ? NS.getHtmlSlice(50000)
        : String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 50000);
      const blob = `${title} ${html.slice(0, 12000)}`;
      const isoHits = (html.match(/\.iso(?:\?|"|'|\s|>|\/|#|$)/gi) || []).length;
      const magnet = /magnet:\?xt=urn:btih:/i.test(html);
      const torrent = /\.torrent\b|bittorrent|磁力链接|种子文件/i.test(html);
      const checksum = /sha256sums|b2sums|sha256\s*:|blake2b|pgp\s*签名|gpg\s*--verify|校验和/i.test(html);
      const mirrors = /(?:mirror\.|mirrors\.|镜像站|镜像列表|mirrorlist|geo\.mirror|fastly\.mirror)/i.test(html)
        || (html.match(/\/iso\/\d{4}\.\d{2}/gi) || []).length >= 3;
      const distroName = /arch\s*linux|ubuntu|debian|fedora|centos|rocky\s*linux|alma\s*linux|manjaro|gentoo|open\s*suse|opensuse|linux\s*mint|kali\s*linux|endeavouros|archlinux/i.test(blob);
      const distroHost = /archlinux|ubuntu|debian|fedoraproject|centos|rockylinux|almalinux|manjaro|opensuse|linuxmint|kali|archlinux\.org/i.test(host);
      const distroIsoName = /archlinux-\d{4}\.\d{2}\.\d{2}|ubuntu-\d{2}\.\d{2}(?:\.\d+)?|debian-\d+|Fedora-Workstation|CentOS-Stream/i.test(html);
      const pathDl = /\/(?:download|downloads|iso|get|releng)(?:\/|$)/i.test(path);
      if ((distroName || distroHost || distroIsoName) && (isoHits >= 1 || magnet || torrent)
        && (checksum || mirrors || isoHits >= 2 || (pathDl && (magnet || torrent || isoHits >= 1)))) {
        return true;
      }
      // 大量 ISO 镜像列表（无「官网客户端」话术）
      if (isoHits >= 2 && (checksum || mirrors) && /linux|iso|发行版|安装映像|installation\s*image/i.test(blob)
        && !/官方客户端|官方正版|立即免费下载/i.test(title)) {
        return true;
      }
      return false;
    } catch { return false; }
  };

  /**
   * 高密度软件/游戏版本归档站（MCAPKS 类：大表 + 海量 APK/zip）。
   * 主线程易被 MutationObserver 全量复扫卡死，应走轻量路径。
   */
  NS.pageLooksLikeHighVolumePackageArchive = function () {
    try {
      const title = document.title || "";
      // 仿冒「官网/官方下载」壳不按归档站放过
      if (/官网|官方下载|官方正版|官方网站|官方客户端|电脑版官网/i.test(title)) return false;
      let pkgAnchors = 0;
      try {
        pkgAnchors = document.querySelectorAll(
          'a[href*=".apk" i], a[href*=".zip" i], a[href*=".exe" i], a[href*=".dmg" i], a[href*=".msi" i], a[href*=".xapk" i]'
        ).length;
      } catch {
        try {
          // 部分浏览器不支持 attr i 标志
          pkgAnchors = document.querySelectorAll('a[href*=".apk"], a[href*=".zip"], a[href*=".exe"], a[href*=".dmg"], a[href*=".msi"]').length;
        } catch { pkgAnchors = 0; }
      }
      const tableRows = (() => {
        try { return document.querySelectorAll("table tbody tr, table#table-version tr, #table-version tbody tr, .version-list .version-item").length; } catch { return 0; }
      })();
      const headHint = `${title} ${document.querySelector("h1,h5,.navbar-brand")?.textContent || ""}`.slice(0, 200);
      const archiveTitle = /版本|全版本|资源|合集|国际版|安卓|apk|archive|下载站|资源网|安装包列表/i.test(headHint);
      if (pkgAnchors >= 40) return true;
      if (pkgAnchors >= 15 && archiveTitle) return true;
      if (tableRows >= 25 && archiveTitle) return true;
      if (tableRows >= 40 && /下载|版本|version/i.test(headHint)) return true;
      return false;
    } catch { return false; }
  };

  NS.isBenignContentPage = function () {
    const state = NS.state;
    if (state.downloadGuardInstalled || state.remoteDownloadDispatchDetected) return false;
    if (state._fakeSpaDetected || state._brandSpoofPortalDetected || state._seoCloakKitDetected) return false;
    if (NS.pageLooksLikeSearchEngineResultsPage()) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    // 大型内容 SPA 结构（无仿冒下载话术）→ benign，供 soft-nav 保持 light
    if (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa()) {
      state._perfBenign = true; state._perfBenignAt = Date.now();
      return true;
    }
    if (NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    // 高密度归档站：不走「有包链就非 benign」逻辑，避免无限重扫
    if (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) {
      state._perfBenign = true; state._perfBenignAt = Date.now();
      return true;
    }
    const title = document.title || "";
    if (/官网|官方下载|官方正版|官方网站|官网下载/i.test(title) && /下载|客户端|远程|杀毒|软件|连接/i.test(title)) return false;
    if (state._perfBenign && Date.now() - (state._perfBenignAt || 0) < 8000) return true;
    const titleNow = document.title || "";
    if (/官网|官方下载|官方正版|客户端下载|免费下载/i.test(titleNow)) {
      try {
        const html = NS.getThreatScanHtml(48000);
        if (/fetch\s*\(\s*['"][^'"]*api\.php/i.test(html) && /download_link/i.test(html)) return false;
        if (typeof NS.hasEncryptedNuxtDownloadConfig === "function" && NS.hasEncryptedNuxtDownloadConfig(html)) return false;
      } catch { /* ignore */ }
    }
    const ctx = NS.estimatePageContext();
    if (!NS.looksLikeNormalContent(ctx)) return false;
    let packageLinkCount = 0; let opaqueHopCount = 0;
    try {
      const anchors = document.links || document.querySelectorAll("a[href]");
      const n = Math.min(anchors.length, 120);
      for (let i = 0; i < n; i++) {
        const a = anchors[i];
        const href = (a.getAttribute("href") || a.getAttribute("data-href") || "").trim();
        if (!href) continue;
        if (NS.isPackageFileUrl(href)) { packageLinkCount++; if (packageLinkCount >= 1) break; }
        else if (NS.looksLikeOpaqueDownloadHopUrl(href)) opaqueHopCount++;
      }
    } catch { /* ignore */ }
    const downloadBtns = NS.getDownloadButtons().length;
    let hreflessDl = 0;
    try {
      document.querySelectorAll("button, a, [role='button']").forEach((el) => {
        if (hreflessDl >= 2) return;
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        if (!/立即下载|免费下载|官方下载|客户端下载|云电脑下载|一键下载/.test(text) || text.length > 36) return;
        const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
        if (!href || href === "#" || /^javascript:/i.test(href) || el.tagName === "BUTTON") hreflessDl++;
      });
    } catch { /* ignore */ }
    if (hreflessDl >= 1 && /官网|官方下载/i.test(title)) return false;
    if (packageLinkCount >= 1 || opaqueHopCount >= 1) return false;
    if (downloadBtns >= 3 && /官网|官方下载|立即下载|杀毒|客户端|远程/i.test(title)) return false;
    if (downloadBtns >= 6 && ctx.visibleTextLength < 2500) return false;
    const structureNodes = document.querySelectorAll('main, article, nav, [role="main"], [role="navigation"], [role="feed"], header, footer').length;
    const hasRichStructure = structureNodes >= 2 || ctx.visibleLinks > 40;
    if (ctx.visibleTextLength > 1500 && hasRichStructure && packageLinkCount === 0 && opaqueHopCount === 0 && downloadBtns < 3 && hreflessDl === 0 && !/官网|官方下载/i.test(title)) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    if (ctx.visibleTextLength > 800 && ctx.visibleLinks > 25 && packageLinkCount === 0 && opaqueHopCount === 0 && downloadBtns < 3 && hreflessDl === 0 && !/官网|官方下载/i.test(title)) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    return false;
  };

  NS.detectDomAbnormalities = function () {
    const state = NS.state;
    const context = NS.estimatePageContext();
    const likelyNormal = NS.looksLikeNormalContent(context) || NS.isBenignContentPage() || NS.looksLikeOfficialClientDownloadPage();
    const allIframes = Array.from(document.querySelectorAll("iframe"));
    const suspiciousIframes = allIframes.filter((f) => {
      try {
        const st = getComputedStyle(f);
        const hidden = st.display === "none" || st.visibility === "hidden" || parseInt(f.getAttribute("width") || "1", 10) === 0 || parseInt(f.getAttribute("height") || "1", 10) === 0 || (f.style && f.style.display === "none");
        if (hidden) return false;
        const src = f.src || f.getAttribute("src") || "";
        if (!src) return true;
        const h = new URL(src, location.href).hostname.toLowerCase();
        const label = (h.split(".")[0] || "").replace(/-/g, "");
        return h.split(".").length <= 2 && /^[a-z0-9]{10,}$/i.test(label) && /\d/.test(label);
      } catch { return false; }
    });
    state.iframeCount = allIframes.length;
    state.formCount = document.querySelectorAll("form").length;
    state.inputCount = document.querySelectorAll("input, textarea, select").length;
    const nodes = document.body ? document.body.getElementsByTagName("*") : [];
    const total = nodes.length;
    let hidden = 0;
    const sample = Math.min(60, total);
    const step = total > 0 ? Math.max(1, Math.floor(total / sample)) : 1;
    for (let i = 0, n = 0; i < total && n < sample; i += step, n++) {
      try { const s = getComputedStyle(nodes[i]); if (s.display === "none" || s.visibility === "hidden" || s.opacity === "0") hidden++; } catch { /* ignore */ }
    }
    state.hiddenCount = sample > 0 ? Math.round((hidden / sample) * total) : 0;
    if (!likelyNormal && state.hiddenCount > 40) NS.addSignal("大量隐藏节点", 8, "页面中存在大量不可见节点，常见于遮罩和隐蔽注入");
    if (!likelyNormal && suspiciousIframes.length > 2) NS.addSignal("异常 iframe 注入", 8, "页面使用多个可见/可疑主机 iframe，可能用于诱导或隐蔽跳转");
    if (!likelyNormal && (state.formCount > 6 || state.inputCount > 15)) NS.addSignal("诱导式表单密集", 6, "大量表单或输入框可能用于钓鱼或信息收集");
    const candidates = document.querySelectorAll("div, section, aside, overlay, [class*='modal'], [class*='mask'], [class*='overlay']");
    let overlays = 0;
    const maxCheck = Math.min(candidates.length, 40);
    for (let i = 0; i < maxCheck; i++) {
      try {
        const el = candidates[i];
        const s = getComputedStyle(el);
        if (s.position !== "fixed" && s.position !== "absolute") continue;
        const rect = el.getBoundingClientRect();
        if (rect.width > window.innerWidth * 0.7 && rect.height > window.innerHeight * 0.7 && parseInt(s.zIndex || "0", 10) > 1000) overlays++;
      } catch { /* ignore */ }
    }
    state.overlayCount = overlays;
    if (!likelyNormal && overlays > 0) NS.addSignal("大面积遮罩层", 7, "页面存在大面积覆盖层，常用于干扰用户操作");
  };

  NS.detectContentMismatch = function () {
    const state = NS.state;
    const context = NS.estimatePageContext();
    const likelyNormal = NS.looksLikeNormalContent(context) || NS.isBenignContentPage() || NS.looksLikeOfficialClientDownloadPage();
    state.textLength = context.visibleTextLength;
    let resourceCount = 0;
    try { resourceCount = performance.getEntriesByType("resource").length; } catch { resourceCount = 0; }
    state.resourceCount = resourceCount;
    if (likelyNormal) return;
    let randomExternal = 0; let stableExternal = 0;
    document.querySelectorAll("script[src], link[href], img[src]").forEach((el) => {
      try {
        const url = el.src || el.href;
        if (!url) return;
        const u = new URL(url, location.href);
        if (u.origin === location.origin) return;
        const h = u.hostname.toLowerCase();
        const label = (h.split(".")[0] || "").replace(/-/g, "");
        const randomish = h.split(".").length <= 2 && /^[a-z0-9]{10,}$/i.test(label) && /\d/.test(label) && /[a-z]/i.test(label);
        if (randomish) randomExternal++; else stableExternal++;
      } catch { /* ignore */ }
    });
    const hasMalwarePackage = Array.from(document.querySelectorAll("a[href]")).some((a) => { const href = a.getAttribute("href") || ""; return NS.isPackageFileUrl(href) && NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(href)); });
    if (state.textLength < 250 && resourceCount > 10 && (randomExternal >= 2 || hasMalwarePackage)) NS.addSignal("内容稀少但资源极多", 8, "页面文字很少，且存在可疑外部资源或乱码安装包");
    if (randomExternal >= 3 || (randomExternal >= 2 && hasMalwarePackage)) NS.addSignal("外部资源异常密集", 7, "页面加载了多个随机特征主机的外部资源");
    void stableExternal;
  };

  NS.detectEnvironmentalAnomalies = function () {
    if (navigator.webdriver) NS.addSignal("自动化环境特征", 6, "页面检测到 webdriver 环境特征");
    if (window.__selenium_unwrapped || window.__webdriver_script || window.__nightmare) NS.addSignal("自动化脚本特征", 6, "页面暴露自动化脚本痕迹");
  };

  NS.detectInteractionAbuse = function () {
    document.addEventListener("fullscreenchange", () => { if (document.fullscreenElement) NS.addSignal("强制全屏", 6, "页面触发全屏操作"); });
  };

  /** 仅在 guard 激活时观察 DOM 突变爆炸（避免每站永久 MO）。 */
  NS.detectMutationBomb = function () {
    const state = NS.state;
    let ticks = 0;
    let observer = null;
    let intervalId = null;
    const ensureObserver = () => {
      if (observer || typeof MutationObserver === "undefined") return;
      try {
        observer = new MutationObserver(() => { state.mutationCount++; ticks++; });
        observer.observe(document.documentElement, { childList: true, subtree: true, attributes: false });
      } catch { observer = null; }
    };
    intervalId = setInterval(() => {
      if (!state.downloadGuardInstalled && !state.remoteDownloadDispatchDetected) {
        ticks = 0;
        if (observer) { try { observer.disconnect(); } catch { /* ignore */ } observer = null; }
        return;
      }
      ensureObserver();
      if (ticks === 0) return;
      const burst = ticks;
      ticks = 0;
      if (burst < 120) return;
      if (NS.isBenignContentPage()) return;
      NS.addSignal("DOM 突然频繁变化", 6, "短时间内 DOM 变化过快，且同时存在下载威胁上下文");
      NS.emitRiskReport();
    }, 3000);
    setTimeout(() => { try { if (intervalId) clearInterval(intervalId); } catch { /* ignore */ } try { if (observer) observer.disconnect(); } catch { /* ignore */ } }, 120000);
  };
})(window.SilverfoxContent ??= {});
