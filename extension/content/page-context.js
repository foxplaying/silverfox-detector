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

  NS.isBenignContentPage = function () {
    const state = NS.state;
    if (state.downloadGuardInstalled || state.remoteDownloadDispatchDetected) return false;
    if (state._fakeSpaDetected || state._brandSpoofPortalDetected || state._seoCloakKitDetected) return false;
    if (NS.pageLooksLikeSearchEngineResultsPage()) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    if (NS.looksLikeUltraMatureIcpDomain() || state._intelLightMode) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) { state._perfBenign = true; state._perfBenignAt = Date.now(); return true; }
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
