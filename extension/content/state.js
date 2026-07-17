/**
 * content state + 工具 + HTML 采样 + 调试日志。
 * 所有模块共享 window.SilverfoxContent 命名空间；state 挂在 NS.state。
 */
;(function (NS) {
  "use strict";

  const HOOK_SOURCE = "silverfox-detector-hooks";
  const CONTENT_SOURCE = "silverfox-detector-content";
  const PACKAGE_EXT = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i;
  const PACKAGE_NAME = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/i;
  const DOWNLOAD_TEXT = /下载|download|安装|客户端|安装包|免费下载|立即下载|官方下载/i;

  NS.HOOK_SOURCE = HOOK_SOURCE;
  NS.CONTENT_SOURCE = CONTENT_SOURCE;
  NS.PACKAGE_EXT = PACKAGE_EXT;
  NS.PACKAGE_NAME = PACKAGE_NAME;
  NS.DOWNLOAD_TEXT = DOWNLOAD_TEXT;

  /** 仅扫描真实 web 页面。 */
  function isHttpOrHttpsPage(urlOrHref) {
    try {
      if (urlOrHref) {
        const u = new URL(String(urlOrHref), location.href);
        return u.protocol === "http:" || u.protocol === "https:";
      }
      const p = String(location.protocol || "").toLowerCase();
      return p === "http:" || p === "https:";
    } catch {
      return false;
    }
  }
  NS.isHttpOrHttpsPage = isHttpOrHttpsPage;

  /** 全局分析状态。 */
  NS.state = {
    score: 0,
    details: [],
    signalSet: new Set(),
    mutationCount: 0, iframeCount: 0, hiddenCount: 0, overlayCount: 0,
    scriptInjectionCount: 0, dynamicExecCount: 0, popupCount: 0, redirectCount: 0,
    fetchCount: 0, crossOriginCount: 0, hosts: new Set(),
    textLength: 0, resourceCount: 0, formCount: 0, inputCount: 0,
    visibleLinks: 0, visibleTextLength: 0, visibleElements: 0,
    remoteDownloadDispatchDetected: false, downloadGuardInstalled: false,
    icpInfo: "", whoisInfo: "", contextCache: null, contextCacheAt: 0,
    protectedTargets: [], protectionNoticeSent: false, icpMatchedHost: "",
    _perfBenign: false, _perfBenignAt: 0, _scanBusy: false, _lastFastScanAt: 0,
    _analysisDone: false, _analysisDoneAt: 0,
    _icpQuerySettled: false, _icpQueryFailed: false,
    _pageBootAt: Date.now(),
    _pendingEncryptedSpa: false, _encryptedSpaRescanArmed: false,
    _proactiveProbeAt: 0, _proactiveProbeBusy: false
  };

  // 模块级缓存（HTML / 下载按钮 / SERP）
  NS.caches = {
    finalizeScheduled: false,
    lastReportAt: 0,
    lastAnalyzedUrl: "",
    pageNavRescanTimer: null,
    pageNavResetBusy: false,
    intelBusy: false,
    intelDoneForUrl: "",
    intelGeneration: 0,
    _htmlCache: "", _htmlCacheAt: 0, _htmlCacheMax: 0,
    _dlBtnCache: null, _dlBtnCacheAt: 0,
    _serpCache: null, _serpCacheAt: 0, _serpCacheUrl: "",
    _highDensityDl: null, _highDensityDlAt: 0,
    _osDistroIso: null, _osDistroIsoAt: 0,
    _highVolArchive: null, _highVolArchiveAt: 0,
    _skipHeavy: null, _skipHeavyAt: 0,
    _primaryKw: null, _primaryKwAt: 0, _primaryKwUrl: "",
    probeCache: new Map(),
    pageToastLastAt: new Map(),
    sentNoticeKeys: new Set(),
    sentNoticeLastAt: new Map()
  };

  // --- 调试日志 ---
  let _silverfoxDebug = false;

  function refreshDebugFlag() {
    try {
      const href = String(location.href || "");
      if (/[?&#]silverfox_debug=1(?:&|#|$)/i.test(href)) { _silverfoxDebug = true; return; }
    } catch { /* ignore */ }
    try {
      if (chrome?.storage?.local) {
        chrome.storage.local.get(["silverfoxDebug"], (r) => {
          void chrome.runtime.lastError;
          if (r && r.silverfoxDebug) _silverfoxDebug = true;
        });
      }
    } catch { /* ignore */ }
  }
  refreshDebugFlag();
  try {
    if (chrome?.storage?.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local" || !changes.silverfoxDebug) return;
        _silverfoxDebug = !!changes.silverfoxDebug.newValue;
      });
    }
  } catch { /* ignore */ }

  NS.silverfoxLog = function (...args) {
    if (!_silverfoxDebug) return;
    try { console.log("[silverfox]", ...args); } catch { /* ignore */ }
  };

  /** 在调试计时下运行检测器；返回布尔结果。 */
  NS.runDetector = function (name, fn) {
    if (!_silverfoxDebug) {
      try { return !!fn(); } catch { return false; }
    }
    const t0 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
    let hit = false;
    try { hit = !!fn(); } catch (e) { NS.silverfoxLog("detect-error", name, e && e.message ? e.message : e); return false; }
    const t1 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
    NS.silverfoxLog("detect", name, hit ? "HIT" : "miss", `${(t1 - t0).toFixed(1)}ms`);
    return hit;
  };

  NS.markAnalysisComplete = function (reason) {
    try { if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) return; } catch { /* ignore */ }
    NS.silverfoxLog("analysis-complete", reason || "", "score=", NS.state.score, "guard=", !!NS.state.downloadGuardInstalled);
    try {
      const hostKey = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
      NS.state._stickyComplete = true;
      NS.state._stickyCompleteHost = hostKey;
    } catch { /* ignore */ }
    if (NS.state._analysisDone) { NS.emitRiskReport(true); return; }
    NS.state._analysisDone = true;
    NS.state._analysisDoneAt = Date.now();
    NS.state._scanBusy = false;
    NS.emitRiskReport(true);
  };

  NS.invalidateHtmlCache = function () {
    const c = NS.caches;
    c._htmlCache = ""; c._htmlCacheAt = 0; c._htmlCacheMax = 0;
    c._dlBtnCache = null; c._dlBtnCacheAt = 0;
    c._serpCache = null; c._serpCacheAt = 0; c._serpCacheUrl = "";
    c._highDensityDl = null; c._highDensityDlAt = 0;
    c._osDistroIso = null; c._osDistroIsoAt = 0;
    c._highVolArchive = null; c._highVolArchiveAt = 0;
    c._skipHeavy = null; c._skipHeavyAt = 0;
    c._primaryKw = null; c._primaryKwAt = 0; c._primaryKwUrl = "";
  };

  NS.scheduleIdle = function (fn, timeoutMs = 1200) {
    try {
      if (typeof requestIdleCallback === "function") {
        requestIdleCallback(() => { try { fn(); } catch { /* ignore */ } }, { timeout: timeoutMs });
        return;
      }
    } catch { /* ignore */ }
    setTimeout(() => { try { fn(); } catch { /* ignore */ } }, Math.min(timeoutMs, 400));
  };

  /** 是否顶层浏览上下文（iframe 内为 false） */
  NS.isTopFrame = function () {
    try { return window === window.top; } catch { return true; }
  };

  /**
   * 向本 frame 的 MAIN page-hooks 发指令；set-guard 时同步广播到子 frame，
   * 否则 iframe 内下载按钮不受顶层盗版拦截影响。
   */
  NS.postToHooks = function (payload) {
    try { window.postMessage({ source: CONTENT_SOURCE, ...payload }, "*"); } catch { /* ignore */ }
    // 顶层 arm/disarm 时向所有子 frame 传播（跨源只能 postMessage，同源再由 content 灰按钮）
    try {
      if (payload && payload.type === "set-guard" && NS.isTopFrame()) {
        const msg = { source: CONTENT_SOURCE, type: "set-guard", enabled: !!payload.enabled, fromTop: true };
        const blast = (win) => {
          try { win.postMessage(msg, "*"); } catch { /* ignore */ }
        };
        try {
          for (let i = 0; i < window.frames.length; i++) blast(window.frames[i]);
        } catch { /* ignore */ }
        try {
          document.querySelectorAll("iframe").forEach((f) => {
            try { if (f.contentWindow) blast(f.contentWindow); } catch { /* ignore */ }
          });
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  };

  /**
   * 顶层 arm 后处理页面内 iframe/embed：
   * - 仅 pointer-events 不够：晚加载的跨源下载壳仍会完整渲染，用户可点
   * - 掏空 src → about:blank、加 sandbox、挡交互；同源再灰内部按钮
   * - 由 installParentGuardInheritance 定时补锁，防 SPA 重插框架
   */
  NS.neutralizePageFramesForGuard = function (on) {
    try {
      if (!NS.isTopFrame()) return;
      document.querySelectorAll("iframe, embed, object").forEach((el) => {
        try {
          const tag = (el.tagName || "").toUpperCase();
          if (on) {
            if (!el.dataset.silverfoxFramePrevPe) {
              el.dataset.silverfoxFramePrevPe = el.style.pointerEvents || "";
            }
            el.style.setProperty("pointer-events", "none", "important");
            el.style.setProperty("visibility", "hidden", "important");
            el.setAttribute("data-silverfox-frame-locked", "1");
            // 保存并掏空导航目标（防晚加载下载落地页）
            try {
              const curSrc = el.getAttribute("src") || el.src || "";
              if (curSrc && !/^about:blank$/i.test(curSrc) && !el.dataset.silverfoxFrameOrigSrc) {
                el.dataset.silverfoxFrameOrigSrc = curSrc;
              }
              if (tag === "IFRAME" || tag === "EMBED") {
                try { el.removeAttribute("src"); } catch { /* ignore */ }
                try { el.src = "about:blank"; } catch { /* ignore */ }
                try { el.setAttribute("src", "about:blank"); } catch { /* ignore */ }
              }
              if (tag === "OBJECT") {
                try {
                  if (!el.dataset.silverfoxFrameOrigData && el.getAttribute("data")) {
                    el.dataset.silverfoxFrameOrigData = el.getAttribute("data");
                  }
                  el.removeAttribute("data");
                } catch { /* ignore */ }
              }
              // 最严沙箱：无下载、无顶层导航、无表单
              try {
                if (tag === "IFRAME") {
                  el.setAttribute("sandbox", "");
                  el.removeAttribute("allow");
                  el.removeAttribute("allowfullscreen");
                }
              } catch { /* ignore */ }
            } catch { /* ignore */ }
            // 同源：灰内部下载控件
            try {
              const doc = el.contentDocument;
              if (doc) {
                doc.querySelectorAll("a, button, [role='button']").forEach((node) => {
                  try {
                    const t = (node.textContent || "").replace(/\s+/g, " ").trim();
                    const href = (node.getAttribute && (node.getAttribute("href") || node.getAttribute("data-href"))) || "";
                    if (/下载|download|安装|客户端|免费获取/i.test(t + " " + href)
                      || /\.(?:exe|zip|msi|apk|dmg)(?:\?|$)/i.test(href)
                      || true) {
                      // 同源 frame 内一律挡可点控件（盗版下载壳）
                      node.style.setProperty("pointer-events", "none", "important");
                      node.style.setProperty("opacity", "0.45", "important");
                      node.setAttribute("data-silverfox-greyed", "1");
                      if (node.tagName === "A") {
                        if (!node.dataset.silverfoxOrigHref && node.getAttribute("href")) {
                          node.dataset.silverfoxOrigHref = node.getAttribute("href");
                        }
                        try { node.setAttribute("href", "javascript:void(0)"); } catch { /* ignore */ }
                      }
                    }
                  } catch { /* ignore */ }
                });
              }
            } catch { /* cross-origin — 已 about:blank */ }
          } else if (el.getAttribute("data-silverfox-frame-locked") === "1") {
            el.style.pointerEvents = el.dataset.silverfoxFramePrevPe || "";
            el.style.visibility = "";
            el.removeAttribute("data-silverfox-frame-locked");
            delete el.dataset.silverfoxFramePrevPe;
            // 一般不自动恢复 src（防立刻再下）；仅清标记
            try { el.removeAttribute("sandbox"); } catch { /* ignore */ }
          }
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
  };

  NS.addSignal = function (name, weight, reason) {
    if (_silverfoxDebug && (Number(weight) || 0) > 0) {
      NS.silverfoxLog("signal", `w${weight}`, name, String(reason || "").slice(0, 100));
    }
    const key = `${name}:${weight}`;
    if (NS.state.signalSet.has(key)) return false;
    NS.state.signalSet.add(key);
    const w = Number(weight) || 0;
    if (w > 0) NS.state.score += w;
    NS.state.details.push({ name, weight: w, reason: reason || "" });
    return true;
  };

  /**
   * 缓存页面 HTML 样本 -- 避免多 MB SPA 上反复全量 outerHTML。
   * 关键：采样 HEAD + body 起始 + body 末尾。Nuxt 钓鱼载荷在 #app 末尾。
   */
  NS.getHtmlSlice = function (maxLen = 80000) {
    const c = NS.caches;
    const now = Date.now();
    const cap = Math.max(8000, Math.min(maxLen, 100000));
    if (c._htmlCache && now - c._htmlCacheAt < 5000 && c._htmlCacheMax >= cap) {
      return c._htmlCache.length > cap ? c._htmlCache.slice(0, cap) : c._htmlCache;
    }
    let raw = "";
    try {
      const de = document.documentElement;
      const head = de && de.querySelector("head");
      const body = de && de.querySelector("body");
      const headHtml = head ? String(head.innerHTML || "").slice(0, Math.min(24000, Math.floor(cap * 0.22))) : "";
      let bodyPart = "";
      if (body) {
        const bi = String(body.innerHTML || "");
        const budget = Math.max(0, cap - headHtml.length - 128);
        if (bi.length <= budget) {
          bodyPart = bi;
        } else {
          const headBudget = Math.floor(budget * 0.5);
          const tailBudget = budget - headBudget;
          bodyPart = `${bi.slice(0, headBudget)}\n<!--silverfox-mid-->\n${bi.slice(-tailBudget)}`;
        }
      }
      let scriptTail = "";
      const titleHot = /官网|官方下载|下载|客户端|远程|免费/i.test(document.title || "");
      if (titleHot) {
        try {
          const scripts = document.scripts || [];
          let n = 0;
          for (let i = scripts.length - 1; i >= 0 && n < 4; i--) {
            const s = scripts[i];
            if (s.src) continue;
            const t = s.textContent || "";
            if (t.length < 80) continue;
            if (/windowsDownload|macDownload|__NUXT__|__DATA__|downloadUrl|download_uri/i.test(t) || t.length >= 3000) {
              scriptTail = `${t.slice(0, 16000)}\n${scriptTail}`;
              n++;
            }
          }
        } catch { /* ignore */ }
      }
      raw = `${headHtml}\n${bodyPart}\n${scriptTail}`;
      if (!raw && de) {
        const full = String(de.innerHTML || "");
        if (full.length <= cap) raw = full;
        else { const hb = Math.floor(cap * 0.5); raw = `${full.slice(0, hb)}\n${full.slice(-(cap - hb))}`; }
      }
    } catch {
      raw = "";
    }
    if (raw.length > cap) {
      const hb = Math.floor(cap * 0.5);
      raw = `${raw.slice(0, hb)}\n${raw.slice(-(cap - hb))}`;
    }
    c._htmlCache = raw;
    c._htmlCacheAt = now;
    c._htmlCacheMax = cap;
    return raw;
  };

  /** 威胁扫描用 HTML 样本（确保包含下载配置尾部）。 */
  NS.getThreatScanHtml = function (maxLen = 90000) {
    const base = NS.getHtmlSlice(Math.min(maxLen, 90000));
    if (/"windowsDownload"|macDownload|androidDownload|__NUXT__|download_uri/i.test(base)) return base;
    if (!/官网|官方下载|下载|客户端|远程/i.test(document.title || "")
      && !/官网|官方下载|立即下载|客户端/i.test(((document.body && document.body.textContent) || "").slice(0, 1500))) return base;
    try {
      const parts = [base];
      let extra = 0;
      try {
        const islands = document.querySelectorAll(
          "script#__NUXT_DATA__, script#__NEXT_DATA__, script[type='application/json'],"
          + " #__NUXT__, #__NUXT_DATA__, [data-nuxt-data]"
        );
        for (let i = 0; i < islands.length && extra < 50000; i++) {
          const t = islands[i].textContent || islands[i].innerHTML || "";
          if (t.length < 40) continue;
          if (/windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|downloadUrl|__NUXT__/i.test(t) || t.length >= 800) {
            const chunk = t.length > 28000 ? `${t.slice(0, 14000)}\n${t.slice(-14000)}` : t;
            parts.push(chunk);
            extra += chunk.length;
          }
        }
      } catch { /* ignore */ }
      const scripts = document.scripts || [];
      for (let i = scripts.length - 1; i >= 0 && extra < 50000; i--) {
        const s = scripts[i];
        if (s.src) continue;
        const t = s.textContent || "";
        if (t.length < 80) continue;
        if (/windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|__NUXT__|__DATA__|download_uri/i.test(t)
          || (t.length >= 4000 && /Download|base64|atob/i.test(t))) {
          const chunk = t.length > 24000 ? `${t.slice(0, 12000)}\n${t.slice(-12000)}` : t;
          parts.push(chunk);
          extra += chunk.length;
        }
      }
      return parts.join("\n").slice(0, Math.min(maxLen, 120000));
    } catch {
      return base;
    }
  };
})(window.SilverfoxContent ??= {});
