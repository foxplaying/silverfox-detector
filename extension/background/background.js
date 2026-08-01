/**
 * background service worker 入口。
 * 加载各模块后注册 webNavigation / tabs / downloads / runtime 监听。
 *
 * 重要：downloads 监听必须在 importScripts 之前挂上。
 * 刷新扩展后 SW 冷启动时，ssl-cert 等大模块加载很慢，若监听注册太晚，
 * 第一次下载的 onCreated 会直接丢失 → 用户感觉要点第二次才检测。
 */
;(function (NS) {
  "use strict";

  // --- 共享状态（各模块通过 NS 访问）---
  /** 被内容脚本标记为需要包下载取消的标签页。 */
  NS.protectedTabs = new Set();
  /** tabId -> { origin, url, setAt, mode } - 保护绑定到该页面 origin。 */
  NS.protectedTabMeta = new Map();
  /** tabId -> { origin, url, setAt } - 已由顶层 content 用 ICP/WHOIS 核验的下载来源。 */
  NS.trustedDownloadTabs = new Map();
  /** origin -> 同一份可信来源元数据；用于 DownloadItem 没有 tabId 时按 referrer 回查。 */
  NS.trustedDownloadOrigins = new Map();
  /** 精确下载 URL -> { tabId, setAt, expiresAt }；补偿 Edge 同时省略 tabId/referrer。 */
  NS.trustedDownloadIntents = new Map();
  /** 精确下载 URL -> 来源 tab；只用于把拦截提示送回页面，绝不参与可信放行。 */
  NS.downloadSourceIntents = new Map();

  NS.normalizeTrustedDownloadUrl = function (raw) {
    try {
      const u = new URL(String(raw || ""));
      if (!/^https?:$/i.test(u.protocol)) return "";
      u.hash = "";
      return u.href;
    } catch { return ""; }
  };

  NS.clearTrustedDownloadSource = function (tabId) {
    if (tabId == null) return;
    const old = NS.trustedDownloadTabs.get(tabId);
    NS.trustedDownloadTabs.delete(tabId);
    if (old && old.origin) {
      const byOrigin = NS.trustedDownloadOrigins.get(old.origin);
      if (!byOrigin || byOrigin.tabId === tabId) NS.trustedDownloadOrigins.delete(old.origin);
    }
    if (NS.trustedDownloadIntents) {
      for (const [key, meta] of NS.trustedDownloadIntents) {
        if (!meta || meta.tabId === tabId) NS.trustedDownloadIntents.delete(key);
      }
    }
    if (NS.downloadSourceIntents) {
      for (const [key, meta] of NS.downloadSourceIntents) {
        if (!meta || meta.tabId === tabId) NS.downloadSourceIntents.delete(key);
      }
    }
  };

  NS.setTrustedDownloadSource = function (tabId, pageUrl) {
    if (tabId == null || tabId < 0) return false;
    let origin = "";
    try {
      const u = new URL(pageUrl || "");
      if (!/^https?:$/i.test(u.protocol)) return false;
      origin = u.origin;
    } catch { return false; }
    NS.clearTrustedDownloadSource(tabId);
    const meta = { tabId, origin, url: pageUrl || "", setAt: Date.now() };
    NS.trustedDownloadTabs.set(tabId, meta);
    NS.trustedDownloadOrigins.set(origin, meta);
    return true;
  };

  NS.rememberTrustedDownloadIntent = function (tabId, href) {
    if (tabId == null || !NS.trustedDownloadTabs.has(tabId)) return false;
    const key = NS.normalizeTrustedDownloadUrl(href);
    if (!key) return false;
    const now = Date.now();
    NS.trustedDownloadIntents.set(key, { tabId, setAt: now, expiresAt: now + 120000 });
    if (NS.trustedDownloadIntents.size > 120) {
      for (const [k, meta] of NS.trustedDownloadIntents) {
        if (!meta || Number(meta.expiresAt || 0) < now || NS.trustedDownloadIntents.size > 100) NS.trustedDownloadIntents.delete(k);
      }
    }
    return true;
  };

  NS.rememberDownloadSourceIntent = function (tabId, href) {
    if (tabId == null || tabId < 0) return false;
    const key = NS.normalizeTrustedDownloadUrl(href);
    if (!key) return false;
    const now = Date.now();
    NS.downloadSourceIntents.set(key, { tabId, setAt: now, expiresAt: now + 120000 });
    if (NS.downloadSourceIntents.size > 160) {
      for (const [k, meta] of NS.downloadSourceIntents) {
        if (!meta || Number(meta.expiresAt || 0) < now || NS.downloadSourceIntents.size > 120) NS.downloadSourceIntents.delete(k);
      }
    }
    return true;
  };

  NS.getDownloadSourceIntentTabId = function (item) {
    const now = Date.now();
    for (const raw of [(item && item.finalUrl) || "", (item && item.url) || ""]) {
      const key = NS.normalizeTrustedDownloadUrl(raw);
      if (!key) continue;
      const intent = NS.downloadSourceIntents.get(key);
      if (!intent) continue;
      if (Number(intent.expiresAt || 0) < now) {
        NS.downloadSourceIntents.delete(key);
        continue;
      }
      return Number.isInteger(intent.tabId) ? intent.tabId : null;
    }
    return null;
  };

  NS.getTrustedDownloadSource = function (item) {
    try {
      const directId = Number.isInteger(item && item.tabId) && item.tabId >= 0 ? item.tabId : null;
      if (directId != null && NS.trustedDownloadTabs.has(directId)) return NS.trustedDownloadTabs.get(directId);
      const referrer = String((item && item.referrer) || "").trim();
      if (referrer) {
        try {
          const origin = new URL(referrer).origin;
          const byOrigin = NS.trustedDownloadOrigins.get(origin) || null;
          if (byOrigin) return byOrigin;
        } catch { /* malformed referrer: still try the exact download intent below */ }
      }
      const now = Date.now();
      for (const raw of [(item && item.finalUrl) || "", (item && item.url) || ""]) {
        const key = NS.normalizeTrustedDownloadUrl(raw);
        if (!key) continue;
        const intent = NS.trustedDownloadIntents.get(key);
        if (!intent) continue;
        if (Number(intent.expiresAt || 0) < now || !NS.trustedDownloadTabs.has(intent.tabId)) {
          NS.trustedDownloadIntents.delete(key);
          continue;
        }
        return NS.trustedDownloadTabs.get(intent.tabId) || null;
      }
      return null;
    } catch { return null; }
  };

  NS.resolveDownloadSourceTabId = function (item) {
    const directId = Number.isInteger(item && item.tabId) && item.tabId >= 0 ? item.tabId : null;
    if (directId != null) return directId;
    const trusted = NS.getTrustedDownloadSource(item);
    if (trusted && Number.isInteger(trusted.tabId)) return trusted.tabId;
    return typeof NS.getDownloadSourceIntentTabId === "function"
      ? NS.getDownloadSourceIntentTabId(item)
      : null;
  };
  /** tabId -> { lastGoodUrl, landedAt, reversing, dnrArmedUntil } - 导航状态。 */
  NS.tabNavState = new Map();

  // --- 下载事件尽早排队（模块未就绪前不丢事件）---
  const _dlEarlyQueue = [];
  let _dlModulesReady = false;
  /** 已处理过的 downloadId，避免 onCreated + onDeterminingFilename 双触发 */
  NS._handledDownloadIds = NS._handledDownloadIds || new Set();
  /** Edge 可能先触发 downloads 事件、后送达页面的可信 URL 消息；短暂合并同一下载的判定。 */
  NS._pendingDownloadTrustChecks = NS._pendingDownloadTrustChecks || new Map();

  function enqueueOrHandleDownload(item, source) {
    try {
      if (!item || item.id == null) return;
      if (!_dlModulesReady) {
        _dlEarlyQueue.push({ item, source: source || "early" });
        return;
      }
      if (typeof NS.handleDownloadItem === "function") {
        NS.handleDownloadItem(item, source || "live");
      }
    } catch (e) {
      try { console.warn("[silverfox] download enqueue", e); } catch { /* ignore */ }
    }
  }

  if (chrome.downloads && chrome.downloads.onCreated) {
    chrome.downloads.onCreated.addListener((item) => {
      enqueueOrHandleDownload(item, "onCreated");
    });
  }
  // 文件名在 onCreated 时常为空；确定文件名后再检一次
  if (chrome.downloads && chrome.downloads.onDeterminingFilename) {
    chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
      try {
        enqueueOrHandleDownload(item, "onDeterminingFilename");
      } catch { /* ignore */ }
      try {
        // 必须调用 suggest，否则下载会卡住
        if (typeof suggest === "function") suggest();
      } catch { /* ignore */ }
    });
  }
  if (chrome.downloads && chrome.downloads.onChanged) {
    chrome.downloads.onChanged.addListener((delta) => {
      try {
        if (!delta || delta.id == null) return;
        // 文件名补全 / 开始写入时再尝试（覆盖 onCreated 信息不全）
        if (!delta.filename && !(delta.state && delta.state.current === "in_progress")) return;
        if (NS._handledDownloadIds && NS._handledDownloadIds.has(delta.id)) return;
        chrome.downloads.search({ id: delta.id }, (items) => {
          try {
            const it = items && items[0];
            if (it) enqueueOrHandleDownload(it, "onChanged");
          } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
    });
  }

  // 模块加载（顺序：工具 → SSL 证书 → PE/VT → 通知 → 导航保护 → 下载判定 → 消息处理）
  importScripts("./filename-heuristics-bg.js");
  importScripts("./ssl-cert-bg.js");
  importScripts("./pe-vt-bg.js");
  importScripts("./notification-bg.js");
  importScripts("./nav-protection-bg.js");
  importScripts("./download-verdict-bg.js");
  importScripts("./message-handler-bg.js");

  // 模块就绪：处理排队中的下载
  _dlModulesReady = true;
  try {
    while (_dlEarlyQueue.length) {
      const q = _dlEarlyQueue.shift();
      if (q && q.item && typeof NS.handleDownloadItem === "function") {
        NS.handleDownloadItem(q.item, q.source || "queued");
      }
    }
  } catch (e) {
    try { console.warn("[silverfox] flush dl queue", e); } catch { /* ignore */ }
  }

  // 从 storage 恢复 protect_tab_*（刷新扩展后内存 Set 会空）
  try {
    chrome.storage.local.get(null, (all) => {
      try {
        if (!all || typeof all !== "object") return;
        Object.keys(all).forEach((k) => {
          if (!/^protect_tab_(\d+)$/.test(k)) return;
          if (!all[k]) return;
          const id = Number(RegExp.$1);
          if (id >= 0) NS.protectedTabs.add(id);
        });
      } catch { /* ignore */ }
    });
  } catch { /* ignore */ }

  // --- 注册 nav-boot + 清理残留 DNR / 启动清系统通知 ---
  try {
    NS.ensureRegisteredNavBoot();
    NS.clearAllHostileNavDnr();
    try { NS.ensureMixedContentUpgradeDnr(); } catch { /* ignore */ }
    // 仅浏览器启动/安装时清托盘，避免 SW 热重启误清正在看的通知
    chrome.runtime.onInstalled.addListener(() => {
      NS.ensureRegisteredNavBoot();
      NS.clearAllHostileNavDnr();
      try { NS.ensureMixedContentUpgradeDnr(); } catch { /* ignore */ }
      try { NS.onNotificationBootCleanup(); } catch { /* ignore */ }
    });
    chrome.runtime.onStartup.addListener(() => {
      NS.ensureRegisteredNavBoot();
      NS.clearAllHostileNavDnr();
      try { NS.ensureMixedContentUpgradeDnr(); } catch { /* ignore */ }
      try { NS.onNotificationBootCleanup(); } catch { /* ignore */ }
    });
  } catch { /* ignore */ }

  // --- webNavigation ---
  if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
    chrome.webNavigation.onBeforeNavigate.addListener((details) => { try { NS.onMainFrameBeforeNavigate(details); } catch (e) { console.warn("beforeNavigate safety net", e); } });
  }
  if (chrome.webNavigation && chrome.webNavigation.onCommitted) {
    chrome.webNavigation.onCommitted.addListener((details) => { try { NS.noteCommittedNavigation(details); } catch (e) { console.warn("nav safety net error", e); } });
  }
  if (chrome.webNavigation && chrome.webNavigation.onHistoryStateUpdated) {
    chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
      try { if (details.frameId !== 0) return; if (details.tabId == null || details.tabId < 0) return; NS.onTabUrlChangedForAnalysis(details.tabId, details.url || ""); NS.injectNavBoot(details.tabId, 0); } catch { /* ignore */ }
    });
  }
  if (chrome.webNavigation && chrome.webNavigation.onReferenceFragmentUpdated) {
    chrome.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
      try { if (details.frameId !== 0) return; if (details.tabId == null || details.tabId < 0) return; NS.onTabUrlChangedForAnalysis(details.tabId, details.url || ""); } catch { /* ignore */ }
    });
  }

  // --- tabs.onUpdated ---
  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.url) {
        const st = NS.getTabNav(tabId);
        const newUrl = changeInfo.url;
        if (st.reversing) { NS.injectNavBoot(tabId, 0); return; }
        NS.onTabUrlChangedForAnalysis(tabId, newUrl);
        if (!NS.isOnProtectedOrigin(tabId, newUrl) || NS.isHostileAutoTarget(newUrl)) {
          if (NS.protectedTabs.has(tabId) && !NS.isOnProtectedOrigin(tabId, newUrl)) {
            NS.pauseNavBlocking(tabId, "tabs-url-leave");
            NS.clearTabAnalysisState(tabId);
            if (!NS.isHostileAutoTarget(newUrl)) st.lastGoodUrl = newUrl;
            NS.injectNavBoot(tabId, 0);
            return;
          }
          if (NS.isHostileAutoTarget(newUrl) && NS.protectedTabs.has(tabId)) { NS.pauseNavBlocking(tabId, "tabs-serp"); }
        }
        if (NS.releaseProtectionIfLeftOrigin(tabId, newUrl)) { st.lastGoodUrl = newUrl; NS.injectNavBoot(tabId, 0); return; }
        if (!NS.isHostileAutoTarget(newUrl)) st.lastGoodUrl = newUrl;
        NS.injectNavBoot(tabId, 0);
      }
      if (changeInfo.status === "loading") NS.injectNavBoot(tabId, 0);
      if (changeInfo.status === "complete" && tab && tab.url && /^https?:/i.test(tab.url)) {
        const st = NS.getTabNav(tabId);
        if (!NS.isHostileAutoTarget(tab.url)) { st.lastGoodUrl = tab.url; NS.releaseProtectionIfLeftOrigin(tabId, tab.url); }
        else if (NS.protectedTabs.has(tabId) && !NS.isOnProtectedOrigin(tabId, tab.url)) { NS.pauseNavBlocking(tabId, "complete-serp"); NS.clearTabAnalysisState(tabId); }
      }
    });
  }

  // DNR 阻塞表现为 ERR_BLOCKED_BY_CLIENT - 解锁使用户离开后能打开搜索
  if (chrome.webNavigation && chrome.webNavigation.onErrorOccurred) {
    chrome.webNavigation.onErrorOccurred.addListener((details) => {
      try {
        if (details.frameId !== 0) return;
        const tabId = details.tabId;
        if (tabId == null || tabId < 0) return;
        const err = String(details.error || "");
        if (!/BLOCKED_BY_CLIENT/i.test(err)) return;
        const st = NS.getTabNav(tabId);
        if (st.reversing) { NS.pauseNavBlocking(tabId, "blocked-during-reverse"); return; }
        NS.pauseNavBlocking(tabId, "err-blocked-by-client");
        NS.clearTabAnalysisState(tabId);
      } catch { /* ignore */ }
    });
  }

  // --- tabs.onRemoved ---
  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => { NS.clearTabAnalysisState(tabId); NS.disarmHostileNavDnr(tabId); NS.tabNavState.delete(tabId); });
  }

  // --- 下载处理（onCreated / onDeterminingFilename / onChanged 共用）---
  // 策略：
  //  1) VT 放行回放 URL（grantVtPass）→ 直接通过
  //  2) 启发式应取消 → 取消 + VT 门禁检测（展示结果，不再自动放行）
  //  3) 保护页安装包 → 先取消，VT 通过后再 downloads.download 放行
  //  4) 其它安装包 → 不拦下载，后台 VT（仅展示）
  NS.handleDownloadItem = function (item, source) {
    try {
      if (!item || item.id == null) return;
      const pendingTrustCheck = NS._pendingDownloadTrustChecks.get(item.id);
      if (pendingTrustCheck && source !== "trust-recheck") {
        pendingTrustCheck.item = { ...pendingTrustCheck.item, ...item };
        return;
      }
      const dlUrl = item.finalUrl || item.url || "";
      // VT 门禁通过后的二次下载
      if (dlUrl && typeof NS.consumeVtPassUrl === "function" && NS.consumeVtPassUrl(dlUrl)) {
        NS._handledDownloadIds.add(item.id);
        return;
      }

      // Edge 的 DownloadItem 常不带 tabId；用已核验页面的 referrer/origin 找回来源 tab。
      const tabId = typeof NS.resolveDownloadSourceTabId === "function"
        ? NS.resolveDownloadSourceTabId(item)
        : (item.tabId ?? null);
      const isPkg = (() => {
        try {
          const name = (item.filename || "").split(/[/\\]/).pop() || "";
          const { PackageHeuristicsBg } = NS;
          if (!PackageHeuristicsBg) {
            // 启发式未加载时：宽松扩展名判断，避免漏检
            return /\.(zip|exe|dll|msi|rar|7z|apk|dmg|pkg|cab|iso)(?:\?|#|$)/i.test(name)
              || /\.(zip|exe|dll|msi|rar|7z|apk|dmg|pkg|cab|iso)(?:\?|#|$)/i.test(dlUrl);
          }
          return !!(PackageHeuristicsBg.PACKAGE_NAME_RE.test(name)
            || PackageHeuristicsBg.PACKAGE_NAME_RE.test(PackageHeuristicsBg.basenameFromPath(dlUrl))
            || /\.(zip|exe|dll|msi|rar|7z|apk)(?:\?|#|$)/i.test(dlUrl));
        } catch { return false; }
      })();

      // 已处理过：跳过（避免 onCreated + onDeterminingFilename 双开 VT）
      if (NS._handledDownloadIds.has(item.id)) return;

      // onCreated 时文件名常空：若还看不出是安装包，留给 onDeterminingFilename/onChanged
      if (!isPkg && (source === "onCreated" || source === "early" || source === "queued")) {
        return;
      }

      const verdict = typeof NS.shouldCancelDownload === "function"
        ? NS.shouldCancelDownload(item)
        : { cancel: false };
      const protectedTab = tabId != null && NS.protectedTabs && NS.protectedTabs.has(tabId);

      // Edge 常同时省略 tabId/referrer；页面 postMessage -> content -> SW 比 downloads 事件稍晚。
      // 对这种无来源且仅命中启发式的下载等待 450ms，再用精确 URL 可信意图复判。
      const hasDirectSourceContext = (Number.isInteger(item.tabId) && item.tabId >= 0)
        || !!String(item.referrer || "").trim();
      if (verdict.cancel && !hasDirectSourceContext && source !== "trust-recheck" && /^https?:\/\//i.test(dlUrl)) {
        const pending = { item: { ...item }, timer: null };
        pending.timer = setTimeout(() => {
          try {
            const latest = NS._pendingDownloadTrustChecks.get(item.id);
            NS._pendingDownloadTrustChecks.delete(item.id);
            if (latest && latest.item) NS.handleDownloadItem(latest.item, "trust-recheck");
          } catch { /* ignore */ }
        }, 450);
        NS._pendingDownloadTrustChecks.set(item.id, pending);
        return;
      }

      const strongProduct = (() => {
        try {
          const { PackageHeuristicsBg } = NS;
          if (!PackageHeuristicsBg) return false;
          const name = PackageHeuristicsBg.basenameFromPath(item.filename)
            || PackageHeuristicsBg.basenameFromPath(dlUrl);
          return PackageHeuristicsBg.looksLikeStrongProductInstallerName(name);
        } catch { return false; }
      })();

      // 标记已处理（取消路径也会 probe）
      const markHandled = () => {
        try {
          const pending = NS._pendingDownloadTrustChecks.get(item.id);
          if (pending && pending.timer) clearTimeout(pending.timer);
          NS._pendingDownloadTrustChecks.delete(item.id);
        } catch { /* ignore */ }
        try { NS._handledDownloadIds.add(item.id); } catch { /* ignore */ }
        // 防止 Set 无限增长
        if (NS._handledDownloadIds.size > 200) {
          const arr = [...NS._handledDownloadIds];
          NS._handledDownloadIds = new Set(arr.slice(-80));
        }
      };

      if (verdict.cancel) {
        markHandled();
        chrome.downloads.cancel(item.id, () => {
          if (chrome.runtime.lastError) {
            console.warn("download cancel failed", chrome.runtime.lastError.message);
            return;
          }
          try { chrome.downloads.erase({ id: item.id }); } catch { /* ignore */ }
          if (tabId != null) NS.safeSetBadge(tabId, "!", "#d93025");
          const cancelLabel = verdict.label || "可疑安装包";
          // 系统通知有冷却且下载可能来自隐藏 iframe；每次实际取消都把页内提示送到顶层 frame。
          if (tabId != null) {
            try {
              chrome.tabs.sendMessage(tabId, {
                type: "show-page-threat-toast",
                title: "已拦截可疑下载文件",
                message: cancelLabel,
                force: true
              }, { frameId: 0 }, () => { void chrome.runtime.lastError; });
            } catch { /* ignore */ }
          }
          const maybeNotify = async () => {
            try {
              if (typeof NS.shouldNotifyDownloadBlock === "function") {
                const allow = await NS.shouldNotifyDownloadBlock(cancelLabel || dlUrl);
                if (!allow) return;
              }
              await NS.showBlockedNotification("已拦截可疑下载文件", cancelLabel, tabId);
            } catch { /* ignore */ }
          };
          maybeNotify();
          const pageUrlForNotice = (() => {
            try {
              if (tabId == null) return dlUrl;
              const st = NS.tabNavState && NS.tabNavState.get ? NS.tabNavState.get(tabId) : null;
              return (st && st.lastGoodUrl) || dlUrl;
            } catch { return dlUrl; }
          })();
          const { PackageHeuristicsBg } = NS;
          if (PackageHeuristicsBg && !(PackageHeuristicsBg.looksLikeProductPackageName(cancelLabel)
            || PackageHeuristicsBg.looksLikeProductSetupWithBuildId(String(cancelLabel).replace(/\.[^.]+$/, "")))) {
            chrome.storage.local.set({
              latestNotice: {
                title: "已拦截可疑下载文件",
                message: cancelLabel,
                tabId,
                url: pageUrlForNotice,
                timestamp: Date.now()
              }
            });
          }
          try {
            if (typeof NS.probeDownloadExecutableAsync === "function") {
              NS.probeDownloadExecutableAsync(item, {
                cancelled: true,
                gate: false,
                requireSignedPe: !!protectedTab,
                sourceTabId: tabId,
                trustedSource: false
              });
            }
          } catch { /* ignore */ }
        });
        return;
      }

      // 保护页上的安装包：先扣下，VT 通过再放行
      if (protectedTab && !verdict.trustedSource && isPkg && !strongProduct && /^https?:\/\//i.test(dlUrl)) {
        markHandled();
        chrome.downloads.cancel(item.id, () => {
          if (chrome.runtime.lastError) {
            console.warn("vt-gate cancel failed", chrome.runtime.lastError.message);
          }
          try { chrome.downloads.erase({ id: item.id }); } catch { /* ignore */ }
          if (tabId != null) NS.safeSetBadge(tabId, "…", "#f59e0b");
          try {
            if (typeof NS.probeDownloadExecutableAsync === "function") {
              NS.probeDownloadExecutableAsync(item, {
                gate: true,
                requireSignedPe: true,
                sourceTabId: tabId,
                trustedSource: false
              });
            }
          } catch { /* ignore */ }
        });
        return;
      }

      // 普通页安装包：不拦，后台 VT 仅展示
      if (isPkg && !strongProduct) {
        markHandled();
        try {
          if (typeof NS.probeDownloadExecutableAsync === "function") {
            NS.probeDownloadExecutableAsync(item, {
              gate: false,
              sourceTabId: tabId,
              trustedSource: !!verdict.trustedSource
            });
          }
        } catch { /* ignore */ }
      }
    } catch (e) {
      console.warn("handleDownloadItem error", e);
    }
  };

  // --- 消息处理 ---
  NS.installMessageHandler();

  // 扩展重载后：已有标签页 content 是死的，轻量 ping 让页面在下次交互前尽量恢复保护态
  try {
    if (chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ url: ["http://*/*", "https://*/*"] }, (tabs) => {
        try {
          (tabs || []).forEach((t) => {
            if (!t || t.id == null) return;
            try {
              chrome.tabs.sendMessage(t.id, { type: "silverfox-sw-awake" }, () => {
                void chrome.runtime.lastError;
              });
            } catch { /* ignore */ }
          });
        } catch { /* ignore */ }
      });
    }
  } catch { /* ignore */ }
})(self.SilverfoxBackground ??= {});
