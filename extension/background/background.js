/**
 * background service worker 入口。
 * 加载各模块后注册 webNavigation / tabs / downloads / runtime 监听。
 */
;(function (NS) {
  "use strict";

  // --- 共享状态（各模块通过 NS 访问）---
  /** 被内容脚本标记为需要包下载取消的标签页。 */
  NS.protectedTabs = new Set();
  /** tabId -> { origin, url, setAt, mode } - 保护绑定到该页面 origin。 */
  NS.protectedTabMeta = new Map();
  /** tabId -> { lastGoodUrl, landedAt, reversing, dnrArmedUntil } - 导航状态。 */
  NS.tabNavState = new Map();

  // 模块加载（顺序：工具 → 通知 → 导航保护 → 下载判定 → 消息处理）
  importScripts("./filename-heuristics-bg.js");
  importScripts("./notification-bg.js");
  importScripts("./nav-protection-bg.js");
  importScripts("./download-verdict-bg.js");
  importScripts("./message-handler-bg.js");

  // --- 注册 nav-boot + 清理残留 DNR / 启动清系统通知 ---
  try {
    NS.ensureRegisteredNavBoot();
    NS.clearAllHostileNavDnr();
    // 仅浏览器启动/安装时清托盘，避免 SW 热重启误清正在看的通知
    chrome.runtime.onInstalled.addListener(() => {
      NS.ensureRegisteredNavBoot();
      NS.clearAllHostileNavDnr();
      try { NS.onNotificationBootCleanup(); } catch { /* ignore */ }
    });
    chrome.runtime.onStartup.addListener(() => {
      NS.ensureRegisteredNavBoot();
      NS.clearAllHostileNavDnr();
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

  // --- downloads.onCreated ---
  if (chrome.downloads && chrome.downloads.onCreated) {
    chrome.downloads.onCreated.addListener((item) => {
      try {
        const verdict = NS.shouldCancelDownload(item);
        if (!verdict.cancel) return;
        chrome.downloads.cancel(item.id, () => {
          if (chrome.runtime.lastError) { console.warn("download cancel failed", chrome.runtime.lastError.message); return; }
          try { chrome.downloads.erase({ id: item.id }); } catch { /* ignore */ }
          const tabId = item.tabId ?? null;
          if (tabId != null) NS.safeSetBadge(tabId, "!", "#d93025");
          const cancelLabel = verdict.label || "可疑安装包";
          const dlUrl = item.finalUrl || item.url || "";
          // 同 URL/文件名 40 分钟内不重复系统通知（浏览器重启恢复下载仍会 cancel，但不连环弹）
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
          if (!(PackageHeuristicsBg.looksLikeProductPackageName(cancelLabel) || PackageHeuristicsBg.looksLikeProductSetupWithBuildId(String(cancelLabel).replace(/\.[^.]+$/, "")))) {
            chrome.storage.local.set({ latestNotice: { title: "已拦截可疑下载文件", message: cancelLabel, tabId, url: pageUrlForNotice, timestamp: Date.now() } });
          }
        });
      } catch (e) { console.warn("onCreated download handler error", e); }
    });
  }

  // --- 消息处理 ---
  NS.installMessageHandler();
})(self.SilverfoxBackground ??= {});
