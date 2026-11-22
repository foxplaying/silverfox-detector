/**
 * 系统通知：使用扩展本地 icons/*.png（与工具栏/扩展管理页同源），
 * 稳定 ID 覆盖 + 内存短冷却 + storage 跨会话冷却。
 * 避免浏览器重启/会话恢复后连环弹出「之前拦过的下载」。
 */
;(function (NS) {
  "use strict";

  NS.shownNoticeKeys = new Set();
  NS.shownNoticeAt = new Map();
  NS.cachedIconDataUrl = null;
  NS.notificationChannelVersions = new Map();

  /** 同 tab 同文案短冷却（防扫描连发） */
  const NOTICE_SHORT_COOLDOWN_MS = 8000;
  /** 同文案跨会话冷却：重启 / 会话恢复重扫不重复弹系统通知 */
  const NOTICE_SESSION_COOLDOWN_MS = 40 * 60 * 1000;
  const COOLDOWN_STORAGE_KEY = "silverfoxNoticeCooldown";
  /** 下载 URL 级冷却（恢复未完成下载时 onCreated 再触发） */
  const DOWNLOAD_URL_COOLDOWN_MS = 40 * 60 * 1000;
  const DOWNLOAD_COOLDOWN_STORAGE_KEY = "silverfoxDownloadNoticeCooldown";

  NS.noticeKey = function (title, message, tabId) {
    return `${tabId ?? "all"}::${String(title)}::${String(message)}`;
  };

  /** 跨 tab / 跨会话：只按标题+正文去重（文件名相同即视为同一条） */
  NS.contentNoticeKey = function (title, message) {
    return `${String(title || "")}::${String(message || "").slice(0, 250)}`;
  };

  NS.notificationIdFromKey = function (key) {
    let h = 0;
    for (let i = 0; i < key.length; i++) h = (Math.imul(31, h) + key.charCodeAt(i)) | 0;
    return `silverfox-notice-${h >>> 0}`;
  };

  NS.clearNotificationChannel = function (channelKey) {
    const channel = String(channelKey || "").trim();
    if (!channel) return false;
    NS.notificationChannelVersions.delete(channel);
    NS.shownNoticeKeys.delete(channel);
    NS.shownNoticeAt.delete(channel);
    for (const key of Array.from(NS.shownNoticeKeys)) {
      if (String(key).startsWith(`${channel}::`)) NS.shownNoticeKeys.delete(key);
    }
    for (const key of Array.from(NS.shownNoticeAt.keys())) {
      if (String(key).startsWith(`${channel}::`)) NS.shownNoticeAt.delete(key);
    }
    try {
      const id = NS.notificationIdFromKey(channel);
      chrome.notifications.clear(id, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
    return true;
  };

  /** 清掉本扩展创建的系统通知（启动时避免托盘残留连环弹出） */
  NS.clearAllSilverfoxNotifications = function () {
    try {
      if (!chrome?.notifications?.getAll) return;
      chrome.notifications.getAll((all) => {
        void chrome.runtime.lastError;
        const ids = Object.keys(all || {});
        for (const id of ids) {
          try {
            // 本扩展 id 均为 silverfox-notice-* / 历史 silverfox-fallback-*
            if (!/^silverfox/i.test(String(id))) continue;
            chrome.notifications.clear(id, () => { void chrome.runtime.lastError; });
          } catch { /* ignore */ }
        }
      });
    } catch { /* ignore */ }
  };

  /** 启动时：清托盘通知 + 不删 cooldown（避免恢复页立刻再弹同一条） */
  NS.onNotificationBootCleanup = function () {
    try { NS.clearAllSilverfoxNotifications(); } catch { /* ignore */ }
  };

  function loadCooldownMap(storageKey) {
    return new Promise((resolve) => {
      try {
        if (!chrome?.storage?.local) { resolve({}); return; }
        chrome.storage.local.get([storageKey], (r) => {
          void chrome.runtime.lastError;
          const map = (r && r[storageKey] && typeof r[storageKey] === "object") ? r[storageKey] : {};
          resolve(map || {});
        });
      } catch { resolve({}); }
    });
  }

  // The two dictionaries are independent. Within one key the next read
  // must wait until the previous chrome.storage.set callback has completed.
  const cooldownWrites = new Map();
  function recordCooldown(storageKey, key, ttl, max, keep, onlyIfNew) {
    const previous = cooldownWrites.get(storageKey) || Promise.resolve();
    const task = previous.then(async () => {
      const now = Date.now();
      const map = pruneCooldownMap(await loadCooldownMap(storageKey), ttl, now);
      if (onlyIfNew && Number(map[key]) > now - ttl) return false;
      map[key] = now;
      const keys = Object.keys(map);
      if (keys.length > max) {
        keys.sort((a, b) => map[a] - map[b]);
        for (const old of keys.slice(0, keys.length - keep)) delete map[old];
      }
      if (chrome?.storage?.local) await new Promise(resolve => {
        chrome.storage.local.set({ [storageKey]: map }, () => { void chrome.runtime.lastError; resolve(); });
      });
      return true;
    }).catch(() => true);
    cooldownWrites.set(storageKey, task);
    return task.finally(() => { if (cooldownWrites.get(storageKey) === task) cooldownWrites.delete(storageKey); });
  }

  function pruneCooldownMap(map, ttlMs, now) {
    const out = {};
    const cut = now - ttlMs;
    for (const k of Object.keys(map || {})) {
      const t = Number(map[k]) || 0;
      if (t > cut) out[k] = t;
    }
    return out;
  }

  /** 与 manifest icons / action.default_icon 同步的本地 PNG。 */
  NS.getNotificationIconUrl = async function () {
    if (NS.cachedIconDataUrl) return NS.cachedIconDataUrl;
    try {
      // 通知区域图标用 128，Windows 右下角展示更清晰且与扩展图标一致
      NS.cachedIconDataUrl = chrome.runtime.getURL("icons/icon128.png");
    } catch (e) {
      console.warn("notification icon url failed", e);
      try {
        NS.cachedIconDataUrl = chrome.runtime.getURL("icons/icon48.png");
      } catch {
        NS.cachedIconDataUrl = chrome.runtime.getURL("icons/icon16.png");
      }
    }
    return NS.cachedIconDataUrl;
  };

  /**
   * 显示拦截通知。
   * - 稳定 notificationId：同文案覆盖，不堆叠
   * - 普通下载拦截：短冷却 + 40min 跨会话冷却（防启动连环弹）
   * - force / 仿冒身份类：绕过 40min 冷却，仅 2s 防同次扫描连发（保证仿冒官网右下角能弹）
   */
  const pendingNotifications = new Map();
  NS.showBlockedNotification = function (title, message, tabId, force = false, options = null) {
    const channel = String(options && options.channelKey || "").trim();
    const version = String(options && options.versionToken || "").trim();
    const key = channel ? JSON.stringify(["channel", channel, version])
      : JSON.stringify(["content", String(title || "威胁检测"), String(message || "").slice(0, 250)]);
    // 冷却时间在创建完成后落盘；创建期间也必须占位，防并发都通过检查。
    if (pendingNotifications.has(key)) return Promise.resolve(false);
    const pending = showBlockedNotificationOnce(title, message, tabId, force, options);
    pendingNotifications.set(key, pending);
    return pending.finally(() => {
      if (pendingNotifications.get(key) === pending) pendingNotifications.delete(key);
    });
  };

  async function showBlockedNotificationOnce(title, message, tabId, force = false, options = null) {
    const t = String(title || "威胁检测");
    const m = String(message || "").slice(0, 250);
    const channelKey = String(options && options.channelKey || "").trim();
    const versionToken = String(options && options.versionToken || "").trim();
    if (channelKey && !versionToken) return false;
    if (channelKey) NS.notificationChannelVersions.set(channelKey, versionToken);
    const channelIsCurrent = () => !channelKey
      || NS.notificationChannelVersions.get(channelKey) === versionToken;
    const contentKey = channelKey || NS.contentNoticeKey(t, m);
    const cooldownKey = options?.cooldownKey || contentKey;
    const key = channelKey ? `${channelKey}::${versionToken}` : NS.noticeKey(t, m, tabId);
    const now = Date.now();
    // 仿冒官网 / 异常跳转：视为身份类，必须能弹系统通知
    const isIdentity = /仿冒|官网|域名|跳转|搜索引擎|brand-spoof|nav-trap/i.test(`${t} ${m}`);
    const forceShow = !!force || isIdentity;

    // 短冷却：普通 8s；force/仿冒仅 2s（同次 scan 双发去重）
    const shortMs = forceShow ? 2000 : NOTICE_SHORT_COOLDOWN_MS;
    const lastMem = NS.shownNoticeAt.get(key)
      || (!channelKey ? NS.shownNoticeAt.get(contentKey) : 0) || 0;
    if (lastMem && now - lastMem < shortMs) return false;

    // 跨会话长冷却：仅约束「非 force 的普通下载拦截」；仿冒/force 不挡
    if (!forceShow) {
      try {
        let map = await loadCooldownMap(COOLDOWN_STORAGE_KEY);
        map = pruneCooldownMap(map, NOTICE_SESSION_COOLDOWN_MS, now);
        const lastStored = Number(map[cooldownKey]) || 0;
        if (lastStored && now - lastStored < NOTICE_SESSION_COOLDOWN_MS) {
          NS.shownNoticeKeys.add(key);
          NS.shownNoticeKeys.add(contentKey);
          NS.shownNoticeAt.set(key, lastStored);
          NS.shownNoticeAt.set(contentKey, lastStored);
          return false;
        }
      } catch { /* ignore storage errors, still try show */ }
    }

    const iconUrl = await NS.getNotificationIconUrl();
    if (!channelIsCurrent()) return false;
    // 稳定 ID：同 contentKey 覆盖，避免 Windows 托盘堆一串
    const id = NS.notificationIdFromKey(contentKey);
    const opts = {
      type: "basic",
      iconUrl,
      title: t,
      message: m,
      priority: 2,
      requireInteraction: false
    };

    const markShown = () => {
      const ts = Date.now();
      NS.shownNoticeKeys.add(key);
      NS.shownNoticeKeys.add(contentKey);
      NS.shownNoticeAt.set(key, ts);
      NS.shownNoticeAt.set(contentKey, ts);
      return recordCooldown(COOLDOWN_STORAGE_KEY, cooldownKey, NOTICE_SESSION_COOLDOWN_MS, 80, 60, false);
    };

    return new Promise((resolve) => {
      const createNotification = (createOpts) => {
        if (!channelIsCurrent()) { resolve(false); return; }
        chrome.notifications.create(id, createOpts, () => {
          if (chrome.runtime.lastError) {
            console.warn("notification failed", chrome.runtime.lastError.message);
            const fallbackIcon = (() => {
              try { return chrome.runtime.getURL("icons/icon48.png"); } catch { return iconUrl; }
            })();
            if (!channelIsCurrent()) { resolve(false); return; }
            chrome.notifications.create(id, { ...createOpts, iconUrl: fallbackIcon }, () => {
              if (chrome.runtime.lastError) {
                console.warn("notification fallback failed", chrome.runtime.lastError.message);
                resolve(false);
                return;
              }
              if (!channelIsCurrent()) { resolve(false); return; }
              resolve(markShown());
            });
            return;
          }
          if (!channelIsCurrent()) { resolve(false); return; }
          resolve(markShown());
        });
      };

      // A brand channel uses one stable notification ID.  Updating it replaces
      // the old hydrated brand in Windows instead of leaving A and B side by
      // side in the notification center.
      if (channelKey && chrome.notifications.update) {
        chrome.notifications.update(id, opts, (updated) => {
          if (chrome.runtime.lastError) void chrome.runtime.lastError;
          if (!channelIsCurrent()) { resolve(false); return; }
          if (updated) {
            resolve(markShown());
            return;
          }
          createNotification(opts);
        });
        return;
      }
      createNotification(opts);
    });
  };

  /**
   * 下载拦截专用：同 URL / 同文件名 40 分钟内不重复系统通知。
   * 返回 true 表示应继续弹（或已弹）；false 表示冷却中应跳过通知（仍可 cancel）。
   */
  NS.shouldNotifyDownloadBlock = async function (urlOrLabel) {
    const raw = String(urlOrLabel || "").trim().slice(0, 300);
    if (!raw) return true;
    return recordCooldown(DOWNLOAD_COOLDOWN_STORAGE_KEY, raw, DOWNLOAD_URL_COOLDOWN_MS, 100, 80, true);
  };

  NS.getNotificationIconUrl().catch(() => {});
})(self.SilverfoxBackground ??= {});
