/**
 * 通知图标（运行时生成蓝色 PNG）+ 系统通知去重/冷却。
 */
;(function (NS) {
  "use strict";

  NS.shownNoticeKeys = new Set();
  NS.shownNoticeAt = new Map();
  NS.cachedIconDataUrl = null;
  const NOTICE_RESHOW_COOLDOWN_MS = 6000;

  NS.noticeKey = function (title, message, tabId) {
    return `${tabId ?? "all"}::${String(title)}::${String(message)}`;
  };

  NS.notificationIdFromKey = function (key) {
    let h = 0;
    for (let i = 0; i < key.length; i++) h = (Math.imul(31, h) + key.charCodeAt(i)) | 0;
    return `silverfox-notice-${h >>> 0}`;
  };

  function crc32(bytes) {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      c ^= bytes[i];
      for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function u32(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }

  function concatBytes(parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }

  function pngChunk(typeStr, data) {
    const type = new Uint8Array(4);
    for (let i = 0; i < 4; i++) type[i] = typeStr.charCodeAt(i);
    const crcBody = concatBytes([type, data]);
    return concatBytes([u32(data.length), type, data, u32(crc32(crcBody))]);
  }

  /** 生成纯色蓝 PNG（#2563EB）-- Chrome 通知需要真 PNG，不能用 SVG。 */
  NS.buildBluePngDataUrl = async function (size = 64) {
    const stride = 1 + size * 4;
    const raw = new Uint8Array(stride * size);
    const R = 37, G = 99, B = 235, A = 255;
    const cx = size / 2; const cy = size / 2;
    const rOuter = size * 0.42; const rOuter2 = rOuter * rOuter;
    for (let y = 0; y < size; y++) {
      const row = y * stride;
      raw[row] = 0;
      for (let x = 0; x < size; x++) {
        const i = row + 1 + x * 4;
        const dx = x + 0.5 - cx; const dy = y + 0.5 - cy;
        const d2 = dx * dx + dy * dy;
        const inCircle = d2 <= rOuter2;
        const inSquare = x > size * 0.08 && x < size * 0.92 && y > size * 0.08 && y < size * 0.92;
        if (inCircle || inSquare) {
          const onCheck = (Math.abs(x - (size * 0.28 + (y - size * 0.48))) < size * 0.07 && y > size * 0.42 && y < size * 0.68 && x < size * 0.5) || (Math.abs(y - (size * 1.05 - x * 0.85)) < size * 0.07 && x > size * 0.42 && x < size * 0.78 && y > size * 0.32 && y < size * 0.62);
          if (onCheck) { raw[i] = 255; raw[i + 1] = 255; raw[i + 2] = 255; raw[i + 3] = 255; }
          else { raw[i] = R; raw[i + 1] = G; raw[i + 2] = B; raw[i + 3] = A; }
        } else { raw[i] = 0; raw[i + 1] = 0; raw[i + 2] = 0; raw[i + 3] = 0; }
      }
    }
    let compressed;
    if (typeof CompressionStream !== "undefined") {
      const cs = new CompressionStream("deflate");
      const writer = cs.writable.getWriter();
      writer.write(raw); writer.close();
      const ab = await new Response(cs.readable).arrayBuffer();
      compressed = new Uint8Array(ab);
    } else {
      return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    }
    const signature = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
    const ihdr = new Uint8Array(13);
    ihdr.set(u32(size), 0); ihdr.set(u32(size), 4);
    ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
    const png = concatBytes([signature, pngChunk("IHDR", ihdr), pngChunk("IDAT", compressed), pngChunk("IEND", new Uint8Array(0))]);
    let binary = "";
    for (let i = 0; i < png.length; i++) binary += String.fromCharCode(png[i]);
    return `data:image/png;base64,${btoa(binary)}`;
  };

  NS.getNotificationIconUrl = async function () {
    if (NS.cachedIconDataUrl) return NS.cachedIconDataUrl;
    try { NS.cachedIconDataUrl = await NS.buildBluePngDataUrl(64); }
    catch (e) {
      console.warn("icon build failed", e);
      NS.cachedIconDataUrl = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    }
    return NS.cachedIconDataUrl;
  };

  /** 显示拦截通知（去重 + 冷却后允许再提示）。 */
  NS.showBlockedNotification = async function (title, message, tabId, force = false) {
    const key = NS.noticeKey(title, message, tabId);
    const now = Date.now();
    const last = NS.shownNoticeAt.get(key) || 0;
    if (!force && NS.shownNoticeKeys.has(key) && now - last < NOTICE_RESHOW_COOLDOWN_MS) return false;
    const iconUrl = await NS.getNotificationIconUrl();
    const id = `${NS.notificationIdFromKey(key)}-${now}`;
    const opts = { type: "basic", iconUrl, title: String(title || "威胁检测"), message: String(message || "").slice(0, 250), priority: 2, requireInteraction: false };
    return new Promise((resolve) => {
      chrome.notifications.create(id, opts, (createdId) => {
        if (chrome.runtime.lastError) {
          console.warn("notification failed", chrome.runtime.lastError.message);
          const fallbackId = `silverfox-fallback-${Date.now()}`;
          const fallbackIcon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
          chrome.notifications.create(fallbackId, { ...opts, iconUrl: fallbackIcon }, () => {
            if (chrome.runtime.lastError) { console.warn("notification fallback failed", chrome.runtime.lastError.message); resolve(false); return; }
            NS.shownNoticeKeys.add(key); NS.shownNoticeAt.set(key, Date.now()); resolve(true);
          });
          return;
        }
        NS.shownNoticeKeys.add(key); NS.shownNoticeAt.set(key, Date.now()); resolve(true);
      });
    });
  };

  // 预构建图标，使首次通知更快
  NS.getNotificationIconUrl().catch(() => {});
})(self.SilverfoxBackground ??= {});
