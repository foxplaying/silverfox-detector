/**
 * 下载意图 UI 判定与灰化/恢复（纯静态 DOM 工具）。
 */
;(function (NS) {
  "use strict";

  class DownloadUi {
    /** 元素是否为下载意图控件（短 CTA 文案 / download 类名）。 */
    static isDownloadIntentText(el) {
      if (!el) return false;
      let text = "";
      try {
        text = `${el.getAttribute("aria-label") || ""} ${el.getAttribute("title") || ""}`.trim();
        if (!text || text.length > 80) {
          text = (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim().slice(0, 64);
        }
      } catch {
        text = (el.textContent || "").trim().slice(0, 64);
      }
      const cls = `${el.className || ""} ${el.id || ""}`;
      const classDl = /(?:^|[\s_-])(?:btn[-_]?download|download[-_]?btn|download[-_]?uri|btn[-_]?install|install[-_]?btn|setup[-_]?btn)(?:[\s_-]|$)/i.test(cls)
        || /(?:^|[\s])download(?:[\s]|$)/i.test(cls);
      return /下载|download|安装|客户端|云电脑|免费下载|官方下载|立即下载/i.test(text) || classDl;
    }

    static greyOut(el) {
      try {
        el.dataset.silverfoxGreyed = "1";
        el.style.setProperty("pointer-events", "none", "important");
        el.style.setProperty("opacity", "0.45", "important");
        el.style.setProperty("cursor", "not-allowed", "important");
        el.style.setProperty("filter", "grayscale(0.6)", "important");
        if (el.tagName === "BUTTON" || el.tagName === "INPUT") el.disabled = true;
        el.setAttribute("aria-disabled", "true");
      } catch { /* ignore */ }
    }

    static restoreGreyed(el) {
      try {
        if (!el) return;
        if (el.dataset.silverfoxGreyed === "1") delete el.dataset.silverfoxGreyed;
        el.style.removeProperty("pointer-events");
        el.style.removeProperty("opacity");
        el.style.removeProperty("cursor");
        el.style.removeProperty("filter");
        if (el.tagName === "BUTTON" || el.tagName === "INPUT") el.disabled = false;
        if (el.getAttribute("aria-disabled") === "true") el.removeAttribute("aria-disabled");
      } catch { /* ignore */ }
    }

    static restoreAllDownloadButtonsInPage() {
      try {
        document.querySelectorAll("a, button, [role='button'], [data-silverfox-greyed='1']").forEach((el) => {
          if (el.dataset.silverfoxGreyed === "1" || DownloadUi.isDownloadIntentText(el)) DownloadUi.restoreGreyed(el);
        });
      } catch { /* ignore */ }
    }

    static disableAllDownloadButtonsInPage() {
      try {
        const { PageContext } = NS;
        if (PageContext.pageLooksLikeSerpUrl()) return; // 永不灰 SERP 结果链接
        document.querySelectorAll("a, button, [role='button']").forEach((el) => {
          if (DownloadUi.isDownloadIntentText(el)) DownloadUi.greyOut(el);
        });
        // 同源 iframe 内下载 CTA（跨源依赖 all_frames + 顶层 set-guard 广播）
        try {
          document.querySelectorAll("iframe").forEach((frame) => {
            try {
              const doc = frame.contentDocument;
              if (!doc) return;
              doc.querySelectorAll("a, button, [role='button']").forEach((el) => {
                try {
                  if (DownloadUi.isDownloadIntentText(el)) DownloadUi.greyOut(el);
                } catch { /* ignore */ }
              });
            } catch { /* cross-origin */ }
          });
        } catch { /* ignore */ }
      } catch { /* ignore */ }
    }
  }

  NS.DownloadUi = DownloadUi;
})(window.SilverfoxPageHooks ??= {});
