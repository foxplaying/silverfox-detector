/**
 * 套件指纹评分：SEO 伪装跳转套件（zhizhu）+ 桌面强制下载套件（dlp-overlay）。
 * 纯静态评分函数，状态由调用方持有。
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristics } = NS;

  class CloakingKit {
    /** 对脚本 blob 评分，命中 zhizhu 套件返回 ≥10。 */
    static scoreCloakingKitBlob(b) {
      if (!b || b.length < 80) return 0;
      let score = 0;
      let hardKit = false;
      if (/zhizhu(?:_main_domain|_processed|_timestamp|Debug)?/i.test(b) || /\[zhizhu\]/i.test(b)) { score += 10; hardKit = true; }
      if (/\bmainDomains\b/.test(b) && /\bprotocol\b\s*:/.test(b)) { score += 5; hardKit = true; }
      if (/\benableAntiDebug\b/.test(b)) score += 2;
      if (/storageKeys/i.test(b) && /(?:zhizhu_)?processed/i.test(b) && /(?:mainDomain|zhizhu_main_domain|timestamp)/i.test(b)) score += 3;
      const hasReferrerGate = /document\.referrer/i.test(b);
      const hasLocReplace = /location\s*\.\s*replace\s*\(/i.test(b);
      if (hasReferrerGate && hasLocReplace) score += 5;
      const no4 = /(?:includes|indexOf)\s*\(\s*['"]4['"]\s*\)/.test(b) && /Math\.(?:random|floor)/i.test(b);
      if (no4 && (hasLocReplace || /\bmainDomains\b/.test(b))) { score += 4; hardKit = true; }
      const mobileFork = /\b(?:mobile|android|iphone|ipad|ipod)\b|ontouchstart|maxTouchPoints/i.test(b);
      const spiderFork = /\b(?:spider|crawler|slurp|baiduspider|googlebot|bingbot|yandexbot|wget\/|curl\/|python-requests)\b/i.test(b);
      if (hasLocReplace && hasReferrerGate && mobileFork && spiderFork) score += 3;
      if (/contextmenu/i.test(b) && /preventDefault/i.test(b) && /\bdebugger\b/.test(b) && /setInterval/i.test(b) && (hasLocReplace || hardKit)) score += 3;
      if (!hardKit && !(hasReferrerGate && hasLocReplace && no4)) score = Math.min(score, 6);
      return score;
    }

    /** 桌面强制下载套件指纹（无域名白名单）：.dlp-overlay / 电脑版推荐 / a+iframe zip 自动下载。 */
    static isDesktopForceDownloadKitBlob(text) {
      const t = String(text || "");
      if (!t || t.length < 30) return false;
      const hasDlpCss = /\.dlp-overlay/i.test(t) && /\.dlp-modal/i.test(t);
      const hasTopbar = /\.dlp-topbar/i.test(t);
      const hasDlpClass = /\bdlp-(?:overlay|modal|topbar)\b/i.test(t);
      const hasPitch = /电脑版推荐|正在为您下载|大屏浏览|功能更完整/i.test(t);
      const hasAutoDl = /triggerDownload|hasTriggered|setTimeout\s*\(\s*show\s*,\s*\d{3,5}/i.test(t)
        || (/createElement\s*\(\s*['"]a['"]\s*\)/i.test(t) && /createElement\s*\(\s*['"]iframe['"]\s*\)/i.test(t) && PackageHeuristics.PACKAGE_EXT.test(t));
      if (hasDlpCss && hasTopbar) return true;
      return (hasDlpCss || hasDlpClass) && (hasPitch || hasAutoDl);
    }

    /** 节点是否为桌面强制下载套件 DOM。 */
    static isDesktopForceDownloadNode(node) {
      if (!node || node.nodeType !== 1) return false;
      try {
        const tag = (node.tagName || "").toLowerCase();
        if (tag === "style") return CloakingKit.isDesktopForceDownloadKitBlob(node.textContent || node.innerHTML || "");
        const cls = `${node.className || ""} ${node.getAttribute && node.getAttribute("class") || ""}`;
        if (/\bdlp-(?:overlay|modal|topbar|btn|badge|close)\b/i.test(cls)) return true;
        if (node.id && /^dlp-/i.test(node.id)) return true;
        if ((tag === "a" || tag === "iframe" || tag === "embed") && node.getAttribute) {
          const href = node.getAttribute("href") || node.getAttribute("src") || "";
          if (href && PackageHeuristics.isPackageFileUrl(href) && !PackageHeuristics.isStrongProductInstallerUrl(href)) {
            const st = (node.getAttribute("style") || "") + (node.style && node.style.cssText || "");
            if (/display\s*:\s*none/i.test(st) || (node.style && node.style.display === "none")) return true;
          }
        }
        const text = (node.textContent || "").slice(0, 400);
        if (/电脑版推荐|正在为您下载[\s\S]{0,40}电脑版/i.test(text)
          && (node.querySelector && node.querySelector("a[href*='.zip'], a[href*='.exe'], .dlp-btn"))) return true;
      } catch { /* ignore */ }
      return false;
    }
  }

  NS.CloakingKit = CloakingKit;
})(window.SilverfoxPageHooks ??= {});
