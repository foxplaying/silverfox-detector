/**
 * SEO 伪装跳转套件（zhizhu 类）指纹扫描。
 * 持有 cloakingKit / kitScanAt 状态，供 NavBlocker 在拦截决策前复用。
 */
;(function (NS) {
  "use strict";

  const { PageShellDetector } = NS;

  class CloakingKitScanner {
    constructor(post) {
      this.cloakingKit = false;
      this.kitScanAt = 0;
      this.post = post; // (msg) => void
    }

    /** 对脚本 blob 评分：命中 zhizhu 套件指纹返回高分。 */
    scoreCloakingKitBlob(b) {
      if (!b || b.length < 80) return 0;
      let score = 0;
      let hardKit = false;
      if (/zhizhu(?:_main_domain|_processed|_timestamp|Debug)?/i.test(b) || /\[zhizhu\]/i.test(b)) {
        score += 10;
        hardKit = true;
      }
      if (/\bmainDomains\b/.test(b) && /\bprotocol\b\s*:/.test(b)) {
        score += 5;
        hardKit = true;
      }
      if (/\benableAntiDebug\b/.test(b)) score += 2;
      if (/storageKeys/i.test(b) && /(?:zhizhu_)?processed/i.test(b)
        && /(?:mainDomain|zhizhu_main_domain|timestamp)/i.test(b)) score += 3;
      const hasReferrerGate = /document\.referrer/i.test(b);
      const hasLocReplace = /location\s*\.\s*replace\s*\(/i.test(b);
      if (hasReferrerGate && hasLocReplace) score += 5;
      const no4 = /(?:includes|indexOf)\s*\(\s*['"]4['"]\s*\)/.test(b) && /Math\.(?:random|floor)/i.test(b);
      if (no4 && (hasLocReplace || /\bmainDomains\b/.test(b))) {
        score += 4;
        hardKit = true;
      }
      const mobileFork = /\b(?:mobile|android|iphone|ipad|ipod)\b|ontouchstart|maxTouchPoints/i.test(b);
      const spiderFork = /\b(?:spider|crawler|slurp|baiduspider|googlebot|bingbot|yandexbot|wget\/|curl\/|python-requests)\b/i.test(b);
      if (hasLocReplace && hasReferrerGate && mobileFork && spiderFork) score += 3;
      if (/contextmenu/i.test(b) && /preventDefault/i.test(b) && /\bdebugger\b/.test(b)
        && /setInterval/i.test(b) && (hasLocReplace || hardKit)) score += 3;
      if (!hardKit && !(hasReferrerGate && hasLocReplace && no4)) {
        score = Math.min(score, 6);
      }
      return score;
    }

    /** 扫描内联脚本与 zhizhuDebug/localStorage；命中后置 cloakingKit 并发 guard/signal。 */
    scanForCloakingKit(force) {
      if (this.cloakingKit) return true;
      if (PageShellDetector.looksLikeSearchPageShape()) return false; // SERP 永不扫描
      if (PageShellDetector.pageLooksLikeOfficialDownloadPayload()) return false;
      const now = Date.now();
      if (!force && now - this.kitScanAt < 250) return this.cloakingKit;
      this.kitScanAt = now;
      try {
        try {
          if (typeof window.zhizhuDebug === "object" && window.zhizhuDebug) {
            this.cloakingKit = true;
            return true;
          }
        } catch { /* ignore */ }
        let blob = "";
        const scripts = document.scripts || [];
        const maxScripts = Math.min(scripts.length, 30);
        for (let i = 0; i < maxScripts && blob.length < 80000; i++) {
          if (scripts[i].src) continue; // 仅内联
          const t = scripts[i].textContent || "";
          if (t.length >= 80) blob += `${t.slice(0, 6000)}\n`;
        }
        if (this.scoreCloakingKitBlob(blob) >= 10) {
          if (PageShellDetector.pageLooksLikeOfficialDownloadPayload()) return false;
          this.cloakingKit = true;
          this.post({ type: "request-guard", reason: "SEO伪装跳转套件(MAIN早期扫描)" });
          this.post({ type: "signal", name: "SEO伪装跳转脚本", weight: 24, reason: "nav-boot kit fingerprint" });
          return true;
        }
      } catch { /* ignore */ }
      return false;
    }
  }

  NS.CloakingKitScanner = CloakingKitScanner;
})(window.SilverfoxNavBoot ??= {});
