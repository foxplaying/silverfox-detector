/**
 * 加密 SPA 下载页延迟复扫：官网 Nuxt 载荷首帧常缺失，需定时重扫直到 hydrate。
 */
;(function (NS) {
  "use strict";

  /** 官网 download landing 可能仍在 hydrate Nuxt 加密配置 / 立即下载按钮。 */
  NS.pageLooksLikePendingEncryptedDownloadSpa = function () {
    try {
      const state = NS.state;
      if (state._fakeSpaDetected || state.downloadGuardInstalled) return false;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (state._intelLightMode || NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()) return false;
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected) return false;

      const title = document.title || "";
      const bodyHead = ((document.body && document.body.textContent) || "").replace(/\s+/g, " ").trim().slice(0, 2500);
      const officialClaim = /官网|官方下载|官方正版|官方网站|官方客户端|全平台官方|电脑版官网/i.test(title)
        || /官网|官方下载|官方正版|官方网站|官方客户端|全平台官方/i.test(bodyHead);

      let nuxtHint = false;
      try {
        nuxtHint = /windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload/i.test(NS.getHtmlSlice(40000))
          || /__NUXT_DATA__|download_uri\s*=/i.test(NS.getHtmlSlice(20000));
      } catch { /* ignore */ }
      if (!officialClaim && !nuxtHint) return false;

      try {
        if (NS.countTransparentProductPackages(NS.getHtmlSlice(40000)) >= 1) return false;
      } catch { /* ignore */ }

      let spaRoot = false;
      try { spaRoot = !!document.querySelector("#__nuxt, #__NUXT__, #__NUXT_DATA__, #app, #root, #__next, [data-v-app]"); } catch { /* ignore */ }
      let dlCta = false;
      try { dlCta = NS.getAllDownloadIntentElements().length >= 1; } catch { /* ignore */ }
      return !!(nuxtHint || (officialClaim && (spaRoot || dlCta)));
    } catch {
      return false;
    }
  };

  /** 官网 SPA 在加密载荷落地前持续分析（或硬 miss）。 */
  NS.shouldDeferAnalysisCompleteForEncryptedSpa = function () {
    try {
      const state = NS.state;
      if (state._fakeSpaDetected || state.downloadGuardInstalled) return false;
      const age = Date.now() - (state._pageBootAt || 0);
      if (age > 8000) return false; // 8s 后放弃等待 hydrate
      return NS.pageLooksLikePendingEncryptedDownloadSpa();
    } catch {
      return false;
    }
  };

  /** 调度强制复扫，使首帧 Nuxt 加密配置 miss 得以恢复。 */
  NS.armEncryptedSpaLateRescan = function () {
    const state = NS.state;
    if (state._encryptedSpaRescanArmed) return;
    if (!NS.pageLooksLikePendingEncryptedDownloadSpa()) return;
    state._encryptedSpaRescanArmed = true;
    state._pendingEncryptedSpa = true;
    [800, 1800, 3200, 5200, 8500].forEach((ms) => {
      setTimeout(() => {
        try {
          if (state._fakeSpaDetected || state.downloadGuardInstalled) { state._pendingEncryptedSpa = false; return; }
          if (!NS.pageLooksLikePendingEncryptedDownloadSpa() && !/官网|官方下载|官方网站/i.test(document.title || "")) {
            state._pendingEncryptedSpa = false;
            if (!state._analysisDone) NS.markAnalysisComplete("encrypted-spa-gone");
            return;
          }
          NS.invalidateHtmlCache();
          if (state._analysisDone && !state.downloadGuardInstalled) state._analysisDone = false;
          if (NS.runDetector("FakeOfficialDownloadSpa#late", NS.detectFakeOfficialDownloadSpa)) {
            state._fakeSpaDetected = true;
            state._pendingEncryptedSpa = false;
            NS.markAnalysisComplete("encrypted-spa-late");
            NS.emitRiskReport(true);
            return;
          }
          if (!NS.hasValidIcpRecord() && !state._brandSpoofPortalDetected) {
            try {
              if (NS.runDetector("BrandSpoofDownloadPortal#late", NS.detectBrandSpoofDownloadPortal)) {
                state._brandSpoofPortalDetected = true;
                state._pendingEncryptedSpa = false;
                NS.markAnalysisComplete("brand-spoof-late");
                NS.emitRiskReport(true);
                return;
              }
            } catch { /* ignore */ }
          }
          const age = Date.now() - (state._pageBootAt || 0);
          if (age >= 4800 && age < 6000) NS.scanSuspiciousPackagesFast(true);
          if (!state._fakeSpaDetected && !state.downloadGuardInstalled && age >= 8000) {
            state._pendingEncryptedSpa = false;
            if (!state._analysisDone) NS.markAnalysisComplete("encrypted-spa-timeout");
          }
        } catch { /* ignore */ }
      }, ms);
    });
  };
})(window.SilverfoxContent ??= {});
