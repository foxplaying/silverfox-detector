/**
 * 主威胁检测器：SEO 套件 / IndexNow 模板 / 多平台 SERP 陷阱 / 品牌仿冒 /
 * 加密 SPA / 克隆页 / 远程乱码包 / 桌面强制下载套件 / 落地页仿冒。
 */
;(function (NS) {
  "use strict";

  NS.scoreSeoCloakingRedirectKit = function (blob) {
    const b = String(blob || "");
    if (b.length < 80) return { score: 0, reasons: [], hardKit: false };
    let score = 0;
    const reasons = [];
    let hardKit = false;
    if (/zhizhu(?:_main_domain|_processed|_timestamp|Debug)?/i.test(b) || /\[zhizhu\]/i.test(b)) { score += 10; reasons.push("kit-id"); hardKit = true; }
    if (/\bmainDomains\b/.test(b) && /\bprotocol\b\s*:/.test(b)) { score += 5; reasons.push("mainDomains+protocol"); hardKit = true; }
    if (/\benableAntiDebug\b/.test(b)) { score += 2; reasons.push("enableAntiDebug"); }
    if (/storageKeys/i.test(b) && /(?:zhizhu_)?processed/i.test(b) && /(?:mainDomain|main_domain|zhizhu_main_domain|timestamp)/i.test(b)) { score += 3; reasons.push("storageKeys"); }
    const hasReferrerGate = /document\.referrer/i.test(b);
    const hasLocReplace = /location\s*\.\s*replace\s*\(/i.test(b);
    if (hasReferrerGate && hasLocReplace) { score += 5; reasons.push("referrer->location.replace"); }
    const randomNoFour = /(?:includes|indexOf)\s*\(\s*['"]4['"]\s*\)/.test(b) && /Math\.(?:random|floor)/i.test(b);
    if (randomNoFour && (hasLocReplace || /\bmainDomains\b/.test(b))) { score += 4; reasons.push("randomSub-no4"); hardKit = true; }
    const mobileFork = /\b(?:mobile|android|iphone|ipad|ipod|iemobile|blackberry|webos)\b|ontouchstart|maxTouchPoints/i.test(b);
    const spiderFork = /\b(?:spider|crawler|slurp|baiduspider|googlebot|bingbot|yandexbot|duckduckbot|facebookexternalhit|wget\/|curl\/|python-requests)\b/i.test(b);
    if (hasLocReplace && hasReferrerGate && mobileFork && spiderFork) { score += 3; reasons.push("mobile+spider+redirect"); }
    const antiCtx = /contextmenu/i.test(b) && /preventDefault/i.test(b);
    const antiDbg = /\bdebugger\b/.test(b) && /setInterval/i.test(b);
    if (antiCtx && antiDbg && (hasLocReplace || hardKit)) { score += 3; reasons.push("antiDebug-stack"); }
    if (/localStorage/i.test(b) && /setItem|getItem/i.test(b) && /Date\.now|getTime/i.test(b) && hasLocReplace && hasReferrerGate) { score += 2; reasons.push("ls-domain-rotate"); }
    if (!hardKit && !(hasReferrerGate && hasLocReplace && randomNoFour)) score = Math.min(score, 6);
    return { score, reasons, hardKit };
  };

  NS.detectSeoCloakingRedirectKit = function () {
    try {
      const state = NS.state;
      if (state._seoCloakKitDetected) return true;
      if (NS.pageLooksLikeLegitimateOfficialDownload()) return false;
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i) || "";
          if (/^zhizhu[_-]/i.test(k) || /zhizhu_(?:main_domain|processed|timestamp)/i.test(k)) {
            state._seoCloakKitDetected = true;
            NS.addSignal("SEO伪装跳转脚本", 24, `localStorage 键: ${k}`);
            NS.installDownloadGuard("检测到 SEO 伪装跳转套件 (storage)", { notify: true, message: "SEO伪装跳转", forceNotify: true });
            NS.postToHooks({ type: "set-guard", enabled: true });
            NS.armBackgroundProtect("full");
            return true;
          }
        }
      } catch { /* ignore */ }
      try {
        if (typeof window.zhizhuDebug === "object" && window.zhizhuDebug) {
          state._seoCloakKitDetected = true;
          NS.addSignal("SEO伪装跳转脚本", 24, "window.zhizhuDebug 调试接口");
          NS.installDownloadGuard("检测到 SEO 伪装跳转套件 (debug API)", { notify: true, message: "SEO伪装跳转", forceNotify: true });
          NS.postToHooks({ type: "set-guard", enabled: true });
          NS.armBackgroundProtect("full");
          return true;
        }
      } catch { /* ignore */ }
      let blob = "";
      try {
        for (const s of Array.from(document.scripts || [])) { const t = s.textContent || ""; if (t.length >= 80) blob += `${t}\n`; if (blob.length > 400000) break; }
      } catch { blob = NS.collectPageScriptScanBlob(200000); }
      const { score, reasons, hardKit } = NS.scoreSeoCloakingRedirectKit(blob);
      if (score < 10 && !hardKit) return false;
      if (score < 8) return false;
      if (NS.pageLooksLikeLegitimateOfficialDownload()) return false;
      state._seoCloakKitDetected = true;
      NS.addSignal("SEO伪装跳转脚本", 24, `命中伪装跳转套件逻辑 (score=${score}): ${reasons.join(", ")}`);
      NS.installDownloadGuard("检测到 SEO 伪装跳转套件，已拦截自动跳转", { notify: true, message: "SEO伪装跳转", forceNotify: true });
      NS.postToHooks({ type: "set-guard", enabled: true });
      NS.armBackgroundProtect("full");
      return true;
    } catch { return false; }
  };

  NS.detectIndexNowSeoPhishTemplate = function () {
    try {
      const state = NS.state;
      if (state._indexNowPhishTemplate) return true;
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return false;
      const siteBaseMeta = document.querySelector('meta[name="site-base"]');
      const indexNowMeta = document.querySelector('meta[name="indexnow-key"]');
      if (!siteBaseMeta || !indexNowMeta) return false;
      const key = String(indexNowMeta.getAttribute("content") || "").trim();
      if (key.length < 16 || !/^[a-f0-9]{16,64}$/i.test(key)) return false;
      let blob = "";
      try { for (const s of Array.from(document.scripts || [])) { const t = s.textContent || ""; if (t.length >= 40) blob += `${t}\n`; if (blob.length > 200000) break; } } catch { blob = NS.collectPageScriptScanBlob(120000); }
      try { blob += `\n${NS.getThreatScanHtml(80000)}`; } catch { /* ignore */ }
      const hasPingFn = /function\s+pingIndexNow\s*\(|pingIndexNow\s*=\s*function/i.test(blob);
      const hasIndexNowApi = /api\.indexnow\.org\/indexnow/i.test(blob);
      const hasBingIndexNow = /www\.bing\.com\/indexnow/i.test(blob);
      const hasKeyLocation = /keyLocation\s*:/i.test(blob) && (/key\s*\+\s*['"]\.txt['"]/i.test(blob) || /['"]\/['"]\s*\+\s*key\s*\+\s*['"]\.txt['"]/i.test(blob));
      const hasIdlePing = /requestIdleCallback\s*\(\s*pingIndexNow/i.test(blob) || (/requestIdleCallback/i.test(blob) && /timeout\s*:\s*3000/i.test(blob) && hasPingFn);
      const hasMojibakeComment = /蹇呭簲\s*IndexNow|IndexNow\s*蹇|閮ㄧ讲鍚庣敓鏁/i.test(blob);
      let kitScore = 0;
      if (hasPingFn) kitScore += 3;
      if (hasIndexNowApi) kitScore += 3;
      if (hasBingIndexNow) kitScore += 2;
      if (hasKeyLocation) kitScore += 3;
      if (hasIdlePing) kitScore += 2;
      if (hasMojibakeComment) kitScore += 2;
      if (hasIndexNowApi && hasBingIndexNow && hasPingFn) kitScore += 2;
      if (kitScore < 8) return false;
      const title = document.title || "";
      const textHead = ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, 4000);
      const downloadCtx = NS.pageClaimsOfficialDownload() || /下载中心|全平台|官方下载|免费下载|客户端下载|安装包/i.test(`${title} ${textHead}`) || (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) || document.querySelectorAll(".platform-btn, button.platform-btn, [class*='platform']").length >= 3 || (typeof NS.collectAllPagePackageHrefs === "function" && NS.collectAllPagePackageHrefs().length >= 1) || (/Windows|macOS|Linux|Android|iOS/i.test(textHead) && /下载|download/i.test(`${title} ${textHead}`));
      if (!downloadCtx) return false;
      state._indexNowPhishTemplate = true;
      state._seoCloakKitDetected = true;
      NS.addSignal("SEO收录仿冒模板", 20, `量产 IndexNow SEO 模板 (site-base + indexnow-key + pingIndexNow, score=${kitScore})`);
      let pkgTarget = "";
      try { const pkgs = NS.collectAllPagePackageHrefs(); pkgTarget = pkgs[0] || ""; } catch { /* ignore */ }
      if (pkgTarget && !state.protectedTargets.includes(pkgTarget)) state.protectedTargets.push(pkgTarget);
      NS.installDownloadGuard("检测到量产 SEO 仿冒下载站模板 (IndexNow kit)", { notify: true, href: pkgTarget || "", message: pkgTarget ? NS.formatPackageLabel(pkgTarget) : "SEO仿冒下载模板", forceNotify: true });
      NS.postToHooks({ type: "set-guard", enabled: true });
      NS.armBackgroundProtect("full");
      NS.disableAllDownloadIntentControls();
      return true;
    } catch { return false; }
  };

  NS.detectMultiPlatformSerpDownloadTrap = function () {
    try {
      const state = NS.state;
      if (state._multiPlatformSerpTrap) return true;
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return false;
      const { claimsOfficial, tokens } = NS.getClaimedBrandContext();
      const officialPitch = claimsOfficial || NS.pageClaimsOfficialDownload();
      if (!officialPitch && tokens.size === 0) return false;
      let blob = "";
      try { for (const s of Array.from(document.scripts || [])) { const t = s.textContent || ""; if (t.length >= 30) blob += `${t}\n`; if (blob.length > 150000) break; } } catch { blob = NS.collectPageScriptScanBlob(120000); }
      try { blob += `\n${NS.getThreatScanHtml(60000)}`; } catch { /* ignore */ }
      const hasStartDownload = /function\s+startDownload\s*\(\s*platform\s*\)/i.test(blob) && /downloadUrls\s*\[\s*platform\s*\]/i.test(blob);
      const mapMatch = blob.match(/(?:const|let|var)\s+downloadUrls\s*=\s*\{([\s\S]{10,1200}?)\}/);
      if (!mapMatch && !hasStartDownload) return false;
      const mapBody = mapMatch ? mapMatch[1] : blob;
      const platformKeys = (mapBody.match(/\b(?:windows|mac|macos|linux|android|ios|win|osx)\b/gi) || []).length;
      const urls = (mapBody.match(/https?:\/\/[^\s"'\\]+/gi) || []).map((u) => u.replace(/[),;]+$/, ""));
      if (urls.length < 2 && platformKeys < 2) return false;
      const absList = [];
      for (const raw of urls) { try { absList.push(new URL(raw, location.href).href); } catch { absList.push(raw); } }
      if (absList.length < 2) return false;
      const unique = [...new Set(absList)];
      const serpHits = absList.filter((u) => NS.looksLikeSearchEngineLandingUrl(u)).length;
      const allSame = unique.length === 1;
      const allSerp = serpHits >= 2 && serpHits === absList.length;
      const sameSerp = allSame && NS.looksLikeSearchEngineLandingUrl(unique[0]);
      const multiSameExternal = allSame && platformKeys >= 3 && !NS.isPackageFileUrl(unique[0]);
      if (!(sameSerp || allSerp || (hasStartDownload && multiSameExternal) || (platformKeys >= 3 && multiSameExternal && officialPitch))) return false;
      const spoofHost = NS.hostLooksLikeBrandMarketingSpoof();
      if (!spoofHost && !officialPitch) return false;
      state._multiPlatformSerpTrap = true;
      const sample = unique[0] || absList[0] || "";
      let hostLabel = sample;
      try { hostLabel = new URL(sample).hostname.replace(/^www\./, ""); } catch { /* keep */ }
      NS.addSignal("多平台下载指向搜索引擎", 18, `多平台下载入口（Windows/macOS/Linux 等）统一跳转搜索引擎/非安装包地址（${hostLabel || "外链"}），非真实安装包`);
      NS.installDownloadGuard("多平台下载跳转搜索引擎（非安装包）", { notify: true, href: "", message: `多平台下载按钮跳转搜索引擎（${hostLabel || "外链"}），不是安装包`, title: "已拦截异常下载跳转", guardKind: "nav-trap", forceNotify: true });
      NS.postToHooks({ type: "set-guard", enabled: true });
      NS.armBackgroundProtect("full");
      NS.disableAllDownloadIntentControls();
      return true;
    } catch { return false; }
  };

  NS.findSuspiciousOffsitePackagesInPage = function () {
    const out = [];
    const seen = new Set();
    const push = (raw) => {
      if (!raw || seen.has(raw)) return;
      try { const abs = new URL(raw, location.href).href; if (seen.has(abs)) return; seen.add(raw); seen.add(abs); out.push(abs); } catch { seen.add(raw); out.push(raw); }
    };
    try {
      const html = NS.getHtmlSlice(120000);
      const pageApex = NS.getRegistrableDomain(location.hostname);
      const reAbs = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|rar|7z)(?:\?[^\s"'<>\\]*)?/gi;
      let m;
      while ((m = reAbs.exec(html)) !== null) {
        const raw = m[0];
        try {
          const u = new URL(raw);
          const apex = NS.getRegistrableDomain(u.hostname);
          const fn = NS.getFilenameFromUrl(raw);
          const publicOss = NS.hostLooksLikePublicObjectStorageEndpoint(u.hostname);
          const oversimple = NS.looksLikeOversimplifiedBrandInstallerName(fn);
          const strongProd = NS.looksLikeStrongProductInstallerName(fn);
          if (strongProd && NS.packageFilenameSharesPageBrand(fn)) continue;
          const sameOrigin = pageApex && apex === pageApex;
          if (NS.packageMismatchesPageBrand(raw) || NS.looksLikeHiddenPackagePath(raw) || NS.looksLikeBrandNearMissPackageName(fn)) { push(raw); continue; }
          if (sameOrigin) continue;
          if (strongProd) continue;
          const clearish = NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(raw) || NS.looksLikeProductPackageName(fn) || NS.isBenignShortInstallerName(fn);
          if (clearish) { const threatClear = NS.looksLikeHighRiskBlobPackageUrl(raw) || NS.looksLikeObjectStoragePackageUrl(raw) || (publicOss && oversimple); if (!threatClear) continue; }
          if (NS.isSuspiciousDownloadFilename(fn) || NS.packageMismatchesPageBrand(raw) || NS.looksLikeRandomDownloadHost(u.hostname) || NS.looksLikeObjectStoragePackageUrl(raw) || (publicOss && oversimple)) push(raw);
        } catch { /* ignore */ }
      }
      const reRel = /["'(=\s](\/?[A-Za-z0-9._/-]{3,120}\.(?:zip|exe|apk|msi|dmg|rar|7z))(?:\?[^"'>\s]*)?["')\s>]/gi;
      while ((m = reRel.exec(html)) !== null) {
        const raw = m[1];
        if (!raw || /^https?:/i.test(raw)) continue;
        try {
          const abs = new URL(raw, location.href).href;
          const fn = NS.getFilenameFromUrl(abs);
          if (NS.looksLikeStrongProductInstallerName(fn) && NS.packageFilenameSharesPageBrand(fn)) continue;
          if (NS.packageMismatchesPageBrand(abs) || NS.looksLikeHiddenPackagePath(abs) || NS.looksLikeBrandNearMissPackageName(fn) || NS.isSuspiciousDownloadFilename(fn)) push(abs);
        } catch { /* ignore */ }
      }
      try {
        NS.collectAllPagePackageHrefs().forEach((href) => {
          const fn = NS.getFilenameFromUrl(href);
          if (NS.looksLikeStrongProductInstallerName(fn) && NS.packageFilenameSharesPageBrand(fn)) return;
          if (NS.packageMismatchesPageBrand(href) || NS.looksLikeHiddenPackagePath(href) || NS.looksLikeBrandNearMissPackageName(fn) || NS.isSuspiciousDownloadFilename(fn)) push(href);
        });
      } catch { /* ignore */ }
    } catch { /* ignore */ }
    return out;
  };

  // 其余大型检测器（detectBrandSpoofDownloadPortal / detectFakeOfficialDownloadSpa /
  // detectClonedOfficialDownloadPage / detectBrandResourceDomainMismatch /
  // detectRemoteGarblePackageDispatch / detectDesktopForceDownloadKit / detectFakeBrandDownloadShell /
  // detectRemoteDownloadApiBinding / detectAntiAnalysisBehavior / 落地页系列）见 detectors-extended.js
})(window.SilverfoxContent ??= {});
