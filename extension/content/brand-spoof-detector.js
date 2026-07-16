/**
 * 品牌仿冒下载门户检测：标题宣称官网 + 域名与品牌不匹配 + 可疑安装包/下载入口。
 * 软仿冒（pad/typo/hyphen）须等 ICP 定论后再 toast，避免 todeskai 沪ICP 误报。
 */
;(function (NS) {
  "use strict";

  NS.detectBrandSpoofDownloadPortal = function () {
    try {
      const state = NS.state;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
      try {
        const hostRoot = NS.brandRootKeyFromHost(location.hostname);
        const titleToks = NS.extractLatinBrandTokens(`${document.title || ""} ${typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(600) : ""}`);
        if (hostRoot.length >= 4 && titleToks.some((t) => t === hostRoot || (t.length >= 4 && (hostRoot.includes(t) || t.includes(hostRoot))))) {
          const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          if (/^(wiki|docs?|help|manual|handbook|bbs|forum|forums|community|git|code|pkg|packages|aur)$/i.test(lab0) || hostRoot.length >= 6) return false;
        }
      } catch { /* ignore */ }
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit) { state._pendingSoftBrandSpoof = false; return false; }
      if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()) return false;
      if (NS.looksLikeLongLivedWhoisDomain()) {
        try {
          const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          const claim = `${document.title || ""} ${typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(800) : ""}`.toLowerCase();
          if (lab.length >= 4 && claim.includes(lab)) return false;
        } catch { /* ignore */ }
      }
      const titleHostCorrEarly = NS.evaluateTitleHostBrandCorrelation();
      const isPadSquat = titleHostCorrEarly.hostMatch === "padded" || titleHostCorrEarly.hostMatch === "typo" || titleHostCorrEarly.hostMatch === "hyphen";
      if (!isPadSquat && (NS.looksLikeMatureOfficialPortal() || NS.shouldNeverArmProtection() || NS.looksLikeSafeOfficialContext())) return false;
      if (isPadSquat && NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected) return false;
      if (titleHostCorrEarly.rigorousMatch || titleHostCorrEarly.hostMatch === "exact") return false;
      if (titleHostCorrEarly.brandToken && /^(lists?|issues?|code|files?|docs?|help|about|blog|news|pull|requests?|settings?|explore|topics?|stars?|forks?|actions?|security|projects?|wiki|people|teams?|marketplace|sponsors?|notifications?|collections?|templates?|examples?|getting|started|quickstart|guides?|tutorial|reference|api|sdk|cli|apps?|web|mobile|desktop|community|learn|changelog|status|careers|contact|terms|license|readme)$/i.test(titleHostCorrEarly.brandToken)) return false;
      if (titleHostCorrEarly.brandToken && NS.BRAND_TOKEN_STOP_RE.test(titleHostCorrEarly.brandToken)) {
        const labFix = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const fixed = NS.pickBrandTokenForHost(NS.extractLatinBrandTokens(`${document.title || ""} ${typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(800) : ""}`), labFix);
        if (!fixed) return false;
        titleHostCorrEarly.brandToken = fixed;
        titleHostCorrEarly.brandHits = Math.max(titleHostCorrEarly.brandHits || 0, 10);
        if (NS.hostLabelIsBrandTypo(labFix.replace(/-/g, ""), fixed)) titleHostCorrEarly.hostMatch = "typo";
        else if (NS.hostLabelIsPaddedBrand(labFix.replace(/-/g, ""), fixed)) titleHostCorrEarly.hostMatch = "padded";
        titleHostCorrEarly.mismatch = titleHostCorrEarly.hostMatch === "typo" || titleHostCorrEarly.hostMatch === "padded" || titleHostCorrEarly.hostMatch === "hyphen" || titleHostCorrEarly.hostMatch === "none";
      }

      const { brandSource, claimsOfficial, tokens } = NS.getClaimedBrandContext();
      const officialPitch = claimsOfficial || NS.pageClaimsOfficialDownload() || NS.pageClaimsBrandDownloadLanding() || /官方下载|全平台官方|官方客户端|客户端下载|官方网站|客户端完全免费|开始使用|远程桌面|电脑版官网|免费下载_官方|官方桌面/i.test(brandSource);
      if (!officialPitch && tokens.size === 0) return false;

      const titleHostCorr = titleHostCorrEarly;
      if (titleHostCorr.hostMatch === "serp") return false;
      if ((titleHostCorr.rigorousMatch || titleHostCorr.hostMatch === "exact") && titleHostCorr.hostMatch !== "padded" && titleHostCorr.hostMatch !== "typo" && titleHostCorr.hostMatch !== "hyphen") return false;

      const offsitePkgs = NS.findSuspiciousOffsitePackagesInPage();
      const hasBrandMismatchPkg = offsitePkgs.some((p) => NS.packageMismatchesPageBrand(p) || NS.looksLikeHiddenPackagePath(p));

      if (!titleHostCorr.mismatch && !hasBrandMismatchPkg && titleHostCorr.hostMatch !== "hyphen" && titleHostCorr.hostMatch !== "padded" && titleHostCorr.hostMatch !== "typo") {
        if (NS.looksLikeSelfConsistentOfficialSite()) return false;
        if (NS.looksLikeOfficialBrandDownloadPage()) return false;
      }

      const spoofHost = NS.hostLooksLikeBrandMarketingSpoof() || titleHostCorr.mismatch || titleHostCorr.hostMatch === "padded" || titleHostCorr.hostMatch === "typo" || titleHostCorr.hostMatch === "hyphen";
      const downloadCtAs = Array.from(document.querySelectorAll("a[href], a[data-href], a[data-url], button, [role='button'], [onclick], .btn-p, .btn-g, .nav-cta, .btn-download")).filter((el) => {
        const href = NS.getElementDownloadHref(el) || el.getAttribute("href") || "";
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        return NS.DOWNLOAD_TEXT.test(text) || /立即下载|免费下载|Windows\s*版|查看其他平台|下载中心/i.test(text) || /download\.php|\/download/i.test(href) || NS.isPackageFileUrl(href) || /^download/i.test((href.split("/").pop() || "")) || /startDownload\s*\(|openDownloadModal/i.test(el.getAttribute("onclick") || "");
      });

      const htmlSliceEarly = NS.getHtmlSlice(80000);
      const cloudDriveQrOnly = /夸克|百度网盘|扫码.*下载|二维码/i.test(htmlSliceEarly) && /modal|qr-grid|qr-item|openDownloadModal/i.test(htmlSliceEarly) && NS.countTransparentProductPackages(htmlSliceEarly) === 0;

      const hasBareDownloadPhp = downloadCtAs.some((el) => {
        try {
          const h = NS.getElementDownloadHref(el) || el.getAttribute("href") || "";
          if (!h) return false;
          const u = new URL(h, location.href);
          const base = (u.pathname.split("/").pop() || "").toLowerCase();
          return /^(?:download|down|getdown)\.(?:php|asp|aspx)$/i.test(base);
        } catch { return false; }
      });

      const htmlSlice = htmlSliceEarly;
      const seoTemplate = /seo[_-]?templates?/i.test(htmlSlice);
      const hasDownloadHub = downloadCtAs.some((el) => { const h = (el.getAttribute("href") || "").toLowerCase(); return /download\.html|\/download\/?$|download\.php/i.test(h); }) || /download\.html/i.test(location.pathname);

      const hostSquat = titleHostCorr.hostMatch === "typo" || titleHostCorr.hostMatch === "padded" || titleHostCorr.hostMatch === "hyphen";
      const hostUnrelated = titleHostCorr.hostMatch === "none" || titleHostCorr.hostMatch === "partial";
      const titleBrandSpoof = titleHostCorr.mismatch && officialPitch && !!titleHostCorr.brandToken && (hostSquat || hasBrandMismatchPkg || offsitePkgs.length >= 1 || hasBareDownloadPhp || cloudDriveQrOnly || (hostUnrelated && (hasDownloadHub || downloadCtAs.length >= 1)));

      if (!spoofHost && !seoTemplate && !titleBrandSpoof && !hasBrandMismatchPkg) {
        if (!(officialPitch && offsitePkgs.length >= 1 && downloadCtAs.length >= 1)) return false;
      } else if (!(offsitePkgs.length >= 1 || hasBareDownloadPhp || downloadCtAs.length >= 1 || hasDownloadHub || titleBrandSpoof || hasBrandMismatchPkg || cloudDriveQrOnly)) {
        if (!(spoofHost && officialPitch && tokens.size >= 1 && (hostSquat || seoTemplate))) return false;
      }

      if (!officialPitch && offsitePkgs.length === 0 && !titleBrandSpoof && !hasBrandMismatchPkg) return false;

      const hardKitEvidence = seoTemplate || hasBrandMismatchPkg || offsitePkgs.some((p) => NS.isPackageFileUrl(p) && (NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(p)) || NS.looksLikeObjectStoragePackageUrl(p) || NS.looksLikeHighRiskBlobPackageUrl(p)));
      const softOnlyIdentity = (hostSquat || titleBrandSpoof) && !hardKitEvidence;
      if (softOnlyIdentity && !NS.hasValidIcpRecord() && !NS.icpSettledForSoftBrandSpoof()) { state._pendingSoftBrandSpoof = true; return false; }
      if (softOnlyIdentity && !NS.hasValidIcpRecord() && state._icpQueryFailed && !state._icpQuerySettled) { state._pendingSoftBrandSpoof = true; return false; }

      let brandPick = titleHostCorr.brandToken || "";
      if (!brandPick || NS.BRAND_TOKEN_STOP_RE.test(brandPick)) {
        const labDisp = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        brandPick = NS.pickBrandTokenForHost([...tokens].filter((t) => /^[a-z]{3,}$/i.test(t)), labDisp) || [...tokens].find((t) => /^[a-z]{4,}$/i.test(t) && !NS.BRAND_TOKEN_STOP_RE.test(t)) || "";
      }
      const brandDisp = NS.formatBrandTokenForDisplay(brandPick);
      state.spoofBrand = brandDisp || state.spoofBrand || "";

      const reasons = [];
      if (titleHostCorr.mismatch && titleHostCorr.brandToken) {
        const matchHint = titleHostCorr.hostMatch === "typo" ? "拼写仿冒" : titleHostCorr.hostMatch === "padded" ? "域名夹带品牌前缀/后缀" : titleHostCorr.hostMatch === "hyphen" ? "域名用连字符拆分品牌名" : titleHostCorr.hostMatch === "none" ? "域名与品牌无关" : "关联不严谨";
        reasons.push(`标题/正文品牌「${brandDisp || titleHostCorr.brandToken}」出现约 ${titleHostCorr.brandHits} 次，与域名 ${location.hostname} 不匹配（${matchHint}）`);
      }
      if (cloudDriveQrOnly && hostSquat) reasons.push("下载仅引导网盘/扫码，无透明官方安装包直链");
      if (spoofHost || seoTemplate) { if (!titleHostCorr.mismatch) reasons.push("域名呈品牌拼写仿冒/营销站特征"); }
      if (offsitePkgs.length) {
        const sample = offsitePkgs[0];
        const label = NS.formatPackageLabel(sample);
        if (NS.packageMismatchesPageBrand(sample)) reasons.push(`安装包文件名与页面品牌不一致: ${label}`);
        else if (NS.looksLikeHiddenPackagePath(sample)) reasons.push(`隐蔽路径安装包: ${label}`);
        else reasons.push(`异常安装包: ${label}`);
      }
      if (hasBareDownloadPhp) reasons.push("下载入口指向 download.php 中转");
      const signalDetail = reasons.join("；") || (brandDisp ? `页面宣称「${brandDisp}」官网下载，但域名 ${location.hostname} 与品牌不一致` : "页面宣称官网下载，但域名与品牌/分发链异常");

      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !hardKitEvidence) { state._pendingSoftBrandSpoof = false; return false; }

      NS.addSignal("仿冒品牌官网下载站", 24, signalDetail);
      for (const p of offsitePkgs.slice(0, 5)) { if (p && NS.isPackageFileUrl(p) && !state.protectedTargets.includes(p)) state.protectedTargets.push(p); }
      const pkgHref = offsitePkgs.find((p) => NS.isPackageFileUrl(p)) || "";
      const noticeTitle = brandDisp ? `已识别仿冒「${brandDisp}」官网` : "已识别仿冒品牌官网";
      const noticeMsg = brandDisp ? `域名 ${location.hostname} 与标题品牌「${brandDisp}」不匹配，疑似仿冒官网下载站` : `域名 ${location.hostname} 与页面宣称品牌不匹配，疑似仿冒官网下载站`;
      NS.installDownloadGuard(brandDisp ? `仿冒品牌官网下载站（仿冒「${brandDisp}」）` : "仿冒品牌官网下载站", { notify: true, href: pkgHref, message: noticeMsg, title: noticeTitle, guardKind: "brand-spoof", forceNotify: true });
      NS.disableAllDownloadIntentControls();
      state._pendingSoftBrandSpoof = false;
      return true;
    } catch { return false; }
  };

  /** 探测同域下载落地页是否包含远程配置解析 + 动态触发下载链路。 */
  NS.detectLinkedLandingPageSources = async function () {
    if (NS.isBenignContentPage() || NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return;
    const candidates = Array.from(document.querySelectorAll("a[href], button, [role='button'], .download-btn, .btn"))
      .map((el) => ({ href: (el.getAttribute("href") || el.getAttribute("data-href") || "").trim(), text: (el.textContent || "").trim().slice(0, 120) }))
      .filter((item) => item.href && NS.looksLikeSameOriginLandingPageUrl(item.href) && /下载|download|安装|客户端下载|官方下载|立即下载|免费|最新版/i.test(item.text))
      .slice(0, 5);
    if (candidates.length === 0) return;
    const checkPage = async (href) => {
      try {
        const { chain, finalText: source } = await NS.fetchWithRedirectChain(href, 5);
        if (!source) return false;
        const remoteSetupFetchPattern = /fetch\s*\(\s*[^)]*\.(?:txt|json|php)/i.test(source) || /(?:const|let|var)\s+\w*(?:REMOTE_)?(?:SETUP|CONFIG|VERSION|PACKAGE)_?URL\s*=/i.test(source) || /(?:const|let|var)\s+\w+_URL\s*=\s*["'`][^"'`\n]+\.(?:txt|json|php)/i.test(source);
        const autoDownloadDispatchPattern = /createElement\(["']a["']\)|\.click\(\)|triggerDownload|location\.href\s*=|history\.back\(\)/i.test(source);
        const remoteDownloadUrlPattern = /https?:\/\/[^"']+\.(?:zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|"|')/i.test(source);
        const landingDownloadKeywords = (source.match(/下载|download|立即下载|免费下载|官方下载|客户端下载|官方|最新版|安装|安装包/i) || []).length;
        const externalScriptSources = Array.from(source.matchAll(/<script[^>]+src=["'](https?:\/\/[^"']+)["']/gi)).map((m) => m[1]);
        const suspiciousScriptSources = externalScriptSources.filter((src) => /(?:analytics|tracker|beacon|pixel|stat|collect|cdn|sdk)/i.test(src)).length;
        const suspiciousLandingPage = landingDownloadKeywords >= 6 && (externalScriptSources.length >= 2 || suspiciousScriptSources >= 1) && /下载|download|install|setup/i.test(source);
        const usesRemoteJsWithAttr = /<script[^>]+src=["']https?:\/\/[^"']+\?attr=/i.test(source);
        const redirectCount = chain.length - 1;
        const hasRedirectChain = redirectCount >= 2 || /http-equiv=["']refresh["']/i.test(source);
        return ((remoteSetupFetchPattern && autoDownloadDispatchPattern && (remoteDownloadUrlPattern || /\.txt/i.test(source))) || suspiciousLandingPage || usesRemoteJsWithAttr) && (hasRedirectChain || redirectCount > 0);
      } catch { return false; }
    };
    const results = await Promise.all(candidates.map((c) => checkPage(c.href)));
    if (results.some(Boolean)) {
      const reason = "按钮指向的同域下载落地页源码包含远程配置解析并动态触发下载的链路";
      NS.addSignal("同域下载落地页远程链", 14, reason);
      NS.installDownloadGuard(reason);
    }
  };
})(window.SilverfoxContent ??= {});
