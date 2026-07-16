/**
 * 扩展检测器：品牌仿冒下载门户 / 品牌资源失配 / 加密 SPA / 克隆页 /
 * 远程乱码包 / 桌面强制下载套件 / 下载壳 / 远程 API / 反调试 / 落地页系列。
 */
;(function (NS) {
  "use strict";

  NS.hasDuplicateDynamicDownloadUriTargets = function () {
    try {
      const els = Array.from(document.querySelectorAll("a.download-uri, .download-uri, [class~='download-uri']"));
      if (els.length >= 2) return true;
      const withHref = Array.from(document.querySelectorAll("a.download-uri[href], a.btn-download[href]"));
      const map = new Map();
      for (const el of withHref) {
        let h = (el.getAttribute("href") || "").trim();
        if (!h || h === "#" || /^javascript:/i.test(h)) continue;
        try { h = new URL(h, location.href).href; } catch { /* keep */ }
        map.set(h, (map.get(h) || 0) + 1);
      }
      for (const n of map.values()) if (n >= 2) return true;
      return false;
    } catch { return false; }
  };

  NS.detectFakeBrandDownloadShell = function () {
    try {
      if (NS.looksLikeSelfConsistentOfficialSite()) return false;
      const fullHtml = NS.getHtmlSlice(100000);
      if (NS.looksLikeOfficialBrandDownloadPage(fullHtml)) return false;
      if (NS.countTransparentProductPackages(fullHtml) >= 1) return false;
      const title = document.title || "";
      const titleOfficial = /官网|官方下载|官方网站|官方正版|官网下载|官方客户端|客户端下载/.test(title);
      if (!titleOfficial) return false;
      // 脚本 + HTML 一起扫（部分模板把 download_uri 写在内联 HTML/事件里）
      let scanBlob = "";
      try {
        scanBlob = NS.collectPageScriptScanBlob(120000) || "";
        const scripts = Array.from(document.scripts || []).map((s) => s.textContent || "").join("\n");
        if (scripts) scanBlob = `${scanBlob}\n${scripts}`.slice(0, 220000);
      } catch { scanBlob = NS.getHtmlSlice(120000) || ""; }
      const dynamicUri = NS.hasDynamicSharedDownloadUriBinding(scanBlob);
      const authorMismatch = NS.hasAuthorBrandHostMismatch();
      const strongAnti = NS.hasStrongAntiAnalysisMarkers(scanBlob);
      const dupDynamic = NS.hasDuplicateDynamicDownloadUriTargets();
      const hasDlShell = document.querySelectorAll(".download-uri, a.download-uri, .btn-download, [class*='btn-download'], .download-btn, #mainDownloadBtn").length >= 1
        || /download-uri|initDownloadLinks|window\.download_uri|download_uri\s*=/i.test(scanBlob);
      // 标题官网 + 下载壳 + download_uri 字样：即使 multiAssign 正则略偏也算壳
      const uriMention = /download_uri|initDownloadLinks/i.test(scanBlob);
      if (!dynamicUri && !authorMismatch && !(hasDlShell && uriMention)) return false;
      if (!dynamicUri && authorMismatch && !strongAnti && !dupDynamic && !uriMention) return false;
      if (!hasDlShell && !dynamicUri && !uriMention) return false;
      const reasons = [];
      if (dynamicUri || (hasDlShell && uriMention)) reasons.push("动态全局 download_uri 绑定多按钮");
      if (authorMismatch) reasons.push("作者品牌域名与当前站点不一致");
      if (strongAnti) reasons.push("禁止右键/F12/debugger 反调试");
      if (dupDynamic) reasons.push("多 download-uri 入口同一目标");
      if (!reasons.length) reasons.push("官网标题 + 动态下载壳");
      const state = NS.state;
      // 必须先于 installDownloadGuard 置位，否则 maybeLift 会因「像官网」在无 ICP 时立刻抬锁恢复按钮
      state._fakeBrandShellDetected = true;
      NS.addSignal("仿冒品牌官网下载壳", 22, `标题宣称官网下载，且存在: ${reasons.join("；")}`);
      if (strongAnti) NS.addSignal("反调试/禁止审查页面", 10, "页面禁止右键/F12 或 debugger 暂停调试，常见于仿冒下载站");
      if (dynamicUri || dupDynamic || (hasDlShell && uriMention)) NS.addSignal("多入口共用动态下载地址", 14, "多个下载按钮写入同一 download_uri/安装包地址");
      const target = (() => {
        try {
          const a = document.querySelector("a.download-uri[href], a.btn-download[href], a.download-btn[href], #mainDownloadBtn[href]");
          return (a && (a.getAttribute("href") || a.href)) || "动态下载地址";
        } catch { return "动态下载地址"; }
      })();
      if (target && !state.protectedTargets.includes(target)) state.protectedTargets.push(target);
      NS.installDownloadGuard(`仿冒品牌官网下载壳: ${reasons[0] || "可疑下载壳"}`, {
        notify: true,
        href: target,
        message: reasons.join("；") || "仿冒品牌官网下载壳",
        title: "已识别仿冒品牌官网下载壳",
        forceNotify: true,
        lockHard: true
      });
      NS.disableAllDownloadIntentControls();
      try { NS.applyDownloadGuardDomLock(true); } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  NS.detectFakeOfficialDownloadSpa = function () {
    try {
      const state = NS.state;
      if (NS.looksLikeSelfConsistentOfficialSite()) return false;
      if (NS.looksLikeMatureOfficialPortal() && NS.countTransparentProductPackages(NS.getThreatScanHtml(60000)) >= 1) return false;
      const title = document.title || "";
      const textHead = ((document.body && document.body.textContent) || "").replace(/\s+/g, " ").trim().slice(0, 5000);
      const html = NS.getThreatScanHtml(180000);
      const hasEncryptedDlConfig = NS.hasEncryptedNuxtDownloadConfig(html);
      const ctx = NS.estimatePageContext();
      const normalContent = NS.looksLikeNormalContent(ctx);
      if (normalContent && !hasEncryptedDlConfig && !/官网|官方下载/i.test(title)) return false;
      const productPkgCount = NS.countTransparentProductPackages(html);
      if (productPkgCount >= 1) return false;
      let liveProductPkgs = 0;
      try {
        const anchors = document.querySelectorAll("a[href]");
        const n = Math.min(anchors.length, 80);
        for (let i = 0; i < n; i++) {
          const h = (anchors[i].getAttribute("href") || "").trim();
          if (!NS.isPackageFileUrl(h) || NS.looksLikeObjectStoragePackageUrl(h)) continue;
          if (NS.looksLikeProductPackageName(NS.getFilenameFromUrl(h))) { liveProductPkgs++; break; }
        }
      } catch { /* ignore */ }
      if (liveProductPkgs >= 1) return false;
      const titleClaimsOfficial = /官网|官方下载|官方正版|官方网站|官方客户端|全平台官方|客户端下载/i.test(title);
      const bodyClaimsOfficial = /官网|官方下载|官方正版|官方网站/i.test(textHead);
      const strongDownloadPitch = (textHead.match(/立即下载|客户端下载|官方下载|免费下载|一键下载|云电脑下载/g) || []).length >= 2;
      const dlBtns = NS.getAllDownloadIntentElements();
      const strongHreflessDlBtns = dlBtns.filter((el) => {
        const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
        const hrefless = el.tagName === "BUTTON" || !href || href === "#" || /^javascript:/i.test(href);
        if (!hrefless) return false;
        const text = `${el.textContent || ""} ${el.getAttribute("aria-label") || ""}`.replace(/\s+/g, " ").trim();
        return /立即下载|免费下载|官方下载|客户端下载|一键下载|云电脑下载|下载客户端|下载中心/.test(text) && text.length < 40;
      }).length;
      const hasDownloadButtons = dlBtns.length >= 1 || strongHreflessDlBtns >= 1;
      const scanBlob = html;
      const strongAnti = NS.hasStrongAntiAnalysisMarkers(scanBlob);
      const weakAnti = NS.hasWeakAntiAnalysisMarkers(scanBlob);
      const downloadPitchText = /下载中心|立即下载|客户端|免费下载|官方下载/i.test(textHead.slice(0, 2500));
      let spaRoot = false;
      try { spaRoot = !!document.querySelector("#__nuxt, #__NUXT__, #__NUXT_DATA__, #app, #root, #__next, [data-v-app]"); } catch { /* ignore */ }
      if (hasEncryptedDlConfig && productPkgCount === 0 && liveProductPkgs === 0 && (titleClaimsOfficial || ((bodyClaimsOfficial || strongDownloadPitch || downloadPitchText) && (hasDownloadButtons || strongHreflessDlBtns >= 1 || spaRoot)))) {
        state._fakeSpaDetected = true;
        state._pendingEncryptedSpa = false;
        NS.addSignal("仿冒官网加密下载配置", 20, "页面宣称官网/下载，但安装包以加密配置下发，且无透明官方安装包链接，常见于仿冒下载站");
        if (strongAnti || weakAnti) NS.addSignal("反调试/禁止审查页面", 10, "页面禁止右键/F12 或跳转 about:blank，常见于仿冒下载站");
        else if (titleClaimsOfficial && (strongHreflessDlBtns >= 1 || hasDownloadButtons)) NS.addSignal("无透明安装包下载入口", 8, "立即下载按钮无透明 .exe/.dmg 链接，配合加密下载配置");
        NS.installDownloadGuard("仿冒官网：加密下发安装包，已禁用下载按钮并拦截本页安装包下载", { notify: true, message: "仿冒官网加密下载", forceNotify: true, title: "已拦截可疑安装包", lockHard: true });
        NS.disableAllDownloadIntentControls();
        return true;
      }
      if (titleClaimsOfficial && strongHreflessDlBtns >= 1 && strongAnti && !normalContent && productPkgCount === 0 && liveProductPkgs === 0) {
        state._fakeSpaDetected = true;
        NS.addSignal("仿冒官网反调试下载页", 18, "页面标题宣称官网，下载按钮无透明安装包链接，并禁止审查/F12->about:blank，常见于仿冒下载站");
        NS.installDownloadGuard("仿冒官网：反调试下载页，已禁用下载按钮", { notify: true, message: "仿冒官网反调试下载", forceNotify: true, lockHard: true });
        NS.disableAllDownloadIntentControls();
        return true;
      }
    } catch { /* ignore */ }
    return false;
  };

  NS.detectClonedOfficialDownloadPage = function () {
    try {
      const state = NS.state;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      const spoofHost = typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof();
      if (!spoofHost) {
        if (NS.looksLikeSelfConsistentOfficialSite()) return false;
        if (NS.looksLikeMatureOfficialPortal()) return false;
        if (NS.looksLikeOfficialBrandDownloadPage() && NS.countTransparentProductPackages(NS.getThreatScanHtml(60000)) >= 1) return false;
        if (typeof NS.isTrustedOfficialDownloadContext === "function" && NS.isTrustedOfficialDownloadContext() && !spoofHost) return false;
      }
      const title = document.title || "";
      const textHead = ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, 6000);
      const hostLowEarly = (location.hostname || "").toLowerCase();
      const wikiLikeHost = /^(wiki|docs?|help|manual|handbook|bbs|forum|forums|community)\./i.test(hostLowEarly) || /\/(wiki|docs?|help|manual)\b/i.test(location.pathname || "");
      const claimsOfficial = /官网|官方下载|官方正版|官方网站|电脑版免费下载|下载中心|全平台官方|官方渠道/.test(`${title} ${textHead}`) || NS.pageClaimsBrandDownloadLanding();
      if (!claimsOfficial) return false;
      if (wikiLikeHost && !/官方下载|官网下载|客户端下载|安装包|立即下载|全平台官方/i.test(`${title} ${textHead.slice(0, 600)}`)) return false;
      const pageApex = NS.guessApexDomain(location.hostname) || NS.getRegistrableDomain(location.hostname);
      const packageHrefs = NS.collectAllPagePackageHrefs();
      const blobPackages = packageHrefs.filter((h) => {
        const fn = NS.getFilenameFromUrl(h);
        if (NS.looksLikeHighRiskBlobPackageUrl(h) || NS.isThreatObjectStoragePackage(h, null)) return true;
        try {
          const uh = new URL(h, location.href).hostname;
          if (NS.isAnonymousPublicObjectHost(uh)) return true;
          if (NS.hostLooksLikePublicObjectStorageEndpoint(uh) && (NS.looksLikeOversimplifiedBrandInstallerName(fn) || !NS.looksLikeStrongProductInstallerName(fn))) {
            if (NS.looksLikeOversimplifiedBrandInstallerName(fn) || NS.looksLikeObjectStoragePackageUrl(h)) return true;
          }
        } catch { /* ignore */ }
        if (NS.looksLikeObjectStoragePackageUrl(h)) return true;
        if (NS.looksLikeBrandNearMissPackageName(fn)) return true;
        if (NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(h) || NS.looksLikeProductPackageName(fn) || NS.isBenignShortInstallerName(fn)) {
          return NS.looksLikeHighRiskBlobPackageUrl(h) || (NS.looksLikeObjectStoragePackageUrl(h) && NS.looksLikeOversimplifiedBrandInstallerName(fn)) || (NS.looksLikeOversimplifiedBrandInstallerName(fn) && (() => { try { return NS.hostLooksLikePublicObjectStorageEndpoint(new URL(h, location.href).hostname); } catch { return false; } })());
        }
        return NS.isSuspiciousDownloadFilename(fn);
      });
      const offsitePackages = packageHrefs.filter((h) => {
        try {
          const u = new URL(h, location.href);
          const pkgApex = NS.guessApexDomain(u.hostname);
          if (!pkgApex || pkgApex === pageApex) return false;
          const fn = NS.getFilenameFromUrl(h);
          if (NS.looksLikeObjectStoragePackageUrl(h) || NS.hostLooksLikePublicObjectStorageEndpoint(u.hostname)) return true;
          if (NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(h) || NS.looksLikeProductPackageName(fn)) return NS.looksLikeHighRiskBlobPackageUrl(h) || NS.looksLikeBrandNearMissPackageName(fn);
          return NS.isSuspiciousDownloadFilename(fn) || NS.looksLikeObjectStoragePackageUrl(h) || NS.looksLikeRandomDownloadHost(u.hostname);
        } catch { return false; }
      });
      let brandAssetHosts = 0;
      const brandHostApexes = new Set();
      // 与 collectBrandResourceMismatch 一致：勿把 soft-static.30405.com 当「盗用品牌资源」
      const titleTokensClone = (typeof NS.extractLatinBrandTokens === "function" ? NS.extractLatinBrandTokens(title) : [])
        .filter((t) => t && t.length >= 4 && !/^(soft|china|download|windows|software|client|official|free)$/i.test(t));
      if (titleTokensClone.length) {
        document.querySelectorAll("img[src], link[href], script[src], a[href]").forEach((el) => {
          try {
            const raw = el.src || el.href || el.getAttribute("href") || "";
            if (!raw || raw.startsWith("data:")) return;
            const u = new URL(raw, location.href);
            if (u.hostname === location.hostname) return;
            const apex = NS.guessApexDomain(u.hostname) || NS.getRegistrableDomain(u.hostname);
            if (!apex || apex === pageApex) return;
            if (pageApex && NS.apexSameBrandFamily(pageApex, apex)) return;
            if (NS.pageIsSameBrandFamilySite(location.hostname, apex)) return;
            if (typeof NS.looksLikePortalOwnedCdnHost === "function" && NS.looksLikePortalOwnedCdnHost(u.hostname, location.hostname)) return;
            if (typeof NS.isPlausibleBrandResourceApex === "function" && !NS.isPlausibleBrandResourceApex(apex, titleTokensClone)) return;
            const apexRoot = (typeof NS.brandRootKeyFromHost === "function" ? NS.brandRootKeyFromHost(apex) : "")
              || (apex.split(".")[0] || "").toLowerCase();
            const hit = titleTokensClone.some((t) => {
              const tl = String(t).toLowerCase();
              return apexRoot === tl || apexRoot.includes(tl) || tl.includes(apexRoot);
            });
            if (hit) { brandAssetHosts++; brandHostApexes.add(apex); }
          } catch { /* ignore */ }
        });
      }
      const ctaEls = Array.from(document.querySelectorAll("a[href], a[data-href], button, .hero-btn, .platform-btn, [class*='download'], [class*='platform'], [onclick]")).filter((el) => {
        const t = (el.textContent || "").replace(/\s+/g, " ").trim();
        return NS.isMultiCtaPlatformOrTierLabel(t) || (/下载|试用|客户端|安装|Windows|macOS|Linux|Android|iOS/i.test(t) && t.length < 48);
      });
      const ctaHrefMap = new Map();
      for (const el of ctaEls) {
        const hrefs = [];
        const h = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
        if (h && NS.isPackageFileUrl(h)) hrefs.push(h);
        for (const a of ["onclick", "onmousedown", "data-url", "data-link"]) { const v = el.getAttribute(a); if (v) NS.extractPackageUrlFromHandlerText(v).forEach((u) => hrefs.push(u)); }
        const label = (el.textContent || "").replace(/\s+/g, " ").trim();
        for (const raw of hrefs) { try { const abs = new URL(raw, location.href).href; if (!ctaHrefMap.has(abs)) ctaHrefMap.set(abs, []); ctaHrefMap.get(abs).push(label); } catch { /* ignore */ } }
      }
      for (const pkg of packageHrefs) { try { const abs = new URL(pkg, location.href).href; if (!ctaHrefMap.has(abs)) ctaHrefMap.set(abs, []); } catch { /* ignore */ } }
      let duplicateProductCtas = false; let multiPlatformSamePackage = false;
      for (const [abs, labels] of ctaHrefMap) {
        if (labels.length < 2) {
          let platformHits = 0;
          try {
            document.querySelectorAll("button, a, [onclick], .platform-btn").forEach((el) => {
              const bl = `${el.getAttribute("onclick") || ""}${el.getAttribute("href") || ""}`;
              if (bl && abs && (bl.includes(abs) || bl.includes(decodeURIComponent(abs.split("/").pop() || "")))) { if (NS.isMultiCtaPlatformOrTierLabel(el.textContent || "")) platformHits++; }
            });
          } catch { /* ignore */ }
          if (platformHits >= 3) { multiPlatformSamePackage = true; if (!labels.length) ctaHrefMap.set(abs, ["Windows", "macOS", "Linux"]); }
          continue;
        }
        const joined = labels.join("|");
        if (/个人|企业|免费|试用|专业|性能|游戏/.test(joined) && new Set(labels).size >= 2) duplicateProductCtas = true;
        const platformBits = [/Windows|Win/i.test(joined), /macOS|Mac|OS\s*X/i.test(joined), /Linux/i.test(joined), /Android/i.test(joined), /iOS|iPhone|iPad/i.test(joined)].filter(Boolean).length;
        if (platformBits >= 2 && labels.length >= 2) multiPlatformSamePackage = true;
      }
      if (!multiPlatformSamePackage && packageHrefs.length >= 1 && ctaEls.length >= 3) {
        const uniquePkgs = new Set(packageHrefs.map((h) => { try { return new URL(h, location.href).href; } catch { return h; } }));
        if (uniquePkgs.size === 1) { const platLabels = ctaEls.filter((el) => NS.isMultiCtaPlatformOrTierLabel(el.textContent || "")); if (platLabels.length >= 3) multiPlatformSamePackage = true; }
      }
      if (multiPlatformSamePackage) duplicateProductCtas = true;
      const identityMismatch = brandAssetHosts >= 4 && brandHostApexes.size >= 1;
      const blobThreat = blobPackages.length >= 1;
      const offsiteBlobLike = blobPackages.length >= 1 || packageHrefs.some((h) => {
        const fn = NS.getFilenameFromUrl(h);
        if (NS.isClearProductOrAndroidPackage(fn) || NS.looksLikeProductPackageName(fn)) return NS.looksLikeHighRiskBlobPackageUrl(h);
        return NS.looksLikeObjectStoragePackageUrl(h);
      });
      if (blobThreat || offsiteBlobLike || multiPlatformSamePackage) {
        const target = blobPackages[0] || offsitePackages[0] || packageHrefs.find((h) => {
          const fn = NS.getFilenameFromUrl(h);
          if (NS.looksLikeObjectStoragePackageUrl(h) || NS.looksLikeBrandNearMissPackageName(fn)) return true;
          if (NS.isClearProductOrAndroidPackage(fn) || NS.looksLikeProductPackageName(fn)) return NS.looksLikeHighRiskBlobPackageUrl(h) || NS.hostLooksLikePublicObjectStorageEndpoint((() => { try { return new URL(h, location.href).hostname; } catch { return ""; } })());
          return NS.isSuspiciousDownloadFilename(fn);
        }) || packageHrefs[0] || "";
        let targetIsClearSafe = false;
        if (target) {
          try {
            const u = new URL(target, location.href);
            const onPublicOss = NS.hostLooksLikePublicObjectStorageEndpoint(u.hostname) || NS.isAnonymousPublicObjectHost(u.hostname) || NS.looksLikeObjectStoragePackageUrl(target);
            const fn = NS.getFilenameFromUrl(target);
            targetIsClearSafe = !onPublicOss && (NS.isClearProductOrAndroidPackage(target) || NS.looksLikeProductPackageName(fn)) && !NS.looksLikeHighRiskBlobPackageUrl(target) && !NS.looksLikeBrandNearMissPackageName(fn);
          } catch { targetIsClearSafe = false; }
        }
        if (target && !targetIsClearSafe) {
          state._brandResourceMismatchDetected = true;
          NS.addSignal("仿冒官网第三方分发安装包", 22, `页面宣称官网，但安装包托管在对象存储/第三方桶: ${NS.formatPackageLabel(target)}`);
          if (!state.protectedTargets.includes(target)) state.protectedTargets.push(target);
          NS.installDownloadGuard(`仿冒官网：安装包来自第三方对象存储 (${NS.formatPackageLabel(target)})`, { notify: true, href: target, message: NS.formatPackageLabel(target), forceNotify: true, lockHard: true });
          NS.disableAllDownloadIntentControls();
          return true;
        }
      }
      if (identityMismatch && (duplicateProductCtas || offsitePackages.length >= 1) && packageHrefs.length >= 1) {
        const target = offsitePackages[0] || blobPackages[0] || packageHrefs.find((h) => { const fn = NS.getFilenameFromUrl(h); return NS.isSuspiciousDownloadFilename(fn) || NS.looksLikeHighRiskBlobPackageUrl(h); });
        if (!target) { /* only clear product */ }
        else {
          state._brandResourceMismatchDetected = true;
          NS.addSignal("域名与品牌资源不一致", 20, `页面域名 ${location.hostname} 与盗用的品牌资源主机不一致，且下载入口异常`);
          if (!state.protectedTargets.includes(target)) state.protectedTargets.push(target);
          NS.installDownloadGuard("仿冒官网：当前域名与页面品牌资源/下载链不一致", { notify: true, href: target, message: NS.formatPackageLabel(target), forceNotify: true, lockHard: true });
          NS.disableAllDownloadIntentControls();
          return true;
        }
      }
      if (identityMismatch && brandHostApexes.size >= 1 && ctaEls.length >= 1) {
        const brandApexList = [...brandHostApexes].filter((a) => a && a !== pageApex && !NS.apexSameBrandFamily(pageApex, a) && !NS.pageIsSameBrandFamilySite(location.hostname, a));
        const topBrand = brandApexList[0];
        if (topBrand && topBrand !== pageApex && !NS.apexSameBrandFamily(pageApex || location.hostname, topBrand) && !NS.pageIsSameBrandFamilySite(location.hostname, topBrand)) {
          state._brandResourceMismatchDetected = true;
          NS.addSignal("域名与品牌资源不一致", 22, `页面域名 ${location.hostname} 大量加载品牌域 ${topBrand} 的资源，且存在下载入口，常见于仿冒官网`);
          const target = packageHrefs[0] || location.href;
          if (!state.protectedTargets.includes(target)) state.protectedTargets.push(target);
          NS.installDownloadGuard(`仿冒官网：域名与品牌资源不一致（≠ ${topBrand}）`, { notify: true, href: target, message: `${location.hostname} ≠ ${topBrand}`, forceNotify: true, lockHard: true });
          NS.disableAllDownloadIntentControls();
          return true;
        }
      }
      if (duplicateProductCtas && packageHrefs.length >= 1) {
        try {
          const target = packageHrefs[0];
          const u = new URL(target, location.href);
          const fn0 = NS.getFilenameFromUrl(target);
          const offsite = NS.guessApexDomain(u.hostname) !== pageApex;
          const onBlob = NS.looksLikeObjectStorageHost(u.hostname) || NS.isAnonymousPublicObjectHost(u.hostname) || NS.looksLikeHighRiskBlobPackageUrl(target) || NS.isThreatObjectStoragePackage(target, null);
          const simpleName = NS.looksLikeOversimplifiedBrandInstallerName(fn0);
          const sameApexClean = !offsite && !onBlob && NS.looksLikeProductPackageName(fn0) && !simpleName && !NS.isAnonymousPublicObjectHost(u.hostname);
          if (!sameApexClean) {
            state._brandResourceMismatchDetected = true;
            NS.addSignal("多版本下载同一安装包", 20, `个人版/企业版等不同入口指向同一安装包: ${NS.formatPackageLabel(target)}`);
            if (onBlob || NS.isAnonymousPublicObjectHost(u.hostname)) NS.addSignal("仿冒官网第三方分发安装包", 22, `安装包托管在匿名对象存储/公共桶: ${u.hostname}`);
            if (!state.protectedTargets.includes(target)) state.protectedTargets.push(target);
            NS.installDownloadGuard(`仿冒官网：多版本按钮共用安装包 (${NS.formatPackageLabel(target)})`, { notify: true, href: target, message: NS.formatPackageLabel(target), forceNotify: true, lockHard: true });
            NS.disableAllDownloadIntentControls();
            return true;
          }
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    return false;
  };

  NS.detectBrandResourceDomainMismatch = function () {
    try {
      const state = NS.state;
      if (state._brandResourceMismatchDetected) return true;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return false;
      if (NS.looksLikeSelfConsistentOfficialSite() && NS.countTransparentProductPackages(NS.getThreatScanHtml(80000)) >= 1) return false;
      const hasIcp = !!(state.icpInfo && String(state.icpInfo).trim() && !/未查询到|查询失败|暂无/.test(state.icpInfo));
      const icpHostOk = !state.icpMatchedHost || NS.intelHostIsValidAttribution(state.icpMatchedHost, location.hostname);
      const whoisOld = /已注册\s*(\d+)\s*天/.exec(state.whoisInfo || "");
      const days = whoisOld ? parseInt(whoisOld[1], 10) : null;
      if (hasIcp && icpHostOk && days != null && days >= 365) return false;
      const title = document.title || "";
      const textHead = ((document.body && document.body.textContent) || "").replace(/\s+/g, " ").trim().slice(0, 4000);
      const claimsOfficial = /官网|官方下载|官方正版|官方网站|电脑版免费下载|官方客户端/i.test(`${title} ${textHead}`);
      if (!claimsOfficial) return false;
      const info = NS.collectBrandResourceMismatch(title);
      if (info.brandAssetHits < 5 || !info.topBrandApex || info.topCount < 3) return false;
      if (!info.pageApex || info.pageApex === info.topBrandApex) return false;
      if (NS.apexSameBrandFamily(info.pageApex, info.topBrandApex) || NS.pageIsSameBrandFamilySite(location.hostname, info.topBrandApex)) return false;
      // 纯数字 CDN / 门户自有资源域：绝不当盗用（soft.china.com + 30405.com）
      const brandRootPre = NS.brandRootKeyFromHost(info.topBrandApex) || (info.topBrandApex.split(".")[0] || "").toLowerCase();
      if (!brandRootPre || /^\d{3,}$/.test(brandRootPre)) return false;
      if (typeof NS.isPlausibleBrandResourceApex === "function"
        && !NS.isPlausibleBrandResourceApex(info.topBrandApex, info.titleTokens || [])) return false;
      // 标题无拉丁品牌 token 对齐到 topBrand → 不是「盗用该品牌官网资源」
      const titleToks = info.titleTokens || [];
      const brandAligned = titleToks.some((t) => {
        const tl = String(t || "").toLowerCase();
        return tl.length >= 4 && (brandRootPre === tl || brandRootPre.includes(tl) || tl.includes(brandRootPre));
      });
      if (!brandAligned) return false;
      const dlBtns = NS.getDownloadButtons().length;
      const hostLow = (location.hostname || "").toLowerCase();
      const wikiLike = /^(wiki|docs?|help|manual|handbook|bbs|forum)\./i.test(hostLow) || /\/(wiki|docs?|help|manual)\b/i.test(location.pathname || "");
      const dlPitch = /立即下载|免费下载|官方下载|客户端下载|电脑版|下载中心|安装包|获取客户端/i.test(textHead) || dlBtns >= 1 || /download/i.test(location.pathname + location.href);
      if (!dlPitch && dlBtns < 1) return false;
      if (wikiLike && !/官方下载|官网下载|客户端下载|安装包|立即下载/i.test(`${title} ${textHead.slice(0, 800)}`) && dlBtns < 2) return false;
      // 门户频道子域（soft./game.）+ 有效 ICP：第三方分发站，不是仿冒品牌官网
      try {
        const portalChan = /^(soft|game|app|down|download|news|blog|bbs|video|music)\./i.test(hostLow.replace(/^www\./, ""));
        if (portalChan && NS.hasValidIcpRecord && NS.hasValidIcpRecord()) return false;
      } catch { /* ignore */ }
      const corr = NS.evaluateTitleHostBrandCorrelation();
      const host = location.hostname.toLowerCase().replace(/^www\./, "");
      const hostLabel = (host.split(".")[0] || "");
      const brandRoot = brandRootPre;
      const hostSquatsBrand = brandRoot.length >= 4 && (hostLabel === brandRoot || host.startsWith(`${brandRoot}.`)) && !NS.pageIsSameBrandFamilySite(host, info.topBrandApex) && !NS.apexSameBrandFamily(info.pageApex, info.topBrandApex);
      // titleHostMismatch  alone 不够：中文产品站在 china.com 频道上很常见
      const titleHostMismatch = !!corr.mismatch && hostSquatsBrand
        && !NS.pageIsSameBrandFamilySite(host, info.topBrandApex)
        && !(corr.brandToken && brandRoot && (corr.brandToken === brandRoot || brandRoot.includes(corr.brandToken) || corr.brandToken.includes(brandRoot)));
      let faviconOffBrand = false;
      try {
        document.querySelectorAll('link[rel*="icon"], link[rel="apple-touch-icon"]').forEach((l) => {
          try {
            const href = l.getAttribute("href") || "";
            if (!href) return;
            const u = new URL(href, location.href);
            if (typeof NS.looksLikePortalOwnedCdnHost === "function" && NS.looksLikePortalOwnedCdnHost(u.hostname, location.hostname)) return;
            const a = NS.guessApexDomain(u.hostname);
            if (a && a === info.topBrandApex && a !== info.pageApex && !NS.apexSameBrandFamily(info.pageApex, a)
              && (typeof NS.isPlausibleBrandResourceApex !== "function" || NS.isPlausibleBrandResourceApex(a, titleToks))) {
              faviconOffBrand = true;
            }
          } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
      let jsonLdBrandMismatch = false;
      try {
        document.querySelectorAll('script[type="application/ld+json"]').forEach((s) => {
          const t = s.textContent || "";
          if (!/"SoftwareApplication"|"Organization"/i.test(t)) return;
          const urls = t.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
          for (const raw of urls) {
            try {
              const a = NS.guessApexDomain(new URL(raw).hostname);
              if (a && a === info.topBrandApex && a !== info.pageApex && !NS.apexSameBrandFamily(info.pageApex, a)
                && (typeof NS.isPlausibleBrandResourceApex !== "function" || NS.isPlausibleBrandResourceApex(a, titleToks))) {
                jsonLdBrandMismatch = true;
              }
            } catch { /* ignore */ }
          }
        });
      } catch { /* ignore */ }
      // 资源量路径：须已对齐真实品牌根（todesk 等 ≥5 字母），数字 CDN/门户 soft-static 已被 collect 滤掉
      const volumeOnly = info.brandAssetHits >= 10 && info.topCount >= 6 && claimsOfficial && dlBtns >= 2
        && brandAligned && brandRoot.length >= 5 && !/^\d+$/.test(brandRoot)
        && !NS.pageIsSameBrandFamilySite(host, info.topBrandApex);
      const strong = hostSquatsBrand || faviconOffBrand || jsonLdBrandMismatch
        || (titleHostMismatch && volumeOnly)
        || volumeOnly;
      if (!strong) return false;
      if (host.endsWith(`.${info.topBrandApex}`)) return false;
      if (NS.apexSameBrandFamily(info.pageApex, info.topBrandApex)) return false;
      const reasons = [`当前域 ${location.hostname}（apex=${info.pageApex}）`, `盗用品牌资源主机 ${info.topBrandApex}（命中 ${info.topCount}+）`];
      if (hostSquatsBrand) reasons.push(`域名冒用品牌词「${brandRoot}」`);
      if (titleHostMismatch) reasons.push(`标题/正文品牌「${corr.brandToken}」出现约 ${corr.brandHits} 次，与域名 ${corr.hostLabel} 关联不严谨（${corr.hostMatch}）`);
      if (faviconOffBrand) reasons.push("favicon/图标来自官方域");
      if (jsonLdBrandMismatch) reasons.push("结构化数据指向官方域");
      state._brandResourceMismatchDetected = true;
      NS.addSignal("域名与品牌资源不一致", 24, reasons.join("；"));
      NS.addSignal("仿冒品牌官网下载站", 18, `页面宣称官网下载，但站点域名与页面加载的品牌资源域名（${info.topBrandApex}）不一致`);
      const target = (() => { try { const a = document.querySelector("a[href*='download'], a.download-btn, .download-btn, a[class*='download'], button"); const h = a && (a.getAttribute("href") || ""); if (h && !/^javascript:/i.test(h) && h !== "#") return new URL(h, location.href).href; } catch { /* ignore */ } return location.href; })();
      if (target && !state.protectedTargets.includes(target)) state.protectedTargets.push(target);
      NS.installDownloadGuard(`仿冒官网：域名与品牌资源不一致（${info.pageApex} ≠ ${info.topBrandApex}）`, { notify: true, href: target, message: `${location.hostname} 盗用 ${info.topBrandApex} 资源`, forceNotify: true, lockHard: true });
      NS.disableAllDownloadIntentControls();
      return true;
    } catch { return false; }
  };

  NS.detectRemoteGarblePackageDispatch = function () {
    try {
      const state = NS.state;
      if (state._remoteGarbleDlDetected) return true;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      const squat = typeof NS.titleBrandVsHostSquatShape === "function" ? NS.titleBrandVsHostSquatShape(document.title || "", lab, "") : "";
      if (squat !== "padded" && squat !== "typo" && squat !== "hyphen" && squat !== "partial" && squat !== "none" && (NS.looksLikeMatureOfficialPortal() || NS.looksLikeSafeOfficialContext())) return false;
      const title = document.title || "";
      const claims = /官网|官方下载|电脑版官网|免费下载|官方客户端|官方桌面|官方正版/i.test(title) || NS.pageClaimsBrandDownloadLanding();
      if (!claims) return false;
      const html = NS.getHtmlSlice(140000);
      const hasRemoteLinkScript = /fetchDownloadLink|currentDownloadLink|downloadLinkFetched|updateAllDownloadButtons/i.test(html) || (/fetch\s*\(/i.test(html) && /\.download-btn/i.test(html) && /href/i.test(html));
      const garbleName = /(?:appinstall|app[_-]?setup|setup|install|down|update)[a-z0-9_]*\.\d{4,}\.(?:zip|exe|msi)/i.test(html) || /\b[a-z]{5,}\.\d{5,}\.(?:zip|exe|msi)\b/i.test(html);
      const randomHostDl = /https?:\/\/(?:www\.)?[a-z0-9]{8,}\.[a-z]{2,}(?:\.[a-z]{2,})?\/(?:load\d*|dl\d*|down|get|file|soft)[^"'<\s]{0,100}\.(?:zip|exe|msi)/i.test(html);
      let liveGarble = "";
      try {
        document.querySelectorAll("a[href], a.download-btn, [data-href]").forEach((a) => {
          if (liveGarble) return;
          const h = (a.getAttribute("href") || a.getAttribute("data-href") || "").trim();
          if (!h || !NS.isPackageFileUrl(h)) return;
          const fn = NS.getFilenameFromUrl(h);
          let host = ""; try { host = new URL(h, location.href).hostname; } catch { /* ignore */ }
          if (NS.isSuspiciousDownloadFilename(fn) || NS.looksLikeRandomDownloadHost(host) || /^(?:app)?(?:install|setup)\w*\.\d{4,}\./i.test(fn)) liveGarble = h;
        });
      } catch { /* ignore */ }
      if (!(liveGarble || (hasRemoteLinkScript && (garbleName || randomHostDl)) || (garbleName && randomHostDl))) return false;
      state._remoteGarbleDlDetected = true;
      state.remoteDownloadDispatchDetected = true;
      let pkg = liveGarble;
      if (!pkg) { const m = html.match(/https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|msi)(?:\?[^\s"'<>\\]*)?/i); if (m) pkg = m[0]; }
      if (pkg && !state.protectedTargets.includes(pkg)) state.protectedTargets.push(pkg);
      const label = pkg ? NS.formatPackageLabel(pkg) : "远程乱码安装包";
      NS.addSignal("远程下发乱码安装包", 22, pkg ? `官网下载页远程拉取安装包，文件名/主机异常: ${label}` : "官网下载页通过脚本远程下发安装包（乱码文件名或高熵下载域名）");
      if (squat === "padded" || squat === "typo" || squat === "hyphen") {
        const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const brandTok = NS.pickBrandTokenForHost(NS.extractLatinBrandTokens(title), lab0) || NS.extractLatinBrandTokens(title)[0] || "";
        if (brandTok) state.spoofBrand = NS.formatBrandTokenForDisplay(brandTok);
        const shapeHint = squat === "hyphen" ? "域名用连字符拆分品牌名" : "域名夹带品牌前缀/后缀";
        NS.addSignal("仿冒品牌官网下载站", 24, brandTok ? `标题/正文品牌「${NS.formatBrandTokenForDisplay(brandTok)}」与域名 ${location.hostname} 不匹配（${shapeHint}）` : `域名 ${location.hostname} 呈品牌营销站形态，且远程下发异常安装包`);
      }
      NS.installDownloadGuard(pkg ? `远程乱码安装包: ${label}` : "远程下发乱码安装包", { notify: true, href: pkg || "", message: pkg ? `远程安装包异常: ${label}` : "官网下载页远程下发乱码安装包", title: state.spoofBrand ? `已识别仿冒「${state.spoofBrand}」官网` : "已拦截远程异常安装包", forceNotify: true, guardKind: state.spoofBrand ? "brand-spoof" : "package", lockHard: true });
      NS.postToHooks({ type: "set-guard", enabled: true });
      NS.disableAllDownloadIntentControls();
      return true;
    } catch { return false; }
  };

  NS.detectDesktopForceDownloadKit = function () {
    try {
      const state = NS.state;
      if (state._desktopForceDlKit) return true;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if ((NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) && !state._desktopForceDlKit) return false;
      const html = NS.getHtmlSlice(100000);
      const hasDlp = /\.dlp-overlay|\.dlp-modal|\.dlp-topbar|\bdlp-overlay\b|\bdlp-topbar\b/i.test(html);
      const hasPitch = /电脑版推荐|正在为您下载[\s\S]{0,60}电脑版|大屏浏览|功能更完整/i.test(html);
      const hasAuto = /triggerDownload|hasTriggered|createElement\s*\(\s*['"]iframe['"]\s*\)/i.test(html) && NS.PACKAGE_EXT.test(html);
      let domHit = false;
      try { domHit = !!document.querySelector(".dlp-overlay, .dlp-topbar, .dlp-modal, .dlp-btn"); } catch { /* ignore */ }
      if (!(hasDlp && (hasPitch || hasAuto)) && !(domHit && hasPitch) && !(hasPitch && hasAuto)) return false;
      state._desktopForceDlKit = true;
      let pkg = "";
      try {
        const m = html.match(/https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|msi|dmg|apk)(?:\?[^\s"'<>\\]*)?/i);
        if (m) pkg = m[0];
        if (!pkg) { document.querySelectorAll("a.dlp-btn, a[href*='.zip'], a[href*='.exe']").forEach((a) => { const h = a.getAttribute("href") || ""; if (NS.isPackageFileUrl(h) && !pkg) pkg = h; }); }
      } catch { /* ignore */ }
      if (pkg && !state.protectedTargets.includes(pkg)) state.protectedTargets.push(pkg);
      NS.addSignal("桌面端强制弹窗下载", 24, pkg ? `检测到桌面端强制弹窗+自动下载套件，目标: ${NS.formatPackageLabel(pkg)}` : "检测到桌面端强制弹窗+自动下载套件 (dlp-overlay / 电脑版推荐)");
      NS.installDownloadGuard(pkg ? `桌面端强制弹窗下载: ${NS.formatPackageLabel(pkg)}` : "桌面端强制弹窗下载套件", { notify: true, href: pkg || "", message: pkg ? NS.formatPackageLabel(pkg) : "已拦截强制弹窗下载", forceNotify: true, title: "已拦截强制弹窗下载", guardKind: "package", lockHard: true });
      NS.postToHooks({ type: "set-guard", enabled: true });
      NS.disableAllDownloadIntentControls();
      try {
        document.querySelectorAll(".dlp-overlay, .dlp-topbar, .dlp-modal, [class*='dlp-overlay'], [class*='dlp-topbar']").forEach((el) => { try { el.remove(); } catch { /* ignore */ } });
        document.querySelectorAll("style").forEach((st) => { if (/\.dlp-overlay|\.dlp-modal|\.dlp-topbar/i.test(st.textContent || "")) { try { st.remove(); } catch { st.textContent = ""; } } });
      } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  NS.detectRemoteDownloadApiBinding = function () {
    const state = NS.state;
    const html = NS.getHtmlSlice(80000);
    const scripts = Array.from(document.scripts).map((s) => s.textContent || "").join("\n").slice(0, 200000);
    const blob = `${html}\n${scripts}`;
    const apiFetch = /fetch\s*\(\s*['"][^'"]*api\.php[^'"]*['"]/i.test(blob)
      || /fetch\s*\(\s*['"]https?:\/\/[^'"]+(?:page-admin|download-api|getdown|getlink|download[_-]?api)[^'"]*['"]/i.test(blob)
      || /\.(?:get|post)\s*\(\s*['"][^'"]*api\.php/i.test(blob)
      || /axios\.[a-z]+\s*\(\s*['"][^'"]*(?:api\.php|getdown|getlink|download)[^'"]*['"]/i.test(blob);
    const bindDownload = /download_link|downloadUrl|down_url|download_url|download_uri|windowsDownload|macDownload/i.test(blob)
      && (/\.href\s*=/.test(blob) || /querySelectorAll\s*\([^)]*download/i.test(blob) || /getElementsByClassName\s*\([^)]*download/i.test(blob) || /downloadElements|initDownloadLinks/i.test(blob));
    let emptyHrefDlBtns = 0;
    try {
      document.querySelectorAll("a, button, [role='button'], .download-btn, #mainDownloadBtn").forEach((el) => {
        const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        if ((!href || href === "#") && (NS.DOWNLOAD_TEXT.test(text) || /download/i.test(el.className || "") || /download/i.test(el.id || ""))) emptyHrefDlBtns += 1;
      });
    } catch { /* ignore */ }
    const shellBind = emptyHrefDlBtns >= 1 && (/download_uri|api\.php|fetchDownloadLink|download_link|initDownloadLinks/i.test(blob) || bindDownload);
    if ((apiFetch && bindDownload) || shellBind) {
      const reason = (apiFetch && bindDownload)
        ? "页面通过远程 api 动态写入下载按钮地址，常见于仿冒官网分发模板"
        : `检测到 ${emptyHrefDlBtns} 个无直链下载按钮并含远程绑定脚本，疑似动态下发安装包`;
      state.remoteDownloadDispatchDetected = true;
      NS.addSignal("远程API动态绑定下载", 18, reason);
      NS.installDownloadGuard(
        (apiFetch && bindDownload) ? "检测到远程 API 动态绑定下载链接" : "下载按钮已绑定可疑远程地址",
        { notify: true, message: (apiFetch && bindDownload) ? "远程动态下载地址" : "下载按钮已绑定可疑远程地址", forceNotify: true, lockHard: true }
      );
      NS.disableAllDownloadIntentControls();
      return true;
    }
    return false;
  };

  NS.detectAntiAnalysisBehavior = function () {
    try {
      if (NS.looksLikeNormalContent(NS.estimatePageContext()) || NS.isBenignContentPage()) return false;
      const scripts = Array.from(document.scripts).map((s) => s.textContent || "").join("\n").slice(0, 150000);
      const html = NS.getHtmlSlice(60000);
      const blob = `${scripts}\n${html}`;
      if (NS.hasStrongAntiAnalysisMarkers(blob)) {
        NS.addSignal("反调试/禁止审查页面", 10, "页面禁止右键/F12 或跳转 about:blank，常见于仿冒下载站");
        return true;
      }
    } catch { /* ignore */ }
    return false;
  };

  NS.looksLikeSameOriginLandingPageUrl = function (href) {
    if (!href) return false;
    try {
      const url = new URL(href, location.href);
      if (url.origin !== location.origin) return false;
      const path = url.pathname || "/";
      // download.html / install.html / get.php / down/ 等落地页
      if (/\.(?:html?|php|asp|aspx|jsp)$/i.test(path)
        && /(?:download|down|install|setup|landing|client|soft|get|dows|app)/i.test(path)) return true;
      return /(?:download|down|dows|install|setup|landing|dl|redirect|clash|verge|client|soft|\d{3,}down|down\d{2,}|dl\d{2,}|app[_-][a-z0-9]{3,})(?:\.|\/|$)/i.test(path);
    } catch { return false; }
  };

  NS.detectRedirectDownloadImpersonation = function () {
    const suspicious = NS.getDownloadButtons().filter((el) => {
      const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
      const text = (el.textContent || "").trim();
      if (!NS.DOWNLOAD_TEXT.test(text) || !NS.looksLikeRedirectLink(href)) return false;
      return !NS.isPackageFileUrl(href);
    });
    if (suspicious.length >= 1) {
      const first = suspicious[0];
      const href = (first.getAttribute("href") || first.getAttribute("data-href") || "").trim();
      NS.addSignal("可疑跳转下载按钮", 4, `下载文案按钮指向中转页 ${href}（仅提示，不拦截页面跳转）`);
      return true;
    }
    return false;
  };

  NS.detectBrandImpersonation = function () {
    const title = (document.title || "").trim();
    const text = ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, 8000);
    const hostname = location.hostname.toLowerCase().replace(/^www\./, "");
    const hasDownloadIntent = /(官方下载|免费下载|立即下载|下载客户端|下载中心|官方正版|正版|官网)/i.test(`${title} ${text}`);
    if (!hasDownloadIntent) return false;
    try {
      const html = NS.getHtmlSlice(120000);
      if (NS.countTransparentProductPackages(html) >= 1) return false;
      if (NS.looksLikeSelfConsistentOfficialSite()) return false;
    } catch { /* ignore */ }
    if (!NS.looksLikeRandomDownloadHost(hostname)) return false;
    const context = NS.estimatePageContext();
    if (NS.looksLikeNormalContent(context) || NS.isBenignContentPage()) return false;
    NS.addSignal("品牌仿冒/域名不匹配", 10, `页面带有品牌下载意图，但当前域名 ${location.hostname} 具有跳转/中转特征`);
    return true;
  };

  NS.detectLandingPageImpersonation = function () {
    const context = NS.estimatePageContext();
    const looksNormal = NS.looksLikeNormalContent(context);
    const benign = NS.isBenignContentPage();
    const officialClient = NS.looksLikeOfficialClientDownloadPage();
    if (officialClient) return;
    const downloadLikeButtons = NS.getDownloadButtons();
    const downloadButtonCount = downloadLikeButtons.length;
    const packageTargets = Array.from(document.querySelectorAll("a[href], a[data-href]")).map((el) => (el.getAttribute("href") || el.getAttribute("data-href") || "").trim()).filter((href) => NS.isPackageFileUrl(href));
    const suspiciousDownloadTargets = packageTargets.filter((href) => NS.isSuspiciousDownloadTarget(href, null));
    const duplicateHiddenTargets = suspiciousDownloadTargets.length >= 2 && new Set(suspiciousDownloadTargets).size < suspiciousDownloadTargets.length;
    const obfuscatedPhpDownloadLinks = packageTargets.filter((href) => NS.looksLikeObfuscatedPhpDownloadUrl(href));
    if (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) {
      for (const href of packageTargets) {
        if (NS.looksLikeHighRiskBlobPackageUrl(href)) { NS.addSignal("可疑安装包链接", 16, `高风险对象存储安装包: ${NS.formatPackageLabel(href)}`); NS.installDownloadGuard(`高风险对象存储安装包: ${NS.formatPackageLabel(href)}`); break; }
      }
    }
    for (const href of packageTargets) {
      if (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) break;
      const fileName = NS.getFilenameFromUrl(href);
      if (NS.isClearProductOrAndroidPackage(fileName) || NS.isClearProductOrAndroidPackage(href) || NS.looksLikeProductPackageName(fileName) || NS.isBenignShortInstallerName(fileName) || NS.isContentAddressedPackageName(fileName)) { if (!NS.looksLikeHighRiskBlobPackageUrl(href)) continue; }
      const badName = NS.isSuspiciousDownloadFilename(fileName);
      const badPhp = NS.looksLikeObfuscatedPhpDownloadUrl(href);
      const badPath = NS.looksLikeHiddenPackagePath(href);
      const brandGap = NS.packageMismatchesPageBrand(href);
      if (badName || badPhp || (badPath && (badName || brandGap || !NS.looksLikeProductPackageName(fileName))) || brandGap) {
        let reason = `安装包链接行为异常: ${NS.formatPackageLabel(href)}`;
        if (badName) reason = `安装包文件名异常 (${fileName}): ${NS.formatPackageLabel(href)}`;
        else if (brandGap) reason = `页面品牌与安装包文件名不符 (${fileName}): ${NS.formatPackageLabel(href)}`;
        else if (badPath) reason = `隐蔽路径安装包: ${NS.formatPackageLabel(href)}`;
        NS.addSignal("可疑安装包链接", 16, reason);
        NS.installDownloadGuard(reason);
        break;
      }
    }
    for (const el of downloadLikeButtons) {
      const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
      if (!href || !NS.isPackageFileUrl(href)) continue;
      if (NS.isSuspiciousDownloadTarget(href, el)) { const fileName = NS.getFilenameFromUrl(href); const reason = `下载按钮指向异常安装包 (${fileName || href})`; NS.addSignal("仿冒页异常下载按钮", 14, reason); NS.installDownloadGuard(reason); break; }
    }
    if (obfuscatedPhpDownloadLinks.length > 0) { NS.addSignal("PHP 下载入口与乱码路径", 18, "页面包含指向安装包的混淆 .php 下载入口"); NS.installDownloadGuard("检测到混淆 PHP 安装包入口"); }
    if (duplicateHiddenTargets && suspiciousDownloadTargets.some((h) => NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(h)))) { NS.addSignal("重复可疑下载目标", 14, "多个入口指向同一可疑安装包地址"); NS.installDownloadGuard("检测到重复可疑安装包目标"); }
    const pageSource = NS.getHtmlSlice(80000);
    const remoteSetupFetchPattern = /fetch\s*\(\s*[^)]*(?:https?:\/\/[^"')]+\.(?:txt|json|php)|\.(?:txt|json|php))/i.test(pageSource) || /(?:const|let|var)\s+\w*(?:REMOTE_)?(?:SETUP|CONFIG|VERSION|PACKAGE)_?URL\s*=/i.test(pageSource) || /(?:const|let|var)\s+\w+_URL\s*=\s*["'`][^"'`\n]+\.(?:txt|json|php)/i.test(pageSource);
    const autoDownloadDispatchPattern = /triggerDownload|createElement\(["']a["']\)\s*;[\s\S]{0,120}\.download\s*=/i.test(pageSource) || /createElement\(["']a["']\)[\s\S]{0,200}\.click\s*\(/i.test(pageSource);
    const remoteDownloadUrlPattern = /https?:\/\/[^"'\s>]+\.(?:zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|"|'|\s|>)/i.test(pageSource);
    const suspiciousDispatchChain = remoteSetupFetchPattern && autoDownloadDispatchPattern && remoteDownloadUrlPattern;
    if (suspiciousDispatchChain) {
      const htmlForDispatch = pageSource;
      const hasCleanPkgs = NS.countTransparentProductPackages(htmlForDispatch) >= 1;
      const hasBadPkg = packageTargets.some((h) => NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(h))) || NS.hasEncryptedNuxtDownloadConfig(htmlForDispatch);
      if (!hasCleanPkgs && hasBadPkg) { NS.addSignal("远程配置解析下载链", 12, "页面读取远程配置并动态触发安装包下载"); NS.installDownloadGuard("检测到远程安装包分发链"); }
    }
    if (benign || looksNormal || officialClient) return;
    try { const htmlSoft = NS.getHtmlSlice(120000); if (NS.countTransparentProductPackages(htmlSoft) >= 1) return; if (NS.looksLikeSelfConsistentOfficialSite()) return; } catch { /* ignore */ }
    NS.detectRedirectDownloadImpersonation();
    NS.detectBrandImpersonation();
    const bodyText = ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, 10000);
    const titleText = (document.title || "").trim();
    const suspiciousPath = /(verify|landing|redirect|secure-download|official-download|app-download)/i.test(location.pathname) || /\/(?:dl|down|dows)\d*\//i.test(location.pathname);
    const suspiciousHostname = /(^|\.)(download|dl|app|verify|secure|official|landing|redirect|setup)[-.]/i.test(location.hostname) || /-(download|dl|app|verify|landing)\./i.test(location.hostname);
    const brandSpoofingText = /官网|官方网站|官方下载|正版|官网首页/i.test(bodyText + titleText);
    const marketingDownloadPhrase = /免费下载|立即下载|下载中心|下载软件|客户端下载|官网下载|官方下载安装/i.test(bodyText);
    const isDownloadLanding = downloadButtonCount >= 3 || document.querySelectorAll('a[href*="download"], a[href*="install"]').length >= 2;
    const downloadLikeText = (bodyText.match(/download|下载|安装|客户端|立即下载|官方|免费/gi) || []).length;
    const lowContent = bodyText.length < 2200 && downloadButtonCount > 0;
    if (brandSpoofingText && marketingDownloadPhrase && (suspiciousHostname || suspiciousPath) && isDownloadLanding) NS.addSignal("伪官方官网落地页", 4, "页面使用官网宣传与下载按钮，但路径/域名行为像中转落地页");
    if (/官网|官方|官方网站/i.test(titleText) && suspiciousHostname) NS.addSignal("可疑官网域名特征", 2, "标题宣称官网，且主机名含中转/下载类行为特征");
    if (marketingDownloadPhrase && suspiciousHostname && isDownloadLanding) NS.addSignal("营销型下载落地页", 3, "页面用大量营销内容和下载按钮引导用户下载");
    if (lowContent && downloadLikeText >= 6 && (suspiciousPath || suspiciousHostname)) NS.addSignal("伪装官网的下载营销页", 3, "高密度下载按钮与稀少正文，常见于伪装官网投毒页");
  };
})(window.SilverfoxContent ??= {});
