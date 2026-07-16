/**
 * ICP/WHOIS 成熟度门 + 官方上下文判定。
 * 决定页面是否为成熟官网（永不 arm）或安全官方下载上下文。
 */
;(function (NS) {
  "use strict";

  NS.getWhoisAgeDays = function () {
    try {
      const m = /已注册\s*(\d+)\s*天/.exec(NS.state.whoisInfo || "");
      if (!m) return null;
      const d = parseInt(m[1], 10);
      return Number.isFinite(d) ? d : null;
    } catch { return null; }
  };

  NS.hasValidIcpRecord = function () {
    try {
      const s = String(NS.state.icpInfo || "").trim();
      if (!s || /未查询到|查询失败|暂无/.test(s)) return false;
      if (NS.state.icpMatchedHost && !NS.intelHostIsValidAttribution(NS.state.icpMatchedHost, location.hostname)) return false;
      return true;
    } catch { return false; }
  };

  NS.looksLikeUltraMatureIcpDomain = function () {
    try {
      const state = NS.state;
      if (state._seoCloakKitDetected || state._fakeSpaDetected) return false;
      if (!NS.hasValidIcpRecord()) return false;
      const days = NS.getWhoisAgeDays();
      return days != null && days >= 3650;
    } catch { return false; }
  };

  NS.looksLikeUltraMatureWhoisDomain = function () {
    try {
      const state = NS.state;
      if (state._seoCloakKitDetected || state._fakeSpaDetected) return false;
      const days = NS.getWhoisAgeDays();
      return days != null && days >= 3650;
    } catch { return false; }
  };

  NS.looksLikeLongLivedWhoisDomain = function () {
    try {
      const state = NS.state;
      if (state._seoCloakKitDetected || state._fakeSpaDetected) return false;
      const days = NS.getWhoisAgeDays();
      return days != null && days >= 1825;
    } catch { return false; }
  };

  NS.icpSettledForSoftBrandSpoof = function () {
    try {
      if (NS.hasValidIcpRecord()) return true;
      if (NS.state._icpQuerySettled) return true;
      return false;
    } catch { return false; }
  };

  NS.notifyHooksOfficialSafe = function (enabled) {
    try {
      NS.postToHooks({ type: "set-official-safe", enabled: !!enabled });
      if (enabled) NS.postToHooks({ type: "set-guard", enabled: false });
    } catch { /* ignore */ }
  };

  /** 清除软品牌仿冒误报（有真实 ICP / 超长 WHOIS）。硬套件留给各自检测器。 */
  NS.clearBrandSpoofFalsePositive = function (reason) {
    const state = NS.state;
    void reason;
    state._brandSpoofPortalDetected = false;
    state.spoofBrand = "";
    state._pendingSoftBrandSpoof = false;
    try { NS.dismissPageToast(); } catch { /* ignore */ }
    try {
      state.details = (state.details || []).filter((d) => {
        if (!d) return false;
        if (d.name === "无ICP备案信息") return false;
        if (/仿冒品牌官网|仿冒站下载拦截|已启用仿冒站|已启用安装包下载拦截/i.test(d.name || "")) return false;
        if (/仿冒|官网下载站|不匹配/i.test(d.reason || "") && /仿冒|品牌/i.test(d.name || "")) return false;
        return true;
      });
      if (state.signalSet && typeof state.signalSet.forEach === "function") {
        const drop = [];
        state.signalSet.forEach((k) => { if (/仿冒品牌官网|仿冒站下载|无ICP备案|安装包下载拦截/i.test(String(k))) drop.push(k); });
        drop.forEach((k) => state.signalSet.delete(k));
      }
      state.score = (state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
    } catch { /* ignore */ }
    try {
      if (state.downloadGuardInstalled || state._earlyShellArmed || (state.protectedTargets && state.protectedTargets.length) || document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']")) {
        NS.clearDownloadGuard(reason || "icp-clear-brand-spoof");
      } else {
        try {
          chrome.runtime.sendMessage({ type: "clear-threat-notice", url: location.href, reason: reason || "icp-clear-brand-spoof" }, () => { void chrome.runtime.lastError; });
        } catch { /* ignore */ }
        try { NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    try { NS.notifyHooksOfficialSafe(true); NS.postToHooks({ type: "set-guard", enabled: false }); } catch { /* ignore */ }
    try { NS.emitRiskReport(true); } catch { /* ignore */ }
  };

  /** ICP/WHOIS 证实长生命周期门户后进入轻量模式，停止复扫。 */
  NS.enterIntelLightMode = function (reason) {
    const state = NS.state;
    state._perfBenign = true;
    state._perfBenignAt = Date.now();
    state._intelLightMode = true;
    if (NS.hasValidIcpRecord() || NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()) {
      NS.clearBrandSpoofFalsePositive(reason || "intel-light");
    }
    try { NS.notifyHooksOfficialSafe(true); NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
    if (state.downloadGuardInstalled || state._earlyShellArmed || (state.protectedTargets && state.protectedTargets.length) || document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']")) {
      try { NS.clearDownloadGuard(reason || "intel-light-mode"); } catch { /* ignore */ }
    }
  };

  NS.looksLikeMatureOfficialPortal = function () {
    try {
      const state = NS.state;
      if (state._seoCloakKitDetected || state._fakeSpaDetected) return false;
      const days = NS.getWhoisAgeDays();
      if (days != null && days >= 3650) return true; // 国际长生命周期域名（github.com）
      if (!NS.hasValidIcpRecord()) return false;
      if (days == null || days < 365) return false;
      if (days >= 3650) return true;
      if (days >= 1825) {
        const textLen = ((document.body && document.body.textContent) || "").replace(/\s+/g, "").length;
        if (textLen >= 200) return true;
        return true;
      }
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) return false;
      try {
        const th = NS.getThreatScanHtml(48000);
        if (NS.hasEncryptedNuxtDownloadConfig(th) && NS.countTransparentProductPackages(th) === 0) return false;
      } catch { /* ignore */ }
      const textLen = ((document.body && document.body.textContent) || "").replace(/\s+/g, "").length;
      if (textLen >= 400) return true;
      let same = 0;
      try {
        const pageApex = NS.getRegistrableDomain(location.hostname);
        document.querySelectorAll('script[src], link[rel="stylesheet"][href], link[rel="preload"][href]').forEach((el) => {
          try {
            const raw = el.src || el.href || "";
            if (pageApex && NS.getRegistrableDomain(new URL(raw, location.href).hostname) === pageApex) same++;
          } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
      return same >= 3;
    } catch { return false; }
  };

  /** 真实长生命周期门户硬安全门：永不 arm guard / 灰按钮 / 视自动包导航为威胁。 */
  NS.shouldNeverArmProtection = function () {
    try {
      const state = NS.state;
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit) {
        if (state._brandSpoofPortalDetected) NS.clearBrandSpoofFalsePositive("should-never-arm-icp");
        state._brandResourceMismatchDetected = false;
        return true;
      }
      if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()) {
        state._brandSpoofPortalDetected = false;
        state._brandResourceMismatchDetected = false;
        return true;
      }
      if (state._seoCloakKitDetected || state._brandSpoofPortalDetected || state._fakeSpaDetected || state._brandResourceMismatchDetected) {
        if (state._brandResourceMismatchDetected && (NS.looksLikeUltraMatureIcpDomain() || NS.looksLikeMatureOfficialPortal() || NS.looksLikeLongLivedWhoisDomain())) {
          state._brandResourceMismatchDetected = false;
        } else if (state._seoCloakKitDetected || state._fakeSpaDetected) {
          return false;
        } else if (state._brandSpoofPortalDetected && NS.looksLikeLongLivedWhoisDomain()) {
          state._brandSpoofPortalDetected = false;
          state.spoofBrand = "";
        } else if (state._brandSpoofPortalDetected) {
          return false;
        }
      }
      if (NS.looksLikeMatureOfficialPortal()) return true;
      if (NS.looksLikeLongLivedWhoisDomain()) {
        try {
          const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          const t = (document.title || "").toLowerCase();
          if (lab.length >= 4 && t.includes(lab)) return true;
        } catch { /* ignore */ }
      }
      return false;
    } catch { return false; }
  };

  NS.pageClaimsOfficialDownload = function () {
    const title = document.title || "";
    const text = ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, 4000);
    const blob = `${title} ${text}`;
    if (!/官网|官方下载|官方正版|官方网站|官方客户端|正版下载|下载中心|全平台官方|全平台.*下载|官方.*下载/.test(blob)) return false;
    if (typeof NS.pageLooksLikeThirdPartyBrandProxyOrMirror === "function" && NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) {
      return /官网|官方下载|官方正版|官方网站|官方客户端|正版下载|全平台官方/i.test(title) && !/加速|代理|镜像|proxy|mirror/i.test(title);
    }
    return true;
  };

  NS.pageLooksLikeThirdPartyBrandProxyOrMirror = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      const title = (document.title || "").trim();
      const og = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
      const siteName = document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "";
      const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
      const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(1500) : "";
      const id = `${title} ${og} ${siteName} ${String(desc).slice(0, 360)} ${headings}`.replace(/\s+/g, " ");
      if (/官方下载|官方正版|官网下载|官方网站|官方客户端/i.test(title) && !/加速|代理|镜像|proxy|mirror|cdn/i.test(title)) return false;
      if (/官网|官方下载|官方正版|官方网站|官方客户端|正版下载/i.test(id) && !/(?:加速|代理|镜像|proxy|mirror).{0,10}(?:下载|服务|工具|站|访问)|(?:下载|访问|资源).{0,8}(?:加速|代理)|加速下载代理|download\s*proxy/i.test(id)) return false;
      const proxyIdentity = /加速下载|下载加速|下载代理|访问代理|资源加速|文件加速|静态资源加速|clone\s*加速|git\s*clone|镜像站|镜像加速|代理服务|proxy\s*service|download\s*proxy|cdn\s*加速|解决.{0,16}(?:访问|下载)|快速访问\s*[A-Za-z一-鿿]/i.test(id)
        || /[A-Za-z][a-zA-Z]{2,}.{0,12}(?:加速|代理|镜像|proxy|mirror)/i.test(`${title} ${og} ${siteName}`)
        || /(?:加速|代理|镜像|proxy|mirror).{0,12}[A-Za-z][a-zA-Z]{2,}/i.test(`${title} ${og} ${siteName}`)
        || /加速下载代理|下载加速代理|GitHub\s*Proxy|ghproxy|gh-proxy/i.test(id);
      if (!proxyIdentity) return false;
      const host = (location.hostname || "").toLowerCase();
      const label = (host.split(".")[0] || "");
      const proxyHostShape = /proxy|mirror|cdn|accel|ghproxy|gh-proxy|gitclone|npmmirror|jsdelivr|fastgit|gitmirror|ghproxy/i.test(host) || /proxy|mirror|cdn|加速|镜像|代理|ghproxy|ghproxy/i.test(label);
      const toolish = proxyHostShape || /代理|加速|镜像|proxy|mirror|工具|服务/i.test(`${title} ${siteName} ${og}`) || /支持\s*(?:Releases|Raw|Archive|clone)|Releases|Raw|Archive/i.test(id);
      return !!(proxyIdentity && toolish);
    } catch { return false; }
  };

  NS.pageClaimsBrandDownloadLanding = function () {
    if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
    if (NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
    if (NS.pageClaimsOfficialDownload()) return true;
    try {
      const title = document.title || "";
      if (/[-–|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title)) return false;
      const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(3000) : "";
      const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
      const og = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
      const claim = `${title} ${headings} ${og}`;
      const body = ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").trim().slice(0, 5000);
      const blob = `${claim} ${String(desc).slice(0, 400)} ${body}`;
      if (/客户端\s*完全\s*免费|客户端永久免费|免费下载|开始使用\s*[A-Za-z]{3,}|电脑版官网|官方桌面/i.test(claim) || /下载\s*(?!代理|加速|镜像)[A-Za-z一-鿿]{2,20}/i.test(claim) || /客户端\s*完全\s*免费|客户端永久免费|开始使用\s*[A-Za-z]{3,}/i.test(blob)) {
        if (/免费下载/i.test(blob) && !/客户端|安装包|官方|开始使用|全平台|电脑版/i.test(claim + blob.slice(0, 500))) { /* weak */ }
        else if (/下载(?:代理|加速|镜像)|加速下载|代理服务/i.test(claim) && !/官方|客户端|安装包|官网/i.test(claim)) { /* proxy */ }
        else return true;
      }
      if (/全平台覆盖|全平台免费|无需绑定.*下载|即刻开始|安装客户端/i.test(claim + blob.slice(0, 800)) && /下载|客户端|安装包|\.zip|\.exe/i.test(blob)) return true;
      const html = NS.getHtmlSlice(80000);
      if (/"@type"\s*:\s*"SoftwareApplication"/i.test(html) && (/downloadUrl|operatingSystem/i.test(html) || /"price"\s*:\s*"0"/i.test(html))) return true;
      const pkgCtas = Array.from(document.querySelectorAll("a[href], button")).filter((el) => { const h = el.getAttribute("href") || ""; return NS.isPackageFileUrl(h); });
      if (pkgCtas.length >= 1 && /[A-Za-z]{4,}/.test(title)) return true;
      return false;
    } catch { return false; }
  };

  NS.hasEncryptedNuxtDownloadConfig = function (html) {
    const h = String(html || "").replace(/data:(?:image|font|application)\/[^;,"]+;base64,[A-Za-z0-9+/=]+/gi, "");
    const dlKeyHits = (h.match(/["']?(?:windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload)["']?\s*:/gi) || []).length;
    const hasDlKeys = dlKeyHits >= 1 || /["'](?:windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload)["']/i.test(h) || /\b(?:windowsDownload|macDownload|androidDownload)\b/i.test(h);
    if (!hasDlKeys) return false;
    const adjacent = (h.match(/["']?(?:windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload)["']?\s*:\s*["'](?!https?:\/\/|\/)[A-Za-z0-9+/]{24,}={0,2}["']/gi) || []).length;
    const paddedB64 = (h.match(/["'][A-Za-z0-9+/]{32,}={1,2}["']/g) || []).length;
    const longB64 = (h.match(/["'][A-Za-z0-9+/]{48,}={0,2}["']/g) || []).length;
    const multiPlatformKeys = dlKeyHits >= 2 || ((h.match(/windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload/gi) || []).length >= 3);
    const hasPlainHttpsPackages = /https?:\/\/[^\s"'<>\\]+?\.(?:exe|dmg|pkg|apk|zip)/i.test(NS.unescapeHtmlForScan(h));
    if (hasPlainHttpsPackages && NS.countTransparentProductPackages(h) >= 1) return false;
    if (adjacent >= 1) return true;
    if (paddedB64 >= 2 || longB64 >= 2) return true;
    if (multiPlatformKeys && (paddedB64 >= 1 || longB64 >= 1 || /["'][A-Za-z0-9+/]{40,}["']/.test(h))) return true;
    if (dlKeyHits >= 1 && (paddedB64 >= 1 || longB64 >= 1 || /["'][A-Za-z0-9+/]{36,}={0,2}["']/.test(h))) return true;
    return false;
  };

  NS.countTransparentProductPackages = function (html) {
    const h = NS.unescapeHtmlForScan(html);
    let count = 0;
    const seen = new Set();
    const pkgUrlRe = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|pkg|deb|rpm)(?:\?[^\s"'<>\\]*)?/gi;
    let m;
    while ((m = pkgUrlRe.exec(h)) !== null) {
      const full = m[0];
      try { if (NS.looksLikeHighRiskBlobPackageUrl(full)) continue; } catch { /* ignore */ }
      const name = NS.normalizeFileName(full);
      if (seen.has(name)) continue;
      if (NS.isBenignShortInstallerName(name) || NS.isClearProductOrAndroidPackage(name) || NS.looksLikeAndroidPackageIdName(name)) { seen.add(name); count++; continue; }
      if ((NS.looksLikeStrongProductInstallerName(name) || NS.looksLikeProductPackageName(name)) && NS.packageFilenameSharesPageBrand(name)) { seen.add(name); count++; }
    }
    const pathRe = /\/([A-Za-z][A-Za-z0-9._-]{2,80}\.(?:exe|dmg|pkg|apk|zip|deb|rpm))/g;
    while ((m = pathRe.exec(h)) !== null) {
      const name = NS.normalizeFileName(m[1]);
      if (seen.has(name)) continue;
      if (NS.isBenignShortInstallerName(name) || NS.isClearProductOrAndroidPackage(name) || NS.looksLikeAndroidPackageIdName(name)) { seen.add(name); count++; continue; }
      if ((NS.looksLikeStrongProductInstallerName(name) || NS.looksLikeProductPackageName(name)) && NS.packageFilenameSharesPageBrand(name)) { seen.add(name); count++; }
    }
    const androidRe = /\b((?:[a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*(?:[._-]\d{2,16})?\.apk)\b/gi;
    while ((m = androidRe.exec(h)) !== null) {
      const name = NS.normalizeFileName(m[1]);
      if (NS.isClearProductOrAndroidPackage(name) && !seen.has(name)) { seen.add(name); count++; }
    }
    return count;
  };

  NS.hasDynamicSharedDownloadUriBinding = function (html) {
    const h = String(html || "");
    const hasGlobalUri = /window\.download_uri\b|download_uri\s*=\s*|var\s+download_uri\b|let\s+download_uri\b|const\s+download_uri\b/i.test(h) || /window\.(?:downloadUrl|downloadURL|down_url|dl_url|packageUrl)\s*=/i.test(h);
    if (!hasGlobalUri) return false;
    const multiAssign = /getElementsByClassName\s*\(\s*['"]download-uri['"]\s*\)/i.test(h) || /querySelectorAll\s*\(\s*['"][^'"]*download-uri[^'"]*['"]\s*\)/i.test(h) || /initDownloadLinks/i.test(h)
      || (/downloadElements/i.test(h) && /\.href\s*=\s*window\.download_uri|location\.href\s*=\s*window\.download_uri/i.test(h))
      || (/\.href\s*=\s*window\.download_uri/i.test(h) && /for\s*\s*\(/i.test(h));
    return multiAssign || (/download_uri/i.test(h) && /downloadElements\.length|for\s*\(\s*let\s+i\s*=\s*0/i.test(h));
  };

  NS.hostBelongsToBrandApex = function (hostname, brandApex) {
    const h = String(hostname || "").toLowerCase().replace(/^www\./, "");
    const a = String(brandApex || "").toLowerCase().replace(/^www\./, "");
    if (!h || !a) return false;
    return h === a || h.endsWith(`.${a}`);
  };

  NS.hasAuthorBrandHostMismatch = function () {
    try {
      if (!/官网|官方下载|官方网站|官方正版|官网下载/.test(document.title || "")) return false;
      const author = (document.querySelector('meta[name="author"]')?.getAttribute("content") || "").trim();
      const fromAuthor = author.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i);
      if (!fromAuthor) return false;
      const brandApex = NS.guessApexDomain(fromAuthor[1]);
      if (!brandApex) return false;
      if (NS.hostBelongsToBrandApex(location.hostname, brandApex)) return false;
      return true;
    } catch { return false; }
  };

  NS.hasWeakAntiAnalysisMarkers = function (htmlOrBlob) {
    const blob = String(htmlOrBlob || "");
    const blockContext = /oncontextmenu\s*=\s*["']return\s+false|addEventListener\s*\(\s*["']contextmenu["']/i.test(blob) && /preventDefault|return\s+false/i.test(blob);
    const blockF12 = /keyCode\s*===?\s*123|key\s*===?\s*["']F12["']|which\s*===?\s*123/i.test(blob) || (/keydown|keypress/i.test(blob) && /F12|ctrlKey.*[isu]|devtools/i.test(blob) && /preventDefault/i.test(blob));
    const blankRedirect = /about:blank/i.test(blob) && (blockF12 || blockContext || /location\s*(?:\.href\s*)?=\s*["']about:blank|location\.replace\s*\(\s*["']about:blank/i.test(blob));
    const antiDebug = /\bdebugger\b/.test(blob) && /setInterval|setTimeout/i.test(blob);
    return !!(blockContext || blockF12 || blankRedirect || antiDebug);
  };

  NS.hasStrongAntiAnalysisMarkers = function (htmlOrBlob) {
    const blob = String(htmlOrBlob || "");
    const blockContextHard = /oncontextmenu\s*=\s*["']return\s+false/i.test(blob) || /addEventListener\s*\(\s*["']contextmenu["']\s*,\s*(?:function|\([^)]*\)\s*=>)[\s\S]{0,180}preventDefault/i.test(blob) || /oncontextmenu\s*=\s*function[\s\S]{0,80}return\s+false/i.test(blob) || /oncontextmenu\s*=\s*["'][^"']*return\s*!?\s*1?\s*false/i.test(blob) || /contextmenu[\s\S]{0,80}preventDefault/i.test(blob);
    const f12ToBlank = (/keyCode\s*===?\s*123|which\s*===?\s*123|key\s*===?\s*["']F12["']|["']F12["']\s*===?\s*\w+\.key/i.test(blob)) && /about:blank/i.test(blob);
    const f12Block = (/keyCode\s*===?\s*123|which\s*===?\s*123|key\s*===?\s*["']F12["']/i.test(blob) || /\bF12\b/.test(blob) && /keydown|keyCode|which/.test(blob)) && /preventDefault|return\s*!?\s*1?\s*false|stopPropagation/i.test(blob);
    const locationBlank = /(?:location\s*(?:\.href\s*)?=\s*["']about:blank|location\.replace\s*\(\s*["']about:blank)/i.test(blob) && (/keyCode\s*===?\s*123|F12|contextmenu|devtools/i.test(blob));
    const debuggerTrap = (/\bdebugger\b/.test(blob) && /setInterval\s*\(|setTimeout\s*\(/i.test(blob)) || /Function\s*\(\s*['"`][^'"`]*debugger/i.test(blob) || /constructor\s*\(\s*['"`]debugger['"`]\s*\)/i.test(blob) || (/\bdebugger\b/.test(blob) && /while\s*\(\s*(?:true|1)\s*\)/i.test(blob));
    const devtoolsDetect = /devtools|outerWidth\s*-\s*innerWidth|Firebug|__REACT_DEVTOOLS/i.test(blob) && (/debugger|about:blank|location\s*\.\s*href|close\s*\(/i.test(blob));
    return !!(blockContextHard || f12ToBlank || f12Block || locationBlank || debuggerTrap || devtoolsDetect);
  };

  NS.collectPageScriptScanBlob = function (maxLen = 120000) {
    try { return NS.getThreatScanHtml(maxLen); } catch { return ""; }
  };

  NS.looksLikeSelfConsistentOfficialSite = function () {
    try {
      const pageApex = NS.guessApexDomain(location.hostname);
      if (!pageApex) return false;
      const htmlSlice = NS.getThreatScanHtml(140000);
      if (NS.hasEncryptedNuxtDownloadConfig(htmlSlice) && NS.countTransparentProductPackages(htmlSlice) === 0) return false;
      const hasBlobPkg = Array.from(document.querySelectorAll("a[href], a[data-href]")).some((a) => {
        const h = (a.getAttribute("href") || a.getAttribute("data-href") || "").trim();
        if (!h) return false;
        const fn = NS.getFilenameFromUrl(h);
        if (NS.isClearProductOrAndroidPackage(fn) || NS.looksLikeProductPackageName(fn)) return NS.looksLikeHighRiskBlobPackageUrl(h);
        return NS.looksLikeObjectStoragePackageUrl(h) || NS.looksLikeHighRiskBlobPackageUrl(h);
      });
      if (hasBlobPkg) return false;
      const hreflangCount = document.querySelectorAll('link[rel="alternate"][hreflang]').length;
      const htmlHead = NS.getHtmlSlice(40000);
      const enterpriseCms = /etc\.clientlibs|adobe-launch|onetrust|data-domain-script|NVIDIAGDC|sitecore|aem-/i.test(htmlHead);
      const hasHardSignal = hreflangCount >= 3 || enterpriseCms || NS.countTransparentProductPackages(htmlSlice) >= 1;
      if (!hasHardSignal) return false;
      let hits = 0;
      const canonical = document.querySelector('link[rel="canonical"]')?.getAttribute("href");
      if (canonical) { try { if (NS.guessApexDomain(new URL(canonical, location.href).hostname) === pageApex) hits += 2; } catch { /* ignore */ } }
      const ogUrl = document.querySelector('meta[property="og:url"]')?.getAttribute("content") || document.querySelector('meta[property="og:url"]')?.content;
      if (ogUrl) { try { if (NS.guessApexDomain(new URL(ogUrl, location.href).hostname) === pageApex) hits += 2; } catch { /* ignore */ } }
      if (hreflangCount >= 5) hits += 3; else if (hreflangCount >= 3) hits += 2;
      let sameOriginAssets = 0;
      document.querySelectorAll('script[src], link[rel="stylesheet"][href], link[rel="preload"][href]').forEach((el) => {
        try { const raw = el.src || el.href || el.getAttribute("href") || ""; if (!raw) return; if (NS.guessApexDomain(new URL(raw, location.href).hostname) === pageApex) sameOriginAssets++; } catch { /* ignore */ }
      });
      if (sameOriginAssets >= 6) hits += 2; else if (sameOriginAssets >= 3) hits += 1;
      if (enterpriseCms && sameOriginAssets >= 2) hits += 2;
      const textLen = ((document.body && document.body.innerText) || "").length;
      if (textLen > 2000) hits += 1;
      return hits >= 5;
    } catch { return false; }
  };

  NS.looksLikeOfficialBrandDownloadPage = function (html) {
    try {
      const full = html ? String(html).slice(0, 120000) : NS.getHtmlSlice(100000);
      const h = NS.unescapeHtmlForScan(full);
      if (NS.countTransparentProductPackages(h) >= 1) return true;
      const fieldRe = /"[A-Za-z0-9_]*Download(?:Link|Url|URI|Path)?"\s*:\s*"(https?:\/\/[^"]+\.(?:exe|dmg|pkg|apk|msi|zip|deb|rpm))"/gi;
      let fm; let structuredProductPkgs = 0;
      while ((fm = fieldRe.exec(h)) !== null) {
        const url = fm[1];
        try { if (NS.looksLikeObjectStorageHost(new URL(url).hostname)) continue; } catch { /* ignore */ }
        if (NS.looksLikeProductPackageName(NS.normalizeFileName(url))) structuredProductPkgs++;
      }
      if (structuredProductPkgs >= 1) return true;
      const author = (document.querySelector('meta[name="author"]')?.getAttribute("content") || "").trim();
      const fromAuthor = author.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i);
      const identityOk = fromAuthor && NS.hostBelongsToBrandApex(location.hostname, NS.guessApexDomain(fromAuthor[1]));
      if (identityOk && !NS.hasDynamicSharedDownloadUriBinding(h)) {
        const pkgRe = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|pkg|deb|rpm)/gi;
        let pm;
        while ((pm = pkgRe.exec(h)) !== null) {
          try { if (NS.looksLikeObjectStorageHost(new URL(pm[0]).hostname)) continue; } catch { /* ignore */ }
          if (NS.looksLikeProductPackageName(NS.normalizeFileName(pm[0]))) return true;
        }
      }
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      return false;
    } catch { return false; }
  };

  NS.looksLikeOfficialClientDownloadPage = function () {
    const title = (document.title || "").trim();
    const titleOk = /(客户端|下载|APP|应用|Android|iOS|电脑版|Mac|远程)/i.test(title);
    if (!titleOk) return false;
    try {
      const html = NS.getHtmlSlice(120000);
      if (typeof NS.hasEncryptedNuxtDownloadConfig === "function" && NS.hasEncryptedNuxtDownloadConfig(html) && NS.countTransparentProductPackages(html) === 0) return false;
      if (typeof NS.countTransparentProductPackages === "function" && NS.countTransparentProductPackages(html) >= 1) return true;
    } catch { /* ignore */ }
    const hasSpaRoot = !!document.querySelector("#root, #app, #__next, #__nuxt, #ice-container, [data-reactroot]");
    const scripts = Array.from(document.scripts).filter((s) => s.src);
    if (scripts.length < 2) return false;
    let stableAsset = 0; let randomAsset = 0;
    scripts.forEach((s) => {
      try {
        const h = new URL(s.src, location.href).hostname.toLowerCase();
        const label = (h.split(".")[0] || "").replace(/-/g, "");
        const depth = h.split(".").length;
        const randomish = depth <= 2 && (/^[a-z0-9]{10,}$/i.test(label) && /\d/.test(label) && /[a-z]/i.test(label));
        if (randomish) randomAsset++; else if (depth >= 3 || /cdn|static|img|asset|media|res\d*/i.test(h)) stableAsset++; else stableAsset++;
      } catch { /* ignore */ }
    });
    if (randomAsset > 0 && randomAsset >= stableAsset) return false;
    const packageHrefs = Array.from(document.querySelectorAll("a[href], a[data-href]")).map((a) => (a.getAttribute("href") || a.getAttribute("data-href") || "").trim()).filter((h) => NS.isPackageFileUrl(h));
    if (packageHrefs.some((h) => NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(h)))) return false;
    if (packageHrefs.some((h) => NS.looksLikeObfuscatedPhpDownloadUrl(h))) return false;
    const hiddenIframes = Array.from(document.querySelectorAll("iframe")).filter((f) => {
      try { const st = getComputedStyle(f); return st.display === "none" || st.visibility === "hidden" || f.width === "0" || f.height === "0"; } catch { return false; }
    }).length;
    if (hasSpaRoot && stableAsset >= 2 && randomAsset === 0) return true;
    if (titleOk && stableAsset >= 3 && packageHrefs.every((h) => NS.looksLikeProductPackageName(NS.getFilenameFromUrl(h)) || !NS.getFilenameFromUrl(h))) return true;
    void hiddenIframes;
    return false;
  };

  NS.pageLooksLikeLegitimateOfficialDownload = function () {
    try {
      try { const corr = NS.evaluateTitleHostBrandCorrelation(); if (corr && corr.mismatch) return false; } catch { /* ignore */ }
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) return false;
      const full = NS.getHtmlSlice(100000);
      if (!full || full.length < 200) return false;
      if (NS.countTransparentProductPackages(full) >= 1) return true;
      const fieldRe = /"[A-Za-z0-9_]*Download(?:Link|Url|URI|Path)?"\s*:\s*"(https?:\/\/[^"]+\.(?:exe|dmg|pkg|apk|msi|zip|deb|rpm))"/gi;
      let fm;
      while ((fm = fieldRe.exec(full)) !== null) {
        try { if (NS.looksLikeObjectStorageHost(new URL(fm[1]).hostname)) continue; } catch { /* ignore */ }
        if (NS.looksLikeProductPackageName(NS.normalizeFileName(fm[1]))) return true;
      }
      if (/window\.__DATA__\s*=/.test(full) && /DownloadLink|downloadLink|installer|win_installer/i.test(full) && /https?:\/\/[^"'\\]+\.(?:exe|dmg|msi|pkg)/i.test(full) && NS.countTransparentProductPackages(full) >= 1) return true;
      const iceOrSpa = !!document.querySelector("#ice-container, #root, #app, #__next, #__nuxt");
      const hasTryAgain = !!document.querySelector("a.tryAgain, .hasDownload a[href], .download-success a[href], a[href*='/win/'], a[href*='/mac/']");
      const sameSiteDl = Array.from(document.querySelectorAll("a[href]")).some((a) => { const h = (a.getAttribute("href") || "").trim(); return h && NS.looksLikeOfficialProductDownloadEndpoint(h); });
      const scripts = Array.from(document.scripts || []).filter((s) => s.src).length;
      if (iceOrSpa && (hasTryAgain || sameSiteDl) && scripts >= 3 && /下载|客户端|官方/i.test(document.title || "")) return true;
      if (NS.looksLikeOfficialBrandDownloadPage(full)) return true;
      if (NS.looksLikeOfficialClientDownloadPage()) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      return false;
    } catch { return false; }
  };

  NS.isTrustedOfficialDownloadContext = function () {
    try {
      if (NS.hostLooksLikeBrandMarketingSpoof()) return false;
      if (NS.looksLikeMatureOfficialPortal()) return true;
      if (typeof NS.pageLooksLikeLegitimateOfficialDownload === "function" && NS.pageLooksLikeLegitimateOfficialDownload()) return true;
      if (NS.looksLikeOfficialBrandDownloadPage()) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      if (NS.looksLikeOfficialClientDownloadPage()) return true;
      const pageApex = NS.getRegistrableDomain(location.hostname);
      if (!pageApex) return false;
      let sameApexAssets = 0;
      try {
        document.querySelectorAll('script[src], link[rel="stylesheet"][href], link[rel="preconnect"][href]').forEach((el) => {
          try { const raw = el.src || el.href || ""; const h = NS.getRegistrableDomain(new URL(raw, location.href).hostname); if (h === pageApex) sameApexAssets++; } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
      const title = document.title || "";
      const headText = `${title} ${(document.querySelector('meta[name="description"]')?.content || "")}`.slice(0, 500);
      const brandish = /安全|杀毒|防护|下载|产品|软件|客户端|企业|官网|官方/i.test(headText);
      const whoisOld = /已注册\s*(\d+)\s*天/.exec(NS.state.whoisInfo || "");
      const days = whoisOld ? parseInt(whoisOld[1], 10) : null;
      const hasIcp = !!(NS.state.icpInfo && !/未查询到/.test(NS.state.icpInfo));
      if (sameApexAssets >= 3 && brandish) return true;
      if (hasIcp && days != null && days >= 365 && brandish) return true;
      if (hasIcp && days != null && days >= 365 && sameApexAssets >= 2) return true;
      return false;
    } catch { return false; }
  };

  NS.looksLikeSafeOfficialContext = function () {
    try {
      const state = NS.state;
      if (state._seoCloakKitDetected || state._brandSpoofPortalDetected || state._fakeSpaDetected) return false;
      try {
        const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const claim = typeof NS.collectTitleAndHeadingClaimText === "function" ? NS.collectTitleAndHeadingClaimText() : (document.title || "");
        const squat = typeof NS.titleBrandVsHostSquatShape === "function" ? NS.titleBrandVsHostSquatShape(claim, lab, "") : "";
        if (squat === "padded" || squat === "typo" || squat === "hyphen") return false;
      } catch { /* ignore */ }
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) return false;
      try {
        const title = document.title || "";
        const claimText = typeof NS.collectTitleAndHeadingClaimText === "function" ? NS.collectTitleAndHeadingClaimText() : title;
        const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        const labelRaw = (host.split(".")[0] || "").toLowerCase();
        const label = labelRaw.replace(/-/g, "");
        const footerId = typeof NS.footerCopyrightMatchesPageHost === "function" ? NS.footerCopyrightMatchesPageHost() : { match: false, hits: 0 };
        const squat2 = typeof NS.titleBrandVsHostSquatShape === "function" ? NS.titleBrandVsHostSquatShape(claimText, labelRaw, "") : "";
        if (footerId.match && squat2 !== "padded" && squat2 !== "typo" && squat2 !== "hyphen" && squat2 !== "partial") {
          if (/^\d{3,4}$/.test(label) || (label.length >= 3 && claimText.toLowerCase().includes(label) && !/-/.test(labelRaw))) return true;
        }
        if ((/官网|官方网站|官方下载|安全中心/i.test(claimText) || footerId.hits >= 1) && label.length >= 2) {
          const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const footerText = (footerId.text || "");
          const hits = (claimText.match(new RegExp(esc, "gi")) || []).length + (footerText.match(new RegExp(esc, "gi")) || []).length;
          if (hits >= 2) {
            let sameFamily = 0;
            const pageApex = NS.getRegistrableDomain(host);
            document.querySelectorAll('script[src], link[href], img[src]').forEach((el) => {
              try {
                const raw = el.src || el.href || "";
                if (!raw || raw.startsWith("data:")) return;
                const ah = new URL(raw, location.href).hostname.toLowerCase();
                const aApex = NS.getRegistrableDomain(ah);
                if (pageApex && aApex === pageApex) sameFamily++;
                else if (label.length >= 3 && ah.replace(/[^a-z0-9]/g, "").includes(label.replace(/[^a-z0-9]/g, ""))) sameFamily++;
              } catch { /* ignore */ }
            });
            if (squat2 === "padded" || squat2 === "typo" || squat2 === "hyphen") { /* not safe */ }
            else {
              if (sameFamily >= 4) return true;
              if (/^\d{3,4}$/.test(label) && hits >= 3) return true;
              if (footerId.hits >= 2 && /版权所有|Copyright/i.test(footerText) && (claimText.toLowerCase().includes(label) || /^\d{3,4}$/.test(label)) && !/-/.test(labelRaw)) return true;
            }
          }
        }
      } catch { /* ignore */ }
      try {
        const threatHtml = NS.getThreatScanHtml(120000);
        if (NS.hasEncryptedNuxtDownloadConfig(threatHtml) && NS.countTransparentProductPackages(threatHtml) === 0) return false;
      } catch { /* ignore */ }
      if (NS.looksLikeMatureOfficialPortal()) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      if (NS.looksLikeOfficialBrandDownloadPage()) return true;
      const title = document.title || "";
      const textLen = ((document.body && document.body.textContent) || "").replace(/\s+/g, "").length;
      const htmlQuick = NS.getThreatScanHtml(80000);
      const hasTransparent = NS.countTransparentProductPackages(htmlQuick) >= 1;
      if (!hasTransparent) {
        if (NS.looksLikeMatureOfficialPortal()) return true;
        return false;
      }
      if (/官网|官方网站|安全中心|集团/i.test(title) && textLen >= 800 && hasTransparent) return true;
      if (/官网|官方下载/i.test(title) && textLen >= 1500 && hasTransparent) return true;
      const hasIcp = !!(NS.state.icpInfo && String(NS.state.icpInfo).trim() && !/未查询到|查询失败|暂无/.test(NS.state.icpInfo));
      if (hasIcp && textLen >= 500 && /官网|官方|下载|安全|软件/i.test(title) && hasTransparent) return true;
      return false;
    } catch { return false; }
  };
})(window.SilverfoxContent ??= {});
