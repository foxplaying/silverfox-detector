/**
 * 品牌仿冒下载门户检测：标题宣称官网 + 域名与品牌不匹配 + 可疑安装包/下载入口。
 * 硬前提：必须通过「软件下载落地页壳」门控（与下载页检测逻辑绑死），资讯/博客不 arm。
 * 软仿冒（pad/typo/hyphen）须等 ICP 定论后再 toast，避免 todeskai 沪ICP 误报。
 */
;(function (NS) {
  "use strict";

  /**
   * 仿冒「中文产品官网首页」快速路径：
   * - 火绒标题 + 免费下载（+ 可选 download.html）
   * - 或 huorong-pc / im-todesk 类营销夹带主机 + 下载 CTA
   * 不依赖完整 corr / 不等 ICP（夹带下载站立即 arm）。
   */
  NS.tryArmChineseBrandDownloadHomeSpoof = function () {
    try {
      const state = NS.state;
      if (state.downloadGuardInstalled && state._brandSpoofPortalDetected) return true;
      // 真备案且非硬套件：仍放过（todeskai 类）
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._desktopForceDlKit) return false;
      if (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature()) return false;
      // 第三方软件门户详情（中华网软件等）：不是仿冒产品官网
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) return false;
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) return false;

      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const lab = labelRaw.replace(/-/g, "");
      const core = typeof NS.inferMarketingPaddedBrandCore === "function"
        ? (NS.inferMarketingPaddedBrandCore(labelRaw) || "")
        : "";
      const isPaddedHost = !!(core && core.length >= 4 && (
        (typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lab, core))
        || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, core))
        || /[-_](pc|app|soft|safe|vip|pro|cn|win|download|client|free|official)$/i.test(labelRaw)
        || /^(pc|app|get|im|aa|ca|download|soft)[-_]/i.test(labelRaw)
      ));
      // 真品牌根域 huorong.com（无夹带后缀）→ 不走此路径
      const isExactBrandApex = !isPaddedHost && !/[-_]/.test(labelRaw)
        && /^(huorong|hongrong|qihoo|sogou|baidu|tencent|dingtalk|todesk|sunlogin|oray|kingsoft|rising)$/i.test(lab);
      if (isExactBrandApex) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-exact-apex", lab);
        return false;
      }
      try {
        if (typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex(host)) {
          return false;
        }
      } catch { /* ignore */ }

      const title = (document.title || "").trim();
      let keywords = "";
      try {
        keywords = document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "";
        if (!keywords) {
          for (const el of Array.from(document.querySelectorAll("meta")).slice(0, 40)) {
            const n = String(el.getAttribute("name") || "").toLowerCase();
            if (n === "keywords" || n.includes("keyword")) {
              keywords = el.getAttribute("content") || "";
              if (keywords) break;
            }
          }
        }
      } catch { /* ignore */ }
      let brand = "";
      // title / og / description 先于 keywords（SEO 虚词「文章」绝不当展示品牌）
      if (typeof NS.pickChineseBrandFromPageSurface === "function") {
        const ogSite = document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "";
        const ogTitle = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
        const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
        brand = NS.pickChineseBrandFromPageSurface(title)
          || NS.pickChineseBrandFromPageSurface(ogSite)
          || NS.pickChineseBrandFromPageSurface(ogTitle)
          || NS.pickChineseBrandFromPageSurface(desc)
          || NS.pickChineseBrandFromPageSurface(document.querySelector("h1")?.textContent || "")
          || NS.pickChineseBrandFromPageSurface(keywords)
          || "";
      }
      if ((!brand || brand.length < 2) && typeof NS.pickChineseBrandFromIdentityConsensus === "function") {
        brand = NS.pickChineseBrandFromIdentityConsensus() || "";
      }
      if (!brand || brand.length < 2) {
        // 扫整段 title 取数字前缀产品；勿用首段纯中文（文章-360… 会误取「文章」）
        const digit = (title.match(/(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
        if (digit && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(digit))) brand = digit;
        else {
          const segs = title.split(/\s*[-–—|:·｜]\s*/).map((p) => p.trim()).filter(Boolean);
          for (const seg of segs) {
            const m = (seg.match(/^([一-鿿]{2,6})/) || [])[1] || "";
            if (!m) continue;
            if (/^(安全|软件|下载|官方|电脑|系统|工具|安静|纯净|强悍|免费|最新|文章|专题|详情|导读|正文)$/.test(m)) continue;
            if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(m)) continue;
            brand = m;
            break;
          }
        }
      }
      if (brand && typeof NS.trimChineseBrandTrail === "function") brand = NS.trimChineseBrandTrail(brand) || brand;
      // 弱词（文章）或裁残后仍弱 → 丢弃，勿 arm 仿冒「文章」
      if (brand && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)) brand = "";
      // 夹带域无中文时：用主机核心当拉丁展示（Huorong）
      if ((!brand || brand.length < 2) && isPaddedHost && core) {
        brand = typeof NS.formatBrandTokenForDisplay === "function"
          ? NS.formatBrandTokenForDisplay(core)
          : (core.charAt(0).toUpperCase() + core.slice(1));
      }
      if (!brand || brand.length < 2) return false;
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)
        && !isPaddedHost) return false;

      // 下载意图：CTA 文案 / download 路径 / 路径含 download
      let hub = 0;
      let dlCta = 0;
      try {
        document.querySelectorAll("a[href], a[data-href], button, .btn-header, .btn-primary, .btn-lg, [class*='download']").forEach((el) => {
          const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
          const text = (el.textContent || "").replace(/\s+/g, " ").trim();
          if (/免费下载|立即下载|立即免费下载|官方下载|个人版|企业版|客户端下载|下载中心|获取客户端/i.test(text)) dlCta++;
          else if (text.length <= 20 && /下载/.test(text)) dlCta++;
          if (href && /download\.html|(?:^|\/)download(?:\/|\.html?|$)|down\.html|install\.html/i.test(href)) hub++;
          if (href && typeof NS.looksLikeSameOriginLandingPageUrl === "function" && NS.looksLikeSameOriginLandingPageUrl(href)) hub++;
        });
      } catch { /* ignore */ }
      const pathDl = /download|down|install|client/i.test(location.pathname || "");
      const titleDl = /下载|官网|官方|客户端|安静|纯净|强悍/i.test(title + keywords);
      // 夹带域 huorong-pc.cn：中文品牌标题即足够 arm（不强制 download.html / CTA）
      // 非夹带域：须下载导流（hub 或双 CTA）
      if (isPaddedHost) {
        if (!/[一-鿿]{2,}/.test(brand) && dlCta < 1 && !titleDl) return false;
      } else if (dlCta < 1 || (hub < 1 && dlCta < 2)) {
        return false;
      }

      const matchHint = isPaddedHost ? "域名夹带品牌前缀/后缀" : "域名与品牌无关";
      state.spoofBrand = brand;
      state._brandSpoofPortalDetected = true;
      const noticeTitle = `已识别仿冒「${brand}」官网`;
      const noticeMsg = `域名 ${location.hostname || host} 与标题品牌「${brand}」不匹配，疑似仿冒官网下载站`;
      NS.addSignal(
        "仿冒品牌官网下载站",
        24,
        `标题/正文品牌「${brand}」与域名 ${location.hostname || host} 不匹配（${matchHint}${isPaddedHost && core ? `，主机核心 ${core}` : ""}）；下载导流门户`
      );
      NS.installDownloadGuard(`仿冒品牌官网下载站（仿冒「${brand}」）`, {
        notify: true,
        href: "",
        message: noticeMsg,
        title: noticeTitle,
        guardKind: "brand-spoof",
        forceNotify: true,
        lockHard: true
      });
      NS.disableAllDownloadIntentControls();
      state._pendingSoftBrandSpoof = false;
      NS.silverfoxLog && NS.silverfoxLog(
        "brand-spoof", "home-fast-path", brand, host,
        isPaddedHost ? `padded:${core}` : "none",
        "cta=", dlCta, "hub=", hub
      );
      try {
        if (typeof NS.proactivelyProbeDownloadButtons === "function") {
          Promise.resolve().then(() => NS.proactivelyProbeDownloadButtons()).catch(() => {});
        }
      } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  NS.detectBrandSpoofDownloadPortal = function () {
    try {
      const state = NS.state;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
      // 应用商店/手机助手详情页（百度手机助手钉钉详情等）：商店分发 App，不是仿冒官网
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-app-market-listing");
        return false;
      }
      // 第三方软件下载门户详情（中华网软件 /soft/1109443.html）：分发站不是仿冒官网
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-software-catalog-portal");
        state._pendingSoftBrandSpoof = false;
        return false;
      }
      // 快速路径：火绒类首页 + download.html 导流（不卡 safe-official / 短域名 corr）
      if (typeof NS.tryArmChineseBrandDownloadHomeSpoof === "function" && NS.tryArmChineseBrandDownloadHomeSpoof()) {
        return true;
      }
      // 与下载页检测绑死：非软件下载落地页壳 → 永不仿冒 arm（含资讯博客）
      const landingShell = typeof NS.evaluateSoftwareDownloadLandingShell === "function"
        ? NS.evaluateSoftwareDownloadLandingShell()
        : null;
      if (!landingShell || !landingShell.ok) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-not-download-landing", landingShell || {});
        state._pendingSoftBrandSpoof = false;
        return false;
      }
      // Linux 发行版 ISO/镜像下载页（archlinux.org.cn 等）：非银狐 exe 仿冒壳
      if (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-os-distro-iso");
        return false;
      }
      // MCAPKS 类高密度版本归档站：非「官网仿冒壳」，跳过以免 querySelectorAll + 包扫描卡死
      if (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-high-volume-archive");
        return false;
      }
      // 禁止用 hostRoot.includes(brand) 早退：im-todesk / todeskai 含 todesk 会被误判成「同站」直接放弃
      try {
        const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const labFlat = lab0.replace(/-/g, "");
        const claim = `${document.title || ""} ${typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(600) : ""}`;
        const titleToks = NS.extractLatinBrandTokens(claim);
        // 仅文档/社区子域 + 主机根与标题品牌 exact 同名时跳过
        if (/^(wiki|docs?|help|manual|handbook|bbs|forum|forums|community|git|code|pkg|packages|aur)$/i.test(lab0)) {
          const hostRoot = NS.brandRootKeyFromHost(location.hostname);
          if (hostRoot.length >= 4 && titleToks.some((t) => t === hostRoot)) return false;
        }
        // 主机标签本身等于某标题品牌且非夹带/拼写仿冒 → 真官网形态
        if (labFlat.length >= 4 && titleToks.some((t) => t === labFlat)) {
          const squat = titleToks.some((t) => t.length >= 4 && (
            NS.hostLabelIsPaddedBrand(labFlat, t)
            || NS.hostLabelIsBrandTypo(labFlat, t)
            || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(lab0, t))
            || NS.hostLabelIsHyphenatedBrandMirror(lab0, t)
          ));
          if (!squat) return false;
        }
      } catch { /* ignore */ }
      // 自家品牌 apex 产品子域（shurufa.sogou.com）：非仿冒
      try {
        if (typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex()) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-product-subdomain-of-apex");
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      } catch { /* ignore */ }
      // 有效 ICP / 超成熟 WHOIS：永不走仿冒 toast（搜狗/百度等）
      if (NS.hasValidIcpRecord() || (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature())
        || NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()) {
        state._pendingSoftBrandSpoof = false;
        try {
          if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
            NS.forceLiftSoftProtectionForTrustedPortal("brand-spoof-skip-trusted");
          }
        } catch { /* ignore */ }
        return false;
      }
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit && !state._fakeBrandShellDetected && !state._remoteGarbleDlDetected) {
        state._pendingSoftBrandSpoof = false;
        return false;
      }
      if (NS.looksLikeUltraMatureWhoisDomain() || NS.looksLikeUltraMatureIcpDomain()) return false;
      if (NS.looksLikeLongLivedWhoisDomain()) {
        try {
          const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          const labFlat = lab.replace(/-/g, "");
          const claim = `${document.title || ""} ${typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(800) : ""}`.toLowerCase();
          // 仅主机标签完整出现在标题且无夹带形态时跳过（im-todesk 不会整段出现在标题）
          if (lab.length >= 4 && claim.includes(lab) && !claim.includes(lab.replace(/-/g, " "))) {
            const toks = NS.extractLatinBrandTokens(claim);
            const squat = toks.some((t) => t.length >= 4 && (
              NS.hostLabelIsPaddedBrand(labFlat, t)
              || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(lab, t))
            ));
            if (!squat) return false;
          }
        } catch { /* ignore */ }
      }
      const titleHostCorrEarly = NS.evaluateTitleHostBrandCorrelation();
      const isPadSquat = titleHostCorrEarly.hostMatch === "padded" || titleHostCorrEarly.hostMatch === "typo" || titleHostCorrEarly.hostMatch === "hyphen";
      // 下载落地壳 + 品牌/域名错配时，勿被 safe-official 误伤（仿冒火绒长文首页）
      const shellMismatchBypass = !!(landingShell && landingShell.ok && landingShell.hasHub
        && (titleHostCorrEarly.mismatch || titleHostCorrEarly.hostMatch === "none" || titleHostCorrEarly.hostMatch === "partial")
        && (titleHostCorrEarly.displayBrand || titleHostCorrEarly.brandToken));
      if (!isPadSquat && !shellMismatchBypass
        && (NS.looksLikeMatureOfficialPortal() || NS.shouldNeverArmProtection() || NS.looksLikeSafeOfficialContext())) {
        return false;
      }
      // 软夹带/拼写有硬套件或安装包证据时不因 ICP 直接放弃（仍可由下方 hardKit 路径 arm）
      if (isPadSquat && NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit && !state._fakeBrandShellDetected) return false;
      // exact 但实际是 padded/hyphen 的误标：若主机为 im-todesk 类，不要当 exact 跳过
      if (titleHostCorrEarly.rigorousMatch || titleHostCorrEarly.hostMatch === "exact") {
        try {
          const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          const br = titleHostCorrEarly.brandToken || "";
          if (br && (NS.hostLabelIsPaddedBrand(lab0.replace(/-/g, ""), br)
            || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(lab0, br))
            || NS.hostLabelIsBrandTypo(lab0.replace(/-/g, ""), br))) {
            titleHostCorrEarly.rigorousMatch = false;
            titleHostCorrEarly.hostMatch = NS.hostLabelIsBrandTypo(lab0.replace(/-/g, ""), br) ? "typo" : "padded";
            titleHostCorrEarly.mismatch = true;
          } else {
            return false;
          }
        } catch { return false; }
      }
      if (titleHostCorrEarly.brandToken && /^(lists?|issues?|code|files?|docs?|help|about|blog|news|pull|requests?|settings?|explore|topics?|stars?|forks?|actions?|security|projects?|wiki|people|teams?|marketplace|sponsors?|notifications?|collections?|templates?|template|examples?|getting|started|quickstart|guides?|tutorial|reference|api|sdk|cli|apps?|web|mobile|desktop|community|learn|changelog|status|careers|contact|terms|license|readme|aurora|generator|schema|inter|website)$/i.test(titleHostCorrEarly.brandToken)) {
        // CMS/泛词：尝试换成中文展示名或主机推断核心，而不是直接放弃检测
        const labFix0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const cnFix = (typeof NS.pickBrandDisplayName === "function"
          ? NS.pickBrandDisplayName({ title: document.title || "", displayBrand: titleHostCorrEarly.displayBrand, brandToken: "" })
          : "") || titleHostCorrEarly.displayBrand || "";
        const coreFix = typeof NS.inferMarketingPaddedBrandCore === "function" ? (NS.inferMarketingPaddedBrandCore(labFix0) || "") : "";
        if (cnFix && /[一-鿿]/.test(cnFix)) {
          titleHostCorrEarly.displayBrand = cnFix;
          titleHostCorrEarly.brandToken = coreFix || cnFix;
          titleHostCorrEarly.mismatch = true;
          if (coreFix && (NS.hostLabelIsPaddedBrand(labFix0.replace(/-/g, ""), coreFix) || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labFix0, coreFix)))) {
            titleHostCorrEarly.hostMatch = "padded";
          } else if (titleHostCorrEarly.hostMatch === "exact" || !titleHostCorrEarly.hostMatch) {
            titleHostCorrEarly.hostMatch = "none";
          }
        } else if (coreFix) {
          titleHostCorrEarly.brandToken = coreFix;
          titleHostCorrEarly.hostMatch = "padded";
          titleHostCorrEarly.mismatch = true;
        } else {
          return false;
        }
      }
      if (titleHostCorrEarly.brandToken && NS.BRAND_TOKEN_STOP_RE.test(String(titleHostCorrEarly.brandToken).toLowerCase()) && !/[一-鿿]/.test(titleHostCorrEarly.brandToken)) {
        const labFix = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const fixed = NS.pickBrandTokenForHost(NS.extractLatinBrandTokens(`${document.title || ""} ${typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(800) : ""}`), labFix)
          || (typeof NS.inferMarketingPaddedBrandCore === "function" ? NS.inferMarketingPaddedBrandCore(labFix) : "")
          || "";
        const cnFix2 = typeof NS.pickBrandDisplayName === "function"
          ? NS.pickBrandDisplayName({ title: document.title || "", displayBrand: titleHostCorrEarly.displayBrand, brandToken: fixed })
          : (titleHostCorrEarly.displayBrand || "");
        if (!fixed && !cnFix2) return false;
        titleHostCorrEarly.brandToken = fixed || cnFix2;
        titleHostCorrEarly.displayBrand = cnFix2 || titleHostCorrEarly.displayBrand || fixed;
        titleHostCorrEarly.brandHits = Math.max(titleHostCorrEarly.brandHits || 0, 10);
        if (fixed && NS.hostLabelIsBrandTypo(labFix.replace(/-/g, ""), fixed)) titleHostCorrEarly.hostMatch = "typo";
        else if (fixed && typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labFix, fixed)) titleHostCorrEarly.hostMatch = "padded";
        else if (fixed && NS.hostLabelIsPaddedBrand(labFix.replace(/-/g, ""), fixed)) titleHostCorrEarly.hostMatch = "padded";
        else if (/[一-鿿]/.test(cnFix2 || "")) titleHostCorrEarly.hostMatch = titleHostCorrEarly.hostMatch === "exact" ? "none" : (titleHostCorrEarly.hostMatch || "none");
        titleHostCorrEarly.mismatch = titleHostCorrEarly.hostMatch === "typo" || titleHostCorrEarly.hostMatch === "padded" || titleHostCorrEarly.hostMatch === "hyphen" || titleHostCorrEarly.hostMatch === "none";
      }

      const claimedCtx = NS.getClaimedBrandContext();
      const { brandSource, claimsOfficial, tokens } = claimedCtx;
      const productBrand = claimedCtx.productBrand || null;
      // 话术与落地壳绑死：落地壳 pitch 为主；claimsOfficial 仅在有壳证据时加持
      // CTA「免费下载」+ download.html 导流：landingShell.softPitch/ok 已覆盖仿冒火绒首页
      const officialPitch = !!(landingShell.pitch || landingShell.softPitch
        || ((claimsOfficial || NS.pageClaimsOfficialDownload() || NS.pageClaimsBrandDownloadLanding()
          || /官方下载|全平台官方|官方客户端|客户端下载|官方网站|客户端完全免费|开始使用|远程桌面|电脑版官网|免费下载_官方|官方桌面|下载中心|全平台客户端|官方安全|免费下载|立即免费下载/i.test(brandSource)
          || /下载中心|全平台|客户端下载|免费下载/i.test(document.title || ""))
          && (landingShell.shellScore >= 2 || landingShell.hardShell || landingShell.ctaCount >= 1 || landingShell.pkgCount >= 1 || landingShell.hasHub)));
      if (!officialPitch && tokens.size === 0 && !landingShell.ok) return false;
      // 无下载壳 pitch/硬壳时，即使有 brand token 也不走仿冒（防内容页）
      if (!landingShell.ok) return false;
      if (!officialPitch && !landingShell.hardShell && landingShell.pkgCount < 1 && !(landingShell.hasHub && landingShell.ctaCount >= 1)) return false;

      const titleHostCorr = titleHostCorrEarly;
      if (titleHostCorr.hostMatch === "serp") return false;
      if ((titleHostCorr.rigorousMatch || titleHostCorr.hostMatch === "exact") && titleHostCorr.hostMatch !== "padded" && titleHostCorr.hostMatch !== "typo" && titleHostCorr.hostMatch !== "hyphen") return false;

      const offsitePkgs = NS.findSuspiciousOffsitePackagesInPage();
      const hasBrandMismatchPkg = offsitePkgs.some((p) => NS.packageMismatchesPageBrand(p) || NS.looksLikeHiddenPackagePath(p));

      if (!titleHostCorr.mismatch && !hasBrandMismatchPkg && titleHostCorr.hostMatch !== "hyphen" && titleHostCorr.hostMatch !== "padded" && titleHostCorr.hostMatch !== "typo") {
        if (NS.looksLikeSelfConsistentOfficialSite()) return false;
        if (NS.looksLikeOfficialBrandDownloadPage()) return false;
      }

      const spoofHost = NS.hostLooksLikeBrandMarketingSpoof() || titleHostCorr.mismatch || titleHostCorr.hostMatch === "padded" || titleHostCorr.hostMatch === "typo" || titleHostCorr.hostMatch === "hyphen"
        || titleHostCorr.hostMatch === "none" || titleHostCorr.hostMatch === "partial";
      const downloadCtAs = Array.from(document.querySelectorAll(
        "a[href], a[data-href], a[data-url], button, [role='button'], [onclick], .btn-p, .btn-g, .nav-cta, .btn-header, .btn-download, .download-btn, a.download-btn, a.btn-primary, a.btn-lg"
      )).filter((el) => {
        const href = NS.getElementDownloadHref(el) || el.getAttribute("href") || "";
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        const cls = String(el.className || "");
        return NS.DOWNLOAD_TEXT.test(text) || /立即下载|免费下载|立即免费下载|立即使用|前往\s*App\s*Store|Windows\s*版|查看其他平台|下载中心|个人版/i.test(text)
          || /download\.php|download\.html|\/download/i.test(href) || NS.isPackageFileUrl(href) || /^download/i.test((href.split("/").pop() || ""))
          || /startDownload\s*\(|openDownloadModal/i.test(el.getAttribute("onclick") || "")
          || ((/download-btn|btn-download|btn-header|btn-primary|btn-lg/i.test(cls)) && text.length > 0 && text.length < 40 && /下载|免费|官方|客户端/i.test(text));
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
      const hasDownloadHub = downloadCtAs.some((el) => { const h = (el.getAttribute("href") || "").toLowerCase(); return /download\.html|\/download\/?$|download\.php/i.test(h); }) || /download\.html/i.test(location.pathname)
        || !!landingShell.hasHub;

      const hostSquat = titleHostCorr.hostMatch === "typo" || titleHostCorr.hostMatch === "padded" || titleHostCorr.hostMatch === "hyphen";
      const hostUnrelated = titleHostCorr.hostMatch === "none" || titleHostCorr.hostMatch === "partial";
      // titleBrandSpoof 必须带下载壳证据（CTA/包/hub/硬壳），禁止「仅品牌词 + 无关域名」
      // brandToken 可能为空而 displayBrand=火绒（纯中文标题）
      const brandIdForSpoof = titleHostCorr.brandToken || titleHostCorr.displayBrand
        || (productBrand && (productBrand.cnBrand || productBrand.displayBrand)) || "";
      const shellEvidence = landingShell.hardShell || landingShell.shellScore >= 2 || downloadCtAs.length >= 1
        || hasBrandMismatchPkg || offsitePkgs.length >= 1 || hasBareDownloadPhp || cloudDriveQrOnly || hasDownloadHub
        || (landingShell.hasHub && landingShell.ctaCount >= 1);
      const identityMismatch = !!(titleHostCorr.mismatch || hostUnrelated || hostSquat);
      const titleBrandSpoof = identityMismatch && officialPitch && !!brandIdForSpoof && shellEvidence
        && (hostSquat || hasBrandMismatchPkg || offsitePkgs.length >= 1 || hasBareDownloadPhp || cloudDriveQrOnly
          || (hostUnrelated && (hasDownloadHub || downloadCtAs.length >= 1 || landingShell.ctaCount >= 1 || landingShell.hasHub)));

      if (!spoofHost && !seoTemplate && !titleBrandSpoof && !hasBrandMismatchPkg) {
        if (!(officialPitch && offsitePkgs.length >= 1 && downloadCtAs.length >= 1 && landingShell.ok)) return false;
      } else if (!(offsitePkgs.length >= 1 || hasBareDownloadPhp || downloadCtAs.length >= 1 || hasDownloadHub || titleBrandSpoof || hasBrandMismatchPkg || cloudDriveQrOnly || landingShell.hardShell)) {
        // 旧路径：hostSquat + officialPitch 无下载壳也可 arm → 已废除，必须落地壳
        return false;
      }

      if (!officialPitch && offsitePkgs.length === 0 && !titleBrandSpoof && !hasBrandMismatchPkg && !landingShell.hardShell) return false;
      // 最终绑定：仍须落地壳 ok（双保险）
      if (!landingShell.ok) return false;

      // 外链下载中转 / 同站品牌错配包 / 多平台共用假包 = 硬证据，不必等 ICP
      let offsiteDlCtas = 0;
      let opaqueHopDl = 0;
      const pagePkgHrefs = [];
      for (const el of downloadCtAs) {
        try {
          const h = NS.getElementDownloadHref(el) || el.getAttribute("href") || "";
          if (!h || h === "#" || /^javascript:/i.test(h)) continue;
          const u = new URL(h, location.href);
          const pageH = (location.hostname || "").toLowerCase().replace(/^www\./, "");
          const linkH = (u.hostname || "").toLowerCase().replace(/^www\./, "");
          if (NS.isPackageFileUrl(h) || NS.isPackageFileUrl(u.href)) pagePkgHrefs.push(u.href);
          if (!linkH || linkH === pageH) continue;
          offsiteDlCtas++;
          if (typeof NS.looksLikeOpaqueDownloadHopUrl === "function" && NS.looksLikeOpaqueDownloadHopUrl(h)) opaqueHopDl++;
          else if (/[?&](?:url|u|target|to|redir|redirect|link|go)=/i.test(u.search || "") || /\/(?:go|jump|redirect|r|link)\b/i.test(u.pathname || "")) opaqueHopDl++;
        } catch { /* ignore */ }
      }
      const hardOffsiteDl = officialPitch && (opaqueHopDl >= 1 || offsiteDlCtas >= 3);
      // 多平台按钮共用同一 zip（tokowin_pc64.zip 当 Windows/Mac/Linux/…）
      const uniqPkgBases = new Set(pagePkgHrefs.map((p) => {
        try { return NS.getFilenameFromUrl(p).toLowerCase(); } catch { return ""; }
      }).filter(Boolean));
      const multiPlatformSameFakePkg = officialPitch && downloadCtAs.length >= 3 && pagePkgHrefs.length >= 3 && uniqPkgBases.size === 1;
      // 多平台「立即下载」但 href=# / 无真实包链（钉钉下载壳）
      let hreflessDl = 0;
      for (const el of downloadCtAs) {
        try {
          const h = (NS.getElementDownloadHref(el) || el.getAttribute("href") || "").trim();
          if (!h || h === "#" || /^javascript:/i.test(h)) hreflessDl++;
        } catch { /* ignore */ }
      }
      const multiPlatformHreflessShell = officialPitch && hreflessDl >= 4
        && /Windows|macOS|Mac|Linux|Android|iOS|鸿蒙/i.test(htmlSliceEarly || "");
      // 页面任意安装包与标题品牌不一致（同站也算，不只 offsite）
      let anyBrandMismatchPkg = hasBrandMismatchPkg;
      if (!anyBrandMismatchPkg && officialPitch) {
        for (const p of pagePkgHrefs) {
          if (NS.packageMismatchesPageBrand(p) || NS.looksLikeBrandNearMissPackageName(NS.getFilenameFromUrl(p))) {
            anyBrandMismatchPkg = true;
            if (!offsitePkgs.includes(p)) offsitePkgs.push(p);
            break;
          }
        }
      }

      // 首页 download.html 导流门户：算硬壳证据，避免 huorong-pc 卡在「padded 等 ICP」
      const homeHubPortal = !!(landingShell.hasHub && (landingShell.ctaCount >= 1 || downloadCtAs.length >= 1));
      const hardKitEvidence = seoTemplate || anyBrandMismatchPkg || hardOffsiteDl || multiPlatformSameFakePkg || multiPlatformHreflessShell
        || homeHubPortal
        || offsitePkgs.some((p) => NS.isPackageFileUrl(p) && (NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(p)) || NS.looksLikeObjectStoragePackageUrl(p) || NS.looksLikeHighRiskBlobPackageUrl(p)));
      // 仅「padded 软夹带 + 无下载门户壳」等 ICP（todeskai 沪ICP 误报）
      // 有首页下载导流 / 硬壳 → 立刻 arm（huorong-pc.cn 仿冒下载站）
      const softOnlyIdentity = (hostSquat || titleBrandSpoof) && !hardKitEvidence;
      const mustWaitIcpForSoft = softOnlyIdentity && titleHostCorr.hostMatch === "padded" && !homeHubPortal;
      if (mustWaitIcpForSoft && !NS.hasValidIcpRecord() && !NS.icpSettledForSoftBrandSpoof()) { state._pendingSoftBrandSpoof = true; return false; }
      if (mustWaitIcpForSoft && !NS.hasValidIcpRecord() && state._icpQueryFailed && !state._icpQuerySettled) { state._pendingSoftBrandSpoof = true; return false; }

      let brandPick = titleHostCorr.brandToken || brandIdForSpoof || "";
      if (!brandPick || (NS.BRAND_TOKEN_STOP_RE.test(String(brandPick).toLowerCase()) && !/[一-鿿]/.test(brandPick))) {
        const labDisp = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        brandPick = NS.pickBrandTokenForHost([...tokens].filter((t) => /^[a-z]{3,}$/i.test(t) && !NS.BRAND_TOKEN_STOP_RE.test(t)), labDisp)
          || (typeof NS.inferMarketingPaddedBrandCore === "function" ? NS.inferMarketingPaddedBrandCore(labDisp) : "")
          || [...tokens].find((t) => /^[a-z]{4,}$/i.test(t) && !NS.BRAND_TOKEN_STOP_RE.test(t))
          || [...tokens].find((t) => /[一-鿿]{2,}/.test(t))
          || brandIdForSpoof
          || "";
      }
      // 展示名：title + h1–h6 + description + keywords + footer 共识（钉钉，非「钉钉双」）
      const surfaceDisp = (typeof NS.pickChineseBrandFromIdentityConsensus === "function"
        ? NS.pickChineseBrandFromIdentityConsensus()
        : "")
        || (typeof NS.pickChineseBrandFromPageSurface === "function"
          ? (() => {
            let schemaNm = "";
            try {
              for (const sc of Array.from(document.querySelectorAll('script[type="application/ld+json"]')).slice(0, 6)) {
                try {
                  const j = JSON.parse(sc.textContent || "");
                  const nodes = Array.isArray(j) ? j : (j && j["@graph"] ? j["@graph"] : [j]);
                  for (const node of nodes) {
                    if (node && /SoftwareApplication|Organization|Product/i.test(String(node["@type"] || "")) && node.name) {
                      schemaNm = String(node.name).trim(); break;
                    }
                  }
                  if (schemaNm) break;
                } catch { /* ignore */ }
              }
            } catch { /* ignore */ }
            let kwMeta = document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "";
            if (!kwMeta) {
              try {
                for (const el of Array.from(document.querySelectorAll("meta")).slice(0, 40)) {
                  const n = String(el.getAttribute("name") || "").toLowerCase();
                  if (n === "keywords" || n.includes("keyword")) {
                    kwMeta = el.getAttribute("content") || "";
                    if (kwMeta) break;
                  }
                }
              } catch { /* ignore */ }
            }
            // title/og 先于 keywords（keywords 常为 SEO「文章」）
            return NS.pickChineseBrandFromPageSurface(schemaNm)
              || NS.pickChineseBrandFromPageSurface(document.title || "")
              || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "")
              || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "")
              || NS.pickChineseBrandFromPageSurface(document.querySelector("h1")?.textContent || "")
              || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[name="description"]')?.getAttribute("content") || "")
              || NS.pickChineseBrandFromPageSurface(kwMeta)
              || NS.pickChineseBrandFromPageSurface(brandSource || "");
          })()
          : "");
      let brandDisp = surfaceDisp
        || brandIdForSpoof
        || (productBrand && productBrand.displayBrand)
        || (titleHostCorr.displayBrand && /[一-鿿]/.test(titleHostCorr.displayBrand) ? titleHostCorr.displayBrand : "")
        || (typeof NS.pickBrandDisplayName === "function"
          ? NS.pickBrandDisplayName({
            title: document.title || "",
            identity: brandSource,
            displayBrand: titleHostCorr.displayBrand,
            brandToken: brandPick
          })
          : "")
        || [...tokens].filter((t) => /[一-鿿]{2,}/.test(t) && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)))
          .sort((a, b) => b.length - a.length)[0]
        || (brandPick && !NS.BRAND_TOKEN_STOP_RE.test(String(brandPick).toLowerCase()) ? NS.formatBrandTokenForDisplay(brandPick) : "")
        || "";
      // 钉钉应用/钉钉双平台 → 钉钉；数字前缀产品（360安全卫士）由 trim 内部保留本体
      if (brandDisp && /[一-鿿]/.test(brandDisp) && typeof NS.trimChineseBrandTrail === "function") {
        brandDisp = NS.trimChineseBrandTrail(brandDisp) || brandDisp;
      }
      // 最终兜底：若仍是弱词，再扫 title 数字产品
      if (brandDisp && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brandDisp)) {
        const dig = ((document.title || "").match(/(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
        brandDisp = (dig && !NS.isWeakChineseBrandToken(dig)) ? dig : "";
      }
      if (surfaceDisp && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(surfaceDisp))) {
        // 共识名优先；勿用更长营销残片覆盖
        if (!brandDisp || brandDisp === surfaceDisp
          || surfaceDisp.length <= brandDisp.length
          || brandDisp.startsWith(surfaceDisp)) {
          brandDisp = surfaceDisp;
        }
      }
      if (brandDisp && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brandDisp)) {
        const primary = typeof NS.pickPrimaryTitleBrandToken === "function"
          ? NS.pickPrimaryTitleBrandToken(document.title || "", (location.hostname || "").split(".")[0] || "")
          : "";
        brandDisp = surfaceDisp
          || (primary && primary.length >= 4 ? NS.formatBrandTokenForDisplay(primary) : "")
          || (productBrand && productBrand.latinToken ? NS.formatBrandTokenForDisplay(productBrand.latinToken) : "")
          || "";
      }
      if (!brandDisp || NS.BRAND_TOKEN_STOP_RE.test(String(brandDisp).toLowerCase())) {
        // 仍无可用展示名则不写 spoofBrand，避免「仿冒 Template」
        state.spoofBrand = state.spoofBrand || "";
      } else {
        state.spoofBrand = brandDisp;
      }

      const showBrand = (brandDisp && !NS.BRAND_TOKEN_STOP_RE.test(String(brandDisp).toLowerCase())) ? brandDisp : "";
      const reasons = [];
      if (titleHostCorr.mismatch && (titleHostCorr.brandToken || showBrand)) {
        const matchHint = titleHostCorr.hostMatch === "typo" ? "拼写仿冒" : titleHostCorr.hostMatch === "padded" ? "域名夹带品牌前缀/后缀" : titleHostCorr.hostMatch === "hyphen" ? "域名用连字符拆分品牌名" : titleHostCorr.hostMatch === "none" ? "域名与品牌无关" : "关联不严谨";
        reasons.push(`标题/正文品牌「${showBrand || titleHostCorr.brandToken}」出现约 ${titleHostCorr.brandHits || 1} 次，与域名 ${location.hostname} 不匹配（${matchHint}）`);
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
      if (hardOffsiteDl) reasons.push("下载按钮指向站外中转/跳转链（非官方直链安装包）");
      if (multiPlatformHreflessShell) reasons.push("多平台下载按钮无真实安装包链接（href 为空/#）");
      const signalDetail = reasons.join("；") || (showBrand ? `页面宣称「${showBrand}」官网下载，但域名 ${location.hostname} 与品牌不一致` : "页面宣称官网下载，但域名与品牌/分发链异常");

      // padded 软仿冒 + 有效 ICP → 撤销；typo/硬证据不因 ICP 放过
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected && !hardKitEvidence
        && titleHostCorr.hostMatch === "padded") {
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      NS.addSignal("仿冒品牌官网下载站", 24, signalDetail);
      for (const p of offsitePkgs.slice(0, 5)) { if (p && NS.isPackageFileUrl(p) && !state.protectedTargets.includes(p)) state.protectedTargets.push(p); }
      // 外链中转也纳入 protectedTargets，便于 MAIN 拦截
      try {
        for (const el of downloadCtAs.slice(0, 8)) {
          const h = NS.getElementDownloadHref(el) || el.getAttribute("href") || "";
          if (!h || !/^https?:/i.test(h)) continue;
          try {
            const u = new URL(h, location.href);
            if (u.hostname.replace(/^www\./, "") !== (location.hostname || "").replace(/^www\./, "") && !state.protectedTargets.includes(u.href)) {
              state.protectedTargets.push(u.href);
            }
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
      const pkgHref = offsitePkgs.find((p) => NS.isPackageFileUrl(p)) || state.protectedTargets.find((p) => /^https?:/i.test(p)) || "";
      const noticeTitle = showBrand ? `已识别仿冒「${showBrand}」官网` : "已识别仿冒品牌官网";
      const noticeMsg = showBrand ? `域名 ${location.hostname} 与标题品牌「${showBrand}」不匹配，疑似仿冒官网下载站` : `域名 ${location.hostname} 与页面宣称品牌不匹配，疑似仿冒官网下载站`;
      // padded 且无门户壳才软等 ICP；首页导流 / typo / none / 硬证据 → lockHard
      const lockHardNow = !!hardKitEvidence || titleHostCorr.hostMatch !== "padded" || homeHubPortal;
      NS.installDownloadGuard(showBrand ? `仿冒品牌官网下载站（仿冒「${showBrand}」）` : "仿冒品牌官网下载站", {
        notify: true,
        href: pkgHref,
        message: noticeMsg,
        title: noticeTitle,
        guardKind: "brand-spoof",
        forceNotify: true,
        lockHard: lockHardNow
      });
      NS.disableAllDownloadIntentControls();
      state._pendingSoftBrandSpoof = false;
      // 主路径命中后也主动 fetch 下载落地
      try {
        if (typeof NS.proactivelyProbeDownloadButtons === "function") {
          Promise.resolve().then(() => NS.proactivelyProbeDownloadButtons()).catch(() => {});
        }
      } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  /**
   * 收集需主动探测的下载按钮目标（无需用户点击）。
   * landing: 同域 HTML 落地页（download.html 等）→ fetch 源码分析
   * probe: 中转/外链/无扩展名下载口 → HEAD/行为探测
   */
  NS.collectProactiveDownloadTargets = function () {
    const landing = [];
    const probe = [];
    const seenL = new Set();
    const seenP = new Set();
    const pushL = (href, el) => {
      try {
        const abs = new URL(href, location.href).href;
        if (seenL.has(abs)) return;
        seenL.add(abs);
        landing.push({ href: abs, el });
      } catch { /* ignore */ }
    };
    const pushP = (href, el) => {
      try {
        const abs = new URL(href, location.href).href;
        if (seenP.has(abs) || seenL.has(abs)) return;
        seenP.add(abs);
        probe.push({ href: abs, el });
      } catch { /* ignore */ }
    };
    try {
      const nodes = document.querySelectorAll(
        "a[href], a[data-href], a[data-url], button, [role='button'], .download-btn, .btn-download, .btn-header, a.btn-primary, a.btn-lg, a.btn-header, [class*='download'], [class*='platform'], [class*='cta']"
      );
      const lim = Math.min(nodes.length, 120);
      for (let i = 0; i < lim; i++) {
        const el = nodes[i];
        const href = (typeof NS.getElementDownloadHref === "function" ? NS.getElementDownloadHref(el) : "")
          || el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-url") || "";
        if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href.trim())) continue;
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        const cls = String(el.className || "");
        const intent = (NS.DOWNLOAD_TEXT && NS.DOWNLOAD_TEXT.test(text))
          || /立即下载|免费下载|官方下载|客户端下载|下载中心|前往下载|立即使用|个人版|企业版|Windows|macOS|Android|iOS|安装包/i.test(text)
          || /download|btn-download|platform|btn-header|btn-primary|btn-lg/i.test(cls);
        const sameOriginLand = typeof NS.looksLikeSameOriginLandingPageUrl === "function" && NS.looksLikeSameOriginLandingPageUrl(href);
        // 路径像 download.html 即使文案弱也收集（首页「个人版下载」）
        const pathLand = /download\.html|(?:^|\/)(?:download|down|install|setup|client|soft)(?:\/|\.html?|$)/i.test(href);
        if (!intent && !sameOriginLand && !pathLand
          && !(typeof NS.needsDownloadBehaviorProbe === "function" && NS.needsDownloadBehaviorProbe(href, el))) continue;
        if (NS.isPackageFileUrl(href)) continue; // 包链已由同步扫描处理
        if (sameOriginLand || pathLand) pushL(href, el);
        else if (typeof NS.needsDownloadBehaviorProbe === "function" && NS.needsDownloadBehaviorProbe(href, el)) pushP(href, el);
        else if (intent) {
          try {
            const u = new URL(href, location.href);
            if (u.origin !== location.origin || /\.(?:php|asp|aspx)$/i.test(u.pathname)) pushP(href, el);
            else if (/\.(?:html?)$/i.test(u.pathname) && /down|install|client|soft|get/i.test(u.pathname)) pushL(href, el);
          } catch { /* ignore */ }
        }
      }
    } catch { /* ignore */ }
    return { landing: landing.slice(0, 8), probe: probe.slice(0, 5) };
  };

  /** 父页品牌 vs 域名错配（主动 fetch 落地页时联动仿冒） */
  NS.getParentPageBrandSpoofContext = function () {
    try {
      // 软件门户 / 应用商店：标题产品名与域名本就不一致，不是仿冒
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
        return { mismatch: false, brand: "", hostMatch: "portal", brandToken: "" };
      }
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) {
        return { mismatch: false, brand: "", hostMatch: "market", brandToken: "" };
      }
      // 有效 ICP / 超成熟 WHOIS：父页不因「中文品牌≠拉丁主机」联动主动探测仿冒
      if (NS.hasValidIcpRecord() || (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature())) {
        const corrTrusted = typeof NS.evaluateTitleHostBrandCorrelation === "function"
          ? NS.evaluateTitleHostBrandCorrelation()
          : null;
        // 仅 padded/typo 营销夹带仍可标 mismatch；soft.china.com 等 none 不联动
        const keep = corrTrusted && (corrTrusted.hostMatch === "padded" || corrTrusted.hostMatch === "typo" || corrTrusted.hostMatch === "hyphen");
        if (!keep) {
          return {
            mismatch: false,
            brand: (corrTrusted && (corrTrusted.displayBrand || corrTrusted.brandToken)) || "",
            hostMatch: (corrTrusted && corrTrusted.hostMatch) || "trusted",
            brandToken: (corrTrusted && corrTrusted.brandToken) || ""
          };
        }
      }
      const corr = typeof NS.evaluateTitleHostBrandCorrelation === "function"
        ? NS.evaluateTitleHostBrandCorrelation()
        : null;
      if (corr && (corr.hostMatch === "exact" || corr.rigorousMatch)) {
        return { mismatch: false, brand: corr.displayBrand || corr.brandToken || "", hostMatch: corr.hostMatch || "exact" };
      }
      let brand = (corr && (corr.displayBrand || corr.brandToken)) || "";
      if (!brand && typeof NS.pickChineseBrandFromIdentityConsensus === "function") {
        brand = NS.pickChineseBrandFromIdentityConsensus() || "";
      }
      if (!brand && typeof NS.pickChineseBrandFromPageSurface === "function") {
        let kw = "";
        try {
          kw = document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "";
          if (!kw) {
            for (const el of Array.from(document.querySelectorAll("meta")).slice(0, 40)) {
              const n = String(el.getAttribute("name") || "").toLowerCase();
              if (n === "keywords" || n.includes("keyword")) {
                kw = el.getAttribute("content") || "";
                if (kw) break;
              }
            }
          }
        } catch { /* ignore */ }
        brand = NS.pickChineseBrandFromPageSurface(document.title || "")
          || NS.pickChineseBrandFromPageSurface(kw)
          || NS.pickChineseBrandFromPageSurface(document.querySelector("h1")?.textContent || "")
          || "";
      }
      // 中文产品 + 拉丁域名无关：即使 corr.mismatch 未置位也视为错配（仿冒火绒首页）
      // 但排除门户频道子域 soft./download.（中华网软件）
      let mismatch = !!(corr && (corr.mismatch
        || corr.hostMatch === "none"
        || corr.hostMatch === "partial"
        || corr.hostMatch === "padded"
        || corr.hostMatch === "typo"
        || corr.hostMatch === "hyphen"));
      if (!mismatch && brand && /[一-鿿]{2,}/.test(brand)) {
        try {
          const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
          const labFlat = lab.replace(/-/g, "");
          // soft/game/download 等门户频道标签：不当「域名与品牌无关」
          if (/^(soft|game|app|down|download|file|news|blog|bbs|video|music|shop|store)$/i.test(labFlat)) {
            mismatch = false;
          } else {
            // 主机不含拼音品牌痕迹且非 product-category 域 → 错配
            const pinyinHint = /huorong|qihoo|360|tencent|baidu|sogou|kingsoft|rising|kaspersky|norton|avast|avg|mcafee|bitdefender|eset|malwarebytes/i.test(labFlat);
            if (labFlat.length >= 3 && !pinyinHint
              && !(typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
                && NS.hostLabelIsBrandProductCategoryDomain(lab, brand))) {
              mismatch = true;
            }
          }
        } catch { /* ignore */ }
      }
      return {
        mismatch: !!(mismatch && brand),
        brand: brand || "",
        hostMatch: (corr && corr.hostMatch) || "none",
        brandToken: (corr && corr.brandToken) || brand || ""
      };
    } catch {
      return { mismatch: false, brand: "", hostMatch: "" };
    }
  };

  /** 从落地页 HTML 抽取安装包 URL（绝对 + 相对） */
  NS.extractPackageUrlsFromHtml = function (source, baseHref) {
    const out = [];
    const seen = new Set();
    const push = (raw) => {
      try {
        let u = String(raw || "").trim();
        if (!u || u.length > 500) return;
        if (/^(javascript:|#|data:|blob:|mailto:)/i.test(u)) return;
        if (!/\.(?:zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(u)) return;
        const abs = new URL(u, baseHref || location.href).href;
        if (seen.has(abs)) return;
        seen.add(abs);
        out.push(abs);
      } catch { /* ignore */ }
    };
    const src = String(source || "");
    try {
      const absRe = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|rar|7z|pkg|appx)(?:\?[^\s"'<>\\]*)?/gi;
      let m;
      while ((m = absRe.exec(src)) !== null && out.length < 12) push(m[0]);
    } catch { /* ignore */ }
    try {
      const relRe = /(?:href|src|data-href|data-url|data-link|content)\s*=\s*["']([^"']+\.(?:zip|exe|apk|msi|dmg|rar|7z|pkg|appx)(?:\?[^"']*)?)["']/gi;
      let m;
      while ((m = relRe.exec(src)) !== null && out.length < 12) push(m[1]);
    } catch { /* ignore */ }
    try {
      const jsRe = /["'`](\/?[\w./-]+\.(?:zip|exe|apk|msi|dmg|rar|7z))(?:\?[^"'`]*)?["'`]/gi;
      let m;
      while ((m = jsRe.exec(src)) !== null && out.length < 12) push(m[1]);
    } catch { /* ignore */ }
    return out;
  };

  /**
   * 分析落地页 HTML：远程下发壳 / 静态安装包 / 与父页联动的仿冒下载门户。
   * opts: { baseHref, parentBrandMismatch, parentBrand }
   */
  NS.analyzeFetchedDownloadLandingHtml = function (source, chain, opts) {
    const o = opts || {};
    if (!source || source.length < 80) return { hit: false, packages: [] };
    // Linux 发行版 ISO/镜像列表页：磁力、校验和、.iso —— 非银狐 exe 壳
    const osIsoLanding = /\.iso(?:\?|"|'|\s|>|\/|#|$)/i.test(source)
      && (/(?:sha256sums|b2sums|magnet:\?xt=urn:btih:|\.torrent\b|bittorrent|pgp\s*签名|gpg\s*--verify)/i.test(source)
        || /(?:mirror\.|mirrors\.|镜像站|\/iso\/\d{4})/i.test(source));
    if (osIsoLanding) {
      return {
        hit: false,
        remoteSetupFetchPattern: false,
        autoDownloadDispatchPattern: false,
        remoteDownloadUrlPattern: false,
        suspiciousLandingPage: false,
        brandSpoofLanding: false,
        staticPackageLanding: false,
        usesRemoteJsWithAttr: false,
        redirectCount: 0,
        osIsoLanding: true,
        packages: []
      };
    }
    const baseHref = o.baseHref || location.href;
    const packages = typeof NS.extractPackageUrlsFromHtml === "function"
      ? NS.extractPackageUrlsFromHtml(source, baseHref)
      : [];
    const remoteSetupFetchPattern = /fetch\s*\(\s*[^)]*\.(?:txt|json|php)/i.test(source)
      || /(?:const|let|var)\s+\w*(?:REMOTE_)?(?:SETUP|CONFIG|VERSION|PACKAGE)_?URL\s*=/i.test(source)
      || /(?:const|let|var)\s+\w+_URL\s*=\s*["'`][^"'`\n]+\.(?:txt|json|php)/i.test(source)
      || /download_uri|initDownloadLinks|getDownloadUrl|fetchDownloadLink/i.test(source);
    const autoDownloadDispatchPattern = /createElement\(["']a["']\)|\.click\(\)|triggerDownload|location\.href\s*=|location\.assign|window\.open\s*\(/i.test(source);
    const remoteDownloadUrlPattern = packages.length >= 1
      || /https?:\/\/[^"'\s<>]+\.(?:zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|"|'|\s|>)/i.test(source);
    const landingDownloadKeywords = (source.match(/下载|download|立即下载|免费下载|官方下载|客户端下载|官方|最新版|安装|安装包|个人版|企业版/gi) || []).length;
    const usesRemoteJsWithAttr = /<script[^>]+src=["']https?:\/\/[^"']+\?attr=/i.test(source);
    const redirectCount = Array.isArray(chain) ? Math.max(0, chain.length - 1) : 0;
    const hasRedirectChain = redirectCount >= 1 || /http-equiv=["']refresh["']/i.test(source);
    const ossOrRandomPkg = remoteDownloadUrlPattern && (
      /(?:oss|cos|s3|cdn|blob|object|qiniucdn|aliyuncs)/i.test(source)
      || /https?:\/\/[a-z0-9]{8,}\.[a-z]{2,}\//i.test(source)
    );
    // 禁止「下载文案 + 任意统计/广告脚本」误伤正规下载站（Arch/发行版/镜像列表）
    const suspiciousLandingPage = landingDownloadKeywords >= 5
      && (remoteSetupFetchPattern
        || usesRemoteJsWithAttr
        || (remoteDownloadUrlPattern && autoDownloadDispatchPattern)
        || (ossOrRandomPkg && autoDownloadDispatchPattern))
      && /下载|download|install|setup|客户端/i.test(source);

    // 父页品牌/域名错配（仿冒火绒首页）→ 落地页有包或下载门户文案即命中
    const parentMismatch = !!o.parentBrandMismatch;
    const parentBrand = String(o.parentBrand || "");
    const brandHintInLanding = parentBrand
      ? (source.includes(parentBrand) || (parentBrand.length >= 2 && new RegExp(parentBrand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(source)))
      : /火绒|huorong|钉钉|dingtalk|todesk|向日葵/i.test(source);
    const brandSpoofLanding = parentMismatch && (
      packages.length >= 1
      || (landingDownloadKeywords >= 2 && /免费下载|立即下载|官方下载|客户端|个人版|安装包|立即免费/i.test(source))
      || (landingDownloadKeywords >= 1 && brandHintInLanding && /下载|客户端|安装/i.test(source))
      || remoteSetupFetchPattern
      || (remoteDownloadUrlPattern && landingDownloadKeywords >= 1)
    );
    let staticPackageLanding = packages.length >= 1 && landingDownloadKeywords >= 3
      && /免费下载|立即下载|官方下载|客户端|安装包|个人版/i.test(source);
    if (staticPackageLanding && !parentMismatch && packages.length >= 1) {
      const allClearProduct = packages.every((p) => {
        try {
          const fn = typeof NS.getFilenameFromUrl === "function" ? NS.getFilenameFromUrl(p) : "";
          return typeof NS.looksLikeStrongProductInstallerName === "function" && NS.looksLikeStrongProductInstallerName(fn)
            && typeof NS.packageFilenameSharesPageBrand === "function" && NS.packageFilenameSharesPageBrand(fn);
        } catch { return false; }
      });
      if (allClearProduct) staticPackageLanding = false;
    }
    if (parentMismatch && packages.length >= 1) staticPackageLanding = true;

    const hit = (remoteSetupFetchPattern && (autoDownloadDispatchPattern || remoteDownloadUrlPattern))
      || (remoteSetupFetchPattern && remoteDownloadUrlPattern)
      || (autoDownloadDispatchPattern && remoteDownloadUrlPattern && landingDownloadKeywords >= 3)
      || suspiciousLandingPage
      || usesRemoteJsWithAttr
      || (ossOrRandomPkg && landingDownloadKeywords >= 3 && autoDownloadDispatchPattern)
      || (hasRedirectChain && remoteDownloadUrlPattern && landingDownloadKeywords >= 2)
      || brandSpoofLanding
      || staticPackageLanding;
    return {
      hit: !!hit,
      remoteSetupFetchPattern,
      autoDownloadDispatchPattern,
      remoteDownloadUrlPattern,
      suspiciousLandingPage,
      brandSpoofLanding: !!brandSpoofLanding,
      staticPackageLanding: !!staticPackageLanding,
      usesRemoteJsWithAttr,
      redirectCount,
      packages
    };
  };

  /**
   * 当前页是否有「应主动 fetch」的下载按钮地址（同域 download.html / 中转等）。
   * 首页导流场景：即使页面像内容站（_perfBenign）也必须探测。
   */
  NS.pageHasProactiveDownloadButtonTargets = function () {
    try {
      if (typeof NS.collectProactiveDownloadTargets === "function") {
        const t = NS.collectProactiveDownloadTargets();
        if (t && ((t.landing && t.landing.length > 0) || (t.probe && t.probe.length > 0))) return true;
      }
      // 快速 DOM 启发：免费下载 → download.html
      if (document.querySelector(
        "a[href*='download.html'], a[href*='/download'], a[href*='Download'], "
        + "a.btn-header[href], a.download-btn[href], a.btn-download[href], "
        + "a.btn-primary[href*='down'], a.btn-lg[href*='down']"
      )) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 主动 fetch/探测下载按钮目标（无需用户点击）。
   * 首页「免费下载→download.html」须在此检出仿冒落地/安装包，勿等用户点进下载页。
   */
  NS.proactivelyProbeDownloadButtons = async function () {
    const state = NS.state;
    try {
      if (state.downloadGuardInstalled || state._proactiveProbeBusy) return false;
      // 可信门户/发行版等仍跳过；内容站 _perfBenign 不挡下载按钮主动 fetch
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return false;
      // 有效 ICP / 超成熟：禁止主动探测把软件门户 arm 成仿冒（soft.china.com）
      if ((NS.hasValidIcpRecord() || (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature()))
        && !(typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "skip-trusted-icp-or-ultra");
        return false;
      }
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "skip-software-catalog");
        return false;
      }
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) return false;
      if (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) return false;
      if (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload()) return false;
      if (NS.pageLooksLikeSearchEngineResultsPage && NS.pageLooksLikeSearchEngineResultsPage()) return false;
      const now = Date.now();
      // 有明确下载按钮目标时缩短节流，避免首页首扫被 4s 冷却挡掉二次补探测
      const hasTargetsEarly = typeof NS.pageHasProactiveDownloadButtonTargets === "function"
        && NS.pageHasProactiveDownloadButtonTargets();
      const coolMs = hasTargetsEarly ? 1800 : 4000;
      if (state._proactiveProbeAt && now - state._proactiveProbeAt < coolMs) return false;
      state._proactiveProbeAt = now;
      state._proactiveProbeBusy = true;

      const { landing, probe } = NS.collectProactiveDownloadTargets();
      if (!landing.length && !probe.length) return false;
      const parentCtx = typeof NS.getParentPageBrandSpoofContext === "function"
        ? NS.getParentPageBrandSpoofContext()
        : { mismatch: false, brand: "" };
      NS.silverfoxLog && NS.silverfoxLog(
        "proactive-probe", "start",
        "landing=", landing.length, "probe=", probe.length,
        "parentMismatch=", !!parentCtx.mismatch, "brand=", parentCtx.brand || ""
      );

      let armed = false;
      const curPath = (location.pathname || "/").replace(/\/+$/, "") || "/";
      const landResults = await Promise.all(landing.map(async ({ href, el }) => {
        try {
          let absPath = "";
          try {
            const u = new URL(href, location.href);
            absPath = (u.pathname || "/").replace(/\/+$/, "") || "/";
            if (u.origin === location.origin && absPath === curPath) return null;
          } catch { /* ignore */ }
          const { chain, finalText: source } = await NS.fetchWithRedirectChain(href, 4);
          if (!source || source.length < 80) return null;
          const analysis = NS.analyzeFetchedDownloadLandingHtml(source || "", chain, {
            baseHref: href,
            parentBrandMismatch: !!parentCtx.mismatch,
            parentBrand: parentCtx.brand || ""
          });
          if (!analysis.hit) return null;
          const pkgs = analysis.packages || [];
          try {
            for (const p of pkgs.slice(0, 8)) {
              if (p && !state.protectedTargets.includes(p)) state.protectedTargets.push(p);
            }
            if (!pkgs.length) {
              const pkgRe = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|rar|7z)(?:\?[^\s"'<>\\]*)?/gi;
              let m; let n = 0;
              while ((m = pkgRe.exec(source)) !== null && n < 6) {
                n++;
                if (!state.protectedTargets.includes(m[0])) state.protectedTargets.push(m[0]);
              }
            }
          } catch { /* ignore */ }
          return { href, el, analysis, packages: pkgs };
        } catch { return null; }
      }));
      const landHit = landResults.find(Boolean);
      if (landHit) {
        const isBrand = !!(landHit.analysis.brandSpoofLanding || parentCtx.mismatch || state.spoofBrand || state._brandSpoofPortalDetected);
        if (isBrand && parentCtx.brand && !state.spoofBrand) {
          try { state.spoofBrand = parentCtx.brand; } catch { /* ignore */ }
        }
        const showBrand = state.spoofBrand || parentCtx.brand || "";
        const reason = landHit.analysis.brandSpoofLanding
          ? `主动探测：首页下载入口指向仿冒落地页（${showBrand || "品牌"} 与域名不匹配）`
          : landHit.analysis.staticPackageLanding
            ? "主动探测：下载按钮指向的落地页含安装包分发"
            : "主动探测：下载按钮指向的落地页含远程配置/动态下发安装包链路";
        NS.addSignal(
          landHit.analysis.brandSpoofLanding ? "主动探测仿冒下载落地" : "同域下载落地页远程链",
          landHit.analysis.brandSpoofLanding ? 22 : 16,
          `${reason} → ${landHit.href}`
        );
        if (landHit.el) try { NS.disableOneSuspiciousElement(landHit.el, landHit.href); } catch { /* ignore */ }
        const pkgHref = (landHit.packages && landHit.packages[0])
          || state.protectedTargets.find((t) => /\.(?:exe|zip|msi|apk|dmg)/i.test(String(t)))
          || landHit.href;
        NS.installDownloadGuard(reason, {
          notify: true,
          href: pkgHref,
          message: showBrand
            ? `域名 ${location.hostname} 与标题品牌「${showBrand}」不匹配，疑似仿冒官网下载站`
            : (pkgHref !== landHit.href ? pkgHref : landHit.href),
          forceNotify: true,
          title: showBrand ? `已识别仿冒「${showBrand}」官网` : "已拦截可疑下载落地页",
          guardKind: isBrand ? "brand-spoof" : "package",
          lockHard: true
        });
        NS.disableAllDownloadIntentControls();
        try { state._brandSpoofPortalDetected = state._brandSpoofPortalDetected || isBrand; } catch { /* ignore */ }
        armed = true;
      }

      if (!armed || !state.downloadGuardInstalled) {
        const probeHits = await Promise.all(probe.map(async ({ href, el }) => {
          try {
            if (typeof NS.probeDownloadBehavior !== "function") return null;
            const result = await NS.probeDownloadBehavior(href);
            if (result && result.isDownload) return { href, el, result };
            return null;
          } catch { return null; }
        }));
        const ph = probeHits.find(Boolean);
        if (ph) {
          NS.applyConfirmedDownloadBlock(ph.href, ph.el, ph.result);
          NS.disableAllDownloadIntentControls();
          armed = true;
        }
      }

      if (armed) try { NS.emitRiskReport(true); } catch { /* ignore */ }
      return armed;
    } catch { return false; }
    finally {
      try { state._proactiveProbeBusy = false; } catch { /* ignore */ }
    }
  };

  /** @deprecated 兼容旧调用名 → 主动探测 */
  NS.detectLinkedLandingPageSources = async function () {
    return NS.proactivelyProbeDownloadButtons();
  };
})(window.SilverfoxContent ??= {});
