/**
 * 品牌仿冒下载门户检测。
 * 主门控：域名 ↔ 页面主身份关键词（title/h1/keywords/logo/og）相关度。
 * 相关且非夹带 → 不仿冒；夹带/拼写/无关 + 下载壳 → 可仿冒。
 * 硬前提：软件下载落地页壳；软仿冒等 ICP。
 */
;(function (NS) {
  "use strict";

  /**
   * 宣称「技术支持/联系我们/客服」但页上无真实联系方式或加群入口 → 空心支持壳（盗版站常见）。
   * 正站通常有 mailto / 电话 / QQ 群 / 微信客服 / Telegram 等。
   */
  NS.pageLooksLikeHollowSupportContactShell = function () {
    try {
      const title = document.title || "";
      const html = typeof NS.getHtmlSlice === "function"
        ? NS.getHtmlSlice(28000)
        : String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 28000);
      const navBlob = (() => {
        try {
          return Array.from(document.querySelectorAll("nav a, header a, footer a, .nav a, .menu a"))
            .map((a) => `${a.textContent || ""} ${a.getAttribute("href") || ""}`)
            .join(" ")
            .slice(0, 2000);
        } catch { return ""; }
      })();
      const claimBlob = `${title} ${navBlob} ${html.slice(0, 12000)}`;
      // 宣称支持/联系
      const claimsSupport = /技术支持|联系我们|联系方式|在线客服|售后服务|帮助中心|客户服务|关于我们|support\.html|contact\.html|\/support|\/contact/i.test(claimBlob)
        || /技术支持|联系我们|客服|售后|帮助中心/i.test(navBlob);
      if (!claimsSupport) return false;
      // 真实联系：邮箱、电话、即时通讯、加群
      let hasRealContact = false;
      try {
        if (document.querySelector('a[href^="mailto:"], a[href^="tel:"], a[href*="mailto:"], a[href*="t.me/"], a[href*="discord."], a[href*="jq.qq.com"]')) {
          hasRealContact = true;
        }
      } catch { /* ignore */ }
      if (!hasRealContact) {
        hasRealContact = /mailto:|tel:\s*\+?\d|@[\w.-]+\.[a-z]{2,}|电话\s*[:：]?\s*\d|手机\s*[:：]?\s*1\d{10}|客服热线|服务热线|\d{3,4}[-\s]?\d{7,8}|1[3-9]\d{9}/i.test(html)
          || /(?:QQ|qq)\s*[:：]?\s*\d{5,12}|QQ\s*群|qq\s*群|加群|群号\s*[:：]?\s*\d{5,}|微信\s*[:：]|微信号|企业微信|公众号|Telegram|Discord|Slack|客服微信/i.test(html)
          || /support@|contact@|service@|help@|info@/i.test(html);
      }
      if (hasRealContact) return false;
      // 仅有 support.html 导航、正文无联系点 → 空心
      return true;
    } catch { return false; }
  };

  /**
   * 下载弹层仅网盘扫码（夸克/百度盘）无直链安装包 → 盗版分发壳。
   */
  NS.pageLooksLikeNetdiskQrOnlyDownload = function () {
    try {
      const title = document.title || "";
      if (!/下载|download|官方|客户端|软件|工具|测试|安装/i.test(title)
        && !document.querySelector("a[href*='download'], .download-btn, [onclick*='Download'], #downloadModal")) {
        return false;
      }
      const html = typeof NS.getHtmlSlice === "function"
        ? NS.getHtmlSlice(20000)
        : String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 20000);
      const netdisk = /夸克|百度网盘|蓝奏云|天翼云盘|阿里云盘|迅雷云盘|扫码.*下载|网盘扫码|长按识别|打开手机扫码/i.test(html);
      if (!netdisk) return false;
      // 几乎无同站 exe/zip 直链
      let pkg = 0;
      try {
        if (typeof NS.collectAllPagePackageHrefs === "function") {
          pkg = (NS.collectAllPagePackageHrefs() || []).length;
        }
      } catch { pkg = 0; }
      if (pkg >= 2) return false;
      return true;
    } catch { return false; }
  };

  /**
   * 仿冒官网快速路径：
   * 1) squat 夹带/连字符拆品牌域 + 下载 CTA（crystaldisk-mark）
   * 2) 域名与主关键词无关 + 官方下载话术 + 下载壳
   * 3) 官方下载壳 + 空心支持/联系 或 纯网盘扫码分发
   */
  NS.tryArmChineseBrandDownloadHomeSpoof = function () {
    try {
      const state = NS.state;
      if (state.downloadGuardInstalled && state._brandSpoofPortalDetected) return true;
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._desktopForceDlKit) return false;
      if (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature()) return false;
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) return false;
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) return false;
      // Arch/Ubuntu 等发行版 ISO / 海量镜像列表：非银狐 exe 假官网，home-fast 直接跳过
      if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-heavy-page");
        return false;
      }
      if ((typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList())
        || (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-high-density-or-os-iso");
        return false;
      }

      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      // 多标签关键词能拼成域名（title/logo/nav 的 ToDesk + AI ≡ todeskai）→ 绝不报盗版
      // 夹带 apex（qq-musics）或营销子域 win. 不得因首标签对齐而跳过
      try {
        const ap0 = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host) || host;
        const apLeft0 = (String(ap0).split(".")[0] || "").toLowerCase();
        const pad0 = typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(apLeft0);
        if (!pad0 && typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
          && NS.hostLabelStronglyAlignedWithIdentityKeywords(apLeft0)) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-identity-aligned", host);
          return false;
        }
      } catch { /* ignore */ }
      const rel = typeof NS.evaluateDomainKeywordRelevance === "function"
        ? NS.evaluateDomainKeywordRelevance(host)
        : null;
      // 几乎关联（exact/category）→ 不显示盗版
      if (rel && rel.related && !rel.squat) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-almost-related", rel.hostMatch, rel.brandToken);
        return false;
      }

      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const lab = labelRaw.replace(/-/g, "");
      // ★ 根源核：整主机解析（pc.v-dingtalk.com.cn → dingtalk），禁止只看首标签 pc
      const hostCores = typeof NS.collectHostBrandCores === "function"
        ? NS.collectHostBrandCores(host)
        : null;
      const core = (hostCores && hostCores.padCore)
        || (typeof NS.resolveHostBrandCore === "function" ? (NS.resolveHostBrandCore(host) || "") : "")
        || (typeof NS.inferMarketingPaddedBrandCore === "function"
          ? (NS.inferMarketingPaddedBrandCore(labelRaw) || "")
          : "");
      const apexLeftRaw = (hostCores && hostCores.apexLeftRaw)
        || (() => {
          try {
            const ap = typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host;
            return (String(ap || "").split(".")[0] || "").toLowerCase();
          } catch { return labelRaw; }
        })();
      // 数字品牌夹带：2345-kantuwangd / 360-xxx（主机以产品数字开头但后缀乱拼）
      const digitPadHost = /^\d{3,6}[-_][a-z0-9]{3,}/i.test(labelRaw)
        || /^\d{3,6}[-_][a-z0-9]{3,}/i.test(apexLeftRaw)
        || (/^\d{3,6}[a-z]{4,}/i.test(lab) && lab.length > 6);
      // 连字符拆品牌：crystaldisk-mark / to-desk / v-dingtalk
      const hyphenHost = !!(rel && rel.squat && rel.hostMatch === "hyphen")
        || ((/-/.test(labelRaw) || /-/.test(apexLeftRaw)) && typeof NS.hostLabelIsHyphenatedBrandMirror === "function"
          && typeof NS.collectPrimaryBrandKeywords === "function" && (() => {
            try {
              const pk = NS.collectPrimaryBrandKeywords();
              const toks = [...(pk.latin || []), ...(pk.tokens || [])].map((x) => String(x).toLowerCase().replace(/[^a-z0-9]/g, ""));
              return toks.some((t) => t.length >= 6 && (
                NS.hostLabelIsHyphenatedBrandMirror(labelRaw, t)
                || NS.hostLabelIsHyphenatedBrandMirror(apexLeftRaw, t)
              ));
            } catch { return false; }
          })());
      const apexFlat0 = (apexLeftRaw || "").replace(/[^a-z0-9]/g, "");
      // 正站产品子域（music.qq.com）不得标 padded
      const officialProdSub = typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
        && NS.hostLooksLikeOfficialProductSubdomain(host);
      // qqmusics / qq-musics / qqyinle：QQ + 音乐拼音/英文仿冒（apex 本身，非 music.qq.com）
      const qqMusicSquat = !officialProdSub && (
        /^(?:qq|weixin|wx)(?:music|musics|yinyue|yinle)$/i.test(apexFlat0)
        || /^qq[-_](?:music|musics|yinyue|yinle)$/i.test(apexLeftRaw || "")
      );
      const isPaddedHost = !officialProdSub && (digitPadHost || hyphenHost || qqMusicSquat
        || !!(hostCores && hostCores.padded)
        || !!(rel && rel.squat && (rel.hostMatch === "padded" || rel.hostMatch === "hyphen" || rel.hostMatch === "typo"))
        || !!(typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftRaw))
        || !!(core && core.length >= 4 && (
          (typeof NS.hostLabelIsPaddedBrand === "function" && (
            NS.hostLabelIsPaddedBrand(lab, core)
            || NS.hostLabelIsPaddedBrand(apexFlat0, core)
          ))
          || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && (
            NS.hostLabelIsPrefixedHyphenBrand(labelRaw, core)
            || NS.hostLabelIsPrefixedHyphenBrand(apexLeftRaw, core)
          ))
          || (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
            && (NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw, core)
              || NS.hostLabelIsMarketingPrefixedBrandShape(apexLeftRaw, core)))
          || /[-_](pc|app|soft|safe|vip|pro|cn|win|download|client|free|official|music|musics)$/i.test(labelRaw)
          || /[-_](pc|app|soft|safe|vip|pro|cn|win|download|client|free|official|music|musics)$/i.test(apexLeftRaw)
          || /^(pc|app|get|im|aa|ca|v|ie|win|download|soft|qq)[-_]/i.test(labelRaw)
          || /^(pc|app|get|im|aa|ca|v|ie|win|download|soft|qq)[-_]/i.test(apexLeftRaw)
          || (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(labelRaw)
            && apexLeftRaw && core && apexFlat0.includes(core)
            && apexFlat0 !== core
            // music.qq.com：label=music 营销词但 apex=qq 干净 → 不当 padded
            && !(apexFlat0.length <= 3 && !/^(?:qq|wx).{4,}/i.test(apexFlat0)))
        )));
      try {
        // 干净品牌根产品子域：music.qq.com / y.qq.com / shurufa.sogou.com → 正站跳过
        // win.qq-musics.com 等夹带 apex 不得跳过
        if (typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
          && NS.hostLooksLikeOfficialProductSubdomain(host)) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-official-product-sub", host);
          return false;
        }
        if (typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex(host)) {
          const apL = apexLeftRaw || "";
          const paddedApex = typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(apL);
          if (!paddedApex) {
            NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-product-subdomain", host);
            return false;
          }
        }
      } catch { /* ignore */ }

      // ★ 展示名：只取等权综合（resolveSpoofDisplayBrand 滤主机碎片 Iehuorong/Huorongpc）
      // isPaddedHost / core / StronglyAligned 只决定「拦不拦」，不写 brand 字符串
      let brand = "";
      const isDebris = (t) => {
        try {
          return typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(t, host);
        } catch { return false; }
      };
      try {
        if (typeof NS.resolveSpoofDisplayBrand === "function") {
          brand = NS.resolveSpoofDisplayBrand(host) || "";
        }
      } catch { brand = ""; }
      if (brand && isDebris(brand)) brand = "";
      if (!brand || brand.length < 2) {
        try {
          const pk = typeof NS.collectPrimaryBrandKeywords === "function"
            ? NS.collectPrimaryBrandKeywords()
            : null;
          if (typeof NS.normalizeDisplayBrandName === "function" && pk && pk.display && !isDebris(pk.display)) {
            brand = NS.normalizeDisplayBrandName(pk.display) || pk.display;
          } else if (pk && pk.display && !isDebris(pk.display)) {
            brand = pk.display;
          }
          if ((!brand || isDebris(brand)) && pk && pk.cn && pk.cn[0]) {
            brand = typeof NS.normalizeDisplayBrandName === "function"
              ? (NS.normalizeDisplayBrandName(pk.cn[0]) || pk.cn[0])
              : pk.cn[0];
          }
          if ((!brand || isDebris(brand)) && pk && pk.latin) {
            for (let i = 0; i < pk.latin.length; i++) {
              const lat = pk.latin[i];
              if (!lat || isDebris(lat)) continue;
              if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(lat)) continue;
              brand = typeof NS.formatBrandTokenForDisplay === "function"
                ? NS.formatBrandTokenForDisplay(lat)
                : lat;
              if (brand) break;
            }
          }
          // 夹带核 + 页内中文桥：火绒
          if ((!brand || isDebris(brand)) && core && core.length >= 4
            && typeof NS.DOMAIN_LATIN_CN_BRIDGE === "object" && NS.DOMAIN_LATIN_CN_BRIDGE[core]) {
            const blob = String((pk && pk.blob) || document.title || "");
            for (const cn of NS.DOMAIN_LATIN_CN_BRIDGE[core]) {
              if (blob.includes(cn)) { brand = cn; break; }
            }
            if (!brand || isDebris(brand)) {
              brand = typeof NS.formatBrandTokenForDisplay === "function"
                ? NS.formatBrandTokenForDisplay(core)
                : core;
            }
          }
        } catch { brand = ""; }
      }
      if (brand && isDebris(brand)) brand = "";
      // 无等权身份时：夹带站仍可 arm，但 toast 用中性文案（勿把 Iehuorong/Reserved 当品牌）
      if (!brand || brand.length < 2) {
        if (!isPaddedHost && !hyphenHost && !digitPadHost) return false;
        brand = "品牌";
      }
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)) return false;
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(brand)) return false;
      // 夹带域（ca-hongrong）绝不可因「自托管资源」跳过；仅干净主机 + CDN 子域才跳过
      try {
        if (!isPaddedHost && !hyphenHost && !digitPadHost
          && typeof NS.hostLabelMatchesPageResourceApex === "function"
          && NS.hostLabelMatchesPageResourceApex(host)) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-resource-apex", host);
          return false;
        }
      } catch { /* ignore */ }

      // SEO 套壳模板（ca-aurora-template / ca-Download-CMS）+ 官方下载话术 → 强化为可 arm
      let seoShell = false;
      try {
        const gen = String(document.querySelector('meta[name="generator"]')?.getAttribute("content") || "");
        const tpl = String(document.querySelector('meta[name="template"]')?.getAttribute("content") || "");
        seoShell = /ca-?download-?cms|ca-?aurora|seo[_-]?template|aurora-template/i.test(`${gen} ${tpl}`)
          || /ca-?download-?cms|ca-?aurora|seo[_-]?template/i.test(document.documentElement?.innerHTML?.slice(0, 8000) || "");
      } catch { /* ignore */ }

      const title = document.title || "";
      const kwMeta = document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "";
      // 官方下载话术（假官网必备）；兼容「| 官方下载」
      const officialClaim = /官网|官方下载|官方正版|官方网站|官方高速|官方渠道|免费下载|立即下载|客户端下载|下载中心|行业标准工具/i.test(
        `${title} ${kwMeta}`
      ) || /官方下载|免费下载|立即下载/i.test(title);

      let hub = 0;
      let dlCta = 0;
      try {
        document.querySelectorAll(
          "a[href], a[data-href], button, .btn-header, .btn-primary, .btn-lg, .btn-sm, .download-btn, [class*='download'], [onclick*='Download'], [onclick*='download']"
        ).forEach((el) => {
          const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
          const text = (el.textContent || "").replace(/\s+/g, " ").trim();
          const onclick = el.getAttribute("onclick") || "";
          if (/免费下载|立即下载|立即免费下载|官方下载|个人版|企业版|客户端下载|下载中心|获取客户端/i.test(text)) dlCta++;
          else if (text.length <= 24 && /下载/.test(text)) dlCta++;
          if (/openDownloadModal|startDownload|showDownload/i.test(onclick)) dlCta++;
          if (href && /download\.html|(?:^|\/)download(?:\/|\.html?|$)|down\.html|install\.html/i.test(href)) hub++;
          if (href && typeof NS.looksLikeSameOriginLandingPageUrl === "function" && NS.looksLikeSameOriginLandingPageUrl(href)) hub++;
        });
      } catch { /* ignore */ }

      const hollowSupport = typeof NS.pageLooksLikeHollowSupportContactShell === "function"
        && NS.pageLooksLikeHollowSupportContactShell();
      const netdiskQr = typeof NS.pageLooksLikeNetdiskQrOnlyDownload === "function"
        && NS.pageLooksLikeNetdiskQrOnlyDownload();

      // 用户规则：
      // A 半真半假（padded/typo/hyphen/partial）→ 盗版
      // B 不相关 + 官网下载壳 → 盗版
      // 几乎关联已在上方 return false
      const domainUnrelated = !!(rel && !rel.related && !rel.squat
        && (rel.mismatch || rel.hostMatch === "none" || !rel.hostMatch));
      const pathSquat = isPaddedHost || hyphenHost || !!(rel && rel.squat)
        || !!(core && core.length >= 4 && /^(?:aa|bb|cc|ca|im|get|pc|app|soft|download|free)[-_]/i.test(labelRaw))
        || !!(rel && (rel.hostMatch === "partial" || rel.hostMatch === "padded"
          || rel.hostMatch === "typo" || rel.hostMatch === "hyphen"));
      const pathUnrelatedOfficial = domainUnrelated && officialClaim && (dlCta >= 1 || hub >= 1);
      const pathHollowOrNetdisk = officialClaim && (dlCta >= 1 || hub >= 1)
        && (hollowSupport || netdiskQr)
        && !!(rel && !rel.related);
      const pathSeoCnBrand = seoShell && officialClaim && (dlCta >= 1 || hub >= 1)
        && brand.length >= 2
        && !!(rel && (!rel.related || rel.squat));

      if (!pathSquat && !pathUnrelatedOfficial && !pathHollowOrNetdisk && !pathSeoCnBrand) return false;
      // squat：有官方话术或下载 CTA 即可（数字/连字符夹带域名常同时具备）
      if (pathSquat && !officialClaim && dlCta < 1 && hub < 1) return false;
      if ((pathUnrelatedOfficial || pathHollowOrNetdisk) && dlCta < 1 && hub < 1) return false;

      const matchHint = pathSquat
        ? ((rel && rel.hostMatch === "typo") ? "拼写仿冒"
          : (hyphenHost || (rel && rel.hostMatch === "hyphen")) ? "域名用连字符拆分品牌名"
          : digitPadHost ? "域名用数字品牌前缀+乱拼后缀" : "域名夹带品牌前缀/后缀")
        : pathSeoCnBrand
          ? "SEO套壳模板+品牌官方下载话术"
          : pathHollowOrNetdisk
            ? (hollowSupport ? "宣称支持/联系但无真实联系方式" : "仅网盘扫码分发无安装包直链")
            : "域名与品牌无关";
      state.spoofBrand = brand;
      state._brandSpoofPortalDetected = true;
      const noticeTitle = `已识别仿冒「${brand}」官网`;
      const noticeMsg = `域名 ${location.hostname || host} 与标题品牌「${brand}」不匹配，疑似仿冒官网下载站`;
      NS.addSignal(
        "仿冒品牌官网下载站",
        24,
        `标题/正文品牌「${brand}」与域名 ${location.hostname || host} 不匹配（${matchHint}）；下载导流门户`
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
        pathSquat ? `squat:${(rel && rel.hostMatch) || "padded"}` : "unrelated-official",
        "cta=", dlCta, "hub=", hub
      );
      try {
        if (typeof NS.proactivelyProbeDownloadButtons === "function") {
          Promise.resolve().then(() => NS.proactivelyProbeDownloadButtons({ force: true, reason: "after-home-fast" })).catch(() => {});
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
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-app-market-listing");
        return false;
      }
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-software-catalog-portal");
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // 干净品牌根 + CDN 子域资源（cdn-www.huorong.cn）→ 正站；夹带域 qq-musics / ca-hongrong 不走此放行
      try {
        const hostChk = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        const labChk = (hostChk.split(".")[0] || "").toLowerCase();
        const apexChk = (typeof NS.getRegistrableDomain === "function"
          ? NS.getRegistrableDomain(hostChk) : hostChk) || hostChk;
        const apexLeftChk = (apexChk.split(".")[0] || "").toLowerCase();
        const looksPadHost = /[-_]/.test(labChk) || /[-_]/.test(apexLeftChk)
          || /^(?:aa|bb|cc|ca|im|get|pc|app|soft|download|free|win|qq)[-_]/i.test(labChk)
          || /^(?:aa|bb|cc|ca|im|get|pc|app|soft|download|free|win|qq)[-_]/i.test(apexLeftChk)
          || (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftChk))
          || (typeof NS.inferMarketingPaddedBrandCore === "function"
            && (NS.inferMarketingPaddedBrandCore(labChk) || NS.inferMarketingPaddedBrandCore(apexLeftChk)))
          || /^(?:qq|wx)(?:music|musics|yinyue|yinle)$/i.test(apexLeftChk.replace(/[^a-z0-9]/g, ""));
        if (!looksPadHost && typeof NS.hostLabelMatchesPageResourceApex === "function" && NS.hostLabelMatchesPageResourceApex()) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-resource-apex");
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      } catch { /* ignore */ }

      // 官方产品子域（music.qq.com / y.qq.com）+ 页内品牌 → 正站
      try {
        const hostOff = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        if (typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
          && NS.hostLooksLikeOfficialProductSubdomain(hostOff)) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-official-product-subdomain", hostOff);
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      } catch { /* ignore */ }

      // 多标签身份（title/logo alt/nav）能拼成域名 → 正站；夹带 apex 上的 win. 不得对齐跳过
      try {
        const hostAlign = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        const labAlign = (hostAlign.split(".")[0] || "").toLowerCase();
        const apexAlign = (typeof NS.getRegistrableDomain === "function"
          ? NS.getRegistrableDomain(hostAlign) : hostAlign) || hostAlign;
        const apexLeftAlign = (apexAlign.split(".")[0] || "").toLowerCase();
        const padAlign = typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftAlign);
        if (!padAlign && typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
          && (NS.hostLabelStronglyAlignedWithIdentityKeywords(labAlign)
            || NS.hostLabelStronglyAlignedWithIdentityKeywords(apexLeftAlign))) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-identity-keyword-aligned", labAlign);
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      } catch { /* ignore */ }

      // ═══ 主门控：域名 ↔ 主身份关键词相关度 ═══
      const domainRel = typeof NS.evaluateDomainKeywordRelevance === "function"
        ? NS.evaluateDomainKeywordRelevance()
        : null;
      // 域名与关键词一致（正站）→ 永不仿冒
      if (domainRel && domainRel.related && !domainRel.squat) {
        NS.silverfoxLog && NS.silverfoxLog(
          "brand-spoof", "skip-domain-keyword-related",
          domainRel.hostMatch, domainRel.brandToken || domainRel.brand
        );
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // 快速路径：squat 或「无关 + 官方下载」
      if (typeof NS.tryArmChineseBrandDownloadHomeSpoof === "function" && NS.tryArmChineseBrandDownloadHomeSpoof()) {
        return true;
      }

      // 发行版 ISO 镜像页（Arch/Ubuntu…）在落地壳判定前跳过，避免 ISO 列表被当 exe 假官网
      if (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-os-distro-iso");
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // 非软件下载落地页壳 → 不 arm
      const landingShell = typeof NS.evaluateSoftwareDownloadLandingShell === "function"
        ? NS.evaluateSoftwareDownloadLandingShell()
        : null;
      if (!landingShell || !landingShell.ok) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-not-download-landing", landingShell || {});
        state._pendingSoftBrandSpoof = false;
        return false;
      }
      if (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-high-volume-archive");
        return false;
      }
      try {
        if (typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex()) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-product-subdomain-of-apex");
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      } catch { /* ignore */ }

      // 有效 ICP / 超成熟：不 toast 软仿冒（假站通常无备案）
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

      // 用 domainRel 构造错配状态（不再依赖 partial 误放行）
      const hasBrandKw = !!(domainRel && (domainRel.brand || domainRel.brandToken
        || (domainRel.keywords && domainRel.keywords.length)));
      const domainMismatch = !!(domainRel && !domainRel.related && hasBrandKw
        && (domainRel.mismatch || domainRel.squat || domainRel.hostMatch === "none"
          || domainRel.hostMatch === "padded" || domainRel.hostMatch === "typo"
          || domainRel.hostMatch === "hyphen" || domainRel.hostMatch === "partial"));

      if (!domainMismatch) {
        // 再跑完整 corr 兜底
        const corr = typeof NS.evaluateTitleHostBrandCorrelation === "function"
          ? NS.evaluateTitleHostBrandCorrelation()
          : null;
        if (!corr || !corr.mismatch) {
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      }

      let titleHostCorr = {
        mismatch: true,
        hostMatch: (domainRel && domainRel.hostMatch) || "none",
        brandToken: (domainRel && (domainRel.brandToken || domainRel.brand)) || "",
        displayBrand: (domainRel && domainRel.brand) || "",
        brandHits: 8,
        rigorousMatch: false
      };
      if (domainRel && domainRel.squat) {
        titleHostCorr.hostMatch = domainRel.hostMatch || "padded";
      }
      if (domainRel && !domainRel.related && !domainRel.squat) {
        titleHostCorr.hostMatch = "none";
      }

      // 下载壳 + 官方话术
      const claimedCtx = typeof NS.getClaimedBrandContext === "function" ? NS.getClaimedBrandContext() : {};
      const { brandSource, claimsOfficial, tokens } = claimedCtx;
      const productBrand = claimedCtx.productBrand || null;
      const titleBlob = `${document.title || ""} ${brandSource || ""}`;
      const officialPitch = !!(landingShell.pitch || landingShell.softPitch
        || claimsOfficial
        || (typeof NS.pageClaimsOfficialDownload === "function" && NS.pageClaimsOfficialDownload())
        || (typeof NS.pageClaimsBrandDownloadLanding === "function" && NS.pageClaimsBrandDownloadLanding())
        || /官网|官方下载|官方正版|官方网站|官方高速|免费下载|立即下载|下载中心|客户端下载/i.test(titleBlob));
      if (!officialPitch && landingShell.ctaCount < 1 && landingShell.pkgCount < 1 && !landingShell.hasHub) {
        return false;
      }
      // 有下载壳 + 域名错配 +（官方话术或明确下载 CTA）
      if (!officialPitch && landingShell.ctaCount < 1) return false;

      // soft padded 等 ICP
      const isSoftPadded = titleHostCorr.hostMatch === "padded"
        && !state._seoCloakKitDetected && !state._fakeSpaDetected && !state._desktopForceDlKit;
      if (isSoftPadded && typeof NS.icpSettledForSoftBrandSpoof === "function" && !NS.hasValidIcpRecord()) {
        if (!NS.icpSettledForSoftBrandSpoof()) {
          state._pendingSoftBrandSpoof = true;
          return false;
        }
      }
      if (NS.hasValidIcpRecord() && isSoftPadded && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // ★ 展示品牌：只读等权（与 home-fast 一致）。拒绝 Iehuorong/Huorongpc 主机碎片
      let brandDisp = "";
      const debrisHost = (t) => {
        try {
          return typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(t, location.hostname);
        } catch { return false; }
      };
      try {
        if (typeof NS.resolveSpoofDisplayBrand === "function") {
          brandDisp = NS.resolveSpoofDisplayBrand(location.hostname) || "";
        }
      } catch { brandDisp = ""; }
      if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
      try {
        if (!brandDisp) {
          const pkD = typeof NS.collectPrimaryBrandKeywords === "function"
            ? NS.collectPrimaryBrandKeywords()
            : null;
          brandDisp = (pkD && pkD.display) || "";
          if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
          if (brandDisp && typeof NS.normalizeDisplayBrandName === "function") {
            brandDisp = NS.normalizeDisplayBrandName(brandDisp) || brandDisp;
          }
          if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
          if (brandDisp && typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(brandDisp)) {
            brandDisp = (pkD && pkD.cn && pkD.cn[0]) || (productBrand && productBrand.cnBrand) || "";
          }
          if ((!brandDisp || debrisHost(brandDisp)) && pkD && pkD.cn && pkD.cn[0]) brandDisp = pkD.cn[0];
        }
      } catch { /* keep brandDisp */ }
      // domainRel.brand 仅当已在等权 cn/latin 列表中才补（避免 bestTok=Reserved/Iehuorong 进 UI）
      if ((!brandDisp || debrisHost(brandDisp)) && domainRel && domainRel.brand
        && !debrisHost(domainRel.brand)
        && !(typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(domainRel.brand))) {
        try {
          const b0 = typeof NS.normalizeDisplayBrandName === "function"
            ? (NS.normalizeDisplayBrandName(domainRel.brand) || domainRel.brand)
            : domainRel.brand;
          const pk2 = typeof NS.collectPrimaryBrandKeywords === "function"
            ? NS.collectPrimaryBrandKeywords()
            : null;
          if (b0 && pk2 && !debrisHost(b0)) {
            if (pk2.cn && pk2.cn.some((x) => String(x) === b0 || String(x).includes(b0) || b0.includes(String(x)))) {
              brandDisp = b0;
            } else {
              const low = String(b0).toLowerCase().replace(/[^a-z0-9]/g, "");
              if (low && !debrisHost(low) && pk2.latin && pk2.latin.some((x) => String(x).toLowerCase() === low)) brandDisp = b0;
            }
          }
        } catch { /* ignore */ }
      }
      if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
      if (brandDisp && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brandDisp)) {
        brandDisp = (productBrand && productBrand.cnBrand) || "";
      }
      if (brandDisp && /[一-鿿]/.test(brandDisp) && typeof NS.trimChineseBrandTrail === "function") {
        brandDisp = NS.trimChineseBrandTrail(brandDisp) || brandDisp;
      }
      if (!brandDisp || (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(String(brandDisp).toLowerCase()))) {
        state.spoofBrand = state.spoofBrand || "";
      } else {
        state.spoofBrand = brandDisp;
      }

      const showBrand = (brandDisp && !(NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(String(brandDisp).toLowerCase())))
        ? brandDisp
        : "";
      if (!showBrand && !titleHostCorr.brandToken) {
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      const matchHint = titleHostCorr.hostMatch === "typo" ? "拼写仿冒"
        : titleHostCorr.hostMatch === "padded" ? "域名夹带品牌前缀/后缀"
          : titleHostCorr.hostMatch === "hyphen" ? "域名用连字符拆分品牌名"
            : titleHostCorr.hostMatch === "none" ? "域名与品牌无关"
              : "关联不严谨";
      const signalDetail = `标题/正文品牌「${showBrand || titleHostCorr.brandToken}」与域名 ${location.hostname} 不匹配（${matchHint}）`;

      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected
        && titleHostCorr.hostMatch === "padded") {
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      NS.addSignal("仿冒品牌官网下载站", 24, signalDetail);
      state._brandSpoofPortalDetected = true;
      const noticeTitle = showBrand ? `已识别仿冒「${showBrand}」官网` : "已识别仿冒品牌官网";
      const noticeMsg = showBrand
        ? `域名 ${location.hostname} 与标题品牌「${showBrand}」不匹配，疑似仿冒官网下载站`
        : `域名 ${location.hostname} 与页面宣称品牌不匹配，疑似仿冒官网下载站`;
      const lockHardNow = titleHostCorr.hostMatch !== "padded"
        || !!(landingShell && (landingShell.hardShell || landingShell.hasHub));
      NS.installDownloadGuard(showBrand ? `仿冒品牌官网下载站（仿冒「${showBrand}」）` : "仿冒品牌官网下载站", {
        notify: true,
        href: "",
        message: noticeMsg,
        title: noticeTitle,
        guardKind: "brand-spoof",
        forceNotify: true,
        lockHard: lockHardNow
      });
      NS.disableAllDownloadIntentControls();
      state._pendingSoftBrandSpoof = false;
      try {
        if (typeof NS.proactivelyProbeDownloadButtons === "function") {
          Promise.resolve().then(() => NS.proactivelyProbeDownloadButtons({ force: true, reason: "after-brand-spoof" })).catch(() => {});
        }
      } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  /** 父页品牌 vs 域名错配（主动 fetch 落地页时联动仿冒） */
  NS.getParentPageBrandSpoofContext = function () {
    try {
      if (typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
        return { mismatch: false, brand: "", hostMatch: "portal", brandToken: "" };
      }
      if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) {
        return { mismatch: false, brand: "", hostMatch: "market", brandToken: "" };
      }
      // 主门控
      if (typeof NS.evaluateDomainKeywordRelevance === "function") {
        const rel = NS.evaluateDomainKeywordRelevance();
        if (rel.related && !rel.squat) {
          return { mismatch: false, brand: rel.brand || "", hostMatch: rel.hostMatch || "exact", brandToken: rel.brandToken || "" };
        }
        if (NS.hasValidIcpRecord() || (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature())) {
          if (!rel.squat) {
            return { mismatch: false, brand: rel.brand || "", hostMatch: "trusted", brandToken: rel.brandToken || "" };
          }
        }
        if (rel.squat) {
          return { mismatch: true, brand: rel.brand || "", hostMatch: rel.hostMatch || "padded", brandToken: rel.brandToken || "" };
        }
        // 无关 / mismatch 标记：有主关键词品牌即联动
        if (rel.mismatch || (rel.hostMatch === "none" && (rel.brand || (rel.keywords && rel.keywords.length)))) {
          return {
            mismatch: true,
            brand: rel.brand || "",
            hostMatch: rel.hostMatch || "none",
            brandToken: rel.brandToken || rel.brand || ""
          };
        }
        return { mismatch: false, brand: rel.brand || "", hostMatch: rel.hostMatch || "none", brandToken: rel.brandToken || "" };
      }
      return { mismatch: false, brand: "", hostMatch: "" };
    } catch {
      return { mismatch: false, brand: "", hostMatch: "" };
    }
  };

  /** 从落地页 HTML 抽取安装包 URL */
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

  NS.analyzeFetchedDownloadLandingHtml = function (source, chain, opts) {
    const o = opts || {};
    if (!source || source.length < 80) return { hit: false, packages: [] };
    const osIsoLanding = /\.iso(?:\?|"|'|\s|>|\/|#|$)/i.test(source)
      && (/(?:sha256sums|b2sums|magnet:\?xt=urn:btih:|\.torrent\b|bittorrent|pgp\s*签名|gpg\s*--verify)/i.test(source)
        || /(?:mirror\.|mirrors\.|镜像站|\/iso\/\d{4})/i.test(source));
    if (osIsoLanding) {
      return {
        hit: false, remoteSetupFetchPattern: false, autoDownloadDispatchPattern: false,
        remoteDownloadUrlPattern: false, suspiciousLandingPage: false, brandSpoofLanding: false,
        staticPackageLanding: false, usesRemoteJsWithAttr: false, redirectCount: 0, osIsoLanding: true, packages: []
      };
    }
    const baseHref = o.baseHref || location.href;
    const packages = typeof NS.extractPackageUrlsFromHtml === "function"
      ? NS.extractPackageUrlsFromHtml(source, baseHref)
      : [];
    const remoteSetupFetchPattern = /fetch\s*\(\s*[^)]*\.(?:txt|json|php)/i.test(source)
      || /(?:const|let|var)\s+\w*(?:REMOTE_)?(?:SETUP|CONFIG|VERSION|PACKAGE)_?URL\s*=/i.test(source)
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
    const suspiciousLandingPage = landingDownloadKeywords >= 5
      && (remoteSetupFetchPattern || usesRemoteJsWithAttr
        || (remoteDownloadUrlPattern && autoDownloadDispatchPattern)
        || (ossOrRandomPkg && autoDownloadDispatchPattern))
      && /下载|download|install|setup|客户端/i.test(source);

    const parentMismatch = !!o.parentBrandMismatch;
    const parentBrand = String(o.parentBrand || "");
    const brandHintInLanding = parentBrand
      ? (source.includes(parentBrand) || (parentBrand.length >= 2 && new RegExp(parentBrand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(source)))
      : false;
    // 父页品牌/域名错配时：落地页只要有下载话术或包，即算仿冒落地（勿等用户点进 download.html）
    const brandSpoofLanding = parentMismatch && (
      packages.length >= 1
      || landingDownloadKeywords >= 2
      || (landingDownloadKeywords >= 1 && brandHintInLanding)
      || remoteSetupFetchPattern
      || remoteDownloadUrlPattern
      || /免费下载|立即下载|官方下载|安装包|\.exe|\.zip|download/i.test(source)
    );
    let staticPackageLanding = packages.length >= 1 && landingDownloadKeywords >= 3
      && /免费下载|立即下载|官方下载|客户端|安装包|个人版/i.test(source);
    if (staticPackageLanding && !parentMismatch && packages.length >= 1) {
      const allClearProduct = packages.every((p) => {
        try {
          const fn = typeof NS.getFilenameFromUrl === "function" ? NS.getFilenameFromUrl(p) : "";
          return typeof NS.looksLikeStrongProductInstallerName === "function" && NS.looksLikeStrongProductInstallerName(fn);
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

  NS.pageHasProactiveDownloadButtonTargets = function () {
    try {
      // 海量镜像/ISO / 天气资讯门户：禁止因附属 APK/广告拖住 analysisComplete
      if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) return false;
      if (typeof NS.pageLooksLikeContentInfoPortal === "function" && NS.pageLooksLikeContentInfoPortal()) return false;
      if (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa()
        && typeof NS.isBenignContentPage === "function" && NS.isBenignContentPage()) return false;
      if ((typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList())
        || (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())) {
        return false;
      }
      if (typeof NS.collectProactiveDownloadTargets === "function") {
        const t = NS.collectProactiveDownloadTargets();
        if (t && ((t.landing && t.landing.length > 0) || (t.probe && t.probe.length > 0))) return true;
      }
      // 仅窄选择器；勿用 a[href*='/download']（Arch 导航/镜像会全中）
      if (document.querySelector(
        "a[href*='download.html'], a.download-btn[href], a.btn-download[href], "
        + "a.btn-header[href], a.btn-primary[href*='down'], a.btn-lg[href*='down'], "
        + "#mainDownloadBtn[href], a.download-uri[href]"
      )) return true;
      return false;
    } catch { return false; }
  };

  NS.collectProactiveDownloadTargets = function () {
    const landing = [];
    const probe = [];
    const seenL = new Set();
    const seenP = new Set();
    // 海量下载列表：直接空结果，禁止 querySelectorAll("a[href]")
    try {
      if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
        return { landing: [], probe: [] };
      }
      if ((typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList())
        || (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())) {
        return { landing: [], probe: [] };
      }
    } catch { /* ignore */ }
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
      // 禁止裸 a[href]：大页上构建 NodeList 本身就会卡死主线程
      const nodes = document.querySelectorAll(
        "a[href*='download.html'], a[data-href*='download'], a.download-btn, a.btn-download, "
        + ".download-btn a, .btn-download, .btn-header, a.btn-primary, a.btn-lg, a.btn-header, "
        + "#mainDownloadBtn, a.download-uri, [class*='btn-download'], [class*='download-btn'], "
        + "button[class*='download'], a[href*='down.html'], a[href*='install.html']"
      );
      const lim = Math.min(nodes.length, 48);
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
        // download.html / down.html 等：无论文案强弱都收（首页「免费下载」）
        const pathLand = /(?:^|[/?#&=])download\.html|(?:^|\/)(?:download|down|install|setup)(?:\/|\.html?|$)/i.test(href)
          || /download\.html|down\.html|install\.html/i.test(href);
        const sameOriginLand = typeof NS.looksLikeSameOriginLandingPageUrl === "function" && NS.looksLikeSameOriginLandingPageUrl(href);
        if (!intent && !sameOriginLand && !pathLand
          && !(typeof NS.needsDownloadBehaviorProbe === "function" && NS.needsDownloadBehaviorProbe(href, el))) continue;
        if (NS.isPackageFileUrl && NS.isPackageFileUrl(href)) continue;
        if (pathLand || sameOriginLand) pushL(href, el);
        else if (typeof NS.needsDownloadBehaviorProbe === "function" && NS.needsDownloadBehaviorProbe(href, el)) pushP(href, el);
        else if (intent) {
          try {
            const u = new URL(href, location.href);
            if (u.origin !== location.origin || /\.(?:php|asp|aspx)$/i.test(u.pathname)) pushP(href, el);
            else if (/\.(?:html?)$/i.test(u.pathname) && /down|install|client|soft|get|download/i.test(u.pathname + u.href)) pushL(href, el);
            else if (/download/i.test(href)) pushL(href, el);
          } catch { /* ignore */ }
        }
      }
    } catch { /* ignore */ }
    return { landing: landing.slice(0, 10), probe: probe.slice(0, 6) };
  };

  /**
   * 主动 fetch 下载按钮目标（download.html 等），无需用户点击。
   * opts.force：扫尾强制再跑（即使首页已 arm brand-spoof / 有 ICP 也要拉落地页包链）
   */
  NS.proactivelyProbeDownloadButtons = async function (opts) {
    const o = opts || {};
    const state = NS.state;
    try {
      if (state._proactiveProbeBusy) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "busy-skip");
        return false;
      }
      // 已 hard 锁且非 force：可跳过；force 仍要 fetch 落地页装包 URL
      if (state.downloadGuardInstalled && !o.force && state._brandSpoofPortalDetected) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "guard-already-on-skip");
        return false;
      }
      if (typeof NS.shouldSkipHeavyPageScan === "function" && NS.shouldSkipHeavyPageScan()) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "skip-heavy-page");
        return false;
      }
      if (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive()) return false;
      if (typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList()) return false;
      if (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload()) return false;
      if (NS.pageLooksLikeSearchEngineResultsPage && NS.pageLooksLikeSearchEngineResultsPage()) return false;

      const { landing, probe } = NS.collectProactiveDownloadTargets();
      const hasTargets = (landing && landing.length > 0) || (probe && probe.length > 0);
      if (!hasTargets) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "no-targets");
        return false;
      }

      // 域名与关键词 related 且非 squat：不 arm 仿冒，但仍可 fetch 看是否有异常包（force 时）
      let domainRelatedSafe = false;
      try {
        if (typeof NS.evaluateDomainKeywordRelevance === "function") {
          const rel = NS.evaluateDomainKeywordRelevance();
          domainRelatedSafe = !!(rel && rel.related && !rel.squat);
        }
      } catch { /* ignore */ }

      // 可信门户：仅无 force 且有明确 download.html 目标时仍 fetch（不因 ICP 整段禁用）
      const trustedSoft = (NS.shouldNeverArmProtection && NS.shouldNeverArmProtection())
        || (NS.looksLikeMatureOfficialPortal && NS.looksLikeMatureOfficialPortal())
        || (NS.hasValidIcpRecord && NS.hasValidIcpRecord())
        || (typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature());
      if (trustedSoft && domainRelatedSafe && !o.force) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "skip-trusted-related");
        return false;
      }

      const now = Date.now();
      const coolMs = o.force ? 800 : (hasTargets ? 1500 : 4000);
      if (!o.force && state._proactiveProbeAt && now - state._proactiveProbeAt < coolMs) {
        NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "cooldown");
        return false;
      }
      state._proactiveProbeAt = now;
      state._proactiveProbeBusy = true;

      const parentCtx = typeof NS.getParentPageBrandSpoofContext === "function"
        ? NS.getParentPageBrandSpoofContext()
        : { mismatch: false, brand: "" };
      // 再补一轮 domainRel mismatch（父页中文品牌 + 无关域名）
      let parentMismatch = !!parentCtx.mismatch;
      let parentBrand = parentCtx.brand || state.spoofBrand || "";
      try {
        if (typeof NS.evaluateDomainKeywordRelevance === "function") {
          const rel2 = NS.evaluateDomainKeywordRelevance();
          if (rel2 && !rel2.related && (rel2.mismatch || rel2.hostMatch === "none") && (rel2.brand || rel2.brandToken)) {
            parentMismatch = true;
            parentBrand = parentBrand || rel2.brand || rel2.brandToken || "";
          }
        }
      } catch { /* ignore */ }

      NS.silverfoxLog && NS.silverfoxLog(
        "proactive-probe", "start",
        "landing=", landing.length, "probe=", probe.length,
        "parentMismatch=", parentMismatch, "brand=", parentBrand || "",
        "reason=", o.reason || ""
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
          if (typeof NS.fetchWithRedirectChain !== "function") {
            NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "no-fetch-api");
            return null;
          }
          NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "fetch", href);
          const { chain, finalText: source } = await NS.fetchWithRedirectChain(href, 4);
          if (!source || source.length < 40) {
            NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "fetch-empty", href, "len=", (source && source.length) || 0);
            return null;
          }
          const analysis = NS.analyzeFetchedDownloadLandingHtml(source || "", chain, {
            baseHref: href,
            parentBrandMismatch: parentMismatch,
            parentBrand: parentBrand || ""
          });
          // 父页品牌错配 + 落地页有下载话术 → 即使无包也视为仿冒落地
          if (parentMismatch && !analysis.hit) {
            const dlKw = (source.match(/下载|download|安装|客户端|免费|官方/gi) || []).length;
            if (dlKw >= 2 || /download|安装包|\.exe|\.zip|免费下载|官方下载/i.test(source)) {
              analysis.hit = true;
              analysis.brandSpoofLanding = true;
            }
          }
          if (!analysis.hit) {
            NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "fetch-no-hit", href, "len=", source.length);
            // 仍收集包 URL 供后续保护
            const pkgs0 = analysis.packages || [];
            for (const p of pkgs0.slice(0, 8)) {
              if (p && state.protectedTargets && !state.protectedTargets.includes(p)) state.protectedTargets.push(p);
            }
            return null;
          }
          const pkgs = analysis.packages || [];
          try {
            for (const p of pkgs.slice(0, 8)) {
              if (p && !state.protectedTargets.includes(p)) state.protectedTargets.push(p);
            }
          } catch { /* ignore */ }
          return { href, el, analysis, packages: pkgs };
        } catch (e) {
          NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "fetch-err", href, e && e.message);
          return null;
        }
      }));
      const landHit = landResults.find(Boolean);
      if (landHit) {
        const isBrand = !!(landHit.analysis.brandSpoofLanding || parentMismatch);
        // 可信 + 域名相关：不 arm 仿冒
        if (isBrand && domainRelatedSafe && trustedSoft) {
          NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "hit-but-trusted-related");
        } else {
          if (isBrand && parentBrand && !state.spoofBrand) {
            try { state.spoofBrand = parentBrand; } catch { /* ignore */ }
          }
          const showBrand = state.spoofBrand || parentBrand || "";
          const reason = landHit.analysis.brandSpoofLanding || parentMismatch
            ? `主动探测：首页下载入口指向仿冒落地页（${showBrand || "品牌"} 与域名不匹配）`
            : landHit.analysis.staticPackageLanding
              ? "主动探测：下载按钮指向的落地页含安装包分发"
              : "主动探测：下载按钮指向的落地页含远程配置/动态下发安装包链路";
          NS.addSignal(
            (landHit.analysis.brandSpoofLanding || parentMismatch) ? "主动探测仿冒下载落地" : "同域下载落地页远程链",
            (landHit.analysis.brandSpoofLanding || parentMismatch) ? 22 : 16,
            `${reason} → ${landHit.href}`
          );
          if (landHit.el) try { NS.disableOneSuspiciousElement(landHit.el, landHit.href); } catch { /* ignore */ }
          const pkgHref = (landHit.packages && landHit.packages[0])
            || (state.protectedTargets || []).find((t) => /\.(?:exe|zip|msi|apk|dmg)/i.test(String(t)))
            || landHit.href;
          NS.installDownloadGuard(reason, {
            notify: true,
            href: pkgHref,
            message: showBrand && isBrand
              ? `域名 ${location.hostname} 与标题品牌「${showBrand}」不匹配，疑似仿冒官网下载站`
              : (pkgHref !== landHit.href ? String(pkgHref) : landHit.href),
            forceNotify: true,
            title: showBrand && isBrand ? `已识别仿冒「${showBrand}」官网` : "已拦截可疑下载落地页",
            guardKind: isBrand ? "brand-spoof" : "package",
            lockHard: true
          });
          NS.disableAllDownloadIntentControls();
          try { state._brandSpoofPortalDetected = state._brandSpoofPortalDetected || isBrand; } catch { /* ignore */ }
          armed = true;
        }
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
      NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "done", "armed=", armed);
      return armed;
    } catch (e) {
      NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "err", e && e.message);
      return false;
    } finally {
      try { state._proactiveProbeBusy = false; } catch { /* ignore */ }
    }
  };

  NS.detectLinkedLandingPageSources = async function () {
    return NS.proactivelyProbeDownloadButtons({ force: true, reason: "compat-linked" });
  };
})(window.SilverfoxContent ??= {});
