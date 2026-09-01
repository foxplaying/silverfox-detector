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
  /** 在线证书/运维查询工具页（非软件下载仿冒）→ 各路径统一跳过 */
  NS.pageLooksLikeWebSslOrOpsToolPage = function () {
    try {
      const path = String(location.pathname || "").toLowerCase();
      const title = String(document.title || "");
      const desc = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").slice(0, 280);
      const blob = `${path} ${title} ${desc}`;
      // 有安装包直链则可能是下载站，不跳过
      try {
        if (typeof NS.collectAllPagePackageHrefs === "function") {
          const pkgs = NS.collectAllPagePackageHrefs() || [];
          if (pkgs.length >= 1) return false;
        }
      } catch { /* ignore */ }
      if (/客户端下载|官方下载|安装包下载|免费下载客户端|电脑版下载|正版下载/i.test(blob)) return false;
      // tools 目录 / ssl-lookup / 证书查询 等
      if (/\/tools?(?:\/|$)|ssl[-_]?lookup|ssl[-_]?check|ssl[-_]?query|cert[-_]?check|whois|dns[-_]?lookup|port[-_]?scan|ttfb|ping|traceroute/i.test(path)) {
        return /工具|查询|检测|检查|lookup|check|analyzer|monitor|uptime|证书|ssl|tls|dns|whois/i.test(blob)
          || /\/tools?\//i.test(path);
      }
      if (/证书查询|证书检测|SSL\s*查询|SSL\s*检查|SSL\s*查找|在线工具|工具\s*[-–—|｜]\s*| - 工具/i.test(title)) return true;
      if (/证书|SSL|TLS/i.test(title) && /查询|检测|检查|工具|lookup|checker/i.test(title) && !/下载|安装|客户端/i.test(title)) return true;
      return false;
    } catch { return false; }
  };

  /** 是否纯拉丁展示名（Dingding / Huorong） */
  NS.isPureLatinSpoofBrand = function (t) {
    return /^[A-Za-z][A-Za-z0-9.\-]{2,28}$/.test(String(t || "").trim());
  };

  function normalizeBrandDecisionHost(hostOpt) {
    try {
      if (typeof NS.normalizeDomain === "function") {
        return String(NS.normalizeDomain(hostOpt || location.hostname) || "")
          .toLowerCase().replace(/^www\./, "");
      }
    } catch { /* fall through */ }
    return String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "")
      .toLowerCase().replace(/^www\./, "").split("/")[0];
  }

  function invalidateBrandSpoofDecision(state, reason) {
    if (!state) return 0;
    const next = Number(state._brandSpoofDecisionGeneration || 0) + 1;
    state._brandSpoofDecisionGeneration = next;
    state._brandSpoofDecisionUrl = String((typeof location !== "undefined" && location.href) || "");
    try {
      NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "invalidate-async-decision", reason || "", next);
    } catch { /* ignore */ }
    return next;
  }

  function hasActiveSoftBrandDecision(state) {
    return !!(state && (
      state._brandSpoofPortalDetected
      || state.spoofBrand
      || state._pendingSoftBrandSpoof
      || state._brandSpoofPresentationDeferred
      || state._brandSpoofFinalizeScheduled
      || state._lastGuardNoticeKind === "brand-spoof"
    ));
  }

  function identityVerificationUnavailableForCurrentUrl(stateOpt) {
    try {
      const state = stateOpt || NS.state || {};
      const urlKey = String(location.href || "");
      return state._identityVerificationUnavailable === true
        && String(state._identityVerificationUnavailableUrl || "") === urlKey;
    } catch { return false; }
  }

  const BRAND_IDENTITY_SELECTOR = [
    "title", "h1",
    'meta[name="keywords"]', 'meta[name="description"]',
    'meta[name="application-name"]', 'meta[property="og:title"]',
    'meta[property="og:site_name"]', '[itemprop="name"]',
    '[class*="logo"]', '[id*="logo"]'
  ].join(",");

  function normalizeBrandIdentityFingerprintPart(value) {
    return String(value || "").replace(/\s+/g, " ").trim().slice(0, 240);
  }

  /**
   * A deliberately small identity snapshot.  It follows only fields used by
   * brand election and a boolean download-CTA bit, so ordinary SPA content
   * mutations cannot keep reopening a settled decision.
   */
  NS.captureBrandElectionIdentityFingerprint = function () {
    try {
      const parts = [normalizeBrandIdentityFingerprintPart(document.title || "")];
      const selectors = [
        "h1",
        'meta[name="keywords"]', 'meta[name="description"]',
        'meta[name="application-name"]', 'meta[property="og:title"]',
        'meta[property="og:site_name"]'
      ];
      selectors.forEach((selector) => {
        const node = document.querySelector(selector);
        parts.push(normalizeBrandIdentityFingerprintPart(
          node && (node.getAttribute?.("content") || node.textContent || "")
        ));
      });
      const identityNodes = document.querySelectorAll(
        '[itemprop="name"], [class*="logo"], [id*="logo"]'
      );
      for (let index = 0; index < Math.min(identityNodes.length, 4); index++) {
        const node = identityNodes[index];
        parts.push(normalizeBrandIdentityFingerprintPart(
          node.getAttribute?.("alt") || node.getAttribute?.("title") || node.textContent || ""
        ));
      }
      let hasDownloadCta = false;
      try {
        hasDownloadCta = !!document.querySelector(
          'a[href*="download"], button[class*="download"], [id*="download"], .download-btn'
        );
      } catch { /* ignore */ }
      parts.push(hasDownloadCta ? "download:1" : "download:0");
      return parts.join("|");
    } catch { return ""; }
  };

  function mutationTouchesBrandIdentity(mutations) {
    try {
      for (const mutation of mutations || []) {
        let target = mutation && mutation.target;
        if (target && target.nodeType === 3) target = target.parentElement;
        if (target && (target.matches?.(BRAND_IDENTITY_SELECTOR)
          || target.closest?.(BRAND_IDENTITY_SELECTOR))) return true;
        if (mutation && mutation.type === "attributes") {
          const attr = String(mutation.attributeName || "");
          if (/^(?:content|alt|title)$/i.test(attr)) return true;
          if (attr === "href" && target
            && /download/i.test(`${String(mutation.oldValue || "")} ${String(target.getAttribute?.("href") || "")}`)) {
            return true;
          }
        }
        const added = (mutation && mutation.addedNodes) || [];
        for (let index = 0; index < Math.min(added.length, 8); index++) {
          const node = added[index];
          if (!node || node.nodeType !== 1) continue;
          if (node.matches?.(BRAND_IDENTITY_SELECTOR)
            || node.querySelector?.(BRAND_IDENTITY_SELECTOR)
            || node.matches?.('a[href*="download"], button[class*="download"], [id*="download"], .download-btn')
            || node.querySelector?.('a[href*="download"], button[class*="download"], [id*="download"], .download-btn')) {
            return true;
          }
        }
      }
    } catch { /* ignore */ }
    return false;
  }

  function clearBrandElectionRetryTimers(state) {
    try {
      if (state._brandElectionRetryTimer) clearTimeout(state._brandElectionRetryTimer);
      if (state._brandElectionHydrationStableTimer) clearTimeout(state._brandElectionHydrationStableTimer);
    } catch { /* ignore */ }
    state._brandElectionRetryTimer = null;
    state._brandElectionHydrationStableTimer = null;
    state._brandElectionRetryPending = false;
  }

  function scheduleBrandElectionResume(reason) {
    const state = NS.state;
    if (!state || state._brandElectionHydrationResumeScheduled) return;
    state._brandElectionHydrationResumeScheduled = true;
    try {
      queueMicrotask(() => {
        state._brandElectionHydrationResumeScheduled = false;
        try {
          if (typeof NS.markAnalysisComplete === "function") {
            NS.markAnalysisComplete(reason || "brand-identity-hydrated");
          }
        } catch { /* ignore */ }
      });
    } catch {
      state._brandElectionHydrationResumeScheduled = false;
    }
  }

  /**
   * Re-open only the current URL's bounded final election when its primary
   * identity fingerprint changes.  Visibility and popup nudges also release a
   * retry whose timer was frozen while Edge kept the tab in the background.
   */
  NS.nudgeBrandElectionAfterHydration = function (reason) {
    const state = NS.state;
    if (!state || state._brandElectionHydrationNudgeBusy) return false;
    try {
      const urlKey = String(location.href || "");
      const fingerprint = NS.captureBrandElectionIdentityFingerprint();
      const previousUrl = String(state._brandElectionIdentityFingerprintUrl || "");
      const previous = String(state._brandElectionIdentityFingerprint || "");
      const explicitWake = /(?:visibility|pageshow|focus|popup)/i.test(String(reason || ""));
      if (previousUrl !== urlKey || !previous) {
        state._brandElectionIdentityFingerprintUrl = urlKey;
        state._brandElectionIdentityFingerprint = fingerprint;
        state._brandElectionIdentityFingerprintAt = Date.now();
        return false;
      }
      const changed = fingerprint !== previous;
      if (!changed) {
        if (explicitWake && (state._brandElectionRetryPending
          || state._brandElectionAwaitingDom
          || (state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented))) {
          state._brandElectionHydrationNudgeBusy = true;
          clearBrandElectionRetryTimers(state);
          state._brandElectionAwaitingDom = false;
          state._brandElectionSettledUrl = "";
          scheduleBrandElectionResume(`brand-election-${String(reason || "wake")}`);
          return true;
        }
        return false;
      }

      state._brandElectionHydrationNudgeBusy = true;
      const hardThreat = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      const hadFinalSoftDecision = !hardThreat && state._brandSpoofFinalPresented === true;
      if (hadFinalSoftDecision && typeof NS.clearBrandSpoofFalsePositive === "function") {
        try {
          NS.clearBrandSpoofFalsePositive("brand-primary-identity-changed", { preserveNoIcp: true });
        } catch { /* ignore */ }
      }
      invalidateBrandSpoofDecision(state, "brand-primary-identity-changed");
      state._brandPinyinRequestSequence = Number(state._brandPinyinRequestSequence || 0) + 1;
      state._brandElectionIdentityFingerprint = fingerprint;
      state._brandElectionIdentityFingerprintUrl = urlKey;
      state._brandElectionIdentityFingerprintAt = Date.now();
      state._brandElectionIdentityRevision = Number(state._brandElectionIdentityRevision || 0) + 1;
      state._brandElectionSettledUrl = "";
      state._brandElectionSettledAt = 0;
      state._brandElectionFinalAttempts = 0;
      state._brandElectionAwaitingDom = false;
      clearBrandElectionRetryTimers(state);
      // Keep analysis pending until the current URL's real identity sources
      // can run the newly hydrated brand snapshot through final election.
      state._brandElectionRetryPending = true;
      try {
        if (typeof NS.rotateAnalysisTransaction === "function") {
          NS.rotateAnalysisTransaction(urlKey, "brand-primary-identity-changed");
        }
      } catch { /* ignore */ }
      if (NS.caches) {
        NS.caches._primaryKw = null;
        NS.caches._primaryKwAt = 0;
        NS.caches._primaryKwUrl = "";
        NS.caches._mutualLatinBrandIdentity = null;
      }
      // Hydration invalidates the display identity even when a real hard
      // download threat remains armed.  Keep the protection flags, but remove
      // the stale named brand and its toast until the new fingerprint wins a
      // final election.
      try {
        if (state._brandSpoofFinalSnapshot || state._lastGuardNoticeKind === "brand-spoof") {
          if (typeof NS.invalidateBrandSpoofNoticeSnapshot === "function") {
            NS.invalidateBrandSpoofNoticeSnapshot(state._brandSpoofFinalSnapshot, "brand-primary-identity-changed");
          } else if (typeof NS.dismissPageToast === "function") NS.dismissPageToast("brand-spoof");
        }
      } catch { /* ignore */ }
      state._brandSpoofFinalSnapshot = null;
      state._brandSpoofFinalPresented = false;
      state._brandSpoofFinalizeScheduled = false;
      state._spoofBrandChineseLocked = false;
      state._spoofPinyinUpgradeDone = false;
      state._brandSpoofLatinOnly = false;
      state._brandSpoofNoticeSent = false;
      state._brandSpoofNoticeKey = "";
      state._lastGuardNoticeKey = "";
      state._lastGuardNoticeVersion = "";
      state.spoofBrand = "";
      if (!hardThreat) {
        state._brandSpoofPresentationDeferred = false;
        state._pendingSoftBrandSpoof = false;
        state._analysisDone = false;
        state._stickyComplete = false;
        state._stickyCompleteHost = "";
      }
      scheduleBrandElectionResume("brand-primary-identity-changed");
      return true;
    } catch { return false; }
    finally { if (state) state._brandElectionHydrationNudgeBusy = false; }
  };

  NS.ensureBrandElectionHydrationWatch = function () {
    try {
      if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) return false;
      if (typeof NS.isSearchUrlShapeOnly === "function" && NS.isSearchUrlShapeOnly()) return false;
      if (typeof NS.isPrivateOrLocalNetworkHost === "function"
        && NS.isPrivateOrLocalNetworkHost()) return false;
      const state = NS.state;
      const cache = NS.caches || {};
      const urlKey = String(location.href || "");
      const previous = cache._brandElectionHydrationWatch;
      if (previous && previous.url === urlKey && previous.active) return true;
      try { previous && previous.stop && previous.stop(); } catch { /* ignore */ }
      state._brandElectionIdentityFingerprintUrl = urlKey;
      state._brandElectionIdentityFingerprint = NS.captureBrandElectionIdentityFingerprint();
      state._brandElectionIdentityFingerprintAt = Date.now();
      let active = true;
      let debounce = null;
      let deadlineTimer = null;
      const observer = typeof MutationObserver === "function"
        ? new MutationObserver((mutations) => {
          if (!active || !mutationTouchesBrandIdentity(mutations)) return;
          if (debounce) return;
          debounce = setTimeout(() => {
            debounce = null;
            if (!active || String(location.href || "") !== urlKey) return;
            NS.nudgeBrandElectionAfterHydration("dom-hydration");
          }, 80);
        }) : null;
      const stop = () => {
        if (!active) return;
        active = false;
        try { observer && observer.disconnect(); } catch { /* ignore */ }
        try { if (debounce) clearTimeout(debounce); } catch { /* ignore */ }
        try { if (deadlineTimer) clearTimeout(deadlineTimer); } catch { /* ignore */ }
        if (cache._brandElectionHydrationWatch === watch) cache._brandElectionHydrationWatch = null;
      };
      const watch = { active: true, url: urlKey, stop };
      cache._brandElectionHydrationWatch = watch;
      try {
        observer && observer.observe(document.documentElement || document, {
          subtree: true,
          childList: true,
          characterData: true,
          attributes: true,
          attributeFilter: ["content", "alt", "title", "href"],
          attributeOldValue: true
        });
      } catch { /* ignore */ }
      deadlineTimer = setTimeout(stop, 15000);
      return true;
    } catch { return false; }
  };

  /**
   * 页面独立拉丁身份与“干净注册域左标”完全互证。
   *
   * 这里只接受 exact：DingTalk ⇄ dingtalk。ding ⇄ dingtalk 的 affix、
   * ding-talk 的 hyphen、v-dingtalk/dingtalk-pc 的 padded 以及 typo 都不能
   * 取得该证据。展示名仍来自页面，域名不会自行制造品牌或白名单。
   */
  NS.getCleanApexMutualLatinExactEvidence = function (hostOpt) {
    try {
      const host = normalizeBrandDecisionHost(hostOpt);
      if (!host) return null;
      const apex = (typeof NS.getRegistrableDomain === "function"
        ? NS.getRegistrableDomain(host) : host) || host;
      const apexRaw = (String(apex).split(".")[0] || "").toLowerCase();
      const apexFlat = apexRaw.replace(/[^a-z0-9]/g, "");
      if (!apexFlat || apexFlat.length < 3 || apexFlat.length > 24) return null;
      if (!/^[a-z][a-z0-9]*$/i.test(apexRaw) || /[-_]/.test(apexRaw)) return null;

      // 结构层先拒绝营销夹带；exact 页面词不能把 padded/typo 主机洗白。
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(apexRaw)) return null;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity(host)) return null;
      try {
        const inferred = typeof NS.inferMarketingPaddedBrandCore === "function"
          ? String(NS.inferMarketingPaddedBrandCore(apexRaw) || "").toLowerCase().replace(/[^a-z0-9]/g, "")
          : "";
        if (inferred && inferred !== apexFlat) return null;
      } catch { /* ignore */ }

      // 每次从当前 DOM 身份槽重建，不能沿用 SPA 上一个页面的 mutual cache。
      if (NS.caches) NS.caches._mutualLatinBrandIdentity = null;
      if (typeof NS.pickHostAlignedLatinBrandFromPage !== "function") return null;
      const displayBrand = String(NS.pickHostAlignedLatinBrandFromPage(host) || "").trim();
      const mutual = NS.caches && NS.caches._mutualLatinBrandIdentity;
      if (!displayBrand || !mutual) return null;
      const mutualHost = normalizeBrandDecisionHost(mutual.host || host);
      const pageForm = String(mutual.pageForm || mutual.flat || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const hostForm = String(mutual.hostForm || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (mutualHost !== host || String(mutual.relation || "") !== "exact") return null;
      if (pageForm !== apexFlat || hostForm !== apexFlat) return null;

      // 若其它已完成关系证据明确认定 squat，exact 拉丁词不得覆盖它。
      try {
        const rel = typeof NS.evaluateDomainKeywordRelevance === "function"
          ? NS.evaluateDomainKeywordRelevance(host) : null;
        if (rel && (rel.squat || /^(?:padded|hyphen|typo|partial)$/i.test(String(rel.hostMatch || "")))) {
          return null;
        }
      } catch { /* ignore */ }
      return { host, apex: String(apex), apexLabel: apexRaw, pageForm, hostForm, displayBrand, relation: "exact" };
    } catch {
      return null;
    }
  };

  /** 当前 DOM 晚到 exact 身份后，撤销先前的纯软品牌误锁。 */
  NS.reconcileSoftBrandSpoofWithMutualLatinExact = function (hostOpt, reasonOpt) {
    try {
      const state = NS.state;
      if (!state) return false;
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return false;
      const evidence = NS.getCleanApexMutualLatinExactEvidence(hostOpt);
      if (!evidence) return false;
      const active = hasActiveSoftBrandDecision(state);
      invalidateBrandSpoofDecision(state, reasonOpt || "mutual-latin-clean-apex-exact");
      state._brandSpoofFinalizeScheduled = false;
      state._brandSpoofFinalPresented = false;
      state._brandSpoofFinalSnapshot = null;
      state._brandElectionRetryPending = false;
      state._pendingSoftBrandSpoof = false;
      state._brandSpoofPresentationDeferred = false;
      if (active) {
        if (typeof NS.clearBrandSpoofFalsePositive === "function") {
          NS.clearBrandSpoofFalsePositive(reasonOpt || "mutual-latin-clean-apex-exact", { preserveNoIcp: true });
        } else {
          state._brandSpoofPortalDetected = false;
          state.spoofBrand = "";
        }
      }
      try {
        NS.silverfoxLog && NS.silverfoxLog(
          "brand-spoof", active ? "lift-mutual-latin-exact" : "skip-mutual-latin-exact",
          evidence.displayBrand, evidence.apex
        );
      } catch { /* ignore */ }
      return true;
    } catch {
      return false;
    }
  };

  /**
   * 同步定稿展示名。标题中文 > pinyin 对齐 > 其它。
   * 有「钉钉应用中心」标题时必出「钉钉」，绝不先返回 Dingding。
   */
  NS.resolveSpoofDisplayBrandNow = function (hintOpt) {
    try {
      const locked = typeof NS.getLockedSpoofDisplayBrand === "function"
        ? NS.getLockedSpoofDisplayBrand() : "";
      if (locked) return locked;

      // 页面身份槽与域名段已经共同声明同一拉丁核时直接定稿；
      // 例如 WPS @ wps-officce-wps，无需进入中文拼音升级链。
      try {
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          const aligned = String(NS.pickHostAlignedLatinBrandFromPage() || "").trim();
          if (aligned && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
            && NS.isForbiddenSpoofDisplayBrand(aligned))) return aligned;
        }
      } catch { /* ignore */ }

      // 1) 标题硬抽（钉钉应用中心 → 钉钉）——同步热路径只做这个
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          const tb = NS.extractChineseBrandFromPageTitle();
          if (tb && /[\u4e00-\u9fff]{2,}/.test(tb)) {
            NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "title-brand", tb, document.title);
            return tb;
          }
        }
      } catch { /* ignore */ }

      let brand = String(hintOpt || "").trim();
      const pickHint = (brand && NS.isPureLatinSpoofBrand(brand)) ? "" : brand;
      try {
        if (typeof NS.pickBestSpoofDisplayBrand === "function") {
          const picked = String(NS.pickBestSpoofDisplayBrand(pickHint) || "").trim();
          if (picked && /[\u4e00-\u9fff]{2,}/.test(picked)) return picked;
          if (picked && !NS.isPureLatinSpoofBrand(picked)) brand = picked;
          else if (picked) brand = picked;
        }
      } catch { /* ignore */ }
      // 同步路径禁止 pinyin 升格（upgrade 会扫库卡死）；留给 async finalize
      return brand;
    } catch {
      return String(hintOpt || "").trim();
    }
  };

  /**
   * 拉丁拼音核 → 页内中文（Dingding→钉钉）。**只改 state，默认不弹 toast**。
   * 展示统一走 commitBrandSpoofPresentation（先定稿再弹一次）。
   */
  NS.upgradeSpoofBrandLatinToChinese = function (opts) {
    try {
      const state = NS.state;
      if (!state) return "";
      void opts;
      try {
        const locked = typeof NS.getLockedSpoofDisplayBrand === "function"
          ? NS.getLockedSpoofDisplayBrand() : "";
        if (locked) return locked;
      } catch { /* ignore */ }
      let current = String(state.spoofBrand || "").trim();
      // 页内拉丁品牌已经与主机段一致时直接纠正旧值并返回，完全跳过 pinyin-pro。
      // 放在弱词清空之前，使 setSpoofDisplayBrand 能同步改写历史「中文」详情。
      try {
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          const aligned = String(NS.pickHostAlignedLatinBrandFromPage() || "").trim();
          if (aligned && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
            && NS.isForbiddenSpoofDisplayBrand(aligned))) {
            if (typeof NS.setSpoofDisplayBrand === "function") {
              NS.setSpoofDisplayBrand(aligned, { forceUnlock: true });
            } else {
              state.spoofBrand = aligned;
              state._spoofBrandChineseLocked = false;
            }
            return String(state.spoofBrand || aligned);
          }
        }
      } catch { /* ignore */ }

      // 清除旧报告/早期抽词遗留的语言壳，不能把「中文」锁成品牌。
      try {
        if (current && typeof NS.isForbiddenSpoofDisplayBrand === "function"
          && NS.isForbiddenSpoofDisplayBrand(current)) {
          if (typeof NS.setSpoofDisplayBrand === "function") {
            NS.setSpoofDisplayBrand("", { allowClear: true, forceUnlock: true });
          } else {
            state.spoofBrand = "";
            state._spoofBrandChineseLocked = false;
          }
          current = "";
        }
      } catch { /* ignore */ }

      if (/[一-鿿]{2,}/.test(current)) {
        state._spoofBrandChineseLocked = true;
        return current;
      }

      let core = "";
      try {
        if (typeof NS.resolveHostBrandCore === "function") {
          core = String(NS.resolveHostBrandCore() || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        }
        if (!core && typeof NS.inferMarketingPaddedBrandCore === "function") {
          const lab = (location.hostname || "").replace(/^www\./i, "").split(".")[0] || "";
          core = String(NS.inferMarketingPaddedBrandCore(lab) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        }
      } catch { /* ignore */ }
      const curLat = current.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (curLat.length >= 4 && /^[a-z][a-z0-9]{3,24}$/i.test(current)) {
        if (!core || core.length < 4 || curLat === core || curLat.includes(core) || core.includes(curLat)) {
          core = core && core.length >= 4 ? core : curLat;
        }
      }
      if ((!core || core.length < 4) && curLat.length >= 4) core = curLat;
      if (!core || core.length < 4) return current;

      if (typeof NS.clearChinesePinyinMatchCache === "function") {
        NS.clearChinesePinyinMatchCache();
      }
      let cn = "";
      try {
        if (typeof NS.findChineseBrandByPinyinInText === "function") {
          cn = String(NS.findChineseBrandByPinyinInText(core) || "").trim();
        }
      } catch { /* ignore */ }
      if ((!cn || !/^[一-鿿]{2,8}$/.test(cn))
        && typeof NS.pickChineseBrandMatchingLatinCore === "function") {
        cn = String(NS.pickChineseBrandMatchingLatinCore(core) || "").trim();
      }
      if (!cn || !/^[一-鿿]{2,8}$/.test(cn)) {
        try {
          const blob = [
            document.title || "",
            document.querySelector("h1")?.textContent || "",
            document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "",
            document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "",
            document.querySelector(".logo, [class*='logo']")?.textContent || "",
            ((document.body && (document.body.innerText || document.body.textContent)) || "").slice(0, 1000)
          ].join(" ").slice(0, 1400);
          const runs = blob.match(/[一-鿿]{2,8}/g) || [];
          const pyOf = (s) => {
            try {
              if (typeof NS.chineseToPinyinFlat === "function") return NS.chineseToPinyinFlat(s) || "";
              if (typeof NS.brandPinyin === "function") return NS.brandPinyin(s) || "";
            } catch { /* ignore */ }
            return "";
          };
          for (let ri = 0; ri < Math.min(runs.length, 40) && !cn; ri++) {
            const run = runs[ri];
            for (let i = 0; i + 2 <= run.length; i++) {
              const pair = run.slice(i, i + 2);
              if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(pair)) continue;
              if (pyOf(pair) === core) {
                cn = pair;
                break;
              }
            }
          }
        } catch { /* ignore */ }
      }
      if (!cn || !/^[一-鿿]{2,8}$/.test(cn)) return current;
      if (typeof NS.setSpoofDisplayBrand === "function") {
        NS.setSpoofDisplayBrand(cn, { lockChinese: true, forceChinese: true });
      } else {
        state.spoofBrand = cn;
        state._spoofBrandChineseLocked = true;
      }
      return String(state.spoofBrand || cn);
    } catch {
      return String((NS.state && NS.state.spoofBrand) || "");
    }
  };

  /**
   * 品牌仿冒属于身份结论，不能早于官网身份核验向用户展示。
   * WHOIS/ICP 与 SSL 并行；ICP 先返回不得单独定稿——否则会先 toast 仿冒，
   * 再被成熟门/OV 撤销，官网闪一秒「已识别仿冒「钉钉」」。
   */
  NS.isBrandSpoofIdentityVerificationSettled = function () {
    try {
      const state = NS.state || {};
      const urlKey = String(location.href || "");
      // A bounded identity timeout is terminal for analysis, but it is not
      // positive evidence.  canPresentSoftBrandSpoofNotice() keeps soft UI and
      // the permanent brand guard suppressed for this exact URL.
      if (identityVerificationUnavailableForCurrentUrl(state)) return true;
      const sslIdentityStartedForCurrentUrl = /^https:/i.test(String(location.protocol || ""))
        && String(state._sslIdentityUrl || "") === urlKey
        && Number(state._sslIdentityStartedAt || 0) > 0;
      // 当前 HTTPS 页 SSL 身份查询已启动 → 必须等其有界回调收口
      if (sslIdentityStartedForCurrentUrl && state._sslIdentitySettled !== true) return false;
      // 强信任官网已确认 → 可定论（调用方应跳过 toast）
      if (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()) return true;
      // ICP 查询未结束 → 绝不定稿
      if (state._icpQuerySettled !== true) return false;
      // 情报管道（WHOIS + 成熟门）未收口 → 继续等（禁止 ICP 先回就弹）
      try {
        const c = NS.caches || {};
        if (c.intelDoneForUrl === urlKey) return true;
      } catch { /* ignore */ }
      // 情报管道内、成熟门已判「非信任」后的显式放行（ensureNotice 前写入）
      if (state._softBrandIdentityReady === true
        && String(state._softBrandIdentityUrl || "") === urlKey) return true;
      return false;
    } catch {
      return !!(NS.state && NS.state._icpQuerySettled === true
        && NS.caches && NS.caches.intelDoneForUrl === String(location.href || ""));
    }
  };

  /**
   * 软仿冒是否允许向用户弹 toast / 系统通知。
   * 未确认官网（有效 ICP / 强信任 / 情报未完）前一律 false。
   */
  NS.canPresentSoftBrandSpoofNotice = function () {
    try {
      const state = NS.state || {};
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) {
        // 真硬套件不走软仿冒门禁
        return true;
      }
      if (identityVerificationUnavailableForCurrentUrl(state)) return false;
      if (!(typeof NS.isBrandSpoofIdentityVerificationSettled === "function"
        && NS.isBrandSpoofIdentityVerificationSettled())) return false;
      if (typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity()) return false;
      // 有效备案：按项目 ICP 门控，软仿冒不提示（避免先弹再被 valid-icp 清掉）
      if (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()) return false;
      return true;
    } catch {
      return false;
    }
  };

  /**
   * 页面是否还欠一次“DOM 身份字段 + 已落定 ICP/WHOIS”后的品牌终选。
   * 首屏早扫只能给中间态，不能因为 sticky complete 把稍后挂载的品牌跳过。
   */
  NS.pageNeedsFinalBrandElection = function () {
    try {
      const state = NS.state || {};
      const urlKey = String(location.href || "");
      if (hasActiveSoftBrandDecision(state)
        && NS.reconcileSoftBrandSpoofWithMutualLatinExact(
          location.hostname, "analysis-complete-mutual-latin-exact"
        )) return false;
      if (state._brandElectionSettledUrl === urlKey) return false;
      if (state._pendingSoftBrandSpoof || state._brandSpoofPresentationDeferred
        || state._brandElectionRetryPending) return true;
      const strong = typeof NS.collectStrongChineseBrandCandidates === "function"
        ? NS.collectStrongChineseBrandCandidates()
        : [];
      if (!strong.length) return false;
      const identityText = [
        document.title || "",
        document.querySelector("h1")?.textContent || "",
        document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "",
        document.querySelector('meta[name="description"]')?.getAttribute("content") || ""
      ].join(" ").slice(0, 1200);
      let downloadIntent = /官网|官方|下载|安装|客户端|电脑版|手机版|软件|应用中心/i.test(identityText);
      if (!downloadIntent && typeof NS.pageHasProactiveDownloadButtonTargets === "function") {
        downloadIntent = !!NS.pageHasProactiveDownloadButtonTargets();
      }
      const hostWarning = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity();
      return !!(downloadIntent || hostWarning);
    } catch {
      return false;
    }
  };

  /** 身份情报落定后统一补跑一次品牌终选，并记录本 URL 已完成。 */
  NS.runFinalBrandElectionAfterIdentity = function (reason) {
    const state = NS.state;
    if (!state) return false;
    const urlKey = String(location.href || "");
    const settleVerifiedBenignElection = (settleReason, resumeAnalysis) => {
      try {
        if (typeof NS.cancelPendingSoftBrandDecision === "function") {
          NS.cancelPendingSoftBrandDecision(settleReason || "brand-election-benign-settled");
        } else {
          state._pendingSoftBrandSpoof = false;
          state._brandSpoofPresentationDeferred = false;
          state._brandSpoofFinalizeScheduled = false;
          state._brandSpoofFinalPresented = false;
          state._brandElectionAwaitingDom = false;
          state._brandElectionRetryPending = false;
          state._analysisCompletionDeferredForBrand = false;
          try {
            if (state._brandElectionRetryTimer) clearTimeout(state._brandElectionRetryTimer);
          } catch { /* ignore */ }
          state._brandElectionRetryTimer = null;
        }
        state._brandElectionSettledUrl = urlKey;
        state._brandElectionSettledAt = Date.now();
        if (resumeAnalysis && typeof NS.markAnalysisComplete === "function") {
          NS.markAnalysisComplete(settleReason || "brand-election-benign-settled");
        }
      } catch { /* ignore */ }
    };
    // settled 标志可能来自 SPA 早期 DOM；晚到的页面拉丁身份必须先有机会
    // 撤销旧软锁，不能被上一轮 settled/armed 状态短路。
    if (NS.reconcileSoftBrandSpoofWithMutualLatinExact(
      location.hostname, "final-election-mutual-latin-exact"
    )) {
      settleVerifiedBenignElection("final-election-mutual-latin-exact", false);
      return false;
    }
    const realHardThreat = typeof NS.hasRealHardKitThreat === "function"
      && NS.hasRealHardKitThreat();
    if (!realHardThreat && identityVerificationUnavailableForCurrentUrl(state)) {
      settleVerifiedBenignElection("brand-election-identity-unavailable", false);
      return false;
    }
    if (state._brandElectionSettledUrl === urlKey) return !!state._brandSpoofPortalDetected;
    if (!(typeof NS.isBrandSpoofIdentityVerificationSettled === "function"
      && NS.isBrandSpoofIdentityVerificationSettled())) return false;
    if (document.readyState === "loading") {
      state._brandElectionAwaitingDom = true;
      if (!state._brandElectionDomListenerInstalled) {
        state._brandElectionDomListenerInstalled = true;
        document.addEventListener("DOMContentLoaded", () => {
          state._brandElectionDomListenerInstalled = false;
          state._brandElectionAwaitingDom = false;
          try {
            if (typeof NS.markAnalysisComplete === "function") {
              NS.markAnalysisComplete("brand-dom-ready");
            }
          } catch { /* ignore */ }
        }, { once: true });
      }
      return false;
    }
    try { NS.ensureBrandElectionHydrationWatch(); } catch { /* ignore */ }
    // Do not elect against a title/H1/meta snapshot that changed in this same
    // turn.  The short stability gate is event-driven on resume and bounded by
    // one timer; it does not extend the identity network deadline.
    const fingerprintAt = String(state._brandElectionIdentityFingerprintUrl || "") === urlKey
      ? Number(state._brandElectionIdentityFingerprintAt || 0) : 0;
    const stableAge = fingerprintAt ? Date.now() - fingerprintAt : 0;
    if (fingerprintAt && stableAge >= 0 && stableAge < 350) {
      state._brandElectionRetryPending = true;
      if (!state._brandElectionHydrationStableTimer) {
        const stableGeneration = Number(state._brandSpoofDecisionGeneration || 0);
        state._brandElectionHydrationStableTimer = setTimeout(() => {
          state._brandElectionHydrationStableTimer = null;
          try {
            if (String(location.href || "") !== urlKey) return;
            if (Number(state._brandSpoofDecisionGeneration || 0) !== stableGeneration) {
              state._brandElectionRetryPending = false;
              scheduleBrandElectionResume("brand-primary-identity-stability-superseded");
              return;
            }
            state._brandElectionRetryPending = false;
            if (typeof NS.markAnalysisComplete === "function") {
              NS.markAnalysisComplete("brand-primary-identity-stable");
            }
          } catch { state._brandElectionRetryPending = false; }
        }, Math.max(25, 350 - stableAge));
      }
      return false;
    }
    try {
      if (NS.caches) {
        NS.caches._primaryKw = null;
        NS.caches._primaryKwAt = 0;
        NS.caches._primaryKwUrl = "";
      }
      state._brandElectionAwaitingDom = false;
      const trustedIdentity = typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity();
      if (trustedIdentity) {
        settleVerifiedBenignElection("final-election-trusted-identity", false);
        return false;
      }
      let hit = false;
      if (typeof NS.detectBrandSpoofDownloadPortal === "function") {
        hit = !!NS.detectBrandSpoofDownloadPortal();
      }
      const attempt = Number(state._brandElectionFinalAttempts || 0) + 1;
      state._brandElectionFinalAttempts = attempt;
      const brandFlowStarted = !!(hit || state._brandSpoofPortalDetected
        || (state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented));
      if (!brandFlowStarted && attempt < 3) {
        // SPA 的 title/H1/meta/下载 CTA 可能在 load 后才挂载；一次 miss 不能永久
        // settled。做有界 0/300/900ms 稳定窗口，避免首访漏、刷新才命中。
        state._brandElectionRetryPending = true;
        if (!state._brandElectionRetryTimer) {
          const delay = attempt === 1 ? 300 : 900;
          const retryGeneration = Number(state._brandSpoofDecisionGeneration || 0);
          state._brandElectionRetryTimer = setTimeout(() => {
            state._brandElectionRetryTimer = null;
            try {
              if (String(location.href || "") !== urlKey) return;
              if (Number(state._brandSpoofDecisionGeneration || 0) !== retryGeneration) {
                // A newer brand transaction superseded this timer. Let the
                // current generation re-evaluate completion instead of
                // leaving this timer's retry latch permanently set.
                if (typeof NS.markAnalysisComplete === "function") {
                  NS.markAnalysisComplete("brand-election-retry-superseded");
                }
                return;
              }
              if (NS.reconcileSoftBrandSpoofWithMutualLatinExact(
                location.hostname, "final-election-retry-mutual-latin-exact"
              )) {
                settleVerifiedBenignElection("brand-election-retry-mutual-latin-exact", true);
                return;
              }
              if (typeof NS.pageHasStrongTrustedIdentity === "function"
                && NS.pageHasStrongTrustedIdentity()) {
                settleVerifiedBenignElection("brand-election-retry-trusted-identity", true);
                return;
              }
              if (typeof NS.markAnalysisComplete === "function") {
                NS.markAnalysisComplete("brand-election-stable-retry");
              }
            } catch {
              // Preserve any real threat/finalizer state, but release this
              // bounded retry's own latch so a helper failure cannot strand
              // the report at analysisComplete:false.
              state._brandElectionRetryPending = false;
              state._brandElectionSettledUrl = urlKey;
              state._brandElectionSettledAt = Date.now();
              if (!(state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented)) {
                state._pendingSoftBrandSpoof = false;
                state._brandSpoofPresentationDeferred = false;
              }
              if (typeof NS.markAnalysisComplete === "function") {
                NS.markAnalysisComplete("brand-election-retry-error");
              }
            }
          }, delay);
        }
        return false;
      }
      state._brandElectionRetryPending = false;
      state._brandElectionSettledUrl = urlKey;
      state._brandElectionSettledAt = Date.now();
      if (!brandFlowStarted) {
        state._pendingSoftBrandSpoof = false;
        state._brandSpoofPresentationDeferred = false;
      }
      if ((hit || state._brandSpoofPortalDetected) && typeof NS.ensureBrandSpoofNotice === "function") {
        NS.ensureBrandSpoofNotice(false);
      }
      NS.silverfoxLog && NS.silverfoxLog("brand-election", "final-pass", reason || "", hit ? "hit" : "miss");
      return hit;
    } catch {
      state._brandElectionSettledUrl = urlKey;
      state._brandElectionSettledAt = Date.now();
      return false;
    }
  };

  /**
   * ★ 仿冒门户：先定展示名，再弹一次 toast。
   * - 中文已就绪 → 立即展示
   * - 仅拉丁核（Dingding）→ 静默 arm 下载拦截，等 pinyin 定稿后再弹「钉钉」
   * - 绝不先弹 Dingding 再改钉钉
   *
   * @param {{ brand: string, matchHint?: string, reason?: string, lockHard?: boolean,
   *           signalDetail?: string, host?: string, noticeMsg?: string }} opts
   */
  NS.commitBrandSpoofPresentation = function (opts) {
    try {
      const state = NS.state;
      if (!state) return "";
      const o = opts || {};
      const host = String(o.host || location.hostname || "").toLowerCase();
      const matchHint = String(o.matchHint || "域名与品牌不匹配");
      const lockHard = o.lockHard !== false;
      const decisionUrl = String(location.href || "");
      const decisionGeneration = invalidateBrandSpoofDecision(state, "brand-presentation-begin");

      const decisionIsCurrent = () => {
        try {
          if (Number(state._brandSpoofDecisionGeneration || 0) !== decisionGeneration) return false;
          if (String(location.href || "") !== decisionUrl
            || String(state._brandSpoofDecisionUrl || "") !== decisionUrl) return false;
          // 页面身份字段可能在 SPA hydrate 后才出现。每个异步边界都以最新
          // clean-apex exact 证据复核，旧候选不得在其后重新 arm。
          if (NS.reconcileSoftBrandSpoofWithMutualLatinExact(host, "async-mutual-latin-clean-apex-exact")) {
            return false;
          }
          const latestTrusted = typeof NS.pageHasStrongTrustedIdentity === "function"
            && NS.pageHasStrongTrustedIdentity();
          if (latestTrusted) {
            invalidateBrandSpoofDecision(state, "async-trusted-identity");
            state._brandSpoofFinalizeScheduled = false;
            state._brandSpoofPresentationDeferred = false;
            state._pendingSoftBrandSpoof = false;
            if (hasActiveSoftBrandDecision(state)
              && typeof NS.clearBrandSpoofFalsePositive === "function") {
              NS.clearBrandSpoofFalsePositive("async-trusted-identity");
            }
            return false;
          }
          return true;
        } catch {
          return false;
        }
      };

      // 英文品牌不走 pinyin：当前 DOM 若已给出与干净 apex 完全一致的
      // 独立拉丁身份，直接否定软仿冒候选。
      if (NS.reconcileSoftBrandSpoofWithMutualLatinExact(host, "mutual-latin-clean-apex-exact")) {
        return "";
      }

      // 官网身份尚未核验完成：只保留“需要复检”标志，不写品牌、不加风险信号、
      // 不安装品牌下载锁，更不能弹出稍后又被 ICP/OV 撤销的仿冒提示。
      const trustedIdentity = typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity();
      if (trustedIdentity) {
        invalidateBrandSpoofDecision(state, "brand-presentation-trusted-identity");
        state._brandSpoofPresentationDeferred = false;
        state._pendingSoftBrandSpoof = false;
        if (state._brandSpoofPortalDetected || state.spoofBrand) {
          try {
            if (typeof NS.clearBrandSpoofFalsePositive === "function") {
              NS.clearBrandSpoofFalsePositive("brand-presentation-trusted-identity");
            }
          } catch { /* ignore */ }
        }
        return "";
      }
      // 有效 ICP + 无真硬套件：官网侧证据已够，软仿冒永不 toast（确认官网前不提示）
      try {
        const hardKit = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
        if (!hardKit && typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()) {
          state._brandSpoofPresentationDeferred = false;
          state._pendingSoftBrandSpoof = false;
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "suppress-toast-valid-icp", host);
          // 有备案时清软误报，避免 popup 闪「仿冒钉钉」
          if (state._brandSpoofPortalDetected || state.spoofBrand
            || state._brandSpoofNoticeSent) {
            try {
              if (typeof NS.clearBrandSpoofFalsePositive === "function") {
                NS.clearBrandSpoofFalsePositive("valid-icp-pre-present");
              }
            } catch { /* ignore */ }
          }
          return "";
        }
      } catch { /* ignore */ }
      if (!(typeof NS.isBrandSpoofIdentityVerificationSettled === "function"
        && NS.isBrandSpoofIdentityVerificationSettled())) {
        state._brandSpoofPresentationDeferred = true;
        state._pendingSoftBrandSpoof = true;
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "presentation-deferred-until-identity", host);
        return "";
      }
      // 双重门：情报/ICP 已结但仍可能是官网证据窗口 → 禁止 toast
      if (typeof NS.canPresentSoftBrandSpoofNotice === "function"
        && !NS.canPresentSoftBrandSpoofNotice()) {
        state._brandSpoofPresentationDeferred = true;
        state._pendingSoftBrandSpoof = true;
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "presentation-deferred-can-present-false", host);
        return "";
      }
      try { NS.ensureBrandElectionHydrationWatch(); } catch { /* ignore */ }
      const identityFingerprintAt = String(state._brandElectionIdentityFingerprintUrl || "") === decisionUrl
        ? Number(state._brandElectionIdentityFingerprintAt || 0) : 0;
      const identityStableAge = identityFingerprintAt ? Date.now() - identityFingerprintAt : 0;
      if (identityFingerprintAt
        && identityStableAge >= 0 && identityStableAge < 350) {
        state._brandSpoofPresentationDeferred = true;
        state._pendingSoftBrandSpoof = true;
        state._brandElectionRetryPending = true;
        if (!state._brandElectionHydrationStableTimer) {
          const commitGeneration = decisionGeneration;
          state._brandElectionHydrationStableTimer = setTimeout(() => {
            state._brandElectionHydrationStableTimer = null;
            try {
              if (String(location.href || "") !== decisionUrl) return;
              if (Number(state._brandSpoofDecisionGeneration || 0) !== commitGeneration) {
                state._brandElectionRetryPending = false;
                scheduleBrandElectionResume("brand-presentation-stability-superseded");
                return;
              }
              state._brandElectionRetryPending = false;
              if (typeof NS.markAnalysisComplete === "function") {
                NS.markAnalysisComplete("brand-presentation-identity-stable");
              }
            } catch { state._brandElectionRetryPending = false; }
          }, Math.max(25, 350 - identityStableAge));
        }
        return "";
      }
      state._brandSpoofPresentationDeferred = false;
      if (!decisionIsCurrent()) return "";
      // 新 generation 已使旧 timer/SW 回调失效；对应 scheduled 标志也必须
      // 一并释放，否则新一轮会误以为仍有有效定稿任务而不再调度。
      if (state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented) {
        state._brandSpoofFinalizeScheduled = false;
      }

      // 旧扫描阶段若曾把「拉丁品牌 + 中文功能描述」定稿，先通过统一状态入口
      // 迁移为真正的页面品牌；迁移会撤销旧 final/notice，允许补发一次正确提示。
      try {
        const rawFinalBrand = String(state.spoofBrand || "").trim();
        if (rawFinalBrand && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          const canonicalFinalBrand = String(NS.canonicalizeBrandDisplayCandidate(rawFinalBrand) || "").trim();
          if (canonicalFinalBrand && canonicalFinalBrand !== rawFinalBrand
            && typeof NS.setSpoofDisplayBrand === "function") {
            NS.setSpoofDisplayBrand(rawFinalBrand, { forceUnlock: true });
          }
        }
      } catch { /* ignore */ }

      // 已最终展示过通常不再抢 toast；但纯拉丁 Qishui/Huorong 若此时才拿到
      // 强中文身份候选，必须允许一次“只升不降”的 SW pinyin 覆盖。
      if (state._brandSpoofFinalPresented) {
        if (!decisionIsCurrent()) return "";
        let allowLatinToChineseRetry = false;
        try {
          const current = String(state.spoofBrand || "").trim();
          const strongCn = typeof NS.collectStrongChineseBrandCandidates === "function"
            ? NS.collectStrongChineseBrandCandidates()
            : [];
          allowLatinToChineseRetry = !!(
            NS.isPureLatinSpoofBrand(current)
            && strongCn.length > 0
            && !state._spoofPinyinUpgradeDone
            && Number(state._brandSpoofLatinUpgradeAttempts || 0) < 2
          );
        } catch { allowLatinToChineseRetry = false; }
        if (allowLatinToChineseRetry) {
          state._brandSpoofLatinUpgradeAttempts = Number(state._brandSpoofLatinUpgradeAttempts || 0) + 1;
          state._brandSpoofFinalPresented = false;
          state._brandSpoofFinalSnapshot = null;
          state._brandSpoofFinalizeScheduled = false;
          state._brandSpoofNoticeSent = false;
          state._brandSpoofNoticeKey = "";
          state._lastGuardNoticeKey = "";
        } else {
        try {
          if (typeof NS.installDownloadGuard === "function") {
            NS.installDownloadGuard(String(o.reason || "仿冒品牌官网下载站"), {
              notify: false,
              guardKind: "brand-spoof",
              lockHard: true
            });
          }
          NS.disableAllDownloadIntentControls();
        } catch { /* ignore */ }
        return String(state.spoofBrand || "");
        }
      }

      if (!decisionIsCurrent()) return "";
      state._brandSpoofPortalDetected = true;
      state._pendingSoftBrandSpoof = false;

      // 主机剥核拉丁：huorongr → Huorong；供 pinyin 对「火绒」与无中文时的兜底展示
      const hostCoreLatin = () => {
        try {
          let core = "";
          if (typeof NS.resolveHostBrandCore === "function") {
            core = String(NS.resolveHostBrandCore(host) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          }
          if (!core && typeof NS.inferMarketingPaddedBrandCore === "function") {
            const lab = (String(host).replace(/^www\./i, "").split(".")[0] || "").toLowerCase();
            core = String(NS.inferMarketingPaddedBrandCore(lab) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          }
          // 整段 host 标签不是品牌名；只有明确营销结构剥核成功才作拉丁兜底。
          // huorongr/qishuiyyds 由页面候选主导的双向匹配确认，禁止盲删末字。
          const labFlat = (String(host).replace(/^www\./i, "").split(".")[0] || "")
            .toLowerCase().replace(/[^a-z0-9]/g, "");
          if (core && core === labFlat && typeof NS.inferMarketingPaddedBrandCore === "function") {
            const peeled = String(NS.inferMarketingPaddedBrandCore(labFlat) || "").toLowerCase();
            if (peeled && peeled.length >= 4 && peeled !== core) core = peeled;
            else core = "";
          }
          if (!core || core.length < 4) return "";
          if (typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(core, host)
            && core === labFlat) return "";
          if (typeof NS.formatBrandTokenForDisplay === "function") {
            return NS.formatBrandTokenForDisplay(core) || "";
          }
          return core.charAt(0).toUpperCase() + core.slice(1);
        } catch { return ""; }
      };
      const hostCoreRaw = () => {
        try {
          let core = typeof NS.resolveHostBrandCore === "function"
            ? String(NS.resolveHostBrandCore(host) || "").toLowerCase().replace(/[^a-z0-9]/g, "")
            : "";
          if (!core && typeof NS.inferMarketingPaddedBrandCore === "function") {
            const lab = (String(host).replace(/^www\./i, "").split(".")[0] || "").toLowerCase();
            core = String(NS.inferMarketingPaddedBrandCore(lab) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          }
          const labFlat = (String(host).replace(/^www\./i, "").split(".")[0] || "")
            .toLowerCase().replace(/[^a-z0-9]/g, "");
          if (core === labFlat) core = "";
          return core.length >= 4 ? core : "";
        } catch { return ""; }
      };

      // 展示名优先级（无 pinyin 热路径）：
      // 1) 页内拉丁 ↔ 域名段（WPS @ wps-officce-wps）← 用户案例，不必 pinyin
      // 2) 标题中文壳（钉钉应用中心）
      // 3) 选举中文（非弱词）
      // 4) 主机核拉丁 / SW pinyin 异步升格
      const forbid = (t) => typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(t);
      let brand = "";
      let hostAlignedLatin = "";
      try {
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          hostAlignedLatin = String(NS.pickHostAlignedLatinBrandFromPage(host) || "").trim();
          if (forbid(hostAlignedLatin)
            || (typeof NS.isHostShapedCompoundBrandToken === "function"
              && NS.isHostShapedCompoundBrandToken(hostAlignedLatin, host))) {
            hostAlignedLatin = "";
          }
        }
      } catch { hostAlignedLatin = ""; }
      try {
        const locked = typeof NS.getLockedSpoofDisplayBrand === "function"
          ? NS.getLockedSpoofDisplayBrand() : "";
        if (locked && !forbid(locked)
          && typeof NS.spoofDisplayBrandAlignsHost === "function"
          && NS.spoofDisplayBrandAlignsHost(locked, host)) brand = locked;
      } catch { /* ignore */ }
      // 页内中文（钉钉）优先，但须能过互锁；失败则回退页内/剥核拉丁（ToDesk），禁止空品牌
      let titleCn = "";
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          titleCn = String(NS.extractChineseBrandFromPageTitle() || "").trim();
          if (forbid(titleCn)) titleCn = "";
        }
      } catch { titleCn = ""; }
      if (!brand && titleCn
        && typeof NS.spoofDisplayBrandAlignsHost === "function"
        && NS.spoofDisplayBrandAlignsHost(titleCn, host)) {
        brand = titleCn;
      }
      // 主机对齐页内拉丁（ToDesk @ totodesk / WPS）；拒绝 TotoDesk 主机碎片
      if (!brand && hostAlignedLatin) brand = hostAlignedLatin;
      if (!brand || (NS.isPureLatinSpoofBrand(brand) && !hostAlignedLatin)) {
        try {
          if (typeof NS.collectPrimaryBrandKeywords === "function") {
            const pk = (NS.caches && NS.caches._primaryKw)
              || NS.collectPrimaryBrandKeywords();
            if (pk && pk.latin && pk.latin.length && typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
              const latHit2 = String(NS.pickHostAlignedLatinBrandFromPage(host) || "").trim();
              if (latHit2 && !forbid(latHit2)
                && !(typeof NS.isHostShapedCompoundBrandToken === "function"
                  && NS.isHostShapedCompoundBrandToken(latHit2, host))) {
                brand = latHit2;
              }
            }
            if ((!brand || forbid(brand)) && pk && pk.display && /[\u4e00-\u9fff]{2,}/.test(pk.display)
              && !forbid(pk.display)
              && typeof NS.spoofDisplayBrandAlignsHost === "function"
              && NS.spoofDisplayBrandAlignsHost(pk.display, host)) {
              brand = String(pk.display).trim();
            } else if ((!brand || forbid(brand)) && pk && pk.cn && pk.cn.length) {
              for (let i = 0; i < Math.min(pk.cn.length, 6); i++) {
                const cn0 = String(pk.cn[i] || "").trim();
                if (cn0 && /[\u4e00-\u9fff]{2,}/.test(cn0) && !forbid(cn0)
                  && typeof NS.spoofDisplayBrandAlignsHost === "function"
                  && NS.spoofDisplayBrandAlignsHost(cn0, host)) {
                  brand = cn0;
                  break;
                }
              }
            }
            if ((!brand || forbid(brand)) && pk && pk.display && /^[A-Za-z]/.test(pk.display)
              && !forbid(pk.display)) {
              const dLow = pk.display.toLowerCase().replace(/[^a-z0-9]/g, "");
              const hFlat = host.replace(/[^a-z0-9]/g, "");
              if (dLow.length >= 2 && hFlat.includes(dLow)
                && !(typeof NS.isHostShapedCompoundBrandToken === "function"
                  && NS.isHostShapedCompoundBrandToken(pk.display, host))) {
                brand = String(pk.display).trim();
              }
            }
          }
        } catch { /* ignore */ }
      }
      if ((!brand || forbid(brand)) && typeof NS.resolveSpoofDisplayBrandNow === "function") {
        const n = String(NS.resolveSpoofDisplayBrandNow("") || "").trim();
        if (n && !forbid(n)
          && !(typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(n, host))) brand = n;
      }
      if (forbid(brand)) brand = "";
      try {
        if (brand && typeof NS.spoofDisplayBrandAlignsHost === "function"
          && !NS.spoofDisplayBrandAlignsHost(brand, host)) {
          // 互锁失败：回退页内拉丁，勿留空（曾导致第二次只剩「仿冒品牌官网」）
          brand = hostAlignedLatin || "";
        }
      } catch { brand = hostAlignedLatin || ""; }
      const latinFallback = (() => {
        try {
          if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
            const h = String(NS.pickHostAlignedLatinBrandFromPage(host) || "").trim();
            if (h && !forbid(h)
              && !(typeof NS.isHostShapedCompoundBrandToken === "function"
                && NS.isHostShapedCompoundBrandToken(h, host))) return h;
          }
        } catch { /* ignore */ }
        // 剥核展示：totodesk → ToDesk（formatSpoofDisplayFromHostCore / hostCoreLatin）
        try {
          if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
            const formatted = String(NS.formatSpoofDisplayFromHostCore(host) || "").trim();
            if (formatted && !forbid(formatted)
              && !(typeof NS.isHostShapedCompoundBrandToken === "function"
                && NS.isHostShapedCompoundBrandToken(formatted, host))) {
              return formatted;
            }
          }
        } catch { /* ignore */ }
        let coreLat = hostCoreLatin();
        try {
          if (coreLat && typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(coreLat, host)) coreLat = "";
        } catch { /* ignore */ }
        return coreLat
          || (o.brand && NS.isPureLatinSpoofBrand(o.brand) && !forbid(o.brand) ? String(o.brand).trim() : "")
          || (state.spoofBrand && NS.isPureLatinSpoofBrand(state.spoofBrand) && !forbid(state.spoofBrand)
            ? String(state.spoofBrand).trim() : "");
      })();
      if (!brand) brand = latinFallback;

      const writeSignals = (finalBrand, validationOpts) => {
        if (!decisionIsCurrent()) return "";
        let fb = String(finalBrand || "").trim();
        try {
          const fbAligned = fb && typeof NS.spoofDisplayBrandAlignsHost === "function"
            && NS.spoofDisplayBrandAlignsHost(fb, host, validationOpts || {});
          if (!fbAligned && typeof NS.extractChineseBrandFromPageTitle === "function") {
            const tb = NS.extractChineseBrandFromPageTitle();
            if (tb && typeof NS.spoofDisplayBrandAlignsHost === "function"
              && NS.spoofDisplayBrandAlignsHost(tb, host, validationOpts || {})) fb = tb;
          }
        } catch { /* ignore */ }
        // 禁止空展示：至少用主机核拉丁（Huorong）
        if (!fb) fb = latinFallback || hostCoreLatin() || "";
        let stored = fb;
        if (typeof NS.setSpoofDisplayBrand === "function") {
          stored = String(NS.setSpoofDisplayBrand(fb, {
            lockChinese: /[\u4e00-\u9fff]{2,}/.test(fb),
            forceChinese: /[\u4e00-\u9fff]{2,}/.test(fb),
            pinyinValidated: !!(validationOpts && validationOpts.pinyinValidated)
          }) || "").trim();
        } else {
          state.spoofBrand = fb;
          stored = fb;
        }
        // 只能依据统一写入后的值决定中文锁；严禁再用原始 fb 覆盖归一结果。
        if (/[\u4e00-\u9fff]{2,}/.test(stored)) state._spoofBrandChineseLocked = true;
        else state._spoofBrandChineseLocked = false;
        const shown = String(state.spoofBrand || stored || "");
        const requestedDetail = String(o.signalDetail || "").trim();
        // 调用方的早期 signalDetail 可能是中性模板；品牌已定稿后必须把品牌写进
        // 详情，确保报告/popup 即使丢失瞬时状态也能回捞正确展示名。
        const detail = shown && !/品牌「[^」]+」/.test(requestedDetail)
          ? `标题/正文品牌「${shown}」与域名 ${host} 不匹配（${matchHint}）`
          : (requestedDetail || (shown
            ? `标题/正文品牌「${shown}」与域名 ${host} 不匹配（${matchHint}）`
            : `域名 ${host} 呈现品牌夹带结构（${matchHint}）`));
        try {
          if (typeof NS.addSignal === "function") {
            NS.addSignal("仿冒品牌官网下载站", 24, detail);
          }
          // addSignal de-duplicates by signal name.  A corrected final brand
          // must therefore replace the old reason instead of leaving the
          // popup/report text on the first hydrated candidate.
          (state.details || []).forEach((d) => {
            if (!d) return;
            if (d.name === "仿冒品牌官网下载站") {
              d.reason = detail;
              return;
            }
            if (/仿冒站下载拦截|主动探测仿冒/i.test(String(d.name || ""))
              && /仿冒|品牌/i.test(String(d.reason || ""))) {
              d.reason = String(d.reason || "").replace(/「[^」]+」/g, `「${shown}」`);
            }
          });
        } catch { /* ignore */ }
        return shown;
      };

      /**
       * 定稿展示。优先中文（火绒）；纯拉丁（Huorong）仅兜底。
       * force=true：允许用中文覆盖已展示的拉丁。
       */
      const presentOnce = (finalBrand, optsPres) => {
        if (!decisionIsCurrent()) return "";
        const force = !!(optsPres && optsPres.force);
        const pinyinValidated = !!(optsPres && optsPres.pinyinValidated);
        const curShown = String(state.spoofBrand || "").trim();
        const requestedBrand = String(finalBrand || "").trim();
        const requestedChineseCorrection = !!(state._brandSpoofFinalPresented
          && pinyinValidated
          && /[\u4e00-\u9fff]{2,}/.test(curShown)
          && /[\u4e00-\u9fff]{2,}/.test(requestedBrand)
          && requestedBrand !== curShown);
        // Chinese is normally monotonic, but the latest sequence/fingerprint
        // checked pinyin result may correct an earlier hydrated Chinese word.
        // Older SW responses never reach this branch.
        if (state._brandSpoofFinalPresented && /[\u4e00-\u9fff]{2,}/.test(curShown)
          && !requestedChineseCorrection) return curShown;
        // 已展示拉丁、新值仍是拉丁 → 忽略（除非 force）
        if (state._brandSpoofFinalPresented && NS.isPureLatinSpoofBrand(curShown)
          && NS.isPureLatinSpoofBrand(String(finalBrand || "")) && !force) {
          return curShown;
        }

        let toShow = String(finalBrand || "").trim();
        // 拒绝弱中文（「中文」）
        try {
          if (toShow && typeof NS.isForbiddenSpoofDisplayBrand === "function"
            && NS.isForbiddenSpoofDisplayBrand(toShow)) {
            toShow = "";
          }
        } catch { /* ignore */ }
        // ★ 主机对齐页内拉丁（WPS）优先于错误中文
        try {
          if ((!toShow || (typeof NS.isForbiddenSpoofDisplayBrand === "function"
            && NS.isForbiddenSpoofDisplayBrand(toShow)))
            && typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
            const lat = NS.pickHostAlignedLatinBrandFromPage(host);
            if (lat) toShow = lat;
          }
        } catch { /* ignore */ }
        try {
          if (typeof NS.extractChineseBrandFromPageTitle === "function") {
            const tb = NS.extractChineseBrandFromPageTitle();
            if (tb && (!toShow || NS.isPureLatinSpoofBrand(toShow)
              || (typeof NS.isForbiddenSpoofDisplayBrand === "function"
                && NS.isForbiddenSpoofDisplayBrand(toShow)))) {
              // 仅当没有主机对齐拉丁时才用标题中文
              if (!toShow || !NS.isPureLatinSpoofBrand(toShow)) toShow = tb;
            }
          }
        } catch { /* ignore */ }
        try {
          if ((!toShow || NS.isPureLatinSpoofBrand(toShow) || (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(toShow)))
            && NS.caches && NS.caches._primaryKw) {
            const pk = NS.caches._primaryKw;
            const cands = [pk.display].concat(pk.cn || []);
            for (let i = 0; i < cands.length; i++) {
              const c = String(cands[i] || "").trim();
              if (!c || !/[\u4e00-\u9fff]{2,}/.test(c)) continue;
              if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(c)) continue;
              // pinyin 就绪：须与主机对齐，否则跳过（避免「中文」）
              try {
                if (pinyinApiReady && pinyinApiReady() && typeof NS.chinesePinyinAlignsHost === "function"
                  && !NS.chinesePinyinAlignsHost(c, host)) continue;
              } catch { /* ignore */ }
              toShow = c;
              break;
            }
          }
        } catch { /* ignore */ }
        // 仍是弱中文 → 回落拉丁核
        try {
          if (toShow && /[\u4e00-\u9fff]/.test(toShow)
            && typeof NS.isWeakChineseBrandToken === "function"
            && NS.isWeakChineseBrandToken(toShow)) {
            toShow = "";
          }
        } catch { /* ignore */ }
        // 最后一道双向门禁：未经 host/pinyin 反证的中文不得进入 toast。
        try {
          if (toShow && typeof NS.spoofDisplayBrandAlignsHost === "function"
            && !NS.spoofDisplayBrandAlignsHost(toShow, host, optsPres || {})) {
            toShow = hostAlignedLatin || latinFallback || hostCoreLatin() || "";
          }
        } catch { toShow = hostAlignedLatin || latinFallback || hostCoreLatin() || ""; }
        if (!toShow) toShow = latinFallback || hostCoreLatin() || "";

        // 中文覆盖已展示的拉丁：重置 notice 去重，允许再弹一次
        const upgradingLatinToCn = state._brandSpoofFinalPresented
          && NS.isPureLatinSpoofBrand(curShown)
          && /[\u4e00-\u9fff]{2,}/.test(toShow);
        const correctingChineseWithPinyin = !!(state._brandSpoofFinalPresented
          && pinyinValidated
          && /[\u4e00-\u9fff]{2,}/.test(curShown)
          && /[\u4e00-\u9fff]{2,}/.test(toShow)
          && toShow !== curShown);
        if (upgradingLatinToCn || correctingChineseWithPinyin) {
          state._brandSpoofNoticeSent = false;
          state._brandSpoofNoticeKey = "";
          state._lastGuardNoticeKey = "";
          state._lastGuardNoticeVersion = "";
          try {
            if (correctingChineseWithPinyin && typeof NS.dismissPageToast === "function") {
              NS.dismissPageToast("brand-spoof");
            }
          } catch { /* ignore */ }
        } else if (state._brandSpoofFinalPresented && !force && !upgradingLatinToCn) {
          return curShown;
        }

        if (!decisionIsCurrent()) return "";
        // 最终再拦一次：未确认官网前绝不 toast
        if (typeof NS.canPresentSoftBrandSpoofNotice === "function"
          && !NS.canPresentSoftBrandSpoofNotice()) {
          state._pendingSoftBrandSpoof = true;
          state._brandSpoofPresentationDeferred = true;
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "presentOnce-suppressed-until-official-check");
          return "";
        }
        const shown = writeSignals(toShow, optsPres || {});
        if (!shown || !decisionIsCurrent()) return "";
        state._brandSpoofFinalPresented = true;
        state._spoofPinyinUpgradeDone = /[\u4e00-\u9fff]{2,}/.test(shown);
        state._brandSpoofLatinOnly = NS.isPureLatinSpoofBrand(shown);
        if (/[\u4e00-\u9fff]{2,}/.test(shown)) {
          state._spoofBrandChineseLocked = true;
          state._brandSpoofLatinOnly = false;
        }

        const noticeSequence = Number(state._brandSpoofNoticeSequence || 0) + 1;
        state._brandSpoofNoticeSequence = noticeSequence;
        const finalSnapshot = {
          final: true,
          brand: shown,
          url: decisionUrl,
          analysisTxn: String(state._analysisTxn || ""),
          analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now(),
          decisionGeneration,
          identityRevision: Number(state._brandElectionIdentityRevision || 0),
          pinyinRequestSequence: Number(state._brandPinyinRequestSequence || 0),
          pinyinFingerprint: String(state._brandPinyinRequestFingerprint || ""),
          noticeSequence,
          issuedAt: Date.now()
        };
        state._brandSpoofFinalSnapshot = finalSnapshot;

        const noticeTitle = shown ? `已识别仿冒「${shown}」官网` : "已识别仿冒品牌官网";
        const noticeMsg = o.noticeMsg
          || (shown
            ? `页面标题/正文品牌「${shown}」与当前域名不匹配，疑似仿冒官网。`
            : `域名 ${host} 与页面宣称品牌不匹配，疑似仿冒官网下载站`);
        const reason = o.reason
          || (shown ? `仿冒品牌官网下载站（仿冒「${shown}」）` : "仿冒品牌官网下载站");
        try {
          if (typeof NS.installDownloadGuard === "function") {
            NS.installDownloadGuard(reason, {
              notify: true,
              href: "",
              message: noticeMsg,
              title: noticeTitle,
              guardKind: "brand-spoof",
              forceNotify: true,
              lockHard,
              brandSnapshot: finalSnapshot
            });
          }
          NS.disableAllDownloadIntentControls();
        } catch { /* ignore */ }
        try {
          if (typeof NS.emitRiskReport === "function") NS.emitRiskReport(true);
        } catch { /* ignore */ }
        NS.silverfoxLog && NS.silverfoxLog(
          "brand-spoof", "present-final", shown || "(empty)", host,
          upgradingLatinToCn ? "upgrade-latin→cn" : (correctingChineseWithPinyin ? "correct-cn→cn" : ""),
          "title=", String(document.title || "").slice(0, 60),
          "core=", hostCoreRaw() || "-"
        );
        // analysisComplete 曾为品牌终选暂缓；中文/最终拉丁定稿后立即在同一首访收口。
        if (state._analysisCompletionDeferredForBrand && !state._brandCompletionResumeScheduled) {
          state._brandCompletionResumeScheduled = true;
          setTimeout(() => {
            state._brandCompletionResumeScheduled = false;
            try {
              if (!decisionIsCurrent()) return;
              if (typeof NS.markAnalysisComplete === "function") {
                NS.markAnalysisComplete("brand-display-final");
              }
            } catch { /* ignore */ }
          }, 0);
        }
        return shown;
      };

      // ① 已是可信展示名（含 WPS 拉丁 / 钉钉中文）。
      // 页内另有强中文身份候选时，拉丁命中只能作 provisional，必须先让 SW
      // 完成 qishui ⇄ 汽水 这类双向确认，不能让 Qishui 抢先 final。
      const strongChineseForUpgrade = typeof NS.collectStrongChineseBrandCandidates === "function"
        ? NS.collectStrongChineseBrandCandidates()
        : [];
      const immediateLatinFromPage = !!(brand && hostAlignedLatin
        && brand.toLowerCase().replace(/[^a-z0-9]/g, "")
          === hostAlignedLatin.toLowerCase().replace(/[^a-z0-9]/g, ""));
      const immediateChineseLocallyValidated = !!(brand && /[\u4e00-\u9fff]{2,}/.test(brand)
        && typeof NS.spoofDisplayBrandAlignsHost === "function"
        && NS.spoofDisplayBrandAlignsHost(brand, host));
      if (brand && !forbid(brand)
        && ((immediateLatinFromPage && strongChineseForUpgrade.length === 0)
          || immediateChineseLocallyValidated)) {
        return presentOnce(brand);
      }
      // 弱中文丢掉
      if (brand && forbid(brand)) brand = "";

      // ② 拉丁核 / 待 pinyin：先静默拦截，再对「火绒」
      const provisional = (brand && !/[\u4e00-\u9fff]/.test(brand) ? brand : "")
        || hostAlignedLatin || latinFallback || hostCoreLatin() || "";
      if (provisional && typeof NS.setSpoofDisplayBrand === "function") {
        NS.setSpoofDisplayBrand(provisional);
      } else if (provisional) {
        state.spoofBrand = provisional;
      }
      // This is candidate state only.  A provisional identity hold owns the
      // short pre-verdict click wait; the permanent brand guard and disabled
      // controls are installed exclusively by presentOnce() after final
      // election.  Otherwise a stale t0 candidate can block the official page
      // before its hydrated identity or pinyin result arrives.

      if (state._brandSpoofFinalizeScheduled) {
        return state._brandSpoofFinalPresented ? String(state.spoofBrand || "") : "";
      }
      state._brandSpoofFinalizeScheduled = true;
      let pinyinReady = false;
      let attempts = 0;

      const pinyinApiReady = () => {
        try {
          const g = typeof globalThis !== "undefined" ? globalThis : null;
          const api = g && (g.__silverfoxPinyinPro || g.pinyinPro);
          return !!(api && typeof api.pinyin === "function");
        } catch { return false; }
      };

      /** 展示用中文是否可信：挡「中文」；pinyin 就绪时必须与主机对齐 */
      const isPlausibleSpoofCn = (c, requirePy) => {
        const s = String(c || "").trim();
        if (!s || !/[\u4e00-\u9fff]{2,}/.test(s)) return false;
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(s)) return false;
        if (/^(?:中文|英文|简体|繁体|官方|官网|下载|安全|应用|中心)$/.test(s)) return false;
        if (requirePy) {
          if (!pinyinApiReady() || typeof NS.chinesePinyinAlignsHost !== "function") return false;
          try { if (!NS.chinesePinyinAlignsHost(s, host)) return false; } catch { return false; }
        }
        return true;
      };

      const lockCn = (c, requirePy) => {
        const s = String(c || "").trim();
        if (!isPlausibleSpoofCn(s, !!requirePy)) return "";
        if (typeof NS.setSpoofDisplayBrand === "function") {
          return String(NS.setSpoofDisplayBrand(s, { lockChinese: true, forceChinese: true }) || "").trim();
        } else {
          state.spoofBrand = s;
          state._spoofBrandChineseLocked = true;
        }
        return s;
      };

      const tryResolveChinese = () => {
        try {
          // 0) 标题硬抽（钉钉应用中心）——结构壳，不强制 pinyin
          try {
            if (typeof NS.extractChineseBrandFromPageTitle === "function") {
              const tb = NS.extractChineseBrandFromPageTitle();
              if (tb) {
                const hit = lockCn(tb, true);
                if (hit) return hit;
              }
            }
          } catch { /* ignore */ }

          // 1) 选举 cn：pinyin 就绪则必须主机对齐；未就绪取非弱中文
          try {
            if (typeof NS.collectPrimaryBrandKeywords === "function") {
              const pk = (NS.caches && NS.caches._primaryKw)
                || NS.collectPrimaryBrandKeywords();
              if (pk && pk.display && isPlausibleSpoofCn(pk.display, true)) {
                const hit = lockCn(pk.display, true);
                if (hit) return hit;
              }
              if (pk && pk.cn) {
                for (let i = 0; i < Math.min(pk.cn.length, 8); i++) {
                  const c = String(pk.cn[i] || "").trim();
                  const hit = lockCn(c, true);
                  if (hit) return hit;
                }
              }
            }
          } catch { /* ignore */ }

          // 2) 页内 pinyin 已废弃；对齐走 SW requestBrandPinyinAlign
        } catch { /* ignore */ }
        return "";
      };

      /**
       * 优先标题中文 / SW pinyin 对齐；拉丁仅兜底。
       */
      const finalize = (allowLatinFallback, forceDecision) => {
        try {
          if (!decisionIsCurrent()) return;
          attempts += 1;
          // 已是可信中文定稿（弱词「中文」不算）
          const curBr = String(state.spoofBrand || "").trim();
          if (state._brandSpoofFinalPresented && /[\u4e00-\u9fff]{2,}/.test(curBr)
            && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(curBr))) {
            return;
          }
          // 已定稿却是弱中文：解锁以便 SW/标题覆盖
          if (state._brandSpoofFinalPresented
            && typeof NS.isWeakChineseBrandToken === "function"
            && NS.isWeakChineseBrandToken(curBr)) {
            state._brandSpoofFinalPresented = false;
            state._spoofBrandChineseLocked = false;
            state._brandSpoofNoticeSent = false;
          }
          const cn = tryResolveChinese();
          if (cn && /[\u4e00-\u9fff]{2,}/.test(cn)) {
            presentOnce(cn, { force: true });
            return;
          }
          // 再强制扫一遍主机↔中文（pinyin 双向）
          if (pinyinApiReady() && typeof NS.pickPageChineseBrandByHostPinyin === "function") {
            try {
              if (typeof NS.clearBrandPinyinCaches === "function") NS.clearBrandPinyinCaches();
              const pyB = NS.pickPageChineseBrandByHostPinyin(host);
              if (pyB) {
                presentOnce(pyB, { force: true });
                return;
              }
            } catch { /* ignore */ }
          }
          const lat = provisional || hostCoreLatin() || "";
          // 拼音未就绪：绝不弹 Huorong/Dingding（等注入 + 选举中文）
          if (!pinyinReady && !pinyinApiReady()) {
            if (allowLatinFallback && (forceDecision || attempts >= 4) && lat) {
              // 最后兜底前再扫一次选举中文
              const lastCn = tryResolveChinese();
              if (lastCn) presentOnce(lastCn, { force: true });
              else presentOnce(lat);
            }
            return;
          }
          pinyinReady = true;
          if (!allowLatinFallback) return;
          // 拼音已就绪：仍优先选举中文；多次未命中才拉丁
          if ((forceDecision || attempts >= 4) && lat) {
            const lastCn2 = tryResolveChinese();
            if (lastCn2) presentOnce(lastCn2, { force: true });
            else presentOnce(lat);
          } else if (allowLatinFallback && forceDecision && !lat) {
            // 已完成两轮 SW/DOM 尝试仍无合法展示名：结束 pending，允许报告
            // 以中性品牌仿冒结论收口，不能永久卡在“正在分析”。
            state._brandSpoofFinalizeScheduled = false;
            if (state._analysisCompletionDeferredForBrand
              && typeof NS.markAnalysisComplete === "function") {
              setTimeout(() => NS.markAnalysisComplete("brand-display-unresolved"), 0);
            }
          }
        } catch {
          if (allowLatinFallback) {
            try {
              presentOnce(provisional || hostCoreLatin() || "", { force: false });
            } catch { /* ignore */ }
          }
        }
      };

      // ★ 拼音在 SW：传短候选，不 inject 网页
      const collectSwPinyinCandidateSnapshot = () => {
        const candidates = typeof NS.collectLightChineseBrandCandidates === "function"
          ? NS.collectLightChineseBrandCandidates() : [];
        const strongCandidates = typeof NS.collectStrongChineseBrandCandidates === "function"
          ? NS.collectStrongChineseBrandCandidates() : [];
        const normalize = (items) => (Array.isArray(items) ? items : [])
          .map((item) => String(item || "").replace(/\s+/g, " ").trim())
          .filter(Boolean).slice(0, 24);
        const cands = normalize(candidates);
        const strongCands = normalize(strongCandidates);
        return {
          cands,
          strongCands,
          fingerprint: `${host}|${cands.join("\u001f")}|${strongCands.join("\u001f")}`
        };
      };

      const swPinyinRequestIsCurrent = (requestSeq, candidateFingerprint) => {
        try {
          if (!decisionIsCurrent()) return false;
          if (Number(state._brandPinyinRequestSequence || 0) !== requestSeq) return false;
          if (String(state._brandPinyinRequestFingerprint || "") !== candidateFingerprint) return false;
          return collectSwPinyinCandidateSnapshot().fingerprint === candidateFingerprint;
        } catch { return false; }
      };

      // The t0 call only warms the service worker.  The t400 snapshot may
      // commit, and sequence + fingerprint checks make every older response
      // and fallback inert after the page hydrates different candidates.
      const kickSwPinyin = (allowCommit) => {
        try {
          if (!decisionIsCurrent()) return;
          const snapshot = collectSwPinyinCandidateSnapshot();
          const cands = snapshot.cands;
          const strongCands = snapshot.strongCands;
          const candidateFingerprint = snapshot.fingerprint;
          const requestSeq = Number(state._brandPinyinRequestSequence || 0) + 1;
          state._brandPinyinRequestSequence = requestSeq;
          state._brandPinyinRequestFingerprint = candidateFingerprint;
          // 标题壳先同步定稿（钉钉应用中心），不依赖 SW
          if (allowCommit) finalize(false);
          if (!cands.length || typeof NS.requestBrandPinyinAlign !== "function") {
            if (allowCommit) {
              setTimeout(() => {
                if (!swPinyinRequestIsCurrent(requestSeq, candidateFingerprint)) return;
                finalize(true);
              }, 600);
            }
            return;
          }
          NS.requestBrandPinyinAlign({
            host,
            candidates: cands,
            strongCandidates: strongCands
          }).then((evidenceSw) => {
            if (!allowCommit || !swPinyinRequestIsCurrent(requestSeq, candidateFingerprint)) return;
            pinyinReady = true;
            const brandSw = evidenceSw && String(evidenceSw.brand || "").trim();
            const relationSw = evidenceSw && typeof NS.classifyBrandPinyinHostEvidence === "function"
              ? NS.classifyBrandPinyinHostEvidence(evidenceSw, host)
              : { officialExact: false, hostMatch: "none" };
            if (evidenceSw) {
              state._brandPinyinEvidence = { ...evidenceSw, ...relationSw, host };
              state._brandPinyinHostMatch = relationSw.hostMatch || "none";
            }
            // 只有“pinyin == 干净注册域左标”的 exact 才否定域名错配；
            // n-qishui / qishuiyyds 即使片段 exact 仍分别是 hyphen/padded。
            if (brandSw && relationSw.officialExact) {
              invalidateBrandSpoofDecision(state, "pinyin-clean-apex-exact");
              state._brandSpoofFinalizeScheduled = false;
              state._brandSpoofFinalPresented = false;
              state._brandSpoofFinalSnapshot = null;
              state._spoofPinyinUpgradeDone = true;
              state._brandElectionSettledUrl = String(location.href || "");
              try {
                if (typeof NS.clearBrandSpoofFalsePositive === "function") {
                  NS.clearBrandSpoofFalsePositive("pinyin-clean-apex-exact", { preserveNoIcp: true });
                } else {
                  state._brandSpoofPortalDetected = false;
                  state.spoofBrand = "";
                  state._pendingSoftBrandSpoof = false;
                }
              } catch { /* ignore */ }
              if (state._analysisCompletionDeferredForBrand
                && typeof NS.markAnalysisComplete === "function") {
                setTimeout(() => {
                  if (String(location.href || "") !== decisionUrl) return;
                  NS.markAnalysisComplete("brand-pinyin-clean-exact");
                }, 0);
              }
              return;
            }
            if (brandSw && /[\u4e00-\u9fff]{2,}/.test(brandSw)
              && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brandSw))) {
              presentOnce(brandSw, { force: true, pinyinValidated: true });
              return;
            }
            finalize(true);
          }).catch(() => {
            if (!allowCommit || !swPinyinRequestIsCurrent(requestSeq, candidateFingerprint)) return;
            finalize(true);
          });
        } catch {
          if (allowCommit) {
            finalize(false);
            const requestSeq = Number(state._brandPinyinRequestSequence || 0);
            const candidateFingerprint = String(state._brandPinyinRequestFingerprint || "");
            setTimeout(() => {
              if (!swPinyinRequestIsCurrent(requestSeq, candidateFingerprint)) return;
              finalize(true);
            }, 800);
          }
        }
      };
      kickSwPinyin(false);
      // 少量重试：标题晚挂 / SW 冷启动
      setTimeout(() => kickSwPinyin(true), 400);
      // 明确截止裁决：两轮 SW 后成功则中文定稿；否则合法拉丁/中性结论收口。
      setTimeout(() => {
        const requestSeq = Number(state._brandPinyinRequestSequence || 0);
        const candidateFingerprint = String(state._brandPinyinRequestFingerprint || "");
        if (!swPinyinRequestIsCurrent(requestSeq, candidateFingerprint)) return;
        finalize(true, true);
      }, 1600);
      // Callers use a non-empty return as a committed threat and may install a
      // fallback brand guard themselves.  Keep the provisional transaction
      // invisible until presentOnce() has actually elected and guarded it.
      return state._brandSpoofFinalPresented ? String(state.spoofBrand || "") : "";
    } catch {
      const state = NS.state || {};
      return state._brandSpoofFinalPresented ? String(state.spoofBrand || "") : "";
    }
  };

  /** @deprecated 由 commitBrandSpoofPresentation 内部定稿；保留空调度兼容旧调用 */
  NS.scheduleSpoofDisplayPinyinUpgrade = function () {
    try {
      const state = NS.state;
      if (!state || state._brandSpoofFinalPresented) return;
      if (!(state._brandSpoofPortalDetected || state.spoofBrand)) return;
      if (/[一-鿿]{2,}/.test(String(state.spoofBrand || ""))) {
        state._spoofBrandChineseLocked = true;
        return;
      }
      // 若尚未走 commit，补一次静默定稿（不先弹拉丁）
      if (!state._brandSpoofFinalizeScheduled && typeof NS.commitBrandSpoofPresentation === "function") {
        NS.commitBrandSpoofPresentation({
          brand: state.spoofBrand || "",
          matchHint: "域名与品牌不匹配",
          lockHard: true
        });
      }
    } catch { /* ignore */ }
  };

  /** 强信任身份：有效 ICP / 超成熟 WHOIS / 可展示 OV·EV → 禁止 brand-spoof */
  NS.pageHasStrongTrustedIdentity = function () {
    try {
      const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      if (!profile) return false;
      // 成熟组合门；或正规且干净的页面再叠加 OV/EV。ICP、WHOIS 年龄、
      // 干净域名、产品子域任一单项都不再直接取得“强信任”身份。
      return !!(profile.trusted
        || (profile.cleanPage && profile.regularPage && profile.orgSsl)
        || (typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
          && NS.hasAuthoritativeMatureOrganizationIdentity(profile)));
    } catch { return false; }
  };

  NS.tryArmChineseBrandDownloadHomeSpoof = function () {
    try {
      const state = NS.state;
      if (NS.reconcileSoftBrandSpoofWithMutualLatinExact(
        location.hostname, "home-fast-mutual-latin-exact"
      )) return false;
      const needsBrandAuthority = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity();
      if (typeof NS.pageLooksLikeWebSslOrOpsToolPage === "function" && NS.pageLooksLikeWebSslOrOpsToolPage()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-web-ops-tool");
        return false;
      }
      // y.qq.com + QQ音乐 / 腾讯 OV / 粤 ICP：绝不当仿冒（须在一切下载壳逻辑之前）
      if (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()) {
        state._pendingSoftBrandSpoof = false;
        if (state._brandSpoofPortalDetected || state.downloadGuardInstalled) {
          try {
            if (typeof NS.clearBrandSpoofFalsePositive === "function") {
              NS.clearBrandSpoofFalsePositive("strong-trusted-identity");
            }
          } catch { /* ignore */ }
        }
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-strong-identity");
        return false;
      }
      // 已 arm 时仍复检开源可信（DOM/情报后到），避免误报粘住
      if (state.downloadGuardInstalled && state._brandSpoofPortalDetected) {
        try {
          if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
            && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
            if (typeof NS.clearBrandSpoofFalsePositive === "function") {
              NS.clearBrandSpoofFalsePositive("trusted-opensource");
            }
            NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-lift-trusted-opensource");
            return false;
          }
        } catch { /* ignore */ }
        return true;
      }
      // 公开代码仓 + 下载落在 forge/成熟同站 → 开源项目站，不按仿冒 arm
      try {
        if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-trusted-opensource");
          return false;
        }
        // 有仓但 ICP/WHOIS 尚未返回：暂不 home-fast arm，等情报 pipeline 再判
        if (typeof NS.pageHasPublicCodeForgePresence === "function"
          && NS.pageHasPublicCodeForgePresence()
          && !(typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord())
          && (typeof NS.getWhoisAgeDays !== "function" || NS.getWhoisAgeDays() == null)
          && !NS.state._icpQuerySettled) {
          state._pendingSoftBrandSpoof = true;
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-defer-opensource-intel");
          return false;
        }
      } catch { /* ignore */ }
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

      // ★ 硬门：只有确认是「软件下载落地壳」才允许 home-fast arm。
      // 曾把 chatgpt.com 等正站误报成仿冒「解析差异」——home-fast 曾绕过壳门控。
      // 仅有导航「Download」链到 /download 不够；须有下载话术或真实包/加密壳。
      try {
        const shell = typeof NS.evaluateSoftwareDownloadLandingShell === "function"
          ? NS.evaluateSoftwareDownloadLandingShell()
          : null;
        if (!shell || !shell.ok) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-not-download-landing", shell || {});
          return false;
        }
        const titleDl = /下载|安装|客户端|安装包/i.test(String(document.title || ""));
        const realDlShell = shell.pkgCount > 0 || shell.encryptedDl
          || ((shell.pitch || shell.softPitch) && (shell.hasHub || shell.ctaCount >= 2 || shell.multiPlatform))
          || (shell.ctaCount >= 2 && shell.pitch && titleDl);
        if (!realDlShell) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-no-real-download-shell", shell.reasons || []);
          return false;
        }
      } catch {
        return false;
      }

      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      // 多标签关键词能拼成域名（title/logo/nav 的 ToDesk + AI ≡ todeskai）→ 绝不报盗版
      // 夹带 apex（qq-musics）或营销子域 win. 不得因首标签对齐而跳过
      // ★ 年轻无备案：禁止强对齐 / related 捷径（todesk-ze 37 天曾放跑）
      const youngUnverified = typeof NS.isYoungUnverifiedRegistration === "function"
        && NS.isYoungUnverifiedRegistration();
      try {
        const ap0 = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host) || host;
        const apLeft0 = (String(ap0).split(".")[0] || "").toLowerCase();
        const pad0 = typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(apLeft0);
        // ★ 主路径：域名 ↔ 页内关键词双向校验（ChatGPT ⇄ chatgpt.com）
        // 垃圾词表只是兜底；只要页内身份核与干净 apex 互证，绝不当软仿冒。
        if (!youngUnverified && !needsBrandAuthority && !pad0
          && typeof NS.pageKeywordsBidirectionallyMatchHost === "function"
          && NS.pageKeywordsBidirectionallyMatchHost(host)) {
          state._pendingSoftBrandSpoof = false;
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-bidirectional-keyword-host", host);
          return false;
        }
        if (!youngUnverified && !needsBrandAuthority && !pad0
          && typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
          && NS.hostLabelStronglyAlignedWithIdentityKeywords(apLeft0)) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-skip-identity-aligned", host);
          return false;
        }
      } catch { /* ignore */ }
      const rel = typeof NS.evaluateDomainKeywordRelevance === "function"
        ? NS.evaluateDomainKeywordRelevance(host)
        : null;
      // 几乎关联（exact/category）→ 不显示盗版；年轻无备案不得走此捷径
      if (!youngUnverified && !needsBrandAuthority && rel && rel.related && !rel.squat) {
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
      // 页内中文产品品牌 + 主机品类拉丁尾（qissmusic 等）：结构 squat，展示名来自页内抽词
      let cnCategorySquat = null;
      let cnCategoryPageBrand = "";
      try {
        if (!officialProdSub
          && (typeof NS.detectChineseProductCategoryHostSquat === "function"
            || typeof NS.detectChineseMusicBrandDomainSquat === "function")) {
          const fn = NS.detectChineseProductCategoryHostSquat || NS.detectChineseMusicBrandDomainSquat;
          const pk0 = typeof NS.collectPrimaryBrandKeywords === "function"
            ? NS.collectPrimaryBrandKeywords()
            : null;
          const cnFromPage = (pk0 && pk0.display && /[一-鿿]/.test(pk0.display) ? pk0.display : "")
            || (pk0 && pk0.cn && pk0.cn.find((x) => /[一-鿿]/.test(String(x))))
            || (rel && rel.brand && /[一-鿿]/.test(rel.brand) ? rel.brand : "")
            || "";
          // 优先页内完整产品形态（汽水音乐 / QQ音乐），短 display「汽水」用 blob 补品类
          const cnBlobHint = (() => {
            try {
              if (typeof NS.pickBestSpoofDisplayBrand === "function") {
                const best = NS.pickBestSpoofDisplayBrand(cnFromPage || "");
                if (best) return best;
              }
              const blob = String((pk0 && pk0.blob) || document.title || "");
              // 拉丁+中文：QQ音乐（纯中文 {2,8}音乐 抽不到）
              const mixed = blob.match(/([A-Za-z][A-Za-z0-9]{0,10}[一-鿿]{1,6}(?:音乐|浏览器|播放器|输入法|客户端)?)/);
              if (mixed && mixed[1]
                && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(mixed[1]))) {
                return mixed[1].replace(/(?:官网|官方|下载).*$/, "");
              }
              const prod = blob.match(/([一-鿿]{2,8}(?:音乐|安全|杀毒|卫士|浏览器|播放器|客户端|输入法|网盘|助手|管家))/);
              if (prod && prod[1]
                && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(prod[1]))) {
                return prod[1];
              }
            } catch { /* ignore */ }
            return cnFromPage;
          })();
          cnCategoryPageBrand = cnBlobHint || cnFromPage || "";
          cnCategorySquat = fn(apexFlat0 || lab, cnBlobHint)
            || fn(apexLeftRaw || labelRaw, cnBlobHint)
            || fn(lab, cnBlobHint);
        }
      } catch { cnCategorySquat = null; }
      // 无页内品牌时：仅结构品类尾也可标 padded 形态（apex 营销夹带），不发明品牌名
      const hostCategoryPadShape = !officialProdSub && !cnCategorySquat
        && typeof NS.parseHostChineseProductCategoryPad === "function"
        && !!(NS.parseHostChineseProductCategoryPad(apexFlat0 || lab, cnCategoryPageBrand)
          || NS.parseHostChineseProductCategoryPad(apexLeftRaw || labelRaw, cnCategoryPageBrand));
      const isPaddedHost = !officialProdSub && (digitPadHost || hyphenHost || qqMusicSquat
        || !!cnCategorySquat || hostCategoryPadShape
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
          || /[-_](pc|app|soft|safe|vip|pro|cn|win|download|client|free|official|music|musics|lab|labs|tech|site)$/i.test(labelRaw)
          || /[-_](pc|app|soft|safe|vip|pro|cn|win|download|client|free|official|music|musics|lab|labs|tech|site)$/i.test(apexLeftRaw)
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
          if (typeof NS.canonicalizeBrandDisplayCandidate === "function" && pk && pk.display && !isDebris(pk.display)) {
            brand = NS.canonicalizeBrandDisplayCandidate(pk.display);
          } else if (pk && pk.display && !isDebris(pk.display)) {
            brand = pk.display;
          }
          if ((!brand || isDebris(brand)) && pk && pk.cn && pk.cn[0]) {
            brand = typeof NS.canonicalizeBrandDisplayCandidate === "function"
              ? NS.canonicalizeBrandDisplayCandidate(pk.cn[0])
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
          // 夹带核：仅当页内身份槽已声明该拉丁核时才可格式化展示（无固定中文桥）
          if ((!brand || isDebris(brand)) && core && core.length >= 4) {
            const coreInfo = pk && pk.scores && pk.scores[core];
            const coreSources = Array.isArray(coreInfo && coreInfo.sources) ? coreInfo.sources : [];
            const pageDeclaredCore = coreSources.some((src) => /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema)$/i.test(String(src)));
            if (pageDeclaredCore) {
              brand = typeof NS.formatBrandTokenForDisplay === "function"
                ? NS.formatBrandTokenForDisplay(core)
                : core;
            }
          }
        } catch { brand = ""; }
      }
      if (brand && isDebris(brand)) brand = "";
      if (brand && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        brand = NS.canonicalizeBrandDisplayCandidate(brand);
      }
      if (brand && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)) brand = "";
      if (brand && typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(brand)) brand = "";
      // 拉丁停用词；中文品牌用 pinyin 与主机校验，不经 isGenericTech
      if (brand && /^[A-Za-z]/.test(brand) && NS.BRAND_TOKEN_STOP_RE
        && NS.BRAND_TOKEN_STOP_RE.test(String(brand).toLowerCase().replace(/[^a-z0-9]/g, ""))) {
        brand = "";
      }
      // 品类 / 品牌-域名 squat：必须尽量填上页内具体品牌（禁止 UI 中性「关联不严谨」空壳）
      if (!brand || brand.length < 2
        || (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand))) {
        const hints = [
          cnCategoryPageBrand,
          cnCategorySquat && cnCategorySquat.chineseSuffix,
          rel && rel.brand,
          rel && rel.display
        ].filter(Boolean);
        if (typeof NS.pickBestSpoofDisplayBrand === "function") {
          brand = NS.pickBestSpoofDisplayBrand(hints[0] || "") || brand;
          if (!brand || brand.length < 2) {
            for (let hi = 0; hi < hints.length; hi++) {
              brand = NS.pickBestSpoofDisplayBrand(hints[hi]) || brand;
              if (brand && brand.length >= 2) break;
            }
          }
        } else if (hints[0]) {
          brand = hints[0];
        }
      }
      // 无等权身份时：夹带站仍可 arm，但状态和 toast 使用中性文案。
      // 占位符绝不能写进 spoofBrand，否则会出现“仿冒「品牌」官网”。
      if ((!brand || brand.length < 2) && !isPaddedHost && !hyphenHost && !digitPadHost) return false;
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
      // 官方下载话术（假官网必备）；兼容「| 官方下载」；含 meta author / description 中的「官方」
      const descMeta = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").slice(0, 200);
      const authorMeta = String(document.querySelector('meta[name="author"]')?.getAttribute("content") || "");
      const officialClaim = /官网|官方下载|官方正版|官方网站|官方高速|官方渠道|免费下载|立即下载|客户端下载|下载中心|行业标准工具|安全官方|官方网站/i.test(
        `${title} ${kwMeta} ${descMeta} ${authorMeta}`
      ) || /官方下载|免费下载|立即下载|官方/i.test(title)
        || /官方/i.test(authorMeta);

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
        ? (((rel && rel.hostMatch === "typo") || (cnCategorySquat && cnCategorySquat.hostMatch === "typo")) ? "拼写仿冒"
          : (hyphenHost || (rel && rel.hostMatch === "hyphen")) ? "域名用连字符拆分品牌名"
          : digitPadHost ? "域名用数字品牌前缀+乱拼后缀" : "域名夹带品牌前缀/后缀")
        : pathSeoCnBrand
          ? "SEO套壳模板+品牌官方下载话术"
          : pathHollowOrNetdisk
            ? (hollowSupport ? "宣称支持/联系但无真实联系方式" : "仅网盘扫码分发无安装包直链")
            : "域名与品牌无关";
      // ★ 展示名：丢弃已算好的拉丁核 hint，强制从标题重选（钉钉应用中心 → 钉钉）
      try {
        if (NS.caches) {
          NS.caches._primaryKw = null;
          NS.caches._primaryKwAt = 0;
        }
        // 空 hint 调用，避免 pickBest(Dingding) 短路
        if (typeof NS.resolveSpoofDisplayBrandNow === "function") {
          brand = NS.resolveSpoofDisplayBrandNow("") || brand;
        } else if (typeof NS.pickBestSpoofDisplayBrand === "function") {
          brand = NS.pickBestSpoofDisplayBrand("") || brand;
        }
      } catch { /* ignore */ }
      if (brand && isDebris(brand)) brand = "";
      // 标题仍无中文、且为夹带站：才允许主机剥核拉丁
      if ((!brand || brand.length < 2 || (/^[A-Za-z]/.test(brand) && !/[一-鿿]/.test(brand)))
        && (pathSquat || isPaddedHost || hyphenHost || digitPadHost)) {
        // 再试标题 2 字专名（不经 pickBest）
        try {
          const t0 = String(document.title || "");
          const head = (t0.split(/\s*[-–—|·｜]\s*/)[0] || "").trim();
          const lead = (head.match(/^([一-鿿]{2,3})应用中心/) || [])[1]
            || (head.match(/^([一-鿿]{2,4})(?:应用中心|应用|中心)/) || [])[1]
            || "";
          if (lead && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(lead))) {
            brand = lead;
          }
        } catch { /* ignore */ }
        if ((!brand || brand.length < 2 || (/^[A-Za-z]/.test(brand) && !/[一-鿿]/.test(brand)))) {
          try {
            if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
              const hostBrand = NS.formatSpoofDisplayFromHostCore(host) || "";
              // 主机剥核若给出中文用中文；纯拉丁仅当标题完全无中文
              if (hostBrand && /[一-鿿]/.test(hostBrand)) brand = hostBrand;
              else if ((!brand || brand.length < 2) && hostBrand && !isDebris(hostBrand)) brand = hostBrand;
            }
            if ((!brand || brand.length < 2) && core && core.length >= 4
              && !isDebris(core)
              && typeof NS.formatBrandTokenForDisplay === "function") {
              brand = NS.formatBrandTokenForDisplay(core) || brand;
            }
          } catch { /* ignore */ }
        }
      }
      if (brand && isDebris(brand)) brand = "";
      if (brand && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)) brand = "";
      // ★ 定稿：中文优先；无标题中文时把主机核拉丁（Huorong）交给 commit 做 pinyin
      let titleBrand = "";
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          titleBrand = NS.extractChineseBrandFromPageTitle() || "";
        }
      } catch { /* ignore */ }
      let hostLatin = "";
      try {
        if ((!titleBrand || titleBrand.length < 2) && core && core.length >= 4
          && typeof NS.formatBrandTokenForDisplay === "function"
          && !isDebris(core)) {
          hostLatin = NS.formatBrandTokenForDisplay(core) || "";
        }
      } catch { /* ignore */ }
      const commitBrand = titleBrand
        || (brand && /[\u4e00-\u9fff]/.test(brand) ? brand : "")
        || hostLatin
        || (brand && !isDebris(brand) ? brand : "");
      let committedBrand = "";
      if (typeof NS.commitBrandSpoofPresentation === "function") {
        committedBrand = NS.commitBrandSpoofPresentation({
          brand: commitBrand,
          host: location.hostname || host,
          matchHint,
          lockHard: true,
          signalDetail: `标题/正文品牌与域名 ${location.hostname || host} 不匹配（${matchHint}）；下载导流门户`
        });
      }
      if (!committedBrand) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "home-fast-waiting-for-identity", host);
        return false;
      }
      NS.silverfoxLog && NS.silverfoxLog(
        "brand-spoof", "home-fast-path",
        (state.spoofBrand || commitBrand || "(pending)"),
        "titleBrand=", titleBrand || "-",
        "hostLatin=", hostLatin || "-",
        host,
        pathSquat ? `squat:${(rel && rel.hostMatch) || "padded"}` : "unrelated-official",
        "cta=", dlCta, "hub=", hub,
        "docTitle=", String(document.title || "").slice(0, 40)
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
      if (NS.reconcileSoftBrandSpoofWithMutualLatinExact(
        location.hostname, "portal-mutual-latin-exact"
      )) return false;
      const needsBrandAuthority = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity();
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (!needsBrandAuthority && NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
      // 最先跳过：在线 SSL/运维工具（非下载仿冒）
      if (typeof NS.pageLooksLikeWebSslOrOpsToolPage === "function" && NS.pageLooksLikeWebSslOrOpsToolPage()) {
        state._pendingSoftBrandSpoof = false;
        return false;
      }
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
        if (!needsBrandAuthority && !looksPadHost
          && typeof NS.hostLabelMatchesPageResourceApex === "function" && NS.hostLabelMatchesPageResourceApex()) {
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
        if (!needsBrandAuthority && !padAlign && typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
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
      if (!needsBrandAuthority && domainRel && domainRel.related && !domainRel.squat) {
        NS.silverfoxLog && NS.silverfoxLog(
          "brand-spoof", "skip-domain-keyword-related",
          domainRel.hostMatch, domainRel.brandToken || domainRel.brand
        );
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // 发行版 ISO 镜像页（Arch/Ubuntu…）在落地壳判定前跳过，避免 ISO 列表被当 exe 假官网
      if (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-os-distro-iso");
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // 在线证书/运维工具页（uptimepro ssl-lookup 等）→ 绝不进仿冒下载链路
      if (typeof NS.pageLooksLikeWebSslOrOpsToolPage === "function" && NS.pageLooksLikeWebSslOrOpsToolPage()) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-web-ops-tool");
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      // y.qq.com / 有效 ICP / 腾讯 OV / 超成熟 WHOIS：正站，跳过整条仿冒链
      if (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()) {
        state._pendingSoftBrandSpoof = false;
        try {
          if (state._brandSpoofPortalDetected || state.downloadGuardInstalled) {
            if (typeof NS.clearBrandSpoofFalsePositive === "function") {
              NS.clearBrandSpoofFalsePositive("strong-trusted-identity");
            }
          }
        } catch { /* ignore */ }
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-strong-trusted-identity");
        return false;
      }

      // ★ 先确认下载落地壳，再跑 home-fast / 完整仿冒链（禁止非下载站误报）
      const landingShell = typeof NS.evaluateSoftwareDownloadLandingShell === "function"
        ? NS.evaluateSoftwareDownloadLandingShell()
        : null;
      if (!landingShell || !landingShell.ok) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-not-download-landing", landingShell || {});
        state._pendingSoftBrandSpoof = false;
        return false;
      }
      // 无真实下载壳证据时不 arm（避免仅有导航 Download 链的正站误报）
      {
        const titleDl = /下载|安装|客户端|安装包/i.test(String(document.title || ""));
        const realDlShell = landingShell.pkgCount > 0 || landingShell.encryptedDl
          || ((landingShell.pitch || landingShell.softPitch)
            && (landingShell.hasHub || landingShell.ctaCount >= 2 || landingShell.multiPlatform))
          || (landingShell.ctaCount >= 2 && landingShell.pitch && titleDl);
        if (!realDlShell) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-no-real-download-shell", landingShell.reasons || []);
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      }

      // ★ 主路径：域名 ↔ 页内关键词双向互证通过 → 正站，不进仿冒链
      try {
        if (typeof NS.pageKeywordsBidirectionallyMatchHost === "function"
          && NS.pageKeywordsBidirectionallyMatchHost()) {
          state._pendingSoftBrandSpoof = false;
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-bidirectional-keyword-host");
          return false;
        }
      } catch { /* ignore */ }

      // 快速路径：须已过下载壳且双向校验未通过；squat 或「无关 + 官方下载」
      if (typeof NS.tryArmChineseBrandDownloadHomeSpoof === "function" && NS.tryArmChineseBrandDownloadHomeSpoof()) {
        return true;
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

      // 仅成熟正规站组合门可抬软仿冒；备案/年龄/干净域名单项均不放行。
      const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      if (matureProfile && matureProfile.trusted) {
        state._pendingSoftBrandSpoof = false;
        try {
          if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
            NS.forceLiftSoftProtectionForTrustedPortal("brand-spoof-skip-trusted");
          }
        } catch { /* ignore */ }
        return false;
      }

      // 公开代码仓 + 安装包指向 forge 或成熟同站（ICP/WHOIS）→ 开源项目官网，非银狐仿冒
      try {
        if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "skip-trusted-opensource-portal");
          state._pendingSoftBrandSpoof = false;
          return false;
        }
      } catch { /* ignore */ }

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
      if (typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity() && isSoftPadded
        && !state._seoCloakKitDetected && !state._fakeSpaDetected) {
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
          if (brandDisp && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
            brandDisp = NS.canonicalizeBrandDisplayCandidate(brandDisp);
          }
          if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
          if (brandDisp && typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(brandDisp)) {
            const fallbackCn = (pkD && pkD.cn && pkD.cn[0]) || (productBrand && productBrand.cnBrand) || "";
            brandDisp = typeof NS.canonicalizeBrandDisplayCandidate === "function"
              ? NS.canonicalizeBrandDisplayCandidate(fallbackCn)
              : fallbackCn;
          }
          if ((!brandDisp || debrisHost(brandDisp)) && pkD && pkD.cn && pkD.cn[0]) {
            brandDisp = typeof NS.canonicalizeBrandDisplayCandidate === "function"
              ? NS.canonicalizeBrandDisplayCandidate(pkD.cn[0])
              : pkD.cn[0];
          }
        }
      } catch { /* keep brandDisp */ }
      // domainRel.brand 仅当已在等权 cn/latin 列表中才补（避免 bestTok=Reserved/Iehuorong 进 UI）
      if ((!brandDisp || debrisHost(brandDisp)) && domainRel && domainRel.brand
        && !debrisHost(domainRel.brand)
        && !(typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(domainRel.brand))) {
        try {
          const b0 = typeof NS.canonicalizeBrandDisplayCandidate === "function"
            ? NS.canonicalizeBrandDisplayCandidate(domainRel.brand)
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
        const fallbackCn = (productBrand && productBrand.cnBrand) || "";
        brandDisp = typeof NS.canonicalizeBrandDisplayCandidate === "function"
          ? NS.canonicalizeBrandDisplayCandidate(fallbackCn)
          : fallbackCn;
      }
      // 品类结构 squat：升级 hostMatch；展示名用页内最佳抽词
      try {
        const labMus = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        const apexMus = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(labMus) : labMus) || labMus;
        const apexLeftMus = (String(apexMus).split(".")[0] || "").replace(/[^a-z0-9]/g, "");
        const pageCn = brandDisp || (domainRel && domainRel.brand) || "";
        const fnCat = NS.detectChineseProductCategoryHostSquat || NS.detectChineseMusicBrandDomainSquat;
        const catSquat = typeof fnCat === "function"
          ? (fnCat(apexLeftMus, pageCn) || fnCat(labMus.split(".")[0] || "", pageCn))
          : null;
        if (catSquat && (titleHostCorr.hostMatch === "none" || titleHostCorr.hostMatch === "partial"
          || titleHostCorr.hostMatch === "padded")) {
          titleHostCorr.hostMatch = catSquat.hostMatch || "typo";
        }
        // 用检测时的中文宣称回填展示名
        if (catSquat && catSquat.chineseSuffix
          && (!brandDisp || brandDisp.length < 2
            || (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brandDisp)))) {
          if (typeof NS.pickBestSpoofDisplayBrand === "function") {
            brandDisp = NS.pickBestSpoofDisplayBrand(catSquat.chineseSuffix) || brandDisp;
          } else if (catSquat.chineseSuffix.length >= 2) {
            brandDisp = catSquat.chineseSuffix;
          }
        }
      } catch { /* ignore */ }
      if ((!brandDisp || brandDisp.length < 2) && typeof NS.pickBestSpoofDisplayBrand === "function") {
        brandDisp = NS.pickBestSpoofDisplayBrand((domainRel && domainRel.brand) || "") || brandDisp;
      }
      if (brandDisp && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        brandDisp = NS.canonicalizeBrandDisplayCandidate(brandDisp);
      }
      const isGenericBrand = (t) => {
        try {
          if (!t) return true;
          // 拉丁停用；中文弱词（内部已优先 pinyin 主机对齐放行钉钉/火绒）
          if (/^[A-Za-z]/.test(String(t)) && NS.BRAND_TOKEN_STOP_RE
            && NS.BRAND_TOKEN_STOP_RE.test(String(t).toLowerCase().replace(/[^a-z0-9]/g, ""))) return true;
          if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)) return true;
          // 纯品类不可作仿冒展示名
          if (/^(?:音乐|安全|杀毒|卫士|软件|下载|官网|官方)$/.test(String(t).trim())) return true;
          return false;
        } catch { return false; }
      };
      if (!brandDisp || isGenericBrand(brandDisp) || debrisHost(brandDisp)) {
        // 再试 title 表面（避免误杀后变中性空壳）；禁止再选中主机碎片
        if (typeof NS.pickBestSpoofDisplayBrand === "function") {
          brandDisp = NS.pickBestSpoofDisplayBrand("") || "";
        }
      }
      if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
      if (brandDisp && isGenericBrand(brandDisp)) brandDisp = "";
      // 夹带域：主机剥核 / 中文桥（火绒 @ huorongr）
      if ((!brandDisp || brandDisp.length < 2)
        && (titleHostCorr.hostMatch === "padded" || titleHostCorr.hostMatch === "typo"
          || titleHostCorr.hostMatch === "hyphen")) {
        try {
          if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
            brandDisp = NS.formatSpoofDisplayFromHostCore(location.hostname) || "";
          }
        } catch { brandDisp = ""; }
        if (brandDisp && debrisHost(brandDisp)) brandDisp = "";
      }
      // 中文已锁定 / 有候选；无候选且未锁定才失败
      try {
        const locked = typeof NS.getLockedSpoofDisplayBrand === "function"
          ? NS.getLockedSpoofDisplayBrand() : "";
        if (locked) brandDisp = locked;
      } catch { /* ignore */ }
      if (brandDisp && (isGenericBrand(brandDisp) || debrisHost(brandDisp))) brandDisp = "";
      if (!brandDisp && !(state._spoofBrandChineseLocked && state.spoofBrand)) {
        // 仍可用主机剥核候选
        try {
          if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
            brandDisp = NS.formatSpoofDisplayFromHostCore(location.hostname) || "";
          }
        } catch { brandDisp = ""; }
        if (brandDisp && (isGenericBrand(brandDisp) || debrisHost(brandDisp))) brandDisp = "";
      }
      if (!brandDisp && !state.spoofBrand) {
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      const matchHint = titleHostCorr.hostMatch === "typo" ? "拼写仿冒"
        : titleHostCorr.hostMatch === "padded" ? "域名夹带品牌前缀/后缀"
          : titleHostCorr.hostMatch === "hyphen" ? "域名用连字符拆分品牌名"
            : titleHostCorr.hostMatch === "none" ? "域名与品牌无关"
              : "关联不严谨";

      if (typeof NS.pageHasStrongTrustedIdentity === "function"
        && NS.pageHasStrongTrustedIdentity()
        && !state._seoCloakKitDetected && !state._fakeSpaDetected
        && titleHostCorr.hostMatch === "padded") {
        state._pendingSoftBrandSpoof = false;
        return false;
      }

      const lockHardNow = titleHostCorr.hostMatch !== "padded"
        || !!(landingShell && (landingShell.hardShell || landingShell.hasHub));
      let committedBrand = "";
      if (typeof NS.commitBrandSpoofPresentation === "function") {
        committedBrand = NS.commitBrandSpoofPresentation({
          brand: brandDisp || state.spoofBrand || "",
          host: location.hostname,
          matchHint,
          lockHard: lockHardNow
        });
      }
      if (!committedBrand) return false;
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
        const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
          ? NS.evaluateMatureLegitimateSiteProfile() : null;
        if (matureProfile && matureProfile.trusted) {
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
      // button.btn-download + GLOBAL_DOWNLOAD_URL 模板也算有目标
      if (document.querySelector(
        "a[href*='download.html'], a.download-btn[href], a.btn-download[href], "
        + "a.btn-header[href], a.btn-primary[href*='down'], a.btn-lg[href*='down'], "
        + "#mainDownloadBtn[href], a.download-uri[href], "
        + "button.btn-download, button.download-btn, button[class*='btn-download']"
      )) return true;
      try {
        if (typeof NS.readPageDeclaredDownloadGlobals === "function"
          && (NS.readPageDeclaredDownloadGlobals() || []).length > 0) return true;
      } catch { /* ignore */ }
      return false;
    } catch { return false; }
  };

  NS.collectProactiveDownloadTargets = function () {
    const cache = NS.caches || {};
    const urlKey = String(location.href || "");
    const now = Date.now();
    if (cache._proactiveTargets && cache._proactiveTargetsUrl === urlKey
      && now - Number(cache._proactiveTargetsAt || 0) < 800) {
      return cache._proactiveTargets;
    }
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
      // 导航「下载」→ /download.html 必须收入（汽水仿冒首页 nav-menu）
      try {
        document.querySelectorAll(
          "nav a[href], .nav a[href], .nav-menu a[href], header a[href], .navbar a[href]"
        ).forEach((el) => {
          const h = (el.getAttribute("href") || "").trim();
          if (!h || /^(javascript:|#)/i.test(h)) return;
          if (/download\.html|down\.html|install\.html|(?:^|\/)download(?:\/|\.html?|$)/i.test(h)) {
            pushL(h, el);
          }
        });
      } catch { /* ignore */ }
      // 禁止裸 a[href]：大页上构建 NodeList 本身就会卡死主线程
      // 含 button.btn-download（汽水仿冒：无 href，靠 onclick + GLOBAL_DOWNLOAD_URL）
      const nodes = document.querySelectorAll(
        "a[href*='download.html'], a[href*='Download.html'], a[data-href*='download'], "
        + "a.download-btn, a.btn-download, "
        + ".download-btn a, .btn-download, button.btn-download, button.download-btn, "
        + ".btn-header, a.btn-primary, a.btn-lg, a.btn-header, "
        + "#mainDownloadBtn, a.download-uri, [class*='btn-download'], [class*='download-btn'], "
        + "button[class*='download'], a[href*='down.html'], a[href*='install.html']"
      );
      const lim = Math.min(nodes.length, 48);
      for (let i = 0; i < lim; i++) {
        const el = nodes[i];
        let href = (typeof NS.getElementDownloadHref === "function" ? NS.getElementDownloadHref(el) : "")
          || el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-url") || "";
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        const cls = String(el.className || "");
        const intent = (NS.DOWNLOAD_TEXT && NS.DOWNLOAD_TEXT.test(text))
          || /立即下载|免费下载|官方下载|客户端下载|下载中心|前往下载|立即使用|个人版|企业版|Windows|macOS|Android|iOS|安装包|下载\s*(?:iOS|Android|Windows|macOS|APK)/i.test(text)
          || /download|btn-download|platform|btn-header|btn-primary|btn-lg/i.test(cls);
        // 无 href 的下载按钮：绑定页面全局下载链（GLOBAL_DOWNLOAD_URL）
        if ((!href || /^(javascript:|#)$/i.test(String(href).trim())) && intent
          && typeof NS.readPageDeclaredDownloadGlobals === "function") {
          const g = NS.readPageDeclaredDownloadGlobals();
          if (g && g[0]) href = g[0];
        }
        if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(String(href).trim())) continue;
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
            // 多平台按钮共用站点首页/根路径（GLOBAL_DOWNLOAD_URL=https://site/）→ 仍要 probe/landing
            const pathBare = (u.pathname || "/").replace(/\/+$/, "") || "/";
            if (u.origin !== location.origin || /\.(?:php|asp|aspx)$/i.test(u.pathname)) pushP(href, el);
            else if (/\.(?:html?)$/i.test(u.pathname) && /down|install|client|soft|get|download/i.test(u.pathname + u.href)) pushL(href, el);
            else if (/download/i.test(href)) pushL(href, el);
            else if (pathBare === "/" || pathBare === "" || pathBare.length <= 1) pushL(href, el);
            else pushP(href, el);
          } catch { /* ignore */ }
        }
      }
      // 页面声明了全局下载 URL、但按钮选择器未挂上：仍收一条探测目标
      if (!landing.length && !probe.length && typeof NS.readPageDeclaredDownloadGlobals === "function") {
        const globals = NS.readPageDeclaredDownloadGlobals();
        for (const g of (globals || []).slice(0, 3)) {
          try {
            if (NS.isPackageFileUrl && NS.isPackageFileUrl(g)) continue;
            const u = new URL(g, location.href);
            if (u.origin === location.origin) pushL(g, null);
            else pushP(g, null);
          } catch { /* ignore */ }
        }
      }
    } catch { /* ignore */ }
    const out = { landing: landing.slice(0, 10), probe: probe.slice(0, 6) };
    cache._proactiveTargets = out;
    cache._proactiveTargetsUrl = urlKey;
    cache._proactiveTargetsAt = now;
    return out;
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
        || (NS.pageHasStrongTrustedIdentity && NS.pageHasStrongTrustedIdentity());
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
            // brandToken 可能只是从 padded 域名剥出的核，只用于判定 mismatch；
            // 只有已通过页面身份共识的 rel2.brand 才能进入展示状态。
            parentBrand = parentBrand || rel2.brand || "";
          }
        }
      } catch { /* ignore */ }
      if (parentBrand && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        parentBrand = NS.canonicalizeBrandDisplayCandidate(parentBrand);
      }

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
        // fetch 期间 ICP/WHOIS/OV 可能刚完成。决策时必须重新读取身份，禁止复用
        // 请求前的 trustedSoft，把已解锁的官网再次按旧结果上锁。
        const trustedAtDecision = (NS.shouldNeverArmProtection && NS.shouldNeverArmProtection())
          || (NS.looksLikeMatureOfficialPortal && NS.looksLikeMatureOfficialPortal())
          || (NS.pageHasStrongTrustedIdentity && NS.pageHasStrongTrustedIdentity());
        const officialProductSubdomain = typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
          && NS.hostLooksLikeOfficialProductSubdomain(location.hostname);
        // 可信 + 域名相关：不 arm 仿冒
        if (isBrand && (trustedAtDecision || officialProductSubdomain)) {
          try {
            if (trustedAtDecision && typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
              NS.forceLiftSoftProtectionForTrustedPortal("proactive-probe-fresh-trusted");
            }
          } catch { /* ignore */ }
          NS.silverfoxLog && NS.silverfoxLog("proactive-probe", "hit-but-trusted-related");
        } else {
          if (isBrand && parentBrand && !state.spoofBrand) {
            try { state.spoofBrand = parentBrand; } catch { /* ignore */ }
          }
          const showBrand = state.spoofBrand || parentBrand || "";
          const reason = landHit.analysis.brandSpoofLanding || parentMismatch
            ? (showBrand
              ? `主动探测：首页下载入口指向仿冒落地页（${showBrand} 与域名不匹配）`
              : "主动探测：首页下载入口指向仿冒落地页（页面品牌与域名不匹配）")
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
