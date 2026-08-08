/**
 * 下载保护 guard：arm/lift、toast/overlay、风险报告、元素禁用/恢复。
 */
;(function (NS) {
  "use strict";

  const { PACKAGE_EXT, PACKAGE_NAME } = NS;

  NS.dismissPageToast = function () {
    try {
      const box = document.getElementById("silverfox-threat-toast");
      if (box) { try { clearTimeout(box.__silverfoxHideTimer); } catch { /* ignore */ } box.remove(); }
      NS.caches.pageToastLastAt.clear();
      try { NS.caches.sentNoticeKeys.clear(); NS.caches.sentNoticeLastAt.clear(); } catch { /* ignore */ }
    } catch { /* ignore */ }
  };

  NS.showPageToast = function (title, message, opts = {}) {
    try {
      // 子 frame 的 fixed Toast 可能落在隐藏/极小 iframe；经后台安全转发到顶层 frame。
      try {
        if (typeof NS.isTopFrame === "function" && !NS.isTopFrame() && chrome?.runtime?.id) {
          chrome.runtime.sendMessage({
            type: "relay-page-threat-toast",
            title: String(title || "已拦截可疑下载文件"),
            message: String(message || "可疑下载已被拦截"),
            force: opts.force !== false
          }, () => { void chrome.runtime.lastError; });
          return;
        }
      } catch { /* fallback to local frame */ }
      const c = NS.caches;
      const key = `${title}::${message}`;
      const now = Date.now();
      const last = c.pageToastLastAt.get(key) || 0;
      if (!opts.force && last && now - last < 1800) return;
      c.pageToastLastAt.set(key, now);
      const id = "silverfox-threat-toast";
      let box = document.getElementById(id);
      if (!box) {
        box = document.createElement("div");
        box.id = id;
        box.setAttribute("role", "alert");
        Object.assign(box.style, {
          position: "fixed", top: "16px", right: "16px", zIndex: "2147483646", maxWidth: "360px",
          padding: "12px 14px 12px 12px", background: "linear-gradient(135deg, #1d4ed8 0%, #2563eb 55%, #3b82f6 100%)",
          color: "#fff", font: "13px/1.45 system-ui,Segoe UI,sans-serif", borderRadius: "10px",
          boxShadow: "0 8px 28px rgba(37, 99, 235, 0.35)", pointerEvents: "auto", display: "flex",
          gap: "10px", alignItems: "flex-start", opacity: "1", transition: "opacity 0.2s ease"
        });
        document.documentElement.appendChild(box);
      }
      box.style.opacity = "0";
      box.textContent = "";
      // 与扩展本地图标同步（48px），避免 emoji/手绘图标不一致
      const icon = document.createElement("img");
      try { icon.src = chrome.runtime.getURL("icons/icon48.png"); } catch { icon.alt = ""; }
      icon.alt = "";
      icon.width = 28;
      icon.height = 28;
      Object.assign(icon.style, {
        width: "28px", height: "28px", flexShrink: "0", borderRadius: "6px",
        objectFit: "contain", marginTop: "1px", background: "rgba(255,255,255,0.15)"
      });
      const body = document.createElement("div"); body.style.flex = "1";
      const t = document.createElement("div"); t.style.fontWeight = "700"; t.style.marginBottom = "4px"; t.textContent = title;
      const m = document.createElement("div"); m.style.opacity = "0.95"; m.textContent = message;
      body.appendChild(t); body.appendChild(m);
      box.appendChild(icon); box.appendChild(body);
      try { void box.offsetWidth; box.style.opacity = "1"; } catch { /* ignore */ }
      clearTimeout(box.__silverfoxHideTimer);
      box.__silverfoxHideTimer = setTimeout(() => {
        try { box.style.opacity = "0"; setTimeout(() => { try { box.remove(); } catch { /* ignore */ } }, 220); }
        catch { try { box.remove(); } catch { /* ignore */ } }
      }, 6500);
    } catch { /* ignore */ }
  };

  NS.showGuardOverlay = function (href, opts = {}) {
    const state = NS.state;
    const targetLabel = NS.formatPackageLabel(href);
    const title = opts.title || "已拦截可疑下载文件";
    const message = opts.message || targetLabel;
    const key = `${title}::${message}`;
    const explicitUserAction = !!opts.userAction;
    const notifyRequested = explicitUserAction || !!opts.forceNotify;
    const isIdentityNotice = opts.guardKind === "brand-spoof" || opts.guardKind === "nav-trap" || /仿冒|官网|域名|跳转|搜索引擎/i.test(`${title} ${message}`);
    try {
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return false;
      if (!isIdentityNotice) {
        const fn = href ? NS.getFilenameFromUrl(href) : "";
        const msgFn = NS.normalizeFileName(String(message || "").split(/[\s/\\]/).pop() || "");
        const isClearProductFile = (name) => {
          if (!name || !PACKAGE_NAME.test(name)) return false;
          return NS.isClearProductOrAndroidPackage(name) || NS.looksLikeStrongProductInstallerName(name) || NS.isBenignShortInstallerName(name) || (NS.looksLikeProductPackageName(name) && !NS.looksLikeOversimplifiedBrandInstallerName(name));
        };
        if (isClearProductFile(fn) || isClearProductFile(msgFn)) return false;
      }
    } catch { /* fall through */ }
    const c = NS.caches;
    const now = Date.now();
    const lastSys = c.sentNoticeLastAt.get(key) || 0;
    const sameIdentityNotice = isIdentityNotice
      && state._lastGuardNoticeKind === (opts.guardKind || "")
      && state._lastGuardNoticeKey === key;
    // brand-spoof 可覆盖 site-identity；拉丁→中文可升格；中文锁定后禁止再发拉丁版
    const titleMsg = `${title} ${message}`;
    const isLatinBrandNotice = opts.guardKind === "brand-spoof"
      && /仿冒「[A-Za-z][A-Za-z0-9.\-]{2,24}」/.test(titleMsg)
      && !/仿冒「[一-鿿]{2,}/.test(titleMsg);
    if (isLatinBrandNotice && state._spoofBrandChineseLocked
      && /[一-鿿]{2,}/.test(String(state.spoofBrand || ""))) {
      // 钉钉已锁定：吞掉 Dingding 通知
      return false;
    }
    const brandUpgradeOverIdentity = opts.guardKind === "brand-spoof"
      && notifyRequested
      && !!state._lastGuardNoticeKind
      && (state._lastGuardNoticeKind !== "brand-spoof"
        || (state._lastGuardNoticeKey && state._lastGuardNoticeKey !== key))
      && !isLatinBrandNotice; // 拉丁版不得靠「升级」抢回
    // 仿冒身份类：更易再次发系统通知（2.5s 内去重即可）
    const sysGap = isIdentityNotice ? 2500 : 8000;
    const canSys = !c.sentNoticeKeys.has(key)
      || (explicitUserAction && now - lastSys >= sysGap)
      || brandUpgradeOverIdentity
      || (!isIdentityNotice && opts.forceNotify && now - lastSys >= 3000);
    if (canSys) {
      c.sentNoticeKeys.add(key);
      c.sentNoticeLastAt.set(key, now);
      const noticePayload = {
        type: "threat-notice",
        title,
        message,
        url: location.href,
        timestamp: now,
        force: !!(notifyRequested || isIdentityNotice || brandUpgradeOverIdentity),
        guardKind: opts.guardKind || ""
      };
      try {
        if (chrome?.runtime?.id) {
          chrome.runtime.sendMessage(noticePayload, () => {
            if (chrome.runtime.lastError) {
              const msg = chrome.runtime.lastError.message || "";
              if (!/message port closed|Extension context invalidated/i.test(msg)) console.warn("threat-notice send failed", msg);
            }
          });
        }
      } catch (err) {
        const msg = err && err.message ? err.message : String(err);
        if (!/Extension context invalidated/i.test(msg)) console.warn("showGuardOverlay failed", msg);
      }
    }
    const canToast = !sameIdentityNotice
      || brandUpgradeOverIdentity
      || (explicitUserAction && now - lastSys >= sysGap);
    if (opts.toast !== false && canToast) {
      NS.showPageToast(title, message, {
        force: notifyRequested || isIdentityNotice || brandUpgradeOverIdentity
      });
    }
    state._lastGuardNoticeKind = opts.guardKind || "";
    state._lastGuardNoticeKey = key;
    if (opts.guardKind === "brand-spoof") {
      state._brandSpoofNoticeSent = true;
      state._brandSpoofNoticeKey = `${title}::${message}`;
    }
    return true;
  };

  /**
   * 用完整身份字段纠正早期写入 spoofBrand 的临时候选。
   * 排名依据仍是 collectPrimaryBrandKeywords 的集体票；这里只比较候选证据强度，
   * 不从正文、资源文件或主机旁路重新发明品牌。
   */
  NS.reconcileActiveSpoofBrand = function ({ force = false } = {}) {
    try {
      const state = NS.state;
      // 中文锁定：钉钉等不得被 re-elect 成 Dingding
      try {
        const locked = typeof NS.getLockedSpoofDisplayBrand === "function"
          ? NS.getLockedSpoofDisplayBrand() : "";
        if (locked) return locked;
      } catch { /* ignore */ }
      let current = String(state.spoofBrand || "").trim();
      if (current && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        current = NS.canonicalizeBrandDisplayCandidate(current);
        if (!current && typeof NS.setSpoofDisplayBrand === "function") {
          NS.setSpoofDisplayBrand("", { allowClear: true, forceUnlock: true });
        } else if (!current) state.spoofBrand = "";
      }
      if (current && /[一-鿿]{2,}/.test(current)) {
        state._spoofBrandChineseLocked = true;
        return current;
      }
      const active = !!(state._brandSpoofPortalDetected || current
        || (state.details || []).some((d) => /仿冒品牌官网/i.test(d.name || "")));
      if (!active || typeof NS.collectPrimaryBrandKeywords !== "function") return current;
      const ready = typeof document === "undefined"
        || document.readyState !== "loading"
        || !!state._analysisDone;
      if (!ready && !force) return current;

      const now = Date.now();
      if (!force && now - Number(state._spoofBrandReconciledAt || 0) < 750) return current;
      state._spoofBrandReconciledAt = now;
      // document_start 可能缓存未完成 DOM；最终身份校正必须重新采样。
      if (NS.caches) {
        NS.caches._primaryKw = null;
        NS.caches._primaryKwAt = 0;
        NS.caches._primaryKwUrl = "";
      }
      const pk = NS.collectPrimaryBrandKeywords();
      let hostAlignedLatin = "";
      try {
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          hostAlignedLatin = String(NS.pickHostAlignedLatinBrandFromPage() || "").trim();
          if (hostAlignedLatin && typeof NS.isForbiddenSpoofDisplayBrand === "function"
            && NS.isForbiddenSpoofDisplayBrand(hostAlignedLatin)) hostAlignedLatin = "";
        }
      } catch { hostAlignedLatin = ""; }
      let candidate = hostAlignedLatin || String((pk && pk.display) || "").trim();
      if (candidate && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        candidate = NS.canonicalizeBrandDisplayCandidate(candidate);
      }
      // 拒绝域名自指展示（HuorongLab @ huorong-lab）
      try {
        if (candidate && typeof NS.isHostShapedCompoundBrandToken === "function"
          && NS.isHostShapedCompoundBrandToken(candidate)) {
          candidate = "";
        }
      } catch { /* ignore */ }
      // display 空/弱/纯拉丁拼音核时：从 title / pinyin 对齐补全（Dingding→钉钉）
      const isPureLatinBrand = (t) => /^[A-Za-z][A-Za-z0-9]{2,24}$/.test(String(t || "").trim());
      const isPureCnBrand = (t) => /^[一-鿿]{2,8}$/.test(String(t || "").trim());
      if ((!candidate || (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(candidate))
          || (isPureLatinBrand(candidate) && !/[一-鿿]/.test(candidate)))
        && typeof NS.pickBestSpoofDisplayBrand === "function") {
        const picked = NS.pickBestSpoofDisplayBrand(current || candidate || "");
        if (picked) candidate = picked;
      }
      // 主机剥核 + pinyin-pro：拉丁核 dingding ↔ 页内「钉钉」
      try {
        if (!hostAlignedLatin
          && (!candidate || isPureLatinBrand(candidate) || !/[一-鿿]/.test(candidate))
          && typeof NS.pickChineseBrandMatchingLatinCore === "function") {
          let core = (typeof NS.resolveHostBrandCore === "function" ? NS.resolveHostBrandCore() : "")
            || (typeof NS.inferMarketingPaddedBrandCore === "function"
              ? NS.inferMarketingPaddedBrandCore((location.hostname || "").replace(/^www\./i, "").split(".")[0] || "")
              : "");
          core = String(core || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          // 当前展示即拉丁核时，直接用它做拼音对齐（Dingding）
          const curLat = String(current || candidate || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          if (curLat.length >= 4 && isPureLatinBrand(current || candidate)) {
            if (!core || core.length < 4) core = curLat;
          }
          if (core) {
            const cn = NS.pickChineseBrandMatchingLatinCore(core);
            if (cn && /[一-鿿]{2,}/.test(cn)) candidate = cn;
          }
        }
      } catch { /* ignore */ }
      if (!candidate) return current;
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(candidate)) return current;
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(candidate)) return current;

      const keyOf = (raw) => String(raw || "").toLowerCase().replace(/[^a-z0-9一-鿿]/gi, "");
      const findEvidence = (raw) => {
        const key = keyOf(raw);
        if (!key || !pk || !pk.scores) return { sources: [], votes: 0 };
        for (const [name, info] of Object.entries(pk.scores)) {
          if (keyOf(name) !== key) continue;
          return {
            sources: Array.isArray(info && info.sources) ? info.sources : [],
            votes: Number((info && (info.votes || info.score)) || 0)
          };
        }
        return { sources: [], votes: 0 };
      };
      const rankEvidence = (ev) => {
        const primary = (ev.sources || []).filter((s) => /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema|domain)$/.test(s)).length;
        return { primary, rank: primary * 100 + (ev.votes || ev.sources.length) * 10 };
      };

      // ★ 拉丁拼音核 → 页内中文（Dingding→钉钉）：不走票数门控，拼音全等即升格
      const pinyinUpgradeLatinToCn = (() => {
        try {
          if (!isPureLatinBrand(current) || !isPureCnBrand(candidate)) return false;
          const lat = String(current).toLowerCase().replace(/[^a-z0-9]/g, "");
          const py = typeof NS.chineseToPinyinFlat === "function"
            ? NS.chineseToPinyinFlat(candidate)
            : (typeof NS.brandPinyin === "function" ? NS.brandPinyin(candidate) : "");
          if (!py || !lat) return false;
          return py === lat || py.startsWith(lat) || lat.startsWith(py);
        } catch { return false; }
      })();
      if (pinyinUpgradeLatinToCn) {
        if (typeof NS.setSpoofDisplayBrand === "function") {
          NS.setSpoofDisplayBrand(candidate, { lockChinese: true, forceChinese: true });
        } else {
          state.spoofBrand = candidate;
          state._spoofBrandChineseLocked = true;
        }
        try {
          (state.details || []).forEach((d) => {
            if (!d || !/仿冒品牌官网/i.test(d.name || "") || !d.reason || !current) return;
            d.reason = String(d.reason).split(`「${current}」`).join(`「${candidate}」`);
          });
        } catch { /* ignore */ }
        // 不在这里弹 toast，避免与 upgrade 抢；由 upgrade/ensure 统一
        return String(state.spoofBrand || candidate);
      }

      // 禁止用纯拉丁候选覆盖当前中文（即使票数更高）
      if (current && /[一-鿿]{2,}/.test(current)
        && candidate && !/[一-鿿]/.test(candidate)) {
        return current;
      }

      const candidateEvidence = findEvidence(candidate);
      const candidateRank = rankEvidence(candidateEvidence);
      // 至少一个主身份字段，或三个独立字段共识；辅助副标不能单独纠正品牌。
      if (candidateRank.primary < 1 && candidateEvidence.sources.length < 3) return current;
      const currentRank = rankEvidence(findEvidence(current));
      if (current && keyOf(current) === keyOf(candidate)) return current;
      if (current && currentRank.rank >= candidateRank.rank) return current;

      if (typeof NS.setSpoofDisplayBrand === "function") {
        NS.setSpoofDisplayBrand(candidate, {
          lockChinese: /[一-鿿]{2,}/.test(candidate)
        });
      } else {
        state.spoofBrand = candidate;
      }
      try {
        (state.details || []).forEach((d) => {
          if (!d || !/仿冒品牌官网/i.test(d.name || "") || !d.reason || !current) return;
          d.reason = String(d.reason).split(`「${current}」`).join(`「${candidate}」`);
        });
      } catch { /* ignore */ }
      return String(state.spoofBrand || candidate);
    } catch {
      return String((NS.state && NS.state.spoofBrand) || "").trim();
    }
  };

  /**
   * 报告已确认品牌仿冒时补发一次品牌通知。
   * 防止“信号已入报告，但 guard 先被其他身份规则占用”导致 Popup 有结论、页面不弹。
   */
  NS.ensureBrandSpoofNotice = function (trustedPortal = false) {
    try {
      const state = NS.state;
      // 任何补发通知路径也必须服从官网身份核验门槛，防止扫描器或报告刷新
      // 把尚未定案的品牌候选提前展示给用户。
      if (!(typeof NS.isBrandSpoofIdentityVerificationSettled === "function"
        && NS.isBrandSpoofIdentityVerificationSettled())) {
        state._pendingSoftBrandSpoof = true;
        return false;
      }
      // 未确认可展示软仿冒前：不弹（有效 ICP / 强信任 / 情报未完）
      if (typeof NS.canPresentSoftBrandSpoofNotice === "function"
        && !NS.canPresentSoftBrandSpoofNotice()) {
        state._pendingSoftBrandSpoof = true;
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "ensure-notice-suppressed-until-official-check");
        return false;
      }
      const active = !trustedPortal && !!(state._brandSpoofPortalDetected || state.spoofBrand
        || (state.details || []).some((d) => /仿冒品牌官网/i.test(d.name || "")));
      if (!active) return false;
      // 定稿中：禁止用临时/空品牌抢弹
      if (state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented) {
        return false;
      }
      // 优先锁定中文；勿用 re-elect 把钉钉改回 Dingding 再弹
      const forbid = (t) => typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(t);
      let brand = "";
      try {
        brand = typeof NS.getLockedSpoofDisplayBrand === "function"
          ? NS.getLockedSpoofDisplayBrand() : "";
      } catch { /* ignore */ }
      if (forbid(brand)) brand = "";
      if (!brand) {
        brand = String(state.spoofBrand || "").trim();
        if (forbid(brand)) brand = "";
      }
      if (!brand) {
        try {
          brand = String(NS.reconcileActiveSpoofBrand({ force: true }) || "").trim();
          if (forbid(brand)) brand = "";
        } catch { /* ignore */ }
      }
      // 仍无品牌：仅允许明确营销结构剥出的主机核兜底；整段标签不能盲删末字。
      if (!brand) {
        try {
          if (typeof NS.extractChineseBrandFromPageTitle === "function") {
            brand = String(NS.extractChineseBrandFromPageTitle() || "").trim();
            if (forbid(brand)) brand = "";
          }
        } catch { /* ignore */ }
      }
      if (!brand) {
        try {
          let core = typeof NS.resolveHostBrandCore === "function"
            ? String(NS.resolveHostBrandCore() || "").toLowerCase().replace(/[^a-z0-9]/g, "")
            : "";
          const lab = String(location.hostname || "").replace(/^www\./i, "").split(".")[0] || "";
          const labFlat = lab.replace(/[^a-z0-9]/g, "");
          if (core === labFlat) core = "";
          if ((!core || core.length < 4) && typeof NS.inferMarketingPaddedBrandCore === "function") {
            core = String(NS.inferMarketingPaddedBrandCore(lab) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          }
          if (core && core.length >= 4 && core !== labFlat) {
            brand = typeof NS.formatBrandTokenForDisplay === "function"
              ? (NS.formatBrandTokenForDisplay(core) || core)
              : (core.charAt(0).toUpperCase() + core.slice(1));
            if (typeof NS.setSpoofDisplayBrand === "function") {
              NS.setSpoofDisplayBrand(brand);
            } else {
              state.spoofBrand = brand;
            }
          }
        } catch { /* ignore */ }
      }
      // 空品牌：不弹「与页面宣称品牌不匹配」空壳 toast
      if (!brand) {
        NS.silverfoxLog && NS.silverfoxLog("brand-spoof", "notice-skip-empty-brand");
        return false;
      }
      // 若当前通知已是中文锁定版，禁止再发拉丁版
      if (state._spoofBrandChineseLocked && /[一-鿿]{2,}/.test(brand)
        && state._brandSpoofNoticeSent
        && /仿冒「[一-鿿]{2,8}」/.test(String(state._brandSpoofNoticeKey || ""))) {
        return false;
      }
      const title = `已识别仿冒「${brand}」官网`;
      const message = `页面标题/正文品牌「${brand}」与当前域名不匹配，疑似仿冒官网。`;
      const key = `${title}::${message}`;
      if (state._brandSpoofNoticeSent && state._brandSpoofNoticeKey === key
        && state._lastGuardNoticeKind === "brand-spoof"
        && state._lastGuardNoticeKey === key) return false;
      // 已发过中文版后，忽略纯拉丁 brand 通知
      if (state._brandSpoofNoticeSent
        && /仿冒「[一-鿿]{2,8}」/.test(String(state._brandSpoofNoticeKey || ""))
        && brand && /^[A-Za-z]/.test(brand) && !/[一-鿿]/.test(brand)) {
        return false;
      }
      const shown = NS.showGuardOverlay("", {
        title,
        message,
        toast: true,
        forceNotify: true,
        guardKind: "brand-spoof"
      }) === true;
      // showGuardOverlay 在正常运行时会记录这组状态；这里再写一次，保证被测试桩、
      // 兼容层或定制 UI 包装后，品牌通知仍能正确去重并保持最高展示优先级。
      if (shown) {
        state._brandSpoofNoticeSent = true;
        state._brandSpoofNoticeKey = key;
        state._lastGuardNoticeKind = "brand-spoof";
        state._lastGuardNoticeKey = key;
      }
      return shown;
    } catch {
      return false;
    }
  };

  NS.resolveReportRiskLevel = function ({
    trustedPortal = false,
    remoteDownloadDispatchDetected = false,
    hasPackageThreat = false,
    downloadGuardInstalled = false,
    score = 0,
    signalCount = 0
  } = {}) {
    if (!trustedPortal && (remoteDownloadDispatchDetected || (hasPackageThreat && score >= 24))) return "high";
    // 高分组合必须先于「≥12 分即中度」判断，否则 40 分永远只能落到 medium。
    if (score >= 40 && signalCount >= 3) return "high";
    if (!trustedPortal && (hasPackageThreat || downloadGuardInstalled || (score >= 12 && signalCount >= 2))) return "medium";
    if (score >= 18 && signalCount >= 2) return "medium";
    return "low";
  };

  NS.emitRiskReport = function (force = false) {
    // ★ 仅顶层上报：广告 iframe 的 incomplete 会盖掉主页面结果 → popup 永久「正在分析」
    try {
      if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) return;
    } catch { /* continue */ }
    const state = NS.state;
    const c = NS.caches;
    const now = Date.now();
    // Keep this local to emitRiskReport.  showGuardOverlay has a similarly named
    // value, but function scope means it is not visible here.  A missing local
    // declaration aborts report construction and makes the popup fall back to
    // its empty 0-score state on every site.
    const brandDecisionPending = !!(
      state._brandSpoofPresentationDeferred
      || state._pendingSoftBrandSpoof
      || state._brandElectionAwaitingDom
      || state._brandElectionRetryPending
      || state._analysisCompletionDeferredForBrand
      || (state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented)
    );
    if (brandDecisionPending) {
      state._analysisDone = false;
      state._stickyComplete = false;
      state._stickyCompleteHost = "";
    }
    if (state._analysisDone && !force && now - c.lastReportAt < 2500) return;
    if (!force && now - c.lastReportAt < 600) return;
    c.lastReportAt = now;
    const hostKey = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
    // ★ 同主机粘性 complete：一旦完成，后续 emit 一律 analysisComplete=true
    // （WHOIS/ICP 回调、DOM/CSS 噪声不得把 popup 打回「正在分析」）
    try {
      if (brandDecisionPending) {
        /* 品牌身份链仍在运行：任何 light/perf/sticky 路径都不能强制 complete。 */
      } else if (state._analysisDone) {
        state._stickyCompleteHost = hostKey;
        state._stickyComplete = true;
      } else if (state._stickyComplete && state._stickyCompleteHost === hostKey) {
        const hardKit = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
        if (!hardKit) state._analysisDone = true;
      } else if (state._perfBenign || state._intelLightMode) {
        // light 页即使漏标 done，报告也按 complete 发，避免闪一下再卡住
        state._analysisDone = true;
        state._stickyComplete = true;
        state._stickyCompleteHost = hostKey;
      }
    } catch { /* ignore */ }
    const threatDetails = state.details.filter((d) => (d.weight || 0) > 0);
    const signalCount = threatDetails.length;
    // 身份可信与下载保护是两条轴：备案/成熟度可清软品牌误报，但不能掩盖
    // 已实锤的 SEO、强制下载、乱码包等硬行为。
    const realHardKit = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
    const identityTrusted = (
      (typeof NS.shouldNeverArmProtection === "function" && NS.shouldNeverArmProtection())
      || (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity())
    );
    const brandIdentitySettled = typeof NS.isBrandSpoofIdentityVerificationSettled === "function"
      && NS.isBrandSpoofIdentityVerificationSettled();
    let brandDisplayFinal = brandIdentitySettled
      && (!state._brandSpoofFinalizeScheduled || state._brandSpoofFinalPresented);
    const protectionTrusted = identityTrusted && !realHardKit;

    // ★ 发报告前：回填 spoofBrand。禁止把已升格的中文（钉钉）盖回拉丁拼音核（Dingding）
    try {
      const portal = !!(state._brandSpoofPortalDetected || state.spoofBrand
        || threatDetails.some((d) => /仿冒品牌官网/i.test(d.name || "")));
      if (portal && !identityTrusted && brandDisplayFinal) {
        // 等待 commit 定稿：勿 re-elect 把临时拉丁写进 popup
        if (state._brandSpoofFinalizeScheduled && !state._brandSpoofFinalPresented) {
          /* skip re-elect */
        } else {
        const curBrand = String(state.spoofBrand || "").trim();
        const cnLocked = !!(state._spoofBrandChineseLocked && /[一-鿿]{2,}/.test(curBrand));
        if (cnLocked) {
          // 中文已由 pinyin 升格锁定，只回写详情
          try {
            (state.details || []).forEach((d) => {
              if (!d || !/仿冒品牌官网/i.test(d.name || "")) return;
              if (!d.reason || !d.reason.includes(`「${curBrand}」`)) {
                d.reason = `标题/正文品牌「${curBrand}」与域名 ${location.hostname} 不匹配`;
              }
            });
          } catch { /* ignore */ }
        } else {
          // 失效早期空缓存，强制 re-elect
          if (NS.caches) {
            NS.caches._primaryKw = null;
            NS.caches._primaryKwAt = 0;
            NS.caches._primaryKwUrl = "";
          }
          let elected = "";
          // 英文品牌无需 pinyin：先用页面身份槽候选主动对齐 host。
          // ToDesk ⇄ to-desk/todek/todsk 应在报告序列化前稳定写回。
          try {
            if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
              elected = String(NS.pickHostAlignedLatinBrandFromPage(location.hostname) || "").trim();
            }
          } catch { elected = ""; }
          // 优先：拼音库已就绪时立刻 Dingding→钉钉
          try {
            if (!elected && typeof NS.upgradeSpoofBrandLatinToChinese === "function"
              && curBrand && /^[A-Za-z][A-Za-z0-9]{2,24}$/.test(curBrand)) {
              const up = NS.upgradeSpoofBrandLatinToChinese({ forceNotify: false });
              if (up && /[一-鿿]{2,}/.test(up)) elected = up;
            }
          } catch { /* ignore */ }
          try {
            if (!elected && typeof NS.reconcileActiveSpoofBrand === "function") {
              elected = String(NS.reconcileActiveSpoofBrand({ force: true }) || "").trim();
            }
          } catch { /* ignore */ }
          if (!elected && typeof NS.pickBestSpoofDisplayBrand === "function") {
            elected = String(NS.pickBestSpoofDisplayBrand(state.spoofBrand || "") || "").trim();
          }
          if (!elected && typeof NS.collectPrimaryBrandKeywords === "function") {
            const pk = NS.collectPrimaryBrandKeywords();
            elected = String((pk && pk.display) || (pk && pk.cn && pk.cn[0]) || "").trim();
            if (elected && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
              elected = NS.canonicalizeBrandDisplayCandidate(elected) || elected;
            }
            if (elected && typeof NS.isWeakChineseBrandToken === "function"
              && NS.isWeakChineseBrandToken(elected)) elected = "";
          }
          if (!elected) {
            for (let di = 0; di < (state.details || []).length; di++) {
              const r = String((state.details[di] && state.details[di].reason) || "");
              const m = r.match(/品牌「([^」]{2,24})」/);
              if (m && m[1] && !/^(?:品牌|音乐|安全)$/.test(m[1])
                && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
                  && NS.isForbiddenSpoofDisplayBrand(m[1]))) {
                elected = m[1];
                break;
              }
            }
          }
          if (!elected && typeof NS.formatSpoofDisplayFromHostCore === "function") {
            try {
              elected = String(NS.formatSpoofDisplayFromHostCore() || "").trim();
            } catch { elected = ""; }
          }
          // 禁止纯拉丁盖掉已有中文；禁止主机碎片
          if (elected && /[一-鿿]/.test(curBrand) && !/[一-鿿]/.test(elected)) {
            elected = curBrand;
          }
          try {
            if (elected && typeof NS.isHostShapedCompoundBrandToken === "function"
              && NS.isHostShapedCompoundBrandToken(elected)) {
              elected = curBrand && !NS.isHostShapedCompoundBrandToken(curBrand) ? curBrand : "";
            }
          } catch { /* ignore */ }
          if (elected && elected.length >= 2
            && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
              && NS.isForbiddenSpoofDisplayBrand(elected))) {
            if (typeof NS.setSpoofDisplayBrand === "function") {
              elected = NS.setSpoofDisplayBrand(elected, {
                forceUnlock: !/[一-鿿]{2,}/.test(elected)
              }) || elected;
            } else {
              state.spoofBrand = elected;
            }
            state._brandSpoofPortalDetected = true;
            if (/[一-鿿]{2,}/.test(elected)) state._spoofBrandChineseLocked = true;
            try {
              (state.details || []).forEach((d) => {
                if (!d || !/仿冒品牌官网/i.test(d.name || "")) return;
                if (!d.reason || !/标题\/正文品牌「/.test(d.reason)) {
                  d.reason = `标题/正文品牌「${elected}」与域名 ${location.hostname} 不匹配（关联不严谨）`;
                } else if (!d.reason.includes(`「${elected}」`)) {
                  d.reason = String(d.reason).replace(/品牌「[^」]*」/, `品牌「${elected}」`);
                }
              });
            } catch { /* ignore */ }
          }
        }
        } // end else (!waiting finalize)
      }
    } catch { /* ignore */ }

    try { NS.ensureBrandSpoofNotice(identityTrusted); } catch { /* ignore */ }
    // ensureBrandSpoofNotice/commit 可能刚在本轮把 ToDesk 等展示名定稿。
    // 报告必须重新读取最终态，不能沿用函数开头的旧布尔值而把 spoofBrand 清空。
    brandDisplayFinal = brandIdentitySettled
      && (!state._brandSpoofFinalizeScheduled || state._brandSpoofFinalPresented);
    // 通知链已经拿到具名品牌时，不能仅因 finalize 的异步标志晚一拍就在完成报告
    // 中清空 spoofBrand；否则通知显示 ToDesk，popup 会退化成“仿冒品牌官网下载站”。
    let reportSpoofBrand = String(state.spoofBrand || "").trim();
    try {
      if (reportSpoofBrand && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        reportSpoofBrand = String(NS.canonicalizeBrandDisplayCandidate(reportSpoofBrand)
          || reportSpoofBrand).trim();
      }
      if (reportSpoofBrand && typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(reportSpoofBrand)) reportSpoofBrand = "";
    } catch { /* keep the already committed display name */ }
    const brandPayloadReady = !!(brandIdentitySettled && reportSpoofBrand
      && (state._brandSpoofPortalDetected || threatDetails.some((d) => /仿冒品牌官网|主动探测仿冒/i.test(d.name || ""))));
    const packageBlockedLive = !protectionTrusted && !!(state.downloadGuardInstalled || state.remoteDownloadDispatchDetected);
    const hasPackageThreat = packageBlockedLive
      || (!protectionTrusted && threatDetails.some((d) => /安装包|下载拦截|仿冒|可疑下载|远程配置|PHP 下载/i.test(d.name || "")));
    const effectiveReportScore = protectionTrusted ? 0 : state.score;
    const riskLevel = NS.resolveReportRiskLevel({
      trustedPortal: protectionTrusted,
      remoteDownloadDispatchDetected: !!state.remoteDownloadDispatchDetected,
      hasPackageThreat,
      downloadGuardInstalled: !!state.downloadGuardInstalled,
      score: effectiveReportScore,
      signalCount: protectionTrusted ? 0 : signalCount
    });
    let score = Math.min(100, effectiveReportScore);
    if (!protectionTrusted && state.downloadGuardInstalled && score < 16) score = Math.max(score, 16);
    if (!protectionTrusted && state.remoteDownloadDispatchDetected && score < 28) score = Math.max(score, 28);
    if (protectionTrusted) score = 0;
    const pkgTargets = protectionTrusted ? [] : (state.protectedTargets || []).filter((t) => {
      try { return NS.isPackageFileUrl(t) || /\.(zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|$)/i.test(String(t)); } catch { return false; }
    }).slice(0, 5);
    const analysisComplete = !brandDecisionPending && !!(state._analysisDone
      || (state._stickyComplete && state._stickyCompleteHost === hostKey));
    const payload = {
      type: "threat-risk", score, riskLevel, analysisComplete,
      details: (() => {
        const hasFakeIcp = (state.details || []).some((d) => /^假冒ICP备案信息/i.test(String(d && d.name || "")));
        const hasDeclared = !!(state.pageDeclaredIcp && String(state.pageDeclaredIcp).trim())
          || !!(state._unverifiedPageIcpClaim)
          || /假冒宣称/i.test(String(state.icpInfo || ""));
        return state.details.filter((d) => {
          if (d.name === "已查询到ICP备案号") return false;
          // 页脚有备案宣称 / 假冒 ICP → 绝不展示「无ICP备案信息」
          if (d.name === "无ICP备案信息" && (hasFakeIcp || hasDeclared)) return false;
          if (d.name === "无ICP备案信息" && (
            NS.looksLikeUltraMatureWhoisDomain()
            || NS.looksLikeLongLivedWhoisDomain()
            || (NS.getWhoisAgeDays() != null && NS.getWhoisAgeDays() >= 365)
            || (typeof NS.hasOrganizationValidatedSsl === "function" && NS.hasOrganizationValidatedSsl())
          )) return false;
          if (/仿冒品牌官网|仿冒站下载拦截|主动探测仿冒/i.test(d.name || "")
            && (identityTrusted || (!brandDisplayFinal && !brandPayloadReady))) return false;
          if (/已启用安装包|非用户手势|跨域跳转/i.test(d.name || "") && protectionTrusted) return false;
          return true;
        }).slice(0, 12);
      })(),
      icpInfo: (typeof NS.formatIcpInfoForReport === "function"
        ? NS.formatIcpInfoForReport(state.icpInfo)
        : (state.icpInfo || "")),
      whoisInfo: state.whoisInfo || "",
      sslInfo: state.sslInfo || null,
      url: location.href,
      downloadGuardInstalled: protectionTrusted ? false : !!state.downloadGuardInstalled,
      packageBlocked: packageBlockedLive,
      protectedTargets: pkgTargets,
      spoofBrand: (identityTrusted || (!brandDisplayFinal && !brandPayloadReady)) ? "" : reportSpoofBrand,
      brandSpoofPortal: (identityTrusted || (!brandDisplayFinal && !brandPayloadReady)) ? false : (!!(state._brandSpoofPortalDetected || reportSpoofBrand) || threatDetails.some((d) => /仿冒品牌官网/i.test(d.name || "")))
    };
    try {
      if (!chrome?.runtime?.id) return;
      chrome.runtime.sendMessage(payload, () => {
        if (chrome.runtime.lastError) {
          const msg = chrome.runtime.lastError.message || "";
          if (!/message port closed|Extension context invalidated/i.test(msg)) console.warn("threat-risk send failed", msg);
        }
      });
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      if (!/Extension context invalidated/i.test(msg)) console.warn("emitRiskReport failed", msg);
    }
  };

  NS.markRemoteDownloadDispatch = function (reason, href, opts = {}) {
    const state = NS.state;
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) return;
    if (href && (
      NS.looksLikeOfficialProductDownloadEndpoint(href) || NS.isClearProductOrAndroidPackage(href) || NS.isAllowlistedProductPackageUrl(href)
      || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(href) || href) || NS.isBenignShortInstallerName(NS.getFilenameFromUrl(href) || href)
      || NS.looksLikeProductPackageName(NS.getFilenameFromUrl(href) || href) || NS.isContentAddressedPackageName(NS.getFilenameFromUrl(href) || href)
      || (NS.isTrustedOfficialDownloadContext() && NS.isSamePageBrandApex(href)) || (NS.looksLikeSafeOfficialContext() && !NS.looksLikeHighRiskBlobPackageUrl(href))
    )) return;
    if (href && !NS.isPackageFileUrl(href) && !NS.looksLikeOpaqueDownloadHopUrl(href)) {
      try {
        const abs = new URL(href, location.href).href;
        const cached = NS.caches.probeCache.get(abs);
        if (!(cached && cached.isDownload)) return;
        if (NS.looksLikeOfficialProductDownloadEndpoint(abs)) return;
      } catch { return; }
    }
    if (!state.remoteDownloadDispatchDetected) { state.remoteDownloadDispatchDetected = true; NS.addSignal("已拦截可疑安装包下载", 20, reason); }
    else NS.addSignal("已拦截可疑下载链接", 8, reason);
    NS.installDownloadGuard(reason, { notify: true, href, forceNotify: !!opts.forceNotify });
    NS.emitRiskReport(true);
  };

  NS.disableOneSuspiciousElement = function (el, href) {
    if (!el) return;
    // 允许重复强化禁用（SPA 重绘后 class 还在但 style 被清掉时）
    try {
      el.dataset.threatDetectorDisabled = "1";
      el.style.setProperty("pointer-events", "none", "important");
      el.style.setProperty("opacity", "0.45", "important");
      el.style.setProperty("filter", "grayscale(0.6)", "important");
      el.style.setProperty("cursor", "not-allowed", "important");
      el.setAttribute("aria-disabled", "true");
      el.setAttribute("title", "已拦截可疑安装包下载");
      if (href && href !== "js-download") el.setAttribute("data-threat-original-href", href);
      else if (href === "js-download" && !el.getAttribute("data-threat-original-href")) el.setAttribute("data-threat-original-href", "js-download");
      if (el.tagName === "A") {
        const cur = el.getAttribute("href");
        if (cur && cur !== "#") el.setAttribute("data-threat-original-href", cur);
        el.removeAttribute("href");
        try { el.href = "javascript:void(0)"; } catch { /* ignore */ }
      }
      if (el.tagName === "BUTTON" || el.tagName === "INPUT") el.disabled = true;
      // 点击兜底：捕获阶段拦截（部分站点用父级委托，仅去 href 不够）
      if (!el.__silverfoxClickBlock) {
        el.__silverfoxClickBlock = true;
        const block = (ev) => {
          try {
            if (!NS.state || !NS.state.downloadGuardInstalled) return;
            ev.preventDefault();
            ev.stopPropagation();
            ev.stopImmediatePropagation();
          } catch { /* ignore */ }
        };
        el.addEventListener("click", block, true);
        el.addEventListener("pointerdown", block, true);
        el.addEventListener("mousedown", block, true);
      }
    } catch { /* ignore */ }
  };

  NS.reEnableOneThreatElement = function (el) {
    if (!el) return;
    try {
      if (el.dataset.threatDetectorDisabled === "1") delete el.dataset.threatDetectorDisabled;
      el.style.removeProperty("pointer-events");
      el.style.removeProperty("opacity");
      el.style.removeProperty("filter");
      el.style.removeProperty("cursor");
      if (el.getAttribute("aria-disabled") === "true") el.removeAttribute("aria-disabled");
      if (el.getAttribute("title") === "已拦截可疑安装包下载") el.removeAttribute("title");
      // disable 时会把 A.href 写成 javascript:void(0) 并另存 data-threat-original-href。
      // 旧逻辑要求 !getAttribute("href") 才还原——void(0) 仍算有 href，导致按钮永久死链。
      const orig = el.getAttribute("data-threat-original-href");
      if (orig && el.tagName === "A" && orig !== "js-download" && !/^javascript:/i.test(orig)) {
        const cur = (el.getAttribute("href") || "").trim();
        if (!cur || cur === "#" || /^javascript:/i.test(cur)) {
          try { el.setAttribute("href", orig); } catch { /* ignore */ }
          try { el.href = orig; } catch { /* ignore */ }
        }
      }
      el.removeAttribute("data-threat-original-href");
      if (el.tagName === "BUTTON" || el.tagName === "INPUT") el.disabled = false;
      try { el.classList && el.classList.remove("silverfox-greyed"); } catch { /* ignore */ }
      try { if (el.dataset) delete el.dataset.silverfoxGreyed; } catch { /* ignore */ }
      try { el.removeAttribute("data-silverfox-greyed"); } catch { /* ignore */ }
    } catch { /* ignore */ }
  };

  NS.reEnableAllThreatDisabledElements = function () {
    try {
      document.querySelectorAll(
        "[data-threat-detector-disabled='1'], [data-silverfox-greyed='1'], a[data-threat-original-href], button[aria-disabled='true'], a[href='javascript:void(0)']"
      ).forEach((el) => NS.reEnableOneThreatElement(el));
      NS.getAllDownloadIntentElements().forEach((el) => NS.reEnableOneThreatElement(el));
      // 兜底：仍挂着 original-href 的锚点强制还原
      document.querySelectorAll("a[data-threat-original-href]").forEach((el) => {
        try {
          const orig = el.getAttribute("data-threat-original-href");
          if (orig && orig !== "js-download" && !/^javascript:/i.test(orig)) {
            el.setAttribute("href", orig);
            try { el.href = orig; } catch { /* ignore */ }
          }
          el.removeAttribute("data-threat-original-href");
          el.style.removeProperty("pointer-events");
          el.style.removeProperty("opacity");
          el.style.removeProperty("filter");
          el.style.removeProperty("cursor");
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
  };

  /**
   * 根据 reason/opts 同步硬套件标志（须在 arm 前调用）。
   * 解决：标志设在 installDownloadGuard 之后 → maybeLift 误判「像官网」立刻抬锁。
   */
  NS.noteHardThreatFromArm = function (reason, opts) {
    try {
      const state = NS.state;
      const o = opts || {};
      const s = `${reason || ""} ${o.message || ""} ${o.title || ""} ${o.guardKind || ""}`;
      // 禁止：任意 lockHard 都标 _fakeBrandShellDetected（会把软品牌仿冒/主动探测
      // 变成 ICP 后仍硬锁，soft.china.com 等正版软件门户永远抬不起）
      // 仅 SEO/乱码/强制弹窗/真下载壳 才写硬标志
      if (o.lockHard && /SEO|强制弹窗|乱码|下载壳|cloaking|dlp|IndexNow|远程乱码|远程下发乱码|download_uri/i.test(s)
        && !/^(?:主动探测仿冒|仿冒品牌官网下载站|品牌.*不匹配)/i.test(String(reason || ""))) {
        // lockHard 真硬套件：可记 remote 分发；fakeBrandShell 仍须文案命中
        state.remoteDownloadDispatchDetected = true;
      }
      if (/SEO伪装|seo.?cloak|IndexNow|SEO收录|伪装跳转/i.test(s)) state._seoCloakKitDetected = true;
      if (/IndexNow|SEO收录仿冒/i.test(s)) state._indexNowPhishTemplate = true;
      if (/桌面端强制|强制弹窗|dlp-overlay|dlp-modal/i.test(s)) state._desktopForceDlKit = true;
      if (/远程乱码|乱码安装包|远程下发乱码/i.test(s)) state._remoteGarbleDlDetected = true;
      if (/多平台.*搜索|搜索引擎.*非安装包|nav-trap|异常下载跳转/i.test(s) || o.guardKind === "nav-trap") state._multiPlatformSerpTrap = true;
      if (/下载壳|download_uri|仿冒品牌官网下载壳/i.test(s)) state._fakeBrandShellDetected = true;
      if (/远程API|远程动态|绑定可疑远程|远程下发|api\.php|download_link|动态绑定下载/i.test(s)) {
        state.remoteDownloadDispatchDetected = true;
      }
      if (/加密下载|加密下发|加密配置|反调试下载页|仿冒官网加密|仿冒官网反调试|无透明安装包/i.test(s)) state._fakeSpaDetected = true;
      if (/品牌资源|域名与品牌|对象存储|盗用.*资源|资源不一致/i.test(s)) state._brandResourceMismatchDetected = true;
      // 软品牌仿冒 / 主动探测：只标 brandSpoof，绝不当 fakeBrandShell 硬锁
      if (o.guardKind === "brand-spoof"
        || /仿冒品牌官网下载站|主动探测仿冒|仿冒「|与标题品牌/.test(s)) {
        state._brandSpoofPortalDetected = true;
      }
      if (/克隆|clone/i.test(s) && !/主动探测/i.test(s)) state._cloneOfficialDetected = true;
    } catch { /* ignore */ }
  };

  /** 硬威胁套件：有任一则禁止 lift/officialSafe 恢复按钮 */
  NS.hasHardThreatKitLocked = function () {
    try {
      const state = NS.state;
      // 超成熟门户（WHOIS≥10y 或 ICP+≥10y）：仅 SEO/强制弹窗/乱码 算硬锁
      // 避免百度等站被 fakeSpa/软仿冒/跨域跳转误锁后永远「可疑安装包已禁用」
      const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      const ultra = !!(matureProfile && (matureProfile.trusted
        || (typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
          && NS.hasAuthoritativeMatureOrganizationIdentity(matureProfile))));
      if (ultra) {
        return typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      }
      // 品牌对齐开源仓：软仿冒不算硬锁（否则按钮永远无法恢复）
      let openSourceTrusted = false;
      try {
        openSourceTrusted = typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal();
      } catch { openSourceTrusted = false; }
      if (
        state._seoCloakKitDetected
        || state._desktopForceDlKit
        || state._remoteGarbleDlDetected
        || state._indexNowPhishTemplate
        || state._unverifiedIcpIdentityThreat
        || state._multiPlatformSerpTrap
        || state._fakeSpaDetected
        || state._fakeBrandShellDetected
        || state._cloneOfficialDetected
      ) return true;
      // 软品牌仿冒：开源可信时不当硬锁
      if (!openSourceTrusted && (state._brandSpoofPortalDetected || state._brandResourceMismatchDetected)) {
        return true;
      }
      if (state.remoteDownloadDispatchDetected
        && (state._seoCloakKitDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected
          || state._fakeSpaDetected || state._fakeBrandShellDetected)) return true;
      try {
        for (const d of state.details || []) {
          const name = d.name || "";
          // 真硬套件信号
          if (/仿冒品牌官网下载壳|远程API动态绑定|SEO伪装|桌面端强制弹窗|远程乱码|远程下发乱码|SEO收录仿冒|多平台下载指向|仿冒官网加密|仿冒官网反调试|域名与品牌资源不一致|对象存储安装包/i.test(name)) return true;
          // 软仿冒下载站：开源可信时忽略
          if (!openSourceTrusted && /仿冒品牌官网下载站/i.test(name)) return true;
        }
      } catch { /* ignore */ }
      return false;
    } catch { return false; }
  };

  /**
   * 清除盗版/强制下载套件的全屏「请稍等正在加载」遮罩（.ld-wrap / 定高 z-index 白屏）。
   * 与 dlp-overlay 不同类名，旧 scrub 扫不到。
   */
  NS.scrubHostileLoadingOverlays = function () {
    try {
      const kill = (el) => {
        if (!el || el.nodeType !== 1) return;
        // 勿动扩展自己的 toast
        try {
          if (el.id && /silverfox/i.test(el.id)) return;
          if (el.className && /silverfox/i.test(String(el.className))) return;
        } catch { /* ignore */ }
        try { el.remove(); } catch {
          try { el.style.setProperty("display", "none", "important"); el.style.setProperty("visibility", "hidden", "important"); } catch { /* ignore */ }
        }
      };

      // 1) 明确 class：ld-wrap / ld-spinner / ld-text
      document.querySelectorAll(".ld-wrap, .ld-spinner, .ld-text, [class*='ld-wrap'], [class*='ld-spinner']").forEach((el) => {
        try {
          // 删最外层 fixed 全屏容器
          let p = el;
          for (let i = 0; i < 5 && p; i++) {
            const s = (p.style && p.style.cssText) || p.getAttribute("style") || "";
            const zi = parseInt((p.style && p.style.zIndex) || "0", 10) || 0;
            if (/position\s*:\s*fixed/i.test(s) && zi >= 999) { kill(p); return; }
            p = p.parentElement;
          }
          kill(el.parentElement || el);
        } catch { /* ignore */ }
      });

      // 2) 结构启发：fixed + 近全屏 + 高 z-index + 加载文案
      document.querySelectorAll("div, section, aside").forEach((el) => {
        try {
          const st = el.getAttribute("style") || "";
          if (!/position\s*:\s*fixed/i.test(st)) return;
          if (!/(?:z-index\s*:\s*(?:999|9\d{3,}|[1-9]\d{4,})|z-index:\s*999999)/i.test(st)
            && !((el.style && parseInt(el.style.zIndex || "0", 10) >= 9999))) {
            // 仍可能是 999999 写在 style 对象里
            const zi = el.style ? parseInt(el.style.zIndex || "0", 10) : 0;
            if (zi < 9999 && !/z-index\s*:\s*999/i.test(st)) return;
          }
          const t = (el.textContent || "").replace(/\s+/g, " ").trim();
          if (t.length > 80) return; // 不像纯加载层
          if (!/请稍等|正在加载|加载中|请稍候|loading|wait/i.test(t)) return;
          // 近全屏
          const w = el.style.width || "";
          const h = el.style.height || "";
          if (!/100%|100vw|100vh/i.test(w + h) && !/top:\s*0/i.test(st)) return;
          kill(el);
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
  };

  /** CSS + class 全局锁下载控件（比逐按钮 style 更抗 SPA 重绘） */
  NS.applyDownloadGuardDomLock = function (on) {
    try {
      const id = "silverfox-dl-guard-style";
      let st = document.getElementById(id);
      if (on) {
        if (!st) {
          st = document.createElement("style");
          st.id = id;
          st.textContent = [
            "html.silverfox-dl-guard-on a.download-uri,html.silverfox-dl-guard-on .download-uri,",
            "html.silverfox-dl-guard-on a.download-btn,html.silverfox-dl-guard-on .download-btn,html.silverfox-dl-guard-on .download-btn-nav,",
            "html.silverfox-dl-guard-on a.btn-download,html.silverfox-dl-guard-on .btn-download,html.silverfox-dl-guard-on #mainDownloadBtn,",
            "html.silverfox-dl-guard-on .platform-btn,html.silverfox-dl-guard-on button.platform-btn,",
            "html.silverfox-dl-guard-on [class*='btn-download'],html.silverfox-dl-guard-on [class*='download-btn'],",
            "html.silverfox-dl-guard-on [data-threat-detector-disabled='1'],html.silverfox-dl-guard-on [data-silverfox-greyed='1']{",
            "pointer-events:none!important;opacity:.45!important;filter:grayscale(.6)!important;cursor:not-allowed!important;}",
            /* 顶层锁住内嵌框架交互，防盗版页把下载按钮塞进 iframe 绕过灰化 */
            "html.silverfox-dl-guard-on iframe[data-silverfox-frame-locked='1'],",
            "html.silverfox-dl-guard-on embed[data-silverfox-frame-locked='1'],",
            "html.silverfox-dl-guard-on object[data-silverfox-frame-locked='1']{",
            "pointer-events:none!important;}"
          ].join("");
          (document.head || document.documentElement).appendChild(st);
        }
        document.documentElement.classList.add("silverfox-dl-guard-on");
        try { if (document.body) document.body.classList.add("silverfox-dl-guard-on"); } catch { /* ignore */ }
        try { if (typeof NS.neutralizePageFramesForGuard === "function") NS.neutralizePageFramesForGuard(true); } catch { /* ignore */ }
      } else {
        document.documentElement.classList.remove("silverfox-dl-guard-on");
        try { if (document.body) document.body.classList.remove("silverfox-dl-guard-on"); } catch { /* ignore */ }
        if (st) try { st.remove(); } catch { /* ignore */ }
        try { if (typeof NS.neutralizePageFramesForGuard === "function") NS.neutralizePageFramesForGuard(false); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  };

  NS.shouldLiftDownloadGuard = function () {
    try {
      const state = NS.state;
      // 真硬套件不 lift；超成熟/ICP 门户用 forceLift 清 soft 后再判
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return false;
      // 开源可信须先于 hasHardThreatKitLocked（后者含 _brandSpoofPortalDetected，会挡住自抬）
      try {
        if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          state._brandSpoofPortalDetected = false;
          state.spoofBrand = "";
          state._brandResourceMismatchDetected = false;
          state.remoteDownloadDispatchDetected = false;
          return true;
        }
      } catch { /* ignore */ }
      if (NS.hasHardThreatKitLocked()) return false;
      const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      const authoritativeIdentity = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
        && NS.hasAuthoritativeMatureOrganizationIdentity(matureProfile);
      if (state.downloadGuardInstalled && /仿冒品牌官网下载壳|远程API动态|SEO伪装|桌面端强制|远程乱码|SEO收录仿冒/i.test(
        (state.details || []).map((d) => d.name || "").join(" ")
      ) && !(matureProfile && (matureProfile.trusted || authoritativeIdentity))) return false;
      // 仅成熟正规站组合门抬起软误报。
      if (matureProfile && (matureProfile.trusted || authoritativeIdentity)) {
        state._brandResourceMismatchDetected = false;
        state.remoteDownloadDispatchDetected = false;
        return true;
      }
      if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) {
        state._brandResourceMismatchDetected = false;
        state.remoteDownloadDispatchDetected = false;
        return true;
      }
      if (NS.hostLooksLikeBrandMarketingSpoof()) return false;
      const html = NS.getThreatScanHtml(120000);
      if (NS.hasEncryptedNuxtDownloadConfig(html) && NS.countTransparentProductPackages(html) === 0) return false;
      const badPkg = (state.protectedTargets || []).some((t) => {
        if (NS.looksLikeOfficialProductDownloadEndpoint(t)) return false;
        if (NS.looksLikeHighRiskBlobPackageUrl(t)) return true;
        const n = NS.getFilenameFromUrl(t) || NS.normalizeFileName(t);
        if (!n) return false;
        if (NS.isClearProductOrAndroidPackage(n) || NS.isBenignShortInstallerName(n) || NS.looksLikeProductPackageName(n)) return false;
        if (NS.isContentAddressedPackageName(n)) return /https?:\/\//i.test(String(t)) && NS.looksLikeHighRiskBlobPackageUrl(t);
        return NS.isSuspiciousDownloadFilename(n);
      });
      if ((NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) && !state._fakeSpaDetected && !NS.hasEncryptedNuxtDownloadConfig(html)) {
        const hasHighRiskBlob = (state.protectedTargets || []).some((t) => NS.looksLikeHighRiskBlobPackageUrl(t));
        if (!hasHighRiskBlob) return true;
      }
      if (badPkg && !(NS.looksLikeMatureOfficialPortal() || NS.looksLikeSafeOfficialContext())) return false;
      const onlyOfficialTargets = (state.protectedTargets || []).length > 0 && (state.protectedTargets || []).every((t) => {
        if (NS.looksLikeOfficialProductDownloadEndpoint(t) || NS.isSamePageBrandApex(t)) return true;
        if (NS.looksLikeHighRiskBlobPackageUrl(t)) return false;
        const n = NS.getFilenameFromUrl(t) || NS.normalizeFileName(t);
        return !n || NS.isClearProductOrAndroidPackage(n) || NS.isBenignShortInstallerName(n) || NS.looksLikeProductPackageName(n) || NS.isContentAddressedPackageName(n);
      });
      if (onlyOfficialTargets && NS.isTrustedOfficialDownloadContext()) return true;
      if (NS.isTrustedOfficialDownloadContext()) return true;
      if (typeof NS.pageLooksLikeLegitimateOfficialDownload === "function" && NS.pageLooksLikeLegitimateOfficialDownload()) return true;
      if (NS.looksLikeOfficialBrandDownloadPage(html)) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      if (NS.looksLikeOfficialClientDownloadPage()) return true;
      const whoisOld = /已注册\s*(\d+)\s*天/.exec(state.whoisInfo || "");
      const days = whoisOld ? parseInt(whoisOld[1], 10) : null;
      const hasIcp = typeof NS.hasValidIcpRecord === "function"
        ? NS.hasValidIcpRecord()
        : !!(state.icpInfo && !/未查询到|查询失败|查询未确认|暂无/.test(state.icpInfo));
      if (hasIcp && days != null && days >= 365) {
        if (onlyOfficialTargets || !badPkg) return true;
        const onlyHashOrClear = (state.protectedTargets || []).every((t) => {
          if (NS.looksLikeHighRiskBlobPackageUrl(t)) return false;
          const n = NS.getFilenameFromUrl(t) || NS.normalizeFileName(t);
          return !n || NS.isContentAddressedPackageName(n) || NS.isClearProductOrAndroidPackage(n) || NS.isBenignShortInstallerName(n) || NS.looksLikeProductPackageName(n);
        });
        if (onlyHashOrClear) return true;
      }
      if (hasIcp && days != null && days >= 365 && NS.countTransparentProductPackages(html) >= 1) return true;
      return false;
    } catch { return false; }
  };

  NS.clearDownloadGuard = function (reason) {
    const state = NS.state;
    // 硬套件锁定时拒绝 clear——但「真硬套件」才挡；可信门户 soft-lift 必须能解开按钮
    // official-or-safe-page 须算可信抬锁：maybeLift 常用此 reason，否则会被
    // hasHardThreatKitLocked（仍含「仿冒品牌官网下载站」detail）挡回并重新上锁
    const trustedLift = /trusted-portal|valid-icp|whois-ultra|brand-spoof-skip-trusted|intel-light|trusted-opensource|clear-brand-spoof|icp-clear-brand-spoof|official-or-safe-page|guard-skip-trusted/i.test(String(reason || ""));
    const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
    if (!trustedLift && NS.hasHardThreatKitLocked() && reason !== "page-reset" && reason !== "serp-light-mode" && !/^reset/i.test(String(reason || ""))) {
      NS.silverfoxLog("guard-clear-blocked", reason || "", "hard-kit-locked");
      try { NS.disableAllDownloadIntentControls(); NS.applyDownloadGuardDomLock(true); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
      return;
    }
    if (trustedLift && realHard) {
      NS.silverfoxLog("guard-clear-blocked", reason || "", "real-hard-kit");
      try { NS.disableAllDownloadIntentControls(); NS.applyDownloadGuardDomLock(true); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
      return;
    }
    // 可信抬锁：先清软仿冒标志，避免后续 hasHardThreatKitLocked 仍因 detail 文案为真
    if (trustedLift && !realHard) {
      try {
        state._brandSpoofPortalDetected = false;
        state.spoofBrand = "";
        state._pendingSoftBrandSpoof = false;
        state._brandSpoofPresentationDeferred = false;
        state._brandResourceMismatchDetected = false;
      } catch { /* ignore */ }
    }
    const hadGuard = state.downloadGuardInstalled || state._earlyShellArmed;
    state.downloadGuardInstalled = false;
    state._earlyShellArmed = false;
    state.protectionNoticeSent = false;
    state._brandSpoofNoticeSent = false;
    state._brandSpoofNoticeKey = "";
    state._lastGuardNoticeKind = "";
    state._lastGuardNoticeKey = "";
    state.remoteDownloadDispatchDetected = false;
    state.protectedTargets = [];
    state._guardRedisableArmed = false;
    try { NS.caches.sentNoticeKeys.clear(); } catch { /* ignore */ }
    try { NS.applyDownloadGuardDomLock(false); } catch { /* ignore */ }
    NS.postToHooks({ type: "set-guard", enabled: false });
    try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ }
    if (NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) NS.notifyHooksOfficialSafe(true);
    NS.reEnableAllThreatDisabledElements();
    // 多次补还原：SPA/样式重写后仍可能丢掉 href
    [0, 50, 200, 600, 1500, 3000].forEach((ms) => setTimeout(() => {
      try {
        if (!state.downloadGuardInstalled) {
          NS.applyDownloadGuardDomLock(false);
          NS.reEnableAllThreatDisabledElements();
          NS.postToHooks({ type: "set-guard", enabled: false });
        }
      } catch { /* ignore */ }
    }, ms));
    try {
      if (chrome?.runtime?.id) {
        chrome.runtime.sendMessage({ type: "set-tab-protect", enabled: false, force: true, url: location.href }, () => { void chrome.runtime.lastError; });
        chrome.runtime.sendMessage({ type: "clear-threat-notice", url: location.href, reason: reason || "lift-guard" }, () => { void chrome.runtime.lastError; });
      }
    } catch { /* ignore */ }
    const softRe = /已启用安装包下载拦截|已启用仿冒站下载拦截|已启用异常跳转拦截|SEO伪装跳转|SEO收录仿冒|多平台下载指向搜索引擎|非用户手势|仿冒品牌官网|仿冒官网|主动探测仿冒|主动探测：|页面嵌入可疑安装包|可疑安装包链接|探测到跳转\/附件下载|探测到下载行为|已拦截可疑|域名与品牌资源不一致|多版本下载同一|无透明安装包|与标题品牌|疑似仿冒官网/;
    if (Array.isArray(state.details)) state.details = state.details.filter((d) => !softRe.test(d.name || "") && !softRe.test(d.reason || ""));
    if (state.signalSet && typeof state.signalSet.clear === "function") {
      state.signalSet.clear();
      let score = 0;
      for (const d of state.details) { const w = Number(d.weight) || 0; state.signalSet.add(`${d.name}:${w}`); score += w; }
      state.score = score;
    }
    if (hadGuard || reason) NS.emitRiskReport(true);
  };

  NS.maybeLiftDownloadGuard = function () {
    try {
      const state = NS.state;
      // 开源可信：整段 clearBrandSpoof（清信号+guard），勿走 official-or-safe-page 被硬锁挡回
      try {
        if (typeof NS.hasRealHardKitThreat === "function" && !NS.hasRealHardKitThreat()
          && typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          if (typeof NS.clearBrandSpoofFalsePositive === "function") {
            NS.clearBrandSpoofFalsePositive("trusted-opensource");
          } else {
            NS.clearDownloadGuard("trusted-opensource");
          }
          try { NS.applyDownloadGuardDomLock(false); NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
          NS.silverfoxLog && NS.silverfoxLog("guard-lift", "trusted-opensource");
          return true;
        }
      } catch { /* ignore */ }
      if (!NS.shouldLiftDownloadGuard()) return false;
      const locked = state.downloadGuardInstalled || state._earlyShellArmed || !!document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']");
      if (!locked && !(state.protectedTargets && state.protectedTargets.length)) {
        NS.postToHooks({ type: "set-guard", enabled: false });
        try { NS.applyDownloadGuardDomLock(false); NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
        return false;
      }
      // 须用可信 reason，否则 hasHardThreatKitLocked 会挡 clear 并 re-lock 按钮
      NS.clearDownloadGuard("official-or-safe-page");
      return true;
    } catch { return false; }
  };

  NS.isHrefSuspiciousPackageSync = function (href, element) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    if (!NS.isPackageFileUrl(href)) return false;
    if (NS.isAllowlistedProductPackageUrl(href)) return false;
    const fileName = NS.getFilenameFromUrl(href);
    if (NS.looksLikeStrongProductInstallerName(fileName) || NS.isClearProductOrAndroidPackage(fileName) || NS.isClearProductOrAndroidPackage(href) || NS.isBenignShortInstallerName(fileName)) return false;
    try {
      const host = new URL(href, location.href).hostname;
      if (NS.isAnonymousPublicObjectHost(host) && !NS.looksLikeStrongProductInstallerName(fileName)) return true;
      if (NS.hostLooksLikePublicObjectStorageEndpoint(host) && NS.looksLikeObjectStoragePackageUrl(href)) return true;
    } catch { /* ignore */ }
    if (NS.looksLikeHighRiskBlobPackageUrl(href) || NS.isThreatObjectStoragePackage(href, element)) return true;
    if (NS.looksLikeBrandNearMissPackageName(fileName)) return true;
    if (NS.isContentAddressedPackageName(fileName)) {
      if (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) return NS.looksLikeHighRiskBlobPackageUrl(href);
      return NS.looksLikeHighRiskBlobPackageUrl(href) || NS.looksLikeObjectStoragePackageUrl(href);
    }
    if (NS.isThreatObjectStoragePackage(href, element)) return true;
    if (NS.looksLikeProductPackageName(fileName) && !NS.looksLikeObjectStoragePackageUrl(href)) return false;
    if (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) return NS.looksLikeHighRiskBlobPackageUrl(href);
    return NS.isSuspiciousDownloadFilename(fileName) || NS.looksLikeHiddenPackagePath(href) || NS.isSuspiciousDownloadTarget(href, element);
  };

  NS.isHrefSuspiciousPackage = function (href, element) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    if (NS.looksLikeOfficialProductDownloadEndpoint(href)) return false;
    if (NS.isClearProductOrAndroidPackage(href)) return false;
    if (NS.isBenignShortInstallerName(NS.getFilenameFromUrl(href))) return false;
    if (NS.isContentAddressedPackageName(NS.getFilenameFromUrl(href)) && (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) && !NS.looksLikeHighRiskBlobPackageUrl(href)) return false;
    if (NS.isTrustedOfficialDownloadContext() && NS.isSamePageBrandApex(href)) return false;
    if (NS.isHrefSuspiciousPackageSync(href, element)) return true;
    try {
      const abs = new URL(href, location.href).href;
      const cached = NS.caches.probeCache.get(abs);
      if (cached && cached.isDownload) {
        if (NS.looksLikeOfficialProductDownloadEndpoint(abs)) return false;
        const fn = cached.filename || cached.fileName || NS.getFilenameFromUrl(abs);
        if (NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(abs)) return false;
        if (NS.isBenignShortInstallerName(fn)) return false;
        if (NS.isContentAddressedPackageName(fn) && (NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal()) && !NS.looksLikeHighRiskBlobPackageUrl(abs)) return false;
        return true;
      }
    } catch { /* ignore */ }
    return false;
  };

  NS.isSuspiciousDownloadTarget = function (href, element) {
    const trimmed = (href || "").trim();
    if (!trimmed || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(trimmed)) return false;
    if (!NS.isPackageFileUrl(trimmed)) return false;
    try {
      const fileName = NS.getFilenameFromUrl(trimmed);
      if (NS.isThreatObjectStoragePackage(trimmed, element)) return true;
      if (NS.looksLikeProductPackageName(fileName) && !NS.looksLikeObjectStoragePackageUrl(trimmed)) return false;
      const fileNameSuspicious = NS.isSuspiciousDownloadFilename(fileName);
      const obfuscatedPhp = NS.looksLikeObfuscatedPhpDownloadUrl(trimmed);
      const hiddenPath = NS.looksLikeHiddenPackagePath(trimmed);
      const brandMismatch = NS.packageMismatchesPageBrand(trimmed);
      const queryDownload = /(filename|file|url|downurl|downloadurl)=/i.test(trimmed) && PACKAGE_EXT.test(trimmed);
      const path = new URL(trimmed, location.href).pathname.toLowerCase();
      const garbledPath = /\/(?:ins\d+|id\d+|[a-f0-9]{10,})\//i.test(path);
      if (obfuscatedPhp) return true;
      if (fileNameSuspicious) return true;
      if (hiddenPath && (fileNameSuspicious || brandMismatch)) return true;
      if (brandMismatch && (fileNameSuspicious || hiddenPath)) return true;
      if (queryDownload && (fileNameSuspicious || garbledPath || obfuscatedPhp)) return true;
      if (garbledPath && PACKAGE_EXT.test(path)) return true;
      if (element && NS.isDownloadIntentElement(element) && fileNameSuspicious) return true;
      return false;
    } catch { return false; }
  };

  NS.applyConfirmedDownloadBlock = function (href, el, probeInfo) {
    if (!href) return;
    if (NS.looksLikeOfficialProductDownloadEndpoint(href) || NS.isTrustedOfficialDownloadContext()) return;
    const probeName = probeInfo?.filename || probeInfo?.fileName || "";
    if (NS.isClearProductOrAndroidPackage(probeName) || NS.isClearProductOrAndroidPackage(href) || NS.looksLikeStrongProductInstallerName(probeName) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(href)) || NS.isAllowlistedProductPackageUrl(href)) return;
    const state = NS.state;
    if (!state.protectedTargets.includes(href)) state.protectedTargets.push(href);
    if (el) NS.disableOneSuspiciousElement(el, href);
    NS.disableSuspiciousDownloadButtons();
    NS.disableAllDownloadIntentControls();
    let label = NS.formatPackageLabel(href);
    try { const u = new URL(href, location.href); if (!PACKAGE_EXT.test(u.pathname)) label = probeInfo?.filename || `${u.hostname}${u.pathname}`; } catch { /* ignore */ }
    const reason = probeInfo?.reason ? `探测到下载行为(${probeInfo.reason}): ${label}` : `已拦截可疑下载: ${label}`;
    NS.addSignal("探测到跳转/附件下载", 14, reason);
    NS.installDownloadGuard(reason, { notify: true, href, message: label, forceNotify: !state.protectionNoticeSent });
  };

  NS.disableSuspiciousDownloadButtons = function () {
    const state = NS.state;
    Array.from(document.querySelectorAll("a[href], a[data-href], a[data-threat-original-href]")).forEach((el) => {
      try {
        const href = (el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-threat-original-href") || "").trim();
        if (!href || /^(javascript:|#)$/i.test(href)) return;
        if (!NS.isHrefSuspiciousPackageSync(href, el) && !NS.isHrefSuspiciousPackage(href, el)) return;
        NS.disableOneSuspiciousElement(el, href);
      } catch { /* ignore */ }
    });
    if (state.downloadGuardInstalled || state.protectedTargets.length > 0) NS.disableAllDownloadIntentControls();
  };

  NS.armBackgroundProtect = function (mode = "full") {
    try {
      if (!chrome?.runtime?.id) return;
      chrome.runtime.sendMessage({ type: "set-tab-protect", enabled: true, mode, provisional: mode === "provisional", url: location.href }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
  };

  NS.pageLooksLikeThinCloakingRelay = function () {
    try {
      if (NS.pageLooksLikeLegitimateOfficialDownload()) return false;
      if (!document.body) return false;
      try {
        const htmlHead = NS.getHtmlSlice(60000);
        if (/window\.__DATA__\s*=/.test(htmlHead) && /DownloadLink|win_installer|\.exe"/i.test(htmlHead) && NS.countTransparentProductPackages(htmlHead) >= 1) return false;
        const spaRoot = document.querySelector("#ice-container, #root, #app, #__next, #__nuxt, [data-reactroot]");
        if (spaRoot) {
          const externalScripts = Array.from(document.scripts || []).filter((s) => s.src).length;
          const title = document.title || "";
          if (externalScripts >= 2 && /官网|官方|下载|客户端/i.test(title) && NS.countTransparentProductPackages(htmlHead) >= 1) return false;
        }
      } catch { /* ignore */ }
      const text = ((document.body && document.body.textContent) || "").replace(/\s+/g, "");
      if (text.length < 48) {
        const scripts = document.scripts ? document.scripts.length : 0;
        const inlineHeavy = Array.from(document.scripts || []).some((s) => !s.src && (s.textContent || "").length > 2000);
        const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
        if (scripts >= 1 && inlineHeavy && ext <= 1) return true;
        if (scripts >= 1 && ext === 0) return true;
        return false;
      }
      if (text.length < 220) {
        const scripts = document.scripts ? document.scripts.length : 0;
        let interactive = 0;
        try { interactive = document.body.querySelectorAll("a[href], button, input, img, video, form, [class*='download']").length; } catch { interactive = 0; }
        const ext = Array.from(document.scripts || []).filter((s) => s.src).length;
        if (scripts >= 1 && interactive < 4 && ext <= 1) return true;
      }
      try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i) || ""; if (/^zhizhu[_-]/i.test(k)) return true; } } catch { /* ignore */ }
      return false;
    } catch { return false; }
  };

  NS.tryEarlyShellProtect = function () {
    try {
      const state = NS.state;
      if (state.downloadGuardInstalled || state._earlyShellArmed) return;
      if (NS.pageLooksLikeSearchEngineResultsPage()) return;
      if (NS.pageLooksLikeLegitimateOfficialDownload()) return;
      try {
        const path = (location.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
        const q = location.search || "";
        if (q.length > 1) {
          if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word)=[^&]+/i.test(q)) return;
          if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|wd|word)=[^&]+/i.test(q)) return;
        }
      } catch { /* ignore */ }
      const title = document.title || "";
      const titleHit = /官网|官方下载|官网下载|客户端下载|下载页面|免费下载|官方正版|官方网站/.test(title);
      let domHit = false;
      try { domHit = !!document.querySelector(".download-uri, a.download-uri, [class~='download-uri']"); } catch { /* ignore */ }
      let uriHit = false;
      try { uriHit = typeof window.download_uri === "string" && window.download_uri.length > 4; } catch { /* ignore */ }
      const thinRelay = NS.pageLooksLikeThinCloakingRelay();
      if (!titleHit && !domHit && !uriHit && !thinRelay) return;
      if (!thinRelay && !domHit && !uriHit) return;
      if (thinRelay && NS.pageLooksLikeLegitimateOfficialDownload()) return;
      state._earlyShellArmed = true;
      NS.armBackgroundProtect("provisional");
    } catch { /* ignore */ }
  };

  /** arm 下载保护 guard：DNR / 包取消 / DOM 禁用 / toast。 */
  NS.installDownloadGuard = function (reason = "检测到可疑安装包下载，已启用文件拦截保护", opts = {}) {
    const state = NS.state;
    const o = opts || {};
    // 所有品牌提示的统一出口：官网身份核验前不允许任何检测器抢先定稿或弹出
    // “已识别仿冒「品牌」官网”。其它 package/nav 等硬威胁通知不受影响。
    if (o.guardKind === "brand-spoof"
      && !(typeof NS.isBrandSpoofIdentityVerificationSettled === "function"
        && NS.isBrandSpoofIdentityVerificationSettled())) {
      state._pendingSoftBrandSpoof = true;
      state._brandSpoofPresentationDeferred = true;
      NS.silverfoxLog("guard-defer", "brand-spoof-wait-official-identity");
      return;
    }
    // 有效备案 / 强信任未否定前：软仿冒不弹 toast（官网会闪一秒再被清掉）
    if (o.guardKind === "brand-spoof"
      && typeof NS.canPresentSoftBrandSpoofNotice === "function"
      && !NS.canPresentSoftBrandSpoofNotice()) {
      state._pendingSoftBrandSpoof = true;
      state._brandSpoofPresentationDeferred = true;
      NS.silverfoxLog("guard-defer", "brand-spoof-wait-confirm-not-official");
      return;
    }
    // 其它检测器不得绕过统一品牌定稿：需要弹品牌通知时先交给 commit，
    // 由 host 拉丁核 / SW pinyin 双向校验完成后再回到这里。
    if (o.guardKind === "brand-spoof" && o.notify !== false
      && !state._brandSpoofFinalPresented
      && typeof NS.commitBrandSpoofPresentation === "function") {
      NS.commitBrandSpoofPresentation({
        brand: state.spoofBrand || "",
        host: location.hostname,
        lockHard: o.lockHard !== false
      });
      return;
    }
    if (o.guardKind === "brand-spoof") {
      try {
        const forbid = (t) => typeof NS.isForbiddenSpoofDisplayBrand === "function"
          && NS.isForbiddenSpoofDisplayBrand(t);
        let correctedBrand = String(state.spoofBrand || "").trim();
        if (forbid(correctedBrand)) correctedBrand = "";
        if (!correctedBrand) {
          correctedBrand = String(NS.reconcileActiveSpoofBrand({ force: true }) || "").trim();
          if (forbid(correctedBrand)) correctedBrand = "";
        }
        // 仍空：标题中文 / 主机剥核，禁止空品牌 toast
        if (!correctedBrand && typeof NS.extractChineseBrandFromPageTitle === "function") {
          correctedBrand = String(NS.extractChineseBrandFromPageTitle() || "").trim();
          if (forbid(correctedBrand)) correctedBrand = "";
        }
        if (!correctedBrand) {
          let core = typeof NS.resolveHostBrandCore === "function"
            ? String(NS.resolveHostBrandCore() || "").toLowerCase().replace(/[^a-z0-9]/g, "")
            : "";
          const lab = String(location.hostname || "").replace(/^www\./i, "").split(".")[0] || "";
          const labFlat = lab.replace(/[^a-z0-9]/g, "");
          if (core === labFlat) core = "";
          if ((!core || core.length < 4) && typeof NS.inferMarketingPaddedBrandCore === "function") {
            core = String(NS.inferMarketingPaddedBrandCore(lab) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          }
          if (core && core.length >= 4 && core !== labFlat) {
            correctedBrand = typeof NS.formatBrandTokenForDisplay === "function"
              ? (NS.formatBrandTokenForDisplay(core) || core)
              : (core.charAt(0).toUpperCase() + core.slice(1));
          }
        }
        // o.title 里若已是「仿冒「中文」」也强制纠正
        try {
          const badInTitle = String(o.title || "").match(/仿冒「([^」]{1,16})」/);
          if (badInTitle && forbid(badInTitle[1])) {
            o.title = "";
            o.message = "";
          }
        } catch { /* ignore */ }
        if (correctedBrand && !forbid(correctedBrand)) {
          try {
            if (typeof NS.setSpoofDisplayBrand === "function") NS.setSpoofDisplayBrand(correctedBrand);
            else state.spoofBrand = correctedBrand;
          } catch { /* ignore */ }
          o.title = `已识别仿冒「${correctedBrand}」官网`;
          if (!o.message || /页面标题|品牌.*不匹配|疑似仿冒官网|页面宣称品牌/i.test(String(o.message))) {
            o.message = `页面标题/正文品牌「${correctedBrand}」与当前域名不匹配，疑似仿冒官网。`;
          }
          if (/仿冒品牌官网|仿冒「/i.test(String(reason)) || !/仿冒「/.test(String(reason))) {
            reason = `仿冒品牌官网下载站（仿冒「${correctedBrand}」）`;
          }
        } else if (forbid(String(state.spoofBrand || ""))) {
          // 清掉错误的「中文」状态，避免 popup/后续 toast 继续用
          try {
            state.spoofBrand = "";
            state._spoofBrandChineseLocked = false;
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
    }
    NS.silverfoxLog("guard-arm?", "reason=", String(reason || "").slice(0, 120), "kind=", o.guardKind || "package", "title=", o.title || "");
    // 先按 ICP/WHOIS 成熟度拦软 arm（勿先 noteHard 把软原因写硬）
    const realHardPre = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
    const matureProfilePre = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
      ? NS.evaluateMatureLegitimateSiteProfile() : null;
    const ultraPre = !!(matureProfilePre && (matureProfilePre.trusted
      || (typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
        && NS.hasAuthoritativeMatureOrganizationIdentity(matureProfilePre))));
    const blobArm = `${reason || ""} ${o.message || ""} ${o.title || ""} ${o.guardKind || ""}`;
    const isSoftBrandSpoofArm = o.guardKind === "brand-spoof"
      || /主动探测仿冒|仿冒品牌官网|与标题品牌|仿冒「|域名.*不匹配.*仿冒/i.test(blobArm);
    // 软件分发门户详情页（结构识别）：永不 arm 软品牌仿冒
    if (isSoftBrandSpoofArm && !realHardPre
      && typeof NS.pageLooksLikeSoftwareCatalogPortal === "function" && NS.pageLooksLikeSoftwareCatalogPortal()) {
      NS.silverfoxLog("guard-skip", "software-catalog-portal");
      try { if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") NS.forceLiftSoftProtectionForTrustedPortal("software-catalog"); } catch { /* ignore */ }
      NS.notifyHooksOfficialSafe(true);
      return;
    }
    // 品牌对齐开源仓 + 可信下载：软仿冒永不 arm，并解除已误锁按钮
    if (isSoftBrandSpoofArm && !realHardPre
      && typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
      && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
      NS.silverfoxLog("guard-skip", "trusted-opensource-soft-brand-spoof");
      try { NS.clearBrandSpoofFalsePositive("trusted-opensource"); } catch { /* ignore */ }
      try { NS.notifyHooksOfficialSafe(true); } catch { /* ignore */ }
      return;
    }
    if ((ultraPre || NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) && !realHardPre) {
      // 成熟正规门户：软品牌仿冒 + lockHard 也不 arm。
      // 仅 SEO/强制弹窗/乱码等真硬套件可越过
      if (isSoftBrandSpoofArm) {
        NS.silverfoxLog("guard-skip", "trusted-portal-soft-brand-spoof");
        try { if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") NS.forceLiftSoftProtectionForTrustedPortal("guard-skip-trusted-brand"); } catch { /* ignore */ }
        NS.notifyHooksOfficialSafe(true);
        return;
      }
      const forceHardKit = !!o.lockHard && /SEO|强制弹窗|乱码|下载壳|cloaking|dlp|IndexNow|远程乱码/i.test(blobArm);
      if (!forceHardKit) {
        NS.silverfoxLog("guard-skip", "trusted-portal-soft");
        try { if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") NS.forceLiftSoftProtectionForTrustedPortal("guard-skip-trusted"); } catch { /* ignore */ }
        NS.notifyHooksOfficialSafe(true);
        return;
      }
    }
    try { NS.noteHardThreatFromArm(reason, o); } catch { /* ignore */ }
    const hardNow = NS.hasHardThreatKitLocked() || !!o.lockHard || !!o.forceHard;
    if ((NS.shouldNeverArmProtection() || NS.looksLikeMatureOfficialPortal()) && !hardNow) {
      NS.silverfoxLog("guard-skip", "mature-official");
      NS.notifyHooksOfficialSafe(true);
      return;
    }
    try {
      const blob = `${reason || ""} ${o.message || ""} ${o.title || ""}`;
      const m = blob.match(/([a-z0-9.-]+\.[a-z.]{2,})\s*[≠!=]+\s*([a-z0-9.-]+\.[a-z.]{2,})/i) || blob.match(/盗用\s*([a-z0-9.-]+\.[a-z.]{2,})/i);
      if (m && !hardNow) {
        const left = m[1] || location.hostname;
        const right = m[2] || m[1];
        if (right && (NS.apexSameBrandFamily(left, right) || NS.pageIsSameBrandFamilySite(left, right) || NS.pageIsSameBrandFamilySite(location.hostname, right))) {
          NS.silverfoxLog("guard-skip", "same-brand-family", left, right);
          return;
        }
      }
    } catch { /* ignore */ }
    const hrefOpt = o.href || "";
    const msgOpt = o.message || "";
    const messageFilename = NS.normalizeFileName((hrefOpt && NS.getFilenameFromUrl(hrefOpt)) || String(msgOpt).split(/[\s/\\]/).pop() || String(reason).split(/[\s/\\]/).pop() || "");
    const guardKind = o.guardKind || "package";
    const isIdentityGuard = guardKind === "brand-spoof" || guardKind === "nav-trap" || /仿冒|官网|域名|跳转/i.test(String(reason || "") + String(msgOpt || ""));
    const hrefFn = hrefOpt ? NS.getFilenameFromUrl(hrefOpt) : "";
    if (!isIdentityGuard && !hardNow && hrefOpt && (NS.looksLikeStrongProductInstallerName(hrefFn) || NS.isBenignShortInstallerName(hrefFn) || NS.looksLikeAndroidPackageIdName(hrefFn) || (NS.isContentAddressedPackageName(hrefFn) && !NS.looksLikeHighRiskBlobPackageUrl(hrefOpt) && !NS.looksLikeOversimplifiedBrandInstallerName(hrefFn))) && !NS.looksLikeOversimplifiedBrandInstallerName(hrefFn) && !NS.looksLikeObjectStoragePackageUrl(hrefOpt) && !NS.looksLikeHighRiskBlobPackageUrl(hrefOpt)) return;
    if (!isIdentityGuard && !hardNow && messageFilename && PACKAGE_NAME.test(messageFilename) && (NS.looksLikeStrongProductInstallerName(messageFilename) || NS.looksLikeProductSetupWithBuildId(messageFilename.replace(/\.[^.]+$/, "")) || NS.isBenignShortInstallerName(messageFilename)) && !NS.looksLikeOversimplifiedBrandInstallerName(messageFilename) && !NS.looksLikeHighRiskBlobPackageUrl(hrefOpt || messageFilename)) return;
    try {
      const reasonHref = (String(reason || "").match(/https?:\/\/[^\s"'<>]+/i) || [])[0] || "";
      if (!hardNow && reasonHref && (NS.isAllowlistedProductPackageUrl(reasonHref) || NS.looksLikeStrongProductInstallerName(NS.getFilenameFromUrl(reasonHref)))) return;
    } catch { /* ignore */ }
    // 软品牌信任门：组合成熟站，或正规干净页面叠加 OV/EV。
    if (guardKind === "brand-spoof" && !state._seoCloakKitDetected && !state._desktopForceDlKit && !state._remoteGarbleDlDetected && !state._indexNowPhishTemplate) {
      if (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()) {
        NS.silverfoxLog("guard-skip", "brand-spoof-blocked-by-trusted-identity");
        NS.clearBrandSpoofFalsePositive("guard-arm-blocked-by-trusted");
        return;
      }
      // 有效 ICP：软仿冒不 arm、不 toast（确认官网证据后禁止闪提示）
      if (!hardNow && !state._fakeBrandShellDetected
        && typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()) {
        NS.silverfoxLog("guard-skip", "brand-spoof-blocked-by-valid-icp");
        try { NS.clearBrandSpoofFalsePositive("guard-arm-blocked-by-valid-icp"); } catch { /* ignore */ }
        return;
      }
      // 品牌对齐开源仓 + 成熟下载：不 arm，并抬已误上的锁
      try {
        if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          NS.silverfoxLog("guard-skip", "brand-spoof-blocked-by-trusted-opensource");
          NS.clearBrandSpoofFalsePositive("trusted-opensource");
          return;
        }
      } catch { /* ignore */ }
      if (!hardNow && !state._fakeBrandShellDetected && !NS.icpSettledForSoftBrandSpoof()) {
        NS.silverfoxLog("guard-defer", "soft-brand-spoof-wait-icp");
        state._pendingSoftBrandSpoof = true;
        return;
      }
      // 情报未完：继续 defer，避免 ICP 先结就 toast
      if (!hardNow && !state._fakeBrandShellDetected
        && typeof NS.canPresentSoftBrandSpoofNotice === "function"
        && !NS.canPresentSoftBrandSpoofNotice()) {
        NS.silverfoxLog("guard-defer", "soft-brand-spoof-wait-intel");
        state._pendingSoftBrandSpoof = true;
        return;
      }
    }
    NS.silverfoxLog("guard-arm", "ok", String(reason || "").slice(0, 100));
    const firstTime = !state.downloadGuardInstalled;
    if (state.downloadGuardInstalled && !o.forceNotify && !o.userAction && o.notify === false) {
      NS.disableAllDownloadIntentControls();
      try { NS.applyDownloadGuardDomLock(true); } catch { /* ignore */ }
      try { NS.scrubHostileLoadingOverlays(); } catch { /* ignore */ }
      NS.postToHooks({ type: "set-guard", enabled: true });
      return;
    }
    NS.armBackgroundProtect("full");
    NS.armImmediatePackageBlock();
    state.downloadGuardInstalled = true;
    state._guardArmedAt = Date.now();
    NS.postToHooks({ type: "set-guard", enabled: true });
    NS.disableSuspiciousDownloadButtons();
    NS.disableAllDownloadIntentControls();
    try { NS.applyDownloadGuardDomLock(true); } catch { /* ignore */ }
    try { NS.scrubHostileLoadingOverlays(); } catch { /* ignore */ }
    // 晚注入的 ld-wrap 全屏加载层：短时反复清
    [50, 200, 500, 1200, 2500, 5000].forEach((ms) => {
      setTimeout(() => {
        try {
          if (NS.state.downloadGuardInstalled) NS.scrubHostileLoadingOverlays();
        } catch { /* ignore */ }
      }, ms);
    });
    // 身份异常拦截是处置动作，不再作为额外证据写入列表或重复加分。
    if (guardKind === "site-identity") { /* action only */ }
    else if (guardKind === "brand-spoof") NS.addSignal("已启用仿冒站下载拦截", 10, reason);
    else if (guardKind === "nav-trap") NS.addSignal("已启用异常跳转拦截", 10, reason);
    else NS.addSignal("已启用安装包下载拦截", 12, reason);
    const shouldNotify = o.notify !== false && (firstTime || o.forceNotify || !state.protectionNoticeSent || guardKind === "brand-spoof" || guardKind === "nav-trap");
    if (shouldNotify) {
      state.protectionNoticeSent = true;
      const href = o.href || "";
      const label = o.message || (href && NS.isPackageFileUrl(href) ? NS.formatPackageLabel(href) : "") || reason || "可疑下载行为";
      const noticeTitle = o.title || (guardKind === "brand-spoof"
        ? "已识别仿冒品牌官网"
        : guardKind === "site-identity"
          ? "已拦截身份异常网站下载"
          : guardKind === "nav-trap" ? "已拦截异常下载跳转" : "已拦截可疑安装包");
      NS.showGuardOverlay(href, { title: noticeTitle, message: label, toast: true, forceNotify: !!o.forceNotify || firstTime || guardKind === "brand-spoof" || guardKind === "nav-trap", userAction: !!o.userAction, guardKind });
    }
    const redisable = () => {
      if (!state.downloadGuardInstalled) return;
      try {
        NS.disableAllDownloadIntentControls();
        NS.applyDownloadGuardDomLock(true);
        NS.postToHooks({ type: "set-guard", enabled: true });
      } catch { /* ignore */ }
    };
    [0, 50, 200, 500, 1200, 2500, 5000, 9000].forEach((ms) => setTimeout(redisable, ms));
    state._guardRedisableArmed = true;
    NS.emitRiskReport(true);
  };
})(window.SilverfoxContent ??= {});
