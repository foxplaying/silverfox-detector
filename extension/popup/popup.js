/**
 * popup 渲染器：读取当前标签页风险报告 + 拦截通知，渲染风险等级与详情。
 */
;(function () {
  "use strict";

  const VT_TRUST_POLICY_VERSION = 4;
  const VT_STATS_POLICY_VERSION = 3;
  /** 与 background pe-vt-bg 加权表一致：group 去重；Avast/AVG 同组 */
  const VT_ENGINE_WEIGHT_TABLE = [
    { id: "Kaspersky", group: "kaspersky", weight: 3, re: /^Kaspersky(?:\s|$|\.)/i },
    { id: "ESET", group: "eset", weight: 2.75, re: /^ESET(?:-NOD32)?$/i },
    { id: "Sophos", group: "sophos", weight: 2.5, re: /^Sophos$/i },
    { id: "BitDefender", group: "bitdefender", weight: 2.25, re: /^BitDefender(?:Falx)?$/i },
    { id: "Avast", group: "avast", weight: 2, re: /^(?:Avast(?:-Mobile)?|AVG)$/i },
    { id: "Huorong", group: "huorong", weight: 2, re: /^(?:Huorong|火绒)$/i },
    { id: "Elastic", group: "elastic", weight: 2, re: /^Elastic$/i },
    { id: "Cynet", group: "cynet", weight: 2, re: /^Cynet$/i },
    { id: "Avira", group: "avira", weight: 1.5, re: /^Avira$/i },
    { id: "WithSecure", group: "withsecure", weight: 1.25, re: /^(?:WithSecure|F-Secure)$/i },
    { id: "Sangfor", group: "sangfor", weight: 1, re: /^(?:Sangfor|深信服)$/i },
    { id: "Rising", group: "rising", weight: 0.75, re: /^(?:Rising|瑞星)$/i }
  ];
  const VT_TRUSTED_ENGINE_RULES = VT_ENGINE_WEIGHT_TABLE.map((r) => [r.id, r.re]);
  const VT_HARD_BLOCK_MIN_SCORE = 5;
  const VT_HARD_BLOCK_MIN_FAMILIES = 2;
  const VT_HARD_BLOCK_STRONG_SCORE = 6.5;

  function matchPopupVtWeightRule(engineName) {
    const raw = String(engineName || "").trim();
    if (!raw) return null;
    for (const rule of VT_ENGINE_WEIGHT_TABLE) {
      if (rule.re.test(raw)) return rule;
    }
    return null;
  }

  function popupTrustedVtEngine(engineName) {
    const rule = matchPopupVtWeightRule(engineName);
    return rule ? rule.id : "";
  }

  function popupVtScoreIsHardBlock(score, familyCount) {
    const s = Number(score) || 0;
    const n = Number(familyCount) || 0;
    if (n < VT_HARD_BLOCK_MIN_FAMILIES) return false;
    if (s >= VT_HARD_BLOCK_STRONG_SCORE) return true;
    return s >= VT_HARD_BLOCK_MIN_SCORE;
  }

  /** 展示用：引擎 + 家族；票权仅内部判断，不写进文案 */
  function formatPopupTrustedDetails(rows) {
    return (Array.isArray(rows) ? rows : []).map((x) => {
      const engine = String((x && x.engine) || "").trim();
      if (!engine) return "";
      const result = String((x && x.result) || "").replace(/\s+/g, " ").trim().slice(0, 48);
      return result ? `${engine}（${result}）` : engine;
    }).filter(Boolean);
  }

  /** 匹配等价 URL（路径尾斜杠归一；hash 对 SPA 重要）。 */
  function urlsMatch(a, b) {
    if (!a || !b) return false;
    if (a === b) return true;
    try {
      const ua = new URL(a);
      const ub = new URL(b);
      if (ua.origin !== ub.origin) return false;
      const pa = (ua.pathname || "/").replace(/\/+$/, "") || "/";
      const pb = (ub.pathname || "/").replace(/\/+$/, "") || "/";
      if (pa !== pb) return false;
      if (ua.search !== ub.search) return false;
      if (ua.hash !== ub.hash) return false;
      return true;
    } catch {
      return String(a) === String(b);
    }
  }

  function popupRiskTxn(report) {
    return String((report && report.analysisTxn) || "").trim();
  }

  function popupRiskTxnStartedAt(report) {
    return Number(report && report.analysisTxnStartedAt) || 0;
  }

  function samePopupRiskTransaction(a, b) {
    const left = popupRiskTxn(a);
    const right = popupRiskTxn(b);
    return !!(left && right && left === right);
  }

  function normalizePopupSha256(value) {
    const hash = String(value || "").trim().toLowerCase();
    return /^[a-f0-9]{64}$/.test(hash) ? hash : "";
  }

  /** 有 VT 派生结论时，外层文件与 VT 结果必须以双方完整 SHA-256 绑定。 */
  function popupVtIdentityUnbound(vtInfo) {
    const vt = vtInfo && vtInfo.vt;
    if (!vt) return false;
    const outerHash = normalizePopupSha256(vtInfo && vtInfo.sha256);
    const vtHash = normalizePopupSha256(vt.hash);
    const hasVtDerivedState = vt.found != null || vt.notFound === true || vt.unknown === true
      || Number(vt.total) > 0 || Number(vt.malicious) > 0 || Number(vt.suspicious) > 0
      || !!vt.sigTrustFromVt || !!vt.signerFromVt;
    if (!hasVtDerivedState) return false;
    return !outerHash || !vtHash || outerHash !== vtHash;
  }

  /** 身份未绑定或统计口径过期时都不能展示旧 VT 派生状态。 */
  function popupVtHashMismatch(vtInfo) {
    const vt = vtInfo && vtInfo.vt;
    if (popupVtIdentityUnbound(vtInfo)) return true;
    return !!(vt && vt.found === true && Number(vt.statsPolicyVersion) !== 3);
  }

  function popupNestedVtMatchesItem(item) {
    const itemHash = normalizePopupSha256(item && item.sha256);
    const vt = item && item.vt;
    const vtHash = normalizePopupSha256(vt && vt.hash);
    if (!itemHash || !vtHash || itemHash !== vtHash) return false;
    // 只有 found 报告带统计口径；notFound/unknown 只要求文件身份精确绑定。
    return vt.found !== true || Number(vt.statsPolicyVersion) === 3;
  }

  function popupNestedSignatureTrust(item) {
    if (!popupNestedVtMatchesItem(item)) {
      return item && item.signed ? "present" : "none";
    }
    const vtTrust = String(item.vt && item.vt.sigTrustFromVt || "").toLowerCase();
    if (/^(?:valid|invalid|none)$/.test(vtTrust)) return vtTrust;
    return String(item.trust || item.sigTrust || (item.signed ? "present" : "none")).toLowerCase();
  }

  function sslValidationRank(infoOrValidation) {
    const value = typeof infoOrValidation === "object"
      ? infoOrValidation && infoOrValidation.validation
      : infoOrValidation;
    const validation = String(value || "").toUpperCase();
    if (validation === "EV") return 3;
    if (validation === "OV") return 2;
    if (validation === "DV") return 1;
    return 0;
  }

  function sslInfoHostKey(info) {
    return String((info && (info.host || info.queriedHost)) || "")
      .toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  }

  function isBogusSslOrganization(org) {
    return /internet\s*widgits|some[-\s]?state|default\s+company/i.test(String(org || ""));
  }

  function usableSslOrganization(info) {
    const org = String((info && info.organization) || "").trim();
    if (!org || isBogusSslOrganization(org)) return "";
    return org;
  }

  function effectiveSslValidationRank(info) {
    const rank = sslValidationRank(info);
    const org = String((info && info.organization) || "").trim();
    return rank >= 2 && org && isBogusSslOrganization(org) ? 0 : rank;
  }

  function sslCertificateIdentity(info) {
    const fingerprint = String((info && (info.fingerprintSha256 || info.fingerprint)) || "")
      .toLowerCase().replace(/[^a-f0-9]/g, "");
    if (fingerprint.length >= 32) return `fp:${fingerprint}`;
    const certId = String((info && (info.certId || info.certificateId)) || "").trim();
    return certId ? `id:${certId}` : "";
  }

  /** Popup 也执行单调升级，防止 runtime/storage 异步回调中的旧 DV 把 OV/EV 画回去。 */
  function chooseStrongerSslInfo(previous, incoming) {
    if (!previous) return incoming || null;
    if (!incoming) return previous || null;
    const previousHost = sslInfoHostKey(previous);
    const incomingHost = sslInfoHostKey(incoming);
    if (previousHost && incomingHost && previousHost !== incomingHost) return incoming;
    const previousRank = effectiveSslValidationRank(previous);
    const incomingRank = effectiveSslValidationRank(incoming);
    if (previousRank !== incomingRank) return incomingRank > previousRank ? incoming : previous;
    const quality = (info) => {
      let score = 0;
      if (usableSslOrganization(info)) score += 8;
      if (info && info.sniChainVerified === true) score += 4;
      if (info && info.liveTlsLeafVerified === true) score += 4;
      if (info && info.unexpiredHostVerified === true) score += 2;
      if (!/^(?:https-reachability|page-https|https-assumed)$/i.test(String((info && info.source) || ""))) score += 1;
      return score;
    };
    const primary = quality(incoming) >= quality(previous) ? incoming : previous;
    const secondary = primary === incoming ? previous : incoming;
    const primaryIdentity = sslCertificateIdentity(primary);
    const secondaryIdentity = sslCertificateIdentity(secondary);
    if (primaryIdentity && primaryIdentity === secondaryIdentity) {
      return {
        ...secondary,
        ...primary,
        organization: usableSslOrganization(primary) || usableSslOrganization(secondary),
        sniChainVerified: primary.sniChainVerified === true || secondary.sniChainVerified === true,
        liveTlsLeafVerified: primary.liveTlsLeafVerified === true || secondary.liveTlsLeafVerified === true,
        unexpiredHostVerified: primary.unexpiredHostVerified === true || secondary.unexpiredHostVerified === true
      };
    }
    return { ...primary };
  }

  class PopupRenderer {
    constructor(root) {
      this.root = root;
      this.activeTabId = null;
      this.activeTabUrl = "";
      /** 同 tab 最近一次「已完成」报告，防止中间态 analysisComplete:false 把 UI 打回「正在分析」 */
      this._lastCompletedByTab = new Map();
      this._activeRiskTxnByTab = new Map();
      /**
       * Popup may open before the content script has persisted its first risk
       * report (especially after a background-tab navigation).  Wake the
       * current document at most once per popup lifetime and URL; storage and
       * runtime listeners will render the report when it arrives.
       */
      this._riskReportWakeRequests = new Set();
      this._vtDetailsRefreshes = new Set();
      this._nestedSignatureRefreshes = new Set();
      this._renderRequestSeq = 0;
    }

    hostKeyFromUrl(u) {
      try {
        // UI reports, notices and file analyses are bound to the exact host.
        // Do not collapse www/bare hosts: their ICP/WHOIS conclusions can differ.
        return new URL(u || "").hostname.toLowerCase().replace(/\.+$/g, "");
      } catch {
        return "";
      }
    }

    /** 合并：新消息 incomplete 时，同主机沿用上次完成报告并合并情报字段 */
    coalesceReport(data, tabUrl) {
      if (!data) return null;
      const tabId = this.activeTabId;
      const txn = popupRiskTxn(data);
      const txnStartedAt = popupRiskTxnStartedAt(data);
      const reportUrl = String(data.url || tabUrl || "");
      const activeTxn = tabId != null ? this._activeRiskTxnByTab.get(tabId) : null;
      if (activeTxn) {
        if (!txn) return null;
        if (activeTxn.analysisTxn === txn) {
          if (activeTxn.url && reportUrl && !urlsMatch(activeTxn.url, reportUrl)) return null;
        } else {
          const replacesNavigationSentinel = /^nav-/.test(String(activeTxn.analysisTxn || ""))
            && !!(activeTxn.url && reportUrl && urlsMatch(activeTxn.url, reportUrl));
          if (!replacesNavigationSentinel
            && txnStartedAt && activeTxn.startedAt && txnStartedAt < activeTxn.startedAt) return null;
          // A different transaction is a hard UI boundary. Never let the old
          // completed score/brand participate in this page's intermediate UI.
          if (tabId != null) this._lastCompletedByTab.delete(tabId);
        }
      }
      if (tabId != null && txn) {
        this._activeRiskTxnByTab.set(tabId, {
          analysisTxn: txn,
          startedAt: txnStartedAt || Date.now(),
          url: reportUrl
        });
      }
      // Identity-source failure is an explicit unresolved terminal.  Do not
      // coalesce it with a previously completed clean snapshot from the same
      // transaction; doing so was the remaining path to a misleading 0 score
      // after Edge froze/restored a tab.
      if (data.identityVerificationUnavailable === true) {
        if (tabId != null) this._lastCompletedByTab.delete(tabId);
        return { ...data, analysisComplete: false };
      }
      const completed = this.isCompletedReport(data);
      if (completed) {
        let next = { ...data, url: data.url || tabUrl, analysisComplete: true };
        const prev = tabId != null ? this._lastCompletedByTab.get(tabId) : null;
        if (prev && this.isCompletedReport(prev)) {
          if (samePopupRiskTransaction(prev, next)
            && urlsMatch(prev.url || tabUrl, next.url || tabUrl)) {
            const sslInfo = /^https:/i.test(String(next.url || tabUrl || ""))
              ? chooseStrongerSslInfo(prev.sslInfo, next.sslInfo)
              : (next.sslInfo || null);
            const prevAt = Number(prev.timestamp) || 0;
            const nextAt = Number(next.timestamp) || 0;
            next = prevAt && nextAt && nextAt < prevAt
              ? { ...prev, sslInfo }
              : { ...next, sslInfo };
            // 同主机的新完成报告仍明确是品牌仿冒时，禁止无名报告覆盖已有具名结论。
            const nextHasBrandRisk = !!(next.brandSpoofPortal
              || (Array.isArray(next.details) && next.details.some((d) => /仿冒品牌官网|主动探测仿冒/i.test(d?.name || ""))));
            if (nextHasBrandRisk && !next.spoofBrand && prev.spoofBrand) {
              next = { ...next, spoofBrand: prev.spoofBrand };
            }
          }
        }
        if (tabId != null) this._lastCompletedByTab.set(tabId, next);
        return next;
      }
      const prev = tabId != null ? this._lastCompletedByTab.get(tabId) : null;
      if (!prev || !this.isCompletedReport(prev)) return data;
      if (samePopupRiskTransaction(prev, data)
        && urlsMatch(prev.url || tabUrl, data.url || tabUrl)) {
        const riskRank = { low: 0, medium: 1, high: 2 };
        const prevRisk = String(prev.riskLevel || "low");
        const nextRisk = String(data.riskLevel || "low");
        const mergeList = (a, b, keyOf) => {
          const out = [];
          const seen = new Set();
          for (const item of [...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])]) {
            const key = keyOf(item);
            if (!key || seen.has(key)) continue;
            seen.add(key);
            out.push(item);
          }
          return out;
        };
        const merged = {
          ...prev,
          ...data,
          analysisComplete: true,
          icpInfo: data.icpInfo || prev.icpInfo,
          icpForcedMissing: Object.prototype.hasOwnProperty.call(data, "icpForcedMissing")
            ? data.icpForcedMissing === true
            : prev.icpForcedMissing === true,
          whoisInfo: data.whoisInfo || prev.whoisInfo,
          sslInfo: /^https:/i.test(String(tabUrl || data.url || prev.url || ""))
            ? chooseStrongerSslInfo(prev.sslInfo, data.sslInfo)
            : (data.sslInfo || null),
          score: Math.max(Number(prev.score) || 0, Number(data.score) || 0),
          riskLevel: (riskRank[nextRisk] || 0) >= (riskRank[prevRisk] || 0) ? nextRisk : prevRisk,
          downloadGuardInstalled: !!(prev.downloadGuardInstalled || data.downloadGuardInstalled),
          packageBlocked: !!(prev.packageBlocked || data.packageBlocked),
          brandSpoofPortal: !!(prev.brandSpoofPortal || data.brandSpoofPortal),
          spoofBrand: data.spoofBrand || prev.spoofBrand || "",
          details: mergeList(data.details, prev.details, (d) =>
            `${d?.name || ""}::${d?.reason || ""}::${d?.weight ?? ""}`),
          protectedTargets: mergeList(data.protectedTargets, prev.protectedTargets, (t) => String(t || "")),
          timestamp: data.timestamp || prev.timestamp,
          url: tabUrl || data.url || prev.url
        };
        if (tabId != null) this._lastCompletedByTab.set(tabId, merged);
        return merged;
      }
      return data;
    }

    clearRoot() { while (this.root.firstChild) this.root.removeChild(this.root.firstChild); }

    requestRiskReportOnce(tabUrl) {
      const tabId = this.activeTabId;
      const url = String(tabUrl || this.activeTabUrl || "");
      if (tabId == null || !/^https?:\/\//i.test(url)) return;
      let documentKey = url;
      try { documentKey = new URL(url).href; } catch { /* keep the original URL */ }
      const requestKey = `${tabId}|${documentKey}`;
      if (this._riskReportWakeRequests.has(requestKey)) return;
      this._riskReportWakeRequests.add(requestKey);
      try {
        chrome.tabs.sendMessage(tabId, {
          type: "silverfox-request-risk-report",
          url
        }, () => { void chrome.runtime.lastError; });
      } catch { /* content script unavailable */ }
    }

    el(tag, className, text) {
      const node = document.createElement(tag);
      if (className) node.className = className;
      if (text != null) node.textContent = text;
      return node;
    }

    isDisplayableOrganizationSsl(info) {
      const validation = String((info && info.validation) || "").toUpperCase();
      if (validation !== "OV" && validation !== "EV") return false;
      if (!String((info && info.organization) || "").trim()) return false;
      if (validation === "EV") return true;
      return info.sniChainVerified === true || info.liveTlsLeafVerified === true
        || info.unexpiredHostVerified === true;
    }

    appendSsl(data) {
      // 展示 CT/Labs 结果；https-assumed 为探测失败后的 HTTPS 回退（可显示 DV）
      const info = data && data.sslInfo;
      if (!info || !info.validation) return;
      const src = String(info.source || "");
      if (src === "page-https" || src === "https-reachability") return;
      const validation = String(info.validation || "").toUpperCase();
      if (!validation || !/^(DV|OV|EV)$/.test(validation)) return;
      const row = this.el("div", "item");
      const strong = document.createElement("strong");
      strong.textContent = "SSL证书: ";
      row.appendChild(strong);
      const span = document.createElement("span");
      // 等级与组织字段分开：tlsIssuer 不冒充组织名。
      const org = this.isDisplayableOrganizationSsl(info)
        ? String(info.organization || "").trim()
        : "";
      // 简洁展示：OV/EV 绿色 + 机构名；DV 黑色（不加中文括号后缀）
      if (validation === "EV" || validation === "OV") {
        span.className = "ssl-org";
        span.textContent = org ? `${validation} · ${org}` : validation;
      } else {
        span.className = "ssl-dv";
        span.textContent = "DV";
      }
      row.appendChild(span);
      this.root.appendChild(row);
    }

    appendIcp(data) {
      if (!data || !data.icpInfo) return;
      const raw = String(data.icpInfo);
      // 只有取得可展示的组织字段，才用组织证书隐藏「未查询到备案信息」
      if (/未查询到|查询失败|暂无/.test(raw)
        && data.icpForcedMissing !== true
        && this.isDisplayableOrganizationSsl(data.sslInfo)) return;
      const icp = this.el("div", "item");
      const strong = document.createElement("strong");
      strong.textContent = "ICP备案: ";
      icp.appendChild(strong);
      icp.appendChild(document.createTextNode(raw));
      this.root.appendChild(icp);
    }

    appendWhois(data) {
      if (!data || !data.whoisInfo) return;
      const row = this.el("div", "item");
      const strong = document.createElement("strong");
      strong.textContent = "WHOIS: ";
      row.appendChild(strong);
      row.appendChild(document.createTextNode(String(data.whoisInfo)));
      this.root.appendChild(row);
    }

    /**
     * 安装包/压缩包 VT：须同时满足「标签页 + 浏览主机」归属。
     * 禁止：同 tabId 换域名后仍显示源站下载的旧 VT。
     * CDN 直链：允许 pageHost === 文件托管 host。
     */
    vtMatchesTab(vt, tabId, tabUrl) {
      if (!vt || typeof vt !== "object") return false;
      const at = Number(vt.timestamp) || 0;
      // 30 分钟内；过期不展示
      if (!at || Date.now() - at > 30 * 60 * 1000) return false;
      const pageHost = this.hostKeyFromUrl(tabUrl);
      const pageHostAt = this.hostKeyFromUrl(vt.pageUrl || "")
        || String(vt.pageHost || "").toLowerCase().replace(/\.+$/g, "");
      const dlHost = this.hostKeyFromUrl(vt.url || "");
      // 换站：当前页主机 ≠ 触发下载时的页面主机，且文件也不是当前站托管 → 不展示
      if (pageHost && pageHostAt && pageHost !== pageHostAt) {
        if (!(dlHost && pageHost === dlHost)) return false;
      }
      // tabId 有则必须一致（跨标签全局 latestExeVt 不得串台）
      if (vt.tabId != null && tabId != null && Number(vt.tabId) !== Number(tabId)) return false;
      // 同 tab 且主机已对齐（或上面 CDN 例外）
      if (vt.tabId != null && tabId != null && Number(vt.tabId) === Number(tabId)) {
        // 无 pageHostAt 时仅信任较新记录，避免脏数据永久粘住
        if (!pageHostAt && pageHost) return (Date.now() - at) < 5 * 60 * 1000;
        return true;
      }
      // 缺 tabId 的旧缓存：严格按主机
      if (!pageHost) return false;
      if (pageHostAt && pageHost === pageHostAt) return true;
      if (dlHost && pageHost === dlHost) return true;
      return false;
    }

    appendPackageVt(vtInfo, tabUrl) {
      if (!this.vtMatchesTab(vtInfo, this.activeTabId, tabUrl || this.activeTabUrl)) return;
      const filename = String(vtInfo.filename || "").trim() || "安装包";
      const status = String(vtInfo.status || "").toLowerCase();
      const kind = String(vtInfo.kind || "").trim();
      const kindLabel = kind === "pe" ? "PE"
        : kind === "msi" ? "MSI"
        : kind === "apk" ? "APK"
        : kind === "archive" ? "压缩包"
        : kind || "文件";
      const peObj = vtInfo.pe || null;
      const rawVt = vtInfo.vt || null;
      const vtStatsPolicyStale = !!(rawVt && rawVt.found === true
        && Number(rawVt.statsPolicyVersion) !== 3);
      const vtHashMismatch = popupVtHashMismatch(vtInfo);
      // Never render or act on statistics that belong to another file.
      const vt = vtHashMismatch ? null : rawVt;
      // hash 不匹配时，所有可能由 VT 回填的派生状态都隔离；只保留本地 PE 证书表粗检。
      const peSigned = vtHashMismatch
        ? !!(peObj && peObj.isPe && peObj.signed)
        : !!(vtInfo.peSigned || (peObj && peObj.signed));
      const sigInfo = vtHashMismatch ? null : (vtInfo.signature || null);
      const nested = Array.isArray(vtInfo.nested) ? vtInfo.nested : (sigInfo && Array.isArray(sigInfo.items) ? sigInfo.items : []);
      // 数字签名主体
      const peSigner = vtHashMismatch ? "" : String(
        (sigInfo && sigInfo.signer)
        || vtInfo.peSigner
        || (peObj && peObj.signerHint)
        || (vt && vt.signerFromVt)
        || ""
      ).trim();
      // none | present(黑) | valid(绿) | invalid(红)
      const storedSigTrust = vtHashMismatch ? "" : String(
        (sigInfo && sigInfo.trust) || vtInfo.peSigTrust || ""
      ).toLowerCase();
      const currentVtSigTrust = String((vt && vt.sigTrustFromVt) || "").toLowerCase();
      // VT 的结构化结论优先于旧的本地/缓存状态；invalid 永远保持红色。
      let peSigTrust = currentVtSigTrust === "invalid" || storedSigTrust === "invalid"
        ? "invalid"
        : (currentVtSigTrust === "valid"
          ? "valid"
          : (currentVtSigTrust === "none" ? "none" : storedSigTrust));
      if (!peSigTrust) {
        if (peSigned || peSigner) peSigTrust = "present";
        else if (peObj && peObj.skipped === true
          && (peObj.signatureUnscanned === true || peObj.unscanned === true
            || /too[-_ ]?large|unscanned|not[-_ ]?read|incomplete/i.test(String(peObj.reason || peObj.error || "")))) {
          peSigTrust = "unknown";
        } else if (peObj && peObj.isPe) peSigTrust = "none";
        else if (nested.length) {
          if (nested.some((n) => popupNestedSignatureTrust(n) === "invalid")) peSigTrust = "invalid";
          else if (nested.every((n) => popupNestedSignatureTrust(n) === "valid")) peSigTrust = "valid";
          else if (nested.some((n) => n.signed || popupNestedSignatureTrust(n) === "present"
            || popupNestedSignatureTrust(n) === "valid")) peSigTrust = "present";
          else peSigTrust = "none";
        }
      }
      const sha = String(vtInfo.sha256 || "").trim();
      const normalizedOuterSha = normalizePopupSha256(sha);
      const guiUrl = String(
        vtHashMismatch
          ? (normalizedOuterSha ? ("https://www.virustotal.com/gui/file/" + normalizedOuterSha) : "")
          : (vtInfo.guiUrl || (vt && vt.guiUrl) || "")
      ).trim();
      const title = vtHashMismatch
        ? (vtStatsPolicyStale ? "VT 旧缓存待重新查询" : "VT 数据与当前文件不匹配，待重新查询")
        : String(vtInfo.title || "").trim();
      const trustedSource = vtInfo.trustedSource === true;

      // 状态行（检测中必须一直显示，直到有明确结果）
      const isChecking = status === "checking" || status === "uploading";
      if (isChecking || title || status === "error" || status === "blocked" || status === "allowed" || status === "flagged") {
        const st = this.el("div", "item");
        const strong0 = document.createElement("strong");
        strong0.textContent = "文件检测: ";
        st.appendChild(strong0);
        const sp = document.createElement("span");
        const junkTitle = /自动解析失败|未自动解析/i.test(title || "");
        if (isChecking) {
          sp.className = "vt-warn";
          sp.textContent = title
            || (status === "uploading"
              ? `正在上传 ${filename}…`
              : `正在 VT 检测 ${filename}…`);
        } else if (vtHashMismatch) {
          sp.className = "vt-warn";
          sp.textContent = title;
        } else if (status === "blocked" || (vtInfo.allowed === false && status !== "done" && status !== "allowed")) {
          sp.className = "vt-bad";
          sp.textContent = junkTitle ? "已完成检测" : (title || "已拦截");
        } else if (status === "allowed") {
          sp.className = "vt-ok";
          sp.textContent = junkTitle ? "已完成检测" : (title || "VT 通过，已放行");
        } else if (status === "flagged") {
          sp.className = "vt-bad";
          sp.textContent = junkTitle ? "已完成检测" : (title || "VT 检出可疑");
        } else if (status === "error") {
          sp.className = "vt-warn";
          sp.textContent = junkTitle ? "检测未完成" : (title || "检测失败");
        } else if (title && !junkTitle) {
          sp.textContent = title;
        } else {
          sp.textContent = "";
        }
        if (sp.textContent) {
          st.appendChild(sp);
          this.root.appendChild(st);
        }
      }

      // 检测中：若已有本地解析（文件名/签名/哈希），仍展示，避免干等空白
      // 仅完全没有任何进度时才只留状态行
      const hasPartial = !!(sha || peObj || peSigner || peSigned || kind);
      if (isChecking && !hasPartial) return;

      // VT 统计（供着色 / 分行展示）
      const sumRaw = String((vt && vt.summary) || "");
      const malN = vt ? (Number(vt.malicious) || 0) : 0;
      const susN = vt ? (Number(vt.suspicious) || 0) : 0;
      const totN = vt ? (Number(vt.total) || 0) : 0;
      const trustedByGroup = new Map();
      for (const detection of (vt && Array.isArray(vt.trustedDetections) ? vt.trustedDetections : [])) {
        const rule = matchPopupVtWeightRule(detection && detection.engine)
          || (detection && detection.engine ? matchPopupVtWeightRule(detection.engine) : null);
        const canonical = (detection && detection.engine && popupTrustedVtEngine(detection.engine))
          || (rule && rule.id) || "";
        const group = (rule && rule.group)
          || (detection && detection.group)
          || String(canonical || "").toLowerCase();
        if (!canonical || !group || trustedByGroup.has(group)) continue;
        const weight = Number(detection && detection.weight) || (rule && rule.weight) || 0;
        trustedByGroup.set(group, { ...detection, engine: canonical, weight, group });
      }
      const trustedRows = Array.from(trustedByGroup.values())
        .sort((a, b) => (Number(b.weight) || 0) - (Number(a.weight) || 0));
      const trustedEngineCount = trustedRows.length;
      const trustedScoreFromVt = Number(vt && vt.trustedScore) || 0;
      const trustedScoreLocal = trustedRows.reduce((s, x) => s + (Number(x.weight) || 0), 0);
      const trustedScore = trustedScoreFromVt > 0
        ? trustedScoreFromVt
        : Math.round(trustedScoreLocal * 100) / 100;
      const trustedEngineNames = trustedRows.map((x) => x.engine);
      const trustedEngineDetails = formatPopupTrustedDetails(trustedRows);
      const trustedObservedByGroup = new Map();
      for (const result of (vt && Array.isArray(vt.trustedEngineResults) ? vt.trustedEngineResults : [])) {
        const rule = matchPopupVtWeightRule(result && result.engine);
        const canonical = popupTrustedVtEngine(result && result.engine) || (rule && rule.id) || "";
        const group = (rule && rule.group) || String(canonical || "").toLowerCase();
        if (canonical && group && !trustedObservedByGroup.has(group)) {
          trustedObservedByGroup.set(group, { ...result, engine: canonical });
        }
      }
      const trustedObservedNames = Array.from(trustedObservedByGroup.values()).map((x) => x.engine);
      const trustedObservedCount = trustedObservedNames.length;
      const trustedHard = !!(vt && vt.trustedScoreHardBlock)
        || popupVtScoreIsHardBlock(trustedScore, trustedEngineCount);
      const unscopedVtSource = !!(vt
        && /^(?:vt-page-component|vt-dom)$/i.test(String(vt.source || "")));
      // softMiss / unknown 绝不当「VT: 无」
      const nestedHasVtHit = nested.some((n) => {
        const nv = popupNestedVtMatchesItem(n) ? n.vt : null;
        return !!(nv && nv.found === true && nv.notFound !== true && !nv.unknown
          && ((Number(nv.malicious) || 0) + (Number(nv.suspicious) || 0) > 0 || Number(nv.total) > 0));
      });
      const isArchiveShellUi = (kind === "archive" || kind === "package" || /\.(?:zip|rar|7z|cab|iso)$/i.test(filename))
        && kind !== "apk"
        && !(peObj && peObj.isPe && !peObj.skipped);
      // 压缩包外壳「无」：包内已有检出时不当主结论（灰鸽子 zip 外壳无记录、exe 高检出）
      const rawVtNone = !!(vt && vt.notFound === true && vt.verifiedNotFound === true
        && !vt.softMiss && vt.unknown !== true);
      const vtNone = rawVtNone && !(isArchiveShellUi && nestedHasVtHit)
        && !(vt && vt.deferToNested && nestedHasVtHit);
      const unverifiedMiss = !!(vt && vt.notFound === true && vt.verifiedNotFound !== true);
      const vtHit = !!(vt && !unscopedVtSource && (vt.found === true
        || (vt.malicious != null && vt.notFound !== true && !vt.unknown && !vt.softMiss)));
      const vtUnknown = !!(vt && !vtNone && !vtHit && !nestedHasVtHit
        && (vt.unknown || vt.softMiss || vt.found == null || vt.needApiKey || unverifiedMiss
          || unscopedVtSource));
      const isJunkVtSummary = /自动解析失败|未自动解析|查询未完成|查询异常|查询超时|仍被验证码|需配置免费 API/i.test(sumRaw);
      const mal = malN;
      const sus = susN;

      // —— ① 文件名单独一行 ——
      const fileRow = this.el("div", "item file-row");
      const fileLabel = document.createElement("strong");
      fileLabel.textContent = kind ? `${kindLabel}: ` : "文件: ";
      fileRow.appendChild(fileLabel);
      const fileSp = document.createElement("span");
      fileSp.className = "file-name";
      fileSp.textContent = filename.length > 48 ? filename.slice(0, 46) + "…" : filename;
      fileRow.appendChild(fileSp);
      this.root.appendChild(fileRow);

      // 检测中且尚无 VT 结论：写「查询中」；若已超时很久则提示结束态文案
      const ageMs = Date.now() - (Number(vtInfo.timestamp) || 0);
      if (isChecking && !vtNone && !vtHit) {
        const vtWait = this.el("div", "item");
        const vtWaitL = document.createElement("strong");
        vtWaitL.textContent = "VT: ";
        vtWait.appendChild(vtWaitL);
        const vtWaitSp = document.createElement("span");
        vtWaitSp.className = "vt-warn";
        if (ageMs > 45000) {
          vtWaitSp.textContent = "查询超时，请重新下载触发检测或配置 API Key";
        } else if (status === "uploading") {
          vtWaitSp.textContent = "正在上传样本…";
        } else {
          vtWaitSp.textContent = "查询中…";
        }
        vtWait.appendChild(vtWaitSp);
        this.root.appendChild(vtWait);
      }

      // —— ② 数字签名单独一行 ——
      // 压缩包外壳无 Authenticode：不显示外层「数字签名: 无」，只展示包内成员
      // APK 外层可显示 JAR/v1 签名状态
      const isArchiveShell = (kind === "archive" || kind === "package"
        || /\.(?:zip|rar|7z|cab|iso)$/i.test(filename))
        && kind !== "apk"
        && !(peObj && peObj.isPe && !peObj.skipped);
      const showOuterSig = !isArchiveShell && (kind === "pe" || kind === "msi" || kind === "apk"
        || peSigned || peSigner || (peObj && peObj.isPe)
        || peSigTrust === "unknown" || peSigTrust === "unscanned"
        || peSigTrust === "none" || peSigTrust === "present" || peSigTrust === "valid" || peSigTrust === "invalid");
      if (showOuterSig) {
        const sigRow = this.el("div", "item sig-row");
        const sigLabel = document.createElement("strong");
        sigLabel.textContent = "数字签名: ";
        sigRow.appendChild(sigLabel);
        const sigSp = document.createElement("span");
        const caLike = /DigiCert|Sectigo|GlobalSign|VeriSign|Symantec|GeoTrust|Thawte|Comodo|USERTrust|Let's\s*Encrypt|\bCA\b|\bRoot\b|Time\s*Stamp/i.test(peSigner);
        const signerName = peSigner && !caLike ? peSigner : "";

        if (peSigTrust === "valid") {
          sigSp.className = "sig-valid";
          sigSp.textContent = signerName ? `${signerName}（VT 有效）` : "有（VT 验证有效）";
        } else if (peSigTrust === "invalid") {
          sigSp.className = "sig-invalid";
          sigSp.textContent = signerName ? `${signerName}（无效/不可信）` : "无效或不生效";
        } else if (peSigTrust === "unknown" || peSigTrust === "unscanned") {
          sigSp.className = "sig-black";
          const tooLarge = /too[-_ ]?large|超过.*(?:mb|大小)/i.test(String(
            (peObj && (peObj.reason || peObj.error))
            || (sigInfo && sigInfo.reason)
            || ""
          ));
          sigSp.textContent = tooLarge
            ? "未检测（文件超过650MB，未完整读取）"
            : "未检测（文件未完整读取）";
        } else if (peSigTrust === "none") {
          sigSp.className = "sig-none";
          sigSp.textContent = "无";
        } else if (peSigTrust === "present" || peSigned || signerName) {
          sigSp.className = "sig-black";
          sigSp.textContent = signerName || "有（未获 VT 真伪结论）";
        } else {
          sigSp.className = "sig-none";
          sigSp.textContent = "无";
        }
        sigRow.appendChild(sigSp);
        this.root.appendChild(sigRow);
      }

      // 包内：文件一行 + 签名一行（压缩包只看这里）
      if (nested.length) {
          for (const n of nested.slice(0, 8)) {
            const nestName = n.name || n.path || "文件";
            const nameRow = this.el("div", "item sig-nested");
            const nameLabel = document.createElement("strong");
            nameLabel.textContent = "包内文件: ";
            nameRow.appendChild(nameLabel);
            const nameSp = document.createElement("span");
            nameSp.className = "file-name";
            nameSp.textContent = nestName;
            nameRow.appendChild(nameSp);
            this.root.appendChild(nameRow);

            const nestSigRow = this.el("div", "item sig-nested sig-nested-indent");
            const nestSigLabel = document.createElement("strong");
            nestSigLabel.textContent = "数字签名: ";
            nestSigRow.appendChild(nestSigLabel);
            const nestSp = document.createElement("span");
            const nt = popupNestedSignatureTrust(n);
            const ns = String(n.signer || n.signerHint || "").trim();
            if (nt === "valid") {
              nestSp.className = "sig-valid";
              nestSp.textContent = ns ? `${ns}（VT 有效）` : "有（VT 有效）";
            } else if (nt === "invalid") {
              nestSp.className = "sig-invalid";
              nestSp.textContent = ns ? `${ns}（无效）` : "无效";
            } else if (nt === "unknown" || nt === "unscanned") {
              nestSp.className = "sig-black";
              nestSp.textContent = "未检测（文件未完整读取）";
            } else if (nt === "none") {
              nestSp.className = "sig-none";
              nestSp.textContent = n.kind === "msi"
                ? "MSI（未解析签名）"
                : (n.note ? String(n.note) : "无");
            } else if (n.signed || nt === "present") {
              nestSp.className = "sig-black";
              nestSp.textContent = ns || "有";
            } else {
              nestSp.className = "sig-none";
              nestSp.textContent = n.kind === "msi"
                ? "MSI（未解析签名）"
                : (n.note ? String(n.note) : "无");
            }
            nestSigRow.appendChild(nestSp);
            this.root.appendChild(nestSigRow);

            // 包内 VT 结果（含指定权威引擎明细，若有）
            const nvt = popupNestedVtMatchesItem(n) ? n.vt : null;
            if (nvt) {
              const nestVtRow = this.el("div", "item sig-nested sig-nested-indent");
              const nestVtLabel = document.createElement("strong");
              nestVtLabel.textContent = "VirusTotal: ";
              nestVtRow.appendChild(nestVtLabel);
              const nestVtSp = document.createElement("span");
              const nMal = Number(nvt.malicious) || 0;
              const nSus = Number(nvt.suspicious) || 0;
              const nTot = Number(nvt.total) || 0;
              const nTrusted = Number(nvt.trustedEngineCount) || Number(nvt.trustedMaliciousCount) || 0;
              const nScore = Number(nvt.trustedScore) || 0;
              const nTrustedDetails = formatPopupTrustedDetails(nvt.trustedDetections).slice(0, 5);
              if (nvt.notFound) {
                nestVtSp.className = "vt-warn";
                nestVtSp.textContent = "无";
              } else if (nvt.found === true) {
                const nHard = !!(nvt.trustedScoreHardBlock)
                  || popupVtScoreIsHardBlock(nScore, nTrusted);
                nestVtSp.className = nMal >= 3 || nHard || nTrusted >= 2 ? "vt-bad" : (nMal > 0 ? "vt-warn" : "vt-ok");
                let line = nTot > 0
                  ? `检出 ${nMal + nSus}/${nTot}（恶意 ${nMal} / 可疑 ${nSus}）`
                  : `恶意 ${nMal} · 可疑 ${nSus}`;
                if (nTrusted >= 1 && nTrustedDetails.length) {
                  line += ` · 权威引擎 ${nTrusted} 家：${nTrustedDetails.join("、")}`;
                } else if (nMal + nSus > 0 && nvt.engineDetailsAvailable !== true) {
                  line += " · 未取到权威引擎逐条明细";
                }
                nestVtSp.textContent = line;
              } else {
                nestVtSp.className = "vt-warn";
                nestVtSp.textContent = "未取到结论";
              }
              nestVtRow.appendChild(nestVtSp);
              this.root.appendChild(nestVtRow);
              const nGui = String(nvt.guiUrl || (n.sha256 ? ("https://www.virustotal.com/gui/file/" + n.sha256) : "")).trim();
              if (nGui && /^https:\/\/www\.virustotal\.com\//i.test(nGui)) {
                const linkRow = this.el("div", "item vt-link sig-nested-indent");
                const a = document.createElement("a");
                a.href = nGui;
                a.target = "_blank";
                a.rel = "noopener noreferrer";
                a.className = "vt-a";
                a.textContent = "在 VT 查看此包内文件 →";
                linkRow.appendChild(a);
                this.root.appendChild(linkRow);
              }
            }
          }
        } else if (isArchiveShell) {
          // 无目标文件时：仅在有说明时显示；纯文档压缩包不刷错误
          const note = String(vtInfo.archiveNote || "").trim();
          const fmt = String(vtInfo.archiveFormat || "").trim();
          if (note || fmt === "rar" || fmt === "7z") {
            const nestRow = this.el("div", "item sig-nested");
            const nestSp = document.createElement("span");
            nestSp.className = "sig-black";
            if (note) nestSp.textContent = note;
            else nestSp.textContent = "压缩包内未发现支持检测的可执行文件";
            nestRow.appendChild(nestSp);
            this.root.appendChild(nestRow);
          }
        }

      // —— ③ VT 单独一行（压缩包：包内已展示检出时，外壳只作次要说明）——
      let vtLine = "";
      let vtLineIsShellNote = false;
      if (vtHashMismatch) {
        vtLine = "VT 数据与当前文件 SHA256 不匹配，待重新查询";
      } else if (isArchiveShellUi && nestedHasVtHit && (rawVtNone || (vt && vt.deferToNested))) {
        // 包内已有 19/69 等结论：外壳「无」降级，避免误读成整包干净
        vtLine = "压缩包外壳无 VT 记录（以上方包内文件为准）";
        vtLineIsShellNote = true;
      } else if (vtHit) {
        if (sumRaw && !isJunkVtSummary && /检出|恶意|VT/i.test(sumRaw)) {
          vtLine = sumRaw.replace(/^VT:\s*/i, "VT: ");
        } else {
          vtLine = totN > 0
            ? `VT 检出 ${malN + susN}/${totN}（恶意 ${malN} / 可疑 ${susN}）`
            : `VT 恶意 ${malN} · 可疑 ${susN}`;
        }
      } else if (vtNone) {
        vtLine = isArchiveShellUi
          ? (/已自动上传|已自动提交|已提交文件/i.test(sumRaw)
            ? sumRaw
            : "压缩包外壳无 VT 记录")
          : (/已自动上传|已自动提交|已提交文件|可手动提交|上传文件/i.test(sumRaw) ? sumRaw : "VT: 无");
      } else if (vtUnknown) {
        vtLine = unscopedVtSource
          ? "VT: 旧版页面比例未通过主报告校验，请重新检测"
          : (unverifiedMiss
          ? "VT: 自动取数未确认，请重新检测"
          : (sumRaw && !isJunkVtSummary
          ? sumRaw
          : "VT: 查询未完成（建议配置 API Key）"));
      }
      if (vtLine) {
        const vtRow = this.el("div", "item vt-block");
        const vtLabel = document.createElement("strong");
        vtLabel.textContent = vtLineIsShellNote || (isArchiveShellUi && (rawVtNone || vtNone))
          ? "外壳VirusTotal: "
          : "VirusTotal: ";
        vtRow.appendChild(vtLabel);
        const vtSp = document.createElement("span");
        vtSp.className = "vt-text";
        if (vtLineIsShellNote) vtSp.className += " vt-muted";
        else if (vtHashMismatch) vtSp.className += " vt-warn";
        else if (unscopedVtSource) vtSp.className += " vt-warn";
        else if (trustedHard || trustedEngineCount >= 2 || status === "blocked" || status === "flagged") vtSp.className += " vt-bad";
        else if (vtNone || (!peSigned && (kind === "pe" || (peObj && peObj.isPe)))) vtSp.className += " vt-warn";
        else if (mal > 0 || sus >= 3) vtSp.className += " vt-warn";
        else if (status === "allowed" || (vtHit && mal === 0)) vtSp.className += " vt-ok";
        vtSp.textContent = vtLine.replace(/^VT:\s*/i, "").replace(/^VirusTotal:\s*/i, "");
        vtRow.appendChild(vtSp);
        this.root.appendChild(vtRow);
      }

      // —— ④ SHA256 单独一行 ——
      if (sha) {
        const shaRow = this.el("div", "item sha-row");
        const shaLabel = document.createElement("strong");
        shaLabel.textContent = isArchiveShellUi ? "压缩包SHA256: " : "SHA256: ";
        shaRow.appendChild(shaLabel);
        const shaSp = document.createElement("span");
        shaSp.className = "sha-text";
        shaSp.textContent = sha.slice(0, 20) + "…";
        shaSp.title = sha;
        shaRow.appendChild(shaSp);
        this.root.appendChild(shaRow);
      }

      // —— 风险检测（始终尝试输出）——
      let risks = Array.isArray(vtInfo.risks)
        ? vtInfo.risks.filter((r) => r && r.text && !/^(?:签署者|发布者|数字签名):/i.test(r.text)
          && !/^VT\s+(?:知名引擎|权威引擎|单个知名|单个权威|总检出|指定五家|指定引擎未检出)/i.test(r.text)
          && !((vtHit || vtUnknown) && /VT 无此文件记录/i.test(r.text))
          && !(unscopedVtSource && /\bVT\b|VirusTotal/i.test(r.text))
          && !/未自动解析|自动解析失败|请点开链接确认|请点开链接或配置/i.test(r.text))
        : [];
      if (vtHashMismatch) {
        risks = risks.filter((r) => !/\bVT\b|VirusTotal/i.test(String((r && r.text) || "")));
      }
      if (!risks.length) {
        if (peSigTrust === "invalid") {
          risks.push({ level: "high", text: "数字签名无效/不可信" });
        } else if (!trustedSource && vtInfo.gated && (kind === "pe" || (peObj && peObj.isPe)) && peSigTrust === "none") {
          risks.push({ level: "medium", text: "未检测到数字签名（来源页处于下载保护状态）" });
        } else if (!trustedSource && vtInfo.gated && nested.length
          && nested.filter((n) => n.kind === "pe" || /\.exe|\.dll/i.test(n.name || ""))
            .every((n) => !n.signed
              && !/^(?:unknown|unscanned)$/i.test(String(n.trust || n.sigTrust || "")))) {
          const peN = nested.filter((n) => n.kind === "pe" || /\.exe|\.dll/i.test(n.name || ""));
          if (peN.length) risks.push({ level: "medium", text: "压缩包内可执行文件均未检测到数字签名" });
        }
        if (vtHit && trustedHard) {
          risks.push({
            level: "high",
            text: `VT 权威引擎共识 ${trustedEngineCount} 家：${trustedEngineDetails.join("、") || trustedEngineNames.join("、") || "已确认恶意"}`
          });
        } else if (vtHit && trustedEngineCount >= 2) {
          risks.push({
            level: trustedScore >= 4.5 ? "high" : "medium",
            text: `VT 权威引擎检出 ${trustedEngineCount} 家：${trustedEngineDetails.join("、") || trustedEngineNames.join("、") || "已确认"}`
          });
        } else if (vtHit && trustedEngineCount === 1) {
          risks.push({
            level: "medium",
            text: `VT 单个权威引擎检出：${trustedEngineDetails[0] || trustedEngineNames[0] || "未知"}（尚未形成共识）`
          });
        } else if (vtHit && (mal >= 1 || sus >= 1) && vt.engineDetailsAvailable !== true) {
          risks.push({ level: "medium", text: `VT 总检出 ${mal + sus} 家；正在补取逐引擎检测结果` });
        } else if (vtHit && (mal >= 1 || sus >= 1)) {
          if (trustedObservedCount >= VT_ENGINE_WEIGHT_TABLE.length) {
            risks.push({ level: "low", text: "VT 权威引擎均未检出（总表有检出，可能为低权重引擎）" });
          } else if (trustedObservedCount > 0) {
            risks.push({
              level: "medium",
              text: `VT 权威引擎未检出（已取得 ${trustedObservedCount}/${VT_ENGINE_WEIGHT_TABLE.length} 家明细：${trustedObservedNames.join("、")}）`
            });
          } else {
            risks.push({ level: "medium", text: `VT 总检出 ${mal + sus} 家；尚未取得权威引擎明细` });
          }
        }
        else if (vtHit && mal === 0) risks.push({ level: "low", text: "VT 未见恶意检出" });
      }
      for (const r of risks) {
        const lv = String(r.level || "info");
        const cls = lv === "high" ? "vt-bad" : lv === "medium" ? "vt-warn" : lv === "low" ? "vt-ok" : "";
        const riskRow = this.el("div", "item");
        const label = document.createElement("strong");
        label.textContent = "风险检测: ";
        riskRow.appendChild(label);
        const sp = document.createElement("span");
        if (cls) sp.className = cls;
        sp.textContent = String(r.text || "").replace(/^风险:\s*/, "");
        riskRow.appendChild(sp);
        this.root.appendChild(riskRow);
      }

      if (guiUrl && /^https:\/\/www\.virustotal\.com\//i.test(guiUrl)) {
        const linkRow = this.el("div", "item vt-link");
        const a = document.createElement("a");
        a.href = guiUrl;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = vtNone
          ? "在 VT 查看此哈希 →"
          : (vtUnknown ? "在 VirusTotal 查看此文件 →" : "在 VirusTotal 打开 →");
        a.className = "vt-a";
        linkRow.appendChild(a);
        this.root.appendChild(linkRow);
      } else if (vtUnknown && sha) {
        // 无 guiUrl 时仍给可点哈希
        const linkRow = this.el("div", "item vt-link");
        const a = document.createElement("a");
        a.href = "https://www.virustotal.com/gui/file/" + sha;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = "在 VirusTotal 查看此文件 →";
        a.className = "vt-a";
        linkRow.appendChild(a);
        this.root.appendChild(linkRow);
      }
      // VT 无结果 / 已真·文件上传
      // 压缩包：包内已有检出时不提示「库中无此样本/上传外壳」（避免 zip 无盖过 exe 19/69）
      const feedSubmitted = !!(vt && (vt.feedSubmitted || vt.submitted));
      const suppressShellNoneTip = !!(isArchiveShellUi && nestedHasVtHit && (rawVtNone || (vt && vt.deferToNested)));
      if (!suppressShellNoneTip && (vtNone || vtUnknown || feedSubmitted || (vt && vt.needCaptcha))) {
        const tip = this.el("div", "item");
        const tipSp = document.createElement("span");
        tipSp.className = feedSubmitted ? "vt-ok" : "vt-warn";
        if (feedSubmitted) {
          tipSp.textContent = "已自动上传文件到 VirusTotal 分析";
        } else if (vtUnknown || (vt && (vt.needApiKey || vt.captcha || vt.softMiss))) {
          if (vt && vt.captcha) {
            tipSp.textContent = "当前 VT 页面会话要求人机验证；可点开上方链接完成验证";
          } else if (vt && vt.authBlocked) {
            tipSp.textContent = "VT 拒绝扩展自动读取（HTTP 401/403）；网页本身仍可人工查看";
          } else if (vt && vt.rateLimited) {
            tipSp.textContent = "VT 自动接口已限流（HTTP 429）；请稍后重试或配置 API Key";
          } else if (/已使用当前浏览器会话加载页面|页面已加载，但未抓到可解析/i.test(sumRaw)) {
            tipSp.textContent = "VT 页面已加载，但统计组件未被自动解析；可点开链接查看";
          } else {
            tipSp.textContent = "VT 自动取数未完成；可点开链接查看，或在设置中配置 API Key 稳定自动读取";
          }
        } else if (vtNone) {
          tipSp.textContent = isArchiveShellUi
            ? "压缩包外壳无 VT 记录；若包内有可执行文件请以上方包内结果为准"
            : "VT 库中无此样本：可手动提交文件";
        } else {
          tipSp.textContent = "可打开 VT 查看或手动提交文件";
        }
        tip.appendChild(tipSp);
        this.root.appendChild(tip);

        // 用户点击才打开；已提交优先链到文件/分析页
        // 压缩包外壳「无」且无包内命中时才推上传页
        if (!(isArchiveShellUi && rawVtNone && nestedHasVtHit)) {
          const up = String(
            (feedSubmitted && vt && vt.guiUrl)
              || (vt && vt.uploadUrl)
              || "https://www.virustotal.com/gui/home/upload"
          );
          const linkRow2 = this.el("div", "item vt-link");
          const a2 = document.createElement("a");
          a2.href = up;
          a2.target = "_blank";
          a2.rel = "noopener noreferrer";
          a2.className = "vt-a";
          a2.textContent = feedSubmitted && vt && vt.guiUrl
            ? "在 VirusTotal 查看文件分析结果 →"
            : "打开 VT 文件上传页 →";
          linkRow2.appendChild(a2);
          this.root.appendChild(linkRow2);
        }
      }
    }

    /** 报告是否已完成扫描（或轻量路径）。 */
    isCompletedReport(data) {
      if (!data || typeof data !== "object") return false;
      if (data.analysisComplete === false) return false;
      if (data.analysisComplete === true) return true;
      // Legacy reports without an explicit completion bit may still surface a
      // concrete threat, but an old score-0/identity-only snapshot is not proof
      // that the current (possibly background-frozen) document finished. Wake
      // the content script instead of reviving the former default-safe UI.
      if (data.downloadGuardInstalled || data.packageBlocked || data.brandSpoofPortal || data.spoofBrand) return true;
      if (Array.isArray(data.details) && data.details.length > 0) return true;
      if ((Number(data.score) || 0) > 0 || /^(?:medium|high)$/i.test(String(data.riskLevel || ""))) return true;
      return false;
    }

    identityRiskFromData(data) {
      const details = Array.isArray(data?.details) ? data.details : [];
      return details.find((d) => /假冒ICP备案信息|页面冒用ICP备案号|备案信息无法核验|域名备案身份异常/i.test(`${d?.name || ""} ${d?.reason || ""}`)) || null;
    }

    /** 报告自身声明包保护仍 armed。 */
    reportHasProtection(data) {
      if (!data) return false;
      if (data.downloadGuardInstalled || data.packageBlocked) return true;
      if (Array.isArray(data.protectedTargets) && data.protectedTargets.length > 0) return true;
      if (Array.isArray(data.details) && data.details.some((d) =>
        /已启用安装包下载拦截|已启用仿冒站下载拦截|已启用异常跳转拦截|下载入口已禁用|下载拦截|已拦截可疑/i.test(d.name || ""))) return true;
      return false;
    }

    looksLikePackageTarget(t) {
      const s = String(t || "");
      if (!s) return false;
      if (/^https?:\/\//i.test(s) && /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(s)) return true;
      if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/i.test(s.split("/").pop() || "")) return true;
      return false;
    }

    looksLikeSearchOrNonPackageTarget(t) {
      const s = String(t || "");
      if (!s || this.looksLikePackageTarget(s)) return false;
      try {
        const u = new URL(s);
        const path = (u.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
        const q = u.search || "";
        if (q && q.length >= 2) {
          if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search)=[^&]+/i.test(q)) return true;
          if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p)=[^&]+/i.test(q)) return true;
          if (/\/(?:url|link|redirect|rd|jump)$/i.test(path) && /[?&](?:q|url|u|target|to|redir|redirect)=[^&]+/i.test(q)) return true;
        }
      } catch { /* not url */ }
      return /^https?:\/\//i.test(s) && !this.looksLikePackageTarget(s);
    }

    sanitizeSpoofBrandName(raw, opts = {}) {
      const confirmedIdentity = opts.confirmedIdentity === true;
      let s = String(raw || "")
        .trim()
        .replace(/(?:官方网站下载|官方网站|官网(?:下载)?|官方(?:下载)?|免费下载|下载)$/u, "")
        .trim();
      if (!s) return "";
      if (/^(?:品牌|产品|功能|特性|特色|方案|官网|官方)$/.test(s)) return "";
      // 语言/地区/版本标签不是产品品牌；旧报告详情也不得把它回捞进标题。
      if (/^(?:中文|英文|英语|汉语|简体|繁体|简体中文|繁体中文|国语|粤语|日文|日语|韩文|韩语|语言|版本|国际|国内|大陆|台湾|香港|海外)$/.test(s)) return "";
      // 仅对 popup 自己从 host 猜出的候选做“域名碎片”过滤。
      // content 已确认并写入 spoofBrand / 详情 / 通知的品牌不可在这里反向推翻：
      // ToDesk @ to-desk、DingTalk @ ding-talk 的相等/近形本来就是仿冒域名证据。
      if (!confirmedIdentity) try {
        const host = String(this.activeTabUrl || "")
          .replace(/^https?:\/\//i, "").split("/")[0].toLowerCase().replace(/^www\./, "");
        const labelRaw = (host.split(".")[0] || "").toLowerCase();
        const lab = labelRaw.replace(/[^a-z0-9]/g, "");
        const flat = s.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (lab && flat) {
          if (flat === lab) return "";
          // 近形主机 flat（差 1～2 字母，如 Dingappsdingdin ≈ dingappsdingding）
          if (flat.length >= 8 && lab.length >= 8 && Math.abs(flat.length - lab.length) <= 2) {
            let diff = 0;
            const a = flat.length <= lab.length ? flat : lab;
            const b = flat.length <= lab.length ? lab : flat;
            let i = 0;
            let j = 0;
            while (i < a.length && j < b.length) {
              if (a[i] === b[j]) { i++; j++; }
              else { diff++; j++; if (diff > 2) break; }
            }
            diff += a.length - i;
            if (diff <= 2) return "";
          }
          if (flat.startsWith(lab)
            && /^(?:lab|labs|soft|app|pro|vip|safe|pc|tech|site)$/i.test(flat.slice(lab.length))) {
            return "";
          }
          // 多段连字符拼接影子：ding-apps-dingding → Dingappsdingding
          if (/-/.test(labelRaw)) {
            const segs = labelRaw.split("-").map((x) => x.replace(/[^a-z0-9]/g, "")).filter(Boolean);
            const joined = segs.join("");
            if (joined && (flat === joined || (flat.length >= 8 && joined.includes(flat) && flat.length >= joined.length - 2))) {
              return "";
            }
            const head = (segs[0] || "");
            if (head.length >= 4 && flat === head + "lab") return "";
            if (head.length >= 4 && flat === head + "labs") return "";
            // 有 apps 中缀时剥出最长品牌段作展示
            if (segs.some((p) => /^(?:apps?)$/i.test(p))) {
              const brandish = segs.filter((p) => p.length >= 4 && !/^(?:apps?|soft|pc|lab|labs)$/i.test(p));
              brandish.sort((a, b) => b.length - a.length);
              if (brandish[0] && (flat.includes(brandish[0]) || joined.includes(flat))) {
                const core = brandish[0];
                return core.charAt(0).toUpperCase() + core.slice(1);
              }
            }
          }
          if (flat.length > 6 && /(?:lab|labs)$/i.test(flat)) {
            const stem = flat.replace(/(?:lab|labs)$/i, "");
            if (stem.length >= 4 && (lab === stem || lab.startsWith(stem) || lab.includes(stem))) {
              s = stem.charAt(0).toUpperCase() + stem.slice(1);
              return s;
            }
          }
        }
      } catch { /* ignore */ }

      // 旧报告可能在扩展刷新期间被短暂复用。这里按语言结构再守一次 UI 边界，
      // 避免旧版误抽出的功能标签重新出现在「仿冒某某官网」里。
      let compact = s.replace(/[\s_\-–—|·:：/\\]+/g, "");
      if (/^(\d{2,4})\1$/.test(compact)) return "";
      const yearHit = compact.match(/^((?:19|20)\d{2})年?(.{0,12})$/u);
      if (yearHit) {
        const year = Number(yearHit[1]);
        const currentYear = new Date().getFullYear();
        if (year >= currentYear - 5 && year <= currentYear + 2) return "";
      }
      if (/^(?:pc|win(?:dows)?|mac(?:os)?|linux|android|ios|iphone|ipad|web|x86|x64|arm(?:32|64)?|32bit|64bit|32位|64位)(?:端|平台)?(?:版|版本|客户端|下载)?$/i.test(compact)) return "";
      if (/^(?:电脑|桌面|手机|移动|网页|安卓|苹果|鸿蒙|通用|绿色|便携|免安装|安装|免费|正式|官方|最新|新|旧|专业|企业|个人|家庭|教育|国际|中文|测试|开发|稳定|会员)(?:版|版本)$/u.test(compact)) return "";

      const mediaCore = compact
        .replace(/^(?:(?:hi|ultra|full)?(?:res|hd|uhd|hdr|hifi)|dolby|dts)/i, "")
        .replace(/[A-Za-z0-9]/g, "");
      if (mediaCore && /^(?:(?:超|极|至臻|高|专业|影院级|母带级)?(?:高清|超清|无损|高保真|高解析|高码率|沉浸式?|臻品|卓越|极致|纯净))+(?:音质|音效|声效|画质|品质|听感|视听|影音|体验|播放|解码)$/.test(mediaCore)) return "";

      const latinWords = s.split(/[\s_\-–—]+/).filter(Boolean);
      const genericModifier = /^(?:best|my|online|cloud|remote|batch|download|free|official|file|files|pdf|video|audio|music|screen|system|web|pc|mobile|smart|quick|easy|fast|secure|security|photo|image|data|disk|office)$/i;
      const genericCapability = /^(?:tools?|apps?|editors?|storage|desktop|rename|centers?|managers?|players?|recorders?|converters?|downloaders?|cleaners?|updaters?|utilit(?:y|ies)|clients?|software|drives?|assistants?|controls?|backup|sync|compressors?|archivers?)$/i;
      if (latinWords.length >= 2
        && latinWords.every((part) => genericModifier.test(part) || genericCapability.test(part))
        && latinWords.some((part) => genericCapability.test(part))) return "";

      // 基础设施/分发前缀若包住一个独立 CamelCase 名称，只保留后面的身份核。
      // 例如旧版 CloudToDesk -> ToDesk；Cloud Drive 的 Drive 是功能词，仍会被丢弃。
      const wrapped = s.match(/^(?:cloud|online|official|download|app|web|pc|free)[\s_\-–—]*([A-Za-z][A-Za-z0-9]{3,})$/i);
      if (wrapped && wrapped[1] && /[A-Z]/.test(wrapped[1])) {
        if (genericCapability.test(wrapped[1])) return "";
        s = wrapped[1].charAt(0).toUpperCase() + wrapped[1].slice(1);
        compact = s.replace(/[\s_\-–—|·:：/\\]+/g, "");
      }

      const mixed = compact.match(/^([A-Za-z][A-Za-z0-9]{1,11})([一-鿿]{2,10})$/);
      if (mixed
        && /^(?:ai|pdf|gpt|ocr|nlp|ml|llm|pc|web|app)$/i.test(mixed[1])
        && /(?:智能)?(?:重?命名|改名|编辑|推荐|生成|识别|分析|检测|搜索|翻译|创作|剪辑|修复|转换|处理|管理|优化|加速|同步|备份|清理|压缩|解压|录制|播放|下载|安装|截图|桌面|控制|协助|协作|连接|访问|办公|会议|教育|助手|运维|操作|服务)$/.test(mixed[2])) return "";

      const modeLead = /^(?:智能|自动|一键|在线|离线|实时|快速|极速|精准|批量|免费|专业|高效|便捷|云端|本地|远程|桌面|移动|跨端|跨平台|多端|多人|团队)/;
      const capabilityTail = /(?:重?命名|改名|编辑|推荐|生成|识别|分析|检测|搜索|翻译|创作|剪辑|修复|转换|处理|管理|优化|加速|同步|备份|清理|压缩|解压|录制|播放|下载|安装|截图|桌面|控制|协助|协作|连接|访问|办公|会议|教育|助手|运维|操作|服务)$/;
      if (modeLead.test(compact) && capabilityTail.test(compact)) return "";
      if (compact.length >= 4 && modeLead.test(compact)
        && /(?:远程)?(?:控|协|连|访|运)$/.test(compact)) return "";
      return s;
    }

    brandSpoofFromData(data) {
      if (!data) return "";
      if (data.spoofBrand) {
        const direct = this.sanitizeSpoofBrandName(data.spoofBrand, { confirmedIdentity: true });
        if (direct) return direct;
      }
      // 内容侧早期 arm 可能未写入 spoofBrand，但信号详情已有「标题/正文品牌「xxx」」
      // 仅在 brandSpoofPortal 或仿冒信号存在时回捞，且经 sanitize 过滤功能词。
      try {
        const portal = !!(data.brandSpoofPortal
          || (Array.isArray(data.details) && data.details.some((d) => /仿冒品牌官网/i.test(d?.name || ""))));
        if (portal && Array.isArray(data.details)) {
          for (const d of data.details) {
            const r = String(d?.reason || d?.name || "");
            const m = r.match(/品牌「([^」]{2,24})」/)
              || r.match(/仿冒「([^」]{2,24})」/);
            if (!m || !m[1]) continue;
            const got = this.sanitizeSpoofBrandName(m[1], { confirmedIdentity: true });
            if (got) return got;
          }
        }
        // 详情仍中性时：从主机夹带结构回推展示名（j-dingtalk → DingTalk）
        // popup 无 content 命名空间，只做结构剥前缀，不发明品牌字典
        if (portal) {
          const host = String(data.host || data.hostname || "").toLowerCase().replace(/^www\./, "");
          const label = (host.split(".")[0] || "");
          if (label && /-/.test(label)) {
            const parts = label.split("-").filter(Boolean);
            if (parts.length >= 2) {
              const first = parts[0];
              const rest = parts.slice(1).join("");
              if (rest.length >= 4 && (first.length === 1 || first.length <= 4)
                && /^(?:j|v|x|z|e|a|s|im|ie|pr|ca|pc|app|get|ott|qq|wx|dl)?$/i.test(first)) {
                const camel = rest.charAt(0).toUpperCase() + rest.slice(1).toLowerCase();
                // desk/talk 形态粗分：dingtalk → DingTalk（末 4 字母大写）
                let disp = camel;
                if (/talk$/i.test(rest) && rest.length >= 6) {
                  disp = rest.slice(0, -4).charAt(0).toUpperCase()
                    + rest.slice(1, -4).toLowerCase()
                    + "Talk";
                } else if (/desk$/i.test(rest) && rest.length >= 6) {
                  disp = rest.slice(0, -4).charAt(0).toUpperCase()
                    + rest.slice(1, -4).toLowerCase()
                    + "Desk";
                }
                const got = this.sanitizeSpoofBrandName(disp);
                if (got) return got;
              }
            }
          }
        }
      } catch { /* ignore */ }
      return "";
    }

    /** 同页品牌通知已定稿、风险报告仍处于极短竞态时，用通知补齐 popup 展示名。 */
    brandSpoofFromNotice(notice) {
      try {
        if (!notice) return "";
        const blob = `${notice.title || ""} ${notice.message || ""}`;
        if (notice.guardKind !== "brand-spoof" && !/仿冒「[^」]+」官网|品牌「[^」]+」/.test(blob)) return "";
        const m = blob.match(/仿冒「([^」]{2,28})」官网/)
          || blob.match(/品牌「([^」]{2,28})」/);
        return m && m[1]
          ? this.sanitizeSpoofBrandName(m[1], { confirmedIdentity: true })
          : "";
      } catch {
        return "";
      }
    }

    /** 通知仅对当前页面 URL 有效；永不回退到 tabId-only。 */
    noticeMatchesTab(latestNotice, tabId, tabUrl, analysisTxn = "") {
      if (!latestNotice) return false;
      if (latestNotice.tabId != null && latestNotice.tabId !== tabId) return false;
      if (!tabUrl || !latestNotice.url) return false;
      if (!urlsMatch(latestNotice.url, tabUrl)) return false;
      const noticeTxn = popupRiskTxn(latestNotice);
      const currentTxn = String(analysisTxn || "").trim();
      if (noticeTxn || currentTxn) return !!(noticeTxn && currentTxn && noticeTxn === currentTxn);
      return true;
    }

    isPackageDetectionNotice(latestNotice) {
      if (!latestNotice) return false;
      const kind = String(latestNotice.guardKind || "").toLowerCase();
      if (kind === "package" || kind === "package-vt") return true;
      if (kind) return false;
      return /\bSHA256\s*:\s*[a-f0-9]{12,64}/i.test(String(latestNotice.message || ""));
    }

    packageNoticeHasTransactionIdentity(latestNotice) {
      if (!latestNotice || !this.isPackageDetectionNotice(latestNotice)) return false;
      if (String(latestNotice.probeId || "")) return true;
      const downloadId = Number(latestNotice.downloadId);
      if (latestNotice.downloadId != null && Number.isInteger(downloadId) && downloadId >= 0) return true;
      if (normalizePopupSha256(latestNotice.sha256)) return true;
      return /\bSHA256\s*:\s*[a-f0-9]{12,64}/i.test(String(latestNotice.message || ""));
    }

    packageNoticeTransactionMismatch(latestNotice, vtInfo) {
      if (!latestNotice || !vtInfo || !this.packageNoticeHasTransactionIdentity(latestNotice)) return false;
      const noticeProbeId = String(latestNotice.probeId || "");
      const vtProbeId = String(vtInfo.probeId || "");
      if (noticeProbeId || vtProbeId) {
        if (!noticeProbeId || !vtProbeId || noticeProbeId !== vtProbeId) return true;
      }
      const noticeDownloadId = Number(latestNotice.downloadId);
      const vtDownloadId = Number(vtInfo.downloadId);
      const noticeHasDownloadId = latestNotice.downloadId != null
        && Number.isInteger(noticeDownloadId) && noticeDownloadId >= 0;
      const vtHasDownloadId = vtInfo.downloadId != null
        && Number.isInteger(vtDownloadId) && vtDownloadId >= 0;
      if (noticeHasDownloadId || vtHasDownloadId) {
        if (!noticeHasDownloadId || !vtHasDownloadId || noticeDownloadId !== vtDownloadId) return true;
      }
      const noticeHash = normalizePopupSha256(latestNotice.sha256);
      const vtHash = normalizePopupSha256(vtInfo.sha256);
      if (noticeHash && vtHash && noticeHash !== vtHash) return true;
      return false;
    }

    /**
     * Package VT owns the structured file/signature/hash UI. A matching
     * package notice still participates in protection state, but its compact
     * message must not be rendered above the same structured report again.
     */
    packageNoticeCoveredByVt(latestNotice, vtInfo, tabUrl) {
      try {
        if (!latestNotice || !vtInfo
          || !this.vtMatchesTab(vtInfo, this.activeTabId, tabUrl || this.activeTabUrl)) return false;
        if (!this.isPackageDetectionNotice(latestNotice)) return false;
        if (this.packageNoticeTransactionMismatch(latestNotice, vtInfo)) return false;
        const outerHash = normalizePopupSha256(vtInfo.sha256);
        if (!outerHash) return false;
        const noticeHash = normalizePopupSha256(latestNotice.sha256);
        if (noticeHash) return noticeHash === outerHash;
        // Compatibility with notices written by older builds: finalMsg used
        // the first 16 hex characters followed by an ellipsis.
        const match = String(latestNotice.message || "")
          .match(/\bSHA256\s*:\s*([a-f0-9]{12,64})/i);
        return !!(match && outerHash.startsWith(String(match[1] || "").toLowerCase()));
      } catch {
        return false;
      }
    }

    /** An older package notice must not survive into a new download probe. */
    stalePackageNoticeForVt(latestNotice, vtInfo, tabUrl) {
      try {
        if (!latestNotice || !vtInfo || !this.isPackageDetectionNotice(latestNotice)
          || !this.vtMatchesTab(vtInfo, this.activeTabId, tabUrl || this.activeTabUrl)) return false;
        if (!this.packageNoticeTransactionMismatch(latestNotice, vtInfo)) return false;
        return (Number(latestNotice.timestamp) || 0) <= (Number(vtInfo.timestamp) || 0);
      } catch {
        return false;
      }
    }

    newerPackageNoticeSupersedesVt(latestNotice, vtInfo, tabUrl) {
      try {
        if (!latestNotice || !vtInfo || !this.isPackageDetectionNotice(latestNotice)
          || !this.vtMatchesTab(vtInfo, this.activeTabId, tabUrl || this.activeTabUrl)
          || !this.packageNoticeTransactionMismatch(latestNotice, vtInfo)) return false;
        return (Number(latestNotice.timestamp) || 0) > (Number(vtInfo.timestamp) || 0);
      } catch {
        return false;
      }
    }

    dataMatchesTab(data, tabUrl) {
      if (!data) return false;
      if (!tabUrl) return true;
      if (!data.url) return false;
      return urlsMatch(data.url, tabUrl);
    }

    /** 干净完成报告（评分 0 / 低、无 guard）必须胜过残留通知。 */
    isCleanSafeReport(data) {
      if (!data || !this.isCompletedReport(data)) return false;
      if (data.identityVerificationUnavailable === true) return false;
      if (this.reportHasProtection(data)) return false;
      const score = Number(data.score) || 0;
      const level = data.riskLevel || "low";
      if (level === "high" || level === "medium") return false;
      if (score >= 12) return false;
      return true;
    }

    hasActiveProtection(data, latestNotice, tabId, tabUrl) {
      if (this.isCleanSafeReport(data)) return false;
      if (data && this.dataMatchesTab(data, tabUrl) && this.reportHasProtection(data)) return true;
      if (this.noticeMatchesTab(latestNotice, tabId, tabUrl, popupRiskTxn(data))
        && !this.isCleanSafeReport(data)) return true;
      return false;
    }

    resolveRiskPresentation(data, protectedActive) {
      let level = data?.riskLevel || "low";
      const score = data?.score ?? 0;
      const details = Array.isArray(data?.details) ? data.details : [];
      if (protectedActive && level === "low") level = score >= 24 || data?.packageBlocked ? "high" : "medium";
      if (!this.reportHasProtection(data) && score === 0 && (level === "medium" || level === "high")) level = "low";
      if (score >= 24 && details.length >= 2 && level === "low") level = "medium";
      const spoofBrand = this.brandSpoofFromData(data);
      const brandSpoof = !!(data?.brandSpoofPortal || spoofBrand) || details.some((d) => /仿冒品牌官网/i.test(d.name || ""));
      const multiSerp = details.some((d) => /多平台下载指向搜索引擎/i.test(d.name || ""));
      let title;
      if (level === "high") title = brandSpoof && spoofBrand ? `存在严重风险（仿冒「${spoofBrand}」官网）` : "存在严重风险";
      else if (level === "medium") {
        if (brandSpoof && spoofBrand) title = `存在中度风险（仿冒「${spoofBrand}」官网）`;
        else if (multiSerp) title = "存在中度风险（异常下载跳转）";
        else if (protectedActive) title = "存在中度风险（已拦截可疑下载）";
        else title = "存在中度风险";
      } else if (score > 0 || details.length > 0) { title = "存在低度风险"; level = "low"; }
      else title = "未发现明显风险";
      if (data?.identityVerificationUnavailable === true
        && !this.reportHasProtection(data) && score === 0 && details.length === 0) {
        level = "medium";
        title = "网站身份核验未完全确认";
      }
      return { level, title };
    }

    renderRisk(data, latestNotice, tabUrl, vtInfo) {
      this.clearRoot();
      const url = tabUrl || this.activeTabUrl;
      // storage.onChanged can briefly pair a newer package notice with the
      // previous probe's structured report. Show only the newer transaction;
      // never compose two different hashes/signature states into one view.
      if (this.newerPackageNoticeSupersedesVt(latestNotice, vtInfo, url)) vtInfo = null;
      const coalesced = this.coalesceReport(data, url);
      // No matching current-transaction report means the current page is
      // still being verified. Never fall back to a previous completed route.
      let matchedData = this.dataMatchesTab(coalesced, url) ? coalesced : null;
      const clean = this.isCleanSafeReport(matchedData);
      const noticeActive = !clean && this.noticeMatchesTab(
        latestNotice,
        this.activeTabId,
        url,
        popupRiskTxn(matchedData)
      );
      const packageNoticeCovered = noticeActive
        && this.packageNoticeCoveredByVt(latestNotice, vtInfo, url);
      const stalePackageNotice = noticeActive && !packageNoticeCovered
        && this.stalePackageNoticeForVt(latestNotice, vtInfo, url);
      const showNotice = noticeActive && !packageNoticeCovered && !stalePackageNotice;
      // The matching package notice remains protection evidence even though
      // appendPackageVt is now its sole visual owner.
      const protectedActive = this.hasActiveProtection(
        matchedData,
        noticeActive && !stalePackageNotice ? latestNotice : null,
        this.activeTabId,
        url
      );
      let brandName = this.brandSpoofFromData(matchedData);
      if (!brandName && showNotice) brandName = this.brandSpoofFromNotice(latestNotice);
      const brandSpoof = !!(matchedData?.brandSpoofPortal || brandName);
      const detailsEarly = Array.isArray(matchedData?.details) ? matchedData.details : [];
      const multiSerp = detailsEarly.some((d) => /多平台下载指向搜索引擎/i.test(d.name || ""));
      const identityRisk = this.identityRiskFromData(matchedData);

      if (brandSpoof) {
        this.root.appendChild(this.el("div", "high", brandName && brandName !== "品牌" ? `已识别仿冒「${brandName}」官网` : "已识别仿冒品牌官网下载站"));
        const item = this.el("div", "item");
        item.appendChild(document.createTextNode(brandName && brandName !== "品牌" ? `页面标题/正文品牌「${brandName}」与当前域名不匹配，疑似仿冒官网。` : "页面宣称品牌官网下载，但域名与品牌关联不严谨。"));
        this.root.appendChild(item);
      } else if (multiSerp) {
        this.root.appendChild(this.el("div", "high", "已拦截异常下载跳转"));
        this.root.appendChild(this.el("div", "item", "多平台下载入口统一跳转搜索引擎，不是真实安装包。"));
      } else if (!identityRisk && showNotice && !this.looksLikeSearchOrNonPackageTarget(latestNotice.message)) {
        this.root.appendChild(this.el("div", "high", latestNotice.title || "已拦截可疑下载文件"));
        const item = this.el("div", "item");
        item.appendChild(document.createTextNode("说明: "));
        item.appendChild(document.createTextNode(String(latestNotice.message || "可疑下载目标")));
        this.root.appendChild(item);
      } else if (!identityRisk && showNotice && this.looksLikeSearchOrNonPackageTarget(latestNotice.message)) {
        this.root.appendChild(this.el("div", "high", latestNotice.title || "已拦截异常下载跳转"));
        this.root.appendChild(this.el("div", "item", String(latestNotice.message || "异常跳转（非安装包）")));
      } else if (!identityRisk && protectedActive && matchedData?.protectedTargets?.some((t) => this.looksLikePackageTarget(t))) {
        const pkg = matchedData.protectedTargets.find((t) => this.looksLikePackageTarget(t));
        this.root.appendChild(this.el("div", "high", "已拦截可疑安装包"));
        const item = this.el("div", "item");
        item.appendChild(document.createTextNode("目标: "));
        const label = String(pkg).split("/").pop() || pkg;
        item.appendChild(document.createTextNode(label));
        this.root.appendChild(item);
      }

      const details = Array.isArray(matchedData?.details) ? matchedData.details : [];
      const completed = this.isCompletedReport(matchedData);
      // 无匹配报告不是安全结论。后台标签页可能尚未运行/落盘首份报告；
      // 唤醒一次当前文档并保持等待态，禁止用默认 0 分冒充已完成扫描。
      if (!matchedData) {
        this.requestRiskReportOnce(url);
        this.root.appendChild(this.el("div", "item", "正在核验网站身份与下载行为…"));
        try { this.appendPackageVt(vtInfo || null, url); } catch { /* ignore */ }
        return;
      }
      if (!completed && matchedData.identityVerificationUnavailable === true) {
        this.root.appendChild(this.el("div", "medium", "网站身份核验未完全确认"));
        this.root.appendChild(this.el(
          "div",
          "item",
          "部分身份来源未能在时限内返回，当前结果未作为安全结论；稍后返回结果会自动更新。"
        ));
        this.appendSsl(matchedData);
        this.appendIcp(matchedData);
        this.appendWhois(matchedData);
        try { this.appendPackageVt(vtInfo || null, url); } catch { /* ignore */ }
        return;
      }
      if (!completed) {
        this.requestRiskReportOnce(url);
        this.root.appendChild(this.el("div", "item", "正在核验网站身份与下载行为…"));
        try { this.appendPackageVt(vtInfo || null, url); } catch { /* ignore */ }
        return;
      }
      const { level, title } = this.resolveRiskPresentation(matchedData, protectedActive);
      this.root.appendChild(this.el("div", level, title));
      this.root.appendChild(this.el("div", "item", `评分: ${matchedData.score ?? 0}`));
      if (matchedData.identityVerificationUnavailable === true) {
        this.root.appendChild(this.el(
          "div",
          "item",
          "部分身份来源未能在时限内返回，当前结果未作为安全结论；稍后返回结果会自动更新。"
        ));
      }
      // SSL 在 ICP 之前；OV/EV 绿色机构名
      this.appendSsl(matchedData);
      this.appendIcp(matchedData);
      this.appendWhois(matchedData);
      // 安装包/压缩包 PE+VT（有检测结果时展示）
      try { this.appendPackageVt(vtInfo || null, url); } catch { /* ignore */ }
      if (protectedActive && this.reportHasProtection(matchedData)) {
        if (brandSpoof) this.root.appendChild(this.el("div", "item", brandName && brandName !== "品牌" ? `状态: 已按仿冒「${brandName}」官网处理，下载入口已禁用` : "状态: 已按仿冒品牌官网处理，下载入口已禁用"));
        else if (identityRisk) this.root.appendChild(this.el("div", "item", "状态: 已按身份异常站点处理，页面下载入口已禁用"));
        else if (multiSerp) this.root.appendChild(this.el("div", "item", "状态: 异常下载跳转已拦截（非安装包）"));
        else this.root.appendChild(this.el("div", "item", "状态: 可疑安装包下载已被禁用/拦截"));
      }
      if (details.length === 0 && !protectedActive) {
        this.root.appendChild(this.el("div", "item", "未检测到威胁行为信号。"));
      } else {
        details.forEach((d) => {
          const line = this.el("div", "item", `- ${d.name || "信号"}`);
          if (d.reason) line.title = String(d.reason);
          this.root.appendChild(line);
        });
      }
    }

    maybeRefreshVtEngineDetails(vtInfo) {
      const vt = vtInfo && vtInfo.vt;
      // 身份未绑定的对象不可据其 VT hash 发起刷新；同 hash 的旧统计口径则必须重查。
      if (popupVtIdentityUnbound(vtInfo)) return;
      const vtStale = popupVtHashMismatch(vtInfo);
      const hash = normalizePopupSha256((vtInfo && vtInfo.sha256) || (vt && vt.hash));
      const detections = (Number(vt && vt.malicious) || 0) + (Number(vt && vt.suspicious) || 0);
      const policyCurrent = Number(vt && vt.trustedPolicyVersion) === VT_TRUST_POLICY_VERSION;
      const statsCurrent = Number(vt && vt.statsPolicyVersion) === VT_STATS_POLICY_VERSION;
      const needsEngineRefresh = detections > 0 && (vt.engineDetailsAvailable !== true || !policyCurrent);
      const needsStatsRefresh = vtStale || !statsCurrent;
      if (!/^[a-f0-9]{64}$/.test(hash) || !vt || vt.found !== true
        || (!needsEngineRefresh && !needsStatsRefresh) || this._vtDetailsRefreshes.has(hash)) return;
      this._vtDetailsRefreshes.add(hash);
      try {
        chrome.runtime.sendMessage({
          type: "refresh-vt-engine-details",
          sha256: hash,
          tabId: this.activeTabId
        }, () => { void chrome.runtime.lastError; });
      } catch { /* ignore */ }
    }

    maybeRefreshNestedSignatures(vtInfo) {
      const hash = String((vtInfo && vtInfo.sha256) || "").toLowerCase();
      const nested = vtInfo && Array.isArray(vtInfo.nested) ? vtInfo.nested : [];
      const now = Date.now();
      const pending = nested.filter((item) => {
        if (!item || !/^[a-f0-9]{64}$/i.test(String(item.sha256 || ""))) return false;
        const nv = item.vt || null;
        if (!popupNestedVtMatchesItem(item)) return true;
        if (nv && nv.notFound === true && nv.verifiedNotFound === true && nv.softMiss !== true) return false;
        const checkedRecently = now - (Number(nv && nv.checkedAt) || 0) < 30000;
        if (nv && nv.unknown === true && checkedRecently) return false;
        if (nv && nv.signatureIncomplete === true && checkedRecently) return false;
        return !!item.signed
          && (!/^(?:valid|invalid|none)$/i.test(String(nv && nv.sigTrustFromVt || ""))
            || (nv && nv.signatureIncomplete === true));
      });
      if (!pending.length) return;
      const refreshKey = `${hash}|${pending.map((item) => item.sha256).join("|")}`;
      if (this._nestedSignatureRefreshes.has(refreshKey)) return;
      this._nestedSignatureRefreshes.add(refreshKey);
      try {
        chrome.runtime.sendMessage({
          type: "refresh-nested-vt-signatures",
          sha256: hash,
          tabId: this.activeTabId
        }, () => { void chrome.runtime.lastError; });
      } catch { /* ignore */ }
    }

    refresh(currentTabUrl, vtOverride = null) {
      if (this.activeTabId == null) return;
      if (currentTabUrl) this.activeTabUrl = currentTabUrl;
      const requestTabId = this.activeTabId;
      const requestUrl = this.activeTabUrl || currentTabUrl || "";
      const requestSeq = ++this._renderRequestSeq;
      const vtTabKey = `latestExeVt_${requestTabId}`;
      chrome.storage.local.get([`risk_${requestTabId}`, "risk_latest", "latestNotice", "latestExeVt", vtTabKey], (result) => {
        if (requestSeq !== this._renderRequestSeq || this.activeTabId !== requestTabId) return;
        const activeUrl = this.activeTabUrl || requestUrl;
        if (requestUrl && activeUrl && !urlsMatch(requestUrl, activeUrl)) return;
        if (chrome.runtime.lastError) { this.clearRoot(); this.root.appendChild(this.el("div", "item", "读取扩展数据失败。")); return; }
        const tabUrl = this.activeTabUrl || requestUrl;
        const localRaw = result[`risk_${requestTabId}`] || null;
        const localData = this.dataMatchesTab(localRaw, tabUrl) ? localRaw : null;
        const latestData = result.risk_latest && this.dataMatchesTab(result.risk_latest, tabUrl) ? result.risk_latest : null;
        const data = localData || latestData || null;
        const notice = result.latestNotice || null;
        // 优先本 tab 键；全局 latestExeVt 必须再过 vtMatchesTab（防换站/串台）
        let vtInfo = null;
        if (vtOverride && this.vtMatchesTab(vtOverride, this.activeTabId, tabUrl)) {
          vtInfo = vtOverride;
        } else {
          const tabVt = result[vtTabKey] || null;
          const globalVt = result.latestExeVt || null;
          if (tabVt && this.vtMatchesTab(tabVt, this.activeTabId, tabUrl)) vtInfo = tabVt;
          else if (globalVt && this.vtMatchesTab(globalVt, this.activeTabId, tabUrl)) vtInfo = globalVt;
        }
        this.renderRisk(data, notice, tabUrl, vtInfo);
        this.maybeRefreshVtEngineDetails(vtInfo);
        this.maybeRefreshNestedSignatures(vtInfo);
      });
    }

    installListeners() {
      chrome.runtime.onMessage.addListener((msg, sender) => {
        if (msg.type === "threat-risk" && sender.tab?.id === this.activeTabId) {
          if (this.activeTabUrl && msg.url && !urlsMatch(msg.url, this.activeTabUrl)) return;
          // 中间态必须从后台合并后的存储读取，不能直接用空白报告覆盖已完成结论。
          if (msg.analysisComplete === false) {
            // Establish the new transaction before the asynchronous storage
            // read. If disk still contains the previous same-URL completion,
            // coalesceReport will now reject it instead of flashing it.
            this.coalesceReport(msg, this.activeTabUrl || msg.url);
            this.refresh(this.activeTabUrl || msg.url);
            return;
          }
          // 保留 latestExeVt：直接 render 不带 vt 会冲掉安装包检测区
          const requestTabId = this.activeTabId;
          const requestUrl = this.activeTabUrl || msg.url || "";
          const requestSeq = ++this._renderRequestSeq;
          const vtTabKey = `latestExeVt_${requestTabId}`;
          chrome.storage.local.get([
            "latestExeVt", vtTabKey, "latestNotice", `risk_${requestTabId}`, "risk_latest"
          ], (extra) => {
            if (requestSeq !== this._renderRequestSeq || this.activeTabId !== requestTabId) return;
            const activeUrl = this.activeTabUrl || requestUrl;
            if (requestUrl && activeUrl && !urlsMatch(requestUrl, activeUrl)) return;
            // Popup 初次打开时，runtime 消息可能先于初始 storage.get 返回；先吸收已落盘强证书，
            // 再渲染实时消息，避免初始 OV 读取被取消后短暂画成 DV。
            const storedRaw = extra && (extra[`risk_${requestTabId}`] || extra.risk_latest);
            if (storedRaw && this.dataMatchesTab(storedRaw, requestUrl)) {
              this.coalesceReport(storedRaw, requestUrl);
            }
            // 先吸收落盘报告，再合并 runtime 报告；不能前面合并、后面却仍渲染原始 msg。
            const reportForRender = this.coalesceReport(msg, requestUrl);
            const tabVt = (extra && extra[vtTabKey]) || null;
            const globalVt = (extra && extra.latestExeVt) || null;
            const tabUrlNow = this.activeTabUrl || msg.url;
            let vtPick = null;
            if (tabVt && this.vtMatchesTab(tabVt, this.activeTabId, tabUrlNow)) vtPick = tabVt;
            else if (globalVt && this.vtMatchesTab(globalVt, this.activeTabId, tabUrlNow)) vtPick = globalVt;
            this.renderRisk(
              reportForRender,
              (extra && extra.latestNotice) || null,
              tabUrlNow,
              vtPick
            );
          });
          return;
        }
        if (msg.type === "threat-notice" && sender.tab?.id === this.activeTabId) {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => { const t = tabs?.[0]; if (t?.url) this.activeTabUrl = t.url; this.refresh(this.activeTabUrl); });
        }
        if (msg.type === "exe-vt-result"
          && Number(msg.tabId ?? msg.report?.tabId) === Number(this.activeTabId)) {
          this.refresh(this.activeTabUrl, msg.vtInfo || null);
          return;
        }
      });
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== "local" || this.activeTabId == null) return;
        if (changes[`risk_${this.activeTabId}`] || changes.risk_latest || changes.latestNotice
          || changes.latestExeVt || changes[`latestExeVt_${this.activeTabId}`]) {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => { const t = tabs?.[0]; if (t?.id === this.activeTabId && t.url) this.activeTabUrl = t.url; this.refresh(this.activeTabUrl); });
        }
      });
      if (chrome.tabs && chrome.tabs.onUpdated) {
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
          if (tabId !== this.activeTabId) return;
          if (changeInfo.url) { this.activeTabUrl = changeInfo.url; this.refresh(this.activeTabUrl); }
          else if (changeInfo.status === "loading" && tab?.url) {
            // Same-URL reload: onCommitted's storage sentinel may still be in
            // flight. Hide the old completed document immediately instead of
            // flashing it until storage.onChanged arrives.
            this.activeTabUrl = tab.url;
            this._lastCompletedByTab.delete(tabId);
            this._activeRiskTxnByTab.delete(tabId);
            this._riskReportWakeRequests.clear();
            this.renderRisk(null, null, this.activeTabUrl, null);
          }
          else if (changeInfo.status === "complete" && tab?.url) { this.activeTabUrl = tab.url; this.refresh(this.activeTabUrl); }
        });
      }
    }

    init() {
      this.installListeners();
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs?.[0];
        if (!tab || tab.id == null) { this.clearRoot(); this.root.appendChild(this.el("div", "item", "无法获取活动标签页，请稍后重试。")); return; }
        this.activeTabId = tab.id;
        this.activeTabUrl = tab.url || "";
        this.refresh(this.activeTabUrl);
      });
    }
  }

  function initSettingsLink() {
    const a = document.getElementById("open-settings");
    if (!a) return;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      try {
        if (chrome.runtime.openOptionsPage) {
          chrome.runtime.openOptionsPage(() => { void chrome.runtime.lastError; });
        } else {
          window.open(chrome.runtime.getURL("options/options.html"), "_blank");
        }
      } catch {
        try { window.open(chrome.runtime.getURL("options/options.html"), "_blank"); } catch { /* ignore */ }
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const root = document.getElementById("result");
    if (!root) return;
    new PopupRenderer(root).init();
    initSettingsLink();
  });
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      PopupRenderer,
      urlsMatch,
      chooseStrongerSslInfo,
      normalizePopupSha256,
      popupVtIdentityUnbound,
      popupVtHashMismatch
    };
  }
})();
