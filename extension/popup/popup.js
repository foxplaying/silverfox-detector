/**
 * popup 渲染器：读取当前标签页风险报告 + 拦截通知，渲染风险等级与详情。
 */
;(function () {
  "use strict";

  const VT_TRUST_POLICY_VERSION = 3;
  const VT_STATS_POLICY_VERSION = 2;
  const VT_TRUSTED_ENGINE_RULES = [
    ["BitDefender", /^BitDefender(?:Falx)?$/i],
    ["ESET", /^ESET(?:-NOD32)?$/i],
    ["Avast", /^Avast(?:-Mobile)?$/i],
    ["Huorong", /^(?:Huorong|火绒)$/i],
    ["Kaspersky", /^Kaspersky$/i]
  ];

  function popupTrustedVtEngine(engineName) {
    const raw = String(engineName || "").trim();
    for (const [canonical, rule] of VT_TRUSTED_ENGINE_RULES) {
      if (rule.test(raw)) return canonical;
    }
    return "";
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

  class PopupRenderer {
    constructor(root) {
      this.root = root;
      this.activeTabId = null;
      this.activeTabUrl = "";
      /** 同 tab 最近一次「已完成」报告，防止中间态 analysisComplete:false 把 UI 打回「正在分析」 */
      this._lastCompletedByTab = new Map();
      this._vtDetailsRefreshes = new Set();
      this._nestedSignatureRefreshes = new Set();
    }

    hostKeyFromUrl(u) {
      try {
        return new URL(u || "").hostname.toLowerCase().replace(/^www\./, "");
      } catch {
        return "";
      }
    }

    /** 合并：新消息 incomplete 时，同主机沿用上次完成报告并合并情报字段 */
    coalesceReport(data, tabUrl) {
      if (!data) return null;
      const tabId = this.activeTabId;
      const completed = this.isCompletedReport(data);
      if (completed) {
        if (tabId != null) this._lastCompletedByTab.set(tabId, { ...data, url: data.url || tabUrl, analysisComplete: true });
        return { ...data, analysisComplete: true };
      }
      const prev = tabId != null ? this._lastCompletedByTab.get(tabId) : null;
      if (!prev || !this.isCompletedReport(prev)) return data;
      const hNew = this.hostKeyFromUrl(data.url || tabUrl);
      const hPrev = this.hostKeyFromUrl(prev.url || tabUrl);
      if (hNew && hPrev && hNew === hPrev) {
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
          whoisInfo: data.whoisInfo || prev.whoisInfo,
          sslInfo: data.sslInfo || prev.sslInfo || null,
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
      // 等级与组织字段分开：urlscan 可直接显示 OV/EV，tlsIssuer 不冒充组织名。
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
     * 安装包/压缩包 VT：优先按准确 tabId 展示；旧缓存缺 tabId 时再按页面主机回退。
     * CDN/重定向域名不应隐藏当前标签页刚触发的文件检测。
     */
    vtMatchesTab(vt, tabId, tabUrl) {
      if (!vt || typeof vt !== "object") return false;
      const at = Number(vt.timestamp) || 0;
      // 30 分钟内；过期不展示
      if (!at || Date.now() - at > 30 * 60 * 1000) return false;
      // 新数据有准确来源 tabId 时以 tab 为准；下载 CDN/重定向域名不得把同 tab 的 VT 隐藏。
      if (vt.tabId != null && tabId != null) return Number(vt.tabId) === Number(tabId);
      const pageHost = this.hostKeyFromUrl(tabUrl);
      if (!pageHost) return false;
      const pageHostAt = this.hostKeyFromUrl(vt.pageUrl || "")
        || String(vt.pageHost || "").toLowerCase().replace(/^www\./, "");
      const dlHost = this.hostKeyFromUrl(vt.url || "");
      // 必须：当前浏览主机 = 触发下载时的页面主机
      if (pageHostAt && pageHost === pageHostAt) return true;
      // 或：文件就托管在当前站（同站直链）
      if (dlHost && pageHost === dlHost) return true;
      // 禁止：仅 tabId 相同但已跳到别的网站仍显示
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
      const peSigned = !!(vtInfo.peSigned || (peObj && peObj.signed));
      const vt = vtInfo.vt || null;
      const sigInfo = vtInfo.signature || null;
      const nested = Array.isArray(vtInfo.nested) ? vtInfo.nested : (sigInfo && Array.isArray(sigInfo.items) ? sigInfo.items : []);
      // 数字签名主体
      const peSigner = String(
        (sigInfo && sigInfo.signer)
        || vtInfo.peSigner
        || (peObj && peObj.signerHint)
        || (vt && vt.signerFromVt)
        || ""
      ).trim();
      // none | present(黑) | valid(绿) | invalid(红)
      let peSigTrust = String(
        (sigInfo && sigInfo.trust) || vtInfo.peSigTrust || (vt && vt.sigTrustFromVt) || ""
      ).toLowerCase();
      if (!peSigTrust) {
        if (peSigned || peSigner) peSigTrust = "present";
        else if (peObj && peObj.isPe) peSigTrust = "none";
        else if (nested.length) {
          if (nested.some((n) => (n.trust || n.sigTrust) === "invalid")) peSigTrust = "invalid";
          else if (nested.every((n) => (n.trust || n.sigTrust) === "valid")) peSigTrust = "valid";
          else if (nested.some((n) => n.signed || (n.trust || n.sigTrust) === "present" || (n.trust || n.sigTrust) === "valid")) peSigTrust = "present";
          else peSigTrust = "none";
        }
      }
      const guiUrl = String(vtInfo.guiUrl || (vt && vt.guiUrl) || "").trim();
      const sha = String(vtInfo.sha256 || "").trim();
      const title = String(vtInfo.title || "").trim();
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
      const trustedByFamily = new Map();
      for (const detection of (vt && Array.isArray(vt.trustedDetections) ? vt.trustedDetections : [])) {
        const canonical = popupTrustedVtEngine(detection && detection.engine);
        if (canonical && !trustedByFamily.has(canonical)) trustedByFamily.set(canonical, detection);
      }
      const trustedRows = Array.from(trustedByFamily, ([engine, detection]) => ({ ...detection, engine }));
      const trustedEngineCount = trustedRows.length;
      const trustedEngineNames = trustedRows.map((x) => x.engine);
      const trustedEngineDetails = trustedRows
        .map((x) => {
          const engine = String(x.engine || "").trim();
          const result = String((x && x.result) || "").replace(/\s+/g, " ").trim().slice(0, 48);
          return engine ? `${engine}${result ? `（${result}）` : ""}` : "";
        }).filter(Boolean);
      const trustedObservedByFamily = new Map();
      for (const result of (vt && Array.isArray(vt.trustedEngineResults) ? vt.trustedEngineResults : [])) {
        const canonical = popupTrustedVtEngine(result && result.engine);
        if (canonical && !trustedObservedByFamily.has(canonical)) trustedObservedByFamily.set(canonical, result);
      }
      const trustedObservedNames = Array.from(trustedObservedByFamily.keys());
      const trustedObservedCount = trustedObservedNames.length;
      const unscopedVtSource = !!(vt
        && /^(?:vt-page-component|vt-dom)$/i.test(String(vt.source || "")));
      // softMiss / unknown 绝不当「VT: 无」
      const vtNone = !!(vt && vt.notFound === true && vt.verifiedNotFound === true
        && !vt.softMiss && vt.unknown !== true);
      const unverifiedMiss = !!(vt && vt.notFound === true && vt.verifiedNotFound !== true);
      const vtHit = !!(vt && !unscopedVtSource && (vt.found === true
        || (vt.malicious != null && vt.notFound !== true && !vt.unknown && !vt.softMiss)));
      const vtUnknown = !!(vt && !vtNone && !vtHit
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
      const isArchiveShell = (kind === "archive" || kind === "package" || /\.zip$/i.test(filename))
        && kind !== "apk"
        && !(peObj && peObj.isPe && !peObj.skipped);
      const showOuterSig = !isArchiveShell && (kind === "pe" || kind === "msi" || kind === "apk"
        || peSigned || peSigner || (peObj && peObj.isPe)
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
            const nt = String(n.trust || n.sigTrust || (n.signed ? "present" : "none")).toLowerCase();
            const ns = String(n.signer || n.signerHint || "").trim();
            if (nt === "valid") {
              nestSp.className = "sig-valid";
              nestSp.textContent = ns ? `${ns}（VT 有效）` : "有（VT 有效）";
            } else if (nt === "invalid") {
              nestSp.className = "sig-invalid";
              nestSp.textContent = ns ? `${ns}（无效）` : "无效";
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

            // 包内 VT 结果
            const nvt = n.vt || null;
            if (nvt) {
              const nestVtRow = this.el("div", "item sig-nested sig-nested-indent");
              const nestVtLabel = document.createElement("strong");
              nestVtLabel.textContent = "VirusTotal: ";
              nestVtRow.appendChild(nestVtLabel);
              const nestVtSp = document.createElement("span");
              const nMal = Number(nvt.malicious) || 0;
              const nSus = Number(nvt.suspicious) || 0;
              const nTot = Number(nvt.total) || 0;
              if (nvt.notFound) {
                nestVtSp.className = "vt-warn";
                nestVtSp.textContent = "无";
              } else if (nvt.found === true) {
                nestVtSp.className = nMal >= 3 ? "vt-bad" : (nMal > 0 ? "vt-warn" : "vt-ok");
                nestVtSp.textContent = nTot > 0
                  ? `检出 ${nMal + nSus}/${nTot}（恶意 ${nMal} / 可疑 ${nSus}）`
                  : `恶意 ${nMal} · 可疑 ${nSus}`;
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

      // —— ③ VT 单独一行 ——
      let vtLine = "";
      if (vtHit) {
        if (sumRaw && !isJunkVtSummary && /检出|恶意|VT/i.test(sumRaw)) {
          vtLine = sumRaw.replace(/^VT:\s*/i, "VT: ");
        } else {
          vtLine = totN > 0
            ? `VT 检出 ${malN + susN}/${totN}（恶意 ${malN} / 可疑 ${susN}）`
            : `VT 恶意 ${malN} · 可疑 ${susN}`;
        }
      } else if (vtNone) {
        vtLine = /已自动上传|已自动提交|已提交文件|可手动提交|上传文件/i.test(sumRaw) ? sumRaw : "VT: 无";
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
        vtLabel.textContent = "VirusTotal: ";
        vtRow.appendChild(vtLabel);
        const vtSp = document.createElement("span");
        vtSp.className = "vt-text";
        if (unscopedVtSource) vtSp.className += " vt-warn";
        else if (trustedEngineCount >= 2 || status === "blocked" || status === "flagged") vtSp.className += " vt-bad";
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
        shaLabel.textContent = "SHA256: ";
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
          && !/^VT\s+(?:知名引擎共识|单个知名引擎检出|总检出|指定五家引擎|指定引擎未检出)/i.test(r.text)
          && !((vtHit || vtUnknown) && /VT 无此文件记录/i.test(r.text))
          && !(unscopedVtSource && /\bVT\b|VirusTotal/i.test(r.text))
          && !/未自动解析|自动解析失败|请点开链接确认|请点开链接或配置/i.test(r.text))
        : [];
      if (!risks.length) {
        if (peSigTrust === "invalid") {
          risks.push({ level: "high", text: "数字签名无效/不可信" });
        } else if (!trustedSource && vtInfo.gated && (kind === "pe" || (peObj && peObj.isPe)) && peSigTrust === "none") {
          risks.push({ level: "medium", text: "未检测到数字签名（来源页处于下载保护状态）" });
        } else if (!trustedSource && vtInfo.gated && nested.length && nested.filter((n) => n.kind === "pe" || /\.exe|\.dll/i.test(n.name || "")).every((n) => !n.signed)) {
          const peN = nested.filter((n) => n.kind === "pe" || /\.exe|\.dll/i.test(n.name || ""));
          if (peN.length) risks.push({ level: "medium", text: "压缩包内可执行文件均未检测到数字签名" });
        }
        if (vtHit && trustedEngineCount >= 2) {
          risks.push({
            level: "high",
            text: `VT 知名引擎共识 ${trustedEngineCount} 家：${trustedEngineDetails.join("、") || trustedEngineNames.join("、") || "已确认恶意"}`
          });
        } else if (vtHit && trustedEngineCount === 1) {
          risks.push({
            level: "medium",
            text: `VT 单个知名引擎检出：${trustedEngineDetails[0] || trustedEngineNames[0] || "未知"}（尚未形成共识）`
          });
        } else if (vtHit && (mal >= 1 || sus >= 1) && vt.engineDetailsAvailable !== true) {
          risks.push({ level: "medium", text: `VT 总检出 ${mal + sus} 家；正在补取逐引擎检测结果` });
        } else if (vtHit && (mal >= 1 || sus >= 1)) {
          if (trustedObservedCount >= VT_TRUSTED_ENGINE_RULES.length) {
            risks.push({ level: "low", text: "VT 未见恶意检出" });
          } else if (trustedObservedCount > 0) {
            risks.push({
              level: "medium",
              text: `VT 指定引擎未检出（已取得 ${trustedObservedCount}/5 家：${trustedObservedNames.join("、")}）`
            });
          } else {
            risks.push({ level: "medium", text: `VT 总检出 ${mal + sus} 家；尚未取得指定五家引擎结果` });
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
      const feedSubmitted = !!(vt && (vt.feedSubmitted || vt.submitted));
      if (vtNone || vtUnknown || feedSubmitted || (vt && vt.needCaptcha)) {
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
          } else if (vt && vt.swCaptcha) {
            tipSp.textContent = "VT 后台接口要求验证；已尝试使用当前浏览器会话实时读取页面";
          } else {
            tipSp.textContent = "VT 自动取数未完成；可点开链接查看，或配置 API Key 稳定读取";
          }
        } else if (vtNone) {
          tipSp.textContent = "VT 库中无此样本：可手动提交文件";
        } else {
          tipSp.textContent = "可打开 VT 查看或手动提交文件";
        }
        tip.appendChild(tipSp);
        this.root.appendChild(tip);

        // 用户点击才打开；已提交优先链到文件/分析页
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

    /** 报告是否已完成扫描（或轻量路径）。 */
    isCompletedReport(data) {
      if (!data || typeof data !== "object") return false;
      if (data.analysisComplete === false) return false;
      if (data.analysisComplete === true) return true;
      // 兼容旧版未携带 analysisComplete 的已完成报告。
      if (typeof data.score === "number" && data.riskLevel) return true;
      if (data.type === "threat-risk" && typeof data.score === "number") return true;
      if (data.downloadGuardInstalled || data.packageBlocked || data.brandSpoofPortal || data.spoofBrand) return true;
      if (Array.isArray(data.details) && data.details.length > 0) return true;
      if (data.icpInfo || data.whoisInfo || data.sslInfo) return true;
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

    sanitizeSpoofBrandName(raw) {
      let s = String(raw || "")
        .trim()
        .replace(/(?:官方网站下载|官方网站|官网(?:下载)?|官方(?:下载)?|免费下载|下载)$/u, "")
        .trim();
      if (!s) return "";
      if (/^(?:品牌|产品|功能|特性|特色|方案|官网|官方)$/.test(s)) return "";

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
      if (/^(?:电脑|桌面|手机|移动|网页|安卓|苹果|鸿蒙|通用|绿色|便携|免安装|安装|免费|正式|官方|最新|新版|旧版|专业|企业|个人|家庭|教育|国际|中文|测试|开发|稳定|会员)(?:版|版本)$/u.test(compact)) return "";

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
      return s;
    }

    brandSpoofFromData(data) {
      if (!data) return "";
      if (data.spoofBrand) {
        const direct = this.sanitizeSpoofBrandName(data.spoofBrand);
        if (direct) return direct;
      }
      // 详情是说明文本，不是可信身份字段。不得从 reason 反向解析品牌，
      // 否则内容侧已拒绝的域名核或功能词会在 Popup 再次复活。
      return "";
    }

    /** 通知仅对当前页面 URL 有效；永不回退到 tabId-only。 */
    noticeMatchesTab(latestNotice, tabId, tabUrl) {
      if (!latestNotice) return false;
      if (latestNotice.tabId != null && latestNotice.tabId !== tabId) return false;
      if (!tabUrl || !latestNotice.url) return false;
      return urlsMatch(latestNotice.url, tabUrl);
    }

    dataMatchesTab(data, tabUrl) {
      if (!data) return false;
      if (!tabUrl) return true;
      if (!data.url) return true;
      if (urlsMatch(data.url, tabUrl)) return true;
      // 同主机即可（SPA 换 path；禁止因精确 URL 不一致一直「正在分析」）
      try {
        const a = this.hostKeyFromUrl(data.url);
        const b = this.hostKeyFromUrl(tabUrl);
        return !!(a && b && a === b);
      } catch {
        return false;
      }
    }

    /** 干净完成报告（评分 0 / 低、无 guard）必须胜过残留通知。 */
    isCleanSafeReport(data) {
      if (!data || !this.isCompletedReport(data)) return false;
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
      if (this.noticeMatchesTab(latestNotice, tabId, tabUrl) && !this.isCleanSafeReport(data)) return true;
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
      return { level, title };
    }

    renderRisk(data, latestNotice, tabUrl, vtInfo) {
      this.clearRoot();
      const url = tabUrl || this.activeTabUrl;
      const coalesced = this.coalesceReport(data, url);
      // 无匹配数据时：同 tab 缓存 / 空报告兜底，禁止永久「正在分析」
      let matchedData = this.dataMatchesTab(coalesced, url) ? coalesced : null;
      if (!matchedData && this.activeTabId != null) {
        const cached = this._lastCompletedByTab.get(this.activeTabId);
        if (cached && this.dataMatchesTab(cached, url)) matchedData = { ...cached, analysisComplete: true };
      }
      if (!matchedData && coalesced && typeof coalesced.score === "number") {
        matchedData = { ...coalesced, analysisComplete: true };
      }
      const clean = this.isCleanSafeReport(matchedData);
      const showNotice = !clean && this.noticeMatchesTab(latestNotice, this.activeTabId, url);
      const protectedActive = this.hasActiveProtection(matchedData, showNotice ? latestNotice : null, this.activeTabId, url);
      const brandName = this.brandSpoofFromData(matchedData);
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
      // 无报告：短时「分析中」后显示默认低风险（避免永久卡住）
      if (!matchedData) {
        this.root.appendChild(this.el("div", "low", "未发现明显风险"));
        this.root.appendChild(this.el("div", "item", "评分: 0"));
        this.root.appendChild(this.el("div", "item", "未检测到威胁行为信号。"));
        try { this.appendPackageVt(vtInfo || null, url); } catch { /* ignore */ }
        return;
      }
      if (!completed) {
        this.root.appendChild(this.el("div", "item", "正在核验网站身份与下载行为…"));
        try { this.appendPackageVt(vtInfo || null, url); } catch { /* ignore */ }
        return;
      }
      const { level, title } = this.resolveRiskPresentation(matchedData, protectedActive);
      this.root.appendChild(this.el("div", level, title));
      this.root.appendChild(this.el("div", "item", `评分: ${matchedData.score ?? 0}`));
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
      const hash = String((vtInfo && vtInfo.sha256) || (vt && vt.hash) || "").toLowerCase();
      const detections = (Number(vt && vt.malicious) || 0) + (Number(vt && vt.suspicious) || 0);
      const policyCurrent = Number(vt && vt.trustedPolicyVersion) === VT_TRUST_POLICY_VERSION;
      const statsCurrent = Number(vt && vt.statsPolicyVersion) === VT_STATS_POLICY_VERSION;
      const needsEngineRefresh = detections > 0 && (vt.engineDetailsAvailable !== true || !policyCurrent);
      const needsStatsRefresh = !statsCurrent;
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
      const pending = nested.filter((item) => item && item.signed
        && /^(?:present)?$/i.test(String(item.sigTrust || item.trust || "present"))
        && /^[a-f0-9]{64}$/i.test(String(item.sha256 || "")));
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
      const vtTabKey = `latestExeVt_${this.activeTabId}`;
      chrome.storage.local.get([`risk_${this.activeTabId}`, "risk_latest", "latestNotice", "latestExeVt", vtTabKey], (result) => {
        if (chrome.runtime.lastError) { this.clearRoot(); this.root.appendChild(this.el("div", "item", "读取扩展数据失败。")); return; }
        const tabUrl = this.activeTabUrl || currentTabUrl || "";
        const localRaw = result[`risk_${this.activeTabId}`] || null;
        const localData = this.dataMatchesTab(localRaw, tabUrl) ? localRaw : null;
        const latestData = result.risk_latest && this.dataMatchesTab(result.risk_latest, tabUrl) ? result.risk_latest : null;
        const data = localData || latestData || null;
        const notice = result.latestNotice || null;
        const vtInfo = (vtOverride && this.vtMatchesTab(vtOverride, this.activeTabId, tabUrl))
          ? vtOverride
          : (result[vtTabKey] || result.latestExeVt || null);
        this.renderRisk(data, notice, tabUrl, vtInfo);
        this.maybeRefreshVtEngineDetails(vtInfo);
        this.maybeRefreshNestedSignatures(vtInfo);
      });
    }

    installListeners() {
      chrome.runtime.onMessage.addListener((msg, sender) => {
        if (msg.type === "threat-risk" && sender.tab?.id === this.activeTabId) {
          // 同主机：允许 path 变化；跨主机严格匹配
          if (this.activeTabUrl && msg.url) {
            const hA = this.hostKeyFromUrl(this.activeTabUrl);
            const hB = this.hostKeyFromUrl(msg.url);
            if (hA && hB && hA !== hB) return;
            if (hA === hB) {
              // 同主机中间态 incomplete 不打断已完成 UI（coalesce 再处理）
            } else if (!urlsMatch(msg.url, this.activeTabUrl)) return;
          }
          // 中间态必须从后台合并后的存储读取，不能直接用空白报告覆盖已完成结论。
          if (msg.analysisComplete === false) {
            this.refresh(this.activeTabUrl || msg.url);
            return;
          }
          // 保留 latestExeVt：直接 render 不带 vt 会冲掉安装包检测区
          const vtTabKey = `latestExeVt_${this.activeTabId}`;
          chrome.storage.local.get(["latestExeVt", vtTabKey, "latestNotice"], (extra) => {
            this.renderRisk(
              msg,
              (extra && extra.latestNotice) || null,
              this.activeTabUrl || msg.url,
              (extra && (extra[vtTabKey] || extra.latestExeVt)) || null
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
  if (typeof module !== "undefined" && module.exports) module.exports = { PopupRenderer, urlsMatch };
})();
