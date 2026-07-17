/**
 * popup 渲染器：读取当前标签页风险报告 + 拦截通知，渲染风险等级与详情。
 */
;(function () {
  "use strict";

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
      if (completed && data.analysisComplete !== false) {
        if (tabId != null) this._lastCompletedByTab.set(tabId, { ...data, url: data.url || tabUrl, analysisComplete: true });
        return { ...data, analysisComplete: true };
      }
      if (completed && data.analysisComplete === false) {
        // 有分数可展示：强制当 complete，并缓存
        const fixed = { ...data, analysisComplete: true };
        if (tabId != null) this._lastCompletedByTab.set(tabId, fixed);
        return fixed;
      }
      const prev = tabId != null ? this._lastCompletedByTab.get(tabId) : null;
      if (!prev || !this.isCompletedReport(prev)) return data;
      const hNew = this.hostKeyFromUrl(data.url || tabUrl);
      const hPrev = this.hostKeyFromUrl(prev.url || tabUrl);
      if (hNew && hPrev && hNew === hPrev) {
        return {
          ...prev,
          ...data,
          analysisComplete: true,
          score: typeof data.score === "number" ? data.score : prev.score,
          riskLevel: data.riskLevel || prev.riskLevel,
          icpInfo: data.icpInfo || prev.icpInfo,
          whoisInfo: data.whoisInfo || prev.whoisInfo,
          details: (Array.isArray(data.details) && data.details.length) ? data.details : prev.details,
          url: tabUrl || data.url || prev.url
        };
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

    appendIcp(data) {
      if (!data || !data.icpInfo) return;
      const icp = this.el("div", "item");
      const strong = document.createElement("strong");
      strong.textContent = "ICP备案: ";
      icp.appendChild(strong);
      icp.appendChild(document.createTextNode(String(data.icpInfo)));
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

    /** 报告是否已完成扫描（或轻量路径）。 */
    isCompletedReport(data) {
      if (!data || typeof data !== "object") return false;
      if (data.analysisComplete === true) return true;
      // 只要带了评分+风险等级就展示结果，禁止 analysisComplete:false 把 UI 打回「正在分析」
      // （WHOIS/ICP 回调常在 ~1s 后误发 incomplete）
      if (typeof data.score === "number" && data.riskLevel) return true;
      if (data.type === "threat-risk" && typeof data.score === "number") return true;
      if (data.downloadGuardInstalled || data.packageBlocked || data.brandSpoofPortal || data.spoofBrand) return true;
      if (Array.isArray(data.details) && data.details.length > 0) return true;
      if (data.icpInfo || data.whoisInfo) return true;
      return false;
    }

    /** 报告自身声明包保护仍 armed。 */
    reportHasProtection(data) {
      if (!data) return false;
      if (data.downloadGuardInstalled || data.packageBlocked) return true;
      if (data.brandSpoofPortal || data.spoofBrand) return true;
      if (Array.isArray(data.protectedTargets) && data.protectedTargets.length > 0) return true;
      if (Array.isArray(data.details) && data.details.some((d) => /已启用安装包下载拦截|已启用仿冒站|已启用异常跳转|下载拦截|仿冒|可疑下载|已拦截可疑/i.test(d.name || ""))) return true;
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

    brandSpoofFromData(data) {
      if (!data) return "";
      if (data.spoofBrand) return String(data.spoofBrand);
      const d = (data.details || []).find((x) => /仿冒品牌官网/i.test(x.name || ""));
      if (!d || !d.reason) return data.brandSpoofPortal ? "品牌" : "";
      const m = String(d.reason).match(/品牌[「「"']([^」」"']+)[」」"']/);
      return m ? m[1] : (data.brandSpoofPortal ? "品牌" : "");
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
      const brandSpoof = !!(data?.brandSpoofPortal || data?.spoofBrand) || details.some((d) => /仿冒品牌官网/i.test(d.name || ""));
      const multiSerp = details.some((d) => /多平台下载指向搜索引擎/i.test(d.name || ""));
      let title;
      if (level === "high") title = brandSpoof && data?.spoofBrand ? `存在严重风险（仿冒「${data.spoofBrand}」官网）` : "存在严重风险";
      else if (level === "medium") {
        if (brandSpoof && data?.spoofBrand) title = `存在中度风险（仿冒「${data.spoofBrand}」官网）`;
        else if (multiSerp) title = "存在中度风险（异常下载跳转）";
        else if (protectedActive) title = "存在中度风险（已拦截可疑下载）";
        else title = "存在中度风险";
      } else if (score > 0 || details.length > 0) { title = "存在低度风险"; level = "low"; }
      else title = "未发现明显风险";
      return { level, title };
    }

    renderRisk(data, latestNotice, tabUrl) {
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

      if (brandSpoof) {
        this.root.appendChild(this.el("div", "high", brandName && brandName !== "品牌" ? `已识别仿冒「${brandName}」官网` : "已识别仿冒品牌官网下载站"));
        const item = this.el("div", "item");
        item.appendChild(document.createTextNode(brandName && brandName !== "品牌" ? `页面标题/正文品牌「${brandName}」与当前域名不匹配，疑似仿冒官网。` : "页面宣称品牌官网下载，但域名与品牌关联不严谨。"));
        this.root.appendChild(item);
      } else if (multiSerp) {
        this.root.appendChild(this.el("div", "high", "已拦截异常下载跳转"));
        this.root.appendChild(this.el("div", "item", "多平台下载入口统一跳转搜索引擎，不是真实安装包。"));
      } else if (showNotice && !this.looksLikeSearchOrNonPackageTarget(latestNotice.message)) {
        this.root.appendChild(this.el("div", "high", latestNotice.title || "已拦截可疑下载文件"));
        const item = this.el("div", "item");
        item.appendChild(document.createTextNode("说明: "));
        item.appendChild(document.createTextNode(String(latestNotice.message || "可疑下载目标")));
        this.root.appendChild(item);
      } else if (showNotice && this.looksLikeSearchOrNonPackageTarget(latestNotice.message)) {
        this.root.appendChild(this.el("div", "high", latestNotice.title || "已拦截异常下载跳转"));
        this.root.appendChild(this.el("div", "item", String(latestNotice.message || "异常跳转（非安装包）")));
      } else if (protectedActive && matchedData?.protectedTargets?.some((t) => this.looksLikePackageTarget(t))) {
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
        return;
      }
      if (!completed) {
        // 有半份数据：直接当完成展示，不再卡「正在分析」
        const { level, title } = this.resolveRiskPresentation(matchedData, protectedActive);
        this.root.appendChild(this.el("div", level, title));
        this.root.appendChild(this.el("div", "item", `评分: ${matchedData.score ?? 0}`));
        this.appendIcp(matchedData);
        this.appendWhois(matchedData);
        if (details.length === 0 && !protectedActive) {
          this.root.appendChild(this.el("div", "item", "未检测到威胁行为信号。"));
        } else {
          details.forEach((d) => {
            const line = this.el("div", "item", `- ${d.name || "信号"}`);
            if (d.reason) line.title = String(d.reason);
            this.root.appendChild(line);
          });
        }
        return;
      }
      const { level, title } = this.resolveRiskPresentation(matchedData, protectedActive);
      this.root.appendChild(this.el("div", level, title));
      this.root.appendChild(this.el("div", "item", `评分: ${matchedData.score ?? 0}`));
      this.appendIcp(matchedData);
      this.appendWhois(matchedData);
      if (protectedActive && this.reportHasProtection(matchedData)) {
        if (brandSpoof) this.root.appendChild(this.el("div", "item", brandName && brandName !== "品牌" ? `状态: 已按仿冒「${brandName}」官网处理，下载入口已禁用` : "状态: 已按仿冒品牌官网处理，下载入口已禁用"));
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

    refresh(currentTabUrl) {
      if (this.activeTabId == null) return;
      if (currentTabUrl) this.activeTabUrl = currentTabUrl;
      chrome.storage.local.get([`risk_${this.activeTabId}`, "risk_latest", "latestNotice"], (result) => {
        if (chrome.runtime.lastError) { this.clearRoot(); this.root.appendChild(this.el("div", "item", "读取扩展数据失败。")); return; }
        const tabUrl = this.activeTabUrl || currentTabUrl || "";
        const localRaw = result[`risk_${this.activeTabId}`] || null;
        const localData = this.dataMatchesTab(localRaw, tabUrl) ? localRaw : null;
        const latestData = result.risk_latest && this.dataMatchesTab(result.risk_latest, tabUrl) ? result.risk_latest : null;
        const data = localData || latestData || null;
        const notice = result.latestNotice || null;
        this.renderRisk(data, notice, tabUrl);
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
          this.renderRisk(msg, null, this.activeTabUrl || msg.url);
          return;
        }
        if (msg.type === "threat-notice" && sender.tab?.id === this.activeTabId) {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => { const t = tabs?.[0]; if (t?.url) this.activeTabUrl = t.url; this.refresh(this.activeTabUrl); });
        }
      });
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName !== "local" || this.activeTabId == null) return;
        if (changes[`risk_${this.activeTabId}`] || changes.risk_latest || changes.latestNotice) {
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

  document.addEventListener("DOMContentLoaded", () => {
    const root = document.getElementById("result");
    if (!root) return;
    new PopupRenderer(root).init();
  });
})();
