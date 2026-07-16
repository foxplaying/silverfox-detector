/**
 * 标题↔主机品牌相关性、营销仿冒主机判定、品牌资源失配收集。
 */
;(function (NS) {
  "use strict";

  NS.getClaimedBrandContext = function () {
    const title = document.title || "";
    const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
    const ogTitle = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
    const ogSite = document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "";
    const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(4000) : (document.querySelector("h1")?.textContent || "");
    const brandSource = `${title} ${headings} ${ogTitle} ${ogSite} ${String(desc).slice(0, 400)}`;
    const claimsOfficial = /官网|官方下载|官方正版|正式版|官方软件|官方网站|电脑版官网|官方桌面|官方客户端/i.test(`${title} ${headings} ${ogTitle}`);
    const tokens = new Set();
    (brandSource.match(/([一-鿿]{2,8})(?=官网|官方|下载|客户端|软件|杀毒|安全)/g) || []).forEach((c) => {
      if (!/^(下载|官方|软件|客户端|安全|杀毒|电脑|免费|最新|正版)$/.test(c)) tokens.add(c);
    });
    NS.extractLatinBrandTokens(brandSource).forEach((low) => tokens.add(low));
    try {
      const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      (brandSource.match(/[A-Za-z][a-zA-Z]{2,}/g) || []).forEach((b) => {
        const low = b.toLowerCase();
        if (low.length === 3 && !NS.BRAND_TOKEN_STOP_RE.test(low) && (lab === low || lab.startsWith(low) || lab.includes(low))) tokens.add(low);
      });
    } catch { /* ignore */ }
    return { brandSource, claimsOfficial, tokens };
  };

  /**
   * 标题 + 标题品牌 token 与主机名相关性（无品牌白名单）。
   * 关键：用 <title> + h1–h6 + footer 版权作为身份声明，而非 meta keywords/body 合作品牌。
   */
  NS.evaluateTitleHostBrandCorrelation = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "serp", hostLabel: "", pageApex: "", rigorousMatch: false };
      const title = document.title || "";
      if (/[-–|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title)) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "serp", hostLabel: "", pageApex: "", rigorousMatch: false };
      const headings = NS.collectHeadingText(4000);
      const claimText = `${title} ${headings}`.replace(/\s+/g, " ").trim();
      const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
      const ogTitle = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
      const ogUrl = document.querySelector('meta[property="og:url"]')?.getAttribute("content") || "";
      const canonical = document.querySelector('link[rel="canonical"]')?.getAttribute("href") || "";
      const host = location.hostname.toLowerCase().replace(/^www\./, "");
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const label = labelRaw.replace(/-/g, "");
      const pageApex = NS.getRegistrableDomain(host) || host;
      const footerId = NS.footerCopyrightMatchesPageHost();
      const footerText = footerId.text || "";

      const squatShape = NS.titleBrandVsHostSquatShape(claimText, labelRaw, "");
      if (squatShape === "padded" || squatShape === "typo" || squatShape === "hyphen") {
        const titleToks = NS.extractLatinBrandTokens(claimText);
        const brandTok = NS.pickBrandTokenForHost(titleToks, labelRaw) || titleToks[0] || "";
        const officialPitchEarly = /官网|官方下载|官方正版|官方网站|电脑版官网|免费下载|官方桌面|官方客户端|专业.*工具|立即下载|全平台官方/i.test(claimText);
        if (officialPitchEarly && brandTok && !NS.BRAND_TOKEN_STOP_RE.test(brandTok)) {
          return { mismatch: true, brandToken: brandTok, brandHits: 12, hostMatch: squatShape, hostLabel: label, pageApex, rigorousMatch: false };
        }
      }

      const claimLow = claimText.toLowerCase();
      if (footerId.match && !NS.isBrandSquatHostMatch(squatShape) && squatShape !== "hyphen") {
        if (/^\d{3,4}$/.test(label)) {
          const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const digitInClaim = (claimText.match(new RegExp(esc, "g")) || []).length;
          if (digitInClaim >= 1 || /版权所有|互联网安全中心/i.test(footerText)) {
            return { mismatch: false, brandToken: label, brandHits: footerId.hits + digitInClaim + 4, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
          }
        } else if (squatShape === "exact" || squatShape === "") {
          if (/-/.test(labelRaw) && NS.hostLabelIsHyphenatedBrandMirror(labelRaw, label)) { /* not exact */ }
          else if (label.length >= 3 && (claimLow.includes(label) || /^\d{3,4}$/.test(label))) {
            return { mismatch: false, brandToken: label, brandHits: footerId.hits + 4, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
          }
        }
      }

      if (/^\d{3,4}$/.test(label)) {
        const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const digitHits = (claimText.match(new RegExp(esc, "g")) || []).length + (footerText.match(new RegExp(esc, "g")) || []).length;
        if (digitHits >= 2 && (/官网|官方|安全|软件|中心/i.test(claimText) || /版权所有|安全中心/i.test(footerText))) {
          return { mismatch: false, brandToken: label, brandHits: digitHits, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
        }
        if (digitHits >= 1 && (/官网|官方网站|官方下载/i.test(claimText) || /版权所有/i.test(footerText)) && (claimText.indexOf(label) >= 0 || footerText.indexOf(label) >= 0)) {
          return { mismatch: false, brandToken: label, brandHits: digitHits, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
        }
      }

      if (/^[a-z][a-z0-9]{2,}$/i.test(label) && label.length >= 3 && squatShape !== "padded" && squatShape !== "typo" && squatShape !== "hyphen" && !/-/.test(labelRaw)) {
        const footLow = footerText.toLowerCase();
        const claimCompact = claimLow.replace(/[^a-z0-9]+/g, "");
        const inClaim = claimLow.includes(label) || (label.length >= 8 && claimCompact.includes(label));
        if (inClaim && label.length >= 4) {
          const hits = ((claimLow + " " + footLow).match(new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length || (claimCompact.includes(label) ? 2 : 0);
          if (hits >= 1) return { mismatch: false, brandToken: label, brandHits: Math.max(hits, 4), hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
        }
        if (inClaim && label.length >= 3 && (/官网|官方|下载|安全|软件|中心|Download|Free|Products|Uninstall/i.test(claimText) || /版权所有|Copyright|©/i.test(footerText))) {
          const hits = ((claimLow + " " + footLow).match(new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length || (claimCompact.includes(label) ? 2 : 0);
          if (hits >= 1) return { mismatch: false, brandToken: label, brandHits: hits, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
        }
      }

      const stop = NS.BRAND_TOKEN_STOP_RE;
      const titleTokens = NS.extractLatinBrandTokens(claimText);
      (claimText.match(/[A-Za-z][a-zA-Z]{2,}/g) || []).forEach((b) => {
        const low = b.toLowerCase();
        if (low.length === 3 && !stop.test(low) && (label === low || label.startsWith(low) || label.includes(low)) && !titleTokens.includes(low)) titleTokens.push(low);
      });
      const ogTokens = NS.extractLatinBrandTokens(ogTitle);
      const headTokens = titleTokens.length ? titleTokens : ogTokens;
      if (!headTokens.length) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "none", hostLabel: label, pageApex, rigorousMatch: false };

      const body = ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").slice(0, 10000).toLowerCase();
      const titleLow = claimLow;
      const full = `${titleLow} ${body}`;

      const uniqueForCompound = [...new Set(headTokens)];
      const compoundSeed = [...uniqueForCompound];
      (claimText.match(/[A-Za-z][a-zA-Z]{3,}/g) || []).forEach((b) => {
        const low = b.toLowerCase();
        if (low.length >= 3 && low.length <= 20 && /^(uninstaller|installer|manager|cleaner|helper|desktop|player|browser|editor)$/i.test(low)) compoundSeed.push(low);
      });
      const compoundHost = NS.hostLabelComposedOfTitleTokens(label, compoundSeed);
      if (compoundHost && squatShape !== "hyphen") {
        const displayTok = uniqueForCompound.filter((t) => t.length >= 3 && !stop.test(t) && label.includes(t)).sort((a, b) => a.length - b.length)[0] || label;
        return { mismatch: false, brandToken: displayTok, brandHits: 12, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
      }

      let brandToken = NS.pickBrandTokenForHost(headTokens, labelRaw);
      let brandHits = 0;
      const uniqueTokens = [...new Set(headTokens)];
      for (const t of uniqueTokens) {
        if (uniqueTokens.some((o) => o !== t && o.length > t.length && o.includes(t))) continue;
        if (stop.test(t) && label !== t) continue;
        let nTitle = 0; let nFull = 0;
        try {
          const re = new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
          nTitle = (titleLow.match(re) || []).length;
          nFull = (full.match(re) || []).length;
        } catch { nTitle = titleLow.split(t).length - 1; nFull = full.split(t).length - 1; }
        if (nTitle < 1 && titleTokens.length > 0) continue;
        if (t.length < 4 && !(label === t || label.startsWith(t) || label.includes(t))) continue;
        let score = nTitle * 10 + Math.min(nFull, 20);
        if (label === t) score += 100;
        else if (NS.hostLabelIsBrandTypo(label, t)) score += 90;
        else if (NS.hostLabelIsPaddedBrand(label, t) || NS.hostLabelIsPaddedBrand(labelRaw, t)) score += 70;
        else if (label.startsWith(t) && t.length >= 3) score += 40;
        else if (label.includes(t) && t.length >= 4) score += 15;
        if (/^(uninstaller|installer|manager|cleaner|remover|helper|desktop|software|application)$/i.test(t)) score -= 50;
        const lead = titleLow.trim().slice(0, 48);
        if (lead.startsWith(t) || new RegExp(`^[^a-z]*${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i").test(titleLow)) score += 25;
        if (score > brandHits || (score === brandHits && NS.hostLabelIsBrandTypo(label, t))) { brandHits = score; brandToken = t; }
      }
      if (brandToken && NS.BRAND_TOKEN_STOP_RE.test(brandToken)) {
        brandToken = NS.pickBrandTokenForHost(headTokens.filter((t) => !NS.BRAND_TOKEN_STOP_RE.test(t)), labelRaw) || headTokens.find((t) => !NS.BRAND_TOKEN_STOP_RE.test(t)) || "";
        brandHits = brandToken ? Math.max(brandHits, 8) : 0;
      }
      if (!brandToken) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "none", hostLabel: label, pageApex, rigorousMatch: false };

      const hyphenMirror = NS.hostLabelIsHyphenatedBrandMirror(labelRaw, brandToken);
      const rigorousMatch = !hyphenMirror && (
        label === brandToken
        || NS.hostLabelComposedOfTitleTokens(label, uniqueTokens.concat(compoundSeed))
        || pageApex === `${brandToken}.com` || pageApex === `${brandToken}.cn` || pageApex === `${brandToken}.com.cn` || pageApex === `${brandToken}.net` || pageApex === `${brandToken}.org`
        || host === `${brandToken}.com` || host === `${brandToken}.cn`
        || host.endsWith(`.${brandToken}.com`) || host.endsWith(`.${brandToken}.cn`) || host.endsWith(`.${brandToken}.com.cn`)
        || (/^\d{3,4}/.test(label) && brandToken === label.replace(/[^0-9].*$/, "") && label.startsWith(brandToken))
        || (label.startsWith(brandToken) && brandToken.length >= 3 && label.length > brandToken.length && NS.hostLabelComposedOfTitleTokens(label, uniqueTokens.concat(compoundSeed)))
      );
      let hostMatch = "none";
      if (hyphenMirror) hostMatch = "hyphen";
      else if (rigorousMatch) hostMatch = "exact";
      else if (NS.hostLabelIsBrandTypo(label, brandToken)) hostMatch = "typo";
      else if (NS.hostLabelIsPaddedBrand(label, brandToken) || NS.hostLabelIsPaddedBrand(labelRaw, brandToken)) hostMatch = "padded";
      else if (label.includes(brandToken) || brandToken.includes(label)) hostMatch = "partial";

      let canonMismatch = false;
      for (const raw of [ogUrl, canonical]) {
        if (!raw) continue;
        try {
          const ch = new URL(raw, location.href).hostname.toLowerCase().replace(/^www\./, "");
          const cLabel = (ch.split(".")[0] || "").replace(/-/g, "");
          const cApex = NS.getRegistrableDomain(ch) || ch;
          if (cApex === pageApex) continue;
          if (cLabel === brandToken || NS.hostLabelIsBrandTypo(cLabel, brandToken) || ch.includes(brandToken)) {
            if (!rigorousMatch) canonMismatch = true;
          }
        } catch { /* ignore */ }
      }

      const thirdPartyProxy = typeof NS.pageLooksLikeThirdPartyBrandProxyOrMirror === "function" && NS.pageLooksLikeThirdPartyBrandProxyOrMirror();
      const officialPitch = !thirdPartyProxy && (
        /官网|官方下载|官方正版|官方网站|全平台官方|官方客户端|远程桌面|客户端下载|电脑版官网|官方桌面/i.test(claimText) || NS.pageClaimsBrandDownloadLanding()
      );
      let mismatch = false;
      if (!thirdPartyProxy) {
        if (officialPitch && hostMatch === "typo" && brandHits >= 2) mismatch = true;
        if (officialPitch && hostMatch === "padded" && brandHits >= 3) mismatch = true;
        if (officialPitch && hostMatch === "hyphen" && brandHits >= 2) mismatch = true;
        if (officialPitch && hostMatch === "none" && brandHits >= 8) mismatch = true;
        if (officialPitch && hostMatch === "partial" && !rigorousMatch && brandHits >= 12) mismatch = true;
        if (officialPitch && canonMismatch && !rigorousMatch && brandHits >= 8) mismatch = true;
        if (!mismatch && hostMatch === "padded" && brandHits >= 8 && /下载|客户端|安装|免费|AI|模型|软件/i.test(titleLow + body.slice(0, 800))) mismatch = true;
        if (!mismatch && hostMatch === "hyphen" && brandHits >= 4 && /下载|客户端|安装|免费|软件|工具|测试/i.test(titleLow + body.slice(0, 800))) mismatch = true;
      }
      return { mismatch, brandToken, brandHits, hostMatch, hostLabel: label, pageApex, rigorousMatch };
    } catch {
      return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "none", hostLabel: "", pageApex: "", rigorousMatch: false };
    }
  };

  NS.hostLooksLikeBrandMarketingSpoof = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
      try {
        const hr = NS.brandRootKeyFromHost(location.hostname);
        const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        if (hr.length >= 4 && /^(wiki|docs?|help|manual|handbook|bbs|forum|forums|community)$/i.test(lab0)) {
          const titleLow = (document.title || "").toLowerCase();
          if (titleLow.includes(hr) || titleLow.replace(/[^a-z0-9]/g, "").includes(hr)) return false;
        }
      } catch { /* ignore */ }
      const state = NS.state;
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected) return false;
      const corrEarly = NS.evaluateTitleHostBrandCorrelation();
      if ((corrEarly.rigorousMatch || corrEarly.hostMatch === "exact") && corrEarly.hostMatch !== "hyphen" && corrEarly.hostMatch !== "padded" && corrEarly.hostMatch !== "typo") return false;

      const { brandSource, claimsOfficial, tokens } = NS.getClaimedBrandContext();
      const softOfficial = claimsOfficial || /官方下载|全平台官方|官方客户端|官方网站|客户端下载|客户端完全免费|客户端永久免费/i.test(brandSource) || NS.pageClaimsBrandDownloadLanding();
      if (!softOfficial && tokens.size === 0) return false;

      const corr = corrEarly;
      if (corr.mismatch && (softOfficial || corr.hostMatch === "padded" || corr.hostMatch === "typo" || corr.hostMatch === "hyphen")) return true;
      if (softOfficial && corr.hostMatch === "hyphen" && corr.brandToken) return true;

      const host = location.hostname.toLowerCase().replace(/^www\./, "");
      const label = (host.split(".")[0] || "").replace(/-/g, "");
      const labelRaw = (host.split(".")[0] || "");
      const pageApex = NS.getRegistrableDomain(host) || "";
      const htmlHead = NS.getHtmlSlice(50000);
      const seoTemplate = /seo[_-]?templates?|\/zd\/[a-z0-9_-]+\/|seo_templates\/index/i.test(`${location.pathname} ${htmlHead}`);
      const schemaBrandSpam = (htmlHead.match(/"@type"\s*:\s*"(?:Organization|SoftwareApplication|WebSite|Product|FAQPage)"/gi) || []).length >= 3 && /"name"\s*:\s*"[^"]{2,40}"/i.test(htmlHead);
      const marketingForm = /^(pc|m|aa|bb|cc|www\d*|download|down|soft|free|get|app|client|safe|vip|pro|gw|guanwang|official|safe)[-_]/i.test(labelRaw) || /[-_](download|down|soft|safe|app|pc|vip|pro|gw|guanwang|official)$/i.test(labelRaw) || /[-_]/.test(labelRaw);
      const titleTokList = [...tokens].filter((t) => /^[a-z]{3,}$/i.test(t)).map((t) => t.toLowerCase());
      const compoundOk = typeof NS.hostLabelComposedOfTitleTokens === "function" && NS.hostLabelComposedOfTitleTokens(label, titleTokList.concat((brandSource.match(/[A-Za-z][a-zA-Z]{3,}/g) || []).map((x) => x.toLowerCase()).filter((x) => /^(uninstaller|installer|manager|cleaner|helper|desktop)$/i.test(x))));
      let brandInHostPartial = false, brandPaddedHost = false, brandHyphenMirror = false, brandExactLabelOnWrongApex = false, brandTypoHost = false;
      for (const t of tokens) {
        if (!/^[a-z]{3,}$/i.test(t)) continue;
        const tl = t.toLowerCase();
        if (/^(uninstaller|installer|download|software|manager|cleaner|desktop|client|setup)$/i.test(tl)) continue;
        if (!compoundOk && label.includes(tl) && label !== tl && label.length > tl.length + 1) brandInHostPartial = true;
        if (!compoundOk && (NS.hostLabelIsPaddedBrand(label, tl) || NS.hostLabelIsPaddedBrand(labelRaw.replace(/-/g, ""), tl))) brandPaddedHost = true;
        if (NS.hostLabelIsHyphenatedBrandMirror(labelRaw, tl)) brandHyphenMirror = true;
        if (NS.hostLabelIsBrandTypo(label, tl) || NS.hostLabelIsBrandTypo(labelRaw.replace(/-/g, ""), tl)) brandTypoHost = true;
        if (softOfficial && (label === tl || host.startsWith(`${tl}.`)) && host.split(".").length >= 3) {
          const realish = new Set([`${tl}.com`, `${tl}.cn`, `${tl}.com.cn`, `${tl}.net`, `${tl}.org`]);
          const pageHost = NS.normalizeDomain(host);
          if (pageHost && !realish.has(pageHost) && !realish.has(pageApex || "")) brandExactLabelOnWrongApex = true;
        }
        if (softOfficial && label === tl) {
          const realish = new Set([`${tl}.com`, `${tl}.cn`, `${tl}.com.cn`, `${tl}.net`, `${tl}.org`]);
          if (pageApex && !realish.has(pageApex) && pageApex !== tl) brandExactLabelOnWrongApex = true;
        }
      }
      const cnProductBrand = /([一-鿿]{2,8})(?=官网|官方|下载|客户端|软件|杀毒|安全)/.test(brandSource) && claimsOfficial;
      const latinMarketingHost = /^[a-z0-9-]{5,}$/i.test(labelRaw) && /[-_]/.test(labelRaw);

      if (seoTemplate && softOfficial) return true;
      if (softOfficial && brandTypoHost) return true;
      if (softOfficial && brandHyphenMirror) return true;
      if ((softOfficial || schemaBrandSpam) && brandPaddedHost) return true;
      if (softOfficial && marketingForm && (brandInHostPartial || brandPaddedHost || brandHyphenMirror || (cnProductBrand && latinMarketingHost && claimsOfficial))) return true;
      if (softOfficial && brandInHostPartial) return true;
      if (softOfficial && brandExactLabelOnWrongApex) return true;
      if (schemaBrandSpam && (brandPaddedHost || brandHyphenMirror) && tokens.size >= 1) return true;
      if (softOfficial && NS.looksLikeRandomDownloadHost(location.hostname)) return true;
      return false;
    } catch { return false; }
  };

  NS.collectBrandResourceMismatch = function (titleOpt) {
    const title = titleOpt || document.title || "";
    const pageApex = NS.guessApexDomain(location.hostname) || NS.getRegistrableDomain(location.hostname);
    const titleTokens = (title.match(/[A-Za-z]{4,}/g) || []).map((t) => t.toLowerCase())
      .filter((t) => t.length >= 4 && !/^(download|windows|linux|android|macos|official|client|software|remote|chrome|https|http|free|desk|home|page|site)$/i.test(t));
    const hostLabel = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
    if (hostLabel.length >= 4 && /[a-z]{4,}/i.test(hostLabel)) titleTokens.push(hostLabel);
    let brandAssetHits = 0;
    const brandApexes = new Map();
    const sampleSel = "img[src], link[href], script[src], a[href], source[src], video[src], audio[src]";
    try {
      const nodes = document.querySelectorAll(sampleSel);
      const n = Math.min(nodes.length, 200);
      for (let i = 0; i < n; i++) {
        const el = nodes[i];
        try {
          const raw = el.currentSrc || el.src || el.href || el.getAttribute("href") || el.getAttribute("src") || "";
          if (!raw || raw.startsWith("data:") || raw.startsWith("javascript:")) continue;
          const u = new URL(raw, location.href);
          if (u.hostname === location.hostname) continue;
          const apex = NS.guessApexDomain(u.hostname) || NS.getRegistrableDomain(u.hostname);
          if (!apex || apex === pageApex) continue;
          if (pageApex && NS.apexSameBrandFamily(pageApex, apex)) continue;
          if (NS.pageIsSameBrandFamilySite(location.hostname, apex)) continue;
          const hostFlat = u.hostname.replace(/[^a-z0-9]/gi, "");
          const hit = titleTokens.some((t) => t.length >= 4 && hostFlat.includes(t));
          if (!hit) continue;
          brandAssetHits++;
          brandApexes.set(apex, (brandApexes.get(apex) || 0) + 1);
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    let topBrandApex = ""; let topCount = 0;
    for (const [apex, c] of brandApexes) { if (c > topCount) { topCount = c; topBrandApex = apex; } }
    return { pageApex, brandAssetHits, brandApexes, topBrandApex, topCount, titleTokens: [...new Set(titleTokens)] };
  };
})(window.SilverfoxContent ??= {});
