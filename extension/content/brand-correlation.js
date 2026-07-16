/**
 * 标题↔主机品牌相关性、营销仿冒主机判定、品牌资源失配收集。
 */
;(function (NS) {
  "use strict";

  /**
   * 品牌身份文本：只拼 title / h* / description / keywords / footer / logo / author。
   * CTA 文案仅作「是否宣称下载」辅助，不参与产品名选词。
   */
  NS.collectBrandIdentityText = function () {
    try {
      const blob = typeof NS.productBrandIdentityBlob === "function"
        ? NS.productBrandIdentityBlob()
        : "";
      if (blob) return blob;
      // fallback（旧路径）
      const title = document.title || "";
      const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(4000) : "";
      return `${title} ${headings}`.replace(/\s+/g, " ").trim();
    } catch {
      return document.title || "";
    }
  };

  NS.getClaimedBrandContext = function () {
    const title = document.title || "";
    const picked = typeof NS.pickProductBrandFromIdentity === "function"
      ? NS.pickProductBrandFromIdentity()
      : null;
    const brandSource = typeof NS.collectBrandIdentityText === "function"
      ? NS.collectBrandIdentityText()
      : `${title}`;
    // 下载话术：身份字段 + 主 CTA（CTA 不进品牌名，只判 official）
    let ctaBits = "";
    try {
      ctaBits = Array.from(document.querySelectorAll("a, button, [role='button'], .btn-header, .btn-primary, .btn-lg"))
        .map((el) => (el.textContent || "").replace(/\s+/g, " ").trim())
        .filter((t) => t.length >= 2 && t.length <= 28 && /下载|安装|客户端|Download|免费|立即/i.test(t))
        .slice(0, 14)
        .join(" ");
    } catch { /* ignore */ }
    const pitchBlob = `${brandSource} ${ctaBits}`;
    // 勿用裸「杀毒软件/安全软件」当官网宣称（科技博客评测「初中生开发杀毒软件」会误报仿冒）
    // 须带 官方/官网/下载落地 话术，或「XX安全」产品标题 + 免费下载类 CTA
    const claimsOfficial = /官网|官方下载|官方正版|正式版|官方软件|官方网站|电脑版官网|官方桌面|官方客户端|官方安全|官方杀毒|杀毒软件官网|安全软件官网|免费下载|立即下载|立即免费下载|个人版|终端安全/i.test(pitchBlob)
      || /官网|官方下载|官方正版|正式版|官方软件|官方网站|电脑版官网|官方桌面|官方客户端|官方安全|官方杀毒|杀毒软件官网|安全软件官网/i.test(title)
      || (/[一-鿿]{2,6}(?:安全|杀毒)/.test(title) && /官方|官网|免费下载|立即下载|个人版|安静|纯净|强悍/i.test(pitchBlob)
        && !/(?:开发|开源|评测|体验|刷到|初中生|B站|趣闻|推荐|介绍).{0,12}(?:杀毒|安全)软件/i.test(title + pitchBlob.slice(0, 200)));
    const tokens = new Set();
    // 身份字段中文候选 + 主品牌
    if (picked && picked.cnBrand) tokens.add(picked.cnBrand);
    if (picked && picked.latinToken) tokens.add(picked.latinToken);
    if (typeof NS.extractChineseProductBrandCandidates === "function") {
      NS.extractChineseProductBrandCandidates(brandSource).forEach((c) => {
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(c)) return;
        tokens.add(c);
      });
    } else {
      (brandSource.match(/([一-鿿]{2,8})(?=官网|官方|下载|客户端|软件|杀毒|安全)/g) || []).forEach((c) => {
        if (/^(下载|官方|软件|客户端|安全|杀毒|电脑|免费|最新|正版|安静|纯净|强悍|文章|专题|详情)$/.test(c)) return;
        tokens.add(c);
      });
    }
    // 仅从身份 blob 抽拉丁（不含 CMS meta / 全文 body）
    NS.extractLatinBrandTokens(brandSource).forEach((low) => tokens.add(low));
    try {
      const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const core = NS.inferMarketingPaddedBrandCore(lab0);
        if (core && core.length >= 4 && !NS.BRAND_TOKEN_STOP_RE.test(core)) tokens.add(core);
      }
    } catch { /* ignore */ }
    return {
      brandSource,
      claimsOfficial,
      tokens,
      productBrand: picked || null
    };
  };

  /**
   * 标题↔主机品牌相关性（无品牌白名单）。
   * 产品关键词只从 title / h* / description / keywords / footer 选（pickProductBrandFromIdentity），
   * 禁止 body / CMS meta（template、generator）参与展示名。
   */
  NS.evaluateTitleHostBrandCorrelation = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "serp", hostLabel: "", pageApex: "", rigorousMatch: false, displayBrand: "" };
      const title = document.title || "";
      if (/[-–|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title)) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "serp", hostLabel: "", pageApex: "", rigorousMatch: false, displayBrand: "" };
      const headings = NS.collectHeadingText(4000);
      // 产品关键词只从 title / h* / desc / keywords / footer 选（见 pickProductBrandFromIdentity）
      const productPick = typeof NS.pickProductBrandFromIdentity === "function"
        ? NS.pickProductBrandFromIdentity((location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "")
        : null;
      const identityText = typeof NS.collectBrandIdentityText === "function"
        ? NS.collectBrandIdentityText()
        : `${title} ${headings}`;
      const claimText = `${title} ${headings}`.replace(/\s+/g, " ").trim();
      // 主机对齐语料 = 身份字段 only，禁止全文/CMS
      const brandCorpus = identityText || claimText;
      const desc = (productPick && productPick.fields && productPick.fields.description)
        || (document.querySelector('meta[name="description"]')?.getAttribute("content") || "");
      const ogTitle = (productPick && productPick.fields && productPick.fields.ogTitle)
        || (document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "");
      const ogUrl = document.querySelector('meta[property="og:url"]')?.getAttribute("content") || "";
      const canonical = document.querySelector('link[rel="canonical"]')?.getAttribute("href") || "";
      const host = location.hostname.toLowerCase().replace(/^www\./, "");
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const label = labelRaw.replace(/-/g, "");
      const pageApex = NS.getRegistrableDomain(host) || host;
      const footerId = NS.footerCopyrightMatchesPageHost();
      const footerText = footerId.text || "";

      // 拉丁 token：只从身份字段；优先产品选词结果再主机对齐
      const latinIdentity = NS.extractLatinBrandTokens(brandCorpus);
      const hostAlignedLatin = (productPick && productPick.latinToken)
        || NS.pickBrandTokenForHost(latinIdentity, labelRaw)
        || "";
      const squatOnHost = hostAlignedLatin
        ? NS.titleBrandVsHostSquatShape(brandCorpus, labelRaw, hostAlignedLatin)
        : NS.titleBrandVsHostSquatShape(brandCorpus, labelRaw, "");
      // 中文产品名：title/h1–h6/keywords/description/footer 共识（网易云音乐/钉钉）
      let cnDisplay = (productPick && productPick.cnBrand) || (productPick && productPick.displayBrand && /[一-鿿]/.test(productPick.displayBrand) ? productPick.displayBrand : "") || "";
      if (!cnDisplay && typeof NS.pickChineseBrandFromIdentityConsensus === "function") {
        cnDisplay = NS.pickChineseBrandFromIdentityConsensus() || "";
      }
      if (!cnDisplay && typeof NS.pickChineseBrandFromPageSurface === "function") {
        // title/og 先于 keywords（避免 SEO「文章」成为展示品牌）
        cnDisplay = NS.pickChineseBrandFromPageSurface(title)
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(document.querySelector("h1")?.textContent || "")
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[name="description"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(600) : "")
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "")
          || "";
      }
      if (!cnDisplay && typeof NS.extractChineseProductBrandCandidates === "function") {
        // 候选按完整名优先：取最长非弱词（数字前缀产品优先）
        const pool = [
          ...NS.extractChineseProductBrandCandidates(claimText),
          ...NS.extractChineseProductBrandCandidates(identityText)
        ].filter((c) => !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(c)));
        pool.sort((a, b) => {
          const da = /^\d{2,6}[一-鿿]{2,6}$/.test(a) ? 1 : 0;
          const db = /^\d{2,6}[一-鿿]{2,6}$/.test(b) ? 1 : 0;
          if (da !== db) return db - da;
          return b.length - a.length;
        });
        cnDisplay = pool[0] || "";
      }
      if (!cnDisplay) {
        try {
          // 优先数字前缀产品（360安全卫士），勿取 title 首段「文章」
          const digitHit = ((title + " " + identityText).match(/(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
          if (digitHit && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(digitHit))) {
            cnDisplay = digitHit;
          }
          const cnHit = (title + identityText).match(/([一-鿿]{2,6})(?=安全|杀毒|官网|官方|下载|软件|客户端)/);
          if (!cnDisplay && cnHit && cnHit[1]
            && !/^(下载|官方|软件|客户端|安全|杀毒|电脑|免费|最新|正版|安静|纯净|强悍|文章|专题|详情)$/.test(cnHit[1])
            && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cnHit[1]))) {
            cnDisplay = cnHit[1];
          }
          if (!cnDisplay && typeof NS.pickChineseBrandFromPageSurface === "function") {
            cnDisplay = NS.pickChineseBrandFromPageSurface(title) || "";
          }
          if (!cnDisplay) {
            const segs = String(title || "").split(/\s*[-–—|:·｜]\s*/);
            for (const seg of segs) {
              const t0 = (seg.match(/[一-鿿]{2,6}/) || [])[0] || "";
              if (!t0) continue;
              if (/^(安全|软件|下载|官方|电脑|系统|工具|音乐|视频|文章|专题|详情|导读|正文)$/.test(t0)) continue;
              if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t0)) continue;
              cnDisplay = t0;
              break;
            }
          }
        } catch { /* ignore */ }
      }
      if (cnDisplay && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cnDisplay)) {
        cnDisplay = "";
      }

      // 与下载落地壳对齐：勿用裸「杀毒软件/安全软件」当官网 pitch（博客评测误报）
      const officialPitchEarly = /官网|官方下载|官方正版|官方网站|电脑版官网|免费下载|立即免费下载|官方桌面|官方客户端|官方安全|官方杀毒|专业.*工具|立即下载|全平台官方|Enterprise|Collaboration|AI-Powered|安静|纯净|强悍|个人版|终端安全/i.test(`${claimText} ${identityText}`);
      // 主机营销夹带核心：即使页上无 Huorong 拉丁，huorong-pc 也可推断
      const inferredHostCore = typeof NS.inferMarketingPaddedBrandCore === "function"
        ? (NS.inferMarketingPaddedBrandCore(labelRaw) || "")
        : "";

      const squatShape = squatOnHost || NS.titleBrandVsHostSquatShape(claimText, labelRaw, hostAlignedLatin || inferredHostCore || "");
      const resolveDisplay = (latinTok) => {
        if (cnDisplay) return cnDisplay;
        if (productPick && productPick.displayBrand) return productPick.displayBrand;
        if (typeof NS.pickBrandDisplayName === "function") {
          return NS.pickBrandDisplayName({ title, identity: identityText, displayBrand: cnDisplay, brandToken: latinTok, labelRaw }) || latinTok || "";
        }
        return latinTok || "";
      };
      // 丢弃 CMS/停用拉丁 token（template/aurora/inter…）
      const usableLatin = (tok) => {
        const t = String(tok || "").toLowerCase();
        return !!(t && t.length >= 4 && !NS.BRAND_TOKEN_STOP_RE.test(t));
      };

      if (squatShape === "padded" || squatShape === "typo" || squatShape === "hyphen") {
        let brandTok = hostAlignedLatin
          || (inferredHostCore && (NS.hostLabelIsPaddedBrand(label, inferredHostCore) || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, inferredHostCore))) ? inferredHostCore : "")
          || (typeof NS.pickPrimaryTitleBrandToken === "function" ? NS.pickPrimaryTitleBrandToken(title || claimText, labelRaw) : "")
          || NS.pickBrandTokenForHost(latinIdentity, labelRaw)
          || "";
        if (brandTok && !usableLatin(brandTok)) brandTok = inferredHostCore && usableLatin(inferredHostCore) ? inferredHostCore : "";
        // 中文站：拉丁 brand 可仅 4 字母（少见）；huorong 等 ≥5 或有中文展示名
        if (officialPitchEarly && brandTok && usableLatin(brandTok) && (brandTok.length >= 5 || cnDisplay)) {
          return {
            mismatch: true,
            brandToken: brandTok,
            brandHits: 14,
            hostMatch: squatShape,
            hostLabel: label,
            pageApex,
            rigorousMatch: false,
            displayBrand: resolveDisplay(brandTok)
          };
        }
        // 仅有中文品牌 + 主机为拼音夹带（关键词/页脚无拉丁时）：用主机核心段作 brandToken 仍标 mismatch
        if (officialPitchEarly && cnDisplay && !brandTok) {
          const core = inferredHostCore
            || label.replace(/(?:pc|app|soft|safe|vip|pro|cn|win|desk|security|guard|download|client)$/i, "");
          if (core.length >= 4 && core !== label && usableLatin(core) && NS.hostLabelIsPaddedBrand(label, core)) {
            return {
              mismatch: true,
              brandToken: core,
              brandHits: 12,
              hostMatch: "padded",
              hostLabel: label,
              pageApex,
              rigorousMatch: false,
              displayBrand: resolveDisplay(core)
            };
          }
        }
      }

      // 关键：中文品牌 + 营销夹带主机（huorong-pc / ca-hongrong），无可靠拉丁产品名时仍标 mismatch
      // 展示名强制中文，避免 meta template →「Template」
      if (cnDisplay && officialPitchEarly && squatShape !== "exact" && squatShape !== "serp") {
        const core = (usableLatin(hostAlignedLatin) ? hostAlignedLatin : "")
          || (usableLatin(inferredHostCore) ? inferredHostCore : "")
          || "";
        const coreOk = core && core.length >= 4 && core !== label
          && (
            NS.hostLabelIsPaddedBrand(label, core)
            || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, core))
            || (/-/.test(labelRaw) && NS.hostLabelIsPaddedBrand(labelRaw.replace(/-/g, ""), core))
          );
        const marketingHost = /[-_]/.test(labelRaw)
          || /^(?:ca|pc|m|aa|bb|cc|get|im|download|soft|safe|vip|pro)[-_]/i.test(labelRaw)
          || (label.length >= 10 && /(?:pc|app|soft|safe|vip|download|client)$/i.test(label));
        if (coreOk) {
          return {
            mismatch: true,
            brandToken: core,
            brandHits: 13,
            hostMatch: "padded",
            hostLabel: label,
            pageApex,
            rigorousMatch: false,
            displayBrand: resolveDisplay(core)
          };
        }
        // ca-hongrong + 标题「火绒安全」：主机与中文品牌无关/弱相关，仍标 none mismatch
        if (marketingHost) {
          return {
            mismatch: true,
            brandToken: core || cnDisplay,
            brandHits: 12,
            hostMatch: coreOk ? "padded" : "none",
            hostLabel: label,
            pageApex,
            rigorousMatch: false,
            displayBrand: resolveDisplay(core || cnDisplay)
          };
        }
        // dingdtalk.com.cn + 钉钉 / 任意无关域 + 火绒：中文产品下载壳 + 域名与品牌无关
        // pureLatin 放宽到 3 字符标签；短域/数字域/连字符无关域一并覆盖
        const pureLatinHost = /^[a-z][a-z0-9]{2,30}$/i.test(label) && !/[-_]/.test(labelRaw);
        const idLow = brandCorpus.toLowerCase();
        const hostInIdentity = label.length >= 3 && (idLow.includes(label) || claimText.toLowerCase().includes(label));
        const hostLooksKnownBrandPinyin = /huorong|hongrong|qihoo|tencent|baidu|sogou|kingsoft|rising|kaspersky|norton|avast|todesk|dingtalk|sunlogin|oray/i.test(label);
        if (!coreOk && !hostInIdentity && !hostLooksKnownBrandPinyin && cnDisplay.length >= 2) {
          // 主机像插字母/双写拼写壳 → typo，否则 none
          let shape = "none";
          if (pureLatinHost || /[-_]/.test(labelRaw) || /^\d/.test(label) || label.length >= 3) {
            try {
              const collapsed = label.replace(/(.)\1+/g, "$1");
              if (collapsed.length >= 5 && collapsed !== label && NS.hostLabelIsBrandTypo(label, collapsed)) shape = "typo";
              if (shape === "none" && pureLatinHost) {
                for (let i = 1; i < label.length - 1; i++) {
                  const stripped = label.slice(0, i) + label.slice(i + 1);
                  if (stripped.length >= 5 && /^[a-z]+$/i.test(stripped) && NS.hostLabelIsBrandTypo(label, stripped)) {
                    shape = "typo";
                    break;
                  }
                }
              }
            } catch { /* ignore */ }
            return {
              mismatch: true,
              brandToken: cnDisplay,
              brandHits: 14,
              hostMatch: shape,
              hostLabel: label,
              pageApex,
              rigorousMatch: false,
              displayBrand: resolveDisplay(cnDisplay)
            };
          }
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
      const headTokens = (titleTokens.length ? titleTokens : ogTokens).filter((t) => t && !NS.BRAND_TOKEN_STOP_RE.test(t));
      if (!headTokens.length) {
        // 纯中文标题 + 自家 apex 产品子域：shurufa.sogou.com +「搜狗输入法」→ exact，非仿冒
        try {
          if (cnDisplay && typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex(host)) {
            const apexBrand = (pageApex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
            const idBlob = `${claimText} ${identityText} ${footerText} ${pageApex}`.toLowerCase();
            // 页内出现 apex 品牌拉丁 / apex 本身，或中文品牌已能代表公司产品线
            if (apexBrand.length >= 3 && (idBlob.includes(apexBrand) || idBlob.includes(pageApex) || /[一-鿿]{2,}/.test(cnDisplay))) {
              return {
                mismatch: false,
                brandToken: apexBrand,
                brandHits: 16,
                hostMatch: "exact",
                hostLabel: label,
                pageApex,
                rigorousMatch: true,
                displayBrand: cnDisplay
              };
            }
          }
        } catch { /* ignore */ }
        // 纯中文标题：不要落到「无 token」静默，也不要用正文 CMS 拉丁冒充品牌
        if (cnDisplay && officialPitchEarly) {
          const marketingHost = /[-_]/.test(labelRaw)
            || /^(?:ca|pc|m|aa|bb|cc|get|im|download|soft|safe|vip|pro)[-_]/i.test(labelRaw);
          const core = usableLatin(inferredHostCore) ? inferredHostCore : (usableLatin(hostAlignedLatin) ? hostAlignedLatin : "");
          // 产品子域（shurufa）不是营销夹带
          if (typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex(host)) {
            return { mismatch: false, brandToken: (pageApex.split(".")[0] || label), brandHits: 12, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true, displayBrand: cnDisplay };
          }
          if (marketingHost || (core && (NS.hostLabelIsPaddedBrand(label, core) || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, core))))) {
            return {
              mismatch: true,
              brandToken: core || cnDisplay,
              brandHits: 12,
              hostMatch: core ? "padded" : "none",
              hostLabel: label,
              pageApex,
              rigorousMatch: false,
              displayBrand: resolveDisplay(core || cnDisplay)
            };
          }
        }
        return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "none", hostLabel: label, pageApex, rigorousMatch: false, displayBrand: cnDisplay || "" };
      }

      // 正文去图标字体，避免 material-symbols 的 chat/home/mail 刷频当作品牌
      const body = typeof NS.collectBrandScoringBodyText === "function"
        ? NS.collectBrandScoringBodyText(8000)
        : ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").slice(0, 8000).toLowerCase();
      const titleLow = claimLow;
      const docTitleLow = (document.title || "").toLowerCase();
      const full = `${titleLow} ${body}`;

      const uniqueForCompound = [...new Set(headTokens)];
      const compoundSeed = [...uniqueForCompound];
      (claimText.match(/[A-Za-z][a-zA-Z]{2,}/g) || []).forEach((b) => {
        const low = b.toLowerCase();
        // 产品复合域名：Arch Linux → archlinux；及 installer/desktop 等尾缀
        if (low.length >= 3 && low.length <= 20 && /^(uninstaller|installer|manager|cleaner|helper|desktop|player|browser|editor|linux|windows|macos|android)$/i.test(low)) compoundSeed.push(low);
      });
      const compoundHost = NS.hostLabelComposedOfTitleTokens(label, compoundSeed);
      if (compoundHost && squatShape !== "hyphen" && squatShape !== "padded" && squatShape !== "typo") {
        const displayTok = uniqueForCompound.filter((t) => t.length >= 3 && !stop.test(t) && label.includes(t)).sort((a, b) => a.length - b.length)[0] || label;
        return { mismatch: false, brandToken: displayTok, brandHits: 12, hostMatch: "exact", hostLabel: label, pageApex, rigorousMatch: true };
      }

      // 标题段首主品牌（DingTalk）作为默认，再按主机对齐微调
      const primaryTitleBrand = typeof NS.pickPrimaryTitleBrandToken === "function"
        ? NS.pickPrimaryTitleBrandToken(document.title || claimText, labelRaw)
        : "";
      let brandToken = NS.pickBrandTokenForHost(headTokens, labelRaw) || primaryTitleBrand || "";
      let brandHits = 0;
      const uniqueTokens = [...new Set(headTokens)];
      for (const t of uniqueTokens) {
        if (uniqueTokens.some((o) => o !== t && o.length > t.length && o.includes(t))) continue;
        if (stop.test(t) && label !== t) continue;
        // 必须出现在标题区（title+h1..h6），禁止仅正文/图标 ligature 当选
        let nTitle = 0; let nDocTitle = 0; let nFull = 0;
        try {
          const re = new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
          nTitle = (titleLow.match(re) || []).length;
          nDocTitle = (docTitleLow.match(re) || []).length;
          nFull = (full.match(re) || []).length;
        } catch {
          nTitle = titleLow.split(t).length - 1;
          nDocTitle = docTitleLow.split(t).length - 1;
          nFull = full.split(t).length - 1;
        }
        if (nTitle < 1 && titleTokens.length > 0) continue;
        if (t.length < 4 && !(label === t || label.startsWith(t) || label.includes(t))) continue;
        // 正文频次权重压低，避免 Chat 刷屏压过 DingTalk
        let score = nTitle * 12 + nDocTitle * 20 + Math.min(nFull, 6);
        if (label === t) score += 100;
        else if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
          && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, t) || NS.hostLabelIsBrandProductCategoryDomain(label, t))) score += 98;
        else if (NS.hostLabelIsBrandTypo(label, t)) score += 90;
        else if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, t)) score += 75;
        else if (NS.hostLabelIsPaddedBrand(label, t) || NS.hostLabelIsPaddedBrand(labelRaw, t)) score += 70;
        else if (label.startsWith(t) && t.length >= 3) score += 40;
        else if (label.includes(t) && t.length >= 5) score += 15;
        else if (label.includes(t) && t.length === 4) score += 5;
        if (/^(uninstaller|installer|manager|cleaner|remover|helper|desktop|software|application)$/i.test(t)) score -= 50;
        // 标题最前的产品名加权（"DingTalk - …"）
        const lead = docTitleLow.trim().slice(0, 48);
        if (lead.startsWith(t) || new RegExp(`^[^a-z]*${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i").test(docTitleLow)) score += 55;
        if (primaryTitleBrand && t === primaryTitleBrand) score += 40;
        if (t.length <= 4) score -= 30;
        score += Math.min(t.length, 14);
        if (score > brandHits || (score === brandHits && t.length > (brandToken || "").length)) { brandHits = score; brandToken = t; }
      }
      // 若主机对齐选了短泛词，但标题主品牌更长且无 stop，回退到标题主品牌
      if (primaryTitleBrand && brandToken && brandToken !== primaryTitleBrand
        && primaryTitleBrand.length >= brandToken.length
        && !stop.test(primaryTitleBrand)
        && brandToken.length <= 4
        && !NS.hostLabelIsBrandTypo(label, brandToken)
        && !(NS.hostLabelIsPaddedBrand(label, brandToken) || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, brandToken)))) {
        brandToken = primaryTitleBrand;
        brandHits = Math.max(brandHits, 20);
      }
      if (brandToken && NS.BRAND_TOKEN_STOP_RE.test(brandToken)) {
        brandToken = NS.pickBrandTokenForHost(headTokens.filter((t) => !NS.BRAND_TOKEN_STOP_RE.test(t)), labelRaw) || headTokens.find((t) => !NS.BRAND_TOKEN_STOP_RE.test(t)) || "";
        brandHits = brandToken ? Math.max(brandHits, 8) : 0;
      }
      if (brandToken && !usableLatin(brandToken)) {
        brandToken = "";
        brandHits = 0;
      }
      if (!brandToken) {
        // 无拉丁标题 token 时：仍尝试中文展示名 + 主机推断核心
        if (cnDisplay && officialPitchEarly && inferredHostCore && usableLatin(inferredHostCore)
          && (NS.hostLabelIsPaddedBrand(label, inferredHostCore) || (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, inferredHostCore)))) {
          return {
            mismatch: true,
            brandToken: inferredHostCore,
            brandHits: 11,
            hostMatch: "padded",
            hostLabel: label,
            pageApex,
            rigorousMatch: false,
            displayBrand: resolveDisplay(inferredHostCore)
          };
        }
        return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "none", hostLabel: label, pageApex, rigorousMatch: false, displayBrand: cnDisplay || "" };
      }

      // 产品子域：shurufa.sogou.com + 标题品牌 搜狗/sogou → 自家产品线，exact
      try {
        if (typeof NS.hostIsProductSubdomainOfBrandApex === "function" && NS.hostIsProductSubdomainOfBrandApex(host)) {
          const apexBrand = (pageApex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          const idLow = `${claimText} ${identityText} ${footerText} ${pageApex}`.toLowerCase();
          if (apexBrand.length >= 3 && (
            brandToken === apexBrand
            || idLow.includes(apexBrand)
            || idLow.includes(pageApex)
            || (cnDisplay && /[一-鿿]{2,}/.test(cnDisplay))
          )) {
            return {
              mismatch: false,
              brandToken: brandToken || apexBrand,
              brandHits: Math.max(brandHits, 14),
              hostMatch: "exact",
              hostLabel: label,
              pageApex,
              rigorousMatch: true,
              displayBrand: resolveDisplay(cnDisplay || brandToken || apexBrand)
            };
          }
        }
      } catch { /* ignore */ }

      const hyphenMirror = NS.hostLabelIsHyphenatedBrandMirror(labelRaw, brandToken);
      const prefixedHyphen = typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, brandToken);
      const paddedBrand = NS.hostLabelIsPaddedBrand(label, brandToken) || NS.hostLabelIsPaddedBrand(labelRaw, brandToken);
      // pyas-security.com + PYAS：品牌产品线域名 → exact，非 partial 仿冒
      const productCategoryDomain = typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
        && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, brandToken)
          || NS.hostLabelIsBrandProductCategoryDomain(label, brandToken));
      // 夹带/前缀仿冒不得标为 rigorous exact（否则 im-todesk 会被当成官网）
      // 子域/apex：*.sogou.com 对品牌 sogou 算 exact
      const apexBrandLabel = (pageApex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const underBrandApex = apexBrandLabel.length >= 3 && (brandToken === apexBrandLabel || pageApex === `${brandToken}.com` || pageApex === `${brandToken}.cn` || pageApex === `${brandToken}.com.cn` || pageApex === `${brandToken}.net` || pageApex === `${brandToken}.org` || host.endsWith(`.${brandToken}.com`) || host.endsWith(`.${brandToken}.cn`) || host.endsWith(`.${brandToken}.com.cn`) || host.endsWith(`.${pageApex}`) && brandToken === apexBrandLabel);
      const rigorousMatch = !hyphenMirror && !prefixedHyphen && !paddedBrand && (
        label === brandToken
        || productCategoryDomain
        || underBrandApex
        || NS.hostLabelComposedOfTitleTokens(label, uniqueTokens.concat(compoundSeed))
        || pageApex === `${brandToken}.com` || pageApex === `${brandToken}.cn` || pageApex === `${brandToken}.com.cn` || pageApex === `${brandToken}.net` || pageApex === `${brandToken}.org`
        || host === `${brandToken}.com` || host === `${brandToken}.cn`
        || host.endsWith(`.${brandToken}.com`) || host.endsWith(`.${brandToken}.cn`) || host.endsWith(`.${brandToken}.com.cn`)
        || (/^\d{3,4}/.test(label) && brandToken === label.replace(/[^0-9].*$/, "") && label.startsWith(brandToken))
        || (label.startsWith(brandToken) && brandToken.length >= 3 && label.length > brandToken.length && NS.hostLabelComposedOfTitleTokens(label, uniqueTokens.concat(compoundSeed)))
      );
      let hostMatch = "none";
      if (hyphenMirror) hostMatch = "hyphen";
      else if (rigorousMatch || productCategoryDomain) hostMatch = "exact";
      else if (NS.hostLabelIsBrandTypo(label, brandToken)) hostMatch = "typo";
      else if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, brandToken)) hostMatch = "padded";
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
      if (!thirdPartyProxy && !productCategoryDomain && hostMatch !== "exact" && !rigorousMatch) {
        if (officialPitch && hostMatch === "typo" && brandHits >= 2) mismatch = true;
        if (officialPitch && hostMatch === "padded" && brandHits >= 3) mismatch = true;
        if (officialPitch && hostMatch === "hyphen" && brandHits >= 2) mismatch = true;
        // 前缀-品牌（im-todesk）在 pick 时 brandHits 可能偏低，官方话术 + padded 即 mismatch
        if (officialPitch && hostMatch === "padded" && brandHits >= 2 && (prefixedHyphen || paddedBrand)) mismatch = true;
        if (officialPitch && hostMatch === "none" && brandHits >= 8) mismatch = true;
        if (officialPitch && hostMatch === "partial" && !rigorousMatch && brandHits >= 12) mismatch = true;
        if (officialPitch && canonMismatch && !rigorousMatch && brandHits >= 8) mismatch = true;
        if (!mismatch && hostMatch === "padded" && brandHits >= 8 && /下载|客户端|安装|免费|AI|模型|软件|远程/i.test(titleLow + body.slice(0, 800))) mismatch = true;
        if (!mismatch && hostMatch === "hyphen" && brandHits >= 4 && /下载|客户端|安装|免费|软件|工具|测试|远程/i.test(titleLow + body.slice(0, 800))) mismatch = true;
        // 中文产品页 + 主机夹带：即便 brandHits 偏低也 mismatch
        if (!mismatch && officialPitchEarly && cnDisplay && hostMatch === "padded" && brandHits >= 2) mismatch = true;
      }
      return {
        mismatch,
        brandToken,
        brandHits,
        hostMatch,
        hostLabel: label,
        pageApex,
        rigorousMatch,
        displayBrand: resolveDisplay(brandToken)
      };
    } catch {
      return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "none", hostLabel: "", pageApex: "", rigorousMatch: false, displayBrand: "" };
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
      const productPitch = softOfficial
        || /安全软件|杀毒软件|免费下载|立即下载|立即免费下载|个人版|安静|纯净|强悍|终端安全|客户端下载/i.test(brandSource)
        || /[一-鿿]{2,}安全|[一-鿿]{2,}杀毒/.test(brandSource);
      const cnProductBrand = /([一-鿿]{2,8})(?=官网|官方|下载|客户端|软件|杀毒|安全)/.test(brandSource) && productPitch;
      const cnTitleBrand = /[一-鿿]{2,4}/.test((document.title || "")) && productPitch
        && !/^(安全|软件|下载|官方|电脑|系统|工具)/.test(((document.title || "").match(/[一-鿿]{2,4}/) || [])[0] || "");
      const latinMarketingHost = /^[a-z0-9-]{5,}$/i.test(labelRaw) && /[-_]/.test(labelRaw);
      // 纯拉丁主机 + 仅中文产品宣称（dingdtalk + 钉钉，页上无 dingtalk 字样）
      const pureLatinHost = /^[a-z][a-z0-9]{4,22}$/i.test(label) && !/[-_]/.test(labelRaw);
      const hostAbsentFromClaim = label.length >= 5 && !String(brandSource || "").toLowerCase().includes(label);
      let inferredPad = false;
      try {
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const core = NS.inferMarketingPaddedBrandCore(labelRaw);
          if (core && (NS.hostLabelIsPaddedBrand(label, core) || NS.hostLabelIsPaddedBrand(labelRaw.replace(/-/g, ""), core))) inferredPad = true;
        }
      } catch { /* ignore */ }

      if (seoTemplate && softOfficial) return true;
      if (softOfficial && brandTypoHost) return true;
      if (softOfficial && brandHyphenMirror) return true;
      if ((softOfficial || schemaBrandSpam || productPitch) && brandPaddedHost) return true;
      if ((softOfficial || productPitch) && (cnProductBrand || cnTitleBrand) && pureLatinHost && hostAbsentFromClaim) return true;
      if (productPitch && inferredPad && (cnProductBrand || cnTitleBrand || softOfficial)) return true;
      if (softOfficial && marketingForm && (brandInHostPartial || brandPaddedHost || brandHyphenMirror || (cnProductBrand && latinMarketingHost))) return true;
      if (productPitch && marketingForm && latinMarketingHost && (cnProductBrand || cnTitleBrand)) return true;
      if (softOfficial && brandInHostPartial) return true;
      if (softOfficial && brandExactLabelOnWrongApex) return true;
      if (schemaBrandSpam && (brandPaddedHost || brandHyphenMirror) && tokens.size >= 1) return true;
      if (softOfficial && NS.looksLikeRandomDownloadHost(location.hostname)) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 是否「可当作被盗用的官方品牌资源域」的 apex。
   * 排除：纯数字 CDN（30405.com）、泛静态/图床主机、门户自有资源域。
   * 真阳性：仿冒页大量拉 todesk.com / 360.cn 等产品官方域资源。
   */
  NS.isPlausibleBrandResourceApex = function (apex, titleTokensOpt) {
    try {
      const a = String(apex || "").toLowerCase().replace(/^www\./, "");
      if (!a || a.length < 4) return false;
      const root = (typeof NS.brandRootKeyFromHost === "function" ? NS.brandRootKeyFromHost(a) : "")
        || (a.split(".")[0] || "").toLowerCase();
      // 纯数字/过短数字根：30405.com 等门户 CDN，不是软件品牌域
      if (!root || /^\d{3,}$/.test(root) || root.length < 3) return false;
      // 泛 CDN / 图床 / 统计 / 字体（绝不当「盗用品牌资源」目标）
      if (/^(cdn|static|assets|img|image|images|media|res|resource|resources|file|files|upload|uploads|oss|cos|s3|bucket|jsdelivr|unpkg|bootcdn|cloudflare|fastly|akamai|baidu|bdstatic|qhimg|qhimgs|gtimg|qq|alicdn|aliyuncs|myqcloud|hwcdn|ksyun|volccdn|bytedance|byteimg)$/i.test(root)) return false;
      if (/\.(?:cdn|static|img|assets|media)\./i.test(a)) return false;
      // 资源根须能对上标题/正文里的拉丁品牌 token（todesk、dingtalk…）
      // 无拉丁品牌时，纯数字 CDN 已在上面剔除；剩余需 root 非泛词
      const tokens = Array.isArray(titleTokensOpt) ? titleTokensOpt : [];
      if (tokens.length) {
        const rootOk = tokens.some((t) => {
          const tl = String(t || "").toLowerCase();
          if (tl.length < 4) return false;
          return root === tl || root.includes(tl) || tl.includes(root);
        });
        if (!rootOk) return false;
      }
      return true;
    } catch { return false; }
  };

  /** 资源主机是否像门户自有 CDN（soft-static.X / soft-img.X），而非盗用某品牌官网 */
  NS.looksLikePortalOwnedCdnHost = function (hostname, pageHostOpt) {
    try {
      const h = String(hostname || "").toLowerCase();
      const page = String(pageHostOpt || location.hostname || "").toLowerCase().replace(/^www\./, "");
      const pageLabel = (page.split(".")[0] || "").toLowerCase();
      // soft-static / soft-img / soft-cdn / download-static 等
      if (/^(?:soft|down|download|file|files|res|resource|static|cdn|img|image|media|assets|frontend|pc|app)[-_.]/i.test(h)) return true;
      if (/[-_.](?:static|cdn|img|image|assets|media|res|frontend|oss|cos)(?:[-_.]|$)/i.test(h)) return true;
      // 主机前缀与页面子域标签相同：soft.china.com → soft-static.30405.com
      if (pageLabel.length >= 3 && pageLabel.length <= 12
        && /^(soft|game|app|down|download|file|news|blog|bbs|forum|video|music|book)$/i.test(pageLabel)
        && (h.startsWith(`${pageLabel}-`) || h.startsWith(`${pageLabel}.`) || h.includes(`.${pageLabel}-`) || h.includes(`${pageLabel}static`) || h.includes(`${pageLabel}img`) || h.includes(`${pageLabel}cdn`))) {
        return true;
      }
      return false;
    } catch { return false; }
  };

  NS.collectBrandResourceMismatch = function (titleOpt) {
    const title = titleOpt || document.title || "";
    const pageApex = NS.guessApexDomain(location.hostname) || NS.getRegistrableDomain(location.hostname);
    // 仅用标题/身份字段中的拉丁品牌 token；禁止把 soft/china 等主机泛标签当品牌
    const GENERIC_HOST_LABEL_RE = /^(www|soft|game|app|apps|down|download|file|files|news|blog|bbs|forum|video|music|book|shop|store|mall|cdn|static|img|image|media|assets|api|m|mobile|wap|pc|web|home|page|site|help|support|docs|wiki|about|user|member|login|reg|search|list|detail|show|view|item|softs|games)$/i;
    let titleTokens = [];
    try {
      if (typeof NS.extractLatinBrandTokens === "function") {
        titleTokens = NS.extractLatinBrandTokens(title).slice();
      } else {
        titleTokens = (title.match(/[A-Za-z]{4,}/g) || []).map((t) => t.toLowerCase());
      }
    } catch { titleTokens = []; }
    titleTokens = titleTokens.filter((t) => {
      const low = String(t || "").toLowerCase();
      if (low.length < 4 || low.length > 24) return false;
      if (GENERIC_HOST_LABEL_RE.test(low)) return false;
      if (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(low)) return false;
      if (/^(download|windows|linux|android|macos|official|client|software|remote|chrome|https|http|free|desk|home|page|site|china|zhonghua|baidu|sogou|qihoo)$/i.test(low)) return false;
      return true;
    });
    // 勿把 soft.china.com 的 soft 塞进品牌 token（会误命中 soft-static.30405.com）
    // 仅当主机标签本身像产品品牌（todesk / huorong）时才加入
    try {
      const hostLabel = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      if (hostLabel.length >= 5 && /[a-z]{5,}/i.test(hostLabel)
        && !GENERIC_HOST_LABEL_RE.test(hostLabel)
        && !(NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(hostLabel))
        && !/^\d+$/.test(hostLabel)) {
        titleTokens.push(hostLabel.replace(/-/g, ""));
      }
    } catch { /* ignore */ }
    titleTokens = [...new Set(titleTokens)];

    let brandAssetHits = 0;
    const brandApexes = new Map();
    const sampleSel = "img[src], link[href], script[src], a[href], source[src], video[src], audio[src]";
    try {
      // 无可用拉丁品牌 token → 无法认定「盗用某品牌官方资源」（中文站 + 数字 CDN 常见于门户）
      if (!titleTokens.length) {
        return { pageApex, brandAssetHits: 0, brandApexes, topBrandApex: "", topCount: 0, titleTokens };
      }
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
          // 门户自有 CDN（soft-static.30405.com）≠ 盗用品牌官网资源
          if (NS.looksLikePortalOwnedCdnHost(u.hostname, location.hostname)) continue;
          if (!NS.isPlausibleBrandResourceApex(apex, titleTokens)) continue;
          const hostFlat = u.hostname.replace(/[^a-z0-9]/gi, "");
          const apexRoot = (typeof NS.brandRootKeyFromHost === "function" ? NS.brandRootKeyFromHost(apex) : "")
            || (apex.split(".")[0] || "").toLowerCase();
          // 命中须落在 apex 品牌根（todesk.com），而非 soft-static 里的 soft
          const hit = titleTokens.some((t) => {
            const tl = String(t || "").toLowerCase();
            if (tl.length < 4) return false;
            if (apexRoot === tl || apexRoot.includes(tl) || tl.includes(apexRoot)) return true;
            // 子域含品牌：cdn.todesk.com / static.xxx-todesk.com
            return hostFlat.includes(tl) && (apexRoot.includes(tl.slice(0, Math.min(tl.length, 6))) || tl.includes(apexRoot.slice(0, Math.min(apexRoot.length, 6))));
          });
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
