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
   * 主身份关键词（用户规则）：
   * 1) 独立证据族：headline、description、site identity、brand mark、footer、domain。
   *    title/H1/OG/Twitter 标题模板副本只算一个 headline 证据族；
   *    description/OG/Twitter description 同理，避免功能标签复制后刷票。
   * 2) 选中的词必须再过一遍上述证据族：相关性不足则弃用（防 Cover/口号抢词）
   * 3) 域名对齐强度参与总榜排序（app-4399 抬 4399，压 Flash 噪声）
   * 4) 域名关联门控另见 evaluateDomainKeywordRelevance：半真半假=盗版；几乎关联=放行
   */
  NS.collectPrimaryBrandKeywords = function () {
    const out = {
      blob: "", latin: [], structuralLatin: [], cn: [], tokens: [],
      display: "", hyphenSplitClaim: false, scores: {}, fieldHits: {}
    };
    const c = NS.caches || {};
    const now = Date.now();
    const urlKey = String(location.href || "");
    // 缓存 / 重入：在 try 外返回，避免 finally 误清外层 collecting 锁
    if (c._primaryKw && c._primaryKwUrl === urlKey && now - (c._primaryKwAt || 0) < 2500) {
      return c._primaryKw;
    }
    if (c._primaryKwCollecting) {
      return c._primaryKw || out;
    }
    c._primaryKwCollecting = true;
    try {
      const fields = typeof NS.collectProductBrandIdentityFields === "function"
        ? NS.collectProductBrandIdentityFields()
        : {};
      // 先采集所有身份字段；复核阶段会按证据族合并模板镜像。
      const tiers = [
        { key: "title", text: String(fields.title || document.title || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "h1", text: String(fields.h1 || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "h2", text: String(fields.h2 || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "keywords", text: String(fields.keywords || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "description", text: String(fields.description || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "ogTitle", text: String(fields.ogTitle || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "ogDescription", text: String(fields.ogDescription || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "ogImageAlt", text: String(fields.ogImageAlt || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "ogSite", text: String(fields.ogSite || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "twitterTitle", text: String(fields.twitterTitle || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "twitterDescription", text: String(fields.twitterDescription || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "twitterImageAlt", text: String(fields.twitterImageAlt || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        // JSON-LD Organization/WebSite name（汽水音乐官网）
        { key: "schema", text: String(fields.schemaName || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        // Logo 是专用品牌位；普通 span/nav 文案只能佐证，不能冒充身份锚。
        { key: "logo", text: String(fields.logo || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "span", text: String(fields.span || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() },
        { key: "footer", text: String(fields.footer || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim() }
      ];
      out.blob = tiers.map((t) => t.text).filter(Boolean).join(" ").replace(/\s+/g, " ").trim();

      // 强字段拼成 blob，用于判断 Instagram 是否真是主产品宣称
      const strongTitleBlob = [
        fields.title, fields.h1, fields.ogTitle, fields.ogSite, fields.twitterTitle, fields.schemaName, document.title
      ].filter(Boolean).join(" ");

      const isWeak = (x) => typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(x);
      // 社交平台名默认垃圾；仅 title/og 主宣称时放行
      const isGarbage = (x) => {
        if (typeof NS.isSocialPlatformNoiseToken === "function" && NS.isSocialPlatformNoiseToken(x)) {
          if (typeof NS.socialPlatformIsPrimaryProductClaim === "function"
            && NS.socialPlatformIsPrimaryProductClaim(x, strongTitleBlob)) {
            return false;
          }
          return true;
        }
        // 域名衍生碎片（Todeskr / Huorongpc）不得进主身份关键词榜
        try {
          if (typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(x)) return true;
          const flat = String(x || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          const host = (typeof location !== "undefined" ? String(location.hostname || "") : "")
            .toLowerCase().replace(/^www\./, "");
          const labelRaw = (host.split(".")[0] || "").toLowerCase();
          const segs = labelRaw.split(/[-_]/).map((p) => p.replace(/[^a-z0-9]/g, "")).filter((p) => p.length >= 4);
          const padCore = typeof NS.inferMarketingPaddedBrandCore === "function"
            ? String(NS.inferMarketingPaddedBrandCore(labelRaw) || "").toLowerCase()
            : "";
          // 仅过滤「等于污染主机段」的词（todeskr），保留页内 ToDesk/todesk
          if (flat && segs.includes(flat) && padCore && flat !== padCore
            && typeof NS.hostLabelIsPaddedBrand === "function"
            && NS.hostLabelIsPaddedBrand(flat, padCore)) {
            return true;
          }
        } catch { /* ignore */ }
        return typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(x);
      };
      const digitRe = NS.CN_DIGIT_PRODUCT_RE || /^\d{2,6}[一-鿿]{2,6}$/;
      // 平台/通用拉丁（Music/App 等不当品牌；Flash 等运行时可作产品名，见 isRuntimePlatformNoiseToken）
      // 平台、版本与功能中心语不是品牌。只过滤完整 token，不会拆伤
      // PowerToys / CloudDrive / AnyDesk 这类复合专名。
      const platLat = /^(?:windows|linux|macos|mac|android|ios|x64|x86|download|official|client|software|music|app|apps|free|online|store|player|audio|video|stream|streaming|social|media|html|canvas|batch|rename|remote|desktop|control|connect|connection|utility|utilities|tool|tools|feature|features|version|center|drive)$/i;

      const normalizeCn = (brand) => {
        let s = String(brand || "").trim();
        if (!s) return "";
        if (typeof NS.normalizeChineseBrandToken === "function") s = NS.normalizeChineseBrandToken(s) || s;
        if (typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          s = NS.canonicalizeBrandDisplayCandidate(s);
        }
        if (!s) return "";
        if (typeof NS.isPlausibleChineseBrandLength === "function" && !NS.isPlausibleChineseBrandLength(s)) return "";
        if (isWeak(s)) return "";
        return s;
      };

      // 候选是否「真实出现在」字段文本中（防抽词漂移）
      const fieldContains = (fieldText, cand) => {
        const f = String(fieldText || "");
        const c0 = String(cand || "");
        if (!f || !c0 || c0.length < 2) return false;
        // 拉丁品牌必须完整命中 token 边界。CloudtoDesk 不能反向证明页面
        // 独立声明过 ToDesk；ToDesk远程桌面仍能正常命中。
        if (/^[a-z0-9]+$/i.test(c0)) {
          const esc = c0.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          return new RegExp(`(?:^|[^A-Za-z0-9])${esc}(?=$|[^A-Za-z0-9])`, "i").test(f);
        }
        // 拉丁+中文候选必须从完整拉丁边界开始。禁止某字段产生 esk博客 后，
        // 再以无边界 includes 命中其它字段里的 tod​esk博客并虚增票数。
        if (/^[A-Za-z][A-Za-z0-9]*[一-鿿]+$/.test(c0)) {
          const esc = c0.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          return new RegExp(`(?:^|[^A-Za-z0-9])${esc}`, "i").test(f);
        }
        if (f.includes(c0)) return true;
        // 归一后再比（关于火绒→火绒）
        try {
          const n = typeof NS.normalizeChineseBrandToken === "function" ? NS.normalizeChineseBrandToken(c0) : c0;
          if (n && n !== c0 && f.includes(n)) return true;
        } catch { /* ignore */ }
        return false;
      };

      const cnScore = new Map(); // brand -> {score, sources:Set}
      const latinScore = new Map();
      // 连字符域名对应的页面多词身份（cloud-drive ↔ “Cloud Drive”）。
      // key 使用扁平域名核，value 只记录强身份字段中真实出现的完整短语。
      const compoundEvidence = new Map();
      const compoundDisplayByKey = new Map();
      const structuralCompoundKeys = new Set();
      const structuralComponentKeys = new Set();
      let distinctiveHyphenDisplay = "";

      const bumpCn = (brand, src, fieldText) => {
        let s = normalizeCn(brand);
        // 未知缩写 + 中文尾串：只有缩写与当前域名确有结构关联时才折叠为品牌核。
        // 这是证据规则，不需要知道缩写属于哪家厂商；QQ音乐等无 3+ 字母域名核的
        // 完整产品名仍按混合品牌保留。
        const mixedAcronym = String(s || "").match(/^([A-Z][A-Z0-9]{2,5})[一-鿿]{1,8}$/u);
        if (mixedAcronym && mixedAcronym[1]
          && typeof NS.candidateDomainAligned === "function"
          && NS.candidateDomainAligned(mixedAcronym[1]) >= 1) {
          bumpLat(mixedAcronym[1], src, fieldText);
          return;
        }
        // ToDesk官网 → ToDesk（混合拉丁+官网尾巴）
        if (s && typeof NS.normalizeDisplayBrandName === "function") {
          const n = NS.normalizeDisplayBrandName(s);
          if (!n) return;
          s = n;
        } else if (s && typeof NS.trimChineseBrandTrail === "function") {
          s = NS.trimChineseBrandTrail(s) || s;
        }
        if (!s) return;
        // 归一后变纯拉丁：走拉丁票，避免 cn 展示「ToDesk官网」
        if (/^[A-Za-z][A-Za-z0-9]*$/.test(s)) {
          bumpLat(s, src, fieldText);
          return;
        }
        // 必须真的出现在该字段，否则不算票（允许字段写 ToDesk官网 而候选是 ToDesk）
        if (!fieldContains(fieldText, s) && !fieldContains(fieldText, brand)
          && !String(fieldText || "").includes(s)
          && !String(fieldText || "").toLowerCase().includes(String(s).toLowerCase())) return;
        const prev = cnScore.get(s) || { score: 0, sources: new Set() };
        if (prev.sources.has(src)) return;
        prev.sources.add(src);
        prev.score = prev.sources.size;
        cnScore.set(s, prev);
      };

      const bumpLat = (tok, src, fieldText) => {
        const low = String(tok || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!low || low.length < 3 || platLat.test(low)) return;
        if (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(low)) return;
        // 页脚/分享里的 Instagram：title 未主宣称则直接不进榜（汽水音乐站）
        if (typeof NS.isSocialPlatformNoiseToken === "function" && NS.isSocialPlatformNoiseToken(low)
          && !(typeof NS.socialPlatformIsPrimaryProductClaim === "function"
            && NS.socialPlatformIsPrimaryProductClaim(low, strongTitleBlob))) {
          return;
        }
        if (isGarbage(low)) return;
        // domain 虚拟字段：主机核本身即出现；其它字段须真实包含
        if (src !== "domain" && !fieldContains(fieldText, low) && !fieldContains(fieldText, tok)) return;
        const prev = latinScore.get(low) || { score: 0, sources: new Set() };
        if (prev.sources.has(src)) return;
        prev.sources.add(src);
        prev.score = prev.sources.size;
        latinScore.set(low, prev);
      };

      // 纯数字门户品牌 4399 / 360 / 2345（title/og 站名；域名 app-4399 也可加 domain 票）
      const bumpDigitBrand = (raw, src, fieldText) => {
        const d = String(raw || "").replace(/[^\d]/g, "");
        if (!/^\d{3,6}$/.test(d)) return;
        if (/^(?:19|20)\d{2}$/.test(d)) return; // 年份
        if (typeof NS.isRepeatedNumericBrandToken === "function"
          && NS.isRepeatedNumericBrandToken(d)) return;
        const ft = String(fieldText || "");
        if (src !== "domain" && !ft.includes(d)) return;
        // 须像站名/产品名，而非纯版本号上下文（Android 6.0 不匹配整段 4399）
        // 强字段 / domain / 「4399APP / - 4399 / content=4399」形态
        const strong = /^(?:title|h1|ogTitle|ogSite|twitterTitle|schema|keywords|description|domain)$/.test(src);
        if (src !== "domain" && !strong && !new RegExp(`(?:^|[^\\d])${d}(?:APP|app|官网|官方|客户端|小游戏|下载|[^\\d]|$)`).test(ft)) return;
        const prev = cnScore.get(d) || { score: 0, sources: new Set() };
        if (prev.sources.has(src)) return;
        prev.sources.add(src);
        prev.score = prev.sources.size;
        cnScore.set(d, prev);
      };

      // 每字段抽候选 → 等权计票
      for (const tier of tiers) {
        const text = String(tier.text || "").trim();
        if (!text) continue;
        // 整字段抽 4399 类数字站名（title「… - 4399」、og:site_name「4399」）
        try {
          const digitHits = text.match(/(?:^|[^\d])(\d{3,6})(?=[^\d]|$)/g) || [];
          digitHits.forEach((m) => {
            const d = (m.match(/\d{3,6}/) || [])[0];
            if (d) bumpDigitBrand(d, tier.key, text);
          });
          // application-name / 整段等于数字
          if (/^\d{3,6}$/.test(text.trim())) bumpDigitBrand(text.trim(), tier.key, text);
        } catch { /* ignore */ }
        const parts = text.split(/[,，、|｜·•]+/);
        parts.forEach((part) => {
          const p = part.trim();
          if (!p || p.length > 80) return;
          if (typeof NS.pickChineseBrandFromPageSurface === "function") {
            bumpCn(NS.pickChineseBrandFromPageSurface(p), tier.key, text);
          }
          if (typeof NS.extractChineseProductBrandCandidates === "function") {
            NS.extractChineseProductBrandCandidates(p).forEach((x) => bumpCn(x, tier.key, text));
          }
          const dig = (p.match(/(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
          if (dig) bumpCn(dig, tier.key, text);
          // 火绒安全 / 360安全卫士：品类在专名内，整段入选；勿剥成「安全」或只留「火绒」
          const fullProd = p.match(/^([一-鿿]{2,8}(?:安全|杀毒|卫士|安全卫士)?)(?:官网|官方|下载|软件|客户端|应用|市场|平台)?$/);
          if (fullProd) {
            let fp = fullProd[1];
            // 「火绒安全软件」→ 火绒安全（软件是渠道词）
            fp = fp.replace(/(?:软件|客户端)$/u, "");
            if (fp.length >= 2) bumpCn(fp, tier.key, text);
          }
          const m = p.match(/^([一-鿿]{2,8})(?:官网|官方|下载|客户端)?$/);
          if (m && !/^(?:安全|杀毒|卫士)$/.test(m[1])) bumpCn(m[1], tier.key, text);
          const dm = p.match(/^(\d{2,6}[一-鿿]{2,6})(?:官网|官方|下载|软件|客户端)?$/);
          if (dm) bumpCn(dm[1], tier.key, text);
          // 混合：ToDesk官网 → 只取 ToDesk（勿把 官网 吃进品牌）
          const mxLat = p.match(/([A-Za-z][A-Za-z0-9]{1,20})(?:官网|官方|下载)/);
          if (mxLat) {
            const pure = typeof NS.normalizeDisplayBrandName === "function"
              ? NS.normalizeDisplayBrandName(mxLat[1])
              : mxLat[1];
            if (pure) bumpLat(pure, tier.key, text);
          }
          // QQ音乐官网：拉丁+中文产品，后缀 官网 必须在捕获组外
          const mx = p.match(/([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})(?:官网|官方|下载)/);
          if (mx) {
            const cleaned = typeof NS.normalizeDisplayBrandName === "function"
              ? NS.normalizeDisplayBrandName(mx[1])
              : (typeof NS.trimChineseBrandTrail === "function" ? NS.trimChineseBrandTrail(mx[1]) : mx[1]);
            if (cleaned) bumpCn(cleaned, tier.key, text);
          }
        });
        if (typeof NS.pickChineseBrandFromPageSurface === "function") {
          bumpCn(NS.pickChineseBrandFromPageSurface(text), tier.key, text);
        }
        if (typeof NS.extractLatinBrandTokens === "function") {
          NS.extractLatinBrandTokens(text).forEach((t) => bumpLat(t, tier.key, text));
        }
      }

      // ── 强身份多词短语 ↔ 完整连字符域名 ──
      // 单个 Drive / Desktop / Remote 仍是功能词；只有域名全部段按顺序组成一个
      // 完整名称，并同时出现在 headline 与 site identity 两个独立证据族时，
      // 才把扁平复合名作为候选。这样 Cloud Drive 正站不会被拆成 Cloud，
      // 而 cloud-todesk 页面独立声明 ToDesk 时仍按前缀夹带处理。
      try {
        const hostNow = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
        const apexNow = typeof NS.getRegistrableDomain === "function"
          ? (NS.getRegistrableDomain(hostNow) || hostNow)
          : hostNow;
        const rawLabel = String(apexNow.split(".")[0] || "").toLowerCase();
        const parts = rawLabel.split("-")
          .map((part) => part.replace(/[^a-z0-9]/g, ""))
          .filter((part) => part.length >= 2);
        const flatCompound = parts.join("");
        if (parts.length >= 2 && parts.length <= 4
          && flatCompound.length >= 5 && flatCompound.length <= 32) {
          const escaped = parts.map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
          const phraseRe = new RegExp(
            `(?:^|[^A-Za-z0-9])(${escaped.join("[\\s_\\-–—·./]*")})(?=$|[^A-Za-z0-9])`,
            "i"
          );
          const hasIndependentStrongOccurrence = (token) => {
            const esc = String(token || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            if (!esc) return false;
            const tokenRe = new RegExp(`(?:^|[^A-Za-z0-9])${esc}(?=$|[^A-Za-z0-9])`, "i");
            const phraseGlobal = new RegExp(phraseRe.source, "ig");
            return tiers.some((tier) => {
              if (!/^(?:title|h1|ogTitle|twitterTitle|ogSite|schema)$/.test(tier.key)) return false;
              const withoutFullPhrase = String(tier.text || "").replace(phraseGlobal, " ");
              return tokenRe.test(withoutFullPhrase);
            });
          };
          const matches = [];
          for (const tier of tiers) {
            const m = String(tier.text || "").match(phraseRe);
            if (m && m[1]) matches.push({ key: tier.key, display: m[1].replace(/\s+/g, " ").trim() });
          }
          const family = (key) => {
            if (/^(?:title|h1|ogTitle|twitterTitle)$/.test(key)) return "headline";
            if (/^(?:description|ogDescription|twitterDescription)$/.test(key)) return "description";
            if (/^(?:ogSite|schema)$/.test(key)) return "siteIdentity";
            if (/^(?:logo|ogImageAlt|twitterImageAlt)$/.test(key)) return "brandMark";
            if (key === "footer") return "footer";
            if (key === "keywords") return "keywords";
            return key;
          };
          const strongFamilies = new Set(matches
            .filter((m) => /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema)$/.test(m.key))
            .map((m) => family(m.key)));
          const hasHeadlineAndSiteIdentity = (info) => {
            const families = new Set(Array.from((info && info.sources) || [])
              .filter((src) => /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema)$/.test(String(src)))
              .map((src) => family(String(src))));
            return families.has("headline") && families.has("siteIdentity");
          };
          const hasIndependentIdentityEvidence = (info) => {
            const sources = Array.from((info && info.sources) || [])
              .filter((src) => /^(?:title|h1|ogTitle|twitterTitle|description|ogDescription|twitterDescription|ogSite|schema|logo|footer|keywords)$/.test(String(src)));
            const families = new Set(sources.map((src) => family(String(src))));
            return families.size >= 2
              && (families.has("headline") || families.has("siteIdentity"));
          };
          const existingJoinedIdentity = hasHeadlineAndSiteIdentity(latinScore.get(flatCompound));
          const partSet = new Set(parts);
          const sameFlatIndependentIdentity = hasIndependentIdentityEvidence(latinScore.get(flatCompound));
          const otherPrimaryIdentity = sameFlatIndependentIdentity
            || [...latinScore.entries()].some(([name, info]) =>
            name !== flatCompound && !partSet.has(name) && hasIndependentIdentityEvidence(info)
          ) || [...cnScore.entries()].some(([, info]) => hasIndependentIdentityEvidence(info));
          if (otherPrimaryIdentity
            && strongFamilies.has("headline") && strongFamilies.has("siteIdentity")) {
            // 域名短语只是页面上的影子副标题时，其组成词也不能再参与品牌 UI
            // 或 identity-aligned 自证（ToDesk + Team Viewer 不能被 team+viewer 洗白）。
            parts.forEach((part) => structuralComponentKeys.add(part));
          }
          // 语言角色分类，不是品牌表：仅“通用修饰语 + 功能中心语”可作为
          // 中性的结构一致短语。Team Viewer / Power Toys / To Desk 等并不满足。
          const genericModifierPart = /^(?:best|my|online|cloud|remote|batch|download|free|official|file|files|pdf|video|audio|music|screen|system|web|pc|mobile|smart|quick|easy|fast|secure|security|photo|image|data|disk|office)$/i;
          const genericCapabilityPart = /^(?:tools?|apps?|editors?|storage|desktop|rename|centers?|managers?|players?|recorders?|converters?|downloaders?|cleaners?|updaters?|utilit(?:y|ies)|clients?|software|drives?|assistants?|controls?|backup|sync|compressors?|archivers?)$/i;
          const genericSeparatedPhrase = parts.every((part) =>
            genericModifierPart.test(part) || genericCapabilityPart.test(part)
          ) && parts.some((part) => genericCapabilityPart.test(part));
          if (genericSeparatedPhrase
            && strongFamilies.has("headline") && strongFamilies.has("siteIdentity")) {
            parts.forEach((part) => structuralComponentKeys.add(part));
          }

          // 基础设施/营销前缀 + 页面已独立声明的后段品牌仍是夹带域。
          // 例：cloud-todesk + 标题 ToDesk，不能被“Cloud ToDesk”结构自洗。
          let trailingIndependentBrand = false;
          for (let i = 1; i < parts.length && !trailingIndependentBrand; i++) {
            const prefixParts = parts.slice(0, i);
            const trailing = parts.slice(i).join("");
            const prefixMarketing = prefixParts.every((part) =>
              (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(part))
              || (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(part))
            );
            const info = latinScore.get(trailing);
            const strongTrailing = info && hasIndependentStrongOccurrence(trailing);
            if (prefixMarketing && trailing.length >= 4 && !platLat.test(trailing) && strongTrailing) {
              trailingIndependentBrand = true;
            }
          }

          if (!trailingIndependentBrand && !otherPrimaryIdentity
            && strongFamilies.has("headline") && strongFamilies.has("siteIdentity")) {
            const preferred = matches.find((m) => /^(?:ogSite|schema)$/.test(m.key))
              || matches.find((m) => /^(?:title|h1|ogTitle|twitterTitle)$/.test(m.key))
              || matches[0];
            if (existingJoinedIdentity || genericSeparatedPhrase) {
              const evidence = new Set(matches.map((m) => m.key));
              compoundEvidence.set(flatCompound, evidence);
              // 通用分隔短语只证明结构一致，不进入 UI 品牌池；页面独立声明
              // joined/CamelCase 专名时才按正常品牌候选处理。
              if (!existingJoinedIdentity) {
                structuralCompoundKeys.add(flatCompound);
                parts.forEach((part) => structuralComponentKeys.add(part));
              }
              // 页面已独立声明 joined/CamelCase 专名时保留它的真实大小写；
              // 不要再被 ogSite 里的可读分词形式 To Desk 覆盖成新“品牌”。
              if (!existingJoinedIdentity && preferred && preferred.display) {
                compoundDisplayByKey.set(flatCompound, preferred.display);
              }
              const prev = latinScore.get(flatCompound) || { score: 0, sources: new Set() };
              evidence.forEach((src) => prev.sources.add(src));
              prev.score = prev.sources.size;
              latinScore.set(flatCompound, prev);
            } else if (preferred && preferred.display) {
              // 非通用拆词保留作展示声明，但绝不能参加 exact 关系判定。
              distinctiveHyphenDisplay = preferred.display;
              out.hyphenSplitClaim = true;
            }
          }
        }
      } catch { /* ignore */ }

      // ── 域名虚拟字段（与 title/h1 等权 1 票）──
      // 只用 voteLatin（品牌核/数字），禁止 iehuorong/huorongpc 整段主机进榜
      // app-4399 → 4399；huorong.cn → huorong + 页内「火绒」；ie-huorong → huorong 核
      const hostCores = typeof NS.collectHostBrandCores === "function"
        ? NS.collectHostBrandCores()
        : { latin: [], voteLatin: [], digits: [], labelRaw: "", flat: "", padCore: "" };
      const voteLats = (hostCores.voteLatin && hostCores.voteLatin.length)
        ? hostCores.voteLatin
        : (hostCores.latin || []);
      const domainFieldText = [
        hostCores.padCore, hostCores.apexLabel, hostCores.root,
        voteLats.join(" "), (hostCores.digits || []).join(" ")
      ].filter(Boolean).join(" ");
      try {
        (hostCores.digits || []).forEach((d) => bumpDigitBrand(d, "domain", domainFieldText));
        voteLats.forEach((lat) => {
          // 夹带整段主机碎片不进拉丁榜
          if (typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(lat)) return;
          bumpLat(lat, "domain", domainFieldText);
        });
        // ★ 选举热路径禁止 pinyin-pro（全站卡死根因）。
        // 中文 +domain 票仅用结构：标题含该中文且主机有 padCore。
        try {
          const title0 = String(document.title || "");
          const pad0 = String(hostCores.padCore || "").toLowerCase();
          if (pad0.length >= 4 && title0) {
            let n = 0;
            for (const [cnBrand] of cnScore.entries()) {
              if (n++ > 20) break;
              if (!/[一-鿿]/.test(cnBrand) || cnBrand.length > 8) continue;
              if (!title0.includes(cnBrand)) continue;
              const prev = cnScore.get(cnBrand) || { score: 0, sources: new Set() };
              if (!prev.sources.has("domain")) {
                prev.sources.add("domain");
                prev.score = prev.sources.size;
                cnScore.set(cnBrand, prev);
              }
            }
          }
        } catch { /* ignore */ }
        // 纯数字已在 cnScore：给已有 4399 补 domain 源
        for (const [cnBrand, info] of cnScore.entries()) {
          if (!/^\d{3,6}$/.test(cnBrand)) continue;
          if (typeof NS.candidateDomainAligned === "function" && NS.candidateDomainAligned(cnBrand) >= 2) {
            if (!info.sources.has("domain")) {
              info.sources.add("domain");
              info.score = info.sources.size;
              cnScore.set(cnBrand, info);
            }
          }
        }
      } catch { /* ignore */ }

      // 再过一遍等权字段（含 domain）：丢弃跨字段相关性不足的候选
      const fieldTexts = Object.fromEntries(tiers.map((t) => [t.key, t.text]));
      fieldTexts.domain = domainFieldText;
      const recountInAllFields = (cand, isCn) => {
        void isCn;
        const hitByFamily = new Map();
        const addHit = (key) => {
          const family = evidenceFamilyOf(key);
          if (!hitByFamily.has(family)) hitByFamily.set(family, key);
        };
        for (const tier of tiers) {
          if (!tier.text) continue;
          if (fieldContains(tier.text, cand)
            || (compoundEvidence.has(String(cand).toLowerCase())
              && compoundEvidence.get(String(cand).toLowerCase()).has(tier.key))) {
            addHit(tier.key);
          }
        }
        // 域名虚拟字段：对齐则算 1 票
        try {
          if (typeof NS.candidateDomainAligned === "function" && NS.candidateDomainAligned(cand) >= 1) {
            addHit("domain");
          } else if (fieldContains(domainFieldText, cand)) {
            addHit("domain");
          }
        } catch { /* ignore */ }
        return Array.from(hitByFamily.values());
      };

      // 主身份强字段：title / 标题 / 社交卡 / schema / domain（keywords 别名不应压过这些）
      const STRONG_FIELD = /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema|domain)$/;
      // 拉丁品牌至少要在页面的主身份文本中独立出现。logo alt 可能同时携带副标
      // （例如「火绒安全 PURE SHIELD」），只能佐证，不能单独把副标抬成品牌。
      const PAGE_IDENTITY_FIELD = /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema)$/;
      const IDENTITY_ANCHOR_FIELD = /^(?:ogSite|schema|logo|domain)$/;

      // 浏览器模板常把同一串内容复制进 title / H1 / OG / Twitter。
      // 这些是同一证据族，不能重复投票；描述和图片 alt 同理。
      const evidenceFamilyOf = (key) => {
        if (/^(?:title|h1|ogTitle|twitterTitle)$/.test(key)) return "headline";
        if (/^(?:description|ogDescription|twitterDescription)$/.test(key)) return "description";
        if (/^(?:ogImageAlt|twitterImageAlt)$/.test(key)) return "imageAlt";
        if (/^(?:ogSite|schema)$/.test(key)) return "siteIdentity";
        return key;
      };

      const acceptCandidate = (cand, votes, sources, isCn) => {
        if (!cand || votes < 1) return false;
        if (isCn && isWeak(cand)) return false;
        if (!isCn && isGarbage(cand)) return false;
        // Flash 等运行时：须域名强对齐或 title 主宣称，否则不当主品牌候选
        if (!isCn && typeof NS.isRuntimePlatformNoiseToken === "function" && NS.isRuntimePlatformNoiseToken(cand)) {
          const primary = typeof NS.runtimePlatformIsPrimaryProductClaim === "function"
            && NS.runtimePlatformIsPrimaryProductClaim(cand, strongTitleBlob);
          const domN = typeof NS.candidateDomainAligned === "function" ? NS.candidateDomainAligned(cand) : 0;
          if (!primary && domN < 2) return false;
        }
        // 必须在等权字段里再扫一遍
        const reHits = recountInAllFields(cand, isCn);
        if (reHits.length < votes) {
          // 以实扫为准
          votes = reHits.length;
        }
        if (votes >= 2) {
          if (isCn) {
            const identityAnchored = reHits.some((k) => IDENTITY_ANCHOR_FIELD.test(k));
            const domainAligned = typeof NS.candidateDomainAligned === "function"
              ? NS.candidateDomainAligned(cand)
              : 0;
            // 纯 title/H1/OG 镜像只有一个 headline 证据族。普通 nav/span/footer
            // 只能佐证；没有专用身份槽或域名桥时，至少需要三个独立证据族。
            if (!identityAnchored && domainAligned < 1 && votes < 3) return false;
          }
          // 拉丁仅出现在 span/logo/footer/keywords/description 等辅助字段，
          // 从未进 title/h1/OG/schema/domain：不能靠辅助字段凑票取得品牌资格。
          // PURE SHIELD 同时出现在副标与页脚，也只能佐证，不能推翻中文主身份。
          if (!isCn && !reHits.some((k) => PAGE_IDENTITY_FIELD.test(k))) return false;
          return true;
        }
        // 单字段：强字段或 domain 对齐
        if (votes === 1 && STRONG_FIELD.test(reHits[0] || "")) {
          if (reHits[0] === "domain") {
            // 域名虚拟字段只负责给“页面已声明的候选”做对齐，不能独立创造
            // 拉丁品牌身份。否则 todiesk 会用一票 domain exact 覆盖页面五票 ToDesk。
            if (typeof NS.isHostShapedCompoundBrandToken === "function"
              && NS.isHostShapedCompoundBrandToken(cand)) return false;
            if (/^\d{3,6}$/.test(cand)) return true;
            return false;
          }
          const ft = fieldTexts[reHits[0]] || "";
          if (digitRe.test(cand)) return true;
          // 混合词不能再无条件当品牌：PC版、AI智能推荐、Res无损音质
          // 都属于版本/功能标题。统一服从产品形态和域名身份校验。
          if (/[A-Za-z]/.test(cand) && /[一-鿿]/.test(cand)
            && typeof NS.looksLikeChineseProductBrandMorphology === "function"
            && NS.looksLikeChineseProductBrandMorphology(cand)) return true;
          if (new RegExp(cand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?:官网|官方|下载|安全|杀毒|软件|客户端|音乐)", "i").test(ft)) return true;
          if (typeof NS.looksLikeChineseProductBrandMorphology === "function"
            && NS.looksLikeChineseProductBrandMorphology(cand) && cand.length >= 3) return true;
        }
        return false; // 相关性不够 → 不选
      };

      const strongHitCount = (entry) => {
        const src = entry && entry.sources ? entry.sources : [];
        return new Set(src.filter((k) => PAGE_IDENTITY_FIELD.test(k)).map(evidenceFamilyOf)).size;
      };

      // 按票数排序，取第一个通过「再过一遍」校验的
      let cnRanked = [...cnScore.entries()]
        .map(([c, info]) => {
          const reHits = recountInAllFields(c, true);
          return { c, votes: reHits.length, sources: reHits };
        })
        .filter((x) => x.votes > 0 && !isWeak(x.c))
        .sort((a, b) => {
          if (b.votes !== a.votes) return b.votes - a.votes;
          const am = /[A-Za-z]/.test(a.c) && /[一-鿿]/.test(a.c);
          const bm = /[A-Za-z]/.test(b.c) && /[一-鿿]/.test(b.c);
          if (am !== bm) return am ? -1 : 1;
          if (digitRe.test(a.c) !== digitRe.test(b.c)) return digitRe.test(a.c) ? -1 : 1;
          return b.c.length - a.c.length;
        });

      // 短残片若被更长产品名包含（安全 ⊂ 火绒安全），且长名票数接近，丢掉短的
      cnRanked = cnRanked.filter((x) => {
        if (x.c.length >= 4 && !/^(?:音乐|安全|杀毒)$/.test(x.c)) return true;
        const longer = cnRanked.find((y) => y.c !== x.c && y.c.includes(x.c) && y.c.length > x.c.length
          && y.votes >= Math.max(1, x.votes - 2));
        return !longer;
      });

      const latRanked = [...latinScore.entries()]
        .map(([t, info]) => {
          const reHits = recountInAllFields(t, false);
          return { c: t, votes: reHits.length, sources: reHits };
        })
        .filter((x) => x.votes > 0 && !isGarbage(x.c) && !platLat.test(x.c))
        .sort((a, b) => {
          // 强字段命中优先，再比票数（避免 keywords 里 Resso 票虚高）
          const as = a.sources.filter((k) => PAGE_IDENTITY_FIELD.test(k)).length;
          const bs = b.sources.filter((k) => PAGE_IDENTITY_FIELD.test(k)).length;
          if (bs !== as) return bs - as;
          return b.votes - a.votes || b.c.length - a.c.length;
        });

      out.cn = cnRanked.filter((x) => acceptCandidate(x.c, x.votes, x.sources, true)).map((x) => x.c);
      const acceptedLatin = latRanked
        .filter((x) => acceptCandidate(x.c, x.votes, x.sources, false))
        .map((x) => x.c);
      // 纯功能短语只用于证明“页面名称与域名结构一致”，不进入 UI 品牌池。
      out.structuralLatin = acceptedLatin.filter((x) => structuralCompoundKeys.has(x));
      out.latin = acceptedLatin.filter((x) =>
        !structuralCompoundKeys.has(x) && !structuralComponentKeys.has(x));

      const fmtDisp = (raw) => {
        if (!raw) return "";
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(raw)) return "";
        let displayInput = String(raw);
        const compoundKey = displayInput.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (compoundKey && compoundDisplayByKey.has(compoundKey)) {
          displayInput = compoundDisplayByKey.get(compoundKey);
        }
        // 计票键统一小写，但展示应恢复页面真实大小写（PowerToys / DeepSeek），
        // 不为每个品牌维护驼峰词表。
        if (/^[a-z0-9]+$/i.test(displayInput)) {
          const esc = displayInput.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const caseFields = [
            fields.schemaName, fields.ogSite, fields.title, fields.h1,
            fields.ogTitle, fields.twitterTitle, fields.span, fields.logo
          ];
          for (const field of caseFields) {
            const m = String(field || "").match(new RegExp(`(?:^|[^A-Za-z0-9])(${esc})(?=$|[^A-Za-z0-9])`, "i"));
            if (m && m[1]) {
              displayInput = m[1];
              if (/[A-Z]/.test(displayInput)) break;
            }
          }
        }
        if (typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          return NS.canonicalizeBrandDisplayCandidate(displayInput);
        }
        if (/^[a-z0-9]+$/i.test(displayInput) && typeof NS.formatBrandTokenForDisplay === "function") {
          return NS.formatBrandTokenForDisplay(displayInput);
        }
        return displayInput.replace(/(?:官网|官方)$/u, "").trim();
      };

      // ── 一张总榜：中文+拉丁合并，按「出现在多少个等权字段」决胜 ──
      // 旧逻辑是 cn 榜冠军 vs lat 榜冠军：汽水音乐若抽词失败进不了 cn 榜，
      // Resso 只要在 lat 榜当选就会单独成为 display——看起来像「多标签压不过别名」。
      // 正确：汽水音乐命中 title+desc+og+kw = 4～6 票，Resso 只在 keywords = 1 票 → 汽水赢。
      const domainAlignOf = (cand) => {
        try {
          return typeof NS.candidateDomainAligned === "function" ? NS.candidateDomainAligned(cand) : 0;
        } catch { return 0; }
      };
      const isHostDebris = (cand) => {
        try {
          return typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(cand);
        } catch { return false; }
      };
      // 运行时噪声：Flash 可作产品名；仅当「非标题主宣称且非域名对齐」时排序垫底
      const isRuntimeNoise = (cand) => {
        try {
          if (typeof NS.isRuntimePlatformNoiseToken !== "function" || !NS.isRuntimePlatformNoiseToken(cand)) return false;
          if (typeof NS.runtimePlatformIsPrimaryProductClaim === "function"
            && NS.runtimePlatformIsPrimaryProductClaim(cand, strongTitleBlob)) return false;
          if (domainAlignOf(cand) >= 2) return false;
          return true;
        } catch { return false; }
      };

      // ★ 选举内禁止 pinyin；domainAlign 对中文用轻量结构（title 含中文 + padCore）
      const withMeta = (x, script) => ({
        ...x,
        script,
        domainAlign: domainAlignOf(x.c),
        hostPy: 0
      });
      const allRanked = []
        .concat(
          cnRanked
            .filter((x) => acceptCandidate(x.c, x.votes, x.sources, true))
            .map((x) => withMeta(x, "cn")),
          latRanked
            .filter((x) => acceptCandidate(x.c, x.votes, x.sources, false)
              && !structuralCompoundKeys.has(x.c)
              && !structuralComponentKeys.has(x.c)
              && !isHostDebris(x.c))
            .map((x) => withMeta(x, "lat"))
        )
        .sort((a, b) => {
          const aDeb = isHostDebris(a.c) ? 1 : 0;
          const bDeb = isHostDebris(b.c) ? 1 : 0;
          if (aDeb !== bDeb) return aDeb - bDeb;
          const aNoise = isRuntimeNoise(a.c) && a.domainAlign < 2 ? 1 : 0;
          const bNoise = isRuntimeNoise(b.c) && b.domainAlign < 2 ? 1 : 0;
          if (aNoise !== bNoise) return aNoise - bNoise;
          const as = strongHitCount(a);
          const bs = strongHitCount(b);
          if (bs !== as) return bs - as;
          if ((b.domainAlign || 0) !== (a.domainAlign || 0)) {
            return (b.domainAlign || 0) - (a.domainAlign || 0);
          }
          if (b.votes !== a.votes) return b.votes - a.votes;
          // 中文优先于拉丁（夹带站展示钉钉/火绒，不依赖 pinyin）
          const aCn = /[一-鿿]/.test(a.c) ? 1 : 0;
          const bCn = /[一-鿿]/.test(b.c) ? 1 : 0;
          if (bCn !== aCn) return bCn - aCn;
          if (a.c.includes(b.c) && a.c.length > b.c.length) return -1;
          if (b.c.includes(a.c) && b.c.length > a.c.length) return 1;
          return b.c.length - a.c.length;
        });

      const bestOverall = allRanked[0] || null;
      const bestCnEntry = allRanked.find((x) => x.script === "cn") || null;
      const bestLatEntry = allRanked.find((x) => x.script === "lat") || null;
      const cnV = bestCnEntry ? bestCnEntry.votes : 0;
      const latV = bestLatEntry ? bestLatEntry.votes : 0;

      // display = 总榜第一（再归一）；主机夹带碎片不可作 display
      out.display = bestOverall && !isHostDebris(bestOverall.c)
        ? fmtDisp(bestOverall.c)
        : "";
      if (!out.display) {
        const nextSafe = allRanked.find((x) => !isHostDebris(x.c) && !!fmtDisp(x.c));
        out.display = nextSafe ? fmtDisp(nextSafe.c) : "";
      }
      if (!out.display && bestCnEntry) {
        out.display = /^\d{3,6}$/.test(bestCnEntry.c) ? bestCnEntry.c : fmtDisp(bestCnEntry.c);
      }
      if (!out.display && bestLatEntry && !isHostDebris(bestLatEntry.c)) {
        out.display = fmtDisp(bestLatEntry.c);
      }
      // ★ 页内身份拉丁（title/h1/og 的 ToDesk）必须压过「仅域名/主机段」拉丁（todeskr→Todeskr）
      // 用户案例：页面写 ToDesk，toast 却显示域名碎片 Todeskr——选举有过滤，但定稿被域名核抢位。
      try {
        const labelRaw0 = String(hostCores.labelRaw || "").toLowerCase();
        const hostSegs0 = labelRaw0.split(/[-_]/)
          .map((p) => p.replace(/[^a-z0-9]/g, ""))
          .filter((p) => p.length >= 4);
        const pad0 = String(hostCores.padCore || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        const dispFlat0 = String(out.display || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        const displayIsHostSegNoise = !!(dispFlat0 && (
          isHostDebris(out.display)
          || (hostSegs0.includes(dispFlat0) && pad0 && dispFlat0 !== pad0)
          || (dispFlat0 === labelRaw0.replace(/[^a-z0-9]/g, "") && pad0 && dispFlat0 !== pad0)
        ));
        const pageLatWinner = allRanked.find((entry) => {
          if (!entry || entry.script !== "lat" || isHostDebris(entry.c)) return false;
          const flat = String(entry.c || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          if (!flat || flat.length < 4) return false;
          // 必须在页面身份槽出现，不能只靠 domain 票
          if (!(entry.sources || []).some((src) => PAGE_IDENTITY_FIELD.test(String(src)))) return false;
          // 排除仍等于污染主机段的词
          if (hostSegs0.includes(flat) && pad0 && flat !== pad0) return false;
          return true;
        });
        if (pageLatWinner && (displayIsHostSegNoise || !out.display
          || ((bestOverall && bestOverall.script === "lat"
            && (bestOverall.sources || []).every((s) => s === "domain"))))) {
          const pageDisp = fmtDisp(pageLatWinner.c);
          if (pageDisp) out.display = pageDisp;
        }
      } catch { /* ignore */ }
      // 纯数字品牌展示保持原样（4399 不要被 format 成别的）
      if (bestOverall && /^\d{3,6}$/.test(bestOverall.c)) out.display = bestOverall.c;
      // ★ 页内强字段中文/混合产品（QQ音乐）永远压过「仅域名核」拉丁（Yinle@qqyinle）
      if (bestCnEntry && strongHitCount(bestCnEntry) > 0
        && (/[一-鿿]/.test(bestCnEntry.c) || /^\d{3,6}/.test(bestCnEntry.c))) {
        const latIsHostOnly = bestOverall && bestOverall.script === "lat"
          && (isHostDebris(bestOverall.c)
            || strongHitCount(bestOverall) === 0
            || (strongHitCount(bestOverall) <= 1 && (bestOverall.sources || []).every((s) => s === "domain")));
        const cnIdentityAnchored = (bestCnEntry.sources || []).some((k) => IDENTITY_ANCHOR_FIELD.test(k));
        const cnClearlyOutranks = bestOverall && bestOverall.script === "lat"
          && cnIdentityAnchored && bestCnEntry.votes > bestOverall.votes;
        if (!bestOverall || bestOverall.script === "cn" || latIsHostOnly || cnClearlyOutranks) {
          const cnDisp = /^\d{3,6}$/.test(bestCnEntry.c) ? bestCnEntry.c : fmtDisp(bestCnEntry.c);
          if (cnDisp) out.display = cnDisp;
        }
      }
      // 若总榜第一是「仅弱字段」的拉丁别名，而中文/数字有强字段 → 改用中文或数字站名
      if (out.display && bestOverall && bestOverall.script === "lat"
        && strongHitCount(bestOverall) === 0 && bestCnEntry && strongHitCount(bestCnEntry) > 0) {
        const cnDisp = /^\d{3,6}$/.test(bestCnEntry.c) ? bestCnEntry.c : fmtDisp(bestCnEntry.c);
        if (cnDisp && (/[一-鿿]/.test(cnDisp) || /^\d{3,6}$/.test(cnDisp))) out.display = cnDisp;
      }
      // 域名强对齐的数字/中文优先于运行时噪声拉丁（双保险）
      if (bestOverall && bestOverall.script === "lat" && isRuntimeNoise(bestOverall.c)
        && bestCnEntry && (bestCnEntry.domainAlign || 0) >= 1) {
        const cnDisp = /^\d{3,6}$/.test(bestCnEntry.c) ? bestCnEntry.c : fmtDisp(bestCnEntry.c);
        if (cnDisp) out.display = cnDisp;
      }
      // 中文优先于拉丁（结构）：有中文候选且总榜是拉丁主机核 → 用中文（选举内不调 pinyin）
      if (bestCnEntry && /[一-鿿]/.test(bestCnEntry.c) && bestOverall && bestOverall.script === "lat") {
        const cnHost = (bestCnEntry.domainAlign || 0) >= 1
          || strongHitCount(bestCnEntry) > 0;
        if (cnHost
          && (isHostDebris(bestOverall.c)
            || (bestOverall.domainAlign || 0) <= (bestCnEntry.domainAlign || 0)
            || /^[A-Za-z][A-Za-z0-9.\-]{2,24}$/.test(String(bestOverall.c || "")))) {
          const cnDisp = fmtDisp(bestCnEntry.c);
          if (cnDisp) out.display = cnDisp;
        }
      }
      if (out.display && /^[A-Za-z][A-Za-z0-9.\-]{2,28}$/.test(String(out.display).trim())
        && bestCnEntry && /[一-鿿]/.test(bestCnEntry.c)
        && ((bestCnEntry.domainAlign || 0) >= 1 || strongHitCount(bestCnEntry) > 0)) {
        const cnDisp = fmtDisp(bestCnEntry.c);
        if (cnDisp) out.display = cnDisp;
      }
      // 页面完整声明了某个连字符段品牌时，基础设施/营销前缀不能与其拼成
      // 新品牌：cloud-todesk + Logo/标题 ToDesk 应展示 ToDesk；仅有
      // CloudDrive 而没有独立 Drive 候选时不会进入此分支。
      try {
        const rawParts = String(hostCores.labelRaw || "").toLowerCase().split("-")
          .map((x) => x.replace(/[^a-z0-9]/g, ""))
          .filter(Boolean);
        const hostLabelFlat = rawParts.join("");
        const displayFlat = String(out.display || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (rawParts.length >= 2 && displayFlat && displayFlat === hostLabelFlat) {
          const coreEntries = allRanked.filter((entry) => {
            if (!entry || entry.script !== "lat") return false;
            const core = String(entry.c || "").toLowerCase().replace(/[^a-z0-9]/g, "");
            const idx = rawParts.indexOf(core);
            if (idx < 0) return false;
            if (!(entry.sources || []).some((src) => PAGE_IDENTITY_FIELD.test(String(src)))) return false;
            const pre = rawParts.slice(0, idx);
            const post = rawParts.slice(idx + 1);
            const prefixOk = pre.length > 0 && pre.every((part) =>
              (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(part))
              || (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(part))
            );
            const suffixOk = post.every((part) =>
              (NS.MKT_HOST_SUFFIX && NS.MKT_HOST_SUFFIX.test(part))
              || (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(part))
            );
            return prefixOk && suffixOk;
          }).sort((a, b) => strongHitCount(b) - strongHitCount(a) || b.votes - a.votes);
          if (coreEntries[0]) {
            const coreDisplay = fmtDisp(coreEntries[0].c);
            if (coreDisplay) out.display = coreDisplay;
          }
        }
      } catch { /* ignore */ }
      // 非通用拆词只作为页面声明的可读名称，不赋予 exact 关系。
      // Team Viewer / To Desk 因而能显示完整声明，同时仍由下面域名关系判为 hyphen/padded。
      if (distinctiveHyphenDisplay) {
        const claimDisplay = fmtDisp(distinctiveHyphenDisplay);
        if (claimDisplay) out.display = claimDisplay;
      }
      // 最终再挡一次主机碎片（Yinle / Iehuorong）
      if (out.display && isHostDebris(out.display)) {
        out.display = bestCnEntry
          ? (/^\d{3,6}$/.test(bestCnEntry.c) ? bestCnEntry.c : fmtDisp(bestCnEntry.c))
          : "";
      }
      // ★ 定稿末段：夹带/拼写主机 + 页内已有中文 → 禁止 display 钉死 Huorong/Dingding
      // 放在连字符拉丁回写之后，确保中文最终胜出（不依赖 pinyin 是否已注入）
      try {
        const latShow = String(out.display || "").trim();
        const latLow = latShow.toLowerCase().replace(/[^a-z0-9]/g, "");
        const isPureLatShow = /^[A-Za-z][A-Za-z0-9.\-]{2,28}$/.test(latShow);
        if (isPureLatShow && bestCnEntry && /[一-鿿]{2,}/.test(bestCnEntry.c)) {
          const pad = String(hostCores.padCore || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          const labF = String(hostCores.flat || hostCores.labelRaw || "")
            .toLowerCase().replace(/[^a-z0-9]/g, "");
          const apexF = String(hostCores.apexLabel || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          const hostPaddedShape = !!(hostCores.padded
            || (pad && labF && labF !== pad && labF.includes(pad))
            || (pad && apexF && apexF !== pad && apexF.includes(pad))
            || (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
              && (NS.apexLabelLooksLikeMarketingPaddedBrand(hostCores.labelRaw)
                || NS.apexLabelLooksLikeMarketingPaddedBrand(hostCores.apexLabel)))
            || /-/.test(String(hostCores.labelRaw || "")));
          const latIsHostCore = !!(latLow && (
            (pad && (latLow === pad || pad.startsWith(latLow) || latLow.startsWith(pad)))
            || (labF && (latLow === labF || labF.startsWith(latLow)
              || (latLow.length >= 4 && labF.includes(latLow))))
            || (apexF && (latLow === apexF || apexF.includes(latLow)))
            || (bestOverall && bestOverall.script === "lat" && (bestOverall.domainAlign || 0) >= 1)
          ));
          if (hostPaddedShape && latIsHostCore) {
            const cnDisp = fmtDisp(bestCnEntry.c);
            if (cnDisp && /[一-鿿]/.test(cnDisp)) out.display = cnDisp;
          }
        }
      } catch { /* ignore */ }

      // 最终再过一遍字段：display 若不在任何字段出现则清空；并强制剥 官网
      if (out.display) {
        out.display = fmtDisp(out.display);
        const finalHits = recountInAllFields(out.display, /[一-鿿]/.test(out.display));
        // 剥尾后的 ToDesk 仍算命中原字段里的 ToDesk官网
        const softHit = finalHits.length >= 1
          || tiers.some((tier) => {
            const ft = String(tier.text || "").toLowerCase();
            const d = String(out.display || "").toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]/gi, "");
            return d && (ft.includes(d) || ft.replace(/[^a-z0-9]/g, "").includes(d.replace(/[^a-z0-9]/g, "")));
          });
        if (!softHit) {
          const fallback = out.cn.find((x) => !!fmtDisp(x) && fmtDisp(x) !== out.display)
            || out.latin.find((x) => !!fmtDisp(x) && x !== String(out.display).toLowerCase());
          out.display = fallback ? fmtDisp(fallback) : "";
        }
        if (out.display) out.display = fmtDisp(out.display);
      }

      const seen = new Set();
      const pushTok = (t) => {
        const s = String(t || "").trim();
        if (!s || s.length < 2) return;
        const key = s.toLowerCase();
        if (seen.has(key)) return;
        seen.add(key);
        out.tokens.push(s);
      };
      out.cn.forEach(pushTok);
      out.latin.forEach(pushTok);

      try {
        cnRanked.forEach((x) => {
          out.scores[x.c] = { score: x.votes, votes: x.votes, sources: x.sources };
          out.fieldHits[x.c] = x.sources;
        });
        latRanked.forEach((x) => {
          out.scores[x.c] = { score: x.votes, votes: x.votes, sources: x.sources };
          out.fieldHits[x.c] = x.sources;
        });
      } catch { /* ignore */ }

      try {
        c._primaryKw = out;
        c._primaryKwUrl = urlKey;
        c._primaryKwAt = now;
      } catch { /* ignore */ }
    } catch { /* ignore */ }
    finally {
      try { c._primaryKwCollecting = false; } catch { /* ignore */ }
    }
    return out;
  };

  /**
   * 域名 ↔ 页面主关键词相关度（仿冒检测主门控，用户规则）：
   * - 几乎关联 related（exact/category）：正站 → 不显示盗版
   * - 半真半假 squat（padded/typo/hyphen/partial）：按盗版处理
   * - 不相关 none：仅当另有官网下载壳时才仿冒（见 tryArm 路径 B）
   * 展示品牌只用 collectPrimaryBrandKeywords 等权多字段结果。
   */
  NS.evaluateDomainKeywordRelevance = function (hostOpt) {
    const empty = {
      related: false, squat: false, mismatch: false, hostMatch: "none", brand: "", brandToken: "",
      keywords: [], score: 0, labelRaw: "", pageApex: ""
    };
    try {
      const host = String(hostOpt || location.hostname || "").toLowerCase().replace(/^www\./, "");
      if (!host) return empty;
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const label = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      const pageApex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
      const apexLabel = (pageApex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const kw = typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords()
        : { blob: "", latin: [], cn: [], tokens: [], display: "" };
      const tokens = [];
      (kw.latin || []).forEach((t) => tokens.push(String(t).toLowerCase()));
      // 完整功能短语可证明连字符域名结构自洽，但不会进入展示品牌。
      (kw.structuralLatin || []).forEach((t) => tokens.push(String(t).toLowerCase()));
      (kw.cn || []).forEach((t) => tokens.push(String(t)));
      // 关系候选只使用已通过页面身份门控的品牌。raw blob 中的域名、
      // 页脚 URL 或产品线短词不能绕过 acceptCandidate 自行参与 exact 判定。
      const cleanTokens = tokens.filter((t) => {
        if (/^(?:ai|gpt|ml|bot|llm)$/i.test(t)) return true;
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return false;
        return true;
      });
      // 域名只能是“被匹配侧”，绝不能把 apex/label/盲剥尾茎重新注入页面
      // cleanTokens 后再与自身判 exact。中文候选与域名的拉丁关系统一交给
      // SW pinyin 返回 candidate/matchedStem/hostForm 结构化证据。
      // 页内中文产品品牌（抽词算法）+ 主机品类拉丁尾 → 结构 squat（不查品牌词库）
      const cnBrandForRoman = (kw.display && /[一-鿿]/.test(kw.display)
        ? kw.display
        : (kw.cn || []).find((x) => /[一-鿿]/.test(String(x))) || "")
        || "";
      // 优先 blob/title 完整产品形态（算法抽词），不查汽水/QQ 等品牌表
      const cnBrandWithBlob = (() => {
        try {
          const blob = String(kw.blob || document.title || "");
          const m = blob.match(/[一-鿿]{2,8}(?:音乐|安全|杀毒|卫士|浏览器|播放器|客户端|输入法|网盘|助手|管家)/);
          if (m && m[0]
            && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(m[0]))) {
            return m[0];
          }
        } catch { /* ignore */ }
        return cnBrandForRoman;
      })();
      const cnCategoryHostSquatEarly = (typeof NS.detectChineseProductCategoryHostSquat === "function"
        || typeof NS.detectChineseMusicBrandDomainSquat === "function")
        ? (() => {
          const fn = NS.detectChineseProductCategoryHostSquat || NS.detectChineseMusicBrandDomainSquat;
          return fn(apexLabel || label, cnBrandWithBlob) || fn(labelRaw, cnBrandWithBlob);
        })()
        : null;

      // 没有通过页面身份门控的候选时，原始 title/footer/blob 不能独自建立
      // 域名关系。品类结构 squat 仍须页内中文产品品牌（cnBrandWithBlob）。
      if (!cleanTokens.length && !cnCategoryHostSquatEarly) {
        return { ...empty, labelRaw, pageApex, keywords: [] };
      }

      let bestMatch = "none";
      let bestTok = "";
      let bestScore = 0;
      const cnRomanizedSuffixTypo = typeof NS.detectChineseProductRomanizedSuffixTypo === "function"
        ? NS.detectChineseProductRomanizedSuffixTypo(cnBrandWithBlob || cnBrandForRoman, apexLabel || label)
        : null;
      const cnCategoryHostSquat = cnCategoryHostSquatEarly;
      const consider = (tok, match, score) => {
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(tok)
          && !/^(?:ai|gpt|ml|bot|llm)$/i.test(tok)) return;
        if (score > bestScore) {
          bestScore = score;
          bestMatch = match;
          bestTok = tok;
        }
      };
      // SW pinyin 的结构化证据是中文页面唯一可进入拉丁关系层的桥。
      // 它来自页面候选→拼音→host 反证，不允许 host 自己制造候选。
      try {
        const pe = NS.state && NS.state._brandPinyinEvidence;
        const peHost = String(pe && pe.host || "").toLowerCase().replace(/^www\./, "");
        if (pe && peHost === host && pe.brand && pe.pinyin) {
          const m = pe.officialExact ? "exact" : String(pe.hostMatch || "none");
          if (/^(?:exact|padded|hyphen|typo)$/.test(m)) {
            consider(String(pe.pinyin), m, 118);
          }
        }
      } catch { /* ignore */ }
      if (cnCategoryHostSquat && cnCategoryHostSquat.brandToken) {
        consider(
          cnCategoryHostSquat.brandToken,
          cnCategoryHostSquat.hostMatch || "typo",
          112
        );
      }

      // 纯功能多词名称不进入品牌 UI，但若它已通过 headline + siteIdentity
      // 双证据，并完整对应连字符域名，应先作为结构 exact 放行。
      const structuralExact = (kw.structuralLatin || [])
        .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
        .find((t) => t && (t === label || t === apexLabel));
      if (structuralExact) consider(structuralExact, "exact", 101);

      // ★ 多标签身份关键词 ↔ 域名高度吻合（todesk+AI=todeskai）→ 正站 exact
      // 营销前缀夹带（ott-todesk / qq-musics / win.qq-musics）强对齐会返回 false，不得标 exact
      try {
        const apexLeftRel = (() => {
          try {
            const ap = typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host;
            return (String(ap || "").split(".")[0] || "").toLowerCase();
          } catch { return labelRaw; }
        })();
        const apexFlatRel = apexLeftRel.replace(/[^a-z0-9]/g, "");
        const mktShape = (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
          && (NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw)
            || NS.hostLabelIsMarketingPrefixedBrandShape(apexLeftRel)))
          || (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftRel))
          || /^(?:qq|wx|weixin)(?:music|musics|yinyue|yinle)$/i.test(apexFlatRel)
          || /^qq[-_](?:music|musics|yinyue|yinle)$/i.test(apexLeftRel);
        // “身份关键词能拼成域名”只能证明相关，不能把删字母或拆连字符的
        // 注册域洗成 exact。品牌候选只取页面身份票，域名自身不能自证。
        let identitySquat = null;
        const authorityShape = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
          && NS.hostNeedsAuthoritativeBrandIdentity(host);
        const pageLatinCands = (kw.latin || [])
          .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
          // 3 字母身份核也有效（由页面多字段共识产生）；近拼仍由
          // latinBrandHostRelation 自己要求至少 5 字符，短核只做明确夹带。
          .filter((t) => t.length >= 3);
        for (let pi = 0; pi < pageLatinCands.length; pi++) {
          const t = pageLatinCands[pi];
          if (/-/.test(apexLeftRel) && apexFlatRel === t) {
            identitySquat = { token: t, match: "hyphen" };
            break;
          }
          if (authorityShape && apexFlatRel !== t && apexFlatRel.includes(t)) {
            identitySquat = { token: t, match: "padded" };
            break;
          }
          const relation = typeof NS.latinBrandHostRelation === "function"
            ? NS.latinBrandHostRelation(t, apexFlatRel) : "none";
          if (relation === "typo") {
            identitySquat = { token: t, match: "typo" };
            break;
          }
        }
        if (identitySquat) {
          consider(identitySquat.token, identitySquat.match, 114);
        } else if (mktShape) {
          // 强制 squat：用 apex 推断核（勿用首标签 win）
          // 排除正站产品子域 music.qq.com（apex=qq 干净，非 qqmusics 粘连）
          const officialSub = typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
            && NS.hostLooksLikeOfficialProductSubdomain(host, kw);
          if (!officialSub) {
            const coreM = (typeof NS.resolveHostBrandCore === "function"
              ? (NS.resolveHostBrandCore(host) || "")
              : "")
              || (typeof NS.inferMarketingPaddedBrandCore === "function"
                ? (NS.inferMarketingPaddedBrandCore(apexLeftRel)
                  || NS.inferMarketingPaddedBrandCore(labelRaw) || "")
                : "");
            if (coreM.length >= 4) consider(coreM, "padded", 88);
            else consider(apexFlatRel || label, "padded", 86);
          }
        } else if (typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
          && NS.hostLooksLikeOfficialProductSubdomain(host, kw)) {
          // music.qq.com / y.qq.com / shurufa.sogou.com + 页内品牌 → 正站 exact
          consider(apexFlatRel || label, "exact", 99);
        } else if (!mktShape
          && !(typeof NS.isYoungUnverifiedRegistration === "function" && NS.isYoungUnverifiedRegistration())
          && typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
          && (NS.hostLabelStronglyAlignedWithIdentityKeywords(labelRaw, kw)
            || NS.hostLabelStronglyAlignedWithIdentityKeywords(apexLeftRel, kw))) {
          // 展示用品牌核：域名前缀里最长的页面拉丁 token（todesk 而非 ai）
          // 强对齐仅对「非夹带、非年轻」apex；todesk-ze 等已在上方走 padded
          const alignLab = apexFlatRel || label;
          let coreTok = "";
          const latinCands = cleanTokens
            .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
            .filter((t) => {
              if (t.length < 4 || !alignLab.startsWith(t) || /^(?:linux|windows|android|macos|ai|gpt)$/i.test(t)) return false;
              if (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(t)) return false;
              const pad = alignLab.slice(t.length);
              // 短垃圾尾（ze/o/x）→ 非 exact 正站
              if (pad.length >= 1 && pad.length <= 2 && /^[a-z0-9]{1,2}$/i.test(pad)
                && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(pad)) return false;
              if (pad && typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(alignLab, t)) return false;
              return true;
            })
            .sort((a, b) => b.length - a.length);
          coreTok = latinCands[0] || (kw.latin && kw.latin[0]) || alignLab;
          if (latinCands[0]) consider(coreTok, "exact", 100);
        }
      } catch { /* ignore */ }

      // 官网页：CDN 子域资源（cdn-www.huorong.cn）→ 干净主机才算正站；ca-hongrong 等夹带域绝不当 exact
      try {
        const pageConfirmedPaddedShape = typeof NS.hostLabelIsPaddedBrand === "function"
          && cleanTokens.some((raw) => {
            const token = String(raw || "").toLowerCase().replace(/[^a-z0-9]/g, "");
            return token.length >= 3
              && (NS.hostLabelIsPaddedBrand(labelRaw, token) || NS.hostLabelIsPaddedBrand(label, token));
          });
        const looksPad = /[-_]/.test(labelRaw)
          || /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|im|qq|wx|dl)[a-z0-9]{3,}/i.test(label)
          || (typeof NS.inferMarketingPaddedBrandCore === "function" && NS.inferMarketingPaddedBrandCore(labelRaw))
          || pageConfirmedPaddedShape;
        if (!looksPad && typeof NS.hostLabelMatchesPageResourceApex === "function"
          && NS.hostLabelMatchesPageResourceApex(host)) {
          consider(label, "exact", 99);
        }
      } catch { /* ignore */ }

      // 中文品牌页 + 营销夹带主机（ca-hongrong / qq-musics / win.qq-musics / qqmusics）：强制 padded squat
      // ★ 根源：整主机 resolveHostBrandCore，勿只看首标签 win
      try {
        const padCore = (typeof NS.resolveHostBrandCore === "function"
          ? (NS.resolveHostBrandCore(host) || "")
          : "")
          || (typeof NS.inferMarketingPaddedBrandCore === "function"
            ? (NS.inferMarketingPaddedBrandCore(labelRaw) || "")
            : "");
        const apexLeft = (() => {
          try {
            const ap = typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host;
            return (String(ap || "").split(".")[0] || "").toLowerCase();
          } catch { return labelRaw; }
        })();
        const apexFlat = apexLeft.replace(/[^a-z0-9]/g, "");
        const hostPadded = !!(padCore && padCore.length >= 4 && (
          (apexFlat && apexFlat !== padCore && apexFlat.includes(padCore))
          || (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
            && (NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw)
              || NS.hostLabelIsMarketingPrefixedBrandShape(apexLeft)))
          || (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeft))
          || /^(?:qq|wx|weixin)(?:music|musics|yinyue|yinle)$/i.test(apexFlat)
          || (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(labelRaw)
            && apexFlat && padCore && apexFlat.includes(padCore) && apexFlat !== padCore)
        ));
        if ((padCore.length >= 4 && hostPadded) || /^(?:qq|wx)(?:music|musics|yinyue|yinle)$/i.test(apexFlat)) {
          const tok = padCore.length >= 4 ? padCore : (apexFlat.replace(/^(?:qq|wx)/i, "") || apexFlat);
          const hasCnBrand = tokens.some((t) => /[一-鿿]{2,}/.test(String(t)));
          const cnBlob = (kw.blob || "") + (kw.display || "");
          if (hasCnBrand || /[一-鿿]{2,}(?:安全|杀毒|官网|官方|下载|软件|卫士|钉钉|音乐)/.test(cnBlob)
            || /QQ\s*音乐|qq音乐/i.test(cnBlob)
            || tokens.some((t) => String(t).toLowerCase().replace(/[^a-z0-9]/g, "") === tok)
            || String(kw.blob || "").toLowerCase().includes(tok)) {
            consider(tok, "padded", 86);
          } else {
            consider(tok, "padded", 82);
          }
        }
        // ca-hongrong / v-dingtalk / qq-musics：前缀 + 核
        if (/^(?:aa|bb|cc|ca|im|ie|get|pc|app|soft|v|pr|ott|qq|win)[-_]/i.test(labelRaw)
          || /^(?:aa|bb|cc|ca|im|ie|get|pc|app|soft|v|pr|ott|qq|win)[-_]/i.test(apexLeft)) {
          const src = /^(?:aa|bb|cc|ca|im|ie|get|pc|app|soft|v|pr|ott|qq|win)[-_]/i.test(apexLeft) ? apexLeft : labelRaw;
          const rest = src.replace(/^(?:aa|bb|cc|ca|im|ie|get|pc|app|soft|v|pr|ott|qq|win)[-_]/i, "").replace(/[^a-z0-9]/g, "");
          if (rest.length >= 4 && (/[一-鿿]{2,}/.test(kw.blob || "") || tokens.some((t) => /[一-鿿]/.test(String(t)))
            || /QQ\s*音乐|music/i.test(kw.blob || "")
            || String(kw.blob || "").toLowerCase().includes(rest))) {
            consider(rest, "padded", 84);
          }
        }
      } catch { /* ignore */ }

      for (const rawTok of cleanTokens.length ? cleanTokens : tokens) {
        const tok = String(rawTok || "").trim();
        if (!tok) continue;
        const low = tok.toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]/gi, "");
        if (low.length < 2) continue;
        const isLatin = /^[a-z0-9]+$/i.test(low);

        if (isLatin) {
          const t = low.replace(/[^a-z0-9]/g, "");
          if (t.length < 3) continue;
          if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) continue;
          // 连字符拆品牌：crystaldisk-mark ≡ CrystalDiskMark → 仿冒 hyphen，绝不当 exact
          // （去连字符后 label===t 曾误判正站 related，导致 crystaldisk-mark.cn 漏拦）
          const hyphenMirror = typeof NS.hostLabelIsHyphenatedBrandMirror === "function"
            && NS.hostLabelIsHyphenatedBrandMirror(labelRaw, t);
          if (hyphenMirror) {
            consider(t, "hyphen", 88);
            continue;
          }
          // exact 主机标签：仅「无连字符」或 labelRaw 整段等于 token
          if (labelRaw === t || (label === t && !/-/.test(labelRaw))) {
            consider(t, "exact", 100);
            continue;
          }
          // 「品牌 + 品类」只说明域名结构模仿了页面产品线，不能证明域名归属。
          // 没有独立 ICP/官方资源证据时按夹带域处理，避免 brand-security 自洗。
          // 开源项目正站靠「公开代码仓 + 下载目标成熟度」门控放行（见 pageLooksLikeTrustedOpenSourceDownloadPortal）。
          if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
            && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, t)
              || NS.hostLabelIsBrandProductCategoryDomain(label, t))) {
            const safeProductLine = typeof NS.hostLabelHasSafeProductLineSuffix === "function"
              && NS.hostLabelHasSafeProductLineSuffix(labelRaw, t);
            if (!safeProductLine) {
              consider(t, "padded", 95);
              continue;
            }
          }
          // apex 品牌根（apex 本身带连字符拆品牌时不当 exact）
          const apexRaw0 = (pageApex.split(".")[0] || "").toLowerCase();
          if (apexLabel === t && !/-/.test(apexRaw0)) {
            consider(t, "exact", 98); continue;
          }
          // 子域在品牌 apex 下（brand.com 子域）
          if (pageApex.startsWith(`${t}.`) || host.endsWith(`.${t}.com`) || host.endsWith(`.${t}.cn`)
            || host.endsWith(`.${t}.com.cn`) || host.endsWith(`.${t}.net`) || host.endsWith(`.${t}.org`)) {
            // 排除 crystaldisk-mark.cn 这种「整段 label 去连字符=品牌」的伪 apex
            if (!hyphenMirror && !/-/.test(labelRaw)) {
              consider(t, "exact", 96); continue;
            }
          }
          // 拼写仿冒 / 夹带
          if (typeof NS.hostLabelIsBrandTypo === "function" && NS.hostLabelIsBrandTypo(label, t)) {
            consider(t, "typo", 70); continue;
          }
          if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, t)) {
            consider(t, "padded", 72); continue;
          }
          if (typeof NS.hostLabelIsPaddedBrand === "function"
            && (NS.hostLabelIsPaddedBrand(label, t) || NS.hostLabelIsPaddedBrand(labelRaw, t))) {
            consider(t, "padded", 72); continue;
          }
          // 包含关系（足够长才算相关）— 连字符镜像已在上方处理
          if (t.length >= 4 && (label.includes(t) || t.includes(label))) {
            // crystaldiskmark 含 crystaldisk：勿把 hyphen 站降成弱 partial
            if (/-/.test(labelRaw) && label.replace(/-/g, "") === t) {
              consider(t, "hyphen", 85);
              continue;
            }
            consider(t, "partial", 50); continue;
          }
          // 主机在关键词 blob 中出现（页脚/标题写了域名品牌）
          if (t.length >= 4 && (kw.blob || "").toLowerCase().includes(t)) {
            // 仅当主机也含该 token 才算 domain 相关
            if (label.includes(t) || labelRaw.includes(t) || apexLabel === t) consider(t, "partial", 55);
          }
        } else {
          // 中文/数字品牌（2345看图王）：
          // - 主机仅为 2345 / apex 2345.com.cn → exact 正站
          // - 2345-kantuwangd / 2345xxx 乱拼拼音 → padded 仿冒，绝不当 exact
          const digits = (tok.match(/\d{2,6}/) || [])[0] || "";
          if (digits && digits.length >= 3) {
            const pureDigitHost = label === digits || apexLabel === digits || labelRaw === digits
              || new RegExp(`^${digits}\\.(com|cn|net|com\\.cn)$`, "i").test(host);
            if (pureDigitHost) {
              consider(tok, "exact", 92);
            } else if (labelRaw.startsWith(`${digits}-`) || label.startsWith(digits)) {
              // 2345-kantuwangd.com.cn：数字品牌 + 乱码后缀 = 营销夹带
              const rest = labelRaw.startsWith(`${digits}-`)
                ? labelRaw.slice(digits.length + 1)
                : label.slice(digits.length);
              if (rest && rest.length >= 2) {
                consider(tok, "padded", 78);
              } else {
                consider(tok, "exact", 90);
              }
            } else if (label.includes(digits) || host.replace(/[^a-z0-9]/g, "").includes(digits)) {
              consider(tok, "partial", 50);
            }
          }
        }
      }

      // 数字夹带主机（2345-kantuwangd）且关键词含同数字产品 → 强制 padded（防止漏判）
      if (bestMatch !== "padded" && bestMatch !== "typo") {
        const digHost = (labelRaw.match(/^(\d{3,6})[-_]?([a-z][a-z0-9]{2,})/i) || []);
        if (digHost[1] && digHost[2]) {
          const hasDigBrand = tokens.some((t) => String(t).includes(digHost[1]));
          if (hasDigBrand) consider(tokens.find((t) => String(t).includes(digHost[1])) || digHost[1], "padded", 80);
        }
      }

      // 产品复合域名：Arch Linux → archlinux；ToDesk AI → todeskai
      // 须在 padded 推断之前，避免 arch+linux / todesk+ai 被当成夹带
      if (!kw.hyphenSplitClaim
        && bestMatch !== "padded" && bestMatch !== "typo" && bestMatch !== "hyphen") {
        try {
          // 复合域名的品牌核只能来自已经通过页面身份门控的 token。
          // 原始 blob 只允许补平台/产品线尾词，不能从 footer 当前域名
          // 重新制造一个 exact 品牌。
          const acceptedCompoundBrands = tokens
            .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
            .filter((t) => t.length >= 3
              && !/^(?:linux|windows|macos|android|bsd|ai|gpt|ml|bot|llm)$/i.test(t));
          const compoundToks = [...new Set(acceptedCompoundBrands)];
          const addProductLineToken = (raw) => {
            const low = String(raw || "").toLowerCase().replace(/[^a-z0-9]/g, "");
            if (/^(?:linux|windows|macos|android|bsd|ai|gpt|ml|bot|llm)$/i.test(low)
              && !compoundToks.includes(low)) {
              compoundToks.push(low);
            }
          };
          // 从 blob 再补平台/产品线词（linux / AI 常被 display 链路滤掉）
          if (typeof NS.extractLatinBrandTokens === "function") {
            NS.extractLatinBrandTokens(kw.blob || "").forEach(addProductLineToken);
          }
          // 标题常见「Brand Platform」空格分词（含 2 字母 AI）
          const titleBits = String((kw && kw.blob) || document.title || "").match(/[A-Za-z][A-Za-z0-9]{0,23}/g) || [];
          titleBits.forEach(addProductLineToken);
          if (typeof NS.hostLabelComposedOfTitleTokens === "function"
            && NS.hostLabelComposedOfTitleTokens(label, compoundToks)) {
            // 展示用品牌核（todesk / arch，而非 ai / linux）
            const coreTok = acceptedCompoundBrands
              .filter((t) => label.startsWith(t))
              .sort((a, b) => b.length - a.length)[0] || label;
            consider(coreTok, "exact", 99);
          } else {
            // 结构回退：主机 = 品牌token + 平台/产品线尾缀（archlinux、todeskai）
            for (const t of acceptedCompoundBrands) {
              if (label === `${t}linux` || label === `${t}windows` || label === `${t}macos` || label === `${t}android`
                || label === `${t}ai` || label === `${t}gpt` || label === `${t}ml` || label === `${t}bot` || label === `${t}llm`) {
                // 页上须能看到产品线词或「Brand AI」话术，避免裸结构误放
                const blobL = String((kw && kw.blob) || document.title || "").toLowerCase();
                const suf = label.slice(t.length);
                if (blobL.includes(t) && (blobL.includes(suf) || new RegExp(`${t}[\\s\\-_]*${suf}`, "i").test(blobL)
                  || (typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
                    && NS.hostLabelStronglyAlignedWithIdentityKeywords(label, kw)))) {
                  consider(t, "exact", 98);
                  break;
                }
              }
            }
          }
        } catch { /* ignore */ }
      }

      // 推断营销夹带核心：huorong-pc → huorong，且关键词含火绒/huorong
      // 已判定 exact/category 的复合域名不再降为 padded
      if (bestMatch === "none" && typeof NS.inferMarketingPaddedBrandCore === "function") {
        const core = NS.inferMarketingPaddedBrandCore(labelRaw) || "";
        if (core.length >= 4) {
          const blobLow = (kw.blob || "").toLowerCase();
          if (blobLow.includes(core) || tokens.some((t) => String(t).toLowerCase().includes(core))) {
            consider(core, "padded", 72);
          } else if (typeof NS.hostLabelIsPaddedBrand === "function" && tokens.some((t) => {
            const tl = String(t).toLowerCase().replace(/[^a-z0-9]/g, "");
            return tl.length >= 4 && NS.hostLabelIsPaddedBrand(label, tl);
          })) {
            consider(core, "padded", 70);
          }
        }
      }

      // 页面资源/页脚可能全部复制当前假域名，不能让这些自证据把拼音尾缀 typo 覆盖成 exact。
      if (cnRomanizedSuffixTypo) {
        // 匹配 token 用推断出的拉丁域名核；最终展示仍统一取 kw.display 中文品牌。
        consider(cnRomanizedSuffixTypo.expectedHostLabel, "typo", 110);
      }

      // 半真半假：夹带/拼写/连字符/弱 partial → squat（按盗版）
      // 几乎关联：仅 exact / category（及极高分 partial 且拉丁主品牌≥5）
      let squat = bestMatch === "padded" || bestMatch === "typo" || bestMatch === "hyphen"
        || (bestMatch === "partial" && bestScore < 85);
      // ★ 双保险：apex 已是营销夹带形态时，禁止 related/exact 放行（todesk-ze 曾被洗成 exact）
      try {
        const apexLeftForce = (() => {
          try {
            const ap = typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host;
            return (String(ap || "").split(".")[0] || labelRaw || "").toLowerCase();
          } catch { return labelRaw; }
        })();
        if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && (NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftForce)
            || NS.apexLabelLooksLikeMarketingPaddedBrand(labelRaw))) {
          squat = true;
          if (bestMatch === "exact" || bestMatch === "category" || bestMatch === "none") {
            bestMatch = "padded";
          }
          if (!bestTok && typeof NS.inferMarketingPaddedBrandCore === "function") {
            bestTok = NS.inferMarketingPaddedBrandCore(apexLeftForce)
              || NS.inferMarketingPaddedBrandCore(labelRaw)
              || bestTok;
          }
        }
      } catch { /* ignore */ }
      let related = !squat && (
        bestMatch === "exact"
        || bestMatch === "category"
        || (bestMatch === "partial" && bestScore >= 85 && /^[a-z0-9]+$/i.test(bestTok) && bestTok.length >= 5)
      );

      // squat 时：若 bestTok 是主机误拆碎片（prto）且不在页内，改用页内真实品牌核（todesk）
      try {
        if (squat && bestTok) {
          const blobFlat0 = String((kw && kw.blob) || document.title || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          const bt0 = String(bestTok).toLowerCase().replace(/[^a-z0-9]/g, "");
          if (bt0.length >= 3 && !blobFlat0.includes(bt0)) {
            const pageCands = cleanTokens
              .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
              .filter((t) => t.length >= 4 && blobFlat0.includes(t)
                && !(typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)));
            let fixed = "";
            for (const t of pageCands.sort((a, b) => b.length - a.length)) {
              if ((typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, t))
                || (typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(label, t))
                || (typeof NS.hostLabelIsHyphenatedBrandMirror === "function" && NS.hostLabelIsHyphenatedBrandMirror(labelRaw, t))
                || (label.includes(t) && label !== t)) {
                fixed = t;
                break;
              }
            }
            if (!fixed && pageCands[0]) fixed = pageCands[0];
            if (fixed) {
              bestTok = fixed;
              if (bestMatch === "none" || bestMatch === "partial") bestMatch = "padded";
              squat = true;
              related = false;
            }
          }
        }
      } catch { /* ignore */ }

      // 展示品牌：一律等权 display（resolve 只读 pk，不写主机旁路）
      // squat/related 旁路只改 hostMatch，不改 brand 字符串
      let brand = "";
      try {
        if (typeof NS.resolveSpoofDisplayBrand === "function") {
          brand = NS.resolveSpoofDisplayBrand(host, kw) || "";
        }
      } catch { brand = ""; }
      if (!brand && kw && kw.display) {
        brand = typeof NS.canonicalizeBrandDisplayCandidate === "function"
          ? NS.canonicalizeBrandDisplayCandidate(kw.display)
          : kw.display;
      }
      // 品类结构 squat：展示名只来自页内抽词（cnBrandWithBlob），绝不从词库发明品牌
      if (cnCategoryHostSquat && (!brand || brand.length < 2)) {
        if (cnBrandForRoman && /[一-鿿]/.test(cnBrandForRoman)
          && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cnBrandForRoman))) {
          brand = cnBrandForRoman;
        } else if (cnBrandWithBlob && /[一-鿿]/.test(cnBrandWithBlob)
          && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cnBrandWithBlob))) {
          brand = cnBrandWithBlob;
        }
      }
      if (brand && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        brand = NS.canonicalizeBrandDisplayCandidate(brand);
      }
      if (brand && typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(brand)) brand = "";
      if (brand && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)) brand = "";
      // 产品线域名：页上是「ToDesk AI」时展示完整产品名，而非截成 Todesk
      try {
        if ((related || bestMatch === "exact" || bestMatch === "category") && bestTok) {
          const blobDisp = String((kw && kw.blob) || document.title || "");
          const bt = String(bestTok).replace(/[^a-z0-9]/gi, "");
          const mAi = blobDisp.match(new RegExp(`\\b(${bt})\\s*(AI|GPT|LLM)\\b`, "i"))
            || blobDisp.match(new RegExp(`(${bt})\\s*(AI|GPT|LLM)`, "i"));
          if (mAi && label === (bt + mAi[2]).toLowerCase().replace(/[^a-z0-9]/g, "")) {
            // 展示名走通用格式化（desk/talk 等结构驼峰），不写死具体品牌
            const head = typeof NS.formatBrandTokenForDisplay === "function"
              ? NS.formatBrandTokenForDisplay(bt)
              : (bt.charAt(0).toUpperCase() + bt.slice(1));
            brand = `${head} ${String(mAi[2]).toUpperCase()}`;
          }
        }
      } catch { /* ignore */ }
      if (!brand && kw && kw.cn && kw.cn[0]) brand = kw.cn[0];
      // 拒绝主机夹带拼词（Iehuorong / Huorongpc）
      if (brand && typeof NS.isHostShapedCompoundBrandToken === "function"
        && NS.isHostShapedCompoundBrandToken(brand, host)) {
        brand = (kw && kw.cn && kw.cn[0]) || "";
      }
      // bestTok 是域名关系核，不是展示身份。品牌名只能来自上面的页面共识。

      // 无主机对齐时 hostMatch 保持 none；有弱 partial 但不 related → 标为 none 便于仿冒链路
      let hostMatchOut = bestMatch;
      if (!related && !squat && bestMatch === "partial" && bestScore < 70) {
        hostMatchOut = "none";
      }
      if (!related && !squat && bestMatch === "none") hostMatchOut = "none";

      const brandTokenOut = bestTok
        || (kw && kw.display)
        || (kw && kw.cn && kw.cn[0])
        || (kw && kw.latin && kw.latin[0])
        || "";

      return {
        related: !!related,
        squat: !!squat,
        // 域名与关键词是否明显错配（有产品品牌 + 非正站相关）
        mismatch: !related && !!(brand || brandTokenOut) && (squat || hostMatchOut === "none"),
        hostMatch: hostMatchOut,
        brand: brand || "",
        brandToken: brandTokenOut,
        keywords: tokens.slice(0, 24),
        score: bestScore,
        labelRaw,
        pageApex,
        primary: kw
      };
    } catch {
      return empty;
    }
  };

  /**
   * 标题↔主机品牌相关性（无品牌白名单）。
   * 产品关键词 = title/description/keywords/h1·h2/footer·copyright/logo·span 综合共识。
   * 禁止 body / CMS meta（template、generator）参与展示名。
   * 优先走 evaluateDomainKeywordRelevance（多字段综合，非单字段抢先）。
   */
  NS.evaluateTitleHostBrandCorrelation = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "serp", hostLabel: "", pageApex: "", rigorousMatch: false, displayBrand: "" };
      const title = document.title || "";
      if (/[-–|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title)) return { mismatch: false, brandToken: "", brandHits: 0, hostMatch: "serp", hostLabel: "", pageApex: "", rigorousMatch: false, displayBrand: "" };
      // 主门控：域名 ↔ 主身份关键词相关 → 直接 exact，不吃功能卡中文口号
      try {
        if (typeof NS.evaluateDomainKeywordRelevance === "function") {
          const rel = NS.evaluateDomainKeywordRelevance();
          if (rel && rel.related && !rel.squat) {
            return {
              mismatch: false,
              brandToken: rel.brandToken || "",
              brandHits: Math.max(12, rel.score || 0),
              hostMatch: (rel.hostMatch === "category" || rel.hostMatch === "partial") ? "exact" : (rel.hostMatch || "exact"),
              hostLabel: rel.labelRaw || "",
              pageApex: rel.pageApex || "",
              rigorousMatch: true,
              displayBrand: rel.brand || ""
            };
          }
        }
      } catch { /* fall through */ }
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
            && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cnHit[1]))) {
            cnDisplay = cnHit[1];
          }
          if (!cnDisplay && typeof NS.pickChineseBrandFromPageSurface === "function") {
            cnDisplay = NS.pickChineseBrandFromPageSurface(title) || "";
          }
        } catch { /* ignore */ }
      }
      if (cnDisplay && typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cnDisplay)) {
        cnDisplay = "";
      }

      // 与下载落地壳对齐：勿用裸「杀毒软件/安全软件」当官网 pitch（博客评测误报）
      const officialPitchEarly = /官网|官方下载|官方正版|官方网站|电脑版官网|免费下载|立即免费下载|官方桌面|官方客户端|官方安全|官方杀毒|专业.*工具|立即下载|全平台官方|Enterprise|Collaboration|AI-Powered|安静|纯净|强悍|个人版|终端安全/i.test(`${claimText} ${identityText}`);
      const cnRomanizedSuffixTypo = cnDisplay && typeof NS.detectChineseProductRomanizedSuffixTypo === "function"
        ? NS.detectChineseProductRomanizedSuffixTypo(cnDisplay, (pageApex.split(".")[0] || labelRaw))
        : null;
      if (officialPitchEarly && cnRomanizedSuffixTypo) {
        return {
          mismatch: true,
          brandToken: cnRomanizedSuffixTypo.expectedHostLabel,
          brandHits: 16,
          hostMatch: "typo",
          hostLabel: label,
          pageApex,
          rigorousMatch: false,
          displayBrand: cnDisplay
        };
      }
      // 页内中文产品品牌 + 主机品类拉丁尾 → mismatch（展示名=页内 cnDisplay）
      const cnCatHostSquat = (typeof NS.detectChineseProductCategoryHostSquat === "function"
        || typeof NS.detectChineseMusicBrandDomainSquat === "function")
        ? (() => {
          const fn = NS.detectChineseProductCategoryHostSquat || NS.detectChineseMusicBrandDomainSquat;
          const hostL = pageApex.split(".")[0] || labelRaw;
          return fn(hostL, cnDisplay) || fn(label, cnDisplay) || fn(labelRaw, cnDisplay);
        })()
        : null;
      if (cnCatHostSquat && cnDisplay && (officialPitchEarly || /[一-鿿]{2,}/.test(cnDisplay))) {
        return {
          mismatch: true,
          brandToken: cnCatHostSquat.brandToken || cnCatHostSquat.expectedHostLabel,
          brandHits: 16,
          hostMatch: cnCatHostSquat.hostMatch || "typo",
          hostLabel: label,
          pageApex,
          rigorousMatch: false,
          displayBrand: cnDisplay
        };
      }
      // 主机营销夹带核心：即使页上无 Huorong 拉丁，huorong-pc 也可推断
      const inferredHostCore = typeof NS.inferMarketingPaddedBrandCore === "function"
        ? (NS.inferMarketingPaddedBrandCore(labelRaw) || "")
        : "";

      const squatShape = squatOnHost || NS.titleBrandVsHostSquatShape(claimText, labelRaw, hostAlignedLatin || inferredHostCore || "");
      const resolveDisplay = (latinTok) => {
        // latinTok 只用于域名相关性判断；展示名必须来自页面身份共识。
        void latinTok;
        try {
          if (typeof NS.resolveSpoofDisplayBrand === "function") {
            return NS.resolveSpoofDisplayBrand(location.hostname) || "";
          }
        } catch { /* ignore */ }
        return "";
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
        // 主机与中文品牌对齐：页内共现拉丁核 / 品类结构（算法，无固定品牌桥）
        const pureLatinHost = /^[a-z][a-z0-9]{2,30}$/i.test(label) && !/[-_]/.test(labelRaw);
        const idLow = brandCorpus.toLowerCase();
        const hostInIdentity = label.length >= 3 && (idLow.includes(label) || claimText.toLowerCase().includes(label));
        const hostCoresForCn = typeof NS.collectHostBrandCores === "function"
          ? NS.collectHostBrandCores(host)
          : null;
        const hostHintsCnBrand = typeof NS.domainLatinRootHintsChineseBrand === "function"
          && !!NS.domainLatinRootHintsChineseBrand(cnDisplay, hostCoresForCn);
        if (!coreOk && !hostInIdentity && !hostHintsCnBrand && cnDisplay.length >= 2) {
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
      const unverifiedCategoryHost = uniqueForCompound.some((t) =>
        typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
        && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, t)
          || NS.hostLabelIsBrandProductCategoryDomain(label, t))
        && !(typeof NS.hostLabelHasSafeProductLineSuffix === "function"
          && NS.hostLabelHasSafeProductLineSuffix(labelRaw, t)));
      if (compoundHost && !unverifiedCategoryHost
        && squatShape !== "hyphen" && squatShape !== "padded" && squatShape !== "typo") {
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
        // crystaldisk-mark：去横线后=品牌 → 连字符仿冒分，不当 exact 100
        if (typeof NS.hostLabelIsHyphenatedBrandMirror === "function" && NS.hostLabelIsHyphenatedBrandMirror(labelRaw, t)) score += 92;
        else if (labelRaw === t || (label === t && !/-/.test(labelRaw))) score += 100;
        else if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
          && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, t) || NS.hostLabelIsBrandProductCategoryDomain(label, t))) {
          score += typeof NS.hostLabelHasSafeProductLineSuffix === "function"
            && NS.hostLabelHasSafeProductLineSuffix(labelRaw, t)
            ? 98
            : 70;
        }
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
      // Brand + 品类词域名仍需独立归属证据；页面自述本身不能把它变成 exact。
      // 开源正站（如 pyas-security + GitHub releases）走公开代码仓 + 下载成熟度门控，不在此自洗。
      const productCategoryDomain = typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
        && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, brandToken)
          || NS.hostLabelIsBrandProductCategoryDomain(label, brandToken));
      const safeProductLineDomain = productCategoryDomain
        && typeof NS.hostLabelHasSafeProductLineSuffix === "function"
        && NS.hostLabelHasSafeProductLineSuffix(labelRaw, brandToken);
      // 夹带/前缀仿冒不得标为 rigorous exact（否则 im-todesk 会被当成官网）
      // 子域/apex：*.sogou.com 对品牌 sogou 算 exact
      const apexBrandLabel = (pageApex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const underBrandApex = apexBrandLabel.length >= 3 && (brandToken === apexBrandLabel || pageApex === `${brandToken}.com` || pageApex === `${brandToken}.cn` || pageApex === `${brandToken}.com.cn` || pageApex === `${brandToken}.net` || pageApex === `${brandToken}.org` || host.endsWith(`.${brandToken}.com`) || host.endsWith(`.${brandToken}.cn`) || host.endsWith(`.${brandToken}.com.cn`) || host.endsWith(`.${pageApex}`) && brandToken === apexBrandLabel);
      const rigorousMatch = !hyphenMirror && !prefixedHyphen && !paddedBrand && (
        label === brandToken
        || safeProductLineDomain
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
      else if (productCategoryDomain && !safeProductLineDomain) hostMatch = "padded";
      else if (rigorousMatch) hostMatch = "exact";
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
        // ★ todesk-ze 等短垃圾尾：有品牌核 + padded 即 mismatch（勿抬到 8 票才认）
        if (!mismatch && hostMatch === "padded" && paddedBrand && brandToken && brandHits >= 1
          && /下载|客户端|安装|免费|官网|官方|软件|远程|桌面/i.test(titleLow + claimText + body.slice(0, 800))) {
          mismatch = true;
        }
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

  /**
   * 品牌夹字/第三方主域不能仅凭页面自称取得“官方网站”身份。
   * 结构例：to+todesk、wps+docs、huorong+r、huorong-m.softw.com.cn。
   * 不维护品牌名单：品牌核来自页面等权身份字段；成熟度只可放行自有 apex，
   * 不能替第三方门户下的品牌子域背书。
   */
  NS.hostNeedsAuthoritativeBrandIdentity = function (hostOpt) {
    try {
      const host = typeof NS.normalizeDomain === "function"
        ? NS.normalizeDomain(hostOpt || location.hostname)
        : String(hostOpt || location.hostname || "").toLowerCase().replace(/^www\./, "");
      if (!host) return false;
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host) || host;
      const apexLeftRaw = (String(apex).split(".")[0] || "").toLowerCase();
      const apexLeft = apexLeftRaw.replace(/[^a-z0-9]/g, "");
      const targets = [];
      const addTarget = (raw, isApex) => {
        const label = String(raw || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (label.length >= 3 && !targets.some((x) => x.label === label && x.isApex === !!isApex)) {
          targets.push({ label, raw: String(raw || "").toLowerCase(), isApex: !!isApex });
        }
      };
      addTarget(apexLeftRaw, true);
      if (host !== apex && host.endsWith(`.${apex}`)) {
        host.slice(0, -(apex.length + 1)).split(".").forEach((p) => {
          if (!/^(?:www|m|wap)$/i.test(p)) addTarget(p, false);
        });
      }

      const tokens = [];
      const seen = Object.create(null);
      const addToken = (raw) => {
        const t = String(raw || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (t.length < 3 || t.length > 24 || seen[t]) return;
        if (/^(?:official|download|downloads|software|client|setup|install|installer|windows|android|desktop|service|services|docs?|help|support|app|apps|soft|safe|free|online)$/i.test(t)) return;
        seen[t] = 1;
        tokens.push(t);
      };
      try {
        const pk = typeof NS.collectPrimaryBrandKeywords === "function"
          ? NS.collectPrimaryBrandKeywords() : null;
        if (pk) {
          (pk.latin || []).forEach(addToken);
          if (/^[a-z0-9][a-z0-9.\-_]{2,24}$/i.test(String(pk.display || ""))) addToken(pk.display);
        }
      } catch { /* ignore */ }
      try {
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          addToken(NS.pickHostAlignedLatinBrandFromPage(host));
        }
      } catch { /* ignore */ }

      const fullAccepted = new Set(tokens);
      const days = typeof NS.getWhoisAgeDays === "function" ? NS.getWhoisAgeDays() : null;
      const authoritativeApex = !!(
        (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord())
        || (typeof NS.hasOrganizationValidatedSsl === "function" && NS.hasOrganizationValidatedSsl())
        || (days != null && days >= 3650)
      );
      const youngOrUnknown = days == null || days < 365;
      const structuralAffix = (s) => {
        const x = String(s || "").toLowerCase();
        if (!x) return false;
        if (x.length <= 2) return true;
        if (/^(?:docs?|help|support|soft|safe|download|down|client|setup|install|official|free|app|apps|pc|m|win|top|pro|vip)$/i.test(x)) return true;
        return typeof NS.isMarketingHostPrefixToken === "function"
          && NS.isMarketingHostPrefixToken(x, { strict: true });
      };
      const productLine = /^(?:ai|gpt|ml|bot|llm|security|antivirus|secure|linux|windows|macos|android)$/i;

      for (const tok of tokens) {
        for (const target of targets) {
          const lab = target.label;
          const idx = lab.indexOf(tok);
          if (idx < 0) continue;
          const left = lab.slice(0, idx);
          const right = lab.slice(idx + tok.length);
          // 品牌子域落在无关 apex 下：门户年龄/备案只证明门户，不证明该品牌官网。
          if (!target.isApex && apexLeft !== tok
            && !apexLeft.includes(tok) && !tok.includes(apexLeft)) return true;
          if (!left && !right) continue;
          // 完整产品线名称确实进入页面身份总榜时，允许通用品类后缀；docs/营销垫除外。
          if (fullAccepted.has(lab) && !left && productLine.test(right)) continue;
          if (!target.isApex) return true;
          if (!authoritativeApex && (structuralAffix(left) || structuralAffix(right))) return true;
          if (!authoritativeApex && youngOrUnknown && !fullAccepted.has(lab)) return true;
        }
      }

      // 仅中文页面仍可用结构剥核兜底：新 apex/第三方子域出现明显尾污染时，
      // 拒绝“干净官网”放行，品牌展示稍后再由 SW pinyin 定稿。
      const claimsBrandDownload = /官网|官方|下载|客户端|安装|安全软件|杀毒/i.test(
        `${document.title || ""} ${String(document.querySelector("h1")?.textContent || "").slice(0, 120)}`
      );
      if (claimsBrandDownload) {
        for (const target of targets) {
          let core = "";
          try {
            core = typeof NS.inferMarketingPaddedBrandCore === "function"
              ? String(NS.inferMarketingPaddedBrandCore(target.raw) || "").replace(/[^a-z0-9]/g, "")
              : "";
          } catch { core = ""; }
          if (core.length >= 4 && core !== target.label && target.label.includes(core)) {
            if (!target.isApex || !authoritativeApex) return true;
          }
        }
      }
      return false;
    } catch {
      return false;
    }
  };

  NS.hostLooksLikeBrandMarketingSpoof = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity()) return true;
      if (NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
      try {
        const hr = NS.brandRootKeyFromHost(location.hostname);
        const lab0 = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        if (hr.length >= 4 && /^(wiki|docs?|help|manual|handbook|bbs|forum|forums|community)$/i.test(lab0)) {
          const titleLow = (document.title || "").toLowerCase();
          if (titleLow.includes(hr) || titleLow.replace(/[^a-z0-9]/g, "").includes(hr)) return false;
        }
      } catch { /* ignore */ }
      // ★ 年轻无备案：必须走仿冒链，禁止任何「正站对齐」捷径
      try {
        if (typeof NS.isYoungUnverifiedRegistration === "function"
          && NS.isYoungUnverifiedRegistration()) {
          /* 不 early-return；继续 mismatch / padded 判定 */
        } else {
          // title/logo/nav 关键词能拼成域名（todesk+AI）→ 非营销仿冒
          // 必须用 apex 左标，勿用 www；todesk-ze 等短垃圾尾不得当正站放行
          const host0 = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
          const apex0 = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host0) : host0) || host0;
          const labAlign = (String(apex0).split(".")[0] || "").toLowerCase();
          if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(labAlign)) {
            /* 夹带 apex：继续往下判仿冒 */
          } else if (typeof NS.hostLabelStronglyAlignedWithIdentityKeywords === "function"
            && NS.hostLabelStronglyAlignedWithIdentityKeywords(labAlign)) {
            return false;
          }
        }
      } catch { /* ignore */ }
      const state = NS.state;
      if (NS.hasValidIcpRecord() && !state._seoCloakKitDetected && !state._fakeSpaDetected) return false;
      const corrEarly = NS.evaluateTitleHostBrandCorrelation();
      if ((corrEarly.rigorousMatch || corrEarly.hostMatch === "exact") && corrEarly.hostMatch !== "hyphen" && corrEarly.hostMatch !== "padded" && corrEarly.hostMatch !== "typo") return false;
      try {
        if (typeof NS.pageLooksLikeTrustedOpenSourceDownloadPortal === "function"
          && NS.pageLooksLikeTrustedOpenSourceDownloadPortal()) {
          return false;
        }
      } catch { /* ignore */ }

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
      const seoTemplate = /seo[_-]?templates?|\/zd\/[a-z0-9_-]+\/|seo_templates\/index|ca-?aurora-template|ca-?download-?cms|aurora-template/i.test(`${location.pathname} ${htmlHead}`)
        || /ca-?download-?cms|ca-?aurora|seo[_-]?template/i.test(String(document.querySelector('meta[name="generator"]')?.getAttribute("content") || "")
          + " " + String(document.querySelector('meta[name="template"]')?.getAttribute("content") || ""));
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
      if (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(low)) return false;
      return true;
    });
    // 仅当主机标签足够长、非纯数字时加入（结构，非词表）
    try {
      const hostLabel = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      if (hostLabel.length >= 5 && /[a-z]{5,}/i.test(hostLabel)
        && !(NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(hostLabel))
        && !/^\d+$/.test(hostLabel)
        && !/^(www|soft|game|download|cdn|static)$/i.test(hostLabel)) {
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
