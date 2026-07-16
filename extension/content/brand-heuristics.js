/**
 * 域名 / 品牌相关性工具：eTLD+1、品牌 token 提取、标题↔主机拼写仿冒判定。
 */
;(function (NS) {
  "use strict";

  NS.normalizeDomain = function (domain) {
    return String(domain || "").replace(/^www\./i, "").trim().toLowerCase();
  };

  /** 粗略 eTLD+1，处理多段公共后缀（*.com.cn / *.co.uk）。 */
  NS.getRegistrableDomain = function (domain) {
    const d = NS.normalizeDomain(domain);
    const parts = d.split(".").filter(Boolean);
    if (parts.length === 0) return "";
    if (parts.length <= 2) return d;
    const last = parts[parts.length - 1] || "";
    const second = parts[parts.length - 2] || "";
    if (parts.length >= 3 && last.length === 2 && /^(com|net|org|gov|edu|ac|co|or|ne|gob|gen|ltd|plc|me)$/i.test(second)) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  };

  /** 公共后缀下的品牌根：archlinux.org / archlinux.org.cn / wiki.archlinux.org.cn -> "archlinux"。 */
  NS.brandRootKeyFromHost = function (hostOrApex) {
    let s = NS.normalizeDomain(hostOrApex);
    if (!s) return "";
    s = s
      .replace(/\.(com|net|org|gov|edu|ac|co|or|ne|gob|gen|ltd|plc|me)\.cn$/i, "")
      .replace(/\.(com|co|org|net|ac|gov)\.(uk|jp|kr|au|nz|za|br|in|hk|tw|sg)$/i, "")
      .replace(/\.(com|org|net|edu|gov|io|co|me|info|cn|app|dev|xyz|top|cc|tv|us|uk|de|fr|jp|ru|br|in|au|ca|nl|se|no|fi|pl|cz|ch|at|be|es|it|pt|mx|ar|cl|za|kr|tw|hk|sg|my|ph|vn|id|th)$/i, "");
    const parts = s.split(".").filter(Boolean);
    if (!parts.length) return "";
    let best = parts[parts.length - 1] || "";
    for (let i = parts.length - 1; i >= 0; i--) {
      const p = parts[i];
      if (p.length >= 4 && p.length >= best.length
        && !/^(www|wiki|docs|doc|help|support|blog|news|forum|forums|bbs|cdn|static|img|image|media|assets|download|dl|api|m|mobile|mail|git|dev|test|beta|store|shop|cloud)$/i.test(p)) {
        best = p;
      }
    }
    return String(best || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  };

  NS.apexSameBrandFamily = function (apexOrHostA, apexOrHostB) {
    try {
      const a = NS.normalizeDomain(apexOrHostA);
      const b = NS.normalizeDomain(apexOrHostB);
      if (!a || !b) return false;
      if (a === b) return true;
      if (a.endsWith(`.${b}`) || b.endsWith(`.${a}`)) return true;
      const ka = NS.brandRootKeyFromHost(a);
      const kb = NS.brandRootKeyFromHost(b);
      if (ka.length >= 4 && ka === kb) return true;
      const ra = NS.getRegistrableDomain(a);
      const rb = NS.getRegistrableDomain(b);
      if (ra && rb && ra === rb) return true;
      const kra = NS.brandRootKeyFromHost(ra);
      const krb = NS.brandRootKeyFromHost(rb);
      return kra.length >= 4 && kra === krb;
    } catch {
      return false;
    }
  };

  NS.pageIsSameBrandFamilySite = function (pageHost, brandApex) {
    try {
      const h = NS.normalizeDomain(pageHost || location.hostname);
      if (!h || !brandApex) return false;
      if (NS.apexSameBrandFamily(h, brandApex)) return true;
      const root = NS.brandRootKeyFromHost(brandApex);
      if (root.length < 4) return false;
      const labels = h.split(".");
      if (labels.some((l) => l === root || (l.length > root.length && l.includes(root)))) {
        return NS.apexSameBrandFamily(NS.getRegistrableDomain(h), brandApex) || NS.brandRootKeyFromHost(h) === root;
      }
      return false;
    } catch {
      return false;
    }
  };

  NS.intelHostIsValidAttribution = function (queriedHost, pageHost) {
    const q = NS.normalizeDomain(queriedHost);
    const p = NS.normalizeDomain(pageHost);
    if (!q || !p) return false;
    if (q === p) return true;
    if (q.includes(".") && p.endsWith(`.${q}`)) return true;
    return false;
  };

  NS.collectHeadingText = function (maxLen = 4000) {
    const parts = [];
    let total = 0;
    try {
      const nodes = document.querySelectorAll("h1, h2, h3, h4, h5, h6");
      const n = Math.min(nodes.length, 80);
      for (let i = 0; i < n; i++) {
        try {
          const t = (nodes[i].innerText || nodes[i].textContent || "").replace(/\s+/g, " ").trim();
          if (!t || t.length < 2) continue;
          if (t.length > 200) { parts.push(t.slice(0, 200)); total += 200; }
          else { parts.push(t); total += t.length; }
          if (total >= maxLen) break;
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    return parts.join(" · ").slice(0, maxLen);
  };

  NS.collectTitleAndHeadingClaimText = function () {
    const title = (document.title || "").trim();
    const headings = NS.collectHeadingText(4000);
    return `${title} ${headings}`.replace(/\s+/g, " ").trim();
  };

  NS.collectFooterCopyrightText = function () {
    const chunks = [];
    try {
      document.querySelectorAll(
        "footer, .footer, #footer, [class*='footer'], [class*='copyright'], [class*='Copyright'], "
        + "[id*='copyright'], [id*='Copyright'], .copy, .copy-right"
      ).forEach((el) => {
        try {
          const t = (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim();
          if (t.length >= 12 && t.length <= 800) chunks.push(t);
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
    if (!chunks.length) {
      try {
        const body = (document.body && (document.body.innerText || document.body.textContent)) || "";
        const tail = body.slice(-2500);
        const m = tail.match(/(?:Copyright|©|版权所有|All\s*Rights\s*Reserved)[^\n]{8,200}/gi);
        if (m) m.slice(0, 4).forEach((s) => chunks.push(s.replace(/\s+/g, " ").trim()));
      } catch { /* ignore */ }
    }
    return chunks.join(" · ");
  };

  NS.footerCopyrightMatchesPageHost = function () {
    try {
      const text = NS.collectFooterCopyrightText();
      if (!text || text.length < 12) return { match: false, text: "", hits: 0 };
      if (!/Copyright|©|版权所有|All\s*Rights\s*Reserved|ICP|互联网安全/i.test(text)) return { match: false, text, hits: 0 };
      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      const label = (host.split(".")[0] || "").replace(/-/g, "");
      const pageApex = NS.getRegistrableDomain(host) || host;
      const low = text.toLowerCase();
      let hits = 0;
      if (pageApex && low.includes(pageApex.toLowerCase())) hits += 2;
      if (host && low.includes(host)) hits += 2;
      if (label.length >= 2) {
        const re = new RegExp(`(?:^|[^0-9a-z])${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:[^0-9a-z]|$)`, "gi");
        hits += (text.match(re) || []).length;
      }
      const hasYear = /(?:19|20)\d{2}\s*[-–~至到]\s*(?:19|20)\d{2}|(?:©|Copyright).{0,12}(?:19|20)\d{2}/i.test(text);
      if (hits >= 1 && hasYear) hits += 1;
      if (hits >= 1 && /版权所有|All\s*Rights/i.test(text)) hits += 1;
      return { match: hits >= 2, text: text.slice(0, 240), hits };
    } catch {
      return { match: false, text: "", hits: 0 };
    }
  };

  const BRAND_TOKEN_STOP_RE = /^(download|desktop|windows|window|linux|android|macos|mac|ios|ipad|iphone|iphones|official|client|clients|software|remote|free|platform|platforms|version|versions|enterprise|server|servers|online|cloud|setup|install|installer|uninstaller|manager|cleaner|browser|chrome|https|http|full|high|speed|secure|native|utility|application|applications|product|products|service|services|update|updates|support|help|about|home|page|site|web|mobile|pc|win|x64|x86|arm64|amd64|store|market|center|centre|studio|suite|pro|lite|plus|max|mini|beta|alpha|stable|latest|release|releases|channel|build|builds)$/i;
  NS.BRAND_TOKEN_STOP_RE = BRAND_TOKEN_STOP_RE;

  const MKT_HOST_PREFIX = /^(?:get|aa|bb|cc|pc|app|free|soft|down|download|safe|vip|pro|gw|guanwang|official|my|the|best|new|top|go|use|try|win|cn|zh|en|www\d*|site|web|online|cloud|mega|super|ultra|real|true|pure|full|mini|lite|max|cool|hot|fast|quick|easy|smart|tech|info|blog|cdn|static|dl|dwn|pkg|pack|to|up|re|un|x|z)$/i;
  const MKT_HOST_SUFFIX = /^(?:app|desktop|client|soft|download|free|pro|vip|official|online|cloud|tool|tools|suite|plus|max|mini|lite|win|windows|setup|install|cn|hub|box|lab|labs|zone|world|center|portal|store|shop|home|site|web|net|pc|mac|ios|android|mobile|webapp|software|ai|bot|gpt|llm|desk)$/i;
  NS.MKT_HOST_PREFIX = MKT_HOST_PREFIX;
  NS.MKT_HOST_SUFFIX = MKT_HOST_SUFFIX;

  NS.extractLatinBrandTokens = function (text) {
    const out = [];
    const seen = new Set();
    (String(text || "").match(/[A-Za-z][a-zA-Z]{2,}/g) || []).forEach((b) => {
      const low = b.toLowerCase();
      if (low.length < 4 || low.length > 24) return;
      if (BRAND_TOKEN_STOP_RE.test(low)) return;
      if (seen.has(low)) return;
      seen.add(low);
      out.push(low);
    });
    return out;
  };

  NS.hostLabelIsPaddedBrand = function (label, brandToken) {
    const lab = String(label || "").toLowerCase().replace(/-/g, "");
    const br = String(brandToken || "").toLowerCase().replace(/-/g, "");
    if (!lab || !br || br.length < 4) return false;
    if (lab === br) return false;
    if (!lab.includes(br)) return false;
    if (lab.startsWith(br)) {
      const pad = lab.slice(br.length);
      if (pad.length >= 2 && pad.length <= 12 && MKT_HOST_SUFFIX.test(pad)) return true;
      if (pad.length >= 2 && pad.length <= 4 && /^(?:app|ai|bot|pro|vip|pc|cn|get|dl)$/i.test(pad)) return true;
    }
    if (lab.endsWith(br)) {
      const pad = lab.slice(0, lab.length - br.length);
      if (pad.length >= 2 && pad.length <= 12 && MKT_HOST_PREFIX.test(pad)) return true;
      if (pad.length >= 2 && pad.length <= 3 && /^(?:aa|bb|cc|pc|my|get|go|to|up|re|un|x|z)$/i.test(pad)) return true;
    }
    const idx = lab.indexOf(br);
    if (idx > 0 && idx + br.length < lab.length) {
      const left = lab.slice(0, idx);
      const right = lab.slice(idx + br.length);
      if (left.length <= 6 && right.length <= 8 && (MKT_HOST_PREFIX.test(left) || left.length <= 3) && (MKT_HOST_SUFFIX.test(right) || right.length <= 4)) return true;
    }
    return false;
  };

  NS.hostLabelComposedOfTitleTokens = function (label, tokens) {
    const lab = String(label || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (lab.length < 6) return false;
    const skip = /^(download|windows|linux|android|macos|official|client|software|remote|chrome|https|http|free|desk|home|page|site|high|full|platform|utility|application|secure|speed|version|enterprise|search|native|group|center|service|services|update|online|cloud|remove|unwanted|programs|program|easily|with|from|that|this|your|have|will|help|trace|traces|unwant|leftover|leftovers|products|product|privacy|policy|cookie|cookies)$/i;
    const toks = [...new Set((tokens || []).map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "")))]
      .filter((t) => t.length >= 3 && t.length <= 20 && !skip.test(t))
      .sort((a, b) => b.length - a.length);
    if (toks.length < 2) return false;
    for (let i = 0; i < toks.length; i++) {
      for (let j = 0; j < toks.length; j++) {
        if (i === j) continue;
        if (lab === toks[i] + toks[j]) return true;
      }
    }
    for (let i = 0; i < Math.min(toks.length, 10); i++) {
      for (let j = 0; j < Math.min(toks.length, 10); j++) {
        for (let k = 0; k < Math.min(toks.length, 10); k++) {
          if (i === j || j === k || i === k) continue;
          if (lab === toks[i] + toks[j] + toks[k]) return true;
        }
      }
    }
    function cover(s, parts) {
      if (!s) return parts >= 2;
      for (const t of toks) { if (s.startsWith(t) && cover(s.slice(t.length), parts + 1)) return true; }
      return false;
    }
    return cover(lab, 0);
  };

  NS.hostLabelIsHyphenatedBrandMirror = function (rawLabel, brandToken) {
    const raw = String(rawLabel || "").toLowerCase();
    const br = String(brandToken || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!raw || br.length < 4) return false;
    if (!/-/.test(raw)) return false;
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)+$/i.test(raw)) return false;
    const stripped = raw.replace(/-/g, "");
    return stripped === br && stripped.length >= 6;
  };

  NS.isBrandSquatHostMatch = function (shape) {
    return shape === "padded" || shape === "typo" || shape === "hyphen" || shape === "partial";
  };

  NS.editDistanceShort = function (a, b) {
    const s = String(a || "");
    const t = String(b || "");
    const m = s.length;
    const n = t.length;
    if (Math.abs(m - n) > 2) return 99;
    if (m === 0) return n;
    if (n === 0) return m;
    const row = new Array(n + 1);
    for (let j = 0; j <= n; j++) row[j] = j;
    for (let i = 1; i <= m; i++) {
      let prev = row[0];
      row[0] = i;
      for (let j = 1; j <= n; j++) {
        const tmp = row[j];
        const cost = s[i - 1] === t[j - 1] ? 0 : 1;
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
        prev = tmp;
      }
    }
    return row[n];
  };

  NS.hostLabelIsBrandTypo = function (hostLabel, brandToken) {
    const a = String(hostLabel || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const b = String(brandToken || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (a.length < 4 || b.length < 4 || a === b) return false;
    if (a.length > 18 || b.length > 18) return false;
    const d = NS.editDistanceShort(a, b);
    return d >= 1 && d <= 2;
  };

  NS.pickBrandTokenForHost = function (tokens, labelRaw) {
    const list = Array.isArray(tokens) ? tokens.filter((t) => t && !BRAND_TOKEN_STOP_RE.test(t)) : [];
    if (!list.length) return "";
    const raw = String(labelRaw || "").toLowerCase();
    const lab = raw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
    const scoreTok = (t) => {
      let s = 0;
      if (lab === t) s += 200;
      if (NS.hostLabelIsBrandTypo(lab, t)) s += 160;
      if (NS.hostLabelIsHyphenatedBrandMirror(raw, t)) s += 140;
      if (NS.hostLabelIsPaddedBrand(lab, t) || NS.hostLabelIsPaddedBrand(raw, t)) s += 120;
      if (lab.includes(t) && t.length >= 4) s += 40;
      if (t.includes(lab) && lab.length >= 4) s += 30;
      const idx = list.indexOf(t);
      if (idx >= 0) s += Math.max(0, 12 - idx);
      s += Math.min(t.length, 12);
      return s;
    };
    const aligned = list.filter((t) => scoreTok(t) >= 40);
    if (aligned.length) return aligned.sort((a, b) => scoreTok(b) - scoreTok(a))[0] || "";
    return list[0] || "";
  };

  NS.titleBrandVsHostSquatShape = function (title, label, brandToken) {
    const t = String(title || "");
    const rawLab = String(label || "").toLowerCase();
    const lab = rawLab.replace(/-/g, "");
    const br = String(brandToken || "").toLowerCase().replace(/-/g, "");
    if (!lab || lab.length < 4) return "";
    let brand = br && br.length >= 4 && !BRAND_TOKEN_STOP_RE.test(br) ? br : "";
    if (!brand || brand.length < 4) {
      const tokens = NS.extractLatinBrandTokens(t);
      brand = NS.pickBrandTokenForHost(tokens, rawLab) || "";
    }
    if (!brand || brand.length < 4) return "";
    if (NS.hostLabelIsHyphenatedBrandMirror(rawLab, brand)) return "hyphen";
    if (lab === brand) return "exact";
    if (NS.hostLabelIsBrandTypo(lab, brand)) return "typo";
    if (NS.hostLabelIsPaddedBrand(lab, brand) || NS.hostLabelIsPaddedBrand(rawLab, brand)) return "padded";
    if (lab.includes(brand) || brand.includes(lab)) return "partial";
    return "none";
  };

  NS.formatBrandTokenForDisplay = function (token) {
    const t = String(token || "").trim();
    if (!t) return "";
    if (/[一-鿿]/.test(t)) return t;
    if (/^[a-z0-9]+$/i.test(t) && t.length <= 24) return t.charAt(0).toUpperCase() + t.slice(1).toLowerCase();
    return t;
  };

  NS.collectPageClaimedBrandTokens = function () {
    const title = (document.title || "");
    const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(4000) : (document.querySelector("h1")?.textContent || "");
    const logo = (document.querySelector(".logo, [class*='logo']")?.textContent || "");
    const footer = typeof NS.collectFooterCopyrightText === "function" ? NS.collectFooterCopyrightText() : "";
    const brandSource = `${title} ${headings} ${logo} ${footer}`;
    const tokens = new Set();
    const latinBrands = brandSource.match(/\b[A-Z][a-zA-Z]{2,}(?:[A-Z][a-zA-Z]+)*\b/g) || [];
    latinBrands.forEach((b) => {
      const low = b.toLowerCase();
      if (low.length >= 4 && !/^(download|windows|linux|android|macos|official|client|software|remote|solution|copyright|rights|reserved)$/i.test(low)) tokens.add(low);
    });
    `${title} ${headings} ${footer}`.match(/[A-Za-z][a-zA-Z]{3,}/g)?.forEach((b) => {
      const low = b.toLowerCase();
      if (low.length >= 4 && !/^(download|windows|linux|android|macos|official|client|software|remote|solution|desktop|copyright|rights|reserved)$/i.test(low)) tokens.add(low);
    });
    (brandSource.match(/\d{3,4}/g) || []).forEach((d) => {
      if (d.length < 3) return;
      if (new RegExp(`${d}(?:官网|官方|安全|互联网|版权|\\.cn|\\.com|\\.net)`, "i").test(brandSource)) tokens.add(d);
    });
    try {
      const label = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      if (label.length >= 2 && brandSource.toLowerCase().includes(label)) tokens.add(label.replace(/-/g, ""));
    } catch { /* ignore */ }
    const cnGeneric = /^(下载|官方|软件|客户端|安全|杀毒|电脑|免费|最新|正版|中心|防护|管家|大师|官网|服务|企业|个人|产品|远程|桌面|控制|版权|所有|互联网)$/;
    const cn = brandSource.match(/([一-鿿]{2,8})(?=官网|官方|下载|客户端|软件|安全中心)/g) || [];
    cn.forEach((c) => { if (!cnGeneric.test(c)) tokens.add(c); });
    return { tokens, brandSource };
  };

  NS.packageFilenameSharesPageBrand = function (fileName, tokensOpt) {
    const fileNameLow = NS.normalizeFileName(fileName).toLowerCase();
    if (!fileNameLow) return false;
    const base = fileNameLow.replace(/\.[^.]+$/, "");
    const baseFlat = base.replace(/[-_.]/g, "");
    const tokens = tokensOpt || NS.collectPageClaimedBrandTokens().tokens;
    for (const t of tokens) {
      const tl = String(t).toLowerCase();
      if (/[一-鿿]/.test(t) && t.length >= 2 && base.includes(t)) return true;
      if (tl.length >= 4 && base.includes(tl)) return true;
      if (tl.length >= 4 && baseFlat.includes(tl.replace(/[-_.]/g, ""))) return true;
    }
    return false;
  };

  NS.packageMismatchesPageBrand = function (href) {
    const fileName = NS.getFilenameFromUrl(href).toLowerCase();
    if (!fileName || !NS.isPackageFileUrl(href)) return false;
    if (NS.isClearProductOrAndroidPackage(fileName) || NS.isClearProductOrAndroidPackage(href) || NS.looksLikeAndroidPackageIdName(fileName) || NS.isBenignShortInstallerName(fileName)) return false;
    const { tokens, brandSource } = NS.collectPageClaimedBrandTokens();
    if (tokens.size === 0) return false;
    if (NS.packageFilenameSharesPageBrand(fileName, tokens)) return false;
    const claimsOfficial = /官网|官方|官方下载|正式版|官方网站/i.test(brandSource);
    const hasDownloadCta = !!document.querySelector("a.btn-download, .btn-download, a[class*='download'], a[href*='.zip'], a[href*='.exe']") || NS.DOWNLOAD_TEXT.test(document.body?.innerText?.slice(0, 2000) || "");
    if (claimsOfficial && (hasDownloadCta || NS.isPackageFileUrl(href))) return true;
    if (hasDownloadCta && tokens.size >= 1 && /远程|桌面|客户端|下载|软件/i.test(brandSource)) return true;
    return false;
  };
})(window.SilverfoxContent ??= {});
