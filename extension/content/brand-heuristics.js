/**
 * 域名 / 品牌相关性工具：eTLD+1、品牌 token 提取、标题↔主机拼写仿冒判定。
 */
;(function (NS) {
  "use strict";

  /** 品牌/对比用：去 www、小写。勿用于 WHOIS/ICP 查询键（会把 www.gov.cn 变成 gov.cn）。 */
  NS.normalizeDomain = function (domain) {
    return String(domain || "").replace(/^www\./i, "").trim().toLowerCase();
  };

  /**
   * 情报查询用主机：小写、去尾点，**保留 www**。
   * www.gov.cn / court.gov.cn 必须原样可查；仅 gov.cn 才是公共后缀。
   */
  NS.normalizeHostForIntel = function (domain) {
    return String(domain || "").trim().toLowerCase().replace(/\.+$/g, "");
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

  /**
   * 公共后缀下的品牌根：
   * - sogou.com / shurufa.sogou.com / www.sogou.com → "sogou"（产品子域用 eTLD+1 左标，勿取 shurufa）
   * - wiki.archlinux.org → "archlinux"
   * - huorong-pc.com.cn → "huorongpc" 等
   */
  NS.brandRootKeyFromHost = function (hostOrApex) {
    const raw = NS.normalizeDomain(hostOrApex);
    if (!raw) return "";
    // 优先 eTLD+1 的品牌标签：shurufa.sogou.com → sogou（非产品词 shurufa）
    try {
      const apex = NS.getRegistrableDomain(raw) || raw;
      const apexLabel = (apex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (apexLabel.length >= 3
        && !/^(www|com|net|org|gov|edu|co|ac)$/i.test(apexLabel)) {
        // 主机是 apex 本身或其子域时，品牌根就是 apex 左标
        if (raw === apex || raw.endsWith(`.${apex}`)) {
          return apexLabel;
        }
      }
    } catch { /* fall through */ }
    let s = raw;
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
        && !/^(www|wiki|docs|doc|help|support|blog|news|forum|forums|bbs|cdn|static|img|image|media|assets|download|dl|api|m|mobile|mail|git|dev|test|beta|store|shop|cloud|shurufa|pinyin|ime|input)$/i.test(p)) {
        best = p;
      }
    }
    return String(best || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  };

  /**
   * 是否「自家品牌 apex 下的产品子域」：shurufa.sogou.com 相对 sogou.com。
   * 中文标题「搜狗…」+ 拉丁 apex sogou → 官方产品线，非仿冒。
   */
  NS.hostIsProductSubdomainOfBrandApex = function (hostOpt) {
    try {
      const host = NS.normalizeDomain(hostOpt || location.hostname);
      if (!host || host.split(".").length < 3) return false;
      const apex = NS.getRegistrableDomain(host);
      if (!apex || host === apex || !host.endsWith(`.${apex}`)) return false;
      const apexBrand = (apex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (apexBrand.length < 3) return false;
      // 子域标签
      const sub = host.slice(0, -(apex.length + 1));
      if (!sub || /^(www|m|mobile|wap)$/i.test(sub)) return false;
      return true;
    } catch { return false; }
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

  // chat/talk/team 等：图标字体 ligature / CMS 元数据 / 通用文案，不能当仿冒品牌主名
  // （否则 DingTalk→Chat；ca-aurora-template meta→Template；Inter 字体→Inter）
  const BRAND_TOKEN_STOP_RE = /^(download|desktop|windows|window|linux|android|macos|mac|ios|ipad|iphone|iphones|official|client|clients|software|remote|free|platform|platforms|version|versions|enterprise|server|servers|online|cloud|setup|install|installer|uninstaller|manager|cleaner|browser|chrome|https|http|full|high|speed|secure|security|native|utility|application|applications|product|products|service|services|update|updates|support|help|about|home|page|site|web|mobile|pc|win|x64|x86|arm64|amd64|store|market|center|centre|studio|suite|pro|lite|plus|max|mini|beta|alpha|stable|latest|release|releases|channel|build|builds|chat|talk|team|teams|live|work|workspace|power|powered|collab|collaboration|collaborate|group|office|email|mail|message|messages|inbox|docs|drive|meet|call|video|audio|share|sync|ai|bot|gpt|model|models|agent|agents|smart|inter|material|symbols|outlined|font|fonts|google|preload|module|assets|vendor|react|script|style|template|templates|theme|themes|layout|layouts|generator|schema|schemas|breadcrumb|breadcrumbs|listitem|website|webpage|summary|twitter|facebook|linkedin|youtube|instagram|weibo|wechat|cdnjs|cloudflare|jquery|bootstrap|webpack|babel|typescript|javascript|stylesheet|favicon|canonical|viewport|charset|aurora|cms|admin|index|content|section|sections|button|buttons|navbar|footer|header|banner|modal|popup|cookie|privacy|policy|terms|license|readme|changelog|status|careers|contact|example|examples|sample|samples|placeholder|lorem|ipsum|false|true|null|undefined|function|return|const|class|import|export)$/i;
  NS.BRAND_TOKEN_STOP_RE = BRAND_TOKEN_STOP_RE;

  // im/qq/wx/ca 等：im-todesk / ca-hongrong 一类「前缀-品牌」营销仿冒
  const MKT_HOST_PREFIX = /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|gw|guanwang|official|my|the|best|new|top|go|use|try|win|cn|zh|en|www\d*|site|web|online|cloud|mega|super|ultra|real|true|pure|full|mini|lite|max|cool|hot|fast|quick|easy|smart|tech|info|blog|cdn|static|dl|dwn|pkg|pack|to|up|re|un|im|qq|wx|wechat|chat|live|msg|mail|soft|x|z)$/i;
  const MKT_HOST_SUFFIX = /^(?:app|desktop|client|soft|download|free|pro|vip|official|online|cloud|tool|tools|suite|plus|max|mini|lite|win|windows|setup|install|cn|hub|box|lab|labs|zone|world|center|portal|store|shop|home|site|web|net|pc|mac|ios|android|mobile|webapp|software|ai|bot|gpt|llm|desk)$/i;
  // 品牌产品线域名后缀（非营销夹带）：pyas-security.com = PYAS 正站，绝不当「域名与品牌无关」
  // 勿把 soft/pc/download/free 放这里——那些仍属 MKT 夹带（huorong-pc / brand-download）
  const BRAND_PRODUCT_CATEGORY_SUFFIX = /^(?:security|antivirus|antimalware|av|secure|protection|defender|endpoint|tech|systems?|network|lab|labs|studio|group|hq)$/i;
  NS.MKT_HOST_PREFIX = MKT_HOST_PREFIX;
  NS.MKT_HOST_SUFFIX = MKT_HOST_SUFFIX;
  NS.BRAND_PRODUCT_CATEGORY_SUFFIX = BRAND_PRODUCT_CATEGORY_SUFFIX;

  /**
   * 主机是否「品牌 + 产品线品类」正站形态：pyas-security / brand-antivirus。
   * 与 im-todesk / brand-pc 营销夹带区分：品类尾缀表示产品线，非 squat。
   */
  NS.hostLabelIsBrandProductCategoryDomain = function (rawLabel, brandToken) {
    try {
      const raw = String(rawLabel || "").toLowerCase().replace(/^www\./, "");
      const br = String(brandToken || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!raw || br.length < 3 || br.length > 20) return false;
      if (BRAND_TOKEN_STOP_RE.test(br)) return false;
      // pyas-security / acme-antivirus
      if (/-/.test(raw)) {
        const parts = raw.split("-").filter(Boolean);
        if (parts.length === 2) {
          const a = parts[0].replace(/[^a-z0-9]/g, "");
          const b = parts[1].replace(/[^a-z0-9]/g, "");
          if (a === br && BRAND_PRODUCT_CATEGORY_SUFFIX.test(b)) return true;
          if (b === br && BRAND_PRODUCT_CATEGORY_SUFFIX.test(a)) return true;
        }
        // pyas-security-lab：首段品牌 + 其余全为品类词
        if (parts.length >= 2 && parts.length <= 3) {
          const head = parts[0].replace(/[^a-z0-9]/g, "");
          if (head === br && parts.slice(1).every((p) => BRAND_PRODUCT_CATEGORY_SUFFIX.test(p.replace(/[^a-z0-9]/g, "")))) {
            return true;
          }
        }
      }
      // pyassecurity（无连字符）
      const lab = raw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      if (lab.startsWith(br) && lab.length > br.length) {
        const pad = lab.slice(br.length);
        if (BRAND_PRODUCT_CATEGORY_SUFFIX.test(pad)) return true;
      }
      return false;
    } catch { return false; }
  };

  NS.extractLatinBrandTokens = function (text) {
    const out = [];
    const seen = new Set();
    // 保留 CamelCase 整词（DingTalk），并拆出可读子段时仍过滤 stop 词
    (String(text || "").match(/[A-Za-z][a-zA-Z]{2,}/g) || []).forEach((b) => {
      const low = b.toLowerCase();
      if (low.length < 4 || low.length > 24) return;
      if (BRAND_TOKEN_STOP_RE.test(low)) return;
      // 连字符 CMS 段：ca-aurora-template → 跳过整段里的 template/aurora
      if (/^(?:min|max|src|href|http|https|www|com|net|org|html|json|xml|css|svg|png|jpg|jpeg|webp|gif)$/i.test(low)) return;
      if (seen.has(low)) return;
      seen.add(low);
      out.push(low);
    });
    return out;
  };

  /**
   * 产品品牌身份字段（有序）：title → h1–h6 → description → keywords → footer → logo。
   * 不采 generator/template 等 CMS meta，也不扫全文 body。
   */
  NS.collectProductBrandIdentityFields = function () {
    const fields = { title: "", h1: "", headings: "", description: "", keywords: "", footer: "", logo: "", ogTitle: "", ogSite: "", author: "", schemaName: "" };
    try {
      fields.title = String(document.title || "").trim();
      try {
        fields.h1 = String(document.querySelector("h1")?.innerText || document.querySelector("h1")?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 200);
      } catch { fields.h1 = ""; }
      fields.headings = typeof NS.collectHeadingText === "function"
        ? NS.collectHeadingText(4000)
        : fields.h1;
      fields.description = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "").trim().slice(0, 500);
      // JSON-LD SoftwareApplication / Organization name（钉钉）
      try {
        const scripts = document.querySelectorAll('script[type="application/ld+json"]');
        for (let i = 0; i < Math.min(scripts.length, 8); i++) {
          try {
            const j = JSON.parse(scripts[i].textContent || "");
            const nodes = Array.isArray(j) ? j : (j["@graph"] ? j["@graph"] : [j]);
            for (const node of nodes) {
              if (!node || typeof node !== "object") continue;
              const typ = String(node["@type"] || "");
              if (/SoftwareApplication|Organization|WebSite|Product/i.test(typ) && node.name) {
                const nm = String(node.name).trim().slice(0, 40);
                if (nm && !fields.schemaName) fields.schemaName = nm;
              }
            }
          } catch { /* ignore one script */ }
        }
      } catch { /* ignore */ }
      let keywords = document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "";
      if (!keywords) {
        try {
          for (const m of Array.from(document.querySelectorAll("meta[content]"))) {
            const n = String(m.getAttribute("name") || m.getAttribute("property") || "").toLowerCase();
            // 仅 keywords，禁止 template/generator 等 name 误入
            if (n === "keywords" || n === "keyword") {
              keywords = m.getAttribute("content") || "";
              if (keywords) break;
            }
          }
        } catch { /* ignore */ }
      }
      fields.keywords = String(keywords || "").trim().slice(0, 600);
      fields.footer = typeof NS.collectFooterCopyrightText === "function" ? String(NS.collectFooterCopyrightText() || "").trim().slice(0, 500) : "";
      fields.ogTitle = String(document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "").trim().slice(0, 300);
      fields.ogSite = String(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "").trim().slice(0, 120);
      fields.author = String(document.querySelector('meta[name="author"]')?.getAttribute("content") || "").trim().slice(0, 120);
      try {
        fields.logo = Array.from(document.querySelectorAll("img[alt], .logo, [class*='logo'] img, .nav-logo-text, .logo-text"))
          .map((el) => (el.getAttribute && el.getAttribute("alt")) || (el.textContent || ""))
          .join(" ")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 300);
      } catch { /* ignore */ }
    } catch { /* ignore */ }
    return fields;
  };

  /** 身份字段拼接文本（供 claimsOfficial / 拉丁对齐）；顺序即优先级 */
  NS.productBrandIdentityBlob = function (fieldsOpt) {
    const f = fieldsOpt || NS.collectProductBrandIdentityFields();
    return [f.title, f.h1, f.schemaName, f.headings, f.ogTitle, f.ogSite, f.description, f.keywords, f.footer, f.author, f.logo]
      .filter(Boolean)
      .join(" ")
      .replace(/\s+/g, " ")
      .trim();
  };

  // 支持/提供/选择：文案动词，绝不当品牌（ToDesk 标题「支持Windows」曾误报仿冒「支持」）
  // 文章/专题/详情：SEO 模板标题前缀（文章-360安全卫士官网下载）绝不当仿冒品牌
  const CN_BRAND_GENERIC_RE = /^(下载|官方|软件|客户端|安全|杀毒|电脑|免费|最新|正版|安静|纯净|强悍|自主|研发|引擎|守护|卫士|浏览器|输入法|管家|个人|企业|首页|产品|服务|功能|系统|工具|中心|防护|大师|版本|电脑端|PC版|pc版|应用|市场|平台|商店|商城|办公|支持|提供|选择|适用|使用|安装|注册|登录|查看|帮助|关于|联系|立即|开始|前往|完美|主流|专业|安全高效|远程|控制|连接|设备|大小|更新|日志|常见|问题|公司|新闻|合作|招聘|要求|说明|步骤|须知|提示|注意|推荐|覆盖|获取|文章|专题|详情|目录|列表|正文|内容|导读|摘要|综述|百科|攻略|教程|评测|体验|介绍|说明文|软文)$/;
  // 单独品类词不能当品牌：QQ音乐 → 音乐；完整产品名须带 QQ/网易 等前缀
  const CN_BRAND_CATEGORY_ALONE_RE = /^(音乐|视频|地图|邮箱|云盘|网盘|直播|电台|小说|阅读|影视|动漫|游戏|支付|钱包|天气|新闻|资讯|购物|外卖|出行|打车|聊天|社交|存储|听书|漫画|文章)$/;
  // 页面章节 h2/h3 标题：系统要求 / 常见问题 / 更新日志 —— 绝不当仿冒品牌名
  const CN_SECTION_HEADING_RE = /^(?:系统|硬件|软件|运行|安装|配置|最低|推荐)?要求$|^(?:常见|热门|下载)?问题$|^(?:更新|版本)(?:日志|记录|历史)?$|^(?:安装|使用|入门|操作)?教程$|^(?:功能|产品|公司|品牌)?介绍$|^(?:使用|下载|安装)?帮助$|^(?:选择|支持)(?:您的)?平台$|^(?:关于我们|联系我们|隐私政策|用户协议|版权声明|友情链接|站点地图|更多资讯|最新动态|热门推荐|相关推荐|用户评价|客户评价|服务优势|核心功能|产品优势|安全下载|全平台覆盖|立即下载|下载中心|产品下载|版本更新|更新记录|桌面端要求|移动端要求|网页版|推荐浏览器|支持的?格式|快速上手|功能对比|为什么选择|对比其他)$/;
  // 功能卡片 h3：格式转换 / 图片美化 / 幻灯片播放 —— 能力描述，非产品品牌（曾误报仿冒「格式转换」）
  const CN_FEATURE_CAPABILITY_RE = /^(?:格式|图片|文件|文档|视频|音频|批量|在线)?(?:转换|互转|转码|压缩|解压|美化|编辑|裁剪|排序|播放|预览|打开|增强|浏览|解码|处理)$|^(?:闪电|极速|智能|批量|一键|自动)(?:打开|预览|转换|处理|增强|排序|播放|美化|浏览)?$|^(?:PDF|OCR)(?:预览|识别|转换|阅读|阅读器)?$|^(?:幻灯片|缩略图)(?:播放|预览)?$|^(?:内存占用|启动速度|格式支持|批量处理|大图无损|极速缩略)$/;
  // 标题/口语句首：这么牛逼 / 太强了 / 真香 —— 绝不当仿冒品牌（博客标题「这么牛逼，…西瓜杀毒」）
  const CN_SLANG_CLICKBAIT_RE = /^(?:这么|那么|太|好|真|超|巨|贼|特)(?:牛逼|牛B|牛b|厉害|强|香|炸|绝|猛|顶|赞|爽|坑|离谱|无语|尴尬|吓人|震撼|惊讶)?$|^(?:牛逼|厉害了|真香|绝了|炸了|离谱|无语|必看|干货|震惊|速看|收藏|转发|初中生|高中生|大学生|小学生)$/;
  // 拉丁后仅接动作/营销中文 → 不是产品名（ToDesk下载 / Windows官方）
  const CN_AFTER_LATIN_ACTION_RE = /^(下载|官方|官网|安全|杀毒|客户端|软件|中心|应用|平台|市场|免费|最新|正版|电脑|安装|注册|登录|卫士|浏览器|输入法|管家|电脑版|PC版|pc版)$/;
  // 钉钉应用 → 钉钉；火绒安全 → 火绒；钉钉双平台 → 钉钉（勿留「钉钉双」）
  const CN_BRAND_TRAIL_RE = /(?:双平台|全平台|多平台|跨平台|全端|双端|多端|应用|市场|平台|软件|客户端|官网|中心|下载站|下载中心|商店|商城|办公|安全|杀毒|卫士|浏览器|输入法|管家)$/;
  // 营销拼接残片：钉钉双 / 企业全（双平台/全平台 去尾后残留）
  const CN_BRAND_MARKETING_RESIDUAL_RE = /^[一-鿿]{2,4}[双全多]$/;
  // 数字+中文产品名：2345看图王 / 360安全卫士 / 115网盘（非纯中文长度 2–6）
  const CN_DIGIT_PRODUCT_RE = /^\d{2,6}[一-鿿]{2,6}$/;
  NS.CN_BRAND_GENERIC_RE = CN_BRAND_GENERIC_RE;
  NS.CN_SECTION_HEADING_RE = CN_SECTION_HEADING_RE;
  NS.CN_FEATURE_CAPABILITY_RE = CN_FEATURE_CAPABILITY_RE;
  NS.CN_SLANG_CLICKBAIT_RE = CN_SLANG_CLICKBAIT_RE;
  NS.CN_DIGIT_PRODUCT_RE = CN_DIGIT_PRODUCT_RE;

  /** 中文/混合产品名长度是否合理（纯中文 2–6；数字前缀 4–12；拉丁+中文 3–10） */
  NS.isPlausibleChineseBrandLength = function (token) {
    const s = String(token || "").trim();
    if (!s || s.length < 2) return false;
    if (CN_DIGIT_PRODUCT_RE.test(s)) return s.length >= 4 && s.length <= 12;
    if (/[A-Za-z]/.test(s) && /[一-鿿]/.test(s)) return s.length >= 3 && s.length <= 10;
    if (/^\d+$/.test(s)) return false;
    return s.length >= 2 && s.length <= 6;
  };

  /** 去掉中文品牌尾部品类/营销词（钉钉应用→钉钉；钉钉双平台→钉钉） */
  NS.trimChineseBrandTrail = function (token) {
    let t = String(token || "").trim();
    if (t.length < 2) return t;
    // 360安全卫士 / 2345看图王：安全/卫士 是产品本体，禁止当营销尾剥掉
    if (CN_DIGIT_PRODUCT_RE.test(t)) return t;
    let guard = 0;
    while (guard++ < 5 && t.length > 2 && CN_BRAND_TRAIL_RE.test(t)) {
      const next = t.replace(CN_BRAND_TRAIL_RE, "");
      if (next.length < 2 || next === t) break;
      t = next;
    }
    // 钉钉双 ← 双平台 剥平台后残留「双」
    if (CN_BRAND_MARKETING_RESIDUAL_RE.test(t) && t.length > 2) {
      const core = t.slice(0, -1);
      if (core.length >= 2 && !CN_BRAND_GENERIC_RE.test(core)) t = core;
    }
    return t;
  };

  /** 是否弱中文「品牌」（虚词/文案/章节标题/功能卡片/标题口语，应让位给钉钉/2345看图王等真产品名） */
  NS.isWeakChineseBrandToken = function (token) {
    const s = String(token || "").trim();
    if (!s) return true;
    if (CN_BRAND_GENERIC_RE.test(s)) return true;
    // 数字+中文产品名（2345看图王）非弱词
    if (CN_DIGIT_PRODUCT_RE.test(s)) return false;
    // 标题口语/标题党：这么牛逼 / 真香 / 必看 —— 绝不当仿冒「这么牛逼」官网
    if (!/[A-Za-z0-9]/.test(s) && CN_SLANG_CLICKBAIT_RE.test(s)) return true;
    // 章节 h2：系统要求 / 常见问题 / 更新日志 —— 绝不当仿冒「系统要求」官网
    if (!/[A-Za-z0-9]/.test(s) && CN_SECTION_HEADING_RE.test(s)) return true;
    // 功能卡片 h3：格式转换 / 图片美化 / PDF预览 —— 绝不当仿冒「格式转换」官网
    // （PDF预览 含拉丁字母，不能只在纯中文分支判弱）
    if (CN_FEATURE_CAPABILITY_RE.test(s)) return true;
    // 纯品类词（音乐/视频）无品牌前缀 → 不当展示名（应为 QQ音乐 等）
    if (!/[A-Za-z0-9]/.test(s) && CN_BRAND_CATEGORY_ALONE_RE.test(s)) return true;
    // 营销残片（钉钉双）不当展示名
    if (!/[A-Za-z0-9]/.test(s) && CN_BRAND_MARKETING_RESIDUAL_RE.test(s)) return true;
    // 含「要求/问题/日志/教程」且无品牌实体感的短语
    if (!/[A-Za-z0-9]/.test(s) && s.length <= 6 && /(?:要求|问题|日志|教程|说明|步骤|须知|帮助|介绍)$/.test(s)
      && !/^(?:火|钉|企|网|腾|阿|微|飞|企|金山|搜狗)/.test(s)) return true;
    // 能力动词尾（转换/预览/美化…）且无数字/拉丁前缀 → 功能名
    if (!/[A-Za-z0-9]/.test(s) && s.length <= 6 && /(?:转换|互转|转码|美化|排序|播放|预览|打开|增强|解码)$/.test(s)
      && !/^(?:火|钉|企|网|腾|阿|微|飞|金山|搜狗|看图)/.test(s)) return true;
    if (s.length <= 2 && /^(支持|提供|选择|使用|下载|安装|官方|免费|最新|查看|帮助|双|全|多)$/.test(s)) return true;
    return false;
  };

  /**
   * 从盗版/仿冒页表面字段直接取产品名（优先完整名，不截成公司前缀/营销残片）。
   * 例：title「钉钉双平台下载」→ 钉钉；keywords「钉钉下载」→ 钉钉；QQ音乐官网 → QQ音乐；
   * 「2345看图王 - 官方…」→ 2345看图王；「文章-360安全卫士官网下载」→ 360安全卫士（勿取「文章」）。
   */
  NS.pickChineseBrandFromPageSurface = function (raw) {
    try {
      const rawFull = String(raw || "").trim();
      if (!rawFull) return "";
      // 整段优先扫数字前缀产品（文章-360安全卫士官网 / SEO 模板）
      try {
        const digitHit = (rawFull.match(/(\d{2,6}[一-鿿]{2,8})/) || [])[1] || "";
        if (digitHit) {
          let ds = digitHit.replace(/(?:双平台|全平台|多平台|跨平台|应用|市场|平台|客户端|官网|中心|下载站|下载中心|商店|商城|官方下载|免费下载).*$/g, "").trim();
          if (!CN_DIGIT_PRODUCT_RE.test(ds) && CN_DIGIT_PRODUCT_RE.test(digitHit)) ds = digitHit;
          // 360安全卫士 = 3 位数字 + 4 字；放宽 [一-鿿]{2,8} 后再裁到 2–6 字中文段
          if (!CN_DIGIT_PRODUCT_RE.test(ds)) {
            const m2 = (digitHit.match(/^(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
            if (m2) ds = m2;
          }
          const lenOk = typeof NS.isPlausibleChineseBrandLength === "function"
            ? NS.isPlausibleChineseBrandLength(ds)
            : (ds.length >= 4 && ds.length <= 12);
          if (ds && /^\d{2,6}[一-鿿]{2,6}$/.test(ds) && lenOk) return ds;
        }
      } catch { /* fall through */ }

      let t = rawFull;
      // 标题党口语句首：这么牛逼，初中生…：西瓜杀毒 → 丢掉口语前缀
      t = t.replace(/^(?:这么|那么|太|好|真|超|巨)(?:牛逼|牛B|厉害|强|香|炸|绝|猛|顶|赞|爽|坑|离谱|无语)?[，,！!？?\s]+/i, "").trim();
      // SEO 模板前缀：文章-360安全卫士… / 专题：…（连字符与冒号都剥）
      t = t.replace(/^(?:震惊|速看|必看|干货|转发|收藏|文章|专题|详情|导读|正文|内容)[-–—|:：·\s，,！!]+/i, "").trim();
      // 逗号分段：首段若是口语/弱词则顺延（keywords「这么牛逼，…西瓜杀毒」）
      const commaParts = t.split(/[,，、|｜]/).map((p) => p.trim()).filter(Boolean);
      if (commaParts.length > 1) {
        let pickedPart = commaParts[0];
        for (const part of commaParts) {
          const head = part.split(/\s*[-–—|:·：]\s*/)[0].trim();
          const pureHead = (head.match(/^([一-鿿]{2,6})/) || [])[1] || "";
          if (/\d{2,6}[一-鿿]{2,}/.test(part)) { pickedPart = part; break; }
          if (pureHead && (CN_SLANG_CLICKBAIT_RE.test(pureHead) || NS.isWeakChineseBrandToken(pureHead) || CN_BRAND_GENERIC_RE.test(pureHead))) continue;
          if (CN_SLANG_CLICKBAIT_RE.test(head) || (head.length <= 6 && NS.isWeakChineseBrandToken(head))) continue;
          pickedPart = part;
          break;
        }
        t = pickedPart;
      } else {
        t = (commaParts[0] || t).trim();
      }
      // 中文冒号后常是产品名：…杀毒软件：西瓜杀毒 Xdows → 优先冒号后
      if (/[：:]/.test(t)) {
        const afterColon = t.split(/[：:]/).slice(1).join("：").trim();
        if (afterColon && afterColon.length >= 2) {
          const afterHit = afterColon.split(/\s*[-–—|]\s*/)[0].trim();
          const probe = afterHit.replace(/^(?:开源|免费)?/, "").trim();
          const probePure = (probe.match(/^(\d{2,6}[一-鿿]{2,6})/) || [])[1]
            || (probe.match(/^([一-鿿]{2,6})/) || [])[1]
            || (probe.match(/^([A-Za-z][A-Za-z0-9]{0,12})/) || [])[1]
            || "";
          if (probePure && !NS.isWeakChineseBrandToken(probePure) && !CN_SLANG_CLICKBAIT_RE.test(probePure)
            && !CN_BRAND_GENERIC_RE.test(probePure)) {
            t = afterHit;
          }
        }
      }
      // 破折号分段：首段弱词（文章-360…）则取含产品名的后续段
      const dashParts = t.split(/\s*[-–—|·]\s*/).map((p) => p.trim()).filter(Boolean);
      if (dashParts.length > 1) {
        let chosen = dashParts[0];
        for (const part of dashParts) {
          if (/\d{2,6}[一-鿿]{2,}/.test(part)) { chosen = part; break; }
          const head = (part.match(/^([一-鿿]{2,6})/) || [])[1] || "";
          if (head && (CN_BRAND_GENERIC_RE.test(head) || NS.isWeakChineseBrandToken(head) || CN_SLANG_CLICKBAIT_RE.test(head))) continue;
          if (head && head.length >= 2) { chosen = part; break; }
          if (!CN_BRAND_GENERIC_RE.test(part) && !NS.isWeakChineseBrandToken(part)) { chosen = part; break; }
        }
        t = chosen;
      } else {
        t = dashParts[0] || t;
      }
      // 先砍双平台/全平台等营销块，再砍官方下载（钉钉双平台下载 → 钉钉）
      t = t.replace(/(?:双平台|全平台|多平台|跨平台|全端|双端|多端).*$/i, "").trim();
      t = t.replace(/(?:官方客户端|官方正版|官方网站|官方下载|官方全平台|客户端下载|免费下载|立即下载|电脑版|手机版|下载中心).*$/i, "").trim();
      // 官网下载 整块（360安全卫士官网下载）
      t = t.replace(/(?:官网下载|官方下载|官网|官方|下载|客户端|软件)$/g, "").trim();
      if (!t) return "";
      // 拉丁+中文：QQ音乐
      const mixed = (t.match(/^([A-Za-z][A-Za-z0-9]{0,7}[一-鿿]{1,5})/) || [])[1] || "";
      if (mixed) {
        const s = NS.trimChineseBrandTrail(mixed);
        if (s && !NS.isWeakChineseBrandToken(s)) {
          const cnOnly = s.replace(/[A-Za-z0-9]+/g, "");
          if (cnOnly && !CN_AFTER_LATIN_ACTION_RE.test(cnOnly) && !CN_BRAND_GENERIC_RE.test(cnOnly)) return s;
        }
      }
      // 数字+中文产品：2345看图王 / 360安全卫士 / 115网盘（须先于纯中文；勿用 trim 剥掉「安全/卫士」）
      const digitCn = (t.match(/^(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
      if (digitCn) {
        // 仅剥营销尾，保留产品本体（360安全卫士 的 安全/卫士 不是虚词尾）
        let s = digitCn.replace(/(?:双平台|全平台|多平台|跨平台|应用|市场|平台|客户端|官网|中心|下载站|下载中心|商店|商城)$/g, "").trim();
        if (!CN_DIGIT_PRODUCT_RE.test(s)) s = digitCn;
        const lenOk = typeof NS.isPlausibleChineseBrandLength === "function"
          ? NS.isPlausibleChineseBrandLength(s)
          : (s.length >= 4 && s.length <= 12);
        if (s && CN_DIGIT_PRODUCT_RE.test(s) && lenOk && !NS.isWeakChineseBrandToken(s)) {
          return s;
        }
      }
      // 纯中文完整产品：网易云音乐 / 钉钉 / 火绒（绝不当「文章」「格式转换」）
      const pure = (t.match(/^([一-鿿]{2,6})/) || [])[1] || "";
      if (!pure) return "";
      const s = NS.trimChineseBrandTrail(pure);
      if (!s || s.length < 2 || s.length > 6) return "";
      if (CN_BRAND_GENERIC_RE.test(s) || NS.isWeakChineseBrandToken(s) || CN_SLANG_CLICKBAIT_RE.test(s)) return "";
      return s;
    } catch { return ""; }
  };

  /**
   * 综合 title / h1–h6 / description / keywords / footer / og 选取中文产品名（盗版页多字段共识）。
   * keywords 短词「钉钉下载」与 h1「钉钉官方下载中心」权重大于标题营销拼接「钉钉双平台下载」。
   */
  NS.pickChineseBrandFromIdentityConsensus = function (fieldsOpt) {
    try {
      const fields = fieldsOpt || (typeof NS.collectProductBrandIdentityFields === "function"
        ? NS.collectProductBrandIdentityFields()
        : {});
      const score = new Map(); // brand -> score
      const bump = (brand, w, src) => {
        let s = String(brand || "").trim();
        // 数字前缀产品保留安全/卫士等本体；其余走营销尾裁剪
        if (CN_DIGIT_PRODUCT_RE.test(s)) {
          const cut = s.replace(/(?:双平台|全平台|多平台|跨平台|应用|市场|平台|客户端|官网|中心|下载站|下载中心|商店|商城)$/g, "").trim();
          if (CN_DIGIT_PRODUCT_RE.test(cut)) s = cut;
        } else {
          s = NS.trimChineseBrandTrail(s);
        }
        if (!s || s.length < 2) return;
        if (typeof NS.isPlausibleChineseBrandLength === "function"
          ? !NS.isPlausibleChineseBrandLength(s)
          : (s.length > 6 && !CN_DIGIT_PRODUCT_RE.test(s))) return;
        if (CN_BRAND_GENERIC_RE.test(s) || NS.isWeakChineseBrandToken(s)) return;
        if (CN_FEATURE_CAPABILITY_RE.test(s) || CN_SECTION_HEADING_RE.test(s)) return;
        const prev = score.get(s) || { score: 0, source: src };
        const next = prev.score + w;
        score.set(s, { score: next, source: prev.score >= next ? prev.source : src });
      };
      const feed = (raw, baseW, src) => {
        const text = String(raw || "").trim();
        if (!text) return;
        // 逗号 / 中点切分：keywords 与 h1·h2·h3 各段单独取词
        const parts = text.split(/[,，、|｜·•]+/);
        parts.forEach((part, i) => {
          const p = part.trim();
          if (!p || p.length > 48) return;
          const hit = NS.pickChineseBrandFromPageSurface(p);
          if (hit) bump(hit, baseW + (p.length <= 12 ? 12 : 4) - Math.min(i, 4), src);
          // 「钉钉下载」「钉钉官方」整段
          const m = p.match(/^([一-鿿]{2,6})(?:安全|杀毒|官网|官方|下载|软件|客户端|应用|市场|平台)?$/);
          if (m) bump(m[1], baseW + 8, src);
          // 「2345看图王」「2345看图王下载」
          const dm = p.match(/^(\d{2,6}[一-鿿]{2,6})(?:安全|杀毒|官网|官方|下载|软件|客户端|应用|市场|平台)?$/);
          if (dm) bump(dm[1], baseW + 14, src);
        });
        const whole = NS.pickChineseBrandFromPageSurface(text);
        if (whole) bump(whole, baseW, src);
      };
      // 权重：title/og/schema 为主；keywords 降权（SEO 虚词「文章」绝不可压过 title 产品名）
      feed(fields.schemaName, 50, "schema");
      feed(fields.title, 48, "title");
      feed(fields.ogSite, 40, "ogSite");
      feed(fields.ogTitle, 36, "ogTitle");
      feed(fields.h1, 34, "h1");
      feed(fields.description, 30, "description");
      feed(fields.keywords, 22, "keywords");
      feed(fields.footer, 24, "footer");
      feed(fields.logo, 14, "logo");
      // h1 单独再扫；h2–h6 仅低权重且过滤章节/功能卡标题
      try {
        const nodes = document.querySelectorAll("h1, h2, h3, h4, h5, h6");
        const lim = Math.min(nodes.length, 24);
        for (let i = 0; i < lim; i++) {
          const tag = (nodes[i].tagName || "H2").toUpperCase();
          const ht = String(nodes[i].innerText || nodes[i].textContent || "").replace(/\s+/g, " ").trim().slice(0, 120);
          if (!ht) continue;
          // 整段是章节名/功能卡则跳过（系统要求 / 格式转换）
          if (CN_SECTION_HEADING_RE.test(ht) || CN_FEATURE_CAPABILITY_RE.test(ht) || NS.isWeakChineseBrandToken(ht)) continue;
          // h3+ 功能区权重大幅压低，避免压过 title/h1 产品名
          const tw = tag === "H1" ? 30 : tag === "H2" ? 6 : 2;
          feed(ht, tw, tag.toLowerCase());
        }
      } catch { /* ignore */ }
      // headings 合集仅作弱补充（已过滤章节/功能卡）
      if (fields.headings) {
        String(fields.headings).split(/\s*[·•]\s*/).forEach((part) => {
          const p = part.trim();
          if (!p || CN_SECTION_HEADING_RE.test(p) || CN_FEATURE_CAPABILITY_RE.test(p) || NS.isWeakChineseBrandToken(p)) return;
          feed(p, 4, "headings");
        });
      }

      let best = ""; let bestS = 0;
      for (const [c, info] of score) {
        let s = info.score;
        // 短核心且被更长营销残片包含时：钉钉 压过 钉钉双
        for (const [other, oinfo] of score) {
          if (other === c) continue;
          if (other.startsWith(c) && other.length > c.length && other.length - c.length <= 2) {
            s += 25; // 自己是更干净核心
          }
          if (c.startsWith(other) && c.length > other.length && c.length - other.length <= 2) {
            s -= 30; // 自己是残片加长
          }
        }
        // 数字前缀产品名（2345看图王）显著加分，压过功能/品类残片
        if (CN_DIGIT_PRODUCT_RE.test(c)) s += 22;
        // keywords 短词略偏好 2–3 字产品名（钉钉/火绒）；数字前缀不吃这套
        if (!CN_DIGIT_PRODUCT_RE.test(c) && c.length >= 2 && c.length <= 3) s += 6;
        // 同分时偏好更长完整产品名（2345看图王 > 看图）
        if (s > bestS || (s === bestS && c.length > best.length)
          || (s === bestS && c.length === best.length && CN_DIGIT_PRODUCT_RE.test(c) && !CN_DIGIT_PRODUCT_RE.test(best))) {
          bestS = s;
          best = c;
        }
      }
      if (!best) return "";
      if (CN_DIGIT_PRODUCT_RE.test(best)) return best;
      return NS.trimChineseBrandTrail(best) || best;
    } catch { return ""; }
  };

  /** 从单段文本抽中文产品品牌候选（火绒安全 → 火绒；钉钉应用下载 → 钉钉；QQ音乐官网 → QQ音乐；2345看图王） */
  NS.extractChineseProductBrandCandidates = function (text) {
    const out = [];
    const seen = new Set();
    const add = (c) => {
      let s = String(c || "").trim();
      if (s.length < 2 || s.length > 12) return;
      // 数字前缀产品不剥安全/卫士
      if (!CN_DIGIT_PRODUCT_RE.test(s)) s = NS.trimChineseBrandTrail(s);
      // 纯中文 2–6 字；数字+中文（2345看图王）4–12；拉丁+中文（QQ音乐）3–10
      const digitCn = CN_DIGIT_PRODUCT_RE.test(s);
      const mixed = /[A-Za-z]/.test(s) && /[一-鿿]/.test(s);
      if (digitCn) {
        if (s.length < 4 || s.length > 12) return;
      } else if (mixed) {
        if (s.length < 3 || s.length > 10) return;
        const cnOnly = s.replace(/[A-Za-z0-9]+/g, "");
        if (!cnOnly || cnOnly.length < 1) return;
        // ToDesk下载 / Windows官方：拉丁后仅营销动作词，不是 QQ音乐 类产品名
        if (CN_AFTER_LATIN_ACTION_RE.test(cnOnly) || CN_BRAND_GENERIC_RE.test(cnOnly)) return;
      } else {
        if (s.length < 2 || s.length > 6) return;
      }
      if (CN_BRAND_GENERIC_RE.test(s) || NS.isWeakChineseBrandToken(s)) return;
      if (CN_FEATURE_CAPABILITY_RE.test(s) || CN_SECTION_HEADING_RE.test(s)) return;
      if (seen.has(s)) return;
      seen.add(s);
      out.push(s);
    };
    const t = String(text || "");
    // 页面完整产品名优先入候选（网易云音乐 / 2345看图王 整词）
    if (typeof NS.pickChineseBrandFromPageSurface === "function") {
      const surface = NS.pickChineseBrandFromPageSurface(t);
      if (surface) add(surface);
    }
    // 数字前缀产品：2345看图王官网 / 360安全…
    (t.match(/(\d{2,6}[一-鿿]{2,6})(?=安全|杀毒|官网|官方|下载|客户端|软件|卫士|浏览器|输入法|管家|电脑版|PC版|pc版|免费|应用|市场|平台|[-–—|:·｜\s,]|$)/g) || []).forEach(add);
    // 拉丁前缀 + 中文产品：QQ音乐官网 / QQ音乐听…（须 lookahead 落在品类/分隔/句末，避免 ToDesk下 残片）
    (t.match(/([A-Za-z][A-Za-z0-9]{0,7}[一-鿿]{1,5})(?=安全|杀毒|官网|官方|下载|客户端|软件|卫士|浏览器|输入法|管家|电脑版|PC版|pc版|免费|应用|市场|双平台|全平台|多平台|平台|听|体验|[-–—|:·｜\s,]|$)/g) || []).forEach(add);
    // 钉钉双平台 / 钉钉应用下载 / 火绒安全官网：先匹配双平台等，避免截成「钉钉双」
    (t.match(/([一-鿿]{2,6})(?=双平台|全平台|多平台|跨平台|安全|杀毒|官网|官方|下载|客户端|软件|卫士|浏览器|输入法|管家|电脑版|PC版|pc版|免费|应用|市场|平台)/g) || []).forEach(add);
    // 关键词/竖线切分；禁止「支持Windows」「提供Windows」
    t.split(/[,，、|｜]+/).forEach((part) => {
      const p = part.trim();
      if (p.length < 2 || p.length > 24) return;
      // 中文后紧跟拉丁（支持Windows / 适用macOS）→ 整段是功能句，不当品牌
      if (/^[一-鿿]{1,6}[A-Za-z]/.test(p)) return;
      if (/[/／]/.test(p) && /^[一-鿿]{1,6}/.test(p)) return; // 支持Windows/Mac/…
      // 2345看图王 / 2345看图王下载
      const digitPart = p.match(/^(\d{2,6}[一-鿿]{2,6})(?:安全|杀毒|官网|官方|下载|软件|卫士|电脑|应用|市场|平台|PC|pc)?$/);
      if (digitPart) add(digitPart[1]);
      // QQ音乐官网 / QQ音乐
      const mixedPart = p.match(/^([A-Za-z][A-Za-z0-9]{0,7}[一-鿿]{1,5})(?:安全|杀毒|官网|官方|下载|软件|卫士|电脑|应用|市场|平台|PC|pc)?$/);
      if (mixedPart) add(mixedPart[1]);
      const m = p.match(/^([一-鿿]{2,6})(?:安全|杀毒|官网|官方|下载|软件|卫士|电脑|应用|市场|平台|PC|pc)?$/);
      if (m) add(m[1]);
      // 整词纯中文产品（网易云音乐 5 字）
      if (/^[一-鿿]{2,6}$/.test(p) && !CN_BRAND_GENERIC_RE.test(p)) add(p);
      if (CN_DIGIT_PRODUCT_RE.test(p)) add(p);
    });
    // 标题段首：优先完整产品名（2345看图王 / 网易云音乐 / QQ音乐）
    // 「文章-360安全卫士官网下载」：首段弱词则顺延后续段，勿把「文章」当品牌
    const headSegs = t.split(/\s*[-–—|:·｜]\s*/).map((p) => p.trim()).filter(Boolean);
    let headTrim = headSegs[0] || t.trim();
    for (const seg of headSegs) {
      const pure = (seg.match(/^([一-鿿]{2,6})/) || [])[1] || "";
      if (/\d{2,6}[一-鿿]{2,}/.test(seg)) { headTrim = seg; break; }
      if (pure && (CN_BRAND_GENERIC_RE.test(pure) || NS.isWeakChineseBrandToken(pure) || CN_SLANG_CLICKBAIT_RE.test(pure))) continue;
      headTrim = seg;
      break;
    }
    if (/^\d{2,6}[一-鿿]/.test(headTrim)) {
      const dFull = (headTrim.match(/^\d{2,6}[一-鿿]{2,6}/) || [])[0];
      if (dFull) add(dFull);
    } else if (/^[一-鿿]/.test(headTrim)) {
      // 段首连续中文 2–6 字 = 页面宣称产品名
      const hFull = (headTrim.match(/^[一-鿿]{2,6}/) || [])[0];
      if (hFull) add(hFull);
    } else {
      // 仅当拉丁后紧跟产品中文且后面是官网/分隔（非 ToDesk下载）
      const mixedHead = (headTrim.match(/^([A-Za-z][A-Za-z0-9]{0,7}[一-鿿]{1,5})(?=安全|杀毒|官网|官方|下载|客户端|软件|[-–—|:·｜\s]|$)/) || [])[1];
      if (mixedHead) add(mixedHead);
    }
    return out;
  };

  /**
   * 产品关键词选主品牌：只从 title / h* / description / keywords / footer / logo 选。
   * 返回 { displayBrand, brandToken, source, latinToken, score }
   * displayBrand 优先中文；brandToken 供主机对齐（拉丁或中文）。
   */
  NS.pickProductBrandFromIdentity = function (labelRawOpt) {
    try {
      const fields = NS.collectProductBrandIdentityFields();
      const labelRaw = String(labelRawOpt != null ? labelRawOpt : ((location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || ""));
      // 字段权重：title/og/schema 为主；keywords 降权（避免 SEO「文章」压过 360安全卫士）
      const tiers = [
        { key: "title", text: fields.title, w: 110 },
        { key: "schemaName", text: fields.schemaName, w: 115 },
        { key: "ogSite", text: fields.ogSite, w: 95 },
        { key: "ogTitle", text: fields.ogTitle, w: 88 },
        { key: "h1", text: fields.h1, w: 85 },
        { key: "description", text: fields.description, w: 78 },
        { key: "keywords", text: fields.keywords, w: 55 },
        { key: "footer", text: fields.footer, w: 55 },
        { key: "headings", text: fields.headings, w: 35 },
        { key: "author", text: fields.author, w: 40 },
        { key: "logo", text: fields.logo, w: 30 }
      ];
      const cnScore = new Map(); // brand -> {score, source}
      const latinScore = new Map();

      for (const tier of tiers) {
        const text = String(tier.text || "").trim();
        if (!text) continue;
        NS.extractChineseProductBrandCandidates(text).forEach((c, idx) => {
          const prev = cnScore.get(c) || { score: 0, source: tier.key };
          const add = tier.w - Math.min(idx, 5) * 2;
          // keywords 里重复出现加权（火绒安全,火绒安全下载…）
          const repeats = (text.split(c).length - 1);
          const next = prev.score + add + Math.min(repeats, 6) * 3;
          cnScore.set(c, { score: next, source: prev.score >= next ? prev.source : tier.key });
        });
        NS.extractLatinBrandTokens(text).forEach((low, idx) => {
          if (BRAND_TOKEN_STOP_RE.test(low)) return;
          const prev = latinScore.get(low) || { score: 0, source: tier.key };
          let add = tier.w - Math.min(idx, 5) * 3;
          // 主机对齐加分（huorong / hongrong）
          if (labelRaw) {
            const lab = labelRaw.replace(/-/g, "");
            if (lab === low) add += 80;
            else if (typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lab, low)) add += 50;
            else if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, low)) add += 55;
            else if (typeof NS.hostLabelIsBrandTypo === "function" && NS.hostLabelIsBrandTypo(lab, low)) add += 40;
            else if (lab.includes(low) && low.length >= 5) add += 25;
          }
          // 页脚 Copyright 里的 Huorong 略加分，但低于 title 中文
          if (tier.key === "footer") add += 5;
          const next = prev.score + add;
          latinScore.set(low, { score: next, source: prev.score >= next ? prev.source : tier.key });
        });
      }

      // 盗版页多字段共识：keywords + title + description + footer（钉钉 非 钉钉双）
      let surfaceBrand = "";
      if (typeof NS.pickChineseBrandFromIdentityConsensus === "function") {
        surfaceBrand = NS.pickChineseBrandFromIdentityConsensus(fields) || "";
      }
      if (!surfaceBrand && typeof NS.pickChineseBrandFromPageSurface === "function") {
        // title/og/description 优先于 keywords（keywords 常为 SEO 虚词「文章」）
        const surfaceSources = [fields.schemaName, fields.title, fields.ogSite, fields.ogTitle, fields.h1, fields.description, fields.keywords, fields.footer, fields.logo];
        for (const src of surfaceSources) {
          const hit = NS.pickChineseBrandFromPageSurface(src);
          if (hit && !NS.isWeakChineseBrandToken(hit)) { surfaceBrand = hit; break; }
        }
      }
      if (surfaceBrand) {
        const prev = cnScore.get(surfaceBrand) || { score: 0, source: "surface" };
        cnScore.set(surfaceBrand, { score: prev.score + 140, source: prev.source === "surface" ? "surface" : prev.source });
      }

      let bestCn = ""; let bestCnScore = 0; let cnSource = "";
      for (const [c, info] of cnScore) {
        const digitCn = CN_DIGIT_PRODUCT_RE.test(c);
        const mixed = /[A-Za-z]/.test(c) && /[一-鿿]/.test(c);
        // 数字前缀产品（2345看图王）/ 拉丁+中文（QQ音乐）优先；纯中文偏好完整产品（网易云音乐 > 网易）
        const lenBonus = digitCn ? 24
          : mixed ? 20
          : (c.length >= 4 ? 16 : c.length === 3 ? 10 : 0);
        let prefixBoost = 0;
        // 与表面取词一致 → 再加分
        if (surfaceBrand && c === surfaceBrand) prefixBoost += 40;
        for (const [other, oinfo] of cnScore) {
          if (other === c) continue;
          const otherMixed = /[A-Za-z0-9]/.test(other) && /[一-鿿]/.test(other);
          // QQ音乐 压过裸「音乐」：纯品类是混合品牌的中文后缀
          if (mixed && !otherMixed) {
            const cCn = c.replace(/[A-Za-z0-9]+/g, "");
            if (cCn === other || c.endsWith(other)) prefixBoost += 30;
          }
          if (!mixed && otherMixed) {
            const oCn = other.replace(/[A-Za-z0-9]+/g, "");
            if (oCn === c || other.endsWith(c)) prefixBoost -= 40;
          }
          // 纯中文：完整产品名压过公司前缀（网易云音乐 > 网易）；
          // 仅当长尾是短名+品类词（钉钉应用→已 trim）时才偏好短核心
          if (!mixed && !otherMixed) {
            if (c.startsWith(other) && other.length >= 2 && c.length > other.length) {
              if (other.length <= 2 && c.length >= 4) {
                prefixBoost += 35; // 网易云音乐 压过 网易
              } else if (c.length - other.length <= 2 && oinfo.score + 4 >= info.score) {
                prefixBoost -= 20; // 略长的品类拼接仍让短核心
              }
            }
            if (other.startsWith(c) && c.length >= 2 && other.length > c.length) {
              if (c.length <= 2 && other.length >= 4) {
                prefixBoost -= 35; // 网易 让位 网易云音乐
              } else if (other.length - c.length <= 2) {
                prefixBoost += 8; // 略短核心仍可
              }
            }
          }
        }
        const s = info.score + lenBonus + prefixBoost;
        // 同分时：数字前缀/混合品牌 > 更长完整产品名 > 表面取词
        const bestDigit = CN_DIGIT_PRODUCT_RE.test(bestCn);
        const bestMixed = /[A-Za-z]/.test(bestCn) && /[一-鿿]/.test(bestCn);
        const better = s > bestCnScore
          || (s === bestCnScore && digitCn && !bestDigit)
          || (s === bestCnScore && mixed && !bestMixed && !bestDigit)
          || (s === bestCnScore && !mixed && !digitCn && !bestMixed && !bestDigit && c.length > bestCn.length)
          || (s === bestCnScore && surfaceBrand && c === surfaceBrand);
        if (better) {
          bestCnScore = s;
          bestCn = c;
          cnSource = info.source;
        }
      }
      if (bestCn && !CN_DIGIT_PRODUCT_RE.test(bestCn)) bestCn = NS.trimChineseBrandTrail(bestCn) || bestCn;
      if (surfaceBrand && !CN_DIGIT_PRODUCT_RE.test(surfaceBrand)) surfaceBrand = NS.trimChineseBrandTrail(surfaceBrand) || surfaceBrand;
      // 共识/表面取词：更完整产品名覆盖（网易 → 网易云音乐）；营销残片（钉钉双）不覆盖钉钉
      if (surfaceBrand && !NS.isWeakChineseBrandToken(surfaceBrand)) {
        if (!bestCn || NS.isWeakChineseBrandToken(bestCn)) {
          bestCn = surfaceBrand;
          cnSource = "surface";
        } else if (surfaceBrand.length > bestCn.length && surfaceBrand.startsWith(bestCn)
          && !CN_BRAND_MARKETING_RESIDUAL_RE.test(surfaceBrand)) {
          bestCn = surfaceBrand;
          cnSource = cnSource || "surface";
        } else if (bestCn.startsWith(surfaceBrand) && bestCn.length > surfaceBrand.length
          && (bestCn.length - surfaceBrand.length <= 2 || CN_BRAND_MARKETING_RESIDUAL_RE.test(bestCn))) {
          // 钉钉双 → 钉钉
          bestCn = surfaceBrand;
          cnSource = "surface";
        }
      }

      let bestLatin = ""; let bestLatinScore = 0; let latinSource = "";
      for (const [low, info] of latinScore) {
        if (info.score > bestLatinScore || (info.score === bestLatinScore && low.length > bestLatin.length)) {
          bestLatinScore = info.score;
          bestLatin = low;
          latinSource = info.source;
        }
      }

      // 标题段首拉丁主品牌（ToDesk下载中心 - …）强加权，压过虚词「支持」
      const titlePrimaryLatin = typeof NS.pickPrimaryTitleBrandToken === "function"
        ? (NS.pickPrimaryTitleBrandToken(fields.title || "", labelRaw) || "")
        : "";
      if (titlePrimaryLatin && titlePrimaryLatin.length >= 4 && !BRAND_TOKEN_STOP_RE.test(titlePrimaryLatin)) {
        const prev = latinScore.get(titlePrimaryLatin) || { score: 0, source: "title" };
        const boosted = Math.max(prev.score, 100) + 90;
        latinScore.set(titlePrimaryLatin, { score: boosted, source: "title-lead" });
        if (boosted > bestLatinScore || (boosted === bestLatinScore && titlePrimaryLatin.length >= bestLatin.length)) {
          bestLatinScore = boosted;
          bestLatin = titlePrimaryLatin;
          latinSource = "title-lead";
        }
      }

      // 展示：真中文产品名优先；虚词「支持」等让位给 ToDesk 等标题拉丁主名
      const cnWeak = !bestCn || NS.isWeakChineseBrandToken(bestCn);
      let displayBrand = "";
      if (!cnWeak && bestCn && bestCnScore + 15 >= bestLatinScore) {
        displayBrand = bestCn;
      } else if (bestLatin) {
        displayBrand = NS.formatBrandTokenForDisplay(bestLatin);
      } else if (bestCn && !cnWeak) {
        displayBrand = bestCn;
      } else if (titlePrimaryLatin) {
        displayBrand = NS.formatBrandTokenForDisplay(titlePrimaryLatin);
      }
      const brandToken = bestLatin || (!cnWeak ? bestCn : "") || titlePrimaryLatin || bestCn || "";
      return {
        displayBrand,
        brandToken,
        latinToken: bestLatin || titlePrimaryLatin || "",
        cnBrand: cnWeak ? "" : bestCn,
        source: displayBrand && bestLatin && displayBrand.toLowerCase() === NS.formatBrandTokenForDisplay(bestLatin).toLowerCase()
          ? latinSource
          : (cnWeak ? latinSource : cnSource),
        score: Math.max(bestCnScore, bestLatinScore),
        fields
      };
    } catch {
      return { displayBrand: "", brandToken: "", latinToken: "", cnBrand: "", source: "", score: 0, fields: null };
    }
  };

  /**
   * 展示用品牌名：严格走身份字段选词；fallback 到传入的 displayBrand/brandToken。
   */
  NS.pickBrandDisplayName = function (opts) {
    try {
      const o = opts || {};
      const picked = typeof NS.pickProductBrandFromIdentity === "function"
        ? NS.pickProductBrandFromIdentity(o.labelRaw)
        : null;
      if (picked && picked.displayBrand && /[一-鿿]/.test(picked.displayBrand)) return picked.displayBrand;
      if (picked && picked.displayBrand && !BRAND_TOKEN_STOP_RE.test(String(picked.displayBrand).toLowerCase())) {
        return picked.displayBrand;
      }
      const title = String(o.title != null ? o.title : (document.title || ""));
      const identity = String(o.identity || o.brandSource || title);
      // 盗版页多字段共识：title / h1–h6 / keywords / description / footer
      if (typeof NS.pickChineseBrandFromIdentityConsensus === "function") {
        const consensus = NS.pickChineseBrandFromIdentityConsensus();
        if (consensus) return consensus;
      }
      if (typeof NS.pickChineseBrandFromPageSurface === "function") {
        const h1 = String(document.querySelector("h1")?.textContent || "").trim();
        const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(800) : h1;
        // title / og:site / description 先于 keywords（keywords 常为 SEO 虚词「文章」）
        const surface = NS.pickChineseBrandFromPageSurface(title)
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(h1)
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[name="description"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(headings)
          || NS.pickChineseBrandFromPageSurface(document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "")
          || NS.pickChineseBrandFromPageSurface(identity);
        if (surface && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(surface))) return surface;
      }
      let cn = String(o.displayBrand || o.cnDisplay || "").trim();
      if (cn && /[一-鿿]/.test(cn) && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(cn))) return cn;
      const fromIdPool = NS.extractChineseProductBrandCandidates(`${title} ${identity}`);
      const fromId = fromIdPool.slice().sort((a, b) => b.length - a.length)[0] || "";
      if (fromId) return fromId;
      const raw = String(o.brandToken || o.latin || o.preferredLatin || "").trim();
      if (!raw || BRAND_TOKEN_STOP_RE.test(raw.toLowerCase())) return "";
      return NS.formatBrandTokenForDisplay(raw);
    } catch { return ""; }
  };

  /** 用于品牌打分的正文：去掉图标字体/脚本，避免 material-symbols 的 chat/home 等 ligature 污染 */
  NS.collectBrandScoringBodyText = function (maxLen = 8000) {
    try {
      const root = document.body;
      if (!root) return "";
      const clone = root.cloneNode(true);
      clone.querySelectorAll(
        "script, style, noscript, svg, .material-symbols-outlined, .material-icons, [class*='material-symbols'], [class*='icon-'], i.fa, i.fas, i.far, i.fab"
      ).forEach((el) => { try { el.remove(); } catch { /* ignore */ } });
      return (clone.innerText || clone.textContent || "").replace(/\s+/g, " ").trim().slice(0, maxLen).toLowerCase();
    } catch {
      try {
        return ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").slice(0, maxLen).toLowerCase();
      } catch { return ""; }
    }
  };

  /** 标题主品牌：优先取 <title> 开头的专有名（DingTalk），而非正文高频泛词（Chat） */
  NS.pickPrimaryTitleBrandToken = function (titleText, labelRaw) {
    const title = String(titleText || "").trim();
    if (!title) return "";
    const head = title.split(/\s*[-–—|:·]\s*/)[0] || title;
    const headTokens = NS.extractLatinBrandTokens(head);
    if (headTokens.length) {
      // 段首最长 token 通常是产品名
      const sorted = headTokens.slice().sort((a, b) => b.length - a.length || a.localeCompare(b));
      const primary = sorted[0] || "";
      if (primary.length >= 4) return primary;
    }
    const all = NS.extractLatinBrandTokens(title);
    if (!all.length) return "";
    return NS.pickBrandTokenForHost(all, labelRaw) || all[0] || "";
  };

  /**
   * 从营销夹带主机推断品牌核心：huorong-pc → huorong；im-todesk → todesk。
   * 用于页面仅有中文品牌名、无拉丁 token 时仍能标 padded。
   */
  NS.inferMarketingPaddedBrandCore = function (rawLabel) {
    try {
      const raw = String(rawLabel || "").toLowerCase().replace(/^www\./, "");
      if (!raw || raw.length < 5) return "";
      const mktSuf = /^(?:pc|app|soft|safe|vip|pro|cn|win|desk|security|guard|download|down|client|free|official|online|cloud|tool|tools|hub|box|lab|mac|ios|android|mobile|ai|bot|gpt|setup|install|site|web|net|home|store)$/i;
      const mktPre = /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|gw|my|the|best|new|top|go|use|try|win|cn|zh|en|im|qq|wx|dl|to|up|re|un|web|www\d*|hi|ok|yes)$/i;
      if (/-/.test(raw)) {
        const parts = raw.split("-").filter(Boolean);
        if (parts.length >= 2) {
          const first = parts[0];
          const last = parts[parts.length - 1];
          // huorong-pc / huorong-safe-pc
          if (mktSuf.test(last) && /^[a-z][a-z0-9]{3,16}$/i.test(first) && !mktPre.test(first) && !mktSuf.test(first)) {
            return first.replace(/[^a-z0-9]/g, "");
          }
          // im-todesk / get-huorong
          if (mktPre.test(first) && parts[1] && /^[a-z][a-z0-9]{3,16}$/i.test(parts[1]) && !mktSuf.test(parts[1])) {
            return String(parts[1]).replace(/[^a-z0-9]/g, "");
          }
        }
      }
      const lab = raw.replace(/-/g, "");
      const m = lab.match(/^([a-z][a-z0-9]{3,16})(pc|app|soft|safe|vip|pro|cn|win|desk|security|guard|download|client|free|official)$/i);
      if (m && m[1] && !mktPre.test(m[1])) return m[1].toLowerCase();
      return "";
    } catch { return ""; }
  };

  NS.hostLabelIsPaddedBrand = function (label, brandToken) {
    const lab = String(label || "").toLowerCase().replace(/-/g, "");
    const br = String(brandToken || "").toLowerCase().replace(/-/g, "");
    if (!lab || !br || br.length < 4) return false;
    if (lab === br) return false;
    if (!lab.includes(br)) return false;
    // pyas-security 等品牌产品线域名：绝不当营销 padded 仿冒
    if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
      && (NS.hostLabelIsBrandProductCategoryDomain(label, br) || NS.hostLabelIsBrandProductCategoryDomain(lab, br))) {
      return false;
    }
    if (lab.startsWith(br)) {
      const pad = lab.slice(br.length);
      // archlinux = Arch Linux 产品复合域名，非 todeskai 类营销夹带
      // （无连字符 + 平台尾缀 linux/windows 时不当 padded）
      if (/^(linux|windows|macos|android)$/i.test(pad) && br.length <= 6 && !/-/.test(String(label || ""))) {
        return false;
      }
      // security/antivirus 产品线尾缀不当 padded
      if (BRAND_PRODUCT_CATEGORY_SUFFIX.test(pad)) return false;
      if (pad.length >= 2 && pad.length <= 12 && MKT_HOST_SUFFIX.test(pad)) return true;
      if (pad.length >= 2 && pad.length <= 4 && /^(?:app|ai|bot|pro|vip|pc|cn|get|dl|im)$/i.test(pad)) return true;
    }
    if (lab.endsWith(br)) {
      const pad = lab.slice(0, lab.length - br.length);
      if (pad.length >= 1 && pad.length <= 12 && MKT_HOST_PREFIX.test(pad)) return true;
      // im-todesk → imtodesk：前缀 im / aa / get 等
      if (pad.length >= 2 && pad.length <= 4 && /^(?:aa|bb|cc|pc|my|get|go|to|up|re|un|im|qq|wx|dl|gw|x|z)$/i.test(pad)) return true;
      if (pad.length === 1 && /[a-z0-9]/i.test(pad)) return true;
    }
    const idx = lab.indexOf(br);
    if (idx > 0 && idx + br.length < lab.length) {
      const left = lab.slice(0, idx);
      const right = lab.slice(idx + br.length);
      if (left.length <= 6 && right.length <= 8 && (MKT_HOST_PREFIX.test(left) || left.length <= 3) && (MKT_HOST_SUFFIX.test(right) || right.length <= 4)) return true;
    }
    return false;
  };

  /**
   * 前缀-品牌连字符：im-todesk / get-todesk / aa-todesk.com.cn
   * （完整连字符镜像 aa-to-desk 仍由 hostLabelIsHyphenatedBrandMirror 处理）
   */
  NS.hostLabelIsPrefixedHyphenBrand = function (rawLabel, brandToken) {
    const raw = String(rawLabel || "").toLowerCase();
    const br = String(brandToken || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!raw || br.length < 4 || !/-/.test(raw)) return false;
    // pyas-security：品牌产品线域名，不是 im-todesk 类前缀夹带
    if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
      && NS.hostLabelIsBrandProductCategoryDomain(raw, br)) {
      return false;
    }
    const parts = raw.split("-").filter(Boolean);
    if (parts.length < 2) return false;
    const norm = (p) => String(p || "").replace(/[^a-z0-9]/g, "");
    let brandIdx = -1;
    for (let i = 0; i < parts.length; i++) {
      const s = norm(parts[i]);
      if (s === br || NS.hostLabelIsBrandTypo(s, br)) { brandIdx = i; break; }
    }
    if (brandIdx < 0) return false;
    const prefix = parts.slice(0, brandIdx).map(norm).join("");
    const suffix = parts.slice(brandIdx + 1).map(norm).join("");
    if (prefix.length === 0 && suffix.length === 0) return false;
    if (prefix.length > 14 || suffix.length > 12) return false;
    // 后缀纯品类（security）→ 非前缀仿冒
    if (!prefix && suffix && BRAND_PRODUCT_CATEGORY_SUFFIX.test(suffix)) return false;
    const prefixOk = !prefix
      || MKT_HOST_PREFIX.test(prefix)
      || /^(?:im|qq|wx|wechat|chat|live|msg|mail|cdn|dl|gw|soft|app|pc|cn|ca|zh|en|vip|pro|my|get|go|to|aa|bb|cc|web|www\d*|hi|ok|yes|best|top|new)$/i.test(prefix)
      || prefix.length <= 3;
    const suffixOk = !suffix
      || MKT_HOST_SUFFIX.test(suffix)
      || /^(?:app|cn|pro|vip|pc|win|soft|dl|hub|lab)$/i.test(suffix)
      || suffix.length <= 4;
    return prefixOk && suffixOk && (prefix.length >= 1 || suffix.length >= 1);
  };

  NS.hostLabelComposedOfTitleTokens = function (label, tokens) {
    const lab = String(label || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (lab.length < 6) return false;
    const skip = /^(download|windows|linux|android|macos|official|client|software|remote|chrome|https|http|free|desk|home|page|site|high|full|platform|utility|application|secure|speed|version|enterprise|search|native|group|center|service|services|update|online|cloud|remove|unwanted|programs|program|easily|with|from|that|this|your|have|will|help|trace|traces|unwant|leftover|leftovers|products|product|privacy|policy|cookie|cookies)$/i;
    const platform = /^(linux|windows|macos|android|bsd)$/i;
    const raw = [...new Set((tokens || []).map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "")))]
      .filter((t) => t.length >= 3 && t.length <= 20);
    const toks = raw.filter((t) => !skip.test(t)).sort((a, b) => b.length - a.length);
    // Arch Linux → archlinux：平台词仅作尾部参与复合
    const primaries = raw.filter((t) => !skip.test(t) || platform.test(t));
    for (const a of primaries) {
      if (platform.test(a) || a.length < 3) continue;
      for (const b of raw) {
        if (a === b) continue;
        if (platform.test(b) && lab === a + b) return true;
      }
    }
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
      if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(raw, t)) s += 135;
      if (NS.hostLabelIsPaddedBrand(lab, t) || NS.hostLabelIsPaddedBrand(raw, t)) s += 120;
      // 主机仅弱包含短词（chat 在 xxxchat 中）加分要克制，避免压过标题主品牌
      if (lab.includes(t) && t.length >= 5) s += 40;
      else if (lab.includes(t) && t.length === 4) s += 12;
      if (t.includes(lab) && lab.length >= 4) s += 30;
      const idx = list.indexOf(t);
      if (idx >= 0) s += Math.max(0, 12 - idx);
      // 更长专有名优先（dingtalk > chat）
      s += Math.min(t.length, 16) * 2;
      if (t.length <= 4) s -= 25;
      return s;
    };
    const aligned = list.filter((t) => scoreTok(t) >= 40);
    if (aligned.length) return aligned.sort((a, b) => scoreTok(b) - scoreTok(a))[0] || "";
    // 无主机对齐时仍优先更长 token，避免 list[0] 碰巧是泛词
    return list.slice().sort((a, b) => b.length - a.length || scoreTok(b) - scoreTok(a))[0] || "";
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
    // im-todesk / get-todesk 等：连字符前缀夹带 → 按 padded 处理
    if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(rawLab, brand)) return "padded";
    if (lab === brand) return "exact";
    // pyas-security.com + 标题 PYAS → 自家产品线域名，exact（非 partial 仿冒）
    if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
      && (NS.hostLabelIsBrandProductCategoryDomain(rawLab, brand) || NS.hostLabelIsBrandProductCategoryDomain(lab, brand))) {
      return "exact";
    }
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
    const cnGeneric = /^(下载|官方|软件|客户端|安全|杀毒|电脑|免费|最新|正版|中心|防护|管家|大师|官网|服务|企业|个人|产品|远程|桌面|控制|版权|所有|互联网|文章|专题|详情|导读|正文|内容)$/;
    const cn = brandSource.match(/([一-鿿]{2,8})(?=官网|官方|下载|客户端|软件|安全中心)/g) || [];
    cn.forEach((c) => {
      if (cnGeneric.test(c)) return;
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(c)) return;
      tokens.add(c);
    });
    // 数字前缀产品（360安全卫士）也入 token 集
    if (typeof NS.extractChineseProductBrandCandidates === "function") {
      NS.extractChineseProductBrandCandidates(brandSource).forEach((c) => tokens.add(c));
    }
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
