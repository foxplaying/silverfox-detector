/**
 * ICP/WHOIS 成熟度门 + 官方上下文判定。
 * 决定页面是否为成熟官网（永不 arm）或安全官方下载上下文。
 */
;(function (NS) {
  "use strict";

  /**
   * 大型内容 SPA 结构启发（无域名白名单）。
   * 用于同站 soft-nav 跳过全量复扫：DOM 巨大 + 无「官网下载」仿冒壳话术。
   * GitHub / GitLab / 文档站 / 天气门户等自然命中；银狐落地页通常节点少且标题含官方下载。
   */
  NS.pageLooksLikeHeavyContentSpa = function () {
    try {
      const state = NS.state;
      if (state && (state.downloadGuardInstalled || state._seoCloakKitDetected || state._fakeSpaDetected
        || state._brandSpoofPortalDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected
        || state._fakeBrandShellDetected)) return false;
      const title = String(document.title || "");
      // 仿冒下载壳话术（软件安装包落地）→ 必须继续扫；天气/资讯标题里的「查询」不算
      if (/官方客户端|官方正版|电脑版官网|立即免费下载|全平台官方/i.test(title)) return false;
      if (/(?:软件|杀毒|远程|连接|桌面)[^。]{0,8}(?:官网|官方下载)/i.test(title)
        || /(?:官网|官方下载)[^。]{0,8}(?:软件|杀毒|远程|客户端|安装包)/i.test(title)) return false;
      let nodes = 0; let links = 0; let scripts = 0;
      try { nodes = document.getElementsByTagName("*").length; } catch { nodes = 0; }
      try { links = document.links ? document.links.length : document.querySelectorAll("a[href]").length; } catch { links = 0; }
      try { scripts = document.scripts ? document.scripts.length : 0; } catch { scripts = 0; }
      // 大型应用壳：节点/链接/脚本密度高（天气/资讯门户）
      if (nodes >= 900 && links >= 25 && scripts >= 8) return true;
      if (nodes >= 1200 && links >= 30) return true;
      if (nodes >= 800 && links >= 40 && scripts >= 6) return true;
      if (nodes >= 2000) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 资讯/天气/内容门户（非软件下载落地）：应 light + 立即 complete。
   * 例：tianqi.2345.com 广州天气预报——有附属 APK/广告，但不是银狐 exe 壳。
   */
  NS.pageLooksLikeContentInfoPortal = function () {
    try {
      const state = NS.state;
      if (state && (state.downloadGuardInstalled || state._seoCloakKitDetected || state._fakeSpaDetected
        || state._brandSpoofPortalDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected)) return false;
      const title = String(document.title || "");
      const kw = String(document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "");
      const desc = String(document.querySelector('meta[name="description"]')?.getAttribute("content") || "");
      const blob = `${title} ${kw} ${desc}`.slice(0, 800);
      // 强软件下载落地话术 → 否
      if (/官方客户端|官方正版|电脑版官网|立即免费下载|远程控制|杀毒软件官网/i.test(blob)) return false;
      const contentTopic = /天气|预报|新闻|资讯|财经|股票|体育|娱乐|视频|小说|论坛|地图|出行|旅游|美食|健康|教育|汽车|房产|天气查询|空气质量|紫外线|降水|风力|温度/i.test(blob);
      if (!contentTopic) return false;
      let nodes = 0; let links = 0; let scripts = 0;
      try { nodes = document.getElementsByTagName("*").length; } catch { nodes = 0; }
      try { links = document.links ? document.links.length : 0; } catch { links = 0; }
      try { scripts = document.scripts ? document.scripts.length : 0; } catch { scripts = 0; }
      // 有实质内容结构
      if (nodes >= 400 && links >= 15) return true;
      if (nodes >= 250 && scripts >= 8 && links >= 10) return true;
      if (contentTopic && links >= 20 && scripts >= 5) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 同站 soft-nav 是否应保持 light、跳过 reset+全量复扫（纯状态/结构逻辑，非域名名单）。
   * 用户规则：有有效 ICP 备案的域名只做首次全量分析；SPA/页内变换后除非手动刷新不再复扫。
   */
  NS.shouldKeepLightOnSameHostSoftNav = function () {
    try {
      const state = NS.state;
      if (!state) return false;
      // 真硬套件仍允许在 soft-nav 上复扫
      if (state._seoCloakKitDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected
        || state._indexNowPhishTemplate) return false;
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return false;
      // 只有成熟正规站组合门通过后，同站变换才保持 light。
      if (typeof NS.pageHasStrongTrustedIdentity === "function" && NS.pageHasStrongTrustedIdentity()) {
        return true;
      }
      if (state.downloadGuardInstalled || state._fakeSpaDetected
        || state._brandSpoofPortalDetected || state._fakeBrandShellDetected) return false;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity()) return false;
      // 无 ICP 时：仿冒下载壳标题仍全量扫
      if (/官网|官方下载|官方正版|官方客户端|立即免费下载/i.test(document.title || "")) return false;
      if (state._intelLightMode || state._perfBenign) return true;
      if (state._analysisDone && (state.score || 0) < 12) return true;
      if (typeof NS.pageLooksLikeHeavyContentSpa === "function" && NS.pageLooksLikeHeavyContentSpa()) return true;
      // WHOIS 超成熟（≥10 年）属证据逻辑，非站点名单
      if (typeof NS.looksLikeUltraMatureWhoisDomain === "function" && NS.looksLikeUltraMatureWhoisDomain()) return true;
      if (typeof NS.looksLikeUltraMatureIcpDomain === "function" && NS.looksLikeUltraMatureIcpDomain()) return true;
      return false;
    } catch { return false; }
  };

  NS.getWhoisAgeDays = function () {
    try {
      const m = /已注册\s*(\d+)\s*天/.exec(NS.state.whoisInfo || "");
      if (!m) return null;
      const d = parseInt(m[1], 10);
      return Number.isFinite(d) ? d : null;
    } catch { return null; }
  };

  // 工信部备案号使用省级行政区简称；固定行政编码集合不是厂商/域名白名单。
  const ICP_REGION_CHAR_CLASS = "京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼";

  /** 折叠全角/零宽字符，便于抽「京ＩＣＰ备１１００００００号－１」等仿冒写法 */
  NS.foldIcpSourceText = function (raw) {
    try {
      let s = String(raw || "");
      if (!s) return "";
      try { s = s.normalize("NFKC"); } catch { /* ignore */ }
      return s
        .replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g, "")
        .replace(/[\u00a0\u3000\u2000-\u200a]/g, " ");
    } catch {
      return String(raw || "");
    }
  };

  /** 归一页面/API 备案号，消除空格、「号」和大小写差异；保留可选网站序号 -N。 */
  NS.normalizeIcpLicense = function (raw) {
    try {
      // 统一破折号；「号-1」→「-1」；末尾孤立「号」去掉
      let text = (typeof NS.foldIcpSourceText === "function" ? NS.foldIcpSourceText(raw) : String(raw || ""))
        .toUpperCase()
        .replace(/\s+/g, "")
        .replace(/[－–—]/g, "-")
        .replace(/号-/g, "-")
        .replace(/号(?=-|$)/g, "");
      // 主体数字 + 可选网站序号（勿把 -1 并进 {A-Z0-9-} 贪婪段里误切）
      const hit = text.match(new RegExp(
        `[${ICP_REGION_CHAR_CLASS}]ICP[备證证][A-Z0-9]{5,20}(?:-\\d{1,4})?`,
        "i"
      ));
      if (!hit) return "";
      return String(hit[0] || "")
        .replace(/[證证]/g, "证")
        .toUpperCase();
    } catch { return ""; }
  };

  /**
   * 备案主体键：省简称 + 备/证 + 主号数字。
   * 页面「浙ICP备2026024359号」与 API「浙ICP备2026024359号-1」→ 同一键，不算冒用。
   */
  NS.icpLicenseBaseKey = function (raw) {
    try {
      const text = (typeof NS.foldIcpSourceText === "function" ? NS.foldIcpSourceText(raw) : String(raw || ""))
        .toUpperCase()
        .replace(/\s+/g, "")
        .replace(/[－–—]/g, "-")
        .replace(/号/g, "");
      const m = text.match(new RegExp(
        `([${ICP_REGION_CHAR_CLASS}])ICP([备證证])([A-Z0-9]{5,20})`,
        "i"
      ));
      if (m) {
        const kind = (m[2] === "证" || m[2] === "證") ? "证" : "备";
        return `${m[1]}ICP${kind}${m[3]}`;
      }
      const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(raw) : "";
      return n ? n.replace(/-\d{1,4}$/g, "") : "";
    } catch { return ""; }
  };

  /** 备案主体号相同即视为一致；网站序号 -1/-2 的差异不算冒用。 */
  NS.icpLicensesReferToSameRecord = function (a, b) {
    const left = typeof NS.icpLicenseBaseKey === "function" ? NS.icpLicenseBaseKey(a) : "";
    const right = typeof NS.icpLicenseBaseKey === "function" ? NS.icpLicenseBaseKey(b) : "";
    if (left && right && left === right) return true;
    // 兜底：完整归一后再剥序号
    const ln = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(a) : "";
    const rn = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(b) : "";
    if (!ln || !rn) return false;
    if (ln === rn) return true;
    return ln.replace(/-\d{1,4}$/g, "") === rn.replace(/-\d{1,4}$/g, "");
  };

  /**
   * 只从页脚/版权区域提取页面自称备案号。
   * ★ 正文、新闻、教程里提到的 ICP 一律不算「页脚宣称」，不得触发「假冒宣称」。
   * 兼容「京 ICP 备 11000000 号-1」、全角数字、页脚内隐藏节点（假备案常 display:none）。
   */
  NS.extractPageDeclaredIcpLicenses = function () {
    const out = [];
    const seen = new Set();
    const pushHit = (hit) => {
      const normalized = NS.normalizeIcpLicense(hit);
      const base = typeof NS.icpLicenseBaseKey === "function" ? NS.icpLicenseBaseKey(hit) : normalized;
      if (!normalized || !base || seen.has(base)) return;
      seen.add(base);
      out.push(normalized);
    };
    const addFromText = (raw) => {
      const src0 = typeof NS.foldIcpSourceText === "function"
        ? NS.foldIcpSourceText(raw)
        : String(raw || "");
      if (!src0) return;
      // ① 允许任意空白：京 ICP 备 11000000 号-1
      const spacedRe = new RegExp(
        `([${ICP_REGION_CHAR_CLASS}])\\s*I\\s*C\\s*P\\s*[备證证備]\\s*([A-Za-z0-9]{5,20})\\s*号?(?:\\s*-\\s*(\\d{1,4}))?`,
        "gi"
      );
      let m;
      while ((m = spacedRe.exec(src0)) !== null) {
        const region = m[1];
        const body = m[2];
        const serial = m[3] ? `-${m[3]}` : "";
        pushHit(`${region}ICP备${body}号${serial}`);
      }
      // ② 压空白后再匹配（兼容全角/间隔点）；破折号统一为 - 以保留序号
      let compact = src0
        .replace(/[·•|｜./／\\]+/g, "")
        .replace(/[－–—]/g, "-")
        .replace(/\s+/g, "")
        .toUpperCase()
        .replace(/[Ｉ]/g, "I")
        .replace(/[Ｃ]/g, "C")
        .replace(/[Ｐ]/g, "P")
        .replace(/備/g, "备");
      if (compact) {
        const hits = compact.match(new RegExp(
          `[${ICP_REGION_CHAR_CLASS}]ICP[备證证][A-Z0-9]{5,20}(?:号)?(?:-\\d{1,4})?`,
          "gi"
        )) || [];
        hits.forEach(pushHit);
      }
    };
    // 重要：优先 textContent。innerText 会丢掉 display:none / visibility:hidden 的假备案号。
    const elText = (el) => {
      try {
        const tc = String(el.textContent || "");
        const it = String(el.innerText || "");
        return tc.length >= it.length ? tc : `${tc}\n${it}`;
      } catch {
        try { return String(el.textContent || el.innerText || ""); } catch { return ""; }
      }
    };
    /** 节点是否落在页脚/版权壳内（排除正文 article/main 里的偶然 class） */
    const isFooterScope = (el) => {
      try {
        if (!el || el.nodeType !== 1) return false;
        // 明确在 main/article/内容区且不在 footer 祖先下 → 排除
        let cur = el;
        let sawFooter = false;
        let sawMain = false;
        for (let depth = 0; cur && depth < 14; depth++) {
          const tag = String(cur.tagName || "").toLowerCase();
          const id = String(cur.id || "").toLowerCase();
          const cls = String(cur.className || "").toLowerCase();
          const blob = `${tag} ${id} ${cls}`;
          if (tag === "footer"
            || /(?:^|[\s_-])(?:footer|foot-bottom|site-footer|page-footer|copyright|beian|icp-info|icp-num|filing)(?:$|[\s_-])/i.test(blob)
            || /(?:^|[\s_-])(?:footer|copyright)(?:$|[\s_-])/i.test(id)
            || id === "footer" || id === "copyright" || id === "beian") {
            sawFooter = true;
            break;
          }
          if (tag === "main" || tag === "article" || /(?:^|[\s_-])(?:article|post-content|entry-content|markdown-body|news-content)(?:$|[\s_-])/i.test(blob)) {
            sawMain = true;
          }
          cur = cur.parentElement;
        }
        if (sawFooter) return true;
        if (sawMain) return false;
        // 备案官网链接：仅当自身 class/父级像页脚，或靠近页面底部
        try {
          const href = String(el.getAttribute && el.getAttribute("href") || "").toLowerCase();
          if (/beian\.miit\.gov\.cn|miitbeian|miit\.gov\.cn\/.*beian/i.test(href)) {
            // 链接文本或父块含版权/备案字样 → 视作页脚声明
            const near = elText(el.parentElement || el);
            if (/版权|Copyright|©|备案|ICP|All\s*Rights/i.test(near)) return true;
            // 视口底部：仿冒页常把备案链钉在底栏
            const r = el.getBoundingClientRect && el.getBoundingClientRect();
            if (r && typeof window !== "undefined" && window.innerHeight
              && r.top > window.innerHeight * 0.72) return true;
          }
        } catch { /* ignore */ }
        // 宽松 class：footer/copyright/beian/icp（避免 foot 误伤 football）
        const selfBlob = `${String(el.id || "")} ${String(el.className || "")} ${String(el.tagName || "")}`.toLowerCase();
        if (/(?:footer|copyright|beian|icp-info|icp-num|site-info|site-meta|foot-bottom)/i.test(selfBlob)) return true;
        return false;
      } catch { return false; }
    };
    try {
      document.querySelectorAll(
        "footer, .footer, #footer, .site-footer, .page-footer, .foot-bottom, "
        + "[class*='footer'], [id*='footer'], "
        + "[class*='copyright'], [id*='copyright'], "
        + "[class*='beian'], [id*='beian'], [class*='icp'], [id*='icp'], "
        + "[class*='filing'], [id*='filing'], "
        + "a[href*='beian.miit.gov.cn'], a[href*='miitbeian'], a[href*='beian.miit']"
      ).forEach((el) => {
        try {
          if (!isFooterScope(el)) return;
          addFromText(elText(el));
          try {
            addFromText(el.getAttribute("title") || "");
            addFromText(el.getAttribute("aria-label") || "");
            addFromText(el.getAttribute("data-icp") || "");
          } catch { /* ignore */ }
          try {
            const oh = String(el.outerHTML || "");
            if (oh.length < 4000 && /ICP|备案|备\d/i.test(oh)) addFromText(oh.replace(/<[^>]+>/g, " "));
          } catch { /* ignore */ }
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
    // 禁止再扫整页 body / 全文 HTML：正文提到闽ICP备…不得触发假冒宣称
    // 无标准 footer 时：仅当 body 末尾同时有「版权/Copyright」与 ICP 时，视作页脚壳
    try {
      if (!out.length && document.body) {
        const full = String(document.body.textContent || "");
        const tail = full.length > 5000 ? full.slice(-3500) : full.slice(-Math.min(full.length, 3500));
        if (tail && /版权|Copyright|©|All\s*Rights\s*Reserved/i.test(tail)
          && /ICP|备案/i.test(tail)
          && !/新闻|报道|教程|文章|如何|什么是|查询备案|ICP查询/i.test(tail.slice(0, 400))) {
          addFromText(tail);
        }
      }
    } catch { /* ignore */ }
    return out;
  };

  /**
   * 情报结束时收口：页脚有备案宣称且权威源无本域记录 → 只保留「假冒ICP」，去掉「无ICP」。
   * 解决抽号时序/空白写法/隐藏节点导致只亮「无ICP备案信息」的问题。
   *
   * 重要：若权威源已命中备案号（或 state.icpInfo 已是真号），绝不可再以
   * remoteMissing=true 表示来源已明确返回未备案；查询失败必须显式传 false，
   * 不能把“查不到结果”和“确认未备案”混成同一状态。
   */
  NS.finalizeIcpClaimSignals = function (remoteRecord, remoteMissing) {
    try {
      const state = NS.state;
      if (!state) return null;
      const declared = typeof NS.extractPageDeclaredIcpLicenses === "function"
        ? NS.extractPageDeclaredIcpLicenses()
        : [];
      // 调用方漏传 remote 时，回填已写入的真备案号（WHOIS 空分支曾踩过此坑）
      let remote = String(remoteRecord || "").trim();
      if (!remote) {
        const info = String(state.icpInfo || "").trim();
        if (info && typeof NS.looksLikeIcpLicense === "function" && NS.looksLikeIcpLicense(info)
          && !/假冒|宣称|待核验|未查询|查询失败/i.test(info)) {
          remote = info.replace(/（主域[^）]*）/g, "").trim();
        }
      }
      const remoteOk = !!(remote && typeof NS.looksLikeIcpLicense === "function" && NS.looksLikeIcpLicense(remote));
      // 真备案：清掉假冒/待核验，按一致主体号收口
      if (remoteOk) {
        if (typeof NS.clearPendingIcpClaimSignals === "function") NS.clearPendingIcpClaimSignals();
        if (typeof NS.clearFakeIcpClaimSignals === "function") NS.clearFakeIcpClaimSignals();
        if (!state.icpInfo || /假冒|宣称|待核验|未查询/i.test(String(state.icpInfo))) {
          state.icpInfo = remote;
        }
        state._unverifiedPageIcpClaim = false;
        if (typeof NS.reconcilePageIcpClaim === "function") {
          return NS.reconcilePageIcpClaim(remote, false, declared);
        }
        return null;
      }
      if (!declared.length) return null;
      const confirmedMissing = remoteMissing === true;
      const check = typeof NS.reconcilePageIcpClaim === "function"
        ? NS.reconcilePageIcpClaim("", confirmedMissing, declared)
        : { declared, unverifiedClaim: true };
      if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
      state.pageDeclaredIcp = declared.join(" / ");
      // 明确未备案 + 页脚仍声明任何备案号 → 最终判为假冒；
      // 只有查询失败、尚无明确结论时，正常格式号码才显示“待核验”。
      const ph = declared.some((d) =>
        typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
      );
      const normal = declared.some((d) => {
        const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
        return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
      });
      if (ph || confirmedMissing) {
        state.icpInfo = `假冒宣称 ${declared.join(" / ")}`;
        state._unverifiedPageIcpClaim = true;
      } else if (normal) {
        state.icpInfo = `页脚宣称 ${declared.join(" / ")}（第三方待核验）`;
        state._unverifiedPageIcpClaim = false;
      } else if (check && check.unverifiedClaim) {
        state.icpInfo = `假冒宣称 ${declared.join(" / ")}`;
        state._unverifiedPageIcpClaim = true;
      }
      return check;
    } catch {
      return null;
    }
  };

  /**
   * 页脚晚挂载时补扫：先写了「无ICP」后，隐藏/异步插入的假号要升级成假冒。
   * 仅在已结算且无真备案时调度。
   */
  NS.scheduleDeferredIcpClaimRescan = function (remoteRecord, remoteMissing) {
    try {
      const state = NS.state;
      const c = NS.caches;
      if (!state || !c) return;
      if (c._icpClaimRescanTimers && Array.isArray(c._icpClaimRescanTimers)) {
        c._icpClaimRescanTimers.forEach((t) => { try { clearTimeout(t); } catch { /* ignore */ } });
      }
      c._icpClaimRescanTimers = [];
      const hostAt = String(location.hostname || "");
      const hrefAt = String(location.href || "");
      const rec = remoteRecord || "";
      const miss = remoteMissing === true;
      [600, 1800, 4000].forEach((ms) => {
        const tid = setTimeout(() => {
          try {
            if (String(location.hostname || "") !== hostAt) return;
            if (String(location.href || "") !== hrefAt) return;
            if (!state._icpQuerySettled) return;
            if (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()) return;
            // 权威源已给真号时不要再降级
            if (rec && typeof NS.looksLikeIcpLicense === "function" && NS.looksLikeIcpLicense(rec)) return;
            // 已有假冒信号且无「无ICP」则可停
            const hasFake = (state.details || []).some((d) => /^假冒ICP备案信息/i.test(String(d && d.name || "")));
            const hasPending = (state.details || []).some((d) => /^备案待核验/i.test(String(d && d.name || "")));
            const hasMissing = (state.details || []).some((d) => d && d.name === "无ICP备案信息");
            if (hasFake && !hasMissing && state._unverifiedPageIcpClaim) return;
            if (hasPending && !hasMissing && !state._unverifiedPageIcpClaim) return;
            const fin = typeof NS.finalizeIcpClaimSignals === "function"
              ? NS.finalizeIcpClaimSignals(rec, miss)
              : null;
            if (fin && fin.declared && fin.declared.length) {
              if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
              if (!state.icpInfo || /未查询到|查询失败|暂无|无ICP/i.test(String(state.icpInfo))) {
                const normal = fin.declared.some((d) => {
                  const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
                  return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
                });
                const ph = fin.declared.some((d) =>
                  typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
                );
                // 已明确未备案时必须收口为假冒；只有查询失败才保留待核验。
                state.icpInfo = (ph || !normal || miss)
                  ? `假冒宣称 ${fin.declared.join(" / ")}`
                  : `页脚宣称 ${fin.declared.join(" / ")}（第三方待核验）`;
              }
              try { NS.emitRiskReport(true); } catch { /* ignore */ }
              NS.silverfoxLog && NS.silverfoxLog("icp", "deferred-claim-rescan", fin.declared.join(","), "ms=", ms);
            }
          } catch { /* ignore */ }
        }, ms);
        c._icpClaimRescanTimers.push(tid);
      });
    } catch { /* ignore */ }
  };

  /** 去掉「无ICP备案信息」信号（已升级为假冒页脚宣称时） */
  NS.clearMissingIcpSignal = function () {
    try {
      const state = NS.state;
      if (!state) return;
      let dropped = 0;
      const before = Array.isArray(state.details) ? state.details.length : 0;
      state.details = (state.details || []).filter((d) => {
        if (!d) return false;
        if (d.name === "无ICP备案信息" || /^无ICP备案信息/i.test(String(d.name || ""))) {
          dropped += 1;
          return false;
        }
        return true;
      });
      if (state.signalSet && typeof state.signalSet.forEach === "function") {
        const drop = [];
        state.signalSet.forEach((k) => {
          const s = String(k || "");
          if (s === "无ICP备案信息" || s.startsWith("无ICP备案信息:") || /^无ICP备案信息/i.test(s)) drop.push(k);
        });
        drop.forEach((k) => state.signalSet.delete(k));
        dropped += drop.length;
      }
      // 分数按剩余 details 重算，避免删信号后分数偏高
      state.score = (state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
      if (dropped && typeof NS.silverfoxLog === "function") {
        NS.silverfoxLog("icp", "cleared-missing-icp-signal", "before=", before, "left=", state.details.length);
      }
    } catch { /* ignore */ }
  };

  /**
   * 明显占位/伪造备案主体号（仿冒页常用 11000000、全 0、重复数字）。
   * 不依赖权威源；与「页脚宣称 + 权威源无记录」互补。
   */
  NS.looksLikePlaceholderIcpLicense = function (raw) {
    try {
      const base = typeof NS.icpLicenseBaseKey === "function"
        ? NS.icpLicenseBaseKey(raw)
        : (typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(raw) : "");
      if (!base) return false;
      const digits = (String(base).match(/[备证]([A-Z0-9]+)$/i) || [])[1] || "";
      if (!digits || digits.length < 5) return false;
      // XXXXXXXX / TEST / DEMO / ABCDEF 等字母占位不可能是正常主体号，
      // 无需等待远程备案接口即可确认页面在展示假号。
      if (/X{4,}|(?:TEST|DEMO|EXAMPLE|SAMPLE|PLACEHOLDER)/i.test(digits)) return true;
      if (!/\d/.test(digits) && /^[A-Z]{5,}$/i.test(digits)) return true;
      // 纯数字主体
      if (!/^\d+$/.test(digits)) return false;
      if (/^0+$/.test(digits)) return true;
      if (/^(\d)\1{4,}$/.test(digits)) return true; // 11111 / 00000
      if (/^(?:123456|1234567|12345678|87654321|11000000|11111111|99999999|10000000|12000000)/.test(digits)) return true;
      if (/^1{2,}0{4,}$/.test(digits)) return true; // 11000000 形态
      return false;
    } catch { return false; }
  };

  NS.evaluatePageIcpConsistency = function (remoteRecord, remoteMissing, declaredOpt) {
    const declared = Array.isArray(declaredOpt)
      ? declaredOpt.map((x) => NS.normalizeIcpLicense(x)).filter(Boolean)
      : NS.extractPageDeclaredIcpLicenses();
    const remote = NS.normalizeIcpLicense(remoteRecord);
    const remoteBase = typeof NS.icpLicenseBaseKey === "function"
      ? NS.icpLicenseBaseKey(remoteRecord || remote)
      : (remote || "").replace(/-\d{1,4}$/g, "");
    // 主体号一致即可：页脚无 -1、API 为 号-1 不算不一致
    const matches = !!(remoteBase && declared.some((x) => NS.icpLicensesReferToSameRecord(remoteRecord || remote, x)));
    const remoteFound = !!(remote || (remoteBase && matches));
    return {
      remote: remote || (matches ? remoteBase : ""),
      remoteBase: remoteBase || "",
      declared: [...new Set(declared)],
      remoteFound,
      remoteMissing: !!remoteMissing && !remoteFound,
      matches,
      // 仅当权威源有号且与页脚主体号完全对不上才算 mismatch（-1 序号差不算）
      mismatch: !!(remoteFound && declared.length && !matches),
      unverifiedClaim: !!(!remoteFound && remoteMissing && declared.length)
    };
  };

  NS.UNVERIFIED_PAGE_ICP_CLAIM_WEIGHT = 25;

  /** 清掉「假冒ICP备案信息：…」类信号（API 随后核验通过 / 主体号一致时） */
  NS.clearFakeIcpClaimSignals = function () {
    try {
      const state = NS.state;
      if (!state) return;
      state.details = (state.details || []).filter((d) => d && !/^假冒ICP备案信息/i.test(String(d.name || "")));
      if (state.signalSet && typeof state.signalSet.forEach === "function") {
        const drop = [];
        state.signalSet.forEach((k) => {
          if (/假冒ICP备案信息/i.test(String(k))) drop.push(k);
        });
        drop.forEach((k) => state.signalSet.delete(k));
      }
      state.score = (state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
      state._unverifiedPageIcpClaim = false;
    } catch { /* ignore */ }
  };

  /** 清掉「备案待核验：…」——权威源已命中真号后不得残留 */
  NS.clearPendingIcpClaimSignals = function () {
    try {
      const state = NS.state;
      if (!state) return;
      state.details = (state.details || []).filter((d) => d && !/^备案待核验/i.test(String(d.name || "")));
      if (state.signalSet && typeof state.signalSet.forEach === "function") {
        const drop = [];
        state.signalSet.forEach((k) => {
          if (/备案待核验/i.test(String(k))) drop.push(k);
        });
        drop.forEach((k) => state.signalSet.delete(k));
      }
      state.score = (state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
    } catch { /* ignore */ }
  };

  /** 记录页面备案一致性；仅“权威源明确未备案 + 页面自称备案”加风险。 */
  NS.reconcilePageIcpClaim = function (remoteRecord, remoteMissing, declaredOpt) {
    const check = NS.evaluatePageIcpConsistency(remoteRecord, remoteMissing, declaredOpt);
    const state = NS.state;
    state.pageDeclaredIcp = check.declared.join(" / ");
    state._icpPageMismatch = check.mismatch;
    state._unverifiedPageIcpClaim = check.unverifiedClaim;

    const placeholders = (check.declared || []).filter((d) =>
      typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
    );

    // 权威源已命中备案号 → 撤「待核验 / 假冒」（主体一致时）；勿残留旧信号
    if (check.remoteFound) {
      if (typeof NS.clearPendingIcpClaimSignals === "function") NS.clearPendingIcpClaimSignals();
      if (check.matches && !placeholders.length && !check.mismatch && !check.unverifiedClaim) {
        if (typeof NS.clearFakeIcpClaimSignals === "function") NS.clearFakeIcpClaimSignals();
        state._unverifiedPageIcpClaim = false;
        state._icpPageMismatch = false;
        return check;
      }
      if (!check.mismatch && !check.unverifiedClaim) {
        if (typeof NS.clearFakeIcpClaimSignals === "function") NS.clearFakeIcpClaimSignals();
        state._unverifiedPageIcpClaim = false;
        return check;
      }
    }

    // 占位号无需远程结论即可确认是假号。
    if (placeholders.length && typeof NS.addSignal === "function") {
      const declaredLabel = placeholders.join(" / ");
      NS.addSignal(
        `假冒ICP备案信息：${declaredLabel}`,
        NS.UNVERIFIED_PAGE_ICP_CLAIM_WEIGHT,
        `页脚备案号 ${declaredLabel} 呈占位/伪造形态（如 11000000）`
      );
      state._unverifiedPageIcpClaim = true;
      if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
      return check;
    }

    if (!check.remoteFound && check.declared.length && typeof NS.addSignal === "function") {
      const declaredLabel = check.declared.join(" / ");
      const looksNormal = check.declared.some((d) => {
        const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
        return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}/i.test(n);
      });
      if (check.remoteMissing) {
        // 查询已完成并明确未备案：正常格式并不能证明号码属于当前域名，必须收口。
        if (typeof NS.clearPendingIcpClaimSignals === "function") NS.clearPendingIcpClaimSignals();
        NS.addSignal(
          `假冒ICP备案信息：${declaredLabel}`,
          NS.UNVERIFIED_PAGE_ICP_CLAIM_WEIGHT,
          `页面页脚声明 ${declaredLabel}，备案查询已确认当前域名无对应记录`
        );
        state._unverifiedPageIcpClaim = true;
        if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
      } else if (looksNormal) {
        // 查询失败/尚未结束：只保留低权待核验，不把网络失败误判成假备案。
        if (typeof NS.clearPendingIcpClaimSignals === "function") NS.clearPendingIcpClaimSignals();
        NS.addSignal(
          `备案待核验：${declaredLabel}`,
          8,
          `页脚声明 ${declaredLabel}，第三方查询尚未取得明确结论（请以工信部为准）`
        );
        state._unverifiedPageIcpClaim = false;
        if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
        if (typeof NS.clearFakeIcpClaimSignals === "function") NS.clearFakeIcpClaimSignals();
      } else {
        NS.addSignal(
          `假冒ICP备案信息：${declaredLabel}`,
          NS.UNVERIFIED_PAGE_ICP_CLAIM_WEIGHT,
          `页面页脚声明 ${declaredLabel}，域名未核验到对应备案`
        );
        state._unverifiedPageIcpClaim = true;
        if (typeof NS.clearMissingIcpSignal === "function") NS.clearMissingIcpSignal();
      }
    }
    return check;
  };

  /**
   * 高置信假备案（可硬拦截）须同时满足：
   * 1) 页脚有宣称且权威源明确 missing；
   * 2) 号呈占位/伪造形态，或 WHOIS 极新且号不像正常年份主体号。
   * 正常形态如 湘ICP备2024068964-3 仅第三方未命中时，不当高置信假冒。
   */
  NS.isHighConfidenceUnverifiedIcpThreat = function (check, ageDaysOpt) {
    try {
      if (!check || !check.unverifiedClaim || !check.remoteMissing) return false;
      const declared = Array.isArray(check.declared) ? check.declared : [];
      if (!declared.length) return false;
      const anyPlaceholder = declared.some((d) =>
        typeof NS.looksLikePlaceholderIcpLicense === "function" && NS.looksLikePlaceholderIcpLicense(d)
      );
      if (anyPlaceholder) return true;
      // 正常「省ICP备20xx…号-n」：第三方未命中可能是源滞后/竞速误杀，不硬拦
      const looksNormalYearBody = declared.some((d) => {
        const n = typeof NS.normalizeIcpLicense === "function" ? NS.normalizeIcpLicense(d) : String(d || "");
        return /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]ICP备20\d{2}\d{4,12}(?:号)?(?:-\d{1,4})?/i.test(n);
      });
      if (looksNormalYearBody) return false;
      const ageDays = ageDaysOpt == null ? NS.getWhoisAgeDays() : Number(ageDaysOpt);
      return !!(Number.isFinite(ageDays) && ageDays >= 0 && ageDays < 30);
    } catch {
      return false;
    }
  };

  /**
   * 假备案确认后：若主机是品牌夹带/拼写/连字符 squat（huorongr / huorong-lab），
   * 直接升级为品牌仿冒拦截与 toast，避免只显示「身份异常」而无「仿冒「Huorong」」。
   * （原仅 typo 路径；padded 单字母尾缀会漏升格，首屏只能再刷一次才出品牌弹窗）
   */
  NS.promoteUnverifiedIcpTypoToBrandSpoof = function () {
    try {
      const state = NS.state;
      if (NS.caches) {
        NS.caches._primaryKw = null;
        NS.caches._primaryKwAt = 0;
        NS.caches._primaryKwUrl = "";
      }
      const host = String(location.hostname || "").toLowerCase();
      const labelRaw = (host.replace(/^www\./, "").split(".")[0] || "").toLowerCase();
      const apex = (typeof NS.getRegistrableDomain === "function"
        ? NS.getRegistrableDomain(host) : host) || host;
      const apexLeft = (String(apex).split(".")[0] || "").toLowerCase();

      const rel = typeof NS.evaluateDomainKeywordRelevance === "function"
        ? NS.evaluateDomainKeywordRelevance(host)
        : null;

      // 夹带 / 拼写 / 连字符 / 营销垫形态（结构判定，不依赖 rel 是否已标 squat）
      let isSquatShape = !!(rel && rel.squat
        && /^(?:typo|padded|hyphen|partial)$/i.test(String(rel.hostMatch || "")));
      if (!isSquatShape) {
        try {
          if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && (NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeft)
              || NS.apexLabelLooksLikeMarketingPaddedBrand(labelRaw))) {
            isSquatShape = true;
          }
          if (!isSquatShape && typeof NS.inferMarketingPaddedBrandCore === "function") {
            const c0 = NS.inferMarketingPaddedBrandCore(labelRaw)
              || NS.inferMarketingPaddedBrandCore(apexLeft) || "";
            const flat = (apexLeft || labelRaw).replace(/[^a-z0-9]/g, "");
            if (c0.length >= 4 && flat && flat !== c0 && flat.includes(c0)) isSquatShape = true;
          }
          if (!isSquatShape && typeof NS.hostLabelIsPaddedBrand === "function") {
            const core = (typeof NS.resolveHostBrandCore === "function"
              ? NS.resolveHostBrandCore(host) : "") || "";
            if (core.length >= 4 && (
              NS.hostLabelIsPaddedBrand(labelRaw.replace(/-/g, ""), core)
              || NS.hostLabelIsPaddedBrand(apexLeft.replace(/-/g, ""), core)
            )) isSquatShape = true;
          }
        } catch { /* ignore */ }
      }
      if (!isSquatShape) return false;

      // 展示名：页内选举 → 主机剥核（Huorong / 火绒），禁止 Huorongr 域名自指
      let brand = "";
      try {
        if (typeof NS.pickBestSpoofDisplayBrand === "function") {
          brand = String(NS.pickBestSpoofDisplayBrand(
            (rel && (rel.brand || rel.brandToken)) || ""
          ) || "").trim();
        }
      } catch { /* ignore */ }
      if (!brand && rel) {
        brand = String(rel.brand || rel.brandToken || (rel.primary && rel.primary.display) || "").trim();
      }
      if ((!brand || brand.length < 2) && typeof NS.formatSpoofDisplayFromHostCore === "function") {
        try { brand = String(NS.formatSpoofDisplayFromHostCore(host) || "").trim(); } catch { /* ignore */ }
      }
      if (brand && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
        brand = NS.canonicalizeBrandDisplayCandidate(brand) || brand;
      }
      try {
        if (brand && typeof NS.isHostShapedCompoundBrandToken === "function"
          && NS.isHostShapedCompoundBrandToken(brand, host)) {
          brand = "";
          if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
            brand = String(NS.formatSpoofDisplayFromHostCore(host) || "").trim();
          }
        }
      } catch { /* ignore */ }
      if (!brand || brand.length < 2) return false;

      const matchHint = (rel && rel.hostMatch === "typo") ? "拼写仿冒"
        : (rel && rel.hostMatch === "hyphen") ? "连字符拆分品牌"
          : "域名夹带品牌前缀/后缀";
      const expected = String((rel && rel.brandToken) || "").trim();
      // ★ 先定稿再展示（假备案升格同样不先弹 Dingding）
      if (typeof NS.commitBrandSpoofPresentation === "function") {
        NS.commitBrandSpoofPresentation({
          brand,
          host,
          matchHint,
          lockHard: true,
          signalDetail: `页面品牌与域名 ${host} 不匹配（${matchHint}${expected ? `；核 ${expected}` : ""}）；假备案 + 新注册域`
        });
      } else {
        state.spoofBrand = brand;
        state._brandSpoofPortalDetected = true;
      }
      return true;
    } catch {
      return false;
    }
  };

  NS.enforceUnverifiedPageIcpDownloadBlock = function (check, ageDaysOpt) {
    const state = NS.state;
    const highConfidence = NS.isHighConfidenceUnverifiedIcpThreat(check, ageDaysOpt);
    state._unverifiedIcpIdentityThreat = highConfidence;
    if (!highConfidence) return false;
    // 优先品牌仿冒（padded/typo/hyphen）；成功则不再弹「身份异常」笼统 toast
    if (NS.promoteUnverifiedIcpTypoToBrandSpoof()) {
      try { NS.disableAllDownloadIntentControls(); } catch { /* ignore */ }
      return true;
    }
    // 已是 brand-spoof：补发品牌通知，勿被 site-identity 盖掉
    if (state._brandSpoofPortalDetected || state.spoofBrand) {
      try {
        if (typeof NS.ensureBrandSpoofNotice === "function") NS.ensureBrandSpoofNotice(false);
      } catch { /* ignore */ }
      try { NS.disableAllDownloadIntentControls(); } catch { /* ignore */ }
      return true;
    }
    if (state.downloadGuardInstalled) {
      try { NS.disableAllDownloadIntentControls(); } catch { /* ignore */ }
      return true;
    }
    const host = String(location.hostname || "当前域名").toLowerCase();
    const declared = (check.declared || []).join(" / ") || state.pageDeclaredIcp || "未知备案号";
    if (typeof NS.installDownloadGuard === "function") {
      NS.installDownloadGuard("新注册域名冒用ICP备案号，已拦截页面下载入口", {
        notify: true,
        title: "已拦截身份异常网站下载",
        message: `域名 ${host} 未查询到备案记录，但页面声明 ${declared}`,
        guardKind: "site-identity",
        forceNotify: true,
        lockHard: true
      });
    }
    try { if (typeof NS.disableAllDownloadIntentControls === "function") NS.disableAllDownloadIntentControls(); } catch { /* ignore */ }
    // 身份异常 arm 后仍尝试一次品牌升格（DOM 晚到时 rel 可能本拍为空）
    try {
      setTimeout(() => {
        try {
          if (NS.state && !NS.state._brandSpoofPortalDetected) {
            NS.promoteUnverifiedIcpTypoToBrandSpoof();
          }
        } catch { /* ignore */ }
      }, 400);
    } catch { /* ignore */ }
    return true;
  };

  NS.hasValidIcpRecord = function () {
    try {
      const s = String(NS.state.icpInfo || "").trim();
      // 假冒 / 待核验 / 未查询到 绝不当「有效备案」
      if (!s || /未查询到|查询失败|暂无|假冒|无ICP|宣称|待核验/i.test(s)) return false;
      if (NS.state._unverifiedPageIcpClaim) return false;
      if (NS.state.icpMatchedHost && !NS.intelHostIsValidAttribution(NS.state.icpMatchedHost, location.hostname)) return false;
      // 需像备案号（排除纯说明文案）
      if (typeof NS.looksLikeIcpLicense === "function" && !NS.looksLikeIcpLicense(s)
        && !/ICP|备案/i.test(s)) return false;
      return true;
    } catch { return false; }
  };

  /** 是否有可展示的组织字段；证书等级本身可在没有组织名时单独展示。 */
  NS.isDisplayableOrganizationSslInfo = function (info) {
    try {
      const v = String((info && info.validation) || "").toUpperCase();
      if (v !== "OV" && v !== "EV") return false;
      if (!String((info && info.organization) || "").trim()) return false;
      if (v === "EV") return true;
      return info.sniChainVerified === true || info.liveTlsLeafVerified === true
        || info.unexpiredHostVerified === true;
    } catch { return false; }
  };

  /** 是否具备可展示的组织级 SSL——用于隐藏「未查询到备案」文案 */
  NS.hasOrganizationValidatedSsl = function () {
    try {
      return NS.isDisplayableOrganizationSslInfo(NS.state.sslInfo);
    } catch { return false; }
  };

  /** A fallback ICP rejected for lack of exact WHOIS must stay visible. */
  NS.shouldPreserveForcedMissingIcp = function () {
    try {
      const state = NS.state || {};
      if (state._icpForcedMissingByFallbackWhois !== true) return false;
      const currentHost = typeof NS.normalizeHostForIntel === "function"
        ? NS.normalizeHostForIntel(location.hostname)
        : String(location.hostname || "").trim().toLowerCase().replace(/\.+$/g, "");
      const forcedHost = typeof NS.normalizeHostForIntel === "function"
        ? NS.normalizeHostForIntel(state._icpForcedMissingHost || "")
        : String(state._icpForcedMissingHost || "").trim().toLowerCase().replace(/\.+$/g, "");
      return !!currentHost && forcedHost === currentHost;
    } catch { return false; }
  };

  /**
   * 当前主机已绑定的组织证书。EV 也必须有实时叶证书/SNI 链/未过期且
   * CN·SAN 命中之一，不能只凭 CT 列表里的 validation 与 O= 取得站点身份。
   */
  NS.hasBoundOrganizationValidatedSsl = function (infoOpt) {
    try {
      const info = infoOpt || (NS.state && NS.state.sslInfo) || null;
      if (!info || !/^(?:OV|EV)$/i.test(String(info.validation || ""))) return false;
      const org = String(info.organization || "").trim();
      if (!org || /internet\s*widgits|some[-\s]?state|default\s+company/i.test(org)) return false;
      const currentHost = String((typeof location !== "undefined" && location.hostname) || "")
        .toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
      const infoHost = String(info.host || info.queriedHost || "")
        .toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
      if (currentHost && infoHost !== currentHost) return false;
      return info.sniChainVerified === true || info.liveTlsLeafVerified === true
        || info.unexpiredHostVerified === true;
    } catch { return false; }
  };

  /**
   * 页面主品牌与注册域根的组织级关系证据。
   * 允许 brand.com 与 brand+非营销名称.com（页面候选主动确认），拒绝
   * brand-docs / brand-download / 单字符污染等仿冒常见形态；域名不生成品牌。
   */
  NS.pageBrandIdentityAlignsOrganizationApex = function (hostOpt) {
    try {
      const host = typeof NS.normalizeDomain === "function"
        ? NS.normalizeDomain(hostOpt || location.hostname)
        : String(hostOpt || location.hostname || "").toLowerCase().replace(/^www\./, "");
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host) || host;
      const apexRaw = String(apex.split(".")[0] || "").toLowerCase();
      const apexFlat = apexRaw.replace(/[^a-z0-9]/g, "");
      if (!apexFlat || /[-_]/.test(apexRaw)) return false;
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(apexRaw)) return false;

      const slots = [
        { primary: true, text: document.title || "" },
        { primary: true, text: document.querySelector("h1")?.textContent || "" },
        { primary: true, text: document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "" },
        { primary: true, text: document.querySelector('meta[name="application-name"]')?.getAttribute("content") || "" },
        { primary: true, text: document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "" },
        { primary: false, text: document.querySelector(".logo, [class*='logo']")?.textContent || "" }
      ].map((slot) => ({ ...slot, text: String(slot.text || "").trim() })).filter((slot) => slot.text);
      if (!slots.length) return false;
      const candidates = new Map();
      slots.forEach((slot) => (slot.text.match(/[A-Za-z][A-Za-z0-9]{3,23}/g) || []).forEach((raw) => {
        const token = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (token.length < 4 || token.length > 20) return;
        if (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(token)) return;
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(token)) return;
        const prev = candidates.get(token) || { sources: 0, primary: 0, lead: 0 };
        prev.sources += 1;
        if (slot.primary) prev.primary += 1;
        const at = slot.text.toLowerCase().indexOf(raw.toLowerCase());
        if (slot.primary && at >= 0 && at <= 24) prev.lead += 1;
        candidates.set(token, prev);
      }));
      const structural = /^(?:docs?|documentation|help|support|manual|soft|safe|downloads?|client|setup|install(?:er)?|official|free|apps?|desktop|services?|pc|win|vip|pro)$/i;
      return Array.from(candidates.entries()).some(([brand, evidence]) => {
        // 页面强候选：至少处于一个主身份槽的前部，或由两个独立身份槽复现。
        if (!(evidence.lead >= 1 || (evidence.primary >= 2 && evidence.sources >= 2))) return false;
        if (brand === apexFlat) return true;
        let affix = "";
        if (apexFlat.startsWith(brand)) affix = apexFlat.slice(brand.length);
        else if (apexFlat.endsWith(brand)) affix = apexFlat.slice(0, apexFlat.length - brand.length);
        else return false;
        if (affix.length < 3 || affix.length > 14 || structural.test(affix)) return false;
        if (typeof NS.isMarketingHostPrefixToken === "function"
          && NS.isMarketingHostPrefixToken(affix, { strict: true })) return false;
        return /^[a-z][a-z0-9]+$/i.test(affix)
          && apexFlat.length <= Math.max(brand.length + 6, brand.length * 3);
      });
    } catch { return false; }
  };

  /** 写入报告用的 ICP 文案：取得可展示的组织字段时才隐藏「未查询到备案信息」 */
  NS.formatIcpInfoForReport = function (icpRaw) {
    try {
      const s = String(icpRaw != null ? icpRaw : (NS.state && NS.state.icpInfo) || "").trim();
      if (!s) return "";
      if (/未查询到|查询失败|暂无/.test(s) && NS.hasOrganizationValidatedSsl()
        && !NS.shouldPreserveForcedMissingIcp()) return "";
      return s;
    } catch {
      return String(icpRaw || "");
    }
  };

  function sslValidationRank(v) {
    const u = String(v || "").toUpperCase();
    if (u === "EV") return 3;
    if (u === "OV") return 2;
    if (u === "DV") return 1;
    return 0;
  }

  const SSL_IDENTITY_WATCHDOG_MS = 26000;

  /**
   * TLS is one input of the provisional download-route controller.  Wake that
   * controller on every terminal TLS path instead of making it wait for its
   * 250ms polling timer (which Edge may heavily throttle in a background tab).
   */
  function announceSslIdentitySettlement(reason) {
    try {
      if (typeof NS.recoverIdentityVerificationAvailability === "function") {
        NS.recoverIdentityVerificationAvailability(reason || "ssl-identity-settled");
      }
    } catch { /* ignore */ }
    try {
      if (typeof NS.nudgeProvisionalDownloadSettlement === "function") {
        NS.nudgeProvisionalDownloadSettlement(reason || "ssl-identity-settled");
      }
    } catch { /* ignore */ }
    try {
      const currentUrl = String(location.href || "");
      const intelReady = NS.state && NS.state._icpQuerySettled === true
        && NS.caches && NS.caches.intelDoneForUrl === currentUrl;
      if (intelReady && typeof NS.markAnalysisComplete === "function") {
        // This also lets the explicit unavailable terminal replace a popup's
        // previous waiting snapshot when a normal (non-/download) tab was
        // frozen until the TLS watchdog fired.
        NS.markAnalysisComplete(reason || "ssl-identity-settled");
      } else if (typeof NS.emitRiskReport === "function") {
        NS.emitRiskReport(true);
      }
    } catch { /* ignore */ }
  }

  function settleImmediateSslIdentity(reason, observed) {
    try {
      const state = NS.state;
      // An immediate terminal path supersedes any older in-flight callback for
      // the same URL.  Rotate the token as well as the timestamp so that a
      // cached/non-HTTPS decision cannot later be overwritten by that callback.
      state._sslIdentityRequestToken = Number(state._sslIdentityRequestToken || 0) + 1;
      state._sslIdentityUrl = String(location.href || "");
      state._sslIdentityStartedAt = Date.now();
      state._sslIdentityObserved = observed === true;
      state._sslIdentitySettled = true;
      state._sslIdentityTimedOut = false;
    } catch { /* still wake the provisional controller below */ }
    announceSslIdentitySettlement(reason);
  }

  /** 已废弃：不再提前写 DV 占位（探测完成前不展示 SSL） */
  NS.ensureSslPlaceholder = function () { /* no-op */ };

  /** 应用 background 推送/查询到的 SSL 证书分类（只升不降；force 仅表示重查，不允许降级） */
  NS.applySslCertInfo = function (info, force) {
    try {
      if (!info || typeof info !== "object") return false;
      const src = String(info.source || "");
      // 旧空占位拒绝；https-assumed 是 CT 失败后的合法 HTTPS 回退
      if (src === "page-https" || src === "https-reachability") return false;
      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      const infoHost = String(info.host || "").toLowerCase().replace(/^www\./, "");
      if (infoHost && host && infoHost !== host) return false;
      let nextVal = String(info.validation || "").toUpperCase();
      if (!/^(DV|OV|EV)$/.test(nextVal)) return false;
      const prev = NS.state.sslInfo;
      const dirtyOrg = (o) => /internet\s*widgits|some[-\s]?state|default\s+company/i.test(String(o || ""));
      const unboundOv = (validation, sniChainVerified, liveTlsLeafVerified, unexpiredHostVerified) => String(validation || "").toUpperCase() === "OV"
        && sniChainVerified !== true && liveTlsLeafVerified !== true && unexpiredHostVerified !== true;
      // OpenSSL 占位 O= 不当组织证书；未绑定 SNI 的 OV 保留等级、只清空组织名
      if (dirtyOrg(info.organization)) {
        if (nextVal === "OV" || nextVal === "EV") nextVal = "DV";
      }
      // 旧结果是占位 OV（Internet Widgits）：允许被正确 DV 覆盖
      const prevBogusOv = prev && dirtyOrg(prev.organization)
        && sslValidationRank(prev.validation) >= 2;
      // 禁止用弱 DV 覆盖已识别的 OV/EV（脏占位 OV 除外）
      if (prev && sslValidationRank(prev.validation) > sslValidationRank(nextVal)
        && !prevBogusOv) {
        return false;
      }
      // 禁止用 https-assumed 覆盖已有 CT/Labs 结果
      if (!force && prev && prev.validation && prev.source && prev.source !== "https-assumed"
        && src === "https-assumed") {
        return false;
      }
      // 同级时保留已有机构名；但拒绝把未绑定实时叶证书的 OV / OpenSSL 占位 org 粘住
      let org = String(info.organization || "").trim();
      if (dirtyOrg(org) || unboundOv(info.validation, info.sniChainVerified, info.liveTlsLeafVerified, info.unexpiredHostVerified)) org = "";
      if (!org && prev && prev.organization && sslValidationRank(prev.validation) === sslValidationRank(nextVal)) {
        if (!dirtyOrg(prev.organization)
          && !unboundOv(prev.validation, prev.sniChainVerified, prev.liveTlsLeafVerified, prev.unexpiredHostVerified)) {
          org = prev.organization;
        }
      }
      // 新结果无 org 但旧结果是脏 CDN/占位 org：清空
      if (!org && prev && (dirtyOrg(prev.organization)
        || unboundOv(prev.validation, prev.sniChainVerified, prev.liveTlsLeafVerified, prev.unexpiredHostVerified))) org = "";
      const finalVal = nextVal;
      NS.state.sslInfo = {
        validation: finalVal,
        organization: org,
        commonName: String(info.commonName || (prev && prev.commonName) || host).trim(),
        state: String(info.state || "secure"),
        fingerprintSha256: String(info.fingerprintSha256 || ""),
        host: infoHost || host,
        at: Number(info.at) || Date.now(),
        limited: !!info.limited,
        source: src || "probe",
        sniChainVerified: info.sniChainVerified === true,
        liveTlsLeafVerified: info.liveTlsLeafVerified === true,
        unexpiredHostVerified: info.unexpiredHostVerified === true,
        assumed: !!info.assumed || src === "https-assumed"
      };
      // 身份裁决不能把「有效 ICP 已返回」误当成整条身份链已结束。
      // 记录 TLS 侧至少已有一次可用结果；OV/EV 组织证书可立即闭环，DV
      // 仍允许 background 的延迟升级链继续把结果提升为 OV/EV。
      try {
        NS.state._sslIdentityUrl = String(location.href || "");
        NS.state._sslIdentityObserved = true;
        // background 的单次 resolve 已跑完当前源集合；DV 也是本轮最终响应。
        // 后台仍可异步升级 OV/EV，届时 apply 会再次触发权威身份闭环。
        NS.state._sslIdentitySettled = true;
        NS.state._sslIdentityTimedOut = false;
      } catch { /* ignore */ }
      // mature profile 的旧缓存可能是在 DV/无证书阶段生成；证书升级后必须立即失效。
      try {
        if (NS.caches) {
          NS.caches._matureLegitProfile = null;
          NS.caches._matureLegitProfileKey = "";
          NS.caches._matureLegitProfileAt = 0;
        }
      } catch { /* ignore */ }
      // OV/EV 时清掉「未查询到备案」展示与软信号
      if (NS.hasOrganizationValidatedSsl() && !NS.shouldPreserveForcedMissingIcp()) {
        if (/未查询到|查询失败|暂无/.test(String(NS.state.icpInfo || ""))) {
          NS.state.icpInfo = "";
        }
        try {
          NS.state.details = (NS.state.details || []).filter((d) => d && d.name !== "无ICP备案信息");
          if (NS.state.signalSet && typeof NS.state.signalSet.forEach === "function") {
            const drop = [];
            NS.state.signalSet.forEach((k) => {
              if (/无ICP备案/i.test(String(k))) drop.push(k);
            });
            drop.forEach((k) => NS.state.signalSet.delete(k));
          }
          NS.state.score = (NS.state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
        } catch { /* ignore */ }
      }
      // ICP/WHOIS 常先到、OV/EV 后到。晚到的组织证书必须补跑一次身份闭环，
      // 否则主动探测留下的软仿冒锁会永久粘住。
      try {
        const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
          ? NS.evaluateMatureLegitimateSiteProfile() : null;
        const authoritative = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
          && NS.hasAuthoritativeMatureOrganizationIdentity(profile);
        if (authoritative && typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
          NS.forceLiftSoftProtectionForTrustedPortal("ssl-identity-upgrade");
        } else if (NS.state._analysisCompletionDeferredForBrand
          && typeof NS.markAnalysisComplete === "function") {
          NS.markAnalysisComplete("ssl-identity-settled");
        }
      } catch { /* ignore */ }
      announceSslIdentitySettlement("ssl-info-applied");
      try { NS.emitRiskReport(true); } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  /** 向 background 拉取当前主机证书分类（CT + Subject 解析）；完成前不展示 SSL */
  NS.requestSslCertInfo = function (force) {
    try {
      if (!chrome?.runtime?.id) {
        settleImmediateSslIdentity("ssl-runtime-unavailable", false);
        return;
      }
      if (!/^https:/i.test(String(location.protocol || ""))) {
        NS.state.sslInfo = null;
        settleImmediateSslIdentity("ssl-non-https", true);
        return;
      }
      // 保留 www：www.gov.cn 叶子是 *.www.gov.cn，剥掉 www 会整链 miss → 假 DV
      const host = (location.hostname || "").toLowerCase();
      // 已是 OV/EV 且非强制则不重查（无机构名的 OV 仍允许再探补 O=）
      if (!force && NS.hasOrganizationValidatedSsl && NS.hasOrganizationValidatedSsl()) {
        const org = String((NS.state.sslInfo && NS.state.sslInfo.organization) || "").trim();
        if (org) {
          settleImmediateSslIdentity("ssl-cache-organization", true);
          try { NS.emitRiskReport(true); } catch { /* ignore */ }
          return;
        }
      }
      // 已是 EV：不重复。OV/DV/assumed 允许再请求（升 EV 或纠正误判）
      if (!force && NS.state.sslInfo && NS.state.sslInfo.validation) {
        const v = String(NS.state.sslInfo.validation || "").toUpperCase();
        const src = String(NS.state.sslInfo.source || "");
        const org = String(NS.state.sslInfo.organization || "").trim();
        if (v === "EV" && org && src !== "page-https" && src !== "https-reachability") {
          settleImmediateSslIdentity("ssl-cache-ev", true);
          return;
        }
        // OV 有机构名：短时内跳过；无机构名必须继续探
        if (v === "OV" && org && !force && NS.state.sslInfo.at
          && Date.now() - Number(NS.state.sslInfo.at) < 1500) {
          settleImmediateSslIdentity("ssl-cache-ov", true);
          return;
        }
        // DV 短时内仍允许 force 升级；非 force 时 1.5s 内不重复刷
        if (v === "DV" && src !== "https-assumed" && src !== "page-https"
          && src !== "https-reachability" && !force && NS.state.sslInfo.at
          && Date.now() - Number(NS.state.sslInfo.at) < 1500) {
          settleImmediateSslIdentity("ssl-cache-dv", true);
          return;
        }
      }
      const requestUrl = String(location.href || "");
      const requestStartedAt = Date.now();
      const requestToken = Number(NS.state._sslIdentityRequestToken || 0) + 1;
      NS.state._sslIdentityRequestToken = requestToken;
      NS.state._sslIdentityUrl = requestUrl;
      NS.state._sslIdentityStartedAt = requestStartedAt;
      NS.state._sslIdentityObserved = false;
      NS.state._sslIdentitySettled = false;
      NS.state._sslIdentityTimedOut = false;

      let watchdogTimer = null;
      let settlementAnnounced = false;
      const watchdogDeadline = requestStartedAt + SSL_IDENTITY_WATCHDOG_MS;
      const isCurrentRequest = () => {
        try {
          return String(location.href || "") === requestUrl
            && String(NS.state._sslIdentityUrl || "") === requestUrl
            && Number(NS.state._sslIdentityStartedAt || 0) === requestStartedAt
            && Number(NS.state._sslIdentityRequestToken || 0) === requestToken;
        } catch { return false; }
      };
      const settleCurrentRequest = (reason, observed, timedOut) => {
        if (!isCurrentRequest()) return false;
        NS.state._sslIdentityObserved = observed === true;
        NS.state._sslIdentitySettled = true;
        NS.state._sslIdentityTimedOut = timedOut === true;
        if (timedOut === true) {
          NS.state._identityVerificationUnavailable = true;
          NS.state._identityVerificationUnavailableUrl = requestUrl;
        }
        if (!settlementAnnounced) {
          settlementAnnounced = true;
          announceSslIdentitySettlement(reason || "ssl-identity-query-settled");
        }
        return true;
      };
      const clearWatchdog = () => {
        if (!watchdogTimer) return;
        try { clearTimeout(watchdogTimer); } catch { /* ignore */ }
        watchdogTimer = null;
      };
      const watchdog = () => {
        if (!isCurrentRequest()) { clearWatchdog(); return; }
        const remaining = watchdogDeadline - Date.now();
        if (remaining > 0) {
          watchdogTimer = setTimeout(watchdog, remaining);
          return;
        }
        clearWatchdog();
        NS.silverfoxLog && NS.silverfoxLog("intel-ssl", "content-watchdog", host, requestUrl);
        // The background probe may still deliver a stronger late result.  This
        // only ends the waiting state; it does not fabricate a certificate.
        settleCurrentRequest("ssl-identity-watchdog", !!NS.state.sslInfo, true);
      };
      watchdogTimer = setTimeout(watchdog, SSL_IDENTITY_WATCHDOG_MS);

      try {
        chrome.runtime.sendMessage({
          type: "get-ssl-cert",
          host,
          force: !!force,
          https: true
        }, (resp) => {
          const err = chrome.runtime.lastError;
          let observed = false;
          try {
            // soft-nav 或后发强制补查已开始：旧响应不得结算新 URL/新一轮。
            if (!isCurrentRequest()) return;
            if (resp && resp.success && resp.sslInfo) {
              // Only a real certificate response supersedes the watchdog's
              // settled-unknown state. A late failure is still unavailable.
              NS.state._sslIdentityTimedOut = false;
              const applied = NS.applySslCertInfo(resp.sslInfo, !!force) === true;
              // A weaker/stale-grade result may be deliberately rejected while
              // a stronger certificate already exists.  The request still
              // reached a terminal response and must settle.
              observed = applied || !!NS.state.sslInfo;
            } else {
              // runtimeError / API 失败同样是“本轮 TLS 已结束”，不能让所有
              // DV 或离线页面永久卡在品牌身份待定。
              void err;
              observed = !!NS.state.sslInfo;
            }
          } catch { observed = !!NS.state.sslInfo; }
          finally {
            clearWatchdog();
            settleCurrentRequest(
              resp && resp.success && resp.sslInfo
                ? "ssl-identity-query-response"
                : "ssl-identity-query-failed",
              observed,
              !(resp && resp.success && resp.sslInfo)
            );
          }
        });
      } catch {
        clearWatchdog();
        settleCurrentRequest("ssl-identity-send-failed", !!NS.state.sslInfo, true);
      }
    } catch {
      settleImmediateSslIdentity("ssl-identity-request-error", !!(NS.state && NS.state.sslInfo));
    }
  };

  /** 纯 WHOIS 年龄 ≥10 年（百度/pcsoft 等）——不因套件标志失效 */
  NS.isWhoisAgeUltraMature = function () {
    try {
      const days = NS.getWhoisAgeDays();
      return days != null && days >= 3650;
    } catch { return false; }
  };

  /** 真硬套件（SEO 壳/强制弹窗/乱码包）——超成熟域也仅这三类可继续锁 */
  NS.hasRealHardKitThreat = function () {
    try {
      const state = NS.state;
      return !!(state._seoCloakKitDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected || state._indexNowPhishTemplate);
    } catch { return false; }
  };

  NS.looksLikeUltraMatureIcpDomain = function () {
    try {
      if (!NS.hasValidIcpRecord()) return false;
      const days = NS.getWhoisAgeDays();
      if (days == null || days < 3650) return false;
      const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      return !!(profile && profile.trusted);
    } catch { return false; }
  };

  NS.looksLikeUltraMatureWhoisDomain = function () {
    try {
      if (!(typeof NS.isWhoisAgeUltraMature === "function" && NS.isWhoisAgeUltraMature())) return false;
      const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      return !!(profile && profile.trusted);
    } catch { return false; }
  };

  NS.looksLikeLongLivedWhoisDomain = function () {
    try {
      const days = NS.getWhoisAgeDays();
      if (days == null || days < 1825) return false;
      const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      return !!(profile && profile.trusted);
    } catch { return false; }
  };

  /**
   * 主机是否公开代码托管/发行平台（基础设施域结构，非产品品牌名单）。
   * 含 releases CDN（githubusercontent）与 pages（github.io / gitlab.io）。
   */
  NS.hostLooksLikePublicCodeForge = function (hostname) {
    try {
      const h = String(hostname || "").toLowerCase().replace(/^www\./, "");
      if (!h || h.length < 4) return false;
      if (/(?:^|\.)github\.com$/i.test(h)) return true;
      if (/(?:^|\.)githubusercontent\.com$/i.test(h)) return true;
      if (/(?:^|\.)github\.io$/i.test(h)) return true;
      if (/(?:^|\.)gitlab\.com$/i.test(h)) return true;
      if (/(?:^|\.)gitlab\.io$/i.test(h)) return true;
      if (/(?:^|\.)gitee\.com$/i.test(h)) return true;
      if (/(?:^|\.)gitcode\.(?:com|net)$/i.test(h)) return true;
      if (/(?:^|\.)codeberg\.org$/i.test(h)) return true;
      if (/(?:^|\.)bitbucket\.org$/i.test(h)) return true;
      if (/(?:^|\.)(?:sourceforge|sf)\.net$/i.test(h)) return true;
      if (/(?:^|\.)(?:git\.)?sr\.ht$/i.test(h)) return true;
      if (/(?:^|\.)sourcehut\.org$/i.test(h)) return true;
      return false;
    } catch { return false; }
  };

  /** 路径是否像仓库/发行页（/owner/repo、/releases、/-/releases…），避免仅链到平台首页 */
  NS.pathLooksLikePublicCodeRepoOrRelease = function (pathname) {
    try {
      const p = String(pathname || "").replace(/\/+$/, "") || "/";
      if (p === "/" || p.length < 3) return false;
      if (/\/releases?(?:\/|$)/i.test(p)) return true;
      if (/\/-\/releases?(?:\/|$)/i.test(p)) return true;
      if (/\/archive\//i.test(p)) return true;
      if (/\/download(?:s)?(?:\/|$)/i.test(p) && /\/(?:repo|project|p)\//i.test(p)) return true;
      // /owner/repo 或更深（排除纯用户主页单段）
      const segs = p.split("/").filter(Boolean);
      if (segs.length >= 2) {
        const a = segs[0];
        const b = segs[1];
        if (/^(?:settings|login|signup|explore|topics|marketplace|pricing|features|about|orgs|organizations|dashboard|notifications|search)$/i.test(a)) {
          return false;
        }
        if (a.length >= 1 && b.length >= 1 && !/^(?:http|https)$/i.test(a)) return true;
      }
      return false;
    } catch { return false; }
  };

  /**
   * 页内用于对齐代码仓的品牌核（拉丁/主机核），不写死具体产品名单。
   * 来源：等权品牌关键词 + 主机标签/产品线首段。
   */
  NS.collectPageBrandTokensForForgeAlign = function () {
    const out = [];
    const seen = new Set();
    const push = (raw, minLen) => {
      const t = String(raw || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const min = minLen != null ? minLen : 3;
      if (!t || t.length < min || t.length > 32) return;
      if (/^(?:com|net|org|www|http|https|html|download|release|releases|official|software|security|antivirus|client|setup|install|github|gitlab|gitee|codeberg|bitbucket)$/i.test(t)) return;
      if (seen.has(t)) return;
      seen.add(t);
      out.push(t);
    };
    try {
      if (typeof NS.collectPrimaryBrandKeywords === "function") {
        const pk = NS.collectPrimaryBrandKeywords();
        if (pk) {
          push(pk.display, 3);
          (pk.latin || []).forEach((x) => push(x, 3));
          (pk.tokens || []).forEach((x) => {
            if (/^[a-z0-9][a-z0-9._-]{2,}$/i.test(String(x || "")) || /[A-Za-z]{3,}/.test(String(x || ""))) {
              push(x, 3);
            }
          });
        }
      }
    } catch { /* ignore */ }
    try {
      if (typeof NS.resolveSpoofDisplayBrand === "function") {
        push(NS.resolveSpoofDisplayBrand(location.hostname), 3);
      }
    } catch { /* ignore */ }
    try {
      const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const label = labelRaw.replace(/[^a-z0-9]/g, "");
      push(label, 4);
      // 连字符产品线：pyas-security → pyas
      if (/-/.test(labelRaw)) {
        labelRaw.split(/[-_]/).forEach((seg) => push(seg, 3));
        if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function") {
          const head = (labelRaw.split(/[-_]/)[0] || "").replace(/[^a-z0-9]/g, "");
          if (head.length >= 3 && NS.hostLabelIsBrandProductCategoryDomain(labelRaw, head)) push(head, 3);
        }
      }
      if (typeof NS.resolveHostBrandCore === "function") {
        push(NS.resolveHostBrandCore(host), 4);
      }
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const core = NS.inferMarketingPaddedBrandCore(labelRaw) || "";
        // 产品线域 infer 常返回空；夹带核仅作补充
        if (core) push(core, 4);
      }
    } catch { /* ignore */ }
    // 长 token 优先，短 token 靠后（匹配时仍全试）
    out.sort((a, b) => b.length - a.length);
    return out;
  };

  /**
   * 代码仓/发行 URL 是否与品牌核强相关：
   * owner、repo、路径段或文件名须完整包含品牌 token（≥4 字母优先；3 字母须整段相等）。
   * 防止页脚随手链一个无关 GitHub 组织却洗白仿冒站。
   */
  NS.forgeUrlStronglyAlignedWithBrandTokens = function (href, brandTokensOpt) {
    try {
      const tokens = Array.isArray(brandTokensOpt) && brandTokensOpt.length
        ? brandTokensOpt
        : NS.collectPageBrandTokensForForgeAlign();
      if (!tokens.length) return false;
      let u;
      try { u = new URL(String(href || ""), location.href); } catch { return false; }
      if (!NS.hostLooksLikePublicCodeForge(u.hostname)) return false;

      const hostFlat = u.hostname.toLowerCase().replace(/[^a-z0-9.]/g, "");
      const segs = (u.pathname || "").split("/").filter(Boolean).map((s) => s.toLowerCase().replace(/[^a-z0-9._-]/g, ""));
      const pathFlat = segs.join("/");
      const fileName = (typeof NS.getFilenameFromUrl === "function"
        ? NS.getFilenameFromUrl(u.href) : (segs[segs.length - 1] || "")).toLowerCase();
      const fileFlat = fileName.replace(/[^a-z0-9]/g, "");
      // owner / repo 优先（github.com/owner/repo/...）
      const owner = segs[0] || "";
      const repo = segs[1] || "";
      const ownerFlat = owner.replace(/[^a-z0-9]/g, "");
      const repoFlat = repo.replace(/[^a-z0-9]/g, "");
      // github.io：user.github.io/project
      const hostLeft = (u.hostname.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");

      const strongHit = (tok) => {
        const t = String(tok || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!t || t.length < 3) return false;
        // 3 字母：必须整段相等（owner/repo/文件主名），防误命中
        if (t.length === 3) {
          return ownerFlat === t || repoFlat === t || hostLeft === t
            || segs.some((s) => s.replace(/[^a-z0-9]/g, "") === t)
            || fileFlat === t || fileFlat.startsWith(t);
        }
        // ≥4：owner/repo/路径/主机/文件名 包含品牌核
        if (ownerFlat === t || repoFlat === t || ownerFlat.includes(t) || repoFlat.includes(t)) return true;
        if (hostLeft === t || hostLeft.includes(t)) return true;
        if (pathFlat.replace(/[^a-z0-9]/g, "").includes(t)) return true;
        if (fileFlat.includes(t)) return true;
        if (hostFlat.includes(t) && !/github|gitlab|gitee|codeberg|bitbucket|sourceforge|githubusercontent/.test(t)) {
          return hostLeft.includes(t);
        }
        return false;
      };

      // 优先用较长品牌核命中
      for (let i = 0; i < tokens.length; i++) {
        if (strongHit(tokens[i])) return true;
      }
      return false;
    } catch { return false; }
  };

  /**
   * 从 DOM 锚点 + HTML 切片收集候选 forge URL（document_start 时 links 可能仍空）。
   */
  NS.collectPublicCodeForgeHrefCandidates = function (limitOpt) {
    const out = [];
    const seen = new Set();
    const push = (raw) => {
      if (!raw || raw.startsWith("#") || raw.startsWith("javascript:")) return;
      let abs = "";
      try { abs = new URL(String(raw), location.href).href; } catch { return; }
      if (seen.has(abs)) return;
      let u;
      try { u = new URL(abs); } catch { return; }
      if (!/^https?:$/i.test(u.protocol)) return;
      if (!NS.hostLooksLikePublicCodeForge(u.hostname)) return;
      seen.add(abs);
      out.push(abs);
    };
    try {
      const limit = Math.min(Math.max(Number(limitOpt) || 160, 40), 240);
      const anchors = document.links || document.querySelectorAll("a[href]");
      const n = Math.min(anchors.length || 0, limit);
      for (let i = 0; i < n; i++) {
        const a = anchors[i];
        push((a && (a.getAttribute("href") || a.href)) || "");
        if (out.length >= limit) return out;
      }
      // 锚点未挂载时扫 HTML（含 github.com/.../releases/download/...）
      if (out.length < 4) {
        const html = typeof NS.getHtmlSlice === "function"
          ? NS.getHtmlSlice(90000)
          : String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 90000);
        const re = /https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|gitee\.com|codeberg\.org|bitbucket\.org|gitcode\.(?:com|net)|(?:git\.)?sr\.ht|sourceforge\.net|objects\.githubusercontent\.com)[^\s"'<>]{4,220}/gi;
        let m;
        while ((m = re.exec(html)) !== null && out.length < limit) {
          push(m[0].replace(/[),.;]+$/, ""));
        }
      }
    } catch { /* ignore */ }
    return out;
  };

  /**
   * 页内是否出现「与品牌强相关」的公开代码仓链接。
   * 仅 forge 主机不够：owner/repo（或发行路径）须含页内品牌核。
   * 注意：否定结果不长缓存（document_start 时尚无 DOM 会假阴性）。
   */
  NS.pageHasPublicCodeForgePresence = function () {
    try {
      const c = NS.caches || {};
      const now = Date.now();
      const href0 = location.href || "";
      // 仅缓存阳性；阴性最多 400ms，避免早扫锁死
      if (c._forgePresenceCache === true && c._forgePresenceUrl === href0 && now - (c._forgePresenceAt || 0) < 8000) {
        return true;
      }
      if (c._forgePresenceCache === false && c._forgePresenceUrl === href0 && now - (c._forgePresenceAt || 0) < 400) {
        return false;
      }
      const brands = NS.collectPageBrandTokensForForgeAlign();
      // title 兜底：collectPrimary 未就绪时仍可从标题抽 PYAS
      try {
        const title = document.title || "";
        (title.match(/[A-Za-z][A-Za-z0-9]{2,24}/g) || []).forEach((w) => {
          const t = w.toLowerCase().replace(/[^a-z0-9]/g, "");
          if (t.length >= 3 && t.length <= 24 && !/^(?:the|and|for|free|security|antivirus|download|source|view)$/i.test(t)) {
            if (!brands.includes(t)) brands.push(t);
          }
        });
      } catch { /* ignore */ }
      let hit = false;
      if (brands.length) {
        brands.sort((a, b) => b.length - a.length);
        const hrefs = NS.collectPublicCodeForgeHrefCandidates(160);
        for (let i = 0; i < hrefs.length; i++) {
          const abs = hrefs[i];
          let u;
          try { u = new URL(abs); } catch { continue; }
          // 仅认可点击的真实 repo/release 路径；pre/code 里伪造的 git clone 文案常截成 github.com/ 无 owner
          const path = String(u.pathname || "");
          if (!NS.pathLooksLikePublicCodeRepoOrRelease(path)
            && !/(?:^|\.)githubusercontent\.com$/i.test(u.hostname)
            && !/(?:^|\.)(?:github|gitlab)\.io$/i.test(u.hostname)) {
            continue;
          }
          // 路径至少 owner/repo 两段（防仿冒页 pre 里假 github 链接洗白）
          const segs = path.split("/").filter(Boolean);
          if (segs.length < 2 && !/(?:^|\.)githubusercontent\.com$/i.test(u.hostname)) continue;
          if (NS.forgeUrlStronglyAlignedWithBrandTokens(abs, brands)) {
            hit = true;
            break;
          }
        }
      }
      c._forgePresenceCache = hit;
      c._forgePresenceAt = now;
      c._forgePresenceUrl = href0;
      return hit;
    } catch { return false; }
  };

  /** 当前页主机是否具备成熟归属证据：有效 ICP，或 WHOIS 注册足够久（与超成熟门户阈值独立） */
  NS.currentPageHostLooksMatureForTrust = function (minDaysOpt) {
    try {
      if (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()) return true;
      const minDays = Number.isFinite(minDaysOpt) ? minDaysOpt : 180;
      const days = typeof NS.getWhoisAgeDays === "function" ? NS.getWhoisAgeDays() : null;
      return days != null && days >= minDays;
    } catch { return false; }
  };

  /**
   * 收集页内安装包类下载 URL（同步、有限扫描）。
   */
  NS.collectPagePackageDownloadHrefs = function (limitOpt) {
    const out = [];
    const seen = new Set();
    const pushPkg = (raw) => {
      if (!raw || raw.startsWith("#") || raw.startsWith("javascript:")) return;
      let abs = raw;
      try { abs = new URL(String(raw), location.href).href; } catch { return; }
      if (seen.has(abs)) return;
      const isPkg = (typeof NS.isPackageFileUrl === "function" && NS.isPackageFileUrl(abs))
        || (typeof NS.looksLikeProductPackageName === "function"
          && NS.looksLikeProductPackageName(typeof NS.getFilenameFromUrl === "function" ? NS.getFilenameFromUrl(abs) : abs))
        || /\.(?:zip|exe|msi|dmg|apk|rar|7z)(?:\?|#|$)/i.test(abs);
      if (!isPkg) return;
      seen.add(abs);
      out.push(abs);
    };
    try {
      const limit = Math.min(Math.max(Number(limitOpt) || 40, 8), 80);
      const nodes = document.querySelectorAll("a[href], a[data-href], button[data-href], [download]");
      for (let i = 0; i < nodes.length && out.length < limit; i++) {
        const el = nodes[i];
        pushPkg((el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("download") || "").trim());
      }
      // DOM 未就绪：从 HTML 抽 forge release 安装包
      if (out.length < 2) {
        const html = typeof NS.getHtmlSlice === "function"
          ? NS.getHtmlSlice(90000)
          : String((document.documentElement && document.documentElement.innerHTML) || "").slice(0, 90000);
        const re = /https?:\/\/[^\s"'<>]+\.(?:zip|exe|msi|dmg|apk|rar|7z)(?:\?[^\s"'<>]*)?/gi;
        let m;
        while ((m = re.exec(html)) !== null && out.length < limit) {
          pushPkg(m[0].replace(/[),.;]+$/, ""));
        }
      }
    } catch { /* ignore */ }
    return out;
  };

  /**
   * 开源项目下载门户可信：
   * 1) 页内有与品牌强相关的公开代码仓（owner/repo 含品牌核）；
   * 2) 安装包下载落在 (a) 品牌对齐的 forge 发行，或 (b) 当前页同 apex 且页成熟（ICP/WHOIS）。
   * 特例：只要存在「品牌对齐的 forge release 安装包」，即视为成熟下载目标（无需 WHOIS）。
   * 真硬套件不放行。不写死产品品牌名单。
   */
  NS.pageLooksLikeTrustedOpenSourceDownloadPortal = function () {
    try {
      const state = NS.state;
      if (state && (state._seoCloakKitDetected || state._desktopForceDlKit
        || state._remoteGarbleDlDetected || state._indexNowPhishTemplate)) {
        return false;
      }
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return false;

      // 每次实判前清阴性缓存，避免 document_start 假阴性粘住
      try {
        if (NS.caches && NS.caches._forgePresenceCache === false) {
          NS.caches._forgePresenceCache = null;
          NS.caches._forgePresenceAt = 0;
        }
      } catch { /* ignore */ }

      let brands = NS.collectPageBrandTokensForForgeAlign();
      // 标题/logo 再补一轮（PYAS Security）
      try {
        const blob = `${document.title || ""} ${(document.querySelector(".logo,a.logo,h1") || {}).textContent || ""}`;
        (blob.match(/[A-Za-z][A-Za-z0-9]{2,24}/g) || []).forEach((w) => {
          const t = w.toLowerCase().replace(/[^a-z0-9]/g, "");
          if (t.length >= 3 && t.length <= 24
            && !/^(?:the|and|for|free|security|antivirus|download|source|view|smart|endpoint|why|choose)$/i.test(t)
            && !brands.includes(t)) brands.push(t);
        });
      } catch { /* ignore */ }
      if (!brands.length) return false;
      brands = brands.slice().sort((a, b) => b.length - a.length);

      // 直接用候选 URL 判仓（不依赖可能过期的 presence 缓存）
      const forgeHrefs = NS.collectPublicCodeForgeHrefCandidates(160);
      let brandAlignedRepo = false;
      let brandAlignedForgePkg = false;
      for (let i = 0; i < forgeHrefs.length; i++) {
        const abs = forgeHrefs[i];
        let u;
        try { u = new URL(abs); } catch { continue; }
        const isPkg = /\.(?:zip|exe|msi|dmg|apk|rar|7z)(?:\?|#|$)/i.test(abs)
          || (typeof NS.isPackageFileUrl === "function" && NS.isPackageFileUrl(abs));
        const pathOk = NS.pathLooksLikePublicCodeRepoOrRelease(u.pathname)
          || /(?:^|\.)githubusercontent\.com$/i.test(u.hostname)
          || /(?:^|\.)(?:github|gitlab)\.io$/i.test(u.hostname)
          || isPkg;
        if (!pathOk) continue;
        if (!NS.forgeUrlStronglyAlignedWithBrandTokens(abs, brands)) continue;
        if (isPkg) brandAlignedForgePkg = true;
        else brandAlignedRepo = true;
      }
      // 安装包列表再扫一轮（含 HTML 兜底）
      if (!brandAlignedForgePkg) {
        const pkgs = NS.collectPagePackageDownloadHrefs(40);
        for (let i = 0; i < pkgs.length; i++) {
          try {
            const host = new URL(pkgs[i]).hostname;
            if (!NS.hostLooksLikePublicCodeForge(host)) continue;
            if (NS.forgeUrlStronglyAlignedWithBrandTokens(pkgs[i], brands)) {
              brandAlignedForgePkg = true;
              break;
            }
          } catch { /* ignore */ }
        }
      }
      // 有品牌对齐仓链但未识别到 repo 页时：仅 release 包也够
      if (!brandAlignedRepo && !brandAlignedForgePkg) {
        // 回退 presence（含 title 补 brand）
        if (!NS.pageHasPublicCodeForgePresence()) return false;
        brandAlignedRepo = true;
      }

      const pageHost = (location.hostname || "").toLowerCase().replace(/^www\./, "");
      const pageApex = (typeof NS.getRegistrableDomain === "function"
        ? NS.getRegistrableDomain(pageHost) : pageHost) || pageHost;
      const pageMature = NS.currentPageHostLooksMatureForTrust(180);

      // ★ 品牌对齐的 forge 安装包 = 成熟下载目标（github releases），无需 WHOIS
      if (brandAlignedForgePkg) return true;

      const pkgs = NS.collectPagePackageDownloadHrefs(40);
      // 无安装包直链：品牌对齐仓 + 当前页成熟 → 文档/介绍型开源站
      if (!pkgs.length) {
        return !!(brandAlignedRepo && pageMature);
      }

      let ok = 0;
      let bad = 0;
      for (let i = 0; i < pkgs.length; i++) {
        const pkg = pkgs[i];
        let host = "";
        try { host = new URL(pkg).hostname.toLowerCase().replace(/^www\./, ""); } catch { bad++; continue; }
        if (NS.hostLooksLikePublicCodeForge(host)) {
          if (NS.forgeUrlStronglyAlignedWithBrandTokens(pkg, brands)) ok++;
          else bad++;
          continue;
        }
        const apex = (typeof NS.getRegistrableDomain === "function"
          ? NS.getRegistrableDomain(host) : host) || host;
        if (apex && pageApex && apex === pageApex) {
          if (pageMature) ok++;
          else bad++;
          continue;
        }
        bad++;
      }
      return ok >= 1 && bad === 0;
    } catch { return false; }
  };

  /**
   * 撤销本 URL 尚在运行的软品牌裁决。
   *
   * ICP/WHOIS/OV 与品牌选举并行，可信身份可能在 pinyin Promise 或稳定窗口
   * 已排队后才到达。抬锁必须先原子清掉所有 pending/final/retry 状态，否则
   * emitRiskReport 会继续发送 incomplete，后台和 Popup 会按设计保留旧风险。
   */
  NS.cancelPendingSoftBrandDecision = function (reason) {
    try {
      const state = NS.state;
      if (!state) return 0;
      try {
        if (state._brandSpoofFinalSnapshot
          && typeof NS.invalidateBrandSpoofNoticeSnapshot === "function") {
          NS.invalidateBrandSpoofNoticeSnapshot(state._brandSpoofFinalSnapshot, reason || "trusted-identity");
        }
      } catch { /* ignore */ }
      const generation = Number(state._brandSpoofDecisionGeneration || 0) + 1;
      state._brandSpoofDecisionGeneration = generation;
      state._brandSpoofDecisionUrl = String(location.href || "");
      state._pendingSoftBrandSpoof = false;
      state._brandSpoofPresentationDeferred = false;
      state._brandSpoofFinalizeScheduled = false;
      state._brandSpoofFinalPresented = false;
      state._brandSpoofFinalSnapshot = null;
      state._brandSpoofLatinOnly = false;
      state._brandSpoofLatinUpgradeAttempts = 0;
      state._spoofPinyinUpgradeScheduled = false;
      state._spoofPinyinUpgradeDone = false;
      state._brandElectionAwaitingDom = false;
      state._brandElectionRetryPending = false;
      state._brandElectionFinalAttempts = 0;
      try {
        if (state._brandElectionRetryTimer) clearTimeout(state._brandElectionRetryTimer);
      } catch { /* ignore */ }
      state._brandElectionRetryTimer = null;
      state._brandElectionSettledUrl = String(location.href || "");
      state._brandElectionSettledAt = Date.now();
      state._analysisCompletionDeferredForBrand = false;
      state._brandCompletionResumeScheduled = false;
      state._brandSpoofNoticeSent = false;
      state._brandSpoofNoticeKey = "";
      state._lastGuardNoticeKind = "";
      state._lastGuardNoticeKey = "";
      state._lastGuardNoticeVersion = "";
      NS.silverfoxLog && NS.silverfoxLog(
        "brand-decision-cancel", String(reason || "trusted-identity"), "generation=", generation
      );
      return generation;
    } catch {
      return 0;
    }
  };

  /**
   * 可信门户软误报一键解除：有效 ICP 或 WHOIS≥10 年。
   * 清 soft flags + guard + packageBlocked，避免 popup 仍显示「可疑安装包已禁用」。
   */
  NS.forceLiftSoftProtectionForTrustedPortal = function (reason) {
    try {
      const state = NS.state;
      const preserveNoIcp = typeof NS.shouldPreserveForcedMissingIcp === "function"
        && NS.shouldPreserveForcedMissingIcp();
      if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return false;
      const profile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      const trusted = !!(profile && (profile.trusted
        || (typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
          && NS.hasAuthoritativeMatureOrganizationIdentity(profile))));
      if (!trusted) return false;
      const identityUrl = String(location.href || "");
      state._trustedBrandIdentityUrl = identityUrl;
      state._trustedBrandIdentityAt = Date.now();
      // 先使所有旧品牌 Promise / retry / deferred 回调失效，再清 guard 与报告。
      // 否则旧回调可能夹在 DOM 恢复和完成态报告之间，把软锁重新装回去。
      if (typeof NS.cancelPendingSoftBrandDecision === "function") {
        NS.cancelPendingSoftBrandDecision(reason || "trusted-portal-soft-lift");
      }
      try { NS.dismissPageToast(); } catch { /* ignore */ }
      const liftStartedAt = Date.now();
      const liftGeneration = Number(state._softLiftGeneration || 0) + 1;
      state._softLiftGeneration = liftGeneration;
      state._brandSpoofPortalDetected = false;
      state._brandResourceMismatchDetected = false;
      state._fakeBrandShellDetected = false;
      state._cloneOfficialDetected = false;
      state._multiPlatformSerpTrap = false;
      // 大型门户 SPA 误报的「加密 SPA」不阻挡抬锁
      if (!state._seoCloakKitDetected && !state._desktopForceDlKit && !state._remoteGarbleDlDetected) {
        state._fakeSpaDetected = false;
      }
      state.remoteDownloadDispatchDetected = false;
      state.spoofBrand = "";
      state._pendingSoftBrandSpoof = false;
      state._earlyShellArmed = false;
      state.protectedTargets = [];
      try {
        state.details = (state.details || []).filter((d) => {
          if (!d) return false;
          if (preserveNoIcp && d.name === "无ICP备案信息") return true;
          if (/已启用安装包下载拦截|已启用仿冒站|已启用异常跳转|非用户手势|可疑安装包|页面嵌入可疑|探测到下载|仿冒品牌官网|主动探测仿冒|主动探测：|无ICP备案|跨域跳转|自动跳转|自动下载|与标题品牌|疑似仿冒官网/i.test(d.name || "")
            || /主动探测仿冒|与标题品牌|疑似仿冒官网/i.test(d.reason || "")) return false;
          return true;
        });
        if (state.signalSet && typeof state.signalSet.clear === "function") {
          const keep = [];
          state.signalSet.forEach((k) => {
            if (!/已启用安装包|已启用仿冒|非用户手势|仿冒品牌|主动探测仿冒|跨域跳转|自动跳转/i.test(String(k))) keep.push(k);
          });
          state.signalSet.clear();
          keep.forEach((k) => state.signalSet.add(k));
        }
        state.score = (state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
      } catch { /* ignore */ }
      // 强制清 guard 标志后再 clear（避免 hard-lock 误挡）；并连发恢复 DOM
      state.downloadGuardInstalled = false;
      state._earlyShellArmed = false;
      try { NS.clearDownloadGuard(reason || "trusted-portal-soft-lift"); } catch { /* ignore */ }
      try { NS.notifyBackgroundDownloadTrust(true, reason || "trusted-portal-soft-lift"); } catch { /* ignore */ }
      try {
        NS.applyDownloadGuardDomLock(false);
        NS.reEnableAllThreatDisabledElements();
        NS.postToHooks({ type: "set-guard", enabled: false });
        NS.notifyHooksOfficialSafe(true);
        NS.postToHooks({ type: "set-light-page", enabled: true });
        // 抗 SPA 重绘：短延迟再恢复一次
        [0, 80, 300, 800, 2000].forEach((ms) => {
          setTimeout(() => {
            try {
              if (NS.state._softLiftGeneration !== liftGeneration) return;
              if (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat()) return;
              if (Number(NS.state._guardArmedAt || 0) > liftStartedAt) return;
              const latestProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
                ? NS.evaluateMatureLegitimateSiteProfile() : null;
              const latestTrusted = !!(latestProfile && (latestProfile.trusted
                || (typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
                  && NS.hasAuthoritativeMatureOrganizationIdentity(latestProfile))));
              if (latestTrusted) {
                NS.state.downloadGuardInstalled = false;
                NS.applyDownloadGuardDomLock(false);
                NS.reEnableAllThreatDisabledElements();
                NS.postToHooks({ type: "set-guard", enabled: false });
                NS.notifyHooksOfficialSafe(true);
              }
            } catch { /* ignore */ }
          }, ms);
        });
      } catch { /* ignore */ }
      state._perfBenign = true;
      state._perfBenignAt = Date.now();
      state._intelLightMode = true;
      // 必须以完成态覆盖后台/Popup 中已落盘的旧仿冒报告；仅 emit incomplete
      // 会被 mergeThreatRiskReport 有意保留，形成“已解锁但 popup 仍报仿冒”。
      try {
        if (typeof NS.markAnalysisComplete === "function") {
          NS.markAnalysisComplete(`trusted-identity-lift:${String(reason || "portal")}`);
        } else {
          state._analysisDone = true;
          state._analysisDoneAt = Date.now();
          NS.emitRiskReport(true);
        }
      } catch { /* ignore */ }
      return true;
    } catch { return false; }
  };

  NS.icpSettledForSoftBrandSpoof = function () {
    try {
      if (NS.hasValidIcpRecord()) return true;
      if (NS.state._icpQuerySettled) return true;
      return false;
    } catch { return false; }
  };

  NS.notifyHooksOfficialSafe = function (enabled) {
    try {
      NS.postToHooks({ type: "set-official-safe", enabled: !!enabled });
      if (enabled) NS.postToHooks({ type: "set-guard", enabled: false });
    } catch { /* ignore */ }
  };

  /** 将已由 ICP/WHOIS 核验的顶层来源同步给后台下载判定。 */
  NS.notifyBackgroundDownloadTrust = function (enabled, reason) {
    try {
      if (typeof NS.isTopFrame === "function" && !NS.isTopFrame()) return;
      if (!chrome?.runtime?.id) return;
      chrome.runtime.sendMessage({
        type: "set-tab-download-trust",
        enabled: !!enabled,
        url: location.href,
        reason: String(reason || ""),
        analysisTxn: NS.state._analysisTxn || "",
        analysisTxnStartedAt: Number(NS.state._analysisTxnStartedAt) || Date.now()
      }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
  };

  /**
   * 清除软品牌仿冒误报（ICP / 超长 WHOIS / 品牌对齐开源仓等）。
   * 注意：不得用 hasHardThreatKitLocked() 在清标志前判定——它包含
   * _brandSpoofPortalDetected，会导致「清仿冒却立刻重新锁上」。
   * 仅真硬套件（SEO/乱码/强制弹窗/假壳）保留 guard。
   */
  NS.clearBrandSpoofFalsePositive = function (reason, opts) {
    const state = NS.state;
    const liftReason = String(reason || "clear-brand-spoof");
    const preserveNoIcp = !!(opts && opts.preserveNoIcp)
      || (typeof NS.shouldPreserveForcedMissingIcp === "function"
        && NS.shouldPreserveForcedMissingIcp());
    // 真硬套件（不含纯软 brand-spoof 标志）
    const authoritativeIdentity = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
      && NS.hasAuthoritativeMatureOrganizationIdentity();
    const keepHard = (typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat())
      || !!(state._seoCloakKitDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected
        || state._indexNowPhishTemplate || state._unverifiedIcpIdentityThreat
        || (!authoritativeIdentity && (state._fakeBrandShellDetected || state._multiPlatformSerpTrap)));
    try {
      if (typeof NS.cancelPendingSoftBrandDecision === "function") {
        NS.cancelPendingSoftBrandDecision(liftReason);
      }
    } catch { /* ignore */ }
    state._brandSpoofPortalDetected = false;
    state.spoofBrand = "";
    state._brandSpoofNoticeSent = false;
    state._brandSpoofNoticeKey = "";
    state._pendingSoftBrandSpoof = false;
    state._brandSpoofPresentationDeferred = false;
    try { NS.dismissPageToast(); } catch { /* ignore */ }
    try {
      // 仅清软品牌信号；保留「仿冒品牌官网下载壳」等硬套件信号
      state.details = (state.details || []).filter((d) => {
        if (!d) return false;
        if (d.name === "无ICP备案信息") return preserveNoIcp;
        if (/仿冒品牌官网下载壳|多入口共用动态下载|反调试/i.test(d.name || "")) return true;
        if (/仿冒品牌官网|仿冒站下载拦截|已启用仿冒站|主动探测仿冒|主动探测：/i.test(d.name || "")) return false;
        if (/仿冒|官网下载站|不匹配|与标题品牌/i.test(d.reason || "") && /仿冒|品牌|主动探测/i.test(d.name || "") && !/下载壳/i.test(d.name || "")) return false;
        return true;
      });
      if (state.signalSet && typeof state.signalSet.forEach === "function") {
        const drop = [];
        state.signalSet.forEach((k) => {
          const s = String(k);
          if (/仿冒品牌官网下载壳|多入口共用|反调试/i.test(s)) return;
          if (/仿冒品牌官网|仿冒站下载|主动探测仿冒/i.test(s)
            || (!preserveNoIcp && /无ICP备案/i.test(s))) drop.push(k);
        });
        drop.forEach((k) => state.signalSet.delete(k));
      }
      state.score = (state.details || []).reduce((s, d) => s + (Number(d.weight) || 0), 0);
    } catch { /* ignore */ }
    if (keepHard) {
      try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
      try { NS.emitRiskReport(true); } catch { /* ignore */ }
      return;
    }
    try {
      if (state.downloadGuardInstalled || state._earlyShellArmed || (state.protectedTargets && state.protectedTargets.length) || document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']")) {
        NS.clearDownloadGuard(liftReason);
      } else {
        try {
          chrome.runtime.sendMessage({
            type: "clear-threat-notice",
            url: location.href,
            reason: liftReason,
            analysisTxn: state._analysisTxn || "",
            analysisTxnStartedAt: Number(state._analysisTxnStartedAt) || Date.now()
          }, () => { void chrome.runtime.lastError; });
        } catch { /* ignore */ }
        try { NS.reEnableAllThreatDisabledElements(); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    try { NS.notifyHooksOfficialSafe(true); NS.postToHooks({ type: "set-guard", enabled: false }); } catch { /* ignore */ }
    try { NS.emitRiskReport(true); } catch { /* ignore */ }
  };

  /** ICP/WHOIS 证实长生命周期门户后进入轻量模式，停止复扫。 */
  NS.enterIntelLightMode = function (reason) {
    const state = NS.state;
    state._perfBenign = true;
    state._perfBenignAt = Date.now();
    state._intelLightMode = true;
    // 真硬套件才保持锁；软假阳性在可信门户上强制抬
    const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
    const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
      ? NS.evaluateMatureLegitimateSiteProfile() : null;
    const authoritativeIdentity = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
      && NS.hasAuthoritativeMatureOrganizationIdentity(matureProfile);
    if (!realHard && matureProfile && (matureProfile.trusted || authoritativeIdentity)) {
      try {
        if (typeof NS.forceLiftSoftProtectionForTrustedPortal === "function") {
          NS.forceLiftSoftProtectionForTrustedPortal(reason || "intel-light");
          return;
        }
      } catch { /* ignore */ }
      NS.clearBrandSpoofFalsePositive(reason || "intel-light");
    }
    if (realHard) {
      try { NS.disableAllDownloadIntentControls(); NS.postToHooks({ type: "set-guard", enabled: true }); } catch { /* ignore */ }
      return;
    }
    try { NS.notifyHooksOfficialSafe(true); NS.postToHooks({ type: "set-light-page", enabled: true }); } catch { /* ignore */ }
    if (state.downloadGuardInstalled || state._earlyShellArmed || (state.protectedTargets && state.protectedTargets.length) || document.querySelector("[data-threat-detector-disabled='1'], [data-silverfox-greyed='1']")) {
      try { NS.clearDownloadGuard(reason || "intel-light-mode"); } catch { /* ignore */ }
    }
  };

  /**
   * 成熟正规站点组合门。
   *
   * 必选：成熟 WHOIS + 干净页面 + 正规页面结构。
   * 可选增强：有效 ICP、OV/EV、干净主域结构。域名“看起来干净”只加分，
   * 永远不能单独把站点定性为官网；品牌夹字也只扣分，不单独否决成熟正规站。
   */
  NS.evaluateMatureLegitimateSiteProfile = function () {
    const empty = {
      trusted: false, matureWhois: false, cleanPage: false, regularPage: false,
      icp: false, orgSsl: false, boundOrgSsl: false, cleanHostHint: false, brandShapeWarning: false,
      officialProductSubdomain: false, pageApexBrandIdentity: false,
      organizationBackedBrandPortal: false,
      cdnHeavyOrganizationRegular: false,
      cdnHeavyRegular: false, cdnHeavyIcpRegular: false,
      sameApexAssets: 0, externalCdnAssets: 0,
      regularScore: 0, ageDays: null
    };
    try {
      const state = NS.state || {};
      const days = typeof NS.getWhoisAgeDays === "function" ? NS.getWhoisAgeDays() : null;
      const icp = typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord();
      const flagsKey = [
        state._seoCloakKitDetected, state._fakeSpaDetected, state._fakeBrandShellDetected,
        state._desktopForceDlKit, state._remoteGarbleDlDetected, state._indexNowPhishTemplate,
        state._unverifiedIcpIdentityThreat
      ].map((x) => x ? 1 : 0).join("");
      const ssl = state.sslInfo || {};
      const sslKey = [
        String(ssl.validation || "").toUpperCase(),
        String(ssl.organization || "").trim(),
        ssl.sniChainVerified === true ? 1 : 0,
        ssl.liveTlsLeafVerified === true ? 1 : 0,
        ssl.unexpiredHostVerified === true ? 1 : 0
      ].join(":");
      const c = NS.caches || {};
      const now = Date.now();
      // 页面级画像会被下载按钮判定反复调用。先用不触碰大 DOM 的状态键命中短缓存，
      // 避免每个按钮都重新读取 body.innerText 和最多 600 个资源节点。
      const quickCacheKey = `${location.href}|${days}|${icp ? 1 : 0}|${state.icpMatchedHost || ""}|${sslKey}|${flagsKey}|${document.readyState}`;
      if (c._matureLegitProfile && c._matureLegitProfileQuickKey === quickCacheKey
        && now - Number(c._matureLegitProfileAt || 0) < 800) {
        return c._matureLegitProfile;
      }
      const bodyText = String((document.body && (document.body.innerText || document.body.textContent)) || "")
        .replace(/\s+/g, " ").trim();
      const assetNodes = (() => {
        try {
          return Array.from(document.querySelectorAll(
            'script[src], link[rel="stylesheet"][href], link[rel="preload"][href], img[src]'
          )).slice(0, 600);
        } catch { return []; }
      })();
      const siteShellCount = (() => {
        try {
          return document.querySelectorAll(
            "header, nav, footer, [role='navigation'], [class*='header'], [class*='navbar'], [class*='footer']"
          ).length;
        } catch { return 0; }
      })();
      const identityNodeCount = (() => {
        try {
          return document.querySelectorAll(
            'link[rel="canonical"], meta[property="og:url"], script[type="application/ld+json"]'
          ).length;
        } catch { return 0; }
      })();
      const cacheKey = `${location.href}|${days}|${icp ? 1 : 0}|${state.icpMatchedHost || ""}|${sslKey}|${flagsKey}|${document.readyState}|${Math.floor(bodyText.length / 100)}|${assetNodes.length}:${siteShellCount}:${identityNodeCount}`;
      if (c._matureLegitProfile && c._matureLegitProfileKey === cacheKey
        && now - Number(c._matureLegitProfileAt || 0) < 800) {
        return c._matureLegitProfile;
      }

      // “成熟”使用现有长生命周期阈值（5 年）；ICP备案不能代替域名年龄。
      const matureWhois = days != null && days >= 1825;
      const orgSsl = typeof NS.hasOrganizationValidatedSsl === "function"
        && NS.hasOrganizationValidatedSsl();
      const boundOrgSsl = typeof NS.hasBoundOrganizationValidatedSsl === "function"
        && NS.hasBoundOrganizationValidatedSsl(ssl);
      const cleanHostHint = typeof NS.looksLikeCleanOfficialBrandHost === "function"
        && NS.looksLikeCleanOfficialBrandHost();
      const brandShapeWarning = typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity();

      let threatHtml = "";
      try { threatHtml = NS.getThreatScanHtml(120000); } catch { threatHtml = ""; }
      const transparentPackages = (() => {
        try { return NS.countTransparentProductPackages(threatHtml); } catch { return 0; }
      })();
      const encryptedOpaque = (() => {
        try {
          return NS.hasEncryptedNuxtDownloadConfig(threatHtml) && transparentPackages === 0;
        } catch { return false; }
      })();
      const hardAntiAnalysis = (() => {
        try { return NS.hasStrongAntiAnalysisMarkers(threatHtml); } catch { return false; }
      })();
      const realHard = typeof NS.hasRealHardKitThreat === "function" && NS.hasRealHardKitThreat();
      const cleanPage = !realHard && !encryptedOpaque && !hardAntiAnalysis
        && !state._seoCloakKitDetected && !state._fakeSpaDetected
        && !state._fakeBrandShellDetected && !state._desktopForceDlKit
        && !state._remoteGarbleDlDetected && !state._indexNowPhishTemplate
        && !state._unverifiedIcpIdentityThreat;

      const host = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
      const apex = typeof NS.getRegistrableDomain === "function"
        ? (NS.getRegistrableDomain(host) || host) : host;
      let sameApexAssets = 0;
      const externalAssetUrls = new Set();
      const externalAssetHosts = new Set();
      const externalAssetApexes = new Set();
      try {
        assetNodes.forEach((el) => {
            try {
              const raw = el.src || el.href || el.getAttribute("src") || el.getAttribute("href") || "";
              if (!raw || raw.startsWith("data:")) return;
              const assetUrl = new URL(raw, location.href);
              if (!/^https?:$/i.test(assetUrl.protocol)) return;
              const ah = assetUrl.hostname.toLowerCase().replace(/\.$/, "");
              const aa = typeof NS.getRegistrableDomain === "function"
                ? (NS.getRegistrableDomain(ah) || ah) : ah;
              if (aa === apex) sameApexAssets++;
              else {
                // 不维护 CDN 品牌表：只把具有稳定注册域、非 IP、非哈希根域的
                // 外部静态资源计为 CDN 结构证据。它只在成熟 WHOIS + ICP +
                // 组织证书同时成立时参与正规页面闭环，不能单独放行站点。
                const apexLeft = String(aa || "").split(".")[0] || "";
                const stableExternalApex = !!(aa && aa.includes(".")
                  && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ah)
                  && !/^\[[0-9a-f:]+\]$/i.test(ah)
                  && !/^xn--/i.test(apexLeft)
                  && !/^[a-f0-9]{18,}$/i.test(apexLeft));
                if (!stableExternalApex) return;
                const assetKey = `${assetUrl.protocol}//${assetUrl.host}${assetUrl.pathname}`;
                externalAssetUrls.add(assetKey);
                externalAssetHosts.add(ah);
                externalAssetApexes.add(aa);
              }
            } catch { /* ignore */ }
          });
      } catch { /* ignore */ }
      const externalCdnAssets = externalAssetUrls.size;

      let canonicalIdentity = false;
      for (const sel of ['link[rel="canonical"]', 'meta[property="og:url"]']) {
        try {
          const el = document.querySelector(sel);
          const raw = el && (el.getAttribute("href") || el.getAttribute("content") || el.href || el.content);
          if (!raw) continue;
          const ch = new URL(raw, location.href).hostname;
          const ca = typeof NS.getRegistrableDomain === "function"
            ? (NS.getRegistrableDomain(ch) || ch) : ch;
          if (ca === apex) canonicalIdentity = true;
        } catch { /* ignore */ }
      }
      const hasTopChrome = !!document.querySelector(
        "header, nav, [role='navigation'], [class*='header'], [class*='navbar']"
      );
      const hasFooterChrome = !!document.querySelector("footer, [class*='footer']");
      const hasSiteChrome = siteShellCount > 0;
      const completeSiteChrome = hasTopChrome && hasFooterChrome;
      const legalIdentity = /Copyright|版权所有|隐私政策|用户协议|联系我们|关于我们/i.test(bodyText.slice(-3000));
      const structuredSite = /"@type"\s*:\s*"(?:Organization|WebSite|Corporation|SoftwareApplication)"/i.test(threatHtml);
      let selfConsistent = false;
      try {
        selfConsistent = typeof NS.looksLikeSelfConsistentOfficialSite === "function"
          && NS.looksLikeSelfConsistentOfficialSite();
      } catch { selfConsistent = false; }

      let regularScore = 0;
      if (bodyText.length >= 350) regularScore += 1;
      if (bodyText.length >= 1500) regularScore += 1;
      if (sameApexAssets >= 2) regularScore += 1;
      if (sameApexAssets >= 5) regularScore += 1;
      if (externalCdnAssets >= 4) regularScore += 1;
      if (externalCdnAssets >= 10 && externalAssetHosts.size >= 2) regularScore += 1;
      if (canonicalIdentity) regularScore += 2;
      if (hasSiteChrome) regularScore += 1;
      if (completeSiteChrome) regularScore += 1;
      if (legalIdentity) regularScore += 1;
      if (structuredSite) regularScore += 1;
      if (selfConsistent) regularScore += 3;
      if (transparentPackages >= 1) regularScore += 1;
      // 以下都是佐证，不能替代上面的页面正规性。
      if (icp) regularScore += 1;
      if (orgSsl) regularScore += 1;
      if (cleanHostHint) regularScore += 1;
      if (brandShapeWarning) regularScore -= 1;

      // 大型组织官网常把所有 JS/CSS/图片放在独立 CDN，既没有 same-apex
      // 静态资源，也可能不给 canonical。此处以完整站点骨架 + 多个稳定外部
      // 资源替代该硬门，但仅限 WHOIS/ICP/OV·EV 已同时核验的页面。
      // 权威同站 ICP 本身就是组织身份来源。对全部静态资源都放在独立 CDN、证书仅 DV 的
      // 大型国内站，不应再强制要求 OV/EV；仍须同时满足成熟 WHOIS、干净页面和完整站点结构。
      const cdnHeavyIcpRegular = !!(matureWhois && icp
        && bodyText.length >= 350
        && externalCdnAssets >= 4
        && externalAssetApexes.size >= 1
        && (completeSiteChrome || (hasSiteChrome && legalIdentity))
        && (legalIdentity || structuredSite || bodyText.length >= 1500)
        && regularScore >= 7);
      const cdnHeavyRegular = !!(matureWhois && icp && ((orgSsl
        && bodyText.length >= 350
        && externalCdnAssets >= 4
        && externalAssetApexes.size >= 1
        && (completeSiteChrome || (hasSiteChrome && legalIdentity))
        && (legalIdentity || structuredSite || bodyText.length >= 1500)
        && regularScore >= 6) || cdnHeavyIcpRegular));
      const regularPage = selfConsistent || cdnHeavyRegular || (
        bodyText.length >= 180
        && (sameApexAssets >= 2 || canonicalIdentity)
        && regularScore >= 4
      );
      const officialProductSubdomain = typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
        && NS.hostLooksLikeOfficialProductSubdomain(location.hostname);
      const pageApexBrandIdentity = typeof NS.pageBrandIdentityAlignsOrganizationApex === "function"
        && NS.pageBrandIdentityAlignsOrganizationApex(location.hostname);
      const cdnHeavyOrganizationRegular = !!(bodyText.length >= 350
        && externalCdnAssets >= 4 && externalAssetApexes.size >= 1
        && completeSiteChrome && legalIdentity
        && (structuredSite || bodyText.length >= 1500)
        && regularScore >= 6);
      // 无 ICP 的境外组织站只能走严格特例：WHOIS≥10 年 + 由 SNI 链、实时
      // 叶证书或未过期匹配证书绑定当前 host 的 OV/EV + 正规/CDN-heavy 结构
      // + 产品子域 + 页面强品牌↔apex。
      // 普通成熟域或任一单项均不能进入该闭环。
      const organizationBackedBrandPortal = !!(days != null && days >= 3650
        && cleanPage && boundOrgSsl && (regularPage || cdnHeavyOrganizationRegular)
        && officialProductSubdomain && pageApexBrandIdentity);
      const out = {
        trusted: !!(matureWhois && cleanPage && (regularPage || organizationBackedBrandPortal)),
        matureWhois, cleanPage, regularPage, icp, orgSsl, boundOrgSsl, cleanHostHint,
        officialProductSubdomain, pageApexBrandIdentity,
        organizationBackedBrandPortal, cdnHeavyOrganizationRegular,
        brandShapeWarning, cdnHeavyRegular, cdnHeavyIcpRegular,
        sameApexAssets, externalCdnAssets,
        regularScore, ageDays: days
      };
      c._matureLegitProfile = out;
      c._matureLegitProfileKey = cacheKey;
      c._matureLegitProfileQuickKey = quickCacheKey;
      c._matureLegitProfileAt = now;
      return out;
    } catch {
      return empty;
    }
  };

  /**
   * 权威成熟组织身份闭环。
   *
   * 品牌扫描可能先把大型 SPA 暂记为 fakeSpa/fakeBrandShell，不能让这些软标志
   * 反过来永久否决随后取得的 WHOIS + 域名备案 + OV/EV 组织身份。四项必须同时
   * 成立，且真实硬套件/假备案仍然一票否决，因此这里不是“有备案就放行”。
   */
  NS.hasAuthoritativeMatureOrganizationIdentity = function (profile) {
    try {
      const state = NS.state || {};
      const realHard = typeof NS.hasRealHardKitThreat === "function"
        && NS.hasRealHardKitThreat();
      const identityUrl = String(location.href || "");
      // 同一 URL 的权威身份一旦由 WHOIS + ICP + OV/EV + 页面结构闭环，
      // 后续软品牌标志或 SPA 重绘不得把它抖回未信任；真硬威胁/假备案仍否决。
      if (!realHard && !state._unverifiedIcpIdentityThreat
        && state._trustedBrandIdentityUrl === identityUrl
        && Number(state._trustedBrandIdentityAt || 0) > 0) return true;
      const p = profile || (typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null);
      if (!p) return false;
      const officialProductSubdomain = typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
        && NS.hostLooksLikeOfficialProductSubdomain(location.hostname);
      const verified = !!(!realHard && !state._unverifiedIcpIdentityThreat
        && p.matureWhois && (
          (p.icp && p.orgSsl && (p.regularPage || officialProductSubdomain))
          || p.organizationBackedBrandPortal === true
        ));
      if (verified) {
        state._trustedBrandIdentityUrl = identityUrl;
        state._trustedBrandIdentityAt = Date.now();
      }
      return verified;
    } catch { return false; }
  };

  /**
   * 年轻且未核验注册域：无有效 ICP，且 WHOIS 未回或年龄 < 365 天。
   * 此类站不得走「关键词强对齐 / exact 正站」捷径——必须过仿冒与下载壳检测。
   * （成熟门本身要 WHOIS≥5 年；本函数补上「不成熟就禁止放行捷径」。）
   */
  NS.isYoungUnverifiedRegistration = function () {
    try {
      if (typeof NS.hasValidIcpRecord === "function" && NS.hasValidIcpRecord()) return false;
      const days = typeof NS.getWhoisAgeDays === "function" ? NS.getWhoisAgeDays() : null;
      // WHOIS 未结算前也视为未核验（避免情报前被强对齐洗白）
      if (days == null) {
        try {
          if (NS.state && NS.state._icpQuerySettled !== true && !NS.state.whoisInfo) return true;
        } catch { /* fall through */ }
        // 已查 WHOIS 但无年龄 / 失败：仍按年轻未核验（有备案的上面已 return false）
        return true;
      }
      return days < 365;
    } catch {
      return true;
    }
  };

  NS.looksLikeMatureOfficialPortal = function () {
    try {
      // 年轻无备案：绝不当成熟门户
      if (typeof NS.isYoungUnverifiedRegistration === "function" && NS.isYoungUnverifiedRegistration()) {
        return false;
      }
      const profile = NS.evaluateMatureLegitimateSiteProfile();
      return !!(profile && (profile.trusted
        || (typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
          && NS.hasAuthoritativeMatureOrganizationIdentity(profile))));
    } catch { return false; }
  };

  /** 真实长生命周期门户硬安全门：永不 arm guard / 灰按钮 / 视自动包导航为威胁。 */
  NS.shouldNeverArmProtection = function () {
    try {
      if (typeof NS.isYoungUnverifiedRegistration === "function" && NS.isYoungUnverifiedRegistration()) {
        return false;
      }
      const state = NS.state;
      const profile = NS.evaluateMatureLegitimateSiteProfile();
      const authoritativeIdentity = typeof NS.hasAuthoritativeMatureOrganizationIdentity === "function"
        && NS.hasAuthoritativeMatureOrganizationIdentity(profile);
      if (!profile || (!profile.trusted && !authoritativeIdentity)) return false;
      state._brandSpoofPortalDetected = false;
      state._brandResourceMismatchDetected = false;
      state.spoofBrand = "";
      return true;
    } catch { return false; }
  };

  NS.pageClaimsOfficialDownload = function () {
    // 应用商店/手机助手详情：是商店在分发 App，不是宣称自己是该 App 官网
    if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) return false;
    const title = document.title || "";
    const text = ((document.body && document.body.innerText) || "").replace(/\s+/g, " ").trim().slice(0, 4000);
    const blob = `${title} ${text}`;
    if (!/官网|官方下载|官方正版|官方网站|官方客户端|正版下载|下载中心|全平台官方|全平台.*下载|官方.*下载/.test(blob)) return false;
    if (typeof NS.pageLooksLikeThirdPartyBrandProxyOrMirror === "function" && NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) {
      return /官网|官方下载|官方正版|官方网站|官方客户端|正版下载|全平台官方/i.test(title) && !/加速|代理|镜像|proxy|mirror/i.test(title);
    }
    return true;
  };

  NS.pageLooksLikeThirdPartyBrandProxyOrMirror = function () {
    try {
      if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
      const title = (document.title || "").trim();
      const og = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
      const siteName = document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "";
      const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
      const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(1500) : "";
      const id = `${title} ${og} ${siteName} ${String(desc).slice(0, 360)} ${headings}`.replace(/\s+/g, " ");
      if (/官方下载|官方正版|官网下载|官方网站|官方客户端/i.test(title) && !/加速|代理|镜像|proxy|mirror|cdn/i.test(title)) return false;
      if (/官网|官方下载|官方正版|官方网站|官方客户端|正版下载/i.test(id) && !/(?:加速|代理|镜像|proxy|mirror).{0,10}(?:下载|服务|工具|站|访问)|(?:下载|访问|资源).{0,8}(?:加速|代理)|加速下载代理|download\s*proxy/i.test(id)) return false;
      const proxyIdentity = /加速下载|下载加速|下载代理|访问代理|资源加速|文件加速|静态资源加速|clone\s*加速|git\s*clone|镜像站|镜像加速|代理服务|proxy\s*service|download\s*proxy|cdn\s*加速|解决.{0,16}(?:访问|下载)|快速访问\s*[A-Za-z一-鿿]/i.test(id)
        || /[A-Za-z][a-zA-Z]{2,}.{0,12}(?:加速|代理|镜像|proxy|mirror)/i.test(`${title} ${og} ${siteName}`)
        || /(?:加速|代理|镜像|proxy|mirror).{0,12}[A-Za-z][a-zA-Z]{2,}/i.test(`${title} ${og} ${siteName}`)
        || /加速下载代理|下载加速代理|GitHub\s*Proxy|ghproxy|gh-proxy/i.test(id);
      if (!proxyIdentity) return false;
      const host = (location.hostname || "").toLowerCase();
      const label = (host.split(".")[0] || "");
      const proxyHostShape = /proxy|mirror|cdn|accel|ghproxy|gh-proxy|gitclone|npmmirror|jsdelivr|fastgit|gitmirror|ghproxy/i.test(host) || /proxy|mirror|cdn|加速|镜像|代理|ghproxy|ghproxy/i.test(label);
      const toolish = proxyHostShape || /代理|加速|镜像|proxy|mirror|工具|服务/i.test(`${title} ${siteName} ${og}`) || /支持\s*(?:Releases|Raw|Archive|clone)|Releases|Raw|Archive/i.test(id);
      return !!(proxyIdentity && toolish);
    } catch { return false; }
  };

  NS.pageClaimsBrandDownloadLanding = function () {
    if (NS.pageLooksLikeSearchEngineResultsPage()) return false;
    if (NS.pageLooksLikeThirdPartyBrandProxyOrMirror()) return false;
    if (typeof NS.pageLooksLikeAppMarketOrAppStoreListing === "function" && NS.pageLooksLikeAppMarketOrAppStoreListing()) return false;
    if (NS.pageClaimsOfficialDownload()) return true;
    try {
      const title = document.title || "";
      if (/[-–|]\s*(搜索|Search|Recherche|Suche|検索)\s*$/i.test(title)) return false;
      const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(3000) : "";
      const desc = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
      const og = document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "";
      const claim = `${title} ${headings} ${og}`;
      const body = ((document.body && (document.body.innerText || document.body.textContent)) || "").replace(/\s+/g, " ").trim().slice(0, 5000);
      // 导航/按钮「免费下载」也算（勿只扫 title——仿冒首页 title 常是「安静·纯净·强悍」）
      let ctaBits = "";
      try {
        ctaBits = Array.from(document.querySelectorAll("a[href], button, .btn-header, .btn-primary, .btn-lg"))
          .slice(0, 30)
          .map((el) => (el.textContent || "").replace(/\s+/g, " ").trim())
          .filter((t) => t.length >= 2 && t.length <= 28 && /下载|官方|客户端|安装|免费/i.test(t))
          .join(" ");
      } catch { /* ignore */ }
      const blob = `${claim} ${String(desc).slice(0, 400)} ${body} ${ctaBits}`;
      // 免费下载 须在 claim 或 CTA/正文中命中（原先只测 claim，首页误杀）
      if (/客户端\s*完全\s*免费|客户端永久免费|免费下载|立即免费下载|立即下载|开始使用\s*[A-Za-z]{3,}|电脑版官网|官方桌面/i.test(claim)
        || /免费下载|立即免费下载|立即下载|官方下载|客户端下载|个人版下载/i.test(ctaBits)
        || /下载\s*(?!代理|加速|镜像)[A-Za-z一-鿿]{2,20}/i.test(claim)
        || /客户端\s*完全\s*免费|客户端永久免费|开始使用\s*[A-Za-z]{3,}|免费下载|立即免费下载/i.test(blob)) {
        if (/免费下载/i.test(blob) && !/客户端|安装包|官方|开始使用|全平台|电脑版|个人版|安全|杀毒|下载/i.test(claim + ctaBits + blob.slice(0, 500))) { /* weak */ }
        else if (/下载(?:代理|加速|镜像)|加速下载|代理服务/i.test(claim) && !/官方|客户端|安装包|官网/i.test(claim)) { /* proxy */ }
        else return true;
      }
      if (/全平台覆盖|全平台免费|无需绑定.*下载|即刻开始|安装客户端/i.test(claim + blob.slice(0, 800)) && /下载|客户端|安装包|\.zip|\.exe/i.test(blob)) return true;
      const html = NS.getHtmlSlice(80000);
      // SoftwareApplication：须有真实下载入口；纯 Web Browser 工具 + price:0 不算下载落地
      if (/"@type"\s*:\s*"SoftwareApplication"/i.test(html)) {
        if (/downloadUrl|installUrl/i.test(html)) return true;
        const webOnlyOs = /"operatingSystem"\s*:\s*"[^"]*Web\s*Browser[^"]*"/i.test(html)
          && !/downloadUrl|installUrl/i.test(html);
        if (!webOnlyOs && /operatingSystem/i.test(html)
          && /Windows|macOS|Android|iOS|Linux|鸿蒙/i.test(html)
          && /下载|download|安装|客户端|安装包/i.test(blob)) {
          return true;
        }
      }
      const pkgCtas = Array.from(document.querySelectorAll("a[href], button")).filter((el) => { const h = el.getAttribute("href") || ""; return NS.isPackageFileUrl(h); });
      if (pkgCtas.length >= 1 && /[A-Za-z]{4,}/.test(title)) return true;
      return false;
    } catch { return false; }
  };

  NS.hasEncryptedNuxtDownloadConfig = function (html) {
    const h = String(html || "").replace(/data:(?:image|font|application)\/[^;,"]+;base64,[A-Za-z0-9+/=]+/gi, "");
    const dlKeyHits = (h.match(/["']?(?:windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload)["']?\s*:/gi) || []).length;
    const hasDlKeys = dlKeyHits >= 1 || /["'](?:windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload)["']/i.test(h) || /\b(?:windowsDownload|macDownload|androidDownload)\b/i.test(h);
    if (!hasDlKeys) return false;
    const adjacent = (h.match(/["']?(?:windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload)["']?\s*:\s*["'](?!https?:\/\/|\/)[A-Za-z0-9+/]{24,}={0,2}["']/gi) || []).length;
    const paddedB64 = (h.match(/["'][A-Za-z0-9+/]{32,}={1,2}["']/g) || []).length;
    const longB64 = (h.match(/["'][A-Za-z0-9+/]{48,}={0,2}["']/g) || []).length;
    const multiPlatformKeys = dlKeyHits >= 2 || ((h.match(/windowsDownload|macDownload|linuxDownload|androidDownload|harmonyDownload|iosDownload/gi) || []).length >= 3);
    const hasPlainHttpsPackages = /https?:\/\/[^\s"'<>\\]+?\.(?:exe|dmg|pkg|apk|zip)/i.test(NS.unescapeHtmlForScan(h));
    if (hasPlainHttpsPackages && NS.countTransparentProductPackages(h) >= 1) return false;
    if (adjacent >= 1) return true;
    if (paddedB64 >= 2 || longB64 >= 2) return true;
    if (multiPlatformKeys && (paddedB64 >= 1 || longB64 >= 1 || /["'][A-Za-z0-9+/]{40,}["']/.test(h))) return true;
    if (dlKeyHits >= 1 && (paddedB64 >= 1 || longB64 >= 1 || /["'][A-Za-z0-9+/]{36,}={0,2}["']/.test(h))) return true;
    return false;
  };

  NS.countTransparentProductPackages = function (html) {
    const h = NS.unescapeHtmlForScan(html);
    let count = 0;
    const seen = new Set();
    const pkgUrlRe = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|pkg|deb|rpm)(?:\?[^\s"'<>\\]*)?/gi;
    let m;
    while ((m = pkgUrlRe.exec(h)) !== null) {
      const full = m[0];
      try { if (NS.looksLikeHighRiskBlobPackageUrl(full)) continue; } catch { /* ignore */ }
      const name = NS.normalizeFileName(full);
      if (seen.has(name)) continue;
      if (NS.isBenignShortInstallerName(name) || NS.isClearProductOrAndroidPackage(name) || NS.looksLikeAndroidPackageIdName(name)) { seen.add(name); count++; continue; }
      if ((NS.looksLikeStrongProductInstallerName(name) || NS.looksLikeProductPackageName(name)) && NS.packageFilenameSharesPageBrand(name)) { seen.add(name); count++; }
    }
    const pathRe = /\/([A-Za-z][A-Za-z0-9._-]{2,80}\.(?:exe|dmg|pkg|apk|zip|deb|rpm))/g;
    while ((m = pathRe.exec(h)) !== null) {
      const name = NS.normalizeFileName(m[1]);
      if (seen.has(name)) continue;
      if (NS.isBenignShortInstallerName(name) || NS.isClearProductOrAndroidPackage(name) || NS.looksLikeAndroidPackageIdName(name)) { seen.add(name); count++; continue; }
      if ((NS.looksLikeStrongProductInstallerName(name) || NS.looksLikeProductPackageName(name)) && NS.packageFilenameSharesPageBrand(name)) { seen.add(name); count++; }
    }
    const androidRe = /\b((?:[a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*(?:[._-]\d{2,16})?\.apk)\b/gi;
    while ((m = androidRe.exec(h)) !== null) {
      const name = NS.normalizeFileName(m[1]);
      if (NS.isClearProductOrAndroidPackage(name) && !seen.has(name)) { seen.add(name); count++; }
    }
    return count;
  };

  NS.hasDynamicSharedDownloadUriBinding = function (html) {
    const h = String(html || "");
    const hasGlobalUri = /window\.download_uri\b|download_uri\s*=\s*|var\s+download_uri\b|let\s+download_uri\b|const\s+download_uri\b/i.test(h) || /window\.(?:downloadUrl|downloadURL|down_url|dl_url|packageUrl)\s*=/i.test(h);
    if (!hasGlobalUri) return false;
    const multiAssign = /getElementsByClassName\s*\(\s*['"]download-uri['"]\s*\)/i.test(h)
      || /querySelectorAll\s*\(\s*['"][^'"]*download-uri[^'"]*['"]\s*\)/i.test(h)
      || /getElementsByClassName\s*\(\s*['"]download-btn['"]\s*\)/i.test(h)
      || /querySelectorAll\s*\(\s*['"][^'"]*download-btn[^'"]*['"]\s*\)/i.test(h)
      || /initDownloadLinks/i.test(h)
      || (/downloadElements/i.test(h) && /\.href\s*=\s*window\.download_uri|location\.href\s*=\s*window\.download_uri/i.test(h))
      || (/\.href\s*=\s*window\.download_uri/i.test(h) && /for\s*\s*\(/i.test(h))
      || (/download_uri/i.test(h) && /\.href\s*=\s*download_uri/i.test(h) && /for\s*\(/i.test(h));
    return multiAssign || (/download_uri/i.test(h) && /downloadElements\.length|for\s*\(\s*let\s+i\s*=\s*0/i.test(h));
  };

  NS.hostBelongsToBrandApex = function (hostname, brandApex) {
    const h = String(hostname || "").toLowerCase().replace(/^www\./, "");
    const a = String(brandApex || "").toLowerCase().replace(/^www\./, "");
    if (!h || !a) return false;
    return h === a || h.endsWith(`.${a}`);
  };

  NS.hasAuthorBrandHostMismatch = function () {
    try {
      if (!/官网|官方下载|官方网站|官方正版|官网下载/.test(document.title || "")) return false;
      const author = (document.querySelector('meta[name="author"]')?.getAttribute("content") || "").trim();
      const fromAuthor = author.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i);
      if (!fromAuthor) return false;
      const brandApex = NS.guessApexDomain(fromAuthor[1]);
      if (!brandApex) return false;
      if (NS.hostBelongsToBrandApex(location.hostname, brandApex)) return false;
      return true;
    } catch { return false; }
  };

  NS.hasWeakAntiAnalysisMarkers = function (htmlOrBlob) {
    const blob = String(htmlOrBlob || "");
    const blockContext = /oncontextmenu\s*=\s*["']return\s+false|addEventListener\s*\(\s*["']contextmenu["']/i.test(blob) && /preventDefault|return\s+false/i.test(blob);
    const blockF12 = /keyCode\s*===?\s*123|key\s*===?\s*["']F12["']|which\s*===?\s*123/i.test(blob) || (/keydown|keypress/i.test(blob) && /F12|ctrlKey.*[isu]|devtools/i.test(blob) && /preventDefault/i.test(blob));
    const blankRedirect = /about:blank/i.test(blob) && (blockF12 || blockContext || /location\s*(?:\.href\s*)?=\s*["']about:blank|location\.replace\s*\(\s*["']about:blank/i.test(blob));
    const antiDebug = /\bdebugger\b/.test(blob) && /setInterval|setTimeout/i.test(blob);
    return !!(blockContext || blockF12 || blankRedirect || antiDebug);
  };

  NS.hasStrongAntiAnalysisMarkers = function (htmlOrBlob) {
    const blob = String(htmlOrBlob || "");
    const blockContextHard = /oncontextmenu\s*=\s*["']return\s+false/i.test(blob) || /addEventListener\s*\(\s*["']contextmenu["']\s*,\s*(?:function|\([^)]*\)\s*=>)[\s\S]{0,180}preventDefault/i.test(blob) || /oncontextmenu\s*=\s*function[\s\S]{0,80}return\s+false/i.test(blob) || /oncontextmenu\s*=\s*["'][^"']*return\s*!?\s*1?\s*false/i.test(blob) || /contextmenu[\s\S]{0,80}preventDefault/i.test(blob);
    const f12ToBlank = (/keyCode\s*===?\s*123|which\s*===?\s*123|key\s*===?\s*["']F12["']|["']F12["']\s*===?\s*\w+\.key/i.test(blob)) && /about:blank/i.test(blob);
    const f12Block = (/keyCode\s*===?\s*123|which\s*===?\s*123|key\s*===?\s*["']F12["']/i.test(blob) || /\bF12\b/.test(blob) && /keydown|keyCode|which/.test(blob)) && /preventDefault|return\s*!?\s*1?\s*false|stopPropagation/i.test(blob);
    const locationBlank = /(?:location\s*(?:\.href\s*)?=\s*["']about:blank|location\.replace\s*\(\s*["']about:blank)/i.test(blob) && (/keyCode\s*===?\s*123|F12|contextmenu|devtools/i.test(blob));
    const debuggerTrap = (/\bdebugger\b/.test(blob) && /setInterval\s*\(|setTimeout\s*\(/i.test(blob)) || /Function\s*\(\s*['"`][^'"`]*debugger/i.test(blob) || /constructor\s*\(\s*['"`]debugger['"`]\s*\)/i.test(blob) || (/\bdebugger\b/.test(blob) && /while\s*\(\s*(?:true|1)\s*\)/i.test(blob));
    const devtoolsDetect = /devtools|outerWidth\s*-\s*innerWidth|Firebug|__REACT_DEVTOOLS/i.test(blob) && (/debugger|about:blank|location\s*\.\s*href|close\s*\(/i.test(blob));
    return !!(blockContextHard || f12ToBlank || f12Block || locationBlank || debuggerTrap || devtoolsDetect);
  };

  NS.collectPageScriptScanBlob = function (maxLen = 120000) {
    try { return NS.getThreatScanHtml(maxLen); } catch { return ""; }
  };

  NS.looksLikeSelfConsistentOfficialSite = function () {
    try {
      // 年轻夹带域的精美下载壳（JSON-LD + 顶栏底栏）不能自证为正站
      if (typeof NS.shouldRejectOfficialDownloadShortcut === "function"
        && NS.shouldRejectOfficialDownloadShortcut()) return false;
      const pageApex = NS.guessApexDomain(location.hostname);
      if (!pageApex) return false;
      const htmlSlice = NS.getThreatScanHtml(140000);
      if (NS.hasEncryptedNuxtDownloadConfig(htmlSlice) && NS.countTransparentProductPackages(htmlSlice) === 0) return false;
      const hasBlobPkg = Array.from(document.querySelectorAll("a[href], a[data-href]")).some((a) => {
        const h = (a.getAttribute("href") || a.getAttribute("data-href") || "").trim();
        if (!h) return false;
        const fn = NS.getFilenameFromUrl(h);
        if (NS.isClearProductOrAndroidPackage(fn) || NS.looksLikeProductPackageName(fn)) return NS.looksLikeHighRiskBlobPackageUrl(h);
        return NS.looksLikeObjectStoragePackageUrl(h) || NS.looksLikeHighRiskBlobPackageUrl(h);
      });
      if (hasBlobPkg) return false;
      const hreflangCount = document.querySelectorAll('link[rel="alternate"][hreflang]').length;
      const htmlHead = NS.getHtmlSlice(40000);
      const enterpriseCms = /etc\.clientlibs|adobe-launch|onetrust|data-domain-script|NVIDIAGDC|sitecore|aem-/i.test(htmlHead);
      const hasHardSignal = hreflangCount >= 3 || enterpriseCms || NS.countTransparentProductPackages(htmlSlice) >= 1;
      if (!hasHardSignal) return false;
      let hits = 0;
      const canonical = document.querySelector('link[rel="canonical"]')?.getAttribute("href");
      if (canonical) { try { if (NS.guessApexDomain(new URL(canonical, location.href).hostname) === pageApex) hits += 2; } catch { /* ignore */ } }
      const ogUrl = document.querySelector('meta[property="og:url"]')?.getAttribute("content") || document.querySelector('meta[property="og:url"]')?.content;
      if (ogUrl) { try { if (NS.guessApexDomain(new URL(ogUrl, location.href).hostname) === pageApex) hits += 2; } catch { /* ignore */ } }
      if (hreflangCount >= 5) hits += 3; else if (hreflangCount >= 3) hits += 2;
      let sameOriginAssets = 0;
      document.querySelectorAll('script[src], link[rel="stylesheet"][href], link[rel="preload"][href]').forEach((el) => {
        try { const raw = el.src || el.href || el.getAttribute("href") || ""; if (!raw) return; if (NS.guessApexDomain(new URL(raw, location.href).hostname) === pageApex) sameOriginAssets++; } catch { /* ignore */ }
      });
      if (sameOriginAssets >= 6) hits += 2; else if (sameOriginAssets >= 3) hits += 1;
      if (enterpriseCms && sameOriginAssets >= 2) hits += 2;
      const textLen = ((document.body && document.body.innerText) || "").length;
      if (textLen > 2000) hits += 1;
      return hits >= 5;
    } catch { return false; }
  };

  NS.looksLikeOfficialBrandDownloadPage = function (html) {
    try {
      if (typeof NS.shouldRejectOfficialDownloadShortcut === "function"
        && NS.shouldRejectOfficialDownloadShortcut()) return false;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity()) return false;
      const full = html ? String(html).slice(0, 120000) : NS.getHtmlSlice(100000);
      const h = NS.unescapeHtmlForScan(full);
      if (NS.countTransparentProductPackages(h) >= 1) return true;
      const fieldRe = /"[A-Za-z0-9_]*Download(?:Link|Url|URI|Path)?"\s*:\s*"(https?:\/\/[^"]+\.(?:exe|dmg|pkg|apk|msi|zip|deb|rpm))"/gi;
      let fm; let structuredProductPkgs = 0;
      while ((fm = fieldRe.exec(h)) !== null) {
        const url = fm[1];
        try { if (NS.looksLikeObjectStorageHost(new URL(url).hostname)) continue; } catch { /* ignore */ }
        if (NS.looksLikeProductPackageName(NS.normalizeFileName(url))) structuredProductPkgs++;
      }
      if (structuredProductPkgs >= 1) return true;
      const author = (document.querySelector('meta[name="author"]')?.getAttribute("content") || "").trim();
      const fromAuthor = author.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i);
      const identityOk = fromAuthor && NS.hostBelongsToBrandApex(location.hostname, NS.guessApexDomain(fromAuthor[1]));
      if (identityOk && !NS.hasDynamicSharedDownloadUriBinding(h)) {
        const pkgRe = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|msi|dmg|pkg|deb|rpm)/gi;
        let pm;
        while ((pm = pkgRe.exec(h)) !== null) {
          try { if (NS.looksLikeObjectStorageHost(new URL(pm[0]).hostname)) continue; } catch { /* ignore */ }
          if (NS.looksLikeProductPackageName(NS.normalizeFileName(pm[0]))) return true;
        }
      }
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      return false;
    } catch { return false; }
  };

  NS.looksLikeOfficialClientDownloadPage = function () {
    if (typeof NS.shouldRejectOfficialDownloadShortcut === "function"
      && NS.shouldRejectOfficialDownloadShortcut()) return false;
    if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
      && NS.hostNeedsAuthoritativeBrandIdentity()) return false;
    const title = (document.title || "").trim();
    const titleOk = /(客户端|下载|APP|应用|Android|iOS|电脑版|Mac|远程)/i.test(title);
    if (!titleOk) return false;
    try {
      const html = NS.getHtmlSlice(120000);
      if (typeof NS.hasEncryptedNuxtDownloadConfig === "function" && NS.hasEncryptedNuxtDownloadConfig(html) && NS.countTransparentProductPackages(html) === 0) return false;
      if (typeof NS.countTransparentProductPackages === "function" && NS.countTransparentProductPackages(html) >= 1) return true;
    } catch { /* ignore */ }
    const hasSpaRoot = !!document.querySelector("#root, #app, #__next, #__nuxt, #ice-container, [data-reactroot]");
    const scripts = Array.from(document.scripts).filter((s) => s.src);
    if (scripts.length < 2) return false;
    let stableAsset = 0; let randomAsset = 0;
    scripts.forEach((s) => {
      try {
        const h = new URL(s.src, location.href).hostname.toLowerCase();
        const label = (h.split(".")[0] || "").replace(/-/g, "");
        const depth = h.split(".").length;
        const randomish = depth <= 2 && (/^[a-z0-9]{10,}$/i.test(label) && /\d/.test(label) && /[a-z]/i.test(label));
        if (randomish) randomAsset++; else if (depth >= 3 || /cdn|static|img|asset|media|res\d*/i.test(h)) stableAsset++; else stableAsset++;
      } catch { /* ignore */ }
    });
    if (randomAsset > 0 && randomAsset >= stableAsset) return false;
    const packageHrefs = Array.from(document.querySelectorAll("a[href], a[data-href]")).map((a) => (a.getAttribute("href") || a.getAttribute("data-href") || "").trim()).filter((h) => NS.isPackageFileUrl(h));
    if (packageHrefs.some((h) => NS.isSuspiciousDownloadFilename(NS.getFilenameFromUrl(h)))) return false;
    if (packageHrefs.some((h) => NS.looksLikeObfuscatedPhpDownloadUrl(h))) return false;
    const hiddenIframes = Array.from(document.querySelectorAll("iframe")).filter((f) => {
      try { const st = getComputedStyle(f); return st.display === "none" || st.visibility === "hidden" || f.width === "0" || f.height === "0"; } catch { return false; }
    }).length;
    if (hasSpaRoot && stableAsset >= 2 && randomAsset === 0) return true;
    if (titleOk && stableAsset >= 3 && packageHrefs.every((h) => NS.looksLikeProductPackageName(NS.getFilenameFromUrl(h)) || !NS.getFilenameFromUrl(h))) return true;
    void hiddenIframes;
    return false;
  };

  /**
   * 廉价：干净品牌根主机（dingtalk.com 首页亦可）。
   * 仅主机结构，不扫 HTML / 品牌文案。
   */
  NS.looksLikeCleanOfficialBrandHost = function () {
    try {
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity()) return false;
      const host = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
      if (!host || host.split(".").length < 2) return false;
      const apex = typeof NS.getRegistrableDomain === "function"
        ? NS.getRegistrableDomain(host) : host;
      const left = (String(apex || "").split(".")[0] || "").toLowerCase();
      if (!left || left.length < 3 || left.length > 16) return false;
      if (/[-_]/.test(left)) return false;
      if (/\d{2,}/.test(left)) return false;
      if (!/^[a-z][a-z0-9]*$/i.test(left)) return false;
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(left)) return false;
      if (typeof NS.parseHostChineseProductCategoryPad === "function"
        && NS.parseHostChineseProductCategoryPad(left)) return false;
      if (host !== apex && host.endsWith(`.${apex}`)) {
        const sub = host.slice(0, -(apex.length + 1)).split(".")[0] || "";
        if (/^(?:win|pc|download|down|dl|soft|vip|free|get|safe|official|cdn|static)$/i.test(sub)) return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  /**
   * 只用于 document_start 的性能静默，不代表官网或可信身份。
   * 该判断不得读取页面品牌，也不得调用 hostNeedsAuthoritativeBrandIdentity；
   * 否则冷启动时页面身份尚未出现，会重新掉回重型 DOM 扫描。
   */
  NS.looksLikeProvisionalDownloadPathShape = function () {
    try {
      if (!/^https?:$/i.test(String(location.protocol || ""))) return false;
      const path = String(location.pathname || "").toLowerCase();
      if (!/\/(?:download|downloads|client|install)(?:\/|$|\.)/i.test(path)
        && !/\/(?:pc|desktop|mobile)\/(?:download|client)(?:\/|$|\.)/i.test(path)) {
        return false;
      }
      const host = String(location.hostname || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
      if (!host || !host.includes(".") || /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3})$/i.test(host) || host.includes(":")) return false;
      const apex = typeof NS.getRegistrableDomain === "function"
        ? (NS.getRegistrableDomain(host) || host) : host;
      const left = (String(apex || "").split(".")[0] || "").toLowerCase();
      if (/^(?:com|net|org|gov|edu|ac|mil)\.(?:cn|uk|jp|kr|au|nz)$/i.test(String(apex || ""))) return false;
      if (!/^[a-z][a-z0-9]{2,17}$/i.test(left) || /\d{2,}/.test(left) || /^xn--/i.test(left)) return false;
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(left)) return false;
      if (typeof NS.parseHostChineseProductCategoryPad === "function"
        && NS.parseHostChineseProductCategoryPad(left)) return false;
      if (host !== apex && host.endsWith(`.${apex}`)) {
        const subs = host.slice(0, -(apex.length + 1)).split(".").filter(Boolean);
        if (subs.some((sub) => /^(?:win|pc|download|down|dl|soft|vip|free|get|safe|official|cdn|static)$/i.test(sub))) return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  /**
   * 廉价判断：干净品牌根 + /download|/client 路径（dingtalk.com/download）。
   * 不扫大 HTML，供 boot/scan 门控，避免正站下载中心卡死。
   */
  NS.looksLikeCleanOfficialDownloadHostPath = function () {
    try {
      if (typeof NS.looksLikeCleanOfficialBrandHost === "function"
        && !NS.looksLikeCleanOfficialBrandHost()) return false;
      const path = String(location.pathname || "").toLowerCase();
      if (!/\/(download|downloads|client|app|apps|get|install)(\/|$|\.)/i.test(path)
        && !/\/(pc|desktop|mobile)\/(download|client)/i.test(path)) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  /**
   * 下载 CTA 是否大面积指向搜索引擎首页/落地（仿冒 download.html 典型）。
   * 正站捷径与 lift 门控共用，避免「长得像官网」洗白。
   */
  NS.pageDownloadCtasMostlySearchEngineTraps = function () {
    try {
      const trapFn = typeof NS.looksLikeSearchEngineTrapUrl === "function"
        ? NS.looksLikeSearchEngineTrapUrl
        : (typeof NS.looksLikeSearchEngineLandingUrl === "function"
          ? NS.looksLikeSearchEngineLandingUrl
          : null);
      if (!trapFn) return false;
      const nodes = document.querySelectorAll(
        "a.js-download[href], a[data-dl][href], a.btn-download[href], a.download-btn[href], "
        + "a.btn-blue[href], a.btn[href], a[class*='download'][href]"
      );
      let dl = 0;
      let trap = 0;
      const lim = Math.min(nodes.length, 40);
      for (let i = 0; i < lim; i++) {
        const el = nodes[i];
        const href = (el.getAttribute("href") || "").trim();
        if (!href || href === "#" || /^javascript:/i.test(href)) continue;
        const text = (el.textContent || "").replace(/\s+/g, " ").trim();
        const cls = String(el.className || "");
        const isDl = /js-download|data-dl|download-btn|btn-download/i.test(`${cls} ${el.getAttribute("data-dl") || ""}`)
          || /立即下载|免费下载|官方下载|客户端下载|下载\s*(?:Windows|macOS|Mac|Linux|Android|iOS|Win)/i.test(text)
          || (/下载/.test(text) && text.length <= 28 && /btn|download/i.test(cls));
        if (!isDl) continue;
        dl++;
        try {
          if (trapFn.call(NS, href)) trap++;
        } catch { /* ignore */ }
      }
      // ≥2 个下载 CTA 且全部/几乎全部指向搜索引擎
      return dl >= 2 && trap >= 2 && trap >= Math.ceil(dl * 0.75);
    } catch {
      return false;
    }
  };

  /** 下载页「正站」捷径的否决：年轻无备案 / 营销夹带 apex / 品牌错配 / 搜索引擎假下载 */
  NS.shouldRejectOfficialDownloadShortcut = function () {
    try {
      if (typeof NS.isYoungUnverifiedRegistration === "function"
        && NS.isYoungUnverifiedRegistration()) return true;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity()) return true;
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function"
        && NS.hostLooksLikeBrandMarketingSpoof()) return true;
      try {
        const ap = typeof NS.getRegistrableDomain === "function"
          ? NS.getRegistrableDomain(location.hostname) : location.hostname;
        const left = (String(ap || "").split(".")[0] || "").toLowerCase();
        if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(left)) return true;
      } catch { /* ignore */ }
      try {
        const corr = typeof NS.evaluateTitleHostBrandCorrelation === "function"
          ? NS.evaluateTitleHostBrandCorrelation() : null;
        if (corr && (corr.mismatch || corr.hostMatch === "padded" || corr.hostMatch === "typo"
          || corr.hostMatch === "hyphen")) return true;
      } catch { /* ignore */ }
      // ★ 用户样例：download.html 上 Windows/macOS/…「立即下载」全链 https://www.bing.com/
      try {
        if (typeof NS.pageDownloadCtasMostlySearchEngineTraps === "function"
          && NS.pageDownloadCtasMostlySearchEngineTraps()) return true;
      } catch { /* ignore */ }
      return false;
    } catch { return false; }
  };

  NS.pageLooksLikeLegitimateOfficialDownload = function () {
    try {
      // ★ todesk-ze.com.cn/download.html：仿冒下载中心长得像正站，
      // 绝不能因 /download + ToDesk 话术就跳过仿冒链（首页能检、下载页不能检的根因）。
      if (typeof NS.shouldRejectOfficialDownloadShortcut === "function"
        && NS.shouldRejectOfficialDownloadShortcut()) return false;
      // 发行版 ISO/镜像列表：合法下载页，非银狐 exe 壳
      if (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload()) return true;
      try { const corr = NS.evaluateTitleHostBrandCorrelation(); if (corr && corr.mismatch) return false; } catch { /* ignore */ }
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) return false;
      const full = NS.getHtmlSlice(100000);
      if (!full || full.length < 200) return false;
      if (NS.countTransparentProductPackages(full) >= 1) return true;
      const fieldRe = /"[A-Za-z0-9_]*Download(?:Link|Url|URI|Path)?"\s*:\s*"(https?:\/\/[^"]+\.(?:exe|dmg|pkg|apk|msi|zip|deb|rpm))"/gi;
      let fm;
      while ((fm = fieldRe.exec(full)) !== null) {
        try { if (NS.looksLikeObjectStorageHost(new URL(fm[1]).hostname)) continue; } catch { /* ignore */ }
        if (NS.looksLikeProductPackageName(NS.normalizeFileName(fm[1]))) return true;
      }
      if (/window\.__DATA__\s*=/.test(full) && /DownloadLink|downloadLink|installer|win_installer/i.test(full) && /https?:\/\/[^"'\\]+\.(?:exe|dmg|msi|pkg)/i.test(full) && NS.countTransparentProductPackages(full) >= 1) return true;
      const iceOrSpa = !!document.querySelector("#ice-container, #root, #app, #__next, #__nuxt");
      const hasTryAgain = !!document.querySelector("a.tryAgain, .hasDownload a[href], .download-success a[href], a[href*='/win/'], a[href*='/mac/']");
      const sameSiteDl = Array.from(document.querySelectorAll("a[href]")).some((a) => { const h = (a.getAttribute("href") || "").trim(); return h && NS.looksLikeOfficialProductDownloadEndpoint(h); });
      const scripts = Array.from(document.scripts || []).filter((s) => s.src).length;
      if (iceOrSpa && (hasTryAgain || sameSiteDl) && scripts >= 3 && /下载|客户端|官方/i.test(document.title || "")) return true;
      if (NS.looksLikeOfficialBrandDownloadPage(full)) return true;
      if (NS.looksLikeOfficialClientDownloadPage()) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      return false;
    } catch { return false; }
  };

  NS.isTrustedOfficialDownloadContext = function () {
    try {
      if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) return false;
      if (typeof NS.shouldRejectOfficialDownloadShortcut === "function"
        && NS.shouldRejectOfficialDownloadShortcut()) return false;
      if (NS.hostLooksLikeBrandMarketingSpoof()) return false;
      if (NS.state && NS.state._fakeBrandShellDetected) return false;
      if (NS.looksLikeMatureOfficialPortal()) return true;
      if (typeof NS.pageLooksLikeLegitimateOfficialDownload === "function" && NS.pageLooksLikeLegitimateOfficialDownload()) return true;
      if (NS.looksLikeOfficialBrandDownloadPage()) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      if (NS.looksLikeOfficialClientDownloadPage()) return true;
      const pageApex = NS.getRegistrableDomain(location.hostname);
      if (!pageApex) return false;
      // ★ 禁止「同 apex 静态资源≥3 + 标题含下载」单独放行——仿冒 download.html 极易命中
      const whoisOld = /已注册\s*(\d+)\s*天/.exec(NS.state.whoisInfo || "");
      const days = whoisOld ? parseInt(whoisOld[1], 10) : null;
      const hasIcp = typeof NS.hasValidIcpRecord === "function"
        ? NS.hasValidIcpRecord()
        : !!(NS.state.icpInfo && !/未查询到|查询失败|查询未确认|暂无/.test(NS.state.icpInfo));
      if (!hasIcp || days == null || days < 365) return false;
      let sameApexAssets = 0;
      try {
        document.querySelectorAll('script[src], link[rel="stylesheet"][href], link[rel="preconnect"][href]').forEach((el) => {
          try { const raw = el.src || el.href || ""; const h = NS.getRegistrableDomain(new URL(raw, location.href).hostname); if (h === pageApex) sameApexAssets++; } catch { /* ignore */ }
        });
      } catch { /* ignore */ }
      const title = document.title || "";
      const headText = `${title} ${(document.querySelector('meta[name="description"]')?.content || "")}`.slice(0, 500);
      const brandish = /安全|杀毒|防护|下载|产品|软件|客户端|企业|官网|官方/i.test(headText);
      if (hasIcp && days >= 365 && brandish && sameApexAssets >= 2) return true;
      if (hasIcp && days >= 365 && sameApexAssets >= 3) return true;
      return false;
    } catch { return false; }
  };

  NS.looksLikeSafeOfficialContext = function () {
    try {
      const state = NS.state;
      if (typeof NS.shouldRejectOfficialDownloadShortcut === "function"
        && NS.shouldRejectOfficialDownloadShortcut()) return false;
      const matureProfile = typeof NS.evaluateMatureLegitimateSiteProfile === "function"
        ? NS.evaluateMatureLegitimateSiteProfile() : null;
      if (matureProfile && matureProfile.trusted) return true;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity()) return false;
      if (state._seoCloakKitDetected || state._brandSpoofPortalDetected || state._fakeSpaDetected || state._fakeBrandShellDetected || state._desktopForceDlKit || state._remoteGarbleDlDetected || state._indexNowPhishTemplate) return false;
      if (typeof NS.hasHardThreatKitLocked === "function" && NS.hasHardThreatKitLocked()) return false;
      // 中文产品名 + 下载导流 + 域名无品牌拼音 → 绝非安全官方上下文（仿冒火绒首页）
      try {
        const title0 = document.title || "";
        const cn0 = typeof NS.pickChineseBrandFromPageSurface === "function"
          ? (NS.pickChineseBrandFromPageSurface(title0) || "")
          : ((title0.match(/[一-鿿]{2,4}/) || [])[0] || "");
        const host0 = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        const lab0 = (host0.split(".")[0] || "").replace(/-/g, "");
        const hasDlHub0 = !!document.querySelector("a[href*='download.html'], a[href*='/download'], a.btn-header[href]");
        const hasDlCta0 = /免费下载|立即下载|官方下载/i.test(
          Array.from(document.querySelectorAll("a,button")).slice(0, 20).map((e) => e.textContent || "").join(" ")
        );
        // 夹带域 huorong-pc 也不是安全官方；主机须与中文品牌对齐才可能安全
        // 对齐：页内共现拉丁核 / 品类结构（算法，无固定品牌桥）
        const labRaw0 = (host0.split(".")[0] || "").toLowerCase();
        const core0 = typeof NS.inferMarketingPaddedBrandCore === "function"
          ? (NS.inferMarketingPaddedBrandCore(labRaw0) || "")
          : "";
        const padded0 = !!(core0 && typeof NS.hostLabelIsPaddedBrand === "function"
          && NS.hostLabelIsPaddedBrand(lab0, core0));
        if (cn0 && cn0.length >= 2 && hasDlHub0 && hasDlCta0) {
          const hostCores0 = typeof NS.collectHostBrandCores === "function"
            ? NS.collectHostBrandCores(host0)
            : null;
          const hostHintsCn0 = typeof NS.domainLatinRootHintsChineseBrand === "function"
            && !!NS.domainLatinRootHintsChineseBrand(cn0, hostCores0);
          const titleFlat0 = title0.toLowerCase().replace(/[^a-z0-9]/g, "");
          const hostLatinInTitle0 = lab0.length >= 3 && titleFlat0.includes(lab0);
          if (padded0 || (!hostHintsCn0 && !hostLatinInTitle0)) {
            return false;
          }
        }
      } catch { /* ignore */ }
      try {
        const lab = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
        const claim = typeof NS.collectTitleAndHeadingClaimText === "function" ? NS.collectTitleAndHeadingClaimText() : (document.title || "");
        const inferred = typeof NS.inferMarketingPaddedBrandCore === "function" ? (NS.inferMarketingPaddedBrandCore(lab) || "") : "";
        const squat = typeof NS.titleBrandVsHostSquatShape === "function" ? NS.titleBrandVsHostSquatShape(claim, lab, inferred) : "";
        if (squat === "padded" || squat === "typo" || squat === "hyphen") return false;
        if (inferred && typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lab.replace(/-/g, ""), inferred)
          && /[一-鿿]{2,}/.test(claim || document.title || "")) return false;
      } catch { /* ignore */ }
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) return false;
      try {
        const title = document.title || "";
        const claimText = typeof NS.collectTitleAndHeadingClaimText === "function" ? NS.collectTitleAndHeadingClaimText() : title;
        const host = (location.hostname || "").toLowerCase().replace(/^www\./, "");
        const labelRaw = (host.split(".")[0] || "").toLowerCase();
        const label = labelRaw.replace(/-/g, "");
        const footerId = typeof NS.footerCopyrightMatchesPageHost === "function" ? NS.footerCopyrightMatchesPageHost() : { match: false, hits: 0 };
        const squat2 = typeof NS.titleBrandVsHostSquatShape === "function" ? NS.titleBrandVsHostSquatShape(claimText, labelRaw, "") : "";
        if (footerId.match && squat2 !== "padded" && squat2 !== "typo" && squat2 !== "hyphen" && squat2 !== "partial") {
          if (/^\d{3,4}$/.test(label) || (label.length >= 3 && claimText.toLowerCase().includes(label) && !/-/.test(labelRaw))) return true;
        }
        if ((/官网|官方网站|官方下载|安全中心/i.test(claimText) || footerId.hits >= 1) && label.length >= 2) {
          const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const footerText = (footerId.text || "");
          const hits = (claimText.match(new RegExp(esc, "gi")) || []).length + (footerText.match(new RegExp(esc, "gi")) || []).length;
          if (hits >= 2) {
            let sameFamily = 0;
            const pageApex = NS.getRegistrableDomain(host);
            document.querySelectorAll('script[src], link[href], img[src]').forEach((el) => {
              try {
                const raw = el.src || el.href || "";
                if (!raw || raw.startsWith("data:")) return;
                const ah = new URL(raw, location.href).hostname.toLowerCase();
                const aApex = NS.getRegistrableDomain(ah);
                if (pageApex && aApex === pageApex) sameFamily++;
                else if (label.length >= 3 && ah.replace(/[^a-z0-9]/g, "").includes(label.replace(/[^a-z0-9]/g, ""))) sameFamily++;
              } catch { /* ignore */ }
            });
            if (squat2 === "padded" || squat2 === "typo" || squat2 === "hyphen") { /* not safe */ }
            else {
              if (sameFamily >= 4) return true;
              if (/^\d{3,4}$/.test(label) && hits >= 3) return true;
              if (footerId.hits >= 2 && /版权所有|Copyright/i.test(footerText) && (claimText.toLowerCase().includes(label) || /^\d{3,4}$/.test(label)) && !/-/.test(labelRaw)) return true;
            }
          }
        }
      } catch { /* ignore */ }
      try {
        const threatHtml = NS.getThreatScanHtml(120000);
        if (NS.hasEncryptedNuxtDownloadConfig(threatHtml) && NS.countTransparentProductPackages(threatHtml) === 0) return false;
      } catch { /* ignore */ }
      if (NS.looksLikeMatureOfficialPortal()) return true;
      if (NS.looksLikeSelfConsistentOfficialSite()) return true;
      if (NS.looksLikeOfficialBrandDownloadPage()) return true;
      const title = document.title || "";
      const textLen = ((document.body && document.body.textContent) || "").replace(/\s+/g, "").length;
      const htmlQuick = NS.getThreatScanHtml(80000);
      const hasTransparent = NS.countTransparentProductPackages(htmlQuick) >= 1;
      if (!hasTransparent) {
        if (NS.looksLikeMatureOfficialPortal()) return true;
        return false;
      }
      if (/官网|官方网站|安全中心|集团/i.test(title) && textLen >= 800 && hasTransparent) return true;
      if (/官网|官方下载/i.test(title) && textLen >= 1500 && hasTransparent) return true;
      const hasIcp = typeof NS.hasValidIcpRecord === "function"
        ? NS.hasValidIcpRecord()
        : !!(NS.state.icpInfo && String(NS.state.icpInfo).trim()
          && !/未查询到|查询失败|查询未确认|暂无/.test(NS.state.icpInfo));
      if (hasIcp && textLen >= 500 && /官网|官方|下载|安全|软件/i.test(title) && hasTransparent) return true;
      return false;
    } catch { return false; }
  };
})(window.SilverfoxContent ??= {});
