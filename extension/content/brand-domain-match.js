/**
 * 品牌 ↔ 域名关联性检测（推荐流程）。
 *
 * 依赖：
 *   - pinyin-pro 仅在 Service Worker 加载，content 发送页面候选与 host 请求双向校验
 *   - tldts 可选；未加载时使用注册域启发式回退
 *
 * 品牌候选：音乐 / yinyue / yy / music(aliases)
 * 域名：tldts 按 Public Suffix 拆注册域 + 分词，再做完全/分词/拼音/首字母/别名/编辑距离/官方域匹配。
 */
;(function (NS) {
  "use strict";

  const INFRA_LABELS = new Set([
    "www", "www2", "www3", "m", "mobile", "wap", "api", "cdn", "static",
    "img", "image", "media", "assets", "login", "account", "secure",
    "mail", "ftp", "blog", "shop", "store", "dev", "test", "beta"
  ]);

  // 拼音结果缓存：避免 buildBrandForms / 扫描路径反复整词典查询卡主线程
  const _pyCache = new Map();
  const _pyInitCache = new Map();
  const _PY_CACHE_MAX = 256;

  function cachePut(map, key, val) {
    if (map.size >= _PY_CACHE_MAX) {
      const first = map.keys().next().value;
      if (first != null) map.delete(first);
    }
    map.set(key, val);
    return val;
  }

  function getPinyinPro() {
    try {
      return (typeof globalThis !== "undefined" && (globalThis.__silverfoxPinyinPro || globalThis.pinyinPro))
        || (typeof pinyinPro !== "undefined" ? pinyinPro : null);
    } catch {
      return null;
    }
  }

  function getTldts() {
    try {
      return (typeof globalThis !== "undefined" && (globalThis.__silverfoxTldts || globalThis.tldts))
        || (typeof tldts !== "undefined" ? tldts : null);
    } catch {
      return null;
    }
  }

  /**
   * 拼音在 Service Worker 中处理，content 永不 inject 大词典。
   * 返回 true 表示可用 SW 做 brand-pinyin-align（与是否 force 无关）。
   */
  NS.ensureBrandLibsLoaded = function (opts) {
    void opts;
    try {
      if (!chrome?.runtime?.id) return Promise.resolve(false);
      return Promise.resolve(true);
    } catch {
      return Promise.resolve(false);
    }
  };

  /**
   * 向 SW 请求：中文候选 ↔ 主机 pinyin 对齐，返回完整结构化证据。
   * @param {{ host?: string, candidates?: string[] }} opts
   * @returns {Promise<object|null>} 中文展示名、匹配核、拼音、host 形态与关系
   */
  NS.requestBrandPinyinAlign = function (opts) {
    try {
      const o = opts || {};
      const host = String(o.host || (typeof location !== "undefined" ? location.hostname : "") || "");
      const candidates = Array.isArray(o.candidates) ? o.candidates.slice(0, 64) : [];
      const strongCandidates = Array.isArray(o.strongCandidates) ? o.strongCandidates.slice(0, 24) : [];
      if (!host || !candidates.length) return Promise.resolve(null);
      if (!chrome?.runtime?.id) return Promise.resolve(null);
      return new Promise((resolve) => {
        try {
          chrome.runtime.sendMessage({
            type: "brand-pinyin-align",
            host,
            candidates,
            strongCandidates
          }, (res) => {
            void chrome.runtime.lastError;
            const brand = res && res.success ? String(res.brand || "").trim() : "";
            if (brand && /[\u4e00-\u9fff]{2,}/.test(brand)
              && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand))) {
              try {
                NS.silverfoxLog && NS.silverfoxLog(
                  "brand-pinyin", "bidirectional-match",
                  brand, `核=${String(res.matchedChinese || brand)}`,
                  String(res.pinyin || ""), "⇄", String(res.hostForm || ""),
                  String(res.relation || "none")
                );
              } catch { /* ignore */ }
              resolve({
                brand,
                matchedChinese: String(res.matchedChinese || "").trim(),
                pinyin: String(res.pinyin || "").trim(),
                hostForm: String(res.hostForm || "").trim(),
                relation: String(res.relation || "none"),
                score: Number(res.score) || 0
              });
            } else {
              resolve(null);
            }
          });
        } catch {
          resolve(null);
        }
      });
    } catch {
      return Promise.resolve(null);
    }
  };

  /**
   * SW 的 pinyin 证据同时决定展示名与域名关系：干净 apex exact 才是相关正站；
   * 带额外标签/连字符/污染尾的 exact 或 affix 仍是 squat。
   */
  NS.classifyBrandPinyinHostEvidence = function (evidence, hostOpt) {
    const out = { officialExact: false, hostMatch: "none", apexLabel: "", pinyin: "" };
    try {
      const e = evidence || {};
      const pinyin = String(e.pinyin || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (pinyin.length < 3) return out;
      const host = String(hostOpt || location.hostname || "").toLowerCase().replace(/^www\./, "");
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host) || host;
      const apexRaw = (String(apex).split(".")[0] || "").toLowerCase();
      const apexFlat = apexRaw.replace(/[^a-z0-9]/g, "");
      const relation = String(e.relation || "none");
      out.apexLabel = apexRaw;
      out.pinyin = pinyin;
      if (relation === "exact" && apexRaw === pinyin) {
        out.officialExact = true;
        out.hostMatch = "exact";
        return out;
      }
      if (relation === "typo") out.hostMatch = "typo";
      else if (/[-_]/.test(apexRaw) && apexFlat.includes(pinyin)) out.hostMatch = "hyphen";
      else if (apexFlat.includes(pinyin) || pinyin.includes(apexFlat)
        || relation === "host-affix" || relation === "brand-affix" || relation === "exact") {
        out.hostMatch = "padded";
      }
      return out;
    } catch {
      return out;
    }
  };

  /**
   * 多字段选举/身份槽中的强中文候选。只有这些候选可以启用较长的污染尾
   * 反证（qishui+yyds）；标题滑窗和正文残片不能取得该权限。
   */
  NS.collectStrongChineseBrandCandidates = function () {
    const out = [];
    const seen = Object.create(null);
    const push = (raw) => {
      const runs = String(raw || "").match(/[\u4e00-\u9fff]{2,24}/g) || [];
      for (let i = 0; i < Math.min(runs.length, 6); i++) {
        const s = runs[i];
        if (s.length < 2 || s.length > 8 || seen[s]) continue;
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(s)) continue;
        seen[s] = 1;
        out.push(s);
      }
    };
    try {
      const pk = NS.caches && NS.caches._primaryKw;
      if (pk) {
        push(pk.display);
        if (pk.cn) pk.cn.slice(0, 8).forEach(push);
      }
    } catch { /* ignore */ }
    try {
      if (typeof NS.extractChineseBrandFromPageTitle === "function") {
        push(NS.extractChineseBrandFromPageTitle());
      }
    } catch { /* ignore */ }
    try {
      push(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "");
      push(document.querySelector('meta[name="application-name"]')?.getAttribute("content") || "");
      push(document.querySelector("h1")?.textContent || "");
    } catch { /* ignore */ }
    return out.slice(0, 24);
  };

  /** 收集短中文候选（标题/og/选举缓存），供 SW pinyin 对齐 */
  NS.collectLightChineseBrandCandidates = function () {
    const out = [];
    const seen = Object.create(null);
    const pushOne = (raw) => {
      const s = String(raw || "").trim().replace(/[^\u4e00-\u9fff]/g, "");
      if (s.length < 2 || s.length > 8) return;
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(s)) return;
      if (seen[s]) return;
      seen[s] = 1;
      out.push(s);
    };
    const push = (raw) => {
      const text = String(raw || "").trim();
      if (!text || !/[\u4e00-\u9fff]/.test(text)) return;
      const runs = text.match(/[\u4e00-\u9fff]{2,24}/g) || [];
      // 整个短产品名优先；长营销标题再拆 2～6 字窗口交给 SW 做拼音反向筛选。
      // 先枚举全部二字窗口，保证“电脑版官方下载火绒…”中的“火绒”不会因
      // 前 24 个候选额度被前方营销文案耗尽。
      runs.slice(0, 10).forEach((run) => { if (run.length <= 8) pushOne(run); });
      for (let len = 2; len <= 6 && out.length < 64; len++) {
        for (let ri = 0; ri < Math.min(runs.length, 10) && out.length < 64; ri++) {
          const run = runs[ri];
          for (let i = 0; i + len <= run.length && out.length < 64; i++) {
            pushOne(run.slice(i, i + len));
          }
        }
      }
    };
    // 已完成的标签选举优先于标题滑窗。否则长营销标题可能先占满 64 个
    // 候选，把真正的 pk.display（如「汽水音乐」）截掉。
    try {
      const pk = NS.caches && NS.caches._primaryKw;
      if (pk) {
        if (pk.display) push(pk.display);
        if (pk.cn) pk.cn.slice(0, 8).forEach(push);
      }
    } catch { /* ignore */ }
    try {
      if (typeof NS.extractChineseBrandFromPageTitle === "function") {
        push(NS.extractChineseBrandFromPageTitle());
      }
    } catch { /* ignore */ }
    try {
      push(document.title || "");
      push(document.querySelector("h1")?.textContent || "");
      push(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "");
      push(document.querySelector('meta[name="application-name"]')?.getAttribute("content") || "");
      const m = String(document.title || "").match(/^([\u4e00-\u9fff]{2,4})应用中心/);
      if (m) push(m[1]);
    } catch { /* ignore */ }
    return out.slice(0, 64);
  };

  NS.normalizeBrandCompare = function (value) {
    try {
      return String(value ?? "")
        .normalize("NFKC")
        .toLowerCase()
        .replace(/[^\p{L}\p{N}\p{Script=Han}]+/gu, "");
    } catch {
      // 旧引擎无 Unicode property → 降级
      return String(value || "").toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/gi, "");
    }
  };

  NS.splitDomainLabel = function (value) {
    return String(value ?? "")
      .normalize("NFKC")
      .toLowerCase()
      .split(/[-_.]+/)
      .map((part) => NS.normalizeBrandCompare(part))
      .filter(Boolean);
  };

  // 热路径缓存：禁止选举排序里反复剥主机核卡死主线程
  let _hostFormsCacheKey = "";
  let _hostFormsCache = null;
  const _pyAlignCache = new Map();
  const _PY_ALIGN_CACHE_MAX = 64;

  /**
   * 当前主机的基础拉丁形态。跨标签选择不在这里自行完成，而是在拿到
   * 页面候选拼音后由候选引导，避免域名先自行推断品牌。
   */
  NS.collectHostLatinFormsForPinyin = function (hostOpt) {
    try {
      const host = NS.normalizeDomain
        ? NS.normalizeDomain(hostOpt || (typeof location !== "undefined" ? location.hostname : ""))
        : String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "")
          .replace(/^www\./i, "").toLowerCase();
      if (!host) return [];
      if (_hostFormsCache && _hostFormsCacheKey === host) return _hostFormsCache.slice();

      const out = [];
      const seen = Object.create(null);
      const add = (s) => {
        const t = String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!t || t.length < 3 || seen[t]) return;
        seen[t] = 1;
        out.push(t);
      };
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const labFlat = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      add(labFlat);
      add(labelRaw.replace(/[^a-z0-9]/g, ""));
      // 单字母/数字尾污染：huorongr → 同时保留 huorong 供「火绒」全拼对齐
      if (labFlat.length >= 6 && /^[a-z]{5,}[a-z0-9]$/i.test(labFlat)) add(labFlat.slice(0, -1));
      if (/-/.test(labelRaw)) {
        const segs = labelRaw.split("-").map((p) => p.replace(/[^a-z0-9]/g, "")).filter(Boolean);
        segs.forEach(add);
        add(segs.join(""));
      }
      let apexLeft = "";
      try {
        const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
        apexLeft = (String(apex).split(".")[0] || "").toLowerCase();
        add(apexLeft.replace(/[^a-z0-9]/g, ""));
        add(apexLeft.replace(/-/g, "").replace(/[^a-z0-9]/g, ""));
        // apex 连字符段（dingtalk-o → dingtalk + o）
        if (/-/.test(apexLeft)) {
          apexLeft.split("-").map((p) => p.replace(/[^a-z0-9]/g, "")).filter(Boolean).forEach(add);
        }
      } catch { /* ignore */ }
      // 轻量剥核：首标签 + apex（pc.dingtalk-o → 须剥 dingtalk-o，不能只看 pc）
      try {
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          add(NS.inferMarketingPaddedBrandCore(labelRaw));
          if (apexLeft) add(NS.inferMarketingPaddedBrandCore(apexLeft));
        }
        if (typeof NS.resolveHostBrandCore === "function") add(NS.resolveHostBrandCore(host));
      } catch { /* ignore */ }
      _hostFormsCacheKey = host;
      _hostFormsCache = out.slice();
      return out;
    } catch {
      return [];
    }
  };

  /**
   * 中文 → 拼音 是否与主机拉丁形态对齐（双向）：
   * - 火绒 → huorong，主机 huorongr：host 以 py 为前缀（+ 短尾垫）
   * - 钉钉 → dingding，主机 ding-apps-dingding：形态表含 dingding
   * 不要求先剥出「干净核」再展示。
   * ★ 拼音库未加载时立即 false（不阻塞主线程）。
   */
  // 仅结构品类/栏目残片（不回调 isWeak，避免与 isWeak↔pinyin 循环）
  function isStructuralWeakCnBrand(cn) {
    const s = String(cn || "").trim();
    if (!s || s.length < 2) return true;
    if (/^(?:品牌|产品|功能|特性|方案|浏览器|客户端|软件|应用|平台|工具|系统|服务|网站|主页|中心|频道|首页|杀毒|卫士|安全|终端|防护|下载|安装|官方|官网|免费|关于|中文|英文|英语|简体|繁体|语言|版本|国际|国内)$/.test(s)) {
      return true;
    }
    if (/(?:支持|中心|教程|指南|文档|新闻|帮助|客服)$/.test(s) && s.length <= 6) return true;
    return false;
  }

  /**
   * 页面候选已给出品牌核时，识别域名额外粘连的文档/支持/分发结构词。
   * 该函数不会从域名反向生成品牌，只用于候选主导的互证与 padded 风险判定。
   */
  NS.isStructuralHostAffixForBrand = function (hostValue, brandValue) {
    try {
      const host = String(hostValue || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const brand = String(brandValue || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (brand.length < 3 || host.length <= brand.length) return false;
      const affixes = [];
      if (host.startsWith(brand)) affixes.push(host.slice(brand.length));
      if (host.endsWith(brand)) affixes.push(host.slice(0, host.length - brand.length));
      return affixes.some((part) => /^(?:docs?|documentation|help|support|manual|soft|safe|downloads?|client|setup|install(?:er)?|official|free|apps?|desktop|services?)$/i.test(part));
    } catch {
      return false;
    }
  };

  /**
   * 页面中文候选经 pinyin-pro 转写后，主动从域名片段中寻找对应序列。
   * 允许跳过域名中的分发/营销片段，但不由域名单独生成品牌核心。
   */
  NS.matchLatinCandidateToHost = function (latinValue, hostOpt, opts) {
    const none = { matched: false, hostForm: "", relation: "none" };
    try {
      const target = String(latinValue || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (target.length < 2) return none;
      const rawHost = String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "")
        .toLowerCase().replace(/^www\./, "").split("/")[0];
      const tokens = rawHost.split(/[^a-z0-9]+/)
        .filter((t) => t && !/^(?:www|com|cn|net|org|co|gov|edu|ac)$/i.test(t))
        .slice(0, 16);
      if (!tokens.length) return none;

      let states = [""];
      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        const next = states.slice();
        for (let si = 0; si < states.length; si++) {
          const joined = states[si] + token;
          if (joined.length <= target.length + 2) next.push(joined);
        }
        // 仅在“页面候选 → target”已经存在时，允许该 target 去确认单标签
        // 边缘的较长污染尾。域名本身不会因此被盲切品牌核。
        const extra = token.length - target.length;
        const maxGuidedNoise = Math.max(4, Math.min(6, Math.ceil(target.length * 0.75)));
        if (opts && opts.allowLongAffix === true
          && target.length >= 5 && extra >= 3 && extra <= maxGuidedNoise
          && (token.startsWith(target) || token.endsWith(target))) {
          next.push(token);
        }
        // 三字母全大写页面身份可确认「品牌核 + 文档/支持/分发词」单标签。
        // 仍由调用方显式授权；普通短词和纯域名推断不会进入这条路径。
        if (opts && opts.allowStructuralAffix === true
          && typeof NS.isStructuralHostAffixForBrand === "function"
          && NS.isStructuralHostAffixForBrand(token, target)) {
          next.push(token);
        }
        states = Array.from(new Set(next)).slice(0, 128);
      }

      let best = none;
      const rank = { exact: 4, typo: 3, "host-affix": 2, "brand-affix": 2, none: 0 };
      for (let i = 0; i < states.length; i++) {
        const form = states[i];
        if (form.length < 2) continue;
        // 两字符品牌仅允许精确关系（QQ 等），禁止短词模糊匹配。
        const guidedStructuralAffix = opts && opts.allowStructuralAffix === true
          && typeof NS.isStructuralHostAffixForBrand === "function"
          && NS.isStructuralHostAffixForBrand(form, target);
        const relation = target === form
          ? "exact"
          : (guidedStructuralAffix
            ? "host-affix"
            : (target.length >= 3 && typeof NS.latinBrandHostRelation === "function"
              ? NS.latinBrandHostRelation(target, form) : "none"));
        if (rank[relation] > rank[best.relation]) {
          best = { matched: true, hostForm: form, relation };
        }
      }
      return best;
    } catch {
      return none;
    }
  };

  // 中文候选经 pinyin-pro 转写后也复用同一套候选主导的拉丁关系匹配。
  NS.matchPinyinToHost = function (pinyinValue, hostOpt, opts) {
    return NS.matchLatinCandidateToHost(pinyinValue, hostOpt, opts);
  };

  /**
   * 页面拉丁身份 ⇄ 域名拉丁身份的统一关系对象。
   * 页面候选确认 hostForm 是品牌片段；hostForm 同时确认页面候选属于当前站点。
   * 展示名始终来自页面原词，域名不会自行发明大小写或品牌名称。
   */
  NS.resolveMutualLatinBrandIdentity = function (pageBrand, hostOpt) {
    const empty = {
      matched: false,
      displayBrand: "",
      pageForm: "",
      hostForm: "",
      relation: "none"
    };
    try {
      const original = String(pageBrand || "").trim();
      const pageForm = original.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!original || pageForm.length < 2) return empty;
      // 短品牌只在页面明确保留全大写身份时，才允许用结构性 host 尾缀互证。
      const shortUpperAcronym = /^[A-Z][A-Z0-9]{2}$/.test(original);
      const hostMatch = NS.matchLatinCandidateToHost(pageForm, hostOpt, {
        allowStructuralAffix: shortUpperAcronym
      });
      if (!hostMatch.matched) return empty;
      let displayBrand = original;
      if (typeof NS.formatBrandTokenForDisplay === "function") {
        displayBrand = NS.formatBrandTokenForDisplay(original) || original;
      }
      return {
        matched: true,
        displayBrand,
        pageForm,
        hostForm: hostMatch.hostForm,
        relation: hostMatch.relation
      };
    } catch {
      return empty;
    }
  };

  /**
   * 中英双名桥：页内中文拼音与主机剥核拉丁共享足够前缀。
   * 例：钉钉→dingding ⇄ 主机 dingtalk / dingtalk-o（非固定品牌表）。
   */
  NS.chinesePinyinBridgesHostLatinCore = function (cnBrand, hostOpt) {
    try {
      const cn0 = String(cnBrand || "").trim().replace(/[^\u4e00-\u9fff]/g, "");
      if (!cn0 || cn0.length < 2 || isStructuralWeakCnBrand(cn0)) return false;
      let py = "";
      try {
        if (typeof NS.brandPinyin === "function") py = String(NS.brandPinyin(cn0) || "");
        if (!py && typeof NS.chineseToPinyinFlat === "function") py = String(NS.chineseToPinyinFlat(cn0) || "");
      } catch { py = ""; }
      py = py.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!py || py.length < 4) return false;

      const forms = [];
      const push = (x) => {
        const t = String(x || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (t.length >= 4 && forms.indexOf(t) < 0) forms.push(t);
      };
      try {
        if (typeof NS.resolveHostBrandCore === "function") push(NS.resolveHostBrandCore(hostOpt));
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const h = String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "")
            .toLowerCase().replace(/^www\./, "");
          const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(h) : h) || h;
          const left = (String(apex).split(".")[0] || "").toLowerCase();
          push(NS.inferMarketingPaddedBrandCore(left));
          push(left.replace(/-/g, ""));
        }
        if (typeof NS.collectHostLatinFormsForPinyin === "function") {
          (NS.collectHostLatinFormsForPinyin(hostOpt) || []).forEach(push);
        }
      } catch { /* ignore */ }
      if (!forms.length) return false;

      for (let i = 0; i < forms.length; i++) {
        const core = forms[i];
        if (core === py) return true;
        // 共享前缀 ≥4，长度接近（dingding ⇄ dingtalk）
        let common = 0;
        const n = Math.min(py.length, core.length);
        while (common < n && py.charCodeAt(common) === core.charCodeAt(common)) common += 1;
        if (common >= 4 && Math.abs(py.length - core.length) <= 3) return true;
        // 主机核以拼音为前缀（短尾垫）
        if (core.startsWith(py) && core.length - py.length <= 4) return true;
      }
      return false;
    } catch {
      return false;
    }
  };

  NS.chinesePinyinAlignsHost = function (cnBrand, hostOpt) {
    try {
      // 库未注入 / 选举进行中：禁止（防止主线程卡死全站无响应）
      if (!getPinyinPro()) {
        // 拼音库未到：仍允许中英双名桥（仅需 brandPinyin 轻量，或结构剥核）
        try {
          if (typeof NS.chinesePinyinBridgesHostLatinCore === "function"
            && NS.chinesePinyinBridgesHostLatinCore(cnBrand, hostOpt)) return true;
        } catch { /* ignore */ }
        return false;
      }
      try {
        if (NS.caches && NS.caches._primaryKwCollecting) return false;
      } catch { /* ignore */ }
      const cn0 = String(cnBrand || "").trim().replace(/[^\u4e00-\u9fff]/g, "");
      if (!cn0 || cn0.length < 2) return false;
      if (isStructuralWeakCnBrand(cn0)) return false;

      const hostKey = (() => {
        try {
          return String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "")
            .toLowerCase().replace(/^www\./, "");
        } catch { return ""; }
      })();
      const cacheKey = `${cn0}|${hostKey}`;
      if (_pyAlignCache.has(cacheKey)) return _pyAlignCache.get(cacheKey);
      const put = (v) => {
        if (_pyAlignCache.size >= _PY_ALIGN_CACHE_MAX) {
          const first = _pyAlignCache.keys().next().value;
          if (first != null) _pyAlignCache.delete(first);
        }
        _pyAlignCache.set(cacheKey, v);
        return v;
      };

      // 整段 + 前 2 字优先（火绒 / 钉钉）；最多再试 3、4 字前缀
      const variants = [cn0];
      if (cn0.length >= 2) variants.push(cn0.slice(0, 2));
      if (cn0.length >= 3) variants.push(cn0.slice(0, 3));
      if (cn0.length >= 4) variants.push(cn0.slice(0, 4));

      for (let vi = 0; vi < variants.length; vi++) {
        const cn = variants[vi];
        if (isStructuralWeakCnBrand(cn)) continue;
        const py = NS.brandPinyin(cn);
        if (!py || py.length < 3) continue;
        if (NS.matchPinyinToHost(py, hostOpt, { allowLongAffix: true }).matched) return put(true);
      }
      // ★ 钉钉(dingding) ⇄ dingtalk-o：全等/编辑距离失败时走中英双名桥
      if (typeof NS.chinesePinyinBridgesHostLatinCore === "function"
        && NS.chinesePinyinBridgesHostLatinCore(cn0, hostOpt)) return put(true);
      return put(false);
    } catch {
      return false;
    }
  };

  /**
   * 展示品牌反向校验：候选必须能从当前 host 的拉丁形态反证回来。
   * - 中文：必须由本地 pinyin 对齐，或由 SW pinyin 返回时显式标记 validated。
   * - 拉丁/混合：页面中的拉丁核必须与 host 段双向覆盖。
   * 这是最终展示门槛，不维护 WPS、火绒等固定品牌表。
   */
  NS.spoofDisplayBrandAlignsHost = function (candidate, hostOpt, opts) {
    try {
      const raw = String(candidate || "").trim();
      if (!raw) return false;
      if (typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(raw)) return false;
      const hasCn = /[\u4e00-\u9fff]/.test(raw);
      const latin = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (hasCn && !latin) {
        if (opts && opts.pinyinValidated === true) return true;
        // ★ 双向校验：中文候选必须自身能对齐当前主机（拼音 / 中英双名桥）。
        // 禁止「页内另有 ChatGPT 对齐主机 ⇒ 任意中文如「解析差异」也算对齐」——
        // 那是单向借道，曾导致 chatgpt.com 误报仿冒「解析差异」。
        if (typeof NS.chinesePinyinAlignsHost === "function" && NS.chinesePinyinAlignsHost(raw, hostOpt)) {
          return true;
        }
        if (typeof NS.chinesePinyinBridgesHostLatinCore === "function"
          && NS.chinesePinyinBridgesHostLatinCore(raw, hostOpt)) {
          return true;
        }
        return false;
      }

      if (latin.length < 2) return false;
      // 拒绝未剥干净的主机碎片展示（Dingtalko @ dingtalk-o）
      try {
        if (typeof NS.isHostShapedCompoundBrandToken === "function"
          && NS.isHostShapedCompoundBrandToken(raw, hostOpt)) return false;
      } catch { /* ignore */ }
      return !!(typeof NS.resolveMutualLatinBrandIdentity === "function"
        && NS.resolveMutualLatinBrandIdentity(raw, hostOpt).matched);
    } catch {
      return false;
    }
  };

  /**
   * 域名 ↔ 页内身份关键词双向校验（主路径，非垃圾词表）。
   * 页内任一拉丁身份核与干净 apex 互证 exact → 正站相关，软仿冒不得 arm。
   * 例：title「下载 ChatGPT」⇄ chatgpt.com；钉钉页拉丁 DingTalk ⇄ dingtalk.com。
   */
  NS.pageKeywordsBidirectionallyMatchHost = function (hostOpt) {
    try {
      const host = String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "")
        .toLowerCase().replace(/^www\./, "");
      if (!host) return false;
      // 年轻无备案夹带域不得靠双向 exact 洗白
      if (typeof NS.isYoungUnverifiedRegistration === "function"
        && NS.isYoungUnverifiedRegistration()) return false;
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity(host)) return false;

      // 干净 apex 的 mutual latin exact（最强双向）
      if (typeof NS.getCleanApexMutualLatinExactEvidence === "function") {
        const ev = NS.getCleanApexMutualLatinExactEvidence(host);
        if (ev && ev.relation === "exact") return true;
      }

      const apex = (typeof NS.getRegistrableDomain === "function"
        ? NS.getRegistrableDomain(host) : host) || host;
      const apexLeft = (String(apex).split(".")[0] || "").toLowerCase();
      const apexFlat = apexLeft.replace(/[^a-z0-9]/g, "");
      if (!apexFlat || apexFlat.length < 3) return false;
      if (/-/.test(apexLeft)) return false;
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeft)) return false;

      const kw = typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords()
        : null;
      const latinList = [...new Set([
        ...((kw && kw.latin) || []),
        ...((kw && kw.structuralLatin) || [])
      ]
        .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
        .filter((t) => t.length >= 3))];

      // 标题/og 再补扫一遍拉丁（选举缓存未含 ChatGPT 时仍能互证）
      try {
        const surface = [
          document.title || "",
          document.querySelector("h1")?.textContent || "",
          document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "",
          document.querySelector('meta[property="og:title"]')?.getAttribute("content") || ""
        ].join(" ");
        const words = surface.match(/[A-Za-z][A-Za-z0-9]{2,23}/g) || [];
        for (let i = 0; i < Math.min(words.length, 40); i++) {
          const flat = words[i].toLowerCase().replace(/[^a-z0-9]/g, "");
          if (flat.length >= 3 && latinList.indexOf(flat) < 0) latinList.push(flat);
        }
      } catch { /* ignore */ }

      for (let i = 0; i < latinList.length; i++) {
        const t = latinList[i];
        if (!t || /^(?:download|official|client|windows|macos|android|linux|ai|gpt|ml|bot)$/i.test(t)) {
          continue;
        }
        // 双向：页内词 → 主机，且主机核 → 能被该词覆盖（exact）
        if (typeof NS.resolveMutualLatinBrandIdentity === "function") {
          const m = NS.resolveMutualLatinBrandIdentity(t, host);
          if (m && m.matched && m.relation === "exact"
            && String(m.pageForm || "") === apexFlat
            && String(m.hostForm || "") === apexFlat) {
            return true;
          }
        }
        if (t === apexFlat || t === apexLeft.replace(/[^a-z0-9]/g, "")) return true;
      }

      // 关系层：evaluateDomainKeywordRelevance 已是关键词→域名综合双向结果
      if (typeof NS.evaluateDomainKeywordRelevance === "function") {
        const rel = NS.evaluateDomainKeywordRelevance(host);
        if (rel && rel.related && !rel.squat
          && (rel.hostMatch === "exact" || rel.hostMatch === "category")) {
          return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  };

  /** 拼音库注入后清对齐缓存 */
  NS.clearHostPinyinAlignCaches = function () {
    try {
      _hostFormsCacheKey = "";
      _hostFormsCache = null;
      _pyAlignCache.clear();
    } catch { /* ignore */ }
  };

  /**
   * 从标题/身份槽 +（可选）已缓存选举结果里，用 pinyin 与主机双向对齐选出展示名。
   * ★ 禁止在 collectPrimaryBrandKeywords 进行中再调 collect（重入卡死白屏）。
   */
  NS.pickPageChineseBrandByHostPinyin = function (hostOpt) {
    try {
      const api = getPinyinPro();
      if (!api || typeof api.pinyin !== "function") return "";

      const candidates = [];
      const seen = Object.create(null);
      const push = (raw) => {
        let s = String(raw || "").trim();
        if (!s || !/[\u4e00-\u9fff]/.test(s)) return;
        s = s.replace(/(?:官方网站|官网|官方|免费下载|下载|客户端|正版).*$/u, "").trim();
        const only = s.replace(/[^\u4e00-\u9fff]/g, "");
        if (only.length >= 2 && only.length <= 8) s = only;
        if (!/^[\u4e00-\u9fff]{2,8}$/.test(s)) return;
        if (isStructuralWeakCnBrand(s)) return;
        if (seen[s]) return;
        seen[s] = 1;
        candidates.push(s);
      };

      // 仅读缓存选举结果，绝不重入 collect
      try {
        const c = NS.caches || {};
        const pk = c._primaryKw;
        const collecting = !!(c._primaryKwCollecting);
        if (pk && !collecting) {
          if (pk.cn) pk.cn.forEach(push);
          if (pk.display) push(pk.display);
          if (pk.scores) {
            Object.keys(pk.scores).forEach((name) => {
              if (/[\u4e00-\u9fff]/.test(name)) push(name);
            });
          }
        }
      } catch { /* ignore */ }

      // 标题/身份槽（轻量，不扫 body）
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          push(NS.extractChineseBrandFromPageTitle());
        }
      } catch { /* ignore */ }
      try {
        const title = String(document.title || "");
        const h1 = String(document.querySelector("h1")?.textContent || "");
        // 壳：xx应用中心
        const shell = (title.match(/^([\u4e00-\u9fff]{2,4})应用中心/) || title.match(/([\u4e00-\u9fff]{2,4})应用中心/) || [])[1];
        if (shell) push(shell);
        const runs = `${title} ${h1}`.match(/[\u4e00-\u9fff]{2,4}/g) || [];
        for (let ri = 0; ri < Math.min(runs.length, 8); ri++) {
          push(runs[ri]);
          if (runs[ri].length >= 2) push(runs[ri].slice(0, 2));
        }
      } catch { /* ignore */ }

      let best = "";
      let bestScore = -1;
      const limit = Math.min(candidates.length, 16);
      for (let i = 0; i < limit; i++) {
        const cn = candidates[i];
        if (!NS.chinesePinyinAlignsHost(cn, hostOpt)) continue;
        const py = NS.brandPinyin(cn) || "";
        const match = NS.matchPinyinToHost(py, hostOpt);
        let score = 50;
        if (match.relation === "exact") score = 100;
        else if (match.relation === "typo") score = 90;
        else if (match.relation === "host-affix" || match.relation === "brand-affix") score = 80;
        if (cn.length === 2) score += 12;
        if (score > bestScore) {
          bestScore = score;
          best = cn;
        }
      }
      return best;
    } catch {
      return "";
    }
  };

  /**
   * 定稿：优先标题中文 / 缓存选举 cn，再用 pinyin 对齐主机。
   * 不重入 collect（选举进行中只读缓存+标题）。
   */
  NS.resolveChineseBrandForHostDisplay = function (hostOpt, latinHintOpt) {
    try {
      // 0) 标题硬抽优先（钉钉应用中心 → 钉钉），不依赖 pinyin
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          const tb = NS.extractChineseBrandFromPageTitle();
          if (tb && /[\u4e00-\u9fff]{2,}/.test(tb)) {
            if (!getPinyinPro() || NS.chinesePinyinAlignsHost(tb, hostOpt)) return tb;
            // 标题壳专名即使 pinyin 未对齐也优先于拉丁 Dingding
            if (/^[\u4e00-\u9fff]{2,4}$/.test(tb) && !isStructuralWeakCnBrand(tb)) return tb;
          }
        }
      } catch { /* ignore */ }

      // 1) 只读缓存选举，禁止重入 collect
      let pk = null;
      try {
        const c = NS.caches || {};
        if (c._primaryKw && !c._primaryKwCollecting) pk = c._primaryKw;
        else if (!c._primaryKwCollecting && typeof NS.collectPrimaryBrandKeywords === "function") {
          pk = NS.collectPrimaryBrandKeywords();
        }
      } catch { /* ignore */ }

      if (pk) {
        const disp = String(pk.display || "").trim();
        if (disp && /[\u4e00-\u9fff]{2,}/.test(disp) && !isStructuralWeakCnBrand(disp)) {
          if (!getPinyinPro() || NS.chinesePinyinAlignsHost(disp, hostOpt)) return disp;
        }
        if (pk.cn && pk.cn.length) {
          if (getPinyinPro()) {
            for (let i = 0; i < Math.min(pk.cn.length, 12); i++) {
              const c = String(pk.cn[i] || "").trim();
              if (!c || !/[\u4e00-\u9fff]{2,}/.test(c)) continue;
              if (NS.chinesePinyinAlignsHost(c, hostOpt)) return c;
            }
          }
          const c0 = String(pk.cn[0] || "").trim();
          if (c0 && /[\u4e00-\u9fff]{2,}/.test(c0) && !isStructuralWeakCnBrand(c0)) return c0;
        }
      }

      if (getPinyinPro()) {
        const byHost = NS.pickPageChineseBrandByHostPinyin(hostOpt);
        if (byHost) return byHost;
      }

      let core = String(latinHintOpt || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if ((!core || core.length < 4) && typeof NS.resolveHostBrandCore === "function") {
        core = String(NS.resolveHostBrandCore(hostOpt) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      }
      if (core && core.length >= 6 && /^[a-z]{5,}[a-z0-9]$/i.test(core)) core = core.slice(0, -1);
      if (core && typeof NS.pickChineseBrandMatchingLatinCore === "function") {
        const cn = NS.pickChineseBrandMatchingLatinCore(core);
        if (cn && /[\u4e00-\u9fff]{2,}/.test(cn)) return cn;
      }
      return "";
    } catch {
      return "";
    }
  };

  /**
   * 用 pinyin-pro.match 在中文文本中定位与拉丁核全拼对应的汉字串。
   * 例：text=「官方钉钉下载」、latin=dingding → 「钉钉」
   * 亦接受 host flat（huorongr）：会尝试与页内中文双向对齐。
   * @returns {string} 匹配到的连续中文，或 ""
   */
  NS.findChineseBrandByPinyinInText = function (latinCore, textOpt) {
    try {
      try {
        if (NS.caches && NS.caches._primaryKwCollecting) return "";
      } catch { /* ignore */ }
      const api = getPinyinPro();
      if (!api || typeof api.pinyin !== "function") return "";

      // 优先轻量：标题/身份槽双向（不读 body）
      try {
        const byHost = NS.pickPageChineseBrandByHostPinyin();
        if (byHost) return byHost;
      } catch { /* fall through */ }

      const core = String(latinCore || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const forms = core && core.length >= 3
        ? [core, ...NS.collectHostLatinFormsForPinyin()]
        : NS.collectHostLatinFormsForPinyin();
      const uniqForms = [];
      const seenF = Object.create(null);
      forms.forEach((f) => {
        const t = String(f || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (t.length >= 3 && !seenF[t]) { seenF[t] = 1; uniqForms.push(t); }
      });
      if (!uniqForms.length) return "";

      // 仅身份槽短文本，禁止 body.innerText 扫整页（曾导致全站无响应）
      let text = String(textOpt || "");
      if (!text) {
        try {
          text = [
            document.title || "",
            document.querySelector("h1")?.textContent || "",
            document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "",
            document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || ""
          ].filter(Boolean).join("\n");
        } catch {
          text = String(document.title || "");
        }
      }
      text = String(text || "").slice(0, 600);
      if (!/[\u4e00-\u9fff]{2,}/.test(text)) return "";

      // 1) 对各主机形态 pinyin-pro.match
      if (typeof api.match === "function") {
        for (let fi = 0; fi < uniqForms.length; fi++) {
          const form = uniqForms[fi];
          let idxs = null;
          try {
            idxs = api.match(text, form, {
              precision: "every", continuous: true, space: "ignore", insensitive: true, v: true
            });
          } catch { idxs = null; }
          if (!idxs || !idxs.length) {
            try {
              idxs = api.match(text, form, {
                precision: "start", continuous: true, space: "ignore", insensitive: true, v: true
              });
            } catch { idxs = null; }
          }
          if (Array.isArray(idxs) && idxs.length >= 2) {
            const sorted = idxs.map(Number).filter((n) => Number.isFinite(n) && n >= 0).sort((a, b) => a - b);
            if (sorted.length >= 2) {
              const start = sorted[0];
              const end = sorted[sorted.length - 1];
              if (end >= start && end - start <= 12) {
                let cn = text.slice(start, end + 1).replace(/[^\u4e00-\u9fff]/g, "");
                if (cn.length >= 2 && cn.length <= 8
                  && !isStructuralWeakCnBrand(cn)
                  && NS.chinesePinyinAlignsHost(cn)) {
                  return cn;
                }
              }
            }
          }
        }
      }

      // 2) 仅 2 字窗、最多 8 段 run（禁止重 isWeak + 大滑动窗）
      const runs = text.match(/[\u4e00-\u9fff]{2,6}/g) || [];
      for (let ri = 0; ri < Math.min(runs.length, 8); ri++) {
        const run = runs[ri];
        const maxStart = Math.min(run.length - 2, 4);
        for (let i = 0; i <= maxStart; i++) {
          const pair = run.slice(i, i + 2);
          if (isStructuralWeakCnBrand(pair)) continue;
          if (NS.chinesePinyinAlignsHost(pair)) return pair;
        }
      }
      return "";
    } catch {
      return "";
    }
  };

  /**
   * 中文/混合串 → 无调拼音（依赖 pinyin-pro；未加载时返回 ""）。
   */
  NS.brandPinyin = function (value) {
    try {
      // 选举进行中禁止 pinyin 词典查询（全站卡死）
      try {
        if (NS.caches && NS.caches._primaryKwCollecting) return "";
      } catch { /* ignore */ }
      const raw = String(value || "");
      if (!raw || raw.length > 48) return "";
      if (_pyCache.has(raw)) return _pyCache.get(raw);
      const api = getPinyinPro();
      // 库未加载：绝不缓存空串，否则注入后永远钉死（钉钉→""）
      if (!api || typeof api.pinyin !== "function") return "";
      const py = api.pinyin(raw, {
        toneType: "none",
        type: "array",
        nonZh: "consecutive",
        v: true
      });
      const joined = Array.isArray(py) ? py.join("") : String(py || "");
      const norm = NS.normalizeBrandCompare(joined);
      // 仅缓存非空结果
      if (norm) return cachePut(_pyCache, raw, norm);
      return "";
    } catch {
      return "";
    }
  };

  /** 清空拼音缓存（库注入后调用） */
  NS.clearBrandPinyinCaches = function () {
    try { _pyCache.clear(); } catch { /* ignore */ }
    try { _pyInitCache.clear(); } catch { /* ignore */ }
  };

  /**
   * 中文 → 拼音首字母串（yy 等）。
   */
  NS.brandPinyinInitials = function (value) {
    try {
      const raw = String(value || "");
      if (!raw || raw.length > 48) return "";
      if (_pyInitCache.has(raw)) return _pyInitCache.get(raw);
      const api = getPinyinPro();
      if (!api || typeof api.pinyin !== "function") return "";
      const py = api.pinyin(raw, {
        pattern: "first",
        toneType: "none",
        type: "array",
        nonZh: "consecutive",
        v: true
      });
      const joined = Array.isArray(py) ? py.join("") : String(py || "");
      const norm = NS.normalizeBrandCompare(joined);
      if (norm) return cachePut(_pyInitCache, raw, norm);
      return "";
    } catch {
      return "";
    }
  };

  /**
   * 混合品牌（短拉丁 + 中文）：QQ音乐、iQOO 等。
   * 拆出 latinHead + 中文尾，供 qq+music / qq+yinyue 组合候选。
   * @returns {{ latin: string, cnRest: string }|null}
   */
  NS.splitMixedLatinChineseBrand = function (brand) {
    try {
      const s = String(brand || "").trim();
      // QQ音乐 / WX音乐 / 163音乐 / 酷狗已是纯中文不走此路径
      const m = s.match(/^([A-Za-z][A-Za-z0-9]{0,7})\s*([一-鿿].+)$/);
      if (!m) return null;
      const latin = String(m[1] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const cnRest = String(m[2] || "").replace(/\s+/g, "");
      if (latin.length < 1 || latin.length > 8 || !/[一-鿿]/.test(cnRest)) return null;
      return { latin, cnRest };
    } catch {
      return null;
    }
  };

  /**
   * 生成品牌全部可比较形式。
   * - 音乐 + aliases → 音乐、yinyue、yy、music
   * - QQ音乐 → 另生成 qq、qqyinyue、qqmusic、qqmusics、qqyinle（拉丁核+品类粘连）
   */
  NS.buildBrandForms = function (brand, aliases) {
    const sources = [brand].concat(Array.isArray(aliases) ? aliases : []).filter(Boolean);
    const forms = new Set();
    const add = (v) => {
      const n = NS.normalizeBrandCompare(v);
      if (n) forms.add(n);
    };

    for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      const raw = NS.normalizeBrandCompare(source);
      const fullPinyin = NS.brandPinyin(source);
      const initials = NS.brandPinyinInitials(source);
      if (raw) forms.add(raw);
      if (fullPinyin) forms.add(fullPinyin);
      if (initials && initials.length >= 2) forms.add(initials);
    }

    // 混合品牌组合：QQ音乐 → qq + (yinyue|music|musics|yinle)
    try {
      const mixed = typeof NS.splitMixedLatinChineseBrand === "function"
        ? NS.splitMixedLatinChineseBrand(brand)
        : null;
      if (mixed && mixed.latin) {
        add(mixed.latin);
        const cnPy = NS.brandPinyin(mixed.cnRest);
        if (cnPy) add(mixed.latin + cnPy);
        const cnInit = NS.brandPinyinInitials(mixed.cnRest);
        if (cnInit && cnInit.length >= 2) add(mixed.latin + cnInit);

        const morphs = typeof NS.extractChineseProductMorphSuffixes === "function"
          ? NS.extractChineseProductMorphSuffixes(mixed.cnRest)
          : [];
        // 整段中文尾也当 morph
        if (mixed.cnRest && morphs.indexOf(mixed.cnRest) < 0) morphs.push(mixed.cnRest);

        for (let mi = 0; mi < morphs.length; mi++) {
          const morph = morphs[mi];
          if (!morph) continue;
          add(morph);
          const mpy = NS.brandPinyin(morph);
          if (mpy) {
            add(mpy);
            add(mixed.latin + mpy);
          }
          const minit = NS.brandPinyinInitials(morph);
          if (minit && minit.length >= 2) {
            add(minit);
            add(mixed.latin + minit);
          }
          // 品类英文粘连（域名仿冒常用 qqmusic，非品牌名单）
          if (/音乐|播放|歌曲|听歌/.test(morph)) {
            add(mixed.latin + "music");
            add(mixed.latin + "musics");
            add(mixed.latin + "yinle");
            add(mixed.latin + "yinyue");
          }
          if (/安全|杀毒|卫士|防护/.test(morph)) {
            add(mixed.latin + "security");
            add(mixed.latin + "safe");
          }
        }
      }
    } catch { /* ignore */ }

    return Array.from(forms);
  };

  NS.levenshteinBrand = function (a, b) {
    const left = NS.normalizeBrandCompare(a);
    const right = NS.normalizeBrandCompare(b);
    const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
    for (let i = 1; i <= left.length; i++) {
      let diagonal = previous[0];
      previous[0] = i;
      for (let j = 1; j <= right.length; j++) {
        const old = previous[j];
        previous[j] = Math.min(
          previous[j] + 1,
          previous[j - 1] + 1,
          diagonal + (left[i - 1] === right[j - 1] ? 0 : 1)
        );
        diagonal = old;
      }
    }
    return previous[right.length];
  };

  NS.brandFormSimilarity = function (a, b) {
    const left = NS.normalizeBrandCompare(a);
    const right = NS.normalizeBrandCompare(b);
    if (!left || !right) return 0;
    if (left === right) return 1;
    return 1 - NS.levenshteinBrand(left, right) / Math.max(left.length, right.length);
  };

  /**
   * 拉丁品牌与域名形态的通用关系。分隔符先归一化；5 字符以上允许一次
   * 插入/删除/替换，9 字符以上才允许两次，避免短通用词被模糊命中。
   * 返回关系而非布尔值，调用方可以把 typo 当风险、exact 当佐证。
   */
  NS.latinBrandHostRelation = function (brandValue, hostValue) {
    try {
      const brand = String(brandValue || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const host = String(hostValue || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (brand.length < 3 || host.length < 3) return "none";
      if (brand === host) return "exact";
      if (brand.length >= 4 && host.includes(brand)) return "host-affix";
      if (host.length >= 4 && brand.includes(host)) return "brand-affix";
      const minLen = Math.min(brand.length, host.length);
      if (minLen < 5 || Math.abs(brand.length - host.length) > 2) return "none";
      const distance = NS.levenshteinBrand(brand, host);
      if (distance === 1) return "typo";
      if (distance === 2 && minLen >= 9) return "typo";
      return "none";
    } catch {
      return "none";
    }
  };

  /**
   * 用 tldts 解析主机（Public Suffix List）。
   * @returns {{ hostname, domain, domainWithoutSuffix, subdomain, publicSuffix }|null}
   */
  NS.parseHostWithTldts = function (hostOrUrl) {
    try {
      let hostname = String(hostOrUrl || "").trim();
      if (!hostname) return null;
      if (/^https?:\/\//i.test(hostname) || hostname.includes("/")) {
        try {
          hostname = new URL(hostname.includes("://") ? hostname : `https://${hostname}`).hostname;
        } catch {
          return null;
        }
      }
      hostname = hostname.replace(/\.$/, "").toLowerCase();
      const api = getTldts();
      if (api && typeof api.parse === "function") {
        const info = api.parse(hostname, {
          extractHostname: false,
          allowPrivateDomains: true
        });
        return {
          hostname: info.hostname || hostname,
          domain: info.domain || "",
          domainWithoutSuffix: info.domainWithoutSuffix || "",
          subdomain: info.subdomain || "",
          publicSuffix: info.publicSuffix || "",
          isPrivate: info.isPrivate === true,
          isIcann: info.isIcann === true,
          pslAvailable: true
        };
      }
      // 无 tldts 时回退到旧 eTLD+1 启发（com.cn / co.uk）
      const apex = typeof NS.getRegistrableDomainFallback === "function"
        ? NS.getRegistrableDomainFallback(hostname)
        : (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(hostname) : hostname);
      const left = hostname === apex ? "" : hostname.slice(0, -(apex.length + 1));
      const rootLabel = (apex.split(".")[0] || "").toLowerCase();
      return {
        hostname,
        domain: apex,
        domainWithoutSuffix: rootLabel,
        subdomain: left,
        publicSuffix: apex.includes(".") ? apex.slice(rootLabel.length + 1) : "",
        isPrivate: false,
        isIcann: false,
        pslAvailable: false
      };
    } catch {
      return null;
    }
  };

  /**
   * 品牌 ↔ 域名关联检测。
   *
   * @param {{ brand: string, url?: string, host?: string, aliases?: string[], officialDomains?: string[] }} opts
   * @returns {{ score, level, reasons, brandForms, rootLabel, registrableDomain, hostname, subdomainLabels }}
   */
  NS.checkBrandDomain = function (opts) {
    // ★ 禁止在此 inject pinyin-pro：evaluateDomain/home-fast 每页都会走到，
    // 注入整包 umd 会卡死所有标签页。库仅由 commitBrandSpoofPresentation force 注入。
    const o = opts || {};
    const brand = String(o.brand || "").trim();
    const aliases = Array.isArray(o.aliases) ? o.aliases : [];
    const officialDomains = Array.isArray(o.officialDomains) ? o.officialDomains : [];
    const empty = {
      brand,
      hostname: "",
      registrableDomain: "",
      rootLabel: "",
      subdomainLabels: [],
      brandForms: [],
      score: 0,
      level: "invalid",
      reasons: ["域名或 URL 格式无效"]
    };

    let hostname = "";
    try {
      const raw = o.url || o.host || (typeof location !== "undefined" ? location.hostname : "");
      if (!raw) return empty;
      if (/^https?:\/\//i.test(raw) || String(raw).includes("/")) {
        hostname = new URL(String(raw).includes("://") ? raw : `https://${raw}`).hostname;
      } else {
        hostname = String(raw).replace(/^www\./i, "").split("/")[0];
      }
      hostname = hostname.replace(/\.$/, "").toLowerCase();
    } catch {
      return empty;
    }

    const domainInfo = NS.parseHostWithTldts(hostname);
    if (!domainInfo || !domainInfo.hostname) {
      return { ...empty, hostname, reasons: ["无法解析域名"] };
    }

    const rootLabel = NS.normalizeBrandCompare(domainInfo.domainWithoutSuffix);
    const subdomainLabels = NS.splitDomainLabel(domainInfo.subdomain)
      .filter((label) => !INFRA_LABELS.has(label));
    const rootTokens = NS.splitDomainLabel(domainInfo.domainWithoutSuffix);
    const allTokens = [...new Set([rootLabel, ...rootTokens, ...subdomainLabels])].filter(Boolean);
    const brandForms = NS.buildBrandForms(brand, aliases);

    let score = 0;
    const reasons = [];

    // 已知官方域名
    const officialMatch = officialDomains.some((item) => {
      try {
        const officialHost = new URL(
          String(item).includes("://") ? item : `https://${item}`
        ).hostname.toLowerCase();
        return hostname === officialHost || hostname.endsWith(`.${officialHost}`);
      } catch {
        return false;
      }
    });
    if (officialMatch) {
      score += 100;
      reasons.push("命中已知官方域名");
    }

    for (let fi = 0; fi < brandForms.length; fi++) {
      const form = brandForms[fi];
      if (!form) continue;

      // 完全匹配注册域左标
      if (rootLabel === form) {
        score = Math.max(score, 90);
        reasons.push(`注册域名与品牌形式完全一致：${form}`);
        continue;
      }

      // 注册域分词
      if (rootTokens.indexOf(form) >= 0) {
        score = Math.max(score, 80);
        reasons.push(`注册域名分词命中品牌形式：${form}`);
        continue;
      }

      // 子域名
      if (subdomainLabels.indexOf(form) >= 0) {
        score = Math.max(score, 55);
        reasons.push(`子域名命中品牌形式：${form}`);
      }

      // 包含（前缀/后缀）
      if (form.length >= 4 && (rootLabel.startsWith(form) || rootLabel.endsWith(form))) {
        score = Math.max(score, 70);
        reasons.push(`注册域名包含品牌形式：${form}`);
      }

      // 编辑距离 / 相似度
      for (let ti = 0; ti < allTokens.length; ti++) {
        const token = allTokens[ti];
        if (form.length < 4 || token.length < 4) continue;
        const value = NS.brandFormSimilarity(form, token);
        if (value >= 0.9) {
          score = Math.max(score, 65);
          reasons.push(`域名与品牌形式高度相似：${form} ↔ ${token}`);
        } else if (value >= 0.8) {
          score = Math.max(score, 45);
          reasons.push(`域名与品牌形式可能相似：${form} ↔ ${token}`);
        }
      }
    }

    score = Math.min(score, 100);
    let level = "weak";
    if (score >= 90) level = "strong";
    else if (score >= 65) level = "likely";
    else if (score >= 40) level = "possible";

    return {
      brand,
      hostname: domainInfo.hostname || hostname,
      registrableDomain: domainInfo.domain || "",
      rootLabel,
      subdomainLabels,
      brandForms,
      score,
      level,
      reasons: [...new Set(reasons)],
      domainWithoutSuffix: domainInfo.domainWithoutSuffix || rootLabel,
      subdomain: domainInfo.subdomain || ""
    };
  };

  /**
   * 页内中文品牌 vs 当前主机：是否「域名像该品牌」的结构仿冒壳。
   *
   * 例：
   * - 页内 QQ音乐 + qqmusic.com / qq-musics.com / qqyinle.com → squat
   * - 页内 QQ音乐 + music.qq.com / y.qq.com → 正站产品子域，不 squat
   * - 页内 汽水音乐 + qissmusic.com → squat（拼音/近拼 + music）
   */
  NS.detectBrandDomainSquatFromClaim = function (cnBrand, hostOpt, aliasesOpt) {
    // 热路径：无 pinyin 时仅做轻量结构，避免 checkBrandDomain 拉起大库逻辑
    // （ensureBrandLibs 已从 checkBrandDomain 移除；此处再挡一次重计算）
    try {
      const brand = String(cnBrand || "").trim();
      if (!brand || !/[一-鿿]/.test(brand)) return null;
      const host = String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "");
      if (!host) return null;

      // 正站产品子域（music.qq.com / y.qq.com）绝不当仿冒
      try {
        if (typeof NS.hostLooksLikeOfficialProductSubdomain === "function"
          && NS.hostLooksLikeOfficialProductSubdomain(host)) {
          return null;
        }
        if (typeof NS.hostIsProductSubdomainOfBrandApex === "function"
          && NS.hostIsProductSubdomainOfBrandApex(host)) {
          const apex = typeof NS.getRegistrableDomain === "function"
            ? NS.getRegistrableDomain(host) : host;
          const apexLeft = (String(apex || "").split(".")[0] || "").toLowerCase();
          // 干净短品牌根（qq）上的产品子域
          if (apexLeft.length >= 2 && apexLeft.length <= 4
            && !(typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
              && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeft))) {
            return null;
          }
        }
      } catch { /* ignore */ }

      const aliases = Array.isArray(aliasesOpt) ? aliasesOpt.slice() : [];
      // 页内拉丁 token 也可作 alias
      try {
        const kw = typeof NS.collectPrimaryBrandKeywords === "function"
          ? NS.collectPrimaryBrandKeywords()
          : null;
        (kw && kw.latin || []).forEach((t) => {
          const s = String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          if (s.length >= 2 && s.length <= 16) aliases.push(s);
        });
      } catch { /* ignore */ }
      // 品类尾也展开候选：汽水音乐 → 再生成 音乐 的 yinyue / yy
      try {
        if (typeof NS.extractChineseProductMorphSuffixes === "function") {
          NS.extractChineseProductMorphSuffixes(brand).forEach((m) => {
            if (m && m !== brand) aliases.push(m);
          });
        }
      } catch { /* ignore */ }
      // 软件域名常见英文品类别名（结构，非品牌表）
      try {
        if (/音乐|播放|听歌|歌曲/.test(brand)) {
          aliases.push("music", "musics", "player");
        }
        if (/安全|杀毒|卫士|防护/.test(brand)) {
          aliases.push("security", "secure", "antivirus");
        }
      } catch { /* ignore */ }

      const rel = NS.checkBrandDomain({ brand, host, aliases });
      if (!rel || rel.level === "invalid") return null;

      // 显式官方域列表 → 不 squat
      if (rel.score >= 100 || ((rel.reasons || []).some((r) => /已知官方域名/.test(String(r))))) {
        return null;
      }

      // 粘连假域：注册域本身 = 拉丁核+品类（qqmusic），且页内宣称混合品牌含该拉丁核
      // 与 music.qq.com（注册域根=qq）区分：后者 rootLabel 是 qq 且 host 是产品子域，已在上方放行
      let gluedHit = false;
      try {
        const mixed = typeof NS.splitMixedLatinChineseBrand === "function"
          ? NS.splitMixedLatinChineseBrand(brand)
          : null;
        const root = String(rel.rootLabel || "").toLowerCase();
        if (mixed && mixed.latin && root.length > mixed.latin.length + 2) {
          if (root.startsWith(mixed.latin)
            && (typeof NS.isLatinSoftwareProductDomainPad === "function"
              ? NS.isLatinSoftwareProductDomainPad(root.slice(mixed.latin.length))
              : /^(?:musics?|yinyue|yinle|player|security|safe)$/i.test(root.slice(mixed.latin.length)))) {
            gluedHit = true;
          }
          // 品牌组合形式精确命中注册域（qqmusic ∈ brandForms）
          if ((rel.brandForms || []).indexOf(root) >= 0 && root.startsWith(mixed.latin)) {
            gluedHit = true;
          }
        }
      } catch { /* ignore */ }

      // 有品牌形式落在注册域分词 / 包含 / 高相似 → 半真半假结构
      const hasTokenHit = gluedHit || (rel.reasons || []).some((r) =>
        /分词命中|完全一致|包含品牌|高度相似|可能相似|子域名命中/.test(String(r)));
      if (!hasTokenHit && rel.score < 40) return null;

      // 纯弱分且无 token 证据 → 不拦
      if (rel.score < 45 && !hasTokenHit && !gluedHit) return null;

      // 仅 rootLabel=qq 完全一致、且不是粘连假域：更像正站品牌根（qq.com），不当 squat
      // 粘连假域 qqmusic 会 gluedHit 或 forms 含 qqmusic
      if (!gluedHit && rel.score >= 90
        && (rel.reasons || []).some((r) => /完全一致/.test(String(r)))
        && String(rel.rootLabel || "").length <= 4) {
        // 极短核 exact 且无粘连证据：可能是正站 apex 访问，交给其它逻辑
        return null;
      }

      // 强命中拼音/别名/粘连但非已知官方域 → 仿冒结构
      const hostMatch = (gluedHit || rel.score >= 65) ? "typo" : "partial";

      return {
        brandToken: rel.rootLabel || "",
        hostMatch,
        prefix: rel.rootLabel || "",
        suffix: "",
        chineseSuffix: brand,
        expectedHostLabel: rel.rootLabel || "",
        score: Math.max(rel.score, gluedHit ? 80 : 0),
        level: gluedHit ? "likely" : rel.level,
        brandForms: rel.brandForms,
        reasons: gluedHit
          ? [...(rel.reasons || []), "拉丁核+品类粘连注册域（如 qqmusic）"]
          : rel.reasons
      };
    } catch {
      return null;
    }
  };
})(window.SilverfoxContent ??= {});
