/**
 * ICP/WHOIS 网络查询 + 24h 缓存 + 下载行为探测。
 * 所有外部 HTTP(S) 必须经 background SW（content-script fetch 受 CORS 限制）。
 */
;(function (NS) {
  "use strict";

  const ICP_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  // 聚合“无备案”只短期复用：避免每次刷新都重打三个来源，同时不给第三方滞后
  // 结果造成长期钉死。任一备案号正缓存仍优先于该负缓存。
  const ICP_MISS_CACHE_TTL_MS = 15 * 60 * 1000;
  const ICP_CACHE_KEY_PREFIX = "icp_cache_v4_";
  const ICP_MISS_KEY_PREFIX = "icp_miss_v2_";
  // 顺序：爱站 → beiancx → uapis（race 并行，任一命中备案号即返回）
  const ICP_CACHE_SOURCES = ["aizhan", "beiancx", "uapis"];
  const WHOIS_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  // v6：禁止用 ageDays 伪造 registeredAt；拒绝 gov.cn/com.cn 公共后缀结果；缓存失效旧脏数据
  const WHOIS_CACHE_KEY_PREFIX = "whois_cache_v6_";

  /**
   * 所有外部 HTTP(S) 经 background SW。content-script fetch 受 CORS 限制。
   * @param {string} url
   * @param {{ method?: string, body?: string, contentType?: string, timeoutMs?: number,
   *           redirect?: string, statusOnly404?: boolean }} [opts]
   */
  NS.fetchPageTextFromBackground = function (url, opts = {}) {
    return new Promise((resolve) => {
      try {
        if (!chrome?.runtime?.id) { resolve({ success: false, error: "no-extension-runtime" }); return; }
        const payload = { type: "fetchPageText", url, method: opts.method || "GET", body: opts.body, contentType: opts.contentType, timeoutMs: opts.timeoutMs != null ? opts.timeoutMs : 5000, redirect: opts.redirect || "follow", statusOnly404: opts.statusOnly404 === true };
        chrome.runtime.sendMessage(payload, (response) => {
          if (chrome.runtime.lastError || !response) { resolve({ success: false, error: chrome.runtime.lastError?.message || response?.error || "fetch-failed" }); return; }
          if (response.success !== true) { resolve({ success: false, error: response.error || "fetch-failed", status: response.status, url: response.url }); return; }
          resolve({ success: true, text: response.text || "", url: response.url || url, status: response.status });
        });
      } catch (e) { resolve({ success: false, error: e?.message || "sendMessage-failed" }); }
    });
  };

  /** 跟随重定向 + 经 background SW 读 body。永不进入安装包文件。 */
  NS.fetchWithRedirectChain = async function (href, maxHops = 4) {
    const chain = [];
    let currentUrl = "";
    try { currentUrl = new URL(href, location.href).href; } catch { return { chain: [], finalText: "" }; }
    let finalText = "";
    if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(currentUrl)) return { chain: [currentUrl], finalText: "" };
    for (let hop = 0; hop < maxHops; hop++) {
      if (chain.includes(currentUrl)) break;
      chain.push(currentUrl);
      if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(currentUrl)) break;
      try {
        const result = await NS.fetchPageTextFromBackground(currentUrl, { timeoutMs: 5000, redirect: "follow" });
        if (!result.success) break;
        if (result.url && result.url !== currentUrl && !chain.includes(result.url)) {
          if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(result.url)) { chain.push(result.url); break; }
          chain.push(result.url);
          currentUrl = result.url;
        }
        finalText = result.text || "";
        const metaRefresh = finalText.match(/<meta[^>]+http-equiv=["']refresh["'][^>]*content=["']\s*\d+;\s*url=([^"']+)["']/i);
        const jsRedirectMatch = finalText.match(/location\.(?:href|assign)\s*=\s*["']([^"']+)["']/i);
        const jsReplaceMatch = finalText.match(/location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i);
        const nextRedirect = metaRefresh?.[1] || jsRedirectMatch?.[1] || jsReplaceMatch?.[1];
        if (nextRedirect && chain.length < maxHops) {
          try {
            const next = new URL(nextRedirect, currentUrl).href;
            if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(next)) { chain.push(next); break; }
            currentUrl = next; continue;
          } catch { break; }
        }
        break;
      } catch { break; }
    }
    return { chain, finalText };
  };

  NS.probeDownloadBehavior = function (url) {
    const c = NS.caches;
    const abs = (() => { try { return new URL(url, location.href).href; } catch { return url; } })();
    if (c.probeCache.has(abs)) return Promise.resolve(c.probeCache.get(abs));
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type: "probeDownloadBehavior", url: abs }, (response) => {
          if (chrome.runtime.lastError || !response) { const fail = { success: false, isDownload: false, error: chrome.runtime.lastError?.message || "probe-failed" }; c.probeCache.set(abs, fail); resolve(fail); return; }
          c.probeCache.set(abs, response);
          resolve(response);
        });
      } catch (e) { const fail = { success: false, isDownload: false, error: e?.message || "probe-failed" }; c.probeCache.set(abs, fail); resolve(fail); }
    });
  };

  // --- ICP 缓存 ---
  function icpCacheStorageKey(domain, source) { return `${ICP_CACHE_KEY_PREFIX}${String(source || "unknown")}_${NS.normalizeDomain(domain)}`; }
  function icpMissingCacheKey(domain) { return `${ICP_MISS_KEY_PREFIX}${NS.normalizeDomain(domain)}`; }

  function readIcpCache(domain, source) {
    const key = icpCacheStorageKey(domain, source);
    return new Promise((resolve) => {
      try {
        if (!chrome?.storage?.local) { resolve(null); return; }
        chrome.storage.local.get([key], (r) => {
          if (chrome.runtime.lastError) { resolve(null); return; }
          const entry = r && r[key];
          if (!entry || typeof entry !== "object" || !entry.ts || !entry.result) { resolve(null); return; }
          if (Date.now() - entry.ts > ICP_CACHE_TTL_MS) { try { chrome.storage.local.remove([key], () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } resolve(null); return; }
          resolve({ ...entry.result, fromCache: true });
        });
      } catch { resolve(null); }
    });
  }

  function readIcpCacheBatch(hosts) {
    const list = (hosts || []).map((h) => NS.normalizeDomain(h)).filter(Boolean);
    const keys = [];
    for (const h of list) { for (const src of ICP_CACHE_SOURCES) keys.push(icpCacheStorageKey(h, src)); keys.push(icpMissingCacheKey(h)); }
    return new Promise((resolve) => {
      const empty = new Map();
      if (!keys.length || !chrome?.storage?.local) { resolve(empty); return; }
      try {
        chrome.storage.local.get(keys, (r) => {
          if (chrome.runtime.lastError) { resolve(empty); return; }
          const map = new Map();
          const now = Date.now();
          const expired = [];
          for (const key of keys) {
            const entry = r && r[key];
            if (!entry || typeof entry !== "object" || !entry.ts) continue;
            const ttl = entry.missing === true ? ICP_MISS_CACHE_TTL_MS : ICP_CACHE_TTL_MS;
            if (now - entry.ts > ttl) { expired.push(key); continue; }
            if (entry.missing === true) { map.set(key, { success: true, icpRecord: "", icpMissing: true, source: entry.source || "aggregate", fromCache: true, queriedHost: entry.queriedHost || "", hostMiss: true }); continue; }
            if (!entry.result) continue;
            map.set(key, { ...entry.result, fromCache: true });
          }
          if (expired.length) { try { chrome.storage.local.remove(expired, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } }
          resolve(map);
        });
      } catch { resolve(empty); }
    });
  }

  function writeIcpMissingCache(domain, meta) {
    const host = NS.normalizeDomain(domain);
    if (!host) return Promise.resolve();
    const key = icpMissingCacheKey(host);
    const toStore = { ts: Date.now(), missing: true, source: (meta && meta.source) || "aggregate", queriedHost: host, triedHosts: (meta && meta.triedHosts) || [] };
    try { if (!chrome?.storage?.local) return Promise.resolve(); chrome.storage.local.set({ [key]: toStore }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
    return Promise.resolve();
  }

  function clearIcpMissingCache(domain) {
    const host = NS.normalizeDomain(domain);
    if (!host || !chrome?.storage?.local) return;
    try { chrome.storage.local.remove([icpMissingCacheKey(host)], () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
  }

  function statusFromIcpBatchMap(host, batchMap) {
    if (!host || !batchMap) return null;
    for (const src of ICP_CACHE_SOURCES) {
      const cached = batchMap.get(icpCacheStorageKey(host, src));
      if (cached && cached.success && cached.icpRecord && NS.looksLikeIcpLicense(cached.icpRecord)) return { kind: "license", data: { ...cached, matchedHost: host, fromCache: true } };
    }
    const hostMiss = batchMap.get(icpMissingCacheKey(host));
    if (hostMiss && (hostMiss.icpMissing || hostMiss.hostMiss || hostMiss.missing)) return { kind: "missing", data: { success: true, icpRecord: "", icpMissing: true, matchedHost: host, queriedHost: hostMiss.queriedHost || host, source: hostMiss.source || "aggregate", fromCache: true } };
    return null;
  }

  function writeIcpCache(domain, result) {
    if (!domain || !result || result.success !== true) return Promise.resolve();
    const source = result.source || "unknown";
    const host = NS.normalizeDomain(domain);
    const key = icpCacheStorageKey(domain, source);
    const hasLicense = !!(result.icpRecord && NS.looksLikeIcpLicense(result.icpRecord));
    const toStore = { ts: Date.now(), result: { success: true, icpRecord: hasLicense ? result.icpRecord : "", icpMissing: hasLicense ? false : true, source, unitName: result.unitName || "", natureName: result.natureName || "", queriedHost: result.queriedHost || host, domain: result.domain || host } };
    try { if (!chrome?.storage?.local) return Promise.resolve(); chrome.storage.local.set({ [key]: toStore }, () => { void chrome.runtime.lastError; }); if (hasLicense) clearIcpMissingCache(host); } catch { /* ignore */ }
    return Promise.resolve();
  }

  async function withIcpCache(domain, source, fetcher, batchMap) {
    // 与 WHOIS 一致：保留 www 作为查询/缓存键
    const host = intelHost(domain);
    if (!host) return { success: false };
    // 只复用「有备案号」的缓存；missing 缓存不短路，避免爱站误 miss 钉死真备案
    if (batchMap) {
      const hit = batchMap.get(icpCacheStorageKey(host, source));
      if (hit && hit.success && hit.icpRecord && NS.looksLikeIcpLicense(hit.icpRecord)) {
        return { ...hit, queriedHost: hit.queriedHost || host, fromCache: true };
      }
    } else {
      const cached = await readIcpCache(host, source);
      if (cached && cached.success && cached.icpRecord && NS.looksLikeIcpLicense(cached.icpRecord)) {
        return { ...cached, queriedHost: cached.queriedHost || host };
      }
    }
    const result = await fetcher(host);
    if (result && result.success) {
      const hasLicense = !!(result.icpRecord && NS.looksLikeIcpLicense(result.icpRecord));
      const normalized = { ...result, source: result.source || source, icpRecord: hasLicense ? result.icpRecord : "", icpMissing: !hasLicense };
      // 仅缓存命中备案；单源 missing 不写 24h 负缓存（爱站对真备案常假 missing）
      if (hasLicense) writeIcpCache(host, normalized);
      if (batchMap) batchMap.set(icpCacheStorageKey(host, source), { ...normalized, fromCache: false });
      return { ...normalized, queriedHost: result.queriedHost || host };
    }
    return result;
  }

  NS.looksLikeIcpLicense = function (value) {
    if (!value) return false;
    const v = String(value).trim();
    // 接口占位/失败文案绝不当备案号
    if (/查询失败|信息查询失败|未找到|未查询|未备案|没有|无备案|暂无|查无|不存在|失败|错误|null|undefined/i.test(v)) {
      return false;
    }
    if (/(ICP|备案)/i.test(v) && /\d{4,}/.test(v)) return true;
    if (/^[一-鿿]{1,3}[A-Z]?\d{1,4}-\d{5,}(?:-\d+)?$/i.test(v)) return true;
    if (/^[一-鿿].{0,6}\d{5,}/.test(v)) return true;
    return false;
  };

  /** uapis/beiancx 字段占位：查询失败、无法识别 等 */
  function isIcpPlaceholderField(s) {
    const v = String(s || "").trim();
    if (!v) return true;
    return /^(?:查询失败|查询成功|失败|错误|无|暂无|null|undefined|n\/a|无法识别|-|—|－)$/i.test(v);
  }

  function extractIcpFromAizhanResponse(text) {
    if (!text) return { success: false };
    const m = String(text).match(/document\.write\s*\(\s*['"]([^'"]*)['"]\s*\)/i);
    if (!m) return { success: false };
    const value = (m[1] || "").trim();
    // 严格三态：明确“无记录”才写 missing；失败/未知文本不能伪装成无备案。
    if (!value || /未找到(?:备案)?信息|未查询到备案|未备案|没有备案|无备案|暂无备案|查无备案|不存在(?:备案)?|null|undefined/i.test(value)) {
      return { success: true, icpRecord: "", icpMissing: true, source: "aizhan" };
    }
    if (/查询失败|信息查询失败|请求失败|服务异常|错误|error|fail/i.test(value)) {
      return { success: false, source: "aizhan" };
    }
    if (NS.looksLikeIcpLicense(value)) {
      return { success: true, icpRecord: value, icpMissing: false, source: "aizhan" };
    }
    return { success: false, source: "aizhan" };
  }

  // 爱站/uapis 轻量接口；beiancx 整页 HTML 更慢
  const ICP_FAST_TIMEOUT_MS = 2000;
  // beiancx 对不存在的裸域偶尔连响应头都不返回；3.2 秒即结束该源，
  // 其它源仍完整执行，避免一个挂起连接拖慢整轮。
  const ICP_BEIANCX_TIMEOUT_MS = 2200;

  /**
   * 解析 uapis.cn ICP JSON，区分三类结局：
   *  - 命中备案号 → success + icpRecord
   *  - 明确无备案 → success + icpMissing（NOT_FOUND / No ICP record）
   *  - 查询失败   → success:false（假 200+查询失败、INVALID_PARAMETER 等，绝不当 missing）
   *
   * 实测失败样例：
   *  {"code":"200","serviceLicence":"查询失败",...,"msg":"查询成功"}
   *  {"code":"NOT_FOUND","message":"No ICP record found for this domain."}
   *  {"code":"INVALID_PARAMETER","message":"ICP信息查询失败"}
   */
  function parseUapisIcpJson(data, host) {
    if (!data || typeof data !== "object") return { success: false, source: "uapis" };
    const code = String(data.code ?? data.status ?? "").trim().toUpperCase();
    const msg = String(data.msg || data.message || "").trim();
    const licenseRaw = String(
      data.serviceLicence || data.serviceLicense || data.icp || data.license || ""
    ).trim();
    const unitRaw = String(data.unitName || "").trim();
    const natureRaw = String(data.natureName || "").trim();
    const domain = intelHost(data.domain || host);
    const unitName = isIcpPlaceholderField(unitRaw) ? "" : unitRaw;
    const natureName = isIcpPlaceholderField(natureRaw) ? "" : natureRaw;
    const base = { source: "uapis", unitName, natureName, domain };

    // ① 真实命中优先（含 msg=query success / 查询成功；勿被其它分支误伤）
    // 实测 ssusu.com: {"code":"200","serviceLicence":"湘ICP备2024068964号","msg":"query success"}
    if (NS.looksLikeIcpLicense(licenseRaw)
      && (code === "200" || code === "0" || code === "OK" || code === "SUCCESS" || code === ""
        || /query\s*success|查询成功|success/i.test(msg))) {
      return {
        ...base,
        success: true,
        icpRecord: licenseRaw,
        icpMissing: false
      };
    }

    // ② 明确无备案
    if (code === "NOT_FOUND" || code === "404"
      || /no\s*icp\s*record|not\s*found|no\s*record|未备案|无备案|查无|不存在/i.test(msg)) {
      return { ...base, success: true, icpRecord: "", icpMissing: true, unitName: "", natureName: "" };
    }

    // ③ 查询失败 / 参数错误（含 code=200 但字段全是「查询失败」的假成功）
    if (code === "INVALID_PARAMETER" || code === "ERROR" || code === "FAIL"
      || /信息查询失败|invalid\s*parameter|参数错误/i.test(msg)
      || isIcpPlaceholderField(licenseRaw)
      || /查询失败/.test(licenseRaw)) {
      return { ...base, success: false };
    }

    // 其它 code / 空结果 → 失败，不写 missing 缓存
    return { ...base, success: false };
  }

  async function queryIcpAizhan(domain, batchMap) {
    return withIcpCache(domain, "aizhan", async (h) => {
      // API 参数：保留 www 的 h；爱站对 www.x 通常也能解析
      const url = `https://icp.aizhan.com/geticp/?host=${encodeURIComponent(h)}`;
      const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: ICP_FAST_TIMEOUT_MS });
      if (!result.success || !result.text) return { success: false, queriedHost: h };
      const parsed = extractIcpFromAizhanResponse(result.text);
      return { ...parsed, source: "aizhan", queriedHost: h };
    }, batchMap);
  }

  async function queryIcpUapis(domain, batchMap) {
    return withIcpCache(domain, "uapis", async (h) => {
      const url = `https://uapis.cn/api/v1/network/icp?domain=${encodeURIComponent(h)}`;
      const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: ICP_FAST_TIMEOUT_MS });
      if (!result.success || !result.text) return { success: false, queriedHost: h };
      try {
        return { ...parseUapisIcpJson(JSON.parse(result.text), h), queriedHost: h };
      } catch {
        return { success: false, queriedHost: h, source: "uapis" };
      }
    }, batchMap);
  }

  /**
   * beiancx.com/{domain}.html
   * SSR 把备案号写在 JSON-LD：mainEntity.identifier（京ICP备… / 粤B2-… 等）。
   * 404 / 未备案 → missing；有 identifier → hit。不必扫整页 CSS/FAQ。
   */
  function extractIcpFromBeiancxHtml(html, httpStatus) {
    if (Number(httpStatus) === 404) {
      return { success: true, icpRecord: "", icpMissing: true, source: "beiancx" };
    }
    const t = String(html || "");
    if (!t) return { success: false, source: "beiancx" };
    if (t.length < 1200 && /404\s*Not\s*Found|nginx/i.test(t)) {
      return { success: true, icpRecord: "", icpMissing: true, source: "beiancx" };
    }

    // ① JSON-LD mainEntity.identifier（站点稳定字段，含非 ICP 形态如 粤B2-20090059-5）
    let lic = "";
    const idm = t.match(/"mainEntity"\s*:\s*\{[^}]*?"identifier"\s*:\s*"([^"]*)"/i);
    if (idm) lic = String(idm[1] || "").trim();

    // ② 兜底：结果卡片 / 页内标准 ICP 号
    if (!NS.looksLikeIcpLicense(lic)) {
      const m = t.match(/result-label[^>]*>\s*备案号\s*<[\s\S]{0,120}?result-value[^>]*>([^<]{4,48})</i)
        || t.match(/([一-鿿]{1,3}ICP[备证]\d{5,12}号(?:-\d+)?)/i);
      if (m) lic = String(m[1] || "").trim();
    }

    if (NS.looksLikeIcpLicense(lic)) {
      const um = t.match(/result-label[^>]*>\s*主办单位名称\s*<[\s\S]{0,120}?result-value[^>]*>([^<]{2,80})</i);
      return {
        success: true,
        icpRecord: lic,
        icpMissing: false,
        source: "beiancx",
        unitName: um ? String(um[1] || "").trim() : ""
      };
    }

    // identifier 为空 / 明确未备案
    if ((idm && !lic) || (/未备案|未查询到备案|暂无备案|没有备案/i.test(t)
      && !/已查询到备案|已备案|ICP filing record/i.test(t))) {
      return { success: true, icpRecord: "", icpMissing: true, source: "beiancx" };
    }
    return { success: false, source: "beiancx" };
  }

  async function queryIcpBeiancx(domain, batchMap) {
    return withIcpCache(domain, "beiancx", async (h) => {
      const url = `https://beiancx.com/${encodeURIComponent(h)}.html`;
      // beiancx 的 nginx 404 偶尔不结束响应体；状态码已足够判定 missing，
      // 不应继续等 response.text() 直到超时。
      const result = await NS.fetchPageTextFromBackground(url, {
        timeoutMs: ICP_BEIANCX_TIMEOUT_MS,
        statusOnly404: true
      });
      const st = Number(result && result.status) || 0;
      if (!result.success) {
        if (st === 404 || /404|not\s*found/i.test(String(result.error || ""))) {
          return { success: true, icpRecord: "", icpMissing: true, source: "beiancx", queriedHost: h };
        }
        return { success: false, queriedHost: h, source: "beiancx" };
      }
      return { ...extractIcpFromBeiancxHtml(result.text || "", st), source: "beiancx", queriedHost: h, domain: h };
    }, batchMap);
  }

  /**
   * 同一 host 的备案源全部并行、全部完成后再汇总。
   * 不用单源 missing 提前展示；也不再用额外 grace timer 硬等。
   */
  async function raceIcpLicense(promises) {
    const list = promises.filter(Boolean);
    if (!list.length) return null;
    const results = await Promise.all(list.map((p) =>
      Promise.resolve(p).catch(() => null)
    ));
    const licenseHit = results.find((r) =>
      r && r.success && r.icpRecord && NS.looksLikeIcpLicense(r.icpRecord)
    );
    if (licenseHit) return { ...licenseHit, icpMissing: false };
    const missing = results.filter((r) => r && r.success && r.icpMissing);
    if (missing.length) {
      const preferred = missing.find((r) => String(r.source || "").toLowerCase() === "uapis")
        || missing.find((r) => String(r.source || "").toLowerCase() === "beiancx")
        || missing[0];
      return {
        ...preferred,
        success: true,
        icpRecord: "",
        icpMissing: true,
        missingSources: missing.map((r) => String(r.source || "")).filter(Boolean)
      };
    }
    return null; // 全失败，不当 missing
  }

  /**
   * ICP 候选：当前主机 → 去 www → eTLD+1。
   * 不再串行二次 WHOIS 扩父域（lifecycle 已绑定 WHOIS，且重复查会极慢）。
   */
  function buildIcpQueryCandidates(domain) {
    const currentHost = intelHost(domain);
    if (!currentHost || !currentHost.includes(".")) return [];
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(currentHost)) return [];
    if (NS.isPublicSuffixOnlyHost(currentHost)) return [];
    const out = [];
    const seen = new Set();
    const push = (h) => {
      const n = intelHost(h);
      if (!n || seen.has(n) || NS.isPublicSuffixOnlyHost(n)) return;
      seen.add(n);
      out.push(n);
    };
    push(currentHost);
    if (/^www\./i.test(currentHost)) push(currentHost.replace(/^www\./i, ""));
    const bare = currentHost.replace(/^www\./i, "");
    const apex = (typeof NS.getRegistrableDomain === "function" && NS.getRegistrableDomain(bare)) || bare;
    if (apex) push(apex);
    return out.length ? out : [currentHost];
  }

  NS.detectIcpDomain = async function (domain) {
    if (!domain) return { icpMissing: false, success: false };
    const pageHost = intelHost(domain);
    const t0 = Date.now();
    const candidates = buildIcpQueryCandidates(domain);
    if (!candidates.length) {
      return { success: false, icpRecord: "", icpMissing: false, queriedHost: pageHost, triedHosts: [] };
    }
    const batchMap = await readIcpCacheBatch(candidates);
    // 有备案号缓存 → 直接用；聚合 miss 稍后在所有候选备案号缓存复核后短路。
    const pageStatus = statusFromIcpBatchMap(pageHost, batchMap);
    if (pageStatus && pageStatus.kind === "license") {
      NS.silverfoxLog("intel-icp", "cache-license-hit", pageHost, "ms=", Date.now() - t0);
      return { ...pageStatus.data, icpMissing: false, matchedHost: pageHost, queriedHost: pageHost };
    }
    let lastSource = "unknown";
    let sawDefinitiveMissing = false;
    let sawPartialMissing = false;
    const partialMissingSources = new Set();
    const toTry = candidates.slice(0, 2);
    const validHosts = toTry.filter((host) =>
      host === pageHost || NS.intelHostIsValidAttribution(host, pageHost)
    );
    // 先扫所有候选的备案号缓存。
    for (const host of validHosts) {
      for (const src of ICP_CACHE_SOURCES) {
        try {
          const hit = batchMap && batchMap.get(icpCacheStorageKey(host, src));
          if (hit && hit.success && hit.icpRecord && NS.looksLikeIcpLicense(hit.icpRecord)) {
            clearIcpMissingCache(pageHost); clearIcpMissingCache(host);
            NS.silverfoxLog("intel-icp", "host-cache-license", host, src, "ms=", Date.now() - t0);
            return { ...hit, icpMissing: false, matchedHost: host, queriedHost: host, source: src };
          }
        } catch { /* ignore */ }
      }
    }
    // 聚合负缓存是在上一轮所有 host/来源完成且没有备案号后写入；只短期复用。
    // 必须放在候选备案号正缓存之后，避免 pageHost miss 掩盖 apex 的备案命中。
    if (pageStatus && pageStatus.kind === "missing") {
      NS.silverfoxLog("intel-icp", "cache-missing-hit", pageHost, "ms=", Date.now() - t0);
      return {
        ...pageStatus.data,
        success: true,
        icpRecord: "",
        icpMissing: true,
        matchedHost: pageHost,
        queriedHost: pageHost,
        triedHosts: toTry,
        fromCache: true
      };
    }
    // www 与裸域并行；每个 host 内的三个来源也并行。总耗时由最慢单源决定，
    // 不再是 host1 完整等待后才开始 host2。
    const hostResults = await Promise.all(validHosts.map(async (host) => {
      NS.silverfoxLog("intel-icp", "all-sources-start", host);
      const winner = await raceIcpLicense([
        queryIcpUapis(host, batchMap),
        queryIcpBeiancx(host, batchMap),
        queryIcpAizhan(host, batchMap)
      ]);
      return { host, winner };
    }));
    // 所有查询完成后，备案号优先于任何 missing。
    for (const { host, winner } of hostResults) {
      if (!(winner && winner.icpRecord && NS.looksLikeIcpLicense(winner.icpRecord))) continue;
      const claimed = NS.normalizeDomain(winner.domain || "");
      if (claimed && claimed !== host && !NS.intelHostIsValidAttribution(claimed, pageHost)) continue;
      clearIcpMissingCache(pageHost); clearIcpMissingCache(host);
      NS.silverfoxLog("intel-icp", "license", host, winner.source, "ms=", Date.now() - t0);
      return { ...winner, icpMissing: false, matchedHost: host, queriedHost: winner.queriedHost || host };
    }
    for (const { winner } of hostResults) {
      if (!(winner && winner.success && winner.icpMissing)) continue;
      const sources = Array.isArray(winner.missingSources) ? winner.missingSources : [winner.source];
      sawPartialMissing = true;
      sources.forEach((s) => { if (s) partialMissingSources.add(String(s)); });
      // 三个解析器都已严格区分“明确无记录”和“查询失败”。
      if (sources.some((s) => /^(?:uapis|beiancx|aizhan)$/i.test(String(s || "")))) {
        sawDefinitiveMissing = true;
      }
      lastSource = winner.source || lastSource;
    }
    if (sawDefinitiveMissing) {
      // 仅严格解析出的明确 missing 才写负缓存；源失败不会进入这里。
      writeIcpMissingCache(pageHost, { source: lastSource, triedHosts: toTry });
      NS.silverfoxLog("intel-icp", "missing", pageHost, "ms=", Date.now() - t0);
      return { success: true, icpRecord: "", icpMissing: true, queriedHost: pageHost, triedHosts: toTry, source: lastSource, fromCache: false };
    }
    if (sawPartialMissing) {
      NS.silverfoxLog("intel-icp", "partial-missing", pageHost,
        Array.from(partialMissingSources).join(",") || "unknown", "ms=", Date.now() - t0);
      return {
        success: false,
        icpRecord: "",
        icpMissing: false,
        partialMissing: true,
        missingSources: Array.from(partialMissingSources),
        queriedHost: pageHost,
        triedHosts: toTry,
        source: lastSource
      };
    }
    NS.silverfoxLog("intel-icp", "fail", pageHost, "ms=", Date.now() - t0);
    return { success: false, icpRecord: "", icpMissing: false, queriedHost: pageHost, triedHosts: toTry, source: lastSource };
  };

  // --- WHOIS 缓存 ---
  function whoisCacheStorageKey(domain) { return WHOIS_CACHE_KEY_PREFIX + NS.normalizeDomain(domain); }

  function readWhoisCache(domain) {
    const key = whoisCacheStorageKey(domain);
    return new Promise((resolve) => {
      try {
        if (!chrome?.storage?.local) { resolve(null); return; }
        chrome.storage.local.get([key], (r) => {
          if (chrome.runtime.lastError) { resolve(null); return; }
          const entry = r && r[key];
          if (!entry || typeof entry !== "object" || !entry.ts || !entry.result) { resolve(null); return; }
          if (Date.now() - entry.ts > WHOIS_CACHE_TTL_MS) { try { chrome.storage.local.remove([key], () => { void chrome.runtime.lastError; }); } catch { /* ignore */ } resolve(null); return; }
          resolve({ ...entry.result, fromCache: true });
        });
      } catch { resolve(null); }
    });
  }

  function writeWhoisCache(domain, result) {
    if (!domain || !result || result.success !== true) return Promise.resolve();
    const reg = parseWhoisDateToIso(result.registeredAt);
    if (!reg) return Promise.resolve(); // 无真实日期不写缓存
    if (NS.isPublicSuffixOnlyHost(result.queriedHost || domain)) return Promise.resolve();
    const key = whoisCacheStorageKey(domain);
    const toStore = {
      ts: Date.now(),
      result: {
        success: true,
        registeredAt: reg,
        ageDays: typeof result.ageDays === "number" ? result.ageDays : null,
        queriedHost: result.queriedHost || NS.normalizeDomain(domain),
        source: result.source || "rdap.ss"
      }
    };
    try { if (!chrome?.storage?.local) return Promise.resolve(); chrome.storage.local.set({ [key]: toStore }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
    return Promise.resolve();
  }

  /**
   * 从 RDAP / rdap.ss 响应抽注册日。
   * 标准 RDAP 用 events；CNNIC/.cn（含 www.gov.cn）常落在 whoisData["Created Date"]。
   */
  NS.extractRegistrationDateFromRdap = function (data) {
    if (!data || typeof data !== "object") return "";

    const toIso = (raw) => {
      if (typeof parseWhoisDateToIso === "function") return parseWhoisDateToIso(raw) || "";
      try {
        const t = Date.parse(String(raw || "").trim().replace(" ", "T"));
        if (!Number.isNaN(t)) return new Date(t).toISOString();
      } catch { /* ignore */ }
      return "";
    };

    // ① 扁平 WHOIS 字段（rdap.ss → CNNIC whoisData / rawData；who-dat → dates.created）
    const pullFlatDate = (obj) => {
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) return "";
      const prefer = [
        "Created Date", "Creation Date", "createdDate", "creationDate",
        "created", "creation_date", "Creation_Date", "Registration Date",
        "Registration Time", "registrationDate", "Registered On"
      ];
      for (const k of prefer) {
        if (obj[k] != null && obj[k] !== "") {
          const iso = toIso(obj[k]);
          if (iso) return iso;
        }
      }
      // who-dat.as93.net：{ dates: { created, updated, expires } }
      try {
        if (obj.dates && typeof obj.dates === "object") {
          for (const k of ["created", "creation", "registered"]) {
            if (obj.dates[k] != null && obj.dates[k] !== "") {
              const iso = toIso(obj.dates[k]);
              if (iso) return iso;
            }
          }
        }
      } catch { /* ignore */ }
      try {
        for (const [k, v] of Object.entries(obj)) {
          if (typeof v !== "string" && typeof v !== "number") continue;
          if (!/creat|registr|注册/i.test(k)) continue;
          if (/expir|更新|modified|updated|last/i.test(k)) continue;
          const iso = toIso(v);
          if (iso) return iso;
        }
      } catch { /* ignore */ }
      return "";
    };

    const flatRoots = [];
    try {
      if (data.data) {
        flatRoots.push(data.data.whoisData, data.data.rawData, data.data);
        if (data.data.levels) {
          flatRoots.push(data.data.levels.registry, data.data.levels.registrar);
        }
      }
      flatRoots.push(data.whoisData, data.rawData, data);
    } catch { /* ignore */ }
    for (const root of flatRoots) {
      const iso = pullFlatDate(root);
      if (iso) return iso;
    }

    // ② 标准 RDAP events
    const collectEvents = (obj, out) => {
      if (!obj || typeof obj !== "object") return;
      if (Array.isArray(obj.events)) {
        for (const ev of obj.events) { if (ev && typeof ev === "object") out.push(ev); }
      }
    };
    const events = [];
    collectEvents(data, events);
    if (data.data && typeof data.data === "object") {
      collectEvents(data.data, events);
      const levels = data.data.levels || {};
      collectEvents(levels.registry, events);
      collectEvents(levels.registrar, events);
      collectEvents(data.data.rawData, events);
    }
    const isReg = (a) => /^(registration|registered|domain registration|created?)$/i.test(String(a || "").trim());
    for (const ev of events) {
      if (isReg(ev.eventAction) && ev.eventDate) {
        const iso = toIso(ev.eventDate);
        if (iso) return iso;
      }
    }

    // ③ JSON 全文兜底
    try {
      const blob = JSON.stringify(data);
      const mEvent = blob.match(/"eventAction"\s*:\s*"registration"\s*,\s*"eventDate"\s*:\s*"([^"]+)"/i)
        || blob.match(/"eventDate"\s*:\s*"([^"]+)"\s*,\s*"eventAction"\s*:\s*"registration"/i);
      if (mEvent && mEvent[1]) {
        const iso = toIso(mEvent[1]);
        if (iso) return iso;
      }
      // CNNIC："Created Date":"1998-12-04 00:00:00"
      const mCn = blob.match(/"Created\s*Date"\s*:\s*"([^"]+)"/i)
        || blob.match(/"Creation\s*Date"\s*:\s*"([^"]+)"/i)
        || blob.match(/"Registration\s*Time"\s*:\s*"([^"]+)"/i);
      if (mCn && mCn[1]) {
        const iso = toIso(mCn[1]);
        if (iso) return iso;
      }
    } catch { /* ignore */ }
    return "";
  };

  /**
   * 是否「恰好」公共后缀主机（仅 gov.cn / com.cn 本身）。
   * 注意：不得对入参做去 www——否则 www.gov.cn → gov.cn 会被误杀。
   * www.gov.cn、court.gov.cn、miit.gov.cn 均为 ≥3 段，一律可查。
   */
  NS.isPublicSuffixOnlyHost = function (domain) {
    try {
      const h = typeof NS.normalizeHostForIntel === "function"
        ? NS.normalizeHostForIntel(domain)
        : String(domain || "").trim().toLowerCase().replace(/\.+$/g, "");
      if (!h || !h.includes(".")) return true;
      const parts = h.split(".").filter(Boolean);
      // ≥3 段：court.gov.cn / www.gov.cn / a.b.com —— 都不是「仅公共后缀」
      if (parts.length >= 3) return false;
      if (parts.length < 2) return true;
      const [a, b] = parts;
      // 恰好 gov.cn / com.cn / org.cn / net.cn / edu.cn / ac.cn
      if (/^(cn)$/i.test(b) && /^(com|net|org|gov|edu|ac|mil)$/i.test(a)) return true;
      // 恰好 co.uk / com.au 等
      if (/^(uk|jp|kr|au|nz|za|br|in|hk|tw|sg)$/i.test(b) && /^(com|co|org|net|ac|gov|edu|ne|or)$/i.test(a)) return true;
      return false;
    } catch { return false; }
  };

  /** 情报查询主机键：保留 www（与 normalizeDomain 区分） */
  function intelHost(domain) {
    return typeof NS.normalizeHostForIntel === "function"
      ? NS.normalizeHostForIntel(domain)
      : String(domain || "").trim().toLowerCase().replace(/\.+$/g, "");
  }

  /** 解析真实注册日；失败返回 ""。绝不接受「今天往前推 N 天」的假日期。 */
  function parseWhoisDateToIso(raw) {
    if (raw == null || raw === "") return "";
    const s = String(raw).trim();
    if (!s || /^(null|undefined|none|n\/a|unknown|-|—)$/i.test(s)) return "";
    // 拒绝明显占位
    if (/^0{4}/.test(s) || s === "1970-01-01" || s.startsWith("1970-01-01")) return "";
    // CNNIC 常见：1998-12-04 00:00:00（空格分隔，Date.parse 在部分环境不稳）
    let t = Date.parse(s);
    if (Number.isNaN(t)) t = Date.parse(s.replace(" ", "T"));
    if (Number.isNaN(t)) {
      const m = s.match(/(\d{4})[-\/.](\d{1,2})[-\/.](\d{1,2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/);
      if (m) {
        const hh = m[4] || "00"; const mm = m[5] || "00"; const ss = m[6] || "00";
        t = Date.parse(`${m[1]}-${m[2].padStart(2, "0")}-${m[3].padStart(2, "0")}T${hh}:${mm}:${ss}Z`);
      }
    }
    if (Number.isNaN(t)) {
      const m2 = s.match(/(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
      if (m2) t = Date.parse(`${m2[1]}T${m2[2]}Z`);
    }
    if (Number.isNaN(t)) return "";
    // 未来超过 1 天或早于 1985 视为脏数据
    const now = Date.now();
    if (t > now + 86400000) return "";
    if (t < Date.parse("1985-01-01T00:00:00Z")) return "";
    return new Date(t).toISOString();
  }

  /**
   * 必须有真实 registeredAt；禁止用 ageDays 反推注册日（否则会出现「今天 / 0 天」）。
   * ageDays 仅作交叉校验或由日期推算。
   */
  function finalizeWhoisResult(host, registeredAt, ageDaysOpt, source) {
    if (NS.isPublicSuffixOnlyHost(host)) return null;
    const regIso = parseWhoisDateToIso(registeredAt);
    if (!regIso) return null;
    let ageDays = null;
    const ageMs = Date.now() - Date.parse(regIso);
    if (!Number.isNaN(ageMs)) ageDays = Math.max(0, Math.floor(ageMs / (24 * 60 * 60 * 1000)));
    // 若 API 给了 creation_days，仅在与真实日期相差 ≤2 天时采用（避免脏 age=0 污染）
    if (typeof ageDaysOpt === "number" && ageDaysOpt >= 0 && Number.isFinite(ageDaysOpt)) {
      const apiDays = Math.floor(ageDaysOpt);
      if (ageDays == null) ageDays = apiDays;
      else if (Math.abs(apiDays - ageDays) <= 2) ageDays = apiDays;
    }
    return {
      success: true,
      registeredAt: regIso,
      ageDays: ageDays != null ? ageDays : null,
      // 保留 www（www.gov.cn 不得写成 gov.cn）
      queriedHost: intelHost(host),
      source: source || "whois"
    };
  }

  async function queryWhoisRdapSs(host) {
    if (NS.isPublicSuffixOnlyHost(host)) return null;
    const url = `https://rdap.ss/api/query?q=${encodeURIComponent(host)}`;
    const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 3000 });
    if (!result.success || !result.text) {
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "rdap-fetch-fail", host, result && result.error);
      return null;
    }
    try {
      const data = JSON.parse(result.text);
      if (data && data.success === false) {
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "rdap-success-false", host);
        return null;
      }
      const registeredAt = NS.extractRegistrationDateFromRdap(data);
      if (!registeredAt) {
        // www.gov.cn 等：有 whoisData 但旧解析只认 events，会丢日
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "rdap-no-date", host);
        return null;
      }
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "rdap-hit", host, registeredAt.slice(0, 10));
      return finalizeWhoisResult(host, registeredAt, null, "rdap.ss");
    } catch (e) {
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "rdap-parse-err", host);
      return null;
    }
  }

  /** 从原始 WHOIS 文本抽注册日（CNNIC / ICANN 通用行） */
  function extractDateFromWhoisText(rawWhois) {
    if (!rawWhois) return "";
    const s = String(rawWhois);
    const lineRe = /(?:Registration\s*Time|Registration\s*Date|Created\s*Date|Creation\s*Date|Created\s*On|Domain\s*Name\s*Commencement\s*Date|注册时间|创建日期)\s*[：:]\s*([0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}(?:\s+[0-9:]{5,8}|T[0-9:]{5,8}Z?)?)/i;
    const lm = s.match(lineRe);
    if (lm) {
      const iso = parseWhoisDateToIso(lm[1]);
      if (iso) return iso;
    }
    return "";
  }

  /** 从候选字段列表取首个可解析日期 */
  function firstParseableDate(candidates) {
    for (const c of candidates) {
      if (c == null || c === "") continue;
      const iso = parseWhoisDateToIso(c);
      if (iso) return iso;
    }
    return "";
  }

  async function queryWhoisWhoiscx(host) {
    if (NS.isPublicSuffixOnlyHost(host)) return null;
    const url = "https://whoiscx.com/api/whois/info/";
    const result = await NS.fetchPageTextFromBackground(url, { method: "POST", body: `domain=${encodeURIComponent(host)}`, contentType: "application/x-www-form-urlencoded;charset=UTF-8", timeoutMs: 3000 });
    if (!result.success || !result.text) return null;
    try {
      const data = JSON.parse(result.text);
      const st = data.status;
      if (st !== 1 && st !== "1" && st !== true && st !== "ok" && st !== 200 && st !== "200") { if (!data.data) return null; }
      const info = (data.data && data.data.info) || {};
      const fields = (data.data && data.data.fields) || {};
      const rawWhois = String(
        (data.data && (data.data.raw || data.data.whois || data.data.raw_whois || data.data.rawWhois))
        || info.raw || info.whois || fields.raw || ""
      );
      let registeredAt = firstParseableDate([
        fields.creation_date, fields.Creation_Date, fields.created, fields.Created,
        info.creation_time, info.creation_date, info.created, info.Created,
        fields["Creation Date"], fields["Created Date"], info["Creation Date"], info["Created Date"]
      ]);
      if (!registeredAt && rawWhois) registeredAt = extractDateFromWhoisText(rawWhois);
      // 仅有 creation_days 而无真实日期 → 丢弃（禁止反推「今天/0天」）
      if (!registeredAt) return null;
      let ageDaysOpt = null;
      if (typeof info.creation_days === "number" && info.creation_days >= 0) ageDaysOpt = Math.floor(info.creation_days);
      else if (info.creation_days != null && /^\d+$/.test(String(info.creation_days))) ageDaysOpt = parseInt(String(info.creation_days), 10);
      return finalizeWhoisResult(host, registeredAt, ageDaysOpt, "whoiscx.com");
    } catch { return null; }
  }

  /**
   * who-dat（as93）：https://who-dat.as93.net/{domain}
   * 免 Key；RDAP 封装，JSON 含 dates.created（ISO）。
   * 例：qq.com → {"isRegistered":true,"dates":{"created":"1995-05-04T04:00:00Z",...}}
   */
  async function queryWhoisWhoDat(host) {
    if (NS.isPublicSuffixOnlyHost(host)) return null;
    const h = intelHost(host);
    if (!h) return null;
    // 路径段：去首尾斜杠；保留点号主机（www.xinhuanet.com / qq.com）
    const url = `https://who-dat.as93.net/${encodeURIComponent(h)}`;
    const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 4000 });
    if (!result.success || !result.text) {
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "whodat-fetch-fail", host, result && result.error);
      return null;
    }
    try {
      const text = String(result.text).trim();
      if (!text.startsWith("{")) return null;
      const data = JSON.parse(text);
      if (!data || typeof data !== "object") return null;
      // 明确未注册
      if (data.isRegistered === false || data.isRegistered === "false") return null;
      // 错误页 / 空结果
      if (data.error || data.message === "not found" || data.status === 404) return null;
      const dates = data.dates && typeof data.dates === "object" ? data.dates : {};
      let registeredAt = firstParseableDate([
        dates.created, dates.creation, dates.registered,
        data.created, data.creationDate, data.registeredAt
      ]);
      // 若嵌套 contacts 无日期，再试标准 RDAP 字段（部分 TLD 可能原样透传）
      if (!registeredAt) registeredAt = NS.extractRegistrationDateFromRdap(data);
      if (!registeredAt) {
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "whodat-no-date", host);
        return null;
      }
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "whodat-hit", host, registeredAt.slice(0, 10));
      return finalizeWhoisResult(host, registeredAt, null, "who-dat.as93.net");
    } catch (e) {
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "whodat-parse-err", host);
      return null;
    }
  }

  /**
   * 天天 hu WHOIS：https://api.tian.hu/whois/{domain}
   * 免 Key；限流约 25/min、300/日。对 .cn / gov.cn 解析质量好（含 Registration Time）。
   */
  async function queryWhoisTianHu(host) {
    if (NS.isPublicSuffixOnlyHost(host)) return null;
    const url = `https://api.tian.hu/whois/${encodeURIComponent(host)}`;
    const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 4500 });
    if (!result.success || !result.text) {
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "tianhu-fetch-fail", host, result && result.error);
      return null;
    }
    try {
      const data = JSON.parse(result.text);
      const code = data && data.code;
      if (code !== 200 && code !== "200") {
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "tianhu-code", host, code);
        return null;
      }
      const payload = data.data || {};
      // status: 1 已注册；0 未注册等
      if (payload.status === 0 || payload.status === "0") return null;
      const fmtDomain = (payload.formatted && payload.formatted.domain) || {};
      let registeredAt = firstParseableDate([
        fmtDomain.created_date_utc, fmtDomain.created_date,
        fmtDomain.creation_date, fmtDomain.creation_date_utc,
        fmtDomain.created, fmtDomain.Created
      ]);
      if (!registeredAt && payload.result) registeredAt = extractDateFromWhoisText(payload.result);
      if (!registeredAt) {
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "tianhu-no-date", host);
        return null;
      }
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "tianhu-hit", host, registeredAt.slice(0, 10));
      return finalizeWhoisResult(host, registeredAt, null, "api.tian.hu");
    } catch (e) {
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "tianhu-parse-err", host);
      return null;
    }
  }

  /**
   * 官方 RDAP（免 Key）：按 TLD 直连注册局，或经 rdap.org 引导跳转。
   * com/net → Verisign；org → PIR；info → Identity Digital；其余 → rdap.org。
   * 已弃用：rdap.afilias.net（DNS 失效，.info 已迁至 identitydigital）。
   */
  function buildOfficialRdapUrls(host) {
    const h = String(host || "").toLowerCase().replace(/\.+$/g, "");
    const urls = [];
    try {
      if (/\.com$/i.test(h)) urls.push(`https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(h)}`);
      else if (/\.net$/i.test(h)) urls.push(`https://rdap.verisign.com/net/v1/domain/${encodeURIComponent(h)}`);
      else if (/\.org$/i.test(h)) urls.push(`https://rdap.publicinterestregistry.org/rdap/domain/${encodeURIComponent(h)}`);
      else if (/\.info$/i.test(h)) urls.push(`https://rdap.identitydigital.services/rdap/domain/${encodeURIComponent(h)}`);
      // 通用引导：跟随 302 到对应注册局 RDAP
      urls.push(`https://rdap.org/domain/${encodeURIComponent(h)}`);
    } catch { /* ignore */ }
    return urls;
  }

  async function queryWhoisOfficialRdap(host) {
    if (NS.isPublicSuffixOnlyHost(host)) return null;
    const urls = buildOfficialRdapUrls(host);
    for (const url of urls) {
      try {
        const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 3500 });
        if (!result.success || !result.text) continue;
        // 非 JSON（HTML 错误页）跳过
        const text = result.text.trim();
        if (!text.startsWith("{") && !text.startsWith("[")) continue;
        const data = JSON.parse(text);
        if (data && (data.errorCode || data.error || data.title === "Error")) continue;
        const registeredAt = NS.extractRegistrationDateFromRdap(data);
        if (!registeredAt) continue;
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "rdap-official-hit", host, registeredAt.slice(0, 10), url.slice(0, 48));
        return finalizeWhoisResult(host, registeredAt, null, "rdap.org");
      } catch { /* try next */ }
    }
    return null;
  }

  function raceWhoisSources(host) {
    return new Promise((resolve) => {
      if (NS.isPublicSuffixOnlyHost(host)) { resolve(null); return; }
      // 多源并行竞速：任一拿到真实 registeredAt 即返回
      // 需 Key 的商业源（WhoisXML / WhoisJSON / IP2WHOIS / WhoisFreaks 等）未接入
      const tasks = [
        queryWhoisWhoDat(host),        // who-dat.as93.net（RDAP 封装，dates.created）
        queryWhoisRdapSs(host),        // rdap.ss
        queryWhoisWhoiscx(host),       // whoiscx.com
        queryWhoisTianHu(host),        // api.tian.hu（对 .cn 很强）
        queryWhoisOfficialRdap(host)   // Verisign / PIR / Identity Digital / rdap.org
      ];
      let pending = tasks.length; let settled = false;
      for (const p of tasks) {
        Promise.resolve(p).then((r) => {
          if (settled) return;
          // 必须有真实 registeredAt
          if (r && r.success && r.registeredAt && parseWhoisDateToIso(r.registeredAt)) { settled = true; resolve(r); return; }
          pending -= 1; if (pending <= 0) resolve(null);
        }).catch(() => { if (settled) return; pending -= 1; if (pending <= 0) resolve(null); });
      }
    });
  }

  /**
   * WHOIS 候选：【当前主机必须第一，保留 www】→ 去 www → 父域 … 直到 eTLD+1。
   * 绝不回落到恰好公共后缀 gov.cn / com.cn 本身。
   */
  NS.buildWhoisQueryCandidates = function (domain) {
    const host = intelHost(domain);
    if (!host || !host.includes(".")) return [];
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return [];
    // 恰好公共后缀才拒；www.gov.cn / court.gov.cn 放行
    if (NS.isPublicSuffixOnlyHost(host)) return [];
    // apex 计算用去 www 的品牌域，但候选列表用 intel 主机
    const bareForApex = host.replace(/^www\./i, "");
    const apex = (typeof NS.getRegistrableDomain === "function" && NS.getRegistrableDomain(bareForApex)) || bareForApex;
    const out = [];
    const seen = new Set();
    const push = (c) => {
      const n = intelHost(c);
      if (!n || !n.includes(".") || seen.has(n)) return;
      if (NS.isPublicSuffixOnlyHost(n)) return; // 拦截恰好 gov.cn
      seen.add(n);
      out.push(n);
    };
    // 1) 当前主机（必须最先，含 www.gov.cn 原样）
    push(host);
    // 2) 去 www（www.gov.cn → gov.cn 会被 isPublicSuffixOnlyHost 拒绝，正确）
    if (/^www\./i.test(host)) {
      const bare = host.replace(/^www\./i, "");
      if (!NS.isPublicSuffixOnlyHost(bare)) push(bare);
    }
    // 3) 逐级父域直到 apex（含）；apex 为 court.gov.cn 时不会推到 gov.cn
    if (apex && !NS.isPublicSuffixOnlyHost(apex)) {
      const bare = host.replace(/^www\./i, "");
      const parts = bare.split(".").filter(Boolean);
      for (let i = 1; i < parts.length - 1; i++) {
        const cand = parts.slice(i).join(".");
        if (NS.isPublicSuffixOnlyHost(cand)) continue;
        // 不得短于 apex（apex 为 eTLD+1）
        if (apex && cand !== apex && !cand.endsWith(`.${apex}`) && !apex.endsWith(`.${cand}`) && cand.length < apex.length) continue;
        push(cand);
        if (cand === apex) break;
      }
      push(apex);
    }
    if (!out.length) push(host);
    return out;
  };

  NS.queryWhoisRegistrationExact = async function (domain) {
    const host = intelHost(domain);
    if (!host || !host.includes(".")) return { success: false, queriedHost: host || "" };
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return { success: false, queriedHost: host };
    if (NS.isPublicSuffixOnlyHost(host)) return { success: false, queriedHost: host };
    const cached = await readWhoisCache(host);
    // 缓存也必须带真实日期；拒绝仅 ageDays / 空日期的旧脏数据
    if (cached && cached.success && cached.registeredAt && parseWhoisDateToIso(cached.registeredAt)
      && !NS.isPublicSuffixOnlyHost(cached.queriedHost || host)) {
      return {
        ...cached,
        registeredAt: parseWhoisDateToIso(cached.registeredAt),
        queriedHost: host
      };
    }
    const out = await raceWhoisSources(host);
    if (out && NS.whoisHasResult(out)) {
      const fixed = { ...out, queriedHost: host };
      writeWhoisCache(host, fixed);
      return fixed;
    }
    return { success: false, queriedHost: host };
  };

  NS.queryWhoisRegistration = async function (domain) {
    // 始终以调用方传入的「当前页域名」为第一查询目标（保留 www）
    const pageHost = intelHost(domain);
    if (!pageHost) return { success: false, queriedHost: "" };
    // 恰好 gov.cn 才拒；www.gov.cn / court.gov.cn 继续
    if (NS.isPublicSuffixOnlyHost(pageHost)) return { success: false, queriedHost: pageHost };

    // ① 强制先查当前域名（www.gov.cn 整主机）
    NS.silverfoxLog && NS.silverfoxLog("intel-whois", "query-current", pageHost);
    const current = await NS.queryWhoisRegistrationExact(pageHost);
    if (NS.whoisHasResult(current)) {
      return { ...current, queriedHost: pageHost, matchedStrategy: "current" };
    }

    // ② 去 www 再查（仅当去 www 后仍不是公共后缀，如 www.example.com → example.com）
    if (/^www\./i.test(pageHost)) {
      const bare = pageHost.replace(/^www\./i, "");
      if (!NS.isPublicSuffixOnlyHost(bare)) {
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "query-bare", bare);
        const bareOut = await NS.queryWhoisRegistrationExact(bare);
        if (NS.whoisHasResult(bareOut)) {
          return { ...bareOut, queriedHost: bare, matchedStrategy: "bare" };
        }
      }
    }

    // ③ 再试 apex / 父域（仍排除恰好公共后缀）
    const candidates = NS.buildWhoisQueryCandidates(pageHost);
    const tried = [pageHost];
    for (const host of candidates) {
      if (!host || host === pageHost) continue;
      if (/^www\./i.test(pageHost) && host === pageHost.replace(/^www\./i, "")) continue;
      if (NS.isPublicSuffixOnlyHost(host)) continue;
      tried.push(host);
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "query-parent", host);
      const out = await NS.queryWhoisRegistrationExact(host);
      if (NS.whoisHasResult(out) && !NS.isPublicSuffixOnlyHost(out.queriedHost || host)) {
        return { ...out, queriedHost: host, matchedStrategy: "parent", pageHost, triedHosts: tried };
      }
    }
    return { success: false, queriedHost: pageHost, triedHosts: tried };
  };

  NS.whoisHasResult = function (whois) {
    if (!whois || !whois.success) return false;
    // 必须有可解析的真实注册日；仅 ageDays / 伪造日不算
    if (!whois.registeredAt) return false;
    if (!parseWhoisDateToIso(whois.registeredAt)) return false;
    if (whois.queriedHost && NS.isPublicSuffixOnlyHost(whois.queriedHost)) return false;
    return true;
  };

  NS.whoisRecordsMatch = function (a, b) {
    if (!NS.whoisHasResult(a) || !NS.whoisHasResult(b)) return false;
    const da = (a.registeredAt || "").slice(0, 10);
    const db = (b.registeredAt || "").slice(0, 10);
    if (da && db && da === db) return true;
    // 仅在两边都有真实日期推出的 age 时才比天数
    if (da && db && typeof a.ageDays === "number" && typeof b.ageDays === "number"
      && Number.isFinite(a.ageDays) && Number.isFinite(b.ageDays) && Math.abs(a.ageDays - b.ageDays) <= 1) return true;
    return false;
  };

  NS.applyWhoisRegistrationRisk = function (whois) {
    if (!NS.whoisHasResult(whois) || typeof whois.ageDays !== "number") return false;
    const days = whois.ageDays;
    const host = whois.queriedHost || location.hostname;
    if (NS.isPublicSuffixOnlyHost(host)) return false;
    const dateStr = (whois.registeredAt || "").slice(0, 10);
    if (NS.isBenignContentPage()) return false;
    if (days < 7) { NS.addSignal("域名注册时间极短", 12, `${host} 注册约 ${days} 天（${dateStr || "未知日期"}），仿冒下载站常见于新注册域名`); return true; }
    if (days < 30) { NS.addSignal("域名注册不足30天", 9, `${host} 注册约 ${days} 天（${dateStr || "未知日期"}），短期域名风险升高`); return true; }
    if (days < 90) { NS.addSignal("域名注册不足90天", 6, `${host} 注册约 ${days} 天（${dateStr || "未知日期"}）`); return true; }
    if (days < 180) { NS.addSignal("域名注册不足半年", 3, `${host} 注册约 ${days} 天（${dateStr || "未知日期"}）`); return true; }
    if (days < 365) { NS.addSignal("域名注册不足1年", 2, `${host} 注册约 ${days} 天（${dateStr || "未知日期"}）`); return true; }
    return false;
  };

  NS.formatWhoisInfoForReport = function (whois) {
    if (!NS.whoisHasResult(whois)) return "";
    const host = whois.queriedHost || NS.getRegistrableDomain(location.hostname) || location.hostname;
    if (NS.isPublicSuffixOnlyHost(host)) return "";
    const dateStr = (parseWhoisDateToIso(whois.registeredAt) || "").slice(0, 10);
    if (!dateStr) return "";
    let days = typeof whois.ageDays === "number" ? whois.ageDays : null;
    if (days == null) {
      const ageMs = Date.now() - Date.parse(dateStr);
      if (!Number.isNaN(ageMs)) days = Math.max(0, Math.floor(ageMs / (24 * 60 * 60 * 1000)));
    }
    const parts = [];
    if (host) parts.push(host);
    parts.push(`注册于 ${dateStr}`);
    if (days != null) parts.push(`已注册 ${days} 天`);
    return parts.join(" · ");
  };

  NS.detectWhoisRegistrationAge = async function (domain) {
    try {
      // 必须查当前页 hostname（保留 www）；禁止 normalizeDomain 把 www.gov.cn 变成 gov.cn
      const host = intelHost(domain || (typeof location !== "undefined" ? location.hostname : "") || "");
      if (!host) {
        NS.state.whoisInfo = "";
        return { success: false, queriedHost: "" };
      }
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "detect-start", host);
      const whois = await NS.queryWhoisRegistration(host);
      if (!NS.whoisHasResult(whois)) {
        NS.state.whoisInfo = "";
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "detect-miss", host, whois && whois.triedHosts);
        return { success: false, queriedHost: (whois && whois.queriedHost) || host, triedHosts: whois && whois.triedHosts };
      }
      NS.state.whoisInfo = NS.formatWhoisInfoForReport(whois);
      if (!NS.state.whoisInfo) {
        NS.silverfoxLog && NS.silverfoxLog("intel-whois", "detect-empty-format", host);
        return { success: false, queriedHost: whois.queriedHost || host };
      }
      NS.silverfoxLog && NS.silverfoxLog("intel-whois", "detect-hit", NS.state.whoisInfo);
      NS.applyWhoisRegistrationRisk(whois);
      return whois;
    } catch { return { success: false }; }
  };
})(window.SilverfoxContent ??= {});
