/**
 * ICP/WHOIS 网络查询 + 24h 缓存 + 下载行为探测。
 * 所有外部 HTTP(S) 必须经 background SW（content-script fetch 受 CORS 限制）。
 */
;(function (NS) {
  "use strict";

  const ICP_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  const ICP_CACHE_KEY_PREFIX = "icp_cache_v4_";
  const ICP_MISS_KEY_PREFIX = "icp_miss_v1_";
  // 顺序：爱站 → beiancx → uapis（race 并行，任一命中备案号即返回）
  const ICP_CACHE_SOURCES = ["aizhan", "beiancx", "uapis"];
  const WHOIS_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  // v6：禁止用 ageDays 伪造 registeredAt；拒绝 gov.cn/com.cn 公共后缀结果；缓存失效旧脏数据
  const WHOIS_CACHE_KEY_PREFIX = "whois_cache_v6_";

  /**
   * 所有外部 HTTP(S) 经 background SW。content-script fetch 受 CORS 限制。
   * @param {string} url
   * @param {{ method?: string, body?: string, contentType?: string, timeoutMs?: number, redirect?: string }} [opts]
   */
  NS.fetchPageTextFromBackground = function (url, opts = {}) {
    return new Promise((resolve) => {
      try {
        if (!chrome?.runtime?.id) { resolve({ success: false, error: "no-extension-runtime" }); return; }
        const payload = { type: "fetchPageText", url, method: opts.method || "GET", body: opts.body, contentType: opts.contentType, timeoutMs: opts.timeoutMs != null ? opts.timeoutMs : 5000, redirect: opts.redirect || "follow" };
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
            if (now - entry.ts > ICP_CACHE_TTL_MS) { expired.push(key); continue; }
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
    if (batchMap) { const hit = batchMap.get(icpCacheStorageKey(host, source)); if (hit && hit.success) return { ...hit, queriedHost: hit.queriedHost || host, fromCache: true }; }
    else { const cached = await readIcpCache(host, source); if (cached && cached.success) return { ...cached, queriedHost: cached.queriedHost || host }; }
    const result = await fetcher(host);
    if (result && result.success) {
      const hasLicense = !!(result.icpRecord && NS.looksLikeIcpLicense(result.icpRecord));
      const normalized = { ...result, source: result.source || source, icpRecord: hasLicense ? result.icpRecord : "", icpMissing: !hasLicense };
      writeIcpCache(host, normalized);
      if (batchMap) batchMap.set(icpCacheStorageKey(host, source), { ...normalized, fromCache: false });
      return { ...normalized, queriedHost: result.queriedHost || host };
    }
    return result;
  }

  NS.looksLikeIcpLicense = function (value) {
    if (!value) return false;
    const v = String(value).trim();
    if (/(ICP|备案)/i.test(v) && /\d{4,}/.test(v)) return true;
    if (/^[一-鿿]{1,3}[A-Z]?\d{1,4}-\d{5,}(?:-\d+)?$/i.test(v)) return true;
    if (/^[一-鿿].{0,6}\d{5,}/.test(v) && !/未|没有|无|暂|失败|错误|找不到/.test(v)) return true;
    return false;
  };

  function extractIcpFromAizhanResponse(text) {
    if (!text) return { success: false };
    const m = String(text).match(/document\.write\s*\(\s*['"]([^'"]*)['"]\s*\)/i);
    if (!m) return { success: false };
    const value = (m[1] || "").trim();
    const isMissingMsg = !value || /未找到|未查询|未备案|没有|无备案|暂无|查无|不存在|null|undefined|失败|错误/i.test(value) || !NS.looksLikeIcpLicense(value);
    if (isMissingMsg) return { success: true, icpRecord: "", icpMissing: true, source: "aizhan" };
    return { success: true, icpRecord: value, icpMissing: false, source: "aizhan" };
  }

  // 爱站/uapis 轻量接口；beiancx 整页 HTML 更慢，超时更短以免拖死 race
  const ICP_FAST_TIMEOUT_MS = 2500;
  const ICP_BEIANCX_TIMEOUT_MS = 2800;
  // 任一源已给出明确 missing 后，再给其它源抢备案号的宽限
  const ICP_RACE_MISSING_GRACE_MS = 500;

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
        const data = JSON.parse(result.text);
        const code = String(data.code ?? data.status ?? "").trim();
        const license = String(data.serviceLicence || data.serviceLicense || data.icp || data.license || "").trim();
        const unitName = String(data.unitName || "").trim();
        const natureName = String(data.natureName || "").trim();
        const msg = String(data.msg || data.message || "").trim();
        if ((code === "200" || code === "0") && NS.looksLikeIcpLicense(license)) return { success: true, icpRecord: license, icpMissing: false, source: "uapis", unitName, natureName, queriedHost: h, domain: intelHost(data.domain || h) };
        if (code === "200" || code === "404" || /未|无备案|查无|不存在|not\s*found|no\s*record/i.test(msg)) return { success: true, icpRecord: "", icpMissing: true, source: "uapis", unitName, natureName, queriedHost: h, domain: intelHost(data.domain || h) };
        return { success: false, queriedHost: h };
      } catch { return { success: false, queriedHost: h }; }
    }, batchMap);
  }

  /**
   * beiancx.com 结果页 HTML：https://beiancx.com/{domain}.html
   * 查无/未备案按 404（及短 nginx 404 页）处理；备案号 / JSON-LD → license。
   * 仅用 beiancx.com（不用 www.beiancx.com）。
   */
  function extractIcpFromBeiancxHtml(html, httpStatus) {
    const status = Number(httpStatus) || 0;
    if (status === 404) return { success: true, icpRecord: "", icpMissing: true, source: "beiancx" };
    const text = String(html || "");
    if (!text) return { success: false, source: "beiancx" };
    // 短 nginx/404 页（查无即 404，无需再扫「未备案」文案）
    if (text.length < 1200 && /404\s*Not\s*Found|nginx/i.test(text) && !/备案号|ICP/i.test(text)) {
      return { success: true, icpRecord: "", icpMissing: true, source: "beiancx" };
    }
    // 结构化 JSON-LD
    try {
      const ldBlocks = text.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi) || [];
      for (const block of ldBlocks) {
        const raw = block.replace(/^[\s\S]*?>/, "").replace(/<\/script>\s*$/i, "");
        try {
          const obj = JSON.parse(raw);
          const pile = Array.isArray(obj) ? obj : [obj];
          for (const o of pile) {
            const lic = String(o?.serviceLicence || o?.serviceLicense || o?.icp || o?.license || o?.identifier || "").trim();
            if (NS.looksLikeIcpLicense(lic)) {
              return {
                success: true,
                icpRecord: lic,
                icpMissing: false,
                source: "beiancx",
                unitName: String(o?.name || o?.unitName || "").trim(),
                natureName: String(o?.natureName || "").trim()
              };
            }
          }
        } catch { /* ignore one block */ }
      }
    } catch { /* ignore */ }
    // 页面「备案号」字段 / 常见 ICP 形态
    const labeled = text.match(/备案号\s*<\/[^>]+>\s*<[^>]+>\s*([一-鿿A-Za-z0-9\-备证]{6,48})/i)
      || text.match(/备案号[：:\s]*([一-鿿A-Za-z0-9\-备证]{6,48})/i)
      || text.match(/>([一-鿿]{1,3}ICP[备证]\d{5,12}号(?:-\d+)?)</i)
      || text.match(/([一-鿿]{1,3}ICP[备证]\d{5,12}号(?:-\d+)?)/i)
      || text.match(/([一-鿿]{1,3}[A-Z]?\d{1,4}-\d{5,}(?:-\d+)?)/);
    if (labeled && labeled[1]) {
      const lic = String(labeled[1]).replace(/<[^>]+>/g, "").trim();
      if (NS.looksLikeIcpLicense(lic)) {
        let unitName = "";
        const um = text.match(/主办单位名称\s*<\/[^>]+>\s*<[^>]+>\s*([^<]{2,80})/i)
          || text.match(/主办单位名称[：:\s]*([^<\n]{2,80})/i);
        if (um) unitName = String(um[1] || "").trim();
        return { success: true, icpRecord: lic, icpMissing: false, source: "beiancx", unitName };
      }
    }
    // 明确「已备案」但抽不出号 → 不判 missing，留给其它源
    if (/已查询到备案|已备案/i.test(text) && /备案号/i.test(text)) return { success: false, source: "beiancx" };
    return { success: false, source: "beiancx" };
  }

  async function queryIcpBeiancx(domain, batchMap) {
    return withIcpCache(domain, "beiancx", async (h) => {
      // 仅 beiancx.com，不用 www.beiancx.com；整页 HTML 重，超时压短
      const url = `https://beiancx.com/${encodeURIComponent(h)}.html`;
      const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: ICP_BEIANCX_TIMEOUT_MS });
      if (!result.success) {
        if (result.status === 404 || /404|not\s*found/i.test(String(result.error || ""))) {
          return { success: true, icpRecord: "", icpMissing: true, source: "beiancx", queriedHost: h };
        }
        return { success: false, queriedHost: h };
      }
      if (result.status === 404) {
        return { success: true, icpRecord: "", icpMissing: true, source: "beiancx", queriedHost: h };
      }
      const parsed = extractIcpFromBeiancxHtml(result.text || "", result.status);
      return { ...parsed, source: "beiancx", queriedHost: h, domain: h };
    }, batchMap);
  }

  /**
   * 并行 race：任一源返回备案号立刻结束；
   * 若已有明确 missing，最多再等 ICP_RACE_MISSING_GRACE_MS 抢备案号，避免 beiancx 拖满 5s。
   */
  function raceIcpLicense(promises) {
    return new Promise((resolve) => {
      const list = promises.filter(Boolean);
      if (!list.length) { resolve(null); return; }
      let pending = list.length;
      let lastOk = null;
      let settled = false;
      let graceTimer = null;
      const finish = (r) => {
        if (settled) return;
        settled = true;
        if (graceTimer) { try { clearTimeout(graceTimer); } catch { /* ignore */ } graceTimer = null; }
        resolve(r);
      };
      for (const p of list) {
        Promise.resolve(p).then((r) => {
          if (settled) return;
          if (r && r.success && r.icpRecord && NS.looksLikeIcpLicense(r.icpRecord)) {
            finish({ ...r, icpMissing: false });
            return;
          }
          if (r && r.success) {
            lastOk = r;
            // 明确未备案：启动短宽限，不再死等最慢源
            if (r.icpMissing && !graceTimer) {
              graceTimer = setTimeout(() => { finish(lastOk); }, ICP_RACE_MISSING_GRACE_MS);
            }
          }
          pending -= 1;
          if (pending <= 0) finish(lastOk);
        }).catch(() => {
          if (settled) return;
          pending -= 1;
          if (pending <= 0) finish(lastOk);
        });
      }
    });
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
      writeIcpMissingCache(pageHost, { source: "no-candidates", triedHosts: [] });
      return { success: true, icpRecord: "", icpMissing: true, queriedHost: pageHost, triedHosts: [], fromCache: false };
    }
    const batchMap = await readIcpCacheBatch(candidates);
    const pageStatus = statusFromIcpBatchMap(pageHost, batchMap);
    if (pageStatus && pageStatus.kind === "missing") {
      NS.silverfoxLog("intel-icp", "cache-miss-hit", pageHost, "ms=", Date.now() - t0);
      return { ...pageStatus.data, icpMissing: true, matchedHost: pageHost, queriedHost: pageHost, triedHosts: candidates, fromCache: true };
    }
    if (pageStatus && pageStatus.kind === "license") {
      NS.silverfoxLog("intel-icp", "cache-license-hit", pageHost, "ms=", Date.now() - t0);
      return { ...pageStatus.data, icpMissing: false, matchedHost: pageHost, queriedHost: pageHost };
    }
    let lastSource = "unknown";
    let sawDefinitiveMissing = false;
    // 最多查 2 个候选（当前 + apex），避免串行 race 叠满
    const toTry = candidates.slice(0, 2);
    for (const host of toTry) {
      if (!NS.intelHostIsValidAttribution(host, pageHost) && host !== pageHost) continue;
      const cached = statusFromIcpBatchMap(host, batchMap);
      if (cached && cached.kind === "license") {
        const matched = cached.data.matchedHost || host;
        if (NS.intelHostIsValidAttribution(matched, pageHost) || matched === host) {
          clearIcpMissingCache(pageHost);
          NS.silverfoxLog("intel-icp", "host-cache-license", host, "ms=", Date.now() - t0);
          return { ...cached.data, icpMissing: false, matchedHost: host, queriedHost: host };
        }
      }
      if (cached && cached.kind === "missing") {
        sawDefinitiveMissing = true;
        lastSource = cached.data.source || lastSource;
        continue;
      }
      NS.silverfoxLog("intel-icp", "race-start", host);
      // aizhan / uapis 快路径 + beiancx 并行；备案号先到先用
      const winner = await raceIcpLicense([
        queryIcpAizhan(host, batchMap),
        queryIcpUapis(host, batchMap),
        queryIcpBeiancx(host, batchMap)
      ]);
      if (winner && winner.source) lastSource = winner.source;
      if (winner && winner.icpRecord && NS.looksLikeIcpLicense(winner.icpRecord)) {
        const claimed = NS.normalizeDomain(winner.domain || "");
        if (claimed && claimed !== host && !NS.intelHostIsValidAttribution(claimed, pageHost)) continue;
        clearIcpMissingCache(pageHost); clearIcpMissingCache(host);
        NS.silverfoxLog("intel-icp", "license", host, winner.source, "ms=", Date.now() - t0);
        return { ...winner, icpMissing: false, matchedHost: host, queriedHost: winner.queriedHost || host };
      }
      if (winner && winner.success) {
        sawDefinitiveMissing = true;
        writeIcpMissingCache(host, { source: winner.source || lastSource, triedHosts: [host] });
        // 当前主机已明确 missing 则不必再拖第二个候选满 race（apex 缓存 miss 再试一次即可）
        if (host === pageHost || host === pageHost.replace(/^www\./i, "")) {
          /* continue to apex once */
        }
      }
    }
    if (sawDefinitiveMissing) {
      writeIcpMissingCache(pageHost, { source: lastSource, triedHosts: toTry });
      NS.silverfoxLog("intel-icp", "missing", pageHost, "ms=", Date.now() - t0);
      return { success: true, icpRecord: "", icpMissing: true, queriedHost: pageHost, triedHosts: toTry, source: lastSource, fromCache: false };
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

    // ① 扁平 WHOIS 字段（rdap.ss → CNNIC whoisData / rawData）
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
      let registeredAt = "";
      // 结构化字段优先，再 CNNIC 文本行
      const dateCandidates = [
        fields.creation_date, fields.Creation_Date, fields.created, fields.Created,
        info.creation_time, info.creation_date, info.created, info.Created,
        fields["Creation Date"], fields["Created Date"], info["Creation Date"], info["Created Date"]
      ];
      for (const c of dateCandidates) {
        registeredAt = parseWhoisDateToIso(c);
        if (registeredAt) break;
      }
      if (!registeredAt && rawWhois) {
        // CNNIC / 通用 WHOIS 行
        const lineRe = /(?:Registration\s*Time|Registration\s*Date|Created\s*Date|Creation\s*Date|Created\s*On|Domain\s*Name\s*Commencement\s*Date|注册时间|创建日期)\s*[：:]\s*([0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}(?:\s+[0-9:]{5,8})?)/i;
        const lm = rawWhois.match(lineRe);
        if (lm) registeredAt = parseWhoisDateToIso(lm[1]);
      }
      // 仅有 creation_days 而无真实日期 → 丢弃（禁止反推「今天/0天」）
      if (!registeredAt) return null;
      let ageDaysOpt = null;
      if (typeof info.creation_days === "number" && info.creation_days >= 0) ageDaysOpt = Math.floor(info.creation_days);
      else if (info.creation_days != null && /^\d+$/.test(String(info.creation_days))) ageDaysOpt = parseInt(String(info.creation_days), 10);
      return finalizeWhoisResult(host, registeredAt, ageDaysOpt, "whoiscx.com");
    } catch { return null; }
  }

  function raceWhoisSources(host) {
    return new Promise((resolve) => {
      if (NS.isPublicSuffixOnlyHost(host)) { resolve(null); return; }
      const tasks = [queryWhoisRdapSs(host), queryWhoisWhoiscx(host)];
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
