/**
 * ICP/WHOIS 网络查询 + 24h 缓存 + 下载行为探测。
 * 所有外部 HTTP(S) 必须经 background SW（content-script fetch 受 CORS 限制）。
 */
;(function (NS) {
  "use strict";

  const ICP_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  const ICP_CACHE_KEY_PREFIX = "icp_cache_v4_";
  const ICP_MISS_KEY_PREFIX = "icp_miss_v1_";
  const ICP_CACHE_SOURCES = ["aizhan", "uapis"];
  const WHOIS_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  const WHOIS_CACHE_KEY_PREFIX = "whois_cache_v5_";

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
    const host = NS.normalizeDomain(domain);
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

  async function queryIcpAizhan(domain, batchMap) {
    const host = NS.normalizeDomain(domain);
    return withIcpCache(host, "aizhan", async (h) => {
      const url = `https://icp.aizhan.com/geticp/?host=${encodeURIComponent(h)}`;
      const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 4000 });
      if (!result.success || !result.text) return { success: false, queriedHost: h };
      const parsed = extractIcpFromAizhanResponse(result.text);
      return { ...parsed, source: "aizhan", queriedHost: h };
    }, batchMap);
  }

  async function queryIcpUapis(domain, batchMap) {
    const host = NS.normalizeDomain(domain);
    return withIcpCache(host, "uapis", async (h) => {
      const url = `https://uapis.cn/api/v1/network/icp?domain=${encodeURIComponent(h)}`;
      const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 4000 });
      if (!result.success || !result.text) return { success: false, queriedHost: h };
      try {
        const data = JSON.parse(result.text);
        const code = String(data.code ?? data.status ?? "").trim();
        const license = String(data.serviceLicence || data.serviceLicense || data.icp || data.license || "").trim();
        const unitName = String(data.unitName || "").trim();
        const natureName = String(data.natureName || "").trim();
        const msg = String(data.msg || data.message || "").trim();
        if ((code === "200" || code === "0") && NS.looksLikeIcpLicense(license)) return { success: true, icpRecord: license, icpMissing: false, source: "uapis", unitName, natureName, queriedHost: h, domain: NS.normalizeDomain(data.domain || h) };
        if (code === "200" || code === "404" || /未|无备案|查无|不存在|not\s*found|no\s*record/i.test(msg)) return { success: true, icpRecord: "", icpMissing: true, source: "uapis", unitName, natureName, queriedHost: h, domain: NS.normalizeDomain(data.domain || h) };
        return { success: false, queriedHost: h };
      } catch { return { success: false, queriedHost: h }; }
    }, batchMap);
  }

  function raceIcpLicense(promises) {
    return new Promise((resolve) => {
      const list = promises.filter(Boolean);
      if (!list.length) { resolve(null); return; }
      let pending = list.length; let lastOk = null; let settled = false;
      for (const p of list) {
        Promise.resolve(p).then((r) => {
          if (settled) return;
          if (r && r.success && r.icpRecord && NS.looksLikeIcpLicense(r.icpRecord)) { settled = true; resolve({ ...r, icpMissing: false }); return; }
          if (r && r.success) lastOk = r;
          pending -= 1;
          if (pending <= 0) resolve(lastOk);
        }).catch(() => { if (settled) return; pending -= 1; if (pending <= 0) resolve(lastOk); });
      }
    });
  }

  async function buildIcpQueryCandidates(domain) {
    const currentHost = NS.normalizeDomain(domain);
    if (!currentHost || !currentHost.includes(".")) return [];
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(currentHost)) return [];
    const chain = NS.buildWhoisQueryCandidates(currentHost);
    if (!chain.length) return [currentHost];
    const currentWhois = await NS.queryWhoisRegistrationExact(currentHost);
    const parents = chain.slice(1);
    const parentsTopDown = parents.slice().reverse();
    const out = []; const seen = new Set();
    for (const parent of parentsTopDown) {
      if (!parent || seen.has(parent)) continue;
      const parentWhois = await NS.queryWhoisRegistrationExact(parent);
      if (!NS.whoisHasResult(parentWhois)) continue;
      if (!NS.whoisHasResult(currentWhois) || !NS.whoisRecordsMatch(currentWhois, parentWhois)) continue;
      seen.add(parent);
      out.push(parent);
    }
    if (!seen.has(currentHost)) out.push(currentHost);
    return out.length ? out : [currentHost];
  }

  NS.detectIcpDomain = async function (domain) {
    if (!domain) return { icpMissing: false, success: false };
    const pageHost = NS.normalizeDomain(domain);
    const candidates = await buildIcpQueryCandidates(domain);
    if (!candidates.length) { writeIcpMissingCache(pageHost, { source: "no-candidates", triedHosts: [] }); return { success: true, icpRecord: "", icpMissing: true, queriedHost: pageHost, triedHosts: [], fromCache: false }; }
    const batchMap = await readIcpCacheBatch(candidates);
    const pageStatus = statusFromIcpBatchMap(pageHost, batchMap);
    if (pageStatus && pageStatus.kind === "missing") { NS.silverfoxLog("intel-icp", "cache-miss-hit", pageHost); return { ...pageStatus.data, icpMissing: true, matchedHost: pageHost, queriedHost: pageHost, triedHosts: candidates, fromCache: true }; }
    if (pageStatus && pageStatus.kind === "license") { NS.silverfoxLog("intel-icp", "cache-license-hit", pageHost); return { ...pageStatus.data, icpMissing: false, matchedHost: pageHost, queriedHost: pageHost }; }
    let lastSource = "unknown"; let sawDefinitiveMissing = false;
    for (const host of candidates) {
      if (!NS.intelHostIsValidAttribution(host, pageHost) && host !== pageHost) continue;
      const cached = statusFromIcpBatchMap(host, batchMap);
      if (cached && cached.kind === "license") { const matched = cached.data.matchedHost || host; if (NS.intelHostIsValidAttribution(matched, pageHost) || matched === host) { clearIcpMissingCache(pageHost); return { ...cached.data, icpMissing: false, matchedHost: host, queriedHost: host }; } }
      if (cached && cached.kind === "missing") { sawDefinitiveMissing = true; lastSource = cached.data.source || lastSource; continue; }
      const winner = await raceIcpLicense([queryIcpAizhan(host, batchMap), queryIcpUapis(host, batchMap)]);
      if (winner && winner.source) lastSource = winner.source;
      if (winner && winner.icpRecord && NS.looksLikeIcpLicense(winner.icpRecord)) {
        const claimed = NS.normalizeDomain(winner.domain || "");
        if (claimed && claimed !== host && !NS.intelHostIsValidAttribution(claimed, pageHost)) continue;
        clearIcpMissingCache(pageHost); clearIcpMissingCache(host);
        return { ...winner, icpMissing: false, matchedHost: host, queriedHost: winner.queriedHost || host };
      }
      if (winner && winner.success) { sawDefinitiveMissing = true; writeIcpMissingCache(host, { source: winner.source || lastSource, triedHosts: [host] }); }
    }
    if (sawDefinitiveMissing) { writeIcpMissingCache(pageHost, { source: lastSource, triedHosts: candidates }); return { success: true, icpRecord: "", icpMissing: true, queriedHost: pageHost, triedHosts: candidates, source: lastSource, fromCache: false }; }
    return { success: false, icpRecord: "", icpMissing: false, queriedHost: pageHost, triedHosts: candidates, source: lastSource };
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
    const key = whoisCacheStorageKey(domain);
    const toStore = { ts: Date.now(), result: { success: true, registeredAt: result.registeredAt || "", ageDays: typeof result.ageDays === "number" ? result.ageDays : null, queriedHost: result.queriedHost || NS.normalizeDomain(domain), source: result.source || "rdap.ss" } };
    try { if (!chrome?.storage?.local) return Promise.resolve(); chrome.storage.local.set({ [key]: toStore }, () => { void chrome.runtime.lastError; }); } catch { /* ignore */ }
    return Promise.resolve();
  }

  NS.extractRegistrationDateFromRdap = function (data) {
    if (!data || typeof data !== "object") return "";
    const collectEvents = (obj, out) => { if (!obj || typeof obj !== "object") return; if (Array.isArray(obj.events)) { for (const ev of obj.events) { if (ev && typeof ev === "object") out.push(ev); } } };
    const events = [];
    collectEvents(data, events);
    if (data.data && typeof data.data === "object") {
      collectEvents(data.data, events);
      const levels = data.data.levels || {};
      collectEvents(levels.registry, events); collectEvents(levels.registrar, events);
      collectEvents(data.data.rawData, events); collectEvents(data.data, events);
    }
    try { const reg = data.data && data.data.levels && data.data.levels.registry; collectEvents(reg, events); const rar = data.data && data.data.levels && data.data.levels.registrar; collectEvents(rar, events); } catch { /* ignore */ }
    const isReg = (a) => /^(registration|registered|domain registration)$/i.test(String(a || "").trim());
    for (const ev of events) { if (isReg(ev.eventAction) && ev.eventDate) { const t = Date.parse(ev.eventDate); if (!Number.isNaN(t)) return new Date(t).toISOString(); } }
    try {
      const blob = JSON.stringify(data);
      const m = blob.match(/"eventAction"\s*:\s*"registration"\s*,\s*"eventDate"\s*:\s*"([^"]+)"/i) || blob.match(/"eventDate"\s*:\s*"([^"]+)"\s*,\s*"eventAction"\s*:\s*"registration"/i);
      if (m && m[1]) { const t = Date.parse(m[1]); if (!Number.isNaN(t)) return new Date(t).toISOString(); }
    } catch { /* ignore */ }
    return "";
  };

  function finalizeWhoisResult(host, registeredAt, ageDaysOpt, source) {
    let ageDays = typeof ageDaysOpt === "number" && ageDaysOpt >= 0 ? Math.floor(ageDaysOpt) : null;
    if (ageDays == null && registeredAt) { const ageMs = Date.now() - Date.parse(registeredAt); if (!Number.isNaN(ageMs)) ageDays = Math.max(0, Math.floor(ageMs / (24 * 60 * 60 * 1000))); }
    if (!registeredAt && ageDays == null) return null;
    let regIso = registeredAt || "";
    if (!regIso && ageDays != null) regIso = new Date(Date.now() - ageDays * 24 * 60 * 60 * 1000).toISOString();
    return { success: true, registeredAt: regIso, ageDays: ageDays != null ? ageDays : null, queriedHost: host, source: source || "whois" };
  }

  async function queryWhoisRdapSs(host) {
    const url = `https://rdap.ss/api/query?q=${encodeURIComponent(host)}`;
    const result = await NS.fetchPageTextFromBackground(url, { timeoutMs: 4500 });
    if (!result.success || !result.text) return null;
    try {
      const data = JSON.parse(result.text);
      if (data && data.success === false) return null;
      const registeredAt = NS.extractRegistrationDateFromRdap(data);
      if (!registeredAt) return null;
      return finalizeWhoisResult(host, registeredAt, null, "rdap.ss");
    } catch { return null; }
  }

  async function queryWhoisWhoiscx(host) {
    const url = "https://whoiscx.com/api/whois/info/";
    const result = await NS.fetchPageTextFromBackground(url, { method: "POST", body: `domain=${encodeURIComponent(host)}`, contentType: "application/x-www-form-urlencoded;charset=UTF-8", timeoutMs: 4500 });
    if (!result.success || !result.text) return null;
    try {
      const data = JSON.parse(result.text);
      const st = data.status;
      if (st !== 1 && st !== "1" && st !== true && st !== "ok" && st !== 200 && st !== "200") { if (!data.data) return null; }
      const info = (data.data && data.data.info) || {};
      const fields = (data.data && data.data.fields) || {};
      let registeredAt = "";
      const candidates = [fields.creation_date, info.creation_time, fields.created, info.created];
      for (const c of candidates) {
        if (!c) continue;
        const normalized = String(c).trim().replace(" ", "T");
        const t = Date.parse(normalized) || Date.parse(String(c).trim().replace(/(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, "$1T$2Z"));
        if (!Number.isNaN(t)) { registeredAt = new Date(t).toISOString(); break; }
        const dOnly = String(c).trim().match(/^(\d{4}-\d{2}-\d{2})/);
        if (dOnly) { const t2 = Date.parse(`${dOnly[1]}T00:00:00Z`); if (!Number.isNaN(t2)) { registeredAt = new Date(t2).toISOString(); break; } }
      }
      let ageDays = null;
      if (typeof info.creation_days === "number" && info.creation_days >= 0) ageDays = Math.floor(info.creation_days);
      else if (info.creation_days != null && /^\d+$/.test(String(info.creation_days))) ageDays = parseInt(String(info.creation_days), 10);
      if (!registeredAt && ageDays == null) return null;
      return finalizeWhoisResult(host, registeredAt, ageDays, "whoiscx.com");
    } catch { return null; }
  }

  function raceWhoisSources(host) {
    return new Promise((resolve) => {
      const tasks = [queryWhoisRdapSs(host), queryWhoisWhoiscx(host)];
      let pending = tasks.length; let settled = false;
      for (const p of tasks) {
        Promise.resolve(p).then((r) => {
          if (settled) return;
          if (r && r.success && (r.registeredAt || typeof r.ageDays === "number")) { settled = true; resolve(r); return; }
          pending -= 1; if (pending <= 0) resolve(null);
        }).catch(() => { if (settled) return; pending -= 1; if (pending <= 0) resolve(null); });
      }
    });
  }

  NS.buildWhoisQueryCandidates = function (domain) {
    const host = NS.normalizeDomain(domain);
    if (!host || !host.includes(".")) return [];
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return [];
    const parts = host.split(".").filter(Boolean);
    if (parts.length < 2) return [];
    const out = []; const seen = new Set();
    for (let i = 0; i <= parts.length - 2; i++) { const cand = parts.slice(i).join("."); if (!cand || seen.has(cand)) continue; if (!cand.includes(".")) continue; seen.add(cand); out.push(cand); }
    return out;
  };

  NS.queryWhoisRegistrationExact = async function (domain) {
    const host = NS.normalizeDomain(domain);
    if (!host || !host.includes(".")) return { success: false, queriedHost: host || "" };
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return { success: false, queriedHost: host };
    const cached = await readWhoisCache(host);
    if (cached && cached.success && (cached.registeredAt || typeof cached.ageDays === "number")) return { ...cached, queriedHost: cached.queriedHost || host };
    const out = await raceWhoisSources(host);
    if (out && NS.whoisHasResult(out)) { writeWhoisCache(host, out); return { ...out, queriedHost: out.queriedHost || host }; }
    return { success: false, queriedHost: host };
  };

  NS.queryWhoisRegistration = async function (domain) {
    const candidates = NS.buildWhoisQueryCandidates(domain);
    if (!candidates.length) return { success: false, queriedHost: NS.normalizeDomain(domain) || "" };
    for (const host of candidates) { const out = await NS.queryWhoisRegistrationExact(host); if (NS.whoisHasResult(out)) return { ...out, queriedHost: out.queriedHost || host }; }
    return { success: false, queriedHost: candidates[0], triedHosts: candidates };
  };

  NS.whoisHasResult = function (whois) {
    if (!whois || !whois.success) return false;
    if (whois.registeredAt) return true;
    if (typeof whois.ageDays === "number" && Number.isFinite(whois.ageDays)) return true;
    return false;
  };

  NS.whoisRecordsMatch = function (a, b) {
    if (!NS.whoisHasResult(a) || !NS.whoisHasResult(b)) return false;
    const da = (a.registeredAt || "").slice(0, 10);
    const db = (b.registeredAt || "").slice(0, 10);
    if (da && db && da === db) return true;
    if (typeof a.ageDays === "number" && typeof b.ageDays === "number" && Number.isFinite(a.ageDays) && Number.isFinite(b.ageDays) && Math.abs(a.ageDays - b.ageDays) <= 1) return true;
    return false;
  };

  NS.applyWhoisRegistrationRisk = function (whois) {
    if (!whois || !whois.success || typeof whois.ageDays !== "number") return false;
    const days = whois.ageDays;
    const host = whois.queriedHost || location.hostname;
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
    if (!whois || !whois.success) return "";
    const host = whois.queriedHost || NS.getRegistrableDomain(location.hostname) || location.hostname;
    const dateStr = (whois.registeredAt || "").slice(0, 10);
    const days = typeof whois.ageDays === "number" ? whois.ageDays : null;
    const parts = [];
    if (host) parts.push(host);
    if (dateStr) parts.push(`注册于 ${dateStr}`);
    if (days != null) parts.push(`已注册 ${days} 天`);
    return parts.join(" · ");
  };

  NS.detectWhoisRegistrationAge = async function (domain) {
    try {
      const whois = await NS.queryWhoisRegistration(domain || location.hostname);
      if (!whois.success) return whois;
      NS.state.whoisInfo = NS.formatWhoisInfoForReport(whois);
      NS.applyWhoisRegistrationRisk(whois);
      return whois;
    } catch { return { success: false }; }
  };
})(window.SilverfoxContent ??= {});
