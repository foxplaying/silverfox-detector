/**
 * SSL 证书等级（DV / OV / EV）探测。
 *
 * Chrome webRequest securityInfo 需开发者 flag，不可用。
 * 方案：多源 CT/公开 API 拉叶子证书，仅根据 **叶子 Subject（使用者）** 与 **certificatePolicies** 分类。
 * 绝不根据 Issuer（颁发者）名称里的 “OV/EV CA” 字样定级（Issuer 仅用于优先下 DER / 禁止 DV 软截止）。
 *
 * ── 数据源（并行发出，先到先用；免 API Key；2026-07 实测）──
 *   1. Qualys SSL Labs  https://api.ssllabs.com/api/v3/analyze  ✓
 *   2. crt.sh           https://crt.sh/?q=&output=json + ?d=id  ✓（偶发 502）
 *   3. Cert Spotter     https://api.certspotter.com/v1/issuances ✓
 *   4. Shodan CT        https://ctl.shodan.io/api/v1/domain|cert ✓
 *   5. NetworkCalc      https://networkcalc.com/api/security/certificate/ ✓（实时叶证书 PEM）
 *   6. MySSL report     https://myssl.com/{domain}               ✓（validation + org）
 *   7. EdgeOne SSL      https://api.edgeone.ai/eo/tools/ssl?url=  ✓（实时 subject/issuer）
 *
 * 不可用/不适合「按域名即时查证」：
 *   - wss://certstream.calidog.io  仅实时 firehose，无 domain 查询；无法保证打开页时有新证
 *   - 官方 CT Log（Google/Cloudflare/DigiCert 等 RFC6962 get-entries）
 *     只能按 index 扫日志，不能按域名检索；域名检索依赖 crt.sh / Cert Spotter / Shodan
 *   - Entrust CT Search（DNS 失效）
 *
 * ── 三级互斥规则（由高到低，不可颠倒）──
 *   EV  扩展验证：策略含 EV OID，或 Subject 同时具备 O + businessCategory + jurisdiction*
 *   OV  组织验证：策略含 OV OID，或 Subject 有组织名 O=（且不满足 EV）
 *   DV  域名验证：仅域名（CN/SAN），无组织名
 *
 * CABF 策略 OID：
 *   2.23.140.1.1       = EV
 *   2.23.140.1.2.1     = DV
 *   2.23.140.1.2.2     = OV
 *   2.23.140.1.2 / 2.23.140.1.2.3 = 基线 / IV → 不当 EV
 */
;(function (NS) {
  "use strict";

  NS.sslCertByHost = NS.sslCertByHost || new Map();
  NS._sslProbeInflight = NS._sslProbeInflight || new Map();
  NS._sslSourceCache = NS._sslSourceCache || new Map();
  NS._sslSourceInflight = NS._sslSourceInflight || new Map();
  NS._sslSourceCooldowns = NS._sslSourceCooldowns || new Map();

  const SSL_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
  const SSL_SOURCE_SUCCESS_TTL_MS = 6 * 60 * 60 * 1000;
  const SSL_SOURCE_EMPTY_TTL_MS = 15 * 60 * 1000;
  const SSL_CERT_CACHE_STORAGE_KEY = "silverfox_ssl_cert_cache_v1";
  const SSL_SOURCE_STATE_STORAGE_KEY = "silverfox_ssl_source_state_v1";
  const SSL_SOURCE_CACHE_MAX = 240;
  let sslPersistentLoaded = false;
  let sslPersistentLoadPromise = null;
  let sslPersistTimer = null;

  function storageLocalAvailable() {
    try {
      return typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
    } catch {
      return false;
    }
  }

  function ensureSslPersistentStateLoaded() {
    if (sslPersistentLoaded) return Promise.resolve();
    if (sslPersistentLoadPromise) return sslPersistentLoadPromise;
    sslPersistentLoadPromise = new Promise((resolve) => {
      const done = () => {
        sslPersistentLoaded = true;
        sslPersistentLoadPromise = null;
        resolve();
      };
      if (!storageLocalAvailable()) {
        done();
        return;
      }
      try {
        chrome.storage.local.get([SSL_CERT_CACHE_STORAGE_KEY, SSL_SOURCE_STATE_STORAGE_KEY], (data) => {
          try {
            void chrome.runtime?.lastError;
            const now = Date.now();
            const certs = data && data[SSL_CERT_CACHE_STORAGE_KEY];
            if (certs && typeof certs === "object") {
              for (const [key, value] of Object.entries(certs)) {
                if (!value || typeof value !== "object") continue;
                const at = Number(value.at) || 0;
                if (!at || now - at > SSL_CACHE_TTL_MS) continue;
                NS.sslCertByHost.set(key, value);
              }
            }
            const state = data && data[SSL_SOURCE_STATE_STORAGE_KEY];
            const cached = state && state.cache;
            if (cached && typeof cached === "object") {
              for (const [key, entry] of Object.entries(cached)) {
                if (!entry || typeof entry !== "object") continue;
                const at = Number(entry.at) || 0;
                const ttl = Math.max(0, Number(entry.ttl) || 0);
                if (!at || !ttl || now - at > ttl) continue;
                NS._sslSourceCache.set(key, entry);
              }
            }
            const cooldowns = state && state.cooldowns;
            if (cooldowns && typeof cooldowns === "object") {
              for (const [provider, entry] of Object.entries(cooldowns)) {
                const until = Number(entry && entry.until) || 0;
                if (until > now) NS._sslSourceCooldowns.set(provider, entry);
              }
            }
          } catch { /* ignore corrupt/old cache */ }
          done();
        });
      } catch {
        done();
      }
    });
    return sslPersistentLoadPromise;
  }

  function pruneSslPersistentState() {
    const now = Date.now();
    for (const [key, value] of NS.sslCertByHost.entries()) {
      const at = Number(value && value.at) || 0;
      if (!at || now - at > SSL_CACHE_TTL_MS) NS.sslCertByHost.delete(key);
    }
    for (const [key, entry] of NS._sslSourceCache.entries()) {
      const at = Number(entry && entry.at) || 0;
      const ttl = Number(entry && entry.ttl) || 0;
      if (!at || !ttl || now - at > ttl) NS._sslSourceCache.delete(key);
    }
    if (NS._sslSourceCache.size > SSL_SOURCE_CACHE_MAX) {
      const oldest = [...NS._sslSourceCache.entries()]
        .sort((a, b) => (Number(a[1] && a[1].at) || 0) - (Number(b[1] && b[1].at) || 0));
      while (oldest.length && NS._sslSourceCache.size > SSL_SOURCE_CACHE_MAX) {
        NS._sslSourceCache.delete(oldest.shift()[0]);
      }
    }
    for (const [provider, entry] of NS._sslSourceCooldowns.entries()) {
      if ((Number(entry && entry.until) || 0) <= now) NS._sslSourceCooldowns.delete(provider);
    }
  }

  function persistSslStateNow() {
    if (!storageLocalAvailable()) return;
    pruneSslPersistentState();
    const certs = Object.fromEntries(NS.sslCertByHost.entries());
    const cache = Object.fromEntries(NS._sslSourceCache.entries());
    const cooldowns = Object.fromEntries(NS._sslSourceCooldowns.entries());
    try {
      chrome.storage.local.set({
        [SSL_CERT_CACHE_STORAGE_KEY]: certs,
        [SSL_SOURCE_STATE_STORAGE_KEY]: { cache, cooldowns, savedAt: Date.now() }
      }, () => { try { void chrome.runtime?.lastError; } catch { /* ignore */ } });
    } catch { /* ignore */ }
  }

  function persistSslStateSoon(immediate) {
    if (!storageLocalAvailable()) return;
    if (sslPersistTimer) {
      clearTimeout(sslPersistTimer);
      sslPersistTimer = null;
    }
    if (immediate) {
      persistSslStateNow();
      return;
    }
    sslPersistTimer = setTimeout(() => {
      sslPersistTimer = null;
      persistSslStateNow();
    }, 250);
  }

  function sslProviderForUrl(url) {
    try {
      const h = new URL(String(url || "")).hostname.toLowerCase();
      if (h === "api.certspotter.com") return "certspotter";
      if (h === "api.ssllabs.com") return "ssllabs";
      if (h === "crt.sh") return "crtsh";
      if (h === "ctl.shodan.io") return "shodan";
      if (h === "networkcalc.com") return "networkcalc";
      if (h === "myssl.com" || h === "www.myssl.com") return "myssl";
      if (h === "api.edgeone.ai") return "edgeone";
    } catch { /* ignore */ }
    return "";
  }

  function retryAfterMs(raw, provider) {
    const fallback = provider === "certspotter" ? 24 * 60 * 60 * 1000 : 30 * 60 * 1000;
    const s = String(raw || "").trim();
    if (!s) return fallback;
    if (/^\d+$/.test(s)) return Math.max(60 * 1000, Number(s) * 1000);
    const at = Date.parse(s);
    if (Number.isFinite(at) && at > Date.now()) return Math.max(60 * 1000, at - Date.now());
    return fallback;
  }

  function providerCoolingDown(provider) {
    if (!provider) return false;
    const entry = NS._sslSourceCooldowns.get(provider);
    if (!entry) return false;
    if ((Number(entry.until) || 0) > Date.now()) return true;
    NS._sslSourceCooldowns.delete(provider);
    persistSslStateSoon(false);
    return false;
  }

  function noteProviderRateLimited(provider, retryAfter) {
    if (!provider) return;
    const now = Date.now();
    const until = now + retryAfterMs(retryAfter, provider);
    const prev = NS._sslSourceCooldowns.get(provider);
    NS._sslSourceCooldowns.set(provider, {
      until: Math.max(until, Number(prev && prev.until) || 0),
      status: 429,
      at: now
    });
    // 429 熔断必须立刻落盘，避免 MV3 Service Worker 重启后继续打限流源。
    persistSslStateSoon(true);
  }

  function sourceEmptyTtl(provider) {
    if (provider === "ssllabs") return 60 * 1000; // IN_PROGRESS 很快可能转 READY
    if (provider === "crtsh") return 10 * 60 * 1000;
    return SSL_SOURCE_EMPTY_TTL_MS;
  }

  function hasBoundSslOrganization(value) {
    const org = String((value && value.organization) || "").trim();
    if (!org || isBogusPlaceholderOrg(org)) return false;
    return value.sniChainVerified === true || value.liveTlsLeafVerified === true
      || value.unexpiredHostVerified === true;
  }

  function sourceSuccessTtl(provider, value) {
    const rank = validationRank(value && value.validation);
    // 只有机构名与当前/未过期匹配叶证书绑定后，OV/EV 才算完整结果。
    if (rank >= 2 && hasBoundSslOrganization(value)) {
      return SSL_SOURCE_SUCCESS_TTL_MS;
    }
    // 升级链只主动刷新 SSL Labs；其它公开源至少覆盖整轮 20s 重试，避免重复扇出与 429。
    const weakTtl = provider === "ssllabs" ? 30 * 1000 : 3 * 60 * 1000;
    if (rank >= 2) return weakTtl;
    if (rank === 1) return canSoftFinishDv(value) ? 3 * 60 * 1000 : weakTtl;
    return weakTtl;
  }

  /**
   * 只失效指定来源、指定主机的空/弱结果。用于 SSL Labs IN_PROGRESS 后补查；
   * 其它来源与 429 熔断保持不变，避免一次升级重试放大成全源请求风暴。
   */
  NS.invalidateWeakSslSourceCacheForHost = function (host, providers) {
    const rawHost = rawHostname(host);
    if (!rawHost) return 0;
    const allowed = new Set((Array.isArray(providers) && providers.length ? providers : ["ssllabs"])
      .map((provider) => String(provider || "").toLowerCase()).filter(Boolean));
    let removed = 0;
    for (const [key, entry] of NS._sslSourceCache.entries()) {
      const splitAt = key.indexOf("|");
      if (splitAt < 1) continue;
      const provider = key.slice(0, splitAt).toLowerCase();
      const cachedHost = key.slice(splitAt + 1);
      if (!allowed.has(provider) || cachedHost !== rawHost) continue;
      const value = entry && entry.value;
      const rank = validationRank(value && value.validation);
      const complete = rank >= 2 && hasBoundSslOrganization(value);
      if (complete) continue;
      NS._sslSourceCache.delete(key);
      removed += 1;
    }
    if (removed) persistSslStateSoon(false);
    return removed;
  };

  async function runCachedSslSource(provider, host, runner) {
    await ensureSslPersistentStateLoaded();
    const key = `${provider}|${rawHostname(host)}`;
    const now = Date.now();
    const cached = NS._sslSourceCache.get(key);
    if (cached && now - (Number(cached.at) || 0) <= (Number(cached.ttl) || 0)) {
      return cached.value || null;
    }
    if (cached) NS._sslSourceCache.delete(key);
    if (providerCoolingDown(provider)) return null;
    if (NS._sslSourceInflight.has(key)) return NS._sslSourceInflight.get(key);
    const p = Promise.resolve().then(runner).catch(() => null).then((value) => {
      // 429 已有独立持久化熔断；不要再用普通空结果覆盖其状态。
      if (value || !providerCoolingDown(provider)) {
        NS._sslSourceCache.set(key, {
          at: Date.now(),
          ttl: value ? sourceSuccessTtl(provider, value) : sourceEmptyTtl(provider),
          value: value || null
        });
        persistSslStateSoon(false);
      }
      return value || null;
    }).finally(() => {
      NS._sslSourceInflight.delete(key);
    });
    NS._sslSourceInflight.set(key, p);
    return p;
  }

  const OID_CN = "2.5.4.3";
  const OID_O = "2.5.4.10";
  const OID_OU = "2.5.4.11";
  const OID_SERIAL = "2.5.4.5";
  const OID_BUSINESS_CAT = "2.5.4.15";
  const OID_CABF_EV = "2.23.140.1.1";
  const OID_CABF_DV = "2.23.140.1.2.1";
  const OID_CABF_OV = "2.23.140.1.2.2";
  const OID_CABF_IV = "2.23.140.1.2.3";
  const OID_JURIS_C = "1.3.6.1.4.1.311.60.2.1.3";
  const OID_JURIS_ST = "1.3.6.1.4.1.311.60.2.1.2";
  const OID_JURIS_L = "1.3.6.1.4.1.311.60.2.1.1";
  // 常见 CA 私有 EV 策略 OID（与 CABF 2.23.140.1.1 并列出现）
  const VENDOR_EV_POLICY_OIDS = [
    "2.16.840.1.114412.2.1",           // DigiCert EV
    "1.3.6.1.4.1.6449.1.2.1.5.1",      // Sectigo/Comodo EV
    "1.3.6.1.4.1.4146.1.1",            // GlobalSign EV
    "2.16.840.1.114028.10.1.2",        // Entrust EV
    "2.16.840.1.114413.1.7.23.3",      // GoDaddy EV
    "2.16.840.1.114414.1.7.23.3",      // Starfield EV
    "1.3.6.1.4.1.8024.0.2.100.1.2",    // QuoVadis EV
    "1.3.6.1.4.1.17326.10.14.2.1.2",   // Camerfirma EV
    "1.3.6.1.4.1.34697.2.1",           // AffirmTrust EV
    "1.3.6.1.4.1.34697.2.2",
    "1.3.6.1.4.1.34697.2.3",
    "1.3.6.1.4.1.34697.2.4"
  ];

  // 颁发者/中间 CA 组织名：绝不能当作站点 OV 的 organization
  const CA_ORG_NAME_RE = /^(?:sectigo\s+limited|comodo\s+ca|digicert\s+inc\.?|let'?s\s+encrypt|zerossl|google\s+trust\s+services|cloudflare,?\s*inc\.?|amazon|amazonaws|globalSign|globalsign\s+nv-sa|ssl\s+corporation|ssl\.com|godaddy|starfield|entrust|usertrust|the\s+usertrust\s+network|verisign|symantec|geotrust|thawte|actalis|certum|buypass|idenTrust|isrg|internet\s+security\s+research\s+group)$/i;
  // Subject CN 像 CA 中间证 / 根证
  const CA_CN_RE = /(?:\bCA\b|\bRoot\b|\bIssuing\b|Certificate\s+Authority|Trust\s+Services|Authentication\s+CA)/i;
  // OpenSSL/演示/占位 O=：绝非真实 OV 机构（winrar.com.cn noSNI 默认证常见）
  // 例：O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
  const BOGUS_PLACEHOLDER_ORG_RE = /^(?:internet\s+widgits\s+pty\.?\s*ltd\.?|default\s+company\s+ltd\.?|my\s+company\s+(?:name|ltd\.?|inc\.?)|example\s+(?:org|company|inc\.?)|test\s+(?:org|company|inc\.?)|asdf|xxxx+|your\s+company|company\s+name|organisation\s+name|organization\s+name)$/i;

  // 几乎只发 DV 的公共/CDN CA（无 DER 时也可报 DV）
  // 注意：勿把 GeoTrust TLS CN / TrustAsia 整家标成 free DV——
  //   yuanshen.com 叶子是 GeoTrust G2 TLS CN + O=上海米哈游天命科技有限公司（OV）。
  // 仅明确 DV 产品线：LiteSSL / Encryption Everywhere / RapidSSL / LE / Cloudflare 等
  const FREE_DV_ISSUER_RE = /let'?s\s*encrypt|zerossl|google\s*trust\s*services|gts\s*ca|cloudflare|ssl\s*corporation|ssl\.com|amazon|amazonaws|litessl|encryption\s*everywhere|cpanel|sectigo\s*rsa\s*domain|domain\s*validation|rapidssl|usertrust|comodo\s*domain|r3|r10|r11|r12|r13|e1|e5|e6|e7|e8|e9|yr1|yr2|ye[12]|we[12]/i;

  /** 缓存键：去 www.，便于 www/裸域共用缓存 */
  function hostKey(hostOrUrl) {
    try {
      if (/^https?:\/\//i.test(String(hostOrUrl || ""))) {
        return new URL(hostOrUrl).hostname.toLowerCase().replace(/^www\./, "");
      }
      return String(hostOrUrl || "").toLowerCase().replace(/^www\./, "").split("/")[0];
    } catch {
      return "";
    }
  }

  /** 探测用主机名：保留 www.，不剥掉 */
  function rawHostname(hostOrUrl) {
    try {
      let h = String(hostOrUrl || "").trim().toLowerCase();
      if (/^https?:\/\//i.test(h)) h = new URL(h).hostname.toLowerCase();
      else h = h.split("/")[0].split("?")[0];
      return h.replace(/\.$/, "").replace(/:\d+$/, "");
    } catch {
      return "";
    }
  }

  /**
   * 粗略 eTLD+1（与 content 侧一致），避免 press-wps.com.cn 被回退到公共后缀 com.cn。
   */
  function getSslRegistrableDomain(domain) {
    const d = String(domain || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    const parts = d.split(".").filter(Boolean);
    if (parts.length === 0) return "";
    if (parts.length <= 2) return d;
    const last = parts[parts.length - 1] || "";
    const second = parts[parts.length - 2] || "";
    // 中国多段后缀：com.cn / gov.cn / 省级 hl.cn 等
    if (last === "cn" && /^(?:ac|ah|bj|com|cq|edu|fj|gd|gov|gs|gx|gz|ha|hb|he|hi|hk|hl|hn|jl|js|jx|ln|mil|mo|net|nm|nx|org|qh|sc|sd|sh|sn|sx|tj|tw|xj|xz|yn|zj)$/i.test(second)) {
      return parts.slice(-3).join(".");
    }
    // co.uk / com.au 等
    if (parts.length >= 3 && last.length === 2 && /^(com|net|org|gov|edu|ac|co|or|ne|gob|gen|ltd|plc|me)$/i.test(second)) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  /**
   * 去掉最左标签得到上层域名。
   * 已到 eTLD+1（如 press-wps.com.cn）时返回空，绝不回退到 com.cn。
   */
  function parentDomainHost(host) {
    const h = String(host || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    if (!h) return "";
    const apex = getSslRegistrableDomain(h);
    if (!apex || h === apex) return "";
    // 仅当仍是 apex 的子域时才上剥一层
    if (!h.endsWith("." + apex) && h !== apex) return "";
    const parts = h.split(".").filter(Boolean);
    const apexParts = apex.split(".").filter(Boolean);
    if (parts.length <= apexParts.length) return "";
    return parts.slice(1).join(".");
  }

  /**
   * SSL 查询主机回退链（严格顺序，查不到才下一级）：
   * 1) 当前 host
   * 2) 上层域名（逐级上剥至 eTLD+1）
   * 不再查子域名 / www. 变体。
   *
   * 例：jyt.jiangsu.gov.cn
   *   → jyt.jiangsu.gov.cn
   *   → jiangsu.gov.cn
   * （止于 apex，不查 gov.cn）
   *
   * 例：www.digicert.com（raw 保留 www 时）
   *   → www.digicert.com
   *   → digicert.com
   */
  function buildSslFallbackHosts(hostRaw) {
    const start = rawHostname(hostRaw);
    if (!start || start === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(start)) return [];
    const apex = getSslRegistrableDomain(start);
    const out = [];
    const seen = new Set();
    const push = (h) => {
      const x = String(h || "").toLowerCase().replace(/\.$/, "");
      if (!x || !x.includes(".") || seen.has(x)) return;
      if (x === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(x)) return;
      if (x.split(".").filter(Boolean).length < 2) return;
      // 拒绝公共后缀本身（com.cn / gov.cn / co.uk）
      if (apex) {
        const apexRight = apex.includes(".") ? apex.split(".").slice(1).join(".") : "";
        if (apexRight && x === apexRight && x !== apex) return;
      }
      if (/^(?:com|net|org|gov|edu|ac)\.cn$/i.test(x) || /^(?:co|org|ac|gov)\.[a-z]{2}$/i.test(x)) return;
      // 必须仍落在同一可注册域下
      if (apex) {
        const bare = x.replace(/^www\./, "");
        if (bare !== apex && !bare.endsWith("." + apex) && x !== apex) return;
      }
      seen.add(x);
      out.push(x);
    };

    // 1) 当前 host（保留 www. 原样，不另查子域）
    push(start);

    // 2) 上层域名（仅上剥，不加 www.）
    let cur = start.replace(/^www\./, "");
    // 若当前带 www.，上一层先试去 www 的同级裸域（算上层/规范名，不是子域）
    if (start.startsWith("www.") && cur !== start) {
      push(cur);
    }
    for (let depth = 0; depth < 6; depth++) {
      const parent = parentDomainHost(cur);
      if (!parent || parent === cur) break;
      push(parent);
      cur = parent;
      if (apex && parent === apex) break;
    }
    return out;
  }

  function encodeOid(oid) {
    const parts = String(oid).split(".").map((x) => parseInt(x, 10));
    if (parts.length < 2) return new Uint8Array(0);
    const body = [];
    body.push(40 * parts[0] + parts[1]);
    for (let i = 2; i < parts.length; i++) {
      let v = parts[i];
      const stack = [v & 0x7f];
      v >>= 7;
      while (v > 0) {
        stack.push((v & 0x7f) | 0x80);
        v >>= 7;
      }
      for (let j = stack.length - 1; j >= 0; j--) body.push(stack[j]);
    }
    const out = new Uint8Array(2 + body.length);
    out[0] = 0x06;
    out[1] = body.length;
    out.set(body, 2);
    return out;
  }

  class DerReader {
    constructor(buf) {
      this.u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
      this.pos = 0;
    }
    remaining() { return this.u8.length - this.pos; }
    peekTag() { return this.remaining() > 0 ? this.u8[this.pos] : -1; }
    readTag() {
      if (this.pos >= this.u8.length) throw new Error("der-eof-tag");
      return this.u8[this.pos++];
    }
    readLength() {
      if (this.pos >= this.u8.length) throw new Error("der-eof-len");
      const b = this.u8[this.pos++];
      if (b < 0x80) return b;
      const n = b & 0x7f;
      if (n === 0 || n > 4) throw new Error("der-len");
      let len = 0;
      for (let i = 0; i < n; i++) {
        if (this.pos >= this.u8.length) throw new Error("der-eof-len2");
        len = (len << 8) | this.u8[this.pos++];
      }
      return len;
    }
    readTLV() {
      const tag = this.readTag();
      const len = this.readLength();
      if (this.pos + len > this.u8.length) throw new Error("der-overflow");
      const start = this.pos;
      this.pos += len;
      return { tag, len, value: this.u8.subarray(start, start + len) };
    }
    enterSequence() {
      const t = this.readTLV();
      if (t.tag !== 0x30) throw new Error("der-expect-seq");
      return new DerReader(t.value);
    }
    enterSet() {
      const t = this.readTLV();
      if (t.tag !== 0x31) throw new Error("der-expect-set");
      return new DerReader(t.value);
    }
    readOid() {
      const t = this.readTLV();
      if (t.tag !== 0x06) throw new Error("der-expect-oid");
      const v = t.value;
      if (!v.length) return "";
      const parts = [Math.floor(v[0] / 40), v[0] % 40];
      let acc = 0;
      for (let i = 1; i < v.length; i++) {
        acc = (acc << 7) | (v[i] & 0x7f);
        if ((v[i] & 0x80) === 0) {
          parts.push(acc);
          acc = 0;
        }
      }
      return parts.join(".");
    }
    readString() {
      const t = this.readTLV();
      // DirectoryString / 常见字符串标签
      if (t.tag === 0x1e) {
        try { return new TextDecoder("utf-16be").decode(t.value); } catch { return ""; }
      }
      try { return new TextDecoder("utf-8").decode(t.value); } catch {
        let s = "";
        for (let i = 0; i < t.value.length; i++) s += String.fromCharCode(t.value[i]);
        return s;
      }
    }
    skip() { this.readTLV(); }
  }

  function parseNameAttrs(nameReader) {
    const attrs = {};
    while (nameReader.remaining() > 0) {
      try {
        // RDN 通常是 SET，偶发为 SEQUENCE
        const tag = nameReader.peekTag();
        const rdn = tag === 0x31 ? nameReader.enterSet()
          : tag === 0x30 ? nameReader.enterSequence()
          : null;
        if (!rdn) {
          nameReader.skip();
          continue;
        }
        while (rdn.remaining() > 0) {
          try {
            const atav = rdn.enterSequence();
            const oid = atav.readOid();
            const val = atav.readString().trim();
            if (oid && val && !attrs[oid]) attrs[oid] = val;
          } catch {
            break;
          }
        }
      } catch {
        break;
      }
    }
    return attrs;
  }

  /**
   * 全量扫描 DER：在 OID 编码后读取相邻字符串（结构化解析失败时的兜底）。
   * 只取「第一次出现」——通常在 subject，而非 extensions 里的重复。
   */
  function scanOidString(der, oidDot) {
    const needle = encodeOid(oidDot);
    if (!needle.length || der.length < needle.length + 4) return "";
    outer:
    for (let i = 0; i <= der.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (der[i + j] !== needle[j]) continue outer;
      }
      // 下一个 TLV 为字符串
      let p = i + needle.length;
      if (p >= der.length) continue;
      const tag = der[p++];
      // 跳过非字符串（偶发 BOOLEAN critical 等不应跟在 Name OID 后）
      if (![0x0c, 0x13, 0x14, 0x16, 0x1e, 0x12, 0x1c].includes(tag)) continue;
      if (p >= der.length) continue;
      let len = der[p++];
      if (len & 0x80) {
        const n = len & 0x7f;
        if (n < 1 || n > 2 || p + n > der.length) continue;
        len = 0;
        for (let k = 0; k < n; k++) len = (len << 8) | der[p++];
      }
      if (len < 1 || len > 256 || p + len > der.length) continue;
      const slice = der.subarray(p, p + len);
      try {
        if (tag === 0x1e) return new TextDecoder("utf-16be").decode(slice).trim();
        return new TextDecoder("utf-8").decode(slice).trim();
      } catch {
        let s = "";
        for (let k = 0; k < slice.length; k++) s += String.fromCharCode(slice[k]);
        return s.trim();
      }
    }
    return "";
  }

  function scanHasOid(der, oidDot) {
    const needle = encodeOid(oidDot);
    if (!needle.length) return false;
    outer:
    for (let i = 0; i <= der.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (der[i + j] !== needle[j]) continue outer;
      }
      return true;
    }
    return false;
  }

  /**
   * 识别 certificatePolicies 中的策略 OID → EV / OV / DV。
   * 只认策略扩展里的 OID，绝不看 Issuer CN 里的 “EV CA / OV CA”。
   */
  function classifyPolicyOid(pOid) {
    const p = String(pOid || "").trim();
    if (!p) return null;
    // 顺序关键：先匹配更长的 2.23.140.1.2.x，再匹配 2.23.140.1.1
    // （避免将来误用 startsWith("2.23.140.1.2") 把 OV/DV 吃成别的）
    if (p === OID_CABF_OV || p.startsWith(OID_CABF_OV + ".")) return "OV";
    if (p === OID_CABF_DV || p.startsWith(OID_CABF_DV + ".")) return "DV";
    if (p === OID_CABF_IV || p.startsWith(OID_CABF_IV + ".")) return "DV";
    // EV：CABF 2.23.140.1.1（不是 2.23.140.1.2*）
    if (p === OID_CABF_EV || p.startsWith(OID_CABF_EV + ".")) return "EV";
    // 厂商 EV OID
    for (let i = 0; i < VENDOR_EV_POLICY_OIDS.length; i++) {
      const v = VENDOR_EV_POLICY_OIDS[i];
      if (p === v || p.startsWith(v + ".")) return "EV";
    }
    return null;
  }

  function parseLeafCertificate(rawDer) {
    const root = new DerReader(rawDer);
    const cert = root.enterSequence();
    const tbs = cert.enterSequence();
    if (tbs.peekTag() === 0xa0) tbs.skip();
    tbs.skip(); // serial
    tbs.skip(); // signature alg
    tbs.skip(); // issuer —— 不读取、不扫 O=
    tbs.skip(); // validity
    const subjectSeq = tbs.readTLV();
    if (subjectSeq.tag !== 0x30) throw new Error("der-subject");
    // 仅 Subject 字节可兜底扫 OID，杜绝扫到 Issuer
    const subjectBytes = subjectSeq.value;
    const subjectAttrs = parseNameAttrs(new DerReader(subjectBytes));
    if (tbs.remaining() > 0) tbs.skip(); // SPKI

    let hasEvPolicy = false;
    let hasOvPolicy = false;
    let hasDvPolicy = false;
    const policies = [];
    while (tbs.remaining() > 0) {
      if (tbs.peekTag() !== 0xa3) {
        try { tbs.skip(); } catch { break; }
        continue;
      }
      try {
        const extWrap = tbs.readTLV();
        const extSeq = new DerReader(extWrap.value).enterSequence();
        while (extSeq.remaining() > 0) {
          try {
            const one = extSeq.enterSequence();
            const oid = one.readOid();
            if (one.peekTag() === 0x01) one.skip();
            const oct = one.readTLV();
            // certificatePolicies
            if (oid === "2.5.29.32" && oct.tag === 0x04) {
              try {
                const pol = new DerReader(oct.value).enterSequence();
                while (pol.remaining() > 0) {
                  const pi = pol.enterSequence();
                  const pOid = pi.readOid();
                  policies.push(pOid);
                  const kind = classifyPolicyOid(pOid);
                  if (kind === "EV") hasEvPolicy = true;
                  else if (kind === "OV") hasOvPolicy = true;
                  else if (kind === "DV") hasDvPolicy = true;
                  while (pi.remaining() > 0) pi.skip();
                }
              } catch { /* ignore */ }
            }
          } catch { break; }
        }
      } catch { break; }
    }
    return {
      subjectAttrs,
      subjectBytes,
      rawDer: rawDer instanceof Uint8Array ? rawDer : new Uint8Array(rawDer),
      policies,
      hasEvPolicy,
      hasOvPolicy,
      hasDvPolicy
    };
  }

  function isCaLikeOrganization(org) {
    const o = String(org || "").trim();
    if (!o) return false;
    if (CA_ORG_NAME_RE.test(o)) return true;
    // “Sectigo Limited” / “DigiCert Inc” 等常见形态
    if (/\b(?:limited|inc\.?|llc|l\.?l\.?c\.?|corp\.?|corporation|gmbh|s\.?a\.?|b\.?v\.?)\b/i.test(o)
      && /(?:sectigo|digicert|comodo|globalsign|godaddy|entrust|verisign|symantec|geotrust|thawte|cloudflare|amazon|sslmate|lets?\s*encrypt)/i.test(o)) {
      return true;
    }
    return false;
  }

  /** OpenSSL 默认 / 演示占位组织名 → 不能当 OV */
  function isBogusPlaceholderOrg(org) {
    const o = String(org || "").trim();
    if (!o) return false;
    if (BOGUS_PLACEHOLDER_ORG_RE.test(o)) return true;
    if (/widgits/i.test(o)) return true;
    if (/^some[-\s]?state$/i.test(o)) return true;
    return false;
  }

  /**
   * 清理假 O=：占位名、CA 机构名（在 DV 链上误扫到 Issuer O= 时）。
   * 返回可用于定级的组织名；空串表示按 DV 处理。
   */
  function sanitizeLeafOrganization(org, issuerName) {
    let o = String(org || "").trim();
    if (!o) return "";
    if (isBogusPlaceholderOrg(o)) return "";
    if (isCaLikeOrganization(o)) return "";
    // 免费 DV 中间 CA 签发的叶子：有 O= 也极可能是误解析，不认 OV
    // （ZeroSSL/LE 合法叶子不应带 Subject.O；有则多半是扫到了错误节点）
    if (isLikelyFreeDvIssuer(issuerName) && !/\bOV\b|\bEV\b|organization/i.test(String(issuerName || ""))) {
      return "";
    }
    return o;
  }

  /**
   * 是否像中间/根证 Subject。
   * 只看 CN（如 “DigiCert EV RSA CA G2”），绝不可因 O=DigiCert, Inc. 就拒绝——
   * digicert.com 官网叶子的 O 正是 DigiCert，误拒后只剩 meta DV。
   */
  function isCaLikeSubject(cn, org) {
    const c = String(cn || "").trim();
    if (!c) return false;
    // 域名形态的 CN 一定是站点叶子
    if (nameLooksLikeHostname(c)) return false;
    if (CA_CN_RE.test(c)) return true;
    return false;
  }

  /** 在 DER 中查找固定字节序列 */
  function scanRawBytes(der, bytes) {
    if (!der || !bytes || !bytes.length || der.length < bytes.length) return false;
    outer:
    for (let i = 0; i <= der.length - bytes.length; i++) {
      for (let j = 0; j < bytes.length; j++) {
        if (der[i + j] !== bytes[j]) continue outer;
      }
      return true;
    }
    return false;
  }

  /**
   * 结构化解析 certificatePolicies 失败时：在叶子 DER 内扫描已知策略 OID。
   * digicert.com 等站常因扩展解析中断导致 hasEvPolicy=false，从而误成 OV。
   * 同时用硬编码 OID 字节兜底，避免 encodeOid 与真实编码不一致。
   */
  function reinforcePolicyFlagsFromDer(rawDer, flags) {
    const out = {
      hasEvPolicy: !!(flags && flags.hasEvPolicy),
      hasOvPolicy: !!(flags && flags.hasOvPolicy),
      hasDvPolicy: !!(flags && flags.hasDvPolicy)
    };
    if (!rawDer || !rawDer.length) return out;
    try {
      // CABF EV 2.23.140.1.1 → 06 05 67 81 0c 01 01（硬编码，最稳）
      const CABF_EV_DER = [0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01];
      // DigiCert EV 2.16.840.1.114412.2.1 → 06 09 60 86 48 01 86 fe 6c 02 01
      const DIGI_EV_DER = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xfe, 0x6c, 0x02, 0x01];
      // CABF OV 2.23.140.1.2.2 → 06 06 67 81 0c 01 02 02
      const CABF_OV_DER = [0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x02];
      // CABF DV 2.23.140.1.2.1 → 06 06 67 81 0c 01 02 01
      const CABF_DV_DER = [0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01];

      if (!out.hasEvPolicy) {
        if (scanRawBytes(rawDer, CABF_EV_DER) || scanRawBytes(rawDer, DIGI_EV_DER)
          || scanHasOid(rawDer, OID_CABF_EV)) {
          out.hasEvPolicy = true;
        }
        if (!out.hasEvPolicy) {
          for (let i = 0; i < VENDOR_EV_POLICY_OIDS.length; i++) {
            if (scanHasOid(rawDer, VENDOR_EV_POLICY_OIDS[i])) {
              out.hasEvPolicy = true;
              break;
            }
          }
        }
      }
      if (!out.hasOvPolicy && (scanRawBytes(rawDer, CABF_OV_DER) || scanHasOid(rawDer, OID_CABF_OV))) {
        out.hasOvPolicy = true;
      }
      if (!out.hasDvPolicy && (scanRawBytes(rawDer, CABF_DV_DER) || scanHasOid(rawDer, OID_CABF_DV))) {
        out.hasDvPolicy = true;
      }
      // 同证扫到 EV 则盖过 OV/DV 策略位
      if (out.hasEvPolicy) {
        out.hasOvPolicy = false;
        out.hasDvPolicy = false;
      }
    } catch { /* ignore */ }
    return out;
  }

  /**
   * 仅用叶子 Subject（使用者）+ certificatePolicies 分类。
   * subjectBytesOpt 只允许扫 Subject 区补 O/CN/业务类别；策略可对整段叶子 DER 扫 OID。
   *
   * 决策树：
   *   1) 中间/根证 → 丢弃
   *   2) EV 策略 OID → EV
   *   3) O + businessCategory + jurisdiction（或登记号）→ EV
   *   4) OV 策略 或 仅有 O= → OV
   *   5) 否则 → DV
   */
  function classifyValidation(parsed, subjectBytesOpt, rawDerOpt) {
    const a = Object.assign({}, (parsed && parsed.subjectAttrs) || {});
    const subBytes = subjectBytesOpt
      || (parsed && parsed.subjectBytes)
      || null;
    const rawDer = rawDerOpt
      || (parsed && parsed.rawDer)
      || null;

    // 策略先扫（决定是否保留 DigiCert 等厂商 O=）
    let hasEvPolicy = !!(parsed && parsed.hasEvPolicy);
    let hasOvPolicy = !!(parsed && parsed.hasOvPolicy);
    let hasDvPolicy = !!(parsed && parsed.hasDvPolicy);
    if (rawDer && rawDer.length) {
      const rein = reinforcePolicyFlagsFromDer(rawDer, {
        hasEvPolicy,
        hasOvPolicy,
        hasDvPolicy
      });
      hasEvPolicy = rein.hasEvPolicy;
      hasOvPolicy = rein.hasOvPolicy;
      hasDvPolicy = rein.hasDvPolicy;
    }

    // 仅在 Subject 区补字段
    if (subBytes && subBytes.length) {
      if (!a[OID_O]) {
        const o = scanOidString(subBytes, OID_O);
        if (o) a[OID_O] = o;
      }
      if (!a[OID_CN]) {
        const cn0 = scanOidString(subBytes, OID_CN);
        if (cn0) a[OID_CN] = cn0;
      }
      if (!a[OID_BUSINESS_CAT]) {
        const bc = scanOidString(subBytes, OID_BUSINESS_CAT);
        if (bc) a[OID_BUSINESS_CAT] = bc;
      }
      if (!a[OID_SERIAL]) {
        const sn = scanOidString(subBytes, OID_SERIAL);
        if (sn) a[OID_SERIAL] = sn;
      }
      if (!a[OID_JURIS_C] && scanHasOid(subBytes, OID_JURIS_C)) {
        a[OID_JURIS_C] = scanOidString(subBytes, OID_JURIS_C) || "Y";
      }
      if (!a[OID_JURIS_ST] && scanHasOid(subBytes, OID_JURIS_ST)) {
        a[OID_JURIS_ST] = scanOidString(subBytes, OID_JURIS_ST) || "Y";
      }
      if (!a[OID_JURIS_L] && scanHasOid(subBytes, OID_JURIS_L)) {
        a[OID_JURIS_L] = scanOidString(subBytes, OID_JURIS_L) || "Y";
      }
    }

    let org = String(a[OID_O] || "").trim();
    let cn = String(a[OID_CN] || "").trim();
    const issuerHint = String((parsed && parsed.issuer) || "").trim();

    // 仅拒绝「CN 明确是中间 CA 名」的证；O=DigiCert 的官网叶子必须放行
    if (isCaLikeSubject(cn, org)) {
      return {
        validation: "DV",
        organization: "",
        commonName: cn,
        subjectAttrs: a,
        rejected: "ca-subject"
      };
    }

    // 无 CN 的 OpenSSL 默认证（仅 O=Internet Widgits）→ 丢弃
    if (!cn && isBogusPlaceholderOrg(org)) {
      return {
        validation: "DV",
        organization: "",
        commonName: "",
        subjectAttrs: a,
        rejected: "openssl-default"
      };
    }

    const hasJuris = !!(a[OID_JURIS_C] || a[OID_JURIS_ST] || a[OID_JURIS_L]);
    const hasBiz = !!a[OID_BUSINESS_CAT];
    const hasSerial = !!a[OID_SERIAL];

    // 厂商名 O=：仅当既无域名 CN、又无 EV/业务字段时才丢（避免链上节点）
    // digicert.com 叶子：O=DigiCert, Inc. + CN=www.digicert.com / EV 策略 → 必须保留并展示
    if (org && isCaLikeOrganization(org)
      && !nameLooksLikeHostname(cn)
      && !hasEvPolicy
      && !hasBiz
      && !hasSerial) {
      org = "";
    }
    // 占位 O= / 免费 DV 链上的假 O= → 清空
    if (org && (isBogusPlaceholderOrg(org)
      || (isLikelyFreeDvIssuer(issuerHint) && !hasOvPolicy && !hasEvPolicy && !hasBiz))) {
      org = "";
    }
    // 域名形态 CN 的站点叶子：即使 O= 像 CA 公司名也保留（官网自签品牌 OV/EV）
    // 已由上方条件保证；此处不再清空

    // EV Subject：O + 业务类别 +（管辖地 或 登记号）
    const evSubjectShape = !!(org && hasBiz && (hasJuris || hasSerial));

    // 明确 DV 策略 OID → 压成 DV（即使误带 O=）
    let validation = "DV";
    if (hasEvPolicy) {
      validation = "EV";
    } else if (evSubjectShape) {
      validation = "EV";
    } else if (hasDvPolicy && !hasOvPolicy && !org) {
      validation = "DV";
    } else if (hasOvPolicy || org) {
      validation = "OV";
    } else {
      validation = "DV";
    }

    // EV/OV 展示组织名；DV 不展示
    const showOrg = validation === "DV" ? "" : org;

    return {
      validation,
      organization: showOrg,
      commonName: cn,
      subjectAttrs: a,
      _flags: {
        hasEvPolicy,
        hasOvPolicy,
        hasBiz,
        hasJuris,
        hasSerial,
        evSubjectShape
      }
    };
  }

  function nameLooksLikeHostname(cn) {
    const s = String(cn || "").toLowerCase().trim();
    if (!s) return false;
    if (s.startsWith("*.")) return true;
    return /^[a-z0-9._-]+\.[a-z]{2,}$/i.test(s);
  }

  function pemToDer(pem) {
    const text = String(pem || "");
    const m = text.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/i);
    if (!m) return null;
    const b64 = m[1].replace(/\s+/g, "");
    try {
      const bin = atob(b64);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      return u8;
    } catch {
      return null;
    }
  }

  function parsePemCert(pem) {
    const der = pemToDer(pem);
    if (!der || der.length < 32) return null;
    let structured = null;
    try {
      structured = parseLeafCertificate(der);
    } catch {
      structured = {
        subjectAttrs: {},
        subjectBytes: null,
        rawDer: der,
        policies: [],
        hasEvPolicy: false,
        hasOvPolicy: false,
        hasDvPolicy: false
      };
    }
    if (structured && !structured.rawDer) structured.rawDer = der;
    const classified = classifyValidation(structured, structured.subjectBytes || null, der);
    if (classified.rejected) return null;
    // 必须至少有 Subject CN（站点身份）；禁止用整段 PEM 的 O=（会命中 Issuer）
    if (!classified.commonName && !classified.organization) return null;
    return classified;
  }

  async function fetchText(url, timeoutMs) {
    await ensureSslPersistentStateLoaded();
    const provider = sslProviderForUrl(url);
    if (providerCoolingDown(provider)) {
      return { ok: false, status: 429, text: "", rateLimited: true, cooldown: true };
    }
    const ms = timeoutMs || 10000;
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => { try { controller.abort(); } catch { /* ignore */ } }, ms) : null;
    // 勿设 User-Agent：扩展里属于 forbidden header，部分环境会导致 fetch 直接失败
    return fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      signal: controller ? controller.signal : undefined,
      headers: { Accept: "application/json,text/html,text/plain,*/*" }
    }).then(async (r) => {
      if (timer) clearTimeout(timer);
      const text = await r.text();
      if (r.status === 429) {
        noteProviderRateLimited(provider, r.headers && r.headers.get("retry-after"));
      }
      return { ok: r.ok, status: r.status, text, rateLimited: r.status === 429 };
    }).catch((e) => {
      if (timer) clearTimeout(timer);
      return { ok: false, status: 0, text: "", error: e && e.message ? e.message : "fetch-failed" };
    });
  }

  /** 拉证书字节：crt.sh/?d= 现返回 application/pkix-cert（DER），偶发 PEM */
  async function fetchBytes(url, timeoutMs) {
    await ensureSslPersistentStateLoaded();
    const provider = sslProviderForUrl(url);
    if (providerCoolingDown(provider)) {
      return {
        ok: false,
        status: 429,
        buf: new Uint8Array(0),
        contentType: "",
        rateLimited: true,
        cooldown: true
      };
    }
    const ms = timeoutMs || 10000;
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => { try { controller.abort(); } catch { /* ignore */ } }, ms) : null;
    return fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      signal: controller ? controller.signal : undefined,
      headers: {
        Accept: "application/pkix-cert,application/x-x509-ca-cert,application/pem-certificate-chain,text/plain,*/*"
      }
    }).then(async (r) => {
      if (timer) clearTimeout(timer);
      const buf = new Uint8Array(await r.arrayBuffer());
      if (r.status === 429) {
        noteProviderRateLimited(provider, r.headers && r.headers.get("retry-after"));
      }
      return {
        ok: r.ok,
        status: r.status,
        buf,
        contentType: String(r.headers.get("content-type") || ""),
        rateLimited: r.status === 429
      };
    }).catch((e) => {
      if (timer) clearTimeout(timer);
      return {
        ok: false,
        status: 0,
        buf: new Uint8Array(0),
        contentType: "",
        error: e && e.message ? e.message : "fetch-failed"
      };
    });
  }

  function classifyFromCrtDownload(buf) {
    if (!buf || buf.length < 32) return null;
    // PEM 文本
    try {
      const text = new TextDecoder("utf-8").decode(buf);
      if (/BEGIN CERTIFICATE/i.test(text)) return parsePemCert(text);
    } catch { /* ignore */ }
    // DER 二进制（crt.sh 当前默认）
    if (buf[0] === 0x30) return classifyFromDerBytes(buf);
    return null;
  }

  /**
   * 证书名/SAN 是否覆盖「查询主机」（TLS 语义，方向不可反）。
   * 允许：exact、www↔裸域、通配 *.base 覆盖 base / a.base。
   * 禁止：子域证盖父域/兄弟域（曾把 todesk-log-upload 的 LE DV 当成 www.todesk.com）。
   */
  function nameMatchesHost(nameValue, host) {
    const hRaw = String(host || "").toLowerCase().replace(/\.$/, "");
    const h = hRaw.replace(/^www\./, "");
    const lines = String(nameValue || "").toLowerCase().split(/[\n,\s]+/).map((s) => s.trim()).filter(Boolean);
    if (!lines.length || !h) return false;
    return lines.some((n) => {
      if (!n) return false;
      // 通配：*.todesk.com → todesk.com / www.todesk.com / a.todesk.com
      //        *.www.gov.cn → www.gov.cn（hRaw）；不覆盖 gov.cn 公共后缀本身
      if (n.startsWith("*.")) {
        const base = n.slice(2);
        if (!base) return false;
        const coversOneLabel = (target) => {
          if (target === base) return true;
          if (!target.endsWith("." + base)) return false;
          const prefix = target.slice(0, -(base.length + 1));
          return !!prefix && !prefix.includes(".");
        };
        return coversOneLabel(hRaw) || coversOneLabel(h);
      }
      const nBare = n.replace(/^www\./, "");
      // exact / www 与裸域互通（产品展示层约定）
      if (n === hRaw || n === h || nBare === h || n === `www.${h}` || nBare === hRaw) return true;
      return false;
    });
  }

  /** 叶子 CN/SAN 是否覆盖查询主机（必须真覆盖，禁止任意 hostname 形状蒙混） */
  function leafMatchesQueryHost(cn, altNames, queryHost) {
    const q = String(queryHost || "").toLowerCase();
    if (!q) return false;
    if (subjectMatchesHost(cn, q) || nameMatchesHost(cn || "", q)) return true;
    if (altNames && nameMatchesHost(altNames, q)) return true;
    return false;
  }

  /**
   * OV 等级可以独立展示；Subject.O 需要满足以下任一条件：
   * 1) 已绑定非 noSNI 叶链；2) 实时 TLS 叶证书；3) 完整 CT 证书未过期且 CN/SAN 覆盖当前 host。
   * 只有 issuer/列表元数据、已过期证书以及 noSNI 默认证都不能提供组织身份。
   */
  function isLiveBoundOv(info) {
    if (!info) return false;
    return String(info.validation || "").toUpperCase() === "OV"
      && (info.sniChainVerified === true || info.liveTlsLeafVerified === true
        || info.unexpiredHostVerified === true);
  }

  function sanitizeOvForDisplay(info) {
    if (!info || String(info.validation || "").toUpperCase() !== "OV") return info;
    if (isLiveBoundOv(info)) return info;
    return {
      ...info,
      organization: "",
      sniChainVerified: false
    };
  }

  /** 只按 CN/SAN 与查询主机的结构关系拒绝错证，不维护 CDN 厂商关键词表。 */
  function isInvalidLeafForHost(cn, altNames, queryHost) {
    if (!String(cn || "").trim() && !String(altNames || "").trim()) return true;
    return !leafMatchesQueryHost(cn, altNames, queryHost);
  }

  /**
   * CT 列表元数据 → 至少 DV。
   * Cert Spotter / crt.sh 的 domain issuances 基本是叶子证；SAN/CN 命中即可展示。
   * 无 DER 时无法证明 OV/EV，一律 DV（有 DER 再升级）。
   * requireKnownDvCa=false：任意匹配发行都给 DV（覆盖 TrustAsia 等未枚举 CA）
   */
  function ctLeafMetaHit(host, dnsNames, issuerName, commonName, notBefore, opts) {
    const requireKnown = !!(opts && opts.requireKnownDvCa);
    if (requireKnown && !isLikelyFreeDvIssuer(issuerName)) return null;
    const names = [dnsNames, commonName].filter(Boolean).join("\n");
    if (names) {
      if (!nameMatchesHost(names, host) && !subjectMatchesHost(commonName, host)) return null;
    } else if (!subjectMatchesHost(commonName, host)) {
      return null;
    }
    const cn = String(commonName || "").trim();
    return {
      validation: "DV",
      organization: "",
      commonName: cn || host,
      source: "ct-meta",
      issuer: String(issuerName || ""),
      notBefore: Number(notBefore) || 0
    };
  }

  /** @deprecated 兼容旧调用名 */
  function freeDvHitFromMeta(host, dnsNames, issuerName, commonName, notBefore) {
    return ctLeafMetaHit(host, dnsNames, issuerName, commonName, notBefore, { requireKnownDvCa: false });
  }

  function parseCrtDate(s) {
    const raw = String(s || "").trim();
    if (!raw) return NaN;
    // "2025-12-18T00:00:00" / "2025-12-18 00:00:00"
    let t = Date.parse(raw);
    if (!Number.isNaN(t)) return t;
    t = Date.parse(raw.replace(" ", "T") + "Z");
    if (!Number.isNaN(t)) return t;
    t = Date.parse(raw.replace(" ", "T"));
    return t;
  }

  function validationRank(v) {
    if (v === "EV") return 3;
    if (v === "OV") return 2;
    if (v === "DV") return 1;
    return 0;
  }

  function isLikelyFreeDvIssuer(issuerName) {
    return FREE_DV_ISSUER_RE.test(String(issuerName || ""));
  }

  /**
   * 颁发者产品线是否暗示组织验证（仅用于：优先下 DER / 禁止 DV 软截止）。
   * 最终 OV/EV 仍只认叶子 Subject/策略 OID，绝不把 Issuer 名当成站点组织。
   *
   * 注意：CFCA OV OCA / WoTrus OV Server CA 等国密/国内部署链名字含 OCA 而非独立词 CA，
   * 旧版 `\bCA\b` 匹配不到，导致 jyt.jiangsu.gov.cn 等站 CFCA 叶子不被优先下 DER。
   */
  function issuerSuggestsOrgValidation(issuerName) {
    const s = String(issuerName || "");
    if (!s) return null;
    // 产品线关键词：CA / OCA（CFCA）/ RSA|ECC|TLS|SSL
    const caProduct = /(?:\bCA\b|\bOCA\b|RSA|ECC|TLS|SSL|Server\s*CA|Issuing)/i.test(s);
    // 明确 EV 中间 CA（如 DigiCert EV RSA CA G2 / WoTrus EV Server CA）
    if (/\bEV\b/i.test(s) && caProduct) return "EV";
    if (/extended\s*validation/i.test(s)) return "EV";
    // 明确 OV 中间 CA（含 CFCA OV OCA、sslTrus OV CA、vTrus OV SSL CA）
    if (/\bOV\b/i.test(s) && caProduct) return "OV";
    if (/organization(?:al)?\s*validation/i.test(s)) return "OV";
    // 国产/区域 OV 产品名（issuer 未写 “OV” 字样时仍按需下 DER）
    if (/\b(?:cfca|wotrus|vtrus|ssltrus|itrus|xcc\s*trust|gdca|sheca|bjca)\b/i.test(s)
      && !/\bDV\b|domain\s*validation|domain\s*secure/i.test(s)) {
      return "MAYBE";
    }
    // 商业 CA（含 GeoTrust TLS CN / DigiCert G5）：必须下叶子 DER 定级，禁止当 free DV 软截止
    if (/digicert|sectigo|comodo|globalsign|geotrust|thawte|entrust|godaddy|starfield|certum|actalis|buypass|quovadis|swisssign|twca|chunghwa|trustasia|china\s*financial\s*certification/i.test(s)
      && !isLikelyFreeDvIssuer(s)) {
      return "MAYBE";
    }
    return null;
  }

  /** 元数据 DV 是否允许软截止（仅明确免费 DV CA；禁止空 issuer / 商业 CA 抢先锁 DV） */
  function canSoftFinishDv(hit) {
    if (!hit || hit.validation !== "DV") return false;
    if (hit.source === "https-assumed") return false; // 假定 DV 不当「快路径」
    if (!hit.issuer) return false;
    if (issuerSuggestsOrgValidation(hit.issuer)) return false;
    if (issuerIsEvProductCa(hit.issuer)) return false;
    return isLikelyFreeDvIssuer(hit.issuer);
  }

  /**
   * 择优：同一 host 下未过期叶子中，**验证等级优先**（EV>OV>DV）。
   * 同级再比：叶子真覆盖目标 host > 可用组织名 > 较新 notBefore。
   * 未绑定 SNI 叶链的 OV 组织名不参与择优。
   */
  function betterResult(a, b) {
    if (!a) return b;
    if (!b) return a;
    const ra = validationRank(a.validation);
    const rb = validationRank(b.validation);
    // 核心：等级优先
    if (rb !== ra) return rb > ra ? b : a;
    // 同级：真覆盖目标 host 优先
    if (!!a.leafOk !== !!b.leafOk) return a.leafOk ? a : b;
    // 同为 OV：与非 noSNI 叶链精确对应的证书优先
    if (ra === 2 && isLiveBoundOv(a) !== isLiveBoundOv(b)) {
      return isLiveBoundOv(b) ? b : a;
    }
    // 同级：有可用组织名更好
    const orgScore = (r) => {
      const o = String(r.organization || "").trim();
      if (!o) return 0;
      if (isBogusPlaceholderOrg(o)) return 0;
      if (String(r.validation || "").toUpperCase() === "OV" && !isLiveBoundOv(r)) return 0;
      // 免费 DV 签发却标 OV+org → 脏结果
      if (isLikelyFreeDvIssuer(r.issuer) && validationRank(r.validation) >= 2) return 0;
      return 1;
    };
    const oa = orgScore(a);
    const ob = orgScore(b);
    if (ob !== oa) return ob > oa ? b : a;
    const ta = Number(a.notBefore) || 0;
    const tb = Number(b.notBefore) || 0;
    if (tb !== ta) return tb > ta ? b : a;
    const rich = (s) => /^(?:ssllabs|ssllabs\+crt\.sh|shodan-ct|networkcalc|myssl|edgeone)$/i.test(String(s || ""));
    if (rich(a.source) && !rich(b.source)) return a;
    if (rich(b.source) && !rich(a.source)) return b;
    return a;
  }

  function parseDnString(dn) {
    const attrs = {};
    const s = String(dn || "").replace(/^subject\s*[:=]\s*/i, "").trim();
    if (!s) return attrs;
    // /C=US/O=Org Name/CN=www.example.com  或  C=US, O=Org, CN=www
    const parts = s.split(/\/(?=[A-Za-z][A-Za-z0-9.]*\s*=)/).join("\n")
      .split(/,(?=\s*[A-Za-z][A-Za-z0-9.]*\s*=)/);
    for (let part of parts) {
      part = part.replace(/^\//, "").trim();
      const m = part.match(/^([A-Za-z][A-Za-z0-9.]*)\s*=\s*(.+)$/);
      if (!m) continue;
      const k = m[1].toUpperCase();
      const v = m[2].trim().replace(/^"|"$/g, "");
      if (k && v && !attrs[k]) attrs[k] = v;
    }
    return attrs;
  }

  /** 中间 CA 产品名是否为 EV 签发链（如 DigiCert EV RSA CA G2）——仅辅助叶子定级 */
  function issuerIsEvProductCa(issuerName) {
    const s = String(issuerName || "");
    if (!s) return false;
    // 必须像 CA 产品名，且带 EV 字样（不是站点 O= 里的公司名）
    if (!/\bEV\b/i.test(s)) return false;
    return /(?:\bCA\b|RSA|ECC|TLS|SSL|Issuing)/i.test(s);
  }

  /**
   * 仅解析 subject DN 字符串。
   * issuerDn 一般不参与定级；但当 issuer 为「EV 产品 CA」且叶子有组织名+域名 CN 时，
   * 可标 EV（SSL Labs 常只给 O=/CN=，导致 digicert 被误成 OV）。
   */
  function classifyFromSubjectDn(subjectDn, issuerDn) {
    const a = parseDnString(subjectDn);
    let org = String(a.O || a.ORGANIZATIONNAME || a.ORGANIZATION || "").trim();
    const cn = String(a.CN || a.COMMONNAME || "").trim();
    // 仅丢弃 CN 明确是中间 CA 的节点
    if (isCaLikeSubject(cn, org)) {
      return null;
    }
    // OpenSSL 默认证：无 CN + 占位 O=
    if (!cn && isBogusPlaceholderOrg(org)) return null;
    const issuer = String(issuerDn || "");
    org = sanitizeLeafOrganization(org, issuer);
    // 官网叶子 O=DigiCert + CN=域名 → 保留；不要剥 O（sanitize 会剥 CA 名，域名 CN 时 digicert 官网再补）
    if (!org) {
      const rawOrg = String(a.O || a.ORGANIZATIONNAME || a.ORGANIZATION || "").trim();
      if (rawOrg && nameLooksLikeHostname(cn) && isCaLikeOrganization(rawOrg)
        && !isBogusPlaceholderOrg(rawOrg) && !isLikelyFreeDvIssuer(issuer)) {
        org = rawOrg;
      }
    }
    const hasJuris = !!(a.JURISDICTIONCOUNTRYNAME || a.JURISDICTIONSTATEORPROVINCENAME
      || a.JURISDICTIONLOCALITYNAME
      || a["1.3.6.1.4.1.311.60.2.1.3"] || a["1.3.6.1.4.1.311.60.2.1.2"]
      || a["1.3.6.1.4.1.311.60.2.1.1"]);
    const hasBiz = !!(a.BUSINESSCATEGORY || a["2.5.4.15"]);
    const hasSerial = !!(a.SERIALNUMBER || a["2.5.4.5"]);
    let validation = "DV";
    if (org && hasBiz && (hasJuris || hasSerial)) {
      validation = "EV";
    } else if (issuerIsEvProductCa(issuer) && (org || nameLooksLikeHostname(cn))) {
      validation = "EV";
    } else if (org) {
      validation = "OV";
    }
    // 明确免费 DV 中间 CA：压 DV（ZeroSSL / LE）
    if (isLikelyFreeDvIssuer(issuer) && !issuerIsEvProductCa(issuer)
      && !/\bOV\b/i.test(issuer)) {
      validation = "DV";
      org = "";
    }
    return {
      validation,
      organization: validation === "DV" ? "" : org,
      commonName: cn,
      issuer
    };
  }

  /** 站点叶子：Subject/CN 应对得上目标 host，排除中间 CA */
  function subjectMatchesHost(cn, host) {
    const hRaw = String(host || "").toLowerCase().replace(/\.$/, "");
    const h = hRaw.replace(/^www\./, "");
    const c = String(cn || "").toLowerCase().trim();
    if (!h || !c) return false;
    if (isCaLikeSubject(c, "")) return false;
    if (c === h || c === hRaw || c === `www.${h}`) return true;
    // *.www.gov.cn 覆盖 www.gov.cn（hRaw）；*.12306.cn 覆盖 www.12306.cn（h）
    if (c.startsWith("*.") && nameMatchesHost(c, hRaw)) return true;
    // SAN 列表可能塞在 cn 字段外，此处只做宽松 host 子串
    if (nameMatchesHost(c, hRaw) || nameMatchesHost(c, h)) return true;
    return false;
  }

  function base64ToDer(b64) {
    try {
      let s = String(b64 || "").replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      const bin = atob(s);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      return u8;
    } catch {
      return null;
    }
  }

  function classifyFromDerBytes(der) {
    if (!der || der.length < 32) return null;
    let structured = null;
    try {
      structured = parseLeafCertificate(der);
    } catch {
      structured = {
        subjectAttrs: {},
        subjectBytes: null,
        rawDer: der,
        policies: [],
        hasEvPolicy: false,
        hasOvPolicy: false,
        hasDvPolicy: false
      };
    }
    if (structured && !structured.rawDer) structured.rawDer = der;
    const rein = reinforcePolicyFlagsFromDer(der, {
      hasEvPolicy: structured.hasEvPolicy,
      hasOvPolicy: structured.hasOvPolicy,
      hasDvPolicy: structured.hasDvPolicy
    });
    structured.hasEvPolicy = rein.hasEvPolicy;
    structured.hasOvPolicy = rein.hasOvPolicy;
    structured.hasDvPolicy = rein.hasDvPolicy;

    const c = classifyValidation(structured, structured.subjectBytes || null, der);
    if (!c || c.rejected) return null;

    // 兜底补组织名（EV 策略在但 O 被误剥时）
    if (rein.hasEvPolicy || (c._flags && c._flags.evSubjectShape)) {
      c.validation = "EV";
    }
    if (c.validation !== "DV" && !c.organization && structured.subjectBytes) {
      const o = scanOidString(structured.subjectBytes, OID_O);
      if (o) c.organization = o;
    }
    if (!c.organization && !c.commonName && c.validation === "DV") return null;
    // 有 EV 策略即使缺 CN 也返回（至少展示 EV）
    if (!c.organization && !c.commonName && c.validation !== "EV") return null;
    return c;
  }

  /**
   * 结合 issuer 修正等级。
   * - DigiCert EV RSA CA → EV
   * - CFCA OV OCA 等明确 OV 中间 CA + 叶子域名匹配 → 至少 OV
   *   （crt.sh 列表元数据无 Subject.O 时，禁止锁死 DV；12306.cn 即此路径）
   * - 商业 CA + 已有组织名 → 至少 OV
   */
  function applyIssuerEvUpgrade(hit, issuerName) {
    if (!hit || !hit.validation) return hit;
    if (validationRank(hit.validation) >= 3) return hit;
    const iss = String(issuerName || hit.issuer || "");
    if (hit.commonName && isCaLikeSubject(hit.commonName, hit.organization)) {
      return hit;
    }
    if (issuerIsEvProductCa(iss)) {
      if (!hit.organization && !hit.commonName) return hit;
      return {
        ...hit,
        validation: "EV",
        organization: hit.organization || "",
        issuer: hit.issuer || iss
      };
    }
    const sug = issuerSuggestsOrgValidation(iss);
    // 明确 OV 产品中间 CA（CFCA OV OCA / DigiCert Basic OV …）：
    // 叶子已匹配主机时，证书类型即为 OV——即使尚无 Subject.O（CT 元数据/DER 失败）。
    if (sug === "OV" && validationRank(hit.validation) < 2
      && (hit.commonName || hit.organization || hit.leafOk)) {
      return {
        ...hit,
        validation: "OV",
        organization: hit.organization || "",
        issuer: hit.issuer || iss
      };
    }
    // 商业 CA + 已有 Subject 组织名 → 至少 OV（列表/残缺路径）
    if (hit.organization && sug
      && validationRank(hit.validation) < 2) {
      return {
        ...hit,
        validation: "OV",
        issuer: hit.issuer || iss
      };
    }
    return hit;
  }

  // ─── 源 1: crt.sh 列表（先出 DV，不阻塞在 /?d= 下载）──────────
  async function sourceCrtSh(host) {
    // 查询键顺序关键：
    //   www.xinhuanet.com 精确查询常为空，叶子是 *.xinhuanet.com → 必须优先 %.apex
    //   www.gov.cn 叶子是 *.www.gov.cn → %.www.gov.cn；禁止扫 %.gov.cn 公共后缀
    const bareHost = host.replace(/^www\./, "");
    const apex = getSslRegistrableDomain(bareHost);
    const queryKeys = [];
    const pushKey = (k) => {
      const s = String(k || "").toLowerCase();
      if (s) queryKeys.push(s);
    };
    // 1) %.bare / %.apex 最先（通配证主路径：*.xinhuanet.com / *.12306.cn / *.todesk.com）
    if (!isCnPublicSuffixApex(bareHost)) pushKey("%." + bareHost);
    if (apex && apex !== bareHost && !isCnPublicSuffixApex(apex)) pushKey("%." + apex);
    // 2) 精确 host / bare
    pushKey(host);
    if (bareHost !== host && !isCnPublicSuffixApex(bareHost)) pushKey(bareHost);
    if (apex && apex !== bareHost && !isCnPublicSuffixApex(apex)) pushKey(apex);
    // 3) www 站：*.www.host（中国政府网 CN=*.www.gov.cn）
    if (/^www\./i.test(host)) pushKey("%." + host);

    const queries = [];
    const seenQ = new Set();
    for (const k of queryKeys) {
      const q = String(k || "").toLowerCase();
      if (!q || seenQ.has(q)) continue;
      seenQ.add(q);
      queries.push(`https://crt.sh/?q=${encodeURIComponent(k)}&exclude=expired&output=json`);
    }
    const rows = [];
    const seenIds = new Set();
    // 并行查前 4 键（已含 %.apex）
    const parallel = await Promise.all(queries.slice(0, 4).map((url) => fetchText(url, 5500)));
    const absorb = (res) => {
      if (!res || !res.ok || !res.text) return;
      const t = res.text.trim();
      if (!t.startsWith("[")) return;
      try {
        const parsed = JSON.parse(t);
        if (!Array.isArray(parsed)) return;
        for (const r of parsed) {
          if (!r) continue;
          const id = r.id != null ? String(r.id) : `${r.common_name}|${r.not_before}|${r.issuer_name}`;
          if (seenIds.has(id)) continue;
          seenIds.add(id);
          rows.push(r);
        }
      } catch { /* ignore */ }
    };
    for (const res of parallel) absorb(res);
    const coveringCount = () => rows.filter((r) => r && (
      nameMatchesHost(String(r.name_value || r.common_name || ""), host)
      || nameMatchesHost(String(r.common_name || ""), host)
      || nameMatchesHost(String(r.name_value || r.common_name || ""), bareHost)
    )).length;
    // 覆盖不足：补剩余键；仍不足则去掉 exclude=expired 再扫 %.apex（precert 偶发被 exclude 滤掉）
    if (coveringCount() < 1) {
      for (let i = 4; i < queries.length; i++) {
        absorb(await fetchText(queries[i], 4500));
        if (coveringCount() >= 2) break;
      }
    }
    if (coveringCount() < 1 && !isCnPublicSuffixApex(bareHost)) {
      const wild = "%." + bareHost;
      absorb(await fetchText(
        `https://crt.sh/?q=${encodeURIComponent(wild)}&output=json`, 5500
      ));
    }
    if (!rows.length) return null;

    const now = Date.now();
    const bare = host.replace(/^www\./, "");
    const candidates = rows
      .filter((r) => r && (r.id != null || r.common_name || r.name_value))
      .map((r) => {
        const notAfter = parseCrtDate(r.not_after);
        const notBefore = parseCrtDate(r.not_before);
        const cn = String(r.common_name || "");
        const nv = String(r.name_value || "");
        const issuer = String(r.issuer_name || "");
        const match = nameMatchesHost(nv || cn, host)
          || nameMatchesHost(cn, host)
          || nameMatchesHost(nv || cn, bare)
          || cn.toLowerCase() === host
          || cn.toLowerCase() === bare
          || cn.toLowerCase() === `*.${bare}`
          || cn.toLowerCase() === `www.${bare}`;
        return { id: r.id, notAfter, notBefore, issuer, cn, nv, match, freeDv: isLikelyFreeDvIssuer(issuer) };
      })
      .filter((r) => r.match)
      .filter((r) => Number.isFinite(r.notAfter) && r.notAfter > now);

    if (!candidates.length) return null;

    // 所有未过期候选严格按签发时间从新到旧；同一时间再优先商业/OV/EV CA。
    candidates.sort((a, b) => {
      const byIssuedAt = (b.notBefore || 0) - (a.notBefore || 0);
      if (byIssuedAt) return byIssuedAt;
      const ra = issuerSuggestsOrgValidation(a.issuer) === "EV" ? 3
        : issuerSuggestsOrgValidation(a.issuer) === "OV" ? 2
        : (!a.freeDv ? 1 : 0);
      const rb = issuerSuggestsOrgValidation(b.issuer) === "EV" ? 3
        : issuerSuggestsOrgValidation(b.issuer) === "OV" ? 2
        : (!b.freeDv ? 1 : 0);
      if (rb !== ra) return rb - ra;
      return (b.notBefore || 0) - (a.notBefore || 0);
    });

    let best = null;

    // ① 商业 CA / EV·OV 中间 CA：先下叶子 DER（Subject 使用者）—— digicert.com 主路径
    const upgrade = candidates
      .filter((c) => c.id != null && (!c.freeDv || issuerSuggestsOrgValidation(c.issuer)))
      .slice(0, 4);
    if (upgrade.length) {
      const pemResults = await Promise.all(
        upgrade.map(async (c) => {
          try {
            const dl = await fetchBytes(`https://crt.sh/?d=${c.id}`, 4000);
            if (!dl.ok || !dl.buf || dl.buf.length < 32) return null;
            const classified = classifyFromCrtDownload(dl.buf);
            if (!classified) return null;
            if (!leafMatchesQueryHost(classified.commonName, c.nv || c.cn, host)) return null;
            return applyIssuerEvUpgrade({
              validation: classified.validation,
              organization: classified.organization || "",
              commonName: classified.commonName || host,
              source: "crt.sh",
              issuer: c.issuer,
              certId: c.id,
              unexpiredHostVerified: c.notAfter > now,
              notBefore: c.notBefore || 0
            }, c.issuer);
          } catch {
            return null;
          }
        })
      );
      const newestVerifiedOrg = pemResults.find((hit) => hit
        && validationRank(hit.validation) >= 2
        && String(hit.organization || "").trim()
        && hit.unexpiredHostVerified === true);
      if (newestVerifiedOrg) return newestVerifiedOrg;
      for (const hit of pemResults) best = betterResult(best, hit);
      // 仅拿到 EV 可提前返回；OV 继续走列表兜底不够，应再试更多 EV 中间 CA 条目
      if (best && validationRank(best.validation) >= 3) return best;
    }

    // ①b 若仍非 EV：再拉一批带 “EV” 字样的中间 CA 叶子（digicert.com）
    if (!best || validationRank(best.validation) < 3) {
      const evMore = candidates
        .filter((c) => c.id != null && /\bEV\b/i.test(c.issuer)
          && !upgrade.some((u) => u.id === c.id))
        .slice(0, 4);
      if (evMore.length) {
        const more = await Promise.all(
          evMore.map(async (c) => {
            try {
              const dl = await fetchBytes(`https://crt.sh/?d=${c.id}`, 4000);
              if (!dl.ok || !dl.buf || dl.buf.length < 32) return null;
              const classified = classifyFromCrtDownload(dl.buf);
              if (!classified) return null;
              if (!leafMatchesQueryHost(classified.commonName, c.nv || c.cn, host)) return null;
              return applyIssuerEvUpgrade({
                validation: classified.validation,
                organization: classified.organization || "",
                commonName: classified.commonName || host,
                source: "crt.sh",
                issuer: c.issuer,
                certId: c.id,
                unexpiredHostVerified: c.notAfter > now,
                notBefore: c.notBefore || 0
              }, c.issuer);
            } catch {
              return null;
            }
          })
        );
        for (const hit of more) best = betterResult(best, hit);
        if (best && validationRank(best.validation) >= 3) return best;
      }
    }

    // ② 列表元数据：先 DV，再按 issuer 升 OV/EV
    // CFCA OV OCA 等即使 DER 下载失败也会在 applyIssuerEvUpgrade 里升为 OV（12306）
    // 注意：无 organization 的 OV 不当作终态，继续返回让上层补 DER
    for (const c of candidates.slice(0, 12)) {
      const meta = ctLeafMetaHit(host, c.nv, c.issuer, c.cn, c.notBefore, { requireKnownDvCa: false });
      if (meta) {
        const hit = applyIssuerEvUpgrade({
          ...meta,
          source: "crt.sh",
          issuer: c.issuer,
          leafOk: true
        }, c.issuer);
        best = betterResult(best, hit);
        // 仅 EV 或 OV+机构名可提前结束；OV 无 O= 继续试下一批
        if (best && validationRank(best.validation) >= 3) return best;
        if (best && validationRank(best.validation) >= 2 && String(best.organization || "").trim()) {
          return best;
        }
      }
    }
    // OV 无 org 但有 certId：再专程下 DER 补机构名（12306 / gov.cn）
    if (best && validationRank(best.validation) >= 2 && !String(best.organization || "").trim()) {
      const needOrg = candidates
        .filter((c) => c.id != null && issuerSuggestsOrgValidation(c.issuer))
        .slice(0, 4);
      for (const c of needOrg) {
        try {
          const dl = await fetchBytes(`https://crt.sh/?d=${c.id}`, 5000);
          if (!dl.ok || !dl.buf || dl.buf.length < 32) continue;
          const classified = classifyFromCrtDownload(dl.buf);
          if (!classified || !classified.organization) continue;
          if (!leafMatchesQueryHost(classified.commonName, classified.commonName, host)
            && !nameMatchesHost(c.nv || c.cn, host)) continue;
          return applyIssuerEvUpgrade({
            validation: classified.validation || best.validation,
            organization: classified.organization,
            commonName: classified.commonName || best.commonName || host,
            source: "crt.sh",
            issuer: c.issuer || best.issuer || "",
            certId: c.id,
            leafOk: true,
            unexpiredHostVerified: c.notAfter > now,
            notBefore: c.notBefore || best.notBefore || 0
          }, c.issuer || best.issuer);
        } catch { /* next */ }
      }
    }
    return best;
  }

  // ─── 源 2: Cert Spotter ──
  // .cn / 政府站：直接 expand=cert_der，一次拿 Subject.O（www.gov.cn / 12306 CFCA）。
  // 其它站：轻量列表优先；OV 无 org / 商业 CA meta DV 再补 DER。
  async function sourceCertSpotter(host) {
    const bare = host.replace(/^www\./, "");
    // 保留 www 优先；gov.cn 公共后缀本身勿单独查（噪声）
    const domains = [host];
    if (bare !== host && !isCnPublicSuffixApex(bare)) domains.push(bare);
    const uniq = [...new Set(domains)];
    const careful = needsCarefulSslProbe(host);

    async function loadRows(domain, timeoutMs, withDer) {
      const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}`
        + `&include_subdomains=false&match_wildcards=true`
        + `&expand=dns_names&expand=issuer`
        + (withDer ? `&expand=cert_der` : "");
      const res = await fetchText(url, timeoutMs);
      if (!res.ok || !res.text || res.status === 429 || res.status >= 500) return null;
      try {
        const rows = JSON.parse(res.text);
        return Array.isArray(rows) ? rows : null;
      } catch {
        return null;
      }
    }

    function scoreRows(rows) {
      const now = Date.now();
      const scored = [];
      if (!rows || !rows.length) return scored;
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        if (!r) continue;
        const notAfter = parseCrtDate(r.not_after);
        if (!Number.isFinite(notAfter) || notAfter <= now) continue;
        const names = Array.isArray(r.dns_names) ? r.dns_names.join("\n") : "";
        const issuerName = (r.issuer && (r.issuer.name || r.issuer.friendly_name)) || "";
        if (names && !nameMatchesHost(names, host) && !nameMatchesHost(names, bare)
          && !nameMatchesHost(names, host.replace(/^www\./, ""))) continue;
        const sug = issuerSuggestsOrgValidation(issuerName);
        const pri = sug === "EV" ? 3 : sug === "OV" ? 2 : sug === "MAYBE" ? 1 : 0;
        scored.push({ r, issuerName, names, pri, notBefore: parseCrtDate(r.not_before) || 0, notAfter });
      }
      scored.sort((a, b) => {
        const byIssuedAt = b.notBefore - a.notBefore;
        if (byIssuedAt) return byIssuedAt;
        return b.pri - a.pri;
      });
      return scored;
    }

    function consumeScored(scored, best) {
      for (let i = 0; i < scored.length; i++) {
        const { r, issuerName, names, notBefore, notAfter } = scored[i];
        if (r.cert_der) {
          const classified = classifyFromDerBytes(base64ToDer(r.cert_der));
          if (classified && !classified.rejected) {
            const cn = classified.commonName || host;
            const org = classified.organization || "";
            const sans = Array.isArray(r.dns_names) ? r.dns_names.join("\n") : names;
            if (!leafMatchesQueryHost(cn, sans, host) && !nameMatchesHost(sans || cn, host)) {
              // DER 解析到的 CN 不覆盖本 host 时跳过（防错证）
            } else if (!isInvalidLeafForHost(cn, sans, host)) {
              let hit = applyIssuerEvUpgrade({
                validation: classified.validation,
                organization: org,
                commonName: cn,
                source: "certspotter",
                issuer: issuerName,
                leafOk: true,
                unexpiredHostVerified: notAfter > Date.now(),
                notBefore
              }, issuerName);
              best = betterResult(best, hit);
              // EV 或 OV+机构名：足够
              if (best && validationRank(best.validation) >= 3) return best;
              if (best && validationRank(best.validation) >= 2
                && String(best.organization || "").trim()) return best;
              continue;
            }
          }
        }
        const cnGuess = (Array.isArray(r.dns_names) && r.dns_names.find((n) => !String(n).startsWith("*.")))
          || (Array.isArray(r.dns_names) && r.dns_names[0])
          || host;
        const meta = ctLeafMetaHit(host, names, issuerName, cnGuess, notBefore, { requireKnownDvCa: false });
        if (meta) {
          let hit = applyIssuerEvUpgrade({
            ...meta,
            source: "certspotter",
            issuer: issuerName,
            leafOk: true
          }, issuerName);
          best = betterResult(best, hit);
          if (best && validationRank(best.validation) >= 3) return best;
        }
      }
      return best;
    }

    let best = null;

    // ① 国内/.cn：直接带 cert_der（CFCA 叶子含中文 O=，如 国务院办公厅秘书局 / 中国铁道科学研究院）
    if (careful) {
      for (const d of uniq) {
        const derRows = await loadRows(d, 5000, true);
        if (!derRows || !derRows.length) continue;
        best = consumeScored(scoreRows(derRows), best);
        if (best && validationRank(best.validation) >= 2
          && String(best.organization || "").trim()) {
          return best;
        }
      }
      if (best && validationRank(best.validation) >= 2) return best;
    }

    // ② 轻量列表（通常 <1s）
    let rows = null;
    for (const d of uniq) {
      rows = await loadRows(d, careful ? 2200 : 2800, false);
      if (rows && rows.length) break;
    }
    best = consumeScored(scoreRows(rows), best);
    if (best && validationRank(best.validation) >= 3) return best;
    // OV + 机构名才算完；无 org 的 OV（issuer 升格）必须再拉 DER
    if (best && validationRank(best.validation) >= 2
      && String(best.organization || "").trim()) return best;
    if (best && canSoftFinishDv(best)) return best;

    // ③ 商业 CA meta DV / OV 无 org / 无结果：必须拉 DER
    const needDer = !best
      || (validationRank(best.validation) >= 2 && !String(best.organization || "").trim())
      || (best.validation === "DV" && (
        issuerSuggestsOrgValidation(best.issuer)
        || issuerIsEvProductCa(best.issuer)
        || !isLikelyFreeDvIssuer(best.issuer)
      ));
    if (needDer) {
      for (const d of uniq) {
        const derRows = await loadRows(d, careful ? 5000 : 4000, true);
        if (!derRows || !derRows.length) continue;
        best = consumeScored(scoreRows(derRows), best);
        if (best && validationRank(best.validation) >= 2
          && String(best.organization || "").trim()) break;
      }
    }
    return best;
  }

  // ─── 源 3: SSL Labs 缓存（只取叶子 Subject，跳过链上 CA）──
  // CT 对 dpm.org.cn / 12306 等常空；Labs READY 的 certs[] 带 subject + raw PEM（OV 定级主路径）。
  // 例：www.dpm.org.cn → CN=*.dpm.org.cn, O=故宫博物院, issuer=GeoTrust G2 TLS CN
  //
  // 关键：必须用 all=on（不要 all=done）——
  //   xinhuanet 等多 IP 站长期 IN_PROGRESS；all=done 在未全局 READY 时**不返回**
  //   endpoint.details / certIds，只能拿到空壳，随后靠 issuer 升 OV 却永远无 O=。
  //   all=on 在单端点 Ready 时就能给 certIds；READY 后 certs[] 含 Subject/PEM。
  // 超时：READY 全量 JSON 常 200–400KB，跨境 5s 会被 AbortController 掐死。
  function labsAnalyzeUrl(host) {
    return `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}`
      + `&publish=off&fromCache=on&maxAge=168&all=on`;
  }

  async function sourceSslLabs(host) {
    const careful = needsCarefulSslProbe(host);
    // 大包体 + 跨境：一律给足时间（xinhuanet READY ≈ 340KB）
    const res = await fetchText(labsAnalyzeUrl(host), careful ? 18000 : 15000);
    if (!res.ok || !res.text) return null;
    let data;
    try {
      data = JSON.parse(res.text);
    } catch {
      return null;
    }
    if (!data || !data.status) return null;
    if (data.status === "DNS" || data.status === "ERROR") return null;
    if (data.status !== "READY" && data.status !== "IN_PROGRESS") return null;

    const endpoints = Array.isArray(data.endpoints) ? data.endpoints : [];
    const sniLeafIds = new Set();
    for (const ep of endpoints) {
      const chains = Array.isArray(ep && ep.details && ep.details.certChains)
        ? ep.details.certChains : [];
      for (const ch of chains) {
        if (!ch || ch.noSni) continue;
        const id0 = Array.isArray(ch.certIds) && ch.certIds[0];
        if (id0) sniLeafIds.add(String(id0).toLowerCase());
      }
    }

    const labsCertId = (item) => String(
      (item && (item.id || item.sha256Hash || item.sha256 || item.certId)) || ""
    ).toLowerCase();

    const bindLabsHitToSni = (hit, itemOrId, forced) => {
      if (!hit) return null;
      const id = typeof itemOrId === "string" ? itemOrId.toLowerCase() : labsCertId(itemOrId);
      const bound = forced === true || (!!id && sniLeafIds.has(id));
      return sanitizeOvForDisplay({ ...hit, sniChainVerified: bound });
    };

    function considerSubject(subject, issuer, altNames) {
      if (!subject && !altNames) return null;
      // 跳过 OpenSSL 占位自签（noSNI 默认）
      if (/Internet\s+Widgits|Some-State/i.test(String(subject || ""))) return null;
      const c = subject ? classifyFromSubjectDn(subject, issuer) : null;
      if (c === null && subject) return null;
      let validation = c && c.validation;
      let organization = sanitizeLeafOrganization((c && c.organization) || "", issuer);
      let commonName = (c && c.commonName) || "";
      if (!commonName && altNames) {
        const names = String(altNames).split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
        commonName = names.find((n) => leafMatchesQueryHost(n, "", host))
          || names.find((n) => !n.startsWith("*.") && nameLooksLikeHostname(n))
          || names[0]
          || "";
      }
      // 无 CN/SAN 不能用查询 host 冒充（曾把 Internet Widgits 默认证判成 OV）
      if (!commonName && !altNames) return null;
      if (!c && !commonName) return null;
      if (!validation) validation = organization ? "OV" : "DV";
      if (!organization && validation === "OV") validation = "DV";
      if (isLikelyFreeDvIssuer(issuer) && !/\bOV\b|\bEV\b/i.test(String(issuer || ""))) {
        validation = "DV";
        organization = "";
      }
      const leafOk = leafMatchesQueryHost(commonName, altNames, host);
      if (!leafOk) return null;
      if (isInvalidLeafForHost(commonName, altNames, host)) return null;
      return applyIssuerEvUpgrade({
        validation,
        organization: validation === "DV" ? "" : organization,
        commonName: commonName || host,
        source: "ssllabs",
        issuer: issuer || (c && c.issuer) || "",
        leafOk: true,
        notBefore: Date.now()
      }, issuer || (c && c.issuer) || "");
    }

    /** Labs certs[] 常带 raw PEM——比 DN 字符串更稳（中文 O= / 策略 OID） */
    function considerLabsCertItem(item) {
      if (!item) return null;
      // Labs issues 位：自签/过期/名字不匹配等（noSNI OpenSSL 默认证常有 issues>0）
      try {
        const issues = Number(item.issues) || 0;
        // bit flags：自签、名字不匹配等；有问题且无域名 CN 时直接跳过
        if (issues > 0) {
          const cns = [].concat(item.commonNames || [], item.altNames || []);
          const anyName = cns.some((n) => nameMatchesHost(String(n || ""), host));
          if (!anyName) return null;
        }
      } catch { /* continue */ }
      const iss = String(item.issuerLabel || item.issuerSubject || item.issuer || "").trim();
      const alts = [].concat(item.commonNames || [], item.altNames || []).join("\n");
      const subDn = String(item.subject || item.rawSubject || "").trim();
      // noSNI OpenSSL 默认证：O=Internet Widgits、无 CN
      if (/Internet\s+Widgits/i.test(subDn) || isBogusPlaceholderOrg(
        (parseDnString(subDn).O || "")
      )) {
        if (!alts || !nameMatchesHost(alts, host)) return null;
      }
      // ① PEM 优先
      const pem = item.raw || item.pem || item.certificate || "";
      if (pem && /BEGIN CERTIFICATE/i.test(String(pem))) {
        try {
          const classified = parsePemCert(pem);
          if (classified && !classified.rejected) {
            // 禁止用查询 host 冒充无 CN 的默认证
            const cnFromCert = classified.commonName
              || (item.commonNames && item.commonNames[0])
              || "";
            if (!cnFromCert && !alts) return null;
            const cn = cnFromCert || host;
            let org = sanitizeLeafOrganization(classified.organization || "", iss);
            let validation = classified.validation;
            if (!org && validation === "OV" && !classified._flags?.hasOvPolicy) {
              validation = "DV";
            }
            if (isLikelyFreeDvIssuer(iss) && !/\bOV\b|\bEV\b/i.test(iss)) {
              validation = "DV";
              org = "";
            }
            if (leafMatchesQueryHost(cnFromCert || cn, alts || cnFromCert, host)
              && !isInvalidLeafForHost(cn, alts, host)
              && !isBogusPlaceholderOrg(org)) {
              return applyIssuerEvUpgrade({
                validation,
                organization: org,
                commonName: cnFromCert || cn,
                source: "ssllabs",
                issuer: iss,
                leafOk: true,
                notBefore: Number(item.notBefore) || Date.now()
              }, iss);
            }
          }
        } catch { /* fall through DN */ }
      }
      // ② Subject DN 字符串
      return considerSubject(subDn, iss, alts);
    }

    const certById = new Map();
    const certList = Array.isArray(data.certs)
      ? data.certs
      : (data.certs && typeof data.certs === "object" ? Object.values(data.certs) : []);
    for (const item of certList) {
      if (!item) continue;
      const id = String(item.id || item.sha256Hash || item.sha256 || "").toLowerCase();
      if (id) certById.set(id, item);
    }

    let best = null;
    const leafShaHints = [];
    // ① 先扫 host.certs（dpm.org.cn 主路径：READY 时 subject+raw 都在这里）
    for (const item of certList) {
      const hit = bindLabsHitToSni(considerLabsCertItem(item), item, false);
      if (!hit) continue;
      // 跳过中间 CA / 无关 CDN 叶子（noSNI volcwaf 等）
      if (hit.commonName && isCaLikeSubject(hit.commonName, hit.organization)) continue;
      best = betterResult(best, hit);
      if (best && validationRank(best.validation) >= 2 && best.organization) break;
    }
    if (best && validationRank(best.validation) >= 2 && best.organization) return best;

    // ② endpoint.details + 叶子 sha 链
    for (const ep of endpoints) {
      const details = ep && ep.details;
      if (!details) continue;
      const cert = details.cert || {};
      const subject = cert.subject || details.certSubject || "";
      const issuer = cert.issuerLabel || cert.issuerSubject || details.certIssuer || "";
      const alts = [].concat(cert.commonNames || [], cert.altNames || []).join("\n");
      const hit = bindLabsHitToSni(considerSubject(subject, issuer, alts), cert, false);
      if (hit) best = betterResult(best, hit);

      const chains = Array.isArray(details.certChains) ? details.certChains : [];
      for (const ch of chains) {
        if (!ch || ch.noSni) continue;
        const ids = Array.isArray(ch.certIds) ? ch.certIds : [];
        if (ids[0]) leafShaHints.push(String(ids[0]).toLowerCase());
        // 链上第 0 条 → certs 表
        if (ids[0]) {
          const leafItem = certById.get(String(ids[0]).toLowerCase());
          const leafHit = bindLabsHitToSni(considerLabsCertItem(leafItem), ids[0], true);
          if (leafHit) best = betterResult(best, leafHit);
        }
      }
      if (best && validationRank(best.validation) >= 2 && best.organization) return best;
    }

    // ③ 先按叶子 sha 补 DER。注意：Labs 给的是终态证指纹，CT 可能只有 precert（指纹不同）→ 常 miss
    //    miss 时必须靠 ⑥ 域搜索 %.apex 补 O=（*.xinhuanet.com）
    if ((!best || validationRank(best.validation) < 2 || !best.organization) && leafShaHints.length) {
      const uniqSha = [...new Set(leafShaHints)].slice(0, 3);
      for (const sha of uniqSha) {
        try {
          const derHit = await fetchCrtShByFingerprint(sha, host);
          if (derHit) best = betterResult(best, bindLabsHitToSni({ ...derHit, source: "ssllabs+fp" }, sha, true));
          if (best && validationRank(best.validation) >= 2 && best.organization) break;
        } catch { /* next */ }
      }
    }

    // ④ 中间 CA 名升 OV——仅使用 Labs 实际返回的中间证书 Subject，不维护指纹映射。
    if (!best || validationRank(best.validation) < 2 || !best.organization) {
      for (const ep of endpoints) {
        const chains = Array.isArray(ep && ep.details && ep.details.certChains)
          ? ep.details.certChains : [];
        for (const ch of chains) {
          // noSNI 链常是 OpenSSL 默认证（Internet Widgits），绝不当站点叶子
          if (!ch || ch.noSni) continue;
          const ids = Array.isArray(ch.certIds) ? ch.certIds : [];
          const midId = ids[1] ? String(ids[1]).toLowerCase() : "";
          const mid = midId ? certById.get(midId) : null;
          const midDn = mid
            ? String(mid.subject || mid.rawSubject || mid.commonName || "").trim()
            : "";
          const leafItem = ids[0] ? certById.get(String(ids[0]).toLowerCase()) : null;
          const fromLeaf = bindLabsHitToSni(considerLabsCertItem(leafItem), ids[0] || "", true);
          if (fromLeaf) {
            best = betterResult(best, fromLeaf);
            continue;
          }
          if (!midDn) continue;
          // 中间 CA 名也不要是占位
          if (/Internet\s+Widgits|Some-State/i.test(midDn)) continue;
          const leafSha = ids[0] ? String(ids[0]).toLowerCase() : "";
          const leafHit = applyIssuerEvUpgrade({
            validation: "DV",
            organization: "",
            commonName: host,
            source: "ssllabs",
            issuer: midDn,
            leafOk: true,
            certId: leafSha,
            fingerprintSha256: leafSha,
            sniChainVerified: true,
            notBefore: Date.now()
          }, midDn);
          if (leafHit) best = betterResult(best, leafHit);
        }
      }
    }

    // ④b 仍无机构名：按域名搜 CT（%.apex），不要死磕 Labs 指纹
    //    实测：www.xinhuanet.com 精确查询 []，%.xinhuanet.com → CFCA *.xinhuanet.com + O=
    if (!best || validationRank(best.validation) < 2 || !String(best.organization || "").trim()) {
      try {
        const domainHit = await sourceCrtSh(host);
        if (domainHit) best = betterResult(best, domainHit);
      } catch { /* ignore */ }
    }

    // ⑤ 仍无机构名：再拉 Labs（IN_PROGRESS 等 READY 写满 certs[]；READY 也可能首次包被截断）
    //    xinhuanet 等多 IP 站从首端点 Ready → 全局 READY 常需 1–3 分钟，二次拉取很关键
    if (!best || validationRank(best.validation) < 2 || !String(best.organization || "").trim()) {
      try {
        const waitMs = data.status === "IN_PROGRESS" ? (careful ? 2500 : 3000) : 800;
        await new Promise((r) => setTimeout(r, waitMs));
        const res2 = await fetchText(labsAnalyzeUrl(host), careful ? 16000 : 14000);
        if (res2.ok && res2.text) {
          let data2;
          try { data2 = JSON.parse(res2.text); } catch { data2 = null; }
          if (data2) {
            const certs2 = Array.isArray(data2.certs)
              ? data2.certs
              : (data2.certs && typeof data2.certs === "object" ? Object.values(data2.certs) : []);
            const eps2 = Array.isArray(data2.endpoints) ? data2.endpoints : [];
            const sniLeafIds2 = new Set();
            for (const ep of eps2) {
              const chains = Array.isArray(ep && ep.details && ep.details.certChains)
                ? ep.details.certChains : [];
              for (const ch of chains) {
                if (!ch || ch.noSni) continue;
                const id0 = Array.isArray(ch.certIds) && ch.certIds[0];
                if (id0) sniLeafIds2.add(String(id0).toLowerCase());
              }
            }
            for (const item of certs2) {
              const id = labsCertId(item);
              const hit = bindLabsHitToSni(considerLabsCertItem(item), id, sniLeafIds2.has(id));
              if (hit) best = betterResult(best, hit);
              if (best && validationRank(best.validation) >= 2 && best.organization) break;
            }
            // 二次包的 certChains 指纹
            if (!best || !String(best.organization || "").trim()) {
              const shas = [];
              for (const ep of eps2) {
                const chains = Array.isArray(ep && ep.details && ep.details.certChains)
                  ? ep.details.certChains : [];
                for (const ch of chains) {
                  if (!ch || ch.noSni) continue;
                  const id0 = Array.isArray(ch.certIds) && ch.certIds[0];
                  if (id0) shas.push(String(id0).toLowerCase());
                }
              }
              for (const sha of [...new Set(shas)].slice(0, 3)) {
                try {
                  const derHit = await fetchCrtShByFingerprint(sha, host);
                  if (derHit && derHit.organization) {
                    best = betterResult(best, bindLabsHitToSni(derHit, sha, true));
                    break;
                  }
                } catch { /* next */ }
              }
            }
          }
        }
      } catch { /* ignore */ }
    }

    // ⑥ 有叶子指纹但无 org：写进 hit，供 enrich / 后台再探
    if (best && !String(best.organization || "").trim() && leafShaHints.length) {
      best = {
        ...best,
        certId: best.certId || leafShaHints[0],
        fingerprintSha256: best.fingerprintSha256 || leafShaHints[0]
      };
    }
    return sanitizeOvForDisplay(best);
  }

  /**
   * 按 SHA-256 指纹取叶子并分类。
   * 优先 Shodan CT（ctl.shodan.io 免 Key，常有 der_base64 + parsed.subject.o），
   * 失败再回 crt.sh。
   */
  async function fetchCrtShByFingerprint(sha256, host) {
    const fp = String(sha256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");
    if (fp.length !== 64) return null;

    // ① Shodan CT：Labs certId 经常就是叶子 SHA-256
    try {
      const shRes = await fetchText(`https://ctl.shodan.io/api/v1/cert/${fp}`, 3500);
      if (shRes.ok && shRes.text) {
        let data;
        try { data = JSON.parse(shRes.text); } catch { data = null; }
        if (data) {
          if (data.der_base64) {
            const classified = classifyFromDerBytes(base64ToDer(data.der_base64));
            if (classified && !classified.rejected) {
              const iss = (data.parsed && data.parsed.issuer
                && (data.parsed.issuer.raw || data.parsed.issuer.cn)) || "";
              return applyIssuerEvUpgrade({
                validation: classified.validation,
                organization: classified.organization || "",
                commonName: classified.commonName || host,
                source: "shodan-ct",
                issuer: iss,
                notBefore: Date.now()
              }, iss);
            }
          }
          const sub = data.parsed && data.parsed.subject;
          if (sub) {
            const org = String(sub.o || "").trim();
            const cn = String(sub.cn || host).trim();
            const iss = (data.parsed.issuer && (data.parsed.issuer.raw || data.parsed.issuer.cn)) || "";
            const validation = org
              ? (issuerIsEvProductCa(iss) ? "EV" : "OV")
              : "DV";
            return applyIssuerEvUpgrade({
              validation,
              organization: validation === "DV" ? "" : org,
              commonName: cn,
              source: "shodan-ct",
              issuer: iss,
              notBefore: Date.now()
            }, iss);
          }
        }
      }
    } catch { /* fall through crt.sh */ }

    // ② crt.sh：JSON 查 id 再下 DER
    const listUrl = `https://crt.sh/?q=${encodeURIComponent(fp)}&output=json`;
    const listRes = await fetchText(listUrl, 3500);
    let certId = null;
    let issuer = "";
    if (listRes.ok && listRes.text && listRes.text.trim().startsWith("[")) {
      try {
        const rows = JSON.parse(listRes.text);
        if (Array.isArray(rows) && rows[0]) {
          certId = rows[0].id;
          issuer = String(rows[0].issuer_name || "");
        }
      } catch { /* ignore */ }
    }
    const tryUrls = [];
    if (certId != null) tryUrls.push(`https://crt.sh/?d=${certId}`);
    tryUrls.push(`https://crt.sh/?sha256=${fp}&d=1`);
    tryUrls.push(`https://crt.sh/?q=${fp}&d=1`);
    for (const u of tryUrls) {
      const dl = await fetchBytes(u, 4000);
      if (!dl.ok || !dl.buf || dl.buf.length < 32) continue;
      const classified = classifyFromCrtDownload(dl.buf);
      if (!classified) continue;
      return applyIssuerEvUpgrade({
        validation: classified.validation,
        organization: classified.organization || "",
        commonName: classified.commonName || host,
        source: "crt.sh",
        issuer: issuer || classified.issuer || "",
        notBefore: Date.now()
      }, issuer);
    }
    return null;
  }

  // ─── 源 4: Shodan CT Logs API（ctl.shodan.io，官方免费、无需 API Key）──
  // GET /api/v1/domain/{domain} → 证书 hash 列表（subject_cn / issuer_cn / SAN）
  // GET /api/v1/cert/{sha256}   → parsed.subject.o + der_base64（可定 OV/EV）
  // 文档：https://ctl.shodan.io/
  async function sourceShodanCt(host) {
    const bare = host.replace(/^www\./, "");
    const apex = getSslRegistrableDomain(bare);
    // 保留 www 查询键：www.gov.cn 的 CT 条目挂在 www.gov.cn，查 gov.cn 常为空
    const domains = [host];
    if (bare !== host) domains.push(bare);
    else if (!isCnPublicSuffixApex(bare)) domains.push("www." + bare);
    else domains.unshift("www." + bare); // gov.cn → 先 www.gov.cn
    if (apex && apex !== bare && !isCnPublicSuffixApex(apex)) domains.push(apex);
    const uniq = [...new Set(domains.map((d) => String(d || "").toLowerCase()).filter(Boolean))];

    const nowSec = Math.floor(Date.now() / 1000);
    const rows = [];
    const seenHash = new Set();

    for (const domain of uniq) {
      const url = `https://ctl.shodan.io/api/v1/domain/${encodeURIComponent(domain)}`;
      const res = await fetchText(url, 4000);
      if (!res.ok || !res.text) continue;
      let list;
      try {
        list = JSON.parse(res.text);
      } catch {
        continue;
      }
      if (!Array.isArray(list) || !list.length) continue;
      for (const r of list) {
        if (!r || !r.hash) continue;
        const h = String(r.hash).toLowerCase();
        if (seenHash.has(h)) continue;
        seenHash.add(h);
        const sans = Array.isArray(r.san_dns_names) ? r.san_dns_names.join("\n") : "";
        const cn = String(r.subject_cn || "");
        const issuer = String(r.issuer_cn || "");
        const notAfter = Number(r.not_after) || 0;
        const notBefore = Number(r.not_before) || 0;
        const names = [sans, cn].filter(Boolean).join("\n");
        if (names && !nameMatchesHost(names, host) && !nameMatchesHost(names, bare)
          && !subjectMatchesHost(cn, host)) {
          continue;
        }
        if (!names) continue;
        const sug = issuerSuggestsOrgValidation(issuer);
        const pri = sug === "EV" ? 3 : sug === "OV" ? 2 : sug === "MAYBE" ? 1 : 0;
        // 必须有明确有效期且当前未过期；历史过期证书不能提供组织身份。
        if (!notAfter || notAfter <= nowSec) continue;
        const item = { hash: h, cn, issuer, sans, notBefore, notAfter, pri };
        rows.push(item);
      }
      // 已有覆盖本 host 的活证可提前停
      if (rows.length >= 8) break;
    }
    if (!rows.length) return null;

    rows.sort((a, b) => {
      const byIssuedAt = (b.notBefore || 0) - (a.notBefore || 0);
      if (byIssuedAt) return byIssuedAt;
      return b.pri - a.pri;
    });

    let best = null;

    // ① 优先拉 OV/EV/商业 CA 的完整证书（parsed.subject.o 或 DER）
    const upgrade = rows.filter((r) => r.pri >= 1 || !isLikelyFreeDvIssuer(r.issuer)).slice(0, 4);
    const targets = upgrade.length ? upgrade : rows.slice(0, 2);

    const certHits = await Promise.all(
      targets.map(async (c) => {
        try {
          const certUrl = `https://ctl.shodan.io/api/v1/cert/${encodeURIComponent(c.hash)}`;
          const res = await fetchText(certUrl, 4000);
          if (!res.ok || !res.text) return null;
          let data;
          try {
            data = JSON.parse(res.text);
          } catch {
            return null;
          }
          if (!data) return null;

          // 优先 DER（策略 OID + Subject 完整）
          if (data.der_base64) {
            const der = base64ToDer(data.der_base64);
            const classified = classifyFromDerBytes(der);
            if (classified && !classified.rejected) {
              const cn = classified.commonName || c.cn || host;
              const org = classified.organization || "";
              const sans = (data.san_dns_names || []).join("\n") || c.sans || "";
              if (!leafMatchesQueryHost(cn, sans, host)
                && !leafMatchesQueryHost(cn, cn, host)) {
                return null;
              }
              if (isInvalidLeafForHost(cn, sans, host)) return null;
              return applyIssuerEvUpgrade({
                validation: classified.validation,
                organization: org,
                commonName: cn,
                source: "shodan-ct",
                issuer: c.issuer
                  || (data.parsed && data.parsed.issuer && (data.parsed.issuer.raw || data.parsed.issuer.cn))
                  || "",
                leafOk: true,
                unexpiredHostVerified: c.notAfter > nowSec,
                notBefore: (c.notBefore || 0) * (c.notBefore > 1e12 ? 1 : 1000)
              }, c.issuer);
            }
          }

          // parsed.subject 回退（Shodan 已拆好 o/cn）
          const sub = data.parsed && data.parsed.subject;
          const iss = data.parsed && data.parsed.issuer;
          if (sub) {
            const org = String(sub.o || sub.organization || "").trim();
            const cn = String(sub.cn || sub.common_name || c.cn || host).trim();
            const issuerRaw = (iss && (iss.raw || iss.cn)) || c.issuer || "";
            const sans = [].concat(
              data.san_dns_names || [],
              (data.parsed.sans && data.parsed.sans.dns) || [],
              c.sans ? String(c.sans).split("\n") : []
            ).filter(Boolean).join("\n");
            if (!leafMatchesQueryHost(cn, sans, host)) return null;
            if (isInvalidLeafForHost(cn, sans, host)) return null;
            let validation = "DV";
            if (org) validation = "OV";
            if (issuerIsEvProductCa(issuerRaw) && (org || nameLooksLikeHostname(cn))) {
              validation = "EV";
            }
            return applyIssuerEvUpgrade({
              validation,
              organization: validation === "DV" ? "" : org,
              commonName: cn || host,
              source: "shodan-ct",
              issuer: issuerRaw,
              leafOk: true,
              unexpiredHostVerified: c.notAfter > nowSec,
              notBefore: (c.notBefore || 0) * (c.notBefore > 1e12 ? 1 : 1000)
            }, issuerRaw);
          }
          return null;
        } catch {
          return null;
        }
      })
    );
    const newestVerifiedOrg = certHits.find((hit) => hit
      && validationRank(hit.validation) >= 2
      && String(hit.organization || "").trim()
      && hit.unexpiredHostVerified === true);
    if (newestVerifiedOrg) return newestVerifiedOrg;
    for (const hit of certHits) best = betterResult(best, hit);
    if (best && validationRank(best.validation) >= 2) return best;

    // ② 列表元数据：至少 DV；OV 中间 CA 不软锁
    for (const c of rows.slice(0, 10)) {
      const meta = ctLeafMetaHit(host, c.sans, c.issuer, c.cn, (c.notBefore || 0) * 1000, {
        requireKnownDvCa: false
      });
      if (meta) {
        best = betterResult(best, applyIssuerEvUpgrade({
          ...meta,
          source: "shodan-ct",
          issuer: c.issuer
        }, c.issuer));
      }
    }
    return best;
  }

  /**
   * 源 5: NetworkCalc 实时 TLS 叶证书（公开 API，无需 Key）。
   * API 不返回完整链/noSni 字段，因此单独标记 liveTlsLeafVerified；只有响应 host 精确归属、
   * 且 PEM 的 CN/SAN 覆盖当前 host 时，才允许用 Subject.O 补组织字段。
   */
  async function sourceNetworkCalc(host) {
    const url = `https://networkcalc.com/api/security/certificate/${encodeURIComponent(host)}`;
    const res = await fetchText(url, needsCarefulSslProbe(host) ? 7000 : 5500);
    if (!res.ok || !res.text) return null;
    let data;
    try {
      data = JSON.parse(res.text);
    } catch {
      return null;
    }
    if (!data || String(data.status || "").toUpperCase() !== "OK") return null;
    const cert = data.certificate;
    if (!cert || typeof cert !== "object") return null;
    const metaHost = rawHostname(data.meta && data.meta.hostname);
    const certHost = rawHostname(cert.hostname);
    if ((!metaHost && !certHost) || (metaHost && metaHost !== host) || (certHost && certHost !== host)) {
      return null;
    }
    const raw = String(cert.raw || "");
    if (!/BEGIN CERTIFICATE/i.test(raw)) return null;
    const classified = parsePemCert(raw);
    if (!classified || classified.rejected) return null;
    const commonName = String(classified.commonName || cert.issued_to || "").trim();
    const altNames = [].concat(cert.alternate_names || [])
      .map((n) => String(n || "").replace(/^DNS:/i, "").trim())
      .filter(Boolean)
      .join("\n");
    if (!leafMatchesQueryHost(commonName, altNames, host)) return null;
    const issuer = String(cert.issued_by || "").trim();
    let organization = sanitizeLeafOrganization(classified.organization || "", issuer);
    let validation = String(classified.validation || "DV").toUpperCase();
    if (!/^(DV|OV|EV)$/.test(validation)) validation = organization ? "OV" : "DV";
    if (!organization && validation === "OV" && !classified._flags?.hasOvPolicy) validation = "DV";
    if (isLikelyFreeDvIssuer(issuer) && !/\bOV\b|\bEV\b/i.test(issuer)) {
      validation = "DV";
      organization = "";
    }
    return applyIssuerEvUpgrade({
      validation,
      organization: validation === "DV" ? "" : organization,
      commonName: commonName || host,
      source: "networkcalc",
      issuer,
      leafOk: true,
      liveTlsLeafVerified: true,
      notBefore: parseCrtDate(cert.valid_from) || Date.now()
    }, issuer);
  }

  /**
   * 源 6: MySSL report
   * GET https://myssl.com/{host}
   * 叶证表字段：cc-tableTit + cc-tableCel（通用名称 / 证书类型 / 组织机构 / 颁发者 / 开始时间 / 备用名称）
   * 取第一张 CN/SAN 覆盖查询主机的叶证。
   */
  async function sourceMyssl(host) {
    const h = rawHostname(host);
    if (!h || !h.includes(".")) return null;

    const url = "https://myssl.com/" + encodeURIComponent(h);
    const res = await fetchText(url, needsCarefulSslProbe(h) ? 10000 : 8000);
    if (!res.ok || !res.text) return null;
    return decodeMysslReportPayload(res.text, h);
  }

  /** cc-tableTit / cc-tableCel 单元格纯文本 */
  function mysslCellText(raw) {
    return String(raw || "")
      .replace(/\x3c[^\x3e]*\x3e/g, " ")
      .replace(/&\w+;|&#\d+;/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  /**
   * 解析 MySSL 报告：按 tr 表对 (cc-tableTit → cc-tableCel) 取字段。
   * 叶证以「信任状态」起块（在通用名称之前）；跳过域名不匹配 / data-code≠0 的次要证。
   *
   * 不匹配示例：
   *   cc-trust-status data-code="4" → 域名不匹配 …
   *   通用名称 → *.ias.tencent-cloud.net (不匹配)
   */
  function decodeMysslReportPayload(payload, queryHost) {
    const h = rawHostname(queryHost);
    if (!h || !payload) return null;
    const body = String(payload);

    // <td class="cc-tableTit">…</td> … <td class="cc-tableCel cc-trust-status" data-code="N">…</td>
    // m1=title, m2=cel open-tag attrs (含 data-code), m3=cel body
    const pairRe =
      /class\s*=\s*["']cc-tableTit["'][^>]*>([\s\S]*?)<\/td>[\s\S]{0,1200}?class\s*=\s*["']cc-tableCel[^"']*["']([^>]*)>([\s\S]*?)<\/td>/gi;
    const pairs = [];
    let m;
    while ((m = pairRe.exec(body))) {
      const title = mysslCellText(m[1]);
      const celAttrs = String(m[2] || "");
      const rawCel = m[3];
      const cell = mysslCellText(rawCel);
      if (!title) continue;
      // data-code="0" 可信；"4" 域名不匹配（cc-nosni-status / 无 SNI 默认证）
      const codeM = celAttrs.match(/data-code\s*=\s*["']?(\d+)/i)
        || String(rawCel).match(/data-code\s*=\s*["']?(\d+)/i);
      const dataCode = codeM ? codeM[1] : "";
      pairs.push({ title, cell, dataCode, celAttrs });
    }
    if (!pairs.length) return null;

    // 「信任状态」在通用名称之前 → 以信任状态开叶；否则遇通用名称兜底开叶
    const leaves = [];
    let cur = null;
    for (const row of pairs) {
      const { title, cell, dataCode, celAttrs } = row;
      if (title === "信任状态") {
        if (cur) leaves.push(cur);
        cur = Object.create(null);
        cur["信任状态"] = cell;
        cur._trustCode = dataCode;
        cur._trustAttrs = celAttrs;
        continue;
      }
      if (!cur) {
        if (title !== "通用名称") continue;
        cur = Object.create(null);
      }
      // 同名字段只记第一次（证书链区会重复 颁发者 等）
      if (cur[title] == null || cur[title] === "") cur[title] = cell;
    }
    if (cur) leaves.push(cur);

    let best = null;
    for (const leaf of leaves) {
      const trust = String(leaf["信任状态"] || "");
      const cnRaw = String(leaf["通用名称"] || "");
      // 跳过域名不匹配：data-code=4 / cc-nosni-status / 文案 / CN 后缀 (不匹配)
      if (String(leaf._trustCode || "") === "4") continue;
      if (/域名不匹配/.test(trust)) continue;
      if (/不匹配/.test(cnRaw)) continue;
      if (/cc-nosni-status/i.test(String(leaf._trustAttrs || "")) || /cc-nosni-status/i.test(trust)) continue;

      let commonName = cnRaw
        .replace(/\s*[(\uFF08][^)\uFF09]*[)\uFF09]\s*$/g, "")
        .replace(/\s+/g, " ")
        .trim();
      if (!commonName) continue;

      const altNames = String(leaf["备用名称"] || "")
        .replace(/\s+/g, "\n")
        .trim();
      if (!leafMatchesQueryHost(commonName, altNames, h)) continue;

      const typeRaw = String(leaf["证书类型"] || "").toUpperCase();
      let validation = "";
      if (/\bEV\b/.test(typeRaw)) validation = "EV";
      else if (/\bOV\b/.test(typeRaw)) validation = "OV";
      else if (/\bDV\b/.test(typeRaw)) validation = "DV";

      const issuer = String(leaf["颁发者"] || "").trim();
      let organization = String(leaf["组织机构"] || "").trim();
      if (organization === "--" || organization === "-" || organization === "—") organization = "";
      organization = sanitizeLeafOrganization(organization, issuer);

      if (!validation) validation = organization ? "OV" : "DV";
      if (validationRank(validation) >= 2 && !organization) continue;
      if (validation === "DV") organization = "";

      if (isLikelyFreeDvIssuer(issuer) && !/\bOV\b|\bEV\b/i.test(issuer)) {
        validation = "DV";
        organization = "";
      }

      const notBefore = parseCrtDate(leaf["开始时间"]) || 0;
      const hit = {
        validation,
        organization: validation === "DV" ? "" : organization,
        commonName: commonName || h,
        source: "myssl",
        issuer,
        leafOk: true,
        liveTlsLeafVerified: true,
        notBefore: notBefore > 0 ? notBefore : Date.now()
      };

      if (!best || validationRank(hit.validation) > validationRank(best.validation)) {
        best = hit;
        if (validationRank(hit.validation) >= 2) break;
      }
    }
    return best;
  }

  /**
   * 源 7: EdgeOne 实时 SSL 查询
   * GET https://api.edgeone.ai/eo/tools/ssl?url=HOST
   * JSON: data.subject.{O,CN} / data.issuer / data.subjectaltname / valid_from
   */
  async function sourceEdgeOne(host) {
    const h = rawHostname(host);
    if (!h || !h.includes(".")) return null;
    // 文档参数为 url=域名；带 https:// 亦可
    const url = "https://api.edgeone.ai/eo/tools/ssl?url=" + encodeURIComponent(h);
    const res = await fetchText(url, needsCarefulSslProbe(h) ? 7000 : 5500);
    if (!res.ok || !res.text) return null;
    let data;
    try { data = JSON.parse(res.text); } catch { return null; }
    if (!data || Number(data.code) !== 0) return null;
    const cert = data.data;
    if (!cert || typeof cert !== "object" || Number(cert.code) !== 0) return null;
    if (cert.ca === true) return null; // 不要 CA 证书

    const sub = cert.subject && typeof cert.subject === "object" ? cert.subject : {};
    const iss = cert.issuer && typeof cert.issuer === "object" ? cert.issuer : {};
    const commonName = String(sub.CN || sub.cn || "").trim();
    const altNames = String(cert.subjectaltname || cert.subjectAltName || "")
      .replace(/DNS:/gi, "")
      .replace(/,/g, "\n");
    if (!leafMatchesQueryHost(commonName, altNames, h)) return null;

    const issuer = [iss.O || iss.o, iss.CN || iss.cn].filter(Boolean).join(" / ").trim()
      || String(iss.CN || iss.cn || iss.O || "").trim();
    let organization = sanitizeLeafOrganization(String(sub.O || sub.o || "").trim(), issuer);
    let validation = organization ? "OV" : "DV";
    if (isLikelyFreeDvIssuer(issuer) && !/\bOV\b|\bEV\b/i.test(issuer)) {
      validation = "DV";
      organization = "";
    }
    // issuer CN 含 EV 且有 O= 时由 applyIssuerEvUpgrade 升 EV
    if (!organization && validationRank(validation) >= 2) return null;

    return applyIssuerEvUpgrade({
      validation,
      organization: validation === "DV" ? "" : organization,
      commonName: commonName || h,
      source: "edgeone",
      issuer,
      leafOk: true,
      liveTlsLeafVerified: true,
      notBefore: parseCrtDate(cert.valid_from) || Date.now()
    }, issuer);
  }

  /**
   * OV/EV 无组织名时补 Subject.O。
   * 场景：issuer 先升到 OV，叶子 O= 要靠 DER（xinhuanet / 12306 / gov.cn）。
   * 顺序：Labs certs PEM → 指纹 → Cert Spotter DER → Shodan 域 → crt.sh。
   */
  async function enrichOrganizationFromCrt(host, hit) {
    if (!hit || !hit.validation) return hit;
    if (validationRank(hit.validation) < 2) return hit;
    if (String(hit.organization || "").trim()) return hit;
    const bare = host.replace(/^www\./, "");
    const domains = [host];
    if (bare !== host && !isCnPublicSuffixApex(bare)) domains.push(bare);

    // ⓪ Labs certs[]（READY 后才有 Subject.O / PEM；xinhuanet 主路径）
    //    专程长超时再拉，避开竞速里被掐断的大包
    try {
      const labsRes = await fetchText(labsAnalyzeUrl(host), 16000);
      if (labsRes.ok && labsRes.text) {
        let labsData;
        try { labsData = JSON.parse(labsRes.text); } catch { labsData = null; }
        if (labsData) {
          const labsSniLeafIds = new Set();
          const labsEndpoints = Array.isArray(labsData.endpoints) ? labsData.endpoints : [];
          for (const ep of labsEndpoints) {
            const chains = Array.isArray(ep && ep.details && ep.details.certChains)
              ? ep.details.certChains : [];
            for (const ch of chains) {
              if (!ch || ch.noSni) continue;
              const id0 = Array.isArray(ch.certIds) && ch.certIds[0];
              if (id0) labsSniLeafIds.add(String(id0).toLowerCase());
            }
          }
          const bindEnrichedLabsHit = (candidate, item) => {
            if (!candidate) return null;
            const id = String((item && (item.id || item.sha256Hash || item.sha256 || item.certId)) || "").toLowerCase();
            return sanitizeOvForDisplay({
              ...candidate,
              sniChainVerified: !!id && labsSniLeafIds.has(id)
            });
          };
          const certs = Array.isArray(labsData.certs)
            ? labsData.certs
            : (labsData.certs && typeof labsData.certs === "object"
              ? Object.values(labsData.certs) : []);
          for (const item of certs) {
            if (!item) continue;
            // PEM 优先
            const pem = item.raw || item.pem || item.certificate || "";
            if (pem && /BEGIN CERTIFICATE/i.test(String(pem))) {
              try {
                const classified = parsePemCert(pem);
                if (classified && !classified.rejected && classified.organization) {
                  const cn = classified.commonName
                    || (item.commonNames && item.commonNames[0]) || host;
                  const alts = [].concat(item.commonNames || [], item.altNames || []).join("\n");
                  if (leafMatchesQueryHost(cn, alts || cn, host)
                    && !isInvalidLeafForHost(cn, alts, host)
                    && !isCaLikeSubject(cn, classified.organization)) {
                    const iss = String(item.issuerLabel || item.issuerSubject || item.issuer || "").trim();
                    const candidate = bindEnrichedLabsHit(applyIssuerEvUpgrade({
                      validation: classified.validation || hit.validation,
                      organization: classified.organization,
                      commonName: cn,
                      source: "ssllabs",
                      issuer: iss || hit.issuer || "",
                      leafOk: true,
                      notBefore: Number(item.notBefore) || hit.notBefore || Date.now()
                    }, iss || hit.issuer), item);
                    if (candidate && candidate.organization) return candidate;
                  }
                }
              } catch { /* next cert */ }
            }
            // Subject DN 字符串
            const sub = String(item.subject || item.rawSubject || "").trim();
            if (sub) {
              const c = classifyFromSubjectDn(sub, item.issuerLabel || item.issuerSubject || "");
              if (c && c.organization) {
                const alts = [].concat(item.commonNames || [], item.altNames || []).join("\n");
                if (leafMatchesQueryHost(c.commonName, alts || c.commonName, host)
                  && !isInvalidLeafForHost(c.commonName, alts, host)) {
                  const candidate = bindEnrichedLabsHit(applyIssuerEvUpgrade({
                    validation: c.validation || hit.validation,
                    organization: c.organization,
                    commonName: c.commonName || host,
                    source: "ssllabs",
                    issuer: c.issuer || hit.issuer || "",
                    leafOk: true,
                    notBefore: Number(item.notBefore) || hit.notBefore || Date.now()
                  }, c.issuer || hit.issuer), item);
                  if (candidate && candidate.organization) return candidate;
                }
              }
            }
          }
          // 仍无 org：从 ready 端点收集叶子 sha 再查指纹库
          if (Array.isArray(labsData.endpoints)) {
            for (const ep of labsData.endpoints) {
              const chains = Array.isArray(ep && ep.details && ep.details.certChains)
                ? ep.details.certChains : [];
              for (const ch of chains) {
                if (!ch || ch.noSni) continue;
                const id0 = Array.isArray(ch.certIds) && ch.certIds[0];
                if (!id0) continue;
                try {
                  const byFp = await fetchCrtShByFingerprint(String(id0).toLowerCase(), host);
                  if (byFp && String(byFp.organization || "").trim()) {
                    const candidate = sanitizeOvForDisplay({ ...byFp, sniChainVerified: true });
                    if (candidate.organization) return candidate;
                  }
                } catch { /* next */ }
              }
            }
          }
        }
      }
    } catch { /* next path */ }

    // ① 已有叶子指纹/certId：直接下 DER
    const fp0 = String(hit.certId || hit.fingerprintSha256 || hit.sha256 || "")
      .toLowerCase().replace(/[^0-9a-f]/g, "");
    if (fp0.length === 64) {
      try {
        const byFp = await fetchCrtShByFingerprint(fp0, host);
        if (byFp && String(byFp.organization || "").trim()) {
          const candidate = sanitizeOvForDisplay({
            ...byFp,
            sniChainVerified: hit.sniChainVerified === true,
            unexpiredHostVerified: hit.unexpiredHostVerified === true
          });
          if (candidate.organization) return candidate;
        }
      } catch { /* next */ }
    }

    // ② Cert Spotter：复用竞速阶段的源级缓存/inflight，禁止补组织时重复消耗配额。
    try {
      const certSpotterHit = await runCachedSslSource(
        "certspotter",
        host,
        () => sourceCertSpotter(host)
      );
      if (certSpotterHit && String(certSpotterHit.organization || "").trim()) {
        return certSpotterHit;
      }
    } catch { /* next source */ }

    // ③ Shodan 域列表 → cert DER（商业 CA 优先）
    for (const d of domains) {
      try {
        const listRes = await fetchText(`https://ctl.shodan.io/api/v1/domain/${encodeURIComponent(d)}`, 4000);
        if (!listRes.ok || !listRes.text) continue;
        let list;
        try { list = JSON.parse(listRes.text); } catch { continue; }
        if (!Array.isArray(list)) continue;
        const nowSec = Math.floor(Date.now() / 1000);
        const cands = list
          .filter((r) => r && r.hash)
          .filter((r) => {
            const names = [r.subject_cn, ...(Array.isArray(r.san_dns_names) ? r.san_dns_names : [])].join("\n");
            return nameMatchesHost(names, host) || nameMatchesHost(names, bare)
              || subjectMatchesHost(r.subject_cn, host);
          })
          .filter((r) => Number(r.not_after) > nowSec)
          .sort((a, b) => {
            const byIssuedAt = (b.not_before || 0) - (a.not_before || 0);
            if (byIssuedAt) return byIssuedAt;
            const pa = issuerSuggestsOrgValidation(a.issuer_cn) ? 1 : 0;
            const pb = issuerSuggestsOrgValidation(b.issuer_cn) ? 1 : 0;
            return pb - pa;
          })
          .slice(0, 3);
        for (const c of cands) {
          const byFp = await fetchCrtShByFingerprint(c.hash, host);
          const names = [c.subject_cn, ...(Array.isArray(c.san_dns_names) ? c.san_dns_names : [])].join("\n");
          if (byFp && String(byFp.organization || "").trim()
            && leafMatchesQueryHost(byFp.commonName, names, host)) {
            return { ...byFp, unexpiredHostVerified: true };
          }
        }
      } catch { /* next */ }
    }

    // ④ crt.sh 列表 + DER（%.bare 优先：xinhuanet 精确 www 查询为空）
    const keys = [];
    if (!isCnPublicSuffixApex(bare)) keys.push("%." + bare, bare);
    keys.push(host);
    if (/^www\./i.test(host)) keys.push("%." + host);
    const seen = new Set();
    for (const k of keys) {
      const key = String(k || "").toLowerCase();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      try {
        const url = `https://crt.sh/?q=${encodeURIComponent(k)}&exclude=expired&output=json`;
        const res = await fetchText(url, 5500);
        if (!res.ok || !res.text || !res.text.trim().startsWith("[")) continue;
        let rows;
        try { rows = JSON.parse(res.text); } catch { continue; }
        if (!Array.isArray(rows) || !rows.length) continue;
        const now = Date.now();
        const cands = rows
          .filter((r) => r && r.id != null)
          .map((r) => ({
            id: r.id,
            issuer: String(r.issuer_name || ""),
            cn: String(r.common_name || ""),
            nv: String(r.name_value || ""),
            notAfter: parseCrtDate(r.not_after),
            notBefore: parseCrtDate(r.not_before)
          }))
          .filter((r) => nameMatchesHost(r.nv || r.cn, host) || nameMatchesHost(r.cn, host)
            || nameMatchesHost(r.nv || r.cn, bare))
          .filter((r) => Number.isFinite(r.notAfter) && r.notAfter > now)
          .sort((a, b) => {
            const byIssuedAt = (b.notBefore || 0) - (a.notBefore || 0);
            if (byIssuedAt) return byIssuedAt;
            const ra = issuerSuggestsOrgValidation(a.issuer) === "EV" ? 3
              : issuerSuggestsOrgValidation(a.issuer) === "OV" ? 2
              : (!isLikelyFreeDvIssuer(a.issuer) ? 1 : 0);
            const rb = issuerSuggestsOrgValidation(b.issuer) === "EV" ? 3
              : issuerSuggestsOrgValidation(b.issuer) === "OV" ? 2
              : (!isLikelyFreeDvIssuer(b.issuer) ? 1 : 0);
            return rb - ra;
          })
          .slice(0, 4);
        for (const c of cands) {
          // crt.sh 偶发 502：同一 id 重试 + 备选 URL
          let classified = null;
          const tryUrls = [
            `https://crt.sh/?d=${c.id}`,
            `https://crt.sh/?id=${c.id}&d=1`
          ];
          for (let attempt = 0; attempt < tryUrls.length && !classified; attempt++) {
            try {
              const dl = await fetchBytes(tryUrls[attempt], 6000);
              if (!dl.ok || !dl.buf || dl.buf.length < 32) continue;
              classified = classifyFromCrtDownload(dl.buf);
            } catch { /* next */ }
          }
          if (!classified || classified.rejected) continue;
          if (!leafMatchesQueryHost(classified.commonName, classified.commonName, host)
            && !nameMatchesHost(c.nv || c.cn, host)) continue;
          if (!classified.organization) continue;
          return applyIssuerEvUpgrade({
            validation: classified.validation || hit.validation,
            organization: classified.organization,
            commonName: classified.commonName || hit.commonName || host,
            source: "crt.sh",
            issuer: c.issuer || hit.issuer || "",
            leafOk: true,
            unexpiredHostVerified: c.notAfter > now,
            certId: c.id,
            notBefore: c.notBefore || hit.notBefore || 0
          }, c.issuer || hit.issuer);
        }
      } catch { /* next key */ }
    }
    return hit;
  }

  /** 单源限时，不拖垮整批并行 */
  function withTimeout(promise, ms) {
    return Promise.race([
      Promise.resolve(promise).catch(() => null),
      new Promise((resolve) => setTimeout(() => resolve(null), ms))
    ]);
  }

  function normalizeProbeHit(host, best) {
    if (!best || !best.validation) return null;
    const clean = sanitizeOvForDisplay(best);
    return {
      validation: clean.validation || "DV",
      organization: clean.organization || "",
      commonName: clean.commonName || host,
      state: "secure",
      host,
      at: Date.now(),
      source: clean.source || "multi",
      issuer: clean.issuer || "",
      certId: clean.certId,
      fingerprintSha256: clean.fingerprintSha256 || "",
      sniChainVerified: clean.sniChainVerified === true,
      liveTlsLeafVerified: clean.liveTlsLeafVerified === true,
      unexpiredHostVerified: clean.unexpiredHostVerified === true,
      notBefore: clean.notBefore || 0
    };
  }

  /** HTTPS 页 CT 全失败时的保守回退：浏览器已完成 TLS，至少是域名验证级 */
  function httpsAssumedDv(host) {
    return {
      validation: "DV",
      organization: "",
      commonName: host,
      state: "secure",
      host,
      at: Date.now(),
      source: "https-assumed",
      issuer: "",
      notBefore: 0,
      assumed: true
    };
  }

  function isPlaceholderSslSource(src) {
    const s = String(src || "");
    // 旧占位拒绝；https-assumed 是探测失败后的合法回退，可展示
    return s === "https-reachability" || s === "page-https";
  }

  /** 国内政府/教育站 */
  function isCnGovOrEduHost(host) {
    const h = String(host || "").toLowerCase();
    return /\.gov\.cn$/i.test(h) || /\.edu\.cn$/i.test(h)
      || /\.(?:gov|edu|mil)(?:\.[a-z]{2})?$/i.test(h);
  }

  /** 恰好是中国多段公共后缀本身（gov.cn / com.cn），扫 %.gov.cn 会淹没真实叶子 */
  function isCnPublicSuffixApex(domain) {
    const d = String(domain || "").toLowerCase().replace(/^www\./, "");
    return /^(?:com|net|org|gov|edu|ac|mil)\.cn$/i.test(d);
  }

  /**
   * 需要「等 Labs / 禁软 DV」的国内站。
   * CT 对 .cn 常空/限流；CFCA OV（12306.cn / www.gov.cn）等易被 https-assumed 锁 DV。
   */
  function needsCarefulSslProbe(host) {
    const h = String(host || "").toLowerCase();
    if (isCnGovOrEduHost(h)) return true;
    // 所有 .cn（含 12306.cn / *.com.cn / www.gov.cn）
    if (/(?:^|\.)cn$/i.test(h)) return true;
    return false;
  }

  /**
   * 单 host 多源并行轮询：先到先用（第一个可用结果即采用，不再 betterResult 合并竞速）。
   * 可用：有 validation；OV/EV 须带机构名（半成品 OV 继续等下一源）。
   *
   * 源：SSL Labs · Cert Spotter · crt.sh · Shodan CT · NetworkCalc · MySSL · EdgeOne
   */
  async function probeSslCertOnce(queryHost, allowCurrentHostSources) {
    const host = rawHostname(queryHost);
    if (!host || host === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return null;

    const careful = needsCarefulSslProbe(host);
    const HARD_MS = careful ? 22000 : 20000;
    const CS_MS = careful ? 6500 : 4500;
    const CRT_MS = careful ? 6000 : 4000;
    const LABS_MS = careful ? 19000 : 17000;
    const SHODAN_MS = careful ? 5000 : 4000;
    const NETWORKCALC_MS = careful ? 7500 : 6000;
    const MYSSL_MS = careful ? 11000 : 9000;
    const EDGEONE_MS = careful ? 7000 : 5500;

    /** 是否可作为「先到先用」的终态结果 */
    function isUsableFirstHit(r) {
      if (!r || !r.validation) return false;
      // OV/EV 无机构名：不可用，继续等其它源
      if (validationRank(r.validation) >= 2 && !String(r.organization || "").trim()) return false;
      return true;
    }

    const raced = await new Promise((resolve) => {
      let pending = 7;
      let settled = false;
      let fallbackBest = null; // 全无可用时，退回 betterResult 最强半成品
      let hardTimer = null;

      const finish = (hit) => {
        if (settled) return;
        settled = true;
        try { if (hardTimer) clearTimeout(hardTimer); } catch { /* ignore */ }
        resolve(hit);
      };

      const onOne = (r) => {
        if (settled) return;
        pending -= 1;
        if (r && r.validation) {
          fallbackBest = betterResult(fallbackBest, r);
          // 谁最先给出可用结果就用谁
          if (isUsableFirstHit(r)) {
            finish(normalizeProbeHit(host, r));
            return;
          }
        }
        if (pending <= 0) finish(normalizeProbeHit(host, fallbackBest));
      };

      hardTimer = setTimeout(() => {
        if (!settled) finish(normalizeProbeHit(host, fallbackBest));
      }, HARD_MS);

      withTimeout(runCachedSslSource("ssllabs", host, () => sourceSslLabs(host)), LABS_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
      withTimeout(runCachedSslSource("certspotter", host, () => sourceCertSpotter(host)), CS_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
      withTimeout(runCachedSslSource("crtsh", host, () => sourceCrtSh(host)), CRT_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
      withTimeout(runCachedSslSource("shodan", host, () => sourceShodanCt(host)), SHODAN_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
      const networkCalcProbe = allowCurrentHostSources === false
        ? Promise.resolve(null)
        : runCachedSslSource("networkcalc", host, () => sourceNetworkCalc(host));
      withTimeout(networkCalcProbe, NETWORKCALC_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
      withTimeout(runCachedSslSource("myssl", host, () => sourceMyssl(host)), MYSSL_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
      withTimeout(runCachedSslSource("edgeone", host, () => sourceEdgeOne(host)), EDGEONE_MS)
        .then((r) => onOne(r))
        .catch(() => onOne(null));
    });

    // 若最终仍是 OV/EV 无机构名（半成品）→ 再专程下 DER 补 O=
    if (raced && validationRank(raced.validation) >= 2 && !String(raced.organization || "").trim()) {
      try {
        const enriched = await enrichOrganizationFromCrt(host, raced);
        if (enriched && enriched.organization) return normalizeProbeHit(host, enriched);
      } catch { /* ignore */ }
    }
    return raced;
  }

  /**
   * 主机回退：当前 host → 上层域名（串行，不查子域名/www.）
   * 当前 host 有 OV/EV 立刻返回；纯 DV 对国内站仍可试上层（证书常挂在 apex）
   */
  NS.probeSslCertForHost = async function (hostRaw) {
    const cacheHost = hostKey(hostRaw) || rawHostname(hostRaw);
    if (!cacheHost || cacheHost === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(cacheHost)) {
      return null;
    }
    const candidates = buildSslFallbackHosts(hostRaw);
    if (!candidates.length) return null;
    // 国内站：当前 + 一层上层（www.12306.cn → 12306.cn；jyt → jiangsu.gov.cn）
    let list = candidates;
    if (needsCarefulSslProbe(cacheHost) || needsCarefulSslProbe(candidates[0])) {
      list = candidates.slice(0, 2);
    }

    let bestAll = null;
    const currentHost = rawHostname(hostRaw);
    for (let i = 0; i < list.length; i++) {
      const q = list[i];
      let hit = null;
      try {
        // NetworkCalc 只允许查询当前页面 host；上层证书回退不得复用其实时结果。
        hit = await probeSslCertOnce(q, q === currentHost);
      } catch {
        hit = null;
      }
      if (!hit || !hit.validation) continue;
      const packed = { ...hit, host: cacheHost, queriedHost: q };
      bestAll = betterResult(bestAll, packed);
      // OV/EV 足够
      if (validationRank(bestAll.validation) >= 2) return bestAll;
      // 国内站当前 host 仅 DV：再试上层（通配证常挂在 apex）
      if (!needsCarefulSslProbe(cacheHost)) {
        return bestAll;
      }
    }
    return bestAll;
  };

  NS.storeSslCertInfo = function (host, info) {
    const key = hostKey(host);
    if (!key || !info) return;
    if (isPlaceholderSslSource(info.source)) return;
    // 入库前清洗：占位 O= 不当 OV
    let clean = { ...sanitizeOvForDisplay(info) };
    if (isBogusPlaceholderOrg(clean.organization)
      || (isLikelyFreeDvIssuer(clean.issuer) && !/\bOV\b|\bEV\b/i.test(String(clean.issuer || "")))) {
      clean.organization = "";
      if (validationRank(clean.validation) >= 2 && isLikelyFreeDvIssuer(clean.issuer)) {
        clean.validation = "DV";
      } else if (isBogusPlaceholderOrg(info.organization)) {
        clean.validation = "DV";
        clean.organization = "";
      }
    }
    const prev = NS.sslCertByHost.get(key);
    // 占位 org / 免费 DV 误升允许被正确结果覆盖；无组织名的 OV 等级本身不是脏结果
    const prevDirty = prev && (
      isBogusPlaceholderOrg(prev.organization)
      || (validationRank(prev.validation) >= 2 && isLikelyFreeDvIssuer(prev.issuer)
        && !String(prev.organization || "").trim())
      || (validationRank(prev.validation) >= 2 && isBogusPlaceholderOrg(prev.organization))
    );
    if (prev && prev.validation
      && validationRank(prev.validation) > validationRank(clean.validation)
      && !prevDirty) {
      return;
    }
    // 同级：新结果更优（有正确 org / 非脏 CDN org）时覆盖
    if (prev && validationRank(prev.validation) === validationRank(clean.validation)) {
      const better = betterResult(prev, { ...clean, host: key });
      if (better === prev && prev.organization && !clean.organization
        && !isBogusPlaceholderOrg(prev.organization)) return;
    }
    NS.sslCertByHost.set(key, { ...clean, host: key, at: Date.now() });
    persistSslStateSoon(false);
  };

  NS.getSslCertInfoForHost = function (host) {
    const key = hostKey(host);
    if (!key) return null;
    const hit = NS.sslCertByHost.get(key);
    if (!hit) return null;
    if (hit.at && Date.now() - hit.at > SSL_CACHE_TTL_MS) {
      NS.sslCertByHost.delete(key);
      persistSslStateSoon(false);
      return null;
    }
    if (isPlaceholderSslSource(hit.source)) return null;
    // 缓存里的占位 OV 视为无效，强制重探
    if (isBogusPlaceholderOrg(hit.organization)) return null;
    return sanitizeOvForDisplay(hit);
  };

  /**
   * 取缓存或探测。
   * opts.https === true：CT 全失败时回退 https-assumed DV（页面已是 HTTPS，浏览器已验过证）。
   */
  NS.resolveSslCertInfo = async function (hostRaw, opts) {
    // 缓存键去 www；探测主机保留 www（www.gov.cn 叶子是 *.www.gov.cn，剥 www 会 miss）
    const host = hostKey(hostRaw);
    const probeHost = rawHostname(hostRaw) || host;
    if (!host) return null;
    await ensureSslPersistentStateLoaded();
    const force = opts && opts.force;
    const pageHttps = !!(opts && opts.https);
    if (!force) {
      const cached = NS.getSslCertInfoForHost(host);
      if (cached && cached.validation) {
        const rank = validationRank(cached.validation);
        // OV 无机构名：不返回「半成品」，继续探补 O=
        const missingOrg = rank >= 2 && !String(cached.organization || "").trim();
        if (rank >= 3 && !missingOrg) {
          return cached;
        } else if (rank === 2 && !missingOrg) {
          const ovAge = cached.at ? Date.now() - cached.at : 1e15;
          if (ovAge < 30 * 1000) {
            if (!NS._sslProbeInflight.has(host)) {
              const bg = (async () => {
                try {
                  const again = await NS.probeSslCertForHost(probeHost);
                  if (again && (validationRank(again.validation) > rank
                    || (again.organization && !cached.organization))) {
                    NS.storeSslCertInfo(host, again);
                  }
                } catch { /* ignore */ }
                finally { NS._sslProbeInflight.delete(host); }
              })();
              NS._sslProbeInflight.set(host, bg);
            }
            return cached;
          }
        } else if (missingOrg) {
          // OV/EV 无 org：不返回半成品，落入下方重探补机构名
        } else if (rank === 1) {
          // 假 DV / 假定 DV 极易粘住：https-assumed 与 ct-meta 几乎不缓存，强制重探
          const src = String(cached.source || "");
          const weakDv = src === "https-assumed" || src === "ct-meta" || src === "crt.sh-meta"
            || !canSoftFinishDv(cached);
          const ttl = weakDv ? 10 * 1000 : 3 * 60 * 1000;
          if (cached.at && Date.now() - cached.at < ttl) {
            if (!NS._sslProbeInflight.has(host)) {
              const bg = (async () => {
                try {
                  const again = await NS.probeSslCertForHost(probeHost);
                  if (again && validationRank(again.validation) > rank) {
                    NS.storeSslCertInfo(host, again);
                  }
                } catch { /* ignore */ }
                finally { NS._sslProbeInflight.delete(host); }
              })();
              NS._sslProbeInflight.set(host, bg);
            }
            // 弱 DV 超过 10s 不返回旧缓存
            if (!weakDv) return cached;
            if (Date.now() - cached.at < 10 * 1000) return cached;
          }
        }
      }
    }
    if (NS._sslProbeInflight.has(host)) return NS._sslProbeInflight.get(host);
    const p = (async () => {
      try {
        let info = null;
        try {
          // 必须保留 www（www.gov.cn ≠ gov.cn）
          info = await NS.probeSslCertForHost(probeHost);
        } catch {
          info = null;
        }
        // CT/Labs 全失败 + 页面 HTTPS → 保守 DV（浏览器已握手成功）
        if ((!info || !info.validation) && pageHttps) {
          info = httpsAssumedDv(host);
        }
        if (!info || !info.validation) return null;
        // 勿用弱结果覆盖更强缓存；但 force 重探时允许 EV 覆盖 OV
        const prev = NS.sslCertByHost.get(host);
        if (prev && validationRank(prev.validation) > validationRank(info.validation)) {
          return prev;
        }
        NS.storeSslCertInfo(host, info);
        return NS.getSslCertInfoForHost(host) || sanitizeOvForDisplay(info);
      } finally {
        NS._sslProbeInflight.delete(host);
      }
    })();
    NS._sslProbeInflight.set(host, p);
    return p;
  };

  NS.installSslCertCapture = function () { /* securityInfo 需 developer flag，不用 */ };
})(self.SilverfoxBackground ??= {});
