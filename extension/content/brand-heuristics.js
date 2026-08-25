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

  /**
   * 粗略 eTLD+1 回退（无 tldts 时）。处理 *.com.cn / *.co.uk 及 .cn 省级后缀。
   */
  NS.getRegistrableDomainFallback = function (domain) {
    const d = NS.normalizeDomain(domain);
    const parts = d.split(".").filter(Boolean);
    if (parts.length === 0) return "";
    if (parts.length <= 2) return d;
    const last = parts[parts.length - 1] || "";
    const second = parts[parts.length - 2] || "";
    if (last === "cn" && /^(?:ac|ah|bj|com|cq|edu|fj|gd|gov|gs|gx|gz|ha|hb|he|hi|hk|hl|hn|jl|js|jx|ln|mil|mo|net|nm|nx|org|qh|sc|sd|sh|sn|sx|tj|tw|xj|xz|yn|zj)$/i.test(second)) {
      return parts.slice(-3).join(".");
    }
    if (parts.length >= 3 && last.length === 2 && /^(com|net|org|gov|edu|ac|co|or|ne|gob|gen|ltd|plc|me)$/i.test(second)) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  };

  /**
   * 注册域名（eTLD+1）：优先 tldts Public Suffix List，否则回退启发。
   * example.com.cn / example.co.uk / example.github.io 均正确。
   */
  NS.getRegistrableDomain = function (domain) {
    try {
      if (typeof NS.parseHostWithTldts === "function") {
        const info = NS.parseHostWithTldts(domain);
        if (info && info.domain) return String(info.domain).toLowerCase();
      }
    } catch { /* ignore */ }
    return NS.getRegistrableDomainFallback(domain);
  };

  /** 是否纯营销/频道主机标签（不可当品牌核） */
  NS.isMarketingHostLabelOnly = function (lab) {
    const s = String(lab || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!s) return true;
    // win.qq-musics / download.xxx / pc.xxx 的首段
    if (/^(?:www|www\d*|m|mobile|wap|pc|app|win|cdn|static|img|image|media|assets|api|mail|ftp|blog|shop|store|download|down|dl|soft|vip|pro|safe|free|official|online|cloud|dev|test|beta|stage|staging|git|docs|doc|help|support|bbs|forum|news|wiki|music|musics)$/i.test(s)) return true;
    if (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(s, { strict: true }) && s.length <= 4) return true;
    return false;
  };

  /**
   * apex 左标是否「营销夹带品牌」形态（非干净正站根）。
   * qq-musics / qqmusics / huorong-pc / v-dingtalk → true；sogou / huorong → false。
   */
  NS.apexLabelLooksLikeMarketingPaddedBrand = function (apexLeftRaw) {
    try {
      const raw = String(apexLeftRaw || "").toLowerCase().replace(/^www\./, "");
      if (!raw || raw.length < 5) return false;
      const flat = raw.replace(/[^a-z0-9]/g, "");
      if (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
        && NS.hostLabelIsMarketingPrefixedBrandShape(raw)) return true;
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const core = NS.inferMarketingPaddedBrandCore(raw) || "";
        if (core.length >= 4 && flat !== core && flat.includes(core)) return true;
      }
      if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
        const st = NS.stripMarketingHostPrefixFromToken(raw) || NS.stripMarketingHostPrefixFromToken(flat) || "";
        if (st.length >= 4 && flat !== st && flat.includes(st)) return true;
      }
      // ★ 品牌-短垃圾尾：todesk-ze / dingtalk-o（1～2 字母数字垫，非 ai/go 产品线）
      if (/-/.test(raw)) {
        const segs = raw.split(/[-_]/).filter(Boolean);
        if (segs.length === 2) {
          const head = segs[0].replace(/[^a-z0-9]/g, "");
          const tail = segs[1].replace(/[^a-z0-9]/g, "");
          if (head.length >= 5 && tail.length >= 1 && tail.length <= 2
            && /^[a-z0-9]{1,2}$/i.test(tail)
            && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(tail)) {
            return true;
          }
        }
      }
      // 扁平短垃圾尾：todeskze（无连字符）——靠 hostLabelIsPaddedBrand，勿盲匹配任意 2 字母尾
      if (typeof NS.hostLabelIsPaddedBrand === "function" && flat.length >= 7) {
        const head2 = flat.slice(0, -2);
        const head1 = flat.slice(0, -1);
        if (head2.length >= 5 && NS.hostLabelIsPaddedBrand(flat, head2)) return true;
        if (head1.length >= 5 && NS.hostLabelIsPaddedBrand(flat, head1)) return true;
      }
      // qq-musics / xx-music(s) 连字符仿冒；huorong-lab / brand-soft 营销垫
      if (/^(?:qq|wx|weixin|netease|wy)[-_]?(?:music|musics|yinyue|yinle)/i.test(flat)) return true;
      if (/[-_](?:music|musics|yinyue|yinle|pc|app|soft|safe|vip|pro|cn|win|download|client|lab|labs|tech|site|official)$/i.test(raw)) {
        const head = raw.split(/[-_]/)[0] || "";
        if (head.length >= 2 && head.length <= 16) return true;
      }
      // qissmusic / xxxyinyue：拉丁前缀 + 中文产品品类尾（结构，非品牌词库）
      if (typeof NS.parseHostChineseProductCategoryPad === "function"
        && NS.parseHostChineseProductCategoryPad(raw || flat)) {
        return true;
      }
      return false;
    } catch { return false; }
  };

  /**
   * ★ 主机品牌核（根源）：扫完整主机名，剥公共后缀 / 营销子域 / 夹带前缀后缀。
   * 例：
   * - pc.v-dingtalk.com.cn → dingtalk（非 pc、非 vdingtalk）
   * - www.huorong-pc.cn → huorong
   * - ie-huorong.com.cn → huorong
   * - app-4399.com.cn →（数字另见 digits；拉丁核可空）
   * - dingtalk.com / www.sogou.com → dingtalk / sogou
   * 所有 padCore / brandRoot / 展示回退应优先走这里，禁止只看首标签。
   */
  NS.resolveHostBrandCore = function (hostOpt) {
    try {
      const host = NS.normalizeDomain(hostOpt || (typeof location !== "undefined" ? location.hostname : ""));
      if (!host) return "";
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
      const apexLeftRaw = (apex.split(".")[0] || "").toLowerCase(); // 保留连字符：v-dingtalk
      const apexFlat = apexLeftRaw.replace(/[^a-z0-9]/g, "");
      const hostParts = host.split(".").filter(Boolean);

      const tryCoreFromLabel = (labRaw) => {
        const lab = String(labRaw || "").toLowerCase();
        if (!lab || lab.length < 2) return "";
        const flat = lab.replace(/[^a-z0-9]/g, "");
        if (!flat || flat.length < 3) return "";
        if (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(flat)) return "";
        // 产品线正站（todeskai / pyas-security）不剥成碎片
        if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
          && NS.hostLabelIsBrandProductCategoryDomain(lab, flat)) {
          return flat.length >= 4 ? flat : "";
        }
        let core = "";
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          core = NS.inferMarketingPaddedBrandCore(lab) || "";
        }
        if (!core && typeof NS.stripMarketingHostPrefixFromToken === "function") {
          core = NS.stripMarketingHostPrefixFromToken(flat) || "";
        }
        if (!core && typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
          && NS.hostLabelIsMarketingPrefixedBrandShape(lab)) {
          // 再尝试 glued / 去前缀
          if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
            core = NS.stripMarketingHostPrefixFromToken(flat) || "";
          }
        }
        // 干净标签本身即品牌（dingtalk、sogou）
        if (!core) {
          const padded = (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
            && NS.hostLabelIsMarketingPrefixedBrandShape(lab))
            || /[-_](?:pc|app|soft|safe|vip|pro|cn|win|download|client|lab|labs|tech|site)$/i.test(lab)
            || /^(?:v|x|z|aa|bb|cc|ca|im|ie|pr|ott)[-_]?/i.test(lab);
          if (!padded && flat.length >= 4 && !/^(?:com|net|org|gov|edu)$/i.test(flat)) {
            core = flat;
          }
        }
        if (core && core.length >= 4 && core !== flat) return core; // 成功剥夹带
        if (core && core.length >= 4) return core;
        return "";
      };

      // 优先 apex 左标（v-dingtalk → dingtalk），再扫子域标签（跳过纯营销 pc/www）
      let best = tryCoreFromLabel(apexLeftRaw);
      if (best) return best;

      // 主机各段：pc.v-dingtalk → 已处理 apex；亦处理 huorong.evil.com 等
      for (let i = 0; i < hostParts.length; i++) {
        const p = hostParts[i];
        if (/^(?:com|net|org|gov|edu|co|ac|cn|uk|jp|hk|tw|sg)$/i.test(p)) continue;
        if (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(p)) continue;
        const c = tryCoreFromLabel(p);
        if (c && c.length >= (best ? best.length : 0)) best = c;
      }
      if (best) return best;

      // 回退：apex flat（干净站）
      if (apexFlat.length >= 3 && !(typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(apexFlat))) {
        return apexFlat;
      }
      return "";
    } catch { return ""; }
  };

  /**
   * 公共后缀下的品牌根（与 resolveHostBrandCore 对齐）：
   * - sogou.com / shurufa.sogou.com → sogou
   * - pc.v-dingtalk.com.cn → dingtalk（剥营销子域 + v- 前缀，根因修复）
   * - huorong-pc.com.cn → huorong（非 huorongpc）
   */
  NS.brandRootKeyFromHost = function (hostOrApex) {
    const raw = NS.normalizeDomain(hostOrApex);
    if (!raw) return "";
    // ★ 根源：先剥夹带，再回退 eTLD+1 左标
    try {
      if (typeof NS.resolveHostBrandCore === "function") {
        const core = NS.resolveHostBrandCore(raw);
        if (core && core.length >= 4) return core;
      }
    } catch { /* fall through */ }
    try {
      const apex = NS.getRegistrableDomain(raw) || raw;
      const apexLeftRaw = (apex.split(".")[0] || "").toLowerCase();
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const c = NS.inferMarketingPaddedBrandCore(apexLeftRaw);
        if (c && c.length >= 4) return c;
      }
      const apexLabel = apexLeftRaw.replace(/[^a-z0-9]/g, "");
      if (apexLabel.length >= 3
        && !/^(www|com|net|org|gov|edu|co|ac)$/i.test(apexLabel)) {
        if (raw === apex || raw.endsWith(`.${apex}`)) {
          // 仍可能是 vdingtalk 整段：再剥一次
          if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
            const st = NS.stripMarketingHostPrefixFromToken(apexLabel);
            if (st && st.length >= 4) return st;
          }
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
        && !/^(www|wiki|docs|doc|help|support|blog|news|forum|forums|bbs|cdn|static|img|image|media|assets|download|dl|api|m|mobile|mail|git|dev|test|beta|store|shop|cloud|shurufa|pinyin|ime|input|pc|app)$/i.test(p)) {
        best = p;
      }
    }
    const flatBest = String(best || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
      const st = NS.stripMarketingHostPrefixFromToken(flatBest);
      if (st && st.length >= 4) return st;
    }
    if (typeof NS.inferMarketingPaddedBrandCore === "function") {
      const c = NS.inferMarketingPaddedBrandCore(String(best || "").toLowerCase());
      if (c && c.length >= 4) return c;
    }
    return flatBest;
  };

  /**
   * 主机可参与品牌计票的「核」：统一走 resolveHostBrandCore。
   * 域名虚拟字段 **只** 用 voteLatin（品牌核/数字），禁止 vdingtalk/iehuorong 整段。
   */
  NS.collectHostBrandCores = function (hostOpt) {
    const out = {
      latin: [], voteLatin: [], digits: [],
      labelRaw: "", apexLabel: "", apexLeftRaw: "", root: "", flat: "", padCore: "", padded: false
    };
    try {
      const host = NS.normalizeDomain(hostOpt || (typeof location !== "undefined" ? location.hostname : ""));
      if (!host) return out;
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
      const apexLeftRaw = (apex.split(".")[0] || "").toLowerCase();
      const apexLabel = apexLeftRaw.replace(/[^a-z0-9]/g, "");
      // ★ 根源核：pc.v-dingtalk.com.cn → dingtalk
      const brandCore = typeof NS.resolveHostBrandCore === "function"
        ? (NS.resolveHostBrandCore(host) || "")
        : "";
      const root = brandCore
        || (typeof NS.brandRootKeyFromHost === "function" ? (NS.brandRootKeyFromHost(host) || "") : "");
      const flat = host.replace(/[^a-z0-9]/g, "");
      const labFlat = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      out.labelRaw = labelRaw;
      out.apexLabel = apexLabel;
      out.apexLeftRaw = apexLeftRaw;
      out.root = root;
      out.flat = flat;

      const pushLat = (s, voteToo) => {
        const t = String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!t || t.length < 3) return;
        if (/^(?:www|com|net|org|gov|edu|co|ac|cn|app|web|www\d+|pc)$/i.test(t)) return;
        if (!out.latin.includes(t)) out.latin.push(t);
        if (voteToo && !out.voteLatin.includes(t)) out.voteLatin.push(t);
      };
      const pushDig = (s) => {
        // 只读取连续数字段，禁止把 360weishi-360 删除字母后拼成 360360。
        const runs = String(s || "").match(/\d{3,6}/g) || [];
        runs.forEach((d) => {
          if (!/^\d{3,6}$/.test(d) || /^(?:19|20)\d{2}$/.test(d)) return;
          if (typeof NS.isRepeatedNumericBrandToken === "function"
            && NS.isRepeatedNumericBrandToken(d)) return;
          if (!out.digits.includes(d)) out.digits.push(d);
        });
      };

      const padCore = brandCore || "";
      out.padCore = padCore;
      // 夹带形态：apex/首标签 比核多前缀后缀，或营销子域挂在夹带 apex 上
      const isPaddedShape = !!(padCore && padCore.length >= 4 && (
        (apexLabel && apexLabel !== padCore && apexLabel.includes(padCore))
        || (labFlat && labFlat !== padCore && labFlat.includes(padCore) && labFlat !== apexLabel)
        || (apexLeftRaw && apexLeftRaw !== padCore && (
          (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
            && NS.hostLabelIsMarketingPrefixedBrandShape(apexLeftRaw))
          || /[-_](?:pc|app|soft|safe|vip|pro|cn|win|download|client|lab|labs|tech|site)$/i.test(apexLeftRaw)
          || /^(?:v|x|z|aa|bb|cc|ca|im|ie|pr|ott|get|pc|app)[-_]/i.test(apexLeftRaw)
        ))
        || (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(labelRaw)
          && apexLabel && padCore && apexLabel.includes(padCore) && apexLabel !== padCore)
      ));
      out.padded = !!isPaddedShape;

      // 计票：只投品牌核
      if (padCore) pushLat(padCore, true);
      // 分段扫：整主机所有标签（含 v-dingtalk 的 dingtalk 段）
      host.split(".").forEach((part) => {
        String(part || "").split(/[-_]/).forEach((seg) => {
          const s = String(seg || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          pushDig(seg);
          if (!s || s.length < 3) return;
          const isMkt = (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(s))
            || (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(s));
          // 仅当段等于品牌核时 vote；其它进 latin 对齐
          pushLat(s, !isMkt && padCore && s === padCore);
        });
      });
      pushDig(labelRaw);
      pushDig(flat);
      if (!isPaddedShape) {
        pushLat(apexLabel, true);
        pushLat(root, true);
        if (labFlat && labFlat.length >= 3) pushLat(labFlat, true);
      } else {
        pushLat(apexLabel, false);
        pushLat(root, false);
        if (labFlat) pushLat(labFlat, false);
        // 夹带剥核仅进对齐用 latin，**不 vote**（qqyinle→yinle 若 vote 会压过标题 QQ音乐）
        if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
          const st = NS.stripMarketingHostPrefixFromToken(apexLabel);
          if (st) pushLat(st, false);
        }
        // padCore 已在上方 vote；若 padCore 仅为剥前缀残片且≠干净 apex，取消其 vote 资格
        if (padCore && apexLabel && apexLabel !== padCore && apexLabel.includes(padCore)) {
          out.voteLatin = (out.voteLatin || []).filter((t) => t !== padCore);
          // 数字门户核（4399）仍保留 vote
          if (/^\d{3,6}$/.test(padCore) && !out.voteLatin.includes(padCore)) out.voteLatin.push(padCore);
        }
      }
      try {
        const digs = flat.match(/\d{3,6}/g) || [];
        digs.forEach(pushDig);
      } catch { /* ignore */ }
      if (!out.voteLatin.length && padCore) pushLat(padCore, true);
      if (!out.voteLatin.length && apexLabel.length >= 3 && !isPaddedShape) pushLat(apexLabel, true);
    } catch { /* ignore */ }
    return out;
  };

  /**
   * 是否「主机夹带拼出来的假品牌」：iehuorong / huorongpc / prtodesk / vdingtalk。
   * 这类绝不当 spoof toast 展示名（应显示火绒 / Huorong / ToDesk / DingTalk / 钉钉）。
   */
  NS.isHostShapedCompoundBrandToken = function (cand, hostOpt) {
    try {
      const low = String(cand || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!low || low.length < 5) return false;
      const host = NS.normalizeDomain(hostOpt || (typeof location !== "undefined" ? location.hostname : ""));
      if (!host) return false;
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const labFlat = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      // 页面候选自身的 CamelCase 边界若与连字符 host 逐段一致，它是完整品牌，
      // 不是域名拼接碎片：ToDesk ⇄ to-desk。CloudToDesk ⇄ cloud-todesk
      // 因分段数量/边界不同，不会被此规则放行。
      try {
        const rawCand = String(cand || "").trim();
        const hostParts = labelRaw.split(/[-_]+/).filter(Boolean);
        const camelParts = rawCand.match(/[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+/g) || [];
        if (hostParts.length >= 2 && camelParts.length === hostParts.length
          && camelParts.every((part, i) => part.toLowerCase() === hostParts[i])) {
          // ToDesk ⇄ to-desk 放行；dingtalk-o ⇄ DingtalkO 仍是垃圾尾夹带
          const lastHp = hostParts[hostParts.length - 1] || "";
          const junkTail = lastHp.length <= 2 && /^[a-z0-9]{1,2}$/i.test(lastHp)
            && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(lastHp);
          if (!junkTail) return false;
        }
      } catch { /* ignore */ }
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
      const apexLeftRaw = (apex.split(".")[0] || "").toLowerCase();
      const apexFlat = apexLeftRaw.replace(/[^a-z0-9]/g, "");
      const hostFlat = host.replace(/[^a-z0-9]/g, "");
      const cores = typeof NS.collectHostBrandCores === "function" ? NS.collectHostBrandCores(host) : null;
      let padCore = (cores && cores.padCore) || "";
      const root = (cores && cores.root) || "";
      // 无 padCore 时只尝试明确营销结构；字符污染由页面候选双向确认。
      if (!padCore && typeof NS.inferMarketingPaddedBrandCore === "function") {
        try {
          padCore = String(NS.inferMarketingPaddedBrandCore(labelRaw) || NS.inferMarketingPaddedBrandCore(apexLeftRaw) || "")
            .toLowerCase().replace(/[^a-z0-9]/g, "");
        } catch { /* ignore */ }
      }

      // ★ 干净剥核本身绝不是碎片：huorong @ huorongr.com.cn / todesk @ pc-todeskr 必须可展示
      // 旧逻辑 nearHostFlat 把「huorong ⊂ huorongr 且长度差≤3」判成碎片 → setSpoof 拒绝 → 空文案
      // 注意：勿对 padCore 再跑「单字母尾」自检——todesk 会被误判成 todes+k 碎片
      if (padCore && padCore.length >= 4 && low === padCore) return false;
      if (root && root.length >= 4 && low === root && padCore && labFlat.includes(padCore) && labFlat !== root) {
        // root 若是整段夹带则仍可能是碎片；仅当 root===padCore 时放行
        if (root === padCore) return false;
      }

      const mktSegOnly = /^(?:apps?|soft|safe|vip|pro|pc|cn|win|lab|labs|tech|site|download|client|free|official|online|tool|tools)$/i;
      const hyphenSegs = (/-/.test(labelRaw) ? labelRaw : (/-/.test(apexLeftRaw) ? apexLeftRaw : ""))
        .split(/[-_]/)
        .map((x) => x.replace(/[^a-z0-9]/g, ""))
        .filter((x) => x.length >= 2);

      // 单段干净核（dingding / todesk）可展示；须先于「多段覆盖」判定，避免 dingding 含子串 ding 被误杀
      // ★ pc-todeskr 的 Todeskr：段在连字符里但自身仍是污染尾 → 碎片
      if (hyphenSegs.length >= 2 && hyphenSegs.includes(low) && low !== labFlat && low !== apexFlat) {
        if (mktSegOnly.test(low)) return true;
        try {
          if (typeof NS.hostLabelIsPaddedBrand === "function") {
            for (let n = 1; n <= 2; n++) {
              const head = low.slice(0, -n);
              const tail = low.slice(-n);
              if (head.length < 5) break;
              if (n === 2 && /^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(tail)) continue;
              if (NS.hostLabelIsPaddedBrand(low, head)) return true;
            }
          }
        } catch { /* ignore */ }
        return false;
      }

      // 仅夹带/多段主机才做「近形 flat」碎片判定，避免 todesk.com + ToDesk 被误杀
      const hostLooksCompound = hyphenSegs.length >= 2
        || (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && (NS.apexLabelLooksLikeMarketingPaddedBrand(labelRaw)
            || NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftRaw)))
        || (padCore && padCore.length >= 4 && labFlat && labFlat !== padCore && labFlat.includes(padCore))
        || (padCore && padCore.length >= 4 && apexFlat && apexFlat !== padCore && apexFlat.includes(padCore));

      // 与主机 flat 近形（Dingappsdingdin ≈ dingappsdingding）
      // 注意：low===padCore 已在上方放行，不会走到这里
      const nearHostFlat = (flat) => {
        if (!flat || flat.length < 5) return false;
        if (low === flat) return true;
        // 禁止：干净核 huorong 因是 huorongr 前缀被误杀（仅当 low 不是 padCore）
        if (padCore && low === padCore) return false;
        if (flat.includes(low) && low.length >= 6 && low.length >= flat.length - 3) return true;
        if (low.includes(flat) && flat.length >= 6 && flat.length >= low.length - 3) return true;
        if (typeof NS.editDistanceShort === "function" && Math.abs(low.length - flat.length) <= 3) {
          const d = NS.editDistanceShort(low, flat);
          if (d != null && d >= 0 && d <= 2 && Math.min(low.length, flat.length) >= 8) return true;
        }
        return false;
      };
      if (hostLooksCompound && (nearHostFlat(labFlat) || nearHostFlat(apexFlat))) return true;

      // 候选 ≈ 多段连字符拼接影子（须比「单段干净核」更长/更碎）
      if (hyphenSegs.length >= 2) {
        const joined = hyphenSegs.join("");
        if (nearHostFlat(joined) || low === joined) return true;
        // 候选含 ≥2 个**互不包含**的主机段（ding+apps，而非 ding ⊂ dingding）
        const hits = [];
        for (let si = 0; si < hyphenSegs.length; si++) {
          const seg = hyphenSegs[si];
          if (seg.length >= 3 && low.includes(seg) && !mktSegOnly.test(seg)) hits.push(seg);
        }
        const independent = hits.filter((seg, idx) =>
          !hits.some((other, j) => j !== idx && other !== seg && other.includes(seg))
        );
        if (independent.length >= 2 && low.length >= 10
          && low.length >= Math.min(joined.length - 2, independent.join("").length)) {
          return true;
        }
        // 营销段 + 品牌段粘在候选里：apps 与 dingding 同时出现
        const hasMkt = hyphenSegs.some((seg) => mktSegOnly.test(seg) && low.includes(seg));
        const hasBrandSeg = hyphenSegs.some((seg) => !mktSegOnly.test(seg) && seg.length >= 4 && low.includes(seg));
        if (hasMkt && hasBrandSeg && low.length >= 8 && nearHostFlat(joined) === false) {
          // Dingappsdingdin 含 apps+ding；即使 edit 距离已在 near 捕获，这里兜底
          if (low.length >= joined.length - 2) return true;
        }
      }

      // 候选等于主机标签整段 → 一律当碎片（禁止「仿冒「Huorongr」/「HuorongLab」」）
      // 干净正站核（dingtalk）仅当 apex 干净且候选==apex 且无夹带时才放行
      if (labFlat && low === labFlat) {
        // 连字符标签整段（huorong-lab → HuorongLab）绝不当展示，优先于 padCore 误等于 flat
        if (/-/.test(labelRaw)) return true;
        if (padCore && padCore === low && apexFlat === low
          && !(typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(labelRaw))) {
          return false;
        }
        if (padCore && padCore !== low && low.includes(padCore)) return true;
        // 默认同名主机标签不当展示品牌
        return true;
      }
      if (apexFlat && low === apexFlat && low.length >= 5) {
        // 连字符 apex 整段拼写（huorong-lab）一律碎片
        if (/-/.test(String((cores && cores.apexLeftRaw) || labelRaw || ""))) return true;
        // apex 自身是干净品牌核（dingtalk.com）→ 不当碎片
        if (padCore && padCore === low
          && !(typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
            && NS.apexLabelLooksLikeMarketingPaddedBrand(apexFlat))) {
          return false;
        }
        // apex 是夹带整段（vdingtalk / iehuorong / huorongpc / huorongr）
        if (padCore && padCore.length >= 4 && low !== padCore && low.includes(padCore)) return true;
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const c2 = NS.inferMarketingPaddedBrandCore(apexFlat) || NS.inferMarketingPaddedBrandCore(
            // 尝试还原连字符：vdingtalk 无法还原，靠 glued 推断
            apexFlat
          );
          if (c2 && c2.length >= 4 && c2 !== low && low.includes(c2)) return true;
        }
        // 单字母尾缀：huorongr
        if (low.length >= 6 && /^[a-z]{5,}[a-z0-9]$/i.test(low)) return true;
        // 单字母/短前缀粘连：v+dingtalk、x+todesk
        if (/^[vxz][a-z]{5,}$/i.test(low) || /^(?:aa|bb|cc|ca|im|ie|pr|gw|get|ott|seo|vip|my|dl)[a-z]{5,}$/i.test(low)) {
          return true;
        }
        // 默认同名 apex 标签：仿冒 UI 不得用域名当「页内品牌」
        if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(apexFlat)) return true;
      }
      // HuorongLab / Huorong-Soft：主机核 + Lab/Soft 等营销尾，仍是域名衍生展示
      if (labFlat && low.length > labFlat.length && low.startsWith(labFlat)
        && /(?:lab|labs|soft|app|pro|vip|safe|pc|official|inc|ltd|tech|site)$/i.test(low.slice(labFlat.length))) {
        return true;
      }
      if (apexFlat && low.length > apexFlat.length && low.startsWith(apexFlat)
        && /(?:lab|labs|soft|app|pro|vip|safe|pc|official|inc|ltd|tech|site)$/i.test(low.slice(apexFlat.length))) {
        return true;
      }
      // 候选 = 主机核 + Lab（核为单字母尾缀剥除后）：huorong + lab on huorongr.com.cn
      if (padCore && padCore.length >= 5 && low.startsWith(padCore)
        && low.length > padCore.length
        && /^(?:lab|labs|soft|app|pro|vip|safe|pc|official|inc|ltd|tech|site)$/i.test(low.slice(padCore.length))) {
        return true;
      }
      if (root && low === root && padCore && padCore !== low && low.includes(padCore)) return true;
      if (hostFlat && low === hostFlat) return true;

      // 主机 = 营销前缀/后缀 + 核
      if (padCore && padCore.length >= 4) {
        // 剥出的干净核（pr-todesk → todesk）本身不是复合碎片。
        // 仅域名推导、页面从未声明的核会在 collectPrimaryBrandKeywords 的
        // domain-only 门控中被拒绝，避免 qqyinle → Yinle 抢占真实中文品牌。
        if (low === padCore) {
          return false;
        }
        if (low.includes(padCore) && low.length > padCore.length) {
          // vdingtalk 含 dingtalk；候选整段等于主机形态
          if (low === labFlat || low === apexFlat || (labFlat && labFlat.includes(low))
            || (apexFlat && apexFlat.includes(low)) || low === `${padCore}pc` || low === `v${padCore}`) {
            return true;
          }
          // 候选 = 短前缀 + padCore
          if (low.endsWith(padCore) && low.length - padCore.length <= 4) return true;
        }
      }
      // 无 padCore：候选等于去连字符 label 且 label 含连字符
      if (/-/.test(labelRaw) && low === labFlat) return true;
      // 结构：候选像「1–3 字母前缀 + 长品牌」，且出现在主机 flat 里
      if (/^[a-z]{1,3}[a-z]{5,16}$/i.test(low) && hostFlat.includes(low)) {
        const m = low.match(/^([a-z]{1,3})([a-z]{5,16})$/i);
        if (m) {
          const pre = m[1].toLowerCase();
          const rest = m[2].toLowerCase();
          if ((pre.length <= 2 || (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(pre)))
            && rest.length >= 5
            && (apexFlat === low || labFlat === low || hostFlat.includes(low))) {
            return true;
          }
        }
      }
      return false;
    } catch { return false; }
  };

  /**
   * 从夹带形态 token 剥出品牌核：vdingtalk→dingtalk，iehuorong→huorong。
   * 仅结构启发，供展示名回退（勿当 related 正站）。
   */
  NS.stripMarketingHostPrefixFromToken = function (token) {
    try {
      const raw = String(token || "").toLowerCase();
      // 连字符：j-dingtalk / v-dingtalk → dingtalk；dingtalk-o → dingtalk
      if (/-/.test(raw)) {
        const parts = raw.split("-").filter(Boolean).map((p) => p.replace(/[^a-z0-9]/g, ""));
        if (parts.length >= 2) {
          const first = parts[0] || "";
          const last = parts[parts.length - 1] || "";
          const rest = parts.slice(1).join("");
          // 长核 + 短垃圾尾（与 inferMarketingPaddedBrandCore 对齐）
          if (parts.length === 2
            && first.length >= 5 && last.length <= 2
            && /^[a-z0-9]{1,2}$/i.test(last)
            && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(last)) {
            return first.toLowerCase();
          }
          if (rest.length >= 4
            && (first.length === 1 || (typeof NS.isMarketingHostPrefixToken === "function"
              && NS.isMarketingHostPrefixToken(first)))) {
            // pc-todeskr → 先 rest=todeskr，再交给 infer 收污染尾 → todesk
            if (typeof NS.inferMarketingPaddedBrandCore === "function") {
              const refined = NS.inferMarketingPaddedBrandCore(raw)
                || NS.inferMarketingPaddedBrandCore(rest);
              if (refined && refined.length >= 4) return refined.toLowerCase();
            }
            return rest.toLowerCase();
          }
        }
      }
      const low = raw.replace(/[^a-z0-9]/g, "");
      if (!low || low.length < 6) return "";
      // totodesk → todesk（与 inferMarketingPaddedBrandCore 一致）
      const toTo = low.match(/^to(to[a-z0-9]{3,16})$/i);
      if (toTo && toTo[1]) return toTo[1].toLowerCase();
      // 无分隔符时只接受高置信单字母频道前缀 v/x/z。j/e/a/s 仅在上方
      // 连字符分支中成立，否则 steam/spotify/amazon 等正常词会被误剥首字母。
      const m = low.match(/^(v|x|z|aa|bb|cc|ca|im|ie|pr|gw|get|ott|seo|cdn|vip|pro|my|pc|app|dl|qq|wx|hd|tv)([a-z][a-z0-9]{4,18})$/i);
      if (m && m[2] && m[2].length >= 5) {
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const refined = NS.inferMarketingPaddedBrandCore(m[2]);
          if (refined && refined.length >= 4) return refined.toLowerCase();
        }
        return m[2].toLowerCase();
      }
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const c = NS.inferMarketingPaddedBrandCore(low);
        if (c && c.length >= 4 && c !== low) return c;
      }
      return "";
    } catch { return ""; }
  };

  /**
   * 仿冒 UI 展示名：夹带主机剥核后格式化（j-dingtalk → DingTalk）。
   * 仅作页内选举失败时的兜底，不替代 collectPrimaryBrandKeywords 冠军。
   */
  NS.formatSpoofDisplayFromHostCore = function (hostOpt) {
    try {
      const host = NS.normalizeDomain(hostOpt || (typeof location !== "undefined" ? location.hostname : ""));
      if (!host) return "";
      let core = "";
      if (typeof NS.resolveHostBrandCore === "function") core = NS.resolveHostBrandCore(host) || "";
      if (!core && typeof NS.collectHostBrandCores === "function") {
        const cores = NS.collectHostBrandCores(host);
        core = (cores && (cores.padCore || (cores.voteLatin && cores.voteLatin[0]))) || "";
      }
      if (!core) {
        const labelRaw = (host.split(".")[0] || "").toLowerCase();
        if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
          core = NS.stripMarketingHostPrefixFromToken(labelRaw) || "";
        }
      }
      core = String(core || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!core || core.length < 4) return "";
      const labFlat = (host.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      // 整段主机标签不能直接当品牌展示；只有明确营销结构剥核成功才使用。
      // 中文/拉丁页面候选的污染尾确认由双向 matcher 完成。
      if (core === labFlat) {
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const peeled = NS.inferMarketingPaddedBrandCore(labFlat) || "";
          if (peeled && peeled.length >= 4 && peeled !== core) core = peeled;
          else return "";
        } else return "";
      }
      // 整段主机拼写核（huoronglab）不当展示——再剥营销尾 lab/pc 等
      try {
        const labelRaw0 = (host.split(".")[0] || "").toLowerCase();
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const peeled2 = NS.inferMarketingPaddedBrandCore(labelRaw0)
            || NS.inferMarketingPaddedBrandCore(labFlat) || "";
          if (peeled2 && peeled2.length >= 4 && peeled2 !== labFlat
            && (core === labFlat || !core || core.includes(peeled2))) {
            core = peeled2;
          }
        }
        // 残片仍带 lab 尾：huoronglab → huorong
        if (core && /(?:lab|labs)$/i.test(core) && core.length >= 7) {
          const stem = core.replace(/(?:lab|labs)$/i, "");
          if (stem.length >= 4) core = stem;
        }
      } catch { /* ignore */ }
      if (typeof NS.isHostShapedCompoundBrandToken === "function"
        && NS.isHostShapedCompoundBrandToken(core, host)) return "";
      // ★ 轻量：标题壳中文（钉钉应用中心→钉钉），禁止 resolveChinese/pinyin 重计算（全站卡死）
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          const tb = NS.extractChineseBrandFromPageTitle();
          if (tb && /[一-鿿]{2,}/.test(tb)) return tb;
        }
      } catch { /* ignore */ }
      try {
        if (typeof NS.pickChineseBrandFromPageSurface === "function") {
          const title = String(document.title || "");
          const cn = NS.pickChineseBrandFromPageSurface(title)
            || NS.pickChineseBrandFromPageSurface(String(document.querySelector("h1")?.textContent || ""));
          if (cn && /[一-鿿]{2,}/.test(cn)) return cn;
        }
      } catch { /* ignore */ }
      if (typeof NS.formatBrandTokenForDisplay === "function") {
        return NS.formatBrandTokenForDisplay(core) || "";
      }
      return core.charAt(0).toUpperCase() + core.slice(1);
    } catch {
      return "";
    }
  };

  /**
   * 候选品牌与当前主机是否域名对齐（0=否 / 1=弱 / 2=强）。
   * 数字门户 app-4399↔4399；拉丁 huorong.cn↔huorong；中文靠 bridge 或数字。
   */
  NS.candidateDomainAligned = function (cand, hostOpt) {
    try {
      const c0 = String(cand || "").trim();
      if (!c0 || c0.length < 2) return 0;
      const cores = typeof NS.collectHostBrandCores === "function"
        ? NS.collectHostBrandCores(hostOpt)
        : null;
      if (!cores) return 0;
      const flat = cores.flat || "";
      const labelRaw = cores.labelRaw || "";
      const lab = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");

      // 纯数字门户
      if (/^\d{3,6}$/.test(c0)) {
        if (cores.digits && cores.digits.includes(c0)) return 2;
        if (flat.includes(c0) || lab.includes(c0)) return 2;
        return 0;
      }
      // 中文/混合：数字前缀（2345看图王）
      const digCn = (c0.match(/^(\d{2,6})/) || [])[1] || "";
      if (digCn && digCn.length >= 3) {
        if (cores.digits && cores.digits.includes(digCn)) return 2;
        if (flat.includes(digCn) || lab.includes(digCn)) return 2;
      }
      // 拉丁
      const low = c0.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (/^[a-z0-9]+$/i.test(low) && low.length >= 3) {
        // 夹带整段主机（iehuorong/huorongpc）不当强对齐——强对齐只给品牌核
        if (typeof NS.isHostShapedCompoundBrandToken === "function"
          && NS.isHostShapedCompoundBrandToken(low, hostOpt || (cores && cores.labelRaw))) {
          // 若候选本身是 padCore 则仍强对齐
          if (!(cores.padCore && cores.padCore === low)) return 0;
        }
        // 计票核（voteLatin）命中 → 强
        if (cores.voteLatin && cores.voteLatin.some((x) => x === low)) return 2;
        if (cores.padCore && cores.padCore === low) return 2;
        if (cores.latin && cores.latin.some((x) => x === low) && !(cores.padded && low === lab)) {
          // 干净主机上的 apex 核
          if (!cores.padded && (lab === low || cores.apexLabel === low || cores.root === low)) return 2;
          return 1;
        }
        if (!cores.padded && (lab === low || cores.apexLabel === low || cores.root === low)) return 2;
        // 三字母页面品牌位于域名开头时给弱对齐（wpsxls ↔ WPS）。
        // 只作为页面候选的并列裁决，不允许域名字段自行创造该品牌。
        if (low.length === 3 && lab.startsWith(low) && lab.length >= low.length + 2) return 1;
        if (low.length >= 4 && (lab.includes(low) || (low.includes(lab) && lab.length >= 4))) return 1;
        if (low.length >= 4 && flat.includes(low) && !cores.padded) return 1;
        // 营销前缀夹带：ott-todesk ↔ todesk（弱对齐，核在 voteLatin 时已是 2）
        if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function"
          && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, low)) return cores.padCore === low ? 2 : 1;
        if (typeof NS.hostLabelIsPaddedBrand === "function"
          && (NS.hostLabelIsPaddedBrand(lab, low) || NS.hostLabelIsPaddedBrand(labelRaw, low))) {
          return cores.padCore === low ? 2 : 1;
        }
        return 0;
      }
      // 中文：选举热路径禁止 pinyin。仅 title 含中文 + padCore → 弱/强对齐
      if (/[一-鿿]/.test(c0)) {
        try {
          const pad = String(cores.padCore || "").toLowerCase();
          const title = String((typeof document !== "undefined" ? document.title : "") || "");
          if (pad.length >= 4 && title.includes(c0)) return 2;
          if (title.includes(c0) && (cores.padded || /-/.test(String(cores.labelRaw || "")))) return 1;
        } catch { /* ignore */ }
      }
      return 0;
    } catch { return 0; }
  };

  /**
   * 中文 → 无调拼音：委托 pinyin-pro（brand-domain-match.js / brandPinyin）。
   * 不再维护自建汉字表。需先 npm install && npm run vendor:libs。
   */
  NS.chineseToPinyinFlat = function (text) {
    try {
      if (typeof NS.brandPinyin === "function") {
        const py = NS.brandPinyin(text);
        if (py) return py;
      }
      // 兼容：直接读 globalThis.pinyinPro
      const api = (typeof globalThis !== "undefined" && (globalThis.__silverfoxPinyinPro || globalThis.pinyinPro)) || null;
      if (api && typeof api.pinyin === "function") {
        const r = api.pinyin(String(text || ""), {
          toneType: "none",
          type: "array",
          nonZh: "consecutive",
          v: true
        });
        const joined = Array.isArray(r) ? r.join("") : String(r || "");
        return String(joined).toLowerCase().replace(/[^a-z0-9]/g, "");
      }
      return "";
    } catch {
      return "";
    }
  };

  // pickChineseBrandMatchingLatinCore：防重入 + 短缓存（避免扫描路径连环调用卡死主线程）
  let _cnPyMatchBusy = false;
  const _cnPyMatchCache = new Map();
  const _CN_PY_MATCH_CACHE_MAX = 32;

  /** 拼音库晚到时清缓存，避免把「未加载时的空结果」永久钉死 */
  NS.clearChinesePinyinMatchCache = function () {
    try { _cnPyMatchCache.clear(); } catch { /* ignore */ }
  };

  /**
   * 用 pinyin-pro 把拉丁主机核（dingding / huorong）对齐到页内中文（钉钉 / 火绒）。
   * 拼音库只做 中文→拼音，不能反查；须从页面抽中文再比拼音。
   *
   * 性能约束：
   * - 禁止调用 collectPrimaryBrandKeywords
   * - 短身份槽 + 有限 2 字窗；命中全等拼音立即返回
   * - 拼音未加载时返回 "" 且不缓存
   *
   * @param {string} latinCore 已剥夹带的拉丁核，如 dingding
   * @param {string} [blobOpt] 可选短文本
   * @returns {string} 匹配的中文展示名，或 ""
   */
  NS.pickChineseBrandMatchingLatinCore = function (latinCore, blobOpt) {
    try {
      const core = String(latinCore || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!core || core.length < 4 || core.length > 24) return "";
      if (_cnPyMatchBusy) return "";

      const hostKey = (() => {
        try {
          return String((typeof location !== "undefined" ? location.hostname : "") || "");
        } catch { return ""; }
      })();
      const titleKey = (() => {
        try { return String(document.title || "").slice(0, 80); } catch { return ""; }
      })();
      const cacheKey = `${core}|${hostKey}|${titleKey}`;
      if (_cnPyMatchCache.has(cacheKey)) return _cnPyMatchCache.get(cacheKey);
      const cachePut = (val) => {
        if (_cnPyMatchCache.size >= _CN_PY_MATCH_CACHE_MAX) {
          const first = _cnPyMatchCache.keys().next().value;
          if (first != null) _cnPyMatchCache.delete(first);
        }
        _cnPyMatchCache.set(cacheKey, val);
        return val;
      };

      const pyOf = (cn) => {
        try {
          if (typeof NS.chineseToPinyinFlat === "function") {
            const p = NS.chineseToPinyinFlat(cn);
            if (p) return p;
          }
          if (typeof NS.brandPinyin === "function") {
            const p = NS.brandPinyin(cn);
            if (p) return p;
          }
        } catch { /* ignore */ }
        return "";
      };
      // 未加载：不缓存空结果（否则拼音晚到永远钉死 Dingding）
      if (!pyOf("火") && !pyOf("安") && !pyOf("钉")) return "";

      _cnPyMatchBusy = true;
      try {
        // ★ 优先 pinyin-pro.match：在 title/正文中直接定位「钉钉」↔ dingding
        try {
          if (typeof NS.findChineseBrandByPinyinInText === "function") {
            const hit = NS.findChineseBrandByPinyinInText(core, blobOpt || "");
            if (hit && /^[一-鿿]{2,8}$/.test(hit)) return cachePut(hit);
          }
        } catch { /* fall through */ }

        // 对齐主机全形态（ding-apps-dingding → dingding），勿只比单一 core
        const hostForms = (() => {
          try {
            if (typeof NS.collectHostLatinFormsForPinyin === "function") {
              return NS.collectHostLatinFormsForPinyin();
            }
          } catch { /* ignore */ }
          return core ? [core] : [];
        })();
        const pyMatchesCore = (py) => {
          if (!py || py.length < 3) return false;
          if (py === core) return true;
          if (hostForms.some((f) => f === py)) return true;
          if (py.startsWith(core) && py.length - core.length <= 10) return true;
          if (core.startsWith(py) && core.length - py.length <= 8 && py.length >= 4) return true;
          // dingappsdingding 含 dingding；huorongr 以 huorong 为前缀
          if (hostForms.some((f) => f && (
            (f.startsWith(py) && f.length - py.length <= 8)
            || (f.includes(py) && py.length >= 4 && f.length - py.length <= 12)
          ))) return true;
          return false;
        };

        const isBadCn = (cn) => {
          const s = String(cn || "").trim();
          if (!s || s.length < 2 || s.length > 8) return true;
          if (!/^[一-鿿]{2,8}$/.test(s)) return true;
          if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(s)) return true;
          if (typeof NS.looksLikeFunctionalClaimBrandToken === "function" && NS.looksLikeFunctionalClaimBrandToken(s)) return true;
          if (/^(?:音乐|安全|杀毒|卫士|软件|下载|官网|官方|客户端|浏览器|技术|支持|关于|首页|中心|系统)$/.test(s)) return true;
          return false;
        };

        const candidates = [];
        const seen = Object.create(null);
        const push = (raw) => {
          if (candidates.length >= 16) return;
          let s = String(raw || "").trim();
          if (!s || !/[一-鿿]/.test(s)) return;
          s = s.replace(/(?:官方网站|官网|官方|免费下载|下载|客户端|正版).*$/u, "").trim();
          const onlyCn = s.replace(/[^\u4e00-\u9fff]/g, "");
          if (onlyCn.length >= 2 && onlyCn.length <= 8) s = onlyCn;
          if (typeof NS.normalizeChineseBrandToken === "function") {
            const n = NS.normalizeChineseBrandToken(s);
            if (n && /^[一-鿿]{2,8}$/.test(n)) s = n;
          }
          if (isBadCn(s) || seen[s]) return;
          seen[s] = 1;
          candidates.push(s);
        };

        // 短身份槽（含 logo 文案，钉钉常出现在 logo/span）
        let blob = String(blobOpt || "").slice(0, 480);
        if (!blob) {
          try {
            blob = [
              String(document.title || "").slice(0, 140),
              String(document.querySelector("h1")?.textContent || "").slice(0, 100),
              String(document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "").slice(0, 60),
              String(document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "").slice(0, 80),
              String(document.querySelector('meta[name="keywords"]')?.getAttribute("content") || "").slice(0, 140),
              String(document.querySelector(".logo, [class*='logo']")?.textContent || "").slice(0, 40)
            ].filter(Boolean).join(" ").slice(0, 480);
          } catch {
            blob = String(document.title || "").slice(0, 140);
          }
        }

        try {
          if (typeof NS.pickChineseBrandFromPageSurface === "function") {
            push(NS.pickChineseBrandFromPageSurface(String(document.title || "").slice(0, 140)));
            push(NS.pickChineseBrandFromPageSurface(String(document.querySelector("h1")?.textContent || "").slice(0, 100)));
            push(NS.pickChineseBrandFromPageSurface(blob));
          }
        } catch { /* ignore */ }

        // 中文 run：整段 + 2 字窗（钉钉嵌在「官方钉钉客户端」中间）
        const runs = String(blob).match(/[一-鿿]{2,10}/g) || [];
        for (let ri = 0; ri < Math.min(runs.length, 14); ri++) {
          const run = runs[ri];
          push(run);
          // 2 字窗优先：钉钉 / 火绒 全拼常整等于 core
          const maxStart = Math.min(run.length - 2, 6);
          for (let i = 0; i <= maxStart; i++) {
            const pair = run.slice(i, i + 2);
            // 先直接拼音全等 → 立刻返回（Dingding→钉钉）
            if (!isBadCn(pair)) {
              const pyFast = pyOf(pair);
              if (pyFast === core) return cachePut(pair);
            }
            push(pair);
          }
          if (run.length >= 3) {
            push(run.slice(0, 3));
            push(run.slice(0, 4));
          }
        }

        let best = "";
        let bestScore = -1;
        const limit = Math.min(candidates.length, 16);
        for (let i = 0; i < limit; i++) {
          const cn = candidates[i];
          const py = pyOf(cn);
          if (!pyMatchesCore(py)) continue;
          let score = 0;
          if (py === core) score = 100 + (10 - Math.min(cn.length, 10));
          else if (py.startsWith(core)) score = 80 - (py.length - core.length);
          else score = 50;
          if (cn.length === 2) score += 8;
          if (score > bestScore) {
            bestScore = score;
            best = cn;
          }
          // 全等 2 字专名足够好
          if (py === core && cn.length === 2) break;
        }
        return cachePut(best);
      } finally {
        _cnPyMatchBusy = false;
      }
    } catch {
      _cnPyMatchBusy = false;
      return "";
    }
  };

  /** @deprecated 已移除自建拼音表；保留空实现以免旧调用抛错 */
  NS._ensureHanziPinyin = function () {
    return Object.create(null);
  };

  /**
   * 从中文品牌抽出「品类尾」候选（算法：取尾部 2～6 字，长优先；非固定品类名单）。
   * 会跳过纯弱/功能词；优先保留含产品意味的尾段。
   */
  NS.extractChineseProductMorphSuffixes = function (cnBrand) {
    try {
      let brand = String(cnBrand || "").replace(/\s+/g, "");
      brand = brand
        .replace(/(?:电脑版|手机版|官方网站|官方网站首页)$/g, "")
        .replace(/(?:官网|官方|下载|客户端|正版|免费|首页|网站)$/g, "")
        .trim();
      if (!brand || !/[一-鿿]/.test(brand)) return [];
      const onlyCn = brand.replace(/[^\u4e00-\u9fff]/g, "");
      if (onlyCn.length < 2) return [];
      const out = [];
      const seen = Object.create(null);
      // 长尾优先：音乐播放器 > 播放器 > 音乐
      for (let len = Math.min(6, onlyCn.length); len >= 2; len--) {
        const suf = onlyCn.slice(onlyCn.length - len);
        if (seen[suf]) continue;
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(suf)
          && len <= 2) continue;
        // 整段品牌本身也可作「全拼」候选（仅当较短）
        seen[suf] = 1;
        out.push(suf);
      }
      // 专名过长时：再补「去掉首 1～2 字后的尾段」已由 slice 覆盖
      return out;
    } catch {
      return [];
    }
  };

  /**
   * 域名里常见的「软件品类英文尾」（结构垫词，不是品牌）。
   * 与页内中文品类尾的语义对齐靠拼音主拼音节启发 + 共现，见 matchLatinPadToChineseMorph。
   */
  NS.isLatinSoftwareProductDomainPad = function (suf) {
    const s = String(suf || "").toLowerCase().replace(/[^a-z]/g, "");
    if (!s || s.length < 4 || s.length > 14) return false;
    // 含拼音品类尾 yinyue/yinle：qqyinle / xxxyinyue 粘连
    return /^(?:musics?|yinyue|yinle|yingyue|player|browser|client|security|secure|antivirus|antimalware|desktop|guard|office|cloud|input|setup|installer|download|soft|app)$/i.test(s);
  };

  /**
   * 拉丁主机尾 是否对齐 中文品类尾（算法）：
   * 1) 等于 chineseToPinyin(中文尾)
   * 2) 与主拼编辑距离 ≤2（yingyue≈yinyue）
   * 3) 是软件品类英文尾，且中文尾能转出拼音（表示页内确有产品形态）
   */
  NS.matchLatinPadToChineseMorph = function (latinSuffix, cnMorph) {
    try {
      const suf = String(latinSuffix || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const morph = String(cnMorph || "").replace(/\s+/g, "");
      if (!suf || suf.length < 3 || !morph || !/[一-鿿]/.test(morph)) return false;
      const py = typeof NS.chineseToPinyinFlat === "function" ? NS.chineseToPinyinFlat(morph) : "";
      if (py && py.length >= 3) {
        if (suf === py) return true;
        if (typeof NS.editDistanceShort === "function"
          && Math.abs(suf.length - py.length) <= 2
          && NS.editDistanceShort(suf, py) <= 2) return true;
      }
      // 英文品类垫：须与中文品类「同域」——用拼音音节启发（yin*↔music 不可靠）
      // 改为：中文尾含典型产品字 + 拉丁为软件品类垫词
      if (typeof NS.isLatinSoftwareProductDomainPad === "function"
        && NS.isLatinSoftwareProductDomainPad(suf)) {
        // 语义粗对齐：音乐类中文 ↔ music/player；安全类 ↔ security…
        if (/音乐|播放|歌曲|听歌/.test(morph) && /^musics?|player|audio|song/i.test(suf)) return true;
        if (/安全|杀毒|卫士|防护|杀软/.test(morph) && /security|secure|antivirus|antimalware|guard|protect/i.test(suf)) return true;
        if (/浏览/.test(morph) && /browser/i.test(suf)) return true;
        if (/客户端|客户/.test(morph) && /client|app/i.test(suf)) return true;
        if (/桌面|远程/.test(morph) && /desktop|remote/i.test(suf)) return true;
        if (/办公/.test(morph) && /office/i.test(suf)) return true;
        if (/网盘|云盘|云/.test(morph) && /cloud|disk|drive/i.test(suf)) return true;
        if (/输入/.test(morph) && /input|ime/i.test(suf)) return true;
      }
      return false;
    } catch {
      return false;
    }
  };

  /** 品类前缀是否像营销壳而非品牌核 */
  NS.isGenericProductCategoryHostPrefix = function (prefix) {
    const p = String(prefix || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!p || p.length < 2 || p.length > 18) return true;
    return /^(?:free|best|top|new|my|the|get|app|web|online|china|chinese|cloud|smart|super|mega|mini|pro|vip|hot|cool|fast|safe|soft|down|download|official|client|mobile|android|ios|pc|win|www\d*|http|https|api|news|blog|forum)$/i.test(p);
  };

  /**
   * 主机是否「拉丁前缀 + 中文产品品类拉丁尾」结构。
   * 有 cnBrandOpt 时：用拼音算法把页内中文品类尾对齐到主机尾（qishuiyinyue / qishuimusic）。
   * 无品牌时：仅识别「前缀 + 软件品类英文尾」结构垫（不发明中文品类名）。
   *
   * @returns {{ prefix: string, suffix: string, chineseSuffix: string }|null}
   */
  NS.parseHostChineseProductCategoryPad = function (hostLabel, cnBrandOpt) {
    try {
      const raw = String(hostLabel || "").toLowerCase().replace(/^www\./, "");
      const lab = raw.replace(/[^a-z0-9]/g, "");
      if (lab.length < 6) return null;

      const brandRaw = String(cnBrandOpt || "").replace(/\s+/g, "");
      const morphs = brandRaw && typeof NS.extractChineseProductMorphSuffixes === "function"
        ? NS.extractChineseProductMorphSuffixes(brandRaw)
        : [];

      let best = null;
      let bestSufLen = 0;

      // A) 页内中文品类 → 拼音 / 英文对齐
      if (morphs.length) {
        for (let mi = 0; mi < morphs.length; mi++) {
          const morph = morphs[mi];
          const py = typeof NS.chineseToPinyinFlat === "function" ? NS.chineseToPinyinFlat(morph) : "";
          const candidates = [];
          if (py && py.length >= 3) candidates.push(py);
          // 扫描主机所有合理尾长，用 matchLatinPadToChineseMorph 判定
          const minLen = 3;
          const maxLen = Math.min(lab.length - 2, Math.max(py.length + 2, 12));
          for (let actualLen = maxLen; actualLen >= minLen; actualLen--) {
            const actualSuffix = lab.slice(-actualLen);
            const prefix = lab.slice(0, lab.length - actualLen);
            if (typeof NS.isGenericProductCategoryHostPrefix === "function"
              && NS.isGenericProductCategoryHostPrefix(prefix)) continue;
            if (typeof NS.matchLatinPadToChineseMorph === "function"
              && NS.matchLatinPadToChineseMorph(actualSuffix, morph)) {
              if (actualLen > bestSufLen) {
                bestSufLen = actualLen;
                best = { prefix, suffix: actualSuffix, chineseSuffix: morph };
              }
              break; // 该 morph 已取最长命中
            }
          }
          // 精确/近拼音快速路径
          for (let ci = 0; ci < candidates.length; ci++) {
            const form = candidates[ci];
            if (lab.endsWith(form) && lab.length > form.length) {
              const prefix = lab.slice(0, lab.length - form.length);
              if (!NS.isGenericProductCategoryHostPrefix(prefix) && form.length > bestSufLen) {
                bestSufLen = form.length;
                best = { prefix, suffix: form, chineseSuffix: morph };
              }
            }
            if (typeof NS.editDistanceShort === "function" && form.length >= 4) {
              const minL = Math.max(3, form.length - 2);
              const maxL = Math.min(lab.length - 2, form.length + 2);
              for (let al = maxL; al >= minL; al--) {
                const actual = lab.slice(-al);
                const prefix = lab.slice(0, lab.length - al);
                if (NS.isGenericProductCategoryHostPrefix(prefix)) continue;
                const d = NS.editDistanceShort(actual, form);
                if (d >= 1 && d <= 2 && al > bestSufLen) {
                  bestSufLen = al;
                  best = { prefix, suffix: actual, chineseSuffix: morph };
                }
              }
            }
          }
        }
      }

      // B) 无页内品牌：仅结构「前缀 + 软件品类英文尾」
      if (!best) {
        for (let len = 12; len >= 4; len--) {
          if (lab.length <= len) continue;
          const suf = lab.slice(-len);
          const prefix = lab.slice(0, lab.length - len);
          if (NS.isGenericProductCategoryHostPrefix(prefix)) continue;
          if (typeof NS.isLatinSoftwareProductDomainPad === "function"
            && NS.isLatinSoftwareProductDomainPad(suf)) {
            best = { prefix, suffix: suf, chineseSuffix: "" };
            break;
          }
        }
      }
      return best;
    } catch {
      return null;
    }
  };

  /**
   * 页内中文产品品牌 vs 域名：结构仿冒。
   * 优先走 checkBrandDomain（pinyin-pro 多候选 + tldts 拆域 + 分词/相似）。
   * 展示品牌由调用方用页内抽词；此处不发明品牌名。
   */
  NS.detectChineseProductCategoryHostSquat = function (hostLabel, cnBrandOpt) {
    try {
      const brandRaw = String(cnBrandOpt || "").replace(/\s+/g, "");
      const brand = brandRaw
        .replace(/(?:电脑版|手机版|官方网站|官方网站首页)$/g, "")
        .replace(/(?:官网|官方|下载|客户端|正版|免费|首页)$/g, "")
        .trim();
      if (!brand || !/[一-鿿]/.test(brand)) return null;

      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(brand)) return null;
      if (typeof NS.looksLikeFunctionalClaimBrandToken === "function"
        && NS.looksLikeFunctionalClaimBrandToken(brand)) return null;

      // 1) checkBrandDomain / squatFromClaim：仅当 pinyin 已在页内（禁止热路径注入大库）
      let pyReady = false;
      try {
        const g = typeof globalThis !== "undefined" ? globalThis : null;
        const api = g && (g.__silverfoxPinyinPro || g.pinyinPro);
        pyReady = !!(api && typeof api.pinyin === "function");
      } catch { pyReady = false; }
      if (pyReady) {
        if (typeof NS.detectBrandDomainSquatFromClaim === "function") {
          const host = String(hostLabel || (typeof location !== "undefined" ? location.hostname : "") || "");
          const hit = NS.detectBrandDomainSquatFromClaim(brand, host);
          if (hit) return hit;
        }
        if (typeof NS.checkBrandDomain === "function") {
          const host = String(hostLabel || (typeof location !== "undefined" ? location.hostname : "") || "");
          const rel = NS.checkBrandDomain({ brand, host });
          if (rel && rel.score >= 45 && rel.score < 90
            && (rel.reasons || []).some((r) => /分词|完全一致|包含|相似|子域名/.test(String(r)))) {
            return {
              brandToken: rel.rootLabel || "",
              hostMatch: rel.score >= 65 ? "typo" : "partial",
              prefix: rel.rootLabel || "",
              suffix: "",
              chineseSuffix: brand,
              expectedHostLabel: rel.rootLabel || "",
              score: rel.score,
              level: rel.level,
              brandForms: rel.brandForms
            };
          }
        }
      }

      // 2) 回退：品类尾结构垫（无 pinyin 也可跑部分路径）
      const pad = typeof NS.parseHostChineseProductCategoryPad === "function"
        ? NS.parseHostChineseProductCategoryPad(hostLabel, brandRaw || brand)
        : null;
      if (!pad || !pad.prefix || !pad.suffix) return null;
      if (!pad.chineseSuffix || !/[一-鿿]/.test(pad.chineseSuffix)) return null;

      const brandHasCat = brand.endsWith(pad.chineseSuffix)
        || brand.includes(pad.chineseSuffix)
        || brandRaw.includes(pad.chineseSuffix);
      if (!brandHasCat) return null;

      try {
        const lab = String(hostLabel || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        const blob = brandRaw.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (lab.length >= 5 && blob && blob.includes(lab)) return null;
      } catch { /* ignore */ }

      return {
        brandToken: pad.prefix,
        hostMatch: "typo",
        prefix: pad.prefix,
        suffix: pad.suffix,
        chineseSuffix: pad.chineseSuffix,
        expectedHostLabel: `${pad.prefix}${pad.suffix}`
      };
    } catch {
      return null;
    }
  };

  /** 兼容旧调用名 */
  NS.detectChineseMusicBrandDomainSquat = function (hostLabel, cnBrandOpt) {
    return typeof NS.detectChineseProductCategoryHostSquat === "function"
      ? NS.detectChineseProductCategoryHostSquat(hostLabel, cnBrandOpt)
      : null;
  };

  /**
   * 域名是否与页内中文品牌对齐（轻量结构，热路径禁用 pinyin）。
   */
  NS.domainLatinRootHintsChineseBrand = function (cnBrand, coresOpt) {
    try {
      const cn = String(cnBrand || "").trim();
      if (!cn || !/[一-鿿]/.test(cn)) return false;
      const cores = coresOpt || (typeof NS.collectHostBrandCores === "function"
        ? NS.collectHostBrandCores()
        : null);
      if (!cores) return false;
      const blob = String((typeof document !== "undefined" ? document.title : "") || "");
      if (!blob.includes(cn)) return false;
      const padCore = String(cores.padCore || cores.apexLabel || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (padCore.length >= 4) return true;
      if (cores.padded || /-/.test(String(cores.labelRaw || ""))) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 是否「自家品牌 apex 下的产品子域」：
   * - shurufa.sogou.com 相对 sogou.com
   * - music.qq.com / y.qq.com 相对 qq.com（2 字母品牌根 + 产品子域，正站）
   * 中文标题「QQ音乐」+ music.qq.com → 官方产品线，非仿冒。
   * 反例：win.qq-musics.com（夹带 apex）不得算正站。
   */
  NS.hostIsProductSubdomainOfBrandApex = function (hostOpt) {
    try {
      // 品牌子域挂在无关第三方 apex 时，不能把第三方主域的成熟度继承成
      // “官方产品子域”身份（huorong-m.softw.com.cn）。
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity(hostOpt)) return false;
      const host = NS.normalizeDomain(hostOpt || location.hostname);
      if (!host || host.split(".").length < 3) return false;
      const apex = NS.getRegistrableDomain(host);
      if (!apex || host === apex || !host.endsWith(`.${apex}`)) return false;
      const apexLeftRaw = (apex.split(".")[0] || "").toLowerCase();
      const apexBrand = apexLeftRaw.replace(/[^a-z0-9]/g, "");
      // 至少 2 字母品牌根（qq.com / jd.com）；单字母 apex 过宽
      if (apexBrand.length < 2) return false;
      // ★ 营销夹带 apex（qq-musics / qqmusics / huorong-pc）下的 win./pc./download.
      // 绝不是 sogou / qq 式正站产品子域
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeftRaw)) {
        return false;
      }
      // 夹带粘连 apex：qqmusics.com.cn 本身不是「干净根」
      if (/^(?:qq|wx|weixin)(?:music|musics|yinyue|yinle)/i.test(apexBrand) && apexBrand.length > 4) {
        return false;
      }
      // 子域标签（可多级 a.b.qq.com → a.b）
      const sub = host.slice(0, -(apex.length + 1));
      if (!sub) return false;
      const subHead = (sub.split(".")[0] || sub).toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!subHead) return false;
      // 纯 www 不当产品子域
      if (/^(?:www|www\d*)$/i.test(subHead)) return false;
      // 仿冒常用营销前缀子域挂干净根（win.xxx.com）——不当正站产品线
      if (/^(?:win|pc|app|download|down|dl|soft|vip|free|get|safe|official)$/i.test(subHead)) {
        return false;
      }
      // 2 字母品牌根：允许 music / y / v / wap 等短产品子域（music.qq.com / y.qq.com）
      if (apexBrand.length === 2) {
        if (subHead.length >= 1 && subHead.length <= 24 && !/[-_]/.test(sub)) return true;
        return false;
      }
      // ≥3 字母品牌根：任意非营销子域（shurufa.sogou.com）
      return true;
    } catch { return false; }
  };

  /**
   * 主机是否「干净品牌根上的官方产品子域」且与页内品牌不冲突。
   * 用于 domain-keyword related 与仿冒跳过（music.qq.com + QQ音乐）。
   */
  NS.hostLooksLikeOfficialProductSubdomain = function (hostOpt, kwOpt) {
    try {
      if (typeof NS.hostNeedsAuthoritativeBrandIdentity === "function"
        && NS.hostNeedsAuthoritativeBrandIdentity(hostOpt)) return false;
      if (typeof NS.hostIsProductSubdomainOfBrandApex !== "function"
        || !NS.hostIsProductSubdomainOfBrandApex(hostOpt)) return false;
      const host = NS.normalizeDomain(hostOpt || location.hostname);
      const apex = NS.getRegistrableDomain(host) || host;
      const apexLeft = (apex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (apexLeft.length < 2) return false;
      // ★ 干净 2 字母品牌根上的产品子域（y.qq.com / music.qq.com / v.qq.com）：
      // 攻击者拿不到 qq.com 下任意子域；不依赖 document_start 时仍为空的标题关键词。
      // 曾误报：标题「QQ音乐」+ y.qq.com 在关键词未就绪时被判「域名与品牌无关」。
      if (apexLeft.length === 2 && host !== apex && host.endsWith(`.${apex}`)) {
        const padApex = typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
          && NS.apexLabelLooksLikeMarketingPaddedBrand(apexLeft);
        if (!padApex) return true;
      }
      // 页内 blob 含 apex 品牌拉丁，或中文身份（QQ音乐含 QQ / 腾讯 场景）
      const kw = kwOpt || (typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords() : null);
      const blob = String((kw && kw.blob) || document.title || "").toLowerCase();
      const blobFlat = blob.replace(/[^a-z0-9\u4e00-\u9fff]/gi, "");
      if (apexLeft.length >= 2 && (blobFlat.includes(apexLeft) || new RegExp(`\\b${apexLeft}\\b`, "i").test(blob))) {
        return true;
      }
      // 标题/OG 有明确中文产品 + 干净 2 字母根（qq + 音乐/微信 等）
      if (apexLeft.length === 2 && /[一-鿿]{2,}/.test(blob)
        && /官网|官方|下载|客户端|音乐|视频|邮箱|游戏|新闻|地图|云/i.test(blob)) {
        return true;
      }
      // 页内拉丁 token 与子域或 apex 对齐
      const subHead = (host.slice(0, -(apex.length + 1)).split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (kw && kw.latin && kw.latin.some((t) => {
        const low = String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        return low.length >= 3 && (low === subHead || low === apexLeft || subHead.includes(low) || low.includes(subHead));
      })) return true;
      return apexLeft.length >= 3;
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
    if (q.includes(".") && p.endsWith(`.${q}`)) {
      try {
        const qi = typeof NS.parseHostWithTldts === "function" ? NS.parseHostWithTldts(q) : null;
        const pi = typeof NS.parseHostWithTldts === "function" ? NS.parseHostWithTldts(p) : null;
        if (qi && qi.pslAvailable === true) {
          // cn.com/github.io and similar shared suffixes have no registrable
          // domain of their own; their identity cannot be inherited by a
          // tenant below them.
          if (!qi.domain || qi.publicSuffix === q) return false;
          if (pi && pi.pslAvailable === true && pi.domain && qi.domain !== pi.domain) return false;
        }
      } catch { /* retain exact suffix fallback when PSL is unavailable */ }
      return true;
    }
    return false;
  };

  /**
   * 采集标题文本。优先 textContent，避免 innerText 触发布局/样式计算，
   * 从而把站点自身的 Mixed Content 自动升级日志堆栈误指到扩展。
   */
  NS.collectHeadingText = function (maxLen = 4000) {
    const parts = [];
    let total = 0;
    try {
      const nodes = document.querySelectorAll("h1, h2, h3, h4, h5, h6");
      const n = Math.min(nodes.length, 80);
      for (let i = 0; i < n; i++) {
        try {
          // 勿用 innerText：会 force layout，Chrome 将 Mixed Content 升级日志挂到本栈
          const t = String(nodes[i].textContent || "").replace(/\s+/g, " ").trim();
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
          const t = String(el.textContent || "").replace(/\s+/g, " ").trim();
          if (t.length >= 12 && t.length <= 800) chunks.push(t);
        } catch { /* ignore */ }
      });
    } catch { /* ignore */ }
    if (!chunks.length) {
      try {
        const body = (document.body && document.body.textContent) || "";
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

  // 协议/扩展/通用技术缩写（仅拉丁）——绝不当仿冒展示品牌
  // 中文品牌合法性不走本表；用 pinyin-pro 与主机双向校验（chinesePinyinAlignsHost）
  const BRAND_TOKEN_STOP_RE = /^(?:https?|http|www|html|htm|com|net|org|css|js|png|jpg|jpeg|gif|svg|webp|json|xml|php|asp|aspx|true|false|null|undefined|ssl|tls|ftp|sftp|ssh|dns|cdn|api|vpn|tcp|udp|smtp|imap|pop3|sql|cpu|gpu|ram|ssd|hdd|usb|wifi|lan|wan|ip|ipv4|ipv6|url|uri|web|app|pc|os|id|ui|ux|seo|cms|sdk|ide|cli|gui|ocr|pdf|zip|rar|exe|dmg|msi|apk|iso|git|npm|cdn|tls1|ssl2|ssl3|http2|http3)$/i;
  NS.BRAND_TOKEN_STOP_RE = BRAND_TOKEN_STOP_RE;

  /**
   * 资源/图标/构建/CMS/版权垃圾 token（B1icon13、Cover、Reserved…）绝不当品牌。
   * Reserved 来自页脚 All Rights Reserved，曾抢占「火绒」展示名。
   */
  NS.looksLikeAssetGarbageToken = function (token) {
    const raw = String(token || "").trim();
    // 本函数只识别拉丁资源/CSS/CMS token。纯中文身份词必须交给
    // isWeakChineseBrandToken 判断；先删中文再检查会把所有中文品牌误判为空垃圾。
    if (/[一-鿿]/.test(raw) && !/[A-Za-z]/.test(raw)) return false;
    const s = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
    // 混合产品名不能先删中文再按纯拉丁长度判断：QQ音乐会被误看成 qq。
    if (/[一-鿿]/.test(raw) && /[A-Za-z]/.test(raw)) {
      if (/^[A-Z]{2}[一-鿿]{1,8}$/.test(raw)) return false;
    }
    if (!s || s.length < 3) return true;
    if (BRAND_TOKEN_STOP_RE.test(s)) return true;
    // 页脚版权 / 法律英语（All Rights Reserved / Copyright 2024）
    if (/^(?:reserved|rights|right|copyright|copyrights|allrightsreserved|allrights|inc|ltd|llc|corp|corporation|limited|company|co|gmbh|plc|pty|sa|ag|bv|nv|spa|srl|kg|oy|ab|as|aps|kk|kft|zrt|pte|sdn|bhd|holdings?|group|enterprise|enterprises|solutions?|technologies|technology|systems?|international|global|worldwide|privacy|policy|terms|conditions|license|licence|disclaimer|trademark|trademarks|registered|reg|patent|patents|year|years|january|february|march|april|june|july|august|september|october|november|december)$/i.test(s)) return true;
    // 图标/样式/布局前缀
    if (/^(?:icon|btn|img|svg|png|jpg|gif|com|std|mod|ys|nav|pprb|mhbl|mhti|pplt|swiper|jquery|slick|three|mesh|sprite|camera|scene|group|vector|axes)/i.test(s)) return true;
    if (/icon\d|\dbtn|btn\d|img\d|svg\d|comicon|icon0/i.test(s)) return true;
    // 字母数字混杂短串：B1icon13、icon091、hr60、x86urlall
    if (/\d/.test(s) && /[a-z]/.test(s)) {
      if (s.length <= 14 && (/^\d+[a-z]+\d*$/i.test(s) || /^[a-z]+\d+[a-z]*\d*$/i.test(s) || /^[a-z]\d/i.test(s))) return true;
      if (/(?:x86|x64|arm64|url|plat|pro=|hr\d)/i.test(s)) return true;
    }
    // 纯构建/框架/WP 残留
    if (/^(?:render|animate|project|position|normalize|clone|scroll|width|height|color|style|class|active|wrap|item|list|pull|head|foot|main|page|cont|box|link|text|info|tit|parga|arrow)$/i.test(s)) return true;
    // WordPress / 布局 / 媒体 UI 词（Cover 曾抢占「网易云音乐」展示名）
    if (/^(?:cover|content|screen|reader|skip|template|block|blocks|button|buttons|image|images|preview|summary|large|small|medium|right|left|center|first|screen|computer|upload|uploads|media|theme|themes|plugin|plugins|wordpress|yoast|schema|graph|locale|robots|follow|index|snippet|video|videos|audio|feed|feeds|comment|comments|breadcrumb|organization|collection|website|entry|point|search|query|input|value|required|string|property|specification|type|types|width|height|sizes|auto|inherit|initial|relative|absolute|flex|grid|none|true|false|null|void|function|const|var|let|this|self|window|document|body|html|head|meta|link|script|style|span|div|nav|section|article|footer|header)$/i.test(s)) return true;
    // 下载/安全/音乐/游戏页常见英文 UI（Flash/HTML5 等运行时见 isRuntimePlatformNoiseToken——可作产品名，不当绝对垃圾）
    if (/^(?:download|downloads|free|official|security|antivirus|software|windows|linux|macos|android|ios|desktop|client|server|update|updates|version|versions|support|about|contact|privacy|cookie|cookies|login|signup|register|home|features|pricing|blog|news|help|faq|docs|document|documents|manual|guide|tutorial|install|setup|uninstall|music|audio|video|player|stream|streaming|app|apps|store|online|social|media|html|javascript|jquery|bootstrap)$/i.test(s)) return true;
    // 注意：Instagram/Facebook 等社交名不在此一律判垃圾——
    // 页脚分享按钮噪声 vs 真仿冒 IG 站，由 isSocialPlatformNoiseToken + title 主宣称共同判断
    // 过短纯英文 UI（3–5 字母通用词，无数字）不当品牌
    if (/^[a-z]{3,5}$/.test(s) && /^(?:home|site|post|posts|page|pages|menu|logo|icon|file|files|data|user|users|admin|login|form|view|edit|save|load|open|close|show|hide|next|prev|back|more|less|full|half|size|font|line|text|dark|light|mode|base|root|core|main|side|top|bottom|all|the|and|for|you|our|with|from|this|that|your|free)$/i.test(s)) return true;
    return false;
  };

  /**
   * 运行时/引擎名：可作产品名（Adobe Flash 播放器下载站），但游戏门户页常作 UI 噪声。
   * 默认不当主品牌；仅当域名对齐或 title/h1 主宣称时放行（见 collectPrimaryBrandKeywords）。
   */
  NS.isRuntimePlatformNoiseToken = function (token) {
    const s = String(token || "").trim().toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!s) return false;
    return /^(?:flash|html5|adobe|webgl|unity|unreal|canvas|shockwave)$/i.test(s);
  };

  /** title/h1/og 是否把 Flash 等运行时当主产品（真·Flash 下载站） */
  NS.runtimePlatformIsPrimaryProductClaim = function (token, titleBlob) {
    try {
      const s = String(token || "").trim().toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!s || !NS.isRuntimePlatformNoiseToken(s)) return false;
      const blob = String(titleBlob || "").toLowerCase();
      if (new RegExp(`\\b${s}\\b.{0,16}(download|official|player|plugin|安装|下载|官网|官方|播放器|插件)`, "i").test(blob)) return true;
      if (new RegExp(`(download|official|player|plugin|安装|下载|官网|官方|播放器|插件).{0,16}\\b${s}\\b`, "i").test(blob)) return true;
      if (new RegExp(`^\\s*${s}\\b`, "i").test(blob.replace(/[^a-z0-9\\s]/g, " "))) return true;
      // Adobe Flash / Flash Player 整名
      if (s === "flash" && /\badobe\s*flash\b|\bflash\s*player\b/i.test(blob)) return true;
      return false;
    } catch { return false; }
  };

  /**
   * 社交网络名：页脚/分享组件噪声，默认不当产品品牌。
   * 仅当 title/h1/og:title 明确以该平台为主产品时才放行（见 collectPrimaryBrandKeywords）。
   */
  NS.isSocialPlatformNoiseToken = function (token) {
    const s = String(token || "").trim().toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!s) return false;
    return /^(?:instagram|insta|facebook|fb|meta|youtube|youtu|yt|tiktok|twitter|tweet|weibo|wechat|weixin|whatsapp|telegram|discord|linkedin|pinterest|snapchat|reddit|tumblr|douyin|bilibili|bili|xiaohongshu|xhs|kuaishou|qqzone|qzone|line|kakao|viber|skype|zoom|slack|github|gitlab|behance|dribbble)$/i.test(s);
  };

  /** title/h1/og 是否把该社交名当主产品（真·仿冒 IG 下载站） */
  NS.socialPlatformIsPrimaryProductClaim = function (token, titleBlob) {
    try {
      const s = String(token || "").trim().toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!s || !NS.isSocialPlatformNoiseToken(s)) return false;
      const blob = String(titleBlob || "").toLowerCase();
      // 标题主位出现 Instagram 下载/官网 等
      if (new RegExp(`\\b${s}\\b.{0,12}(download|official|app|client|安装|下载|官网|官方)`, "i").test(blob)) return true;
      if (new RegExp(`(download|official|安装|下载|官网|官方).{0,12}\\b${s}\\b`, "i").test(blob)) return true;
      // 标题以 Instagram 开头或整段就是平台名
      if (new RegExp(`^\\s*${s}\\b`, "i").test(blob.replace(/[^a-z0-9\\s]/g, " "))) return true;
      return false;
    } catch { return false; }
  };

  // 主机形态：短前缀/后缀（结构启发，非品牌词表）— im-todesk / ott-todesk / huorong-pc
  // ott = 常见营销/频道前缀（ott-todesk.com.cn），绝不当正站复合
  // lab/labs：钓鱼站常用「品牌-lab」营销垫（huorong-lab），不当产品线正站
  const MKT_HOST_PREFIX = /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|pr|my|the|best|new|top|go|use|try|win|cn|zh|en|www\d*|im|ie|qq|wx|dl|to|up|re|un|gw|seo|ott|cdn|tv|hd|4k|vip|x|z)$/i;
  const MKT_HOST_SUFFIX = /^(?:app|desktop|client|soft|download|free|pro|vip|official|online|tool|tools|win|windows|setup|install|cn|hub|box|pc|mac|ios|android|mobile|desk|lab|labs)$/i;
  // 产品线尾缀可拼正站；营销前缀拼域名一律 squat
  // 注意：lab/labs 不在此列——huorong-lab 是夹带仿冒，非 pyas-security 类正站产品线
  const PRODUCT_LINE_HOST_TOKEN = /^(?:ai|gpt|ml|bot|llm|security|antivirus|av|linux|windows|macos|android|bsd)$/i;
  // 产品线后缀（结构）：pyas-security = 品牌+品类；亦含 OS 发行版粘连、AI 产品线（todeskai）
  // 与 brand-pc / im-todesk / huorong-lab 营销夹带区分：品类尾缀表示正站产品线，非 squat
  const BRAND_PRODUCT_CATEGORY_SUFFIX = /^(?:security|antivirus|antimalware|av|secure|protection|defender|endpoint|tech|systems?|network|studio|group|hq|linux|windows|macos|android|ai|gpt|ml|bot|llm)$/i;
  NS.MKT_HOST_PREFIX = MKT_HOST_PREFIX;
  NS.MKT_HOST_SUFFIX = MKT_HOST_SUFFIX;
  NS.BRAND_PRODUCT_CATEGORY_SUFFIX = BRAND_PRODUCT_CATEGORY_SUFFIX;
  NS.PRODUCT_LINE_HOST_TOKEN = PRODUCT_LINE_HOST_TOKEN;

  /**
   * 主机段是否营销前缀（ott / pr / im / get…），用于拒绝「ott+todesk=正站」误放。
   * opts.strict：无连字符主机用，勿含 to/up/re（否则 todeskai 会被拆成 to+deskai）。
   */
  NS.isMarketingHostPrefixToken = function (tok, opts) {
    const p = String(tok || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!p || p.length > 10) return false;
    if (PRODUCT_LINE_HOST_TOKEN.test(p)) return false;
    // 严格表：明确营销/频道前缀（含 ott / ie；单字母 v/x/z 仅 glued 夹带用）
    if (/^(?:get|aa|bb|cc|ca|pc|app|im|ie|qq|wx|dl|gw|pr|seo|ott|cdn|tv|hd|vip|pro|my|free|soft|safe|down|download|www\d*)$/i.test(p)) {
      return true;
    }
    // 单字母频道前缀：v-dingtalk / j-dingtalk / vdingtalk（strict 亦认）
    // j/e/a/s 等常见「单字母-品牌」仿冒夹带（www.j-dingtalk.com.cn）
    if (/^[vxzjeas]$/i.test(p)) return true;
    if (opts && opts.strict) return false;
    // 宽松：连字符主机可用短前缀 to/go/up（to-desk 镜像另论）
    if (MKT_HOST_PREFIX.test(p)) return true;
    // 任意单字母（连字符主机 j-dingtalk / m-todesk）
    if (/^[a-z]$/i.test(p)) return true;
    return false;
  };

  /**
   * 主机是否「营销前缀 + 品牌」夹带形态：ott-todesk / pr-todesk / j-dingtalk / imtodesk。
   * 此类绝不当 domain-keyword related 正站。
   */
  NS.hostLabelIsMarketingPrefixedBrandShape = function (rawLabel, brandTokenOpt) {
    try {
      const raw = String(rawLabel || "").toLowerCase().replace(/^www\./, "");
      if (!raw || raw.length < 5) return false;
      const lab = raw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      // 连字符：ott-todesk / j-dingtalk（可用宽松前缀表 + 单字母）
      if (/-/.test(raw)) {
        const parts = raw.split("-").filter(Boolean).map((p) => p.replace(/[^a-z0-9]/g, ""));
        if (parts.length >= 2) {
          const first = parts[0];
          const rest = parts.slice(1).join("");
          const prefixOk = NS.isMarketingHostPrefixToken(first)
            || (first.length === 1 && /^[a-z]$/i.test(first));
          if (prefixOk && rest.length >= 4
            && !(typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
              && NS.hostLabelIsBrandProductCategoryDomain(raw, rest))) {
            if (!brandTokenOpt) return true;
            const br = String(brandTokenOpt).toLowerCase().replace(/[^a-z0-9]/g, "");
            return !br || rest === br || rest.includes(br) || br.includes(rest);
          }
        }
      }
      // 无连字符：vdingtalk / otttodesk——严格前缀；单字母 v/x/z 从 n=1 扫
      if (brandTokenOpt) {
        const br = String(brandTokenOpt).toLowerCase().replace(/[^a-z0-9]/g, "");
        if (br.length >= 4 && lab.endsWith(br) && lab.length > br.length) {
          const pre = lab.slice(0, lab.length - br.length);
          if (NS.isMarketingHostPrefixToken(pre, { strict: true })) return true;
        }
      } else {
        for (let n = 1; n <= 6; n++) {
          if (lab.length <= n + 3) break;
          const pre = lab.slice(0, n);
          const rest = lab.slice(n);
          if (n === 1 && !/^[vxz]$/i.test(pre)) continue;
          if (NS.isMarketingHostPrefixToken(pre, { strict: true }) && rest.length >= 5
            && !(typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
              && NS.hostLabelIsBrandProductCategoryDomain(lab, rest))) {
            return true;
          }
        }
      }
      return false;
    } catch { return false; }
  };

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

  /**
   * 可由页面强身份明确声明的窄产品线后缀。仅允许无连字符的技术/平台组合；
   * security / antivirus / defender 等泛安全品类不在此列，不能靠页面自述洗白。
   */
  NS.hostLabelHasSafeProductLineSuffix = function (rawLabel, brandToken) {
    try {
      const raw = String(rawLabel || "").toLowerCase().replace(/^www\./, "");
      const br = String(brandToken || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!raw || !br || /[-_]/.test(raw)) return false;
      const lab = raw.replace(/[^a-z0-9]/g, "");
      if (!lab.startsWith(br) || lab.length <= br.length) return false;
      const suffix = lab.slice(br.length);
      return /^(?:ai|gpt|ml|bot|llm|linux|windows|macos|android|bsd)$/i.test(suffix);
    } catch {
      return false;
    }
  };

  NS.extractLatinBrandTokens = function (text) {
    const out = [];
    const seen = new Set();
    // 保留 CamelCase 整词（DingTalk）；过滤图标/资源/WP 垃圾（B1icon13、Cover）
    (String(text || "").match(/[A-Za-z][A-Za-z0-9]{2,}/g) || []).forEach((b) => {
      const low = b.toLowerCase();
      // 允许全大写 3 字母缩写进入候选池；它是不是品牌由后续
      // “强身份字段复现 + 域名相关度”决定，而不是在这里维护缩写词表。
      const shortAcronym = b.length === 3 && /^[A-Z][A-Z0-9]{2}$/.test(b);
      if ((!shortAcronym && low.length < 4) || low.length > 24) return;
      if (BRAND_TOKEN_STOP_RE.test(low)) return;
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(low)) return;
      // 连字符 CMS 段：ca-aurora-template → 跳过整段里的 template/aurora
      if (/^(?:min|max|src|href|http|https|www|com|net|org|html|json|xml|css|svg|png|jpg|jpeg|webp|gif)$/i.test(low)) return;
      // 纯字母过短 UI 词 / 版权词（社交平台名由上层 isGarbage 结合 title 判断，此处不一律丢）
      if (/^(?:icon|button|image|logo|free|down|link|page|home|user|login|search|menu|nav|cover|block|group|style|rights|reserved|copyright)$/i.test(low)) return;
      if (seen.has(low)) return;
      seen.add(low);
      out.push(low);
    });
    return out;
  };

  /**
   * 页内静态资源是否大量落在「干净品牌根」apex（cdn-www.huorong.cn on huorong.cn）。
   * 仅用于中文品牌正站（title 无拉丁）自证；绝不可把 ca-hongrong 自托管资源当成正站。
   */
  NS.hostLabelMatchesPageResourceApex = function (hostOpt) {
    try {
      const host = String(hostOpt || location.hostname || "").toLowerCase().replace(/^www\./, "");
      if (!host) return false;
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const label = labelRaw.replace(/[^a-z0-9]/g, "");
      if (label.length < 4) return false;
      // 营销夹带 / 连字符拆品牌 / 前缀 ca-aa-im- 等：盗版站也会自托管同域 CSS，绝不当正站
      if (/-/.test(labelRaw) || /_/.test(labelRaw)) return false;
      // 产品线正站（todeskai = todesk+ai）不当营销前缀；to 过宽会误伤 todesk*
      let productLineHost = false;
      if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function") {
        for (let n = Math.min(label.length - 2, 16); n >= 4; n--) {
          if (NS.hostLabelIsBrandProductCategoryDomain(label, label.slice(0, n))) {
            productLineHost = true;
            break;
          }
        }
      }
      if (!productLineHost) {
        if (/^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|im|qq|wx|dl|my|go|up)[a-z0-9]{3,}/i.test(label)) return false;
        // to 前缀仅拦非 todesk 族（toxxx 营销站）
        if (/^to[a-z0-9]{3,}/i.test(label) && !/^todesk/i.test(label)) return false;
      }
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const core = NS.inferMarketingPaddedBrandCore(labelRaw) || "";
        if (core && core.length >= 4 && core !== label) return false;
      }
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
      // 要求出现「子域 CDN」形态，而非仅当前 host 自引用（盗版站全是自引用）
      let sameApex = 0;
      let cdnLike = 0;
      const nodes = document.querySelectorAll("link[href], script[src], img[src], source[src]");
      const n = Math.min(nodes.length, 80);
      for (let i = 0; i < n; i++) {
        try {
          const raw = nodes[i].getAttribute("href") || nodes[i].getAttribute("src") || "";
          if (!raw || raw.startsWith("data:") || raw.startsWith("#") || raw.startsWith("javascript:")) continue;
          const h = new URL(raw, location.href).hostname.toLowerCase().replace(/^www\./, "");
          if (!h || h === host) continue; // 跳过纯同 host（假站自引用）
          if (h === apex || h.endsWith("." + apex)) {
            sameApex++;
            // cdn-www / static / img / assets 子域更像正站资源体系
            if (/^(?:cdn|static|img|image|assets?|media|res|resource|download|dl|file|files)[-.]/i.test(h)
              || h.startsWith("cdn-") || h.startsWith("cdn.")
              || h.indexOf("cdn-" + label) === 0
              || h.indexOf("static." + label) === 0) {
              cdnLike++;
            }
            if (cdnLike >= 2 || sameApex >= 6) return true;
          }
        } catch { /* ignore */ }
      }
      return cdnLike >= 2 || sameApex >= 6;
    } catch { return false; }
  };

  /**
   * 读 meta content：兼容 property= / name=（twitter 卡两种写法都有）。
   */
  NS.readMetaContent = function (/* names */) {
    try {
      const names = Array.prototype.slice.call(arguments).filter(Boolean);
      for (let i = 0; i < names.length; i++) {
        const key = String(names[i] || "").trim();
        if (!key) continue;
        const esc = key.replace(/"/g, "");
        let el = document.querySelector(`meta[property="${esc}"]`)
          || document.querySelector(`meta[name="${esc}"]`)
          || document.querySelector(`meta[property="${esc}" i]`)
          || document.querySelector(`meta[name="${esc}" i]`);
        if (!el) {
          // 残缺 HTML：属性名含 key 片段
          try {
            for (const m of Array.from(document.querySelectorAll("meta[content]"))) {
              const n = String(m.getAttribute("property") || m.getAttribute("name") || "").toLowerCase();
              if (n === key.toLowerCase()) { el = m; break; }
            }
          } catch { /* ignore */ }
        }
        const c = el && el.getAttribute("content");
        if (c && String(c).trim()) return String(c).trim();
      }
    } catch { /* ignore */ }
    return "";
  };

  /**
   * 产品品牌身份字段：title / description / keywords / h1 / h2 / footer·copyright /
   * logo·span / og:* / twitter:* / schema。
   * 不采 generator/template 等 CMS meta，也不扫全文 body。
   */
  NS.collectProductBrandIdentityFields = function () {
    const fields = {
      title: "", h1: "", h2: "", headings: "", description: "", keywords: "",
      footer: "", logo: "", span: "",
      ogTitle: "", ogDescription: "", ogImageAlt: "", ogSite: "",
      twitterTitle: "", twitterDescription: "", twitterImageAlt: "",
      author: "", schemaName: ""
    };
    try {
      const meta = (typeof NS.readMetaContent === "function")
        ? (...keys) => NS.readMetaContent.apply(null, keys)
        : (k) => String(document.querySelector(`meta[property="${k}"], meta[name="${k}"]`)?.getAttribute("content") || "").trim();

      fields.title = String(document.title || "").trim();
      try {
        // textContent：避免 innerText 触发布局导致 Mixed Content 日志挂到扩展栈
        fields.h1 = String(document.querySelector("h1")?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 200);
      } catch { fields.h1 = ""; }
      // h2 单独采集（综合共识用）；限长，避免功能卡堆砌。textContent 避免 Mixed Content 栈误归因
      try {
        fields.h2 = Array.from(document.querySelectorAll("h2"))
          .map((el) => String(el.textContent || "").replace(/\s+/g, " ").trim())
          .filter((t) => t.length >= 2 && t.length <= 80)
          .slice(0, 12)
          .join(" · ")
          .slice(0, 400);
      } catch { fields.h2 = ""; }
      fields.headings = typeof NS.collectHeadingText === "function"
        ? NS.collectHeadingText(4000)
        : [fields.h1, fields.h2].filter(Boolean).join(" · ");
      fields.description = String(
        meta("description")
        || document.querySelector('meta[name="description"]')?.getAttribute("content")
        || ""
      ).trim().slice(0, 500);
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
      let keywords = document.querySelector('meta[name="keywords" i], meta[name="keyword" i]')?.getAttribute("content") || "";
      if (!keywords) {
        try {
          // 兼容残缺 HTML：<meta name="keywords" , content="…"> 等
          for (const m of Array.from(document.querySelectorAll("meta[content]"))) {
            const n = String(m.getAttribute("name") || m.getAttribute("property") || "").toLowerCase().replace(/[^a-z]/g, "");
            if (n === "keywords" || n === "keyword") {
              keywords = m.getAttribute("content") || "";
              if (keywords) break;
            }
            // name 属性异常时：content 像「品牌,下载,官网」关键词串也认
            if (!keywords) {
              const c = String(m.getAttribute("content") || "");
              if (c.length >= 4 && c.length <= 400 && /[,，]/.test(c)
                && /下载|官网|官方|客户端|浏览器|Firefox|Chrome|软件/i.test(c)
                && !/^(?:text\/|width=|initial-scale)/i.test(c)) {
                const nm = String(m.getAttribute("name") || "");
                if (!nm || /key/i.test(nm) || nm.length <= 2) {
                  keywords = c;
                  break;
                }
              }
            }
          }
        } catch { /* ignore */ }
      }
      fields.keywords = String(keywords || "").trim().slice(0, 600);
      fields.footer = typeof NS.collectFooterCopyrightText === "function" ? String(NS.collectFooterCopyrightText() || "").trim().slice(0, 500) : "";
      // Open Graph / Twitter Card 身份（与 title/description 等权参与品牌共识）
      fields.ogTitle = String(meta("og:title") || "").trim().slice(0, 300);
      fields.ogDescription = String(meta("og:description") || "").trim().slice(0, 500);
      fields.ogImageAlt = String(meta("og:image:alt") || "").trim().slice(0, 200);
      fields.ogSite = String(meta("og:site_name") || "").trim().slice(0, 120);
      fields.twitterTitle = String(meta("twitter:title") || "").trim().slice(0, 300);
      fields.twitterDescription = String(meta("twitter:description") || "").trim().slice(0, 500);
      fields.twitterImageAlt = String(meta("twitter:image:alt") || "").trim().slice(0, 200);
      fields.author = String(meta("author") || document.querySelector('meta[name="author"]')?.getAttribute("content") || "").trim().slice(0, 120);
      try {
        // logo / img：alt 文案 + 文件名中的品牌段（todesk-ai-logo.svg → todesk ai）
        fields.logo = Array.from(document.querySelectorAll(
          "img[alt], img[src*='logo'], .logo, [class*='logo'] img, .nav-logo-text, .logo-text, "
          + "a.logo, .logo a, .logo-link, .hero-brand-logo, .cta-brand-logo, .nav-logo-img"
        ))
          .map((el) => {
            const alt = (el.getAttribute && el.getAttribute("alt")) || "";
            const tx = (el.textContent || "").replace(/\s+/g, " ").trim();
            let srcBits = "";
            try {
              const src = (el.getAttribute && (el.getAttribute("src") || el.getAttribute("data-src"))) || "";
              if (src && !/^data:/i.test(src)) {
                const base = String(src).split("?")[0].split("#")[0].split("/").pop() || "";
                // todesk-ai-logo.svg → todesk ai logo
                srcBits = base
                  .replace(/\.(?:svg|png|jpg|jpeg|gif|webp|ico)$/i, "")
                  .replace(/[-_]+/g, " ")
                  .replace(/\d+/g, " ")
                  .replace(/\b(?:logo|icon|img|image|brand|nav|hero|cta|v)\b/gi, " ")
                  .replace(/\s+/g, " ")
                  .trim();
              }
            } catch { /* ignore */ }
            // 丢弃纯文件名 alt（icon09.svg）
            let altUse = alt;
            if (alt && /\.(?:svg|png|jpg|jpeg|gif|webp|ico)$/i.test(alt)) altUse = "";
            if (altUse && typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(altUse)) altUse = "";
            return `${altUse} ${tx} ${srcBits}`.trim();
          })
          .filter(Boolean)
          .join(" ")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 400);
      } catch { /* ignore */ }
      // 导航/品牌 span：品牌位 + 含产品名的 nav 链接（了解ToDesk AI）
      try {
        const brandSpans = Array.from(document.querySelectorAll(
          ".brand, .brand-name, .site-name, .site-title, .nav-brand, .navbar-brand, "
          + "[class*='brand-name'], [class*='sitename'], .logo-text, .nav-logo-text, "
          + "a.logo, .logo > span:not([class*='icon']), .header-title, .nav-title, "
          + ".logo-todesk, .logo-ai, .hero-brand-todesk, .hero-brand-ai"
        ))
          .map((el) => (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim())
          .filter((t) => t.length >= 2 && t.length <= 28
            && !/^(首页|下载|登录|注册|更多|菜单|导航|可访问|立即|免费)$/i.test(t)
            && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)));
        const navBrandLinks = Array.from(document.querySelectorAll(
          "nav a, .nav-links a, .navbar a, header a, .mobile-nav-drawer a, #mobileNavDrawer a"
        ))
          .map((el) => (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim())
          .filter((t) => t.length >= 2 && t.length <= 36
            && /[A-Za-z]{3,}|[一-鿿]{2,}/.test(t)
            && !/^(首页|下载|登录|注册|更多|菜单|导航|可访问|立即下载|免费下载|联系我们|关于我们)$/i.test(t)
            && !(typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)));
        fields.span = [...brandSpans, ...navBrandLinks]
          .slice(0, 16)
          .join(" · ")
          .slice(0, 360);
      } catch { fields.span = ""; }
    } catch { /* ignore */ }
    return fields;
  };

  /** 身份字段拼接文本（供 claimsOfficial / 拉丁对齐）；顺序即优先级。h3+ 功能卡排最后且可截断。 */
  NS.productBrandIdentityBlob = function (fieldsOpt) {
    const f = fieldsOpt || NS.collectProductBrandIdentityFields();
    // 主身份在前：title/desc/kw/h1/h2/og·twitter/footer/span/logo；headings 尾部弱补充
    return [
      f.title, f.h1, f.schemaName,
      f.ogTitle, f.ogDescription, f.ogImageAlt, f.ogSite,
      f.twitterTitle, f.twitterDescription, f.twitterImageAlt,
      f.logo, f.span, f.keywords, f.description, f.h2, f.footer, f.author, f.headings
    ]
      .filter(Boolean)
      .join(" ")
      .replace(/\s+/g, " ")
      .trim();
  };

  // 数字+中文产品形态：2345看图王 / 360安全卫士（结构正则，非词表）
  const CN_DIGIT_PRODUCT_RE = /^\d{2,6}[一-鿿]{2,6}$/;
  NS.CN_DIGIT_PRODUCT_RE = CN_DIGIT_PRODUCT_RE;
  /** 是否两个相同三位数字核被错误粘连：360360 / 789789。 */
  NS.isRepeatedNumericBrandToken = function (token) {
    const s = String(token || "").replace(/[^\d]/g, "");
    return /^\d{6}$/.test(s) && s.slice(0, 3) === s.slice(3);
  };
  /** 近期年份 + 文案尾串是版本/时效标签，不是数字品牌。 */
  NS.looksLikeYearMarketingBrandToken = function (token) {
    try {
      const s = String(token || "").replace(/[\s_\-–—|·:：]+/g, "");
      const m = s.match(/^((?:19|20)\d{2})(.*)$/u);
      if (!m) return false;
      const year = Number(m[1]);
      const tail = String(m[2] || "").replace(/^年/u, "");
      if (!tail) return true;
      // 动态时间窗：无需枚举“最新/新版/特别版”等营销文案。
      const currentYear = new Date().getFullYear();
      return year >= currentYear - 5 && year <= currentYear + 2 && tail.length <= 12;
    } catch { return false; }
  };

  /**
   * 平台、架构、版本和发行渠道标签不是站点品牌。
   * 这是有限且稳定的版本语法分类（PC版、x64版、桌面版等），不是品牌名单。
   */
  NS.looksLikePlatformEditionLabel = function (token) {
    try {
      const raw = String(token || "").trim();
      if (!raw) return false;
      const s = raw.replace(/[\s_\-–—|·:：/\\]+/g, "");
      if (!s) return false;
      if (/^(?:pc|win(?:dows)?|mac(?:os)?|linux|android|ios|iphone|ipad|web|x86|x64|arm(?:32|64)?|32bit|64bit|32位|64位)(?:端|平台)?(?:版|版本|客户端|下载)?$/i.test(s)) return true;
      if (/^(?:电脑|桌面|手机|移动|网页|安卓|苹果|鸿蒙|通用|绿色|便携|免安装|安装|免费|正式|官方|最新|新|旧|专业|企业|个人|家庭|教育|国际|中文|测试|开发|稳定|会员)(?:版|版本)$/u.test(s)) return true;
      // 短大写缩写 +「版」描述的是该缩写的发行版本；真正品牌应从其它身份字段提取。
      if (/^[A-Z0-9]{2,8}(?:版|版本)$/u.test(s)) return true;
      return false;
    } catch {
      return false;
    }
  };

  // 兼容旧引用：无预设词表，恒为永不匹配
  const NEVER = /(?!)/;
  NS.CN_BRAND_GENERIC_RE = NEVER;
  NS.CN_SECTION_HEADING_RE = NEVER;
  NS.CN_FEATURE_CAPABILITY_RE = NEVER;
  NS.CN_MARKETING_SLOGAN_RE = NEVER;
  NS.CN_SLANG_CLICKBAIT_RE = NEVER;

  /** 中文/混合产品名长度是否合理（结构，非词表） */
  NS.isPlausibleChineseBrandLength = function (token) {
    const s = String(token || "").trim();
    if (!s || s.length < 2) return false;
    if (typeof NS.looksLikeYearMarketingBrandToken === "function"
      && NS.looksLikeYearMarketingBrandToken(s)) return false;
    if (typeof NS.looksLikePlatformEditionLabel === "function"
      && NS.looksLikePlatformEditionLabel(s)) return false;
    if (CN_DIGIT_PRODUCT_RE.test(s)) return s.length >= 4 && s.length <= 12;
    if (/[A-Za-z]/.test(s) && /[一-鿿]/.test(s)) return s.length >= 3 && s.length <= 10;
    if (/^\d+$/.test(s)) return false;
    // 纯中文产品名通常 2–6 字；过长多为口号截断（网易云音乐为每个）
    return s.length >= 2 && s.length <= 6;
  };

  /** 结构裁尾：剥句末「官网/官方/下载」等分发后缀（含 ToDesk官网 → ToDesk）
   * 勿剥产品本体里的「安全/杀毒/卫士」（火绒安全 ≠ 火绒 + 可丢的安全）
   */
  NS.trimChineseBrandTrail = function (token) {
    let t = String(token || "").trim();
    if (t.length < 2) return t;
    if (CN_DIGIT_PRODUCT_RE.test(t)) return t;
    let guard = 0;
    while (guard++ < 6 && t.length > 1) {
      // 仅剥分发/渠道/栏目尾巴；「…安全 / …杀毒 / …卫士」是产品名一部分，保留
      // 「钉钉应用中心」→「钉钉」：应用中心是栏目壳不是品牌
      let next = t
        .replace(/(?:官网下载|官方下载|免费下载|立即下载|客户端下载|下载中心|电脑版|手机版)$/u, "")
        .replace(/(?:应用中心|帮助中心|新闻中心|服务中心|支持中心)$/u, "")
        .replace(/(?:官网|官方网站|官方)$/u, "")
        .replace(/(?:软件|客户端)$/u, "") // 火绒安全软件 → 火绒安全
        .replace(/(?:应用)$/u, "") // 钉钉应用 → 钉钉（须在「中心」之后剥）
        .replace(/(?:下载)$/u, "")
        .trim();
      // 勿把「火绒安全」剥成「火绒」；勿留下纯「安全」
      if (next && next !== t) {
        if (/^(?:安全|杀毒|卫士|软件|客户端|官方|官网|应用|中心)$/.test(next)) break;
        if (next.length < 2) break;
        t = next;
        continue;
      }
      break;
    }
    return t;
  };

  /**
   * 页面常把品牌与栏目/口号/功能说明粘在一个标签里：ToDesk博客、ToDesk快。
   * 若拉丁前缀与当前 host 通过双向身份校验，只保留页面声明的拉丁品牌；
   * 仅当中文尾部本身是完整产品品类（QQ音乐、UC浏览器）时保留混合产品名。
   * 这是“品牌主体 + 中文尾部角色”判断，不依赖具体厂商品牌名单。
   */
  NS.normalizeHostAlignedLatinBrandWithNonIdentityTail = function (token, hostOpt) {
    try {
      const raw = String(token || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim();
      const m = raw.match(/^([A-Za-z][A-Za-z0-9]{1,24})[\s_\-–—]*([一-鿿]{1,10})$/u);
      if (!m) return "";
      const tail = String(m[2] || "").replace(/[\s_\-–—]/g, "");
      if (typeof NS.resolveMutualLatinBrandIdentity !== "function") return "";
      const mutual = NS.resolveMutualLatinBrandIdentity(
        m[1],
        hostOpt || (typeof location !== "undefined" ? location.hostname : "")
      );
      if (!(mutual && mutual.matched && mutual.displayBrand)) return "";
      // 完整产品品类属于名称本体，不裁：QQ音乐、UC浏览器、QQ邮箱等。
      // “博客/快/中文/远程桌面/官方服务”等栏目或描述不满足此形态，折叠回品牌主体。
      if (/^(?:(?:云)?音乐|浏览器|播放器|输入法|客户端|安全卫士|杀毒软件|网盘|办公套件|助手|管家|邮箱|地图|视频|直播|阅读|游戏|空间)$/u.test(tail)) {
        return "";
      }
      return String(mutual.displayBrand).trim();
    } catch {
      return "";
    }
  };

  /**
   * 展示用品牌名归一：去掉「官网」尾巴，避免 toast「仿冒「ToDesk官网」官网」。
   * 纯拉丁结果走 formatBrandTokenForDisplay（ToDesk）。
   */
  NS.normalizeDisplayBrandName = function (name) {
    try {
      let t = String(name || "").trim();
      if (!t) return "";
      // 数字门户品牌原样展示
      if (/^\d{3,6}$/.test(t) && !/^(?:19|20)\d{2}$/.test(t)) {
        if (typeof NS.isRepeatedNumericBrandToken === "function"
          && NS.isRepeatedNumericBrandToken(t)) return "";
        return t;
      }
      // 版权/法律词绝不当展示品牌（All Rights Reserved → Reserved）
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
      if (/^(?:reserved|rights|copyright|all\s*rights(\s*reserved)?)$/i.test(t)) return "";
      // “已确认拉丁品牌 + 中文栏目/产品描述”只展示页面品牌身份。
      // tod​esk博客 / tod​esk云电脑 → ToDesk；QQ音乐仍保留完整产品名。
      try {
        const alignedLatin = typeof NS.normalizeHostAlignedLatinBrandWithNonIdentityTail === "function"
          ? NS.normalizeHostAlignedLatinBrandWithNonIdentityTail(t)
          : "";
        if (alignedLatin) return alignedLatin;
      } catch { /* ignore */ }
      // Flash 可作产品名：仅当既非域名对齐又非标题主宣称时，归一阶段才挡（collect 层会再判）
      // 此处不一律清空——避免真·Flash 站 display 被抹掉
      t = NS.trimChineseBrandTrail(t) || t;
      t = t.replace(/(?:远程控制软件|远程桌面软件|远程控制|远程桌面)$/u, "").trim();
      t = t.replace(/(?:官网|官方网站|官方|下载|客户端)$/u, "").trim();
      if (!t || t.length < 2) return "";
      // 纯拉丁
      if (/^[A-Za-z][A-Za-z0-9.\-]*$/.test(t)) {
        const clean = t.replace(/[^A-Za-z0-9]/g, "");
        if (clean.length < 2) return "";
        return typeof NS.formatBrandTokenForDisplay === "function"
          ? NS.formatBrandTokenForDisplay(clean)
          : (clean.charAt(0).toUpperCase() + clean.slice(1));
      }
      // 混合 QQ音乐：再裁一次
      if (typeof NS.normalizeChineseBrandToken === "function" && /[一-鿿]/.test(t)) {
        const n = NS.normalizeChineseBrandToken(t);
        if (n && n.length >= 2) t = n;
      }
      // 仍带 官网 则强剥
      t = t.replace(/(?:官网|官方)$/u, "").trim();
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)) return "";
      return t;
    } catch {
      return String(name || "").trim();
    }
  };

  /**
   * 结构裁头：剥栏目/关于页前缀「关于火绒杀毒」→ 火绒杀毒；「走进钉钉」→ 钉钉。
   */
  NS.trimChineseBrandLead = function (token) {
    let t = String(token || "").trim();
    if (t.length < 3) return t;
    if (CN_DIGIT_PRODUCT_RE.test(t)) return t;
    // 关于/走进/了解/认识/欢迎使用 + 产品名
    const m = t.match(/^(?:关于|走进|了解|认识|欢迎使用|欢迎来到|什么是)(.+)$/u);
    if (m && m[1] && m[1].length >= 2) {
      t = m[1].trim();
      // 「我们」「本公司」等空壳不要
      if (/^(?:我们|本公司|本站|本产品|软件|产品)$/.test(t)) return "";
    }
    return t;
  };

  /** 中文品牌归一：先裁头再裁尾再截口号 */
  NS.normalizeChineseBrandToken = function (token) {
    let t = String(token || "").trim();
    if (!t) return "";
    if (CN_DIGIT_PRODUCT_RE.test(t)) return t;
    t = NS.trimChineseBrandLead(t) || t;
    t = NS.trimChineseBrandTrail(t) || t;
    if (typeof NS.cutChineseBrandBeforeSlogan === "function") {
      const cut = NS.cutChineseBrandBeforeSlogan(t);
      if (cut && cut.length >= 2) t = cut;
    }
    return t;
  };

  /**
   * 口号句截断（结构）：
   * 「网易云音乐为每个…」→ 网易云音乐；「QQ音乐听我想听」→ QQ音乐
   */
  NS.cutChineseBrandBeforeSlogan = function (token) {
    const s = String(token || "").trim();
    if (!s || s.length < 3) return s;
    // 拉丁+中文品牌 + 口号谓语（听/为/是/让/开启…）
    const mixed = s.match(/^([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})(?=[听为是让给把与和开启].)/);
    if (mixed && mixed[1] && mixed[1].length >= 3) return mixed[1];
    // 纯中文品牌为… / 品牌是… / 品牌让…
    const m = s.match(/^([一-鿿]{2,6})(?=[为是让给把与和听开启].)/);
    if (m && m[1] && m[1].length >= 2) return m[1];
    return s;
  };

  /**
   * 音视频规格/品质卖点不是品牌。
   * 采用“形容词 + 媒体属性”的结构判断，避免把 Hi-Res 无损音质抽成
   * 「Res无损音质」；这里没有维护任何厂商品牌名单。
   */
  NS.looksLikeMediaFeatureClaimToken = function (token) {
    try {
      const s = String(token || "")
        .replace(/[\s\-_/·•]+/g, "")
        .replace(/^(?:hi|ultra|full)?(?:res|hd|uhd|hdr|hifi)/i, "")
        .trim();
      if (!s || !/[一-鿿]/.test(s)) return false;
      const cn = s.replace(/[A-Za-z0-9]/g, "");
      if (!cn) return false;
      return /^(?:(?:超|极|至臻|高|专业|影院级|母带级)?(?:高清|超清|无损|高保真|高解析|高码率|沉浸式?|臻品|卓越|极致|纯净))+(?:音质|音效|声效|画质|品质|听感|视听|影音|体验|播放|解码)$/.test(cn)
        || /^(?:无损|高清|超清|高保真|高解析|高码率)(?:音频|音乐|视频)$/.test(cn);
    } catch {
      return false;
    }
  };

  /**
   * “技术缩写/能力标签 + 功能动作”属于功能标题，不属于站点身份。
   * 只有具备产品品类尾缀（QQ音乐、Firefox浏览器）或拉丁部分与域名对齐时，
   * 混合词才保留为品牌候选。该规则按语言形态工作，不依赖厂商品牌表。
   */
  NS.looksLikeFunctionalClaimBrandToken = function (token) {
    try {
      const s = String(token || "").replace(/[\s\-_/·•]+/g, "").trim();
      if (!s || !/[一-鿿]/.test(s)) return false;
      if (typeof NS.looksLikeMediaFeatureClaimToken === "function"
        && NS.looksLikeMediaFeatureClaimToken(s)) return true;

      const mixed = s.match(/^([A-Za-z][A-Za-z0-9]{1,11})([一-鿿]{2,10})$/);
      const latin = mixed ? mixed[1] : "";
      const cn = mixed ? mixed[2] : s;
      const productSuffix = /(?:音乐|浏览器|播放器|输入法|客户端|安全卫士|杀毒软件|网盘|办公套件|助手|管家)$/;
      // 动作/卖点中心语（推荐/生成/智能…）：即使以「音乐」结尾也是功能，不是「QQ音乐」式产品
      // 反例曾误报：仿冒「AI推荐音乐」官网（qishuihi 汽水仿冒页功能卡）
      const actionLeadCn = /^(?:推荐|智能推荐|猜你|为你|个性|热门|精选|每日|生成|编辑|识别|分析|搜索|播放|下载|安装|转换|处理|创作|剪辑|智能)/;
      if (actionLeadCn.test(cn) || actionLeadCn.test(s.replace(/[A-Za-z0-9]+/g, ""))) return true;
      // 纯中文：推荐音乐 / 智能推荐歌单 / AI 前缀剥掉后仍功能
      const cnOnly = s.replace(/[A-Za-z0-9]+/g, "");
      if (/^(?:推荐|智能|猜你喜欢|为你推荐|个性推荐).{0,6}(?:音乐|歌曲|歌单|曲库|播单)$/.test(cnOnly)
        || /^(?:AI|人工智能)?(?:推荐|智能).{0,4}(?:音乐|歌曲|歌单)$/.test(s)) return true;
      // AI/GPT/PDF 等技术标签 + 中文：默认功能（域名对齐除外）
      if (mixed && /^(?:AI|AIGC|GPT|LLM|ML|OCR|PDF|VPN|SDK|API|CPU|GPU|AR|VR|IoT)$/i.test(latin)) {
        if (!(typeof NS.candidateDomainAligned === "function"
          && NS.candidateDomainAligned(latin) >= 1)) return true;
      }
      // QQ音乐 / Firefox浏览器：拉丁产品核 + 品类尾缀 → 可保留为品牌
      if (mixed && productSuffix.test(cn) && !actionLeadCn.test(cn)) return false;
      if (mixed && typeof NS.candidateDomainAligned === "function"
        && NS.candidateDomainAligned(latin) >= 1) return false;

      // 编辑/推荐/生成等是动作中心语；前面的 AI、PDF、GPT 只是技术或格式限定。
      const actionTail = /(?:重?命名|改名|编辑|推荐|生成|识别|分析|检测|搜索|翻译|创作|剪辑|修复|转换|处理|管理|优化|加速|同步|备份|清理|压缩|解压|录制|播放|下载|安装)$/;
      if (mixed && actionTail.test(cn)) return true;

      // 短大写缩写 + 三字以上非产品品类说明，默认视为能力标签；
      // 真正与域名一致的缩写已在上方获得身份豁免。
      if (mixed && /^[A-Z][A-Z0-9]{1,4}$/.test(latin)
        && cn.length >= 3 && !productSuffix.test(cn)) return true;

      // 纯中文功能标题通常由“方式/范围 + 操作或通用品类”构成。
      // 这是语言结构分类，不是厂商品牌表：批量重命名、远程桌面、云端办公等
      // 即使被模板复制到 title/H1/OG，也不能因此变成品牌。
      // ★「免费远程」曾误 toast：modeLead=免费 但尾「远程」旧表漏收。
      const modeLead = /^(?:智能|自动|一键|在线|离线|实时|快速|极速|精准|批量|免费|专业|高效|便捷|云端|本地|远程|桌面|移动|跨端|跨平台|多端|多人|团队|个性|每日|热门|精选|官方|正版|最新)/;
      const capabilityTail = /(?:重?命名|改名|编辑|推荐|生成|识别|分析|检测|搜索|翻译|创作|剪辑|修复|转换|处理|管理|优化|加速|同步|备份|清理|压缩|解压|录制|播放|下载|安装|截图|远程|桌面|控制|协助|协作|连接|访问|办公|会议|教育|助手|运维|操作|服务|音乐|歌曲|歌单|软件|工具|系统)$/;
      if (!mixed && modeLead.test(cn) && capabilityTail.test(cn)) return true;
      // 免费远程 / 极速桌面 / 专业控制：整段即「方式+品类」，无专名
      if (!mixed && /^(?:智能|自动|一键|在线|离线|实时|快速|极速|精准|批量|免费|专业|高效|便捷|云端|本地|官方|正版|最新)(?:远程|桌面|控制|协助|协作|连接|访问|办公)(?:软件|工具|服务|系统|客户端)?$/.test(cn)) {
        return true;
      }
      // 滑窗候选可能把动作词截成「控/协/连/访/运」；它仍是功能句残片，
      // 不能因为截断后的拼音碰巧贴近域名就升级为品牌。
      if (!mixed && cn.length >= 4 && modeLead.test(cn)
        && /(?:远程)?(?:控|协|连|访|运|程)$/.test(cn)) return true;
      return false;
    } catch {
      return false;
    }
  };

  /**
   * 是否「不可用」中文品牌 token（结构判断，无业务词表）。
   * 挡 UI/卖点残片与站点栏目：「可访问」「技术支持」「下载中心」等绝不当仿冒展示名。
   */
  /**
   * 禁止作为「仿冒「X」官网」展示的 X（语言壳/品类壳）。
   * 所有 toast / spoofBrand 写入必须经此门禁——与 pinyin 无关。
   */
  NS.isForbiddenSpoofDisplayBrand = function (token) {
    try {
      const s = String(token || "").trim();
      if (!s || s.length < 2) return true;
      // 语言/地区壳（曾误 toast「仿冒「中文」官网」）
      if (/^(?:中文|英文|英语|汉语|简体|繁体|简体中文|繁体中文|国语|粤语|日文|日语|韩文|韩语|语言|版本|国际|国内|大陆|台湾|香港|海外)$/.test(s)) {
        return true;
      }
      // 版本、下载和安装服务话术只能描述页面功能，不能成为“仿冒「X」官网”的 X。
      if (/^(?:电脑|电脑版|桌面|桌面版|PC版|客户端|官方|正版|免费|最新|新版|旧版|高速|安全).{0,6}(?:下载|安装|服务|软件|版本|客户端)?$/i.test(s)) return true;
      // 「免费远程 / 极速桌面 / 官方控制」：totodesk 等站首屏曾误抽此为品牌
      if (/^(?:智能|自动|一键|在线|快速|极速|免费|专业|高效|便捷|云端|本地|官方|正版|最新)?(?:远程|桌面|控制|协助|连接|访问)(?:软件|工具|服务|系统|客户端)?$/.test(s)) return true;
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(s)) return true;
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(s)) return true;
      // 主机/域名衍生碎片（Todeskr @ pc-todeskr、Huorongr）不得进 toast
      if (typeof NS.isHostShapedCompoundBrandToken === "function"
        && NS.isHostShapedCompoundBrandToken(s)) return true;
      // 仅当候选等于当前主机的污染段（非干净剥核）时禁展示——勿对 ToDesk/todesk 误杀
      try {
        const flat = s.toLowerCase().replace(/[^a-z0-9]/g, "");
        const host = NS.normalizeDomain((typeof location !== "undefined" && location.hostname) || "");
        const labelRaw = (host.split(".")[0] || "").toLowerCase();
        const segs = labelRaw.split(/[-_]/).map((p) => p.replace(/[^a-z0-9]/g, "")).filter((p) => p.length >= 4);
        const padCore = typeof NS.inferMarketingPaddedBrandCore === "function"
          ? String(NS.inferMarketingPaddedBrandCore(labelRaw) || "").toLowerCase()
          : "";
        if (flat && segs.includes(flat) && padCore && flat !== padCore
          && typeof NS.hostLabelIsPaddedBrand === "function"
          && NS.hostLabelIsPaddedBrand(flat, padCore)) {
          return true;
        }
      } catch { /* ignore */ }
      return false;
    } catch {
      return true;
    }
  };

  /**
   * 页内拉丁品牌 ↔ 域名段对齐（无需 pinyin）。
   * 例：app.wps-officce-wps.com.cn + 页内 WPS →「WPS」
   * 这是仿冒展示首选：主机已夹带品牌拉丁核且页面声明同一核。
   */
  NS.pickHostAlignedLatinBrandFromPage = function (hostOpt) {
    try {
      const host = NS.normalizeDomain
        ? NS.normalizeDomain(hostOpt || (typeof location !== "undefined" ? location.hostname : ""))
        : String(hostOpt || "").toLowerCase().replace(/^www\./, "");
      if (!host) return "";
      const segs = [];
      const seen = Object.create(null);
      const addSeg = (s) => {
        const t = String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!t || t.length < 2 || t.length > 16 || seen[t]) return;
        if (/^(?:www|com|net|org|app|web|www\d+|pc|cdn|api|m|mobile|download|dl|get|soft|safe|vip|pro|cn|win|lab|labs|tech|site|official|free|client)$/i.test(t)) return;
        seen[t] = 1;
        segs.push(t);
      };
      host.split(".").forEach((part) => {
        String(part || "").split(/[-_]/).forEach(addSeg);
      });
      try {
        if (typeof NS.resolveHostBrandCore === "function") addSeg(NS.resolveHostBrandCore(host));
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const lab0 = (host.split(".")[0] || "");
          addSeg(NS.inferMarketingPaddedBrandCore(lab0));
          // apex 左标（totodesk.com.cn 的 totodesk，勿只看子域 pc）
          try {
            const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : host) || host;
            const apexLeft = (String(apex).split(".")[0] || "");
            addSeg(NS.inferMarketingPaddedBrandCore(apexLeft));
            addSeg(apexLeft.replace(/-/g, ""));
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
      if (!segs.length) return "";

      // 页内身份槽（短，无 body）。保留证据族，避免“域名 exact”在后续扫描中
      // 反过来压过页面已经明确声明的品牌（Steam → Steampowered）。
      let blob = "";
      let identitySlots = [];
      try {
        identitySlots = [
          { source: "title", family: "headline", primary: true, text: document.title || "" },
          { source: "h1", family: "headline", primary: true, text: document.querySelector("h1")?.textContent || "" },
          { source: "ogSite", family: "siteIdentity", primary: true, text: document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "" },
          { source: "applicationName", family: "siteIdentity", primary: true, text: document.querySelector('meta[name="application-name"]')?.getAttribute("content") || "" },
          { source: "ogTitle", family: "headline", primary: true, text: document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "" },
          { source: "logo", family: "brandMark", primary: false, text: document.querySelector(".logo, [class*='logo']")?.textContent || "" }
        ].map((slot) => ({ ...slot, text: String(slot.text || "").trim() })).filter((slot) => slot.text);
        blob = identitySlots.map((slot) => slot.text).join(" ");
      } catch {
        blob = String(document.title || "");
        identitySlots = blob
          ? [{ source: "title", family: "headline", primary: true, text: blob }]
          : [];
      }
      // 选举拉丁榜
      try {
        const pk = NS.caches && NS.caches._primaryKw;
        if (pk && pk.latin) blob += " " + pk.latin.join(" ");
        if (pk && pk.display && /^[A-Za-z]/.test(pk.display)) blob += " " + pk.display;
      } catch { /* ignore */ }
      const blobLow = blob.toLowerCase();
      if (!blobLow) return "";

      // 页面身份槽里的完整拉丁品牌主动到 host 中匹配。to-desk、todek、todsk
      // 都由页面候选 ToDesk(todesk) 引导命中；域名不会先自行生成展示品牌。
      try {
        const identityWords = blob.match(/[A-Za-z][A-Za-z0-9]{2,23}/g) || [];
        let nearBest = null;
        const sourceFamily = (source) => {
          const s = String(source || "");
          if (/^(?:title|h1|ogTitle|twitterTitle)$/i.test(s)) return "headline";
          if (/^(?:ogSite|schema|applicationName)$/i.test(s)) return "siteIdentity";
          if (/^logo$/i.test(s)) return "brandMark";
          return s && s !== "domain" ? s : "";
        };
        const primarySource = (source) => /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema|applicationName)$/i.test(String(source || ""));
        const exactLatinHit = (text, word) => {
          const esc = String(word || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          return !!(esc && new RegExp(`(?:^|[^A-Za-z0-9])${esc}(?=$|[^A-Za-z0-9])`, "i").test(String(text || "")));
        };
        const pageEvidenceFor = (original, flat) => {
          const families = new Set();
          const primaryFamilies = new Set();
          let occurrences = 0;
          let leadHits = 0;
          identitySlots.forEach((slot) => {
            if (!exactLatinHit(slot.text, original)) return;
            occurrences += 1;
            families.add(slot.family);
            if (slot.primary) primaryFamilies.add(slot.family);
            const idx = String(slot.text || "").toLowerCase().indexOf(String(original || "").toLowerCase());
            if (idx >= 0 && idx <= 24) leadHits += 1;
          });
          try {
            const pk = NS.caches && NS.caches._primaryKw;
            for (const [name, info] of Object.entries((pk && pk.scores) || {})) {
              const key = String(name || "").toLowerCase().replace(/[^a-z0-9]/g, "");
              if (!key || key !== flat) continue;
              (Array.isArray(info && info.sources) ? info.sources : []).forEach((source) => {
                const family = sourceFamily(source);
                if (family) families.add(family);
                if (primarySource(source)) primaryFamilies.add(family);
              });
            }
          } catch { /* ignore */ }
          return {
            families: families.size,
            primaryFamilies: primaryFamilies.size,
            occurrences,
            leadHits,
            pageDeclared: primaryFamilies.size > 0 || (families.size >= 2 && families.has("brandMark"))
          };
        };
        const lockedKey = (() => {
          try {
            const state = NS.state || {};
            const ev = state._spoofBrandEvidence;
            const url = String((typeof location !== "undefined" && location.href) || "").split("#")[0];
            if (!state._spoofBrandEvidenceLocked || !ev || ev.url !== url) return "";
            return String(state.spoofBrand || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          } catch { return ""; }
        })();
        for (let wi = 0; wi < Math.min(identityWords.length, 80); wi++) {
          const original = identityWords[wi];
          const flat = original.toLowerCase().replace(/[^a-z0-9]/g, "");
          const shortUpperAcronym = /^[A-Z][A-Z0-9]{2}$/.test(original);
          if ((!shortUpperAcronym && flat.length < 5) || flat.length > 20 || BRAND_TOKEN_STOP_RE.test(flat)) continue;
          const pageEvidence = pageEvidenceFor(original, flat);
          // 域名/host 核只能反证页面身份，不能凭 exact 关系自己成为候选。
          if (!pageEvidence.pageDeclared) continue;
          const match = typeof NS.resolveMutualLatinBrandIdentity === "function"
            ? NS.resolveMutualLatinBrandIdentity(original, host)
            : { matched: false, displayBrand: "", pageForm: flat, hostForm: "", relation: "none" };
          if (!match.matched) continue;
          const relationRank = match.relation === "exact" ? 4
            : (match.relation === "typo" ? 3 : 2);
          // 页面独立身份证据是主排序，host exact 只作最后一级关系分。
          // 已由强页面证据锁定的候选在同页保持稳定，后来的 host 长核不得抢位。
          const score = (lockedKey && flat === lockedKey ? 1000000 : 0)
            + pageEvidence.primaryFamilies * 10000
            + pageEvidence.families * 1000
            + pageEvidence.leadHits * 100
            + pageEvidence.occurrences * 10
            + relationRank;
          if (!nearBest || score > nearBest.score
            || (score === nearBest.score && pageEvidence.primaryFamilies > nearBest.pageEvidence.primaryFamilies)
            || (score === nearBest.score && pageEvidence.primaryFamilies === nearBest.pageEvidence.primaryFamilies
              && pageEvidence.occurrences > nearBest.pageEvidence.occurrences)) {
            nearBest = {
              original,
              displayBrand: match.displayBrand || original,
              flat: match.pageForm || flat,
              score,
              relation: match.relation,
              hostForm: match.hostForm,
              pageEvidence
            };
          }
        }
        if (nearBest) {
          try {
            if (NS.caches) NS.caches._mutualLatinBrandIdentity = { ...nearBest, host };
            NS.silverfoxLog && NS.silverfoxLog(
              "brand-latin", "mutual-identity",
              nearBest.original, nearBest.flat, "⇄", nearBest.hostForm, nearBest.relation
            );
          } catch { /* ignore */ }
          if (nearBest.original === nearBest.original.toUpperCase() && nearBest.original.length <= 5) {
            return nearBest.original;
          }
          return nearBest.displayBrand || nearBest.original;
        }
      } catch { /* ignore */ }

      // 优先：段在页内整词出现，保留页内大小写（WPS 而非 Wps）
      // 短核优先（wps 优于 officce 拼写噪声）
      const ranked = segs.slice().sort((a, b) => {
        // 页内命中优先
        const aHit = blobLow.includes(a) ? 1 : 0;
        const bHit = blobLow.includes(b) ? 1 : 0;
        if (bHit !== aHit) return bHit - aHit;
        // 3–6 字母品牌核优先于长噪声段
        const aNice = a.length >= 2 && a.length <= 6 ? 1 : 0;
        const bNice = b.length >= 2 && b.length <= 6 ? 1 : 0;
        if (bNice !== aNice) return bNice - aNice;
        return a.length - b.length;
      });

      for (let i = 0; i < ranked.length; i++) {
        const seg = ranked[i];
        if (!blobLow.includes(seg)) continue;
        // 整词优先
        const re = new RegExp(`(?:^|[^A-Za-z0-9])(${seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})(?=$|[^A-Za-z0-9])`, "i");
        const m = blob.match(re);
        if (m && m[1]) {
          // 全大写短核保持（WPS / QQ）
          if (/^[a-z0-9]{2,5}$/i.test(m[1]) && m[1] === m[1].toUpperCase()) return m[1];
          if (/^[a-z]{2,5}$/i.test(seg) && new RegExp(`\\b${seg}\\b`, "i").test(blob)
            && blob.match(new RegExp(`\\b${seg}\\b`, "gi"))?.some((x) => x === x.toUpperCase())) {
            return seg.toUpperCase();
          }
          return m[1];
        }
        // 主机夹带粘连：wpsofficce 含 wps，页内有 WPS
        if (seg.length >= 3 && blobLow.includes(seg)) {
          const up = blob.match(new RegExp(seg, "i"));
          if (up && up[0]) {
            if (seg.length <= 5 && up[0] === up[0].toUpperCase()) return up[0];
            return typeof NS.formatBrandTokenForDisplay === "function"
              ? (NS.formatBrandTokenForDisplay(seg) || up[0])
              : up[0];
          }
        }
      }
      return "";
    } catch {
      return "";
    }
  };

  NS.isWeakChineseBrandToken = function (token) {
    const s = String(token || "").trim();
    if (!s) return true;
    if (s.length < 2) return true;
    // ★ 禁止在此调用 chinesePinyinAlignsHost：
    // chinesePinyinAlignsHost 内部会再调 isWeak → 无限递归 → 页面白屏卡死。
    // pinyin 主机对齐只在选举/展示定稿层做，本函数只做结构 weak。
    // 纯拉丁协议垃圾：BRAND_TOKEN_STOP_RE（替代已删的 isGenericTech）
    if (!/[一-鿿]/.test(s)) {
      const flat = s.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (flat && BRAND_TOKEN_STOP_RE.test(flat)) return true;
    }
    if (typeof NS.looksLikeYearMarketingBrandToken === "function"
      && NS.looksLikeYearMarketingBrandToken(s)) return true;
    if (typeof NS.looksLikePlatformEditionLabel === "function"
      && NS.looksLikePlatformEditionLabel(s)) return true;
    if (typeof NS.looksLikeMediaFeatureClaimToken === "function"
      && NS.looksLikeMediaFeatureClaimToken(s)) return true;
    if (typeof NS.looksLikeFunctionalClaimBrandToken === "function"
      && NS.looksLikeFunctionalClaimBrandToken(s)) return true;
    // 纯数字：年份弱；3–6 位门户数字品牌（4399/360/2345）放行
    if (/^\d+$/.test(s)) {
      if (/^(?:19|20)\d{2}$/.test(s)) return true;
      if (typeof NS.isRepeatedNumericBrandToken === "function"
        && NS.isRepeatedNumericBrandToken(s)) return true;
      if (/^\d{3,6}$/.test(s)) return false;
      return true;
    }
    // 下载页标题前缀动作词（「下载 火狐浏览器」）绝不当品牌
    if (/^(?:下载|安装|获取|官方|官网|免费|最新|正版|立即|马上|关于)$/.test(s)) return true;
    // 纯品类残片：远程/桌面 alone（常被「免费远程」截出后半）
    if (/^(?:远程|桌面|控制|协助|连接|访问|办公)$/.test(s)) return true;
    // 「免费远程」「极速桌面」「专业控制」：方式词+远程桌面品类，无专名（totodesk 首屏误报）
    if (/^(?:智能|自动|一键|在线|离线|实时|快速|极速|精准|批量|免费|专业|高效|便捷|云端|本地|官方|正版|最新)(?:远程|桌面|控制|协助|协作|连接|访问|办公)(?:软件|工具|服务|系统|客户端)?$/.test(s)) return true;
    // 语言/地区壳词：曾误 toast「仿冒「中文」官网」
    if (/^(?:中文|英文|英语|汉语|简体|繁体|简体中文|繁体中文|国语|粤语|日文|日语|韩文|韩语|语言|版本|国际|国内|大陆|台湾|香港|海外)$/.test(s)) return true;
    // 未裁净的「关于…」栏目整段（关于火绒杀毒）——应先 trimChineseBrandLead，残留整段仍弱
    if (/^关于/.test(s) && s.length >= 4) return true;
    // 纯品类词（无专名）——「安全」 alone 会在 火绒安全/终端安全 里到处命中抢票
    if (/^(?:品牌|产品|功能|特性|特色|方案|浏览器|客户端|软件|应用|平台|工具|系统|服务|网站|主页|中心|频道|首页|博客|新闻|资讯|社区|论坛|帮助|文档|教程|指南|专栏|杀毒|卫士|安全|终端|防护|防御|查杀|病毒|木马|广告|弹窗|音乐|歌曲|视频|办公|网盘|助手|管家)$/.test(s)) return true;
    // 功能卖点整段：「AI推荐音乐」「推荐歌曲」「智能歌单」绝不当仿冒展示名
    if (/^(?:AI|AIGC|GPT)?(?:推荐|智能推荐|猜你|为你|个性|热门|精选).{0,4}(?:音乐|歌曲|歌单|曲库|播单)$/i.test(s.replace(/[\s\-_/]+/g, ""))) return true;
    if (/^(?:推荐|智能)(?:音乐|歌曲|歌单)$/.test(s)) return true;
    // 营销口号（非产品名）：「音乐同好聚集」「开启沉浸式体验」等曾抢占 QQ音乐
    if (!/[A-Za-z0-9]/.test(s) && s.length >= 4) {
      if (/同好|聚集|沉浸|打造|专属|宇宙|听觉|爱好者|聚集地|开启|体验$|独特的你|听我想听|推荐音乐|智能推荐/.test(s)) return true;
    }
    // 站点栏目/导航形态：「技术支持」「下载中心」「新闻中心」「常见问题」「文档教程」
    // （support.html 标题「技术支持 - CrystalDiskMark…」曾误报仿冒「技术支持」）
    if (!/[A-Za-z0-9]/.test(s) && s.length >= 2 && s.length <= 8) {
      if (/(?:支持|中心|教程|指南|文档|新闻|资讯|论坛|社区|博客|帮助|问题|排查|关于|联系|客服|售后|频道|专栏)$/.test(s)) return true;
      if (/^(?:技术|客户|售后|在线|人工)?支持$/.test(s)) return true;
      if (/^(?:常见问题|故障排查|使用文档|联系作者|联系我们|关于我们|新闻中心|下载中心|帮助中心)$/.test(s)) return true;
    }
    // 程度/情态短词：可访问、更安全、最快速、全平台、跨平台、超流畅
    if (/^[可更最超全跨][一-鿿]{1,3}$/.test(s)) return true;
    // 属性词尾巴：可用性、稳定性、个性化
    if (s.length <= 5 && /[性度化]$/.test(s)) return true;
    // 营销/场景残片起手
    if (/^(?:适用|支持|提供|包含|拥有|具备|用于|基于|通过|随时|随地|轻松|快速|安全可靠|隐私保护|注重|获取|下载|安装)/.test(s)
      && !/(?:浏览器|客户端|卫士|管家|音乐|杀毒)$/.test(s)) return true;
    // 平台/系统名中文
    if (/^(?:视窗|苹果|安卓|鸿蒙|统信|麒麟)$/.test(s)) return true;
    // 明显口号残片：以「为/是/的」等结尾或含连接谓语
    if (/[为是让给把]$/.test(s)) return true;
    if (s.length >= 6 && /[为是让给把与和]/.test(s)) return true;
    // 「的」字结构（注重隐私的浏览）不当品牌
    if (s.includes("的") && s.length <= 6) return true;
    return false;
  };

  /**
   * 唯一的 UI 品牌候选边界。返回空串表示“明确拒绝”，调用方不得再回退原词。
   * 检测结论与展示名解耦：没有可信名称时仍可中性拦截。
   */
  NS.canonicalizeBrandDisplayCandidate = function (token) {
    try {
      let t = String(token || "").trim();
      if (!t) return "";
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
      if (typeof NS.normalizeDisplayBrandName === "function") {
        t = NS.normalizeDisplayBrandName(t);
      } else if (typeof NS.trimChineseBrandTrail === "function" && /[一-鿿]/.test(t)) {
        t = NS.trimChineseBrandTrail(t);
      }
      t = String(t || "").trim();
      if (!t) return "";
      if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)) return "";
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
      if (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(t.toLowerCase())) return "";
      return t;
    } catch {
      return "";
    }
  };

  /**
   * 中文 token 是否像「完整产品名」形态（结构加分用，非词表）。
   * 如 火狐浏览器 / 360安全卫士 / 网易云音乐 / QQ音乐。
   */
  NS.looksLikeChineseProductBrandMorphology = function (token) {
    const s = String(token || "").trim();
    if (!s || s.length < 2) return false;
    if (NS.CN_DIGIT_PRODUCT_RE && NS.CN_DIGIT_PRODUCT_RE.test(s)) return true;
    if (/[A-Za-z]/.test(s) && /[一-鿿]/.test(s) && s.length >= 3) {
      if (typeof NS.looksLikeFunctionalClaimBrandToken === "function"
        && NS.looksLikeFunctionalClaimBrandToken(s)) return false;
      const mixed = s.replace(/[\s\-_/·•]+/g, "").match(/^([A-Za-z][A-Za-z0-9]{1,20})([一-鿿]{1,10})$/);
      if (!mixed) return false;
      if (/(?:音乐|浏览器|播放器|输入法|客户端|安全卫士|杀毒软件|网盘|办公套件|助手|管家)$/.test(mixed[2])) return true;
      return typeof NS.candidateDomainAligned === "function"
        && NS.candidateDomainAligned(mixed[1]) >= 1;
    }
    // 专名 + 品类后缀（火绒安全 / 360安全卫士）
    if (/[一-鿿]{2,}(?:浏览器|客户端|播放器|输入法|安全卫士|安全|杀毒|卫士|管家|助手|音乐|网盘|办公)$/.test(s)
      && !/^(?:安全|杀毒|卫士)$/.test(s)) return true;
    // 2–3 字专名后不接品类也可，但需非弱词
    if (s.length >= 2 && s.length <= 4 && /[一-鿿]{2,4}/.test(s) && !NS.isWeakChineseBrandToken(s)
      && !/^[可更最超全跨]/.test(s)) return true;
    return false;
  };

  /**
   * 从单段表面文本取产品名（结构规则，无词表）。
   * 优先：拉丁+中文官网（QQ音乐官网）→ 数字产品 → 纯中文官网 → 段首混合/中文。
   * 勿用「音乐官网」截掉前面的 QQ（曾误报仿冒「音乐」）。
   */
  NS.pickChineseBrandFromPageSurface = function (raw) {
    try {
      let rawFull = String(raw || "").replace(/[\u200b-\u200d\ufeff]/g, "").trim();
      if (!rawFull) return "";

      // ⓪ 标题前缀动作词：「下载 火狐浏览器」「安装：钉钉」→ 丢掉「下载」
      rawFull = rawFull
        .replace(/^(?:免费|立即|官方)?(?:下载|安装|获取)[\s:：\-–—|·　]+/u, "")
        .replace(/^(?:下载|安装|获取)(?=[一-鿿A-Za-z])/u, "")
        .trim();
      if (!rawFull) return "";

      // ⓪′ 空格分段：首段仅 2 字动作、后续为产品 → 顺延（下载 火狐浏览器）
      try {
        const sp = rawFull.split(/[\s　]+/).map((p) => p.trim()).filter(Boolean);
        if (sp.length >= 2 && /^(?:下载|安装|获取|官方|官网)$/.test(sp[0]) && sp[1].length >= 2) {
          rawFull = sp.slice(1).join(" ");
        }
      } catch { /* ignore */ }

      // ① 拉丁+官网：「ToDesk官网」→ ToDesk（须先于「拉丁+中文」吞掉 官网）
      try {
        const latOff = (rawFull.match(
          /([A-Za-z][A-Za-z0-9]{1,20})(?:官网|官方(?:下载|网站|客户端|正版|软件)?|下载)/
        ) || [])[1] || "";
        if (latOff && latOff.length >= 2) {
          return typeof NS.canonicalizeBrandDisplayCandidate === "function"
            ? NS.canonicalizeBrandDisplayCandidate(latOff)
            : (typeof NS.normalizeDisplayBrandName === "function" ? NS.normalizeDisplayBrandName(latOff) : latOff);
        }
        // 拉丁+中文+官网：「QQ音乐官网」——中文在 官网 之前，且捕获组不含 官网
        const mixedOff = (rawFull.match(
          /([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})(?:官网|官方(?:下载|网站|客户端|正版|软件)?)/
        ) || [])[1] || "";
        if (mixedOff) {
          let ms = NS.trimChineseBrandTrail(mixedOff) || mixedOff;
          ms = typeof NS.canonicalizeBrandDisplayCandidate === "function"
            ? NS.canonicalizeBrandDisplayCandidate(ms)
            : (typeof NS.normalizeDisplayBrandName === "function" ? NS.normalizeDisplayBrandName(ms) : ms);
          if (ms.length >= 2 && !NS.isWeakChineseBrandToken(ms)) return ms;
        }
        // 数字+中文+官网
        const digOff = (rawFull.match(/(\d{2,6}[一-鿿]{2,6})(?:官网|官方)/) || [])[1] || "";
        if (digOff && CN_DIGIT_PRODUCT_RE.test(digOff)) return digOff;
        // 纯中文产品+官网：「火绒安全官网」「网易云音乐官网」——优先带 安全/卫士 的完整专名
        const cnOffFull = (rawFull.match(
          /(?<![A-Za-z0-9])([一-鿿]{2,6}(?:安全|杀毒|卫士|安全卫士)?)(?:官网|官方(?:下载|网站|客户端|正版|软件)?)/
        ) || [])[1] || "";
        if (cnOffFull && NS.isPlausibleChineseBrandLength(cnOffFull) && !NS.isWeakChineseBrandToken(cnOffFull)) {
          return cnOffFull.replace(/(?:软件)$/u, "") || cnOffFull;
        }
        const cnOff = (rawFull.match(/(?<![A-Za-z0-9])([一-鿿]{2,6})(?:官网|官方(?:下载|网站|客户端|正版|软件)?)/) || [])[1] || "";
        if (cnOff && NS.isPlausibleChineseBrandLength(cnOff) && !NS.isWeakChineseBrandToken(cnOff)) return cnOff;
      } catch {
        // 无 lookbehind 时回退：先扫拉丁+中文官网
        try {
          const mixedOff2 = (rawFull.match(
            /([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})(?:官网|官方)/
          ) || [])[1] || "";
          if (mixedOff2 && mixedOff2.length >= 3) return NS.trimChineseBrandTrail(mixedOff2) || mixedOff2;
          const cnOff2 = (rawFull.match(/([一-鿿]{2,6})(?:官网|官方)/) || [])[1] || "";
          // 若「音乐官网」前紧贴拉丁，丢弃
          if (cnOff2) {
            const idx = rawFull.indexOf(cnOff2 + "官网");
            const idx2 = rawFull.indexOf(cnOff2 + "官方");
            const i = idx >= 0 ? idx : idx2;
            if (i > 0 && /[A-Za-z0-9]/.test(rawFull.charAt(i - 1))) {
              /* skip pure cn-off */
            } else if (NS.isPlausibleChineseBrandLength(cnOff2) && !NS.isWeakChineseBrandToken(cnOff2)) {
              return cnOff2;
            }
          }
        } catch { /* fall through */ }
      }

      // ② 数字前缀产品
      try {
        const digitHit = (rawFull.match(/(\d{2,6}[一-鿿]{2,8})/) || [])[1] || "";
        if (digitHit) {
          let ds = digitHit.replace(/(?:官网|官方|下载|客户端).*$/u, "").trim();
          if (!CN_DIGIT_PRODUCT_RE.test(ds)) {
            const m2 = (digitHit.match(/^(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
            if (m2) ds = m2;
          }
          if (ds && CN_DIGIT_PRODUCT_RE.test(ds) && NS.isPlausibleChineseBrandLength(ds)) return ds;
        }
      } catch { /* fall through */ }

      // ③ 整段任意位置的拉丁+中文产品（QQ音乐听我想听）
      try {
        const mixedAny = (rawFull.match(/([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})/) || [])[1] || "";
        if (mixedAny && mixedAny.length >= 3) {
          const ms = NS.trimChineseBrandTrail(mixedAny) || mixedAny;
          // 拉丁后仅 1 字中文且像品类尾巴时仍保留（QQ音 太残；QQ音乐 OK）
          const cnPart = ms.replace(/[A-Za-z0-9]+/g, "");
          if (cnPart.length >= 1 && cnPart.length <= 6 && !NS.isWeakChineseBrandToken(ms)) return ms;
        }
      } catch { /* fall through */ }

      let t = rawFull;
      // ④ 破折号分段：优先拉丁产品 / 官网形态；栏目段「技术支持」让位「CrystalDiskMark …」
      const dashParts = t.split(/\s*[-–—|·｜]\s*/).map((p) => p.trim()).filter(Boolean);
      if (dashParts.length > 1) {
        let chosen = "";
        // 优先：含较长拉丁产品名的段（CrystalDiskMark / Firefox）
        for (const part of dashParts) {
          const lat = (part.match(/[A-Za-z][A-Za-z0-9]{3,}/) || [])[0] || "";
          if (lat.length >= 5 && !/^(?:Windows|Linux|MacOS|macOS|Android|iOS|Support|Download|Help)/i.test(lat)) {
            chosen = part;
            break;
          }
        }
        if (!chosen) {
          for (const part of dashParts) {
            if (/[A-Za-z][A-Za-z0-9]*[一-鿿]/.test(part) && /官网|官方/.test(part)) { chosen = part; break; }
            if (/[A-Za-z][A-Za-z0-9]{2,}/.test(part) && /[一-鿿]{2,}/.test(part)) { chosen = part; break; }
            if (/[A-Za-z][A-Za-z0-9]{3,}/.test(part) && !/^(?:Windows|Linux|MacOS|macOS|Android|iOS)/i.test(part)) {
              chosen = part; break;
            }
            if (/[一-鿿]{2,}.{0,4}(?:官网|官方)/.test(part) || /\d{2,6}[一-鿿]{2,}/.test(part)) {
              chosen = part; break;
            }
          }
        }
        if (!chosen) {
          // 优先含浏览器/客户端/音乐等产品形态的较长中文段，跳过栏目/适用于…
          for (const part of dashParts) {
            const head = part.replace(/^(?:下载|安装|获取)[\s　]*/u, "");
            if (/^[一-鿿]{2,8}/.test(head) && !/^适用/.test(head) && head.length >= 3
              && !NS.isWeakChineseBrandToken(head.slice(0, 6))) {
              chosen = head; break;
            }
          }
        }
        if (!chosen) {
          for (const part of dashParts) {
            if (/^[A-Za-z]/.test(part) && part.length >= 2
              && !/^(?:Windows|Linux|MacOS|macOS|Android|iOS)/i.test(part)) {
              chosen = part; break;
            }
          }
        }
        if (!chosen) {
          // 勿取栏目弱词；取含中文产品的第一段
          // 优先含产品形态的段（汽水音乐官方下载），勿先命中「应用下载」栏目壳
          chosen = dashParts.find((p) => /[一-鿿]{2,}(?:音乐|安全|杀毒|卫士|浏览器|客户端|播放器|管家|助手)/.test(p))
            || dashParts.find((p) => /[一-鿿]{3,}/.test(p) && !/^(?:适用|应用下载|产品下载|软件下载)/.test(p)
              && !NS.isWeakChineseBrandToken((p.match(/^[一-鿿]{2,6}/) || [])[0] || ""))
            || dashParts.find((p) => /[一-鿿]{2,}/.test(p) && !/^(?:下载|安装|获取|适用|应用)/.test(p)
              && !NS.isWeakChineseBrandToken((p.match(/^[一-鿿]{2,6}/) || [])[0] || ""))
            || dashParts.find((p) => /[A-Za-z][A-Za-z0-9]{3,}/.test(p))
            || dashParts[0];
        }
        t = chosen;
      } else {
        t = dashParts[0] || t;
      }
      // 段内再剥前缀动作
      t = t.replace(/^(?:免费|立即|官方)?(?:下载|安装|获取)[\s:：　]+/u, "").trim();
      if (/[：:]/.test(t)) {
        const after = t.split(/[：:]/).slice(1).join("：").trim();
        if (after.length >= 2 && after.length < t.length) {
          const afterHead = after.split(/\s*[-–—|]\s*/)[0].trim();
          if (afterHead.length >= 2 && afterHead.length <= 12) t = afterHead;
        }
      }
      t = t.replace(/(?:官网下载|官方下载|免费下载|立即下载|客户端下载|下载中心|电脑版|手机版).*$/u, "").trim();
      t = t.replace(/(?:官网|官方|下载)$/u, "").trim();
      // 「应用下载」栏目壳：后面还有产品名时丢掉
      if (/^(?:应用|产品|软件)?下载$/.test(t) || /^(?:官方)?下载中心$/.test(t)) {
        const rest = rawFull.replace(/^[\s\S]*?[-–—|]\s*/, "").trim();
        if (rest && rest !== rawFull && rest.length >= 2) t = rest
          .replace(/(?:官网下载|官方下载|免费下载|立即下载).*$/u, "")
          .replace(/(?:官网|官方|下载)$/u, "")
          .trim() || t;
      }
      if (!t) return "";
      // 拉丁+中文（段首）
      const mixed = (t.match(/^([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})/) || [])[1] || "";
      if (mixed) {
        const ms = NS.trimChineseBrandTrail(mixed) || mixed;
        if (ms.length >= 3 && !NS.isWeakChineseBrandToken(ms)) return ms;
      }
      const digitCn = (t.match(/^(\d{2,6}[一-鿿]{2,6})/) || [])[1] || "";
      if (digitCn && NS.isPlausibleChineseBrandLength(digitCn)) return digitCn;
      t = NS.cutChineseBrandBeforeSlogan(t) || t;
      // 优先「…音乐 / …安全」完整产品形态（汽水音乐），勿只取前 2 字
      const fullMorph = (t.match(/^([一-鿿]{2,6}(?:音乐|安全|杀毒|卫士|浏览器|客户端|播放器|输入法|管家|助手|网盘))/) || [])[1] || "";
      if (fullMorph && !NS.isWeakChineseBrandToken(fullMorph)) {
        return fullMorph;
      }
      // 「钉钉应用中心 / 火绒安全中心」：专名 + 应用/中心栏目壳 → 只取专名
      // 禁止「中文官网」→「中文」
      const shellLead = (t.match(/^([一-鿿]{2,4})(?:应用中心|应用|中心|官方|官网)/) || [])[1] || "";
      if (shellLead
        && !(typeof NS.isForbiddenSpoofDisplayBrand === "function" && NS.isForbiddenSpoofDisplayBrand(shellLead))
        && !NS.isWeakChineseBrandToken(shellLead)
        && !/^(?:应用|官方|官网|下载|安全|杀毒|中文|英文)$/.test(shellLead)) {
        return shellLead;
      }
      const pure = (t.match(/^([一-鿿]{2,6})/) || [])[1] || "";
      if (!pure) return "";
      // 纯中文前若原文紧贴拉丁（QQ音乐 → 勿只取 音乐）：在 raw 中校验
      try {
        const pidx = rawFull.indexOf(pure);
        if (pidx > 0 && /[A-Za-z0-9]/.test(rawFull.charAt(pidx - 1))) {
          const mixedBack = (rawFull.slice(Math.max(0, pidx - 12), pidx + pure.length)
            .match(/([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})$/) || [])[1] || "";
          if (mixedBack && mixedBack.length >= 3) return NS.trimChineseBrandTrail(mixedBack) || mixedBack;
        }
      } catch { /* ignore */ }
      let s = typeof NS.normalizeChineseBrandToken === "function"
        ? (NS.normalizeChineseBrandToken(pure) || pure)
        : (NS.trimChineseBrandTrail(pure));
      s = NS.cutChineseBrandBeforeSlogan(s) || s;
      // 段首仍是「关于…」整句时再裁一次
      if (typeof NS.trimChineseBrandLead === "function") s = NS.trimChineseBrandLead(s) || s;
      // 整段仍是「…应用中心」弱词时再剥壳
      if (s && NS.isWeakChineseBrandToken(s)) {
        const peeled = NS.trimChineseBrandTrail(s);
        if (peeled && peeled !== s && !NS.isWeakChineseBrandToken(peeled)) s = peeled;
        else {
          const lead2 = (s.match(/^([一-鿿]{2,4})/) || [])[1] || "";
          if (lead2 && !NS.isWeakChineseBrandToken(lead2)) s = lead2;
        }
      }
      if (!s || !NS.isPlausibleChineseBrandLength(s) || NS.isWeakChineseBrandToken(s)) return "";
      // 过短纯中文（2 字）且全文存在「拉丁+该中文」时让位混合品牌
      if (s.length <= 2) {
        const mixedPrefer = (rawFull.match(new RegExp("([A-Za-z][A-Za-z0-9]{0,12}" + s + ")")) || [])[1] || "";
        if (mixedPrefer && mixedPrefer.length > s.length) return mixedPrefer;
      }
      // 短残片且不像产品形态时，全文另有「…浏览器/客户端」等则改返回产品
      if (typeof NS.looksLikeChineseProductBrandMorphology === "function"
        && !NS.looksLikeChineseProductBrandMorphology(s) && s.length <= 3) {
        const prod = (rawFull.match(/([一-鿿]{2,6}(?:浏览器|客户端|播放器|输入法|安全卫士|杀毒|管家|助手|音乐))/) || [])[1]
          || (rawFull.match(/([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})/) || [])[1]
          || (rawFull.match(/(\d{2,6}[一-鿿]{2,6})/) || [])[1]
          || "";
        if (prod && !NS.isWeakChineseBrandToken(prod)) return NS.trimChineseBrandTrail(prod) || prod;
      }
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
        // 数字前缀产品保留安全/卫士等本体；其余走营销头尾裁剪
        if (CN_DIGIT_PRODUCT_RE.test(s)) {
          const cut = s.replace(/(?:双平台|全平台|多平台|跨平台|应用|市场|平台|客户端|官网|中心|下载站|下载中心|商店|商城)$/g, "").trim();
          if (CN_DIGIT_PRODUCT_RE.test(cut)) s = cut;
        } else if (typeof NS.normalizeChineseBrandToken === "function") {
          s = NS.normalizeChineseBrandToken(s) || s;
        } else {
          s = NS.trimChineseBrandTrail(s);
        }
        if (!s || s.length < 2) return;
        if (typeof NS.isPlausibleChineseBrandLength === "function"
          ? !NS.isPlausibleChineseBrandLength(s)
          : (s.length > 6 && !CN_DIGIT_PRODUCT_RE.test(s))) return;
        if (NS.isWeakChineseBrandToken(s)) return;
        const prev = score.get(s) || { score: 0, source: src };
        const next = prev.score + w;
        score.set(s, { score: next, source: prev.score >= next ? prev.source : src });
      };
      const feed = (raw, src) => {
        const text = String(raw || "").trim();
        if (!text) return;
        // 每字段最多计 1 票：字段内任一候选命中即对该候选 +EQ（同一 src 不重复）
        const seenLocal = new Set();
        const mark = (hit) => {
          let h = String(hit || "").trim();
          if (!h) return;
          if (typeof NS.normalizeChineseBrandToken === "function") h = NS.normalizeChineseBrandToken(h) || h;
          if (!h || seenLocal.has(h)) return;
          seenLocal.add(h);
          bump(h, 1, src); // 等权 1 票
        };
        text.split(/[,，、|｜·•]+/).forEach((part) => {
          const p = part.trim();
          if (!p || p.length > 48) return;
          mark(NS.pickChineseBrandFromPageSurface(p));
          // 火绒安全整段保留；勿 /安全$/ 可选剥成「火绒」或留下「安全」
          const fullProd = p.match(/^([一-鿿]{2,8}(?:安全|杀毒|卫士|安全卫士)?)(?:官网|官方|下载|软件|客户端|应用|市场|平台)?$/);
          if (fullProd) mark(fullProd[1].replace(/(?:软件|客户端)$/u, ""));
          const m = p.match(/^([一-鿿]{2,6})(?:官网|官方|下载|客户端)?$/);
          if (m && !/^(?:安全|杀毒|卫士)$/.test(m[1])) mark(m[1]);
          const dm = p.match(/^(\d{2,6}[一-鿿]{2,6})(?:官网|官方|下载|软件|客户端|应用|市场|平台)?$/);
          if (dm) mark(dm[1]);
        });
        mark(NS.pickChineseBrandFromPageSurface(text));
      };
      // 等权身份字段（与 collectPrimaryBrandKeywords 一致，含 OG / Twitter）
      feed(fields.title, "title");
      feed(fields.description, "description");
      feed(fields.keywords, "keywords");
      feed(fields.h1, "h1");
      feed(fields.h2, "h2");
      feed(fields.ogTitle, "ogTitle");
      feed(fields.ogDescription, "ogDescription");
      feed(fields.ogImageAlt, "ogImageAlt");
      feed(fields.ogSite, "ogSite");
      feed(fields.twitterTitle, "twitterTitle");
      feed(fields.twitterDescription, "twitterDescription");
      feed(fields.twitterImageAlt, "twitterImageAlt");
      feed(fields.span || fields.logo, "span");
      feed(fields.footer, "footer");

      let best = ""; let bestS = 0;
      for (const [c, info] of score) {
        // 票数主导；同分才形态决胜
        let s = info.score * 100;
        for (const [other] of score) {
          if (other === c) continue;
          if (other.startsWith(c) && other.length > c.length && other.length - c.length <= 2) s += 2;
          if (c.startsWith(other) && c.length > other.length && c.length - other.length <= 2) s -= 2;
        }
        if (CN_DIGIT_PRODUCT_RE.test(c)) s += 3;
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

  /** 从单段文本抽中文/混合产品候选（结构规则，无词表） */
  NS.extractChineseProductBrandCandidates = function (text) {
    const out = [];
    const seen = new Set();
    const add = (c) => {
      let s = String(c || "").trim();
      if (s.length < 2 || s.length > 12) return;
      if (!CN_DIGIT_PRODUCT_RE.test(s)) s = NS.trimChineseBrandTrail(s);
      if (!NS.isPlausibleChineseBrandLength(s)) return;
      if (NS.isWeakChineseBrandToken(s)) return;
      if (seen.has(s)) return;
      seen.add(s);
      out.push(s);
    };
    const t = String(text || "").replace(/[\u200b-\u200d\ufeff]/g, "");
    if (typeof NS.pickChineseBrandFromPageSurface === "function") {
      const surface = NS.pickChineseBrandFromPageSurface(t);
      if (surface) add(surface);
    }
    (t.match(/\d{2,6}[一-鿿]{2,6}/g) || []).forEach(add);
    (t.match(/[A-Za-z][A-Za-z0-9]{0,10}[一-鿿]{1,6}/g) || []).forEach(add);
    t.split(/[,，、|｜]+/).forEach((part) => {
      const p = part.trim();
      if (p.length < 2 || p.length > 32) return;
      if (/^[一-鿿]{1,6}[A-Za-z]/.test(p)) return;
      add(NS.pickChineseBrandFromPageSurface(p) || "");
      if (/^[一-鿿]{2,8}$/.test(p)) add(p);
      if (CN_DIGIT_PRODUCT_RE.test(p)) add(p);
    });
    // 破折号分段：优先含数字/拉丁的段
    const headSegs = t.split(/\s*[-–—|:·｜]\s*/).map((p) => p.trim()).filter(Boolean);
    for (const seg of headSegs) {
      if (/\d{2,6}[一-鿿]{2,}/.test(seg) || /^[A-Za-z]/.test(seg)) {
        add(NS.pickChineseBrandFromPageSurface(seg) || "");
        break;
      }
    }
    if (headSegs[0]) add(NS.pickChineseBrandFromPageSurface(headSegs[0]) || "");
    return out;
  };

  /**
   * 产品关键词选主品牌：展示名 **只** 走 collectPrimaryBrandKeywords 等权综合
   * （title/description/keywords/h1/h2/span/footer 各 1 票）。
   * 本函数仅补充 brandToken（供主机对齐），不再另起一套加权打分。
   */
  NS.pickProductBrandFromIdentity = function (labelRawOpt) {
    try {
      const labelRaw = String(labelRawOpt != null ? labelRawOpt : ((location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || ""));
      // ★ 唯一展示名来源：等权多字段共识
      const pk = typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords()
        : { display: "", cn: [], latin: [], tokens: [], scores: {} };
      const displayBrand = pk.display || "";
      const cnBrand = (pk.cn && pk.cn[0]) || (/[一-鿿]/.test(displayBrand) ? displayBrand : "");
      let latinToken = (pk.latin && pk.latin[0]) || "";
      // 主机对齐用：可在等权结果的拉丁列表里挑与 host 最相关的，但 **不改 displayBrand**
      if (labelRaw && pk.latin && pk.latin.length) {
        const lab = labelRaw.replace(/-/g, "");
        const aligned = pk.latin.find((low) => {
          if (lab === low) return true;
          if (typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lab, low)) return true;
          if (typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, low)) return true;
          if (typeof NS.hostLabelIsBrandTypo === "function" && NS.hostLabelIsBrandTypo(lab, low)) return true;
          return false;
        });
        if (aligned) latinToken = aligned;
      }
      const brandToken = latinToken || cnBrand || displayBrand || "";
      const topVotes = displayBrand && pk.scores && pk.scores[displayBrand]
        ? (pk.scores[displayBrand].votes || pk.scores[displayBrand].score || 0)
        : 0;
      return {
        displayBrand,
        brandToken,
        latinToken: latinToken || "",
        cnBrand: cnBrand || "",
        source: "equal-field-votes",
        score: topVotes,
        fields: typeof NS.collectProductBrandIdentityFields === "function"
          ? NS.collectProductBrandIdentityFields()
          : null
      };
    } catch {
      return { displayBrand: "", brandToken: "", latinToken: "", cnBrand: "", source: "", score: 0, fields: null };
    }
  };

  /**
   * 展示用品牌名：只走等权综合 collectPrimaryBrandKeywords，禁止表面字段抢先。
   */
  NS.pickBrandDisplayName = function (opts) {
    try {
      void opts;
      if (typeof NS.collectPrimaryBrandKeywords === "function") {
        const pk = NS.collectPrimaryBrandKeywords();
        if (typeof NS.resolveSpoofDisplayBrand === "function") {
          return NS.resolveSpoofDisplayBrand(
            typeof location !== "undefined" ? location.hostname : "",
            pk
          ) || "";
        }
        if (pk && pk.display && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          return NS.canonicalizeBrandDisplayCandidate(pk.display);
        }
        if (pk && pk.display) return pk.display;
      }
      // brandToken 是相关性/域名核，不是页面声明的展示身份。
      return "";
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

  /** 标题主品牌：优先取 <title> 开头的专有名（DingTalk/Firefox），而非平台词 Windows/Linux */
  NS.pickPrimaryTitleBrandToken = function (titleText, labelRaw) {
    let title = String(titleText || "").trim();
    if (!title) return "";
    // 剥「下载 火狐…」动作前缀，避免段首无拉丁
    title = title
      .replace(/^(?:免费|立即|官方)?(?:下载|安装|获取)[\s:：\-–—|·　]+/u, "")
      .replace(/^(?:下载|安装|获取)(?=[一-鿿A-Za-z])/u, "")
      .trim() || title;
    const plat = /^(?:windows|linux|macos|mac|android|ios|x64|x86|platform)$/i;
    const head = title.split(/\s*[-–—|:·]\s*/)[0] || title;
    const headTokens = NS.extractLatinBrandTokens(head).filter((t) => !plat.test(t));
    if (headTokens.length) {
      const sorted = headTokens.slice().sort((a, b) => b.length - a.length || a.localeCompare(b));
      const primary = sorted[0] || "";
      if (primary.length >= 4) return primary;
    }
    const all = NS.extractLatinBrandTokens(title).filter((t) => !plat.test(t));
    if (!all.length) return "";
    return NS.pickBrandTokenForHost(all, labelRaw) || all[0] || "";
  };

  /**
   * 从营销夹带主机推断品牌核心：huorong-pc → huorong；im-todesk / pr-todesk → todesk。
   * 用于页面仅有中文品牌名、无拉丁 token 时仍能标 padded。
   * 切勿把 prtodesk 拆成 prto+desk（desk 是 ToDesk 品牌本体后缀，不是营销垫词）。
   */
  NS.inferMarketingPaddedBrandCore = function (rawLabel) {
    try {
      const raw = String(rawLabel || "").toLowerCase().replace(/^www\./, "");
      if (!raw || raw.length < 5) return "";
      // 营销结构剥出的核再收 1～2 字符污染尾：pc-todeskr → todeskr → todesk
      // 仅用于「前缀/后缀夹带剥出的段」，禁止对 google/notion/todesk 等干净整词盲删末字。
      const finishCore = (core0) => {
        let x = String(core0 || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!x || x.length < 6) return x.length >= 4 ? x : "";
        const rawSegs = raw.split(/[-_]/).map((p) => String(p || "").replace(/[^a-z0-9]/g, "")).filter(Boolean);
        // 只收「原始标签里出现过的污染段」：todeskr ∈ pc-todeskr；不收已干净的 todesk
        if (!rawSegs.includes(x) && x !== raw.replace(/[^a-z0-9]/g, "")) return x;
        // 干净整词标签（google）即便 == rawFlat 也不剥：须同时是「多段夹带后的剩余段」或 padded 形
        const fromMktSegment = rawSegs.length >= 2 && rawSegs.includes(x);
        if (!fromMktSegment) return x;
        try {
          if (typeof NS.hostLabelIsPaddedBrand === "function") {
            for (let n = 1; n <= 2; n++) {
              const head = x.slice(0, -n);
              const tail = x.slice(-n);
              if (head.length < 5) break;
              if (!/^[a-z0-9]+$/i.test(tail)) continue;
              if (n === 2 && /^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(tail)) continue;
              if (NS.hostLabelIsPaddedBrand(x, head)) {
                x = head;
                break;
              }
            }
          }
        } catch { /* ignore */ }
        return x;
      };
      // 营销夹带后缀（huorong-pc / huorong-lab）；勿含 security/antivirus/ai/gpt——产品线正站
      const mktSuf = /^(?:pc|app|soft|safe|vip|pro|cn|win|desk|guard|download|down|client|free|official|online|tool|tools|hub|box|mac|ios|android|mobile|setup|install|site|web|net|home|store|lab|labs|tech)$/i;
      // ie/v-huorong：ie、v 为短营销前缀（频道/单字母夹带）
      const mktPre = /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|pr|gw|my|the|best|new|top|go|use|try|win|cn|zh|en|im|ie|v|x|z|qq|wx|dl|to|up|re|un|web|www\d*|hi|ok|yes|seo|cdn|ott|tv|hd)$/i;
      const isMktPre = (part) => mktPre.test(part)
        || (typeof NS.isMarketingHostPrefixToken === "function"
          && NS.isMarketingHostPrefixToken(part, { strict: true }));
      // 品牌产品线域：不推断为 padded 核心
      if (/-/.test(raw) && typeof NS.hostLabelIsBrandProductCategoryDomain === "function") {
        const parts0 = raw.split("-").filter(Boolean);
        if (parts0.length >= 2) {
          const head0 = parts0[0].replace(/[^a-z0-9]/g, "");
          if (head0.length >= 3 && NS.hostLabelIsBrandProductCategoryDomain(raw, head0)) return "";
        }
      }
      if (/-/.test(raw)) {
        const parts = raw.split("-").filter(Boolean).map((p) => String(p || "").replace(/[^a-z0-9]/g, ""));
        if (parts.length >= 2) {
          const first = parts[0];
          const last = parts[parts.length - 1];
          // ding-apps-dingding / brand-app-brand：中间 apps 等营销垫，取最长非营销段
          if (parts.length >= 3) {
            const mktMid = /^(?:apps?|soft|safe|vip|pro|pc|cn|win|download|down|client|free|official|online|tool|tools|hub|box|lab|labs|tech|site|web|net|store)$/i;
            const brandish = parts.filter((p) => p.length >= 4 && !mktMid.test(p) && !isMktPre(p) && !mktSuf.test(p));
            if (brandish.length >= 1) {
              brandish.sort((a, b) => b.length - a.length || b.localeCompare(a));
              // ding 与 dingding 并存时取更长完整核
              return finishCore(brandish[0]);
            }
          }
          // ott-todesk / pr-todesk / aa-todesk / im-todesk / pc-todeskr：短前缀 + 品牌核 → 核心是后段
          if (first.length >= 1 && first.length <= 4 && last.length >= 4 && last.length <= 18
            && !mktSuf.test(last) && !isMktPre(last)
            && (isMktPre(first) || first.length <= 3
              || /^(?:pr|gw|seo|cdn|ott|tv|hd|www\d*|vip|pro|soft|safe|dl)$/i.test(first)
              || (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(first)))) {
            return finishCore(last);
          }
          // ding-apps / brand-apps：尾段营销 → 前段；若中段 apps 且末段更长品牌
          if (parts.length === 2 && mktSuf.test(last) && /^[a-z][a-z0-9]{3,16}$/i.test(first) && !isMktPre(first) && !mktSuf.test(first)) {
            return finishCore(first);
          }
          // ★ dingtalk-o / todesk-x / huorong-1：长品牌核 + 1～2 字符垃圾尾
          // （仿冒站常用单字母/数字垫；勿把 -ai/-go 产品线误剥——上面品类域已 return ""）
          if (parts.length === 2
            && first.length >= 5 && first.length <= 18
            && last.length >= 1 && last.length <= 2
            && /^[a-z0-9]{1,2}$/i.test(last)
            && /^[a-z][a-z0-9]{4,17}$/i.test(first)
            && !isMktPre(first) && !mktSuf.test(first)
            && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(last)) {
            return finishCore(first);
          }
          // apps 作中缀的 2+ 段：ding-apps-xxx 已在 ≥3 处理；brand-apps 见上
          if (parts.some((p) => /^(?:apps?)$/i.test(p))) {
            const brandish2 = parts.filter((p) => p.length >= 4 && !/^(?:apps?)$/i.test(p) && !isMktPre(p) && !mktSuf.test(p));
            if (brandish2.length) {
              brandish2.sort((a, b) => b.length - a.length);
              return finishCore(brandish2[0]);
            }
          }
          // huorong-pc / huorong-safe-pc（非 pyas-security）
          if (mktSuf.test(last) && /^[a-z][a-z0-9]{3,16}$/i.test(first) && !isMktPre(first) && !mktSuf.test(first)) {
            return finishCore(first);
          }
          // im-todesk / get-huorong（多段时取品牌段）
          if (isMktPre(first) && parts[1] && /^[a-z][a-z0-9]{3,16}$/i.test(parts[1]) && !mktSuf.test(parts[1])) {
            return finishCore(String(parts[1]));
          }
        }
      }
      const lab = raw.replace(/-/g, "");
      // 不再对无页面证据的整段标签盲删最后一个字符。
      // huorongr / qishuiyyds 之类必须由页面候选经 pinyin/拉丁双向确认；
      // 否则 google/notion 等正常标签也会被错误裁短。
      // 无连字符：禁止用 desk 作营销尾缀——todesk/anydesk 等品牌以 desk 结尾，
      // 否则 prtodesk → prto+desk 误报「Prto」；含 lab：huoronglab → huorong
      const m = lab.match(/^([a-z][a-z0-9]{3,16})(pc|app|soft|safe|vip|pro|cn|win|security|guard|download|client|free|official|lab|labs|tech|site)$/i);
      if (m && m[1] && !isMktPre(m[1])) return finishCore(m[1].toLowerCase());
      // ★ totodesk → todesk：前缀 to + 仍以 to 开头的品牌核。
      // 勿写通用 ^to(...)——会把 todeskai 剥成 deskai；仅 remainder 仍以 to 起头才剥。
      const toToBrand = lab.match(/^to(to[a-z0-9]{3,16})$/i);
      if (toToBrand && toToBrand[1] && !mktSuf.test(toToBrand[1]) && !isMktPre(toToBrand[1])) {
        return finishCore(toToBrand[1].toLowerCase());
      }
      // 无连字符前缀粘连：vdingtalk → dingtalk；qqmusics → musics（勿含 to，避免 todeskai 被拆）
      const glued = lab.match(/^(v|x|z|aa|bb|cc|ca|im|ie|pr|gw|get|ott|seo|cdn|vip|my|dl|qq|wx|hd|tv|win|pc)([a-z][a-z0-9]{4,18})$/i);
      if (glued && glued[2] && glued[2].length >= 4 && glued[2].length <= 18
        && !mktSuf.test(glued[2]) && !mktPre.test(glued[2])) {
        return finishCore(glued[2].toLowerCase());
      }
      // 品类尾剥核：qissmusic → qiss；qishuiyinyue → qishui；qqmusic → qq（算法，无品牌特判）
      try {
        if (typeof NS.parseHostChineseProductCategoryPad === "function") {
          const pad = NS.parseHostChineseProductCategoryPad(raw || lab);
          if (pad && pad.prefix && pad.prefix.length >= 2 && pad.prefix.length <= 16) {
            return finishCore(pad.prefix);
          }
        }
      } catch { /* ignore */ }
      // 裸标签污染尾（todeskr / huorongr）不在此盲剥——交由页面候选双向匹配；
      // 夹带路径（pc-todeskr）已在上方 finishCore 收尾。
      return "";
    } catch { return ""; }
  };

  const spoofBrandEvidenceKey = (raw) => String(raw || "").trim()
    .toLowerCase().replace(/[^a-z0-9一-鿿]/gi, "");

  const spoofBrandEvidenceUrl = () => {
    try {
      return String((typeof location !== "undefined" && location.href) || "").split("#")[0];
    } catch {
      return "";
    }
  };

  const spoofBrandSourceFamily = (source) => {
    const s = String(source || "");
    if (/^(?:title|h1|ogTitle|twitterTitle)$/i.test(s)) return "headline";
    if (/^(?:ogSite|schema|applicationName)$/i.test(s)) return "siteIdentity";
    if (/^logo$/i.test(s)) return "brandMark";
    return s && s !== "domain" ? s : "";
  };

  /**
   * 展示候选的通用证据等级。域名只负责反证，不会单独得到“强页面身份”级别。
   * 返回值供统一 setter 做单调升级；不维护任何品牌名白名单。
   */
  NS.getSpoofDisplayBrandEvidence = function (brand, opts) {
    const raw = String(brand || "").trim();
    const key = spoofBrandEvidenceKey(raw);
    const out = {
      key,
      url: spoofBrandEvidenceUrl(),
      rank: 0,
      kind: "none",
      primaryFamilies: 0,
      families: 0,
      pagePreferred: false,
      hostMatched: false,
      pinyinValidated: false
    };
    try {
      if (!raw || !key) return out;
      if (typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(raw)) return out;

      const o = opts || {};
      const families = new Set();
      const primaryFamilies = new Set();
      let primaryDisplay = false;
      const addSource = (source) => {
        const family = spoofBrandSourceFamily(source);
        if (family) families.add(family);
        if (/^(?:title|h1|ogTitle|twitterTitle|ogSite|schema|applicationName)$/i.test(String(source || ""))) {
          primaryFamilies.add(family);
        }
      };

      try {
        const pk = NS.caches && NS.caches._primaryKw;
        primaryDisplay = spoofBrandEvidenceKey(pk && pk.display) === key;
        for (const [name, info] of Object.entries((pk && pk.scores) || {})) {
          if (spoofBrandEvidenceKey(name) !== key) continue;
          (Array.isArray(info && info.sources) ? info.sources : []).forEach(addSource);
        }
      } catch { /* ignore */ }

      // 缓存尚未完成时只读短身份槽；不扫正文，不把正文营销词抬成品牌。
      try {
        const slots = [
          { source: "title", text: document.title || "" },
          { source: "h1", text: document.querySelector("h1")?.textContent || "" },
          { source: "ogSite", text: document.querySelector('meta[property="og:site_name"]')?.getAttribute("content") || "" },
          { source: "applicationName", text: document.querySelector('meta[name="application-name"]')?.getAttribute("content") || "" },
          { source: "ogTitle", text: document.querySelector('meta[property="og:title"]')?.getAttribute("content") || "" },
          { source: "logo", text: document.querySelector(".logo, [class*='logo']")?.textContent || "" }
        ];
        const hasCn = /[一-鿿]/.test(raw);
        const esc = raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        slots.forEach((slot) => {
          const text = String(slot.text || "");
          if (!text) return;
          const hit = hasCn
            ? text.includes(raw)
            : new RegExp(`(?:^|[^A-Za-z0-9])${esc}(?=$|[^A-Za-z0-9])`, "i").test(text);
          if (hit) addSource(slot.source);
        });
      } catch { /* ignore */ }

      const hasCn = /[一-鿿]/.test(raw);
      if (hasCn) {
        try {
          if (typeof NS.chinesePinyinAlignsHost === "function"
            && NS.chinesePinyinAlignsHost(raw)) out.pinyinValidated = true;
        } catch { /* ignore */ }
        try {
          const sw = NS.state && NS.state._brandPinyinEvidence;
          if (sw && spoofBrandEvidenceKey(sw.brand) === key) out.pinyinValidated = true;
        } catch { /* ignore */ }
      } else {
        try {
          out.hostMatched = !!(typeof NS.resolveMutualLatinBrandIdentity === "function"
            && NS.resolveMutualLatinBrandIdentity(raw).matched);
        } catch { /* ignore */ }
        try {
          const preferred = typeof NS.pickHostAlignedLatinBrandFromPage === "function"
            ? NS.pickHostAlignedLatinBrandFromPage()
            : "";
          out.pagePreferred = spoofBrandEvidenceKey(preferred) === key;
        } catch { /* ignore */ }
      }

      out.primaryFamilies = primaryFamilies.size;
      out.families = families.size;
      let rank = 10;
      if (families.size > 0) rank = Math.max(rank, 80 + families.size * 10);
      if (primaryFamilies.size > 0) rank = Math.max(rank, 220 + primaryFamilies.size * 40);
      if (primaryDisplay) rank += 40;
      if (out.hostMatched) rank += 60;
      if (out.pagePreferred) rank += 120;
      if (out.pinyinValidated) rank = Math.max(rank, 560);
      // 非 pinyin 的中文定稿必须来自至少两个独立主身份族；标题/OG 镜像只算 headline 一族。
      if (hasCn && o.forceChinese === true && primaryFamilies.size >= 2) rank = Math.max(rank, 520);
      out.rank = rank;
      out.kind = out.pinyinValidated
        ? "pinyin-mutual"
        : (out.pagePreferred && out.hostMatched
          ? "page-host-mutual"
          : (primaryFamilies.size > 0 ? "page-identity" : (out.hostMatched ? "host-fallback" : "weak")));
      return out;
    } catch {
      return out;
    }
  };

  /**
   * 统一写入 spoofBrand，防止「钉钉」与「Dingding」互相覆盖抢 toast。
   * 规则：
   * - 已锁定中文（_spoofBrandChineseLocked）时，禁止纯拉丁/拼音核回写
   * - 当前已是中文时，禁止用纯拉丁替换
   * - 强页面身份一旦成立，只允许同名或经 pinyin/定稿验证的语义升级
   * - 写入中文时自动锁定
   * @returns {string} 实际生效的展示名
   */
  NS.setSpoofDisplayBrand = function (brand, opts) {
    try {
      const state = NS.state;
      if (!state) return String(brand || "").trim();
      const o = opts || {};
      let next = String(brand || "").trim();
      let cur = String(state.spoofBrand || "").trim();
      const isCn = (t) => /[一-鿿]{2,}/.test(String(t || ""));
      const isPureLatin = (t) => /^[A-Za-z][A-Za-z0-9.\-]{2,28}$/.test(String(t || "").trim());

      // 所有写入都先经过同一 UI 边界；禁止旁路把 tod​esk云电脑锁成中文品牌。
      try {
        if (next && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          const normalized = NS.canonicalizeBrandDisplayCandidate(next);
          if (normalized) next = normalized;
        }
      } catch { /* ignore */ }

      // 旧扫描阶段可能已经把「拉丁品牌 + 中文功能描述」写入并锁定。
      // 在判断锁之前先迁移当前状态，否则 tod​esk云电脑 会以“中文品牌”拒绝 ToDesk 覆盖。
      try {
        if (cur && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          const normalizedCur = String(NS.canonicalizeBrandDisplayCandidate(cur) || "").trim();
          if (normalizedCur && normalizedCur !== cur) {
            const oldCur = cur;
            cur = normalizedCur;
            state.spoofBrand = normalizedCur;
            state._spoofBrandEvidence = null;
            state._spoofBrandEvidenceLocked = false;
            state._spoofBrandChineseLocked = isCn(normalizedCur);
            state._brandSpoofFinalPresented = false;
            state._brandSpoofFinalSnapshot = null;
            state._brandSpoofNoticeSent = false;
            state._brandSpoofNoticeKey = "";
            state._lastGuardNoticeKey = "";
            try {
              (state.details || []).forEach((d) => {
                if (!d || !d.reason) return;
                d.reason = String(d.reason).split(`「${oldCur}」`).join(`「${normalizedCur}」`);
              });
            } catch { /* ignore */ }
          }
        }
      } catch { /* ignore */ }

      // 当前已是弱中文（「中文」）：视为未锁，允许纠正
      const curWeakCn = isCn(cur) && typeof NS.isWeakChineseBrandToken === "function"
        && NS.isWeakChineseBrandToken(cur);

      // 会话锁定：中文展示不可被拉丁拼音核打回（弱中文除外）
      if (state._spoofBrandChineseLocked && isCn(cur) && !o.forceUnlock && !curWeakCn) {
        if (!next || isPureLatin(next) || !isCn(next)) return cur;
        // 仅允许显式 forceChinese 换另一中文
        if (next !== cur && !o.forceChinese) return cur;
      }
      // 未锁但已是中文：仍禁止纯拉丁覆盖（Dingding 不得盖 钉钉）；弱中文可被拉丁核纠正
      if (isCn(cur) && next && !isCn(next) && !curWeakCn) return cur;

      if (!next) {
        if (o.allowClear && (!state._spoofBrandChineseLocked || o.forceUnlock)) {
          state.spoofBrand = "";
          state._spoofBrandEvidence = null;
          state._spoofBrandEvidenceLocked = false;
          state._brandSpoofFinalSnapshot = null;
          if (o.forceUnlock) state._spoofBrandChineseLocked = false;
          return "";
        }
        return cur;
      }

      // 禁止写入弱中文展示（「中文」「官方」等）——统一门禁
      if (typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(next)) {
        return cur;
      }

      // 主机碎片不写——但干净剥核（huorong @ huorongr）必须放行
      try {
        const lowN = next.toLowerCase().replace(/[^a-z0-9]/g, "");
        let isCleanCore = false;
        // 页面身份槽声明的完整品牌与 host 对齐时，不能再被域名碎片过滤器清掉。
        // 该判断依赖页面候选，域名本身仍不能独立生成展示品牌。
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          const pageAligned = String(NS.pickHostAlignedLatinBrandFromPage() || "")
            .toLowerCase().replace(/[^a-z0-9]/g, "");
          if (pageAligned && pageAligned === lowN) isCleanCore = true;
        }
        if (typeof NS.resolveHostBrandCore === "function") {
          const hc = String(NS.resolveHostBrandCore() || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          if (hc && hc.length >= 4 && lowN === hc) isCleanCore = true;
        }
        if (typeof NS.inferMarketingPaddedBrandCore === "function" && !isCleanCore) {
          try {
            const lab = String((typeof location !== "undefined" ? location.hostname : "") || "")
              .replace(/^www\./i, "").split(".")[0] || "";
            const pe = String(NS.inferMarketingPaddedBrandCore(lab) || "").toLowerCase().replace(/[^a-z0-9]/g, "");
            if (pe && pe === lowN) isCleanCore = true;
          } catch { /* ignore */ }
        }
        if (!isCleanCore && typeof NS.isHostShapedCompoundBrandToken === "function"
          && NS.isHostShapedCompoundBrandToken(next)
          && !isCn(next)) {
          return cur;
        }
      } catch { /* ignore */ }

      // ── 证据单调升级 ──
      // 强页面身份 + host 互证一旦成立，后来的 host 长核、正文弱词或其它拉丁
      // 候选不得覆盖。唯一例外是已通过 pinyin/中文定稿链验证的语义升级。
      const evidenceUrl = spoofBrandEvidenceUrl();
      const currentKey = spoofBrandEvidenceKey(cur);
      const nextKey = spoofBrandEvidenceKey(next);
      let storedEvidence = state._spoofBrandEvidence;
      if (!storedEvidence || storedEvidence.url !== evidenceUrl || storedEvidence.key !== currentKey) {
        storedEvidence = cur && typeof NS.getSpoofDisplayBrandEvidence === "function"
          ? NS.getSpoofDisplayBrandEvidence(cur)
          : null;
        state._spoofBrandEvidence = storedEvidence;
        // 单一 headline 只能作为当前候选，不能永久锁死；至少达到多身份族、
        // 页面票王+互证或等价强度后才进入不可降级状态。
        state._spoofBrandEvidenceLocked = !!(storedEvidence && storedEvidence.rank >= 300);
      }
      const nextEvidence = typeof NS.getSpoofDisplayBrandEvidence === "function"
        ? NS.getSpoofDisplayBrandEvidence(next, o)
        : { key: nextKey, url: evidenceUrl, rank: 0, kind: "none" };
      const currentForbidden = !!(cur && typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(cur));
      const currentRank = Number((storedEvidence && storedEvidence.rank) || 0);
      const nextRank = Number((nextEvidence && nextEvidence.rank) || 0);
      const semanticChineseUpgrade = !!(cur && isPureLatin(cur) && isCn(next)
        && (nextEvidence.pinyinValidated
          || (o.forceChinese === true
            && Number(nextEvidence.primaryFamilies || 0) >= 2
            && nextRank > currentRank)));
      // A later, sequence-checked SW result may correct one early Chinese
      // extraction to another Chinese identity after SPA hydration.  This is
      // not a general force override: only the current pinyin-mutual result
      // may cross the existing evidence lock.
      const verifiedChineseCorrection = !!(cur && isCn(cur) && isCn(next)
        && currentKey !== nextKey
        && o.pinyinValidated === true
        && nextEvidence && nextEvidence.pinyinValidated === true
        && nextRank >= currentRank);

      if (cur && currentKey && nextKey && currentKey !== nextKey && !currentForbidden && !curWeakCn) {
        const currentLocked = !!state._spoofBrandEvidenceLocked || currentRank >= 300;
        // 已确认身份不允许不同拉丁/弱中文覆盖；中文升级必须有双向或定稿证据。
        if (currentLocked && !semanticChineseUpgrade && !verifiedChineseCorrection) return cur;
        // 未锁候选也只允许严格增强，避免多个扫描器在同一证据等级来回抢占。
        if (!semanticChineseUpgrade && !verifiedChineseCorrection && nextRank <= currentRank) return cur;
      }

      if (next === cur) {
        if (nextEvidence && (!storedEvidence || nextEvidence.rank > Number(storedEvidence.rank || 0))) {
          state._spoofBrandEvidence = nextEvidence;
          state._spoofBrandEvidenceLocked = nextEvidence.rank >= 300;
        }
        if (isCn(next)) state._spoofBrandChineseLocked = true;
        return cur;
      }

      state.spoofBrand = next;
      state._brandSpoofFinalSnapshot = null;
      state._spoofBrandEvidence = nextEvidence;
      state._spoofBrandEvidenceLocked = Number((nextEvidence && nextEvidence.rank) || 0) >= 300;
      // 旧版本可能把「中文」等弱词锁成中文品牌；被可信拉丁核纠正时同步解锁。
      if (curWeakCn && !isCn(next)) {
        state._spoofBrandChineseLocked = false;
        // 清理同一页面已生成的旧文案，并允许正确品牌重新展示一次。
        try {
          (state.details || []).forEach((d) => {
            if (!d || !d.reason) return;
            d.reason = String(d.reason)
              .split(`品牌「${cur}」`).join(`品牌「${next}」`)
              .split(`仿冒「${cur}」`).join(`仿冒「${next}」`);
          });
          state._brandSpoofNoticeSent = false;
          state._brandSpoofNoticeKey = "";
          if (String(state._lastGuardNoticeKey || "").includes(cur)) {
            state._lastGuardNoticeKey = "";
          }
        } catch { /* ignore */ }
      }
      // 任何被允许的严格升级都同步改写旧详情；被拒绝的候选永远走不到这里。
      if (cur && cur !== next && !curWeakCn) {
        try {
          (state.details || []).forEach((d) => {
            if (!d || !d.reason) return;
            d.reason = String(d.reason)
              .split(`品牌「${cur}」`).join(`品牌「${next}」`)
              .split(`仿冒「${cur}」`).join(`仿冒「${next}」`);
          });
          if (String(state._brandSpoofNoticeKey || "").includes(cur)
            || String(state._lastGuardNoticeKey || "").includes(cur)) {
            state._brandSpoofNoticeSent = false;
            state._brandSpoofNoticeKey = "";
            state._lastGuardNoticeKey = "";
          }
        } catch { /* ignore */ }
      }
      if (isCn(next)) {
        state._spoofBrandChineseLocked = true;
      }
      return next;
    } catch {
      return String(brand || "").trim();
    }
  };

  /** 当前是否应固定使用中文 spoof 展示（禁止再选 Dingding） */
  NS.getLockedSpoofDisplayBrand = function () {
    try {
      const state = NS.state;
      if (!state) return "";
      let cur = String(state.spoofBrand || "").trim();
      // 修正同一页面早期已经锁入的混合功能候选，无需等待重新导航。
      try {
        if (cur && typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          const normalized = String(NS.canonicalizeBrandDisplayCandidate(cur) || "").trim();
          if (normalized && normalized !== cur) {
            cur = typeof NS.setSpoofDisplayBrand === "function"
              ? String(NS.setSpoofDisplayBrand(cur, { forceUnlock: true }) || normalized).trim()
              : normalized;
            if (typeof NS.setSpoofDisplayBrand !== "function") {
              state.spoofBrand = normalized;
              state._spoofBrandChineseLocked = /[一-鿿]{2,}/.test(normalized);
            }
          }
        }
      } catch { /* ignore */ }
      // 弱中文锁定无效（「中文」不得当锁定展示名）
      if (typeof NS.isForbiddenSpoofDisplayBrand === "function"
        && NS.isForbiddenSpoofDisplayBrand(cur)) {
        return "";
      }
      if (state._spoofBrandChineseLocked && /[一-鿿]{2,}/.test(cur)) return cur;
      if (/[一-鿿]{2,}/.test(cur) && !/^[A-Za-z]/.test(cur)) return cur;
      return "";
    } catch { return ""; }
  };

  /**
   * 从 document.title 硬抽中文展示品牌（不依赖 pinyin、不走 clean 链）。
   * 例：「钉钉应用中心 | 官方全平台免费下载」→「钉钉」
   * 亦：「Huorong 火绒安全官网」「火绒 Huorong」→「火绒/火绒安全」
   * 这是仿冒 toast 的最高优先级来源，禁止被主机核 Dingding/Huorong 覆盖。
   */
  NS.extractChineseBrandFromPageTitle = function (titleOpt) {
    try {
      let t = String(titleOpt != null ? titleOpt : (typeof document !== "undefined" ? document.title : "") || "")
        .replace(/[\u200b-\u200d\ufeff]/g, "")
        .trim();
      if (!t) return "";
      // 首段（| · — 等分隔）
      const head = (t.split(/[\s]*[|｜·•\-–—][\s]*/)[0] || t).trim();
      if (!head) return "";
      // 栏目壳专名：只挡纯品类；中文合法性靠 pinyin 主机对齐 + 结构品类，不走 isGenericTech
      // 栏目/语言壳：禁止「中文官网」「应用中心」当品牌
      const okShellBrand = (s) => {
        const x = String(s || "").trim();
        if (!x || x.length < 2 || x.length > 6) return false;
        if (!/^[\u4e00-\u9fff]{2,6}$/.test(x)) return false;
        if (/^(?:应用|中心|官方|官网|下载|安全|杀毒|卫士|软件|客户端|平台|工具|系统|服务|首页|频道|中文|英文|英语|简体|繁体|语言|版本|国际|国内|远程|桌面|免费|正版|最新)$/.test(x)) {
          return false;
        }
        // 「免费远程」整段
        if (/^(?:免费|官方|正版|最新|极速|专业|智能|云端)?(?:远程|桌面|控制)(?:软件|客户端)?$/.test(x)) return false;
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(x)) return false;
        return true;
      };
      // 1) 专名 + 应用中心（钉钉应用中心 → 钉钉）——最高优先级，须过 weak
      let m = head.match(/^([\u4e00-\u9fff]{2,4})应用中心/);
      if (m && m[1] && okShellBrand(m[1])) return m[1];
      // 2) 专名 + 安全/应用/中心/官方…（火绒安全官网；钉钉应用）
      //    禁止「中文官网」：中文 是语言壳
      m = head.match(/^([\u4e00-\u9fff]{2,4})(?:安全|杀毒|卫士)?(?:应用中心|应用|中心|官方|官网|客户端|下载)/);
      if (m && m[1]) {
        let s = m[1];
        const withProd = head.match(new RegExp("^(" + s + "(?:安全|杀毒|卫士))"));
        if (withProd && withProd[1] && okShellBrand(withProd[1])) return withProd[1];
        if (okShellBrand(s)) return s;
      }
      // 3) 整标题任意位置「xx应用中心」
      m = t.match(/([\u4e00-\u9fff]{2,4})应用中心/);
      if (m && m[1] && okShellBrand(m[1])) return m[1];
      // 3b) 拉丁前缀后的中文：「Huorong 火绒安全」
      m = t.match(/[A-Za-z][A-Za-z0-9.\-]{2,24}\s*([\u4e00-\u9fff]{2,6})(?:安全|杀毒|卫士|官网|官方|下载|客户端|应用|中心)?/);
      if (m && m[1]) {
        let s = m[1];
        const withProd = t.match(new RegExp(s + "(安全|杀毒|卫士)"));
        if (withProd && okShellBrand(s + withProd[1])) return s + withProd[1];
        if (okShellBrand(s)) return s;
      }
      // 3c) 任意位置「xx安全/杀毒/卫士」产品专名（勿匹配「中文安全」类弱壳）
      m = t.match(/([\u4e00-\u9fff]{2,4})(?:安全|杀毒|卫士)(?:官网|官方|下载|客户端|软件|中心)?/);
      if (m && m[1]) {
        const full = m[0].replace(/(?:官网|官方|下载|客户端|软件|中心)$/u, "");
        if (okShellBrand(full)) return full;
        if (okShellBrand(m[1])) return m[1];
      }
      // 4) 首段 2～4 字纯中文（剥栏目后）——须 weak 过关
      m = head.match(/^([\u4e00-\u9fff]{2,6})/);
      if (m && m[1]) {
        let s = m[1];
        if (typeof NS.trimChineseBrandTrail === "function") {
          const peeled = NS.trimChineseBrandTrail(s);
          if (peeled && peeled.length >= 2) s = peeled;
        }
        s = s.replace(/(?:应用中心|应用|中心)$/u, "");
        if (okShellBrand(s) && s.length <= 4) return s;
      }
      // 5) 不再扫「任意中文 run」——易把「中文/官方」当品牌；只信上面结构壳
      return "";
    } catch {
      return "";
    }
  };

  /**
   * 仿冒 UI 展示名：页内抽词优先（title 表面 / 等权 display / 中文榜），
   * 拒绝弱词「音乐」、主机碎片、功能卖点。供 home-fast / 主检测 / guard 共用。
   */
  NS.pickBestSpoofDisplayBrand = function (hintOpt) {
    try {
      // 中文已锁定：直接返回，禁止再选举 Dingding
      try {
        const locked = typeof NS.getLockedSpoofDisplayBrand === "function"
          ? NS.getLockedSpoofDisplayBrand() : "";
        if (locked) return locked;
      } catch { /* ignore */ }

      const isBad = (t) => {
        const s = String(t || "").trim();
        if (!s || s.length < 2) return true;
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(s)) return true;
        if (typeof NS.looksLikeFunctionalClaimBrandToken === "function" && NS.looksLikeFunctionalClaimBrandToken(s)) return true;
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(s)) return true;
        if (NS.BRAND_TOKEN_STOP_RE && NS.BRAND_TOKEN_STOP_RE.test(s.toLowerCase())) return true;
        // 纯品类/语言壳不够作展示（「音乐」「安全」「中文」）
        if (/^(?:音乐|安全|杀毒|卫士|软件|下载|官网|官方|客户端|浏览器|中文|英文|简体|繁体|语言|版本)$/.test(s)) return true;
        // 禁止域名标签/域名衍生当「被仿冒品牌」（Huorongr、HuorongLab @ huorongr.com.cn）
        try {
          if (typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(s)) return true;
        } catch { /* ignore */ }
        return false;
      };
      const clean = (t) => {
        let s = String(t || "").trim();
        if (!s) return "";
        if (typeof NS.canonicalizeBrandDisplayCandidate === "function") {
          const c = NS.canonicalizeBrandDisplayCandidate(s);
          // canonicalize 误清空时保留原串（勿把「汽水音乐」洗成空）
          if (c) s = c;
        }
        return isBad(s) ? "" : s;
      };

      // 强制重新选举：避免 document_start 空 title 的缓存 display
      try {
        if (NS.caches) {
          const urlKey = String((typeof location !== "undefined" ? location.href : "") || "").split("#")[0];
          if (NS.caches._primaryKwUrl && NS.caches._primaryKwUrl !== urlKey) {
            NS.caches._primaryKw = null;
          }
          // 标题已有实质内容时丢弃过期空选举
          if (NS.caches._primaryKw && !(NS.caches._primaryKw.display)
            && String(document.title || "").trim().length >= 2) {
            NS.caches._primaryKw = null;
            NS.caches._primaryKwAt = 0;
          }
        }
      } catch { /* ignore */ }

      // 0) 调用方提示：仅中文/混合可立即返回。纯拉丁 hint（Dingding）延后。
      let hit = clean(hintOpt);
      if (hit && /[\u4e00-\u9fff]{2,}/.test(hit)) return hit;
      const deferredLatinHint = (hit && /^[A-Za-z]/.test(hit) && !/[\u4e00-\u9fff]/.test(hit)) ? hit : "";

      // 0a) 页内拉丁 ↔ 域名段（WPS @ wps-officce-wps）——无需 pinyin
      try {
        if (typeof NS.pickHostAlignedLatinBrandFromPage === "function") {
          const lat = String(NS.pickHostAlignedLatinBrandFromPage() || "").trim();
          hit = clean(lat);
          if (hit) return hit;
        }
      } catch { /* ignore */ }

      // 0b) ★ 标题硬抽中文壳（钉钉应用中心）
      try {
        if (typeof NS.extractChineseBrandFromPageTitle === "function") {
          const titleBrand = NS.extractChineseBrandFromPageTitle();
          if (titleBrand && /[\u4e00-\u9fff]{2,}/.test(titleBrand)
            && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
              && NS.isForbiddenSpoofDisplayBrand(titleBrand))) return titleBrand;
        }
        const title0 = String(document.title || "");
        if (title0 && typeof NS.pickChineseBrandFromPageSurface === "function") {
          hit = clean(NS.pickChineseBrandFromPageSurface(title0));
          if (hit && /[\u4e00-\u9fff]{2,}/.test(hit)
            && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
              && NS.isForbiddenSpoofDisplayBrand(hit))) return hit;
        }
      } catch { /* ignore */ }

      // 1) ★ 标签选举总榜——display/cn/latin，禁止 pinyin
      try {
        const pk = typeof NS.collectPrimaryBrandKeywords === "function"
          ? NS.collectPrimaryBrandKeywords()
          : null;
        if (pk && pk.display) {
          hit = clean(pk.display);
          if (hit && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
            && NS.isForbiddenSpoofDisplayBrand(hit))) {
            // 拉丁 display 且主机含该核 → 直接用（WPS）
            if (/^[A-Za-z]/.test(hit)) {
              const hl = (typeof location !== "undefined" ? location.hostname : "").toLowerCase();
              if (hl.replace(/[^a-z0-9]/g, "").includes(hit.toLowerCase().replace(/[^a-z0-9]/g, ""))) {
                return hit;
              }
            }
            if (/[一-鿿]{2,}/.test(hit)) return hit;
          }
        }
        if (pk && pk.cn && pk.cn.length) {
          for (let i = 0; i < Math.min(pk.cn.length, 8); i++) {
            hit = clean(pk.cn[i]);
            if (hit && /[一-鿿]{2,}/.test(hit)
              && !(typeof NS.isForbiddenSpoofDisplayBrand === "function"
                && NS.isForbiddenSpoofDisplayBrand(hit))) return hit;
          }
        }
      } catch { /* ignore */ }

      // 2) resolveSpoofDisplayBrand（仍走选举 display）
      try {
        if (typeof NS.resolveSpoofDisplayBrand === "function") {
          hit = clean(NS.resolveSpoofDisplayBrand());
          if (hit) return hit;
        }
      } catch { /* ignore */ }

      // 3) title / 表面产品名（含 QQ音乐、汽水音乐官网）
      try {
        const title = String(document.title || "");
        if (typeof NS.pickChineseBrandFromPageSurface === "function") {
          hit = clean(NS.pickChineseBrandFromPageSurface(title));
          if (hit) return hit;
        }
        // 拉丁+中文产品：QQ音乐
        const mixed = title.match(/([A-Za-z][A-Za-z0-9]{0,10}[一-鿿]{1,6}(?:音乐|浏览器|播放器|输入法|客户端|网盘|助手|管家)?)/);
        if (mixed) {
          hit = clean(mixed[1].replace(/(?:官网|官方|下载).*$/, ""));
          if (hit) return hit;
        }
        const cnProd = title.match(/([一-鿿]{2,8}(?:音乐|安全|杀毒|卫士|浏览器|播放器|客户端|输入法|网盘|助手|管家))/);
        if (cnProd) {
          hit = clean(cnProd[1]);
          if (hit) return hit;
        }
        // 钉钉/火绒类短中文品牌（2字）+ 官网/下载话术
        const cnShort = title.match(/([一-鿿]{2,6})(?:官网|官方|下载|客户端|安全中心)/);
        if (cnShort) {
          hit = clean(cnShort[1]);
          if (hit) return hit;
        }
        // h1
        const h1 = String(document.querySelector("h1")?.textContent || "").trim().slice(0, 80);
        if (h1 && typeof NS.pickChineseBrandFromPageSurface === "function") {
          hit = clean(NS.pickChineseBrandFromPageSurface(h1));
          if (hit) return hit;
        }
      } catch { /* ignore */ }

      // 4) 夹带主机剥核兜底（j-dingtalk → DingTalk）——仅结构核，禁止用整段 apex
      try {
        if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
          hit = clean(NS.formatSpoofDisplayFromHostCore());
          if (hit && /[一-鿿]{2,}/.test(hit)) return hit;
        }
      } catch { /* ignore */ }

      // 5) 最后才用延迟的拉丁 hint / 主机核（Dingding）——标题无中文时的兜底
      if (deferredLatinHint) return deferredLatinHint;
      try {
        if (typeof NS.formatSpoofDisplayFromHostCore === "function") {
          hit = clean(NS.formatSpoofDisplayFromHostCore());
          if (hit) return hit;
        }
      } catch { /* ignore */ }

      return "";
    } catch {
      return "";
    }
  };

  /**
   * 仿冒 toast / spoofBrand 的展示名 —— **只** 读等权综合结果。
   *
   * 旁路（StronglyAligned / padded / inferCore）只负责「拦不拦 / related 与否」，
   * 不得在这里用主机分、页脚拉丁、core 碎片改写展示名（否则 Reserved/Prto 会进 UI）。
   *
   * 来源优先级（均须已通过 collectPrimaryBrandKeywords 的 acceptCandidate）：
   *   display → cn[0] → latin[0]（latin 须非垃圾）
   * 仅做归一清洗（剥「官网」），不重新计票、不扫主机。
   */
  NS.resolveSpoofDisplayBrand = function (hostOpt, kwOpt) {
    try {
      const kw = kwOpt || (typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords()
        : null);
      if (!kw) return "";
      const host = String(hostOpt || (typeof location !== "undefined" ? location.hostname : "") || "");

      const isHostDebris = (raw) => {
        try {
          return typeof NS.isHostShapedCompoundBrandToken === "function"
            && NS.isHostShapedCompoundBrandToken(raw, host);
        } catch { return false; }
      };

      const clean = (raw) => {
        const input = String(raw || "").trim();
        if (!input) return "";
        // 夹带域整段（Iehuorong / Huorongpc）绝不当展示名
        if (isHostDebris(input)) return "";
        let t = typeof NS.canonicalizeBrandDisplayCandidate === "function"
          ? NS.canonicalizeBrandDisplayCandidate(input)
          : input;
        if (!t || isHostDebris(t)) return "";
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
        return t;
      };

      const hasIndependentPageIdentityEvidence = (raw) => {
        try {
          const key = String(raw || "").toLowerCase().replace(/[^a-z0-9一-鿿]/gi, "");
          if (!key || !kw.scores) return false;
          const accepted = [...(kw.latin || []), ...(kw.cn || [])].some((name) =>
            String(name || "").toLowerCase().replace(/[^a-z0-9一-鿿]/gi, "") === key
          );
          if (!accepted) return false;
          for (const [name, info] of Object.entries(kw.scores)) {
            const nk = String(name || "").toLowerCase().replace(/[^a-z0-9一-鿿]/gi, "");
            const sources = Array.isArray(info && info.sources) ? info.sources : [];
            // 必须来自页面身份槽，不能仅凭 padded 域名自行发明展示名。
            if (nk === key) {
              // logo alt 可能是“主品牌 + 英文副标”，只能佐证，不能独立授权
              // 一个域名核成为展示品牌（PURE SHIELD 即属于这种情况）。
              return sources.some((src) => /^(?:title|h1|ogTitle|twitterTitle|ogSite|schema)$/i.test(String(src)));
            }
          }
        } catch { /* ignore */ }
        return false;
      };

      // 从碎片 token 回退到干净核展示名
      const fromCore = (core, blobOpt) => {
        const c = String(core || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!c || c.length < 4 || isHostDebris(c)) return "";
        const blob = String(blobOpt != null ? blobOpt : ((kw && kw.blob) || document.title || ""));
        const blobLow = blob.toLowerCase();
        const blobFlat = blobLow.replace(/[^a-z0-9\u4e00-\u9fff]/gi, "");
        // 无固定中文桥：拉丁核必须被页面自己的身份字段声明过。
        // pr-todesk + 页面 ToDesk 可展示；仅由域名剥出的碎片不可展示。
        if (!hasIndependentPageIdentityEvidence(c)) return "";
        if (blobFlat.includes(c) || blobLow.includes(c)) {
          return clean(
            typeof NS.formatBrandTokenForDisplay === "function"
              ? NS.formatBrandTokenForDisplay(c)
              : c
          );
        }
        // scores 已确认页面独立身份槽出现该核，可安全格式化展示。
        return clean(
          typeof NS.formatBrandTokenForDisplay === "function"
            ? NS.formatBrandTokenForDisplay(c)
            : c
        );
      };

      // 0) 标签选举 display：中文直接用（选举内已 pinyin 抬 火绒）
      {
        const dDisp = clean(kw.display);
        if (dDisp && /[一-鿿]/.test(dDisp)) return dDisp;
      }

      // 0b) 选举 cn 榜（结构优先，不调 pinyin）
      if (kw.cn && kw.cn.length) {
        for (let i = 0; i < Math.min(kw.cn.length, 8); i++) {
          const cn = String(kw.cn[i] || "").trim();
          if (!cn) continue;
          const d0 = clean(cn);
          if (!d0) continue;
          if (/^\d{3,6}/.test(d0)) return d0;
          if (/[一-鿿]/.test(d0)) return d0;
        }
      }

      // 0c) 无中文时才用总榜纯拉丁 display（Huorong）——禁止 pinyin 热路径
      {
        const dDisp = clean(kw.display);
        if (dDisp) return dDisp;
      }

      // 1) 等权票王 display（已滤主机碎片）
      let disp = clean(kw.display);
      if (disp && !isHostDebris(disp)) return disp;
      if (kw.display && isHostDebris(kw.display)) {
        // 有中文时绝不再回退到主机核 Yinle
        if (kw.cn && kw.cn.some((x) => /[一-鿿]/.test(String(x || "")))) {
          /* fall through to cn list */
        } else {
          const stripped = typeof NS.stripMarketingHostPrefixFromToken === "function"
            ? NS.stripMarketingHostPrefixFromToken(kw.display)
            : "";
          const cores0 = typeof NS.collectHostBrandCores === "function" ? NS.collectHostBrandCores(host) : null;
          const core0 = stripped || (cores0 && cores0.padCore) || "";
          disp = fromCore(core0);
          if (disp && !isHostDebris(disp)) return disp;
        }
      }

      // 2) 等权已准入的中文列表（含 QQ音乐 等混合）
      if (kw.cn && kw.cn.length) {
        for (let i = 0; i < kw.cn.length; i++) {
          disp = clean(kw.cn[i]);
          if (disp && /[一-鿿]/.test(disp)) return disp;
          if (disp && !isHostDebris(disp)) return disp;
        }
      }

      // 3) 等权已准入的拉丁列表—— 跳过 vdingtalk；碎片则剥前缀
      if (kw.latin && kw.latin.length) {
        for (let i = 0; i < kw.latin.length; i++) {
          const low = String(kw.latin[i] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          if (!low || low.length < 3) continue;
          if (isHostDebris(low)) {
            const st = typeof NS.stripMarketingHostPrefixFromToken === "function"
              ? NS.stripMarketingHostPrefixFromToken(low)
              : "";
            disp = fromCore(st);
            if (disp) return disp;
            continue;
          }
          if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(low)) continue;
          disp = clean(
            typeof NS.formatBrandTokenForDisplay === "function"
              ? NS.formatBrandTokenForDisplay(low)
              : low
          );
          if (disp) return disp;
        }
      }

      // 4) 夹带域营销核（vdingtalk → dingtalk → DingTalk / 钉钉）
      try {
        const cores = typeof NS.collectHostBrandCores === "function" ? NS.collectHostBrandCores(host) : null;
        let core = (cores && cores.padCore) || "";
        if (!core && cores && cores.apexLabel) {
          core = typeof NS.stripMarketingHostPrefixFromToken === "function"
            ? (NS.stripMarketingHostPrefixFromToken(cores.apexLabel) || "")
            : "";
          if (!core && typeof NS.inferMarketingPaddedBrandCore === "function") {
            core = NS.inferMarketingPaddedBrandCore(cores.apexLabel) || "";
          }
        }
        if (core.length >= 4) {
          disp = fromCore(core);
          if (disp) return disp;
        }
      } catch { /* ignore */ }

      // 故意不把整段主机 / 页脚碎片写进展示
      return "";
    } catch {
      return "";
    }
  };

  NS.hostLabelIsPaddedBrand = function (label, brandToken) {
    const lab = String(label || "").toLowerCase().replace(/-/g, "");
    const br = String(brandToken || "").toLowerCase().replace(/-/g, "");
    if (!lab || !br || br.length < 3) return false;
    if (lab === br) return false;
    if (!lab.includes(br)) return false;
    const structuralAffix = typeof NS.isStructuralHostAffixForBrand === "function"
      && NS.isStructuralHostAffixForBrand(lab, br);
    // 三字母品牌只开放命名明确的结构/分发夹带；不放宽任意短词包含关系。
    if (br.length === 3 && !structuralAffix) return false;
    // pyas-security 等品牌产品线域名：绝不当营销 padded 仿冒
    if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
      && (NS.hostLabelIsBrandProductCategoryDomain(label, br) || NS.hostLabelIsBrandProductCategoryDomain(lab, br))) {
      return false;
    }
    if (structuralAffix) return true;
    if (lab.startsWith(br)) {
      const pad = lab.slice(br.length);
      // archlinux / todeskai = 品牌+平台/产品线粘连正站，非营销夹带
      // （无连字符 + 平台尾缀 linux/windows 时不当 padded；ai 等走下方品类后缀）
      if (/^(linux|windows|macos|android)$/i.test(pad) && br.length <= 6 && !/-/.test(String(label || ""))) {
        return false;
      }
      // security/antivirus/ai 产品线尾缀不当 padded（todeskai、pyassecurity）
      if (BRAND_PRODUCT_CATEGORY_SUFFIX.test(pad)) return false;
      // 单字母/数字尾缀拼写污染：huorongr / todeskx（火绒仿冒 huorongr.com.cn）
      if (pad.length === 1 && /[a-z0-9]/i.test(pad) && br.length >= 5) return true;
      // 双字符乱尾（非品类）：huorongxx（过短营销词已在 mkt 表）
      if (pad.length === 2 && /^[a-z0-9]{2}$/i.test(pad) && br.length >= 5
        && !BRAND_PRODUCT_CATEGORY_SUFFIX.test(pad) && !MKT_HOST_SUFFIX.test(pad)) return true;
      if (pad.length >= 2 && pad.length <= 12 && MKT_HOST_SUFFIX.test(pad)) return true;
      // 短营销垫：app/pro/vip…；勿含 ai/bot——已归产品线品类
      if (pad.length >= 2 && pad.length <= 4 && /^(?:app|pro|vip|pc|cn|get|dl|im)$/i.test(pad)) return true;
    }
    if (lab.endsWith(br)) {
      const pad = lab.slice(0, lab.length - br.length);
      if (pad.length >= 1 && pad.length <= 12 && MKT_HOST_PREFIX.test(pad)) return true;
      // im-todesk / pr-todesk / ott-todesk → 无连字符粘连（严格前缀，避免 to+desk 误伤）
      if (pad.length >= 2 && pad.length <= 4 && /^(?:aa|bb|cc|pc|my|get|go|to|up|re|un|im|qq|wx|dl|gw|pr|seo|ott|tv|hd|cdn|x|z)$/i.test(pad)) return true;
      if (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(pad, { strict: true })) return true;
      if (pad.length === 1 && /[a-z0-9]/i.test(pad)) return true;
    }
    const idx = lab.indexOf(br);
    if (idx > 0 && idx + br.length < lab.length) {
      const left = lab.slice(0, idx);
      const right = lab.slice(idx + br.length);
      // todeskai 中间命中 desk 时 right=ai 是产品线，不当 padded（防 to+desk+ai 误夹带）
      if (BRAND_PRODUCT_CATEGORY_SUFFIX.test(right) || BRAND_PRODUCT_CATEGORY_SUFFIX.test(left)) return false;
      if (left.length <= 6 && right.length <= 8 && (MKT_HOST_PREFIX.test(left) || left.length <= 3) && (MKT_HOST_SUFFIX.test(right) || right.length <= 4)) return true;
    }
    return false;
  };

  /**
   * 域名标签与页面身份关键词是否「高度吻合」：
   * 从 title / h1·h2 / logo·img alt·src / nav / og 等抽出平台名后，
   * 若能拼成域名（todesk + AI → todeskai），则正站，不显示盗版。
   * 注意：ott-todesk / pr-todesk 是营销前缀夹带——即使页上同时有 OTT 与 ToDesk，也非正站。
   */
  NS.hostLabelStronglyAlignedWithIdentityKeywords = function (labelOpt, kwOpt) {
    try {
      const host = String(location.hostname || "").toLowerCase().replace(/^www\./, "");
      const labelRaw = String(labelOpt || (host.split(".")[0] || "")).toLowerCase();
      const lab = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      if (lab.length < 5) return false;
      // ★ 年轻无备案：禁止「强吻合正站」放行（todesk-ze 37 天曾靠此洗白）
      if (typeof NS.isYoungUnverifiedRegistration === "function"
        && NS.isYoungUnverifiedRegistration()) {
        return false;
      }
      // 先完成统一采集；显式 kw 与默认调用必须走完全相同的判断路径。
      // detector 的 fast-skip 通常不传 kwOpt，若稍后才采集会漏掉
      // cloud-todesk + 页面独立 ToDesk 这类夹带结构。
      const kw = kwOpt || (typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords()
        : null);
      // 页面只以空格/连字符拆写一个非通用复合名时，这是可读声明，不是
      // 官方 exact 证明（Team Viewer / To Desk 等仍须走 hyphen/padded 判定）。
      if (kw && kw.hyphenSplitClaim) return false;
      const acceptedLatin = [...new Set([
        ...(kw && kw.latin || []),
        ...(kw && kw.structuralLatin || [])
      ]
        .map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, ""))
        .filter((t) => t.length >= 3))];
      const acceptedLatinSet = new Set(acceptedLatin);
      // “高度吻合”用于正站放行，必须至少有一个已通过页面身份门控的
      // 拉丁品牌核；原始 footer/title 字符串不能独自提供品牌身份。
      if (!acceptedLatin.length) return false;

      // ★ 营销前缀夹带（ott-todesk / pr-todesk / im-todesk）→ 绝非「高度吻合正站」
      if (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
        && NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw)) {
        return false;
      }
      // ★ todesk-ze / dingtalk-o：短垃圾尾夹带，绝不当 todesk/dingtalk 正站复合
      if (typeof NS.apexLabelLooksLikeMarketingPaddedBrand === "function"
        && NS.apexLabelLooksLikeMarketingPaddedBrand(labelRaw)) {
        return false;
      }
      // cloud 等较长基础设施段只在“页面已独立声明完整品牌段”时局部判定，
      // 避免全局拆坏 CloudDrive，同时拒绝 cloud-todesk + ToDesk 被当正站复合。
      try {
        if (acceptedLatin.some((tok) =>
          typeof NS.hostLabelIsPrefixedHyphenBrand === "function"
          && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, tok))) {
          return false;
        }
      } catch { /* ignore */ }
      try {
        const core0 = typeof NS.inferMarketingPaddedBrandCore === "function"
          ? (NS.inferMarketingPaddedBrandCore(labelRaw) || "")
          : "";
        if (core0.length >= 4) {
          if ((typeof NS.hostLabelIsPrefixedHyphenBrand === "function" && NS.hostLabelIsPrefixedHyphenBrand(labelRaw, core0))
            || (typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lab, core0))) {
            return false;
          }
        }
        // 页内拉丁核是当前 lab 前缀且剩余为短垃圾尾 → 仍是 padded，非正站
        if (acceptedLatin.some((tok) => {
          if (tok.length < 4 || !lab.startsWith(tok) || lab === tok) return false;
          const pad = lab.slice(tok.length);
          if (pad.length >= 1 && pad.length <= 2 && /^[a-z0-9]{1,2}$/i.test(pad)
            && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(pad)) return true;
          return typeof NS.hostLabelIsPaddedBrand === "function" && NS.hostLabelIsPaddedBrand(lab, tok);
        })) return false;
      } catch { /* ignore */ }

      let blob = String((kw && kw.blob) || "").trim();
      if (!blob && typeof NS.productBrandIdentityBlob === "function") {
        blob = String(NS.productBrandIdentityBlob() || "");
      }
      if (!blob) blob = String(document.title || "");

      // 补扫 logo/nav（缓存未就绪或早期扫描时 identity 可能缺字段）
      try {
        const extras = [];
        document.querySelectorAll(
          "img[alt], img[src*='logo'], img.cta-brand-logo, img.hero-brand-logo, img.nav-logo-img, "
          + "nav a, .nav-links a, .navbar a, header a, .logo, .logo-todesk, .logo-ai, .hero-brand"
        ).forEach((el, i) => {
          if (i > 48) return;
          const alt = (el.getAttribute && el.getAttribute("alt")) || "";
          const tx = (el.textContent || "").replace(/\s+/g, " ").trim().slice(0, 40);
          let srcBits = "";
          try {
            const src = (el.getAttribute && (el.getAttribute("src") || "")) || "";
            if (src && !/^data:/i.test(src)) {
              const base = src.split("?")[0].split("/").pop() || "";
              srcBits = base.replace(/\.(?:svg|png|jpe?g|gif|webp|ico)$/i, "").replace(/[-_]+/g, " ");
            }
          } catch { /* ignore */ }
          if (alt) extras.push(alt);
          if (tx && tx.length >= 2) extras.push(tx);
          if (srcBits) extras.push(srcBits);
        });
        if (extras.length) blob = `${blob} ${extras.join(" ")}`.replace(/\s+/g, " ").trim();
      } catch { /* ignore */ }

      const blobLow = blob.toLowerCase();
      const blobFlat = blobLow.replace(/[^a-z0-9]/g, "");
      // 整段域名只有在它本身已经作为页面身份候选通过门控时才算吻合。
      // footer/正文抄写当前域名不提供身份票，不能把 todiesk 自洗成 exact。
      if (acceptedLatinSet.has(lab)
        && !(typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
          && NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw))) {
        return true;
      }
      // 页面声明 Brand，并不能证明 brand-security / brand-antivirus 等域名归属。
      // 只有页面把完整连写名称本身作为身份候选（上面的 acceptedLatinSet.has(lab)）
      // 才能走 exact；仅“品牌 + 品类词”必须留给 ICP/官方资源归属门控。
      if (acceptedLatin.some((t) => t !== lab
        && typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
        && (NS.hostLabelIsBrandProductCategoryDomain(labelRaw, t)
          || NS.hostLabelIsBrandProductCategoryDomain(lab, t))
        && !(typeof NS.hostLabelHasSafeProductLineSuffix === "function"
          && NS.hostLabelHasSafeProductLineSuffix(labelRaw, t)))) {
        return false;
      }

      const productLine = PRODUCT_LINE_HOST_TOKEN;
      const bits = new Set(acceptedLatin);
      // 原始页面只补产品线词（保留 2 字母 AI），不能补新的品牌核。
      (blob.match(/[A-Za-z][A-Za-z0-9]{0,23}/g) || []).forEach((b) => {
        const low = b.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (productLine.test(low)) bits.add(low);
      });
      if (typeof NS.extractLatinBrandTokens === "function") {
        NS.extractLatinBrandTokens(blob).forEach((t) => {
          const low = String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "");
          if (productLine.test(low)) bits.add(low);
        });
      }

      const list = [...bits];
      // brand + 产品线（页上有 ToDesk 与 AI，域 todeskai）——尾缀必须是产品线，不能是营销前缀拼法
      for (const t of list) {
        if (t.length < 4 || productLine.test(t) || !acceptedLatinSet.has(t)) continue;
        if (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(t)) continue;
        if (!lab.startsWith(t) || lab.length <= t.length) continue;
        const pad = lab.slice(t.length);
        if (!productLine.test(pad)) continue;
        // 品牌出现在身份
        if (!blobLow.includes(t) && !blobFlat.includes(t)) continue;
        // 产品线词出现：独立 AI / 空格 ToDesk AI / 连写 todeskai / logo todesk-ai
        const padOnPage = bits.has(pad)
          || new RegExp(`(?:^|[^a-z])${pad}(?:[^a-z]|$)`, "i").test(blobLow)
          || blobFlat.includes(t + pad)
          || new RegExp(`${t}[\\s\\-_]*${pad}`, "i").test(blobLow);
        if (!padOnPage) continue;
        return true;
      }

      // 两段身份 token 直接拼接成域名——禁止 营销前缀+品牌（ott+todesk）
      for (let i = 0; i < list.length; i++) {
        const a = list[i];
        if (a.length < 2) continue;
        for (let j = 0; j < list.length; j++) {
          if (i === j) continue;
          const b = list[j];
          if (b.length < 2) continue;
          if (lab !== a + b && lab !== b + a) continue;
          // 任一段是营销前缀 → 夹带，非正站
          const aMkt = typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(a);
          const bMkt = typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(b);
          if (aMkt || bMkt) continue;
          // 允许 brand+产品线 或 两段均非前缀的产品复合（arch+linux 走下方 platform）
          if (productLine.test(a) || productLine.test(b)) {
            // 产品线须在尾部：todesk+ai / arch+linux
            if (lab === a + b && productLine.test(b) && acceptedLatinSet.has(a)) return true;
            if (lab === b + a && productLine.test(a) && acceptedLatinSet.has(b)) return true;
            continue;
          }
          // 两段均较长的产品复合（少见）
          if (a.length >= 4 && b.length >= 4
            && acceptedLatinSet.has(a) && acceptedLatinSet.has(b)) return true;
        }
      }

      // 品类域名：todesk + ai 结构（即便 AI 抽词失败，标题有 Brand AI 话术也认）
      if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function") {
        for (const t of list) {
          if (t.length < 4 || productLine.test(t) || !acceptedLatinSet.has(t)) continue;
          if (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(t)) continue;
          if (!NS.hostLabelIsBrandProductCategoryDomain(lab, t)
            && !NS.hostLabelIsBrandProductCategoryDomain(labelRaw, t)) continue;
          if (!blobLow.includes(t) && !blobFlat.includes(t)) continue;
          const pad = lab.startsWith(t) ? lab.slice(t.length) : "";
          if (pad && productLine.test(pad)) {
            // 页上有 Brand AI / Brand-AI / BrandAI 任一即可
            if (new RegExp(`${t}[\\s\\-_]*${pad}`, "i").test(blobLow) || bits.has(pad) || blobFlat.includes(lab)) {
              return true;
            }
            // title 形态 "ToDesk AI - …"
            if (new RegExp(`${t}.{0,6}${pad}`, "i").test(blobLow)) return true;
          } else if (!pad) {
            return true;
          }
        }
      }

      // hostLabelComposedOfTitleTokens 回退（内部已拒营销前缀拼接）
      if (typeof NS.hostLabelComposedOfTitleTokens === "function"
        && NS.hostLabelComposedOfTitleTokens(lab, list)) {
        return true;
      }

      return false;
    } catch {
      return false;
    }
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
      // 仅在页面候选已完整命中某个连字符段时，允许 cloud 等基础设施段
      // 作为局部前缀；不把 cloud 全局设为可剥前缀，避免误伤 CloudDrive。
      || (typeof NS.isMarketingHostLabelOnly === "function" && NS.isMarketingHostLabelOnly(prefix))
      || /^(?:im|qq|wx|wechat|chat|live|msg|mail|cdn|dl|gw|soft|app|pc|cn|ca|zh|en|vip|pro|pr|seo|my|get|go|to|aa|bb|cc|web|www\d*|hi|ok|yes|best|top|new)$/i.test(prefix)
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
    // 营销前缀夹带主机不当正站复合
    if (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
      && NS.hostLabelIsMarketingPrefixedBrandShape(lab)) {
      return false;
    }
    const skip = /^(download|windows|linux|android|macos|official|client|software|remote|chrome|https|http|free|desk|home|page|site|high|full|platform|utility|application|secure|speed|version|enterprise|search|native|group|center|service|services|update|online|cloud|remove|unwanted|programs|program|easily|with|from|that|this|your|have|will|help|trace|traces|unwant|leftover|leftovers|products|product|privacy|policy|cookie|cookies)$/i;
    // 平台/产品线尾缀：arch+linux、todesk+ai（AI 仅 2 字母，须放宽）
    const platform = PRODUCT_LINE_HOST_TOKEN || /^(linux|windows|macos|android|bsd|ai|gpt|ml|bot|llm)$/i;
    const isMkt = (t) => typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(t);
    const raw = [...new Set((tokens || []).map((t) => String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "")))]
      .filter((t) => (t.length >= 2 && t.length <= 20) && (t.length >= 3 || platform.test(t)));
    const toks = raw.filter((t) => (!skip.test(t) || platform.test(t)) && !isMkt(t)).sort((a, b) => b.length - a.length);
    // Arch Linux → archlinux；ToDesk AI → todeskai（ott+todesk 禁止）
    const primaries = raw.filter((t) => (!skip.test(t) || platform.test(t)) && !isMkt(t));
    for (const a of primaries) {
      if (platform.test(a) || a.length < 3 || isMkt(a)) continue;
      for (const b of raw) {
        if (a === b || isMkt(b)) continue;
        if (platform.test(b) && lab === a + b) return true;
      }
    }
    if (toks.length < 2) return false;
    for (let i = 0; i < toks.length; i++) {
      for (let j = 0; j < toks.length; j++) {
        if (i === j) continue;
        if (isMkt(toks[i]) || isMkt(toks[j])) continue;
        if (lab === toks[i] + toks[j]) {
          // 允许 brand+产品线；两段均 ≥4 的非前缀复合
          if (platform.test(toks[j]) || platform.test(toks[i])) {
            if (platform.test(toks[j]) && !platform.test(toks[i])) return true;
            continue;
          }
          if (toks[i].length >= 4 && toks[j].length >= 4) return true;
        }
      }
    }
    for (let i = 0; i < Math.min(toks.length, 10); i++) {
      for (let j = 0; j < Math.min(toks.length, 10); j++) {
        for (let k = 0; k < Math.min(toks.length, 10); k++) {
          if (i === j || j === k || i === k) continue;
          if (isMkt(toks[i]) || isMkt(toks[j]) || isMkt(toks[k])) continue;
          if (lab === toks[i] + toks[j] + toks[k]) return true;
        }
      }
    }
    function cover(s, parts, used) {
      if (!s) return parts >= 2;
      for (let i = 0; i < toks.length; i++) {
        if (used.has(i)) continue;
        const t = toks[i];
        if (isMkt(t)) continue;
        if (!s.startsWith(t)) continue;
        const nextUsed = new Set(used);
        nextUsed.add(i);
        if (cover(s.slice(t.length), parts + 1, nextUsed)) return true;
      }
      return false;
    }
    return cover(lab, 0, new Set());
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

  /**
   * 中文品牌品类尾拼音 vs 主机尾：仅「差一个字母」的拼写 typo（算法，无硬编码品类表）。
   * 例：页内「…音乐」→ yinyue，主机 …yinyuer → distance 1。
   * 完整结构 squat（qissmusic）见 detectChineseProductCategoryHostSquat。
   */
  NS.detectChineseProductRomanizedSuffixTypo = function (cnBrand, hostLabel) {
    try {
      const brand = String(cnBrand || "").replace(/\s+/g, "");
      const label = String(hostLabel || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!brand || !/[一-鿿]/.test(brand) || label.length < 7) return null;
      if (typeof NS.chineseToPinyinFlat !== "function" || typeof NS.editDistanceShort !== "function") return null;
      const morphs = typeof NS.extractChineseProductMorphSuffixes === "function"
        ? NS.extractChineseProductMorphSuffixes(brand)
        : [];
      for (let i = 0; i < morphs.length; i++) {
        const cnSuffix = morphs[i];
        const expectedSuffix = NS.chineseToPinyinFlat(cnSuffix);
        if (!expectedSuffix || expectedSuffix.length < 4) continue;
        // 已是正确拼音尾 → 非 suffix-typo
        if (label.endsWith(expectedSuffix)) return null;
        // 已是品类结构完整匹配（含英文 music 等）→ 交由 category squat
        if (typeof NS.matchLatinPadToChineseMorph === "function") {
          for (let al = Math.min(14, label.length - 2); al >= 4; al--) {
            const act = label.slice(-al);
            if (NS.matchLatinPadToChineseMorph(act, cnSuffix)) return null;
          }
        }
        const minLen = Math.max(4, expectedSuffix.length - 1);
        const maxLen = Math.min(label.length - 2, expectedSuffix.length + 1);
        for (let actualLen = minLen; actualLen <= maxLen; actualLen++) {
          const actualSuffix = label.slice(-actualLen);
          const prefix = label.slice(0, -actualLen);
          if (prefix.length < 2) continue;
          const distance = NS.editDistanceShort(actualSuffix, expectedSuffix);
          if (distance !== 1) continue;
          return {
            chineseSuffix: cnSuffix,
            expectedSuffix,
            actualSuffix,
            expectedHostLabel: `${prefix}${expectedSuffix}`,
            distance
          };
        }
      }
      return null;
    } catch {
      return null;
    }
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
    // Brand + 泛品类词只能说明域名在模仿产品线，不能单靠页面自述证明归属。
    if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function"
      && (NS.hostLabelIsBrandProductCategoryDomain(rawLab, brand) || NS.hostLabelIsBrandProductCategoryDomain(lab, brand))) {
      return typeof NS.hostLabelHasSafeProductLineSuffix === "function"
        && NS.hostLabelHasSafeProductLineSuffix(rawLab, brand)
        ? "exact"
        : "padded";
    }
    if (NS.hostLabelIsBrandTypo(lab, brand)) return "typo";
    if (NS.hostLabelIsPaddedBrand(lab, brand) || NS.hostLabelIsPaddedBrand(rawLab, brand)) return "padded";
    if (lab.includes(brand) || brand.includes(lab)) return "partial";
    return "none";
  };

  /**
   * 软件品牌拉丁核展示用形态切分词缀（英语词根/品类尾，不是品牌名单）。
   * 从右往左剥，可处理任意 head+morph：ding+talk、to+desk、crystal+disk+mark、any+desk…
   */
  NS.BRAND_DISPLAY_MORPH_SUFFIXES = [
    "antivirus", "security", "desktop", "browser", "player", "client", "driver",
    "disk", "mark", "soft", "desk", "talk", "safe", "guard", "music", "cloud",
    "info", "time", "box", "drive", "work", "book", "note", "cast", "link",
    "hub", "lab", "view", "sync", "mail", "chat", "meet", "flow", "base",
    "data", "ware", "lock", "shot", "play", "tune", "wave", "fire", "fox",
    "tech", "code", "pack", "tool", "kit", "zone", "port", "gate", "wall",
    "shield", "bolt", "spark", "pulse", "grid", "core", "edge", "node",
    "share", "drop", "path", "route", "bridge", "stack", "layer", "frame",
    "panel", "board", "card", "chip", "stream", "feed", "live", "room",
    "space", "land", "world", "home", "house", "place", "site", "page",
    "net", "app", "cam", "max", "pro", "bit", "key", "pass", "bee", "ant",
    "cat", "dog", "sun", "sky", "moon", "star", "bird", "fish"
  ];

  /**
   * 纯小写拉丁品牌核 → 结构驼峰（算法，无 dingtalk/todesk 特例）。
   * crystaldiskmark → CrystalDiskMark；dingtalk → DingTalk；todesk → ToDesk；anydesk → AnyDesk
   */
  NS.camelizeLatinBrandToken = function (raw) {
    try {
      const low = String(raw || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!low) return "";
      if (/^[a-z]{2,3}$/.test(low)) return low.toUpperCase();
      if (low.length < 4) return low.charAt(0).toUpperCase() + low.slice(1);

      const morphs = (NS.BRAND_DISPLAY_MORPH_SUFFIXES || [])
        .slice()
        .sort((a, b) => b.length - a.length);
      const parts = [];
      let rest = low;
      let guard = 0;
      // 从右往左反复剥形态词缀（最长优先）
      while (rest.length >= 4 && guard++ < 10) {
        let peeled = false;
        for (let i = 0; i < morphs.length; i++) {
          const suf = morphs[i];
          if (!suf || suf.length < 3) continue;
          // 头部至少留 2 字符（to+desk、we+chat 类）
          if (rest.length < suf.length + 2) continue;
          if (!rest.endsWith(suf)) continue;
          parts.unshift(suf.charAt(0).toUpperCase() + suf.slice(1).toLowerCase());
          rest = rest.slice(0, rest.length - suf.length);
          peeled = true;
          break;
        }
        if (!peeled) break;
      }
      if (parts.length && rest.length >= 2) {
        const head = rest.charAt(0).toUpperCase() + rest.slice(1).toLowerCase();
        return head + parts.join("");
      }
      // 无词缀可剥：首字母大写
      return low.charAt(0).toUpperCase() + low.slice(1).toLowerCase();
    } catch {
      const s = String(raw || "");
      return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "";
    }
  };

  NS.formatBrandTokenForDisplay = function (token) {
    let t = String(token || "").trim();
    if (!t) return "";
    if (/[一-鿿]/.test(t)) return t;
    // 页面 CamelCase 的分词边界若与连字符域名逐段完全一致，应保留页面品牌。
    // ToDesk ⇄ to-desk 命中；CloudToDesk ⇄ cloud-todesk 边界不同，不命中。
    // ★ 勿保留 dingtalk-o → DingtalkO / Dingtalko：短垃圾尾要先剥核
    try {
      const host = NS.normalizeDomain((typeof location !== "undefined" && location.hostname) || "");
      const labelRaw = (String(host || "").split(".")[0] || "").toLowerCase();
      const hostParts = labelRaw.split(/[-_]+/).filter(Boolean);
      const camelParts = t.match(/[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+/g) || [];
      const lastHost = hostParts[hostParts.length - 1] || "";
      const junkTail = hostParts.length === 2 && lastHost.length <= 2
        && /^[a-z0-9]{1,2}$/i.test(lastHost)
        && !/^(?:ai|go|tv|os|io|me|up|db|js|py|id)$/i.test(lastHost);
      if (!junkTail && hostParts.length >= 2 && camelParts.length === hostParts.length
        && camelParts.every((part, i) => part.toLowerCase() === hostParts[i])) {
        return t;
      }
      // 展示串已是「核+短尾」粘连（Dingtalko @ dingtalk-o）→ 剥尾再格式化
      if (junkTail && hostParts[0] && hostParts[0].length >= 5) {
        const flat = t.toLowerCase().replace(/[^a-z0-9]/g, "");
        const core = hostParts[0];
        if (flat === `${core}${lastHost}` || flat === core) {
          t = core;
        }
      }
    } catch { /* ignore */ }
    // 夹带拼词先剥前缀再格式化：vdingtalk → dingtalk → DingTalk；totodesk → todesk → ToDesk
    try {
      const low0 = t.toLowerCase().replace(/[^a-z0-9]/g, "");
      // ★ 先剥 totodesk，否则 camelize 会剥 desk 残成 TotoDesk
      if (/^to(to[a-z0-9]{3,16})$/i.test(low0)) {
        const peeledTo = low0.replace(/^to/i, "");
        if (peeledTo.length >= 5) t = peeledTo;
      } else if (typeof NS.isHostShapedCompoundBrandToken === "function" && NS.isHostShapedCompoundBrandToken(t)) {
        let stripped = typeof NS.stripMarketingHostPrefixFromToken === "function"
          ? NS.stripMarketingHostPrefixFromToken(t)
          : "";
        // Todeskr @ pc-todeskr：strip(t) 对裸段可能空；改用整主机剥核 todesk
        if ((!stripped || stripped.length < 4) && typeof NS.inferMarketingPaddedBrandCore === "function") {
          try {
            const host0 = NS.normalizeDomain((typeof location !== "undefined" && location.hostname) || "");
            const lab0 = (host0.split(".")[0] || "").toLowerCase();
            const core0 = NS.inferMarketingPaddedBrandCore(lab0) || "";
            const flat0 = low0;
            if (core0.length >= 4 && flat0 !== core0
              && (flat0 === lab0.replace(/[^a-z0-9]/g, "")
                || lab0.split(/[-_]/).map((p) => p.replace(/[^a-z0-9]/g, "")).includes(flat0))
              && typeof NS.hostLabelIsPaddedBrand === "function"
              && NS.hostLabelIsPaddedBrand(flat0, core0)) {
              stripped = core0;
            }
          } catch { /* ignore */ }
        }
        if (stripped && stripped.length >= 4) t = stripped;
      } else if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
        // 结构：短营销前缀 + 较长拉丁核（不写死具体品牌）
        if (/^(?:v|x|z|aa|bb|cc|ca|im|ie|pr|ott|get|my)[a-z]{4,}$/i.test(low0)) {
          const stripped = NS.stripMarketingHostPrefixFromToken(low0);
          if (stripped && stripped.length >= 4) t = stripped;
        }
      }
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const low1 = String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        const peeled = NS.inferMarketingPaddedBrandCore(low1) || "";
        if (peeled && peeled.length >= 4 && peeled !== low1) t = peeled;
      }
    } catch { /* ignore */ }
    // 已有内部大写（CrystalDiskMark / DeepSeek）保持；营销前缀粘连脏驼峰（VdingTalk）不保留
    if (/[A-Z]/.test(t.slice(1)) && /[a-z]/.test(t)
      && !/^[VxZ][a-z]{2,}[A-Z]/.test(t)
      && !/^(?:Aa|Bb|Cc|Ca|Im|Ie|Pr|Ott|Get|My)[a-z]+[A-Z]/.test(t)) {
      return t;
    }
    if (/^[a-z0-9]+$/i.test(t) && t.length <= 28) {
      if (typeof NS.camelizeLatinBrandToken === "function") {
        return NS.camelizeLatinBrandToken(t) || (t.charAt(0).toUpperCase() + t.slice(1).toLowerCase());
      }
      return t.charAt(0).toUpperCase() + t.slice(1).toLowerCase();
    }
    return t;
  };

  NS.collectPageClaimedBrandTokens = function () {
    const title = (document.title || "");
    const headings = typeof NS.collectHeadingText === "function" ? NS.collectHeadingText(4000) : (document.querySelector("h1")?.textContent || "");
    const logo = (document.querySelector(".logo, [class*='logo']")?.textContent || "");
    const footer = typeof NS.collectFooterCopyrightText === "function" ? NS.collectFooterCopyrightText() : "";
    const brandSource = `${title} ${headings} ${logo} ${footer}`;
    const tokens = new Set();
    // 含 3 字母全大写核（WPS / QQ / VIP 需另挡）
    const latinBrands = brandSource.match(/\b[A-Z]{2,8}\b|\b[A-Z][a-zA-Z]{2,}(?:[A-Z][a-zA-Z]+)*\b/g) || [];
    latinBrands.forEach((b) => {
      const low = b.toLowerCase();
      if (low.length >= 3 && !/^(download|windows|linux|android|macos|official|client|software|remote|solution|copyright|rights|reserved|vip|app|web|api|cdn|pdf|ssl|tls|http|html|com|net|org)$/i.test(low)) {
        tokens.add(low);
      }
    });
    `${title} ${headings} ${footer}`.match(/\b[A-Za-z]{3,}\b/g)?.forEach((b) => {
      const low = b.toLowerCase();
      if (low.length >= 3 && !/^(download|windows|linux|android|macos|official|client|software|remote|solution|desktop|copyright|rights|reserved|vip|app|web|api|cdn)$/i.test(low)) {
        tokens.add(low);
      }
    });
    (brandSource.match(/\d{3,4}/g) || []).forEach((d) => {
      if (d.length < 3) return;
      if (new RegExp(`${d}(?:官网|官方|安全|互联网|版权|\\.cn|\\.com|\\.net)`, "i").test(brandSource)) tokens.add(d);
    });
    try {
      const label = (location.hostname || "").toLowerCase().replace(/^www\./, "").split(".")[0] || "";
      if (label.length >= 2 && brandSource.toLowerCase().includes(label)) tokens.add(label.replace(/-/g, ""));
    } catch { /* ignore */ }
    // 中文/数字产品：结构抽取，无词表过滤
    if (typeof NS.extractChineseProductBrandCandidates === "function") {
      NS.extractChineseProductBrandCandidates(brandSource).forEach((c) => tokens.add(c));
    }
    (brandSource.match(/\d{2,6}[一-鿿]{2,6}/g) || []).forEach((c) => tokens.add(c));
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
