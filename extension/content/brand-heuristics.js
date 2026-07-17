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
        const st = NS.stripMarketingHostPrefixFromToken(flat) || "";
        if (st.length >= 4 && flat !== st && flat.includes(st)) return true;
      }
      // qq-musics / xx-music(s) 连字符仿冒
      if (/^(?:qq|wx|weixin|netease|wy)[-_]?(?:music|musics|yinyue|yinle)/i.test(flat)) return true;
      if (/[-_](?:music|musics|yinyue|yinle|pc|app|soft|safe|vip|pro|cn|win|download|client)$/i.test(raw)) {
        const head = raw.split(/[-_]/)[0] || "";
        if (head.length >= 2 && head.length <= 12) return true;
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
            || /[-_](?:pc|app|soft|safe|vip|pro|cn|win|download|client)$/i.test(lab)
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
        const d = String(s || "").replace(/[^\d]/g, "");
        if (!/^\d{3,6}$/.test(d) || /^(?:19|20)\d{2}$/.test(d)) return;
        if (!out.digits.includes(d)) out.digits.push(d);
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
          || /[-_](?:pc|app|soft|safe|vip|pro|cn|win|download|client)$/i.test(apexLeftRaw)
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
      const apex = (typeof NS.getRegistrableDomain === "function" ? NS.getRegistrableDomain(host) : "") || host;
      const apexFlat = (apex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const hostFlat = host.replace(/[^a-z0-9]/g, "");
      const cores = typeof NS.collectHostBrandCores === "function" ? NS.collectHostBrandCores(host) : null;
      const padCore = (cores && cores.padCore) || "";
      const root = (cores && cores.root) || "";

      // 候选 == 首标签 / apex / 整 host 去符号（含 download.vdingtalk.com 时 apex=vdingtalk）
      if (labFlat && low === labFlat) return true;
      if (apexFlat && low === apexFlat && low.length >= 5) {
        // apex 自身是干净品牌核（dingtalk.com）→ 不当碎片
        if (padCore && padCore === low) return false;
        // apex 是夹带整段（vdingtalk / iehuorong / huorongpc）
        if (padCore && padCore.length >= 4 && low !== padCore && low.includes(padCore)) return true;
        if (typeof NS.inferMarketingPaddedBrandCore === "function") {
          const c2 = NS.inferMarketingPaddedBrandCore(apexFlat) || NS.inferMarketingPaddedBrandCore(
            // 尝试还原连字符：vdingtalk 无法还原，靠 glued 推断
            apexFlat
          );
          if (c2 && c2.length >= 4 && c2 !== low && low.includes(c2)) return true;
        }
        // 单字母/短前缀粘连：v+dingtalk、x+todesk
        if (/^[vxz][a-z]{5,}$/i.test(low) || /^(?:aa|bb|cc|ca|im|ie|pr|gw|get|ott|seo|vip|my|dl)[a-z]{5,}$/i.test(low)) {
          return true;
        }
      }
      if (root && low === root && padCore && padCore !== low && low.includes(padCore)) return true;
      if (hostFlat && low === hostFlat) return true;

      // 主机 = 营销前缀/后缀 + 核
      if (padCore && padCore.length >= 4) {
        // ★ 夹带域剥出的核本身若只来自「前缀+核」整段（qqyinle→yinle），展示时仍算主机碎片
        //    页内真品牌「QQ音乐」不得被 Yinle 抢走；干净站 dingtalk.com 的 padCore===apex 则放行
        if (low === padCore) {
          if (apexFlat && apexFlat !== padCore && apexFlat.includes(padCore)) return true; // yinle @ qqyinle
          if (labFlat && labFlat !== padCore && labFlat.includes(padCore) && labFlat.length > padCore.length) return true;
          return false; // 干净 apex 核
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
      const low = String(token || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!low || low.length < 6) return "";
      // 已知短前缀表（含单字母 v/x/z）
      const m = low.match(/^(v|x|z|aa|bb|cc|ca|im|ie|pr|gw|get|ott|seo|cdn|vip|pro|my|pc|app|dl|qq|wx|hd|tv)([a-z][a-z0-9]{4,18})$/i);
      if (m && m[2] && m[2].length >= 5) return m[2].toLowerCase();
      if (typeof NS.inferMarketingPaddedBrandCore === "function") {
        const c = NS.inferMarketingPaddedBrandCore(low);
        if (c && c.length >= 4 && c !== low) return c;
      }
      return "";
    } catch { return ""; }
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
      // 中文：域名拉丁根 bridge（须页内已有该中文；bridge 只定对齐强度）
      if (/[一-鿿]/.test(c0) && typeof NS.domainLatinRootHintsChineseBrand === "function") {
        if (NS.domainLatinRootHintsChineseBrand(c0, cores)) return 2;
      }
      return 0;
    } catch { return 0; }
  };

  /**
   * 域名拉丁根是否提示该中文品牌（薄桥，非全量拼音表）。
   * 仅当主机核命中已知根且候选中文匹配时返回 true——配合页内真实出现才加 domain 票。
   * 例：www.huorong.cn + 火绒；可扩展。
   */
  NS.DOMAIN_LATIN_CN_BRIDGE = {
    huorong: ["火绒", "火绒安全"],
    hongrong: ["火绒", "火绒安全"],
    dingtalk: ["钉钉"],
    qihoo: ["360", "360安全卫士"],
    sogou: ["搜狗"],
    baidu: ["百度"],
    tencent: ["腾讯"],
    // 仿冒拼音/英文夹带：qqyinle / qqmusics / qq-musics → 页内 QQ音乐
    yinle: ["QQ音乐", "QQ音乐官网"],
    yinyue: ["QQ音乐", "QQ音乐官网"],
    musics: ["QQ音乐", "QQ音乐官网"],
    music: ["QQ音乐", "QQ音乐官网"],
    alibaba: ["阿里", "阿里巴巴"],
    huawei: ["华为"],
    xiaomi: ["小米"],
    netease: ["网易"],
    youku: ["优酷"],
    bilibili: ["哔哩哔哩", "B站"],
    kuaishou: ["快手"]
  };

  NS.domainLatinRootHintsChineseBrand = function (cnBrand, coresOpt) {
    try {
      const cn = String(cnBrand || "").trim();
      if (!cn || !/[一-鿿]/.test(cn)) return false;
      const cores = coresOpt || (typeof NS.collectHostBrandCores === "function"
        ? NS.collectHostBrandCores()
        : null);
      if (!cores || !cores.latin || !cores.latin.length) return false;
      const bridge = NS.DOMAIN_LATIN_CN_BRIDGE || {};
      for (const root of cores.latin) {
        const hints = bridge[root];
        if (!hints || !hints.length) continue;
        for (const h of hints) {
          if (cn === h || cn.includes(h) || h.includes(cn)) return true;
        }
      }
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
      if (typeof NS.hostIsProductSubdomainOfBrandApex !== "function"
        || !NS.hostIsProductSubdomainOfBrandApex(hostOpt)) return false;
      const host = NS.normalizeDomain(hostOpt || location.hostname);
      const apex = NS.getRegistrableDomain(host) || host;
      const apexLeft = (apex.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (apexLeft.length < 2) return false;
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

  // 仅协议/扩展名/字面量——不维护业务词黑名单；品牌取舍靠域名相关度
  const BRAND_TOKEN_STOP_RE = /^(https?|http|www|html|htm|com|net|org|css|js|png|jpg|jpeg|gif|svg|webp|json|xml|php|asp|aspx|true|false|null|undefined)$/i;
  NS.BRAND_TOKEN_STOP_RE = BRAND_TOKEN_STOP_RE;

  /**
   * 资源/图标/构建/CMS/版权垃圾 token（B1icon13、Cover、Reserved…）绝不当品牌。
   * Reserved 来自页脚 All Rights Reserved，曾抢占「火绒」展示名。
   */
  NS.looksLikeAssetGarbageToken = function (token) {
    const s = String(token || "").trim().toLowerCase().replace(/[^a-z0-9]/g, "");
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
  const MKT_HOST_PREFIX = /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|pr|my|the|best|new|top|go|use|try|win|cn|zh|en|www\d*|im|ie|qq|wx|dl|to|up|re|un|gw|seo|ott|cdn|tv|hd|4k|vip|x|z)$/i;
  const MKT_HOST_SUFFIX = /^(?:app|desktop|client|soft|download|free|pro|vip|official|online|cloud|tool|tools|win|windows|setup|install|cn|hub|box|pc|mac|ios|android|mobile|desk)$/i;
  // 产品线尾缀可拼正站；营销前缀拼域名一律 squat
  const PRODUCT_LINE_HOST_TOKEN = /^(?:ai|gpt|ml|bot|llm|security|antivirus|av|lab|labs|linux|windows|macos|android|bsd)$/i;
  // 产品线后缀（结构）：pyas-security = 品牌+品类；亦含 OS 发行版粘连、AI 产品线（todeskai）
  // 与 brand-pc / im-todesk 营销夹带区分：品类尾缀表示正站产品线，非 squat
  const BRAND_PRODUCT_CATEGORY_SUFFIX = /^(?:security|antivirus|antimalware|av|secure|protection|defender|endpoint|tech|systems?|network|lab|labs|studio|group|hq|linux|windows|macos|android|ai|gpt|ml|bot|llm)$/i;
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
    // 单字母频道前缀：v-dingtalk / vdingtalk（strict 亦认，供无连字符扫描）
    if (/^[vxz]$/i.test(p)) return true;
    if (opts && opts.strict) return false;
    // 宽松：连字符主机可用短前缀 to/go/up（to-desk 镜像另论）
    if (MKT_HOST_PREFIX.test(p)) return true;
    return false;
  };

  /**
   * 主机是否「营销前缀 + 品牌」夹带形态：ott-todesk / pr-todesk / imtodesk。
   * 此类绝不当 domain-keyword related 正站。
   */
  NS.hostLabelIsMarketingPrefixedBrandShape = function (rawLabel, brandTokenOpt) {
    try {
      const raw = String(rawLabel || "").toLowerCase().replace(/^www\./, "");
      if (!raw || raw.length < 5) return false;
      const lab = raw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      // 连字符：ott-todesk（可用宽松前缀表）
      if (/-/.test(raw)) {
        const parts = raw.split("-").filter(Boolean).map((p) => p.replace(/[^a-z0-9]/g, ""));
        if (parts.length >= 2) {
          const first = parts[0];
          const rest = parts.slice(1).join("");
          if (NS.isMarketingHostPrefixToken(first) && rest.length >= 4
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

  NS.extractLatinBrandTokens = function (text) {
    const out = [];
    const seen = new Set();
    // 保留 CamelCase 整词（DingTalk）；过滤图标/资源/WP 垃圾（B1icon13、Cover）
    (String(text || "").match(/[A-Za-z][A-Za-z0-9]{2,}/g) || []).forEach((b) => {
      const low = b.toLowerCase();
      if (low.length < 4 || low.length > 24) return;
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
        fields.h1 = String(document.querySelector("h1")?.innerText || document.querySelector("h1")?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 200);
      } catch { fields.h1 = ""; }
      // h2 单独采集（综合共识用）；限长，避免功能卡堆砌
      try {
        fields.h2 = Array.from(document.querySelectorAll("h2"))
          .map((el) => (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim())
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
      // 仅剥分发/渠道尾巴；「…安全 / …杀毒 / …卫士」是产品名一部分，保留
      let next = t
        .replace(/(?:官网下载|官方下载|免费下载|立即下载|客户端下载|下载中心|电脑版|手机版)$/u, "")
        .replace(/(?:官网|官方网站|官方)$/u, "")
        .replace(/(?:软件|客户端)$/u, "") // 火绒安全软件 → 火绒安全
        .replace(/(?:下载)$/u, "")
        .trim();
      // 勿把「火绒安全」剥成「火绒」；勿留下纯「安全」
      if (next && next !== t) {
        if (/^(?:安全|杀毒|卫士|软件|客户端|官方|官网)$/.test(next)) break;
        if (next.length < 2) break;
        t = next;
        continue;
      }
      break;
    }
    return t;
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
      if (/^\d{3,6}$/.test(t) && !/^(?:19|20)\d{2}$/.test(t)) return t;
      // 版权/法律词绝不当展示品牌（All Rights Reserved → Reserved）
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
      if (/^(?:reserved|rights|copyright|all\s*rights(\s*reserved)?)$/i.test(t)) return "";
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
   * 是否「不可用」中文品牌 token（结构判断，无业务词表）。
   * 挡 UI/卖点残片与站点栏目：「可访问」「技术支持」「下载中心」等绝不当仿冒展示名。
   */
  NS.isWeakChineseBrandToken = function (token) {
    const s = String(token || "").trim();
    if (!s) return true;
    if (s.length < 2) return true;
    // 纯数字：年份弱；3–6 位门户数字品牌（4399/360/2345）放行
    if (/^\d+$/.test(s)) {
      if (/^(?:19|20)\d{2}$/.test(s)) return true;
      if (/^\d{3,6}$/.test(s)) return false;
      return true;
    }
    // 下载页标题前缀动作词（「下载 火狐浏览器」）绝不当品牌
    if (/^(?:下载|安装|获取|官方|官网|免费|最新|正版|立即|马上|关于)$/.test(s)) return true;
    // 未裁净的「关于…」栏目整段（关于火绒杀毒）——应先 trimChineseBrandLead，残留整段仍弱
    if (/^关于/.test(s) && s.length >= 4) return true;
    // 纯品类词（无专名）——「安全」 alone 会在 火绒安全/终端安全 里到处命中抢票
    if (/^(?:浏览器|客户端|软件|应用|平台|工具|系统|服务|网站|主页|中心|频道|首页|杀毒|卫士|安全|终端|防护|防御|查杀|病毒|木马|广告|弹窗|音乐|歌曲|视频|办公|网盘|助手|管家)$/.test(s)) return true;
    // 营销口号（非产品名）：「音乐同好聚集」「开启沉浸式体验」等曾抢占 QQ音乐
    if (!/[A-Za-z0-9]/.test(s) && s.length >= 4) {
      if (/同好|聚集|沉浸|打造|专属|宇宙|听觉|爱好者|聚集地|开启|体验$|独特的你|听我想听/.test(s)) return true;
    }
    // 站点栏目/导航形态：「技术支持」「下载中心」「新闻中心」「常见问题」「文档教程」
    // （support.html 标题「技术支持 - CrystalDiskMark…」曾误报仿冒「技术支持」）
    if (!/[A-Za-z0-9]/.test(s) && s.length >= 2 && s.length <= 8) {
      if (/(?:支持|中心|教程|指南|文档|新闻|资讯|论坛|社区|帮助|问题|排查|关于|联系|客服|售后|频道|专栏)$/.test(s)) return true;
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
   * 中文 token 是否像「完整产品名」形态（结构加分用，非词表）。
   * 如 火狐浏览器 / 360安全卫士 / 网易云音乐 / QQ音乐。
   */
  NS.looksLikeChineseProductBrandMorphology = function (token) {
    const s = String(token || "").trim();
    if (!s || s.length < 2) return false;
    if (NS.CN_DIGIT_PRODUCT_RE && NS.CN_DIGIT_PRODUCT_RE.test(s)) return true;
    if (/[A-Za-z]/.test(s) && /[一-鿿]/.test(s) && s.length >= 3) return true;
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
      let rawFull = String(raw || "").trim();
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
          return typeof NS.normalizeDisplayBrandName === "function"
            ? (NS.normalizeDisplayBrandName(latOff) || latOff)
            : latOff;
        }
        // 拉丁+中文+官网：「QQ音乐官网」——中文在 官网 之前，且捕获组不含 官网
        const mixedOff = (rawFull.match(
          /([A-Za-z][A-Za-z0-9]{0,12}[一-鿿]{1,6})(?:官网|官方(?:下载|网站|客户端|正版|软件)?)/
        ) || [])[1] || "";
        if (mixedOff) {
          let ms = NS.trimChineseBrandTrail(mixedOff) || mixedOff;
          ms = (typeof NS.normalizeDisplayBrandName === "function" ? NS.normalizeDisplayBrandName(ms) : ms) || ms;
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
    const t = String(text || "");
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
      const o = opts || {};
      if (typeof NS.collectPrimaryBrandKeywords === "function") {
        const pk = NS.collectPrimaryBrandKeywords();
        if (pk && pk.display) return pk.display;
      }
      const picked = typeof NS.pickProductBrandFromIdentity === "function"
        ? NS.pickProductBrandFromIdentity(o.labelRaw)
        : null;
      if (picked && picked.displayBrand) return picked.displayBrand;
      const raw = String(o.brandToken || o.latin || o.preferredLatin || o.displayBrand || "").trim();
      if (!raw || BRAND_TOKEN_STOP_RE.test(raw.toLowerCase())) return "";
      if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(raw)) return "";
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
      // 营销夹带后缀（huorong-pc）；勿含 security/antivirus/ai/gpt——产品线正站
      const mktSuf = /^(?:pc|app|soft|safe|vip|pro|cn|win|desk|guard|download|down|client|free|official|online|cloud|tool|tools|hub|box|mac|ios|android|mobile|setup|install|site|web|net|home|store)$/i;
      // ie/v-huorong：ie、v 为短营销前缀（频道/单字母夹带）
      const mktPre = /^(?:get|aa|bb|cc|ca|pc|app|free|soft|down|download|safe|vip|pro|pr|gw|my|the|best|new|top|go|use|try|win|cn|zh|en|im|ie|v|x|z|qq|wx|dl|to|up|re|un|web|www\d*|hi|ok|yes|seo|cdn|ott|tv|hd)$/i;
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
          // ott-todesk / pr-todesk / aa-todesk / im-todesk：短前缀 + 品牌核 → 核心是后段
          if (first.length >= 1 && first.length <= 4 && last.length >= 4 && last.length <= 18
            && !mktSuf.test(last) && !mktPre.test(last)
            && (mktPre.test(first) || first.length <= 3
              || /^(?:pr|gw|seo|cdn|ott|tv|hd|www\d*|vip|pro|soft|safe|dl)$/i.test(first)
              || (typeof NS.isMarketingHostPrefixToken === "function" && NS.isMarketingHostPrefixToken(first)))) {
            return last;
          }
          // huorong-pc / huorong-safe-pc（非 pyas-security）
          if (mktSuf.test(last) && /^[a-z][a-z0-9]{3,16}$/i.test(first) && !mktPre.test(first) && !mktSuf.test(first)) {
            return first;
          }
          // im-todesk / get-huorong（多段时取品牌段）
          if (mktPre.test(first) && parts[1] && /^[a-z][a-z0-9]{3,16}$/i.test(parts[1]) && !mktSuf.test(parts[1])) {
            return String(parts[1]);
          }
        }
      }
      const lab = raw.replace(/-/g, "");
      // 无连字符：禁止用 desk 作营销尾缀——todesk/anydesk 等品牌以 desk 结尾，
      // 否则 prtodesk → prto+desk 误报「Prto」
      const m = lab.match(/^([a-z][a-z0-9]{3,16})(pc|app|soft|safe|vip|pro|cn|win|security|guard|download|client|free|official)$/i);
      if (m && m[1] && !mktPre.test(m[1])) return m[1].toLowerCase();
      // 无连字符前缀粘连：vdingtalk → dingtalk；qqmusics → musics（勿含 to，避免 todeskai 被拆）
      const glued = lab.match(/^(v|x|z|aa|bb|cc|ca|im|ie|pr|gw|get|ott|seo|cdn|vip|my|dl|qq|wx|hd|tv|win)([a-z][a-z0-9]{4,18})$/i);
      if (glued && glued[2] && glued[2].length >= 4 && glued[2].length <= 18
        && !mktSuf.test(glued[2]) && !mktPre.test(glued[2])) {
        return glued[2].toLowerCase();
      }
      // qq-musics / qq-music 连字符：核取 music(s) 段供 padded 判定（展示仍走 QQ音乐）
      if (/^qq[-_]?musics?$/i.test(lab) || /^qq[-_]musics?$/i.test(raw)) {
        return (lab.match(/musics?$/i) || ["music"])[0].toLowerCase();
      }
      return "";
    } catch { return ""; }
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
        let t = String(raw || "").trim();
        if (!t) return "";
        // 夹带域整段（Iehuorong / Huorongpc）绝不当展示名
        if (isHostDebris(t)) return "";
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
        if (typeof NS.isWeakChineseBrandToken === "function" && NS.isWeakChineseBrandToken(t)) return "";
        if (typeof NS.normalizeDisplayBrandName === "function") {
          t = NS.normalizeDisplayBrandName(t) || "";
        } else if (typeof NS.trimChineseBrandTrail === "function" && /[一-鿿]/.test(t)) {
          t = NS.trimChineseBrandTrail(t) || t;
        }
        if (!t || isHostDebris(t)) return "";
        if (typeof NS.looksLikeAssetGarbageToken === "function" && NS.looksLikeAssetGarbageToken(t)) return "";
        return t;
      };

      // 从碎片 token 回退到干净核展示名
      const fromCore = (core, blobOpt) => {
        const c = String(core || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!c || c.length < 4 || isHostDebris(c)) return "";
        const blob = String(blobOpt != null ? blobOpt : ((kw && kw.blob) || document.title || ""));
        const blobLow = blob.toLowerCase();
        const blobFlat = blobLow.replace(/[^a-z0-9\u4e00-\u9fff]/gi, "");
        // 中文桥优先（dingtalk→钉钉）
        if (typeof NS.DOMAIN_LATIN_CN_BRIDGE === "object" && NS.DOMAIN_LATIN_CN_BRIDGE[c]) {
          for (const cn of NS.DOMAIN_LATIN_CN_BRIDGE[c]) {
            if (blob.includes(String(cn))) {
              const dCn = clean(cn);
              if (dCn) return dCn;
            }
          }
        }
        if (blobFlat.includes(c) || blobLow.includes(c)) {
          return clean(
            typeof NS.formatBrandTokenForDisplay === "function"
              ? NS.formatBrandTokenForDisplay(c)
              : c
          );
        }
        // 页内只有 VdingTalk 碎片时：仍用核展示（仿冒 toast 需要可读品牌）
        return clean(
          typeof NS.formatBrandTokenForDisplay === "function"
            ? NS.formatBrandTokenForDisplay(c)
            : c
        );
      };

      // 0) ★ 页内等权中文/混合产品（QQ音乐）永远优先于主机拉丁碎片（Yinle）
      if (kw.cn && kw.cn.length) {
        for (let i = 0; i < kw.cn.length; i++) {
          const cn = String(kw.cn[i] || "").trim();
          if (!cn) continue;
          // 优先含中文的产品名
          if (!/[一-鿿]/.test(cn) && !/^\d{3,6}/.test(cn)) continue;
          const d0 = clean(cn);
          if (d0 && /[一-鿿]/.test(d0)) return d0;
          if (d0 && /^\d{3,6}/.test(d0)) return d0;
        }
      }
      // 0b) display 本身已是中文产品
      {
        const dDisp = clean(kw.display);
        if (dDisp && /[一-鿿]/.test(dDisp)) return dDisp;
      }

      // 0c) 页内中文 + 域名桥（火绒/钉钉 @ 夹带域）
      try {
        const cores = typeof NS.collectHostBrandCores === "function" ? NS.collectHostBrandCores(host) : null;
        if (cores && (cores.padCore || (cores.voteLatin && cores.voteLatin.length))
          && kw.cn && kw.cn.length
          && typeof NS.domainLatinRootHintsChineseBrand === "function") {
          for (let i = 0; i < kw.cn.length; i++) {
            const cn = String(kw.cn[i] || "").trim();
            if (!cn || !/[一-鿿]/.test(cn)) continue;
            if (NS.domainLatinRootHintsChineseBrand(cn, cores)) {
              const d0 = clean(cn);
              if (d0) return d0;
            }
          }
        }
      } catch { /* ignore */ }

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
      // archlinux / todeskai = 品牌+平台/产品线粘连正站，非营销夹带
      // （无连字符 + 平台尾缀 linux/windows 时不当 padded；ai 等走下方品类后缀）
      if (/^(linux|windows|macos|android)$/i.test(pad) && br.length <= 6 && !/-/.test(String(label || ""))) {
        return false;
      }
      // security/antivirus/ai 产品线尾缀不当 padded（todeskai、pyassecurity）
      if (BRAND_PRODUCT_CATEGORY_SUFFIX.test(pad)) return false;
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

      // ★ 营销前缀夹带（ott-todesk / pr-todesk / im-todesk）→ 绝非「高度吻合正站」
      if (typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
        && NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw)) {
        return false;
      }
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
      } catch { /* ignore */ }

      const kw = kwOpt || (typeof NS.collectPrimaryBrandKeywords === "function"
        ? NS.collectPrimaryBrandKeywords()
        : null);
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
      // 域名整段出现在身份——但夹带域会在页脚写 ott-todesk.com.cn，不能当正站
      if ((blobFlat.includes(lab) || blobLow.includes(labelRaw))
        && !(typeof NS.hostLabelIsMarketingPrefixedBrandShape === "function"
          && NS.hostLabelIsMarketingPrefixedBrandShape(labelRaw))) {
        // 仅当不是「营销前缀+品牌」时，域名自现才算吻合
        return true;
      }

      const productLine = PRODUCT_LINE_HOST_TOKEN;
      const bits = new Set();
      // 保留 2 字母产品线词 AI
      (blob.match(/[A-Za-z][A-Za-z0-9]{0,23}/g) || []).forEach((b) => {
        const low = b.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (low.length >= 2 && low.length <= 24) bits.add(low);
      });
      (kw && kw.latin || []).forEach((t) => {
        const low = String(t || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (low.length >= 2) bits.add(low);
      });
      if (typeof NS.extractLatinBrandTokens === "function") {
        NS.extractLatinBrandTokens(blob).forEach((t) => bits.add(String(t).toLowerCase()));
      }

      const list = [...bits];
      // brand + 产品线（页上有 ToDesk 与 AI，域 todeskai）——尾缀必须是产品线，不能是营销前缀拼法
      for (const t of list) {
        if (t.length < 4 || productLine.test(t)) continue;
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
            if (lab === a + b && productLine.test(b) && a.length >= 3) return true;
            if (lab === b + a && productLine.test(a) && b.length >= 3) return true;
            continue;
          }
          // 两段均较长的产品复合（少见）
          if (a.length >= 4 && b.length >= 4) return true;
        }
      }

      // 品类域名：todesk + ai 结构（即便 AI 抽词失败，标题有 Brand AI 话术也认）
      if (typeof NS.hostLabelIsBrandProductCategoryDomain === "function") {
        for (const t of list) {
          if (t.length < 4 || productLine.test(t)) continue;
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
    function cover(s, parts) {
      if (!s) return parts >= 2;
      for (const t of toks) {
        if (isMkt(t)) continue;
        if (s.startsWith(t) && cover(s.slice(t.length), parts + 1)) return true;
      }
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
    let t = String(token || "").trim();
    if (!t) return "";
    if (/[一-鿿]/.test(t)) return t;
    // 夹带拼词先剥前缀再格式化：VdingTalk/vdingtalk → DingTalk（勿显示 VdingTalk）
    try {
      if (typeof NS.isHostShapedCompoundBrandToken === "function" && NS.isHostShapedCompoundBrandToken(t)) {
        const stripped = typeof NS.stripMarketingHostPrefixFromToken === "function"
          ? NS.stripMarketingHostPrefixFromToken(t)
          : "";
        if (stripped && stripped.length >= 4) t = stripped;
      } else if (typeof NS.stripMarketingHostPrefixFromToken === "function") {
        // 页内写死 VdingTalk 而主机比对未命中时，仍剥已知短前缀
        const low0 = t.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (/^(?:v|x|z|aa|bb|cc|ca|im|ie|pr)[a-z]{5,}$/i.test(low0)) {
          const stripped = NS.stripMarketingHostPrefixFromToken(low0);
          if (stripped && stripped.length >= 5) t = stripped;
        }
      }
    } catch { /* ignore */ }
    // 已有内部大写（CrystalDiskMark / DeepSeek）保持；但 VdingTalk 已在上方剥前缀
    if (/[A-Z]/.test(t.slice(1)) && /[a-z]/.test(t) && !/^[VxZ][a-z]{2,}(?:Talk|Desk|Soft)/.test(t)) return t;
    if (/^[a-z0-9]+$/i.test(t) && t.length <= 24) {
      // 常见驼峰：crystaldiskmark → CrystalDiskMark；todesk → ToDesk；dingtalk → DingTalk
      const low = t.toLowerCase();
      if (low.length >= 6 && /disk|mark|soft|desk|talk|safe|guard|music|cloud/i.test(low)) {
        try {
          const camel = low
            .replace(/(disk|mark|soft|desk|talk|safe|guard|music|cloud|info|time|box)/gi, (m) => m.charAt(0).toUpperCase() + m.slice(1).toLowerCase())
            .replace(/^[a-z]/, (c) => c.toUpperCase());
          if (camel.length === low.length) return camel.charAt(0).toUpperCase() + camel.slice(1);
        } catch { /* fall through */ }
      }
      // dingtalk 无 talk 分段时的专用驼峰
      if (low === "dingtalk") return "DingTalk";
      if (low === "todesk") return "ToDesk";
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
