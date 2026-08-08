/**
 * 品牌拼音：仅在 Service Worker 内加载 pinyin-pro（默认词典，非 complete）。
 * 网页 content 不注入词典，避免全站卡死。
 */
;(function (NS) {
  "use strict";

  let _pyReady = false;
  let _pyApi = null;
  const _cache = new Map();
  const _CACHE_MAX = 256;

  function ensurePinyin() {
    if (_pyReady && _pyApi) return true;
    try {
      // 仅加载一次 umd；失败则后续返回空
      if (!_pyApi) {
        try {
          importScripts("../vendor/pinyin-pro/pinyin-pro.umd.js");
        } catch (e) {
          try { console.warn("[silverfox] pinyin importScripts", e); } catch { /* ignore */ }
        }
        _pyApi = (typeof self !== "undefined" && (self.pinyinPro || self.__silverfoxPinyinPro))
          || (typeof pinyinPro !== "undefined" ? pinyinPro : null)
          || null;
      }
      _pyReady = !!( _pyApi && typeof _pyApi.pinyin === "function");
      return _pyReady;
    } catch {
      _pyReady = false;
      return false;
    }
  }

  function normalize(value) {
    try {
      return String(value ?? "")
        .normalize("NFKC")
        .toLowerCase()
        .replace(/[^\p{L}\p{N}\p{Script=Han}]+/gu, "");
    } catch {
      return String(value || "").toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/gi, "");
    }
  }

  function isWeakCn(s) {
    const t = String(s || "").trim();
    if (!t || t.length < 2) return true;
    if (/^(?:中文|英文|英语|汉语|简体|繁体|简体中文|繁体中文|语言|版本|官方|官网|下载|应用|中心|安全|杀毒|卫士|软件|客户端|平台|工具|系统|服务|首页|频道|品牌|产品|免费|关于)$/.test(t)) {
      return true;
    }
    // 营销/版本/安装话术不是品牌。这里按语言结构过滤，不维护厂商品牌表。
    if (/^(?:电脑|电脑版|桌面|桌面版|PC版|客户端|官方|正版|免费|最新|新版|旧版|高速|安全).{0,6}(?:下载|安装|服务|软件|版本|客户端)?$/i.test(t)) return true;
    const modeLead = /^(?:智能|自动|一键|在线|离线|实时|快速|极速|精准|批量|免费|专业|高效|便捷|云端|本地|远程|桌面|移动|跨端|跨平台|多端|多人|团队|个性|每日|热门|精选)/;
    const capabilityTail = /(?:重?命名|改名|编辑|推荐|生成|识别|分析|检测|搜索|翻译|创作|剪辑|修复|转换|处理|管理|优化|加速|同步|备份|清理|压缩|解压|录制|播放|下载|安装|截图|桌面|控制|协助|协作|连接|访问|办公|会议|教育|助手|运维|操作|服务|音乐|歌曲|歌单)$/;
    if (modeLead.test(t) && (capabilityTail.test(t)
      || (t.length >= 4 && /(?:远程)?(?:控|协|连|访|运)$/.test(t)))) return true;
    return false;
  }

  function editDistance(a, b) {
    const s = String(a || "");
    const t = String(b || "");
    if (Math.abs(s.length - t.length) > 2) return 99;
    const row = Array.from({ length: t.length + 1 }, (_, i) => i);
    for (let i = 1; i <= s.length; i++) {
      let diagonal = row[0];
      row[0] = i;
      for (let j = 1; j <= t.length; j++) {
        const old = row[j];
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1,
          diagonal + (s[i - 1] === t[j - 1] ? 0 : 1));
        diagonal = old;
      }
    }
    return row[t.length];
  }

  function latinRelation(a, b) {
    const left = String(a || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const right = String(b || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (left.length < 3 || right.length < 3) return "none";
    if (left === right) return "exact";
    if (left.length >= 4 && right.includes(left)) return "host-affix";
    if (right.length >= 4 && left.includes(right)) return "brand-affix";
    const minLen = Math.min(left.length, right.length);
    if (minLen < 5 || Math.abs(left.length - right.length) > 2) return "none";
    const d = editDistance(left, right);
    if (d === 1 || (d === 2 && minLen >= 9)) return "typo";
    return "none";
  }

  NS.brandPinyinBg = function (text) {
    try {
      const raw = String(text || "");
      if (!raw || raw.length > 48) return "";
      if (_cache.has(raw)) return _cache.get(raw);
      if (!ensurePinyin()) return "";
      const py = _pyApi.pinyin(raw, {
        toneType: "none",
        type: "array",
        nonZh: "consecutive",
        v: true
      });
      const joined = Array.isArray(py) ? py.join("") : String(py || "");
      const norm = normalize(joined);
      if (norm) {
        if (_cache.size >= _CACHE_MAX) {
          const first = _cache.keys().next().value;
          if (first != null) _cache.delete(first);
        }
        _cache.set(raw, norm);
      }
      return norm || "";
    } catch {
      return "";
    }
  };

  /** 主机基础拉丁形态；不在这里跨标签自行推断品牌。 */
  NS.collectHostLatinFormsBg = function (hostOpt) {
    const out = [];
    const seen = Object.create(null);
    const add = (s) => {
      const t = String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!t || t.length < 3 || seen[t]) return;
      seen[t] = 1;
      out.push(t);
    };
    try {
      const host = String(hostOpt || "").toLowerCase().replace(/^www\./, "").split("/")[0];
      if (!host) return out;
      const labelRaw = (host.split(".")[0] || "").toLowerCase();
      const labFlat = labelRaw.replace(/-/g, "").replace(/[^a-z0-9]/g, "");
      add(labFlat);
      add(labelRaw.replace(/[^a-z0-9]/g, ""));
      if (/-/.test(labelRaw)) {
        const segs = labelRaw.split("-").map((p) => p.replace(/[^a-z0-9]/g, "")).filter(Boolean);
        segs.forEach(add);
        add(segs.join(""));
      }
      // 简单 eTLD+1 左标
      const parts = host.split(".");
      if (parts.length >= 2) {
        const apexLeft = parts[0];
        if (parts.length >= 3 && /^(?:com|net|org|co|gov|edu|ac)$/i.test(parts[parts.length - 2])) {
          add(parts[parts.length - 3]);
        } else {
          add(apexLeft.replace(/[^a-z0-9]/g, ""));
        }
      }
    } catch { /* ignore */ }
    return out;
  };

  /**
   * 由页面候选的拼音主动在 host 中选择片段。
   * 例如“钉钉”先得到 dingding，再从 ding-soft.pc-ding.com 中依次选择
   * ding + ding；域名不会先自行剥出一个品牌。
   */
  function matchPinyinToHost(py, hostOpt, opts) {
    const none = { matched: false, hostForm: "", relation: "none" };
    const target = String(py || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (target.length < 3) return none;
    const host = String(hostOpt || "").toLowerCase().replace(/^www\./, "").split("/")[0];
    const tokens = host.split(/[^a-z0-9]+/).filter((t) => t && !/^(?:www|com|cn|net|org|co|gov|edu|ac)$/i.test(t)).slice(0, 16);
    if (!tokens.length) return none;

    // states 是“由 target 引导后可能保留的域名片段”，每一步都允许跳过噪声片段。
    let states = [""];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      const next = states.slice();
      for (let si = 0; si < states.length; si++) {
        const joined = states[si] + token;
        if (joined.length <= target.length + 2) next.push(joined);
      }
      // 页面中文候选先给出 target 后，才允许在单个域名标签边缘确认较长污染尾。
      // 例如「汽水」→ qishui，可确认 qishui+yyds；这里绝不从 qishuiyyds
      // 自行猜 qishui，因此不会退回成“按域名前缀发明品牌”。
      const extra = token.length - target.length;
      const maxGuidedNoise = Math.max(4, Math.min(6, Math.ceil(target.length * 0.75)));
      if (opts && opts.allowLongAffix === true
        && target.length >= 5 && extra >= 3 && extra <= maxGuidedNoise
        && (token.startsWith(target) || token.endsWith(target))) {
        next.push(token);
      }
      states = Array.from(new Set(next)).slice(0, 128);
    }

    let best = none;
    const rank = { exact: 4, typo: 3, "host-affix": 2, "brand-affix": 2, none: 0 };
    for (let i = 0; i < states.length; i++) {
      const form = states[i];
      if (form.length < 3) continue;
      const relation = latinRelation(target, form);
      if (rank[relation] > rank[best.relation]) {
        best = { matched: true, hostForm: form, relation };
      }
    }
    return best;
  }

  /**
   * 页面选举出的完整产品名可由其中文品牌核完成域名反证。
   * 例：「汽水音乐」的「汽水」⇄ qishui 命中后，展示仍保留「汽水音乐」。
   * 这里只识别通用产品形态尾，不维护任何厂商品牌名单。
   */
  function displayCandidateAfterStemMatch(candidate, matchedStem) {
    const full = String(candidate || "");
    const stem = String(matchedStem || "");
    if (!full || !stem || full === stem) return stem || full;
    if (!full.startsWith(stem) || stem.length < 2) return stem;
    const tail = full.slice(stem.length);
    if (/^(?:(?:云)?音乐|浏览器|播放器|输入法|客户端|安全|安全卫士|杀毒软件|网盘|云盘|办公套件|助手|管家|邮箱|地图|视频|直播|阅读|游戏|空间)$/u.test(tail)) {
      return full;
    }
    return stem;
  }

  /**
   * 中文候选 vs 主机：pinyin 双向校验，选出展示品牌。
   * @returns {{ brand: string, pinyin: string, score: number }}
   */
  NS.alignChineseBrandToHostBg = function (host, candidates, strongCandidatesOpt) {
    const empty = { brand: "", pinyin: "", hostForm: "", relation: "none", score: -1 };
    try {
      if (!ensurePinyin()) return empty;
      const list = Array.isArray(candidates) ? candidates : [];
      const strongSet = new Set((Array.isArray(strongCandidatesOpt) ? strongCandidatesOpt : [])
        .map((s) => String(s || "").replace(/[^\u4e00-\u9fff]/g, ""))
        .filter((s) => s.length >= 2 && s.length <= 8));
      let best = empty;
      const seen = Object.create(null);
      for (let i = 0; i < Math.min(list.length, 64); i++) {
        let cn = String(list[i] || "").trim();
        if (!cn || !/[\u4e00-\u9fff]/.test(cn)) continue;
        cn = cn.replace(/[^\u4e00-\u9fff]/g, "");
        if (cn.length < 2 || cn.length > 8) continue;
        if (isWeakCn(cn) || seen[cn]) continue;
        seen[cn] = 1;
        const strongCandidate = strongSet.has(cn);
        const variants = [cn];
        for (let prefixLen = 2; prefixLen <= Math.min(4, cn.length - 1); prefixLen++) {
          variants.push(cn.slice(0, prefixLen));
        }
        for (let vi = 0; vi < variants.length; vi++) {
          const v = variants[vi];
          if (isWeakCn(v)) continue;
          const py = NS.brandPinyinBg(v);
          const match = matchPinyinToHost(py, host, { allowLongAffix: strongCandidate });
          if (!match.matched) continue;
          let score = 50;
          if (match.relation === "exact") score = 100;
          else if (match.relation === "typo") score = 90;
          else if (match.relation === "host-affix" || match.relation === "brand-affix") score = 80;
          if (v.length === 2) score += 12;
          const displayBrand = strongCandidate
            ? displayCandidateAfterStemMatch(cn, v)
            : v;
          // 完整页面产品名通过其品牌核完成双向确认，比同分的二字窗口优先。
          if (displayBrand === cn && v !== cn) score += 8;
          if (score > best.score) {
            best = {
              brand: displayBrand,
              matchedChinese: v,
              pinyin: py,
              hostForm: match.hostForm,
              relation: match.relation,
              score
            };
          }
        }
      }
      return best.score >= 0 ? best : empty;
    } catch {
      return empty;
    }
  };

  NS.brandPinyinBatchBg = function (texts) {
    const arr = Array.isArray(texts) ? texts : [];
    const out = [];
    for (let i = 0; i < Math.min(arr.length, 32); i++) {
      const t = String(arr[i] || "");
      out.push({ text: t, pinyin: NS.brandPinyinBg(t) });
    }
    return out;
  };
})(self.SilverfoxBackground ??= {});
