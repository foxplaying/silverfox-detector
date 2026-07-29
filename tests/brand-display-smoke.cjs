const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const sources = [
  "extension/content/brand-heuristics.js",
  "extension/content/brand-correlation.js"
].map((file) => fs.readFileSync(path.join(root, file), "utf8"));

function analyze(host, identity) {
  const document = {
    title: identity.title || "",
    body: null,
    documentElement: { innerHTML: "" },
    querySelector: () => null,
    querySelectorAll: () => []
  };
  const context = {
    window: {},
    document,
    location: {
      href: `https://${host}/`,
      hostname: host,
      pathname: "/",
      search: ""
    },
    URL,
    Date,
    console,
    setTimeout,
    clearTimeout
  };
  vm.createContext(context);
  for (const source of sources) vm.runInContext(source, context);

  const ns = context.window.SilverfoxContent;
  ns.caches = {};
  ns.collectProductBrandIdentityFields = () => ({
    title: "", h1: "", h2: "", headings: "", description: "", keywords: "",
    footer: "", logo: "", span: "", ogTitle: "", ogDescription: "",
    ogImageAlt: "", ogSite: "", twitterTitle: "", twitterDescription: "",
    twitterImageAlt: "", author: "", schemaName: "", ...identity
  });
  return { ns, result: ns.collectPrimaryBrandKeywords() };
}

{
  const { ns, result } = analyze("app.wps-xlsx.com.cn", {
    title: "WPS官网 - WPS Office 免费办公软件下载",
    h1: "WPS Office",
    description: "WPS Office 提供文字、表格、演示和 PDF 工具",
    keywords: "WPS,WPS Office,XLSX,表格",
    ogTitle: "WPS Office",
    ogSite: "WPS Office"
  });
  assert.equal(result.display, "WPS");
  assert.ok(result.latin.includes("wps"));
  assert.equal(ns.formatBrandTokenForDisplay("wps"), "WPS");
  assert.equal(ns.looksLikeAssetGarbageToken("B1图标"), true);
  assert.equal(ns.resolveSpoofDisplayBrand("app.wps-xlsx.com.cn"), "WPS");
  assert.equal(ns.evaluateDomainKeywordRelevance("app.wps-xlsx.com.cn").brand, "WPS");
}

{
  const { ns, result } = analyze("web.wps-leading.com.cn", {
    title: "WPS中文官网 - 免费办公软件下载",
    h1: "WPS中文",
    description: "WPS中文办公软件，支持文档、表格与演示",
    ogTitle: "WPS中文"
  });
  assert.equal(result.display, "WPS");
  assert.equal(ns.resolveSpoofDisplayBrand("web.wps-leading.com.cn"), "WPS");
  assert.equal(ns.evaluateDomainKeywordRelevance("web.wps-leading.com.cn").brand, "WPS");
}

{
  const { ns, result } = analyze("wpsxls.com.cn", {
    title: "PDF编辑 - WPS Office 免费办公软件",
    h1: "WPS Office",
    description: "使用 WPS 编辑 PDF、文字和表格",
    keywords: "WPS,PDF编辑,PDF工具",
    ogTitle: "WPS Office"
  });
  assert.equal(result.display, "WPS");
  // PDF 可以留在候选池，但跨字段和域名证据不足，不能抢占真实品牌。
  assert.ok(result.latin.includes("pdf"));
  assert.equal(ns.resolveSpoofDisplayBrand("wpsxls.com.cn"), "WPS");
  assert.equal(ns.evaluateDomainKeywordRelevance("wpsxls.com.cn").brand, "WPS");
}

{
  const currentYear = new Date().getFullYear();
  const { ns, result } = analyze("kingsoft-wps.com", {
    title: `WPS下载 - ${currentYear}最新版免费正版办公软件下载`,
    h1: `WPS Office ${currentYear}最新`,
    h2: `${currentYear}最新版本`,
    description: `${currentYear}最新版 WPS 提供免费正版办公软件下载`,
    keywords: `WPS办公软件,${currentYear}最新,免费办公软件下载`,
    ogTitle: `WPS下载 - ${currentYear}最新版`,
    ogDescription: `${currentYear}最新版 WPS 办公软件`,
    footer: `© ${currentYear} WPS 办公软件，保留所有权利`
  });
  assert.equal(ns.isWeakChineseBrandToken(`${currentYear}最新`), true);
  assert.equal(ns.normalizeDisplayBrandName(`${currentYear}最新`), "");
  assert.equal(result.display, "WPS");
  assert.equal(ns.resolveSpoofDisplayBrand("kingsoft-wps.com"), "WPS");
  assert.equal(ns.evaluateDomainKeywordRelevance("kingsoft-wps.com").brand, "WPS");
}

{
  const nextYear = new Date().getFullYear() + 1;
  for (const acronym of ["NXT", "QRS", "ZKM"]) {
    const host = `${acronym.toLowerCase()}-suite.example`;
    const { ns, result } = analyze(host, {
      title: `PDF编辑 - ${acronym}中文 ${nextYear}特别版`,
      h1: `${acronym}中文`,
      description: `${acronym}中文提供文档与表格处理能力`,
      keywords: `PDF编辑,${acronym}中文,${nextYear}特别版`,
      ogTitle: `${acronym}中文`
    });
    assert.equal(ns.isWeakChineseBrandToken(`${nextYear}特别版`), true);
    assert.equal(result.display, acronym);
    assert.equal(ns.resolveSpoofDisplayBrand(host), acronym);
  }
}

{
  const { result } = analyze("qq-musics.com.cn", {
    title: "QQ音乐官网 - 听我想听",
    h1: "QQ音乐",
    description: "QQ音乐提供歌曲播放和客户端下载",
    ogTitle: "QQ音乐"
  });
  assert.equal(result.display, "QQ音乐");
}

{
  const { ns, result } = analyze("qishuiyinyuer.com.cn", {
    title: "汽水音乐官方下载",
    h1: "汽水音乐",
    description: "汽水音乐官方客户端，提供正版歌曲与音乐播放服务",
    keywords: "汽水音乐,音乐播放器",
    ogTitle: "汽水音乐"
  });
  assert.equal(result.display, "汽水音乐");
  const typo = ns.detectChineseProductRomanizedSuffixTypo("汽水音乐", "qishuiyinyuer");
  assert.equal(typo.expectedSuffix, "yinyue");
  assert.equal(typo.actualSuffix, "yinyuer");
  assert.equal(typo.expectedHostLabel, "qishuiyinyue");
  assert.equal(ns.detectChineseProductRomanizedSuffixTypo("汽水音乐", "qishuiyinyue"), null);
  assert.equal(ns.evaluateDomainKeywordRelevance("qishuiyinyuer.com.cn").hostMatch, "typo");
  assert.equal(ns.evaluateDomainKeywordRelevance("qishuiyinyuer.com.cn").squat, true);
}

{
  const { ns, result } = analyze("qishuiyinyuer.com.cn", {
    title: "汽水音乐 - Hi-Res无损音质",
    h1: "Hi-Res无损音质",
    h2: "汽水音乐",
    description: "汽水音乐提供 Hi-Res无损音质和正版歌曲播放",
    keywords: "Hi-Res无损音质,汽水音乐,音乐播放器",
    ogTitle: "Hi-Res无损音质",
    ogDescription: "汽水音乐，畅享 Hi-Res无损音质",
    schemaName: "汽水音乐",
    footer: "© 2026 汽水音乐"
  });
  assert.equal(ns.looksLikeMediaFeatureClaimToken("Res无损音质"), true);
  assert.equal(ns.isWeakChineseBrandToken("Res无损音质"), true);
  assert.equal(result.display, "汽水音乐");
  assert.equal(ns.evaluateDomainKeywordRelevance("qishuiyinyuer.com.cn").brand, "汽水音乐");
}

{
  const { ns, result } = analyze("qishuiyinyuer.com.cn", {
    title: "汽水音乐 - AI智能推荐",
    h1: "AI智能推荐",
    h2: "汽水音乐",
    description: "汽水音乐通过 AI智能推荐发现更多正版歌曲",
    keywords: "AI智能推荐,汽水音乐,音乐播放器",
    ogTitle: "AI智能推荐",
    ogDescription: "汽水音乐 AI智能推荐",
    schemaName: "汽水音乐",
    footer: "© 2026 汽水音乐"
  });
  assert.equal(ns.looksLikeFunctionalClaimBrandToken("AI智能推荐"), true);
  assert.equal(ns.isWeakChineseBrandToken("AI智能推荐"), true);
  assert.equal(ns.looksLikeChineseProductBrandMorphology("AI智能推荐"), false);
  assert.equal(ns.looksLikeFunctionalClaimBrandToken("PDF智能编辑"), true);
  assert.equal(ns.looksLikeFunctionalClaimBrandToken("QQ音乐"), false);
  assert.equal(result.display, "汽水音乐");
  assert.equal(ns.evaluateDomainKeywordRelevance("qishuiyinyuer.com.cn").brand, "汽水音乐");
}

{
  const { ns, result } = analyze("www.cn-qishui.com", {
    title: "PC版下载 - 汽水音乐下载",
    h1: "汽水音乐",
    h2: "功能亮点",
    description: "汽水音乐PC版，畅享无损高品质音乐体验",
    keywords: "PC版,汽水音乐,音乐下载",
    ogTitle: "PC版下载 - 汽水音乐下载",
    ogDescription: "下载汽水音乐 PC 版",
    ogImageAlt: "汽水音乐应用预览",
    schemaName: "汽水音乐",
    footer: "2025 © 抖音 | 汽水音乐"
  });
  for (const label of ["PC版", "Windows版", "x64版", "桌面版", "手机版", "安卓版", "iOS版", "64位"]) {
    assert.equal(ns.looksLikePlatformEditionLabel(label), true, label);
    assert.equal(ns.isWeakChineseBrandToken(label), true, label);
  }
  assert.equal(ns.looksLikeChineseProductBrandMorphology("PC版"), false);
  assert.equal(result.display, "汽水音乐");
  assert.equal(ns.evaluateDomainKeywordRelevance("www.cn-qishui.com").brand, "汽水音乐");
}

{
  const { ns, result } = analyze("xinghebofangqii.example", {
    title: "星河播放器 - Ultra-HD高清画质",
    h1: "Ultra-HD高清画质",
    description: "星河播放器提供 Ultra-HD高清画质和流畅播放",
    ogTitle: "星河播放器",
    schemaName: "星河播放器"
  });
  assert.equal(ns.looksLikeMediaFeatureClaimToken("HD高清画质"), true);
  assert.equal(result.display, "星河播放器");
}

{
  const { ns } = analyze("xingheliulanqii.example", {
    title: "星河浏览器官方网站",
    h1: "星河浏览器",
    description: "星河浏览器官方客户端下载",
    ogTitle: "星河浏览器"
  });
  const typo = ns.detectChineseProductRomanizedSuffixTypo("星河浏览器", "xingheliulanqii");
  assert.equal(typo.expectedSuffix, "liulanqi");
  assert.equal(typo.distance, 1);
}

{
  const { result } = analyze("ca-huorong.com.cn", {
    title: "火绒安全官网 - 免费杀毒软件下载",
    h1: "火绒安全",
    description: "火绒安全提供终端防护和病毒查杀",
    ogTitle: "火绒安全"
  });
  assert.equal(result.display, "火绒安全");
}

{
  const { ns, result } = analyze("www.hr-huorong.hl.cn", {
    title: "火绒官网-正版火绒安全下载_火绒最新版_火绒杀毒软件免费安装",
    h1: "火绒安全 纯净守护",
    h2: "智能查杀 纯净守护",
    description: "火绒官网提供火绒安全软件正版免费下载。火绒杀毒引擎轻巧高效，火绒系统防护可实时守护电脑安全。",
    keywords: "火绒官网,火绒最新版,火绒安全下载,火绒杀毒,火绒防护软件,火绒安全中心",
    logo: "火绒安全 PURE SHIELD",
    span: "火绒安全 PURE SHIELD 纯净守护",
    footer: "火绒安全 PURE SHIELD 火绒安全软件专注纯净安全体验"
  });
  assert.equal(ns.looksLikeAssetGarbageToken("火绒安全"), false);
  assert.equal(ns.looksLikeAssetGarbageToken("汽水音乐"), false);
  assert.equal(result.latin.includes("shield"), false);
  assert.equal(result.display, "火绒安全");
  assert.equal(ns.resolveSpoofDisplayBrand("www.hr-huorong.hl.cn", result), "火绒安全");
  assert.equal(ns.evaluateDomainKeywordRelevance("www.hr-huorong.hl.cn").brand, "火绒安全");
}

{
  const { ns, result } = analyze("360weishi-360.com.cn", {
    title: "360安全卫士下载中心-官方正版最新下载",
    h1: "360安全卫士 Windows版",
    description: "360安全卫士官方下载，永久免费，提供病毒查杀与系统加速",
    ogTitle: "360安全卫士下载中心",
    footer: "© 2026 360安全卫士"
  });
  assert.deepEqual(Array.from(ns.collectHostBrandCores("360weishi-360.com.cn").digits), ["360"]);
  assert.equal(ns.isRepeatedNumericBrandToken("360360"), true);
  assert.equal(ns.normalizeDisplayBrandName("360360"), "");
  assert.equal(result.display, "360安全卫士");
  assert.equal(ns.resolveSpoofDisplayBrand("360weishi-360.com.cn"), "360安全卫士");
  assert.equal(ns.evaluateDomainKeywordRelevance("360weishi-360.com.cn").brand, "360安全卫士");
}

{
  const { ns, result } = analyze("789guard-789.example", {
    title: "789安全卫士官方下载",
    h1: "789安全卫士",
    description: "789安全卫士提供终端防护功能",
    ogTitle: "789安全卫士"
  });
  assert.deepEqual(Array.from(ns.collectHostBrandCores("789guard-789.example").digits), ["789"]);
  assert.equal(result.display, "789安全卫士");
}

console.log("brand display smoke tests passed");
