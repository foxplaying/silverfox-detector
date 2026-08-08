/**
 * vendor 桥：把 pinyin-pro / tldts 挂到 globalThis，供 content 脚本使用。
 * 须在 pinyin-pro.umd.js 与 tldts.umd.min.js 之后加载。
 */
;(function (g) {
  "use strict";
  try {
    if (g.pinyinPro && !g.__silverfoxPinyinPro) g.__silverfoxPinyinPro = g.pinyinPro;
  } catch (e) { /* ignore */ }
  try {
    if (g.tldts && !g.__silverfoxTldts) g.__silverfoxTldts = g.tldts;
  } catch (e) { /* ignore */ }
})(typeof globalThis !== "undefined" ? globalThis : this);
