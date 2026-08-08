/**
 * VirusTotal MAIN-world 钩子：在 SPA 发起 /ui/files 请求时截获响应体。
 * run_at: document_start，保证先于页面脚本安装。
 * 扩展后台打开 gui/file/{hash} 后读取 window.__sfVtCapture / __sfVtCaptures。
 */
;(function () {
  "use strict";
  try {
    if (window.__sfVtHookBoot) return;
    window.__sfVtHookBoot = true;
    window.__sfVtCapture = null;
    window.__sfVtCaptureStatus = 0;
    window.__sfVtCaptureUrl = "";
    window.__sfVtCaptures = window.__sfVtCaptures || {};

    const interestingUrl = (u) => {
      const s = String(u || "");
      // 文件报告、分析、搜索、行为摘要等都可能带 last_analysis_stats
      return /\/ui\/files\//i.test(s)
        || /\/ui\/file_behaviours\//i.test(s)
        || /\/ui\/analyses\//i.test(s)
        || (/\/ui\/search/i.test(s) && /query=/i.test(s));
    };

    const capture = (url, status, body) => {
      try {
        const u = String(url || "");
        if (!interestingUrl(u)) return;
        const text = String(body || "");
        if (text.length < 2) return;
        // captcha 体也记下，便于后台区分「被拦」与「无数据」
        window.__sfVtCapture = text.slice(0, 800000);
        window.__sfVtCaptureStatus = status || 0;
        window.__sfVtCaptureUrl = u;
        const m = u.match(/\/ui\/files\/([a-f0-9]{64})/i)
          || text.match(/"sha256"\s*:\s*"([a-f0-9]{64})"/i)
          || text.match(/"id"\s*:\s*"([a-f0-9]{64})"/i);
        if (m) {
          const key = m[1].toLowerCase();
          const prev = window.__sfVtCaptures[key];
          // 优先保留含 stats 的响应，避免被后续 captcha/空壳覆盖
          const preferNew = !prev || !prev.text
            || (/last_analysis_stats|"malicious"\s*:\s*\d+/i.test(text)
              && !/last_analysis_stats|"malicious"\s*:\s*\d+/i.test(String(prev.text || "")))
            || text.length >= String(prev.text || "").length;
          if (preferNew) {
            window.__sfVtCaptures[key] = {
              text: text.slice(0, 800000),
              status: status || 0,
              at: Date.now(),
              url: u.slice(0, 500)
            };
          }
        }
      } catch { /* ignore */ }
    };

    const ofetch = window.fetch;
    if (typeof ofetch === "function" && !ofetch.__sfVtWrapped) {
      const wrapped = function () {
        const args = arguments;
        let url = "";
        try {
          const a0 = args[0];
          url = typeof a0 === "string" ? a0 : (a0 && a0.url) ? a0.url : String(a0 || "");
        } catch { url = ""; }
        // 只旁路截获，不吞页面错误、不改 reject 语义
        return ofetch.apply(this, args).then((res) => {
          try {
            if (interestingUrl(url) || interestingUrl(res && res.url)) {
              const c = res.clone();
              c.text().then((t) => capture(url || (res && res.url), res.status, t)).catch(() => {});
            }
          } catch { /* ignore */ }
          return res;
        }, (err) => {
          throw err;
        });
      };
      wrapped.__sfVtWrapped = true;
      window.fetch = wrapped;
    }

    const XO = window.XMLHttpRequest;
    if (XO && XO.prototype) {
      const open = XO.prototype.open;
      const send = XO.prototype.send;
      XO.prototype.open = function (method, url) {
        try { this.__sfVtUrl = url; } catch { /* ignore */ }
        return open.apply(this, arguments);
      };
      XO.prototype.send = function () {
        try {
          this.addEventListener("load", function () {
            try {
              capture(this.__sfVtUrl, this.status, this.responseText);
            } catch { /* ignore */ }
          });
        } catch { /* ignore */ }
        return send.apply(this, arguments);
      };
    }
  } catch { /* ignore */ }
})();
