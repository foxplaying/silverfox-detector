/**
 * VirusTotal MAIN-world 钩子：在 SPA 发起 /ui/files 请求时截获响应体。
 * run_at: document_start，保证先于页面脚本安装。
 * 扩展后台打开 gui/file/{hash} 后读取 window.__sfVtCapture。
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

    const capture = (url, status, body) => {
      try {
        const u = String(url || "");
        if (!/\/ui\/files\/[a-f0-9]{64}/i.test(u) && !/\/ui\/files\/[a-f0-9]{64}/i.test(u.split("?")[0])) {
          // 也接受 path 中带 hash
          if (!/\/ui\/files\//i.test(u)) return;
        }
        const text = String(body || "");
        if (text.length < 2) return;
        window.__sfVtCapture = text.slice(0, 800000);
        window.__sfVtCaptureStatus = status || 0;
        window.__sfVtCaptureUrl = u;
        const m = u.match(/\/ui\/files\/([a-f0-9]{64})/i);
        if (m) {
          window.__sfVtCaptures[m[1].toLowerCase()] = {
            text: text.slice(0, 800000),
            status: status || 0,
            at: Date.now()
          };
        }
      } catch { /* ignore */ }
    };

    const ofetch = window.fetch;
    if (typeof ofetch === "function") {
      window.fetch = function () {
        const args = arguments;
        let url = "";
        try {
          const a0 = args[0];
          url = typeof a0 === "string" ? a0 : (a0 && a0.url) ? a0.url : String(a0 || "");
        } catch { url = ""; }
        // 只旁路截获 /ui/files，不吞页面错误、不改 reject 语义
        return ofetch.apply(this, args).then((res) => {
          try {
            if (/\/ui\/files\//i.test(url)) {
              const c = res.clone();
              c.text().then((t) => capture(url, res.status, t)).catch(() => {});
            }
          } catch { /* ignore */ }
          return res;
        }, (err) => {
          // 原样抛出，避免 Unhandled rejection 归因到扩展
          throw err;
        });
      };
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
