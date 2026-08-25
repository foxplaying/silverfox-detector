/**
 * VirusTotal MAIN-world 钩子：仅截获 SPA 的目标文件根报告 /ui/files/{sha256}。
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
    window.__sfVtCaptureQuality = -1;
    window.__sfVtCaptures = window.__sfVtCaptures || {};

    const fileReportHashFromUrl = (u) => {
      try {
        const parsed = new URL(String(u || ""), location.origin);
        const match = parsed.pathname.match(/^\/ui\/files\/([a-f0-9]{64})\/?$/i);
        return match ? match[1].toLowerCase() : "";
      } catch {
        return "";
      }
    };

    const interestingUrl = (u) => !!fileReportHashFromUrl(u);

    const captureQuality = (text, key) => {
      const s = String(text || "");
      const targetIdentity = new RegExp('"(?:sha256|id)"\\s*:\\s*"' + key + '"', "i").test(s);
      const hasStats = /"last_analysis_stats"\s*:\s*\{|"malicious"\s*:\s*\d+/i.test(s);
      if (targetIdentity && hasStats) return 5;
      if (/NotFoundError|Item not found/i.test(s)) return 4;
      if (targetIdentity) return 3;
      if (/RecaptchaRequired|captcha|verify (?:that )?you are human/i.test(s)) return 0;
      return 1;
    };

    const capture = (url, status, body) => {
      try {
        const u = String(url || "");
        const key = fileReportHashFromUrl(u);
        if (!key) return;
        const text = String(body || "");
        if (text.length < 2) return;
        if (key) {
          const prev = window.__sfVtCaptures[key];
          const quality = captureQuality(text, key);
          const previousQuality = prev && Number.isFinite(Number(prev.quality))
            ? Number(prev.quality)
            : captureQuality(prev && prev.text, key);
          // 质量优先：目标 hash 的报告 > 明确 NotFound > 元数据 > 空壳 > captcha。
          const preferNew = !prev || !prev.text || quality > previousQuality
            || (quality === previousQuality && text.length >= String(prev.text || "").length);
          if (preferNew) {
            window.__sfVtCapture = text.slice(0, 800000);
            window.__sfVtCaptureStatus = status || 0;
            window.__sfVtCaptureUrl = u;
            window.__sfVtCaptureQuality = quality;
            window.__sfVtCaptures[key] = {
              text: text.slice(0, 800000),
              status: status || 0,
              at: Date.now(),
              url: u.slice(0, 500),
              quality
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
              const captureUrl = interestingUrl(url) ? url : (res && res.url);
              c.text().then((t) => capture(captureUrl, res.status, t)).catch(() => {});
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
