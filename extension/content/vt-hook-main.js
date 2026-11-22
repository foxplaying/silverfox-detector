/** Capture only the current VT file's structured root report, never related files. */
;(function () {
  "use strict";
  if (window.__sfVtHookBoot) return;
  window.__sfVtHookBoot = true;
  window.__sfVtCaptures = Object.create(null);

  function endpointHash(url) {
    try {
      const u = new URL(url, location.origin);
      if (u.protocol !== "https:" || u.hostname !== "www.virustotal.com") return "";
      return (u.pathname.match(/^\/ui\/files\/([a-f0-9]{64})\/?$/i) || [])[1]?.toLowerCase() || "";
    } catch { return ""; }
  }

  function capture(requestUrl, responseUrl, status, text) {
    try {
      const hash = endpointHash(requestUrl);
      const current = (location.pathname.match(/^\/gui\/file\/([a-f0-9]{64})(?:\/|$)/i) || [])[1];
      if (!hash || !current || current.toLowerCase() !== hash || endpointHash(responseUrl) !== hash) return;
      const body = JSON.parse(text);
      const node = body && body.data;
      let quality = 0;
      if (node && node.attributes && (!node.type || node.type === "file")) {
        const ids = [node.id, node.attributes.sha256].filter((v) => v != null && v !== "");
        if (!ids.length || !ids.every((v) => String(v).toLowerCase() === hash)) return;
        quality = node.attributes.last_analysis_stats ? 2 : 1;
      } else if (body && body.error && body.error.code === "NotFoundError") {
        quality = 1;
      } else return;
      const previous = window.__sfVtCaptures[hash];
      if (previous && previous.quality > quality) return;
      // Keep JSON intact; truncation previously forced unbound text/DOM fallbacks.
      window.__sfVtCaptures = { [hash]: { text: JSON.stringify(body), status, url: responseUrl,
        at: Date.now(), quality } };
    } catch { /* Invalid or unrelated responses are not evidence. */ }
  }

  const originalFetch = window.fetch;
  if (typeof originalFetch === "function") {
    window.fetch = function (...args) {
      const url = typeof args[0] === "string" ? args[0] : args[0]?.url || String(args[0] || "");
      return originalFetch.apply(this, args).then((response) => {
        if (endpointHash(url) && endpointHash(response.url)) {
          try { response.clone().text().then((text) => capture(url, response.url, response.status, text)).catch(() => {}); }
          catch { /* ignore */ }
        }
        return response;
      });
    };
  }
  const proto = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (proto) {
    const open = proto.open;
    const send = proto.send;
    proto.open = function (method, url) {
      this.__sfVtUrl = url;
      return open.apply(this, arguments);
    };
    proto.send = function () {
      this.addEventListener("load", function () {
        try { capture(this.__sfVtUrl, this.responseURL, this.status, this.responseText); } catch { /* ignore */ }
      }, { once: true });
      return send.apply(this, arguments);
    };
  }
})();
