// Both extension worlds can lock the same DOM control. Keep one pre-lock
// snapshot on the element so either world can perform the final restoration.
;(function () {
  "use strict";
  const key = "silverfoxControlBefore";
  const locked = { "pointer-events": "none", opacity: "0.45", filter: "grayscale(0.6)", cursor: "not-allowed" };
  globalThis.SilverfoxControlState = {
    capture(el) {
      if (el.dataset[key]) return;
      const styles = {};
      for (const name of Object.keys(locked)) styles[name] = [
        el.style.getPropertyValue(name), el.style.getPropertyPriority(name)
      ];
      el.dataset[key] = JSON.stringify({ styles, disabled: el.disabled === true,
        aria: el.getAttribute("aria-disabled"), title: el.getAttribute("title") });
    },
    restore(el) {
      const raw = el.dataset[key];
      if (!raw) return false;
      delete el.dataset[key];
      try {
        const saved = JSON.parse(raw);
        for (const name of Object.keys(locked)) {
          if (el.style.getPropertyValue(name) !== locked[name] || el.style.getPropertyPriority(name) !== "important") continue;
          const [value, priority] = saved.styles[name];
          if (value) el.style.setProperty(name, value, priority);
          else el.style.removeProperty(name);
        }
        if (/^(BUTTON|INPUT)$/.test(el.tagName) && el.disabled) el.disabled = saved.disabled === true;
        for (const [name, held, value] of [["aria-disabled", "true", saved.aria], ["title", "已拦截可疑安装包下载", saved.title]]) {
          if (el.getAttribute(name) !== held) continue;
          if (value == null) el.removeAttribute(name); else el.setAttribute(name, value);
        }
        return true;
      } catch { return false; }
    }
  };
})();
