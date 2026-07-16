/**
 * 用户手势追踪（同文档激活窗口 + 跨文档 SSO 链）。
 * 持有 gestureAt 内存态，sessionStorage 跨跳桥接。
 */
;(function (NS) {
  "use strict";

  /** 同文档用户激活窗口。 */
  const GESTURE_MS = 2500;
  /** 真实点击后的跨文档链（SAML/SSO 多跳）；整页跳转清空内存，sessionStorage 在同标签页桥接。 */
  const CHAIN_GESTURE_MS = 20000;
  const GESTURE_SS_KEY = "__silverfox_ug_at";

  class GestureTracker {
    constructor() {
      this.gestureAt = 0;
      this._installListeners();
    }

    persistGestureAt(ts) {
      try {
        sessionStorage.setItem(GESTURE_SS_KEY, String(ts));
      } catch { /* 私密模式 / 受限存储 */ }
    }

    readChainGestureAt() {
      try {
        const n = parseInt(sessionStorage.getItem(GESTURE_SS_KEY) || "0", 10);
        return Number.isFinite(n) ? n : 0;
      } catch {
        return 0;
      }
    }

    markGesture(e) {
      try {
        if (e && e.isTrusted === false) return;
        if (e && typeof e.button === "number" && e.button !== 0) return; // 右键非主激活
        this.gestureAt = Date.now();
        // keydown 不写 sessionStorage -- 搜索框每次按键都会抖动存储
        const t = e && e.type;
        if (t !== "keydown") this.persistGestureAt(this.gestureAt);
      } catch {
        this.gestureAt = Date.now();
      }
    }

    /** 当前是否有有效用户手势（含 navigator.userActivation 与跨文档链）。 */
    hasGesture() {
      try {
        if (navigator.userActivation && navigator.userActivation.isActive) return true;
      } catch { /* ignore */ }
      const now = Date.now();
      if (now - this.gestureAt < GESTURE_MS) return true;
      const chainAt = this.readChainGestureAt();
      if (chainAt > 0 && now - chainAt < CHAIN_GESTURE_MS) return true;
      return false;
    }

    _installListeners() {
      try {
        const opts = { capture: true, passive: true };
        for (const t of ["pointerdown", "mousedown", "click", "touchstart"]) {
          window.addEventListener(t, (e) => this.markGesture(e), opts);
          document.addEventListener(t, (e) => this.markGesture(e), opts);
        }
        // keydown：仅内存、仅 window（不 document ×2）
        window.addEventListener("keydown", (e) => this.markGesture(e), opts);
      } catch { /* ignore */ }
    }
  }

  NS.GestureTracker = GestureTracker;
})(window.SilverfoxNavBoot ??= {});
