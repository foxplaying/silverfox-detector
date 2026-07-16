/**
 * Location / window.open / Navigation API 原型级拦截（纯静态）。
 * 必须在页面脚本首次访问 Location 前完成 patch（document_start MAIN 注入保证）。
 */
;(function (NS) {
  "use strict";

  const { PackageClassifier } = NS;

  class LocationGuard {
    /** patch Location.prototype.assign/replace/href，命中拦截则吞掉跳转。 */
    static patchLoc(proto, blocker) {
      if (!proto || proto.__silverfoxBootLoc) return;
      proto.__silverfoxBootLoc = true;
      try {
        const oa = proto.assign;
        if (oa) {
          proto.assign = function (u) {
            if (blocker.tryBlock(u, "boot-assign")) return undefined;
            return oa.call(this, u);
          };
        }
      } catch { /* ignore */ }
      try {
        const or = proto.replace;
        if (or) {
          proto.replace = function (u) {
            if (blocker.tryBlock(u, "boot-replace")) return undefined;
            return or.call(this, u);
          };
        }
      } catch { /* ignore */ }
      try {
        const desc = Object.getOwnPropertyDescriptor(proto, "href");
        if (desc && desc.set) {
          Object.defineProperty(proto, "href", {
            configurable: true,
            enumerable: true,
            get() { return desc.get.call(this); },
            set(v) {
              if (blocker.tryBlock(v, "boot-href")) return;
              return desc.set.call(this, v);
            }
          });
        }
      } catch { /* ignore */ }
    }

    /** patch window.open。 */
    static patchWindowOpen(blocker) {
      try {
        const oo = window.open;
        if (oo) {
          window.open = function (u, ...r) {
            if (u != null && u !== "" && blocker.tryBlock(u, "boot-open")) return null;
            return oo.apply(this, [u, ...r]);
          };
        }
      } catch { /* ignore */ }
    }

    /** Navigation API：无手势时取消/拦截 navigate 事件。 */
    static patchNavigation(gesture, blocker) {
      try {
        if (typeof navigation !== "undefined" && navigation.addEventListener) {
          navigation.addEventListener("navigate", (e) => {
            try {
              if (gesture.hasGesture()) return;
              const dest = e.destination && e.destination.url;
              if (!dest || !blocker.shouldBlock(dest)) return;
              if (e.cancelable) e.preventDefault();
              if (e.canIntercept) e.intercept({ handler() { /* swallow */ } });
              blocker.tryBlock(dest, "boot-navigate-event");
            } catch { /* ignore */ }
          });
        }
      } catch { /* ignore */ }
    }
  }

  NS.LocationGuard = LocationGuard;
  // 便于 index.js 直接取用
  void PackageClassifier;
})(window.SilverfoxNavBoot ??= {});
