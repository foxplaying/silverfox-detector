/**
 * 包文件名 / URL 形态分类器（纯静态工具，无状态）。
 * 供 nav-boot 其余模块与 MAIN-world 拦截策略复用。
 */
;(function (NS) {
  "use strict";

  /** 安装包扩展名（含查询/锚点边界）。 */
  const PKG = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i;

  class PackageClassifier {
    static PKG = PKG;

    /** 把任意 URL/字符串/Location 统一成 href 字符串。 */
    static hrefOf(u) {
      if (u == null) return "";
      if (typeof u === "string") return u;
      try {
        if (typeof URL !== "undefined" && u instanceof URL) return u.href;
      } catch { /* ignore */ }
      try {
        if (u && typeof u.href === "string") return u.href;
      } catch { /* ignore */ }
      return String(u);
    }

    /** 是否为安装包 URL（含 ?filename= 等查询参数形态）。 */
    static isPkg(h) {
      try {
        const u = new URL(h, location.href);
        if (PKG.test(u.pathname) || PKG.test(u.href)) return true;
        for (const k of ["filename", "file", "name", "downurl", "downloadurl"]) {
          const v = u.searchParams.get(k) || "";
          if (PKG.test(v)) return true;
        }
      } catch {
        if (PKG.test(h)) return true;
      }
      return false;
    }

    /** 强产品安装包（Brand_official_setup_2.6.3.0.exe 等），任何 CDN 路径都放行。 */
    static isStrongProductPkg(h) {
      try {
        let name = "";
        try {
          const u = new URL(h, location.href);
          name = (u.pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
        } catch {
          name = String(h || "").split("?")[0].split("/").pop() || "";
        }
        try { name = decodeURIComponent(name).trim(); } catch { name = String(name || "").trim(); }
        if (!name) return false;
        const base = name.replace(/\.(apk|xapk|apks|aab|exe|zip|msi|dmg|pkg|rar|7z|appx)$/i, "");
        if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base)
          && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base))) {
          return true;
        }
        // 短 CDN stub
        if (/^(?:inst|setup|install|installer|update|upgrade|patch|down|download|soft|client|package|pkg|release|stable|official|online|full|mini|lite|web|get|run|start|main|core|base|app)$/i.test(base)) {
          return true;
        }
        // Android 反向域名 APK
        if (/^(?:[a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*(?:[._-]\d{2,16})?$/i.test(base)) return true;
        // 应用商店 / CDN 内容寻址哈希（MD5/SHA；或 资源号_哈希.exe）
        if (/^[a-f0-9]{16,64}$/i.test(base)) return true;
        if (/^\d{4,20}[._-][a-f0-9]{16,64}$/i.test(base)) return true;
        if (/^[a-f0-9]{16,64}[._-]\d{4,20}$/i.test(base)) return true;
        return false;
      } catch {
        return false;
      }
    }

    /** 可读产品 / Android 包名（非乱码恶意文件）。 */
    static isClearProductPkg(h) {
      try {
        if (PackageClassifier.isStrongProductPkg(h)) return true;
        let name = "";
        try {
          const u = new URL(h, location.href);
          name = (u.pathname.split("/").filter(Boolean).pop() || "").split("?")[0];
        } catch {
          name = String(h || "").split("?")[0].split("/").pop() || "";
        }
        try { name = decodeURIComponent(name).trim(); } catch { name = String(name || "").trim(); }
        if (!name) return false;
        const base = name.replace(/\.(apk|xapk|apks|aab|exe|zip|msi|dmg|pkg|rar|7z|appx)$/i, "");
        if (/^(?:[a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*(?:[._-]\d{2,16})?$/i.test(base)) return true;
        if (/^(?:[a-z][a-z0-9_]*\.){2,}[a-z0-9_]+$/i.test(base) && (base.match(/\./g) || []).length >= 2) return true;
        // 内容寻址哈希（应用商店 / CDN：纯 hex 或 资源号_哈希）
        if (/^[a-f0-9]{16,64}$/i.test(base)) return true;
        if (/^\d{4,20}[._-][a-f0-9]{16,64}$/i.test(base)) return true;
        if (/^[a-f0-9]{16,64}[._-]\d{4,20}$/i.test(base)) return true;
        if (/^(?:inst|setup|install|installer|update|upgrade|patch|down|download|soft|client|package|pkg|release|stable|official|online|full|mini|lite|web|get|run|start|main|core|base|app)$/i.test(base)) return true;
        if (/^[A-Za-z][A-Za-z0-9._-]{2,60}?[._-](?:setup|install|installer)[._-]\d{4,16}$/i.test(base)
          && /[a-zA-Z]{4,}/.test(base)
          && !/^(?:app|soft|setup)[._-]/i.test(base)) {
          return true;
        }
        if (/[._-](?:setup|install|installer|client)(?:[._-](?:x64|x86|amd64|win32|win64))?$/i.test(base)
          || /(?:setup|installer)$/i.test(base)) {
          const head = base.replace(/[._-](?:x64|x86|amd64|win32|win64)$/i, "")
            .replace(/[._-]?(?:setup|install|installer|client)$/i, "");
          if (head.length >= 2 && /[a-zA-Z]{2,}/.test(head)
            && !/^(?:app|soft|proxy|down|dl)$/i.test(head)) {
            return true;
          }
        }
        if (/^\d{3,4}[a-z]{2,}[a-z0-9_-]{0,24}$/i.test(base) && base.length <= 28) return true;
        const noBrand = base.replace(/^\d{3,4}(?=[a-z])/i, "");
        if (/^[A-Za-z][A-Za-z0-9_-]{2,40}(?:[._-]\d+(?:\.\d+){0,4})?$/i.test(base)
          && /[a-zA-Z]{4,}/.test(base)
          && !/\d{2,}[a-z]{3,}/i.test(noBrand === base ? base : noBrand.replace(/^[a-z]{2,8}$/i, ""))) {
          return true;
        }
        return false;
      } catch {
        return false;
      }
    }

    /** SERP / 搜索外链跳转 URL 形态（仅路径+查询，无引擎主机名白名单）。 */
    static isSearchTrap(h) {
      try {
        const u = new URL(h, location.href);
        const path = (u.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
        const q = u.search || "";
        if (!q || q.length < 2) return false;
        if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path)
          && /[?&](?:q|query|keyword|text|wd|word|p|search)=[^&]+/i.test(q)) return true;
        if (/\/(?:s|web)$/i.test(path)
          && /[?&](?:q|query|keyword|text|wd|word|p)=[^&]+/i.test(q)) return true;
        if (/\/(?:url|link|redirect|rd|jump)$/i.test(path)
          && /[?&](?:q|url|u|target|to|redir|redirect)=[^&]+/i.test(q)) return true;
        return false;
      } catch {
        return false;
      }
    }

    /** 是否跨域。 */
    static crossOrigin(h) {
      try {
        return new URL(h, location.href).origin !== location.origin;
      } catch {
        return false;
      }
    }
  }

  NS.PackageClassifier = PackageClassifier;
})(window.SilverfoxNavBoot ??= {});
