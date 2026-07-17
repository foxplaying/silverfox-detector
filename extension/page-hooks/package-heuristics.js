/**
 * 文件名 / 包 URL / 对象存储主机 / SERP 形态分类器（纯静态，无状态）。
 * 供 page-hooks 拦截策略与 DOM 守卫复用。
 */
;(function (NS) {
  "use strict";

  const PACKAGE_EXT = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i;
  const PACKAGE_NAME = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/i;

  class PackageHeuristics {
    static PACKAGE_EXT = PACKAGE_EXT;
    static PACKAGE_NAME = PACKAGE_NAME;

    static normalizeFileName(raw) {
      if (!raw) return "";
      let s = String(raw).trim();
      s = s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      s = s.replace(/u002[fF]/g, "/");
      try { s = decodeURIComponent(s); } catch { /* ignore */ }
      s = s.split("?")[0].split("#")[0];
      s = s.split(/[/\\]/).filter(Boolean).pop() || s;
      return s.trim();
    }

    static getFilenameFromUrl(href) {
      try {
        const u = new URL(href, location.href);
        return PackageHeuristics.normalizeFileName(u.pathname.split("/").filter(Boolean).pop() || "");
      } catch {
        return PackageHeuristics.normalizeFileName(href || "");
      }
    }

    static isPackageFileUrl(href) {
      if (!href || typeof href !== "string") return false;
      const trimmed = href.trim();
      if (!trimmed || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(trimmed)) return false;
      try {
        const u = new URL(trimmed, location.href);
        if (PACKAGE_EXT.test(u.pathname)) return true;
        for (const key of ["filename", "file", "name", "downurl", "downloadurl", "path"]) {
          const v = u.searchParams.get(key) || "";
          if (PACKAGE_NAME.test(v) || PACKAGE_EXT.test(v)) return true;
        }
        if (/\.php(?:\/|$)/i.test(u.pathname) && PACKAGE_EXT.test(u.href)) return true;
        return false;
      } catch {
        return false;
      }
    }

    static looksLikeRandomDownloadHost(hostname) {
      if (!hostname) return false;
      const h = hostname.toLowerCase().replace(/^www\./, "");
      const label = (h.split(".")[0] || "").replace(/-/g, "");
      if (/^(?:cdn|static|img|image|images|media|assets|download|downloads|dl|update|ssl|res|resource|soft|package|pkg|file|files|mirrors?|mirror|store|app|apps|api|www\d*|s\d+|p\d+|v\d+)$/i.test(label)) return false;
      if (/[a-z]{3,}/i.test(label.replace(/\d+/g, "")) && (label.match(/\d/g) || []).length <= 3 && label.length <= 14) return false;
      if (label.length >= 6 && /[a-z]/i.test(label) && /\d/.test(label) && !/[a-z]{4,}/i.test(label.replace(/\d+/g, ""))) return true;
      if (label.length >= 10 && /^[a-z0-9]+$/i.test(label) && /\d/.test(label) && (label.match(/\d/g) || []).length >= 3 && !/[a-z]{4,}/i.test(label.replace(/\d+/g, ""))) return true;
      if (/^[a-z]{1,3}\d{3,}[a-z0-9]*$/i.test(label) && label.length >= 6) return true;
      return false;
    }

    static looksLikeOpaqueDownloadHopUrl(href) {
      if (!href || typeof href !== "string") return false;
      const trimmed = href.trim();
      if (!trimmed || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(trimmed)) return false;
      try {
        const u = new URL(trimmed, location.href);
        const path = u.pathname.toLowerCase().replace(/\/+$/, "") || "/";
        const segments = path.split("/").filter(Boolean);
        if (segments.length === 0) return false; // 裸首页：交 content fetch-probe
        const last = segments[segments.length - 1] || "";
        if (PACKAGE_EXT.test(path)) return false;
        if (/\.(html?|php|aspx?|jsp)(?:$|\?)/i.test(path) && !/\d+down/i.test(path)) return false;
        return /^(?:\d{2,}down|down\d{2,}|dl\d{2,}|getfile|getdown|soft\d+|file\d+|pkg\d+)$/i.test(last)
          || /\/(?:\d{2,}down|down\d{2,}|dl\d{2,})(?:\/)?$/i.test(path);
      } catch {
        return false;
      }
    }

    static looksLikeAndroidPackageIdName(baseName) {
      let b = String(baseName || "").trim().replace(/\.(apk|xapk|apks|aab)$/i, "");
      if (b.length < 7 || b.length > 120) return false;
      if (!/^(?:[a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*(?:[._-]\d{2,16})?$/i.test(b)) {
        if (!/^(?:[a-z][a-z0-9_]*\.){2,}[a-z0-9_]+$/i.test(b)) return false;
        if ((b.match(/\./g) || []).length < 2) return false;
      }
      const last = b.split(".").pop() || "";
      const lastNoBuild = last.replace(/[._-]\d{2,16}$/i, "");
      if (/^[a-f0-9]{12,}$/i.test(lastNoBuild)) return false;
      if (lastNoBuild.length >= 8 && !/[a-z]{3,}/i.test(lastNoBuild)) return false;
      return true;
    }

    static hasGarbleDigitLetterSoup(stem) {
      const s = String(stem || "");
      if (!s) return false;
      const noBrand = s.replace(/^\d{3,4}(?=[a-zA-Z])/i, "");
      if (/[a-z]{2,}\d{2,}[a-z]{3,}/i.test(s)) return true;
      if (/(?:^|[._-])\d{2,}[a-z]{3,}(?:[._-]|$)/i.test(noBrand) && !/^\d{3,4}[a-z]/i.test(s)) return true;
      if (/\d{2,}[a-z]{3,}/i.test(noBrand) && noBrand !== s) {
        if (/^[a-z]{2,8}(?:[._-][a-z0-9]+)*$/i.test(noBrand)) return false;
        return true;
      }
      if (!/^\d{3,4}[a-z]/i.test(s) && /\d{2,}[a-z]{3,}/i.test(s)) return true;
      if (/[a-z]{1,3}\d{2,}[a-z]{2,}/i.test(s) && !/^\d{3,4}/.test(s)) return true;
      return false;
    }

    static isBenignShortInstallerName(fileName) {
      const name = PackageHeuristics.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "").toLowerCase();
      if (base.length < 2 || base.length > 12) return false;
      if (!/^[a-z]+$/i.test(base)) return false;
      return /^(?:inst|setup|install|installer|update|upgrade|patch|down|download|soft|client|package|pkg|release|stable|official|online|full|mini|lite|web|get|run|start|main|core|base|app|bundle|deploy|launch)$/i.test(base);
    }

    static looksLikeProductSetupWithBuildId(stem) {
      const s = String(stem || "");
      if (!s || s.length < 8 || s.length > 120) return false;
      const m = s.match(
        /^([A-Za-z一-鿿][A-Za-z0-9一-鿿._-]{2,60}?)[._-](?:setup|install|installer|client)[._-](\d{4,16})(?:[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64))?$/i
      );
      if (!m) return false;
      const head = m[1] || "";
      if (/^(?:app|soft|proxy|intsoft|down|dl|file|pkg|client|setup|install|installer)$/i.test(head)) return false;
      if (!/[a-zA-Z一-鿿]{4,}/.test(head)) return false;
      if (PackageHeuristics.hasGarbleDigitLetterSoup(head)) return false;
      return true;
    }

    static looksLikeReadableInstallerStem(stem) {
      const s = String(stem || "");
      if (!s || s.length < 3 || s.length > 120) return false;
      if (/^[a-f0-9]{10,}$/i.test(s) || /^\d{6,}$/.test(s)) return false;
      if (PackageHeuristics.looksLikeProductSetupWithBuildId(s)) return true;
      if (/^(?:app[_-]?setup|setup)[._-]\d{4,}/i.test(s)) return false;
      if (/(?:^|[._-])setup[._-]\d{4,}/i.test(s) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{4,}/i.test(s)) return false;
      if (PackageHeuristics.hasGarbleDigitLetterSoup(s)) return false;
      if (/[._-](?:setup|install|installer|client|official)(?:[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64))?$/i.test(s) || /(?:setup|installer)$/i.test(s)) {
        const head = s
          .replace(/[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64)$/i, "")
          .replace(/[._-]?(?:setup|install|installer|client|official)$/i, "");
        if (head.length >= 2 && /[a-zA-Z一-鿿]{2,}/.test(head) && !/^(?:app|soft|proxy|intsoft|down|dl|file|pkg)$/i.test(head)) return true;
      }
      if (/^\d{3,4}[a-z]{2,}[a-z0-9_-]{0,24}$/i.test(s) && s.length <= 28) {
        const letters = s.replace(/^\d{3,4}/, "").replace(/[0-9_\-]/g, "");
        if (letters.length >= 2) return true;
      }
      return false;
    }

    static looksLikeProductPackageName(fileName) {
      const name = PackageHeuristics.normalizeFileName(fileName);
      if (!name) return false;
      const base = name.replace(/\.[^.]+$/, "");
      if (base.length < 3 || base.length > 96) return false;
      if (PackageHeuristics.looksLikeAndroidPackageIdName(base) || PackageHeuristics.looksLikeAndroidPackageIdName(name)) return true;
      if (PackageHeuristics.isBenignShortInstallerName(name)) return true;
      let stem = base.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64|mac|linux)$/i, "");
      stem = stem.replace(/[._-]?v?\d+(?:\.\d+){1,5}$/i, "");
      if (!stem || stem.length < 2) stem = base.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64|mac|linux)$/i, "");
      if (PackageHeuristics.looksLikeReadableInstallerStem(stem) || PackageHeuristics.looksLikeReadableInstallerStem(base)
        || PackageHeuristics.looksLikeProductSetupWithBuildId(stem) || PackageHeuristics.looksLikeProductSetupWithBuildId(base)) return true;
      if (PackageHeuristics.hasGarbleDigitLetterSoup(stem)) return false;
      if (/^(?:app[_-]?setup|setup)[._-]\d{5,}/i.test(base)) return false;
      if (/(?:^|[._-])setup[._-]\d{5,}/i.test(base) && !PackageHeuristics.looksLikeProductSetupWithBuildId(base)
        && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{5,}/i.test(base)) return false;
      if (/^[a-f0-9]{10,}$/i.test(base) || /^\d{6,}$/.test(base)) return false;
      if (/\.\d{3,7}$/.test(base) && !/\d+\.\d+/.test(base) && !/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(base)) return false;
      const letterRuns = stem.match(/[a-zA-Z一-鿿]{3,}/g) || [];
      if (letterRuns.length === 0) return false;
      if (letterRuns.every((w) => /^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))) return false;
      if (/^(?:\d{3,4})?[A-Za-z一-鿿][A-Za-z一-鿿0-9_-]{1,48}$/i.test(stem)
        && letterRuns.some((w) => !/^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))) return true;
      if (/\d+\.\d+/.test(base) && letterRuns.some((w) => !/^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))
        && !PackageHeuristics.hasGarbleDigitLetterSoup(stem)) return true;
      return false;
    }

    /**
     * 内容寻址哈希包名（应用商店 / CDN）：
     * 纯 MD5/SHA；或 资源号_哈希（105065437_ecfe3287…bc97.exe）
     */
    static isContentAddressedPackageName(fileName) {
      const name = PackageHeuristics.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "");
      if (!base || base.length > 120) return false;
      if (/^[a-f0-9]{16,64}$/i.test(base)) return true;
      if (/^\d{4,20}[._-][a-f0-9]{16,64}$/i.test(base)) return true;
      if (/^[a-f0-9]{16,64}[._-]\d{4,20}$/i.test(base)) return true;
      if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(base)) return true;
      return false;
    }

    static isSuspiciousPackageFilename(fileName) {
      if (!fileName) return false;
      const name = PackageHeuristics.normalizeFileName(fileName);
      if (PACKAGE_NAME.test(name)) {
        // 哈希 APK/包：应用商店内容寻址，非乱码
        if (PackageHeuristics.isContentAddressedPackageName(name)) return false;
        if (PackageHeuristics.looksLikeProductPackageName(name)) return false;
        if (PackageHeuristics.isBenignShortInstallerName(name)) return false;
        const baseName = name.replace(/\.[^.]+$/, "");
        if (PackageHeuristics.looksLikeAndroidPackageIdName(baseName)) return false;
        if (PackageHeuristics.looksLikeReadableInstallerStem(baseName)) return false;
        if (PackageHeuristics.looksLikeProductSetupWithBuildId(baseName)) return false;
        const withoutArch = baseName.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64)$/i, "");
        if (PackageHeuristics.hasGarbleDigitLetterSoup(withoutArch)) return true;
        if (/^[a-z]{2,4}-\d+[a-z0-9]/i.test(baseName)) return true;
        if (/\.[0-9]{3,7}$/.test(baseName) && !/\d+\.\d+\.\d+/.test(baseName) && !/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(baseName)) return true;
        if (/^(?:app[_-]?setup|setup)[._-]\d{5,}/i.test(baseName)) return true;
        if (/(?:^|[._-])setup[._-]\d{5,}/i.test(baseName) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{5,}/i.test(baseName)) return true;
        // 短于 16 的 hex 仍可疑；16–64 已由 isContentAddressedPackageName 放过
        if (/^[a-f0-9]{12,15}$/i.test(baseName)) return true;
        if (/(?:^|[_\-.])(app|soft|client|proxy|intsoft)(?![a-z])[_\-.]?\d{5,}$/i.test(baseName)) return true;
        if (/(?:\d{3,}down|down\d{3,}|dl\d{3,})/i.test(baseName)) return true;
        return false;
      }
      if (/^(?:\d+down|down\d+|dl\d+)$/i.test(name)) return true;
      return false;
    }

    static looksLikeHiddenPackagePath(href) {
      try {
        const path = new URL(href, location.href).pathname.toLowerCase();
        if (!PACKAGE_EXT.test(path)) return false;
        if (PackageHeuristics.looksLikeProductPackageName(PackageHeuristics.getFilenameFromUrl(href))) return false;
        if (/\/[a-z0-9]{1,3}\/[a-z0-9._-]{6,}\.(zip|exe|apk|dmg|msi|rar|7z)(?:$|\?)/i.test(path)) return true;
        if (/\/(?:xz|dl|down|d|f|get|file|pkg|soft)\/[^/]+\.(zip|exe|apk|msi|rar|7z)/i.test(path)) return true;
        return false;
      } catch {
        return false;
      }
    }

    static isSiteHomeUrl(href) {
      try {
        const u = new URL(href, location.href);
        const path = (u.pathname || "/").replace(/\/+$/, "") || "";
        return path === "" || path === "/";
      } catch {
        return false;
      }
    }

    static isAnonymousPublicObjectHost(hostname) {
      const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
      if (!h || !h.includes(".")) return false;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return false;
      const parts = h.split(".").filter(Boolean);
      if (parts.length < 2) return false;
      const left = parts[0] || "";
      const allNonTld = parts.slice(0, -1);
      if (/(^|\.)(blob|bucket|objstore|objectstore|filestore|object-storage|file-storage|objects?)(\.|$)/i.test(h)) return true;
      for (const label of allNonTld) {
        if (!label || label.length < 3) continue;
        if (/^[a-f0-9]{16,}$/i.test(label)) return true;
        if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(label)) return true;
        if (/^[a-z]{1,8}-[a-f0-9]{12,}$/i.test(label)) return true;
        if (label.length >= 16 && /^[a-z0-9-]+$/i.test(label) && /[a-z]/i.test(label) && /\d/.test(label)
          && (label.match(/\d/g) || []).length >= 4 && !/[aeiou]{2,}/i.test(label.replace(/-/g, ""))
          && !/^(www|cdn|static|img|image|images|media|assets|download|downloads|dl|update|api|app|m|mobile|shop|store|mail|ns\d*|dns|git|dev|test|stage|prod|beta|docs|help|support|blog|news|ssl|res)$/i.test(label)) return true;
      }
      if (parts.length >= 3) {
        if (/^[a-z]{1,8}-[a-f0-9]{12,}$/i.test(left)) return true;
        if (left.length >= 20 && /^[a-z0-9-]+$/i.test(left) && /\d/.test(left) && /[a-z]/i.test(left) && (left.match(/\d/g) || []).length >= 5) return true;
      }
      return false;
    }

    static hostLooksLikePublicObjectStorageEndpoint(hostname) {
      const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
      if (!h) return false;
      if (/(?:^|\.)oss-[a-z0-9-]+(?:\.|$)/i.test(h)) return true;
      if (/(?:^|\.)s3[-.][a-z0-9-]+(?:\.|$)/i.test(h) || /(^|\.)s3(?:\.|$)/i.test(h)) return true;
      if (/(?:^|\.)cos\.[a-z0-9.-]+/i.test(h) || /(^|\.)cos(?:\.|$)/i.test(h)) return true;
      if (/(?:^|\.)(?:r2|blob|objectstorage|objects)(?:\.|$)/i.test(h)) return true;
      if (/(?:^|\.)tos-[a-z0-9-]+(?:\.|$)/i.test(h)) return true;
      if (/(?:^|\.)tos\.[a-z0-9.-]+/i.test(h)) return true;
      if (/(?:^|\.)(?:volces|volcengine|myqcloud|aliyuncs)(?:\.|$)/i.test(h) && /(?:^|\.)(?:tos|oss|cos|s3)(?:-|\.|$)/i.test(h)) return true;
      if (/\b(?:tos|oss|cos)-[a-z]{2}-[a-z0-9-]+/i.test(h)) return true;
      return false;
    }

    static looksLikeObjectStorageHost(hostname) {
      const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
      if (!h || !h.includes(".")) return false;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return false;
      if (PackageHeuristics.isAnonymousPublicObjectHost(h)) return true;
      if (PackageHeuristics.hostLooksLikePublicObjectStorageEndpoint(h)) return true;
      const parts = h.split(".").filter(Boolean);
      if (parts.length < 2) return false;
      const allNonTld = parts.slice(0, -1);
      for (const label of allNonTld) {
        if (!label || label.length < 3) continue;
        if (/^[a-f0-9]{16,}$/i.test(label)) return true;
        if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(label)) return true;
        if (/^[a-z]{2,8}-[a-f0-9]{12,}$/i.test(label)) return true;
        if (label.length >= 12 && /^[a-z0-9-]+$/i.test(label) && /[a-z]/i.test(label) && /\d/.test(label)
          && (label.match(/\d/g) || []).length >= 3
          && !/^(www|cdn|static|img|image|images|media|assets|download|downloads|dl|update|api|app|m|mobile|shop|store|mail|ns\d*|dns|git|dev|test|stage|prod|beta|docs|help|support|blog|news)$/i.test(label)) {
          if (label.length >= 16 || !/[aeiou]{2,}/i.test(label.replace(/-/g, ""))) return true;
        }
      }
      if (/(^|\.)(blob|bucket|objstore|objectstore|filestore|object-storage|file-storage)(\.|$)/i.test(h)) return true;
      if (parts.length >= 4) {
        const mid = parts.slice(0, -2);
        if (mid.some((l) => (l.length >= 8 && /[a-z]/i.test(l) && /\d/.test(l) && /^[a-z0-9-]+$/i.test(l)) || /^[a-f0-9]{10,}$/i.test(l))) return true;
      }
      const sub0 = parts.length >= 3 ? parts[0] : "";
      if (sub0.length >= 18 && /^[a-z0-9-]+$/i.test(sub0) && /\d/.test(sub0) && /[a-z]/i.test(sub0)) {
        if (/(?:mirror|mirrors|package|download|cdn|static|client|release|asset|media|update|files?|dist|build|prod|game)/i.test(sub0)) return false;
        if ((sub0.match(/\d/g) || []).length >= 4) return true;
      }
      return false;
    }

    static pathHasOpaqueStorageSegments(pathname) {
      const segs = String(pathname || "").split("/").filter(Boolean);
      for (const s of segs) {
        const base = s.split("?")[0];
        if (/^[a-f0-9]{16,}$/i.test(base)) return true;
        if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(base)) return true;
        if (base.length >= 24 && /^[a-z0-9_-]+$/i.test(base) && /\d/.test(base) && /[a-z]/i.test(base) && !PACKAGE_NAME.test(base)) return true;
      }
      return false;
    }

    static looksLikeHighRiskBlobPackageUrl(href) {
      if (!href || !PackageHeuristics.isPackageFileUrl(href)) return false;
      try {
        const u = new URL(href, location.href);
        const fn = PackageHeuristics.getFilenameFromUrl(u.href);
        const base = (fn || "").replace(/\.[^.]+$/, "");
        if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base)
          && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base)) && !PackageHeuristics.isSuspiciousPackageFilename(fn)) return false;
        if (PackageHeuristics.looksLikeProductPackageName(fn) && !PackageHeuristics.isSuspiciousPackageFilename(fn)) return false;
        if (PackageHeuristics.isAnonymousPublicObjectHost(u.hostname)) return true;
        try {
          const pageApex = location.hostname.toLowerCase().replace(/^www\./, "").split(".").slice(-2).join(".");
          const pkgApex = u.hostname.toLowerCase().replace(/^www\./, "").split(".").slice(-2).join(".");
          if (pageApex && pkgApex && pageApex !== pkgApex && PackageHeuristics.hostLooksLikePublicObjectStorageEndpoint(u.hostname)) return true;
        } catch { /* ignore */ }
        return PackageHeuristics.looksLikeObjectStorageHost(u.hostname) && PackageHeuristics.pathHasOpaqueStorageSegments(u.pathname);
      } catch {
        return false;
      }
    }

    static looksLikeOversimplifiedBrandInstallerName(fileName) {
      const name = PackageHeuristics.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "");
      if (/\d+\.\d+\.\d+/.test(base)) return false;
      if (/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(base)) return false;
      if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base) && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base))) return false;
      if (/^[a-z][a-z0-9]{2,16}[._-](?:win|windows|mac|osx|linux|x64|x86|amd64|arm64)(?:[._-](?:x64|x86|amd64|arm64|win|mac))?$/i.test(base)) return true;
      if (/^[A-Za-z][A-Za-z0-9]{2,28}[._-]v?\d{1,3}[._-](?:win|windows|mac|osx|linux|x64|x86|amd64|arm64)(?:[._-](?:x64|x86|64|32))?$/i.test(base)) return true;
      if (/^[A-Za-z][A-Za-z0-9]{2,28}[._-](?:win|windows|mac|osx|linux)(?:[._-](?:x64|x86|64|32))?$/i.test(base) && !/\d+\.\d+/.test(base)) return true;
      return false;
    }

    static looksLikeObjectStoragePackageUrl(href) {
      if (!href || !PackageHeuristics.isPackageFileUrl(href)) return false;
      try {
        const u = new URL(href, location.href);
        const fn = PackageHeuristics.getFilenameFromUrl(u.href);
        const baseFn = (fn || "").replace(/\.[^.]+$/, "");
        if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(baseFn) && (/\d+\.\d+/.test(baseFn) || /[._-]\d{4,}/.test(baseFn))) return false;
        const oversimple = PackageHeuristics.looksLikeOversimplifiedBrandInstallerName(fn);
        const clearPkg = PackageHeuristics.looksLikeProductPackageName(fn) || PackageHeuristics.isBenignShortInstallerName(fn)
          || PackageHeuristics.looksLikeAndroidPackageIdName(fn) || PackageHeuristics.looksLikeAndroidPackageIdName(fn.replace(/\.[^.]+$/, ""));
        const hostHit = PackageHeuristics.looksLikeObjectStorageHost(u.hostname);
        const opaquePath = PackageHeuristics.pathHasOpaqueStorageSegments(u.pathname);
        const publicOss = PackageHeuristics.hostLooksLikePublicObjectStorageEndpoint(u.hostname);
        if (PackageHeuristics.isAnonymousPublicObjectHost(u.hostname)) return true;
        const pageApex = (() => {
          try {
            const p = location.hostname.toLowerCase().replace(/^www\./, "").split(".");
            return p.length >= 2 ? p.slice(-2).join(".") : location.hostname;
          } catch { return ""; }
        })();
        const pkgHost = u.hostname.toLowerCase().replace(/^www\./, "");
        const pkgParts = pkgHost.split(".");
        const pkgApex = pkgParts.length >= 2 ? pkgParts.slice(-2).join(".") : pkgHost;
        const offsite = pageApex && pkgApex && pageApex !== pkgApex;
        if ((publicOss || hostHit) && oversimple) return true;
        if (offsite && publicOss && !PackageHeuristics.isStrongProductInstallerUrl(href)) return true;
        if (clearPkg && !oversimple && !publicOss) return false;
        if (hostHit) return true;
        if (offsite && opaquePath) return true;
        if (offsite && PackageHeuristics.looksLikeRandomDownloadHost(u.hostname)) return true;
        return false;
      } catch {
        return false;
      }
    }

    /** 强产品安装包 URL（Brand_official_setup_2.6.3.0.exe 等），任何 CDN 路径放行。 */
    static isStrongProductInstallerUrl(href) {
      try {
        if (!href || !PackageHeuristics.isPackageFileUrl(href)) return false;
        const fileName = PackageHeuristics.getFilenameFromUrl(href);
        if (!fileName || PackageHeuristics.isSuspiciousPackageFilename(fileName)) return false;
        const baseName = fileName.replace(/\.[^.]+$/, "");
        if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(baseName) && (/\d+\.\d+/.test(baseName) || /[._-]\d{4,}/.test(baseName))) return true;
        if (PackageHeuristics.looksLikeProductSetupWithBuildId(baseName)) return true;
        if (PackageHeuristics.looksLikeAndroidPackageIdName(fileName) || PackageHeuristics.looksLikeAndroidPackageIdName(baseName)) return true;
        if (PackageHeuristics.isBenignShortInstallerName(fileName)) return true;
        return false;
      } catch {
        return false;
      }
    }

    /** @deprecated 别名，保留调用点；含义仅强产品白名单。 */
    static isClearOrStrongProductPackageUrl(href) {
      return PackageHeuristics.isStrongProductInstallerUrl(href);
    }

    static getRegistrableDomainSafe(hostname) {
      const h = String(hostname || "").toLowerCase().replace(/^www\./, "");
      const parts = h.split(".").filter(Boolean);
      if (parts.length <= 2) return h;
      return parts.slice(-2).join(".");
    }

    /** 同 apex 官方产品下载路径（钉钉 /win/d/ tryAgain）。 */
    static isSameApexOfficialDownloadPath(href) {
      try {
        const u = new URL(PackageHeuristics.coerceHref(href), location.href);
        if (u.hostname.replace(/^www\./, "") !== location.hostname.replace(/^www\./, "")
          && PackageHeuristics.getRegistrableDomainSafe(u.hostname) !== PackageHeuristics.getRegistrableDomainSafe(location.hostname)) return false;
        const path = (u.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
        return /^\/(?:win|windows|mac|osx|macos|linux|android|ios|pc|download|downloads)(?:\/(?:d|dl|download|get)?)?$/i.test(path);
      } catch {
        return false;
      }
    }

    /** URL 是否表现为文件下载 / 安装包 / 下载 hop（非普通页面）。 */
    static looksLikeDownloadOrPackageNav(href) {
      if (!href) return false;
      const s = PackageHeuristics.coerceHref(href);
      if (PackageHeuristics.isPackageFileUrl(s)) return true;
      if (PackageHeuristics.looksLikeOpaqueDownloadHopUrl(s)) return true;
      if (PackageHeuristics.looksLikeObjectStoragePackageUrl(s)) return true;
      try {
        const u = new URL(s, location.href);
        const path = (u.pathname || "").toLowerCase();
        const last = path.split("/").filter(Boolean).pop() || "";
        if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx|bin|iso)(?:$|\?)/i.test(path)) return true;
        if (/^(?:download|getfile|getdown|attachment|file)(?:\.php|\.aspx?)?$/i.test(last)) return true;
        if (/[?&](?:download|attachment|filename)=/i.test(u.search)) return true;
      } catch { /* ignore */ }
      return false;
    }

    /** SEO 伪装跳转：自动跳到 SERP / 外链 hop 形态（无引擎主机名硬编码）。 */
    static isSearchEngineTrapRedirect(href) {
      try {
        const u = new URL(PackageHeuristics.coerceHref(href), location.href);
        const path = (u.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
        const q = u.search || "";
        if (!q || q.length < 2) return false;
        if (/(?:^|\/)(?:search|results?)(?:\/|$)/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p|search)=[^&]+/i.test(q)) return true;
        if (/\/(?:s|web)$/i.test(path) && /[?&](?:q|query|keyword|text|wd|word|p)=[^&]+/i.test(q)) return true;
        if (/\/(?:url|link|redirect|rd|jump)$/i.test(path) && /[?&](?:q|url|u|target|to|redir|redirect)=[^&]+/i.test(q)) return true;
        return false;
      } catch {
        return false;
      }
    }

    static isCrossOrigin(href) {
      try {
        const u = new URL(PackageHeuristics.coerceHref(href), location.href);
        return u.origin !== location.origin;
      } catch {
        return false;
      }
    }

    static coerceHref(url) {
      if (url == null) return "";
      if (typeof url === "string") return url;
      try { if (typeof URL !== "undefined" && url instanceof URL) return url.href; } catch { /* ignore */ }
      try { if (url && typeof url.href === "string") return url.href; } catch { /* ignore */ }
      return String(url);
    }
  }

  NS.PackageHeuristics = PackageHeuristics;
})(window.SilverfoxPageHooks ??= {});
