/**
 * background 文件名 / 包 URL / 对象存储主机分类器（静态，无状态）。
 * SW 独立副本（无法共享 content/page-hooks 命名空间）。
 */
;(function (NS) {
  "use strict";

  const PACKAGE_NAME_RE = /\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/i;

  class PackageHeuristicsBg {
    static PACKAGE_NAME_RE = PACKAGE_NAME_RE;

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

    static basenameFromPath(p) { return PackageHeuristicsBg.normalizeFileName(p); }

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
      if (/\d{2,}[a-z]{3,}/i.test(noBrand) && noBrand !== s) { if (/^[a-z]{2,8}(?:[._-][a-z0-9]+)*$/i.test(noBrand)) return false; return true; }
      if (!/^\d{3,4}[a-z]/i.test(s) && /\d{2,}[a-z]{3,}/i.test(s)) return true;
      if (/[a-z]{1,3}\d{2,}[a-z]{2,}/i.test(s) && !/^\d{3,4}/.test(s)) return true;
      return false;
    }

    static isBenignShortInstallerName(fileName) {
      const name = PackageHeuristicsBg.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME_RE.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "").toLowerCase();
      if (base.length < 2 || base.length > 12) return false;
      if (!/^[a-z]+$/i.test(base)) return false;
      return /^(?:inst|setup|install|installer|update|upgrade|patch|down|download|soft|client|package|pkg|release|stable|official|online|full|mini|lite|web|get|run|start|main|core|base|app|bundle|deploy|launch)$/i.test(base);
    }

    static looksLikeProductSetupWithBuildId(stem) {
      const s = String(stem || "");
      if (!s || s.length < 8 || s.length > 120) return false;
      const m = s.match(/^([A-Za-z一-鿿][A-Za-z0-9一-鿿._-]{2,60}?)[._-](?:setup|install|installer|client)[._-](\d{4,16})(?:[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64))?$/i);
      if (!m) return false;
      const head = m[1] || "";
      if (/^(?:app|soft|proxy|intsoft|down|dl|file|pkg|client|setup|install|installer)$/i.test(head)) return false;
      if (!/[a-zA-Z一-鿿]{4,}/.test(head)) return false;
      if (PackageHeuristicsBg.hasGarbleDigitLetterSoup(head)) return false;
      return true;
    }

    static looksLikeReadableInstallerStem(stem) {
      const s = String(stem || "");
      if (!s || s.length < 3 || s.length > 120) return false;
      if (/^[a-f0-9]{10,}$/i.test(s) || /^\d{6,}$/.test(s)) return false;
      if (PackageHeuristicsBg.looksLikeProductSetupWithBuildId(s)) return true;
      if (/^(?:app[_-]?setup|setup)[._-]\d{4,}/i.test(s)) return false;
      if (/(?:^|[._-])setup[._-]\d{4,}/i.test(s) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{4,}/i.test(s)) return false;
      if (PackageHeuristicsBg.hasGarbleDigitLetterSoup(s)) return false;
      if (/[._-](?:setup|install|installer|client|official)(?:[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64))?$/i.test(s) || /(?:setup|installer)$/i.test(s)) {
        const head = s.replace(/[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64)$/i, "").replace(/[._-]?(?:setup|install|installer|client|official)$/i, "");
        if (head.length >= 2 && /[a-zA-Z一-鿿]{2,}/.test(head) && !/^(?:app|soft|proxy|intsoft|down|dl|file|pkg)$/i.test(head)) return true;
      }
      if (/^\d{3,4}[a-z]{2,}[a-z0-9_-]{0,24}$/i.test(s) && s.length <= 28) { const letters = s.replace(/^\d{3,4}/, "").replace(/[0-9_\-]/g, ""); if (letters.length >= 2) return true; }
      return false;
    }

    static looksLikeProductPackageName(fileName) {
      const name = PackageHeuristicsBg.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME_RE.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "");
      if (base.length < 3 || base.length > 96) return false;
      if (PackageHeuristicsBg.looksLikeAndroidPackageIdName(base)) return true;
      if (PackageHeuristicsBg.isBenignShortInstallerName(name)) return true;
      let stem = base.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64|mac|linux)$/i, "");
      stem = stem.replace(/[._-]?v?\d+(?:\.\d+){1,5}$/i, "");
      if (!stem || stem.length < 2) stem = base.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64|mac|linux)$/i, "");
      if (PackageHeuristicsBg.looksLikeReadableInstallerStem(stem) || PackageHeuristicsBg.looksLikeReadableInstallerStem(base) || PackageHeuristicsBg.looksLikeProductSetupWithBuildId(stem) || PackageHeuristicsBg.looksLikeProductSetupWithBuildId(base)) return true;
      if (PackageHeuristicsBg.hasGarbleDigitLetterSoup(stem)) return false;
      if (/^(?:app[_-]?setup|setup)[._-]\d{4,}/i.test(base)) return false;
      if (/(?:^|[._-])setup[._-]\d{4,}/i.test(base) && !PackageHeuristicsBg.looksLikeProductSetupWithBuildId(base) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{4,}/i.test(base)) return false;
      if (/\.\d{3,7}$/.test(base) && !/\d+\.\d+/.test(base) && !/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(base)) return false;
      const letterRuns = stem.match(/[a-zA-Z一-鿿]{3,}/g) || [];
      if (letterRuns.length === 0) return false;
      if (letterRuns.every((w) => /^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))) return false;
      if (/^(?:\d{3,4})?[A-Za-z一-鿿][A-Za-z一-鿿0-9_-]{1,48}$/i.test(stem) && letterRuns.some((w) => !/^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))) return true;
      if (/\d+\.\d+/.test(base) && letterRuns.some((w) => !/^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w)) && !PackageHeuristicsBg.hasGarbleDigitLetterSoup(stem)) return true;
      return false;
    }

    static looksLikeSvgPathOrNumericJunkName(fileName) {
      const name = String(fileName || "").trim();
      if (!name || name.length < 6) return false;
      if (/\.7z$/i.test(name)) {
        const base = name.replace(/\.7z$/i, "");
        if (!/[a-zA-Z一-鿿]/.test(base)) return true;
        if ((base.match(/-?\.\d+/g) || []).length >= 2) return true;
        if ((base.match(/\d+\.\d+/g) || []).length >= 3) return true;
        if (/^[\d.\-eE+]+$/.test(base)) return true;
        if ((base.match(/\./g) || []).length >= 3 && !/[a-zA-Z一-鿿]{3,}/.test(base)) return true;
      }
      if ((name.match(/-?\.\d+/g) || []).length >= 3 && /\.(?:zip|exe|7z|rar)$/i.test(name)) return true;
      return false;
    }

    static isSuspiciousPackageFilename(fileName) {
      const name = PackageHeuristicsBg.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME_RE.test(name)) return false;
      if (PackageHeuristicsBg.looksLikeSvgPathOrNumericJunkName(name)) return false;
      const baseCheck = name.replace(/\.[^.]+$/, "");
      if (!/[a-zA-Z一-鿿]/.test(baseCheck)) return false;
      if (PackageHeuristicsBg.looksLikeProductPackageName(name)) return false;
      if (PackageHeuristicsBg.isBenignShortInstallerName(name)) return false;
      const baseName = name.replace(/\.[^.]+$/, "");
      if (PackageHeuristicsBg.looksLikeAndroidPackageIdName(baseName)) return false;
      if (PackageHeuristicsBg.looksLikeReadableInstallerStemBg(baseName)) return false;
      if (PackageHeuristicsBg.looksLikeProductSetupWithBuildId(baseName)) return false;
      if (/^[a-f0-9]{16,64}$/i.test(baseCheck)) return false;
      const withoutArch = baseName.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64)$/i, "");
      if (PackageHeuristicsBg.hasGarbleDigitLetterSoup(withoutArch)) return true;
      if (/^[a-z]{2,4}-\d+[a-z0-9]/i.test(baseName)) return true;
      if (/\.[0-9]{3,7}$/.test(baseName) && !/\d+\.\d+/.test(baseName) && !/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(baseName)) return true;
      if (/^(?:app[_-]?setup|setup)[._-]\d{5,}/i.test(baseName)) return true;
      if (/(?:^|[._-])setup[._-]\d{5,}/i.test(baseName) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{5,}/i.test(baseName)) return true;
      if (/^[a-f0-9]{12,}$/i.test(baseName)) return true;
      if (/(?:^|[_\-.])(app|soft|client|proxy|intsoft)(?![a-z])[_\-.]?\d{5,}$/i.test(baseName)) return true;
      if (/(?:\d{3,}down|down\d{3,}|dl\d{3,})/i.test(baseName)) return true;
      if (/^(?:\d+down|down\d+|dl\d+)$/i.test(name)) return true;
      return false;
    }

    // 别名（原 looksLikeReadableInstallerStemBg，与 looksLikeReadableInstallerStem 同义）
    static looksLikeReadableInstallerStemBg(stem) { return PackageHeuristicsBg.looksLikeReadableInstallerStem(stem); }

    static looksLikeOpaqueHopUrl(url) {
      try {
        const u = new URL(url);
        const last = u.pathname.toLowerCase().split("/").filter(Boolean).pop() || "";
        return /^(?:\d{2,}down|down\d{2,}|dl\d{2,}|getfile|getdown)$/i.test(last);
      } catch { return false; }
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
        if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(label)) return true;
        if (/^[a-z]{1,8}-[a-f0-9]{12,}$/i.test(label)) return true;
        if (label.length >= 16 && /^[a-z0-9-]+$/i.test(label) && /[a-z]/i.test(label) && /\d/.test(label) && (label.match(/\d/g) || []).length >= 4 && !/[aeiou]{2,}/i.test(label.replace(/-/g, "")) && !/^(www|cdn|static|img|image|images|media|assets|download|downloads|dl|update|api|app|m|mobile|shop|store|mail|smtp|ns\d*|dns|git|dev|test|stage|staging|prod|beta|docs|help|support|blog|news)$/i.test(label)) return true;
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
      if (PackageHeuristicsBg.isAnonymousPublicObjectHost(h)) return true;
      if (PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(h)) return true;
      const parts = h.split(".").filter(Boolean);
      if (parts.length < 2) return false;
      const allNonTld = parts.slice(0, -1);
      for (const label of allNonTld) {
        if (!label || label.length < 3) continue;
        if (/^[a-f0-9]{16,}$/i.test(label)) return true;
        if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(label)) return true;
        if (/^[a-z]{2,8}-[a-f0-9]{12,}$/i.test(label)) return true;
        if (label.length >= 12 && /^[a-z0-9-]+$/i.test(label) && /[a-z]/i.test(label) && /\d/.test(label) && (label.match(/\d/g) || []).length >= 3 && !/^(www|cdn|static|img|image|images|media|assets|download|downloads|dl|update|api|app|m|mobile|shop|store|mail|smtp|ns\d*|dns|git|dev|test|stage|prod|beta|docs|help|support|blog|news)$/i.test(label)) { if (label.length >= 16 || !/[aeiou]{2,}/i.test(label.replace(/-/g, ""))) return true; }
      }
      if (/(^|\.)(blob|bucket|objstore|objectstore|filestore|object-storage|file-storage)(\.|$)/i.test(h)) return true;
      if (parts.length >= 4) { const mid = parts.slice(0, -2); if (mid.some((l) => (l.length >= 8 && /[a-z]/i.test(l) && /\d/.test(l) && /^[a-z0-9-]+$/i.test(l)) || /^[a-f0-9]{10,}$/i.test(l))) return true; }
      const sub0 = parts.length >= 3 ? parts[0] : "";
      if (sub0.length >= 18 && /^[a-z0-9-]+$/i.test(sub0) && /\d/.test(sub0) && /[a-z]/i.test(sub0)) { if (/(?:mirror|mirrors|package|download|cdn|static|client|release|asset|media|update|files?|dist|build|prod|game)/i.test(sub0)) return false; if ((sub0.match(/\d/g) || []).length >= 4) return true; }
      return false;
    }

    static pathHasOpaqueStorageSegments(pathname) {
      const segs = String(pathname || "").split("/").filter(Boolean);
      for (const s of segs) {
        const base = s.split("?")[0];
        if (/^[a-f0-9]{16,}$/i.test(base)) return true;
        if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(base)) return true;
        if (base.length >= 24 && /^[a-z0-9_-]+$/i.test(base) && /\d/.test(base) && /[a-z]/i.test(base) && !PACKAGE_NAME_RE.test(base)) return true;
      }
      return false;
    }

    static looksLikeStrongProductInstallerName(fileName) {
      const name = PackageHeuristicsBg.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME_RE.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "");
      if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base) && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base))) return true;
      if (PackageHeuristicsBg.isSuspiciousPackageFilename(name)) return false;
      if (PackageHeuristicsBg.hasGarbleDigitLetterSoup(base)) return false;
      if (PackageHeuristicsBg.looksLikeProductSetupWithBuildId(base)) return true;
      if (PackageHeuristicsBg.looksLikeProductPackageName(name) && /(?:setup|install|installer|client|official|release)/i.test(base) && /\d+\.\d+/.test(base)) return true;
      return false;
    }

    static looksLikeObjectStoragePackageUrl(url) {
      try {
        const u = new URL(url);
        const fn = PackageHeuristicsBg.basenameFromPath(u.pathname) || PackageHeuristicsBg.basenameFromPath(url);
        if (!PACKAGE_NAME_RE.test(u.pathname) && !PACKAGE_NAME_RE.test(fn)) return false;
        if (PackageHeuristicsBg.looksLikeStrongProductInstallerName(fn) || PackageHeuristicsBg.looksLikeProductPackageName(fn)) return false;
        if (PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(u.hostname)) return true;
        if (PackageHeuristicsBg.looksLikeObjectStorageHost(u.hostname)) return true;
        if (PackageHeuristicsBg.pathHasOpaqueStorageSegments(u.pathname)) { const parts = u.hostname.toLowerCase().split(".").filter(Boolean); if (parts.length >= 3) return true; const left = parts[0] || ""; if (left.length >= 10 && /\d/.test(left) && /[a-z]/i.test(left)) return true; }
        return false;
      } catch { return false; }
    }

    static looksLikeOversimplifiedBrandInstallerName(fileName) {
      const name = PackageHeuristicsBg.normalizeFileName(fileName);
      if (!name || !PACKAGE_NAME_RE.test(name)) return false;
      const base = name.replace(/\.[^.]+$/, "");
      if (/\d+\.\d+\.\d+/.test(base)) return false;
      if (/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(base)) return false;
      if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base) && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base))) return false;
      if (/^[a-z][a-z0-9]{2,16}[._-](?:win|windows|mac|osx|linux|x64|x86|amd64|arm64)(?:[._-](?:x64|x86|amd64|arm64|win|mac))?$/i.test(base)) return true;
      if (/^[A-Za-z][A-Za-z0-9]{2,28}[._-]v?\d{1,3}[._-](?:win|windows|mac|osx|linux|x64|x86|amd64|arm64)(?:[._-](?:x64|x86|64|32))?$/i.test(base)) return true;
      if (/^[A-Za-z][A-Za-z0-9]{2,28}[._-](?:win|windows|mac|osx|linux)(?:[._-](?:x64|x86|64|32))?$/i.test(base) && !/\d+\.\d+/.test(base)) return true;
      return false;
    }
  }

  NS.PackageHeuristicsBg = PackageHeuristicsBg;
})(self.SilverfoxBackground ??= {});
