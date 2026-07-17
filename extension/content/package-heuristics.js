/**
 * content 文件名 / 包 URL / 对象存储 / 下载意图启发式。
 * isolated world 独立副本（无法共享 MAIN-world 命名空间）。
 */
;(function (NS) {
  "use strict";

  const { PACKAGE_EXT, PACKAGE_NAME, DOWNLOAD_TEXT } = NS;

  NS.normalizeFileName = function (raw) {
    if (!raw) return "";
    let s = String(raw).trim();
    s = s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    s = s.replace(/u002[fF]/g, "/");
    s = s.replace(/u005[cC]/g, "\\");
    try { s = decodeURIComponent(s); } catch { /* ignore */ }
    s = s.split("?")[0].split("#")[0].split("&")[0];
    s = s.split(/[/\\]/).filter(Boolean).pop() || s;
    const pkgTok = s.match(/([A-Za-z0-9][A-Za-z0-9._-]{2,100}\.(?:zip|exe|apk|xapk|apks|aab|dmg|msi|rar|7z|pkg|appx))$/i);
    if (pkgTok) s = pkgTok[1];
    return s.trim();
  };

  NS.looksLikeSvgPathOrNumericJunkName = function (fileName) {
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
    if ((name.match(/-?\.\d+/g) || []).length >= 3 && /[.\-](?:zip|exe|7z|rar|pkg)$/i.test(name)) return true;
    if (/^[MmLlHhVvCcSsQqTtAa][\d.\s,\-eE+]+[Zz]?$/i.test(name.replace(/\.(zip|exe|7z|rar)$/i, ""))) return true;
    return false;
  };

  NS.isPlausiblePackageFileName = function (fileName) {
    const name = NS.normalizeFileName(fileName);
    if (!name || name.length < 5 || name.length > 120) return false;
    if (NS.looksLikeSvgPathOrNumericJunkName(name)) return false;
    if (!PACKAGE_NAME.test(name) && !/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/i.test(name)) return false;
    const base = name.replace(/\.[^.]+$/, "");
    if (!/[a-zA-Z一-鿿]/.test(base)) return false;
    const leadingDotFloats = (base.match(/-?\.\d+/g) || []).length;
    if (leadingDotFloats >= 2 && !/[a-zA-Z一-鿿]{3,}/.test(base)) return false;
    return true;
  };

  NS.getFilenameFromUrl = function (href) {
    if (!href) return "";
    try {
      const u = new URL(href, location.href);
      return NS.normalizeFileName(u.pathname.split("/").filter(Boolean).pop() || "");
    } catch {
      return NS.normalizeFileName(href);
    }
  };

  NS.isPackageFileUrl = function (href) {
    if (!href || typeof href !== "string") return false;
    const trimmed = href.trim();
    if (!trimmed || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(trimmed)) return false;
    if (NS.looksLikeSvgPathOrNumericJunkName(trimmed) || NS.looksLikeSvgPathOrNumericJunkName(NS.normalizeFileName(trimmed))) return false;
    try {
      const u = new URL(trimmed, location.href);
      const base = NS.normalizeFileName(u.pathname);
      if (PACKAGE_EXT.test(u.pathname)) return NS.isPlausiblePackageFileName(base);
      for (const key of ["filename", "file", "name", "downurl", "downloadurl", "path"]) {
        const v = u.searchParams.get(key) || "";
        if ((PACKAGE_NAME.test(v) || PACKAGE_EXT.test(v)) && NS.isPlausiblePackageFileName(v)) return true;
      }
      if (/\.php(?:\/|$)/i.test(u.pathname) && PACKAGE_EXT.test(u.href)) return NS.isPlausiblePackageFileName(base) || NS.isPlausiblePackageFileName(NS.normalizeFileName(u.href));
      return false;
    } catch {
      return false;
    }
  };

  NS.looksLikeAndroidPackageIdName = function (baseName) {
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
  };

  NS.hasGarbleDigitLetterSoup = function (stem) {
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
  };

  NS.looksLikeProductSetupWithBuildId = function (stem) {
    const s = String(stem || "");
    if (!s || s.length < 8 || s.length > 120) return false;
    const m = s.match(/^([A-Za-z一-鿿][A-Za-z0-9一-鿿._-]{2,60}?)[._-](?:setup|install|installer|client)[._-](\d{4,16})(?:[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64))?$/i);
    if (!m) return false;
    const head = m[1] || "";
    if (/^(?:app|soft|proxy|intsoft|down|dl|file|pkg|client|setup|install|installer)$/i.test(head)) return false;
    if (!/[a-zA-Z一-鿿]{4,}/.test(head)) return false;
    if (NS.hasGarbleDigitLetterSoup(head)) return false;
    return true;
  };

  NS.looksLikeReadableInstallerStem = function (stem) {
    const s = String(stem || "");
    if (!s || s.length < 3 || s.length > 120) return false;
    if (/^[a-f0-9]{10,}$/i.test(s) || /^\d{6,}$/.test(s)) return false;
    if (NS.looksLikeProductSetupWithBuildId(s)) return true;
    if (/^(?:app[_-]?setup|setup)[._-]\d{4,}/i.test(s)) return false;
    if (/(?:^|[._-])(?:app[_-]?setup)[._-]\d{4,}/i.test(s)) return false;
    if (/(?:^|[._-])setup[._-]\d{4,}/i.test(s) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{4,}/i.test(s)) return false;
    if (NS.hasGarbleDigitLetterSoup(s)) return false;
    if (/[._-](?:setup|install|installer|client|official)(?:[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64))?$/i.test(s) || /(?:setup|installer)$/i.test(s)) {
      const head = s.replace(/[._-](?:x64|x86|x86_64|amd64|arm64|win32|win64)$/i, "").replace(/[._-]?(?:setup|install|installer|client|official)$/i, "");
      if (head.length >= 2 && /[a-zA-Z一-鿿]{2,}/.test(head) && !/^(?:app|soft|proxy|intsoft|down|dl|file|pkg)$/i.test(head)) return true;
    }
    if (/^\d{3,4}[a-z]{2,}[a-z0-9_-]{0,24}$/i.test(s) && s.length <= 28) {
      const letters = s.replace(/^\d{3,4}/, "").replace(/[0-9_\-]/g, "");
      if (letters.length >= 2) return true;
    }
    return false;
  };

  NS.isBenignShortInstallerName = function (fileName) {
    const name = NS.normalizeFileName(fileName);
    if (!name || !PACKAGE_NAME.test(name)) return false;
    const base = name.replace(/\.[^.]+$/, "").toLowerCase();
    if (base.length < 2 || base.length > 12) return false;
    if (!/^[a-z]+$/i.test(base)) return false;
    if (NS.hasGarbleDigitLetterSoup(base)) return false;
    return /^(?:inst|setup|install|installer|update|upgrade|patch|down|download|soft|client|package|pkg|release|stable|official|online|full|mini|lite|web|get|run|start|main|core|base|app|bundle|deploy|launch)$/i.test(base);
  };

  /**
   * 内容寻址/哈希文件名（应用商店 / 对象 CDN 常见），非银狐乱码包：
   * - 纯 MD5(32)/SHA1(40)/SHA256(64) stem：F4138527…96.apk
   * - 资源号 + 哈希：105065437_ecfe32872db0a584cf7649348ad0bc97.exe
   * - 哈希 + 资源号 / UUID
   */
  NS.isContentAddressedPackageName = function (fileName) {
    const name = NS.normalizeFileName(fileName);
    if (!name || !PACKAGE_NAME.test(name)) return false;
    const base = name.replace(/\.[^.]+$/, "");
    if (!base || base.length > 120) return false;
    // 纯 16–64 位 hex
    if (/^[a-f0-9]{16,64}$/i.test(base)) return true;
    // 数字资源 ID + 分隔 + 16–64 hex（CDN 常见）
    if (/^\d{4,20}[._-][a-f0-9]{16,64}$/i.test(base)) return true;
    // hex + 分隔 + 数字资源 ID
    if (/^[a-f0-9]{16,64}[._-]\d{4,20}$/i.test(base)) return true;
    // UUID
    if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(base)) return true;
    return false;
  };

  NS.looksLikeProductPackageName = function (fileName) {
    if (!fileName) return false;
    const name = NS.normalizeFileName(fileName);
    const baseEarly = name.replace(/\.[^.]+$/, "");
    if (NS.looksLikeAndroidPackageIdName(baseEarly) || NS.looksLikeAndroidPackageIdName(name)) return true;
    if (NS.isBenignShortInstallerName(name)) return true;
    if (NS.looksLikeSvgPathOrNumericJunkName(name) || !NS.isPlausiblePackageFileName(name)) return false;
    const base = name.replace(/\.[^.]+$/, "");
    if (base.length < 3 || base.length > 96) return false;
    if (NS.looksLikeAndroidPackageIdName(base)) return true;
    let stem = base.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64|mac|linux)$/i, "");
    stem = stem.replace(/[._-]?v?\d+(?:\.\d+){1,5}$/i, "");
    if (!stem || stem.length < 2) stem = base.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64|mac|linux)$/i, "");
    if (NS.looksLikeReadableInstallerStem(stem) || NS.looksLikeReadableInstallerStem(base)
      || NS.looksLikeProductSetupWithBuildId(stem) || NS.looksLikeProductSetupWithBuildId(base)) return true;
    if (NS.hasGarbleDigitLetterSoup(stem)) return false;
    if (/\.\d{3,7}$/.test(base) && !/\d+\.\d+/.test(base) && !/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(base)) return false;
    if (/\.\d{3,7}$/.test(base) && !/\d+\.\d+(\.\d+)?/.test(base.replace(/\.\d{3,7}$/, ""))) {
      const gStem = base.replace(/\.\d{3,7}$/, "");
      if (!/[A-Za-z一-鿿]{4,}/.test(gStem) || /\d/.test(gStem.replace(/[-_.]/g, "").slice(0, 8))) return false;
    }
    if (/^[a-f0-9]{10,}$/i.test(base) || /^\d{6,}$/.test(base)) return false;
    const letterRuns = stem.match(/[a-zA-Z一-鿿]{3,}/g) || [];
    if (letterRuns.length === 0) return false;
    const onlyArchWords = letterRuns.every((w) => /^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install)$/i.test(w));
    if (onlyArchWords) return false;
    if (/^(?:app[_-]?setup|setup)[._-]\d{4,}/i.test(base)) return false;
    if (/(?:^|[._-])setup[._-]\d{4,}/i.test(base) && !NS.looksLikeProductSetupWithBuildId(base) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{4,}/i.test(base)) return false;
    if (/^(?:\d{3,4})?[A-Za-z一-鿿][A-Za-z一-鿿0-9_-]{1,80}$/i.test(stem) && !NS.hasGarbleDigitLetterSoup(stem) && !/^[a-z]{2,4}-\d+/i.test(stem)
      && letterRuns.some((w) => !/^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))) return true;
    if (/\d+\.\d+/.test(base) && letterRuns.some((w) => !/^(windows|win|mac|linux|android|ios|x64|x86|amd64|arm64|setup|install|lite|pro)$/i.test(w))) {
      if (!NS.hasGarbleDigitLetterSoup(stem) && !/^(?:app[_-]?setup|setup)[._-]\d{4,}/i.test(base)
        && (NS.looksLikeProductSetupWithBuildId(base) || !/(?:^|[._-])setup[._-]\d{4,}/i.test(base) || /[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{4,}/i.test(base))) return true;
    }
    if (/(setup|install|client|release|stable|official|installer|lite|正式版|安装包)/i.test(stem || base)) {
      return !NS.hasGarbleDigitLetterSoup(stem) && !/[._-]\d{5,}/.test(stem);
    }
    return false;
  };

  NS.isSuspiciousDownloadFilename = function (fileName) {
    if (!fileName) return false;
    const name = NS.normalizeFileName(fileName);
    if (!NS.isPlausiblePackageFileName(name) || NS.looksLikeSvgPathOrNumericJunkName(name)) return false;
    const lower = name.toLowerCase();
    const extension = lower.split(".").pop() || "";
    if (!/^(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)$/.test(extension)) return false;
    // 内容寻址哈希包名（应用商店 CDN）不当可疑乱码
    if (NS.isContentAddressedPackageName(name)) return false;
    if (NS.looksLikeProductPackageName(name)) return false;
    if (NS.isBenignShortInstallerName(name)) return false;
    const baseName = name.replace(/\.[^.]+$/, "");
    if (NS.looksLikeAndroidPackageIdName(baseName)) return false;
    if (NS.looksLikeReadableInstallerStem(baseName)) return false;
    if (NS.looksLikeProductSetupWithBuildId(baseName)) return false;
    const withoutArch = baseName.replace(/[._-](x64|x86|x86_64|amd64|arm64|arm|win32|win64)$/i, "");
    if (NS.hasGarbleDigitLetterSoup(withoutArch)) return true;
    if (/^[a-z]{2,4}-\d+[a-z0-9]/i.test(baseName)) return true;
    if (/\.[0-9]{3,10}$/.test(baseName) && !/\d+\.\d+\.\d+/.test(baseName) && !/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(baseName)) return true;
    if (/^(?:app)?(?:install|setup|installer|down|update|client)[a-z0-9]*\.\d{4,}$/i.test(baseName)) return true;
    // 短于 16 的 hex 仍可疑；16–64 已由 isContentAddressedPackageName 放过
    if (/^[a-f0-9]{12,15}$/i.test(baseName)) return true;
    if (/(?:^|[_\-.])(app|soft|client|proxy|intsoft)(?![a-z])[_\-.]?\d{5,}$/i.test(baseName)) return true;
    if (/^(?:app[_-]?setup|setup)[._-]\d{5,}/i.test(baseName)) return true;
    if (/(?:^|[._-])setup[._-]\d{5,}/i.test(baseName) && !/[a-zA-Z一-鿿]{4,}[._-]setup[._-]\d{5,}/i.test(baseName)) return true;
    if (/(?:\d{3,}down|down\d{3,}|dl\d{3,})/i.test(baseName)) return true;
    if (/^(?:\d+down|down\d+|dl\d+)$/i.test(name)) return true;
    if (/^[a-z0-9]{4,}_[a-z0-9]{4,}\.\d{5,}/i.test(baseName)) return true;
    if (baseName.length >= 20 && !/[a-zA-Z]{4,}/.test(withoutArch.replace(/[0-9_\-.]/g, ""))) return true;
    if (/^(?:\d{8,}|[a-z]{1,3}\d{6,})$/i.test(baseName)) return true;
    if (!/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(baseName) && /_[a-z]{2,6}\d{4,}[a-z0-9]*$/i.test(baseName)
      && !/_(?:x64|x86|x86_64|amd64|arm64|win32|win64|mac|linux)\d*$/i.test(baseName)) return true;
    if (!/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(baseName) && /[a-z]{3,}[-_][a-z0-9.-]*[_-][a-z]{2,5}\d{4,}$/i.test(baseName)) return true;
    return false;
  };

  NS.looksLikeHiddenPackagePath = function (href) {
    if (!href) return false;
    try {
      const u = new URL(href, location.href);
      const path = u.pathname.toLowerCase();
      if (!PACKAGE_EXT.test(path)) return false;
      const fn = NS.getFilenameFromUrl(href);
      if (NS.looksLikeStrongProductInstallerName(fn) || NS.packageFilenameSharesPageBrand(fn)) return false;
      if (NS.looksLikeProductPackageName(fn) && NS.packageFilenameSharesPageBrand(fn)) return false;
      if (/\/[a-z0-9]{1,3}\/[a-z0-9._-]{6,}\.(zip|exe|apk|dmg|msi|rar|7z)(?:$|\?)/i.test(path)) return true;
      if (/\/(?:xz|dl|down|d|f|get|file|pkg|soft)\/[^/]+\.(zip|exe|apk|msi|rar|7z)/i.test(path)) return true;
      return false;
    } catch {
      return false;
    }
  };

  NS.looksLikeObfuscatedPhpDownloadUrl = function (href) {
    if (!href) return false;
    try {
      const u = new URL(href, location.href);
      const path = u.pathname.toLowerCase();
      const fileName = path.split("/").filter(Boolean).pop() || "";
      const phpEntry = /\/(?:down|download|install|setup|link|jump|goto|redirect|api|share|file)\.php(?:\/|$)/i.test(path) || /\/[^/]+\.php(?:\/|$)/i.test(path);
      const hasPackageSuffix = PACKAGE_EXT.test(path) || PACKAGE_EXT.test(fileName);
      const obfuscatedSegment = /\/([a-f0-9]{10,}|[a-z0-9_-]{12,})(?:\/|$)/i.test(path) || /[a-f0-9]{16,}/i.test(fileName);
      return phpEntry && hasPackageSuffix && (obfuscatedSegment || fileName.length >= 16);
    } catch {
      return false;
    }
  };

  NS.looksLikeRedirectLink = function (href) {
    if (!href) return false;
    try {
      const u = new URL(href, location.href);
      const path = u.pathname.toLowerCase();
      const host = u.hostname.toLowerCase();
      const noFileSuffix = !PACKAGE_EXT.test(path);
      const hostLabel = (host.split(".")[0] || "").replace(/-/g, "");
      const looksRandomHost = host.split(".").length <= 2 && (
        (/^[a-z0-9]{10,}$/i.test(hostLabel) && /\d/.test(hostLabel) && /[a-z]/i.test(hostLabel))
        || (/[0-9]{6,}/.test(hostLabel) && hostLabel.length >= 8)
        || /^[a-f0-9]{12,}$/i.test(hostLabel)
      );
      const redirectLikePath = /\/(?:jump|goto|redirect|out|click|track)\b/i.test(path) || /\/(?:dl|link)\/[a-z0-9]{6,}/i.test(path);
      const suspiciousGarbledPath = /\/(?:\d+[a-z]{2,}|[a-z]{2,}\d+|[a-z0-9_-]{10,})(?:down|dl|zip|setup|install)?(?:[\/\?#]|$)/i.test(path);
      const isExternal = u.origin !== location.origin;
      return isExternal && noFileSuffix && (NS.looksLikeObfuscatedPhpDownloadUrl(href) || looksRandomHost || redirectLikePath || suspiciousGarbledPath);
    } catch {
      return false;
    }
  };

  NS.isClearProductOrAndroidPackage = function (fileNameOrUrl) {
    if (!fileNameOrUrl) return false;
    const name = NS.normalizeFileName(/https?:\/\//i.test(String(fileNameOrUrl)) ? NS.getFilenameFromUrl(fileNameOrUrl) : fileNameOrUrl);
    if (!name) return false;
    const base = name.replace(/\.[^.]+$/, "");
    // 内容寻址包名：应用商店 / CDN（纯 hex 或 资源号_哈希.exe/.apk）
    if (NS.isContentAddressedPackageName(name)) return true;
    if (NS.looksLikeAndroidPackageIdName(base) || NS.looksLikeAndroidPackageIdName(name)) return true;
    if (NS.isBenignShortInstallerName(name)) return true;
    if (NS.looksLikeProductPackageName(name)) return true;
    return false;
  };

  NS.looksLikeStrongProductInstallerName = function (fileName) {
    const name = NS.normalizeFileName(fileName);
    if (!name || !PACKAGE_NAME.test(name)) return false;
    const base = name.replace(/\.[^.]+$/, "");
    if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base) && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base))) return true;
    if (NS.hasGarbleDigitLetterSoup(base)) return false;
    if (NS.looksLikeProductSetupWithBuildId(base)) return true;
    if (NS.looksLikeProductPackageName(name) && /(?:setup|install|installer|client|official|release|正式版)/i.test(base) && /\d+\.\d+/.test(base)) return true;
    return false;
  };

  NS.isAllowlistedProductPackageUrl = function (href) {
    if (!href || !NS.isPackageFileUrl(href)) return false;
    const fn = NS.getFilenameFromUrl(href);
    if (NS.looksLikeStrongProductInstallerName(fn)) return true;
    if (NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(href)) return true;
    if (NS.looksLikeProductPackageName(fn) && !NS.looksLikeBrandNearMissPackageName(fn) && !NS.looksLikeOversimplifiedBrandInstallerName(fn) && !NS.isSuspiciousDownloadFilename(fn)) return true;
    return false;
  };

  NS.isAnonymousPublicObjectHost = function (hostname) {
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
      if (label.length >= 16 && /^[a-z0-9-]+$/i.test(label) && /[a-z]/i.test(label) && /\d/.test(label)
        && (label.match(/\d/g) || []).length >= 4 && !/[aeiou]{2,}/i.test(label.replace(/-/g, ""))
        && !/^(www|cdn|static|img|image|images|media|assets|download|downloads|dl|update|api|app|m|mobile|shop|store|mail|smtp|ns\d*|dns|git|dev|test|stage|staging|prod|beta|docs|help|support|blog|news|video|player|ssl|res)$/i.test(label)) return true;
    }
    if (parts.length >= 3) {
      if (/^[a-z]{1,8}-[a-f0-9]{12,}$/i.test(left)) return true;
      if (left.length >= 20 && /^[a-z0-9-]+$/i.test(left) && /\d/.test(left) && /[a-z]/i.test(left) && (left.match(/\d/g) || []).length >= 5) return true;
    }
    return false;
  };

  NS.hostLooksLikePublicObjectStorageEndpoint = function (hostname) {
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
  };

  NS.looksLikeObjectStorageHost = function (hostname) {
    const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
    if (!h || !h.includes(".")) return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return false;
    if (NS.isAnonymousPublicObjectHost(h)) return true;
    if (NS.hostLooksLikePublicObjectStorageEndpoint(h)) return true;
    const parts = h.split(".").filter(Boolean);
    if (parts.length < 2) return false;
    const subLabels = parts.length >= 3 ? parts.slice(0, -2) : parts.slice(0, -1);
    const allNonTld = parts.slice(0, -1);
    for (const label of allNonTld) {
      if (!label || label.length < 3) continue;
      if (/^[a-f0-9]{16,}$/i.test(label)) return true;
      if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(label)) return true;
      if (/^[a-z]{2,8}-[a-f0-9]{12,}$/i.test(label)) return true;
      if (label.length >= 12 && /^[a-z0-9-]+$/i.test(label) && /[a-z]/i.test(label) && /\d/.test(label)
        && (label.match(/\d/g) || []).length >= 3
        && !/^(www|cdn|static|img|image|images|media|assets|download|downloads|dl|update|api|app|m|mobile|shop|store|mail|smtp|ns\d*|dns|git|dev|test|stage|staging|prod|beta|docs|help|support|blog|news|video|player)$/i.test(label)) {
        if (label.length >= 16 || !/[aeiou]{2,}/i.test(label.replace(/-/g, ""))) return true;
      }
    }
    if (/(^|\.)(blob|bucket|objstore|objectstore|filestore|object-storage|file-storage)(\.|$)/i.test(h)) return true;
    if (parts.length >= 4) {
      const mid = parts.slice(0, -2);
      if (mid.some((l) => (l.length >= 8 && /[a-z]/i.test(l) && /\d/.test(l) && /^[a-z0-9-]+$/i.test(l)) || /^[a-f0-9]{10,}$/i.test(l))) return true;
    }
    if (subLabels.length >= 1) {
      const first = subLabels[0] || "";
      if (first.length >= 18 && /^[a-z0-9-]+$/i.test(first) && /\d/.test(first) && /[a-z]/i.test(first)) {
        if (/(?:mirror|mirrors|package|download|cdn|static|client|release|asset|media|update|files?|dist|build|prod|game)/i.test(first)) { /* not anonymous */ }
        else if ((first.match(/\d/g) || []).length >= 4) return true;
      }
    }
    return false;
  };

  NS.pathHasOpaqueStorageSegments = function (pathname) {
    const segs = String(pathname || "").split("/").filter(Boolean);
    for (const s of segs) {
      const base = s.split("?")[0];
      if (/^[a-f0-9]{16,}$/i.test(base)) return true;
      if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(base)) return true;
      if (base.length >= 24 && /^[a-z0-9_-]+$/i.test(base) && /\d/.test(base) && /[a-z]/i.test(base) && !PACKAGE_NAME.test(base)) return true;
    }
    return false;
  };

  NS.looksLikeHighRiskBlobPackageUrl = function (href) {
    if (!href || !NS.isPackageFileUrl(href)) return false;
    try {
      const u = new URL(href, location.href);
      const fn = NS.getFilenameFromUrl(u.href);
      if (NS.looksLikeStrongProductInstallerName(fn)) return false;
      if (NS.isAnonymousPublicObjectHost(u.hostname) && !NS.looksLikeProductPackageName(fn) && !NS.isClearProductOrAndroidPackage(fn)) return true;
      if (NS.isAnonymousPublicObjectHost(u.hostname) && NS.looksLikeOversimplifiedBrandInstallerName(fn)) return true;
      try {
        const pageApex = NS.guessApexDomain(location.hostname) || NS.getRegistrableDomain(location.hostname);
        const pkgApex = NS.guessApexDomain(u.hostname) || NS.getRegistrableDomain(u.hostname);
        if (pageApex && pkgApex && pageApex !== pkgApex && NS.hostLooksLikePublicObjectStorageEndpoint(u.hostname)
          && !NS.looksLikeProductPackageName(fn) && !NS.isClearProductOrAndroidPackage(fn)) return true;
      } catch { /* ignore */ }
      return NS.looksLikeObjectStorageHost(u.hostname) && NS.pathHasOpaqueStorageSegments(u.pathname) && !NS.looksLikeStrongProductInstallerName(fn);
    } catch {
      return false;
    }
  };

  NS.looksLikeOversimplifiedBrandInstallerName = function (fileName) {
    const name = NS.normalizeFileName(fileName);
    if (!name || !PACKAGE_NAME.test(name)) return false;
    const base = name.replace(/\.[^.]+$/, "");
    if (/\d+\.\d+\.\d+/.test(base)) return false;
    if (/^(?:[a-z][a-z0-9_]*\.){2,}/i.test(base)) return false;
    if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(base) && (/\d+\.\d+/.test(base) || /[._-]\d{4,}/.test(base))) return false;
    if (/^[a-z][a-z0-9]{2,16}[._-](?:win|windows|mac|osx|linux|x64|x86|amd64|arm64)(?:[._-](?:x64|x86|amd64|arm64|win|mac))?$/i.test(base)) return true;
    if (/^[A-Za-z][A-Za-z0-9]{2,28}[._-]v?\d{1,3}[._-](?:win|windows|mac|osx|linux|x64|x86|amd64|arm64)(?:[._-](?:x64|x86|64|32))?$/i.test(base)) return true;
    if (/^[A-Za-z][A-Za-z0-9]{2,28}[._-](?:win|windows|mac|osx|linux)(?:[._-](?:x64|x86|64|32))?$/i.test(base) && !/\d+\.\d+/.test(base)) return true;
    return false;
  };

  NS.looksLikeObjectStoragePackageUrl = function (href) {
    if (!href || !NS.isPackageFileUrl(href)) return false;
    try {
      const u = new URL(href, location.href);
      const fn = NS.getFilenameFromUrl(u.href);
      const baseFn = (fn || "").replace(/\.[^.]+$/, "");
      if (/[a-zA-Z一-鿿]{4,}[._-](?:official[_-]?)?(?:setup|install|installer|client)/i.test(baseFn) && (/\d+\.\d+/.test(baseFn) || /[._-]\d{4,}/.test(baseFn))) return false;
      const oversimple = NS.looksLikeOversimplifiedBrandInstallerName(fn);
      const clearPkg = NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(u.href) || NS.isBenignShortInstallerName(fn) || NS.looksLikeProductPackageName(fn);
      const strongProduct = NS.looksLikeStrongProductInstallerName(fn);
      const hostHit = NS.looksLikeObjectStorageHost(u.hostname);
      const opaquePath = NS.pathHasOpaqueStorageSegments(u.pathname);
      const anonHost = NS.isAnonymousPublicObjectHost(u.hostname);
      const publicOss = NS.hostLooksLikePublicObjectStorageEndpoint(u.hostname);
      let pageApex = "";
      try { pageApex = NS.guessApexDomain(location.hostname) || NS.getRegistrableDomain(location.hostname); } catch { pageApex = ""; }
      const pkgApex = NS.guessApexDomain(u.hostname) || NS.getRegistrableDomain(u.hostname);
      const offsite = pageApex && pkgApex && pageApex !== pkgApex;
      if (strongProduct && !NS.looksLikeBrandNearMissPackageName(fn)) return false;
      if (anonHost) return true;
      if (offsite && publicOss && !clearPkg) return true;
      if (clearPkg) {
        if (strongProduct) return false;
        if ((hostHit || publicOss) && oversimple) return true;
        if (hostHit && opaquePath) return true;
        if (offsite && publicOss && oversimple) return true;
        if (offsite && hostHit && NS.looksLikeBrandNearMissPackageName(fn)) return true;
        return false;
      }
      if (hostHit) return true;
      if (offsite && opaquePath) return true;
      if (offsite && NS.looksLikeRandomDownloadHost(u.hostname)) return true;
      if (offsite) {
        const parts = u.hostname.toLowerCase().split(".").filter(Boolean);
        if (parts.length >= 3) {
          const left = parts[0] || "";
          if (left.length >= 10 && /\d/.test(left) && /[a-z]/i.test(left) && !/cdn|static|download|dl|update|img|ssl/i.test(left) && !/[a-z]{3,}/i.test(left.replace(/\d+/g, ""))) return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  };

  NS.looksLikeBrandNearMissPackageName = function (fileName) {
    const name = NS.normalizeFileName(fileName);
    if (!name || !PACKAGE_NAME.test(name)) return false;
    const base = name.replace(/\.[^.]+$/, "").replace(/\s+/g, "");
    if (/\s+\.(zip|exe|apk|msi|dmg|rar|7z)$/i.test(NS.normalizeFileName(fileName).replace(/%20/g, " ")) || /\s/.test(String(fileName || "").split("/").pop() || "")) return true;
    const title = `${document.title || ""} ${(document.body && document.body.innerText) || ""}`.slice(0, 2000);
    const brandTokens = (title.match(/[A-Za-z]{4,}/g) || []).map((t) => t.toLowerCase())
      .filter((t) => t.length >= 4 && !/^(download|windows|linux|android|macos|official|client|software|remote|free|desk|home|page|site|http|https)$/i.test(t));
    const stem = base.toLowerCase().replace(/[._-]/g, "");
    for (const b of brandTokens) {
      if (stem === b || stem.startsWith(b)) continue;
      if (b.length >= 4 && stem.length >= 4) {
        let common = 0;
        while (common < b.length && common < stem.length && b[common] === stem[common]) common++;
        if (common >= 4 && b !== stem.slice(0, b.length) && stem.includes(b.slice(0, 4)) && !stem.includes(b)) return true;
        if (Math.abs(b.length - stem.replace(/\d/g, "").length) <= 2) {
          const letters = stem.replace(/[0-9._-]/g, "");
          if (letters.length >= 4 && b.length >= 4 && letters !== b && letters.slice(0, 4) === b.slice(0, 4) && letters !== b) return true;
        }
      }
    }
    return false;
  };

  NS.isThreatObjectStoragePackage = function (href, element) {
    if (!NS.looksLikeObjectStoragePackageUrl(href) && !NS.looksLikeHighRiskBlobPackageUrl(href)) return false;
    const fn = NS.getFilenameFromUrl(href);
    try {
      const host = new URL(href, location.href).hostname;
      if (NS.isAnonymousPublicObjectHost(host)) return true;
      if (NS.hostLooksLikePublicObjectStorageEndpoint(host) && NS.looksLikeObjectStoragePackageUrl(href)) return true;
    } catch { /* ignore */ }
    if (NS.looksLikeHighRiskBlobPackageUrl(href)) return true;
    if (NS.looksLikeBrandNearMissPackageName(fn)) return true;
    if (NS.isClearProductOrAndroidPackage(fn) || NS.isClearProductOrAndroidPackage(href) || NS.looksLikeProductPackageName(fn)) {
      if (NS.looksLikeHighRiskBlobPackageUrl(href)) return true;
      if (NS.looksLikeObjectStoragePackageUrl(href) && NS.looksLikeOversimplifiedBrandInstallerName(fn)) return true;
      return false;
    }
    if (NS.pageClaimsOfficialDownload() && NS.isSuspiciousDownloadFilename(fn)) return true;
    if (element && NS.isDownloadIntentElement(element) && NS.isSuspiciousDownloadFilename(fn)) return true;
    return false;
  };

  NS.looksLikeRandomDownloadHost = function (hostname) {
    if (!hostname) return false;
    const h = hostname.toLowerCase().replace(/^www\./, "");
    const parts = h.split(".");
    if (parts.length < 2) return false;
    const label = (parts[0] || "").replace(/-/g, "");
    if (/^(?:cdn|static|img|image|images|media|assets|download|downloads|dl|update|ssl|res|resource|soft|package|pkg|file|files|mirrors?|mirror|store|app|apps|api|www\d*|s\d+|p\d+|v\d+)$/i.test(label)) return false;
    if (/[a-z]{3,}/i.test(label.replace(/\d+/g, "")) && (label.match(/\d/g) || []).length <= 3 && label.length <= 14) return false;
    if (label.length >= 6 && /[a-z]/i.test(label) && /\d/.test(label) && !/[a-z]{4,}/i.test(label.replace(/\d+/g, ""))) return true;
    if (label.length >= 10 && /^[a-z0-9]+$/i.test(label) && /\d/.test(label) && (label.match(/\d/g) || []).length >= 3 && !/[a-z]{4,}/i.test(label.replace(/\d+/g, ""))) return true;
    if (/^[a-z]{1,3}\d{3,}[a-z0-9]*$/i.test(label) && label.length >= 6) return true;
    return false;
  };

  NS.looksLikeOpaqueDownloadHopUrl = function (href) {
    if (!href || typeof href !== "string") return false;
    const trimmed = href.trim();
    if (!trimmed || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(trimmed)) return false;
    try {
      const u = new URL(trimmed, location.href);
      const path = u.pathname.toLowerCase().replace(/\/+$/, "") || "/";
      const segments = path.split("/").filter(Boolean);
      if (segments.length === 0) return false;
      const last = segments[segments.length - 1] || "";
      if (PACKAGE_EXT.test(path)) return false;
      if (/\.(html?|php|aspx?|jsp|htm)(?:$|\?)/i.test(path) && !/\d+down/i.test(path)) return false;
      return /^(?:\d{2,}down|down\d{2,}|dl\d{2,}|getfile|getdown|soft\d+|file\d+|pkg\d+)$/i.test(last) || /\/(?:\d{2,}down|down\d{2,}|dl\d{2,})(?:\/)?$/i.test(path);
    } catch {
      return false;
    }
  };

  NS.looksLikeSearchEngineLandingUrl = function (url) {
    try {
      const u = new URL(url, location.href);
      if (/\.(zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?|#|$)/i.test(u.pathname || "") || PACKAGE_EXT.test(u.href)) return false;
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
  };

  NS.isSiteHomeUrl = function (href) {
    try {
      const u = new URL(href, location.href);
      const path = (u.pathname || "/").replace(/\/+$/, "") || "";
      return path === "" || path === "/";
    } catch {
      return false;
    }
  };

  NS.isSamePageBrandApex = function (href) {
    try {
      const u = new URL(href, location.href);
      const a = NS.getRegistrableDomain(u.hostname);
      const b = NS.getRegistrableDomain(location.hostname);
      return !!(a && b && a === b);
    } catch {
      return false;
    }
  };

  NS.looksLikeOfficialProductDownloadEndpoint = function (href) {
    if (!href || /^(javascript:|#|data:|blob:|mailto:|tel:)/i.test(href)) return false;
    try {
      if (typeof NS.hostLooksLikeBrandMarketingSpoof === "function" && NS.hostLooksLikeBrandMarketingSpoof()) return false;
      const u = new URL(href, location.href);
      if (!NS.isSamePageBrandApex(u.href)) return false;
      const path = (u.pathname || "").toLowerCase().replace(/\/+$/, "") || "/";
      const base = (path.split("/").filter(Boolean).pop() || "").split("?")[0];
      if (/^(?:\d{2,}down|down\d{2,}|dl\d{2,}|getfile|getdown)$/i.test(base.replace(/\.[^.]+$/, ""))) return false;
      if (/^\/(?:win|windows|mac|osx|macos|linux|android|ios|pc|desktop)(?:\/(?:d|dl|download|get|installer?))?$/i.test(path)) return true;
      if (/^\/(?:download|downloads|getclient|getapp|client)(?:\/[a-z0-9._-]{0,32})?$/i.test(path)) return true;
      const bareDownloadPhp = /^(?:download|down|getdown|getfile)\.(?:php|asp|aspx|jsp)$/i.test(base);
      if (/\.(php|asp|aspx|jsp)$/i.test(base)) {
        if (bareDownloadPhp) return typeof NS.isTrustedOfficialDownloadContext === "function" && NS.isTrustedOfficialDownloadContext() && !NS.hostLooksLikeBrandMarketingSpoof();
        if (/^download[a-z0-9._-]+\./i.test(base)) return true;
        if (/^get(?:file|down|soft|client|setup|installer)[a-z0-9._-]*\./i.test(base)) return true;
        if (/\/(?:product|products|download|soft|client|support)\/[^?#]*download/i.test(path)) return true;
        if (/\/download\/[a-z0-9._-]+\.(php|asp|aspx|jsp)$/i.test(path) && !/[a-f0-9]{12,}/i.test(path)) return true;
      }
      if (NS.isPackageFileUrl(u.href)) {
        const fn = NS.getFilenameFromUrl(u.href);
        if (NS.looksLikeProductPackageName(fn) && !NS.looksLikeObjectStoragePackageUrl(u.href)) return true;
      }
      return false;
    } catch {
      return false;
    }
  };

  NS.isAuthSsoOrLoginRedirectUrl = function (href) {
    try {
      if (!href || typeof href !== "string") return false;
      const u = new URL(href, location.href);
      if (!/^https?:$/i.test(u.protocol)) return false;
      const path = (u.pathname || "").toLowerCase();
      const host = (u.hostname || "").toLowerCase();
      const q = u.search || "";
      if (PACKAGE_EXT.test(path) || PACKAGE_EXT.test(u.href)) return false;
      if (/\/(?:saml2?|sso|oauth2?|oidc|openid(?:-connect)?|adfs|cas|idp)(?:\/|$)/i.test(path)) return true;
      if (/\/default\/saml\//i.test(path) || /\/idp\/(?:sso|login|profile|start)/i.test(path)) return true;
      if (/\/oauth2?\/(?:v\d+\/)?(?:authorize|auth|token|logout)/i.test(path)) return true;
      if (/\/(?:login|signin|sign-in|logon|authenticate)(?:\/|$)/i.test(path) && /[?&](?:SAMLRequest|SAMLResponse|RelayState|client_id|response_type|redirect_uri|code_challenge|scope)=/i.test(q)) return true;
      if (/(?:^|\.)(?:login|sso|auth|accounts|access|idp|sts|adfs|signin)\./i.test(host) && /saml|sso|oauth|openid|authorize|idp|login|auth/i.test(path + q)) return true;
      if (/(?:^|\.)(?:okta\.com|auth0\.com|microsoftonline\.com|windows\.net|google\.com|onelogin\.com|pingidentity\.com|duo\.com|cloudflareaccess\.com)$/i.test(host)) return true;
      return false;
    } catch {
      return false;
    }
  };

  NS.formatPackageLabel = function (href) {
    if (!href) return "可疑下载目标";
    try {
      const cleaned = NS.normalizeFileName(href);
      if (cleaned && PACKAGE_NAME.test(cleaned)) return cleaned;
      const u = new URL(href, location.href);
      const name = NS.normalizeFileName(u.pathname.split("/").filter(Boolean).pop() || "");
      if (name && PACKAGE_NAME.test(name)) return name;
      if (NS.looksLikeOpaqueDownloadHopUrl(href)) return `${u.hostname}${u.pathname}`;
      if (name) return name;
      if (cleaned) return cleaned;
    } catch {
      const cleaned = NS.normalizeFileName(href);
      if (cleaned) return cleaned;
    }
    return "可疑下载目标";
  };

  NS.extractPackageUrlFromHandlerText = function (text) {
    if (!text || typeof text !== "string") return [];
    const found = [];
    const re = /https?:\/\/[^\s"'<>\\]+?\.(?:zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?[^\s"'<>\\]*)?/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      let u = m[0].replace(/[),;]+$/, "");
      try { u = decodeURIComponent(u); } catch { /* keep */ }
      if (NS.isPackageFileUrl(u)) found.push(u);
    }
    const re2 = /(?:window\.open|location\.href\s*=|location\.assign\s*\()\s*[(]?\s*['"]([^'"]+\.(?:zip|exe|apk|dmg|msi|rar|7z|pkg|appx)(?:\?[^'"]*)?)['"]/gi;
    while ((m = re2.exec(text)) !== null) {
      const raw = m[1];
      if (!raw) continue;
      try {
        const abs = new URL(raw, location.href).href;
        if (NS.isPackageFileUrl(abs)) found.push(abs);
      } catch { /* ignore */ }
    }
    return found;
  };

  NS.collectAllPagePackageHrefs = function () {
    const set = new Set();
    const MAX = 80;
    const add = (h) => {
      if (set.size >= MAX) return;
      if (!h || typeof h !== "string") return;
      const t = h.trim();
      if (!t || /^(javascript:|#)$/i.test(t)) return;
      try {
        const abs = new URL(t, location.href).href;
        if (NS.isPackageFileUrl(abs)) set.add(abs);
      } catch {
        if (NS.isPackageFileUrl(t)) set.add(t);
      }
    };
    const archiveHeavy = typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive();
    const nodeCap = archiveHeavy ? 60 : 400;
    try {
      const nodes = document.querySelectorAll("a[href], a[data-href], a[data-url], [data-download], [data-down]");
      const n = Math.min(nodes.length, nodeCap);
      for (let i = 0; i < n && set.size < MAX; i++) {
        add(NS.getElementDownloadHref(nodes[i]) || nodes[i].getAttribute("href") || "");
      }
    } catch { /* ignore */ }
    if (!archiveHeavy || set.size < 12) {
      try {
        const nodes2 = document.querySelectorAll("[onclick], [onmousedown], [ondblclick], button, .platform-btn, [class*='download'], [class*='platform']");
        const n2 = Math.min(nodes2.length, archiveHeavy ? 40 : 200);
        for (let i = 0; i < n2 && set.size < MAX; i++) {
          const el = nodes2[i];
          const attrs = ["onclick", "onmousedown", "ondblclick", "data-href", "data-url", "data-link", "href"];
          for (const a of attrs) {
            const v = el.getAttribute && el.getAttribute(a);
            if (v) NS.extractPackageUrlFromHandlerText(v).forEach(add);
          }
        }
      } catch { /* ignore */ }
    }
    if (!archiveHeavy) {
      try { NS.extractPackageUrlFromHandlerText(NS.getThreatScanHtml(80000)).forEach(add); } catch { /* ignore */ }
    }
    return Array.from(set);
  };

  NS.isMultiCtaPlatformOrTierLabel = function (text) {
    const t = String(text || "").replace(/\s+/g, " ").trim();
    if (!t || t.length > 48) return false;
    return /Windows|macOS|Mac\s*OS|Linux|Android|iOS|iPad|Win(?:dows)?|个人|企业|免费|试用|专业|性能|游戏|客户端|官方下载|立即下载|免费下载/i.test(t);
  };

  NS.getElementDownloadHref = function (el) {
    if (!el) return "";
    const keys = ["href", "data-href", "data-url", "data-download", "data-down", "data-link", "data-threat-original-href"];
    for (const k of keys) {
      const v = (el.getAttribute && el.getAttribute(k)) || "";
      if (v && String(v).trim() && !/^(javascript:|#)$/i.test(String(v).trim())) return String(v).trim();
    }
    try {
      for (const a of ["onclick", "onmousedown", "ondblclick"]) {
        const v = el.getAttribute && el.getAttribute(a);
        if (!v) continue;
        const found = NS.extractPackageUrlFromHandlerText(v);
        if (found.length) return found[0];
      }
    } catch { /* ignore */ }
    return "";
  };

  NS.getDownloadButtons = function () {
    const c = NS.caches;
    const now = Date.now();
    if (c._dlBtnCache && now - c._dlBtnCacheAt < 2000) return c._dlBtnCache;
    let els = [];
    try {
      els = Array.from(document.querySelectorAll(
        "a.download-btn, a.btn-download, .download-btn, .btn-download, a[class*='download'], button[class*='download'], a[href*='download']"
      ));
    } catch { els = []; }
    if (els.length < 2) {
      try {
        const more = document.querySelectorAll("a[href], button, [role='button']");
        const limit = Math.min(more.length, 80);
        for (let i = 0; i < limit; i++) els.push(more[i]);
      } catch { /* ignore */ }
    }
    const out = [];
    const seen = new Set();
    for (const el of els) {
      if (!el || seen.has(el)) continue;
      seen.add(el);
      const text = (el.textContent || "").trim().slice(0, 80);
      const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
      if (DOWNLOAD_TEXT.test(text) || /download|install|setup|apk|exe|zip|dmg|msi|pkg|appx/i.test(href)) {
        out.push(el);
        if (out.length >= 24) break;
      }
    }
    c._dlBtnCache = out;
    c._dlBtnCacheAt = now;
    return out;
  };

  NS.isDownloadIntentElement = function (el) {
    if (!el) return false;
    if (NS.pageLooksLikeSearchEngineResultsPage()) {
      const href = (el.getAttribute && (el.getAttribute("href") || el.getAttribute("data-href"))) || "";
      return !!(href && NS.isPackageFileUrl(href));
    }
    let text = "";
    try {
      text = `${el.getAttribute("aria-label") || ""} ${el.getAttribute("title") || ""}`.trim();
      if (!text || text.length > 80) {
        const raw = (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim();
        text = raw.slice(0, 64);
      }
    } catch {
      text = (el.textContent || "").trim().slice(0, 64);
    }
    const className = `${el.className || ""} ${el.id || ""}`;
    const classDl = /(?:^|[\s_-])(?:btn[-_]?download|download[-_]?btn|download[-_]?uri|btn[-_]?install|install[-_]?btn|setup[-_]?btn)(?:[\s_-]|$)/i.test(className) || /(?:^|[\s])download(?:[\s]|$)/i.test(className);
    return DOWNLOAD_TEXT.test(text) || /电脑端|电脑版|Mac版|Windows|Linux|Android|iOS|立即下载|客户端|云电脑|免费下载|官方下载/i.test(text) || classDl;
  };

  NS.getAllDownloadIntentElements = function () {
    // 海量镜像/归档页禁止全量扫 a，否则主线程卡死
    try {
      if ((typeof NS.pageLooksLikeHighDensityDownloadList === "function" && NS.pageLooksLikeHighDensityDownloadList())
        || (typeof NS.pageLooksLikeHighVolumePackageArchive === "function" && NS.pageLooksLikeHighVolumePackageArchive())
        || (typeof NS.pageLooksLikeOsDistroIsoDownload === "function" && NS.pageLooksLikeOsDistroIsoDownload())) {
        const small = document.querySelectorAll(
          "a.download-btn, a.btn-download, .download-btn, button[class*='download'], a[href*='.exe'], a[href*='.zip']"
        );
        return Array.from(small).filter((el) => NS.isDownloadIntentElement(el)).slice(0, 24);
      }
    } catch { /* ignore */ }
    const nodes = document.querySelectorAll("a, button, [role='button'], input[type='button'], input[type='submit']");
    const cap = Math.min(nodes.length, 200);
    const out = [];
    for (let i = 0; i < cap; i++) {
      if (NS.isDownloadIntentElement(nodes[i])) {
        out.push(nodes[i]);
        if (out.length >= 40) break;
      }
    }
    return out;
  };

  NS.disableAllDownloadIntentControls = function () {
    const state = NS.state;
    const seen = new Set();
    const disableEl = (el) => {
      if (!el || seen.has(el)) return;
      seen.add(el);
      const href = (el.getAttribute("href") || el.getAttribute("data-href") || el.getAttribute("data-threat-original-href") || state.protectedTargets[0] || "").trim();
      NS.disableOneSuspiciousElement(el, href || "js-download");
    };
    NS.getAllDownloadIntentElements().forEach(disableEl);
    try {
      document.querySelectorAll(
        "a.download-uri, .download-uri, a.download-btn, .download-btn, .download-btn-nav, a.btn-download, .btn-download, #mainDownloadBtn, .platform-btn, button.platform-btn, [class*='btn-download'], [class*='download-btn'], [class*='Download'], a[class*='down'], button[class*='down']"
      ).forEach(disableEl);
    } catch { /* ignore */ }
    // 文案兜底：短 CTA
    try {
      document.querySelectorAll("a, button, [role='button']").forEach((el) => {
        const t = (el.textContent || "").replace(/\s+/g, " ").trim();
        if (t.length > 0 && t.length < 36 && /立即下载|免费下载|官方下载|客户端下载|电脑版|Windows\s*版|Mac\s*版|下载客户端|一键下载/i.test(t)) disableEl(el);
      });
    } catch { /* ignore */ }
    // 同源 iframe 内部下载按钮（跨源由 postToHooks 广播 + all_frames MAIN 钩子处理）
    try {
      document.querySelectorAll("iframe").forEach((frame) => {
        try {
          const doc = frame.contentDocument;
          if (!doc) return;
          doc.querySelectorAll(
            "a, button, [role='button'], a.download-btn, .download-btn, [class*='download']"
          ).forEach((el) => {
            try {
              const t = (el.textContent || "").replace(/\s+/g, " ").trim();
              const href = (el.getAttribute("href") || el.getAttribute("data-href") || "").trim();
              if (NS.isDownloadIntentElement(el)
                || (t.length > 0 && t.length < 40 && /下载|安装|客户端|Download/i.test(t))
                || /\.(?:exe|zip|msi|apk|dmg)(?:\?|$)/i.test(href)) {
                disableEl(el);
              }
            } catch { /* ignore */ }
          });
        } catch { /* cross-origin */ }
      });
    } catch { /* ignore */ }
    try { if (state.downloadGuardInstalled && typeof NS.applyDownloadGuardDomLock === "function") NS.applyDownloadGuardDomLock(true); } catch { /* ignore */ }
    try { if (state.downloadGuardInstalled && typeof NS.neutralizePageFramesForGuard === "function") NS.neutralizePageFramesForGuard(true); } catch { /* ignore */ }
    try { if (state.downloadGuardInstalled && typeof NS.scrubHostileLoadingOverlays === "function") NS.scrubHostileLoadingOverlays(); } catch { /* ignore */ }
  };

  NS.tryDecodeBase64Payload = function (str, maxLayers = 5) {
    let s = String(str || "").replace(/\s+/g, "");
    if (s.length < 16 || s.length > 8000) return "";
    for (let i = 0; i < maxLayers; i++) {
      try {
        const bin = atob(s);
        let text = bin;
        try { text = decodeURIComponent(escape(bin)); } catch { /* keep binary latin1 */ }
        if (/https?:\/\/[^\s"'<>]+/i.test(text) || PACKAGE_EXT.test(text) || /[a-z0-9._-]{4,}\.(zip|exe|apk|msi|dmg)/i.test(text)) return text;
        const compact = text.replace(/\s+/g, "");
        if (/^[A-Za-z0-9+/]+=*$/.test(compact) && compact.length >= 16) { s = compact; continue; }
        return text;
      } catch {
        break;
      }
    }
    return "";
  };

  NS.isEmbeddedPackageThreat = function (nameOrUrl) {
    const name = NS.normalizeFileName(/https?:\/\//i.test(String(nameOrUrl || "")) ? NS.getFilenameFromUrl(nameOrUrl) : nameOrUrl);
    if (!name || !NS.isPlausiblePackageFileName(name)) return false;
    if (NS.isClearProductOrAndroidPackage(name) || NS.isBenignShortInstallerName(name) || NS.looksLikeProductPackageName(name)) {
      if (/https?:\/\//i.test(String(nameOrUrl || ""))) return NS.looksLikeHighRiskBlobPackageUrl(nameOrUrl);
      return false;
    }
    const safeOfficial = NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal();
    if (NS.isContentAddressedPackageName(name)) {
      if (/https?:\/\//i.test(String(nameOrUrl || ""))) return NS.looksLikeHighRiskBlobPackageUrl(nameOrUrl);
      return false;
    }
    if (!NS.isSuspiciousDownloadFilename(name)) return false;
    if (safeOfficial) {
      if (/https?:\/\//i.test(String(nameOrUrl || ""))) return NS.looksLikeHighRiskBlobPackageUrl(nameOrUrl);
      return false;
    }
    return true;
  };

  NS.scanEmbeddedPackageThreats = function () {
    const state = NS.state;
    let found = null;
    try {
      const html = NS.getHtmlSlice(120000);
      const safeOfficial = NS.looksLikeSafeOfficialContext() || NS.looksLikeMatureOfficialPortal();
      const pkgRe = /([A-Za-z][A-Za-z0-9._-]{2,80}\.(?:zip|exe|apk|msi|dmg|rar|7z))(?:\b|(?=[?"'#\s<>]))/gi;
      let m;
      while ((m = pkgRe.exec(html)) !== null) {
        const name = NS.normalizeFileName(m[1]);
        if (!name || !NS.isPlausiblePackageFileName(name)) continue;
        if (!NS.isEmbeddedPackageThreat(name)) continue;
        found = found || name;
        if (!state.protectedTargets.includes(name)) state.protectedTargets.push(name);
      }
      const fieldRe = /"(?:windowsDownload|macDownload|linuxDownload|androidDownload|iosDownload|downloadUrl|download_url|download_link|packageUrl)"\s*:\s*"([^"]{16,})"/gi;
      while ((m = fieldRe.exec(html)) !== null) {
        const raw = m[1];
        const decoded = NS.tryDecodeBase64Payload(raw) || raw;
        const urls = decoded.match(/https?:\/\/[^\s"'<>]+/gi) || [];
        const names = decoded.match(/[A-Za-z][A-Za-z0-9._-]{2,80}\.(?:zip|exe|apk|msi|dmg|rar|7z)\b/gi) || [];
        for (const u of urls) {
          const fname = NS.getFilenameFromUrl(u);
          if (!NS.isPlausiblePackageFileName(fname)) continue;
          if (NS.isPackageFileUrl(u) && NS.isEmbeddedPackageThreat(u)) {
            found = found || fname || u;
            if (!state.protectedTargets.includes(u)) state.protectedTargets.push(u);
          } else if (!NS.isPackageFileUrl(u) && NS.looksLikeOpaqueDownloadHopUrl(u) && !safeOfficial) {
            found = found || u;
            if (!state.protectedTargets.includes(u)) state.protectedTargets.push(u);
          }
        }
        for (const name of names) {
          const n = NS.normalizeFileName(name);
          if (!NS.isEmbeddedPackageThreat(n)) continue;
          found = found || n;
          if (!state.protectedTargets.includes(n)) state.protectedTargets.push(n);
        }
        if (/[A-Za-z0-9+/]{20,}={0,2}/.test(raw) && !urls.length) {
          const d = NS.tryDecodeBase64Payload(raw);
          const n = (d.match(/[A-Za-z0-9][A-Za-z0-9._-]{2,80}\.(?:zip|exe|apk|msi|dmg)/i) || [])[0];
          if (n && NS.isEmbeddedPackageThreat(n)) {
            found = found || n;
            if (!state.protectedTargets.includes(n)) state.protectedTargets.push(n);
          }
        }
      }
      if (safeOfficial) return found;
      const b64Re = /[A-Za-z0-9+/]{48,}={0,2}/g;
      let count = 0;
      while ((m = b64Re.exec(html)) !== null && count < 40) {
        count++;
        const decoded = NS.tryDecodeBase64Payload(m[0]);
        if (!decoded) continue;
        const names = decoded.match(/[A-Za-z0-9][A-Za-z0-9._-]{2,80}\.(?:zip|exe|apk|msi|dmg)/gi) || [];
        for (const name of names) {
          if (!NS.isEmbeddedPackageThreat(name)) continue;
          found = found || name;
          if (!state.protectedTargets.includes(name)) state.protectedTargets.push(name);
        }
        const urls = decoded.match(/https?:\/\/[^\s"'<>]+\.(?:zip|exe|apk|msi|dmg)[^\s"'<>]*/gi) || [];
        for (const u of urls) {
          if (!NS.isEmbeddedPackageThreat(u)) continue;
          const fname = NS.getFilenameFromUrl(u);
          found = found || fname || u;
          if (!state.protectedTargets.includes(u)) state.protectedTargets.push(u);
        }
      }
    } catch { /* ignore */ }
    return found;
  };

  NS.unescapeHtmlForScan = function (html) {
    return String(html || "").replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/u002[fF]/g, "/");
  };

  NS.guessApexDomain = function (hostname) { return NS.getRegistrableDomain(hostname); };
})(window.SilverfoxContent ??= {});
