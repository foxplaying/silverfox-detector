/**
 * 下载取消判定：decide whether a chrome.downloads item should be cancelled.
 */
;(function (NS) {
  "use strict";

  const { PackageHeuristicsBg } = NS;

  /** 决定是否取消某下载项。强产品永不取消；高熵桶/保护标签页/可疑文件名取消。 */
  NS.shouldCancelDownload = function (item) {
    const url = item.finalUrl || item.url || "";
    const name = PackageHeuristicsBg.basenameFromPath(item.filename) || PackageHeuristicsBg.basenameFromPath(url);
    const baseFromName = String(name || "").replace(/\.[^.]+$/, "");
    const nameFromUrl = PackageHeuristicsBg.basenameFromPath(url);
    if (PackageHeuristicsBg.looksLikeAndroidPackageIdName(baseFromName)
      || PackageHeuristicsBg.looksLikeAndroidPackageIdName(name)
      || PackageHeuristicsBg.looksLikeAndroidPackageIdName(nameFromUrl)) {
      return { cancel: false };
    }
    if (PackageHeuristicsBg.looksLikeStrongProductInstallerName(name)
      || PackageHeuristicsBg.looksLikeStrongProductInstallerName(nameFromUrl)) {
      return { cancel: false };
    }
    // ICP/WHOIS 已核验且无真实硬威胁的来源页：文件名/CDN 启发式只做后台 VT，不预先取消。
    if (typeof NS.getTrustedDownloadSource === "function" && NS.getTrustedDownloadSource(item)) {
      return { cancel: false, trustedSource: true };
    }

    const oversimple = PackageHeuristicsBg.looksLikeOversimplifiedBrandInstallerName(name)
      || PackageHeuristicsBg.looksLikeOversimplifiedBrandInstallerName(nameFromUrl);
    // ★ 可读产品/曲包名优先放行（须在 OSS / 保护页整包取消之前），
    // 否则 Phira 谱面挂 COS/OSS 或软 arm 保护页会被误杀。
    const readableProduct = !oversimple && (
      PackageHeuristicsBg.looksLikeProductPackageName(name)
      || PackageHeuristicsBg.looksLikeProductPackageName(nameFromUrl)
    );

    try {
      const host = new URL(url).hostname;
      const isPkg = PackageHeuristicsBg.PACKAGE_NAME_RE.test(name)
        || PackageHeuristicsBg.PACKAGE_NAME_RE.test(nameFromUrl)
        || PackageHeuristicsBg.PACKAGE_NAME_RE.test(new URL(url).pathname);
      const anonHost = PackageHeuristicsBg.isAnonymousPublicObjectHost(host);
      const publicOss = PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(host);
      const ossUrl = PackageHeuristicsBg.looksLikeObjectStoragePackageUrl(url);

      // 匿名高熵桶：一律取消（含可读名——桶本身不可信）
      if (isPkg && anonHost) return { cancel: true, label: name || url };
      // 公开 OSS/COS：仅拦 oversimple / 非产品名；可读曲包放行
      if (isPkg && (publicOss || ossUrl) && !readableProduct) {
        return { cancel: true, label: name || url };
      }
      if (isPkg && oversimple && (anonHost || publicOss)) {
        return { cancel: true, label: name || url };
      }
    } catch { /* ignore */ }

    if (readableProduct) return { cancel: false };

    // 保护页：仍放行可读产品包；乱码/跳转 hop 继续取消
    if (item.tabId != null && typeof NS.isTabProtected === "function" && NS.isTabProtected(item.tabId)) {
      if (PackageHeuristicsBg.looksLikeOpaqueHopUrl(url)) return { cancel: true, label: url };
      if (PackageHeuristicsBg.PACKAGE_NAME_RE.test(name)
        || PackageHeuristicsBg.PACKAGE_NAME_RE.test(nameFromUrl)) {
        return { cancel: true, label: name || url };
      }
      if (PackageHeuristicsBg.looksLikeObjectStoragePackageUrl(url)) {
        return { cancel: true, label: name || url };
      }
    }

    if (PackageHeuristicsBg.isSuspiciousPackageFilename(name)) return { cancel: true, label: name || url };
    if (PackageHeuristicsBg.isSuspiciousPackageFilename(nameFromUrl)) {
      return { cancel: true, label: nameFromUrl };
    }
    if (PackageHeuristicsBg.looksLikeOpaqueHopUrl(url)) return { cancel: true, label: url };
    return { cancel: false };
  };
})(self.SilverfoxBackground ??= {});
