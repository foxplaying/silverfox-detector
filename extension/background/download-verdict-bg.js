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
    if (PackageHeuristicsBg.looksLikeAndroidPackageIdName(baseFromName) || PackageHeuristicsBg.looksLikeAndroidPackageIdName(name) || PackageHeuristicsBg.looksLikeAndroidPackageIdName(PackageHeuristicsBg.basenameFromPath(url))) return { cancel: false };
    if (PackageHeuristicsBg.looksLikeStrongProductInstallerName(name) || PackageHeuristicsBg.looksLikeStrongProductInstallerName(PackageHeuristicsBg.basenameFromPath(url))) return { cancel: false };
    const oversimple = PackageHeuristicsBg.looksLikeOversimplifiedBrandInstallerName(name) || PackageHeuristicsBg.looksLikeOversimplifiedBrandInstallerName(PackageHeuristicsBg.basenameFromPath(url));
    try {
      const host = new URL(url).hostname;
      const isPkg = PackageHeuristicsBg.PACKAGE_NAME_RE.test(name) || PackageHeuristicsBg.PACKAGE_NAME_RE.test(PackageHeuristicsBg.basenameFromPath(url)) || PackageHeuristicsBg.PACKAGE_NAME_RE.test(new URL(url).pathname);
      if (isPkg && (PackageHeuristicsBg.isAnonymousPublicObjectHost(host) || PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(host) || PackageHeuristicsBg.looksLikeObjectStoragePackageUrl(url) || (oversimple && PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(host)))) return { cancel: true, label: name || url };
      if (isPkg && oversimple && (PackageHeuristicsBg.isAnonymousPublicObjectHost(host) || PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(host))) return { cancel: true, label: name || url };
    } catch { /* ignore */ }
    if (item.tabId != null && NS.protectedTabs.has(item.tabId)) {
      if (PackageHeuristicsBg.PACKAGE_NAME_RE.test(name) || PackageHeuristicsBg.PACKAGE_NAME_RE.test(PackageHeuristicsBg.basenameFromPath(url)) || PackageHeuristicsBg.looksLikeOpaqueHopUrl(url)) return { cancel: true, label: name || url };
      if (PackageHeuristicsBg.looksLikeObjectStoragePackageUrl(url)) return { cancel: true, label: name || url };
    }
    if (!oversimple && (PackageHeuristicsBg.looksLikeProductPackageName(name) || PackageHeuristicsBg.looksLikeProductPackageName(PackageHeuristicsBg.basenameFromPath(url)))) {
      try { const host = new URL(url).hostname; if (!PackageHeuristicsBg.hostLooksLikePublicObjectStorageEndpoint(host) && !PackageHeuristicsBg.isAnonymousPublicObjectHost(host)) return { cancel: false }; } catch { return { cancel: false }; }
    }
    if (PackageHeuristicsBg.isSuspiciousPackageFilename(name)) return { cancel: true, label: name || url };
    if (PackageHeuristicsBg.isSuspiciousPackageFilename(PackageHeuristicsBg.basenameFromPath(url))) return { cancel: true, label: PackageHeuristicsBg.basenameFromPath(url) };
    if (PackageHeuristicsBg.looksLikeOpaqueHopUrl(url)) return { cancel: true, label: url };
    return { cancel: false };
  };
})(self.SilverfoxBackground ??= {});
