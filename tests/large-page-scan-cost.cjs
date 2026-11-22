"use strict";
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const read = file => fs.readFileSync(path.join(__dirname, "../extension/content", file), "utf8");
function fixture(url, title, hrefs, spa = true) {
  const stats = { linkPasses: 0, hrefReads: 0, brandChecks: 0, trustChecks: 0, packageChecks: 0 };
  const links = hrefs.map(h => ({ tagName: "A", getAttribute() { stats.hrefReads++; return h; } }));
  const document = { title, scripts: [{src:"a"}, {src:"b"}, {src:"c"}],
    querySelector: s => s.startsWith("#ice-container") && spa ? {} : null,
    get links() { stats.linkPasses++; return links; },
    querySelectorAll(s) { if (s === "a[href]") { stats.linkPasses++; return links; } return []; } };
  const NS = { PACKAGE_EXT:/\.(exe|zip|msi)(?:\?|#|$)/i, PACKAGE_NAME:/\.(exe|zip|msi)$/i, caches:{} };
  const ctx = vm.createContext({window:{SilverfoxContent:NS}, document, location:new URL(url), URL});
  for (const f of ["package-heuristics.js", "intel-gates.js"]) vm.runInContext(read(f), ctx);
  Object.assign(NS, {shouldRejectOfficialDownloadShortcut:()=>false, pageLooksLikeOsDistroIsoDownload:()=>false,
    evaluateTitleHostBrandCorrelation:()=>({}), hostLooksLikeBrandMarketingSpoof() { stats.brandChecks++; return false; },
    getHtmlSlice:()=>"x".repeat(300), countTransparentProductPackages:()=>0, getRegistrableDomain:h=>h,
    looksLikeOfficialBrandDownloadPage:()=>false, looksLikeOfficialClientDownloadPage:()=>false,
    looksLikeSelfConsistentOfficialSite:()=>false, isTrustedOfficialDownloadContext(){stats.trustChecks++; return false;}});
  const original = NS.isPackageFileUrl;
  NS.isPackageFileUrl = href => { stats.packageChecks++; return original(href); };
  return { NS, stats, document };
}
const ordinary = Array.from({length: 5000}, (_,i)=>"/owner/repo/blob/main/file-"+i+".md");
const repo = fixture("https://github.com/optiscaler/OptiScaler","GitHub - optiscaler/OptiScaler",ordinary);
assert.equal(repo.NS.pageLooksLikeLegitimateOfficialDownload(), false);
assert.equal(repo.stats.linkPasses, 0);
const catalog = fixture("https://download.example/versions","客户端下载",[...ordinary, "/download.php", "/windows"]);
assert.equal(catalog.NS.pageLooksLikeLegitimateOfficialDownload(), true);
assert.equal(catalog.stats.hrefReads, 5002, "do not miss a real final-row endpoint");
assert.equal(catalog.stats.brandChecks, 1, "one synchronous page verdict, not one per row");
assert.equal(catalog.stats.trustChecks, 0, "no circular trust for download.php");
assert.equal(catalog.stats.packageChecks, 0, "no file classification for ordinary navigation paths");
catalog.NS.hostLooksLikeBrandMarketingSpoof = () => true;
assert.equal(catalog.NS.pageLooksLikeLegitimateOfficialDownload(), false, "no stale safe result after page changes");
assert.equal(catalog.NS.looksLikeOfficialProductDownloadEndpoint("/windows"), false);
assert.equal(catalog.NS.looksLikeOfficialProductDownloadEndpoint("https://elsewhere.example/windows",false), false);
assert.equal(catalog.NS.isPackageFileUrl("/fetch?filename=Client%2Ezip"), true);
assert.equal(catalog.NS.isPackageFileUrl("/Client.exe"), true);
console.log("PASS: repository decision performs zero link passes; 5,002-row download list needs one brand check; suspicious hosts and query-string packages still recognized");
