<div align="center">

<img src="extension/icons/icon.svg" width="96" height="96" alt="Silverfox Detector" />

English | [简体中文](./README.md)

# Silverfox Detector

Behavioral web threat detector - a Chrome extension that flags suspicious download landing pages via DOM heuristics and MAIN-world behavioral hooks.

[![Manifest](https://img.shields.io/badge/manifest-v3-blue)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Version](https://img.shields.io/badge/version-0.1.1-green)](./extension/manifest.json)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey)](./LICENSE)

</div>

> [!NOTE]
> A modular, class-based Chrome MV3 extension architecture, split into five focused module directories: `nav-boot`, `page-hooks`, `content`, `background`, and `popup`.

## Features

Silverfox Detector watches every HTTP/HTTPS page for download-phishing patterns and arms layered defenses before a malicious installer can land:

- **SEO cloaking redirect kits** (zhizhu-class) - intercepts `location.replace`/`assign`/`href` and `window.open` at `document_start` in the MAIN world, before page JS runs.
- **Brand-spoof download portals** - title/heading brand ↔ host correlation catches typo, padded, and hyphen-mirror squat domains (e.g. `todeskai.com` claiming ToDesk).
- **Encrypted Nuxt SPA shells** - detects `windowsDownload`/`macDownload` keys with opaque base64 payloads and no transparent package links.
- **Desktop force-download kits** - strips `.dlp-overlay`/`电脑版推荐` DOM and blocks hidden `a`/`iframe` package auto-downloads.
- **Remote garble package dispatch** - flags `fetchDownloadLink` -> random-host garble installer flows.
- **Object-storage package drops** - anonymous bucket / OSS / TOS / R2 packages on off-site hosts.
- **ICP / WHOIS intel** - 24h-cached multi-source ICP lookup (aizhan / beiancx / uapis) and RDAP WHOIS age; valid ICP clears soft brand-spoof false positives.
- **Download cancellation** - SW cancels suspicious `chrome.downloads` items; DNR short-burst blocks SERP bounce hops.

## Architecture

Three execution contexts, each modularized:

```
extension/
├── manifest.json
├── nav-boot/          # MAIN world, document_start - earliest Location hooks
│   ├── package-classifier.js   # PackageClassifier (static): pkg/product/SSO/SERP
│   ├── sso-detector.js         # SsoDetector (static): SAML/OAuth/IdP hops
│   ├── page-shell-detector.js  # PageShellDetector (static): SERP/official/phish shell
│   ├── cloaking-kit-scanner.js # CloakingKitScanner (stateful): zhizhu fingerprint
│   ├── gesture-tracker.js      # GestureTracker (stateful): activation window
│   ├── nav-blocker.js          # NavBlocker (stateful): shouldBlock / tryBlock
│   ├── location-guard.js       # LocationGuard (static): proto patches
│   └── index.js                # NavBoot (entry): wires modules, installs hooks
├── page-hooks/       # MAIN world, document_start - policy upgrade + DOM guard
│   ├── package-heuristics.js   # PackageHeuristics (static)
│   ├── page-context.js         # PageContext (static): SERP/light/shell
│   ├── cloaking-kit.js         # CloakingKit (static): dlp + zhizhu scoring
│   ├── download-ui.js          # DownloadUi (static): grey-out / restore
│   ├── nav-policy.js           # NavPolicy (stateful): guard/hops/gesture
│   ├── dom-guard.js            # DomGuard (static): proto wraps, scrub
│   └── index.js                # PageHooks (entry): assembles policy + hooks
├── content/          # isolated world - scan, intel, guard, UI
│   ├── state.js                # state + caches + debug + HTML sampling
│   ├── package-heuristics.js   # filename / object-storage / download-intent
│   ├── brand-heuristics.js     # eTLD+1, brand tokens, squat shapes
│   ├── brand-correlation.js    # title↔host correlation, marketing spoof
│   ├── brand-spoof-detector.js # detectBrandSpoofDownloadPortal + linked landing
│   ├── encrypted-spa.js        # pending Nuxt hydrate late rescan
│   ├── intel-gates.js          # ICP/WHOIS maturity gates, official context
│   ├── intel-network.js        # ICP/WHOIS fetch + 24h cache + probe
│   ├── page-context.js         # SERP detection, benign/DOM anomaly
│   ├── detectors.js            # SEO kit, IndexNow, multi-platform SERP
│   ├── detectors-extended.js   # clone page, remote garble, dlp, landing
│   ├── guard.js                # installDownloadGuard, toast, report, lift
│   ├── scanner.js              # scanSuspiciousPackagesFast, click intercept
│   └── lifecycle.js            # finalize, SPA reset, hooks bridge, boot
├── background/       # service worker - nav protection, downloads, intel fetch
│   ├── filename-heuristics-bg.js  # PackageHeuristicsBg (static)
│   ├── notification-bg.js         # PNG icon gen + system notifications
│   ├── nav-protection-bg.js       # DNR, force-restore, tab state
│   ├── download-verdict-bg.js     # shouldCancelDownload
│   ├── message-handler-bg.js      # fetchPageText / probe / risk / notice
│   └── background.js              # entry: state + importScripts + listeners
├── popup/
│   ├── popup.html
│   └── popup.js                # PopupRenderer class
└── icons/icon.svg
```

### Detection pipeline

```
document_start (MAIN)
  nav-boot  ──► Location.assign/replace/href + window.open patched
  page-hooks ──► fetch / createElement / href / src / appendChild wrapped
                 click capture + meta-refresh + programmatic click

document_start (isolated)
  content   ──► startIcpWhoisIntelEarly (async WHOIS->ICP)
                 tryEarlyShellProtect + armImmediatePackageBlock
                 watchSuspiciousPackagesLive (MO + 200/900/1600ms + late rescan)

DOMContentLoaded + idle + load
  scanSuspiciousPackagesFast main chain:
    1. SeoCloakingRedirectKit   2. DesktopForceDownloadKit
    3. RemoteGarblePackageDispatch 4. IndexNowSeoPhishTemplate
    5. MultiPlatformSerpDownloadTrap 6. BrandSpoofDownloadPortal (ICP-gated)
    7. BrandResourceDomainMismatch   8. FakeOfficialDownloadSpa
    ── early-exit: benign-early / primary-clean ──
    9. RemoteDownloadApiBinding  10. AntiAnalysisBehavior
    11. FakeOfficialDownloadSpa#2  12. FakeBrandDownloadShell
    13. ClonedOfficialDownloadPage  14. scanEmbeddedPackageThreats
    15. DOM a[href] package sweep   16. collectAllPagePackageHrefs
    17. probeDownloadBehavior (≤3 async)

service worker
  webNavigation beforeNavigate ──► client_redirect SERP/package -> force-restore
  downloads.onCreated ──► shouldCancelDownload -> cancel + erase + notify
  onMessage ──► fetchPageText / probeDownloadBehavior / threat-risk / set-tab-protect
```

### Signal dictionary (weights)

| Signal | Weight |
|--------|-------:|
| SEO伪装跳转脚本 / 仿冒品牌官网下载站 | 24 |
| 仿冒品牌官网下载壳 / 仿冒官网第三方分发 / 多版本下载同一安装包 | 22 |
| 仿冒官网加密下载配置 / 已拦截可疑安装包下载 | 20 |
| SEO收录仿冒模板 / 域名与品牌资源不一致 | 20 |
| 远程API动态绑定下载 / PHP 下载入口 / 仿冒官网反调试下载页 | 18 |
| 多平台下载指向搜索引擎 / 远程下发乱码安装包 | 18 |
| 可疑安装包链接 / 页面嵌入可疑安装包 | 16 |
| 远程下发下载地址 / 桌面端强制弹窗下载 | 16 |
| 多入口共用动态下载地址 / 探测到跳转/附件下载 | 14 |
| 域名注册时间极短 | 12 |
| 已启用安装包下载拦截 / 远程配置解析下载链 | 12 |
| 反调试/禁止审查页面 / 已启用仿冒站/异常跳转拦截 | 10 |
| 域名注册不足30天 / 品牌仿冒/域名不匹配 | 9 |
| 无透明安装包下载入口 / 已拦截可疑下载链接 | 8 |
| 大量隐藏节点 / 异常 iframe / 内容稀少资源极多 | 8 |
| 大面积遮罩层 / 外部资源异常密集 | 7 |
| 无ICP备案信息 / DOM 突变 / 自动化 / 强制全屏 / 表单密集 | 6 |
| 伪官方官网落地页 / 可疑跳转下载按钮 | 4 |
| 营销型下载落地页 / 伪装官网营销页 | 3 |
| 域名<半年 / <1年 / 可疑官网域名特征 | 3 / 2 / 2 |

## Install (developer/unpacked)

1. Clone this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the `extension/` directory.

> [!IMPORTANT]
> Load the `extension/` directory into Chrome.

## Debug

Runtime debug logging is off by default. Enable with any of:

| Method | Action |
|--------|--------|
| URL param | Append `?silverfox_debug=1` or `#silverfox_debug=1` |
| Storage | `chrome.storage.local.set({ silverfoxDebug: true })` |
| Off | `chrome.storage.local.set({ silverfoxDebug: false })` + remove URL param |

Filter the page DevTools console by `[silverfox]` to see scan gates, detector HIT/miss with timing, early-exits, guard arm/lift, and ICP results.

## Key design decisions

- **No domain allowlists.** Brand/CDN/object-storage detection is behavioral (entropy, role tokens, path shapes) - no hardcoded vendor hostnames.
- **MAIN-world hooks install at `document_start`.** Chrome injects MAIN scripts before page JS, so `Location.prototype` is patched before any cloaking redirect fires.
- **Soft brand-spoof waits for ICP.** Padded/typo hosts (e.g. `todeskai.com` + 沪ICP) defer the toast until ICP settles, avoiding permanent false-positive UX.
- **DNR is short-burst only.** SERP-blocking session rules auto-expire (3-15s) and never auto-renew, so intentional search after leaving a phish page is never `ERR_BLOCKED_BY_CLIENT`.

## Project layout conventions

- MAIN-world modules attach to `window.SilverfoxNavBoot` / `window.SilverfoxPageHooks`.
- Content modules attach to `window.SilverfoxContent`; shared state lives in `NS.state` / `NS.caches`.
- Background modules attach to `self.SilverfoxBackground`; the SW entry uses `importScripts` to load them.
- Each module is an IIFE that reads `NS ??= {}`, so load order is flexible within a context.

<div align="center">

Silverfox Detector · Apache License 2.0

</div>
