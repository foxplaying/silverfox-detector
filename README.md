<div align="center">

<img src="extension/icons/icon.svg" width="96" height="96" alt="Silverfox Detector" />

[English](./README_en.md) | 简体中文

# Silverfox Detector

行为式网页威胁检测器 —— 一个 Chrome 扩展，通过 DOM 启发式与 MAIN-world 行为钩子识别可疑下载落地页。

[![Manifest](https://img.shields.io/badge/manifest-v3-blue)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Version](https://img.shields.io/badge/version-0.1.1-green)](./extension/manifest.json)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey)](./LICENSE)

</div>

> [!NOTE]
> 模块化、基于 class 的 Chrome MV3 扩展架构，拆分为 `nav-boot`、`page-hooks`、`content`、`background`、`popup` 五个聚焦模块目录。

## 功能

Silverfox Detector 监控每个 HTTP/HTTPS 页面的下载钓鱼模式，并在恶意安装包落地前启用分层防御：

- **SEO 伪装跳转套件**（zhizhu 类）—— 在 `document_start` 于 MAIN world 拦截 `location.replace`/`assign`/`href` 与 `window.open`，先于页面 JS 执行。
- **品牌仿冒下载门户** —— 标题/正文品牌 ↔ 主机相关性，识别拼写、夹带、连字符镜像抢注域名（如 `aa-todesk.com` 宣称 ToDesk）。
- **加密 Nuxt SPA 壳** —— 检测 `windowsDownload`/`macDownload` 键 + 不透明 base64 载荷且无透明安装包链接。
- **桌面端强制下载套件** —— 清除 `.dlp-overlay`/`电脑版推荐` DOM，拦截隐藏 `a`/`iframe` 安装包自动下载。
- **远程乱码安装包下发** —— 标记 `fetchDownloadLink` -> 随机主机乱码安装包流程。
- **对象存储安装包投递** —— 站外匿名桶 / OSS / TOS / R2 安装包。
- **ICP / WHOIS 情报** -- 24h 缓存多源 ICP 查询（爱站 / beiancx / uapis）与 RDAP WHOIS 域龄；有效 ICP 清除软品牌仿冒误报。
- **下载取消** —— SW 取消可疑 `chrome.downloads` 项；DNR 短脉冲阻断 SERP 跳转 hop。

## 架构

三个执行上下文，各自模块化：

```
extension/
├── manifest.json
├── nav-boot/          # MAIN world, document_start - 最早的 Location 钩子
│   ├── package-classifier.js   # PackageClassifier（静态）：包/产品/SSO/SERP
│   ├── sso-detector.js         # SsoDetector（静态）：SAML/OAuth/IdP 多跳
│   ├── page-shell-detector.js  # PageShellDetector（静态）：SERP/官方/钓鱼壳
│   ├── cloaking-kit-scanner.js # CloakingKitScanner（有状态）：zhizhu 指纹
│   ├── gesture-tracker.js      # GestureTracker（有状态）：激活窗口
│   ├── nav-blocker.js          # NavBlocker（有状态）：shouldBlock / tryBlock
│   ├── location-guard.js       # LocationGuard（静态）：原型 patch
│   └── index.js                # NavBoot（入口）：组合模块、安装钩子
├── page-hooks/       # MAIN world, document_start - 策略升级 + DOM 守卫
│   ├── package-heuristics.js   # PackageHeuristics（静态）
│   ├── page-context.js         # PageContext（静态）：SERP/light/壳
│   ├── cloaking-kit.js         # CloakingKit（静态）：dlp + zhizhu 评分
│   ├── download-ui.js          # DownloadUi（静态）：灰化 / 恢复
│   ├── nav-policy.js           # NavPolicy（有状态）：guard/hops/gesture
│   ├── dom-guard.js            # DomGuard（静态）：原型 wrap、scrub
│   └── index.js                # PageHooks（入口）：组装策略 + 钩子
├── content/          # isolated world - 扫描、情报、guard、UI
│   ├── state.js                # state + caches + 调试 + HTML 采样
│   ├── package-heuristics.js   # 文件名 / 对象存储 / 下载意图
│   ├── brand-heuristics.js     # eTLD+1、品牌 token、抢注形态
│   ├── brand-correlation.js    # 标题↔主机相关性、营销仿冒
│   ├── brand-spoof-detector.js # detectBrandSpoofDownloadPortal + 关联落地页
│   ├── encrypted-spa.js        # 待 hydrate Nuxt 延迟复扫
│   ├── intel-gates.js          # ICP/WHOIS 成熟度门、官方上下文
│   ├── intel-network.js        # ICP/WHOIS fetch + 24h 缓存 + probe
│   ├── page-context.js         # SERP 检测、benign/DOM 异常
│   ├── detectors.js            # SEO 套件、IndexNow、多平台 SERP
│   ├── detectors-extended.js   # 克隆页、远程乱码包、dlp、落地页
│   ├── guard.js                # installDownloadGuard、toast、报告、lift
│   ├── scanner.js              # scanSuspiciousPackagesFast、点击拦截
│   └── lifecycle.js            # finalize、SPA 重置、hooks 桥、boot
├── background/       # service worker - 导航保护、下载、情报 fetch
│   ├── filename-heuristics-bg.js  # PackageHeuristicsBg（静态）
│   ├── notification-bg.js         # PNG 图标生成 + 系统通知
│   ├── nav-protection-bg.js       # DNR、强制拉回、标签页状态
│   ├── download-verdict-bg.js     # shouldCancelDownload
│   ├── message-handler-bg.js      # fetchPageText / probe / risk / notice
│   └── background.js              # 入口：状态 + importScripts + 监听
├── popup/
│   ├── popup.html
│   └── popup.js                # PopupRenderer class
└── icons/icon.svg
```

### 检测流水线

```
document_start (MAIN)
  nav-boot  ──► Location.assign/replace/href + window.open 已 patch
  page-hooks ──► fetch / createElement / href / src / appendChild 已 wrap
                 点击捕获 + meta-refresh + 程序化 click

document_start (isolated)
  content   ──► startIcpWhoisIntelEarly（异步 WHOIS->ICP）
                 tryEarlyShellProtect + armImmediatePackageBlock
                 watchSuspiciousPackagesLive（MO + 200/900/1600ms + 延迟复扫）

DOMContentLoaded + idle + load
  scanSuspiciousPackagesFast 主链：
    1. SeoCloakingRedirectKit   2. DesktopForceDownloadKit
    3. RemoteGarblePackageDispatch 4. IndexNowSeoPhishTemplate
    5. MultiPlatformSerpDownloadTrap 6. BrandSpoofDownloadPortal（ICP 门控）
    7. BrandResourceDomainMismatch   8. FakeOfficialDownloadSpa
    ── 提前退出：benign-early / primary-clean ──
    9. RemoteDownloadApiBinding  10. AntiAnalysisBehavior
    11. FakeOfficialDownloadSpa#2  12. FakeBrandDownloadShell
    13. ClonedOfficialDownloadPage  14. scanEmbeddedPackageThreats
    15. DOM a[href] 包扫描          16. collectAllPagePackageHrefs
    17. probeDownloadBehavior（≤3 异步）

service worker
  webNavigation beforeNavigate ──► client_redirect SERP/包 -> 强制拉回
  downloads.onCreated ──► shouldCancelDownload -> 取消 + 擦除 + 通知
  onMessage ──► fetchPageText / probeDownloadBehavior / threat-risk / set-tab-protect
```

### 信号字典（权重）

| 信号 | 权重 |
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

## 安装（开发者/未打包）

1. 克隆本仓库。
2. 打开 `chrome://extensions`。
3. 启用**开发者模式**。
4. 点击**加载已解压的扩展程序**，选择 `extension/` 目录。

> [!IMPORTANT]
> 请加载 `extension/` 目录到 Chrome。

## 调试

运行时调试日志默认关闭。任选其一开启：

| 方式 | 操作 |
|--------|--------|
| URL 参数 | 加 `?silverfox_debug=1` 或 `#silverfox_debug=1` |
| storage | `chrome.storage.local.set({ silverfoxDebug: true })` |
| 关闭 | `chrome.storage.local.set({ silverfoxDebug: false })` 并去掉 URL 参数 |

在页面 DevTools Console 过滤 `[silverfox]`，可见扫描闸门、检测器 HIT/miss 及耗时、提前退出、guard arm/lift、ICP 结果。

## 关键设计决策

- **无域名白名单。** 品牌/CDN/对象存储检测均为行为式（熵、角色 token、路径形态）—— 无硬编码厂商主机名。
- **MAIN-world 钩子在 `document_start` 安装。** Chrome 在页面 JS 之前注入 MAIN 脚本，故 `Location.prototype` 在任何伪装跳转触发前已被 patch。
- **软品牌仿冒等待 ICP。** 夹带/拼写主机（如 `todeskai.com` + 沪ICP）延迟 toast 至 ICP 定论，避免永久误报 UX。
- **DNR 仅短脉冲。** SERP 阻断 session 规则自动过期（3–15s）且永不自动续期，故离开钓鱼页后的正常搜索永不 `ERR_BLOCKED_BY_CLIENT`。

## 项目结构约定

- MAIN-world 模块挂载到 `window.SilverfoxNavBoot` / `window.SilverfoxPageHooks`。
- content 模块挂载到 `window.SilverfoxContent`；共享状态在 `NS.state` / `NS.caches`。
- background 模块挂载到 `self.SilverfoxBackground`；SW 入口用 `importScripts` 加载。
- 每个模块是读取 `NS ??= {}` 的 IIFE，故上下文内加载顺序灵活。

<div align="center">

Silverfox Detector · Apache License 2.0

</div>
