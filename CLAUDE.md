# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Silverfox Detector 是一个 Chrome MV3 扩展，通过 DOM 启发式与 MAIN-world 行为钩子检测可疑下载落地页（银狐类钓鱼）。采用模块化、基于 class 的架构。

## 开发与加载

无构建步骤、无打包器、无测试套件。扩展是纯静态 JS，直接由 Chrome 加载。

- **加载**：`chrome://extensions` -> 开发者模式 -> 加载已解压 -> 选 `extension/` 目录。
- **调试日志**：URL 加 `?silverfox_debug=1` 或 `chrome.storage.local.set({ silverfoxDebug: true })`，DevTools Console 过滤 `[silverfox]`。
- **改逻辑后**：在 `chrome://extensions` 点扩展卡片刷新，再刷新目标页。MAIN-world 脚本（nav-boot/page-hooks）改动尤其需要硬刷新（Ctrl+Shift+R）。

## 关键架构约束（跨多文件理解）

### 三个执行上下文，命名空间隔离

每个上下文有独立的命名空间对象，IIFE 模式 `;(function (NS) { ... })(window.SilverfoxXxx ??= {})`。**模块间不能直接 import**——同一上下文靠全局 NS 对象共享，跨上下文靠 `window.postMessage` / `chrome.runtime.sendMessage`。

| 上下文 | 命名空间 | world | run_at | 职责 |
|--------|----------|-------|--------|------|
| `nav-boot/` | `window.SilverfoxNavBoot` | MAIN | document_start | 最早 Location 钩子（先于页面 JS） |
| `page-hooks/` | `window.SilverfoxPageHooks` | MAIN | document_start | 策略升级 + DOM 原型 wrap |
| `content/` | `window.SilverfoxContent` | isolated | document_start | 扫描、情报、guard、UI |
| `background/` | `self.SilverfoxBackground` | SW | - | 导航保护、下载取消、ICP/WHOIS fetch |
| `popup/` | IIFE 局部 | - | - | PopupRenderer class |

### manifest 加载顺序即依赖顺序

`manifest.json` 的 `content_scripts.js` 数组顺序就是加载顺序，**改文件名/增删文件必须同步改 manifest**。nav-boot 必须在 page-hooks 前（page-hooks 依赖 `window.__silverfoxNavApi`）；content 内部 state.js 必须最先（其余模块读 `NS.state`/`NS.caches`）；background 用 `importScripts` 显式加载，顺序在 background.js 里。

### MAIN-world vs isolated 的职责边界

MAIN world 与页面 JS 共享 DOM，能 patch `Location.prototype`、wrap `fetch`/`createElement`——但这些原型改动**只能在 MAIN**。isolated world（content）无法 patch 页面原型，只能通过 `postMessage` 向 MAIN 发指令（`set-guard`/`set-official-safe`/`set-light-page`），MAIN 通过 `signal`/`blocked-download`/`request-guard` 回报。content 持有真正的分析状态（`NS.state`）和风险评分。

### 三套文件名启发式是独立副本

`page-hooks/package-heuristics.js`（MAIN）、`content/package-heuristics.js`（isolated）、`background/filename-heuristics-bg.js`（SW）各自有一份文件名/对象存储分类逻辑，因为跨上下文无法共享。**改其中一套时，要判断另外两套是否需要同步**——它们语义相同但 API 略异（如 background 用 `PackageHeuristicsBg.looksLikeProductPackageName`，content 用 `NS.looksLikeProductPackageName`）。

## 改检测逻辑时必读

### scanSuspiciousPackagesFast 主链顺序（content/scanner.js）

主链 8 个检测器顺序**有语义**：SEO 套件→桌面套件→远程乱码→IndexNow→多平台SERP→品牌仿冒（ICP 门控）→品牌资源失配→加密SPA。前 8 个跑完有 `primary-threat-armed` 提前退出。二级链（9-17）仅在 titleHot 或 found 或 pending 加密 SPA 时跑。改顺序会影响"哪个检测器先 arm guard"和 toast 文案。

### ICP 门控是反误报核心

软品牌仿冒（padded/typo/hyphen 主机）**必须等 ICP 定论**才 toast——`detectBrandSpoofDownloadPortal` 里的 `_pendingSoftBrandSpoof` 机制。有效 ICP 会调 `clearBrandSpoofFalsePositive` 撤销。`installDownloadGuard`（guard.js）对 `guardKind === "brand-spoof"` 有 ICP 检查会拒绝 arm。动这部分要理解 todeskai.com + 沪ICP 这类合法但被误报的案例。

### DNR 永不自动续期

`armHostileNavDnr`（background/nav-protection-bg.js）的 session 规则 3-15s 自动过期，`setTimeout` 内显式 `removeRuleIds`。这是为了避免用户离开钓鱼页后正常搜索被 `ERR_BLOCKED_BY_CLIENT`。**不要加自动续期逻辑**。

### 强产品安装包豁免贯穿全代码

`Brand_official_setup_2.6.3.0.exe`、Android 反向域名 APK、短 CDN stub（`inst.exe`）在**每条阻断路径**都豁免。guard.js 的 `installDownloadGuard` 开头有一长串 `if (...looksLikeStrongProductInstallerName...) return` 拒绝 arm。加新阻断路径时必须保留这个豁免，否则会误杀游戏/钉钉等官方客户端。

## 状态与缓存

content 的全局状态在 `NS.state`（score/details/signalSet/protectedTargets/各 `_xxxDetected` 标志），缓存（HTML/下载按钮/SERP/probe）在 `NS.caches`。`invalidateHtmlCache` 在 SPA URL 变更和加密 SPA 复扫前必须调。`resetAnalysisStateForPageChange`（lifecycle.js）列出所有需重置的字段——新增状态字段时记得加到这里。

## 代码风格约定

- 中文注释、中文 commit message（见全局 CLAUDE.md）。
- 静态工具用 `class Xxx { static method() {} }`，有状态的用 `class Xxx { constructor() {...} }`。
- 大量正则字面量含 Unicode 破折号 `[-–-|]`——`node --check` 会误报 "Range out of order"，但 Chrome V8 正常加载，不要"修复"。
- `try { ... } catch { /* ignore */ }` 是有意的——扩展在不可信页面运行，任何 API 都可能抛错。
