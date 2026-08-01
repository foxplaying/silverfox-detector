/**
 * 安装包/压缩包：文件哈希 + VirusTotal +（PE 才做）Authenticode 粗检（试验版）。
 *
 * 覆盖：exe / dll / sys / msi / zip / rar / 7z / apk / dmg / pkg / appx / cab / iso …
 * 流程：
 *   1) 对下载 URL fetch 文件字节（有大小上限）
 *   2) PE：Authenticode 粗检；ZIP：扫包内 exe/dll/msi 签名
 *   3) 数字签名着色：有签黑 / VT 验真绿 / 无效或无签红
 *   4) 全部类型：SHA-256 → 查询 VT 文件报告（仅文件，不做 URL 网页分析）
 *      - 可选 API v3 Key → /api/v3/files/{hash}
 *      - ★ 后台开 VT 文件页，MAIN world 同源 fetch /ui/files
 *      - 仅明确 404/NotFound 才「VT:无」
 *   5) 库中无样本且有 API Key：仅 API 自动上传（无 Key 不上传）
 *
 * 不做完整 WinVerifyTrust；大文件/一次性链接可能失败。
 */
;(function (NS) {
  "use strict";

  const VT_GUI_BASE = "https://www.virustotal.com/gui/file/";
  const VT_UI_BASE = "https://www.virustotal.com/ui/files/";
  const VT_UI_UPLOAD = "https://www.virustotal.com/ui/files";
  const VT_UPLOAD_PAGE = "https://www.virustotal.com/gui/home/upload";
  /** 全量拉取 / 分段扫描统一上限 650MB */
  const MAX_FULL_FETCH = 650 * 1024 * 1024;
  const MAX_RANGE_ARCHIVE = 650 * 1024 * 1024;
  const VT_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
  const VT_TRUST_POLICY_VERSION = 3;
  const VT_STATS_POLICY_VERSION = 2;
  const FETCH_TIMEOUT_MS = 120000;
  /** 与网页 https://www.virustotal.com/gui/home/upload 一致：最大 650MB */
  const VT_UPLOAD_MAX = 650 * 1024 * 1024;
  /** 直传 /files 约 32MB；更大必须先取 upload_url 再 POST */
  const VT_DIRECT_UPLOAD_MAX = 32 * 1024 * 1024;

  // 与 filename-heuristics 对齐并略宽：压缩包 + 安装包 + 移动包
  const PACKAGE_EXT_RE = /\.(?:zip|exe|dll|sys|scr|msi|msp|apk|dmg|pkg|appx|msix|cab|rar|7z|iso|img|gz|tgz|tar|xz|bz2|wim|esd|deb|rpm)(?:\?|#|$)/i;
  const PE_EXT_RE = /\.(?:exe|dll|sys|scr|ocx|cpl|efi|acm|ax|drv|mui)(?:\?|#|$)/i;
  const ARCHIVE_EXT_RE = /\.(?:zip|rar|7z|cab|gz|tgz|tar|xz|bz2|wim|iso|img|apk|dmg|pkg|appx|msix|deb|rpm)(?:\?|#|$)/i;
  /** 压缩包内要扫的目标：Windows PE / MSI / Android APK */
  const NESTED_EXE_RE = /\.(?:exe|dll|sys|scr|ocx|cpl|msi|msp|efi|drv|apk)(?:\?|#|$)/i;
  const MAX_NESTED_SCAN = 12;
  /** 包内单文件解压上限（安装包 exe 常 >12MB，过小会整包漏检） */
  const MAX_NESTED_BYTES = 48 * 1024 * 1024;
  /** 包内做 VT 查询的上限（避免一次下太多） */
  const MAX_NESTED_VT = 8;
  /** RAR/7z 由 7-Zip WASM 解码；WASM 会复制输入，单独设置更保守的内存上限。 */
  const MAX_WASM_ARCHIVE_BYTES = 192 * 1024 * 1024;
  const MAX_WASM_ARCHIVE_ENTRIES = 4096;
  const MAX_WASM_EXTRACT_TOTAL = 96 * 1024 * 1024;
  const WASM_ARCHIVE_TIMEOUT_MS = 60000;
  const ARCHIVE_TASK_DB = "silverfox_archive_tasks_v1";
  const ARCHIVE_TASK_STORE = "tasks";
  let archiveOffscreenCreatePromise = null;

  NS._vtByHash = NS._vtByHash || new Map();
  NS._peVtInflight = NS._peVtInflight || new Map();

  function u16(view, off, le) {
    return le ? view.getUint16(off, true) : view.getUint16(off, false);
  }
  function u32(view, off, le) {
    return le ? view.getUint32(off, true) : view.getUint32(off, false);
  }

  function bytesToHex(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
    return s;
  }

  NS.sha256HexOfBuffer = async function (arrayBuffer) {
    if (!arrayBuffer || !crypto || !crypto.subtle) return "";
    try {
      const dig = await crypto.subtle.digest("SHA-256", arrayBuffer);
      return bytesToHex(dig);
    } catch {
      return "";
    }
  };

  /**
   * 解析 PE Authenticode 证书表（IMAGE_DIRECTORY_ENTRY_SECURITY = 4）。
   * 注意：该目录的 VirtualAddress 实际是文件偏移，不是 RVA。
   */
  NS.parsePeAuthenticode = function (arrayBuffer) {
    const out = {
      isPe: false,
      signed: false,
      certTableOffset: 0,
      certTableSize: 0,
      signerHint: "",
      error: ""
    };
    try {
      if (!arrayBuffer || arrayBuffer.byteLength < 0x40) {
        out.error = "too-small";
        return out;
      }
      const view = new DataView(arrayBuffer);
      // MZ
      if (u16(view, 0, true) !== 0x5a4d) {
        out.error = "not-mz";
        return out;
      }
      const e_lfanew = u32(view, 0x3c, true);
      if (e_lfanew <= 0 || e_lfanew + 24 > arrayBuffer.byteLength) {
        out.error = "bad-lfanew";
        return out;
      }
      // PE\0\0
      if (u32(view, e_lfanew, true) !== 0x00004550) {
        out.error = "not-pe";
        return out;
      }
      out.isPe = true;
      const coff = e_lfanew + 4;
      const sizeOfOptional = u16(view, coff + 16, true);
      const optOff = coff + 20;
      if (optOff + sizeOfOptional > arrayBuffer.byteLength) {
        out.error = "opt-truncated";
        return out;
      }
      const magic = u16(view, optOff, true);
      // PE32=0x10b, PE32+=0x20b
      let ddOff = 0;
      if (magic === 0x10b) ddOff = optOff + 96;
      else if (magic === 0x20b) ddOff = optOff + 112;
      else {
        out.error = "bad-magic";
        return out;
      }
      // DataDirectory[4] = security
      const secEntry = ddOff + 4 * 8;
      if (secEntry + 8 > arrayBuffer.byteLength) {
        out.error = "dd-truncated";
        return out;
      }
      const certOff = u32(view, secEntry, true);
      const certSize = u32(view, secEntry + 4, true);
      out.certTableOffset = certOff;
      out.certTableSize = certSize;
      if (certOff > 0 && certSize >= 8
        && certOff + Math.min(certSize, 64) <= arrayBuffer.byteLength) {
        out.signed = true;
        // 粗提 PKCS#7 / 证书里的可打印组织串
        try {
          const sliceLen = Math.min(certSize, 65536, arrayBuffer.byteLength - certOff);
          const u8 = new Uint8Array(arrayBuffer, certOff, sliceLen);
          // 软件发布者 = 叶子证书 Subject，不是 DigiCert 等 Issuer
          out.signerHint = sanitizePublisherName(extractSignerHintFromCertBlob(u8));
        } catch { /* ignore */ }
      }
      return out;
    } catch (e) {
      out.error = e && e.message ? e.message : "parse-fail";
      return out;
    }
  };

  /**
   * 是否证书颁发机构 / 时间戳站等「链上机构名」。
   * 这些是 Issuer，绝不是用户要看的软件发布者（Subject）。
   */
  function isCertificateAuthorityName(s) {
    const t = String(s || "").trim();
    if (!t) return true;
    // DigiCert, Inc. 这类不带 CA 字样的颁发机构也要拦
    if (/\b(?:DigiCert|Sectigo|GlobalSign|VeriSign|Symantec|GeoTrust|Thawte|Comodo|USERTrust|AddTrust|IdenTrust|Buypass|QuoVadis|SwissSign|Actalis|Trustwave|Certum|Entrust|AffirmTrust|GoDaddy|Starfield|Let's\s*Encrypt|SSL\.com|Amazon\s+Trust|Cloudflare|ZeroSSL|Certainly|Gandi|Fastly)\b/i.test(t)) {
      return true;
    }
    if (/\b(?:CA|Root|Class\s*[123]|Authority|PCA|Timestamp(?:ing)?|Time\s*Stamping|Code\s*Signing\s*CA|EV\s*RSA|AAA\s*Certificate)\b/i.test(t)) {
      return true;
    }
    // Microsoft 链上中间/根（不是 MS 自己签产品时的发布者组织）
    if (/^Microsoft\s+(?:Root|RSA|ECC|Time|Code\s+Signing|Identity|Windows\s+Hardware|Marketplace|Third\s+Party)/i.test(t)) {
      return true;
    }
    if (/Internet\s+Widgits|Some-State|Default\s+Company|Example|Test\s+Org|localhost/i.test(t)) {
      return true;
    }
    return false;
  }

  function isJunkSignerName(s) {
    const t = String(s || "").trim();
    if (t.length < 2 || t.length > 100) return true;
    if (isCertificateAuthorityName(t)) return true;
    return false;
  }

  function derElement(u8, p, end) {
    if (p >= end || p < 0) return null;
    const tag = u8[p++];
    if (p >= end) return null;
    let len = u8[p++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n < 1 || n > 3 || p + n > end) return null;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | u8[p++];
    }
    if (len < 0 || p + len > end) return null;
    return { tag, contentStart: p, contentEnd: p + len, next: p + len };
  }

  function decodeDerString(u8, off, len, tag) {
    try {
      if (tag === 0x1e) {
        let s = "";
        for (let i = 0; i + 1 < len; i += 2) {
          const c = (u8[off + i] << 8) | u8[off + i + 1];
          if (c >= 32) s += String.fromCharCode(c);
        }
        return s;
      }
      const slice = u8.subarray(off, off + len);
      try {
        return new TextDecoder("utf-8", { fatal: false }).decode(slice);
      } catch {
        let s = "";
        for (let i = 0; i < slice.length; i++) {
          const c = slice[i];
          if (c >= 32 && c < 127) s += String.fromCharCode(c);
        }
        return s;
      }
    } catch {
      return "";
    }
  }

  /** Name / RDN 内扫 organizationName / commonName */
  function parseX509Name(u8, start, end) {
    const out = { O: "", CN: "", OU: "" };
    try {
      const oidO = [0x06, 0x03, 0x55, 0x04, 0x0a];
      const oidCN = [0x06, 0x03, 0x55, 0x04, 0x03];
      const oidOU = [0x06, 0x03, 0x55, 0x04, 0x0b];
      const readAfterOid = (oid) => {
        const ol = oid.length;
        for (let i = start; i + ol + 2 < end; i++) {
          let ok = true;
          for (let j = 0; j < ol; j++) {
            if (u8[i + j] !== oid[j]) { ok = false; break; }
          }
          if (!ok) continue;
          let p = i + ol;
          const el = derElement(u8, p, end);
          if (!el) continue;
          // 直接是字符串，或 SET/SEQ 包一层
          if (el.tag === 0x0c || el.tag === 0x13 || el.tag === 0x14 || el.tag === 0x16 || el.tag === 0x1e) {
            return decodeDerString(u8, el.contentStart, el.contentEnd - el.contentStart, el.tag).trim();
          }
          if (el.tag === 0x30 || el.tag === 0x31) {
            const inner = derElement(u8, el.contentStart, el.contentEnd);
            if (inner && (inner.tag === 0x0c || inner.tag === 0x13 || inner.tag === 0x14 || inner.tag === 0x16 || inner.tag === 0x1e)) {
              return decodeDerString(u8, inner.contentStart, inner.contentEnd - inner.contentStart, inner.tag).trim();
            }
          }
        }
        return "";
      };
      out.O = readAfterOid(oidO);
      out.CN = readAfterOid(oidCN);
      out.OU = readAfterOid(oidOU);
    } catch { /* ignore */ }
    return out;
  }

  /** 从单张 X.509 证书取 Issuer / Subject（要 Subject=发布者，不要 Issuer=CA） */
  function extractIssuerSubjectFromCert(u8, certOff, certEnd) {
    try {
      const cert = derElement(u8, certOff, certEnd);
      if (!cert || cert.tag !== 0x30) return null;
      const tbs = derElement(u8, cert.contentStart, cert.contentEnd);
      if (!tbs || tbs.tag !== 0x30) return null;
      let p = tbs.contentStart;
      const tbsEnd = tbs.contentEnd;
      let el = derElement(u8, p, tbsEnd);
      if (!el) return null;
      // version [0] OPTIONAL
      if (el.tag === 0xa0) {
        p = el.next;
        el = derElement(u8, p, tbsEnd);
        if (!el) return null;
      }
      // serialNumber
      p = el.next;
      // signature AlgorithmIdentifier
      el = derElement(u8, p, tbsEnd);
      if (!el) return null;
      p = el.next;
      // issuer Name
      el = derElement(u8, p, tbsEnd);
      if (!el || el.tag !== 0x30) return null;
      const issuer = parseX509Name(u8, el.contentStart, el.contentEnd);
      p = el.next;
      // validity
      el = derElement(u8, p, tbsEnd);
      if (!el) return null;
      p = el.next;
      // subject Name
      el = derElement(u8, p, tbsEnd);
      if (!el || el.tag !== 0x30) return null;
      const subject = parseX509Name(u8, el.contentStart, el.contentEnd);
      return { issuer, subject };
    } catch {
      return null;
    }
  }

  /** 在 PKCS#7 证书袋里找 X.509 证书范围（0x30 0x82 len） */
  function findX509CertRanges(u8) {
    const ranges = [];
    const n = u8.length;
    for (let i = 0; i + 8 < n; i++) {
      if (u8[i] !== 0x30) continue;
      let hdr = 2;
      let len = 0;
      if (u8[i + 1] === 0x82) {
        len = (u8[i + 2] << 8) | u8[i + 3];
        hdr = 4;
      } else if (u8[i + 1] === 0x83) {
        len = (u8[i + 2] << 16) | (u8[i + 3] << 8) | u8[i + 4];
        hdr = 5;
      } else if (u8[i + 1] === 0x81) {
        len = u8[i + 2];
        hdr = 3;
      } else if (u8[i + 1] < 0x80) {
        len = u8[i + 1];
        hdr = 2;
      } else continue;
      // 代码签名证书通常数百～数千字节
      if (len < 256 || len > 12000) continue;
      if (i + hdr + len > n) continue;
      // TBSCertificate 紧跟
      if (u8[i + hdr] !== 0x30) continue;
      ranges.push({ off: i, end: i + hdr + len });
      i += hdr + len - 1;
    }
    return ranges;
  }

  function pickPublisherDisplayName(subject) {
    if (!subject) return "";
    const o = String(subject.O || "").trim();
    const cn = String(subject.CN || "").trim();
    // 优先组织名 O=（发布者公司），再 CN=
    if (o && !isCertificateAuthorityName(o) && !isJunkSignerName(o)) return o;
    if (cn && !isCertificateAuthorityName(cn) && !isJunkSignerName(cn)) return cn;
    return "";
  }

  /**
   * 从 Authenticode PKCS#7 提取「软件发布者」= 叶子证书 Subject。
   * 绝不返回 DigiCert 等 Issuer/CA 名。
   */
  function extractSignerHintFromCertBlob(u8) {
    try {
      if (!u8 || !u8.length) return "";
      // 跳过 WIN_CERTIFICATE 8 字节头再解析一份
      const views = [u8];
      if (u8.length > 16) views.push(u8.subarray(8));

      const leafCandidates = [];
      const anySubject = [];

      for (const blob of views) {
        const ranges = findX509CertRanges(blob);
        for (const r of ranges) {
          const pair = extractIssuerSubjectFromCert(blob, r.off, r.end);
          if (!pair) continue;
          const subName = pickPublisherDisplayName(pair.subject);
          const issO = String((pair.issuer && pair.issuer.O) || "").trim();
          const issCN = String((pair.issuer && pair.issuer.CN) || "").trim();
          const issuerIsCa = isCertificateAuthorityName(issO) || isCertificateAuthorityName(issCN)
            || isCertificateAuthorityName(issO + " " + issCN);
          const subjectIsCa = !subName; // pick 已滤 CA；空=像 CA/无效

          if (subName) {
            anySubject.push({ name: subName, issuerIsCa, score: 0 });
            // 叶子特征：Subject 不是 CA，且 Issuer 是 CA（最常见代码签名形态）
            if (issuerIsCa) {
              leafCandidates.push({ name: subName, score: 100 });
            } else {
              leafCandidates.push({ name: subName, score: 40 });
            }
          } else if (!subjectIsCa) {
            // subject 被滤掉则跳过
          }
        }
      }

      // ① 叶子 Subject 优先
      if (leafCandidates.length) {
        leafCandidates.sort((a, b) => b.score - a.score || b.name.length - a.name.length);
        for (const c of leafCandidates) {
          if (c.name && !isCertificateAuthorityName(c.name)) return c.name.slice(0, 120);
        }
      }
      if (anySubject.length) {
        for (const c of anySubject) {
          if (c.name && !isCertificateAuthorityName(c.name)) return c.name.slice(0, 120);
        }
      }

      // ② 兜底：全文扫 O=/CN=，但仍强滤 CA（避免再出现 DigiCert, Inc.）
      let text8 = "";
      try {
        text8 = new TextDecoder("utf-8", { fatal: false }).decode(u8);
      } catch {
        text8 = "";
      }
      const reO = /(?:\bO\s*=\s*)([^\n,=/]{2,80})/gi;
      let m;
      const orgHits = [];
      while ((m = reO.exec(text8))) {
        const t = String(m[1] || "").replace(/\s+/g, " ").trim();
        if (t && !isJunkSignerName(t) && !isCertificateAuthorityName(t)) orgHits.push(t);
      }
      if (orgHits.length) return orgHits[0].slice(0, 120);

      // ③ 已知软件厂商字面量（仍排除 CA）
      const corp = text8.match(
        /\b((?:Microsoft Corporation|Google LLC|Apple Inc|Adobe Inc|RARLAB|win\.rar\s*GmbH|IrfanView|7-Zip|Mozilla Corporation|Tencent|Kingsoft|VMware|Oracle Corporation)\b[A-Za-z0-9 .,&]{0,30})/i
      );
      if (corp && !isCertificateAuthorityName(corp[1])) return String(corp[1]).trim().slice(0, 120);

      return "";
    } catch {
      return "";
    }
  }

  /** VT 回填的签署者字符串也可能是 CA 链，同样过滤 */
  function sanitizePublisherName(s) {
    const t = String(s || "").replace(/\0/g, "").replace(/\s+/g, " ").trim();
    if (!t || isJunkSignerName(t) || isCertificateAuthorityName(t)) return "";
    // VT 有时返回 "A; B; DigiCert" 多段，取第一段非 CA
    if (/[;|]/.test(t)) {
      const parts = t.split(/[;|]/).map((x) => x.trim()).filter(Boolean);
      for (const p of parts) {
        if (!isCertificateAuthorityName(p) && !isJunkSignerName(p)) return p.slice(0, 120);
      }
      return "";
    }
    return t.slice(0, 120);
  }

  function signerNamesLooselyMatch(a, b) {
    const norm = (s) => String(s || "").toLowerCase()
      .replace(/\.(com|inc|ltd|llc|gmbh|corp|corporation|co)\b/g, "")
      .replace(/[^a-z0-9\u4e00-\u9fff]+/g, "");
    const x = norm(a);
    const y = norm(b);
    if (!x || !y || x.length < 3 || y.length < 3) return false;
    return x.includes(y) || y.includes(x) || x.slice(0, 10) === y.slice(0, 10);
  }

  /**
   * 从 VT signature_info 判定数字签名真伪。
   * trust: valid | invalid | present | none | ""
   * VT 对已校验 Authenticode 常见：verified === "Signed"
   */
  function vtSignatureMetaFromAttrs(attrs) {
    const sig = (attrs && (attrs.signature_info || attrs.signatureInfo)) || null;
    if (!sig || typeof sig !== "object") return { trust: "", signer: "" };
    const signer = signerFromAttrs(attrs);
    const verified = String(sig.verified || sig.status || sig.result || sig.signersstatus || "").trim();
    const blob = (verified + " " + JSON.stringify(sig)).toLowerCase();

    // 假签 / 失效（优先）
    if (/invalid\s*signature|not\s*trusted|untrusted|revoked|bad\s*signature|certificate\s*expired|signing\s*error|broken|ineffective/i.test(blob)) {
      if (!/^signed$/i.test(verified)) {
        return { trust: "invalid", signer };
      }
    }
    if (/^invalid\b/i.test(verified) || /签名无效|证书已过期|不可信/i.test(verified)) {
      return { trust: "invalid", signer };
    }
    if (/unsigned|not\s*signed|no\s*signature|无签名/i.test(verified)) {
      return { trust: "none", signer: "" };
    }

    // VT 明确 Signed / Valid → 绿
    // 注意：verified 字段值经常就是 "Signed"（表示通过校验的签名）
    if (/^signed$/i.test(verified) || /^valid$/i.test(verified)
      || /^signed by\b/i.test(verified)
      || /signature\s*valid|valid\s*signature|successfully\s*verified/i.test(blob)) {
      return { trust: "valid", signer };
    }

    // 有 signers / 签名日期等结构化信息，且无 invalid 字样：
    // VT 已解析出签名链 → 视为验真通过（绿）
    if (signer || sig.signers || sig.subject || sig["signers details"] || sig["signing date"] || sig.signing_date
      || sig.x509 || sig["x509"]) {
      return { trust: "valid", signer };
    }
    return { trust: "", signer };
  }

  /**
   * 从 VT JSON 正文 / 页文案抠 signature_info（DOM 刮检出时常缺 attrs）
   */
  function extractVtSignatureFromText(text) {
    const s = String(text || "");
    if (!s || s.length < 20) return { trust: "", signer: "" };
    // invalid
    if (/invalid\s*signature|not\s*trusted|certificate\s*expired|签名无效/i.test(s)
      && !/"verified"\s*:\s*"Signed"/i.test(s)) {
      const mBad = s.match(/"signers"\s*:\s*"([^"]{2,160})"/i);
      return { trust: "invalid", signer: sanitizePublisherName(mBad ? mBad[1].split(";")[0] : "") };
    }
    const mVer = s.match(/"verified"\s*:\s*"([^"]+)"/i);
    const verified = mVer ? mVer[1].trim() : "";
    let signer = "";
    const mSigners = s.match(/"signers"\s*:\s*"([^"]{2,200})"/i);
    if (mSigners) {
      const first = mSigners[1].split(";")[0].trim();
      signer = sanitizePublisherName(first);
    }
    if (!signer) {
      const mSub = s.match(/"subject"\s*:\s*"([^"]{2,120})"/i);
      if (mSub) signer = sanitizePublisherName(mSub[1]);
    }
    // 页面文案：Signed by Xxx / 签名者
    if (!signer) {
      const mBy = s.match(/(?:Signed by|签名者|签名：)\s*([A-Za-z0-9 .,&_()+\-]{3,80}|[\u4e00-\u9fffA-Za-z0-9 .,&]{2,60})/i);
      if (mBy) signer = sanitizePublisherName(mBy[1]);
    }
    if (/^signed$/i.test(verified) || /^valid$/i.test(verified)) {
      return { trust: "valid", signer };
    }
    if (/unsigned|not\s*signed/i.test(verified)) {
      return { trust: "none", signer: "" };
    }
    if (/"signature_info"\s*:\s*\{/i.test(s) && (signer || verified)) {
      return { trust: "valid", signer };
    }
    if (signer && /Signed by|signature_info|Authenticode|数字签名/i.test(s)) {
      return { trust: "valid", signer };
    }
    return { trust: "", signer };
  }

  /**
   * 综合本地 PE 证书表 + VT signature_info → 数字签名展示状态。
   * trust: none | present(黑) | valid(绿) | invalid(红)
   *
   * 绿：VT 确认签名有效（verified=Signed / 有 signature_info 签名人等）
   * 黑：仅本地有证书表，VT 未给出验真结论
   * 红：无签名，或 VT 判定无效
   */
  function resolveDigitalSignature(pe, vt, nested) {
    const localSigned = !!(pe && pe.isPe && pe.signed);
    const localName = sanitizePublisherName((pe && pe.signerHint) || "");
    const vtName = sanitizePublisherName((vt && vt.signerFromVt) || "");
    const name = localName || vtName;
    let vtTrust = String((vt && vt.sigTrustFromVt) || "").toLowerCase();

    // 从 VT summary/raw 再抠一层（DOM/部分 JSON 路径）
    if ((!vtTrust || vtTrust === "present") && vt) {
      const blob = [vt.summary, vt.rawText, vt.pageHint].filter(Boolean).join("\n");
      if (blob) {
        const ex = extractVtSignatureFromText(blob);
        if (ex.trust) vtTrust = ex.trust;
        // signer 回填由调用方处理
      }
    }

    let trust = "none";

    if (vtTrust === "invalid") {
      trust = "invalid";
    } else if (vtTrust === "valid") {
      trust = "valid";
    } else if (vtTrust === "none" && !localSigned) {
      trust = "none";
    } else if (localSigned && vt && vt.found === true && vt.notFound !== true && !vt.unknown) {
      // 本地有签 + VT 库中有该文件：
      // 若 VT 给出了签名人且与本地一致（或仅一边有名），升为绿
      if (vtTrust === "present" || vtName || vtTrust === "valid") {
        if (!vtName || !localName || signerNamesLooselyMatch(localName, vtName)) {
          trust = "valid";
        } else {
          // 本地与 VT 签名人不一致 → 可疑红
          trust = "invalid";
        }
      } else if (vt.sigTrustFromVt === "" || !vtTrust) {
        // VT 有报告但未带回 signature_info：保持黑（仅本地有签）
        trust = "present";
      } else {
        trust = "present";
      }
    } else if (localSigned || vtTrust === "present") {
      trust = "present";
    } else if (pe && pe.isPe) {
      trust = "none";
    } else {
      trust = "";
    }

    // VT 有签名人 + found，即使本地解析失败也绿
    if (trust !== "invalid" && vt && vt.found === true && vtTrust === "valid") {
      trust = "valid";
    }
    if (trust !== "invalid" && vt && vt.found === true && vtName && (vtTrust === "valid" || vtTrust === "present")) {
      trust = "valid";
    }

    const items = [];
    if (Array.isArray(nested)) {
      for (const n of nested) {
        if (!n) continue;
        items.push({
          name: n.name || "?",
          kind: n.kind || "",
          signed: !!n.signed,
          signer: sanitizePublisherName(n.signerHint || ""),
          trust: n.sigTrust || (n.signed ? "present" : "none")
        });
      }
    }
    // 外层无 PE 但包内有可执行文件
    if ((!pe || !pe.isPe || pe.skipped) && items.length) {
      if (items.some((x) => x.trust === "invalid")) trust = "invalid";
      else if (items.every((x) => x.trust === "valid")) trust = "valid";
      else if (items.some((x) => x.signed || x.trust === "present" || x.trust === "valid")) {
        trust = trust === "valid" ? "valid" : "present";
      } else trust = "none";
    }

    return {
      trust: trust || "none",
      signer: name || vtName,
      items
    };
  }

  // ---------- ZIP 内嵌可执行文件（store / deflate；中文名 GBK/UTF-8）----------
  async function inflateZipPayload(u8) {
    if (typeof DecompressionStream === "undefined") return null;
    // ZIP 规范为 raw deflate；个别实现带 zlib 头，两种都试
    for (const fmt of ["deflate-raw", "deflate"]) {
      try {
        const ds = new DecompressionStream(fmt);
        const stream = new Blob([u8]).stream().pipeThrough(ds);
        const ab = await new Response(stream).arrayBuffer();
        if (ab && ab.byteLength >= 64) return ab;
      } catch { /* try next */ }
    }
    return null;
  }

  function decodeZipName(bytes, flags) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const utf8Flag = !!(flags & 0x800);
    const tryDec = (enc) => {
      try {
        return new TextDecoder(enc, { fatal: false }).decode(u8);
      } catch {
        return "";
      }
    };
    if (utf8Flag) {
      const n = tryDec("utf-8");
      if (n) return n;
    }
    // Windows 中文压缩包常见 GBK/GB18030（无 UTF-8 标志）
    const gbk = tryDec("gbk") || tryDec("gb18030");
    const utf = tryDec("utf-8");
    // 优先能匹配可执行扩展、且替换符更少的
    const score = (s) => {
      if (!s) return -1;
      let sc = 0;
      if (NESTED_EXE_RE.test(s) || /\.(exe|dll|sys|scr|msi|msp|ocx)$/i.test(s)) sc += 10;
      if (!/\uFFFD/.test(s)) sc += 5;
      if (/[\u4e00-\u9fff]/.test(s)) sc += 2;
      return sc;
    };
    return score(gbk) >= score(utf) ? (gbk || utf || "") : (utf || gbk || "");
  }

  /** 扩展名是否像可执行/安装包（兼容乱码文件名，看原始字节尾缀） */
  function zipEntryLooksExecutable(nameStr, nameBytes) {
    const n = String(nameStr || "");
    if (NESTED_EXE_RE.test(n)) return true;
    if (/\.(exe|dll|sys|scr|ocx|cpl|msi|msp|efi|drv|apk)$/i.test(n)) return true;
    if (!nameBytes || nameBytes.length < 4) return false;
    // 原始字节以 .exe/.dll/.apk/... 结尾（ASCII）
    const tail = [];
    for (let i = Math.max(0, nameBytes.length - 5); i < nameBytes.length; i++) {
      const c = nameBytes[i];
      if (c >= 32 && c < 127) tail.push(String.fromCharCode(c));
    }
    const t = tail.join("").toLowerCase();
    return /\.(exe|dll|sys|scr|ocx|cpl|msi|msp|efi|drv|apk)$/.test(t);
  }

  /** APK = ZIP 且含 AndroidManifest / classes.dex */
  function zipEntriesLookLikeApk(entries) {
    if (!entries || !entries.length) return false;
    let hasManifest = false;
    let hasDex = false;
    for (const e of entries) {
      const n = String(e.name || "").replace(/\\/g, "/");
      if (/^AndroidManifest\.xml$/i.test(n) || /\/AndroidManifest\.xml$/i.test(n)) hasManifest = true;
      if (/^classes(?:\d+)?\.dex$/i.test(n.split("/").pop() || "")) hasDex = true;
      if (hasManifest && hasDex) return true;
    }
    return hasManifest || hasDex;
  }

  function apkJarSignedFromEntries(entries) {
    if (!entries || !entries.length) return false;
    return entries.some((e) => {
      const n = String(e.name || "").replace(/\\/g, "/");
      return /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(n) || /^META-INF\/.+\.SF$/i.test(n);
    });
  }

  function basenameFromZipPath(name) {
    const s = String(name || "").replace(/\\/g, "/");
    const parts = s.split("/");
    return parts[parts.length - 1] || s;
  }

  /** 在文件前部找 ZIP 签名（兼容自解压 PE 头 + ZIP 尾） */
  function findZipStartOffset(ab) {
    try {
      const u8 = new Uint8Array(ab);
      if (u8.length < 4) return -1;
      if (u8[0] === 0x50 && u8[1] === 0x4b) return 0;
      const limit = Math.min(u8.length - 4, 4 * 1024 * 1024);
      for (let i = 0; i < limit; i++) {
        if (u8[i] !== 0x50 || u8[i + 1] !== 0x4b) continue;
        const b2 = u8[i + 2];
        const b3 = u8[i + 3];
        // local 0304 / central 0102 / eocd 0506 / data descriptor 0708
        if ((b2 === 0x03 && b3 === 0x04) || (b2 === 0x01 && b3 === 0x02)
          || (b2 === 0x05 && b3 === 0x06) || (b2 === 0x07 && b3 === 0x08)) {
          return i;
        }
      }
      return -1;
    } catch {
      return -1;
    }
  }

  function detectArchiveFormat(ab) {
    try {
      const u8 = new Uint8Array(ab, 0, Math.min(16, ab.byteLength));
      if (u8[0] === 0x50 && u8[1] === 0x4b) return "zip";
      if (u8[0] === 0x52 && u8[1] === 0x61 && u8[2] === 0x72 && u8[3] === 0x21) return "rar";
      if (u8[0] === 0x37 && u8[1] === 0x7a && u8[2] === 0xbc && u8[3] === 0xaf) return "7z";
      if (u8[0] === 0x1f && u8[1] === 0x8b) return "gzip";
      // 自解压：前有 MZ，后面嵌 ZIP
      if (u8[0] === 0x4d && u8[1] === 0x5a && findZipStartOffset(ab) > 0) return "zip";
      if (findZipStartOffset(ab) >= 0) return "zip";
      return "unknown";
    } catch {
      return "unknown";
    }
  }

  function sliceZipView(ab) {
    const off = findZipStartOffset(ab);
    if (off <= 0) return ab;
    return ab.slice(off);
  }

  function parseZipCentralEntries(ab) {
    try {
      const u8 = new Uint8Array(ab);
      const view = new DataView(ab);
      let eocd = -1;
      const min = Math.max(0, u8.length - 65557);
      for (let i = u8.length - 22; i >= min; i--) {
        if (view.getUint32(i, true) === 0x06054b50) {
          eocd = i;
          break;
        }
      }
      if (eocd < 0) return null;
      const cdOff = view.getUint32(eocd + 16, true);
      const cdTotal = view.getUint16(eocd + 10, true);
      // ZIP64 时 cdOff 可能是 0xffffffff —— 暂不支持超大包
      if (cdOff === 0xffffffff || cdOff >= u8.length) return null;
      const entries = [];
      let o = cdOff;
      for (let n = 0; n < cdTotal && o + 46 <= u8.length; n++) {
        if (view.getUint32(o, true) !== 0x02014b50) break;
        const method = view.getUint16(o + 10, true);
        const flags = view.getUint16(o + 8, true);
        let compSize = view.getUint32(o + 20, true);
        let uncompSize = view.getUint32(o + 24, true);
        const nameLen = view.getUint16(o + 28, true);
        const extraLen = view.getUint16(o + 30, true);
        const commentLen = view.getUint16(o + 32, true);
        let localOff = view.getUint32(o + 42, true);
        const nameBytes = u8.subarray(o + 46, o + 46 + nameLen);
        const name = decodeZipName(nameBytes, flags);
        // external attrs：DOS 低字节 bit4 = 目录
        const extAttr = view.getUint32(o + 38, true);
        const isDirAttr = !!(extAttr & 0x10) || ((((extAttr >>> 16) & 0xf000) === 0x4000));
        // ZIP64 extra (0x0001)
        const readU64 = (off) => {
          try {
            if (typeof view.getBigUint64 === "function") return Number(view.getBigUint64(off, true));
          } catch { /* fall */ }
          const lo = view.getUint32(off, true);
          const hi = view.getUint32(off + 4, true);
          return hi * 4294967296 + lo;
        };
        if ((compSize === 0xffffffff || uncompSize === 0xffffffff || localOff === 0xffffffff) && extraLen > 0) {
          let eo = o + 46 + nameLen;
          const eEnd = eo + extraLen;
          while (eo + 4 <= eEnd) {
            const tag = view.getUint16(eo, true);
            const sz = view.getUint16(eo + 2, true);
            if (tag === 0x0001 && eo + 4 + sz <= eEnd) {
              let p = eo + 4;
              if (uncompSize === 0xffffffff && p + 8 <= eo + 4 + sz) {
                uncompSize = readU64(p);
                p += 8;
              }
              if (compSize === 0xffffffff && p + 8 <= eo + 4 + sz) {
                compSize = readU64(p);
                p += 8;
              }
              if (localOff === 0xffffffff && p + 8 <= eo + 4 + sz) {
                localOff = readU64(p);
              }
              break;
            }
            eo += 4 + sz;
          }
        }
        entries.push({
          name,
          nameBytes,
          method,
          flags,
          compSize,
          uncompSize,
          localOff,
          isDirAttr
        });
        o += 46 + nameLen + extraLen + commentLen;
      }
      return entries;
    } catch {
      return null;
    }
  }

  /** 中央目录失败时：顺序扫 local file header */
  function parseZipLocalEntriesFallback(ab) {
    try {
      const u8 = new Uint8Array(ab);
      const view = new DataView(ab);
      const entries = [];
      let o = 0;
      let guard = 0;
      while (o + 30 < u8.length && guard++ < 5000) {
        const sig = view.getUint32(o, true);
        if (sig === 0x02014b50 || sig === 0x06054b50) break; // central / eocd
        if (sig !== 0x04034b50) {
          o += 1;
          continue;
        }
        const flags = view.getUint16(o + 6, true);
        const method = view.getUint16(o + 8, true);
        let compSize = view.getUint32(o + 18, true);
        let uncompSize = view.getUint32(o + 22, true);
        const nameLen = view.getUint16(o + 26, true);
        const extraLen = view.getUint16(o + 28, true);
        const nameBytes = u8.subarray(o + 30, o + 30 + nameLen);
        const name = decodeZipName(nameBytes, flags);
        const dataStart = o + 30 + nameLen + extraLen;
        // data descriptor：尺寸在数据后，尽力跳过（不可靠），无 central 时尽量用 header 尺寸
        if ((flags & 0x8) && (compSize === 0 || uncompSize === 0)) {
          // 无法可靠定位下一 entry，停止顺序扫描
          break;
        }
        if (dataStart + compSize > u8.length) break;
        entries.push({
          name,
          nameBytes,
          method,
          flags,
          compSize,
          uncompSize,
          localOff: o,
          _dataStart: dataStart
        });
        o = dataStart + compSize;
        if (flags & 0x8) {
          // optional data descriptor 12 or 16 bytes
          if (o + 4 <= u8.length && view.getUint32(o, true) === 0x08074b50) o += 16;
          else o += 12;
        }
      }
      return entries;
    } catch {
      return [];
    }
  }

  function readZipLocalPayload(ab, entry) {
    try {
      const view = new DataView(ab);
      const u8 = new Uint8Array(ab);
      if (entry._dataStart != null) {
        const ds = entry._dataStart;
        const cs = entry.compSize;
        if (ds + cs > ab.byteLength) return null;
        if (entry.flags & 0x1) return null;
        return {
          name: entry.name,
          method: entry.method,
          uncompSize: entry.uncompSize,
          data: u8.subarray(ds, ds + cs)
        };
      }
      const o = entry.localOff;
      if (o < 0 || o + 30 > ab.byteLength) return null;
      if (view.getUint32(o, true) !== 0x04034b50) return null;
      const nameLen = view.getUint16(o + 26, true);
      const extraLen = view.getUint16(o + 28, true);
      const dataStart = o + 30 + nameLen + extraLen;
      let compSize = entry.compSize;
      // 若 central 尺寸异常，尝试 local header 尺寸
      if (!compSize || compSize > ab.byteLength) {
        const locComp = view.getUint32(o + 18, true);
        if (locComp > 0 && dataStart + locComp <= ab.byteLength) compSize = locComp;
      }
      if (dataStart + compSize > ab.byteLength) return null;
      if (entry.flags & 0x1) return null;
      return {
        name: entry.name,
        method: entry.method,
        uncompSize: entry.uncompSize,
        data: u8.subarray(dataStart, dataStart + compSize)
      };
    } catch {
      return null;
    }
  }

  function copyToArrayBuffer(u8) {
    const out = new ArrayBuffer(u8.byteLength);
    new Uint8Array(out).set(u8);
    return out;
  }

  function isMzPeBuffer(ab) {
    try {
      if (!ab || ab.byteLength < 0x40) return false;
      const v = new DataView(ab);
      return v.getUint16(0, true) === 0x5a4d; // MZ
    } catch {
      return false;
    }
  }

  function isOleMsiBuffer(ab) {
    try {
      if (!ab || ab.byteLength < 8) return false;
      const u = new Uint8Array(ab, 0, 4);
      return u[0] === 0xd0 && u[1] === 0xcf && u[2] === 0x11 && u[3] === 0xe0;
    } catch {
      return false;
    }
  }

  function readU16LE(u8, o) {
    return u8[o] | (u8[o + 1] << 8);
  }
  function readU32LE(u8, o) {
    return (u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24)) >>> 0;
  }

  /**
   * 估算 PE 在文件中的原始占用（含 Authenticode 证书表）。
   * 用于 ZIP store 模式下在裸缓冲区里切出完整 PE。
   */
  function estimatePeRawSize(u8, off) {
    try {
      if (off < 0 || off + 0x40 >= u8.length) return 0;
      if (u8[off] !== 0x4d || u8[off + 1] !== 0x5a) return 0;
      const e_lfanew = readU32LE(u8, off + 0x3c);
      if (e_lfanew < 0x40 || e_lfanew > 0x1000) return 0;
      if (off + e_lfanew + 24 >= u8.length) return 0;
      if (readU32LE(u8, off + e_lfanew) !== 0x00004550) return 0;
      const coff = off + e_lfanew + 4;
      const numSec = readU16LE(u8, coff + 2);
      const sizeOpt = readU16LE(u8, coff + 16);
      if (numSec <= 0 || numSec > 96 || sizeOpt < 96 || sizeOpt > 0x400) return 0;
      const optOff = coff + 20;
      if (optOff + sizeOpt > u8.length) return 0;
      const magic = readU16LE(u8, optOff);
      let sizeOfHeaders = 0;
      let ddBase = 0;
      if (magic === 0x10b) {
        sizeOfHeaders = readU32LE(u8, optOff + 60);
        ddBase = optOff + 96;
      } else if (magic === 0x20b) {
        sizeOfHeaders = readU32LE(u8, optOff + 60);
        ddBase = optOff + 112;
      } else return 0;
      let maxEnd = sizeOfHeaders || 0;
      const secTable = optOff + sizeOpt;
      for (let i = 0; i < numSec; i++) {
        const s = secTable + i * 40;
        if (s + 40 > u8.length) break;
        const rawSize = readU32LE(u8, s + 16);
        const rawPtr = readU32LE(u8, s + 20);
        if (rawPtr > 0 && rawSize > 0) {
          const end = rawPtr + rawSize;
          if (end > maxEnd) maxEnd = end;
        }
      }
      // Authenticode 证书目录（文件偏移）
      if (ddBase + 4 * 8 + 8 <= u8.length) {
        const certOff = readU32LE(u8, ddBase + 4 * 8);
        const certSize = readU32LE(u8, ddBase + 4 * 8 + 4);
        if (certOff > 0 && certSize >= 8 && certOff + certSize > maxEnd) {
          maxEnd = certOff + certSize;
        }
      }
      if (maxEnd < 0x200 || maxEnd > MAX_NESTED_BYTES) return 0;
      if (off + maxEnd > u8.length) {
        // 截断到可用长度（至少要有 PE 头）
        maxEnd = u8.length - off;
        if (maxEnd < 0x200) return 0;
      }
      return maxEnd;
    } catch {
      return 0;
    }
  }

  /**
   * 兜底：在 ZIP 原始字节里找 store 进包的 PE（不依赖中央目录解压成功）。
   */
  function scanRawBufferForPeSignatures(ab, limit) {
    const items = [];
    try {
      const u8 = ab instanceof Uint8Array ? ab : new Uint8Array(ab);
      const maxScan = Math.min(u8.length - 0x200, 64 * 1024 * 1024);
      const stepLimit = limit || MAX_NESTED_SCAN;
      let i = 0;
      let hits = 0;
      while (i < maxScan && items.length < stepLimit) {
        // 找 MZ
        if (u8[i] !== 0x4d || u8[i + 1] !== 0x5a) {
          i++;
          continue;
        }
        const peSize = estimatePeRawSize(u8, i);
        if (!peSize) {
          i++;
          continue;
        }
        // 避免把 ZIP 自身局部头附近的噪声当 PE（极少 MZ 误报）
        try {
          const slice = u8.subarray(i, i + peSize);
          const fileAb = copyToArrayBuffer(slice);
          const pe = NS.parsePeAuthenticode(fileAb);
          if (pe && pe.isPe) {
            hits++;
            let sha256 = "";
            try {
              // 同步路径无法 await；sha 在 attachVt 前由调用方补也行
              // 这里用占位，上层 attachVtToNestedItems 需要 sha256
            } catch { /* ignore */ }
            items.push({
              name: "embedded_" + hits + ".exe",
              path: "raw@" + i,
              kind: "pe",
              signed: !!pe.signed,
              signerHint: pe.signerHint || "",
              sigTrust: pe.signed ? "present" : "none",
              sha256,
              _fileAb: fileAb
            });
            i += Math.max(peSize - 0x100, 0x200); // 跳过本 PE 主体
            continue;
          }
        } catch { /* next */ }
        i += 0x40;
      }
    } catch { /* ignore */ }
    return items;
  }

  function openArchiveTaskDb() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(ARCHIVE_TASK_DB, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(ARCHIVE_TASK_STORE)) {
          db.createObjectStore(ARCHIVE_TASK_STORE, { keyPath: "id" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("archive-db-open-failed"));
    });
  }

  async function putArchiveTask(record) {
    const db = await openArchiveTaskDb();
    try {
      await new Promise((resolve, reject) => {
        const tx = db.transaction(ARCHIVE_TASK_STORE, "readwrite");
        const store = tx.objectStore(ARCHIVE_TASK_STORE);
        store.put(record);
        // 顺便清理上次浏览器异常退出留下的任务。
        const all = store.openCursor();
        all.onsuccess = () => {
          const cursor = all.result;
          if (!cursor) return;
          const value = cursor.value;
          if (value && value.id !== record.id && Date.now() - Number(value.createdAt || 0) > 10 * 60 * 1000) {
            cursor.delete();
          }
          cursor.continue();
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("archive-task-write-failed"));
        tx.onabort = () => reject(tx.error || new Error("archive-task-write-aborted"));
      });
    } finally {
      db.close();
    }
  }

  async function getArchiveTask(id) {
    const db = await openArchiveTaskDb();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(ARCHIVE_TASK_STORE, "readonly");
        const request = tx.objectStore(ARCHIVE_TASK_STORE).get(id);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error || new Error("archive-task-read-failed"));
      });
    } finally {
      db.close();
    }
  }

  async function deleteArchiveTask(id) {
    const db = await openArchiveTaskDb();
    try {
      await new Promise((resolve, reject) => {
        const tx = db.transaction(ARCHIVE_TASK_STORE, "readwrite");
        tx.objectStore(ARCHIVE_TASK_STORE).delete(id);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("archive-task-delete-failed"));
        tx.onabort = () => reject(tx.error || new Error("archive-task-delete-aborted"));
      });
    } finally {
      db.close();
    }
  }

  async function archiveOffscreenExists() {
    const documentUrl = chrome.runtime.getURL("offscreen/archive.html");
    if (chrome.runtime && typeof chrome.runtime.getContexts === "function") {
      try {
        const contexts = await chrome.runtime.getContexts({
          contextTypes: ["OFFSCREEN_DOCUMENT"],
          documentUrls: [documentUrl]
        });
        return Array.isArray(contexts) && contexts.length > 0;
      } catch { /* use hasDocument fallback */ }
    }
    if (chrome.offscreen && typeof chrome.offscreen.hasDocument === "function") {
      try { return !!(await chrome.offscreen.hasDocument()); } catch { return false; }
    }
    // Chromium 109-115 没有 runtime.getContexts；按官方建议从 SW clients 查找。
    if (typeof clients !== "undefined" && clients && typeof clients.matchAll === "function") {
      try {
        const matched = await clients.matchAll();
        return (matched || []).some((client) => client && client.url === documentUrl);
      } catch { return false; }
    }
    return false;
  }

  async function ensureArchiveOffscreenDocument() {
    if (!chrome.offscreen || typeof chrome.offscreen.createDocument !== "function") {
      throw new Error("offscreen-api-unavailable");
    }
    if (await archiveOffscreenExists()) return;
    if (!archiveOffscreenCreatePromise) {
      archiveOffscreenCreatePromise = chrome.offscreen.createDocument({
        url: "offscreen/archive.html",
        reasons: ["WORKERS"],
        justification: "使用本地 WASM 安全检查 RAR/7z 压缩包内的可执行文件"
      }).catch(async (error) => {
        // 两个并发扫描可能都先看到不存在；另一方创建成功时可直接复用。
        if (await archiveOffscreenExists()) return;
        throw error;
      }).finally(() => {
        archiveOffscreenCreatePromise = null;
      });
    }
    await archiveOffscreenCreatePromise;
  }

  function sendArchiveOffscreenMessage(taskId) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        target: "archive-offscreen",
        type: "silverfox-archive-extract",
        taskId
      }, (response) => {
        const error = chrome.runtime.lastError;
        if (error) {
          reject(new Error(error.message || "archive-offscreen-message-failed"));
          return;
        }
        if (!response || response.ok !== true) {
          reject(new Error(response && response.error || "archive-offscreen-no-response"));
          return;
        }
        resolve(response);
      });
    });
  }

  async function runArchiveDecoderTask(arrayBuffer, format) {
    if (arrayBuffer.byteLength > MAX_WASM_ARCHIVE_BYTES) {
      return {
        status: "too-large",
        format,
        extracted: [],
        note: `${format.toUpperCase()} 超过本地安全拆包上限（${Math.round(MAX_WASM_ARCHIVE_BYTES / 1048576)}MB）`
      };
    }
    const taskId = (crypto && typeof crypto.randomUUID === "function")
      ? crypto.randomUUID()
      : `archive-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await putArchiveTask({
      id: taskId,
      createdAt: Date.now(),
      format,
      input: arrayBuffer,
      limits: {
        maxEntries: MAX_WASM_ARCHIVE_ENTRIES,
        maxCandidates: Math.max(MAX_NESTED_SCAN, 16),
        maxFileBytes: MAX_NESTED_BYTES,
        maxTotalBytes: MAX_WASM_EXTRACT_TOTAL
      }
    });
    let timer = null;
    try {
      await ensureArchiveOffscreenDocument();
      await Promise.race([
        sendArchiveOffscreenMessage(taskId),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("archive-offscreen-timeout")), WASM_ARCHIVE_TIMEOUT_MS);
        })
      ]);
      const stored = await getArchiveTask(taskId);
      if (!stored || !stored.result) throw new Error("archive-offscreen-result-missing");
      return stored.result;
    } finally {
      if (timer) clearTimeout(timer);
      try { await deleteArchiveTask(taskId); } catch { /* stale task cleanup handles it later */ }
    }
  }

  async function scanRarOr7zExecutables(arrayBuffer, format) {
    const result = { items: [], format, note: "" };
    let decoded = null;
    try {
      decoded = await runArchiveDecoderTask(arrayBuffer, format);
    } catch (error) {
      const message = String(error && error.message || error || "");
      if (/offscreen-api-unavailable/i.test(message)) {
        result.note = `${format.toUpperCase()} 本地解码需要 Chromium 109 或更高版本`;
      } else if (/timeout/i.test(message)) {
        result.note = `${format.toUpperCase()} 解码超时，已终止本地拆包`;
      } else {
        result.note = `${format.toUpperCase()} 本地解码失败（压缩包可能损坏或缺少分卷）`;
      }
      try { console.warn("[silverfox] archive-wasm task", format, error); } catch { /* ignore */ }
      return result;
    }

    result.note = String(decoded && decoded.note || "");
    const extracted = Array.isArray(decoded && decoded.extracted) ? decoded.extracted : [];
    for (const entry of extracted) {
      if (result.items.length >= MAX_NESTED_SCAN) break;
      const fileAb = entry && entry.buffer;
      if (!(fileAb instanceof ArrayBuffer) || fileAb.byteLength < 64) continue;
      await pushNestedFromBuffer(
        result.items,
        fileAb,
        String(entry.name || basenameFromZipPath(entry.path) || "file.bin"),
        String(entry.path || entry.name || "file.bin"),
        !!entry.byExt
      );
    }
    if (result.items.length && !(decoded && decoded.truncatedEntries)
      && !(decoded && decoded.skippedTooLarge)
      && Number(decoded && decoded.candidatesTotal || 0) <= Math.max(MAX_NESTED_SCAN, 16)) {
      result.note = "";
    }
    try {
      console.log("[silverfox] archive-wasm nested", format, {
        entries: Number(decoded && decoded.entriesTotal || 0),
        candidates: Number(decoded && decoded.candidatesTotal || 0),
        extracted: extracted.length,
        matched: result.items.length,
        status: decoded && decoded.status
      });
    } catch { /* ignore */ }
    return result;
  }

  /**
   * 从 ZIP/RAR/7z 中抽出可执行成员并做 PE 签名粗检。
   * 策略：扩展名优先；扩展名匹配不到时，对包内文件解压并用 MZ/OLE 魔数探测。
   * 返回 { items, format, note }
   */
  async function scanNestedExecutablesInArchive(arrayBuffer) {
    const result = { items: [], format: "unknown", note: "" };
    if (!arrayBuffer || arrayBuffer.byteLength < 64) {
      result.note = "文件过小";
      return result;
    }
    result.format = detectArchiveFormat(arrayBuffer);
    if (result.format === "rar") {
      return scanRarOr7zExecutables(arrayBuffer, "rar");
    }
    if (result.format === "7z") {
      return scanRarOr7zExecutables(arrayBuffer, "7z");
    }
    if (result.format !== "zip") {
      result.note = "无法识别为 ZIP（扩展名可能被伪装）";
      return result;
    }

    // 去掉自解压 stub，只解析 ZIP 区段
    const zipAb = sliceZipView(arrayBuffer);
    let entries = parseZipCentralEntries(zipAb);
    let parseVia = "central";
    if (!entries || !entries.length) {
      entries = parseZipLocalEntriesFallback(zipAb);
      parseVia = "local";
    }
    if (!entries || !entries.length) {
      result.note = "ZIP 目录解析失败";
      try { console.warn("[silverfox] zip: no entries", arrayBuffer.byteLength); } catch { /* ignore */ }
      return result;
    }

    // 全部「文件」项；尺寸虚高不直接丢弃（很多安装包 >12MB）
    const fileEntries = [];
    let skippedMethod = 0;
    let skippedCrypt = 0;
    let skippedDir = 0;
    let skippedSize = 0;
    for (let ei = 0; ei < entries.length; ei++) {
      const e = entries[ei];
      if (!e) continue;
      const rawName = String(e.name || "");
      const looksDir = !!(e.isDirAttr)
        || /[/\\]\s*$/.test(rawName)
        || rawName.endsWith("/")
        || rawName.endsWith("\\");
      // 名称像 exe 时即使带目录属性也试（个别打包工具脏属性）
      let base = basenameFromZipPath(rawName);
      if (!base) base = "entry_" + ei;
      const byExtEarly = zipEntryLooksExecutable(rawName, e.nameBytes)
        || zipEntryLooksExecutable(base, e.nameBytes);
      if (looksDir && !byExtEarly) {
        skippedDir++;
        continue;
      }
      if (e.flags & 0x1) {
        skippedCrypt++;
        continue;
      }
      if (e.method !== 0 && e.method !== 8) {
        skippedMethod++;
        continue;
      }
      // 仅当「压缩后」就超过上限才跳过；uncomp 虚高仍尝试解压
      if (e.compSize > 0 && e.compSize !== 0xffffffff && e.compSize > MAX_NESTED_BYTES) {
        skippedSize++;
        continue;
      }
      const byExt = byExtEarly;
      fileEntries.push({ e, base, byExt });
    }

    // 仍为空：强制纳入所有非加密条目再试（避免 1 个文件被误判目录/尺寸）
    if (!fileEntries.length && entries.length) {
      for (let ei = 0; ei < entries.length; ei++) {
        const e = entries[ei];
        if (!e || (e.flags & 0x1)) continue;
        if (e.method !== 0 && e.method !== 8) continue;
        let base = basenameFromZipPath(e.name || "") || ("entry_" + ei);
        fileEntries.push({
          e,
          base,
          byExt: zipEntryLooksExecutable(e.name, e.nameBytes) || zipEntryLooksExecutable(base, e.nameBytes)
        });
      }
      if (fileEntries.length) {
        try { console.warn("[silverfox] zip force-include entries", fileEntries.length); } catch { /* ignore */ }
      }
    }

    if (!fileEntries.length) {
      const sample = entries.slice(0, 6).map((x) => {
        const n = String(x.name || "");
        return `${n || "?"} method=${x.method} flags=${x.flags} comp=${x.compSize} uncomp=${x.uncompSize}`;
      }).join("; ");
      result.note = `ZIP 有 ${entries.length} 项仍无法处理（目录 ${skippedDir}/加密 ${skippedCrypt}/算法 ${skippedMethod}/过大 ${skippedSize}）${sample ? " · " + sample : ""}`;
      try {
        console.warn("[silverfox] zip empty files", {
          entries: entries.length,
          skippedDir,
          skippedCrypt,
          skippedMethod,
          skippedSize,
          sample: entries.slice(0, 12).map((x) => ({
            name: x.name,
            method: x.method,
            flags: x.flags,
            comp: x.compSize,
            uncomp: x.uncompSize,
            isDirAttr: x.isDirAttr
          }))
        });
      } catch { /* ignore */ }
      return result;
    }

    // 扩展名命中优先；其余靠 MZ 探测
    fileEntries.sort((a, b) => {
      if (a.byExt !== b.byExt) return a.byExt ? -1 : 1;
      const da = (String(a.e.name).match(/[/\\]/g) || []).length;
      const db = (String(b.e.name).match(/[/\\]/g) || []).length;
      return da - db || (a.e.uncompSize || 0) - (b.e.uncompSize || 0);
    });

    // 扩展名命中的都试；再额外对非扩展名项做魔数探测（上限）
    const byExtList = fileEntries.filter((x) => x.byExt);
    const otherList = fileEntries.filter((x) => !x.byExt);
    const toTry = byExtList.concat(otherList).slice(0, Math.max(MAX_NESTED_SCAN, 16));

    let tried = 0;
    let inflateFail = 0;
    let mzHits = 0;

    // 整包本身就是 APK：记一条 APK 项（验 META-INF 签名），不扫“未找到 PE”噪音
    if (zipEntriesLookLikeApk(entries)) {
      result.isApkContainer = true;
      const jarSigned = apkJarSignedFromEntries(entries);
      // 外层 APK 由调用方处理；这里仍可列出内嵌 so/dex 否。只记签名状态供上层。
      result.apkSigned = jarSigned;
    }

    for (const { e, base, byExt } of toTry) {
      if (result.items.length >= MAX_NESTED_SCAN) break;
      try {
        const payload = readZipLocalPayload(zipAb, e);
        if (!payload || !payload.data || !payload.data.byteLength) {
          inflateFail++;
          continue;
        }
        let fileAb = null;
        if (payload.method === 0) {
          fileAb = copyToArrayBuffer(payload.data);
        } else if (payload.method === 8) {
          fileAb = await inflateZipPayload(payload.data);
        }
        tried++;
        if (!fileAb || fileAb.byteLength < 64) {
          inflateFail++;
          continue;
        }

        const displayName = base || basenameFromZipPath(e.name) || "file.bin";
        const before = result.items.length;
        await pushNestedFromBuffer(result.items, fileAb, displayName, e.name, byExt);
        if (result.items.length > before && result.items[result.items.length - 1].kind === "pe") {
          mzHits++;
        }
      } catch {
        inflateFail++;
      }
    }

    // 目录解压失败时：裸扫 ZIP 缓冲里 store 的 PE
    if (!result.items.length) {
      try {
        const rawHits = scanRawBufferForPeSignatures(zipAb, MAX_NESTED_SCAN);
        if (rawHits.length) {
          // 补 sha256 供 VT
          for (const h of rawHits) {
            if (!h.sha256 && h.pe) {
              // pe 无 buffer；raw 扫描未留 ab — 跳过 sha
            }
          }
          result.items = rawHits;
          result.note = "";
          try { console.log("[silverfox] zip raw-MZ hits", rawHits.length); } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
    }

    if (!result.items.length) {
      // 非错误：只是包内没有我们关心的 PE/APK/MSI（文档/图片等已静默过滤）
      if (result.isApkContainer) {
        result.note = "";
      } else if (inflateFail > 0 && byExtList.length > 0) {
        result.note = "包内目标文件解压失败（可能加密或损坏）";
      } else {
        result.note = ""; // 不报「未扫到 PE」吓人话术
      }
      try {
        console.log("[silverfox] zip no target items", {
          parseVia,
          entries: entries.length,
          files: fileEntries.length,
          byExt: byExtList.length,
          tried,
          inflateFail,
          isApk: !!result.isApkContainer
        });
      } catch { /* ignore */ }
    } else {
      result.note = "";
      try {
        console.log("[silverfox] zip nested", result.items.length, "mz", mzHits, parseVia,
          result.items.map((x) => x.name + ":" + x.kind + (x.signed ? ":signed" : "")).join(", "));
      } catch { /* ignore */ }
    }
    return result;
  }

  /** 综合签名 + VT 给出风险条目（给 popup「风险检测」） */
  function buildFileRiskLines(report, context) {
    const risks = [];
    const trustedSource = !!(context && context.trustedSource);
    const requireSignedPe = !!(context && context.requireSignedPe);
    const pe = report && report.pe;
    const vt = report && report.vt;
    const sig = report && report.signature;
    const nested = (report && report.nested) || [];
    // 数字签名进独立行，风险里只报严重问题
    if (sig && sig.trust === "invalid") {
      risks.push({ level: "high", text: "数字签名无效/不可信（VT 或证书异常）" });
    } else if (!trustedSource && requireSignedPe && pe && pe.isPe && !pe.signed) {
      risks.push({ level: "medium", text: "未检测到数字签名（来源页处于下载保护状态）" });
    } else if (!trustedSource && requireSignedPe && nested.length && nested.every((n) => !n.signed && n.kind === "pe")) {
      risks.push({ level: "medium", text: "压缩包内可执行文件均未检测到数字签名" });
    }
    if (vt) {
      const mal = Number(vt.malicious) || 0;
      const sus = Number(vt.suspicious) || 0;
      const trustedCount = Number(vt.trustedEngineCount) || 0;
      const trustedNames = Array.isArray(vt.trustedDetections)
        ? vt.trustedDetections.map((x) => x && x.engine).filter(Boolean).slice(0, 8)
        : [];
      const trustedDetails = Array.isArray(vt.trustedDetections)
        ? vt.trustedDetections.map((x) => {
          const engine = String((x && x.engine) || "").trim();
          const result = String((x && x.result) || "").replace(/\s+/g, " ").trim().slice(0, 48);
          return engine ? `${engine}${result ? `（${result}）` : ""}` : "";
        }).filter(Boolean).slice(0, 8)
        : [];
      const trustedObserved = Array.isArray(vt.trustedEngineResults)
        ? vt.trustedEngineResults.map((x) => x && x.engine).filter(Boolean)
        : [];
      const trustedObservedCount = Math.max(Number(vt.trustedEngineObservedCount) || 0, trustedObserved.length);
      // 仅明确 notFound 且非 softMiss 才报「无此文件」
      const none = vt.notFound === true && !vt.softMiss && vt.unknown !== true;
      if (none) {
        // VT 无记录只说明样本尚未入库，不是恶意证据。
      } else if (vt.softMiss || vt.unknown || vt.found == null) {
        // 查询未完成属于检测状态，不是风险结论；popup 的 VirusTotal 行单独提示。
      } else if (trustedCount >= 2) {
        risks.push({
          level: "high",
          text: `VT 知名引擎共识 ${trustedCount} 家：${trustedDetails.join("、") || trustedNames.join("、") || "已确认恶意"}`
        });
      } else if (trustedCount === 1) {
        risks.push({
          level: "medium",
          text: `VT 单个知名引擎检出：${trustedDetails[0] || trustedNames[0] || "未知"}（尚未形成共识）`
        });
      } else if ((mal >= 1 || sus >= 1) && vt.engineDetailsAvailable !== true) {
        risks.push({
          level: "medium",
          text: `VT 总检出 ${mal + sus} 家；正在补取逐引擎检测结果`
        });
      } else if (mal >= 1 || sus >= 1) {
        if (trustedObservedCount >= VT_TRUSTED_ENGINE_RULES.length) {
          risks.push({ level: "low", text: "VT 未见恶意检出" });
        } else if (trustedObservedCount > 0) {
          risks.push({
            level: "medium",
            text: `VT 指定引擎未检出（已取得 ${trustedObservedCount}/5 家：${trustedObserved.join("、")}）`
          });
        } else {
          risks.push({ level: "medium", text: `VT 总检出 ${mal + sus} 家；尚未取得指定五家引擎结果` });
        }
      } else if (vt.found === true && mal === 0) {
        risks.push({ level: "low", text: "VT 未见恶意检出" });
      }
    }
    return risks;
  }

  function withTimeout(promise, ms) {
    return Promise.race([
      Promise.resolve(promise).catch((e) => {
        throw e;
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))
    ]);
  }

  async function fetchArrayBuffer(url, opts) {
    const timeoutMs = (opts && opts.timeoutMs) || FETCH_TIMEOUT_MS;
    const maxBytes = (opts && opts.maxBytes) || MAX_FULL_FETCH;
    const headers = (opts && opts.headers) || {};
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => {
      try { controller.abort(); } catch { /* ignore */ }
    }, timeoutMs) : null;
    try {
      const res = await fetch(url, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "follow",
        signal: controller ? controller.signal : undefined,
        headers
      });
      if (timer) clearTimeout(timer);
      if (!res.ok) return { ok: false, status: res.status, buf: null, headers: res.headers };
      const len = Number(res.headers.get("content-length") || 0);
      if (len > maxBytes) {
        return {
          ok: false,
          status: res.status,
          buf: null,
          tooLarge: true,
          contentLength: len,
          headers: res.headers
        };
      }
      const ab = await res.arrayBuffer();
      if (ab.byteLength > maxBytes) {
        return {
          ok: false,
          status: res.status,
          buf: null,
          tooLarge: true,
          contentLength: ab.byteLength,
          headers: res.headers
        };
      }
      return { ok: true, status: res.status, buf: ab, headers: res.headers, contentLength: ab.byteLength };
    } catch (e) {
      if (timer) clearTimeout(timer);
      return {
        ok: false,
        status: 0,
        buf: null,
        error: e && e.message ? e.message : "fetch-fail"
      };
    }
  }

  /** HTTP Range 拉取 [start, end] 闭区间 */
  async function fetchByteRange(url, start, end, timeoutMs) {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => {
      try { controller.abort(); } catch { /* ignore */ }
    }, timeoutMs || 30000) : null;
    try {
      const res = await fetch(url, {
        method: "GET",
        credentials: "omit",
        cache: "no-store",
        redirect: "follow",
        signal: controller ? controller.signal : undefined,
        headers: {
          Range: "bytes=" + start + "-" + end,
          Accept: "*/*"
        }
      });
      if (timer) clearTimeout(timer);
      if (res.status !== 206 && res.status !== 200) {
        return { ok: false, status: res.status, buf: null, rangeSupported: res.status !== 200 };
      }
      const ab = await res.arrayBuffer();
      return {
        ok: true,
        status: res.status,
        buf: ab,
        rangeSupported: res.status === 206
      };
    } catch (e) {
      if (timer) clearTimeout(timer);
      return {
        ok: false,
        status: 0,
        buf: null,
        error: e && e.message ? e.message : "range-fail"
      };
    }
  }

  async function headContentLength(url) {
    try {
      const res = await fetch(url, {
        method: "HEAD",
        credentials: "omit",
        cache: "no-store",
        redirect: "follow"
      });
      if (!res.ok) return 0;
      return Number(res.headers.get("content-length") || 0) || 0;
    } catch {
      return 0;
    }
  }

  /**
   * 超大 ZIP：Range 读尾部 EOCD + 中央目录，再按需 Range 抽取包内 PE。
   * 不需要把整包载入内存。
   */
  async function scanLargeZipByHttpRange(url) {
    const result = {
      items: [],
      format: "zip",
      note: "",
      contentLength: 0,
      partial: true
    };
    let total = await headContentLength(url);
    if (!total || total < 64) {
      // HEAD 失败：试 Range 最后 1 字节拿 Content-Range
      const probe = await fetchByteRange(url, 0, 0, 15000);
      if (probe.ok && probe.buf) {
        // 若 200 返回全文则放弃 range 路径
        if (probe.status === 200 && probe.buf.byteLength > 2) {
          result.note = "服务器不支持分段下载，且文件过大";
          return result;
        }
      }
      result.note = "无法获取文件大小，跳过超大包扫描";
      return result;
    }
    result.contentLength = total;
    if (total > MAX_RANGE_ARCHIVE) {
      result.note = "文件超过 650MB，跳过包内扫描（" + Math.round(total / 1048576) + "MB）";
      return result;
    }

    // 读尾部 512KB 找 EOCD
    const tailLen = Math.min(total, 512 * 1024);
    const tailStart = total - tailLen;
    const tailRes = await fetchByteRange(url, tailStart, total - 1, 45000);
    if (!tailRes.ok || !tailRes.buf) {
      result.note = "分段读取 ZIP 尾部失败（服务器可能不支持 Range）";
      return result;
    }
    if (tailRes.status === 200 && tailRes.buf.byteLength === total && total > MAX_FULL_FETCH) {
      // 服务器忽略 Range，塞了全文但我们不应整包吃掉
      result.note = "服务器忽略 Range 且文件过大";
      return result;
    }

    const tailU8 = new Uint8Array(tailRes.buf);
    const tailView = new DataView(tailRes.buf);
    let eocdRel = -1;
    for (let i = tailU8.length - 22; i >= 0; i--) {
      if (tailView.getUint32(i, true) === 0x06054b50) {
        eocdRel = i;
        break;
      }
    }
    if (eocdRel < 0) {
      result.note = "ZIP 尾部未找到中央目录（EOCD）";
      return result;
    }
    const cdOff = tailView.getUint32(eocdRel + 16, true);
    const cdTotal = tailView.getUint16(eocdRel + 10, true);
    if (cdOff === 0xffffffff || cdOff >= total) {
      result.note = "ZIP64 超大目录暂不支持分段扫描";
      return result;
    }
    // 中央目录可能不在 tail 里
    let cdBuf = null;
    const cdEnd = total - (tailU8.length - eocdRel); // absolute end before eocd... better:
    // EOCD absolute offset
    const eocdAbs = tailStart + eocdRel;
    const cdSizeFromEocd = tailView.getUint32(eocdRel + 12, true);
    const cdAbs = cdOff;
    const cdNeed = Math.min(cdSizeFromEocd || (eocdAbs - cdAbs), 8 * 1024 * 1024);
    if (cdAbs >= tailStart) {
      // 中央目录已在 tail 内
      const rel = cdAbs - tailStart;
      cdBuf = tailRes.buf.slice(rel, rel + Math.min(cdNeed, tailU8.length - rel));
    } else {
      const cdRes = await fetchByteRange(url, cdAbs, cdAbs + cdNeed - 1, 45000);
      if (!cdRes.ok || !cdRes.buf) {
        result.note = "分段读取 ZIP 中央目录失败";
        return result;
      }
      cdBuf = cdRes.buf;
    }

    // 把 central directory 伪装成 mini-zip 来复用 parseZipCentralEntries？更简单：手写扫 CD
    const entries = [];
    try {
      const u8 = new Uint8Array(cdBuf);
      const view = new DataView(cdBuf);
      let o = 0;
      for (let n = 0; n < cdTotal && o + 46 <= u8.length; n++) {
        if (view.getUint32(o, true) !== 0x02014b50) break;
        const method = view.getUint16(o + 10, true);
        const flags = view.getUint16(o + 8, true);
        const compSize = view.getUint32(o + 20, true);
        const uncompSize = view.getUint32(o + 24, true);
        const nameLen = view.getUint16(o + 28, true);
        const extraLen = view.getUint16(o + 30, true);
        const commentLen = view.getUint16(o + 32, true);
        const localOff = view.getUint32(o + 42, true);
        const nameBytes = u8.subarray(o + 46, o + 46 + nameLen);
        const name = decodeZipName(nameBytes, flags);
        const extAttr = view.getUint32(o + 38, true);
        const isDirAttr = !!(extAttr & 0x10);
        entries.push({
          name,
          nameBytes,
          method,
          flags,
          compSize,
          uncompSize,
          localOff,
          isDirAttr
        });
        o += 46 + nameLen + extraLen + commentLen;
      }
    } catch {
      result.note = "解析 ZIP 中央目录失败";
      return result;
    }

    if (!entries.length) {
      result.note = "ZIP 中央目录为空";
      return result;
    }

    // 选可执行候选
    const candidates = [];
    for (let ei = 0; ei < entries.length; ei++) {
      const e = entries[ei];
      const rawName = String(e.name || "");
      let base = basenameFromZipPath(rawName) || ("entry_" + ei);
      const looksDir = e.isDirAttr || /[/\\]$/.test(rawName);
      const byExt = zipEntryLooksExecutable(rawName, e.nameBytes)
        || zipEntryLooksExecutable(base, e.nameBytes);
      if (looksDir && !byExt) continue;
      if (e.flags & 0x1) continue;
      if (e.method !== 0 && e.method !== 8) continue;
      if (e.compSize > MAX_NESTED_BYTES) continue;
      candidates.push({ e, base, byExt });
    }
    candidates.sort((a, b) => (a.byExt === b.byExt ? 0 : a.byExt ? -1 : 1));

    const toTry = candidates.slice(0, MAX_NESTED_SCAN);
    // 无扩展名命中时，仍尝试前几个非目录条目靠 MZ
    if (!toTry.length) {
      for (let ei = 0; ei < Math.min(entries.length, 8); ei++) {
        const e = entries[ei];
        if ((e.flags & 0x1) || (e.method !== 0 && e.method !== 8)) continue;
        if (e.compSize > MAX_NESTED_BYTES) continue;
        toTry.push({
          e,
          base: basenameFromZipPath(e.name) || ("entry_" + ei),
          byExt: false
        });
      }
    }

    for (const { e, base, byExt } of toTry) {
      if (result.items.length >= MAX_NESTED_SCAN) break;
      try {
        // Range: local header + compressed payload
        // local header 最大约 30+64k+64k，再加 compSize
        const need = 30 + 65536 + 65536 + (e.compSize || 0) + 64;
        const end = Math.min(total - 1, e.localOff + need - 1);
        if (e.localOff >= total) continue;
        const chunk = await fetchByteRange(url, e.localOff, end, 45000);
        if (!chunk.ok || !chunk.buf) continue;
        // 把 chunk 当成从 offset 0 开始的假 buffer，修正 localOff=0
        const fakeEntry = Object.assign({}, e, {
          localOff: 0,
          _dataStart: null
        });
        const payload = readZipLocalPayload(chunk.buf, fakeEntry);
        if (!payload || !payload.data || !payload.data.byteLength) {
          // 直接用 local 头解析
          const view = new DataView(chunk.buf);
          if (view.getUint32(0, true) !== 0x04034b50) continue;
          const nameLen = view.getUint16(26, true);
          const extraLen = view.getUint16(28, true);
          const dataStart = 30 + nameLen + extraLen;
          const cs = e.compSize;
          if (dataStart + cs > chunk.buf.byteLength) {
            // 再拉精确区间
            const exact = await fetchByteRange(url, e.localOff + dataStart, e.localOff + dataStart + cs - 1, 45000);
            if (!exact.ok || !exact.buf) continue;
            let fileAb = null;
            if (e.method === 0) fileAb = exact.buf;
            else fileAb = await inflateZipPayload(new Uint8Array(exact.buf));
            if (!fileAb) continue;
            await pushNestedFromBuffer(result.items, fileAb, base, e.name, byExt);
            continue;
          }
          const data = new Uint8Array(chunk.buf, dataStart, cs);
          let fileAb = null;
          if (e.method === 0) fileAb = copyToArrayBuffer(data);
          else fileAb = await inflateZipPayload(data);
          if (!fileAb) continue;
          await pushNestedFromBuffer(result.items, fileAb, base, e.name, byExt);
          continue;
        }
        let fileAb = null;
        if (payload.method === 0) fileAb = copyToArrayBuffer(payload.data);
        else fileAb = await inflateZipPayload(payload.data);
        if (!fileAb) continue;
        await pushNestedFromBuffer(result.items, fileAb, base, e.name, byExt);
      } catch { /* next */ }
    }

    if (!result.items.length) {
      result.note = "大文件分段扫描未抽出可执行文件（共 " + entries.length + " 项，候选 "
        + candidates.length + "）";
    }
    return result;
  }

  async function pushNestedFromBuffer(items, fileAb, base, path, byExt) {
    if (!fileAb || fileAb.byteLength < 64) return;
    const displayName = base || "file.bin";
    let sha256 = "";
    try { sha256 = await NS.sha256HexOfBuffer(fileAb); } catch { sha256 = ""; }

    // 嵌套 APK（.apk 扩展名，或 ZIP 内含 AndroidManifest/classes.dex）
    if (/\.apk$/i.test(displayName)
      || (detectArchiveFormat(fileAb) === "zip"
        && zipEntriesLookLikeApk(parseZipCentralEntries(fileAb) || parseZipLocalEntriesFallback(fileAb) || []))) {
      try {
        const ents = parseZipCentralEntries(fileAb) || parseZipLocalEntriesFallback(fileAb) || [];
        const jarSigned = apkJarSignedFromEntries(ents);
        items.push({
          name: displayName,
          path: path || displayName,
          kind: "apk",
          signed: jarSigned,
          signerHint: jarSigned ? "APK 已签名（JAR/v1）" : "",
          sigTrust: jarSigned ? "present" : "none",
          note: jarSigned ? "" : "APK 未见 META-INF 签名",
          sha256
        });
        return;
      } catch { /* fall through */ }
    }

    if (isOleMsiBuffer(fileAb) || /\.msi$/i.test(displayName) || /\.msp$/i.test(displayName)) {
      items.push({
        name: displayName,
        path: path || displayName,
        kind: "msi",
        signed: false,
        signerHint: "",
        sigTrust: "none",
        note: "MSI 未解析 Authenticode",
        sha256
      });
      return;
    }
    if (!isMzPeBuffer(fileAb)) {
      // 其它类型静默过滤，不报错、不入列表
      return;
    }
    const pe = NS.parsePeAuthenticode(fileAb);
    if (!pe || !pe.isPe) {
      // 非完整 PE 静默跳过
      return;
    }
    items.push({
      name: displayName,
      path: path || displayName,
      kind: "pe",
      signed: !!pe.signed,
      signerHint: pe.signerHint || "",
      sigTrust: pe.signed ? "present" : "none",
      sha256
    });
  }

  /** 对包内前 N 个目标做 VT 查询（有 sha256 即可） */
  async function attachVtToNestedItems(items, budgetMs) {
    if (!items || !items.length) return items;
    const t0 = Date.now();
    const budget = Math.max(5000, budgetMs || 25000);
    // 本地已发现 Authenticode/JAR 签名的成员优先，避免无签名文件先耗尽 VT 时间预算。
    const candidates = items.slice().sort((a, b) => Number(!!b?.signed) - Number(!!a?.signed));
    for (const it of candidates) {
      if (!it) continue;
      if (it.kind !== "pe" && it.kind !== "apk" && it.kind !== "msi") continue;
      // 补全哈希
      if ((!it.sha256 || it.sha256.length !== 64) && it._fileAb) {
        try { it.sha256 = await NS.sha256HexOfBuffer(it._fileAb); } catch { /* ignore */ }
      }
      try { delete it._fileAb; } catch { /* ignore */ }
    }

    const byHash = new Map();
    for (const it of candidates) {
      const hash = String((it && it.sha256) || "").toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(hash)) continue;
      if (!byHash.has(hash)) byHash.set(hash, []);
      byHash.get(hash).push(it);
    }
    const targets = Array.from(byHash.entries()).slice(0, MAX_NESTED_VT);
    let cursor = 0;
    const worker = async () => {
      while (cursor < targets.length) {
        const index = cursor++;
        const [hash, groupedItems] = targets[index];
        const remaining = budget - (Date.now() - t0);
        if (remaining < 1500) return;
        const requireSignature = groupedItems.some((item) => !!item.signed);
        let vt = null;
        try {
          vt = await raceMs(
            NS.lookupVirusTotalHash(hash, { requireSignature }),
            Math.min(25000, remaining),
            null
          );
        } catch { vt = null; }
        if (!vt || typeof vt !== "object") continue;
        for (const it of groupedItems) {
          it.vt = {
            found: vt.found,
            notFound: !!vt.notFound,
            unknown: !!vt.unknown,
            malicious: Number(vt.malicious) || 0,
            suspicious: Number(vt.suspicious) || 0,
            total: Number(vt.total) || 0,
            summary: vt.summary || "",
            guiUrl: vt.guiUrl || (VT_GUI_BASE + it.sha256),
            sigTrustFromVt: vt.sigTrustFromVt || "",
            signerFromVt: vt.signerFromVt || ""
          };
          // 用 VT 签名结论升级包内项
          if (vt.sigTrustFromVt === "valid") {
            it.sigTrust = "valid";
            if (vt.signerFromVt) it.signerHint = sanitizePublisherName(vt.signerFromVt) || it.signerHint;
          } else if (vt.sigTrustFromVt === "invalid") {
            it.sigTrust = "invalid";
          } else if (vt.signerFromVt && it.signed) {
            it.sigTrust = "valid";
            it.signerHint = sanitizePublisherName(vt.signerFromVt) || it.signerHint;
          }
        }
      }
    };
    // 两个并发兼顾延迟与 VT 限流：比逐个串行快，又避免一次打开大量隐藏页。
    await Promise.all(Array.from({ length: Math.min(2, targets.length) }, () => worker()));
    // 清掉可能残留的 buffer
    for (const it of items) {
      try { delete it._fileAb; delete it.pe; } catch { /* ignore */ }
    }
    return items;
  }

  function vtNotFoundResult(hash, extra) {
    const guiUrl = VT_GUI_BASE + hash;
    return Object.assign({
      success: true,
      found: false,
      notFound: true,
      verifiedNotFound: !!(extra && extra.verifiedNotFound),
      hash,
      guiUrl,
      uploadUrl: VT_UPLOAD_PAGE,
      source: "vt",
      status: 404,
      summary: "VT: 无"
    }, extra || {});
  }

  function vtUnknownResult(hash, extra) {
    const guiUrl = VT_GUI_BASE + hash;
    // unknown：没有 found/notFound 结论。summary 默认空，避免弹出「解析失败」假结论
    return Object.assign({
      success: true,
      found: null,
      notFound: false,
      unknown: true,
      hash,
      guiUrl,
      uploadUrl: "",
      source: "vt",
      summary: ""
    }, extra || {});
  }

  /**
   * VT GUI 反滥用头：base64(`${rand}-ZG9udCBiZSBldmls-${unixTs}`)
   * 与网页端 x-vt-anti-abuse-header 同算法；缺此头极易 RecaptchaRequiredError。
   */
  function buildVtAntiAbuseHeader() {
    try {
      // 11 位量级随机串 + 固定 "dont be evil" + 秒级时间戳（可带小数）
      const rand = String(Math.floor(1e10 + Math.random() * 9e10));
      const ts = (Date.now() / 1000).toFixed(3);
      const raw = `${rand}-ZG9udCBiZSBldmls-${ts}`;
      // btoa 仅 ASCII；raw 全 ASCII
      if (typeof btoa === "function") return btoa(raw);
      // SW 兜底
      const bytes = new TextEncoder().encode(raw);
      let bin = "";
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin);
    } catch {
      return "";
    }
  }

  /**
   * 对齐浏览器里 VT GUI 对 /ui/files/{hash} 的请求头
   *（用户抓包：x-tool / x-app-version / x-vt-anti-abuse-header / accept-ianguage）
   */
  function vtUiHeaders() {
    const anti = buildVtAntiAbuseHeader();
    const h = {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Accept-Language": "en,en-GB;q=0.9,en-US;q=0.8",
      // VT 自创头（拼写就是 ianguage）
      "Accept-ILanguage": "en-US,en;q=0.9,es;q=0.8",
      Referer: "https://www.virustotal.com/",
      "X-Tool": "vt-ui-main",
      "X-App-Version": "v1x622x0"
    };
    if (anti) h["X-VT-Anti-Abuse-Header"] = anti;
    return h;
  }

  /**
   * VT「库中无此样本」判定。
   * 注意：GUI/UI 对不存在样本**常常不是 HTTP 404**，而是：
   *  - JSON: {"error":{"code":"NotFoundError",...}}（可能 status 200）
   *  - 页面文案: "Item not found" + 威胁情报营销段
   *    ("Are you looking for advanced malware searching capabilities?")
   */
  function looksLikeVtItemNotFound(text) {
    const s = String(text || "");
    if (!s || s.length < 8) return false;
    // 已有分析 stats 则不是 not found
    if (/"last_analysis_stats"\s*:\s*\{/i.test(s) && /"malicious"\s*:\s*\d+/i.test(s)) return false;
    if (/"type_description"\s*:\s*"/i.test(s) && /"sha256"\s*:\s*"[a-f0-9]{64}"/i.test(s)
      && !/"error"\s*:\s*\{/i.test(s)) {
      return false;
    }
    // 只接受结构化 JSON error code；页面文案/营销区/搜索空态均无权证明该哈希不存在。
    if (/"code"\s*:\s*"(?:NotFoundError|ResourceNotFoundError)"/i.test(s)
      && /"error"\s*:\s*\{/i.test(s)) return true;
    return false;
  }

  /** GUI 页面明确的查无文案；只能结合当前 hash URL + 连续稳定观察使用。 */
  function looksLikeVtExplicitItemNotFoundText(text) {
    const s = String(text || "");
    return /\bItem not found\b|\bFile not found\b|尚未分析该文件|未找到该文件|无此文件|样本不存在/i.test(s);
  }

  function isVtNotFoundError(data, status) {
    // 只认结构化 error body；UI 的 404 可能是鉴权/反自动化返回。
    if (data && data.error) {
      const blob = JSON.stringify(data.error).slice(0, 600);
      if (/NotFoundError|ResourceNotFound|not\s*found among|does not exist/i.test(blob)) return true;
      if (looksLikeVtItemNotFound(blob)) return true;
    }
    return false;
  }

  function isVtRateOrAuthError(data, status) {
    if (status === 429 || status === 401 || status === 403) return true;
    if (!data || !data.error) return false;
    const blob = JSON.stringify(data.error).slice(0, 400);
    // NotFound 不算鉴权错误
    if (/NotFoundError|ResourceNotFound/i.test(blob)) return false;
    return /QuotaExceeded|TooManyRequests|rate\s*limit|AuthenticationRequired|Forbidden|UserNotActive|WrongCredentials|RecaptchaRequired|recaptcha|captcha/i.test(blob);
  }

  function isVtCaptchaError(data, status) {
    if (!data || !data.error) return false;
    const blob = JSON.stringify(data.error).slice(0, 400);
    if (/NotFoundError|ResourceNotFound/i.test(blob)) return false;
    return /RecaptchaRequired|recaptcha|captcha/i.test(blob);
  }

  function readStorageKeys(keys) {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get(keys, (r) => {
          if (chrome.runtime.lastError) resolve({});
          else resolve(r || {});
        });
      } catch {
        resolve({});
      }
    });
  }

  async function getVtApiKey() {
    const r = await readStorageKeys(["vtApiKey", "virusTotalApiKey"]);
    return String((r && (r.vtApiKey || r.virusTotalApiKey)) || "").trim();
  }

  async function fetchVtJson(url, timeoutMs, opts) {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => {
      try { controller.abort(); } catch { /* ignore */ }
    }, timeoutMs || 14000) : null;
    const headers = (opts && opts.headers) || vtUiHeaders();
    // 必须 include：带上用户浏览器里 VT 会话 Cookie，omit 几乎必触 reCAPTCHA
    const credentials = (opts && opts.credentials) || "include";
    try {
      const res = await fetch(url, {
        method: "GET",
        credentials,
        cache: "no-store",
        redirect: "follow",
        signal: controller ? controller.signal : undefined,
        headers
      });
      if (timer) clearTimeout(timer);
      const text = await res.text();
      let data = null;
      try { data = JSON.parse(text); } catch {
        // 偶发 JSON 夹在 HTML 里
        const m = String(text || "").match(/\{[\s\S]*"data"\s*:\s*\{[\s\S]{20,}?\}[\s\S]*\}$/);
        if (m) {
          try { data = JSON.parse(m[0]); } catch { data = null; }
        }
      }
      return { status: res.status, ok: res.ok, data, text };
    } catch (e) {
      if (timer) clearTimeout(timer);
      return {
        status: 0,
        ok: false,
        data: null,
        text: "",
        error: e && e.message ? e.message : "fetch-fail"
      };
    }
  }

  function cacheVtResult(hash, result, ttlMs) {
    try {
      NS._vtByHash.set(hash, {
        at: Date.now(),
        ttl: ttlMs || VT_CACHE_TTL_MS,
        result
      });
    } catch { /* ignore */ }
  }

  /** 清除 VT 查询缓存（配置 API Key 后立刻生效） */
  NS.clearVtLookupCache = function () {
    try { NS._vtByHash.clear(); } catch { /* ignore */ }
  };

  // 启动时清掉历史上错误的 softMiss「假无」缓存
  try {
    if (NS._vtByHash && NS._vtByHash.forEach) {
      const drop = [];
      NS._vtByHash.forEach((v, k) => {
        const r = v && v.result;
        if (r && (r.softMiss || r.source === "vt-no-key")) drop.push(k);
      });
      drop.forEach((k) => NS._vtByHash.delete(k));
    }
  } catch { /* ignore */ }

  /**
   * 官方 API v3（免费 Community Key，约 4 次/分）。
   * 这是稳定拿到 last_analysis_stats 的主路径。
   */
  async function lookupVtApiV3(hash, apiKey, guiUrl) {
    if (!apiKey) return null;
    try {
      const r = await fetchVtJson(
        "https://www.virustotal.com/api/v3/files/" + hash,
        16000,
        {
          credentials: "omit",
          headers: {
            Accept: "application/json",
            "x-apikey": apiKey
          }
        }
      );
      if (isVtNotFoundError(r.data, r.status) || r.status === 404) {
        return vtNotFoundResult(hash, { source: "vt-api-v3", status: r.status, verifiedNotFound: true });
      }
      if (r.status === 401 || r.status === 403) {
        return vtUnknownResult(hash, {
          source: "vt-api-v3",
          needApiKey: true,
          badApiKey: true,
          summary: "VT: API Key 无效，请在弹窗底部重填"
        });
      }
      if (r.status === 429) {
        return vtUnknownResult(hash, {
          source: "vt-api-v3",
          rateLimited: true,
          summary: "VT: API 限流（免费约 4 次/分），稍后重试"
        });
      }
      if (r.data) {
        // v3 与 UI 同形：{ data: { attributes } }
        const parsed = parseVtUiJson(r.data, hash, guiUrl);
        if (parsed && parsed.found === true) {
          parsed.source = "vt-api-v3";
          return parsed;
        }
        if (parsed && parsed.notFound) {
          parsed.source = "vt-api-v3";
          return parsed;
        }
        // 直接 attributes
        if (r.data.data && r.data.data.attributes) {
          const hit = fileHitFromAttrs(r.data.data.attributes, hash, guiUrl, "vt-api-v3");
          if (hit) return hit;
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  function raceMs(promise, ms, onTimeoutValue) {
    let timer = null;
    const timeoutP = new Promise((resolve) => {
      timer = setTimeout(() => resolve(onTimeoutValue), Math.max(500, ms || 1000));
    });
    return Promise.race([
      Promise.resolve(promise).then((v) => {
        if (timer) clearTimeout(timer);
        return v;
      }, (e) => {
        if (timer) clearTimeout(timer);
        throw e;
      }),
      timeoutP
    ]);
  }

  function waitTabComplete(tabId, timeoutMs) {
    return new Promise((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        try { chrome.tabs.onUpdated.removeListener(onUpdated); } catch { /* ignore */ }
        resolve();
      };
      const onUpdated = (id, info) => {
        if (id === tabId && info && info.status === "complete") finish();
      };
      try {
        chrome.tabs.onUpdated.addListener(onUpdated);
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError) return;
          if (tab && tab.status === "complete") finish();
        });
      } catch { /* ignore */ }
      // 硬上限，避免 SPA 永不 complete 卡死整条 VT 链
      setTimeout(finish, Math.min(Math.max(2000, timeoutMs || 8000), 10000));
    });
  }

  /**
   * 从 VT GUI 页面正文刮检出比（用户浏览器里看到的那串 x/y）。
   */
  function parseVtDomStats(pageHint, hash, guiUrl) {
    const s = String(pageHint || "");
    if (!s || s.length < 10) return null;
    // DOM 文案不是权威查无结果，不能在这里返回 notFound。
    // 常见： "0 / 72" "2/70" "No security vendors flagged this file as malicious"
    let malicious = null;
    let total = null;
    let suspicious = 0;

    // 主报告顶部的明确文案优先，避免抓到 Relations/历史视图里的其他比例。
    const mMainFlag = s.match(/(\d{1,3})\s*\/\s*(\d{2,3})\s+security vendors?\s+flagged this file as malicious/i)
      || s.match(/(\d{1,3})\s*\/\s*(\d{2,3})\s*(?:家|个)安全(?:厂商|引擎).{0,30}(?:标记|检出).{0,20}(?:恶意|有害)/i);
    if (mMainFlag) {
      const a = parseInt(mMainFlag[1], 10);
      const b = parseInt(mMainFlag[2], 10);
      if (b >= 20 && b <= 120 && a <= b) {
        malicious = a;
        total = b;
      }
    }

    // 不再从全页任意比例猜主报告。Relations、历史视图等组件会产生 0/91 一类无关值；
    // 没有明确「flagged this file」上下文时宁可返回未知。
    if (malicious == null || total == null) return null;

    const mRatio = malicious == null
      ? s.match(/(\d{1,3})\s*\/\s*(\d{2,3})(?:\s*(?:security vendors|engines|检测|Communit))?/i)
      : null;
    if (mRatio && malicious == null) {
      const a = parseInt(mRatio[1], 10);
      const b = parseInt(mRatio[2], 10);
      // 合理范围：引擎总数通常 40–90
      if (b >= 20 && b <= 120 && a <= b) {
        malicious = a;
        total = b;
      }
    }
    // "X security vendors flagged this file as malicious"
    const mFlag = s.match(/(\d{1,3})\s+security vendors?\s+flagged/i);
    if (mFlag && malicious == null) {
      malicious = parseInt(mFlag[1], 10);
    }
    if (/No security vendors flagged this file as malicious/i.test(s) && malicious == null) {
      malicious = 0;
    }
    // 中文 GUI
    const mCn = s.match(/(\d{1,3})\s*\/\s*(\d{2,3})\s*(?:个安全厂商|家引擎|检测)/i);
    if (mCn) {
      malicious = parseInt(mCn[1], 10);
      total = parseInt(mCn[2], 10);
    }
    if (malicious == null && !/Community Score|Detections|检测结果|security vendors/i.test(s)) {
      return null;
    }
    if (malicious == null) malicious = 0;
    if (!total || total < malicious) total = Math.max(malicious, 0);

    const signer = "";
    return {
      success: true,
      found: true,
      notFound: false,
      hash,
      guiUrl,
      source: "vt-dom",
      statsPolicyVersion: VT_STATS_POLICY_VERSION,
      malicious,
      suspicious,
      undetected: total > malicious ? total - malicious : 0,
      harmless: 0,
      total: total || malicious,
      ratio: total ? `${malicious + suspicious}/${total}` : `${malicious}`,
      signerFromVt: "",
      summary: formatVtSummary(malicious, suspicious, total || 0, signer)
    };
  }

  /**
   * 扩展在浏览器内打开 VT 文件页：
   *  content/vt-hook-main.js（document_start MAIN）拦截 SPA 的 /ui/files 响应
   *  后台轮询 window.__sfVtCaptures[hash] + DOM 兜底
   */
  async function fetchVtUiFromPageContext(hash, budgetMs) {
    if (!chrome.tabs || !chrome.scripting || !chrome.scripting.executeScript) {
      return null;
    }
    const fileHash = String(hash || "").toLowerCase();
    if (fileHash.length !== 64) return null;
    // 页内路径仅作无 Key 兜底：预算压短，避免半分钟卡死
    const budget = Math.min(Math.max(7000, budgetMs || 16000), 20000);
    const targetUrl = "https://www.virustotal.com/gui/file/" + fileHash;

    const readCaptureFn = (h) => {
      try {
        const key = String(h || "").toLowerCase();
        let text = "";
        let status = 0;
        try {
          const bag = window.__sfVtCaptures && window.__sfVtCaptures[key];
          if (bag && bag.text) {
            text = String(bag.text);
            status = bag.status || 0;
          } else if (window.__sfVtCapture
            && String(window.__sfVtCaptureUrl || "").toLowerCase().includes(key)) {
            text = String(window.__sfVtCapture);
            status = window.__sfVtCaptureStatus || 0;
          }
        } catch { /* ignore */ }
        let pageHint = "";
        const domRatios = [];
        const pageEngineResults = [];
        const engineResultKeys = new Set();
        const scannedValues = new WeakSet();
        let pageSignatureInfo = null;
        const trustedRowCandidates = new Map();
        const trustedDomRules = [
          ["BitDefender", /\bBitDefender(?:Falx)?\b/i], ["ESET", /\bESET(?:-NOD32)?\b/i],
          ["Avast", /\bAvast(?:-Mobile)?\b/i], ["Kaspersky", /\bKaspersky\b/i],
          ["Huorong", /\bHuorong\b|火绒/i]
        ];
        const considerTrustedRow = (rawText) => {
          const rowText = String(rawText || "").replace(/\s+/g, " ").trim();
          if (rowText.length < 4 || rowText.length > 360
            || /Security vendors?' analysis|May differ from commercial/i.test(rowText)) return;
          for (const [canonical, rule] of trustedDomRules) {
            const match = rowText.match(rule);
            if (!match || rowText.length <= match[0].length + 1) continue;
            const previous = trustedRowCandidates.get(canonical);
            if (!previous || rowText.length < previous.text.length) {
              trustedRowCandidates.set(canonical, { text: rowText, label: match[0], index: match.index || 0 });
            }
          }
        };
        const addEngineResult = (value) => {
          if (!value || typeof value !== "object") return;
          const engine = String(value.engine_name || value.engineName || value.engine || "").trim();
          const category = String(value.category || "").toLowerCase();
          const result = String(value.result || value.detStr || "").trim();
          if (!engine || !/^(?:malicious|suspicious|harmless|undetected|timeout|confirmed-timeout|type-unsupported|failure)$/i.test(category)) return;
          const recordKey = `${engine.toLowerCase()}|${category}|${result}`;
          if (engineResultKeys.has(recordKey)) return;
          engineResultKeys.add(recordKey);
          pageEngineResults.push({ engine_name: engine, category, result: result.slice(0, 160) });
        };
        const captureSignatureInfo = (value) => {
          if (pageSignatureInfo || !value || typeof value !== "object") return;
          const sig = value.signature_info || value.signatureInfo;
          if (!sig || typeof sig !== "object") return;
          try {
            const json = JSON.stringify(sig);
            if (json && json.length <= 50000) pageSignatureInfo = JSON.parse(json);
          } catch { /* ignore non-serializable component state */ }
        };
        const scanEngineValue = (value, depth) => {
          if (!value || depth > 3 || (typeof value !== "object" && !Array.isArray(value))) return;
          if (typeof value === "object") {
            if (scannedValues.has(value)) return;
            scannedValues.add(value);
          }
          captureSignatureInfo(value);
          if (Array.isArray(value)) {
            for (const item of value.slice(0, 160)) scanEngineValue(item, depth + 1);
            return;
          }
          addEngineResult(value);
          for (const prop of ["analyses", "analysis", "detections", "results", "items", "rows", "data",
            "attributes", "last_analysis_results", "lastAnalysisResults", "value", "object"]) {
            try {
              if (value[prop] && value[prop] !== value) scanEngineValue(value[prop], depth + 1);
            } catch { /* ignore getter */ }
          }
        };
        try {
          const chunks = [];
          const roots = [document];
          let rootIndex = 0;
          let shadowCount = 0;
          let textChars = 0;
          while (rootIndex < roots.length && shadowCount < 180) {
            const root = roots[rootIndex++];
            if (root === document && document.body) {
              const bodyText = String(document.body.innerText || "");
              chunks.push(bodyText);
              textChars += bodyText.length;
            } else if (textChars < 180000 && document.createTreeWalker) {
              // ShadowRoot 没有 innerText；逐个取文本节点并跳过 style/script，避免 CSS
              // 把真正的主报告文案挤出截断范围。
              const walker = document.createTreeWalker(root, (window.NodeFilter && NodeFilter.SHOW_TEXT) || 4);
              const local = [];
              let node = null;
              while ((node = walker.nextNode()) && textChars < 180000) {
                const parentTag = String(node.parentElement && node.parentElement.tagName || "").toUpperCase();
                if (/^(?:STYLE|SCRIPT|NOSCRIPT|TEMPLATE)$/.test(parentTag)) continue;
                const value = String(node.nodeValue || "").replace(/\s+/g, " ").trim();
                if (!value) continue;
                local.push(value);
                textChars += value.length + 1;
              }
              if (local.length) chunks.push(local.join(" "));
            }
            // 比例组件可能位于很深的位置；单独查询，避免被通用 3000 节点上限截掉。
            for (const el of Array.from(root.querySelectorAll
              ? root.querySelectorAll("vt-ui-detections-ratio") : [])) {
              const detections = Number(el.detections ?? el.getAttribute("detections"));
              const total = Number(el.total ?? el.getAttribute("total"));
              if (Number.isFinite(detections) && Number.isFinite(total) && total >= 20 && total <= 200
                && detections >= 0 && detections <= total) {
                domRatios.push({
                  detections,
                  total,
                  large: !!(el.classList && el.classList.contains("large")),
                  visible: typeof el.getClientRects === "function" ? el.getClientRects().length > 0 : true
                });
              }
            }
            const elements = Array.from(root.querySelectorAll ? root.querySelectorAll("*") : []).slice(0, 3000);
            for (const el of elements) {
              const elementTag = String(el && el.tagName || "").toUpperCase();
              if (!/^(?:STYLE|SCRIPT|NOSCRIPT|TEMPLATE)$/.test(elementTag)) {
                try { considerTrustedRow(el.innerText || el.textContent || ""); } catch { /* ignore */ }
              }
              if (String(el.localName || "").includes("-")) {
                for (const prop of ["analyses", "analysis", "detections", "results", "items", "rows", "data",
                  "attributes", "last_analysis_results", "lastAnalysisResults", "value", "object"]) {
                  try { scanEngineValue(el[prop], 0); } catch { /* ignore getter */ }
                }
              }
              if (!el || !el.shadowRoot || shadowCount++ >= 180) continue;
              roots.push(el.shadowRoot);
            }
          }
          pageHint = chunks.join("\n").slice(0, 180000);
          for (const [canonical, candidate] of trustedRowCandidates) {
            let resultText = candidate.text.slice(candidate.index + candidate.label.length).trim();
            let nextEngineAt = resultText.length;
            for (const [, rule] of trustedDomRules) {
              const next = resultText.match(rule);
              if (next && next.index != null && next.index > 0) nextEngineAt = Math.min(nextEngineAt, next.index);
            }
            resultText = resultText.slice(0, nextEngineAt).trim();
            if (!resultText || /Security vendors|analysis$/i.test(resultText)) continue;
            let category = /\bSuspicious\b|可疑/i.test(resultText) ? "suspicious" : "malicious";
            if (/\bUndetected\b|\bHarmless\b|\bTimeout\b|Confirmed timeout|Unable to process|type unsupported|未检出|无害|超时/i.test(resultText)) {
              category = /\bHarmless\b|无害/i.test(resultText) ? "harmless"
                : (/Timeout|超时/i.test(resultText) ? "timeout" : "undetected");
            }
            addEngineResult({ engine_name: canonical, category, result: resultText });
          }
          domRatios.sort((a, b) => Number(b.visible) - Number(a.visible)
            || Number(b.large) - Number(a.large) || b.total - a.total);
        } catch { /* ignore */ }
        return {
          status,
          text: text.slice(0, 800000),
          pageHint,
          pageUrl: String(location.href || "").slice(0, 500),
          captureUrl: String(window.__sfVtCaptureUrl || "").slice(0, 500),
          domRatios: domRatios.slice(0, 20),
          pageEngineResults: pageEngineResults.slice(0, 120),
          pageSignatureInfo,
          hooked: !!window.__sfVtHookBoot,
          ok: text.length > 20
        };
      } catch (e) {
        return {
          status: 0,
          text: "",
          pageHint: "",
          error: e && e.message ? String(e.message) : "read-fail"
        };
      }
    };

    const activeFetchFn = async (h) => {
      try {
        const rand = String(Math.floor(1e10 + Math.random() * 9e10));
        const ts = (Date.now() / 1000).toFixed(3);
        const anti = btoa(`${rand}-ZG9udCBiZSBldmls-${ts}`);
        const res = await fetch("https://www.virustotal.com/ui/files/" + h, {
          method: "GET",
          credentials: "include",
          cache: "no-store",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "Accept-Language": "en,en-GB;q=0.9,en-US;q=0.8",
            "Accept-ILanguage": "en-US,en;q=0.9,es;q=0.8",
            "X-Tool": "vt-ui-main",
            "X-App-Version": "v1x622x0",
            "X-VT-Anti-Abuse-Header": anti
          }
        });
        const text = await res.text();
        let pageHint = "";
        const domRatios = [];
        const pageEngineResults = [];
        const engineResultKeys = new Set();
        const scannedValues = new WeakSet();
        let pageSignatureInfo = null;
        const trustedRowCandidates = new Map();
        const trustedDomRules = [
          ["BitDefender", /\bBitDefender(?:Falx)?\b/i], ["ESET", /\bESET(?:-NOD32)?\b/i],
          ["Avast", /\bAvast(?:-Mobile)?\b/i], ["Kaspersky", /\bKaspersky\b/i],
          ["Huorong", /\bHuorong\b|火绒/i]
        ];
        const considerTrustedRow = (rawText) => {
          const rowText = String(rawText || "").replace(/\s+/g, " ").trim();
          if (rowText.length < 4 || rowText.length > 360
            || /Security vendors?' analysis|May differ from commercial/i.test(rowText)) return;
          for (const [canonical, rule] of trustedDomRules) {
            const match = rowText.match(rule);
            if (!match || rowText.length <= match[0].length + 1) continue;
            const previous = trustedRowCandidates.get(canonical);
            if (!previous || rowText.length < previous.text.length) {
              trustedRowCandidates.set(canonical, {
                text: rowText,
                label: match[0],
                index: match.index || 0
              });
            }
          }
        };
        const addEngineResult = (value) => {
          if (!value || typeof value !== "object") return;
          const engine = String(value.engine_name || value.engineName || value.engine || "").trim();
          const category = String(value.category || "").toLowerCase();
          const result = String(value.result || value.detStr || "").trim();
          if (!engine || !/^(?:malicious|suspicious|harmless|undetected|timeout|confirmed-timeout|type-unsupported|failure)$/i.test(category)) return;
          const recordKey = `${engine.toLowerCase()}|${category}|${result}`;
          if (engineResultKeys.has(recordKey)) return;
          engineResultKeys.add(recordKey);
          pageEngineResults.push({ engine_name: engine, category, result: result.slice(0, 160) });
        };
        const captureSignatureInfo = (value) => {
          if (pageSignatureInfo || !value || typeof value !== "object") return;
          const sig = value.signature_info || value.signatureInfo;
          if (!sig || typeof sig !== "object") return;
          try {
            const json = JSON.stringify(sig);
            if (json && json.length <= 50000) pageSignatureInfo = JSON.parse(json);
          } catch { /* ignore non-serializable component state */ }
        };
        const scanEngineValue = (value, depth) => {
          if (!value || depth > 3 || (typeof value !== "object" && !Array.isArray(value))) return;
          if (typeof value === "object") {
            if (scannedValues.has(value)) return;
            scannedValues.add(value);
          }
          captureSignatureInfo(value);
          if (Array.isArray(value)) {
            for (const item of value.slice(0, 160)) scanEngineValue(item, depth + 1);
            return;
          }
          addEngineResult(value);
          for (const prop of ["analyses", "analysis", "detections", "results", "items", "rows", "data",
            "attributes", "last_analysis_results", "lastAnalysisResults", "value", "object"]) {
            try {
              if (value[prop] && value[prop] !== value) scanEngineValue(value[prop], depth + 1);
            } catch { /* ignore getter */ }
          }
        };
        try {
          const chunks = [];
          const roots = [document];
          let rootIndex = 0;
          let shadowCount = 0;
          let textChars = 0;
          while (rootIndex < roots.length && shadowCount < 180) {
            const root = roots[rootIndex++];
            if (root === document && document.body) {
              const bodyText = String(document.body.innerText || "");
              chunks.push(bodyText);
              textChars += bodyText.length;
            } else if (textChars < 180000 && document.createTreeWalker) {
              const walker = document.createTreeWalker(root, (window.NodeFilter && NodeFilter.SHOW_TEXT) || 4);
              const local = [];
              let node = null;
              while ((node = walker.nextNode()) && textChars < 180000) {
                const parentTag = String(node.parentElement && node.parentElement.tagName || "").toUpperCase();
                if (/^(?:STYLE|SCRIPT|NOSCRIPT|TEMPLATE)$/.test(parentTag)) continue;
                const value = String(node.nodeValue || "").replace(/\s+/g, " ").trim();
                if (!value) continue;
                local.push(value);
                textChars += value.length + 1;
              }
              if (local.length) chunks.push(local.join(" "));
            }
            for (const el of Array.from(root.querySelectorAll
              ? root.querySelectorAll("vt-ui-detections-ratio") : [])) {
              const detections = Number(el.detections ?? el.getAttribute("detections"));
              const total = Number(el.total ?? el.getAttribute("total"));
              if (Number.isFinite(detections) && Number.isFinite(total) && total >= 20 && total <= 200
                && detections >= 0 && detections <= total) {
                domRatios.push({
                  detections,
                  total,
                  large: !!(el.classList && el.classList.contains("large")),
                  visible: typeof el.getClientRects === "function" ? el.getClientRects().length > 0 : true
                });
              }
            }
            const elements = Array.from(root.querySelectorAll ? root.querySelectorAll("*") : []).slice(0, 3000);
            for (const el of elements) {
              const elementTag = String(el && el.tagName || "").toUpperCase();
              if (!/^(?:STYLE|SCRIPT|NOSCRIPT|TEMPLATE)$/.test(elementTag)) {
                try { considerTrustedRow(el.innerText || el.textContent || ""); } catch { /* ignore */ }
              }
              if (String(el.localName || "").includes("-")) {
                for (const prop of ["analyses", "analysis", "detections", "results", "items", "rows", "data",
                  "attributes", "last_analysis_results", "lastAnalysisResults", "value", "object"]) {
                  try { scanEngineValue(el[prop], 0); } catch { /* ignore getter */ }
                }
              }
              if (!el || !el.shadowRoot || shadowCount++ >= 180) continue;
              roots.push(el.shadowRoot);
            }
          }
          pageHint = chunks.join("\n").slice(0, 180000);
          for (const [canonical, candidate] of trustedRowCandidates) {
            let resultText = candidate.text.slice(candidate.index + candidate.label.length).trim();
            let nextEngineAt = resultText.length;
            for (const [, rule] of trustedDomRules) {
              const next = resultText.match(rule);
              if (next && next.index != null && next.index > 0) nextEngineAt = Math.min(nextEngineAt, next.index);
            }
            resultText = resultText.slice(0, nextEngineAt).trim();
            if (!resultText || /Security vendors|analysis$/i.test(resultText)) continue;
            let category = /\bSuspicious\b|可疑/i.test(resultText) ? "suspicious" : "malicious";
            if (/\bUndetected\b|\bHarmless\b|\bTimeout\b|Confirmed timeout|Unable to process|type unsupported|未检出|无害|超时/i.test(resultText)) {
              category = /\bHarmless\b|无害/i.test(resultText) ? "harmless"
                : (/Timeout|超时/i.test(resultText) ? "timeout" : "undetected");
            }
            addEngineResult({ engine_name: canonical, category, result: resultText });
          }
          domRatios.sort((a, b) => Number(b.visible) - Number(a.visible)
            || Number(b.large) - Number(a.large) || b.total - a.total);
        } catch { /* ignore */ }
        const key = String(h || "").toLowerCase();
        try {
          if (text && window.__sfVtCaptures) {
            window.__sfVtCaptures[key] = { text: text.slice(0, 800000), status: res.status, at: Date.now() };
          }
          window.__sfVtCapture = text;
          window.__sfVtCaptureStatus = res.status;
        } catch { /* ignore */ }
        return {
          status: res.status,
          text: String(text || "").slice(0, 800000),
          pageHint,
          pageUrl: String(location.href || "").slice(0, 500),
          captureUrl: "https://www.virustotal.com/ui/files/" + key,
          domRatios: domRatios.slice(0, 20),
          pageEngineResults: pageEngineResults.slice(0, 120),
          pageSignatureInfo,
          ok: res.ok
        };
      } catch (e) {
        // executeScript 会单独序列化此函数，不能引用外层 readCaptureFn。
        return {
          status: 0,
          text: "",
          pageHint: "",
          pageUrl: String(location.href || "").slice(0, 500),
          captureUrl: "",
          domRatios: [],
          pageEngineResults: [],
          ok: false,
          error: e && e.message ? String(e.message) : "page-fetch-fail"
        };
      }
    };

    const exec = async (tabId, func, args, timeoutMs, world) => {
      try {
        const injected = await raceMs(
          chrome.scripting.executeScript({
            target: { tabId },
            world: world || "MAIN",
            func,
            args: args || []
          }),
          timeoutMs || 8000,
          null
        );
        if (!injected || !injected[0]) return null;
        return injected[0].result;
      } catch {
        return null;
      }
    };

    const work = (async () => {
      let tabId = null;
      let created = false;
      try {
        // 始终新建非活动标签页：不抢前台、不触碰用户手动打开的 VT 页面。
        // 新导航也能保证 document_start 的响应钩子从一开始安装。
        const tab = await raceMs(new Promise((resolve) => {
          try {
            chrome.tabs.create(
              { url: targetUrl, active: false },
              (t) => {
                if (chrome.runtime.lastError) resolve(null);
                else resolve(t || null);
              }
            );
          } catch {
            resolve(null);
          }
        }), 5000, null);
        created = !!(tab && tab.id != null);

        if (!tab || tab.id == null) return null;
        tabId = tab.id;
        await waitTabComplete(tabId, 10000);

        let payload = null;
        let stableItemNotFoundHits = 0;
        // 短轮询：预算由上层 cap，避免 18×600ms 拖死
        const pollN = Math.max(8, Math.min(30, Math.floor(budget / 600)));
        for (let i = 0; i < pollN; i++) {
          await new Promise((r) => setTimeout(r, 400));
          payload = await exec(tabId, readCaptureFn, [fileHash], 2500);
          // MAIN world 可能被页面策略或旧标签页状态挡住；DOM 读取改由隔离世界兜底。
          if (!payload || (!(payload.pageHint || "").trim()
            && !(Array.isArray(payload.domRatios) && payload.domRatios.length))) {
            const isolated = await exec(tabId, readCaptureFn, [fileHash], 2500, "ISOLATED");
            if (isolated) {
              if (!payload) payload = isolated;
              else {
                if (isolated.pageHint) payload.pageHint = isolated.pageHint;
                if (Array.isArray(isolated.domRatios) && isolated.domRatios.length) {
                  payload.domRatios = isolated.domRatios;
                }
                if (Array.isArray(isolated.pageEngineResults) && isolated.pageEngineResults.length) {
                  payload.pageEngineResults = isolated.pageEngineResults;
                }
                if (!payload.pageSignatureInfo && isolated.pageSignatureInfo) {
                  payload.pageSignatureInfo = isolated.pageSignatureInfo;
                }
                if (!payload.pageUrl && isolated.pageUrl) payload.pageUrl = isolated.pageUrl;
              }
            }
          }
          const currentPageHint = String((payload && payload.pageHint) || "");
          const currentPageReady = currentPageHint.toLowerCase().includes(fileHash);
          if (currentPageReady
            && /(\d{1,3})\s*\/\s*(\d{2,3})\s+security vendors?\s+flagged this file as malicious/i.test(currentPageHint)) {
            const mainMatch = currentPageHint.match(/(\d{1,3})\s*\/\s*(\d{2,3})\s+security vendors?\s+flagged this file as malicious/i);
            const mainDetected = mainMatch ? (parseInt(mainMatch[1], 10) || 0) : 0;
            const hasPageEngines = !!(payload && Array.isArray(payload.pageEngineResults)
              && payload.pageEngineResults.length);
            const hasPageSignature = !!(payload && payload.pageSignatureInfo);
            // 有检出时继续等厂商表和 signature_info 属性渲染；引擎表先出现不代表签名数据已就绪。
            if (mainDetected === 0 || (hasPageEngines && hasPageSignature) || i >= 16) break;
          }
          const capturedText = String((payload && payload.text) || "");
          // 任意长响应可能只是 Recaptcha/鉴权/占位对象，不能因此提前结束页面轮询。
          // 只有真正包含报告统计时才收下，继续等待页面组件完成渲染。
          if (capturedText && !/RecaptchaRequired/i.test(capturedText)
            && (/last_analysis_stats/i.test(capturedText)
              || /"malicious"\s*:\s*\d+/i.test(capturedText))) {
            const captureHasSignature = /"signature_info"\s*:/i.test(capturedText)
              || !!(payload && payload.pageSignatureInfo);
            if (captureHasSignature || i >= 8) break;
          }
          if (capturedText && /NotFoundError|Item not found/i.test(capturedText)) {
            break;
          }
          if (payload && String(payload.pageUrl || "").toLowerCase().includes(fileHash)
            && looksLikeVtExplicitItemNotFoundText(payload.pageHint)
            && !/\d{1,3}\s*\/\s*\d{2,3}|last_analysis_stats|security vendors? flagged/i.test(payload.pageHint || "")) {
            stableItemNotFoundHits++;
            // SPA 加载中可能短暂出现空态；连续四次（约 1.6s）稳定后才认定。
            if (stableItemNotFoundHits >= 4) {
              payload.notFoundStable = true;
              break;
            }
          } else {
            stableItemNotFoundHits = 0;
          }
          // 不因普通比例组件提前结束；必须等主报告文案或权威 JSON。
        }

        // 钩子未截到：页内同源补一枪
        const finalCapturedText = String((payload && payload.text) || "");
        const hasResolvedCapture = /last_analysis_stats|"malicious"\s*:\s*\d+|NotFoundError|Item not found/i.test(finalCapturedText)
          || /\d{1,3}\s*\/\s*\d{2,3}\s+security vendors?\s+flagged this file as malicious/i.test(String((payload && payload.pageHint) || ""));
        if (!payload || !hasResolvedCapture || /RecaptchaRequired/i.test(finalCapturedText)) {
          const active = await exec(tabId, activeFetchFn, [fileHash], 5000);
          if (active) {
            if (!payload) payload = active;
            else {
              if (active.text && active.text.length >= (payload.text || "").length
                && !/RecaptchaRequired/i.test(active.text)) {
                payload.text = active.text;
                payload.status = active.status;
              }
              if (active.pageHint && active.pageHint.length > (payload.pageHint || "").length) {
                payload.pageHint = active.pageHint;
              }
              if (Array.isArray(active.domRatios) && active.domRatios.length) {
                payload.domRatios = active.domRatios;
              }
              if (Array.isArray(active.pageEngineResults) && active.pageEngineResults.length) {
                payload.pageEngineResults = active.pageEngineResults;
              }
              if (!payload.pageSignatureInfo && active.pageSignatureInfo) {
                payload.pageSignatureInfo = active.pageSignatureInfo;
              }
            }
          }
        }

        return payload;
      } catch {
        return null;
      } finally {
        if (created && tabId != null) {
          try {
            chrome.tabs.remove(tabId, () => { void chrome.runtime.lastError; });
          } catch { /* ignore */ }
        }
      }
    })();

    try {
      return await raceMs(work, budget, null);
    } catch {
      return null;
    }
  }

  function enrichVtResultWithSignature(result, text, pageHint) {
    if (!result || typeof result !== "object") return result;
    const blob = [text, pageHint, result.summary].filter(Boolean).join("\n");
    const ex = extractVtSignatureFromText(blob);
    if (ex.signer && !result.signerFromVt) result.signerFromVt = ex.signer;
    if (ex.trust) {
      // 已有 invalid 不降级；valid 优先
      if (ex.trust === "invalid" || !result.sigTrustFromVt || result.sigTrustFromVt === "present") {
        result.sigTrustFromVt = ex.trust;
      }
      if (ex.trust === "valid") result.sigTrustFromVt = "valid";
    }
    // 若 JSON attrs 路径已带 trust，保留更强结论
    if (result.sigTrustFromVt === "invalid") { /* keep */ }
    result.pageHint = pageHint || result.pageHint || "";
    return result;
  }

  function parseVtPageFetchPayload(payload, hash, guiUrl) {
    if (!payload) return null;
    const status = Number(payload.status) || 0;
    const text = String(payload.text || "");
    const pageHint = String(payload.pageHint || "");
    const pageUrl = String(payload.pageUrl || "").toLowerCase();
    let data = null;
    try { data = JSON.parse(text); } catch { data = null; }
    const pageEngineConsensus = vtEngineConsensusFromPageResults(payload.pageEngineResults);
    const structuredAttrs = data && data.data && data.data.attributes
      ? data.data.attributes
      : (data && data.attributes ? data.attributes : null);
    const pageSignatureInfo = payload.pageSignatureInfo
      || (structuredAttrs && (structuredAttrs.signature_info || structuredAttrs.signatureInfo))
      || null;
    const finalizePageResult = (result) => {
      const out = enrichVtResultWithSignature(result, text, pageHint);
      if (!out || !pageSignatureInfo) return out;
      const meta = vtSignatureMetaFromAttrs({ signature_info: pageSignatureInfo });
      if (meta.signer && !out.signerFromVt) out.signerFromVt = meta.signer;
      if (meta.trust === "invalid" || meta.trust === "valid"
        || (!out.sigTrustFromVt && meta.trust)) out.sigTrustFromVt = meta.trust;
      return out;
    };

    // 主报告顶部文案（例如 23/70 ... flagged this file）比全页任意比例组件可靠。
    // 同时要求当前完整哈希已渲染，排除 SPA 切换期间的上一文件残留 DOM。
    const pageHasCurrentHash = pageHint.toLowerCase().includes(String(hash || "").toLowerCase());
    if (pageHasCurrentHash
      && /security vendors?\s+flagged this file as malicious|安全(?:厂商|引擎).{0,30}(?:标记|检出).{0,20}(?:恶意|有害)/i.test(pageHint)) {
      const mainDom = parseVtDomStats(pageHint, hash, guiUrl);
      if (mainDom) {
        mainDom.source = "vt-page-main-report";
        if (pageEngineConsensus.engineDetailsAvailable) Object.assign(mainDom, pageEngineConsensus);
        return finalizePageResult(mainDom);
      }
    }

    // ① 页面/JSON 明确无样本（Item not found，常非 HTTP 404）
    if (isVtNotFoundError(data, status)) {
      return vtNotFoundResult(hash, { source: "vt-page", status: status || 200, verifiedNotFound: true });
    }
    if (payload.notFoundStable === true && pageUrl.includes(String(hash || "").toLowerCase())
      && looksLikeVtExplicitItemNotFoundText(pageHint)) {
      return vtNotFoundResult(hash, { source: "vt-page-dom", status: status || 200, verifiedNotFound: true });
    }

    // ② UI JSON 完整报告（浏览器页内同源 fetch 成功时）
    if (data && !isVtCaptchaError(data, status)) {
      const parsed = parseVtUiJson(data, hash, guiUrl);
      if (parsed && (parsed.found === true || parsed.notFound === true)) {
        parsed.source = "vt-page";
        return finalizePageResult(parsed);
      }
      if (data.data && data.data.attributes) {
        const hit = fileHitFromAttrs(data.data.attributes, hash, guiUrl, "vt-page");
        if (hit) return finalizePageResult(hit);
      }
    }
    if (text && !isVtCaptchaError(data, status)) {
      const fromText = parseVtStatsFromAnyText(text, hash, guiUrl, "vt-page-text");
      if (fromText && fromText.found === true) {
        return finalizePageResult(fromText);
      }
      // 仅有 signature_info 无 stats 时也尽量验签
      const onlySig = extractVtSignatureFromText(text);
      if (onlySig.trust === "valid" || onlySig.signer) {
        const base = fromText || {
          success: true,
          found: true,
          notFound: false,
          hash,
          guiUrl,
          source: "vt-page-sig",
          malicious: 0,
          suspicious: 0,
          total: 0,
          summary: ""
        };
        base.signerFromVt = onlySig.signer || base.signerFromVt || "";
        base.sigTrustFromVt = onlySig.trust || base.sigTrustFromVt || "";
        if (base.found === true) return finalizePageResult(base);
      }
    }

    // ③ 逐引擎明细可直接计算主报告分母。只计算有效判定，排除 timeout/failure/type-unsupported。
    const pageStats = vtStatsFromPageResults(payload.pageEngineResults);
    if (pageHasCurrentHash && pageStats.total >= 20) {
      const fromRows = {
        success: true,
        found: true,
        notFound: false,
        hash,
        guiUrl,
        source: "vt-page-engine-results",
        statsPolicyVersion: VT_STATS_POLICY_VERSION,
        ...pageStats,
        ratio: `${pageStats.malicious + pageStats.suspicious}/${pageStats.total}`,
        signerFromVt: "",
        summary: formatVtSummary(pageStats.malicious, pageStats.suspicious, pageStats.total, ""),
        ...pageEngineConsensus
      };
      return finalizePageResult(fromRows);
    }

    // ④ DOM 刮取检出比 + 签名文案
    const fromDom = pageHasCurrentHash ? parseVtDomStats(pageHint, hash, guiUrl) : null;
    if (fromDom) {
      fromDom.source = "vt-page-main-report";
      if (pageEngineConsensus.engineDetailsAvailable) Object.assign(fromDom, pageEngineConsensus);
      return finalizePageResult(fromDom);
    }

    if (isVtCaptchaError(data, status) && !fromDom) {
      return null;
    }
    return null;
  }

  /**
   * 查 VT（整段 ≤28s）：
   *  1) 可选 API Key v3
   *  2) ★ 扩展打开 VT 页：DOM 刮取 + 页内同源 fetch（浏览器会话，非外部爬）
   *  3) SW 直连短试
   */
  NS.lookupVirusTotalHash = async function (sha256, lookupOptions) {
    const hash = String(sha256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");
    if (hash.length !== 64) {
      return { success: false, error: "bad-hash", guiUrl: "", uploadUrl: VT_UPLOAD_PAGE, summary: "VT: 哈希无效" };
    }
    const guiUrl = VT_GUI_BASE + hash;
    const requireSignature = !!(lookupOptions && lookupOptions.requireSignature);
    const cached = NS._vtByHash.get(hash);
    const ttl = (cached && cached.ttl) || VT_CACHE_TTL_MS;
    if (cached && cached.at && Date.now() - cached.at < ttl) {
      const cr = cached.result || {};
      const cachedDetections = (Number(cr.malicious) || 0) + (Number(cr.suspicious) || 0);
      const summaryNeedsEngineRefresh = cr.source === "vt-page-main-report"
        && cr.found === true && cachedDetections > 0 && cr.engineDetailsAvailable !== true;
      const staleTrustPolicy = cr.found === true && cachedDetections > 0
        && Number(cr.trustedPolicyVersion) !== VT_TRUST_POLICY_VERSION;
      const staleStatsPolicy = cr.found === true
        && Number(cr.statsPolicyVersion) !== VT_STATS_POLICY_VERSION;
      const cachedSignatureMissing = requireSignature && cr.found === true
        && !/^(?:valid|invalid)$/i.test(String(cr.sigTrustFromVt || ""));
      // 绝不信任「猜的无」缓存（曾把验证码/失败误标成 notFound）
      if (cr.softMiss || cr.source === "vt-no-key"
        || cr.source === "vt-page-component" || cr.source === "vt-dom"
        || summaryNeedsEngineRefresh || staleTrustPolicy || staleStatsPolicy
        || cachedSignatureMissing) {
        try { NS._vtByHash.delete(hash); } catch { /* ignore */ }
      } else if (cr.found === true || (cr.notFound === true && cr.verifiedNotFound === true)) {
        return { ...cr, cached: true };
      } else if (cr.unknown && Date.now() - cached.at < 5000) {
        return { ...cr, cached: true };
      }
    }

    const apiKey = await getVtApiKey();
    // 有 Key：API 为主；无 Key：SW + 短页内（仅明确 NotFound 才报「无」）
    const LOOKUP_BUDGET_MS = apiKey ? 10000 : 28000;
    const t0 = Date.now();
    const remain = () => Math.max(0, LOOKUP_BUDGET_MS - (Date.now() - t0));

    const runLookup = async () => {
      // 扩展 SW 直连与真实 VT 页面属于不同请求上下文：SW 被验证码挡住，
      // 不代表携带浏览器会话的 GUI 页面也被验证码挡住。
      let sawSwCaptcha = false;
      let sawPageCaptcha = false;
      let sawRateLimit = false;
      let sawAuthBlocked = false;
      let sawLoadedPageWithoutStats = false;

      // ① 官方 v3（有 Key）
      if (apiKey) {
        try {
          const viaApi = await raceMs(
            lookupVtApiV3(hash, apiKey, guiUrl),
            Math.min(9000, Math.max(3000, remain())),
            null
          );
          if (viaApi && viaApi.found === true) {
            cacheVtResult(hash, viaApi, VT_CACHE_TTL_MS);
            return viaApi;
          }
          // API 404/NotFoundError 才是真「无」
          if (viaApi && viaApi.notFound === true && !viaApi.softMiss) {
            cacheVtResult(hash, viaApi, VT_CACHE_TTL_MS);
            return viaApi;
          }
          if (viaApi && viaApi.badApiKey) {
            cacheVtResult(hash, viaApi, 60 * 1000);
            return viaApi;
          }
          if (viaApi && viaApi.rateLimited) {
            const rl = vtUnknownResult(hash, {
              source: "api-rate",
              rateLimited: true,
              summary: "VT: API 限流，稍后重试"
            });
            cacheVtResult(hash, rl, 30 * 1000);
            return rl;
          }
        } catch { /* fall through */ }
        // Key 失败：短 SW；仍只有明确 notFound 才报无
        if (remain() > 1500) {
          try {
            const r1 = await fetchVtJson(VT_UI_BASE + hash, Math.min(4000, remain()));
            if (!isVtCaptchaError(r1.data, r1.status)
              && isVtNotFoundError(r1.data, r1.status)) {
              const miss = vtNotFoundResult(hash, { source: "vt-ui", status: r1.status || 200, verifiedNotFound: true });
              cacheVtResult(hash, miss, VT_CACHE_TTL_MS);
              return miss;
            }
            if (r1.data && !isVtCaptchaError(r1.data, r1.status)) {
              const parsed = parseVtUiJson(r1.data, hash, guiUrl);
              if (parsed && parsed.found === true) {
                cacheVtResult(hash, parsed, VT_CACHE_TTL_MS);
                return parsed;
              }
              if (parsed && parsed.notFound === true) {
                cacheVtResult(hash, parsed, VT_CACHE_TTL_MS);
                return parsed;
              }
            }
            if (r1.text) {
              const fromText = parseVtStatsFromAnyText(r1.text, hash, guiUrl, "vt-ui-text");
              if (fromText && fromText.found === true) {
                cacheVtResult(hash, fromText, VT_CACHE_TTL_MS);
                return fromText;
              }
            }
          } catch { /* ignore */ }
        }
        const unkKey = vtUnknownResult(hash, {
          source: "api-miss",
          summary: "VT: 查询未完成"
        });
        cacheVtResult(hash, unkKey, 8 * 1000);
        return unkKey;
      }

      // ② 无 Key：SW 短试
      if (remain() > 1000) {
        try {
          const r1 = await fetchVtJson(VT_UI_BASE + hash, Math.min(4500, remain()));
          // captcha/鉴权失败：绝不当「无」
          if (isVtCaptchaError(r1.data, r1.status)) {
            sawSwCaptcha = true;
          } else if (isVtRateOrAuthError(r1.data, r1.status)) {
            if (r1.status === 429) sawRateLimit = true;
            else sawAuthBlocked = true;
          } else {
            if (isVtNotFoundError(r1.data, r1.status)) {
              // 明确 NotFound 才报无
              const miss = vtNotFoundResult(hash, {
                source: "vt-ui",
                status: r1.status || 200,
                summary: "VT: 无",
                verifiedNotFound: true
              });
              cacheVtResult(hash, miss, VT_CACHE_TTL_MS);
              return miss;
            }
            if (r1.data) {
              const parsed = parseVtUiJson(r1.data, hash, guiUrl);
              if (parsed && parsed.found === true) {
                cacheVtResult(hash, parsed, VT_CACHE_TTL_MS);
                return parsed;
              }
              if (parsed && parsed.notFound === true) {
                cacheVtResult(hash, parsed, VT_CACHE_TTL_MS);
                return parsed;
              }
            }
            if (r1.text) {
              const fromText = parseVtStatsFromAnyText(r1.text, hash, guiUrl, "vt-ui-text");
              if (fromText && fromText.found === true) {
                cacheVtResult(hash, fromText, VT_CACHE_TTL_MS);
                return fromText;
              }
            }
          }
        } catch { /* continue */ }
      }

      // ③ 无 Key：页内短读（浏览器会话，能拿到真结果；仍只认明确 notFound）
      if (remain() > 3500) {
        try {
          const pagePayload = await fetchVtUiFromPageContext(
            hash,
            Math.min(20000, remain() - 300)
          );
          if (pagePayload && pagePayload.pageHint && String(pagePayload.pageHint).trim().length > 20) {
            sawLoadedPageWithoutStats = true;
          }
          if (pagePayload && (Number(pagePayload.status) === 401 || Number(pagePayload.status) === 403)) {
            sawAuthBlocked = true;
          }
          if (pagePayload && /RecaptchaRequired|recaptcha|captcha/i.test(String(pagePayload.text || ""))) {
            sawPageCaptcha = true;
          }
          if (pagePayload && /verify (?:that )?you are human|人机验证|验证码|captcha/i.test(String(pagePayload.pageHint || ""))) {
            sawPageCaptcha = true;
          }
          const pageParsed = parseVtPageFetchPayload(pagePayload, hash, guiUrl);
          if (pageParsed && pageParsed.found === true) {
            cacheVtResult(hash, pageParsed, VT_CACHE_TTL_MS);
            return pageParsed;
          }
           if (pageParsed && pageParsed.notFound === true && pageParsed.verifiedNotFound === true && !pageParsed.softMiss) {
            cacheVtResult(hash, pageParsed, VT_CACHE_TTL_MS);
            return pageParsed;
          }
        } catch (e) {
          try { console.warn("[silverfox] vt-page-fetch", e); } catch { /* ignore */ }
        }
      }

      // 查不清 ≠ 库中无（禁止再 softMiss 成「VT: 无」）
      const unk = vtUnknownResult(hash, {
        source: "vt",
        needApiKey: true,
        // 只有真实 GUI 页面也出现挑战时，popup 才宣称「页面要求人机验证」。
        captcha: sawPageCaptcha,
        swCaptcha: sawSwCaptcha,
        authBlocked: sawAuthBlocked,
        rateLimited: sawRateLimit,
        summary: sawPageCaptcha
          ? "VT: 当前页面会话要求人机验证"
          : (sawLoadedPageWithoutStats
            ? "VT: 已使用当前浏览器会话加载页面，但未抓到可解析的检出统计"
            : (sawAuthBlocked
              ? "VT: 自动接口拒绝扩展读取（HTTP 401/403）；页面链接仍可查看"
              : (sawRateLimit
                ? "VT: 自动接口限流（HTTP 429），稍后重试"
                : (sawSwCaptcha
                  ? "VT: 后台接口要求验证，当前会话页面未返回可解析统计"
                  : "VT: 自动取数未完成，请点开链接查看"))))
      });
      cacheVtResult(hash, unk, 8 * 1000);
      return unk;
    };

    try {
      const out = await raceMs(
        runLookup(),
        LOOKUP_BUDGET_MS + 500,
        vtUnknownResult(hash, { source: "vt-timeout", summary: "" })
      );
      return out || vtUnknownResult(hash, { summary: "" });
    } catch {
      return vtUnknownResult(hash, { source: "vt-error", summary: "" });
    }
  };

  /** 从任意文本中抠 last_analysis_stats / malicious 等 */
  function parseVtStatsFromAnyText(text, hash, guiUrl, source) {
    const s = String(text || "");
    if (!s || s.length < 20) return null;
    // 完整 last_analysis_stats 对象
    const mStats = s.match(/"last_analysis_stats"\s*:\s*\{([^}]{5,500})\}/i);
    if (mStats) {
      const block = mStats[1];
      const g = (k) => {
        const m = block.match(new RegExp('"' + k + '"\\s*:\\s*(\\d+)', "i"));
        return m ? parseInt(m[1], 10) : 0;
      };
      const malicious = g("malicious");
      const suspicious = g("suspicious");
      const undetected = g("undetected");
      const harmless = g("harmless");
      const total = malicious + suspicious + undetected + harmless;
      // 抽到 stats 即视为有记录（含 0 检出）
      const signer = "";
      return {
        success: true,
        found: true,
        notFound: false,
        hash,
        guiUrl,
        source: source || "vt-text",
        statsPolicyVersion: VT_STATS_POLICY_VERSION,
        malicious,
        suspicious,
        undetected,
        harmless,
        total,
        ratio: total ? `${malicious + suspicious}/${total}` : `${malicious}+${suspicious}`,
        signerFromVt: "",
        summary: formatVtSummary(malicious, suspicious, total, signer)
      };
    }
    // "malicious":0,"suspicious":0,"undetected":70...
    const mMal = s.match(/"malicious"\s*:\s*(\d+)\s*,\s*"suspicious"\s*:\s*(\d+)/i);
    if (mMal) {
      const malicious = parseInt(mMal[1], 10) || 0;
      const suspicious = parseInt(mMal[2], 10) || 0;
      const mUnd = s.match(/"undetected"\s*:\s*(\d+)/i);
      const mHarm = s.match(/"harmless"\s*:\s*(\d+)/i);
      const und = mUnd ? parseInt(mUnd[1], 10) : 0;
      const harm = mHarm ? parseInt(mHarm[1], 10) : 0;
      const total = malicious + suspicious + und + harm;
      if (total > 0 || /last_analysis/i.test(s)) {
        return {
          success: true,
          found: true,
          notFound: false,
          hash,
          guiUrl,
          source: source || "vt-text",
          statsPolicyVersion: VT_STATS_POLICY_VERSION,
          malicious,
          suspicious,
          undetected: und,
          harmless: harm,
          total,
          ratio: total ? `${malicious + suspicious}/${total}` : `${malicious}+${suspicious}`,
          signerFromVt: "",
          summary: formatVtSummary(malicious, suspicious, total, "")
        };
      }
    }
    return null;
  }

  function parseVtFileUploadPayload(data, text, status) {
    const out = {
      success: false,
      needCaptcha: false,
      analysisId: "",
      guiUrl: "",
      hash: "",
      status: status || 0,
      uploadUrl: VT_UPLOAD_PAGE
    };
    let body = data;
    if (!body && text) {
      try { body = JSON.parse(text); } catch { body = null; }
    }
    if (body && body.error) {
      const blob = JSON.stringify(body.error).slice(0, 500);
      if (/recaptcha|captcha|AuthenticationRequired|Forbidden/i.test(blob)) {
        out.needCaptcha = true;
        out.error = "recaptcha";
        out.summary = "VT 文件上传需人机验证";
      } else {
        out.error = String(body.error.message || body.error.code || "upload-error").slice(0, 120);
        out.summary = "VT 文件上传失败";
      }
      return out;
    }
    const id = body && body.data && body.data.id ? String(body.data.id) : "";
    const dtype = body && body.data && body.data.type ? String(body.data.type) : "";
    // 分析 id 常为 uuid 或带 -；完成态可能直接给 sha256
    const sha = body && body.data && body.data.attributes && body.data.attributes.sha256
      ? String(body.data.attributes.sha256).toLowerCase()
      : (/^[a-f0-9]{64}$/i.test(id) ? id.toLowerCase() : "");
    // analysis / file 对象都算上传成功
    if (id || sha || (status >= 200 && status < 300 && body && body.data
      && (/analysis|file/i.test(dtype) || body.data.links))) {
      out.success = true;
      out.analysisId = id;
      out.hash = sha;
      if (sha) out.guiUrl = VT_GUI_BASE + sha;
      else if (id && /analysis/i.test(dtype)) {
        out.guiUrl = "https://www.virustotal.com/gui/file-analysis/" + encodeURIComponent(id);
      } else if (id) {
        out.guiUrl = "https://www.virustotal.com/gui/file-analysis/" + encodeURIComponent(id);
      } else {
        out.guiUrl = VT_UPLOAD_PAGE;
      }
      out.summary = "已提交文件到 VT 分析";
      return out;
    }
    out.error = "http-" + (status || 0);
    out.summary = "VT 文件上传失败";
    if (status === 401 || status === 403 || status === 429) out.needCaptcha = true;
    return out;
  }

  /** 按体积估算上传超时：约 1MB/s + 缓冲，上限 15 分钟 */
  function vtUploadTimeoutMs(byteLength) {
    const mb = Math.max(1, (byteLength || 0) / (1024 * 1024));
    return Math.min(15 * 60 * 1000, Math.max(45000, Math.ceil(mb * 1200) + 30000));
  }

  async function fetchVtUploadUrlApi(apiKey) {
    try {
      const ur = await fetch("https://www.virustotal.com/api/v3/files/upload_url", {
        method: "GET",
        cache: "no-store",
        headers: { Accept: "application/json", "x-apikey": apiKey }
      });
      const uj = await ur.json();
      if (uj && uj.data) return String(uj.data);
    } catch { /* ignore */ }
    return "";
  }

  async function postMultipartToVt(endpoint, form, headers, timeoutMs) {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller
      ? setTimeout(() => { try { controller.abort(); } catch { /* ignore */ } }, timeoutMs || 120000)
      : null;
    // 跨域 upload_url（GCS 等）带 cookie 会 CORS 失败；仅 virustotal.com 用 include
    let credentials = "omit";
    try {
      if (headers && headers.__credentials === "include") credentials = "include";
      else if (headers && headers.__credentials === "omit") credentials = "omit";
      else if (/virustotal\.com/i.test(String(endpoint || ""))) credentials = "include";
    } catch { credentials = "omit"; }
    try {
      const h = Object.assign({}, headers || {});
      delete h.__credentials;
      const res = await fetch(endpoint, {
        method: "POST",
        cache: "no-store",
        credentials,
        headers: h,
        body: form,
        signal: controller ? controller.signal : undefined
      });
      if (timer) clearTimeout(timer);
      const text = await res.text();
      let data = null;
      try { data = JSON.parse(text); } catch { data = null; }
      return { status: res.status, text, data, ok: res.ok };
    } catch (e) {
      if (timer) clearTimeout(timer);
      return {
        status: 0,
        text: "",
        data: null,
        ok: false,
        error: e && e.message ? e.message : "upload-fail"
      };
    }
  }

  function makeVtFileForm(arrayBuffer, name) {
    const form = new FormData();
    // SW 里用 Uint8Array 更稳，避免部分环境对裸 ArrayBuffer 的 Blob 处理异常
    const bytes = arrayBuffer instanceof Uint8Array
      ? arrayBuffer
      : new Uint8Array(arrayBuffer);
    form.append(
      "file",
      new Blob([bytes], { type: "application/octet-stream" }),
      name
    );
    return form;
  }

  /**
   * 真·文件上传：仅 API Key 路径（无 Key 不上传、不做 UI 上传）。
   * 上限 650MB；≤32MB 直传 /files，更大先取 upload_url。
   */
  NS.submitFileBytesToVt = async function (arrayBuffer, filename) {
    if (!arrayBuffer || !arrayBuffer.byteLength) {
      return { success: false, error: "empty-file", uploadUrl: VT_UPLOAD_PAGE };
    }
    if (arrayBuffer.byteLength > VT_UPLOAD_MAX) {
      return {
        success: false,
        error: "too-large",
        uploadUrl: VT_UPLOAD_PAGE,
        summary: "文件超过 650MB，VT 不接受（请拆包后手动上传）"
      };
    }
    const apiKey = await getVtApiKey();
    if (!apiKey) {
      return {
        success: false,
        error: "no-api-key",
        needApiKey: true,
        uploadUrl: VT_UPLOAD_PAGE,
        summary: "未配置 API Key，跳过自动上传"
      };
    }
    const name = String(filename || "sample.bin").replace(/[^\w.\-()+ ]+/g, "_").slice(0, 120);
    const size = arrayBuffer.byteLength;
    const needUploadUrl = size > VT_DIRECT_UPLOAD_MAX;
    const timeoutMs = vtUploadTimeoutMs(size);

    try {
      let uploadEndpoint = "https://www.virustotal.com/api/v3/files";
      if (needUploadUrl) {
        const big = await fetchVtUploadUrlApi(apiKey);
        if (big && /^https?:\/\//i.test(big)) {
          uploadEndpoint = big;
        } else {
          return {
            success: false,
            error: "upload-url-fail",
            uploadUrl: VT_UPLOAD_PAGE,
            summary: "无法获取 VT 大文件上传地址"
          };
        }
      }
      const res = await postMultipartToVt(
        uploadEndpoint,
        makeVtFileForm(arrayBuffer, name),
        {
          Accept: "application/json",
          "x-apikey": apiKey,
          __credentials: /virustotal\.com/i.test(uploadEndpoint) ? "omit" : "omit"
        },
        timeoutMs
      );
      if (res.error) {
        return {
          success: false,
          error: res.error,
          uploadUrl: VT_UPLOAD_PAGE,
          summary: "VT API 上传失败（网络或超时）"
        };
      }
      const parsed = parseVtFileUploadPayload(res.data, res.text, res.status);
      if (parsed.success) {
        return Object.assign(parsed, {
          source: "api-v3",
          size,
          summary: "已通过 API 提交文件到 VT"
        });
      }
      return Object.assign(parsed, {
        summary: parsed.summary || ("VT API 上传失败" + (parsed.error ? "：" + parsed.error : "")),
        uploadUrl: VT_UPLOAD_PAGE
      });
    } catch (e) {
      return {
        success: false,
        error: e && e.message ? e.message : "upload-fail",
        uploadUrl: VT_UPLOAD_PAGE,
        summary: "VT API 上传失败"
      };
    }
  };

  NS._vtFeedCooldown = NS._vtFeedCooldown || new Map();

  /**
   * 设置：vtAutoSubmitUrl 默认 true
   * → 无库结果且已配置 API Key 时自动上传文件
   */
  async function readVtFeedSettings() {
    const r = await readStorageKeys(["vtAutoSubmitUrl"]);
    const autoSubmit = r.vtAutoSubmitUrl === undefined ? true : !!r.vtAutoSubmitUrl;
    return { autoSubmit };
  }

  /**
   * 真·文件上传（仅 API Key）：无 Key 直接跳过，不走 UI 上传。
   */
  NS.feedFileToVtUpload = async function (arrayBuffer, filename, opts) {
    opts = opts || {};
    if (!arrayBuffer || !arrayBuffer.byteLength) {
      return {
        success: false,
        error: "need-file-bytes",
        uploadUrl: VT_UPLOAD_PAGE,
        submitted: false,
        autoSubmit: true,
        summary: "无文件字节，无法上传"
      };
    }
    const forceSubmit = !!opts.forceSubmit;
    const settings = await readVtFeedSettings();
    const autoSubmit = forceSubmit || settings.autoSubmit;
    const ab = arrayBuffer;
    const name = String(filename || opts.filename || "sample.bin");
    const coolKey = "file:" + String(opts.sha256 || name).toLowerCase()
      + ":" + (ab && ab.byteLength ? ab.byteLength : 0);

    const out = {
      success: false,
      uploadUrl: VT_UPLOAD_PAGE,
      submitted: false,
      guiUrl: "",
      autoSubmit,
      summary: ""
    };

    if (ab.byteLength > VT_UPLOAD_MAX) {
      out.error = "too-large";
      out.summary = "文件超过 650MB，VT 不接受";
      return out;
    }
    if (!autoSubmit) {
      out.summary = "已关闭自动上传";
      return out;
    }

    const apiKey = await getVtApiKey();
    if (!apiKey) {
      out.error = "no-api-key";
      out.needApiKey = true;
      out.summary = "未配置 API Key，跳过自动上传";
      return out;
    }

    const lastOk = NS._vtFeedCooldown.get(coolKey + ":ok") || 0;
    if (!forceSubmit && lastOk && (Date.now() - lastOk < 10 * 60 * 1000)) {
      out.success = true;
      out.submitted = true;
      out.summary = "该文件近期已上传过";
      return out;
    }
    const lastFail = NS._vtFeedCooldown.get(coolKey + ":fail") || 0;
    if (!forceSubmit && lastFail && (Date.now() - lastFail < 90 * 1000)) {
      out.error = "cool-fail";
      out.summary = "上传刚失败，稍后重试";
      return out;
    }

    try {
      const up = await NS.submitFileBytesToVt(ab, name);
      out.upload = up;
      if (up && up.success) {
        NS._vtFeedCooldown.set(coolKey + ":ok", Date.now());
        out.success = true;
        out.submitted = true;
        out.guiUrl = up.guiUrl || "";
        out.analysisId = up.analysisId || "";
        out.hash = up.hash || "";
        out.summary = up.summary || "已上传文件到 VT 分析";
        return out;
      }
      NS._vtFeedCooldown.set(coolKey + ":fail", Date.now());
      out.error = (up && up.error) || "upload-fail";
      out.needApiKey = !!(up && up.needApiKey);
      out.detail = (up && up.detail) || "";
      out.summary = (up && up.summary) || "API 上传失败";
      return out;
    } catch (e) {
      NS._vtFeedCooldown.set(coolKey + ":fail", Date.now());
      out.error = e && e.message ? e.message : "feed-fail";
      out.summary = "自动上传失败";
      return out;
    }
  };

  function statsFromAttrs(attrs) {
    const stats = (attrs && (attrs.last_analysis_stats || attrs.lastAnalysisStats || attrs.stats)) || {};
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const undetected = Number(stats.undetected) || 0;
    const harmless = Number(stats.harmless) || 0;
    // VT 主报告分母只统计产生有效判定的引擎；超时、失败和不支持类型不进入 x/y 的 y。
    const total = malicious + suspicious + undetected + harmless;
    return { malicious, suspicious, undetected, harmless, total, stats };
  }

  // VT 总检出数只作参考；自动拦截必须依赖独立、知名安全引擎的明细共识。
  const VT_TRUSTED_ENGINE_RULES = [
    ["BitDefender", /^BitDefender(?:Falx)?$/i],
    ["ESET", /^ESET(?:-NOD32)?$/i],
    ["Avast", /^Avast(?:-Mobile)?$/i],
    ["Kaspersky", /^Kaspersky$/i],
    ["Huorong", /^(?:Huorong|火绒)$/i]
  ];

  function trustedVtEngineName(engineName) {
    const raw = String(engineName || "").trim();
    if (!raw) return "";
    for (const [canonical, rule] of VT_TRUSTED_ENGINE_RULES) {
      if (rule.test(raw)) return canonical;
    }
    return "";
  }

  function vtEngineConsensusFromEntries(entries, detailsAvailable) {
    const out = {
      trustedPolicyVersion: VT_TRUST_POLICY_VERSION,
      engineDetailsAvailable: !!detailsAvailable,
      detectedEngines: [],
      trustedEngineResults: [],
      trustedEngineObservedCount: 0,
      trustedDetections: [],
      trustedEngineCount: 0,
      trustedMaliciousCount: 0,
      trustedSuspiciousCount: 0
    };
    if (!out.engineDetailsAvailable || !Array.isArray(entries)) return out;

    const trustedByFamily = new Map();
    const trustedResultsByFamily = new Map();
    const categoryRank = { malicious: 6, suspicious: 5, harmless: 4, undetected: 3, timeout: 2 };
    for (const entry of entries) {
      const key = Array.isArray(entry) ? entry[0] : "";
      const raw = Array.isArray(entry) ? entry[1] : entry;
      if (!raw || typeof raw !== "object") continue;
      const category = String(raw.category || "").toLowerCase();
      const engine = String(raw.engine_name || raw.engineName || key || "").trim();
      const item = {
        engine,
        category,
        result: String(raw.result || "").slice(0, 160)
      };
      const trusted = trustedVtEngineName(engine);
      if (trusted) {
        const observed = trustedResultsByFamily.get(trusted);
        if (!observed || (categoryRank[category] || 0) > (categoryRank[observed.category] || 0)) {
          trustedResultsByFamily.set(trusted, { ...item, engine: trusted });
        }
      }
      if (category !== "malicious" && category !== "suspicious") continue;
      out.detectedEngines.push(item);
      if (!trusted) continue;
      const previous = trustedByFamily.get(trusted);
      // 同一厂商的多个别名/移动版只算一个独立引擎；malicious 高于 suspicious。
      if (!previous || (previous.category !== "malicious" && category === "malicious")) {
        trustedByFamily.set(trusted, { ...item, engine: trusted });
      }
    }
    out.detectedEngines = out.detectedEngines.slice(0, 50);
    out.trustedEngineResults = Array.from(trustedResultsByFamily.values());
    out.trustedEngineObservedCount = out.trustedEngineResults.length;
    out.trustedDetections = Array.from(trustedByFamily.values());
    out.trustedEngineCount = out.trustedDetections.length;
    out.trustedMaliciousCount = out.trustedDetections.filter((x) => x.category === "malicious").length;
    out.trustedSuspiciousCount = out.trustedDetections.filter((x) => x.category === "suspicious").length;
    return out;
  }

  function vtEngineConsensusFromAttrs(attrs) {
    const results = attrs && (attrs.last_analysis_results || attrs.lastAnalysisResults);
    const entries = results && typeof results === "object" ? Object.entries(results) : [];
    return vtEngineConsensusFromEntries(entries, entries.length > 0);
  }

  function vtEngineConsensusFromPageResults(results) {
    const entries = Array.isArray(results) ? results.filter((x) => x && typeof x === "object") : [];
    return vtEngineConsensusFromEntries(entries, entries.length > 0);
  }

  function vtStatsFromPageResults(results) {
    const byEngine = new Map();
    const valid = new Set(["malicious", "suspicious", "undetected", "harmless"]);
    for (const raw of (Array.isArray(results) ? results : [])) {
      if (!raw || typeof raw !== "object") continue;
      const engine = String(raw.engine_name || raw.engineName || raw.engine || "").trim();
      const category = String(raw.category || "").toLowerCase();
      if (!engine || !valid.has(category)) continue;
      byEngine.set(engine.toLowerCase(), category);
    }
    const stats = { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, total: 0 };
    for (const category of byEngine.values()) stats[category] += 1;
    stats.total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
    return stats;
  }

  function signerFromAttrs(attrs) {
    const sig = (attrs && (attrs.signature_info || attrs.signatureInfo)) || {};
    const signers = sig.signers || sig.subject || sig["signers details"] || sig.signersdetails || "";
    let signerStr = "";
    if (typeof signers === "string") signerStr = signers;
    else if (Array.isArray(signers)) {
      signerStr = signers.map((s) => (s && (s.name || s.subject || s)).toString()).filter(Boolean).join("; ");
    } else if (signers && typeof signers === "object") {
      signerStr = String(signers.name || signers.subject || "");
    }
    // 有的样本在 signature_info.product / description
    if (!signerStr && sig.product) signerStr = String(sig.product);
    if (!signerStr && sig.copyright) signerStr = String(sig.copyright);
    return sanitizePublisherName(signerStr);
  }

  function fileHitFromAttrs(attrs, hash, guiUrl, source) {
    if (!attrs || typeof attrs !== "object") return null;
    // 有文件元数据即视为库中存在（即使 stats 暂空）
    const hasMeta = !!(
      attrs.sha256 || attrs.sha1 || attrs.md5
      || attrs.type_description || attrs.type_tag || attrs.type_extension
      || attrs.last_analysis_date || attrs.first_submission_date
      || attrs.last_analysis_stats || attrs.lastAnalysisStats
      || attrs.meaningful_name || attrs.meaningfulName
      || attrs.size != null
    );
    if (!hasMeta) return null;
    const { malicious, suspicious, undetected, harmless, total } = statsFromAttrs(attrs);
    const engineConsensus = vtEngineConsensusFromAttrs(attrs);
    const sigMeta = vtSignatureMetaFromAttrs(attrs);
    const signer = sigMeta.signer || signerFromAttrs(attrs);
    return {
      success: true,
      found: true,
      notFound: false,
      hash,
      guiUrl,
      source: source || "vt-ui",
      statsPolicyVersion: VT_STATS_POLICY_VERSION,
      malicious,
      suspicious,
      undetected,
      harmless,
      ...engineConsensus,
      total: total || (malicious + suspicious + undetected + harmless),
      ratio: total ? `${malicious + suspicious}/${total}` : `${malicious}+${suspicious}`,
      signerFromVt: signer,
      sigTrustFromVt: sigMeta.trust || "",
      meaningfulName: String(attrs.meaningful_name || attrs.meaningfulName || "").slice(0, 120),
      summary: formatVtSummary(malicious, suspicious, total, signer)
    };
  }

  function parseVtUiJson(data, hash, guiUrl) {
    if (!data || typeof data !== "object") return null;
    // 明确 NotFound（常非 HTTP 404）→ VT: 无
    if (data.error) {
      if (isVtNotFoundError(data, 0) || looksLikeVtItemNotFound(JSON.stringify(data.error))) {
        return vtNotFoundResult(hash, { source: "vt-ui", verifiedNotFound: true });
      }
      // 限流/鉴权：不是「无」
      return null;
    }
    // 常见：{ data: { id, type, attributes } }
    const node = data.data || data;
    const attrs = (node && node.attributes) || (data.attributes) || null;
    if (attrs && typeof attrs === "object") {
      const hit = fileHitFromAttrs(attrs, hash, guiUrl, "vt-ui");
      if (hit) return hit;
    }
    // 有时 data 本身就是 attributes
    if (node && typeof node === "object" && (node.last_analysis_stats || node.sha256 || node.type_description)) {
      const hit = fileHitFromAttrs(node, hash, guiUrl, "vt-ui");
      if (hit) return hit;
    }
    return null;
  }

  /** UI search 返回：data 数组里 type=file 的项 */
  function parseVtSearchJson(data, hash, guiUrl) {
    if (!data || typeof data !== "object") return null;
    if (data.error) {
      if (isVtNotFoundError(data, 0)) return vtNotFoundResult(hash, { source: "vt-search", verifiedNotFound: true });
      return null;
    }
    const list = Array.isArray(data.data) ? data.data
      : (data.data ? [data.data] : (Array.isArray(data) ? data : []));
    if (!list.length) {
      // 空结果：可能是无记录，也可能是限流后空壳——不武断判无
      return null;
    }
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const id = String(item.id || "").toLowerCase();
      const type = String(item.type || "").toLowerCase();
      const attrs = item.attributes || item;
      // 命中同 hash 的 file
      if (type === "file" || /^[a-f0-9]{64}$/.test(id) || (attrs && attrs.sha256)) {
        const itemHash = (attrs && attrs.sha256) || id;
        if (itemHash && String(itemHash).toLowerCase() !== hash && type === "file" && id && id !== hash) {
          // 不同文件，跳过
          continue;
        }
        if (type === "file" || String(itemHash).toLowerCase() === hash || (attrs && String(attrs.sha256 || "").toLowerCase() === hash)) {
          const hit = fileHitFromAttrs(attrs || {}, hash, guiUrl, "vt-search");
          if (hit) return hit;
          // 至少 search 点到了这个 hash
          return {
            success: true,
            found: true,
            notFound: false,
            hash,
            guiUrl,
            source: "vt-search",
            malicious: 0,
            suspicious: 0,
            total: 0,
            summary: "VT: 库中有此文件（详情请点开）",
            signerFromVt: ""
          };
        }
      }
    }
    return null;
  }

  function parseVtGuiHtml(html, hash, guiUrl, status) {
    const text = String(html || "");
    const base = {
      success: true,
      found: null,
      notFound: false,
      unknown: true,
      hash,
      guiUrl,
      source: "vt-gui",
      statsPolicyVersion: VT_STATS_POLICY_VERSION,
      status: status || 0,
      summary: "VT: 请点开链接查看检出"
    };
    if (!text) {
      base.summary = "VT: 请点开链接查看检出";
      return base;
    }
    // GUI HTML/营销文案不是权威查无结果，继续尝试解析真实 stats。
    // 尝试从内嵌 JSON / 文案抽检出
    let malicious = null;
    let total = null;
    const mStats = text.match(/"last_analysis_stats"\s*:\s*\{([^}]{0,400})\}/i);
    if (mStats) {
      const block = mStats[1];
      const g = (k) => {
        const m = block.match(new RegExp('"' + k + '"\\s*:\\s*(\\d+)', "i"));
        return m ? parseInt(m[1], 10) : 0;
      };
      malicious = g("malicious");
      const sus = g("suspicious");
      const und = g("undetected");
      const harm = g("harmless");
      total = malicious + sus + und + harm;
      base.malicious = malicious;
      base.suspicious = sus;
      base.undetected = und;
      base.harmless = harm;
      base.total = total;
      base.found = true;
      base.notFound = false;
      base.unknown = false;
      base.summary = formatVtSummary(malicious, sus, total, "");
      return base;
    }
    const mRatio = text.match(/(\d{1,3})\s*\/\s*(\d{1,3})\s*(?:security vendors|engines|检测)/i)
      || text.match(/"malicious"\s*:\s*(\d+)\s*,\s*"suspicious"\s*:\s*(\d+)/i);
    if (mRatio) {
      if (/malicious/i.test(mRatio[0])) {
        malicious = parseInt(mRatio[1], 10);
        const sus = parseInt(mRatio[2], 10) || 0;
        base.malicious = malicious;
        base.suspicious = sus;
        base.found = true;
        base.notFound = false;
        base.unknown = false;
        base.ratio = `${malicious + sus}?`;
        base.summary = formatVtSummary(malicious, sus, 0, "");
        return base;
      }
      malicious = parseInt(mRatio[1], 10);
      total = parseInt(mRatio[2], 10);
      base.malicious = malicious;
      base.total = total;
      base.found = true;
      base.notFound = false;
      base.unknown = false;
      base.ratio = `${malicious}/${total}`;
      base.summary = formatVtSummary(malicious, 0, total, "");
      return base;
    }
    const mMal = text.match(/"malicious"\s*:\s*(\d+)/i);
    const mUnd = text.match(/"undetected"\s*:\s*(\d+)/i);
    if (mMal) {
      malicious = parseInt(mMal[1], 10);
      const und = mUnd ? parseInt(mUnd[1], 10) : 0;
      base.malicious = malicious;
      base.undetected = und;
      base.found = true;
      base.notFound = false;
      base.unknown = false;
      base.summary = formatVtSummary(malicious, 0, malicious + und, "");
      return base;
    }
    // SPA 壳 / 登录墙：未知（有记录也可能是这壳），绝不能写成「无」
    if (/login|captcha|Access denied|cf-browser-verification/i.test(text) && text.length < 4000) {
      base.summary = "VT: 需登录/人机验证，请点开链接查看";
      return base;
    }
    base.summary = "VT: 请点开链接查看检出";
    return base;
  }

  function formatVtSummary(malicious, suspicious, total, signer) {
    const m = Number(malicious) || 0;
    const s = Number(suspicious) || 0;
    const t = Number(total) || 0;
    let head;
    if (t > 0) head = `VT 检出 ${m + s}/${t}（恶意 ${m} / 可疑 ${s}）`;
    else head = `VT 恶意 ${m} · 可疑 ${s}`;
    if (signer) head += ` · 数字签名: ${String(signer).slice(0, 60)}`;
    return head;
  }

  function basenameFromUrlOrName(url, filename) {
    try {
      if (filename) {
        const b = String(filename).split(/[/\\]/).pop();
        if (b) return b;
      }
    } catch { /* ignore */ }
    try {
      return decodeURIComponent(new URL(url).pathname.split("/").pop() || "") || "package.bin";
    } catch {
      return "package.bin";
    }
  }

  function packageKindFromName(nameOrUrl) {
    const s = String(nameOrUrl || "").toLowerCase();
    if (PE_EXT_RE.test(s)) return "pe";
    if (/\.msi(?:\?|#|$)/i.test(s) || /\.msp(?:\?|#|$)/i.test(s)) return "msi";
    if (/\.apk(?:\?|#|$)/i.test(s)) return "apk";
    if (ARCHIVE_EXT_RE.test(s)) return "archive";
    if (PACKAGE_EXT_RE.test(s)) return "package";
    return "";
  }

  function looksLikePackageItem(item) {
    try {
      const url = item.finalUrl || item.url || "";
      const name = (item.filename || "").split(/[/\\]/).pop() || "";
      if (PACKAGE_EXT_RE.test(name) || PACKAGE_EXT_RE.test(url)) return true;
      // Content-Disposition / 无扩展名但启发式包名
      try {
        const { PackageHeuristicsBg } = NS;
        if (PackageHeuristicsBg && PackageHeuristicsBg.PACKAGE_NAME_RE) {
          if (PackageHeuristicsBg.PACKAGE_NAME_RE.test(name)
            || PackageHeuristicsBg.PACKAGE_NAME_RE.test(PackageHeuristicsBg.basenameFromPath(url))) {
            return true;
          }
        }
      } catch { /* ignore */ }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * 对 URL 拉文件 →（可选）PE 签名粗检 + SHA256 + VT。
   * 适用于 exe/msi/zip/rar/7z/apk/dmg 等。
   */
  NS.inspectPackageUrl = async function (url, meta) {
    const u = String(url || "");
    const name = (meta && meta.filename) || basenameFromUrlOrName(u, "");
    if (!u || !/^https?:\/\//i.test(u)) {
      return { success: false, error: "bad-url" };
    }
    const kind = packageKindFromName(name) || packageKindFromName(u) || "package";
    const key = u.slice(0, 300);
    if (NS._peVtInflight.has(key)) return NS._peVtInflight.get(key);

    const p = (async () => {
      const report = {
        success: false,
        url: u.slice(0, 500),
        filename: name,
        kind,
        pe: null,
        sha256: "",
        vt: null,
        at: Date.now()
      };
      try {
        const looksArchive = kind === "archive" || kind === "package"
          || ARCHIVE_EXT_RE.test(name) || ARCHIVE_EXT_RE.test(u);
        let fetched = await fetchArrayBuffer(u, {
          timeoutMs: FETCH_TIMEOUT_MS,
          maxBytes: MAX_FULL_FETCH
        });

        // 超大文件：全量下载失败时，对压缩包走 Range 分段扫包内 PE
        if ((!fetched.ok || !fetched.buf) && fetched.tooLarge) {
          const sizeMb = fetched.contentLength
            ? Math.round(fetched.contentLength / 1048576)
            : "?";
          if (looksArchive) {
            try {
              const rangeScan = await scanLargeZipByHttpRange(u);
              report.kind = "archive";
              report.pe = { isPe: false, signed: false, signerHint: "", skipped: true, reason: "archive" };
              report.nested = (rangeScan && rangeScan.items) || [];
              report.archiveFormat = (rangeScan && rangeScan.format) || "zip";
              report.sha256 = ""; // 未全量下载，无法可靠哈希
              report.vt = {
                success: true,
                found: null,
                notFound: false,
                unknown: true,
                summary: "",
                guiUrl: ""
              };
              report.success = true;
              report.partialScan = true;
              report.error = "";
              if (report.nested.length) {
                report.archiveNote = (rangeScan && rangeScan.note)
                  || ("大文件约 " + sizeMb + "MB，分段扫描到包内 "
                    + report.nested.length + " 个可执行文件");
              } else {
                report.archiveNote = (rangeScan && rangeScan.note)
                  || ("文件过大（约 " + sizeMb + "MB），分段扫描未抽出可执行文件");
              }
              if (report.nested.length && !(meta && meta.skipNestedVt)) {
                try {
                  await attachVtToNestedItems(report.nested, Number(meta && meta.nestedVtBudgetMs) || 30000);
                } catch { /* ignore */ }
              }
              report.signature = resolveDigitalSignature(report.pe, null, report.nested);
              return report;
            } catch (e) {
              report.error = "文件过大（约 " + sizeMb + "MB），分段扫描失败";
              report.success = false;
              report.archiveNote = report.error;
              return report;
            }
          }
          report.error = "文件过大（约 " + sizeMb + "MB，上限 "
            + Math.round(MAX_RANGE_ARCHIVE / 1048576) + "MB）";
          report.success = false;
          return report;
        }

        if (!fetched.ok || !fetched.buf) {
          report.error = fetched.error || ("http-" + (fetched.status || 0));
          report.success = false;
          return report;
        }
        const ab = fetched.buf;
        // PE：Authenticode；其它先标 kind。包内扫描会与外层 VT 网络查询并行。
        if (kind === "pe" || (kind !== "archive" && kind !== "msi" && kind !== "apk"
          && NS.parsePeAuthenticode(ab).isPe)) {
          report.pe = NS.parsePeAuthenticode(ab);
          if (report.pe && report.pe.isPe) report.kind = "pe";
        } else {
          report.pe = { isPe: false, signed: false, signerHint: "", skipped: true, reason: kind };
        }
        report.nested = [];
        report.archiveNote = "";
        report.archiveFormat = "";

        // ★ 本地解析（快）→ 立刻 onPartial → VT 查询 → 再 onPartial → 上传后台跑
        report.sha256 = await NS.sha256HexOfBuffer(ab);
        try {
          report.signature = resolveDigitalSignature(report.pe, null, []);
        } catch { /* ignore */ }
        // 本地 PE/哈希就绪：先推 UI，不必等 VT
        if (meta && typeof meta.onPartial === "function") {
          try {
            meta.onPartial({
              stage: "local",
              report: {
                success: true,
                url: report.url,
                filename: report.filename,
                kind: report.kind,
                pe: report.pe,
                sha256: report.sha256,
                signature: report.signature,
                vt: null,
                nested: [],
                at: Date.now()
              }
            });
          } catch { /* ignore */ }
        }

        const skipNested = !!(meta && meta.skipNested);
        const detectedArchiveFormat = detectArchiveFormat(ab);
        const isZipLike = !skipNested && (kind === "archive" || kind === "package" || kind === "apk"
          || ARCHIVE_EXT_RE.test(name) || ARCHIVE_EXT_RE.test(u)
          || detectedArchiveFormat === "zip" || detectedArchiveFormat === "rar"
          || detectedArchiveFormat === "7z");
        // 解压/包内 PE 解析与外层 VT 查询互不依赖，并行可直接省掉一段串行等待。
        const nestedScanPromise = isZipLike
          ? Promise.resolve().then(() => scanNestedExecutablesInArchive(ab)).then((scan) => {
            // 包内本地解析一完成就推给 popup，不必等外层 VT；签名先黑色，VT 验真后再升级绿色。
            if (meta && typeof meta.onPartial === "function" && scan) {
              try {
                const nestedItems = scan.items || [];
                meta.onPartial({
                  stage: "local",
                  report: {
                    success: true,
                    url: report.url,
                    filename: report.filename,
                    kind: report.kind === "pe" ? "pe" : "archive",
                    pe: report.pe,
                    sha256: report.sha256,
                    signature: resolveDigitalSignature(report.pe, null, nestedItems),
                    vt: null,
                    nested: nestedItems,
                    archiveNote: scan.note || "",
                    archiveFormat: scan.format || "",
                    at: Date.now()
                  }
                });
              } catch { /* ignore partial UI update */ }
            }
            return scan;
          })
          : null;

        if (report.sha256) {
          try {
            report.vt = await raceMs(
              NS.lookupVirusTotalHash(report.sha256),
              30000,
              vtUnknownResult(report.sha256, {
                source: "vt-inspect-timeout",
                summary: ""
              })
            );
          } catch {
            report.vt = vtUnknownResult(report.sha256, {
              source: "vt-inspect-error",
              summary: ""
            });
          }
          if (!report.vt) {
            report.vt = vtUnknownResult(report.sha256, { summary: "" });
          }
          try {
            report.vt = enrichVtResultWithSignature(
              report.vt,
              report.vt && (report.vt.rawText || report.vt.summary) || "",
              report.vt && report.vt.pageHint || ""
            );
          } catch { /* ignore */ }
          if (report.pe && report.pe.isPe && report.pe.signed && !report.pe.signerHint
            && report.vt && report.vt.signerFromVt) {
            const fromVt = sanitizePublisherName(report.vt.signerFromVt);
            if (fromVt) report.pe.signerHint = fromVt;
          }
          if (report.pe && report.pe.isPe && report.pe.signed && report.vt && report.vt.found === true) {
            if (!report.vt.sigTrustFromVt || report.vt.sigTrustFromVt === "present") {
              if (report.vt.signerFromVt || report.pe.signerHint) {
                const a = report.pe.signerHint || "";
                const b = report.vt.signerFromVt || "";
                if (!a || !b || signerNamesLooselyMatch(a, b)) {
                  report.vt.sigTrustFromVt = "valid";
                }
              }
            }
          }
          try {
            report.signature = resolveDigitalSignature(report.pe, report.vt, []);
          } catch { /* ignore */ }

          // VT 有结论后立刻回调（门禁可据此放行，不必等上传/包内扫）
          if (meta && typeof meta.onPartial === "function") {
            try {
              meta.onPartial({
                stage: "vt",
                report: {
                  success: true,
                  url: report.url,
                  filename: report.filename,
                  kind: report.kind,
                  pe: report.pe,
                  sha256: report.sha256,
                  signature: report.signature,
                  vt: report.vt,
                  nested: [],
                  at: Date.now()
                }
              });
            } catch { /* ignore */ }
          }

          // 仅「明确库中无」才自动上传；unknown/查询失败绝不标成「无」
          const definitiveMiss = report.vt && report.vt.notFound === true
            && report.vt.verifiedNotFound === true
            && !report.vt.softMiss
            && report.vt.unknown !== true;
          const needFeed = definitiveMiss && report.vt.found !== true;
          if (needFeed) {
            report.vt.found = false;
            report.vt.notFound = true;
            if (!report.vt.summary || !/^VT:\s*无/i.test(report.vt.summary)) {
              report.vt.summary = "VT: 无";
            }
            report.vt.uploadUrl = VT_UPLOAD_PAGE;
            if (ab && ab.byteLength && ab.byteLength <= VT_UPLOAD_MAX) {
              const deferUp = !(meta && meta.deferUpload === false);
              const runUpload = async () => {
                try {
                  const feed = await NS.feedFileToVtUpload(ab, name, {
                    sha256: report.sha256,
                    forceSubmit: false
                  });
                  report.vtFeed = feed;
                  report.vtUpload = feed && feed.upload;
                  if (feed && feed.submitted) {
                    report.vt.feedSubmitted = true;
                    report.vt.submitted = true;
                    report.vt.summary = "VT: 无 → 已自动上传文件分析";
                    if (feed.guiUrl) report.vt.guiUrl = feed.guiUrl;
                    try { NS._vtByHash.delete(String(report.sha256 || "").toLowerCase()); } catch { /* ignore */ }
                  } else if (feed) {
                    if (feed.needApiKey || feed.error === "no-api-key") {
                      report.vt.summary = "VT: 无 → 需 API Key 才能自动上传";
                    } else if (feed.error === "too-large") {
                      report.vt.summary = "VT: 无 → 超过 650MB";
                    } else if (feed.autoSubmit === false) {
                      /* keep */
                    } else {
                      report.vt.summary = "VT: 无 → API 上传失败，可手动提交文件";
                    }
                  }
                  if (meta && typeof meta.onPartial === "function" && feed) {
                    try {
                      meta.onPartial({ stage: "upload", report: {
                        success: true,
                        filename: report.filename,
                        kind: report.kind,
                        pe: report.pe,
                        sha256: report.sha256,
                        signature: report.signature,
                        vt: report.vt,
                        url: report.url
                      }});
                    } catch { /* ignore */ }
                  }
                } catch (e) {
                  try { console.warn("[silverfox] vt-auto-upload", e); } catch { /* ignore */ }
                }
              };
              if (deferUp) {
                void runUpload();
              } else {
                await runUpload();
              }
            } else if (ab && ab.byteLength > VT_UPLOAD_MAX) {
              report.vt.summary = "VT: 无 → 超过 650MB，VT 不接受";
            } else {
              report.vt.summary = "VT: 无 → 可手动提交文件";
            }
          }
        }

        // 包内扫描任务已在外层 VT 查询前启动，这里汇合结果。
        if (isZipLike) {
          try {
            const nestScan = await nestedScanPromise;
            report.nested = nestScan.items || [];
            report.archiveNote = nestScan.note || "";
            report.archiveFormat = nestScan.format || "";
            if (nestScan.isApkContainer || kind === "apk") {
              report.kind = "apk";
              report.apkSigned = !!nestScan.apkSigned;
              report.pe = {
                isPe: false,
                signed: !!nestScan.apkSigned,
                signerHint: nestScan.apkSigned ? "APK 已签名（JAR/v1）" : "",
                skipped: false,
                reason: "apk"
              };
              if (!report.nested.length) report.archiveNote = "";
            } else if (report.nested.length || nestScan.format === "zip"
              || nestScan.format === "rar" || nestScan.format === "7z") {
              if (report.kind !== "pe") report.kind = "archive";
            }
            if (report.nested.length && !(meta && meta.skipNestedVt)) {
              try {
                await attachVtToNestedItems(
                  report.nested,
                  Number(meta && meta.nestedVtBudgetMs) || 25000
                );
              } catch { /* ignore */ }
            }
          } catch {
            report.nested = [];
            report.archiveNote = "";
          }
        }

        report.signature = resolveDigitalSignature(report.pe, report.vt, report.nested);
        report.success = true;
        return report;
      } catch (e) {
        report.error = e && e.message ? e.message : "inspect-fail";
        return report;
      }
    })();

    NS._peVtInflight.set(key, p);
    try {
      return await p;
    } finally {
      NS._peVtInflight.delete(key);
    }
  };

  /** @deprecated 兼容旧名 */
  NS.inspectExecutableUrl = function (url, meta) {
    return NS.inspectPackageUrl(url, meta);
  };

  function formatInspectNotice(report, context) {
    const pe = report.pe || {};
    const vt = report.vt || {};
    const kind = report.kind || "";
    const bits = [];
    if (kind && kind !== "pe") {
      const kindLabel = {
        msi: "MSI",
        archive: "压缩包",
        package: "安装包"
      }[kind] || kind;
      bits.push("类型: " + kindLabel);
    }
    const sig = report.signature || resolveDigitalSignature(pe, vt, report.nested);
    if (sig && (pe.isPe || (report.nested && report.nested.length) || sig.trust === "none")) {
      if (sig.trust === "none") bits.push("数字签名: 无");
      else if (sig.signer) bits.push("数字签名: " + sig.signer + (sig.trust === "valid" ? "（VT 有效）" : sig.trust === "invalid" ? "（无效）" : ""));
      else bits.push(sig.trust === "valid" ? "数字签名: 有（VT 有效）" : sig.trust === "invalid" ? "数字签名: 无效" : "数字签名: 有");
      if (Array.isArray(sig.items) && sig.items.length) {
        const nestBits = sig.items.slice(0, 4).map((it) => {
          if (!it.signed) return (it.name || "?") + " 无签名";
          return (it.name || "?") + (it.signer ? (" " + it.signer) : " 有签名");
        });
        bits.push("包内: " + nestBits.join("; "));
      }
    } else if (pe.error && kind === "pe") {
      bits.push("PE: 未解析");
    }
    if (vt) {
      if (vt.notFound === true && !vt.softMiss && vt.unknown !== true) {
        bits.push(/已自动上传|已自动提交|已提交文件|可手动提交|上传文件|需验证/i.test(String(vt.summary || ""))
          ? String(vt.summary)
          : "VT: 无");
      } else if (vt.unknown || vt.softMiss || vt.found == null) {
        bits.push(String(vt.summary || "VT: 查询未完成"));
      } else if (vt.found === true && vt.summary) {
        bits.push(String(vt.summary));
      } else if (vt.found === true) {
        bits.push("VT: 库中有记录");
      }
    }
    if (report.sha256) bits.push("SHA256: " + report.sha256.slice(0, 16) + "…");
    const risks = buildFileRiskLines(report, context);
    for (const r of risks) {
      if (r.level === "high" || r.level === "medium") bits.push("风险: " + r.text);
    }
    if (report.error) bits.push("错误: " + report.error);
    return bits.join(" · ").slice(0, 280);
  }

  /** 通过 VT 门禁后允许再下一次的 URL（防回路） */
  NS._vtPassUrls = NS._vtPassUrls || new Map();

  NS.consumeVtPassUrl = function (url) {
    const u = String(url || "");
    if (!u || !NS._vtPassUrls.has(u)) return false;
    const exp = NS._vtPassUrls.get(u);
    NS._vtPassUrls.delete(u);
    return Number(exp) > Date.now();
  };

  NS.grantVtPassUrl = function (url, ttlMs) {
    const u = String(url || "");
    if (!u) return;
    NS._vtPassUrls.set(u, Date.now() + Math.max(5000, ttlMs || 90000));
  };

  function resolvePageContext(tabId) {
    return (async () => {
      let pageUrl = "";
      let pageHost = "";
      try {
        if (tabId != null && NS.tabNavState && NS.tabNavState.get) {
          const st = NS.tabNavState.get(tabId);
          if (st && st.lastGoodUrl) pageUrl = String(st.lastGoodUrl || "");
        }
      } catch { /* ignore */ }
      if (!pageUrl && tabId != null && chrome.tabs && chrome.tabs.get) {
        try {
          pageUrl = await new Promise((resolve) => {
            try {
              chrome.tabs.get(tabId, (t) => { resolve((t && t.url) || ""); });
            } catch { resolve(""); }
          });
        } catch { pageUrl = ""; }
      }
      // 仅作为 VT 展示归属兜底：用户刚触发下载时，当前活动页就是最可靠的 UI 容器。
      // 此结果不参与下载可信判定或放行。
      if (!pageUrl && tabId == null && chrome.tabs && chrome.tabs.query) {
        try {
          const active = await new Promise((resolve) => {
            try {
              chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
                const t = Array.isArray(tabs) ? tabs.find((x) => x && /^https?:/i.test(x.url || "")) : null;
                resolve(t || null);
              });
            } catch { resolve(null); }
          });
          if (active) {
            tabId = active.id != null ? active.id : null;
            pageUrl = String(active.url || "");
          }
        } catch { /* ignore */ }
      }
      try {
        pageHost = new URL(pageUrl || "").hostname.toLowerCase().replace(/^www\./, "");
      } catch { pageHost = ""; }
      return { tabId, pageUrl, pageHost };
    })();
  }

  // 内存态 + 序号，避免 storage.get/set 竞态把 done 又盖回 checking
  NS._latestExeVtMem = NS._latestExeVtMem || null;
  NS._latestExeVtSeq = NS._latestExeVtSeq || 0;

  function vtWriteRank(status, stage) {
    const s = String(status || "");
    if (s === "blocked" || s === "flagged") return 100;
    if (s === "allowed" || s === "done" || s === "error") return 90;
    if (s === "uploading") return 40;
    if (s === "checking") {
      if (stage === "vt" || stage === "upload") return 30;
      if (stage === "local") return 20;
      return 10;
    }
    return 0;
  }

  function writeLatestExeVt(payload) {
    try {
      const nextStatus = payload.status || "done";
      const nextUrl = String(payload.url || "").slice(0, 400);
      const stage = String(payload.stage || "");
      const nextRank = vtWriteRank(nextStatus, stage);
      const allowRankDowngrade = payload.allowRankDowngrade === true;
      const seq = ++NS._latestExeVtSeq;
      const prev = NS._latestExeVtMem;

      // 同 URL：禁止用更低阶段/checking 覆盖已完成
      if (prev && prev.url && nextUrl && prev.url === nextUrl) {
        const prevRank = Number(prev._rank) || 0;
        if (nextRank < prevRank && !allowRankDowngrade) return;
        // 已 done/allowed/blocked 后，忽略迟到的 checking 局部写
        if (/^(done|allowed|blocked|flagged|error)$/i.test(String(prev.status || ""))
          && /^(checking|uploading)$/i.test(nextStatus)) {
          return;
        }
      }
      // 不同 URL：若当前检测中且未超时，不让别的文件半成品冲掉
      if (prev && prev.url && nextUrl && prev.url !== nextUrl) {
        if (/^(checking|uploading)$/i.test(String(prev.status || ""))
          && (Date.now() - (Number(prev.timestamp) || 0) < 120000)
          && nextRank < 90) {
          return;
        }
      }

      const entry = {
        title: payload.title || "安装包/压缩包检测",
        status: nextStatus,
        stage: stage || "",
        message: payload.message || "",
        filename: payload.filename || "",
        kind: payload.kind || "",
        url: nextUrl,
        pageUrl: (payload.pageUrl || "").slice(0, 500),
        pageHost: payload.pageHost || "",
        sha256: payload.sha256 || "",
        peSigned: !!payload.peSigned,
        peSigner: payload.peSigner || "",
        peSigTrust: payload.peSigTrust || "",
        trustedSource: !!payload.trustedSource,
        pe: payload.pe || null,
        nested: Array.isArray(payload.nested) ? payload.nested : [],
        archiveNote: payload.archiveNote || "",
        archiveFormat: payload.archiveFormat || "",
        signature: payload.signature || null,
        risks: Array.isArray(payload.risks) ? payload.risks : [],
        vt: payload.vt || null,
        guiUrl: payload.guiUrl || "",
        tabId: payload.tabId != null ? payload.tabId : null,
        downloadId: Number.isInteger(payload.downloadId) ? payload.downloadId : null,
        releasedDownloadId: Number.isInteger(payload.releasedDownloadId) ? payload.releasedDownloadId : null,
        gated: !!payload.gated,
        allowed: payload.allowed,
        timestamp: Date.now(),
        success: payload.success !== false,
        _rank: nextRank,
        _seq: seq
      };
      NS._latestExeVtMem = entry;
      const toStore = Object.assign({}, entry);
      delete toStore._rank;
      delete toStore._seq;
      const storagePayload = { latestExeVt: toStore };
      if (entry.tabId != null) storagePayload[`latestExeVt_${entry.tabId}`] = toStore;
      chrome.storage.local.set(storagePayload, () => {
        void chrome.runtime.lastError;
      });
      return toStore;
    } catch { return null; }
  }

  /**
   * Cancel the download task and remove the file already written to disk.
   * Chromium can briefly keep the file busy after cancel, so retry removal.
   */
  async function deleteDownloadFileById(downloadId) {
    if (!Number.isInteger(downloadId) || downloadId < 0
      || !chrome.downloads || typeof chrome.downloads.removeFile !== "function") {
      return false;
    }

    if (typeof chrome.downloads.cancel === "function") {
      await new Promise((resolve) => {
        try {
          chrome.downloads.cancel(downloadId, () => {
            void chrome.runtime.lastError;
            resolve();
          });
        } catch { resolve(); }
      });
    }

    for (let attempt = 0; attempt < 4; attempt += 1) {
      const removed = await new Promise((resolve) => {
        try {
          chrome.downloads.removeFile(downloadId, () => {
            const failed = !!chrome.runtime.lastError;
            resolve(!failed);
          });
        } catch { resolve(false); }
      });
      if (removed) return true;

      const alreadyGone = await new Promise((resolve) => {
        if (typeof chrome.downloads.search !== "function") {
          resolve(false);
          return;
        }
        try {
          chrome.downloads.search({ id: downloadId }, (items) => {
            void chrome.runtime.lastError;
            const found = Array.isArray(items) ? items[0] : null;
            resolve(!!found && found.exists === false);
          });
        } catch { resolve(false); }
      });
      if (alreadyGone) return true;
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    }
    return false;
  }

  /**
   * Popup 读到旧的“只有汇总”结果时，强制重查一次并把引擎明细写回原记录。
   * 这会绕过 6 小时 VT 缓存，避免新明细解析逻辑永远没有执行机会。
   */
  NS.refreshStoredVirusTotalDetails = async function (sha256, tabId) {
    const hash = String(sha256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");
    if (hash.length !== 64) return { success: false, error: "bad-hash" };
    try { NS._vtByHash.delete(hash); } catch { /* ignore */ }
    const vt = await NS.lookupVirusTotalHash(hash);
    if (!vt || vt.found !== true) return { success: false, vt: vt || null };

    const tabKey = Number.isInteger(tabId) && tabId >= 0 ? `latestExeVt_${tabId}` : "";
    const stored = await new Promise((resolve) => {
      const keys = tabKey ? [tabKey, "latestExeVt"] : ["latestExeVt"];
      try { chrome.storage.local.get(keys, (value) => resolve(value || {})); }
      catch { resolve({}); }
    });
    const current = (tabKey && stored[tabKey]) || stored.latestExeVt || NS._latestExeVtMem || null;
    if (!current || String(current.sha256 || "").toLowerCase() !== hash) {
      return { success: true, vt, updated: false };
    }

    const consensus = vtShouldHardBlock({ vt }, {});
    const oldPolicyVtFlag = Number(current.vt && current.vt.trustedPolicyVersion) !== VT_TRUST_POLICY_VERSION
      && /^(?:blocked|flagged)$/i.test(String(current.status || ""))
      && /\bVT\b|VirusTotal/i.test(String(current.title || ""));
    const removableDownloadId = Number.isInteger(current.releasedDownloadId)
      ? current.releasedDownloadId
      : (!current.gated && Number.isInteger(current.downloadId) ? current.downloadId : null);
    let fileDeleted = false;
    if (consensus.block && Number.isInteger(removableDownloadId)) {
      fileDeleted = await deleteDownloadFileById(removableDownloadId);
    }
    const status = consensus.block ? "flagged"
      : (oldPolicyVtFlag ? (current.gated ? "allowed" : "done") : String(current.status || "done"));
    const title = consensus.block
      ? (fileDeleted ? "VT 三家知名引擎检出，文件已删除"
        : (current.gated ? "VT 知名引擎检出，已拦截下载" : "VT 三家知名引擎检出可疑文件"))
      : (oldPolicyVtFlag ? "检测完成" : current.title);
    const updated = writeLatestExeVt({
      ...current,
      stage: "vt",
      status,
      title,
      vt,
      guiUrl: vt.guiUrl || current.guiUrl || (VT_GUI_BASE + hash),
      tabId: Number.isInteger(tabId) && tabId >= 0 ? tabId : current.tabId,
      allowed: consensus.block ? false : (oldPolicyVtFlag ? true : current.allowed),
      allowRankDowngrade: oldPolicyVtFlag && !consensus.block,
      success: true
    });
    const previouslyBlockedByVt = vtShouldHardBlock({ vt: current.vt || null }, {}).reason === "vt-trusted-consensus";
    if (consensus.block && !previouslyBlockedByVt && Number.isInteger(tabId) && tabId >= 0) {
      try {
        chrome.tabs.sendMessage(tabId, {
          type: "show-page-threat-toast",
          title: "VT 检出可疑安装包",
          message: String(current.filename || "知名安全引擎检出该文件").slice(0, 240),
          force: true
        }, { frameId: 0 }, () => { void chrome.runtime.lastError; });
      } catch { /* ignore */ }
    }
    try {
      chrome.runtime.sendMessage({
        type: "exe-vt-result",
        tabId: updated && updated.tabId,
        vtInfo: updated || { ...current, vt }
      }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
    return { success: true, vt, updated: !!updated };
  };

  NS.refreshStoredNestedSignatures = async function (sha256, tabId) {
    const parentHash = String(sha256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");
    const tabKey = Number.isInteger(tabId) && tabId >= 0 ? `latestExeVt_${tabId}` : "";
    const stored = await new Promise((resolve) => {
      const keys = tabKey ? [tabKey, "latestExeVt"] : ["latestExeVt"];
      try { chrome.storage.local.get(keys, (value) => resolve(value || {})); }
      catch { resolve({}); }
    });
    const current = (tabKey && stored[tabKey]) || stored.latestExeVt || NS._latestExeVtMem || null;
    if (!current || (parentHash && String(current.sha256 || "").toLowerCase() !== parentHash)) {
      return { success: false, error: "stale-report" };
    }
    const nested = Array.isArray(current.nested)
      ? current.nested.map((item) => ({ ...item, vt: item && item.vt ? { ...item.vt } : null }))
      : [];
    const pending = nested.filter((item) => item && item.signed
      && /^(?:present)?$/i.test(String(item.sigTrust || item.trust || "present"))
      && /^[a-f0-9]{64}$/i.test(String(item.sha256 || "")));
    if (!pending.length) return { success: true, updated: false };

    await attachVtToNestedItems(nested, 30000);
    const signature = resolveDigitalSignature(current.pe || null, current.vt || null, nested);
    const updated = writeLatestExeVt({
      ...current,
      nested,
      signature,
      peSigTrust: signature && signature.trust ? signature.trust : current.peSigTrust,
      tabId: Number.isInteger(tabId) && tabId >= 0 ? tabId : current.tabId,
      success: true
    });
    try {
      chrome.runtime.sendMessage({
        type: "exe-vt-result",
        tabId: updated && updated.tabId,
        vtInfo: updated || { ...current, nested, signature }
      }, () => { void chrome.runtime.lastError; });
    } catch { /* ignore */ }
    return { success: true, updated: !!updated };
  };

  /**
   * VT 是否「拦死」：指定知名引擎恶意/可疑检出合计至少三家，或保护态未签名 PE。
   * VT 查不到 / 失败：不拦死（避免正常站全挂），但 popup 会显示状态。
   */
  function vtShouldHardBlock(report, opts) {
    const vt = report && report.vt;
    const trustedMalicious = vt ? (Number(vt.trustedMaliciousCount) || 0) : 0;
    const trustedSuspicious = vt ? (Number(vt.trustedSuspiciousCount) || 0) : 0;
    const trustedCount = trustedMalicious + trustedSuspicious;
    const trustedConsensus = trustedCount >= 3;
    if (vt && vt.engineDetailsAvailable === true && trustedConsensus) {
      return { block: true, reason: "vt-trusted-consensus", trustedCount };
    }
    const pe = report && report.pe;
    if (opts && opts.requireSignedPe && pe && pe.isPe && !pe.signed) {
      return { block: true, reason: "unsigned-pe" };
    }
    return { block: false, reason: "" };
  }

  /**
   * 下载项：可选「先拦 → 分析 → 再放行」门禁。
   * opts.gate === true：先 cancel 用户下载；扩展另拉一份做 PE/哈希/VT；
   *   未硬拦时再 chrome.downloads.download 下一次（=「放行再下一次」，不是放行磁盘上已下完的文件）。
   * gate=false：用户下载不中断，后台另拉分析仅展示。
   */
  NS.probeDownloadExecutableAsync = function (item, opts) {
    try {
      if (!item || !looksLikePackageItem(item)) return;
      const url = item.finalUrl || item.url || "";
      if (!url || !/^https?:\/\//i.test(url)) return;
      if (/^(blob:|file:|filesystem:)/i.test(url)) return;
      // Edge 的 DownloadItem 常缺 tabId；复用下载来源/精确 URL 关联，否则 popup 会因
      // tabId/pageUrl 为空而过滤掉 VT 结果，最终只剩系统通知。
      let tabId = Number.isInteger(opts && opts.sourceTabId) && opts.sourceTabId >= 0
        ? opts.sourceTabId
        : (typeof NS.resolveDownloadSourceTabId === "function"
          ? NS.resolveDownloadSourceTabId(item)
          : (item.tabId ?? null));
      const filename = basenameFromUrlOrName(url, item.filename);
      const gate = !!(opts && opts.gate);
      const downloadId = item.id;
      let released = false;
      let pageUrl = "";
      let pageHost = "";
      let pageVtToastShown = false;
      let downloadDeletePromise = null;
      let releasedDownloadId = null;

      const rememberReleasedDownloadId = (newDownloadId) => {
        if (!Number.isInteger(newDownloadId)) return;
        releasedDownloadId = newDownloadId;
        if (NS._latestExeVtMem && NS._latestExeVtMem.url === url) {
          NS._latestExeVtMem.releasedDownloadId = newDownloadId;
        }
        const keys = ["latestExeVt"];
        if (Number.isInteger(tabId) && tabId >= 0) keys.push(`latestExeVt_${tabId}`);
        try {
          chrome.storage.local.get(keys, (stored) => {
            const updates = {};
            for (const key of keys) {
              const entry = stored && stored[key];
              if (entry && entry.url === url) {
                updates[key] = { ...entry, releasedDownloadId: newDownloadId };
              }
            }
            if (Object.keys(updates).length) {
              chrome.storage.local.set(updates, () => { void chrome.runtime.lastError; });
            }
          });
        } catch { /* ignore */ }
      };

      const deleteVtDetectedDownload = () => {
        if (gate || !Number.isInteger(downloadId)) return Promise.resolve(false);
        if (!downloadDeletePromise) {
          downloadDeletePromise = deleteDownloadFileById(downloadId);
        }
        return downloadDeletePromise;
      };

      const showPageVtToast = (title, message) => {
        if (pageVtToastShown || tabId == null || !chrome.tabs || !chrome.tabs.sendMessage) return;
        pageVtToastShown = true;
        try {
          chrome.tabs.sendMessage(tabId, {
            type: "show-page-threat-toast",
            title: String(title || "VT 检出可疑安装包").slice(0, 120),
            message: String(message || filename || "知名安全引擎检出该文件").slice(0, 240),
            force: true
          }, { frameId: 0 }, () => { void chrome.runtime.lastError; });
        } catch { /* ignore */ }
      };

      const releaseDownload = () => {
        if (!gate || released) return;
        released = true;
        try {
          NS.grantVtPassUrl(url, 120000);
          if (chrome.downloads && chrome.downloads.download) {
            chrome.downloads.download({
              url,
              filename: filename || undefined,
              conflictAction: "uniquify",
              saveAs: false
            }, (newDownloadId) => {
              void chrome.runtime.lastError;
              rememberReleasedDownloadId(newDownloadId);
            });
          }
        } catch { /* ignore */ }
      };

      const writePartial = (stage, pr) => {
        try {
          pr = pr || {};
          const pe = pr.pe || null;
          const sig = pr.signature || null;
          const vt = pr.vt || null;
          const peSigner = sanitizePublisherName(
            (sig && sig.signer) || (pe && pe.signerHint) || (vt && vt.signerFromVt) || ""
          );
          // VT 阶段：直接写成完成态，避免卡在「正在解析/查询中」
          if (stage === "vt") {
            const hardEarly = vtShouldHardBlock(pr, {
              requireSignedPe: !!(opts && opts.requireSignedPe)
            });
            let st = "done";
            let title = "检测完成";
            let allowed = true;
            if (gate) {
              if (hardEarly.block) {
                st = "blocked";
                allowed = false;
                title = hardEarly.reason === "unsigned-pe"
                  ? "已拦截未签名安装包"
                  : "VT 检出，已拦截下载";
              } else {
                st = "allowed";
                title = "未达拦截阈值，已放行下载";
                releaseDownload();
              }
            } else if (hardEarly.block) {
              st = "flagged";
              allowed = false;
              title = "VT 检出可疑安装包";
              if (hardEarly.reason === "vt-trusted-consensus") {
                void deleteVtDetectedDownload();
              } else {
                try {
                  if (downloadId != null && chrome.downloads && chrome.downloads.cancel) {
                    chrome.downloads.cancel(downloadId, () => { void chrome.runtime.lastError; });
                  }
                } catch { /* ignore */ }
              }
            }
            if (hardEarly.block && hardEarly.reason === "vt-trusted-consensus") {
              showPageVtToast(title, filename);
            }
            const guiUrl = (vt && vt.guiUrl)
              || (pr.sha256 ? (VT_GUI_BASE + pr.sha256) : "")
              || VT_UPLOAD_PAGE;
            writeLatestExeVt({
              stage: "vt",
              status: st,
              title,
              message: formatInspectNotice(pr, opts) || filename,
              filename,
              kind: pr.kind || "",
              url,
              pageUrl,
              pageHost,
              sha256: pr.sha256 || "",
              peSigned: !!(pe && pe.signed) || !!(sig && sig.trust && sig.trust !== "none"),
              peSigner,
              peSigTrust: (sig && sig.trust) || (vt && vt.sigTrustFromVt) || "",
              pe,
              signature: sig,
              nested: Array.isArray(pr.nested) ? pr.nested : [],
              vt,
              guiUrl,
              tabId,
              downloadId,
              releasedDownloadId,
              trustedSource: !!(opts && opts.trustedSource),
              gated: gate,
              allowed,
              success: true
            });
            return;
          }
          writeLatestExeVt({
            stage: stage || "local",
            status: "checking",
            title: gate ? "正在解析文件（下载已暂扣）" : "正在解析文件…",
            message: `本地解析完成 ${filename}，正在查 VT…`,
            filename,
            kind: pr.kind || "",
            url,
            pageUrl,
            pageHost,
            sha256: pr.sha256 || "",
            peSigned: !!(pe && pe.signed) || !!(sig && sig.trust && sig.trust !== "none"),
            peSigner,
            peSigTrust: (sig && sig.trust) || "",
            pe,
            signature: sig,
            nested: Array.isArray(pr.nested) ? pr.nested : [],
            vt: null,
            guiUrl: pr.sha256 ? (VT_GUI_BASE + pr.sha256) : "",
            tabId,
            downloadId,
            releasedDownloadId,
            trustedSource: !!(opts && opts.trustedSource),
            gated: gate,
            allowed: false,
            success: true
          });
        } catch { /* ignore */ }
      };

      void (async () => {
        try {
          const ctx = await resolvePageContext(tabId);
          if (tabId == null && ctx.tabId != null) tabId = ctx.tabId;
          pageUrl = ctx.pageUrl || "";
          pageHost = ctx.pageHost || "";

          writeLatestExeVt({
            status: "checking",
            title: gate ? "正在检测（下载已暂扣）" : "正在检测",
            message: gate
              ? `已暂扣下载，正在拉取并解析 ${filename}…`
              : `正在解析 ${filename}…`,
            filename,
            url,
            pageUrl,
            pageHost,
            tabId,
            downloadId,
            releasedDownloadId,
            trustedSource: !!(opts && opts.trustedSource),
            gated: gate,
            allowed: false,
            success: true
          });

          const report = await raceMs(
            NS.inspectPackageUrl(url, {
              filename,
              deferUpload: true,
              skipNestedVt: false,
              nestedVtBudgetMs: gate ? 30000 : 25000,
              onPartial: (p) => {
                if (!p || !p.report) return;
                writePartial(p.stage || "local", p.report);
              }
            }),
            90000,
            null
          );
          if (!report) {
            writeLatestExeVt({
              status: "error",
              title: "检测超时",
              message: "检测超时，请配置 API Key 后重试",
              filename,
              url,
              pageUrl,
              pageHost,
              tabId,
              downloadId,
              releasedDownloadId,
              gated: gate,
              allowed: !gate,
              success: false
            });
            if (gate) releaseDownload();
            return;
          }
          const message = formatInspectNotice(report, opts);
          const guiUrl = (report.vt && report.vt.guiUrl)
            || ((report.vt && report.vt.found === true && report.sha256)
              ? (VT_GUI_BASE + report.sha256)
              : (report.vt && report.vt.uploadUrl) || VT_UPLOAD_PAGE);
          const hard = vtShouldHardBlock(report, {
            requireSignedPe: !!(opts && opts.requireSignedPe)
          });

          const vtObj = report.vt || null;
          const vtDefinitive = !!(vtObj && (vtObj.found === true || vtObj.notFound === true));
          const vtUploaded = !!(vtObj && (vtObj.feedSubmitted || vtObj.submitted));

          let allowed = true;
          let status = "done";
          let title = "安装包/压缩包检测";
          let finalMsg = message;
          if (!vtDefinitive && !vtUploaded && report.sha256) {
            title = "文件解析完成（VT 自动取数受限）";
            if (!finalMsg || !/VT/i.test(finalMsg)) {
              finalMsg = (finalMsg ? finalMsg + " · " : "") + "VT 自动取数未完成，请点开链接查看";
            }
          }

          if (gate) {
            if (hard.block) {
              allowed = false;
              status = "blocked";
              title = hard.reason === "unsigned-pe"
                ? "已拦截未签名安装包"
                : "VT 检出，已拦截下载";
              finalMsg = message || filename;
            } else {
              // 未硬拦：放行 = 再触发一次浏览器下载（分析前已 cancel）
              allowed = true;
              status = "allowed";
              const vtClean = vtObj && vtObj.found === true
                && (Number(vtObj.malicious) || 0) < 3
                && (Number(vtObj.suspicious) || 0) < 5;
              title = vtClean ? "未发现高危，已放行下载" : "未达拦截阈值，已放行下载";
              finalMsg = message || "未发现高危检出";
              if (!released) {
                finalMsg += " · 正在开始下载…";
                releaseDownload();
              }
            }
          } else if (hard.block) {
            // 非门禁：用户下载本就在进行，高危时才尝试 cancel
            allowed = false;
            status = "flagged";
            title = "VT 检出可疑安装包";
            if (hard.reason === "vt-trusted-consensus") {
              void deleteVtDetectedDownload();
            } else {
              try {
                if (downloadId != null && chrome.downloads && chrome.downloads.cancel) {
                  chrome.downloads.cancel(downloadId, () => { void chrome.runtime.lastError; });
                }
              } catch { /* ignore */ }
            }
          }

          if (hard.block && hard.reason === "vt-trusted-consensus") {
            showPageVtToast(title, filename);
          }

          // 数字签名：本地叶子证书 + VT signature_info 真伪 + 包内成员
          if (!report.signature) {
            report.signature = resolveDigitalSignature(report.pe, report.vt, report.nested);
          }
          const peSigner = sanitizePublisherName(
            (report.signature && report.signature.signer)
            || (report.pe && report.pe.signerHint)
            || (report.vt && report.vt.signerFromVt)
            || ""
          );
          if (report.pe && report.pe.signed && peSigner) {
            report.pe.signerHint = peSigner;
          }
          const riskLines = buildFileRiskLines(report, opts);
          const finalVtEntry = writeLatestExeVt({
            stage: "final",
            status,
            title,
            message: finalMsg,
            filename,
            kind: report.kind || "",
            url,
            pageUrl,
            pageHost,
            sha256: report.sha256 || "",
            peSigned: !!(report.pe && report.pe.signed) || !!(report.signature && report.signature.trust !== "none" && report.signature.trust),
            peSigner,
            peSigTrust: (report.signature && report.signature.trust) || "",
            pe: report.pe || null,
            nested: Array.isArray(report.nested) ? report.nested.map((n) => ({
              name: n.name,
              path: n.path,
              kind: n.kind,
              signed: !!n.signed,
              signerHint: n.signerHint || "",
              sigTrust: n.sigTrust || "",
              note: n.note || "",
              sha256: n.sha256 || "",
              vt: n.vt || null
            })) : [],
            archiveNote: report.archiveNote || "",
            archiveFormat: report.archiveFormat || "",
            signature: report.signature || null,
            risks: riskLines,
            vt: report.vt || null,
            guiUrl,
            tabId,
            downloadId,
            releasedDownloadId,
            trustedSource: !!(opts && opts.trustedSource),
            gated: gate,
            allowed,
            success: !!report.success
          });

          // popup 读取完整报告；高危 VT 共识同时由上面的 showPageVtToast 发到来源页右上角。
          try {
            chrome.runtime.sendMessage({
              type: "exe-vt-result",
              tabId,
              pageUrl,
              vtInfo: finalVtEntry,
              report: {
                tabId,
                pageUrl,
                filename,
                kind: report.kind,
                sha256: report.sha256,
                pe: report.pe,
                nested: report.nested,
                signature: report.signature,
                vt: report.vt,
                risks: riskLines,
                message: finalMsg,
                guiUrl,
                status,
                allowed
              }
            }, () => { void chrome.runtime.lastError; });
          } catch { /* ignore */ }

          if ((!allowed || hard.block) && typeof NS.showBlockedNotification === "function") {
            try {
              await NS.showBlockedNotification(title, finalMsg || filename, tabId);
            } catch { /* ignore */ }
          }

          // 拦截说明写入 latestNotice，popup 顶部也能看到
          if (gate && !allowed) {
            try {
              chrome.storage.local.set({
                latestNotice: {
                  title,
                  message: finalMsg || filename,
                  tabId,
                  url: pageUrl || url,
                  timestamp: Date.now()
                }
              });
            } catch { /* ignore */ }
          }

          try {
            console.log("[silverfox] package-vt", status, report.kind, filename, finalMsg, guiUrl);
          } catch { /* ignore */ }
        } catch (e) {
          try {
            writeLatestExeVt({
              status: "error",
              title: "VT 检测失败",
              message: e && e.message ? e.message : "inspect-fail",
              filename,
              url,
              tabId,
              downloadId,
              releasedDownloadId,
              gated: gate,
              allowed: !gate,
              success: false
            });
          } catch { /* ignore */ }
          try { console.warn("[silverfox] package-vt fail", e); } catch { /* ignore */ }
        }
      })();
    } catch { /* ignore */ }
  };
})(self.SilverfoxBackground ??= {});
