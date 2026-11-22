importScripts("../vendor/sevenzip-wasm/sevenzip-wasm.js");

const DB_NAME = "silverfox_archive_tasks_v1";
const DB_VERSION = 1;
const STORE_NAME = "tasks";
const EXECUTABLE_RE = /\.(?:exe|dll|sys|scr|ocx|cpl|msi|msp|efi|drv|apk)$/i;
const FALLBACK_MAGIC_MAX = 4 * 1024 * 1024;

function openTaskDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("archive-db-open-failed"));
  });
}

async function getTask(id) {
  const db = await openTaskDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(id);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error || new Error("archive-task-read-failed"));
    });
  } finally {
    db.close();
  }
}

/** 仅当后台任务仍存在时写回，超时清理后不会被 Worker 重新创建。 */
async function finishTask(id, result) {
  const db = await openTaskDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(id);
      request.onsuccess = () => {
        const current = request.result;
        if (current) {
          current.input = null;
          current.result = result;
          current.finishedAt = Date.now();
          store.put(current);
        }
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error("archive-task-write-failed"));
      tx.onabort = () => reject(tx.error || new Error("archive-task-write-aborted"));
    });
  } finally {
    db.close();
  }
}

function basename(path) {
  const normalized = String(path || "").replace(/\\/g, "/");
  return normalized.split("/").filter(Boolean).pop() || "file.bin";
}

function safeArchivePath(path) {
  const clean = String(path || "").replace(/\\/g, "/")
    .split("/")
    .filter((part) => part && part !== "." && part !== "..")
    .join("/");
  return clean.slice(0, 1024);
}

function safeFsPath(path) {
  const normalized = safeArchivePath(path);
  if (!normalized || normalized.startsWith("-") || /[\0\r\n]/.test(normalized)) return "";
  return normalized;
}

function parseTechnicalList(lines) {
  const entries = [];
  let current = null;
  for (const rawLine of lines || []) {
    const line = String(rawLine || "").trim();
    if (!line) {
      if (current && current.path) entries.push(current);
      current = null;
      continue;
    }
    const match = line.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    const value = match[2].trim();
    if (key === "path") {
      if (current && current.path) entries.push(current);
      current = { path: value, size: 0, encrypted: false, directory: false };
      continue;
    }
    if (!current) continue;
    if (key === "size") current.size = Number(value);
    else if (key === "encrypted") current.encrypted = value === "+";
    else if (key === "attributes") current.directory = /\bD\b|^D/i.test(value);
  }
  if (current && current.path) entries.push(current);
  return entries;
}

function hasEncryptionDiagnostic(output) {
  // A filename such as password.exe is not proof of encryption.
  return String(output || "").split(/\r?\n/).some((line) =>
    !/^\s*(?:Path|Name)\s*=/i.test(line) && (
      /(?:enter|incorrect|wrong|requires?|need|missing)\s+(?:a\s+|the\s+)?(?:password|passphrase)\b/i.test(line)
      || /^\s*Encrypted\s*=\s*\+\s*$/i.test(line)
      || /^\s*Method\s*=.*(?:AES|7zAES)\b/i.test(line)
      || /(?:cannot|can not).*encrypted archive|data error in encrypted file|encrypted headers/i.test(line)));
}

// RAR5 archive encryption header, validated with its CRC32 before trusting its type.
// Format reference: https://www.rarlab.com/technote.htm#enchead
function hasRar5EncryptedHeader(input) {
  const bytes = new Uint8Array(input);
  const signature = [0x52, 0x61, 0x72, 0x21, 0x1a, 7, 1, 0];
  if (bytes.length < 15 || !signature.every((b, i) => bytes[i] === b)) return false;
  let pos = 12;
  const readVint = (end) => {
    let value = 0, factor = 1;
    for (let count = 0; count < 8 && pos < end; count++, factor *= 128) {
      const byte = bytes[pos++]; value += (byte & 127) * factor;
      if (!Number.isSafeInteger(value)) return null;
      if (!(byte & 128)) return value;
    }
    return null;
  };
  const size = readVint(Math.min(bytes.length, 15));
  if (size == null || size < 21 || size > 128 || pos + size > bytes.length) return false;
  const end = pos + size;
  if (readVint(end) !== 4) return false;
  let crc = 0xffffffff;
  for (let i = 12; i < end; i++) {
    crc ^= bytes[i];
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return ((crc ^ 0xffffffff) >>> 0) === new DataView(input).getUint32(8, true);
}

function classifyFailure(result, output) {
  if (result.encrypted === true || hasEncryptionDiagnostic(output)) {
    result.status = "encrypted";
    result.encrypted = true;
    result.note = `${result.format.toUpperCase()} 已加密，需要密码，未进行包内文件与数字签名扫描`;
  } else {
    result.status = "error";
    result.note = /missing volume|cannot find.*(?:volume|\.part\d+)|unexpected end of (?:archive|data)/i.test(String(output || ""))
      ? "压缩包数据不完整或缺少分卷，无法拆包验签"
      : "无法拆包验签，原因尚未确认（可能需要密码、格式不受支持、文件损坏或缺少分卷）";
  }
  return result;
}

function fsReadFile(sevenZip, path) {
  try {
    const bytes = sevenZip.FS.readFile(path);
    return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  } catch {
    return null;
  }
}

async function processTask(task) {
  const limits = task.limits || {};
  const maxEntries = Math.max(1, Number(limits.maxEntries) || 4096);
  const maxCandidates = Math.max(1, Number(limits.maxCandidates) || 16);
  const maxFileBytes = Math.max(64, Number(limits.maxFileBytes) || 48 * 1024 * 1024);
  const maxTotalBytes = Math.max(maxFileBytes, Number(limits.maxTotalBytes) || 96 * 1024 * 1024);
  const format = task.format === "rar" ? "rar" : "7z";
  const result = {
    status: "ok",
    format,
    encrypted: null,
    entriesTotal: 0,
    candidatesTotal: 0,
    skippedTooLarge: 0,
    truncatedEntries: false,
    extracted: [],
    note: ""
  };
  if (!(task.input instanceof ArrayBuffer) || task.input.byteLength < 8) {
    result.status = "error";
    result.note = "压缩包数据为空或不完整";
    return result;
  }
  if (format === "rar" && hasRar5EncryptedHeader(task.input)) {
    result.encrypted = true;
    return classifyFailure(result, "");
  }

  const stdout = [];
  const stderr = [];
  const pendingOutput = { out: [], err: [] };
  const decodeOutput = (bytes) => new TextDecoder("utf-8").decode(new Uint8Array(bytes));
  const captureByte = (key, lines, byte) => {
    if (byte == null || byte === 10) {
      if (pendingOutput[key].length) lines.push(decodeOutput(pendingOutput[key]));
      pendingOutput[key] = [];
    } else if (byte !== 13) pendingOutput[key].push(byte);
  };
  const diagnosticText = (error = "") => [...stdout, decodeOutput(pendingOutput.out), ...stderr, decodeOutput(pendingOutput.err), error].join("\n");
  let sevenZip = null;
  try {
    sevenZip = await SevenZipWasm({
      locateFile: (name) => new URL(`../vendor/sevenzip-wasm/${name}`, self.location.href).href,
      print: (line) => stdout.push(String(line || "")),
      printErr: (line) => stderr.push(String(line || "")),
      // Password prompts may not end in a newline before WASM aborts on stdin.
      stdout: (byte) => captureByte("out", stdout, byte),
      stderr: (byte) => captureByte("err", stderr, byte),
      stdin: () => null
    });
    const archiveName = `/input.${format}`;
    sevenZip.FS.writeFile(archiveName, new Uint8Array(task.input));
    const listCode = sevenZip.callMain(["l", "-slt", "-ba", "-bd", "-bsp0", archiveName]);
    const diagnostic = diagnosticText();
    const listed = parseTechnicalList(stdout);
    result.encrypted = listed.some((entry) => entry.encrypted);
    if (listCode !== 0) {
      return classifyFailure(result, diagnostic);
    }
    result.entriesTotal = listed.length;
    result.encrypted = listed.some((entry) => entry.encrypted);
    if (result.encrypted || hasEncryptionDiagnostic(diagnostic)) {
      return classifyFailure(result, diagnostic);
    }

    result.truncatedEntries = listed.length > maxEntries;
    const candidates = [];
    for (const entry of listed.slice(0, maxEntries)) {
      if (!entry || entry.directory) continue;
      const path = safeFsPath(entry.path);
      const size = Number(entry.size);
      if (!path || !Number.isFinite(size) || size < 64) continue;
      const byExt = EXECUTABLE_RE.test(path);
      if (size > maxFileBytes) {
        if (byExt) result.skippedTooLarge++;
        continue;
      }
      if (!byExt && size > FALLBACK_MAGIC_MAX) continue;
      candidates.push({ path, name: basename(path), size, byExt });
    }
    candidates.sort((a, b) => {
      if (a.byExt !== b.byExt) return a.byExt ? -1 : 1;
      const depthA = (a.path.match(/\//g) || []).length;
      const depthB = (b.path.match(/\//g) || []).length;
      return depthA - depthB || a.size - b.size;
    });
    result.candidatesTotal = candidates.length;

    const selected = [];
    let advertisedTotal = 0;
    for (const candidate of candidates.slice(0, maxCandidates)) {
      if (advertisedTotal + candidate.size > maxTotalBytes) break;
      advertisedTotal += candidate.size;
      selected.push(candidate);
    }
    if (selected.length) {
      sevenZip.FS.mkdir("/out");
      stdout.length = 0;
      stderr.length = 0;
      pendingOutput.out = []; pendingOutput.err = [];
      const extractCode = sevenZip.callMain([
        "x", "-y", "-spd", "-bd", "-bsp0", "-bso1", "-bse1",
        archiveName, "-o/out", "--", ...selected.map((entry) => entry.path)
      ]);
      if (extractCode !== 0) {
        return classifyFailure(result, diagnosticText());
      }
      let actualTotal = 0;
      for (const candidate of selected) {
        const bytes = fsReadFile(sevenZip, `/out/${candidate.path}`);
        if (!bytes || bytes.byteLength < 64 || bytes.byteLength > maxFileBytes) continue;
        if (actualTotal + bytes.byteLength > maxTotalBytes) break;
        actualTotal += bytes.byteLength;
        result.extracted.push({
          name: candidate.name,
          path: candidate.path,
          size: bytes.byteLength,
          byExt: candidate.byExt,
          buffer: bytes.slice().buffer
        });
      }
    }

    const limitations = [];
    if (result.truncatedEntries) limitations.push(`条目超过 ${maxEntries} 项，仅检查前 ${maxEntries} 项`);
    if (candidates.length > maxCandidates) limitations.push(`候选超过 ${maxCandidates} 个，仅按优先级检查前 ${maxCandidates} 个`);
    if (result.skippedTooLarge) limitations.push(`${result.skippedTooLarge} 个目标文件超过单文件安全上限`);
    result.note = limitations.join("；");
    return result;
  } catch (error) {
    return classifyFailure(result, diagnosticText(error && error.message || error || ""));
  } finally {
    if (sevenZip && sevenZip.FS) {
      try { sevenZip.FS.unlink(`/input.${format}`); } catch { /* module is about to be discarded */ }
    }
  }
}

self.addEventListener("message", (event) => {
  const taskId = String(event && event.data && event.data.taskId || "");
  (async () => {
    const task = await getTask(taskId);
    if (!task) return { ok: false, error: "archive-task-missing" };
    const result = await processTask(task);
    await finishTask(taskId, result);
    return {
      ok: true,
      status: result.status,
      extracted: result.extracted.length,
      entriesTotal: result.entriesTotal
    };
  })().then((response) => self.postMessage(response), (error) => {
    self.postMessage({ ok: false, error: String(error && error.message || error || "archive-worker-failed") });
  });
}, { once: true });
