"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "..");
const factory = require(path.join(root, "extension/vendor/sevenzip-wasm/sevenzip-wasm.js"));
const wasmBinary = fs.readFileSync(path.join(root, "extension/vendor/sevenzip-wasm/sevenzip-wasm.wasm"));
const source = fs.readFileSync(path.join(root, "extension/offscreen/archive-worker.js"), "utf8");
function worker(SevenZipWasm) {
  const context = { importScripts() {}, SevenZipWasm, URL, ArrayBuffer, Uint8Array, DataView, TextDecoder,
    self: { location: { href: "https://extension.test/offscreen/archive-worker.js" }, addEventListener() {} } };
  vm.createContext(context);
  vm.runInContext(source + "\nthis.run = processTask; this.diagnostic = hasEncryptionDiagnostic; this.header = hasRar5EncryptedHeader;", context);
  return context;
}
const bytes = new Uint8Array(128); bytes[0] = 77; bytes[1] = 90;
const arrayBuffer = (data) => data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);

async function main() {
  const fixtures = [];
  for (const mode of ["plain", "password", "headers"]) {
    const zip = await factory({ wasmBinary, print() {}, printErr() {} });
    zip.FS.writeFile("/测试.exe", bytes);
    const args = ["a", "-t7z", "/test.7z", "/测试.exe", "-bd", "-bsp0"];
    if (mode !== "plain") args.push("-pfixture-password");
    if (mode === "headers") args.push("-mhe=on");
    assert.equal(zip.callMain(args), 0);
    fixtures.push({ mode, input: arrayBuffer(zip.FS.readFile("/test.7z")) });
  }
  const actual = worker(async (opts) => {
    const zip = await factory({ ...opts, wasmBinary });
    const main = zip.callMain;
    zip.callMain = (args) => { try { return main(args); } finally { process.exitCode = 0; } };
    return zip;
  });
  for (const fixture of fixtures) {
    const result = await actual.run({ format: "7z", input: fixture.input });
    if (fixture.mode === "plain") {
      assert.equal(result.status, "ok", result.note);
      assert.equal(result.extracted.length, 1);
      assert.equal(result.extracted[0].name, "测试.exe");
    } else {
      assert.equal(result.status, "encrypted", fixture.mode + ": " + result.note);
      assert.equal(result.encrypted, true);
      assert.equal(result.extracted.length, 0);
      assert.match(result.note, /需要密码/);
    }
  }
  console.log("PASS: actual bundled WASM handles plain, password-protected and header-encrypted 7z; Unicode names preserved");

  // RAR5 encryption header fixture with its real CRC; no encrypted contents are read.
  const content = Uint8Array.from([21, 4, 0, 0, 0, 15, ...new Array(16).fill(0)]);
  const rar = new Uint8Array(12 + content.length);
  rar.set([0x52, 0x61, 0x72, 0x21, 0x1a, 7, 1, 0]); rar.set(content, 12);
  let crc = 0xffffffff;
  for (const byte of content) { crc ^= byte; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  new DataView(rar.buffer).setUint32(8, (crc ^ 0xffffffff) >>> 0, true);
  const neverDecode = worker(async () => { throw new Error("encrypted RAR header must stop before decoding"); });
  assert.equal(neverDecode.header(rar.buffer), true);
  const encryptedRar = await neverDecode.run({ format: "rar", input: rar.buffer });
  assert.equal(encryptedRar.status, "encrypted");
  rar[8] ^= 1; assert.equal(neverDecode.header(rar.buffer), false);
  console.log("PASS: CRC-validated RAR5 encryption header; corrupt header is not accepted as encryption");

  // Password prompts without newline, followed by an exception, used to be lost.
  for (const stage of ["list", "extract"]) {
    let calls = 0;
    const mock = worker(async (opts) => ({ FS: { writeFile() {}, unlink() {}, mkdir() {} }, callMain() {
      calls++;
      if (stage === "extract" && calls === 1) {
        ["Path = app.exe", "Size = 128", "Encrypted = -", ""].forEach(opts.print); return 0;
      }
      for (const byte of Buffer.from("Enter password (will not be echoed):")) opts.stdout(byte);
      throw new Error("Aborted");
    } }));
    const result = await mock.run({ format: "rar", input: bytes.buffer });
    assert.equal(result.status, "encrypted"); assert.match(result.note, /需要密码/);
  }
  assert.equal(actual.diagnostic("Path = password.exe\nEncrypted = -\nMethod = LZMA2\n"), false);
  assert.equal(actual.diagnostic("Data Error : password.exe"), false);
  const broken = worker(async (opts) => ({ FS: { writeFile() {}, unlink() {} }, callMain() {
    opts.printErr("Cannot open the file as archive"); return 2;
  } }));
  const failure = await broken.run({ format: "rar", input: bytes.buffer });
  assert.equal(failure.status, "error"); assert.match(failure.note, /原因尚未确认/);
  assert.notEqual(failure.encrypted, true);
  console.log("PASS: password prompt survives both exception paths; unknown failures and filenames are not classified as encrypted");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
