"use strict";
const assert = require("node:assert/strict"), vm = require("node:vm");
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const read = name => fs.readFileSync(path.join(__dirname, "..", "extension", name), "utf8");
const node = () => ({ children: [], appendChild(child) { this.children.push(child); } });
const host = "portal.example.test", missing = "未查询到备案信息";
const content = { state: {} }, bg = {}, requests = [];
const tlv = (tag, ...fields) => { const value = Buffer.concat(fields); assert.ok(value.length < 128);
  return Buffer.concat([Buffer.from([tag, value.length]), value]); };
const attr = (n, v) => tlv(49, tlv(48, tlv(6, Buffer.from([85, 4, n])), tlv(12, Buffer.from(v))));
const der = tlv(48, tlv(48, tlv(2, Buffer.from([1])), tlv(48), tlv(48, attr(10, "Issuing CA")), tlv(48),
  tlv(48, attr(3, host), attr(10, "示例公司")), tlv(48)));
const ctx = vm.createContext({ console, URL, TextDecoder, atob, setTimeout, clearTimeout, crypto: crypto.webcrypto,
  self: { SilverfoxBackground: bg }, window: { SilverfoxContent: content }, location: new URL("https://" + host),
  document: { addEventListener() {}, createElement: node, createTextNode: text => ({ textContent: text }) },
  module: { exports: {} }, fetch: async u => { requests.push(u); return new Response(der); } });
async function main() {
  for (const f of ["shared/ssl-evidence.js", "popup/popup.js", "content/intel-gates.js"])
    vm.runInContext(read(f), ctx);
  const root = node(), renderer = new ctx.module.exports.PopupRenderer(root);
  const ev = { host, validation: "EV", organization: "", sniChainVerified: true,
    fingerprintSha256: crypto.createHash("sha256").update(der).digest("hex") };
  for (const [grade, forced, raw, expected] of [
    ["EV", false, missing, ""], ["EV", true, missing, ""], ["DV", false, missing, missing],
    ...["粤ICP备12345678号-1", "假冒宣称 琼ICP备20000605-1", "备案查询失败"].map(x => ["EV", false, x, x])
  ]) {
    const sslInfo = { ...ev, validation: grade };
    content.state.sslInfo = sslInfo;
    content.state._icpForcedMissingByFallbackWhois = forced; content.state._icpForcedMissingHost = host;
    assert.equal(content.formatIcpInfoForReport(raw), expected);
    root.children.length = 0;
    renderer.appendIcp({ sslInfo, icpInfo: raw, icpForcedMissing: forced });
    assert.equal(root.children[0]?.children[1].textContent || "", expected);
  }
  vm.runInContext(read("background/ssl-cert-bg.js").replace("  NS.installSslCertCapture = function",
    "  Object.assign(NS, { subject: classifyFromSubjectDn, enrich: enrichOrganizationFromCrt, sourceNetworkCalc, sourceEdgeOne, sourceSslLabs, decodeMysslReportPayload });\n  NS.installSslCertCapture = function"), ctx);
  for (const dn of ["/C=CN/O=示例公司/CN=" + host, "CN=" + host + ", 2.5.4.10=示例公司",
    "CN=" + host + "\norganizationName=示例公司"])
    assert.equal(bg.subject(dn, "").organization, "示例公司");
  assert.equal(bg.subject('CN=' + host + ',O="Holding, O=Division",C=US', "").organization, "Holding, O=Division");
  assert.equal(bg.subject("CN=" + host + ", O=Example\\, Inc.", "").organization, "Example, Inc.");
  assert.equal(bg.subject("CN=" + host, "O=Issuing CA").organization, "");
  const enriched = await bg.enrich(host, ev);
  assert.equal(enriched.organization, "示例公司");
  renderer.appendSsl({ sslInfo: enriched });
  assert.equal(root.children.at(-1).children[1].textContent, "EV · 示例公司");
  assert.equal((await bg.enrich(host, { ...ev, fingerprintSha256: "c".repeat(64) })).organization, "");
  assert.equal((await bg.enrich(host, { ...ev, fingerprintSha256: "" })).organization, "");
  assert.equal(requests.length, 2, "no domain-wide lookup to guess a missing EV holder");
  const caHost = "www.digicert.com", holder = "DigiCert, Inc.", issuer = "DigiCert EV RSA CA G2";
  const leaf = tlv(48, tlv(48, tlv(2, Buffer.from([1])), tlv(48), tlv(48, attr(10, "DigiCert Inc")), tlv(48),
    tlv(48, attr(3, caHost), attr(10, holder)), tlv(48)));
  const raw = "-----BEGIN CERTIFICATE-----\n" + leaf.toString("base64") + "\n-----END CERTIFICATE-----";
  const reply = payload => { ctx.fetch = async () => new Response(JSON.stringify(payload)); };
  const checkHolder = hit => {
    renderer.appendSsl({ sslInfo: hit });
    assert.equal(root.children.at(-1).children[1].textContent, "EV · " + holder);
    assert.equal(hit?.organization, holder);
  };
  reply({status: "OK", certificate: {hostname: caHost, raw, issued_by: issuer}});
  checkHolder(await bg.sourceNetworkCalc(caHost));
  for (const pem of ["", raw]) {
    reply({status: "READY", certs: [{id: "leaf", subject: "CN=" + caHost + ",O=" + holder,
      raw: pem, issuerLabel: issuer}], endpoints: [{details: {certChains: [{certIds: ["leaf"]}]}}]});
    checkHolder(await bg.sourceSslLabs(caHost));
  }
  const edge = {code: 0, ca: false, subject: {CN: caHost, O: holder}, issuer: {CN: issuer, O: "DigiCert Inc"}};
  reply({code: 0, data: edge});
  checkHolder(await bg.sourceEdgeOne(caHost));
  delete edge.subject.O;
  reply({code: 0, data: edge});
  assert.equal((await bg.sourceEdgeOne(caHost)).organization, "", "issuer alone cannot name the holder");
  assert.equal(await bg.sourceEdgeOne("other.example"), null);
  const row = (k, v) => '<td class="cc-tableTit">' + k + '</td><td class="cc-tableCel">' + v + '</td>';
  const first = row("通用名称", caHost) + row("证书类型", "EV") + row("颁发者", issuer);
  checkHolder(bg.decodeMysslReportPayload(first + row("组织机构", holder), caHost));
  assert.equal(bg.decodeMysslReportPayload(first + row("通用名称", issuer) + row("组织机构", holder), caHost),
    null, "an intermediate certificate row cannot supply the website holder");
  const cacheBg = {}, at = Date.now(), weak = {at, ttl: 180000, value: null};
  const stored = { silverfox_ssl_cert_cache_v2: {
    [caHost]: {host: caHost, validation: "EV", organization: "", at}
  }, silverfox_ssl_source_state_v1: {cache: {
    ["networkcalc|" + caHost]: weak,
    ["myssl|" + caHost]: {...weak, value: {validation: "EV", organization: holder}},
    ["networkcalc|" + host]: weak
  }, cooldowns: {networkcalc: {until: at + 60000}}} };
  const cacheCtx = vm.createContext({self: {SilverfoxBackground: cacheBg}, URL,
    chrome: {runtime: {}, storage: {local: {get(keys, cb) {cb(stored);}, set() {}}}}});
  vm.runInContext(read("background/ssl-cert-bg.js").replace("  NS.installSslCertCapture = function",
    "  NS.restore = ensureSslPersistentStateLoaded; NS.installSslCertCapture = function"), cacheCtx);
  await cacheBg.restore();
  assert.equal(cacheBg._sslSourceCache.has("networkcalc|" + caHost), false);
  assert.ok(cacheBg._sslSourceCache.has("myssl|" + caHost));
  assert.ok(cacheBg._sslSourceCache.has("networkcalc|" + host));
  assert.ok(cacheBg._sslSourceCooldowns.has("networkcalc"));
  console.log("EV subject, exact-leaf enrichment and ICP display regressions passed.");
}
main().catch(e => { console.error(e); process.exitCode = 1; });
