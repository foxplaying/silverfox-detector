"use strict";
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const assert = require("node:assert/strict");
const read = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");

async function main() {
  // Exercise the production method without booting unrelated page hooks.
  const source = read("extension/page-hooks/index.js");
  const start = source.indexOf("    _installNavigationApiPatch() {");
  const end = source.indexOf("    _installMetaRefreshStrip() {", start);
  assert.ok(start >= 0 && end > start);
  const calls = [], location = new URL("https://watch.example/video/1");
  const nativeResult = { committed: Promise.resolve("entry"), finished: Promise.resolve("entry") };
  const navigation = { navigate(...args) { calls.push({ receiver: this, args }); return nativeResult; } };
  const policy = { tryBlockNavigation: url => url === "https://bad.example/payload.exe" };
  vm.runInNewContext(`class Fixture { ${source.slice(start, end)} }
    const hooks = new Fixture(); hooks.policy = policy; hooks._installNavigationApiPatch();`, {
    navigation, location, policy, DOMException, PackageHeuristics: { coerceHref: String }
  });
  const blocked = navigation.navigate("https://bad.example/payload.exe", { history: "push" });
  assert.equal(calls.length, 0, "blocked navigation must not reload current document");
  for (const promise of [blocked.committed, blocked.finished]) {
    await assert.rejects(promise, error => error.name === "AbortError");
  }
  const options = { history: "replace", state: { fixture: true } };
  assert.equal(navigation.navigate("/video/2", options), nativeResult);
  assert.equal(calls.length, 1); assert.equal(calls[0].receiver, navigation);
  assert.equal(calls[0].args[0], "/video/2"); assert.equal(calls[0].args[1], options);
  // Explicitly requested normal same-URL navigation is not globally disabled.
  assert.equal(navigation.navigate(location.href), nativeResult);
  assert.equal(calls.length, 2);
  console.log("PASS: blocked Navigation API call cancels without self-reload; normal navigation preserves native result/options");

  const writes = [];
  class Element {
    constructor(tag, attrs = {}, parent = null) {
      this.tagName = tag; this.nodeType = 1; this.attrs = new Map(Object.entries(attrs)); this.parentElement = parent;
      this.paused = true; this.currentTime = 123;
    }
    getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
    hasAttribute(name) { return this.attrs.has(name); }
    setAttribute(name, value) { writes.push({ element: this, name, value }); this.attrs.set(name, value); }
  }
  function resourceClass(tag) {
    return class extends Element {
      constructor(attrs, parent) { super(tag, attrs, parent); }
      get src() { return this.getAttribute("src"); }
      set src(value) { Element.prototype.setAttribute.call(this, "src", value); }
    };
  }
  const HTMLImageElement = resourceClass("IMG"), HTMLVideoElement = resourceClass("VIDEO"),
    HTMLAudioElement = resourceClass("AUDIO"), HTMLSourceElement = resourceClass("SOURCE"),
    HTMLEmbedElement = resourceClass("EMBED"), HTMLInputElement = resourceClass("INPUT");
  const video = new HTMLVideoElement({ src: "http://cdn.example/video.mp4", autoplay: "", poster: "http://cdn.example/poster.jpg" });
  const audio = new HTMLAudioElement({ src: "http://cdn.example/audio.mp3", "data-src": "http://cdn.example/audio.mp3" });
  const nested = new HTMLSourceElement({ src: "http://cdn.example/nested.mp4" }, video);
  const detached = new HTMLSourceElement({ src: "http://cdn.example/detached.mp4" });
  const embed = new HTMLEmbedElement({ src: "http://cdn.example/player" });
  const track = new Element("TRACK", { src: "http://cdn.example/subtitles.vtt" }, video);
  const media = [video, audio, nested, detached, embed, track];
  const image = new HTMLImageElement({ src: "http://cdn.example/poster.jpg" });
  const pictureSource = new HTMLSourceElement({ srcset: "http://cdn.example/a.jpg 1x" }, new Element("PICTURE"));
  const document = { readyState: "loading", querySelectorAll: () => [...media, image, pictureSource],
    addEventListener(type, fn) { if (type === "DOMContentLoaded") this.ready = fn; } };
  const hooks = {};
  const nativeMediaSetters = [HTMLVideoElement, HTMLAudioElement, HTMLSourceElement, HTMLEmbedElement]
    .map(type => [type, Object.getOwnPropertyDescriptor(type.prototype, "src").set]);
  vm.runInNewContext(read("extension/page-hooks/mixed-content-quiet.js"), {
    window: { SilverfoxPageHooks: hooks }, document, location, URL, Element,
    HTMLImageElement, HTMLVideoElement, HTMLAudioElement, HTMLSourceElement, HTMLEmbedElement, HTMLInputElement,
    setTimeout: () => 1, clearTimeout() {}
  });
  assert.equal(image.getAttribute("src"), "https://cdn.example/poster.jpg");
  assert.equal(pictureSource.getAttribute("srcset"), "https://cdn.example/a.jpg 1x");
  assert.equal(writes.some(write => media.includes(write.element)), false);
  document.ready(); hooks.MixedContentQuiet.scanTree(document);
  assert.equal(writes.some(write => media.includes(write.element)), false, "rescans must not rewrite paused media");
  for (const el of media) { assert.equal(el.paused, true); assert.equal(el.currentTime, 123); }
  for (const [type, setter] of nativeMediaSetters) assert.equal(Object.getOwnPropertyDescriptor(type.prototype, "src").set, setter);
  for (const el of media) {
    const value = "http://cdn.example/new-resource";
    const before = writes.length;
    el.setAttribute("src", value);
    assert.equal(writes.length, before + 1); assert.equal(el.getAttribute("src"), value);
  }
  // Even detached source property writes must stay untouched until page assigns ownership.
  detached.src = "http://cdn.example/another.mp4";
  assert.equal(detached.src, "http://cdn.example/another.mp4");
  hooks.MixedContentQuiet.uninstall("test");
  console.log("PASS: initial/DOMContentLoaded/repeated scans never rewrite media; native resource assignments and image upgrades preserved");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
