/**
 * Mint a botguard token in plain Node, with no browser and no jsdom.
 *
 * Why this is a different experiment from the jsdom line: the interpreter's whole
 * environment surface is small and was read statically out of the build source -
 * `window.performance.now`, `+new Date`, `document.hidden`, `document.body`,
 * `createElement("iframe")` + `src` + `load`/`error`, `contentWindow.location.href`,
 * `window.btoa`, `trustedTypes`, `requestIdleCallback`/`setImmediate`, `Math.random`.
 * It never touches `navigator`, `screen` or `userAgent`. So the VM's frame realm only
 * has to be a *real engine realm* with those objects on it - which `node:vm` provides
 * and jsdom cannot: every realm here gets V8's own intrinsics and a genuine native
 * `eval` (jsdom's `window.eval` is a wrapper, and a Proxy over a native eval is one of
 * the few things measured to push Chrome onto the degraded branch).
 *
 * Usage:
 *   node research/node_mint.mjs --material /tmp/bgbuild/material.json [--debug]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf("--" + name);
  return i < 0 ? dflt : args[i + 1];
};
const DEBUG = args.includes("--debug");
const TRACE = args.includes("--trace");
const EVAL_LOG = args.includes("--eval-log");
const materialPath = opt("material", "/tmp/bgbuild/material.json");
const FRAME_DELAY = Number(opt("frame-delay", "1"));
const ENV = (opt("env", "") || "").split(",").filter(Boolean);
const TIME_SCALE = Number(opt("time-scale", "1")) || 1;
const freqPath = opt("freq", new URL("./freq.txt", import.meta.url).pathname);

const material = JSON.parse(readFileSync(materialPath, "utf8"));
const arr = material.arr;
const interpFile = opt("interp-file", null);
const interp = interpFile ? readFileSync(interpFile, "utf8") : arr[5][arr[5].length - 1];
const freq = readFileSync(freqPath, "utf8");

const log = (...a) => { if (DEBUG || TRACE) console.log("[dbg]", ...a); };
let evalSeq = 0;
const CAPTURED = [];
if (TRACE) {
  process.on("uncaughtException", (e) => log("UNCAUGHT", String(e && e.stack ? e.stack.split("\n").slice(0, 4).join(" | ") : e)));
  process.on("unhandledRejection", (e) => log("REJECTED", String(e)));
}

/** A DOM node good enough for the interpreter: style, children, events. */
function makeElement(realm, tag) {
  const listeners = new Map();
  const el = {
    tagName: String(tag).toUpperCase(),
    nodeType: 1,
    style: {},
    children: [],
    ownerDocument: null,
    dataset: {},
    classList: { add() {}, remove() {}, contains: () => false },
    addEventListener(type, fn, opts) {
      log(realm.label, "addEventListener", el.tagName, type, typeof fn, JSON.stringify(opts ?? null));
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    removeEventListener(type, fn) {
      const l = listeners.get(type) || [];
      listeners.set(type, l.filter((f) => f !== fn));
    },
    dispatch(type, ev) {
      for (const fn of listeners.get(type) || []) fn.call(el, ev);
    },
    appendChild(c) { el.children.push(c); c.parentNode = el; log(realm.label, "appendChild", el.tagName, c.tagName); return c; },
    append(c) { el.children.push(c); c.parentNode = el; },
    removeChild(c) { el.children = el.children.filter((x) => x !== c); log(realm.label, "removeChild", el.tagName, c.tagName); return c; },
    insertBefore(c) { el.children.push(c); return c; },
    getElementsByTagName() { return []; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    hasChildNodes() { return el.children.length > 0; },
    contains(c) { return el.children.includes(c); },
    setAttribute() {},
    getAttribute() { return null; },
    removeAttribute() {},
    focus() {},
    click() {},
    get firstChild() { return el.children[0] || null; },
    get lastChild() { return el.children[el.children.length - 1] || null; },
    get childNodes() { return el.children; },
    get parentElement() { return el.parentNode || null; },
    get textContent() { return el._text || ""; },
    set textContent(v) { el._text = String(v); },
    get innerHTML() { return el._text || ""; },
    set innerHTML(v) { el._text = String(v); },
    get innerText() { return el._text || ""; },
    set innerText(v) { el._text = String(v); },
    get offsetHeight() { return 0; },
    get offsetWidth() { return 0; },
    getBoundingClientRect: () => ({ x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }),
    attachShadow: () => makeElement(realm, "shadow"),
  };
  // An iframe is the one element whose behaviour the VM measures: `src` assignment is
  // what starts the frame, and `load` / `error` are what it waits for.
  if (String(tag).toLowerCase() === "iframe") {
    let frameWin = null;
    Object.defineProperty(el, "src", {
      get: () => el._src || "",
      set: (v) => {
        el._src = String(v);
        log(realm.label, "iframe.src =", String(v).slice(0, 120));
        realm.onFrameSrc(el, el._src);
      },
    });
    Object.defineProperty(el, "contentWindow", { get: () => frameWin, set: (w) => { frameWin = w; } });
    Object.defineProperty(el, "contentDocument", { get: () => (frameWin ? frameWin.document : null) });
  }
  return el;
}

/** One window-like realm: real V8 intrinsics, fake DOM. */
function makeRealm(label, shared) {
  const sandbox = {};
  const ctx = createContext(sandbox, { name: label });
  const g = runInContext("globalThis", ctx);

  const realm = { label, ctx, g, document: null, timers: [] };

  const body = makeElement(realm, "body");
  const head = makeElement(realm, "head");
  const docEl = makeElement(realm, "html");
  docEl.appendChild(head);
  docEl.appendChild(body);

  realm.document = {
    label,
    nodeType: 9,
    contentType: "text/html",
    hidden: ENV.includes("hidden"),
    URL: "https://translate.google.com/?sl=auto&tl=zh-CN&op=images",
    scripts: [],
    all: undefined,
    visibilityState: "visible",
    readyState: "complete",
    cookie: "",
    referrer: "",
    title: "Google Translate",
    body,
    head,
    documentElement: docEl,
    createElement: (t) => makeElement(realm, t),
    createTextNode: (t) => ({ nodeType: 3, textContent: String(t), _text: String(t) }),
    createComment: (t) => ({ nodeType: 8, textContent: String(t) }),
    createDocumentFragment: () => makeElement(realm, "fragment"),
    getElementsByTagName: () => [],
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener() {},
    removeEventListener() {},
    hasFocus: () => true,
    get activeElement() { return body; },
  };
  // body/head/documentElement are built before the document object exists, so their
  // ownerDocument is repaired here (a null ownerDocument is a real difference from a browser).
  for (const el of [body, head, docEl, ...docEl.children]) {
    el.ownerDocument = realm.document;
    el.document = realm.document;
  }
  realm.document.defaultView = g;
  realm.document.location = null;

  const location = {
    href: "https://translate.google.com/?sl=auto&tl=zh-CN&op=images",
    protocol: "https:",
    host: "translate.google.com",
    hostname: "translate.google.com",
    origin: "https://translate.google.com",
    pathname: "/",
    search: "?sl=auto&tl=zh-CN&op=images",
    hash: "",
    assign() {},
    replace() {},
    reload() {},
    toString() { return location.href; },
  };
  realm.document.location = location;
  realm.location = location;

  const performance = {
    // The VM gates work on elapsed time (`if(U-S.A5 < S.YB-G) bail`), so a realm that is much faster
    // than a browser can fail a timing gate rather than a semantic one. --time-scale makes the clock
    // run faster without making the code slower.
    now: ENV.includes("perf0") ? () => 0 : () => {
      const t = Number(process.hrtime.bigint() / 1000n) / 1000;
      return t * TIME_SCALE;
    },
    timeOrigin: Date.now(),
    timing: { navigationStart: Date.now() - 500 },
    getEntriesByType: () => [],
    getEntriesByName: () => [],
    mark() {},
    measure() {},
  };

  // An iframe in this realm gets a *fresh* realm of its own (that is what a real frame
  // is), created lazily on `src` assignment and handed to the element as contentWindow.
  realm.onFrameSrc = (el, src) => {
    const frame = makeRealm(label + ":frame", shared);
    // A real frame resolves `src` against the document before navigating, so its
    // `location.href` is absolute; the interpreter tests it with /^h/ (http/https).
    frame.location.href = new URL(src || "", location.href).href;
    el.contentWindow = frame.g;
    shared.frames.push(frame);
    const fire = (type) => {
      try { el.dispatch(type, { type, target: el }); } catch (e) { log(label, "frame event threw", String(e)); }
    };
    // Real frames fire `load` after a navigation; keep it off the current stack so the
    // VM's own setInterval/setTimeout machinery is what advances the state machine.
    setTimeout(() => fire("load"), FRAME_DELAY);
  };

  const extra = {};
  // Chrome exposes both of these; a bare vm context does not. The interpreter branches on
  // them, so their absence is a real environment difference, not a detail.
  if (ENV.includes("win")) {
    // The Window surface a real frame has and a bare realm does not. `length` is the frame count,
    // `frameElement` the embedding element - both are cheap to get wrong and invisible in a shim.
    extra.length = shared.frames.length;
    extra.frameElement = null;
    extra.screenX = 0; extra.screenY = 0; extra.scrollX = 0; extra.scrollY = 0;
    extra.localStorage = { getItem: () => null, setItem() {}, removeItem() {}, clear() {}, length: 0 };
    extra.sessionStorage = extra.localStorage;
    extra.crypto = { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256); return a; } };
    extra.indexedDB = undefined;
    extra.chrome = undefined;
    extra.Notification = undefined;
    extra.WebGLRenderingContext = undefined;
    extra.RTCPeerConnection = undefined;
    extra.customElements = { get: () => undefined, define() {}, whenDefined: () => Promise.resolve() };
  }
  if (ENV.includes("idle")) {
    extra.requestIdleCallback = (fn) => setTimeout(() => fn({ didTimeout: false, timeRemaining: () => 50 }), 1);
    extra.cancelIdleCallback = (id) => clearTimeout(id);
  }
  if (ENV.includes("tt")) {
    extra.trustedTypes = {
      createPolicy(name, rules) {
        const f = (v) => String(v);
        return { createHTML: f, createScript: f, createScriptURL: f, name };
      },
      getPolicyNames: () => ["default"],
      emptyHTML: "",
    };
  }
  if (TRACE) {
    // Sink for the frame source the VM builds. A Node function on the sandbox is callable from the
    // realm, which avoids every question about where `globalThis` points inside the minified code.
    g.__capture = (src) => { CAPTURED.push(String(src)); };
  }
  Object.assign(g, extra, {
    window: g,
    self: g,
    top: shared.top || g,
    parent: shared.top || g,
    frames: shared.frames,
    document: realm.document,
    location,
    performance,
    navigator: {
      userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
      language: "en-US",
      languages: ["en-US", "en"],
      platform: "Linux x86_64",
      vendor: "Google Inc.",
      webdriver: false,
      hardwareConcurrency: 8,
      onLine: true,
    },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    console,
    requestAnimationFrame: (fn) => setTimeout(() => fn(performance.now()), 16),
    cancelAnimationFrame: (id) => clearTimeout(id),
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => true,
    postMessage() {},
    getComputedStyle: () => ({ getPropertyValue: () => "" }),
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1040,
    devicePixelRatio: 1,
    origin: "https://translate.google.com",
    isSecureContext: true,
    name: "",
    closed: false,
    opener: null,
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
  });
  // `Math`/`Date`/`JSON`/`String`/... come from the context's own intrinsics: do not
  // assign Node's copies onto the global, that would defeat the point of a real realm.
  if (TRACE && EVAL_LOG) {
    // Diagnostic only: show every eval the VM performs in this realm and whether it throws.
    // Off by default: replacing `window.eval` makes the program's handler eval indirect, and the
    // first handler then throws `fC is not defined` (measured). Text patches are safe; this is not.
    const origEval = g.eval;
    g.eval = function (src, ...rest) {
      let out, err = null;
      try { out = origEval(src, ...rest); } catch (e) { err = String(e).slice(0, 300); }
      log(label, "eval", String(src).length, JSON.stringify(String(src).slice(0, 70)), err ? "THREW " + err : "ok:" + typeof out);
      // The frame-side source is NOT the file we pass in (measured: 64841 vs 66581 B), so a stack
      // position is only readable against the text that was actually evaluated. Keep the big one.
      if (String(src).length > 10000) {
        // A sourceURL turns "<anonymous>:1340:32236" into "<file>:line:col" for the text that was
        // actually evaluated. The frame copy is generated per run (62-66 KB, length varies), so a
        // position is only meaningful against that run's own file.
        evalSeq += 1;
        const file = `/tmp/frame_src_${evalSeq}.js`;
        writeFileSync(file, String(src));
        return origEval(String(src) + "\n//# sourceURL=" + file, ...rest);
      }
      if (err) throw new Error(err);
      return out;
    };
    // Field profile of section 2b: the serializer's concat calls are `nonce(2)+field(n)`.
    const P = g.Array.prototype;
    const opush = P.push, oconcat = P.concat;
    P.push = function (...a) { const r = opush.apply(this, a); if (this.length > 200) log(label, "push ->", this.length); return r; };
    P.concat = function (...a) { const r = oconcat.apply(this, a); if (r.length > 200) log(label, "concat", this.length, "+", a.map((x) => (x && x.length) || 0).join(","), "->", r.length); return r; };
  }
  return realm;
}

if (args.includes("--probe-realm")) {
  // Does the interpreter install itself when it is evaluated in a plain realm? This isolates the
  // frame-side copy from everything the VM does around it.
  const sh = { frames: [] };
  const r = makeRealm("probe", sh);
  let err = null;
  try { runInContext(interp, r.ctx, { filename: "interp-probe.js" }); } catch (e) { err = String(e).slice(0, 300); }
  console.log(JSON.stringify({
    err,
    ridgeslice: typeof r.g.ridgeslice,
    fC: typeof r.g.fC, q: typeof r.g.q, a: typeof r.g.a, E: typeof r.g.E, Z: typeof r.g.Z,
    globals: Object.keys(r.g).length,
  }, null, 1));
  process.exit(0);
}

const shared = { frames: [] };
const page = makeRealm("page", shared);
shared.top = page.g;

// The interpreter is evaluated the way the page does it: a plain indirect eval in the
// page realm, which publishes `window.ridgeslice`.
// In trace mode, publish the frame-boot event array (`A` in the boot handler) so the
// load/error/retry profile the VM recorded can be read back after the mint.
// Trace mode only publishes the frame-boot event array (`A` in the boot handler); everything else
// is untouched. Measured trap: adding a `console.log` to the handler-eval site
// (`function(w){return eval(w)}`) changes what the eval'd handler can resolve - the very first
// program handler then throws `fC is not defined`, which the pristine run does not. Any text
// patch of an eval site is therefore a behavioural change, not an observation.
let interpSrc = TRACE ? interp.replace("P=0,X=null,A=[],L.f=", "P=0,X=null,A=(globalThis.__A=[]),L.f=") : interp;
if (args.includes("--capture-src") && interpSrc.includes("b=A.eval(")) {
  // Capture the text the VM evaluates in the frame realm. WARNING, measured: this call-through is
  // NOT neutral - the program then throws `Eb is not a function` / `fC is not defined` and runs a
  // different instruction count, because `A.eval` is the interpreter's own scope-bound eval. Use it
  // to read the generated text, never to measure behaviour. (The frame copy is a variant of the page
  // text, not a copy: patches propagate, lengths vary per run, columns are stable.)
  interpSrc = interpSrc.replace("b=A.eval(",
    "b=(function(__s){try{__capture(__s)}catch(__e){}return A.eval(__s)})(");
}
if (TRACE && interpSrc === interp) console.log("[dbg] WARN: boot array anchor not found");
runInContext(interpSrc, page.ctx, { filename: "interp.js" });
const VM = page.g.ridgeslice;
if (!VM || typeof VM.a !== "function") {
  console.log(JSON.stringify({ stage: "install", keys: VM ? Object.keys(VM) : null }));
  process.exit(2);
}

const noop = () => {};
const out = { stage: "mint" };
const t0 = Date.now();
try {
  const api = await new Promise((res, rej) => {
    try {
      VM.a(arr[0], (...f) => res(f), true, page.document.body, noop, [[], []], undefined, false,
        [noop, noop, noop, noop, noop]);
    } catch (e) { rej(e); }
  });
  out.api = Array.isArray(api) ? api.map((x) => typeof x) : typeof api;
  const token = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  out.token_len = token.length;
  {
    const raw = token.startsWith(";") ? token.slice(1) : token;
    const pad = "=".repeat((4 - (raw.length % 4)) % 4);
    writeFileSync(opt("out", "/tmp/node-token.bin"), Buffer.from(raw + pad, "base64"));
  }
  out.head = token.slice(0, 48);
  if (TRACE) {
    out.src_count = CAPTURED.length;
    CAPTURED.forEach((src, i) => {
      const pad = src.length - src.replace(/^\n+/, "").length;
      writeFileSync(`/tmp/frame_src_${i}_pad${pad}.js`, src);
    });
  }
  out.frames = shared.frames.length;
  {
    const f = shared.frames[0];
    if (f) {
      const keys = Object.keys(f.g).filter((k) => !k.startsWith("__"));
      out.frame_globals = keys.length;
      out.frame_has = { fC: typeof f.g.fC, q: typeof f.g.q, a: typeof f.g.a, E: typeof f.g.E, n: typeof f.g.n, Z: typeof f.g.Z, YU: typeof f.g.YU };
    }
  }
  {
    // Emit hook (research/bgpatch.py --emit) publishes the instance as `__vmref` per realm.
    let em = [];
    for (const r of [page, ...shared.frames]) {
      try {
        const vm = r.g.__vmref;
        if (vm && vm.__em && vm.__em.length > em.length) em = vm.__em;
      } catch (e) {}
    }
    out.em = em.map((e) => [e[0], e[1], e[6], e[5] ? String(e[5]).slice(0, 6000) : null]);
  }
  if (TRACE) {
    for (const r of [page, ...shared.frames]) {
      try { out["A_" + r.label] = r.g.__A || null; } catch (e) {}
    }
    out.ms = Date.now() - t0;
  }
} catch (e) {
  out.error = String(e && e.stack ? e.stack.split("\n").slice(0, 6).join(" | ") : e);
}
console.log(JSON.stringify(out, null, 1));
process.exit(0);
