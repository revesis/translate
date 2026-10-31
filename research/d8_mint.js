// Browserless mint on the exact V8 that Chrome 159 ships (d8 = V8 shell: no Blink, no browser).
//
// The Node port established that the generated frame program is byte-identical in both realms
// (section 70) and that the VM's whole host surface is `window`, `document.createElement('div').style`
// and `document.createElement('img')` (section 73). What Node cannot supply is Chrome's engine: this
// d8 is built from the same checkout as the trusted browser binary, so the engine version, the error
// texts and the intrinsics match by construction.
//
//   d8 --allow-natives-syntax research/d8_mint.js --material /path/material.json --freq /path/freq.txt
//
// Realms: `Realm.createAllowCrossRealmAccess()` - the VM reaches its frame realm through
// `iframe.contentWindow`, which is what a same-origin blank frame looks like.

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/159.0.0.0 Safari/537.36";
const ENV = [];
let TRACE = false;
// d8 hands the script its arguments through the top-level `arguments` object (scriptArgs is not
// defined in this engine build), so capture it before any function shadows it.
const ARGV = typeof arguments !== "undefined" ? Array.from(arguments) : [];

function log() {
  if (!TRACE) return;
  print("[trace] " + Array.prototype.join.call(arguments, " "));
}

function btoaBinary(s) {
  const str = String(s);
  let out = "";
  for (let i = 0; i < str.length; i += 3) {
    const a = str.charCodeAt(i) & 0xff;
    const hasB = i + 1 < str.length;
    const hasC = i + 2 < str.length;
    const b = hasB ? str.charCodeAt(i + 1) & 0xff : 0;
    const c = hasC ? str.charCodeAt(i + 2) & 0xff : 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] +
      (hasB ? B64[(n >> 6) & 63] : "=") + (hasC ? B64[n & 63] : "=");
  }
  return out;
}

function atobBinary(s) {
  const str = String(s).replace(/[^A-Za-z0-9+/]/g, "");
  let out = "";
  for (let i = 0; i < str.length; i += 4) {
    const n = (B64.indexOf(str[i]) << 18) | (B64.indexOf(str[i + 1] || "A") << 12) |
      ((str[i + 2] ? B64.indexOf(str[i + 2]) : 0) << 6) | (str[i + 3] ? B64.indexOf(str[i + 3]) : 0);
    out += String.fromCharCode((n >> 16) & 0xff);
    if (str[i + 2]) out += String.fromCharCode((n >> 8) & 0xff);
    if (str[i + 3]) out += String.fromCharCode(n & 0xff);
  }
  return out;
}

/** The style object the VM probes: `document.createElement('div').style`. */
function makeStyle() {
  const props = new Map();
  const style = {
    get cssText() { return Array.from(props).map(([k, v]) => k + ": " + v + ";").join(" "); },
    set cssText(v) {
      props.clear();
      String(v || "").split(";").forEach((d) => {
        const i = d.indexOf(":");
        if (i > 0) props.set(d.slice(0, i).trim(), d.slice(i + 1).trim());
      });
    },
    get length() { return props.size; },
    item(i) { return Array.from(props.keys())[i] || ""; },
    getPropertyValue(k) { return props.get(String(k)) || ""; },
    setProperty(k, v) { props.set(String(k), String(v)); },
    removeProperty(k) { const o = props.get(String(k)) || ""; props.delete(String(k)); return o; },
    getPropertyPriority() { return ""; },
    display: "", visibility: "", width: "", height: "", color: "", position: "",
  };
  Object.defineProperty(style, Symbol.toStringTag, { value: "CSSStyleDeclaration" });
  return style;
}

function makeElement(realm, tag) {
  const listeners = new Map();
  const lower = String(tag).toLowerCase();
  const el = {
    tagName: String(tag).toUpperCase(),
    nodeName: String(tag).toUpperCase(),
    nodeType: 1,
    ownerDocument: null,
    style: makeStyle(),
    children: [],
    dataset: {},
    classList: { add() {}, remove() {}, contains() { return false; } },
    addEventListener(type, fn) {
      log(realm.label, "addEventListener", el.tagName, type, typeof fn);
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    removeEventListener(type, fn) {
      listeners.set(type, (listeners.get(type) || []).filter((f) => f !== fn));
    },
    dispatch(type, ev) { (listeners.get(type) || []).forEach((fn) => fn.call(el, ev)); },
    appendChild(c) { el.children.push(c); if (c) c.parentNode = el; return c; },
    append(c) { el.children.push(c); if (c) c.parentNode = el; },
    removeChild(c) { el.children = el.children.filter((x) => x !== c); return c; },
    insertBefore(c) { el.children.push(c); return c; },
    getElementsByTagName() { return []; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    hasChildNodes() { return el.children.length > 0; },
    contains(c) { return el.children.indexOf(c) >= 0; },
    setAttribute() {},
    getAttribute() { return null; },
    removeAttribute() {},
    focus() {},
    click() {},
    get firstChild() { return el.children[0] || null; },
    get childNodes() { return el.children; },
    get parentElement() { return el.parentNode || null; },
    get textContent() { return el._text || ""; },
    set textContent(v) { el._text = String(v); },
    get innerHTML() { return el._text || ""; },
    set innerHTML(v) { el._text = String(v); },
    get offsetWidth() { return 0; },
    get offsetHeight() { return 0; },
    getBoundingClientRect() {
      return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 };
    },
  };
  if (lower === "img") {
    el.complete = true; el.naturalWidth = 0; el.naturalHeight = 0; el.width = 0; el.height = 0;
  }
  if (lower === "iframe") {
    // In a browser an iframe has a WindowProxy from the moment it is created (about:blank), not only
    // after `src` is assigned. Measured: the VM reads through a freshly created iframe's contentWindow,
    // and returning null there produces `Cannot read properties of null (reading 'String')`.
    // A browser gives an iframe one window for its whole life: creating it (about:blank), assigning
    // `src` and re-assigning it all navigate that same WindowProxy. Measured: returning null before
    // `src` leaves the interpreter without a scope object, and creating a second realm on `src` adds a
    // frame the VM did not ask for (frame count 2 instead of 1).
    let frameRealm = null;
    let frameWin = null;
    const navigate = (src) => {
      if (!frameRealm) {
        frameRealm = makeRealm("frame" + shared.frames.length);
        shared.frames.push(frameRealm);
        frameWin = frameRealm.g;
      }
      frameRealm.g.location.href = resolveUrl(String(src || ""), (realm.document && realm.document.URL) || "https://translate.google.com/");
      shared.timers.push(() => el.dispatch("load", { type: "load", target: el }));
    };
    Object.defineProperty(el, "src", {
      get() { return el._src || ""; },
      set(v) {
        el._src = String(v);
        log(realm.label, "iframe.src =", el._src.slice(0, 100));
        navigate(el._src);
      },
    });
    Object.defineProperty(el, "contentWindow", {
      get() { if (!frameRealm) navigate(""); return frameWin; },
      set(w) { frameWin = w; },
    });
    Object.defineProperty(el, "contentDocument", {
      get() { if (!frameRealm) navigate(""); return frameWin.document; },
    });
  }
  if (ENV.indexOf("webidl") >= 0) {
    // DOM methods are WebIDL operations too: a foreign receiver must fail the way a browser fails, or
    // the VM's authenticity probes see a plain JS function.
    const guard = guarded(el);
    for (const m of ["appendChild", "removeChild", "insertBefore", "addEventListener",
                     "removeEventListener", "setAttribute", "getAttribute", "removeAttribute",
                     "getElementsByTagName", "querySelector", "querySelectorAll", "contains",
                     "hasChildNodes", "focus", "click", "getBoundingClientRect"]) {
      if (typeof el[m] === "function") el[m] = guard(el[m]);
    }
  }
  return el;
}

const shared = { frames: [], interp: "", timers: [], intervalRuns: 0 };
const D8_GLOBAL = globalThis;

/**
 * WebIDL operations reject a foreign receiver with `Illegal invocation`, and the VM probes exactly that
 * (four such errors in a trusted browser run). The guard has to accept a *detached* call, which in a
 * classic script still arrives with a global as `this`: the realm global for a realm-created function,
 * d8's own global for one created here. Anything else is a probe.
 */
function guarded(realmGlobal) {
  return (impl) => function (...args) {
    if (this !== D8_GLOBAL && this !== realmGlobal) throw new TypeError("Illegal invocation");
    return impl.apply(null, args);
  };
}

/** Absolute URL the way a frame resolves one; d8 has no URL class. */
function resolveUrl(src, base) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(src)) return src;
  if (src.startsWith("//")) return base.split(":")[0] + ":" + src;
  const m = /^([a-z][a-z0-9+.-]*:\/\/[^/]*)(.*)$/i.exec(base);
  const origin = m ? m[1] : "https://translate.google.com";
  const path = m ? m[2] : "/";
  if (src.startsWith("/")) return origin + src;
  if (src.startsWith("#")) return origin + path + src;
  return origin + path.replace(/[^/]*$/, "") + src;
}

/** One V8 realm of the browser's engine version, with a DOM shim on its global. */
function makeRealm(label) {
  const r = Realm.createAllowCrossRealmAccess();
  const g = Realm.global(r);
  const realm = { label, r, g, document: null, onFrameSrc: null };

  const body = makeElement(realm, "body");
  const head = makeElement(realm, "head");
  const html = makeElement(realm, "html");
  html.appendChild(head);
  html.appendChild(body);

  const doc = {
    nodeType: 9,
    contentType: "text/html",
    hidden: ENV.indexOf("hidden") >= 0,
    visibilityState: "visible",
    readyState: "complete",
    URL: "https://translate.google.com/?sl=auto&tl=zh-CN&op=images",
    cookie: "",
    referrer: "",
    title: "Google Translate",
    scripts: { length: 1, item: () => null, 0: undefined },
    body, head, documentElement: html,
    createElement(t) { return makeElement(realm, t); },
    createTextNode(t) { return { nodeType: 3, textContent: String(t) }; },
    createComment(t) { return { nodeType: 8, textContent: String(t) }; },
    createDocumentFragment() { return makeElement(realm, "fragment"); },
    getElementsByTagName() { return []; },
    getElementById() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    addEventListener() {},
    removeEventListener() {},
    hasFocus() { return true; },
    get activeElement() { return body; },
  };
  for (const el of [body, head, html]) { el.ownerDocument = doc; el.document = doc; }
  realm.document = doc;

  const t0 = Date.now();
  const perf = { now() { return Date.now() - t0; } };
  // `length` is the child-frame count, and it changes when an iframe is appended.
  Object.defineProperty(g, "length", {
    get() {
      let n = 0;
      for (const c of doc.body.children) if (String(c.tagName).toLowerCase() === "iframe") n += 1;
      return n;
    },
  });

  const loc = {
    href: doc.URL, protocol: "https:", host: "translate.google.com",
    search: "?sl=auto&tl=zh-CN&op=images", pathname: "/",
  };

  const hostFn = ENV.indexOf("webidl") >= 0 ? guarded(g) : (f) => f;
  Object.assign(g, {
    window: g, self: g, top: g, parent: g, frames: g,
    document: doc, location: loc, performance: perf,
    history: { length: 2, state: null, pushState() {}, replaceState() {}, back() {}, forward() {}, go() {} },
    btoa: hostFn(btoaBinary), atob: hostFn(atobBinary),
    setTimeout(fn, ms, ...rest) { shared.timers.push(() => fn(...rest)); return 1; },
    clearTimeout() {},
    setInterval(fn, ms, ...rest) {
      // A real interval keeps firing; the VM's state machine depends on it staying alive, so re-arm
      // (bounded, so a runaway interval cannot hang the drain loop).
      const tick = () => {
        if (shared.intervalRuns++ > 200) return;
        try { fn(...rest); } catch (e) { log("interval threw", String(e).slice(0, 60)); }
        shared.timers.push(tick);
      };
      shared.timers.push(tick);
      return 1;
    },
    clearInterval() {},
    setImmediate(fn, ...rest) { shared.timers.push(() => fn(...rest)); return 1; },
    queueMicrotask(fn) { Promise.resolve().then(fn); },
    requestIdleCallback(fn) {
      shared.timers.push(() => fn({ timeRemaining: () => 5, didTimeout: false }));
      return 1;
    },
    cancelIdleCallback() {},
    requestAnimationFrame(fn) { shared.timers.push(() => fn(0)); return 1; },
    cancelAnimationFrame() {},
    addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
    postMessage() {},
    getComputedStyle() { return { getPropertyValue() { return ""; } }; },
    matchMedia() { return { matches: false, addListener() {}, removeListener() {} }; },
    innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1040,
    devicePixelRatio: 1, name: "", closed: false,
    navigator: {
      userAgent: UA, language: "en-US", languages: ["en-US", "en"],
      platform: "Linux x86_64", webdriver: false,
    },
    screen: {
      width: 1920, height: 1080, availWidth: 1920, availHeight: 1040,
      colorDepth: 24, pixelDepth: 24,
    },
    console: { log: (...a) => log(label, ...a), error: (...a) => log(label, ...a),
               warn: (...a) => log(label, ...a), info: (...a) => log(label, ...a),
               debug: (...a) => log(label, ...a) },
  });

  if (ENV.indexOf("evalog") >= 0) {
    // Diagnostic only (this perturbs: section 65). Wrapping the realm's eval is the only way to see
    // why the VM's generated frame copy fails to initialise, since the error is caught inside the VM.
    const origEval = g.eval;
    g.eval = function (src) {
      try {
        return origEval(src);
      } catch (e) {
        print("[evalog] " + label + " eval len=" + String(src).length + " THREW " +
          String(e && e.message) + "\n" + String(e && e.stack).split("\n").slice(0, 6).join("\n"));
        throw e;
      }
    };
  }


  // A browser realm exposes a large DOM constructor surface; see the header of this patch.
  for (const name of ["Node", "Element", "HTMLElement", "HTMLDivElement", "HTMLSpanElement", "HTMLAnchorElement", "HTMLImageElement", "HTMLIFrameElement", "HTMLScriptElement", "HTMLCanvasElement", "HTMLInputElement", "HTMLBodyElement", "HTMLHtmlElement", "HTMLHeadElement", "HTMLDocument", "Document", "DocumentFragment", "ShadowRoot", "Text", "Comment", "Attr", "CharacterData", "CSSStyleDeclaration", "CSSStyleSheet", "CSS", "CSSRule", "CSSRuleList", "MediaList", "StyleSheetList", "Event", "EventTarget", "CustomEvent", "MouseEvent", "KeyboardEvent", "UIEvent", "FocusEvent", "InputEvent", "MessageEvent", "ErrorEvent", "ProgressEvent", "StorageEvent", "PopStateEvent", "HashChangeEvent", "PageTransitionEvent", "MutationObserver", "IntersectionObserver", "ResizeObserver", "PerformanceObserver", "ReportingObserver", "URL", "URLSearchParams", "Blob", "File", "FileList", "FileReader", "FormData", "Headers", "Request", "Response", "XMLHttpRequest", "WebSocket", "Worker", "SharedWorker", "MessageChannel", "MessagePort", "BroadcastChannel", "Image", "Audio", "Option", "Range", "Selection", "DOMParser", "XMLSerializer", "XPathResult", "XPathEvaluator", "Navigator", "Screen", "History", "Location", "Storage", "Crypto", "CryptoKey", "SubtleCrypto", "IDBFactory", "IDBDatabase", "Notification", "Permissions", "Clipboard", "DataTransfer", "DataTransferItem", "DragEvent", "WheelEvent", "TouchEvent", "AbortController", "AbortSignal", "ReadableStream", "WritableStream", "TransformStream", "TextEncoder", "TextDecoder", "DOMTokenList", "DOMRect", "DOMRectReadOnly", "DOMStringMap", "DOMException", "DOMImplementation", "NodeList", "HTMLCollection", "NamedNodeMap", "MediaQueryList", "VisualViewport", "TrustedHTML", "TrustedScript", "TrustedScriptURL", "TrustedTypePolicy", "TrustedTypePolicyFactory"]) {
    if (typeof g[name] === "undefined") {
      const ctor = { [name]: function () {} }[name];
      Object.defineProperty(ctor, "name", { value: name });
      g[name] = ctor;
    }
  }

  // The iframe is the one element whose behaviour the VM measures: assigning `src` starts a frame.
  // The frame's own interpreter is *not* installed here - the VM evaluates a generated copy of it in
  // the frame realm itself, and doing it for it changes what that copy can resolve (measured in the
  // Node port: `n is not a function`).
  realm.onFrameSrc = (el, src) => {
    log(label, "frame src", String(src).slice(0, 80));
    const fr = makeRealm("frame" + shared.frames.length);
    // A real frame resolves `src` against its document before navigating, so `location.href` is
    // absolute; the interpreter tests it with /^h/ (http/https).
    fr.g.location.href = resolveUrl(String(src || ""), doc.URL);
    shared.frames.push(fr);
    el.__setFrameWin(fr.g);
    log(label, "frame realm kinds:", Realm.eval(fr.r,
      "[typeof window, typeof document, typeof document.createElement, typeof btoa, typeof String, " +
      "typeof Object, typeof eval, typeof Function].join(',')"));
    Promise.resolve().then(() => el.dispatch("load", { type: "load", target: el }));
  };
  return realm;
}

function drain(rounds) {
  for (let i = 0; i < rounds; i++) {
    %PerformMicrotaskCheckpoint();
    if (shared.timers.length) {
      const fn = shared.timers.shift();
      try { fn(); } catch (e) { log("timer threw", String(e).slice(0, 80)); }
    }
  }
}

function main() {
  let materialPath = null;
  let freqPath = null;
  const argv = ARGV;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--material") materialPath = argv[++i];
    else if (argv[i] === "--freq") freqPath = argv[++i];
    else if (argv[i] === "--trace") TRACE = true;
    else if (argv[i] === "--env") ENV.push.apply(ENV, String(argv[++i]).split(","));
  }
  if (!materialPath) throw new Error("need --material");
  const material = JSON.parse(read(materialPath));
  const arr = material.arr;
  const interp = arr[5][arr[5].length - 1];
  const freq = freqPath ? read(freqPath) : "";
  shared.interp = interp;

  const page = makeRealm("page");
  Realm.eval(page.r, interp);
  const VM = page.g.ridgeslice;
  if (!VM || typeof VM.a !== "function") throw new Error("install failed: " + typeof VM);

  const noop = () => {};
  let apiArgs = null;
  let token = null;
  let failure = null;
  try {
    VM.a(arr[0], (...f) => { apiArgs = f; }, true, page.document.body, noop, [[], []],
      undefined, false, [noop, noop, noop, noop, noop]);
    for (let i = 0; i < 200 && !apiArgs; i++) drain(4);
    if (!apiArgs) throw new Error("VM.a never resolved");
    apiArgs[0]((t) => { token = String(t); }, [freq, undefined, undefined, undefined]);
    for (let i = 0; i < 400 && token === null; i++) drain(4);
  } catch (e) {
    failure = String(e && e.stack ? e.stack : e);
  }
  print(JSON.stringify({
    stage: failure ? "error" : "mint",
    error: failure,
    api: apiArgs ? apiArgs.map((x) => typeof x) : null,
    token_len: token ? token.length : 0,
    head: token ? token.slice(0, 64) : "",
    token: token || "",
    frames: shared.frames.length,
    ops_page: page.g.__ops ? page.g.__ops.length : 0,
    ops_frame: shared.frames.length && shared.frames[0].g.__ops ? shared.frames[0].g.__ops.slice(-40) : null,
    ops_frame_n: shared.frames.length && shared.frames[0].g.__ops ? shared.frames[0].g.__ops.length : 0,
    // fC() install trace (research patch): which field id each handler-table entry landed in.
    ins_page: page.g.__ins ? page.g.__ins.slice(0, 24) : null,
    ins_frame: shared.frames.length ? (shared.frames[0].g.__ins || []).slice(0, 24) : null,
    ins_frame_n: shared.frames.length && shared.frames[0].g.__ins ? shared.frames[0].g.__ins.length : 0,
  }));
}

main();
