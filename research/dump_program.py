"""Recover the botguard program (`NU`) as plaintext and validate it against the reader log.

Usage: python3 research/dump_program.py [--sweep] [--port N] [--out DIR]

What it does, in one page load:

1. reads the page document body over CDP and parses `"mnsUbf"` out of it, so the program
   blob and the interpreter come from the *same* build pair (builds rotate per load; mixing
   a blob from one pair with an interpreter from another makes the inner program fail with
   `FNLSyntaxError`);
2. patches the interpreter (research/bgpatch.py), recomputes `arr[2]` = base64url(sha256) so
   the integrity gate still passes, and evaluates the patched text as the page's *first*
   string eval (the page enforces Trusted Types, a second eval of the same string is
   refused);
3. mints once with `blockcache` on: every natural read is logged, and each 64-bit block whose
   keystream the reader just regenerated is read out in full;
4. rebuilds the program buffer from those blocks, then bit-slices the buffer at every logged
   read position and compares with the value the VM itself returned.

`--sweep` instead forces the reader over every 8-bit offset in ascending order. That is the
negative experiment: the keystream factory is stateful, so a block's key depends on how many
blocks were regenerated before it, and the sweep only agrees with the natural plaintext for
the blocks whose visit order it happens to reproduce (measured: divergence from block 43).
"""
import argparse
import collections
import asyncio
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA, ChromeSession  # noqa: E402
import bgpatch  # noqa: E402

URL = "https://translate.google.com/?sl=auto&tl=zh-CN&op=images"
# The VM boots inside a frame that can be gone before the caller looks, so instrumentation
# state is written to the top window instead of the realm that runs the code.
TOP_SINK = "(window.top||window)"
CHROME = os.environ.get("BG_CHROME", "/usr/bin/google-chrome-stable")

JS = r"""(async () => {
  const arr = %s;
  const src = %s;
  const freq = %s;
  const sweepNow = %s;
  window.__sweepNow = sweepNow;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 300); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({ stage: 'install', evalErr: evalErr });
  if (!window.__MINE) return JSON.stringify({ stage: 'not-mine' });
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const tok = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  // the VM assembles a copy of the interpreter per realm, so the instrumentation state can
  // live in the page, in a frame, or in a detached frame - scan everything we can see.
  const realms = [window];
  const walk = (w) => {
    let frames = [];
    try { frames = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of frames) {
      try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {}
    }
  };
  walk(window);
  let found = null, states = [];
  const inst = (w) => {
    // logs live on the VM instance (see research/bgpatch.py); window is the fallback for the
    // patch hunk that has not been migrated yet
    const v = w.__vmref || {};
    return { rd: v.__rd || w.__rd || [], rv: v.__rv || w.__rv || [],
             prog: v.__prog || w.__prog || {}, dump: w.__dump || [] };
  };
  for (const w of realms) {
    try {
      const st = inst(w);
      const n = Object.keys(st.prog).length;
      states.push({ prog: n, rd: st.rd.length, dump: st.dump.length });
      if (!found && (n || st.dump.length || st.rd.length)) { found = w; window.__FOUND = st; }
    } catch (e) {}
  }
  if (!found) return JSON.stringify({ tok: tok.length, head: tok.slice(0, 60), states: states,
                                      err: 'no instrumentation state in any realm' });
  const meta = found.__vmeta || {};
  const st = window.__FOUND;
  const blocks = [];
  for (const k of Object.keys(st.prog)) blocks.push([parseInt(k, 10), st.prog[k]]);
  return JSON.stringify({ tok: tok.length, head: tok.slice(0, 24), V: meta.V,
                          nu: (meta.prog || []).length, seed: meta.seed,
                          nblocks: blocks.length, blocks: blocks,
                          sweep: st.dump, sweepErr: String(found.__sweepErr || ''),
                          ip: (found.__vmref && found.__vmref.__ip) || [],
                          hn: (found.__vmref && found.__vmref.__hn) || {},
                          tab: (function () {
                            // one row per field-table slot: the id, its own keys, and what the
                            // `prototype`/`value` members hold - an instruction's opcode is the id
                            // whose slot carries the handler, so this dumps the instruction set
                            const out = [];
                            const S = (f) => { try { return f(); } catch (q) { return null; } };
                            try {
                              const vm = found.__vmref, h = (vm && vm.h) || {};
                              for (const k of Object.keys(h)) {
                                const e = h[k];
                                const p = S(() => e.prototype);
                                out.push([+k,
                                  S(() => Object.keys(e).join(",")),
                                  S(() => typeof p),
                                  S(() => typeof e.value),
                                  S(() => String(p).slice(0, 200)),
                                  S(() => Object.keys(p).join(",")),
                                  S(() => String(p.constructor).slice(0, 120))]);
                              }
                            } catch (e) {}
                            return out;
                          })(),
                          log: st.rd, vals: st.rv });
})()"""


def validate(buf: bytearray, log: list, vals: list, known: bytearray | None = None) -> dict:
    """Bit-slice the recovered buffer at every logged read and compare with the VM's value.

    Reads with the decrypt flag off (the 32-bit seed fetch) are skipped by construction:
    the recovered buffer is always decrypted.
    """
    bits = []
    for byte in buf:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    ok = bad = skipped = uncovered = 0
    first = None
    malformed = 0
    for entry, val in zip(log, vals):
        if not (isinstance(entry, list) and len(entry) == 3
                and all(isinstance(x, (int, float, bool)) for x in entry)):
            malformed += 1
            continue
        cnt, flag, start = int(entry[0]), int(entry[1]), int(entry[2])
        logged = int(val[1]) if isinstance(val, list) else int(val)
        if flag == 0:
            skipped += 1
            continue
        if start + cnt > len(bits):
            continue
        if known is not None and not all(known[(start + i) >> 3] for i in range(cnt)):
            # a position the run never captured is zero in the buffer, so comparing there
            # would be a test of the zero fill, not of the recovery
            uncovered += 1
            continue
        got = 0
        for i in range(cnt):
            got = (got << 1) | bits[start + i]
        if got == logged:
            ok += 1
        else:
            bad += 1
            if first is None:
                first = {"start": start, "bits": cnt, "logged": logged, "recovered": got}
    return {"match": ok, "mismatch": bad, "skipped_plaintext": skipped,
            "uncovered_reads": uncovered, "malformed_entries": malformed,
            "first_mismatch": first}


MINT_JS = r"""(async () => {
  const arr = %s;
  if (typeof window.ridgeslice === 'undefined') { (0, eval)(%s); }
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { window.ridgeslice.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const token = await new Promise((res) => api[0]((t) => res(String(t)), [%s, undefined, undefined, undefined]));
  return JSON.stringify({token: String(token).length, head: String(token).slice(0, 32)});
})()"""


FRAME_ANCHORS = ("__ip", "z(230", "x(44", "G(339", "NU[", "cF[", "x9[", "sourceMappingURL")


async def dump_frame_scripts(cs, arr, plain: str, out: str) -> None:
    """Mint once with the pristine interpreter, then dump every compiled script >= 4 KB."""
    import json as _json
    freq = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    res = _json.loads(await cs.eval(MINT_JS % (json.dumps(arr), json.dumps(plain),
                                               json.dumps(freq))))
    print("pristine mint:", res)
    print(f"compiled scripts: {len(cs.scripts)}")
    rows = []
    for sid in cs.script_order:
        meta = cs.scripts.get(sid) or {}
        if (meta.get("len") or 0) < 4000:
            continue
        try:
            src = (await cs.send("Debugger.getScriptSource", scriptId=sid)).get("scriptSource", "")
        except Exception as e:
            print(f"  {sid}: source unavailable ({e})")
            continue
        open(os.path.join(out, f"script_{sid}.js"), "w").write(src)
        hits = {k: src.count(k) for k in FRAME_ANCHORS if src.count(k)}
        rows.append((sid, meta.get("len"), len(src), meta.get("ctx"), meta.get("url", "")))
        print(f"  {sid}: reported {meta.get('len')} src {len(src)} ctx {meta.get('ctx')} "
              f"url {meta.get('url', '')[:50]!r}")
        print(f"      anchors {hits}")
    json.dump({"build": arr[2], "interp": len(plain), "scripts": rows},
              open(os.path.join(out, "scripts.json"), "w"), indent=1)


AB_JS = r"""(async () => {
  const arr = %s;
  const src = %s;
  const freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 300); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({ stage: 'install', evalErr: evalErr });
  if (!window.__MINE) return JSON.stringify({ stage: 'not-mine' });
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const mint = async () => {
    const api = await new Promise((res, rej) => {
      try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
      catch (e) { rej(e); }
    });
    return await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  };
  const realms = [window];
  const walk = (w) => {
    let frames = [];
    try { frames = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of frames) {
      try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {}
    }
  };
  window.__sweepNow = false;
  const tok1 = await mint();
  walk(window);
  let st = null;
  for (const w of realms) { try { if (!st && (w.__rd || []).length) st = w; } catch (e) {} }
  if (!st) return JSON.stringify({ stage: 'no log', tok1: tok1.length });
  const log = (st.__rd || []).slice(), vals = (st.__rv || []).slice();
  const meta = st.__vmeta || {};
  window.__sweepNow = true;
  let tok2 = '';
  try { tok2 = await mint(); } catch (e) { tok2 = 'THROW'; }
  let sw = null;
  for (const w of realms) { try { if (!sw && (w.__dump || []).length) sw = w; } catch (e) {} }
  return JSON.stringify({ tok1: tok1.length, tok2: String(tok2).length, V: meta.V,
                          nu: (meta.prog || []).length, seed: meta.seed,
                          sweep: (sw && sw.__dump) || [], log: log, vals: vals });
})()"""


TWICE_JS = r"""(async () => {
  const arr = %s;
  const src = %s;
  const freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 300); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({ stage: 'install', evalErr: evalErr });
  if (!window.__MINE) return JSON.stringify({ stage: 'not-mine' });
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const realms = [window];
  const walk = (w) => {
    let frames = [];
    try { frames = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of frames) {
      try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {}
    }
  };
  const mint = async () => {
    const api = await new Promise((res, rej) => {
      try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
      catch (e) { rej(e); }
    });
    return await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  };
  const collect = () => {
    walk(window);
    // prefer the state the frame pushed out (it may be gone by now)
    if ((window.__MSGS || []).length) {
      const last = window.__MSGS[window.__MSGS.length - 1];
      try {
        const o = JSON.parse(last);
        const rd = o.rd || [], wr = o.wr || [];
        if (rd.length || wr.length) {
          window.__MSGS = [];
          return { rd: rd, wr: wr };
        }
      } catch (e) {}
    }
    for (const w of realms) {
      try { if (w.__prog && Object.keys(w.__prog).length) return w; } catch (e) {}
    }
    return null;
  };
  const take = (w) => {
    const out = {};
    for (const k of Object.keys(w.__prog || {})) out[k] = w.__prog[k];
    return out;
  };
  const tok1 = await mint();
  const w1 = collect();
  if (!w1) return JSON.stringify({ stage: 'no capture 1', tok1: tok1.length });
  const first = take(w1);
  const meta = w1.__vmeta || {};
  for (const w of realms) { try { w.__prog = {}; } catch (e) {} }
  const tok2 = await mint();
  const w2 = collect();
  const second = w2 ? take(w2) : {};
  return JSON.stringify({ tok1: tok1.length, tok2: String(tok2).length, V: meta.V,
                          nu: (meta.prog || []).length, seed: meta.seed,
                          first: Object.entries(first), second: Object.entries(second) });
})()"""


FIELDS_JS = r"""(async () => {
  const arr = %s;
  const src = %s;
  const fa = %s;
  const fb = %s;
  const mut = %s;
  const early = %s;
  let evalErr = null;
  if (!early) {
    try { delete window.ridgeslice; } catch (e) {}
    try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 300); }
  }
  const VM = (early && window.__MINEV) || window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({ stage: 'install', early: early, evalErr: evalErr });
  if (!window.__MINE) return JSON.stringify({ stage: 'not-mine', early: early });
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const realms = [];
  const walk = (w) => {
    realms.push(w);
    let frames = [];
    try { frames = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of frames) {
      try { const c = f.contentWindow; if (c) walk(c); } catch (e) {}
    }
  };
  const mint = async (freq) => {
    const api = await new Promise((res, rej) => {
      try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
      catch (e) { rej(e); }
    });
    return await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  };
  let lastSt = null;
  const collect = () => {
    walk(window);
    // prefer the state the frame pushed out (it may be gone by now)
    if ((window.__MSGS || []).length) {
      const last = window.__MSGS[window.__MSGS.length - 1];
      try {
        const o = JSON.parse(last);
        const rd = o.rd || [], wr = o.wr || [];
        if (rd.length || wr.length) {
          window.__MSGS = [];
          return { rd: rd, wr: wr };
        }
      } catch (e) {}
    }
    let best = null;
    for (const w of realms) {
      try {
        const log = (w.__vmref && w.__vmref.__wr) || w.__wr;
        if (!best && log && log.length) { best = log.slice(); lastSt = w; }
        if (w.__vmref && w.__vmref.__wr) w.__vmref.__wr = [];
        w.__wr = [];
      } catch (e) {}
    }
    return best || [];
  };
  collect();
  const tokA = await mint(fa);
  // `ridgeslice` is the module namespace, not the instance, so `__booted` cannot be read off
  // it. Instead: did *any* realm end up holding patched state? If none did, the mint was
  // served by a pristine copy and only a page reload can change that.
  walk(window);
  let anyState = false;
  for (const w of realms) {
    try {
      if (w.__booted || w.__vmeta || (w.__vmref && (w.__vmref.__wr || []).length) || (w.__wr || []).length) { anyState = true; break; }
    } catch (e) {}
  }
  if (!anyState) return JSON.stringify({ stage: 'pristine-vm', tokA: tokA.length, realms: realms.length });
  const gotA = collect();
  const wrA = Array.isArray(gotA) ? gotA : (gotA.wr || []);
  const tokB = await mint(fb);
  const gotB = collect();
  const wrB = Array.isArray(gotB) ? gotB : (gotB.wr || []);
  let tokC = null, wrC = null;
  if (mut !== null) {
    window.__mut = mut;
    tokC = await mint(fb);
    wrC = collect();
    window.__mut = null;
  }
  let meta = {};
  for (const w of realms) { try { if (!meta.V && w.__vmeta) meta = w.__vmeta; } catch (e) {} }
  const vmDiag = {};
  try {
    vmDiag.booted = VM.__booted || window.__booted || 0;
    vmDiag.entry = window.__REntry || 0;
    vmDiag.comp = (window.__comp || []).slice(0, 6);
    vmDiag.msgs = (window.__MSGS || []).length;
    vmDiag.evs = (window.__evs || []).slice(0, 6);
    vmDiag.topRd = (window.__rd || []).length;
    vmDiag.topWr = (window.__wr || []).length;
    vmDiag.vmeta = VM.__vmeta ? 1 : 0;
    vmDiag.rd = (VM.__rd || []).length;
    vmDiag.wr = (VM.__wr || []).length;
    vmDiag.inst = [];
    vmDiag.prog = (VM.__prog ? Object.keys(VM.__prog).length : 0);
    vmDiag.isGlobal = (window.ridgeslice === VM) ? 1 : 0;
    vmDiag.aCalls = window.__aCalls || 0;
    vmDiag.aVals = window.__aVals || 0;
    vmDiag.aLen = (typeof VM.a === 'function') ? String(VM.a).length : -1;
  } catch (e) { vmDiag.err = String(e); }
  const states = realms.map((w) => {
    try {
      const v = w.__vmref || {};
      return { wr: ((v.__wr || w.__wr) || []).length, rd: ((v.__rd || w.__rd) || []).length,
               jy: typeof w.__JY };
    } catch (e) { return { err: 1 }; }
  });
  const iv = (lastSt && lastSt.__vmref) || {};
  return JSON.stringify({ vmDiag: vmDiag, states: states, tokA: tokA.length, tokB: tokB.length,
                          tokC: tokC === null ? null : tokC.length, V: meta.V,
                          nu: (meta.prog || []).length, wrA: wrA, wrB: wrB, wrC: wrC,
                          rd: iv.__rd || (lastSt && lastSt.__rd) || [],
                          rv: iv.__rv || (lastSt && lastSt.__rv) || [],
                          ip: iv.__ip || [], hn: iv.__hn || {} });
})()"""


WRITERS_JS = r"""(async () => {
  const arr = %s;
  const src = %s;
  const freq = %s;
  const nCopies = %s;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 300); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({ stage: 'install', evalErr: evalErr });
  if (!window.__MINE) return JSON.stringify({ stage: 'not-mine' });
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const realms = [window];
  const walk = (w) => {
    let frames = [];
    try { frames = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of frames) {
      try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {}
    }
  };
  const setKill = (k) => {
    walk(window);
    for (const w of realms) { try { w.__kill = k; } catch (e) {} }
  };
  const mint = async () => {
    const api = await new Promise((res, rej) => {
      try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
      catch (e) { rej(e); }
    });
    return await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  };
  const out = [];
  const control = await mint();
  out.push({ k: -1, len: control.length, head: control.slice(0, 24) });
  for (let k = 0; k < nCopies; k++) {
    setKill(k);
    let tok = '';
    try { tok = await mint(); } catch (e) { tok = 'THROW'; }
    out.push({ k: k, len: String(tok).length, head: String(tok).slice(0, 24) });
  }
  setKill(-1);
  let after = '';
  try { after = await mint(); } catch (e) { after = 'THROW'; }
  out.push({ k: -2, len: String(after).length, head: String(after).slice(0, 24) });
  return JSON.stringify({ runs: out, realms: realms.length });
})()"""



async def read_doc_material(cs, reload_page: bool = False):
    """(Re)load the page and return the parsed material of the document that is now live."""
    if reload_page:
        cs.doc_request = None
        await cs.send("Page.reload")
        await asyncio.sleep(7)
    if not cs.doc_request:
        raise SystemExit("no document response captured")
    body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
    html = body.get("body", "")
    if body.get("base64Encoded"):
        html = base64.b64decode(html).decode("utf-8", "replace")
    arr = json.loads("[" + (parse_material(html)[4:]))
    return arr


class CS(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.doc_request = None
        self.body: bytes = b""
        self.served: list = []
        # every compiled script the debugger reports; the VM's real code is one of these and
        # does not live in the page realm (section 24), so this is the only way to see it
        self.scripts: dict = {}
        self.script_order: list = []

    async def send(self, method, **params):
        self._id += 1
        mid = self._id
        fut = self._loop.create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        return await asyncio.wait_for(fut, timeout=900)

    async def _read(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(Exception(str(msg["error"])))
                        else:
                            fut.set_result(msg.get("result", {}))
                elif msg.get("method") == "Fetch.requestPaused":
                    p = msg["params"]
                    url = p.get("request", {}).get("url", "")
                    self.served.append(url)
                    if "/js/bg/" in url and self.body:
                        # serve the patched interpreter for the by-hash request too: if the VM
                        # fetches its own copy, every patch in arr[5][-1] is inert without this
                        await self.send("Fetch.fulfillRequest", requestId=p["requestId"],
                                        responseCode=200,
                                        responseHeaders=[{"name": "content-type",
                                                          "value": "application/javascript; charset=utf-8"}],
                                        body=base64.b64encode(self.body).decode())
                    else:
                        await self.send("Fetch.continueRequest", requestId=p["requestId"])
                elif msg.get("method") == "Debugger.scriptParsed":
                    p = msg["params"]
                    self.scripts[p.get("scriptId")] = {
                        "url": p.get("url", ""), "len": p.get("length", 0),
                        "ctx": p.get("executionContextId")}
                    self.script_order.append(p.get("scriptId"))
                elif msg.get("method") == "Network.responseReceived":
                    p = msg["params"]
                    if p.get("type") == "Document" and self.doc_request is None:
                        self.doc_request = p["requestId"]
        except Exception:
            pass


def parse_material(html: str) -> str:
    i = html.find('"mnsUbf":')
    if i < 0:
        raise SystemExit("mnsUbf missing from the document body")
    start = html.index('"', i + len('"mnsUbf":'))
    material, _ = json.JSONDecoder().raw_decode(html[start:])
    return material


async def run(sweep: bool, port: int, out: str, log_only: bool = False, ab: bool = False,
              twice: bool = False, fields: bool = False, same: bool = False,
              mutate: int | None = None, writers: bool = False, early: bool = False,
              loop: bool = False, frame_scripts: bool = False, handlers: bool = False) -> None:
    freq = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    cs = CS(CHROME, port, DEFAULT_UA, "/tmp/bg-dump-" + str(port))
    await cs.start()
    try:
        await cs.send("Network.enable")
        await cs.send("Fetch.enable", patterns=[{"urlPattern": "*js/bg/*", "requestStage": "Request"}])
        if frame_scripts:
            await cs.send("Debugger.enable")
        await cs.navigate(URL, settle=7)
        if not cs.doc_request:
            raise SystemExit("no document response captured")
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        arr = json.loads("[" + (parse_material(html)[4:]))
        plain = arr[5][-1]
        # keep the same-build material: builds rotate per load, so a patching failure can only
        # be diagnosed against the interpreter that this exact load served.
        tag = str(arr[2])[:16]
        os.makedirs(out, exist_ok=True)
        open(os.path.join(out, "interp_" + tag + ".js"), "w").write(plain)
        open(os.path.join(out, "blob_" + tag + ".txt"), "w").write(arr[0])
        print(f"served /js/bg requests: {len([u for u in cs.served if '/js/bg/' in u])}")
        print(f"build: hash={arr[2]} blob={len(arr[0])} interp={len(plain)} ts={arr[4]}")
        if frame_scripts:
            await dump_frame_scripts(cs, arr, plain, out)
            return
        if writers:
            src, info = bgpatch.patch(plain, entry=False, ret=False, boot=False, killswitch=True)
        else:
            src, info = bgpatch.patch(plain, blockcache=not (sweep or log_only or ab or fields),
                                      sweep=sweep or ab, writes=fields, loop=loop,
                                      handlers=handlers)
        arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
        cs.body = src.encode()
        print("patch:", {k: v for k, v in info.items() if k != "params"})
        if frame_scripts:
            await dump_frame_scripts(cs, arr, plain, out)
            return
        if writers:
            n = int(info.get("writers_patched") or 0)
            d = json.loads(await cs.eval(WRITERS_JS % (json.dumps(arr), json.dumps(src),
                                                      json.dumps(freq), str(n))))
            print({k: v for k, v in d.items() if k != "runs"})
            for run in d.get("runs") or []:
                tag = {-1: "control", -2: "control after"}.get(run["k"], f"kill copy {run['k']}")
                print(f"  {tag:>14}: token_len={run['len']} head={run['head']!r}")
            return
        if fields and early:
            # The page's own bootguard sometimes wins the race for `ridgeslice`, after which the
            # eval-ed copy is installed but never executed. Inject the patched interpreter at
            # document start instead, so it claims the name before any page script runs. The
            # material and the interpreter must be the same build, and the build rotates per
            # load, so retry until two consecutive loads agree on the unpatched hash.
            script_id = None
            orig = None
            arr = src = info = None
            for attempt in range(5):
                arr = await read_doc_material(cs, reload_page=script_id is not None)
                if script_id is not None and arr[2] == orig:
                    print(f"attempt {attempt + 1}: build {orig[:16]} matches the injected copy")
                    break
                if script_id is not None:
                    await cs.send("Page.removeScriptToEvaluateOnNewDocument", identifier=script_id)
                    script_id = None
                orig = arr[2]
                src, info = bgpatch.patch(arr[5][-1], blockcache=False, writes=True,
                                          canary=True, post=True)
                print(f"attempt {attempt + 1}: injected patched interpreter for build "
                      f"{orig[:16]}, reloading")
                # Clear the name first (the page's own bootguard may have claimed it) and keep
                # our object under a private name, because whoever writes `window.ridgeslice`
                # last wins the global - and the page has more chances to write it than we do.
                injected = ("try{window.ridgeslice=void 0}catch(e){};" + src
                            + ";window.__MINE=1;window.__MINEV=window.ridgeslice;"
                            "window.__aCalls=0;window.__aVals=0;window.__comp=[];window.__evs=[];"
                            "window.__MSGS=[];window.addEventListener(String.fromCharCode(109,"
                            "101,115,115,97,103,101),function(e){window.__MSGS.push(e.data);});"
                            "(function(){var F=window.Function;window.Function=function(){"
                            "try{var a=arguments[arguments.length-1];var t=String(a);"
                            "window.__comp.push([t.length,t.indexOf('__MINE'),t.slice(0,40)]);}"
                            "catch(e){}return F.apply(this,arguments);};})();"
                            "(function(){var e=window.eval;window.eval=function(x){"
                            "try{var t=String(x);window.__evs.push([t.length,t.indexOf('__MINE'),t.slice(0,40)]);"
                            "window.parent.postMessage(JSON.stringify({e:t.length,m:t.indexOf('__MINE'),"
                            "h:t.slice(0,60)}),String.fromCharCode(42));}"
                            "catch(q){}return e.call(window,x);};})();"
                            "(function(){var v=window.__MINEV;if(!v||typeof v.a!==125)try{}catch(e){} })();"
                            "(function(){var v=window.__MINEV;if(v&&typeof v.a==='function'){var o=v.a;"
                            "v.a=function(){window.__aCalls++;var r=o.apply(this,arguments);"
                            "if(r&&typeof r==='object')window.__aVals++;return r;};}})();")
                r = await cs.send("Page.addScriptToEvaluateOnNewDocument", source=injected)
                script_id = r.get("identifier")
            else:
                raise SystemExit("could not line up two loads on the same build")
            arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
            cs.body = src.encode()
            print("patch:", {k: v for k, v in info.items() if k != "params"})
            fb = freq if (same or mutate is not None) else (
                freq[:-8] + "AAAAAAA1" if len(freq) > 16 else freq + "B")
            d = json.loads(await cs.eval(FIELDS_JS % (
                json.dumps(arr), json.dumps(src), json.dumps(freq), json.dumps(fb),
                "null" if mutate is None else str(mutate), "true")))
            print({k: v for k, v in d.items() if k not in ("wrA", "wrB", "wrC", "states")})
            print("vm diag:", d.get("vmDiag"), "| realms:", len(d.get("states") or []))
            a, b = d.get("wrA") or [], d.get("wrB") or []
            print(f"field writes: A={len(a)} B={len(b)}"
                  f"  instructions={len(d.get('ip') or [])}  handlers={len(d.get('hn') or {})}")
            if a and b:
                differ = [(x, y) for x, y in zip(a, b) if x != y]
                print("positions differing:", len(differ))
                for x, y in differ[:10]:
                    print("  A", x[0], x[1], str(x[2])[:60])
                    print("  B", y[0], y[1], str(y[2])[:60])
                ids = {}
                for x in a:
                    ids.setdefault(x[0], []).append((x[1], len(x[2] or "")))
                print("distinct field ids written:", len(ids))
                json.dump(d, open(os.path.join(out, "run_fields_early.json"), "w"))
            return
        if fields:
            fb = freq if (same or mutate is not None) else (
                freq[:-8] + "AAAAAAA1" if len(freq) > 16 else freq + "B")
            # Two independent failures look identical from the outside (an empty write log):
            # a live writer copy the anchor misses, and the page's own bootguard winning the
            # race for `ridgeslice` so the VM we call is pristine. The patch marks the instance
            # (`VM.__booted`), so the injected script can tell them apart - and a pristine VM is
            # only fixable by reloading the page, not by re-minting.
            d = {}
            for attempt in range(4):
                d = json.loads(await cs.eval(FIELDS_JS % (
                    json.dumps(arr), json.dumps(src), json.dumps(freq), json.dumps(fb),
                    "null" if mutate is None else str(mutate), "false")))
                if d.get("wrA") and d.get("wrB"):
                    if attempt:
                        print(f"capture succeeded on attempt {attempt + 1}")
                    break
                if d.get("stage") == "pristine-vm":
                    print(f"attempt {attempt + 1}: the VM under test is not the patched copy,"
                          " reloading the page")
                    arr = await read_doc_material(cs, reload_page=True)
                    plain = arr[5][-1]
                    tag = str(arr[2])[:16]
                    open(os.path.join(out, "interp_" + tag + ".js"), "w").write(plain)
                    open(os.path.join(out, "blob_" + tag + ".txt"), "w").write(arr[0])
                    src, info = bgpatch.patch(plain, blockcache=False, writes=True,
                                              loop=loop, handlers=handlers)
                    arr[2] = base64.urlsafe_b64encode(
                        hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
                    cs.body = src.encode()
                    print(f"           rebuilt against build {arr[2][:16]}, patch:",
                          {k: v for k, v in info.items() if k not in ("params", "wrappers")})
                    continue
                print(f"attempt {attempt + 1}: empty write log, retrying")
                await asyncio.sleep(2)
            print({k: v for k, v in d.items() if k not in ("wrA", "wrB", "wrC", "states")})
            print("vm diag:", d.get("vmDiag"), "| realms:", len(d.get("states") or []))
            a, b = d.get("wrA") or [], d.get("wrB") or []
            if not a or not b:
                return
            c = d.get("wrC")
            if c is not None:
                noise = {x[0] for x, y in zip(a, b) if x != y}
                effect = [(x, z) for x, z in zip(a, c) if x != z and x[0] not in noise]
                print(f"baseline noise ids (same payload, no mutation): {sorted(noise)}")
                print(f"mutation-only differences: {len(effect)}")
                for x, z in effect[:15]:
                    print("  ", x[0], x[1], str(x[2])[:60], "->", z[1], str(z[2])[:60])
            print(f"field writes: A={len(a)} B={len(b)}"
                  f"  instructions={len(d.get('ip') or [])}  handlers={len(d.get('hn') or {})}")
            differ = [(x, y) for x, y in zip(a, b) if x != y]
            print("positions differing:", len(differ))
            for x, y in differ[:12]:
                print("  A", x[0], x[1], str(x[2])[:70])
                print("  B", y[0], y[1], str(y[2])[:70])
            ids = {}
            for x in a:
                ids.setdefault(x[0], []).append((x[1], len(x[2] or "")))
            print("distinct field ids written:", len(ids))
            print("id -> [(size, json_len)]:", {k: v[:3] for k, v in list(ids.items())[:40]})
            json.dump(d, open(os.path.join(out, "run_fields.json"), "w"))
            return
        if twice:
            d = json.loads(await cs.eval(TWICE_JS % (json.dumps(arr), json.dumps(src),
                                                     json.dumps(freq))))
            print({k: v for k, v in d.items() if k not in ("first", "second")})
            nbytes = d.get("nu") or 0
            if not nbytes:
                return
            bufs = []
            for tag in ("first", "second"):
                buf = bytearray(nbytes)
                mask = bytearray(nbytes)
                for idx, vals in d.get(tag) or []:
                    for k, val in enumerate(vals):
                        pos = int(idx) * 8 + k
                        if pos < nbytes:
                            buf[pos] = int(val) & 255
                            mask[pos] = 1
                print(tag, "blocks", len(d.get(tag) or []), "bytes", sum(mask))
                bufs.append((buf, mask))
            (b1, m1), (b2, m2) = bufs
            both = sum(1 for i in range(nbytes) if m1[i] and m2[i])
            same = sum(1 for i in range(nbytes) if m1[i] and m2[i] and b1[i] == b2[i])
            print(f"overlap {both} bytes, identical {same}",
                  round(same / both, 4) if both else "-")
            diff = [i for i in range(nbytes) if m1[i] and m2[i] and b1[i] != b2[i]]
            print("differing offsets:", diff[:10], "count", len(diff))
            open(os.path.join(out, "program_twice_1.bin"), "wb").write(bytes(b1))
            open(os.path.join(out, "program_twice_2.bin"), "wb").write(bytes(b2))
            return
        if ab:
            d = json.loads(await cs.eval(AB_JS % (json.dumps(arr), json.dumps(src),
                                                   json.dumps(freq))))
            dump, nbytes = d.get("sweep") or [], d.get("nu") or 0
            print({k: v for k, v in d.items() if k not in ("sweep", "log", "vals")})
            if not dump or not nbytes:
                return
            buf = bytearray(x & 255 for x in dump[:nbytes])
            print("sweep coverage:", len(buf), "/", nbytes)
            print("validation:", validate(buf, d.get("log") or [], d.get("vals") or []))
            open(os.path.join(out, "program_sweep_ab.bin"), "wb").write(bytes(buf))
            json.dump(d, open(os.path.join(out, "run_sweep_ab.json"), "w"))
            return
        d = json.loads(await cs.eval(JS % (json.dumps(arr), json.dumps(src), json.dumps(freq),
                                            "true" if sweep else "false")))
        print({k: v for k, v in d.items() if k not in ("blocks", "sweep", "log", "vals")})
        nbytes = d.get("nu") or 0
        if log_only:
            raw = d.get("log") or []
            reads = [e for e in raw if isinstance(e, list) and len(e) == 3
                     and all(isinstance(x, (int, float, bool)) for x in e)]
            blockhit = set()
            for entry in reads:
                cnt, start = int(entry[0]), int(entry[2])
                for b in range(start // 64, (start + cnt - 1) // 64 + 1):
                    blockhit.add(b)
            total = (nbytes + 7) // 8
            ip = [x for x in (d.get("ip") or [])
                  if isinstance(x, (int, float)) or (isinstance(x, list) and len(x) == 2)]
            ptrs = [x[0] if isinstance(x, list) else x for x in ip]
            depth = collections.Counter(x[1] for x in ip if isinstance(x, list))
            rows = d.get("tab") or []
            tab = {int(t[0]): t for t in rows if isinstance(t, list) and t}
            ptypes = {}
            for v in tab.values():
                ptypes[v[2] if len(v) > 2 else "?"] = ptypes.get(v[2] if len(v) > 2 else "?", 0) + 1
            print(f"field table: {len(tab)} ids, prototype types {ptypes}")
            hn = d.get("hn") or {}
            print(f"handlers captured at dispatch: {len(hn)}")
            for v in rows[:3]:
                print("   sample", v)
            print(f"log-only: reads={len(reads)} (malformed {len(raw) - len(reads)})"
                  f" blocks touched={len(blockhit)}/{total}"
                  f" ({round(len(blockhit) / max(total, 1), 4)})"
                  f"  instructions={len(ip)} distinct_ips={len(set(ptrs))}"
                  f" monotone={ptrs == sorted(ptrs)} depths={dict(depth)}")
            json.dump({"build": {"hash": arr[2], "blob": len(arr[0]), "interp": len(plain)},
                       "info": info, "run": d},
                      open(os.path.join(out, "run_log.json"), "w"))
            print("wrote", os.path.join(out, "run_log.json"))
            return
        if sweep:
            dump = d.get("sweep") or []
            if not dump or not nbytes:
                return
            buf = bytearray(x & 255 for x in dump[:nbytes])
            print("sweep coverage:", len(buf), "/", nbytes)
        else:
            blocks = d.get("blocks") or []
            if not blocks or not nbytes:
                return
            buf = bytearray(nbytes)
            mask = bytearray(nbytes)
            for idx, vals in blocks:
                for k, val in enumerate(vals):
                    pos = idx * 8 + k
                    if pos < nbytes:
                        buf[pos] = int(val) & 255
                        mask[pos] = 1
            print("blocks:", len(blocks), "bytes known:", sum(mask), "/", nbytes,
                  round(sum(mask) / nbytes, 4))
            print("validation:", validate(buf, d.get("log") or [], d.get("vals") or [], mask))
        os.makedirs(out, exist_ok=True)
        tag = "sweep" if sweep else "blocks"
        open(os.path.join(out, f"program_{tag}.bin"), "wb").write(bytes(buf))
        json.dump({"build": {"hash": arr[2], "blob": len(arr[0]), "interp": len(plain)},
                   "info": info, "run": d}, open(os.path.join(out, f"run_{tag}.json"), "w"))
        print("wrote", os.path.join(out, f"program_{tag}.bin"),
              "sha256", hashlib.sha256(bytes(buf)).hexdigest()[:16])
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", action="store_true", help="force a full ascending sweep (negative control)")
    ap.add_argument("--port", type=int, default=10220)
    ap.add_argument("--out", default="/tmp/bg-dump")
    ap.add_argument("--log-only", action="store_true", help="passive log only, no block capture")
    ap.add_argument("--frame-scripts", action="store_true",
                    help="mint with the pristine interpreter and dump every compiled script")
    ap.add_argument("--handlers", action="store_true",
                    help="with --loop: capture String(handler) once per dispatched op id")
    ap.add_argument("--loop", action="store_true",
                    help="log the instruction-loop pointer, i.e. one entry per executed instruction")
    ap.add_argument("--early", action="store_true",
                    help="with --fields: inject the patched interpreter at document start")
    ap.add_argument("--writers", action="store_true",
                    help="probe which writer copy is live by aborting each in turn")
    ap.add_argument("--mutate", type=int, default=None,
                    help="with --fields: flip plaintext program byte N before the second mint")
    ap.add_argument("--same", action="store_true",
                    help="with --fields: use the identical payload twice (isolates per-sign noise)")
    ap.add_argument("--fields", action="store_true",
                    help="two mints with different payloads; log and diff every field write")
    ap.add_argument("--twice", action="store_true",
                    help="two mints in one page; compare the two recovered buffers")
    ap.add_argument("--ab", action="store_true",
                    help="mint once naturally then once with the forced sweep (negative control)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    asyncio.run(run(a.sweep, a.port, a.out, a.log_only, a.ab, a.twice, a.fields, a.same,
                    a.mutate, a.writers, a.early, a.loop, a.frame_scripts, a.handlers))


if __name__ == "__main__":
    main()
