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
CHROME = "/usr/bin/google-chrome-stable"

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
  for (const w of realms) {
    try {
      const n = Object.keys(w.__prog || {}).length;
      states.push({ prog: n, rd: (w.__rd || []).length, dump: (w.__dump || []).length });
      if (!found && (n || (w.__dump || []).length || (w.__rd || []).length)) found = w;
    } catch (e) {}
  }
  if (!found) return JSON.stringify({ tok: tok.length, head: tok.slice(0, 60), states: states,
                                      err: 'no instrumentation state in any realm' });
  const meta = found.__vmeta || {};
  const blocks = [];
  for (const k of Object.keys(found.__prog || {})) blocks.push([parseInt(k, 10), found.__prog[k]]);
  return JSON.stringify({ tok: tok.length, head: tok.slice(0, 24), V: meta.V,
                          nu: (meta.prog || []).length, seed: meta.seed,
                          nblocks: blocks.length, blocks: blocks,
                          sweep: found.__dump || [], sweepErr: String(found.__sweepErr || ''),
                          log: found.__rd || [], vals: found.__rv || [] });
})()"""


def validate(buf: bytearray, log: list, vals: list) -> dict:
    """Bit-slice the recovered buffer at every logged read and compare with the VM's value.

    Reads with the decrypt flag off (the 32-bit seed fetch) are skipped by construction:
    the recovered buffer is always decrypted.
    """
    bits = []
    for byte in buf:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    ok = bad = skipped = 0
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
            "malformed_entries": malformed, "first_mismatch": first}


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
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 300); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({ stage: 'install', evalErr: evalErr });
  if (!window.__MINE) return JSON.stringify({ stage: 'not-mine' });
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
  const collect = () => {
    walk(window);
    let best = null;
    for (const w of realms) {
      try {
        const log = (w.__vmref && w.__vmref.__wr) || w.__wr;
        if (!best && log && log.length) best = log.slice();
        if (w.__vmref && w.__vmref.__wr) w.__vmref.__wr = [];
        w.__wr = [];
      } catch (e) {}
    }
    return best || [];
  };
  collect();
  const tokA = await mint(fa);
  const wrA = collect();
  const tokB = await mint(fb);
  let tokC = null, wrC = null;
  if (mut !== null) {
    window.__mut = mut;
    tokC = await mint(fb);
    wrC = collect();
    window.__mut = null;
  }
  const wrB = collect();
  let meta = {};
  for (const w of realms) { try { if (!meta.V && w.__vmeta) meta = w.__vmeta; } catch (e) {} }
  const states = realms.map((w) => {
    try { return { wr: (w.__wr || []).length, rd: (w.__rd || []).length, jy: typeof w.__JY }; }
    catch (e) { return { err: 1 }; }
  });
  return JSON.stringify({ states: states, tokA: tokA.length, tokB: tokB.length,
                          tokC: tokC === null ? null : tokC.length, V: meta.V,
                          nu: (meta.prog || []).length, wrA: wrA, wrB: wrB, wrC: wrC });
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


class CS(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.doc_request = None
        self.body: bytes = b""
        self.served: list = []

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
              mutate: int | None = None, writers: bool = False) -> None:
    freq = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    cs = CS(CHROME, port, DEFAULT_UA, "/tmp/bg-dump-" + str(port))
    await cs.start()
    try:
        await cs.send("Network.enable")
        await cs.send("Fetch.enable", patterns=[{"urlPattern": "*js/bg/*", "requestStage": "Request"}])
        await cs.navigate(URL, settle=7)
        if not cs.doc_request:
            raise SystemExit("no document response captured")
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        arr = json.loads("[" + (parse_material(html)[4:]))
        plain = arr[5][-1]
        print(f"served /js/bg requests: {len([u for u in cs.served if '/js/bg/' in u])}")
        print(f"build: hash={arr[2]} blob={len(arr[0])} interp={len(plain)} ts={arr[4]}")
        if writers:
            src, info = bgpatch.patch(plain, entry=False, ret=False, boot=False, killswitch=True)
        else:
            src, info = bgpatch.patch(plain, blockcache=not (sweep or log_only or ab or fields),
                                      sweep=sweep or ab, writes=fields)
        arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
        cs.body = src.encode()
        print("patch:", {k: v for k, v in info.items() if k != "params"})
        if writers:
            n = int(info.get("writers_patched") or 0)
            d = json.loads(await cs.eval(WRITERS_JS % (json.dumps(arr), json.dumps(src),
                                                      json.dumps(freq), str(n))))
            print({k: v for k, v in d.items() if k != "runs"})
            for run in d.get("runs") or []:
                tag = {-1: "control", -2: "control after"}.get(run["k"], f"kill copy {run['k']}")
                print(f"  {tag:>14}: token_len={run['len']} head={run['head']!r}")
            return
        if fields:
            fb = freq if (same or mutate is not None) else (
                freq[:-8] + "AAAAAAA1" if len(freq) > 16 else freq + "B")
            # the write log comes back empty on some runs even though the reader fired (the
            # live writer can sit in a copy the anchor misses), so retry a few times before
            # treating an empty diff as a result
            d = {}
            for attempt in range(3):
                d = json.loads(await cs.eval(FIELDS_JS % (
                    json.dumps(arr), json.dumps(src), json.dumps(freq), json.dumps(fb),
                    "null" if mutate is None else str(mutate))))
                if d.get("wrA") and d.get("wrB"):
                    if attempt:
                        print(f"capture succeeded on attempt {attempt + 1}")
                    break
                print(f"attempt {attempt + 1}: empty write log, retrying")
                await asyncio.sleep(2)
            print({k: v for k, v in d.items() if k not in ("wrA", "wrB", "wrC", "states")})
            print("realm states:", d.get("states"))
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
            print(f"field writes: A={len(a)} B={len(b)}")
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
            blockhit = set()
            for entry in d.get("log") or []:
                cnt, start = int(entry[0]), int(entry[2])
                for b in range(start // 64, (start + cnt - 1) // 64 + 1):
                    blockhit.add(b)
            total = (nbytes + 7) // 8
            print(f"log-only: reads={len(d.get('log') or [])} blocks touched={len(blockhit)}"
                  f"/{total} ({round(len(blockhit) / max(total, 1), 4)})")
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
        print("validation:", validate(buf, d.get("log") or [], d.get("vals") or []))
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
                    a.mutate, a.writers))


if __name__ == "__main__":
    main()
