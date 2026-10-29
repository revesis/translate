"""Same build, two realms: what the VM records in Chrome versus outside a browser.

The Node harness (`research/node_mint.mjs`) reaches the frame path and mints, but its token
is in the degraded size regime. To find the difference without guessing, run *the same*
build material through Chrome (trusted path) and through Node, and compare the three things
the VM itself records:

  * the frame-boot event array (`A` in the boot handler: load/error/retry + timings),
  * the serializer's field profile (`concat` calls, i.e. `nonce(2) + field(n)`),
  * the pre-base64 token bytes.

Hooks are installed in *every* execution context via `Page.addScriptToEvaluateOnNewDocument`
plus `Runtime.executionContextCreated`, which sections 2b/5 measured to be invisible to the
VM (the token stays in the trusted range).

    python3 research/probe_realm.py --material /tmp/bgbuild/material.json --out /tmp/bg-realm
"""
import argparse
import asyncio
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA, ChromeSession, PAGE_URL  # noqa: E402

HOOK = r"""(function(){
  if (window.__rlog) return 'already';
  window.__rlog = {push: [], cat: [], bt: []};
  var P = Array.prototype, push = P.push, concat = P.concat;
  // The boot handler's event array is short and numeric; anything longer is payload noise.
  P.push = function(){
    try {
      if (this.length <= 8 && typeof arguments[0] === 'number')
        window.__rlog.push.push([this.length].concat(Array.prototype.slice.call(arguments).map(function(v){
          return typeof v === 'number' ? v : (v && v.length) || typeof v;
        })));
    } catch (e) {}
    return push.apply(this, arguments);
  };
  P.concat = function(){
    try {
      var out = concat.apply(this, arguments), n = 0;
      for (var i = 0; i < arguments.length; i++) n += (arguments[i] && arguments[i].length) || 0;
      if (out.length > 200) window.__rlog.cat.push([this.length, n, out.length]);
    } catch (e) {}
    return concat.apply(this, arguments);
  };
  var orig = window.btoa;
  if (orig) window.btoa = function(s){
    try { window.__rlog.bt.push({len: String(s).length, s: String(s)}); } catch (e) {}
    return orig.apply(this, arguments);
  };
  return 'hooked';
})()"""

MINT = r"""(async () => {
  const arr = %s, freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(%s); } catch (e) { evalErr = String(e).slice(0, 300); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({stage: 'install', evalErr: evalErr});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const tok = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  const realms = [window];
  const walk = (w) => {
    let fs = [];
    try { fs = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of fs) { try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {} }
  };
  walk(window);
  const logs = realms.map((w) => { try { return w.__rlog || null; } catch (e) { return null; } });
  return JSON.stringify({tok: tok, logs: logs});
})()"""


class RS(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.hooked = set()
        self.scripts: list = []

    async def _read(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(RuntimeError(str(msg["error"])))
                        else:
                            fut.set_result(msg.get("result", {}))
                elif msg.get("method") == "Debugger.scriptParsed":
                    p = msg["params"]
                    self.scripts.append({"id": p.get("scriptId"), "ctx": p.get("executionContextId"),
                                         "url": p.get("url", ""), "len": p.get("length", 0)})
                elif msg.get("method") == "Runtime.executionContextCreated":
                    ctx = msg["params"]["context"]
                    cid = ctx.get("id")
                    if cid in self.hooked:
                        continue
                    self.hooked.add(cid)
                    # Install without waiting for the reply: this runs on the reader task and
                    # a frame's own code may already be queued behind it.
                    self._id += 1
                    await self.ws.send(json.dumps({"id": self._id, "method": "Runtime.evaluate",
                                                   "params": {"expression": HOOK, "contextId": cid}}))
                    self._pending.pop(self._id, None)
        except Exception:  # noqa: BLE001
            pass


async def run(material_path: str, out: str, port: int) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    cs = RS("/usr/bin/google-chrome-stable", port, DEFAULT_UA, "/tmp/bg-realm-%d" % port)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs.send("Page.addScriptToEvaluateOnNewDocument", source=HOOK, runImmediately=True)
        await cs.navigate(PAGE_URL, settle=7)
        d = json.loads(await cs.eval(MINT % (json.dumps(arr), json.dumps(freq), json.dumps(interp))))
        tok = d.get("tok") or ""
        os.makedirs(out, exist_ok=True)
        json.dump(d, open(os.path.join(out, "realm.json"), "w"))
        raw = tok[1:] if tok.startswith(";") else tok
        pad = "=" * (-len(raw) % 4)
        blob = base64.urlsafe_b64decode(raw + pad)
        open(os.path.join(out, "token.bin"), "wb").write(blob)
        print("token chars", len(tok), "bytes", len(blob), "head", blob[:16].hex())
        for i, lg in enumerate(d.get("logs") or []):
            if not lg:
                continue
            print("realm", i, "boot-pushes", lg["push"], "concat", lg["cat"], "btoa", [b["len"] for b in lg["bt"]])
        # Every eval the VM performs becomes a script with an empty URL; the short ones are the
        # program-computed handlers, which is where a realm difference shows up first.
        import collections
        by_ctx = collections.Counter(sc["ctx"] for sc in cs.scripts)
        print("scripts", len(cs.scripts), "per context", dict(by_ctx))
        rows = []
        for sc in cs.scripts:
            if not sc["url"] and 0 < sc["len"] < 400:
                try:
                    src = (await cs.send("Debugger.getScriptSource", scriptId=sc["id"])).get("scriptSource", "")
                except Exception:  # noqa: BLE001
                    src = ""
                rows.append({"id": sc["id"], "ctx": sc["ctx"], "len": sc["len"], "src": src})
        json.dump(rows, open(os.path.join(out, "short_scripts.json"), "w"), indent=0)
        for r in rows:
            print("  script", r["id"], "ctx", r["ctx"], "len", r["len"], "src", r["src"][:100].replace("\n", "\\n"))
        # Which globals does the frame realm end up with? The program installs its own helpers
        # there by evaluating `NAME=function(...)` assignments, so this is the check that says
        # whether the self-hosting step ran at all.
        frame_ctx = next((r["ctx"] for r in rows if r["src"].startswith("0,function(z){fC")), None)
        if frame_ctx:
            probe = ("JSON.stringify({fC:typeof fC,q:typeof q,a:typeof a,E:typeof E,Z:typeof Z,"
                     "YU:typeof YU,rs:typeof ridgeslice,n:Object.keys(window).length})")
            res = await cs.send("Runtime.evaluate", expression=probe, contextId=frame_ctx,
                                returnByValue=True)
            print("frame globals ctx", frame_ctx, res.get("result", {}).get("value"))
        print("wrote", out)
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild/material.json")
    ap.add_argument("--out", default="/tmp/bg-realm")
    ap.add_argument("--port", type=int, default=10301)
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port))


if __name__ == "__main__":
    main()
