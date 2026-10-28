"""Log the serializer's own appends (Array.prototype.push / concat) in the frame realm.

Section 2b measured the *sizes* of the concat calls this way; the open questions of section 38 are
about the bytes the hooked emitters do not produce (the three stray bytes between chunks). This
probe keeps the same CDP-only hook and records, for one pristine mint:

  * every `push` into an array whose length is 20..4000 (that covers the token accumulator),
  * every `concat` with the length of `this`, each argument's length, and the argument's first
    bytes,

so the assembly order and the origin of the stray bytes can be read off the log instead of guessed.

    python3 research/probe_concat.py --port 10420 --out /tmp/bg-cat
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

from bgr_sidecar import DEFAULT_UA  # noqa: E402
import dump_program as dp  # noqa: E402
from probe_serializer import SerCS, MINT  # noqa: E402

HOOK = r"""(function(){
  if (window.__ch) return 'already';
  window.__ch = 1; window.__cl = [];
  var ids = new WeakMap(), next = 1;
  var idOf = function(a){
    var v = ids.get(a);
    if (v === undefined) { v = next++; ids.set(a, v); }
    return v;
  };
  var isByte = function(v){ return typeof v === 'number' && v >= 0 && v <= 255 && v === (v|0); };
  var byteish = function(a){
    try {
      if (!a || typeof a.length !== 'number' || a.length === 0) return false;
      var n = Math.min(a.length, 6);
      for (var i = 0; i < n; i++) if (!isByte(a[i])) return false;
      return true;
    } catch (e) { return false; }
  };
  var push = function(rec){ window.__cl.push(rec); if (window.__cl.length > 12000) window.__cl.shift(); };
  var oc = Array.prototype.concat, op = Array.prototype.push;
  Array.prototype.push = function(){
    try {
      if (arguments.length && isByte(arguments[0]) && this.length >= 1 && byteish(this)) {
        push(['p', idOf(this), this.length, arguments[0]]);
      }
    } catch (e) {}
    return op.apply(this, arguments);
  };
  Array.prototype.concat = function(){
    try {
      var hit = byteish(this);
      for (var i = 0; i < arguments.length && !hit; i++) hit = byteish(arguments[i]);
      if (hit) {
        var rec = ['c', idOf(this), this.length, []];
        for (var i = 0; i < arguments.length; i++) {
          var a = arguments[i], head = null;
          try { head = (a && a.slice) ? Array.prototype.slice.call(a, 0, 6) : null; } catch (e) {}
          rec[3].push([a && a.length, head, a && a.length ? idOf(a) : 0]);
        }
        push(rec);
      }
    } catch (e) {}
    return oc.apply(this, arguments);
  };
  return 'hooked';
})()"""

READ = r"""(function(){
  return JSON.stringify({n: (window.__cl || []).length, log: (window.__cl || [])});
})()"""


class CatCS(SerCS):
    async def poll_hooks(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            for cid in list(self.contexts):
                if cid in self.hooked:
                    continue
                try:
                    await self.send("Runtime.evaluate", expression=HOOK, contextId=cid,
                                    returnByValue=True)
                    self.hooked.add(cid)
                except Exception:  # noqa: BLE001
                    self.hooked.add(cid)
            await asyncio.sleep(0.05)

    async def read_log(self) -> list:
        out = []
        for cid in list(self.contexts):
            try:
                r = await self.send("Runtime.evaluate", expression=READ, contextId=cid,
                                    returnByValue=True)
                v = (r.get("result") or {}).get("value")
                if v:
                    d = json.loads(v)
                    if d.get("n"):
                        out.append((cid, d))
            except Exception:  # noqa: BLE001
                pass
        return out


async def run(port: int, out: str) -> None:
    freq = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    cs = CatCS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-cat-%d" % port)
    await cs.start()
    stop = asyncio.Event()
    poller = None
    try:
        await cs.send("Network.enable")
        await cs.navigate(dp.URL, settle=7)
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        arr = json.loads("[" + dp.parse_material(html)[4:])
        plain = arr[5][-1]
        print("build", str(arr[2])[:16])
        poller = asyncio.create_task(cs.poll_hooks(stop))
        res = json.loads(await cs.eval(MINT % (json.dumps(arr), json.dumps(plain),
                                               json.dumps(freq))))
        await asyncio.sleep(0.4)
        stop.set()
        logs = await cs.read_log()
        os.makedirs(out, exist_ok=True)
        json.dump({"build": str(arr[2])[:16], "token": res.get("tok"), "logs": logs},
                  open(os.path.join(out, "cat.json"), "w"), default=str)
        tok = res.get("tok") or ""
        raw = b""
        if tok:
            b = tok[1:]
            b += "=" * (-len(b) % 4)
            raw = base64.urlsafe_b64decode(b)
            print("token", len(tok), "chars", len(raw), "bytes")
        for cid, d in logs:
            print(f"ctx {cid}: {d['n']} events")
            pushes = [e for e in d["log"] if e[0] == "p"]
            cats = [e for e in d["log"] if e[0] == "c"]
            print(f"  pushes {len(pushes)}  concats {len(cats)}")
            for e in cats[:60]:
                print(f"  concat this={e[1]} args={[(a[0], a[1]) for a in e[2]]} tail={e[3]}")
            # group pushes by their array length trajectory: a byte stream shows up as
            # consecutive pushes with n, n+1, n+2 ...
            if pushes:
                print(f"  first pushes {pushes[:4]}")
                print(f"  last pushes  {pushes[-4:]}")
        print("wrote", os.path.join(out, "cat.json"))
    finally:
        stop.set()
        if poller:
            poller.cancel()
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10420)
    ap.add_argument("--out", default="/tmp/bg-cat")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out))


if __name__ == "__main__":
    main()
