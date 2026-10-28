"""Read the pre-encode buffer and the field buffers at btoa time, without patching the VM.

Section 5 of docs/botguard-notes.md records the recipe: replace `window.btoa` in the frame realm
over CDP (invisible to the VM), keep the pre-base64 string, and reach the VM instance through
`CallSite.getThis()`. This script does exactly that for one pristine mint and prints:

  * the token bytes (the string Google will see, before base64),
  * every VM object seen on the stack, with the byte length of the interesting field buffers,
  * the first bytes of field 146's buffer, so it can be compared with the token body.

    python3 research/probe_serializer.py --port 10410 --out /tmp/bg-ser
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

# installed in every execution context as soon as it appears; the mint runs in a frame that is
# created during the call, so installing only on the page realm misses the one that matters
HOOK = r"""(function(){
  if (window.__bth) return 'already';
  window.__bth = 1; window.__bt = [];
  var orig = window.btoa;
  window.btoa = function(s){
    try {
      var prev = Error.prepareStackTrace, frames = null;
      Error.prepareStackTrace = function(e, f){ frames = f; return 'x'; };
      try { new Error().stack; } catch (e) {}
      Error.prepareStackTrace = prev;
      var selfs = [];
      if (frames) for (var i = 0; i < frames.length && i < 8; i++) {
        try { selfs.push(frames[i].getThis()); } catch (e) { selfs.push(null); }
      }
      window.__bt.push({len: String(s).length, s: String(s), selfs: selfs});
    } catch (e) {}
    return orig.apply(this, arguments);
  };
  return 'hooked';
})()"""

READ = r"""(function(){
  var out = [];
  var ids = [146, 117, 99, 23, 444, 473, 495, 277, 261, 311, 323, 474, 134, 89, 56, 408, 97];
  (window.__bt || []).forEach(function(rec){
    var info = {len: rec.len, vm: 0, fields: {}};
    (rec.selfs || []).forEach(function(o){
      try {
        if (!o || !o.h || !o.NU) return;
        info.vm = 1;
        ids.forEach(function(id){
          var t = o.h[id];
          if (!t) return;
          var p = t.prototype, row = {has: 1};
          try { row.value = typeof t.value; } catch (e) {}
          if (p && typeof p.length === 'number') {
            row.len = p.length;
            row.head = Array.prototype.slice.call(p, 0, 16);
          }
          info.fields[id] = row;
        });
      } catch (e) { info.err = String(e); }
    });
    out.push(info);
  });
  return JSON.stringify({bt: out.length, recs: out});
})()"""

MINT = r"""(async () => {
  const arr = %s, plain = %s, freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  try { (0, eval)(plain); } catch (e) { return JSON.stringify({stage: 'eval', err: String(e)}); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({stage: 'install'});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false,
               [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const tok = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  return JSON.stringify({stage: 'ok', tok: String(tok)});
})()"""


class SerCS(dp.CS):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.contexts: dict = {}
        self.hooked: set = set()

    async def _read(self):
        # same loop as dp.CS, plus context tracking; installing the hook is left to a poller so
        # this coroutine never awaits a request of its own (that would deadlock the reader)
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
                    continue
                meth = msg.get("method")
                if meth == "Runtime.executionContextCreated":
                    p = msg["params"]["context"]
                    self.contexts[p["id"]] = p
                elif meth == "Fetch.requestPaused":
                    p = msg["params"]
                    url = p.get("request", {}).get("url", "")
                    self.served.append(url)
                    if "/js/bg/" in url and self.body:
                        await self.send("Fetch.fulfillRequest", requestId=p["requestId"],
                                        responseCode=200,
                                        responseHeaders=[{"name": "content-type",
                                                          "value": "application/javascript"}],
                                        body=base64.b64encode(self.body).decode())
                    else:
                        await self.send("Fetch.continueRequest", requestId=p["requestId"])
                elif meth == "Debugger.scriptParsed":
                    p = msg["params"]
                    self.scripts[p.get("scriptId")] = {"url": p.get("url", ""),
                                                       "len": p.get("length", 0),
                                                       "ctx": p.get("executionContextId")}
                    self.script_order.append(p.get("scriptId"))
                elif meth == "Network.responseReceived":
                    p = msg["params"]
                    if p.get("type") == "Document" and self.doc_request is None:
                        self.doc_request = p["requestId"]
        except Exception:  # noqa: BLE001
            pass

    async def poll_hooks(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            for cid, ctx in list(self.contexts.items()):
                if cid in self.hooked:
                    continue
                try:
                    await self.send("Runtime.evaluate", expression=HOOK, contextId=cid,
                                    returnByValue=True)
                    self.hooked.add(cid)
                except Exception:  # noqa: BLE001
                    self.hooked.add(cid)
            await asyncio.sleep(0.05)

    async def read_all(self) -> list:
        out = []
        for cid in list(self.contexts):
            try:
                r = await self.send("Runtime.evaluate", expression=READ, contextId=cid,
                                    returnByValue=True)
                v = (r.get("result") or {}).get("value")
                if v and json.loads(v).get("bt"):
                    out.append((cid, json.loads(v)))
            except Exception:  # noqa: BLE001
                pass
        return out


async def run(port: int, out: str) -> None:
    freq = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    cs = SerCS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-ser-%d" % port)
    await cs.start()
    stop = asyncio.Event()
    poller = None
    try:
        await cs.send("Network.enable")
        await cs.navigate(dp.URL, settle=7)
        if not cs.doc_request:
            raise SystemExit("no document response captured")
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        arr = json.loads("[" + dp.parse_material(html)[4:])
        plain = arr[5][-1]
        print("build", str(arr[2])[:16], "interp", len(plain))
        poller = asyncio.create_task(cs.poll_hooks(stop))
        res = json.loads(await cs.eval(MINT % (json.dumps(arr), json.dumps(plain),
                                               json.dumps(freq))))
        print("mint", {k: (len(v) if isinstance(v, str) and k == "tok" else v)
                       for k, v in res.items()})
        await asyncio.sleep(0.4)
        stop.set()
        recs = await cs.read_all()
        os.makedirs(out, exist_ok=True)
        dump = {"build": str(arr[2])[:16], "token": res.get("tok"), "contexts": recs}
        json.dump(dump, open(os.path.join(out, "ser.json"), "w"))
        tok = res.get("tok") or ""
        if tok:
            b = tok[1:]
            b += "=" * (-len(b) % 4)
            raw = base64.urlsafe_b64decode(b)
            print("token chars", len(tok), "bytes", len(raw), raw[:16].hex(" "))
        for cid, rec in recs:
            for r in rec["recs"]:
                print(f"  ctx {cid} pre-encode len {r['len']} vm {r['vm']}")
                for fid, f in sorted((r.get("fields") or {}).items(), key=lambda kv: int(kv[0])):
                    print(f"    field {fid}: len {f.get('len')} value {f.get('value')} "
                          f"head {bytes(f.get('head') or []).hex(' ')}")
        print("wrote", os.path.join(out, "ser.json"))
    finally:
        stop.set()
        if poller:
            poller.cancel()
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10410)
    ap.add_argument("--out", default="/tmp/bg-ser")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out))


if __name__ == "__main__":
    main()
