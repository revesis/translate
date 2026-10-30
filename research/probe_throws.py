"""Which host operations does the VM probe for authenticity? Pause on caught exceptions and ask.

A trusted run's engine log carries four `Illegal invocation` errors (section 71). They come from Blink
bindings, not from V8, so they cannot be reproduced in a shim by accident - and finding the call sites
from the message alone is guesswork. Chrome's `Debugger.setPauseOnExceptions('caught')` works on real
contexts (unlike Node's inspector, which does not expose vm contexts at all), so this records the throw
site of every caught exception with its stack.

    python3 research/probe_throws.py --material /tmp/bgbuild/material.json --out /tmp/bg-throws

Output: throws.json - one record per caught exception: message, top frames (name, script, line, col),
and the source line when the script is short (an eval'd handler).
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

MINT = r"""(async () => {
  const arr = %s, freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  try { (0, eval)(%s); } catch (e) {}
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({stage: 'install'});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const tok = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  return JSON.stringify({tok: String(tok)});
})()"""


class TH(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = []
        self.scripts = {}
        self.sources = {}
        self.resume_q: asyncio.Queue = asyncio.Queue()

    async def _raw(self, method, **params):
        self._id += 1
        mid = self._id
        fut = self._loop.create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        return await asyncio.wait_for(fut, timeout=60)

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
                    continue
                m = msg.get("method")
                if m == "Debugger.scriptParsed":
                    p = msg["params"]
                    self.scripts[p["scriptId"]] = {"url": p.get("url", ""), "len": p.get("length", 0),
                                                   "ctx": p.get("executionContextId")}
                elif m == "Debugger.paused":
                    # Never await here; a task resumes once the record is written.
                    asyncio.create_task(self._on_pause(msg["params"]))
        except Exception:  # noqa: BLE001
            pass

    async def _on_pause(self, p):
        rec = {"reason": p.get("reason"),
               "exc": ((p.get("data") or {}).get("description") or "").split("\n")[0][:200],
               "frames": []}
        for f in (p.get("callFrames") or [])[:8]:
            loc = f.get("location") or {}
            sid = loc.get("scriptId")
            meta = self.scripts.get(sid, {})
            rec["frames"].append({"fn": f.get("functionName") or "", "line": loc.get("lineNumber"),
                                  "col": loc.get("columnNumber"), "len": meta.get("len"),
                                  "url": meta.get("url", "")})
        try:
            top = (p.get("callFrames") or [{}])[0]
            sid = (top.get("location") or {}).get("scriptId")
            if sid and sid not in self.sources and (self.scripts.get(sid, {}).get("len") or 0) < 4000:
                src = await self._raw("Debugger.getScriptSource", scriptId=sid)
                self.sources[sid] = src.get("scriptSource", "")
                rec["src"] = self.sources[sid][:300]
        except Exception:  # noqa: BLE001
            pass
        self.records.append(rec)
        try:
            await self._raw("Debugger.resume")
        except Exception:  # noqa: BLE001
            pass


async def run(material_path: str, out: str, port: int, chrome: str) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    cs = TH(chrome, port, DEFAULT_UA, "/tmp/bg-th-%d" % port)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs.navigate(PAGE_URL, settle=7)
        await cs.send("Debugger.setPauseOnExceptions", state="caught")
        d = json.loads(await cs.eval(MINT % (json.dumps(arr), json.dumps(freq), json.dumps(interp))))
        tok = d.get("tok") or ""
        raw = tok[1:] if tok.startswith(";") else tok
        blob = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        os.makedirs(out, exist_ok=True)
        json.dump({"token_chars": len(tok), "token_bytes": len(blob), "head": blob[:16].hex(),
                   "throws": cs.records}, open(os.path.join(out, "throws.json"), "w"), indent=1)
        print("token", len(tok), "chars", len(blob), "B head", blob[:16].hex())
        print("caught exceptions:", len(cs.records))
        for r in cs.records[:16]:
            print(f"  {r['exc'][:70]}")
            for f in r["frames"][:3]:
                print(f"     {f['fn'] or '<anon>'} line={f['line']} col={f['col']} len={f['len']}")
        print("wrote", out)
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild/material.json")
    ap.add_argument("--out", default="/tmp/bg-throws")
    ap.add_argument("--port", type=int, default=10611)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome))


if __name__ == "__main__":
    main()
