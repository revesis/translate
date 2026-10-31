"""Read `U8` - the tag-132 source, i.e. the VM's exception log - in a real browser, without patching JS.

Section 91 resolved the record table: tag 132's payload is `Kk(U8.length,2).concat(U8)`. So at that call
site `U8` is in scope, and a CDP breakpoint there can read it as plain values (breakpoints move code
positions, not source text, so the VM cannot see them - section 85).

    python3 research/probe_u8.py --material /tmp/bgbuild_local/material.json --out /tmp/bg-u8

Prints: the kind and size of U8, and the first bytes as text (the log is `message + ":" + stack` per
caught error, so it should be readable) plus as hex.
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

ANCHOR = "Kk(U8.length,2).concat(U8)"

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

READS = [
    ("kind", "typeof U8 + (Array.isArray(U8) ? ':array' : '')"),
    ("len", "String(U8 ? U8.length : -1)"),
    ("text", "String(U8 ? Array.prototype.map.call(U8, function (b) { return String.fromCharCode(b); }).join('') : '')"),
    ("hex", "String(U8 ? Array.prototype.map.call(U8, function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join('') : '')"),
    ("budget", "typeof C === 'function' ? String((function(){ try { return String(C(this, 468)[0]); } catch (e) { return 'n/a'; } })()) : 'n/a'"),
]


def line_col(src: str, offset: int) -> tuple:
    return src.count("\n", 0, offset), offset - (src.rfind("\n", 0, offset) + 1)


class U8(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.armed = []
        self.rec = None
        self.scripts = {}

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
                    self.scripts[p["scriptId"]] = p.get("length", 0)
                    if p.get("length", 0) > 20000:
                        asyncio.create_task(self._arm(p["scriptId"]))
                elif m == "Debugger.paused":
                    asyncio.create_task(self._on_pause(msg["params"]))
        except Exception:  # noqa: BLE001
            pass

    async def _arm(self, sid):
        try:
            src = (await self._raw("Debugger.getScriptSource", scriptId=sid)).get("scriptSource", "")
            if not src.startswith("\n\n"):
                return
            off = src.find(ANCHOR)
            if off < 0:
                return
            # Only the largest copy matters: the page interp and the frame copy both contain the anchor,
            # and the serializer that runs is the frame realm's.
            start = 0
            made = 0
            while made < 12:
                off = src.find(ANCHOR, start)
                if off < 0:
                    break
                start = off + 1
                line, col = line_col(src, off)
                try:
                    r = await self._raw("Debugger.setBreakpoint", location={
                        "scriptId": sid, "lineNumber": line, "columnNumber": col})
                    self.armed.append({"scriptId": sid, "len": len(src), "line": line, "col": col,
                                       "id": r.get("breakpointId")})
                    made += 1
                except Exception as e:  # noqa: BLE001
                    self.armed.append({"scriptId": sid, "line": line, "col": col, "err": str(e)[:40]})
        except Exception as e:  # noqa: BLE001
            self.armed.append({"scriptId": sid, "error": str(e)[:100]})

    async def _on_pause(self, p):
        top = (p.get("callFrames") or [{}])[0]
        if True:
            self.loc = {"scriptId": (top.get("location") or {}).get("scriptId"),
                        "line": (top.get("location") or {}).get("lineNumber"),
                        "col": (top.get("location") or {}).get("columnNumber")}
            rec = {}
            for label, expr in READS:
                try:
                    r = await self._raw("Debugger.evaluateOnCallFrame",
                                        callFrameId=top.get("callFrameId"),
                                        expression=expr, returnByValue=True)
                    res = r.get("result") or {}
                    rec[label] = res.get("value")
                    if rec[label] is None:
                        rec[label] = {"raw": res.get("description") or res.get("type") or str(r)[:120]}
                except Exception as e:  # noqa: BLE001
                    rec[label] = "ERR " + str(e)[:60]
            kind = rec.get("kind")
            ok = isinstance(kind, str) and kind != "undefined"
            if ok and self.rec is None:
                self.rec = rec
            self.hits = getattr(self, "hits", [])
            self.hits.append({"at": getattr(self, "loc", None), "kind": kind, "useful": ok})
        try:
            await self._raw("Debugger.resume")
        except Exception:  # noqa: BLE001
            pass


async def run(material_path: str, out: str, port: int, chrome: str) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    cs = U8(chrome, port, DEFAULT_UA, "/tmp/bg-u8-%d" % port)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs.navigate(PAGE_URL, settle=7)
        d = json.loads(await cs.eval(MINT % (json.dumps(arr), json.dumps(freq), json.dumps(interp))))
        tok = d.get("tok") or ""
        raw = tok[1:] if tok.startswith(";") else tok
        blob = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        os.makedirs(out, exist_ok=True)
        json.dump({"token_chars": len(tok), "token_bytes": len(blob), "head": blob[:16].hex(),
                   "armed": cs.armed, "u8": cs.rec, "u8_at": getattr(cs, "loc", None),
                   "hits": getattr(cs, "hits", [])[:20]}, open(os.path.join(out, "u8.json"), "w"), indent=1)
        print(f"token {len(tok)} chars / {len(blob)} B   breakpoints {len(cs.armed)}")
        if cs.rec:
            print("paused at:", getattr(cs, "loc", None))
            print("U8 kind:", cs.rec.get("kind"), " len:", cs.rec.get("len"))
            text = cs.rec.get("text") if isinstance(cs.rec.get("text"), str) else ""
            print("U8 text (first 600):", repr(text[:600]))
            print("hits:", getattr(cs, "hits", [])[:8])
        else:
            print("no U8 hit")
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild_local/material.json")
    ap.add_argument("--out", default="/tmp/bg-u8")
    ap.add_argument("--port", type=int, default=10720)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome))


if __name__ == "__main__":
    main()
