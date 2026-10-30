"""Read the VM's roll-call names in the browser without touching any JS text.

The roll call (section 82) is the interpreter re-evaluating each helper's name and source in the frame
realm. In d8 it runs in a different order and never reaches the `window`/`null`/`x` probes that the
browser makes. Text patches cannot answer why (they perturb, sections 65/83), but a CDP breakpoint can:
it changes code positions, not source, so the VM's own anti-tamper checks cannot see it.

Breakpoint: inside `function(w){return eval(w)}` of the frame copy, where `w` is the name about to be
evaluated. Offsets are converted to line/column against the source the engine actually compiled (the
frame copy carries random leading/embedded newlines, so columns are stable and lines are not).

    python3 research/probe_breakpoint.py --material /root/bg/build/material.json --out /root/bg/bp

Output: bp.json - every hit in order, with the name, the script, and the realm label when available.
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

ANCHOR = "function(w){return eval(w)}"

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


def line_col(src: str, offset: int) -> tuple:
    line = src.count("\n", 0, offset)
    col = offset - (src.rfind("\n", 0, offset) + 1)
    return line, col


class BP(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.hits = []
        self.armed = []
        self.scripts = {}
        self.diag_done = False

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
                    self.scripts[p["scriptId"]] = {"url": p.get("url", ""), "len": p.get("length", 0)}
                    if p.get("length", 0) > 20000:
                        asyncio.create_task(self._arm(p["scriptId"]))
                elif m == "Debugger.paused":
                    asyncio.create_task(self._on_pause(msg["params"]))
        except Exception:  # noqa: BLE001
            pass

    async def _arm(self, sid):
        try:
            src = (await self._raw("Debugger.getScriptSource", scriptId=sid)).get("scriptSource", "")
            off = src.find(ANCHOR)
            if off < 0:
                return
            # Break *inside* the function, at the `return eval(w)` statement: at the call site `w` is
            # not in scope and every hit evaluates to undefined.
            inner = off + len("function(w){")
            line, col = line_col(src, inner)
            r = await self._raw("Debugger.setBreakpoint", location={
                "scriptId": sid, "lineNumber": line, "columnNumber": col})
            self.armed.append({"scriptId": sid, "line": line, "col": col,
                               "len": len(src), "id": r.get("breakpointId")})
        except Exception as e:  # noqa: BLE001
            self.armed.append({"scriptId": sid, "error": str(e)[:120]})

    async def _on_pause(self, p):
        top = (p.get("callFrames") or [{}])[0]
        rec = {"reason": p.get("reason"), "scriptId": (top.get("location") or {}).get("scriptId"),
               "line": (top.get("location") or {}).get("lineNumber"),
               "name": None, "args": None}
        try:
            r = await self._raw("Debugger.evaluateOnCallFrame", callFrameId=top.get("callFrameId"),
                                expression="String(w)")
            rec["name"] = (r.get("result") or {}).get("value")
        except Exception as e:  # noqa: BLE001
            rec["error"] = str(e)[:120]
        if not self.diag_done and rec.get("name") in ("l7", "n", "q", "E", "a", "Ss", "Yq"):
            # First hit only: read the VM's own module state. All of these are plain property reads -
            # calling the interpreter's helpers could mutate a slot.
            diag = {}
            for label, expr in [
                ("params", "['z','g','V','L','Y'].map(function(n){try{return n+':'+typeof eval(n)}catch(e){return n+':-'}}).join(' ')"),
                ("K_type", "typeof K + ':' + (K ? Object.getOwnPropertyNames(K).length : -1)"),
                ("K_keys", "K ? Object.getOwnPropertyNames(K).join(',') : ''"),
                ("K_T", "K && typeof K.T + ':' + (K.T ? K.T.length : -1)"),
                ("K_u", "K && K.u ? Object.getOwnPropertyNames(K.u).length : -1"),
                ("pc422", "K && K.u && K.u[422] ? typeof K.u[422] + ':' + String(K.u[422].value) : 'none'"),
                ("globals", "typeof window + '|' + typeof globalThis + '|' + typeof String"),
                ("slot422_keys", "K.u[422] ? Object.getOwnPropertyNames(K.u[422]).join(',') : 'none'"),
                ("slot422_val", "K.u[422] ? (typeof K.u[422].value) + ':' + String(K.u[422].value).slice(0,40) : 'none'"),
                ("slot422_valval", "K.u[422] && K.u[422].value ? (typeof K.u[422].value.value) + ':' + String(K.u[422].value.value).slice(0,40) : 'none'"),
            ]:
                try:
                    rr = await self._raw("Debugger.evaluateOnCallFrame",
                                         callFrameId=top.get("callFrameId"), expression=expr)
                    diag[label] = (rr.get("result") or {}).get("value")
                except Exception as e:  # noqa: BLE001
                    diag[label] = "ERR " + str(e)[:60]
            rec["diag"] = diag
            self.diag_done = True
        try:
            r2 = await self._raw("Debugger.evaluateOnCallFrame", callFrameId=top.get("callFrameId"),
                                 expression="typeof w + ':' + (String(w).length)")
            rec["args"] = (r2.get("result") or {}).get("value")
        except Exception as e:  # noqa: BLE001
            rec["error"] = str(e)[:120]
        if True:
            focus = {}
            for label, expr in [
                ("Y", "String(Y)"),
                ("L", "String(L)"),
                ("next_off", "String(F(z,37))"),
                ("types", "[typeof z,typeof g,typeof V,typeof t,typeof u7,typeof Z,typeof K].join(',')"),
            ]:
                try:
                    rr = await self._raw("Debugger.evaluateOnCallFrame",
                                         callFrameId=top.get("callFrameId"), expression=expr)
                    focus[label] = (rr.get("result") or {}).get("value")
                except Exception as e:  # noqa: BLE001
                    focus[label] = "ERR " + str(e)[:60]
            frames = []
            for f in (p.get("callFrames") or [])[1:4]:
                loc = f.get("location") or {}
                frames.append({"fn": f.get("functionName") or "", "line": loc.get("lineNumber"),
                               "col": loc.get("columnNumber")})
            rec["focus"] = {"state": focus, "callers": frames}
        self.hits.append(rec)
        try:
            await self._raw("Debugger.resume")
        except Exception:  # noqa: BLE001
            pass


async def run(material_path: str, out: str, port: int, chrome: str) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    cs = BP(chrome, port, DEFAULT_UA, "/tmp/bg-bp-%d" % port)
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
                   "armed": cs.armed, "hits": cs.hits},
                  open(os.path.join(out, "bp.json"), "w"), indent=1)
        print(f"token {len(tok)} chars / {len(blob)} B   breakpoints armed: {len(cs.armed)}   "
              f"hits: {len(cs.hits)}")
        names = [h["name"] for h in cs.hits if h.get("name")]
        print("first 24 names:", names[:24])
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/root/bg/build/material.json")
    ap.add_argument("--out", default="/root/bg/bp")
    ap.add_argument("--port", type=int, default=10620)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome))


if __name__ == "__main__":
    main()
