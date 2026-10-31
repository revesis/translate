"""Which script actually *executes* the collector? Position mapping alone cannot say.

`Debugger.getPossibleBreakpoints` on the page copy (script 21, the interp text) offers nothing on the
collector's line before column 61710, although the collector's source text sits at column ~26756. That
means that occurrence is *data* - the interp carries its own text as a string (it builds the frame
program from it), so a breakpoint there resolves to a nearby code position and never fires.

This tool enumerates every script the page creates, finds the copies that contain the anchor text, and
asks the engine whether the anchor's own column is breakable. The copies where it is are the ones that
can be broken, i.e. the code, not the embedded string.

    python3 research/probe_anchor.py --material /tmp/bgbuild_now/material.json --out /tmp/bg-anchor
"""
import argparse
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA, ChromeSession, PAGE_URL  # noqa: E402
from probe_468 import derive  # noqa: E402

INSTALL = r"""(async () => { try { (0, eval)(%s); } catch (e) {} return typeof window.ridgeslice; })()"""

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


def line_col(src, off):
    return src.count("\n", 0, off), off - (src.rfind("\n", 0, off) + 1)


class A(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.all = {}

    async def _raw(self, method, **params):
        self._id += 1
        mid = self._id
        fut = self._loop.create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        return await asyncio.wait_for(fut, timeout=90)

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
                    self.all[p["scriptId"]] = {"url": (p.get("url") or "")[:70],
                                               "len": p.get("length", 0)}
        except Exception:  # noqa: BLE001
            pass


async def scan(cs, anchor, label):
    out = []
    for sid, meta in list(cs.all.items()):
        if meta["len"] > 3_000_000:
            continue
        try:
            src = (await cs._raw("Debugger.getScriptSource", scriptId=sid)).get("scriptSource", "")
        except Exception:  # noqa: BLE001
            continue
        if anchor not in src:
            continue
        occ = []
        start = 0
        while True:
            off = src.find(anchor, start)
            if off < 0:
                break
            start = off + 1
            line, col = line_col(src, off)
            # Is this very column a code position the engine would break at?
            try:
                r = await cs._raw("Debugger.getPossibleBreakpoints",
                                  start={"scriptId": sid, "lineNumber": line,
                                         "columnNumber": max(0, col - 40)},
                                  end={"scriptId": sid, "lineNumber": line,
                                       "columnNumber": col + 400},
                                  restrictToFunction=False)
                locs = [(l.get("lineNumber"), l.get("columnNumber"))
                        for l in (r.get("locations") or [])]
            except Exception as e:  # noqa: BLE001
                locs = "ERR " + str(e)[:60]
            occ.append({"off": off, "line": line, "col": col, "breakable": locs})
        d = derive(src)
        out.append({"scriptId": sid, "url": meta["url"], "len": len(src),
                    "frame_prefix": src.startswith("\n\n"), "lines": src.count("\n"),
                    "collector": bool(d), "occurrences": occ})
    print("== %s: %d scripts, %d with the anchor" % (label, len(cs.all), len(out)))
    for r in out:
        print("  script %-3s len %-7s lines %-5s frame=%s url=%s"
              % (r["scriptId"], r["len"], r["lines"], r["frame_prefix"], r["url"]))
        for o in r["occurrences"]:
            print("      at %s:%s  breakable=%s" % (o["line"], o["col"], o["breakable"]))
    return out


async def run(material_path, out, port, chrome, do_mint):
    m = json.load(open(material_path))
    interp = m["arr"][5][-1]
    d = derive(interp)
    anchor = '%s+=":"+%s.stack' % (d["acc"], d["msg"])
    print("anchor:", repr(anchor))
    cs = A(chrome, port, DEFAULT_UA, "/tmp/bg-anchor-%d" % port)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs.navigate(PAGE_URL, settle=7)
        if do_mint:
            freq = open(os.path.join(HERE, "freq.txt")).read()
            t = json.loads(await cs.eval(MINT % (json.dumps(m["arr"]), json.dumps(freq),
                                                 json.dumps(interp))))
            print("mint token chars:", len(t.get("tok") or ""))
            await asyncio.sleep(1.0)
            before = await scan(cs, anchor, "after mint")
        else:
            print("install:", await cs.eval(INSTALL % json.dumps(interp)))
            await asyncio.sleep(2.0)
            before = await scan(cs, anchor, "after install")
        os.makedirs(out, exist_ok=True)
        json.dump({"anchor": anchor, "before": before}, open(os.path.join(out, "anchor.json"), "w"), indent=1)
    finally:
        await cs.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild_now/material.json")
    ap.add_argument("--out", default="/tmp/bg-anchor")
    ap.add_argument("--port", type=int, default=10790)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    ap.add_argument("--mint", action="store_true")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome, a.mint))


if __name__ == "__main__":
    main()
