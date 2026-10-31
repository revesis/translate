"""Position-mapping diagnostic: what line/column does Chrome report for the collector's anchor?

`Debugger.setBreakpoint` snapped a page-realm breakpoint from (7, 26851) to (7, 61710), i.e. 34 859
columns away, while the same request on the frame copy landed exactly. This tool asks the engine
directly instead of computing offsets:

* `scriptParsed` metadata for every copy (startLine/startColumn/endLine/endColumn/url);
* `Debugger.searchInContent` for the unique anchor `X+=":"+k.stack` (full result, not just the line);
* `Debugger.getPossibleBreakpoints` around the anchor, and around the snapped position;
* the text at each reported line/column, sliced from `getScriptSource`.

    python3 research/probe_bp.py --material /tmp/bgbuild_now/material.json --out /tmp/bg-bp468
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

EVAL = r"""(async () => { try { (0, eval)(%s); } catch (e) {} return typeof window.ridgeslice; })()"""


def slicer(src):
    def at(line, col):
        lines = src.split("\n")
        if line is None or line >= len(lines):
            return "<no line>"
        return lines[line][max(0, (col or 0) - 40):(col or 0) + 60]
    return at


class Diag(ChromeSession):
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
                elif msg.get("method") == "Debugger.scriptParsed":
                    p = msg["params"]
                    if p.get("length", 0) > 20000:
                        (self.parsed.setdefault("big", []).append(
                            {k: p.get(k) for k in ("scriptId", "url", "startLine", "startColumn",
                                                   "endLine", "endColumn", "length", "hash")}))
        except Exception:  # noqa: BLE001
            pass


async def run(material_path, out, port, chrome):
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    d = derive(interp)
    q = '%s+=":"+%s.stack' % (d["acc"], d["msg"])
    print("anchor query:", repr(q), " material off:", d["off_stack"])
    cs = Diag(chrome, port, DEFAULT_UA, "/tmp/bg-bp468-%d" % port)
    cs.parsed = {}
    await cs.start()
    report = {"query": q, "copies": []}
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs.navigate(PAGE_URL, settle=7)
        print("install:", await cs.eval(EVAL % json.dumps(interp)))
        await asyncio.sleep(1.0)
        for meta in cs.parsed.get("big", []):
            sid = meta["scriptId"]
            src = (await cs._raw("Debugger.getScriptSource", scriptId=sid)).get("scriptSource", "")
            if not derive(src):
                continue
            frame = src.startswith("\n\n")
            sl = slicer(src)
            rec = {"scriptId": sid, "frame": frame, "len": len(src), "meta": meta}
            try:
                rec["search"] = await cs._raw("Debugger.searchInContent", scriptId=sid, query=q)
            except Exception as e:  # noqa: BLE001
                rec["search_err"] = str(e)[:100]
            off = src.find(q)
            line = src.count("\n", 0, off)
            col = off - (src.rfind("\n", 0, off) + 1)
            cul = col
            rec["own"] = {"line": line, "col": col, "text": sl(line, col)}
            # Breakable positions in a window around the anchor, and the one Chrome picks for it.
            try:
                rec["possible"] = await cs._raw(
                    "Debugger.getPossibleBreakpoints",
                    start={"scriptId": sid, "lineNumber": line, "columnNumber": 0},
                    end={"scriptId": sid, "lineNumber": line,
                         "columnNumber": max(len(src.split("\n")[line]), col + 200)},
                    restrictToFunction=False)
            except Exception as e:  # noqa: BLE001
                rec["possible_err"] = str(e)[:100]
            try:
                bp = await cs._raw("Debugger.setBreakpoint", location={
                    "scriptId": sid, "lineNumber": line, "columnNumber": col})
                rec["actual"] = bp.get("actualLocation")
                a = bp.get("actualLocation") or {}
                rec["actual_text"] = sl(a.get("lineNumber"), a.get("columnNumber"))
                rec["bp_id"] = bp.get("breakpointId")
            except Exception as e:  # noqa: BLE001
                rec["bp_err"] = str(e)[:100]
            # What does the engine say is on the source text at the snapped position?
            rec["possible_at_actual"] = None
            if rec.get("actual"):
                a = rec["actual"]
                try:
                    r = await cs._raw(
                        "Debugger.getPossibleBreakpoints",
                        start={"scriptId": sid, "lineNumber": a["lineNumber"],
                               "columnNumber": max(0, (a.get("columnNumber") or 0) - 3)},
                        end={"scriptId": sid, "lineNumber": a["lineNumber"],
                             "columnNumber": (a.get("columnNumber") or 0) + 3},
                        restrictToFunction=False)
                    rec["possible_at_actual"] = r.get("locations")
                except Exception as e:  # noqa: BLE001
                    rec["possible_at_actual"] = "ERR " + str(e)[:80]
            report["copies"].append(rec)
            print("--- copy %s frame=%s len=%s startLine/Col=%s/%s"
                  % (sid, frame, len(src), meta.get("startLine"), meta.get("startColumn")))
            print("    own:", rec["own"])
            print("    search:", json.dumps(rec.get("search") or rec.get("search_err"))[:300])
            poss = (rec.get("possible") or {}).get("locations") or []
            cols = sorted(l.get("columnNumber") or 0 for l in poss)
            near = [c for c in cols if abs(c - cul) <= 1500]
            print("    possible on line: n=%d  min=%s max=%s" % (len(cols), cols[:1], cols[-1:] if cols else []))
            print("    anchor col %d (%s) nearest possible:" % (cul, cul), near[:10])
            print("    first possible cols:", cols[:12])
            print("    actual:", rec.get("actual"), "text:", repr(rec.get("actual_text")))
        os.makedirs(out, exist_ok=True)
        json.dump(report, open(os.path.join(out, "bp468.json"), "w"), indent=1)
    finally:
        await cs.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild_now/material.json")
    ap.add_argument("--out", default="/tmp/bg-bp468")
    ap.add_argument("--port", type=int, default=10780)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome))


if __name__ == "__main__":
    main()
