"""Node-side field-274 measurement: what the VM appends in `node:vm`.

Section 96 measured the browser side with a CDP breakpoint on the writer's guard. d8 cannot do
that (its inspector hides Realm contexts), but node's inspector *does* expose `node:vm` contexts -
measured: a breakpoint set in a vm-context script hits, and `evaluateOnCallFrame` reads the locals.

Nothing is hard-coded, because builds rotate field ids. The current build (`hwFN46BzpU0xcs39`) names
them in the interpreter text:

    F=function(J,f,x){ ... J==231||J==110||J==297 ... }        the field writer (J = field id)
    PX(qZ(L.length,2).concat(L),231,this,132)                  tag-132 record <- field 231
    ib(72,110,f,qZ(v.length,2).concat(v),17)                   the exception collector <- field 110

so field 231 is this build's mining-transcript field (274 in the build section 96 measured) and 110
is the exception log.

The frame copy does not exist until the mint starts, so arming after `Debugger.scriptParsed` is too
late (measured: 15 breakpoints, 0 hits). The probe therefore arms `beforeScriptExecution` and arms
each new script at the moment it is about to run.

    python3 research/probe_node274.py --material /tmp/bgbuild_now/material.json --out /tmp/bg-node274
"""
import argparse
import asyncio
import json
import os
import re
import subprocess
import time
import urllib.request

import websockets

HERE = os.path.dirname(os.path.abspath(__file__))
NODE_MINT = os.path.join(HERE, "node_mint.mjs")

# `x.message&&(v+=x.message)` - group 1 = the error holder, group 2 = the accumulator.
RE_MSG = re.compile(r"([A-Za-z_$][\w$]*)\.message&&\(\s*([A-Za-z_$][\w$]*)\s*\+=")
# The collector's append: `ib(72,110,f,qZ(v.length,2).concat(v),17)`.
RE_APPEND = re.compile(r"([A-Za-z_$][\w$]*)\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*[A-Za-z_$][\w$]*\s*,"
                       r"\s*([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\.length\s*,\s*2\s*\)"
                       r"\s*\.concat\(\s*\5\s*\)")
# A writer guard over field ids: `J==231||J==110||J==297`.
RE_GUARD = re.compile(r"([A-Za-z_$][\w$]*)==(\d+)\|\|\1==(\d+)\|\|\1==(\d+)")
# The serializer's tag-132 emit: `PX(qZ(L.length,2).concat(L),231,this,132)` - mint always reaches it
# when the record exists, so it is the decisive "is this copy executed?" anchor.
RE_TAG132 = re.compile(r",\s*\d+\s*,\s*this\s*,\s*132\s*\)")

ARGS_EXPR = ("Array.prototype.map.call(arguments,function(a){return typeof a==='number'?String(a):"
             "(Array.isArray(a)?'A'+a.length+'['+Array.prototype.slice.call(a,0,24).join(',')+']':"
             "(typeof a==='string'?a.slice(0,200):typeof a))}).join('|')")


def line_col(src: str, off: int) -> tuple:
    return src.count("\n", 0, off), off - (src.rfind("\n", 0, off) + 1)


class NodeCDP:
    def __init__(self, port: int):
        self.port = port
        self.ws = None
        self.seq = 0
        self.pend = {}
        self.events = []
        self.scripts = {}

    async def connect(self) -> None:
        url = None
        for _ in range(60):
            try:
                targets = json.load(urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/json/list", timeout=2))
                page = next((t for t in targets if t.get("type") == "node"), None)
                if page:
                    url = page["webSocketDebuggerUrl"]
                    break
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.2)
        if not url:
            raise RuntimeError("node inspector never came up")
        self.ws = await websockets.connect(url, max_size=128 * 1024 * 1024)
        self.rt = asyncio.create_task(self._reader())
        await self.send("Runtime.enable")
        await self.send("Debugger.enable")

    async def _reader(self) -> None:
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self.pend.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                elif "method" in msg:
                    self.events.append(msg)
                    if msg["method"] == "Debugger.scriptParsed":
                        p = msg["params"]
                        self.scripts[p["scriptId"]] = {
                            "url": (p.get("url") or "")[:60], "len": p.get("length", 0)}
        except Exception:  # noqa: BLE001
            pass

    async def send(self, method, **params):
        self.seq += 1
        fut = asyncio.get_running_loop().create_future()
        self.pend[self.seq] = fut
        await self.ws.send(json.dumps({"id": self.seq, "method": method, "params": params}))
        return await asyncio.wait_for(fut, 30)

    async def source(self, sid: str) -> str:
        r = await self.send("Debugger.getScriptSource", scriptId=sid)
        return (r.get("result") or {}).get("scriptSource", "")

    async def possible(self, sid, line, col, before=40, after=200):
        r = await self.send("Debugger.getPossibleBreakpoints",
                            start={"scriptId": sid, "lineNumber": line,
                                   "columnNumber": max(0, col - before)},
                            end={"scriptId": sid, "lineNumber": line, "columnNumber": col + after},
                            restrictToFunction=False)
        return sorted((l.get("columnNumber") or 0) for l in (r.get("result", {}).get("locations") or []))

    async def arm(self, sid, line, col):
        r = await self.send("Debugger.setBreakpoint", location={
            "scriptId": sid, "lineNumber": line, "columnNumber": col})
        return (r.get("result") or {}).get("breakpointId")

    async def ev(self, cfid, expr):
        r = await self.send("Debugger.evaluateOnCallFrame", callFrameId=cfid,
                            expression=expr, returnByValue=True)
        res = r.get("result", {}).get("result") or {}
        return res.get("value", res.get("description"))

    def take_pauses(self):
        out = [e for e in self.events if e.get("method") == "Debugger.paused"]
        self.events = [e for e in self.events if e.get("method") != "Debugger.paused"]
        return out


class Probe:
    def __init__(self, cdp: NodeCDP, scan_only: bool):
        self.cdp = cdp
        self.scan_only = scan_only
        self.scanned = {}
        self.armed = []
        self.sites = {}
        self.hits = []

    async def scan_and_arm(self, sid: str, meta: dict) -> None:
        if sid in self.scanned:
            return
        src = await self.cdp.source(sid)
        self.scanned[sid] = True
        if not src:
            return
        d = RE_MSG.search(src)
        g = RE_GUARD.search(src)
        a = RE_APPEND.search(src)
        t = RE_TAG132.search(src)
        if not (d or g or a or t):
            return
        info = {"sid": sid, "url": meta.get("url"), "len": len(src),
                "msg": d.groups() if d else None, "guard": g.groups() if g else None,
                "append": a.groups() if a else None, "tag132": bool(t)}
        self.scanned[sid] = info
        print("script %-4s len %-7s url %-14s msg=%s guard=%s append=%s"
              % (sid, len(src), meta.get("url"), info["msg"], info["guard"], info["append"]))
        if self.scan_only:
            return
        for label, text in (("log", d.group(0) if d else None),
                            ("append", a.group(0) if a else None),
                            ("tag132", t.group(0) if t else None),
                            ("guard", g.group(0) if g else None)):
            if not text:
                continue
            off = src.find(text)
            line, col = line_col(src, off)
            cols = await self.cdp.possible(sid, line, col)
            if not cols:
                self.armed.append({"sid": sid, "label": label, "skipped": "data, not code"})
                continue
            pick = min(cols, key=lambda c: abs(c - col))
            bid = await self.cdp.arm(sid, line, pick)
            if bid:
                self.sites[bid] = "%s#%s" % (label, sid)
            self.armed.append({"sid": sid, "label": label, "text_col": col, "col": pick, "id": bid})
            print("  armed %-7s %s:%s -> %s id=%s" % (label, line, col, pick, bid))

    async def drain(self) -> None:
        for p in self.cdp.take_pauses():
            params = p["params"]
            try:
                if params.get("reason") == "instrumentation":
                    sid = (params.get("data") or {}).get("scriptId")
                    if sid:
                        await self.scan_and_arm(sid, self.cdp.scripts.get(sid, {}))
                    await self.cdp.send("Debugger.resume")
                    continue
                cf = (params.get("callFrames") or [{}])[0]
                loc = cf.get("location") or {}
                rec = {"reason": params.get("reason"), "sid": loc.get("scriptId"),
                       "line": loc.get("lineNumber"), "col": loc.get("columnNumber"),
                       "site": self.sites.get((params.get("hitBreakpoints") or [None])[0]),
                       "frames": [f.get("functionName") or "?"
                                  for f in (params.get("callFrames") or [])[:8]]}
                cfid = cf.get("callFrameId")
                if cfid:
                    rec["args"] = await self.cdp.ev(cfid, ARGS_EXPR)
                self.hits.append(rec)
                await self.cdp.send("Debugger.resume")
            except Exception:  # noqa: BLE001 - the node process may exit mid-drain
                return


async def run(material: str, out: str, port: int, delay: int, scan_only: bool) -> None:
    os.makedirs(out, exist_ok=True)
    token_path = os.path.join(out, "node-token.bin")
    proc = subprocess.Popen(
        ["node", f"--inspect=127.0.0.1:{port}", NODE_MINT, "--material", material,
         "--out", token_path, "--arm-delay", str(delay)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    cdp = NodeCDP(port)
    await cdp.connect()
    probe = Probe(cdp, scan_only)
    try:
        try:
            r = await cdp.send("Debugger.setInstrumentationBreakpoint",
                               instrumentation="beforeScriptExecution")
            print("instrumentation breakpoint:", json.dumps(r.get("result", r.get("error")))[:120])
        except Exception as e:  # noqa: BLE001
            print("instrumentation breakpoint unsupported:", str(e)[:120])
        deadline = time.time() + delay / 1000.0 + 25
        while time.time() < deadline:
            for sid, meta in list(cdp.scripts.items()):
                await probe.scan_and_arm(sid, meta)
            await probe.drain()
            if proc.poll() is not None:
                break
            await asyncio.sleep(0.2)
        while proc.poll() is None:
            await probe.drain()
            await asyncio.sleep(0.15)
        await probe.drain()
        stdout, stderr = proc.communicate(timeout=30)
        mint = None
        for candidate in (stdout.strip(), stdout.strip().splitlines()[-1] if stdout.strip() else ""):
            try:
                mint = json.loads(candidate)
                break
            except Exception:  # noqa: BLE001
                continue
        if mint is None:
            mint = {"stdout": stdout[-2000:], "stderr": stderr[-2000:]}
        json.dump({"mint": mint, "scripts": probe.scanned, "armed": probe.armed, "hits": probe.hits,
                   "hits_total": len(probe.hits)}, open(os.path.join(out, "node274.json"), "w"), indent=1)
        print("token_len", mint.get("token_len"), "armed", len(probe.armed), "hits", len(probe.hits))
        by = {}
        for h in probe.hits:
            by[h.get("site")] = by.get(h.get("site"), 0) + 1
        print("by site", by)
        for h in probe.hits[:24]:
            print("--- %-12s %s:%s:%s frames %s" % (h.get("site"), h.get("sid"), h.get("line"),
                                                    h.get("col"), "/".join(h.get("frames") or [])))
            print("    args", (h.get("args") or "")[:240])
    finally:
        try:
            await cdp.ws.close()
        except Exception:  # noqa: BLE001
            pass
        if proc.poll() is None:
            proc.kill()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild_now/material.json")
    ap.add_argument("--out", default="/tmp/bg-node274")
    ap.add_argument("--port", type=int, default=10761)
    ap.add_argument("--arm-delay", type=int, default=9000)
    ap.add_argument("--scan-only", action="store_true")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.arm_delay, a.scan_only))


if __name__ == "__main__":
    main()
