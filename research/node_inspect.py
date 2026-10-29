"""Capture the source the VM actually evaluates, without wrapping its eval.

Why this exists: the frame-side copy the VM runs is NOT the interpreter text the page hands out. It is
a different rendering (comments intact, `var PD=function...` instead of the minified prologue) that the
program assembles per run, so a stack position (`<anonymous>:line:col`) can only be read against that
run's own text. Wrapping `window.eval` to save it is not an option - any wrapper turns the handler's
direct eval into an indirect one and the first program handler then throws `fC is not defined`.

So: `Debugger.scriptParsed` + `Debugger.getScriptSource`, which is invisible to the VM.

    python3 research/node_inspect.py --material /tmp/bgbuild/material.json
    # -> /tmp/inspect_src_<id>.js  and the ERRSTACK lines from the run on stdout
"""
import argparse
import asyncio
import json
import os
import re
import subprocess
import urllib.request

import websockets

HERE = os.path.dirname(os.path.abspath(__file__))
MINT = os.path.join(HERE, "node_mint.mjs")


async def run(material: str, port: int, min_len: int, interp_file: str | None) -> None:
    args = ["node", f"--inspect-brk=127.0.0.1:{port}", MINT, "--material", material,
            "--out", "/tmp/inspect-token.bin"]
    if interp_file:
        args += ["--interp-file", interp_file]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    saved = {}
    try:
        ws_url = None
        for _ in range(100):
            try:
                targets = json.loads(urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/json/list", timeout=2).read())
                page = next((t for t in targets if t.get("type") == "node"), None)
                if page:
                    ws_url = page["webSocketDebuggerUrl"]
                    break
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.2)
        if not ws_url:
            raise SystemExit("no inspector target")

        mid = 0
        pending: dict = {}
        scripts: list = []

        async def send(ws, method, **params):
            nonlocal mid
            mid += 1
            fut = asyncio.get_running_loop().create_future()
            pending[mid] = fut
            await ws.send(json.dumps({"id": mid, "method": method, "params": params}))
            return await asyncio.wait_for(fut, timeout=60)

        async with websockets.connect(ws_url, max_size=128 * 1024 * 1024) as ws:
            done = asyncio.Event()

            async def reader():
                async for raw in ws:
                    msg = json.loads(raw)
                    if "id" in msg:
                        fut = pending.pop(msg["id"], None)
                        if fut and not fut.done():
                            fut.set_result(msg.get("result", {}))
                    elif msg.get("method") == "Debugger.scriptParsed":
                        scripts.append(msg["params"])
                    elif msg.get("method") == "Runtime.executionContextDestroyed":
                        pass
                    if msg.get("method") in ("Runtime.executionContextsCleared",):
                        pass

            task = asyncio.create_task(reader())
            await send(ws, "Debugger.enable")
            await send(ws, "Runtime.enable")
            await send(ws, "Runtime.runIfWaitingForDebugger")
            # The mint is ~200 ms; poll the process rather than the protocol.
            while proc.poll() is None:
                await asyncio.sleep(0.2)
            await asyncio.sleep(0.5)
            for sc in scripts:
                if (sc.get("length") or 0) >= min_len:
                    try:
                        src = (await send(ws, "Debugger.getScriptSource",
                                          scriptId=sc["scriptId"])).get("scriptSource", "")
                    except Exception:  # noqa: BLE001
                        continue
                    path = f"/tmp/inspect_src_{sc['scriptId']}.js"
                    open(path, "w").write(src)
                    saved[path] = len(src)
            task.cancel()
    finally:
        out, _ = proc.communicate(timeout=30)

    print("scripts seen:", len(scripts),
          [(sc.get("scriptId"), sc.get("url") or "<no-url>", sc.get("length")) for sc in scripts
           if not sc.get("url") or "interp" in (sc.get("url") or "")][:20])
    print("saved scripts:", {k: v for k, v in saved.items()})
    lines = (out or "").splitlines()
    for i, line in enumerate(lines):
        if line.startswith(("ERRSTACK", "ERRCOLLECT")):
            print("\n".join(lines[i:i + 7]))
            print("---")
    stacks = re.findall(r"at \w+ \(<anonymous>:(\d+):(\d+)\)", out or "")
    if stacks:
        print("first frame positions:", stacks[:3])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild/material.json")
    ap.add_argument("--port", type=int, default=9311)
    ap.add_argument("--min-len", type=int, default=20000)
    ap.add_argument("--interp-file", default=None)
    a = ap.parse_args()
    asyncio.run(run(a.material, a.port, a.min_len, a.interp_file))


if __name__ == "__main__":
    main()
