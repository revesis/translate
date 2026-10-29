"""Ordered log of every eval the VM performs in a trusted Chrome mint - without touching the page.

Why this and not a patched Chromium: `Debugger.setBreakpointOnFunctionCall` is a V8-level breakpoint,
so it does not replace `window.eval`, does not add a scope, and does not show up in the interpreter's
own checks - the token stays in the trusted range (measured, printed at the end). On every hit the
first argument is read out of the call frame with `Debugger.evaluateOnCallFrame`, which is the source
the program asked the realm to run.

    python3 research/probe_evaltrace.py --material /tmp/bgbuild/material.json --out /tmp/bg-evaltrace

Output: /tmp/bg-evaltrace/evals.jsonl, one record per eval - realm context, source (full), and whether
it threw. This is the stream the Node harness only gets 3 entries into.
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
  return JSON.stringify({tok: String(tok)});
})()"""


class ET(ChromeSession):
    """Chrome session that breakpoints the frame realm's eval and records each call's source."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.ctx_seen = set()
        self.script_ctx = {}
        self.bp_ctx = set()
        self.records = []
        self.errors = []
        self.pending = []

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
                    self.script_ctx[p.get("scriptId")] = p.get("executionContextId")
                    continue
                if m == "Runtime.executionContextCreated":
                    c = msg["params"]["context"]
                    cid = c.get("id")
                    self.ctx_seen.add(cid)
                    # Breakpoint `window.eval` in every context: the page realm's copy runs the boot
                    # and the frame realm's copy runs the program, and both are wanted, labelled.
                    # no inline install: the interp replaces `window.eval` after it boots, so the
                    # breakpoint is (re)installed from the driver loop below, repeatedly.
                elif m == "Debugger.paused":
                    # Never await inside the reader: the reply we would wait for is delivered by this
                    # very loop. Hand the pause to a task, which resumes when it is done.
                    asyncio.create_task(self._handle_pause((msg["params"].get("callFrames") or [{}])[0]))
        except Exception:  # noqa: BLE001
            pass

    async def _install_eval_bp(self, cid):
        # A context exists a moment before its global is usable, so retry briefly.
        for attempt in range(12):
            try:
                r = await self._raw("Runtime.evaluate", expression="window.eval",
                                    contextId=cid, returnByValue=False)
                oid = (r.get("result") or {}).get("objectId")
                if oid:
                    await self._raw("Debugger.setBreakpointOnFunctionCall", objectId=oid)
                    self.bp_ctx.add(cid)
                    return
                self.errors.append(["no-object", cid, str(r)[:160]])
            except Exception as e:  # noqa: BLE001
                self.errors.append(["install", cid, str(e)[:160]])
            await asyncio.sleep(0.05)

    async def _handle_pause(self, frame):
        rec = {"ctx": self._ctx_of(frame), "src": None, "type": None}
        try:
            r = await self._raw("Debugger.evaluateOnCallFrame",
                                callFrameId=frame.get("callFrameId"),
                                expression="[typeof arguments[0]==='string'?arguments[0]:null,"
                                           "typeof arguments[0]]",
                                returnByValue=True)
            val = (r.get("result") or {}).get("value") or [None, None]
            rec["src"], rec["type"] = val[0], val[1]
        except Exception as e:  # noqa: BLE001
            rec["err"] = str(e)[:120]
        self.records.append(rec)
        try:
            await self._raw("Debugger.resume")
        except Exception:  # noqa: BLE001
            pass

    def _ctx_of(self, frame):
        """Realm of a call frame, via the script it is in (scriptParsed carries the context id)."""
        return self.script_ctx.get((frame.get("location") or {}).get("scriptId"))


async def run(material_path: str, out: str, port: int, chrome: str) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    cs = ET(chrome, port, DEFAULT_UA, "/tmp/bg-et-%d" % port)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs.navigate(PAGE_URL, settle=7)
        # after navigation the document context is the lowest live id; treat it as the page realm
        mint = asyncio.create_task(cs.eval(MINT % (json.dumps(arr), json.dumps(freq), json.dumps(interp))))
        # The frame realm exists only during the mint, and its `eval` is replaced by the interpreter
        # once it boots; poll both for a couple of seconds and breakpoint whatever is there.
        for _ in range(20):
            await asyncio.sleep(0.15)
            for cid in list(cs.ctx_seen):
                if cid in cs.bp_ctx:
                    continue
                await cs._install_eval_bp(cid)
            if mint.done():
                break
        d = json.loads(await mint)
        tok = d.get("tok") or ""
        raw = tok[1:] if tok.startswith(";") else tok
        blob = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        os.makedirs(out, exist_ok=True)
        json.dump({"token_chars": len(tok), "token_bytes": len(blob), "head": blob[:16].hex(),
                   "contexts": sorted(cs.ctx_seen), "bp_contexts": sorted(cs.bp_ctx),
                   "evals": len(cs.records), "errors": cs.errors[:10]},
                  open(os.path.join(out, "summary.json"), "w"), indent=1)
        with open(os.path.join(out, "evals.jsonl"), "w") as f:
            for r in cs.records:
                f.write(json.dumps(r) + "\n")
        print("token", len(tok), "chars", len(blob), "B head", blob[:16].hex())
        print("contexts", sorted(cs.ctx_seen), "breakpointed", sorted(cs.bp_ctx))
        print("evals recorded", len(cs.records), "errors", cs.errors[:4])
        for r in cs.records[:8]:
            print("   ", r.get("type"), (r.get("src") or "")[:90].replace("\n", "\\n"))
        print("wrote", out)
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild/material.json")
    ap.add_argument("--out", default="/tmp/bg-evaltrace")
    ap.add_argument("--port", type=int, default=10421)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome))


if __name__ == "__main__":
    main()
