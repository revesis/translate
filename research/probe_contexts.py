"""What are the VM's per-probe execution contexts? List every context the page creates during a mint.

Section 86 showed the browser's mining probes each running in a *different* execution context. This
records `Runtime.executionContextCreated` for one pristine mint, so the answer is measured rather than
assumed: origin, name, whether it is a default context (a frame/window) and its frame id.

    python3 research/probe_contexts.py --material /root/bg/build/material.json --out /root/bg/ctx
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


class Ctx(ChromeSession):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.contexts = []

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
                if msg.get("method") == "Runtime.executionContextCreated":
                    c = msg["params"]["context"]
                    aux = c.get("auxData") or {}
                    self.contexts.append({
                        "id": c.get("id"), "origin": c.get("origin", ""), "name": c.get("name", ""),
                        "isDefault": aux.get("isDefault"), "frameId": aux.get("frameId"),
                        "type": aux.get("type"),
                    })
        except Exception:  # noqa: BLE001
            pass


async def run(material_path: str, out: str, port: int, chrome: str) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    cs = Ctx(chrome, port, DEFAULT_UA, "/tmp/bg-ctx-%d" % port)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.navigate(PAGE_URL, settle=7)
        before = len(cs.contexts)
        d = json.loads(await cs.eval(MINT % (json.dumps(arr), json.dumps(freq), json.dumps(interp))))
        await asyncio.sleep(0.5)
        os.makedirs(out, exist_ok=True)
        json.dump({"token_chars": len(d.get("tok") or ""), "contexts": cs.contexts},
                  open(os.path.join(out, "ctx.json"), "w"), indent=1)
        print(f"token {len(d.get('tok') or '')} chars; contexts before mint {before}, "
              f"total {len(cs.contexts)}")
        for c in cs.contexts[before:]:
            print(f"  ctx {c['id']:>3} default={c['isDefault']} type={c['type']} "
                  f"origin={c['origin'][:40]!r} name={c['name'][:20]!r}")
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/root/bg/build/material.json")
    ap.add_argument("--out", default="/root/bg/ctx")
    ap.add_argument("--port", type=int, default=10650)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome))


if __name__ == "__main__":
    main()
