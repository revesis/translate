"""Same build, same page, two payloads: does the content change what the VM emits?

A/B/A minting showed the *token bytes* do not react to the content string (section 50). This probe asks
the question one level down: with the emitter hook installed, mint with payload A, clear the log, mint
with payload B, and diff the emission lists (field, length, flag, payload head). Same build, same
instance, so build variance cannot explain a difference.

    python3 research/probe_payload.py --port 10720 --out /tmp/bg-pay --freq-a /tmp/freq_qr.txt
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA  # noqa: E402
import bgpatch  # noqa: E402
import dump_program as dp  # noqa: E402

JS = r"""(async () => {
  const arr = %s, src = %s, f1 = %s, f2 = %s;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 200); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({stage: 'install', evalErr: evalErr});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false,
               [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const mint = (f) => new Promise((res) => api[0]((t) => res(String(t)),
                                                  [f, undefined, undefined, undefined]));
  // the emit hook writes to the *instance* (`vm.__em`), which the boot hunk publishes as
  // window.__vmref; the global `VM` is a different object and reading it returns nothing
  const realms = [window];
  const walk = (w) => {
    let fs = [];
    try { fs = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of fs) { try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {} }
  };
  walk(window);
  const inst = (() => { for (const w of realms) { try { if (w.__vmref) return w.__vmref; } catch (e) {} } return VM; })();
  // the head chunks are emitted while the API is being built (VM.a), the records during the mint,
  // so the baseline is taken after setup and only the mint-phase slice is compared
  const base = (inst.__em || []).length;
  const t1 = await mint(f1);
  const n1 = (inst.__em || []).length;
  const em1 = (inst.__em || []).slice(base, n1);
  const t2 = await mint(f2);
  const em2 = (inst.__em || []).slice(n1);
  const cut = (e) => [e[0], e[1], (e.length > 6 ? e[6] : 0), (e[5] || '').slice(0, 24)];
  return JSON.stringify({stage: 'ok', t: [String(t1), String(t2)],
                         e: [em1.map(cut), em2.map(cut)]});
})()"""


async def run(port: int, out: str, fa: str | None, fb: str | None) -> None:
    f1 = open(fa or os.path.join(HERE, "freq.txt")).read() if (fa or os.path.exists(
        os.path.join(HERE, "freq.txt"))) else "hello"
    f2 = open(fb).read() if fb else (f1.replace("&", "&zz=1&", 1) if "&" in f1 else f1 + "&zz=1")
    cs = dp.CS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-pay-%d" % port)
    await cs.start()
    try:
        await cs.send("Network.enable")
        await cs.navigate(dp.URL, settle=7)
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        arr = json.loads("[" + dp.parse_material(html)[4:])
        plain = arr[5][-1]
        tag = str(arr[2])[:16]
        try:
            src, info = bgpatch.patch(plain, blockcache=False, writes=True, loop=True,
                                      handlers=True, fieldread=True, emit=True)
        except SystemExit as e:
            print("full patch failed (%s); emit only" % e)
            src, info = bgpatch.patch(plain, entry=False, ret=False, boot=False, emit=True)
        arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
        d = json.loads(await cs.eval(JS % (json.dumps(arr), json.dumps(src),
                                           json.dumps(f1), json.dumps(f2))))
        os.makedirs(out, exist_ok=True)
        json.dump(d, open(os.path.join(out, "pay.json"), "w"))
        if d.get("stage") != "ok":
            print("mint failed:", d)
            return
        print(f"build {tag}  freq A {len(f1)} chars  freq B {len(f2)} chars")
        for name, tok, em in (("A", d["t"][0], d["e"][0]), ("B", d["t"][1], d["e"][1])):
            print(f"  {name}: token {len(tok)} chars  emissions {len(em)}")
        ea, eb = d["e"]
        # compare as multisets of (field, len, flag); payload heads differ by randomness
        ka = sorted((e[0], e[1], e[2]) for e in ea)
        kb = sorted((e[0], e[1], e[2]) for e in eb)
        print(f"  same emission shape: {ka == kb}")
        if ka != kb:
            only_a = [x for x in ka if x not in kb]
            only_b = [x for x in kb if x not in ka]
            print(f"    only in A: {only_a[:12]}")
            print(f"    only in B: {only_b[:12]}")
        fields_a = sorted({e[0] for e in ea})
        fields_b = sorted({e[0] for e in eb})
        print(f"  fields A: {fields_a}")
        print(f"  fields B: {fields_b}")
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10720)
    ap.add_argument("--out", default="/tmp/bg-pay")
    ap.add_argument("--freq-a")
    ap.add_argument("--freq-b")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out, a.freq_a, a.freq_b))


if __name__ == "__main__":
    main()
