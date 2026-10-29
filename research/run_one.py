"""One page load, one mint, all three logs: instruction boundaries, reads, field writes.

`dump_program.py --fields` mints twice (payload A and B) to diff them, which breaks the
write-to-instruction join: the write log then holds both mints. This runner mints exactly once and
returns the three logs together, which is what `research/disasm.py` needs.

    python3 research/run_one.py --port 10290 --out /tmp/bg-one
    python3 research/disasm.py /tmp/bg-one/one.json --table
    python3 research/disasm.py /tmp/bg-one/one.json --emit /tmp/map.json
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
  const arr = %s, src = %s, freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  let evalErr = null;
  try { (0, eval)(src); } catch (e) { evalErr = String(e).slice(0, 200); }
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({stage: 'install', evalErr: evalErr});
  if (!window.__MINE) return JSON.stringify({stage: 'not-mine'});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const tok = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  const realms = [window];
  const walk = (w) => {
    let fs = [];
    try { fs = Array.from(w.document.querySelectorAll('iframe')); } catch (e) { return; }
    for (const f of fs) { try { const c = f.contentWindow; if (c) { realms.push(c); walk(c); } } catch (e) {} }
  };
  walk(window);
  let vm = null;
  for (const w of realms) { try { if (!vm && w.__vmref) vm = w.__vmref; } catch (e) {} }
  if (!vm) return JSON.stringify({stage: 'no vm', tok: tok.length});
  let ix = [];
  for (const w of realms) { try { if (w.__ixlog && w.__ixlog.length > ix.length) ix = w.__ixlog; } catch (e) {} }
  return JSON.stringify({tok: tok.length, tokstr: tok, ip: vm.__ip || [], rd: vm.__rd || [], rv: vm.__rv || [],
                         wr: vm.__wr || [], hn: vm.__hn || {}, fr: vm.__fr || [],
                         hr: vm.__hr || {}, em: vm.__em || [], ix: ix,
                         V: vm.V || vm.U || vm.j || null});
})()"""


async def run(port: int, out: str, ixproxy: bool = False) -> None:
    freq_path = os.path.join(HERE, "freq.txt")
    freq = open(freq_path).read() if os.path.exists(freq_path) else "hello"
    cs = dp.CS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-one-%d" % port)
    await cs.start()
    try:
        await cs.send("Network.enable")
        await cs.send("Fetch.enable", patterns=[{"urlPattern": "*js/bg/*", "requestStage": "Request"}])
        await cs.navigate(dp.URL, settle=7)
        if not cs.doc_request:
            raise SystemExit("no document response captured")
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        arr = json.loads("[" + dp.parse_material(html)[4:])
        plain = arr[5][-1]
        tag = str(arr[2])[:16]
        os.makedirs(out, exist_ok=True)
        open(os.path.join(out, "interp_" + tag + ".js"), "w").write(plain)
        # Builds rotate and each family moves the reader/writer anchors, so a full patch can fail
        # on a family nobody has taught `bgpatch` yet. The emit measurement does not need any of
        # those hunks: fall back to the emitter hook alone rather than losing the load.
        mode = "full"
        try:
            src, info = bgpatch.patch(plain, blockcache=False, writes=True, loop=True,
                                      handlers=True, fieldread=True, emit=True, ixproxy=ixproxy)
        except SystemExit as e:
            print("full patch failed (%s); retrying with emit only" % e)
            src, info = bgpatch.patch(plain, entry=False, ret=False, boot=False, emit=True,
                                      ixproxy=ixproxy)
            mode = "emit-only"
        arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
        print("build", tag, "mode", mode,
              {k: v for k, v in info.items() if k not in ("params", "wrappers")})
        d = json.loads(await cs.eval(JS % (json.dumps(arr), json.dumps(src), json.dumps(freq))))
        print({k: (len(v) if isinstance(v, (list, dict)) else v) for k, v in d.items()})
        d["build"] = tag
        json.dump(d, open(os.path.join(out, "one.json"), "w"))
        print("wrote", os.path.join(out, "one.json"))
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10290)
    ap.add_argument("--out", default="/tmp/bg-one")
    ap.add_argument("--ixproxy", action="store_true",
                    help="also wrap field accessors in a Proxy that logs index writes (section 44)")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out, a.ixproxy))


if __name__ == "__main__":
    main()
