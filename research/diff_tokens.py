"""Locate a content-bound region of the token by A/B/A minting and diffing.

Section 49 showed the head ignores the request content. If the token is bound to the body at all, the
binding has to be somewhere in the records. Method: mint A, B, A in one page load (same `VM.a`
instance), where B differs only in the content-binding string (`freq`). Everything that differs
between the two **A** mints is per-mint noise; a position that is *stable between the two A mints* but
*different in B* is content-sensitive - no heuristics about which fields are random.

    python3 research/diff_tokens.py --port 10680 --out /tmp/bg-diff
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

from bgr_sidecar import DEFAULT_UA  # noqa: E402
import dump_program as dp  # noqa: E402

JS = r"""(async () => {
  const arr = %s, plain = %s, f1 = %s, f2 = %s;
  try { delete window.ridgeslice; } catch (e) {}
  try { (0, eval)(plain); } catch (e) { return JSON.stringify({stage:'eval', err:String(e)}); }
  const VM = window.ridgeslice;
  if (!VM) return JSON.stringify({stage:'install'});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false,
               [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const mint = (f) => new Promise((res) => api[0]((t) => res(String(t)),
                                                  [f, undefined, undefined, undefined]));
  const a1 = await mint(f1), b = await mint(f2), a2 = await mint(f1);
  return JSON.stringify({stage: 'ok', t: [a1, b, a2]});
})()"""


def dec(tok: str) -> bytes:
    body = tok[1:] if tok.startswith(";") else tok
    body += "=" * (-len(body) % 4)
    return base64.urlsafe_b64decode(body)


def common_prefix(x: bytes, y: bytes, start: int = 0) -> int:
    n = 0
    while start + n < min(len(x), len(y)) and x[start + n] == y[start + n]:
        n += 1
    return n


def common_suffix(x: bytes, y: bytes) -> int:
    n = 0
    while n < min(len(x), len(y)) and x[-1 - n] == y[-1 - n]:
        n += 1
    return n


async def run(port: int, out: str) -> None:
    f1 = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    # a minimal, well-formed change: one extra form field, so the body stays the same shape
    f2 = f1.replace("&", "&zz=1&", 1) if "&" in f1 else f1 + "&zz=1"
    cs = dp.CS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-diff-%d" % port)
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
        d = json.loads(await cs.eval(JS % (json.dumps(arr), json.dumps(plain),
                                           json.dumps(f1), json.dumps(f2))))
        os.makedirs(out, exist_ok=True)
        json.dump(d, open(os.path.join(out, "diff.json"), "w"))
        if d.get("stage") != "ok":
            print("mint failed:", d)
            return
        a1, b, a2 = (dec(x) for x in d["t"])
        print(f"build {str(arr[2])[:16]}  lengths A {len(a1)}  B {len(b)}  A' {len(a2)}")
        print(f"  A head {a1[:24].hex(' ')}")
        print(f"  B head {b[:24].hex(' ')}")
        # per-mint noise = everything that differs between the two A mints
        pre = common_prefix(a1, a2, 5)          # skip the 5 per-mint bytes at the front
        suf = common_suffix(a1, a2)
        print(f"  A vs A': common prefix from 5 = {pre} B, common suffix = {suf} B "
              f"(noise window {len(a1) - suf - pre - 5} B in the middle)")
        # a position is content-sensitive if it is stable across the two A mints but differs in B
        stable = [(5 + i) for i in range(pre)] + \
                 [(len(a1) - 1 - i) for i in range(suf)]
        diffs = []
        for pos in stable:
            if pos < len(b) and a1[pos] != b[pos]:
                diffs.append((pos, a1[pos], b[pos]))
        print(f"  content-sensitive positions: {len(diffs)}")
        for pos, x, y in diffs[:20]:
            print(f"    at {pos:4d}: A {x:02x}  B {y:02x}")
        if not diffs:
            print("  -> B is identical to A everywhere the two A mints agree: no content binding in "
                  "the stable regions")
        # also: is the noise window the same size in B? (that is the bulk's random length)
        pre_b = common_prefix(a1, b, 5)
        suf_b = common_suffix(a1, b)
        print(f"  A vs B:  common prefix from 5 = {pre_b} B, common suffix = {suf_b} B "
              f"(diff window {len(a1) - suf_b - pre_b - 5} B)")
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10680)
    ap.add_argument("--out", default="/tmp/bg-diff")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out))


if __name__ == "__main__":
    main()
