"""Pin the VM's random source to a constant and see which bytes of the token follow.

Section 42 showed field 473 (the tag-99 payload) and field 146's head are written before the program's
first read, and section 41 showed the bulk is the function that pushes `Math.random()*255|0`. This
probe replaces that expression with `170` in the interpreter text, mints once, and reports:

  * the token's 2-byte nonce (token[0:2], with the `C[1] = C[0]^30` invariant),
  * the first write to the tag-99 source field,
  * the tag-23 payload,

so "is this random filler?" becomes a value comparison instead of an entropy argument.

    python3 research/probe_rng.py --port 10530 --out /tmp/bg-rng
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA  # noqa: E402
import bgpatch  # noqa: E402
import dump_program as dp  # noqa: E402
from run_one import JS  # noqa: E402
from record_map import records, token_field  # noqa: E402

FILLER = "170"
# `Math.random()` appears 7 times (255 filler, 1E9 id, this.n, the 7824-newline padding), and
# `+new Date` 6 times; pinning one at a time is how the tag-99 tail gets attributed
RANDOM_PIN = "0.5"
DATE_PIN = "1700000000000"


async def run(port: int, out: str, mode: str = "filler") -> None:
    freq = open(os.path.join(HERE, "freq.txt")).read() if os.path.exists(
        os.path.join(HERE, "freq.txt")) else "hello"
    cs = dp.CS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-rng-%d" % port)
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
        pinned, n255 = re.subn(r"Math\.random\(\)\*255\|0", FILLER, plain)
        nrand = ndate = 0
        if mode in ("random", "both"):
            pinned, nrand = re.subn(r"Math\.random\(\)", RANDOM_PIN, pinned)
        if mode in ("date", "both", "all"):
            pinned, ndate = re.subn(r"\+new Date", DATE_PIN, pinned)
        nperf = 0
        if mode == "all":
            # the remaining time sources: bare `new Date`, `performance.now()`
            pinned, nperf = re.subn(r"performance\.now\(\)", "0", pinned)
            pinned, ndate2 = re.subn(r"new Date(?!\))", "(" + DATE_PIN + ")", pinned)
            ndate += ndate2
        print("build", tag, f"pinned: filler={n255} random={nrand} date={ndate} perf={nperf}")

        try:
            src, info = bgpatch.patch(pinned, blockcache=False, writes=True, loop=True,
                                      handlers=True, fieldread=True, emit=True)
        except SystemExit as e:
            print("full patch failed (%s); emit only" % e)
            src, info = bgpatch.patch(pinned, entry=False, ret=False, boot=False, emit=True)
        arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
        d = json.loads(await cs.eval(JS % (json.dumps(arr), json.dumps(src), json.dumps(freq))))
        os.makedirs(out, exist_ok=True)
        json.dump(d, open(os.path.join(out, "rng.json"), "w"))
        tok = d.get("tokstr") or ""
        raw = b""
        if tok:
            b = tok[1:]
            b += "=" * (-len(b) % 4)
            raw = base64.urlsafe_b64decode(b)
            print(f"token {len(raw)} B  head {raw[:8].hex(' ')}  "
                  f"nonce {raw[0]:02x} {raw[1]:02x}  xor {raw[0] ^ raw[1]:#04x}")
        field = token_field(d)
        srcs = {r["source"] for r in records(pinned, field) if r["source"]}
        print("token field", field, "source fields", sorted(srcs))
        for w in d.get("wr") or []:
            if int(w[0]) in srcs:
                print(f"  write field {w[0]} len {w[1]} rv {w[3]} value {str(w[2])[:40]}")
        for e in d.get("em") or []:
            if len(e) > 6 and e[6] in (23, 99, 117):
                p = base64.b64decode(e[5]) if e[5] else b""
                tail = p[-8:].hex(" ") if p else ""
                print(f"  emit tag {e[6]} len {e[1]} head {p[:14].hex(' ')} tail {tail}")
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10530)
    ap.add_argument("--out", default="/tmp/bg-rng")
    ap.add_argument("--mode", choices=("filler", "random", "date", "both", "all"), default="filler")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out, a.mode))


if __name__ == "__main__":
    main()
