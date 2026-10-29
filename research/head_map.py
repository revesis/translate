"""Where the head chunks get their values: the emit op, the source field, and who filled that field.

The head of the token (before the first tagged record) is written by program instructions of the form
`[op, sourceField, tokenField]` (section 39). This tool prints, per head chunk, the op that emitted it
and - for the source field it copies - the op that wrote that field, so "the marker comes from field
40" becomes "field 40 was written by op X, handler ...".

    python3 research/head_map.py /tmp/bg-k-10502/one.json
"""
import argparse
import collections
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import disasm  # noqa: E402
from align_emits import token_bytes  # noqa: E402


def token_field_of(d: dict) -> int:
    """The field whose emissions carry the token body (id rotates per build)."""
    raw = token_bytes(d.get("tokstr") or "")
    em = [e for e in (d.get("em") or []) if isinstance(e, list)]
    body = raw[5:]
    for f in sorted({int(e[0]) for e in em}):
        out = bytearray()
        for e in em:
            if int(e[0]) != f:
                continue
            if len(e) > 6 and e[6]:
                out.append(int(e[6]) & 0xFF)
            if len(e) > 5 and e[5]:
                import base64
                out += base64.b64decode(e[5])
        if bytes(out) == body:
            return f
    return 146


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--interp")
    ap.add_argument("--limit", type=int, default=12)
    a = ap.parse_args()

    d = json.load(open(a.path))
    field = token_field_of(d)
    _, reads, ips, writes, freads = disasm.load(a.path)
    bounds, _missed = disasm.segment(reads, ips)
    ins = disasm.instructions(reads, bounds, writes, freads)
    hn = {int(k): v for k, v in (d.get("hn") or {}).items()}

    # instruction index -> (tokens, written fields); and the reverse for a field -> writing ops
    by_field = collections.defaultdict(list)
    for x in ins:
        for f in x["written"]:
            by_field[int(f)].append(x)

    def instr_for(rv: int):
        for k, (i, _depth) in enumerate(bounds):
            j = bounds[k + 1][0] if k + 1 < len(bounds) else len(reads)
            if i < rv <= j:
                return ins[k] if k < len(ins) else None
        return None

    print(f"run {a.path}  build {d.get('build')}  token field {field}")
    print("  #  bytes  emit-op  src  who wrote src            handler")
    head = [e for e in (d.get("em") or []) if int(e[0]) == field and not (len(e) > 6 and e[6])]
    for n, e in enumerate(head[:a.limit], 1):
        payload = e[5] or ""
        x = instr_for(int(e[3]))
        if not x:
            print(f"  {n:2d} {int(e[1]):5d}  (no instruction window)")
            continue
        t = x["tokens"]
        op, src = (t[0], t[1]) if len(t) >= 2 else (t[0], None)
        ws = by_field.get(src or -1, [])
        wop = ws[0]["tokens"][0] if ws and ws[0]["tokens"] else None
        h = re.sub(r"\s+", " ", (hn.get(wop) or ""))[:40] if wop else ""
        nw = len(ws)
        print(f"  {n:2d} {int(e[1]):5d}  {op:7d} {str(src):>4s}  "
              f"{('op ' + str(wop) + ' x' + str(nw)) if wop else '-':22s} {h}")
    # summary of the head's source fields
    srcs = collections.Counter()
    for e in head:
        x = instr_for(int(e[3]))
        if x and len(x["tokens"]) >= 2:
            srcs[x["tokens"][1]] += 1
    print("  head source fields:", dict(srcs))


if __name__ == "__main__":
    main()
