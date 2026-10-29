#!/usr/bin/env python3
"""Read the patched build's engine log: the ordered stream of dynamic compilations, and the errors.

The patched Chromium (research/patch_chromium.py) prints two kinds of line to stderr:

    [EVALLOG] len=<n> ctx=<ptr> head=<first 120 chars>
    [ERRLOG] <message>

This turns that into the thing we actually need: the program's instruction stream as the realm sees it,
in order, with the field ids each generated handler mentions, plus where the engine-constructed errors
land in that stream. Compare it with the Node harness (which gets 3 entries in and then throws).

    python3 research/analyze_evallog.py /tmp/chrome-stderr.log --handlers
    python3 research/analyze_evallog.py /tmp/chrome-stderr.log --json /tmp/stream.json
"""
import argparse
import json
import re

LINE = re.compile(r"\[EVALLOG\] len=(\d+) ctx=(0x[0-9a-f]+) head=(.*)$")
ERR = re.compile(r"\[ERRLOG\] (.*)$")
# The generated handlers read fields through these accessors; ids are literals in the source.
READS = [
    ("Z", re.compile(r"\bZ\([A-Za-z_$][\w$]*,(\d+)\)")),
    ("a", re.compile(r"\ba\((\d+),")),
    ("C", re.compile(r"\bC\([A-Za-z_$][\w$]*,(\d+)\)")),
    ("W", re.compile(r"\bW\((\d+),")),
    ("n", re.compile(r"\bn\([A-Za-z_$][\w$]*,(\d+)\)")),
    ("F", re.compile(r"\bF\([A-Za-z_$][\w$]*,(\d+)\)")),
]


def unescape(head: str) -> str:
    return head.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")


def classify(n: int) -> str:
    if n > 50000:
        return "interp"
    if n < 400:
        return "handler"
    return "other"


def fields(src: str) -> dict:
    out = {}
    for name, pat in READS:
        ids = sorted({int(x) for x in pat.findall(src)})
        if ids:
            out[name] = ids
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--handlers", action="store_true", help="print every handler with its field reads")
    ap.add_argument("--json", default=None)
    ap.add_argument("--limit", type=int, default=40)
    a = ap.parse_args()

    stream = []
    for line in open(a.path, errors="replace"):
        m = LINE.search(line)
        if m:
            src = unescape(m.group(3))
            stream.append({"kind": "eval", "len": int(m.group(1)), "ctx": m.group(2),
                           "head": src, "class": classify(int(m.group(1))),
                           "fields": fields(src)})
            continue
        m = ERR.search(line)
        if m:
            stream.append({"kind": "error", "text": m.group(1)[:400]})

    evals = [r for r in stream if r["kind"] == "eval"]
    errs = [r for r in stream if r["kind"] == "error"]
    print(f"evals {len(evals)}  errors {len(errs)}")
    for cls in ("interp", "handler", "other"):
        n = sum(1 for r in evals if r["class"] == cls)
        print(f"  {cls:8s} {n}")
    ctxs = {}
    for r in evals:
        ctxs.setdefault(r["ctx"], []).append(r)
    for ctx, rs in ctxs.items():
        print(f"  ctx {ctx}: {len(rs)} evals, "
              f"{sum(1 for r in rs if r['class'] == 'handler')} handlers")

    handlers = [r for r in evals if r["class"] == "handler"]
    if a.handlers:
        print("\n-- handler stream")
        for i, r in enumerate(handlers[: a.limit]):
            f = r["fields"]
            print(f"{i:3d} len={r['len']:4d} ctx={r['ctx']} "
                  f"{'; '.join(f'{k}:{v}' for k, v in f.items())}")
            print(f"     {r['head'][:110]}")
    print("\n-- errors")
    for r in errs[:20]:
        print("   ", r["text"][:160])

    if a.json:
        json.dump(stream, open(a.json, "w"), indent=1)
        print("wrote", a.json)


if __name__ == "__main__":
    main()
