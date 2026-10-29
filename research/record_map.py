"""Map each token record to the field it copies and the handler that filled that field.

Section 41 read the serializer's record table off the call sites (`tag`, payload = `len16 + field(id)`).
This tool closes the loop for one run: for every record, it resolves the source field id from the
assignment just before the call site, then joins that field's writes to the instructions that made
them (read-count window, same rule as `disasm.py`) and prints the op ids plus the handler text.

    python3 research/record_map.py /tmp/bg-l-10513/one.json
    python3 research/record_map.py /tmp/bg-l-10513/one.json --interp /tmp/bg-l-10513/interp_X.js
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
from align_emits import emission_stream, token_bytes  # noqa: E402


def balanced(text: str, i: int):
    depth = 0
    for j in range(i, min(len(text), i + 2000)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j
    return None, None


def split_args(text: str) -> list:
    out, depth, cur = [], 0, ""
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def token_field(d: dict) -> int:
    """The field whose emission stream equals the token body (the id rotates per build)."""
    raw = token_bytes(d.get("tokstr") or "")
    em = [e for e in (d.get("em") or []) if isinstance(e, list)]
    body = raw[5:]          # token = nonce(2) + head(3) + emitted stream
    for f in sorted({int(e[0]) for e in em}):
        if emission_stream(em, f) == body:
            return f
    return 146


def records(interp: str, field: int) -> list:
    """(tag, target field, source field or None, source expression) per serializer call site."""
    out = []
    for m in re.finditer(r"(?<![\w.$])(\w+)\(", interp):
        if interp[max(0, m.start() - 9):m.start()].endswith("=function"):
            continue
        args, _ = balanced(interp, m.end() - 1)
        if not args:
            continue
        parts = split_args(args)
        if len(parts) < 4 or str(field) not in parts:
            continue
        tag = next((int(p) for p in reversed(parts) if p.isdigit()), None)
        if tag is None:
            continue
        # the payload is the one argument that is neither the target field, nor the instance, nor
        # a bare number; taking the longest of those also covers `len1 + counter` records
        cand = [p for p in parts if p not in (str(field), "this") and not p.isdigit()]
        payload = max(cand, key=len) if cand else ""
        src_var = None
        mc = re.search(r"\.concat\((\w+)\)", payload)
        if mc:
            src_var = mc.group(1)
        src_field, src_expr = None, payload
        if src_var:
            # the value is bound just before the call: `YI=z(311,this)` / `T=w(this,473)`
            back = interp[max(0, m.start() - 900):m.start()]
            mb = None
            # `YI=z(311,this)` or `T=w(this,473)`: the field id is whichever argument is not the
            # instance, and the accessor name rotates, so only the number is trusted
            for cand in re.finditer(re.escape(src_var) + r"=(\w+)\((\w+),(\w+)\)", back):
                a1, a2 = cand.group(2), cand.group(3)
                for arg in (a1, a2):
                    if arg.isdigit():
                        mb = cand
                        src_field = int(arg)
                if mb:
                    break
            if mb:
                src_expr = mb.group(0)
        out.append({"fn": m.group(1), "tag": tag, "target": field,
                    "source": src_field, "expr": src_expr})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--interp", help="interpreter text (default: interp_*.js next to the run)")
    a = ap.parse_args()

    d = json.load(open(a.path))
    interp_path = a.interp
    if not interp_path:
        cand = glob.glob(os.path.join(os.path.dirname(a.path), "interp_*.js"))
        if not cand:
            raise SystemExit("no interp_*.js next to the run; pass --interp")
        interp_path = cand[0]
    interp = open(interp_path).read()
    field = token_field(d)
    recs = records(interp, field)
    hn = {int(k): v for k, v in (d.get("hn") or {}).items()}

    _, reads, ips, writes, freads = disasm.load(a.path)
    bounds, missed = disasm.segment(reads, ips)
    ins = disasm.instructions(reads, bounds, writes, freads)
    # instruction index -> op id and the fields it wrote
    ops_by_write = collections.defaultdict(list)
    for x in ins:
        for f in x["written"]:
            ops_by_write[int(f)].append(x["tokens"][0] if x["tokens"] else None)

    print(f"run {a.path}  build {d.get('build')}  token field {field}  "
          f"reads {len(reads)}  instructions {len(ins)}  writes {len(writes)}")
    print(" tag  target  source  writes  bytes  ops (top)              handler")
    seen = set()
    for r in sorted({(x["tag"], x["source"]): x for x in recs}.values(),
                    key=lambda x: (x["tag"], x["source"] or 0)):
        key = (r["tag"], r["source"])
        if key in seen:
            continue
        seen.add(key)
        src = r["source"]
        ws = [w for w in writes if src is not None and int(w[0]) == src]
        ops = collections.Counter(ops_by_write.get(src or -1, []))
        top = ", ".join(f"{o}x{n}" for o, n in ops.most_common(3)) or "-"
        h = (hn.get(ops.most_common(1)[0][0]) if ops else "") or ""
        h = re.sub(r"\s+", " ", h)[:44]
        print(f" {r['tag']:4d} {r['target']:6d} {str(src):>6s} {len(ws):7d} "
              f"{sum(int(w[1]) for w in ws):6d}  {top:22s} {h}")
        if src is None:
            print(f"        payload expression: {r['expr'][:70]}")
    if missed:
        print(f"  ({missed} boundaries unmapped)")
    extra = [r for r in recs if r["source"] is None]
    if extra:
        print("  call sites whose source could not be resolved:",
              sorted({(r["tag"], r["expr"][:40]) for r in extra}))


if __name__ == "__main__":
    main()
