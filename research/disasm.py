"""Turn one `--loop` + `--fields` run into an instruction table and a disassembly.

Requires the three logs a single run can produce (`/tmp/run_ops.py` does that, or
`dump_program.py --log-only --loop` for the boundary half):

    ip   instruction boundaries: [bit pointer, nesting depth] per executed instruction
    rd/rv  every read and its plaintext value, in order
    wr   field writes: [fieldId, size, json, readsCompletedWhenWritten]

Instruction k owns the reads between boundary k and k+1. A write belongs to the instruction whose
read window contains it (`i < readsCompleted <= j`, i.e. the write fires after its operands were
read, and one boundary later it would be attributed to the next instruction).

Token encoding, measured in section 25 of the notes: one 8-bit read is 0..127; a byte with bit 7
set is followed by a 2-bit read and encodes `(b & 0x7f) << 2 | t` (0..511).

Usage:
    python3 research/disasm.py ops.json --table
    python3 research/disasm.py ops.json --handler 87
    python3 research/disasm.py ops.json --instr 0:40
"""
import argparse
import collections
import json
import sys


def load(path):
    d = json.load(open(path))
    log = d.get("rd") or []
    vals = d.get("rv") or []
    reads = [(int(e[0]), int(e[2]), int(v[1]) if isinstance(v, list) else int(v))
             for e, v in zip(log, vals)]
    ips = [x for x in (d.get("ip") or []) if isinstance(x, (int, float)) or
           (isinstance(x, list) and len(x) == 2)]
    # `wr` comes from a write-log run, `wrA` from `--fields` (the first of its two mints)
    writes = [w for w in (d.get("wr") or d.get("wrA") or [])
              if isinstance(w, list) and len(w) >= 4]
    return d, reads, ips, writes


def segment(reads, ips):
    """Chronological mapping of boundaries to read indices, so loops and repeats resolve."""
    bounds, cur, missed = [], 0, 0
    for item in ips:
        ptr, depth = (item, None) if not isinstance(item, list) else item
        j = cur
        while j < len(reads) and reads[j][1] != ptr:
            j += 1
        if j >= len(reads):
            missed += 1
            continue
        bounds.append((j, depth))
        cur = j + 1
    return bounds, missed


def tokens(seg):
    out, i = [], 0
    while i < len(seg):
        w, start, v = seg[i]
        if w == 8 and i + 1 < len(seg) and seg[i + 1][0] == 2 and start + 8 == seg[i + 1][1]:
            out.append((v - 128) << 2 | seg[i + 1][2])
            i += 2
        else:
            out.append(v)
            i += 1
    return out


def instructions(reads, bounds, writes):
    out = []
    for k, (i, depth) in enumerate(bounds):
        j = bounds[k + 1][0] if k + 1 < len(bounds) else len(reads)
        t = tokens(reads[i:j])
        eff = [int(w[0]) for w in writes if i < int(w[3]) <= j]
        if t:
            out.append({"tokens": t, "written": eff, "depth": depth})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--table", action="store_true", help="per-handler profile")
    ap.add_argument("--handler", type=int, help="dump every instance of one handler")
    ap.add_argument("--instr", help="slice of instructions, e.g. 0:40")
    ap.add_argument("--limit", type=int, default=16, help="tokens per instruction when dumping")
    ap.add_argument("--emit", help="write a machine-readable map (op -> kind/arity/target)")
    a = ap.parse_args()

    d, reads, ips, writes = load(a.path)
    bounds, missed = segment(reads, ips)
    ins = instructions(reads, bounds, writes)
    depths = collections.Counter(x["depth"] for x in ins)
    print(f"reads {len(reads)}  boundaries {len(ips)} (unmapped {missed})  "
          f"instructions {len(ins)}  writes {len(writes)}  depths {dict(depths)}")

    if a.table:
        prof = collections.defaultdict(lambda: {"n": 0, "len": collections.Counter(),
                                                "wr": 0, "pos": collections.Counter()})
        for x in ins:
            t = x["tokens"]
            p = prof[t[0]]
            p["n"] += 1
            p["len"][len(t)] += 1
            if len(x["written"]) == 1:
                p["wr"] += 1
                if x["written"][0] in t[1:]:
                    p["pos"][t[1:].index(x["written"][0]) + 1] += 1
        print(f"distinct handlers {len(prof)}")
        print("handler   n  arity(top)                  writes  target-index")
        for h in sorted(prof, key=lambda x: -prof[x]["n"]):
            p = prof[h]
            print(f"  {h:4d} {p['n']:4d}  {str(dict(p['len'].most_common(3))):26s} "
                  f"{p['wr']:6d}  {dict(p['pos'].most_common(3))}")

    def show(x):
        w = ",".join(str(f) for f in x["written"]) or "-"
        t = " ".join(str(v) for v in x["tokens"][:a.limit])
        extra = "" if len(x["tokens"]) <= a.limit else f" ...(+{len(x['tokens']) - a.limit})"
        print(f"  [{t}{extra}]  writes {w}")

    if a.emit:
        hn = {int(k): v for k, v in (d.get("hn") or {}).items()}
        prof = collections.defaultdict(lambda: {"count": 0, "arities": collections.Counter(),
                                                "target_positions": collections.Counter(),
                                                "writes": 0, "samples": []})
        for x in ins:
            t = x["tokens"]
            p = prof[t[0]]
            p["count"] += 1
            p["arities"][len(t)] += 1
            if len(x["written"]) == 1:
                p["writes"] += 1
                if x["written"][0] in t[1:]:
                    p["target_positions"][t[1:].index(x["written"][0]) + 1] += 1
            if len(p["samples"]) < 3:
                p["samples"].append(t[:10])
        out = {"reads": len(reads), "instructions": len(ins), "writes": len(writes),
               "handlers": {str(op): {"value": (hn.get(op) or "")[:120],
                                       "count": pr["count"],
                                       "arities": dict(pr["arities"]),
                                       "writes": pr["writes"],
                                       "target_positions": dict(pr["target_positions"]),
                                       "samples": pr["samples"]}
                            for op, pr in prof.items()}}
        json.dump(out, open(a.emit, "w"), indent=1)
        print(f"wrote {a.emit} ({len(out['handlers'])} ops)")

    if a.handler is not None:
        for x in ins:
            if x["tokens"][0] == a.handler:
                show(x)
    if a.instr:
        lo, _, hi = a.instr.partition(":")
        lo, hi = int(lo or 0), int(hi or lo + 40)
        for x in ins[lo:hi]:
            show(x)


if __name__ == "__main__":
    sys.exit(main())
