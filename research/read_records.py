"""Turn a field-write log plus its read log into per-write program records.

The two logs are produced by the same run (`dump_program.py --fields`, which returns `wrA`,
`rd` and `rv`), and both live on the VM instance, so a write's 4th element is the number of
reads that had completed when it happened. Consecutive writes therefore delimit the program
region that produced them - that is the closest thing to a "record" boundary we have.

Reads are tokenised with the encoding the interpreter uses (see bgpatch.py / the notes):
one 8-bit read is a value 0..127; an 8-bit read with bit 7 set is followed by a 2-bit read
and the pair encodes `(v & 0x7f) << 2 | t`, i.e. 128..511. A 32-bit read with the decrypt
flag off is one of the program's seed words.

Usage:
    python3 research/read_records.py /tmp/bg-f-al/run_fields.json --table
    python3 research/read_records.py /tmp/bg-f-al/run_fields.json --record 60
    python3 research/read_records.py /tmp/bg-f-al/run_fields.json --fid 201
"""
import argparse
import json
import sys


def tokens(log, vals):
    """(bit position, width, value, kind) for every read, with escapes folded."""
    seq = [(int(e[0]), int(e[2]), int(v[1]) if isinstance(v, list) else int(v))
           for e, v in zip(log, vals)]
    out, read_to_tok, i = [], [], 0
    while i < len(seq):
        w, s, v = seq[i]
        if w == 8 and i + 1 < len(seq) and seq[i + 1][0] == 2 and s + 8 == seq[i + 1][1]:
            out.append((s, 10, (v - 128) << 2 | seq[i + 1][2], "esc"))
            read_to_tok += [len(out) - 1, len(out) - 1]
            i += 2
        else:
            out.append((s, w, v, "seed" if w == 32 else "raw"))
            read_to_tok.append(len(out) - 1)
            i += 1
    return out, read_to_tok


def load(path):
    d = json.load(open(path))
    log = d.get("rd") or []
    vals = d.get("rv") or []
    writes = d.get("wrA") or []
    toks, r2t = tokens(log, vals)
    return d, toks, r2t, writes


def as_text(tok_slice):
    """Best-effort ascii view of the payload tokens (they are not plaintext)."""
    return "".join(chr(v) if 32 <= v < 127 else "." for _, _, v, _ in tok_slice)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--table", action="store_true", help="one line per write: fid, size, read span")
    ap.add_argument("--record", type=int, help="dump the token range of write #N")
    ap.add_argument("--fid", type=int, help="dump every record that wrote this field id")
    ap.add_argument("--limit", type=int, default=24, help="tokens per record to print")
    a = ap.parse_args()

    d, toks, r2t, writes = load(a.path)
    print(f"build {d.get('build', {}).get('hash', '?')[:20]}  reads {len(d.get('rd') or [])}"
          f" -> tokens {len(toks)}  writes {len(writes)}  token {d.get('tokA')}")
    prev = 0
    spans = []
    for n, w in enumerate(writes):
        idx = w[3] if len(w) > 3 else 0
        t0 = r2t[prev] if prev < len(r2t) else len(toks) - 1
        t1 = r2t[min(idx, len(r2t) - 1)] if r2t else 0
        spans.append((n, w, t0, t1))
        prev = idx

    def show(n, w, t0, t1):
        rng = toks[t0:max(t1, t0) + 1]
        val = str(w[2])
        val = val if len(val) <= 48 else val[:45] + "..."
        print(f"#{n} fid={w[0]} size={w[1]} reads={t1 - t0 + 1} value={val!r}")
        print("   " + " ".join(f"{s}:{wd}={v}{'e' if k == 'esc' else ''}{'S' if k == 'seed' else ''}"
                               for s, wd, v, k in rng[:a.limit]))
        if len(rng) > a.limit:
            print(f"   ... {len(rng) - a.limit} more tokens")

    if a.table:
        for n, w, t0, t1 in spans:
            val = str(w[2])
            print(f"#{n:4d} fid={w[0]:4d} size={w[1]:6d} toks={t1 - t0 + 1:6d} "
                  f"pos={toks[t0][0] if toks else 0:8d} {val[:40]!r}")
    if a.record is not None:
        for n, w, t0, t1 in spans:
            if n == a.record:
                show(n, w, t0, t1)
    if a.fid is not None:
        for n, w, t0, t1 in spans:
            if w[0] == a.fid:
                show(n, w, t0, t1)


if __name__ == "__main__":
    sys.exit(main())
