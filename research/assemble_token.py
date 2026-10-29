"""Assemble a token from its spec, and check the assembler against a real capture.

The format is specified in docs/token-format.md; this is the executable version of that spec. Two modes:

  (default)  round-trip: take the pieces of one run (head constants + tagged records) and rebuild the
             token from the *layout*, then compare it with the token the VM actually produced. A match
             means the layout model is complete and the assembler emits bytes in the right order.
  --fresh    prototype mint: keep the per-load constants but generate a new nonce and new bulk, i.e.
             what an offline minter would do. The result is a syntactically valid token for the same
             load whose random regions are new.

    python3 research/assemble_token.py /tmp/bg-l-10512/one.json
    python3 research/assemble_token.py /tmp/bg-l-10512/one.json --fresh
"""
import argparse
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from align_emits import emission_stream, token_bytes  # noqa: E402


def token_field(d: dict) -> int:
    raw = token_bytes(d.get("tokstr") or "")
    em = [e for e in (d.get("em") or []) if isinstance(e, list)]
    body = raw[5:]
    for f in sorted({int(e[0]) for e in em}):
        if emission_stream(em, f) == body:
            return f
    return 146


def pieces(d: dict):
    """The token field's emissions in order, as (flag, payload).

    Untagged chunks are *interleaved* with tagged records (the counter byte `07` comes after the
    tag-117 record), so the stream cannot be split into "head" and "records" - it is one ordered list.
    """
    field = token_field(d)
    em = [e for e in (d.get("em") or []) if isinstance(e, list) and int(e[0]) == field]
    items = []
    for e in em:
        flag = int(e[6]) if len(e) > 6 and e[6] else 0
        payload = base64.b64decode(e[5]) if len(e) > 5 and e[5] else b""
        items.append((flag, payload))
    return field, items


def assemble(items, nonce: bytes, byte4: int, fresh_bulk=None) -> bytes:
    """token = nonce(2) + [b8, nonce[1], byte4] + sum(flag?1B:0 + payload), in emission order."""
    out = bytearray()
    out += nonce
    out += bytes([0xB8, nonce[1], byte4 & 0xFF])
    for flag, payload in items:
        if fresh_bulk is not None and flag == 23 and len(payload) > 2:
            payload = payload[:2] + fresh_bulk(len(payload) - 2)
        if flag:
            out.append(flag & 0xFF)
        out += payload
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--fresh", action="store_true",
                    help="new nonce and new bulk instead of the captured ones")
    a = ap.parse_args()
    d = json.load(open(a.path))
    raw = token_bytes(d.get("tokstr") or "")
    if not raw:
        raise SystemExit("this run has no token string saved")
    field, items = pieces(d)
    tagged = [(f, len(p)) for f, p in items if f]
    print(f"run {a.path}  build {d.get('build')}  token field {field}")
    print(f"  emissions {len(items)}  tagged {tagged}")
    if a.fresh:
        nonce = os.urandom(2)
        bulk = os.urandom
        out = assemble(items, nonce, raw[4], fresh_bulk=bulk)
        print(f"  fresh nonce {nonce.hex(' ')}  byte4 {raw[4]:02x} (copied: derivation unknown)")
        print(f"  assembled {len(out)} B vs captured {len(raw)} B  "
              f"marker intact={out[5:14] == raw[5:14]}")
        tok = ";" + base64.urlsafe_b64encode(out).decode().rstrip("=")
        print(f"  token: {tok[:64]}...")
        json.dump({"token": tok}, open(os.path.join(os.path.dirname(a.path) or ".",
                                                    "assembled.json"), "w"))
        return
    out = assemble(items, raw[0:2], raw[4])
    ok = out == raw
    print(f"  assembled {len(out)} B vs captured {len(raw)} B  identical={ok}")
    if not ok:
        n = min(len(out), len(raw))
        i = next((k for k in range(n) if out[k] != raw[k]), n)
        print(f"  first difference at {i}: assembled {out[max(0, i - 4):i + 8].hex(' ')}  "
              f"captured {raw[max(0, i - 4):i + 8].hex(' ')}")


if __name__ == "__main__":
    main()
