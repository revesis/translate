"""Rebuild field 146's byte stream from the emission log and check it against the token.

Each emitter call may push one flag byte before its payload (`J&&L(255-~(J&255)+-256)`), so the
stream is `flag + payload` per call, in call order. With that byte the accounting closes:
`token = nonce(2) + field146`, `field146 = head(3) + emissions`.

    python3 research/align_emits.py /tmp/bg-e2/one.json
    python3 research/align_emits.py /tmp/bg-*/one.json --all
"""
import argparse
import base64
import json
import sys


def token_bytes(tok: str) -> bytes:
    body = tok[1:] if tok.startswith(";") else tok
    body += "=" * (-len(body) % 4)
    return base64.urlsafe_b64decode(body)


def emission_stream(em) -> bytes:
    """flag byte (when set) + payload, per call, in call order, for field 146 only."""
    out = bytearray()
    for e in em:
        if int(e[0]) != 146:
            continue
        flag = int(e[6]) if len(e) > 6 and e[6] is not None else 0
        if flag:
            out.append(flag & 0xFF)
        if len(e) > 5 and e[5]:
            out += base64.b64decode(e[5])
        elif len(e) > 4 and e[4]:
            out += bytes(e[4])
    return bytes(out)


def align(path: str, verbose: bool = True) -> dict:
    d = json.load(open(path))
    tok = d.get("tokstr") or ""
    em = [e for e in (d.get("em") or []) if isinstance(e, list) and len(e) >= 3]
    raw = token_bytes(tok)
    stream = emission_stream(em)
    f146 = raw[2:]                       # token = nonce(2) + field146
    head = f146[:3]                      # b8 <nonce[1]> <byte>; the emitted stream starts at 3
    body = f146[3:]
    ok = body == stream
    first_diff = next((i for i, (a, b) in enumerate(zip(body, stream)) if a != b), None)
    out = {"path": path, "build": d.get("build"), "token_chars": len(tok), "token_bytes": len(raw),
           "emits": len(em), "emits146": sum(1 for e in em if int(e[0]) == 146),
           "stream": len(stream), "body": len(body), "exact": ok,
           "first_diff": first_diff, "head": head,
           "flag_bytes": [(i, int(e[6])) for i, e in enumerate(em)
                          if len(e) > 6 and e[6]]}
    if verbose:
        print(f"{path}  build {out['build']}  token {len(tok)} chars / {len(raw)} bytes")
        print(f"  emits {out['emits']} (field 146: {out['emits146']})  stream {len(stream)} B  "
              f"body {len(body)} B  exact={ok}" + (f"  first diff at {first_diff}" if not ok else ""))
        print(f"  head {head.hex(' ')}  flag bytes {[(i, hex(v)) for i, v in out['flag_bytes']]}")
        if not ok:
            i = first_diff or 0
            print(f"  body   {body[max(0, i - 8):i + 16].hex(' ')}")
            print(f"  stream {stream[max(0, i - 8):i + 16].hex(' ')}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--all", action="store_true", help="skip runs without emissions")
    a = ap.parse_args()
    for p in a.paths:
        d = json.load(open(p))
        if a.all and not d.get("em"):
            continue
        align(p)
        print()


if __name__ == "__main__":
    sys.exit(main())
