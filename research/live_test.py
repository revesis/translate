"""One controlled live request with an offline-assembled token (single attempt, no retries).

The format work (docs/token-format.md, section 52) can build a token byte-for-byte; the open question
is whether the service *accepts* one whose nonce and bulk were generated outside the VM. This tool does
exactly one request and classifies the answer:

    accepted       200 + a 4-element wrb.fr payload  (OCR text + translation)
    verified/echo  200 + a 1-element payload         (token verified, nothing extracted)
    rejected       400 + an `er` chunk               (token did not verify)
    blocked        HTML body / 403 / 429

Everything comes from ONE page load: the cookies, f.sid and bl from that page, and the per-load
constants from a patched mint in that same load. The token sent is assembled by
research/assemble_token.py with a fresh nonce and fresh bulk.

    python3 research/live_test.py --port 10750 --out /tmp/bg-live            # one request
    python3 research/live_test.py --port 10750 --dry-run                     # stop before the POST
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA  # noqa: E402
import bgpatch  # noqa: E402
import dump_program as dp  # noqa: E402
from run_one import JS as MINT_JS  # noqa: E402
from assemble_token import assemble, pieces  # noqa: E402
from gt_image import BATCHEXECUTE, CLIENT_HINTS, RPC, UA  # noqa: E402

FREQ_TL = "zh-CN"


def make_image(path: str) -> bytes:
    """A picture with unambiguous text, so a verified token must return 4 elements."""
    os.system("convert -size 1000x260 xc:white -fill black -pointsize 56 "
              "-annotate +30+90 'BACKUP JOB FAILED ON NODE DB-07' "
              "-annotate +30+180 'ERROR CODE 1284 - RETRY ABORTED' " + path)
    return open(path, "rb").read()


async def capture(port: int, image: bytes, mime: str, out: str):
    """One page load: cookies + f.sid/bl + a patched mint (for the per-load constants)."""
    b64 = base64.b64encode(image).decode()
    inner = json.dumps([[b64, mime], "auto", FREQ_TL], separators=(",", ":"))
    freq = json.dumps([[[RPC, inner, None, "generic"]]], separators=(",", ":"))
    cs = dp.CS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-live-%d" % port)
    await cs.start()
    try:
        await cs.send("Network.enable")
        await cs.navigate(dp.URL, settle=7)
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        import re
        sid = re.search(r'FdrFJe":"(-?\d+)"', html)
        bl = re.search(r'"cfb2h":"([^"]+)"', html)
        arr = json.loads("[" + dp.parse_material(html)[4:])
        plain = arr[5][-1]
        tag = str(arr[2])[:16]
        try:
            src, info = bgpatch.patch(plain, blockcache=False, writes=True, loop=True,
                                      handlers=True, fieldread=True, emit=True)
        except SystemExit as e:
            print("  full patch failed (%s); emit only" % e)
            src, info = bgpatch.patch(plain, entry=False, ret=False, boot=False, emit=True)
        arr[2] = base64.urlsafe_b64encode(hashlib.sha256(src.encode()).digest()).decode().rstrip("=")
        d = json.loads(await cs.eval(MINT_JS % (json.dumps(arr), json.dumps(src),
                                                json.dumps(freq))))
        cookies = await cs.send("Network.getCookies", urls=[dp.URL])
        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies.get("cookies", []))
        return {"freq": freq, "sid": sid.group(1) if sid else None,
                "bl": bl.group(1) if bl else None, "cookies": cookie_header,
                "build": tag, "mint": d}
    finally:
        await cs.stop()


def classify(raw: str, status: int) -> tuple:
    if raw.lstrip().startswith("<"):
        return "blocked", f"HTML body ({len(raw)} chars)"
    for line in raw.split("\n"):
        line = line.strip()
        if not line.startswith("[["):
            continue
        try:
            chunks = json.loads(line)
        except json.JSONDecodeError:
            continue
        for chunk in chunks:
            if isinstance(chunk, list) and len(chunk) >= 3 and chunk[0] == "wrb.fr":
                if chunk[1] == RPC and chunk[2]:
                    payload = json.loads(chunk[2])
                    if isinstance(payload, list) and len(payload) >= 4:
                        return "accepted", payload[1:4]
                    return "verified/echo", f"{len(payload)} element(s)"
                if len(chunk) >= 5 and isinstance(chunk[4], list):
                    return "rejected", f"er chunk {chunk[4][:2]}"
    return "unknown", f"status {status}, {len(raw)} chars"


async def run(port: int, out: str, dry: bool, control: bool = False,
              control_fresh: bool = False, control_byte4: bool = False) -> None:
    os.makedirs(out, exist_ok=True)
    img_path = os.path.join(out, "text.png")
    image = make_image(img_path)
    cap = await capture(port, image, "image/png", out)
    print(f"build {cap['build']}  sid {'yes' if cap['sid'] else 'no'}  bl {'yes' if cap['bl'] else 'no'}"
          f"  cookies {len(cap['cookies'])} chars  mint {cap['mint'].get('tok')} chars")
    d = cap["mint"]
    if not d.get("tokstr"):
        raise SystemExit("mint produced no token; nothing to assemble")
    field, items = pieces(d)
    raw_token = d["tokstr"]
    import base64 as b64mod
    body = raw_token[1:]
    body += "=" * (-len(body) % 4)
    raw_bytes = b64mod.urlsafe_b64decode(body)
    if control_byte4:
        from bgr_sidecar import LocalSigner
        signer = LocalSigner(profile_dir="/tmp/bg-live-signer").start()
        try:
            out_sign = signer.sign(cap["freq"])
        finally:
            signer.stop()
        bgr = out_sign["bgr"]
        pristine = json.loads(bgr)[0]
        pb = pristine[1:]
        pb += "=" * (-len(pb) % 4)
        raw_p = b64mod.urlsafe_b64decode(pb)
        out_b = bytearray(raw_p)
        old = out_b[4]
        out_b[4] = (old ^ 0xFF) if old != (old ^ 0xFF) else (old + 1) & 0xFF
        token = ";" + b64mod.urlsafe_b64encode(bytes(out_b)).decode().rstrip("=")
        print(f"  pristine {len(pristine)} chars ({len(raw_p)} B)  byte4 {old:02x} -> {out_b[4]:02x}"
              f"  nonce untouched ({raw_p[0]:02x} {raw_p[1]:02x})  same length="
              f"{len(token) == len(pristine)}")
    elif control_fresh:
        # parse the trusted token: keep every per-load constant, replace only the nonce and the bulk.
        # The bulk is the tag-23 record: 0x17, a 2-byte length, then exactly that many bytes to the end.
        from bgr_sidecar import LocalSigner
        signer = LocalSigner(profile_dir="/tmp/bg-live-signer").start()
        try:
            out_sign = signer.sign(cap["freq"])
        finally:
            signer.stop()
        bgr = out_sign["bgr"]
        pristine = json.loads(bgr)[0]
        pb = pristine[1:]
        pb += "=" * (-len(pb) % 4)
        raw_p = b64mod.urlsafe_b64decode(pb)
        pos = None
        for i in range(len(raw_p) - 3, 5, -1):
            if raw_p[i] == 0x17:
                n = (raw_p[i + 1] << 8) | raw_p[i + 2]
                if i + 3 + n == len(raw_p):
                    pos = i
                    break
        print(f"  pristine {len(pristine)} chars ({len(raw_p)} B)  bulk record at {pos}"
              + (f" len {(raw_p[pos + 1] << 8) | raw_p[pos + 2]}" if pos else ""))
        out_b = bytearray(raw_p)
        r = os.urandom(1)[0]
        out_b[0] = r
        out_b[1] = r ^ 0x1E
        out_b[3] = out_b[1]                      # token[3] mirrors nonce[1]
        if pos:
            n = (raw_p[pos + 1] << 8) | raw_p[pos + 2]
            out_b[pos + 3:pos + 3 + n] = os.urandom(n)
        token = ";" + b64mod.urlsafe_b64encode(bytes(out_b)).decode().rstrip("=")
        print(f"  re-randomised token {len(token)} chars (same length="
              f"{len(token) == len(pristine)})  nonce {out_b[0]:02x} {out_b[1]:02x}")
    elif control:
        # the control: a pristine token from the shipped signer (its own browser, its own page),
        # sent through the same hand-built envelope as the assembled one
        from bgr_sidecar import LocalSigner
        signer = LocalSigner(profile_dir="/tmp/bg-live-signer").start()
        try:
            out_sign = signer.sign(cap["freq"])
        finally:
            signer.stop()
        bgr = out_sign["bgr"]
        token = json.loads(bgr)[0]
        print(f"  control token {len(token)} chars (build {out_sign.get('build')}), "
              f"captured-in-load {len(raw_token)}")
    else:
        token = ";" + b64mod.urlsafe_b64encode(
            assemble(items, os.urandom(2), raw_bytes[4], fresh_bulk=os.urandom)).decode().rstrip("=")
        print(f"  assembled token {len(token)} chars (captured {len(raw_token)})  "
              f"same length={len(token) == len(raw_token)}")
    json.dump({"token": token, "captured": raw_token, "sid": cap["sid"], "bl": cap["bl"]},
              open(os.path.join(out, "live.json"), "w"))
    if dry:
        print("dry run: not sending")
        return

    query = urllib.parse.urlencode({
        "rpcids": RPC, "source-path": "/", "f.sid": cap["sid"], "bl": cap["bl"],
        "hl": "en-US", "soc-app": "1", "soc-platform": "1", "soc-device": "1",
        "_reqid": "100000", "rt": "c",
    })
    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "X-Same-Domain": "1",
        "Origin": "https://translate.google.com",
        "Referer": dp.URL,
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": cap["cookies"],
        "X-Goog-BatchExecute-Bgr": (bgr if control else
                                    json.dumps([token, None, None, 214, 4, None, None, 0, "2"],
                                               separators=(",", ":"))),
        "X-Goog-Ext-387202953-Jspb": '["/DataService.GetImageTranslation"]',
    }
    headers.update(CLIENT_HINTS)
    req = urllib.request.Request(BATCHEXECUTE + "?" + query,
                                 data=urllib.parse.urlencode({"f.req": cap["freq"]}).encode(),
                                 headers=headers)
    print("  sending ONE request (no retries)")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            status, raw = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        print(f"  request failed: {type(e).__name__}: {e}")
        return
    cls, detail = classify(raw, status)
    print(f"  HTTP {status}  class={cls}  detail={detail}")
    open(os.path.join(out, "response.txt"), "w").write(raw)
    print(f"  raw response saved to {os.path.join(out, 'response.txt')} ({len(raw)} chars)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10750)
    ap.add_argument("--out", default="/tmp/bg-live")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--control-byte4", action="store_true",
                    help="pristine token with ONLY byte 4 changed: discriminates 'nonce is bound' "
                         "from 'any single-byte edit breaks it'")
    ap.add_argument("--control-fresh", action="store_true",
                    help="pristine token from the signer, then a fresh nonce and a fresh bulk, "
                         "everything else kept: does the service accept a re-randomised token?")
    ap.add_argument("--control", action="store_true",
                    help="send a browser-minted (pristine) token in the same envelope instead of the "
                         "assembled one: the control for section 53")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out, a.dry_run, a.control, a.control_fresh, a.control_byte4))


if __name__ == "__main__":
    main()
