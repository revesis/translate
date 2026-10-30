"""One real request with a token minted by d8 - no browser in the minting path at all.

The capture half still loads the page in a browser, but only to obtain what the *request* needs
(cookies, `f.sid`, `bl`) and the build material of that load. The token itself is produced by
`research/d8_mint.js` on the V8 shell that matches the browser's engine version, and that is the whole
point: if the service accepts it, the mint no longer needs a browser.

    python3 research/d8_live_test.py --port 10760 --out /tmp/bg-d8live     # ONE request, no retries
    python3 research/d8_live_test.py --port 10760 --dry-run                # stop before the POST

Classification (same vocabulary as research/live_test.py):
    accepted       200 + a 4-element wrb.fr payload (OCR text + translation)
    verified/echo  200 + a 1-element payload (token verified, nothing extracted)
    rejected       400 + an `er` chunk (token did not verify)
    blocked        HTML body / 403 / 429
"""
import argparse
import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA  # noqa: E402
import dump_program as dp  # noqa: E402
from gt_image import BATCHEXECUTE, CLIENT_HINTS, RPC, UA  # noqa: E402

REMOTE = "root@192.168.92.26"
D8 = "/root/chromium/src/out/Rel/d8"
REMOTE_DIR = "/root/bg/live"
FREQ_TL = "zh-CN"


def make_image(path: str) -> bytes:
    os.system("convert -size 1000x260 xc:white -fill black -pointsize 56 "
              "-annotate +30+90 'BACKUP JOB FAILED ON NODE DB-07' "
              "-annotate +30+180 'ERROR CODE 1284 - RETRY ABORTED' " + path)
    return open(path, "rb").read()


async def capture(port: int, image: bytes, mime: str) -> dict:
    """One page load: cookies + f.sid/bl + the untouched build material, and the request payload."""
    b64 = base64.b64encode(image).decode()
    inner = json.dumps([[b64, mime], "auto", FREQ_TL], separators=(",", ":"))
    freq = json.dumps([[[RPC, inner, None, "generic"]]], separators=(",", ":"))
    cs = dp.CS(dp.CHROME, port, DEFAULT_UA, "/tmp/bg-d8live-%d" % port)
    await cs.start()
    try:
        await cs.send("Network.enable")
        await cs.navigate(dp.URL, settle=7)
        body = await cs.send("Network.getResponseBody", requestId=cs.doc_request)
        html = body.get("body", "")
        if body.get("base64Encoded"):
            html = base64.b64decode(html).decode("utf-8", "replace")
        sid = re.search(r'FdrFJe":"(-?\d+)"', html)
        bl = re.search(r'"cfb2h":"([^"]+)"', html)
        arr = json.loads("[" + dp.parse_material(html)[4:])
        cookies = await cs.send("Network.getCookies", urls=[dp.URL])
        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies.get("cookies", []))
        return {"freq": freq, "arr": arr, "sid": sid.group(1) if sid else None,
                "bl": bl.group(1) if bl else None, "cookies": cookie_header,
                "build": str(arr[2])[:16]}
    finally:
        await cs.stop()


def mint_with_d8(arr: list, freq: str, workdir: str) -> dict:
    """Ship the material to the V8 shell, mint there, bring the token back. No browser involved."""
    os.makedirs(workdir, exist_ok=True)
    mat = os.path.join(workdir, "material.json")
    frq = os.path.join(workdir, "freq.txt")
    json.dump({"arr": arr}, open(mat, "w"))
    open(frq, "w").write(freq)
    subprocess.run(["ssh", "-o", "BatchMode=yes", REMOTE, f"mkdir -p {REMOTE_DIR}"], check=True)
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", mat, frq, f"{REMOTE}:{REMOTE_DIR}/"], check=True)
    out = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", REMOTE,
         f"cd {REMOTE_DIR} && timeout 300 {D8} --allow-natives-syntax /root/bg/d8_mint.js -- "
         f"--material {REMOTE_DIR}/material.json --freq {REMOTE_DIR}/freq.txt 2>/dev/null | tail -1"],
        check=True, capture_output=True, text=True).stdout
    return json.loads(out.strip().splitlines()[-1])


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


async def run(port: int, out: str, dry: bool) -> None:
    os.makedirs(out, exist_ok=True)
    image = make_image(os.path.join(out, "text.png"))
    cap = await capture(port, image, "image/png")
    print(f"build {cap['build']}  sid {'yes' if cap['sid'] else 'no'}  "
          f"bl {'yes' if cap['bl'] else 'no'}  cookies {len(cap['cookies'])} chars")
    mint = mint_with_d8(cap["arr"], cap["freq"], os.path.join(out, "mint"))
    print(f"  d8 mint: {mint.get('token_len')} chars, frames {mint.get('frames')}, "
          f"error {mint.get('error')}")
    token = mint.get("token") or ""
    if not token:
        raise SystemExit("d8 produced no token; nothing to send")
    raw_bytes = base64.urlsafe_b64decode(token[1:] + "=" * (-len(token[1:]) % 4))
    print(f"  token {len(token)} chars / {len(raw_bytes)} B  head {raw_bytes[:16].hex()}")
    json.dump({"token": token, "sid": cap["sid"], "bl": cap["bl"]},
              open(os.path.join(out, "d8_token.json"), "w"))
    if dry:
        print("  --dry-run: stopping before the POST")
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
        "X-Goog-BatchExecute-Bgr": json.dumps(
            [token, None, None, 214, 4, None, None, 0, "2"], separators=(",", ":")),
        "X-Goog-Ext-387202953-Jspb": '["/DataService.GetImageTranslation"]',
    }
    headers.update(CLIENT_HINTS)
    req = urllib.request.Request(
        BATCHEXECUTE + "?" + query,
        data=urllib.parse.urlencode({"f.req": cap["freq"]}).encode(), headers=headers)
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10760)
    ap.add_argument("--out", default="/tmp/bg-d8live")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    asyncio.run(run(a.port, a.out, a.dry_run))


if __name__ == "__main__":
    main()
