"""Fetch one page load's botguard build material without a browser.

The page document carries the build pair inline: ``"mnsUbf":`` holds the proto whose
``[0]`` is the program blob and ``[5][-1]`` the interpreter source. That makes the
material reachable from plain urllib, which is the first requirement of any
browserless mint (the material must not need a DOM to obtain).

    python3 research/fetch_build.py --out /tmp/bgbuild
    # -> /tmp/bgbuild/interp_<hash>.js, blob_<hash>.txt, material.json
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA, PAGE_URL  # noqa: E402
from dump_program import parse_material  # noqa: E402


def fetch(url: str = PAGE_URL, ua: str = DEFAULT_UA) -> tuple[list, str]:
    req = urllib.request.Request(url, headers={"user-agent": ua, "accept-language": "en-US,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=45) as r:
        html = r.read().decode("utf-8", "replace")
    arr = json.loads("[" + parse_material(html)[4:])
    return arr, arr[5][-1]


def save(arr: list, interp: str, out: str) -> str:
    os.makedirs(out, exist_ok=True)
    tag = str(arr[2])[:16]
    open(os.path.join(out, "interp_" + tag + ".js"), "w").write(interp)
    blob = arr[0]
    raw = base64.b64decode(blob[3:] if isinstance(blob, str) else blob)
    open(os.path.join(out, "blob_" + tag + ".txt"), "wb").write(raw)
    json.dump({"arr": arr, "interp_sha256": hashlib.sha256(interp.encode()).hexdigest(),
               "blob_len": len(raw), "blob_head": raw[:16].hex()},
              open(os.path.join(out, "material.json"), "w"))
    return tag


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/bgbuild")
    a = ap.parse_args()
    arr, interp = fetch()
    tag = save(arr, interp, a.out)
    print("build", tag, "interp", len(interp), "B blob", len(arr[0]), "proto fields", len(arr))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
