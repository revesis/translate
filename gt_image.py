#!/usr/bin/env python3
"""Image translation (OCR + translate) against Google's images tab, pure HTTP.

The page's single RPC is
    POST https://translate.google.com/_/TranslateWebserverUi/data/batchexecute?rpcids=WqWDPb
    f.req = [[["WqWDPb", "<inner JSON>", null, "generic"]]]
    inner  = [[<base64 image>, "<mime>"], "<sl>", "<tl>"]

Verified against a real browser session (2026-10): the RPC answers with
    [ [<base64 image>, "<mime>"], "<OCR source text>", "<translated text>", "<detected lang>" ]
and with only ONE element, [[<base64 image>, "<mime>"]], when Google declines to
OCR the picture. That happens for images with little text — a screenshot of a
few words returns nothing, a dense page of text returns the full text. Treat the
one-element response as "no text found", not as an error.

No browser needed, but a fresh page visit is required to mint the cookies and
the f.sid token; they are reused for a while afterwards.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

PAGE = "https://translate.google.com/?sl=auto&tl=zh-CN&op=images"
RPC = "WqWDPb"                                    # /DataService.GetImageTranslation
BATCHEXECUTE = "https://translate.google.com/_/TranslateWebserverUi/data/batchexecute"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/156.0.0.0 Safari/537.36")

# Chrome's client hints. The RPC returns the echo instead of OCR unless the
# request carries these and a matching User-Agent.
CLIENT_HINTS = {
    "sec-ch-ua": '"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-form-factors": '"Desktop"',
    "sec-ch-ua-full-version": '"156.0.8078.47"',
    "sec-ch-ua-full-version-list": ('"Not:A-Brand";v="8.0.0.0", "Chromium";v="156.0.8078.47", '
                                    '"Google Chrome";v="156.0.8078.47"'),
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Linux"',
    "sec-ch-ua-platform-version": '""',
    "sec-ch-ua-wow64": "?0",
}

SESSION_TTL = 600.0        # reuse cookies + f.sid for ten minutes
MAX_IMAGE_BYTES = 12 * 1024 * 1024
SUPPORTED_MIME = {"image/png", "image/jpeg", "image/webp", "image/gif"}


class ImageTranslateError(Exception):
    """Upstream refused or the response could not be understood."""


def sniff_mime(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:3] == b"GIF":
        return "image/gif"
    return "image/png"


class ImageTranslator:
    """OCR + translate an image. One upstream request per image."""

    def __init__(self, timeout: float = 90.0, retries: int = 2, signer_url: str | None = None,
                 signer=None):
        self.timeout = timeout
        self.retries = retries
        # Optional botguard sidecar (see bgr_sidecar.py). Without it Google answers
        # with the image echoed back instead of OCR text.
        self.signer_url = signer_url or os.environ.get("GT_SIGNER_URL") or None
        # In-process signer (bgr_sidecar.LocalSigner). Takes precedence over the URL.
        self.signer = signer
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._jar))
        self._sid: str | None = None
        self._bl: str | None = None
        self._minted = 0.0

    # ---------- session ----------

    def _mint_session(self, force: bool = False) -> None:
        if not force and self._sid and (time.time() - self._minted) < SESSION_TTL:
            return
        req = urllib.request.Request(PAGE, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with self._opener.open(req, timeout=self.timeout) as r:
            html = r.read().decode("utf-8", "replace")
        sid = re.search(r'FdrFJe":"(-?\d+)"', html)
        bl = re.search(r'"cfb2h":"([^"]+)"', html)
        if not sid or not bl:
            raise ImageTranslateError("could not mint f.sid/bl from the translate page")
        self._sid, self._bl, self._minted = sid.group(1), bl.group(1), time.time()

    # ---------- upstream ----------

    def _sign(self, freq: str) -> str | None:
        """Ask the botguard sidecar for the X-Goog-BatchExecute-Bgr value."""
        if self.signer is not None:
            out = self.signer.sign(freq)
            if out.get("sid"):
                self._sid = out["sid"]
            if out.get("bl"):
                self._bl = out["bl"]
            return out.get("bgr")
        if not self.signer_url:
            return None
        body = json.dumps({"f_req": freq}).encode()
        req = urllib.request.Request(self.signer_url.rstrip("/") + "/sign", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout + 90) as r:
            out = json.loads(r.read().decode())
        if out.get("sid"):
            self._sid = out["sid"]
        if out.get("bl"):
            self._bl = out["bl"]
        return out.get("bgr")

    def _call(self, image: bytes, mime: str, sl: str, tl: str) -> list:
        b64 = base64.b64encode(image).decode("ascii")
        inner = json.dumps([[b64, mime], sl, tl], separators=(",", ":"))
        # f.req is THREE levels deep; two levels makes Google answer 400/echo.
        freq = json.dumps([[[RPC, inner, None, "generic"]]], separators=(",", ":"))
        bgr = self._sign(freq)
        query = urllib.parse.urlencode({
            "rpcids": RPC, "source-path": "/", "f.sid": self._sid, "bl": self._bl,
            "hl": "en-US", "soc-app": "1", "soc-platform": "1", "soc-device": "1",
            "_reqid": str(random.randint(100000, 999999)), "rt": "c",
        })
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
            "X-Same-Domain": "1",
            "Origin": "https://translate.google.com",
            "Referer": PAGE,
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        headers.update(CLIENT_HINTS)
        if bgr:
            headers["X-Goog-BatchExecute-Bgr"] = bgr
            headers["X-Goog-Ext-387202953-Jspb"] = '["/DataService.GetImageTranslation"]'
        req = urllib.request.Request(BATCHEXECUTE + "?" + query,
                                     data=urllib.parse.urlencode({"f.req": freq}).encode(),
                                     headers=headers)
        with self._opener.open(req, timeout=self.timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        return self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> list:
        """Pull the wrb.fr payload out of the batchexecute envelope."""
        for line in raw.split("\n"):
            line = line.strip()
            if not line.startswith("[["):
                continue
            try:
                chunks = json.loads(line)
            except json.JSONDecodeError:
                continue
            for chunk in chunks:
                if isinstance(chunk, list) and len(chunk) >= 3 and chunk[0] == "wrb.fr" and chunk[1] == RPC:
                    if chunk[2] is None:
                        return []
                    return json.loads(chunk[2])
        if raw.lstrip().startswith("<"):
            raise ImageTranslateError("upstream returned an HTML block (rate limited / rejected)")
        raise ImageTranslateError(f"no {RPC} payload in response: {raw[:160]!r}")

    # ---------- public ----------

    def translate_image(self, data: bytes, mime: str | None = None,
                        sl: str = "auto", tl: str = "zh-CN") -> dict:
        if not data:
            raise ImageTranslateError("empty image")
        if len(data) > MAX_IMAGE_BYTES:
            raise ImageTranslateError(f"image larger than {MAX_IMAGE_BYTES} bytes")
        mime = (mime or sniff_mime(data)).split(";")[0].strip().lower()
        if mime not in SUPPORTED_MIME:
            raise ImageTranslateError(f"unsupported image type {mime!r}")

        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                self._mint_session(force=attempt > 0 and last is not None)
                payload = self._call(data, mime, sl, tl)
                return self._shape(payload, sl, tl)
            except (urllib.error.URLError, urllib.error.HTTPError, ImageTranslateError) as e:
                last = e
                if attempt + 1 < self.retries:
                    time.sleep(1.5 + attempt * 2)
        raise last or ImageTranslateError("unknown failure")

    @staticmethod
    def _shape(payload: list, sl: str, tl: str) -> dict:
        """[[img,mime], src, dst, lang] or [[img,mime]] when no text was found."""
        text = translation = detected = ""
        if isinstance(payload, list) and len(payload) >= 2:
            text = payload[1] if isinstance(payload[1], str) else ""
            translation = payload[2] if len(payload) > 2 and isinstance(payload[2], str) else ""
            detected = payload[3] if len(payload) > 3 and isinstance(payload[3], str) else ""
        out = {"text": text, "translation": translation,
               "detected": detected, "sl": sl, "tl": tl,
               "found_text": bool(text)}
        if not text:
            out["note"] = ("no text recognised - Google returns an empty result for images "
                           "with little text; use a denser, higher-resolution picture")
        return out


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fixture.png"
    tl = sys.argv[2] if len(sys.argv) > 2 else "zh-CN"
    t0 = time.time()
    res = ImageTranslator().translate_image(open(path, "rb").read(), tl=tl)
    print(json.dumps(res, ensure_ascii=False, indent=2)[:2000])
    print(f"({time.time() - t0:.2f}s)", file=sys.stderr)
