#!/usr/bin/env python3
"""Local HTTP API in front of the Google Translate upstream (stdlib only).

Run:
    python3 gt_server.py                     # 127.0.0.1:8770
    GT_HOST=0.0.0.0 GT_PORT=8770 GT_API_KEY=secret python3 gt_server.py

Endpoints
    GET  /health
    GET  /translate?q=hello&sl=auto&tl=zh-CN
    POST /translate        {"text": "...", "sl": "auto", "tl": "zh-CN"}
    POST /translate/batch  {"items": ["a","b"], "sl": "auto", "tl": "zh-CN"}
    GET  /languages

Auth: when GT_API_KEY is set, every endpoint except /health requires
"Authorization: Bearer <key>". Upstream calls are serialized, so one instance
serves one client's traffic at a time.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gt_client import RateLimited, TranslateError, Translator

HOST = os.environ.get("GT_HOST", "127.0.0.1")
PORT = int(os.environ.get("GT_PORT", "8770"))
API_KEY = os.environ.get("GT_API_KEY", "").strip()
DEFAULT_TL = os.environ.get("GT_DEFAULT_TL", "zh-CN")
# Reach the upstream through a proxy when the host cannot talk to Google directly
# (mainland-China servers must use one). Empty = direct / system env proxy.
GT_PROXY = os.environ.get("GT_PROXY", "").strip() or None
# Override the upstream URL (mirror / self-hosted gateway); must accept the same
# translate_a/t query shape.
GT_ENDPOINT = os.environ.get("GT_ENDPOINT", "").strip() or None
MAX_BODY = 2 * 1024 * 1024          # 2 MB of request body
MAX_ITEMS = 500

COMMON_LANGS = {
    "auto": "Detect language", "zh-CN": "Chinese (Simplified)", "zh-TW": "Chinese (Traditional)",
    "en": "English", "ja": "Japanese", "ko": "Korean", "fr": "French", "de": "German",
    "es": "Spanish", "pt": "Portuguese", "ru": "Russian", "it": "Italian", "ar": "Arabic",
    "hi": "Hindi", "th": "Thai", "vi": "Vietnamese", "id": "Indonesian", "tr": "Turkish",
    "nl": "Dutch", "pl": "Polish", "uk": "Ukrainian", "sv": "Swedish", "he": "Hebrew",
}

_tr_kwargs: dict = {"proxy": GT_PROXY}
if GT_ENDPOINT:
    _tr_kwargs["endpoint"] = GT_ENDPOINT
TR = Translator(**_tr_kwargs)


class Handler(BaseHTTPRequestHandler):
    server_version = "gt-api/1.0"
    protocol_version = "HTTP/1.1"

    # ---------- helpers ----------

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code: int, kind: str, msg: str) -> None:
        self._send(code, {"error": {"type": kind, "message": msg}})

    def _authed(self) -> bool:
        if not API_KEY:
            return True
        got = self.headers.get("Authorization", "")
        if got == f"Bearer {API_KEY}":
            return True
        self._err(401, "unauthorized", "missing or wrong bearer token")
        return False

    def _json_body(self) -> dict | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._err(411, "bad_request", "invalid Content-Length")
            return None
        if n <= 0:
            self._err(400, "bad_request", "empty body")
            return None
        if n > MAX_BODY:
            self._err(413, "payload_too_large", f"body over {MAX_BODY} bytes")
            return None
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._err(400, "bad_request", "body must be JSON")
            return None
        if not isinstance(data, dict):
            self._err(400, "bad_request", "body must be a JSON object")
            return None
        return data

    def log_message(self, format, *args):       # keep stdout clean, one line per request
        sys.stdout.write("%s %s\n" % (self.address_string(), format % args))
        sys.stdout.flush()

    # ---------- routing ----------

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/health":
            self._send(200, {"ok": True, "auth": bool(API_KEY)})
            return
        if not self._authed():
            return
        if path == "/languages":
            self._send(200, {"languages": COMMON_LANGS})
            return
        if path == "/translate":
            q = urllib.parse.parse_qs(query)
            text = (q.get("q") or q.get("text") or [""])[0]
            sl = (q.get("sl") or ["auto"])[0]
            tl = (q.get("tl") or [DEFAULT_TL])[0]
            if not text.strip():
                self._err(400, "bad_request", "missing q")
                return
            self._do_translate(text, sl, tl)
            return
        self._err(404, "not_found", f"no route {path}")

    def do_POST(self):
        path, _, _query = self.path.partition("?")
        if not self._authed():
            return
        data = self._json_body()
        if data is None:
            return
        sl = str(data.get("sl") or "auto")
        tl = str(data.get("tl") or DEFAULT_TL)
        if path == "/translate":
            text = data.get("text", data.get("q"))
            if not isinstance(text, str) or not text.strip():
                self._err(400, "bad_request", "field 'text' must be a non-empty string")
                return
            self._do_translate(text, sl, tl)
            return
        if path == "/translate/batch":
            items = data.get("items")
            if not isinstance(items, list) or not items or not all(isinstance(i, str) for i in items):
                self._err(400, "bad_request", "field 'items' must be a non-empty list of strings")
                return
            if len(items) > MAX_ITEMS:
                self._err(413, "payload_too_large", f"at most {MAX_ITEMS} items per call")
                return
            try:
                res = TR.translate_many([i if i.strip() else "" for i in items], sl=sl, tl=tl)
            except RateLimited as e:
                self._err(429, "rate_limited", str(e))
                return
            except TranslateError as e:
                self._err(502, "upstream_error", str(e))
                return
            res["count"] = len(items)
            self._send(200, res)
            return
        self._err(404, "not_found", f"no route {path}")

    def _do_translate(self, text: str, sl: str, tl: str) -> None:
        try:
            res = TR.translate(text, sl=sl, tl=tl)
        except RateLimited as e:
            self._err(429, "rate_limited", str(e))
            return
        except TranslateError as e:
            self._err(502, "upstream_error", str(e))
            return
        self._send(200, res)


def main() -> None:
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    print(f"gt-api listening on http://{HOST}:{PORT}  auth={'bearer' if API_KEY else 'none'}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
