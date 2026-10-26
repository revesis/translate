#!/usr/bin/env python3
"""Offline self-test: fake upstream, no network calls to Google.

    python3 selftest.py

Checks the parts that are easy to get wrong: response-shape parsing (auto vs
explicit sl), line structure preservation, batching limits, retry on the
anti-bot HTML page, and the upstream-endpoint override.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gt_client import (MAX_ENCODED_BYTES, MAX_ITEMS_PER_REQUEST, RateLimited,
                       Translator, _line_pieces)

fails: list[str] = []
hits: list[dict] = []
MODE = {"kind": "json", "fail_first": 0}


class FakeUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query, keep_blank_values=True)
        qs = q.get("q", [])
        sl = q.get("sl", ["auto"])[0]
        records = {"qs": qs, "sl": sl, "tl": q.get("tl", [""])[0],
                   "url_bytes": len(self.path.encode())}
        hits.append(records)

        if MODE["fail_first"] > 0:
            MODE["fail_first"] -= 1
            body = b"<html><title>Sorry...</title></html>"
            self.send_response(429)
        else:
            if sl == "auto":
                rows = [[f"T({x})", "en"] for x in qs]
            else:
                rows = [f"T({x})" for x in qs]
            body = json.dumps(rows, ensure_ascii=False).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def check(name: str, cond: bool, extra: str = "") -> None:
    print(("PASS  " if cond else "FAIL  ") + name + (f"  {extra}" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{srv.server_address[1]}/translate_a/t"
    tr = Translator(endpoint=endpoint, min_interval=0, retries=3, timeout=5)

    # 1. explicit sl -> list of strings
    hits.clear()
    r = tr.translate("hello", sl="en", tl="zh-CN")
    check("explicit sl parses plain string list", r["text"] == "T(hello)", repr(r))
    check("explicit sl reports no detected lang", r["detected"] == "")

    # 2. auto -> pairs, detected surfaced
    hits.clear()
    r = tr.translate("hello", tl="zh-CN")
    check("auto parses [text, lang] pairs", r["text"] == "T(hello)", repr(r))
    check("detected language surfaced", r["detected"] == "en", repr(r))

    # 3. line structure and blank lines preserved, one q per line
    hits.clear()
    src = "first line\n\nthird line\n"
    r = tr.translate(src)
    check("newlines preserved", r["text"] == "T(first line)\n\nT(third line)\n", repr(r["text"]))
    check("blank lines are not sent upstream",
          bool(hits) and hits[0]["qs"] == ["first line", "third line"],
          repr([h["qs"] for h in hits]))

    # 4. long single line is split and re-joined without loss
    hits.clear()
    long_line = "x" * 3000
    r = tr.translate(long_line)
    n_pieces = len(_line_pieces(long_line))
    check("long line split into pieces", n_pieces >= 3, str(n_pieces))
    check("long line round-trips without loss", r["text"].count("T(") == n_pieces,
          repr(r["text"][:60]))

    # 5. batching respects both limits
    hits.clear()
    many = "\n".join(f"line {i}" for i in range(MAX_ITEMS_PER_REQUEST * 2 + 7))
    r = tr.translate(many)
    check("line count preserved on big input", len(r["text"].split("\n")) == len(many.split("\n")))
    check("batching splits by item count",
          all(len(h["qs"]) <= MAX_ITEMS_PER_REQUEST for h in hits),
          repr([len(h["qs"]) for h in hits]))
    check("batching splits by encoded size",
          all(h["url_bytes"] < MAX_ENCODED_BYTES + 500 for h in hits),
          repr([h["url_bytes"] for h in hits]))
    check("more than one request for big input", len(hits) >= 3, str(len(hits)))

    # 6. CJK source: percent-encoding inflates ~9x, still bounded
    hits.clear()
    cjk = "\n".join(["这是一段中文文本用来测试编码长度" for _ in range(100)])
    tr.translate(cjk)
    check("CJK batches stay under the byte cap",
          all(h["url_bytes"] < MAX_ENCODED_BYTES + 500 for h in hits),
          repr([h["url_bytes"] for h in hits]))

    # 7. retry after the anti-bot page
    hits.clear()
    MODE["fail_first"] = 2
    tr_retry = Translator(endpoint=endpoint, min_interval=0, retries=4, timeout=5)
    r = tr_retry.translate("retry me", sl="en")
    check("recovers after 2 anti-bot pages", r["text"] == "T(retry me)", repr(r))

    # 8. gives up with RateLimited when the wall never lifts
    MODE["fail_first"] = 99
    try:
        Translator(endpoint=endpoint, min_interval=0, retries=2, timeout=5).translate("nope", sl="en")
        check("raises RateLimited when blocked", False)
    except RateLimited:
        check("raises RateLimited when blocked", True)
    finally:
        MODE["fail_first"] = 0

    srv.shutdown()
    print()
    print("FAILED: %d" % len(fails) if fails else "all checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
