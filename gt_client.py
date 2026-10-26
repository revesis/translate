#!/usr/bin/env python3
"""Pure-HTTP Google Translate client. No browser, no third-party deps.

Upstream endpoint:
    https://translate.googleapis.com/translate_a/t?client=dict-chrome-ex&sl=auto&tl=zh-CN&q=...

Verified behaviour (this host, 2026-10):
  * one q                    -> [["translated","detected-lang"]]
  * many q + sl=auto         -> [["t1","en"],["t2","en"], ...]
  * many q + explicit sl     -> ["t1","t2", ...]
  * Upstream accepts GET only. POST is answered with a 302 to /sorry (anti-bot
    page), so this client never sends POST.
  * An unknown tl does not error: the source text comes back unchanged, so the
    caller must validate target languages itself.
  * translate_a/single?client=gtx returns 429 from this host and is unusable.

Segmentation: dict-chrome-ex swallows newlines, so line structure is preserved
locally -- each line becomes one q parameter, batched by item count and encoded
size; over-long lines are cut at sentence boundaries.
"""

from __future__ import annotations

import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "https://translate.googleapis.com/translate_a/t"
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

MAX_ITEMS_PER_REQUEST = 50
MAX_ENCODED_BYTES = 6000
MAX_SEGMENT_CHARS = 1400
_UNKNOWN = "auto"


class TranslateError(Exception):
    """Upstream refused or unavailable."""


class RateLimited(TranslateError):
    """Rate limited or blocked by the anti-bot page."""


def _quote(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _sentence_split(line: str) -> list[str]:
    """Cut at sentence-ending punctuation; pieces concatenate back to the input."""
    marks = "。！？；….!?;"
    pieces, buf = [], ""
    for ch in line:
        buf += ch
        if ch in marks and len(buf) >= 200:
            pieces.append(buf)
            buf = ""
    if buf:
        pieces.append(buf)
    out: list[str] = []
    for p in pieces:
        while len(p) > MAX_SEGMENT_CHARS:
            out.append(p[:MAX_SEGMENT_CHARS])
            p = p[MAX_SEGMENT_CHARS:]
        if p:
            out.append(p)
    return out


def _line_pieces(line: str) -> list[str]:
    if len(line) <= MAX_SEGMENT_CHARS:
        return [line]
    return _sentence_split(line)


class Translator:
    def __init__(self, endpoint: str = ENDPOINT, ua: str = DEFAULT_UA,
                 timeout: float = 25.0, retries: int = 3,
                 min_interval: float = 0.15, proxy: str | None = None):
        self.endpoint = endpoint
        self.ua = ua
        self.timeout = timeout
        self.retries = retries
        self.min_interval = min_interval
        self._lock = threading.Lock()   # serialize upstream calls; bursts get flagged
        self._last = 0.0
        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)

    # ---------------- internals ----------------

    def _throttle(self) -> None:
        gap = time.monotonic() - self._last
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last = time.monotonic()

    def _request(self, qs: list[str], sl: str, tl: str) -> list[list[str]]:
        """One upstream request -> [[text, lang], ...] in the same order as qs."""
        parts = ["client=dict-chrome-ex", "sl=" + _quote(sl), "tl=" + _quote(tl)]
        parts += ["q=" + _quote(q) for q in qs]
        url = self.endpoint + "?" + "&".join(parts)
        req = urllib.request.Request(url, headers={
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://translate.google.com/",
        })

        last_err: Exception | None = None
        for attempt in range(self.retries):
            try:
                with self._lock:
                    self._throttle()
                    with self._opener.open(req, timeout=self.timeout) as r:
                        status = r.status
                        body = r.read().decode("utf-8", "replace")
                if status != 200 or body.lstrip().startswith("<"):
                    raise RateLimited(f"upstream status={status} body={body[:120]!r}")
                return self._parse(json.loads(body), len(qs))
            except RateLimited as e:
                last_err = e
            except urllib.error.HTTPError as e:
                if e.code in (429, 403):
                    last_err = RateLimited(f"HTTP {e.code}")
                else:
                    last_err = TranslateError(f"HTTP {e.code}")
                    if e.code not in (500, 502, 503, 504):
                        raise
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                last_err = TranslateError(repr(e))
            time.sleep(min(8.0, 1.2 * (2 ** attempt)) + random.uniform(0, 0.6))
        raise last_err or TranslateError("unknown failure")

    @staticmethod
    def _parse(data, n: int) -> list[list[str]]:
        if not isinstance(data, list):
            raise TranslateError(f"unexpected payload: {str(data)[:120]}")
        out: list[list[str]] = []
        for item in data:
            if isinstance(item, list):
                text = item[0] if item and isinstance(item[0], str) else ""
                lang = item[1] if len(item) > 1 and isinstance(item[1], str) else _UNKNOWN
            elif isinstance(item, str):
                text, lang = item, _UNKNOWN
            else:
                text, lang = "", _UNKNOWN
            out.append([text, lang])
        while len(out) < n:
            out.append(["", _UNKNOWN])
        return out[:n]

    # ---------------- public ----------------

    @staticmethod
    def _plan(text: str) -> tuple[list[str], dict[int, list[str]]]:
        """Split a block into lines plus the translatable pieces of each line."""
        lines = text.split("\n")
        per_line: dict[int, list[str]] = {}
        for li, line in enumerate(lines):
            if line.strip():
                per_line[li] = _line_pieces(line)
        return lines, per_line

    def _run_batches(self, texts: list[str], sl: str, tl: str) -> list[tuple[str, str]]:
        """Translate a flat list of pieces -> [(text, lang)] in input order."""
        results: list[str] = [""] * len(texts)
        langs: list[str] = [""] * len(texts)
        batch: list[list] = []                     # [[piece, index], ...]
        enc = 0

        def flush() -> None:
            nonlocal batch, enc
            if not batch:
                return
            rows = self._request([b[0] for b in batch], sl, tl)
            for (_, idx), (tr, lang) in zip(batch, rows):
                results[idx] = tr
                langs[idx] = lang if lang and lang != _UNKNOWN else ""
            batch, enc = [], 0

        for idx, piece in enumerate(texts):
            q = _quote(piece)
            if batch and (len(batch) >= MAX_ITEMS_PER_REQUEST
                          or enc + len(q) > MAX_ENCODED_BYTES):
                flush()
            batch.append([piece, idx])
            enc += len(q)
        flush()
        return list(zip(results, langs))

    @staticmethod
    def _detected(langs: list[str], sl: str) -> str:
        seen = [l for l in langs if l]
        if sl != "auto" or not seen:
            return ""
        return max(set(seen), key=seen.count)

    def translate(self, text: str, sl: str = "auto", tl: str = "zh-CN") -> dict:
        """Translate a whole block, keeping line breaks and blank lines."""
        lines, per_line = self._plan(text)

        flat: list[str] = []
        slots: list[tuple[int, int]] = []
        for li, pieces in per_line.items():
            for pi, piece in enumerate(pieces):
                flat.append(piece)
                slots.append((li, pi))

        rows = self._run_batches(flat, sl, tl) if flat else []
        done = {slot: row[0] for slot, row in zip(slots, rows)}

        out_lines: list[str] = []
        for li, line in enumerate(lines):
            if not line.strip():
                out_lines.append(line)
                continue
            pieces = per_line.get(li) or [line]
            out_lines.append("".join(done.get((li, pi), p) for pi, p in enumerate(pieces)))

        return {
            "text": "\n".join(out_lines),
            "sl": sl,
            "tl": tl,
            "detected": self._detected([row[1] for row in rows], sl),
        }

    def translate_many(self, items: list[str], sl: str = "auto", tl: str = "zh-CN") -> dict:
        """Translate many independent blocks in as few upstream requests as possible."""
        plans = [self._plan(it) for it in items]

        flat: list[str] = []
        owner: list[tuple[int, int, int]] = []      # (item_idx, line_idx, piece_idx)
        for ii, (_lines, per_line) in enumerate(plans):
            for li, pieces in per_line.items():
                for pi, piece in enumerate(pieces):
                    flat.append(piece)
                    owner.append((ii, li, pi))

        rows = self._run_batches(flat, sl, tl) if flat else []
        done = {slot: row[0] for slot, row in zip(owner, rows)}

        langs_per_item: dict[int, list[str]] = {}
        for (ii, _li, _pi), row in zip(owner, rows):
            langs_per_item.setdefault(ii, []).append(row[1])

        outs = []
        for ii, (lines, per_line) in enumerate(plans):
            cols: list[str] = []
            for li, line in enumerate(lines):
                if not line.strip():
                    cols.append(line)
                    continue
                pieces = per_line.get(li) or [line]
                cols.append("".join(done.get((ii, li, pi), p) for pi, p in enumerate(pieces)))
            outs.append("\n".join(cols))

        dets = [self._detected(langs_per_item.get(ii, []), sl) for ii in range(len(items))]
        return {"translations": outs, "detected": dets, "sl": sl, "tl": tl}


if __name__ == "__main__":
    import sys
    src = " ".join(sys.argv[1:]) or sys.stdin.read()
    print(json.dumps(Translator().translate(src), ensure_ascii=False, indent=2))
