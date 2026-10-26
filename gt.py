#!/usr/bin/env python3
"""CLI for the Google Translate client -- same code path as the HTTP API.

    python3 gt.py "hello world"
    python3 gt.py "hello" -tl ja --json
    cat notes.md | python3 gt.py -tl zh-CN
    python3 gt.py -f article.txt -tl en --out article.en.txt
    python3 gt.py --lines file.txt -tl zh-CN --out file.zh.txt   # one request line-group set
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from gt_client import RateLimited, TranslateError, Translator


def main() -> int:
    # Same default the server uses, so one env var configures both surfaces.
    default_tl = os.environ.get("GT_DEFAULT_TL") or "zh-CN"
    ap = argparse.ArgumentParser(description="Google Translate over plain HTTP (no browser).")
    ap.add_argument("text", nargs="*", help="text to translate; omit to read stdin")
    ap.add_argument("-sl", "--source", default="auto", help="source language (default: auto)")
    ap.add_argument("-tl", "--target", default=default_tl,
                    help=f"target language (default: $GT_DEFAULT_TL or zh-CN, now: {default_tl})")
    ap.add_argument("-f", "--file", help="read input from a file")
    ap.add_argument("--out", help="write translated text to a file")
    ap.add_argument("--json", action="store_true", help="print the full JSON result")
    ap.add_argument("--lines", action="store_true",
                    help="translate every input line separately, keep line count")
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--min-interval", type=float, default=0.15,
                    help="minimum seconds between upstream requests (default 0.15)")
    args = ap.parse_args()

    if args.file:
        src = open(args.file, encoding="utf-8").read()
    elif args.text:
        src = " ".join(args.text)
    else:
        src = sys.stdin.read()
    if not src.strip():
        ap.error("empty input")

    tr = Translator(timeout=args.timeout, min_interval=args.min_interval)
    try:
        if args.lines:
            lines = src.split("\n")
            res = tr.translate_many(lines, sl=args.source, tl=args.target)
            out = "\n".join(res["translations"])
            payload = res
        else:
            payload = tr.translate(src, sl=args.source, tl=args.target)
            out = payload["text"]
    except RateLimited as e:
        print(f"rate limited by upstream: {e}", file=sys.stderr)
        return 2
    except TranslateError as e:
        print(f"upstream error: {e}", file=sys.stderr)
        return 3

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out if out.endswith("\n") else out + "\n")
        print(f"wrote {args.out} ({len(out)} chars)", file=sys.stderr)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif not args.out:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
