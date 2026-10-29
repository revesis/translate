#!/usr/bin/env python3
"""Add engine-level logging to a Chromium/V8 checkout, so the signing instance can be observed.

Why this exists: every JavaScript-level instrument is detected. The interpreter stringifies its own
functions, so a single array push inside its eval wrapper turns the mint into the 43-character error
token (docs/botguard-notes.md section 65). C++ logging changes no JS source text, so it is the only
non-perturbing route left.

Two hooks, both logging-only, both anchored on exact text so a mismatch is loud instead of silent:

  [EVALLOG] len=<n> ctx=<ptr> head=<first 120 chars>
      every dynamic compilation (eval, Function, and the VM's generated frame source) - this is the
      program's instruction stream as the realm sees it.
  [ERRLOG] <message>
      every engine-constructed error, i.e. what the interpreter's collector would record.

    python3 patch_chromium.py --src /root/chromium/src --dry-run
    python3 patch_chromium.py --src /root/chromium/src
    # then: ninja -C out/Rel chrome -j4     (incremental: V8 + relink)

Logs go to stderr; run chrome with --no-sandbox --enable-logging=stderr and capture it.
"""
import argparse
import os
import sys

EVAL_ANCHOR = """MaybeDirectHandle<JSFunction> Compiler::GetFunctionFromString(
    Isolate* isolate, DirectHandle<NativeContext> context,
    Handle<Object> source, int parameters_end_pos, bool is_code_like) {
"""

EVAL_CODE = """  // botguard research: log every dynamic compilation (eval / Function / generated frame source).
  if (IsString(*source)) {
    Tagged<String> src_string = Cast<String>(*source);
    int src_len = src_string->length();
    std::unique_ptr<char[]> src_head =
        src_string->ToCString(0, src_len > 120 ? 120 : src_len);
    fprintf(stderr, "[EVALLOG] len=%d ctx=%p head=%s\\n", src_len,
            reinterpret_cast<void*>(context->ptr()), src_head.get());
  }
"""

# Two Format(isolate, index, args) call sites exist; the DCHECK below it is unique to
# ErrorUtils::MakeGenericError, so the anchor carries it and the log goes in between.
ERR_ANCHOR = """  DirectHandle<String> msg = MessageFormatter::Format(isolate, index, args);
  DirectHandle<Object> options = isolate->factory()->undefined_value();

  DCHECK(mode != SKIP_UNTIL_SEEN);
"""

ERR_CODE = """  // botguard research: log the engine-constructed error text (what the VM's collector records).
  {
    std::unique_ptr<char[]> err_text = msg->ToCString();
    fprintf(stderr, "[ERRLOG] %s\\n", err_text.get());
  }
  DirectHandle<Object> options = isolate->factory()->undefined_value();

  DCHECK(mode != SKIP_UNTIL_SEEN);
"""


def ensure_cstdio(text: str) -> str:
    if "#include <cstdio>" in text:
        return text
    i = text.find("\n#include ")
    if i < 0:
        raise SystemExit("no include block found")
    return text[: i + 1] + "#include <cstdio>\n" + text[i + 1:]


def apply(path: str, anchor: str, code: str, dry: bool) -> bool:
    text = open(path).read()
    n = text.count(anchor)
    if n != 1:
        print(f"  ANCHOR MISS in {path}: {n} occurrences")
        return False
    if code in text:
        print(f"  already patched: {path}")
        return True
    text = text.replace(anchor, anchor + code)
    text = ensure_cstdio(text)
    if not dry:
        open(path, "w").write(text)
    print(f"  {'would patch' if dry else 'patched'}: {path}")
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="/root/chromium/src")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    v8 = os.path.join(a.src, "v8", "src")
    targets = [
        (os.path.join(v8, "codegen", "compiler.cc"), EVAL_ANCHOR, EVAL_CODE),
        (os.path.join(v8, "execution", "messages.cc"), ERR_ANCHOR, ERR_CODE),
    ]
    ok = True
    for path, anchor, code in targets:
        if not os.path.exists(path):
            print(f"  MISSING {path}")
            ok = False
            continue
        ok = apply(path, anchor, code, a.dry_run) and ok
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
