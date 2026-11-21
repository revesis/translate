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

# The anchor already carries the following two lines, so the inserted code must not repeat them
# (the first attempt did, and clang stopped at "redefinition of 'options'").
ERR_CODE = """  // botguard research: log the engine-constructed error text (what the VM's collector records) and,
  // when BG_ERRSTK is set, where it was thrown. The stack is what turns "n is not a function" into an
  // address; it costs a stack walk, so keep it behind an env var for oracle runs.
  {
    std::unique_ptr<char[]> err_text = msg->ToCString();
    fprintf(stderr, "[ERRLOG] %s\\n", err_text.get());
    // The throw site's script position, so an error can be mapped back to the generated frame source
    // dumped by [EVALSRC]. ComputeLocation reads the current exception/pending message; if it has none
    // (the error object is still being built) it returns false and we print nothing.
    MessageLocation loc;
    if (isolate->ComputeLocation(&loc)) {
      DirectHandle<Script> sc = direct_handle(loc.script());
      if (!sc.is_null()) {
        // The source length joins this hit to the `[EVALLOG] len=..` line of the same eval.
        Tagged<UnionOf<String, Undefined>> src_obj = sc->source();
        int src_len = IsString(src_obj) ? Cast<String>(src_obj)->length() : -1;
        fprintf(stderr, "[ERRLOC] len=%d line=%d col=%d\\n", src_len,
                Script::GetLineNumber(sc, loc.start_pos()),
                Script::GetColumnNumber(sc, loc.start_pos()));
      }
    }
    if (getenv("BG_ERRSTK") != nullptr) {
      std::ostringstream bg_ss;
      isolate->PrintCurrentStackTrace(bg_ss);
      fprintf(stderr, "[ERRSTK] %s\\n", bg_ss.str().c_str());
      // The VM keeps its field tables (`Y`, `Pf`) on an object that moves between frames: the mining
      // handlers receive it as a free variable, not as a receiver. Dump the receiver of every frame
      // and, for the wide interpreter loop, its parameters, so the object graph can be read offline.
      DirectHandle<Name> kY = isolate->factory()->NewStringFromAsciiChecked("Y");
      DirectHandle<Name> kPf = isolate->factory()->NewStringFromAsciiChecked("Pf");
      DirectHandle<Name> kJ = isolate->factory()->NewStringFromAsciiChecked("J");
      DirectHandle<Name> kB = isolate->factory()->NewStringFromAsciiChecked("bU");
      DirectHandle<Name> kI = isolate->factory()->NewStringFromAsciiChecked("I");
      auto dump_field = [isolate](DirectHandle<JSObject> o, DirectHandle<Name> k,
                                  const char* label) {
        MaybeHandle<Object> mv = Object::GetProperty(isolate, o, k);
        DirectHandle<Object> v;
        if (!mv.ToHandle(&v)) { fprintf(stderr, " %s=?", label); return; }
        if (IsUndefined(*v)) { fprintf(stderr, " %s=undef", label); return; }
        if (IsNull(*v)) { fprintf(stderr, " %s=null", label); return; }
        if (IsJSArray(*v)) {
          DirectHandle<JSArray> a = Cast<JSArray>(v);
          Tagged<Number> alen = a->length();
          if (IsSmi(alen)) {
            fprintf(stderr, " %s=arr%lld", label, static_cast<long long>(Cast<Smi>(alen).value()));
          } else {
            fprintf(stderr, " %s=arr?", label);
          }
          return;
        }
        if (IsSmi(*v)) {
          fprintf(stderr, " %s=smi%lld", label, static_cast<long long>(Cast<Smi>(*v).value()));
          return;
        }
        if (IsHeapNumber(*v)) {
          fprintf(stderr, " %s=num%.6f", label, Cast<HeapNumber>(*v)->value());
          return;
        }
        fprintf(stderr, " %s=%p", label, reinterpret_cast<void*>(v.address()));
      };
      auto dump_j = [isolate, &dump_field, kY, kPf](DirectHandle<JSObject> o, DirectHandle<Name> k) {
        Maybe<bool> own = JSReceiver::HasOwnProperty(
            isolate, direct_handle(Cast<JSReceiver>(*o), isolate), k);
        if (own.IsJust()) fprintf(stderr, " ownJ=%d", own.FromJust() ? 1 : 0);
        MaybeHandle<Object> mv = Object::GetProperty(isolate, o, k);
        DirectHandle<Object> v;
        if (!mv.ToHandle(&v)) { fprintf(stderr, " J=?"); return; }
        if (IsUndefined(*v)) { fprintf(stderr, " J=undef"); return; }
        if (IsNull(*v)) { fprintf(stderr, " J=null"); return; }
        if (IsSmi(*v)) {
          fprintf(stderr, " J=smi%lld", static_cast<long long>(Cast<Smi>(*v).value()));
          return;
        }
        if (IsHeapNumber(*v)) {
          fprintf(stderr, " J=num%.6f", Cast<HeapNumber>(*v)->value());
          return;
        }
        if (IsJSObject(*v)) {
          DirectHandle<JSObject> jo = Cast<JSObject>(v);
          fprintf(stderr, " J=%p JisRecv=%d", reinterpret_cast<void*>(jo.address()),
                  jo.address() == o.address() ? 1 : 0);
          dump_field(jo, kY, "JY");
          dump_field(jo, kPf, "JPf");
          return;
        }
        fprintf(stderr, " J=%s", IsString(*v) ? "str" : "other");
      };
      static const char* kExtra[] = {"A", "j", "tE", "Lo", "TY", "MF", "X", "rB",
                                     "S", "o", "v", "C", "L", "d", "u", "B", "A1",
                                     "EL", "Nw", "oR", "b2", "qw", "IR", "RF", "Mw",
                                     "lU", "AE", "m", "Wx", "Qd", "h1", "bS", "NF",
                                     "uS", "tE2", "aR", "n", "N"};
      auto dump_extra = [isolate, &dump_field](DirectHandle<JSObject> o) {
        for (const char* k : kExtra) {
          DirectHandle<Name> key = isolate->factory()->NewStringFromAsciiChecked(k);
          dump_field(o, key, k);
        }
      };
      for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) {
        JavaScriptFrame* jf = it.frame();
        Tagged<Script> sc = jf->script();
        Tagged<Object> src = sc->source();
        int slen = IsString(src) ? Cast<String>(src)->length() : -1;
        Tagged<String> fn = jf->function()->shared()->Name();
        std::unique_ptr<char[]> fnc = fn->ToCString();
        fprintf(stderr, "[ERRFRM] fn=%s len=%d", fnc.get(), slen);
        Tagged<Object> recv = jf->receiver();
        fprintf(stderr, " recv=%p", reinterpret_cast<void*>(recv.ptr()));
        uint32_t np = jf->ComputeParametersCount();
        uint32_t na = jf->GetActualArgumentCount();
        fprintf(stderr, " np=%u na=%u\\n", np, na);
        if (IsJSObject(recv)) {
          DirectHandle<JSObject> ro = direct_handle(Cast<JSObject>(recv), isolate);
          fprintf(stderr, "   recvobj:");
          dump_field(ro, kY, "Y");
          dump_field(ro, kPf, "Pf");
          dump_field(ro, kB, "bU");
          dump_field(ro, kI, "I");
          dump_j(ro, kJ);
          dump_extra(ro);
          fprintf(stderr, "\\n");
        }
        if (np > 20 || (slen > 0 && slen < 1000 && np > 0)) {
          for (uint32_t i = 0; i < np; i++) {
            Tagged<Object> p = jf->GetParameter(static_cast<int>(i));
            fprintf(stderr, "   arg[%u]=%p", i, reinterpret_cast<void*>(p.ptr()));
            if (IsJSObject(p)) {
              DirectHandle<JSObject> po = direct_handle(Cast<JSObject>(p), isolate);
              dump_field(po, kY, "Y");
              dump_field(po, kPf, "Pf");
              dump_field(po, kB, "bU");
              dump_field(po, kI, "I");
              dump_j(po, kJ);
              dump_extra(po);
            } else {
              if (IsSmi(p)) {
                fprintf(stderr, " smi%lld", static_cast<long long>(Cast<Smi>(p).value()));
              } else if (IsString(p)) {
                fprintf(stderr, " str");
              } else if (IsUndefined(p)) {
                fprintf(stderr, " undef");
              } else {
                fprintf(stderr, " other");
              }
            }
            fprintf(stderr, "\\n");
          }
        }
      }
    }
  }
"""


# Writes to the VM core's `J`. `Object::SetProperty(LookupIterator*, ...)` is the common entry for every
# named store (the store ICs call it straight from ic/ic.cc:2295/2395/4641), so `x.J = ...` and
# `this.J = ...` land here whether the property already exists or is being added. The filter is the
# one-character name "J" plus a "Y" array on the receiver - i.e. exactly the VM core - so the hot path
# stays quiet. Prints the value and the JS stack of the writer.
JWRITE_ANCHOR = """Maybe<bool> Object::SetProperty(LookupIterator* it, DirectHandle<Object> value,
                                StoreOrigin store_origin,
                                Maybe<ShouldThrow> should_throw) {
  if (it->IsFound()) {
"""

JWRITE_CODE = """  // botguard research: log stores of the name "J" on an object carrying a "Y" array (the VM core),
  // with the writer's JS stack. This is what puts a non-self value into the core's J.
  {
    static const bool bg_jwrite = getenv("BG_JWRITE") != nullptr;
    Isolate* bg_isolate = it->isolate();
    if (bg_jwrite && !it->IsElement()) {
      DirectHandle<Name> bg_name = it->name();
      if (IsString(*bg_name) && Cast<String>(*bg_name)->length() == 1 &&
          Cast<String>(*bg_name)->Get(0) == u'J') {
        DirectHandle<JSAny> bg_recv = it->GetReceiver();
        if (IsJSObject(*bg_recv)) {
          DirectHandle<JSObject> bg_ro = Cast<JSObject>(bg_recv);
          DirectHandle<Name> bg_ky = bg_isolate->factory()->NewStringFromAsciiChecked("Y");
          MaybeHandle<Object> bg_y = Object::GetProperty(bg_isolate, bg_ro, bg_ky);
          DirectHandle<Object> bg_yv;
          if (bg_y.ToHandle(&bg_yv) && IsJSArray(*bg_yv)) {
            Tagged<Object> bg_v = *value;
            fprintf(stderr, "[JWRITE] recv=%p val=",
                    reinterpret_cast<void*>(bg_ro.address()));
            if (IsSmi(bg_v)) {
              fprintf(stderr, "smi%lld", static_cast<long long>(Cast<Smi>(bg_v).value()));
            } else if (IsHeapNumber(bg_v)) {
              fprintf(stderr, "num%.6f", Cast<HeapNumber>(bg_v)->value());
            } else {
              fprintf(stderr, "%p", reinterpret_cast<void*>(bg_v.ptr()));
            }
            fprintf(stderr, "\\n");
            for (JavaScriptStackFrameIterator bg_it(bg_isolate); !bg_it.done(); bg_it.Advance()) {
              JavaScriptFrame* bg_f = bg_it.frame();
              Tagged<Script> bg_sc = bg_f->script();
              Tagged<Object> bg_src = bg_sc->source();
              int bg_len = IsString(bg_src) ? Cast<String>(bg_src)->length() : -1;
              Tagged<String> bg_fn = bg_f->function()->shared()->Name();
              std::unique_ptr<char[]> bg_fnc = bg_fn->ToCString();
              fprintf(stderr, "  [JFRM] fn=%s len=%d\\n", bg_fnc.get(), bg_len);
            }
            std::ostringstream bg_ss;
            bg_isolate->PrintCurrentStackTrace(bg_ss);
            fprintf(stderr, "%s", bg_ss.str().c_str());
          }
        }
      }
    }
  }
"""


def ensure_cstdio(text: str) -> str:
    """Add the logging includes once, after the first include line."""
    need = [h for h in ("#include <cstdio>", "#include <cstdlib>", "#include <sstream>",
                        '#include "src/objects/script.h"', '#include "src/execution/frames.h"',
                        '#include "src/objects/objects.h"', '#include "src/objects/js-objects.h"',
                        '#include "src/objects/name.h"', '#include "src/objects/js-array.h"',
                        '#include "src/objects/heap-number.h"', '#include "src/objects/string.h"',
                        '#include "src/objects/lookup.h"')
            if h not in text]
    if not need:
        return text
    i = text.find("\n#include ")
    if i < 0:
        raise SystemExit("no include block found")
    return text[: i + 1] + "".join(h + "\n" for h in need) + text[i + 1:]


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


# The real eval path: GetFunctionFromString only covers the Function() constructor shape. Measured:
# patching it alone produced 0 [EVALLOG] lines on a trusted mint (the ERRLOG hook fired 12 times).
EVAL_EVAL_ANCHOR = """MaybeDirectHandle<JSFunction> Compiler::GetFunctionFromEval(
    Isolate* isolate, DirectHandle<String> source,
    DirectHandle<SharedFunctionInfo> outer_info, DirectHandle<Context> context,
    LanguageMode language_mode, ParseRestriction restriction,
    int parameters_end_pos, int eval_position,
    ParsingWhileDebugging parsing_while_debugging,
    bool private_name_lookup_skips_outer_class) {
"""

EVAL_EVAL_CODE = """  // botguard research: log every eval-compiled source (this is the path the VM's frame uses).
  // Big sources (the VM's generated frame copy, ~62-64 KB) are dumped in full so the two realms'
  // generated programs can be diffed; everything else is logged by length and head only.
  {
    int src_len = source->length();
    std::unique_ptr<char[]> src_head = source->ToCString(0, src_len > 120 ? 120 : src_len);
    fprintf(stderr, "[EVALLOG] len=%d ctx=%p head=%s\\n", src_len,
            reinterpret_cast<void*>(context->ptr()), src_head.get());
    if (src_len > 50000) {
      std::unique_ptr<char[]> full = source->ToCString();
      fprintf(stderr, "[EVALSRC] %s\\n[EVALSRC-END]\\n", full.get());
    }
  }
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="/root/chromium/src")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    v8 = os.path.join(a.src, "v8", "src")
    targets = [
        (os.path.join(v8, "codegen", "compiler.cc"), EVAL_ANCHOR, EVAL_CODE),
        (os.path.join(v8, "execution", "messages.cc"), ERR_ANCHOR, ERR_CODE),
        (os.path.join(v8, "codegen", "compiler.cc"), EVAL_EVAL_ANCHOR, EVAL_EVAL_CODE),
        (os.path.join(v8, "objects", "objects.cc"), JWRITE_ANCHOR, JWRITE_CODE),
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
