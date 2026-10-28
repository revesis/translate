"""Build-agnostic patcher for the botguard interpreter's bit reader.

Research tooling for the decompiler line of work (docs/botguard-notes.md). Nothing here is
imported by the shipped sidecar.

Every build renames things: identifiers, several field ids, and even the reader's parameter
order (`(bits, flag, vm)` in one build, `(flag, bits, vm)` in the next). Line numbers move
too. So nothing is hard-coded - each anchor is matched structurally:

  * reader      : `if((P=GETTER(A,B),P)>=VM.VFLD)throw[ARR,31];`
  * bits / flag : whichever of the first two parameters the keystream guard `<name>&&(`
                  tests is the flag; the other one is the bit count
  * block cache : `<hldr>.<cache>!=<x>>>6`   (the per-64-bit-block keystream cache)
  * boot site   : `VM.PROG=F(...atob(...)...),VM.VFLD=VM.PROG.length<<3,CALL(...,[0,0,0])`

Hunks (each can be enabled on its own, to bisect behaviour):

  entry - bit pointer taken from `window.__fp` when the caller armed it, and a passive log
          of `[bits, flag, startBit]` for every natural read
  ret   - passive log of the returned plaintext value; with `blockcache`, also reads the
          eight bytes of a block whose keystream was just regenerated (the pointer store
          that immediately follows puts the VM's own pointer back)
  boot  - exposes `__vmref`, `__JY` (the reader), `__vmeta`, `__blk` and optionally
          `__sweep()`

Two traps this file encodes: the source is assembled inside a JS string literal, so injected
code must be quote-free; and the patched text is evaluated in the page realm while the VM
also assembles a copy in a frame realm, so `window.*` state can end up split across two
objects - the caller must scan every realm for it.
"""
import re

READER_ANCHOR = re.compile(
    r"if\(\(?(\w+)=(\w+)\(([^()]*)\),\1\)?>=(\w+)\.(\w+)\)throw\[(\w+),31\];")
BOOT_ANCHOR = re.compile(
    r"(\w+)\.(\w+)=\w+\([^;]{0,80}?atob\(([^)]*)\)\)+,\1\.(\w+)=\1\.\2\.length"
    r"(?:<<3|\*8),(\w+)\(([^)]*),\[0,0,0\]\)")


def find_reader(s: str) -> dict:
    m = READER_ANCHOR.search(s)
    if not m:
        raise SystemExit("reader anchor not found")
    ptr, getter, args, vm, vfld, arr = m.groups()
    if vm not in [a.strip() for a in args.split(",")]:
        raise SystemExit("unexpected reader call shape: " + getter + "(" + args + ")")
    return {"start": m.start(), "end": m.end(), "ptr": ptr, "call": getter + "(" + args + ")",
            "vm": vm, "vfld": vfld, "arr": arr}


def brace_end(s: str, i: int) -> int:
    """Index just past the `}` closing the block that opens at s[i]."""
    depth = 0
    while i < len(s):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise SystemExit("unbalanced braces")


def in_string(s: str, i: int) -> bool:
    """True when s[i] sits inside a '...' / "..." / `...` literal.

    Part of the interpreter text is itself the source of the inner program (it is assembled as
    a string and compiled at runtime), so a patch anchor can land inside code that only exists
    after that compile. Text injected there must be valid *inner* JS, and the anchor check has
    to know the difference.
    """
    quote = None
    j = 0
    while j < i:
        c = s[j]
        if quote:
            if c == "\\":
                j += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        j += 1
    return quote is not None


def split_top(expr: str) -> list:
    """Split a JS expression on top-level commas (parentheses only)."""
    parts, depth, cur = [], 0, ""
    for ch in expr:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def find_name(s: str, upto: int, vm: str):
    """Name, params and body span of the reader: the last `NAME=function(...){` taking the vm."""
    best = None
    for m in re.finditer(r"([\w$]+)=function\(([^)]*)\)\{", s[:upto]):
        params = [p.strip() for p in m.group(2).split(",")]
        if vm in params:
            best = (m.group(1), params, m.end() - 1)
    if not best:
        raise SystemExit("reader name not found")
    return best[0], best[1], best[2], brace_end(s, best[2])


def patch(src: str, entry=True, ret=True, boot=True, sweep=False, blockcache=False,
          writes=False, killswitch=False, sink=None, canary=False, post=False, kinds=False,
          loop=False, handlers=False, fieldread=False):
    """Instrument the interpreter. `sink` is the JS expression used for state ("window" by
    default, or "(window.top||window)" when the VM runs in a frame that may be removed
    before the caller can look at it)."""
    S = sink or "window"
    r = find_reader(src)
    name, params, bstart, bend = find_name(src, r["start"], r["vm"])
    body = src[bstart:bend]
    seg = src[r["start"]:r["start"] + 2600]
    mflag = re.search(r"\b(\w+)&&\(", body)
    if not mflag:
        raise SystemExit("keystream guard not found")
    flag_name = mflag.group(1)
    # the bit count is the parameter the loop seed copies into the loop counter. Two shapes seen:
    #   for(y=(d=(I=(b=0,BITS),X),...);I>0;)      I=(b=0,BITS)
    #   for(m=(C=r,(v=BITS,d).TU).length,...;v>0;) v=BITS
    bits_name = ""
    mcond = re.search(r";(\w+)>0;", body)
    if mcond:
        lv = mcond.group(1)
        minit = (re.search(r"\b" + lv + r"=\(\w+=\d+,(\w+)\)", body)
                 or re.search(r"\b" + lv + r"=(\w+)[,)]", body))
        if minit and minit.group(1) in params:
            bits_name = minit.group(1)
    if flag_name not in params or not bits_name or bits_name == flag_name:
        raise SystemExit("cannot tell bits from flag: " + str(params[:4]))

    b = BOOT_ANCHOR.search(src)
    if not b:
        raise SystemExit("boot anchor not found")
    seed_call, seed_vm = b.group(5), b.group(1)
    argl = [a.strip() for a in b.group(6).split(",")]
    seed_id = next((a for a in argl if a.isdigit()), "")
    prog_field, vfield = b.group(2), b.group(4)
    if not seed_id:
        raise SystemExit("seed field id not found in " + seed_call + "(" + b.group(6) + ")")

    mc = re.search(r"\.(\w+)!=\w+>>6", body)
    cache_field = mc.group(1) if mc else ""
    # build the reader's argument list by role instead of by position: builds have shipped
    # (bits, flag, vm), (flag, bits, vm) and (vm, flag, bits).
    role = {bits_name: "8", flag_name: "true", r["vm"]: "v"}
    head = params[:3]
    if sorted(role) != sorted(head):
        raise SystemExit("unexpected reader head params: " + str(head))
    read_args = ",".join(role[p] for p in head) + ","

    if entry:
        entry_old = src[r["start"]:r["end"]]
        # the log lives on the VM instance, not on `window`: the writer hook runs in the same
        # scope as the reader hook, so instance-scoped logs stay aligned with each other even
        # when the text is evaluated in more than one realm.
        entry_new = ("if((" + r["ptr"] + "=(" + S + ".__fp!=null&&" + S + ".__fpv===" + r["vm"]
                     + "?" + S + ".__fp:" + r["call"] + ")," + r["ptr"] + ")>=" + r["vm"] + "."
                     + r["vfld"] + ")throw[" + r["arr"] + ",31];"
                     + "!" + S + ".__lock&&(" + r["vm"] + ".__rd=" + r["vm"] + ".__rd||[]).push(["
                     + bits_name + "," + flag_name + "," + r["ptr"] + "]);")
        src = src.replace(entry_old, entry_new, 1)

    if ret:
        # The reader's tail is `return CALL, VALUE}` in every build seen so far, but the call's
        # shape moves (the pointer field id may be the first or the second argument), so the
        # value is taken as the last top-level comma element instead of by pattern.
        j = body.rfind("return ")
        if j < 0 or not body.endswith("}"):
            raise SystemExit("reader return not found")
        expr = body[j + len("return "):-1].strip()
        parts = split_top(expr)
        if len(parts) < 2:
            raise SystemExit("unexpected reader return: " + expr)
        retvar = parts[-1].strip()
        ret_old = "return " + expr + "}"
        if src.count(ret_old) != 1:
            raise SystemExit("reader return not unique (" + str(src.count(ret_old)) + "): " + ret_old[:80])
        pre = ""
        if blockcache and cache_field:
            pre = ("(" + S + ".__r!==" + r["vm"] + "." + cache_field + "&&(" + S + ".__r="
                   + r["vm"] + "." + cache_field + "," + S + ".__blk(" + r["vm"] + "."
                   + cache_field + "," + r["vm"] + "))),")
        ret_new = ("return " + ",".join(parts[:-1]) + "," + pre
                   + "(!" + S + ".__lock&&(" + r["vm"] + ".__rv=" + r["vm"] + ".__rv||[]).push(["
                   + bits_name + "," + retvar + "]))," + retvar + "}")
        src = src.replace(ret_old, ret_new, 1)

    if boot:
        win = src[r["start"]:r["start"] + 2000]
        mfd = (re.search(re.escape(r["vm"]) + r"\.(\w+)\.length", win)
               or re.search(r"\)\.(\w+)\)\.length", win))
        fd_name = mfd.group(1) if mfd else ""
        boot_old = seed_call + "(" + b.group(6) + ",[0,0,0])"
        # optional single-byte mutation of the loaded program, for A/B runs:
        # `window.__mut = N` flips plaintext byte N (the array is decrypted per read, so
        # flipping the stored byte flips what the reader returns).
        boot_new = (boot_old + ",(" + S + ".__mut!=null&&(" + seed_vm + "." + prog_field
                    + "[" + S + ".__mut]^=1))," + seed_vm + ".__booted=1," + S + ".__booted=1,"
                    + S + ".__vmref=" + seed_vm
                    + "," + S + ".__JY=" + name
                    + "," + S + ".__vmeta={V:" + seed_vm + "." + vfield + ",prog:" + seed_vm + "."
                    + prog_field + ",seed:" + seed_vm + ".l"
                    + ((",fd:" + seed_vm + "." + fd_name) if fd_name else "") + "}")
        if blockcache and cache_field:
            # `__lock` (not `__fp`) guards logging: the capture recurses through the reader's
            # own return hook, and the nested call clears `__fp`, which used to let the forced
            # reads through into the log (they then "validate" the buffer they produced).
            boot_new += ("," + S + ".__prog=" + S + ".__prog||{}," + S + ".__blk=function(n,v){"
                         "if(n==null||" + S + ".__lock)return;" + S + ".__lock=1;var i,q;"
                         + S + ".__fpv=v;for(i=0;i<8;i++){q=n*64+i*8;" + S + ".__fp=q;"
                         + S + ".__prog[n]=" + S + ".__prog[n]||[];"
                         + S + ".__prog[n][i]=" + S + ".__JY(" + read_args + "v);}"
                         + S + ".__fp=null;" + S + ".__fpv=null;" + S + ".__lock=0;}")
        if sweep:
            boot_new += (",window.__sweep=function(){var v=window.__vmref,o=[],p;"
                         "window.__fpv=v;try{for(p=0;p<v." + vfield + ";p+=8){window.__fp=p;"
                         "o.push(window.__JY(" + read_args + "v));}}"
                         "catch(e){window.__sweepErr=String(e);o.push(-1);}"
                         "window.__fp=null;window.__fpv=null;window.__dump=o;"
                         "return o.length;}"
                         ",(window.__sweepNow||(window.parent&&window.parent.__sweepNow))"
                         "&&window.__sweep()")
        if src.count(boot_old) != 1:
            raise SystemExit("boot site not unique (%d)" % src.count(boot_old))
        src = src.replace(boot_old, boot_new)

    info_writer = {}
    if writes or killswitch:
        # The field writer is recognisable by its switch on the bit-pointer and concat ids;
        # a build ships several copies of it (they are all reached from different paths), so
        # patch every copy. Params are (fieldId, vm, value).
        cop = 0
        k = 0
        for m in reversed(list(re.finditer(r"switch\(!\((\w+)==(\d+)\u007c\u007c\1==(\d+)\)\)", src))):
            name_w, fid, id_ptr, id_cat = m.group(1), m.group(1), m.group(2), m.group(3)
            fn = None
            for f in re.finditer(r"([\w$]+)=function\(([^)]*)\)\{", src[:m.start()]):
                params_w = [x.strip() for x in f.group(2).split(",")]
                if fid in params_w and len(params_w) >= 3:
                    fn = (f, params_w)
            if not fn:
                continue
            f, params_w = fn
            val = params_w[2]
            # The vm is the parameter that holds the field table (`VM.l[id]` / `VM.h[id]`), not
            # necessarily the second one: a build ships copies with (vm, id, value) *and*
            # (id, vm, value). Logging on the wrong one throws inside a live writer and takes
            # the whole patched VM down (the page then falls back to its pristine copy).
            wend = brace_end(src, f.end() - 1)
            wbody = src[f.end():wend]
            mv = next((m for m in re.finditer(r"\b(\w+)\.\w+\[", wbody)
                       if m.group(1) in params_w), None)
            vmp = mv.group(1) if mv else params_w[1]
            push = ("[" + fid + ",(" + val + "&&" + val + ".length)|0,(function(q){try{return "
                    "JSON.stringify(q)}catch(e){return String(q)}})(" + val + "),(" + vmp
                    + ".__rv||[]).length]")
            if killswitch:
                # self-identifying probe: copy #k aborts the run when window.__kill === k, so
                # the live copy can be found from the token alone (no cross-realm state).
                inject = ("(window.__kill===" + str(k) + ")&&(function(){throw 0})();")
            else:
                # log on the VM instance, not on `window`: the patched text runs in a realm
                # the page may not be able to enumerate, but the VM object is shared by
                # reference, so the log is reachable from whichever realm holds `__vmref`.
                inject = (vmp + ".__wr=" + vmp + ".__wr||[],(" + fid + "!==" + id_ptr + "&&"
                          + fid + "!==" + id_cat + ")&&" + vmp + ".__wr.push(" + push + ");")
            k += 1
            if inject in src[f.end():f.end() + 200]:
                continue
            src = src[:f.end()] + inject + src[f.end():]
            cop += 1
        if not cop:
            raise SystemExit("writer anchor not found")
        info_writer = {"writers_patched": cop, "skip_ids": [id_ptr, id_cat],
                       "mode": "killswitch" if killswitch else "writes"}

    if canary:
        # Canary on the VM entry the object exposes (`d.a = NAME`): if the counter fires, the
        # code we call really is the text we patched. A build can define NAME more than once
        # (the last definition wins), so every definition is instrumented.
        ma = re.search(r"\.a=(\w+)\)", src)
        if not ma:
            raise SystemExit("VM entry anchor (.a=NAME) not found")
        entry_name = ma.group(1)
        n_defs = 0
        for f in reversed(list(re.finditer(re.escape(entry_name) + r"=function\([^)]*\)\{", src))):
            src = src[:f.end()] + "window.__REntry=(window.__REntry||0)+1;" + src[f.end():]
            n_defs += 1
        info_canary = {"entry": entry_name, "entry_defs_patched": n_defs}
    else:
        info_canary = {}

    if kinds:
        # Every 8-bit read goes through one of a few thin wrappers, and the wrapper's "kind"
        # argument decides how the bytes are decoded (escape, varint, plain). The kind is a
        # constant at each call site, so tagging the wrapper entry turns a bare value stream
        # into typed operands: tag,kind interleaved with the read log by call order.
        wraps = {}
        for m in re.finditer(r"\b" + re.escape(name) + r"\(([^()]*)\)", src):
            args = [a.strip() for a in m.group(1).split(",")]
            if "8" not in args or not any(a in ("true", "!0", "1") for a in args):
                continue
            vmarg = next((a for a in args if a not in ("8", "2", "32", "true", "false", "!0", "1")), "")
            if not vmarg:
                continue
            fn = None
            for f in re.finditer(r"([\w$]+)=function\(([^)]*)\)\{", src[:m.start()]):
                fn = (f, [p.strip() for p in f.group(2).split(",")])
            if not fn:
                continue
            f, params_f = fn
            if f.start() not in wraps:
                # log the first two parameters raw: which one is the kind is a per-build
                # detail (the vm may be a local alias, not a parameter), and both are small
                # integers, so the tag is enough to separate the wrapper.
                wraps[f.start()] = (f, params_f, params_f[:2])
        patched = {}
        order = sorted(wraps.items(), key=lambda kv: kv[0])
        for tag, (_, (f, params_f, kindp)) in enumerate(order):
            inject = ("(window.__wk=window.__wk||[]).push([" + str(tag)
                      + "".join("," + p + "|0" for p in kindp) + "]);")
            if inject in src[f.end():f.end() + 200]:
                continue
            src = src[:f.end()] + inject + src[f.end():]
            patched[f.group(1)] = {"tag": tag, "params": params_f, "logged": kindp}
        if not patched:
            raise SystemExit("no value-reader wrapper found")
        info_kinds = {"wrappers": patched}
    else:
        info_kinds = {}

    if post:
        # The realm that does the work is a frame the page cannot read, so hand the state over
        # with postMessage (works cross-origin) right before the token is returned by the
        # base64url encoder. Quote-free: targetOrigin '*' is built with fromCharCode.
        i = src.find("window.btoa")
        if i < 0:
            raise SystemExit("btoa site not found")
        j = src.find("break a}", i)
        if j < 0:
            raise SystemExit("btoa block end not found")
        post_code = (";try{window.parent.postMessage(JSON.stringify({rd:window.__rd||[],"
                     "rv:window.__rv||[],wr:window.__wr||[],prog:window.__prog||{},"
                     "vmeta:window.__vmeta||{},booted:window.__booted||0}),"
                     "String.fromCharCode(42))}catch(q){}")
        src = src[:j] + post_code + src[j:]
        info_post = {"post": True}
    else:
        info_post = {}

    if loop:
        # The interpreter's instruction loop fetches the program pointer once per instruction:
        #   for(...;--J;)try{ if(F.o)...; else { if((P=z(PTR,VM),P)>=L)break; ... } }
        # One instruction is one iteration, so logging the fetched pointer gives the exact
        # instruction boundary without breakpoints; the token stream then segments by itself.
        # Last hunk on purpose: it inserts in the middle of the text, and every earlier hunk
        # uses offsets into the pre-patch string (a stale `r["start"]` slices the wrong span).
        ptr_id = re.search(r"\d+", r["call"]).group(0)
        hits = [m for m in re.finditer(r"\b(\w+)=(\w+)\(" + ptr_id + r",(\w+)\)", src)
                if "--" in src[max(0, m.start() - 300):m.start()]
                and len(src[max(0, m.start() - 300):m.start()].rsplit("--", 1)[-1]) < 120]
        if not hits:
            raise SystemExit("instruction loop not found")
        m = hits[0]
        lv, vm_l = m.group(1), m.group(3)
        # `,(expr)` and not `,expr)`: on the builds that keep the instruction loop in the inner
        # program text the injected code is compiled at runtime, and a missing paren turns the
        # whole token into the VM's `FNLSyntaxError: Unexpected token '.'` answer.
        # `,(expr)` with no trailing paren: the fetch sits in one of two shapes -
        # `if(A=f(PTR,V),A>=L)` and `if((A=f(PTR,V),A)>=L)` - and only this form is valid in
        # both. (A stray paren here is compiled at runtime and comes back as FNLSyntaxError.)
        # `pe` is the interpreter's own nesting counter (`F.pe++` on entry, `F.pe--` on exit),
        # so logging it with the pointer separates the loop's levels - a nested run pushes its
        # own boundaries into the same array otherwise, and the segments mix two streams.
        # the nesting counter's name rotates with the build (`F.pe++` on Fhxs, `q.U8++` on EON):
        # take it from the `if(!VM.X){VM.COUNTER++;` prologue of the loop-containing function
        mdep = re.search(r"if\(!(\w+)\.\w+\)\{(\w+)\.(\w+)\+\+;", src)
        dep = (mdep.group(2) + "." + mdep.group(3)) if mdep else "null"
        inject = (",(" + vm_l + ".__ip=" + vm_l + ".__ip||[]).push([" + lv + "," + dep + "])")
        src = src[:m.end()] + inject + src[m.end():]
        info_loop = {"loop_sites": len(hits), "loop": m.group(0), "ip_log": vm_l + ".__ip",
                     "inner_text": in_string(src, m.start())}
    else:
        info_loop = {}

    # The loop's dispatch expression, per build. Each entry: pattern, then the group indices for
    # (dst = the handler value, op id, vm) and for the accessor call that fetched the slot, plus
    # whether that accessor takes the field id first or second. Shapes, not names - every name and
    # every id in these expressions rotates per build (sections 15/27).
    DISPATCH_SHAPES = [
        # Fhxs: Y=z((G=B(F,(ZS(21,F,P),37)),G),F)         accessor z(id, vm)
        (r"(\w+)=(\w+)\(\((\w+)=(\w+)\((\w+),\("
         r"(\w+)\((\d+),\5,(\w+)\),(\d+)\)\),\3\),\w+\)", 1, 3, 5, 2, 1),
        # pBm:  I=(b=f(78,(e(71,q,R),q)),T(q,b))          accessor T(vm, id)
        (r"(\w+)=\((\w+)=(\w+)\((\d+),\((\w+)\((\d+),(\w+),(\w+)\),\w+\)\),"
         r"(\w+)\((\w+),\2\)\)", 1, 2, 7, 9, 2),
        # EON:  z=B(V,(C=Z(V,(E(V,328,J),17)),C))         accessor B(vm, id)
        (r"(\w+)=(\w+)\((\w+),\((\w+)=(\w+)\((\w+),\((\w+)\((\w+),(\d+),(\w+)\),"
         r"(\d+)\)\),\4\)\)", 1, 4, 3, 2, 2),
    ]

    def find_dispatch(source: str):
        for pat, g_dst, g_op, g_vm, g_acc, idpos in DISPATCH_SHAPES:
            m = re.search(pat, source)
            if m:
                return m, m.group(g_dst), m.group(g_op), m.group(g_vm), m.group(g_acc), idpos
        return None, None, None, None, None, None

    if handlers or fieldread:
        m, dst, op, vmsel, acc, idpos = find_dispatch(src)
    else:
        m = None

    if handlers:
        # A handler slot is drained once the run has used it (section 26), so a post-mint walk of
        # `vm.h` only sees `create,concat`. Record `String(handler)` once per op id, from the loop.
        info_handlers = {}
        if m:
            inject = (";(" + vmsel + ".__hn=" + vmsel + ".__hn||{})[" + op + "]===void 0&&("
                      + vmsel + ".__hn[" + op + "]=String(" + dst + ").slice(0,400))")
            src = src[:m.end()] + inject + src[m.end():]
            info_handlers = {"handler_expr": m.group(0), "op": op, "handler": dst}
        else:
            info_handlers = {"handler_expr": None}
    else:
        info_handlers = {}

    if fieldread:
        # Which *fields* an instruction touched is invisible in the read log (that only covers the
        # program stream), but every field access goes through the accessor the loop uses for the
        # op slot, so logging its (id, readsCompleted) pairs attributes field reads the same way
        # writes are attributed.
        info_fr = {}
        if acc:
            # names are reused inside one build (EON defines `B` three times), so pick the
            # definition that actually indexes a field table: `{t = vm.TABLE[id]`
            m_def = None
            for cand in re.finditer(r"\b" + re.escape(acc) + r"=function\(([^)]*)\)\{", src):
                if re.search(r"=\w+\.\w+\[", src[cand.end():cand.end() + 120]):
                    m_def = cand
            if m_def:
                ps = [x.strip() for x in m_def.group(1).split(",")]
                if len(ps) >= 2:
                    fid_arg, vm_arg = (ps[0], ps[1]) if idpos == 1 else (ps[1], ps[0])
                    inject = ("(" + vm_arg + ".__fr=" + vm_arg + ".__fr||[]).push([" + fid_arg + ",("
                              + vm_arg + ".__rv||[]).length]);")
                    src = src[:m_def.end()] + inject + src[m_def.end():]
                    info_fr = {"accessor": acc, "idpos": idpos, "id_arg": fid_arg, "patched": True}
                else:
                    info_fr = {"accessor": acc, "patched": False}
        else:
            info_fr = {"accessor": None}
    else:
        info_fr = {}

    # marker: proves the copy the page is running is *this* text. Some loads end up executing
    # a pristine copy (the page's own bootguard wins the race), and without the marker that is
    # indistinguishable from "nothing to log".
    if "window.__MINE=1;" not in src:
        src = src + "window.__MINE=1;"
    info = {"reader": name, "params": params[:3], "bits": bits_name, "flag": flag_name,
            "cache_field": cache_field, "vfield": vfield, "prog_field": prog_field,
            "seed_field": seed_id, "seed_call": seed_call}
    info.update(info_writer)
    info.update(info_canary)
    info.update(info_kinds)
    info.update(info_loop)
    info.update(info_handlers)
    info.update({"fieldread": info_fr} if info_fr else {})
    info.update(info_post)
    return src, info
