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
    r"if\(\((\w+)=(\w+)\(([^()]*)\),\1\)>=(\w+)\.(\w+)\)throw\[(\w+),31\];")
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


def find_name(s: str, upto: int, vm: str):
    """Name and parameter list of the reader: last `NAME=function(...){` taking the vm."""
    best = None
    for m in re.finditer(r"([\w$]+)=function\(([^)]*)\)\{", s[:upto]):
        params = [p.strip() for p in m.group(2).split(",")]
        if vm in params:
            best = (m.group(1), params)
    if not best:
        raise SystemExit("reader name not found")
    return best


def patch(src: str, entry=True, ret=True, boot=True, sweep=False, blockcache=False,
          writes=False, killswitch=False):
    r = find_reader(src)
    name, params = find_name(src, r["start"], r["vm"])
    seg = src[r["start"]:r["start"] + 2600]
    mflag = re.search(r"\b(\w+)&&\(", seg)
    if not mflag:
        raise SystemExit("keystream guard not found")
    flag_name = mflag.group(1)
    bits_name = next((p for p in params[:2] if p != flag_name), "")
    if flag_name not in params[:2] or not bits_name:
        raise SystemExit("cannot tell bits from flag: " + str(params[:2]))

    b = BOOT_ANCHOR.search(src)
    if not b:
        raise SystemExit("boot anchor not found")
    seed_call, seed_vm = b.group(5), b.group(1)
    argl = [a.strip() for a in b.group(6).split(",")]
    seed_id = next((a for a in argl if a.isdigit()), "")
    prog_field, vfield = b.group(2), b.group(4)
    if not seed_id:
        raise SystemExit("seed field id not found in " + seed_call + "(" + b.group(6) + ")")

    mc = re.search(r"\.(\w+)!=\w+>>6", seg)
    cache_field = mc.group(1) if mc else ""
    read_args = "8,true," if params[0] == bits_name else "true,8,"

    if entry:
        entry_old = src[r["start"]:r["end"]]
        entry_new = ("if((" + r["ptr"] + "=(window.__fp!=null&&window.__fpv===" + r["vm"]
                     + ")?window.__fp:" + r["call"] + "," + r["ptr"] + ")>=" + r["vm"] + "."
                     + r["vfld"] + ")throw[" + r["arr"] + ",31];"
                     "window.__fp==null&&(window.__rd=window.__rd||[]).push(["
                     + bits_name + "," + flag_name + "," + r["ptr"] + "]);")
        src = src.replace(entry_old, entry_new, 1)

    if ret:
        m_id = re.search(r"\d+", r["call"])
        if not m_id:
            raise SystemExit("pointer field id not found in " + r["call"])
        ptr_id = m_id.group(0)
        seg = src[r["start"]:r["start"] + 2600]
        mret = None
        for m in re.finditer(r"return (\w+)\(" + ptr_id + r",[^}]*?,(\w+)\}", seg):
            mret = m
        if not mret:
            raise SystemExit("reader return not found")
        ret_old = mret.group(0)
        retvar = mret.group(2)
        tail = "," + retvar + "}"
        if not ret_old.endswith(tail):
            raise SystemExit("unexpected reader return tail: " + ret_old)
        pre = ""
        if blockcache and cache_field:
            pre = ("(window.__r!==" + r["vm"] + "." + cache_field + "&&(window.__r="
                   + r["vm"] + "." + cache_field + ",window.__blk(" + r["vm"] + "."
                   + cache_field + "," + r["vm"] + "))),")
        ret_new = (ret_old[:-len(tail)] + "," + pre
                   + "(window.__fp==null&&(window.__rv=window.__rv||[]).push(["
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
        boot_new = (boot_old + ",(window.__mut!=null&&(" + seed_vm + "." + prog_field
                    + "[window.__mut]^=1)),window.__vmref=" + seed_vm + ",window.__JY=" + name
                    + ",window.__vmeta={V:" + seed_vm + "." + vfield + ",prog:" + seed_vm + "."
                    + prog_field + ",seed:" + seed_vm + ".l"
                    + ((",fd:" + seed_vm + "." + fd_name) if fd_name else "") + "}")
        if blockcache and cache_field:
            boot_new += (",window.__prog=window.__prog||{},window.__blk=function(n,v){"
                         "if(n==null)return;var i,q;window.__fpv=v;for(i=0;i<8;i++){q=n*64+i*8;window.__fp=q;"
                         "window.__prog[n]=window.__prog[n]||[];"
                         "window.__prog[n][i]=window.__JY(" + read_args + "v);}"
                         "window.__fp=null;window.__fpv=null;}")
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
            push = ("[" + fid + ",(" + val + "&&" + val + ".length)|0,(function(x){try{return "
                    "JSON.stringify(x)}catch(e){return String(x)}})(" + val + ")]")
            if killswitch:
                # self-identifying probe: copy #k aborts the run when window.__kill === k, so
                # the live copy can be found from the token alone (no cross-realm state).
                inject = ("(window.__kill===" + str(k) + ")&&(function(){throw 0})();")
            else:
                # log on the VM instance, not on `window`: the patched text runs in a realm
                # the page may not be able to enumerate, but the VM object is shared by
                # reference, so the log is reachable from whichever realm holds `__vmref`.
                vmp = params_w[1]
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

    # marker: proves the copy the page is running is *this* text. Some loads end up executing
    # a pristine copy (the page's own bootguard wins the race), and without the marker that is
    # indistinguishable from "nothing to log".
    if "window.__MINE=1;" not in src:
        src = src + "window.__MINE=1;"
    info = {"reader": name, "params": params[:3], "bits": bits_name, "flag": flag_name,
            "cache_field": cache_field, "vfield": vfield, "prog_field": prog_field,
            "seed_field": seed_id, "seed_call": seed_call}
    info.update(info_writer)
    return src, info
