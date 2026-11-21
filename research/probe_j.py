"""Read the exception log in plain text, at the collector, in a real browser (item 0, next step 2).

What the earlier attempts got wrong (section 96): a script's *text* is not its *code*. The interpreter
carries its own source as a string - it builds the frame program from it - so the collector's text
appears at columns the engine reports as unbreakable, and `setBreakpoint` silently snaps to the nearest
real code position (34 859 columns away in one case), where the locals are whatever that code has.

So this probe works in two phases against one page load:

1. a warm-up mint, so every script the VM creates exists;
2. scan **all** scripts for the collector's unique concat and for the tag-132 record payloads, and keep
   only occurrences where `Debugger.getPossibleBreakpoints` reports a code position at that column -
   the live copy, not the embedded text. Those are armed;
3. a second mint with the breakpoints in place.

`V_` builds `message + ":" + stack`, caps it by the budget byte in field 468, encodes it and appends it
to field **274** - which the serialiser emits as the tag-132 record (`js(a$(h.length,2).concat(h),...,
134,132)` with `h=C(this,274)`). Section 95's "U8" is that field-274 array; 468 only carries the budget.
The plaintext exists on `V_`'s stack and nowhere else, hence the breakpoint.

Every value read at a hit is a property read on locals or on the VM's arena - no interpreter call, so
the measurement does not perturb the mint (section 89).

    python3 research/probe_j.py --material /tmp/bgbuild_now/material.json --out /tmp/bg-j

Output: `<out>/f468.json` - both tokens, the armed sites, and every hit. The extra arms this variant
adds read the VM core's `J`:

* `xj#` at `x.A1=0` (immediately after `x.J=x` in `uu`) - is `x.J` the self-reference there?
* `j42#` at `this.J=G` and `tj#` at `G=this.J,this.J=this` in the interpreter loop - what are `G`
  and `this.J` at those two states?
* `fld#` on the 57-byte mining handler - is `G.J === G`?
"""
import argparse
import asyncio
import base64
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from bgr_sidecar import DEFAULT_UA, ChromeSession, PAGE_URL  # noqa: E402

# `k.message&&(X+=k.message)` - group 1 = the message holder, group 2 = the accumulator.
RE_MSG = re.compile(r"([A-Za-z_$][\w$]*)\.message&&\(\s*([A-Za-z_$][\w$]*)\s*\+=")
# `y=C(J,468)` - group 1 = budget holder, group 2 = getter, group 3 = VM instance.
RE_BUDGET = re.compile(r"([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*468\s*\)")
# `U8.length,2).concat(U8)` - a record payload of the tag-132 shape; group 1 = the field local.
RE_REC = re.compile(r"([A-Za-z_$][\w$]*)\.length\s*,\s*2\s*\)\s*\.concat\(\s*\1\s*\)")
# The field-append guard inside the writer function: `J==231||J==110||J==297` in the 2026-11-20
# build (the older build's `u==274||u==444||u==77` is the same shape with rotated ids). Only the
# variable and the ids move, so match the shape and let the ids come from the material.
RE_GUARD = re.compile(r"([A-Za-z_$][\w$]*)==(\d+)\|\|\1==(\d+)\|\|\1==(\d+)")

MINT = r"""(async () => {
  const arr = %s, freq = %s;
  try { delete window.ridgeslice; } catch (e) {}
  try { (0, eval)(%s); } catch (e) {}
  const VM = window.ridgeslice;
  if (!VM || typeof VM.a !== 'function') return JSON.stringify({stage: 'install'});
  try { delete window.ridgeslice; } catch (e) {}
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { VM.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const tok = await new Promise((res) => api[0]((t) => res(String(t)), [freq, undefined, undefined, undefined]));
  return JSON.stringify({tok: String(tok)});
})()"""


def derive(src: str, at: int = 0) -> dict:
    """Derive the collector's identifiers from a script copy, starting the search at `at`."""
    m = RE_MSG.search(src, at)
    if not m:
        return {}
    msg, acc = m.group(1), m.group(2)
    tail = src[m.end():m.end() + 3000]
    b = RE_BUDGET.search(tail)
    if not b:
        return {}
    return {"msg": msg, "acc": acc, "budget": b.group(1), "getter": b.group(2), "obj": b.group(3)}


def line_col(src: str, off: int) -> tuple:
    return src.count("\n", 0, off), off - (src.rfind("\n", 0, off) + 1)


def tok_bytes(tok: str) -> bytes:
    raw = tok[1:] if tok.startswith(";") else tok
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


class F468(ChromeSession):
    def __init__(self, *a, **k):
        self.dump_src = k.pop("dump_src", None)
        super().__init__(*a, **k)
        self.armed = []
        self.sites = {}          # breakpointId -> {site, sid, vars}
        self.hits = []
        self.scripts = {}
        self.seen = set()
        self.lock = asyncio.Lock()
        self.t0 = time.time()

    def log(self, *a):
        print("[%6.1fs]" % (time.time() - self.t0), *a, flush=True)

    # -- CDP plumbing -------------------------------------------------------------------------------
    async def _raw(self, method, **params):
        self._id += 1
        mid = self._id
        fut = self._loop.create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        return await asyncio.wait_for(fut, timeout=90)

    async def _read(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(RuntimeError(str(msg["error"])))
                        else:
                            fut.set_result(msg.get("result", {}))
                    continue
                m = msg.get("method")
                if m == "Debugger.scriptParsed":
                    p = msg["params"]
                    self.scripts[p["scriptId"]] = {"url": (p.get("url") or "")[:60],
                                                   "len": p.get("length", 0)}
                elif m == "Debugger.paused":
                    asyncio.create_task(self._on_pause(msg["params"]))
        except Exception:  # noqa: BLE001
            pass

    async def _eval(self, cfid, expr):
        try:
            r = await self._raw("Debugger.evaluateOnCallFrame", callFrameId=cfid,
                                expression=expr, returnByValue=True)
            res = r.get("result") or {}
            if "value" in res:
                return res["value"]
            return {"raw": res.get("description") or res.get("type") or str(r)[:100]}
        except Exception as e:  # noqa: BLE001
            return "ERR " + str(e)[:80]

    # -- arming -------------------------------------------------------------------------------------
    async def _possible(self, sid, line, col, before=40, after=500):
        """Columns in [col-before, col+after] where the engine would actually stop."""
        try:
            r = await self._raw("Debugger.getPossibleBreakpoints",
                                start={"scriptId": sid, "lineNumber": line,
                                       "columnNumber": max(0, col - before)},
                                end={"scriptId": sid, "lineNumber": line,
                                     "columnNumber": col + after},
                                restrictToFunction=False)
            return sorted((l.get("columnNumber") or 0) for l in (r.get("locations") or []))
        except Exception:  # noqa: BLE001
            return []

    async def _arm_text(self, sid, src, text, site, variables, limit=2):
        """Arm the first `limit` *code* occurrences of `text`; log the data-only ones and move on."""
        made = 0
        for off in [m.start() for m in re.finditer(re.escape(text), src)]:
            line, col = line_col(src, off)
            cols = await self._possible(sid, line, col)
            if not cols:
                self.armed.append({"site": site, "scriptId": sid, "line": line, "col": col,
                                   "skipped": "text is data, not code"})
                continue
            pick = next((c for c in cols if c >= col - 40), cols[0])
            try:
                r = await self._raw("Debugger.setBreakpoint", location={
                    "scriptId": sid, "lineNumber": line, "columnNumber": pick})
            except Exception as e:  # noqa: BLE001
                self.armed.append({"site": site, "scriptId": sid, "line": line, "col": pick,
                                   "err": str(e)[:60]})
                continue
            bid = r.get("breakpointId")
            if bid:
                self.sites[bid] = {"site": site, "sid": sid, "vars": variables}
            self.armed.append({"site": site, "scriptId": sid, "line": line, "text_col": col,
                               "col": pick, "id": bid, "actual": r.get("actualLocation")})
            self.log("armed %-18s script %-3s text %s:%s -> code %s" % (site, sid, line, col, pick))
            made += 1
            if made >= limit:
                break
        return made

    async def _arm(self, sid):
        """Consider one script, at the moment it is about to run (`beforeScriptExecution`).

        Each mint creates a *new* frame program, so arming during a warm-up measures a dead copy. The
        instrumentation pause is the only place where the live copy is both parsed and not yet run.
        """
        if sid in self.seen:
            return
        self.seen.add(sid)
        meta = self.scripts.setdefault(sid, {})
        if (meta.get("len") or 0) > 200_000:
            meta["skipped"] = "too big for the VM's own copies"
            return
        try:
            src = (await self._raw("Debugger.getScriptSource",
                                   scriptId=sid)).get("scriptSource", "")
        except Exception as e:  # noqa: BLE001
            meta["err"] = "source: " + str(e)[:60]
            return
        d = derive(src)
        recs = [m.group(1) for m in RE_REC.finditer(src)]
        meta.update({"src_len": len(src), "frame": src.startswith("\n\n"),
                     "collector": bool(d), "recs": list(dict.fromkeys(recs))[:6]})
        if self.dump_src and len(src) > 20000:
            os.makedirs(self.dump_src, exist_ok=True)
            open(os.path.join(self.dump_src, "cdn-%s.js" % sid), "w").write(src)
        if d:
            q = '%s+=":"+%s.stack' % (d["acc"], d["msg"])
            meta["armed_log"] = await self._arm_text(
                sid, src, q, "log#%s" % sid,
                {"msg": d["msg"], "acc": d["acc"], "obj": d["obj"]})
        if (meta.get("len") or 0) > 20000:
            meta["armed_xj"] = await self._arm_text(
                sid, src, "x.A1=0", "xj#%s" % sid, {"x": "x"})
            meta["armed_j42"] = await self._arm_text(
                sid, src, "this.J=G", "j42#%s" % sid, {"g": "G", "self": "this"})
            meta["armed_tj"] = await self._arm_text(
                sid, src, "G=this.J,this.J=this", "tj#%s" % sid, {"g": "G", "self": "this"})
        if len(src) == 57 and "G.J" in src:
            meta["armed_gj"] = await self._arm_text(
                sid, src, "G.J)}", "gj#%s" % sid, {"g": "G"})
        g = RE_GUARD.search(src)
        if g:
            text = "%s==%s||%s==%s||%s==%s" % (g.group(1), g.group(2), g.group(1), g.group(3),
                                              g.group(1), g.group(4))
            meta["armed_field"] = await self._arm_text(
                sid, src, text, "fld#%s" % sid, {"field": g.group(1)})
        for var in dict.fromkeys(recs):
            text = "%s.length,2).concat(%s)" % (var, var)
            n = await self._arm_text(sid, src, text, "rec#%s:%s" % (sid, var), {"rec": var}, limit=1)
            if n:
                meta.setdefault("armed_rec", []).append(var)

    # -- pause handling -----------------------------------------------------------------------------
    async def _on_pause(self, p):
        async with self.lock:
            await self._pause_body(p)

    async def _pause_body(self, p):
        if p.get("reason") == "instrumentation":
            sid = (p.get("data") or {}).get("scriptId")
            if sid:
                await self._arm(sid)
            try:
                await self._raw("Debugger.resume")
            except Exception:  # noqa: BLE001
                pass
            return
        cf = p.get("callFrames") or [{}]
        top = cf[0]
        loc = top.get("location") or {}
        hit = p.get("hitBreakpoints") or []
        info = self.sites.get(hit[0]) if hit else None
        rec = {"sid": loc.get("scriptId"), "line": loc.get("lineNumber"),
               "col": loc.get("columnNumber"), "reason": p.get("reason"),
               "site": (info or {}).get("site"),
               "frames": [f.get("functionName") or "?" for f in cf[:8]]}
        v = (info or {}).get("vars") or {}
        cfid = top.get("callFrameId")
        if "field" in v:
            fvar = v["field"]
            rec["field_id"] = await self._eval(cfid, "String(%s)" % fvar)
            rec["args"] = await self._eval(
                cfid, "Array.prototype.map.call(arguments, function(a){ return typeof a === 'number' "
                      "? String(a) : (Array.isArray(a) ? 'A' + a.length + '[' + "
                      "Array.prototype.slice.call(a, 0, 16).map(function(v){return typeof v === "
                      "'number' ? v : (typeof v);}).join(',') + ']' : typeof a); }).join('|')")
            rec["callers"] = [f.get("functionName") or "?" for f in cf[:12]]
            rec["argJ"] = await self._eval(
                cfid, "(arguments[1]&&typeof arguments[1]==='object')?"
                       "('Jtype='+typeof arguments[1].J+' J='+String(arguments[1].J)"
                       "+' self='+String(arguments[1].J===arguments[1])"
                       "+' Y='+arguments[1].Y.length+' Pf='+arguments[1].Pf.length"
                       "+' bU='+arguments[1].bU.length):'arg1='+typeof arguments[1]")
            rec["useful"] = True
            self.hits.append(rec)
            self.log("hit %-16s field=%s args=%s frames=%s"
                     % (rec.get("site"), rec.get("field_id"), (rec.get("args") or "")[:60],
                        "/".join(rec.get("frames") or [])))
            try:
                await self._raw("Debugger.resume")
            except Exception:  # noqa: BLE001
                pass
            return
        if "x" in v and str(v.get("x")) == "x":
            xv = v["x"]
            rec["xj_self"] = await self._eval(cfid, "String(%s.J === %s)" % (xv, xv))
            rec["xj_type"] = await self._eval(cfid, "typeof %s.J" % xv)
            rec["xj_val"] = await self._eval(cfid, "String(%s.J)" % xv)
            rec["useful"] = True
            self.hits.append(rec)
            self.log("hit xj %s self=%s type=%s val=%s" % (rec.get("site"), rec.get("xj_self"),
                                                           rec.get("xj_type"), rec.get("xj_val")))
            try:
                await self._raw("Debugger.resume")
            except Exception:
                pass
            return
        if "g" in v and "self" in v:
            rec["g_type"] = await self._eval(cfid, "typeof %s" % v["g"])
            rec["g_val"] = await self._eval(cfid, "String(%s)" % v["g"])
            rec["thisJ"] = await self._eval(cfid, "String(%s.J)" % v["self"])
            rec["thisJself"] = await self._eval(cfid, "String(%s.J === %s)" % (v["self"], v["self"]))
            rec["useful"] = True
            self.hits.append(rec)
            self.log("hit %s G=%s(%s) this.J=%s self=%s" % (rec.get("site"), rec.get("g_val"),
                                                            rec.get("g_type"), rec.get("thisJ"),
                                                            rec.get("thisJself")))
            try:
                await self._raw("Debugger.resume")
            except Exception:
                pass
            return
        if "self" in v:
            rec["tj_self"] = await self._eval(cfid, "String(this.J === this)")
            rec["tj_type"] = await self._eval(cfid, "typeof this.J")
            rec["tj_val"] = await self._eval(cfid, "String(this.J)")
            rec["useful"] = True
            self.hits.append(rec)
            self.log("hit tj %s self=%s type=%s val=%s" % (rec.get("site"), rec.get("tj_self"),
                                                           rec.get("tj_type"), rec.get("tj_val")))
            try:
                await self._raw("Debugger.resume")
            except Exception:
                pass
            return
        if "g" in v:
            gv = v["g"]
            rec["g_type"] = await self._eval(cfid, "typeof %s" % gv)
            rec["g_desc"] = await self._eval(
                cfid, "(function(){try{var o=%s;return o?(typeof o)+':'+(o.Y?(o.Y.length):'-')+':'+(o.Pf?o.Pf.length:'-'):'null'}catch(e){return 'err'}})()" % gv)
            rec["gj_type"] = await self._eval(cfid, "typeof %s.J" % gv)
            rec["gj_val"] = await self._eval(cfid, "String(%s.J)" % gv)
            rec["gj_self"] = await self._eval(cfid, "String(%s.J === %s)" % (gv, gv))
            rec["gj_j"] = await self._eval(cfid, "(function(){try{var o=%s.J;return o?typeof o.J:'null'}catch(e){return 'err'}})()" % gv)
            rec["gj_jself"] = await self._eval(cfid, "String(%s.J.J === %s.J)" % (gv, gv))
            rec["gj_bU"] = await self._eval(cfid, "(function(){try{var o=%s.J;return o?(o.bU?o.bU.length:'-'):'-'}catch(e){return 'err'}})()" % gv)
            rec["gj_desc"] = await self._eval(
                cfid, "(function(){try{var o=%s.J;return (o&&typeof o==='object')?('obj Y='+(o.Y?o.Y.length:'-')+' Pf='+(o.Pf?o.Pf.length:'-')):('nonobj:'+String(o))}catch(e){return 'err'}})()" % gv)
            rec["useful"] = True
            self.hits.append(rec)
            self.log("hit gj %s G=%s G.J=%s (%s)" % (rec.get("site"), rec.get("g_desc"),
                                                     rec.get("gj_val"), rec.get("gj_desc")))
            try:
                await self._raw("Debugger.resume")
            except Exception:
                pass
            return
        if "rec" in v:
            var = v["rec"]
            rec["type"] = await self._eval(cfid, "typeof %s + (Array.isArray(%s) ? ':array' : '')"
                                                % (var, var))
            rec["len"] = await self._eval(cfid, "String(%s && %s.length)" % (var, var))
            rec["text"] = await self._eval(
                cfid, "(%s && typeof %s === 'string') ? %s.slice(0, 2000) : "
                      "(Array.isArray(%s) ? Array.prototype.slice.call(%s, 0, 40).join(',') : String(%s))"
                % (var, var, var, var, var, var))
            rec["this_kind"] = await self._eval(cfid, "typeof this")
            rec["this_u"] = await self._eval(
                cfid, "(this && this.u) ? Object.getOwnPropertyNames(this.u).join(',') : '-'")
            rec["this_u468"] = await self._eval(
                cfid, "(this && this.u && this.u[468]) ? String(this.u[468].length) + '@0=' + String(this.u[468][0]) : 'none'")
            rec["this_u274"] = await self._eval(
                cfid, "(this && this.u && this.u[274]) ? String(this.u[274].length) + ': ' + "
                      "Array.prototype.slice.call(this.u[274], 0, 16).join(',') : 'none'")
            rec["same274"] = await self._eval(cfid, "(this && this.u) ? String(this.u[274] === %s) : '-'" % var)
        else:
            msg, obj = v.get("msg", "k"), v.get("obj", "J")
            rec["msg_text"] = await self._eval(
                cfid, "(function(){try{return %s && %s.message ? String(%s.message) : '-'}catch(e){return 'n/a'}})()"
                % (msg, msg, msg))
            rec["stack_text"] = await self._eval(
                cfid, "(function(){try{return %s && %s.stack ? String(%s.stack) : '-'}catch(e){return 'n/a'}})()"
                % (msg, msg, msg))
            rec["acc_type"] = await self._eval(cfid, "typeof %s" % v.get("acc", "X"))
            rec["budget"] = await self._eval(
                cfid, "(function(){try{var y=%s.u[468];return y ? String(y[0]) : 'none'}catch(e){return 'n/a'}})()"
                % obj)
            rec["arena274"] = await self._eval(
                cfid, "(function(){try{var y=%s.u[274];return y ? String(y.length) : 'none'}catch(e){return 'n/a'}})()"
                % obj)
        rec["useful"] = (isinstance(rec.get("msg_text"), str) and rec["msg_text"] not in ("-", "n/a")) \
            if "msg_text" in rec else (isinstance(rec.get("type"), str) and rec["type"] != "undefined")
        self.hits.append(rec)
        self.log("hit %-18s budget=%s arena274=%s msg=%r"
                 % (rec.get("site"), rec.get("budget"), rec.get("arena274"),
                    (rec.get("msg_text") or "")[:50]))
        try:
            await self._raw("Debugger.resume")
        except Exception:  # noqa: BLE001
            pass


async def run(material_path: str, out: str, port: int, chrome: str, dump_src) -> None:
    m = json.load(open(material_path))
    arr = m["arr"]
    interp = arr[5][-1]
    freq = open(os.path.join(HERE, "freq.txt")).read()
    print("material collector:", derive(interp))
    expr = MINT % (json.dumps(arr), json.dumps(freq), json.dumps(interp))
    cs = F468(chrome, port, DEFAULT_UA, "/tmp/bg-468-%d" % port, dump_src=dump_src)
    await cs.start()
    try:
        await cs.send("Runtime.enable")
        await cs.send("Debugger.enable")
        await cs._raw("Debugger.setInstrumentationBreakpoint",
                      instrumentation="beforeScriptExecution")
        await cs.navigate(PAGE_URL, settle=7)
        cs.log("navigated, minting")
        t = json.loads(await asyncio.wait_for(cs.eval(expr), timeout=180))
        tok = t.get("tok") or ""
        blob = tok_bytes(tok)
        good = [h for h in cs.hits if h.get("useful")]
        logs = [h for h in good if str(h.get("site", "")).startswith("log")]
        lens = [len((h.get("msg_text") or "") + ":" + (h.get("stack_text") or "")) for h in logs]
        recap = {"token": tok, "token_chars": len(tok), "token_bytes": len(blob), "head": blob[:16].hex(),
                 "scripts": cs.scripts, "armed": cs.armed, "hits": cs.hits,
                 "hits_total": len(cs.hits), "hits_useful": len(good), "log_hits": len(logs),
                 "sum_plaintext_len": sum(lens),
                 "first_budget": logs[0].get("budget") if logs else None,
                 "last_budget": logs[-1].get("budget") if logs else None,
                 "first_arena274": logs[0].get("arena274") if logs else None,
                 "last_arena274": logs[-1].get("arena274") if logs else None}
        os.makedirs(out, exist_ok=True)
        json.dump(recap, open(os.path.join(out, "f468.json"), "w"), indent=1)
        print("token (%d chars / %d B)  armed %d  hits %d (%d useful, %d collector)"
              % (len(tok), len(blob), len(cs.sites), len(cs.hits), len(good), len(logs)))
        for sid, s in cs.scripts.items():
            if s.get("collector") or s.get("armed_rec"):
                print("  script %-3s len %-7s frame=%s collector=%s armed_log=%s armed_rec=%s %s"
                      % (sid, s.get("src_len"), s.get("frame"), s.get("collector"),
                         s.get("armed_log"), s.get("armed_rec"), s.get("skipped") or ""))
        for h in cs.hits[:24]:
            print("--- %s at %s:%s col %s  frames %s" % (h.get("site"), h.get("sid"), h.get("line"),
                                                         h.get("col"), "/".join(h.get("frames") or [])))
            if h.get("budget") is not None:
                print("    budget:", h.get("budget"), " arena274:", h.get("arena274"))
                print("    message:", repr(h.get("msg_text")))
                print("    stack:", repr((h.get("stack_text") or "")[:300]))
            if h.get("len") is not None:
                print("    rec len:", h.get("len"), "type:", h.get("type"), "same274:", h.get("same274"))
                print("    this_u468:", h.get("this_u468"))
                print("    this_u274:", h.get("this_u274"))
                print("    value:", repr(h.get("text")))
        for needle in (b"CSSMathMin", b"Linux x86_64", b"GMT+0900"):
            i = blob.find(needle)
            print("  token contains %-12s at byte %s" % (needle.decode(), i))
        print("collector hits:", len(logs), " sum plaintext:", recap["sum_plaintext_len"],
              " budget first/last:", recap["first_budget"], recap["last_budget"],
              " arena274 first/last:", recap["first_arena274"], recap["last_arena274"])
    finally:
        await cs.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--material", default="/tmp/bgbuild_now/material.json")
    ap.add_argument("--out", default="/tmp/bg-468")
    ap.add_argument("--port", type=int, default=10760)
    ap.add_argument("--chrome", default="/usr/bin/google-chrome-stable")
    ap.add_argument("--dump-src", default=None, help="directory for the scanned script sources")
    a = ap.parse_args()
    asyncio.run(run(a.material, a.out, a.port, a.chrome, a.dump_src))


if __name__ == "__main__":
    main()
