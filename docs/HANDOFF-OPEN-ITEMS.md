# Handoff: mint a trusted token with no browser (state 2026-11-20)

Written for a fresh session that continues the botguard work. Read this first, then
`docs/token-format.md` (one-page format spec), then the referenced sections of `docs/botguard-notes.md`
(97-104 are this session's evidence). Do not re-derive what is measured.

## The target, and where it stands

**Target: a trusted token without a browser.** The shipped path (real Chrome over CDP,
`bgr_sidecar.py`) works and is *not* the goal. The browserless engines (`node:vm`, d8) mint a token in
the degraded regime.

* Trusted (Chrome): 1411-1437 chars, inside the trusted 1405-1447 band.
* Browserless (node **and** d8, same material): **3019 chars / 2264 B**, identical in both.
* The excess is **1187 B**, and it is one thing: the exception text the collector `V_` appends into the
  tag-132 field (field **231** in the 2026-11-20 build; 274 in the build section 96 measured). A
  trusted mint records no exception; the browserless engines throw six times and `V_` writes each
  `message:stack` there.

**Root cause, sharply scoped (sections 100-105).** The VM core object carries its fields in two tables,
`Y` (sparse array by field id) and `Pf`. They **are** created in a synthetic realm - section 105
falsifies the earlier "undefined on the instance" reading: the live core has `Y=arr512`, `Pf=arr0`.
What differs is `J`: the mining handlers are handed `G.J`, and in d8 `G.J` is an own Smi (159054, then
171716) where Blink has `G.J === G`. All six errors are field helpers reading a Smi's tables:

```
[ERRLOC] len=173 col=27  m  -> m=function(J,f,x){if((x=J.Y[f],...)...)     reading '345'/'194'/'56'
[ERRLOC] len=205 col=29  w  -> w=function(...){... J.Y[f] ...}              reading '27'
[ERRLOC] len=107 col=32  Q8 -> Q8=function(...){T.Pf.length>x?...}          reading 'length'
```

The core object is `uu`'s `x` (the interpreter loop's `this`; it carries `Nw`, the one property only
`uu` writes). `uu` sets `x.Y=[]` / `x.Pf=[]` / `x.bU=[]` / `x.J=x` at frame offset ~35 KB, and that runs
in a synthetic realm too (section 105). The generated frame program is **byte-identical in both realms**
(section 70), so the difference is not the initialiser - it is the later write to `J`. That is the next
read.

## Machines and tools (new since the old handoff)

* **Build host `192.168.92.26`** (root, 1 TB free, 4 cores, Ubuntu). Carries a Chromium 159 checkout
  (`~/chromium/src`, V8 15.9.40) with a patched **d8** and **chrome** in `out/Rel`. This is the machine
  that makes the browserless internals readable; the old handoff's "d8 is gone" is obsolete.
* `research/patch_chromium.py` applies the engine hooks, now five: `[EVALLOG]` (every eval: len+head),
  `[EVALSRC]` (full source of >50 KB evals = the frame copy), `[ERRLOG]` (every engine error),
  `[ERRLOC]` (`Isolate::ComputeLocation` -> source len + line/col), `[ERRFRM]` (per-frame function name
  + script length + `np`/`na` + a field dump of the receiver and of every parameter: `Y`/`Pf`/`bU`/`I`,
  `J` with an own-property flag, and ~34 more core fields, under `BG_ERRSTK`).
* Rebuild after editing the patch: `cd ~/chromium/src/v8 && git checkout -- src/execution/messages.cc`
  (only that file; the `[EVALLOG]`/`[EVALSRC]` hooks live in `compiler.cc` and are stable), then
  `python3 ~/patch_chromium.py --src ~/chromium/src` and `ninja -C out/Rel d8 -j4` (~2-4 min, 5 steps).
* Run: `BG_ERRSTK=1 ./chromium/src/out/Rel/d8 --allow-natives-syntax d8_mint.js -- --material
  material.json --freq freq.txt`. The `--` before script args matters (d8 eats `--material` else).
  `material.json` / `d8_mint.js` / `freq.txt` live in `/root/` on the host; re-scp after local edits.

## Established this session (do not re-run)

* **`fetch_build.py` format change**: `arr[0]` is now plain urlsafe base64 (no 3-byte prefix);
  `decode_blob()` tolerates both. Build `hwFN46BzpU0xcs39`.
* **Field ids rotate again**: tag-132 source = **231**, exception collector appends to **110**, writer
  is `F(J,f,x)` with guard `J==231||J==110||J==297`. Nothing may hard-code 274/444/77.
* **Chrome baseline on this build** (`probe_468.py`, guard taught the rotated shape): token 1437 /
  1077 B; field 231 = **898 B over 6 appends** (the mining transcript); field 110 = 266 writes but is
  not in the token. `probe_468.py` derives the guard's ids from the material.
* **node's inspector sees `node:vm` contexts** (d8's does not) and breakpoints in them hit - but the
  68 KB frame copy the inspector shows (script 124) never executes: collector/writer/tag-132 anchors
  all armed, zero hits; only a 368-byte handler hits. `CallSite.getThis()` is `undefined` on every VM
  frame. So the node side cannot be measured from inside; the host's d8 is the instrument.
* **The six errors' full chains** (`[ERRFRM]`):
  `main(25357) -> frame(62905) -> k1(137) -> Ae(514) -> handler(57) -> g(1120) -> TQ(342) -> m(173)`.
  The handler is `function(G,I,Z){Z=g(G,(I=g(G,26),57)),F(Z,b,""+n(G,I))}`; it hands `G.J` to the
  helpers. In Blink `G.J` is the core's self-reference; in d8 it is a Smi (section 105).
* **`uu`'s initialiser is not skipped** (section 105): evaluating its second statement in node leaves
  `x.Y`/`x.Pf`/`x.bU` set and `x.J === x` true, and the d8 core has `Y=arr512`, `Pf=arr0`, `Nw=arr5`.
* **`ZK` writes a number into `J`**: its assignment RHS is `T.A + Y` (`research/probe_zk_rhs.js`).
* **The interpreter loop is invoked with one argument** (`np=44 na=1`), so its `G` parameter is
  `undefined`; `a==71`'s `this.J=this` is gated behind `m(this,231)`.
* **Negative controls**: `node_mint --env win|webidl|tags|style|proxy|hidden` all mint exactly 3019
  (host-surface options change nothing); a `trustedTypes` shim in d8 changes nothing; d8's inspector
  bridge does not arm on this build (`insp_pauses 0`).

## Item 0 - active: what writes the Smi into the core's own `J`?

The old question ("why are `Y`/`Pf` undefined") is answered: they are not (section 105). The live
core - the interpreter loop's `this`, carrying `Nw`, the only property `uu` writes - has `Y=arr512`,
`Pf=arr0`, `bU=arr22216` in d8. `uu` really does set `x.J = x`. The handlers fail because they are
handed `G.J`, and in d8 `G.J` is an own Smi (`ownJ=1`): 159054 at the first error, 171716 from the
second on. In Blink `G.J === G` and `G.J.bU` = 22216.

So: name the write that replaces the core's self-referential `J` with a Smi. Candidates already
measured (`docs/botguard-notes.md` section 105): `ZK` stores `T.J = T.A + Y`; `YV` saves/restores
`f.J`; `vT` stores `this.J = f` but is reachable only through `x.qw`, which the frame program never
calls; the loop's `a==42` writes `this.J = G` with `G` = `undefined` (`np=44 na=1`), and `a==71`
writes `this.J = this` but only after `m(this,231)` succeeds. Two negatives: `J` is written only twice
(159054, then 171716) and is not a clock (`WALL=0.13 s`, `uS=smi0`) nor the live read position (`m`
keeps advancing while `J` stays 171716) - so it is one stale write, not a counter.

**Acceptance criterion:** the value and the writing frame at the moment `J` stops being the core's
self-reference. An engine-side `J`-write watch, or a per-state read of `this.J` inside the loop
(`xj#`/`j42#`/`tj#` arms in `research/probe_j.py` are the Chrome-side starting point), closes it.
Note `x.J=x` sits in `uu`'s second statement at frame offset 35999-36316; `research/probe_uu_condition.js`
evaluates that condition in isolation.

**Trap.** Never observe by patching an eval site or any interp text you then measure (sections 65, 83).
The only non-perturbing window is engine-level (the d8 hooks above).

## Item 1 - the five bytes at the end of the tag-99 record (low value)

Tag-99 is `len16 + field(F)`; the first four bytes are `RNG(4)`, the last five arrive by direct index
assignment and are not `Math.random` / `+new Date` (sections 41-46). Dead ends, do not re-run: any
`Math.random` site pinned, all `+new Date` pinned, pinning `performance.now` (degrades to a 33-char
error token), a field-buffer `Proxy` (inert), wrapping the slot by name (wrong copy). The live route:
refactor `research/bgpatch.py:patch_emit` into `detect(src)->sites` / `inject(src,sites)`, wrap the
emitter's own call expression, and put the log sink on the **VM instance** (`vm.__ixlog`), never
`window`. Acceptance: an entry counter at the top of the accessor must read non-zero on a run that also
produced emissions. **Value: low - these bytes affect no trust decision; if two attempts fail, close it
and return to item 0.**

## Item 2 - where the per-load constants come from (blocked on bgpatch's loop hunk)

The head carries per-load constants (6-byte marker, two 4-byte words, a 64-byte block); provenance is
the goal. `bgpatch.py` was taught this build's **boot / reader / writer** shapes (seed is `Q`'s third
argument; reader is `return(...)` with no space; writer is an if-chain, not a switch) but the **loop
hunk still fails** ("instruction loop not found"), so `run_one.py` falls back to emit-only and
`head_map.py` / `disasm.py --dataflow` are empty. Next: adapt the loop hunk, or read the constants'
writers straight from the `[EVALSRC]` frame source. Acceptance: name the environment reads behind each
constant group. Trap: instrumented runs are degraded; use provenance only.

## Item 3 - the authentication construction

Unchanged. Emitters XOR only fields 277/473/474 with a per-block keystream; editing any one byte of a
trusted token loses the OCR (sections 53-56). Open: reproduce the MAC/keystream offline against a
captured token, or prove it needs key material only inside the VM instance (`hq`/`Tu`). Live requests
need explicit user approval; prefer offline tests.

## Tool inventory (adds to the old list)

| tool | purpose |
| --- | --- |
| `research/probe_node274.py` | start `node --inspect` on `node_mint.mjs --arm-delay`, arm by shape, drain pauses |
| `research/probe_468.py` | Chrome: writer-guard append stream (ids derived), collector, code-only breakpoints |
| `research/probe_j.py` | Chrome: same, plus arms that read the core's `J` (`xj#`/`j42#`/`tj#`/`fld#`) |
| `research/patch_chromium.py` | the d8 engine hooks, incl. `[ERRLOC]`/`[ERRFRM]`; run on the build host |
| `research/probe_uu_condition.js` | node: evaluates `uu`'s 2nd statement; shows `x.Y`/`x.Pf`/`x.J=x` all run |
| `research/probe_zk_rhs.js` | node: evaluates `ZK`'s `T.J=` RHS; shows it stores `T.A+Y` |
| `research/probe_uu_args.js` | node: `uu` argument-order probe (needs `x1`/`qa` stubs) |
| `node_mint.mjs --arm-delay/--btoa-dump` | arm window / stack read at btoa (section 97: both negative) |

## Working rules

* Builds rotate per load and so do all ids. Derive roles structurally; never hard-code an id or a name.
* One experiment per page load; two dumps are only comparable inside the same page.
* Instrumentation pushes the VM onto the degraded branch - fine for provenance, fatal for a trusted
  token. Use engine-level logging, or hooks installed from outside the realm.
* Commit each verified conclusion to `main` with the measurement in the message, and push; verify with
  `git ls-remote origin refs/heads/main` equal to `git rev-parse HEAD`.
* Code comments and docstrings in English; chat replies in Chinese.
* Do not touch the shipped sidecar (`bgr_sidecar.py`, `gt_server.py`, `gt_image.py`, `Dockerfile*`).
