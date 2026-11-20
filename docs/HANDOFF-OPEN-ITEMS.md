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

**Root cause, sharply scoped (sections 100-104).** The VM instance carries its fields in two tables,
`Y` (sparse array by field id) and `Pf`. In a synthetic realm they are `undefined` on the instance the
mining handlers receive; in Blink they are initialised. All six errors are field helpers reading them:

```
[ERRLOC] len=173 col=27  m  -> m=function(J,f,x){if((x=J.Y[f],...)...)     reading '345'/'194'/'56'
[ERRLOC] len=205 col=29  w  -> w=function(...){... J.Y[f] ...}              reading '27'
[ERRLOC] len=107 col=32  Q8 -> Q8=function(...){T.Pf.length>x?...}          reading 'length'
```

The instance is built by `new bW` in the generated frame source (~11865); its initialiser sets
`x.Y=[]` / `x.Pf=[]` (~40 KB). The generated frame program is **byte-identical in both realms**
(section 70), so the difference is which branch of that initialiser runs. That is the next read.

## Machines and tools (new since the old handoff)

* **Build host `192.168.92.26`** (root, 1 TB free, 4 cores, Ubuntu). Carries a Chromium 159 checkout
  (`~/chromium/src`, V8 15.9.40) with a patched **d8** and **chrome** in `out/Rel`. This is the machine
  that makes the browserless internals readable; the old handoff's "d8 is gone" is obsolete.
* `research/patch_chromium.py` applies the engine hooks, now five: `[EVALLOG]` (every eval: len+head),
  `[EVALSRC]` (full source of >50 KB evals = the frame copy), `[ERRLOG]` (every engine error),
  `[ERRLOC]` (`Isolate::ComputeLocation` -> source len + line/col), `[ERRFRM]` (per-frame function name
  + script length, under `BG_ERRSTK`).
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
  The handler is `function(G,I,Z){Z=g(G,(I=g(G,26),57)),F(Z,b,""+n(G,I))}`; `G.J` is a self-reference
  (`vT` does `this.J=f`, `ib` tests `x.J==x`). So the helper reads the *instance's* tables.
* **Negative controls**: `node_mint --env win|webidl|tags|style|proxy|hidden` all mint exactly 3019
  (host-surface options change nothing); a `trustedTypes` shim in d8 changes nothing; d8's inspector
  bridge does not arm on this build (`insp_pauses 0`).

## Item 0 - active: why are `Y`/`Pf` undefined on the instance?

Read the `bW` constructor (frame source ~11865) and the initialiser at ~40 KB. The frame source is the
`[EVALSRC] ... [EVALSRC-END]` block of the d8 stderr - save it and read offline. Compare with the
identical Chrome frame program (section 70) to find the branch that sets `Y`/`Pf`. The handler reaches
the instance through `k1` (len 137) -> `Ae` (len 514); both are in `[EVALLOG]`.

**Acceptance criterion:** name the condition that skips (or defers) `x.Y=[]` / `x.Pf=[]` in a synthetic
realm. Everything else about the gap follows from that.

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
| `research/patch_chromium.py` | the d8 engine hooks, incl. `[ERRLOC]`/`[ERRFRM]`; run on the build host |
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
