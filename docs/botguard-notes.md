# Botguard reverse-engineering notes

Baseline for the "no browser" line of work. Everything below was measured on this
host against the live service; nothing here is copied from other write-ups.

Scope: the token that `/DataService.GetImageTranslation` (rpcid `WqWDPb`) requires in
`X-Goog-BatchExecute-Bgr`, minted by Google's botguard VM. Text translation does not
use any of this.

Status: the VM's decision is **not** reproduced without a browser yet. A browser
sidecar is what ships (`bgr_sidecar.py`); these notes exist so the serializer work can
continue from facts instead of guesses.

---

## 1. Two token shapes, and they are not the same format

The VM emits one of two shapes. Both are `";" + base64url(bytes)`.

| | trusted | degraded |
| --- | --- | --- |
| token string | 1405–1447 chars | 2118–2897 chars |
| decoded bytes | **1065–1087** | **2114–2170** |
| entropy | 7.83 bits/byte | 7.90 bits/byte |
| fixed marker | present at offset 5–6 | present at offset 5–6 |
| lag 1/2/4/8/16 autocorrelation | 0.2–0.8 % | 0.2–0.8 % |
| shared 10-byte windows with the other shape | **none** | **none** |

Marker (8 bytes, the only thing both shapes share):

```
00 06 0b 77 65 eb 2b 77
```

Observed heads (one pair from the same minute, same request body):

```
trusted   35 2b b8 2b 4f | d0 00 06 0b 77 65 eb 2b 77 | 5f 50 5f ce 75 12 75 8f 24 26 00 40 01 10 0a …
degraded  43 5d b8 5d 48 | d0 00 06 0b 77 65 eb 2b 77 | 50 5f ce 75 12 75 8f 24 12 00 03 16 00 f9 75 …
```

Reading:

* the 5 bytes before the marker follow the preamble the interpreter builds:
  `C = AY(2).concat(field146)`, then `C[1] = C[0] ^ 30`. Both shapes satisfy it
  (`0x35 ^ 0x2b == 0x1e`, `0x43 ^ 0x5d == 0x1e`), so the preamble is shape-independent.
* after the marker the two diverge immediately (trusted carries one extra `0x5f`), and
  the degraded shape then carries **~1050 bytes more payload**.
* high entropy, no periodic XOR structure, no shared windows: the body is encrypted
  with a per-sign keystream. Byte-level diffing of the payload is therefore not
  possible offline - the plaintext only exists inside the VM.

Raw captures (not committed): `/tmp/buf_trusted.bin` (1065 B), `/tmp/buf_wrapped.bin`
(2114 B), both produced by the `btoa` hook in §5.

## 2. What the VM object looks like at encode time

Reached by walking `CallSite.getThis()` from the `btoa` call (§5). The object sits on
call frames 2–4 and has 54 own properties. Selected ones, with values from one trusted
run:

| prop | observed | note |
| --- | --- | --- |
| `h` | 512 slots | field factories, `{create, concat}` per slot; `create()` returns the field value, `undefined` for slots that were already consumed |
| `NU` | 22353 B | program bytecode (the blob) |
| `P` | 3 frames | interpreter call stack; each frame is 7 items (fn id, args, `Arguments`) |
| `hq` | 8 B | per-sign XOR table, e.g. `47 132 201 191 76 4 130 25` |
| `rc` | 32–33 ints | recorded inter-operation timings, ms |
| `jr` | float | accumulated time (trusted ~1592 ms, degraded ~166 ms) |
| `V` | 178824 | constant in both shapes |
| `Pc` | 29590–30009 | constant-ish |
| `i` | int32 | varies per sign |
| `E5`, `ir`, `K`, `Ke`, `R` | ints | trusted `E5=16 ir=3 Ke=18 R=2200`; degraded `E5=0 ir=0 Ke=25 R=100` |
| `qU`, `BY`, `Ty` | ms epochs | clock base |
| `dc`, `xE`, `IA`, `Zh`, `pu` | 0 length | unused on this path |
| `C` | 54 keys | back-reference to the instance |

The `h` slots are **per-byte value factories, not containers**. Measured anatomy of a
slot (frame realm, right after a mint):

```
ownKeys        ["create", "concat"]
prototype      not Object.prototype; an object dressed up as a function
               (propertyIsEnumerable, length, call, splice, prototype, stack, parent, floor)
create         function(n){ G=(c=(G+=6+7*Y,n), 7+2*(G&-8)-2*(G^7))+(~G&7) }   // returns a NUMBER
arity          1
sameCreate     false across slots (each slot closes over its own G/Y state)
```

So a field is never materialised as an array: the writers call `create(n)` once per
byte, push the result straight into the output buffer, and XOR it with the per-sign
table on the way. At encode time the interesting ids (146, 277, 261, 311, 323, 444,
473, 474, 495, 117) return `undefined` from `create()` simply because they were
already drained; 21 and 230 still return numbers (140846, 178824) because they are
counters, not payloads.

Consequence: the plaintext field breakdown cannot be read after the fact at all. It
has to be intercepted **while it is generated**, which means hooking the writer
functions (`ax`, `qj` in the inline build) or wrapping each slot's `create` between
instance creation and serialization.

### 2b. Field sizes, measured by instrumenting the writers

`Array.prototype.push` and `Array.prototype.concat` can be wrapped in the frame realm
via CDP **without losing trust** (token stays 1405–1447), which makes the writer
pipeline observable. Every `concat` the serializer performs is `nonce(2) + field(n)`,
so the call list is a field-size profile for the run:

```
trusted (5 calls)   2+2=4?   no: this=99 + [2] -> 101
                    2 + 64   = 66
                    2 + 71   = 73
                    2 + 881  = 883
                    2 + 1059 = 1061      <- final field146, becomes the token

degraded (9 calls)  99 + 2   = 101
                    2 + 542  = 544   (three identical calls)
                    2 + 542  = 544
                    2 + 542  = 544
                    2 + 365  = 367
                    2 + 19   = 21
                    2 + 26   = 28
                    2 + 2052 = 2054
                    2 + 2112 = 2114      <- final token
```

The degraded run does not drop fields - it writes **more of them** (9 vs 5), including
three byte-identical 542-byte blocks. That matches the byte-level observation in §1
(~1050 extra bytes of high-entropy payload).

Array sizes alone identify the *output* buffers reliably (1074 B trusted vs 2052 B
degraded, matching the token sizes), but not the field ids: the id is an argument of
the writer (`ax`/`qj`), not of `concat`. Mapping sizes to ids is the next step.

## 3. Where the encode happens

Call stack at the `btoa` call, captured inside the frame realm:

```
at window.btoa (<anonymous>:1:180)
at o3   (eval at <anonymous> (eval at <anonymous> (:4:14)), <anonymous>:4022:5990)
at Rz.wT(eval at <anonymous> (eval at <anonymous> (:4:14)), <anonymous>:4022:7256)
at DS.eV(eval at <anonymous> (eval at <anonymous> (:4:14)), <anonymous>:4022:61340)
at Rz.eval [as F](eval at <anonymous> (eval at <anonymous> (:4:14)), <anonymous>:4022:60724)
```

Column numbers are stable across runs (5990 / 7256 / 61340 / 60724); the line number
is not - it moves with the per-run assembly (1322, 4022, 6656, 7617 all observed).
Names are per-run mangled: the same functions appeared as `o3` / `wT` / `eV` / `F` in
one build and as `y4` / … in another. **Do not key anything off names or lines.**

`DS.eV` is the encoder (`btoa` + `+`→`-`, `/`→`_`, strip `=`), `Rz.F` is the VM entry.

## 4. Hypothesis ledger

Everything here was tested; each line says what was changed and what the token did.
Token length is the cheap discriminator: trusted ≈ 1405–1447, degraded ≈ 2800 (jsdom)
or 2114 bytes (Chrome with a wrapped eval).

| # | hypothesis | experiment | result |
| --- | --- | --- | --- |
| 1 | layout is fingerprinted | jsdom: `offsetHeight` / `getBoundingClientRect` / `clientWidth` forced to non-zero | token 2897, unchanged - **excluded** |
| 2 | frame intrinsics must not be shared | node:vm frame with its own `Math`/`Date`/`JSON` | 2897, unchanged - **excluded** |
| 3 | frame realm is missing APIs | filled `requestIdleCallback`, `trustedTypes`, `chrome`, `matchMedia`, `MessageChannel`, `IntersectionObserver`, `Permissions`, `isSecureContext` | 2817, unchanged - **excluded** |
| 4 | frame realm needs the same hardening as the page | `harden(frameWindow)` applied on load and on every `contentWindow` read (verified to run before the eval) | 2817, unchanged - **excluded** |
| 5 | identity relations (`parent`, `top`, `frameElement`, `length`, `origin`) | measured in jsdom | all correct (`parent === outer`, `frameElement === iframe`, `length === 0`, …) - **excluded** |
| 6 | the VM inspects stack traces | `Error.prototype.stack` getter wrapped in the frame realm via CDP | **0 reads**; `Error.prepareStackTrace` never called - **excluded** |
| 7 | timing / clock | frame `performance.now` → 0, `Date.now` → constant | `jr=0`, `rc` all zeros, token **still trusted** - **excluded** |
| 8 | native functions are authenticity-checked | 17 natives wrapped in `Proxy` (createElement, querySelector, setAttribute, getAttribute, getBoundingClientRect, Math.random, Date.now, performance.now, JSON.stringify, Array.push, defineProperty, gOPD, Fn.toString, btoa, setTimeout, charCodeAt, getRandomValues) | token 1404, **trusted** - none of them is checked |
| 9 | script origin / sourceURL matters | tried to read the frame script's URL | `scriptParsed.url` is empty; no js/bg script is fetched - **not testable this way** |

Two things that *do* flip a trusted Chrome run to degraded:

* wrapping `contentWindow.eval` (plain function, `Proxy` of the native, or a wrapper
  with a forged `toString`) → 2820. Nothing else tested does.
* `chrome-headless-shell` as the engine (§7).

## 5. Tooling that works (CDP, invisible to the VM)

All of it runs over CDP, so the page cannot see it, and none of it breaks trust
(verified by the token staying in the trusted range).

1. **Frame-realm hook.** Subscribe to `Runtime.executionContextCreated`, pick the
   child contexts (`auxData.isDefault`, id != main), then `Runtime.evaluate` with that
   `contextId`. This is how `window.btoa` was replaced to capture the pre-encode bytes
   and the stack; also how the `Error.prototype.stack` getter and the frozen clock were
   installed.
2. **Capture the pre-encode buffer.** Replace `window.btoa` in the frame realm, push
   `[length, string, new Error().stack]`, and read `window.__bt` back from that context
   after the mint. This yields exactly the bytes Google will see, before base64.
3. **Reach the VM object.** Inside the `btoa` hook, set
   `Error.prepareStackTrace = (e, frames) => { window.__selfs = frames.map(f => f.getThis()) }`,
   then force `new Error().stack`; frames 2–4 carry the VM instance (§2).
4. **Breakpoints.** `Debugger.setBreakpoint` works inside the frame script, but line
   anchoring is unreliable (see §6), so prefer the hook in (2).

## 6. Traps worth remembering

* **Text patching never reaches the frame.** The VM assembles its own copy of the
  interpreter at runtime (a marker prepended to the string we pass never appears in the
  frame's script; patching `arr[5][-1]` does not either). The frame script is a
  no-URL, ~63–68 KB script whose length changes every run.
* **Builds rotate.** `?op=images` alternates between two builds:
  `FhxsKBPKEL3Q_…` (interpreter carries the program inline, 7 × `k(this,` anchors) and
  `EONwmJdvD0_…` (program only in the 30 KB blob, 0 anchors). Pin one build when doing
  experiments, and check that the *pair* (blob + interpreter) is consistent - mixing
  builds silently yields a wrong token.
* **The VM global is not always called `ridgeslice`.** Find it by scanning
  `Object.keys(window)` for an object with an `.a` function.
* **`getPossibleBreakpoints` over a whole frame script returns almost nothing**
  (1 position in 2742 lines): the readable text is largely packed string arrays.
* **`Debugger.setBreakpointOnFunctionCall` does not fire on builtins** (`btoa`).
* **CDP will not serialise a call-frame argument** (`Object reference chain is too
  long`) - evaluate `String(...)` and parse in Python.
* **`chrome_crashpad_handler` must exist** or chromium aborts at start-up; the Vulkan
  validation layer and the mesa GL stack can both go (see README).

## 7. chrome-headless-shell: rejected

Same page, same UA, same request path; only the binary differs.

| signal | full chrome | headless-shell |
| --- | --- | --- |
| `navigator.webdriver` | false | **true** |
| `navigator.userAgentData.brands` | Not:A-Brand, Chromium, Google Chrome | Not:A-Brand, Chromium, **HeadlessChrome** |
| `window.chrome` | `loadTimes,csi,app` | none |
| `navigator.plugins` / `mimeTypes` | 5 / 2 | 0 / 0 |
| `screen` | 800×600 (headful Xvfb) | 1920×1040 |
| `languages` | en-US,en | en-US |
| `document.hasFocus()` | false | true |
| `performance.memory` | 4395630592 | 3760000000 |

Token length is normal (1412–1468, trusted range) but the RPC answers with the echo
only. Patching all of the above in the frame realm via CDP does not help, and neither
does sending the request *from inside the page* (so the browser supplies its own
headers): still 1 element, while full chrome on the same path returns 4.

Conclusion: the VM's short/long choice and Google's accept/reject are **two
independent decisions**. headless-shell passes the first and fails the second, and the
remaining tells are engine-internal (the injected `chrome.*` shims are JS functions,
not natives). Full chromium is required.

## 8. Open questions for the serializer work

1. Capture field writes *during* serialization instead of after - **attempted, blocked**.
   The VM instance is closure-local: scanning every property of every global in the
   frame realm finds no reference to it (`globalRefs: []`, no VM global at all by that
   name in the frame - the `ridgeslice` object our own code holds lives in the *outer*
   realm). The only way to reach it is a call stack, and constructing `Error`s inside
   the `Array.prototype.push` hook - even one per mint, to cache the instance - flips
   the token to degraded (3095 chars). A pure counting wrapper on `push` stays trusted
   (1420), so the trigger is the Error construction, not the wrapper.

   Two known-good facts
   to build on: the VM is **reusable inside one page** (three consecutive mints all
   returned trusted-length tokens), and each slot's `create` is a per-instance closure,
   so arming breakpoints on a *previous* instance's factories catches nothing (and
   disturbed the next mint: token 111). The workable route is a tight poller in the
   frame realm that wraps the new instance's `h[*].create` as soon as
   `ridgeslice.a(...)` has produced it, or a breakpoint on the writers themselves
   (`ax`/`qj`), whose ids are arguments rather than names.
2. Decode the keystream: `hq` is only 8 bytes but the payload shows no lag-8
   periodicity, so either the key is expanded or the fields are hashed into it.
   Recovering the key schedule would make offline field diffing possible.
3. Explain the eval sensitivity: wrapping `contentWindow.eval` is the only JS-level
   change that flips the shape. Whatever it detects lives below the JS-visible surface
   (V8 context metadata is the standing hypothesis; §4 rows 6 and 9 rule out the
   obvious ways to observe it).

---

## 9. The bytecode (`NU`) - offline access, and why the "key" is not one

Two facts that make the decompiler work possible without a browser:

**1. The program is recoverable offline.** `arr[0]` in the `mnsUbf` material is
`"Boau" + base64(bytecode) + 45 chars of tail`. The exact slice was confirmed against a
live VM instance (`inst.NU`, 22353 bytes) byte for byte:

```python
raw  = arr[0]                      # 29852 chars
b64  = raw[3:3 + 29804]            # 29804 chars -> 22353 bytes
nu   = base64.b64decode(b64)       # == inst.NU
```

**2. `hq` is per-page-load, and it is NOT the code key (correction).** The interpreter
has a bit reader that can XOR each byte with an 8-byte table `hq`, guarded by a boolean
argument (`F && (...)`):

```js
n = g % 8; u = g >> 3; r = t.NU[u]; r ^= t.hq[u & 7];   // g = bit offset
```

An earlier pair of runs happened to share `hq` (`47 132 201 191 76 4 130 25`), but a
later load produced a different table (`12 142 221 92 168 97 234 221`), so `hq` is
**per page load**. `NU` itself is fixed by the build (it is a slice of `arr[0]`), so the
code stream cannot be XORed with a per-load key: the XOR path is for *data* reads, and
the code path takes the `F == false` branch. Treat raw `NU` as the instruction stream.

The reader is MSB-first: take bit `(byte >> (7 - (bit & 7))) & 1`.

```python
nu = base64.b64decode(arr[0][3:3+29804])   # 22353 bytes, build-fixed
```

`nu` is **not** readable text and not byte-aligned instructions: it is a bit-packed
stream (8/5/3-bit framings all look like noise, and XORing with `hq` changes nothing
structural). The instruction encoding is the actual decompiler work.

### What the array hooks can and cannot see

`Array.prototype.push` / `concat` wrappers stay trust-neutral (token 1423) and reveal
the *field sizes* (§2b), but they cannot reveal field *contents*: every array they
capture is a pre-allocated, uniform buffer (2276 zeros, etc.). The interpreter writes
bytes by index assignment - `L[G++] = e` in its UTF-8 encoder, the same pattern in the
field writers - so the byte stream never passes through an array method that JS can
intercept. Reaching it would need a Proxy on an array created inside the closure, which
is not obtainable.

Next step: log what the reader *returns* during a real run instead of guessing the
framing. The readers are `JY`, `B`, `a`, `R3` in the interpreter; wrapping them in the
frame realm (trust does not matter for this - it is data collection) gives the executed
instruction stream directly, and the state machine's dispatch (`D` / `ZS`, which write
`this.h[field]`) can then be mapped opcode by opcode.

---

## 10. Dispatch tracing (the decompiler's first instrument)

Names, line numbers and script ids all rotate per run, so nothing can be hard-coded -
but a breakpoint can be *discovered*: pause at random, scan the call stack for the
dispatcher (it appears as `cH` on this build), take its `(scriptId, line, column)` from
that very stack, set a breakpoint there, resume. Every later hit is deterministic.

State observed at the dispatcher on 400 consecutive hits:

| arg | value | meaning |
| --- | --- | --- |
| `b` | 230 | the field id holding the bit counter |
| `F` | 2768, 2818, 2846, … 36568, 36592 | current **bit offset** into the program |
| `L` | 178824 | total program bits - exactly `22353 * 8`, i.e. `NU.length << 3` |
| `J` | 29932, 29931, 29930, … | bits remaining (decreases by the instruction width) |
| `Y` | 201 (constant in all 400 hits) | a kind tag, **not** the opcode |

Bit-offset deltas over the trace: 26, 24, 42, 50, 34, 68, 32, 0 (all even, with `0`
repeating ~8 % of the time - several dispatch entries per instruction). Offsets also
jump between regions (2768 → 35212), so the trace covers several functions.

This gives the instruction stream as `(bit offset, remaining bits)` pairs without
knowing the encoding in advance.

### The x2 framing was wrong (retracted)

An earlier note claimed the bit counter was in 2-bit units (`offset * 2`) because the
first 4 bits at those offsets showed a repeating period-6 body. A longer trace refutes it:
`F` reaches 136108, so `F * 2` = 272216 **exceeds the program** (178824 bits), and at the
raw offsets the same 4-bit field is uniform (16 of 16 values in a 65-instruction run, no
loop). The apparent structure at x2 was aliasing on a bit-shifted read.

What actually survives as fact:

* `F` is even-aligned in every hit (deltas 24, 26, 32, 34, 42, 50, 68).
* Raw `F` stays inside the program: 66206 .. 136108 of 178824 bits.
* Instruction-to-instruction distance is 24-68 bits, consistent per opcode value seen so
  far (52/68/136 for one, 52 for another, 84 for a third).
* No 4-bit opcode prefix is visible at raw offsets in either bit order.

Conclusion: the opcode framing cannot be inferred by guessing offsets into `NU`. It has to
be read from the interpreter itself - hook the bit reader and log `(bit offset, value,
width)` for every call. That yields the instruction stream directly, with no framing
assumptions.

### Coverage limit of one breakpoint

Tracing with the `cH` breakpoint armed for a whole mint yields only ~770 dispatch events,
not the ~3700 a 22353-byte program would need at ~6 bytes per instruction. So `cH` is one
of several dispatch entry points - `eT`, `T6`, `tY`, `z` and `k` also appear on the stacks
(the sampler saw 83/61/41/28/14 frames respectively). Within the window `cH` does cover,
the trace is a 6-instruction loop repeated 27 times:

```
op 4 (52 bits)  op 4 (68)  op 4 (136)  op 4 (52)  op 10 (52)  op 12 (84)
```

Arming works progressively: every pause carries its callers, so each hit lets you arm one
more name (`T6`, `tY`, `a3` were picked up that way). But arming by name is the wrong
filter: `a3` and `tY` turned out to be utility functions called in tight loops with
**constant** arguments (`b=34`, `b=65` for all 1500 hits each), and they consumed the whole
3000-hit budget. `cH` remains the only entry point observed so far whose arguments
*change* (`b=230`, `F` walking the bit stream).

So the selection rule is: arm a candidate only if its arguments vary across hits. Next
attempt should arm `cH` first, then test the others against that rule instead of by
frequency on the stack.

### The reader is readable, and the interpreter is hash-checked

On this build the reader survives un-mangling inside the interpreter string:

```js
JY=function(b,F,t,...){ if((M=k(t,230),M)>=t.V) throw[PH,31]; ... r=t.NU[u], ...
R3=function(b){ return b.o?YY(b.D,b):JY(8,true,b) }
```

`JY(bits, flag, vm)` reads `bits` bits starting at the pointer kept in **field 230** and
returns the value, so a logger at its entry would give `(count, start bit)` for every read -
the instruction stream and its operands, with no framing guesswork.

Two things block source instrumentation:

* `arr[2]` is exactly `base64url(sha256(interpreter source))` - verified byte for byte, so
  it is the interpreter's integrity check. Patching the source means recomputing it.
* Recomputing `arr[2]` is **not enough**: with the patched interpreter and a matching hash
  the token collapses to 913 characters and the reader is never entered (0 reads), so a
  second gate rejects it - most likely the VM loading the interpreter by hash from
  `https://www.google.com/js/bg/<hash>` rather than using the eval'd copy.

## 11. Instrumenting the reader (breakthrough)

The interpreter string can be patched: `arr[2]` only has to equal
`base64url(sha256(source))`, so recompute it and the instrumented build is accepted. The
VM bootstraps inside an **iframe**, so the log lives on the iframe's `window`, not the top
one - read it through `document.querySelectorAll('iframe')[0].contentWindow`.

The reader, complete:

```js
JY=function(b,F,t,...){
  if((M=k(t,230),M)>=t.V) throw[PH,31];
  for(q=(E=(J=0,b),g=M,t.FD.length); E>0;)
    n=g%8, u=g>>3, c=8-(n|0), r=t.NU[u], P=c<E?c:E,
    F&&(G=g, L=t, L.R!=G>>6 && (L.R=G>>6, Y=w(L,15),
         L.hq=WH(16,L.R,L.i,[0,0,Y[1],Y[2]],551)), r^=t.hq[u&q]),
    g+=P, J|=(r>>8-(n|0)-(P|0)&(1<<P)-1)<<(E|0)-(P|0), E-=P;
  return D(230,(e=J,t),(M|0)+(b|0)), e }
```

Facts that follow:

* `NU` is **XOR-encrypted at rest**, keystream regenerated per 64-bit block
  (`L.R = G>>6`) from the per-load seed `t.i` via `WH(16, blockIndex, t.i, [0,0,Y[1],Y[2]], 551)`.
  That is why `hq` differs between loads - it is not a build constant at all.
* `F` is the decrypt flag; every read in a real signing run had it set.
* The reader walks the program with a **bit** pointer (field 230), and reads cross byte
  boundaries (a 2-bit read at bit 40 followed by an 8-bit read at bit 42).

Logging at the reader's return gives plaintext. A full signing run produces **13482
reads** (12666 x 8 bits, 812 x 2 bits, 4 x 32 bits) covering **100 %** of the program
(178832 of 178824 bits), all with `F = 1`.

Reassembly note: the sweep is **not** one contiguous pass. The gap histogram is `0` for
13341 of 13481 consecutive reads, but two jumps of 32118 and 59064 bits split it into
three segments, and 17+5 reads step backwards (the 2-bit re-reads). Placing the returned
values by position therefore covers only 103034 of 178824 bits (57.6 %): the two skipped
bands are simply not read on this path, they must be pulled on demand by another accessor
(`R3`/`YY` for field objects). Entropy of the reconstructed 57 % is 4.88 bits/byte versus
7.75 for the ciphertext, and short runs like `divprotectcache_y` come out readable, so the
placement is right where it covers.

## 12. Field writer and the origin of the keystream seed

`D(fieldId, vm, value)` is the only writer, and it is readable:

```js
D=function(b,F,t){
  switch(!(b==230||b==21)){
    case !null:                                   // b != 230 && b != 21
      if(F.fe && b!=15) return;
      b==146||b==277||b==261||b==473||b==311||b==444||b==323||b==495||b==474||b==117
        ? F.h[b] || (F.h[b] = R(7,0,t,F,142,b))
        : F.h[b] = R(21,0,t,F,97,b);
      break;
    case ![]:                                     // b == 230 || b == 21
      F.h[b] ? F.h[b].concat(t) : F.h[b] = R(26,F,t);
  }
  b==15 && (F.i = JY(32,false,F), F.R = void 0)
}
```

So the keystream seed `t.i` is simply **32 bits stored in the program itself**, read with
`JY(32, false, vm)` - decryption off. Field 230 is the bit pointer, 21 concatenates, and
ten specific ids (146, 277, 261, 473, 311, 444, 323, 495, 474, 117) use `R(7, ...)` while
every other field uses `R(21, ...)`.

That also explains the read gaps: fields are created lazily by `R` and only pulled from the
program when dereferenced (`z` -> `.value` -> `w` -> `.create()`), so the two skipped bands
are read by that lazy path rather than by `JY` during the initial sweep.

**Retracted in section 14** - `create()` never touches the program, and the reader is the only
reader. Keep the writer description above, drop the explanation at the end.

## 13. Keystream capture does not give offline decryption (negative result)

The keystream is observable: logging `L.hq` right after it is regenerated gives eight bytes
per block, with a constant per-load seed (`t.i = -1154219265` in one run) and
`Y[1] = Y[2] = 0`:

```
block 0: 160  74 159 168  38 213  68 165
block 1:  35 175  96  20 202 198  77  59
block 2: 135  47 140 239 247 171 224  57
```

Trying to decrypt `NU` offline with those blocks (`byte u ^= ks[u>>3][u & 7]`) **fails**:
only 343 of 2795 blocks were regenerated in that run (12.3 % of the program), and the
resulting bytes are noise (entropy 7.94). So the captured keystream is not directly
indexable as "byte u uses ks[u >> 3][u & 7]", and re-implementing `WH` is not an option
either - the `sh` helper it calls is a different function in this build (the name is
reused by a DOM helper), so the source cannot be lifted as-is.

Consequence: the reliable artifact is the **logged return values** of `JY` (true plaintext,
no keystream needed), not an offline decryptor. The gaps have to be filled by instrumenting
the lazy field path (`R`/`T` -> `.create()`), not by keystream math.

Next: decode the operands of a few opcodes and check them against the trace (e.g. op 12's
10-byte operand should be a constant or a field reference), then map opcodes to the
handlers seen on the stack (`cH` -> `eT` -> `z`/`k`).

## 14. Corrections: the lazy field path does not read the program

Two claims in sections 12 and 13 are wrong, and everything below depends on the fix.

**1. There is exactly one program read site in the interpreter.** Counting
`<program>[` occurrences in two builds:

```
/tmp/interp_orig.js  (FhxsKBPKEL3Q_, 66505 chars)  .NU[ -> 1 hit, at offset 43743
/tmp/interp_page.js  (EONwmJdvD0_,  66684 chars)  .x9[ -> 1 hit, at offset 34489
```

Both are the `r = t.NU[u]` / `V = d.x9[S]` inside the reader. Nothing else in the 66 KB of
interpreter code indexes the program, so no other accessor can pull a byte out of it. The
two skipped bands of section 11 are simply **not consumed by that run**; they are not read
"by the lazy path".

**2. `create()` is a counter-based byte factory, not a program accessor.** The `create` the
field objects install (Fhxs build, verbatim):

```js
P[J.T] = function(n){ G=(c=(G+=6+7*Y,n), 7+2*(G&-8)-2*(G^7)) + (~G&7) }
```

`G`, `c`, `Y` are closure state; the string `NU` never appears in the body. So
`R(...) -> .create()` cannot fill anything: it manufactures numbers out of a small PRNG.
The earlier explanation of the gaps is withdrawn.

Consequence: coverage can only be raised by making the reader *regenerate more blocks*, not
by finding a second reader.

## 15. Builds rotate per load, and so does everything inside the interpreter

Four page loads in about 40 minutes produced three different interpreter hashes, and the same
hash kept arriving with different program blobs:

| interpreter hash | interp len | blob len observed |
| --- | --- | --- |
| `FhxsKBPKEL3Q_7SAGqK2qCBSmJCvn03PW-hnc3EmGb4` | 66505 | 29492 … 30183 |
| `EONwmJdvD0_rTF3DwpNQuYvLZBRpy3uP7JNRMBuZCNs` | 66684 | 29638 … 30035 |
| `TsNWy9jFir5dhpfrFwzH2KnV5fIUrB_LPmNheeH61GY` | 66517 | 29892 |

Because the blob length moves on every load, **the program differs per load**: two dumps can
only be compared inside one page load. Mixing a blob from one load with an interpreter from
another still parses (the interpreter is integrity-checked against itself, `arr[2] ==
base64url(sha256(arr[5][-1]))`, verified again here) but the assembled inner program then
fails with `FNLSyntaxError: Unexpected token …` and the VM returns that as the token - the
"wrong build pair" signature.

Everything else rotates too, which is why every earlier note that hard-coded a name broke on
the next build:

| role | Fhxs build | EONwm build |
| --- | --- | --- |
| reader | `JY(bits, flag, vm)` | `xG(flag, bits, vm)` |
| program field | `NU` | `x9` |
| program length (bits) | `V` | `U` |
| bit pointer field | 230 | 339 |
| seed field | 15 | 43 |
| block keystream cache | `R` | `v` |
| mask table | `FD` | `TU` |
| keystream mixer | `WH` | `W9` |

The reader's **parameter order changes between builds**, which is the trap that produced a
dump of 22 340 bytes of `00`/`01` at first: called as `JY(8, true, vm)` on a build whose
signature is `(flag, bits, vm)`, the reader read *one bit* per call and the 8-bit stride
walked the program eight times too fast. `research/bgpatch.py` now reads the roles out of the
body: the parameter the keystream guard `<name>&&(` tests is the flag, the other of the first
two is the bit count.

One more page-level gate: the document enforces **Trusted Types** for string evaluation, so
the interpreter can be `eval`-ed exactly once per page. A second `(0, eval)(src)` of the same
string is refused with `EvalError: Evaluating a string as JavaScript violates this
document's Trusted Type assignment requirements` - which looks like "the VM stopped working"
if you do not print the error. All patching has to happen in the *first* eval of a page.

## 16. Recovering the program: read each block when its keystream is fresh

The reader XORs every byte with an 8-byte table that is regenerated whenever the bit pointer
enters a new 64-bit block:

```js
L.R != G>>6 && (L.R = G>>6, Y = w(L,15), L.hq = WH(16, L.R, L.i, [0,0,Y[1],Y[2]], 551))
```

`w(L,15)` pulls from the seed field's factory, i.e. the table is produced by a **stateful
PRNG**: the key for block *k* depends on how many blocks were regenerated before it, not on
*k* alone. Two facts follow, and both are measured:

* a blind ascending sweep of the whole program decrypts only the first stretch correctly
  (section 17);
* right after a regeneration, that block's 8-byte table is valid for **all eight bytes** of
  the block, not just the bit the program asked for.

So the instrument reads the whole block at that moment. In the reader's return path, after
the block cache changed, it walks the eight byte-aligned offsets of the block with a forced
bit pointer; the pointer store that immediately follows puts the VM's own pointer back, which
is why the run keeps working long enough to finish the sweep.

Measured with `research/dump_program.py` (block-capture mode). Two mints of the *same* program
in one page load, with the real `f_req` payload:

```
token 1041 / 1041, V 177696 bits, nu 22212 bytes
instance 1: 351 blocks, 2808 bytes
instance 2: 351 blocks, 2808 bytes
overlap 2808 bytes, identical 2808 (1.0), differing offsets: none
```

and with a short synthetic payload, where the program flow is longer:

```
token 3229 / 3229, V 178336 bits, nu 22292 bytes
instance 1: 1342 blocks, 10736 bytes
instance 2: 1342 blocks, 10736 bytes
overlap 10736 bytes, identical 10736 (1.0)
```

So the capture is reproducible and non-destructive enough that both instances complete a
normal mint. Coverage per run is the blocks that run regenerates - 351 of 2777 blocks with the
real payload (12.6 %), 1342 of 2787 with the synthetic one (48.2 %) - which is the number that
matters: the instrument turns "one byte asked for per block" into "all eight bytes of every
visited block", it does not create blocks the run never enters.

Single-instance runs validated against their own log:

```
blocks 2762, bytes known 22091/22091 (1.0), validation match 2761 mismatch 0 skipped 1
blocks 2793, bytes known 22340/22340 (1.0), validation match 2792 mismatch 0 skipped 1
```

Both of those ended in the VM's error regime (token length 48) and walked *every* block, which
is what the forced reads do to a run: pushing the pointer to block boundaries turns the program
into a sequential scan. The values are still right (the reads match), but do not read those two
rows as "a normal run covers 100 %" - a normal run is the 351/1342-block picture above.

"validation" bit-slices the recovered buffer at every position the run's own log recorded and
compares with the value the VM returned there; the single skipped read is the 32-bit seed fetch,
which the VM takes with the decrypt flag off and the buffer holds decrypted.

Reproduce:

```
python3 research/dump_program.py --port 10220 --out /tmp/bg-dump
```

The payload fixture can be dropped at `research/freq.txt`; without it a tiny synthetic payload
is used, which only changes how much of the program the run executes.

## 17. A forced sweep cannot decrypt unvisited blocks (measured)

Same tooling, `--sweep`: mint once naturally (passive log only), then force the reader over
every 8-bit offset in ascending order on the next mint and compare.

```
sweep coverage: 22192 / 22192 bytes
validation: match 523  mismatch 5164  skipped_plaintext 4
first mismatch: start=2752 bits=8 logged=87 recovered=150
```

Divergence starts at bit 2752 = block 43 and never recovers: the sweep regenerates blocks
0,1,2,… in order, while the run regenerates a different sequence, so from the first block the
run skipped, the PRNG has advanced by a different number of steps and every later table is
wrong. An earlier run of the same experiment diverged at bit 2784 (block 43) - the boundary
is stable, the numbers are not.

This closes the offline-decryption question for good: the keystream is not a function of the
block index alone, so no reordering of reads can reconstruct keys for blocks the VM never
visited. Section 13's conclusion stands, with a better reason.

## 18. How much does a run actually touch?

`--log-only` (passive log, no block capture), one run:

```
reads=20174  blocks touched=2201/2778 (79.2 %)   token 1224 chars
```

So at 64-bit-block granularity a single degraded-length run visits about four fifths of the
program with the real payload; the 57.6 % figure in section 11 was measured in *bits* placed
by the log, which is a stricter and less useful number. That block coverage is what section
16's per-block read multiplies by eight: it cannot hand back the fifth a run never enters -
only a perturbed run walks every block (section 16's 100 % rows), and a perturbed run is not
the run you wanted to measure.

## 19. What the recovered program looks like

`program_blocks.bin` from section 16 (22 340 bytes, EONwm build): entropy **7.99 bits/byte**,
256 distinct byte values, 38.2 % printable bytes, longest printable run 9 characters, no
`divprotectcache`/`google`/`Boa` strings. So in this build the plaintext program is
**obfuscated byte data, not assembler-like text** - the readable fragments seen in the 57.6 %
reconstruction came from the Fhxs build, whose program layout differs.

That changes the next step: decoding this build means finding the record structure inside a
high-entropy blob (the 8-bit reads the program itself makes are the only hint at framing),
not reading opcodes out of a printable stream. The instruments that are now in place:

* `research/bgpatch.py` - structural, build-agnostic patcher (entry log, return log, block
  capture, forced sweep; per-hunk toggles for bisection).
* `research/dump_program.py` - one-shot runner: same-build-pair material, Trusted-Types-safe
  single eval, capture, validation, artifact dump. `--log-only`, `--sweep`, `--ab` are the
  three controls used above.

Next: dump two runs *within one page load* (the VM is reusable, section 8) and diff them -
differences isolate the input-dependent fields from the fixed program skeleton, which is the
mapping the serializer needs.

## 20. The field table, logged

`research/bgpatch.py` grew a `writes` hunk: it patches **every copy of the field writer** and
records `[fieldId, len(value), JSON(value)]` for each write, skipping only the bit-pointer and
concat sinks (every read stores the pointer, so those two ids would drown everything else).

The writer is recognised by its switch on the pointer and concat ids, not by name - a single
build ships **three** copies of it, and they do not even agree on the argument order:

```
switch(!(F==230||F==21))  inside K(b,F,t)    <- field id in the *second* param
switch(!(b==230||b==21))  inside D(b,F,t)
switch(!(b==230||b==21))  inside ZS(b,F,t)   <- the one the boot calls
```

Anchoring on the parameter name, or patching only `D`, silently loses most writes.

Measured, one page load, two mints with payloads that differ by one character
(`"hello"` vs `"helloB"`, both tokens 1100 chars, `NU` 22 347 bytes):

```
field writes: A=706  B=706
positions differing: 5
  473  4B  A [72,60,133,195]     B [46,32,236,84]
  474  4B  A [136,68,95,133]     B [31,231,27,193]
  277  4B  A [135,229,23,59]     B [104,127,164,83]
   86  0B  A 1793164444493       B 1793164445475        <- wall clock, ms
  201  4B  A ["hello",null,null,null]   B ["helloB",null,null,null]
distinct field ids written: 137
```

So the *content* binding is a single field: 201, which receives the payload string as its
first element. 473/474/277 change on every sign (four bytes each) and 86 is the clock; the
other 700-odd writes are identical across the two runs. That is the shape the serializer needs:
a fixed skeleton plus a handful of per-sign fields.

What the ids carry is not only numbers. A sample of the table from the same run:

```
  0   "0,function(y,p,X,C,H){D((H=k(y,(p=a((X=B(y,8),2..."   handler source, 76 B
 35   "var eval=\"kdggzrisih\";eval"                        the realm's global name
 46   ",A,AJ,Aq,BY,Bc,C,Cc,D,E5,F,FD,G,IA,Il,J,Jq,K,Ke..."     208 B property list
 18 "contentWindow"   20 "parent"   22 "appendChild"   26 "length"
 39 "createElement"   55 "prototype"  57 "Array"       63 "document"
 15   [0,0,0] then [1475166842,-778591371,-334337046,null]    seed words
117   [2048]          146 [184,0,0]      201 {} then ["hello",null,null,null]
```

Two notes on reading this table:

* `len(value)` is `value.length`, so objects and numbers show 0; the JSON column is the payload.
  Values that stringify to `undefined` (functions, `undefined`) come back as `null` - the
  logger is lossy there on purpose, a JSON round trip through CDP is the constraint.
* Field 15 is written twice: once at boot with `[0,0,0]`, then with four 32-bit words. The last
  two are what the keystream mixer consumes (`[0,0,Y[1],Y[2]]` in section 11) - so the
  "Y[1] = Y[2] = 0" observation in section 13 was one run's luck, not a property.

Reproduce:

```
python3 research/dump_program.py --fields --port 10240 --out /tmp/bg-fields
```

Next: turn the write log into the token layout - write order plus sizes against the 1100-byte
token, then check the three per-sign fields against the bytes that move between two mints of the
same payload.

### Same payload twice: three random fields and a clock

Same tool, `--fields --same` (both mints get the identical payload):

```
writes 700 / 700, tokens 896 / 896
differing positions: 4
  473  4B  [40,27,34,165]   | [93,184,23,108]
  474  4B  [56,225,40,39]   | [68,93,236,101]
  277  4B  [224,86,249,246] | [98,160,204,84]
   10  0B  1793164558231    | 1793164559103     <- clock, ms
```

With the payload varying the same four moved plus field 201, so the decomposition is exact:

| class | fields | behaviour |
| --- | --- | --- |
| fixed skeleton | the other ~133 ids | byte-identical in every run of the same build |
| per-sign randomness | 473, 474, 277 | four fresh bytes each, independent of the payload |
| clock | 86 in one build, 10 in the next | ms since epoch, so the id rotates with the build |
| content | 201 | carries the payload string |

That is what "generate the signature for an arbitrary input" reduces to: reproduce the skeleton,
fill three random 4-byte fields, stamp the clock, put the payload in 201, and run the serializer.

Reproduce:

```
python3 research/dump_program.py --fields --same --port 10242 --out /tmp/bg-fields-same
```

### Mutating the program, and where the writer anchor still fails

`--fields --mutate N` flips plaintext program byte N just before the second mint (the program
array is decrypted per read, so flipping the stored byte flips what the reader returns). Two
attempts at byte 300 produced no difference beyond the usual noise:

```
tokA/tokB/tokC 812 812 812     diffs vs baseline: 456, 36 (random), 56 (clock)
tokA/tokB/tokC 871 871 871     (no write log at all - see below)
```

So either that byte is not consumed by this run (coverage is a fraction of the program, section
18) or the class of change is invisible at field granularity. A useful version of this
experiment has to sweep offsets inside the blocks the run actually visits, not a single guess.

The bigger problem it exposed: `--fields` sometimes comes back with a full reader log and an
empty write log in the same run:

```
realm states: [.. {wr:0, rd:37789, jy:function} ..]     token 1311 chars
```

The reader instrumentation fired 37 789 times and a token came out, so fields were written - by
a writer copy the hunk did not patch. The anchor (the `switch(!(p==<ptr>||p==<cat>))`) matches
two or three copies per build, and at least one live writer must take a different shape (section
4 already saw `ax`/`qj` called directly). Until that anchor is found, treat `--fields` as
"works on some builds": when `wrA` is empty, reload and retry rather than trusting an empty
diff.


### Build dependence of the random fields

The same experiment on the EONwm build gives **two** random four-byte fields, not three:

```
field writes: A=516  B=516          (same payload twice)
positions differing: 3
  456  4B  [183,210,202,52] | [236,153,252,49]
   36  4B  [89,131,244,38]  | [97,163,51,239]
   21  0B  1793166465419    | 1793166466652     <- clock
```

So the class breakdown holds (skeleton / random / clock / content) but the *count* of random
fields and every id in it is per build: 473+474+277 with the clock at 86 in Fhxs, 456+36 with
the clock at 21 in EONwm. Anything that hard-codes an id will work for one build and silently
do the wrong thing on the next.

Two robustness fixes landed with these runs: the boot anchor now accepts `length<<3` or
`length*8` and a nested `atob(...)` call (one build - `TsNWy9jFi…`, interp 66517 - did not match
the old pattern at all), and `--fields` retries the mint up to three times when the write log
comes back empty.


## 21. Shipping-path availability, re-checked

The research instruments above are not the product; this is what the shipped path measured.

In-process signer (`bgr_sidecar.LocalSigner`, the `gt_server` embed):

```
signer ready in 11.6s
mint 1: token_len=1432  build=FhxsKBPKEL3Q_  in 4.6s
mint 2: token_len=1425  build=FhxsKBPKEL3Q_  in 2.8s
mint 3: token_len=1408  build=FhxsKBPKEL3Q_  in 2.7s
mint 4: token_len=1405  build=FhxsKBPKEL3Q_  in 1.3s
mint 5: token_len=1439  build=EONwmJdvD0_    in 7.5s
mint 6: token_len=1447  build=EONwmJdvD0_    in 3.1s
mint 7: token_len=1428  build=EONwmJdvD0_    in 5.6s
trusted-range: 7/7
```

End to end through `ImageTranslator`, twice on the same image:

```
1: found_text=True detected=en in 3.6s
   text='Backup job failed on node db-07 ...'
   translation='节点 db-07 上的备份作业失败 ...'
2: found_text=True detected=en in 2.9s   (same text/translation)
```

Both HTTP surfaces as well (`python3 bgr_sidecar.py --port …`):

```
GET  /health  -> {"ok": true, "build": "FhxsKBPKEL3Q_…", "age_s": 23.8, "ua": "…"}
POST /sign    -> token_len 1423, build Fhxs…, sid yes, bl yes
```

and the refresh path that matters when the build rotates under a running page - four mints with a
forced `/refresh` between each:

```
before refresh:   1429   after #1: 1425   after #2: 1416   after #3: 1439     (build EONwm…)
```

Conclusion: the shipped path is healthy across both build pairs and survives refreshes; mint
latency is 1.3-8.5 s, one image translation 3-4 s. **The instrument flakiness described in the
research sections does not touch it**: the sidecar evaluates Google's pristine interpreter, so the
"which writer copy / which realm" problem cannot arise there.

## 22. Which writer copy is live: all of them (probe), and one open flakiness

`--writers` gives every writer copy a self-identifying abort (`(window.__kill===k)&&(function(){throw 0})()`)
and mints once per k, so the live copy is visible from the token length alone - no cross-realm
state involved.

```
build FhxsKBPKEL3Q_, 3 writer copies, 5 realms visible
        control: token_len=1169  ';6Pa49qzQAAYLd2XrK3df…'
    kill copy 0: token_len=21    'E:undefined:undefined'
    kill copy 1: token_len=21    'E:undefined:undefined'
    kill copy 2: token_len=21    'E:undefined:undefined'
  control after: token_len=1169  ';Fgi4CFLQAAYLd2XrK3df…'
```

Every copy fires during a normal run, and the run recovers afterwards (the "control after" mint is
normal), so the empty write logs were **not** an anchor-coverage problem: at least one live copy is
always patched.

What is still unexplained: on some page loads the patched copy installs (a marker appended to the
source proves the eval ran, `window.__MINE`) and produces tokens, yet none of its instrumentation
fires - no reader hits, no field writes, no boot state, in any realm we can enumerate, and no
`/js/bg/` request is made either (Fetch served zero). The same build, one load later, is fully
instrumented. The symptom is recorded here rather than guessed at: `--fields` reports
`stage: not-mine` when the eval did not take, and an empty log otherwise, and the runner retries
three times.

Practical rule for the research line: **one page load, one attempt, retry the load** - do not trust
an empty capture, and never compare two dumps that came from different loads (the program itself
is per-load, section 15).

## 23. Early injection: installed and called, still not instrumented

The load-time race hypothesis was: the page's own bootguard claims `ridgeslice` first, so the
eval-ed copy is installed but never executed. The fix tried was `Page.addScriptToEvaluateOnNewDocument`
with the patched source, so it runs at document start, plus:

* the name is cleared first (`window.ridgeslice = void 0`) so the interpreter builds a **fresh**
  object instead of reusing the page's (which would skip `a = R` because `m > 40`);
* the object is kept under a private name (`__MINEV`) because whoever writes the global last wins,
  and the page gets more chances to write it than we do;
* `__MINE` at the end of the source proves the text ran;
* two consecutive loads must agree on the unpatched interpreter hash, because the build rotates
  per load (`--early` reloads until it does).

Measured (Fhxs build, 3 writer copies, 5 realms visible):

```
attempt 1: injected patched interpreter for build FhxsKBPKEL3Q_7SA, reloading
attempt 2: build FhxsKBPKEL3Q_7SA matches the injected copy
vmDiag: {booted: 0, vmeta: 0, rd: 0, wr: 0, prog: 0, isGlobal: 0, aCalls: 2, aVals: 2, aLen: 112}
tokA: 763   tokB: 611   nu: 0
field writes: A=0  B=0
```

`aCalls: 2` is the decisive line: the VM entry we call *is* the one from our object (called twice,
one per mint, both returning values), and the object is ours (`__MINE`), yet the patched boot site
never executes (`__booted` stays 0), no reader hit is recorded and no field write lands.

So the failure is not a load-order race at all. **The code that boots the instance is not the text
we patched, even though the entry point we call is.** In these builds the visible interpreter text
contains the inner program as a string (`.join('\n')` then compiled), and patching inside that
string is silent: injecting an invalid token there leaves `node --check` happy because it is string
content. The next experiment is therefore precise: patch the string element that carries the boot
site, verify with `__booted`, and only then claim the inner pipeline is instrumented.

Until then: `--fields` without `--early` still works on some loads (sections 20 and 22), `--early`
does not work, and the corpus run over several payload lengths is on hold because the capture has
to be stable first.

## 24. Step 1 resolved far enough to name the real problem: the frame realm is unreachable

Three probes were added to answer "is the code we call the code we patched":

1. **Entry canary** - `d.a = NAME` names the VM entry; every definition of `NAME` gets
   `window.__REntry++`. A build defines that name more than once (2-4 times), so all of them are
   instrumented.
2. **Compile hooks** - `Function` and `eval` are wrapped at document start, recording
   `[length, indexOf('__MINE')]` for every compiled string.
3. **Top-window sink** - all instrumentation state written to `(window.top||window)` instead of
   the local `window`.

Measured (Fhxs, injected early, two mints):

```
vmDiag: {entry: 2, comp: [], evs: [], booted: 0, topRd: 0, topWr: 0, aCalls: 2, aVals: 2,
         isGlobal: 0, aLen: 112}
tokA: 768   tokB: 616
```

Reading it:

* `entry: 2` and `aCalls: 2` - the entry point we call **is** the patched text, and it ran twice.
* `comp: []`, `evs: []` - **no** string was compiled in that realm. So the inner program is
  compiled in another realm, which is also why the reader/boot patches inside our own text never
  fire there: that text is only the outer scaffolding in this realm.
* `topRd: 0` with the top sink, and every instrumented run lands at 600-1300 characters instead of
  the 1405-1447 trusted range - with the top sink the instrumentation does not survive at all,
  which is what a cross-origin frame writing to `window.top.__rd` would do (the access throws).

So the real blocker is not injection order, not the anchor set, and not the writer copies: **the
frame realm that does the work cannot be reached from the page**, and its own `window` state dies
with it before the caller looks.

Concrete next step, no longer speculative: stop reading state *out* of that realm and let it push
itself out with `window.parent.postMessage(...)`, which works across origins, called from inside
the reader/writer hooks (batched, e.g. every N entries plus once at the end of the mint). Keep
`sink=window` for the state, add the message bridge, and the page assembles the log itself.

Until that exists, the rule from section 22 stands: `--fields` with `sink=window` works on some
loads (sections 20/22), `--early` with the top sink does not, and the payload-corpus and mutation
sweep items stay blocked behind a stable capture.

## 25. A fourth build family, and the instruments that finally read it

The build rotated again (`pBmIPB2A48cBn4jKyOYwFBBd99dEifKv9scgd1q6IH4`, interpreter 66398) and
every anchor in `research/bgpatch.py` failed on it: the reader entry lost its extra parentheses
and the parameter order changed for the third time. Everything below was measured after making
the patcher role-based instead of position-based.

### Roles are stable, positions are not (four builds)

| role | Fhxs `KBPKEL3Q_` | EON `wmJdvD0_` | pBm `IPB2A48c` |
| --- | --- | --- | --- |
| reader | `JY(bits, flag, vm)` | `xG(flag, bits, vm)` | `RE(vm, flag, bits)` |
| program field | `NU` | `x9` | `cF` |
| program length (bits) | `V` | `U` | `j` |
| bit-pointer field | 230 | 339 | 44 |
| concat sink field | 21 | 328 | 71 |
| seed field | 15 | 43 | 335 |
| block keystream cache | `R` | `v` | `U` |
| writer copies | 3 | 2 | 2 |

The patcher now derives each of these structurally: the entry check gives the pointer field and
the vm, the keystream guard `<x>&&(` gives the flag, the loop seed (`I=(b=0,BITS)` or
`v=BITS`) gives the bit count, and the reader call is rebuilt as `(vm, flag, bits)` in whatever
order that build declares. Reader returns are split on top-level commas instead of matched by
pattern (`return CALL, VALUE}` holds, but the call's shape does not).

### The value encoding, finally measured

The interpreter reads the program through a thin wrapper. Its 8-bit branch is:

```js
L = ((L = JY(8,true,q), L & 128) && (L ^= 128, Z = JY(2,true,q), L = (L << 2) + (Z|0)), L)
```

so one 8-bit read is a value 0..127, and a byte with bit 7 set is followed by one 2-bit read that
completes a 9-bit value `((b & 0x7f) << 2) | t` (0..511). Checked on a full run:

```
reads 13786   widths {8: 12739, 2: 1042, 32: 5}   flag-off reads 5 (all 32-bit)
2-bit reads preceded by an adjacent 8-bit read >= 128: 1042    violations: 0
identity  -2*~(J&t)-3-(~J^t) == (J<<2)|t   mismatches over all 128x4 inputs: 0
```

That kills the "2-bit opcode" reading for good: a 2-bit read is never a field of its own, it is
the low half of an extended value. The other wrapper (`R3(vm)` / `Ww(vm)` / `A9(vm)` depending
on build) reads a plain byte with **no** escape - 4277 of the 8-bit reads in that run returned
>= 128 and had no follow-up, so those came through this path. It is used for the 7-bit varint
(`J & 128 && (J = J & 127 | R3(t) << b)`).

### The program is consumed as one linear token stream

`--log-only` with the real `f_req` payload, twice, on two builds:

```
Fhxs: reads 13786  blocks touched 1396/2798 (49.9 %)   token 1057
pBm : reads 20801  blocks touched 2255/2791 (80.8 %)   token  961
step histogram (start - previous end): {0: 13646, -10: 19, -8: 2, <5 large jumps}
```

So the reads are contiguous bit by bit - the interpreter walks the program as a stream, it does
not jump around like a bytecode PC. The 19 negative steps are the 2-bit re-reads of the escape
pair, and the handful of large steps are the region transitions already noted in section 11.

### Correction: the block-capture read log is not a trace

Section 16's block capture forces a read of all eight byte offsets of a block whenever its
keystream is regenerated. Measured consequence: in that mode the logged reads come out at
multiples of 64 bits with a 56-bit stride, i.e. exactly the block boundaries - the pointer the
capture leaves behind drags the VM's own position. Numbers from one such run:

```
blocks 522, bytes known 4176/22303 (18.7 %), reads 523, step histogram {56: 390, 62: 130}
```

Compare with the 13646/13785 contiguous steps above. **Use `--log-only` for traces and
block-capture mode only for program bytes**; the two must not be mixed.

Two further defects in that mode were found and fixed, both of which had been making the
"validation" number look like proof:

* the forced reads leaked into the log (the guard tested `__fp`, and the capture recurses through
  the reader's own return hook, whose nested call clears `__fp`): one run logged 54 296 reads, all
  of them at multiples of 64, and "validated" them against the buffer they had just produced.
  The guard is now an explicit `__lock`.
* `validate()` compared reads placed over *uncaptured* bytes, which are zero in the buffer. It
  now takes the capture mask and counts those as `uncovered_reads` instead of matches.

After both fixes, one block-capture run reports:

```
blocks 300, bytes known 2400/22455 (10.7 %), reads 300,
validation: match 300  mismatch 0  uncovered_reads 0  malformed 0
```

One natural read per captured block and nothing else - the mode is honest now, and the
perturbation it causes (a run that walks the whole program ends in the error regime, section 16)
is unchanged.

### Why `--fields` used to come back empty: it was breaking the VM, not missing it

This is the concrete explanation for the "patched copy installs, produces tokens, logs nothing"
symptom in sections 22 and 24, at least on the pBm and EON builds:

The writer ships **two or three copies with different parameter orders** - `FP(vm, id, value)`
and `e(id, vm, value)` in the same build - and the write hook logged on `arguments[1]`
unconditionally. On the `(vm, id, value)` copy that is the *field id*, i.e. a number, so
`id.__wr = id.__wr || []` silently did nothing and `id.__wr.push(...)` threw `TypeError` inside
a live writer. The first field write killed the patched VM, and the page's own copy (kept in a
closure, not in `window`) served the mint - a normal-looking token, zero instrumentation.

Fix: the vm is now the parameter the field table is indexed through (`VM.l[id]`, `VM.b[id]`,
`VM.G[R]` depending on build). Measured after the fix, same tool, three builds:

```
Fhxs: 698 field writes, 134 distinct ids
EON : 517 / 520 writes, 88 / 90 distinct ids   (two loads)
```

`--fields` also had a latent `TypeError: not enough arguments for format string` (six `%s` in
the script, five supplied) that made the whole mode crash as soon as `--early` was added; fixed.

### Logs live on the VM instance now

The read log used to go to `window` and the write log to the instance. In a run where the text is
evaluated in more than one realm that split the two logs across objects, and the write record's
"how many reads had completed" field came back as `0` for a whole mint. Both logs are now written
to the instance (`vm.__rd`, `vm.__rv`, `vm.__wr`), which is the only object the collector can
reach through `__vmref` anyway. Alignment after the change, one run:

```
writes 516  reads 4823  read-index range 0..4809  monotone: True
```

### What the aligned records say so far (and one negative)

`research/read_records.py` folds the read log into tokens (escape-aware) and prints the token
range that each field write consumed, so a write can be read as "these program words produced
this field". Example, EON build:

```
#75 fid=44 size=0 value="riwmjyadvy"
    107 7 18 21 2 7 18 21 117 7 18 21 95 7 18 21 111 ...     77 tokens
#80 fid=23 size=0 value="function(N,Q,h,t,P){E(N,(t=(Q=G((h=K(N,..."   7 tokens
#83 fid=101 size=0 value="0,function(N,Q,h,t,P){E(N,..."               3 tokens
```

Two things follow, and the first one is a negative:

* **a write's read range is not a record.** The field id sits at a different token offset in
  every record (most often 2, then 1, 3, 4, 6, 0, 5, 7 ...), so "one record per field write" is
  wrong and the grammar cannot be read off the write boundaries alone.
* **long strings are assembled, not stored.** A 100+ character handler source costs 3-7 tokens,
  while a 10-character random realm name costs 77. So the program computes strings (concatenation
  plus a per-run random base) instead of carrying them as literals, which is consistent with
  section 20's field table: the readable strings there were field *values*, not program bytes.

Next, in order: (1) put the read counter on the reader's *entry* as well, so a write can be
pinned to the exact reads inside its range rather than to a boundary; (2) split the token stream
at the operand boundaries the wrapper implies (an 8-bit value, an extended 9-bit value, a seed),
which gives a typed stream without needing the dispatch table; (3) only then look for the
dispatch - the `cH`-style tracing of section 10 is the fallback if the stream turns out to be
interpreted out of order after all.

## 26. The frame's program is readable and patchable, and the loop gives instruction boundaries

Section 24 stopped at "the frame realm is unreachable". Two instruments close that: the debugger
reads the compiled program, and one injection into it yields one log entry per executed
instruction.

### The compiled program, straight from the debugger

`Debugger.enable` before navigation, then a pristine mint (no patch at all, token 1433 chars in
the trusted range), then `Debugger.getScriptSource` for every script over 4 KB:

```
compiled scripts: 292
  script 21: 66505 chars  ctx 1  url ''            <- the interpreter text we get from the page
  script 37: 63772 chars  ctx 2  url ''            <- the program, in the frame realm
      anchors: z(230 x1   NU[ x1   sourceMappingURL x1
  script 20: 166862 chars ctx 1  url ''   (another copy, page realm)
```

Script 37 is the thing that actually runs: it contains the reader `JY`, the writer `D`, the
dispatcher `T6` (`switch(!(G==NQ)){... G==E4 ... G==az`), and the instruction loop `eT`. It is the
big string chunk of the page's interpreter text joined with the wrapper chunks
(`'(function(){/*'`, the licence comment, the closing `}\');'`) plus a prefix of random newlines
(`Array(Math.random()*7824|0).join('\n')`), which is why its length never matches the chunk.

New mode: `python3 research/dump_program.py --frame-scripts --port 10270 --out /tmp/bg-scripts`.
Script ids and offsets rotate per load, so nothing may be hard-coded - search the dumped source.

### The inner text is patchable, once two patcher bugs are out of the way

Instrumenting `eT` inside that text works. The first attempts died with the VM's own
`FNLSyntaxError`, and both causes are worth recording:

* **the loop hunk must run last.** It inserts text in the middle of the source, and the reader /
  writer / boot hunks locate their spans *before* that happens (`r["start"]` from an earlier
  `find_reader` call), so a stale offset slices the wrong span and the replacement is garbage.
  Each hunk alone produced valid text; only the combination broke, which is what pointed at
  ordering rather than at the injection itself.
* **the injected expression needs the surrounding shape.** The fetch appears as
  `if(A=f(PTR,V),A>=L)` on one build and `if((A=f(PTR,V),A)>=L)` on another; only
  `,(expr)` with no trailing paren (i.e. `,((VM.__ip=VM.__ip||[]).push(A))`) is valid in both. A
  stray paren is compiled at runtime and comes back as the token `FNLSyntaxError: ...`.

The `loop` hunk logs the fetched pointer once per iteration; the pointer field is 230 / 339 / 44
depending on the build, and the fetch site is found as `NAME=GETTER(PTR,VM)` preceded by a
`--STEP;` loop counter, not by name.

Measured, one run per build (log-only, real payload, loop hunk on):

```
reads 10896  instructions 1084  distinct pointers 646   (Fhxs, token 1045)
reads  5242  instructions  993  distinct pointers 560   (pBm,  token  ~900)
reads 15815  instructions  938  distinct pointers 513   (EON,  token  848, 517 field writes)
```

Fewer distinct pointers than instructions is the program looping, which is expected; the pointer
sequence is not monotone and that is a fact about the program, not noise.

### Segmenting the read stream by those boundaries

Instruction `k` owns the reads between boundary `k` and `k+1` (map the boundary into the read log
chronologically, so loops and repeats resolve correctly). Token arity over 1071 boundaries:

```
tokens per instruction: 3 x319, 1 x230, 4 x187, 5 x92, 6 x67, 8 x60, 2 x58, 7 x25, 9 x7, 11 x4
```

and per leading token, the arity is often fixed:

```
leading token  n    arity         leading token  n    arity
          418  58   2 (58/58)              96  25   4 (25/25)
          412  58   4 (58/58)             121  21   3 (21/21)
           82  29   3 (29/29)              18  49   4 (47/49)
           89 125   3 (124/125)           48  74   3 (73/74)
```

while others vary in a way that looks data-carrying (`288`: 5 or 8, `104`: 4 or 5, `28`: 5 or 6)
- a bytecode with inline operands whose length depends on the data, not a fixed-width encoding.

### What the leading token is not (negative result)

The obvious reading - "leading token = opcode, i.e. the field id whose slot holds the handler,
because the loop does `Y = z(B(F,37), F)`" - does not survive the write log. Joining the write log
to the same run (`wr[i][3]` is the number of reads completed when the write happened) gives the
fields each leading token writes:

```
288 (139x) writes 101 (124), 107 (63), 85 (31)      <- not one target
 89 (125x) writes  85 (59),  88 (32), 59 (31)
104 (121x) writes 107 (40),  88 (27), 66 (1)
418  (58x) writes  88 (31)
```

So either the handler takes its target field as an operand, or a segment mixes two loop levels.
Cheapest way to separate the two: log a depth counter alongside the pointer (increment on `eT`
entry, decrement on exit) and re-run the same join. Until that is measured, treat the leading
token as "handler id, target may be an operand".

The field table cannot answer it after the fact: a post-mint walk of `vm.h` reports 137 slots, all
with own keys `create,concat`, `prototype === undefined`, `value === undefined` - the slots are
drained by the run (section 2), so the handler has to be captured *while* it is live.

### The program opens with a string table, not with code

The first boundary (bit 32, right after the 32-bit seed) owns 166 tokens, and their values are
ASCII bytes:

```
... -divprotectcache_ 1l."..CA.B..Wy3.Y.S....G5'&k@.Z>..|#.LgT}..C.Es+xPF..H...)m ..
```

so the region after the seed is a table of names (`divprotectcache_…`) with a few binary fields
mixed in, and the instruction stream proper starts at bit 1362 on that run. That is consistent
with section 11's readable fragments and with section 19's high entropy on the EON build: the
*header* is text, the *payload* regions are not.

### Instruments added this round

```
--frame-scripts   pristine mint + dump every compiled script >= 4 KB, with anchor counts
--loop            log the instruction-loop pointer (one entry per executed instruction)
                  (also carried through --log-only, which now reports instruction counts)
research/read_records.py   tokenise a read log and print the token range behind each write
```

Next, in order: (1) depth counter on the loop, to separate nested levels before anything else is
concluded from segments; (2) capture a handler while it is live - the field slot is drained after
the mint, so this needs a poller or a breakpoint, not a post-mortem walk; (3) re-run the
op-to-effect join with both of those in place, which is the point where an instruction table
becomes a table instead of a guess.

## 27. The instruction table, measured

Three things had to be fixed before the opcode question could be answered, and the answer turned
out to be "there is no opcode - there is a handler id plus a per-handler operand layout".

### Nesting: there is none (measured, instrument fixed)

The loop's nesting counter rotates with the build (`F.pe` on Fhxs, `q.U8` on pBm, `V.mp` on EON),
so the counter is now taken from the loop-containing function's `if(!VM.X){VM.COUNTER++;` prologue
instead of being hard-coded. Logging it beside the pointer gives, for a whole run:

```
instructions 956   depths {1: 956}          (EON)
instructions 1222  depths {1: 1222}         (Fhxs)
```

Every boundary is at depth 1, so the segments from section 26 do **not** mix two loop levels - that
hypothesis is dead and the variability in per-handler effects is a property of the handlers.

### The write attribution was off by one

A write carries "reads completed when it fired" (`wr[i][3]`). The window of instruction `k` is
`[i, j)` in read indices, so the correct test is `i < readsCompleted <= j`; the first version used
`i <= readsCompleted`, which credited each write to the *previous* instruction (visible in the
samples as a target field equal to the previous instruction's target). After the fix, the join is
clean: **every instruction that writes exactly one field has that field id among its own tokens**
(511/511 in one run, 519/519 in another).

### Handler -> layout

`research/disasm.py` prints the profile. One run (EON, 956 instructions, 519 writes):

```
handler   n  arity(top)            writes  target-index
   288  138  {5:60, 8:58, 7:10}       131  {2:131}
    50  124  {3:123, 4:1}             124  {2:124}
   104  108  {5:67, 4:8, 6:5}           0  {}
    48   74  {3:73, 1:1}               73  {2:73}
   418   58  {2:58}                     0  {}
   412   58  {4:58}                     0  {}
    18   48  {4:46, 5:2}                0  {}
    37   46  {3:40, 1:6}               40  {2:40}
    55   41  {5:17, 6:8, 4:8}           0  {}
```

and from another run, the handlers that put the target first or last:

```
    32   31  {3:31}                     31  {1:31}      -> [32, TARGET, value]
    87   17  {6:15, 1:2}                13  {1:13}      -> [87, TARGET, a, b, c, d]
    96   26  {4:26}                     25  {3:24}      -> [96, a, b, TARGET]
   113   21  {7:11, 5:6, 1:2}           17  {2:17}
```

Concretely, from the disassembly:

```
[87 108 0 2 8 0]        writes 108
[87 17 0 144 238 241]   writes 17
[32 40 208]             writes 40
[32 81 16]              writes 81
[37 46 32]              writes 32
[50 ...]                writes its second token
```

So the grammar is `[handler, operands...]` where the handler decides how many operands follow and
where the target field id sits - index 1, 2 or 3 depending on the handler, and a large group of
handlers (104, 418, 412, 18, 55 in that run) never writes at all, i.e. they produce values for the
next handler. Arity varies for the data-carrying handlers (`288`: 5/8/7) exactly as a
length-prefixed inline payload would.

**Caveat that matters for anything reusable: the handler ids rotate per build.** The three-token
writer with the target at index 2 is `101` in one run and `50` in the next, on the same build
family. Only the (arity, target-position) shape is stable, so any table has to be rebuilt per
load, or keyed by shape rather than by id.

### Where this leaves the decompiler

Facts now in hand, each with a reproducible instrument behind it:

1. the program's plaintext, per 64-bit block (section 16), and its read stream (section 25);
2. instruction boundaries, one per executed instruction (section 26), with nesting (this section);
3. the operand tokens of every instruction, and the field(s) it wrote (this section);
4. the shape of the handlers: arity and target position, per build.

The open end is the *non-writing* handlers: 104/418/412/18/55 in one run are 60 % of the executed
instructions, and what they push (a value, a string, a callback) is not visible in the write log.
Two ways in, in order of cost: (a) join the *field reads* to the instruction (a handler that reads
field X leaves a `z(X, vm)` trail, which shows up as the field id among the tokens), or (b) capture
a live handler - a breakpoint on the loop that dumps `String(Y)` once per handler id, since the
slot is drained after the mint and a post-mortem walk only ever sees `create,concat`.

## 28. What a leading token actually selects: a slot value, function or data

Section 27 called the leading token a "handler id" because the loop does `Y = z(op, vm)` and then
calls `Y(F, J)`. Capturing `String(Y)` at dispatch (new `--handlers` hunk) shows that the slot
holds *either* a function *or* plain data, so the stream is a serialized computation over the
field table, not a uniform opcode stream.

Instrument: the loop's dispatch expression differs per build, so three shapes are matched in turn -

```
Fhxs  Y=z((G=B(F,(ZS(21,F,P),37)),G),F)
pBm   I=(b=f(78,(e(71,q,R),q)),T(q,b))
EON   z=B(V,(C=Z(V,(E(V,328,J),17)),C))
```

- and the first time an op id is seen, `String(handler).slice(0,400)` is stored on the instance
(`vm.__hn`), which survives the drain because it is a string copy taken *during* the run.

One run (pBm build, 1958 instructions, 30744 reads, 100 % of the program's blocks touched,
127 distinct op ids dispatched):

```
47  function(...)              real operations
37  numeric literal / array    constants (e.g. op 6 = twelve 32-bit words)
 9  array literal              constants
28  other                      strings, DOM objects, native method references
 6  empty                      slot already drained when captured
```

Samples that make the shape concrete:

```
op  1  function(E,q,L,Z,I,l){... l^I ... (q==1?Z<<L:Z>>>L) ...}      arithmetic on a 3-slot frame
op  5  function(D,k,H,M,p,g){p=(H=(g=f(13,(k=f(20,D),D)),M=f(27,J),x(k,D)),x(g,D)),e(M,D,+(H==p))}
                                                                    compare two field values, write bool
op  7  function(D,k,H,M,p){... FP(G,M,function(g){return eval(g)}(AF(N(D.W,H)))) ...}
                                                                    eval of a computed string
op 24  function(E,q,L,...){(q.push((I=E[0]<<24|E[1]<<16|E[2]<<8|E[3])...   32-bit packing
op  6  1718972003,1953066862,1160540460,1277975084,...              a constant table
op 17  "style"      op 29  "<<"      op 35  "slice"
op 34  function replace() { [native code] }
op 10  [object Window]      op 13  [object HTMLBodyElement]
```

So the program is a table of *slots* whose values are the operations, the constants, and the
captured environment objects the run needs - which is exactly what section 20's field table showed
from the other side (fields carrying strings, property lists, DOM references).

This also explains why the per-op effect table of section 27 looked heterogeneous: an op that
selects a *constant* writes nothing, and an op that selects a function may write a field named by
one of its operands. The (arity, target-position) measurements stand; only the word "opcode" was
wrong.

### Instruments, final state for this line of work

```
research/bgpatch.py        role-based patcher; hunks: entry, ret, boot, blockcache, sweep, writes,
                           killswitch, canary, post, kinds, loop, handlers
                           (order matters: loop and handlers run last, they insert mid-text)
research/dump_program.py   one page load, same build pair, raw material saved per load;
                           --log-only --loop [--handlers] is the trace mode,
                           --fields for the write table, --frame-scripts for the debugger dump
research/read_records.py   tokenise a read log, print the token range behind each write
research/disasm.py         instruction table (handler, arity, target position) + disassembly
```

Reproduce the table:

```
python3 research/dump_program.py --log-only --loop --handlers --port 10286 --out /tmp/bg-h
python3 research/disasm.py /tmp/bg-h/run_log.json --table
```

Next: the 47 functions are the instruction set in source form; the next useful artefact is a
per-build map `op id -> (kind, arity, operands, target)` in a machine-readable file, built by
joining the three logs, so that a later session can compare two builds by *shape* and see which
operations are stable (arithmetic, compare, eval, 32-bit packing) and which are environment
probes that change with the page.

## 29. One run, three logs, one machine-readable map

`--fields` mints twice (payload A, payload B) to diff them, which silently breaks the
write-to-instruction join: the write log then holds both mints and every write lands in the wrong
window. So the join has its own runner:

```
research/run_one.py     one page load, one mint, patch(writes, loop, handlers)
                        -> one.json {ip, rd, rv, wr, hn, V, tok}
research/disasm.py      --table (per-op profile), --emit (machine-readable map), --handler N,
                        --instr a:b (disassembly)
```

First map, committed as `research/opmap-sample.json` (EON build, 19 KB):

```
reads 4946   boundaries 939 (unmapped 33)   instructions 906   writes 518
distinct ops 78   captured handler values 48   depths {1: 906}

ops with a single arity and at least one write: 5
ops that never write:                          65
```

and the per-op profile that matters, unchanged from section 27 and now on a single mint:

```
handler   n  arity(top)             writes  target-index
   288  141  {5:61, 8:58, 1:12}        129  {2:129}
    73  124  {3:123, 4:1}             124  {2:124}
   104  121  {5:40, 6:38, 4:16}         0  {}
    48   73  {3:73}                    73  {2:73}
    37   59  {3:54, 1:5}               59  {2:54}
   412   59  {4:58, 1:1}                0  {}
   418   58  {2:58}                     0  {}
    18   48  {4:46, 5:2}                0  {}
    34   28  {3:28}                    28  {1:28}
```

Two things the map makes obvious that the tables did not:

* **the handler ids are per build but the shape is not.** The three-token writer with the target at
  index 2 was `101` in one run, `73` in this one and `50` in another, on the same build family.
  Anything reusable must key on `(arity, target position, handler source shape)`, never on the id.
* **a single-token "instruction" is a boundary artefact, not an op.** 33-34 boundaries per run have
  no read at their offset (the loop takes the `if(F.o)` path, which reads from a different field
  and does not touch the program pointer), and the header instruction that consumes the whole ASCII
  table shows up as one 169-token record. Both are visible in the arity histograms and should be
  excluded before a map is used to compare builds.

What is still missing for "generate the field table offline": the map says *which* fields an op
writes and in what order, but not how the value is computed. The 47 functions captured in section
28 are the computation, in source form, one per op - so the remaining work is to read those
functions (they are plain, if flattened, JavaScript) and pair each with the operands its arity
implies. That is a per-build transcription task now, not a discovery task.

## 30. Mechanism: the handler reads its own operands, the loop only picks it

Update to how sections 27-29 should be read. The loop does

```js
if((P=z(PTR,vm),P)>=V)break;
Y = z((G = B(vm,(ZS(CAT,vm,P),KIND)), G), vm);   // fetch op id, look up its slot value
... Y && Y(HANDLER_MARK) ? Y(vm, step) : throw;   // call it with exactly TWO arguments
```

so a handler receives `(vm, step)` and nothing else. Everything that looks like an "operand" in the
token stream is a value the handler itself pulled out of the program during its own execution:

```
op 48   function(N,Q,h,t,P){q(N,(Q=(t=(P=K(N,20),Z(F,20)),B(S,P)),h=l(D,t),t),h+Q)}
        tokens [48, 61, 118]  ->  writes field 118
```

Two program values are read inside that call (the reads log shows exactly two), and the field that
ends up written is one of those two values - so the target id is *read*, not encoded in a laid-out
instruction. That is why section 27's arity is not constant per op: it counts the reads a handler
made, and handlers loop over data-dependent lengths.

Tiny handlers confirm the calling convention by having no parameters at all and working purely off
closure state:

```
op 34   function(){K(0,40,c,1)}       tokens [34, 102, 208], [34, 51, 16]   -> writes 1 field
op 90   function(){K(0,41,x,2)}       tokens [90, 207, 3, 83]              -> writes 1 field
op 149  function(N,Q,h){(h=Z(N,(Q=K(c,3),13)),q)(Y,h,""+l(N,Q))}
```

So the decompiler's unit is (handler source, the values it read, the field it wrote) - all three are
now measured per instruction, and the remaining work is transcribing the 47 handler functions per
build into operations. What must not be inferred from the token stream alone is a fixed operand
layout: there is none, because the handler is the parser.

## 31. First annotated ops: what the written value is compared to what was read

Method: for instructions with exactly one write, compare the written value with the tokens the
handler itself read in that instruction (section 30). Three outcomes are possible and each is
informative - the value equals a token (a literal store), the value is unrelated to the tokens (a
computed store), or the instruction writes nothing at all (a value producer).

One EON run (906 instructions, 518 writes) annotated this way:

```
op   n   arity  shape                    written value            reading
 34  28       3  [34, T, V]               == V, 28/28              STORE_IMM: field[T] = V
133   4     169  [133, T, a, b, ...]      == tokens[3:], 4/4       STORE_ARRAY: field[T] = the 165-byte
                                                                   array that follows (the header's
                                                                   ASCII table, "divprotectcache_...")
288 129   5/7/8  [288, a, T, ...]         clock (e.g. 1793192953745) or an object     computed store:
                                                                   the run's ms clock goes to field T
 73 124       3  [73, T, a]               "0," / 4-byte / 2-byte   computed store, size varies
 48  73       3  [48, a, T]               a 73-byte function source string             computed store
 37  54       3  [37, a, T]               (function / opaque)       computed store
 96  22       4  [96, a, b, T]            [object Window] / [object HTMLDocument]
                                                                    STORE_DOM_REF: a captured DOM
                                                                    object lands in field T
 90   4       4  [90, T, a, b]            851 / 2048 / 28573        computed store of a small int
 87  13       6  [87, T, a, b, c, d]      133120 / 343635057 / -2073085794
                                                                    computed 32-bit store
 68  22       3  [68, 63, T]              opaque, size 3/5/7       computed store
--  ---      --  ------------------------ ------------------------ ---------------------------
 34,133,288,73,48,37,96,90,87,68 cover 447 of 906 instructions (49 %)
```

and the value producers, which never write:

```
op   n  arity   role
104 121   4/5/6  reads a few values (largest single group in the program)
418  58   2      [418, x] one operand
412  58   4      [412, a, b, T]-shaped but writes nothing
 18  48   4/5    [18, a, b, c]
```

Two concrete facts worth carrying forward:

* **the clock is a program instruction, not a header field.** Field 74/54 (per build) receives
  `Date.now()` from op 288 during the run, which is the "clock" of section 20 seen from the
  instruction side.
* **the ASCII table at the start of the program is stored by one instruction.** Op 133 consumes the
  whole table and writes it as one 165-element array; that is why the first boundary looked like a
  169-token record (section 29) - it is a single bulk store, not a merged segment.

Caveat, unchanged: every id above is per build (the store-immediate op is 34 here, and the same
shape appeared as 32 on another build). The *shapes* - `[op, T, V]` immediate, `[op, T, ...]`
computed, `[op, a, b, T]` with the target last, `[op, a, T, ...]` with the target in the middle -
are what transfer.

## 32. Field reads per instruction: the operands are mostly on a stack, not in fields

The read log only covers the program stream, so "which fields does this instruction touch" needed a
fourth instrument: patch the field accessor (the same function the loop uses to fetch the op slot)
to log `[fieldId, readsCompletedWhenRead]`, then attribute by the same window rule as writes.

The accessor is not a stable name and its id argument moves, so both are taken from the dispatch
expression matched for the handler capture (section 28). Measured on all three builds:

```
Fhxs  accessor z(id, vm)   EON  accessor B(vm, id)   pBm  accessor T(vm, id)
```

- EON needed one extra guard: it defines `B` three times in one build, so the definition is picked
  by "its body indexes a field table" (`=vm.TABLE[id]`), not by being the last definition.

One run (pBm, 921 instructions, 441 writes, 11451 field reads, all depths 1) with the op-id read
and the bit pointer filtered out (the pointer, field 44 here, is touched by nearly every
instruction):

```
op     n   inputs (fields read)            outputs (fields written)
   299  144  []                              []
    13  125  [(27, 31), (339, 1)]            [(111, 59), (124, 32), (15, 31)]
   467  117  []                              [(27, 45), (79, 28), (16, 3)]
   430   73  []                              []
   200   67  []                              [(124, 30), (50, 12)]
    53   59  []                              []
    18   29  [(266, 1), (366, 1), (375, 1)]  [(27, 18), (124, 2)]
   264   23  [(118, 3), (84, 2), (27, 2)]    []
   425    5  [(366, 3), (447, 2)]            []
```

Reading it:

* **most instructions touch no field at all** - neither read nor write. Combined with section 30
  (the handler gets only `(vm, step)`), that means the operand flow is an implicit stack: the
  handlers call the reader for program values, push results, and a few of them pop and store. The
  stack is the missing half of the dataflow, and it is a VM-internal array (`J.P`-shaped in the
  dispatcher `tY`, which does `c = L.P.pop()`).
* **the one op with a clear content role is 13**: 125 executions, reads field 27, writes 111 (59x),
  124 (32x) and **field 15 (31x)** - 15 is the seed field of section 12, so this is where the
  per-sign seed is generated and stored - the same event section 20 saw as "field 15 written twice".
* fields 366 and 266 are read by the rare ops (425, 337, 441, 18) - 366 is the field the reader's
  own dispatch writes (`T(this,366)` appeared in the EON boot), i.e. a bookkeeping slot.

So the decompiler now has, per instruction: the handler source, the program values it read, the
fields it read, and the fields it wrote. What it does not have is the stack, and the measurements
above say that is where most of the operands live. Next instrument, then: log the stack depth (and
the top few values) beside each boundary, which turns "op 430 does nothing visible" into
"op 430 consumes two values".

Reproduce:

```
python3 research/run_one.py --port 10292 --out /tmp/bg-fr        # now also patches the accessor
python3 research/disasm.py /tmp/bg-fr/one.json --dataflow
```

## 33. Correction: the stack is not the operand channel (measured, 31 of 1092)

Section 32 guessed that the operands of the "does nothing visible" ops live on an internal stack.
The loop hunk now logs the stack depth beside each boundary as well - the property name comes from
the dispatcher's own `c = VM.P.pop()` (only the property is reusable; the local there is a different
variable at the loop site, and using it would throw at runtime).

One run (pBm, 1092 boundaries):

```
stack depth histogram: {1: 1061, 2: 31}      range 1..2
delta between consecutive instructions: {0: 1029, +1: 31, -1: 31}
```

So the stack is used by **one construct, 31 times in 1092 instructions** - it is not where the
operands of the frequent producer ops live. The hypothesis in section 32 is wrong and is withdrawn.

What the loop does with a handler's result is visible in the code, and it is the more likely
channel:

```js
oz(52, (Y && (e=Y[E4], t-(~e&t)) ? Y(F,J) : nZ(0,[PH,21,G],F,17)), false), false, J, false, F)
```

- the handler's **return value** is passed straight into `oz(52, ...)` together with the step, i.e.
  the value channel is the call's return value plus whatever `oz` keeps, not a stack array.

`oz` itself is another flattened multi-purpose function (like most of this interpreter), so the next
measurement should be cheaper than reading it: log the *return value* of each handler call the same
way the handler string is logged (`String(value).slice(0,...)` for primitives, `typeof` otherwise),
which requires one more injection at the same site and answers "what does op 430 produce" directly.

Standing summary of what is measured per instruction: handler source, program values read, fields
read, fields written, stack depth. Missing: the value the handler returned.

## 34. Handlers are void, and the byte emitters are two functions away

Following section 33's lead, the loop call is now wrapped so the value handed on is recorded per op
id (`vm.__hr[op] = [typeof r, String(r).slice(0,160)]`, one call kept). One run, 34 distinct op
values captured:

```
op 10, 26, 30, 48, 53, 63, 69, 72, 80, 95, 98, 106, 114, 118, 123, 154, 156, 160, 200, 206 ...
  typeof = undefined      value = undefined        (all of them)
```

So handlers are **void**: they communicate by mutating the VM instance, not by returning. Section
33's "the return value is the channel" is wrong as well and is withdrawn. What that leaves is the
instance itself - and the two functions that actually append to a field's byte buffer are easy to
find, because they are the only ones that XOR the per-field keystream on the way in:

```js
ax = function(b,F,t,J,...){ if(t.C==t) for(e=w(t,b), b==277||b==474||b==473 ? (Y=function(c,...){
                                        ... e.push(e.Tu[u&7]^c) ... }) : ... }
     // ax(FIELD_ID, data, vm, ...)   -> e = field buffer, bytes XORed with e.Tu
qj = function(b,F,t,...){ while(b.C==b){ for(G=z(t,b), t==277||t==474||t==473 ? (L=function(c){...G.push(G.Tu[M&7]^c)...}) : L=function(c){G.push(c)}, ...
     // qj(vm, data, FIELD_ID, ...)   -> same, argument order rotated again
```

`e.Tu` / `G.Tu` is the keystream table that `WH` regenerates (`G.Tu=WH(16, block, seed, [0,0,..], 551)`
in the body of those emitters), i.e. the same table section 13 captured and section 17 proved
unusable out of band. Here it is used the other way round - to *encrypt* the field bytes on the way
out - which is why the token's payload is the field table XORed with a per-sign keystream.

That is the remaining measurement for the serializer: hook `ax`/`qj` (both shapes are already
recognisable, the same way the field writer was) and log `(fieldId, data length, first bytes)`. It
turns "the program wrote field 146" into "field 146 received these bytes in this order", which is
one step short of the token itself.

## 35. The emit hook: implemented for one shape, and the two ways it can silently break a run

Section 34 named the next step: hook the byte emitters. That is implemented (`emit=True`, wired into
`research/run_one.py`), and the way it had to be done is worth recording because both traps change
VM behaviour without any error:

**trap 1 - inserting before the body brace.** The emitters are `while(vm.C==vm){...}` (qj) and
`if(vm.C==vm)for(...)` (ax). Appending text at the end of the matched condition produces

```js
while(b.C==b)(b.__em=...).push([...]);{for(...)}      // WRONG: the loop now repeats the log
if(t.C==t)(t.__em=...).push([...]);for(...)           // WRONG: the for now runs unconditionally
```

so the log has to go *inside* the block (`while(...){(log);...}`), and where there is no block it
has to be folded into the condition instead:

```js
if(((t.__em=t.__em||[]).push([b,len,first]),t.C==t))for(...)   // correct, condition preserved
```

**trap 2 - stale offsets, again.** Two emitters in one source, so the match list must be walked in
reverse (each injection shifts the offsets of the ones behind it). This is the third time this class
of bug has appeared in this file (sections 26, 35): any hunk that inserts text must either run last
or process its matches back to front.

Shape detected on the Fhxs build (both verified to still produce a normal token by `node --check`
plus the injected-code review):

```
qj(vm, data, fieldId)   while(vm.C==vm){ log(fieldId, data.length, data[0]); ... }
ax(fieldId, data, vm)   if((log(...), vm.C==vm)) for(...)
      logged: [fieldId, data.length, data[0]]
```

**not yet exercised live**: four page loads after wiring it up all served the pBm or EON builds, and
those emitters are shaped differently - the keystream table is called `s8` and the index expression
is obfuscated, e.g.

```js
R.push(R.s8[-~(a&7)+(a^7)+(~a^7)]^u)        // pBm: same idea, table name and index differ
```

so the detector has to generalise to `X.push(X.TABLE[<any index>]^byte)` and then find the enclosing
function's field-id parameter. That is a ten-minute change, but it has to be verified on a build
that actually ships it, which is why it is recorded here rather than guessed at.

## 36. The token field, filled: 17 emits, 780 bytes, target id is the last token

The emit hook (section 35) finally ran on a build whose emitters it can see (Fhxs). Two runs, one
before and one after adding the read counter to the log:

```
run A (no read counter)   18 emits   696 bytes   fields {146: 683, 444: 2, 134: 7, 473: 4}
run B (with read counter) 17 emits   780 bytes   fields {146: 773, 444: 2,  89: 1, 473: 4}
```

The emission sequence for field 146 in run A, which is the token field of section 2b:

```
  #  len  first                            #  len  first
  1    1    208                            8    2      0
  2    2      0                            9   64      1
  3    6     11                           14    1      1
  4    1     95                           15    1      7
  5    4    106                           17   11      0
  6    4      9                           18  585      2      <- the bulk
  7    1     38
```

Run B attributes each emit to an instruction (the log carries the read count, so the same window
rule as writes applies) and the shape is immediately readable - **the target field id is the last
token of the instruction**:

```
field 146 len   1  <- tokens [163,  82, 146]
field 146 len   2  <- tokens [490,  11, 146]
field 146 len   6  <- tokens [490,  11, 146]
field 146 len   1  <- tokens [163,  57, 146]
field 146 len   4  <- tokens [460,  52, 146]
field 146 len  64  <- tokens [490,   9, 146]
field 444 len   1  <- tokens [163,  94, 444]
field 473 len   4  <- tokens [263,  50, 473]
```

So the emitter call reads its field id from the program (last token), and the *length* is not an
operand: `[490, 11, 146]` emits 2 bytes in one call and 6 in another, and `[490, 9, 146]` emits 2 and
64 - the byte count comes from the value being appended.

Two consequences worth keeping:

* **the last five emissions have no instruction window.** They land after the loop's final boundary,
  i.e. in the serializer phase (`DS.eV` / `o3` of section 3), including the final 585/675-byte write.
  So the token is assembled in two phases: incremental chunks during the program run, one bulk write
  at encode time - which is why section 2b saw "2 + 1059" as the last `concat`.
* **the small chunk sizes match section 2b exactly** (1, 2, 4, 6, 11, 64 ...): those are the
  length-prefixed per-field headers seen from the inside.

Still unhooked: the pBm/EON emitters (different keystream table name and an obfuscated index, section
35). The analytical fallback now works without them - for those builds, "last token of the
instruction is the emit target" can be checked against the write log directly.

Reproduce:

```
python3 research/run_one.py --port 10322 --out /tmp/bg-em      # needs a Fhxs load for emit events
python3 research/disasm.py /tmp/bg-em/one.json --emit-log
```

### The emit log accounts for the token's size exactly (measured twice)

Token length is `";" + base64url(bytes)`, so the byte count is `len/4*3 + (0 if len%4==0 else len%4-1)`.
Against the emissions into field 146:

```
run A   token 923 chars = 692 bytes   emits into 146 = 683   difference +9
run B   token 1043 chars = 782 bytes  emits into 146 = 773   difference +9
```

Both runs: `token_bytes == emits_into_146 + 9`. The nine bytes are the constant head of section 1
(the 5-byte preamble built by `AY(2)` with `C[1] = C[0] ^ 30`, then part of the 8-byte marker), which
is written outside the hooked emitters. Total emissions (including the other fields) do **not** match
the token size (`-4` and `+2`), which is a useful discriminator: only field 146's stream reaches the
token.

## 37. Byte level: the token is a chain of length-prefixed chunks, and field values appear verbatim

The emit hook now logs the first 16 payload bytes of small chunks as well. One run (Fhxs, token 869
chars) shows the whole structure of the field-146 stream:

```
field 146 len   1   [208]
field 146 len   2   [0, 6]
field 146 len   6   [11, 119, 101, 235, 43, 119]
field 146 len   1   [95]
field 146 len   4   [149, 46, 128, 215]
field 146 len   4   [155, 38, 82, 92]
field 146 len   1   [38]
field 146 len   2   [0, 64]
field 146 len  64   (larger than 16, only the length is logged)
field 444 len   1   [104]        field 444 len 1 [144]
field 146 len   1   [1]          field 146 len 1 [7]
field 473 len   4   [0, 2, 104, 144]
field 146 len  11   [0, 9, 247, 110, 217, 227, 72, 63, 116, 220, 19]
field 146 len 545   (the bulk)
```

Three things are readable directly:

* **every chunk carries its own length prefix.** `[0, 9, ...]` is nine payload bytes, `[0, 2, ...]`
  is two. That is the "nonce(2) + field(n)" pattern of section 2b seen from inside the field.
* **field values appear verbatim.** The write log has field 473 = `[247, 110, 217, 227]`, and the
  next emission into 146 is `[0, 9, 247, 110, 217, 227, ...]` - the same four bytes, unencrypted,
  followed by five more. So at this point the stream is plaintext field data, and the encryption of
  section 34 (`e.Tu[i&7]^c`) is applied only on the paths that target 277/473/474 (the emitter has
  exactly that `b==277||b==474||b==473` branch).
* **the emission that fills 473 is itself `[0, 2, 104, 144]`** - prefix plus two bytes, i.e. the
  field's own stream is built the same way as the token's.

Size accounting over three runs (`token_bytes` = `len/4*3` of the base64url part, i.e. after
dropping the leading `;`):

```
run A  token 923 chars -> 692 bytes   emits(146) 683   difference 9
run B  token 1043 chars -> 782 bytes  emits(146) 773   difference 9
run C  token 869 chars -> 651 bytes   emits(146) 643   difference 8
```

So `token_bytes = emits(146) + head` with head = 8..9 bytes. That head is the nonce and the marker
of section 1 (`C = AY(2).concat(field146)`, `C[1] = C[0]^30`), and its last byte moves with the
length encoding - which is the one thing here that is *not* pinned down yet.

This is as far as the emission side can be pushed without decoding the handler that composes each
chunk. What it already gives the serializer work: the exact chunk order and the per-chunk byte
counts for one run, plus the invariant that only field 146's stream reaches the token.

### The marker of section 1 is produced by these emissions, byte for byte

Section 1 measured an 8-byte marker at offset 5 of both token shapes, `00 06 0b 77 65 eb 2b 77`, and
a `d0` immediately before it. The emission log of run C starts:

```
field 146 len 1  [208]                     = 0xd0
field 146 len 2  [0, 6]                    = 0x00 0x06
field 146 len 6  [11, 119, 101, 235, 43, 119]
                                           = 0x0b 0x77 0x65 0xeb 0x2b 0x77
```

which is `d0 | 00 06 0b 77 65 eb 2b 77` - exactly the head that was captured from the wire in
section 1, now arriving as three separate length-prefixed chunks. That also explains the missing
bytes in the size accounting: the marker tail is written by a path the emit hook does not see (the
`concat` the serializer does at encode time, section 2b), which is the 6-7 bytes between
`emits(146)` and `token_bytes - 2`.

So the head of the token is not a constant that gets prepended at the end - it is emitted first, one
chunk at a time, by the program.

## 38. Aligning the emission log with the token itself: 843 of 851 bytes accounted for

`run_one.py` now returns the token string as well, so the emission log can be aligned against the
actual bytes instead of counted. One run (Fhxs, token 1136 chars = 851 bytes, 19 emissions of which
13 target field 146):

```
token head : 1e 00 b8 00 5a | d0 00 06 0b 77 65 eb 2b 77 | 5f ...
              ^ 5-byte preamble        ^ the section-1 marker
emissions  : [208] [0,6] [11,119,101,235,43,119] [95] [182,88,175,137] [208,219,78,140] ...
             = d0    00 06  0b 77 65 eb 2b 77        5f  ...
```

So the marker that section 1 captured from the wire is emitted as three separate chunks, the byte
after it (`5f`) as a fourth, and the alignment then walks the rest of the stream:

```
aligned from byte 5 to byte 850 of 851
  gap at 0  (5 bytes) : 1e 00 b8 00 5a      <- the preamble (C = AY(2).concat(field146), C[1]=C[0]^30;
                                               here 0x1e ^ 0x00 = 0x1e, the same invariant section 1
                                               measured as 0x35 ^ 0x2b)
  gap at 90 (1 byte)  : 75
  gap at 93 (1 byte)  : 63
  tail      (1 byte)  : eb
```

Reading: **843 of the token's 851 bytes come out of the emission log**, 5 of the remaining 8 are the
preamble, and three single bytes sit between chunks. Those three are written by the encode-time path
that the emit hook does not see (the `concat` of section 2b) - which is also why the earlier size
accounting came out as `+9, +9, +8`: the head is 5 + a small number of stray bytes, one per affected
chunk boundary.

Also verified in the same run: emission payloads for other fields (444, 473, 134) do **not** appear
anywhere in the token - only field 146's stream does. That is the discriminator that makes the
alignment unambiguous.

With that, the token's byte layout is measured end to end for one build: `preamble(5) + emitted
chunks(843) + 3 stray bytes`, in emission order, and every chunk's payload is either known (<=16B)
or known by length.

## 39. The three stray bytes are the emitter's flag argument, and the accounting now closes exactly

Section 38 left three single bytes between chunks and called them "written by the encode-time path
that the emit hook does not see". That is **withdrawn**: they are pushed by the emitter itself, as a
*leading* byte before the payload, and the hook simply never looked at the argument that carries it.

### The measurement

Both emitter shapes push a flag byte before the data:

```js
qj = function(b,F,t,J,...){while(b.C==b){ ... J&&L(255-~(J&255)+-256),P=F.length,Y=0;Y<P;Y++)L(F[Y]); ...}}
ax = function(b,F,t,J,...){if(t.C==t)for(...){ ... J&&Y(255-~(J&255)+-256),P=F.length,G=0;G<P;G++)Y(F[G]); ...}}
```

`255-~(J&255)+-256` is `J&255` written obfuscated (`~x = -(x+1)`), so the call emits **one extra byte
`J&255` when `J` is truthy**, then the payload. The hook logged `(fieldId, data.length, data[0], …)`
and nothing about `J`, which is exactly one unexplained byte per call with a truthy `J`.

The hook now logs it (7th element, `(J&255)|0`), and the accounting closes byte for byte. One Fhxs
run, token 1005 chars:

```
token 753 bytes = nonce(2) + field146(751)
field146 = b8 96 cc  +  stream(748)
stream   = concatenation over field-146 emissions of (flag? 1 byte : 0) + payload
exact=True   (748 of 748 bytes identical, not "covered" - equal)
flags    = [0x75, 0x62, 0x63, 0x17]      # four calls had a truthy J
```

Reproduce: `python3 research/align_emits.py /tmp/bg-e-10432/one.json` →
`stream 748 B  body 748 B  exact=True`.

### What that says about the token's shape

* `token = nonce(2) + field146`, and `field146 = head(3) + Σ(flag + payload)`. The three head bytes
  are `b8, token[1], x` — i.e. the nonce's *second* byte appears twice, which is the `C[1]=C[0]^30`
  invariant of section 1 seen from the field side (`token[0]^token[1] == 0x1e` on all six runs
  measured: `35 2b`, `43 5d`, `1e 00`, `65 7b`, `18 06`, `7a 64`).
* The concat graph is now measured, not inferred (`research/probe_concat.py`, CDP hooks on
  `Array.prototype.push/concat` in the frame realm, pristine mint):

```
concat id257(2B) + id258(2B)      x4      -> 4-byte pieces
concat id278(2B) + id90(64B)
concat id280(2B) + id279(71B)
concat id281(2B) + id99(876B)
concat id282(2B) + id250(1054B)   <- the token: 2 + 1054 = 1056 bytes
```

  so the serializer builds *pieces* as `nonce(2) + field(n)` and the last one is `nonce + field146`.
  Field 146's own pushes are visible in the same log: array id 250 has 966 pushes covering
  `n = 88..1053` with **no gaps in `n`**, i.e. every byte of the buffer - flag bytes included - is an
  `Array.prototype.push`.
* Field buffers are drained before `btoa` (`vm.h[146].prototype` has no `length`, `create()` returns
  `undefined`), so the buffer can only be read while it is being built (push hook) or from the token
  itself. `research/probe_serializer.py` confirms this and returns the pre-encode string (1085 B on a
  trusted run).

### Which handler produces which chunk (section 38's question 1)

`research/disasm.py --emit-log` joins an emission to the instruction that was executing (read-count
window). The head of the token is emitted by **three-token instructions of the form
`[op, sourceField, 146]`**, and the op set is stable across runs of the same build family:

| op | bytes written | verified against the write log (run 10432) |
| --- | --- | --- |
| 163 | 1 | field 7 = 208 → `d0`; field 27 = 38 → `26`; field 92 = 95 → `5f` |
| 460 | 4 (uint32 BE) | field 50 = 372310253 → `16 31 00 ed`; field 72 = -1560620949 → `a2 fa d0 6b` |
| 490 | 2 + n | field 40 = `[11,119,101,235,43,119]` → `00 06` + the section-1 marker; field 72 = 64 B → `00 40` + 64 B |

The *argument* is a source field id and rotates per run (run e1: 65/91/102/112/62/19/87; run 10432:
7/40/92/50/72/27/72), which is why an earlier note could not see a constant layout: the template is
constant, the field ids are not. A fourth op, 118, emits into field 97 with the same `len16 + bytes`
shape (it is the one that produced the 57732-byte "emission" in run e1 - a real value, not a hook
artefact).

The **tail records are serializer-phase**: their read count equals the final read count
(`rv = 19080` = end of the program), so they have no instruction window and are not program
instructions at all. Shape, measured: `[flag][len16][data]`, e.g.

```
flag 0x75 + [01]                 flag 0x63 + [00 09] + 9 B
flag 0x62 + [00 02] + 2 B        flag 0x17 + [02 85] + 645 B     (into field 473 for 0x62)
```

The flag is not a constant of the format: 0x75 and 0x63 repeated across runs, the bulk record's flag
was 0x17 in one run and 0xeb in another, so it is a per-run id (a field id or a schema tag) that the
serializer passes as the emitter's 4th argument. It is **not** simply "the source field's id": in the
two runs whose flag was 0x17, field 23 was written (`253` at rv 0), but in the 0xeb run field 235 does
not appear in the write log at all - so the tag rotates with the build, exactly like field ids and op
ids (section 15), and has to be measured per run instead of being mapped once. **Open:** identify the serializer function that
passes it - the cheapest instrument is a CDP `Debugger.setBreakpoint` on the emitter entry (invisible
to the VM, unlike a JS-level hook) and reading `callFrames[1]` for the five tail calls.

### What the >16 B payloads actually contain (section 38's question 3)

The hook now logs every payload up to 4096 B (base64), so the bulk is readable. It is **opaque**:

```
payload 647 B = [02 85] (len16 = 645) + 645 B body
body entropy 7.68 bits/byte, 0.363 printable, no ASCII run >= 6, no nested [len16][value] parse
```

So the bulk is high-entropy *before* it reaches field 146, and field 146 is the un-XORed emitter path
(section 34) - the data is not encrypted on the way out, it is already random/encrypted when the
program writes it. Reading its content therefore needs the generating handler, not the token; this
is the same conclusion section 13/17 reached for the keystream, now with the payload in hand instead
of inferred.

### Limits of the instrument

* The emit hook matches the Fhxs emitter shape only (`while(vm.C==vm)` / `if(t.C==t)` guard after
  `=function(...){`). EON and pBm loads log **0** emissions; their emitters are state machines
  (`B==80?(R.push(R.s8[-~(a&7)+(a^7)+(~a^7)]^u),B=3)`), so the detector has to key off
  `X.push(X.TABLE[<any index>]^byte)` and take the field id from the buffer, not from a parameter.
  Until that exists, every emission measurement needs a Fhxs load (roughly one load in two).
* The flag byte and the payload are logged at *function entry*, so a call with `J` truthy but
  `J&255 == 0` is indistinguishable from a call with no flag. No such call was observed, but the
  accounting would silently stay correct-by-length and wrong-by-position if one appeared.

## 40. The emitter hook now covers every build family, and the accounting closes on all of them

Section 39 could only measure Fhxs loads (the hook keyed off `while(vm.C==vm)` / `if(t.C==t)` and the
literal flag expression). That limit is gone: five families have been measured, each with **two**
emitter sites, and every run below closes byte for byte.

| build | emitter sites | token field | mode | run |
| --- | --- | --- | --- | --- |
| FhxsKBPKEL3Q_ | ax, qj | 146 | full | exact 724/724 |
| EONwmJdvD0_ | UC, W | 299 | full | exact 759/759 |
| pBmIPB2A48c | y4, Gm | 366 | full | exact 766/766 |
| X9X8Htl1zlji | (2 sites) | 478 | full | exact 883/883 |
| SnVlM0KMiNaW | qh, Ez | 483 | emit-only | exact 956/956 |

**The token's field id is not 146.** It rotates with the build like every other id (146 / 299 / 366 /
478 / 483 above), so nothing may hard-code it. `research/align_emits.py` now identifies the field by
content: it tries each field that emitted something and keeps the one whose `flag + payload` stream
equals the token body. Sections 37-39 say "field 146" throughout; read that as "the token field".

### How the state-machine emitters are found

The shape (EON/pBm/SnVl/X9X8) has no `.C==` guard and the flag expression is obfuscated differently
per build, so nothing is matched literally:

```
qh=function(N,y,e,D,...){for(true;y.o==y;Number()){{q=p(y,N),
     N==401||N==291||N==307 ? (M=<keystream closure>, u=K(448,y)) : M=function(P){q.push(P)},
     D&&M(-1-~D-(D^255)+(~D&255)),          // the flag byte, obfuscated as D&255
     A=0,n=e.length;while(A<n)M(e[A]),A++}}
```

* **anchor:** the byte loop itself, `PUSH(DATA[i])`. Everything else is derived from what uses it:
  the flag is the `FLAG&&PUSH(<expr mentioning FLAG>)` call to the same closure just before the loop
  (argument parsed with paren balance, because `-1-~D-(D^255)+(~D&255)` contains parens), the vm is
  the identity comparison in the guard, the field id is the accessor argument that is not the vm, and
  the data is the array indexed by the loop.
* **the guard rotates:** `if(vm.C==vm)`, `switch(!(vm.R==vm))`, `for(true;vm.o==vm;Number())`. Match
  the identity comparison `(\w+)\.\w+==\1`, not the statement around it.
* **the flag expression rotates:** `J&&L(255-~(J&255)+-256)` (Fhxs), `Z&&Q(Z&255)` (pBm),
  `q&&P(-1-~q-(q^255)+(~q&255))` (SnVl). All three are `FLAG&255` written three different ways.
* a function must be hooked **once**: the Fhxs emitters match both detectors (guard side and loop
  side), and a double hook logs every call twice, which breaks the accounting while still looking
  plausible. Shape A (guard) is resolved first and shape B skips those function starts.

### Emit-only mode, and the two anchors that fail on new families

Two of today's loads (`SnVlM0KMiNaW`, `U5tYCxBAtKrhIfdN`) do not match the reader anchors at all -
`cannot tell bits from flag: ['N','y','e','D']` and `boot anchor not found`. The emit hunk needs none
of them, so `bgpatch.patch(src, entry=False, ret=False, boot=False, emit=True)` now runs it on its own
and `run_one.py` falls back to that when the full patch raises. Two consequences:

* the boot hunk is what normally publishes `window.__vmref` (the handle `run_one` uses to read the
  logs), so in emit-only mode the first emit publishes it: `(window.__vmref=window.__vmref||vm),…`.
* read counts (`vm.__rv`) are empty in that mode, so emissions cannot be joined to instructions - the
  byte accounting still works, the instruction attribution does not.

### Correction: the "0xeb" stray was an alignment artefact

Section 39 recorded the bulk record's flag as 0x17 in one run and 0xeb in another, and the previous
commit inferred a per-build rotation from it. That 0xeb was **not** a logged flag: it came from the
alignment walk, which had no flag byte to place and therefore shifted the 745-byte chunk one byte
early, leaving the chunk's last byte (`eb`) looking like a trailing stray. With the flag logged, every
run measured since shows the same four values:

```
flags = 0x75, 0x62, 0x63, 0x17      (14 of 14 logged runs, all five families)
```

So the tags are stable across builds in this window (14 runs), and the rotating id is the *token field*, not the
flag. Whether the tags rotate over time is untested - record the value per run, do not assume it.

## 41. The tail records are a fixed serializer table, and its tags are protocol constants

Section 39 left "which serializer function passes the flag" open. It is answerable statically: the
emitters are called from a handful of literal call sites in the serializer, and the 4th argument at
each of them is a **constant tag**. Grepping the emitter names in the interpreter text (skipping the
definitions, arguments parsed with paren balance) gives the whole table. Fhxs:

```
qj(this, Q9(2,YI.length).concat(YI), 146, 18)     YI = z(311,this)
qj(this, Q9(1,this.K+1>>1),          146, 117)
ax(146,  Q9(2,T.length).concat(T),   this, 99)    T  = w(this,473)
ax(473,  Q9(2,Z.length).concat(Z),   this, 98)    Z  = field 323 or 444
qj(this, Q9(2,n).concat(AY(n)),      146, 23)     <- the bulk
qj(this, [],                         146, 6)
ax(146,  [],                         this, 231)
qj(this, Q9(2,g.length).concat(g),   146, 132)    g  = field 311, sliced at 1E6
```

and EON has the same eight, with its own ids (`UC(36,this,299,vs(m.length,2).concat(m),18)`,
`W(299,this,vs(aN.length,2).concat(aN),99)`, ...), as do pBm (`y4(366,mq(k.length,2).concat(k),this,99)`)
and SnVl (`qh(483,this,pg(2,V6.length).concat(V6),99)`). The tag set is **identical in all four
families**:

```
6, 18, 23, 98, 99, 117, 132, 231        (plus 17 on a non-token field in pBm)
```

So the flag is a **record type**, a literal in the interpreter text - not a per-build id and not a
rotated tag. That supersedes the "per-build rotation" reading of section 39 and the "stable in this
window" hedge of section 40: the tags are constants, and it is the *field ids* in the same call
expressions (311, 473, 323/444, 299, 366, 483) that rotate.

What each record carries, read off the call sites:

| tag | payload | note |
| --- | --- | --- |
| 6 | empty | marker, no data |
| 231 | empty | marker, no data |
| 18 | `len16 + field(311)` | the collected blob |
| 23 | `len16 + AY(n)` | the bulk, `n` derived from lengths |
| 98 | `len16 + field(323/444)` | also emitted *into* field 473 in Fhxs |
| 99 | `len16 + field(473)` | the 9-byte block seen in every run |
| 117 | `len1 + (K+1>>1)` | a small counter |
| 132 | `len16 + field(311)`, sliced at 1E6 | the tail |

That is also the answer to "which handler produces the tail": none - the records are appended by the
serializer after the program loop has finished (`rv` equals the final read count, section 39), and
each one is a copy of another field's buffer, which is why field values appear verbatim in the token
(section 37). The head, by contrast, is produced by program instructions (`[op, srcField, tokenField]`,
section 39).

### The bulk is random filler, not encrypted content (measured, all four families)

`AY` is the same function that produces the 2-byte nonce in section 1 (`C = AY(2).concat(field146)`),
and the bulk record is `Q9(2,n).concat(AY(n))`. The name rotates, but the function does not: it is the
one whose body pushes `Math.random()*255|0`, and in every family the tag-23 argument is exactly that
function:

```
Fhxs   .concat(AY(n)),146,23)     AY  = ...F.push(Math.random()*255|0)...
pBm    .concat(LC(p)),this,23)    LC  = ...q.push(Math.random()*255|0)...
SnVl   .concat(Kg(O)),23)         Kg  = ...y.push(Math.random()*255|0)...
EON    .concat(sC(y)),23)         sC  = ...R.push(Math.random()*255|0)...
```

So the bulk payload is **`n` random bytes** - padding, sized by a length derived earlier in the same
expression - and nothing is hidden in it. That accounts for every property measured in section 39
(entropy 7.68 b/B, no ASCII runs, no nested length structure, length varying per run while the
surrounding records stay fixed) and it means a reimplementation only has to emit `n` bytes from any
RNG, not reproduce their content. The token's *information* is in the fixed records (18, 98, 99, 117,
132), not in the bulk.

Check it with one grep per family:

```
grep -o 'Math.random()\*255' interp.js          # -> the filler function
grep -o '\.concat(\w+(\w+)),[^;]\{0,12\}23)' interp.js   # -> the tag-23 site uses it
```

## 42. Which field each record copies, and why only four tags show up

Section 41 gave the tag table from the call sites. This section resolves, per run, which field each
record's payload is copied from and what wrote that field. Tool: `research/record_map.py` (joins the
call sites in the interpreter text with the write log and the instruction windows of `disasm.py`).

```
python3 research/record_map.py /tmp/bg-k-10502/one.json      # Fhxs
 tag  target  source  writes  bytes  payload expression
    6    146   None       0      0  []
   18    146    311       1      0  (YI = z(311,this))
   23    146   None       0      0  Q9(2,n).concat(AY(n))
   99    146    473       1      4  Q9(2,T.length).concat(T)
  117    146   None       0      0  Q9(1,this.K+1>>1)
  132    146   None       0      0  Q9(2,g.length).concat(g)
  231    146   None       0      0  []
```

and the same shape on the other families, with their own ids:

| tag | Fhxs (146) | EON (299) | pBm (366) | payload |
| --- | --- | --- | --- | --- |
| 18 | field 311 | field 163 | field 2 | `len16 + field` |
| 99 | field 473 | field 456 | field 375 | `len16 + field` |
| 117 | — | — | — | `len1 + (counter+1>>1)` |
| 132 | — | — | — | `len16 + field`, sliced at 1E6 |
| 23 | — | — | — | `len16 + RNG(n)` |

**The 99 record is a verbatim copy of the field it names.** One Fhxs run: field 473 was written
`[93,166,152,25]` and the tag-99 payload is `00 09 5d a6 98 19 39 b0 07 f4 94` - the same four bytes
(`5d a6 98 19`) right after the length prefix. That is the section-37 "field values appear verbatim"
observation, now with the record that carries it.

**Why a run shows only four flags (117, 98, 99, 23) and not all eight tags:** the call sites are
guarded by their source field's length - `YI.length>0&&qj(...,146,18)`, `T.length>4&&ax(...,99)`,
`g.length>4&&(n>0&&qj(...,146,23))` - and in these runs fields 311 / 2 / 163 are empty (their write
log entry is a 0-byte write), so 18 and 132 are never emitted, while 6 and 231 sit on a branch that
did not run. The tag table is the format; which tags appear is data-dependent.

**These source fields are seeded before the program reads anything.** Every write the map finds for
them has `readsCompleted == 0`, i.e. it lands before the first program read (the page's setup values:
`117 = 2048`, `23 = 253`, `99 = 6`, `473 = [93,166,152,25]`, and `146 = [184,0,0]` in the same run).
So the informational records of a normal token are *inputs plus the head template*, not something the
program collected - which is the opposite of what "botguard collects environment data" suggests, and
it matters for a reimplementation: those values come from the caller, not from a VM computation.

What is still open on this line: the two computed records (`117` = counter `this.K`, `132` = a field
sliced at 1E6) and the exact provenance of the seeded fields (which caller-side step writes 473's four
bytes). Both are narrow; neither needs the VM's program.

## 43. Pinning the RNG shows exactly which bytes are random: the nonce, the bulk, and field 473's seed

Section 42 left "where do the seeded bytes come from" open, and section 41 argued the bulk is filler
from entropy alone. Both are settled by one substitution: replace `Math.random()*255|0` (one site per
build, inside the filler function) with the constant `170` in the interpreter text, mint once, and
compare. Tool: `research/probe_rng.py`.

One run (U5tYCxBAtKrhIfdN, emit-only, token field 134, 621 bytes):

```
token head          aa b4 b8 b4 ee d0 00 06 0b 77 65 eb 2b 77
                    ^^ nonce[0] pinned          ^ marker intact
nonce[0] ^ nonce[1] 0x1e                        (the C[1]=C[0]^30 invariant still holds)
tag 23  payload     02 01 | aa aa aa aa aa aa aa aa ...     len16 = 513, all filler
tag 99  payload     00 09 | aa aa aa aa | 11 f0 21 76 c5     first 4 pinned, last 5 not
```

Reading:

* **the 2-byte nonce is the RNG's output** - `token[0]` became `aa` and `token[1]` became `aa^0x1e`,
  so `AY(2)` in section 1 is exactly this filler function;
* **the bulk is the RNG's output** - every byte of the 513-byte body is `aa`, which closes the
  question instead of inferring it from entropy (section 41);
* **the tag-99 record's first 4 bytes are the RNG's output too** - it starts with four `aa` (that
  field is 473 in the Fhxs run of section 42, a different id here), so the value that appears verbatim
  in the token is `RNG(4)`, not something the page passed in. The "caller input" reading of section 42
  is therefore right for the *counter* fields (117 = 2048, 23 = 253, 99 = 6) but wrong for this one,
  which is generated;
* **the last 5 bytes of the tag-99 record are not RNG** (`11 f0 21 76 c5` stayed random-looking), so
  that record is 4 random bytes + 5 bytes from somewhere else - the one remaining unknown in an
  otherwise accounted-for token.

So a normal token is: head template (program instructions) + four records, of which the bulk and the
first four bytes of the 99 record are randomness and the rest are small caller-set numbers plus five
unexplained bytes. For a reimplementation that means the only content that must be *computed* is those
five bytes and the counter records; everything else is a template or an RNG draw.

Reproduce:

```
python3 research/probe_rng.py --port 10530 --out /tmp/bg-rng
```

## 44. The five unexplained bytes: what they are not, and the instrument that is left

Section 43 pinned the filler function and left the last five bytes of the tag-99 record unexplained
(`11 f0 21 76 c5` in one run). Four exclusions, all measured, so nobody spends a round on them again:

| candidate | test | result |
| --- | --- | --- |
| the filler RNG | `Math.random()*255\|0` -> 170 | first 4 bytes become `aa`, the last 5 stay random |
| any `Math.random()` | all 6-7 sites -> `0.5` (two runs) | last 5 still differ (`47 0b 7a eb 98` vs `74 68 02 e1 3a`) |
| `+new Date` | all 6 sites -> constant, with the RNG pinned (two runs) | last 5 still differ (`41 1e a4 ff 42` vs `24 98 f6 9f 33`) |
| an emitter call | full emission logs of four families | **no 5-byte emission into that field exists in any run** - its only emission is the tag-98 `00 02 xx yy` |

So the bytes are not from `Math.random`, not from a wall-clock read, and not produced by `ax`/`qj` at
all. Since the field demonstrably holds them (the tag-99 copy is `len16 + field`, and the length is
9), they must arrive by **direct index assignment** (`field[i] = v`), which is invisible to both the
emit hook and the push/concat hook - section 37 already saw that shape in the writers
(`L[G++] = e`), and the interpreter contains the same pattern on fields (`w(this,117)[0] = c.shift()`).

The instrument that would catch it: a `Proxy` over the field buffer, or `Object.defineProperty` on the
indices the copy will read, installed from the accessor patch (the accessor is already located for the
field-read hook). It has to be a Proxy over the *array*, not a hook on `Array.prototype`, and the
accessor returns `create()` or `prototype` depending on the slot state, so both branches need covering.

Trap worth recording: pinning `performance.now()` to 0 (together with the date pins) does not merely
leave the bytes random - the whole mint degrades to a 33-character token, i.e. an error answer. The
timing source cannot be neutralised that way, so it is not a usable discriminator.

---

One-page distillation of sections 1 and 36-44 (shape, op table, tag table, what is random, what is
still open): `docs/token-format.md`. Read that first; this file is the evidence.

## 45. The Proxy over the field accessor sees nothing: the exposed object is not the storage

Section 44 named a `Proxy` over the field buffer as the instrument for the last five bytes. It is
implemented (`bgpatch.patch(..., ixproxy=True)`, `run_one.py --ixproxy`) and it **does not work**, for
a reason worth recording.

What it does: every accessor the emitters call (`vm.h[id]` on Fhxs, `vm.G[id]` on EON, `vm.l[id]` on
pBm - the table name rotates) gets *every* `return` wrapped in `__ix(id, value)`, which returns a
cached `Proxy` (WeakMap per target, so identity comparisons keep working) whose `set` trap logs
`[fieldId, index, value]` to `window.__ixlog`. Verified offline on four families: 2-5 returns
wrapped, `node --check` clean, and the `return(expr)` -> `return __ix(...)` rewrite needs an explicit
space (`return__ix(...)` parses as a call to an identifier called `return__ix`, is valid JavaScript,
and silently returns `undefined`).

Measured live: 25 emissions and a normal-length token, **`__ixlog` empty**. So no index assignment
ever happens on the object the accessor returns. That is consistent with section 2's anatomy of a
slot - "an object dressed up as a function" whose `create`/`concat`/`push` are its own methods - i.e.
the bytes are appended to an array the object closes over, not to the object itself. Wrapping the
object's indices can never see them.

The instrument that is left, therefore, is not a Proxy over the object but a wrapper around **the
slot's own methods**: replace `a.push` / `a.concat` on the returned object with loggers that record
`(fieldId, method, arguments, length before/after)`. `probe_concat.py` already showed the shape works
(it hooked `Array.prototype` and saw 966 pushes into the token field, `n = 88..1053` with no gaps);
the missing piece is doing it per *slot object* so the field id is known, and checking the tag-99
source field specifically rather than the token field.

Two things this round did establish, independent of the five bytes:

* the accessor returns `create()` on one branch and `prototype` on the other (`if(L.value)return
  L.create(); return ...prototype`), so any instrument that only wraps one branch measures half the
  traffic - the same class of mistake as the emit hook logging `data` but not the flag byte;
* `--ixproxy` costs nothing when off, and with it on the token and the emission log are unchanged
  (25 emissions, trusted length), so the wrapping itself is inert rather than harmful.

## 46. The five bytes are closed as a known unknown: both instrument routes are dead ends

Section 44 proposed a `Proxy` over the field buffer, section 45 showed the proxy version is inert.
This section records the two further attempts and why the line is being closed rather than continued.

**Attempt 2 - wrap the slot's methods (not its indices).** Replaced the Proxy with per-slot wrappers
around `push`/`concat`/`create`, logging `(fieldId, method, length before/after, first argument)`.
Offline clean on Fhxs/pBm; live: 457 emissions (vs the usual ~20), `__ixlog` empty. Wrapping the
*definition* by name is the flaw - names are reused within one build (section 15), so the wrapped
`z`/`w` is not the function the emitters call.

**Attempt 3 - wrap the emitter's own call expression instead of the definition.** This is the correct
shape (it is the same function object by construction), and it exposed the real blocker with a clean
measurement: an **entry counter injected into the accessor body read 0 while 21 emissions fired**
(and 0 again on an EON run with 18). So the emitter that produces the emissions does not go through
the accessor whose call sits in its text - i.e. the copy that runs is not the copy that is being
instrumented, which is the section-24 problem in a new place.

**Attempt 4 - inline the wrapper at the call site** (a named helper appended to the source is not in
scope in the running copy, and its `ReferenceError` aborts the patched mint while the page's pristine
copy still returns a token, which is exactly why the counters read 0). This one does not compile yet:
the call-site offsets are collected *before* the emit-hunk injections, which shift the text, so the
replacement lands in the wrong place (`node --check` fails). Fixing it needs `patch_emit` split into
detect -> inject -> re-detect, which is a real refactor, not a tweak.

Decision: stop. The five bytes are 5 of ~750 in a token that is already accounted for everywhere else,
they do not participate in the trust decision (length, marker and nonce all unaffected), and four
attempts have cost more than the format work they would unlock. Recorded as a known unknown:

* the tag-99 record is `len16 + field`, the field is `RNG(4)` + 5 bytes;
* those 5 bytes are not `Math.random`, not the clock, not an emitter call (section 44);
* they are appended to the slot's internal array, which no instrument installed so far can see.

If someone reopens it: the two-pass refactor of `patch_emit` is the prerequisite, and the measurement
that says you have it right is the accessor entry counter being non-zero on a run with emissions.

**What is left that is worth more:** the head template. The op table (163 / 460 / 490 / 118) and the
record table are specified; what is not yet done is proving where the *source fields* of the head
chunks (the marker, the 64-byte block, the two 4-byte words) get their values - that is the body of a
reimplementation, and unlike these 5 bytes it is measurable with the tools that already work
(`record_map.py` joins a field to the op that wrote it).

## 47. The head's source fields are filled by a tiny writer family: `write(width, 0, value, N)`

Section 39 mapped the head chunks to emit instructions `[op, sourceField, tokenField]`. The missing
half was who fills those source fields. Tool: `research/head_map.py` (per head chunk: emit op, source
field, and the op that wrote that field with its handler text). One Fhxs run:

```
  #  bytes  emit-op  src  who wrote src        handler
  1     1      163  113  op 20  x66     function(){R(30,0,u,1)}
  2     2      490    6  op 425 x3      function(y,p,X,C,H,U){while(11)if(G6/=G6 ...   <- the marker
  3     6      490    6  op 425 x3
  4     1      163   66  op 20  x2      function(){R(30,0,u,1)}
  5     4      460   28  op 308 x2      function(){R(31,0,V,4)}
  6     4      460   60  op 308 x6      function(){R(31,0,V,4)}
  7     1      163   62  op 20  x2      function(){R(30,0,u,1)}
  8     2      490   57  op 425 x67     ...
  9    64      490   57  op 425 x67
```

and the same shape on EON (`op 72  function(){K(0,40,c,1)}`, `op 87  function(){K(0,42,D,4)}`) and pBm
(`op 21  function(){st(0,(zQ>>=66,1),8,c,6)}`, `op 106 function(D){lf=(st(0,4,8,D,7),qs>>211)}`).

Reading: the head's values are produced by a **writer family of one shape**, `write(tag, 0, value, N)`
- `N` is the width (1 or 4 in the examples), the third argument is the value, and the whole handler is
one call. The marker (6 bytes) and the 64-byte block come from a longer handler (op 425 in Fhxs,
133 in EON, 337 in pBm) that produces a byte string rather than a word.

So the head is fully accounted for mechanically: `write` ops fill fields -> `163/460/490` emit them
into the token field. What a reimplementation still has to reproduce is the *values* those writers are
handed (the two 4-byte words and the 64-byte block), not the plumbing - and the words are exactly the
kind of thing section 43 showed to be RNG or counters, which is the next thing to check per field.

Caveat: the last row of a run is sometimes an untagged emit (`ax(146, Q9(1, this[zF].length), this)` in
Fhxs) whose source field has no logged writer, so it shows `-`. That is the counter byte, not a
missing record.

## 48. The head splits into per-mint and per-load parts, and the marker is per build

Section 47 said the head is mechanical and the open question was the *values*. Three mints inside one
page load answer it (`/tmp/twice.py` recipe: mint three times from the same `VM.a(...)` instance):

```
build SnVlM0KMiNaWq5YD
  mint0 1064B  cd d3 b8 d3 b7 | d0 00 06 7a 16 4e 5f 5a 16 | 5f 44 31 b4 88 a6 d6 b9 a6 26 00 40 01 10 0a d9
  mint1 1070B  1f 01 b8 01 65 | d0 00 06 7a 16 4e 5f 5a 16 | 5f 44 31 b4 88 a6 d6 b9 a6 26 00 40 01 10 0a d9
  mint2 1070B  01 1f b8 1f 7b | d0 00 06 7a 16 4e 5f 5a 16 | 5f 44 31 b4 88 a6 d6 b9 a6 26 00 40 01 10 0a d9
```

| bytes | value | varies |
| --- | --- | --- |
| 0-1 | nonce, `nonce[0]^nonce[1] == 0x1e` | per mint |
| 2 | `b8` | never |
| 3 | `nonce[1]` | with the nonce |
| 4 | one byte | per mint; constant (`ee`) under RNG pinning, so derived from the same random stream |
| 5-13 | `d0 00 06` + 6 bytes | 6 bytes are **per build** |
| 13-14 | `5f 44` | per load |
| 14-22 | two 4-byte words | **per load** (identical across the three mints) |
| 22-25 | `26 00 40` | never |
| 25-89 | 64-byte block, starts `01 10 0a d9` | per load (same prefix in all three) |

Two corrections to earlier sections:

* **the 8-byte "marker" is per build, not universal.** Section 1 called it "the only thing both shapes
  share", which is true for the two shapes of one build, but the value differs between families:
  Fhxs / EON / pBm emit `00 06 0b 77 65 eb 2b 77`, SnVl / X9X8 / U5tYCx emit `00 06 7a 16 4e 5f 5a 16`
  (stable across runs of the same family). So it must be read from the build, not hard-coded.
* **the two 4-byte words and the 64-byte block are per *load*, not per mint.** That is why pinning the
  RNG or the clock never stabilised them across runs: every run was a fresh load with its own values.
  They are session/environment data (the thing the VM collects), which a reimplementation has to take
  from its caller rather than compute - the opposite of the nonce, which it can generate.

So the head is: 3 bytes of per-mint randomness (2 nonce + 1 derived), a per-build 6-byte tag, and
per-load constants (`5f 44`, two words, the 64-byte block) - the last group being the only part that
carries information about the client.

Still open on this line: how the per-load words are computed (they are not RNG and not the clock -
section 44's exclusions apply to them as well), and whether `5f 44` and the 64-byte block are also
environment-derived. The discriminating experiment is the same one that produced the table: mint
twice, change exactly one input between mints (e.g. `freq`), and see which head bytes move.

## 49. The head does not depend on the request content at all

Section 48 named the experiment: mint with the same inputs, then change exactly one (`freq`, the
content-binding string) and see which head bytes move. Measured, one load, three mints A / B / A:

```
  mint0 A 1080B  b3 ad b8 ad c9 | ... | 5f bd a3 f2 1f e7 36 6e 96 26 00 40 01 10 0a d9
  mint1 B 1083B  23 3d b8 3d 59 | ... | 5f bd a3 f2 1f e7 36 6e 96 26 00 40 01 10 0a d9
  mint2 A 1083B  6e 70 b8 70 14 | ... | 5f bd a3 f2 1f e7 36 6e 96 26 00 40 01 10 0a d9
```

The two 4-byte words (`bd a3 f2 1f`, `e7 36 6e 96`) are byte-identical for A, B and A, and so is
everything else after the nonce. Only `nonce(2)` and byte 4 differ, and they differ between the two
**A** mints as well - i.e. they are per-mint randomness, not a reaction to the input.

So the head carries **no content binding**. If the token is bound to the request body at all (section 1
observed that a token minted for one image is not accepted for another), the binding lives in the
tagged records, not in the head - the candidates being the tag-18 blob, the 9-byte tag-99 record, or
the `n` that sizes the bulk.

Next: byte-diff two tokens whose `freq` differs (A vs B above) after masking the per-mint randomness,
and look for a region that is stable between two A mints but changes on B. That is the only remaining
way to find a content hash without decoding the records, and it needs the tokens saved, not just their
heads.

## 50. A/B/A diffing finds no content-bound byte, and points at the record that is always empty

Section 49 left one test: diff two tokens whose content string differs, masking per-mint noise. Tool:
`research/diff_tokens.py` - mint A, B, A' in one load (B differs only in `freq`), then treat
everything that differs between A and A' as noise and ask whether B differs from A anywhere that A and
A' agree.

```
build FhxsKBPKEL3Q_7SA   lengths A 1076  B 1082  A' 1082
  A  head 82 9c b8 9c f8 | marker | 5f 74 33 50 60 3c ec 5d b2 26 ...
  B  head 6c 72 b8 72 16 | marker | 5f 74 33 50 60 3c ec 5d b2 26 ...
  A vs A': common prefix from 5 = 93 B, common suffix = 0 B
  content-sensitive positions: 0
```

Reading:

* the **first 93 bytes after the nonce are stable across mints** - that is the head (3 + 9 + 4 + 4 + 1
  + 2 + 64 = 87) plus the first few record bytes - and B matches A on every one of them;
* **nothing after that is stable**: the common suffix between two mints of the *same* input is 0
  bytes, so the whole tail (records + bulk) is per-mint. The 6-byte length difference between A and A'
  is in that tail, not a reaction to B;
* therefore no byte of the token that a caller could see is a function of the content string, at least
  for a synthetic `freq`.

Where the binding can still be: the **tag-18 record**. Its payload is `len16 + field(311)`, its call
site is guarded by `YI.length > 0`, and in every run measured so far that field was empty (a 0-byte
write), so the record never appears. That is exactly the record a content hash would live in, and the
reason the diff above cannot see it. Testing it needs a `freq` that actually populates the field - i.e.
a real `f_req` for the live RPC rather than `research/freq.txt`'s shape - which is a load-generation
problem, not an instrumentation one.

Until then, the honest summary is: the token's stable content is per-load environment data plus a
per-build tag; the per-mint tail is randomness; no content binding was found in any part a synthetic
request exercises.

## 51. Same build, two payloads: the mint does not encode the content

Section 50 diffed token bytes and found nothing content-sensitive; the weakness was that the two mints
were of the same *shape*, so a size effect could have been hidden. Tool: `research/probe_payload.py` -
one load, one patched instance, mint with payload A, then with payload B (A = `freq.txt`, B = A plus
one form field), and compare the **mint-phase** emissions. The head chunks are emitted while the API is
being built (`VM.a`), so the baseline is taken after setup; only what the mint itself emits is compared.

```
build SnVlM0KMiNaWq5YD   freq A 2075 chars  freq B 2080 chars
  A: token 904 chars  emissions 5   fields [307, 483]
  B: token 904 chars  emissions 5   fields [307, 483]
  same emission shape: True

build X9X8Htl1zljiC_ED
  A: token 1028 chars  emissions 5  fields [154, 478]
  B: token 1028 chars  emissions 5  fields [154, 478]
  same emission shape: True
```

Two builds, same result: the mint emits the same fields with the same lengths and the same tags, and
the token has the same length, for two different payloads. Together with section 50 (no byte of the
stable region reacts to the content) that settles the client side:

* the token is **not** a function of the `f.req` body - not as a hash, not as a length, not as a
  field that switches on;
* so the "a token minted for one payload is not accepted for another" observation of section 1 is
  enforced on the **server** against the envelope (`f.sid`, `bl`, `_reqid`, the attested headers) or by
  comparing the token's freshness against the request, not by a digest inside the token.

Consequence for a reimplementation: the token's per-load constants are environment data, the per-mint
bytes are randomness, and the payload does not have to be reproduced in the token at all. That removes
the largest imagined obstacle (hashing the body) from the offline-mint problem - what remains there is
the trust gate of section 1, which is a different question.

A caveat worth keeping: all of this is measured with `freq` as the only varied input. If a future
capture shows the token changing with the *image* but not with a JSON string of the same size, the
difference would have to come from a field that reads the payload's bytes rather than its length -
nothing in the emission log suggests one exists, but it has not been excluded for every build.

## 52. The spec is executable: the assembler reproduces five tokens byte for byte

`docs/token-format.md` describes the layout; `research/assemble_token.py` implements it. Round-trip mode
takes one run's emissions as pieces, rebuilds the token **from the layout** (not from the token), and
compares:

```
pBm  366  13 emissions  tagged [(117,1),(99,11),(23,665)]   assembled 771 vs 771  identical=True
EON  299  ...                                                764 vs 764  identical=True
Fhxs 146  ...                                                729 vs 729  identical=True
X9X8 478  ...                                                799 vs 799  identical=True
U5tY 134  ...                                                835 vs 835  identical=True
```

Five families, byte-identical. Two things this pinned down that the prose model had wrong:

* **untagged chunks are interleaved with the tagged records.** The `07` byte (the `zF` counter) comes
  *after* the tag-117 record, not before the first tag, so the stream cannot be split into "head" and
  "records" - it is one ordered list of `(tag?, payload)`. The first assembler version dropped that byte
  and was off by exactly one at offset 92 on every build.
* **the head is not a separate phase in the byte stream**: `nonce(2) + [b8, nonce[1], byte4]` is the
  only prefix; everything after it is the emission stream in order.

`--fresh` is the offline-minter prototype: keep the per-load constants, generate a new nonce, regenerate
the bulk, and emit a token of the same length with the marker intact. What it does **not** answer is
whether Google accepts it - that is section 1's trust gate, and testing it needs a live request with a
full envelope (cookies, `f.sid`, `bl`, attested headers), i.e. a decision about sending a synthetic
token to the service rather than another read-only measurement.

## 53. One live request with an assembled token: the format is accepted, the echo is the environment

Section 52 left one question: does the service accept a token whose nonce and bulk were generated
outside the VM? One controlled request, no retries (approved as a single attempt):

* one page load in headless Chrome, desktop UA: cookies, `f.sid`, `bl` and a patched mint from that
  same load (the per-load constants);
* `research/assemble_token.py --fresh` rebuilt the token with a new nonce and a fresh bulk - same
  length as the captured one (895 chars);
* one POST to `/TranslateWebserverUi/data/batchexecute` with the wrapped bgr header
  (`[token,null,null,214,4,null,null,0,"2"]`), the attested client hints, the page's cookies, and the
  image (`BACKUP JOB FAILED ON NODE DB-07`, 1000x260, clear text).

Result:

```
HTTP 200
wrb.fr payload: 1 element  ->  [[<base64 image>, "image/png"]]
the returned image is byte-identical to the upload (sha256 match)
```

Reading:

* **the token verified.** A token that fails verification answers `400` with an `er` chunk (section 1);
  this one did not. So the assembled bytes pass whatever structural check the server runs - the
  format work is complete enough to be accepted as a token.
* **the response is the degraded echo, not "no text found".** The image carries large clear text and
  the echo is byte-identical to the upload, which is the signature section 1 documented for a client
  the service does not trust (`[[b64, mime]]` with nothing extracted). "No text found" would have to
  come from OCR that ran and produced nothing, which is implausible for this image.
* **so the discriminator is not the token's bytes.** A byte-correct token from an untrusted
  environment is still served the echo - which is the section-1 conclusion reached from the opposite
  direction: the gate attests the client, not the token.

Caveats, stated plainly:

* the constants came from a *patched* mint in headless Chrome, i.e. exactly the client that gets
  degraded; a browser-minted token in the same envelope is the missing control, and it would cost a
  second request (not run, per the single-attempt rule). Section 21's shipped-path measurement
  (in-process signer, real image, `found_text=True`) is the informal stand-in;
* the envelope was rebuilt by hand (cookies from the load, fixed `_reqid`), so "the envelope was
  wrong" cannot be fully excluded as the reason for the echo - but a wrong envelope answers `400`,
  and this was a clean `200`;
* one request is one data point; nothing here says a *trusted* client would accept a synthetic token,
  only that the token itself is not what the gate is looking at.

Reproduce: `python3 research/live_test.py --port N --out DIR` (add `--dry-run` to stop before the POST).

## 54. The control overturns section 53: a pristine token in the same envelope gets OCR

Section 53 sent an assembled token and got the echo, and concluded that the gate attests the client
rather than the token. The control it named - a browser-minted token through the *same* hand-built
envelope - was run once (one request, no retries):

```
control token 1429 chars (shipped signer, build wlvZkA...), captured-in-load mint 1163 chars
HTTP 200  class=accepted
  payload: ['BACKUP JOB FAILED ON NODE DB-07\n\nERROR CODE 1284 - RETRY ABORTED',
            '节点 DB-07 上的备份作业失败\n\n错误代码 1284 - 重试已中止', 'en']
```

So the envelope is fine (it carries OCR with a pristine token), and **section 53's conclusion is
withdrawn**: the echo was not "the environment, not the token". With the same cookies, `f.sid`, `bl`,
headers and image, a 1429-character token returns text and an 895-character assembled token returns the
echo.

What that means:

* the gate is **not about the token's format** - the assembled token verified (no `400`/`er`), so its
  structure is right;
* the gate **is** about the token's content: the difference between the two tokens is the per-load
  constants (the environment snapshot) and the length regime (895 vs 1429 chars, i.e. the
  instrumented/degraded branch versus the trusted one);
* the assembled token inherited its constants from a **patched** mint, and instrumentation is exactly
  what pushes the VM onto the degraded branch (section 24: instrumented runs land at 600-1300 chars
  instead of 1405-1447). So "assemble from a captured token" and "capture with the emit hook" are
  mutually exclusive as done so far - the capture destroys the trust it needs to preserve.

The next experiment that would settle it does not need the emit hook at all: **parse the per-load
constants out of a pristine trusted token** (they are in the head: `5f 44`, the two 4-byte words, the
64-byte block), assemble a token with a fresh nonce and fresh bulk around them, and send it once. If
that is accepted, the constants are reusable and an offline minter is feasible with a one-time
trusted capture; if it is echoed, the token's freshness/nonce is bound to the mint and the offline
route is closed for good. That is one more request, so it is left for an explicit decision.

## 55. Re-randomising a trusted token's nonce is enough to lose the OCR

Section 54 proposed: parse the constants out of a pristine token, put a fresh nonce (and a fresh bulk)
around them, send once. The bulk could not be located - a trusted token has **no `0x17` tag-23 record**
(a scan of the last 1200 bytes finds no `[0x17][len16][...]` ending at the token end), so its tail is a
different format from the instrumented tokens of sections 41-52. What was possible is the nonce half:

```
pristine 1419 chars (1063 B)      from the shipped signer, trusted range
re-randomised 1419 chars          only bytes 0,1,3 changed: new r, token[1] = r^0x1e, token[3] = token[1]
HTTP 200  class=verified/echo     1 element, the returned image is byte-identical to the upload
```

So a token that the control (section 54) got OCR from, with **two bytes of nonce changed**, is served
the echo - while its structure still verifies (`200`, no `400`/`er`). The service binds the token to
its nonce.

**Confound, stated plainly:** byte 4 is derived from the same random stream (section 48) and was left
at its captured value, so "stale byte 4" is an alternative explanation for the echo. Separating the two
needs one more request that changes **only byte 4** and leaves the nonce intact: accepted would mean
byte 4 is inert and the nonce is the bound value; echoed would mean any single-byte edit breaks it,
i.e. the whole token is authenticated.

What this already rules out, together with section 54:

* an offline minter cannot take a trusted token and re-randomise it - the nonce (or its companion byte)
  is inside whatever the server authenticates;
* the assembled token of section 53 was not rejected for being malformed, it was rejected for not
  carrying a trustworthy environment - which is consistent with the token being a MAC over
  VM-generated values, not a serialisation the caller can re-derive.

The practical conclusion stands and is now better supported: the Chrome sidecar is the only working
signer, and the token is not something a reimplementation can mint from the outside.

## 56. Any single-byte edit of a trusted token loses the OCR: the line is closed

Section 55 left one discriminator: change **only byte 4** (the RNG-derived byte, nonce untouched) and
see whether the echo is caused by the nonce being bound or by any edit at all. One request:

```
pristine 1419 chars (1063 B)   byte4 d5 -> 2a   nonce untouched (af b1)   same length
HTTP 200  class=verified/echo  1 element, image byte-identical to the upload
```

Combined with the previous two requests:

| token sent | edit | answer |
| --- | --- | --- |
| assembled from a patched mint's constants | many bytes | `200` echo |
| pristine, re-randomised nonce (bytes 0/1/3) | 3 bytes | `200` echo |
| pristine, byte 4 only | 1 byte | `200` echo |
| pristine, unmodified (control) | none | `200` **accepted**, OCR + translation |

So **no single byte of the token can be changed without losing the OCR**, while the unmodified token
gets it. The token is authenticated end to end: the values the VM generates (nonce, the derived byte,
the per-load constants) are inside whatever the server checks, and the structure we reverse-engineered
is the *encoding* of that authenticated blob, not a document the caller can rewrite.

That closes the offline-mint question, definitively:

* the format work (sections 36-52) is complete and executable - `assemble_token.py` rebuilds real
  tokens byte for byte, and the server accepts the *structure* (no `400`/`er` for our builds);
* but a token cannot be **constructed** outside the VM: every byte is authenticated, so the only
  tokens that work are ones the VM itself produced;
* what remains possible outside the VM is what section 1 already measured: **replay** a freshly minted
  token (it stays valid for minutes and is payload-independent per section 51), which is exactly what
  the shipped sidecar does.

Practical consequence: nothing changes for the product. `bgr_sidecar.py` stays the signer, `/translate`
needs no token, `/translate/image` needs the sidecar, and local OCR remains the browserless option for
images. The research line is finished; the remaining open item (the tag-99 five bytes, section 46) is
cosmetic and does not affect any of the above.

The three remaining open items (tag-99 five bytes, per-load constant provenance, authentication
construction) have their own handoff: `docs/HANDOFF-OPEN-ITEMS.md`. Start there.

## 57. The build material needs no browser, and the interpreter runs in Node

Sections 1-56 treated "the VM only runs in a browser" as the boundary. It is not the material's
boundary: everything the VM needs ships *inline in the document*, so a plain `urllib` GET is enough.

```
python3 research/fetch_build.py --out /tmp/bgbuild
# build U5tYCxBAtKrhIfdN  interp 66581 B  blob 30123 B  proto fields 8
```

`arr[0]` is the program blob (a base64 string with a 3-char prefix), `arr[2]` the interpreter hash,
`arr[5][-1]` the interpreter source. No cookie, no UA beyond a desktop one, no JS execution.

**The interpreter's whole environment surface is statically readable, and it is small.** Grepping the
66 KB of minified source for every host object gives: `window.performance.now` (falls back to
`+new Date`), `document.hidden`, `document.body`/`documentElement.lastChild`,
`document.createElement("iframe")` + `style.display` + `src` + `load`/`error` +
`contentWindow.location.href`, `window.btoa`, `e.trustedTypes`, `e.requestIdleCallback` /
`e.setImmediate`, `Math.random`, `setTimeout`/`setInterval`, and `eval`. **`navigator` does not appear
in the source at all** - not once, in any build measured. So whatever a browser contributes to the
token, it is not `userAgent`/`plugins`/`webdriver`/`screen`; section 4's "copying the environment into
jsdom does not help" was chasing a surface the interpreter never reads.

`research/node_mint.mjs` is the harness: `node:vm` contexts as realms, a ~150-line DOM shim, no
browser and no jsdom. It boots the VM for real:

* `VM.a(arr[0], cb, true, document.body, noop, [[],[]], undefined, false, [noop x5])` returns the API;
* the VM creates the iframe, sets `src` to `/_/TranslateWebserverUi/bscframe` (the interpreter resolves
  it against the document itself), waits for `load`, and records the boot profile;
* the frame realm is a *second* `vm` context, so it has V8's own intrinsics and a genuine native
  `eval` - the thing jsdom cannot provide;
* the interpreter is eval'd inside that frame (64-69 KB, padded with random newlines), and the program
  runs there;
* a token comes back.

Boot profile recorded by the VM in Node: `A = [82, 0, 1, 15, 21]` - load on attempt 1, 0 ms load
time, 21 ms from boot start. Chrome's own run records `[82, 0, 1, 15, 1399]`: same event sequence,
real network latency. The frame path itself works outside a browser.

## 58. The Node token is byte-identical to a trusted token for its first 90 bytes

Same build material, minted twice: once in headless Chrome (the shipped path, section 21) and once in
Node. Chrome: 1435 chars / 1075 B. Node: 2893 chars / 2169 B.

```
chrome  4a 54 | b8 54 30 | d0 00 06 7a 16 4e 5f 5a 16 | 5f 2b b0 0e ee 80 e2 f2 c8 26 00 40 01 10 0a ...
node    fd e3 | b8 e3 b9 | d0 00 06 7a 16 4e 5f 5a 16 | 5f 2b b0 0e ee 80 e2 f2 c8 26 00 40 01 10 0a ...
              ^ per-mint                        ^ identical from offset 5 to offset 89
```

Measured on both: bytes 5..89 are identical - the head template, the per-build marker, `5f`, both
4-byte words, `26 00 40` and the whole 64-byte block. Only the per-mint bytes differ (the 2-byte nonce
and the derived byte at offset 4). So the "per-load constants" of section 48 are **not** an environment
snapshot: a Chrome realm and a Node realm produce the same ones from the same material. They are
build/material-derived, and the environment does not enter the head at all.

The two tokens diverge at offset 90 and differ in *length*, so the rest of this section is about the
tail: what the VM appends after the head, and why a browser gets a short one.

## 59. The VM records its own caught exceptions into the token - that is the length regime

The emit hook (`research/bgpatch.py`, emit-only patch) runs on the Node side too, and it explains the
whole difference. 24 emissions in one Node mint:

```
token field <- 1,2,6,1,4,4,1,2,64   the head, 85 B (identical to Chrome's)
field 274   <- 858, 870, 2, 314     tag 23 records, flag 0x17
token field <- 5 (tag 18), 1 (tag 117), 1 (untagged), 7 (tag 98), 14 (tag 99), 2054 (tag 132)
```

The 2054-byte tag-132 payload decodes to plaintext, and it is not padding:

```
03 58 "Cannot read properties of null (reading 'String'):TypeError: Cannot read properties of
       null (reading 'String')\n    at eval (...) ... at Yq ... at sn ... at d.eval [as R] ..."
03 64 "Cannot read properties of undefined (reading 'replace'):TypeError: ..."
01 38 "V.apply is not a function:TypeError: V.apply is not a function ..."
```

That text is built by the error collector `V_` in the interpreter source:

```js
X="", k&&(k.message&&(X+=k.message), k.stack&&(X+=":"+k.stack)),
y=C(J,468), y[0]>3;            // field 468's first byte is a byte budget
  X=X.slice(0, y[0]); y[0]-=len; X=b7(2,X,J.T)   // b7 = the encoder, so the text is not plaintext in the token
```

So every exception the VM catches anywhere in the program is appended - message + `":"` + full stack,
encrypted, length-capped by the budget in field 468 - and emitted as a **tag-132 record** into the
token field. Consequences, all measured:

* a **trusted** mint catches nothing, so it has no tag-132 record. Chrome's own concat profile for this
  build is `[2,894,896] [2,1072,1074]` - two fields, no error field, 1074 B total;
* a mint in a realm that makes the program throw carries the recorded text instead: 2054 B of it here,
  which is why the Node token is 2169 B and why jsdom landed at 2114-2170 B;
* section 2b's degraded profile - nine fields including **three byte-identical 542-byte blocks** - is
  the same mechanism: three caught exceptions of equal length, recorded three times. The "degraded
  token" is not a weaker token; it is a token with a crash log in it;
* instrumentation makes the VM throw (a hook that runs inside the VM's own path), which is why
  patched runs land in the long regime. The length is a symptom, not a branch decision.

The first error in Node is `Cannot read properties of null (reading 'String')`, thrown inside the
program's handler `GK`, which the program calls with `u === undefined`; the program then stops
advancing (2 handler evals, then the error path), and what follows is the tail above. Chrome does not
throw there.

**Ruled out as the cause** (each one measured, token length unchanged at 2893 chars): `document.hidden
= true`; `performance.now() -> 0`; adding `trustedTypes` + `requestIdleCallback` to the realm (Chrome
has both, a bare `vm` context has neither); delaying the frame's `load` by 1 / 200 / 1200 ms (Chrome
takes ~1.4 s because the frame is fetched over the network, Node fires immediately - it does not
matter).

## 60. What the frame realm does that a plain realm does not: it evals its own helpers

`Debugger.scriptParsed` on a Chrome mint shows 245-260 *eval'd* scripts in the mint's frame realm, all
with an empty URL, and they are the interpreter's own pieces:

```
[]  ({})  1  js  $q  a$  d  C
C=function(J,k,u){...}   a=function(...){...}   q=function(...){...}   E=function(...){...}
Z=function(...){...}     YU=function(...){...}  fC=function(...){...}  Ss=function(...){...}
0,function(z){fC(6,z,21,0,1)}   0,function(z,g,V,L){L=n(h,32),V=W(5,z);...}
var eval="wbytsbazhn";eval      (1).toString(0)   new Array(-1)   null.x
```

Read: the program does not just *run* in the frame realm, it **rebuilds the interpreter there by
eval'ing source strings** - helper definitions as sloppy-mode global assignments, identifiers on their
own, and deliberate error probes (`null.x`, `new Array(-1)`, `(1).toString(0)`) whose *messages* are
mined for strings. That is the self-hosting step of section 26's "the inner text is patchable", seen
from the other side: the frame realm is an eval sandbox, and the program's own instruction stream is
what feeds it.

Two traps measured on this line:

* **A `console.log` inserted at the handler-eval site changes what the handler can resolve.** Patching
  `function(w){return eval(w)}` to log the source first makes the very first program handler throw
  `fC is not defined` - an error the pristine run does not have. The helpers are IIFE-locals reachable
  only through the direct eval's scope chain, so any rewrite of that call site is a behavioural change.
  Observe from `Array.prototype`/`btoa`/`Debugger`, never from the eval site.
* **The frame realm's globals are not where the helpers live.** After a completed Chrome mint,
  `typeof fC === "undefined"` inside the frame context (`Object.keys(window).length` 238). The eval'd
  `fC=function(...)` assignments resolve inside the eval scope, not on the window. A Node realm with 37
  globals and no `fC` is therefore *not* by itself evidence of a broken realm.

## 61. Where the browserless mint stands

Reproduced without a browser: the material (urllib), the interpreter install, the iframe boot, the
frame realm, the program's eval sandbox, the head template and the per-build constants - the Node
token's first 90 bytes equal a trusted Chrome token's. Not yet reproduced: the program's full
instruction sequence in a synthetic realm. It advances two instructions and then throws, and the
recorded text is what makes the token long.

The open question is now narrow and instrument-shaped: **which value the program reads makes `GK` run
with `u === undefined`** (and, downstream, `L.ue` not a function in the `V.apply` handler). Candidates,
in order of cheapness to test in `research/node_mint.mjs`: the field-seeding order (the two
`fC(6,z,2x,0,n)` writes happen before the error), `document.body`'s identity as passed to `VM.a`, and
the element surface the program touches (section 57's list is the complete read surface, so any missing
member is enumerable). `research/probe_realm.py` gives the same-build Chrome control for every step:
boot profile, concat/field profile, pre-encode token bytes and the eval'd script list.

## 62. The frame copy is generated, its eval is scope-bound, and where the program throws

Four things measured on the Node line after section 61, all of them about *how to observe* as much as
about what is there.

**The frame copy is assembled per run from the page's interpreter text.** The VM does not eval the text
it was handed: it builds a variant (62 016-62 080 chars of code plus 400-7 800 random newlines, so the
same stack position reports a different *line* every run but the same *column*). Text patches to the
page copy **do** reach it - an `ERRSTACK` log inserted in the page text shows up inside the captured
frame source - which is why the emit hook of section 59 works from the page copy. This corrects the
earlier reading of section 24: the signing instance's text is generated, not pristine, and it inherits
what the page copy says.

**`A.eval(...)` cannot be routed through another frame.** The boot eval is `b=A.eval(Z(...)(...))`. Even
a semantics-preserving call-through - `b=(function(s){capture(s);return A.eval(s)})(SRC)` - changes the
program: it then throws `Eb is not a function`, then `fC is not defined`, and runs a different number of
instructions. So the callee is the interpreter's *own* eval, bound to its scope chain (that is how the
eval'd program handlers resolve `fC`, `q`, `E`, `Yr`), and every observation must stay off that call
path. The same trap as section 60, one level deeper: not just `window.eval`, the call site too.

**Where the program throws (stable columns, three TypeErrors).**

```
col 32012  Cannot read properties of null (reading 'String')
col 32012  Cannot read properties of undefined (reading 'replace')
col 30177  V.apply is not a function
chain: Yq(23808) -> sn(39477) -> d.eval as R(58964) -> a5(26194) -> Jx(8707) -> HD(10398) -> Timeout
```

The handler at 32012, as it reads in the frame copy:

```js
function(z,g,V,L,Y,w){
  YU(z,(L=(g=C(z,(w=F(z,(V=F((Y=W(14,z),z),5),12)),V)),Z(h,Y))==g,w),+L)
}
```

`C`/`Z` are field readers (`J.u[k]`, throwing `[FK,30,k]` when the slot is missing), `W` is the slot
accessor factory, `F` is the dispatcher, `YU` a field writer. Nothing in the frame copy reads a property
literally named `String` (grep: 0 hits for `.String`), so the name comes from a computed key - i.e. from
the interpreter's own "manufacture a string out of an error message" machinery (`null.x`,
`new Array(-1)`, `(1).toString(0)` are eval'd for exactly that, section 60). The read lands on `null`
because the frame copy's init left something unset, and the two TypeErrors at the same column are the
same expression failing on two different values.

**Two environment facts that are real but not the trigger.** The frame URL is an empty document
(`/_/TranslateWebserverUi/bscframe` -> 15 B, `<!DOCTYPE html>`), so there is nothing to load that the
shim is missing; but its CSP is `script-src 'unsafe-eval'; require-trusted-types-for 'script'`, so in
Chrome every eval inside the frame must go through a Trusted Types policy. Adding a fake policy, plus
`requestIdleCallback`, plus the Window surface a bare realm lacks (`length`, `frameElement`, storages,
`crypto`, `customElements`, `document.URL/scripts/all`), leaves the token at 2893 chars - measured, four
variants. Not the trigger.

**Node's inspector cannot trace this throw.** `Debugger.setPauseOnExceptions('caught')` and `('all')`
both produce exactly one pause (`Break on start`, no frames) - before and after
`runIfWaitingForDebugger` - even for a plain `try{vm.runInContext('null["String"]')}catch{}`. So
`research/node_inspect.py` can list scripts but cannot hand out the throw site; the remaining routes are
`Debugger.setBreakpointOnFunctionCall` on the frame's eval object, or the bytecode tools
(`disasm.py` / `read_records.py`) against the program itself.

## 63. Two more negatives, and the number that has to move

Instrumenting the two field readers (`C`, `Z`) to log a null container and a missing slot - both are
plain function-body patches, so they propagate into the frame copy - gives **0 hits** on a run that
still throws all three TypeErrors. So the null is *not* a field-table miss: no slot is missing, no
container is null, and the failing read is a computed member access (`X[name]`) on a null object
somewhere else. That removes the whole "the program asks for a field that was never seeded" family of
explanations.

Making the clock run faster (`performance.now() x10, x100`, i.e. the same code, more elapsed time)
changes nothing either: 2893 chars in all three runs. The dispatcher does contain a timing gate
(`if(U-S.A5 < S.YB-G) bail`), so the program *can* bail on being too fast, but that gate is not what
stops this run through the clock the realm controls.

**The number to move.** One mint in Chrome's frame realm evaluates ~245 program-computed handler
snippets (`Debugger.scriptParsed`, section 60). The same mint in Node evaluates **3**. Any fix -
realm surface, timing, `document.body`, eval plumbing - has to move that count, because the token's
length is downstream of how far the program's instruction stream gets. Watch it with
`node research/node_mint.mjs --trace --eval-log` (the eval hook perturbs, so use it as a relative
counter only) or by counting `Debugger.scriptParsed` entries in the Chrome control
(`research/probe_realm.py`).

## 64. The stream diverges on field 45: the program asks for a slot nothing wrote

The second accessor (`a`, the one that throws `[FK,30,f]`) and the slot deleter (`fT`, which sets
`S.u[f] = void 0`) patched to log, on the same run that throws the three TypeErrors:

```
A-MISS 4
FT 422 [object Object]
A-MISS 45
FT 422 [object Object]
A-MISS 45      (x N, repeating)
```

So: **field 4 is asked for once and never seeded, then field 45 is asked for on every subsequent
step**, while the dispatcher keeps deleting/rewriting field 422 (the instruction pointer). The head
has already been written at that point (section 59's emit map), so the boot is fine - it is the
program's own instruction stream that diverges at instruction ~3, and from then on it keeps asking for
a slot that no instruction in this run wrote.

That is a concrete, look-up-able target: `45` is an ordinary field id, so the op map answers it
offline - `python3 research/disasm.py RUN.json --table` / `research/record_map.py` on a Chrome run will
name the instruction that writes field 45 and the op that reads it. Nothing about this needs another
live request, and nothing about it is a realm surface (sections 62-63 ruled those out): the realm is
good enough to boot the frame, write the head and run three instructions.

Working hypothesis to test against the op map: the program takes its first branch on a value the realm
supplies (a timing sample or `document.body`'s identity), lands on the branch that reads 45 instead of
the one that writes it, and the missing slot is the *symptom* rather than the cause. If the op map says
45 is written by an instruction that only runs on the other branch, the divergence is one comparison
earlier and that comparison is where the realm difference has to be found.

## 65. The VM checks its own function sources: any edit to the eval wrapper kills the mint

One line added to the handler-eval function - `function(w){return eval(w)}` becomes
`function(w){try{(globalThis.__hs=globalThis.__hs||[]).push(String(w))}catch(e){}return eval(w)}`, i.e.
an array push and no I/O - and the mint returns a **43-character token** (the interpreter's `FNL` error
token, section 10) instead of 2893. Nothing else changed: same material, same realm, same call.

That is not a timing effect (a push costs microseconds and the earlier `console.log` version failed the
same way, as did the call-through). It is the interpreter stringifying its own functions: the eval
wrapper's `toString()` is part of what it checks, so *every* source-level edit of a function that lands
in the signing copy is detected, no matter how harmless. Two consequences that shape the rest of this
work:

* the page copy is safe to patch (the emit hook, the collector log, the reader logs all worked there)
  while the **signing copy is not** - which is also why the frame copy is *generated* per run rather
  than evaluated from the text we pass (section 62): the program assembles a source whose functions
  stringify to what it expects;
* non-perturbing observation of the signing instance has to happen **below JavaScript**. That is the
  whole justification for the patched Chromium build: C++-level logging of eval/compile and of host
  object reads changes no JS source text, so the checks stay quiet.

## 66. The dispatch loop can be logged from outside the VM - but only the degraded path

`Yq` is the instruction loop, and it reads the field id of each instruction before dispatching it:

```js
if(y=Z(S,422), y>=f) break;                    // pointer vs program length
X=(M=F(S,(q(376,S,y),5)), a(M,S));             // M = field id read from the stream, a(M,S) = accessor
t(true,(X&&X[hf]&u ? X(S,k) : V_(S,[FK,21,M],J,1), k),13,S,false,false)
```

Logging `[pointer, M]` there (an array push inside the loop) is **non-perturbing in Node**: the token
stays at 2893 chars and the same three TypeErrors appear. That gives the program's instruction stream
from outside the VM for the first time:

* Node: **756 instructions**, pointer 32 -> 175 840 of 180 448 bits - i.e. the program does *not* stop
  early, it runs to ~97 % of its bytecode and then throws near the end. The earlier "3 evals" reading
  (section 63) was the handler-eval count, not the instruction count.
* the same patch in Chrome gives 884 instructions and a **1177-char / 882-byte token** - outside both
  known regimes (trusted 1065-1087 B, degraded 2114-2170 B). So the patch is detected there, as every
  text patch is (section 65): instrumenting Chrome's signing copy always lands it on a third path.
* comparing the two streams, the first 49 instructions are identical and they diverge at index 50, where
  Chrome executes `[61316, 37]` twice and Node once - a loop-count difference at the same program
  position, not a different branch.

Consequence for method: the instruction stream is observable in Node and *not* in a trusted Chrome run,
so the two cannot be compared directly by this instrument. That is the case for the patched build: a
C++-level eval log records the trusted path without touching a single JS source, and the field ids each
handler reads can be recovered from the logged sources.

## 67. The instruction stream has run-to-run noise: single-run diffs are meaningless

Two Node runs of the same material with the same `[pointer, field]` patch differ from each other:

```
run1 759 instructions   run2 762
common prefix 104  ->  run1 repeats (66622, 3) twice, run2 once
```

Same program, same realm, same input - the loop counts are not deterministic (they are the VM's
"collect until ..." loops, so the clock/`Math.random` decides how many iterations happen). Therefore:

* a Node-vs-Chrome stream diff at index 50 (section 66) is **inside the noise band** and says nothing
  about the realm. Do not chase it;
* the stream has to be compared the way section 50 compares tokens: several runs per side, keep only
  the positions that are *stable within* a side, then ask whether the other side differs where its own
  runs agree;
* the handler source string (element 3 of the log) carries per-run random names, so compare
  `(pointer, field)` pairs only - the strings never match across runs even when the instruction does.

This also gives the noise a name: it is the same timing-driven iteration count that made section 63's
"too fast" gate plausible. If the Node/Chrome difference is real, it will show up as a *stable*
difference, not as a count off by one.

## 68. First stable realm difference in the stream: field 443 is data in Node, a function in Chrome

Collapsing consecutive repeats (section 67) makes each side deterministic: 3 Node runs give the same
747 instructions, 3 patched-Chrome runs the same 880. Comparing those two collapsed streams, the common
prefix is **256** instructions, and the difference is stable across runs:

```
node    ptr=69144 field=107  function(z,g,V,L,Y){(V=a((Y=C((L=n((g=W(15,I),z),35),K),g),L),z),E)(L,z,V+Y)}
        ptr=69152 field=92   <same handler>
        ptr=69160 field=69   value: string
        ptr=69168 field=443  value: number
chrome  ptr=69144 field=107  <same handler>
        ptr=69168 field=443  function(z,g,V,L,Y){for(Y=56;Y!=53;)Y==56?Y=t(true,g,6,I,false,true)?53:16:...
        ptr=69202 field=130  ...
```

Two facts, both stable:

* Node executes the 69144 instruction **twice** (fields 107 then 92, same handler) where Chrome runs it
  once and moves on;
* at ptr 69168 the slot the dispatcher pulls up is a **number in Node and a function in Chrome**. The
  accessor returns `create()` for a value slot and `prototype` for a function slot, so this is a real
  difference in what the field table holds - and a number where a function is expected is exactly the
  shape of the `V.apply is not a function` error this run later throws (section 59).

Caveat, stated because it matters: Chrome's side here is the *instrumented* run (882-byte token), so the
difference could in principle be caused by the patch rather than by the realm. What makes it worth
carrying forward is that it is reproducible, it is at a named program position, and it has the right
shape - a slot holding data where a function is required. The patched build's [EVALLOG] from the
*trusted* path is what decides it.

## 69. The stream is one outer loop, and the realms differ in how far the pointer advances per iteration

Reading the collapsed streams in order (section 68) shows the shape of the program, which the token
never did:

```
175814 f=30   ->  175840 f=3  ->  175864 f=443 -> 175898 f=263 -> 175924 f=37 -> 175964 f=37
             ->  176030 f=467 -> jump back into the 69118/69220 region -> 69144 f=107 -> ... -> 175814
```

So the program is **one outer loop**: a fixed tail (175814-176030) collects/writes, then it jumps into a
small handler region around 69k, runs a handful of instructions there, and returns. Each pass moves the
jump target on (69118 -> 69220 -> 69246 -> ...), i.e. that region is a *dispatch table* walked by
pointer.

The difference is inside one pass:

```
node   69144 f=107  -> next 69152 f=92 -> 69160 f=69 (a STRING) -> 69168 f=443
chrome 69144 f=107  -> next 69168 f=443
```

The instruction at 69144 is the same source in both runs
(`function(z,g,V,L,Y){(V=a((Y=C((L=n((g=W(15,I),z),35),K),g),L),z),E)(L,z,V+Y)}`), yet the pointer after
it is 69152 in Node and 69168 in Chrome - 8 bits consumed versus 24. Two instructions (`f=92`, `f=69`)
exist in Node's stream and **never** in Chrome's (14 and 11 occurrences vs 0). Since `f=92`'s handler is
byte-identical to `f=107`'s, the program is running the same code under a different field id, and `f=69`
is a *string* slot being dispatched as an instruction.

That is the mechanism to chase next: the operand read after a dispatch consumed a different number of
bits in the two realms, so everything after it shifts. Whether that is a keystream state difference or a
jump target computed from a value is what the trusted-path log has to answer - both realms decode the
same 256 instructions before it, so the blob and the keystream agree up to there.

## 70. The generated frame program is byte-identical in both realms

The patched build dumps any eval source over 50 KB in full (`[EVALSRC]`), which settles a question the
token could not: **what the frame realm actually runs**. Chrome 159 (trusted, 1073 B token) and Node
produce the same text:

```
chrome core 62 021 chars   node core 62 080
common prefix 26 875 chars - identical up to `V_=function(...)`, which is where the Node copy carries
an ERRSTACK log this session inserted
```

Two consequences:

* the "frame copy" is the **interpreter itself** (comments intact: `Copyright Google LLC
  SPDX-License-Identifier: Apache-2.0`), not the program blob, and it is generated identically in both
  realms - so the program is not what differs;
* a text patch of the page copy **does** reach it (that is why the emit hook and the collector log
  worked), which also means any such patch is visible to the interpreter's own checks (section 65).

So the divergence has to be a *value* the interpreter reads from its realm, not the code it runs.

## 71. A trusted run's engine log: 242 handlers and 12 errors, four of them "Illegal invocation"

`[ERRLOG]` from the trusted path (our build, 1073 B token, no patch to any JS):

```
Cannot read properties of undefined (reading '422')
Illegal invocation          x4
Function.prototype.toString requires that 'this' be a Function
Invalid or unexpected token
Cannot read properties of undefined (reading 'y')
Cannot read properties of null (reading 'x')        <- the deliberate probe
Invalid array length                                <- the deliberate probe (new Array(-1))
z8p1 is not defined                                 <- the deliberate probe
toString() radix argument must be between 2 and 36  <- the deliberate probe ((1).toString(0))
```

Readings that matter:

* **the trusted run throws too.** Errors are normal; what differs is that none of them end up in the
  token (no tag-132 record), so section 59's "crash log" is about the *collector*, not about the VM
  being error-free;
* `Function.prototype.toString requires that 'this' be a Function` is section 65's mechanism, measured
  from the engine side: the interpreter really does stringify things and probe the failure;
* **four `Illegal invocation`s are native-authenticity probes** - the VM calls a host operation with a
  receiver it does not accept and reads the failure. A shim whose methods are plain JS functions cannot
  fail that way, which is a detectable difference in exactly the direction we are hunting.

`[EVALLOG]` on the same run: 526 dynamic compilations, of which 242 are program handlers and ~120 are
single identifiers / `[]` (the string-mining evals). Ordered, the first handlers are
`fC(6,z,21,0,1)`, `fC(6,z,20,0,2)`, the `L=n(h,32)` handler, the char-code loop, the `_.$`/`_.M` loop,
`var eval="..."`, the `Ss`/`V.apply` handler, then `l7=` and the arithmetic family (`V*Y`, `V-Y`, `V%Y`),
then the helper re-installs (`n=`, `q=`, `E=`, `a=`, `Z=`).

## 72. Two shim constraints measured the hard way

* **`atob` must accept a detached call.** The interpreter calls it bare at its entry
  (`this.mz=H(8,28,atob(K),255)`); giving it a receiver check aborts the mint before it starts
  (`TypeError: Illegal invocation` from `interp.js:2:3715`).
* **`btoa` must too.** `G=window.btoa; y=G(X)` is a detached call, and a strict receiver check turns the
  mint into the `E:Illegal invocation` error token (813 chars). In a browser this works because a
  sloppy-mode detached call still has the global object as its receiver, which the WebIDL binding
  accepts - so the shim must not be stricter than the browser.

## 73. The VM's whole host surface, enumerated from the trusted run

The patched build logs every dynamic compilation. In a trusted run there are 257 of them, and only
**62 distinct short ones** (<= 40 chars) - these are the VM's string-mining probes. The list is the
complete answer to "what does the token read from the browser":

```
1   C  E  F  W  Z  a  d  n  q                       interpreter identifiers
2   $q Eb HO IV MT M_ Ss Un V_ XZ YU Yq ZP a$ b7 fC fT js l7 nT sn tf vL
2   []
3   x='                                   -> SyntaxError: Invalid or unexpected token
4   ({})      4  null
6   null.x                                -> Cannot read properties of null (reading 'x')
6   window                                -> THE GLOBAL
11  2.32831e-10                           -> float formatting probe
11  z8p1.p8='x'                           -> ReferenceError: z8p1 is not defined
13  new Array(-1)                         -> RangeError: Invalid array length
14  0,function(){}
15  (1).toString(0)                       -> RangeError: toString() radix argument must be between 2 and 36
15  var z9p3;z9p3.y                       -> Cannot read properties of undefined (reading 'y')
19  /.*\d:\d\d | \d+$/g                   -> date/time parsing (timezone digits)
22  0,function(z){IV(0,z)} ... {XZ(1,z)}  helper installs
26  var eval="drahmkzqfb";eval            -> shadowed-eval probe
27  0,function(){fC(6,I,5,0,4)}
29  (0,function(a,b){return b-a})         comparator
29  document.createElement('img')         -> HOST
31  0,function(z){IV(3,z),BD=41-nv}
34  0,function(J){J[0]=this.h5()-J[1]}    clock probe (performance.now)
35  document.createElement('div').style   -> HOST
38  0,function($){for($ in $)this.push($)} key enumerator
```

Three consequences:

* the environment surface is **three expressions**: `window`, `document.createElement('div').style`,
  `document.createElement('img')`. There is no navigator, no screen, no canvas, no WebGL, no fonts,
  no audio - the "device fingerprint" in the token is built from *engine behaviour and error texts*,
  not from the machine;
* the mining is text-based: the VM provokes V8 errors and slices the message. Anything that changes an
  error message changes the token;
* Node 26 (V8 14.6) reproduces **all seven** mined messages byte-for-byte (`Cannot read properties of
  null (reading 'x')`, `z8p1 is not defined`, `Invalid array length`, `toString() radix argument must
  be between 2 and 36`, `Cannot read properties of undefined (reading 'y')`, `Invalid or unexpected
  token`, `Function.prototype.toString requires that 'this' be a Function`). The engine-version
  hypothesis is therefore dead: the strings are identical.

## 74. Field-level trace of the failing probe

Patching `Ss` (the slot reader) and `E`/`q` (the slot writers) with plain array pushes leaves the Node
token at 2893 chars, so the trace is non-perturbing. It says:

* the slots that hold *host* values hold exactly what the shim provides:
  `field 90 = (t) => makeElement(realm, t)` (createElement), `field 14 = appendChild(c) {...}`,
  `field 15 = function push() { [native code] }`;
* the slots that hold *strings* hold mined names: `field 65 = "Array"`, `field 105 = "toString"`
  (written as `"replace"` then `"toString"` at trace positions 1629 / 1653);
* the handler that the trusted run throws `Illegal invocation` from - four times - is the *same*
  handler Node dies in:

```
function(z,g,V,L,Y,w){for(w=44;w!=38;)w==61?(L=Ss(6,24,z,1,0),V=L.ue,Y=L.Ka,
  E(L.be,z,V.apply(Y,L.H)),h.bw=B.K(),w=16):...}
```

  In Node the slot holds the *string* `"toString"`, so the failure is `V.apply is not a function`; in
  Chrome the same handler reaches a *native function* and the failure is `Illegal invocation`. Both
  are caught, so this is a probe of *native authenticity* (`fn.apply(foreignReceiver, args)` must
  throw), not the branch that decides the token - but it is the one place where the two realms
  visibly disagree about a host value's kind.

## 75. Every receiver guard on btoa/atob breaks the mint

Measured four ways (strict guard, `this !== g`, `this !== globalThis`, a sloppy function created
*inside* the realm so a bare call gets the realm global): each one turns the mint into the
`E:Illegal invocation` error token (813-822 chars). The interpreter reaches btoa/atob through calls a
browser would also reject but that it expects to succeed, so the guard cannot be global - it has to be
per-method and mirror the exact receiver the VM passes. `atob` is called bare at the interpreter's own
entry (`this.mz=H(8,28,atob(K),255)`), which is the call that dies first.

Also negative: enriching `style` (CSSStyleDeclaration-shaped: `cssText`, `length`, `item`,
`getPropertyValue`, `setProperty`, `removeProperty`, a `constructor` name) and `img`
(`complete`/`naturalWidth`/`naturalHeight`/`decode`) changes nothing - 2893 chars either way. Those
two probes are satisfied by any object.

## 76. d8: the browser's own V8 without the browser - and it fails exactly like Node

Ninja target `d8` builds in **10 steps** from the same checkout as the browser binary (`[10/10] LINK ./d8`,
a few minutes on 4 cores) and reports `V8 version 15.9.40`, i.e. the engine inside Chromium 159. It
also carries our C++ instrumentation: `[ERRLOG]`/`[EVALLOG]`/`[EVALSRC]` all fire in d8.

The port (`research/d8_mint.js`) uses real V8 realms instead of `node:vm`:

```
Realm.createAllowCrossRealmAccess()   one realm per window, cross-realm because the VM reaches its
                                      frame through `iframe.contentWindow` (a same-origin blank frame)
Realm.global(r)                       the realm's global object, to hang the DOM shim on
Realm.eval(r, interp)                 the interpreter, evaluated inside that realm
%PerformMicrotaskCheckpoint()         d8 has no event loop: drain microtasks by hand (needs
                                      --allow-natives-syntax; %RunMicrotasks does not exist in 15.9)
arguments (top level)                 d8 hands script args through the top-level `arguments`,
                                      not through `scriptArgs`, and they only arrive after `--`
```

Result: the VM installs, the iframe opens, the string mining runs - and then it fails the *same* way
Node does:

```
10  n is not a function
 9  V.apply is not a function
 1  Cannot read properties of null (reading 'String')
 1  Cannot set properties of undefined (setting '')
 1  Cannot read properties of undefined (reading 'replace')
 1  Cannot read properties of undefined (reading 'removeEventListener')
```

Compare the trusted browser run (section 71), which contains **no `is not a function` error at all**.
So the engine-version hypothesis is dead twice over: the same V8, with the same error texts, produces
the same degraded path outside Blink. What is missing is the **DOM/bindings layer**, not the JS engine:
in the browser every value the VM probes through `.apply` / `n.call` really is a native function, and
`fn.apply(foreignReceiver, args)` really throws `Illegal invocation`.

A diagnostic (perturbing, section 65) confirms the frame copy is where it breaks: wrapping the frame
realm's `eval` - which makes the VM's `A.eval(src)` an indirect eval - makes the mint *complete*
instead of dying at `n.call is not a function`, producing 2817 chars / 2112 B with the per-build marker
**not** at offset 5, i.e. the degraded band. The frame copy is the whole interpreter again
(`\n`xN + `(function(){...}).call(this)`, 66 340 chars, measured), so its initialisation order is what
our shim disturbs.

Practical value: this is a much better laboratory than Node - same engine as the target, our own
embedder, working `[ERRLOG]`/`[EVALLOG]`, no browser process, and a 10-step rebuild - which makes the
"reproduce Blink's binding layer" work measurable instead of speculative.

## 77. The real blocker was `iframe.contentWindow`: null before `src`, a WindowProxy in a browser

In a browser an iframe owns a WindowProxy from the moment it is created (about:blank); `src` only
navigates it. Both shims returned `null` until the `src` setter fired. The interpreter reads *through* a
freshly created iframe's `contentWindow` during its own boot, so it got `null` and reported it as

```
Cannot read properties of null (reading 'String')        <- window["String"] on a null WindowProxy
Cannot read properties of undefined (reading 'replace')  <- the same null's btoa result
```

Fixing the getter (create the frame realm lazily on first access, `src` navigates an existing one) is the
single largest step this line has made:

| | before | after |
| --- | --- | --- |
| d8 engine errors | 25 (`n is not a function` x10, `V.apply is not a function` x9, ...) | **1** |
| d8 token | mint never completed (threw `n.call is not a function`) | **801 chars / 600 B, completed** |
| Node token | 2893 chars / 2169 B | 3016 chars (still the degraded band) |

And the one error d8 still reports,

```
[ERRLOG] Cannot read properties of undefined (reading '422')
```

is *exactly* the first error the trusted browser run reports (section 71). The d8 token also carries the
per-build marker **at offset 5 and 85 identical bytes after it**:

```
d8       0a 14 b8 14 4e | d0 00 06 7a 16 4e 5f 5a 16 5f b5 f9 d3 d5 7b 19 77 fd 26 00 40 01 10 0a d9 d4 9a 37 64 c1 ...
trusted  12 0c b8 0c 68 | d0 00 06 7a 16 4e 5f 5a 16 5f b5 f9 d3 d5 7b 19 77 fd 26 00 40 01 10 0a d9 d4 9a 37 64 c1 ...
                        ^ common from offset 5, divergence at offset 90
```

The five bytes in front are three varint length fields (`0a 14` = field 1, 20 bytes; `12 0c` = field 1,
12 bytes), i.e. **d8 emits a shorter record than the browser, not a corrupt one**: 600 B against 1078 B
(our build) / 1063 B (official Chrome), diverging at offset 90.

## 78. What is still missing is exactly the Blink binding layer

Count the engine errors each environment produces for the same program:

```
trusted Chrome   12   four of them `Illegal invocation` (Blink bindings, cannot exist in V8 alone)
d8               1    the `(reading '422')` probe both share
Node             25   plus a cascade of `is not a function` from the same root cause as 77
```

`Illegal invocation` is thrown by Blink's WebIDL bindings, not by V8, so a V8-only embedder cannot produce
it however the shim is written - and the VM's native-authenticity probes read *which* failure a call
produces. That is the remaining gap, and it is now the only one: the program is identical (70), the frame
copy initialises (77), the mining runs, and the first error matches.

Two shim rules that came out of this round and must not be undone:

* an iframe's `contentWindow` is never null; it is a window from creation;
* `atob`/`btoa` must accept detached calls (75) - a receiver check turns the mint into an error token.

### 77b. One window per iframe, not one per navigation

Assigning `src` after the realm already exists must *navigate* that window, not create a second one.
Both ports now keep `{frameRealm}` per element and only create a realm on first need; `src` re-navigates
(the frame count in the d8 run is still 2 because the VM's boot creates a second iframe, which is what a
retry looks like from the outside). Token size is stable at 801 chars / 600 B across runs, its random
parts change per nonce, and the 85 bytes after the marker are still identical to the browser's.

## 79. First live request with a browserlessly minted token: HTTP 200, token accepted, no extraction

`research/d8_live_test.py`: the page is loaded in a browser only for the *request* material (cookies,
`f.sid`, `bl`) and the build material of that load; the token comes from `d8_mint.js` on the V8 shell.

Dry run (build `U5tYCxBAtKrhIfdN`): 1253 chars / **939 B**, marker at offset 5, no engine error.

The one real request (build `wlvZkANqlDPB_YSU`, one POST, no retries):

```
d8 mint: 2923 chars / 2191 B, 2 frames, no error
HTTP 200  wrb.fr payload = 1 element = the base64 PNG echoed back
```

Read it against the vocabulary in `live_test.py`: `accepted` would be a 4-element payload (OCR text +
translation), `rejected` would be 400 + an `er` chunk. What happened is neither - the service answered
200 and echoed the image, i.e. **the token passed the gate but the call extracted nothing**. So the
question "can a token be minted without a browser" is now "a browserless token is not rejected; it is
also not yet enough".

Two things to note before the next request:

* 2191 B is inside the *degraded* band (the crash-log tokens are 2114-2170 B), while that same day's dry
  run produced 939 B - close to the trusted 1063-1078 B. The build rotated between the two runs, so the
  first thing to check is whether the new build's interp makes d8 fall into the degraded path again
  (`[ERRLOG]` count for that run was not captured - it should be).
* a control is needed before reading anything into the 1-element payload: the same envelope with a
  browser-minted token. If the control also returns 1 element, the envelope is what is wrong, not the
  token.

## 80. The control came back as the echo too - and it did not isolate what it was meant to

One control request (`live_test.py --control`: a token from the shipped signer in the *same* envelope):

```
page load  build U5tYCxBAtKrhIfdN    sid/bl/cookies ok
control token 1441 chars (shipped signer, build wlvZkANqlDPB_YSU...)
HTTP 200  class=verified/echo  detail 1 element (the uploaded image, byte-identical)
```

That is the same answer the d8 token got, which *looks* like "the token is not what decides it" - but the
control is confounded: the signer minted under build `wlvZkA...` while the cookies/`f.sid`/`bl` came from
a page load that served `U5tY...`. Section 54's accepted control did not have that mismatch. So this run
separates nothing, and the reading has to stay conservative.

What the three requests together do establish:

| token | length regime | build vs page | answer |
| --- | --- | --- | --- |
| shipped signer (54) | 1429 chars, trusted | matched | **accepted, OCR text** |
| shipped signer (80) | 1441 chars, trusted | **mismatched** | 200 echo |
| d8 mint (79) | 2923 chars, degraded | matched | 200 echo |

So `200 + echo` is the answer for *any* token the service will not fully credit - wrong session, wrong
build, or wrong length regime - and a `400`/`er` rejection is not what happens. **HTTP 200 therefore says
nothing about a token's quality**, and section 79's "accepted at the gate" over-read its own result: a
degraded token is served the echo exactly like a foreign one.

Both usable handles point the same way:

* section 24 and 54: the discriminator is the **length regime** - trusted mints are 1405-1447 chars,
  everything instrumented or shimmed lands at 600-1300;
* d8 currently mints **1253 chars** for build `U5tY...` (939 B) and 2923 for `wlvZkA...`: the first is
  inside the degraded band, the second is a crash log.

So the next request is only worth making once d8 lands in 1405-1447 chars for a build that matches its own
page load, and a matching-build control has to be re-established first. That means closing the remaining
~180 chars, which is the Blink binding layer (section 78), not the request envelope.

## 81. Receiver guards on the host methods change nothing - the four `Illegal invocation`s are not ours

Implemented the WebIDL rule properly this time: a guarded host function accepts its own receiver, the
realm global, or d8's global (a detached call in a classic script still arrives with a global), and
throws `Illegal invocation` for anything else. Applied to `btoa`/`atob` and to sixteen element methods
(`appendChild`, `addEventListener`, `getBoundingClientRect`, ...).

```
plain    801 chars, 1 engine error
webidl   801 chars, 1 engine error     (identical)
```

So the VM never probes any of those twenty operations with a foreign receiver inside its own run. The
four `Illegal invocation` errors in the trusted browser log most likely come from **the page's other
scripts** during the load - `probe_realm.py` loads the real translate page, which runs Google's own code
as well as the VM - and not from the attestation program at all. That retires the "native authenticity
probe" reading of section 71 and with it the shim rule it implied.

What still differs, measured on the same request payload (`freq` for the image RPC):

```
browser mint   ~1429 chars   trusted band
d8 mint         1253 chars   (dry run, build U5tYCxBAtKrhIfdN)
d8 mint          801 chars   (different payload, same build)
```

and the mining stream: the browser probes `x`, `null.x`, `window`, `z8p1.p8='x'`, `new Array(-1)`,
`(1).toString(0)`, `var z9p3;z9p3.y` - names and error probes it needs in order to *build* strings -
while d8 probes `l7`, `String`, `undefined`, `t5`, `n`. The VM is mining a different set because it is in
a different internal state, and the missing ~176 chars in the token are the consequence, not the cause.
That state difference is what the next round has to bisect, with the mining stream as the signal: it is
short, ordered, and shifts the moment the environment changes.

## 82. The mining is the interpreter rebuilding itself in the frame realm - and only the order differs

Patching the single eval site (`function(w){return eval(w)}(u7(Z(z.T,L)))`, the only textual `eval(` in the
interp) to log what it is about to evaluate shows what the "generated frame copy" really is: a **roll
call**. For each helper the VM evaluates its *name* and then its *whole source* in the frame realm
(`C`, then `C=function(J,k,u){u=J.u[k];...}`), i.e. it re-installs the interpreter there one function at a
time, and the sequence of those re-installations is the program.

Compare the sequences for the same build (`U5tYCxBAtKrhIfdN`):

```
chrome  l7 l7= n n= q q= E E= a a= ZP Z Z= d fC fC= b7 YU YU= fT js HO ...   (59 names)
d8      $q d C C= js a a= q q= E E= n n= fT Z Z= YU YU= Yq Un MT nT ...       (50 names)
```

* **the same set of helpers**, in a different order - so nothing is missing from the environment in the
  sense of a helper being unavailable;
* chrome's stream carries four extra probes that d8 never makes: **`window`, `null`, `x`, `a$`** - the
  host/global lookups and the error-mining probes (`null.x`, `x='`), i.e. exactly the ones whose messages
  end up in the token;
* d8's stream also re-mines the eval-site handler itself, because this diagnostic patch changed its
  source - an artifact of section 65, not a finding.

So the remaining difference is no longer "the shim is missing a host object" (section 81 showed the host
methods are never probed), and no longer the engine (section 76): it is the **order and scope of the
interpreter's own re-installation inside the frame realm**. Only once the VM reaches the point where it
asks for `window` does it start mining error messages, and d8 never gets there - which is why its token
is ~176 chars shorter and lands in the degraded band.

Practical consequence for the next round: the question to answer is what makes the VM stop before the
`window` probe. The roll-call order is program-driven, so the state that shifts it is one of the values
the VM reads *before* the roll call - and the roll call itself is now observable with a one-line patch
and a two-minute d8 rebuild, with the four extra probes in chrome's stream as the success signal.

## 83. Field ids come out of `fC` as data, and the trace perturbs the mint

Instrumenting the install path (`fC`: `y=W(12,k); {f=S; while(M>S) f=f<<8|M_(k), M--} q(y,k,f)`) shows it
writes **numbers**, not handlers, into the fields it computes:

```
frame0 installs, first 24 of 48
[53,133120] [43,208] [0,16] [91,95] [100,1] [24,2] [99,732958446] [90,-2132610360] [52,-1032738375]
[17,210517757] [422,130248] [36,0] [22,38] [25,463782196] [64,-1398121178] [422,61144] [43,-938796855] ...
```

* the ids are a mix of small numbers (`0`, `22`, `24`, `53`) and program-level ones (`422`, `397`), so the
  handler table is not a contiguous block - a shift of a counter would move many of them at once, which is
  consistent with section 82's "same helpers, different order";
* `fC` writes the *same* field (`422`, the instruction pointer) twice with different values, i.e. it is
  also the data-write path, not only an install path;
* this patch perturbs: the token moved 801 -> 1177 chars (section 36's third regime), so these numbers are
  read from a run that is no longer the one under study. Do not treat the sequence as ground truth without
  a non-perturbing variant.

All the frame-side work happens in **frame0** (page realm shows no installs at all), which confirms
section 82's picture: the roll call and the install table are built in the frame realm, and that realm is
the one whose state has to match the browser's.

Ways forward, in order of cost:

1. read the same table **without** touching the interp text - e.g. patch `q` from C++ is impossible, but
   d8 can wrap the *global* `q` after `Realm.eval(page.r, interp)` if the interp leaks it (it does not), or
   the frame's `q` can be captured from `Realm.eval(frame, "typeof q")` after install - a non-text probe
   worth trying first;
2. compare the *first* install id only, from a run with a single log line, keeping the perturbation small
   enough that the token length stays at 801/1253;
3. treat the field-id shift as the hypothesis and look for what consumes ids before the roll call: the two
   `fC(6,z,21,0,1)` / `fC(6,z,20,0,2)` boots run in both realms, so the extra consumption is between them
   and the first mined name.

## 84. Correction: the roll call is identical - section 82 compared a patched run to an unpatched one

Section 82 said d8 mines a different set in a different order and never reaches the `window` probe. That
was wrong, and it was wrong for the reason the notes keep recording: the d8 stream it used came from a run
whose interp text carried a `console.log` at the eval site (section 65's trap), and it was compared against
an *unpatched* Chrome stream. The unpatched d8 run (`logs/plain.log`, C++ `[EVALLOG]` only) reads:

```
fC(6,z,21,0,1)  fC(6,z,20,0,2)  [] [] []  var eval="drahmkzqfb";eval
l7 n q E a ZP Z d fC b7 YU fT js HO Un sn Eb nT Yq W MT vL tf XZ Ss $q IV C
IV(0,z) IV(7,z) V_ M_ M_=function(...) XZ(2,z) F [] []
function($){for($ in $)this.push($)}
nT l7 tf [] [] [] fT(0,1,...) IV(3,z) XZ(1,z) function(){fC(6,I,5,0,4)} IV(4,z) M_=... XZ(4,z)
document.createElement('div').style
document.createElement('img')
window
[] []
```

That is the browser's sequence, item for item, **including the three host probes**. So the roll call is not
where the two environments differ, and the "state difference before the roll call" story of sections 82-83
is withdrawn.

What is left is the output, measured with the same material and the same `freq`:

```
chrome  1064 B   (probe_realm.py, build U5tYCxBAtKrhIfdN)
d8       600 B   (d8_mint.js, same material, same freq)
        identical through offset 90, diverging at 90
```

Same program, same roll call, same host probes - and 464 bytes that the browser writes and d8 does not.

## 85. A non-perturbing window into the browser's VM state

`research/probe_breakpoint.py` sets a CDP breakpoint inside the mining function
(`function(w){return eval(w)}`, at the `return eval(w)` statement, so `w` is in scope) in the frame copy.
Breakpoints move code positions, not source text, so the VM's anti-tamper checks cannot see them: the token
stayed in the trusted band on five consecutive runs (1419 / 1445 / 1447 / 1456 / 1428 chars =
1063-1091 B), where a one-line text patch moved it to 1177 (section 83).

It yields, per hit, the name about to be evaluated, and `evaluateOnCallFrame` allows plain property reads of
the VM's own state at that moment. First frame-realm snapshot (at `l7`):

```
K = the module object: 53 own keys
  Gy,W7,og,Sj,fa,mz,Z,YB,D6,nG,gg,F,CG,bw,o,WT,U,dt,fG,G,wt,vT,u,W,oS,kB,ie,N1,A5,V,m,J,Y,Dk,
  Rg,Uj,Q7,j,h,Ez,D,m1,t5,q1,T,jj,Oz,dg,LG,TC,uy,FY,jzua
K.T  object      K.u  125 slots      slot 422 = {create, concat}, value is an object
```

Two practical notes: the page's own script also contains the anchor (script 52, 167 KB), and its `K` is a DOM
element (`__wiz`, `__jsaction`) - the diagnostic must be pinned to the frame realm's short helper names or it
reads the wrong object. And the naive tag-walk over the two tokens above (`tag | len16 | payload`) does not
parse either token to the end, so naming the 464 missing bytes needs the emitter-side tools
(`record_map.py` / `align_emits.py`) against these two captures rather than a from-scratch parser.

## 86. The VM runs each environment probe in a fresh execution context - and we give it two

The `[EVALLOG]` line carries the execution-context id, which is the column that had not been used yet.
Grouping a trusted browser run by it:

```
59 evals  ctx 0x11a20197b92d      <- the frame copy (the roll call)
 3 evals  ctx 0x11a202056cf1
 1 eval   each of ~20 other contexts
```

and the mining probes are **each in a different context**:

```
window             0x11a201a9c179
2.32831e-10        0x11a2020384a9
null.x             0x11a2021c783d
new Array(-1)      0x11a2021cb8c9
z8p1.p8='x'        0x11a2021cf6b5
(1).toString(0)    0x11a2021d35e5
```

So the VM spawns a **short-lived realm per probe** (through the iframe it creates; a parsed-script context
per probe is what an `iframe` + `contentWindow.eval` looks like from the engine side). Our d8 shim reports
`frames: 2` for the whole mint, so it only ever hands the VM two realms: the roll call runs, the probe
budget runs out of worlds after `window`, and the mining stops there. That is the divergence - not the
helper order (section 84), not the host surface (section 81), not the engine (section 76).

It also explains the record that was believed impossible. Both tokens end with a **tag-132 record**, the
VM's exception log:

```
chrome  tag 132 at offset 177, length 884, ends exactly at the end of a 1064-byte token
d8      tag 132 at offset 389, length 208, ends exactly at the end of a  600-byte token
```

Chrome's log is the 12 engine errors it reports (section 71) - each probe throws, the message and stack are
logged; d8's 208 bytes are the one error it reaches. The 464-byte difference is therefore mostly log, plus
212 bytes that d8 writes elsewhere in the same window (616 vs 87 bytes before the log record).

So section 59 / `token-format.md` item 3 needs a qualifier: the tag-132 record is not "absent in a trusted
mint", it is *small* in one - the trusted regime carries the probes it ran, and the degraded regime carries
a long stack for every helper-eval failure as well.

## 87. Correction: the `ctx=` column is a heap pointer, not a context id - section 86's mechanism is void

`patch_chromium.py` prints `reinterpret_cast<void*>(context->ptr())`, i.e. the address of the context
*object on the V8 heap*. That address moves with GC and allocation, so grouping evals by it and concluding
"each probe runs in its own execution context" (section 86) is unfounded. Measured with CDP instead
(`research/probe_contexts.py`, one pristine 1432-char mint):

```
contexts before mint 2, total 4
  ctx 2 default=True type=default origin=https://translate.google.com
  ctx 3 default=True type=default origin=https://translate.google.com
```

Two realms, not twenty - the page and its one frame, which is what the d8 shim also creates. So the VM does
**not** spawn a realm per probe, and section 86's mechanism is withdrawn.

What survives from 86 is only what was read off the tokens themselves, which needs no context theory:

* both a trusted 1064-byte token and the 600-byte d8 token **end in a tag-132 record**, 884 bytes and 208
  bytes respectively (each record's length lands exactly on the end of its buffer);
* d8 writes 212 bytes *more* than the browser in the window before that record (299 vs 87 bytes at offset 90)
  and 676 bytes fewer inside it.

And the probe gap is real, measured by text rather than by context: `new Array(-1)`, `(1).toString(0)`,
`z8p1...`, `z9p3...` appear in the browser's eval stream and never in d8's, while `null.x` and `window`
appear in both. d8's stream simply ends after `window` (eval 142-144 of 144).

**Tooling caveat, add it to any patch that prints a context**: `context->ptr()` is a heap address. Use it at
most as "same object right now", never as an identity key across a run, and prefer CDP when the question is
"which realm".

## 88. d8's mining is an exact prefix of the browser's: the walk is right and it stops at 143

Aligning both `[EVALLOG]` streams at the first shared eval (the chrome stream carries two extra `1`-length
evals before it) gives a clean answer:

```
d8      143 evals   (after alignment)
chrome  253 evals
common prefix 143 - i.e. all of d8, element for element
d8 ends at:  ... 'window', '[]', '[]'
chrome goes on: '[]', '[]', '[]', '2.32831e-10', ...
```

So the program's walk is **identical** and d8 simply stops. Everything before the stop - including the two
`document.createElement` probes and `window` - matches, which is why the first 90 bytes of the token match
too. The 464-byte difference is entirely what happens after eval 143.

Tried and ruled out as the pacing: a real timer surface. The shim now implements `setTimeout`,
`setInterval` (self-re-arming, bounded), `setImmediate`, `requestIdleCallback` and `requestAnimationFrame`
as a job queue drained between microtask checkpoints - a shim that *accepts* a callback and never fires it
is a silent truncation. Result: unchanged (801 chars, 144 evals). So the VM is not waiting on a timer it
never gets.

Next: the guard that decides continuation sits in the mining handler itself
(`Y==56 ? Y = t(true,g,6,I,false,true) ? 53 : 16 : ...`). At the `window` hit in Chrome the breakpoint can
read that call's value and the following `F(z,37)` / `Z(z.T,L)`; whatever makes it take the `53` (stop)
branch is the answer, and it is a *decision*, not a missing object - the next probe in the browser is the
number literal `2.32831e-10`, which needs nothing from the host.

## 89. Breakpoints are non-perturbing only if the evaluated expressions are pure

Reading the mining handler's state at every hit (`String(Y)`, `String(L)`, the caller frames) works, and it
confirms the shape: every hit arrives through the same chain

```
<anonymous> col 32466   (the mining handler, one call per name)
Yq          col 23808   (the program's instruction loop)
sn          col 39417
```

with `Y = 16`, i.e. the branch that *does* the eval, and `L` the offset just decoded. So the handler is
never told to stop - it is simply not called again.

**But the same run also proves the trap**: `next_off` was evaluated as `String(F(z,37))`, and `F` is the
instruction decoder - calling it *advances* the decode state. That run produced 7 hits and a **3075-char**
token where the clean runs produce 44-64 hits and 1428-1456 chars. So a breakpoint is invisible only while
the expressions are pure reads: `F`, `Z`, `a`, `n`, `q`, `E` all mutate or re-enter the VM. Read `Y`, `L`,
`typeof`, and plain properties; never call the interpreter's own helpers to "look ahead".

This is the same lesson as section 65 in another register: the instrument has to be passive. The CDP window
(section 85) stays valid for the values it already produced, but any follow-up must be built on `Debugger`
stepping and plain reads only.

## 90. Measured: the missing mining evals are worth ~1 char each, not the 464 bytes

Five clean breakpoint runs (count only, no diagnostic expressions - section 89's trap), same build and
material:

```
hits 42   token 1417 chars / 1062 B
hits 64   token 1415 chars / 1060 B
hits 64   token 1432 chars / 1073 B
hits 64   token 1428 chars / 1070 B
hits 64   token 1440 chars / 1079 B
```

Two things this settles:

* **the mining count is adaptive, not fixed** - the same material mints with 42 or 64 roll-call evals and
  the token stays in the trusted band either way;
* **the per-eval cost is about one character**: 22 extra mining evals move the token by ~13-25 chars, i.e.
  ~1 char each. d8 is missing ~110 evals, which at that rate is ~110 chars = ~82 bytes - a sixth of the
  464-byte gap at most.

So the truncation is **not** where the difference lives, and chasing the post-`window` probes further would
have been the wrong path. The 464 bytes are much more likely the tag-132 record itself (section 86: 884 B in
the browser, 208 B in d8, with d8 writing 212 B more elsewhere) - i.e. *what populates the exception log*,
not *how many mining steps run*.

Next target, in order:

1. `research/record_map.py` on a fresh `run_one.py` capture (needs a run on the remote: it wants `one.json`
   with the emission log) - it names, per record, the source field and the instructions that wrote it, which
   is the only way to say what the 884 B log is made of;
2. compare that field's content between a browser run and d8, since d8's copy is 208 B.
