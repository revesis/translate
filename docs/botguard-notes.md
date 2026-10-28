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

