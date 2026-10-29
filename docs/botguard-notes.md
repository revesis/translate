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
