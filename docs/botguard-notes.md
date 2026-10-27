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

The `h` slots are **factories, not values**: at encode time `create()` on the
interesting ids (146, 277, 261, 311, 323, 444, 473, 474, 495, 117) returns
`undefined`, because the serializer has already consumed them. Only 21 and 230 return
numbers (140846, 178824). So the field breakdown has to be captured *during*
serialization, not after.

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

1. Capture field writes *during* serialization instead of after: the slots are
   consumed by the time `btoa` runs, so the hook has to land earlier - e.g. on the
   first `hq` use, or by tracing the writer functions (`ax`/`qj` in the inline build)
   from the frame script with `Debugger.setBreakpointByUrl` replaced by a
   script-id-based breakpoint armed at parse time.
2. Decode the keystream: `hq` is only 8 bytes but the payload shows no lag-8
   periodicity, so either the key is expanded or the fields are hashed into it.
   Recovering the key schedule would make offline field diffing possible.
3. Explain the eval sensitivity: wrapping `contentWindow.eval` is the only JS-level
   change that flips the shape. Whatever it detects lives below the JS-visible surface
   (V8 context metadata is the standing hypothesis; §4 rows 6 and 9 rule out the
   obvious ways to observe it).
