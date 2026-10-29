# Handoff: the three open items

Written for a fresh session that continues the botguard work in this repo. Read this first, then
`docs/token-format.md` (one-page format spec), then the referenced sections of
`docs/botguard-notes.md` (the evidence). Do not re-derive what is already measured.

## Where things stand

The format is finished and executable: `research/assemble_token.py` rebuilds real tokens byte for byte
on five build families (section 52). The offline-mint question is **closed** by four live requests
(sections 53-56): an assembled token, a re-randomised nonce and a single changed byte all get the
degraded echo, while the unmodified token gets OCR - so the token is authenticated end to end and only
the VM can produce one. What remains is understanding, not capability: three narrow questions below.

Do not spend time on: offline minting (closed), jsdom minting (sections 1, 45: spent), the head's
content binding (sections 49-51: none), or the marker (section 48: it is per build, not universal).

---

## Item 1 - the five bytes at the end of the tag-99 record

**What is known.** The tag-99 record is `len16 + field(F)` where F rotates (473 Fhxs, 456 EON, 375 pBm,
77/154 others). F holds `RNG(4) + 5 bytes`. Pinning the RNG (`research/probe_rng.py --mode filler`)
turns the first four into `aa` and leaves the last five random. Sections 41-43, 52.

**What is excluded, do not re-run** (section 44/45/46):

| attempt | result |
| --- | --- |
| any `Math.random()` site pinned (`--mode random`) | tail still differs between runs |
| all `+new Date` pinned (`--mode date`) | tail still differs |
| pinning `performance.now()` | the whole mint degrades to a 33-char error token - not a usable discriminator |
| an emitter call carrying the 5 bytes | no such emission exists in any of the five families' logs |
| `Proxy` over the accessor's returned object (index writes) | inert: 25 emissions, empty log |
| wrapping the slot's methods by *name* | wrong copy: 457 emissions, empty log |
| wrapping the emitter's own call expression | correct shape, but offsets are stale (see below) |

**Why the last one failed.** `patch_emit` collects call-site offsets from the source text, then injects
the emit-hunk log statements, which shift the text; the wrap then lands in the wrong place and
`node --check` fails. Two traps from that attempt: `return(expr)` needs an explicit space before an
inserted wrapper (`return__ix(...)` is valid JS, calls an undefined identifier, and silently returns
`undefined`), and the accessor returns `create()` on one branch and `prototype` on the other, so only
wrapping one branch measures half the traffic.

**The next step, in order.**

1. Refactor `research/bgpatch.py:patch_emit` into `detect(src) -> sites` / `inject(src, sites)`, and
   call it twice: detect, wrap the accessor call sites, re-detect, then inject the emit logs. That is
   the prerequisite, not a nicety.
2. Wrap at the *emitter's own call expression* (`z(t,b)` -> `__ix(vm, field, z(t,b))`), inline, with
   the log sink on the **VM instance** (`vm.__ixlog`), never on `window`: the VM runs in a frame the
   page cannot read (section 24), which is why the first two attempts reported zero.
3. Log `(fieldId, method, length before/after, first argument)` for `push`/`concat`/`create` on the
   returned object, and for index assignment if the object allows it.

**Acceptance criterion:** an entry counter injected at the top of the accessor must read non-zero on a
run that also produced emissions. If it reads 0 while emissions are non-zero, the wrap is not on the
live path and the measurement is meaningless - that is the check that failed twice.

**Value:** low. These 5 bytes affect no trust decision and no part of the format's usefulness. If two
attempts do not produce the writer, close it again and move to item 2.

---

## Item 2 - where the per-load constants come from

**What is known.** The head carries, after the nonce and the per-build 6-byte tag: `5f 44`, two 4-byte
words, `26 00 40`, and a 64-byte block. Three mints in one page load leave all of them identical;
a new load changes all of them (section 48). They are an environment snapshot, and they are the part
of the token that differs between a trusted and a degraded mint (sections 54-56).

**What is known about how they are produced.** `research/head_map.py` joins each head chunk to the
`[op, sourceField, tokenField]` instruction that emitted it and to the op that wrote that source field.
Those writers are a one-call family:

```
Fhxs  op 20   function(){R(30,0,u,1)}      1-byte writes
      op 308  function(){R(31,0,V,4)}      4-byte writes
      op 425  function(y,p,X,C,H,U){...}   the 6-byte marker
EON   op 72   function(){K(0,40,c,1)}   op 87  function(){K(0,42,D,4)}
pBm   op 21   function(){st(0,(zQ>>=66,1),8,c,6)}   op 106  function(D){lf=(st(0,4,8,D,7),qs>>211)}
```

**The next step.** Follow the *inputs* of those writer ops back to their sources. `disasm.py` already
has the dataflow view (`--dataflow`, per-op inputs/outputs from the field-read log `fr`), and
`record_map.py` shows how a field joins to its writer. Concretely, for one run:

1. `python3 research/head_map.py RUN.json` - head chunk -> emit op -> source field -> writer op;
2. `python3 research/disasm.py RUN.json --dataflow` - which fields the writer ops read;
3. repeat for the two 4-byte words and the 64-byte block, and look for the handler that touches
   `navigator`/`screen`/`performance`/`document` (the op handlers are recorded per op id in `hn`).

**Acceptance criterion:** name the environment reads that feed each of the four constant groups, i.e.
"the 64-byte block is assembled from these N values, read by these ops". That is a provenance answer,
not a byte-level one.

**Trap:** instrumented runs land on the degraded branch (600-1300 char tokens), so the *values* you
see are not the ones a trusted token carries. The provenance (which ops read which environment value)
is still valid; do not try to compare the values with a trusted token byte for byte.

---

## Item 3 - the authentication construction

**What is known.**

* The emitters XOR field bytes with a per-field keystream on the way in, but **only for fields 277 /
  473 / 474** (`b==277||b==474||b==473` in `ax`/`qj`); the token field is the un-XORed path, which is
  why its payload reads as plaintext (section 34, 37).
* The keystream is regenerated per field block: `G.Tu = WH(16, block, seed, [0,0,Y[1],Y[2]], 551)`
  where `Y = w(vm,15)` and the seed field rotates (section 12/13).
* Empirically the whole token is authenticated: changing **one** byte (nonce, or the RNG-derived byte 4)
  turns an accepted token into the degraded echo while the structure still verifies - `200`, no `er`
  chunk (sections 55, 56). So validity is not "correct bytes in the right order".

**What is open.** The construction itself: is it a MAC over the plaintext, a keystream over the whole
blob, or a signature over a subset of the VM's state? Which key material, and where does it live?

**Instruments that already reach the right places.**

* `research/probe_serializer.py` replaces `window.btoa` in the frame realm and reaches the VM instance
  through `CallSite.getThis()`; at that point `vm.hq` (8-byte per-sign table), `vm.rc` (timings),
  `vm.jr`, `vm.i`, `vm.V` are readable (section 2). Start there: dump them for two mints in one load
  and see which of them changes when the token changes.
* `research/probe_concat.py` shows the serializer's assembly graph (`nonce(2)+field(n)` per piece);
  the last piece is `nonce + tokenField`. The code around the `btoa` site is the encode path
  (`o3` / `DS.eV`, section 3) and is the thing to read next.
* `research/assemble_token.py` gives a *byte-exact* model of the plaintext stream, so any candidate
  construction can be tested against a real token offline, without requests.

**Acceptance criterion:** either reproduce the authentication of a captured token offline (a
verifiable MAC/keystream over the known plaintext), or prove it needs key material that only exists
inside the VM instance (e.g. `hq`/`Tu` derived from a value the page cannot read). Both are useful;
a half-answer ("it looks like a MAC") is not.

**Hard rules for this item.** Live requests are the only way to *test* acceptance and each one needs
explicit user approval; four have been spent (sections 53-56) and the answers are recorded. Do not
send synthetic tokens on your own. Prefer offline tests against captured tokens.

---

## Tool inventory

| tool | purpose |
| --- | --- |
| `research/run_one.py` | one load, one mint: boundaries, reads, writes, emissions (`--freq FILE` for the payload) |
| `research/align_emits.py` | is the token exactly `flag+payload` per emission? finds the token field by content |
| `research/disasm.py` | instruction table, per-op profile, `--dataflow`, `--emit-log` |
| `research/record_map.py` | tag -> source field -> writing op, with handler text |
| `research/head_map.py` | head chunk -> emit op -> source field -> writer op |
| `research/probe_serializer.py` | pre-encode string + VM instance at `btoa` time |
| `research/probe_concat.py` | serializer assembly graph with array ids |
| `research/probe_rng.py` | pin the RNG / the clock (`--mode filler|random|date|perf|both|all`) |
| `research/probe_payload.py` | same build, two payloads: do the mint-phase emissions differ? |
| `research/diff_tokens.py` | A/B/A minting, per-mint noise vs content-sensitive bytes |
| `research/assemble_token.py` | spec -> token (`--fresh` for a new nonce/bulk) |
| `research/live_test.py` | one live request (`--dry-run`, `--control`, `--control-fresh`, `--control-byte4`) |

## Working rules

* Builds rotate per load and so do all ids (token field, source fields, op ids, tag values inside
  expressions). Derive roles structurally; never hard-code an id or a name.
* One experiment per page load: two dumps are only comparable inside the same page.
* Instrumentation pushes the VM onto the degraded branch - fine for provenance, fatal for anything
  that needs a trusted token.
* Commit each verified conclusion to `main` with the measurement in the message, and push; verify with
  `git ls-remote origin refs/heads/main` equal to `git rev-parse HEAD`.
* Code comments and docstrings in English; chat replies in Chinese.
* Do not touch the shipped sidecar (`bgr_sidecar.py`, `gt_server.py`, `gt_image.py`, `Dockerfile*`):
  the research line is separate.
