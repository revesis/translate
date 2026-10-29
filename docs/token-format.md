# Token format, as measured

One page for the thing the notes take 40 sections to establish. Every number here came from a live
run; the section references point at the evidence in `botguard-notes.md`, and the tool that produced
it is named so it can be re-run instead of trusted.

Scope: the token Google's botguard VM returns, i.e. the string that goes into
`X-Goog-BatchExecute-Bgr` for `/DataService.GetImageTranslation` (rpcid `WqWDPb`). Text translation
does not use it.

## Shape

```
token_string = ";" + base64url(token_bytes)

token_bytes  = nonce(2) + token_field

token_field  = head(3) + record*            # head = b8, nonce[1], x
                                          # nonce[0] ^ nonce[1] == 0x1e   (section 1, 43)
record       = [tag:1] [payload]           # tag only when the call site passes one
```

Measured end to end: the token body after `nonce(2) + head(3)` is byte-for-byte the concatenation of
`(tag byte when set) + payload` over the emitter calls, in call order (sections 39, 40 - `exact=True`
on five build families).

## The head (3 bytes + 26 bytes of template)

Written by program instructions, three tokens each, `[op, sourceField, tokenField]`
(section 39):

| op | writes | example |
| --- | --- | --- |
| 163 | 1 byte | field 7 = 208 -> `d0` |
| 460 | uint32 big-endian | field 50 = 372310253 -> `16 31 00 ed` |
| 490 | 2-byte BE length + bytes | field 40 = the 6-byte marker -> `00 06 0b 77 65 eb 2b 77` |
| 118 | same shape, other targets | field 97 |

The op set is stable per build family; the **source field ids rotate per run**, so the template is
constant while the ids are not.

The 8-byte marker `00 06 0b 77 65 eb 2b 77` is not a prefix constant: it is emitted as three separate
chunks (sections 37, 38).

## The records

Appended by the serializer after the program loop has finished (`readsCompleted` equals the final
read count, section 39). The tags are **protocol constants**, identical in Fhxs / EON / pBm / SnVl
(section 41):

| tag | payload | source |
| --- | --- | --- |
| 6 | empty | branch that usually does not run |
| 231 | empty | same |
| 18 | `len16 + field(311/163/2)` | the collected blob; skipped when that field is empty |
| 23 | `len16 + RNG(n)` | **random filler**, n from the run's lengths |
| 98 | `len16 + field(323/444)` | also emitted *into* the 99-source field in Fhxs |
| 99 | `len16 + field(473/456/375)` | 4 random bytes + 5 unexplained (section 44) |
| 117 | `len1 + (counter+1>>1)` | `this.K` |
| 132 | `len16 + field`, sliced at 1E6 | skipped when that field is empty |

Which tags appear is data-dependent: each call site is guarded by its source field's length, and in
the runs measured only 117 / 98 / 99 / 23 were emitted.

## What is random, what is set, what is unknown

Measured by pinning the interpreter's RNG (section 43):

* **nonce(2)** - `RNG(2)`; pinning the filler function to 170 gives `aa, aa^0x1e`.
* **tag 23 bulk** - `RNG(n)`, every byte; it is padding, not encrypted content.
* **tag 99, first 4 bytes** - `RNG(4)`; the interpreter initialises that field with `K(vm, 473, AY(4))`.
* **caller-set numbers** - `117 = 2048`, `23 = 253`, `99 = 6` are written before the program's first
  read (`readsCompleted == 0`), so they are inputs, not collected data.
* **unexplained** - the last 5 bytes of the tag-99 record. Not `Math.random` (all sites pinned), not
  `+new Date` (pinned), not an emitter call (no 5-byte emission exists in any log), so they arrive by
  direct index assignment. Catching that needs a `Proxy` over the field buffer installed from the
  accessor patch - both the `create()` and `prototype` branches.

## Instrument map

| tool | answers |
| --- | --- |
| `research/run_one.py` | one load, one mint, three logs (boundaries, reads, writes) plus emissions |
| `research/align_emits.py` | is the token exactly `flag+payload` per emission? (finds the token field by content) |
| `research/disasm.py` | which instruction emitted / wrote what |
| `research/record_map.py` | which field each tag copies, and what wrote that field |
| `research/probe_serializer.py` | pre-encode string and the VM instance, via a `btoa` hook |
| `research/probe_concat.py` | the serializer's assembly graph (array ids, `nonce(2)+field(n)`) |
| `research/probe_rng.py` | pin the RNG / the clock and see which bytes follow |

Builds rotate per load and the token field id rotates with them (146 / 299 / 366 / 478 / 483
measured), so nothing may hard-code an id: derive it by content (`align_emits`) or by role (the
argument that is not the instance).

## What is still open

1. The 5 bytes above (instrument: field-buffer `Proxy`).
2. `117`'s counter value (`this.K`) - readable from the instance, not yet correlated with the byte.
3. The `18` / `132` sources' provenance in runs where they are non-empty.
4. A pure-offline mint: the head template and the records are now specified, but nothing yet emits a
   token Google accepts without a browser (section 1's trust gate is a separate problem).
