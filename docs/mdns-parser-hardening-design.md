# Bounded mDNS parser and lifecycle hardening

Status: proposed design and implementation plan; no production changes yet.

Review baseline: `master`, commit
`394dca9dc4d5f1eb20140d524c8b2f2366a53cfa`.

## 1. Scope and goals

This work addresses the six areas of the focused review:

1. One DNS name/compression decoder shared by all parsing paths.
2. Exact PTR, SRV, TXT, and A record boundaries.
3. UDP short reads, short writes, and explicit error recovery.
4. Responder/query ownership, lifecycle, and callback reentrancy.
5. A binary-safe TXT API with a documented legacy adapter.
6. Deterministic regressions, property tests, and coverage-guided fuzzing.

The relevant implementation is in [MDNS.cpp](../MDNS.cpp) and the public
interface is in [MDNS.h](../MDNS.h). Existing TXT behavior is illustrated by
[registration](../examples/Ethernet/RegisteringServicesWithTxtRecord/RegisteringServicesWithTxtRecord.ino)
and [discovery](../examples/Ethernet/DiscoveringServices/DiscoveringServices.ino).

Goals:

- Never access bytes outside the received packet or the applicable field.
- Bound allocation, parsing work, and callback delivery.
- Never publish an incomplete, malformed, or incorrectly associated result.
- Make failure observable without changing existing `1`/`0` return contracts.
- Preserve valid existing sketches and their callback signatures.
- Keep protocol parsing independent of Arduino, UDP, heap allocation, and
  callbacks so tests exercise the actual production parser.

Non-goals for this series:

- A complete RFC 6762 implementation, including probing/conflict resolution,
  new known-answer suppression behavior, IPv6/AAAA support, or a cache rewrite.
- Cross-datagram DNS-SD record assembly. Incomplete sets must be safe, but a
  full discovery cache needs a separate TTL, eviction, goodbye, and deduplication
  design. This limitation remains explicitly documented.
- Platform/core upgrades, unrelated cleanup, or a generic networking framework.
- Concurrent use from multiple threads/interrupts, or deleting the `MDNS`
  object from its own callback.

## 2. Review findings and repair ownership

Numbers refer to the focused review, not to an external issue tracker.

| Finding | Root problem | Implementation stage |
| --- | --- | --- |
| R1 | Service name/TXT allocation omits terminating NUL | P1 |
| R2 | Unchecked header/field reads and ignored UDP short reads | P2, P3 |
| R3 | PTR length subtraction underflows | P3 |
| R4 | Callback cleanup uses mutable query state; stale pointer writes | P4 |
| R5 | Callback and query members are not fully initialized | P1 |
| R6 | Removal dereferences empty service slots | P1 |
| R7 | Duplicated name parsers guess compression using low-byte offsets | P2, P3 |
| R8 | Incomplete service sets expose uninitialized/mismatched port/IP | P3 |
| R9 | UDP send errors are discarded and success state advances early | P5 |
| R10 | TXT length/empty encoding and callback contract are ambiguous | P6 |
| R11 | Absolute timeout comparison fails across clock wrap | P4 |

Adjacent ownership defects exposed by these fixes, such as failed allocation
leaving partially published state, belong in the same series. Unrelated
features do not.

## 3. Core abstraction A: PacketCursor

### 3.1 Representation and operations

Use a non-owning immutable `PacketView` containing the byte pointer and a
`size_t` length. A `PacketCursor` references that packet and holds absolute
`position` and exclusive `end` offsets.

Conceptual operations, not a frozen public API:

- `readU8`, `readU16BE`, `readU32BE`
- `take(length)` for a bounded byte span
- `skip(length)`
- `subcursor(length)` for a bounded field such as RDATA
- `remaining()` and `position()`

The cursor is an internal helper, not a new user-facing abstraction. It must
not allocate memory, touch UDP, or invoke a callback.

Invariants:

1. `position <= end <= packet.length`.
2. Validate `length <= end - position` before advancing. Do not first compute
   `position + length`, which may overflow.
3. A failed operation leaves the cursor and output arguments unchanged.
4. A subcursor covers exactly the requested span; successful creation advances
   the parent by that span. Failure leaves both unchanged.
5. Read integers explicitly in network byte order. Do not cast packet bytes to
   wider integer pointers or depend on packed bitfield layout/alignment.
6. Zero-length operations are valid only where the enclosing protocol permits
   them. Never dereference a null pointer merely because the length is zero.

Use an internal parse-status enum with at least truncated input, invalid label,
invalid pointer, name too long, invalid RDATA, output too small, and resource
limit. Keep these distinct from socket failure and allocation failure.

### 3.2 Header and section traversal

- Read the 12-byte DNS header through the cursor.
- Interpret flags with masks rather than copying into `DNSHeader_t`.
- Walk questions, answers, authority records, and additional records
  separately. Do not add all four 16-bit counts in a potentially 16-bit
  expression.
- Every iteration must consume bytes or return an error.
- Parse a question as name plus QTYPE/QCLASS; parse a resource record as owner
  name, TYPE, CLASS, TTL, RDLENGTH, and an exact RDATA subcursor.
- Unsupported TYPEs may be skipped only after validating their envelope.
- Known supported RDATA shapes must be checked even when a record does not
  match the active query.
- Parse syntax independently from application policy. For example, masking
  the class high bit must not erase the distinction between a question's QU
  request and a resource record's cache-flush flag.

Require all declared sections to be well formed before committing responses
or callbacks. Do not return early after finding the first matching A record.
The proposed strict mode also rejects undeclared trailing bytes; capture valid
peer traffic before integration and record any interoperability exception
explicitly rather than silently ignoring malformed tails.

## 4. Core abstraction B: one DNS name decoder

### 4.1 Contract

Conceptually:

`decodeName(packet, startOffset, encodedEnd, output, outputCapacity)`

Return an internal status plus:

- `encodedBytes`: bytes consumed at the original field location;
- `expandedBytes`: uncompressed wire-name length, including the root byte.

On failure, do not advance the caller's cursor or expose partially decoded
output as a valid name. The caller commits the returned consumption only on
success.

`encodedEnd` is the question/RDATA/packet boundary applicable to the original
name encoding. The immutable full packet remains available for compression
pointer dereferences.

**Two different bounds are essential:** the original name and both bytes of
each original compression pointer must fit the field. A pointer target may
legitimately lie outside that RDATA, provided it lies inside the packet.
Requiring all dereferenced bytes to stay inside RDATA would reject valid PTR
and compressed SRV target inputs.

### 4.2 Representation and comparison

Decode to uncompressed, length-prefixed labels, not an unescaped dotted
C string. Preserve original label bytes and boundaries. Embedded dots in a
service instance label must not create extra labels, and binary label bytes
must not be truncated by `strlen`.

DNS equality compares full label sequences with ASCII case folding for
`A` through `Z`; other bytes remain unchanged. Never match by packet offset,
low pointer byte, a name prefix, or the first available address.

Convert to the existing callback representation only at the API boundary.
Ordinary existing names must retain their current presentation. Before
implementation, specify escaping or explicit rejection for names that cannot
be represented unambiguously by the legacy C-string callback; never truncate
them silently. Preserve original case for display.

### 4.3 Decoder algorithm and limits

1. Read the next tag within the current applicable bound.
2. `00xxxxxx` denotes a label length. Zero terminates the name; nonzero lengths
   must be at most 63 and fit the bound.
3. `11xxxxxx` denotes a two-byte pointer. Decode all 14 offset bits:
   `((first & 0x3f) << 8) | second`.
4. Reject reserved `01`/`10` tag classes and pointers outside the packet.
5. Track the original consumed bytes separately. A pointer terminates the
   original encoded name; dereferenced bytes do not increase `encodedBytes`.
6. Reject expanded names longer than 255 wire bytes, including length bytes
   and the terminal root byte.
7. Guarantee termination without allocating a packet-sized visited bitmap:
   impose a monotonic traversal-work budget bounded by packet length, counting
   both tags and traversed label bytes. A cycle/overlong traversal exhausts it
   and fails. A smaller hop cap must not be introduced without documenting the
   resulting interoperability restriction.
8. Proposed policy: reject forward/self pointers as invalid compression;
   retain the work budget to catch backward-pointer cycles through labels.
   This policy must have explicit tests rather than being an accidental
   consequence of an implementation detail.

Only this decoder interprets name labels and compression. Owner names,
question names, PTR targets, and SRV targets all call it.

## 5. Resource record semantics and transaction boundary

| Record | Required validation | Result eligibility |
| --- | --- | --- |
| PTR | One decoded name; original encoded consumption equals RDLENGTH | Full target instance name, not `RDLENGTH - 2` or a guessed first label |
| SRV | Three 16-bit fields followed by exactly one target name; at least 7 bytes structurally | Publish port/target only after complete parsing; a root target is not a usable service endpoint |
| TXT | Every length-prefixed segment fits remaining RDATA; no compression interpretation | Preserve exact binary bytes and explicit length |
| A | RDLENGTH is exactly 4 and all four bytes are present | Publish IPv4 only after validation |
| Unknown | Complete RR envelope and RDATA span | Skip without interpreting RDATA |

The receiver should tolerate safely decoded compressed SRV targets for
interoperability; this does not authorize the sender to introduce compression
where the applicable SRV rules prohibit it.

Accept zero-byte TXT RDATA on receive as an empty interoperability case;
normalize locally generated empty TXT to one zero-length string (`00`).
Distinguish a missing TXT record from a present empty TXT record internally.

Service assembly:

- Associate queried service type -> PTR instance -> SRV owner -> SRV target
  -> A owner using complete decoded names.
- TXT owner must equal the instance name.
- Initialize every candidate and use explicit `havePTR`, `haveSRV`, `haveA`,
  and `haveTXT` validity flags.
- A discovery callback requires PTR, SRV, and A for that instance. TXT remains
  optional, preserving the current callback's optional TXT behavior.
- TTL-zero records must not create a new positive discovery result.
- Support record ordering and valid placement in answer/additional sections;
  do not depend on PTR appearing first.
- Remove the unrelated-first-A fallback.
- Preserve duplicate notifications across repeated packets as the examples
  currently describe; cross-packet deduplication is not added here.

Validate first, publish second. A malformed later record must not leave an
earlier callback or response committed. Prefer a validation pass followed by
bounded rescans for at most the existing six per-packet service candidates,
rather than an unbounded table or six permanent 255-byte expanded names.
Reuse a small number of name scratch buffers and retain validated offsets
into the live packet where possible.

Define deterministic handling of duplicate/conflicting RR sets and capacity
overflow before integration. Recommended initial policy: identical duplicates
do not duplicate a callback within one packet; unrepresentable conflicting
sets/resource exhaustion fail explicitly rather than selecting an arbitrary
endpoint or returning a misleading partial success.

## 6. UDP receive, send, and error observability

### 6.1 Receive

- Keep `parsePacket()` in its signed return type until validated: zero means
  no packet; negative means backend error, not a huge unsigned length.
- Reject packets below 12 bytes or above the agreed receive-memory limit
  before allocation. Check allocation-size conversions on 16-bit targets.
- Capture peer metadata before callbacks or socket recovery can change it.
- Read exactly the advertised datagram length. Recommended initial policy:
  a negative, zero, or short read rejects this packet; never parse an
  uninitialized tail or combine bytes from two datagrams.
- Discard only the remainder of that datagram, with a bounded operation.
  Verify whether `flush()` actually provides this behavior on each supported
  backend; do not assume its semantics from the name.
- Release the packet on every exit. Packet-local flags/candidates are reset
  and no staged callback/response is committed on failure.
- If the backend cannot discard reliably, transition to explicit socket
  recovery rather than guessing that the next `parsePacket()` starts cleanly.

### 6.2 Send

- Check `beginPacket`, every `write`, and `endPacket`.
- A checked byte-write helper must be used by all existing name and record
  serializer helpers; a top-level check cannot detect their ignored writes.
- Require each write to return the requested count. Do not retry a suffix
  unless the backend contract proves safe within the same pending datagram.
- Preflight field lengths, packet size, and offsets before beginning a send.
  Write only initialized bytes and exact field widths. In particular, the
  current query path writes the header-sized scratch buffer for its 4-byte
  QTYPE/QCLASS trailer; replace that with an exact-length write and regression.
- On short write, do not call `endPacket()` to deliberately transmit a known
  partial packet.
- Generic Arduino UDP has no portable transmit-abort guarantee. A small
  private recovery helper may need `stop()` plus `beginMulticast()` on the
  exclusively used UDP object. Verify this against each backend and report
  rejoin failure. Do not describe `flush()` as a transmit rollback.
- An `endPacket()` failure can leave delivery uncertain; report failure,
  preserve coherent local state, and allow bounded retry. Do not promise
  network-level exactly-once delivery or retraction of an already sent packet.
- Update last-successful-send/announcement times only after successful
  completion. Track retry scheduling separately so an outage does not cause
  a tight resend loop on every `run()`.

### 6.3 API and state outcomes

Retain existing `1`/`0` success returns. Returning a negative enum through
those APIs would break sketches using `if (mdns.resolveName(...))`.

Propose an additive error-status accessor for legacy `void run()` and removal
methods, including parse/resource/socket failures. Do not repurpose
success/timeout callbacks for transport errors. Specify when status is reset,
and ensure a later successful operation in the same `run()` does not hide an
earlier failure. Existing error enum values must retain their numeric values.

Recommended atomicity rules, to confirm before implementation:

- Initial query-send failure returns `0` and leaves that new query inactive.
- Registration returning `0` must not secretly retain the newly added record.
- A failed replacement allocation must not destroy an existing valid name.
- Removing a service always clears local ownership; a failed goodbye is
  observable but does not resurrect the service.
- Recovery failure marks the transport unavailable; a subsequent explicit
  `begin()` can retry. Do not claim successful reinitialization prematurely.

These rules address observable failure behavior, not just return statements.

## 7. Query/responder lifecycle and reentrancy

- Initialize both callback pointers, query timers, protocol/state fields, and
  any reentrancy marker in the constructor.
- Distinguish cancellation, timeout, completion, and transport failure.
- Before a one-shot completion/timeout callback, detach the old query into
  local owned storage and clear its member state.
- After a callback, release only detached old storage; never clear whatever
  query currently occupies that member.
- For ongoing discovery, copy/snapshot callback arguments instead of writing
  temporary NULs into the active query name.
- Use a per-query generation token. If a callback cancels/replaces discovery,
  stop delivering candidates belonging to the previous generation. Callback
  replacement alone takes effect at the next safe dispatch boundary.
- Proposed contract: callbacks may cancel/start queries and add/remove service
  records. Nested `run()` is rejected without recursive dispatch and exposes
  the already-processing status. Document this instead of silently allowing
  nested parsing to mutate the outer packet.
- Callback argument storage is borrowed and valid only for the duration of
  that callback. Users must copy data they retain.
- Iterate responders by current valid slots; never keep a record pointer
  across a callback that can delete it.
- Destructor cleanup frees names, queries, and records without sending
  goodbyes or invoking callbacks, then stops but does not delete the borrowed
  UDP object. The UDP object must outlive `MDNS`.
- Repeated `begin()` and failed initialization need explicit state tests; do
  not broaden reinitialization semantics accidentally.

Store query start time and duration, using unsigned elapsed subtraction.
Preserve `timeout == 0` as unlimited. Define a maximum finite duration and
the required servicing interval so wraparound correctness has a precise
contract. Refresh time after callbacks; do not apply a pre-callback `now` to
a query created by that callback.

## 8. TXT API and compatibility

The legacy `const char* textContent` is already length-prefixed TXT wire data,
not plain text. For example, the registration example supplies a length byte
followed by `path=/2`. Do not insert a new prefix or encode it a second time.

Proposed additive interface:

- A five-argument `addServiceRecord` overload accepting
  `const uint8_t* txtData, size_t txtLength`.
- A distinctly named setter for a new callback carrying TXT bytes and length.
  Avoid an overload that makes `setServiceFoundCallback(NULL)` ambiguous.
- One active service callback mode at a time; installing either legacy or
  binary mode replaces the other. No duplicate delivery.

Binary API contract:

- Input is complete TXT RDATA consisting of length-prefixed strings.
- Copy validated bytes during registration; no retained caller pointer.
- Null pointer with nonzero length is invalid.
- Length zero is empty TXT and is transmitted as `00`.
- Nonempty data must validate segment by segment and fit the RR and configured
  outbound packet limits.
- Callback bytes exclude any implementation-added NUL sentinel.
- Missing TXT uses null pointer/zero length. Present empty TXT should provide
  a nonnull borrowed pointer even when the received RDATA length is zero.

Legacy adapter:

- Keep all existing signatures, integer return conventions, and ordinary
  wire bytes for valid legacy inputs.
- Compute the legacy byte span using `strlen`, validate it, then use the same
  binary implementation. Do not claim support for embedded NUL in this mode.
- Treat omitted TXT, `NULL`, and `""` consistently as empty TXT on every target.
  This is an intentional wire-level correction, to document in release notes.
- Preserve the existing legacy callback's appended NUL convention without
  treating it as part of RDATA. Document that embedded NUL/zero-length segments
  cannot be consumed reliably by sentinel-only legacy readers.
- Do not promise binary/ABI compatibility for precompiled code if the exposed
  record layout changes; require rebuilding sketches. Source compatibility
  and legacy example compilation are acceptance requirements.

## 9. Implementation sequence and acceptance gates

Each stage should be a reviewable commit or small PR. Add regressions with
the corresponding fix; fuzzing is not deferred until all implementation ends.

| Stage | Work | Dependency | Exit criteria |
| --- | --- | --- | --- |
| P0: baseline/harness | Host Arduino/UDP/clock/allocation test doubles; valid packet fixtures; record baseline memory/flash usage | None | Actual production code builds in harness; baseline valid queries, responses, and legacy TXT bytes captured |
| P1: immediate ownership fixes | Correct allocation lengths; initialize members; skip empty slots; transactional allocation cleanup | P0 | Boundary/allocation-failure/sparse-removal tests pass under address and undefined-behavior sanitizers |
| P2: pure parser primitives | Add cursor and shared name decoder with explicit statuses | P0 | Direct boundary/property tests pass; decoder fuzzer uses production code and has deterministic resource bounds |
| P3: parser integration | Replace both legacy name loops; validate all RR envelopes/RDATA; exact association; staged delivery; receive short-read recovery | P1, P2 | No legacy compression guessing remains; truncation/malformed tails produce no packet-derived events; valid record permutations agree |
| P4: lifecycle | Detach/generation-safe callbacks; nested-run policy; wrap-safe timeouts; cleanup/reinitialization rules | P1, P3 | Cancel/restart/timeout/replacement tests preserve new state with no use-after-free or leaks |
| P5: transmit semantics | Checked writes throughout serializers; preflight; exact query trailer; status visibility; backend recovery and retry scheduling | P1, P3, P4 | Every injected send failure is observable; no known-short packet is finalized; subsequent operation recovers or reports unavailable |
| P6: TXT compatibility | Explicit-length API, callback mode, legacy adapter, empty normalization; update examples/docs | P3, P4, P5 | Binary round trips, legacy source compilation, invalid segment tests, and cross-platform empty-byte assertions pass |
| P7: release gate | Expand fuzz corpus; target builds; memory budgets; hardware receive/send recovery checks | P1-P6 | All gates below pass; limitations and intentional behavior changes documented |

P1 and P2 can proceed independently after P0. Integrate later stages in order
to avoid changing parser, callback, and transport ownership simultaneously.
Do not merge partially wired helpers while leaving an unsafe legacy path in
normal execution.

## 10. Test matrix and measurable completion criteria

| Area | Required cases | Property |
| --- | --- | --- |
| Cursor/header | Lengths 0..12; each field truncated; counts 0, 1, 65535 | No out-of-bounds access; failure does not advance cursor; work bounded by input |
| Names | Labels 0, 1, 63, reserved tags 64/128; expanded wire lengths 254, 255, 256 | Correct root handling, limits, and label-preserving equality |
| Compression | Targets 0, 11, 12, 255, 256, 16383; valid earlier targets; self/forward/cyclic chains; missing second byte | Termination; full 14-bit decoding; exact original consumption; invalid targets rejected |
| PTR | RDLENGTH 0, 1, 2, 3; root, pure pointer, labels plus pointer, uncompressed names | No subtraction underflow; exact RDATA consumption; no unusable endpoint emitted |
| SRV | RDLENGTH 0..8; fixed fields truncated; root/compressed/uncompressed targets | Port/target valid only together; pointer target outside RDATA but inside packet accepted when otherwise valid |
| TXT | Lengths 0, 1, 255, 256 and over-limit declarations; multiple/empty segments; embedded NUL; segment overrun | No segment crosses RDATA; raw data preserved; legacy adapter does not double-encode |
| A | RDLENGTH 0, 3, 4, 5 and truncated four-byte data | Only exactly four available bytes become an address |
| Assembly | All 24 permutations of one PTR/SRV/TXT/A set; missing each RR; unrelated A; shared target; duplicates; TTL zero | Matching complete endpoints are order-independent; no random port/fallback IP; no false positive from incomplete sets |
| Transaction | Valid early RR plus malformed late RR; capacity overflow | No packet-derived callback/response on rejected packet |
| Receive | Negative/zero/short backend reads; oversize/OOM; bad packet followed by valid packet | No uninitialized tail parsing; bounded discard; next packet remains intact |
| Send | Fail begin; short/failing every write position; fail end; fail multicast rejoin | Observable status; no success timestamps on failure; bounded retries; coherent state |
| Callback | Cancel/restart both query types; discovery callback alters records/callback; nested run; timeout restarts | No stale writes/frees; new query survives; old-generation delivery stops |
| Ownership | Stack/global objects; empty/sparse/remove-all; each allocation failure; destruction with active state | No uninitialized pointers, leaks, double free, or dangling ownership |
| Time | Start near UINT32_MAX; finite timeout crosses wrap; zero timeout; callback advances clock | Elapsed-time semantics, no premature timeout, no immediate resend storm |

Fuzz targets:

1. Cursor/name decoder with arbitrary bytes, start offsets, field ends, and
   output capacities.
2. Full packet validation/assembly using the same production parser.
3. Stateful fake-UDP/query operation sequences, including failures and
   callback-triggered operations.

Use sanitizer-enabled host tests on a supported compiler/runner; do not add
fuzzing dependencies to embedded library builds. Check in minimized
regressions and deterministic seeds. Generated valid compressed/uncompressed
names must decode equally; compare independently expected label sequences
and golden packets, not only encoder/decoder round trips that could share a
bug. Assert step/allocation bounds, not only wall-clock time.

Proposed gates:

- All deterministic regressions and at least 10,000 fixed-seed generated cases
  per principal property pass with no sanitizer findings.
- CI runs each fuzz target for at least 60 seconds; before release, run each
  target for at least one hour with the seed corpus. Record toolchain, seed,
  duration, executed cases, and coverage. Time alone is not proof of safety.
- Cover every parse-error category and every UDP failure injection point.
- Preserve existing Ethernet/WiFi example builds on the board matrix in
  [compile-examples.yml](../.github/workflows/compile-examples.yml).
- Ensure validation triggers include the root-level implementation files;
  the current compile workflow's `src/**` filter alone does not cover them.
  This is a narrowly related validation change, not a workflow cleanup.
- Measure flash, static RAM, peak heap, and worst-case stack on at least one
  smallest supported AVR and one 32-bit target. Approve explicit packet,
  scratch-buffer, and CPU-work limits before P3 merges.
- Exercise bad-then-good receive and failed-then-successful send on Ethernet
  and WiFi101 backends. A fake UDP test cannot prove real backend recovery.

## 11. Decisions to approve before implementation

The plan recommends policies but does not silently approve behavior changes:

1. Receive/transmit byte caps and scratch-memory budgets for small AVR versus
   32-bit targets. Measure first; do not impose a guessed universal 512-byte
   DNS cap or allocate buffers for the full protocol maximum on small MCUs.
2. Legacy name presentation for embedded dot/NUL labels and malformed legacy
   TXT input, including release-note wording.
3. Exact status-accessor signature/reset semantics and nested `run()` behavior.
4. UDP backend abort/discard/rejoin behavior and whether exclusive ownership
   of the supplied UDP socket can be documented as a requirement.
5. Registration/query failure atomicity and duplicate/conflicting RR policy.
6. Keep cross-packet assembly deferred, or fund a separate bounded-cache
   design if interoperability testing shows it is required for the release.

Successful completion means the six scoped surfaces are wired through the
same validated paths, measured on supported targets, and covered by
regressions. It does not mean every broader mDNS protocol feature is implemented.
