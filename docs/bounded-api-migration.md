# Bounded mDNS API migration

Rebuild sketches and libraries together: existing method signatures and the
`1` success / `0` failure convention remain source compatible, but object and
record layouts have changed. The UDP object is borrowed, must outlive `MDNS`,
and must be used exclusively by this instance.

## Names and TXT

Host arguments are a single nonempty label (at most 63 bytes), without `.local`.
Discovery accepts one service label such as `_http`. Registration accepts
`instance._http`; the **last dot** separates the service label. Thus
`Living.Room._http` registers the single instance label `Living.Room`, not two
labels. Instance labels preserve non-ASCII bytes (including UTF-8); ASCII control bytes
and DEL are rejected. Service labels begin with `_` and otherwise contain ASCII
letters, digits or hyphens. Protocol must be `MDNSServiceTCP` or `MDNSServiceUDP`.
Empty labels and implicit truncation are not accepted.

The legacy TXT argument was already length-prefixed DNS TXT RDATA, **not plain
text**. It is still validated and copied without adding another length prefix:

```cpp
mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP, "\x07" "path=/2");
```

Omitted, null and empty TXT now consistently transmit one byte `00`, including
on AVR and Teensy. Use the binary overload for embedded NUL or empty segments:

```cpp
const uint8_t txt[] = {3, 'a', 0, 'b', 0};
mdns.addServiceRecord("Web._http", 80, MDNSServiceTCP, txt, sizeof(txt));
```

The bytes must comprise complete length-prefixed strings. Null with nonzero
length, overrunning segments and oversized data fail. Input is copied.
`setServiceFoundBinaryCallback()` installs a callback with the existing first
five arguments followed by `const uint8_t* txt, size_t txtLength`.
Installing either callback mode replaces the other. The legacy setter is not
overloaded, so `setServiceFoundCallback(NULL)` remains unambiguous.

Received TXT bytes are preserved exactly. Missing TXT is null/zero; present
empty TXT is nonnull/zero (or nonnull/one for the wire encoding `00`). Legacy
callbacks receive an extra NUL sentinel, not part of RDATA; sentinel-only
readers cannot reliably consume binary values or zero-length segments.

## Ownership and callbacks

Callback arguments are borrowed until that callback returns. Copy retained
data. Callbacks may cancel/restart queries, change callbacks and add/remove
services. Completion/timeout detaches the old query before calling user code.
Restarted queries survive callback return; cancellation/replacement ends
delivery for the old discovery generation. Callback replacement alone takes
effect at the next candidate boundary.

Nested `run()` is rejected with `MDNSAlreadyProcessingQuery`. Threads,
interrupt-driven calls and deleting `MDNS` from its own callback are unsupported.
Destruction frees all owned storage, stops the socket, and never sends
goodbyes or deletes the borrowed UDP object.

Timeout zero means unlimited. Finite timeouts are at most `0x7fffffff`
milliseconds. Service `run()` at least once per `0x7fffffff` milliseconds;
elapsed unsigned 32-bit subtraction handles a clock wrap. Name timeout retains
the legacy `255.255.255.255` address; service timeout has a null instance.
Timeout also reports `MDNSTimedOut` through `lastError()`.

## Errors, atomicity and transport

`lastError()` exposes failures from both integer and void methods. Existing
error numeric values are unchanged. New statuses distinguish malformed
packets, resource limits, conflicting records and unrepresentable names.
Each top-level network/query/name/registration/removal operation and `run()`
starts a new status interval; getters and callback setters do not clear status.
Within `run()`, the first error is retained even if later work succeeds or a
callback invokes another operation.

Invalid names and allocation failures leave existing names/queries intact.
Once a valid replacement query is installed, failed initial transmission
returns zero and leaves that query inactive. Failed registration owns no new
record. Removal always frees the local record even if the goodbye fails.
`setName()` also preflights existing registrations against the packet cap.
Repeated `begin()` preserves services, replaces the name, cancels queries and
rejoins the transport. Failed rejoin leaves transport unavailable; explicit
`begin()` is needed to retry after recovery failure.

Every begin/write/end result is checked. A short write never calls
`endPacket()`. Failed I/O, short reads and invalid advertised receive sizes use
bounded `stop()` plus `beginMulticast()` recovery, not ambiguous `flush()`
semantics. The backend must actually reset pending receive/transmit state on
`stop()`. Delivery after `endPacket()` failure is uncertain, not exactly once.
Closing the socket may also discard otherwise valid datagrams already queued
before recovery. Their preservation is not promised: UDP is lossy. Recovery
tests deliver the subsequent valid packet only after rejoin has succeeded.
A malformed DNS shape detected after an exact, complete read is rejected
without unnecessarily restarting the socket; no unread tail remains.
Availability reflects the backend API return, not confirmed multicast delivery:
WiFi101's multicast initialization does not propagate its membership
`setsockopt` result. Hardware join/recovery validation is still required.
Query/announcement retries are limited to one attempt per second; their
success timestamps advance only after a complete successful transmission.

## Bounds and interoperability

Compile-time defaults are `MDNS_MAX_PACKET_SIZE=512` on AVR (`ARDUINO_ARCH_AVR`
or `__AVR__`) and `1472` on other architectures, with `MDNS_MAX_TXT_SIZE=128`
on both. Define these consistently for library and sketch to override them.
The non-AVR default admits a conventional Ethernet-MTU IPv4 UDP payload; it
is not a universal DNS packet-size limit. Serialization preflights the entire uncompressed response before
opening a datagram. Long but individually valid labels can exceed the outbound
packet budget and fail explicitly. The AVR limit favors small AVR SRAM over
accepting every Ethernet-sized datagram; eight configured registration slots
remain available but their actual names/TXT consume additional heap.

After whole-packet validation, an allocation-free scan measures the largest
expanded name, `N`, and largest supported TXT RDATA, `T`. Discovery allocates
one block of `sizeof(Assembly) + C * sizeof(Candidate) + N + max(N, T + 1)`
bytes. `C` is a conservative upper bound from positive PTR count, capped at
six; duplicate PTRs still count only once during result assembly. Scratch
descriptors occupy 40 bytes on x86-64 or 10 on AVR; each seven-offset candidate
uses 56 or 14 bytes respectively. Thus one PTR, names of 26 bytes and small TXT
need only 76 bytes on AVR, not two fixed 255-byte buffers or six permanent slots.
Full 255-byte names are still supported: maximum default scratch plus metadata
is 886 bytes on x86-64 or 604 bytes on AVR. TXT dispatch reuses the second name
buffer; callback name snapshots reuse the first. Host-only resolution and
responder questions allocate only `N` bytes, freed before callback/send.

In the x86-64 sanitizer/allocation-failure suite, `sizeof(MDNS)` is 208 bytes.
The ordinary host-answer fixture peaks at 91 bytes of production heap and the
ordinary service fixture at 374. An exact-cap packet with a 255-byte name,
maximum TXT and callback restart peaks at 1,193 bytes with cap512, or 2,153
with cap1472. All tracked allocations are freed at teardown. Allocator
metadata, FakeUDP storage and user-owned callback allocations are excluded.
Received bytes are allocated at their actual length; outbound bytes at their
preflighted length. These are budgeting measurements/layout calculations,
not a claim that every eight-service configuration fits a 2-KiB AVR.
Increasing the cap from 512 to 1472 adds up to 960 bytes to a live receive
packet, not necessarily to scratch. Integration tests exercise pointers
above offsets 255 and 512, and the suite also runs with an explicit 1024-byte
cap to cover a common override.

AVR GCC 7.3 (`-Os`, ATmega328P, without LTO) reports 76 bytes for `_process`,
8 for `_receive` and 27 for `run`. Summing the validation call chain through
`validatePacket` (56), `readRecord` (33), `skipName` (18) and `decodeName` (34)
gives 252 bytes. Service assembly's deeper path is about 333 bytes. Traversal
helpers are deliberately not inlined on GCC/Clang, so those frames are gone
before callbacks: only 111 bytes of `run`/receive/process frames remain.
For the ordinary 186-byte service fixture, AVR temporary heap is
`186 + 76 = 262` bytes; with those live entry frames, library temporaries are
about 373 bytes during callback dispatch, below 500. These figures exclude
resident names/queries, sketch and callback frames, allocator overhead,
interrupt handlers and backend frames. They are compiler/layout budgets, not
a hardware stack high-water measurement. On AVR, allocations temporarily
raise avr-libc's heap-growth stack margin to at least 320 bytes for receive
and discovery assembly allocations, or 192 for other allocations, then restore
the previous margin. This avoids relying
on the allocator's 32-byte default when deeper library calls are imminent.
Existing larger margins are preserved. Other libraries, interrupts and
callbacks still need their own stack budgeting.

Discovery remains available on AVR, including Uno/Nano; there is no blanket
physical-SRAM feature restriction. Actual packet-sized scratch and a bounded
packet-specific candidate table replace the earlier fixed buffers. Allocation
failure remains explicit through `MDNSOutOfMemory`; configured packet/TXT or
six-candidate exhaustion reports `MDNSResourceLimit`.

A 512-byte receive cap is an upper bound, not a promise that every discovery
packet fits a small board. At the cap with full-length names, packet plus
discovery scratch alone can be 1,116 bytes on AVR, before query storage,
allocator metadata and stack.
The Nano example's roughly 1 KiB remaining after static data cannot support
every worst-case packet plus caller/callback buffers. Low-headroom applications
may report `MDNSOutOfMemory` instead of handling the full cap. Typical packets
use much less scratch, but verify actual stack high-water and socket behavior
before deployment rather than inferring runtime safety from compilation.

All declared sections and known record shapes must validate before any
packet-derived response or callback. Trailing undeclared bytes, forward/self
compression pointers and malformed unrelated records reject the whole packet.
Discovery only joins records within one response datagram, using exact
case-insensitive label equality for PTR instance, SRV owner/target, A owner and
TXT owner. Missing PTR/SRV/A sets and root SRV targets produce no callback.
TXT is optional; TTL-zero records cannot create positive results.
There is no unrelated-address fallback or cross-datagram cache.

At most six distinct matching positive PTR instances are staged. A seventh
rejects the entire packet with `MDNSResourceLimit`, rather than publishing an
arbitrary subset. Identical duplicates deliver once per packet; conflicting
SRV/TXT/A data rejects the entire packet. Repeated valid datagrams may still
notify repeatedly. Instance names not representable by the callback's single
printable label are rejected explicitly rather than truncated or flattened.

Responses remain multicast; this is not a new RFC 6762 implementation.
Probing, conflict resolution, known-answer suppression, IPv6 and cross-packet
DNS-SD assembly remain outside this change. Hardware socket recovery and SRAM
headroom must be verified on the actual supported Arduino UDP backend.
