# ArduinoMDNS

[![Check Arduino status](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/check-arduino.yml/badge.svg)](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/check-arduino.yml)
[![Compile Examples status](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/compile-examples.yml/badge.svg)](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/compile-examples.yml)
[![Spell Check status](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/spell-check.yml/badge.svg)](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/spell-check.yml)

mDNS library for Arduino. Based on [@TrippyLighting](https://github.com/TrippyLighting)'s [EthernetBonjour](https://github.com/TrippyLighting/EthernetBonjour) library.

Supports mDNS (registering services) and DNS-SD (service discovery).

## Bounded parsing and API compatibility

See the [hardening design](docs/mdns-parser-hardening-design.md) for the
parser boundaries, staged implementation, and validation gates.
The [API migration guide](docs/bounded-api-migration.md) documents binary TXT,
callback lifetimes, error reporting, resource limits, and intentional changes
to malformed-input handling.

Host regressions, allocation-failure tests, and deterministic properties run
with `bash tests/run-tests.sh` on Linux or WSL using GCC and ASan/UBSan.
Coverage-guided fuzzing runs with `bash tests/run-fuzz.sh` using Clang; set
`MDNS_FUZZ_SECONDS=3600` for the one-hour-per-target release run.
These host tools are not dependencies of embedded builds.

## AZ3166 manual hardware validation

The [manual hardware test guide](extras/hardware/MulticastMdnsTest/README.md)
describes compile-only verification, explicit upload/run, network probing,
and optional elevated TTL capture against this library checkout using the
Core-provided `AZ3166MulticastUDP` transport.

These files were copied from `AaronWangTT/devkit-sdk`; this migration does not
remove the SDK copies. Core transport implementations and platform packaging
remain owned by devkit-sdk. CI tests the host-side tools without flashing hardware.

## HomeTemperature fork

Release 1.1.1 is maintained for
[AaronWangTT/HomeTemperature](https://github.com/AaronWangTT/HomeTemperature).
It adds bounded packet handling, send-error reporting, reusable responder
lifecycle methods, and a borrowed transport abstraction for platforms without
the Arduino `UDP` base class. Existing sketches that pass an `EthernetUDP` or
`WiFiUDP` instance to `MDNS` remain source-compatible. Custom transports can
pass `false` as the second constructor argument to skip the legacy WIZnet boot
delay. Release 1.1.1 additionally validates DNS names and record lengths,
preserves state across allocation and transport failures, fixes DNS-SD query
and TXT encoding, handles full 14-bit compression offsets, and makes timeout
callbacks safe to re-enter.

## Host tests

The parser and lifecycle regression suite runs with AddressSanitizer and
UndefinedBehaviorSanitizer:

```sh
cmake -S tests/host -B build/host -DCMAKE_BUILD_TYPE=Debug
cmake --build build/host --parallel
ctest --test-dir build/host --output-on-failure
```

## TXT record encoding

The `textContent` argument to `addServiceRecord()` uses the library's existing
wire-format contract: pass one or more DNS character-strings, each prefixed by
its one-byte length. For example, `"\x06" "path=/"` advertises `path=/`.
Malformed character-string sequences are rejected.

## Requirements

Any Arduino core and networking library that provides a UDP-compatible object
with the operations used by `MDNS`, including:

 * AVR core 1.6.18 or later (bundled with IDE 1.8.2 and later) for AVR boards
 * SAMD core 1.6.13 or later for SAMD boards
 * Arduino Ethernet and WiFi101 libraries
