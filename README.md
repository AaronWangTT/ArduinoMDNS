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

## Requirements

Any Arduino core and networking library that supports the new `virtual` `UDP::beginMulticast(...)` method, including:

 * AVR core 1.6.18 or later (bundled with IDE 1.8.2 and later) for AVR boards
 * SAMD core 1.6.13 or later for SAMD boards
 * Arduino Ethernet and WiFi101 libraries
