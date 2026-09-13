# ArduinoMDNS

[![Check Arduino status](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/check-arduino.yml/badge.svg)](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/check-arduino.yml)
[![Compile Examples status](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/compile-examples.yml/badge.svg)](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/compile-examples.yml)
[![Spell Check status](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/spell-check.yml/badge.svg)](https://github.com/arduino-libraries/ArduinoMDNS/actions/workflows/spell-check.yml)

mDNS library for Arduino. Based on [@TrippyLighting](https://github.com/TrippyLighting)'s [EthernetBonjour](https://github.com/TrippyLighting/EthernetBonjour) library.

Supports mDNS (registering services) and DNS-SD (service discovery).

## HomeTemperature fork

Release 1.1.0 is maintained for
[AaronWangTT/HomeTemperature](https://github.com/AaronWangTT/HomeTemperature).
It adds bounded packet handling, send-error reporting, reusable responder
lifecycle methods, and a borrowed transport abstraction for platforms without
the Arduino `UDP` base class. Existing sketches that pass an `EthernetUDP` or
`WiFiUDP` instance to `MDNS` remain source-compatible.

## Requirements

Any Arduino core and networking library that provides a UDP-compatible object
with the operations used by `MDNS`, including:

 * AVR core 1.6.18 or later (bundled with IDE 1.8.2 and later) for AVR boards
 * SAMD core 1.6.13 or later for SAMD boards
 * Arduino Ethernet and WiFi101 libraries
