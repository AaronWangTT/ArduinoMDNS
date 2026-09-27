# Hardware tool validation: 2026-09-27

## Result

**Real-board functional validation passed. Full hardware qualification did not
run because IPv4 TTL capture was explicitly skipped.**

The migrated runner reported:

```text
action: Run
result: functional-passed-ttl-skipped
ttl: skipped
hardwareQualified: false
error: null
```

This migration and validation did not modify or delete SDK source files. The
registration-only example is not duplicated here; the complete hardware test
sketch is retained.

## Tested inputs

- Board: MXCHIP AZ3166 / STM32F412, ST-Link on COM3.
- Detected internal flash: 1,048,576 bytes.
- Arduino CLI: 1.5.1.
- Python: 3.12.10; PowerShell 7.
- Core: an isolated staged checkout of `AaronWangTT/devkit-sdk`, revision
  `fc1b82a0ea8a0bf1c2bd0b2b0f4d2aeaa83a6ef2`, profile `base`.
- FQBN: `AZ3166Checkout:stm32f4:MXCHIP_AZ3166`.
- Library: this ArduinoMDNS checkout, based on merged commit
  `52af85fe541f465ef65b75cfe850e8bccee47dab`. The runner confirmed the selected
  library directory, rather than accepting the SDK's bundled copy.
- Runner/sketch/probe inputs: exact SHA-256 hashes retained in the local run's
  `summary.json`. These identify the working-tree tools executed before this
  report was added.
- Run window: 2026-09-27 21:12:35 through 21:14:03, UTC+08:00.

Reproduction command at the current location, with host-specific paths supplied.
The suite was subsequently moved from `tests/hardware` to `extras/hardware` to
comply with Arduino library rule LD003:

```powershell
& .\extras\hardware\MulticastMdnsTest\Test-MulticastMdnsHardware.ps1 `
    -Action Run -Port COM3 `
    -ArduinoCli $ArduinoCliPath `
    -SdkRoot $SdkCheckout `
    -Profile base `
    -SkipTtlCapture
```

## Observed results

| Check | Result | Evidence |
| --- | --- | --- |
| Compile from this library checkout | PASS | Selected-library assertion passed |
| Program storage | PASS | CLI reports 233,132 / 1,048,576 bytes |
| Static RAM | PASS | CLI reports 47,648 / 262,144 bytes |
| Test firmware upload | PASS | OpenOCD wrote a 344,064-byte image and reported `Verified OK` |
| Stored Wi-Fi configuration | PASS | Board connected without credentials being added to source |
| Responder startup | PASS | `HW_MDNS:BOOT`, `HW_MDNS:READY` |
| Disconnect/reconnect and multicast rejoin | PASS | `HW_MDNS:REJOIN_BEGIN`, then `HW_MDNS:REJOIN_READY` |
| Host A response | PASS | Parsed address matched the board; response length 50 bytes |
| PTR/SRV/TXT/A service response | PASS | Parsed instance, target, port 8080, TXT string and IPv4 address matched |
| Service response shape | PASS | 317 bytes, flags `0x8400`, 0 questions, 5 answers, 0 authority/additional records |
| Captured IPv4 TTL 255 | NOT RUN | `-SkipTtlCapture` selected explicitly |
| Original firmware restoration | PASS | Application region restored, then all 1,048,576 flash bytes verified before reset/run |

The wire probe produced:

```text
MDNS_DNSSD_HARDWARE_PASS address_bytes=50 service_bytes=317 flags=0x8400 questions=0 answers=5 authority=0 additional=0
```

The ELF/program-storage estimate and uploaded binary length are different
measurements; the binary also reflects the platform image layout. Static RAM
figures are not heap or stack high-water measurements.

## Additional tool validation

- Compile-only `Verify` passed for both SDK profiles: `base` and `azure-iot`.
- The installed Core 2.0.2 missing-header preflight failed as expected, with
  instructions to provide a compatible Core or explicit SDK checkout.
- The probe's existing `--self-test` passed.
- All 10 synthetic Python DNS/PCAPNG/TTL tests passed.
- PowerShell parsing/default/provenance checks and all 9 synthetic capture
  ownership/cleanup scenarios passed without accessing PktMon or a board.

## Firmware protection and limitations

Before testing, the complete internal flash was read and verified into a
private local backup. Restoration was performed separately from the runner:
only the application region beginning at `0x0800C000` was rewritten, leaving
the bootloader out of the write operation. A subsequent full-flash verification
matched the original backup, and the board was reset to run that firmware.

The first manually issued restore command failed to open its Windows path due
to OpenOCD/Tcl quoting. It was corrected to the uploader's double-brace quoting;
the final programming, application verification and full-flash verification
all succeeded. The test firmware is not left installed.

Automatic TTL capture is unavailable on this host: the inspected PktMon help
does not establish named-filter removal support, and normal execution is not
elevated. The capture helper therefore fails closed instead of clearing shared
filters or stopping another capture. No real packet capture was performed.

This run does not establish TTL 255, long-duration hardware stability, heap or
stack high-water bounds, or qualification of other boards/transports.

Raw serial/network logs and the firmware backup remain under the ignored
`.hardware-results` directory. They are intentionally not committed: logs
contain LAN information and a firmware backup may contain private configuration.
This report omits Wi-Fi names, IP addresses and private firmware contents.

## Review follow-up validation

The probe was subsequently hardened against false qualification:

- PCAPNG packet lengths cannot consume trailers, padding beyond their declared
  packet, or the next block. Section/interface metadata and Ethernet link type
  are checked; truncated or unsupported packet blocks are rejected.
- Captured IPv4/UDP lengths must describe a complete, unfragmented datagram.
  TTL evidence requires UDP source/destination port 5353 and a nonempty,
  structurally valid DNS response. Queries cannot establish or contaminate
  response TTL evidence.
- Live responses require source port 5353. DNS name expansion, compression,
  supported RDATA lengths and trailing-data boundaries are checked.

Before the fixes, the new regressions reproduced 17 failures and 1 error.
Afterward all **18 Python tests** and the probe self-test passed. The
PowerShell safety tests remained unchanged. A clean source export also passed
Arduino Lint 1.3.0 with no errors; the pre-existing reserved-name warning
LP012 remains. Manual tools/sketches now live under `extras/hardware` to
satisfy library layout rule LD003.

The hardened live probe was rechecked on the same board after Wi-Fi rejoin,
using the previously verified firmware fixture. The fixture hash and unchanged
library source hashes were checked before reuse; only the host-side probe had
changed. It again reported the 50-byte A response and 317-byte service response
shown above. The final retest result was `functional-probe-retest-passed`.
The original firmware was again restored and the complete internal flash
verified. No SDK repository operation was required for this retest.

One preliminary retest's external launcher could not select a unique Python
executable. It failed rather than claiming success, restored the firmware, and
was corrected to preflight the selected interpreter before the successful
repeat. That launcher is not part of the migrated runner.

These fixes and synthetic TTL tests do **not** change the physical TTL status:
real IPv4 TTL capture remains unverified, and `hardwareQualified` remains false.
