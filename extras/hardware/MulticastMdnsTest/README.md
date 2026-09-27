# AZ3166 multicast mDNS hardware test

Copied from `devkit-sdk\tests\hardware\manual\MulticastMdnsTest` at SDK revision
`fc1b82a0ea8a0bf1c2bd0b2b0f4d2aeaa83a6ef2`, then adapted for this
ArduinoMDNS checkout. The copy operation did not modify or remove SDK originals.
The matching
`MulticastMdnsTest.ino` imports `AZ3166MulticastUdp.h`: the transport comes
from the AZ3166 Core; the mDNS implementation must come from **this repository**.
No Core packaging implementation is copied into ArduinoMDNS.

The suite lives under `extras` because Arduino library rule LD003 requires
sketches to be under `examples` or `extras`. It is a manual test fixture, not
a registration-only example.

See [the recorded test results](TEST_RESULTS.md) for the real-board functional
run, firmware restoration, and explicitly unverified TTL/hardware limits.

## Dependencies

- Windows, PowerShell 7 (`pwsh`), Git, Arduino CLI and the AZ3166 Core/compiler.
- A Core with `AZ3166MulticastUDP`. The inspected **Core 2.0.2 installation lacks
  `AZ3166MulticastUdp.h`** and is rejected with an actionable preflight message.
  Install a compatible Core, or explicitly use `-SdkRoot` below. The runner
  never silently falls back to a sibling SDK or its bundled ArduinoMDNS.
- For `Run` only: Python 3 (standard library only), a DevKit connected through
  ST-Link, its explicit `COMn` port, and PC/board on the same IPv4 LAN.
  VPNs/firewalls must allow mDNS UDP 5353 multicast.
- Configure working Wi-Fi credentials on the board beforehand. The sketch
  calls **`WiFi.begin()` without arguments**, using stored credentials;
  do not put credentials into the sketch or logs.
- For TTL capture: permission to approve a UAC prompt, compatible Windows
  PktMon, and an idle, empty-filter capture window. See the safety gate below.

## Compile only (the default)

From this repository root:

```powershell
& .\extras\hardware\MulticastMdnsTest\Test-MulticastMdnsHardware.ps1 `
    -ArduinoCli C:\tools\arduino-cli.exe
```

This is equivalent to `-Action Verify`. It does not upload, access serial,
execute Python/network probes, request elevation, or capture packets.
An explicit `-Port` does not enable uploads by itself.

Use a compatible SDK checkout without modifying or installing it:

```powershell
& .\extras\hardware\MulticastMdnsTest\Test-MulticastMdnsHardware.ps1 `
    -Action Verify `
    -ArduinoCli C:\tools\arduino-cli.exe `
    -SdkRoot C:\STM32F412\devkit-sdk `
    -Profile base `
    -ArduinoDataDirectory "$env:LOCALAPPDATA\Arduino15"
```

`-SdkRoot` requires that checkout's existing
`tools\build\Az3166Build.Common.ps1` and
`tools\package\Stage-Az3166Platform.ps1`. The runner reads its build lock,
uses the pinned `ar`/`nm` already installed under the chosen
`ArduinoDataDirectory\packages\AZ3166\tools`, and stages the platform in its
own retained run directory. Both `base` (default) and `azure-iot` profiles are
supported. It neither rewrites SDK files nor vendors Core build tooling.
`-Profile` is rejected without `-SdkRoot` rather than ignored. The default
Arduino data directory is `%LOCALAPPDATA%\Arduino15`; a custom value is
preserved in the isolated CLI configuration.

The compile command includes `--library <absolute ArduinoMDNS repository>`.
The runner retains verbose compiler output and requires its `Using library
ArduinoMDNS ... in folder:` entry to equal this repository before declaring
Verify success or allowing an upload. The selected Core path, library path,
Git revisions/worktree state, source SHA-256 hashes, and build artifacts are
recorded for provenance. If CLI output changes and cannot be validated, the
runner fails closed; inspect `compile.log`.

## Explicit hardware run

```powershell
& .\extras\hardware\MulticastMdnsTest\Test-MulticastMdnsHardware.ps1 `
    -Action Run -Port COM3 `
    -ArduinoCli C:\tools\arduino-cli.exe `
    -SdkRoot C:\STM32F412\devkit-sdk
```

`Run` requires an explicit port and installs the validation sketch. Restore
the intended production firmware afterward. `-PythonExecutable` can select
a particular Python 3 executable. No automatic port selection is performed.

Full acceptance requires compilation with this library, OpenOCD `Verified OK`,
stored-credential Wi-Fi connection, responder startup, disconnect/reconnect
and multicast rejoin, parsed A/PTR/SRV/TXT responses with correct names,
targets, service port, TXT lengths and IPv4 address, **and captured IPv4 TTL
255** on board responses.

The sketch advertises test metadata; it does not implement an HTTP server on
port 8080. The probe checks DNS-SD records, not an HTTP response.

`-SkipTtlCapture` runs only functional checks. Its successful result is
`functional-passed-ttl-skipped`, `ttl: skipped`, `hardwareQualified: false`.
It must never be reported as full hardware qualification.

## PktMon safety and limitations

Only the TTL helper is elevated. It checks status read-only before changes,
rejects busy, inaccessible, localized/unrecognized status, existing filters,
or unknown listing formats, and requires help advertising **named-filter
removal**. It adds a unique filter, uses a unique run-specific ETL path and
confirms the active log path identifies its session before stopping it.
It removes only its own named filter, never clears all filters, never stops
a pre-existing session, and never overwrites existing capture files.
If ownership becomes uncertain, it leaves state alone, fails, and logs the
unique filter name for manual inspection. Do not run other PktMon tools
concurrently: PktMon has machine-global state, not atomic ownership locks.

On this development machine, `pktmon filter remove help` advertises only
global removal, so **automatic TTL capture is intentionally unavailable**.
Non-elevated status also returns access denied. These are safety/preflight
limitations, not a successful TTL test. Use a PktMon version with verified
named removal and supported English status formats, or independently collect
a pcapng and validate it with:

```powershell
python .\extras\hardware\MulticastMdnsTest\mdns_probe.py `
    --board 192.168.1.50 --pcap .\board-mdns.pcapng
```

An external capture result is separate evidence; it does not retroactively
turn the runner's skipped result into full qualification.

TTL validation accepts only complete, unfragmented Ethernet/IPv4 DNS responses
from the board on UDP source and destination port 5353. Queries and empty DNS
responses cannot establish evidence. PCAPNG section/interface metadata,
enhanced packet block lengths, IPv4/UDP lengths, DNS names and RDATA boundaries
are validated; malformed or unsupported captures fail rather than reading
trailers or adjacent blocks as packet data.

## Evidence and tests

Every invocation retains `.hardware-results\<run-id>` on success and failure:
CLI configuration, SDK staging/build output when applicable, source and
artifact SHA-256 hashes in `summary.json`, compile/upload logs, serial/probe
logs, and TTL ETL/pcapng/logs when produced. Read `result`, `error`, `ttl`,
and `hardwareQualified` together. Failed runs throw/nonzero exit; Verify
success means compile-only, never hardware success. Keep captures private
because they may contain LAN traffic. Delete your own old run directories
manually when no longer needed.

Host-side Python probe tests do not need a board; they validate DNS and capture
parsing with synthetic packets. CI must remain compile/host-test-only, never
run `-Action Run`, serial access, UAC, uploads or live capture.

Run the dependency-free PowerShell runner safety tests with:

```powershell
pwsh -NoProfile -File .\extras\hardware\MulticastMdnsTest\Test-MdnsHardwareRunner.ps1
```

These parse the scripts, check defaults/library binding and ownership helpers,
and replace all PktMon/probe commands with synthetic doubles. Cases cover busy
or unknown state, unsupported removal, pre-existing filters/logs, successful
owned cleanup, failed probes/start, and a session whose ownership changes.
They require neither elevation nor hardware and never invoke real PktMon.
