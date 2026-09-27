#requires -Version 7.0

[CmdletBinding()]
param(
    [ValidateSet('Verify', 'Run')]
    [string]$Action = 'Verify',
    [ValidatePattern('^COM\d+$')]
    [string]$Port,
    [string]$ArduinoCli = 'arduino-cli',
    [string]$ArduinoDataDirectory,
    [string]$SdkRoot,
    [ValidateSet('base', 'azure-iot')]
    [string]$Profile = 'base',
    [string]$PythonExecutable = 'python',
    [switch]$SkipTtlCapture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$root = Join-Path $repositoryRoot ".hardware-results\$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$build = Join-Path $root 'build'
$configuration = Join-Path $root 'arduino-cli.yaml'
$probe = Join-Path $PSScriptRoot 'mdns_probe.py'
$summary = [ordered]@{
    action = $Action
    result = 'failed'
    hardwareQualified = $false
    ttl = 'not-run'
    port = $Port
    libraryRoot = $repositoryRoot
    selectedLibrary = $null
    sdkRoot = $SdkRoot
    profile = if ($SdkRoot) { $Profile } else { 'installed' }
    platformRoot = $null
    fqbn = $null
    startedUtc = [DateTime]::UtcNow.ToString('o')
    sourceHashes = @()
    artifactHashes = @()
    error = $null
}
$null = New-Item -ItemType Directory -Path $root -Force

function Invoke-LoggedCommand {
    param([string]$Executable, [string[]]$Arguments, [string]$LogName)

    $log = Join-Path $root $LogName
    $output = (& $Executable @Arguments 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $output | Set-Content -LiteralPath $log -Encoding utf8
    if ($code -ne 0) {
        throw "$Executable failed (exit $code). See $log"
    }
    return $output
}

function Get-InputHashes {
    $files = @(
        Get-ChildItem -LiteralPath $repositoryRoot -File |
            Where-Object { $_.Extension -in @('.h', '.cpp') -or $_.Name -eq 'library.properties' }
        Get-ChildItem -LiteralPath (Join-Path $repositoryRoot 'utility') -File -Recurse
        Get-ChildItem -LiteralPath $PSScriptRoot -File |
            Where-Object { $_.Extension -in @('.ino', '.py', '.ps1') }
    )
    return @($files | Sort-Object FullName | ForEach-Object {
        @{ path = $_.FullName; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
}

function Wait-ForSerialMarker {
    param([string]$Marker, [int]$Seconds)

    $serial = [IO.Ports.SerialPort]::new($Port, 115200, 'None', 8, 'One')
    $serial.ReadTimeout = 1000
    try {
        $serial.Open()
        $deadline = (Get-Date).AddSeconds($Seconds)
        while ((Get-Date) -lt $deadline) {
            try {
                $line = $serial.ReadLine().Trim()
                if ($line) {
                    $line | Add-Content -LiteralPath (Join-Path $root 'serial.log')
                    Write-Host $line
                    if ($line -match 'HW_MDNS:.*FAILED') { throw "Hardware reported failure: $line" }
                    if ($line -match $Marker) { return $Matches[1] }
                }
            }
            catch [TimeoutException] {}
        }
        throw "Timed out waiting for serial marker: $Marker"
    }
    finally {
        if ($serial.IsOpen) { $serial.Close() }
        $serial.Dispose()
    }
}

function Get-CandidateLocalAddress {
    param([string]$BoardAddress)

    $boardBytes = [Net.IPAddress]::Parse($BoardAddress).GetAddressBytes()
    return @(
        Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object {
                if ($_.AddressState -ne 'Preferred' -or $_.PrefixLength -eq 0) { return $false }
                $candidateBytes = [Net.IPAddress]::Parse($_.IPAddress).GetAddressBytes()
                $remaining = [int]$_.PrefixLength
                for ($index = 0; $index -lt 4; $index++) {
                    $bits = [Math]::Min(8, [Math]::Max(0, $remaining))
                    if ($bits -gt 0) {
                        $mask = (0xff -shl (8 - $bits)) -band 0xff
                        if (($candidateBytes[$index] -band $mask) -ne ($boardBytes[$index] -band $mask)) {
                            return $false
                        }
                    }
                    $remaining -= $bits
                }
                return $true
            } |
            Select-Object -ExpandProperty IPAddress -Unique
    )
}

try {
    if ($Action -eq 'Run' -and -not $Port) { throw 'Action Run requires an explicit -Port COMn; no automatic upload port selection.' }
    if (-not $SdkRoot -and $PSBoundParameters.ContainsKey('Profile')) {
        throw '-Profile is only supported with -SdkRoot; installed packages retain their installed profile.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot 'ArduinoMDNS.h')) -or
        -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'MulticastMdnsTest.ino'))) {
        throw 'Run this script in ArduinoMDNS\tests\hardware\MulticastMdnsTest with its matching sketch.'
    }
    $summary.sourceHashes = Get-InputHashes
    $summary.libraryRevision = (& git -C $repositoryRoot rev-parse HEAD | Out-String).Trim()
    $summary.libraryChanges = @(& git -C $repositoryRoot status --short --untracked-files=no)
    if (-not $ArduinoDataDirectory) {
        if (-not $env:LOCALAPPDATA) { throw 'Specify -ArduinoDataDirectory on this host.' }
        $ArduinoDataDirectory = Join-Path $env:LOCALAPPDATA 'Arduino15'
    }
    $ArduinoDataDirectory = (Resolve-Path -LiteralPath $ArduinoDataDirectory).Path
    $summary.arduinoDataDirectory = $ArduinoDataDirectory
    $arduino = @(Get-Command $ArduinoCli -CommandType Application -ErrorAction Stop)[0].Source
    $summary.arduinoCli = $arduino
    $summary.arduinoCliSha256 = (Get-FileHash -LiteralPath $arduino).Hash
    $null = Invoke-LoggedCommand $arduino @('version') 'cli-version.log'
    $fqbn = 'AZ3166:stm32f4:MXCHIP_AZ3166'
    if ($SdkRoot) {
        $SdkRoot = (Resolve-Path -LiteralPath $SdkRoot).Path
        $summary.sdkRoot = $SdkRoot
        $common = Join-Path $SdkRoot 'tools\build\Az3166Build.Common.ps1'
        $stager = Join-Path $SdkRoot 'tools\package\Stage-Az3166Platform.ps1'
        foreach ($required in @($common, $stager)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing SDK dependency: $required" }
        }
        . $common
        $lock = Get-Az3166BuildLock -Path (Join-Path $SdkRoot 'tools\build\az3166-build-lock.json')
        $toolRoot = Join-Path $ArduinoDataDirectory 'packages\AZ3166\tools'
        $bin = Join-Path $toolRoot "$($lock.tools.armNoneEabiGcc.packageName)\$($lock.tools.armNoneEabiGcc.version)\bin"
        $ar = Join-Path $bin 'arm-none-eabi-ar.exe'
        $nm = Join-Path $bin 'arm-none-eabi-nm.exe'
        foreach ($tool in @($ar, $nm)) {
            if (-not (Test-Path -LiteralPath $tool)) { throw "Install the SDK's pinned build tools into $ArduinoDataDirectory; missing $tool" }
        }
        $stage = Join-Path $root 'sketchbook\hardware\AZ3166Checkout\stm32f4'
        $summary.sdkRevision = (& git -C $SdkRoot rev-parse HEAD | Out-String).Trim()
        $summary.sdkChanges = @(& git -C $SdkRoot status --short)
        # The external stager uses GetTempPath; keep all of its scratch files in this run's evidence directory.
        $oldTemp = $env:TEMP
        $oldTmp = $env:TMP
        try {
            $env:TEMP = $root
            $env:TMP = $root
            $null = Invoke-LoggedCommand (Join-Path $PSHOME 'pwsh.exe') @(
                '-NoProfile', '-File', $stager, '-Destination', $stage,
                '-Profile', $Profile, '-Ar', $ar, '-Nm', $nm
            ) 'stage.log'
        }
        finally { $env:TEMP = $oldTemp; $env:TMP = $oldTmp }
        $fqbn = $lock.arduino.fqbn
    }
    $summary.fqbn = $fqbn
    @{
        directories = @{
            data = $ArduinoDataDirectory
            downloads = (Join-Path $root 'downloads')
            user = (Join-Path $root 'sketchbook')
        }
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $configuration -Encoding utf8
    $cliArguments = @('--config-file', $configuration, '--no-color')
    $details = Invoke-LoggedCommand $arduino ($cliArguments + @('board', 'details', '--fqbn', $fqbn, '--json')) 'board.json' |
        ConvertFrom-Json
    $platformProperty = @($details.build_properties | Where-Object { $_ -like 'runtime.platform.path=*' })
    if ($platformProperty.Count -ne 1) { throw 'Cannot establish selected Core platform provenance from Arduino CLI board metadata.' }
    $platformRoot = $platformProperty[0].Substring('runtime.platform.path='.Length)
    $summary.platformRoot = $platformRoot
    $transportHeaders = @(Get-ChildItem -LiteralPath $platformRoot -Filter AZ3166MulticastUdp.h -File -Recurse)
    if ($transportHeaders.Count -eq 0) {
        throw "Selected Core at $platformRoot lacks AZ3166MulticastUdp.h (released Core 2.0.2 does not include it). Install a Core containing AZ3166MulticastUDP, or explicitly pass -SdkRoot to a devkit-sdk checkout with this implementation and existing staging/build tools. No SDK or bundled-library fallback was used."
    }
    $summary.transportHeaders = @($transportHeaders | ForEach-Object {
        @{ path = $_.FullName; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash }
    })
    Write-Host "Compiling with ArduinoMDNS checkout: $repositoryRoot"
    Write-Host "Core: $platformRoot; FQBN: $fqbn"
    $compile = Invoke-LoggedCommand $arduino ($cliArguments + @(
        'compile', '--fqbn', $fqbn, '--build-path', $build, '--warnings', 'all',
        '--verbose', '--library', $repositoryRoot, $PSScriptRoot
    )) 'compile.log'
    $selected = @([regex]::Matches($compile, '(?m)^Using library ArduinoMDNS\s+at version\s+.+?\s+in folder:\s*(.+?)\s*$'))
    if ($selected.Count -ne 1 -or
        [IO.Path]::GetFullPath($selected[0].Groups[1].Value.Trim()).TrimEnd('\', '/') -ine $repositoryRoot.TrimEnd('\', '/')) {
        throw 'Compilation did not confirm this ArduinoMDNS checkout as the selected library; refusing hardware validation. See compile.log.'
    }
    $summary.selectedLibrary = $selected[0].Groups[1].Value.Trim()
    Write-Host "Verified selected library: $($summary.selectedLibrary)"
    if ($Action -eq 'Verify') {
        $summary.result = 'compile-only-passed'
        Write-Host 'Compile-only verification passed; no upload, serial, network probe, or packet capture performed.'
        return
    }

    $python = @(Get-Command $PythonExecutable -CommandType Application -ErrorAction Stop)[0].Source
    if ((Invoke-LoggedCommand $python @('--version') 'python-version.log') -notmatch '^Python 3\.') {
        throw 'Python 3 is required for mDNS packet validation.'
    }
    $upload = Invoke-LoggedCommand $arduino ($cliArguments + @(
        'upload', '--fqbn', $fqbn, '--port', $Port, '--input-dir', $build, $PSScriptRoot
    )) 'upload.log'
    if ($upload -notmatch '\*\*\s+Verified OK\s+\*\*') { throw 'Upload completed without OpenOCD reporting Verified OK.' }
    $boardAddress = Wait-ForSerialMarker -Marker '^HW_MDNS:REJOIN_READY IP=(\d+\.\d+\.\d+\.\d+)$' -Seconds 90
    $summary.boardAddress = $boardAddress
    $localAddress = $null
    foreach ($candidate in Get-CandidateLocalAddress $boardAddress) {
        try {
            $null = Invoke-LoggedCommand $python @($probe, '--local', $candidate, '--board', $boardAddress) "probe-$candidate.log"
            $localAddress = $candidate
            break
        }
        catch { Write-Warning $_ }
    }
    if (-not $localAddress) { throw "No local interface received valid mDNS responses from $boardAddress." }
    $summary.localAddress = $localAddress
    if ($SkipTtlCapture) {
        $summary.ttl = 'skipped'
        $summary.result = 'functional-passed-ttl-skipped'
        Write-Warning 'Functional checks passed, but TTL capture was skipped: NOT full hardware qualification.'
    }
    else {
        $summary.ttl = 'failed'
        $pcap = Join-Path $root 'mdns.pcapng'
        $captureArguments = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', (Join-Path $PSScriptRoot 'Capture-MdnsTtl.ps1'),
            '-BoardAddress', $boardAddress, '-LocalAddress', $localAddress,
            '-EtlPath', (Join-Path $root 'mdns.etl'), '-PcapPath', $pcap,
            '-ProbeScript', $probe, '-LogPath', (Join-Path $root 'pktmon.log'),
            '-PythonExecutable', $python
        )
        # Start-Process flattens ArgumentList; quote each argument, including paths with spaces.
        $quoted = @($captureArguments | ForEach-Object {
            if ($_ -match '["\r\n]') { throw 'Invalid quote or newline in capture arguments.' }
            '"' + $_ + '"'
        })
        $capture = Start-Process (Join-Path $PSHOME 'pwsh.exe') -Verb RunAs -ArgumentList $quoted -Wait -PassThru
        if ($capture.ExitCode -ne 0) { throw "Elevated capture failed ($($capture.ExitCode)); see pktmon.log. No full hardware qualification." }
        $null = Invoke-LoggedCommand $python @($probe, '--board', $boardAddress, '--pcap', $pcap) 'ttl-validation.log'
        $summary.ttl = 'passed'
        $summary.result = 'hardware-passed'
        $summary.hardwareQualified = $true
        Write-Host 'AZ3166 multicast mDNS hardware qualification passed, including IPv4 TTL 255.'
    }
}
catch {
    $summary.error = $_.Exception.Message
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $root 'error.log')
    throw
}
finally {
    $summary.finishedUtc = [DateTime]::UtcNow.ToString('o')
    $summary.artifactHashes = @(Get-ChildItem -LiteralPath $root -File -Recurse |
        Where-Object { $_.Extension -in @('.log', '.json', '.yaml', '.elf', '.bin', '.hex', '.pcapng', '.etl') } |
        ForEach-Object { @{ path = $_.FullName; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash } })
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'summary.json') -Encoding utf8
    Write-Host "Retained evidence: $root"
}
