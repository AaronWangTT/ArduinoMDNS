#requires -Version 7.0
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BoardAddress,
    [Parameter(Mandatory = $true)]
    [string]$LocalAddress,
    [Parameter(Mandatory = $true)]
    [string]$EtlPath,
    [Parameter(Mandatory = $true)]
    [string]$PcapPath,
    [Parameter(Mandatory = $true)]
    [string]$ProbeScript,
    [Parameter(Mandatory = $true)]
    [string]$LogPath,
    [Parameter(Mandatory = $true)]
    [string]$PythonExecutable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$filterName = 'ArduinoMDNS-' + [guid]::NewGuid().ToString('N')
$started = $false
$filterAdded = $false
$logCreated = $false

function Invoke-PktMon {
    param([string[]]$Arguments)

    "pktmon $($Arguments -join ' ')" | Add-Content -LiteralPath $LogPath
    $output = (& pktmon @Arguments 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $output | Add-Content -LiteralPath $LogPath
    if ($code -ne 0) { throw "pktmon $($Arguments -join ' ') failed with exit code $code." }
    return $output
}

function Test-PktMonIdle {
    param([string]$Status)

    return $Status.Trim() -cmatch '\A(Packet Monitor is not running\.|Packet monitoring is not running\.)\z'
}

function Test-PktMonOwned {
    param([string]$Status, [string]$ExpectedEtl)

    $files = @([regex]::Matches($Status, '(?im)^\s*Log file(?: name)?\s*:\s*"?([^"\r\n]+?)"?\s*$'))
    if ($files.Count -ne 1) { return $false }
    try {
        return [IO.Path]::GetFullPath($files[0].Groups[1].Value.Trim()) -ieq [IO.Path]::GetFullPath($ExpectedEtl)
    }
    catch { return $false }
}

function Assert-PktMonIdle {
    $status = Invoke-PktMon @('status')
    if (-not (Test-PktMonIdle $status)) {
        throw 'PktMon is busy or its status format is unknown. No session will be stopped. Arrange an idle capture window manually.'
    }
}

try {
    foreach ($path in @($LogPath, $EtlPath, $PcapPath)) {
        if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite existing evidence: $path" }
    }
    $null = New-Item -ItemType File -Path $LogPath
    $logCreated = $true
    foreach ($address in @($BoardAddress, $LocalAddress)) {
        if ([Net.IPAddress]::Parse($address).AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw 'BoardAddress and LocalAddress must be IPv4 addresses.'
        }
    }
    $EtlPath = [IO.Path]::GetFullPath($EtlPath)
    Assert-PktMonIdle
    $removeHelp = Invoke-PktMon @('filter', 'remove', 'help')
    if ($removeHelp -notmatch '(?im)^\s*pktmon filter remove\s+(?:\[<?name>?\]|<name>)') {
        throw 'This PktMon version cannot prove support for removing a named filter. Capture is disabled to preserve global filters. Use a supported PktMon version or collect a pcapng externally; -SkipTtlCapture is functional-only, not qualification.'
    }
    $filters = Invoke-PktMon @('filter', 'list')
    if ($filters.Trim() -cnotmatch '\A(No packet filters\.|No filters\.)\z') {
        throw 'PktMon filters already exist or their listing is unknown. They will not be changed; arrange an empty-filter capture window manually.'
    }
    Assert-PktMonIdle
    $null = Invoke-PktMon @(
        'filter', 'add', $filterName, '--ip-address', $BoardAddress,
        '--transport-protocol', 'UDP', '--port', '5353'
    )
    $filterAdded = $true
    Assert-PktMonIdle
    $null = Invoke-PktMon @('start', '--capture', '--pkt-size', '0', '--file-name', $EtlPath)
    $started = $true
    if (-not (Test-PktMonOwned (Invoke-PktMon @('status')) $EtlPath)) {
        throw 'Cannot confirm ownership of the running PktMon session; refusing to stop an unknown session.'
    }
    Start-Sleep -Seconds 1
    & $PythonExecutable $ProbeScript --local $LocalAddress --board $BoardAddress --send-only 2>&1 |
        Add-Content -LiteralPath $LogPath
    if ($LASTEXITCODE -ne 0) { throw "mDNS probe failed with exit code $LASTEXITCODE." }
}
catch {
    if ($logCreated) { $_ | Out-String | Add-Content -LiteralPath $LogPath }
    throw
}
finally {
    if ($filterAdded) {
        # Never issue global stop/remove commands without positively identifying our own session.
        $status = Invoke-PktMon @('status')
        if ($started -and (Test-PktMonOwned $status $EtlPath)) {
            $null = Invoke-PktMon @('stop')
            $status = Invoke-PktMon @('status')
        }
        if (Test-PktMonIdle $status) {
            $null = Invoke-PktMon @('filter', 'remove', $filterName)
        }
        else {
            $message = "Capture ownership/state changed. Left session and filter '$filterName' untouched; inspect pktmon.log and clean up manually."
            $message | Add-Content -LiteralPath $LogPath
            throw $message
        }
    }
}

$null = Invoke-PktMon @('etl2pcap', $EtlPath, '--out', $PcapPath)
if (-not (Test-Path -LiteralPath $PcapPath -PathType Leaf)) { throw "PktMon did not produce $PcapPath." }
