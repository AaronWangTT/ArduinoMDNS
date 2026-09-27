#requires -Version 7.0
# Host-only regression tests: evaluate script bodies with synthetic commands, never PktMon or a board.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$testRoot = Join-Path $repositoryRoot ".hardware-results\runner-tests-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$null = New-Item -ItemType Directory -Path $testRoot -Force

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Read-ScriptAst {
    param([string]$Name)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $Name), [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "Parser errors in $Name"
    return $ast
}

$runnerAst = Read-ScriptAst 'Test-MulticastMdnsHardware.ps1'
$captureAst = Read-ScriptAst 'Capture-MdnsTtl.ps1'
$actionParameter = @($runnerAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Action' })[0]
Assert-True ($actionParameter.DefaultValue.Value -eq 'Verify') 'Default must be compile-only Verify.'
$runnerText = $runnerAst.Extent.Text
Assert-True ($runnerText.Contains("'--library', `$repositoryRoot")) 'Compile must explicitly bind current library.'
Assert-True ($runnerText.Contains('$summary.selectedLibrary =')) 'Selected library provenance must be recorded.'
Assert-True ($runnerText.Contains("'functional-passed-ttl-skipped'")) 'Skipped TTL must have a partial result.'

# Extract only definitions for pure helper checks; do not execute runner/capture entry points.
$definitions = $captureAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Test-PktMonIdle', 'Test-PktMonOwned')
}, $true)
foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
Assert-True (Test-PktMonIdle "Packet Monitor is not running.`r`n") 'Known idle output rejected.'
Assert-True (-not (Test-PktMonIdle 'Packet Monitor is running.')) 'Running status accepted.'
Assert-True (-not (Test-PktMonIdle 'Access is denied.')) 'Unknown status accepted.'
$ownedEtl = Join-Path $testRoot 'owned.etl'
Assert-True (Test-PktMonOwned "Log file: $ownedEtl" $ownedEtl) 'Owned ETL not recognized.'
Assert-True (-not (Test-PktMonOwned "Log file: $ownedEtl.other" $ownedEtl)) 'Foreign ETL recognized as owned.'
Assert-True (-not (Test-PktMonOwned "Log file: $ownedEtl`nLog file: C:\other.etl" $ownedEtl)) 'Ambiguous ETL recognized.'

# The AST EndBlock excludes #requires and parameters, allowing command doubles in an unelevated host.
$captureBody = [scriptblock]::Create(($captureAst.EndBlock.Statements.Extent.Text -join "`n"))
foreach ($scenario in @('busy', 'unknown', 'unsupported', 'filters', 'success', 'probe-failed', 'start-failed', 'ownership-changed', 'existing-log')) {
    & {
        $state = @{
            scenario = $scenario
            phase = 'idle'
            calls = [Collections.Generic.List[string]]::new()
        }
        $folder = Join-Path $testRoot $scenario
        $null = New-Item -ItemType Directory -Path $folder
        $BoardAddress = '192.0.2.10'
        $LocalAddress = '192.0.2.20'
        $EtlPath = Join-Path $folder 'owned.etl'
        $PcapPath = Join-Path $folder 'owned.pcapng'
        $LogPath = Join-Path $folder 'pktmon.log'
        $ProbeScript = 'synthetic-probe.py'
        $PythonExecutable = 'Invoke-SyntheticProbe'
        if ($scenario -eq 'existing-log') { 'untouched' | Set-Content -LiteralPath $LogPath }

        function Start-Sleep {}
        function Invoke-SyntheticProbe {
            $global:LASTEXITCODE = if ($state.scenario -eq 'probe-failed') { 1 } else { 0 }
            'Synthetic probe'
        }
        function pktmon {
            $command = $args -join ' '
            $state.calls.Add($command)
            $global:LASTEXITCODE = 0
            switch -Regex ($command) {
                '^status$' {
                    if ($state.scenario -eq 'unknown') { return 'Unknown localized output' }
                    if ($state.scenario -eq 'busy' -or $state.phase -eq 'foreign') { return 'Log file: C:\foreign.etl' }
                    if ($state.phase -eq 'running') { return "Log file: $EtlPath" }
                    return 'Packet Monitor is not running.'
                }
                '^filter remove help$' {
                    if ($state.scenario -eq 'unsupported') { return 'pktmon filter remove' }
                    return 'pktmon filter remove [name]'
                }
                '^filter list$' {
                    if ($state.scenario -eq 'filters') { return 'Existing filter: preserve-me' }
                    return 'No packet filters.'
                }
                '^filter add ' { return 'Added' }
                '^filter remove ArduinoMDNS-[0-9a-f]+$' { return 'Removed named filter' }
                '^start ' {
                    $state.phase = if ($state.scenario -in @('start-failed', 'ownership-changed')) { 'foreign' } else { 'running' }
                    if ($state.scenario -eq 'start-failed') { $global:LASTEXITCODE = 1 }
                    return 'Synthetic start'
                }
                '^stop$' {
                    Assert-True ($state.phase -eq 'running') 'Attempted to stop an unowned session.'
                    $state.phase = 'idle'
                    return 'Stopped'
                }
                '^etl2pcap ' { 'synthetic' | Set-Content -LiteralPath $PcapPath; return 'Converted' }
                default { throw "Unexpected synthetic PktMon invocation: $command" }
            }
        }

        $failed = $false
        try { & $captureBody }
        catch {
            $failed = $true
            if ($scenario -eq 'success') { Write-Warning $_ }
        }
        Assert-True ($failed -eq ($scenario -ne 'success')) "Wrong outcome: $scenario"
        Assert-True (-not ($state.calls -contains 'filter remove')) 'Global filter removal is forbidden.'
        if ($scenario -in @('busy', 'unknown', 'unsupported', 'filters', 'existing-log')) {
            Assert-True (@($state.calls | Where-Object { $_ -match '^(start|stop|filter add|filter remove Arduino)' }).Count -eq 0) "Preflight mutated state: $scenario"
        }
        if ($scenario -in @('success', 'probe-failed')) {
            Assert-True ($state.calls -contains 'stop') "Own capture not stopped: $scenario"
            Assert-True (@($state.calls | Where-Object { $_ -match '^filter remove ArduinoMDNS-' }).Count -eq 1) "Own filter not removed: $scenario"
        }
        if ($scenario -in @('start-failed', 'ownership-changed')) {
            Assert-True (-not ($state.calls -contains 'stop')) "Foreign capture stopped: $scenario"
            Assert-True (@($state.calls | Where-Object { $_ -match '^filter remove ArduinoMDNS-' }).Count -eq 0) "Filter modified during foreign capture: $scenario"
        }
        if ($scenario -eq 'existing-log') {
            Assert-True ((Get-Content -LiteralPath $LogPath -Raw).Trim() -eq 'untouched') 'Existing log was modified.'
        }
        Write-Host "PASS $scenario"
    }
}
Write-Host "PASS parser, defaults, library binding, TTL reporting, ownership helpers and 9 synthetic capture scenarios. Logs: $testRoot"
