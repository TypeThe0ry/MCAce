[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = Join-Path $PSScriptRoot 'anticheat-live-fixture-smoke.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count -ne 0) { throw 'ANTICHEAT_LIVE_FIXTURE_SCRIPT_PARSE_FAILED' }

foreach ($required in @(
        'MCACE_ANTICHEAT_LIVE_FIXTURE_V1',
        'CONTROLLED_EXECUTABLE_CLIENT_AND_SERVER_CORRELATION',
        'client_executable_code_loaded',
        'client_modlist_reported',
        'server_behavior_signal_independent',
        'correlated_same_session',
        'server_confirmed_count',
        'clean_false_positive_count',
        'QUARANTINE',
        'third_party_code_loaded',
        'ReportOnly',
        ':mcace-runtime-integration:test')) {
    if (-not $source.Contains($required)) {
        throw "ANTICHEAT_LIVE_FIXTURE_STATIC_CONTRACT_MISSING: $required"
    }
}

foreach ($forbidden in @(
        'https://',
        'http://',
        'Start-Process',
        'java -jar',
        'Invoke-WebRequest')) {
    if ($source.Contains($forbidden)) {
        throw "ANTICHEAT_LIVE_FIXTURE_FORBIDDEN_EXTERNAL_EXECUTION_TOKEN: $forbidden"
    }
}

$javaSource = Get-Content -LiteralPath (Join-Path $repoRoot 'mcace-runtime-integration/src/test/java/com/ellan/mcace/runtime/AntiCheatLiveFixtureMain.java') -Raw
$entrypointSource = Get-Content -LiteralPath (Join-Path $repoRoot 'mcace-runtime-integration/src/test/java/com/ellan/mcace/runtime/ControlledCheatEntrypoint.java') -Raw
foreach ($requiredJava in @(
        'URLClassLoader',
        'CONTROLLED_CHEAT_FIXTURE_EXECUTED',
        'CLIENT_REPORTED',
        'SERVER_CONFIRMED',
        'mcace-fixture-server',
        'DETECTION_MATCH_EXACT_SHA256')) {
    if (-not ($javaSource.Contains($requiredJava) -or $entrypointSource.Contains($requiredJava))) {
        throw "ANTICHEAT_LIVE_FIXTURE_JAVA_CONTRACT_MISSING: $requiredJava"
    }
}

Write-Output 'ANTICHEAT_LIVE_FIXTURE_WRAPPER_STATIC_PASS'
