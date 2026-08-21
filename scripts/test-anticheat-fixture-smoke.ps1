[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = Join-Path $PSScriptRoot 'anticheat-fixture-smoke.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count -ne 0) { throw 'ANTICHEAT_FIXTURE_SCRIPT_PARSE_FAILED' }

foreach ($required in @(
        'MCACE_ANTICHEAT_FIXTURE_CLASSIFICATION_V1',
        'STATIC_FIXTURE_ONLY_NO_THIRD_PARTY_CODE_EXECUTION',
        'third_party_network_access',
        'executable_code_loaded',
        'ReportOnly',
        'dependency-verification=strict',
        'MCACE_TEST_METEOR_JAR',
        'MCACE_TEST_XRAY_PACK')) {
    if (-not $source.Contains($required)) {
        throw "ANTICHEAT_FIXTURE_STATIC_CONTRACT_MISSING: $required"
    }
}

foreach ($forbidden in @(
        'Start-Process',
        'runClient',
        'java -jar',
        'FabricLoader.getInstance',
        'PluginManager.callEvent')) {
    if ($source.Contains($forbidden)) {
        throw "ANTICHEAT_FIXTURE_FORBIDDEN_EXECUTION_TOKEN: $forbidden"
    }
}

Write-Output 'ANTICHEAT_FIXTURE_WRAPPER_STATIC_PASS'
