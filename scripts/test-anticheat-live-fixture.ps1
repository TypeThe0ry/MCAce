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
        'ConvertTo-ReportTimestamp',
        'Resolve-JavaHome',
        'MCACE_JAVA21_HOME',
        'ANTICHEAT_LIVE_FIXTURE_JAVA21_REQUIRED',
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

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ("mcace-anticheat-live-report-{0}" -f [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fixtureRoot -Force
try {
    $reportPath = Join-Path $fixtureRoot 'report.json'
    $report = [ordered]@{
        schema = 'MCACE_ANTICHEAT_LIVE_FIXTURE_V1'
        passed = $true
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        client_executable_code_loaded = $true
        third_party_code_loaded = $false
        server_confirmed_count = 3
        clean_false_positive_count = 0
    }
    [IO.File]::WriteAllText(
        $reportPath,
        (($report | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    $reportHash = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $reportOnlyOutput = (& $scriptPath -ReportOnly -ReportPath $reportPath `
        -ExpectedReportSha256 $reportHash -MaximumReportAgeMinutes 5 | Out-String).Trim()
    if ($reportOnlyOutput -cne "ANTICHEAT_LIVE_FIXTURE_REPORT_ONLY_PASS|$reportHash") {
        throw 'ANTICHEAT_LIVE_FIXTURE_REPORT_ONLY_RUNTIME_FAILED'
    }
}
finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'ANTICHEAT_LIVE_FIXTURE_WRAPPER_STATIC_PASS'
