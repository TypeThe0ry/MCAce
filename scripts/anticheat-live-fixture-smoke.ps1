[CmdletBinding(DefaultParameterSetName = 'Disabled')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$Execute,
    [Parameter(ParameterSetName = 'Report', Mandatory)] [switch]$ReportOnly,
    [Parameter(ParameterSetName = 'Report', Mandatory)] [string]$ReportPath,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')] [string]$ExpectedReportSha256,
    [Parameter(ParameterSetName = 'Report')]
    [ValidateRange(1, 1440)] [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$schema = 'MCACE_ANTICHEAT_LIVE_FIXTURE_V1'
$reportRoot = Join-Path $repoRoot 'build\anticheat-live-fixtures\evidence-runs'

function Assert-AbsoluteRegularFile([string]$Path, [string]$Field) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"') -or
            -not [IO.Path]::IsPathRooted($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw "ANTICHEAT_LIVE_FIXTURE_ABSOLUTE_PATH_REQUIRED: $Field"
    }
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) {
        return $item.FullName
    }
    throw "ANTICHEAT_LIVE_FIXTURE_REGULAR_FILE_REQUIRED: $Field"
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ExactHash([string]$Path, [string]$Expected, [string]$Field) {
    $actual = Get-FileSha256 $Path
    if ($actual -cne $Expected.Trim().ToLowerInvariant()) {
        throw "ANTICHEAT_LIVE_FIXTURE_HASH_MISMATCH: $Field"
    }
    return $actual
}

function ConvertTo-ReportTimestamp([object]$Value) {
    if ($Value -is [DateTimeOffset]) {
        return [DateTimeOffset]$Value
    }
    if ($Value -is [DateTime]) {
        return [DateTimeOffset]([DateTime]$Value)
    }

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Value,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed)) {
        throw 'ANTICHEAT_LIVE_FIXTURE_REPORT_TIMESTAMP_INVALID'
    }
    return $parsed
}

function Write-SanitizedReport([hashtable]$Report) {
    $null = New-Item -ItemType Directory -Path $reportRoot -Force
    $runId = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $runRoot = Join-Path $reportRoot $runId
    $null = New-Item -ItemType Directory -Path $runRoot -Force
    $reportFile = Join-Path $runRoot 'report.json'
    $staging = "$reportFile.staging-$([guid]::NewGuid().ToString('N'))"
    $Report.generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    [IO.File]::WriteAllText(
        $staging,
        (($Report | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $staging -Destination $reportFile -Force
    return $reportFile
}

if ($PSCmdlet.ParameterSetName -eq 'Report') {
    $resolved = Assert-AbsoluteRegularFile $ReportPath 'ReportPath'
    $actualHash = Assert-ExactHash $resolved $ExpectedReportSha256 'ReportPath'
    $report = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ($report.schema -cne $schema -or $report.passed -ne $true -or
            $report.client_executable_code_loaded -ne $true -or
            $report.third_party_code_loaded -ne $false -or
            $report.server_confirmed_count -ne 3 -or
            $report.clean_false_positive_count -ne 0) {
        throw 'ANTICHEAT_LIVE_FIXTURE_REPORT_INVALID'
    }
    # PowerShell 7.5+ may materialize ISO-8601 JSON strings as DateTime values.
    # Handle both that representation and the string representation used by
    # Windows PowerShell without an implicit culture-sensitive ToString/Parse.
    $generatedAt = ConvertTo-ReportTimestamp $report.generated_at
    $age = ([DateTimeOffset]::UtcNow - $generatedAt.ToUniversalTime()).TotalMinutes
    if ($age -lt -1 -or $age -gt $MaximumReportAgeMinutes) {
        throw 'ANTICHEAT_LIVE_FIXTURE_REPORT_STALE'
    }
    Write-Output "ANTICHEAT_LIVE_FIXTURE_REPORT_ONLY_PASS|$actualHash"
    exit 0
}

if ($PSCmdlet.ParameterSetName -ne 'Execute') {
    throw 'ANTICHEAT_LIVE_FIXTURE_EXECUTE_OR_REPORT_ONLY_REQUIRED'
}

$gradle = Join-Path $repoRoot 'gradlew.bat'
if (-not (Test-Path -LiteralPath $gradle -PathType Leaf)) {
    throw 'ANTICHEAT_LIVE_FIXTURE_GRADLE_WRAPPER_MISSING'
}
$testClass = 'com.ellan.mcace.runtime.AntiCheatLiveFixtureIntegrationTest'
$arguments = @(
    ':mcace-runtime-integration:test', '--tests', $testClass, '--offline', '--no-daemon',
    '--no-parallel', '--max-workers=1', '--no-configuration-cache', '--console=plain'
)
$oldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
Push-Location -LiteralPath $repoRoot
try {
    $output = (& $gradle @arguments 2>&1 | Out-String)
}
finally {
    Pop-Location
}
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $oldErrorActionPreference
if ($exitCode -ne 0) {
    throw "ANTICHEAT_LIVE_FIXTURE_GRADLE_FAILED: exit=$exitCode`n$output"
}
$testXmlPath = Join-Path $repoRoot 'mcace-runtime-integration\build\test-results\test\TEST-com.ellan.mcace.runtime.AntiCheatLiveFixtureIntegrationTest.xml'
$testOutput = if (Test-Path -LiteralPath $testXmlPath -PathType Leaf) {
    Get-Content -LiteralPath $testXmlPath -Raw
} else { '' }
if (($output + $testOutput) -notmatch 'ANTICHEAT_LIVE_FIXTURE_INTEGRATION_PASS\|versions=3\|executed=true\|server_confirmed=3\|clean_false_positive=0') {
    throw 'ANTICHEAT_LIVE_FIXTURE_PASS_MARKER_MISSING'
}

$sourceCommit = ((& git -C $repoRoot rev-parse HEAD) | Out-String).Trim()
if ($sourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'ANTICHEAT_LIVE_FIXTURE_SOURCE_COMMIT_UNAVAILABLE'
}
$report = [ordered]@{
    schema = $schema
    passed = $true
    source_commit = $sourceCommit.ToLowerInvariant()
    fixture_mode = 'CONTROLLED_EXECUTABLE_CLIENT_AND_SERVER_CORRELATION'
    client_executable_code_loaded = $true
    client_modlist_reported = $true
    server_behavior_signal_independent = $true
    correlated_same_session = $true
    server_confirmed_count = 3
    server_confirmed_action = 'QUARANTINE'
    clean_false_positive_count = 0
    signed_lab_policy = $true
    third_party_code_loaded = $false
    third_party_network_access = $false
    public_server = $false
    actual_fabric_client = $false
    versions = @('1.21.11', '26.1.2', '26.2')
    negative_boundary = [ordered]@{
        clean_client_no_mod_observation = $true
        clean_client_no_impossible_movement = $true
        clean_client_no_server_confirmed_event = $true
    }
    limitations = @(
        'The executable fixture is an MCAce-owned test JAR, not third-party cheat code.',
        'The harness is a loopback protocol/client-server integration, not a public server or a full Minecraft GUI session.',
        'Quarantine is emitted by the signed lab policy runtime; production authority and live kick/ban remain separate release gates.'
    )
    test_class = $testClass
    sanitization = [ordered]@{
        absolute_paths_copied = $false
        pids_copied = $false
        ports_copied = $false
        uuids_copied = $false
        fixture_bytes_copied = $false
    }
}
$reportFile = Write-SanitizedReport $report
$reportHash = Get-FileSha256 $reportFile
Write-Output "ANTICHEAT_LIVE_FIXTURE_EXECUTE_PASS|$reportHash|$reportFile"
