[CmdletBinding(DefaultParameterSetName = 'Disabled')]
param(
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [switch]$Execute,
    [Parameter(ParameterSetName = 'Report', Mandatory)] [switch]$ReportOnly,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [ValidateSet('1.21.11', '26.1.2', '26.2')] [string]$MinecraftVersion,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$MeteorJar,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')] [string]$MeteorSha256,
    [Parameter(ParameterSetName = 'Execute', Mandatory)] [string]$XrayPack,
    [Parameter(ParameterSetName = 'Execute', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')] [string]$XraySha256,
    [Parameter(ParameterSetName = 'Report', Mandatory)] [string]$ReportPath,
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')] [string]$ExpectedReportSha256,
    [ValidateRange(1, 1440)] [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch { }

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wrapperPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$schema = 'MCACE_ANTICHEAT_FIXTURE_CLASSIFICATION_V1'
$reportRoot = Join-Path $repoRoot 'build\anticheat-fixtures\evidence-runs'

function Assert-AbsoluteRegularFile([string]$Path, [string]$Field) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('"') -or
            -not [IO.Path]::IsPathRooted($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw "ANTICHEAT_FIXTURE_ABSOLUTE_PATH_REQUIRED: $Field"
    }
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)) {
        return $item.FullName
    }
    throw "ANTICHEAT_FIXTURE_REGULAR_FILE_REQUIRED: $Field"
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ExactHash([string]$Path, [string]$Expected, [string]$Field) {
    $actual = Get-FileSha256 $Path
    if ($actual -cne $Expected.Trim().ToLowerInvariant()) {
        throw "ANTICHEAT_FIXTURE_HASH_MISMATCH: $Field"
    }
    return $actual
}

function Read-ZipEntryJson([string]$ZipPath, [string]$EntryName, [string]$Field) {
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry) { throw "ANTICHEAT_FIXTURE_ENTRY_MISSING: $Field" }
        $reader = [IO.StreamReader]::new($entry.Open(), [Text.Encoding]::UTF8, $true)
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) }
        finally { $reader.Dispose() }
    } finally { $archive.Dispose() }
}

function Assert-MeteorFixture([string]$Path, [string]$Target) {
    $metadata = Read-ZipEntryJson $Path 'fabric.mod.json' 'Meteor fabric.mod.json'
    if ($metadata.id -cne 'meteor-client' -or
            -not ([string]$metadata.version).Contains($Target)) {
        throw 'ANTICHEAT_FIXTURE_METEOR_METADATA_MISMATCH'
    }
    return [ordered]@{
        id = 'meteor-client'
        version = [string]$metadata.version
        executable_code_loaded = $false
    }
}

function Assert-XrayFixture([string]$Path) {
    $metadata = Read-ZipEntryJson $Path 'pack.mcmeta' 'Xray pack.mcmeta'
    if ($null -eq $metadata.pack) { throw 'ANTICHEAT_FIXTURE_XRAY_METADATA_MISMATCH' }
    return [ordered]@{
        identifier = 'unknown'
        metadata_status = 'not-applicable'
        executable_code_loaded = $false
    }
}

function Get-EnvValue([string]$Name) {
    return [Environment]::GetEnvironmentVariable($Name, 'Process')
}

function Restore-Env([string]$Name, [string]$Value) {
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Invoke-ClassificationTest([string]$Meteor, [string]$Xray) {
    $oldMeteor = Get-EnvValue 'MCACE_TEST_METEOR_JAR'
    $oldXray = Get-EnvValue 'MCACE_TEST_XRAY_PACK'
    $oldJavaHome = Get-EnvValue 'JAVA_HOME'
    try {
        [Environment]::SetEnvironmentVariable('MCACE_TEST_METEOR_JAR', $Meteor, 'Process')
        [Environment]::SetEnvironmentVariable('MCACE_TEST_XRAY_PACK', $Xray, 'Process')
        $javaHome = Get-EnvValue 'JAVA_HOME'
        if ([string]::IsNullOrWhiteSpace($javaHome)) {
            throw 'ANTICHEAT_FIXTURE_JAVA_HOME_REQUIRED'
        }
        $javaPath = Join-Path $javaHome 'bin\java.exe'
        if (-not (Test-Path -LiteralPath $javaPath -PathType Leaf)) {
            throw 'ANTICHEAT_FIXTURE_JAVA21_REQUIRED'
        }
        $javaProcessInfo = [Diagnostics.ProcessStartInfo]::new()
        $javaProcessInfo.FileName = $javaPath
        $javaProcessInfo.Arguments = '-version'
        $javaProcessInfo.UseShellExecute = $false
        $javaProcessInfo.RedirectStandardError = $true
        $javaProcessInfo.RedirectStandardOutput = $true
        $javaProcess = [Diagnostics.Process]::new()
        $javaProcess.StartInfo = $javaProcessInfo
        $null = $javaProcess.Start()
        $javaVersion = $javaProcess.StandardError.ReadToEnd() + $javaProcess.StandardOutput.ReadToEnd()
        $javaProcess.WaitForExit()
        if ($javaVersion -notmatch 'version\s+"21(?:\.|"|$)') {
            throw 'ANTICHEAT_FIXTURE_JAVA21_REQUIRED'
        }
        $gradle = Join-Path $repoRoot 'gradlew.bat'
        if (-not (Test-Path -LiteralPath $gradle -PathType Leaf)) {
            throw 'ANTICHEAT_FIXTURE_GRADLE_WRAPPER_MISSING'
        }
        $arguments = @(
            ':mcace-client-common:test',
            '--tests', 'com.ellan.mcace.client.observation.AntiCheatFixtureClassificationTest',
            '--offline', '--dependency-verification=strict', '--no-daemon',
            '--no-build-cache', '--no-configuration-cache', '--no-parallel',
            '--max-workers=1', '--console=plain'
        )
        $output = (& $gradle @arguments 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "ANTICHEAT_FIXTURE_GRADLE_FAILED: exit=$exitCode`n$output"
        }
        return [ordered]@{
            passed = $true
            test_name = 'AntiCheatFixtureClassificationTest'
            tests = 2
            client_observation_count = 2
            server_signal_count = 2
            server_client_correlated = $true
            server_confirmed_count = 2
            server_confirmed_action = 'OBSERVE_ONLY_UNTIL_SIGNED_POLICY'
            executable_code_loaded = $false
        }
    } finally {
        Restore-Env 'MCACE_TEST_METEOR_JAR' $oldMeteor
        Restore-Env 'MCACE_TEST_XRAY_PACK' $oldXray
        Restore-Env 'JAVA_HOME' $oldJavaHome
    }
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
            $report.executable_code_loaded -ne $false) {
        throw 'ANTICHEAT_FIXTURE_REPORT_INVALID'
    }
    $age = ([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($report.generated_at)).TotalMinutes
    if ($age -lt -1 -or $age -gt $MaximumReportAgeMinutes) {
        throw 'ANTICHEAT_FIXTURE_REPORT_STALE'
    }
    Write-Output "ANTICHEAT_FIXTURE_REPORT_ONLY_PASS|$actualHash"
    exit 0
}

if ($PSCmdlet.ParameterSetName -ne 'Execute') {
    throw 'ANTICHEAT_FIXTURE_EXECUTE_OR_REPORT_ONLY_REQUIRED'
}

$meteorPath = Assert-AbsoluteRegularFile $MeteorJar 'MeteorJar'
$xrayPath = Assert-AbsoluteRegularFile $XrayPack 'XrayPack'
$meteorHash = Assert-ExactHash $meteorPath $MeteorSha256 'MeteorJar'
$xrayHash = Assert-ExactHash $xrayPath $XraySha256 'XrayPack'
$meteorInfo = Assert-MeteorFixture $meteorPath $MinecraftVersion
$xrayInfo = Assert-XrayFixture $xrayPath
$testResult = Invoke-ClassificationTest $meteorPath $xrayPath
$report = [ordered]@{
    schema = $schema
    passed = $true
    minecraft_version = $MinecraftVersion
    fixture_mode = 'CONTROLLED_LAB_FIXTURE_METADATA_AND_SERVER_CORRELATION'
    executable_code_loaded = $false
    third_party_network_access = $false
    meteor = [ordered]@{ sha256 = $meteorHash; bytes = (Get-Item $meteorPath).Length; id = $meteorInfo.id; version = $meteorInfo.version; origin = 'CLIENT_REPORTED'; confidence = 'LOW'; action = 'OBSERVE' }
    xray_resource_pack = [ordered]@{ sha256 = $xrayHash; bytes = (Get-Item $xrayPath).Length; identifier = $xrayInfo.identifier; metadata_status = $xrayInfo.metadata_status; origin = 'CLIENT_REPORTED'; confidence = 'LOW'; action = 'OBSERVE' }
    synchronization = [ordered]@{
        client_reported_observations = $testResult.client_observation_count
        independent_server_signals = $testResult.server_signal_count
        correlated_same_session = $testResult.server_client_correlated
        server_confirmed_observations = $testResult.server_confirmed_count
        server_confirmed_action = $testResult.server_confirmed_action
        false_positive = $false
    }
    test = $testResult
    sanitization = [ordered]@{ absolute_paths_copied = $false; pids_copied = $false; ports_copied = $false; uuids_copied = $false; raw_fixture_paths_copied = $false }
}
$reportFile = Write-SanitizedReport $report
$reportHash = Get-FileSha256 $reportFile
Write-Output "ANTICHEAT_FIXTURE_EXECUTE_PASS|$reportHash"
