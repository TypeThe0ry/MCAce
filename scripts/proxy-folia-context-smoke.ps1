[CmdletBinding()]
param(
    [ValidateSet('Velocity', 'Bungee', 'Both')]
    [string]$Proxy = 'Both',
    [switch]$UsePreparedOffline,
    [string]$PreparedRoot = '',
    [string]$FoliaJar = '',
    [string]$FoliaSha256 = '',
    [switch]$ReportOnly,
    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build\runtime-player-probe\runs'
$aggregateRoot = Join-Path $repoRoot 'build\runtime-player-probe\folia-current'
$aggregatePath = Join-Path $aggregateRoot 'report.json'
$expectedFoliaSha256 = 'dcf2333211c1468c8eddc482bc8549600818cc661a709124a79c752f8fa2ac3a'
$artifactPaths = [ordered]@{
    velocity = Join-Path $repoRoot 'mcace-server-velocity\build\libs\mcace-server-velocity-0.1.0-SNAPSHOT.jar'
    bungee = Join-Path $repoRoot 'mcace-server-bungeecord\build\libs\mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
    paper = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
}

function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "FOLIA_CONTEXT_FILE_REQUIRED: $Path" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-DirectLocalPath([string]$Path, [switch]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw "FOLIA_CONTEXT_DIRECTORY_REQUIRED: $Path" }
    if (-not $Directory -and $item.PSIsContainer) { throw "FOLIA_CONTEXT_FILE_REQUIRED: $Path" }
    if ($item.PSDrive.DisplayRoot -or $item.PSDrive.Root.StartsWith('\\')) {
        throw "FOLIA_CONTEXT_LOCAL_DRIVE_REQUIRED: $Path"
    }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "FOLIA_CONTEXT_REPARSE_PATH_REJECTED: $($cursor.FullName)"
        }
        $parentPath = Split-Path -Path $cursorPath -Parent
        if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $cursorPath) { break }
        $cursorPath = $parentPath
    }
    return $item.FullName
}

function Resolve-OfflineGradle {
    $gradleUserRoot = if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { Join-Path $env:USERPROFILE '.gradle' }
    $root = Join-Path $gradleUserRoot 'wrapper\dists\gradle-9.6.1-bin'
    $commands = @(Get-ChildItem -LiteralPath $root -Filter gradle.bat -File -Recurse -ErrorAction Stop)
    if ($commands.Count -ne 1) { throw 'FOLIA_CONTEXT_OFFLINE_GRADLE_9_6_1_REQUIRED' }
    return Assert-DirectLocalPath $commands[0].FullName
}

function Assert-Java21 {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) { throw 'FOLIA_CONTEXT_JAVA_HOME_21_REQUIRED' }
    $java = Assert-DirectLocalPath (Join-Path $env:JAVA_HOME 'bin\java.exe')
    $text = (& $java -version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $text -notmatch '(?m)^(openjdk|java) version "21\.') {
        throw 'FOLIA_CONTEXT_JAVA_21_REQUIRED'
    }
}

function Get-SourceManifestSha256 {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $rootInputs = @('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties', 'gradlew', 'gradlew.bat')
        $wrapperInputs = @('scripts\proxy-folia-context-smoke.ps1', 'scripts\test-proxy-folia-context-smoke.ps1')
        $files = Get-ChildItem -LiteralPath $repoRoot -File -Recurse -Force |
            Where-Object {
                $relative = $_.FullName.Substring($repoRoot.Length + 1)
                $segments = $relative -split '\\'
                $moduleInput = $segments[0] -like 'mcace-*' -and
                    ('src' -in $segments -or $segments[-1] -in @('build.gradle.kts', 'gradle.lockfile'))
                $relative -in $rootInputs -or $relative -in $wrapperInputs -or
                    $segments[0] -eq 'gradle' -or $moduleInput
            } | Sort-Object FullName
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("$relative|$(Get-Sha256 $file.FullName)`n")
            [void]$sha.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return [Convert]::ToHexString($sha.Hash).ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-CurrentBinding {
    if (-not $UsePreparedOffline) {
        throw 'FOLIA_CONTEXT_USE_PREPARED_OFFLINE_REQUIRED: online preparation is not performed by this gate'
    }
    if ([string]::IsNullOrWhiteSpace($PreparedRoot) -or [string]::IsNullOrWhiteSpace($FoliaJar) -or
            [string]::IsNullOrWhiteSpace($FoliaSha256)) {
        throw 'FOLIA_CONTEXT_PREPARED_ROOT_JAR_AND_SHA_REQUIRED'
    }
    Assert-Java21
    $resolvedPrepared = Assert-DirectLocalPath ([System.IO.Path]::GetFullPath($PreparedRoot)) -Directory
    $resolvedFolia = Assert-DirectLocalPath ([System.IO.Path]::GetFullPath($FoliaJar))
    foreach ($directory in @('cache', 'libraries', 'versions')) {
        $null = Assert-DirectLocalPath (Join-Path $resolvedPrepared $directory) -Directory
    }
    if (Test-Path -LiteralPath (Join-Path $resolvedPrepared 'admission-test-private-key.pk8')) {
        throw 'FOLIA_CONTEXT_EPHEMERAL_PRIVATE_KEY_RETAINED'
    }
    $supplied = $FoliaSha256.Trim().ToLowerInvariant()
    if ($supplied -notmatch '^[0-9a-f]{64}$' -or $supplied -ne $expectedFoliaSha256 -or
            (Get-Sha256 $resolvedFolia) -ne $supplied) {
        throw 'FOLIA_CONTEXT_ARTIFACT_SHA256_MISMATCH'
    }
    $hashes = [ordered]@{}
    foreach ($entry in $artifactPaths.GetEnumerator()) {
        $null = Assert-DirectLocalPath $entry.Value
        $hashes[$entry.Key] = Get-Sha256 $entry.Value
    }
    return [ordered]@{
        prepared_root = $resolvedPrepared
        folia_jar = $resolvedFolia
        source_manifest_sha256 = Get-SourceManifestSha256
        folia_server_sha256 = $supplied
        velocity_plugin_sha256 = $hashes.velocity
        bungee_plugin_sha256 = $hashes.bungee
        paper_plugin_sha256 = $hashes.paper
        java_major = 21
        gradle_version = '9.6.1'
    }
}

function Assert-RawReport([string]$Path, [string]$ExpectedProxy) {
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $mode = if ($ExpectedProxy -eq 'VELOCITY') { 'velocity-modern' } else { 'bungee-ip-forwarding' }
    if ($report.schema -ne 4 -or $report.proxy -ne $ExpectedProxy -or
            $report.backend_platform -ne 'FOLIA' -or $report.backend_minecraft_version -ne '1.21.4' -or
            $report.forwarding_mode -ne $mode) { throw "FOLIA_CONTEXT_REPORT_IDENTITY_INVALID: $Path" }
    foreach ($name in @('forwarding_configured', 'tcp_connected', 'login_success', 'compression_seen',
            'configuration_finished', 'mcace_server_hello', 'mcace_auth_result', 'mcace_auth_accepted',
            'backend_admission', 'backend_context_shadow_audit')) {
        if ($report.$name -isnot [bool] -or -not $report.$name) {
            throw "FOLIA_CONTEXT_REPORT_ASSERTION_FAILED: $ExpectedProxy/$name"
        }
    }
    if (@($report.limitations).Count -ne 0 -or @($report.remaining_run_processes).Count -ne 0) {
        throw "FOLIA_CONTEXT_REPORT_LIMITATION_OR_PROCESS_RESIDUE: $ExpectedProxy"
    }
    return [ordered]@{
        platform = $ExpectedProxy
        forwarding_mode = $mode
        authenticated = $true
        backend_admission = $true
        backend_context_shadow_audit = $true
        limitations_count = 0
        remaining_run_process_count = 0
        raw_report_sha256 = Get-Sha256 $Path
        raw_report = $Path.Substring($repoRoot.Length + 1).Replace('\', '/')
        passed = $true
    }
}

function Write-Aggregate([object]$Binding, [object[]]$Cases) {
    New-Item -ItemType Directory -Force -Path $aggregateRoot | Out-Null
    $report = [ordered]@{
        schema = 'MCACE_PROXY_FOLIA_CONTEXT_CURRENT_V1'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED_PREPARED_OFFLINE'
        proxy_scope = $Proxy.ToUpperInvariant()
        backend_platform = 'FOLIA'
        backend_minecraft_version = '1.21.4'
        exact_folia_1_21_1_coverage = $false
        source_manifest_sha256 = $Binding.source_manifest_sha256
        folia_server_sha256 = $Binding.folia_server_sha256
        velocity_plugin_sha256 = $Binding.velocity_plugin_sha256
        bungee_plugin_sha256 = $Binding.bungee_plugin_sha256
        paper_plugin_sha256 = $Binding.paper_plugin_sha256
        java_major = 21
        gradle_version = '9.6.1'
        expected_case_count = $Cases.Count
        observed_case_count = $Cases.Count
        all_cases_passed = $true
        cases = $Cases
    }
    [System.IO.File]::WriteAllText($aggregatePath, ($report | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false))
}

function Assert-Aggregate([object]$Binding) {
    if (-not (Test-Path -LiteralPath $aggregatePath -PathType Leaf)) { throw 'FOLIA_CONTEXT_AGGREGATE_REQUIRED' }
    $report = Get-Content -LiteralPath $aggregatePath -Raw | ConvertFrom-Json
    $age = [DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse([string]$report.generated_at)
    if ($age.TotalMinutes -lt 0 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw 'FOLIA_CONTEXT_AGGREGATE_STALE'
    }
    foreach ($name in @('source_manifest_sha256', 'folia_server_sha256', 'velocity_plugin_sha256',
            'bungee_plugin_sha256', 'paper_plugin_sha256', 'java_major', 'gradle_version')) {
        if ($report.$name -ne $Binding.$name) { throw "FOLIA_CONTEXT_BINDING_MISMATCH: $name" }
    }
    if ($report.schema -ne 'MCACE_PROXY_FOLIA_CONTEXT_CURRENT_V1' -or
            -not $report.all_cases_passed -or $report.exact_folia_1_21_1_coverage -ne $false -or
            $report.observed_case_count -ne $report.expected_case_count) { throw 'FOLIA_CONTEXT_AGGREGATE_INVALID' }
    foreach ($case in @($report.cases)) {
        $rawPath = Join-Path $repoRoot ([string]$case.raw_report).Replace('/', '\')
        if ((Get-Sha256 $rawPath) -ne $case.raw_report_sha256) { throw 'FOLIA_CONTEXT_RAW_BINDING_MISMATCH' }
        $null = Assert-RawReport $rawPath ([string]$case.platform)
    }
}

$binding = Get-CurrentBinding
if ($ReportOnly) {
    Assert-Aggregate $binding
    Write-Output 'PROXY_FOLIA_CONTEXT_SMOKE_PASS|build/runtime-player-probe/folia-current/report.json'
    exit 0
}

$gradle = Resolve-OfflineGradle
$selectors = switch ($Proxy) {
    'Velocity' { [ordered]@{ VELOCITY = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingToFoliaReturnsShadowContext' } }
    'Bungee' { [ordered]@{ BUNGEE = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingToFoliaReturnsShadowContext' } }
    default { [ordered]@{
        VELOCITY = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingToFoliaReturnsShadowContext'
        BUNGEE = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingToFoliaReturnsShadowContext'
    } }
}
$cases = [System.Collections.Generic.List[object]]::new()
foreach ($entry in $selectors.GetEnumerator()) {
    $started = [DateTime]::UtcNow.AddSeconds(-2)
    & $gradle '-Dmcace.runtime.folia-context.enabled=true' `
        "-Dmcace.runtime.folia.jar=$($binding.folia_jar)" `
        "-Dmcace.runtime.folia.prepared-root=$($binding.prepared_root)" `
        '-Dmcace.runtime.folia.minecraft-version=1.21.4' ':mcace-runtime-integration:test' `
        '--tests' $entry.Value '--rerun-tasks' '--offline' '--no-build-cache' `
        '--no-configuration-cache' '--no-daemon' '--no-parallel' '--max-workers=1' '--console=plain'
    if ($LASTEXITCODE -ne 0) { throw "FOLIA_CONTEXT_GRADLE_FAILED: $($entry.Key)" }
    $prefix = $entry.Key.ToString().ToLowerInvariant() + '-folia-'
    $fresh = @(Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction Stop |
        Where-Object { $_.Name.StartsWith($prefix) } |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -ErrorAction SilentlyContinue } |
        Where-Object { $null -ne $_ -and $_.LastWriteTimeUtc -ge $started } |
        Sort-Object LastWriteTimeUtc -Descending)
    if ($fresh.Count -ne 1) { throw "FOLIA_CONTEXT_FRESH_REPORT_COUNT_INVALID: $($entry.Key)/$($fresh.Count)" }
    $cases.Add((Assert-RawReport $fresh[0].FullName $entry.Key))
}
$bindingAfter = Get-CurrentBinding
foreach ($name in @('source_manifest_sha256', 'folia_server_sha256', 'velocity_plugin_sha256',
        'bungee_plugin_sha256', 'paper_plugin_sha256')) {
    if ($binding[$name] -ne $bindingAfter[$name]) { throw "FOLIA_CONTEXT_SOURCE_CHANGED: $name" }
}
Write-Aggregate $binding $cases.ToArray()
Assert-Aggregate $binding
Write-Output 'PROXY_FOLIA_CONTEXT_SMOKE_PASS|build/runtime-player-probe/folia-current/report.json'
