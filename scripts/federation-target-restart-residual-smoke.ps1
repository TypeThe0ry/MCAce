[CmdletBinding(DefaultParameterSetName = 'Execute')]
param(
    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [switch]$ReportOnly,

    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$reportSchema = 'MCACE_FEDERATION_TARGET_RESTART_EXECUTED_V2'
$bindingSchema = 'MCACE_FEDERATION_TARGET_RESTART_BINDING_V1'
$commitSchema = 'MCACE_FEDERATION_TARGET_RESTART_COMMIT_V1'
$fileTimestampLowerBoundTolerance = [TimeSpan]::FromSeconds(2)
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build\runtime-federation-target-restart\runs'
$evidenceRunsRoot = Join-Path $repoRoot 'build\runtime-federation-target-restart\evidence-runs'
$wrapperPropertiesPath = Join-Path $repoRoot 'gradle\wrapper\gradle-wrapper.properties'
$gradleWrapperJarPath = Join-Path $repoRoot 'gradle\wrapper\gradle-wrapper.jar'
$platformPaths = [ordered]@{
    velocity = Join-Path $repoRoot 'build\platform-smoke\cache\velocity-3.5.1-615.jar'
    paper = Join-Path $repoRoot 'build\platform-smoke\cache\paper-1.21.1-133.jar'
    paper_prepared = Join-Path $repoRoot 'build\platform-smoke\cache\paper-1.21.1-133-prepared'
}
$expectedPlatformSha256 = [ordered]@{
    velocity = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
    paper = '39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9'
}
$test = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityTargetRestartResidualReplayRealProcessGate'
$rawPrefix = 'velocity-target-velocity-'
$artifactPaths = [ordered]@{
    velocity = Join-Path $repoRoot 'mcace-server-velocity\build\libs\mcace-server-velocity-0.1.0-SNAPSHOT.jar'
    bungee = Join-Path $repoRoot 'mcace-server-bungeecord\build\libs\mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
    paper = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
}

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-PathSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $hasher.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-DirectLocalPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw "FEDERATION_RESTART_DIRECTORY_REQUIRED: $Path" }
    if (-not $Directory -and $item.PSIsContainer) { throw "FEDERATION_RESTART_FILE_REQUIRED: $Path" }
    if (-not [string]::IsNullOrWhiteSpace([string]$item.PSDrive.DisplayRoot) -or
            ([string]$item.PSDrive.Root).StartsWith('\\')) {
        throw "FEDERATION_RESTART_LOCAL_DRIVE_REQUIRED: $Path"
    }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "FEDERATION_RESTART_REPARSE_PATH_REJECTED: $($cursor.FullName)"
        }
        $parentPath = Split-Path -Path $cursorPath -Parent
        if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $cursorPath) { break }
        $cursorPath = $parentPath
    }
    return $item.FullName
}

function ConvertTo-RepoRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $repoRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'FEDERATION_RESTART_PATH_OUTSIDE_REPOSITORY'
    }
    return $fullPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Get-JsonPropertyNames {
    param([Parameter(Mandatory)]$Value)
    return @($Value.PSObject.Properties | ForEach-Object Name)
}

function Test-ExactJsonProperties {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Expected
    )

    $actual = @(Get-JsonPropertyNames $Value | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Test-JsonString([object]$Value) { return $Value -is [string] }
function Test-JsonBoolean([object]$Value) { return $Value -is [bool] }
function Test-JsonInteger([object]$Value) {
    return $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64]
}
function Test-JsonArray([object]$Value) { return $Value -is [System.Array] }

function ConvertFrom-StrictJson {
    param([Parameter(Mandatory)][string]$Raw)

    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        return ConvertFrom-Json -InputObject $Raw -DateKind String -ErrorAction Stop
    }
    return ConvertFrom-Json -InputObject $Raw -ErrorAction Stop
}

function ConvertTo-FreshUtcTimestamp {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Field
    )

    if (-not (Test-JsonString $Value)) { throw "FEDERATION_RESTART_TIMESTAMP_INVALID: $Field" }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($Value, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed) -or
            $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "FEDERATION_RESTART_TIMESTAMP_INVALID: $Field"
    }
    $age = [DateTimeOffset]::UtcNow - $parsed
    if ($age.TotalMinutes -lt -2 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw "FEDERATION_RESTART_EVIDENCE_STALE: $Field"
    }
    return $parsed
}

function Assert-RawTimestampWindow {
    param(
        [Parameter(Mandatory)][DateTimeOffset]$Observed,
        [Parameter(Mandatory)][DateTimeOffset]$NotBefore,
        [Parameter(Mandatory)][DateTimeOffset]$NotAfter,
        [Parameter(Mandatory)][string]$Field
    )

    if ($NotAfter -lt $NotBefore) {
        throw "FEDERATION_RESTART_RAW_TIMESTAMP_WINDOW_INVALID: $Field"
    }
    # Only the lower bound permits a filesystem-resolution allowance. A timestamp after
    # invocation completion is always rejected as future evidence.
    if ($Observed -gt [DateTimeOffset]::UtcNow -or $Observed -gt $NotAfter -or
            $Observed.Add($fileTimestampLowerBoundTolerance) -lt $NotBefore) {
        throw "FEDERATION_RESTART_RAW_TIMESTAMP_OUTSIDE_INVOCATION: $Field"
    }
}

function Assert-SanitizedJson {
    param([Parameter(Mandatory)][string]$Raw)

    if ($Raw.Length -gt 262144 -or
            $Raw -match '(?i)(?:^|["''\s])[a-z]:[\\/]' -or
            $Raw -match '\\\\' -or
            $Raw -match '(?i)(?:^|["''\s])/(?:home|users|tmp|var|opt|mnt|root|etc|usr)/' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b' -or
            $Raw -match '(?i)"(?:pid|process_id|process_ids|[a-z0-9_]+_(?:pid|process_id|process_ids))"\s*:' -or
            $Raw -match '(?i)"(?:port|ports|[a-z0-9_]+_(?:port|ports))"\s*:') {
        throw 'FEDERATION_RESTART_EVIDENCE_NOT_SANITIZED'
    }
}

function Open-LockedJsonEvidence {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 4194304)][int]$MaximumBytes = 262144,
        [switch]$RequireSanitized
    )

    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($resolved, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw 'FEDERATION_RESTART_EVIDENCE_SIZE_INVALID'
        }
        $memory = New-Object System.IO.MemoryStream
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        } finally {
            $memory.Dispose()
        }
        $raw = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($RequireSanitized) { Assert-SanitizedJson $raw }
        $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        return [pscustomobject]@{
            path = $resolved
            raw = $raw
            sha256 = Get-BytesSha256 $bytes
            last_write_time_utc = $item.LastWriteTimeUtc
            stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Get-WrapperProperty {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $matching = @($Lines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($Name) + '\s*=') })
    if ($matching.Count -ne 1) { throw "FEDERATION_RESTART_WRAPPER_PROPERTY_INVALID: $Name" }
    return ($matching[0] -split '=', 2)[1].Trim()
}

function Assert-CleanGradleInputs {
    param([Parameter(Mandatory)][string]$GradleUserHome)

    foreach ($name in @('GRADLE_OPTS', 'JAVA_OPTS', '_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS',
            'JDK_JAVA_OPTIONS', 'GRADLE_JAVA_HOME')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "FEDERATION_RESTART_UNBOUND_GRADLE_ENVIRONMENT_REJECTED: $name"
        }
    }
    foreach ($projectFile in @('.gradle\init.gradle', '.gradle\init.gradle.kts')) {
        if (Test-Path -LiteralPath (Join-Path $repoRoot $projectFile)) {
            throw "FEDERATION_RESTART_UNBOUND_GRADLE_INPUT_REJECTED: $projectFile"
        }
    }
    $projectProperties = Assert-DirectLocalPath (Join-Path $repoRoot 'gradle.properties')
    if (@(Get-Content -LiteralPath $projectProperties -ErrorAction Stop |
            Where-Object { $_ -match '^\s*org\.gradle\.java\.home\s*=' }).Count -gt 0) {
        throw 'FEDERATION_RESTART_UNBOUND_GRADLE_JAVA_OVERRIDE_REJECTED'
    }
    if (Test-Path -LiteralPath (Join-Path $repoRoot 'gradle\gradle-daemon-jvm.properties')) {
        throw 'FEDERATION_RESTART_UNBOUND_GRADLE_DAEMON_JVM_CRITERIA_REJECTED'
    }
    $userRoot = Assert-DirectLocalPath $GradleUserHome -Directory
    foreach ($name in @('gradle.properties', 'init.gradle', 'init.gradle.kts')) {
        if (Test-Path -LiteralPath (Join-Path $userRoot $name)) {
            throw "FEDERATION_RESTART_UNBOUND_GRADLE_INPUT_REJECTED: $name"
        }
    }
    $initRoot = Join-Path $userRoot 'init.d'
    if (Test-Path -LiteralPath $initRoot -PathType Container) {
        $null = Assert-DirectLocalPath $initRoot -Directory
        $initItems = @(Get-ChildItem -LiteralPath $initRoot -Recurse -Force -ErrorAction Stop)
        if (@($initItems | Where-Object {
                    ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                }).Count -gt 0) {
            throw 'FEDERATION_RESTART_UNBOUND_GRADLE_INIT_REPARSE_REJECTED'
        }
        $initScripts = @($initItems | Where-Object {
                -not $_.PSIsContainer -and $_.Name -match '(?i)\.gradle(?:\.kts)?$'
            })
        if ($initScripts.Count -gt 0) { throw 'FEDERATION_RESTART_UNBOUND_GRADLE_INIT_SCRIPT_REJECTED' }
    }
}

function Get-TreeManifestBinding {
    param([Parameter(Mandatory)][string]$RootPath)

    $root = Assert-DirectLocalPath $RootPath -Directory
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction Stop)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $files) {
        $resolved = Assert-DirectLocalPath $file.FullName
        $relative = $resolved.Substring($root.Length + 1).Replace('\', '/')
        $encodedName = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($relative))
        $lines.Add("$encodedName`t$($file.Length)`t$(Get-PathSha256 $resolved)")
    }
    $ordered = [string[]]$lines.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n") + "`n")
    return [pscustomobject]@{ sha256 = Get-BytesSha256 $bytes; file_count = [int]$ordered.Count }
}

function Get-PlatformBinding {
    $hashes = [ordered]@{}
    foreach ($name in @('velocity', 'paper')) {
        $path = Assert-DirectLocalPath $platformPaths[$name]
        $hash = Get-PathSha256 $path
        if ($hash -cne $expectedPlatformSha256[$name]) {
            throw "FEDERATION_RESTART_PLATFORM_SHA256_MISMATCH: $name"
        }
        $hashes[$name] = $hash
    }
    $prepared = Get-TreeManifestBinding $platformPaths.paper_prepared
    if ($prepared.file_count -le 0) { throw 'FEDERATION_RESTART_PREPARED_PAPER_EMPTY' }
    return [pscustomobject]@{
        velocity_server_sha256 = $hashes.velocity
        paper_server_sha256 = $hashes.paper
        paper_prepared_manifest_sha256 = $prepared.sha256
        paper_prepared_file_count = $prepared.file_count
    }
}

function Resolve-ExactJava21 {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME) -or $env:JAVA_HOME.IndexOf('"') -ge 0) {
        throw 'FEDERATION_RESTART_JAVA_HOME_21_REQUIRED'
    }
    $javaHome = Assert-DirectLocalPath $env:JAVA_HOME -Directory
    $java = Assert-DirectLocalPath (Join-Path $javaHome 'bin\java.exe')
    $item = Get-Item -LiteralPath $java -Force -ErrorAction Stop
    $fileVersion = [string]$item.VersionInfo.FileVersion
    if ($fileVersion -notmatch '^(\d+)(?:\.|$)' -or [int]$Matches[1] -ne 21) {
        throw "FEDERATION_RESTART_JAVA_21_REQUIRED: $fileVersion"
    }
    return [pscustomobject]@{
        path = $java
        sha256 = Get-PathSha256 $java
        file_version = $fileVersion
        major = 21
    }
}

function Resolve-OfflineGradle961 {
    $properties = @(Get-Content -LiteralPath (Assert-DirectLocalPath $wrapperPropertiesPath) -ErrorAction Stop)
    $distributionUrl = Get-WrapperProperty -Name 'distributionUrl' -Lines $properties
    $distributionSha256 = (Get-WrapperProperty -Name 'distributionSha256Sum' -Lines $properties).ToLowerInvariant()
    if ($distributionUrl -notmatch '/gradle-9\.6\.1-bin\.zip$' -or
            $distributionSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'FEDERATION_RESTART_OFFLINE_GRADLE_9_6_1_CONFIGURATION_REQUIRED'
    }
    $version = '9.6.1'
    $gradleUserHome = if ([string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else {
        [System.IO.Path]::GetFullPath($env:GRADLE_USER_HOME)
    }
    Assert-CleanGradleInputs -GradleUserHome $gradleUserHome
    $distributionRoot = Assert-DirectLocalPath (Join-Path $gradleUserHome "wrapper\dists\gradle-$version-bin") -Directory
    $valid = New-Object 'System.Collections.Generic.List[object]'
    foreach ($installation in @(Get-ChildItem -LiteralPath $distributionRoot -Directory -Force -ErrorAction Stop)) {
        try {
            $installationRoot = Assert-DirectLocalPath $installation.FullName -Directory
            $ok = Assert-DirectLocalPath (Join-Path $installationRoot "gradle-$version-bin.zip.ok")
            $gradleRoot = Assert-DirectLocalPath (Join-Path $installationRoot "gradle-$version") -Directory
            $command = Assert-DirectLocalPath (Join-Path $gradleRoot 'bin\gradle.bat')
            $launcher = Assert-DirectLocalPath (Join-Path $gradleRoot "lib\gradle-launcher-$version.jar")
            $core = Assert-DirectLocalPath (Join-Path $gradleRoot "lib\gradle-core-$version.jar")
            $null = $ok
            $manifest = Get-TreeManifestBinding $gradleRoot
            $valid.Add([pscustomobject]@{
                version = $version
                distribution_sha256 = $distributionSha256
                user_home = $gradleUserHome
                command_sha256 = Get-PathSha256 $command
                launcher_path = $launcher
                launcher_sha256 = Get-PathSha256 $launcher
                core_sha256 = Get-PathSha256 $core
                installation_manifest_sha256 = $manifest.sha256
                installation_file_count = $manifest.file_count
            })
        } catch {
            if ($_.Exception.Message -notlike 'Cannot find path*' -and
                    $_.Exception.Message -notlike 'FEDERATION_RESTART_*_REQUIRED*') { throw }
        }
    }
    if ($valid.Count -ne 1) {
        throw 'FEDERATION_RESTART_OFFLINE_GRADLE_9_6_1_REQUIRED: expected exactly one verified cached installation'
    }
    return $valid[0]
}

function Get-GateSourceInputPaths {
    $paths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in @('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties',
            'gradlew', 'gradlew.bat', 'scripts\federation-target-restart-residual-smoke.ps1',
            'scripts\test-federation-evidence-binding.ps1')) {
        $candidate = Join-Path $repoRoot $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $paths.Add((Assert-DirectLocalPath $candidate))
        }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'gradle') -Recurse -Force -File -ErrorAction Stop)) {
        $paths.Add((Assert-DirectLocalPath $file.FullName))
    }
    foreach ($module in @(Get-ChildItem -LiteralPath $repoRoot -Directory -Filter 'mcace-*' -Force)) {
        foreach ($name in @('build.gradle.kts', 'gradle.lockfile')) {
            $candidate = Join-Path $module.FullName $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $paths.Add((Assert-DirectLocalPath $candidate))
            }
        }
        $sourceRoot = Join-Path $module.FullName 'src'
        if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force -File -ErrorAction Stop)) {
                $paths.Add((Assert-DirectLocalPath $file.FullName))
            }
        }
    }
    $ordered = [string[]]@($paths.ToArray() | Select-Object -Unique)
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    return $ordered
}

function Get-SourceManifestBinding {
    $paths = Get-GateSourceInputPaths
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $paths) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $relative = ConvertTo-RepoRelativePath $item.FullName
        $encodedName = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($relative))
        $lines.Add("$encodedName`t$($item.Length)`t$(Get-PathSha256 $item.FullName)")
    }
    $ordered = [string[]]$lines.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n") + "`n")
    return [pscustomobject]@{ sha256 = Get-BytesSha256 $bytes; file_count = [int]$ordered.Count }
}

function Get-CurrentBinding {
    $java = Resolve-ExactJava21
    $gradle = Resolve-OfflineGradle961
    $source = Get-SourceManifestBinding
    $platform = Get-PlatformBinding
    foreach ($artifact in $artifactPaths.Values) { $null = Assert-DirectLocalPath $artifact }
    return [ordered]@{
        wrapper_sha256 = Get-PathSha256 (Assert-DirectLocalPath $PSCommandPath)
        source_manifest_sha256 = $source.sha256
        source_file_count = $source.file_count
        velocity_plugin_sha256 = Get-PathSha256 $artifactPaths.velocity
        bungee_plugin_sha256 = Get-PathSha256 $artifactPaths.bungee
        paper_plugin_sha256 = Get-PathSha256 $artifactPaths.paper
        velocity_server_sha256 = $platform.velocity_server_sha256
        paper_server_sha256 = $platform.paper_server_sha256
        paper_prepared_manifest_sha256 = $platform.paper_prepared_manifest_sha256
        paper_prepared_file_count = $platform.paper_prepared_file_count
        gradle_wrapper_jar_sha256 = Get-PathSha256 (Assert-DirectLocalPath $gradleWrapperJarPath)
        gradle_wrapper_properties_sha256 = Get-PathSha256 (Assert-DirectLocalPath $wrapperPropertiesPath)
        java_executable_sha256 = $java.sha256
        java_file_version = $java.file_version
        java_major = $java.major
        gradle_version = $gradle.version
        gradle_distribution_sha256 = $gradle.distribution_sha256
        gradle_command_sha256 = $gradle.command_sha256
        gradle_launcher_sha256 = $gradle.launcher_sha256
        gradle_core_sha256 = $gradle.core_sha256
        gradle_installation_manifest_sha256 = $gradle.installation_manifest_sha256
        gradle_installation_file_count = $gradle.installation_file_count
        java_path = $java.path
        gradle_user_home = $gradle.user_home
        gradle_launcher_path = $gradle.launcher_path
    }
}

function Assert-CurrentBindingUnchanged {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Before,
        [Parameter(Mandatory)][System.Collections.IDictionary]$After
    )

    foreach ($name in @($Before.Keys)) {
        if ([string]$Before[$name] -cne [string]$After[$name]) {
            throw "FEDERATION_RESTART_CURRENT_INPUT_CHANGED_DURING_RUN: $name"
        }
    }
}

function Assert-RawRestartReport {
    param([Parameter(Mandatory)]$Evidence)

    $names = @('schema', 'source_proxy', 'target_proxy', 'source_authenticated',
        'grant_stored_in_memory_test_harness', 'source_client_disconnected_before_target_auth',
        'first_target_locally_authenticated', 'first_target_observed', 'old_target_proxy_terminated',
        'target_paper_kept_running', 'target_identity_preserved', 'target_federation_config_preserved',
        'restarted_target_locally_authenticated', 'target_session_changed', 'target_challenge_changed',
        'old_outer_session_rejected', 'old_session_proof_rejected', 'invalid_old_proofs_no_observation',
        'target_restart_residual_reobserved', 'residual_reacceptance',
        'post_restart_same_process_replay_rejected', 'residual_is_observation_only',
        'durable_replay_protection', 'test_only_retained_grant_or_source_session_key_written_to_disk',
        'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'content_free_audit',
        'source_audit_healthy', 'target_audit_healthy', 'temporary_proxy_private_keys_removed',
        'fabric_gui_coverage', 'limitations', 'cleanup_process_ids', 'remaining_run_processes', 'passed')
    try { $report = ConvertFrom-StrictJson $Evidence.raw }
    catch { throw 'FEDERATION_RESTART_RAW_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $report $names)) { throw 'FEDERATION_RESTART_RAW_SCHEMA_INVALID' }
    if (-not (Test-JsonInteger $report.schema) -or $report.schema -ne 2 -or
            -not (Test-JsonString $report.source_proxy) -or $report.source_proxy -cne 'VELOCITY' -or
            -not (Test-JsonString $report.target_proxy) -or $report.target_proxy -cne 'VELOCITY') {
        throw 'FEDERATION_RESTART_RAW_IDENTITY_INVALID'
    }
    foreach ($name in @('source_authenticated', 'grant_stored_in_memory_test_harness',
            'source_client_disconnected_before_target_auth', 'first_target_locally_authenticated',
            'first_target_observed', 'old_target_proxy_terminated', 'target_paper_kept_running',
            'target_identity_preserved', 'target_federation_config_preserved',
            'restarted_target_locally_authenticated', 'target_session_changed', 'target_challenge_changed',
            'old_outer_session_rejected', 'old_session_proof_rejected', 'invalid_old_proofs_no_observation',
            'target_restart_residual_reobserved', 'residual_reacceptance',
            'post_restart_same_process_replay_rejected', 'residual_is_observation_only',
            'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'content_free_audit',
            'source_audit_healthy', 'target_audit_healthy', 'temporary_proxy_private_keys_removed', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name) -or -not $report.$name) {
            throw "FEDERATION_RESTART_RAW_ASSERTION_INVALID: $name"
        }
    }
    foreach ($name in @('durable_replay_protection',
            'test_only_retained_grant_or_source_session_key_written_to_disk', 'fabric_gui_coverage')) {
        if (-not (Test-JsonBoolean $report.$name) -or $report.$name) {
            throw "FEDERATION_RESTART_RAW_FALSE_BOUNDARY_INVALID: $name"
        }
    }
    if (-not (Test-JsonArray $report.limitations) -or @($report.limitations).Count -ne 0 -or
            -not (Test-JsonArray $report.cleanup_process_ids) -or @($report.cleanup_process_ids).Count -lt 5 -or
            -not (Test-JsonArray $report.remaining_run_processes) -or @($report.remaining_run_processes).Count -ne 0) {
        throw 'FEDERATION_RESTART_RAW_BOUNDARY_INVALID'
    }
    foreach ($processId in @($report.cleanup_process_ids)) {
        if (-not (Test-JsonInteger $processId) -or $processId -le 0) {
            throw 'FEDERATION_RESTART_RAW_CLEANUP_ID_INVALID'
        }
    }
    return $report
}

function Open-AndAssertRawRestart {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][DateTimeOffset]$NotBefore,
        [Parameter(Mandatory)][DateTimeOffset]$NotAfter
    )

    $evidence = Open-LockedJsonEvidence -Path $Path -MaximumBytes 1048576
    try {
        Assert-RawTimestampWindow ([DateTimeOffset]$evidence.last_write_time_utc) `
            $NotBefore $NotAfter 'restart'
        $report = Assert-RawRestartReport $evidence
        return [pscustomobject]@{
            path = $evidence.path
            relative_path = ConvertTo-RepoRelativePath $evidence.path
            sha256 = $evidence.sha256
            last_write_at = ([DateTimeOffset]$evidence.last_write_time_utc).ToUniversalTime().ToString('o')
            invocation_started_at = $NotBefore.ToUniversalTime().ToString('o')
            invocation_finished_at = $NotAfter.ToUniversalTime().ToString('o')
            report = $report
            stream = $evidence.stream
        }
    } catch {
        $evidence.stream.Dispose()
        throw
    }
}

function Get-FreshRestartEvidence {
    param(
        [Parameter(Mandatory)][DateTimeOffset]$NotBefore,
        [Parameter(Mandatory)][DateTimeOffset]$NotAfter
    )

    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) {
        throw 'FEDERATION_RESTART_RAW_REPORT_REQUIRED'
    }
    $candidates = @(Get-ChildItem -LiteralPath $runsRoot -Directory -Force -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $_.Name.StartsWith($rawPrefix, [StringComparison]::Ordinal)
        } |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -Force -ErrorAction SilentlyContinue } |
        Where-Object {
            $null -ne $_ -and
            $_.LastWriteTimeUtc -ge $NotBefore.Subtract($fileTimestampLowerBoundTolerance).UtcDateTime -and
            $_.LastWriteTimeUtc -le $NotAfter.UtcDateTime
        } |
        Sort-Object LastWriteTimeUtc -Descending)
    if ($candidates.Count -ne 1) {
        throw "FEDERATION_RESTART_FRESH_RAW_REPORT_COUNT_INVALID: $($candidates.Count)"
    }
    return Open-AndAssertRawRestart -Path $candidates[0].FullName `
        -NotBefore $NotBefore -NotAfter $NotAfter
}

function Resolve-BoundRawReportPath {
    param([Parameter(Mandatory)][string]$RelativePath)

    if ($RelativePath.IndexOf('\') -ge 0 -or $RelativePath.StartsWith('/') -or
            $RelativePath -match '(^|/)\.\.(/|$)' -or $RelativePath.IndexOf(':') -ge 0 -or
            -not $RelativePath.StartsWith("build/runtime-federation-target-restart/runs/$rawPrefix",
                [StringComparison]::Ordinal) -or
            -not $RelativePath.EndsWith('/report.json', [StringComparison]::Ordinal)) {
        throw 'FEDERATION_RESTART_RAW_PATH_INVALID'
    }
    $resolved = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath.Replace('/', '\')))
    $runsPrefix = [System.IO.Path]::GetFullPath($runsRoot).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($runsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FEDERATION_RESTART_RAW_PATH_INVALID'
    }
    return Assert-DirectLocalPath $resolved
}

function Get-RestartReportPropertyNames {
    return @('schema', 'generated_at', 'source_mode', 'source_proxy', 'target_proxy',
        'source_authenticated', 'grant_stored_in_memory_test_harness',
        'source_client_disconnected_before_target_auth', 'first_target_locally_authenticated',
        'first_target_observed', 'old_target_proxy_terminated', 'target_paper_kept_running',
        'target_identity_preserved', 'target_federation_config_preserved',
        'restarted_target_locally_authenticated', 'target_session_changed', 'target_challenge_changed',
        'old_outer_session_rejected', 'old_session_proof_rejected', 'invalid_old_proofs_no_observation',
        'target_restart_residual_reobserved', 'residual_reacceptance',
        'post_restart_same_process_replay_rejected', 'residual_is_observation_only',
        'durable_replay_protection', 'test_only_retained_grant_or_source_session_key_written_to_disk',
        'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'content_free_audit',
        'source_audit_healthy', 'target_audit_healthy', 'temporary_proxy_private_keys_removed',
        'fabric_gui_coverage', 'limitations_count', 'cleanup_process_count',
        'remaining_run_process_count', 'passed')
}

function Assert-PassingAggregateRaw {
    param([Parameter(Mandatory)][string]$Raw)

    try { $report = ConvertFrom-StrictJson $Raw }
    catch { throw 'FEDERATION_RESTART_AGGREGATE_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $report (Get-RestartReportPropertyNames))) {
        throw 'FEDERATION_RESTART_AGGREGATE_SCHEMA_INVALID'
    }
    $null = ConvertTo-FreshUtcTimestamp $report.generated_at 'generated_at'
    if (-not (Test-JsonString $report.schema) -or $report.schema -cne $reportSchema -or
            -not (Test-JsonString $report.source_mode) -or $report.source_mode -cne 'EXECUTED' -or
            -not (Test-JsonString $report.source_proxy) -or $report.source_proxy -cne 'VELOCITY' -or
            -not (Test-JsonString $report.target_proxy) -or $report.target_proxy -cne 'VELOCITY') {
        throw 'FEDERATION_RESTART_AGGREGATE_IDENTITY_INVALID'
    }
    foreach ($name in @('source_authenticated', 'grant_stored_in_memory_test_harness',
            'source_client_disconnected_before_target_auth', 'first_target_locally_authenticated',
            'first_target_observed', 'old_target_proxy_terminated', 'target_paper_kept_running',
            'target_identity_preserved', 'target_federation_config_preserved',
            'restarted_target_locally_authenticated', 'target_session_changed', 'target_challenge_changed',
            'old_outer_session_rejected', 'old_session_proof_rejected', 'invalid_old_proofs_no_observation',
            'target_restart_residual_reobserved', 'residual_reacceptance',
            'post_restart_same_process_replay_rejected', 'residual_is_observation_only',
            'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'content_free_audit',
            'source_audit_healthy', 'target_audit_healthy', 'temporary_proxy_private_keys_removed', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name) -or -not $report.$name) {
            throw "FEDERATION_RESTART_AGGREGATE_ASSERTION_INVALID: $name"
        }
    }
    foreach ($name in @('durable_replay_protection',
            'test_only_retained_grant_or_source_session_key_written_to_disk', 'fabric_gui_coverage')) {
        if (-not (Test-JsonBoolean $report.$name) -or $report.$name) {
            throw "FEDERATION_RESTART_AGGREGATE_FALSE_BOUNDARY_INVALID: $name"
        }
    }
    if (-not (Test-JsonInteger $report.limitations_count) -or $report.limitations_count -ne 0 -or
            -not (Test-JsonInteger $report.cleanup_process_count) -or $report.cleanup_process_count -lt 5 -or
            -not (Test-JsonInteger $report.remaining_run_process_count) -or
            $report.remaining_run_process_count -ne 0) {
        throw 'FEDERATION_RESTART_AGGREGATE_BOUNDARY_INVALID'
    }
    return $report
}

function Assert-BindingRaw {
    param(
        [Parameter(Mandatory)][string]$Raw,
        [Parameter(Mandatory)][string]$ReportSha256,
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Current
    )

    $names = @('schema', 'generated_at', 'report_schema', 'report_generated_at', 'report_sha256',
        'source_mode', 'wrapper_sha256', 'source_manifest_sha256', 'source_file_count',
        'velocity_plugin_sha256', 'bungee_plugin_sha256', 'paper_plugin_sha256',
        'velocity_server_sha256', 'paper_server_sha256',
        'paper_prepared_manifest_sha256', 'paper_prepared_file_count',
        'gradle_wrapper_jar_sha256', 'gradle_wrapper_properties_sha256',
        'java_executable_sha256', 'java_file_version', 'java_major', 'gradle_version',
        'gradle_distribution_sha256', 'gradle_command_sha256', 'gradle_launcher_sha256',
        'gradle_core_sha256', 'gradle_installation_manifest_sha256',
        'gradle_installation_file_count', 'raw_report_count', 'raw_report', 'raw_report_sha256',
        'raw_report_last_write_at', 'invocation_started_at', 'invocation_finished_at', 'passed')
    try { $binding = ConvertFrom-StrictJson $Raw }
    catch { throw 'FEDERATION_RESTART_BINDING_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $binding $names)) { throw 'FEDERATION_RESTART_BINDING_SCHEMA_INVALID' }
    $null = ConvertTo-FreshUtcTimestamp $binding.generated_at 'binding.generated_at'
    if (-not (Test-JsonString $binding.schema) -or $binding.schema -cne $bindingSchema -or
            -not (Test-JsonString $binding.report_schema) -or $binding.report_schema -cne $reportSchema -or
            -not (Test-JsonString $binding.report_generated_at) -or
            $binding.report_generated_at -cne $Report.generated_at -or
            $binding.generated_at -cne $Report.generated_at -or
            -not (Test-JsonString $binding.report_sha256) -or
            $binding.report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $binding.report_sha256 -cne $ReportSha256 -or
            -not (Test-JsonString $binding.source_mode) -or $binding.source_mode -cne 'EXECUTED' -or
            -not (Test-JsonInteger $binding.source_file_count) -or
            $binding.source_file_count -ne $Current.source_file_count -or
            -not (Test-JsonInteger $binding.paper_prepared_file_count) -or
            $binding.paper_prepared_file_count -ne $Current.paper_prepared_file_count -or
            -not (Test-JsonInteger $binding.java_major) -or $binding.java_major -ne 21 -or
            -not (Test-JsonInteger $binding.gradle_installation_file_count) -or
            $binding.gradle_installation_file_count -ne $Current.gradle_installation_file_count -or
            -not (Test-JsonInteger $binding.raw_report_count) -or $binding.raw_report_count -ne 1 -or
            -not (Test-JsonBoolean $binding.passed) -or -not $binding.passed) {
        throw 'FEDERATION_RESTART_BINDING_INVALID'
    }
    foreach ($name in @('wrapper_sha256', 'source_manifest_sha256', 'velocity_plugin_sha256',
            'bungee_plugin_sha256', 'paper_plugin_sha256', 'velocity_server_sha256',
            'paper_server_sha256', 'paper_prepared_manifest_sha256', 'gradle_wrapper_jar_sha256',
            'gradle_wrapper_properties_sha256', 'java_executable_sha256', 'gradle_distribution_sha256',
            'gradle_command_sha256', 'gradle_launcher_sha256', 'gradle_core_sha256',
            'gradle_installation_manifest_sha256')) {
        if (-not (Test-JsonString $binding.$name) -or $binding.$name -cnotmatch '^[0-9a-f]{64}$' -or
                $binding.$name -cne [string]$Current[$name]) {
            throw "FEDERATION_RESTART_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    foreach ($name in @('java_file_version', 'gradle_version')) {
        if (-not (Test-JsonString $binding.$name) -or $binding.$name -cne [string]$Current[$name]) {
            throw "FEDERATION_RESTART_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    if (-not (Test-JsonString $binding.raw_report) -or
            -not (Test-JsonString $binding.raw_report_sha256) -or
            $binding.raw_report_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'FEDERATION_RESTART_RAW_BINDING_INVALID'
    }
    $expectedWriteAt = ConvertTo-FreshUtcTimestamp $binding.raw_report_last_write_at 'raw_report_last_write_at'
    $invocationStartedAt = ConvertTo-FreshUtcTimestamp $binding.invocation_started_at 'invocation_started_at'
    $invocationFinishedAt = ConvertTo-FreshUtcTimestamp $binding.invocation_finished_at 'invocation_finished_at'
    $reportGeneratedAt = ConvertTo-FreshUtcTimestamp $Report.generated_at 'report.generated_at'
    if ($invocationFinishedAt -gt $reportGeneratedAt) {
        throw 'FEDERATION_RESTART_RAW_TIMESTAMP_AFTER_REPORT'
    }
    Assert-RawTimestampWindow $expectedWriteAt $invocationStartedAt $invocationFinishedAt 'restart'
    $path = Resolve-BoundRawReportPath $binding.raw_report
    $evidence = Open-LockedJsonEvidence -Path $path -MaximumBytes 1048576
    try {
        $null = Assert-RawRestartReport $evidence
        $actualWriteAt = ([DateTimeOffset]$evidence.last_write_time_utc).ToUniversalTime()
        if ($evidence.sha256 -cne $binding.raw_report_sha256 -or $actualWriteAt -ne $expectedWriteAt) {
            throw 'FEDERATION_RESTART_RAW_REPORT_CURRENT_MISMATCH'
        }
        Assert-RawTimestampWindow $actualWriteAt $invocationStartedAt $invocationFinishedAt 'restart'
    } finally {
        $evidence.stream.Dispose()
    }
}

function Assert-CommitMarkerRaw {
    param(
        [Parameter(Mandatory)][string]$Raw,
        [Parameter(Mandatory)][string]$ReportSha256,
        [Parameter(Mandatory)][string]$BindingSha256,
        [Parameter(Mandatory)]$Report
    )

    $names = @('schema', 'generated_at', 'report_schema', 'binding_schema',
        'report_sha256', 'binding_sha256', 'committed')
    try { $marker = ConvertFrom-StrictJson $Raw }
    catch { throw 'FEDERATION_RESTART_COMMIT_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $marker $names)) {
        throw 'FEDERATION_RESTART_COMMIT_SCHEMA_INVALID'
    }
    $null = ConvertTo-FreshUtcTimestamp $marker.generated_at 'commit.generated_at'
    if (-not (Test-JsonString $marker.schema) -or $marker.schema -cne $commitSchema -or
            -not (Test-JsonString $marker.generated_at) -or $marker.generated_at -cne $Report.generated_at -or
            -not (Test-JsonString $marker.report_schema) -or $marker.report_schema -cne $reportSchema -or
            -not (Test-JsonString $marker.binding_schema) -or $marker.binding_schema -cne $bindingSchema -or
            -not (Test-JsonString $marker.report_sha256) -or
            $marker.report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $marker.report_sha256 -cne $ReportSha256 -or
            -not (Test-JsonString $marker.binding_sha256) -or
            $marker.binding_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $marker.binding_sha256 -cne $BindingSha256 -or
            -not (Test-JsonBoolean $marker.committed) -or -not $marker.committed) {
        throw 'FEDERATION_RESTART_COMMIT_INVALID'
    }
}

function Assert-EvidencePair {
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Current
    )

    $reportEvidence = $null
    $bindingEvidence = $null
    $commitEvidence = $null
    try {
        $reportEvidence = Open-LockedJsonEvidence -Path $ReportPath -RequireSanitized
        $bindingPath = Join-Path (Split-Path -Parent $ReportPath) 'binding.json'
        $commitPath = Join-Path (Split-Path -Parent $ReportPath) 'commit.json'
        $bindingEvidence = Open-LockedJsonEvidence -Path $bindingPath -RequireSanitized
        $commitEvidence = Open-LockedJsonEvidence -Path $commitPath -RequireSanitized
        $report = Assert-PassingAggregateRaw $reportEvidence.raw
        Assert-CommitMarkerRaw $commitEvidence.raw $reportEvidence.sha256 $bindingEvidence.sha256 $report
        Assert-BindingRaw $bindingEvidence.raw $reportEvidence.sha256 $report $Current
        return $report
    } finally {
        if ($null -ne $commitEvidence) { $commitEvidence.stream.Dispose() }
        if ($null -ne $bindingEvidence) { $bindingEvidence.stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.stream.Dispose() }
    }
}

function Get-LatestCompleteEvidenceReport {
    if (-not (Test-Path -LiteralPath $evidenceRunsRoot -PathType Container)) { return $null }
    $candidates = @(Get-ChildItem -LiteralPath $evidenceRunsRoot -Directory -Force -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $_.Name -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$' -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'report.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'binding.json') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'commit.json') -PathType Leaf)
        } |
        Sort-Object Name -Descending |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -Force -ErrorAction Stop })
    if ($candidates.Count -eq 0) { return $null }
    return $candidates[0].FullName
}

function New-EvidencePair {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Current,
        [Parameter(Mandatory)]$RawEvidence
    )

    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $raw = $RawEvidence.report
    $report = [ordered]@{
        schema = $reportSchema
        generated_at = $generatedAt
        source_mode = 'EXECUTED'
        source_proxy = 'VELOCITY'
        target_proxy = 'VELOCITY'
        source_authenticated = [bool]$raw.source_authenticated
        grant_stored_in_memory_test_harness = [bool]$raw.grant_stored_in_memory_test_harness
        source_client_disconnected_before_target_auth = [bool]$raw.source_client_disconnected_before_target_auth
        first_target_locally_authenticated = [bool]$raw.first_target_locally_authenticated
        first_target_observed = [bool]$raw.first_target_observed
        old_target_proxy_terminated = [bool]$raw.old_target_proxy_terminated
        target_paper_kept_running = [bool]$raw.target_paper_kept_running
        target_identity_preserved = [bool]$raw.target_identity_preserved
        target_federation_config_preserved = [bool]$raw.target_federation_config_preserved
        restarted_target_locally_authenticated = [bool]$raw.restarted_target_locally_authenticated
        target_session_changed = [bool]$raw.target_session_changed
        target_challenge_changed = [bool]$raw.target_challenge_changed
        old_outer_session_rejected = [bool]$raw.old_outer_session_rejected
        old_session_proof_rejected = [bool]$raw.old_session_proof_rejected
        invalid_old_proofs_no_observation = [bool]$raw.invalid_old_proofs_no_observation
        target_restart_residual_reobserved = [bool]$raw.target_restart_residual_reobserved
        residual_reacceptance = [bool]$raw.residual_reacceptance
        post_restart_same_process_replay_rejected = [bool]$raw.post_restart_same_process_replay_rejected
        residual_is_observation_only = [bool]$raw.residual_is_observation_only
        durable_replay_protection = [bool]$raw.durable_replay_protection
        test_only_retained_grant_or_source_session_key_written_to_disk =
            [bool]$raw.test_only_retained_grant_or_source_session_key_written_to_disk
        local_trust_risk_admission_unchanged = [bool]$raw.local_trust_risk_admission_unchanged
        target_paper_admission_verified = [bool]$raw.target_paper_admission_verified
        content_free_audit = [bool]$raw.content_free_audit
        source_audit_healthy = [bool]$raw.source_audit_healthy
        target_audit_healthy = [bool]$raw.target_audit_healthy
        temporary_proxy_private_keys_removed = [bool]$raw.temporary_proxy_private_keys_removed
        fabric_gui_coverage = [bool]$raw.fabric_gui_coverage
        limitations_count = @($raw.limitations).Count
        cleanup_process_count = @($raw.cleanup_process_ids).Count
        remaining_run_process_count = @($raw.remaining_run_processes).Count
        passed = [bool]$raw.passed
    }
    $reportJson = ($report | ConvertTo-Json -Depth 8) + "`n"
    Assert-SanitizedJson $reportJson
    $reportBytes = [Text.UTF8Encoding]::new($false).GetBytes($reportJson)
    $binding = [ordered]@{
        schema = $bindingSchema
        generated_at = $generatedAt
        report_schema = $reportSchema
        report_generated_at = $generatedAt
        report_sha256 = Get-BytesSha256 $reportBytes
        source_mode = 'EXECUTED'
        wrapper_sha256 = $Current.wrapper_sha256
        source_manifest_sha256 = $Current.source_manifest_sha256
        source_file_count = $Current.source_file_count
        velocity_plugin_sha256 = $Current.velocity_plugin_sha256
        bungee_plugin_sha256 = $Current.bungee_plugin_sha256
        paper_plugin_sha256 = $Current.paper_plugin_sha256
        velocity_server_sha256 = $Current.velocity_server_sha256
        paper_server_sha256 = $Current.paper_server_sha256
        paper_prepared_manifest_sha256 = $Current.paper_prepared_manifest_sha256
        paper_prepared_file_count = $Current.paper_prepared_file_count
        gradle_wrapper_jar_sha256 = $Current.gradle_wrapper_jar_sha256
        gradle_wrapper_properties_sha256 = $Current.gradle_wrapper_properties_sha256
        java_executable_sha256 = $Current.java_executable_sha256
        java_file_version = $Current.java_file_version
        java_major = $Current.java_major
        gradle_version = $Current.gradle_version
        gradle_distribution_sha256 = $Current.gradle_distribution_sha256
        gradle_command_sha256 = $Current.gradle_command_sha256
        gradle_launcher_sha256 = $Current.gradle_launcher_sha256
        gradle_core_sha256 = $Current.gradle_core_sha256
        gradle_installation_manifest_sha256 = $Current.gradle_installation_manifest_sha256
        gradle_installation_file_count = $Current.gradle_installation_file_count
        raw_report_count = 1
        raw_report = $RawEvidence.relative_path
        raw_report_sha256 = $RawEvidence.sha256
        raw_report_last_write_at = $RawEvidence.last_write_at
        invocation_started_at = $RawEvidence.invocation_started_at
        invocation_finished_at = $RawEvidence.invocation_finished_at
        passed = $true
    }
    $bindingJson = ($binding | ConvertTo-Json -Depth 8) + "`n"
    Assert-SanitizedJson $bindingJson
    $bindingBytes = [Text.UTF8Encoding]::new($false).GetBytes($bindingJson)
    $commit = [ordered]@{
        schema = $commitSchema
        generated_at = $generatedAt
        report_schema = $reportSchema
        binding_schema = $bindingSchema
        report_sha256 = Get-BytesSha256 $reportBytes
        binding_sha256 = Get-BytesSha256 $bindingBytes
        committed = $true
    }
    $commitJson = ($commit | ConvertTo-Json -Depth 4) + "`n"
    Assert-SanitizedJson $commitJson
    $commitBytes = [Text.UTF8Encoding]::new($false).GetBytes($commitJson)

    if (Test-Path -LiteralPath $evidenceRunsRoot) {
        $null = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    } else {
        $null = Assert-DirectLocalPath (Split-Path -Parent $evidenceRunsRoot) -Directory
        New-Item -ItemType Directory -Path $evidenceRunsRoot | Out-Null
        $null = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    }
    $runName = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ss-fffffffZ')
    $evidenceRoot = Join-Path $evidenceRunsRoot $runName
    $stagingRoot = Join-Path $evidenceRunsRoot ('.staging-' + $runName + '-' + [System.IO.Path]::GetRandomFileName())
    if ((Test-Path -LiteralPath $evidenceRoot) -or (Test-Path -LiteralPath $stagingRoot)) {
        throw 'FEDERATION_RESTART_EVIDENCE_RUN_COLLISION'
    }
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    try {
        $reportPath = Join-Path $stagingRoot 'report.json'
        $bindingPath = Join-Path $stagingRoot 'binding.json'
        $commitPath = Join-Path $stagingRoot 'commit.json'
        [System.IO.File]::WriteAllBytes($reportPath, $reportBytes)
        [System.IO.File]::WriteAllBytes($bindingPath, $bindingBytes)
        # Last staged write, followed by one same-volume directory rename into the committed set.
        [System.IO.File]::WriteAllBytes($commitPath, $commitBytes)
        $null = Assert-EvidencePair $reportPath $Current
        [System.IO.Directory]::Move($stagingRoot, $evidenceRoot)
        return (Join-Path $evidenceRoot 'report.json')
    } finally {
        if (Test-Path -LiteralPath $stagingRoot -PathType Container) {
            foreach ($name in @('report.json', 'binding.json', 'commit.json')) {
                $candidate = Join-Path $stagingRoot $name
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    [System.IO.File]::Delete((Assert-DirectLocalPath $candidate))
                }
            }
            [System.IO.Directory]::Delete((Assert-DirectLocalPath $stagingRoot -Directory), $false)
        }
    }
}

if ($ReportOnly) {
    # There are intentionally no report/binding/raw path parameters. Selection is always local and latest-complete.
    $current = Get-CurrentBinding
    $latestReport = Get-LatestCompleteEvidenceReport
    if ($null -eq $latestReport) { throw 'FEDERATION_RESTART_COMPLETE_EVIDENCE_PAIR_REQUIRED' }
    $null = Assert-EvidencePair $latestReport $current
    Write-Output "FEDERATION_TARGET_RESTART_RESIDUAL_PASS|$(ConvertTo-RepoRelativePath $latestReport)"
    exit 0
}

$currentBefore = Get-CurrentBinding
$rawEvidence = $null
try {
    $startedAt = [DateTimeOffset]::UtcNow
    Write-Host "MCAce federation target-restart residual gate: $test"
    & $currentBefore.java_path '-classpath' $currentBefore.gradle_launcher_path `
        'org.gradle.launcher.GradleMain' '-Dmcace.runtime.federation.restart.enabled=true' `
        ':mcace-runtime-integration:test' '--tests' $test '--rerun-tasks' `
        '--offline' '--dependency-verification=strict' '--no-build-cache' `
        '--no-configuration-cache' '--no-daemon' '--no-parallel' '--max-workers=1' `
        '--console=plain' '--gradle-user-home' $currentBefore.gradle_user_home `
        '--project-dir' $repoRoot
    $finishedAt = [DateTimeOffset]::UtcNow
    if ($LASTEXITCODE -ne 0) { throw 'FEDERATION_RESTART_GRADLE_FAILED' }
    $rawEvidence = Get-FreshRestartEvidence -NotBefore $startedAt -NotAfter $finishedAt
    $currentAfter = Get-CurrentBinding
    Assert-CurrentBindingUnchanged $currentBefore $currentAfter
    $reportPath = New-EvidencePair $currentAfter $rawEvidence
    Write-Output "FEDERATION_TARGET_RESTART_RESIDUAL_PASS|$(ConvertTo-RepoRelativePath $reportPath)"
} finally {
    if ($null -ne $rawEvidence -and $null -ne $rawEvidence.stream) { $rawEvidence.stream.Dispose() }
}
