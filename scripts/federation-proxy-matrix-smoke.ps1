[CmdletBinding(DefaultParameterSetName = 'Execute')]
param(
    [Parameter(ParameterSetName = 'Execute')]
    [ValidateSet('VelocityToVelocity', 'VelocityToBungee', 'BungeeToVelocity', 'BungeeToBungee', 'All')]
    [string]$Pair = 'All',

    [Parameter(ParameterSetName = 'Report', Mandatory)]
    [switch]$ReportOnly,

    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$reportSchema = 'MCACE_FEDERATION_PROXY_MATRIX_EXECUTED_V3'
$bindingSchema = 'MCACE_FEDERATION_PROXY_MATRIX_BINDING_V1'
$commitSchema = 'MCACE_FEDERATION_PROXY_MATRIX_COMMIT_V1'
$fileTimestampLowerBoundTolerance = [TimeSpan]::FromSeconds(2)
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build\runtime-federation-matrix\runs'
$evidenceRunsRoot = Join-Path $repoRoot 'build\runtime-federation-matrix\evidence-runs'
$wrapperPropertiesPath = Join-Path $repoRoot 'gradle\wrapper\gradle-wrapper.properties'
$gradleWrapperJarPath = Join-Path $repoRoot 'gradle\wrapper\gradle-wrapper.jar'
$platformPaths = [ordered]@{
    # The raw peer only accepts release wire profiles.  Bind this four-pair
    # federation run to the same reviewed 1.21.11 assets used by the release
    # matrix instead of the legacy 1.21.1 smoke cache.
    velocity = Join-Path $repoRoot 'build\runtime-assets\velocity\3.5.1-615\server.jar'
    bungee = Join-Path $repoRoot 'build\runtime-assets\bungeecord\2085\server.jar'
    paper = Join-Path $repoRoot 'build\runtime-assets\paper\1.21.11\132\server.jar'
    paper_prepared = Join-Path $repoRoot 'build\runtime-assets\paper\1.21.11\132\prepared'
}
$expectedPlatformSha256 = [ordered]@{
    velocity = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
    bungee = 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'
    paper = '5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba'
}
$federationRuntime = [ordered]@{
    backend_kind = 'PAPER'
    minecraft_version = '1.21.11'
    minecraft_protocol = 774
    server_java_feature = 21
    prepared_tree_sha256 = 'db29ac6443ecef6d633a7576fe003974f6e826cb042cc15752e3b18514ee2922'
}
$artifactPaths = [ordered]@{
    velocity = Join-Path $repoRoot 'mcace-server-velocity\build\libs\mcace-server-velocity-0.1.0-SNAPSHOT.jar'
    bungee = Join-Path $repoRoot 'mcace-server-bungeecord\build\libs\mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
    paper = Join-Path $repoRoot 'mcace-server-paper\build\libs\mcace-server-paper-0.1.0-SNAPSHOT.jar'
}
$allCases = @(
    [pscustomobject]@{
        Pair = 'VelocityToVelocity'
        Test = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityToVelocityRealProcessGate'
        Prefix = 'velocity-to-velocity-'
        Source = 'VELOCITY'
        Target = 'VELOCITY'
        SourceNetwork = 'matrix-source-velocity'
        TargetNetwork = 'matrix-target-velocity'
    },
    [pscustomobject]@{
        Pair = 'VelocityToBungee'
        Test = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationVelocityToBungeeRealProcessGate'
        Prefix = 'velocity-to-bungee-'
        Source = 'VELOCITY'
        Target = 'BUNGEE'
        SourceNetwork = 'matrix-source-velocity'
        TargetNetwork = 'matrix-target-bungee'
    },
    [pscustomobject]@{
        Pair = 'BungeeToVelocity'
        Test = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationBungeeToVelocityRealProcessGate'
        Prefix = 'bungee-to-velocity-'
        Source = 'BUNGEE'
        Target = 'VELOCITY'
        SourceNetwork = 'matrix-source-bungee'
        TargetNetwork = 'matrix-target-velocity'
    },
    [pscustomobject]@{
        Pair = 'BungeeToBungee'
        Test = 'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.federationBungeeToBungeeRealProcessGate'
        Prefix = 'bungee-to-bungee-'
        Source = 'BUNGEE'
        Target = 'BUNGEE'
        SourceNetwork = 'matrix-source-bungee'
        TargetNetwork = 'matrix-target-bungee'
    }
)

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
    if ($Directory -and -not $item.PSIsContainer) { throw "FEDERATION_MATRIX_DIRECTORY_REQUIRED: $Path" }
    if (-not $Directory -and $item.PSIsContainer) { throw "FEDERATION_MATRIX_FILE_REQUIRED: $Path" }
    if (-not [string]::IsNullOrWhiteSpace([string]$item.PSDrive.DisplayRoot) -or
            ([string]$item.PSDrive.Root).StartsWith('\\')) {
        throw "FEDERATION_MATRIX_LOCAL_DRIVE_REQUIRED: $Path"
    }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "FEDERATION_MATRIX_REPARSE_PATH_REJECTED: $($cursor.FullName)"
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
        throw 'FEDERATION_MATRIX_PATH_OUTSIDE_REPOSITORY'
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

    if (-not (Test-JsonString $Value)) { throw "FEDERATION_MATRIX_TIMESTAMP_INVALID: $Field" }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($Value, 'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed) -or
            $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "FEDERATION_MATRIX_TIMESTAMP_INVALID: $Field"
    }
    $age = [DateTimeOffset]::UtcNow - $parsed
    if ($age.TotalMinutes -lt -2 -or $age.TotalMinutes -gt $MaximumReportAgeMinutes) {
        throw "FEDERATION_MATRIX_EVIDENCE_STALE: $Field"
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
        throw "FEDERATION_MATRIX_RAW_TIMESTAMP_WINDOW_INVALID: $Field"
    }
    # A coarse filesystem may round an on-time write down. Never permit a timestamp after
    # the invocation finished; the tolerance applies only to the lower bound.
    if ($Observed -gt [DateTimeOffset]::UtcNow -or $Observed -gt $NotAfter -or
            $Observed.Add($fileTimestampLowerBoundTolerance) -lt $NotBefore) {
        throw "FEDERATION_MATRIX_RAW_TIMESTAMP_OUTSIDE_INVOCATION: $Field"
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
        throw 'FEDERATION_MATRIX_EVIDENCE_NOT_SANITIZED'
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
            throw 'FEDERATION_MATRIX_EVIDENCE_SIZE_INVALID'
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
    if ($matching.Count -ne 1) { throw "FEDERATION_MATRIX_WRAPPER_PROPERTY_INVALID: $Name" }
    return ($matching[0] -split '=', 2)[1].Trim()
}

function Assert-CleanGradleInputs {
    param([Parameter(Mandatory)][string]$GradleUserHome)

    foreach ($name in @('GRADLE_OPTS', 'JAVA_OPTS', '_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS',
            'JDK_JAVA_OPTIONS', 'GRADLE_JAVA_HOME')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "FEDERATION_MATRIX_UNBOUND_GRADLE_ENVIRONMENT_REJECTED: $name"
        }
    }
    foreach ($projectFile in @('.gradle\init.gradle', '.gradle\init.gradle.kts')) {
        if (Test-Path -LiteralPath (Join-Path $repoRoot $projectFile)) {
            throw "FEDERATION_MATRIX_UNBOUND_GRADLE_INPUT_REJECTED: $projectFile"
        }
    }
    $projectProperties = Assert-DirectLocalPath (Join-Path $repoRoot 'gradle.properties')
    if (@(Get-Content -LiteralPath $projectProperties -ErrorAction Stop |
            Where-Object { $_ -match '^\s*org\.gradle\.java\.home\s*=' }).Count -gt 0) {
        throw 'FEDERATION_MATRIX_UNBOUND_GRADLE_JAVA_OVERRIDE_REJECTED'
    }
    if (Test-Path -LiteralPath (Join-Path $repoRoot 'gradle\gradle-daemon-jvm.properties')) {
        throw 'FEDERATION_MATRIX_UNBOUND_GRADLE_DAEMON_JVM_CRITERIA_REJECTED'
    }
    $userRoot = Assert-DirectLocalPath $GradleUserHome -Directory
    foreach ($name in @('gradle.properties', 'init.gradle', 'init.gradle.kts')) {
        if (Test-Path -LiteralPath (Join-Path $userRoot $name)) {
            throw "FEDERATION_MATRIX_UNBOUND_GRADLE_INPUT_REJECTED: $name"
        }
    }
    $initRoot = Join-Path $userRoot 'init.d'
    if (Test-Path -LiteralPath $initRoot -PathType Container) {
        $null = Assert-DirectLocalPath $initRoot -Directory
        $initItems = @(Get-ChildItem -LiteralPath $initRoot -Recurse -Force -ErrorAction Stop)
        if (@($initItems | Where-Object {
                    ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                }).Count -gt 0) {
            throw 'FEDERATION_MATRIX_UNBOUND_GRADLE_INIT_REPARSE_REJECTED'
        }
        $initScripts = @($initItems | Where-Object {
                -not $_.PSIsContainer -and $_.Name -match '(?i)\.gradle(?:\.kts)?$'
            })
        if ($initScripts.Count -gt 0) { throw 'FEDERATION_MATRIX_UNBOUND_GRADLE_INIT_SCRIPT_REJECTED' }
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

function Get-PreparedTreeBinding {
    param([Parameter(Mandatory)][string]$RootPath)

    # Keep this byte-for-byte compatible with RuntimeProcessAssets.preparedTreeSha256:
    # domain || big-endian(path-byte-count) || path || big-endian(file-size) || file bytes,
    # with the cache/libraries/versions files sorted by slash-normalized relative path.
    $root = Assert-DirectLocalPath $RootPath -Directory
    $files = New-Object 'System.Collections.Generic.List[object]'
    foreach ($requiredDirectory in @('cache', 'libraries', 'versions')) {
        $directory = Assert-DirectLocalPath (Join-Path $root $requiredDirectory) -Directory
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Recurse -Force -File -ErrorAction Stop)) {
            $resolved = Assert-DirectLocalPath $file.FullName
            $relative = $resolved.Substring($root.Length + 1).Replace('\', '/')
            $files.Add([pscustomobject]@{ path = $resolved; relative = $relative; size = [long]$file.Length })
        }
    }
    $ordered = @($files | Sort-Object -Property relative)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $domain = [Text.Encoding]::ASCII.GetBytes('MCACE_PREPARED_TREE_SHA256_V1' + [char]0)
        $null = $hash.TransformBlock($domain, 0, $domain.Length, $domain, 0)
        foreach ($file in $ordered) {
            $relativeBytes = [Text.Encoding]::UTF8.GetBytes([string]$file.relative)
            $pathLength = [BitConverter]::GetBytes([int]$relativeBytes.Length)
            $sizeBytes = [BitConverter]::GetBytes([long]$file.size)
            if ([BitConverter]::IsLittleEndian) {
                [Array]::Reverse($pathLength)
                [Array]::Reverse($sizeBytes)
            }
            $null = $hash.TransformBlock($pathLength, 0, $pathLength.Length, $pathLength, 0)
            $null = $hash.TransformBlock($relativeBytes, 0, $relativeBytes.Length, $relativeBytes, 0)
            $null = $hash.TransformBlock($sizeBytes, 0, $sizeBytes.Length, $sizeBytes, 0)
            $stream = [IO.File]::Open([string]$file.path, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                $buffer = New-Object byte[] (64 * 1024)
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $null = $hash.TransformBlock($buffer, 0, $read, $buffer, 0)
                }
            } finally {
                $stream.Dispose()
            }
        }
        $null = $hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return [pscustomobject]@{
            sha256 = ([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant()
            file_count = [int]$ordered.Count
        }
    } finally {
        $hash.Dispose()
    }
}

function Get-PlatformBinding {
    $hashes = [ordered]@{}
    foreach ($name in @('velocity', 'bungee', 'paper')) {
        $path = Assert-DirectLocalPath $platformPaths[$name]
        $hash = Get-PathSha256 $path
        if ($hash -cne $expectedPlatformSha256[$name]) {
            throw "FEDERATION_MATRIX_PLATFORM_SHA256_MISMATCH: $name"
        }
        $hashes[$name] = $hash
    }
    $prepared = Get-PreparedTreeBinding $platformPaths.paper_prepared
    if ($prepared.file_count -le 0) { throw 'FEDERATION_MATRIX_PREPARED_PAPER_EMPTY' }
    if ($prepared.sha256 -cne $federationRuntime.prepared_tree_sha256) {
        throw "FEDERATION_MATRIX_PREPARED_PAPER_SHA256_MISMATCH: expected=$($federationRuntime.prepared_tree_sha256); actual=$($prepared.sha256)"
    }
    return [pscustomobject]@{
        velocity_server_sha256 = $hashes.velocity
        bungee_server_sha256 = $hashes.bungee
        paper_server_sha256 = $hashes.paper
        paper_prepared_manifest_sha256 = $prepared.sha256
        paper_prepared_file_count = $prepared.file_count
    }
}

function Resolve-ExactJava21 {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME) -or $env:JAVA_HOME.IndexOf('"') -ge 0) {
        throw 'FEDERATION_MATRIX_JAVA_HOME_21_REQUIRED'
    }
    $javaHome = Assert-DirectLocalPath $env:JAVA_HOME -Directory
    $java = Assert-DirectLocalPath (Join-Path $javaHome 'bin\java.exe')
    $item = Get-Item -LiteralPath $java -Force -ErrorAction Stop
    $fileVersion = [string]$item.VersionInfo.FileVersion
    if ($fileVersion -notmatch '^(\d+)(?:\.|$)' -or [int]$Matches[1] -ne 21) {
        throw "FEDERATION_MATRIX_JAVA_21_REQUIRED: $fileVersion"
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
        throw 'FEDERATION_MATRIX_OFFLINE_GRADLE_9_6_1_CONFIGURATION_REQUIRED'
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
                command_path = $command
                command_sha256 = Get-PathSha256 $command
                launcher_path = $launcher
                launcher_sha256 = Get-PathSha256 $launcher
                core_sha256 = Get-PathSha256 $core
                installation_manifest_sha256 = $manifest.sha256
                installation_file_count = $manifest.file_count
            })
        } catch {
            if ($_.Exception.Message -notlike 'Cannot find path*' -and
                    $_.Exception.Message -notlike 'FEDERATION_MATRIX_*_REQUIRED*') { throw }
        }
    }
    if ($valid.Count -ne 1) {
        throw 'FEDERATION_MATRIX_OFFLINE_GRADLE_9_6_1_REQUIRED: expected exactly one verified cached installation'
    }
    return $valid[0]
}

function Get-GateSourceInputPaths {
    $paths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in @('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties',
            'gradlew', 'gradlew.bat', 'scripts\federation-proxy-matrix-smoke.ps1',
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
        bungee_server_sha256 = $platform.bungee_server_sha256
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
            throw "FEDERATION_MATRIX_CURRENT_INPUT_CHANGED_DURING_RUN: $name"
        }
    }
}

function Assert-RawCaseReport {
    param(
        [Parameter(Mandatory)]$Evidence,
        [Parameter(Mandatory)]$Definition
    )

    $names = @('schema', 'source_proxy', 'target_proxy', 'source_network_id', 'target_network_id',
        'source_authenticated', 'grant_stored_in_memory', 'source_client_disconnected_before_target_auth',
        'target_locally_authenticated', 'presentation_sent', 'first_outer_length', 'inner_length',
        'nonce_distinct_attempted', 'target_observed', 'same_assertion_replay_rejected',
        'content_free_audit', 'source_audit_healthy', 'target_audit_healthy',
        'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'fabric_gui_coverage',
        'limitations', 'cleanup_process_ids', 'remaining_run_processes', 'passed')
    try { $report = ConvertFrom-StrictJson $Evidence.raw }
    catch { throw "FEDERATION_MATRIX_RAW_JSON_INVALID: $($Definition.Pair)" }
    if (-not (Test-ExactJsonProperties $report $names)) {
        throw "FEDERATION_MATRIX_RAW_SCHEMA_INVALID: $($Definition.Pair)"
    }
    if (-not (Test-JsonInteger $report.schema) -or $report.schema -ne 2 -or
            -not (Test-JsonString $report.source_proxy) -or $report.source_proxy -cne $Definition.Source -or
            -not (Test-JsonString $report.target_proxy) -or $report.target_proxy -cne $Definition.Target -or
            -not (Test-JsonString $report.source_network_id) -or $report.source_network_id -cne $Definition.SourceNetwork -or
            -not (Test-JsonString $report.target_network_id) -or $report.target_network_id -cne $Definition.TargetNetwork) {
        throw "FEDERATION_MATRIX_RAW_IDENTITY_INVALID: $($Definition.Pair)"
    }
    foreach ($name in @('source_authenticated', 'grant_stored_in_memory',
            'source_client_disconnected_before_target_auth', 'target_locally_authenticated',
            'presentation_sent', 'nonce_distinct_attempted', 'target_observed',
            'same_assertion_replay_rejected', 'content_free_audit', 'source_audit_healthy',
            'target_audit_healthy', 'local_trust_risk_admission_unchanged',
            'target_paper_admission_verified', 'passed')) {
        if (-not (Test-JsonBoolean $report.$name) -or -not $report.$name) {
            throw "FEDERATION_MATRIX_RAW_ASSERTION_INVALID: $($Definition.Pair)/$name"
        }
    }
    if (-not (Test-JsonBoolean $report.fabric_gui_coverage) -or $report.fabric_gui_coverage -or
            -not (Test-JsonInteger $report.first_outer_length) -or
            -not (Test-JsonInteger $report.inner_length) -or
            $report.first_outer_length -le $report.inner_length -or $report.inner_length -le 0 -or
            -not (Test-JsonArray $report.limitations) -or @($report.limitations).Count -ne 0 -or
            -not (Test-JsonArray $report.cleanup_process_ids) -or @($report.cleanup_process_ids).Count -lt 4 -or
            -not (Test-JsonArray $report.remaining_run_processes) -or @($report.remaining_run_processes).Count -ne 0) {
        throw "FEDERATION_MATRIX_RAW_BOUNDARY_INVALID: $($Definition.Pair)"
    }
    foreach ($processId in @($report.cleanup_process_ids)) {
        if (-not (Test-JsonInteger $processId) -or $processId -le 0) {
            throw "FEDERATION_MATRIX_RAW_CLEANUP_ID_INVALID: $($Definition.Pair)"
        }
    }
    return $report
}

function Resolve-BoundRawReportPath {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)]$Definition
    )

    if ($RelativePath.IndexOf('\') -ge 0 -or $RelativePath.StartsWith('/') -or
            $RelativePath -match '(^|/)\.\.(/|$)' -or $RelativePath.IndexOf(':') -ge 0) {
        throw "FEDERATION_MATRIX_RAW_PATH_INVALID: $($Definition.Pair)"
    }
    $expectedPrefix = "build/runtime-federation-matrix/runs/$($Definition.Prefix)"
    if (-not $RelativePath.StartsWith($expectedPrefix, [StringComparison]::Ordinal) -or
            -not $RelativePath.EndsWith('/report.json', [StringComparison]::Ordinal)) {
        throw "FEDERATION_MATRIX_RAW_PATH_INVALID: $($Definition.Pair)"
    }
    $resolved = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath.Replace('/', '\')))
    $runsPrefix = [System.IO.Path]::GetFullPath($runsRoot).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($runsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "FEDERATION_MATRIX_RAW_PATH_INVALID: $($Definition.Pair)"
    }
    return Assert-DirectLocalPath $resolved
}

function Open-AndAssertRawCase {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)][DateTimeOffset]$NotBefore,
        [Parameter(Mandatory)][DateTimeOffset]$NotAfter
    )

    $evidence = Open-LockedJsonEvidence -Path $Path -MaximumBytes 1048576
    try {
        Assert-RawTimestampWindow ([DateTimeOffset]$evidence.last_write_time_utc) `
            $NotBefore $NotAfter $Definition.Pair
        $report = Assert-RawCaseReport $evidence $Definition
        $relative = ConvertTo-RepoRelativePath $evidence.path
        return [pscustomobject]@{
            path = $evidence.path
            relative_path = $relative
            sha256 = $evidence.sha256
            last_write_at = ([DateTimeOffset]$evidence.last_write_time_utc).ToUniversalTime().ToString('o')
            invocation_started_at = $NotBefore.ToUniversalTime().ToString('o')
            invocation_finished_at = $NotAfter.ToUniversalTime().ToString('o')
            report = $report
            definition = $Definition
            stream = $evidence.stream
        }
    } catch {
        $evidence.stream.Dispose()
        throw
    }
}

function Get-FreshCaseEvidence {
    param(
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)][DateTimeOffset]$NotBefore,
        [Parameter(Mandatory)][DateTimeOffset]$NotAfter
    )

    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) {
        throw "FEDERATION_MATRIX_RAW_REPORT_REQUIRED: $($Definition.Pair)"
    }
    $candidates = @(Get-ChildItem -LiteralPath $runsRoot -Directory -Force -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $_.Name.StartsWith($Definition.Prefix, [StringComparison]::Ordinal)
        } |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'report.json') -Force -ErrorAction SilentlyContinue } |
        Where-Object {
            $null -ne $_ -and
            $_.LastWriteTimeUtc -ge $NotBefore.Subtract($fileTimestampLowerBoundTolerance).UtcDateTime -and
            $_.LastWriteTimeUtc -le $NotAfter.UtcDateTime
        } |
        Sort-Object LastWriteTimeUtc -Descending)
    if ($candidates.Count -ne 1) {
        throw "FEDERATION_MATRIX_FRESH_RAW_REPORT_COUNT_INVALID: $($Definition.Pair)/$($candidates.Count)"
    }
    return Open-AndAssertRawCase -Path $candidates[0].FullName -Definition $Definition `
        -NotBefore $NotBefore -NotAfter $NotAfter
}

function Assert-PassingAggregateRaw {
    param([Parameter(Mandatory)][string]$Raw)

    $names = @('schema', 'generated_at', 'source_mode', 'pair_scope', 'expected_case_count',
        'observed_case_count', 'all_cases_passed', 'matrix_completed', 'transfer_model',
        'source_to_target_broker_present', 'explicit_consent_required',
        'same_process_replay_rejection_covered', 'durable_audit_health_covered',
        'target_restart_residual_covered', 'fabric_gui_coverage', 'cases')
    $caseNames = @('pair', 'source_proxy', 'target_proxy', 'source_authenticated',
        'grant_stored_in_memory', 'source_client_disconnected_before_target_auth',
        'target_locally_authenticated', 'presentation_sent', 'presentation_shape_valid',
        'nonce_distinct_attempted', 'target_observed', 'same_assertion_replay_rejected',
        'content_free_audit', 'source_audit_healthy', 'target_audit_healthy',
        'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'passed')
    try { $report = ConvertFrom-StrictJson $Raw }
    catch { throw 'FEDERATION_MATRIX_AGGREGATE_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $report $names)) { throw 'FEDERATION_MATRIX_AGGREGATE_SCHEMA_INVALID' }
    $null = ConvertTo-FreshUtcTimestamp $report.generated_at 'generated_at'
    if (-not (Test-JsonString $report.schema) -or $report.schema -cne $reportSchema -or
            -not (Test-JsonString $report.source_mode) -or $report.source_mode -cne 'EXECUTED' -or
            -not (Test-JsonString $report.pair_scope) -or $report.pair_scope -cne 'ALL' -or
            -not (Test-JsonInteger $report.expected_case_count) -or $report.expected_case_count -ne 4 -or
            -not (Test-JsonInteger $report.observed_case_count) -or $report.observed_case_count -ne 4 -or
            -not (Test-JsonBoolean $report.all_cases_passed) -or -not $report.all_cases_passed -or
            -not (Test-JsonBoolean $report.matrix_completed) -or -not $report.matrix_completed -or
            -not (Test-JsonString $report.transfer_model) -or
            $report.transfer_model -cne 'CLIENT_CARRIED_PROCESS_MEMORY_ONLY' -or
            -not (Test-JsonBoolean $report.source_to_target_broker_present) -or $report.source_to_target_broker_present -or
            -not (Test-JsonBoolean $report.explicit_consent_required) -or -not $report.explicit_consent_required -or
            -not (Test-JsonBoolean $report.same_process_replay_rejection_covered) -or
            -not $report.same_process_replay_rejection_covered -or
            -not (Test-JsonBoolean $report.durable_audit_health_covered) -or
            -not $report.durable_audit_health_covered -or
            -not (Test-JsonBoolean $report.target_restart_residual_covered) -or
            $report.target_restart_residual_covered -or
            -not (Test-JsonBoolean $report.fabric_gui_coverage) -or $report.fabric_gui_coverage -or
            -not (Test-JsonArray $report.cases) -or @($report.cases).Count -ne 4) {
        throw 'FEDERATION_MATRIX_AGGREGATE_INVALID'
    }
    $observedPairs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($case in @($report.cases)) {
        if (-not (Test-ExactJsonProperties $case $caseNames)) { throw 'FEDERATION_MATRIX_AGGREGATE_CASE_SCHEMA_INVALID' }
        $definition = @($allCases | Where-Object { $_.Pair -ceq $case.pair })
        if ($definition.Count -ne 1 -or -not (Test-JsonString $case.pair) -or
                -not (Test-JsonString $case.source_proxy) -or $case.source_proxy -cne $definition[0].Source -or
                -not (Test-JsonString $case.target_proxy) -or $case.target_proxy -cne $definition[0].Target) {
            throw 'FEDERATION_MATRIX_AGGREGATE_CASE_IDENTITY_INVALID'
        }
        foreach ($name in @('source_authenticated', 'grant_stored_in_memory',
                'source_client_disconnected_before_target_auth', 'target_locally_authenticated',
                'presentation_sent', 'presentation_shape_valid', 'nonce_distinct_attempted',
                'target_observed', 'same_assertion_replay_rejected', 'content_free_audit',
                'source_audit_healthy', 'target_audit_healthy', 'local_trust_risk_admission_unchanged',
                'target_paper_admission_verified', 'passed')) {
            if (-not (Test-JsonBoolean $case.$name) -or -not $case.$name) {
                throw "FEDERATION_MATRIX_AGGREGATE_CASE_ASSERTION_INVALID: $($case.pair)/$name"
            }
        }
        $observedPairs.Add([string]$case.pair)
    }
    $actual = [string[]]$observedPairs.ToArray()
    $expected = [string[]]@($allCases | ForEach-Object Pair)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($expected, [StringComparer]::Ordinal)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw 'FEDERATION_MATRIX_AGGREGATE_CASE_SET_INVALID' }
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
        'velocity_server_sha256', 'bungee_server_sha256', 'paper_server_sha256',
        'paper_prepared_manifest_sha256', 'paper_prepared_file_count',
        'gradle_wrapper_jar_sha256', 'gradle_wrapper_properties_sha256',
        'java_executable_sha256', 'java_file_version', 'java_major', 'gradle_version',
        'gradle_distribution_sha256', 'gradle_command_sha256', 'gradle_launcher_sha256',
        'gradle_core_sha256', 'gradle_installation_manifest_sha256',
        'gradle_installation_file_count', 'raw_report_count', 'raw_reports', 'passed')
    $rawNames = @('pair', 'source_proxy', 'target_proxy', 'raw_report', 'raw_report_sha256',
        'raw_report_last_write_at', 'invocation_started_at', 'invocation_finished_at')
    try { $binding = ConvertFrom-StrictJson $Raw }
    catch { throw 'FEDERATION_MATRIX_BINDING_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $binding $names)) { throw 'FEDERATION_MATRIX_BINDING_SCHEMA_INVALID' }
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
            -not (Test-JsonInteger $binding.raw_report_count) -or $binding.raw_report_count -ne 4 -or
            -not (Test-JsonArray $binding.raw_reports) -or @($binding.raw_reports).Count -ne 4 -or
            -not (Test-JsonBoolean $binding.passed) -or -not $binding.passed) {
        throw 'FEDERATION_MATRIX_BINDING_INVALID'
    }
    foreach ($name in @('wrapper_sha256', 'source_manifest_sha256', 'velocity_plugin_sha256',
            'bungee_plugin_sha256', 'paper_plugin_sha256', 'velocity_server_sha256',
            'bungee_server_sha256', 'paper_server_sha256', 'paper_prepared_manifest_sha256',
            'gradle_wrapper_jar_sha256',
            'gradle_wrapper_properties_sha256', 'java_executable_sha256', 'gradle_distribution_sha256',
            'gradle_command_sha256', 'gradle_launcher_sha256', 'gradle_core_sha256',
            'gradle_installation_manifest_sha256')) {
        if (-not (Test-JsonString $binding.$name) -or $binding.$name -cnotmatch '^[0-9a-f]{64}$' -or
                $binding.$name -cne [string]$Current[$name]) {
            throw "FEDERATION_MATRIX_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    foreach ($name in @('java_file_version', 'gradle_version')) {
        if (-not (Test-JsonString $binding.$name) -or $binding.$name -cne [string]$Current[$name]) {
            throw "FEDERATION_MATRIX_BINDING_CURRENT_MISMATCH: $name"
        }
    }
    $observedPairs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rawReport in @($binding.raw_reports)) {
        if (-not (Test-ExactJsonProperties $rawReport $rawNames) -or
                -not (Test-JsonString $rawReport.pair)) {
            throw 'FEDERATION_MATRIX_RAW_BINDING_SCHEMA_INVALID'
        }
        $definition = @($allCases | Where-Object { $_.Pair -ceq $rawReport.pair })
        if ($definition.Count -ne 1 -or
                -not (Test-JsonString $rawReport.source_proxy) -or $rawReport.source_proxy -cne $definition[0].Source -or
                -not (Test-JsonString $rawReport.target_proxy) -or $rawReport.target_proxy -cne $definition[0].Target -or
                -not (Test-JsonString $rawReport.raw_report) -or
                -not (Test-JsonString $rawReport.raw_report_sha256) -or
                $rawReport.raw_report_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'FEDERATION_MATRIX_RAW_BINDING_INVALID'
        }
        $expectedWriteAt = ConvertTo-FreshUtcTimestamp $rawReport.raw_report_last_write_at 'raw_report_last_write_at'
        $invocationStartedAt = ConvertTo-FreshUtcTimestamp $rawReport.invocation_started_at 'invocation_started_at'
        $invocationFinishedAt = ConvertTo-FreshUtcTimestamp $rawReport.invocation_finished_at 'invocation_finished_at'
        $reportGeneratedAt = ConvertTo-FreshUtcTimestamp $Report.generated_at 'report.generated_at'
        if ($invocationFinishedAt -gt $reportGeneratedAt) {
            throw "FEDERATION_MATRIX_RAW_TIMESTAMP_AFTER_REPORT: $($rawReport.pair)"
        }
        Assert-RawTimestampWindow $expectedWriteAt $invocationStartedAt $invocationFinishedAt $rawReport.pair
        $path = Resolve-BoundRawReportPath $rawReport.raw_report $definition[0]
        $evidence = Open-LockedJsonEvidence -Path $path -MaximumBytes 1048576
        try {
            $null = Assert-RawCaseReport $evidence $definition[0]
            $actualWriteAt = ([DateTimeOffset]$evidence.last_write_time_utc).ToUniversalTime()
            if ($evidence.sha256 -cne $rawReport.raw_report_sha256 -or $actualWriteAt -ne $expectedWriteAt) {
                throw "FEDERATION_MATRIX_RAW_REPORT_CURRENT_MISMATCH: $($rawReport.pair)"
            }
            Assert-RawTimestampWindow $actualWriteAt $invocationStartedAt $invocationFinishedAt $rawReport.pair
        } finally {
            $evidence.stream.Dispose()
        }
        $observedPairs.Add([string]$rawReport.pair)
    }
    $actual = [string[]]$observedPairs.ToArray()
    $expected = [string[]]@($allCases | ForEach-Object Pair)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($expected, [StringComparer]::Ordinal)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw 'FEDERATION_MATRIX_RAW_BINDING_CASE_SET_INVALID' }
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
    catch { throw 'FEDERATION_MATRIX_COMMIT_JSON_INVALID' }
    if (-not (Test-ExactJsonProperties $marker $names)) {
        throw 'FEDERATION_MATRIX_COMMIT_SCHEMA_INVALID'
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
        throw 'FEDERATION_MATRIX_COMMIT_INVALID'
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

function ConvertTo-AggregateCase {
    param([Parameter(Mandatory)]$CaseEvidence)

    return [ordered]@{
        pair = $CaseEvidence.definition.Pair
        source_proxy = $CaseEvidence.report.source_proxy
        target_proxy = $CaseEvidence.report.target_proxy
        source_authenticated = [bool]$CaseEvidence.report.source_authenticated
        grant_stored_in_memory = [bool]$CaseEvidence.report.grant_stored_in_memory
        source_client_disconnected_before_target_auth = [bool]$CaseEvidence.report.source_client_disconnected_before_target_auth
        target_locally_authenticated = [bool]$CaseEvidence.report.target_locally_authenticated
        presentation_sent = [bool]$CaseEvidence.report.presentation_sent
        presentation_shape_valid = [bool]($CaseEvidence.report.first_outer_length -gt $CaseEvidence.report.inner_length -and
            $CaseEvidence.report.inner_length -gt 0)
        nonce_distinct_attempted = [bool]$CaseEvidence.report.nonce_distinct_attempted
        target_observed = [bool]$CaseEvidence.report.target_observed
        same_assertion_replay_rejected = [bool]$CaseEvidence.report.same_assertion_replay_rejected
        content_free_audit = [bool]$CaseEvidence.report.content_free_audit
        source_audit_healthy = [bool]$CaseEvidence.report.source_audit_healthy
        target_audit_healthy = [bool]$CaseEvidence.report.target_audit_healthy
        local_trust_risk_admission_unchanged = [bool]$CaseEvidence.report.local_trust_risk_admission_unchanged
        target_paper_admission_verified = [bool]$CaseEvidence.report.target_paper_admission_verified
        passed = [bool]$CaseEvidence.report.passed
    }
}

function New-EvidencePair {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Current,
        [Parameter(Mandatory)][object[]]$CaseEvidence
    )

    if ($CaseEvidence.Count -ne 4) { throw 'FEDERATION_MATRIX_COMPLETE_4_OF_4_EXECUTION_REQUIRED' }
    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $aggregateCases = @($CaseEvidence | ForEach-Object { ConvertTo-AggregateCase $_ })
    $report = [ordered]@{
        schema = $reportSchema
        generated_at = $generatedAt
        source_mode = 'EXECUTED'
        pair_scope = 'ALL'
        expected_case_count = 4
        observed_case_count = $aggregateCases.Count
        all_cases_passed = $true
        matrix_completed = $true
        transfer_model = 'CLIENT_CARRIED_PROCESS_MEMORY_ONLY'
        source_to_target_broker_present = $false
        explicit_consent_required = $true
        same_process_replay_rejection_covered = $true
        durable_audit_health_covered = $true
        target_restart_residual_covered = $false
        fabric_gui_coverage = $false
        cases = $aggregateCases
    }
    $reportJson = ($report | ConvertTo-Json -Depth 12) + "`n"
    Assert-SanitizedJson $reportJson
    $reportBytes = [Text.UTF8Encoding]::new($false).GetBytes($reportJson)
    $rawBindings = @($CaseEvidence | ForEach-Object {
        [ordered]@{
            pair = $_.definition.Pair
            source_proxy = $_.definition.Source
            target_proxy = $_.definition.Target
            raw_report = $_.relative_path
            raw_report_sha256 = $_.sha256
            raw_report_last_write_at = $_.last_write_at
            invocation_started_at = $_.invocation_started_at
            invocation_finished_at = $_.invocation_finished_at
        }
    })
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
        bungee_server_sha256 = $Current.bungee_server_sha256
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
        raw_report_count = 4
        raw_reports = $rawBindings
        passed = $true
    }
    $bindingJson = ($binding | ConvertTo-Json -Depth 12) + "`n"
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
        throw 'FEDERATION_MATRIX_EVIDENCE_RUN_COLLISION'
    }
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    try {
        $reportPath = Join-Path $stagingRoot 'report.json'
        $bindingPath = Join-Path $stagingRoot 'binding.json'
        $commitPath = Join-Path $stagingRoot 'commit.json'
        [System.IO.File]::WriteAllBytes($reportPath, $reportBytes)
        [System.IO.File]::WriteAllBytes($bindingPath, $bindingBytes)
        # The commit marker is deliberately the final staged write. The directory becomes visible
        # to ReportOnly in one same-volume rename only after the complete triplet validates.
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
    if ($null -eq $latestReport) { throw 'FEDERATION_MATRIX_COMPLETE_EVIDENCE_PAIR_REQUIRED' }
    $null = Assert-EvidencePair $latestReport $current
    Write-Output "FEDERATION_PROXY_MATRIX_PASS|$(ConvertTo-RepoRelativePath $latestReport)"
    exit 0
}

if ($Pair -cne 'All') {
    throw 'FEDERATION_MATRIX_COMPLETE_4_OF_4_EXECUTION_REQUIRED'
}

$currentBefore = Get-CurrentBinding
$caseEvidence = New-Object 'System.Collections.Generic.List[object]'
try {
    # Deliberately sequential: each case owns two disposable proxies and two Paper backends.
    foreach ($case in $allCases) {
        $startedAt = [DateTimeOffset]::UtcNow
        Write-Host "MCAce federation proxy matrix: $($case.Test)"
        $runtimeArguments = @(
            '-Dmcace.runtime.backend-kind=' + $federationRuntime.backend_kind,
            '-Dmcace.runtime.minecraft-version=' + $federationRuntime.minecraft_version,
            '-Dmcace.runtime.minecraft-protocol=' + $federationRuntime.minecraft_protocol,
            '-Dmcace.runtime.server-java-feature=' + $federationRuntime.server_java_feature,
            '-Dmcace.runtime.backend.jar=' + $platformPaths.paper,
            '-Dmcace.runtime.backend.jar.sha256=' + $expectedPlatformSha256.paper,
            '-Dmcace.runtime.backend.prepared-root=' + $platformPaths.paper_prepared,
            '-Dmcace.runtime.backend.prepared-root.sha256=' + $federationRuntime.prepared_tree_sha256,
            '-Dmcace.runtime.server-java=' + $currentBefore.java_path,
            '-Dmcace.runtime.server-java.sha256=' + $currentBefore.java_executable_sha256,
            '-Dmcace.runtime.velocity.jar=' + $platformPaths.velocity,
            '-Dmcace.runtime.velocity.jar.sha256=' + $expectedPlatformSha256.velocity,
            '-Dmcace.runtime.bungee.jar=' + $platformPaths.bungee,
            '-Dmcace.runtime.bungee.jar.sha256=' + $expectedPlatformSha256.bungee
        )
        # Invoke the verified Gradle distribution directly.  Supplying each
        # binding as its own Gradle CLI -D argument preserves the property
        # boundaries all the way into the forked Test Executor (the previous
        # direct GradleMain invocation collapsed the values on Windows).
        $gradleArguments = [string[]]@(
            '-Dmcace.runtime.federation.enabled=true'
        ) + [string[]]$runtimeArguments + [string[]]@(
            ':mcace-runtime-integration:test',
            '--tests', $case.Test,
            '--rerun-tasks',
            '--offline', '--dependency-verification=strict', '--no-build-cache',
            '--no-configuration-cache', '--no-daemon', '--no-parallel', '--max-workers=1',
            '--console=plain', '--gradle-user-home', $currentBefore.gradle_user_home,
            '--project-dir', $repoRoot
        )
        & $currentBefore.command_path @gradleArguments
        $finishedAt = [DateTimeOffset]::UtcNow
        if ($LASTEXITCODE -ne 0) { throw "FEDERATION_MATRIX_GRADLE_FAILED: $($case.Pair)" }
        $caseEvidence.Add((Get-FreshCaseEvidence -Definition $case -NotBefore $startedAt -NotAfter $finishedAt))
    }
    if ($caseEvidence.Count -ne 4) { throw 'FEDERATION_MATRIX_COMPLETE_4_OF_4_EXECUTION_REQUIRED' }
    $currentAfter = Get-CurrentBinding
    Assert-CurrentBindingUnchanged $currentBefore $currentAfter
    $reportPath = New-EvidencePair $currentAfter $caseEvidence.ToArray()
    Write-Output "FEDERATION_PROXY_MATRIX_PASS|$(ConvertTo-RepoRelativePath $reportPath)"
} finally {
    foreach ($evidence in $caseEvidence) {
        if ($null -ne $evidence.stream) { $evidence.stream.Dispose() }
    }
}
