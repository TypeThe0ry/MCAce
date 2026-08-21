[CmdletBinding(DefaultParameterSetName = 'Execute')]
param(
    [ValidateSet('Velocity', 'Bungee', 'Both')]
    [string]$Proxy = 'Both',

    [Parameter(Mandatory, ParameterSetName = 'Execute')]
    [Parameter(Mandatory, ParameterSetName = 'Report')]
    [ValidateSet('1.21.11', '26.1.2', '26.2')]
    [string]$FabricTarget,

    [Parameter(Mandatory, ParameterSetName = 'Report')]
    [switch]$ReportOnly,

    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gradle = Join-Path $repoRoot 'gradlew.bat'
$runsRoot = Join-Path $repoRoot 'build/runtime-trusted-disposition/runs'
$aggregateParent = Join-Path $repoRoot 'build/runtime-trusted-disposition'
$evidenceRunsRoot = Join-Path $aggregateParent 'evidence-runs'
$aggregateSchema = 'MCACE_TRUSTED_DISPOSITION_PROCESS_AGGREGATE_V4'
$bindingSchema = 'MCACE_TRUSTED_DISPOSITION_PROCESS_BINDING_V3'
$commitSchema = 'MCACE_TRUSTED_DISPOSITION_PROCESS_COMMIT_V1'
$maximumEvidenceBytes = 1048576
$fileTimestampLowerBoundTolerance = [TimeSpan]::FromSeconds(2)
$artifactPaths = [ordered]@{
    velocity = Join-Path $repoRoot 'mcace-server-velocity/build/libs/mcace-server-velocity-0.1.0-SNAPSHOT.jar'
    bungee = Join-Path $repoRoot 'mcace-server-bungeecord/build/libs/mcace-server-bungeecord-0.1.0-SNAPSHOT.jar'
    paper = Join-Path $repoRoot 'mcace-server-paper/build/libs/mcace-server-paper-0.1.0-SNAPSHOT.jar'
}
$targetDefinitions = @{
    '1.21.11' = [pscustomobject]@{
        minecraft_version = '1.21.11'; protocol = 774; server_java_feature = 21
        paper = Join-Path $repoRoot 'build/runtime-assets/paper/1.21.11/132/server.jar'
        paper_sha256 = '5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba'
        prepared = Join-Path $repoRoot 'build/runtime-assets/paper/1.21.11/132/prepared'
        prepared_tree_sha256 = 'db29ac6443ecef6d633a7576fe003974f6e826cb042cc15752e3b18514ee2922'
        velocity = Join-Path $repoRoot 'build/runtime-assets/velocity/3.5.1-615/server.jar'
        velocity_sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
        bungee = Join-Path $repoRoot 'build/runtime-assets/bungeecord/2085/server.jar'
        bungee_sha256 = 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'
        server_java_sha256 = '9f8d9893143b74849253c1fc323d095bfbf6dc9c7761caa9c5b62d44d9ee21e1'
    }
    '26.1.2' = [pscustomobject]@{
        minecraft_version = '26.1.2'; protocol = 775; server_java_feature = 25
        paper = Join-Path $repoRoot 'build/runtime-assets/paper/26.1.2/74/server.jar'
        paper_sha256 = '1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7'
        prepared = Join-Path $repoRoot 'build/runtime-assets/paper/26.1.2/74/prepared'
        prepared_tree_sha256 = '135440652cdcc94d6fc09c4aae7cd59a626fa60eaf48a398e8ae86bee8ef7d97'
        velocity = Join-Path $repoRoot 'build/runtime-assets/velocity/3.5.1-615/server.jar'
        velocity_sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
        bungee = Join-Path $repoRoot 'build/runtime-assets/bungeecord/2085/server.jar'
        bungee_sha256 = 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'
        server_java_sha256 = 'd5f1b9e03e298ebfb04d2326ecc1e2af3e6817f9b4d7f9f151fe856d56975650'
    }
    '26.2' = [pscustomobject]@{
        minecraft_version = '26.2'; protocol = 776; server_java_feature = 25
        paper = Join-Path $repoRoot 'build/runtime-assets/paper/26.2/112/server.jar'
        paper_sha256 = 'bd3a58cf96874e5ea6643f5f6fe9b4f5bf9e34b795fa078c2f0ee8b98b2f907e'
        prepared = Join-Path $repoRoot 'build/runtime-assets/paper/26.2/112/prepared'
        prepared_tree_sha256 = 'c88abb4e25a5f400282b2d5d9fff5e1701259f26c1f609062f14310f20f0218a'
        velocity = Join-Path $repoRoot 'build/runtime-assets/velocity/3.5.1-615/server.jar'
        velocity_sha256 = 'b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'
        bungee = Join-Path $repoRoot 'build/runtime-assets/bungeecord/2085/server.jar'
        bungee_sha256 = 'e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce'
        server_java_sha256 = 'd5f1b9e03e298ebfb04d2326ecc1e2af3e6817f9b4d7f9f151fe856d56975650'
    }
}
$targetDefinition = $targetDefinitions[$FabricTarget]
if ($null -eq $targetDefinition) { throw 'TRUSTED_DISPOSITION_TARGET_REQUIRED' }
$platformPaths = [ordered]@{
    velocity = $targetDefinition.velocity
    bungee = $targetDefinition.bungee
    paper = $targetDefinition.paper
    paper_prepared = $targetDefinition.prepared
}
$expectedPlatformSha256 = [ordered]@{
    velocity = $targetDefinition.velocity_sha256
    bungee = $targetDefinition.bungee_sha256
    paper = $targetDefinition.paper_sha256
}
$observerPath = Join-Path $repoRoot 'mcace-runtime-integration/build/libs/mcace-runtime-velocity-observer-test-only.jar'
$runtimeAssetBindingLimitation = 'CANONICAL_SOURCE_ASSETS_WINDOW_BOUND_RUN_ROOT_COPY_DIGEST_NOT_EMITTED'

$velocityCases = @(
    [pscustomobject]@{
        Test = 'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.velocityAdministratorReviewedExactHashCanRouteLimit'
        Prefix = 'velocity-enforce_limit-*'; Platform = 'VELOCITY'; Case = 'ENFORCE_LIMIT'
        Kind = 'ROUTE'; ExpectedBackend = 'LIMITED'
    },
    [pscustomobject]@{
        Test = 'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.velocityAdministratorReviewedExactHashCanRouteQuarantine'
        Prefix = 'velocity-enforce_quarantine-*'; Platform = 'VELOCITY'; Case = 'ENFORCE_QUARANTINE'
        Kind = 'ROUTE'; ExpectedBackend = 'QUARANTINE'
    },
    [pscustomobject]@{
        Test = 'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.velocityAdministratorReviewedDenyClosesOnlyCurrentConnectionAndAllowsCleanReconnect'
        Prefix = 'velocity-enforce_deny_reconnect-*'; Platform = 'VELOCITY'; Case = 'ENFORCE_DENY_RECONNECT'
        Kind = 'DENY_RECONNECT'; ExpectedBackend = 'LOBBY_AFTER_RECONNECT'
    }
)
$bungeeCases = @(
    [pscustomobject]@{
        Test = 'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.bungeeAdministratorReviewedExactHashCanRouteLimit'
        Prefix = 'bungee-enforce_limit-*'; Platform = 'BUNGEE'; Case = 'ENFORCE_LIMIT'
        Kind = 'ROUTE'; ExpectedBackend = 'LIMITED'
    },
    [pscustomobject]@{
        Test = 'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.bungeeAdministratorReviewedExactHashCanRouteQuarantine'
        Prefix = 'bungee-enforce_quarantine-*'; Platform = 'BUNGEE'; Case = 'ENFORCE_QUARANTINE'
        Kind = 'ROUTE'; ExpectedBackend = 'QUARANTINE'
    },
    [pscustomobject]@{
        Test = 'com.ellan.mcace.runtime.RealProxyDispositionMatrixGateTest.bungeeAdministratorReviewedDenyClosesOnlyCurrentConnectionAndAllowsCleanReconnect'
        Prefix = 'bungee-enforce_deny_reconnect-*'; Platform = 'BUNGEE'; Case = 'ENFORCE_DENY_RECONNECT'
        Kind = 'DENY_RECONNECT'; ExpectedBackend = 'LOBBY_AFTER_RECONNECT'
    }
)
$cases = switch ($Proxy) {
    'Velocity' { @($velocityCases) }
    'Bungee' { @($bungeeCases) }
    default { @($velocityCases) + @($bungeeCases) }
}
if (-not $ReportOnly -and $Proxy -cne 'Both') {
    throw 'TRUSTED_DISPOSITION_COMPLETE_6_OF_6_EXECUTION_REQUIRED'
}

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($digest.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $digest.Dispose()
    }
}

function Get-PathSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $digest = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($digest.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $digest.Dispose()
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

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal) -or
            $fullPath.StartsWith('//', [StringComparison]::Ordinal)) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_LOCAL_PATH_REQUIRED'
    }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) {
        throw "TRUSTED_DISPOSITION_EVIDENCE_DIRECTORY_REQUIRED: $fullPath"
    }
    if (-not $Directory -and $item.PSIsContainer) {
        throw "TRUSTED_DISPOSITION_EVIDENCE_FILE_REQUIRED: $fullPath"
    }
    if ($item.PSDrive.DisplayRoot -or $item.PSDrive.Root.StartsWith('\\')) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_LOCAL_PATH_REQUIRED'
    }
    $cursorPath = $item.FullName
    while (-not [string]::IsNullOrWhiteSpace($cursorPath)) {
        $cursor = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_REPARSE_PATH_REJECTED: $($cursor.FullName)"
        }
        $parentPath = Split-Path -Path $cursorPath -Parent
        if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $cursorPath) {
            break
        }
        $cursorPath = $parentPath
    }
    return $item.FullName
}

function ConvertTo-RepoRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $repoRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Trusted trusted disposition report path escapes the repository root: $fullPath"
    }
    return $fullPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Resolve-RepoRelativeEvidencePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath.Contains('\') -or
            $RelativePath.StartsWith('/', [StringComparison]::Ordinal) -or
            $RelativePath.Contains(':') -or @($RelativePath.Split('/') | Where-Object {
                $_ -eq '.' -or $_ -eq '..' -or [string]::IsNullOrWhiteSpace($_)
            }).Count -ne 0) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_RELATIVE_PATH_INVALID'
    }
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath))
    $rootPrefix = $repoRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_RELATIVE_PATH_ESCAPE'
    }
    return $candidate
}

function Test-JsonString {
    param($Value)
    return $Value -is [string]
}

function Test-JsonBoolean {
    param($Value)
    return $Value -is [bool]
}

function Test-JsonInteger {
    param($Value)
    return $Value -is [int] -or $Value -is [long]
}

function Test-ExactJsonProperties {
    param($Value, [Parameter(Mandatory)][string[]]$Expected)

    if ($null -eq $Value -or $Value -is [System.Array] -or $Value -is [string] -or
            $Value -is [ValueType]) {
        return $false
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object Name)
    if ($actual.Count -ne $Expected.Count) {
        return $false
    }
    foreach ($name in $Expected) {
        if ($actual -cnotcontains $name) {
            return $false
        }
    }
    return $true
}

function ConvertTo-EvidenceUtc {
    param($Value, [Parameter(Mandatory)][string]$Failure)

    if (-not (Test-JsonString $Value)) {
        throw $Failure
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value, 'o', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed) -or
            $parsed.Offset -ne [TimeSpan]::Zero) {
        throw $Failure
    }
    return $parsed.UtcDateTime
}

function Assert-NoDuplicateJsonProperties {
    param([Parameter(Mandatory)][string]$Raw, [Parameter(Mandatory)][string]$Failure)

    $objectProperties = [System.Collections.Generic.List[object]]::new()
    $inString = $false
    $escaped = $false
    $stringStart = -1
    for ($index = 0; $index -lt $Raw.Length; $index++) {
        $character = $Raw[$index]
        if ($inString) {
            if ($escaped) {
                $escaped = $false
                continue
            }
            if ($character -eq '\') {
                $escaped = $true
                continue
            }
            if ($character -ne '"') {
                continue
            }
            $inString = $false
            $after = $index + 1
            while ($after -lt $Raw.Length -and [char]::IsWhiteSpace($Raw[$after])) {
                $after++
            }
            if ($after -lt $Raw.Length -and $Raw[$after] -eq ':' -and
                    $objectProperties.Count -gt 0) {
                $token = $Raw.Substring($stringStart, $index - $stringStart + 1)
                try {
                    $name = [string]($token | ConvertFrom-Json -ErrorAction Stop)
                } catch {
                    throw $Failure
                }
                $current = $objectProperties[$objectProperties.Count - 1]
                if (-not $current.Add($name)) {
                    throw "$Failure`: $name"
                }
            }
            continue
        }
        if ($character -eq '"') {
            $inString = $true
            $stringStart = $index
        } elseif ($character -eq '{') {
            $objectProperties.Add(
                [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal))
        } elseif ($character -eq '}') {
            if ($objectProperties.Count -eq 0) {
                throw $Failure
            }
            $objectProperties.RemoveAt($objectProperties.Count - 1)
        }
    }
    if ($inString -or $objectProperties.Count -ne 0) {
        throw $Failure
    }
}

function Assert-SanitizedEvidenceJson {
    param([Parameter(Mandatory)][string]$Raw, [Parameter(Mandatory)][string]$Failure)

    if ($Raw -match '(?i)(?:^|["''\s])[a-z]:[\\/]' -or
            $Raw -match '\\\\' -or
            $Raw -match '(?i)(?:^|["''\s])/(?:home|users|tmp|var|opt|mnt|root|etc|usr)/' -or
            $Raw -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b' -or
            $Raw -match '(?i)"(?:pid|process_id|process_ids|[a-z0-9_]+_(?:pid|process_id|process_ids))"\s*:' -or
            $Raw -match '(?i)"(?:port|ports|[a-z0-9_]+_(?:port|ports))"\s*:') {
        throw $Failure
    }
    try {
        $decoded = $Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw $Failure
    }
    $pending = [System.Collections.Generic.Stack[object]]::new()
    $pending.Push($decoded)
    while ($pending.Count -gt 0) {
        $value = $pending.Pop()
        if ($value -is [string]) {
            if ($value -match '(?i)^[a-z]:[\\/]' -or $value -match '^[\\/]{2}' -or
                    $value -match '(?i)^/(?:home|users|tmp|var|opt|mnt|root|etc|usr)/' -or
                    $value -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b') {
                throw $Failure
            }
            continue
        }
        if ($null -eq $value -or $value -is [ValueType]) { continue }
        if ($value -is [System.Array]) {
            foreach ($entry in $value) { if ($null -ne $entry) { $pending.Push($entry) } }
            continue
        }
        foreach ($property in $value.PSObject.Properties) {
            if ($property.Name -match '(?i)(?:^|_)(?:pid|process_id|process_ids|port|ports)$') {
                throw $Failure
            }
            if ($null -ne $property.Value) { $pending.Push($property.Value) }
        }
    }
}

function Read-BoundedJsonEvidence {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = Assert-DirectLocalPath $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        $itemBefore = Get-Item -LiteralPath $resolved -Force
        if ($stream.Length -le 0 -or $stream.Length -gt $maximumEvidenceBytes -or
                $stream.Length -ne $itemBefore.Length) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_SIZE_INVALID: $resolved"
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "TRUSTED_DISPOSITION_EVIDENCE_CHANGED_DURING_READ: $resolved" }
            $offset += $read
        }
        $raw = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) { $raw = $raw.Substring(1) }
        Assert-NoDuplicateJsonProperties $raw 'TRUSTED_DISPOSITION_EVIDENCE_JSON_DUPLICATE_PROPERTY'
        $convertFromJson = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
        if ($convertFromJson.Parameters.ContainsKey('DateKind')) {
            $json = $raw | ConvertFrom-Json -DateKind String -ErrorAction Stop
        } else {
            $json = $raw | ConvertFrom-Json -ErrorAction Stop
        }
        $itemAfter = Get-Item -LiteralPath $resolved -Force
        if ($itemAfter.Length -ne $itemBefore.Length -or
                $itemAfter.LastWriteTimeUtc -ne $itemBefore.LastWriteTimeUtc) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_CHANGED_DURING_READ: $resolved"
        }
        return [pscustomobject]@{
            Path = $resolved
            RelativePath = ConvertTo-RepoRelativePath $resolved
            Raw = $raw
            Json = $json
            Sha256 = Get-BytesSha256 $bytes
            LastWriteTimeUtc = $itemAfter.LastWriteTimeUtc
            Stream = $stream
        }
    } catch {
        if ($null -ne $stream) { $stream.Dispose() }
        throw
    }
}

function Write-Utf8Json {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)

    $json = ($Value | ConvertTo-Json -Depth 8) + "`n"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    return $bytes
}

function Get-SourceManifestBinding {
    $paths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in @('build.gradle.kts', 'settings.gradle.kts', 'gradle.properties',
            'gradlew', 'gradlew.bat', 'scripts/trusted-disposition-proxy-matrix-smoke.ps1',
            'scripts/test-disposition-trusted-evidence-binding.ps1')) {
        [void]$paths.Add((Assert-DirectLocalPath (Join-Path $repoRoot $relative)))
    }
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'gradle') -Recurse -Force -File)) {
        [void]$paths.Add((Assert-DirectLocalPath $file.FullName))
    }
    foreach ($module in @(Get-ChildItem -LiteralPath $repoRoot -Directory -Filter 'mcace-*' -Force)) {
        foreach ($name in @('build.gradle.kts', 'gradle.lockfile')) {
            $candidate = Join-Path $module.FullName $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                [void]$paths.Add((Assert-DirectLocalPath $candidate))
            }
        }
        $sourceRoot = Join-Path $module.FullName 'src'
        if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force -File)) {
                [void]$paths.Add((Assert-DirectLocalPath $file.FullName))
            }
        }
    }
    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $paths) {
        $relative = ConvertTo-RepoRelativePath $path
        $encodedName = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($relative))
        $item = Get-Item -LiteralPath $path -Force
        $entries.Add("$encodedName`t$($item.Length)`t$(Get-PathSha256 $path)")
    }
    $ordered = $entries.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n") + "`n")
    return [pscustomobject]@{
        source_manifest_sha256 = Get-BytesSha256 $manifestBytes
        source_file_count = [int]$ordered.Count
    }
}

function Get-JavaBinding {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME) -or $env:JAVA_HOME.Contains('"')) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_JAVA_HOME_21_REQUIRED'
    }
    $javaHome = Assert-DirectLocalPath $env:JAVA_HOME -Directory
    $resolved = Assert-DirectLocalPath (Join-Path $javaHome 'bin/java.exe')
    $item = Get-Item -LiteralPath $resolved -Force
    $version = [string]$item.VersionInfo.FileVersion
    if ([string]::IsNullOrWhiteSpace($version)) {
        $version = [string]$item.VersionInfo.ProductVersion
    }
    if ($version -notmatch '^21(?:\.|$)') {
        throw "TRUSTED_DISPOSITION_EVIDENCE_JAVA_21_REQUIRED: $version"
    }
    return [pscustomobject]@{
        path = $resolved
        java_executable_sha256 = Get-PathSha256 $resolved
        java_file_version = $version
        java_major = 21
    }
}

function Get-TargetServerJavaBinding {
    $targetJavaHome = if ($targetDefinition.server_java_feature -eq 21) {
        $env:JAVA_HOME
    } else {
        $env:MCACE_JAVA25_HOME
    }
    if ([string]::IsNullOrWhiteSpace($targetJavaHome) -or $targetJavaHome.Contains('"')) {
        throw "TRUSTED_DISPOSITION_TARGET_JAVA_HOME_REQUIRED: $FabricTarget"
    }
    $java = Assert-DirectLocalPath (Join-Path $targetJavaHome 'bin/java.exe')
    $item = Get-Item -LiteralPath $java -Force
    $version = [string]$item.VersionInfo.FileVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = [string]$item.VersionInfo.ProductVersion }
    if ($version -notmatch "^$($targetDefinition.server_java_feature)(?:\.|$)") {
        throw "TRUSTED_DISPOSITION_TARGET_JAVA_FEATURE_MISMATCH: $FabricTarget / $version"
    }
    $sha = Get-PathSha256 $java
    if ($sha -cne $targetDefinition.server_java_sha256) {
        throw "TRUSTED_DISPOSITION_TARGET_JAVA_SHA256_MISMATCH: $FabricTarget"
    }
    return [pscustomobject]@{ path = $java; sha256 = $sha; version = $version; feature = [int]$targetDefinition.server_java_feature }
}

function Get-LocalTreeManifest {
    param([Parameter(Mandatory)][string]$RootPath)

    $root = (Assert-DirectLocalPath $RootPath -Directory).TrimEnd('\', '/')
    $entries = [System.Collections.Generic.List[string]]::new()
    $directoryCount = 1
    foreach ($entry in @(Get-ChildItem -LiteralPath $root -Recurse -Force)) {
        $resolved = Assert-DirectLocalPath $entry.FullName -Directory:$entry.PSIsContainer
        $relative = $resolved.Substring($root.Length + 1).Replace('\', '/')
        $encodedName = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($relative))
        if ($entry.PSIsContainer) {
            $directoryCount++
            $entries.Add("D`t$encodedName")
        } else {
            $entries.Add("F`t$encodedName`t$($entry.Length)`t$(Get-PathSha256 $resolved)")
        }
    }
    $ordered = $entries.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $manifestBytes = [Text.UTF8Encoding]::new($false).GetBytes(($ordered -join "`n") + "`n")
    return [pscustomobject]@{
        sha256 = Get-BytesSha256 $manifestBytes
        file_count = [int]@($ordered | Where-Object { $_.StartsWith("F`t", [StringComparison]::Ordinal) }).Count
        directory_count = [int]$directoryCount
    }
}

function Resolve-OfflineGradle961 {
    foreach ($name in @('GRADLE_OPTS', 'JAVA_OPTS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS',
            'JDK_JAVA_OPTIONS', 'GRADLE_JAVA_HOME')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_UNBOUND_JAVA_GRADLE_OPTION_REJECTED: $name"
        }
    }
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        if ([string]$entry.Key -like 'ORG_GRADLE_PROJECT_*' -and
                -not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_UNBOUND_GRADLE_PROJECT_PROPERTY_REJECTED: $($entry.Key)"
        }
    }
    $projectProperties = Get-Content -LiteralPath `
        (Assert-DirectLocalPath (Join-Path $repoRoot 'gradle.properties'))
    if (@($projectProperties | Where-Object { $_ -match '^\s*org\.gradle\.java\.home\s*=' }).Count -ne 0) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_PROJECT_JAVA_OVERRIDE_REJECTED'
    }
    foreach ($relative in @('.gradle/init.gradle', '.gradle/init.gradle.kts',
            'gradle/gradle-daemon-jvm.properties')) {
        if (Test-Path -LiteralPath (Join-Path $repoRoot $relative)) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_UNBOUND_PROJECT_GRADLE_INPUT_REJECTED: $relative"
        }
    }
    $propertiesPath = Assert-DirectLocalPath (Join-Path $repoRoot 'gradle/wrapper/gradle-wrapper.properties')
    $properties = Get-Content -LiteralPath $propertiesPath
    $distributionUrl = @($properties | Where-Object { $_ -like 'distributionUrl=*' })
    $distributionSha = @($properties | Where-Object { $_ -like 'distributionSha256Sum=*' })
    if ($distributionUrl.Count -ne 1 -or $distributionSha.Count -ne 1 -or
            $distributionUrl[0] -notmatch 'gradle-(?<version>[0-9]+(?:\.[0-9]+)+)-bin\.zip$') {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_GRADLE_WRAPPER_IDENTITY_INVALID'
    }
    $gradleVersion = $Matches['version']
    if ($gradleVersion -cne '9.6.1') {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_OFFLINE_GRADLE_9_6_1_REQUIRED'
    }
    $sha256 = $distributionSha[0].Substring('distributionSha256Sum='.Length).Trim().ToLowerInvariant()
    if ($sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_GRADLE_DISTRIBUTION_SHA_INVALID'
    }
    $gradleUserHome = if (-not [string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        [System.IO.Path]::GetFullPath($env:GRADLE_USER_HOME)
    } elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_GRADLE_USER_HOME_REQUIRED'
    }
    foreach ($candidate in @(
            (Join-Path $gradleUserHome 'gradle.properties'),
            (Join-Path $gradleUserHome 'init.gradle'),
            (Join-Path $gradleUserHome 'init.gradle.kts'))) {
        if (Test-Path -LiteralPath $candidate) {
            throw 'TRUSTED_DISPOSITION_EVIDENCE_UNBOUND_USER_GRADLE_INPUT_REJECTED'
        }
    }
    $initDirectory = Join-Path $gradleUserHome 'init.d'
    if (Test-Path -LiteralPath $initDirectory -PathType Container) {
        $initScripts = @(Get-ChildItem -LiteralPath $initDirectory -Recurse -Force -File |
            Where-Object { $_.Name -match '(?i)\.gradle(?:\.kts)?$' })
        if ($initScripts.Count -ne 0) {
            throw 'TRUSTED_DISPOSITION_EVIDENCE_UNBOUND_USER_GRADLE_INPUT_REJECTED'
        }
    }
    $gradleUserHome = Assert-DirectLocalPath $gradleUserHome -Directory
    $distributionRoot = Assert-DirectLocalPath `
        (Join-Path $gradleUserHome 'wrapper/dists/gradle-9.6.1-bin') -Directory
    $validInstallations = [System.Collections.Generic.List[object]]::new()
    foreach ($installationParentItem in @(Get-ChildItem -LiteralPath $distributionRoot `
            -Directory -Force -ErrorAction Stop)) {
        $installationParent = Assert-DirectLocalPath $installationParentItem.FullName -Directory
        $markerCandidate = Join-Path $installationParent 'gradle-9.6.1-bin.zip.ok'
        $homeCandidate = Join-Path $installationParent 'gradle-9.6.1'
        if (-not (Test-Path -LiteralPath $markerCandidate -PathType Leaf) -or
                -not (Test-Path -LiteralPath $homeCandidate -PathType Container)) {
            continue
        }
        $gradleInstallationHome = Assert-DirectLocalPath $homeCandidate -Directory
        $launcher = Assert-DirectLocalPath `
            (Join-Path $gradleInstallationHome 'lib/gradle-launcher-9.6.1.jar')
        $core = Assert-DirectLocalPath `
            (Join-Path $gradleInstallationHome 'lib/gradle-core-9.6.1.jar')
        $command = Assert-DirectLocalPath (Join-Path $gradleInstallationHome 'bin/gradle.bat')
        [void](Assert-DirectLocalPath $markerCandidate)
        $installation = Get-LocalTreeManifest $gradleInstallationHome
        $validInstallations.Add([pscustomobject]@{
            launcher = $launcher; core = $core; command = $command; manifest = $installation
        })
    }
    if ($validInstallations.Count -ne 1) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_OFFLINE_GRADLE_9_6_1_REQUIRED'
    }
    $selected = $validInstallations[0]
    $wrapperJar = Assert-DirectLocalPath (Join-Path $repoRoot 'gradle/wrapper/gradle-wrapper.jar')
    return [pscustomobject]@{
        gradle_version = $gradleVersion
        gradle_distribution_sha256 = $sha256
        gradle_wrapper_sha256 = Get-PathSha256 (Assert-DirectLocalPath $gradle)
        gradle_wrapper_jar_sha256 = Get-PathSha256 $wrapperJar
        gradle_launcher_path = $selected.launcher
        gradle_launcher_sha256 = Get-PathSha256 $selected.launcher
        gradle_core_sha256 = Get-PathSha256 $selected.core
        gradle_command_sha256 = Get-PathSha256 $selected.command
        gradle_installation_manifest_sha256 = $selected.manifest.sha256
        gradle_installation_file_count = $selected.manifest.file_count
        gradle_installation_directory_count = $selected.manifest.directory_count
        gradle_user_home = $gradleUserHome
    }
}

function Get-PlatformBinding {
    $hashes = [ordered]@{}
    foreach ($name in @('velocity', 'bungee', 'paper')) {
        $path = Assert-DirectLocalPath $platformPaths[$name]
        $hash = Get-PathSha256 $path
        if ($hash -cne $expectedPlatformSha256[$name]) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_PLATFORM_SHA256_MISMATCH: $name"
        }
        $hashes[$name] = $hash
    }
    $prepared = Get-LocalTreeManifest $platformPaths.paper_prepared
    if ($prepared.file_count -le 0) { throw 'TRUSTED_DISPOSITION_EVIDENCE_PREPARED_PAPER_EMPTY' }
    return [pscustomobject]@{
        velocity_server_sha256 = $hashes.velocity
        bungee_server_sha256 = $hashes.bungee
        paper_server_sha256 = $hashes.paper
        paper_prepared_manifest_sha256 = $prepared.sha256
        paper_prepared_file_count = $prepared.file_count
        paper_prepared_directory_count = $prepared.directory_count
    }
}

function Get-CurrentSourceEnvironmentBinding {
    $source = Get-SourceManifestBinding
    $java = Get-JavaBinding
    $serverJava = Get-TargetServerJavaBinding
    $gradleBinding = Resolve-OfflineGradle961
    return [ordered]@{
        gate_wrapper_sha256 = Get-PathSha256 (Assert-DirectLocalPath $PSCommandPath)
        source_manifest_sha256 = $source.source_manifest_sha256
        source_file_count = $source.source_file_count
        java_executable_sha256 = $java.java_executable_sha256
        java_file_version = $java.java_file_version
        java_major = $java.java_major
        target_minecraft_version = $targetDefinition.minecraft_version
        target_protocol = $targetDefinition.protocol
        target_server_java_feature = $serverJava.feature
        target_server_java_path = $serverJava.path
        target_server_java_version = $serverJava.version
        target_server_java_sha256 = $serverJava.sha256
        target_prepared_tree_sha256 = $targetDefinition.prepared_tree_sha256
        gradle_version = $gradleBinding.gradle_version
        gradle_distribution_sha256 = $gradleBinding.gradle_distribution_sha256
        gradle_wrapper_sha256 = $gradleBinding.gradle_wrapper_sha256
        gradle_wrapper_jar_sha256 = $gradleBinding.gradle_wrapper_jar_sha256
        gradle_launcher_path = $gradleBinding.gradle_launcher_path
        gradle_launcher_sha256 = $gradleBinding.gradle_launcher_sha256
        gradle_core_sha256 = $gradleBinding.gradle_core_sha256
        gradle_command_sha256 = $gradleBinding.gradle_command_sha256
        gradle_installation_manifest_sha256 = $gradleBinding.gradle_installation_manifest_sha256
        gradle_installation_file_count = $gradleBinding.gradle_installation_file_count
        gradle_installation_directory_count = $gradleBinding.gradle_installation_directory_count
        gradle_user_home = $gradleBinding.gradle_user_home
        java_path = $java.path
    }
}

function Get-CurrentEvidenceBinding {
    $sourceEnvironment = Get-CurrentSourceEnvironmentBinding
    $platform = Get-PlatformBinding
    foreach ($artifact in $artifactPaths.Values) {
        [void](Assert-DirectLocalPath $artifact)
    }
    $sourceEnvironment.velocity_plugin_sha256 = Get-PathSha256 $artifactPaths.velocity
    $sourceEnvironment.bungee_plugin_sha256 = Get-PathSha256 $artifactPaths.bungee
    $sourceEnvironment.paper_plugin_sha256 = Get-PathSha256 $artifactPaths.paper
    $sourceEnvironment.velocity_observer_sha256 = Get-PathSha256 (Assert-DirectLocalPath $observerPath)
    foreach ($name in @('velocity_server_sha256', 'bungee_server_sha256', 'paper_server_sha256',
            'paper_prepared_manifest_sha256', 'paper_prepared_file_count',
            'paper_prepared_directory_count')) {
        $sourceEnvironment[$name] = $platform.$name
    }
    return $sourceEnvironment
}

function Assert-CurrentBindingUnchanged {
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)

    foreach ($name in @('gate_wrapper_sha256', 'source_manifest_sha256', 'source_file_count',
            'java_executable_sha256', 'java_file_version', 'java_major', 'gradle_version',
            'target_minecraft_version', 'target_protocol', 'target_server_java_feature',
            'target_server_java_path', 'target_server_java_version', 'target_server_java_sha256',
            'target_prepared_tree_sha256',
            'gradle_distribution_sha256', 'gradle_wrapper_sha256', 'gradle_wrapper_jar_sha256',
            'gradle_launcher_sha256', 'gradle_core_sha256', 'gradle_command_sha256',
            'gradle_installation_manifest_sha256', 'gradle_installation_file_count',
            'gradle_installation_directory_count', 'gradle_user_home',
            'velocity_plugin_sha256', 'bungee_plugin_sha256', 'paper_plugin_sha256',
            'velocity_observer_sha256',
            'velocity_server_sha256', 'bungee_server_sha256', 'paper_server_sha256',
            'paper_prepared_manifest_sha256', 'paper_prepared_file_count',
            'paper_prepared_directory_count')) {
        if ($Before[$name] -ne $After[$name]) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_SOURCE_CHANGED_DURING_RUN: $name"
        }
    }
}

function Get-CaseReportPaths {
    param([Parameter(Mandatory)]$CaseDefinition)

    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) { return @() }
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($run in @(Get-ChildItem -LiteralPath $runsRoot -Directory -Force -ErrorAction Stop |
            Where-Object { $_.Name -like $CaseDefinition.Prefix })) {
        $runPath = Assert-DirectLocalPath $run.FullName -Directory
        $path = Join-Path $runPath 'report.json'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $paths.Add((Assert-DirectLocalPath $path))
        }
    }
    return $paths.ToArray()
}

function Get-NewCaseReport {
    param(
        [Parameter(Mandatory)]$CaseDefinition,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$BeforePaths,
        [Parameter(Mandatory)][DateTimeOffset]$InvocationStartedAt,
        [Parameter(Mandatory)][DateTimeOffset]$InvocationFinishedAt,
        [Parameter(Mandatory)]$AssetSnapshot
    )

    $before = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $BeforePaths) { [void]$before.Add($path) }
    $newPaths = @(Get-CaseReportPaths $CaseDefinition | Where-Object { -not $before.Contains($_) })
    if ($newPaths.Count -ne 1) {
        throw "TRUSTED_DISPOSITION_EVIDENCE_FRESH_CASE_REPORT_COUNT_INVALID: $($CaseDefinition.Platform)/$($CaseDefinition.Case)/$($newPaths.Count)"
    }
    $evidence = Read-BoundedJsonEvidence $newPaths[0]
    try {
        $writeAt = [DateTimeOffset]::new($evidence.LastWriteTimeUtc, [TimeSpan]::Zero)
        if ($writeAt -lt $InvocationStartedAt.Subtract($fileTimestampLowerBoundTolerance) -or
                $writeAt -gt $InvocationFinishedAt -or $writeAt -gt [DateTimeOffset]::UtcNow) {
            throw "TRUSTED_DISPOSITION_EVIDENCE_CASE_REPORT_TIMESTAMP_INVALID: $($evidence.RelativePath)"
        }
        $result = [pscustomobject]@{
            Path = $evidence.Path
            RelativePath = $evidence.RelativePath
            Report = $evidence.Json
            Raw = $evidence.Raw
            RawSha256 = $evidence.Sha256
            LastWriteTimeUtc = $evidence.LastWriteTimeUtc
            InvocationStartedAt = $InvocationStartedAt
            InvocationFinishedAt = $InvocationFinishedAt
            AssetSnapshot = $AssetSnapshot
            Definition = $CaseDefinition
            Stream = $evidence.Stream
        }
        Assert-CaseReport $result
        Assert-SanitizedEvidenceJson $result.Raw 'TRUSTED_DISPOSITION_RAW_REPORT_NOT_SANITIZED'
        return $result
    } catch {
        $evidence.Stream.Dispose()
        throw
    }
}

function Close-CaseReportStreams {
    param([Parameter(Mandatory)][System.Collections.Generic.List[object]]$Reports)

    foreach ($report in $Reports) {
        if ($null -ne $report.Stream) {
            $report.Stream.Dispose()
            $report.Stream = $null
        }
    }
}

function Remove-OwnedRawRoots {
    param([Parameter(Mandatory)][System.Collections.Generic.List[string]]$Roots)

    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) { return }
    $expectedParent = (Assert-DirectLocalPath $runsRoot -Directory).TrimEnd('\', '/')
    foreach ($root in @($Roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $resolvedRoot = Assert-DirectLocalPath $root -Directory
        if ((Split-Path -Parent $resolvedRoot).TrimEnd('\', '/') -cne $expectedParent) {
            throw 'TRUSTED_DISPOSITION_EVIDENCE_RAW_CLEANUP_SCOPE_INVALID'
        }
        $entries = @(Get-ChildItem -LiteralPath $resolvedRoot -Force -ErrorAction Stop)
        if ($entries.Count -ne 1 -or $entries[0].PSIsContainer -or
                $entries[0].Name -cne 'report.json') {
            throw 'TRUSTED_DISPOSITION_EVIDENCE_RAW_CLEANUP_LAYOUT_INVALID'
        }
        [System.IO.File]::Delete((Assert-DirectLocalPath $entries[0].FullName))
        [System.IO.Directory]::Delete($resolvedRoot, $false)
    }
}

function Remove-UnpublishedEvidenceRoot {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $parent = Assert-DirectLocalPath $evidenceRunsRoot -Directory
    $root = Assert-DirectLocalPath $Path -Directory
    if ((Split-Path -Parent $root) -cne $parent -or
            (Split-Path -Leaf $root) -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$') {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_ROLLBACK_SCOPE_INVALID'
    }
    $entries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    $names = @($entries | Where-Object { -not $_.PSIsContainer } |
        ForEach-Object Name | Sort-Object)
    if (@($entries | Where-Object PSIsContainer).Count -ne 0 -or $names.Count -ne 3 -or
            $names[0] -cne 'binding.json' -or $names[1] -cne 'commit.json' -or
            $names[2] -cne 'report.json') {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_ROLLBACK_LAYOUT_INVALID'
    }
    foreach ($entry in $entries) {
        [System.IO.File]::Delete((Assert-DirectLocalPath $entry.FullName))
    }
    [System.IO.Directory]::Delete($root, $false)
}

function Assert-CaseReport {
    param([Parameter(Mandatory)]$CaseReport)

    $report = $CaseReport.Report
    $definition = $CaseReport.Definition
    $routeProperties = @('schema', 'platform', 'case', 'evidence_origin', 'review_scope',
        'authorization_contract', 'expected_backend', 'forwarding_configured',
        'administrator_publisher_active', 'authentication_accepted', 'review_command_sent',
        'authorization_observed', 'authorization_journal_persisted',
        'authorization_persisted_before_execution', 'trusted_disposition_result_observed',
        'lobby_admission', 'limited_admission', 'quarantine_admission', 'route_completion',
        'current_connection_retained', 'owned_process_cleanup_zero', 'run_material_removed',
        'artifact_content_retained_in_report', 'case_passed')
    $velocityDenyProperties = @('schema', 'platform', 'case', 'evidence_origin',
        'review_scope', 'authorization_contract', 'scope', 'forwarding_configured',
        'fixture_login_ratelimit_disabled', 'administrator_publisher_active',
        'first_clean_manifest_sent', 'first_authentication_accepted',
        'first_lobby_verified_admission', 'review_command_sent', 'authorization_observed',
        'authorization_journal_persisted', 'authorization_persisted_before_execution',
        'denied_result_observed', 'first_connection_closed', 'disconnect_evidence',
        'limited_admission', 'quarantine_admission', 'same_offline_identity',
        'independent_authenticated_session', 'clean_manifest_sent',
        'clean_reconnect_authentication_accepted', 'clean_reconnect_configuration_completed',
        'clean_reconnect_lobby_verified_admission', 'clean_reconnect_stage', 'termination',
        'old_session_cleanup', 'reconnect_fixture_ready', 'clean_reconnect_outcome',
        'owned_process_cleanup_zero', 'run_material_removed', 'fabric_gui_coverage',
        'case_passed', 'matrix_completed')
    $bungeeDenyProperties = @('schema', 'platform', 'case', 'evidence_origin',
        'review_scope', 'authorization_contract', 'scope', 'forwarding_configured',
        'administrator_publisher_active', 'first_clean_manifest_sent',
        'first_authentication_accepted', 'first_lobby_verified_admission',
        'review_command_sent', 'authorization_observed', 'authorization_journal_persisted',
        'authorization_persisted_before_execution', 'denied_result_observed',
        'first_connection_closed', 'disconnect_evidence', 'proxy_registry_empty_before_reconnect',
        'limited_admission', 'quarantine_admission', 'same_offline_identity',
        'independent_authenticated_session', 'clean_manifest_sent',
        'clean_reconnect_authentication_accepted', 'clean_reconnect_configuration_completed',
        'clean_reconnect_lobby_verified_admission', 'clean_reconnect_stage', 'termination',
        'clean_reconnect_outcome', 'owned_process_cleanup_zero', 'run_material_removed',
        'artifact_content_retained_in_report', 'case_passed')
    $expectedProperties = if ($definition.Kind -eq 'ROUTE') {
        $routeProperties
    } elseif ($definition.Platform -eq 'VELOCITY') {
        $velocityDenyProperties
    } else {
        $bungeeDenyProperties
    }
    if (-not (Test-ExactJsonProperties $report $expectedProperties)) {
        throw "TRUSTED_DISPOSITION_EVIDENCE_CASE_REPORT_SCHEMA_INVALID: $($CaseReport.Path)"
    }
    $required = [ordered]@{
        platform = (Test-JsonString $report.platform) -and $report.platform -ceq $definition.Platform
        case = (Test-JsonString $report.case) -and $report.case -ceq $definition.Case
        evidence_origin = (Test-JsonString $report.evidence_origin) -and
            $report.evidence_origin -ceq 'ADMIN_REVIEWED'
        review_scope = (Test-JsonString $report.review_scope) -and $report.review_scope -ceq 'EXACT_HASH'
        authorization_contract = (Test-JsonString $report.authorization_contract) -and
            $report.authorization_contract -ceq 'UUID_CONTEXT_COMMITMENT_V3'
        forwarding_configured = (Test-JsonBoolean $report.forwarding_configured) -and $report.forwarding_configured
        administrator_publisher_active = (Test-JsonBoolean $report.administrator_publisher_active) -and
            $report.administrator_publisher_active
        authorization_observed = (Test-JsonBoolean $report.authorization_observed) -and
            $report.authorization_observed
        authorization_journal_persisted = (Test-JsonBoolean $report.authorization_journal_persisted) -and
            $report.authorization_journal_persisted
        authorization_persisted_before_execution =
            (Test-JsonBoolean $report.authorization_persisted_before_execution) -and
            $report.authorization_persisted_before_execution
        owned_process_cleanup_zero = (Test-JsonBoolean $report.owned_process_cleanup_zero) -and
            $report.owned_process_cleanup_zero
        run_material_removed = (Test-JsonBoolean $report.run_material_removed) -and $report.run_material_removed
        case_passed = (Test-JsonBoolean $report.case_passed) -and $report.case_passed
    }
    if ($definition.Kind -eq 'ROUTE') {
        $required.schema = (Test-JsonString $report.schema) -and
            $report.schema -ceq 'TRUSTED_DISPOSITION_PROCESS_GATE'
        $required.expected_backend = (Test-JsonString $report.expected_backend) -and
            $report.expected_backend -ceq $definition.ExpectedBackend
        $required.authentication_accepted = (Test-JsonBoolean $report.authentication_accepted) -and
            $report.authentication_accepted
        $required.review_command_sent = (Test-JsonBoolean $report.review_command_sent) -and $report.review_command_sent
        $required.trusted_disposition_result_observed =
            (Test-JsonBoolean $report.trusted_disposition_result_observed) -and
            $report.trusted_disposition_result_observed
        $required.lobby_admission = (Test-JsonBoolean $report.lobby_admission) -and $report.lobby_admission
        $required.route_completion = (Test-JsonString $report.route_completion) -and
            $report.route_completion -ceq 'SUCCESS'
        $required.current_connection_retained =
            (Test-JsonBoolean $report.current_connection_retained) -and $report.current_connection_retained
        $required.artifact_content_retained_in_report =
            (Test-JsonBoolean $report.artifact_content_retained_in_report) -and
            -not $report.artifact_content_retained_in_report
        $required.limited_admission = (Test-JsonBoolean $report.limited_admission) -and
            [bool]$report.limited_admission -eq ($definition.ExpectedBackend -eq 'LIMITED')
        $required.quarantine_admission = (Test-JsonBoolean $report.quarantine_admission) -and
            [bool]$report.quarantine_admission -eq ($definition.ExpectedBackend -eq 'QUARANTINE')
    } else {
        $required.schema = (Test-JsonString $report.schema) -and
            $report.schema -ceq 'TRUSTED_DENY_RECONNECT_PROCESS_GATE'
        $required.scope = (Test-JsonString $report.scope) -and
            $report.scope -ceq 'CURRENT_CONNECTION_THEN_CLEAN_RECONNECT'
        foreach ($name in @('first_clean_manifest_sent', 'first_authentication_accepted',
                'first_lobby_verified_admission', 'review_command_sent', 'denied_result_observed',
                'first_connection_closed', 'same_offline_identity', 'independent_authenticated_session',
                'clean_manifest_sent', 'clean_reconnect_authentication_accepted',
                'clean_reconnect_configuration_completed', 'clean_reconnect_lobby_verified_admission')) {
            $required[$name] = (Test-JsonBoolean $report.$name) -and [bool]$report.$name
        }
        $required.disconnect_evidence = (Test-JsonString $report.disconnect_evidence) -and
            $report.disconnect_evidence -ceq 'REMOTE_EOF_OR_RESET'
        $required.limited_admission = (Test-JsonBoolean $report.limited_admission) -and -not $report.limited_admission
        $required.quarantine_admission =
            (Test-JsonBoolean $report.quarantine_admission) -and -not $report.quarantine_admission
        $required.clean_reconnect_stage = (Test-JsonString $report.clean_reconnect_stage) -and
            $report.clean_reconnect_stage -ceq 'LOBBY_VERIFIED'
        $required.termination = (Test-JsonString $report.termination) -and $report.termination -ceq 'NONE'
        $required.clean_reconnect_outcome = (Test-JsonString $report.clean_reconnect_outcome) -and
            $report.clean_reconnect_outcome -ceq 'VERIFIED_LOBBY'
        if ($definition.Platform -eq 'VELOCITY') {
            $required.fixture_login_ratelimit_disabled =
                (Test-JsonBoolean $report.fixture_login_ratelimit_disabled) -and
                $report.fixture_login_ratelimit_disabled
            $required.old_session_cleanup = (Test-JsonString $report.old_session_cleanup) -and
                $report.old_session_cleanup -ceq 'RECONNECT_FIXTURE_READY'
            $required.reconnect_fixture_ready = (Test-JsonBoolean $report.reconnect_fixture_ready) -and
                $report.reconnect_fixture_ready
            $required.fabric_gui_coverage = (Test-JsonBoolean $report.fabric_gui_coverage) -and
                -not $report.fabric_gui_coverage
            $required.matrix_completed = (Test-JsonBoolean $report.matrix_completed) -and
                -not $report.matrix_completed
        } else {
            $required.proxy_registry_empty_before_reconnect =
                (Test-JsonBoolean $report.proxy_registry_empty_before_reconnect) -and
                $report.proxy_registry_empty_before_reconnect
            $required.artifact_content_retained_in_report =
                (Test-JsonBoolean $report.artifact_content_retained_in_report) -and
                -not $report.artifact_content_retained_in_report
        }
    }
    $failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
    if ($failed.Count -gt 0) {
        throw "Trusted disposition report failed validation ($($failed -join ', ')): $($CaseReport.Path)"
    }
}

function Assert-CasePointer {
    param([Parameter(Mandatory)][string]$RelativePath, [Parameter(Mandatory)]$Definition)

    $prefix = $Definition.Prefix.Substring(0, $Definition.Prefix.Length - 1)
    $runsRelative = (ConvertTo-RepoRelativePath $runsRoot).TrimEnd('/')
    $pattern = '^' + [regex]::Escape("$runsRelative/$prefix") + '[A-Za-z0-9._-]+/report\.json$'
    if ($RelativePath -cnotmatch $pattern) {
        throw "TRUSTED_DISPOSITION_EVIDENCE_CASE_POINTER_INVALID: $RelativePath"
    }
    return Resolve-RepoRelativeEvidencePath $RelativePath
}

function Assert-Aggregate {
    param(
        [Parameter(Mandatory)]$AggregateEvidence,
        [Parameter(Mandatory)][object[]]$ExpectedCases,
        [Parameter(Mandatory)][datetime]$GeneratedAtUtc,
        [Parameter(Mandatory)]$BindingJson,
        [Parameter(Mandatory)][AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$HeldRawEvidence
    )

    $aggregate = $AggregateEvidence.Json
    Assert-SanitizedEvidenceJson $AggregateEvidence.Raw 'TRUSTED_DISPOSITION_AGGREGATE_NOT_SANITIZED'
    $topProperties = @('schema', 'generated_at', 'source_mode', 'proxy_scope',
        'target_minecraft_version', 'target_protocol', 'target_server_java_feature',
        'target_server_java_sha256', 'target_prepared_tree_sha256',
        'expected_case_count', 'observed_case_count', 'all_cases_passed', 'matrix_completed',
        'evidence_origin', 'review_scope', 'authorization_contract',
        'client_report_independent_enforcement', 'authorization_persisted_before_execution',
        'deny_scope', 'automatic_permanent_ban', 'fabric_gui_coverage',
        'actual_run_root_digest_coverage', 'runtime_asset_binding_limitation', 'cases')
    if (-not (Test-ExactJsonProperties $aggregate $topProperties)) {
        throw 'TRUSTED_DISPOSITION_AGGREGATE_SCHEMA_INVALID'
    }
    $expectedScope = 'BOTH'
    $required = [ordered]@{
        schema = (Test-JsonString $aggregate.schema) -and $aggregate.schema -ceq $aggregateSchema
        generated_at = (Test-JsonString $aggregate.generated_at) -and
            (ConvertTo-EvidenceUtc $aggregate.generated_at 'TRUSTED_DISPOSITION_AGGREGATE_TIMESTAMP_INVALID') -eq $GeneratedAtUtc
        source_mode = (Test-JsonString $aggregate.source_mode) -and $aggregate.source_mode -ceq 'EXECUTED'
        proxy_scope = (Test-JsonString $aggregate.proxy_scope) -and $aggregate.proxy_scope -ceq $expectedScope
        target_minecraft_version = (Test-JsonString $aggregate.target_minecraft_version) -and
            $aggregate.target_minecraft_version -ceq $FabricTarget
        target_protocol = (Test-JsonInteger $aggregate.target_protocol) -and
            $aggregate.target_protocol -eq $targetDefinition.protocol
        target_server_java_feature = (Test-JsonInteger $aggregate.target_server_java_feature) -and
            $aggregate.target_server_java_feature -eq $targetDefinition.server_java_feature
        target_server_java_sha256 = (Test-JsonString $aggregate.target_server_java_sha256) -and
            $aggregate.target_server_java_sha256 -ceq $targetDefinition.server_java_sha256
        target_prepared_tree_sha256 = (Test-JsonString $aggregate.target_prepared_tree_sha256) -and
            $aggregate.target_prepared_tree_sha256 -ceq $targetDefinition.prepared_tree_sha256
        expected_case_count = (Test-JsonInteger $aggregate.expected_case_count) -and
            $aggregate.expected_case_count -eq $ExpectedCases.Count
        observed_case_count = (Test-JsonInteger $aggregate.observed_case_count) -and
            $aggregate.observed_case_count -eq $ExpectedCases.Count
        all_cases_passed = (Test-JsonBoolean $aggregate.all_cases_passed) -and $aggregate.all_cases_passed
        matrix_completed = (Test-JsonBoolean $aggregate.matrix_completed) -and
            $aggregate.matrix_completed
        evidence_origin = (Test-JsonString $aggregate.evidence_origin) -and
            $aggregate.evidence_origin -ceq 'ADMIN_REVIEWED'
        review_scope = (Test-JsonString $aggregate.review_scope) -and $aggregate.review_scope -ceq 'EXACT_HASH'
        authorization_contract = (Test-JsonString $aggregate.authorization_contract) -and
            $aggregate.authorization_contract -ceq 'UUID_CONTEXT_COMMITMENT_V3'
        client_report_independent_enforcement =
            (Test-JsonBoolean $aggregate.client_report_independent_enforcement) -and
            -not $aggregate.client_report_independent_enforcement
        authorization_persisted_before_execution =
            (Test-JsonBoolean $aggregate.authorization_persisted_before_execution) -and
            $aggregate.authorization_persisted_before_execution
        deny_scope = (Test-JsonString $aggregate.deny_scope) -and
            $aggregate.deny_scope -ceq 'CURRENT_CONNECTION_ONLY'
        automatic_permanent_ban = (Test-JsonBoolean $aggregate.automatic_permanent_ban) -and
            -not $aggregate.automatic_permanent_ban
        fabric_gui_coverage = (Test-JsonBoolean $aggregate.fabric_gui_coverage) -and
            -not $aggregate.fabric_gui_coverage
        actual_run_root_digest_coverage =
            (Test-JsonBoolean $aggregate.actual_run_root_digest_coverage) -and
            -not $aggregate.actual_run_root_digest_coverage
        runtime_asset_binding_limitation =
            (Test-JsonString $aggregate.runtime_asset_binding_limitation) -and
            $aggregate.runtime_asset_binding_limitation -ceq $runtimeAssetBindingLimitation
        cases = $aggregate.cases -is [System.Array] -and @($aggregate.cases).Count -eq $ExpectedCases.Count
    }
    $failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
    if ($failed.Count -gt 0) {
        throw "TRUSTED_DISPOSITION_AGGREGATE_ASSERTION_FAILED: $($failed -join ', ')"
    }
    $caseProperties = @('platform', 'case', 'evidence_origin', 'review_scope',
        'authorization_contract', 'authorization_journal_persisted',
        'authorization_persisted_before_execution', 'expected_backend',
        'first_connection_closed', 'current_connection_retained', 'clean_reconnect_outcome',
        'route_completion', 'owned_process_cleanup_zero', 'run_material_removed',
        'case_passed', 'report', 'raw_report_sha256')
    for ($index = 0; $index -lt $ExpectedCases.Count; $index++) {
        $definition = $ExpectedCases[$index]
        $case = @($aggregate.cases)[$index]
        if (-not (Test-ExactJsonProperties $case $caseProperties)) {
            throw "TRUSTED_DISPOSITION_AGGREGATE_CASE_SCHEMA_INVALID: $index"
        }
        $caseRequired = [ordered]@{
            platform = (Test-JsonString $case.platform) -and $case.platform -ceq $definition.Platform
            case = (Test-JsonString $case.case) -and $case.case -ceq $definition.Case
            evidence_origin = (Test-JsonString $case.evidence_origin) -and
                $case.evidence_origin -ceq 'ADMIN_REVIEWED'
            review_scope = (Test-JsonString $case.review_scope) -and $case.review_scope -ceq 'EXACT_HASH'
            authorization_contract = (Test-JsonString $case.authorization_contract) -and
                $case.authorization_contract -ceq 'UUID_CONTEXT_COMMITMENT_V3'
            authorization_journal_persisted =
                (Test-JsonBoolean $case.authorization_journal_persisted) -and
                $case.authorization_journal_persisted
            authorization_persisted_before_execution =
                (Test-JsonBoolean $case.authorization_persisted_before_execution) -and
                $case.authorization_persisted_before_execution
            expected_backend = (Test-JsonString $case.expected_backend) -and
                $case.expected_backend -ceq $definition.ExpectedBackend
            first_connection_closed = (Test-JsonBoolean $case.first_connection_closed) -and
                [bool]$case.first_connection_closed -eq ($definition.Kind -eq 'DENY_RECONNECT')
            current_connection_retained = (Test-JsonBoolean $case.current_connection_retained) -and
                [bool]$case.current_connection_retained -eq ($definition.Kind -eq 'ROUTE')
            clean_reconnect_outcome = (Test-JsonString $case.clean_reconnect_outcome) -and
                $case.clean_reconnect_outcome -ceq $(if ($definition.Kind -eq 'DENY_RECONNECT') {
                    'VERIFIED_LOBBY'
                } else { 'NOT_APPLICABLE' })
            route_completion = (Test-JsonString $case.route_completion) -and
                $case.route_completion -ceq $(if ($definition.Kind -eq 'ROUTE') {
                    'SUCCESS'
                } else { 'NOT_APPLICABLE' })
            owned_process_cleanup_zero =
                (Test-JsonBoolean $case.owned_process_cleanup_zero) -and $case.owned_process_cleanup_zero
            run_material_removed = (Test-JsonBoolean $case.run_material_removed) -and $case.run_material_removed
            case_passed = (Test-JsonBoolean $case.case_passed) -and $case.case_passed
            report = Test-JsonString $case.report
            raw_report_sha256 = (Test-JsonString $case.raw_report_sha256) -and
                $case.raw_report_sha256 -cmatch '^[0-9a-f]{64}$'
        }
        $caseFailed = @($caseRequired.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
        if ($caseFailed.Count -gt 0) {
            throw "TRUSTED_DISPOSITION_AGGREGATE_CASE_ASSERTION_FAILED: $index/$($caseFailed -join ', ')"
        }
        $rawPath = Assert-CasePointer $case.report $definition
        $rawEvidence = Read-BoundedJsonEvidence $rawPath
        try {
            $caseBinding = @($BindingJson.case_bindings)[$index]
            $started = ConvertTo-EvidenceUtc $caseBinding.invocation_started_at `
                'TRUSTED_DISPOSITION_CASE_BINDING_START_INVALID'
            $finished = ConvertTo-EvidenceUtc $caseBinding.invocation_finished_at `
                'TRUSTED_DISPOSITION_CASE_BINDING_FINISH_INVALID'
            $writeAt = ConvertTo-EvidenceUtc $caseBinding.raw_report_last_write_at `
                'TRUSTED_DISPOSITION_CASE_BINDING_MTIME_INVALID'
            if ($rawEvidence.Sha256 -cne $case.raw_report_sha256) {
                throw "TRUSTED_DISPOSITION_EVIDENCE_RAW_REPORT_SHA256_MISMATCH: $($case.report)"
            }
            if ($started -gt $finished -or $finished -gt $GeneratedAtUtc -or
                    $writeAt -lt $started.Subtract($fileTimestampLowerBoundTolerance) -or
                    $writeAt -gt $finished -or $writeAt -gt [DateTime]::UtcNow -or
                    $writeAt -ne $rawEvidence.LastWriteTimeUtc) {
                throw "TRUSTED_DISPOSITION_RAW_REPORT_TIMESTAMP_INVALID: $($case.report)"
            }
            Assert-SanitizedEvidenceJson $rawEvidence.Raw 'TRUSTED_DISPOSITION_RAW_REPORT_NOT_SANITIZED'
            Assert-CaseReport ([pscustomobject]@{
                Path = $rawEvidence.Path; RelativePath = $rawEvidence.RelativePath
                Report = $rawEvidence.Json; RawSha256 = $rawEvidence.Sha256
                LastWriteTimeUtc = $rawEvidence.LastWriteTimeUtc; Definition = $definition
            })
            $HeldRawEvidence.Add($rawEvidence)
        } catch {
            $rawEvidence.Stream.Dispose()
            throw
        }
    }
}

function Assert-Binding {
    param(
        [Parameter(Mandatory)]$BindingEvidence,
        [Parameter(Mandatory)]$AggregateEvidence,
        [Parameter(Mandatory)]$Current,
        [Parameter(Mandatory)][datetime]$GeneratedAtUtc,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$RawEvidence
    )

    $binding = $BindingEvidence.Json
    Assert-SanitizedEvidenceJson $BindingEvidence.Raw 'TRUSTED_DISPOSITION_BINDING_NOT_SANITIZED'
    $properties = @('schema', 'report_schema', 'report_generated_at', 'report_sha256',
        'binding_generated_at', 'source_mode', 'proxy_scope', 'expected_case_count',
        'matrix_completed', 'gate_wrapper_sha256', 'source_manifest_sha256', 'source_file_count',
        'target_minecraft_version', 'target_protocol', 'target_server_java_feature',
        'target_server_java_sha256', 'target_prepared_tree_sha256', 'velocity_observer_sha256',
        'velocity_plugin_sha256', 'bungee_plugin_sha256', 'paper_plugin_sha256',
        'velocity_server_sha256', 'bungee_server_sha256', 'paper_server_sha256',
        'paper_prepared_manifest_sha256', 'paper_prepared_file_count',
        'paper_prepared_directory_count',
        'java_executable_sha256', 'java_file_version', 'java_major', 'gradle_version',
        'gradle_distribution_sha256', 'gradle_wrapper_sha256', 'gradle_wrapper_jar_sha256',
        'gradle_launcher_sha256', 'gradle_core_sha256', 'gradle_command_sha256',
        'gradle_installation_manifest_sha256', 'gradle_installation_file_count',
        'gradle_installation_directory_count', 'actual_run_root_digest_coverage',
        'runtime_asset_binding_limitation', 'case_bindings', 'passed')
    if (-not (Test-ExactJsonProperties $binding $properties)) {
        throw 'TRUSTED_DISPOSITION_BINDING_SCHEMA_INVALID'
    }
    $bindingGeneratedAt = ConvertTo-EvidenceUtc $binding.binding_generated_at 'TRUSTED_DISPOSITION_BINDING_TIMESTAMP_INVALID'
    $required = [ordered]@{
        schema = (Test-JsonString $binding.schema) -and $binding.schema -ceq $bindingSchema
        report_schema = (Test-JsonString $binding.report_schema) -and $binding.report_schema -ceq $aggregateSchema
        report_generated_at = (Test-JsonString $binding.report_generated_at) -and
            (ConvertTo-EvidenceUtc $binding.report_generated_at 'TRUSTED_DISPOSITION_BINDING_REPORT_TIMESTAMP_INVALID') -eq $GeneratedAtUtc
        report_sha256 = (Test-JsonString $binding.report_sha256) -and
            $binding.report_sha256 -ceq $AggregateEvidence.Sha256
        binding_generated_at = $bindingGeneratedAt -ge $GeneratedAtUtc.AddSeconds(-1) -and
            $bindingGeneratedAt -le $GeneratedAtUtc.AddMinutes(2)
        source_mode = (Test-JsonString $binding.source_mode) -and $binding.source_mode -ceq 'EXECUTED'
        proxy_scope = (Test-JsonString $binding.proxy_scope) -and
            $binding.proxy_scope -ceq 'BOTH'
        target_minecraft_version = (Test-JsonString $binding.target_minecraft_version) -and
            $binding.target_minecraft_version -ceq $FabricTarget
        target_protocol = (Test-JsonInteger $binding.target_protocol) -and
            $binding.target_protocol -eq $targetDefinition.protocol
        target_server_java_feature = (Test-JsonInteger $binding.target_server_java_feature) -and
            $binding.target_server_java_feature -eq $targetDefinition.server_java_feature
        target_server_java_sha256 = (Test-JsonString $binding.target_server_java_sha256) -and
            $binding.target_server_java_sha256 -ceq $Current.target_server_java_sha256
        target_prepared_tree_sha256 = (Test-JsonString $binding.target_prepared_tree_sha256) -and
            $binding.target_prepared_tree_sha256 -ceq $Current.target_prepared_tree_sha256
        velocity_observer_sha256 = (Test-JsonString $binding.velocity_observer_sha256) -and
            $binding.velocity_observer_sha256 -ceq $Current.velocity_observer_sha256
        expected_case_count = (Test-JsonInteger $binding.expected_case_count) -and
            $binding.expected_case_count -eq 6
        matrix_completed = (Test-JsonBoolean $binding.matrix_completed) -and
            $binding.matrix_completed
        source_file_count = (Test-JsonInteger $binding.source_file_count) -and
            $binding.source_file_count -eq $Current.source_file_count
        java_major = (Test-JsonInteger $binding.java_major) -and $binding.java_major -eq 21
        gradle_installation_file_count =
            (Test-JsonInteger $binding.gradle_installation_file_count) -and
            $binding.gradle_installation_file_count -eq $Current.gradle_installation_file_count
        gradle_installation_directory_count =
            (Test-JsonInteger $binding.gradle_installation_directory_count) -and
            $binding.gradle_installation_directory_count -eq $Current.gradle_installation_directory_count
        paper_prepared_file_count = (Test-JsonInteger $binding.paper_prepared_file_count) -and
            $binding.paper_prepared_file_count -eq $Current.paper_prepared_file_count
        paper_prepared_directory_count =
            (Test-JsonInteger $binding.paper_prepared_directory_count) -and
            $binding.paper_prepared_directory_count -eq $Current.paper_prepared_directory_count
        actual_run_root_digest_coverage =
            (Test-JsonBoolean $binding.actual_run_root_digest_coverage) -and
            -not $binding.actual_run_root_digest_coverage
        runtime_asset_binding_limitation =
            (Test-JsonString $binding.runtime_asset_binding_limitation) -and
            $binding.runtime_asset_binding_limitation -ceq $runtimeAssetBindingLimitation
        case_bindings = $binding.case_bindings -is [System.Array] -and
            @($binding.case_bindings).Count -eq 6
        passed = (Test-JsonBoolean $binding.passed) -and $binding.passed
    }
    foreach ($name in @('gate_wrapper_sha256', 'source_manifest_sha256', 'velocity_observer_sha256', 'velocity_plugin_sha256',
            'bungee_plugin_sha256', 'paper_plugin_sha256', 'java_executable_sha256',
            'velocity_server_sha256', 'bungee_server_sha256', 'paper_server_sha256',
            'paper_prepared_manifest_sha256',
            'java_file_version', 'gradle_version', 'gradle_distribution_sha256',
            'gradle_wrapper_sha256', 'gradle_wrapper_jar_sha256', 'gradle_launcher_sha256',
            'gradle_core_sha256', 'gradle_command_sha256', 'gradle_installation_manifest_sha256')) {
        $required[$name] = (Test-JsonString $binding.$name) -and
            [string]$binding.$name -ceq [string]$Current[$name]
    }
    foreach ($name in @('report_sha256', 'gate_wrapper_sha256', 'source_manifest_sha256',
            'velocity_observer_sha256',
            'velocity_plugin_sha256', 'bungee_plugin_sha256', 'paper_plugin_sha256',
            'velocity_server_sha256', 'bungee_server_sha256', 'paper_server_sha256',
            'paper_prepared_manifest_sha256',
            'java_executable_sha256', 'gradle_distribution_sha256', 'gradle_wrapper_sha256',
            'gradle_wrapper_jar_sha256', 'gradle_launcher_sha256', 'gradle_core_sha256',
            'gradle_command_sha256', 'gradle_installation_manifest_sha256')) {
        $required["${name}_format"] = (Test-JsonString $binding.$name) -and
            $binding.$name -cmatch '^[0-9a-f]{64}$'
    }
    $failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
    if ($failed.Count -gt 0) {
        throw "TRUSTED_DISPOSITION_BINDING_ASSERTION_FAILED: $($failed -join ', ')"
    }
    $caseProperties = @('platform', 'case', 'raw_report', 'raw_report_sha256',
        'raw_report_last_write_at', 'invocation_started_at', 'invocation_finished_at',
        'source_manifest_sha256', 'source_file_count', 'velocity_plugin_sha256',
        'bungee_plugin_sha256', 'paper_plugin_sha256', 'velocity_server_sha256',
        'bungee_server_sha256', 'paper_server_sha256', 'paper_prepared_manifest_sha256',
        'paper_prepared_file_count', 'paper_prepared_directory_count')
    $digestNames = @('source_manifest_sha256', 'velocity_plugin_sha256',
        'bungee_plugin_sha256', 'paper_plugin_sha256', 'velocity_server_sha256',
        'bungee_server_sha256', 'paper_server_sha256', 'paper_prepared_manifest_sha256')
    $expectedCaseKeys = @($cases | ForEach-Object { "$($_.Platform)|$($_.Case)" })
    $actualCaseKeys = @($binding.case_bindings | ForEach-Object { "$($_.platform)|$($_.case)" })
    if (($actualCaseKeys -join "`n") -cne ($expectedCaseKeys -join "`n")) {
        throw 'TRUSTED_DISPOSITION_CASE_BINDING_SET_INVALID'
    }
    for ($index = 0; $index -lt $cases.Count; $index++) {
        $caseBinding = @($binding.case_bindings)[$index]
        $aggregateCase = @($AggregateEvidence.Json.cases)[$index]
        $raw = $RawEvidence[$index]
        $definition = $cases[$index]
        if (-not (Test-ExactJsonProperties $caseBinding $caseProperties)) {
            throw "TRUSTED_DISPOSITION_CASE_BINDING_SCHEMA_INVALID: $index"
        }
        $started = ConvertTo-EvidenceUtc $caseBinding.invocation_started_at `
            'TRUSTED_DISPOSITION_CASE_BINDING_START_INVALID'
        $finished = ConvertTo-EvidenceUtc $caseBinding.invocation_finished_at `
            'TRUSTED_DISPOSITION_CASE_BINDING_FINISH_INVALID'
        $writeAt = ConvertTo-EvidenceUtc $caseBinding.raw_report_last_write_at `
            'TRUSTED_DISPOSITION_CASE_BINDING_MTIME_INVALID'
        if ($started -gt $finished -or $finished -gt $GeneratedAtUtc -or
                $writeAt -lt $started.Subtract($fileTimestampLowerBoundTolerance) -or
                $writeAt -gt $finished -or $writeAt -gt [DateTime]::UtcNow -or
                $writeAt -ne $raw.LastWriteTimeUtc -or
                -not (Test-JsonString $caseBinding.platform) -or
                $caseBinding.platform -cne $definition.Platform -or
                -not (Test-JsonString $caseBinding.case) -or
                $caseBinding.case -cne $definition.Case -or
                -not (Test-JsonString $caseBinding.raw_report) -or
                $caseBinding.raw_report -cne $aggregateCase.report -or
                $caseBinding.raw_report -cne $raw.RelativePath -or
                -not (Test-JsonString $caseBinding.raw_report_sha256) -or
                $caseBinding.raw_report_sha256 -cne $aggregateCase.raw_report_sha256 -or
                $caseBinding.raw_report_sha256 -cne $raw.Sha256 -or
                -not (Test-JsonInteger $caseBinding.source_file_count) -or
                $caseBinding.source_file_count -ne $Current.source_file_count -or
                -not (Test-JsonInteger $caseBinding.paper_prepared_file_count) -or
                $caseBinding.paper_prepared_file_count -ne $Current.paper_prepared_file_count -or
                -not (Test-JsonInteger $caseBinding.paper_prepared_directory_count) -or
                $caseBinding.paper_prepared_directory_count -ne $Current.paper_prepared_directory_count) {
            throw "TRUSTED_DISPOSITION_CASE_BINDING_INVALID: $index"
        }
        foreach ($name in $digestNames) {
            if (-not (Test-JsonString $caseBinding.$name) -or
                    $caseBinding.$name -cnotmatch '^[0-9a-f]{64}$' -or
                    $caseBinding.$name -cne [string]$Current[$name]) {
                throw "TRUSTED_DISPOSITION_CASE_BINDING_CURRENT_MISMATCH: $index/$name"
            }
        }
    }
}

function Assert-CommitMarker {
    param(
        [Parameter(Mandatory)]$CommitEvidence,
        [Parameter(Mandatory)]$ReportEvidence,
        [Parameter(Mandatory)]$BindingEvidence,
        [Parameter(Mandatory)]$Report
    )

    Assert-SanitizedEvidenceJson $CommitEvidence.Raw 'TRUSTED_DISPOSITION_COMMIT_NOT_SANITIZED'
    $properties = @('schema', 'generated_at', 'report_schema', 'binding_schema',
        'report_sha256', 'binding_sha256', 'committed')
    $commit = $CommitEvidence.Json
    if (-not (Test-ExactJsonProperties $commit $properties) -or
            -not (Test-JsonString $commit.schema) -or $commit.schema -cne $commitSchema -or
            -not (Test-JsonString $commit.generated_at) -or
            $commit.generated_at -cne $Report.generated_at -or
            -not (Test-JsonString $commit.report_schema) -or
            $commit.report_schema -cne $aggregateSchema -or
            -not (Test-JsonString $commit.binding_schema) -or
            $commit.binding_schema -cne $bindingSchema -or
            -not (Test-JsonString $commit.report_sha256) -or
            $commit.report_sha256 -cne $ReportEvidence.Sha256 -or
            -not (Test-JsonString $commit.binding_sha256) -or
            $commit.binding_sha256 -cne $BindingEvidence.Sha256 -or
            -not (Test-JsonBoolean $commit.committed) -or -not $commit.committed) {
        throw 'TRUSTED_DISPOSITION_COMMIT_INVALID'
    }
}

function Assert-EvidencePair {
    param([Parameter(Mandatory)][string]$ReportPath)

    $reportEvidence = $null
    $bindingEvidence = $null
    $commitEvidence = $null
    $heldRaw = [System.Collections.Generic.List[object]]::new()
    try {
        $pairRoot = Assert-DirectLocalPath (Split-Path -Parent $ReportPath) -Directory
        $entries = @(Get-ChildItem -LiteralPath $pairRoot -Force -ErrorAction Stop)
        $files = @($entries | Where-Object { -not $_.PSIsContainer } | ForEach-Object Name | Sort-Object)
        if (@($entries | Where-Object PSIsContainer).Count -ne 0 -or $files.Count -ne 3 -or
                $files[0] -cne 'binding.json' -or $files[1] -cne 'commit.json' -or
                $files[2] -cne 'report.json') {
            throw 'TRUSTED_DISPOSITION_EVIDENCE_PAIR_LAYOUT_INVALID'
        }
        $reportEvidence = Read-BoundedJsonEvidence $ReportPath
        $bindingEvidence = Read-BoundedJsonEvidence (Join-Path $pairRoot 'binding.json')
        $commitEvidence = Read-BoundedJsonEvidence (Join-Path $pairRoot 'commit.json')
        $generatedAtUtc = ConvertTo-EvidenceUtc $reportEvidence.Json.generated_at `
            'TRUSTED_DISPOSITION_AGGREGATE_TIMESTAMP_INVALID'
        $nowUtc = [DateTime]::UtcNow
        if ($generatedAtUtc -gt $nowUtc.AddMinutes(2) -or
                $generatedAtUtc -lt $nowUtc.AddMinutes(-$MaximumReportAgeMinutes)) {
            throw 'TRUSTED_DISPOSITION_AGGREGATE_FRESHNESS_INVALID'
        }
        $current = Get-CurrentEvidenceBinding
        Assert-Aggregate $reportEvidence $cases $generatedAtUtc $bindingEvidence.Json $heldRaw
        Assert-CommitMarker $commitEvidence $reportEvidence $bindingEvidence $reportEvidence.Json
        Assert-Binding $bindingEvidence $reportEvidence $current $generatedAtUtc $heldRaw
        $currentAfter = Get-CurrentEvidenceBinding
        Assert-CurrentBindingUnchanged $current $currentAfter
        return [pscustomobject]@{ ReportPath = $reportEvidence.Path }
    } finally {
        foreach ($raw in $heldRaw) { $raw.Stream.Dispose() }
        if ($null -ne $commitEvidence) { $commitEvidence.Stream.Dispose() }
        if ($null -ne $bindingEvidence) { $bindingEvidence.Stream.Dispose() }
        if ($null -ne $reportEvidence) { $reportEvidence.Stream.Dispose() }
    }
}

function Get-LatestCommittedPair {
    if (-not (Test-Path -LiteralPath $evidenceRunsRoot -PathType Container)) {
        throw 'TRUSTED_DISPOSITION_REPORT_ONLY_COMMITTED_PAIR_NOT_FOUND'
    }
    if (@(Get-ChildItem -LiteralPath $evidenceRunsRoot -Directory -Force -ErrorAction Stop |
            Where-Object { $_.Name -like '.attempt-*' -or $_.Name -like '.staging-*' }).Count -ne 0) {
        throw 'TRUSTED_DISPOSITION_REPORT_ONLY_UNCOMMITTED_EXECUTION_PRESENT'
    }
    $pair = Get-ChildItem -LiteralPath $evidenceRunsRoot -Directory -Force -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $_.Name -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$' -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'commit.json') -PathType Leaf)
        } |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $pair) {
        throw 'TRUSTED_DISPOSITION_REPORT_ONLY_COMMITTED_PAIR_NOT_FOUND'
    }
    $newestCandidate = Get-ChildItem -LiteralPath $evidenceRunsRoot -Directory -Force -ErrorAction Stop |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $_.Name -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$'
        } | Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $newestCandidate -or $newestCandidate.Name -cne $pair.Name) {
        throw 'TRUSTED_DISPOSITION_REPORT_ONLY_NEWEST_EVIDENCE_NOT_COMMITTED'
    }
    return [pscustomobject]@{ ReportPath = Join-Path $pair.FullName 'report.json' }
}

if ($ReportOnly) {
    $latest = Get-LatestCommittedPair
    $validated = Assert-EvidencePair $latest.ReportPath
    Write-Output "TRUSTED_DISPOSITION_PROCESS_MATRIX_PASS|$(ConvertTo-RepoRelativePath $validated.ReportPath)"
    exit 0
}

$before = Get-CurrentEvidenceBinding
$caseReports = [System.Collections.Generic.List[object]]::new()
$ownedRawRoots = [System.Collections.Generic.List[string]]::new()
$published = $false
$evidenceMoved = $false
$attemptRoot = $null
$stagingRoot = $null
try {
    [void][System.IO.Directory]::CreateDirectory($evidenceRunsRoot)
    $runName = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ss-fffffffZ')
    $attemptRoot = Join-Path $evidenceRunsRoot ('.attempt-' + $runName)
    [void][System.IO.Directory]::CreateDirectory($attemptRoot)
    # Deliberately sequential: real proxies and disposable Paper backends never overlap.
    foreach ($case in $cases) {
        $caseBefore = Get-CurrentEvidenceBinding
        Assert-CurrentBindingUnchanged $before $caseBefore
        $priorPaths = [string[]]@(Get-CaseReportPaths $case)
        $startedAt = [DateTimeOffset]::UtcNow
        $finishedAt = $null
        Push-Location $repoRoot
        try {
            $runtimeArguments = [System.Collections.Generic.List[string]]::new()
            foreach ($argument in @(
                    '-Dmcace.runtime.trusted-disposition.enabled=true',
                    '-Dmcace.runtime.backend-kind=PAPER',
                    "-Dmcace.runtime.backend.jar=$($targetDefinition.paper)",
                    "-Dmcace.runtime.backend.jar.sha256=$($targetDefinition.paper_sha256)",
                    "-Dmcace.runtime.backend.prepared-root=$($targetDefinition.prepared)",
                    "-Dmcace.runtime.backend.prepared-root.sha256=$($targetDefinition.prepared_tree_sha256)",
                    "-Dmcace.runtime.minecraft-version=$($targetDefinition.minecraft_version)",
                    "-Dmcace.runtime.minecraft-protocol=$($targetDefinition.protocol)",
                    "-Dmcace.runtime.server-java=$($caseBefore.target_server_java_path)",
                    "-Dmcace.runtime.server-java.sha256=$($targetDefinition.server_java_sha256)",
                    "-Dmcace.runtime.server-java-feature=$($targetDefinition.server_java_feature)")) {
                $runtimeArguments.Add($argument)
            }
            if ($case.Platform -ceq 'VELOCITY') {
                $runtimeArguments.Add("-Dmcace.runtime.velocity-observer.jar=$observerPath")
                $runtimeArguments.Add("-Dmcace.runtime.velocity.jar=$($targetDefinition.velocity)")
                $runtimeArguments.Add("-Dmcace.runtime.velocity.jar.sha256=$($targetDefinition.velocity_sha256)")
            } else {
                $runtimeArguments.Add("-Dmcace.runtime.bungee.jar=$($targetDefinition.bungee)")
                $runtimeArguments.Add("-Dmcace.runtime.bungee.jar.sha256=$($targetDefinition.bungee_sha256)")
            }
            & $caseBefore.java_path '-classpath' $caseBefore.gradle_launcher_path `
                'org.gradle.launcher.GradleMain' ':mcace-runtime-integration:test' `
                '--tests' $case.Test @runtimeArguments `
                '--offline' '--dependency-verification=strict' '--rerun-tasks' `
                '--no-build-cache' '--no-configuration-cache' '--no-daemon' '--no-parallel' `
                '--max-workers=1' '--console=plain' '--gradle-user-home' `
                $caseBefore.gradle_user_home '--project-dir' $repoRoot
            if ($LASTEXITCODE -ne 0) {
                throw "MCAce trusted disposition process gate failed: $($case.Test)"
            }
        } finally {
            $finishedAt = [DateTimeOffset]::UtcNow
            Pop-Location
        }
        $caseAfter = Get-CurrentEvidenceBinding
        Assert-CurrentBindingUnchanged $caseBefore $caseAfter
        Assert-CurrentBindingUnchanged $before $caseAfter
        $caseReport = Get-NewCaseReport -CaseDefinition $case -BeforePaths $priorPaths `
            -InvocationStartedAt $startedAt -InvocationFinishedAt $finishedAt `
            -AssetSnapshot $caseAfter
        $ownedRawRoots.Add((Split-Path -Parent $caseReport.Path))
        $caseReports.Add($caseReport)
    }

    if ($caseReports.Count -ne 6) { throw 'TRUSTED_DISPOSITION_COMPLETE_6_OF_6_EXECUTION_REQUIRED' }
    $current = Get-CurrentEvidenceBinding
    Assert-CurrentBindingUnchanged $before $current
    $aggregateCases = @($caseReports | ForEach-Object {
        [ordered]@{
            platform = $_.Report.platform
            case = $_.Report.case
            evidence_origin = $_.Report.evidence_origin
            review_scope = $_.Report.review_scope
            authorization_contract = $_.Report.authorization_contract
            authorization_journal_persisted = $_.Report.authorization_journal_persisted
            authorization_persisted_before_execution = $_.Report.authorization_persisted_before_execution
            expected_backend = $_.Definition.ExpectedBackend
            first_connection_closed = if ($_.Definition.Kind -eq 'DENY_RECONNECT') {
                $_.Report.first_connection_closed
            } else { $false }
            current_connection_retained = if ($_.Definition.Kind -eq 'ROUTE') {
                $_.Report.current_connection_retained
            } else { $false }
            clean_reconnect_outcome = if ($_.Definition.Kind -eq 'DENY_RECONNECT') {
                $_.Report.clean_reconnect_outcome
            } else { 'NOT_APPLICABLE' }
            route_completion = if ($_.Definition.Kind -eq 'ROUTE') {
                $_.Report.route_completion
            } else { 'NOT_APPLICABLE' }
            owned_process_cleanup_zero = $_.Report.owned_process_cleanup_zero
            run_material_removed = $_.Report.run_material_removed
            case_passed = $_.Report.case_passed
            report = $_.RelativePath
            raw_report_sha256 = $_.RawSha256
        }
    })
    $caseBindings = @($caseReports | ForEach-Object {
        $snapshot = $_.AssetSnapshot
        [ordered]@{
            platform = $_.Report.platform
            case = $_.Report.case
            raw_report = $_.RelativePath
            raw_report_sha256 = $_.RawSha256
            raw_report_last_write_at = ([DateTimeOffset]::new(
                $_.LastWriteTimeUtc, [TimeSpan]::Zero)).ToString('o')
            invocation_started_at = $_.InvocationStartedAt.ToUniversalTime().ToString('o')
            invocation_finished_at = $_.InvocationFinishedAt.ToUniversalTime().ToString('o')
            source_manifest_sha256 = $snapshot.source_manifest_sha256
            source_file_count = $snapshot.source_file_count
            velocity_plugin_sha256 = $snapshot.velocity_plugin_sha256
            bungee_plugin_sha256 = $snapshot.bungee_plugin_sha256
            paper_plugin_sha256 = $snapshot.paper_plugin_sha256
            velocity_server_sha256 = $snapshot.velocity_server_sha256
            bungee_server_sha256 = $snapshot.bungee_server_sha256
            paper_server_sha256 = $snapshot.paper_server_sha256
            paper_prepared_manifest_sha256 = $snapshot.paper_prepared_manifest_sha256
            paper_prepared_file_count = $snapshot.paper_prepared_file_count
            paper_prepared_directory_count = $snapshot.paper_prepared_directory_count
        }
    })
    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $aggregate = [ordered]@{
        schema = $aggregateSchema
        generated_at = $generatedAt
        source_mode = 'EXECUTED'
        proxy_scope = 'BOTH'
        target_minecraft_version = $targetDefinition.minecraft_version
        target_protocol = $targetDefinition.protocol
        target_server_java_feature = $targetDefinition.server_java_feature
        target_server_java_sha256 = $current.target_server_java_sha256
        target_prepared_tree_sha256 = $current.target_prepared_tree_sha256
        expected_case_count = 6
        observed_case_count = $aggregateCases.Count
        all_cases_passed = $true
        matrix_completed = $true
        evidence_origin = 'ADMIN_REVIEWED'
        review_scope = 'EXACT_HASH'
        authorization_contract = 'UUID_CONTEXT_COMMITMENT_V3'
        client_report_independent_enforcement = $false
        authorization_persisted_before_execution = $true
        deny_scope = 'CURRENT_CONNECTION_ONLY'
        automatic_permanent_ban = $false
        fabric_gui_coverage = $false
        actual_run_root_digest_coverage = $false
        runtime_asset_binding_limitation = $runtimeAssetBindingLimitation
        cases = $aggregateCases
    }
    $reportJson = ($aggregate | ConvertTo-Json -Depth 12) + "`n"
    Assert-SanitizedEvidenceJson $reportJson 'TRUSTED_DISPOSITION_AGGREGATE_NOT_SANITIZED'
    $reportBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($reportJson)
    $binding = [ordered]@{
        schema = $bindingSchema
        report_schema = $aggregateSchema
        report_generated_at = $generatedAt
        report_sha256 = Get-BytesSha256 $reportBytes
        binding_generated_at = $generatedAt
        source_mode = 'EXECUTED'
        proxy_scope = 'BOTH'
        expected_case_count = 6
        matrix_completed = $true
        target_minecraft_version = $current.target_minecraft_version
        target_protocol = $current.target_protocol
        target_server_java_feature = $current.target_server_java_feature
        target_server_java_sha256 = $current.target_server_java_sha256
        target_prepared_tree_sha256 = $current.target_prepared_tree_sha256
        gate_wrapper_sha256 = $current.gate_wrapper_sha256
        source_manifest_sha256 = $current.source_manifest_sha256
        source_file_count = $current.source_file_count
        velocity_observer_sha256 = $current.velocity_observer_sha256
        velocity_plugin_sha256 = $current.velocity_plugin_sha256
        bungee_plugin_sha256 = $current.bungee_plugin_sha256
        paper_plugin_sha256 = $current.paper_plugin_sha256
        velocity_server_sha256 = $current.velocity_server_sha256
        bungee_server_sha256 = $current.bungee_server_sha256
        paper_server_sha256 = $current.paper_server_sha256
        paper_prepared_manifest_sha256 = $current.paper_prepared_manifest_sha256
        paper_prepared_file_count = $current.paper_prepared_file_count
        paper_prepared_directory_count = $current.paper_prepared_directory_count
        java_executable_sha256 = $current.java_executable_sha256
        java_file_version = $current.java_file_version
        java_major = $current.java_major
        gradle_version = $current.gradle_version
        gradle_distribution_sha256 = $current.gradle_distribution_sha256
        gradle_wrapper_sha256 = $current.gradle_wrapper_sha256
        gradle_wrapper_jar_sha256 = $current.gradle_wrapper_jar_sha256
        gradle_launcher_sha256 = $current.gradle_launcher_sha256
        gradle_core_sha256 = $current.gradle_core_sha256
        gradle_command_sha256 = $current.gradle_command_sha256
        gradle_installation_manifest_sha256 = $current.gradle_installation_manifest_sha256
        gradle_installation_file_count = $current.gradle_installation_file_count
        gradle_installation_directory_count = $current.gradle_installation_directory_count
        actual_run_root_digest_coverage = $false
        runtime_asset_binding_limitation = $runtimeAssetBindingLimitation
        case_bindings = $caseBindings
        passed = $true
    }
    $bindingJson = ($binding | ConvertTo-Json -Depth 12) + "`n"
    Assert-SanitizedEvidenceJson $bindingJson 'TRUSTED_DISPOSITION_BINDING_NOT_SANITIZED'
    $bindingBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($bindingJson)
    $commit = [ordered]@{
        schema = $commitSchema
        generated_at = $generatedAt
        report_schema = $aggregateSchema
        binding_schema = $bindingSchema
        report_sha256 = Get-BytesSha256 $reportBytes
        binding_sha256 = Get-BytesSha256 $bindingBytes
        committed = $true
    }
    $commitJson = ($commit | ConvertTo-Json -Depth 4) + "`n"
    Assert-SanitizedEvidenceJson $commitJson 'TRUSTED_DISPOSITION_COMMIT_NOT_SANITIZED'
    $commitBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($commitJson)
    $evidenceRoot = Join-Path $evidenceRunsRoot $runName
    $stagingRoot = Join-Path $evidenceRunsRoot ('.staging-' + $runName + '-' +
        [System.IO.Path]::GetRandomFileName())
    if ((Test-Path -LiteralPath $evidenceRoot) -or (Test-Path -LiteralPath $stagingRoot)) {
        throw 'TRUSTED_DISPOSITION_EVIDENCE_RUN_COLLISION'
    }
    [void][System.IO.Directory]::CreateDirectory($stagingRoot)
    $reportPath = Join-Path $stagingRoot 'report.json'
    $bindingPath = Join-Path $stagingRoot 'binding.json'
    $commitPath = Join-Path $stagingRoot 'commit.json'
    [System.IO.File]::WriteAllBytes($reportPath, $reportBytes)
    [System.IO.File]::WriteAllBytes($bindingPath, $bindingBytes)
    # The commit marker is deliberately the final staged write.
    [System.IO.File]::WriteAllBytes($commitPath, $commitBytes)
    $null = Assert-EvidencePair $reportPath
    [System.IO.Directory]::Move($stagingRoot, $evidenceRoot)
    $stagingRoot = $null
    $evidenceMoved = $true
    # Windows locks stay held through staged validation and the atomic publish, then are released
    # before any owned-path cleanup can run.
    Close-CaseReportStreams $caseReports
    [System.IO.Directory]::Delete($attemptRoot, $false)
    $attemptRoot = $null
    $published = $true
    Write-Output "TRUSTED_DISPOSITION_PROCESS_MATRIX_PASS|$(ConvertTo-RepoRelativePath (Join-Path $evidenceRoot 'report.json'))"
} catch {
    $executionFailure = $_
    Close-CaseReportStreams $caseReports
    if (-not $published) {
        if ($evidenceMoved) {
            try {
                Remove-UnpublishedEvidenceRoot $evidenceRoot
                $evidenceMoved = $false
            } catch {
                # Exact rollback failure retains the attempt marker, so ReportOnly remains blocked.
            }
        }
        try {
            Remove-OwnedRawRoots $ownedRawRoots
        } catch {
            # Cleanup must never replace the execution/validation failure. A non-exact directory
            # is deliberately retained instead of broadening deletion authority.
        }
    }
    throw $executionFailure
} finally {
    Close-CaseReportStreams $caseReports
    if ($null -ne $stagingRoot -and (Test-Path -LiteralPath $stagingRoot -PathType Container)) {
        foreach ($name in @('report.json', 'binding.json', 'commit.json')) {
            $candidate = Join-Path $stagingRoot $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                [System.IO.File]::Delete((Assert-DirectLocalPath $candidate))
            }
        }
        [System.IO.Directory]::Delete((Assert-DirectLocalPath $stagingRoot -Directory), $false)
    }
    if ($null -ne $attemptRoot -and (Test-Path -LiteralPath $attemptRoot -PathType Container)) {
        if (-not $evidenceMoved -or $published) {
            [System.IO.Directory]::Delete((Assert-DirectLocalPath $attemptRoot -Directory), $false)
        }
    }
}
